//! App-engine runtime for globally authorized committee sessions.
//!
//! Everything here reads COMMITTED state: the GLOBAL authorization records and
//! cursor from one snapshot, and the shard's phase roots, cursor and outgoing
//! history from another. Read failures are errors, never an empty checkpoint,
//! so a member that cannot establish its parent abstains instead of voting.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use quil_cw_consensus::adapters::ProposalContext;
use quil_cw_consensus::handoff::automaton::{AuthorizedParent, ParentReader};
use quil_cw_consensus::handoff::{Checkpoint, Seal, Session};
use quil_execution::global_intrinsic::handoff::{
    self, schedule, CertificateSubmission, CommittedView, Status,
};
use quil_hypergraph::HypergraphCrdt;
use quil_types::error::{QuilError, Result};
use quil_types::store::ClockStore;

/// Consecutive request-free data frames required under the selected parent
/// before a seal may be proposed. Header N+1 carries frame N's fee total,
/// settlements, spends and accumulator report to the global chain; a seal has
/// no header, so the last frames with outflows must be followed by data frames
/// that relay them. Two gives the relay one redundant carrier.
pub const DRAIN_FRAMES: u64 = 2;

fn unavailable(message: impl Into<String>) -> QuilError {
    QuilError::ExecutionUnavailable(format!("app committee session: {}", message.into()))
}

/// How this shard's consensus must be started, per committed GLOBAL state.
pub enum SessionChoice {
    /// The application never entered the protocol: legacy registry committee.
    Legacy,
    /// The protocol governs this network but no usable session exists yet
    /// (not authorized, or the head is retired and its successor is pending).
    Pending(&'static str),
    Session(Session),
}

/// GLOBAL's committed view, or `None` where it is unavailable and no
/// committee-handoff policy is installed. A regular node records the GLOBAL
/// cursor a committed view needs only while a policy is installed, and a node
/// upgraded from the mainnet build has none. Without a policy nothing creates
/// sessions or legacy tips, so every shard is legacy; refusing instead kept
/// every regular's shards from starting.
pub fn committed_view(global: &Arc<HypergraphCrdt>) -> Result<Option<CommittedView>> {
    match CommittedView::capture(global) {
        Ok(view) => Ok(Some(view)),
        Err(_) if quil_types::consensus::committee_handoff_policy().is_none() => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn resolve(global: &Arc<HypergraphCrdt>, filter: &[u8], global_frame: u64) -> Result<SessionChoice> {
    let Some(view) = committed_view(global)? else {
        return Ok(SessionChoice::Legacy);
    };
    if let Some(session) = handoff::head(&view, filter)? {
        return Ok(match handoff::status(&view, &session.id()?)? {
            Status::Closed(_) => SessionChoice::Pending("head session is retired"),
            _ => SessionChoice::Session(session),
        });
    }
    // A shard with legacy history that GLOBAL has not registered as generation
    // zero yet keeps producing under the legacy verifier, before and after
    // activation: its tip must keep advancing for
    // the registration to find a tip certified in the current epoch.
    if handoff::legacy::pending(&view, filter)? {
        return Ok(SessionChoice::Legacy);
    }
    if handoff::manages_application(&view, filter)? {
        return Ok(SessionChoice::Pending("application is managed; shard has no session"));
    }
    Ok(match quil_types::consensus::committee_handoff_policy() {
        Some(policy) if global_frame >= policy.activation_frame => {
            SessionChoice::Pending("first session not authorized yet")
        }
        _ => SessionChoice::Legacy,
    })
}

/// Whether `session` is the first session of a shard that a merge created:
/// its activating request sealed more than one source. A member of such a
/// session holds at most the data of the source it came from, so it must
/// inherit the merged range from an archive before it can build or verify a
/// frame. (A split child's members already hold the parent's whole range, which
/// covers the child.)
pub fn merged_from(global: &Arc<HypergraphCrdt>, session: &Session) -> Result<bool> {
    if session.generation != 1 {
        return Ok(false);
    }
    let view = CommittedView::capture(global)?;
    Ok(handoff::schedule::activating_request(&view, &session.filter)?
        .is_some_and(|request| request.sources.len() + request.vacant.len() > 1))
}

/// Whether the running session is still the one to run: `Ok(false)` once it is
/// retired or superseded, so the run loop stops the host and resolves again.
pub fn still_current(global: &Arc<HypergraphCrdt>, session: &Session) -> Result<bool> {
    let view = CommittedView::capture(global)?;
    let id = session.id()?;
    let Some(head) = handoff::head(&view, &session.filter)? else {
        return Err(QuilError::Store("running session lost its head record".into()));
    };
    Ok(head.id()? == id && !matches!(handoff::status(&view, &id)?, Status::Closed(_)))
}

/// Whether this prover's worker must keep running consensus on `filter`: it is
/// a member of the shard's head session and that session has not supplied its
/// terminal seal. The SESSION decides this, not the registry: a member whose
/// allocation is already Leaving, Kicked or reassigned is still part of the
/// quorum that must finalize frames and, eventually, the seal. (Otherwise a
/// shard can lose its whole closing committee to voluntary leaves.)
pub fn retains_worker(global: &Arc<HypergraphCrdt>, filter: &[u8], member: &[u8]) -> bool {
    let check = || -> Result<bool> {
        let view = CommittedView::capture(global)?;
        let Some(session) = handoff::head(&view, filter)? else {
            return Ok(false);
        };
        if !session.members.iter().any(|key| key == member) {
            return Ok(false);
        }
        Ok(match handoff::status(&view, &session.id()?)? {
            Status::Active => true,
            Status::Sealing(_) => !schedule::seal_submitted(&view, &session)?,
            Status::Closed(_) => false,
        })
    };
    match check() {
        Ok(retain) => retain,
        // No authenticated GLOBAL state yet: this node cannot be running a
        // session host (startup needs the same snapshot), so nothing is closing.
        Err(QuilError::ExecutionUnavailable(_)) => false,
        // A store or decoding failure says nothing about the session: do not
        // release a possibly closing member on it.
        Err(error) => {
            tracing::warn!(filter = hex::encode(filter), %error,
                "committee authorization unreadable; retaining the worker");
            true
        }
    }
}

struct HistoryTip {
    frame: u64,
    root: [u8; 32],
}

/// Reads the authorized, durably materialized parent for the handoff proposer.
pub struct ParentSource {
    session: Session,
    session_id: [u8; 32],
    global: Arc<HypergraphCrdt>,
    shard: Arc<HypergraphCrdt>,
    clock: Arc<dyn ClockStore>,
    /// Shared with the leader: request-free frames while the session closes.
    closing: Arc<AtomicBool>,
    history: Mutex<Option<HistoryTip>>,
    /// Unix seconds of the last operator-visible "parent unavailable" line.
    last_reported: std::sync::atomic::AtomicU64,
}

impl ParentSource {
    pub fn new(
        session: Session,
        global: Arc<HypergraphCrdt>,
        shard: Arc<HypergraphCrdt>,
        clock: Arc<dyn ClockStore>,
        closing: Arc<AtomicBool>,
    ) -> Result<Arc<Self>> {
        let session_id = session.id()?;
        Ok(Arc::new(Self {
            session,
            session_id,
            global,
            shard,
            clock,
            closing,
            history: Mutex::new(None),
            last_reported: std::sync::atomic::AtomicU64::new(0),
        }))
    }

    pub fn reader(self: &Arc<Self>) -> ParentReader {
        let source = self.clone();
        Arc::new(move |context| {
            source.read(context).inspect_err(|error| {
                // Expected while this member catches up to the selected parent;
                // persistent repetition means its state or history is incomplete.
                // This is the only trace of why a member abstains, so surface it
                // to operators, at most twice a minute.
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let last = source.last_reported.load(Ordering::Relaxed);
                if now >= last + 30 && source.last_reported
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
                {
                    tracing::info!(view = context.view, parent_view = context.parent_view, %error,
                        "committee session parent unavailable; abstaining");
                } else {
                    tracing::debug!(view = context.view, parent_view = context.parent_view, %error,
                        "committee session parent unavailable; abstaining");
                }
            })
        })
    }

    fn frame_is_request_free(&self, frame: u64) -> Result<bool> {
        // A predecessor drained before its seal, so a session's base and below
        // carry no unrelayed outflows. Generation zero's base is a legacy tip
        // that never drained: its frames count as they are.
        if frame <= self.session.base_frame && self.session.generation != 0 {
            return Ok(true);
        }
        Ok(self
            .clock
            .get_shard_clock_frame(&self.session.filter, frame, false)?
            .requests
            .is_empty())
    }

    /// Extend the cached chain when the tip only advanced; otherwise rebuild.
    fn history_root(
        &self,
        records: &dyn quil_types::store::SnapshotReadable,
        through: u64,
    ) -> Result<[u8; 32]> {
        let mut cache = self.history.lock().map_err(|_| unavailable("history cache poisoned"))?;
        let root = match cache.as_ref() {
            Some(tip) if tip.frame == through => tip.root,
            Some(tip) if tip.frame < through => handoff::history::extend(
                records, &self.session, tip.frame, tip.root, through,
            )?,
            _ => handoff::history::root(records, &self.session, through)?,
        };
        *cache = Some(HistoryTip { frame: through, root });
        Ok(root)
    }

    fn read(&self, context: ProposalContext) -> Result<AuthorizedParent> {
        let view = CommittedView::capture(&self.global)?;
        let head = handoff::head(&view, &self.session.filter)?
            .ok_or_else(|| unavailable("session has no head record"))?;
        if head.id()? != self.session_id {
            return Err(unavailable("session was superseded"));
        }
        let request = schedule::closing_request(&view, &self.session)?;
        self.closing.store(request.is_some(), Ordering::Release);

        let shard = self.shard.capture_committed_shard(&self.session.filter)?;
        let recorded = shard
            .records
            .read_record(&quil_store::encoding::consensus_materialized_cursor_key(&self.session.filter))?
            .map(|bytes| {
                bytes.as_slice().try_into().map(u64::from_be_bytes)
                    .map_err(|_| unavailable("malformed materialized cursor"))
            })
            .transpose()?;
        let cursor = match recorded {
            Some(cursor) => cursor,
            // A shard that has never materialized a frame has no cursor record.
            None if self.session.base_frame == 0 => 0,
            None => return Err(unavailable("source state has not been recovered")),
        };
        if cursor < self.session.base_frame {
            return Err(unavailable("materialized state precedes the session genesis"));
        }
        // Generation zero continues a legacy instance: its base is a certified
        // legacy frame the instance resumes from as its finalized floor, not a
        // virtual genesis at view zero.
        let (view_number, digest) = if cursor == self.session.base_frame && self.session.generation != 0 {
            (0, self.session.genesis)
        } else {
            let frame = self.clock.get_shard_clock_frame(&self.session.filter, cursor, false)?;
            let header = frame.header.ok_or_else(|| unavailable("materialized frame has no header"))?;
            if header.frame_number != cursor || header.address != self.session.filter {
                return Err(unavailable("materialized frame record is inconsistent"));
            }
            (header.rank, quil_crypto::poseidon::hash_bytes_to_32(&header.output)?)
        };
        if digest != context.parent.0 || view_number != context.parent_view {
            return Err(unavailable(format!(
                "selected parent (view {}, {}) is not the local materialized tip (frame {cursor}, view {view_number}, {})",
                context.parent_view, hex::encode(&context.parent.0[..4]), hex::encode(&digest[..4]),
            )));
        }
        let history_root = match recorded {
            Some(_) => self.history_root(shard.records.as_ref(), cursor)?,
            None => handoff::history::start(&self.session)?,
        };

        // A generation-0 seal must name a frame above its base: the base is the
        // registration's tip, and only a later frame carries this session's
        // certificate (`Seal::validate`).
        let sealable = self.session.generation != 0 || cursor > self.session.base_frame;
        let mut drained = sealable;
        if sealable {
            for back in 0..DRAIN_FRAMES {
                match cursor.checked_sub(back) {
                    Some(frame) => drained &= self.frame_is_request_free(frame)?,
                    None => break,
                }
            }
        }
        Ok(AuthorizedParent {
            checkpoint: Checkpoint {
                frame: cursor,
                view: view_number,
                digest,
                state_roots: shard.roots,
                history_root,
            },
            closing_request: request.filter(|_| drained),
        })
    }
}

impl ParentSource {
    /// Checkpoint of a selected parent executed privately over the materialized
    /// tip: the committed checkpoint extended by exactly that frame, with roots
    /// and outgoing history read from the private branch. Caches nothing.
    pub(crate) fn read_private(
        &self,
        context: ProposalContext,
        parent: &crate::app_engine::PrivateAppParent,
    ) -> Result<AuthorizedParent> {
        let view = CommittedView::capture(&self.global)?;
        let head = handoff::head(&view, &self.session.filter)?
            .ok_or_else(|| unavailable("session has no head record"))?;
        if head.id()? != self.session_id {
            return Err(unavailable("session was superseded"));
        }
        let request = schedule::closing_request(&view, &self.session)?;
        self.closing.store(request.is_some(), Ordering::Release);
        if parent.digest != context.parent
            || parent.view != context.parent_view
            || parent.base < self.session.base_frame
            || parent.frame_number <= self.session.base_frame
        {
            return Err(unavailable("private parent differs from the selection or session"));
        }
        let committed = self.shard.capture_committed_shard(&self.session.filter)?;
        let recorded = committed
            .records
            .read_record(&quil_store::encoding::consensus_materialized_cursor_key(&self.session.filter))?;
        let base_root = match recorded {
            Some(_) => self.history_root(committed.records.as_ref(), parent.base)?,
            None if parent.base == self.session.base_frame => handoff::history::start(&self.session)?,
            None => return Err(unavailable("source state has not been recovered")),
        };
        let branch = parent.crdt.capture_committed_shard(&self.session.filter)?;
        let history_root = handoff::history::extend(
            branch.records.as_ref(), &self.session, parent.base, base_root, parent.frame_number,
        )?;
        // The parent itself, the unfinalized frames below it, then the
        // committed frames below those.
        let unfinalized: Vec<bool> = std::iter::once(parent.frame.requests.is_empty())
            .chain(parent.request_free_below.iter().rev().copied())
            .take(DRAIN_FRAMES as usize)
            .collect();
        let mut drained = unfinalized.iter().all(|free| *free);
        for back in 0..(DRAIN_FRAMES as usize).saturating_sub(unfinalized.len()) {
            match parent.base.checked_sub(back as u64) {
                Some(frame) => drained &= self.frame_is_request_free(frame)?,
                None => break,
            }
        }
        Ok(AuthorizedParent {
            checkpoint: Checkpoint {
                frame: parent.frame_number,
                view: parent.view,
                digest: parent.digest.0,
                state_roots: branch.roots,
                history_root,
            },
            closing_request: request.filter(|_| drained),
        })
    }
}

/// Canonical `CommitteeHandoff` request for a finalized seal, ready for the
/// prover-message transport. Resubmission of the same seal is harmless.
pub fn submission(seal_bytes: &[u8], certificate: Vec<u8>) -> Result<Vec<u8>> {
    CertificateSubmission { seal: Seal::decode(seal_bytes)?, certificate }.to_canonical_bytes()
}

/// One page of a shard's recorded outgoing records `[from, through]`, fetched
/// from an archive: contiguous from `from`, possibly shorter. Unauthenticated
/// until its chain is checked against a certified history root.
pub type OutgoingHistorySource = Arc<
    dyn Fn(Vec<u8>, u64, u64) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<FrameOutgoing>>> + Send>>
        + Send
        + Sync,
>;

pub use quil_execution::global_intrinsic::handoff::history::FrameOutgoing;

/// Fetched history held before its chain is verified.
const MAX_FETCHED_HISTORY_BYTES: usize = 256 << 20;
/// Records written per commit when installing verified history.
const MAX_INSTALL_BATCH_BYTES: usize = 8 << 20;

/// Install a same-filter predecessor's outgoing history this member cannot
/// re-derive locally (it joined through an archive-anchored jump, or its
/// records differ), fetched from an archive and accepted only if its chain
/// equals the predecessor's sealed, quorum-certified history root. A fenced
/// predecessor has no certified root and is skipped, as is a member whose
/// cursor is not at the sealed frame. Returns how many histories it installed.
pub async fn recover_sealed_history(
    global: &Arc<HypergraphCrdt>,
    shard: &Arc<HypergraphCrdt>,
    session: &Session,
    fetch: &OutgoingHistorySource,
) -> Result<usize> {
    let view = CommittedView::capture(global)?;
    let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&session.filter);
    let mut installed = 0;
    for (source, checkpoint) in handoff::origins(&view, &session.id()?)? {
        if source.filter != session.filter
            || checkpoint.frame <= source.base_frame
            || handoff::is_fenced(&view, &source.id()?)?
        {
            continue;
        }
        let local = shard.capture_committed_shard(&session.filter)?;
        let cursor = local
            .records
            .read_record(&cursor_key)?
            .and_then(|bytes| bytes.as_slice().try_into().ok().map(u64::from_be_bytes));
        if cursor != Some(checkpoint.frame) {
            continue;
        }
        match handoff::history::root(local.records.as_ref(), &source, checkpoint.frame) {
            Ok(root) if root == checkpoint.history_root => continue,
            Ok(_) => {}
            Err(QuilError::ExecutionUnavailable(_)) => {}
            Err(error) => return Err(error),
        }
        let mut root = handoff::history::start(&source)?;
        let mut fetched = Vec::new();
        let mut bytes = 0usize;
        let mut next = source.base_frame + 1;
        while next <= checkpoint.frame {
            let page = fetch(session.filter.clone(), next, checkpoint.frame).await?;
            if page.is_empty() {
                return Err(unavailable(format!("no archive served outgoing records from frame {next}")));
            }
            for outgoing in page {
                if outgoing.frame != next || next > checkpoint.frame {
                    return Err(unavailable("archive outgoing history is not the requested range"));
                }
                root = handoff::history::link(root, &outgoing)?;
                bytes += outgoing.fees.len() + outgoing.settlements.len() + outgoing.spends.len()
                    + outgoing.digest.len() + outgoing.report.len();
                if bytes > MAX_FETCHED_HISTORY_BYTES {
                    return Err(unavailable("predecessor outgoing history exceeds the fetch limit"));
                }
                fetched.push(outgoing);
                next += 1;
            }
        }
        if root != checkpoint.history_root {
            return Err(unavailable("archive outgoing history does not match the sealed history root"));
        }
        let mut batch = Vec::new();
        let mut batch_bytes = 0usize;
        for record in fetched.iter().flat_map(|outgoing| outgoing.records(&session.filter)) {
            batch_bytes += record.0.len() + record.1.len();
            batch.push(record);
            if batch_bytes >= MAX_INSTALL_BATCH_BYTES {
                shard.checkpoint_shard_records(&session.filter, &local.roots, &cursor_key, checkpoint.frame, &batch)?;
                batch.clear();
                batch_bytes = 0;
            }
        }
        if !batch.is_empty() {
            shard.checkpoint_shard_records(&session.filter, &local.roots, &cursor_key, checkpoint.frame, &batch)?;
        }
        tracing::info!(
            filter = hex::encode(&session.filter), generation = source.generation,
            frames = fetched.len(), through = checkpoint.frame,
            "installed predecessor outgoing history fetched from an archive and matched to its sealed root",
        );
        installed += 1;
    }
    Ok(installed)
}

/// A successor may vote only over the state its sources ended at. For a source
/// on this same filter the local committed roots at the checkpoint frame must
/// equal the sealed roots exactly, and the local outgoing history must
/// re-derive the sealed, quorum-certified history root: a member that cannot
/// (it joined through an archive-anchored jump) first recovers it from
/// certified headers or an archive ([`recover_sealed_history`]), and abstains
/// until it has. Other shapes (split child, merged parent) are authenticated by
/// the shard sync that stages their data, pinned to the sources' sealed roots
/// ([`origin_anchors`]); this check cannot compare a sub-range against the
/// source's whole-range roots. Where no source state is certified (a fenced
/// source, a first session) or an archive no longer resolves it, the staged
/// data is unauthenticated and the committee's first header attests it.
///
/// A source GLOBAL fenced after its closing timeout has no certified history
/// root and, for a fence at its executed tip, no certified post-state roots.
/// Its successor requires the member to hold exactly the fenced frame, the
/// frame the fence names, and accepts it without a history comparison; the
/// successor committee's first header then attests the roots.
pub fn successor_state_matches(
    global: &Arc<HypergraphCrdt>,
    shard: &Arc<HypergraphCrdt>,
    clock: &dyn ClockStore,
    session: &Session,
) -> Result<()> {
    let view = CommittedView::capture(global)?;
    for (source, checkpoint) in handoff::origins(&view, &session.id()?)? {
        if source.filter != session.filter {
            continue;
        }
        let local = shard.capture_committed_shard(&session.filter)?;
        let recorded = local
            .records
            .read_record(&quil_store::encoding::consensus_materialized_cursor_key(&session.filter))?
            .and_then(|bytes| bytes.as_slice().try_into().ok().map(u64::from_be_bytes));
        let cursor = recorded.unwrap_or(0);
        if cursor < checkpoint.frame {
            return Err(unavailable("predecessor state has not been recovered through its seal"));
        }
        if handoff::is_fenced(&view, &source.id()?)? {
            if cursor > checkpoint.frame {
                // Past the fence is this session's own chain when GLOBAL has
                // executed the session's frames past it and the local frame
                // at that tip is the one GLOBAL executed: a member restarting
                // inside a successor it already ran. Refusing it would stop the
                // shard, every member refusing itself at a restart. Otherwise the member executed
                // predecessor frames the fence discarded.
                // A member behind that tip (a new joiner synced between the
                // fence and it) catches up first.
                let own_tip = handoff::session_tip(&view, &session.id()?)?
                    .filter(|tip| tip.frame > checkpoint.frame);
                if own_tip.as_ref().is_some_and(|tip| cursor < tip.frame) {
                    return Err(unavailable("behind this session's executed frames"));
                }
                let executed = own_tip.and_then(|tip| {
                    let frame = clock.get_shard_clock_frame(&session.filter, tip.frame, false).ok()?;
                    let digest = quil_crypto::poseidon::hash_bytes_to_32(&frame.header?.output).ok()?;
                    Some(digest == tip.digest)
                });
                if executed != Some(true) {
                    return Err(QuilError::Consensus(
                        "local state is past the predecessor's fenced checkpoint".into(),
                    ));
                }
                continue;
            }
            if checkpoint.state_roots != [[0; 32]; 4] && local.roots != checkpoint.state_roots {
                return Err(QuilError::Consensus(
                    "local state differs from the predecessor's fenced checkpoint".into(),
                ));
            }
            let digest = if cursor == source.base_frame {
                source.genesis
            } else {
                let frame = clock.get_shard_clock_frame(&session.filter, cursor, false)?;
                let header = frame.header.ok_or_else(|| unavailable("fenced frame has no header"))?;
                quil_crypto::poseidon::hash_bytes_to_32(&header.output)?
            };
            if digest != checkpoint.digest {
                return Err(QuilError::Consensus(
                    "local frame at the fence differs from the fenced frame".into(),
                ));
            }
            tracing::warn!(
                filter = hex::encode(&session.filter), generation = session.generation, frame = cursor,
                "predecessor was fenced after its closing timeout; accepting its checkpoint without \
                 a certified history root",
            );
            continue;
        }
        if cursor == checkpoint.frame {
            if local.roots != checkpoint.state_roots {
                // This member does not hold the state its predecessor sealed
                // (it never held the range, or holds another version). As a
                // recoverable gap it requests the shard sync, which installs
                // the state from an archive pinned to the sealed roots
                // (`origin_anchors`); as a consensus error it retried the same
                // comparison forever.
                return Err(unavailable("local state differs from the predecessor's sealed checkpoint"));
            }
            // A shard that never materialized a frame has no cursor record; its
            // history is the chain's starting value, as the parent reader has it.
            let history = match recorded {
                Some(_) => handoff::history::root(local.records.as_ref(), &source, cursor)?,
                None => handoff::history::start(&source)?,
            };
            if history != checkpoint.history_root {
                return Err(QuilError::Consensus(
                    "local outgoing history differs from the predecessor's sealed history".into(),
                ));
            }
        }
    }
    Ok(())
}

/// The certified state a member of `filter` with no frame of its own can
/// authenticate an archive's copy against: `(source filter, sealed roots)` for
/// each origin of the shard's current session. The sources partition the
/// shard's range, so syncing each one pinned to its roots yields the shard's
/// state, verified. A same-filter origin fenced at its base (a session that
/// never ran) holds exactly its own origins' state and is looked through.
/// Empty when any part of the state has no certified roots: a first session,
/// or a source fenced after it ran (a fence certifies no post-state).
pub fn origin_anchors(global: &Arc<HypergraphCrdt>, filter: &[u8]) -> Result<Vec<(Vec<u8>, [[u8; 32]; 4])>> {
    const MAX_LOOK_THROUGH: usize = 16;
    let view = CommittedView::capture(global)?;
    let Some(session) = handoff::head(&view, filter)? else { return Ok(Vec::new()) };
    let mut pending = vec![session];
    let mut anchors: Vec<(Vec<u8>, [[u8; 32]; 4])> = Vec::new();
    let mut steps = 0;
    while let Some(session) = pending.pop() {
        steps += 1;
        if steps > MAX_LOOK_THROUGH {
            return Ok(Vec::new());
        }
        let origins = handoff::origins(&view, &session.id()?)?;
        if origins.is_empty() {
            return Ok(Vec::new());
        }
        for (source, checkpoint) in origins {
            if checkpoint.state_roots != [[0; 32]; 4] {
                if !anchors.iter().any(|(f, roots)| *f == source.filter && *roots == checkpoint.state_roots) {
                    anchors.push((source.filter, checkpoint.state_roots));
                }
            } else if source.filter == session.filter
                && checkpoint.frame == source.base_frame
                && checkpoint.digest == source.genesis
            {
                pending.push(source);
            } else {
                return Ok(Vec::new());
            }
        }
    }
    Ok(anchors)
}

/// A member whose session GLOBAL authorized from a fenced same-filter
/// predecessor, holding shard state past the fence while the session has
/// executed nothing past it, holds frames the fence discarded: it can neither
/// continue the fenced session nor start this one. Rewind the shard to the
/// fence. The frame after the fence (this member's own, certified by the
/// fenced session) names the fenced frame's post-state roots, and must build
/// on the frame the fence names. State, cursor and clock head move back to the
/// fence; the discarded frames are deleted. Returns the fence frame when it
/// rewound.
pub fn rewind_past_fence(
    global: &Arc<HypergraphCrdt>,
    shard: &Arc<HypergraphCrdt>,
    clock: &dyn ClockStore,
    session: &Session,
) -> Result<Option<u64>> {
    let view = CommittedView::capture(global)?;
    for (source, checkpoint) in handoff::origins(&view, &session.id()?)? {
        if source.filter != session.filter || !handoff::is_fenced(&view, &source.id()?)? {
            continue;
        }
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&session.filter);
        let local = shard.capture_committed_shard(&session.filter)?;
        let cursor = local.records.read_record(&cursor_key)?
            .and_then(|bytes| bytes.as_slice().try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0);
        if cursor <= checkpoint.frame
            || handoff::session_tip(&view, &session.id()?)?.is_some_and(|tip| tip.frame > checkpoint.frame)
        {
            return Ok(None);
        }
        // A member that holds no frame at the fence joined after it (by an
        // archive sync onto this session's chain); nothing here to rewind.
        let (Ok(fenced), Ok(next)) = (
            clock.get_shard_clock_frame(&session.filter, checkpoint.frame, false),
            clock.get_shard_clock_frame(&session.filter, checkpoint.frame + 1, false),
        ) else {
            return Ok(None);
        };
        let fenced = fenced.header.ok_or_else(|| unavailable("fenced frame has no header"))?;
        let header = next.header.ok_or_else(|| unavailable("frame after the fence has no header"))?;
        if quil_crypto::poseidon::hash_bytes_to_32(&fenced.output)? != checkpoint.digest
            || !crate::frame_validator::app_frame_links_to_child(&fenced, &header)
        {
            return Err(QuilError::Consensus("local frames at the fence differ from the fenced frame".into()));
        }
        // This session's own first frame also builds on the fence. The fenced
        // session's frames anchor before GLOBAL fenced it (its closing request
        // plus the timeout); this session's anchor at or after that.
        let request = match handoff::status(&view, &source.id()?)? {
            Status::Sealing(request) | Status::Closed(request) => handoff::request(&view, &request)?,
            Status::Active => None,
        }
        .ok_or_else(|| unavailable("fenced predecessor has no closing request"))?;
        let fenced_at = request.frame
            .saturating_add(schedule::FENCE_AFTER_EPOCHS.saturating_mul(quil_types::consensus::epoch_length_frames()));
        if header.global_frame_number >= fenced_at {
            return Ok(None);
        }
        let roots: [[u8; 32]; 4] = header.state_roots.iter()
            .map(|root| <[u8; 32]>::try_from(root.as_slice()).ok())
            .collect::<Option<Vec<_>>>()
            .and_then(|roots| roots.try_into().ok())
            .ok_or_else(|| QuilError::Consensus("frame after the fence carries malformed state roots".into()))?;
        shard.rewind_app_shard(&session.filter, &roots)?;
        shard.checkpoint_frame_cursor(checkpoint.frame, &cursor_key)?;
        for frame in checkpoint.frame + 1..=cursor {
            shard.invalidate_domain_shard_commit(frame, &session.filter[..32])?;
        }
        let stored = clock.get_latest_shard_clock_frame(&session.filter).ok()
            .and_then(|frame| frame.header.map(|header| header.frame_number))
            .unwrap_or(cursor);
        clock.set_latest_shard_clock_frame_number(&session.filter, checkpoint.frame)?;
        clock.delete_shard_clock_frame_range(&session.filter, checkpoint.frame + 1, cursor.max(stored) + 1)?;
        tracing::warn!(
            filter = hex::encode(&session.filter), generation = session.generation,
            from = cursor, to = checkpoint.frame,
            "rewound shard state to the checkpoint GLOBAL fenced its predecessor at",
        );
        return Ok(Some(checkpoint.frame));
    }
    Ok(None)
}

#[cfg(test)]
mod successor_tests {
    use super::*;
    use quil_cw_consensus::handoff::{Checkpoint, Seal};
    use quil_execution::global_intrinsic::handoff::{CertificateSubmission, DesiredCommittee};
    use quil_execution::hypergraph_state::HypergraphState;
    use quil_execution::token_intrinsic::{settlement_record, spend_relay};
    use quil_types::crypto::Signer as _;

    fn crdt() -> Arc<HypergraphCrdt> {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let crdt = Arc::new(HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
        crdt
    }

    /// Frame `frame`'s outgoing records, as the materializer writes them.
    fn outflow_records(filter: &[u8], frame: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        use quil_store::encoding;
        vec![
            (encoding::clock_shard_frame_fee_total_key(filter, frame), 0u128.to_be_bytes().to_vec()),
            (encoding::clock_shard_frame_settlements_key(filter, frame), settlement_record::encode_entries(&[]).unwrap()),
            (encoding::clock_shard_frame_spends_key(filter, frame), spend_relay::encode_frame_entries(&[]).unwrap()),
            (encoding::clock_shard_frame_accumulator_key(filter, frame), Vec::new()),
        ]
    }

    fn global_state() -> (Arc<HypergraphCrdt>, HypergraphState) {
        let global = crdt();
        let state = HypergraphState::new(global.clone());
        (global, state)
    }

    fn commit(global: &Arc<HypergraphCrdt>, state: &HypergraphState, frame: u64) {
        state.commit().unwrap();
        state.abort();
        global.commit_with_global_cursor(frame, &quil_store::encoding::global_materialized_cursor_key()).unwrap();
    }

    /// A first session on `filter` with a successor scheduled at frame 3.
    fn closing_session(
        global: &Arc<HypergraphCrdt>, state: &HypergraphState, filter: &[u8],
    ) -> (Session, Vec<quil_crypto::FalconSigner>, handoff::Request) {
        let signers: Vec<_> = (0..3).map(|_| quil_crypto::FalconSigner::generate()).collect();
        let mut members: Vec<Vec<u8>> = signers.iter().map(|s| s.public_key().to_vec()).collect();
        members.sort();
        let source = Session {
            chain_id: [7; 32], filter: filter.to_vec(), generation: 1,
            genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
            base_frame: 0, authorization: [0; 32], members: members.clone(),
        };
        commit(global, state, 1);
        handoff::initialize(state, 2, &source).unwrap();
        commit(global, state, 2);
        let request = handoff::schedule(state, 3, vec![filter.to_vec()],
            vec![DesiredCommittee { filter: filter.to_vec(), members }]).unwrap();
        commit(global, state, 3);
        (source, signers, request)
    }

    fn outgoing(filter: &[u8], frame: u64) -> FrameOutgoing {
        let mut outgoing = FrameOutgoing { frame, ..Default::default() };
        for (key, value) in outflow_records(filter, frame) {
            use quil_store::encoding;
            if key == encoding::clock_shard_frame_fee_total_key(filter, frame) { outgoing.fees = value; }
            else if key == encoding::clock_shard_frame_settlements_key(filter, frame) { outgoing.settlements = value; }
            else if key == encoding::clock_shard_frame_spends_key(filter, frame) { outgoing.spends = value; }
            else { outgoing.digest = value; }
        }
        outgoing
    }

    /// An archive that serves `frames` from memory, at most two per page.
    fn archive(frames: Vec<FrameOutgoing>) -> OutgoingHistorySource {
        Arc::new(move |_filter, from, through| {
            let page: Vec<_> = frames.iter().filter(|f| f.frame >= from && f.frame <= through).take(2).cloned().collect();
            Box::pin(async move { Ok(page) })
        })
    }

    /// A member that joined the predecessor through an archive-anchored jump
    /// holds no outgoing records before its anchor and cannot re-walk the
    /// sealed history. It abstains (no acceptance on state-root equality) until
    /// it installs the predecessor's records from an archive, accepted only if
    /// their chain equals the sealed, quorum-certified history root.
    #[tokio::test]
    async fn successor_requires_the_sealed_history_and_recovers_it_from_an_archive() {
        let (global, state) = global_state();
        let filter = vec![0x01; 32];
        let (source, signers, request) = closing_session(&global, &state, &filter);
        let clock = quil_store::RocksClockStore::new(quil_store::RocksDb::open_in_memory().unwrap().inner());

        // The true history, frames 1..=3, and its certified root.
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&filter);
        let certified: Vec<_> = (1..=3).map(|frame| outgoing(&filter, frame)).collect();
        let mut history = handoff::history::start(&source).unwrap();
        for frame in &certified {
            history = handoff::history::link(history, frame).unwrap();
        }

        // The member's shard: cursor at the sealed frame, records for that
        // frame only (frames 1 and 2 predate its anchor).
        let shard = crdt();
        shard.commit_with_frame_cursor_and_records(3, &cursor_key, &outflow_records(&filter, 3)).unwrap();
        let sealed_roots = shard.capture_committed_shard(&filter).unwrap().roots;
        let seal = Seal {
            request: request.id().unwrap(), session: source.id().unwrap(), view: 9,
            checkpoint: Checkpoint { frame: 3, view: 5, digest: [0x33; 32], state_roots: sealed_roots, history_root: history },
        };
        let certificate = crate::test_support::certify_seal(&source, &signers, &seal);
        handoff::record_session_tip(&state, 4, &seal.session, &seal.checkpoint).unwrap();
        assert!(handoff::apply_submission(&state, 4, &CertificateSubmission { seal, certificate }).unwrap());
        commit(&global, &state, 4);
        let successor = handoff::head(&state, &filter).unwrap().unwrap();
        assert_eq!((successor.generation, successor.base_frame), (2, 3));

        let error = successor_state_matches(&global, &shard, &clock, &successor).unwrap_err();
        assert!(matches!(error, QuilError::ExecutionUnavailable(_)), "no acceptance on roots alone: {error}");

        // Records that do not chain to the sealed root are refused, and nothing is written.
        let mut forged = certified.clone();
        forged[0].fees = 7u128.to_be_bytes().to_vec();
        let error = recover_sealed_history(&global, &shard, &successor, &archive(forged)).await.unwrap_err();
        assert!(error.to_string().contains("does not match the sealed history root"), "{error}");
        assert!(successor_state_matches(&global, &shard, &clock, &successor).is_err());
        let error = recover_sealed_history(&global, &shard, &successor, &archive(certified[1..].to_vec())).await.unwrap_err();
        assert!(error.to_string().contains("not the requested range"), "a gap is refused: {error}");

        assert_eq!(recover_sealed_history(&global, &shard, &successor, &archive(certified.clone())).await.unwrap(), 1);
        successor_state_matches(&global, &shard, &clock, &successor).unwrap();
        assert_eq!(recover_sealed_history(&global, &shard, &successor, &archive(Vec::new())).await.unwrap(), 0,
            "a re-derivable history needs no fetch");

        // A complete but different local lineage is a mismatch, which certified
        // archive records then correct.
        let differing = crdt();
        for frame in 1..=3 {
            let mut records = outflow_records(&filter, frame);
            if frame == 2 {
                records[0].1 = 9u128.to_be_bytes().to_vec();
            }
            differing.commit_with_frame_cursor_and_records(frame, &cursor_key, &records).unwrap();
        }
        let error = successor_state_matches(&global, &differing, &clock, &successor).unwrap_err();
        assert!(matches!(error, QuilError::Consensus(_)) && error.to_string().contains("sealed history"), "{error}");
        assert_eq!(recover_sealed_history(&global, &differing, &successor, &archive(certified)).await.unwrap(), 1);
        successor_state_matches(&global, &differing, &clock, &successor).unwrap();

        // Behind the seal: recoverable, not a mismatch.
        let behind = crdt();
        behind.commit_with_frame_cursor_and_records(2, &cursor_key, &outflow_records(&filter, 2)).unwrap();
        let error = successor_state_matches(&global, &behind, &clock, &successor).unwrap_err();
        assert!(error.to_string().contains("not been recovered through its seal"), "{error}");

        // At the sealed frame with other state: recoverable by a sync pinned to
        // the sealed roots, so it requests one instead of refusing for good.
        let other = crdt();
        other.add_vertex(&quil_hypergraph::Location { app_address: [0x01; 32], data_address: [9; 32] }, &[9; 64]).unwrap();
        other.commit_with_frame_cursor_and_records(3, &cursor_key, &outflow_records(&filter, 3)).unwrap();
        let error = successor_state_matches(&global, &other, &clock, &successor).unwrap_err();
        assert!(matches!(error, QuilError::ExecutionUnavailable(_)) && error.to_string().contains("sealed checkpoint"),
            "{error}");
    }

    /// A predecessor GLOBAL fenced after its closing timeout has no certified
    /// history root. Its successor accepts a member holding exactly the fenced
    /// frame, and refuses one past it or holding a different frame there.
    /// A split child with no frame of its own authenticates its state against
    /// the parent's sealed roots, also after it stalled and was fenced at its
    /// base; a first session, and a child whose parent was fenced after it
    /// ran, have no certified state to anchor to.
    #[test]
    fn a_frameless_child_anchors_to_its_parents_sealed_state() {
        let (global, state) = global_state();
        let root = vec![0x03; 32];
        let child = |bit: u8| { let mut f = root.clone(); f.extend_from_slice(&[0, 1, bit]); f };
        let (left, right) = (child(0), child(128));
        let signers: Vec<_> = (0..3).map(|_| quil_crypto::FalconSigner::generate()).collect();
        let mut members: Vec<Vec<u8>> = signers.iter().map(|s| s.public_key().to_vec()).collect();
        members.sort();
        let parent = Session {
            chain_id: [7; 32], filter: root.clone(), generation: 1,
            genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
            base_frame: 0, authorization: [0; 32], members: members.clone(),
        };
        commit(&global, &state, 1);
        handoff::initialize(&state, 2, &parent).unwrap();
        commit(&global, &state, 2);
        assert!(origin_anchors(&global, &root).unwrap().is_empty(), "a first session");
        let split = handoff::schedule(&state, 3, vec![root.clone()], vec![
            DesiredCommittee { filter: left.clone(), members: members.clone() },
            DesiredCommittee { filter: right.clone(), members: members.clone() },
        ]).unwrap();
        commit(&global, &state, 3);
        let sealed = [[0x51; 32], [0x52; 32], [0x53; 32], [0x54; 32]];
        let seal = Seal {
            request: split.id().unwrap(), session: parent.id().unwrap(), view: 9,
            checkpoint: Checkpoint { frame: 6, view: 8, digest: [0x66; 32], state_roots: sealed, history_root: [0x67; 32] },
        };
        let certificate = crate::test_support::certify_seal(&parent, &signers, &seal);
        handoff::record_session_tip(&state, 4, &seal.session, &seal.checkpoint).unwrap();
        assert!(handoff::apply_submission(&state, 4, &CertificateSubmission { seal, certificate }).unwrap());
        commit(&global, &state, 4);
        assert_eq!(origin_anchors(&global, &left).unwrap(), vec![(root.clone(), sealed)]);

        // The left child never runs; a membership change asks it to close, and
        // it is fenced at its base. Its successor still anchors to the parent.
        let stalled = handoff::head(&state, &left).unwrap().unwrap();
        let change = handoff::schedule(&state, 5, vec![left.clone()],
            vec![DesiredCommittee { filter: left.clone(), members: members.clone() }]).unwrap();
        commit(&global, &state, 5);
        let due = 5 + schedule::FENCE_AFTER_EPOCHS * quil_types::consensus::epoch_length_frames();
        assert_eq!(schedule::fence_stalled_sources(&state, due, &[left.clone()]).unwrap(), 1);
        commit(&global, &state, due);
        assert!(schedule::activated(&CommittedView::capture(&global).unwrap(), &change.id().unwrap()).unwrap());
        assert_ne!(handoff::head(&state, &left).unwrap().unwrap().id().unwrap(), stalled.id().unwrap());
        assert_eq!(origin_anchors(&global, &left).unwrap(), vec![(root.clone(), sealed)], "looked through the base fence");

        // The right child ran (GLOBAL executed a frame), then stalled and was
        // fenced at its tip: nothing certifies its post-state.
        let right_session = handoff::head(&state, &right).unwrap().unwrap();
        handoff::record_session_tip(&state, due + 1, &right_session.id().unwrap(),
            &Checkpoint { frame: 2, view: 3, digest: [0x22; 32], state_roots: [[9; 32]; 4], history_root: [0; 32] }).unwrap();
        handoff::schedule(&state, due + 1, vec![right.clone()],
            vec![DesiredCommittee { filter: right.clone(), members }]).unwrap();
        commit(&global, &state, due + 1);
        let later = due + 1 + schedule::FENCE_AFTER_EPOCHS * quil_types::consensus::epoch_length_frames();
        assert_eq!(schedule::fence_stalled_sources(&state, later, &[right.clone()]).unwrap(), 1);
        commit(&global, &state, later);
        assert!(origin_anchors(&global, &right).unwrap().is_empty(), "a source fenced after it ran");
    }

    #[test]
    fn successor_of_a_fenced_predecessor_requires_exactly_the_fenced_frame() {
        use quil_types::store::ClockStore as _;
        let (global, state) = global_state();
        let filter = vec![0x02; 32];
        let (source, _, request) = closing_session(&global, &state, &filter);
        let clock_db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(clock_db.inner());
        let store_frame = |number: u64, output: u8| {
            let frame = quil_types::proto::global::AppShardFrame {
                header: Some(quil_types::proto::global::FrameHeader {
                    address: filter.clone(), frame_number: number, output: vec![output; 32], ..Default::default()
                }),
                ..Default::default()
            };
            let selector = vec![number as u8; 32];
            let txn = clock.new_transaction(false).unwrap();
            clock.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
            txn.commit().unwrap();
            let txn = clock.new_transaction(false).unwrap();
            clock.commit_shard_clock_frame(&filter, number, &selector, txn.as_ref(), false).unwrap();
            txn.commit().unwrap();
        };
        store_frame(3, 0x33);
        let digest = quil_crypto::poseidon::hash_bytes_to_32(&[0x33; 32]).unwrap();
        handoff::record_session_tip(&state, 4, &source.id().unwrap(),
            &Checkpoint { frame: 3, view: 5, digest, state_roots: [[1; 32]; 4], history_root: [2; 32] }).unwrap();
        let due = 3 + schedule::FENCE_AFTER_EPOCHS * quil_types::consensus::epoch_length_frames();
        assert_eq!(schedule::fence_stalled_sources(&state, due, &[filter.clone()]).unwrap(), 1);
        commit(&global, &state, due);
        assert!(handoff::is_fenced(&CommittedView::capture(&global).unwrap(), &source.id().unwrap()).unwrap());
        assert!(schedule::activated(&CommittedView::capture(&global).unwrap(), &request.id().unwrap()).unwrap());
        let successor = handoff::head(&state, &filter).unwrap().unwrap();
        assert_eq!(successor.base_frame, 3);

        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&filter);
        let at_fence = crdt();
        at_fence.commit_with_frame_cursor_and_records(3, &cursor_key, &outflow_records(&filter, 3)).unwrap();
        successor_state_matches(&global, &at_fence, &clock, &successor).unwrap();

        let past = crdt();
        past.commit_with_frame_cursor_and_records(4, &cursor_key, &outflow_records(&filter, 4)).unwrap();
        let error = successor_state_matches(&global, &past, &clock, &successor).unwrap_err();
        assert!(error.to_string().contains("past the predecessor's fenced checkpoint"), "{error}");

        // Once GLOBAL has executed the successor's own frames past the fence,
        // a member restarting inside it holds that chain and resumes; one
        // whose frame there differs, or that has not reached it, does not.
        store_frame(6, 0x66);
        handoff::record_session_tip(&state, due + 1, &successor.id().unwrap(), &Checkpoint {
            frame: 6, view: 9, digest: quil_crypto::poseidon::hash_bytes_to_32(&[0x66; 32]).unwrap(),
            state_roots: [[3; 32]; 4], history_root: [0; 32],
        }).unwrap();
        commit(&global, &state, due + 1);
        let resumed = crdt();
        resumed.commit_with_frame_cursor_and_records(6, &cursor_key, &outflow_records(&filter, 6)).unwrap();
        successor_state_matches(&global, &resumed, &clock, &successor).unwrap();
        assert_eq!(rewind_past_fence(&global, &resumed, &clock, &successor).unwrap(), None,
            "a member inside a successor that has run is never rewound");
        // A member behind the executed tip (a new joiner synced between the
        // fence and it) is told to catch up, which requests a shard sync.
        let error = successor_state_matches(&global, &past, &clock, &successor).unwrap_err();
        assert!(matches!(error, QuilError::ExecutionUnavailable(_)) && error.to_string().contains("behind this session"), "{error}");
        store_frame(6, 0x67);
        let error = successor_state_matches(&global, &resumed, &clock, &successor).unwrap_err();
        assert!(error.to_string().contains("past the predecessor's fenced checkpoint"), "{error}");

        store_frame(3, 0x44);
        let error = successor_state_matches(&global, &at_fence, &clock, &successor).unwrap_err();
        assert!(error.to_string().contains("differs from the fenced frame"), "{error}");
    }

    // Fixture k's shard …000804: GLOBAL fenced its generation 5 at app frame
    // 651 while every member had materialized 652, so none could start the
    // successor. A member past the fence rewinds to it: state, cursor and head.
    #[test]
    fn a_member_past_a_fence_rewinds_its_shard_to_the_fenced_frame() {
        use quil_types::store::ClockStore as _;
        let (global, state) = global_state();
        let filter = vec![0x02; 32];
        let (source, _, _) = closing_session(&global, &state, &filter);
        let clock_db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(clock_db.inner());
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&filter);
        let shard = crdt();
        shard.set_unified_tree(true);
        let at = |byte: u8| quil_hypergraph::Location { app_address: [0x02; 32], data_address: [byte; 32] };
        shard.add_vertex(&at(1), b"one").unwrap();
        shard.add_vertex(&at(2), b"two").unwrap();
        shard.commit_with_frame_cursor_and_records(3, &cursor_key, &outflow_records(&filter, 3)).unwrap();
        let fenced_roots = shard.capture_committed_shard(&filter).unwrap().roots;
        shard.add_vertex(&at(1), b"one, changed after the fence").unwrap();
        shard.add_vertex(&at(3), b"added after the fence").unwrap();
        shard.remove_vertex(&at(2)).unwrap();
        shard.commit_with_frame_cursor_and_records(4, &cursor_key, &outflow_records(&filter, 4)).unwrap();
        assert_ne!(shard.capture_committed_shard(&filter).unwrap().roots, fenced_roots);

        let store_frame = |header: quil_types::proto::global::FrameHeader| {
            let number = header.frame_number;
            let frame = quil_types::proto::global::AppShardFrame { header: Some(header), ..Default::default() };
            let selector = vec![number as u8; 32];
            let txn = clock.new_transaction(false).unwrap();
            clock.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
            txn.commit().unwrap();
            let txn = clock.new_transaction(false).unwrap();
            clock.commit_shard_clock_frame(&filter, number, &selector, txn.as_ref(), false).unwrap();
            txn.commit().unwrap();
        };
        let fenced_digest = quil_crypto::poseidon::hash_bytes_to_32(&[0x33; 32]).unwrap();
        store_frame(quil_types::proto::global::FrameHeader {
            address: filter.clone(), frame_number: 3, rank: 5, output: vec![0x33; 32], ..Default::default()
        });
        store_frame(quil_types::proto::global::FrameHeader {
            address: filter.clone(), frame_number: 4, rank: 6, output: vec![0x44; 32],
            parent_selector: fenced_digest.to_vec(),
            state_roots: fenced_roots.iter().map(|root| root.to_vec()).collect(),
            ..Default::default()
        });
        handoff::record_session_tip(&state, 4, &source.id().unwrap(),
            &Checkpoint { frame: 3, view: 5, digest: fenced_digest, state_roots: [[1; 32]; 4], history_root: [2; 32] }).unwrap();
        let due = 3 + schedule::FENCE_AFTER_EPOCHS * quil_types::consensus::epoch_length_frames();
        assert_eq!(schedule::fence_stalled_sources(&state, due, &[filter.clone()]).unwrap(), 1);
        commit(&global, &state, due);
        let successor = handoff::head(&state, &filter).unwrap().unwrap();
        assert!(successor_state_matches(&global, &shard, &clock, &successor).is_err(), "wedged past the fence");

        assert_eq!(rewind_past_fence(&global, &shard, &clock, &successor).unwrap(), Some(3));
        assert_eq!(shard.capture_committed_shard(&filter).unwrap().roots, fenced_roots);
        assert_eq!(shard.get_vertex_data(&at(1)), Some(b"one".to_vec()), "a change after the fence is undone");
        assert_eq!(shard.get_vertex_data(&at(2)), Some(b"two".to_vec()), "a removal after the fence is undone");
        assert_eq!(shard.get_vertex_data(&at(3)), None, "an add after the fence is gone");
        assert_eq!(shard.read_frame_cursor(&cursor_key).unwrap(), 3);
        assert_eq!(clock.get_latest_shard_clock_frame(&filter).unwrap().header.unwrap().frame_number, 3);
        assert!(clock.get_shard_clock_frame(&filter, 4, false).is_err(), "the discarded frame is deleted");
        successor_state_matches(&global, &shard, &clock, &successor).unwrap();
        assert_eq!(rewind_past_fence(&global, &shard, &clock, &successor).unwrap(), None, "once");

        // The successor's own first frame builds on the fence too. It anchors
        // at or after the fence, before GLOBAL has executed it, and stays.
        shard.add_vertex(&at(4), b"the successor's own").unwrap();
        shard.commit_with_frame_cursor_and_records(4, &cursor_key, &outflow_records(&filter, 4)).unwrap();
        store_frame(quil_types::proto::global::FrameHeader {
            address: filter.clone(), frame_number: 4, rank: 7, output: vec![0x55; 32],
            parent_selector: fenced_digest.to_vec(), global_frame_number: due,
            state_roots: fenced_roots.iter().map(|root| root.to_vec()).collect(),
            ..Default::default()
        });
        assert_eq!(rewind_past_fence(&global, &shard, &clock, &successor).unwrap(), None);
        assert_eq!(shard.get_vertex_data(&at(4)), Some(b"the successor's own".to_vec()));

        // A member that joined after the fence holds no frame at it.
        let joiner_clock_db = quil_store::RocksDb::open_in_memory().unwrap();
        let joiner_clock = quil_store::RocksClockStore::new(joiner_clock_db.inner());
        let joiner = crdt();
        joiner.commit_with_frame_cursor_and_records(5, &cursor_key, &outflow_records(&filter, 5)).unwrap();
        assert_eq!(rewind_past_fence(&global, &joiner, &joiner_clock, &successor).unwrap(), None);
    }

    // The same rewind on a sub-shard of a split application: only the shard's
    // subtree goes back; a sibling's later changes stay. Its removes subtree
    // was empty at the target while the tree held a sibling's removal.
    #[test]
    fn a_rewind_restores_one_sub_shard_and_leaves_its_siblings() {
        let app = [0x05u8; 32];
        let bits = [false, false, false, false, false, true, false, false];
        let filter = quil_forest::encode_shard_bit_path(&app, &bits);
        let inside = |byte: u8| quil_hypergraph::Location { app_address: app, data_address: [0x04, byte, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte] };
        let outside = |byte: u8| quil_hypergraph::Location { app_address: app, data_address: [0x80 | byte; 32] };
        let shard = crdt();
        shard.set_unified_tree(true);
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&filter);
        shard.add_vertex(&inside(1), b"inside one").unwrap();
        shard.add_vertex(&inside(2), b"inside two").unwrap();
        shard.add_vertex(&outside(1), b"sibling one").unwrap();
        shard.add_vertex(&outside(2), b"sibling two").unwrap();
        shard.commit_with_frame_cursor_and_records(3, &cursor_key, &[]).unwrap();
        shard.remove_vertex(&outside(2)).unwrap();
        shard.commit_with_frame_cursor_and_records(4, &cursor_key, &[]).unwrap();
        let target = shard.capture_committed_shard(&filter).unwrap().roots;
        assert_eq!(target[1], [0; 32], "the tree holds only a sibling's removal");

        shard.add_vertex(&inside(1), b"inside one, changed").unwrap();
        shard.add_vertex(&inside(3), b"inside three").unwrap();
        shard.remove_vertex(&inside(2)).unwrap();
        shard.add_vertex(&outside(3), b"sibling three").unwrap();
        shard.commit_with_frame_cursor_and_records(5, &cursor_key, &[]).unwrap();
        shard.rewind_app_shard(&filter, &target).unwrap();

        assert_eq!(shard.capture_committed_shard(&filter).unwrap().roots, target);
        assert_eq!(shard.get_vertex_data(&inside(1)), Some(b"inside one".to_vec()));
        assert_eq!(shard.get_vertex_data(&inside(2)), Some(b"inside two".to_vec()));
        assert_eq!(shard.get_vertex_data(&inside(3)), None);
        assert_eq!(shard.get_vertex_data(&outside(2)), None, "a sibling's removal stays");
        assert_eq!(shard.get_vertex_data(&outside(3)), Some(b"sibling three".to_vec()), "a sibling's later add stays");
        shard.rewind_app_shard(&filter, &target).unwrap();
        assert_eq!(shard.capture_committed_shard(&filter).unwrap().roots, target, "a second rewind changes nothing");
    }

    /// With no committee-handoff policy (mainnet today) a regular node never
    /// records the GLOBAL cursor a committed view needs. Its shards still start,
    /// as legacy, instead of failing to read GLOBAL session state forever.
    #[test]
    fn without_a_policy_a_node_without_a_global_cursor_starts_legacy_shards() {
        assert!(quil_types::consensus::committee_handoff_policy().is_none());
        let global = crdt();
        assert!(CommittedView::capture(&global).is_err(), "no GLOBAL cursor recorded");
        assert!(matches!(resolve(&global, &[0x03; 32], 100).unwrap(), SessionChoice::Legacy));
    }

    /// Generation zero continues a legacy chain: its base is the registered
    /// tip, a certified frame at its own view, so the parent there is that
    /// frame (never a view-0 virtual genesis) and no seal names it. The tip
    /// never drained, so its requests count toward the drain; the first
    /// drained frame after it is sealable, and its history starts at the tip.
    #[test]
    fn generation_zero_extends_its_legacy_tip_and_seals_only_after_it() {
        use quil_execution::global_intrinsic::handoff::legacy;
        use quil_types::consensus::{CommitteeHandoffPolicy, ProverAllocationInfo, ProverStatus};
        let global = crdt();
        let state = HypergraphState::new(global.clone());
        let commit = |frame: u64| {
            state.commit().unwrap();
            state.abort();
            global.commit_with_global_cursor(frame, &quil_store::encoding::global_materialized_cursor_key()).unwrap();
        };
        let filter = vec![0x02; 32];
        let signers: Vec<_> = (0..3).map(|_| quil_crypto::FalconSigner::generate()).collect();
        let mut pubkeys = std::collections::HashMap::new();
        let mut allocations = Vec::new();
        for signer in &signers {
            let address = quil_crypto::poseidon::hash_bytes_to_32(signer.public_key()).unwrap().to_vec();
            pubkeys.insert(address.clone(), signer.public_key().to_vec());
            allocations.push((address, ProverAllocationInfo {
                status: ProverStatus::Active, confirmation_filter: filter.clone(), rejection_filter: vec![],
                join_frame_number: 0, leave_frame_number: 0, pause_frame_number: 0, resume_frame_number: 0,
                kick_frame_number: 0, join_confirm_frame_number: 0, join_reject_frame_number: 0,
                leave_confirm_frame_number: 0, leave_reject_frame_number: 0, last_active_frame_number: 0,
                epoch: u64::MAX, ring: 0, vertex_address: vec![],
            }));
        }
        let scan = quil_execution::prover_registry::CommittedProverScan::from_parts(pubkeys, allocations);

        // The shard's legacy frames 4 and 5, as materialized locally.
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let shard = crdt();
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&filter);
        let put = |number: u64, rank: u64, requests: usize| {
            let frame = quil_types::proto::global::AppShardFrame {
                header: Some(quil_types::proto::global::FrameHeader {
                    address: filter.clone(), frame_number: number, rank,
                    output: vec![number as u8; 516], ..Default::default()
                }),
                requests: vec![Default::default(); requests],
                ..Default::default()
            };
            let selector = quil_crypto::poseidon::hash_bytes_to_32(&frame.header.as_ref().unwrap().output).unwrap();
            let txn = clock.new_transaction(false).unwrap();
            clock.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
            clock.commit_shard_clock_frame(&filter, number, &selector, txn.as_ref(), false).unwrap();
            txn.commit().unwrap();
            shard.commit_with_frame_cursor_and_records(number, &cursor_key, &outflow_records(&filter, number)).unwrap();
            selector
        };
        put(4, 15, 0);
        // The tip was not drained: it carries a request.
        let tip_digest = put(5, 17, 1);

        // GLOBAL records frame 5 as the tip and registers generation 0 there.
        let policy = CommitteeHandoffPolicy { activation_frame: 0, chain_id: [7; 32], legacy_history: quil_types::consensus::LegacyHistory::Migrate, membership_boundary_frame: u64::MAX};
        commit(1);
        let tip = legacy::LegacyTip {
            checkpoint: Checkpoint { frame: 5, view: 17, digest: tip_digest, state_roots: [[0; 32]; 4], history_root: [0; 32] },
            anchor: 0,
        };
        legacy::record_tip(&state, 2, &filter, &tip).unwrap();
        commit(2);
        assert_eq!(legacy::migrate(&state, 3, &policy, &[filter.clone()], &scan).unwrap(), 1);
        commit(3);
        let zero = handoff::head(&state, &filter).unwrap().unwrap();
        assert_eq!((zero.generation, zero.base_frame), (0, 5));
        let request = schedule::closing_request(&CommittedView::capture(&global).unwrap(), &zero).unwrap().unwrap();

        let closing = Arc::new(AtomicBool::new(false));
        let source = ParentSource::new(
            zero.clone(), global.clone(), shard.clone(), clock.clone() as Arc<dyn ClockStore>, closing.clone(),
        ).unwrap();
        let context = |view: u64, parent_view: u64, parent: [u8; 32]| ProposalContext {
            epoch: 0, view, parent_view, parent: quil_cw_consensus::adapters::digest_from_identity(parent),
        };
        // At the tip: the certified frame itself, drained or not, is no seal.
        let at_tip = source.read(context(18, 17, tip_digest)).unwrap();
        assert_eq!((at_tip.checkpoint.frame, at_tip.checkpoint.view, at_tip.checkpoint.digest), (5, 17, tip_digest));
        assert_eq!(at_tip.closing_request, None);
        assert!(closing.load(Ordering::Acquire), "the committee drains from registration");
        assert!(source.read(context(18, 0, zero.genesis)).is_err(), "no view-0 virtual genesis");

        // A member whose tip WAS drained (frames 4 and 5 request-free) still
        // offers no seal of the tip itself.
        let drained_clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let drained_shard = crdt();
        for (number, rank) in [(4u64, 15u64), (5, 17)] {
            let frame = quil_types::proto::global::AppShardFrame {
                header: Some(quil_types::proto::global::FrameHeader {
                    address: filter.clone(), frame_number: number, rank,
                    output: vec![number as u8; 516], ..Default::default()
                }),
                ..Default::default()
            };
            let selector = quil_crypto::poseidon::hash_bytes_to_32(&frame.header.as_ref().unwrap().output).unwrap();
            let txn = drained_clock.new_transaction(false).unwrap();
            drained_clock.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
            drained_clock.commit_shard_clock_frame(&filter, number, &selector, txn.as_ref(), false).unwrap();
            txn.commit().unwrap();
            drained_shard.commit_with_frame_cursor_and_records(number, &cursor_key, &outflow_records(&filter, number)).unwrap();
        }
        let drained_source = ParentSource::new(
            zero.clone(), global.clone(), drained_shard, drained_clock as Arc<dyn ClockStore>,
            Arc::new(AtomicBool::new(false)),
        ).unwrap();
        assert_eq!(drained_source.read(context(18, 17, tip_digest)).unwrap().closing_request, None);

        // The first frame past it is not drained yet: the tip's own request
        // counts, though the tip is the base.
        let next = put(6, 19, 0);
        assert_eq!(source.read(context(20, 19, next)).unwrap().closing_request, None);
        // Two request-free frames past the tip seal, over the history since it.
        let drained = put(7, 21, 0);
        let sealable = source.read(context(22, 21, drained)).unwrap();
        assert_eq!(sealable.closing_request, Some(request));
        assert_eq!(sealable.checkpoint.frame, 7);
        let records = shard.capture_committed_shard(&filter).unwrap().records;
        assert_eq!(sealable.checkpoint.history_root, handoff::history::root(records.as_ref(), &zero, 7).unwrap());
    }
}
