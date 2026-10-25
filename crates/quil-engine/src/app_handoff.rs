//! App-engine runtime for globally authorized committee sessions.
//!
//! Everything here reads COMMITTED state: the GLOBAL authorization records and
//! cursor from one snapshot, and the shard's phase roots, cursor and outgoing
//! history from another. Read failures are errors, never an empty checkpoint,
//! so a member that cannot establish its parent abstains instead of voting.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use quil_cw_consensus::adapters::ProposalContext;
use quil_cw_consensus::handoff::automaton::{AuthorizedParent, ClosingAbsence, ClosingProbe, ParentReader};
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

/// Why [`successor_state_matches`] refuses a member that does not yet hold
/// its same-filter predecessor's state through the seal.
const PREDECESSOR_UNRECOVERED: &str = "predecessor state has not been recovered through its seal";

/// Whether `error` is [`successor_state_matches`] waiting for this member to
/// recover its predecessor's sealed state.
pub fn predecessor_unrecovered(error: &QuilError) -> bool {
    matches!(error, QuilError::ExecutionUnavailable(reason) if reason.ends_with(PREDECESSOR_UNRECOVERED))
}

/// The same-filter predecessor whose state a member of a shard's current
/// session must hold before it may start ([`successor_state_matches`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredecessorSeal {
    pub session_generation: u64,
    pub predecessor_generation: u64,
    /// The frame its seal, or its fence, names.
    pub through: u64,
    pub fenced: bool,
}

/// The [`PredecessorSeal`] of `filter`'s current session, if it has a
/// same-filter origin.
pub fn same_filter_predecessor(global: &Arc<HypergraphCrdt>, filter: &[u8]) -> Result<Option<PredecessorSeal>> {
    let view = CommittedView::capture(global)?;
    let Some(session) = handoff::head(&view, filter)? else { return Ok(None) };
    for (source, checkpoint) in effective_origins(&view, &session)?.origins {
        if source.filter == session.filter {
            return Ok(Some(PredecessorSeal {
                session_generation: session.generation,
                predecessor_generation: source.generation,
                through: checkpoint.frame,
                fenced: handoff::is_fenced(&view, &source.id()?)?,
            }));
        }
    }
    Ok(None)
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
        // A GLOBAL state sync between chunks withholds the view for a while;
        // it says nothing about the session, so keep a possibly hosting member.
        Err(error) if handoff::global_sync_in_progress(&error) => true,
        // No authenticated GLOBAL state yet: this node cannot be running a
        // session host (startup needs the same snapshot), so nothing is closing.
        Err(QuilError::ExecutionUnavailable(_)) => false,
        // A store or decoding failure says nothing about the session: do not
        // release a possibly closing member on it.
        // Once a minute at most: the reconcile asks every frame, and the
        // recovery gate on each recovery request.
        Err(error) => {
            static LAST_WARN_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            let last = LAST_WARN_SECS.load(std::sync::atomic::Ordering::Relaxed);
            if now.saturating_sub(last) >= 60
                && LAST_WARN_SECS.compare_exchange(last, now, std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed).is_ok()
            {
                tracing::warn!(filter = hex::encode(filter), %error,
                    "committee authorization unreadable; retaining the worker (repeats at most once a minute)");
            }
            true
        }
    }
}

/// Of `filters`, those whose head session counts `member` and is not closed:
/// the sessions this prover's workers are there to host.
pub fn member_sessions(global: &Arc<HypergraphCrdt>, filters: &[Vec<u8>], member: &[u8]) -> Result<std::collections::HashSet<Vec<u8>>> {
    let view = CommittedView::capture(global)?;
    let mut counted = std::collections::HashSet::new();
    for filter in filters {
        let Some(session) = handoff::head(&view, filter)? else { continue };
        if session.members.iter().any(|key| key == member)
            && !matches!(handoff::status(&view, &session.id()?)?, Status::Closed(_))
        {
            counted.insert(filter.clone());
        }
    }
    Ok(counted)
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
    /// The engine's staged-data flag ([`Self::require_staged_data`]).
    data_ready: std::sync::OnceLock<Arc<AtomicBool>>,
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
            data_ready: std::sync::OnceLock::new(),
        }))
    }

    /// No parent, and so no seal, while `staged` is false. At its base a
    /// session's checkpoint is this member's committed shard roots, and a seal
    /// checks only that members agree on them: members that had not staged the
    /// shard's data agreed on their partial roots and certified them, and
    /// every same-filter successor then required those roots. Data frames are
    /// gated on the same flag (`AppSeamProposer::data_ready`).
    pub fn require_staged_data(&self, staged: Arc<AtomicBool>) {
        let _ = self.data_ready.set(staged);
    }

    fn check_staged(&self) -> Result<()> {
        match self.data_ready.get() {
            Some(staged) if !staged.load(Ordering::Acquire) => Err(unavailable("covered shard data is not staged")),
            _ => Ok(()),
        }
    }

    pub fn reader(self: &Arc<Self>) -> ParentReader {
        self.reader_of(true)
    }

    /// The authorized checkpoint at the local materialized tip, whatever the
    /// selected parent: a re-seal's voters compare the notarized seal they
    /// extend against it (`HandoffProposer::with_seal_parents`).
    pub fn tip_reader(self: &Arc<Self>) -> ParentReader {
        self.reader_of(false)
    }

    fn reader_of(self: &Arc<Self>, selected: bool) -> ParentReader {
        let source = self.clone();
        Arc::new(move |context| {
            source.authorized(context, selected).inspect_err(|error| {
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
                    tracing::info!(filter = %hex::encode(&source.session.filter), generation = source.session.generation,
                        view = context.view, parent_view = context.parent_view, %error,
                        "committee session parent unavailable; abstaining");
                } else {
                    tracing::debug!(filter = %hex::encode(&source.session.filter), generation = source.session.generation,
                        view = context.view, parent_view = context.parent_view, %error,
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

    #[cfg(test)]
    fn read(&self, context: ProposalContext) -> Result<AuthorizedParent> {
        self.authorized(context, true)
    }

    /// Why this member's parent names no closing request, for a seal of its
    /// session it is asked to vote on (`HandoffProposer::with_closing_probe`).
    /// `anchors` holds the GLOBAL headers this node received. A request
    /// absent from a committed view behind the GLOBAL head asks `refresh` for
    /// an early pull of that view; the seal waits only if one can land soon,
    /// which needs this process's sync task to honour requests.
    pub fn closing_probe(
        self: &Arc<Self>,
        anchors: Arc<dyn ClockStore>,
        refresh: Arc<crate::global_view_refresh::ViewRefresh>,
    ) -> ClosingProbe {
        let source = self.clone();
        Arc::new(move || source.closing_absence(anchors.as_ref(), &refresh))
    }

    fn closing_absence(
        &self,
        anchors: &dyn ClockStore,
        refresh: &crate::global_view_refresh::ViewRefresh,
    ) -> ClosingAbsence {
        let absent = |detail: String| ClosingAbsence { detail, refreshing: false };
        let view = match CommittedView::capture(&self.global) {
            Ok(view) => view,
            Err(error) => return absent(format!("committed GLOBAL view unavailable: {error}")),
        };
        let at = view.frame();
        match schedule::closing_request(&view, &self.session) {
            Ok(Some(_)) => absent(format!(
                "closing request in the committed GLOBAL view at frame {at}, but the checkpoint is not \
                 sealable: its last {DRAIN_FRAMES} frames are not free of requests, or it is the base"
            )),
            Ok(None) => {
                let head = anchors.get_latest_global_clock_frame().ok()
                    .and_then(|frame| frame.header).map(|header| header.frame_number);
                // A header's prover root binds the state before its frame, so
                // a refresh now reaches the frame below the head.
                let reach = head.map(|head| head.saturating_sub(1)).filter(|reach| *reach > at);
                let refreshing = reach.is_some_and(|reach| refresh.request(
                    crate::global_view_refresh::Reason::SealBeforeClosingRequest, reach, std::time::Instant::now(),
                ));
                ClosingAbsence {
                    detail: format!(
                        "no closing request in the committed GLOBAL view at frame {at}, GLOBAL head {}",
                        head.map_or_else(|| "unknown".to_string(), |head| head.to_string()),
                    ),
                    refreshing,
                }
            }
            Err(error) => absent(format!("closing request unreadable at committed GLOBAL frame {at}: {error}")),
        }
    }

    /// The authorized checkpoint at the local materialized tip; when
    /// `selected`, only if it is the selected parent.
    fn authorized(&self, context: ProposalContext, selected: bool) -> Result<AuthorizedParent> {
        self.check_staged()?;
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
        if selected && (digest != context.parent.0 || view_number != context.parent_view) {
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
        self.check_staged()?;
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

/// The canonical GLOBAL `FrameHeader` of a finalized app frame, its
/// certificate carried in the signature field as the frame stores it: what a
/// member submits for the frame's work, and a seal's drain header.
pub fn canonical_header(frame: &quil_types::proto::global::AppShardFrame) -> Result<Vec<u8>> {
    let header = frame.header.as_ref().ok_or_else(|| unavailable("stored frame has no header"))?;
    quil_execution::global_intrinsic::frame_header::FrameHeader {
        address: header.address.clone(),
        frame_number: header.frame_number,
        rank: header.rank,
        timestamp: header.timestamp,
        difficulty: header.difficulty,
        output: header.output.clone(),
        parent_selector: header.parent_selector.clone(),
        requests_root: header.requests_root.clone(),
        state_roots: header.state_roots.clone(),
        prover: header.prover.clone(),
        fee_multiplier_vote: header.fee_multiplier_vote as i64,
        public_key_signature_bls48581: header.public_key_signature_bls48581.as_ref()
            .map(|signature| signature.signature.clone())
            .unwrap_or_default(),
        storage_attestation_root: header.storage_attestation_root.clone(),
        global_frame_number: header.global_frame_number,
        storage_attestation: frame.storage_attestation.as_ref().map(prost::Message::encode_to_vec).unwrap_or_default(),
        fee_total: header.fee_total.clone(),
        settlements: header.settlements.clone(),
        accumulator: header.accumulator.clone(),
        spends: header.spends.clone(),
    }
    .to_canonical_bytes()
}

/// A finalized app frame that carried no requests, rebuilt from the header
/// a GLOBAL frame carries for it ([`canonical_header`], back as a proto
/// `FrameHeader`): the frame its members stored. That header carries the
/// committee's storage attestation, which the body holds beside its header
/// and whose header field stays empty, and a commonware certificate there
/// lacks the empty public key members store with it. The second value says
/// why the frame comes without the attestation its header commits to (a
/// member that held none submitted the header, or the bytes do not decode),
/// so its possession proof cannot be verified; `None` when it carries the
/// attestation or commits to none.
pub fn frame_from_carried_header(
    carried: &quil_types::proto::global::FrameHeader,
) -> (quil_types::proto::global::AppShardFrame, Option<String>) {
    use prost::Message;
    let mut header = carried.clone();
    let encoded = std::mem::take(&mut header.storage_attestation);
    if let Some(signature) = header.public_key_signature_bls48581.as_mut().filter(|signature| {
        signature.public_key.is_none()
            && quil_cw_consensus::app_cert::unwrap_cert_from_header(&signature.signature).is_some()
    }) {
        signature.public_key = Some(quil_types::proto::keys::Bls48581g2PublicKey { key_value: Vec::new() });
    }
    let (storage_attestation, missing) = if encoded.is_empty() {
        let missing = (!header.storage_attestation_root.is_empty())
            .then(|| "the carried header holds no storage attestation".to_string());
        (None, missing)
    } else {
        match quil_types::proto::global::StorageAttestation::decode(encoded.as_slice()) {
            Ok(attestation) => (Some(attestation), None),
            Err(error) => (None, Some(format!("the carried storage attestation does not decode: {error}"))),
        }
    };
    (quil_types::proto::global::AppShardFrame { header: Some(header), requests: Vec::new(), storage_attestation }, missing)
}

/// A finalized seal as submitted: the encoded submission, with the drain
/// headers GLOBAL needs to accept it (#699).
pub struct DrainedSeal {
    pub bytes: Vec<u8>,
    /// The source frame GLOBAL has executed through (its base before any).
    pub executed: u64,
    pub checkpoint: u64,
    pub attached: usize,
    /// Why the drain is what it is: `attached`, `partial` (the next
    /// [`MAX_DRAIN_HEADERS`](quil_execution::global_intrinsic::handoff::MAX_DRAIN_HEADERS)
    /// of more missing; a later submission brings the rest and the seal),
    /// `executed` (GLOBAL has the checkpoint), `inactive` (before the drain
    /// frame) or `too_many` (more missing than one submission carries, before
    /// the partial drain frame; the fence closes the session).
    pub reason: &'static str,
}

/// `base` (an encoded `CertificateSubmission`) with drain headers: the
/// source's stored frames from the one after GLOBAL's committed executed tip
/// through the sealed checkpoint (`handoff::SealSubmission`). GLOBAL accepts a
/// seal only once it has executed its checkpoint frame, and a sealed session's
/// last headers can miss their lockstep window for good. None are attached
/// when GLOBAL has executed the checkpoint or before the drain frame. When
/// more are missing than one submission carries, the next ones are (a partial
/// drain), from the partial drain frame; before it none are, and the fence
/// closes such a session.
pub fn drained_seal(global: &Arc<HypergraphCrdt>, clock: &dyn ClockStore, base: &[u8]) -> Result<DrainedSeal> {
    use quil_execution::global_intrinsic::handoff::{self as h, SealSubmission, MAX_DRAIN_HEADERS};
    let submission = CertificateSubmission::from_canonical_bytes(base)?;
    let view = CommittedView::capture(global)?;
    let id = submission.seal.session;
    let session = h::session(&view, &id)?.ok_or_else(|| unavailable("sealed session is not recorded"))?;
    let executed = h::session_tip(&view, &id)?.map_or(session.base_frame, |tip| tip.frame);
    let checkpoint = submission.seal.checkpoint.frame;
    let plain = |reason| DrainedSeal { bytes: base.to_vec(), executed, checkpoint, attached: 0, reason };
    if executed >= checkpoint {
        return Ok(plain("executed"));
    }
    // The submission lands in a later GLOBAL frame than the one viewed.
    if view.frame().saturating_add(1) < h::seal_drain_frame() {
        return Ok(plain("inactive"));
    }
    let partial = checkpoint - executed > MAX_DRAIN_HEADERS as u64;
    if partial && view.frame().saturating_add(1) < h::seal_recovery_frame() {
        return Ok(plain("too_many"));
    }
    let through = if partial { executed + MAX_DRAIN_HEADERS as u64 } else { checkpoint };
    let drain = (executed + 1..=through)
        .map(|number| canonical_header(&clock.get_shard_clock_frame(&session.filter, number, false)?))
        .collect::<Result<Vec<_>>>()?;
    let attached = drain.len();
    Ok(DrainedSeal {
        bytes: SealSubmission { submission, drain }.to_canonical_bytes()?,
        executed,
        checkpoint,
        attached,
        reason: if partial { "partial" } else { "attached" },
    })
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

/// Same-filter predecessors whose certified outgoing history must be audited
/// before this member can start the successor at its local checkpoint.
/// Fences supply no certified history root; their checkpoint is verified by
/// [`successor_state_matches`] instead of delaying startup for a history audit.
pub fn predecessor_history_sources(
    view: &CommittedView,
    session: &Session,
    cursor: u64,
) -> Result<Vec<(Session, Checkpoint)>> {
    let mut sources = Vec::new();
    for (source, checkpoint) in effective_origins(view, session)?.origins {
        if source.filter == session.filter
            && checkpoint.frame == cursor
            && !handoff::is_fenced(view, &source.id()?)?
        {
            sources.push((source, checkpoint));
        }
    }
    Ok(sources)
}

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
    for (source, checkpoint) in effective_origins(&view, session)?.origins {
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
            let page = fetch(session.filter.clone(), next, checkpoint.frame).await.map_err(|error| match error {
                QuilError::ExecutionUnavailable(message) => unavailable(format!(
                    "generation {} outgoing history (frames {}-{}, sealed root {}): {message}",
                    source.generation, source.base_frame + 1, checkpoint.frame, hex::encode(&checkpoint.history_root[..8]),
                )),
                other => other,
            })?;
            if page.is_empty() {
                return Err(unavailable(format!(
                    "no archive served generation {}'s outgoing records from frame {next} through {}",
                    source.generation, checkpoint.frame,
                )));
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

/// Frames past a fenced checkpoint that [`own_session_chain`] walks at most:
/// a longer local chain is not taken as the session's own. Sessions seen on
/// mainnet ran a few hundred frames past their fence.
const MAX_OWN_CHAIN_FRAMES: u64 = 4096;

/// The prefix of [`fence_rewind`]'s refusal of the frames at a fence.
const FENCE_FRAMES_DIFFER: &str = "local frames at the fence differ from the fenced frame";

/// Why [`fence_rewind`] re-anchors a member whose frames past the fence
/// name its session's genesis but contradict its chain
/// ([`OwnChain::Broken`]).
pub(crate) const OWN_CHAIN_BROKEN: &str = "local frames past the fence do not form this session's chain";

/// What a member's frames past its session's fenced same-filter
/// predecessor checkpoint are ([`own_session_chain`]).
#[derive(Debug, PartialEq, Eq)]
pub enum OwnChain {
    /// The frames from the fence to the materialized cursor are the
    /// session's own: the first names the session's authorized genesis over
    /// the fenced frame, and each later one extends the one before it.
    Held,
    /// The frame after the fence does not name the session's genesis (or is
    /// absent): what lies past the fence is not the session's.
    NotOwn,
    /// The frame after the fence names the session's genesis, but the frames
    /// contradict its chain, for the reason given.
    Broken(String),
    /// The frame after the fence names the session's genesis, but this node
    /// holds too few of the frames to its head to verify the chain (one is
    /// missing, or more than [`MAX_OWN_CHAIN_FRAMES`] lie past the fence): a
    /// shard sync can supply them.
    Unverified(String),
}

/// An [`OwnChain::Held`] that one start found, for a session (its ID), a
/// materialized cursor and the digest of the frame there: the start's later
/// check reuses it instead of walking the frames again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeldOwnChain(Option<([u8; 32], u64, [u8; 32])>);

/// [`own_session_chain`], reusing and recording `held`.
fn own_session_chain_held(
    clock: &dyn ClockStore,
    session: &Session,
    checkpoint: &Checkpoint,
    cursor: u64,
    held: &mut HeldOwnChain,
) -> Result<OwnChain> {
    let head = clock.get_shard_clock_frame(&session.filter, cursor, false).ok()
        .and_then(|frame| frame.header)
        .map(|header| quil_crypto::poseidon::hash_bytes_to_32(&header.output))
        .transpose()?;
    let key = head.map(|head| session.id().map(|id| (id, cursor, head))).transpose()?;
    if key.is_some() && held.0 == key {
        return Ok(OwnChain::Held);
    }
    let chain = own_session_chain(clock, session, checkpoint, cursor)?;
    if chain == OwnChain::Held {
        held.0 = key;
    }
    Ok(chain)
}

/// Lifecycle lines said once per process for a kind, shard filter, session
/// generation and fence frame: a start retried every 10 s repeated them.
/// Bounded; a full set starts over.
static SAID_ONCE: Mutex<std::collections::BTreeSet<(&'static str, Vec<u8>, u64, u64)>> =
    Mutex::new(std::collections::BTreeSet::new());
const MAX_SAID_ONCE: usize = 1024;

/// Whether this process has not yet said `kind` for `session` at `fence`.
fn first_said(kind: &'static str, session: &Session, fence: u64) -> bool {
    let mut said = SAID_ONCE.lock().unwrap_or_else(|e| e.into_inner());
    if said.len() >= MAX_SAID_ONCE {
        said.clear();
    }
    said.insert((kind, session.filter.clone(), session.generation, fence))
}

/// Whether this member's frames past `checkpoint`, the fenced checkpoint
/// `session` is based at, through materialized cursor `cursor`, are
/// `session`'s own chain. A session's first frame names its authorized
/// genesis, not the fenced frame; that genesis derives from the GLOBAL
/// authorization made after the fence, so no frame of the fenced session
/// names it. A member restarting inside its session holds such a chain
/// before GLOBAL has executed any of it, or while GLOBAL's executed tip lies
/// past its head. This only classifies frames this node already stored; it
/// accepts none.
pub fn own_session_chain(
    clock: &dyn ClockStore,
    session: &Session,
    checkpoint: &Checkpoint,
    cursor: u64,
) -> Result<OwnChain> {
    let fence = checkpoint.frame;
    // The clock store holds a shard's frame `n` only as a frame of that
    // shard at `n`: it refuses to commit any other there.
    let header = |number: u64| {
        clock.get_shard_clock_frame(&session.filter, number, false).ok().and_then(|frame| frame.header)
    };
    let Some(first) = header(fence + 1).filter(|first| first.parent_selector == session.genesis) else {
        return Ok(OwnChain::NotOwn);
    };
    if session.base_frame != fence {
        return Ok(OwnChain::Broken(format!(
            "frame {} names this session's genesis, but the session is based at {}, not at the fence {fence}",
            fence + 1, session.base_frame,
        )));
    }
    let fenced = header(fence).map(|fenced| quil_crypto::poseidon::hash_bytes_to_32(&fenced.output)).transpose()?;
    if fenced != Some(checkpoint.digest) {
        return Ok(OwnChain::Broken(format!("local frame {fence} at the fence is not the fenced frame")));
    }
    let past = cursor.saturating_sub(fence);
    if past > MAX_OWN_CHAIN_FRAMES {
        return Ok(OwnChain::Unverified(format!(
            "{past} frames past the fence exceed the {MAX_OWN_CHAIN_FRAMES} this check walks",
        )));
    }
    let mut parent = first;
    for number in fence + 2..=cursor {
        let Some(child) = header(number) else {
            return Ok(OwnChain::Unverified(format!("no local frame {number} below the head {cursor}")));
        };
        if !crate::frame_validator::app_frame_links_to_child(&parent, &child) {
            return Ok(OwnChain::Broken(format!("local frame {number} does not extend frame {}", number - 1)));
        }
        parent = child;
    }
    Ok(OwnChain::Held)
}

/// The prefix of [`fence_rewind`]'s refusal of frames past a checkpoint
/// that name a looked-through session's genesis but are not its chain.
const ENDED_FRAMES_REFUSED: &str =
    "local frames past the checkpoint name a session GLOBAL ended at its base";

/// A frame header's pre-state roots: the state after the frame before it.
fn header_state_roots(header: &quil_types::proto::global::FrameHeader) -> Result<[[u8; 32]; 4]> {
    header.state_roots.iter()
        .map(|root| <[u8; 32]>::try_from(root.as_slice()).ok())
        .collect::<Option<Vec<_>>>()
        .and_then(|roots| roots.try_into().ok())
        .ok_or_else(|| QuilError::Consensus(format!("frame {} carries malformed state roots", header.frame_number)))
}

/// A rewind refused because its target state is not retained here: a
/// member that pruned it, or never held it.
fn not_retained(error: &QuilError) -> bool {
    matches!(error, QuilError::ExecutionUnavailable(_)) && error.to_string().contains("not retained here")
}

/// Rewind `filter`'s shard from its head `cursor` to frame `to`, whose
/// state has roots `roots`: state, cursor and clock head move back, and the
/// frames past `to` are deleted. Changes nothing when that state is not
/// retained here ([`not_retained`]).
fn rewind_shard(
    shard: &Arc<HypergraphCrdt>,
    clock: &dyn ClockStore,
    filter: &[u8],
    to: u64,
    cursor: u64,
    roots: &[[u8; 32]; 4],
) -> Result<()> {
    shard.rewind_app_shard(filter, roots)?;
    shard.checkpoint_frame_cursor(to, &quil_store::encoding::consensus_materialized_cursor_key(filter))?;
    for frame in to + 1..=cursor {
        shard.invalidate_domain_shard_commit(frame, &filter[..32])?;
    }
    let stored = clock.get_latest_shard_clock_frame(filter).ok()
        .and_then(|frame| frame.header.map(|header| header.frame_number))
        .unwrap_or(cursor);
    clock.set_latest_shard_clock_frame_number(filter, to)?;
    clock.delete_shard_clock_frame_range(filter, to + 1, cursor.max(stored) + 1)
}

/// Whether this member holds `session`'s frame at GLOBAL's executed tip
/// `tip` of it, past `checkpoint`, with its cursor at or past that tip: it
/// is on the session's own chain there, whatever its frames below hold (an
/// archive bootstrap onto the chain keeps the frames below its anchor).
fn holds_executed_tip(clock: &dyn ClockStore, session: &Session, checkpoint: &Checkpoint, tip: &Checkpoint, cursor: u64) -> bool {
    tip.frame > checkpoint.frame
        && cursor >= tip.frame
        && clock.get_shard_clock_frame(&session.filter, tip.frame, false).ok()
            .and_then(|frame| frame.header)
            .and_then(|header| quil_crypto::poseidon::hash_bytes_to_32(&header.output).ok())
            == Some(tip.digest)
}

/// [`fence_rewind`] of a member holding, past `checkpoint`, the frames of a
/// session [`effective_origins`] looked through to it (`looked_through`).
/// GLOBAL ended that session at its base, this checkpoint, having executed
/// none of its frames, and authorized this session from the checkpoint:
/// the frames are discarded whether the checkpoint was sealed or fenced.
/// Rewinds to the checkpoint when the frame after it names that session's
/// genesis over the checkpoint frame, with the checkpoint's state where the
/// checkpoint certifies one (a fence at a tip carries no roots), and the
/// frames to the head `cursor` extend it. `None` when that frame names no
/// looked-through session's genesis, or GLOBAL's executed tip of this
/// session vouches for the member's head ([`holds_executed_tip`]). Frames
/// it cannot verify here (no or another frame at the checkpoint, a hole, a
/// chain that does not link or is too long to walk, another pre-state) are
/// unrewindable, for a re-anchor at the checkpoint to replace. A member
/// behind GLOBAL's executed tip whose frames below an archive anchor are the
/// ended session's is such a case: it is re-anchored rather than caught up.
/// Frames of a session GLOBAL executed are refused.
fn rewind_looked_through(
    view: &CommittedView,
    shard: &Arc<HypergraphCrdt>,
    clock: &dyn ClockStore,
    session: &Session,
    checkpoint: &Checkpoint,
    looked_through: &[Session],
    cursor: u64,
) -> Result<Option<FenceRewind>> {
    let header = |number: u64| {
        clock.get_shard_clock_frame(&session.filter, number, false).ok().and_then(|frame| frame.header)
    };
    let Some(first) = header(checkpoint.frame + 1) else {
        return Ok(None);
    };
    let Some(ended) = looked_through.iter().find(|ended| first.parent_selector == ended.genesis) else {
        return Ok(None);
    };
    let executed = handoff::session_tip(view, &session.id()?)?;
    if executed.as_ref().is_some_and(|tip| holds_executed_tip(clock, session, checkpoint, tip, cursor)) {
        return Ok(None);
    }
    let tip = executed.as_ref().map(|tip| tip.frame);
    let refuse = |detail: String| {
        fence_refusal(ENDED_FRAMES_REFUSED, &format!("generation {}: {detail}", ended.generation), session, cursor, tip)
    };
    let unrewindable = |reason: &'static str, error: Option<QuilError>| -> Result<Option<FenceRewind>> {
        Ok(Some(FenceRewind::Unrewindable {
            fence: UnrewindableFence {
                generation: session.generation, local_head: cursor, fence: checkpoint.frame, session_tip: tip, reason,
            },
            error,
        }))
    };
    // GLOBAL ends a session at its base only while it has executed none of
    // its frames; frames it executed are never discarded.
    if handoff::session_tip(view, &ended.id()?)?.is_some() {
        return Err(refuse("GLOBAL executed frames of the session".into()));
    }
    let at_checkpoint = header(checkpoint.frame)
        .map(|frame| quil_crypto::poseidon::hash_bytes_to_32(&frame.output))
        .transpose()?;
    match at_checkpoint {
        None => return unrewindable("no local frame at the checkpoint", None),
        Some(digest) if digest != checkpoint.digest => {
            return unrewindable("local frame at the checkpoint is not the checkpoint's", None);
        }
        Some(_) => {}
    }
    // The walk that tells a session's own frames past its base, here for
    // the looked-through session's.
    match own_session_chain(clock, ended, checkpoint, cursor)? {
        OwnChain::Held => {}
        OwnChain::NotOwn => return Ok(None),
        OwnChain::Broken(_) => {
            return unrewindable("local frames past the checkpoint do not form the ended session's chain", None);
        }
        OwnChain::Unverified(_) => return unrewindable("local frames past the checkpoint are incomplete", None),
    }
    let roots = header_state_roots(&first)?;
    if checkpoint.state_roots != [[0; 32]; 4] && roots != checkpoint.state_roots {
        return unrewindable("local frame after the checkpoint starts from state other than the checkpoint's", None);
    }
    match rewind_shard(shard, clock, &session.filter, checkpoint.frame, cursor, &roots) {
        Ok(()) => {}
        Err(error) if not_retained(&error) => return unrewindable("checkpoint state not retained locally", Some(error)),
        Err(error) => return Err(error),
    }
    tracing::warn!(
        filter = hex::encode(&session.filter), generation = session.generation,
        ended_generation = ended.generation, from = cursor, to = checkpoint.frame,
        "rewound shard state past the frames of a session GLOBAL ended at its base without executing them",
    );
    Ok(Some(FenceRewind::Rewound(checkpoint.frame)))
}

/// A refusal of a member's frames past a fence: `prefix`, `detail`, and the
/// shard, session, local head and GLOBAL's executed tip of the session.
fn fence_refusal(prefix: &str, detail: &str, session: &Session, cursor: u64, tip: Option<u64>) -> QuilError {
    QuilError::Consensus(format!(
        "{prefix}: {detail} (filter {}, generation {}, local_head {cursor}, session_tip {})",
        hex::encode(&session.filter), session.generation,
        tip.map_or_else(|| "none".to_string(), |tip| tip.to_string()),
    ))
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
    successor_state_matches_held(global, shard, clock, session, &mut HeldOwnChain::default())
}

/// [`successor_state_matches`], reusing the own chain the start's
/// [`fence_rewind_held`] found.
pub fn successor_state_matches_held(
    global: &Arc<HypergraphCrdt>,
    shard: &Arc<HypergraphCrdt>,
    clock: &dyn ClockStore,
    session: &Session,
    held: &mut HeldOwnChain,
) -> Result<()> {
    let view = CommittedView::capture(global)?;
    for (source, checkpoint) in effective_origins(&view, session)?.origins {
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
            return Err(unavailable(PREDECESSOR_UNRECOVERED));
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
                // fence and it, or a member restarted while its session ran
                // on) catches up first. Before GLOBAL has executed any of the
                // session's frames, a member holding them as the session's
                // own chain ([`own_session_chain`]) resumes too.
                let own_tip = handoff::session_tip(&view, &session.id()?)?
                    .filter(|tip| tip.frame > checkpoint.frame);
                let tip = own_tip.as_ref().map(|tip| tip.frame);
                if let Some(tip) = tip.filter(|tip| cursor < *tip) {
                    return Err(unavailable(format!(
                        "behind this session's executed frames (local_head {cursor}, session_tip {tip})",
                    )));
                }
                let executed = own_tip.and_then(|tip| {
                    let frame = clock.get_shard_clock_frame(&session.filter, tip.frame, false).ok()?;
                    let digest = quil_crypto::poseidon::hash_bytes_to_32(&frame.header?.output).ok()?;
                    Some(digest == tip.digest)
                });
                let refusal = match executed {
                    Some(true) => None,
                    Some(false) => Some("the local frame at this session's executed tip is not the one GLOBAL executed".to_string()),
                    None if tip.is_some() => Some("no local frame at this session's executed tip".to_string()),
                    None => match own_session_chain_held(clock, session, &checkpoint, cursor, held)? {
                        OwnChain::Held => None,
                        OwnChain::NotOwn => Some("the frames past it are not this session's, which GLOBAL has not executed".to_string()),
                        OwnChain::Broken(reason) | OwnChain::Unverified(reason) => Some(reason),
                    },
                };
                if let Some(detail) = refusal {
                    return Err(fence_refusal(
                        "local state is past the predecessor's fenced checkpoint", &detail, session, cursor, tip,
                    ));
                }
                if first_said("own-frames-past-fence", session, checkpoint.frame) {
                    tracing::info!(
                        filter = hex::encode(&session.filter), generation = session.generation,
                        fence = checkpoint.frame, local_head = cursor,
                        session_tip = %tip.map_or_else(|| "none".to_string(), |tip| tip.to_string()),
                        "this session's own frames past its fenced predecessor's checkpoint pass the fence check",
                    );
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
            // An accepted lifecycle state, not a fault: said once, though a
            // worker refused later in its start, such as one not seated,
            // repeats this check every 10 s.
            if first_said("fenced-predecessor-accepted", session, cursor) {
                tracing::info!(
                    filter = hex::encode(&session.filter), generation = session.generation, frame = cursor,
                    "predecessor was fenced after its closing timeout; accepting its checkpoint without \
                     a certified history root",
                );
            }
            continue;
        }
        // Past a sealed checkpoint lies this session's own chain, whose first
        // frame names its genesis.
        if cursor > checkpoint.frame {
            let first = clock.get_shard_clock_frame(&session.filter, checkpoint.frame + 1, false).ok()
                .and_then(|frame| frame.header);
            // A frame there naming another genesis, such as a looked-through
            // session's that [`fence_rewind`] discards, carries state GLOBAL
            // never executed, unless GLOBAL's executed tip of this session
            // vouches for the head above it ([`holds_executed_tip`]). A member
            // behind that tip catches up first. A member holding no frame
            // there, such as an archive-anchored joiner, is not checked here.
            if let Some(first) = first.filter(|first| first.parent_selector != session.genesis) {
                let own_tip = handoff::session_tip(&view, &session.id()?)?;
                let tip = own_tip.as_ref().map(|tip| tip.frame);
                if !own_tip.as_ref().is_some_and(|own| holds_executed_tip(clock, session, &checkpoint, own, cursor)) {
                    if let Some(tip) = tip.filter(|tip| *tip > checkpoint.frame && cursor < *tip) {
                        return Err(unavailable(format!(
                            "behind this session's executed frames (local_head {cursor}, session_tip {tip})",
                        )));
                    }
                    return Err(fence_refusal(
                        "local state is past the predecessor's sealed checkpoint",
                        &format!(
                            "local frame {} names parent {}, not this session's genesis {}",
                            first.frame_number, hex::encode(&first.parent_selector), hex::encode(session.genesis),
                        ),
                        session, cursor, tip,
                    ));
                }
            }
        }
        if cursor == checkpoint.frame {
            if local.roots != checkpoint.state_roots {
                // This member does not hold the state its predecessor sealed
                // (it never held the range, or holds another version). As a
                // recoverable gap it requests the shard sync, which installs
                // the state from an archive pinned to the sealed roots
                // ([`sealed_state_mismatch`]); as a consensus error it retried
                // the same comparison forever. The refusal names both roots.
                return Err(unavailable(SealedStateMismatch {
                    generation: source.generation, frame: checkpoint.frame,
                    local_roots: local.roots, sealed_roots: checkpoint.state_roots,
                }.to_string()));
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

/// Why [`successor_state_matches`] refuses a member at its same-filter
/// predecessor's sealed checkpoint that holds other state there.
pub const SEALED_STATE_DIFFERS: &str = "local state differs from the predecessor's sealed checkpoint";

/// A member whose committed cursor is at its same-filter predecessor's
/// sealed checkpoint, with committed roots other than the sealed ones
/// ([`sealed_state_mismatch`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedStateMismatch {
    /// The predecessor's generation.
    pub generation: u64,
    /// The frame its seal names, at which this member's cursor is.
    pub frame: u64,
    /// This member's committed roots.
    pub local_roots: [[u8; 32]; 4],
    pub sealed_roots: [[u8; 32]; 4],
}

impl SealedStateMismatch {
    /// The first four bytes of each of `roots`, in hex.
    pub fn prefixes(roots: &[[u8; 32]; 4]) -> String {
        roots.iter().map(|root| hex::encode(&root[..4])).collect::<Vec<_>>().join(",")
    }
}

impl std::fmt::Display for SealedStateMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{SEALED_STATE_DIFFERS} (generation {} sealed at frame {}: committed roots here {}, sealed roots {})",
            self.generation, self.frame, Self::prefixes(&self.local_roots), Self::prefixes(&self.sealed_roots))
    }
}

/// The [`SealedStateMismatch`] for which [`successor_state_matches`] refuses
/// a member of `filter`'s current session, if any: its committed cursor is at
/// a same-filter origin's sealed (not fenced) checkpoint, the origins taken
/// as [`effective_origins`] gives them, and its committed roots are not the
/// sealed ones. Such a member has no frame to replay: the shard sync installs
/// the sealed state, pinned to its roots, instead.
pub fn sealed_state_mismatch(
    global: &Arc<HypergraphCrdt>,
    shard: &Arc<HypergraphCrdt>,
    filter: &[u8],
) -> Result<Option<SealedStateMismatch>> {
    let view = CommittedView::capture(global)?;
    let Some(session) = handoff::head(&view, filter)? else { return Ok(None) };
    let origins = match effective_origins(&view, &session) {
        Ok(effective) => effective.origins,
        Err(QuilError::ExecutionUnavailable(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    for (source, checkpoint) in origins {
        if source.filter != filter || handoff::is_fenced(&view, &source.id()?)? {
            continue;
        }
        let local = shard.capture_committed_shard(filter)?;
        let cursor = local
            .records
            .read_record(&quil_store::encoding::consensus_materialized_cursor_key(filter))?
            .and_then(|bytes| bytes.as_slice().try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0);
        if cursor == checkpoint.frame && local.roots != checkpoint.state_roots {
            return Ok(Some(SealedStateMismatch {
                generation: source.generation, frame: checkpoint.frame,
                local_roots: local.roots, sealed_roots: checkpoint.state_roots,
            }));
        }
    }
    Ok(None)
}

/// A session's origins as the state it starts from: each same-filter origin
/// that sealed or was fenced at its own base, never having produced a frame,
/// is replaced by that origin's own origins, again and again. Such a
/// checkpoint names only its genesis; its roots are what its closing members
/// held, which nothing checked. Members that had not staged the shard's data
/// sealed their partial roots that way, and every successor then required
/// them, for good. Looking through gives the state the origin was authorized
/// from: the same roots when its members held them, the certified roots below
/// otherwise. Generation zero is not looked through: its base is a certified
/// legacy frame. Each looked-through origin is its successor's predecessor,
/// one generation below it, so the walk ends without a step limit: a limit
/// refused every session of a shard whose committees had sealed at their
/// base more often, and each refused session sealed at its base in turn.
pub struct EffectiveOrigins {
    pub origins: Vec<(Session, quil_cw_consensus::handoff::Checkpoint)>,
    /// A looked-through origin had no origins of its own (a first session):
    /// part of the state was never certified.
    pub uncertified: bool,
    /// The same-filter sessions looked through. Each ended at its base, the
    /// checkpoint frame of the origin it was based at, so GLOBAL executed
    /// none of its frames: a member's frames of one past that checkpoint
    /// are discarded ([`fence_rewind`]).
    pub looked_through: Vec<Session>,
}

pub fn effective_origins(view: &CommittedView, session: &Session) -> Result<EffectiveOrigins> {
    let start = session.id()?;
    let mut origins = Vec::new();
    let mut uncertified = false;
    let mut looked_through = Vec::new();
    let mut pending = vec![(start, session.generation)];
    while let Some((id, generation)) = pending.pop() {
        let direct = handoff::origins(view, &id)?;
        if direct.is_empty() && id != start {
            uncertified = true;
        }
        for (source, checkpoint) in direct {
            let at_base = source.filter == session.filter
                && source.generation != 0
                && checkpoint.frame == source.base_frame
                && checkpoint.digest == source.genesis;
            if at_base {
                if source.generation >= generation {
                    return Err(QuilError::Store("a same-filter origin does not precede its successor".into()));
                }
                pending.push((source.id()?, source.generation));
                looked_through.push(source);
            } else {
                origins.push((source, checkpoint));
            }
        }
    }
    Ok(EffectiveOrigins { origins, uncertified, looked_through })
}

/// The digest (`poseidon(output)`) GLOBAL committed for `filter`'s frame
/// `number`: the executed tip of the shard's current session or of a
/// same-filter origin, or the checkpoint an origin sealed or was fenced at.
/// GLOBAL verified that frame's certificate when it executed or sealed it, so
/// a frame whose output hashes to this digest is authenticated by committed
/// state even when it carries no certificate of its own (a frame final only
/// through a descendant, or a sealed session's last frame).
pub fn committed_frame_digest(global: &Arc<HypergraphCrdt>, filter: &[u8], number: u64) -> Result<Option<[u8; 32]>> {
    committed_frame_digest_in(&CommittedView::capture(global)?, filter, number, false)
}

/// [`committed_frame_digest`], with the origins taken as [`effective_origins`]
/// gives them: a same-filter session sealed or fenced at its base, never
/// having run, is looked through to the checkpoint below it. A shard whose
/// successors each closed at the sealed checkpoint without a frame of their
/// own has only such sessions as direct origins, which name no frame.
pub fn committed_frame_digest_looked_through(
    global: &Arc<HypergraphCrdt>,
    filter: &[u8],
    number: u64,
) -> Result<Option<[u8; 32]>> {
    committed_frame_digest_in(&CommittedView::capture(global)?, filter, number, true)
}

fn committed_frame_digest_in(
    view: &CommittedView,
    filter: &[u8],
    number: u64,
    look_through: bool,
) -> Result<Option<[u8; 32]>> {
    let Some(head) = handoff::head(view, filter)? else { return Ok(None) };
    let tip_of = |session: &Session| -> Result<Option<[u8; 32]>> {
        Ok(handoff::session_tip(view, &session.id()?)?
            .filter(|tip| tip.frame == number)
            .map(|tip| tip.digest))
    };
    if let Some(digest) = tip_of(&head)? {
        return Ok(Some(digest));
    }
    let origins = match look_through.then(|| effective_origins(view, &head)) {
        Some(Ok(effective)) => effective.origins,
        Some(Err(QuilError::ExecutionUnavailable(_))) | None => handoff::origins(view, &head.id()?)?,
        Some(Err(error)) => return Err(error),
    };
    for (source, checkpoint) in origins {
        if source.filter != filter {
            continue;
        }
        if checkpoint.frame == number && checkpoint.frame != source.base_frame {
            return Ok(Some(checkpoint.digest));
        }
        // Frames an origin executed past its checkpoint are not this
        // shard's history: its successor continues from the checkpoint.
        if number > checkpoint.frame {
            continue;
        }
        if let Some(digest) = tip_of(&source)? {
            return Ok(Some(digest));
        }
    }
    Ok(None)
}

/// The frame GLOBAL has executed `filter`'s current session through: its
/// recorded tip, else its base (nothing executed yet). `None` without a
/// session.
pub fn committed_tip(global: &Arc<HypergraphCrdt>, filter: &[u8]) -> Result<Option<u64>> {
    committed_tip_in(&CommittedView::capture(global)?, filter)
}

/// [`committed_tip`] read from a captured `view`.
pub fn committed_tip_in(view: &CommittedView, filter: &[u8]) -> Result<Option<u64>> {
    let Some(session) = handoff::head(view, filter)? else { return Ok(None) };
    Ok(Some(handoff::session_tip(view, &session.id()?)?.map_or(session.base_frame, |tip| tip.frame)))
}

/// [`committed_tip`] of each of `filters` that has a session, read from one
/// committed view; a filter whose records cannot be read is left out.
pub fn committed_tips(global: &Arc<HypergraphCrdt>, filters: &[Vec<u8>]) -> Result<Vec<(Vec<u8>, u64)>> {
    let view = CommittedView::capture(global)?;
    Ok(filters.iter().filter_map(|filter| {
        let session = handoff::head(&view, filter).ok()??;
        let tip = handoff::session_tip(&view, &session.id().ok()?).ok()?;
        Some((filter.clone(), tip.map_or(session.base_frame, |tip| tip.frame)))
    }).collect())
}

/// Whether `ended`, a session of `filter`, is one the current session was
/// looked through to ([`effective_origins`]: same filter, ended at its base,
/// none of its frames executed) at the current session's base, while GLOBAL
/// has executed no frame of the current session. Its base state is then the
/// current session's.
pub fn shares_unexecuted_base(global: &Arc<HypergraphCrdt>, filter: &[u8], ended: &Session) -> Result<bool> {
    let view = CommittedView::capture(global)?;
    let Some(head) = handoff::head(&view, filter)? else { return Ok(false) };
    if handoff::session_tip(&view, &head.id()?)?.is_some() {
        return Ok(false);
    }
    let id = ended.id()?;
    Ok(effective_origins(&view, &head)?.looked_through.iter()
        .any(|through| through.base_frame == head.base_frame && through.id().is_ok_and(|other| other == id)))
}

/// The certified state a member of `filter` with no frame of its own can
/// authenticate an archive's copy against: `(source filter, sealed roots)` for
/// each origin of the shard's current session. The sources partition the
/// shard's range, so syncing each one pinned to its roots yields the shard's
/// state, verified. A same-filter origin sealed or fenced at its base (a
/// session that never ran) is looked through ([`effective_origins`]).
/// Empty when any part of the state has no certified roots: a first session,
/// or a source fenced after it ran (a fence certifies no post-state).
pub fn origin_anchors(global: &Arc<HypergraphCrdt>, filter: &[u8]) -> Result<Vec<(Vec<u8>, [[u8; 32]; 4])>> {
    let view = CommittedView::capture(global)?;
    let Some(session) = handoff::head(&view, filter)? else { return Ok(Vec::new()) };
    let effective = match effective_origins(&view, &session) {
        Ok(effective) => effective,
        Err(QuilError::ExecutionUnavailable(_)) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if effective.uncertified || effective.origins.is_empty() {
        return Ok(Vec::new());
    }
    let mut anchors: Vec<(Vec<u8>, [[u8; 32]; 4])> = Vec::new();
    for (source, checkpoint) in effective.origins {
        if checkpoint.state_roots == [[0; 32]; 4] {
            return Ok(Vec::new());
        }
        if !anchors.iter().any(|(f, roots)| *f == source.filter && *roots == checkpoint.state_roots) {
            anchors.push((source.filter, checkpoint.state_roots));
        }
    }
    Ok(anchors)
}

/// A shard head past its session's fence that this node cannot rewind: the
/// frames above the fence are the fenced predecessor's, which the fence
/// discarded, and the frames or state the rewind needs are not held here.
/// It needs a re-anchor at the fence from an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrewindableFence {
    pub generation: u64,
    /// The shard's materialized cursor.
    pub local_head: u64,
    pub fence: u64,
    /// The frame GLOBAL has executed the session through, if any.
    pub session_tip: Option<u64>,
    pub reason: &'static str,
}

/// What [`fence_rewind`] found.
#[derive(Debug)]
pub enum FenceRewind {
    /// Nothing to rewind: no fenced same-filter origin, a head at or below
    /// the fence, or this session's own frames past it.
    Untouched,
    /// The shard was rewound to this fence frame.
    Rewound(u64),
    /// Discarded frames past the fence that cannot be rewound here. `error`
    /// is the rewind's own refusal when it ran, which is still the result.
    Unrewindable { fence: UnrewindableFence, error: Option<QuilError> },
}

impl FenceRewind {
    /// The re-anchor at the fence a head this node cannot rewind owes
    /// ([`rebase_for_reanchor`]); `None` for anything else.
    pub fn reanchor(&self) -> Option<ReanchorMarker> {
        match self {
            FenceRewind::Unrewindable { fence, .. } => Some(ReanchorMarker {
                generation: fence.generation, fence: fence.fence, from_cursor: fence.local_head, head: None,
            }),
            FenceRewind::Untouched | FenceRewind::Rewound(_) => None,
        }
    }
}

/// [`fence_rewind`] as the fence frame when it rewound. A head it cannot
/// rewind is not rewound, or fails with the rewind's refusal.
pub fn rewind_past_fence(
    global: &Arc<HypergraphCrdt>,
    shard: &Arc<HypergraphCrdt>,
    clock: &dyn ClockStore,
    session: &Session,
) -> Result<Option<u64>> {
    match fence_rewind(global, shard, clock, session)? {
        FenceRewind::Rewound(fence) => Ok(Some(fence)),
        FenceRewind::Unrewindable { error: Some(error), .. } => Err(error),
        FenceRewind::Untouched | FenceRewind::Unrewindable { error: None, .. } => Ok(None),
    }
}

/// A member whose session GLOBAL authorized from a fenced same-filter
/// predecessor, holding shard state past the fence that is not this
/// session's own, holds frames the fence discarded: it can neither continue
/// the fenced session nor start this one. Rewind the shard to the fence. The
/// frame after the fence (this member's own, certified by the fenced
/// session) names the fenced frame's post-state roots, and must build on the
/// frame the fence names. State, cursor and clock head move back to the
/// fence; the discarded frames are deleted. A member without those frames or
/// the fenced state is named as such ([`UnrewindableFence`]) and left as it
/// is, as is one whose own frames past the fence contradict its session's
/// chain ([`OWN_CHAIN_BROKEN`]): both owe a re-anchor.
pub fn fence_rewind(
    global: &Arc<HypergraphCrdt>,
    shard: &Arc<HypergraphCrdt>,
    clock: &dyn ClockStore,
    session: &Session,
) -> Result<FenceRewind> {
    fence_rewind_held(global, shard, clock, session, &mut HeldOwnChain::default())
}

/// [`fence_rewind`], recording in `held` the session's own chain it finds
/// for the start's later [`successor_state_matches_held`].
pub fn fence_rewind_held(
    global: &Arc<HypergraphCrdt>,
    shard: &Arc<HypergraphCrdt>,
    clock: &dyn ClockStore,
    session: &Session,
    held: &mut HeldOwnChain,
) -> Result<FenceRewind> {
    let view = CommittedView::capture(global)?;
    let EffectiveOrigins { origins, looked_through, .. } = effective_origins(&view, session)?;
    for (source, checkpoint) in origins {
        if source.filter != session.filter {
            continue;
        }
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&session.filter);
        let local = shard.capture_committed_shard(&session.filter)?;
        let cursor = local.records.read_record(&cursor_key)?
            .and_then(|bytes| bytes.as_slice().try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0);
        if !handoff::is_fenced(&view, &source.id()?)? {
            // Past a sealed checkpoint lies this session's own chain, which
            // `successor_state_matches` checks, or a looked-through session's.
            if cursor > checkpoint.frame {
                if let Some(outcome) =
                    rewind_looked_through(&view, shard, clock, session, &checkpoint, &looked_through, cursor)?
                {
                    return Ok(outcome);
                }
                // Any other frame there that is not this session's, with no
                // executed tip of it vouching for the head, is state to start
                // over neither (`successor_state_matches` refuses it) nor to
                // rewind here: a re-anchor at the checkpoint replaces it.
                let foreign = clock.get_shard_clock_frame(&session.filter, checkpoint.frame + 1, false).ok()
                    .and_then(|frame| frame.header)
                    .is_some_and(|first| first.parent_selector != session.genesis);
                let executed = handoff::session_tip(&view, &session.id()?)?;
                if foreign && !executed.as_ref().is_some_and(|tip| holds_executed_tip(clock, session, &checkpoint, tip, cursor)) {
                    return Ok(FenceRewind::Unrewindable {
                        fence: UnrewindableFence {
                            generation: session.generation, local_head: cursor, fence: checkpoint.frame,
                            session_tip: executed.map(|tip| tip.frame),
                            reason: "local frame after the checkpoint is not this session's",
                        },
                        error: None,
                    });
                }
            }
            continue;
        }
        if cursor <= checkpoint.frame {
            return Ok(FenceRewind::Untouched);
        }
        // Past the fence is this session's own chain once GLOBAL has executed
        // the session's frames past it and the local frame at that tip is the
        // one GLOBAL executed, as `successor_state_matches` accepts it. A
        // member behind that tip, or whose frame there differs, may still
        // hold the predecessor's discarded frames once the successor has
        // produced: the anchor check below tells them apart.
        let executed = handoff::session_tip(&view, &session.id()?)?;
        let at_tip = executed.as_ref().filter(|tip| tip.frame > checkpoint.frame).and_then(|tip| {
            let frame = clock.get_shard_clock_frame(&session.filter, tip.frame, false).ok()?;
            let digest = quil_crypto::poseidon::hash_bytes_to_32(&frame.header?.output).ok()?;
            Some(digest == tip.digest)
        });
        if at_tip == Some(true) && executed.as_ref().is_some_and(|tip| cursor >= tip.frame) {
            return Ok(FenceRewind::Untouched);
        }
        // A session looked through to this fence, GLOBAL having ended it at
        // its base, left its frames here.
        if let Some(outcome) =
            rewind_looked_through(&view, shard, clock, session, &checkpoint, &looked_through, cursor)?
        {
            return Ok(outcome);
        }
        let unrewindable = |reason: &'static str, error: Option<QuilError>| FenceRewind::Unrewindable {
            fence: UnrewindableFence {
                generation: session.generation, local_head: cursor, fence: checkpoint.frame,
                session_tip: executed.as_ref().map(|tip| tip.frame), reason,
            },
            error,
        };
        // The fenced session's frames anchor before GLOBAL fenced it, at
        // `schedule::fence_due_frame` of its closing request's frame, as
        // GLOBAL dates the fence; this session's at or after that.
        let requested_at = || -> Result<Option<u64>> {
            let request = match handoff::status(&view, &source.id()?)? {
                Status::Sealing(request) | Status::Closed(request) => handoff::request(&view, &request)?,
                Status::Active => None,
            };
            Ok(request.map(|request| request.frame))
        };
        let fenced = clock.get_shard_clock_frame(&session.filter, checkpoint.frame, false);
        let next = clock.get_shard_clock_frame(&session.filter, checkpoint.frame + 1, false);
        let (fenced, next) = match (fenced, next) {
            (Ok(fenced), Ok(next)) => (fenced, next),
            (fenced, next) => {
                // A member that holds no frame at the fence or after it
                // joined after it (by an archive sync onto this session's
                // chain), with nothing here to rewind, or holds the
                // predecessor's discarded frames without the ones a rewind
                // needs (an archive-installed head). A frame past the fence
                // anchored before GLOBAL fenced it, or a frame at the
                // session's executed tip that differs from GLOBAL's, says
                // which. Unknown counts as a joiner.
                let discarded = at_tip == Some(false) || requested_at().ok().flatten().map(schedule::fence_due_frame).is_some_and(|due| {
                    let before = |frame: Result<quil_types::proto::global::AppShardFrame>| {
                        frame.ok().and_then(|frame| frame.header).is_some_and(|header| {
                            header.frame_number > checkpoint.frame && header.global_frame_number < due
                        })
                    };
                    before(next)
                        || before(clock.get_shard_clock_frame(&session.filter, cursor, false))
                        || before(clock.get_latest_shard_clock_frame(&session.filter))
                });
                if !discarded {
                    return Ok(FenceRewind::Untouched);
                }
                let reason = if fenced.is_err() { "no local frame at the fence" } else { "no local frame after the fence" };
                return Ok(unrewindable(reason, None));
            }
        };
        let fenced = fenced.header.ok_or_else(|| unavailable("fenced frame has no header"))?;
        let header = next.header.ok_or_else(|| unavailable("frame after the fence has no header"))?;
        let tip = executed.as_ref().map(|tip| tip.frame);
        let differ = |detail: String| fence_refusal(FENCE_FRAMES_DIFFER, &detail, session, cursor, tip);
        let fenced_digest = quil_crypto::poseidon::hash_bytes_to_32(&fenced.output)?;
        if fenced_digest != checkpoint.digest {
            return Err(differ(format!(
                "local frame {} has digest {}, the fenced frame {}",
                checkpoint.frame, hex::encode(fenced_digest), hex::encode(checkpoint.digest),
            )));
        }
        // This session's own frames past the fence, before GLOBAL has
        // executed any or while its executed tip lies past this head, are no
        // predecessor's: kept ([`own_session_chain`]). Its frame at the
        // executed tip differing from GLOBAL's is refused. Too few of its
        // frames to verify, behind the executed tip, are left for the
        // successor check, which asks the shard sync for them.
        //
        // Own frames that contradict the session's chain (a frame that does
        // not extend the one before it) cannot all be the session's, and
        // this node cannot tell which are: refused, the member stayed
        // blocked for good (an operator's node: "local frame 5779 does not
        // extend frame 5778" for 6.5 hours), as no start, sync or replay
        // mends a stored frame below the head. The shard is re-anchored at
        // the frame GLOBAL committed instead: its state is synced pinned to
        // that frame's roots, and the session's later frames are replayed
        // from archives, each linked to its parent. A head GLOBAL's
        // executed tip vouches for returned untouched above.
        let behind = tip.is_some_and(|tip| tip > cursor);
        match own_session_chain_held(clock, session, &checkpoint, cursor, held)? {
            OwnChain::Held if at_tip != Some(false) => return Ok(FenceRewind::Untouched),
            OwnChain::Held => {
                return Err(differ("this session's local frame at its executed tip is not the one GLOBAL executed".into()));
            }
            OwnChain::Unverified(_) if behind => return Ok(FenceRewind::Untouched),
            OwnChain::Broken(reason) => {
                return Ok(unrewindable(OWN_CHAIN_BROKEN, Some(fence_refusal(OWN_CHAIN_BROKEN, &reason, session, cursor, tip))));
            }
            OwnChain::Unverified(reason) => return Err(differ(reason)),
            OwnChain::NotOwn => {}
        }
        if !crate::frame_validator::app_frame_links_to_child(&fenced, &header) {
            return Err(differ(format!(
                "local frame {} names parent {}, neither the fenced frame nor this session's genesis {}",
                header.frame_number, hex::encode(&header.parent_selector), hex::encode(session.genesis),
            )));
        }
        // A frame that extends the fenced frame is the fenced session's,
        // whenever it anchors: this session's first frame names its genesis
        // instead. GLOBAL discarded every frame past the fence.
        let requested = requested_at()?.ok_or_else(|| unavailable("fenced predecessor has no closing request"))?;
        let roots = header_state_roots(&header)?;
        match rewind_shard(shard, clock, &session.filter, checkpoint.frame, cursor, &roots) {
            Ok(()) => {}
            Err(error) if not_retained(&error) => {
                return Ok(unrewindable("fence state not retained locally", Some(error)));
            }
            Err(error) => return Err(error),
        }
        tracing::warn!(
            filter = hex::encode(&session.filter), generation = session.generation,
            from = cursor, to = checkpoint.frame, after_epochs = schedule::fence_after_epochs(requested),
            "rewound shard state to the checkpoint GLOBAL fenced its predecessor at",
        );
        return Ok(FenceRewind::Rewound(checkpoint.frame));
    }
    Ok(FenceRewind::Untouched)
}

/// A shard re-anchor at its session fence whose rebase has not committed
/// ([`rebase_for_reanchor`]). Kept durably from before the shard sync may
/// write the shard's trees until the rebase moves the materialized cursor
/// ([`reanchor_gate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReanchorMarker {
    pub generation: u64,
    /// The fence the head lay past.
    pub fence: u64,
    /// The materialized cursor the re-anchor began at.
    pub from_cursor: u64,
    /// The digest (`poseidon(output)`) of the local frame at `from_cursor`
    /// when the re-anchor began, if there was one.
    pub head: Option<[u8; 32]>,
}

impl ReanchorMarker {
    /// This marker, naming the digest of `filter`'s local frame at its cursor.
    pub fn with_head(mut self, clock: &dyn ClockStore, filter: &[u8]) -> Self {
        self.head = local_frame_digest(clock, filter, self.from_cursor);
        self
    }
}

/// The re-anchor a shard owes once certified archive frames have kept
/// failing to replay onto this worker's trees at materialized cursor
/// `cursor` (a pre-state mismatch): the trees no longer hold the state the
/// local lineage claims, and no replay can bring them back. It anchors at
/// `committed`, the frame GLOBAL committed for the shard
/// ([`committed_tip`]), which must lie above the cursor: the cursor stands
/// as the fence, so the rebase ([`rebase_for_reanchor`]) keeps the lineage
/// through it and drops only frames stored past it, and the trees are
/// synced pinned to the anchor's roots. `None` without a committed frame
/// above the cursor: nothing GLOBAL committed names the state to sync.
pub fn replay_mismatch_reanchor(generation: u64, cursor: u64, committed: Option<u64>) -> Option<ReanchorMarker> {
    committed.filter(|&tip| tip > cursor)
        .map(|_| ReanchorMarker { generation, fence: cursor, from_cursor: cursor, head: None })
}

/// The re-anchor a shard owes when a payload eviction dropped its subtree
/// from this worker's store at materialized cursor `cursor`
/// ([`dropped_lineage`]): as [`replay_mismatch_reanchor`], except that it
/// anchors at the cursor itself when GLOBAL committed no frame above it, as
/// on a shard whose committee stalled at this worker's head. The trees
/// cannot match any frame there, so the shard would otherwise start on an
/// empty subtree; the rebase replaces the local frame at an anchor that is
/// the fence ([`rebase_for_reanchor`]). `None` without a committed frame at
/// or above the cursor.
pub fn evicted_lineage_reanchor(generation: u64, cursor: u64, committed: Option<u64>) -> Option<ReanchorMarker> {
    committed.filter(|&tip| tip >= cursor)
        .map(|_| ReanchorMarker { generation, fence: cursor, from_cursor: cursor, head: None })
}

/// Why a shard owes a re-anchor, read from its marker: a head past its
/// session fence records the fence below that head ([`fence_rewind`]), a
/// persistent replay mismatch records the cursor itself
/// ([`replay_mismatch_reanchor`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReanchorCause {
    /// The head lies past its session's fence on frames the fence discarded.
    PastFence,
    /// The trees no longer hold the state the local lineage claims.
    ReplayMismatch,
}

impl ReanchorCause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PastFence => "head past the session fence",
            Self::ReplayMismatch => "persistent replay mismatch",
        }
    }
}

impl ReanchorMarker {
    /// Why it is owed ([`ReanchorCause`]).
    pub fn cause(&self) -> ReanchorCause {
        if self.from_cursor > self.fence { ReanchorCause::PastFence } else { ReanchorCause::ReplayMismatch }
    }
}

/// What a persistent replay mismatch of `filter` needs of GLOBAL: the frame
/// it committed for the shard ([`committed_tip`]), the head session's
/// generation (0 without one), and whether a re-anchor finds its anchor
/// under that session ([`reanchor_applies`]).
pub fn replay_mismatch_inputs(global: &Arc<HypergraphCrdt>, filter: &[u8]) -> Result<(Option<u64>, u64, bool)> {
    let committed = committed_tip(global, filter)?;
    let view = CommittedView::capture(global)?;
    let generation = handoff::head(&view, filter)?.map_or(0, |head| head.generation);
    Ok((committed, generation, reanchor_applies(global, filter)?))
}

/// The digest (`poseidon(output)`) of `filter`'s local frame `number`, if
/// this node holds it.
pub fn local_frame_digest(clock: &dyn ClockStore, filter: &[u8], number: u64) -> Option<[u8; 32]> {
    let frame = clock.get_shard_clock_frame(filter, number, false).ok()?;
    quil_crypto::poseidon::hash_bytes_to_32(&frame.header?.output).ok()
}

/// What a recorded re-anchor marker means for the shard as it stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReanchorGate {
    /// No marker.
    Absent,
    /// Its rebase has not committed: the trees may hold a partial sync over
    /// the discarded head, and nothing may start on them.
    Owed(ReanchorMarker),
    /// Its rebase committed (the cursor moved), or another frame stands at
    /// the head it was recorded for: it is cleared.
    Stale(ReanchorMarker),
}

/// [`ReanchorGate`] of `marker` at materialized cursor `cursor`, whose
/// local frame has digest `head` (`None`: no frame there). A rebase deletes
/// the head frame before it moves the cursor, so a missing frame at an
/// unmoved cursor is a rebase in progress: still owed.
pub fn reanchor_gate(marker: Option<ReanchorMarker>, cursor: u64, head: Option<[u8; 32]>) -> ReanchorGate {
    let Some(marker) = marker else { return ReanchorGate::Absent };
    if cursor != marker.from_cursor {
        return ReanchorGate::Stale(marker);
    }
    match (marker.head, head) {
        (Some(recorded), Some(found)) if recorded != found => ReanchorGate::Stale(marker),
        _ => ReanchorGate::Owed(marker),
    }
}

/// [`reanchor_gate`] of `marker` for `filter` as its stores stand.
pub fn reanchor_gate_at(
    shard: &Arc<HypergraphCrdt>,
    clock: &dyn ClockStore,
    filter: &[u8],
    marker: Option<ReanchorMarker>,
) -> Result<ReanchorGate> {
    if marker.is_none() {
        return Ok(ReanchorGate::Absent);
    }
    let cursor = shard.read_frame_cursor(&quil_store::encoding::consensus_materialized_cursor_key(filter))?;
    Ok(reanchor_gate(marker, cursor, local_frame_digest(clock, filter, cursor)))
}

#[cfg(test)]
pub fn read_reanchor_marker(clock: &dyn ClockStore, filter: &[u8]) -> Result<Option<ReanchorMarker>> {
    let txn = clock.new_transaction(false)?;
    let value = txn.get(&quil_store::encoding::app_reanchor_key(filter));
    let _ = txn.abort();
    let Some(bytes) = value? else { return Ok(None) };
    decode_reanchor_marker(&bytes)
        .map(Some)
        .ok_or_else(|| QuilError::Store("malformed shard re-anchor marker".into()))
}

/// A marker's bytes: generation, fence and cursor (8-byte BE each), then
/// the head digest (zero for none), which a marker written without it
/// lacks.
fn decode_reanchor_marker(bytes: &[u8]) -> Option<ReanchorMarker> {
    let field = |i: usize| bytes.get(i * 8..i * 8 + 8).and_then(|b| b.try_into().ok()).map(u64::from_be_bytes);
    let head = match bytes.len() {
        24 => None,
        56 => Some(<[u8; 32]>::try_from(&bytes[24..56]).ok()?).filter(|head| *head != [0; 32]),
        _ => return None,
    };
    Some(ReanchorMarker { generation: field(0)?, fence: field(1)?, from_cursor: field(2)?, head })
}

/// [`read_reanchor_marker`] for a check that must not stay blocked: a
/// malformed marker is cleared and reported by its length (`Some(len)`).
/// If the head still lies past the fence, the next rewind check records a
/// fresh marker for it before anything starts.
pub fn load_reanchor_marker(clock: &dyn ClockStore, filter: &[u8]) -> Result<(Option<ReanchorMarker>, Option<usize>)> {
    let txn = clock.new_transaction(false)?;
    let value = txn.get(&quil_store::encoding::app_reanchor_key(filter));
    let _ = txn.abort();
    let Some(bytes) = value? else { return Ok((None, None)) };
    match decode_reanchor_marker(&bytes) {
        Some(marker) => Ok((Some(marker), None)),
        None => {
            clear_reanchor_marker(clock, filter)?;
            Ok((None, Some(bytes.len())))
        }
    }
}

pub fn write_reanchor_marker(clock: &dyn ClockStore, filter: &[u8], marker: &ReanchorMarker) -> Result<()> {
    let mut value = Vec::with_capacity(56);
    for field in [marker.generation, marker.fence, marker.from_cursor] {
        value.extend_from_slice(&field.to_be_bytes());
    }
    value.extend_from_slice(&marker.head.unwrap_or([0; 32]));
    let txn = clock.new_transaction(false)?;
    if let Err(error) = txn.set(&quil_store::encoding::app_reanchor_key(filter), &value) {
        let _ = txn.abort();
        return Err(error);
    }
    txn.commit()
}

pub fn clear_reanchor_marker(clock: &dyn ClockStore, filter: &[u8]) -> Result<()> {
    let txn = clock.new_transaction(false)?;
    if let Err(error) = txn.delete(&quil_store::encoding::app_reanchor_key(filter)) {
        let _ = txn.abort();
        return Err(error);
    }
    txn.commit()
}

/// The materialized cursor at which a payload eviction dropped `filter`'s
/// subtree from this worker's store while its frames and cursor stayed
/// ([`quil_store::encoding::CONSENSUS_APP_LINEAGE_DROPPED`]), while that
/// record still describes the shard: its cursor has not moved since. A
/// record the cursor moved past (a sync or re-anchor installed the state
/// again) is cleared, as is a malformed one.
pub fn dropped_lineage(shard: &HypergraphCrdt, clock: &dyn ClockStore, filter: &[u8]) -> Result<Option<u64>> {
    let txn = clock.new_transaction(false)?;
    let value = txn.get(&quil_store::encoding::app_lineage_dropped_key(filter));
    let _ = txn.abort();
    let Some(bytes) = value? else { return Ok(None) };
    let cursor = shard.read_frame_cursor(&quil_store::encoding::consensus_materialized_cursor_key(filter))?;
    match <[u8; 8]>::try_from(bytes.as_slice()).map(u64::from_be_bytes) {
        Ok(dropped) if dropped == cursor && cursor > 0 => Ok(Some(cursor)),
        _ => {
            clear_dropped_lineage(clock, filter)?;
            Ok(None)
        }
    }
}

pub fn clear_dropped_lineage(clock: &dyn ClockStore, filter: &[u8]) -> Result<()> {
    let txn = clock.new_transaction(false)?;
    if let Err(error) = txn.delete(&quil_store::encoding::app_lineage_dropped_key(filter)) {
        let _ = txn.abort();
        return Err(error);
    }
    txn.commit()
}

/// Whether `anchor` is the frame GLOBAL committed for `filter` at its
/// number: the executed tip of the shard's current session, or a
/// same-filter origin's checkpoint or tip, the origins taken as
/// [`effective_origins`] gives them, as the re-anchor's fence was found
/// ([`fence_rewind`]). A session sealed or fenced at its base, never having
/// run, is looked through to the checkpoint below it: otherwise a fence
/// under such a session could never be re-anchored at until its successor
/// ran, which may need this member. A re-anchor installs nothing else: its
/// validation alone would accept any certified frame of the session.
pub fn anchor_is_committed(
    global: &Arc<HypergraphCrdt>,
    filter: &[u8],
    anchor: &quil_types::proto::global::AppShardFrame,
) -> Result<bool> {
    let Some(header) = anchor.header.as_ref().filter(|header| header.address == filter) else {
        return Ok(false);
    };
    let (number, digest) = (header.frame_number, quil_crypto::poseidon::hash_bytes_to_32(&header.output)?);
    let view = CommittedView::capture(global)?;
    let Some(head) = handoff::head(&view, filter)? else { return Ok(false) };
    let at_tip = |session: &Session| -> Result<bool> {
        Ok(handoff::session_tip(&view, &session.id()?)?
            .is_some_and(|tip| tip.frame == number && tip.digest == digest))
    };
    if at_tip(&head)? {
        return Ok(true);
    }
    let effective = match effective_origins(&view, &head) {
        Ok(effective) => effective,
        Err(QuilError::ExecutionUnavailable(_)) => return Ok(false),
        Err(error) => return Err(error),
    };
    for (source, checkpoint) in effective.origins {
        if source.filter != filter {
            continue;
        }
        if (checkpoint.frame == number && checkpoint.digest == digest) || at_tip(&source)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The anchor a re-anchor attempt found to be the frame GLOBAL committed
/// ([`anchor_is_committed`]). Validated before the tree sync and again at
/// installation, it is accepted the second time though GLOBAL has since
/// executed the successor past it: the head session's tip moves with every
/// frame GLOBAL executes, and an executed frame stays committed.
/// The memo holds only under the head session it was found under: a new
/// session is checked afresh.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CommittedAnchor(Option<([u8; 32], u64, [u8; 32])>);

impl CommittedAnchor {
    /// Whether `anchor` is the frame GLOBAL committed: the one already found
    /// so under the same head session, or one [`anchor_is_committed`]
    /// accepts now, then remembered with that head.
    pub fn accept(
        &mut self,
        global: &Arc<HypergraphCrdt>,
        filter: &[u8],
        anchor: &quil_types::proto::global::AppShardFrame,
    ) -> Result<bool> {
        let Some(header) = anchor.header.as_ref().filter(|header| header.address == filter) else {
            return Ok(false);
        };
        let (frame, digest) = (header.frame_number, quil_crypto::poseidon::hash_bytes_to_32(&header.output)?);
        let view = CommittedView::capture(global)?;
        let Some(head) = handoff::head(&view, filter)?.map(|head| head.id()).transpose()? else {
            return Ok(false);
        };
        if self.remembers(head, frame, digest) {
            return Ok(true);
        }
        let committed = anchor_is_committed(global, filter, anchor)?;
        if committed {
            self.0 = Some((head, frame, digest));
        }
        Ok(committed)
    }

    /// Whether `(frame, digest)` was found committed under head session `head`.
    fn remembers(&self, head: [u8; 32], frame: u64, digest: [u8; 32]) -> bool {
        self.0 == Some((head, frame, digest))
    }
}

/// Whether a re-anchor can still find its anchor under `filter`'s current
/// head session: the head executed frames of its own, or one of its
/// effective origins ([`effective_origins`]) is of this filter, whose
/// checkpoint or tip the anchor is. A later session whose origins are all
/// other shards', or that has none, gives the shard its state another way
/// (its origins' pinned state), and the marker no longer applies. Unknown
/// keeps it: no head (a view behind, or a retired shard, is no proof the
/// fence is gone) or an unresolvable origin.
pub fn reanchor_applies(global: &Arc<HypergraphCrdt>, filter: &[u8]) -> Result<bool> {
    let view = CommittedView::capture(global)?;
    let Some(head) = handoff::head(&view, filter)? else { return Ok(true) };
    if handoff::session_tip(&view, &head.id()?)?.is_some() {
        return Ok(true);
    }
    match effective_origins(&view, &head) {
        Ok(effective) => Ok(continues_filter(&effective.origins, filter)),
        Err(QuilError::ExecutionUnavailable(_)) => Ok(true),
        Err(error) => Err(error),
    }
}

/// `filter`'s current head session, as (generation, effective origins), for
/// naming it; `None` without one, or when its origins do not resolve.
pub fn head_summary(global: &Arc<HypergraphCrdt>, filter: &[u8]) -> Option<(u64, usize)> {
    let view = CommittedView::capture(global).ok()?;
    let head = handoff::head(&view, filter).ok()??;
    let origins = effective_origins(&view, &head).ok()?.origins.len();
    Some((head.generation, origins))
}

/// Whether any of `origins` is of `filter`.
fn continues_filter(origins: &[(Session, Checkpoint)], filter: &[u8]) -> bool {
    origins.iter().any(|(source, _)| source.filter == filter)
}

/// Persist certified `frame` as `filter`'s shard frame `frame_number`. The
/// clock head moves to it only when it is above the head.
pub(crate) fn commit_clock_head(
    clock: &dyn ClockStore,
    filter: &[u8],
    frame: &quil_types::proto::global::AppShardFrame,
    frame_number: u64,
) -> Result<()> {
    let header = frame.header.as_ref().ok_or_else(|| QuilError::InvalidArgument(
        "shard clock frame has no header".into()))?;
    if header.frame_number != frame_number || header.address != filter {
        return Err(QuilError::InvalidArgument("shard clock frame context mismatch".into()));
    }
    let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)?.to_vec();
    // The clock store resolves staged bytes from committed storage, so
    // staging must finish before the canonical/head transaction is built.
    let txn = clock.new_transaction(false)?;
    if let Err(error) = clock.stage_shard_clock_frame(&selector, frame, txn.as_ref()) {
        let _ = txn.abort();
        return Err(error);
    }
    txn.commit()?;
    let txn = clock.new_transaction(false)?;
    if let Err(error) = clock.commit_shard_clock_frame(filter, frame_number, &selector, txn.as_ref(), false) {
        let _ = txn.abort();
        return Err(error);
    }
    txn.commit()
}

/// The local frames a rebase dropped, `from..=to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rebased {
    pub from: u64,
    pub to: u64,
}

/// Rebase a shard whose owed re-anchor ([`ReanchorMarker`]) synced its
/// trees to archive anchor `anchor`'s pre-state (the state after frame
/// `anchor - 1`, which the anchor's header names), before the anchor is
/// replayed. The anchor is at or above the fence. Every local frame from
/// the first past the fence, or from the anchor when that is the fence,
/// up to the old head goes, with its relay records (fee total,
/// settlements, spends, accumulator digest) and shard commits: past the
/// fence they are the fenced predecessor's discarded frames, and frames
/// below a later anchor are never materialized here again, so their
/// records would stay for the relay windows and the session's outgoing
/// history to read. `discard_above` then drops what the caller keeps of
/// frames above `min(anchor - 1, fence)` (finalized records, fee window).
/// The anchor's certified predecessor becomes the clock head and, last,
/// the materialized cursor moves to it, which commits the rebase; the
/// marker is cleared after it. Interrupted before the cursor moves, the
/// re-anchor stays owed and repeats every step.
pub fn rebase_for_reanchor(
    shard: &Arc<HypergraphCrdt>,
    clock: &dyn ClockStore,
    filter: &[u8],
    marker: &ReanchorMarker,
    anchor: u64,
    predecessor: Option<&quil_types::proto::global::AppShardFrame>,
    discard_above: impl FnOnce(u64) -> Result<()>,
) -> Result<Rebased> {
    use quil_store::encoding;
    let app = filter.get(..32).ok_or_else(|| QuilError::InvalidArgument("a re-anchor needs a shard filter".into()))?;
    if anchor < marker.fence {
        return Err(QuilError::InvalidArgument("a re-anchor never anchors below its fence".into()));
    }
    let synced_to = anchor.checked_sub(1)
        .ok_or_else(|| QuilError::InvalidArgument("a re-anchor needs an anchor above genesis".into()))?;
    let cursor_key = encoding::consensus_materialized_cursor_key(filter);
    let cursor = shard.read_frame_cursor(&cursor_key)?;
    let stored = clock.get_latest_shard_clock_frame(filter).ok()
        .and_then(|frame| frame.header.map(|header| header.frame_number))
        .unwrap_or(0);
    let top = cursor.max(stored).max(marker.from_cursor);
    let from = anchor.min(marker.fence.saturating_add(1));
    if from <= top {
        let records = clock.new_transaction(false)?;
        for frame in from..=top {
            for key in [
                encoding::clock_shard_frame_fee_total_key(filter, frame),
                encoding::clock_shard_frame_settlements_key(filter, frame),
                encoding::clock_shard_frame_spends_key(filter, frame),
                encoding::clock_shard_frame_accumulator_key(filter, frame),
            ] {
                if let Err(error) = records.delete(&key) {
                    let _ = records.abort();
                    return Err(error);
                }
            }
        }
        records.commit()?;
        for frame in from..=top {
            shard.invalidate_domain_shard_commit(frame, app)?;
        }
        clock.delete_shard_clock_frame_range(filter, from, top + 1)?;
    }
    // Before the cursor moves: a crash after it would leave records above
    // the cursor that a later start replays into the successor.
    discard_above(synced_to.min(marker.fence))?;
    clock.set_latest_shard_clock_frame_number(filter, synced_to)?;
    if synced_to > 0 {
        let predecessor = predecessor
            .ok_or_else(|| QuilError::InvalidArgument("a re-anchor needs its anchor's predecessor".into()))?;
        commit_clock_head(clock, filter, predecessor, synced_to)?;
    }
    shard.checkpoint_frame_cursor(synced_to, &cursor_key)?;
    clear_reanchor_marker(clock, filter)?;
    clear_dropped_lineage(clock, filter)?;
    Ok(Rebased { from, to: top })
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

    /// While an archive state sync of GLOBAL installs its chunks, the
    /// committed view is withheld, and a member of the head session keeps
    /// its worker: the wait says nothing about the session, unlike a node
    /// with no GLOBAL state yet. Once the sync is in, the view shows the
    /// archive's state (here without the session).
    #[test]
    fn a_global_sync_between_chunks_withholds_the_view_but_keeps_the_worker() {
        use quil_execution::global_intrinsic::handoff::global_sync_in_progress;
        let (global, state) = global_state();
        let filter = vec![0x0c; 32];
        let (source, _, _) = closing_session(&global, &state, &filter);
        let member = source.members[0].clone();
        assert!(retains_worker(&global, &filter, &member));

        let address = [0xff; 32];
        let archive = Arc::new(HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        for byte in 1..=3u8 {
            let location = quil_hypergraph::Location { app_address: address, data_address: [byte; 32] };
            archive.add_vertex(&location, &[byte; 48]).unwrap();
        }
        archive.commit(1).unwrap();
        let (version, root) = archive.serve_forest_head(&address, 0).unwrap();
        let reader = quil_hypergraph::testing::CrdtTreeReader { source: archive, shard_id: address.to_vec(), phase: 0 };
        let mut plan = global.prepare_phase_sync(&reader, version, &address, 0, &[],
            Some(quil_forest::SubtreeSyncAnchor::AppRoot(root))).unwrap();
        // The archive's records replace the local ones, which it lacks.
        let blob = |(key, leaf): &([u8; 32], Option<Vec<u8>>)| if leaf.is_some() { vec![key[0]; 48] } else { Vec::new() };
        let first = vec![blob(&plan.remaining()[0])];
        global.apply_sync_chunk(&mut plan, &first).unwrap();
        assert!(!plan.remaining().is_empty());
        let error = CommittedView::capture(&global).err().expect("no committed view between a sync's chunks");
        assert!(global_sync_in_progress(&error), "{error}");
        assert!(retains_worker(&global, &filter, &member), "the member keeps its worker while the sync installs");

        let rest: Vec<_> = plan.remaining().iter().map(blob).collect();
        global.apply_sync_chunk(&mut plan, &rest).unwrap();
        assert_eq!(global.finish_phase_sync(&plan).unwrap(), root);
        let view = CommittedView::capture(&global).unwrap();
        assert!(handoff::head(&view, &filter).unwrap().is_none());
        assert!(!retains_worker(&global, &filter, &member));
    }

    /// A member whose cursor is at its predecessor's sealed checkpoint, with
    /// other state there, is refused with the frame and both roots, and
    /// [`sealed_state_mismatch`] names the same, also under a session sealed
    /// at its base: the shard sync installs the sealed state from them. A
    /// member holding the sealed state, or one behind the seal, has none
    /// (…091f80 at frame 4693, 2026-10-23).
    #[test]
    fn a_member_at_a_sealed_checkpoint_with_other_state_is_named_with_both_roots() {
        let (global, state) = global_state();
        let clock = quil_store::RocksClockStore::new(quil_store::RocksDb::open_in_memory().unwrap().inner());
        let filter = vec![0x0b; 32];
        let (source, signers, request) = closing_session(&global, &state, &filter);
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&filter);
        let at = |byte: u8| quil_hypergraph::Location { app_address: [0x0b; 32], data_address: [byte; 32] };
        let member = crdt();
        member.add_vertex(&at(7), &[7; 64]).unwrap();
        let mut history = handoff::history::start(&source).unwrap();
        for frame in 1..=3 {
            member.commit_with_frame_cursor_and_records(frame, &cursor_key, &outflow_records(&filter, frame)).unwrap();
            history = handoff::history::link(history, &outgoing(&filter, frame)).unwrap();
        }
        let sealed = member.capture_committed_shard(&filter).unwrap().roots;
        let seal = Seal {
            request: request.id().unwrap(), session: source.id().unwrap(), view: 9,
            checkpoint: Checkpoint { frame: 3, view: 5, digest: [0x33; 32], state_roots: sealed, history_root: history },
        };
        let certificate = crate::test_support::certify_seal(&source, &signers, &seal);
        handoff::record_session_tip(&state, 4, &seal.session, &seal.checkpoint).unwrap();
        assert!(handoff::apply_submission(&state, 4, &CertificateSubmission { seal, certificate }).unwrap());
        commit(&global, &state, 4);
        let second = handoff::head(&state, &filter).unwrap().unwrap();
        let close = handoff::schedule(&state, 5, vec![filter.clone()], vec![DesiredCommittee {
            filter: filter.clone(), members: second.members.clone(),
        }]).unwrap();
        commit(&global, &state, 5);
        let seal = Seal {
            request: close.id().unwrap(), session: second.id().unwrap(), view: 9,
            checkpoint: Checkpoint {
                frame: 3, view: 0, digest: second.genesis, state_roots: [[0xb0; 32]; 4], history_root: [0xb1; 32],
            },
        };
        let certificate = crate::test_support::certify_seal(&second, &signers, &seal);
        assert!(handoff::apply_submission(&state, 6, &CertificateSubmission { seal, certificate }).unwrap());
        commit(&global, &state, 6);
        let third = handoff::head(&state, &filter).unwrap().unwrap();
        assert_eq!((third.generation, third.base_frame), (3, 3));

        let other = crdt();
        other.add_vertex(&at(9), &[9; 64]).unwrap();
        other.commit_with_frame_cursor_and_records(3, &cursor_key, &outflow_records(&filter, 3)).unwrap();
        let local = other.capture_committed_shard(&filter).unwrap().roots;
        assert_ne!(local, sealed);
        assert_eq!(sealed_state_mismatch(&global, &other, &filter).unwrap(),
            Some(SealedStateMismatch { generation: 1, frame: 3, local_roots: local, sealed_roots: sealed }));
        let error = successor_state_matches(&global, &other, &clock, &third).unwrap_err();
        assert!(matches!(error, QuilError::ExecutionUnavailable(_)), "a recoverable gap: {error}");
        assert_eq!(error.to_string(), format!(
            "execution unavailable: app committee session: local state differs from the predecessor's sealed \
            checkpoint (generation 1 sealed at frame 3: committed roots here {}, sealed roots {})",
            SealedStateMismatch::prefixes(&local), SealedStateMismatch::prefixes(&sealed)));

        assert_eq!(sealed_state_mismatch(&global, &member, &filter).unwrap(), None, "holds the sealed state");
        successor_state_matches(&global, &member, &clock, &third).expect("holds the sealed state");
        let behind = crdt();
        behind.add_vertex(&at(9), &[9; 64]).unwrap();
        behind.commit_with_frame_cursor_and_records(2, &cursor_key, &outflow_records(&filter, 2)).unwrap();
        assert_eq!(sealed_state_mismatch(&global, &behind, &filter).unwrap(), None, "behind the seal: it replays");
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
        let view = CommittedView::capture(&global).unwrap();
        let sources = predecessor_history_sources(&view, &successor, 3).unwrap();
        assert_eq!(sources.len(), 1, "a sealed predecessor still requires its history");
        assert_eq!(sources[0].0.id().unwrap(), source.id().unwrap());
        assert!(predecessor_history_sources(&view, &successor, 2).unwrap().is_empty(),
            "state below the checkpoint must be recovered first");

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
        assert_eq!(schedule::fence_stalled_sources(&state, due, &[left.clone()], None).unwrap(), 1);
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
        assert_eq!(schedule::fence_stalled_sources(&state, later, &[right.clone()], None).unwrap(), 1);
        commit(&global, &state, later);
        assert!(origin_anchors(&global, &right).unwrap().is_empty(), "a source fenced after it ran");
    }

    /// A session sealed at its base never produced a frame: its seal names
    /// only its genesis, with whatever roots its closing members held. Members
    /// that had not staged the shard's data certified partial roots that way,
    /// and every successor then required them. Successors look through it: to
    /// nothing when the chain began with a first session (no requirement, an
    /// unpinned sync), and to the certified checkpoint below otherwise.
    #[test]
    fn a_session_sealed_at_its_base_is_looked_through_to_its_origins() {
        let (global, state) = global_state();
        let clock = quil_store::RocksClockStore::new(quil_store::RocksDb::open_in_memory().unwrap().inner());
        let bogus = [[0xb0; 32]; 4];
        let seal_at_base = |session: &Session, signers: &[quil_crypto::FalconSigner], request: &handoff::Request, frame| {
            let seal = Seal {
                request: request.id().unwrap(), session: session.id().unwrap(), view: 9,
                checkpoint: Checkpoint {
                    frame: session.base_frame, view: 0, digest: session.genesis,
                    state_roots: bogus, history_root: [0xb1; 32],
                },
            };
            let certificate = crate::test_support::certify_seal(session, signers, &seal);
            assert!(handoff::apply_submission(&state, frame, &CertificateSubmission { seal, certificate }).unwrap());
            commit(&global, &state, frame);
            handoff::head(&state, &session.filter).unwrap().unwrap()
        };

        // A first session sealed at its base: nothing below it is certified.
        let first = vec![0x05; 32];
        let (source, signers, request) = closing_session(&global, &state, &first);
        let successor = seal_at_base(&source, &signers, &request, 4);
        assert_eq!((successor.generation, successor.base_frame), (2, 0));
        let holder = crdt();
        holder.add_vertex(&quil_hypergraph::Location { app_address: [0x05; 32], data_address: [9; 32] }, &[9; 64]).unwrap();
        holder.commit(1).unwrap();
        successor_state_matches(&global, &holder, &clock, &successor)
            .expect("the shard's real state is not refused for the roots of a seal at base");
        assert!(origin_anchors(&global, &first).unwrap().is_empty(), "nothing certified: unpinned");

        // A session that ran and sealed its roots, then a successor sealed at
        // its base: the next one requires the certified roots.
        let ran = vec![0x06; 32];
        let (source, signers, request) = closing_session(&global, &state, &ran);
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&ran);
        let member = crdt();
        member.add_vertex(&quil_hypergraph::Location { app_address: [0x06; 32], data_address: [7; 32] }, &[7; 64]).unwrap();
        let mut history = handoff::history::start(&source).unwrap();
        for frame in 1..=3 {
            member.commit_with_frame_cursor_and_records(frame, &cursor_key, &outflow_records(&ran, frame)).unwrap();
            history = handoff::history::link(history, &outgoing(&ran, frame)).unwrap();
        }
        let certified = member.capture_committed_shard(&ran).unwrap().roots;
        let seal = Seal {
            request: request.id().unwrap(), session: source.id().unwrap(), view: 9,
            checkpoint: Checkpoint { frame: 3, view: 5, digest: [0x33; 32], state_roots: certified, history_root: history },
        };
        let certificate = crate::test_support::certify_seal(&source, &signers, &seal);
        handoff::record_session_tip(&state, 5, &seal.session, &seal.checkpoint).unwrap();
        assert!(handoff::apply_submission(&state, 5, &CertificateSubmission { seal, certificate }).unwrap());
        commit(&global, &state, 5);
        let second = handoff::head(&state, &ran).unwrap().unwrap();
        let close = handoff::schedule(&state, 6, vec![ran.clone()], vec![DesiredCommittee {
            filter: ran.clone(), members: second.members.clone(),
        }]).unwrap();
        commit(&global, &state, 6);
        let third = seal_at_base(&second, &signers, &close, 7);
        assert_eq!((third.generation, third.base_frame), (3, 3));
        assert_eq!(origin_anchors(&global, &ran).unwrap(), vec![(ran.clone(), certified)]);
        successor_state_matches(&global, &member, &clock, &third).expect("holds the certified state");
        let other = crdt();
        other.add_vertex(&quil_hypergraph::Location { app_address: [0x06; 32], data_address: [9; 32] }, &[9; 64]).unwrap();
        other.commit_with_frame_cursor_and_records(3, &cursor_key, &outflow_records(&ran, 3)).unwrap();
        let error = successor_state_matches(&global, &other, &clock, &third).unwrap_err();
        assert!(error.to_string().contains("sealed checkpoint"), "other state is still refused: {error}");
    }

    /// A session that ran and sealed at frame 3, then sessions based at the
    /// seal that each sealed at their base: the sealed frame's digest, which
    /// the head's direct origin does not name, still authenticates the
    /// headers an outgoing-history or carry-window read starts from, and
    /// only that frame's (…091f80: generation 12 sealed at frame 4693,
    /// generations 13 to 23 sealed or fenced there, 2026-10-23).
    #[test]
    fn history_reads_take_a_sealed_frame_under_sessions_sealed_at_its_seal() {
        let (global, state) = global_state();
        let filter = vec![0x0a; 32];
        let (source, signers, request) = closing_session(&global, &state, &filter);
        let sealed = [0x3a; 32];
        let seal = Seal {
            request: request.id().unwrap(), session: source.id().unwrap(), view: 9,
            checkpoint: Checkpoint { frame: 3, view: 5, digest: sealed, state_roots: [[4; 32]; 4], history_root: [5; 32] },
        };
        let certificate = crate::test_support::certify_seal(&source, &signers, &seal);
        handoff::record_session_tip(&state, 4, &seal.session, &seal.checkpoint).unwrap();
        assert!(handoff::apply_submission(&state, 4, &CertificateSubmission { seal, certificate }).unwrap());
        commit(&global, &state, 4);
        let mut head = handoff::head(&state, &filter).unwrap().unwrap();
        let committed = |number| crate::app_history_recovery::committed_digest(Some(&global), &filter, number).unwrap();
        assert_eq!(committed(3), Some(sealed), "the sealed checkpoint, a direct origin");
        for frame in [5, 7] {
            let close = handoff::schedule(&state, frame, vec![filter.clone()], vec![DesiredCommittee {
                filter: filter.clone(), members: head.members.clone(),
            }]).unwrap();
            commit(&global, &state, frame);
            let seal = Seal {
                request: close.id().unwrap(), session: head.id().unwrap(), view: 9,
                checkpoint: Checkpoint {
                    frame: head.base_frame, view: 0, digest: head.genesis,
                    state_roots: [[4; 32]; 4], history_root: [0xb1; 32],
                },
            };
            let certificate = crate::test_support::certify_seal(&head, &signers, &seal);
            assert!(handoff::apply_submission(&state, frame + 1, &CertificateSubmission { seal, certificate }).unwrap());
            commit(&global, &state, frame + 1);
            head = handoff::head(&state, &filter).unwrap().unwrap();
        }
        assert_eq!((head.generation, head.base_frame), (4, 3));
        assert_eq!(committed_frame_digest(&global, &filter, 3).unwrap(), None, "direct origins name only a base");
        assert_eq!(committed(3), Some(sealed), "looked through to the seal");
        for number in [2, 4] {
            assert_eq!(committed(number), None);
        }
        assert_eq!(crate::app_history_recovery::committed_digest(None, &filter, 3).unwrap(), None, "no GLOBAL state");
    }

    /// Committees that cannot produce keep sealing at their base, one session
    /// after another. However long that run grows, a successor still looks
    /// through it to the last certified checkpoint, rather than refusing to
    /// start and so sealing at its base too.
    #[test]
    fn a_long_run_of_sessions_sealed_at_their_base_is_looked_through() {
        let (global, state) = global_state();
        let clock = quil_store::RocksClockStore::new(quil_store::RocksDb::open_in_memory().unwrap().inner());
        let filter = vec![0x09; 32];
        let (source, signers, request) = closing_session(&global, &state, &filter);
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&filter);
        let member = crdt();
        member.add_vertex(&quil_hypergraph::Location { app_address: [0x09; 32], data_address: [7; 32] }, &[7; 64]).unwrap();
        let mut history = handoff::history::start(&source).unwrap();
        for frame in 1..=3 {
            member.commit_with_frame_cursor_and_records(frame, &cursor_key, &outflow_records(&filter, frame)).unwrap();
            history = handoff::history::link(history, &outgoing(&filter, frame)).unwrap();
        }
        let certified = member.capture_committed_shard(&filter).unwrap().roots;
        let seal = Seal {
            request: request.id().unwrap(), session: source.id().unwrap(), view: 9,
            checkpoint: Checkpoint { frame: 3, view: 5, digest: [0x33; 32], state_roots: certified, history_root: history },
        };
        let certificate = crate::test_support::certify_seal(&source, &signers, &seal);
        handoff::record_session_tip(&state, 5, &seal.session, &seal.checkpoint).unwrap();
        assert!(handoff::apply_submission(&state, 5, &CertificateSubmission { seal, certificate }).unwrap());
        commit(&global, &state, 5);

        let mut head = handoff::head(&state, &filter).unwrap().unwrap();
        let mut frame = 6;
        for _ in 0..20 {
            let close = handoff::schedule(&state, frame, vec![filter.clone()], vec![DesiredCommittee {
                filter: filter.clone(), members: head.members.clone(),
            }]).unwrap();
            commit(&global, &state, frame);
            let seal = Seal {
                request: close.id().unwrap(), session: head.id().unwrap(), view: 9,
                checkpoint: Checkpoint {
                    frame: head.base_frame, view: 0, digest: head.genesis,
                    state_roots: [[0xb0; 32]; 4], history_root: [0xb1; 32],
                },
            };
            let certificate = crate::test_support::certify_seal(&head, &signers, &seal);
            assert!(handoff::apply_submission(&state, frame + 1, &CertificateSubmission { seal, certificate }).unwrap());
            commit(&global, &state, frame + 1);
            head = handoff::head(&state, &filter).unwrap().unwrap();
            frame += 2;
        }
        assert_eq!((head.generation, head.base_frame), (22, 3));
        let view = CommittedView::capture(&global).unwrap();
        let effective = effective_origins(&view, &head).unwrap();
        assert!(!effective.uncertified);
        assert_eq!(effective.origins.len(), 1);
        assert_eq!((effective.origins[0].0.generation, effective.origins[0].1.frame), (1, 3));
        assert_eq!(origin_anchors(&global, &filter).unwrap(), vec![(filter.clone(), certified)]);
        successor_state_matches(&global, &member, &clock, &head).expect("holds the certified state");
    }

    /// GLOBAL authenticates a frame by the digest it committed for it: the
    /// checkpoint a predecessor sealed, or an executed tip. A seal at a
    /// session's base names its genesis, not a frame, and authenticates none.
    #[test]
    fn committed_frame_digests_are_sealed_checkpoints_and_executed_tips() {
        let (global, state) = global_state();
        let filter = vec![0x07; 32];
        let (source, signers, request) = closing_session(&global, &state, &filter);
        assert_eq!(committed_frame_digest(&global, &filter, 3).unwrap(), None);
        handoff::record_session_tip(&state, 4, &source.id().unwrap(),
            &Checkpoint { frame: 2, view: 3, digest: [0x22; 32], state_roots: [[1; 32]; 4], history_root: [0; 32] }).unwrap();
        commit(&global, &state, 4);
        assert_eq!(committed_frame_digest(&global, &filter, 2).unwrap(), Some([0x22; 32]), "the executed tip");
        let seal = Seal {
            request: request.id().unwrap(), session: source.id().unwrap(), view: 9,
            checkpoint: Checkpoint { frame: 3, view: 5, digest: [0x33; 32], state_roots: [[1; 32]; 4], history_root: [0x44; 32] },
        };
        let certificate = crate::test_support::certify_seal(&source, &signers, &seal);
        handoff::record_session_tip(&state, 5, &seal.session, &seal.checkpoint).unwrap();
        assert!(handoff::apply_submission(&state, 5, &CertificateSubmission { seal, certificate }).unwrap());
        commit(&global, &state, 5);
        let successor = handoff::head(&state, &filter).unwrap().unwrap();
        assert_eq!(successor.generation, 2);
        assert_eq!(committed_frame_digest(&global, &filter, 3).unwrap(), Some([0x33; 32]), "the sealed checkpoint");
        assert_eq!(committed_frame_digest(&global, &filter, 2).unwrap(), None, "below the predecessor's tip");
        assert_eq!(committed_frame_digest(&global, &[0x08; 32], 3).unwrap(), None, "another shard");
        handoff::record_session_tip(&state, 6, &source.id().unwrap(),
            &Checkpoint { frame: 4, view: 6, digest: [0x55; 32], state_roots: [[1; 32]; 4], history_root: [0; 32] }).unwrap();
        commit(&global, &state, 6);
        assert_eq!(committed_frame_digest(&global, &filter, 4).unwrap(), None, "a predecessor's tip past its seal");
    }

    /// A session fenced at its base without an executed frame is looked
    /// through by its successor based at the same frame: its base state is
    /// the successor's until GLOBAL executes a frame of the successor.
    #[test]
    fn a_session_fenced_at_its_base_shares_its_successors_unexecuted_base() {
        let (global, state) = global_state();
        let filter = vec![0x0c; 32];
        let (source, _, _) = closing_session(&global, &state, &filter);
        assert!(!shares_unexecuted_base(&global, &filter, &source).unwrap(), "still the head");
        let due = 3 + schedule::FENCE_AFTER_EPOCHS * quil_types::consensus::epoch_length_frames();
        assert_eq!(schedule::fence_stalled_sources(&state, due, &[filter.clone()], None).unwrap(), 1);
        commit(&global, &state, due);
        let successor = handoff::head(&state, &filter).unwrap().unwrap();
        assert_eq!(successor.base_frame, source.base_frame);
        assert!(shares_unexecuted_base(&global, &filter, &source).unwrap());
        assert!(!shares_unexecuted_base(&global, &filter, &successor).unwrap(), "the head is not looked through");
        handoff::record_session_tip(&state, due + 1, &successor.id().unwrap(), &Checkpoint {
            frame: 1, view: 1, digest: [0x55; 32], state_roots: [[1; 32]; 4], history_root: [0; 32],
        }).unwrap();
        commit(&global, &state, due + 1);
        assert!(!shares_unexecuted_base(&global, &filter, &source).unwrap(), "GLOBAL executed a successor frame");
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
        assert_eq!(schedule::fence_stalled_sources(&state, due, &[filter.clone()], None).unwrap(), 1);
        commit(&global, &state, due);
        assert!(handoff::is_fenced(&CommittedView::capture(&global).unwrap(), &source.id().unwrap()).unwrap());
        assert!(schedule::activated(&CommittedView::capture(&global).unwrap(), &request.id().unwrap()).unwrap());
        let successor = handoff::head(&state, &filter).unwrap().unwrap();
        assert_eq!(successor.base_frame, 3);
        assert!(predecessor_history_sources(
            &CommittedView::capture(&global).unwrap(), &successor, 3,
        ).unwrap().is_empty(), "a fenced predecessor has no certified history to audit");

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
        assert_eq!(schedule::fence_stalled_sources(&state, due, &[filter.clone()], None).unwrap(), 1);
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

        // The successor's own first frame names the session's genesis, not
        // the fenced frame. Before GLOBAL has executed it, it stays.
        shard.add_vertex(&at(4), b"the successor's own").unwrap();
        shard.commit_with_frame_cursor_and_records(4, &cursor_key, &outflow_records(&filter, 4)).unwrap();
        store_frame(quil_types::proto::global::FrameHeader {
            address: filter.clone(), frame_number: 4, rank: 7, output: vec![0x55; 32],
            parent_selector: successor.genesis.to_vec(), global_frame_number: due,
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

    /// A successor member that had materialized the predecessor's frame 4
    /// past the fence GLOBAL set at frame 3, as in
    /// `a_member_past_a_fence_rewinds_its_shard_to_the_fenced_frame`: shard
    /// state, cursor and frames 3 and 4 as the fenced session left them.
    struct PastFence {
        global: Arc<HypergraphCrdt>,
        state: HypergraphState,
        shard: Arc<HypergraphCrdt>,
        clock: quil_store::RocksClockStore,
        _clock_db: quil_store::RocksDb,
        successor: Session,
        filter: Vec<u8>,
        fenced_digest: [u8; 32],
        fenced_roots: [[u8; 32]; 4],
        due: u64,
    }

    impl PastFence {
        /// GLOBAL fences the successor at its base, never having run, and
        /// authorizes the next session from it: also based at the fence.
        fn fence_successor_at_its_base(&self) -> Session {
            let request = handoff::schedule(&self.state, self.due + 1, vec![self.filter.clone()],
                vec![DesiredCommittee { filter: self.filter.clone(), members: self.successor.members.clone() }]).unwrap();
            commit(&self.global, &self.state, self.due + 1);
            let due = schedule::fence_due_frame(request.frame);
            assert_eq!(schedule::fence_stalled_sources(&self.state, due, &[self.filter.clone()], None).unwrap(), 1);
            commit(&self.global, &self.state, due);
            let next = handoff::head(&self.state, &self.filter).unwrap().unwrap();
            assert_eq!((next.generation, next.base_frame), (self.successor.generation + 1, 3));
            next
        }
    }

    fn store_header(clock: &quil_store::RocksClockStore, header: quil_types::proto::global::FrameHeader) {
        use quil_types::store::ClockStore as _;
        let (filter, number) = (header.address.clone(), header.frame_number);
        let frame = quil_types::proto::global::AppShardFrame { header: Some(header), ..Default::default() };
        let selector = vec![number as u8; 32];
        let txn = clock.new_transaction(false).unwrap();
        clock.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
        txn.commit().unwrap();
        let txn = clock.new_transaction(false).unwrap();
        clock.commit_shard_clock_frame(&filter, number, &selector, txn.as_ref(), false).unwrap();
        txn.commit().unwrap();
    }

    fn past_fence() -> PastFence {
        past_fence_due(3 + schedule::FENCE_AFTER_EPOCHS * quil_types::consensus::epoch_length_frames())
    }

    /// [`past_fence`], with GLOBAL fencing the predecessor (requested at
    /// frame 3) at `due` and not at the frame before it.
    fn past_fence_due(due: u64) -> PastFence {
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
        shard.commit_with_frame_cursor_and_records(3, &cursor_key, &outflow_records(&filter, 3)).unwrap();
        let fenced_roots = shard.capture_committed_shard(&filter).unwrap().roots;
        shard.add_vertex(&at(1), b"one, changed after the fence").unwrap();
        shard.commit_with_frame_cursor_and_records(4, &cursor_key, &outflow_records(&filter, 4)).unwrap();
        let fenced_digest = quil_crypto::poseidon::hash_bytes_to_32(&[0x33; 32]).unwrap();
        store_header(&clock, quil_types::proto::global::FrameHeader {
            address: filter.clone(), frame_number: 3, rank: 5, output: vec![0x33; 32], ..Default::default()
        });
        store_header(&clock, quil_types::proto::global::FrameHeader {
            address: filter.clone(), frame_number: 4, rank: 6, output: vec![0x44; 32],
            parent_selector: fenced_digest.to_vec(),
            state_roots: fenced_roots.iter().map(|root| root.to_vec()).collect(),
            ..Default::default()
        });
        handoff::record_session_tip(&state, 4, &source.id().unwrap(),
            &Checkpoint { frame: 3, view: 5, digest: fenced_digest, state_roots: [[1; 32]; 4], history_root: [2; 32] }).unwrap();
        assert_eq!(schedule::fence_stalled_sources(&state, due - 1, &[filter.clone()], None).unwrap(), 0);
        assert_eq!(schedule::fence_stalled_sources(&state, due, &[filter.clone()], None).unwrap(), 1);
        commit(&global, &state, due);
        let successor = handoff::head(&state, &filter).unwrap().unwrap();
        PastFence { global, state, shard, clock, _clock_db: clock_db, successor, filter, fenced_digest, fenced_roots, due }
    }

    impl PastFence {
        /// GLOBAL executes the successor through frame 4, whose output is `output`.
        fn execute_successor(&self, output: u8) {
            handoff::record_session_tip(&self.state, self.due + 1, &self.successor.id().unwrap(), &Checkpoint {
                frame: 4, view: 9, digest: quil_crypto::poseidon::hash_bytes_to_32(&[output; 32]).unwrap(),
                state_roots: [[3; 32]; 4], history_root: [0; 32],
            }).unwrap();
            commit(&self.global, &self.state, self.due + 1);
        }

        fn cursor(&self) -> u64 {
            self.shard.read_frame_cursor(&quil_store::encoding::consensus_materialized_cursor_key(&self.filter)).unwrap()
        }
    }

    // A member still holding the fenced predecessor's frames once the
    // successor has produced past the fence was never rewound: the rewind
    // waited for GLOBAL to have executed nothing past the fence. A member
    // whose frame at the executed tip is not the one GLOBAL executed
    // rewinds all the same, and then holds exactly the fenced frame.
    #[test]
    fn a_member_past_a_fence_rewinds_after_its_successor_has_produced() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        past.execute_successor(0x55);
        assert!(successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).is_err());

        assert_eq!(rewind_past_fence(&past.global, &past.shard, &past.clock, &past.successor).unwrap(), Some(3));
        assert_eq!(past.shard.capture_committed_shard(&past.filter).unwrap().roots, past.fenced_roots);
        assert_eq!(past.cursor(), 3);
        assert!(past.clock.get_shard_clock_frame(&past.filter, 4, false).is_err(), "the discarded frame is deleted");
        successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
    }

    // From the early fence frame GLOBAL fences one epoch after the closing
    // request (`schedule::fence_due_frame`). A frame past the fence that
    // extends the fenced frame is the predecessor's and is discarded, here
    // one anchored the frame before the fence; the successor's own first
    // frame names the session's genesis and stays. The anchor does not tell
    // them apart (`a_frame_extending_the_fence_is_rewound_however_late_it_anchors`).
    #[test]
    fn an_early_fence_rewinds_the_predecessors_frame_and_keeps_the_sessions_own() {
        handoff::set_early_fence_frame_for_thread(Some(0));
        let due = 3 + quil_types::consensus::epoch_length_frames();
        assert_eq!(schedule::fence_due_frame(3), due);
        let past = past_fence_due(due);
        let header = |rank: u64, output: u8, anchor: u64| quil_types::proto::global::FrameHeader {
            address: past.filter.clone(), frame_number: 4, rank, output: vec![output; 32],
            parent_selector: past.fenced_digest.to_vec(), global_frame_number: anchor,
            state_roots: past.fenced_roots.iter().map(|root| root.to_vec()).collect(),
            ..Default::default()
        };
        store_header(&past.clock, header(6, 0x44, due - 1));
        assert_eq!(rewind_past_fence(&past.global, &past.shard, &past.clock, &past.successor).unwrap(), Some(3),
            "extends the fenced frame: the predecessor's");
        assert_eq!(past.cursor(), 3);

        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&past.filter);
        let own = quil_hypergraph::Location { app_address: [0x02; 32], data_address: [4; 32] };
        past.shard.add_vertex(&own, b"the successor's own").unwrap();
        past.shard.commit_with_frame_cursor_and_records(4, &cursor_key, &outflow_records(&past.filter, 4)).unwrap();
        store_header(&past.clock, quil_types::proto::global::FrameHeader {
            parent_selector: past.successor.genesis.to_vec(), ..header(7, 0x55, due)
        });
        assert_eq!(rewind_past_fence(&past.global, &past.shard, &past.clock, &past.successor).unwrap(), None,
            "names the session's genesis: the successor's own");
        assert_eq!(past.cursor(), 4);
        assert_eq!(past.shard.get_vertex_data(&own), Some(b"the successor's own".to_vec()));
        handoff::set_early_fence_frame_for_thread(None);
    }

    // A member whose frame at the executed tip is the one GLOBAL executed
    // holds this session's own chain, whatever its frames' anchors say.
    #[test]
    fn a_member_holding_the_executed_tip_is_not_rewound() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        past.execute_successor(0x44);
        let roots = past.shard.capture_committed_shard(&past.filter).unwrap().roots;
        assert!(matches!(fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap(),
            FenceRewind::Untouched));
        assert_eq!(rewind_past_fence(&past.global, &past.shard, &past.clock, &past.successor).unwrap(), None);
        assert_eq!(past.shard.capture_committed_shard(&past.filter).unwrap().roots, roots);
        assert_eq!(past.cursor(), 4);
        assert!(past.clock.get_shard_clock_frame(&past.filter, 4, false).is_ok());
        successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
    }

    /// The successor's own frames 4 through `through` past the fence at 3,
    /// anchored at the fence, materialized through the last: the first names
    /// the session's genesis, as a session's first frame does, and frame `n`
    /// has output `0x50 | n`.
    fn own_frames(past: &PastFence, through: u64) {
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&past.filter);
        let mut parent = past.successor.genesis;
        for number in 4..=through {
            let output = vec![0x50 | number as u8; 32];
            store_header(&past.clock, quil_types::proto::global::FrameHeader {
                address: past.filter.clone(), frame_number: number, rank: number, output: output.clone(),
                parent_selector: parent.to_vec(), global_frame_number: past.due, ..Default::default()
            });
            parent = quil_crypto::poseidon::hash_bytes_to_32(&output).unwrap();
        }
        past.shard.commit_with_frame_cursor_and_records(through, &cursor_key, &outflow_records(&past.filter, through)).unwrap();
    }

    /// GLOBAL executes the successor through frame `frame`, whose output is `output`.
    fn execute_successor_through(past: &PastFence, frame: u64, output: u8) {
        handoff::record_session_tip(&past.state, past.due + 1, &past.successor.id().unwrap(), &Checkpoint {
            frame, view: 9, digest: quil_crypto::poseidon::hash_bytes_to_32(&[output; 32]).unwrap(),
            state_roots: [[3; 32]; 4], history_root: [0; 32],
        }).unwrap();
        commit(&past.global, &past.state, past.due + 1);
    }

    /// The fenced checkpoint the successor is based at.
    fn fence_of(past: &PastFence) -> Checkpoint {
        let view = CommittedView::capture(&past.global).unwrap();
        effective_origins(&view, &past.successor).unwrap().origins.remove(0).1
    }

    // A member restarted inside its session before GLOBAL executed any of
    // the session's frames holds them past the fence. Its first frame names
    // the session's genesis, not the fenced frame: it is no predecessor's
    // and resumes, unrewound. Refused before as frames that "differ from the
    // fenced frame", the member stayed blocked for its whole session.
    #[test]
    fn a_member_restarted_inside_its_session_before_global_executed_it_resumes() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        own_frames(&past, 5);
        let roots = past.shard.capture_committed_shard(&past.filter).unwrap().roots;
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        assert!(matches!(outcome, FenceRewind::Untouched), "{outcome:?}");
        assert_eq!(rewind_past_fence(&past.global, &past.shard, &past.clock, &past.successor).unwrap(), None);
        assert_eq!(past.shard.capture_committed_shard(&past.filter).unwrap().roots, roots);
        assert_eq!(past.cursor(), 5);
        assert!(past.clock.get_shard_clock_frame(&past.filter, 4, false).is_ok(), "its own frames stay");
        successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
    }

    // A member restarted while its session ran on lies behind GLOBAL's
    // executed tip of the session. It is told to catch up, which requests
    // the shard sync, instead of being refused on its own frames, which
    // requested nothing. Caught up, it resumes.
    #[test]
    fn a_member_restarted_behind_its_sessions_executed_tip_catches_up() {
        let past = past_fence();
        own_frames(&past, 5);
        execute_successor_through(&past, 7, 0x57);
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        assert!(matches!(outcome, FenceRewind::Untouched), "{outcome:?}");
        assert_eq!(past.cursor(), 5);
        let error = successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).unwrap_err();
        assert!(matches!(error, QuilError::ExecutionUnavailable(_)) && error.to_string().contains("behind this session"),
            "{error}");

        own_frames(&past, 7);
        assert!(matches!(fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap(),
            FenceRewind::Untouched));
        successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
    }

    // A frame past the fence that extends the fenced frame is the fenced
    // session's, however late it anchors: GLOBAL discarded every frame past
    // the fence, and this session's own first frame names its genesis. Kept
    // when anchored at or after the fence, it left the member refused on it
    // for good, never rewound or re-anchored.
    #[test]
    fn a_frame_extending_the_fence_is_rewound_however_late_it_anchors() {
        use quil_types::store::ClockStore as _;
        for late in [0, 5] {
            let past = past_fence();
            store_header(&past.clock, quil_types::proto::global::FrameHeader {
                address: past.filter.clone(), frame_number: 4, rank: 6, output: vec![0x44; 32],
                parent_selector: past.fenced_digest.to_vec(), global_frame_number: past.due + late,
                state_roots: past.fenced_roots.iter().map(|root| root.to_vec()).collect(),
                ..Default::default()
            });
            assert_eq!(rewind_past_fence(&past.global, &past.shard, &past.clock, &past.successor).unwrap(), Some(3),
                "anchored {late} frames after the fence");
            assert_eq!(past.cursor(), 3);
            assert!(past.clock.get_shard_clock_frame(&past.filter, 4, false).is_err(), "the discarded frame is deleted");
            successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        }
    }

    // A member behind its session's executed tip with a hole in its own
    // frames cannot verify them, and is asked to sync instead of being
    // refused on them. Without an executed tip past its head it stays
    // refused.
    #[test]
    fn a_hole_in_the_own_frames_behind_the_executed_tip_asks_for_a_sync() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        own_frames(&past, 6);
        past.clock.delete_shard_clock_frame_range(&past.filter, 5, 6).unwrap();
        let error = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap_err();
        assert!(error.to_string().contains("differ from the fenced frame"), "{error}");
        execute_successor_through(&past, 9, 0x59);
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        assert!(matches!(outcome, FenceRewind::Untouched), "{outcome:?}");
        assert_eq!(past.cursor(), 6);
        let error = successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).unwrap_err();
        assert!(matches!(error, QuilError::ExecutionUnavailable(_)) && error.to_string().contains("behind this session"),
            "{error}");
    }

    // Frames past the fence that are not the session's own chain stay
    // refused: a frame after the fence naming neither the fenced frame nor
    // the session's genesis, own frames over a frame at the fence that is not
    // the fenced one, and own frames whose frame at GLOBAL's executed tip is
    // not the one GLOBAL executed. Own frames broken by a frame that does
    // not extend the one before it are re-anchored instead
    // (`own_frames_broken_past_the_fence_are_reanchored`).
    #[test]
    fn frames_past_a_fence_that_are_not_the_sessions_own_chain_stay_refused() {
        let refused = |past: &PastFence, case: &str| {
            let error = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap_err();
            assert!(error.to_string().contains("differ from the fenced frame"), "{case}: {error}");
            let error = successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).unwrap_err();
            assert!(error.to_string().contains("past the predecessor's fenced checkpoint"), "{case}: {error}");
        };
        let past = past_fence();
        own_frames(&past, 5);
        store_header(&past.clock, quil_types::proto::global::FrameHeader {
            address: past.filter.clone(), frame_number: 4, rank: 6, output: vec![0x54; 32],
            parent_selector: vec![0x99; 32], global_frame_number: past.due, ..Default::default()
        });
        refused(&past, "neither parent");

        let past = past_fence();
        own_frames(&past, 5);
        store_header(&past.clock, quil_types::proto::global::FrameHeader {
            address: past.filter.clone(), frame_number: 3, rank: 5, output: vec![0x34; 32], ..Default::default()
        });
        refused(&past, "another frame at the fence");

        let past = past_fence();
        own_frames(&past, 5);
        execute_successor_through(&past, 5, 0x66);
        refused(&past, "another frame at the executed tip");
    }

    // A member's own frames past the fence broken by a frame that does not
    // extend the one before it owe a re-anchor at the frame GLOBAL
    // committed, rather than a refusal for good (an operator's node: "local
    // frame 5779 does not extend frame 5778" for 6.5 hours, nothing owed).
    // Nothing is rewound locally; the rebase drops the frames past the
    // fence, and the anchor's replay leaves a member the successor accepts.
    // Behind GLOBAL's executed tip it is re-anchored at that tip; a head
    // GLOBAL's executed tip vouches for stays untouched whatever lies below.
    #[test]
    fn own_frames_broken_past_the_fence_are_reanchored() {
        use quil_types::store::ClockStore as _;
        let broken = |through: u64| {
            let past = past_fence();
            own_frames(&past, through);
            store_header(&past.clock, quil_types::proto::global::FrameHeader {
                address: past.filter.clone(), frame_number: 5, rank: 5, output: vec![0x55; 32],
                parent_selector: vec![0x99; 32], global_frame_number: past.due, ..Default::default()
            });
            past
        };
        let past = broken(6);
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        let FenceRewind::Unrewindable { fence, error } = &outcome else { panic!("{outcome:?}") };
        assert_eq!((fence.fence, fence.local_head, fence.session_tip, fence.reason), (3, 6, None, OWN_CHAIN_BROKEN));
        let error = error.as_ref().expect("the broken link is named").to_string();
        assert!(error.contains(&format!("{OWN_CHAIN_BROKEN}: local frame 5 does not extend frame 4")) && error.contains("local_head 6"), "{error}");
        assert!(!error.contains(FENCE_FRAMES_DIFFER), "the fenced frame matched: {error}");
        assert_eq!(past.cursor(), 6, "nothing is rewound locally");
        let marker = outcome.reanchor().expect("a broken own chain owes a re-anchor");
        assert_eq!(marker, ReanchorMarker { generation: past.successor.generation, fence: 3, from_cursor: 6, head: None });
        assert_eq!(committed_tip(&past.global, &past.filter).unwrap(), Some(3), "the anchor is the fence");
        let marker = marker.with_head(&past.clock, &past.filter);
        write_reanchor_marker(&past.clock, &past.filter, &marker).unwrap();
        assert_eq!(gate_of(&past), ReanchorGate::Owed(marker));

        // The shard sync installed frame 3's pre-state; the actor rebases.
        let rebased = rebase_for_reanchor(&past.shard, &past.clock, &past.filter, &marker, 3,
            Some(&header_frame(&past.filter, 2, 0x22)), |kept| { assert_eq!(kept, 2); Ok(()) }).unwrap();
        assert_eq!(rebased, Rebased { from: 3, to: 6 });
        assert_eq!(past.cursor(), 2);
        for number in 4..=6 {
            assert!(past.clock.get_shard_clock_frame(&past.filter, number, false).is_err(), "frame {number} is dropped");
        }
        assert_eq!(gate_of(&past), ReanchorGate::Absent);
        // The anchor's replay: the fenced frame and the state after it.
        past.shard.rewind_app_shard(&past.filter, &past.fenced_roots).unwrap();
        store_header(&past.clock, quil_types::proto::global::FrameHeader {
            address: past.filter.clone(), frame_number: 3, rank: 5, output: vec![0x33; 32], ..Default::default()
        });
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&past.filter);
        past.shard.checkpoint_frame_cursor(3, &cursor_key).unwrap();
        assert!(matches!(fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap(),
            FenceRewind::Untouched));
        successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).unwrap();

        // Behind GLOBAL's executed tip: re-anchored at that tip.
        let past = broken(6);
        execute_successor_through(&past, 9, 0x59);
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        assert!(matches!(&outcome, FenceRewind::Unrewindable { fence, error: Some(_) }
            if fence.reason == OWN_CHAIN_BROKEN && fence.session_tip == Some(9)), "{outcome:?}");
        assert_eq!(committed_tip(&past.global, &past.filter).unwrap(), Some(9));

        // A head at GLOBAL's executed tip, its frame the one GLOBAL executed.
        let past = broken(7);
        execute_successor_through(&past, 7, 0x57);
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        assert!(matches!(outcome, FenceRewind::Untouched), "{outcome:?}");
        assert_eq!(past.cursor(), 7);
    }

    // The own-chain check names why frames past a fence are not the
    // session's own, and walks a bounded number of them.
    #[test]
    fn the_own_chain_check_names_why_frames_are_not_the_sessions() {
        let past = past_fence();
        let fence = fence_of(&past);
        assert_eq!(own_session_chain(&past.clock, &past.successor, &fence, 4).unwrap(), OwnChain::NotOwn,
            "the predecessor's discarded frame names the fenced frame");
        own_frames(&past, 6);
        assert_eq!(own_session_chain(&past.clock, &past.successor, &fence, 6).unwrap(), OwnChain::Held);
        match own_session_chain(&past.clock, &past.successor, &fence, 7).unwrap() {
            OwnChain::Unverified(reason) => assert!(reason.contains("no local frame 7"), "{reason}"),
            other => panic!("{other:?}"),
        }
        match own_session_chain(&past.clock, &past.successor, &fence, 3 + MAX_OWN_CHAIN_FRAMES + 1).unwrap() {
            OwnChain::Unverified(reason) => assert!(reason.contains("exceed"), "{reason}"),
            other => panic!("{other:?}"),
        }
        let mut elsewhere = past.successor.clone();
        elsewhere.base_frame = 2;
        match own_session_chain(&past.clock, &elsewhere, &fence, 6).unwrap() {
            OwnChain::Broken(reason) => assert!(reason.contains("not at the fence"), "{reason}"),
            other => panic!("{other:?}"),
        }
        let mut another = past.successor.clone();
        another.genesis = quil_crypto::poseidon::hash_bytes_to_32(&[0x77; 32]).unwrap();
        assert_eq!(own_session_chain(&past.clock, &another, &fence, 6).unwrap(), OwnChain::NotOwn,
            "a frame naming another session's genesis");
        let mut held = HeldOwnChain::default();
        assert_eq!(own_session_chain_held(&past.clock, &past.successor, &fence, 6, &mut held).unwrap(), OwnChain::Held);
        assert_ne!(held, HeldOwnChain::default(), "a held chain is recorded");
        assert_eq!(own_session_chain_held(&past.clock, &another, &fence, 6, &mut held).unwrap(), OwnChain::NotOwn,
            "for its own session only");
        store_header(&past.clock, quil_types::proto::global::FrameHeader {
            address: past.filter.clone(), frame_number: 4, rank: 6, output: vec![0x54; 32],
            parent_selector: vec![0x99; 32], global_frame_number: past.due, ..Default::default()
        });
        let error = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap_err().to_string();
        assert_eq!(own_session_chain(&past.clock, &past.successor, &fence, 6).unwrap(), OwnChain::NotOwn);
        for named in [
            "neither the fenced frame nor this session's genesis".to_string(),
            format!("filter {}", hex::encode(&past.filter)),
            format!("generation {}", past.successor.generation),
            "local_head 6".to_string(),
            "session_tip none".to_string(),
        ] {
            assert!(error.contains(&named), "{named}: {error}");
        }
    }

    /// A predecessor (generation 1) that ended at frame 3, sealed there or
    /// fenced at its executed tip there; a session (generation 2) whose
    /// members finalized frames past it that GLOBAL never executed, so
    /// GLOBAL fenced it at its base; and the successor (generation 3) looked
    /// through it to the predecessor's checkpoint. The member's shard is at
    /// the checkpoint, with frames 1 to 3 materialized. With `runs` above
    /// one, as many sessions in a row ended at their base (`all_ended`).
    struct EndedAtBase {
        global: Arc<HypergraphCrdt>,
        state: HypergraphState,
        shard: Arc<HypergraphCrdt>,
        clock: quil_store::RocksClockStore,
        _clock_db: quil_store::RocksDb,
        filter: Vec<u8>,
        ended: Session,
        all_ended: Vec<Session>,
        successor: Session,
        roots: [[u8; 32]; 4],
        frame: u64,
    }

    fn location(byte: u8) -> quil_hypergraph::Location {
        quil_hypergraph::Location { app_address: [0x02; 32], data_address: [byte; 32] }
    }

    fn ended_at_base(sealed: bool) -> EndedAtBase {
        ended_at_base_runs(sealed, 1)
    }

    fn ended_at_base_runs(sealed: bool, runs: u64) -> EndedAtBase {
        let (global, state) = global_state();
        let filter = vec![0x02; 32];
        let (source, signers, request) = closing_session(&global, &state, &filter);
        let clock_db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(clock_db.inner());
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&filter);
        let shard = crdt();
        shard.set_unified_tree(true);
        let mut history = handoff::history::start(&source).unwrap();
        for frame in 1..=3 {
            if frame == 3 {
                shard.add_vertex(&location(1), b"one").unwrap();
            }
            shard.commit_with_frame_cursor_and_records(frame, &cursor_key, &outflow_records(&filter, frame)).unwrap();
            history = handoff::history::link(history, &outgoing(&filter, frame)).unwrap();
        }
        let roots = shard.capture_committed_shard(&filter).unwrap().roots;
        store_header(&clock, quil_types::proto::global::FrameHeader {
            address: filter.clone(), frame_number: 3, rank: 5, output: vec![0x33; 32], ..Default::default()
        });
        let digest = quil_crypto::poseidon::hash_bytes_to_32(&[0x33; 32]).unwrap();
        let mut frame = if sealed {
            let seal = Seal {
                request: request.id().unwrap(), session: source.id().unwrap(), view: 9,
                checkpoint: Checkpoint { frame: 3, view: 5, digest, state_roots: roots, history_root: history },
            };
            let certificate = crate::test_support::certify_seal(&source, &signers, &seal);
            handoff::record_session_tip(&state, 4, &seal.session, &seal.checkpoint).unwrap();
            assert!(handoff::apply_submission(&state, 4, &CertificateSubmission { seal, certificate }).unwrap());
            commit(&global, &state, 4);
            4
        } else {
            handoff::record_session_tip(&state, 4, &source.id().unwrap(),
                &Checkpoint { frame: 3, view: 5, digest, state_roots: [[1; 32]; 4], history_root: [2; 32] }).unwrap();
            let due = schedule::fence_due_frame(3);
            assert_eq!(schedule::fence_stalled_sources(&state, due, &[filter.clone()], None).unwrap(), 1);
            commit(&global, &state, due);
            due
        };
        let mut all_ended = Vec::new();
        for _ in 0..runs {
            let ended = handoff::head(&state, &filter).unwrap().unwrap();
            assert_eq!(ended.base_frame, 3);
            frame += 1;
            handoff::schedule(&state, frame, vec![filter.clone()], vec![DesiredCommittee {
                filter: filter.clone(), members: ended.members.clone(),
            }]).unwrap();
            commit(&global, &state, frame);
            frame = schedule::fence_due_frame(frame);
            assert_eq!(schedule::fence_stalled_sources(&state, frame, &[filter.clone()], None).unwrap(), 1);
            commit(&global, &state, frame);
            all_ended.push(ended);
        }
        let ended = all_ended[0].clone();
        assert_eq!(ended.generation, 2);
        let due = frame;
        let view = CommittedView::capture(&global).unwrap();
        for ended in &all_ended {
            assert!(handoff::is_fenced(&view, &ended.id().unwrap()).unwrap());
            assert!(handoff::session_tip(&view, &ended.id().unwrap()).unwrap().is_none());
        }
        let successor = handoff::head(&state, &filter).unwrap().unwrap();
        assert_eq!((successor.generation, successor.base_frame), (2 + runs, 3));
        let effective = effective_origins(&view, &successor).unwrap();
        assert_eq!(effective.origins.len(), 1);
        assert_eq!(effective.origins[0].0.id().unwrap(), source.id().unwrap(), "looked through to the predecessor");
        assert_eq!(handoff::is_fenced(&view, &source.id().unwrap()).unwrap(), !sealed);
        EndedAtBase { global, state, shard, clock, _clock_db: clock_db, filter, ended, all_ended, successor, roots, frame: due }
    }

    impl EndedAtBase {
        /// Frames 4 and 5 past the checkpoint, materialized: frame 4 names
        /// `genesis` over the checkpoint's state (as `first` leaves it) and
        /// changes vertex 1, frame 5 extends it and adds vertex 2.
        fn frames(&self, genesis: [u8; 32], first: impl FnOnce(&mut quil_types::proto::global::FrameHeader)) {
            let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&self.filter);
            self.shard.add_vertex(&location(1), b"one, changed past the checkpoint").unwrap();
            self.shard.commit_with_frame_cursor_and_records(4, &cursor_key, &outflow_records(&self.filter, 4)).unwrap();
            self.shard.add_vertex(&location(2), b"added past the checkpoint").unwrap();
            self.shard.commit_with_frame_cursor_and_records(5, &cursor_key, &outflow_records(&self.filter, 5)).unwrap();
            let mut header = quil_types::proto::global::FrameHeader {
                address: self.filter.clone(), frame_number: 4, rank: 6, output: vec![0x44; 32],
                parent_selector: genesis.to_vec(),
                state_roots: self.roots.iter().map(|root| root.to_vec()).collect(),
                ..Default::default()
            };
            first(&mut header);
            store_header(&self.clock, header);
            store_header(&self.clock, quil_types::proto::global::FrameHeader {
                address: self.filter.clone(), frame_number: 5, rank: 7, output: vec![0x45; 32],
                parent_selector: quil_crypto::poseidon::hash_bytes_to_32(&[0x44; 32]).unwrap().to_vec(),
                ..Default::default()
            });
        }

        /// The ended session's frames 4 and 5.
        fn ended_frames(&self) {
            self.frames(self.ended.genesis, |_| {});
        }

        fn cursor(&self) -> u64 {
            self.shard.read_frame_cursor(&quil_store::encoding::consensus_materialized_cursor_key(&self.filter)).unwrap()
        }

        /// The ended session's frames are gone: state, cursor and head are
        /// the checkpoint's, which the successor accepts.
        fn assert_rewound(&self) {
            use quil_types::store::ClockStore as _;
            assert_eq!(self.shard.capture_committed_shard(&self.filter).unwrap().roots, self.roots);
            assert_eq!(self.shard.get_vertex_data(&location(1)), Some(b"one".to_vec()), "a change past it is undone");
            assert_eq!(self.shard.get_vertex_data(&location(2)), None, "an add past it is gone");
            assert_eq!(self.cursor(), 3);
            assert_eq!(self.clock.get_latest_shard_clock_frame(&self.filter).unwrap().header.unwrap().frame_number, 3);
            assert!(self.clock.get_shard_clock_frame(&self.filter, 4, false).is_err(), "frame 4 is deleted");
            assert!(self.clock.get_shard_clock_frame(&self.filter, 5, false).is_err(), "frame 5 is deleted");
            successor_state_matches(&self.global, &self.shard, &self.clock, &self.successor).unwrap();
            assert!(matches!(fence_rewind(&self.global, &self.shard, &self.clock, &self.successor).unwrap(),
                FenceRewind::Untouched), "once");
        }

        /// The member's state, cursor and frames past the checkpoint stay.
        fn assert_kept(&self, roots: [[u8; 32]; 4]) {
            use quil_types::store::ClockStore as _;
            assert_eq!(self.shard.capture_committed_shard(&self.filter).unwrap().roots, roots);
            assert_eq!(self.cursor(), 5);
            assert!(self.clock.get_shard_clock_frame(&self.filter, 4, false).is_ok());
        }
    }

    // A member holding frames of a session GLOBAL ended at its base, having
    // executed none, past its sealed predecessor's checkpoint: the successor
    // is looked through to that checkpoint, and the member started it over
    // the discarded frames' state, for no check ran past a sealed
    // checkpoint. It rewinds to the checkpoint.
    #[test]
    fn frames_of_a_session_ended_at_its_base_are_rewound_to_a_sealed_checkpoint() {
        let ended = ended_at_base(true);
        ended.ended_frames();
        let outcome = fence_rewind(&ended.global, &ended.shard, &ended.clock, &ended.successor).unwrap();
        assert!(matches!(outcome, FenceRewind::Rewound(3)), "{outcome:?}");
        ended.assert_rewound();
    }

    // The same past a predecessor fenced at its tip: refused before as frames
    // that differ from the fenced frame, the member stayed blocked, and no
    // re-anchor followed.
    #[test]
    fn frames_of_a_session_ended_at_its_base_are_rewound_to_a_fenced_checkpoint() {
        let ended = ended_at_base(false);
        ended.ended_frames();
        let outcome = fence_rewind(&ended.global, &ended.shard, &ended.clock, &ended.successor).unwrap();
        assert!(matches!(outcome, FenceRewind::Rewound(3)), "{outcome:?}");
        ended.assert_rewound();
    }

    // A member that no longer holds the checkpoint's state is named as one
    // that cannot rewind here, which a re-anchor at the checkpoint resolves.
    #[test]
    fn frames_of_a_session_ended_at_its_base_without_the_checkpoint_state_are_unrewindable() {
        for sealed in [true, false] {
            let ended = ended_at_base(sealed);
            ended.ended_frames();
            let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&ended.filter);
            let pruned = crdt();
            pruned.set_unified_tree(true);
            pruned.add_vertex(&location(9), b"only the head's state").unwrap();
            pruned.commit_with_frame_cursor_and_records(5, &cursor_key, &outflow_records(&ended.filter, 5)).unwrap();
            let roots = pruned.capture_committed_shard(&ended.filter).unwrap().roots;
            match fence_rewind(&ended.global, &pruned, &ended.clock, &ended.successor).unwrap() {
                FenceRewind::Unrewindable { fence, error: Some(QuilError::ExecutionUnavailable(_)) } => {
                    assert_eq!(fence, UnrewindableFence {
                        generation: 3, local_head: 5, fence: 3, session_tip: None,
                        reason: "checkpoint state not retained locally",
                    }, "sealed {sealed}");
                }
                other => panic!("sealed {sealed}: {other:?}"),
            }
            assert_eq!(pruned.capture_committed_shard(&ended.filter).unwrap().roots, roots);
            assert_eq!(pruned.read_frame_cursor(&cursor_key).unwrap(), 5);
        }
    }

    // The successor's own frames past a sealed checkpoint name its genesis:
    // kept, and accepted, as are a joiner's state without frames there.
    #[test]
    fn the_sessions_own_frames_past_a_sealed_checkpoint_stay() {
        let ended = ended_at_base(true);
        ended.frames(ended.successor.genesis, |_| {});
        let roots = ended.shard.capture_committed_shard(&ended.filter).unwrap().roots;
        let outcome = fence_rewind(&ended.global, &ended.shard, &ended.clock, &ended.successor).unwrap();
        assert!(matches!(outcome, FenceRewind::Untouched), "{outcome:?}");
        ended.assert_kept(roots);
        successor_state_matches(&ended.global, &ended.shard, &ended.clock, &ended.successor).unwrap();

        let joiner_clock_db = quil_store::RocksDb::open_in_memory().unwrap();
        let joiner_clock = quil_store::RocksClockStore::new(joiner_clock_db.inner());
        let joiner = crdt();
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&ended.filter);
        joiner.commit_with_frame_cursor_and_records(5, &cursor_key, &outflow_records(&ended.filter, 5)).unwrap();
        store_header(&joiner_clock, quil_types::proto::global::FrameHeader {
            address: ended.filter.clone(), frame_number: 5, rank: 9, output: vec![0x66; 32], ..Default::default()
        });
        assert!(matches!(fence_rewind(&ended.global, &joiner, &joiner_clock, &ended.successor).unwrap(),
            FenceRewind::Untouched));
        successor_state_matches(&ended.global, &joiner, &joiner_clock, &ended.successor).unwrap();
    }

    // Frames past the checkpoint that are not a looked-through session's
    // discardable chain are neither rewound nor accepted: another parent,
    // another pre-state, another frame at the checkpoint, or a session GLOBAL
    // executed frames of. All but the last are left for a re-anchor.
    #[test]
    fn frames_past_a_checkpoint_that_are_not_an_ended_sessions_chain_stay_refused() {
        let cases: [(&str, fn(&EndedAtBase)); 4] = [
            ("another parent", |ended| ended.frames([0x99; 32], |_| {})),
            ("another pre-state", |ended| ended.frames(ended.ended.genesis, |header| {
                header.state_roots = vec![vec![0x07; 32]; 4];
            })),
            ("another frame at the checkpoint", |ended| {
                ended.ended_frames();
                store_header(&ended.clock, quil_types::proto::global::FrameHeader {
                    address: ended.filter.clone(), frame_number: 3, rank: 5, output: vec![0x34; 32],
                    ..Default::default()
                });
            }),
            ("executed by GLOBAL", |ended| {
                ended.ended_frames();
                handoff::record_session_tip(&ended.state, ended.frame + 1, &ended.ended.id().unwrap(), &Checkpoint {
                    frame: 4, view: 6, digest: quil_crypto::poseidon::hash_bytes_to_32(&[0x44; 32]).unwrap(),
                    state_roots: ended.roots, history_root: [0; 32],
                }).unwrap();
                commit(&ended.global, &ended.state, ended.frame + 1);
            }),
        ];
        for sealed in [true, false] {
            for (case, make) in &cases {
                if !sealed && *case == "another pre-state" {
                    // A fence at a tip certifies no roots to compare.
                    continue;
                }
                let ended = ended_at_base(sealed);
                make(&ended);
                let roots = ended.shard.capture_committed_shard(&ended.filter).unwrap().roots;
                match (fence_rewind(&ended.global, &ended.shard, &ended.clock, &ended.successor), *case) {
                    // A frame there that is not the checkpoint's is one a
                    // re-anchor at the checkpoint replaces.
                    (Ok(FenceRewind::Unrewindable { fence, error: None }), "another frame at the checkpoint")
                        if fence.reason == "local frame at the checkpoint is not the checkpoint's" => {}
                    // Past a sealed checkpoint a frame naming no looked-through
                    // session's genesis is replaced by a re-anchor too.
                    (Ok(FenceRewind::Unrewindable { fence, error: None }), "another parent")
                        if sealed && fence.reason == "local frame after the checkpoint is not this session's" => {}
                    (Ok(FenceRewind::Unrewindable { fence, error: None }), "another pre-state")
                        if fence.reason == "local frame after the checkpoint starts from state other than the checkpoint's" => {}
                    (Err(QuilError::Consensus(_)), "another parent") if !sealed => {}
                    (Err(QuilError::Consensus(_)), "executed by GLOBAL") => {}
                    (other, _) => panic!("{case}, sealed {sealed}: {other:?}"),
                }
                ended.assert_kept(roots);
                let error = successor_state_matches(&ended.global, &ended.shard, &ended.clock, &ended.successor)
                    .unwrap_err();
                assert!(matches!(error, QuilError::Consensus(_)), "{case}, sealed {sealed}: {error}");
            }
        }
    }

    // A successor member an archive bootstrap moved onto the session's chain
    // at the frame GLOBAL executed it through keeps the frames below its
    // anchor, here the ended session's first two: GLOBAL's executed tip
    // vouches for its head, which is neither rewound nor refused. A frame
    // there other than GLOBAL's is refused. Behind the tip nothing vouches
    // for it and the frames below its anchor cannot be walked: it is named
    // unrewindable, which a re-anchor at the checkpoint resolves, while the
    // successor check asks it to catch up.
    #[test]
    fn a_member_at_the_sessions_executed_tip_keeps_stale_frames_below_it() {
        for sealed in [true, false] {
            let ended = ended_at_base(sealed);
            ended.ended_frames();
            let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&ended.filter);
            store_header(&ended.clock, quil_types::proto::global::FrameHeader {
                address: ended.filter.clone(), frame_number: 7, rank: 20, output: vec![0x77; 32], ..Default::default()
            });
            ended.shard.add_vertex(&location(3), b"the successor's state").unwrap();
            ended.shard.commit_with_frame_cursor_and_records(7, &cursor_key, &outflow_records(&ended.filter, 7)).unwrap();
            let tip = |frame: u64, output: u8| Checkpoint {
                frame, view: 20, digest: quil_crypto::poseidon::hash_bytes_to_32(&[output; 32]).unwrap(),
                state_roots: [[3; 32]; 4], history_root: [0; 32],
            };
            handoff::record_session_tip(&ended.state, ended.frame + 1, &ended.successor.id().unwrap(), &tip(7, 0x77)).unwrap();
            commit(&ended.global, &ended.state, ended.frame + 1);
            let roots = ended.shard.capture_committed_shard(&ended.filter).unwrap().roots;
            let outcome = fence_rewind(&ended.global, &ended.shard, &ended.clock, &ended.successor).unwrap();
            assert!(matches!(outcome, FenceRewind::Untouched), "sealed {sealed}: {outcome:?}");
            assert_eq!(ended.shard.capture_committed_shard(&ended.filter).unwrap().roots, roots);
            assert_eq!(ended.cursor(), 7);
            successor_state_matches(&ended.global, &ended.shard, &ended.clock, &ended.successor)
                .unwrap_or_else(|error| panic!("sealed {sealed}: {error}"));

            store_header(&ended.clock, quil_types::proto::global::FrameHeader {
                address: ended.filter.clone(), frame_number: 7, rank: 20, output: vec![0x78; 32], ..Default::default()
            });
            assert!(successor_state_matches(&ended.global, &ended.shard, &ended.clock, &ended.successor).is_err(),
                "sealed {sealed}: another frame at the executed tip");

            store_header(&ended.clock, quil_types::proto::global::FrameHeader {
                address: ended.filter.clone(), frame_number: 7, rank: 20, output: vec![0x77; 32], ..Default::default()
            });
            handoff::record_session_tip(&ended.state, ended.frame + 2, &ended.successor.id().unwrap(), &tip(9, 0x99)).unwrap();
            commit(&ended.global, &ended.state, ended.frame + 2);
            match fence_rewind(&ended.global, &ended.shard, &ended.clock, &ended.successor).unwrap() {
                FenceRewind::Unrewindable { fence, error: None } => assert_eq!(fence, UnrewindableFence {
                    generation: 3, local_head: 7, fence: 3, session_tip: Some(9),
                    reason: "local frames past the checkpoint are incomplete",
                }, "sealed {sealed}"),
                other => panic!("sealed {sealed}: {other:?}"),
            }
            assert_eq!(ended.cursor(), 7);
            let error = successor_state_matches(&ended.global, &ended.shard, &ended.clock, &ended.successor).unwrap_err();
            assert!(matches!(error, QuilError::ExecutionUnavailable(_)) && error.to_string().contains("behind this session"),
                "sealed {sealed}: {error}");
        }
    }

    // A member behind its session's executed tip that holds the frame at
    // the tip above its cursor, over the fenced predecessor's discarded
    // frame: the frame at the tip alone said it was on the session's chain,
    // and its predecessor's state stayed under the frames it caught up.
    // It rewinds to the fence.
    #[test]
    fn a_member_behind_the_executed_tip_still_rewinds_the_predecessors_frames() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        store_header(&past.clock, quil_types::proto::global::FrameHeader {
            address: past.filter.clone(), frame_number: 9, rank: 20, output: vec![0x59; 32], ..Default::default()
        });
        execute_successor_through(&past, 9, 0x59);
        assert_eq!(past.cursor(), 4);
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        assert!(matches!(outcome, FenceRewind::Rewound(3)), "{outcome:?}");
        assert_eq!(past.cursor(), 3);
        assert_eq!(past.shard.capture_committed_shard(&past.filter).unwrap().roots, past.fenced_roots);
        assert!(past.clock.get_shard_clock_frame(&past.filter, 4, false).is_err(), "the discarded frame is deleted");
        successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
    }

    // Frames of an ended session this node cannot verify, with no frame at
    // the checkpoint or a hole below the head, are named unrewindable, for a
    // re-anchor at the checkpoint, rather than refused for good.
    #[test]
    fn unverifiable_frames_of_a_session_ended_at_its_base_are_unrewindable() {
        use quil_types::store::ClockStore as _;
        for sealed in [true, false] {
            for (missing, reason) in [
                (3, "no local frame at the checkpoint"),
                (5, "local frames past the checkpoint are incomplete"),
            ] {
                let ended = ended_at_base(sealed);
                ended.ended_frames();
                ended.clock.delete_shard_clock_frame_range(&ended.filter, missing, missing + 1).unwrap();
                let roots = ended.shard.capture_committed_shard(&ended.filter).unwrap().roots;
                match fence_rewind(&ended.global, &ended.shard, &ended.clock, &ended.successor) {
                    Ok(FenceRewind::Unrewindable { fence, error: None }) => assert_eq!(fence, UnrewindableFence {
                        generation: 3, local_head: 5, fence: 3, session_tip: None, reason,
                    }, "sealed {sealed}"),
                    other => panic!("missing {missing}, sealed {sealed}: {other:?}"),
                }
                ended.assert_kept(roots);
                assert!(successor_state_matches(&ended.global, &ended.shard, &ended.clock, &ended.successor).is_err());
            }
        }
    }

    // Two sessions in a row ended at their base: frames of either are told
    // apart by the genesis they name, and rewound.
    #[test]
    fn frames_of_either_of_two_sessions_ended_at_their_base_are_rewound() {
        for sealed in [true, false] {
            for which in 0..2 {
                let ended = ended_at_base_runs(sealed, 2);
                assert_eq!(ended.all_ended.len(), 2);
                ended.frames(ended.all_ended[which].genesis, |_| {});
                let outcome = fence_rewind(&ended.global, &ended.shard, &ended.clock, &ended.successor).unwrap();
                assert!(matches!(outcome, FenceRewind::Rewound(3)), "sealed {sealed}, session {which}: {outcome:?}");
                ended.assert_rewound();
            }
        }
    }

    // Without the rewind, the successor check alone refuses to start over a
    // looked-through session's frames past a sealed checkpoint, naming them.
    #[test]
    fn the_successor_check_refuses_another_sessions_frames_past_a_sealed_checkpoint() {
        let ended = ended_at_base(true);
        ended.ended_frames();
        let error = successor_state_matches(&ended.global, &ended.shard, &ended.clock, &ended.successor)
            .unwrap_err();
        assert!(matches!(error, QuilError::Consensus(_)), "{error}");
        let error = error.to_string();
        for named in [
            "past the predecessor's sealed checkpoint".to_string(),
            format!("names parent {}", hex::encode(ended.ended.genesis)),
            format!("filter {}", hex::encode(&ended.filter)),
            "generation 3".to_string(),
            "local_head 5".to_string(),
        ] {
            assert!(error.contains(&named), "{named}: {error}");
        }
    }

    // A frame of another shard cannot stand as the shard's frame after the
    // fence, even naming the session's genesis: the clock store refuses to
    // commit it there, which the own-chain check relies on.
    #[test]
    fn a_first_frame_of_another_shard_cannot_stand_after_the_fence() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        own_frames(&past, 5);
        let frame = quil_types::proto::global::AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: vec![0x03; 32], frame_number: 4, rank: 4, output: vec![0x54; 32],
                parent_selector: past.successor.genesis.to_vec(), global_frame_number: past.due, ..Default::default()
            }),
            ..Default::default()
        };
        let selector = vec![0xf4; 32];
        let txn = past.clock.new_transaction(false).unwrap();
        past.clock.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
        txn.commit().unwrap();
        let txn = past.clock.new_transaction(false).unwrap();
        assert!(past.clock.commit_shard_clock_frame(&past.filter, 4, &selector, txn.as_ref(), false).is_err());
        let _ = txn.abort();
        assert_eq!(own_session_chain(&past.clock, &past.successor, &fence_of(&past), 5).unwrap(), OwnChain::Held,
            "the session's own frame 4 still stands");
    }

    // A start at a fenced predecessor's checkpoint says once, at info, that
    // it accepts the checkpoint, however often the start is retried: it
    // warned at every 10 s retry of a worker refused later in its start.
    #[test]
    fn a_start_at_a_fence_says_once_that_the_predecessor_was_fenced() {
        let (global, state) = global_state();
        let filter = vec![0x0c; 32];
        let (source, _, _) = closing_session(&global, &state, &filter);
        let clock_db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(clock_db.inner());
        store_header(&clock, quil_types::proto::global::FrameHeader {
            address: filter.clone(), frame_number: 3, rank: 5, output: vec![0x33; 32], ..Default::default()
        });
        let digest = quil_crypto::poseidon::hash_bytes_to_32(&[0x33; 32]).unwrap();
        handoff::record_session_tip(&state, 4, &source.id().unwrap(),
            &Checkpoint { frame: 3, view: 5, digest, state_roots: [[1; 32]; 4], history_root: [2; 32] }).unwrap();
        let due = 3 + schedule::FENCE_AFTER_EPOCHS * quil_types::consensus::epoch_length_frames();
        assert_eq!(schedule::fence_stalled_sources(&state, due, &[filter.clone()], None).unwrap(), 1);
        commit(&global, &state, due);
        let successor = handoff::head(&state, &filter).unwrap().unwrap();
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&filter);
        let at_fence = crdt();
        at_fence.commit_with_frame_cursor_and_records(3, &cursor_key, &outflow_records(&filter, 3)).unwrap();

        let logs = crate::outage::test_logs::CapturedLogs::default();
        let _guard = logs.install();
        for _ in 0..3 {
            successor_state_matches(&global, &at_fence, &clock, &successor).unwrap();
        }
        let lines = logs.lines_with("predecessor was fenced");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("INFO"), "{lines:?}");
    }

    // A member past the fence on the predecessor's discarded frames without
    // the fenced frame (an archive-installed head), or without the fenced
    // state, cannot rewind here: the check names why and leaves the shard
    // as it was, with the rewind's refusal still its result. A joiner on
    // the successor's chain is not named.
    #[test]
    fn a_member_past_a_fence_that_cannot_rewind_here_is_named() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        past.clock.delete_shard_clock_frame_range(&past.filter, 3, 4).unwrap();
        let roots = past.shard.capture_committed_shard(&past.filter).unwrap().roots;
        match fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap() {
            FenceRewind::Unrewindable { fence, error: None } => assert_eq!(fence, UnrewindableFence {
                generation: past.successor.generation, local_head: 4, fence: 3, session_tip: None,
                reason: "no local frame at the fence",
            }),
            other => panic!("{other:?}"),
        }
        assert_eq!(rewind_past_fence(&past.global, &past.shard, &past.clock, &past.successor).unwrap(), None);
        assert_eq!(past.shard.capture_committed_shard(&past.filter).unwrap().roots, roots);
        assert_eq!(past.cursor(), 4);

        let past = past_fence();
        store_header(&past.clock, quil_types::proto::global::FrameHeader {
            address: past.filter.clone(), frame_number: 4, rank: 6, output: vec![0x44; 32],
            parent_selector: past.fenced_digest.to_vec(), state_roots: vec![vec![0x09; 32]; 4],
            ..Default::default()
        });
        match fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap() {
            FenceRewind::Unrewindable { fence, error: Some(QuilError::ExecutionUnavailable(_)) } => {
                assert_eq!(fence.reason, "fence state not retained locally");
            }
            other => panic!("{other:?}"),
        }
        let error = rewind_past_fence(&past.global, &past.shard, &past.clock, &past.successor).unwrap_err();
        assert!(error.to_string().contains("not retained here"), "{error}");
        assert_eq!(past.cursor(), 4);

        let joiner_clock_db = quil_store::RocksDb::open_in_memory().unwrap();
        let joiner_clock = quil_store::RocksClockStore::new(joiner_clock_db.inner());
        let joiner = crdt();
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&past.filter);
        joiner.commit_with_frame_cursor_and_records(5, &cursor_key, &outflow_records(&past.filter, 5)).unwrap();
        store_header(&joiner_clock, quil_types::proto::global::FrameHeader {
            address: past.filter.clone(), frame_number: 5, rank: 9, output: vec![0x66; 32],
            global_frame_number: past.due, ..Default::default()
        });
        assert!(matches!(fence_rewind(&past.global, &joiner, &joiner_clock, &past.successor).unwrap(),
            FenceRewind::Untouched));
    }

    /// Discarded frames `numbers` of the predecessor past the fence at 3,
    /// anchored before GLOBAL fenced it, materialized through the last.
    fn discarded_head(past: &PastFence, numbers: &[u64]) {
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&past.filter);
        for &number in numbers {
            store_header(&past.clock, quil_types::proto::global::FrameHeader {
                address: past.filter.clone(), frame_number: number, rank: number + 3,
                output: vec![0x40 | number as u8; 32], ..Default::default()
            });
        }
        let changed = quil_hypergraph::Location { app_address: [0x02; 32], data_address: [9; 32] };
        past.shard.add_vertex(&changed, b"a discarded frame's").unwrap();
        let last = *numbers.last().unwrap();
        past.shard.commit_with_frame_cursor_and_records(last, &cursor_key, &outflow_records(&past.filter, last)).unwrap();
    }

    fn header_frame(filter: &[u8], number: u64, output: u8) -> quil_types::proto::global::AppShardFrame {
        quil_types::proto::global::AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: filter.to_vec(), frame_number: number, output: vec![output; 32], ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Frame `frame`'s relay records, as a member that materialized it keeps them.
    fn store_relay_records(clock: &quil_store::RocksClockStore, filter: &[u8], frame: u64) {
        use quil_types::store::ClockStore as _;
        clock.put_shard_frame_fee_total(filter, frame, 7).unwrap();
        clock.put_shard_frame_settlements(filter, frame, &[frame as u8]).unwrap();
        clock.put_shard_frame_spends(filter, frame, &[frame as u8]).unwrap();
        clock.put_shard_frame_accumulator(filter, frame, &[frame as u8; 32], b"report").unwrap();
    }

    fn relay_records_of(clock: &quil_store::RocksClockStore, filter: &[u8], frame: u64) -> [bool; 4] {
        use quil_types::store::ClockStore as _;
        [
            clock.get_shard_frame_fee_total(filter, frame).unwrap().is_some(),
            clock.get_shard_frame_settlements(filter, frame).unwrap().is_some(),
            clock.get_shard_frame_spends(filter, frame).unwrap().is_some(),
            clock.get_shard_frame_accumulator(filter, frame).unwrap().is_some(),
        ]
    }

    fn gate_of(past: &PastFence) -> ReanchorGate {
        let marker = read_reanchor_marker(&past.clock, &past.filter).unwrap();
        reanchor_gate_at(&past.shard, &past.clock, &past.filter, marker).unwrap()
    }

    // An operator's worker installed an archive checkpoint past the fence
    // (2026-10-13): it held the predecessor's discarded frames 5 and 6 and
    // nothing at the fence, so it could neither rewind nor start, for six
    // days. It owes a re-anchor at the frame GLOBAL committed, which while
    // the successor has executed nothing is the fence, its base. Once the
    // shard sync has installed that frame's pre-state, the rebase drops the
    // discarded frames and moves head and cursor below the anchor; the
    // anchor's replay then leaves a member the successor accepts.
    #[test]
    fn a_head_past_a_fence_without_its_frames_is_reanchored_at_the_fence() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        past.clock.delete_shard_clock_frame_range(&past.filter, 3, 5).unwrap();
        discarded_head(&past, &[5, 6]);
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        assert!(matches!(&outcome, FenceRewind::Unrewindable { fence, error: None }
            if fence.reason == "no local frame at the fence"), "{outcome:?}");
        let marker = outcome.reanchor().expect("a head past the fence that cannot rewind owes a re-anchor");
        assert_eq!(marker, ReanchorMarker { generation: past.successor.generation, fence: 3, from_cursor: 6, head: None });
        let marker = marker.with_head(&past.clock, &past.filter);
        assert_eq!(marker.head, Some(quil_crypto::poseidon::hash_bytes_to_32(&[0x46; 32]).unwrap()));
        assert_eq!(past.successor.base_frame, 3, "a fenced predecessor's successor is based at the fence");
        assert_eq!(committed_tip(&past.global, &past.filter).unwrap(), Some(3), "the anchor is the fence");
        write_reanchor_marker(&past.clock, &past.filter, &marker).unwrap();
        assert_eq!(gate_of(&past), ReanchorGate::Owed(marker));

        // The shard sync installed frame 3's pre-state; the actor rebases.
        let rebased = rebase_for_reanchor(&past.shard, &past.clock, &past.filter, &marker, 3,
            Some(&header_frame(&past.filter, 2, 0x22)), |kept| { assert_eq!(kept, 2); Ok(()) }).unwrap();
        assert_eq!(rebased, Rebased { from: 3, to: 6 });
        assert_eq!(past.cursor(), 2);
        assert_eq!(past.clock.get_latest_shard_clock_frame(&past.filter).unwrap().header.unwrap().frame_number, 2);
        for number in [5, 6] {
            assert!(past.clock.get_shard_clock_frame(&past.filter, number, false).is_err(), "frame {number} is dropped");
        }
        assert_eq!(read_reanchor_marker(&past.clock, &past.filter).unwrap(), None, "the rebase committed");
        assert_eq!(gate_of(&past), ReanchorGate::Absent);

        // The anchor's replay: the fenced frame and the state after it.
        past.shard.rewind_app_shard(&past.filter, &past.fenced_roots).unwrap();
        store_header(&past.clock, quil_types::proto::global::FrameHeader {
            address: past.filter.clone(), frame_number: 3, rank: 5, output: vec![0x33; 32], ..Default::default()
        });
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&past.filter);
        past.shard.checkpoint_frame_cursor(3, &cursor_key).unwrap();
        assert!(matches!(fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap(),
            FenceRewind::Untouched));
        successor_state_matches(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
    }

    // Once GLOBAL has executed the successor past the fence, the anchor is
    // its executed tip, and the frame there that is not GLOBAL's still says
    // the head is the predecessor's. The rebase drops every discarded frame
    // past the fence, not only those from the anchor up, and their relay
    // records: frames below the anchor are never materialized here again.
    // It never anchors below the fence.
    #[test]
    fn a_reanchor_past_the_successors_tip_drops_every_discarded_frame() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        past.clock.delete_shard_clock_frame_range(&past.filter, 3, 5).unwrap();
        discarded_head(&past, &[5, 6, 8]);
        for frame in [3, 5, 6, 8] {
            store_relay_records(&past.clock, &past.filter, frame);
        }
        handoff::record_session_tip(&past.state, past.due + 1, &past.successor.id().unwrap(), &Checkpoint {
            frame: 8, view: 12, digest: quil_crypto::poseidon::hash_bytes_to_32(&[0x88; 32]).unwrap(),
            state_roots: [[3; 32]; 4], history_root: [0; 32],
        }).unwrap();
        commit(&past.global, &past.state, past.due + 1);
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        let marker = outcome.reanchor().expect("the frame at the executed tip differs from GLOBAL's");
        assert_eq!(marker.from_cursor, 8);
        assert_eq!(committed_tip(&past.global, &past.filter).unwrap(), Some(8), "the anchor is the executed tip");

        let below = rebase_for_reanchor(&past.shard, &past.clock, &past.filter, &marker, 2,
            Some(&header_frame(&past.filter, 1, 0x11)), |_| Ok(()));
        assert!(below.is_err(), "an anchor below the fence");
        assert_eq!(past.cursor(), 8);
        assert!(past.clock.get_shard_clock_frame(&past.filter, 5, false).is_ok(), "nothing dropped");

        let rebased = rebase_for_reanchor(&past.shard, &past.clock, &past.filter, &marker, 8,
            Some(&header_frame(&past.filter, 7, 0x77)), |kept| { assert_eq!(kept, 3); Ok(()) }).unwrap();
        assert_eq!(rebased, Rebased { from: 4, to: 8 });
        assert_eq!(past.cursor(), 7);
        assert_eq!(past.clock.get_latest_shard_clock_frame(&past.filter).unwrap().header.unwrap().output, vec![0x77; 32]);
        for number in [5, 6, 8] {
            assert!(past.clock.get_shard_clock_frame(&past.filter, number, false).is_err(), "frame {number} is dropped");
            assert_eq!(relay_records_of(&past.clock, &past.filter, number), [false; 4], "frame {number}'s relay records");
        }
        assert_eq!(relay_records_of(&past.clock, &past.filter, 3), [true; 4], "the fence's records stay");
    }

    // A member past the fence on this session's own chain owes nothing:
    // its frame at the executed tip is the one GLOBAL executed.
    #[test]
    fn a_member_on_the_sessions_own_chain_owes_no_reanchor() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        past.execute_successor(0x44);
        past.clock.delete_shard_clock_frame_range(&past.filter, 3, 4).unwrap();
        let roots = past.shard.capture_committed_shard(&past.filter).unwrap().roots;
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        assert!(matches!(outcome, FenceRewind::Untouched), "{outcome:?}");
        assert_eq!(outcome.reanchor(), None);
        assert_eq!(past.shard.capture_committed_shard(&past.filter).unwrap().roots, roots);
        assert_eq!(past.cursor(), 4);
        assert!(past.clock.get_shard_clock_frame(&past.filter, 4, false).is_ok());
    }

    // The marker outlives a restart, per shard, with or without the head it
    // names, also in the layout without a head. A malformed marker is an
    // error to a plain read; a check that must not block clears it.
    #[test]
    fn a_reanchor_marker_survives_a_restart_and_a_malformed_one_is_cleared() {
        use quil_types::store::ClockStore as _;
        let clock_db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(clock_db.inner());
        let filter = vec![0x02; 32];
        assert_eq!(read_reanchor_marker(&clock, &filter).unwrap(), None);
        for head in [Some([0x46; 32]), None] {
            let marker = ReanchorMarker { generation: 2, fence: 1015, from_cursor: 1018, head };
            write_reanchor_marker(&clock, &filter, &marker).unwrap();
            let restarted = quil_store::RocksClockStore::new(clock_db.inner());
            assert_eq!(read_reanchor_marker(&restarted, &filter).unwrap(), Some(marker));
            assert_eq!(read_reanchor_marker(&restarted, &[0x03; 32]).unwrap(), None, "per shard");
        }
        clear_reanchor_marker(&clock, &filter).unwrap();
        assert_eq!(read_reanchor_marker(&clock, &filter).unwrap(), None);
        let txn = clock.new_transaction(false).unwrap();
        let mut short = Vec::new();
        for field in [2u64, 1015, 1018] {
            short.extend_from_slice(&field.to_be_bytes());
        }
        txn.set(&quil_store::encoding::app_reanchor_key(&filter), &short).unwrap();
        txn.commit().unwrap();
        let headless = ReanchorMarker { generation: 2, fence: 1015, from_cursor: 1018, head: None };
        assert_eq!(read_reanchor_marker(&clock, &filter).unwrap(), Some(headless), "the layout without a head");
        assert_eq!(load_reanchor_marker(&clock, &filter).unwrap(), (Some(headless), None));

        // The 56-byte layout with a head, written raw.
        let mut full = short.clone();
        full.extend_from_slice(&[0x46; 32]);
        let txn = clock.new_transaction(false).unwrap();
        txn.set(&quil_store::encoding::app_reanchor_key(&filter), &full).unwrap();
        txn.commit().unwrap();
        let headed = ReanchorMarker { head: Some([0x46; 32]), ..headless };
        assert_eq!(load_reanchor_marker(&clock, &filter).unwrap(), (Some(headed), None), "the 56-byte layout");

        let mut longer = full.clone();
        longer.push(1);
        for malformed in [vec![1; 17], longer] {
            let txn = clock.new_transaction(false).unwrap();
            txn.set(&quil_store::encoding::app_reanchor_key(&filter), &malformed).unwrap();
            txn.commit().unwrap();
            assert!(read_reanchor_marker(&clock, &filter).is_err(), "{} bytes", malformed.len());
            assert_eq!(load_reanchor_marker(&clock, &filter).unwrap(), (None, Some(malformed.len())),
                "cleared, not blocking");
            assert_eq!(read_reanchor_marker(&clock, &filter).unwrap(), None);
        }
    }

    // Owed while the cursor stands where the re-anchor began and the head
    // there is the one recorded, or already deleted by the rebase; stale
    // once the cursor moved (the rebase committed) or another frame stands
    // at that cursor (the shard reached that height another way).
    #[test]
    fn a_reanchor_is_owed_until_its_rebase_moves_the_cursor_or_its_head_is_replaced() {
        let head = Some([0x46; 32]);
        let marker = ReanchorMarker { generation: 2, fence: 3, from_cursor: 6, head };
        assert_eq!(reanchor_gate(None, 6, head), ReanchorGate::Absent);
        assert_eq!(reanchor_gate(Some(marker), 6, head), ReanchorGate::Owed(marker), "a partial sync may be in the trees");
        assert_eq!(reanchor_gate(Some(marker), 6, None), ReanchorGate::Owed(marker), "the rebase deleted the head");
        assert_eq!(reanchor_gate(Some(marker), 2, None), ReanchorGate::Stale(marker), "the rebase committed");
        assert_eq!(reanchor_gate(Some(marker), 2, head), ReanchorGate::Stale(marker));
        assert_eq!(reanchor_gate(Some(marker), 6, Some([0x66; 32])), ReanchorGate::Stale(marker), "another frame there");
        let unheaded = ReanchorMarker { head: None, ..marker };
        assert_eq!(reanchor_gate(Some(unheaded), 6, Some([0x66; 32])), ReanchorGate::Owed(unheaded));
    }

    /// An evicted lineage anchors at the frame GLOBAL committed, or at its
    /// own head when that is the committed tip, as on a shard whose
    /// committee stalled there; a replay mismatch needs a committed frame
    /// above the head.
    #[test]
    fn an_evicted_lineage_anchors_at_its_head_when_the_shard_stalled_there() {
        let at = |fence| Some(ReanchorMarker { generation: 3, fence, from_cursor: fence, head: None });
        assert_eq!(evicted_lineage_reanchor(3, 5, Some(5)), at(5), "the stalled shard");
        assert_eq!(evicted_lineage_reanchor(3, 5, Some(9)), at(5));
        assert_eq!(evicted_lineage_reanchor(3, 5, Some(4)), None, "GLOBAL behind the head");
        assert_eq!(evicted_lineage_reanchor(3, 5, None), None);
        assert_eq!(replay_mismatch_reanchor(3, 5, Some(5)), None);
        assert_eq!(at(5).unwrap().cause(), ReanchorCause::ReplayMismatch);
    }

    // An operator's joining worker held a lineage from an earlier tenure
    // whose trees no longer matched it (2026-10-20): every archive frame
    // past its head failed to replay with a pre-state mismatch, for hours,
    // from every archive. Its session was never fenced. Once that persists
    // it owes a re-anchor at the frame GLOBAL committed above its head: the
    // rebase keeps the lineage through the head, drops the frames stored
    // past it with their relay records, and moves the cursor below the
    // anchor, which then replays as the session's executed tip. Without a
    // committed frame above the head it owes none.
    #[test]
    fn a_lineage_whose_trees_diverged_is_reanchored_at_the_committed_frame_above_it() {
        use quil_types::proto::global::FrameHeader;
        use quil_types::store::ClockStore as _;
        // A first session on its own chain, never fenced, executed through 9.
        let (global, state) = global_state();
        let filter = vec![0x06; 32];
        let signers: Vec<_> = (0..3).map(|_| quil_crypto::FalconSigner::generate()).collect();
        let mut members: Vec<Vec<u8>> = signers.iter().map(|s| s.public_key().to_vec()).collect();
        members.sort();
        let session = Session {
            chain_id: [7; 32], filter: filter.clone(), generation: 1,
            genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
            base_frame: 0, authorization: [0; 32], members,
        };
        commit(&global, &state, 1);
        handoff::initialize(&state, 2, &session).unwrap();
        commit(&global, &state, 2);
        let tip = quil_crypto::poseidon::hash_bytes_to_32(&[0x99; 32]).unwrap();
        handoff::record_session_tip(&state, 3, &session.id().unwrap(), &Checkpoint {
            frame: 9, view: 12, digest: tip, state_roots: [[3; 32]; 4], history_root: [0; 32],
        }).unwrap();
        commit(&global, &state, 3);
        assert_eq!(replay_mismatch_inputs(&global, &filter).unwrap(), (Some(9), 1, true));

        // The worker's lineage through 5, materialized through 4.
        let clock_db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(clock_db.inner());
        let shard = crdt();
        shard.set_unified_tree(true);
        let cursor_key = quil_store::encoding::consensus_materialized_cursor_key(&filter);
        for number in 1..=5u64 {
            store_header(&clock, FrameHeader {
                address: filter.clone(), frame_number: number, rank: number, output: vec![0x10 | number as u8; 32],
                ..Default::default()
            });
            store_relay_records(&clock, &filter, number);
        }
        shard.commit_with_frame_cursor_and_records(4, &cursor_key, &outflow_records(&filter, 4)).unwrap();
        let cursor = || shard.read_frame_cursor(&cursor_key).unwrap();
        assert_eq!(cursor(), 4);

        for (head, committed) in [(4, None), (9, Some(9)), (10, Some(9))] {
            assert_eq!(replay_mismatch_reanchor(1, head, committed), None, "{head} {committed:?}");
        }
        let marker = replay_mismatch_reanchor(1, 4, Some(9)).unwrap().with_head(&clock, &filter);
        assert_eq!(marker, ReanchorMarker { generation: 1, fence: 4, from_cursor: 4,
            head: Some(quil_crypto::poseidon::hash_bytes_to_32(&[0x14; 32]).unwrap()) });
        assert_eq!(marker.cause(), ReanchorCause::ReplayMismatch);
        assert_eq!(ReanchorMarker { fence: 3, from_cursor: 6, ..marker }.cause(), ReanchorCause::PastFence);
        write_reanchor_marker(&clock, &filter, &marker).unwrap();
        let gate = || reanchor_gate_at(&shard, &clock, &filter, read_reanchor_marker(&clock, &filter).unwrap()).unwrap();
        assert_eq!(gate(), ReanchorGate::Owed(marker));
        // A payload eviction's record of the dropped subtree at the cursor.
        let dropped_key = quil_store::encoding::app_lineage_dropped_key(&filter);
        let txn = clock.new_transaction(false).unwrap();
        txn.set(&dropped_key, &4u64.to_be_bytes()).unwrap();
        txn.commit().unwrap();
        assert_eq!(dropped_lineage(&shard, &clock, &filter).unwrap(), Some(4));
        assert!(reanchor_applies(&global, &filter).unwrap());
        assert!(anchor_is_committed(&global, &filter, &header_frame(&filter, 9, 0x99)).unwrap());
        assert!(!anchor_is_committed(&global, &filter, &header_frame(&filter, 9, 0x98)).unwrap());
        assert!(!anchor_is_committed(&global, &filter, &header_frame(&filter, 5, 0x15)).unwrap(), "a lineage frame");

        let rebased = rebase_for_reanchor(&shard, &clock, &filter, &marker, 9,
            Some(&header_frame(&filter, 8, 0x88)), |kept| { assert_eq!(kept, 4); Ok(()) }).unwrap();
        assert_eq!(rebased, Rebased { from: 5, to: 5 });
        assert_eq!(cursor(), 8);
        assert!(clock.get_shard_clock_frame(&filter, 5, false).is_err(), "the frame past the head is dropped");
        assert_eq!(relay_records_of(&clock, &filter, 5), [false; 4]);
        for number in 1..=4u64 {
            assert_eq!(clock.get_shard_clock_frame(&filter, number, false).unwrap().header.unwrap().output,
                vec![0x10 | number as u8; 32], "frame {number} stays");
            assert_eq!(relay_records_of(&clock, &filter, number), [true; 4], "frame {number}'s records stay");
        }
        assert_eq!(clock.get_latest_shard_clock_frame(&filter).unwrap().header.unwrap().output, vec![0x88; 32]);
        assert_eq!(gate(), ReanchorGate::Absent, "the rebase committed");
        let txn = clock.new_transaction(false).unwrap();
        assert_eq!(txn.get(&dropped_key).unwrap(), None, "and cleared the dropped-lineage record");
        let _ = txn.abort();

        // The anchor replays: the head is the frame GLOBAL executed.
        store_header(&clock, FrameHeader {
            address: filter.clone(), frame_number: 9, rank: 12, output: vec![0x99; 32], ..Default::default()
        });
        shard.checkpoint_frame_cursor(9, &cursor_key).unwrap();
        assert_eq!(local_frame_digest(&clock, &filter, cursor()), Some(tip));
        assert_eq!(gate(), ReanchorGate::Absent);
    }

    // A rebase interrupted after its deletions, before the cursor moves (a
    // crash there), leaves the re-anchor owed; run again it converges: the
    // marker is cleared, and the records kept above the cursor are dropped
    // before the cursor moves.
    #[test]
    fn a_rebase_interrupted_before_its_cursor_moves_stays_owed_and_converges_when_rerun() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        past.clock.delete_shard_clock_frame_range(&past.filter, 3, 5).unwrap();
        discarded_head(&past, &[5, 6]);
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &past.successor).unwrap();
        let marker = outcome.reanchor().unwrap().with_head(&past.clock, &past.filter);
        write_reanchor_marker(&past.clock, &past.filter, &marker).unwrap();
        let predecessor = header_frame(&past.filter, 2, 0x22);

        let crashed = rebase_for_reanchor(&past.shard, &past.clock, &past.filter, &marker, 3, Some(&predecessor),
            |_| Err(QuilError::Internal("stopped after the deletions".into())));
        assert!(crashed.is_err());
        assert_eq!(past.cursor(), 6, "the cursor has not moved");
        assert!(past.clock.get_shard_clock_frame(&past.filter, 6, false).is_err(), "the head is already deleted");
        assert_eq!(gate_of(&past), ReanchorGate::Owed(marker), "still owed after a restart");

        let finalized = std::cell::RefCell::new(vec![2u64, 3, 5, 6]);
        let rebased = rebase_for_reanchor(&past.shard, &past.clock, &past.filter, &marker, 3, Some(&predecessor),
            |kept| {
                assert_eq!(past.cursor(), 6, "kept records are dropped before the cursor moves");
                finalized.borrow_mut().retain(|&number| number <= kept);
                Ok(())
            }).unwrap();
        assert_eq!(rebased, Rebased { from: 3, to: 6 });
        assert_eq!(past.cursor(), 2);
        assert!(finalized.borrow().iter().all(|&number| number <= past.cursor()), "{:?}", finalized.borrow());
        assert_eq!(gate_of(&past), ReanchorGate::Absent, "the marker is cleared");
        assert_eq!(past.clock.get_latest_shard_clock_frame(&past.filter).unwrap().header.unwrap().frame_number, 2);
    }

    // A successor fenced at its base, never having run, does not hide the
    // fence below it: the head is still owed a re-anchor there, and the
    // fenced frame is the committed anchor, as before the successor closed.
    #[test]
    fn a_fence_under_a_session_closed_at_its_base_is_still_the_committed_anchor() {
        use quil_types::store::ClockStore as _;
        let past = past_fence();
        past.clock.delete_shard_clock_frame_range(&past.filter, 3, 5).unwrap();
        discarded_head(&past, &[5, 6]);
        let next = past.fence_successor_at_its_base();
        assert_eq!(committed_tip(&past.global, &past.filter).unwrap(), Some(3), "the anchor is the fence");
        assert_eq!(committed_frame_digest(&past.global, &past.filter, 3).unwrap(), None,
            "direct origins name only the successor's base");
        let outcome = fence_rewind(&past.global, &past.shard, &past.clock, &next).unwrap();
        assert_eq!(outcome.reanchor().map(|marker| (marker.fence, marker.from_cursor)), Some((3, 6)));
        let committed = |frame| anchor_is_committed(&past.global, &past.filter, &frame).unwrap();
        assert!(committed(header_frame(&past.filter, 3, 0x33)), "the fenced frame, looked through to");
        assert!(!committed(header_frame(&past.filter, 3, 0x34)));
    }

    // A sealed or fenced frame stays committed when the successors based at
    // it each closed there without a frame: looked through, their origin's
    // checkpoint names it. Only that frame, under its own digest.
    #[test]
    fn a_checkpoint_under_sessions_closed_at_their_base_keeps_its_committed_digest() {
        let past = past_fence();
        past.fence_successor_at_its_base();
        assert_eq!(committed_frame_digest(&past.global, &past.filter, 3).unwrap(), None);
        assert_eq!(committed_frame_digest_looked_through(&past.global, &past.filter, 3).unwrap(),
            Some(past.fenced_digest), "the checkpoint the closed successor was based at");
        for (filter, number) in [(past.filter.clone(), 2), (past.filter.clone(), 4), (vec![0x08; 32], 3)] {
            assert_eq!(committed_frame_digest_looked_through(&past.global, &filter, number).unwrap(), None);
        }
    }

    // The anchor an attempt validated as GLOBAL's executed tip is accepted
    // at installation though GLOBAL executed the successor past it since:
    // the head's tip moves with each frame GLOBAL executes.
    #[test]
    fn a_committed_anchor_stays_accepted_after_the_successor_produces_past_it() {
        let past = past_fence();
        past.execute_successor(0x55);
        let anchor = header_frame(&past.filter, 4, 0x55);
        let mut attempt = CommittedAnchor::default();
        assert!(attempt.accept(&past.global, &past.filter, &anchor).unwrap(), "validated before the tree sync");
        handoff::record_session_tip(&past.state, past.due + 2, &past.successor.id().unwrap(), &Checkpoint {
            frame: 5, view: 10, digest: quil_crypto::poseidon::hash_bytes_to_32(&[0x66; 32]).unwrap(),
            state_roots: [[3; 32]; 4], history_root: [0; 32],
        }).unwrap();
        commit(&past.global, &past.state, past.due + 2);
        assert!(!anchor_is_committed(&past.global, &past.filter, &anchor).unwrap(), "no longer the executed tip");
        assert!(attempt.accept(&past.global, &past.filter, &anchor).unwrap(), "accepted again at installation");
        assert!(!attempt.accept(&past.global, &past.filter, &header_frame(&past.filter, 4, 0x56)).unwrap());
        assert!(!CommittedAnchor::default().accept(&past.global, &past.filter, &anchor).unwrap(), "a new attempt");
    }

    // A re-anchor applies while the shard's current session continues this
    // filter's chain (its own tip, or a same-filter origin, looked through
    // sessions closed at their base); not under a session whose origins are
    // all other shards', or that has none.
    #[test]
    fn a_reanchor_applies_while_the_current_session_continues_this_shards_chain() {
        let past = past_fence();
        assert!(reanchor_applies(&past.global, &past.filter).unwrap(), "the successor of the fenced session");
        past.fence_successor_at_its_base();
        assert!(reanchor_applies(&past.global, &past.filter).unwrap(), "looked through a session closed at its base");
        let origin = |filter: u8| (Session {
            chain_id: [7; 32], filter: vec![filter; 32], generation: 1, genesis: [0; 32],
            base_frame: 0, authorization: [0; 32], members: Vec::new(),
        }, Checkpoint { frame: 3, view: 5, digest: [0; 32], state_roots: [[0; 32]; 4], history_root: [0; 32] });
        assert!(continues_filter(&[origin(0x01), origin(0x02)], &[0x02; 32]));
        assert!(!continues_filter(&[origin(0x01), origin(0x03)], &[0x02; 32]), "origins on other shards");
        assert!(!continues_filter(&[], &[0x02; 32]), "no origins");
        assert!(reanchor_applies(&past.global, &[0x07; 32]).unwrap(), "no head: kept");
        assert_eq!(head_summary(&past.global, &past.filter), Some((past.successor.generation + 1, 1)));
    }

    // The memo of a committed anchor holds only under the head session it
    // was found under.
    #[test]
    fn a_committed_anchor_is_remembered_only_under_its_head_session() {
        let memo = CommittedAnchor(Some(([1; 32], 4, [0x55; 32])));
        assert!(memo.remembers([1; 32], 4, [0x55; 32]));
        assert!(!memo.remembers([2; 32], 4, [0x55; 32]), "another head session");
        assert!(!memo.remembers([1; 32], 4, [0x56; 32]));
        assert!(!CommittedAnchor::default().remembers([1; 32], 4, [0x55; 32]));
    }

    // A re-anchor installs only the frame GLOBAL committed: the fenced frame
    // while the successor has executed nothing, its executed tip after.
    #[test]
    fn a_reanchor_anchor_must_be_the_frame_global_committed() {
        let past = past_fence();
        let committed = |frame| anchor_is_committed(&past.global, &past.filter, &frame).unwrap();
        assert!(committed(header_frame(&past.filter, 3, 0x33)), "the fenced frame");
        assert!(!committed(header_frame(&past.filter, 3, 0x34)), "another frame at the fence");
        assert!(!committed(header_frame(&past.filter, 4, 0x44)), "a discarded frame");
        assert!(!committed(header_frame(&[0x03; 32], 3, 0x33)), "another shard's frame");
        past.execute_successor(0x55);
        assert!(committed(header_frame(&past.filter, 4, 0x55)), "the successor's executed tip");
        assert!(!committed(header_frame(&past.filter, 4, 0x44)));
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

    /// A seal this member cannot authorize names the missing input: a closing
    /// request its committed GLOBAL view does not hold, refreshed early while
    /// the GLOBAL head is ahead of that view and this process's sync task
    /// honours requests, or a held request whose checkpoint is not sealable.
    #[test]
    fn a_seal_before_the_closing_request_asks_for_a_fresher_global_view() {
        let (global, state) = global_state();
        let filter = vec![0x05; 32];
        let mut members: Vec<Vec<u8>> = (0..3)
            .map(|_| quil_crypto::FalconSigner::generate().public_key().to_vec()).collect();
        members.sort();
        let session = Session {
            chain_id: [7; 32], filter: filter.clone(), generation: 1,
            genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
            base_frame: 0, authorization: [0; 32], members: members.clone(),
        };
        commit(&global, &state, 1);
        handoff::initialize(&state, 2, &session).unwrap();
        commit(&global, &state, 2);
        let anchors = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let head = |number: u64| anchors.seed_frame(quil_types::proto::global::GlobalFrame {
            header: Some(quil_types::proto::global::GlobalFrameHeader { frame_number: number, ..Default::default() }),
            ..Default::default()
        });
        let source = ParentSource::new(
            session.clone(), global.clone(), crdt(), anchors.clone() as Arc<dyn ClockStore>,
            Arc::new(AtomicBool::new(false)),
        ).unwrap();
        use crate::global_view_refresh::{Reason, ViewRefresh};
        let refresh = Arc::new(ViewRefresh::default());
        let probe = source.closing_probe(anchors.clone() as Arc<dyn ClockStore>, refresh.clone());

        // The head's root binds frame 2, which the view holds: nothing newer.
        head(3);
        let current = probe();
        assert!(!current.refreshing);
        assert_eq!(current.detail, "no closing request in the committed GLOBAL view at frame 2, GLOBAL head 3");

        // GLOBAL moved on. A process whose sync task does not honour requests
        // (an archive, a separate worker) refuses at once, naming its view.
        head(10);
        let unhonoured = probe();
        assert!(!unhonoured.refreshing);
        assert_eq!(unhonoured.detail, "no closing request in the committed GLOBAL view at frame 2, GLOBAL head 10");
        assert_eq!(refresh.requested(Reason::SealBeforeClosingRequest), None);

        // A regular node's in-process worker asks for frame 9 and waits.
        refresh.enable(720);
        assert!(probe().refreshing);
        assert_eq!(refresh.requested(Reason::SealBeforeClosingRequest), Some(9));
        // Not while a pull short of frame 9 runs: the next starts after it.
        refresh.begin(5);
        assert!(!probe().refreshing);
        refresh.end(std::time::Instant::now());
        refresh.settle(9);

        // The refreshed view holds the request: what is missing is a sealable checkpoint.
        handoff::schedule(&state, 3, vec![filter.clone()],
            vec![DesiredCommittee { filter: filter.clone(), members }]).unwrap();
        commit(&global, &state, 9);
        let held = probe();
        assert!(!held.refreshing);
        assert!(held.detail.starts_with("closing request in the committed GLOBAL view at frame 9, but the checkpoint is not sealable"),
            "{}", held.detail);
        assert_eq!(refresh.requested(Reason::SealBeforeClosingRequest), None);
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
                last_signed_frame_number: 0, epoch: u64::MAX, ring: 0, vertex_address: vec![],
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
        let policy = CommitteeHandoffPolicy { activation_frame: 0, chain_id: [7; 32], legacy_history: quil_types::consensus::LegacyHistory::Migrate, membership_boundary_frame: u64::MAX, first_session_boundary_frame: u64::MAX};
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
        // A member that has not staged the shard's data reads no parent, so it
        // can neither propose nor verify a seal of its partial roots.
        let staged = Arc::new(AtomicBool::new(false));
        source.require_staged_data(staged.clone());
        let unstaged = source.read(context(18, 17, tip_digest)).unwrap_err();
        assert!(unstaged.to_string().contains("not staged"), "{unstaged}");
        staged.store(true, Ordering::Release);
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
