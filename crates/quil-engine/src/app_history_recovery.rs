//! Bounded, resumable recovery of a session's outgoing history before voting.
//! Headers are authenticated before their relay fields are used. Omitted
//! accumulator fields are resolved only by an exact state match or the
//! nonempty carry-window implication; ambiguity remains unavailable.

use prost::Message;
use quil_cw_consensus::handoff::Session;
use quil_execution::{
    token_intrinsic::{
        accumulator_header::{self, CARRY_WINDOW_FRAMES, HEARTBEAT_FRAMES},
        settlement_record, shard_accumulator, spend_relay,
    },
    ExecutionEngineManager,
};
use quil_store::encoding;
use quil_types::{
    error::{QuilError, Result},
    proto::global::{AppShardFrame, FrameHeader},
    store::{ClockStore, SnapshotReadable},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use crate::{
    app_engine::DeliveryFrameSource,
    frame_validator::{
        app_frame_links_to_child, validate_archive_replay_chain, BlsAppFrameValidator,
        MAX_REPLAY_DESCENDANTS,
    },
};

const MAX_FRAMES: usize = 8;
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROGRESS_BYTES: usize = 2 * 1024 * 1024;
const MAX_REPORT_STATES: usize = 8;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
type Roots = [[u8; 32]; 4];

fn unavailable(message: impl Into<String>) -> QuilError {
    QuilError::ExecutionUnavailable(format!("app history recovery: {}", message.into()))
}

/// How often a running outgoing-history walk logs a batch at info; its
/// first batch in this process and its last always do.
const WALK_PROGRESS_REPEAT: Duration = Duration::from_secs(5 * 60);

/// Running walks by filter: when each last logged at info, and its
/// `(done, next, target)` after its latest batch. An abandoned walk leaves
/// one entry, bounded by the filters this process served.
static WALKS: Mutex<BTreeMap<Vec<u8>, (Instant, (u64, u64, u64))>> = Mutex::new(BTreeMap::new());

/// Record a committed batch of `filter`'s walk at `now`: whether it is
/// logged at info. A finished walk is forgotten.
fn walk_batch(filter: &[u8], progress: (u64, u64, u64), now: Instant) -> bool {
    let mut walks = WALKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (done, _, target) = progress;
    if done == target {
        walks.remove(filter);
        return true;
    }
    let last = walks.get(filter).map(|(at, _)| *at);
    let due = last.is_none_or(|at| now.saturating_duration_since(at) >= WALK_PROGRESS_REPEAT);
    walks.insert(
        filter.to_vec(),
        (if due { now } else { last.unwrap_or(now) }, progress),
    );
    due
}

/// `filter`'s running walk in this process, `(done, next, target)`.
pub(crate) fn walk_progress(filter: &[u8]) -> Option<(u64, u64, u64)> {
    WALKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(filter)
        .map(|(_, progress)| *progress)
}

#[derive(Serialize, Deserialize)]
struct Progress {
    version: u8,
    session: [u8; 32],
    done: u64,
    target: u64,
    next: u64,
    carry: u64,
    last_report: Vec<u8>,
    reports: Vec<(Roots, Vec<u8>)>,
    /// `(m, report)`: every frame above `m` still to be walked, down to but
    /// excluding `m`, has `report` (see [`earlier_report`]).
    #[serde(default)]
    implied: Option<(u64, Vec<u8>)>,
}

impl Progress {
    fn remember(&mut self, roots: Roots, report: Vec<u8>) -> Result<()> {
        if !report.is_empty() {
            shard_accumulator::ShardReport::decode(&report)?;
        }
        if let Some((_, existing)) = self.reports.iter().find(|(known, _)| *known == roots) {
            if *existing != report {
                return Err(unavailable(
                    "authenticated reports disagree over identical state",
                ));
            }
            return Ok(());
        }
        self.reports.insert(0, (roots, report));
        self.reports.truncate(MAX_REPORT_STATES);
        Ok(())
    }

    fn report(&self, roots: &Roots) -> Option<Vec<u8>> {
        self.reports
            .iter()
            .find(|(known, _)| known == roots)
            .map(|(_, report)| report.clone())
    }

    fn resolve(&self, header: &FrameHeader) -> Result<Option<Vec<u8>>> {
        let roots = header_roots(header)?;
        let report = if !header.accumulator.is_empty()
            || header.frame_number % HEARTBEAT_FRAMES == 0
        {
            Some(header.accumulator.clone())
        } else {
            self.report(&roots).or_else(|| {
                (self.carry > 0 && !self.last_report.is_empty()).then(|| self.last_report.clone())
            })
        };
        if let Some(report) = report.as_ref() {
            if !report.is_empty() {
                shard_accumulator::ShardReport::decode(report)?;
            }
            if (self.carry > 0 && *report != self.last_report)
                || self.report(&roots).is_some_and(|known| known != *report)
            {
                return Err(unavailable("certified accumulator constraints disagree"));
            }
        }
        Ok(report)
    }

    fn validate(&self, session: &Session, cursor: u64) -> Result<()> {
        let reason = if self.version != 1 {
            Some("unsupported version")
        } else if self.session != session.id()? {
            Some("session mismatch")
        } else if self.done < session.base_frame {
            Some("audited prefix precedes session base")
        } else if self.done > self.next {
            Some("audited prefix exceeds next frame")
        } else if self.next > self.target {
            Some("next frame exceeds target")
        } else if self.target > cursor {
            Some("target exceeds cursor")
        } else if self.carry > CARRY_WINDOW_FRAMES {
            Some("carry exceeds window")
        } else if self.reports.len() > MAX_REPORT_STATES {
            Some("too many report states")
        } else if self.last_report.len() > shard_accumulator::MAX_REPORT_BYTES {
            Some("last report exceeds byte limit")
        } else if self
            .implied
            .as_ref()
            .is_some_and(|(low, _)| *low < self.done || *low >= self.next)
        {
            Some("implied report range is outside the remaining audit")
        } else if self
            .implied
            .as_ref()
            .is_some_and(|(_, report)| report.len() > shard_accumulator::MAX_REPORT_BYTES)
        {
            Some("implied report exceeds byte limit")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(unavailable(format!(
                "invalid recovery progress: {reason} (version={}, base={}, done={}, next={}, target={}, cursor={}, carry={}, report_states={}, last_report_bytes={})",
                self.version, session.base_frame, self.done, self.next, self.target, cursor,
                self.carry, self.reports.len(), self.last_report.len(),
            )));
        }
        if let Some((_, report)) = self
            .implied
            .as_ref()
            .filter(|(_, report)| !report.is_empty())
        {
            shard_accumulator::ShardReport::decode(report)?;
        }
        for (_, report) in &self.reports {
            if !report.is_empty() {
                shard_accumulator::ShardReport::decode(report)?;
            }
        }
        if !self.last_report.is_empty() {
            shard_accumulator::ShardReport::decode(&self.last_report)?;
        }
        if (self.carry > 0 && self.last_report.is_empty())
            || self
                .reports
                .iter()
                .map(|(roots, _)| roots)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.reports.len()
        {
            return Err(unavailable("inconsistent recovery progress"));
        }
        Ok(())
    }
}

fn header_roots(header: &FrameHeader) -> Result<Roots> {
    if header.state_roots.len() != 4 {
        return Err(unavailable("invalid header roots"));
    }
    let mut roots = [[0; 32]; 4];
    for (out, bytes) in roots.iter_mut().zip(&header.state_roots) {
        *out = bytes
            .as_slice()
            .try_into()
            .map_err(|_| unavailable("non-forest header roots"))?;
    }
    Ok(roots)
}

/// The digest GLOBAL committed for a frame of the shard being recovered
/// ([`committed_digest`]).
type CommittedDigest<'a> = &'a (dyn Fn(u64) -> Result<Option<[u8; 32]>> + Sync);

/// The digest GLOBAL committed for `filter`'s frame `number` as `global`
/// holds it, `None` without GLOBAL state. Same-filter sessions that closed
/// at their base are looked through
/// ([`crate::app_handoff::committed_frame_digest_looked_through`]): when
/// every session based at a seal closed there without a frame, only the
/// sealed origin below them names the sealed frame, which has no
/// certificate of its own. A member that joined at that frame could not
/// read its predecessor's history or its carry window down from it
/// (…091f80 at frame 4693 under generations 13 to 23, 2026-10-23).
pub(crate) fn committed_digest(
    global: Option<&Arc<quil_hypergraph::HypergraphCrdt>>,
    filter: &[u8],
    number: u64,
) -> Result<Option<[u8; 32]>> {
    match global {
        Some(global) => {
            crate::app_handoff::committed_frame_digest_looked_through(global, filter, number)
        }
        None => Ok(None),
    }
}

/// Headers one batch keeps authenticated for the frames below them.
const MAX_AUTHENTICATED: usize = 2 * MAX_REPLAY_DESCENDANTS + MAX_FRAMES;
/// Frames one batch may ask peers for, runs up to a certified descendant
/// and second reads of a local frame included.
const MAX_PEER_FETCHES: usize = 2 * MAX_REPLAY_DESCENDANTS;
/// How long one batch may spend reading headers: one frame fetched from a
/// peer and prepared, with margin. The batch checks its 3 s only between
/// frames, and one frame's run up to a certified descendant can read many.
const BATCH_BUDGET: Duration = Duration::from_secs(30);

struct Headers<'a> {
    filter: &'a [u8],
    /// The generation whose history is read, named in refusals.
    generation: Option<u64>,
    clock: &'a dyn ClockStore,
    validator: &'a BlsAppFrameValidator,
    source: Option<&'a DeliveryFrameSource>,
    committed: CommittedDigest<'a>,
    /// Headers this batch authenticated. Recovery reads downward, so each
    /// one authenticates the frame below it when that frame has no
    /// certificate of its own.
    authenticated: Mutex<BTreeMap<u64, FrameHeader>>,
    /// When this batch stops reading ([`BATCH_BUDGET`]).
    deadline: Instant,
    peer_fetches: AtomicUsize,
}

#[async_trait::async_trait]
trait VerifiedHeaders: Sync {
    async fn get(&self, number: u64) -> Result<FrameHeader>;
}

/// How long fetching one historical frame from a peer may take.
const FRAME_FETCH_BUDGET: Duration = Duration::from_secs(8);
/// How long preparing one frame's history may take: its GLOBAL anchor and
/// storage registrations can come from peers, the registrations under their
/// own 15 s budget, whose errors this leaves visible. One 3 s budget for
/// fetch, preparation and validation together cut every frame that needed a
/// peer short, so recovery never progressed. Recovery runs on the engine's
/// retry tick; the batch still stops after 3 s between frames.
const FRAME_HISTORY_BUDGET: Duration = Duration::from_secs(17);

/// A frame's header without its body, which linked validation never reads.
fn header_only(header: &FrameHeader) -> AppShardFrame {
    AppShardFrame {
        header: Some(header.clone()),
        requests: Vec::new(),
        storage_attestation: None,
    }
}

fn validate_linked(validator: &BlsAppFrameValidator, frame: &AppShardFrame) -> Result<bool> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        validator.validate_linked_without_storage(frame)
    }))
    .unwrap_or_else(|_| {
        Err(QuilError::Internal(
            "linked frame validation panicked".into(),
        ))
    })
}

/// Whether `child` names the last frame of `run` as its parent.
fn extends(run: &[(FrameHeader, bool)], child: &AppShardFrame) -> bool {
    run.last()
        .zip(child.header.as_ref())
        .is_some_and(|((parent, _), child)| app_frame_links_to_child(parent, child))
}

impl<'a> Headers<'a> {
    fn new(
        filter: &'a [u8],
        generation: Option<u64>,
        clock: &'a dyn ClockStore,
        validator: &'a BlsAppFrameValidator,
        source: Option<&'a DeliveryFrameSource>,
        committed: CommittedDigest<'a>,
    ) -> Self {
        Self {
            filter,
            generation,
            clock,
            validator,
            source,
            committed,
            authenticated: Mutex::new(BTreeMap::new()),
            deadline: Instant::now() + BATCH_BUDGET,
            peer_fetches: AtomicUsize::new(0),
        }
    }

    fn known(&self, number: u64) -> Option<FrameHeader> {
        self.authenticated
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&number)
            .cloned()
    }

    /// Keep `header` authenticated, dropping the highest others past
    /// [`MAX_AUTHENTICATED`]: recovery reads downward.
    fn remember(&self, header: FrameHeader) {
        let number = header.frame_number;
        let mut authenticated = self.authenticated.lock().unwrap_or_else(|e| e.into_inner());
        authenticated.insert(number, header);
        while authenticated.len() > MAX_AUTHENTICATED {
            let Some(highest) = authenticated
                .keys()
                .rev()
                .copied()
                .find(|key| *key != number)
            else {
                break;
            };
            authenticated.remove(&highest);
        }
    }

    /// The time left of this batch's budget for reading frame `number`.
    fn remaining(&self, number: u64) -> Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(unavailable(format!(
                "reading historical frame {number} would pass the batch's {} s budget; the next start resumes",
                BATCH_BUDGET.as_secs(),
            )));
        }
        Ok(left)
    }

    /// Frame `number` from the local store, or from a peer when the store
    /// lacks it or `from_peer`, and whether the store supplied it.
    async fn fetch(&self, number: u64, from_peer: bool) -> Result<(AppShardFrame, bool)> {
        let stored = if from_peer {
            None
        } else {
            match self.clock.get_shard_clock_frame(self.filter, number, false) {
                Ok(frame) => Some(frame),
                Err(QuilError::NotFound(_)) => None,
                Err(error) => return Err(error),
            }
        };
        let local = stored.is_some();
        let frame = match stored {
            Some(frame) => frame,
            None => {
                let source = self.source.ok_or_else(|| {
                    unavailable(format!("no source for historical frame {number}"))
                })?;
                if self.peer_fetches.fetch_add(1, Ordering::Relaxed) >= MAX_PEER_FETCHES {
                    return Err(unavailable(format!(
                        "historical frame {number}: this batch already asked peers for {MAX_PEER_FETCHES} \
                         frames; the next start resumes"
                    )));
                }
                let budget = FRAME_FETCH_BUDGET.min(self.remaining(number)?);
                tokio::time::timeout(budget, source(self.filter.to_vec(), number))
                    .await
                    .map_err(|_| {
                        unavailable(format!(
                            "fetching historical frame {number} timed out after {} ms",
                            budget.as_millis()
                        ))
                    })?
                    .ok_or_else(|| {
                        unavailable(format!("no peer served historical frame {number}"))
                    })?
            }
        };
        if frame.encoded_len() > MAX_FRAME_BYTES
            || frame
                .header
                .as_ref()
                .is_none_or(|h| h.address != self.filter || h.frame_number != number)
        {
            return Err(unavailable(format!(
                "historical frame {number} is the wrong frame or oversized"
            )));
        }
        Ok((frame, local))
    }

    /// Fetch the GLOBAL anchor and storage registrations `frame`'s
    /// validation reads: as a frame with its own certificate, or as one
    /// final through a certified descendant.
    async fn prepare(&self, frame: &AppShardFrame, certified: bool) -> Result<()> {
        let number = frame.header.as_ref().map_or(0, |h| h.frame_number);
        let budget = FRAME_HISTORY_BUDGET.min(self.remaining(number)?);
        let prepared = if certified {
            tokio::time::timeout(budget, self.validator.prepare_storage_history(frame)).await
        } else {
            tokio::time::timeout(
                budget,
                self.validator.prepare_storage_history_of_linked(frame),
            )
            .await
        };
        prepared
            .map_err(|_| unavailable(format!(
                "preparing historical frame {number}'s anchor and storage history timed out after {} ms",
                budget.as_millis(),
            )))?
            .map_err(|error| match error {
                QuilError::ExecutionUnavailable(message) => unavailable(format!("historical frame {number}: {message}")),
                other => other,
            })
    }

    /// Authenticate `frame` by itself: by its own certificate, or by the
    /// digest GLOBAL committed for it (a sealed checkpoint or an executed
    /// tip, whose certificate GLOBAL verified). False for a frame with
    /// neither, which only a certified descendant can authenticate.
    async fn authenticate(&self, frame: &AppShardFrame) -> Result<bool> {
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| unavailable("historical frame has no header"))?;
        let number = header.frame_number;
        if header.public_key_signature_bls48581.is_some() {
            self.prepare(frame, true).await?;
            if !crate::app_engine::validate_app_frame_panic_safe(self.validator, frame, false)? {
                return Err(QuilError::InvalidSignature(format!(
                    "historical frame {number} rejected"
                )));
            }
            return Ok(true);
        }
        let digest = quil_crypto::poseidon::hash_bytes_to_32(&header.output)?;
        if (self.committed)(number)? != Some(digest) {
            return Ok(false);
        }
        let body = header_only(header);
        self.prepare(&body, false).await?;
        if !validate_linked(self.validator, &body)? {
            return Err(QuilError::InvalidSignature(format!(
                "historical frame {number} rejected"
            )));
        }
        Ok(true)
    }

    /// Why frame `number`, which has no certificate of its own, was not
    /// authenticated through a descendant.
    fn unlinked(&self, number: u64, reason: impl std::fmt::Display) -> QuilError {
        let generation = self
            .generation
            .map_or_else(String::new, |g| format!(" of generation {g}"));
        unavailable(format!(
            "historical frame {number}{generation} (filter {}) has no certificate of its own, and {reason}",
            hex::encode(self.filter),
        ))
    }

    /// Authenticate a frame without a certificate of its own through the
    /// frame that made it final (Simplex finalizes a view's ancestors with
    /// it): the run above it, each frame naming the one below as its
    /// parent, up to the nearest frame authenticated by itself or earlier
    /// in this batch, at most `MAX_REPLAY_DESCENDANTS` frames up. A local
    /// frame that breaks the run is read once more from a peer: the store
    /// can hold a frame of another chain at that height.
    async fn linked(&self, header: FrameHeader, stored: bool) -> Result<FrameHeader> {
        let number = header.frame_number;
        // The run's frames, and whether the local store supplied each.
        let mut run = vec![(header, stored)];
        let terminal = loop {
            self.remaining(number)?;
            let next = run.last().expect("the run holds the frame").0.frame_number + 1;
            if run.len() > MAX_REPLAY_DESCENDANTS {
                return Err(self.unlinked(
                    number,
                    format!(
                    "frames {}-{} above it carry none (nearest certified descendant: none within \
                     {MAX_REPLAY_DESCENDANTS} frames)",
                    number + 1,
                    next - 1,
                ),
                ));
            }
            let cached = self.known(next);
            let (mut child, mut child_stored) = match &cached {
                Some(header) => (header_only(header), false),
                None => self.fetch(next, false).await.map_err(|error| self.unlinked(number, format!(
                    "its descendant frame {next} is unavailable (nearest certified descendant: unknown): {error}")))?,
            };
            if !extends(&run, &child) && child_stored && self.source.is_some() {
                if let Ok((fetched, _)) = self.fetch(next, true).await {
                    child = fetched;
                    child_stored = false;
                }
            }
            if !extends(&run, &child)
                && run.last().is_some_and(|(_, stored)| *stored)
                && self.source.is_some()
            {
                if let Ok((fetched, _)) = self.fetch(next - 1, true).await {
                    let parent = fetched.header.expect("fetch checked the header");
                    let below = run.len().checked_sub(2).map(|i| &run[i].0);
                    if below.is_none_or(|below| app_frame_links_to_child(below, &parent)) {
                        *run.last_mut().expect("the run holds the frame") = (parent, false);
                    }
                }
            }
            if !extends(&run, &child) {
                return Err(self.unlinked(number, format!(
                    "frame {next} does not name frame {} as its parent (nearest certified descendant: unknown)",
                    next - 1,
                )));
            }
            let child_header = child.header.clone().expect("fetch checked the header");
            if cached.is_some() {
                run.push((child_header.clone(), false));
                break child_header;
            }
            let authenticated = self.authenticate(&child).await?;
            run.push((child_header.clone(), child_stored));
            if authenticated {
                self.remember(child_header.clone());
                break child_header;
            }
        };
        let frames: Vec<AppShardFrame> =
            run.iter().map(|(header, _)| header_only(header)).collect();
        for frame in frames[..frames.len() - 1].iter().rev() {
            self.prepare(frame, false).await?;
        }
        validate_archive_replay_chain(
            &frames[0],
            &frames[1..],
            // Authenticated above, by itself or earlier in this batch.
            |frame| Ok(frame.header.as_ref() == Some(&terminal)),
            |frame| validate_linked(self.validator, frame),
        )?;
        for (header, _) in &run[..run.len() - 1] {
            self.remember(header.clone());
        }
        Ok(run.swap_remove(0).0)
    }
}

#[async_trait::async_trait]
impl VerifiedHeaders for Headers<'_> {
    async fn get(&self, number: u64) -> Result<FrameHeader> {
        if let Some(header) = self.known(number) {
            return Ok(header);
        }
        let (frame, stored) = self.fetch(number, false).await?;
        let header = frame.header.clone().expect("fetch checked the header");
        if !self.authenticate(&frame).await? {
            return self.linked(header, stored).await;
        }
        self.remember(header.clone());
        // Recovery consumes authenticated headers only. Unchecked request
        // bodies are never installed into the canonical frame store.
        Ok(header)
    }
}

fn required(snapshot: &dyn SnapshotReadable, key: &[u8]) -> Result<Vec<u8>> {
    snapshot
        .read_record(key)?
        .ok_or_else(|| unavailable("materialized tip has incomplete outgoing records"))
}

fn outflows(header: &FrameHeader, frame: u64) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if header.frame_number
        != frame
            .checked_add(1)
            .ok_or_else(|| unavailable("frame overflow"))?
        || (!header.fee_total.is_empty() && header.fee_total.len() != 16)
    {
        return Err(unavailable("invalid previous-frame relay"));
    }
    let settlements = settlement_record::decode_relay(header.frame_number, &header.settlements)?
        .into_iter()
        .find(|(n, _)| *n == frame)
        .map(|(_, entries)| entries)
        .unwrap_or_default();
    let spends = spend_relay::decode_relay(header.frame_number, &header.spends)?
        .into_iter()
        .find(|(n, _)| *n == frame)
        .map(|(_, entries)| entries)
        .unwrap_or_default();
    Ok((
        quil_execution::global_intrinsic::frame_header::fee_total_to_bytes(
            quil_execution::global_intrinsic::frame_header::fee_total_from_bytes(&header.fee_total),
        ),
        settlement_record::encode_entries(&settlements)?,
        spend_relay::encode_frame_entries(&spends)?,
    ))
}

/// The member executed certified frame `frame` itself: its outgoing records for
/// that frame were committed with its verified state and cursor. When the
/// session's history is audited through `frame - 1`, the audited prefix extends
/// to `frame`, so a restart audits only frames the member did not execute.
/// Without this, every restart re-audited everything since the last restart at
/// eight frames per retry (four minutes for 240 frames on a localnet, hours for
/// a shard that ran a day), with the whole committee out of consensus.
///
/// Any other state (a sync jump, an audit in progress, a concurrent write)
/// leaves the prefix unchanged, and the next recovery audits the difference.
pub fn extend_audited(
    manager: &ExecutionEngineManager,
    session: &Session,
    frame: u64,
) -> Result<bool> {
    if frame <= session.base_frame {
        return Ok(false);
    }
    let shard = manager.crdt();
    let snapshot = shard.capture_committed_shard(&session.filter)?;
    let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
    if snapshot.records.read_record(&cursor_key)?.as_deref() != Some(frame.to_be_bytes().as_slice())
    {
        return Ok(false);
    }
    let progress_key = encoding::app_history_recovery_key(&session.filter, &session.id()?);
    let mut progress: Progress = match snapshot.records.read_record(&progress_key)? {
        Some(bytes) if bytes.len() <= MAX_PROGRESS_BYTES => serde_json::from_slice(&bytes)
            .map_err(|_| unavailable("malformed recovery progress"))?,
        Some(_) => return Err(unavailable("oversized recovery progress")),
        None => Progress {
            version: 1,
            session: session.id()?,
            done: session.base_frame,
            target: session.base_frame,
            next: session.base_frame,
            carry: 0,
            last_report: Vec::new(),
            reports: Vec::new(),
            implied: None,
        },
    };
    progress.validate(session, frame)?;
    if progress.done + 1 != frame
        || progress.next != progress.done
        || progress.target != progress.done
    {
        return Ok(false);
    }
    for key in [
        encoding::clock_shard_frame_fee_total_key(&session.filter, frame),
        encoding::clock_shard_frame_settlements_key(&session.filter, frame),
        encoding::clock_shard_frame_spends_key(&session.filter, frame),
        encoding::clock_shard_frame_accumulator_key(&session.filter, frame),
    ] {
        if snapshot.records.read_record(&key)?.is_none() {
            return Ok(false);
        }
    }
    progress.done = frame;
    progress.target = frame;
    progress.next = frame;
    let encoded = serde_json::to_vec(&progress).map_err(|e| unavailable(e.to_string()))?;
    shard.checkpoint_shard_records(
        &session.filter,
        &snapshot.roots,
        &cursor_key,
        frame,
        &[(progress_key, encoded)],
    )?;
    Ok(true)
}

/// Header `n + 1` omitted frame `n`'s report off the heartbeat, and neither an
/// authenticated state nor the carry window resolves it. An omitted report is
/// empty or unchanged from the previous frame. Coin blocks are append-only and
/// a session's range is fixed, so a shard's report never becomes empty within
/// a session: an empty report `n` means report `n - 1` was empty too. Either
/// way report `n` equals report `n - 1`, so the nearest earlier frame whose
/// report is determined decides it: a carried report, an omission on a
/// heartbeat (empty), a known state, or this session's audited record at
/// `done`. A heartbeat header always decides, which bounds the search.
///
/// Returns that frame and its report; `None` when the search reaches the
/// session base undecided.
async fn earlier_report(
    headers: &dyn VerifiedHeaders,
    progress: &Progress,
    records: &dyn SnapshotReadable,
    session: &Session,
    n: u64,
) -> Result<Option<(u64, Vec<u8>)>> {
    let mut m = n;
    while m > progress.done {
        m -= 1;
        if m == progress.done && progress.done > session.base_frame {
            return recorded_report(records, &session.filter, m).map(|report| Some((m, report)));
        }
        let header = headers.get(m + 1).await?;
        if !header.accumulator.is_empty() || (m + 1) % HEARTBEAT_FRAMES == 0 {
            if !header.accumulator.is_empty() {
                shard_accumulator::ShardReport::decode(&header.accumulator)?;
            }
            return Ok(Some((m, header.accumulator)));
        }
        if let Some(report) = progress.report(&header_roots(&header)?) {
            return Ok(Some((m, report)));
        }
    }
    Ok(None)
}

/// The audited report of a frame this session already recovered.
fn recorded_report(records: &dyn SnapshotReadable, filter: &[u8], frame: u64) -> Result<Vec<u8>> {
    let digest = records
        .read_record(&encoding::clock_shard_frame_accumulator_key(filter, frame))?
        .ok_or_else(|| unavailable(format!("audited frame {frame} has no accumulator record")))?;
    if digest.is_empty() {
        return Ok(Vec::new());
    }
    let report = records
        .read_record(&encoding::clock_shard_accumulator_report_key(
            filter, &digest,
        ))?
        .ok_or_else(|| unavailable(format!("audited frame {frame} lacks its report")))?;
    if accumulator_header::report_digest(&report) != digest {
        return Err(unavailable(format!(
            "audited frame {frame} report does not match its digest"
        )));
    }
    Ok(report)
}

/// One bounded batch; false means the caller must remain out of consensus and
/// retry. Completed records and the next recovery position share one write.
/// `global` supplies the digests GLOBAL committed for the shard's frames,
/// which authenticate a frame without a certificate of its own.
pub async fn recover(
    session: &Session,
    manager: Arc<ExecutionEngineManager>,
    clock: Arc<dyn ClockStore>,
    validator: Arc<BlsAppFrameValidator>,
    global: Option<&Arc<quil_hypergraph::HypergraphCrdt>>,
    source: Option<&DeliveryFrameSource>,
    expected_cursor: u64,
) -> Result<bool> {
    let committed = |number: u64| committed_digest(global, &session.filter, number);
    let headers = Headers::new(
        &session.filter,
        Some(session.generation),
        clock.as_ref(),
        validator.as_ref(),
        source,
        &committed,
    );
    recover_with_headers(session, manager, &headers, expected_cursor).await
}

async fn recover_with_headers(
    session: &Session,
    manager: Arc<ExecutionEngineManager>,
    headers: &dyn VerifiedHeaders,
    expected_cursor: u64,
) -> Result<bool> {
    if expected_cursor < session.base_frame {
        return Err(unavailable("cursor precedes the session base"));
    }
    if expected_cursor == session.base_frame {
        return Ok(true);
    }
    let shard = manager.crdt();
    let snapshot = shard.capture_committed_shard(&session.filter)?;
    let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
    if snapshot.records.read_record(&cursor_key)?.as_deref()
        != Some(expected_cursor.to_be_bytes().as_slice())
    {
        return Err(unavailable("engine cursor differs from committed state"));
    }
    let progress_key = encoding::app_history_recovery_key(&session.filter, &session.id()?);
    let stored = snapshot.records.read_record(&progress_key)?;
    let mut progress: Progress = match stored {
        Some(bytes) => {
            if bytes.len() > MAX_PROGRESS_BYTES {
                return Err(unavailable("oversized recovery progress"));
            }
            serde_json::from_slice(&bytes)
                .map_err(|_| unavailable("malformed recovery progress"))?
        }
        None => Progress {
            version: 1,
            session: session.id()?,
            done: session.base_frame,
            target: session.base_frame,
            next: session.base_frame,
            carry: 0,
            last_report: Vec::new(),
            reports: Vec::new(),
            implied: None,
        },
    };
    progress.validate(session, expected_cursor)?;
    if progress.done == expected_cursor {
        return Ok(true);
    }
    if progress.next == progress.done {
        // The durable cursor denotes locally executed post-state. Authenticate
        // its certified frame before deriving the report from this snapshot.
        let anchor = headers.get(expected_cursor).await?.global_frame_number;
        let manager = manager.clone();
        let records = snapshot.records.clone();
        let filter = session.filter.clone();
        let report = tokio::task::spawn_blocking(move || {
            manager.snapshot_accumulator_report(records.as_ref(), &filter, anchor)
        })
        .await
        .map_err(|e| unavailable(format!("snapshot report task: {e}")))??;
        progress.target = expected_cursor;
        progress.next = expected_cursor;
        progress.carry = 0;
        progress.last_report = report.clone();
        progress.reports.clear();
        progress.implied = None;
        progress.remember(snapshot.roots, report)?;
    }
    let start = Instant::now();
    let mut records = Vec::new();
    let mut processed = 0;
    let mut blocked = None;
    while progress.next > progress.done
        && processed < MAX_FRAMES
        && start.elapsed() < Duration::from_secs(3)
    {
        let n = progress.next;
        let recovered = async {
            if n == progress.target {
                let fees = required(
                    snapshot.records.as_ref(),
                    &encoding::clock_shard_frame_fee_total_key(&session.filter, n),
                )?;
                let settlements = required(
                    snapshot.records.as_ref(),
                    &encoding::clock_shard_frame_settlements_key(&session.filter, n),
                )?;
                let spends = required(
                    snapshot.records.as_ref(),
                    &encoding::clock_shard_frame_spends_key(&session.filter, n),
                )?;
                if fees.len() != 16 {
                    return Err(unavailable("malformed tip fee total"));
                }
                settlement_record::decode_entries(&settlements)?;
                spend_relay::decode_frame_entries(&spends)?;
                return Ok((
                    fees,
                    settlements,
                    spends,
                    progress.last_report.clone(),
                    None,
                ));
            }
            let header = headers.get(n + 1).await?;
            let roots = header_roots(&header)?;
            let mut report = progress.resolve(&header)?;
            if report.is_none() {
                // A preceding heartbeat may authenticate the same unchanged
                // state even when this member's first saved frame is later.
                // A heartbeat at or below the session base belongs to another
                // shard's history (this filter has no frame there).
                let heartbeat = header.frame_number / HEARTBEAT_FRAMES * HEARTBEAT_FRAMES;
                if heartbeat > session.base_frame && heartbeat < header.frame_number {
                    let anchor = headers.get(heartbeat).await?;
                    progress.remember(header_roots(&anchor)?, anchor.accumulator)?;
                    report = progress.resolve(&header)?;
                }
            }
            let implied = progress
                .implied
                .as_ref()
                .filter(|(low, _)| n > *low)
                .map(|(_, report)| report.clone());
            if report.is_none() {
                report = implied.clone();
            }
            if report.is_none() {
                if let Some((low, earlier)) =
                    earlier_report(headers, &progress, snapshot.records.as_ref(), session, n)
                        .await?
                {
                    progress.implied = Some((low, earlier.clone()));
                    report = Some(earlier);
                }
            } else if implied.is_some() && report != implied {
                return Err(unavailable("certified accumulator constraints disagree"));
            }
            let report = report.ok_or_else(|| {
                unavailable(format!("no authenticated accumulator report for frame {n}"))
            })?;
            progress.remember(roots, report.clone())?;
            let (fees, settlements, spends) = outflows(&header, n)?;
            Ok((
                fees,
                settlements,
                spends,
                report,
                Some(header.accumulator.is_empty()),
            ))
        }
        .await;
        let (fees, settlements, spends, report, omitted) = match recovered {
            Ok(value) => value,
            Err(error) => {
                blocked = Some(error);
                break;
            }
        };
        let digest = accumulator_header::report_digest(&report);
        records.extend([
            (
                encoding::clock_shard_frame_fee_total_key(&session.filter, n),
                fees,
            ),
            (
                encoding::clock_shard_frame_settlements_key(&session.filter, n),
                settlements,
            ),
            (
                encoding::clock_shard_frame_spends_key(&session.filter, n),
                spends,
            ),
            (
                encoding::clock_shard_frame_accumulator_key(&session.filter, n),
                digest.clone(),
            ),
        ]);
        if !digest.is_empty() {
            records.push((
                encoding::clock_shard_accumulator_report_key(&session.filter, &digest),
                report.clone(),
            ));
        }
        progress.carry = if omitted == Some(true) && !report.is_empty() {
            CARRY_WINDOW_FRAMES
        } else {
            progress.carry.saturating_sub(1)
        };
        progress.last_report = report;
        progress.next -= 1;
        if progress
            .implied
            .as_ref()
            .is_some_and(|(low, _)| *low >= progress.next)
        {
            progress.implied = None;
        }
        processed += 1;
    }
    if processed == 0 {
        return Err(blocked.unwrap_or_else(|| unavailable("no recovery progress")));
    }
    if progress.next == progress.done {
        progress.done = progress.target;
        progress.next = progress.target;
        progress.reports.clear();
        progress.last_report.clear();
        progress.carry = 0;
        progress.implied = None;
    }
    let encoded = serde_json::to_vec(&progress).map_err(|e| unavailable(e.to_string()))?;
    if encoded.len() > MAX_PROGRESS_BYTES {
        return Err(unavailable("recovery progress exceeds byte limit"));
    }
    records.push((progress_key, encoded));
    if records
        .iter()
        .map(|(k, v)| k.len() + v.len())
        .sum::<usize>()
        > MAX_BATCH_BYTES
    {
        return Err(unavailable("recovery batch exceeds byte limit"));
    }
    shard.checkpoint_shard_records(
        &session.filter,
        &snapshot.roots,
        &cursor_key,
        expected_cursor,
        &records,
    )?;
    if walk_batch(
        &session.filter,
        (progress.done, progress.next, progress.target),
        Instant::now(),
    ) {
        tracing::info!(
            filter = hex::encode(&session.filter),
            generation = session.generation,
            processed,
            target = progress.target,
            next = progress.next,
            done = progress.done,
            remaining = progress.next.saturating_sub(progress.done),
            completed = progress.done == progress.target,
            "recovered authenticated outgoing history batch"
        );
    } else {
        tracing::debug!(
            filter = hex::encode(&session.filter),
            processed,
            target = progress.target,
            next = progress.next,
            done = progress.done,
            "recovered authenticated outgoing history batch"
        );
    }
    if let Some(error) = blocked {
        tracing::warn!(filter = hex::encode(&session.filter), %error, "outgoing history recovery remains incomplete");
    }
    Ok(progress.done == expected_cursor)
}

/// Fill the accumulator records of the carry window below this member's tip
/// that it never executed or recovered, from authenticated headers only.
///
/// The field of header `cursor + 1` reads the reports of frames
/// `cursor - CARRY_WINDOW_FRAMES ..= cursor`
/// ([`crate::app_engine::accumulator_field`]). A member that joined at or near
/// the tip holds no record below its first executed or recovered frame: an
/// archive bootstrap replays only its anchor, and [`recover`] audits only a
/// session's own frames. Its fee and settlement checks still pass from the
/// certified relay windows it adopted, so it nullifies every next header over
/// the accumulator field alone, and the heartbeat that would settle the field
/// is never reached while too many members do so.
///
/// A missing frame `k` is resolved by the rules [`recover`] applies: header
/// `k + 1` carries its report or is a heartbeat; header `k + 1`'s pre-state
/// roots equal a state whose report is known (this member's committed tip);
/// or a later header omitted a nonempty report, which fixes the frames of its
/// carry window. Anything else stays unknown. Existing records are never
/// replaced, and one that contradicts the certified headers fails the whole
/// batch. Returns the frames written and the first frame left unresolved.
/// `global` authenticates headers as in [`recover`].
pub async fn recover_carry_window(
    filter: &[u8],
    manager: Arc<ExecutionEngineManager>,
    clock: Arc<dyn ClockStore>,
    validator: Arc<BlsAppFrameValidator>,
    global: Option<&Arc<quil_hypergraph::HypergraphCrdt>>,
    source: Option<&DeliveryFrameSource>,
    cursor: u64,
) -> Result<(usize, Option<u64>)> {
    let committed = |number: u64| committed_digest(global, filter, number);
    let headers = Headers::new(
        filter,
        None,
        clock.as_ref(),
        validator.as_ref(),
        source,
        &committed,
    );
    recover_carry_window_with_headers(filter, manager, clock.as_ref(), &headers, cursor).await
}

async fn recover_carry_window_with_headers(
    filter: &[u8],
    manager: Arc<ExecutionEngineManager>,
    clock: &dyn ClockStore,
    headers: &dyn VerifiedHeaders,
    cursor: u64,
) -> Result<(usize, Option<u64>)> {
    if cursor <= 1 {
        return Ok((0, None));
    }
    let low = cursor.saturating_sub(CARRY_WINDOW_FRAMES).max(1);
    let shard = manager.crdt();
    let snapshot = shard.capture_committed_shard(filter)?;
    let cursor_key = encoding::consensus_materialized_cursor_key(filter);
    if snapshot.records.read_record(&cursor_key)?.as_deref()
        != Some(cursor.to_be_bytes().as_slice())
    {
        return Err(unavailable("engine cursor differs from committed state"));
    }
    let digest_of = |frame: u64| {
        snapshot
            .records
            .read_record(&encoding::clock_shard_frame_accumulator_key(filter, frame))
    };
    // An empty tip report is never carried, so the field does not read the
    // window; without a tip record the field is unknown for another reason.
    match digest_of(cursor)? {
        Some(digest) if !digest.is_empty() => {}
        _ => return Ok((0, None)),
    }
    if (low..cursor)
        .map(&digest_of)
        .collect::<Result<Vec<_>>>()?
        .iter()
        .all(Option::is_some)
    {
        return Ok((0, None));
    }
    // The tip's record was committed with the state this snapshot holds.
    let tip = recorded_report(snapshot.records.as_ref(), filter, cursor)?;
    let mut progress = Progress {
        version: 1,
        session: [0; 32],
        done: 0,
        target: 0,
        next: 0,
        carry: 0,
        last_report: tip.clone(),
        reports: Vec::new(),
        implied: None,
    };
    progress.remember(snapshot.roots, tip)?;
    let mut records = Vec::new();
    let mut written = 0;
    let mut unresolved = None;
    let mut blocked = None;
    let mut frame = cursor;
    while frame > low {
        frame -= 1;
        if crate::app_engine::legacy_relay_frame(clock, filter, frame) {
            break;
        }
        let (derived, omitted) = if progress.carry > 0 {
            (Some(progress.last_report.clone()), None)
        } else {
            let header = match headers.get(frame + 1).await {
                Ok(header) => header,
                Err(error) => {
                    unresolved = Some(frame);
                    blocked = Some(error);
                    break;
                }
            };
            let report = progress.resolve(&header)?;
            if let Some(report) = report.as_ref() {
                progress.remember(header_roots(&header)?, report.clone())?;
            }
            (report, Some(header.accumulator.is_empty()))
        };
        let recorded = match digest_of(frame)? {
            Some(_) => Some(recorded_report(snapshot.records.as_ref(), filter, frame)?),
            None => None,
        };
        let report = match (derived, recorded) {
            (Some(derived), Some(recorded)) if derived != recorded => {
                return Err(unavailable(format!(
                    "frame {frame}'s accumulator record differs from its certified carry window"
                )));
            }
            (_, Some(recorded)) => recorded,
            (Some(derived), None) => {
                let digest = accumulator_header::report_digest(&derived);
                records.push((
                    encoding::clock_shard_frame_accumulator_key(filter, frame),
                    digest.clone(),
                ));
                if !digest.is_empty() {
                    records.push((
                        encoding::clock_shard_accumulator_report_key(filter, &digest),
                        derived.clone(),
                    ));
                }
                written += 1;
                derived
            }
            (None, None) => {
                unresolved = Some(frame);
                break;
            }
        };
        progress.carry = if omitted == Some(true) && !report.is_empty() {
            CARRY_WINDOW_FRAMES
        } else {
            progress.carry.saturating_sub(1)
        };
        progress.last_report = report;
    }
    if !records.is_empty() {
        shard.checkpoint_shard_records(filter, &snapshot.roots, &cursor_key, cursor, &records)?;
    } else if let Some(error) = blocked {
        return Err(error);
    }
    Ok((written, unresolved))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::Signer as _;
    use std::{collections::BTreeMap, path::Path, sync::Mutex};

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "quil-history-recovery-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn session() -> Session {
        Session {
            chain_id: [1; 32],
            filter: quil_forest::encode_shard_bit_path(&[2; 32], &[false; 6]),
            generation: 2,
            genesis: [3; 32],
            base_frame: 77,
            authorization: [4; 32],
            members: vec![quil_crypto::FalconSigner::generate().public_key().to_vec()],
        }
    }

    fn progress(session: &Session) -> Progress {
        Progress {
            version: 1,
            session: session.id().unwrap(),
            done: 77,
            target: 95,
            next: 94,
            carry: 0,
            last_report: vec![],
            reports: vec![],
            implied: None,
        }
    }

    fn header(session: &Session, number: u64, roots: Roots) -> FrameHeader {
        FrameHeader {
            address: session.filter.clone(),
            frame_number: number,
            state_roots: roots.iter().map(|root| root.to_vec()).collect(),
            fee_total: quil_execution::global_intrinsic::frame_header::fee_total_field(fee(
                number - 1
            )),
            spends: spend_relay::encode_relay(&[(number - 1, vec![vec![number as u8 - 1; 3]])])
                .unwrap(),
            ..Default::default()
        }
    }

    fn fee(frame: u64) -> u128 {
        if frame % 2 == 0 {
            0
        } else {
            u128::from(frame)
        }
    }

    #[test]
    fn header_fee_encoding_is_normalized_without_inventing_missing_tip_records() {
        let session = session();
        let mut h = header(&session, 95, [[0; 32]; 4]);
        assert!(
            h.fee_total.is_empty(),
            "wire zero is omitted by the production frame encoder"
        );
        assert_eq!(outflows(&h, 94).unwrap().0, 0u128.to_be_bytes());
        h.fee_total = 42u128.to_be_bytes().to_vec();
        assert_eq!(outflows(&h, 94).unwrap().0, 42u128.to_be_bytes());
        h.fee_total = vec![1];
        assert!(outflows(&h, 94).is_err());
        h.fee_total.clear();
        assert!(outflows(&h, 93).is_err());
    }

    // A structurally valid nonempty report with a zero subtree root. These
    // unit cases test constraints, not certification of its contents.
    fn report(context: u8) -> Vec<u8> {
        let layer_bytes = shard_accumulator::LAYER_BYTES;
        let mut bytes = b"QCT3AR\0\x01".to_vec();
        bytes.extend_from_slice(&[context; 32]);
        bytes.push(1);
        bytes.push(6);
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.resize(41 + layer_bytes, 0);
        shard_accumulator::ShardReport::decode(&bytes).unwrap();
        bytes
    }

    #[test]
    fn omission_is_resolved_only_by_an_authenticated_state_or_nonempty_carry() {
        let session = session();
        let mut p = progress(&session);
        let roots = [[1; 32]; 4];
        let mut h = header(&session, 93, roots);
        let a = report(1);
        let b = report(2);
        p.remember([[2; 32]; 4], a.clone()).unwrap();
        p.last_report = a.clone();
        assert!(
            p.resolve(&h).unwrap().is_none(),
            "a newer report alone proves nothing"
        );
        p.remember(roots, a.clone()).unwrap();
        assert_eq!(p.resolve(&h).unwrap(), Some(a.clone()));
        p.reports.clear();
        p.carry = 1;
        assert_eq!(p.resolve(&h).unwrap(), Some(a.clone()));
        h.accumulator = b.clone();
        assert!(
            p.resolve(&h).is_err(),
            "a carried report must satisfy the certified omission window"
        );
        p.carry = 0;
        assert_eq!(p.resolve(&h).unwrap(), Some(b));
        h.accumulator.clear();
        h.frame_number = 96;
        assert_eq!(
            p.resolve(&h).unwrap(),
            Some(vec![]),
            "a mandatory empty heartbeat establishes absence"
        );
        p.remember(roots, a.clone()).unwrap();
        assert!(
            p.resolve(&h).is_err(),
            "the same state cannot have empty and nonempty reports"
        );
        assert!(p.remember(roots, vec![]).is_err());
        p.reports.clear();
        p.carry = 1;
        assert!(p.resolve(&h).is_err());
        p.carry = 0;
        h.frame_number = 93;
        h.accumulator = b"not a report".to_vec();
        assert!(p.resolve(&h).is_err());
    }

    #[test]
    fn progress_rejects_wrong_sessions_ranges_and_inconsistent_constraints() {
        let session = session();
        let mut p = progress(&session);
        p.validate(&session, 95).unwrap();
        p.session[0] ^= 1;
        assert!(p.validate(&session, 95).is_err());
        p.session = session.id().unwrap();
        p.next = 76;
        assert!(p.validate(&session, 95).is_err());
        p.next = 94;
        assert!(p.validate(&session, 94).is_err());
        p.carry = 1;
        assert!(p.validate(&session, 95).is_err());
        p.last_report = report(1);
        p.validate(&session, 95).unwrap();
        p.reports = vec![([[1; 32]; 4], vec![]), ([[1; 32]; 4], vec![])];
        assert!(p.validate(&session, 95).is_err());
    }

    fn open(
        path: &Path,
    ) -> (
        quil_store::RocksDb,
        Arc<quil_store::RocksHypergraphStore>,
        Arc<ExecutionEngineManager>,
    ) {
        let db = quil_store::RocksDb::open(path).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let prover = Arc::new(quil_types::crypto::NoopInclusionProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            prover.clone(),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(true);
        let stubs = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = Arc::new(ExecutionEngineManager::new(
            prover,
            stubs.key_manager,
            crdt,
            stubs.circuit_compiler,
            Arc::new(quil_store::RocksClockStore::new(db.inner())),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            false,
        ));
        (db, store, manager)
    }

    fn tip(session: &Session, n: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (
                encoding::clock_shard_frame_fee_total_key(&session.filter, n),
                fee(n).to_be_bytes().to_vec(),
            ),
            (
                encoding::clock_shard_frame_settlements_key(&session.filter, n),
                settlement_record::encode_entries(&[]).unwrap(),
            ),
            (
                encoding::clock_shard_frame_spends_key(&session.filter, n),
                spend_relay::encode_frame_entries(&[vec![n as u8; 3]]).unwrap(),
            ),
            (
                encoding::clock_shard_frame_accumulator_key(&session.filter, n),
                vec![9; 32],
            ),
        ]
    }

    // Bypass only header authentication for storage/fault tests. The separate
    // production-source test below uses the real validator and rejects unsigned
    // frames before even a progress marker is written.
    struct VerifiedFixture {
        frames: BTreeMap<u64, FrameHeader>,
        fail_at: Mutex<Option<u64>>,
        reads: Mutex<Vec<u64>>,
    }
    #[async_trait::async_trait]
    impl VerifiedHeaders for VerifiedFixture {
        async fn get(&self, number: u64) -> Result<FrameHeader> {
            self.reads.lock().unwrap().push(number);
            if *self.fail_at.lock().unwrap() == Some(number) {
                return Err(unavailable("test source unavailable"));
            }
            self.frames
                .get(&number)
                .cloned()
                .ok_or_else(|| unavailable("test source missing frame"))
        }
    }

    #[tokio::test]
    async fn bounded_recovery_resumes_after_reopen_fetch_failure_and_failed_commit() {
        let directory = Directory::new();
        let session = session();
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        let progress_key =
            encoding::app_history_recovery_key(&session.filter, &session.id().unwrap());
        let headers = VerifiedFixture {
            frames: (78..=96)
                .map(|n| (n, header(&session, n, [[0; 32]; 4])))
                .collect(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        {
            let (_db, _store, manager) = open(&directory.0);
            let mut records = tip(&session, 95);
            records.push((
                encoding::clock_shard_frame_accumulator_key(&session.filter, 82),
                vec![8; 32],
            ));
            manager
                .crdt()
                .commit_with_frame_cursor_and_records(95, &cursor_key, &records)
                .unwrap();
            assert!(
                !recover_with_headers(&session, manager.clone(), &headers, 95)
                    .await
                    .unwrap()
            );
            let snapshot = manager
                .crdt()
                .capture_committed_shard(&session.filter)
                .unwrap();
            let p: Progress = serde_json::from_slice(
                &snapshot
                    .records
                    .read_record(&progress_key)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!((p.done, p.target, p.next), (77, 95, 87));
            assert!(snapshot
                .records
                .read_record(&encoding::clock_shard_frame_fee_total_key(
                    &session.filter,
                    87
                ))
                .unwrap()
                .is_none());
            assert_eq!(snapshot.roots, [[0; 32]; 4]);
        }
        {
            let (db, store, manager) = open(&directory.0);
            *headers.fail_at.lock().unwrap() = Some(85);
            assert!(
                !recover_with_headers(&session, manager.clone(), &headers, 95)
                    .await
                    .unwrap()
            );
            let partial = manager
                .crdt()
                .capture_committed_shard(&session.filter)
                .unwrap();
            let saved = partial.records.read_record(&progress_key).unwrap().unwrap();
            let p: Progress = serde_json::from_slice(&saved).unwrap();
            assert_eq!(p.next, 84);
            *headers.fail_at.lock().unwrap() = None;
            store.fail_commit_for_test(true);
            assert!(
                recover_with_headers(&session, manager.clone(), &headers, 95)
                    .await
                    .is_err()
            );
            let failed = manager
                .crdt()
                .capture_committed_shard(&session.filter)
                .unwrap();
            assert_eq!(
                failed.records.read_record(&progress_key).unwrap(),
                Some(saved)
            );
            assert!(failed
                .records
                .read_record(&encoding::clock_shard_frame_fee_total_key(
                    &session.filter,
                    84
                ))
                .unwrap()
                .is_none());
            store.fail_commit_for_test(false);
            assert!(
                recover_with_headers(&session, manager.clone(), &headers, 95)
                    .await
                    .unwrap()
            );
            let complete = manager
                .crdt()
                .capture_committed_shard(&session.filter)
                .unwrap();
            for n in 78..=95 {
                for (key, value) in tip(&session, n).into_iter().take(3) {
                    assert_eq!(
                        complete.records.read_record(&key).unwrap(),
                        Some(value),
                        "frame {n}"
                    );
                }
                assert_eq!(
                    complete
                        .records
                        .read_record(&encoding::clock_shard_frame_accumulator_key(
                            &session.filter,
                            n
                        ))
                        .unwrap(),
                    Some(vec![])
                );
            }
            assert_eq!(complete.roots, [[0; 32]; 4]);
            assert_eq!(
                complete.records.read_record(&cursor_key).unwrap(),
                Some(95u64.to_be_bytes().to_vec())
            );
            quil_execution::global_intrinsic::handoff::history::root(
                complete.records.as_ref(),
                &session,
                95,
            )
            .unwrap();
            assert!(quil_store::RocksClockStore::new(db.inner()).get_latest_shard_clock_frame(&session.filter).is_err(),
                "history repair never installs synthetic header bodies or advances the canonical head");
        }
        let (_db, _store, manager) = open(&directory.0);
        headers.reads.lock().unwrap().clear();
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap()
        );
        assert!(
            headers.reads.lock().unwrap().is_empty(),
            "a completed prefix survives restart"
        );
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(96, &cursor_key, &tip(&session, 96))
            .unwrap();
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 96)
                .await
                .unwrap()
        );
        assert_eq!(
            *headers.reads.lock().unwrap(),
            vec![96],
            "only the new tail needs auditing"
        );
    }

    #[tokio::test]
    async fn nonempty_omission_constraints_and_report_blobs_survive_batch_boundaries() {
        let directory = Directory::new();
        let session = session();
        let (_, _, manager) = open(&directory.0);
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(95, &cursor_key, &tip(&session, 95))
            .unwrap();
        let carried = report(1);
        let headers = VerifiedFixture {
            frames: (78..=95)
                .map(|n| {
                    let roots = if n > 92 {
                        [[0; 32]; 4]
                    } else if n >= 91 {
                        [[1; 32]; 4]
                    } else {
                        [[n as u8; 32]; 4]
                    };
                    let mut h = header(&session, n, roots);
                    if n == 92 {
                        h.accumulator = carried.clone();
                    }
                    (n, h)
                })
                .collect(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        assert!(
            !recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap()
        );
        assert!(
            !recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap()
        );
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap()
        );
        let snapshot = manager
            .crdt()
            .capture_committed_shard(&session.filter)
            .unwrap();
        let digest = accumulator_header::report_digest(&carried);
        for n in 78..=95 {
            let expected = if n <= 91 { digest.clone() } else { vec![] };
            assert_eq!(
                snapshot
                    .records
                    .read_record(&encoding::clock_shard_frame_accumulator_key(
                        &session.filter,
                        n
                    ))
                    .unwrap(),
                Some(expected)
            );
        }
        assert_eq!(
            snapshot
                .records
                .read_record(&encoding::clock_shard_accumulator_report_key(
                    &session.filter,
                    &digest
                ))
                .unwrap(),
            Some(carried)
        );
    }

    // A shard stays out of consensus when header 303 omits frame 302's report
    // right after header 304 carried a changed one: neither the carry window
    // nor a known state decides it. An
    // omitted report equals the previous frame's (coin blocks only grow), so
    // the nearest earlier carried report decides it.
    #[tokio::test]
    async fn an_omission_below_a_changed_report_takes_the_earlier_report() {
        let directory = Directory::new();
        let session = session();
        let (_, _, manager) = open(&directory.0);
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(95, &cursor_key, &tip(&session, 95))
            .unwrap();
        let (a, b) = (report(1), report(2));
        let frames: BTreeMap<u64, FrameHeader> = (78..=95)
            .map(|n| {
                let roots = if n == 95 {
                    [[0; 32]; 4]
                } else {
                    [[n as u8; 32]; 4]
                };
                let mut h = header(&session, n, roots);
                match n {
                    94 => h.accumulator = b.clone(),
                    92 => h.accumulator = a.clone(),
                    _ => {}
                }
                (n, h)
            })
            .collect();
        let headers = VerifiedFixture {
            frames,
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        let mut complete = false;
        for _ in 0..4 {
            complete = recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap();
            if complete {
                break;
            }
        }
        assert!(complete);
        assert!(
            headers
                .reads
                .lock()
                .unwrap()
                .iter()
                .all(|n| *n > session.base_frame),
            "no header before the session base is fetched"
        );
        let snapshot = manager
            .crdt()
            .capture_committed_shard(&session.filter)
            .unwrap();
        let digest = |r: &Vec<u8>| accumulator_header::report_digest(r);
        for n in 78..=94 {
            let expected = match n {
                94 => vec![],
                93 => digest(&b),
                _ => digest(&a),
            };
            assert_eq!(
                snapshot
                    .records
                    .read_record(&encoding::clock_shard_frame_accumulator_key(
                        &session.filter,
                        n
                    ))
                    .unwrap(),
                Some(expected),
                "frame {n}"
            );
        }
    }

    #[tokio::test]
    async fn recovery_rejects_a_saved_audit_past_the_cursor_without_writes() {
        let directory = Directory::new();
        let session = session();
        let (_, _, manager) = open(&directory.0);
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        let progress_key =
            encoding::app_history_recovery_key(&session.filter, &session.id().unwrap());
        let mut saved = progress(&session);
        saved.done = 95;
        saved.next = 95;
        let encoded = serde_json::to_vec(&saved).unwrap();
        let mut records = tip(&session, 94);
        records.push((progress_key.clone(), encoded.clone()));
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(94, &cursor_key, &records)
            .unwrap();
        let headers = VerifiedFixture {
            frames: BTreeMap::new(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        let error = recover_with_headers(&session, manager.clone(), &headers, 94)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("target exceeds cursor"),
            "{error}"
        );
        assert!(
            error.to_string().contains("target=95, cursor=94"),
            "{error}"
        );
        let snapshot = manager
            .crdt()
            .capture_committed_shard(&session.filter)
            .unwrap();
        assert_eq!(
            snapshot.records.read_record(&progress_key).unwrap(),
            Some(encoded)
        );
        assert_eq!(
            snapshot.records.read_record(&cursor_key).unwrap(),
            Some(94u64.to_be_bytes().to_vec())
        );
        assert!(headers.reads.lock().unwrap().is_empty());
        // The same audited prefix is valid when the committed cursor reaches it.
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(95, &cursor_key, &tip(&session, 95))
            .unwrap();
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap()
        );
        assert!(headers.reads.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn executed_frames_extend_the_audited_prefix_but_a_jump_does_not() {
        let directory = Directory::new();
        let session = session();
        let (_, _, manager) = open(&directory.0);
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        let headers = VerifiedFixture {
            frames: (78..=82)
                .map(|n| (n, header(&session, n, [[0; 32]; 4])))
                .collect(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        for n in 78..=79 {
            manager
                .crdt()
                .commit_with_frame_cursor_and_records(n, &cursor_key, &tip(&session, n))
                .unwrap();
            assert!(extend_audited(&manager, &session, n).unwrap(), "frame {n}");
        }
        assert!(
            !extend_audited(&manager, &session, 79).unwrap(),
            "already audited"
        );
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 79)
                .await
                .unwrap()
        );
        assert!(
            headers.reads.lock().unwrap().is_empty(),
            "executed frames need no audit"
        );

        // A frame the member did not execute (a sync jump) is not extended over.
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(81, &cursor_key, &tip(&session, 81))
            .unwrap();
        assert!(!extend_audited(&manager, &session, 81).unwrap());
        let mut complete = false;
        for _ in 0..3 {
            complete = recover_with_headers(&session, manager.clone(), &headers, 81)
                .await
                .unwrap();
            if complete {
                break;
            }
        }
        assert!(complete);
        assert_eq!(
            *headers.reads.lock().unwrap(),
            vec![81, 81],
            "only the jumped frames are audited"
        );
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(82, &cursor_key, &tip(&session, 82))
            .unwrap();
        assert!(extend_audited(&manager, &session, 82).unwrap());
    }

    #[tokio::test]
    async fn unknown_state_and_missing_tip_records_remain_unavailable() {
        let directory = Directory::new();
        let session = session();
        let (_db, _store, manager) = open(&directory.0);
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        manager
            .crdt()
            .checkpoint_frame_cursor(95, &cursor_key)
            .unwrap();
        let headers = VerifiedFixture {
            frames: [
                (95, header(&session, 95, [[1; 32]; 4])),
                (64, header(&session, 64, [[2; 32]; 4])),
            ]
            .into_iter()
            .collect(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 76)
                .await
                .is_err()
        );
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .is_err()
        );
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(95, &cursor_key, &tip(&session, 95))
            .unwrap();
        assert!(
            !recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap()
        );
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .is_err()
        );
        let snapshot = manager
            .crdt()
            .capture_committed_shard(&session.filter)
            .unwrap();
        assert!(snapshot
            .records
            .read_record(&encoding::clock_shard_frame_fee_total_key(
                &session.filter,
                94
            ))
            .unwrap()
            .is_none());
        let key = encoding::app_history_recovery_key(&session.filter, &session.id().unwrap());
        let p: Progress =
            serde_json::from_slice(&snapshot.records.read_record(&key).unwrap().unwrap()).unwrap();
        assert_eq!((p.done, p.next), (77, 94));
    }

    #[tokio::test]
    async fn production_source_rejects_unsigned_or_substituted_frames_without_writes() {
        use quil_types::proto::global::AppShardFrame;
        let directory = Directory::new();
        let session = session();
        let (db, _store, manager) = open(&directory.0);
        let clock: Arc<dyn ClockStore> = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        let validator = Arc::new(BlsAppFrameValidator::new(
            Arc::new(crate::test_support::TestProverRegistry::new()),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        ));
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(95, &cursor_key, &tip(&session, 95))
            .unwrap();
        let mut unsigned = header(&session, 95, [[0; 32]; 4]);
        unsigned.output = quil_crypto::porep::deterministic_app_frame_output(
            &unsigned.parent_selector,
            &unsigned.requests_root,
            &unsigned.state_roots,
            &quil_crypto::porep::derive_storage_beacon(0, &[]),
            unsigned.frame_number,
            unsigned.rank,
            &unsigned.prover,
            unsigned.difficulty,
            unsigned.fee_multiplier_vote,
            unsigned.timestamp,
            &unsigned.storage_attestation_root,
            fee(94),
            &unsigned.settlements,
            &unsigned.accumulator,
            &unsigned.spends,
        );
        for variant in 0..4 {
            let mut h = unsigned.clone();
            match variant {
                1 => h.frame_number += 1,
                2 => h.address[0] ^= 1,
                3 => h.output[0] ^= 1,
                _ => {}
            }
            let frame = AppShardFrame {
                header: Some(h),
                requests: vec![],
                storage_attestation: None,
            };
            let source: DeliveryFrameSource = Arc::new(move |_, _| {
                let frame = frame.clone();
                Box::pin(async move { Some(frame) })
            });
            let error = recover(
                &session,
                manager.clone(),
                clock.clone(),
                validator.clone(),
                None,
                Some(&source),
                95,
            )
            .await
            .unwrap_err();
            if variant == 0 {
                assert!(
                    error
                        .to_string()
                        .contains("historical frame 95 of generation 2 ")
                        && error.to_string().contains("no certificate of its own"),
                    "{error}"
                );
            }
            let snapshot = manager
                .crdt()
                .capture_committed_shard(&session.filter)
                .unwrap();
            assert!(snapshot
                .records
                .read_record(&encoding::app_history_recovery_key(
                    &session.filter,
                    &session.id().unwrap()
                ))
                .unwrap()
                .is_none());
            assert_eq!(
                snapshot
                    .records
                    .read_record(&encoding::clock_shard_frame_accumulator_key(
                        &session.filter,
                        95
                    ))
                    .unwrap(),
                Some(vec![9; 32])
            );
        }
    }

    fn validator() -> BlsAppFrameValidator {
        BlsAppFrameValidator::new(
            Arc::new(crate::test_support::TestProverRegistry::new()),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        )
    }

    /// A validator whose live legacy committee is `signer` alone.
    fn validator_trusting(signer: &quil_crypto::FalconSigner) -> BlsAppFrameValidator {
        use quil_types::consensus::{ProverInfo, ProverStatus};
        BlsAppFrameValidator::new(
            Arc::new(crate::test_support::TestProverRegistry::with_prover(
                ProverInfo {
                    public_key: signer.public_key().to_vec(),
                    address: vec![7; 32],
                    status: ProverStatus::Active,
                    kick_frame_number: 0,
                    allocations: vec![],
                    available_storage: 0,
                    seniority: 0,
                    delegate_address: vec![],
                },
            )),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        )
    }

    /// Give `header` a legacy CW finalization certificate of `signer`.
    fn certify(header: &mut FrameHeader, signer: &quil_crypto::FalconSigner) {
        use quil_cw_consensus::{
            _consensus::{
                simplex::{
                    scheme::Namespace,
                    types::{Finalization, Proposal, Subject},
                },
                types::{Epoch, Round, View},
            },
            _crypto::{sha256::Digest, Signer as _},
            _utils::{ordered::Set, N3f1},
            app_cert::{encode_finalization, wrap_cert_for_header},
            falcon_base::FalconPrivateKey,
            falcon_scheme::Generic,
            falcon_simplex::SimplexFalconScheme,
        };
        let key = FalconPrivateKey::from_bytes(signer.private_key(), signer.public_key()).unwrap();
        let participants: Set<_> = vec![key.public_key()].try_into().unwrap();
        let mut namespace = b"appshard".to_vec();
        namespace.extend_from_slice(&header.address);
        let scheme = Generic::<Namespace>::signer(&namespace, participants, key).unwrap();
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(header.rank)),
            View::new(header.rank - 1),
            Digest(digest(header)),
        );
        let vote = scheme
            .sign::<SimplexFalconScheme, Digest>(Subject::Finalize {
                proposal: &proposal,
            })
            .unwrap();
        let certificate = scheme
            .assemble::<SimplexFalconScheme, _, N3f1>(vec![vote])
            .unwrap();
        header.public_key_signature_bls48581 =
            Some(quil_types::proto::keys::Bls48581AggregateSignature {
                signature: wrap_cert_for_header(&encode_finalization(&Finalization {
                    proposal,
                    certificate,
                })),
                bitmask: vec![1],
                ..Default::default()
            });
    }

    fn digest(header: &FrameHeader) -> [u8; 32] {
        quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap()
    }

    /// Frames `from..=to` of one shard with no certificate of their own,
    /// each naming the one below as its parent at a later rank, with the
    /// output the validator recomputes.
    fn uncertified_chain(session: &Session, from: u64, to: u64, roots: Roots) -> Vec<FrameHeader> {
        let mut parent = vec![7; 32];
        (from..=to)
            .map(|n| {
                let mut h = header(session, n, roots);
                h.rank = n;
                h.parent_selector = parent.clone();
                h.output = quil_crypto::porep::deterministic_app_frame_output(
                    &h.parent_selector,
                    &h.requests_root,
                    &h.state_roots,
                    &quil_crypto::porep::derive_storage_beacon(0, &[]),
                    h.frame_number,
                    h.rank,
                    &h.prover,
                    h.difficulty,
                    h.fee_multiplier_vote,
                    h.timestamp,
                    &h.storage_attestation_root,
                    quil_execution::global_intrinsic::frame_header::fee_total_from_bytes(
                        &h.fee_total,
                    ),
                    &h.settlements,
                    &h.accumulator,
                    &h.spends,
                );
                parent = digest(&h).to_vec();
                h
            })
            .collect()
    }

    fn store(clock: &quil_store::RocksClockStore, header: &FrameHeader) {
        let selector = digest(header).to_vec();
        let txn = clock.new_transaction(false).unwrap();
        clock
            .stage_shard_clock_frame(&selector, &header_only(header), txn.as_ref())
            .unwrap();
        txn.commit().unwrap();
        let txn = clock.new_transaction(false).unwrap();
        clock
            .commit_shard_clock_frame(
                &header.address,
                header.frame_number,
                &selector,
                txn.as_ref(),
                false,
            )
            .unwrap();
        txn.commit().unwrap();
    }

    fn opened() -> (Directory, quil_store::RocksDb) {
        let directory = Directory::new();
        let db = quil_store::RocksDb::open(&directory.0).unwrap();
        (directory, db)
    }

    fn stored(
        session: &Session,
        from: u64,
        to: u64,
    ) -> (Directory, quil_store::RocksDb, Vec<FrameHeader>) {
        let (directory, db) = opened();
        let clock = quil_store::RocksClockStore::new(db.inner());
        let chain = uncertified_chain(session, from, to, [[0; 32]; 4]);
        for header in &chain {
            store(&clock, header);
        }
        (directory, db, chain)
    }

    /// A peer source serving `frames` by number, counting requests.
    fn serving(frames: &[FrameHeader], calls: Arc<AtomicUsize>) -> DeliveryFrameSource {
        let frames: BTreeMap<u64, FrameHeader> =
            frames.iter().map(|h| (h.frame_number, h.clone())).collect();
        Arc::new(move |_, number| {
            calls.fetch_add(1, Ordering::SeqCst);
            let frame = frames.get(&number).map(header_only);
            Box::pin(async move { frame })
        })
    }

    fn read<'a>(
        session: &'a Session,
        clock: &'a quil_store::RocksClockStore,
        validator: &'a BlsAppFrameValidator,
        committed: CommittedDigest<'a>,
    ) -> Headers<'a> {
        Headers::new(
            &session.filter,
            Some(session.generation),
            clock,
            validator,
            None,
            committed,
        )
    }

    // Simplex finalizes a view's ancestors with it, so they carry no
    // certificate of their own. Recovery refused each ("missing BLS
    // signature"), and a member that joined a shard through an archive
    // never started consensus (2026-10-20: frame 3051 of g15 on
    // ...000807, 7 h).
    #[tokio::test]
    async fn frames_without_a_certificate_are_recovered_below_the_frame_global_committed() {
        let directory = Directory::new();
        let session = session();
        let (db, _store, manager) = open(&directory.0);
        let clock = quil_store::RocksClockStore::new(db.inner());
        let chain = uncertified_chain(&session, 78, 95, [[0; 32]; 4]);
        for header in &chain {
            store(&clock, header);
        }
        let top = digest(chain.last().unwrap());
        let committed = move |n: u64| -> Result<Option<[u8; 32]>> { Ok((n == 95).then_some(top)) };
        let validator = validator();
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(95, &cursor_key, &tip(&session, 95))
            .unwrap();
        let mut batches = 0;
        while !recover_with_headers(
            &session,
            manager.clone(),
            &read(&session, &clock, &validator, &committed),
            95,
        )
        .await
        .unwrap()
        {
            batches += 1;
            assert!(batches < 20, "recovery stalls");
        }
        let complete = manager
            .crdt()
            .capture_committed_shard(&session.filter)
            .unwrap();
        for n in 78..=95 {
            for (key, value) in tip(&session, n).into_iter().take(3) {
                assert_eq!(
                    complete.records.read_record(&key).unwrap(),
                    Some(value),
                    "frame {n}"
                );
            }
        }
    }

    #[tokio::test]
    async fn frames_below_a_certified_frame_are_authenticated_by_its_certificate() {
        let session = session();
        let signer = quil_crypto::FalconSigner::generate();
        let mut chain = uncertified_chain(&session, 90, 96, [[0; 32]; 4]);
        certify(&mut chain[6], &signer);
        let (_directory, db) = opened();
        let clock = quil_store::RocksClockStore::new(db.inner());
        for header in &chain {
            store(&clock, header);
        }
        let committed = |_: u64| -> Result<Option<[u8; 32]>> { Ok(None) };
        let validator = validator_trusting(&signer);
        let headers = read(&session, &clock, &validator, &committed);
        assert_eq!(headers.get(93).await.unwrap(), chain[3]);
        assert_eq!(headers.get(96).await.unwrap(), chain[6]);
        let stranger = validator_trusting(&quil_crypto::FalconSigner::generate());
        assert!(
            read(&session, &clock, &stranger, &committed)
                .get(93)
                .await
                .is_err(),
            "a certificate of another committee authenticates nothing"
        );
    }

    #[tokio::test]
    async fn a_run_through_a_frame_with_an_invalid_certificate_is_refused() {
        let session = session();
        let signer = quil_crypto::FalconSigner::generate();
        let mut chain = uncertified_chain(&session, 90, 96, [[0; 32]; 4]);
        certify(&mut chain[5], &quil_crypto::FalconSigner::generate());
        let (_directory, db) = opened();
        let clock = quil_store::RocksClockStore::new(db.inner());
        for header in &chain {
            store(&clock, header);
        }
        let top = digest(&chain[6]);
        let committed = move |n: u64| -> Result<Option<[u8; 32]>> { Ok((n == 96).then_some(top)) };
        let validator = validator_trusting(&signer);
        let error = read(&session, &clock, &validator, &committed)
            .get(94)
            .await
            .unwrap_err();
        assert!(matches!(error, QuilError::InvalidSignature(_)), "{error}");
    }

    #[tokio::test]
    async fn a_frame_its_descendant_does_not_name_is_refused() {
        let session = session();
        let (_directory, db, chain) = stored(&session, 90, 95);
        let clock = quil_store::RocksClockStore::new(db.inner());
        // A valid frame 94 of other contents, which frame 95 does not name.
        let other = uncertified_chain(&session, 90, 94, [[5; 32]; 4]);
        store(&clock, &other[4]);
        let top = digest(&chain[5]);
        let committed = move |n: u64| -> Result<Option<[u8; 32]>> { Ok((n == 95).then_some(top)) };
        let validator = validator();
        let headers = read(&session, &clock, &validator, &committed);
        assert_eq!(headers.get(95).await.unwrap(), chain[5]);
        let error = headers.get(94).await.unwrap_err();
        let text = error.to_string();
        assert!(
            matches!(error, QuilError::ExecutionUnavailable(_))
                && text.contains("historical frame 94 of generation 2 ")
                && text.contains(&hex::encode(&session.filter))
                && text.contains("frame 95 does not name frame 94 as its parent"),
            "{text}"
        );
        assert!(
            headers.get(93).await.is_err(),
            "nothing below the other frame is authenticated"
        );
    }

    // The store can hold a frame of another chain at a height (a member
    // past a fence); a peer serves the canonical one.
    #[tokio::test]
    async fn a_local_frame_that_breaks_the_run_is_read_again_from_a_peer() {
        let session = session();
        let validator = validator();
        for wrong in [95u64, 94] {
            let (_directory, db, chain) = stored(&session, 90, 96);
            let clock = quil_store::RocksClockStore::new(db.inner());
            let other = uncertified_chain(&session, 90, wrong, [[5; 32]; 4]);
            store(&clock, other.last().unwrap());
            let committed_frame = wrong + 1;
            let top = digest(&chain[(committed_frame - 90) as usize]);
            let committed = move |n: u64| -> Result<Option<[u8; 32]>> {
                Ok((n == committed_frame).then_some(top))
            };
            let source = serving(&chain, Arc::new(AtomicUsize::new(0)));
            let headers = Headers::new(
                &session.filter,
                Some(session.generation),
                &clock,
                &validator,
                Some(&source),
                &committed,
            );
            assert_eq!(
                headers.get(committed_frame).await.unwrap(),
                chain[(committed_frame - 90) as usize]
            );
            assert_eq!(
                headers.get(94).await.unwrap(),
                chain[4],
                "the local frame {wrong} is another chain's"
            );
        }
    }

    #[tokio::test]
    async fn a_frame_without_a_certificate_needs_globals_digest_or_a_certified_descendant() {
        let session = session();
        let (_directory, db, chain) = stored(&session, 90, 95);
        let clock = quil_store::RocksClockStore::new(db.inner());
        let validator = validator();
        for answer in [None, Some([1; 32])] {
            let committed = move |_: u64| -> Result<Option<[u8; 32]>> { Ok(answer) };
            let error = read(&session, &clock, &validator, &committed)
                .get(95)
                .await
                .unwrap_err();
            let text = error.to_string();
            assert!(
                matches!(error, QuilError::ExecutionUnavailable(_))
                    && text.contains("historical frame 95 of generation 2 ")
                    && text.contains(&hex::encode(&session.filter))
                    && text.contains("descendant frame 96 is unavailable"),
                "{text}"
            );
        }
        let top = digest(&chain[5]);
        let committed = move |n: u64| -> Result<Option<[u8; 32]>> { Ok((n == 95).then_some(top)) };
        assert_eq!(
            read(&session, &clock, &validator, &committed)
                .get(95)
                .await
                .unwrap(),
            chain[5]
        );
    }

    #[tokio::test]
    async fn the_search_for_a_certified_descendant_is_bounded() {
        let session = session();
        let (_directory, db, chain) = stored(&session, 95, 128);
        let clock = quil_store::RocksClockStore::new(db.inner());
        let validator = validator();
        let far = digest(&chain[33]);
        let committed = move |n: u64| -> Result<Option<[u8; 32]>> { Ok((n == 128).then_some(far)) };
        let error = read(&session, &clock, &validator, &committed)
            .get(95)
            .await
            .unwrap_err();
        assert!(
            matches!(error, QuilError::ExecutionUnavailable(_))
                && error
                    .to_string()
                    .contains("frames 96-127 above it carry none")
                && error.to_string().contains("none within 32 frames"),
            "{error}"
        );
        let near = digest(&chain[32]);
        let committed =
            move |n: u64| -> Result<Option<[u8; 32]>> { Ok((n == 127).then_some(near)) };
        assert_eq!(
            read(&session, &clock, &validator, &committed)
                .get(95)
                .await
                .unwrap(),
            chain[0]
        );
    }

    #[tokio::test]
    async fn a_batch_asks_peers_for_a_bounded_number_of_frames() {
        let session = session();
        let (_directory, db) = opened();
        let clock = quil_store::RocksClockStore::new(db.inner());
        let validator = validator();
        let chain = uncertified_chain(&session, 90, 200, [[0; 32]; 4]);
        let calls = Arc::new(AtomicUsize::new(0));
        let source = serving(&chain, calls.clone());
        let committed = |_: u64| -> Result<Option<[u8; 32]>> { Ok(None) };
        let headers = Headers::new(
            &session.filter,
            Some(session.generation),
            &clock,
            &validator,
            Some(&source),
            &committed,
        );
        let first = headers.get(100).await.unwrap_err();
        assert!(
            first.to_string().contains("none within 32 frames"),
            "{first}"
        );
        let second = headers.get(99).await.unwrap_err();
        assert!(
            second
                .to_string()
                .contains("already asked peers for 64 frames"),
            "{second}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 64);
    }

    #[tokio::test]
    async fn a_slow_peer_stops_the_batch_at_its_deadline() {
        let session = session();
        let (_directory, db) = opened();
        let clock = quil_store::RocksClockStore::new(db.inner());
        let chain = uncertified_chain(&session, 90, 96, [[0; 32]; 4]);
        for header in chain.iter().filter(|h| h.frame_number != 95) {
            store(&clock, header);
        }
        let top = digest(&chain[6]);
        let committed = move |n: u64| -> Result<Option<[u8; 32]>> { Ok((n == 96).then_some(top)) };
        let silent: DeliveryFrameSource =
            Arc::new(|_, _| Box::pin(std::future::pending::<Option<AppShardFrame>>()));
        let validator = validator();
        let mut headers = Headers::new(
            &session.filter,
            Some(session.generation),
            &clock,
            &validator,
            Some(&silent),
            &committed,
        );
        headers.deadline = Instant::now() + Duration::from_millis(300);
        let started = Instant::now();
        let error = headers.get(94).await.unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the deadline bounds the read"
        );
        assert!(
            matches!(error, QuilError::ExecutionUnavailable(_))
                && error
                    .to_string()
                    .contains("descendant frame 95 is unavailable"),
            "{error}"
        );
        assert!(
            headers
                .get(93)
                .await
                .unwrap_err()
                .to_string()
                .contains("budget"),
            "a spent budget reads nothing"
        );
    }

    #[tokio::test]
    async fn the_frame_that_authenticates_a_run_survives_a_full_cache() {
        let session = session();
        let (_directory, db, chain) = stored(&session, 1, 130);
        let clock = quil_store::RocksClockStore::new(db.inner());
        let digests: BTreeMap<u64, [u8; 32]> = chain
            .iter()
            .filter(|h| (10..=81).contains(&h.frame_number) || h.frame_number == 120)
            .map(|h| (h.frame_number, digest(h)))
            .collect();
        let committed = move |n: u64| -> Result<Option<[u8; 32]>> { Ok(digests.get(&n).copied()) };
        let validator = validator();
        let headers = read(&session, &clock, &validator, &committed);
        for n in 10..=81 {
            headers.get(n).await.unwrap();
        }
        assert_eq!(headers.get(100).await.unwrap(), chain[99]);
    }

    // A heartbeat lookup reads a frame well below the last one read.
    #[tokio::test]
    async fn a_header_authenticated_earlier_in_the_batch_authenticates_frames_below_it() {
        let session = session();
        let (_directory, db, chain) = stored(&session, 64, 96);
        let clock = quil_store::RocksClockStore::new(db.inner());
        let validator = validator();
        let top = digest(&chain[32]);
        let asked = std::sync::atomic::AtomicBool::new(false);
        let committed = |n: u64| -> Result<Option<[u8; 32]>> {
            Ok((n == 96 && !asked.swap(true, Ordering::SeqCst)).then_some(top))
        };
        let headers = read(&session, &clock, &validator, &committed);
        assert_eq!(headers.get(96).await.unwrap(), chain[32]);
        assert_eq!(headers.get(70).await.unwrap(), chain[6]);
        assert_eq!(headers.get(71).await.unwrap(), chain[7]);
        assert!(
            read(&session, &clock, &validator, &committed)
                .get(70)
                .await
                .is_err(),
            "without the earlier header nothing authenticates it"
        );
    }

    /// A member that joined at the tip: the tip's nonempty report and the
    /// certified fee and settlement records, none for the carry window.
    fn joined_at_tip(
        manager: &Arc<ExecutionEngineManager>,
        session: &Session,
        cursor: u64,
        tip_report: &[u8],
    ) {
        let filter = &session.filter;
        let digest = accumulator_header::report_digest(tip_report);
        let accumulator = encoding::clock_shard_frame_accumulator_key(filter, cursor);
        let mut records: Vec<_> = tip(session, cursor)
            .into_iter()
            .filter(|(key, _)| *key != accumulator)
            .collect();
        records.push((accumulator, digest.clone()));
        records.push((
            encoding::clock_shard_accumulator_report_key(filter, &digest),
            tip_report.to_vec(),
        ));
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(
                cursor,
                &encoding::consensus_materialized_cursor_key(filter),
                &records,
            )
            .unwrap();
    }

    // Header 100 builds on the state the tip frame left unchanged, so frame
    // 99 holds the tip's report; header 100 omitted that nonempty report, so
    // frames 91..=98 hold it too. Before, the member nullified header 101.
    #[tokio::test]
    async fn the_carry_window_below_a_joined_tip_is_recovered_from_certified_headers() {
        quil_execution::token_intrinsic::global_commit::set_relay_activation_frame_for_thread(
            Some(0),
        );
        let directory = Directory::new();
        let session = session();
        let filter = session.filter.clone();
        let (db, _, manager) = open(&directory.0);
        let clock = quil_store::RocksClockStore::new(db.inner());
        let tip_report = report(1);
        let digest = accumulator_header::report_digest(&tip_report);
        joined_at_tip(&manager, &session, 100, &tip_report);
        let field = || {
            crate::app_engine::accumulator_field(
                &crate::app_engine::FrameOutflows::default(),
                &clock,
                &filter,
                101,
            )
        };
        assert_eq!(
            field(),
            None,
            "without the window the next field is unknown"
        );
        let headers = VerifiedFixture {
            frames: (90..=100)
                .map(|n| {
                    (
                        n,
                        header(
                            &session,
                            n,
                            if n == 100 {
                                [[0; 32]; 4]
                            } else {
                                [[n as u8; 32]; 4]
                            },
                        ),
                    )
                })
                .collect(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        assert_eq!(
            recover_carry_window_with_headers(&filter, manager.clone(), &clock, &headers, 100)
                .await
                .unwrap(),
            (8, None)
        );
        assert_eq!(
            *headers.reads.lock().unwrap(),
            vec![100],
            "the omission at header 100 decides the rest"
        );
        for n in 92..=99 {
            assert_eq!(
                clock.get_shard_frame_accumulator(&filter, n).unwrap(),
                Some(digest.clone()),
                "frame {n}"
            );
        }
        assert!(
            clock
                .get_shard_frame_accumulator(&filter, 91)
                .unwrap()
                .is_none(),
            "nothing below the window"
        );
        assert_eq!(
            field(),
            Some(vec![]),
            "an unchanged report off the heartbeat is not carried"
        );
        assert_eq!(
            recover_carry_window_with_headers(&filter, manager.clone(), &clock, &headers, 100)
                .await
                .unwrap(),
            (0, None)
        );
        assert_eq!(
            headers.reads.lock().unwrap().len(),
            1,
            "a complete window reads no header"
        );
    }

    #[tokio::test]
    async fn an_undecided_or_contradicted_carry_window_stays_unknown() {
        quil_execution::token_intrinsic::global_commit::set_relay_activation_frame_for_thread(
            Some(0),
        );
        let directory = Directory::new();
        let session = session();
        let filter = session.filter.clone();
        let (db, _, manager) = open(&directory.0);
        let clock = quil_store::RocksClockStore::new(db.inner());
        joined_at_tip(&manager, &session, 100, &report(1));
        let field = || {
            crate::app_engine::accumulator_field(
                &crate::app_engine::FrameOutflows::default(),
                &clock,
                &filter,
                101,
            )
        };
        // The tip frame changed the state: frame 99's report is not known.
        let changed = VerifiedFixture {
            frames: (90..=100)
                .map(|n| (n, header(&session, n, [[n as u8; 32]; 4])))
                .collect(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        assert_eq!(
            recover_carry_window_with_headers(&filter, manager.clone(), &clock, &changed, 100)
                .await
                .unwrap(),
            (0, Some(99))
        );
        assert_eq!(field(), None);
        // A record the certified window contradicts is kept, and nothing is
        // written over the batch.
        let other = report(2);
        let other_digest = accumulator_header::report_digest(&other);
        manager
            .crdt()
            .checkpoint_shard_records(
                &filter,
                &[[0; 32]; 4],
                &encoding::consensus_materialized_cursor_key(&filter),
                100,
                &[
                    (
                        encoding::clock_shard_frame_accumulator_key(&filter, 95),
                        other_digest.clone(),
                    ),
                    (
                        encoding::clock_shard_accumulator_report_key(&filter, &other_digest),
                        other,
                    ),
                ],
            )
            .unwrap();
        let unchanged = VerifiedFixture {
            frames: (90..=100)
                .map(|n| {
                    (
                        n,
                        header(
                            &session,
                            n,
                            if n == 100 {
                                [[0; 32]; 4]
                            } else {
                                [[n as u8; 32]; 4]
                            },
                        ),
                    )
                })
                .collect(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        assert!(recover_carry_window_with_headers(
            &filter,
            manager.clone(),
            &clock,
            &unchanged,
            100
        )
        .await
        .is_err());
        assert_eq!(
            clock.get_shard_frame_accumulator(&filter, 95).unwrap(),
            Some(other_digest)
        );
        assert!(clock
            .get_shard_frame_accumulator(&filter, 99)
            .unwrap()
            .is_none());
        assert_eq!(field(), None);
    }

    /// A walk logs its first batch, then at most one batch per interval,
    /// and its last; it is forgotten once finished.
    #[test]
    fn a_walk_logs_its_first_batch_every_interval_and_its_end() {
        let filter = [0x5a; 35];
        let start = Instant::now();
        assert!(walk_batch(&filter, (10, 95, 100), start));
        assert!(!walk_batch(
            &filter,
            (10, 87, 100),
            start + Duration::from_secs(10)
        ));
        assert_eq!(walk_progress(&filter), Some((10, 87, 100)));
        assert!(walk_batch(
            &filter,
            (10, 40, 100),
            start + WALK_PROGRESS_REPEAT
        ));
        assert!(walk_batch(
            &filter,
            (100, 100, 100),
            start + WALK_PROGRESS_REPEAT + Duration::from_secs(10)
        ));
        assert_eq!(walk_progress(&filter), None);
    }
}
