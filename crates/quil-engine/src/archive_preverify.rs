//! Archive proof verification outside the ingest lock.
//!
//! An archive materializes every application frame a GLOBAL frame carries
//! while it holds its [`ArchiveAppShardIngest`], and materialization verifies
//! the frames' confidential token proofs first, in a worker child, at about
//! two minutes per batch shield. Gossip ingest, its retry pass and the gap
//! fetch's admission wait for that lock meanwhile, and the GLOBAL frame
//! executes only once every proof of its backlog has verified, one frame
//! after another.
//!
//! Verdicts are a pure function of the operation bytes and the network
//! policy, cached process-wide, so when they are computed changes nothing
//! that execution decides. This module computes them before the lock is
//! taken:
//!
//! * [`ProofPrewarm`]: frames are queued as they are admitted and their proofs
//!   verified on a background thread, so a GLOBAL frame that later carries
//!   their headers finds the verdicts cached;
//! * [`preverify_through`]: before the GLOBAL hook takes the ingest, the
//!   frames it is about to materialize are verified with the lock released;
//! * [`ProofSettlement`]: a GLOBAL proposal holds a shard's header back while
//!   the frames it would sequence carry expensive operations this archive has
//!   not verified yet, so GLOBAL does not wait for them.
//!
//! Every bound only moves work back to where it ran before: a verdict not
//! computed ahead is computed by the locked materialization, and a header
//! held past [`SETTLE_HOLD_LIMIT`] rides, GLOBAL waiting for its proofs.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use quil_execution::manager::{PreverifyCounts, PreverifyPacing};
use quil_types::proto::global::MessageBundle;
use tracing::{info, warn};

use crate::archive_ingest::ArchiveAppShardIngest;

/// Verifies `(application, canonical bundle)` pairs, filling the verdict cache
/// (`ExecutionEngineManager::preverify_bundles_paced` in a node).
pub type ProofVerifier =
    dyn Fn(&[(Vec<u8>, Vec<u8>)], &PreverifyPacing<'_>) -> PreverifyCounts + Send + Sync;

/// How often the background queues log what they did.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(600);

/// GLOBAL hook passes running: the background pre-verification starts no new
/// proof while one runs, so the worker slots serve the frames GLOBAL waits on.
static SEQUENCED_PASSES: AtomicUsize = AtomicUsize::new(0);

/// A GLOBAL frame's materialization on this archive, from its proof
/// pre-verification through the locked pass; [`ProofPrewarm`] yields to it.
pub struct SequencedPass(());

impl SequencedPass {
    pub fn begin() -> Self {
        SEQUENCED_PASSES.fetch_add(1, Ordering::AcqRel);
        Self(())
    }
}

impl Drop for SequencedPass {
    fn drop(&mut self) {
        SEQUENCED_PASSES.fetch_sub(1, Ordering::AcqRel);
    }
}

fn sequenced_pass_running() -> bool {
    SEQUENCED_PASSES.load(Ordering::Acquire) > 0
}

/// `(application, canonical bytes)` of a frame's bundles, as materialization
/// hands them to the verifier. A bundle that does not encode is skipped here
/// and by materialization alike.
fn canonical_pairs(address: &[u8], requests: &[MessageBundle]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let application = address[..address.len().min(32)].to_vec();
    requests
        .iter()
        .filter_map(|bundle| crate::consensus_wire::app_bundle_to_canonical_bytes(bundle).ok())
        .map(|bytes| (application.clone(), bytes))
        .collect()
}

fn encoded_len(requests: &[MessageBundle]) -> usize {
    requests.iter().map(prost::Message::encoded_len).sum()
}

// ---------------------------------------------------------------------------
// Background pre-verification of admitted frames
// ---------------------------------------------------------------------------

/// Frames queued for background pre-verification. Past either bound the
/// oldest is dropped (counted): its proofs are then verified when GLOBAL
/// materializes it, as before.
pub const PREWARM_MAX_FRAMES: usize = 1024;
pub const PREWARM_MAX_BYTES: usize = 128 << 20;
/// How long the background thread waits after proofs found no worker slot.
const PREWARM_BUSY_PAUSE: Duration = Duration::from_secs(1);
/// Most frames verified at once: the most verifier slots an archive sizes
/// itself to.
const PREWARM_MAX_LANES: usize = 8;

/// What verifying a frame's confidential operations costs, as admission sees
/// it ([`ProofPrewarm::offer`]): its operations, and of them those not known
/// to verify within the per-frame verification budget on this archive (a
/// batch shield, or any size class not measured here yet).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperationCost {
    pub operations: usize,
    pub expensive: usize,
}

/// Classifies `(application, canonical bundle)` pairs ([`OperationCost`]).
pub type OperationClassifier = dyn Fn(&[(Vec<u8>, Vec<u8>)]) -> OperationCost + Send + Sync;

/// The execution manager's [`OperationCost`] of `pairs`.
pub fn classify_operations(pairs: &[(Vec<u8>, Vec<u8>)]) -> OperationCost {
    use quil_execution::ExecutionEngineManager as Manager;
    let sizes = Manager::confidential_operation_sizes(pairs);
    let budget = Manager::frame_verification_budget_secs();
    OperationCost {
        operations: sizes.len(),
        expensive: sizes
            .iter()
            .filter(|&&bytes| !Manager::verification_known_to_fit(bytes, budget))
            .count(),
    }
}

/// Verifies the confidential proofs of admitted frames in the background,
/// oldest first, before a GLOBAL frame needs them: one frame per verifier
/// slot at once ([`Self::with_lanes`]), so frames carrying one operation each
/// keep every slot busy. It uses the worker's slots like any verification,
/// starts no new proof while a GLOBAL hook pass runs ([`SequencedPass`]), and
/// never takes the ingest lock. Frames without confidential operations are
/// not queued. It records when frames carrying expensive operations were
/// admitted and verified, which GLOBAL proposals read ([`ProofSettlement`]).
pub struct ProofPrewarm {
    shared: Arc<PrewarmShared>,
}

/// Verifier slots, read when the first frame is offered.
pub type PrewarmLanes = dyn Fn() -> usize + Send + Sync;

struct PrewarmShared {
    state: Mutex<PrewarmState>,
    wake: Condvar,
    verify: Arc<ProofVerifier>,
    classify: Arc<OperationClassifier>,
    lanes: Arc<PrewarmLanes>,
    started: std::sync::atomic::AtomicBool,
    max_frames: usize,
    max_bytes: usize,
}

#[derive(Default)]
struct PrewarmState {
    queue: VecDeque<PrewarmItem>,
    bytes: usize,
    started: bool,
    shutdown: bool,
    /// Since the last summary.
    window: PrewarmStats,
    /// Since start.
    total: PrewarmStats,
    summarized: Option<Instant>,
    settlement: SettlementLedger,
}

struct PrewarmItem {
    address: Vec<u8>,
    frame: u64,
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrewarmStats {
    pub queued: usize,
    /// Frames queued again because proofs found no worker slot.
    pub requeued: usize,
    pub dropped: usize,
    pub frames: usize,
    pub counts: PreverifyCounts,
}

impl PrewarmStats {
    fn add(&mut self, other: PrewarmStats) {
        self.queued += other.queued;
        self.requeued += other.requeued;
        self.dropped += other.dropped;
        self.frames += other.frames;
        self.counts.add(other.counts);
    }
}

impl ProofPrewarm {
    pub fn new(verify: Arc<ProofVerifier>) -> Self {
        Self::with_bounds(verify, PREWARM_MAX_FRAMES, PREWARM_MAX_BYTES)
    }

    pub fn with_bounds(verify: Arc<ProofVerifier>, max_frames: usize, max_bytes: usize) -> Self {
        Self {
            shared: Arc::new(PrewarmShared {
                state: Mutex::new(PrewarmState::default()),
                wake: Condvar::new(),
                verify,
                classify: Arc::new(classify_operations),
                lanes: Arc::new(|| 1),
                started: Default::default(),
                max_frames: max_frames.max(1),
                max_bytes,
            }),
        }
    }

    /// Verify up to `lanes()` frames at once (the worker's verifier slots, at
    /// most [`PREWARM_MAX_LANES`]), read when the first frame is offered.
    /// One frame at a time verified a frame's one operation on one slot of
    /// two: alone it took 65 s, two at once 40 s each (2026-11-01).
    pub fn with_lanes(self, lanes: Arc<PrewarmLanes>) -> Self {
        self.configure(|shared| shared.lanes = lanes)
    }

    /// Classify admitted frames with `classify` instead of the execution
    /// manager ([`classify_operations`]).
    pub fn with_classifier(self, classify: Arc<OperationClassifier>) -> Self {
        self.configure(|shared| shared.classify = classify)
    }

    /// Before the first offer, nothing else holds the shared state.
    fn configure(mut self, change: impl FnOnce(&mut PrewarmShared)) -> Self {
        if let Some(shared) = Arc::get_mut(&mut self.shared) {
            change(shared);
        }
        self
    }

    /// Queue the bundles of frame `frame` of `address`, admitted above the
    /// cursor, without waiting. The lanes start with the first frame. A frame
    /// carrying expensive operations is recorded until GLOBAL executes it
    /// ([`ProofSettlement`]), also when the queue drops it: GLOBAL then
    /// verifies it when it materializes it, and the hold limit applies.
    pub fn offer(&self, address: &[u8], frame: u64, requests: &[MessageBundle]) {
        if requests.is_empty() {
            return;
        }
        let shared = &self.shared;
        let pairs = canonical_pairs(address, requests);
        let cost = (*shared.classify)(&pairs);
        if cost.operations == 0 {
            return;
        }
        let lanes = (!shared.started.load(Ordering::Acquire)).then(|| (*shared.lanes)());
        let bytes = encoded_len(requests);
        let mut state = shared.lock();
        if state.shutdown {
            return;
        }
        if cost.expensive > 0 {
            state
                .settlement
                .admit(address, frame, cost.expensive, Instant::now());
        }
        state.queue.push_back(PrewarmItem {
            address: address.to_vec(),
            frame,
            pairs,
            bytes,
        });
        state.bytes += bytes;
        state.window.queued += 1;
        shared.trim(&mut state);
        if !state.started {
            state.started = true;
            shared.started.store(true, Ordering::Release);
            let lanes = lanes.unwrap_or(1).clamp(1, PREWARM_MAX_LANES);
            for lane in 0..lanes {
                let thread_shared = shared.clone();
                let spawned = std::thread::Builder::new()
                    .name(format!("archive-proof-prewarm-{lane}"))
                    .spawn(move || thread_shared.run());
                if let Err(error) = spawned {
                    if lane == 0 {
                        state.started = false;
                        shared.started.store(false, Ordering::Release);
                    }
                    warn!(%error, lane, lanes, "archive proof prewarm lane did not start; proofs verify when GLOBAL materializes their frames");
                    break;
                }
            }
        }
        drop(state);
        shared.wake.notify_one();
    }

    /// Queued frames and what was done since start (tests and summaries).
    pub fn stats(&self) -> (usize, PrewarmStats) {
        let state = self.shared.lock();
        let mut total = state.total;
        total.add(state.window);
        (state.queue.len(), total)
    }

    /// What GLOBAL proposals ask of the frames this records
    /// ([`ProofSettlement`]).
    pub fn settlement(&self) -> ProofSettlement {
        ProofSettlement {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for ProofPrewarm {
    fn drop(&mut self) {
        self.shared.lock().shutdown = true;
        self.shared.wake.notify_all();
    }
}

impl PrewarmShared {
    fn lock(&self) -> std::sync::MutexGuard<'_, PrewarmState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Drop the oldest frames past either bound, counted.
    fn trim(&self, state: &mut PrewarmState) {
        while state.queue.len() > self.max_frames || state.bytes > self.max_bytes {
            let Some(dropped) = state.queue.pop_front() else {
                break;
            };
            state.bytes -= dropped.bytes;
            state.window.dropped += 1;
        }
    }

    /// One lane: verifies the oldest queued frame, again and again.
    fn run(&self) {
        let pause: &(dyn Fn() -> bool + Sync) = &sequenced_pass_running;
        loop {
            let item = {
                let mut state = self.lock();
                loop {
                    if state.shutdown {
                        return;
                    }
                    Self::summarize(&mut state, self.max_frames);
                    if let Some(item) = state.queue.pop_front() {
                        state.bytes -= item.bytes;
                        break item;
                    }
                    state = match self.wake.wait_timeout(state, SUMMARY_INTERVAL) {
                        Ok((state, _)) => state,
                        Err(poisoned) => poisoned.into_inner().0,
                    };
                }
            };
            let counts = (*self.verify)(
                &item.pairs,
                &PreverifyPacing {
                    parallelism: None,
                    done: None,
                    pause: Some(pause),
                },
            );
            let mut state = self.lock();
            state.window.frames += 1;
            state.window.counts.add(counts);
            // Proofs that found no worker slot go to the back of the queue:
            // the next attempt finds the verdicts others computed meanwhile
            // cached, and the frame bound still applies.
            if counts.busy > 0 && !state.shutdown {
                state.window.requeued += 1;
                state.bytes += item.bytes;
                state.queue.push_back(item);
                self.trim(&mut state);
                drop(state);
                std::thread::sleep(PREWARM_BUSY_PAUSE);
                continue;
            }
            // Verified here, or failed in the worker, which GLOBAL then
            // retries when it materializes the frame.
            state
                .settlement
                .settle(&item.address, item.frame, Instant::now());
        }
    }

    /// One line per [`SUMMARY_INTERVAL`] while frames are queued or verified.
    fn summarize(state: &mut PrewarmState, max_frames: usize) {
        let now = Instant::now();
        let since = *state.summarized.get_or_insert(now);
        if now.duration_since(since) < SUMMARY_INTERVAL {
            return;
        }
        state.summarized = Some(now);
        state.settlement.summarize(now);
        let window = std::mem::take(&mut state.window);
        state.total.add(window);
        if window == PrewarmStats::default() && state.queue.is_empty() {
            return;
        }
        info!(
            scope = "this archive",
            queued = window.queued,
            frames = window.frames,
            operations = window.counts.operations,
            verified = window.counts.verified,
            cached = window.counts.cached,
            busy = window.counts.busy,
            failed = window.counts.unavailable,
            requeued = window.requeued,
            dropped = window.dropped,
            pending = state.queue.len(),
            max_frames,
            interval_secs = SUMMARY_INTERVAL.as_secs(),
            "archive proof prewarm summary: confidential proofs of admitted application frames verified ahead of GLOBAL; \
             dropped frames verify when GLOBAL materializes them"
        );
    }
}

// ---------------------------------------------------------------------------
// Settlement: GLOBAL sequences a shard once its expensive proofs verified
// ---------------------------------------------------------------------------

/// How much longer than this archive took, from admission, a frame carrying
/// expensive operations is still held once its proofs verified here. The
/// other archives verify it from their own admission, at their own pace, and
/// GLOBAL waits for the third of four: on 2026-10-30 archives ran two and four
/// verifier slots, and one operation verified for 40-69 s.
const SETTLE_MARGIN: u32 = 2;
/// A shard whose newer frames keep carrying expensive operations is never
/// all verified. Once its oldest held such frame verified here and waited
/// this many times as long as that took, at least [`SETTLE_LAG_FLOOR`], its
/// header rides anyway: archives then wait only for the newer operations,
/// which they are verifying already.
const SETTLE_LAG_FACTOR: u32 = 3;
const SETTLE_LAG_FLOOR: Duration = Duration::from_secs(60);
/// The longest a shard's header is held, from the admission of its oldest
/// frame above the cursor carrying expensive operations: past it the header
/// rides whatever is verified, and GLOBAL waits for the rest, as it did
/// without the hold. Only verification running behind arrivals reaches it.
/// Once that frame verified here, the limit is three times as long as it
/// took, within [`SETTLE_HOLD_LIMIT_MAX`], so a slow archive's margin fits.
pub const SETTLE_HOLD_LIMIT: Duration = Duration::from_secs(600);
/// No hold lasts longer. At about 10 s per application frame a shard held
/// this long is about 120 frames ahead, within the frames an archive
/// buffers per shard (128).
pub const SETTLE_HOLD_LIMIT_MAX: Duration = Duration::from_secs(1200);
/// Frames the ledger records at most; further ones are never held.
const SETTLE_MAX_FRAMES: usize = 4096;

/// What a GLOBAL proposal does with a shard's header ([`ProofSettlement`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// No frame it makes archives materialize carries expensive operations.
    Clear,
    /// Every such frame verified here, and the margin for slower archives
    /// passed: it rides.
    Settled,
    /// Held back: archives are still verifying those operations.
    Settling,
    /// Newer frames keep carrying such operations; the oldest verified here
    /// and waited its lag bound: it rides.
    LagBound,
    /// The oldest such frame waited its hold limit ([`SETTLE_HOLD_LIMIT`]):
    /// it rides, and GLOBAL waits for what is not verified yet.
    HoldLimit,
}

impl Settlement {
    /// Whether the header is held back.
    pub fn holds(self) -> bool {
        self == Settlement::Settling
    }
}

/// Whether a GLOBAL proposal holds a shard's header back while archives
/// verify the expensive confidential operations of the frames it would make
/// them materialize, so that GLOBAL never waits for them: read from what
/// [`ProofPrewarm`] recorded at admission and verification, under a lock held
/// only to read it. Every hold ends ([`SETTLE_HOLD_LIMIT_MAX`]).
#[derive(Clone)]
pub struct ProofSettlement {
    shared: Arc<PrewarmShared>,
}

impl ProofSettlement {
    /// The header of `address` through `through`, above its cursor `cursor`
    /// (the last frame GLOBAL executed).
    pub fn check(&self, address: &[u8], cursor: u64, through: u64) -> Settlement {
        self.shared
            .lock()
            .settlement
            .decide(address, cursor, through, Instant::now())
    }
}

#[derive(Default)]
struct SettlementLedger {
    shards: std::collections::HashMap<Vec<u8>, ShardSettlement>,
    frames: usize,
    window: SettlementStats,
    /// Since when proposals carry headers past the hold limit, and when that
    /// was last warned.
    limit: Option<(Instant, Instant, usize)>,
}

/// One shard's frames above its cursor that carry expensive operations.
struct ShardSettlement {
    /// When the oldest of them was admitted. Only GLOBAL executing the shard
    /// past frames (a higher cursor) moves it, so no hold outlasts
    /// [`SETTLE_HOLD_LIMIT_MAX`] from it.
    since: Instant,
    frames: std::collections::BTreeMap<u64, PendingProofs>,
}

#[derive(Clone, Copy, Debug)]
struct PendingProofs {
    queued: Instant,
    operations: usize,
    /// When this archive verified them.
    settled: Option<Instant>,
}

impl PendingProofs {
    fn took(&self, settled: Instant) -> Duration {
        settled.saturating_duration_since(self.queued)
    }

    fn margin_passed(&self, now: Instant) -> bool {
        self.settled.is_some_and(|settled| {
            now.saturating_duration_since(self.queued) >= self.took(settled) * SETTLE_MARGIN
        })
    }

    /// The hold limit of a shard whose oldest held frame is this one.
    fn hold_limit(&self) -> Duration {
        self.settled.map_or(SETTLE_HOLD_LIMIT, |settled| {
            (self.took(settled) * SETTLE_LAG_FACTOR).clamp(SETTLE_HOLD_LIMIT, SETTLE_HOLD_LIMIT_MAX)
        })
    }

    fn lag_bound(&self) -> Option<Duration> {
        self.settled
            .map(|settled| (self.took(settled) * SETTLE_LAG_FACTOR).max(SETTLE_LAG_FLOOR))
    }
}

/// What the ledger saw in one summary interval.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SettlementStats {
    /// Frames admitted carrying expensive operations, and those not recorded
    /// because the ledger was full (never held).
    admitted: usize,
    untracked: usize,
    /// Proposal checks of a shard with such frames: held, and released by
    /// each rule.
    held: usize,
    settled: usize,
    lag_bound: usize,
    hold_limit: usize,
    /// The longest any held shard had waited.
    longest_hold: Duration,
}

impl ShardSettlement {
    fn decide(&self, through: u64, now: Instant) -> Settlement {
        let mut pending = self.frames.range(..=through).map(|(_, p)| p).peekable();
        let Some(oldest) = pending.peek().copied() else {
            return Settlement::Clear;
        };
        let held = now.saturating_duration_since(self.since);
        let limit = oldest.hold_limit();
        let (mut unsettled, mut margin) = (false, true);
        for proofs in pending {
            unsettled |= proofs.settled.is_none();
            margin &= proofs.margin_passed(now);
        }
        // Every one verified here: the margin, or the limit, ends the hold.
        if !unsettled && (margin || held >= limit) {
            return Settlement::Settled;
        }
        if unsettled
            && oldest
                .lag_bound()
                .is_some_and(|lag| now.saturating_duration_since(oldest.queued) >= lag)
        {
            return Settlement::LagBound;
        }
        if held >= limit {
            return Settlement::HoldLimit;
        }
        Settlement::Settling
    }
}

impl SettlementLedger {
    fn admit(&mut self, address: &[u8], frame: u64, operations: usize, now: Instant) {
        self.window.admitted += 1;
        if self
            .shards
            .get(address)
            .is_some_and(|shard| shard.frames.contains_key(&frame))
        {
            return;
        }
        if self.frames >= SETTLE_MAX_FRAMES {
            self.window.untracked += 1;
            return;
        }
        let shard = self
            .shards
            .entry(address.to_vec())
            .or_insert_with(|| ShardSettlement {
                since: now,
                frames: Default::default(),
            });
        if shard.frames.is_empty() {
            shard.since = now;
        }
        shard.frames.insert(
            frame,
            PendingProofs {
                queued: now,
                operations,
                settled: None,
            },
        );
        self.frames += 1;
    }

    fn settle(&mut self, address: &[u8], frame: u64, now: Instant) {
        if let Some(proofs) = self
            .shards
            .get_mut(address)
            .and_then(|shard| shard.frames.get_mut(&frame))
        {
            if proofs.settled.is_none() {
                proofs.settled = Some(now);
            }
        }
    }

    fn decide(&mut self, address: &[u8], cursor: u64, through: u64, now: Instant) -> Settlement {
        let Some(shard) = self.shards.get_mut(address) else {
            return Settlement::Clear;
        };
        // GLOBAL executed the shard through its cursor: those frames are done.
        let above = shard.frames.split_off(&cursor.saturating_add(1));
        let executed = std::mem::replace(&mut shard.frames, above).len();
        if executed > 0 {
            self.frames -= executed;
            let oldest = shard.frames.values().map(|proofs| proofs.queued).min();
            match oldest {
                Some(oldest) => shard.since = oldest,
                None => {
                    self.shards.remove(address);
                    return Settlement::Clear;
                }
            }
        }
        let decision = shard.decide(through, now);
        let held = now.saturating_duration_since(shard.since);
        let stats = &mut self.window;
        match decision {
            Settlement::Clear => {}
            Settlement::Settled => stats.settled += 1,
            Settlement::Settling => {
                stats.held += 1;
                stats.longest_hold = stats.longest_hold.max(held);
            }
            Settlement::LagBound => stats.lag_bound += 1,
            Settlement::HoldLimit => {
                stats.hold_limit += 1;
                let (unsettled, operations) = shard
                    .frames
                    .range(..=through)
                    .filter(|(_, proofs)| proofs.settled.is_none())
                    .fold((0, 0), |(frames, ops), (_, proofs)| {
                        (frames + 1, ops + proofs.operations)
                    });
                let first = self.limit.is_none();
                let run = self.limit.get_or_insert((now, now, 0));
                run.2 += 1;
                let warn_now = first || now.saturating_duration_since(run.1) >= SUMMARY_INTERVAL;
                if warn_now {
                    run.1 = now;
                    let (since, _, count) = *run;
                    warn!(
                        scope = "this archive",
                        address = %hex::encode(address),
                        cursor,
                        through,
                        held_secs = held.as_secs(),
                        unsettled_frames = unsettled,
                        unsettled_operations = operations,
                        proposals = count,
                        for_secs = now.saturating_duration_since(since).as_secs(),
                        limit_secs = shard
                            .frames
                            .values()
                            .next()
                            .map_or(SETTLE_HOLD_LIMIT, PendingProofs::hold_limit)
                            .as_secs(),
                        reason = "proof verification on this archive runs behind the expensive confidential operations arriving",
                        action = "GLOBAL execution waits for these proofs on archives that have not verified them; check the \
                                  prewarm summary's pending frames and proofWorker.maxConcurrent; a line follows when it ends",
                        "GLOBAL proposal carries a shard header past the proof settlement hold limit"
                    );
                }
            }
        }
        decision
    }

    /// Once per summary interval: forget frames held past twice the hold
    /// limit (they hold nothing any more), close a hold-limit run that saw
    /// no such proposal this interval, and log what the interval did.
    fn summarize(&mut self, now: Instant) {
        let stale = SETTLE_HOLD_LIMIT_MAX * 2;
        let mut forgotten = 0;
        self.shards.retain(|_, shard| {
            let before = shard.frames.len();
            shard
                .frames
                .retain(|_, proofs| now.saturating_duration_since(proofs.queued) < stale);
            forgotten += before - shard.frames.len();
            !shard.frames.is_empty()
        });
        self.frames -= forgotten;
        let window = std::mem::take(&mut self.window);
        if window.hold_limit == 0 {
            if let Some((since, _, count)) = self.limit.take() {
                info!(
                    scope = "this archive",
                    proposals = count,
                    for_secs = now.saturating_duration_since(since).as_secs(),
                    "GLOBAL proposals no longer carry shard headers past the proof settlement hold limit"
                );
            }
        }
        if window == SettlementStats::default() && self.frames == 0 {
            return;
        }
        info!(
            scope = "this archive",
            admitted = window.admitted,
            untracked = window.untracked,
            held = window.held,
            settled = window.settled,
            lag_bound = window.lag_bound,
            hold_limit = window.hold_limit,
            longest_hold_secs = window.longest_hold.as_secs(),
            shards = self.shards.len(),
            frames = self.frames,
            forgotten,
            interval_secs = SUMMARY_INTERVAL.as_secs(),
            "archive proof settlement summary: GLOBAL proposals held headers of shards whose frames carry expensive \
             confidential operations until this archive verified them, so GLOBAL does not wait for those proofs"
        );
    }
}

// ---------------------------------------------------------------------------
// The GLOBAL hook's pre-verification
// ---------------------------------------------------------------------------

/// Application frames, and bytes of their bundles, read ahead per GLOBAL
/// frame. Frames beyond either verify under the lock, as before.
pub const PREPASS_MAX_FRAMES: usize = 1024;
pub const PREPASS_MAX_BYTES: usize = 128 << 20;
/// How long a pass retries operations that found no worker slot. Past it the
/// locked materialization verifies them, as before.
pub const PREPASS_BUSY_WINDOW: Duration = Duration::from_secs(300);
const PREPASS_BUSY_PAUSE: Duration = Duration::from_millis(500);
/// A pass longer than this is logged at info.
const PREPASS_NOTE: Duration = Duration::from_secs(5);
/// A pass longer than this warns, again every [`PREPASS_PROGRESS_INTERVAL`].
const PREPASS_WARN: Duration = Duration::from_secs(120);
const PREPASS_PROGRESS_INTERVAL: Duration = Duration::from_secs(60);

/// The bounds of [`preverify_through`].
#[derive(Clone, Copy, Debug)]
pub struct PrepassLimits {
    pub max_frames: usize,
    pub max_bytes: usize,
    pub busy_window: Duration,
    pub busy_pause: Duration,
}

impl Default for PrepassLimits {
    fn default() -> Self {
        Self {
            max_frames: PREPASS_MAX_FRAMES,
            max_bytes: PREPASS_MAX_BYTES,
            busy_window: PREPASS_BUSY_WINDOW,
            busy_pause: PREPASS_BUSY_PAUSE,
        }
    }
}

/// What [`preverify_through`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrepassReport {
    pub shards: usize,
    pub frames: usize,
    /// Frames left to the locked pass by [`PrepassLimits`].
    pub truncated: bool,
    pub rounds: usize,
    pub counts: PreverifyCounts,
}

/// A body the pass reads: held in memory, or stored above the cursor.
pub(crate) enum PlannedBody {
    Held(Vec<MessageBundle>),
    Stored(u64),
}

/// What a pass may still read: frames and bundle bytes.
pub(crate) struct PlanBudget {
    frames: usize,
    bytes: usize,
    pub(crate) truncated: bool,
}

impl PlanBudget {
    /// Take one frame of `bytes`; `false` (and truncated) past either bound.
    pub(crate) fn take(&mut self, bytes: usize) -> bool {
        if self.frames == 0 || bytes > self.bytes {
            self.truncated = true;
            return false;
        }
        self.frames -= 1;
        self.bytes -= bytes;
        true
    }

    /// Take `bytes` more for a frame already taken.
    fn take_bytes(&mut self, bytes: usize) -> bool {
        if bytes > self.bytes {
            self.truncated = true;
            return false;
        }
        self.bytes -= bytes;
        true
    }

    pub(crate) fn bundle_bytes(requests: &[MessageBundle]) -> usize {
        encoded_len(requests)
    }
}

/// Verify the confidential proofs of the frames the GLOBAL frame
/// `global_frame` is about to materialize (`targets`: per shard, the highest
/// frame it carries) without holding `ingest`, which is held only to look up
/// which bodies it holds. The locked materialization then finds their
/// verdicts cached; anything this leaves unverified it verifies itself.
pub fn preverify_through(
    ingest: &Mutex<ArchiveAppShardIngest>,
    global_frame: u64,
    targets: &[(Vec<u8>, u64)],
) -> PrepassReport {
    preverify_through_within(ingest, global_frame, targets, PrepassLimits::default())
}

pub fn preverify_through_within(
    ingest: &Mutex<ArchiveAppShardIngest>,
    global_frame: u64,
    targets: &[(Vec<u8>, u64)],
    limits: PrepassLimits,
) -> PrepassReport {
    let start = Instant::now();
    let mut report = PrepassReport::default();
    if targets.is_empty() {
        return report;
    }
    let mut budget = PlanBudget {
        frames: limits.max_frames,
        bytes: limits.max_bytes,
        truncated: false,
    };
    let (planned, verify, clock) = {
        let mut guard = crate::archive_ingest::lock_ingest(ingest);
        let mut planned = Vec::new();
        for (address, through) in targets {
            let bodies = guard.plan_bodies(address, *through, &mut budget);
            if !bodies.is_empty() {
                planned.push((address.clone(), bodies));
            }
        }
        let (verify, clock) = guard.preverify_sources();
        (planned, verify, clock)
    };
    let mut pairs = Vec::new();
    'shards: for (address, bodies) in planned {
        let mut frames = 0;
        for body in bodies {
            let requests = match body {
                PlannedBody::Held(requests) => requests,
                PlannedBody::Stored(number) => {
                    match clock.get_shard_clock_frame(&address, number, false) {
                        Ok(frame) if budget.take_bytes(encoded_len(&frame.requests)) => {
                            frame.requests
                        }
                        Ok(_) => break 'shards,
                        Err(_) => continue,
                    }
                }
            };
            if requests.is_empty() {
                continue;
            }
            frames += 1;
            pairs.extend(canonical_pairs(&address, &requests));
        }
        if frames > 0 {
            report.shards += 1;
            report.frames += frames;
        }
    }
    report.truncated = budget.truncated;
    if pairs.is_empty() {
        return report;
    }
    let (shards, frames, bundles) = (report.shards, report.frames, pairs.len());
    let done = AtomicUsize::new(0);
    let finished = Mutex::new(false);
    let finished_signal = Condvar::new();
    std::thread::scope(|scope| {
        let progress = scope.spawn(|| {
            let mut warned: Option<Instant> = None;
            let mut finished_guard = finished.lock().unwrap_or_else(|p| p.into_inner());
            loop {
                if *finished_guard {
                    return;
                }
                let elapsed = start.elapsed();
                if elapsed >= PREPASS_WARN
                    && warned.is_none_or(|at| at.elapsed() >= PREPASS_PROGRESS_INTERVAL)
                {
                    warned = Some(Instant::now());
                    warn!(
                        scope = "this archive",
                        frame = global_frame,
                        shards,
                        frames,
                        bundles,
                        done = done.load(Ordering::Relaxed),
                        secs = elapsed.as_secs(),
                        action = "GLOBAL execution of this frame waits for these proofs; the archive ingest stays free; \
                                  it ends when they verify (raise proofWorker.maxConcurrent if CPU allows)",
                        "archive GLOBAL frame proof pre-verification still running"
                    );
                }
                finished_guard = match finished_signal.wait_timeout(finished_guard, Duration::from_secs(1)) {
                    Ok((guard, _)) => guard,
                    Err(poisoned) => poisoned.into_inner().0,
                };
            }
        });
        loop {
            report.rounds += 1;
            done.store(0, Ordering::Relaxed);
            let counts = (*verify)(
                &pairs,
                &PreverifyPacing {
                    parallelism: None,
                    done: Some(&done),
                    pause: None,
                },
            );
            if report.rounds == 1 {
                report.counts = counts;
            } else {
                // Later rounds find earlier verdicts cached; they add what
                // they verified and replace what is still outstanding.
                report.counts.verified += counts.verified;
                report.counts.busy = counts.busy;
                report.counts.unavailable = counts.unavailable;
            }
            if counts.busy == 0 || start.elapsed() >= limits.busy_window {
                break;
            }
            std::thread::sleep(limits.busy_pause);
        }
        *finished.lock().unwrap_or_else(|p| p.into_inner()) = true;
        finished_signal.notify_all();
        let _ = progress.join();
    });
    let elapsed = start.elapsed();
    if elapsed >= PREPASS_NOTE {
        let counts = report.counts;
        macro_rules! pass_line {
            ($level:ident) => {
                $level!(
                    scope = "this archive",
                    frame = global_frame,
                    shards = report.shards,
                    frames = report.frames,
                    operations = counts.operations,
                    cached = counts.cached,
                    verified = counts.verified,
                    busy = counts.busy,
                    failed = counts.unavailable,
                    rounds = report.rounds,
                    truncated = report.truncated,
                    secs = elapsed.as_secs_f64(),
                    "archive GLOBAL frame proof pre-verification: proofs verified before taking the ingest; \
                     busy or failed ones verify in the locked pass"
                )
            };
        }
        if elapsed >= PREPASS_WARN {
            pass_line!(warn);
        } else {
            pass_line!(info);
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(tag: u8) -> MessageBundle {
        MessageBundle {
            requests: Vec::new(),
            timestamp: tag as i64,
        }
    }

    /// Every bundle one operation, the first `expensive` of a frame expensive.
    fn counting(expensive: usize) -> Arc<OperationClassifier> {
        Arc::new(move |pairs: &[(Vec<u8>, Vec<u8>)]| OperationCost {
            operations: pairs.len(),
            expensive: expensive.min(pairs.len()),
        })
    }

    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A verifier that blocks until `gate` opens and counts its calls.
    fn gated_verifier(
        gate: Arc<(Mutex<bool>, Condvar)>,
        calls: Arc<AtomicUsize>,
    ) -> Arc<ProofVerifier> {
        Arc::new(
            move |pairs: &[(Vec<u8>, Vec<u8>)], _: &PreverifyPacing<'_>| {
                let (open, opened) = &*gate;
                let mut open = open.lock().unwrap();
                while !*open {
                    open = opened.wait(open).unwrap();
                }
                calls.fetch_add(1, Ordering::SeqCst);
                PreverifyCounts {
                    operations: pairs.len(),
                    verified: pairs.len(),
                    ..Default::default()
                }
            },
        )
    }

    /// Past its frame bound the queue drops its oldest frames, counted, and
    /// verifies the rest once the verifier is free again.
    #[test]
    fn the_prewarm_queue_drops_its_oldest_frames_past_its_bound_and_recovers() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let prewarm =
            ProofPrewarm::with_bounds(gated_verifier(gate.clone(), calls.clone()), 4, usize::MAX)
                .with_classifier(counting(0));
        // The first frame is taken and blocks the verifier.
        prewarm.offer(b"shard", 0, &[bundle(0)]);
        wait_for("the first frame to be taken", || prewarm.stats().0 == 0);
        for tag in 1..=7 {
            prewarm.offer(b"shard", tag as u64, &[bundle(tag)]);
        }
        let (pending, stats) = prewarm.stats();
        assert_eq!((pending, stats.queued, stats.dropped), (4, 8, 3));
        // Frames without bundles are not queued.
        prewarm.offer(b"shard", 8, &[]);
        assert_eq!(prewarm.stats().1.queued, 8);
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        wait_for("the queue to drain", || prewarm.stats().1.frames == 5);
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert_eq!(prewarm.stats().0, 0);
    }

    /// A frame larger than the byte bound is dropped; later frames verify.
    #[test]
    fn the_prewarm_queue_drops_frames_past_its_byte_bound() {
        let gate = Arc::new((Mutex::new(true), Condvar::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let small = encoded_len(&[bundle(1)]);
        let prewarm = ProofPrewarm::with_bounds(gated_verifier(gate, calls.clone()), 16, small)
            .with_classifier(counting(0));
        prewarm.offer(b"shard", 1, &[bundle(1), bundle(2)]);
        assert_eq!(prewarm.stats().1.dropped, 1);
        prewarm.offer(b"shard", 2, &[bundle(3)]);
        wait_for("the small frame", || calls.load(Ordering::SeqCst) == 1);
        assert_eq!(prewarm.stats().1.frames, 1);
    }

    /// Proofs that found no worker slot are tried again from the back of
    /// the queue until they verify.
    #[test]
    fn a_prewarmed_frame_whose_proofs_found_no_worker_slot_is_tried_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let verifier: Arc<ProofVerifier> = {
            let calls = calls.clone();
            Arc::new(
                move |pairs: &[(Vec<u8>, Vec<u8>)], _: &PreverifyPacing<'_>| {
                    let busy = calls.fetch_add(1, Ordering::SeqCst) == 0;
                    PreverifyCounts {
                        operations: pairs.len(),
                        verified: if busy { 0 } else { pairs.len() },
                        busy: if busy { pairs.len() } else { 0 },
                        ..Default::default()
                    }
                },
            )
        };
        let prewarm = ProofPrewarm::new(verifier).with_classifier(counting(0));
        prewarm.offer(b"shard", 1, &[bundle(1)]);
        wait_for("the second attempt", || prewarm.stats().1.frames == 2);
        let (pending, stats) = prewarm.stats();
        assert_eq!((pending, stats.requeued, stats.counts.verified), (0, 1, 1));
        std::thread::sleep(PREWARM_BUSY_PAUSE * 2);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "verified once it found a slot"
        );
    }

    /// Frames without confidential operations are not queued: there is
    /// nothing to verify.
    #[test]
    fn a_frame_without_confidential_operations_is_not_queued() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(true), Condvar::new()));
        let none = Arc::new(|_: &[(Vec<u8>, Vec<u8>)]| OperationCost::default());
        let prewarm = ProofPrewarm::new(gated_verifier(gate, calls.clone())).with_classifier(none);
        prewarm.offer(b"shard", 1, &[bundle(1)]);
        assert_eq!(prewarm.stats(), (0, PrewarmStats::default()));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// The prewarm verifies one frame per lane at once, so frames carrying
    /// one operation each keep every verifier slot busy.
    #[test]
    fn the_prewarm_verifies_a_frame_per_lane_at_once() {
        let (running, most) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let verifier: Arc<ProofVerifier> = {
            let (running, most, gate) = (running.clone(), most.clone(), gate.clone());
            Arc::new(
                move |pairs: &[(Vec<u8>, Vec<u8>)], _: &PreverifyPacing<'_>| {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    most.fetch_max(now, Ordering::SeqCst);
                    let (open, opened) = &*gate;
                    let mut open = open.lock().unwrap();
                    while !*open {
                        open = opened.wait(open).unwrap();
                    }
                    running.fetch_sub(1, Ordering::SeqCst);
                    PreverifyCounts {
                        operations: pairs.len(),
                        verified: pairs.len(),
                        ..Default::default()
                    }
                },
            )
        };
        let prewarm = ProofPrewarm::new(verifier)
            .with_classifier(counting(0))
            .with_lanes(Arc::new(|| 3));
        for frame in 1..=4 {
            prewarm.offer(b"shard", frame, &[bundle(frame as u8)]);
        }
        wait_for("three frames verifying at once", || {
            most.load(Ordering::SeqCst) == 3
        });
        assert_eq!(prewarm.stats().0, 1, "the fourth waits for a lane");
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        wait_for("every frame", || prewarm.stats().1.frames == 4);
        assert_eq!(most.load(Ordering::SeqCst), 3, "never more than the lanes");
    }

    fn admitted(ledger: &mut SettlementLedger, frame: u64, at: Instant) {
        ledger.admit(b"shard", frame, 1, at);
    }

    /// A shard whose frames carry expensive operations is held until this
    /// archive verified them and the margin for slower archives passed; then
    /// it rides, and once GLOBAL executed it nothing of it is held.
    #[test]
    fn a_shard_is_held_until_its_expensive_proofs_verified_and_the_margin_passed() {
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let mut ledger = SettlementLedger::default();
        admitted(&mut ledger, 5, at(0));
        assert_eq!(ledger.decide(b"other", 0, 9, at(1)), Settlement::Clear);
        assert_eq!(
            ledger.decide(b"shard", 4, 4, at(1)),
            Settlement::Clear,
            "a header below it rides"
        );
        assert_eq!(ledger.decide(b"shard", 4, 6, at(10)), Settlement::Settling);
        ledger.settle(b"shard", 5, at(30));
        // Verified in 30 s here: held until 60 s after admission.
        assert_eq!(ledger.decide(b"shard", 4, 6, at(59)), Settlement::Settling);
        assert_eq!(ledger.decide(b"shard", 4, 6, at(60)), Settlement::Settled);
        assert_eq!(ledger.window.held, 2);
        assert_eq!(ledger.window.longest_hold, Duration::from_secs(59));
        // GLOBAL executed it: forgotten.
        assert_eq!(ledger.decide(b"shard", 6, 7, at(61)), Settlement::Clear);
        assert_eq!((ledger.frames, ledger.shards.len()), (0, 0));
    }

    /// Newer frames that keep carrying expensive operations never all
    /// verify: once the oldest verified and waited three times its
    /// verification (at least a minute), the shard rides; once GLOBAL
    /// executed it, a later such frame holds it again.
    #[test]
    fn a_shard_receiving_expensive_operations_without_pause_rides_at_its_lag_bound() {
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let mut ledger = SettlementLedger::default();
        admitted(&mut ledger, 5, at(0));
        ledger.settle(b"shard", 5, at(40));
        admitted(&mut ledger, 6, at(10));
        admitted(&mut ledger, 7, at(100));
        assert_eq!(ledger.decide(b"shard", 4, 7, at(119)), Settlement::Settling);
        assert_eq!(ledger.decide(b"shard", 4, 7, at(120)), Settlement::LagBound);
        assert_eq!(ledger.window.lag_bound, 1);
        // The header it rode with executed through frame 6; frame 7 holds
        // it again, from its own admission.
        assert_eq!(ledger.decide(b"shard", 6, 8, at(121)), Settlement::Settling);
        assert_eq!(ledger.shards[&b"shard".to_vec()].since, at(100));
        // A slow first verification (300 s here) raises the hold limit to
        // three times that, so the lag bound, not the limit, releases it.
        let mut ledger = SettlementLedger::default();
        admitted(&mut ledger, 5, at(0));
        ledger.settle(b"shard", 5, at(300));
        admitted(&mut ledger, 6, at(10));
        assert_eq!(ledger.decide(b"shard", 4, 6, at(899)), Settlement::Settling);
        assert_eq!(ledger.decide(b"shard", 4, 6, at(900)), Settlement::LagBound);
        // All verified, the slowest so slowly that its margin passes the
        // limit: the limit releases it, as settled.
        let mut ledger = SettlementLedger::default();
        admitted(&mut ledger, 5, at(0));
        ledger.settle(b"shard", 5, at(700));
        let limit = SETTLE_HOLD_LIMIT_MAX.as_secs();
        assert_eq!(
            ledger.decide(b"shard", 4, 5, at(limit - 1)),
            Settlement::Settling
        );
        assert_eq!(
            ledger.decide(b"shard", 4, 5, at(limit)),
            Settlement::Settled
        );
        assert_eq!(ledger.window.hold_limit, 0);
        // A fast first verification still holds it for the floor.
        let mut ledger = SettlementLedger::default();
        admitted(&mut ledger, 5, at(0));
        ledger.settle(b"shard", 5, at(1));
        admitted(&mut ledger, 6, at(2));
        assert_eq!(ledger.decide(b"shard", 4, 6, at(59)), Settlement::Settling);
        assert_eq!(ledger.decide(b"shard", 4, 6, at(60)), Settlement::LagBound);
    }

    /// No hold outlasts the hold limit from the oldest such frame above the
    /// cursor, whatever is still unverified and however many frames arrive;
    /// past it every proposal carries the header until GLOBAL executes it.
    #[test]
    fn no_hold_outlasts_the_hold_limit() {
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let limit = SETTLE_HOLD_LIMIT.as_secs();
        let mut ledger = SettlementLedger::default();
        admitted(&mut ledger, 5, at(0));
        for frame in 6..20 {
            admitted(&mut ledger, frame, at((frame - 5) * 40));
        }
        assert_eq!(
            ledger.decide(b"shard", 4, 19, at(limit - 1)),
            Settlement::Settling
        );
        assert_eq!(
            ledger.decide(b"shard", 4, 19, at(limit)),
            Settlement::HoldLimit
        );
        assert!(ledger.limit.is_some(), "warned");
        assert_eq!(
            ledger.decide(b"shard", 4, 19, at(limit * 3)),
            Settlement::HoldLimit
        );
        // Only GLOBAL executing frames moves it: through frame 9, the oldest
        // left was admitted at 200 s.
        assert_eq!(
            ledger.decide(b"shard", 9, 19, at(200 + limit - 1)),
            Settlement::Settling
        );
        assert_eq!(
            ledger.decide(b"shard", 9, 19, at(200 + limit)),
            Settlement::HoldLimit
        );
        assert_eq!(ledger.window.hold_limit, 3);
        // An interval without such a proposal ends the run.
        ledger.summarize(at(200 + limit));
        ledger.summarize(at(200 + limit + 1));
        assert!(ledger.limit.is_none());
    }

    /// The ledger records at most its bound; a frame it did not record never
    /// holds its shard, and frames past twice the hold limit are forgotten.
    #[test]
    fn the_ledger_is_bounded_and_never_holds_what_it_did_not_record() {
        let start = Instant::now();
        let mut ledger = SettlementLedger::default();
        for frame in 0..SETTLE_MAX_FRAMES as u64 {
            ledger.admit(b"full", frame, 1, start);
        }
        ledger.admit(b"shard", 1, 1, start);
        assert_eq!(ledger.window.untracked, 1);
        assert_eq!(ledger.decide(b"shard", 0, 1, start), Settlement::Clear);
        ledger.summarize(start + SETTLE_HOLD_LIMIT_MAX * 2);
        assert_eq!((ledger.frames, ledger.shards.len()), (0, 0));
        ledger.admit(b"shard", 1, 1, start + SETTLE_HOLD_LIMIT_MAX * 2);
        assert_eq!(
            ledger.decide(b"shard", 0, 1, start + SETTLE_HOLD_LIMIT_MAX * 2),
            Settlement::Settling
        );
    }

    /// The prewarm records an admitted frame carrying expensive operations,
    /// and the proposal check holds its shard until a lane verified it, then
    /// releases it once the margin passed. A frame of cheap operations only,
    /// also verified ahead, never holds.
    #[test]
    fn the_prewarm_holds_a_shard_until_a_lane_verified_its_expensive_frame() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let prewarm = ProofPrewarm::new(gated_verifier(gate.clone(), calls.clone()))
            .with_classifier(counting(1));
        let settlement = prewarm.settlement();
        prewarm.offer(b"shard", 3, &[bundle(1)]);
        assert!(settlement.check(b"shard", 2, 3).holds());
        let cheap = ProofPrewarm::new(gated_verifier(gate.clone(), calls.clone()))
            .with_classifier(counting(0));
        cheap.offer(b"shard", 3, &[bundle(1)]);
        assert_eq!(cheap.settlement().check(b"shard", 2, 3), Settlement::Clear);
        std::thread::sleep(Duration::from_millis(20));
        assert!(settlement.check(b"shard", 2, 3).holds(), "not verified yet");
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        wait_for("the shard to settle", || {
            settlement.check(b"shard", 2, 3) == Settlement::Settled
        });
        assert_eq!(settlement.check(b"shard", 3, 4), Settlement::Clear);
    }
}
