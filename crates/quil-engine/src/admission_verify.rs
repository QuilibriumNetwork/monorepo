//! Confidential proofs verified as submissions arrive.
//!
//! A member verified a submission's confidential proofs only once a frame
//! carrying it was proposed, and materializing that frame waited for the
//! verdict: a 96-source batch shield held its shard's engine for five to
//! fourteen minutes, during which the members built no storage snapshot and
//! were kicked for the missing epoch proof (devnet, 2026-10-29). Verdicts are a
//! pure function of the operation bytes and the network policy, cached
//! process-wide, so computing them on arrival changes only when they are
//! computed: proposals then carry operations whose verdicts are cached, and
//! materializing them verifies nothing.
//!
//! Three lanes, verified in this order. Submissions a finalized frame waits
//! on ([`AdmissionQueue::offer`] with `front`), in the order frames asked for
//! them. Then vote-time warm-ups of a proposal's long operations
//! ([`AdmissionQueue::offer_warmup`]): speculative, since the proposal may
//! never finalize. Then the rest, oldest first. Every member receives a
//! submission at about the same time and verifies in the same order, so the
//! members finish it at about the same time and a proposal carrying it right
//! after its leader verified it finds the others ready. The queue verifies up
//! to [`background_threads`] at once: one fewer than the proof worker admits,
//! so a slot stays free for the frames and proposals that verify inline. One
//! at a time verified about 16 batch shields an hour (240 s each) while more
//! arrived, and frames waiting on them failed (mainnet, 2026-10-31); two at
//! once on a 16-core node took 4% longer each. Across the node's processes,
//! verifications no frame waits on stay off the first node-wide worker slot
//! ([`verifying_for_frame`]), which frames and inline verifications share.
//!
//! Bounds and recovery: a submission no frame waits on is dropped from the
//! queue past its count or byte bound and offered again by the proposal that
//! holds it or the frame that needs it; one whose verification found no
//! worker slot is retried [`MAX_ATTEMPTS`] times per offer. Warm-ups are
//! bounded by [`MAX_WARMUPS`] (the oldest goes first) and dropped once queued
//! for [`WARMUP_TTL`], or once their shard materialized their frame
//! ([`AdmissionQueue::end_warmups`]); a warm-up a finalized frame then needs
//! is offered again by that frame and joins the frames' lane. A warm-up of a
//! proposal that never finalizes therefore holds at most one queue thread for
//! one verification. A submission a frame waits on is never dropped for the
//! bounds (frames waiting are bounded by the frames this node holds: only
//! finalized frames wait, besides one bundle per shard that its proposals
//! held past their hold bound) and is retried while the worker is busy, at
//! the front: a worker slot frees within one verification's wall timeout. One
//! whose verification failed in the worker (crash, timeout, resource cap,
//! panic) is retried until it failed [`MAX_FAILURES`] times, after which this
//! node's proposals leave it out and it ages out of the pool unless another
//! member's proposal carries it; a frame carrying it then verifies it inline.

use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use quil_execution::manager::PreverifyCounts;
use tracing::{info, warn};

/// Verifies one submission's confidential proofs, filling the verdict cache.
pub type AdmissionJob = Arc<dyn Fn() -> PreverifyCounts + Send + Sync>;

/// Submissions waiting, and bytes of them. Past either bound the oldest no
/// frame waits on is dropped (counted); its proofs are verified when a
/// proposal or frame needs them, as before.
pub const MAX_BUNDLES: usize = 256;
pub const MAX_BYTES: usize = 64 << 20;
/// Vote-time warm-ups queued at once. A member trailing its leader is the
/// only one a warm-up helps (a leader carries a long operation only once it
/// verified it), and the frame that finalizes asks for its own operations
/// anyway, so a few proposals' worth suffices; past it the oldest goes.
pub const MAX_WARMUPS: usize = 16;
/// A warm-up still queued after this is dropped: its proposal's view has
/// long ended, and if the proposal finalized, its frame asked for it.
pub const WARMUP_TTL: Duration = Duration::from_secs(120);
/// Attempts per submission no frame waits on whose verification found no
/// worker slot.
const MAX_ATTEMPTS: u8 = 3;
/// Verifications of one submission that may fail in the worker before this
/// node's proposals leave it out.
pub const MAX_FAILURES: u8 = 3;
/// Submissions whose failures are remembered; past it the oldest is
/// forgotten (and may be verified again).
const FAILURE_ENTRIES: usize = 1024;
/// Pause after a verification found no worker slot.
const BUSY_PAUSE: Duration = Duration::from_secs(1);
/// How often the queue logs what it did.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(600);
/// Arrivals ([`offer_arrival`]) are verified up to the queue's threads times
/// this much estimated worker time per this window: at most what the queue
/// verifies meanwhile, so arrivals never queue more work than it finishes in
/// one window ahead of the proposals and frames that offer theirs. Past it
/// an arrival is not queued; a proposal or frame needing it verifies it.
const ARRIVAL_WINDOW: Duration = Duration::from_secs(600);
/// The proof worker admits at most this many verifications at once.
const MAX_THREADS: usize = 64;

/// Verifications the queue runs at once for a proof worker admitting
/// `concurrency` (`proofWorker.maxConcurrent`): one fewer, so a slot stays
/// free for frames and proposals verifying inline, and at least one.
pub fn background_threads(concurrency: Option<usize>) -> usize {
    concurrency
        .map_or(1, |slots| slots.saturating_sub(1))
        .clamp(1, MAX_THREADS)
}

thread_local! {
    static FOR_FRAME: Cell<bool> = const { Cell::new(false) };
}

/// Whether the admission job running on this thread verifies a submission a
/// finalized frame waits on. Jobs pass it to the proof worker: the others
/// are background verifications, which leave the first node-wide worker slot
/// to frames and inline verifications in every node process.
pub fn verifying_for_frame() -> bool {
    FOR_FRAME.with(Cell::get)
}

/// The proposal a warm-up was queued for.
struct Warm {
    shard: Vec<u8>,
    frame: u64,
    expires: Instant,
}

struct Item {
    digest: [u8; 32],
    bytes: usize,
    attempts: u8,
    operations: usize,
    job: AdmissionJob,
    /// Set for a vote-time warm-up no frame waits on yet.
    warm: Option<Warm>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdmissionStats {
    pub queued: usize,
    pub requeued: usize,
    pub dropped: usize,
    /// Submissions that reached [`MAX_FAILURES`].
    pub released: usize,
    /// Warm-ups queued, and those dropped (bound, age, frame materialized).
    pub warmups: usize,
    pub warmups_dropped: usize,
    pub counts: PreverifyCounts,
    /// Arrivals not queued because they need no verification: the collector
    /// already held them or a finalized frame consumed them, they fail
    /// dispatch's checks before native work, or the global commit decided
    /// them ([`note_arrival_skipped`](AdmissionQueue::note_arrival_skipped)).
    pub arrival_skipped: usize,
    /// Arrivals not queued past the [`ARRIVAL_WINDOW`] budget.
    pub arrival_over_budget: usize,
    /// Estimated worker-seconds of the arrivals admitted.
    pub arrival_secs: u64,
}

#[derive(Default)]
struct State {
    /// Submissions frames wait on first, in the order frames asked for
    /// them, then warm-ups, then the rest.
    queue: VecDeque<Item>,
    /// Digests queued or verifying.
    pending: HashSet<[u8; 32]>,
    /// Digests queued or verifying that a frame waits on.
    wanted: HashSet<[u8; 32]>,
    bytes: usize,
    /// Verifying threads started, and how many to run.
    threads: usize,
    target_threads: usize,
    window: AdmissionStats,
    summarized: Option<Instant>,
    /// Estimated worker-seconds arrivals may still take, and when it was
    /// last refilled (`None`: full).
    arrival_credit: f64,
    arrival_refilled: Option<Instant>,
    /// Digest → verifications of it that failed in the worker, oldest first.
    failures: HashMap<[u8; 32], u8>,
    failure_order: VecDeque<[u8; 32]>,
    /// Shard filter → the latest frame it materialized: warm-ups of it and
    /// earlier frames are no longer needed.
    ended: HashMap<Vec<u8>, u64>,
}

impl State {
    fn failed(&self, digest: &[u8; 32]) -> u8 {
        self.failures.get(digest).copied().unwrap_or(0)
    }

    /// Count a failed verification of `digest`; its new count.
    fn note_failure(&mut self, digest: [u8; 32], capacity: usize) -> u8 {
        if !self.failures.contains_key(&digest) {
            while self.failure_order.len() >= capacity.max(1) {
                if let Some(oldest) = self.failure_order.pop_front() {
                    self.failures.remove(&oldest);
                }
            }
            self.failure_order.push_back(digest);
        }
        let count = self.failures.entry(digest).or_insert(0);
        *count = count.saturating_add(1);
        *count
    }

    fn forget_failures(&mut self, digest: &[u8; 32]) {
        if self.failures.remove(digest).is_some() {
            self.failure_order.retain(|d| d != digest);
        }
    }

    /// Queued submissions frames wait on: the head of the queue.
    fn wanted_queued(&self) -> usize {
        self.queue
            .iter()
            .take_while(|item| self.wanted.contains(&item.digest))
            .count()
    }

    /// Queued warm-ups: right behind the submissions frames wait on.
    fn warm_queued(&self) -> usize {
        self.queue
            .iter()
            .skip(self.wanted_queued())
            .take_while(|item| item.warm.is_some())
            .count()
    }

    /// Queue `item` behind the submissions frames already wait on.
    fn queue_wanted(&mut self, mut item: Item) {
        item.warm = None;
        let at = self.wanted_queued();
        self.queue.insert(at, item);
    }

    /// Queue warm-up `item` behind the others, ahead of arrivals.
    fn queue_warm(&mut self, item: Item) {
        let at = self.wanted_queued() + self.warm_queued();
        self.queue.insert(at, item);
    }

    /// Whether warm-up `warm` is still worth verifying at `now`.
    fn warm_live(&self, warm: &Warm, now: Instant) -> bool {
        now < warm.expires
            && self
                .ended
                .get(&warm.shard)
                .is_none_or(|ended| *ended < warm.frame)
    }

    /// Remove the queued item at `index` (dropped, not verified).
    fn drop_at(&mut self, index: usize) {
        if let Some(dropped) = self.queue.remove(index) {
            self.bytes -= dropped.bytes;
            self.pending.remove(&dropped.digest);
            self.window.dropped += 1;
            if dropped.warm.is_some() {
                self.window.warmups_dropped += 1;
            }
        }
    }

    /// Drop the queued warm-ups no longer worth verifying.
    fn prune_warm(&mut self, now: Instant) {
        let start = self.wanted_queued();
        let mut index = start;
        while index < start + self.warm_queued() {
            let live = self.queue[index]
                .warm
                .as_ref()
                .is_some_and(|warm| self.warm_live(warm, now));
            if live {
                index += 1;
            } else {
                self.drop_at(index);
            }
        }
    }

    fn finish(&mut self, digest: &[u8; 32]) {
        self.pending.remove(digest);
        self.wanted.remove(digest);
    }
}

/// Where an offer goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lane {
    /// A finalized frame waits on it.
    Frame,
    /// A vote-time warm-up.
    Warm,
    /// Everything else.
    Arrival,
}

/// One bounded queue of submissions whose proofs background threads verify:
/// those frames wait on first, then warm-ups, then the rest oldest first.
pub struct AdmissionQueue {
    state: Mutex<State>,
    wake: Condvar,
    max_bundles: usize,
    max_bytes: usize,
    max_warmups: usize,
    warmup_ttl: Duration,
    failure_entries: usize,
    /// Whether offers start the background threads (tests drive it by hand).
    spawn: bool,
}

impl AdmissionQueue {
    pub fn new(max_bundles: usize, max_bytes: usize, spawn: bool) -> Arc<Self> {
        Self::build(
            max_bundles,
            max_bytes,
            FAILURE_ENTRIES,
            MAX_WARMUPS,
            WARMUP_TTL,
            spawn,
        )
    }

    fn build(
        max_bundles: usize,
        max_bytes: usize,
        failure_entries: usize,
        max_warmups: usize,
        warmup_ttl: Duration,
        spawn: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                target_threads: 1,
                ..State::default()
            }),
            wake: Condvar::new(),
            max_bundles: max_bundles.max(1),
            max_bytes,
            max_warmups: max_warmups.max(1),
            warmup_ttl,
            failure_entries,
            spawn,
        })
    }

    /// Admit an arrival estimated at `cost_secs` worker-seconds under the
    /// [`ARRIVAL_WINDOW`] budget: the queue's threads times the window,
    /// refilled at one second per thread per second. One is admitted while
    /// any credit is left, so the work admitted per window exceeds the
    /// budget by at most one arrival. False (counted) past it.
    pub fn admit_arrival(&self, cost_secs: f64, now: Instant) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let threads = state.target_threads.max(1) as f64;
        let capacity = threads * ARRIVAL_WINDOW.as_secs_f64();
        let credit = match state.arrival_refilled {
            None => capacity,
            Some(at) => (state.arrival_credit
                + now.saturating_duration_since(at).as_secs_f64() * threads)
                .min(capacity),
        };
        state.arrival_refilled = Some(now);
        let admitted = credit > 0.0;
        if admitted {
            let cost = if cost_secs.is_finite() {
                cost_secs.max(0.0)
            } else {
                capacity
            };
            state.arrival_credit = credit - cost;
            state.window.arrival_secs = state
                .window
                .arrival_secs
                .saturating_add(cost.round() as u64);
        } else {
            state.arrival_credit = credit;
            state.window.arrival_over_budget += 1;
        }
        Self::summarize(&mut state);
        admitted
    }

    /// Give back an admitted arrival's credit when it was not queued.
    pub fn refund_arrival(&self, cost_secs: f64) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.arrival_refilled.is_some() && cost_secs.is_finite() {
            let capacity = state.target_threads.max(1) as f64 * ARRIVAL_WINDOW.as_secs_f64();
            state.arrival_credit = (state.arrival_credit + cost_secs.max(0.0)).min(capacity);
            state.window.arrival_secs = state
                .window
                .arrival_secs
                .saturating_sub(cost_secs.max(0.0).round() as u64);
        }
    }

    /// Count an arrival not queued because it needs no verification.
    pub fn note_arrival_skipped(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.window.arrival_skipped += 1;
        Self::summarize(&mut state);
    }

    /// Run up to `threads` verifications at once ([`background_threads`]);
    /// threads start with the next offer.
    pub fn set_threads(&self, threads: usize) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .target_threads = threads.clamp(1, MAX_THREADS);
    }

    /// Whether `digest`'s verification failed in the worker
    /// [`MAX_FAILURES`] times: it is not queued again, and proposals leave
    /// it out.
    pub fn released(&self, digest: &[u8; 32]) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .failed(digest)
            >= MAX_FAILURES
    }

    /// Queue a submission's verification of `operations` confidential
    /// operations, at the back or, for a finalized frame that waits on it
    /// (`front`), behind the submissions frames already wait on. False when
    /// it is already queued or verifying (a queued one a frame now waits on
    /// moves up), when it alone exceeds the byte bound, when it was released
    /// ([`Self::released`]), or when the queue is full of submissions frames
    /// wait on and warm-ups and no frame waits on this one.
    pub fn offer(
        self: &Arc<Self>,
        digest: [u8; 32],
        bytes: usize,
        operations: usize,
        job: AdmissionJob,
        front: bool,
    ) -> bool {
        let lane = if front { Lane::Frame } else { Lane::Arrival };
        self.offer_in(digest, bytes, operations, job, lane, None)
    }

    /// [`Self::offer`] for a finalized frame that waits on it, `job`
    /// verifying it as that frame executes it: a queued verification of it
    /// takes `job` in its place, so the frame's wait ends on what the frame
    /// verifies (an operation a gate refuses only after the frame's
    /// anchor), not on what a frame not known yet would.
    pub fn offer_for_frame(
        self: &Arc<Self>,
        digest: [u8; 32],
        bytes: usize,
        operations: usize,
        job: AdmissionJob,
    ) -> bool {
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(item) = state.queue.iter_mut().find(|item| item.digest == digest) {
                item.job = job.clone();
            }
        }
        self.offer(digest, bytes, operations, job, true)
    }

    /// Queue a vote-time warm-up of a proposal for `frame` of `shard`:
    /// behind the submissions frames wait on, ahead of arrivals, at most
    /// [`MAX_WARMUPS`] (the oldest is dropped), dropped once queued for
    /// [`WARMUP_TTL`] or once the shard materialized `frame`
    /// ([`Self::end_warmups`]), and retried [`MAX_ATTEMPTS`] times while the
    /// worker is busy. False when it is already queued or verifying (a
    /// queued arrival moves up; a queued warm-up takes the newer proposal),
    /// when the shard already materialized `frame`, and as [`Self::offer`].
    pub fn offer_warmup(
        self: &Arc<Self>,
        digest: [u8; 32],
        bytes: usize,
        operations: usize,
        job: AdmissionJob,
        shard: &[u8],
        frame: u64,
    ) -> bool {
        let warm = Warm {
            shard: shard.to_vec(),
            frame,
            expires: Instant::now() + self.warmup_ttl,
        };
        self.offer_in(digest, bytes, operations, job, Lane::Warm, Some(warm))
    }

    /// `shard` materialized `frame`: its warm-ups of that frame and earlier
    /// are dropped, and later offers of them refused. Those the frame needs
    /// it asked for first, which moved them to the frames' lane.
    pub fn end_warmups(&self, shard: &[u8], frame: u64) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let ended = state.ended.entry(shard.to_vec()).or_insert(frame);
        *ended = (*ended).max(frame);
        state.prune_warm(Instant::now());
    }

    fn offer_in(
        self: &Arc<Self>,
        digest: [u8; 32],
        bytes: usize,
        operations: usize,
        job: AdmissionJob,
        lane: Lane,
        warm: Option<Warm>,
    ) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.failed(&digest) >= MAX_FAILURES {
            return false;
        }
        if bytes > self.max_bytes {
            state.window.dropped += 1;
            return false;
        }
        state.prune_warm(now);
        if warm
            .as_ref()
            .is_some_and(|warm| !state.warm_live(warm, now))
        {
            return false;
        }
        if state.pending.contains(&digest) {
            self.promote(&mut state, digest, lane, warm);
            return false;
        }
        if lane == Lane::Warm && state.warm_queued() >= self.max_warmups {
            let oldest = state.wanted_queued();
            state.drop_at(oldest);
        }
        while !state.queue.is_empty()
            && (state.queue.len() >= self.max_bundles || state.bytes + bytes > self.max_bytes)
        {
            let frames = state.wanted_queued();
            let warming = state.warm_queued();
            if frames + warming < state.queue.len() {
                // The oldest arrival goes first.
                state.drop_at(frames + warming);
            } else if lane != Lane::Arrival && warming > 0 {
                // Then the oldest warm-up, for a frame or a newer warm-up.
                state.drop_at(frames);
            } else if lane == Lane::Frame {
                // Only submissions frames wait on are queued, bounded by
                // the finalized frames this node holds: admit this one too.
                break;
            } else {
                state.window.dropped += 1;
                return false;
            }
        }
        let item = Item {
            digest,
            bytes,
            attempts: 0,
            operations,
            job,
            warm,
        };
        match lane {
            Lane::Frame => {
                state.wanted.insert(digest);
                state.queue_wanted(item);
            }
            Lane::Warm => {
                state.window.warmups += 1;
                state.queue_warm(item);
            }
            Lane::Arrival => state.queue.push_back(item),
        }
        state.pending.insert(digest);
        state.bytes += bytes;
        state.window.queued += 1;
        let start = if self.spawn {
            state.target_threads.saturating_sub(state.threads)
        } else {
            0
        };
        state.threads += start;
        drop(state);
        let mut started = 0;
        for _ in 0..start {
            let queue = self.clone();
            let spawned = std::thread::Builder::new()
                .name("proof-admission".into())
                .spawn(move || queue.run());
            if spawned.is_err() {
                break;
            }
            started += 1;
        }
        if started < start {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.threads -= start - started;
            if state.threads == 0 {
                // Nothing verifies the queue: give its entries back to the
                // proposals and frames that verify them anyway.
                state.queue.clear();
                state.pending.clear();
                state.wanted.clear();
                state.bytes = 0;
                return false;
            }
        }
        self.wake.notify_one();
        true
    }

    /// A pending `digest` offered again in `lane`: a frame now waiting on it
    /// moves it to the frames' lane; a warm-up moves a queued arrival up
    /// (within [`MAX_WARMUPS`]) or gives a queued warm-up its newer proposal.
    fn promote(&self, state: &mut State, digest: [u8; 32], lane: Lane, warm: Option<Warm>) {
        if state.wanted.contains(&digest) {
            return;
        }
        let index = state.queue.iter().position(|item| item.digest == digest);
        match lane {
            Lane::Frame => {
                state.wanted.insert(digest);
                // A frame now waits on it: a queued one moves up.
                if let Some(item) = index.and_then(|index| state.queue.remove(index)) {
                    state.queue_wanted(item);
                }
            }
            Lane::Warm => {
                let Some(index) = index else { return };
                if state.queue[index].warm.is_some() {
                    state.queue[index].warm = warm;
                } else if state.warm_queued() < self.max_warmups {
                    if let Some(mut item) = state.queue.remove(index) {
                        item.warm = warm;
                        state.window.warmups += 1;
                        state.queue_warm(item);
                    }
                }
            }
            Lane::Arrival => {}
        }
    }

    /// Whether `digest` is queued or verifying.
    pub fn pending(&self, digest: &[u8; 32]) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending
            .contains(digest)
    }

    /// Submissions queued ahead of `digest`; `None` when it is not queued
    /// (verifying, or not pending).
    pub fn queued_ahead(&self, digest: &[u8; 32]) -> Option<usize> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .queue
            .iter()
            .position(|item| &item.digest == digest)
    }

    /// Verify the first queued submission. False when none is queued.
    pub fn run_one(&self) -> bool {
        self.run_next().is_some()
    }

    /// [`Self::run_one`], with what the verification found.
    fn run_next(&self) -> Option<PreverifyCounts> {
        let (item, for_frame) = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.prune_warm(Instant::now());
            let item = state.queue.pop_front()?;
            state.bytes -= item.bytes;
            let for_frame = state.wanted.contains(&item.digest);
            (item, for_frame)
        };
        // A panicking verification counts as one failed in the worker, so
        // the thread keeps verifying the queue frames wait on.
        let previous = FOR_FRAME.with(|cell| cell.replace(for_frame));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (item.job)()));
        FOR_FRAME.with(|cell| cell.set(previous));
        let counts = outcome.unwrap_or_else(|_| {
            warn!(
                scope = "this node",
                submission = %hex::encode(&item.digest[..8]),
                operations = item.operations,
                action = "counted as a failed verification and retried; a defect to report",
                "confidential proof verification panicked in the admission queue"
            );
            PreverifyCounts {
                operations: item.operations,
                unavailable: item.operations.max(1),
                ..Default::default()
            }
        });
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.window.counts.add(counts);
        let wanted = state.wanted.contains(&item.digest);
        // A warm-up no frame waits on goes back only while worth verifying,
        // and within the warm-up bound.
        let warm_back = match item.warm.as_ref() {
            Some(warm) if !wanted => {
                state.warm_live(warm, now) && state.warm_queued() < self.max_warmups
            }
            _ => true,
        };
        let failures = if counts.unavailable > 0 {
            state.note_failure(item.digest, self.failure_entries)
        } else {
            if counts.busy == 0 {
                state.forget_failures(&item.digest);
            }
            0
        };
        if failures >= MAX_FAILURES {
            state.finish(&item.digest);
            state.window.released += 1;
            warn!(
                scope = "this node's proof worker",
                submission = %hex::encode(&item.digest[..8]),
                operations = item.operations,
                failures,
                action = "this node's proposals leave the submission out; it ages out of this node's pool unless \
                          another member's proposal carries it, and a frame carrying it verifies it inline; \
                          check this node's proof worker (proofWorker settings, memory, CPU)",
                "confidential proofs of a submission failed to verify in this node's proof worker"
            );
        } else if (failures > 0 || counts.busy > 0) && !warm_back {
            // A warm-up whose proposal's time passed: left to the frame that
            // needs it, if one does.
            state.finish(&item.digest);
            state.window.warmups_dropped += 1;
        } else if failures > 0 {
            // Failed in the worker (counted above): try again after the
            // rest of its lane.
            state.window.requeued += 1;
            state.bytes += item.bytes;
            if wanted {
                state.queue_wanted(item);
            } else if item.warm.is_some() {
                state.queue_warm(item);
            } else {
                state.queue.push_back(item);
            }
        } else if counts.busy > 0 && wanted {
            // Found no worker slot while a frame waits on it: first again.
            state.window.requeued += 1;
            state.bytes += item.bytes;
            state.queue.push_front(Item { warm: None, ..item });
        } else if counts.busy > 0 && item.attempts + 1 < MAX_ATTEMPTS {
            // Found no worker slot: try again after the rest of its lane.
            state.window.requeued += 1;
            state.bytes += item.bytes;
            let item = Item {
                attempts: item.attempts + 1,
                ..item
            };
            if item.warm.is_some() {
                state.queue_warm(item);
            } else {
                state.queue.push_back(item);
            }
        } else {
            state.finish(&item.digest);
        }
        Self::summarize(&mut state);
        Some(counts)
    }

    fn run(self: Arc<Self>) {
        loop {
            {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                while state.queue.is_empty() {
                    state = self
                        .wake
                        .wait_timeout(state, SUMMARY_INTERVAL)
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                    Self::summarize(&mut state);
                }
            }
            if self.run_next().is_some_and(|counts| counts.busy > 0) {
                std::thread::sleep(BUSY_PAUSE);
            }
        }
    }

    /// What the queue did since its last summary.
    pub fn stats(&self) -> AdmissionStats {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).window
    }

    /// One line per [`SUMMARY_INTERVAL`] while submissions are queued or
    /// verified.
    fn summarize(state: &mut State) {
        let now = Instant::now();
        let since = *state.summarized.get_or_insert(now);
        if now.duration_since(since) < SUMMARY_INTERVAL {
            return;
        }
        state.summarized = Some(now);
        let window = std::mem::take(&mut state.window);
        if window == AdmissionStats::default() && state.queue.is_empty() {
            return;
        }
        info!(
            scope = "this node",
            queued = window.queued,
            operations = window.counts.operations,
            verified = window.counts.verified,
            joined = window.counts.joined,
            cached = window.counts.cached,
            busy = window.counts.busy,
            failed = window.counts.unavailable,
            requeued = window.requeued,
            dropped = window.dropped,
            released = window.released,
            warmups = window.warmups,
            warmups_dropped = window.warmups_dropped,
            pending = state.queue.len(),
            frames_waiting = state.wanted_queued(),
            warming = state.warm_queued(),
            threads = state.threads,
            arrival_skipped = window.arrival_skipped,
            arrival_over_budget = window.arrival_over_budget,
            arrival_secs = window.arrival_secs,
            arrival_budget_secs =
                (state.target_threads.max(1) as u64).saturating_mul(ARRIVAL_WINDOW.as_secs()),
            interval_secs = SUMMARY_INTERVAL.as_secs(),
            "confidential proof admission summary: proofs of arriving submissions verified before a frame \
             carries them, those finalized frames wait on first, then vote-time warm-ups (bounded, dropped \
             when their proposal's time passed); dropped ones, and arrivals past the budget or needing no \
             verification (skipped), verify when a proposal or frame needs them"
        );
    }
}

/// Size the node's queue to a proof worker admitting `slots` verifications
/// at once ([`background_threads`]); logged once per call (at startup).
pub fn use_worker_slots(slots: usize) {
    let threads = background_threads(Some(slots));
    global().set_threads(threads);
    info!(
        scope = "this node",
        worker_slots = slots,
        threads,
        "confidential proof admission queue sized: it verifies up to `threads` submissions at once and \
         leaves the proof worker's other slots to frames and proposals verifying inline"
    );
}

/// The node's queue.
pub fn global() -> &'static Arc<AdmissionQueue> {
    static QUEUE: std::sync::OnceLock<Arc<AdmissionQueue>> = std::sync::OnceLock::new();
    QUEUE.get_or_init(|| AdmissionQueue::new(MAX_BUNDLES, MAX_BYTES, true))
}

/// The digest submissions are known by: SHA3-256 of their canonical bytes.
pub fn digest(canonical: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    Sha3_256::digest(canonical).into()
}

/// A canonical submission's confidential operation count, digest and
/// verification job on `exec`'s worker, one operation at a time per queue
/// thread, ahead of `executing`; `None` without confidential operations.
fn submission_job(
    exec: &Arc<quil_execution::ExecutionEngineManager>,
    application: &[u8],
    canonical: &[u8],
    executing: quil_execution::manager::ExecutingFrame,
) -> Option<(usize, [u8; 32], AdmissionJob)> {
    let application = application[..application.len().min(32)].to_vec();
    let operations = quil_execution::ExecutionEngineManager::confidential_operation_count(
        &application,
        canonical,
    );
    if operations == 0 {
        return None;
    }
    let digest = digest(canonical);
    let pair = vec![(application, canonical.to_vec())];
    let exec = exec.clone();
    let job: AdmissionJob = Arc::new(move || {
        exec.preverify_bundles_paced(
            &pair,
            &quil_execution::manager::PreverifyPacing {
                parallelism: Some(1),
                background: !verifying_for_frame(),
                executing,
                ..Default::default()
            },
        )
    });
    Some((operations, digest, job))
}

/// Queue the verification of a canonical submission's confidential proofs on
/// `exec`'s worker, one operation at a time per queue thread (one fewer
/// thread than the worker's slots, [`use_worker_slots`]), so the worker
/// keeps a slot for the frames it materializes. Submissions without confidential
/// operations are not queued. True when it is queued or verifying now.
pub fn offer_submission(
    queue: &Arc<AdmissionQueue>,
    exec: &Arc<quil_execution::ExecutionEngineManager>,
    application: &[u8],
    canonical: &[u8],
    front: bool,
) -> bool {
    let later = quil_execution::manager::ExecutingFrame::Later;
    let Some((operations, digest, job)) = submission_job(exec, application, canonical, later)
    else {
        return false;
    };
    queue.offer(digest, canonical.len(), operations, job, front) || queue.pending(&digest)
}

/// [`offer_submission`] for a finalized app-shard frame anchored at GLOBAL
/// frame `anchor` (`None`: without an anchor) that waits on it, verified
/// as that frame executes it ([`AdmissionQueue::offer_for_frame`]): what
/// execution there admits is verified, whatever GLOBAL frame this node saw
/// since, and what it refuses before the proof is not.
pub fn offer_frame_submission(
    queue: &Arc<AdmissionQueue>,
    exec: &Arc<quil_execution::ExecutionEngineManager>,
    application: &[u8],
    canonical: &[u8],
    anchor: Option<u64>,
) -> bool {
    let executing = quil_execution::manager::ExecutingFrame::App(anchor);
    let Some((operations, digest, job)) = submission_job(exec, application, canonical, executing)
    else {
        return false;
    };
    queue.offer_for_frame(digest, canonical.len(), operations, job) || queue.pending(&digest)
}

/// What became of a confidential submission when it reached this node, for
/// the line of a frame that later waits on its proofs ([`note_arrival`]).
/// Ordered by how far it got: across this node's shards the furthest counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArrivalVerdict {
    /// None of this node's shards is the one that verifies it on arrival.
    NotDesignated,
    /// Its designated shard's collector did not take it as new.
    NotCollected,
    /// Nothing left to verify, or it failed dispatch's checks first.
    Skipped,
    /// Admitted under the budget, but the queue did not take it.
    NotQueued,
    /// Past the arrival budget ([`ARRIVAL_WINDOW`]).
    OverBudget,
    /// Queued, or already verifying, on arrival.
    Queued,
}

impl ArrivalVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotDesignated => "not designated",
            Self::NotCollected => "not collected",
            Self::Skipped => "skipped",
            Self::NotQueued => "not queued",
            Self::OverBudget => "over budget",
            Self::Queued => "queued",
        }
    }
}

/// When a submission first reached this node, and the furthest it got.
pub type Arrival = (Instant, ArrivalVerdict);

/// Submissions whose arrival this node remembers ([`note_arrival`]); past it
/// the oldest is forgotten.
pub const ARRIVAL_ENTRIES: usize = 4096;

/// Bundles one line describes ([`describe_arrivals`]); the rest are counted.
pub const DESCRIBED_BUNDLES: usize = 4;

/// When each confidential submission first reached this node and the
/// furthest it got on arrival, bounded to its newest entries.
pub struct ArrivalLog {
    entries: HashMap<[u8; 32], Arrival>,
    order: VecDeque<[u8; 32]>,
    max: usize,
}

impl ArrivalLog {
    pub fn new(max: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            max: max.max(1),
        }
    }

    /// Record an arrival of `digest` at `now`: the first arrival's time is
    /// kept, and the furthest verdict.
    pub fn note(&mut self, digest: [u8; 32], verdict: ArrivalVerdict, now: Instant) {
        if let Some((_, kept)) = self.entries.get_mut(&digest) {
            *kept = (*kept).max(verdict);
            return;
        }
        if self.order.len() >= self.max {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(digest);
        self.entries.insert(digest, (now, verdict));
    }

    pub fn get(&self, digest: &[u8; 32]) -> Option<Arrival> {
        self.entries.get(digest).copied()
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

fn arrival_log() -> &'static Mutex<ArrivalLog> {
    static LOG: std::sync::OnceLock<Mutex<ArrivalLog>> = std::sync::OnceLock::new();
    LOG.get_or_init(|| Mutex::new(ArrivalLog::new(ARRIVAL_ENTRIES)))
}

/// Remember that the submission `digest` reached one of this node's shards
/// at `now`, and what became of it there.
pub fn note_arrival(digest: [u8; 32], verdict: ArrivalVerdict, now: Instant) {
    arrival_log()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .note(digest, verdict, now);
}

/// When the submission `digest` first reached this node, and the furthest it
/// got on arrival; `None` if it never arrived here (or was forgotten).
pub fn arrival(digest: &[u8; 32]) -> Option<Arrival> {
    arrival_log()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(digest)
}

/// One line's account of the bundles a frame waits on: for each of the
/// first [`DESCRIBED_BUNDLES`], its digest's first four bytes, how long
/// before `now` it first reached this node and what became of it then
/// (`9ac09df9 seen 312 s ago (not designated)`), or that it never arrived
/// here (`9ac09df9 not seen arriving`); then `+N more`.
pub fn describe_arrivals(bundles: &[([u8; 32], Option<Arrival>)], now: Instant) -> String {
    let mut parts: Vec<String> = bundles
        .iter()
        .take(DESCRIBED_BUNDLES)
        .map(|(digest, seen)| {
            let short: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
            match seen {
                Some((at, verdict)) => format!(
                    "{short} seen {} s ago ({})",
                    now.saturating_duration_since(*at).as_secs(),
                    verdict.as_str()
                ),
                None => format!("{short} not seen arriving"),
            }
        })
        .collect();
    if bundles.len() > DESCRIBED_BUNDLES {
        parts.push(format!("+{} more", bundles.len() - DESCRIBED_BUNDLES));
    }
    parts.join("; ")
}

/// [`describe_arrivals`] of the submissions `digests` as this node saw them
/// arrive ([`arrival`]): the `bundles` of a frame waiting on their proofs.
pub fn describe_waiting(digests: &[[u8; 32]], now: Instant) -> String {
    let bundles: Vec<_> = digests
        .iter()
        .map(|digest| (*digest, arrival(digest)))
        .collect();
    describe_arrivals(&bundles, now)
}

/// Queue an arriving canonical submission's verification
/// ([`offer_submission`], at the back) under the [`ARRIVAL_WINDOW`] budget.
/// `sizes`: the bytes of each of its confidential operations still to
/// verify (`ExecutionEngineManager::arrival_operations`), charged at their
/// estimated verification time. Returns what became of it.
pub fn offer_arrival(
    queue: &Arc<AdmissionQueue>,
    exec: &Arc<quil_execution::ExecutionEngineManager>,
    application: &[u8],
    canonical: &[u8],
    sizes: &[usize],
    now: Instant,
) -> ArrivalVerdict {
    if sizes.is_empty() {
        queue.note_arrival_skipped();
        return ArrivalVerdict::Skipped;
    }
    if queue.pending(&digest(canonical)) {
        return ArrivalVerdict::Queued;
    }
    let cost: f64 = sizes
        .iter()
        .map(|bytes| quil_execution::ExecutionEngineManager::estimated_verify_secs(*bytes))
        .sum();
    if !queue.admit_arrival(cost, now) {
        return ArrivalVerdict::OverBudget;
    }
    if offer_submission(queue, exec, application, canonical, false) {
        return ArrivalVerdict::Queued;
    }
    queue.refund_arrival(cost);
    ArrivalVerdict::NotQueued
}

/// [`offer_submission`] as a vote-time warm-up of a proposal for `frame` of
/// `shard` anchored at GLOBAL frame `anchor`
/// ([`AdmissionQueue::offer_warmup`]), verified as that proposal executes
/// it once finalized.
pub fn offer_warmup_submission(
    queue: &Arc<AdmissionQueue>,
    exec: &Arc<quil_execution::ExecutionEngineManager>,
    application: &[u8],
    canonical: &[u8],
    shard: &[u8],
    frame: u64,
    anchor: Option<u64>,
) -> bool {
    let executing = quil_execution::manager::ExecutingFrame::App(anchor);
    let Some((operations, digest, job)) = submission_job(exec, application, canonical, executing)
    else {
        return false;
    };
    queue.offer_warmup(digest, canonical.len(), operations, job, shard, frame)
        || queue.pending(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn job(runs: &Arc<AtomicUsize>, counts: PreverifyCounts) -> AdmissionJob {
        let runs = runs.clone();
        Arc::new(move || {
            runs.fetch_add(1, Ordering::SeqCst);
            counts
        })
    }

    fn verified() -> PreverifyCounts {
        PreverifyCounts {
            operations: 1,
            verified: 1,
            ..Default::default()
        }
    }

    #[test]
    fn a_submission_is_verified_once_and_pending_until_then() {
        let queue = AdmissionQueue::new(8, 1 << 20, false);
        let runs = Arc::new(AtomicUsize::new(0));
        assert!(queue.offer([1; 32], 10, 1, job(&runs, verified()), false));
        assert!(
            !queue.offer([1; 32], 10, 1, job(&runs, verified()), false),
            "a second offer is not queued again"
        );
        assert!(queue.pending(&[1; 32]));
        assert!(queue.run_one());
        assert!(!queue.pending(&[1; 32]));
        assert!(!queue.run_one());
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(queue.stats().counts.verified, 1);
    }

    #[test]
    fn the_admission_queue_drops_its_oldest_past_its_bounds_and_frames_go_first() {
        let queue = AdmissionQueue::new(2, 100, false);
        let runs = Arc::new(AtomicUsize::new(0));
        assert!(queue.offer([1; 32], 10, 1, job(&runs, verified()), false));
        assert!(queue.offer([2; 32], 10, 1, job(&runs, verified()), false));
        // Past the count bound the oldest goes.
        assert!(queue.offer([3; 32], 10, 1, job(&runs, verified()), false));
        assert!(!queue.pending(&[1; 32]));
        assert_eq!(queue.stats().dropped, 1);
        // Past the byte bound too; one larger than the bound is refused.
        assert!(!queue.offer([4; 32], 101, 1, job(&runs, verified()), false));
        assert!(queue.offer([5; 32], 85, 1, job(&runs, verified()), false));
        assert!(!queue.pending(&[2; 32]));
        // A frame's submission goes first, past the bounds dropping the
        // oldest arrival ([3]); a queued one a frame now waits on moves up
        // behind the frames already waiting.
        assert!(queue.offer([6; 32], 1, 1, job(&runs, verified()), true));
        assert!(!queue.pending(&[3; 32]));
        assert!(!queue.offer([5; 32], 85, 1, job(&runs, verified()), true));
        let order = |queue: &AdmissionQueue| -> Vec<[u8; 32]> {
            queue
                .state
                .lock()
                .unwrap()
                .queue
                .iter()
                .map(|item| item.digest)
                .collect()
        };
        assert_eq!(order(&queue), vec![[6; 32], [5; 32]]);
        assert_eq!(queue.queued_ahead(&[5; 32]), Some(1));
        // Full of submissions frames wait on, the queue refuses an arrival
        // (it verifies when a proposal or frame needs it) and takes it
        // again once one of them verified.
        assert!(!queue.offer([1; 32], 10, 1, job(&runs, verified()), false));
        assert!(queue.run_one());
        assert!(queue.offer([1; 32], 10, 1, job(&runs, verified()), false));
        assert_eq!(order(&queue), vec![[5; 32], [1; 32]]);
        while queue.run_one() {}
        assert!(!queue.pending(&[1; 32]));
        assert_eq!(runs.load(Ordering::SeqCst), 3, "[6], [5] and [1]");
    }

    /// The queue verifies one fewer submission at once than the proof
    /// worker admits, at least one, so a slot stays free for inline
    /// verifications; its threads verify concurrently.
    #[test]
    fn the_admission_queue_verifies_as_many_at_once_as_the_worker_spares() {
        assert_eq!(background_threads(None), 1);
        assert_eq!(background_threads(Some(1)), 1);
        assert_eq!(background_threads(Some(2)), 1);
        assert_eq!(background_threads(Some(3)), 2);
        assert_eq!(background_threads(Some(1000)), MAX_THREADS);
        let queue = AdmissionQueue::new(8, 1 << 20, true);
        queue.set_threads(background_threads(Some(3)));
        let started = Arc::new(AtomicUsize::new(0));
        let overlapped = Arc::new(AtomicUsize::new(0));
        let job = || -> AdmissionJob {
            let started = started.clone();
            let overlapped = overlapped.clone();
            Arc::new(move || {
                started.fetch_add(1, Ordering::SeqCst);
                let deadline = Instant::now() + Duration::from_secs(10);
                while started.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                if started.load(Ordering::SeqCst) >= 2 {
                    overlapped.fetch_add(1, Ordering::SeqCst);
                }
                verified()
            })
        };
        assert!(queue.offer([1; 32], 10, 1, job(), false));
        assert!(queue.offer([2; 32], 10, 1, job(), false));
        let deadline = Instant::now() + Duration::from_secs(30);
        while (queue.pending(&[1; 32]) || queue.pending(&[2; 32])) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            overlapped.load(Ordering::SeqCst),
            2,
            "with three worker slots the queue verified one submission at a time"
        );
        assert_eq!(queue.state.lock().unwrap().threads, 2);
    }

    /// A verification that panics counts as one failed in the worker: the
    /// submission is retried, then released, and the queue, background
    /// thread included, goes on verifying the rest.
    #[test]
    fn a_panicking_verification_counts_as_failed_and_the_queue_goes_on() {
        let runs = Arc::new(AtomicUsize::new(0));
        let panicking: AdmissionJob = Arc::new(|| panic!("verifier fault (test)"));
        let queue = AdmissionQueue::new(8, 1 << 20, false);
        assert!(queue.offer([1; 32], 10, 1, panicking.clone(), true));
        assert!(queue.offer([2; 32], 10, 1, job(&runs, verified()), false));
        while queue.run_one() {}
        assert!(queue.released(&[1; 32]) && !queue.pending(&[1; 32]));
        assert_eq!(queue.stats().counts.unavailable, MAX_FAILURES as usize);
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        let queue = AdmissionQueue::new(8, 1 << 20, true);
        assert!(queue.offer([3; 32], 10, 1, panicking, false));
        assert!(queue.offer([4; 32], 10, 1, job(&runs, verified()), false));
        let deadline = Instant::now() + Duration::from_secs(10);
        while queue.pending(&[4; 32]) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!queue.pending(&[4; 32]), "the background thread stopped");
        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_busy_verification_is_retried_a_bounded_number_of_times() {
        let queue = AdmissionQueue::new(8, 1 << 20, false);
        let runs = Arc::new(AtomicUsize::new(0));
        let busy = PreverifyCounts {
            operations: 1,
            busy: 1,
            ..Default::default()
        };
        assert!(queue.offer([7; 32], 10, 1, job(&runs, busy), false));
        while queue.run_one() {}
        // Retried until the bound, then left to the frame that needs it.
        assert_eq!(runs.load(Ordering::SeqCst), MAX_ATTEMPTS as usize);
        assert!(!queue.pending(&[7; 32]));
        assert_eq!(queue.stats().requeued, MAX_ATTEMPTS as usize - 1);
    }

    /// A verification that fails in the worker is retried after the rest of
    /// the queue until it failed `MAX_FAILURES` times; then the submission
    /// is released: not queued again, and `released` tells proposals to
    /// leave it out. A later success forgets earlier failures.
    #[test]
    fn a_failing_verification_is_retried_then_released() {
        let queue = AdmissionQueue::new(8, 1 << 20, false);
        let runs = Arc::new(AtomicUsize::new(0));
        let failed = PreverifyCounts {
            operations: 1,
            unavailable: 1,
            ..Default::default()
        };
        assert!(queue.offer([8; 32], 10, 1, job(&runs, failed), false));
        assert!(queue.offer([2; 32], 10, 1, job(&runs, verified()), false));
        // The failed one goes behind the other, then is retried.
        assert!(queue.run_one());
        assert!(queue.pending(&[8; 32]) && !queue.released(&[8; 32]));
        while queue.run_one() {}
        assert_eq!(runs.load(Ordering::SeqCst), MAX_FAILURES as usize + 1);
        assert!(queue.released(&[8; 32]));
        assert!(!queue.pending(&[8; 32]));
        assert_eq!(queue.stats().released, 1);
        assert!(
            !queue.offer([8; 32], 10, 1, job(&runs, verified()), true),
            "a released submission is not queued again"
        );
        // One that fails once and then verifies is not released.
        let flaky = Arc::new(AtomicUsize::new(0));
        let flaky_job: AdmissionJob = {
            let flaky = flaky.clone();
            Arc::new(move || {
                if flaky.fetch_add(1, Ordering::SeqCst) == 0 {
                    failed
                } else {
                    verified()
                }
            })
        };
        assert!(queue.offer([3; 32], 10, 1, flaky_job, false));
        while queue.run_one() {}
        assert_eq!(flaky.load(Ordering::SeqCst), 2);
        assert!(!queue.released(&[3; 32]) && !queue.pending(&[3; 32]));
    }

    /// Failures are remembered for a bounded number of submissions: past
    /// the bound the oldest is forgotten and may be verified again.
    #[test]
    fn remembered_failures_are_bounded() {
        let queue = AdmissionQueue::build(8, 1 << 20, 2, MAX_WARMUPS, WARMUP_TTL, false);
        let runs = Arc::new(AtomicUsize::new(0));
        let failed = PreverifyCounts {
            operations: 1,
            unavailable: 1,
            ..Default::default()
        };
        for digest in [[1u8; 32], [2; 32]] {
            assert!(queue.offer(digest, 10, 1, job(&runs, failed), false));
            while queue.run_one() {}
            assert!(queue.released(&digest));
        }
        assert!(queue.offer([3; 32], 10, 1, job(&runs, failed), false));
        assert!(queue.run_one());
        assert!(!queue.released(&[1; 32]), "the oldest is forgotten");
        assert!(queue.released(&[2; 32]));
        assert!(queue.offer([1; 32], 10, 1, job(&runs, verified()), false));
    }

    #[test]
    fn the_background_thread_verifies_what_is_offered() {
        let queue = AdmissionQueue::new(8, 1 << 20, true);
        let runs = Arc::new(AtomicUsize::new(0));
        assert!(queue.offer([9; 32], 10, 1, job(&runs, verified()), false));
        let deadline = Instant::now() + Duration::from_secs(10);
        while queue.pending(&[9; 32]) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!queue.pending(&[9; 32]));
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    /// Arrivals take at most the queue's threads times the window of
    /// estimated verification time, refilled as time passes, one arrival
    /// past the last credit at most; refused ones are counted, and a refund
    /// gives credit back.
    #[test]
    fn arrivals_are_admitted_within_their_budget_and_refilled_over_time() {
        let queue = AdmissionQueue::new(8, 1 << 20, false);
        let start = Instant::now();
        let window = ARRIVAL_WINDOW.as_secs_f64();
        // One thread: the window's seconds, then one more past the last credit.
        let mut admitted = 0;
        while queue.admit_arrival(100.0, start) {
            admitted += 1;
            assert!(admitted < 1000, "the budget never ran out");
        }
        assert_eq!(admitted, (window / 100.0).ceil() as usize);
        assert_eq!(queue.stats().arrival_over_budget, 1);
        // Refilled at one second per thread per second: one second's credit
        // admits one more, which overdraws it.
        assert!(queue.admit_arrival(100.0, start + Duration::from_secs(1)));
        assert!(!queue.admit_arrival(1.0, start + Duration::from_secs(1)));
        assert!(queue.admit_arrival(100.0, start + Duration::from_secs(200)));
        assert!(!queue.admit_arrival(100.0, start + Duration::from_secs(200)));
        // A refund gives the credit back.
        queue.refund_arrival(150.0);
        assert!(queue.admit_arrival(100.0, start + Duration::from_secs(200)));
        // Never more than one window ahead, however long it was idle.
        let later = start + Duration::from_secs(100_000);
        let mut admitted = 0;
        while queue.admit_arrival(100.0, later) {
            admitted += 1;
        }
        assert_eq!(admitted, (window / 100.0).ceil() as usize);
        // More threads, more budget.
        let queue = AdmissionQueue::new(8, 1 << 20, false);
        queue.set_threads(3);
        let mut admitted = 0;
        while queue.admit_arrival(100.0, start) {
            admitted += 1;
        }
        assert_eq!(admitted, (3.0 * window / 100.0).ceil() as usize);
        // A non-finite estimate takes the whole budget.
        let queue = AdmissionQueue::new(8, 1 << 20, false);
        assert!(queue.admit_arrival(f64::INFINITY, start));
        assert!(!queue.admit_arrival(1.0, start));
    }

    fn busy() -> PreverifyCounts {
        PreverifyCounts {
            operations: 1,
            busy: 1,
            ..Default::default()
        }
    }

    fn order(queue: &AdmissionQueue) -> Vec<[u8; 32]> {
        queue
            .state
            .lock()
            .unwrap()
            .queue
            .iter()
            .map(|item| item.digest)
            .collect()
    }

    fn warm_queue(max_bundles: usize, max_bytes: usize, max_warmups: usize) -> Arc<AdmissionQueue> {
        AdmissionQueue::build(
            max_bundles,
            max_bytes,
            FAILURE_ENTRIES,
            max_warmups,
            WARMUP_TTL,
            false,
        )
    }

    /// Warm-ups queue behind the submissions frames wait on and ahead of
    /// arrivals, at most `max_warmups` of them: past it the oldest goes, and
    /// the queue takes warm-ups again once one verified.
    #[test]
    fn warm_ups_are_bounded_and_queue_between_frames_and_arrivals() {
        let queue = warm_queue(16, 1 << 20, 2);
        let runs = Arc::new(AtomicUsize::new(0));
        assert!(queue.offer([0xa1; 32], 10, 1, job(&runs, verified()), false));
        for n in 1..=3u8 {
            assert!(queue.offer_warmup([n; 32], 10, 1, job(&runs, verified()), b"shard", 5));
        }
        assert!(
            !queue.pending(&[1; 32]),
            "past the bound the oldest warm-up goes"
        );
        assert_eq!(queue.stats().warmups_dropped, 1);
        assert!(queue.offer([0xf1; 32], 10, 1, job(&runs, verified()), true));
        assert_eq!(
            order(&queue),
            vec![[0xf1; 32], [2; 32], [3; 32], [0xa1; 32]],
            "frames first, then warm-ups, then arrivals"
        );
        // An arrival offered as a warm-up moves up only within the bound;
        // a frame waiting on a warm-up takes it into the frames' lane.
        assert!(!queue.offer_warmup([0xa1; 32], 10, 1, job(&runs, verified()), b"shard", 5));
        assert_eq!(queue.queued_ahead(&[0xa1; 32]), Some(3));
        assert!(!queue.offer([3; 32], 10, 1, job(&runs, verified()), true));
        assert_eq!(
            order(&queue),
            vec![[0xf1; 32], [3; 32], [2; 32], [0xa1; 32]]
        );
        assert!(queue.run_one() && queue.run_one());
        assert!(!queue.offer_warmup([0xa1; 32], 10, 1, job(&runs, verified()), b"shard", 5));
        assert_eq!(order(&queue), vec![[2; 32], [0xa1; 32]]);
        while queue.run_one() {}
        assert!(queue.offer_warmup([4; 32], 10, 1, job(&runs, verified()), b"shard", 6));
        assert!(queue.run_one());
        assert_eq!(runs.load(Ordering::SeqCst), 5);
    }

    /// Past the count or byte bound arrivals go first, then the oldest
    /// warm-up (for a frame or a newer warm-up), never a submission a frame
    /// waits on; an arrival never displaces a warm-up.
    #[test]
    fn the_bounds_drop_arrivals_then_warm_ups_never_frames() {
        let queue = warm_queue(3, 1 << 20, 8);
        let runs = Arc::new(AtomicUsize::new(0));
        let ok = || job(&runs, verified());
        assert!(queue.offer_warmup([1; 32], 10, 1, ok(), b"shard", 5));
        assert!(queue.offer([0xa1; 32], 10, 1, ok(), false));
        assert!(queue.offer([0xa2; 32], 10, 1, ok(), false));
        assert!(queue.offer_warmup([2; 32], 10, 1, ok(), b"shard", 5));
        assert_eq!(order(&queue), vec![[1; 32], [2; 32], [0xa2; 32]]);
        assert!(queue.offer([0xf1; 32], 10, 1, ok(), true));
        assert_eq!(order(&queue), vec![[0xf1; 32], [1; 32], [2; 32]]);
        assert!(
            !queue.offer([0xa3; 32], 10, 1, ok(), false),
            "an arrival displaced a warm-up"
        );
        assert!(queue.offer([0xf2; 32], 10, 1, ok(), true));
        assert!(queue.offer([0xf3; 32], 10, 1, ok(), true));
        assert_eq!(order(&queue), vec![[0xf1; 32], [0xf2; 32], [0xf3; 32]]);
        assert!(
            !queue.offer_warmup([3; 32], 10, 1, ok(), b"shard", 5),
            "a warm-up displaced a submission a frame waits on"
        );
        assert!(queue.offer([0xf4; 32], 10, 1, ok(), true));
        assert_eq!(queue.stats().warmups_dropped, 2);
        while queue.run_one() {}
        assert!(queue.offer_warmup([3; 32], 10, 1, ok(), b"shard", 5));
        // The byte bound too: a frame's submission takes a warm-up's bytes.
        let queue = warm_queue(8, 100, 8);
        assert!(queue.offer_warmup([1; 32], 60, 1, ok(), b"shard", 5));
        assert!(queue.offer([0xf1; 32], 60, 1, ok(), true));
        assert!(!queue.pending(&[1; 32]) && queue.pending(&[0xf1; 32]));
        assert!(!queue.offer_warmup([2; 32], 60, 1, ok(), b"shard", 5));
        assert!(queue.run_one());
        assert!(queue.offer_warmup([2; 32], 60, 1, ok(), b"shard", 5));
    }

    /// A shard that materialized a frame needs no warm-up of it or earlier
    /// frames: those queued are dropped and later offers refused, except one
    /// the frame waits on; other shards' and later frames' warm-ups stay.
    #[test]
    fn warm_ups_end_when_their_shard_materializes_their_frame() {
        let queue = warm_queue(16, 1 << 20, 8);
        let runs = Arc::new(AtomicUsize::new(0));
        let ok = || job(&runs, verified());
        assert!(queue.offer_warmup([1; 32], 10, 1, ok(), b"a", 5));
        assert!(queue.offer_warmup([2; 32], 10, 1, ok(), b"a", 5));
        assert!(queue.offer_warmup([3; 32], 10, 1, ok(), b"a", 6));
        assert!(queue.offer_warmup([4; 32], 10, 1, ok(), b"b", 5));
        // Frame 5 of shard a finalized carrying [2]: it asks first.
        assert!(!queue.offer([2; 32], 10, 1, ok(), true));
        queue.end_warmups(b"a", 5);
        assert_eq!(order(&queue), vec![[2; 32], [3; 32], [4; 32]]);
        assert!(
            !queue.offer_warmup([5; 32], 10, 1, ok(), b"a", 5),
            "a warm-up of a materialized frame was queued"
        );
        // A queued warm-up offered again by a newer proposal takes its frame.
        assert!(queue.offer_warmup([6; 32], 10, 1, ok(), b"a", 7));
        assert!(!queue.offer_warmup([3; 32], 10, 1, ok(), b"a", 8));
        queue.end_warmups(b"a", 7);
        assert_eq!(order(&queue), vec![[2; 32], [3; 32], [4; 32]]);
        while queue.run_one() {}
        assert_eq!(runs.load(Ordering::SeqCst), 3);
    }

    /// A warm-up still queued after its time to live is dropped; offered
    /// again (a newer proposal) it is queued afresh.
    #[test]
    fn a_warm_up_past_its_time_to_live_is_dropped() {
        let ttl = Duration::from_secs(1);
        let queue = AdmissionQueue::build(16, 1 << 20, FAILURE_ENTRIES, 8, ttl, false);
        let runs = Arc::new(AtomicUsize::new(0));
        assert!(queue.offer_warmup([1; 32], 10, 1, job(&runs, verified()), b"a", 5));
        assert!(queue.pending(&[1; 32]));
        std::thread::sleep(ttl + Duration::from_millis(200));
        assert!(!queue.run_one(), "an expired warm-up was verified");
        assert!(!queue.pending(&[1; 32]));
        assert_eq!(queue.stats().warmups_dropped, 1);
        assert!(queue.offer_warmup([1; 32], 10, 1, job(&runs, verified()), b"a", 5));
        assert!(queue.run_one());
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    /// A warm-up that finds the worker busy is retried a bounded number of
    /// times, like an arrival, while a submission a frame waits on is
    /// retried first until a slot frees; only the latter verifies as a
    /// frame's, taking any node-wide worker slot.
    #[test]
    fn a_busy_warm_up_is_retried_a_bounded_number_of_times_and_runs_as_background() {
        let queue = warm_queue(16, 1 << 20, 8);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recording = |digest: u8, counts: PreverifyCounts| -> AdmissionJob {
            let seen = seen.clone();
            Arc::new(move || {
                seen.lock().unwrap().push((digest, verifying_for_frame()));
                counts
            })
        };
        assert!(queue.offer_warmup([1; 32], 10, 1, recording(1, busy()), b"a", 5));
        assert!(queue.offer([0xa1; 32], 10, 1, recording(0xa1, verified()), false));
        while queue.run_one() {}
        assert!(!queue.pending(&[1; 32]));
        let seen_warm: Vec<_> = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(d, _)| *d == 1)
            .copied()
            .collect();
        assert_eq!(seen_warm, vec![(1, false); MAX_ATTEMPTS as usize]);
        assert!(!verifying_for_frame());
        seen.lock().unwrap().clear();
        let left = Arc::new(AtomicUsize::new(MAX_ATTEMPTS as usize + 2));
        let frame: AdmissionJob = {
            let (seen, left) = (seen.clone(), left.clone());
            Arc::new(move || {
                seen.lock().unwrap().push((0xf1, verifying_for_frame()));
                if left.fetch_sub(1, Ordering::SeqCst) > 1 {
                    busy()
                } else {
                    verified()
                }
            })
        };
        assert!(queue.offer_warmup([0xf1; 32], 10, 1, frame, b"a", 6));
        // The frame of the warm-up finalized and waits on it.
        assert!(!queue.offer([0xf1; 32], 10, 1, recording(0, verified()), true));
        while queue.run_one() {}
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(0xf1, true); MAX_ATTEMPTS as usize + 2]
        );
        assert!(!queue.pending(&[0xf1; 32]));
    }

    /// A submission's arrival keeps when it first reached this node and the
    /// furthest it got on any of its shards; the log forgets its oldest
    /// entries past its bound.
    #[test]
    fn the_arrival_log_keeps_the_first_arrival_and_the_furthest_verdict() {
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(5);
        let mut log = ArrivalLog::new(3);
        log.note([1; 32], ArrivalVerdict::NotDesignated, t0);
        log.note([1; 32], ArrivalVerdict::Queued, later);
        log.note([1; 32], ArrivalVerdict::NotCollected, later);
        let (at, verdict) = log.get(&[1; 32]).expect("the arrival is remembered");
        assert_eq!(at, t0, "the first arrival's time is kept");
        assert_eq!(
            verdict,
            ArrivalVerdict::Queued,
            "the furthest verdict is kept"
        );
        for tag in 2..=4 {
            log.note([tag; 32], ArrivalVerdict::OverBudget, later);
        }
        assert_eq!(log.len(), 3, "the arrival log is bounded");
        assert!(log.get(&[1; 32]).is_none(), "the oldest entry went first");
        assert!(log.get(&[4; 32]).is_some());
    }

    /// The `bundles` of a frame waiting on proofs name, for each of the first
    /// four, when it first reached this node and what became of it, or that
    /// it never arrived here; the rest are counted.
    #[test]
    fn a_waiting_frame_names_when_its_bundles_arrived_and_their_verdicts() {
        let now = Instant::now();
        note_arrival(
            [0x9a; 32],
            ArrivalVerdict::NotDesignated,
            now - Duration::from_secs(312),
        );
        note_arrival([0x9b; 32], ArrivalVerdict::OverBudget, now);
        let mut digests = vec![[0x9a; 32], [0xee; 32], [0x9b; 32]];
        assert_eq!(
            describe_waiting(&digests, now),
            "9a9a9a9a seen 312 s ago (not designated); eeeeeeee not seen arriving; \
             9b9b9b9b seen 0 s ago (over budget)",
            "the bundles line names each arrival"
        );
        digests.extend([[0xe1; 32], [0xe2; 32], [0xe3; 32]]);
        let line = describe_waiting(&digests, now);
        assert!(
            line.ends_with("e1e1e1e1 not seen arriving; +2 more"),
            "the bundles line is bounded: {line}"
        );
        assert_eq!(
            line.matches(" s ago (").count(),
            2,
            "two of the bundles were seen: {line}"
        );
    }
}
