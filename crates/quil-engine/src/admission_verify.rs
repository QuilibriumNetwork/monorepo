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
//! Submissions a frame waits on ([`AdmissionQueue::offer`] with `front`) are
//! verified first, in the order frames asked for them; the rest oldest
//! first. Every member receives a submission at about the same time and
//! verifies in the same order, so the members finish it at about the same
//! time and a proposal carrying it right after its leader verified it finds
//! the others ready. The queue verifies up to [`background_threads`] at once:
//! one fewer than the proof worker admits, so a slot stays free for the
//! frames and proposals that verify inline. One at a time verified about 16
//! batch shields an hour (240 s each) while more arrived, and frames waiting
//! on them failed (mainnet, 2026-10-31); two at once on a 16-core node took
//! 4% longer each.
//!
//! Bounds and recovery: a submission no frame waits on is dropped from the
//! queue past its count or byte bound and offered again by the proposal that
//! holds it or the frame that needs it; one whose verification found no
//! worker slot is retried [`MAX_ATTEMPTS`] times per offer. A submission a
//! frame waits on is never dropped for the bounds (frames waiting are bounded
//! by the frames this node holds) and is retried while the worker is busy, at
//! the front: a worker slot frees within one verification's wall timeout. One
//! whose verification failed in the worker (crash, timeout, resource cap,
//! panic) is retried until it failed [`MAX_FAILURES`] times, after which this
//! node's proposals leave it out and it ages out of the pool unless another
//! member's proposal carries it; a frame carrying it then verifies it inline.

use std::collections::{HashSet, VecDeque};
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

struct Item {
    digest: [u8; 32],
    bytes: usize,
    attempts: u8,
    operations: usize,
    job: AdmissionJob,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdmissionStats {
    pub queued: usize,
    pub requeued: usize,
    pub dropped: usize,
    /// Submissions that reached [`MAX_FAILURES`].
    pub released: usize,
    pub counts: PreverifyCounts,
}

#[derive(Default)]
struct State {
    /// Submissions frames wait on first, in the order frames asked for
    /// them, then the rest.
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
    /// Digest → verifications of it that failed in the worker, oldest first.
    failures: std::collections::HashMap<[u8; 32], u8>,
    failure_order: VecDeque<[u8; 32]>,
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

    /// Queue `item` behind the submissions frames already wait on.
    fn queue_wanted(&mut self, item: Item) {
        let at = self.wanted_queued();
        self.queue.insert(at, item);
    }

    fn finish(&mut self, digest: &[u8; 32]) {
        self.pending.remove(digest);
        self.wanted.remove(digest);
    }
}

/// One bounded queue of submissions whose proofs background threads verify:
/// those frames wait on first, then the rest oldest first.
pub struct AdmissionQueue {
    state: Mutex<State>,
    wake: Condvar,
    max_bundles: usize,
    max_bytes: usize,
    failure_entries: usize,
    /// Whether offers start the background threads (tests drive it by hand).
    spawn: bool,
}

impl AdmissionQueue {
    pub fn new(max_bundles: usize, max_bytes: usize, spawn: bool) -> Arc<Self> {
        Self::with_failure_entries(max_bundles, max_bytes, FAILURE_ENTRIES, spawn)
    }

    fn with_failure_entries(
        max_bundles: usize,
        max_bytes: usize,
        failure_entries: usize,
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
            failure_entries,
            spawn,
        })
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
    /// operations, at the back or, for a frame that waits on it (`front`),
    /// behind the submissions frames already wait on. False when it is
    /// already queued or verifying (a queued one a frame now waits on moves
    /// up), when it alone exceeds the byte bound, when it was released
    /// ([`Self::released`]), or when the queue is full of submissions frames
    /// wait on and no frame waits on this one.
    pub fn offer(
        self: &Arc<Self>,
        digest: [u8; 32],
        bytes: usize,
        operations: usize,
        job: AdmissionJob,
        front: bool,
    ) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.failed(&digest) >= MAX_FAILURES {
            return false;
        }
        if bytes > self.max_bytes {
            state.window.dropped += 1;
            return false;
        }
        if state.pending.contains(&digest) {
            if front && state.wanted.insert(digest) {
                // A frame now waits on it: a queued one moves up.
                if let Some(index) = state.queue.iter().position(|item| item.digest == digest) {
                    if let Some(item) = state.queue.remove(index) {
                        state.queue_wanted(item);
                    }
                }
            }
            return false;
        }
        while !state.queue.is_empty()
            && (state.queue.len() >= self.max_bundles || state.bytes + bytes > self.max_bytes)
        {
            let oldest = state.wanted_queued();
            if let Some(dropped) = state.queue.remove(oldest) {
                state.bytes -= dropped.bytes;
                state.pending.remove(&dropped.digest);
                state.window.dropped += 1;
            } else if front {
                // Only submissions frames wait on are queued, bounded by
                // the frames this node holds: admit this one too.
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
        };
        if front {
            state.wanted.insert(digest);
            state.queue_wanted(item);
        } else {
            state.queue.push_back(item);
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
        let item = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let item = state.queue.pop_front()?;
            state.bytes -= item.bytes;
            item
        };
        // A panicking verification counts as one failed in the worker, so
        // the thread keeps verifying the queue frames wait on.
        let counts = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (item.job)()))
            .unwrap_or_else(|_| {
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
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.window.counts.add(counts);
        let wanted = state.wanted.contains(&item.digest);
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
        } else if failures > 0 {
            // Failed in the worker (counted above): try again after the
            // rest of the queue, or after the others frames wait on.
            state.window.requeued += 1;
            state.bytes += item.bytes;
            if wanted {
                state.queue_wanted(item);
            } else {
                state.queue.push_back(item);
            }
        } else if counts.busy > 0 && wanted {
            // Found no worker slot while a frame waits on it: first again.
            state.window.requeued += 1;
            state.bytes += item.bytes;
            state.queue.push_front(item);
        } else if counts.busy > 0 && item.attempts + 1 < MAX_ATTEMPTS {
            // Found no worker slot: try again after the rest of the queue.
            state.window.requeued += 1;
            state.bytes += item.bytes;
            state.queue.push_back(Item {
                attempts: item.attempts + 1,
                ..item
            });
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
            cached = window.counts.cached,
            busy = window.counts.busy,
            failed = window.counts.unavailable,
            requeued = window.requeued,
            dropped = window.dropped,
            released = window.released,
            pending = state.queue.len(),
            frames_waiting = state.wanted_queued(),
            threads = state.threads,
            interval_secs = SUMMARY_INTERVAL.as_secs(),
            "confidential proof admission summary: proofs of arriving submissions verified before a frame \
             carries them, those frames wait on first; dropped ones verify when a proposal or frame needs them"
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
    let application = application[..application.len().min(32)].to_vec();
    let operations = quil_execution::ExecutionEngineManager::confidential_operation_count(
        &application,
        canonical,
    );
    if operations == 0 {
        return false;
    }
    let digest = digest(canonical);
    let pair = vec![(application, canonical.to_vec())];
    let exec = exec.clone();
    let job: AdmissionJob = Arc::new(move || {
        exec.preverify_bundles_paced(
            &pair,
            &quil_execution::manager::PreverifyPacing {
                parallelism: Some(1),
                ..Default::default()
            },
        )
    });
    queue.offer(digest, canonical.len(), operations, job, front) || queue.pending(&digest)
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
        let queue = AdmissionQueue::with_failure_entries(8, 1 << 20, 2, false);
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
}
