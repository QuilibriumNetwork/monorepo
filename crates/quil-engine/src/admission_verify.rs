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
//! One thread verifies, one operation at a time, oldest first: every member
//! receives a submission at about the same time and verifies in the same
//! order, so the members finish it at about the same time and a proposal
//! carrying it right after its leader verified it finds the others ready.
//! Two verifications at once (this queue and a proposal's warm-up) each ran
//! at half speed (devnet, 2026-10-29).
//!
//! Bounds and recovery: a submission dropped from the queue (count or byte
//! bound) is offered again by the proposal that holds it or the frame that
//! needs it; one whose verification found no worker slot is retried
//! [`MAX_ATTEMPTS`] times per offer; one whose verification failed in the
//! worker (crash, timeout, resource cap) is retried until it failed
//! [`MAX_FAILURES`] times, after which this node's proposals leave it out and
//! it ages out of the pool unless another member's proposal carries it.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use quil_execution::manager::PreverifyCounts;
use tracing::{info, warn};

/// Verifies one submission's confidential proofs, filling the verdict cache.
pub type AdmissionJob = Arc<dyn Fn() -> PreverifyCounts + Send + Sync>;

/// Submissions waiting, and bytes of them. Past either bound the oldest is
/// dropped (counted); its proofs are verified when a proposal or frame needs
/// them, as before.
pub const MAX_BUNDLES: usize = 256;
pub const MAX_BYTES: usize = 64 << 20;
/// Attempts per submission whose verification found no worker slot.
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
    queue: VecDeque<Item>,
    /// Digests queued or verifying.
    pending: HashSet<[u8; 32]>,
    bytes: usize,
    started: bool,
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
}

/// One bounded queue of submissions whose proofs a background thread
/// verifies, oldest first, one at a time.
pub struct AdmissionQueue {
    state: Mutex<State>,
    wake: Condvar,
    max_bundles: usize,
    max_bytes: usize,
    failure_entries: usize,
    /// Whether offers start the background thread (tests drive it by hand).
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
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
            max_bundles: max_bundles.max(1),
            max_bytes,
            failure_entries,
            spawn,
        })
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
    /// operations, at the back or, for a frame that waits on it, at the
    /// front. False when it is already queued or verifying, when it alone
    /// exceeds the byte bound, or when it was released ([`Self::released`]).
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
            if front {
                // A frame now waits on it: move a queued one to the front.
                if let Some(index) = state.queue.iter().position(|item| item.digest == digest) {
                    if let Some(item) = state.queue.remove(index) {
                        state.queue.push_front(item);
                    }
                }
            }
            return false;
        }
        while !state.queue.is_empty()
            && (state.queue.len() >= self.max_bundles || state.bytes + bytes > self.max_bytes)
        {
            if let Some(oldest) = state.queue.pop_front() {
                state.bytes -= oldest.bytes;
                state.pending.remove(&oldest.digest);
                state.window.dropped += 1;
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
            state.queue.push_front(item);
        } else {
            state.queue.push_back(item);
        }
        state.pending.insert(digest);
        state.bytes += bytes;
        state.window.queued += 1;
        let start = self.spawn && !state.started;
        state.started |= start;
        drop(state);
        if start {
            let queue = self.clone();
            let spawned = std::thread::Builder::new()
                .name("proof-admission".into())
                .spawn(move || queue.run());
            if spawned.is_err() {
                // Nothing verifies the queue: give its entries back to the
                // proposals and frames that verify them anyway.
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                state.started = false;
                state.queue.clear();
                state.pending.clear();
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

    /// Verify the oldest queued submission. False when none is queued.
    pub fn run_one(&self) -> bool {
        let item = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match state.queue.pop_front() {
                Some(item) => {
                    state.bytes -= item.bytes;
                    item
                }
                None => return false,
            }
        };
        let counts = (item.job)();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.window.counts.add(counts);
        let failures = if counts.unavailable > 0 {
            state.note_failure(item.digest, self.failure_entries)
        } else {
            if counts.busy == 0 {
                state.forget_failures(&item.digest);
            }
            0
        };
        if failures >= MAX_FAILURES {
            state.pending.remove(&item.digest);
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
        } else if failures > 0 || (counts.busy > 0 && item.attempts + 1 < MAX_ATTEMPTS) {
            // Failed in the worker (counted above), or found no worker
            // slot: try again after the rest of the queue.
            state.window.requeued += 1;
            state.bytes += item.bytes;
            state.queue.push_back(Item {
                attempts: item.attempts + u8::from(counts.busy > 0),
                ..item
            });
        } else {
            state.pending.remove(&item.digest);
        }
        Self::summarize(&mut state);
        true
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
            let busy_before = self.stats().counts.busy;
            self.run_one();
            if self.stats().counts.busy > busy_before {
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
            interval_secs = SUMMARY_INTERVAL.as_secs(),
            "confidential proof admission summary: proofs of arriving submissions verified before a frame \
             carries them; dropped ones verify when a proposal or frame needs them"
        );
    }
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
/// `exec`'s worker, one operation at a time so the worker keeps a slot for
/// the frames it materializes. Submissions without confidential operations
/// are not queued. True when it is queued or verifying now.
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
    fn the_queue_drops_its_oldest_past_its_bounds_and_frames_go_first() {
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
        // A frame's submission jumps the queue, and an already queued one is
        // moved to the front.
        assert!(queue.offer([6; 32], 1, 1, job(&runs, verified()), true));
        assert!(!queue.offer([5; 32], 85, 1, job(&runs, verified()), true));
        let order: Vec<[u8; 32]> = queue
            .state
            .lock()
            .unwrap()
            .queue
            .iter()
            .map(|item| item.digest)
            .collect();
        assert_eq!(order, vec![[5; 32], [6; 32]]);
        // A dropped submission is queued again when a proposal or frame
        // offers it, and verified.
        assert!(queue.offer([1; 32], 10, 1, job(&runs, verified()), false));
        while queue.run_one() {}
        assert!(!queue.pending(&[1; 32]));
        assert_eq!(runs.load(Ordering::SeqCst), 2, "[6] and the re-offered [1]");
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
