//! The background jobs of hash storage proofs (decided 2026-10-26): each
//! seat's snapshot captures and encodes, its parts of the member's epoch
//! proof, and the node's epoch proofs.
//!
//! A job runs in a lane, after the jobs queued in that lane before it: a
//! seat's shard, whose jobs run one at a time as a standalone worker runs its
//! own, or the node's epoch proofs ([`EPOCH_PROOF_LANE`]). Lanes run side by
//! side, bounded by memory and cores: before its heavy work a job reserves
//! what it holds at its peak ([`reserve`]), and reservations are granted in
//! the order asked, each once it fits in the jobs' share of the memory
//! available to the node ([`MEMORY_SHARE_PERCENT`]) and a core is free of
//! them. A node with the memory encodes every seat at once; one without
//! encodes as many as fit, then the next as each finishes. A job alone runs
//! whatever its size.
//!
//! Labelling a leaf is one chain of hashes, a core's work for about an hour
//! per GiB. With one job at a time for the whole node, a node's later seats
//! missed their renewal's grace.

use std::collections::{HashMap, VecDeque};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use quil_types::error::{QuilError, Result};
use tracing::{info, warn};

/// The lane of the node's epoch proofs (`storage_epoch_batch`).
pub const EPOCH_PROOF_LANE: &[u8] = b"epoch proofs";

/// Percent of the memory available to the node the jobs may hold together;
/// the rest is headroom for the node and for the estimates' error.
pub const MEMORY_SHARE_PERCENT: u64 = 75;

/// How often a reservation that does not fit looks at the memory again,
/// besides whenever another one changes.
const RECHECK: Duration = Duration::from_secs(5);

type Job = Box<dyn FnOnce() + Send>;

fn lanes() -> MutexGuard<'static, HashMap<Vec<u8>, VecDeque<Job>>> {
    static LANES: OnceLock<Mutex<HashMap<Vec<u8>, VecDeque<Job>>>> = OnceLock::new();
    LANES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Run `job` in `lane`, after the jobs queued there before it, on a thread
/// the lane keeps while it has jobs. A job that fails or panics is logged;
/// its caller asks again when it next needs it.
pub fn spawn(lane: &[u8], label: &'static str, job: impl FnOnce() -> Result<()> + Send + 'static) {
    let shown = hex::encode(lane);
    let job: Job = Box::new(move || {
        let started = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job))
            .unwrap_or_else(|_| Err(QuilError::Internal("the job panicked".into())));
        match result {
            Ok(()) => info!(
                label,
                lane = %shown,
                seconds = started.elapsed().as_secs_f64(),
                "storage snapshot job done"
            ),
            Err(error) => {
                warn!(label, lane = %shown, %error, "storage snapshot job failed; it is tried again when next needed")
            }
        }
    });
    {
        let mut lanes = lanes();
        if let Some(queued) = lanes.get_mut(lane) {
            queued.push_back(job);
            return;
        }
        lanes.insert(lane.to_vec(), VecDeque::new());
    }
    let owned = lane.to_vec();
    if let Err(error) = std::thread::Builder::new()
        .name("storage-jobs".into())
        .spawn(move || run_lane(owned, job))
    {
        lanes().remove(lane);
        warn!(label, lane = %hex::encode(lane), %error, "storage job thread not started; the lane's jobs are dropped");
    }
}

/// Run `first`, then the lane's queued jobs in order, until none is left.
fn run_lane(lane: Vec<u8>, first: Job) {
    let mut next = Some(first);
    while let Some(job) = next {
        job();
        let mut lanes = lanes();
        next = lanes.get_mut(&lane).and_then(VecDeque::pop_front);
        if next.is_none() {
            lanes.remove(&lane);
        }
    }
}

/// Reserve `bytes` for a job's work: waits, behind the reservations asked
/// for before it, until it fits beside the ones held.
pub fn reserve(bytes: u64) -> Reservation {
    static ADMISSION: OnceLock<Admission> = OnceLock::new();
    ADMISSION
        .get_or_init(|| Admission::new(job_slots(), Box::new(available_memory)))
        .reserve(bytes)
}

/// Jobs that may hold memory at once: one per core, less the master's.
pub fn job_slots() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1).max(1))
}

/// Run `work` on each of `items`, on as many threads as jobs may hold
/// memory at once ([`job_slots`]), each item reserving its own ([`reserve`]):
/// the leaves of one seat side by side. Returns each item's result in order;
/// after a failure, items not started yet are not run.
pub fn for_each_parallel<T: Sync, R: Send>(
    items: &[T],
    work: impl Fn(&T) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let results: Mutex<Vec<Option<Result<R>>>> =
        Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..job_slots().min(items.len()) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= items.len() || failed.load(Ordering::Relaxed) {
                    break;
                }
                let result = work(&items[index]);
                if result.is_err() {
                    failed.store(true, Ordering::Relaxed);
                }
                results.lock().unwrap_or_else(PoisonError::into_inner)[index] = Some(result);
            });
        }
    });
    let mut out = Vec::with_capacity(items.len());
    for result in results.into_inner().unwrap_or_else(PoisonError::into_inner) {
        match result {
            Some(result) => out.push(result?),
            None => {
                return Err(QuilError::ExecutionUnavailable(
                    "a storage job stopped at an earlier failure".into(),
                ))
            }
        }
    }
    Ok(out)
}

/// Bytes of memory available to the node now: the host's, or less within
/// its container's limit, page cache counted available as the host counts
/// it. `None` when the host does not say.
fn available_memory() -> Option<u64> {
    let mut system = sysinfo::System::new();
    system.refresh_memory();
    let host = system.available_memory();
    if host == 0 {
        return None;
    }
    let container = system
        .cgroup_limits()
        .map(|limits| limits.total_memory.saturating_sub(limits.rss));
    Some(container.map_or(host, |container| container.min(host)))
}

/// Memory a job holds while it works, granted by [`reserve`] and given back
/// when dropped.
#[must_use = "the memory is given back when the reservation drops"]
pub struct Reservation {
    admission: &'static Admission,
    bytes: u64,
}

impl Reservation {
    /// Correct the reservation to `bytes` once the work's size is known.
    /// Never waits: a job holding memory does not wait for more.
    pub fn resize(&mut self, bytes: u64) {
        let mut state = self.admission.state();
        state.reserved = state
            .reserved
            .saturating_sub(self.bytes)
            .saturating_add(bytes);
        self.bytes = bytes;
        drop(state);
        self.admission.changed.notify_all();
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.admission.state();
        state.reserved = state.reserved.saturating_sub(self.bytes);
        state.holders = state.holders.saturating_sub(1);
        drop(state);
        self.admission.changed.notify_all();
    }
}

/// Grants the jobs' reservations ([`reserve`]): in the order asked, each
/// once it fits.
pub struct Admission {
    state: Mutex<State>,
    changed: Condvar,
    slots: usize,
    available: Box<dyn Fn() -> Option<u64> + Send + Sync>,
}

#[derive(Default)]
struct State {
    /// Bytes the reservations held come to.
    reserved: u64,
    /// Reservations held.
    holders: usize,
    /// Tickets of the reservations waiting, in the order asked.
    waiting: VecDeque<u64>,
    next_ticket: u64,
    /// Memory available when the last reservation granted to no others was.
    idle_available: Option<u64>,
}

impl Admission {
    /// At most `slots` reservations held at once, sharing the memory
    /// `available` reports (`None` when it cannot tell: one at a time).
    pub fn new(slots: usize, available: Box<dyn Fn() -> Option<u64> + Send + Sync>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            slots: slots.max(1),
            available,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserve `bytes` ([`reserve`]).
    pub fn reserve(&'static self, bytes: u64) -> Reservation {
        let mut state = self.state();
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        state.waiting.push_back(ticket);
        let started = Instant::now();
        let mut waited = false;
        while state.waiting.front() != Some(&ticket) || !self.fits(&mut state, bytes) {
            if !waited {
                waited = true;
                info!(
                    bytes,
                    reserved = state.reserved,
                    jobs = state.holders,
                    ahead = state.waiting.len() - 1,
                    "storage job waits for memory"
                );
            }
            state = self
                .changed
                .wait_timeout(state, RECHECK)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        state.waiting.pop_front();
        state.reserved = state.reserved.saturating_add(bytes);
        state.holders += 1;
        let jobs = state.holders;
        drop(state);
        if waited {
            info!(
                bytes,
                jobs,
                seconds = started.elapsed().as_secs_f64(),
                "storage job has its memory"
            );
        }
        // The next in line may fit beside this one.
        self.changed.notify_all();
        Reservation {
            admission: self,
            bytes,
        }
    }

    /// Whether `bytes` more fit beside the reservations held.
    fn fits(&self, state: &mut State, bytes: u64) -> bool {
        if state.holders == 0 {
            // Alone, a job runs whatever its size. What is available while
            // no job holds anything is what the next ones share.
            state.idle_available = (self.available)();
            return true;
        }
        if state.holders >= self.slots {
            return false;
        }
        let (Some(idle), Some(now)) = (state.idle_available, (self.available)()) else {
            return false;
        };
        // The reservations held are mostly allocated, so what is available
        // now plus them is what the jobs could have: less when the node has
        // grown, and never more than with none held, as one granted a moment
        // ago has allocated nothing yet.
        let could = idle.min(now.saturating_add(state.reserved));
        let share = u128::from(could) * u128::from(MEMORY_SHARE_PERCENT) / 100;
        u128::from(state.reserved) + u128::from(bytes) <= share
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc};

    const GIB: u64 = 1 << 30;
    const SOON: Duration = Duration::from_secs(10);
    const NOT_YET: Duration = Duration::from_millis(300);

    fn admission(slots: usize, available: u64) -> (&'static Admission, Arc<AtomicU64>) {
        let memory = Arc::new(AtomicU64::new(available));
        let probe = memory.clone();
        let admission = Box::leak(Box::new(Admission::new(
            slots,
            Box::new(move || Some(probe.load(Ordering::SeqCst)).filter(|&bytes| bytes > 0)),
        )));
        (admission, memory)
    }

    /// A reservation held on a thread of its own: `granted` hears when it is,
    /// and dropping `release` gives it back.
    struct Held {
        granted: mpsc::Receiver<()>,
        release: mpsc::Sender<()>,
    }

    fn hold(admission: &'static Admission, bytes: u64) -> Held {
        let (granted_tx, granted) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let _reservation = admission.reserve(bytes);
            granted_tx.send(()).unwrap();
            let _ = released.recv();
        });
        Held { granted, release }
    }

    fn granted(held: &Held) -> bool {
        held.granted.recv_timeout(SOON).is_ok()
    }

    fn still_waiting(held: &Held) -> bool {
        held.granted.recv_timeout(NOT_YET).is_err()
    }

    fn waiting(admission: &Admission) -> usize {
        admission.state().waiting.len()
    }

    fn until_waiting(admission: &Admission, count: usize) {
        let deadline = Instant::now() + SOON;
        while waiting(admission) < count {
            assert!(Instant::now() < deadline, "no reservation waits");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn jobs_that_fit_run_together_and_the_next_when_one_finishes() {
        // 40 GiB available: the jobs share 30.
        let (admission, _) = admission(8, 40 * GIB);
        let first = hold(admission, 10 * GIB);
        assert!(granted(&first));
        let second = hold(admission, 10 * GIB);
        assert!(granted(&second));
        let third = hold(admission, 10 * GIB);
        assert!(granted(&third), "30 GiB of 30 fit");
        let fourth = hold(admission, 10 * GIB);
        assert!(still_waiting(&fourth), "40 GiB do not");
        drop(first.release);
        assert!(granted(&fourth), "it runs once one finishes");
    }

    #[test]
    fn a_job_larger_than_the_share_runs_alone() {
        let (admission, _) = admission(8, 8 * GIB);
        let large = hold(admission, 20 * GIB);
        assert!(granted(&large), "alone, it runs");
        let small = hold(admission, GIB);
        assert!(still_waiting(&small), "nothing runs beside it");
        drop(large.release);
        assert!(granted(&small));
    }

    #[test]
    fn a_waiting_reservation_holds_later_ones_back() {
        let (admission, _) = admission(8, 40 * GIB);
        let first = hold(admission, 20 * GIB);
        assert!(granted(&first));
        let large = hold(admission, 20 * GIB);
        until_waiting(admission, 1);
        let small = hold(admission, GIB);
        until_waiting(admission, 2);
        assert!(
            still_waiting(&small),
            "it would fit, but waits its turn behind the larger one"
        );
        drop(first.release);
        assert!(granted(&large));
        assert!(granted(&small), "then it fits beside it");
    }

    #[test]
    fn a_node_that_cannot_tell_its_memory_runs_one_job_at_a_time() {
        let (admission, _) = admission(8, 0);
        let first = hold(admission, GIB);
        assert!(granted(&first));
        let second = hold(admission, GIB);
        assert!(still_waiting(&second));
        drop(first.release);
        assert!(granted(&second));
    }

    #[test]
    fn no_more_jobs_hold_memory_than_there_are_slots() {
        let (admission, _) = admission(2, 1 << 50);
        let first = hold(admission, GIB);
        let second = hold(admission, GIB);
        assert!(granted(&first) && granted(&second));
        let third = hold(admission, GIB);
        assert!(still_waiting(&third));
        drop(second.release);
        assert!(granted(&third));
    }

    #[test]
    fn the_share_shrinks_when_the_node_holds_more_memory() {
        let (admission, memory) = admission(8, 40 * GIB);
        let first = hold(admission, 10 * GIB);
        assert!(granted(&first));
        // The node grew by 20 GiB besides the job: 10 + 10 GiB do not fit in
        // (10 + 10) * 0.75.
        memory.store(10 * GIB, Ordering::SeqCst);
        let second = hold(admission, 10 * GIB);
        assert!(still_waiting(&second));
        memory.store(30 * GIB, Ordering::SeqCst);
        assert!(granted(&second), "it looks again without being told");
    }

    #[test]
    fn a_resized_reservation_counts_at_its_new_size() {
        let (admission, _) = admission(8, 40 * GIB);
        let (resized_tx, resized) = mpsc::channel();
        let (shrink, shrink_rx) = mpsc::channel::<()>();
        let (done, done_rx) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut reservation = admission.reserve(GIB);
            reservation.resize(25 * GIB);
            resized_tx.send(()).unwrap();
            shrink_rx.recv().unwrap();
            reservation.resize(GIB);
            let _ = done_rx.recv();
        });
        resized.recv_timeout(SOON).unwrap();
        let next = hold(admission, 10 * GIB);
        assert!(still_waiting(&next), "35 GiB do not fit in 30");
        shrink.send(()).unwrap();
        assert!(granted(&next));
        drop(done);
    }

    #[test]
    fn a_lane_runs_its_jobs_in_order_beside_the_other_lanes() {
        let (order_tx, order) = mpsc::channel::<&'static str>();
        let (open, gate) = mpsc::channel::<()>();
        let first = order_tx.clone();
        spawn(b"test lane: ordered", "test", move || {
            gate.recv().unwrap();
            first.send("first").unwrap();
            Ok(())
        });
        let second = order_tx.clone();
        spawn(b"test lane: ordered", "test", move || {
            second.send("second").unwrap();
            Ok(())
        });
        let beside = order_tx;
        spawn(b"test lane: beside", "test", move || {
            beside.send("beside").unwrap();
            Ok(())
        });
        assert_eq!(
            order.recv_timeout(SOON),
            Ok("beside"),
            "another lane runs while this one's first job waits"
        );
        open.send(()).unwrap();
        assert_eq!(order.recv_timeout(SOON), Ok("first"));
        assert_eq!(order.recv_timeout(SOON), Ok("second"));
    }

    #[test]
    fn a_job_that_panics_leaves_its_lane_running() {
        let (ran_tx, ran) = mpsc::channel();
        spawn(b"test lane: panics", "test", || panic!("a job panics"));
        spawn(b"test lane: panics", "test", move || {
            ran_tx.send(()).unwrap();
            Ok(())
        });
        assert!(ran.recv_timeout(SOON).is_ok());
    }
}
