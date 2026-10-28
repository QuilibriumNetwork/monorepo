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
//!
//! Work done ahead of when it is needed ([`reserve_ahead`]) gives its memory
//! back while work due now waits for memory ([`Reservation::yield_requested`],
//! looked at every few milliseconds of its labelling), and starts again once
//! no work due now has waited or held memory for a while
//! ([`wait_for_due_work`]): a renewal's snapshot waited 40 minutes behind one
//! leaf labelled ahead (2026-10-28).
//!
//! A stopping node stops its jobs ([`shut_down`]) before it exits: they use
//! its stores, which exit tears down under a thread still using them.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
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

/// How long work due now must have neither waited for memory nor held any
/// before work ahead that yielded to it starts again ([`wait_for_due_work`]):
/// a gap between one seat's encode and the next's does not end it.
const DUE_QUIET: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(60)
};

type Job = Box<dyn FnOnce() + Send>;

/// A lane's running job and the jobs queued behind it, by label.
struct Lane {
    running: &'static str,
    queued: VecDeque<(&'static str, Job)>,
}

/// The node's lanes ([`spawn`]), and whether it is stopping ([`shut_down`]).
#[derive(Default)]
struct Jobs {
    lanes: Mutex<HashMap<Vec<u8>, Lane>>,
    /// Notified whenever a lane empties.
    idle: Condvar,
    stopping: AtomicBool,
    /// Whether a job not started for the stop has been logged.
    refused: AtomicBool,
}

fn jobs() -> &'static Jobs {
    static JOBS: OnceLock<Jobs> = OnceLock::new();
    JOBS.get_or_init(Default::default)
}

/// Run `job` in `lane`, after the jobs queued there before it, on a thread
/// the lane keeps while it has jobs. A job that fails or panics is logged;
/// its caller asks again when it next needs it. Once the node is stopping
/// ([`shut_down`]) the job is dropped.
pub fn spawn(lane: &[u8], label: &'static str, job: impl FnOnce() -> Result<()> + Send + 'static) {
    jobs().spawn(lane, label, job)
}

/// Stop the jobs before the process exits: drop the queued ones and any
/// spawned later, and wait up to `grace` for the running ones to end (one
/// working through a seat's leaves stops at the next, [`for_each_parallel`]).
/// Returns the labels of the jobs still running, one per lane.
pub fn shut_down(grace: Duration) -> Vec<&'static str> {
    jobs().shut_down(grace)
}

/// Whether the node is stopping its jobs ([`shut_down`]): long work looks
/// at it to end early.
pub fn stopping() -> bool {
    jobs().stopping()
}

/// Exit the process with `code` at once, skipping the exit handlers and
/// static destructors: RocksDB's, run under a thread still using a store
/// (a storage job, say), abort the process. The stores replay their
/// write-ahead log at the next start. Flush the logs first.
pub fn exit_now(code: i32) -> ! {
    #[cfg(unix)]
    unsafe {
        libc::_exit(code);
    }
    #[cfg(not(unix))]
    std::process::exit(code);
}

impl Jobs {
    fn lanes(&self) -> MutexGuard<'_, HashMap<Vec<u8>, Lane>> {
        self.lanes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    fn spawn(
        &'static self,
        lane: &[u8],
        label: &'static str,
        job: impl FnOnce() -> Result<()> + Send + 'static,
    ) {
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
                Err(error) if self.stopping() => {
                    info!(label, lane = %shown, %error, "storage snapshot job stopped with the node")
                }
                Err(error) => {
                    warn!(label, lane = %shown, %error, "storage snapshot job failed; it is tried again when next needed")
                }
            }
        });
        {
            let mut lanes = self.lanes();
            // Under the lock: the stop empties the queues under it.
            if self.stopping() {
                drop(lanes);
                if !self.refused.swap(true, Ordering::SeqCst) {
                    info!(label, lane = %hex::encode(lane), "storage job not started: the node is stopping; later ones are not either");
                }
                return;
            }
            if let Some(entry) = lanes.get_mut(lane) {
                entry.queued.push_back((label, job));
                return;
            }
            let entry = Lane {
                running: label,
                queued: VecDeque::new(),
            };
            lanes.insert(lane.to_vec(), entry);
        }
        let owned = lane.to_vec();
        if let Err(error) = std::thread::Builder::new()
            .name("storage-jobs".into())
            .spawn(move || self.run_lane(owned, job))
        {
            self.lanes().remove(lane);
            self.idle.notify_all();
            warn!(label, lane = %hex::encode(lane), %error, "storage job thread not started; the lane's jobs are dropped");
        }
    }

    /// Run `first`, then the lane's queued jobs in order, until none is left
    /// or the node is stopping.
    fn run_lane(&self, lane: Vec<u8>, first: Job) {
        let mut next = Some(first);
        while let Some(job) = next {
            job();
            let mut lanes = self.lanes();
            // A stopping node takes no queued job.
            let entry = lanes.get_mut(&lane).filter(|_| !self.stopping());
            next = entry.and_then(|entry| {
                let (label, job) = entry.queued.pop_front()?;
                entry.running = label;
                Some(job)
            });
            if next.is_none() {
                lanes.remove(&lane);
                self.idle.notify_all();
            }
        }
    }

    /// [`shut_down`].
    fn shut_down(&self, grace: Duration) -> Vec<&'static str> {
        let started = Instant::now();
        let deadline = started + grace;
        self.stopping.store(true, Ordering::SeqCst);
        let (running, queued) = {
            let mut lanes = self.lanes();
            let queued: Vec<(&'static str, Job)> = lanes
                .values_mut()
                .flat_map(|lane| std::mem::take(&mut lane.queued))
                .collect();
            (lanes.len(), queued)
        };
        // Dropped here, not under the lock: a job's store may close as it
        // drops.
        let dropped = queued.len();
        drop(queued);
        let mut lanes = self.lanes();
        while !lanes.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            lanes = self
                .idle
                .wait_timeout(lanes, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let still: Vec<&'static str> = lanes.values().map(|lane| lane.running).collect();
        drop(lanes);
        if still.is_empty() {
            info!(
                running,
                dropped,
                seconds = started.elapsed().as_secs_f64(),
                "storage jobs stopped before exit"
            );
        }
        still
    }
}

/// Wait until `lane` has no job running or queued, at most `timeout`: a test
/// whose job reads its store must not exit while the job runs, or process
/// exit tears the store down under it.
#[cfg(test)]
pub(crate) fn wait_lane_idle(lane: &[u8], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while jobs().lanes().contains_key(lane) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

/// Reserve `bytes` for a job's work: waits, behind the reservations asked
/// for before it, until it fits beside the ones held.
pub fn reserve(bytes: u64) -> Reservation {
    admission().reserve(bytes)
}

/// Reserve `bytes` for work done ahead of when it is needed (labelling a
/// later epoch's leaves, `crate::storage_labels`): like [`reserve`], behind
/// every reservation asked for work due now, whenever asked. Once granted,
/// the work gives the memory back while work due now waits for memory
/// ([`Reservation::yield_requested`]), so a renewal's snapshot never waits
/// for it for long.
pub fn reserve_ahead(bytes: u64) -> Reservation {
    admission().reserve_with(bytes, Urgency::Ahead)
}

/// Wait until no work due now has waited for memory or held any for
/// [`DUE_QUIET`]: when work ahead that gave its memory back to it
/// ([`Reservation::yield_requested`]) starts again. False, without waiting
/// further, once the node is stopping ([`shut_down`]).
pub fn wait_for_due_work() -> bool {
    admission().wait_due_quiet(DUE_QUIET, &stopping)
}

fn admission() -> &'static Admission {
    static ADMISSION: OnceLock<Admission> = OnceLock::new();
    ADMISSION.get_or_init(|| Admission::new(job_slots(), Box::new(available_memory)))
}

/// Whether a reservation's work is due now (a snapshot a renewal waits for,
/// an epoch proof) or done ahead of when it is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    Due,
    Ahead,
}

/// Jobs that may hold memory at once: one per core, less the master's.
pub fn job_slots() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1).max(1))
}

/// Run `work` on each of `items`, on as many threads as jobs may hold
/// memory at once ([`job_slots`]), each item reserving its own ([`reserve`]):
/// the leaves of one seat side by side. Returns each item's result in order;
/// after a failure, or once the node is stopping ([`shut_down`]), items not
/// started yet are not run.
pub fn for_each_parallel<T: Sync, R: Send>(
    items: &[T],
    work: impl Fn(&T) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    use std::sync::atomic::AtomicUsize;
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let results: Mutex<Vec<Option<Result<R>>>> =
        Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..job_slots().min(items.len()) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= items.len() || failed.load(Ordering::Relaxed) || jobs().stopping() {
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
            None if jobs().stopping() => {
                return Err(QuilError::ExecutionUnavailable(
                    "the node is stopping".into(),
                ))
            }
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
    urgency: Urgency,
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

    /// Whether work ahead holding this reservation ([`reserve_ahead`])
    /// should give it back, dropping it, and start again once work due now
    /// is done ([`wait_for_due_work`]): a reservation for work due now waits
    /// for memory. Never for work due now.
    pub fn yield_requested(&self) -> bool {
        self.urgency == Urgency::Ahead && self.admission.state().due_waiting > 0
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.admission.state();
        state.reserved = state.reserved.saturating_sub(self.bytes);
        state.holders = state.holders.saturating_sub(1);
        if self.urgency == Urgency::Due {
            state.due_held = state.due_held.saturating_sub(1);
            state.due_last = Some(Instant::now());
        }
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
    /// Tickets of the reservations waiting, in the order granted: those due
    /// now in the order asked, then those ahead in the order asked.
    waiting: VecDeque<(u64, Urgency)>,
    next_ticket: u64,
    /// Memory available when the last reservation granted to no others was.
    idle_available: Option<u64>,
    /// Reservations held for work due now.
    due_held: usize,
    /// Reservations for work due now waiting, once they found they do not
    /// fit or are not first in line: what work ahead gives its memory back
    /// for ([`Reservation::yield_requested`]).
    due_waiting: usize,
    /// When a reservation for work due now last was granted or given back.
    due_last: Option<Instant>,
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
        self.reserve_with(bytes, Urgency::Due)
    }

    /// Reserve `bytes` for work of `urgency` ([`reserve`], [`reserve_ahead`]).
    pub fn reserve_with(&'static self, bytes: u64, urgency: Urgency) -> Reservation {
        let mut state = self.state();
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        // Work due now goes before every reservation for work ahead.
        let position = match urgency {
            Urgency::Due => state
                .waiting
                .iter()
                .position(|&(_, waiting)| waiting == Urgency::Ahead)
                .unwrap_or(state.waiting.len()),
            Urgency::Ahead => state.waiting.len(),
        };
        state.waiting.insert(position, (ticket, urgency));
        let started = Instant::now();
        let mut waited = false;
        while state.waiting.front().map(|&(front, _)| front) != Some(ticket)
            || !self.fits(&mut state, bytes)
        {
            if !waited {
                waited = true;
                if urgency == Urgency::Due {
                    state.due_waiting += 1;
                }
                info!(
                    bytes,
                    reserved = state.reserved,
                    jobs = state.holders,
                    ahead = state
                        .waiting
                        .iter()
                        .position(|&(waiting, _)| waiting == ticket)
                        .unwrap_or(0),
                    due = urgency == Urgency::Due,
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
        if urgency == Urgency::Due {
            if waited {
                state.due_waiting = state.due_waiting.saturating_sub(1);
            }
            state.due_held += 1;
            state.due_last = Some(Instant::now());
        }
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
            urgency,
        }
    }

    /// Wait until no reservation for work due now has waited or been held
    /// for `quiet` ([`wait_for_due_work`]); false, at once, when `stop` says
    /// so.
    pub fn wait_due_quiet(&self, quiet: Duration, stop: &dyn Fn() -> bool) -> bool {
        let mut state = self.state();
        loop {
            if stop() {
                return false;
            }
            let busy = state.due_held > 0 || state.due_waiting > 0;
            let left = state
                .due_last
                .map_or(Duration::ZERO, |at| quiet.saturating_sub(at.elapsed()));
            if !busy && left.is_zero() {
                return true;
            }
            let wait = if busy { RECHECK } else { left.min(RECHECK) };
            state = self
                .changed
                .wait_timeout(state, wait)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
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
        hold_with(admission, bytes, Urgency::Due)
    }

    fn hold_with(admission: &'static Admission, bytes: u64, urgency: Urgency) -> Held {
        let (granted_tx, granted) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let _reservation = admission.reserve_with(bytes, urgency);
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

    /// A reservation for work due now (a renewal's snapshot) goes before
    /// those for work ahead (labelling a later epoch) asked for before it.
    #[test]
    fn work_due_now_is_granted_before_work_ahead_asked_earlier() {
        let (admission, _) = admission(8, 40 * GIB);
        let first = hold(admission, 20 * GIB);
        assert!(granted(&first));
        let ahead = hold_with(admission, 20 * GIB, Urgency::Ahead);
        until_waiting(admission, 1);
        let later_ahead = hold_with(admission, GIB, Urgency::Ahead);
        until_waiting(admission, 2);
        let due = hold(admission, 20 * GIB);
        until_waiting(admission, 3);
        assert_eq!(
            admission
                .state()
                .waiting
                .iter()
                .map(|&(_, urgency)| urgency)
                .collect::<Vec<_>>(),
            vec![Urgency::Due, Urgency::Ahead, Urgency::Ahead],
            "the due reservation waits first in line"
        );
        drop(first.release);
        assert!(granted(&due), "the work due now runs first");
        assert!(still_waiting(&ahead), "the work ahead waits behind it");
        assert!(still_waiting(&later_ahead));
        drop(due.release);
        assert!(granted(&ahead));
        assert!(granted(&later_ahead), "work ahead keeps its own order");
    }

    /// Work ahead holding memory is asked to give it back once work due now
    /// waits for memory, and not before; work due now is never asked.
    #[test]
    fn work_ahead_is_asked_to_yield_while_work_due_now_waits() {
        let (admission, _) = admission(8, 8 * GIB);
        let ahead = admission.reserve_with(4 * GIB, Urgency::Ahead);
        assert!(!ahead.yield_requested(), "nothing waits");
        let small = hold(admission, GIB);
        assert!(granted(&small), "it fits beside the work ahead");
        assert!(
            !ahead.yield_requested(),
            "work due now that fits waits for nothing"
        );
        let due = hold(admission, 4 * GIB);
        until_waiting(admission, 1);
        assert!(ahead.yield_requested(), "work due now waits for memory");
        drop(ahead);
        assert!(
            granted(&due),
            "it runs once the work ahead gives its memory back"
        );
        let now = admission.reserve(GIB);
        assert!(!now.yield_requested(), "never work due now");
        drop(now);
        let next = admission.reserve_with(GIB, Urgency::Ahead);
        assert!(!next.yield_requested(), "nothing due waits any more");
        drop(small.release);
        drop(due.release);
    }

    /// Work ahead that yielded starts again only once no work due now has
    /// waited or held memory for the quiet time, and at once when stopping.
    #[test]
    fn work_ahead_waits_for_work_due_now_to_be_done() {
        let (admission, _) = admission(8, 8 * GIB);
        let quiet = Duration::from_millis(300);
        assert!(
            admission.wait_due_quiet(quiet, &|| false),
            "no work due now"
        );
        let due = hold(admission, GIB);
        assert!(granted(&due));
        let (resumed_tx, resumed) = mpsc::channel();
        std::thread::spawn(move || {
            resumed_tx
                .send((admission.wait_due_quiet(quiet, &|| false), Instant::now()))
                .unwrap();
        });
        assert!(
            resumed.recv_timeout(NOT_YET).is_err(),
            "not while work due now holds memory"
        );
        let released = Instant::now();
        drop(due.release);
        let (done, at) = resumed.recv_timeout(SOON).unwrap();
        assert!(done);
        assert!(
            at.duration_since(released) >= quiet,
            "only after the quiet time"
        );
        let held = hold(admission, GIB);
        assert!(granted(&held));
        assert!(
            !admission.wait_due_quiet(quiet, &|| true),
            "a stopping node does not wait"
        );
        drop(held.release);
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

    /// Lanes of their own, so a test's stop leaves the node's running.
    fn own_jobs() -> &'static Jobs {
        Box::leak(Box::new(Jobs::default()))
    }

    #[test]
    fn a_stop_waits_for_the_running_job_and_drops_the_queued_ones() {
        let jobs = own_jobs();
        let (started_tx, started) = mpsc::channel();
        let (open, gate) = mpsc::channel::<()>();
        jobs.spawn(b"test lane", "test", move || {
            started_tx.send(()).unwrap();
            gate.recv().unwrap();
            Ok(())
        });
        let (ran_tx, ran) = mpsc::channel::<()>();
        jobs.spawn(b"test lane", "test", move || {
            ran_tx.send(()).unwrap();
            Ok(())
        });
        started.recv_timeout(SOON).unwrap();
        // The running job ends once the stop has begun.
        std::thread::spawn(move || {
            while !jobs.stopping() {
                std::thread::sleep(Duration::from_millis(5));
            }
            open.send(()).unwrap();
        });
        assert!(jobs.shut_down(SOON).is_empty(), "every job stopped in time");
        assert_eq!(
            ran.try_recv(),
            Err(mpsc::TryRecvError::Disconnected),
            "the queued job was dropped without running"
        );
    }

    #[test]
    fn a_job_spawned_once_stopping_does_not_run() {
        let jobs = own_jobs();
        assert!(jobs.shut_down(SOON).is_empty());
        let (ran_tx, ran) = mpsc::channel::<()>();
        jobs.spawn(b"test lane", "test", move || {
            ran_tx.send(()).unwrap();
            Ok(())
        });
        assert_eq!(
            ran.recv_timeout(NOT_YET),
            Err(mpsc::RecvTimeoutError::Disconnected),
            "the job was dropped without running"
        );
        assert!(jobs.lanes().is_empty());
    }

    #[test]
    fn a_job_longer_than_the_grace_is_left_running() {
        let jobs = own_jobs();
        let (open, gate) = mpsc::channel::<()>();
        jobs.spawn(b"test lane", "long", move || {
            let _ = gate.recv();
            Ok(())
        });
        let grace = Duration::from_millis(200);
        let started = Instant::now();
        assert_eq!(jobs.shut_down(grace), vec!["long"]);
        let waited = started.elapsed();
        assert!(
            waited >= grace && waited < SOON,
            "the stop waits for the grace, then returns: {waited:?}"
        );
        drop(open);
        assert!(jobs.shut_down(SOON).is_empty(), "the job ends once let go");
    }
}
