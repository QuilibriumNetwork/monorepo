//! The background jobs of hash storage proofs (decided 2026-10-26): each
//! seat's snapshot captures and encodes, its parts of the member's epoch
//! proof, and the node's epoch proofs.
//!
//! A job runs in a lane, after the jobs queued in that lane before it: a
//! seat's shard, whose jobs run one at a time as a standalone worker runs its
//! own, or the node's epoch proofs ([`EPOCH_PROOF_LANE`]). Lanes run side by
//! side, bounded by memory and cores: before its heavy work a job reserves
//! what it holds at its peak ([`reserve`]), and reservations are granted
//! smallest first, each once it fits in the jobs' share of the memory
//! available to the node ([`MEMORY_SHARE_PERCENT`]) and a core is free of
//! them. A node with the memory encodes every seat at once; one without
//! encodes as many as fit, then the next as each finishes. A job alone runs
//! whatever its size. One that does not fit lets later ones that do pass it,
//! a bounded number of times ([`PASS_LIMIT`], [`PASS_WINDOW`]): a large leaf
//! labelled ahead at the head of the queue kept smaller ones that fit waiting
//! for an hour while one job held memory (2026-10-29). A job whose work's
//! window passes while it waits leaves the queue ([`reserve_until`]).
//!
//! Labelling a leaf is one chain of hashes, a core's work for about 80
//! minutes per GiB. With one job at a time for the whole node, a node's
//! later seats missed their renewal's grace. Taken in the order asked, one
//! large leaf held a node's only free core past every other seat's grace
//! (2026-10-28: a leaf of 30 million nodes labelled for 75 minutes of a
//! 54-minute grace); smallest first, the seats with small leaves register.
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

use std::collections::{HashMap, HashSet, VecDeque};
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

/// How long one look at the memory beside the reservations held bounds the
/// jobs' share ([`Admission`]). A reservation granted a moment ago has
/// allocated nothing yet, so what is available just after it still holds
/// its memory: the look taken before it bounds the next ones until it has
/// allocated (a leaf's read took about three minutes to, 2026-10-28). Five
/// minutes also hold the node's own peaks, its periodic prover-tree pull
/// among them.
const LOOK_WINDOW: Duration = Duration::from_secs(300);

/// How long work due now must have neither waited for memory nor held any
/// before work ahead that yielded to it starts again ([`wait_for_due_work`]):
/// a gap between one seat's encode and the next's does not end it.
const DUE_QUIET: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(60)
};

/// How often later reservations that fit may pass one that does not before
/// none may ([`Admission::admit_waiting`]): it then holds its place until it
/// fits, at the latest once the jobs holding memory end and it runs alone.
/// Each pass is a job that ends within its own run, so the one passed waits
/// at most for those granted before the bound, not for every job asked after
/// it.
const PASS_LIMIT: u32 = 8;

/// How long after a reservation was first passed later ones may still pass
/// it ([`PASS_LIMIT`]): a few small jobs a while apart do not keep a large
/// one waiting for hours.
const PASS_WINDOW: Duration = Duration::from_secs(600);

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
            .spawn(move || {
                on_process_cpus();
                self.run_lane(owned, job)
            })
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

/// Reserve `bytes` for a job's work: waits, behind the smaller reservations
/// and those of its size asked for before it, until it fits beside the ones
/// held.
pub fn reserve(bytes: u64) -> Reservation {
    admission().reserve(bytes)
}

/// [`reserve`] for work that is of no use once `expired` says so (a
/// renewal's grace passed): `None` once it does while the reservation
/// waits, which then leaves the queue, holding neither memory nor a place.
pub fn reserve_until(bytes: u64, expired: &dyn Fn() -> bool) -> Option<Reservation> {
    admission().reserve_until(bytes, Urgency::Due, expired)
}

/// Reserve `bytes` for work done ahead of when it is needed (labelling a
/// later epoch's leaves, `crate::storage_labels`): like [`reserve`], behind
/// every reservation asked for work due now, whenever asked. Once granted,
/// the work gives the memory back while work due now waits for memory
/// ([`Reservation::yield_requested`]), so a renewal's snapshot never waits
/// for it for long. `None` once `expired` says the work is of no use any
/// more while it waits ([`reserve_until`]).
pub fn reserve_ahead(bytes: u64, expired: &dyn Fn() -> bool) -> Option<Reservation> {
    admission().reserve_until(bytes, Urgency::Ahead, expired)
}

/// Reserve `bytes` for a storage settlement's work (its held replicas, or
/// proving it alone): at once, beside every job and whether or not a slot is
/// free, when it fits in the headroom left beside the jobs' share of the
/// memory available now (a quarter, [`MEMORY_SHARE_PERCENT`]); otherwise as
/// [`reserve`]. A settlement takes seconds, and GLOBAL withholds the storage
/// share (before epoch 1342: kicks) of a member whose committed roots go
/// unproven by the window's end: it must not wait behind seals relabelling
/// for an hour.
pub fn reserve_settlement(bytes: u64) -> Reservation {
    admission().reserve_settlement(bytes)
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

/// Jobs that may hold memory at once: one per core the process may use,
/// less the master's. Counted once, on a thread of the process's CPUs: the
/// thread asking is often a data worker's, pinned to one core, and counting
/// its CPUs ran every node's jobs one at a time (2026-10-29).
pub fn job_slots() -> usize {
    static SLOTS: OnceLock<usize> = OnceLock::new();
    *SLOTS.get_or_init(|| {
        let counted = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("storage-slots".into())
                .spawn_scoped(scope, || {
                    let process = on_process_cpus();
                    (std::thread::available_parallelism().ok(), process)
                })
                .ok()
                .and_then(|thread| thread.join().ok())
        });
        let (cpus, source) = match counted {
            Some((Some(cpus), true)) => (cpus.get(), "process CPUs"),
            Some((Some(cpus), false)) => (cpus.get(), "the asking thread's CPUs"),
            _ => (1, "unknown"),
        };
        let slots = cpus.saturating_sub(1).max(1);
        info!(
            slots,
            cpus,
            source,
            "storage job slots counted: up to this many jobs hold memory at once, one per CPU \
             the node may use less the master's; each also waits until its memory fits"
        );
        slots
    })
}

/// Move the calling storage job thread onto the process's CPUs: it inherits
/// the set of the thread that started it, often a data worker's single core,
/// where the jobs side by side would share that core. False when it stays on
/// its own set, which is logged once.
fn on_process_cpus() -> bool {
    use quil_lattice_ct::confidential::relation::backend::worker_process::use_process_cpus;
    static WARNED: AtomicBool = AtomicBool::new(false);
    let moved = use_process_cpus();
    if !moved && !WARNED.swap(true, Ordering::Relaxed) {
        warn!(
            "storage job thread stays on the CPUs of the thread that started it, a data \
             worker's core perhaps: the process's CPU set is unknown or was refused; \
             storage jobs side by side may share one core and take longer"
        );
    }
    moved
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
    // A test's stable replica key epoch, for the work's threads too.
    let stable_key = quil_types::consensus::stable_replica_key_epoch_thread_override();
    std::thread::scope(|scope| {
        for _ in 0..job_slots().min(items.len()) {
            scope.spawn(|| {
                quil_types::consensus::set_stable_replica_key_epoch_for_thread(stable_key);
                on_process_cpus();
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= items.len() || failed.load(Ordering::Relaxed) || jobs().stopping() {
                        break;
                    }
                    let result = work(&items[index]);
                    if result.is_err() {
                        failed.store(true, Ordering::Relaxed);
                    }
                    results.lock().unwrap_or_else(PoisonError::into_inner)[index] = Some(result);
                }
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
        state.stale = true;
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
        state.stale = true;
        drop(state);
        self.admission.changed.notify_all();
    }
}

/// Grants the jobs' reservations ([`reserve`]): those for work due now
/// smallest first, then those for work ahead in the order asked, each once
/// it fits ([`Admission::admit_waiting`]).
pub struct Admission {
    state: Mutex<State>,
    /// [`PASS_WINDOW`], shorter in tests.
    pass_window: Duration,
    changed: Condvar,
    slots: usize,
    available: Box<dyn Fn() -> Option<u64> + Send + Sync>,
    /// [`LOOK_WINDOW`], shorter in tests.
    window: Duration,
}

#[derive(Default)]
struct State {
    /// Bytes the reservations held come to.
    reserved: u64,
    /// Reservations held.
    holders: usize,
    /// Tickets of the reservations waiting, with their urgency and bytes, in
    /// the order looked at ([`Admission::admit_waiting`]): those due now
    /// smallest first, then in the order asked, then those ahead in the order
    /// asked.
    waiting: VecDeque<(u64, Urgency, u64)>,
    next_ticket: u64,
    /// Memory available when the last reservation granted to no others was,
    /// raised to what is available beside the ones held whenever that is
    /// more: the most the jobs could have.
    idle_available: Option<u64>,
    /// What was available plus the reservations held, at the looks within
    /// [`LOOK_WINDOW`] that were lower than every later one: the front is
    /// the lowest.
    looks: VecDeque<(Instant, u64)>,
    /// The latest look at the memory beside reservations held.
    last_look: Option<Look>,
    /// Reservations held for work due now.
    due_held: usize,
    /// Reservations for work due now waiting, once they found they do not
    /// fit or are not first in line: what work ahead gives its memory back
    /// for ([`Reservation::yield_requested`]).
    due_waiting: usize,
    /// When a reservation for work due now last was granted or given back.
    due_last: Option<Instant>,
    /// Tickets granted by a pass over the waiting reservations
    /// ([`Admission::admit_waiting`]) that their jobs have not taken up yet:
    /// counted as held.
    granted: HashSet<u64>,
    /// Waiting reservations later ones passed, by ticket.
    passed: HashMap<u64, Passed>,
    /// Whether a reservation was asked for, given back, resized or left
    /// since the last pass.
    stale: bool,
    /// When the last pass was.
    last_pass: Option<Instant>,
}

/// How a waiting reservation was passed by later ones that fit while it did
/// not ([`PASS_LIMIT`]).
#[derive(Debug, Clone, Copy)]
struct Passed {
    times: u32,
    first: Instant,
    /// Whether it holds its place now, logged as it began to.
    holding: bool,
}

/// One look at the memory beside the reservations held ([`Admission`]).
#[derive(Debug, Clone, Copy)]
struct Look {
    available: u64,
    idle_available: u64,
    window_low: u64,
    share: u64,
}

impl Admission {
    /// At most `slots` reservations held at once, sharing the memory
    /// `available` reports (`None` when it cannot tell: one at a time).
    pub fn new(slots: usize, available: Box<dyn Fn() -> Option<u64> + Send + Sync>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            pass_window: PASS_WINDOW,
            changed: Condvar::new(),
            slots: slots.max(1),
            available,
            window: LOOK_WINDOW,
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
        let Some(reservation) = self.reserve_until(bytes, urgency, &|| false) else {
            unreachable!("a reservation whose work never expires does not leave the queue")
        };
        reservation
    }

    /// Reserve `bytes` for work of `urgency`, or `None` once `expired` says
    /// its work is of no use any more while it waits, looked at whenever it
    /// looks at the memory again ([`reserve_until`]).
    pub fn reserve_until(
        &'static self,
        bytes: u64,
        urgency: Urgency,
        expired: &dyn Fn() -> bool,
    ) -> Option<Reservation> {
        let mut state = self.state();
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        // Work due now goes before every reservation for work ahead, and
        // before larger ones for work due now: the shortest ends first.
        let position = match urgency {
            Urgency::Due => state
                .waiting
                .iter()
                .position(|&(_, waiting, asked)| waiting == Urgency::Ahead || asked > bytes)
                .unwrap_or(state.waiting.len()),
            Urgency::Ahead => state.waiting.len(),
        };
        state.waiting.insert(position, (ticket, urgency, bytes));
        state.stale = true;
        let started = Instant::now();
        let mut waited = false;
        while !self.take_grant(&mut state, ticket) {
            if !waited {
                waited = true;
                if urgency == Urgency::Due {
                    state.due_waiting += 1;
                }
                let look = state.last_look;
                info!(
                    bytes,
                    reserved = state.reserved,
                    jobs = state.holders,
                    available = look.map(|look| look.available),
                    idle_available = look.map(|look| look.idle_available),
                    window_low = look.map(|look| look.window_low),
                    share = look.map(|look| look.share),
                    ahead = state
                        .waiting
                        .iter()
                        .position(|&(waiting, _, _)| waiting == ticket)
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
            // Not under the lock: the caller's look may take its own.
            drop(state);
            let gone = expired();
            state = self.state();
            if gone {
                self.leave(state, ticket, urgency, bytes, started);
                return None;
            }
        }
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
                due = urgency == Urgency::Due,
                seconds = started.elapsed().as_secs_f64(),
                "storage job has its memory"
            );
        }
        // The next in line may fit beside this one.
        self.changed.notify_all();
        Some(Reservation {
            admission: self,
            bytes,
            urgency,
        })
    }

    /// Whether `ticket`'s reservation was granted, after a pass over the
    /// waiting ones ([`Admission::admit_waiting`]) when one changed since the
    /// last or [`RECHECK`] passed; taken up if so.
    fn take_grant(&self, state: &mut State, ticket: u64) -> bool {
        if state.stale || state.last_pass.is_none_or(|at| at.elapsed() >= RECHECK) {
            self.admit_waiting(state);
        }
        if !state.granted.remove(&ticket) {
            return false;
        }
        state.passed.remove(&ticket);
        true
    }

    /// Grant the waiting reservations that fit now, in their order
    /// ([`State::waiting`]), first fit: one that does not fit lets later ones
    /// that do pass it, except that
    /// - work ahead never passes work due now: granted, it would be asked to
    ///   give its memory back at once ([`Reservation::yield_requested`]);
    /// - nothing passes one passed [`PASS_LIMIT`] times, or first passed
    ///   [`PASS_WINDOW`] ago. It holds its place until it fits beside the
    ///   jobs holding memory, at the latest once they end and it runs alone.
    fn admit_waiting(&self, state: &mut State) {
        state.stale = false;
        state.last_pass = Some(Instant::now());
        let mut skipped: Vec<u64> = Vec::new();
        let mut due_skipped = false;
        let mut granted = false;
        let mut index = 0;
        while index < state.waiting.len() && state.holders < self.slots {
            let (ticket, urgency, bytes) = state.waiting[index];
            if urgency == Urgency::Ahead && due_skipped {
                break;
            }
            if self.fits(state, bytes) {
                state.waiting.remove(index);
                state.reserved = state.reserved.saturating_add(bytes);
                state.holders += 1;
                state.granted.insert(ticket);
                let now = Instant::now();
                for &passed in &skipped {
                    let entry = state.passed.entry(passed).or_insert(Passed {
                        times: 0,
                        first: now,
                        holding: false,
                    });
                    entry.times = entry.times.saturating_add(1);
                }
                granted = true;
                continue;
            }
            if self.holds_place(state, ticket, urgency, bytes) {
                break;
            }
            skipped.push(ticket);
            due_skipped |= urgency == Urgency::Due;
            index += 1;
        }
        if granted {
            self.changed.notify_all();
        }
    }

    /// Whether the waiting reservation `ticket`, which does not fit, holds
    /// its place: nothing later passes it ([`PASS_LIMIT`], [`PASS_WINDOW`]).
    /// Logged once, as it begins to.
    fn holds_place(&self, state: &mut State, ticket: u64, urgency: Urgency, bytes: u64) -> bool {
        let (reserved, jobs) = (state.reserved, state.holders);
        let Some(passed) = state.passed.get_mut(&ticket) else {
            return false;
        };
        let since = passed.first.elapsed();
        if passed.times < PASS_LIMIT && since < self.pass_window {
            return false;
        }
        if !passed.holding {
            passed.holding = true;
            info!(
                bytes,
                due = urgency == Urgency::Due,
                passed = passed.times,
                seconds = since.as_secs_f64(),
                reserved,
                jobs,
                "storage job holds its place for memory: smaller jobs that fit passed it while it \
                 did not; none passes it now until it fits beside the jobs holding memory, at the \
                 latest once they end and it runs alone: an expected wait"
            );
        }
        true
    }

    /// `ticket`'s reservation leaves the queue: its work's window passed
    /// while it waited ([`reserve_until`]). Granted meanwhile but not taken
    /// up, its memory is given back.
    fn leave(
        &self,
        mut state: MutexGuard<'_, State>,
        ticket: u64,
        urgency: Urgency,
        bytes: u64,
        started: Instant,
    ) {
        if let Some(index) = state.waiting.iter().position(|&(t, _, _)| t == ticket) {
            state.waiting.remove(index);
        } else if state.granted.remove(&ticket) {
            state.reserved = state.reserved.saturating_sub(bytes);
            state.holders = state.holders.saturating_sub(1);
        }
        state.passed.remove(&ticket);
        if urgency == Urgency::Due {
            // It waited: its window is looked at only after a wait.
            state.due_waiting = state.due_waiting.saturating_sub(1);
            state.due_last = Some(Instant::now());
        }
        state.stale = true;
        let (waiting, jobs) = (state.waiting.len(), state.holders);
        drop(state);
        info!(
            bytes,
            due = urgency == Urgency::Due,
            seconds = started.elapsed().as_secs_f64(),
            waiting,
            jobs,
            "storage job leaves the queue for memory: its work's window passed while it waited, \
             so it takes neither memory nor a place before other jobs (its own line says which \
             window)"
        );
        self.changed.notify_all();
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

    /// Reserve `bytes` for a settlement ([`reserve_settlement`]).
    pub fn reserve_settlement(&'static self, bytes: u64) -> Reservation {
        let mut state = self.state();
        let now = (self.available)();
        let headroom =
            now.map(|now| u128::from(now) * u128::from(100 - MEMORY_SHARE_PERCENT) / 100);
        if state.holders > 0 && !headroom.is_some_and(|room| u128::from(bytes) <= room) {
            drop(state);
            return self.reserve(bytes);
        }
        if state.holders == 0 {
            state.idle_available = now;
        }
        state.reserved = state.reserved.saturating_add(bytes);
        state.holders += 1;
        state.due_held += 1;
        state.due_last = Some(Instant::now());
        drop(state);
        self.changed.notify_all();
        Reservation {
            admission: self,
            bytes,
            urgency: Urgency::Due,
        }
    }

    /// Whether `bytes` more fit beside the reservations held.
    ///
    /// Alone, a job runs whatever its size, and what is available then is
    /// the most the jobs could have. Beside others, the jobs share
    /// [`MEMORY_SHARE_PERCENT`] of the less of two bounds, looked at again
    /// whenever a reservation asks or waits:
    /// - the most the jobs could have, raised whenever more is available
    ///   beside the ones held (the node gave memory back);
    /// - the lowest look within [`LOOK_WINDOW`] at what was available plus
    ///   the reservations held: less when the node has grown, and a
    ///   reservation granted a moment ago, which has allocated nothing yet,
    ///   is not counted both as available and as held.
    ///
    /// The share is never less than that of what is available now, which
    /// the reservations fit in even if none has allocated anything. So no
    /// single look decides for longer than the window (2026-10-29: the one
    /// taken when the last job alone was granted decided for as long as any
    /// job held memory, too high once the node had grown, too low once it
    /// had given memory back).
    fn fits(&self, state: &mut State, bytes: u64) -> bool {
        let now = Instant::now();
        if state.holders == 0 {
            state.idle_available = (self.available)();
            state.looks.clear();
            if let Some(idle) = state.idle_available {
                state.looks.push_back((now, idle));
            }
            return true;
        }
        if state.holders >= self.slots {
            return false;
        }
        let Some(available) = (self.available)() else {
            return false;
        };
        let idle = state
            .idle_available
            .map_or(available, |idle| idle.max(available));
        state.idle_available = Some(idle);
        // The reservations held are mostly allocated, so what is available
        // now plus them is what the jobs could have.
        let bound = available.saturating_add(state.reserved);
        while state
            .looks
            .front()
            .is_some_and(|&(at, _)| now.saturating_duration_since(at) > self.window)
        {
            state.looks.pop_front();
        }
        while state.looks.back().is_some_and(|&(_, low)| low >= bound) {
            state.looks.pop_back();
        }
        state.looks.push_back((now, bound));
        let window_low = state.looks.front().map_or(bound, |&(_, low)| low);
        let could = idle.min(window_low).max(available);
        let share = u128::from(could) * u128::from(MEMORY_SHARE_PERCENT) / 100;
        state.last_look = Some(Look {
            available,
            idle_available: idle,
            window_low,
            share: u64::try_from(share).unwrap_or(u64::MAX),
        });
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
        admission_looking(slots, available, Duration::from_secs(1))
    }

    /// [`admission`] whose looks at the memory bound the share for `window`.
    fn admission_looking(
        slots: usize,
        available: u64,
        window: Duration,
    ) -> (&'static Admission, Arc<AtomicU64>) {
        let memory = Arc::new(AtomicU64::new(available));
        let probe = memory.clone();
        let mut admission = Admission::new(
            slots,
            Box::new(move || Some(probe.load(Ordering::SeqCst)).filter(|&bytes| bytes > 0)),
        );
        admission.window = window;
        (Box::leak(Box::new(admission)), memory)
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

    /// A settlement's reservation does not wait for a free slot while seals
    /// hold them all, when it fits in the headroom; one that does not waits
    /// like any other.
    #[test]
    fn a_settlement_does_not_wait_behind_seals_holding_every_slot() {
        let (admission, _) = admission(2, 40 * GIB);
        let seals = [hold(admission, 10 * GIB), hold(admission, 10 * GIB)];
        assert!(seals.iter().all(granted));
        let (granted_tx, settled) = mpsc::channel();
        std::thread::spawn(move || {
            let _reservation = admission.reserve_settlement(GIB);
            granted_tx.send(()).unwrap();
        });
        assert!(
            settled.recv_timeout(SOON).is_ok(),
            "the settlement waited for a slot the seals hold"
        );
        let (granted_tx, large) = mpsc::channel();
        std::thread::spawn(move || {
            let _reservation = admission.reserve_settlement(20 * GIB);
            granted_tx.send(()).unwrap();
        });
        assert!(
            large.recv_timeout(NOT_YET).is_err(),
            "beyond the headroom it waits"
        );
        drop(seals);
        assert!(large.recv_timeout(SOON).is_ok());
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
        let later_ahead = hold_with(admission, 15 * GIB, Urgency::Ahead);
        until_waiting(admission, 2);
        let due = hold(admission, 20 * GIB);
        until_waiting(admission, 3);
        assert_eq!(
            admission
                .state()
                .waiting
                .iter()
                .map(|&(_, urgency, _)| urgency)
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
        assert!(still_waiting(&later_ahead), "35 GiB do not fit in 30");
        drop(ahead.release);
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

    /// Reservations for work due now are granted smallest first, those of
    /// one size in the order asked (2026-10-28: a node's one free core
    /// labelled a large leaf past every other seat's renewal's grace).
    #[test]
    fn a_smaller_reservation_due_now_goes_before_a_larger_one_waiting() {
        let (admission, _) = admission(1, 40 * GIB);
        let first = hold(admission, GIB);
        assert!(granted(&first));
        let large = hold(admission, 4 * GIB);
        until_waiting(admission, 1);
        let small = hold(admission, GIB);
        until_waiting(admission, 2);
        let same = hold(admission, GIB);
        until_waiting(admission, 3);
        drop(first.release);
        assert!(
            granted(&small),
            "a 1 GiB reservation asked for after a 4 GiB one is granted first"
        );
        assert!(still_waiting(&large));
        drop(small.release);
        assert!(granted(&same), "then the one of its size asked after it");
        assert!(still_waiting(&large));
        drop(same.release);
        assert!(granted(&large));
    }

    /// Work ahead stays behind all work due now, however small, and keeps
    /// the order asked whatever its size.
    #[test]
    fn work_ahead_waits_behind_larger_work_due_now_in_the_order_asked() {
        let (admission, _) = admission(1, 40 * GIB);
        let first = hold(admission, GIB);
        assert!(granted(&first));
        let ahead_large = hold_with(admission, 4 * GIB, Urgency::Ahead);
        until_waiting(admission, 1);
        let ahead_small = hold_with(admission, GIB, Urgency::Ahead);
        until_waiting(admission, 2);
        let due = hold(admission, 8 * GIB);
        until_waiting(admission, 3);
        assert_eq!(
            admission
                .state()
                .waiting
                .iter()
                .map(|&(_, urgency, bytes)| (urgency, bytes / GIB))
                .collect::<Vec<_>>(),
            vec![(Urgency::Due, 8), (Urgency::Ahead, 4), (Urgency::Ahead, 1)]
        );
        drop(first.release);
        assert!(granted(&due));
        drop(due.release);
        assert!(granted(&ahead_large));
        assert!(still_waiting(&ahead_small));
        drop(ahead_large.release);
        assert!(granted(&ahead_small));
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

    /// An admission of `slots` jobs sharing a constant `available`, whose
    /// waiting reservations may be passed for `window` after first being.
    fn admission_passing(slots: usize, available: u64, window: Duration) -> &'static Admission {
        let admission = Box::leak(Box::new(Admission::new(
            slots,
            Box::new(move || Some(available)),
        )));
        admission.pass_window = window;
        admission
    }

    /// A reservation that fits passes a larger one before it that does not,
    /// rather than waiting behind it while memory is free (2026-10-29:
    /// leaves labelled ahead that fit waited an hour behind one of 8 GB
    /// while a single job held memory).
    #[test]
    fn a_smaller_job_ahead_passes_a_larger_one_that_does_not_fit() {
        let (admission, _) = admission(8, 40 * GIB);
        let first = hold(admission, 20 * GIB);
        assert!(granted(&first));
        let large = hold_with(admission, 20 * GIB, Urgency::Ahead);
        until_waiting(admission, 1);
        let small = hold_with(admission, 5 * GIB, Urgency::Ahead);
        assert!(
            granted(&small),
            "25 GiB fit in 30: it passes the 20 GiB one asked before it"
        );
        assert!(still_waiting(&large), "40 GiB do not fit in 30");
        drop(first.release);
        assert!(granted(&large), "it runs once it fits");
        drop(small.release);
        drop(large.release);
    }

    /// Work ahead that fits does not pass work due now that does not: it
    /// would be asked to give its memory back at once.
    #[test]
    fn work_ahead_that_fits_does_not_pass_work_due_now() {
        let (admission, _) = admission(8, 40 * GIB);
        let first = hold(admission, 20 * GIB);
        assert!(granted(&first));
        let due = hold(admission, 20 * GIB);
        until_waiting(admission, 1);
        let ahead = hold_with(admission, GIB, Urgency::Ahead);
        assert!(
            still_waiting(&ahead),
            "21 GiB fit in 30, but work due now waits"
        );
        drop(first.release);
        assert!(granted(&due));
        assert!(granted(&ahead), "then it runs beside it: 21 GiB fit");
        drop(due.release);
        drop(ahead.release);
    }

    /// A reservation passed [`PASS_LIMIT`] times holds its place: later ones
    /// that fit wait behind it until it runs, alone if it fits beside no job.
    #[test]
    fn a_job_passed_too_often_holds_its_place_and_runs_alone() {
        let (admission, _) = admission(PASS_LIMIT as usize + 4, 40 * GIB);
        let first = hold(admission, 20 * GIB);
        assert!(granted(&first));
        let large = hold_with(admission, 35 * GIB, Urgency::Ahead);
        until_waiting(admission, 1);
        let passers: Vec<Held> = (0..PASS_LIMIT)
            .map(|_| {
                let small = hold_with(admission, GIB, Urgency::Ahead);
                assert!(granted(&small), "it fits and passes the large one");
                small
            })
            .collect();
        let late = hold_with(admission, GIB, Urgency::Ahead);
        assert!(
            still_waiting(&late),
            "29 GiB fit in 30, but nothing passes the large one any more"
        );
        drop(first.release);
        assert!(still_waiting(&large), "43 GiB do not fit in 30");
        assert!(still_waiting(&late), "nor does anything pass it");
        drop(passers);
        assert!(granted(&large), "it runs alone once no job holds memory");
        assert!(
            still_waiting(&late),
            "nothing runs beside a job larger than the share"
        );
        drop(large.release);
        assert!(granted(&late));
    }

    /// A reservation first passed [`PASS_WINDOW`] ago holds its place however
    /// few passed it, until it fits.
    #[test]
    fn a_job_passed_for_the_window_holds_its_place_until_it_fits() {
        let window = Duration::from_millis(300);
        let admission = admission_passing(8, 40 * GIB, window);
        let first = hold(admission, 20 * GIB);
        assert!(granted(&first));
        let large = hold_with(admission, 20 * GIB, Urgency::Ahead);
        until_waiting(admission, 1);
        let small = hold_with(admission, GIB, Urgency::Ahead);
        assert!(granted(&small), "it passes the large one");
        std::thread::sleep(window * 2);
        let late = hold_with(admission, GIB, Urgency::Ahead);
        assert!(
            still_waiting(&late),
            "22 GiB fit in 30, but the large one was first passed a window ago"
        );
        drop(first.release);
        assert!(granted(&large), "it runs once it fits: 21 GiB");
        assert!(granted(&late), "then the late one beside it: 22 GiB");
        drop(small.release);
        drop(large.release);
        drop(late.release);
    }

    /// A reservation whose work's window passes while it waits leaves the
    /// queue: it is not granted, and work behind it no longer waits for it.
    #[test]
    fn a_job_whose_window_passed_leaves_the_queue() {
        let (admission, _) = admission(8, 40 * GIB);
        let first = hold(admission, 20 * GIB);
        assert!(granted(&first));
        let expired = Arc::new(AtomicBool::new(false));
        let flag = expired.clone();
        let (left_tx, left) = mpsc::channel();
        std::thread::spawn(move || {
            let reservation =
                admission.reserve_until(20 * GIB, Urgency::Due, &|| flag.load(Ordering::SeqCst));
            left_tx.send(reservation.is_none()).unwrap();
        });
        until_waiting(admission, 1);
        let ahead = hold_with(admission, 5 * GIB, Urgency::Ahead);
        assert!(
            still_waiting(&ahead),
            "work ahead waits behind work due now"
        );
        expired.store(true, Ordering::SeqCst);
        assert_eq!(
            left.recv_timeout(SOON),
            Ok(true),
            "it leaves the queue without memory"
        );
        assert!(granted(&ahead), "25 GiB fit in 30 once it left");
        assert_eq!(admission.state().due_waiting, 0, "no work due now waits");
        assert_eq!(waiting(admission), 0);
        drop(first.release);
        drop(ahead.release);
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

    /// A reservation granted a moment ago has allocated nothing, so what is
    /// available still holds its memory: the next one is weighed against
    /// what the node had before it was granted, not against what was
    /// available when no job held memory, before the node grew.
    #[test]
    fn a_reservation_granted_a_moment_ago_is_not_counted_twice_once_the_node_grew() {
        let (admission, memory) = admission_looking(8, 40 * GIB, Duration::from_secs(600));
        let first = hold(admission, 10 * GIB);
        assert!(granted(&first), "alone, with 40 GiB available");
        // It allocated its 10 GiB and the node grew by 16: the jobs could
        // have 14 + 10 GiB, and share 18.
        memory.store(14 * GIB, Ordering::SeqCst);
        let second = hold(admission, 4 * GIB);
        assert!(granted(&second), "14 GiB fit in 18");
        // It has allocated nothing yet: 14 GiB are still available.
        let third = hold(admission, 5 * GIB);
        assert!(
            still_waiting(&third),
            "19 GiB do not fit in the 18 the jobs share, though 14 available plus 14 held \
             would come to 28 and with none held 40 were"
        );
        // The second allocated its memory and the first gave its back.
        memory.store(20 * GIB, Ordering::SeqCst);
        drop(first.release);
        assert!(granted(&third), "9 GiB fit in 18");
        drop(second.release);
        drop(third.release);
    }

    /// Memory the node gives back while jobs hold theirs is shared at once,
    /// not once every job has ended: what is available beside them is less
    /// than what would be with none held.
    #[test]
    fn memory_the_node_gives_back_is_shared_while_jobs_hold_theirs() {
        let (admission, memory) = admission_looking(8, 10 * GIB, Duration::from_secs(600));
        let first = hold(admission, 4 * GIB);
        assert!(
            granted(&first),
            "alone, while the node peaks at 10 GiB available"
        );
        memory.store(6 * GIB, Ordering::SeqCst);
        let second = hold(admission, 20 * GIB);
        assert!(still_waiting(&second), "24 GiB do not fit in 7.5");
        // The node gave 30 GiB back.
        memory.store(36 * GIB, Ordering::SeqCst);
        assert!(
            granted(&second),
            "24 GiB fit in 27 of the 36 available, though the first still holds its memory"
        );
        drop(first.release);
        drop(second.release);
    }

    /// What the node gave back stays the most the jobs could have once they
    /// have allocated it, until a job is granted alone again.
    #[test]
    fn memory_given_back_stays_shared_once_jobs_allocate_it() {
        let window = Duration::from_millis(200);
        let (admission, memory) = admission_looking(8, 10 * GIB, window);
        let first = hold(admission, 4 * GIB);
        assert!(granted(&first));
        memory.store(36 * GIB, Ordering::SeqCst);
        let second = hold(admission, 20 * GIB);
        assert!(granted(&second), "24 GiB fit in 27");
        // The second allocated its 20 GiB; the looks before are past.
        memory.store(16 * GIB, Ordering::SeqCst);
        std::thread::sleep(window * 2);
        let third = hold(admission, 2 * GIB);
        assert!(
            granted(&third),
            "26 GiB fit in 27 of the 36 seen beside the first, not in 12 of the 16 available"
        );
        drop(first.release);
        drop(second.release);
        drop(third.release);
    }

    /// A peak of the node's lowers the share for the window only: once the
    /// peak is past, the share comes back without every job ending.
    #[test]
    fn a_peak_of_the_node_lowers_the_share_for_the_window_only() {
        let window = Duration::from_millis(500);
        let (admission, memory) = admission_looking(8, 40 * GIB, window);
        let first = hold(admission, 10 * GIB);
        assert!(granted(&first));
        // The first allocated its memory, and the node peaks at 20 GiB more.
        memory.store(10 * GIB, Ordering::SeqCst);
        let second = hold(admission, 14 * GIB);
        assert!(still_waiting(&second), "24 GiB do not fit in 15");
        memory.store(30 * GIB, Ordering::SeqCst);
        assert!(
            granted(&second),
            "24 GiB fit in 30 once the peak's look is past, though 22.5 is all of the 30 \
             available alone"
        );
        drop(first.release);
        drop(second.release);
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

    /// CPUs the calling thread may run on, as `job_slots` counted them.
    #[cfg(target_os = "linux")]
    fn cpus() -> usize {
        std::thread::available_parallelism().map_or(0, |n| n.get())
    }

    /// Run `f` on a thread pinned to one core, as each data worker's is,
    /// once the process's CPU set is recorded, as the node does at startup.
    #[cfg(target_os = "linux")]
    fn on_a_pinned_thread<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
        quil_lattice_ct::confidential::relation::backend::worker_process::remember_process_cpus();
        let core = core_affinity::get_core_ids()
            .and_then(|cores| cores.last().copied())
            .expect("a core to pin to");
        std::thread::spawn(move || {
            assert!(core_affinity::set_for_current(core), "pin the test thread");
            assert_eq!(cpus(), 1, "the thread runs on one core");
            f()
        })
        .join()
        .unwrap()
    }

    /// Storage jobs are asked for from a data worker's thread, pinned to one
    /// core: they still get a slot per core the process may use, less one,
    /// not one in all (2026-10-29: every node ran one at a time).
    #[cfg(target_os = "linux")]
    #[test]
    fn job_slots_asked_from_a_pinned_thread_count_the_process_cpus() {
        let process = cpus();
        if process < 3 {
            eprintln!("skipped: this process may use {process} CPUs, so one slot is right");
            return;
        }
        let slots = on_a_pinned_thread(job_slots);
        assert_eq!(
            slots,
            process - 1,
            "a thread pinned to one core counted {slots} slot(s) for a process of {process} CPUs"
        );
    }

    /// A lane started from a pinned thread, and the threads a seat's leaves
    /// run on, run on every CPU the process may use, not that one core.
    #[cfg(target_os = "linux")]
    #[test]
    fn jobs_started_from_a_pinned_thread_run_on_the_process_cpus() {
        let process = cpus();
        if process < 2 {
            eprintln!("skipped: this process may use one CPU");
            return;
        }
        let (lane, leaves) = on_a_pinned_thread(|| {
            let (tx, rx) = mpsc::channel();
            own_jobs().spawn(b"test lane", "cpus", move || {
                tx.send(cpus()).unwrap();
                Ok(())
            });
            let lane = rx.recv_timeout(SOON).expect("the lane's job ran");
            let leaves = for_each_parallel(&[(); 4], |_| Ok(cpus())).unwrap();
            (lane, leaves)
        });
        assert_eq!(
            lane, process,
            "the lane's thread runs on {lane} of {process} CPUs"
        );
        assert!(
            leaves.iter().all(|&cpus| cpus == process),
            "the leaves' threads run on {leaves:?} of {process} CPUs"
        );
    }
}
