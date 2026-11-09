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
//! encodes as many as fit, then the next as each finishes. Work due now
//! alone runs whatever its size; work done ahead of when it is needed
//! ([`reserve_ahead`]) runs, alone too, only within the jobs' share of what
//! is available ([`Admission::fits`]): admitted alone whatever its size, a
//! leaf labelled ahead reserving 8.0 GB started on a 16 GB host with 0.54 GB
//! available and held its resident memory at 13.1 to 13.5 GB, the host
//! almost unresponsive (2026-11-03). One that does not fit lets later ones
//! that do pass it, a bounded number of times ([`PASS_LIMIT`],
//! [`PASS_WINDOW`]): a large leaf labelled ahead at the head of the queue
//! kept smaller ones that fit waiting for an hour while one job held memory
//! (2026-10-29). A job whose work's window passes while it waits leaves the
//! queue ([`reserve_until`]).
//!
//! Labelling a leaf is one chain of hashes, a core's work for about 80
//! minutes per GiB. With one job at a time for the whole node, a node's
//! later seats missed their renewal's grace. Taken in the order asked, one
//! large leaf held a node's only free core past every other seat's grace
//! (2026-10-28: a leaf of 30 million nodes labelled for 75 minutes of a
//! 54-minute grace); smallest first, the seats with small leaves register.
//!
//! Work done ahead of when it is needed ([`reserve_ahead`]) gives its memory
//! back while more urgent work waits for memory that it holds
//! ([`Reservation::yield_requested`], looked at every few milliseconds of its
//! labelling): a renewal's snapshot waited 40 minutes behind one leaf
//! labelled ahead (2026-10-28). Only as much of it as that work lacks is
//! asked to, the least advanced first: asking all of it whenever any work due
//! now waited gave up 13 leaves' labelling, about 7,800 core-seconds, for
//! epoch proof parts of a few GB each (2026-11-01). Work ahead waits in its
//! own order ([`AheadOrder`]): leaves that cannot be labelled within their
//! renewal's grace first, a seat's together, those of seats needing fewer
//! first, so the memory finishes whole seats; leaves that can fill what is
//! left, and give it back to those. Work that gave its memory back asks for
//! it again at once, in its place, and starts again as soon as it fits:
//! waiting instead until no work due now had held memory for a minute, it
//! waited through every seat's snapshot while the memory was there
//! (2026-11-01).
//!
//! At most [`ahead_jobs_for`] leaves are labelled ahead at once, whatever
//! the memory lets at a moment: one per four of the node's CPUs, and as
//! many of the largest leaves' reservations as the jobs' share of its memory
//! holds beside one such leaf labelled now, never fewer than [`AHEAD_JOBS`]:
//! four of about 4.5 GB each held 17.9 GB of a 32 GB node's 20.5 GB
//! (2026-11-01), and at two, a node of 55 seats registers no more leaves of
//! 30 million nodes than one of 15 (3 an epoch), where without the cap such
//! nodes registered 11 to 49 (2026-11-03). Sized by 16 GiB a leaf, three
//! times what one holds, a 16-thread node of 31 GiB kept two and gave up 8
//! of its 10 seats of such leaves in an epoch (2026-11-06). Persistent
//! sectors, for epochs where persistent storage holds, run ahead on every
//! slot the memory admits, beside those leaves. While a renewal's leaf is
//! labelled now ([`Reservation::labelling_now`]), only [`ahead_beside_due`]
//! go on beside it; the others pause, keeping their memory and layers, and go
//! on once it ends ([`Reservation::wait_while_paused`]): beside three or four
//! leaves labelled ahead, a 16-thread node's renewal leaf ran at under 70% of
//! its estimated pace and missed its grace, where three leaves at a time ran
//! at 85 to 94% (2026-11-01).
//!
//! A node's processes on one host (a master and its standalone workers)
//! admit their jobs together ([`install_host_ledger`],
//! [`crate::storage_ledger`]): each counts what the others' reservations
//! hold against the jobs' share and the others' leaves labelled ahead
//! against [`ahead_jobs_for`]; work due now waiting in one asks the others'
//! labelling ahead to give its memory back and start no more; and one
//! process at a time runs work due now beyond the share alone. Each
//! process admitting its own, several could hold the share of the host's
//! memory, label leaves ahead up to the cap and run work due now beyond
//! the share at once: a process sees another's jobs only once they have
//! allocated. One process at a time decides ([`Admission::grant_turn`]):
//! two asking in the same instant each read no record of the other, and
//! both took the share.
//!
//! A stopping node stops its jobs ([`shut_down`]) before it exits: they use
//! its stores, which exit tears down under a thread still using them.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use quil_types::error::{QuilError, Result};
use tracing::{info, warn};

use crate::storage_ledger::HostLedger;

#[cfg(any(target_os = "macos", test))]
mod macos_memory;

/// The lane of the node's epoch proofs (`storage_epoch_batch`).
pub const EPOCH_PROOF_LANE: &[u8] = b"epoch proofs";

/// Percent of the memory available to the node the jobs may hold together;
/// the rest is headroom for the node and for the estimates' error.
pub const MEMORY_SHARE_PERCENT: u64 = 75;

/// Leaves labelled ahead at once ([`reserve_ahead`]) on the smallest node,
/// whatever the memory lets; more on a larger one ([`ahead_jobs_for`]). Each
/// takes a core and about 152 bytes a node, 4.9 GB for a leaf of 32 million
/// nodes. One asking beyond them waits in its order and starts once one of
/// them ends: labelled, given back to more urgent work, or given up at its
/// epoch's snapshot frame (`crate::storage_labels`). Work ahead for an epoch
/// where persistent storage holds is not counted against them and may take
/// every slot ([`ahead_in_parallel`]).
pub const AHEAD_JOBS: usize = 2;

/// CPUs of the node per leaf labelled ahead ([`ahead_jobs_for`]): a quarter
/// of its threads at most, half its cores where each has two, the rest left
/// to its workers and to leaves labelled now.
const AHEAD_JOB_CPUS: usize = 4;

/// Nodes of the leaf [`ahead_jobs_for`] sizes a node's memory by: the
/// largest leaves mainnet nodes label ahead, measured at 32,339,852 nodes
/// (2026-11-01; 13 of a 15-seat node's 18 leaves on 2026-11-06).
const AHEAD_JOB_NODES: u64 = 32_339_852;

/// The leaves a node of `cpus` CPUs and `memory` bytes labels ahead at once:
/// one per [`AHEAD_JOB_CPUS`] CPUs, and as many leaves of
/// [`AHEAD_JOB_NODES`] as the jobs' share of the memory
/// ([`MEMORY_SHARE_PERCENT`]) holds at the bytes labelling one ahead
/// reserves (`crate::storage_labels::label_ahead_bytes`, 5.4 GB) beside one
/// labelled now (`crate::storage_snapshot::encoding_bytes`, 8.0 GB); never
/// fewer than [`AHEAD_JOBS`]. The memory available at a moment still bounds
/// them (`Admission::fits`).
pub fn ahead_jobs_for(cpus: usize, memory: u64) -> usize {
    let share = u128::from(memory) * u128::from(MEMORY_SHARE_PERCENT) / 100;
    let now = u128::from(crate::storage_snapshot::encoding_bytes(AHEAD_JOB_NODES));
    let each = u128::from(crate::storage_labels::label_ahead_bytes(AHEAD_JOB_NODES)).max(1);
    let by_memory = usize::try_from(share.saturating_sub(now) / each).unwrap_or(usize::MAX);
    (cpus / AHEAD_JOB_CPUS).min(by_memory).max(AHEAD_JOBS)
}

/// Leaves labelled ahead that go on beside a leaf labelled now on the
/// smallest node ([`ahead_beside_due`]).
pub const AHEAD_JOBS_BESIDE_DUE: usize = 1;

/// Of `ahead_jobs` leaves labelled ahead ([`ahead_jobs_for`]), those that go
/// on while a renewal's leaf is labelled now
/// ([`Reservation::labelling_now`]): the most urgent, then the most advanced.
/// The others pause until no leaf is labelled now
/// ([`Reservation::wait_while_paused`]), at the latest at the renewal's
/// grace frame, where its snapshot stops. With none, a leaf of 32 million
/// nodes could not be labelled ahead in what the window has left after a
/// grace; half of them, and at least [`AHEAD_JOBS_BESIDE_DUE`], keep such
/// leaves going and leave the cores to what is due.
pub fn ahead_beside_due(ahead_jobs: usize) -> usize {
    (ahead_jobs / 2).max(AHEAD_JOBS_BESIDE_DUE)
}

/// How often labelling ahead that pauses ([`Reservation::wait_while_paused`])
/// looks whether its work is still of use, besides whenever a reservation
/// changes.
const PAUSE_RECHECK: Duration = Duration::from_secs(1);

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

/// How long work ahead may stay held back for memory before a warning says
/// so, and how often at most it repeats ([`Admission::fits`]): a storage
/// epoch at the ideal frame time, after which the epoch's snapshots have
/// labelled their leaves themselves.
const AHEAD_HELD_BACK_WARN: Duration = Duration::from_millis(
    quil_types::consensus::EPOCH_LENGTH_FRAMES * quil_types::consensus::IDEAL_FRAME_TIME_MS,
);

/// How long a pass waits for its turn to decide
/// ([`crate::storage_ledger::HostLedger::grant_turn`]). A turn lasts about a
/// millisecond: reading the records, a look at the memory, writing a record.
/// This is the most it holds the admission's own lock for one; past it the
/// pass is put off to the next one ([`RECHECK`]).
const GRANT_WAIT: Duration = Duration::from_millis(100);

/// How long another process may keep the turn before this one decides
/// without it ([`Admission::grant_turn`]): the turn of a process stopped or
/// stuck on its disk must not stop the host's storage jobs. Deciding without
/// it risks only what the turn prevents, two grants in one instant.
const GRANT_PATIENCE: Duration = Duration::from_secs(30);

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
        let stable = quil_types::consensus::stable_replica_key_epoch_thread_override();
        let persistent = quil_types::consensus::persistent_storage_epoch_thread_override();
        let profile = quil_types::consensus::storage_seal_profile_thread_override();
        let minimum = quil_types::consensus::min_sector_nodes_thread_override();
        let job: Job = Box::new(move || {
            struct Overrides(
                Option<u64>,
                Option<u64>,
                Option<quil_types::consensus::StorageSealProfile>,
                Option<u64>,
            );
            impl Drop for Overrides {
                fn drop(&mut self) {
                    quil_types::consensus::set_stable_replica_key_epoch_for_thread(self.0);
                    quil_types::consensus::set_persistent_storage_epoch_for_thread(self.1);
                    quil_types::consensus::set_storage_seal_profile_for_thread(self.2);
                    quil_types::consensus::set_min_sector_nodes_for_thread(self.3);
                }
            }
            let _restore = Overrides(
                quil_types::consensus::stable_replica_key_epoch_thread_override(),
                quil_types::consensus::persistent_storage_epoch_thread_override(),
                quil_types::consensus::storage_seal_profile_thread_override(),
                quil_types::consensus::min_sector_nodes_thread_override(),
            );
            quil_types::consensus::set_stable_replica_key_epoch_for_thread(stable);
            quil_types::consensus::set_persistent_storage_epoch_for_thread(persistent);
            quil_types::consensus::set_storage_seal_profile_for_thread(profile);
            quil_types::consensus::set_min_sector_nodes_for_thread(minimum);
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

/// The jobs queued in `lane` behind the one running there: a test counts
/// what a lane holds while its running job waits.
#[cfg(test)]
pub(crate) fn queued_in_lane(lane: &[u8]) -> usize {
    jobs().lanes().get(lane).map_or(0, |lane| lane.queued.len())
}

/// Bytes the storage jobs hold now through their reservations: the labelling
/// buffers of the leaves labelled now and ahead, and the replicas of seals
/// and settlements. A job holds its reservation, as a peak, from its grant.
pub fn held_bytes() -> u64 {
    admission().held_bytes()
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
/// every reservation asked for work due now, whenever asked, and among work
/// ahead in its `order`. Once granted, the work gives the memory back while
/// more urgent work waits for it ([`Reservation::yield_requested`]), so a
/// renewal's snapshot never waits for it for long. `None` once `expired`
/// says the work is of no use any more while it waits ([`reserve_until`]).
/// Work for an `epoch` where persistent storage holds may run on every slot;
/// other work counts against [`AHEAD_JOBS`] ([`ahead_in_parallel`]).
pub fn reserve_ahead(
    bytes: u64,
    order: AheadOrder,
    epoch: u64,
    expired: &dyn Fn() -> bool,
) -> Option<Reservation> {
    let parallel = ahead_in_parallel(epoch);
    admission().reserve_ahead_in(bytes, Some(order), true, parallel, expired)
}

/// Whether work ahead for `epoch` may run on every slot the memory admits
/// rather than within [`AHEAD_JOBS`]: only where persistent storage holds
/// (`quil_types::consensus::persistent_storage_at`), whose sectors are
/// certified side by side. Before it, labelling ahead keeps the cap the
/// legacy leaves were measured with.
pub fn ahead_in_parallel(epoch: u64) -> bool {
    quil_types::consensus::persistent_storage_at(epoch)
}

/// [`reserve_ahead`] for work that holds its memory briefly and is never
/// asked to give it back (reading a leaf's data).
pub fn reserve_ahead_brief(
    bytes: u64,
    order: AheadOrder,
    expired: &dyn Fn() -> bool,
) -> Option<Reservation> {
    admission().reserve_ordered(bytes, Urgency::Ahead, Some(order), false, expired)
}

/// A place for a seat's work ahead ([`AheadOrder::seat`]): seats asking
/// later go later.
pub fn ahead_place() -> u64 {
    admission().next_ticket()
}

/// Where work ahead waits among other work ahead ([`reserve_ahead`]), first
/// lowest, and which work ahead gives its memory back to which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AheadOrder {
    /// Whether the work could also be done when it is needed (a leaf its
    /// snapshot labels within half the renewal's grace): such work goes
    /// after all that could not, and gives its memory back to it while that
    /// waits.
    pub deferrable: bool,
    /// How many leaves of its seat could not: seats needing fewer go first,
    /// so the memory finishes whole seats.
    pub seat_leaves: u32,
    /// Its seat's place ([`ahead_place`]): a seat's leaves go together, in
    /// the order the seats asked.
    pub seat: u64,
    /// Its leaf's place in its seat.
    pub leaf: u64,
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

fn admission() -> &'static Admission {
    static ADMISSION: OnceLock<Admission> = OnceLock::new();
    ADMISSION.get_or_init(|| {
        let slots = job_slots();
        let mut admission = Admission::new(slots, Box::new(available_memory));
        // `job_slots` is one per CPU less the master's.
        let cpus = slots.saturating_add(1);
        // Tests size the node's admission as the smallest node's, whatever
        // the host; those of a larger node's cap build their own.
        let memory = if cfg!(test) { None } else { total_memory() };
        admission.ahead_jobs = memory.map_or(AHEAD_JOBS, |memory| ahead_jobs_for(cpus, memory));
        admission.ahead_beside_due = ahead_beside_due(admission.ahead_jobs);
        info!(
            ahead_jobs = admission.ahead_jobs,
            beside_due = admission.ahead_beside_due,
            cpus,
            memory_bytes = memory.unwrap_or(0),
            "storage labelling ahead sized for this node: up to this many leaves are labelled \
             ahead at once, and this many go on beside a leaf labelled now"
        );
        admission
    })
}

/// Admit this process's storage jobs together with the node's other
/// processes on this host that use `dir` ([`crate::storage_ledger`]). The
/// first call decides; a process that never calls it admits its own alone.
pub fn install_host_ledger(dir: &std::path::Path) {
    match HostLedger::open(dir) {
        Ok(ledger) => {
            if admission().use_ledger(ledger) {
                info!(dir = %dir.display(),
                    "storage jobs are admitted with the node's other processes on this host: \
                     what their jobs hold counts against the jobs' share of the memory");
            }
        }
        Err(error) => warn!(dir = %dir.display(), %error, scope = "this node",
            action = "check that this directory is writable by every process of the node",
            "storage jobs of this process are admitted without the node's other processes on \
             this host: their jobs together may exceed the share of the memory"),
    }
}

/// This process's record among the host's ([`install_host_ledger`]), once
/// in use: the label store counts its labels still to write there
/// (`crate::storage_labels::install`).
pub(crate) fn host_ledger() -> Option<&'static HostLedger> {
    admission().ledger.get()
}

/// [`install_host_ledger`] for a master that runs storage jobs beside
/// standalone workers (a cluster's master proves the node's epoch proofs
/// from their parts), in the ledger directory of the workers' labels
/// (`labels_dir`, [`crate::storage_labels::host_ledger_dir`]). The master
/// keeps no labels itself.
pub fn install_master_ledger(labels_dir: &std::path::Path) {
    install_host_ledger(&crate::storage_labels::host_ledger_dir(labels_dir));
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
    #[cfg(test)]
    if let Some(slots) = Some(TEST_SLOTS.load(Ordering::SeqCst)).filter(|&s| s > 0) {
        return slots;
    }
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
    let persistent = quil_types::consensus::persistent_storage_epoch_thread_override();
    let profile = quil_types::consensus::storage_seal_profile_thread_override();
    let minimum = quil_types::consensus::min_sector_nodes_thread_override();
    std::thread::scope(|scope| {
        for slot in 0..job_slots().min(items.len()) {
            std::thread::Builder::new()
                .name(format!("stor-leaf-{slot}"))
                .spawn_scoped(scope, || {
                    quil_types::consensus::set_stable_replica_key_epoch_for_thread(stable_key);
                    quil_types::consensus::set_persistent_storage_epoch_for_thread(persistent);
                    quil_types::consensus::set_storage_seal_profile_for_thread(profile);
                    quil_types::consensus::set_min_sector_nodes_for_thread(minimum);
                    on_process_cpus();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= items.len()
                            || failed.load(Ordering::Relaxed)
                            || jobs().stopping()
                        {
                            break;
                        }
                        let result = work(&items[index]);
                        if result.is_err() {
                            failed.store(true, Ordering::Relaxed);
                        }
                        results.lock().unwrap_or_else(PoisonError::into_inner)[index] =
                            Some(result);
                    }
                })
                .expect("spawn a storage leaf thread");
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

/// Jobs a test lets the node's admission hold at once
/// ([`set_job_slots_for_test`]); 0 for the host's count ([`job_slots`]).
#[cfg(test)]
static TEST_SLOTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Make the node's admission ([`reserve`]) hold `slots` jobs at once
/// whatever this host's CPUs: a test of leaves side by side needs as many
/// places on a 3-CPU runner as on a larger one. Call it before the
/// process's first storage job, as the admission counts its slots once. For
/// tests that run in a process of their own (nextest).
#[cfg(test)]
pub(crate) fn set_job_slots_for_test(slots: usize) {
    TEST_SLOTS.store(slots, Ordering::SeqCst);
    assert_eq!(
        admission().slots,
        slots.max(1),
        "the job slots are set before the process's first storage job"
    );
}

/// Memory a test sizes the node's jobs against ([`set_available_for_test`]);
/// 0 for the host's.
#[cfg(test)]
static TEST_AVAILABLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Make the node's admission ([`reserve`]) see `bytes` available to the node,
/// or the host's memory again with `None`: a test of jobs that must or must
/// not fit beside each other sizes them against it. For tests that run in a
/// process of their own (nextest).
#[cfg(test)]
pub(crate) fn set_available_for_test(bytes: Option<u64>) {
    TEST_AVAILABLE.store(bytes.unwrap_or(0), Ordering::SeqCst);
}

/// Leaves the node labels now ([`Reservation::labelling_now`]), for tests.
#[cfg(test)]
pub(crate) fn labelling_now_count() -> usize {
    admission().state().labelling_now
}

/// Leaves labelled ahead that pause now ([`Reservation::wait_while_paused`]),
/// for tests.
#[cfg(test)]
pub(crate) fn pausing_count() -> usize {
    admission().state().pausing
}

/// Bytes available for additional work. macOS uses a pressure-aware process
/// budget; other hosts use available RAM, bounded by their container's limit.
/// `None` means the platform could not be queried, rather than zero headroom.
fn available_memory() -> Option<u64> {
    #[cfg(test)]
    if let Some(bytes) = Some(TEST_AVAILABLE.load(Ordering::SeqCst)).filter(|&b| b > 0) {
        return Some(bytes);
    }
    #[cfg(target_os = "macos")]
    {
        macos_memory::available()
    }
    #[cfg(not(target_os = "macos"))]
    {
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
}

/// Bytes that must be available for `bytes` of work ahead to fit with no
/// job holding memory ([`Admission::fits`], [`MEMORY_SHARE_PERCENT`]).
fn needs_available(bytes: u64) -> u64 {
    let needed = u128::from(bytes) * 100 / u128::from(MEMORY_SHARE_PERCENT);
    u64::try_from(needed).unwrap_or(u64::MAX)
}

/// Bytes of memory the node has at all: the host's, or its container's limit
/// when less. `None` when the host does not say.
fn total_memory() -> Option<u64> {
    let mut system = sysinfo::System::new();
    system.refresh_memory();
    let host = system.total_memory();
    if host == 0 {
        return None;
    }
    let container = system.cgroup_limits().map(|limits| limits.total_memory);
    Some(container.map_or(host, |container| container.min(host)))
}

/// Memory a job holds while it works, granted by [`reserve`] and given back
/// when dropped.
#[must_use = "the memory is given back when the reservation drops"]
pub struct Reservation {
    admission: &'static Admission,
    bytes: u64,
    ticket: u64,
    /// Whether it labels a leaf now ([`Self::labelling_now`]).
    labelling: bool,
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
        if let Some(yielding) = state.yielding.get_mut(&self.ticket) {
            yielding.bytes = bytes;
        }
        state.stale = true;
        self.admission.publish(&state);
        drop(state);
        self.admission.changed.notify_all();
    }

    /// Whether work ahead holding this reservation ([`reserve_ahead`])
    /// should give it back, dropping it, and ask for it again, granted once
    /// it fits: more urgent work waits for memory this holds
    /// ([`Admission::ask_yields`]). Never for work due now, nor for a brief
    /// reservation ([`reserve_ahead_brief`]).
    pub fn yield_requested(&self) -> bool {
        let mut state = self.admission.state();
        self.admission.look_elsewhere(&mut state);
        state
            .yielding
            .get(&self.ticket)
            .is_some_and(|yielding| yielding.asked)
    }

    /// Mark this reservation, for work due now, as labelling a leaf now (a
    /// renewal's snapshot without labels kept ahead for it): while it is
    /// held, labelling ahead beyond [`ahead_beside_due`] pauses and
    /// none more starts, so the leaf has the node's cores (2026-11-01: beside
    /// three or four leaves labelled ahead, a renewal's leaf of 15 million
    /// nodes estimated at 37 minutes was still labelled after 3,137 s, at its
    /// grace).
    pub fn labelling_now(&mut self) {
        if std::mem::replace(&mut self.labelling, true) {
            return;
        }
        let mut state = self.admission.state();
        state.labelling_now += 1;
        state.stale = true;
        drop(state);
        self.admission.changed.notify_all();
    }

    /// Whether labelling ahead holding this reservation pauses now: a leaf
    /// is labelled now, and [`ahead_beside_due`] leaves labelled ahead
    /// more urgent or more advanced go on beside it.
    pub fn paused(&self) -> bool {
        self.admission.pauses(&self.admission.state(), self.ticket)
    }

    /// Pause, holding the memory, while [`Self::paused`] says so: until no
    /// leaf is labelled now or this goes on beside it, it is asked to give
    /// its memory back ([`Self::yield_requested`]), or `gone` says its work
    /// is of no use any more, looked at every [`PAUSE_RECHECK`]. Returns how
    /// long it paused.
    pub fn wait_while_paused(&self, gone: &dyn Fn() -> bool) -> Duration {
        let started = Instant::now();
        let mut state = self.admission.state();
        if !self.admission.pauses(&state, self.ticket) {
            return Duration::ZERO;
        }
        state.pausing += 1;
        while self.admission.pauses(&state, self.ticket) {
            state = self
                .admission
                .changed
                .wait_timeout(state, PAUSE_RECHECK)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
            // Not under the lock: the caller's look may take its own.
            drop(state);
            let gone = gone();
            state = self.admission.state();
            if gone {
                break;
            }
        }
        state.pausing = state.pausing.saturating_sub(1);
        started.elapsed()
    }

    /// Note that the work holding this reservation has done `done` of `of`
    /// parts: of work asked to give memory back, the least advanced is asked
    /// first, losing the least.
    pub fn progress(&self, done: u64, of: u64) {
        let millionths = u128::from(done.min(of)) * 1_000_000 / u128::from(of.max(1));
        if let Some(yielding) = self.admission.state().yielding.get_mut(&self.ticket) {
            yielding.millionths = millionths as u32;
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.admission.state();
        state.reserved = state.reserved.saturating_sub(self.bytes);
        state.holders = state.holders.saturating_sub(1);
        state.yielding.remove(&self.ticket);
        if self.labelling {
            state.labelling_now = state.labelling_now.saturating_sub(1);
        }
        if state
            .alone
            .as_ref()
            .is_some_and(|(holder, _)| *holder == self.ticket)
        {
            state.alone = None;
        }
        state.stale = true;
        self.admission.publish(&state);
        drop(state);
        self.admission.changed.notify_all();
    }
}

/// Grants the jobs' reservations ([`reserve`]): those for work due now
/// smallest first, then those for work ahead in their order
/// ([`AheadOrder`]), each once it fits ([`Admission::admit_waiting`]).
pub struct Admission {
    state: Mutex<State>,
    /// [`PASS_WINDOW`], shorter in tests.
    pass_window: Duration,
    changed: Condvar,
    slots: usize,
    /// [`ahead_jobs_for`]; more in tests of the memory alone.
    ahead_jobs: usize,
    /// Work ahead in parallel ([`ahead_in_parallel`]) at once: the slots.
    parallel_ahead_jobs: usize,
    /// [`ahead_beside_due`].
    ahead_beside_due: usize,
    available: Box<dyn Fn() -> Option<u64> + Send + Sync>,
    /// [`LOOK_WINDOW`], shorter in tests.
    window: Duration,
    /// [`AHEAD_HELD_BACK_WARN`], shorter in tests.
    held_back_warn: Duration,
    /// The host's other processes' jobs ([`install_host_ledger`]).
    ledger: OnceLock<HostLedger>,
    /// Whether a failed write of this process's record was logged.
    ledger_warned: AtomicBool,
    /// [`GRANT_PATIENCE`], shorter in tests.
    grant_patience: Duration,
}

#[derive(Default)]
struct State {
    /// What the host's other processes' jobs hold, read at each pass
    /// ([`Admission::admit_waiting`]).
    others: crate::storage_ledger::Held,
    /// Whether another process holds the host's alone lock, read with
    /// [`State::others`].
    alone_elsewhere: bool,
    /// The host's alone lock and the reservation holding it: work due now
    /// beyond the jobs' share, alone in this process ([`Admission::fits`]).
    alone: Option<(u64, std::fs::File)>,
    /// The alone lock taken by the fit being granted.
    alone_pending: Option<std::fs::File>,
    /// Since when another process has kept the turn to decide, and whether
    /// this one has logged deciding without it ([`Admission::grant_turn`]).
    grant_busy: Option<(Instant, bool)>,
    /// Whether this process's labelling ahead gives memory back to another
    /// process's work due now, logged as it begins and ends.
    yielding_elsewhere: bool,
    /// Bytes the reservations held come to.
    reserved: u64,
    /// Reservations held.
    holders: usize,
    /// The reservations waiting, in the order looked at
    /// ([`Admission::admit_waiting`], [`Waiting::place`]).
    waiting: VecDeque<Waiting>,
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
    /// Reservations held for work ahead that gives its memory back when
    /// asked ([`Reservation::yield_requested`]), by ticket.
    yielding: HashMap<u64, Yielding>,
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
    /// Reservations held for leaves labelled now
    /// ([`Reservation::labelling_now`]).
    labelling_now: usize,
    /// Labelling ahead pausing ([`Reservation::wait_while_paused`]).
    pausing: usize,
    /// Since when work ahead is held back for memory ([`Admission::fits`]),
    /// until some is granted or none waits.
    held_back: Option<HeldBack>,
}

/// Work ahead held back for memory ([`State::held_back`]).
#[derive(Debug, Clone, Copy)]
struct HeldBack {
    since: Instant,
    /// The bytes of the last work ahead that did not fit with no job
    /// holding memory.
    bytes: u64,
    /// When it was last warned of ([`AHEAD_HELD_BACK_WARN`]).
    warned: Option<Instant>,
}

/// A reservation waiting ([`State::waiting`]).
#[derive(Debug, Clone, Copy)]
struct Waiting {
    ticket: u64,
    urgency: Urgency,
    bytes: u64,
    /// Its place in line, first lowest: work due now smallest first, those
    /// of one size in the order asked; then work ahead in its order
    /// ([`AheadOrder`]), in the order asked within one.
    place: (u8, u64, u64, u64, u64),
    /// Whether, granted, it gives its memory back when asked.
    yields: bool,
    /// Whether it is work ahead in parallel ([`ahead_in_parallel`]), not
    /// counted against [`AHEAD_JOBS`].
    parallel: bool,
}

impl Waiting {
    /// How urgent it is, most first: work due now, work ahead that could not
    /// be done when needed, work ahead that could.
    fn rank(&self) -> u8 {
        self.place.0
    }
}

/// A reservation held for work ahead that gives its memory back when asked
/// ([`State::yielding`]).
#[derive(Debug, Clone, Copy)]
struct Yielding {
    rank: u8,
    bytes: u64,
    /// Its work's progress ([`Reservation::progress`]), in millionths.
    millionths: u32,
    /// Whether it was asked to give its memory back.
    asked: bool,
    /// Whether it is work ahead in parallel ([`ahead_in_parallel`]).
    parallel: bool,
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

/// What keeps a waiting job from starting: every slot held (`job_slots`),
/// the reservations held plus its own over the jobs' share or the share
/// unreadable (`memory`), else it would fit and a job ahead of it in order
/// holds its place (`queue_order`).
fn binding_limit(
    holders: usize,
    slots: usize,
    reserved: u64,
    bytes: u64,
    share: Option<u64>,
) -> &'static str {
    if holders >= slots {
        "job_slots"
    } else if share.is_none_or(|share| u128::from(reserved) + u128::from(bytes) > u128::from(share))
    {
        "memory"
    } else {
        "queue_order"
    }
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
            ahead_jobs: AHEAD_JOBS,
            parallel_ahead_jobs: slots.max(1),
            ahead_beside_due: AHEAD_JOBS_BESIDE_DUE,
            available,
            window: LOOK_WINDOW,
            held_back_warn: AHEAD_HELD_BACK_WARN,
            ledger: OnceLock::new(),
            ledger_warned: AtomicBool::new(false),
            grant_patience: GRANT_PATIENCE,
        }
    }

    /// Admit with the host's other processes from now on; false when a
    /// ledger was in use already.
    pub fn use_ledger(&self, ledger: HostLedger) -> bool {
        self.ledger.set(ledger).is_ok()
    }

    /// This process's turn to decide among the host's
    /// ([`crate::storage_ledger::HostLedger::grant_turn`]), kept from reading
    /// the others' records until its own says what it granted, so two
    /// processes never decide on the same records. `None` when another
    /// process has it: put off to the next pass, up to `grant_patience`.
    /// `Some(None)` to decide without a turn: no ledger, the directory
    /// cannot be used (then neither can the records, so the processes admit
    /// alone, as `install_host_ledger` warns), or past the patience.
    fn grant_turn(&self, state: &mut State) -> Option<Option<std::fs::File>> {
        let Some(ledger) = self.ledger.get() else {
            return Some(None);
        };
        match ledger.grant_turn(GRANT_WAIT) {
            Ok(Some(turn)) => {
                if let Some((since, true)) = state.grant_busy.take() {
                    info!(
                        seconds = since.elapsed().as_secs_f64(),
                        "storage jobs decide in turn again: the node's other process gave up its \
                         turn"
                    );
                }
                Some(Some(turn))
            }
            Err(error) => {
                if !self.ledger_warned.swap(true, Ordering::Relaxed) {
                    warn!(dir = %ledger.dir().display(), %error, scope = "this node",
                        action = "check that this directory is writable by every process of the node",
                        "storage job admission cannot take its turn among the node's other \
                         processes on this host: it decides without them; logged once");
                }
                Some(None)
            }
            Ok(None) => {
                let (since, warned) = state.grant_busy.get_or_insert((Instant::now(), false));
                if since.elapsed() < self.grant_patience {
                    return None;
                }
                if !*warned {
                    *warned = true;
                    warn!(dir = %ledger.dir().display(), seconds = since.elapsed().as_secs_f64(),
                        scope = "this node",
                        action = "check for a stopped or stuck process of the node, or a stalled disk",
                        "storage job admission goes on without its turn: another process of the \
                         node has kept it past the bound, so jobs asked in the same instant could \
                         together exceed the share until it gives it up");
                }
                Some(None)
            }
        }
    }

    /// Read what the host's other processes hold ([`State::others`]).
    fn read_others(&self, state: &mut State) {
        let Some(ledger) = self.ledger.get() else {
            return;
        };
        state.others = ledger.others();
        state.alone_elsewhere = state.alone.is_none() && ledger.alone_elsewhere();
    }

    /// Write what this process's jobs hold to its record, for the host's
    /// other processes.
    fn publish(&self, state: &State) {
        let Some(ledger) = self.ledger.get() else {
            return;
        };
        let held = crate::storage_ledger::Held {
            bytes: state.reserved,
            ahead: state.yielding.len() as u64,
            due_waiting: state.holders < self.slots
                && state
                    .waiting
                    .iter()
                    .any(|waiting| waiting.urgency == Urgency::Due),
        };
        if let Err(error) = ledger.publish(held) {
            if !self.ledger_warned.swap(true, Ordering::Relaxed) {
                warn!(dir = %ledger.dir().display(), %error, scope = "this node",
                    action = "check the free space and permissions of this directory",
                    "storage job admission record not written: the node's other processes on \
                     this host admit their jobs without what this one holds; logged once");
            }
        }
    }

    /// With the host's other processes ([`install_host_ledger`]), a pass
    /// over the waiting reservations ([`Self::admit_waiting`]) once
    /// [`RECHECK`] passed since the last, also with none waiting here: work
    /// due now in another process asks labelling ahead here to give its
    /// memory back.
    fn look_elsewhere(&self, state: &mut State) {
        if self.ledger.get().is_some() && state.last_pass.is_none_or(|at| at.elapsed() >= RECHECK) {
            self.admit_waiting(state);
        }
    }

    /// While work due now in another process waits for memory, or runs
    /// alone beyond the share, ask this process's labelling ahead to give
    /// its memory back ([`Reservation::yield_requested`]).
    fn yield_to_elsewhere(&self, state: &mut State) {
        let wanted = state.others.due_waiting || state.alone_elsewhere;
        if wanted {
            let mut asked = 0usize;
            for yielding in state.yielding.values_mut() {
                if !yielding.asked {
                    yielding.asked = true;
                    asked += 1;
                }
            }
            if asked > 0 || !state.yielding_elsewhere {
                info!(
                    asked,
                    other_processes_bytes = state.others.bytes,
                    alone_elsewhere = state.alone_elsewhere,
                    "storage jobs ahead give memory back to another process of the node on this \
                     host: its work due now waits for memory or runs alone; no more labelling \
                     ahead starts here until it has its memory: an expected wait"
                );
            }
        } else if state.yielding_elsewhere {
            info!(
                "storage jobs ahead may start again: no other process of the node on this \
                   host waits for memory for work due now"
            );
        }
        state.yielding_elsewhere = wanted;
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Bytes the reservations held come to now.
    pub fn held_bytes(&self) -> u64 {
        self.state().reserved
    }

    /// Reserve `bytes` ([`reserve`]).
    pub fn reserve(&'static self, bytes: u64) -> Reservation {
        self.reserve_with(bytes, Urgency::Due)
    }

    /// Reserve `bytes` for work of `urgency` ([`reserve`], [`reserve_ahead`]):
    /// work ahead in the order asked, giving its memory back when asked.
    pub fn reserve_with(&'static self, bytes: u64, urgency: Urgency) -> Reservation {
        let Some(reservation) = self.reserve_until(bytes, urgency, &|| false) else {
            unreachable!("a reservation whose work never expires does not leave the queue")
        };
        reservation
    }

    /// Reserve `bytes` for work of `urgency`, or `None` once `expired` says
    /// its work is of no use any more while it waits, looked at whenever it
    /// looks at the memory again ([`reserve_until`]): work ahead in the
    /// order asked, giving its memory back when asked.
    pub fn reserve_until(
        &'static self,
        bytes: u64,
        urgency: Urgency,
        expired: &dyn Fn() -> bool,
    ) -> Option<Reservation> {
        self.reserve_ordered(bytes, urgency, None, true, expired)
    }

    /// A ticket: the order reservations and seats ([`ahead_place`]) asked.
    fn next_ticket(&self) -> u64 {
        let mut state = self.state();
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        ticket
    }

    /// [`Self::reserve_until`], work ahead waiting in `order` (the order
    /// asked if none) and giving its memory back when asked if it `yields`;
    /// counted against [`AHEAD_JOBS`].
    pub fn reserve_ordered(
        &'static self,
        bytes: u64,
        urgency: Urgency,
        order: Option<AheadOrder>,
        yields: bool,
        expired: &dyn Fn() -> bool,
    ) -> Option<Reservation> {
        self.reserve_classed(bytes, urgency, order, yields, false, expired)
    }

    /// [`Self::reserve_ordered`] for work ahead, in parallel
    /// ([`ahead_in_parallel`]) or not.
    pub fn reserve_ahead_in(
        &'static self,
        bytes: u64,
        order: Option<AheadOrder>,
        yields: bool,
        parallel: bool,
        expired: &dyn Fn() -> bool,
    ) -> Option<Reservation> {
        self.reserve_classed(bytes, Urgency::Ahead, order, yields, parallel, expired)
    }

    fn reserve_classed(
        &'static self,
        bytes: u64,
        urgency: Urgency,
        order: Option<AheadOrder>,
        yields: bool,
        parallel: bool,
        expired: &dyn Fn() -> bool,
    ) -> Option<Reservation> {
        let parallel = parallel && urgency == Urgency::Ahead;
        let mut state = self.state();
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        // Work due now goes before every reservation for work ahead, and
        // before larger ones for work due now: the shortest ends first.
        let place = match urgency {
            Urgency::Due => (0, bytes, ticket, 0, 0),
            Urgency::Ahead => {
                let order = order.unwrap_or(AheadOrder {
                    deferrable: false,
                    seat_leaves: 0,
                    seat: ticket,
                    leaf: 0,
                });
                (
                    1 + u8::from(order.deferrable),
                    u64::from(order.seat_leaves),
                    order.seat,
                    order.leaf,
                    ticket,
                )
            }
        };
        let position = state
            .waiting
            .iter()
            .position(|waiting| waiting.place > place)
            .unwrap_or(state.waiting.len());
        state.waiting.insert(
            position,
            Waiting {
                ticket,
                urgency,
                bytes,
                place,
                yields: yields && urgency == Urgency::Ahead,
                parallel,
            },
        );
        state.stale = true;
        let started = Instant::now();
        let mut waited = false;
        while !self.take_grant(&mut state, ticket) {
            if !waited {
                waited = true;
                let (labelling, cap) = (
                    self.ahead_holding(&state, parallel),
                    self.ahead_cap(&state, parallel),
                );
                let look = state.last_look;
                if yields && urgency == Urgency::Ahead && self.ahead_full(&state, parallel) {
                    info!(
                        bytes,
                        labelling_ahead = labelling,
                        cap,
                        parallel,
                        labelling_now = state.labelling_now,
                        "storage job ahead waits for a labelling slot: only cap leaves are \
                         labelled ahead at once, fewer while a renewal's leaf is labelled now, \
                         for the memory and cores that work takes; it starts in its order once \
                         one of them ends: an expected wait"
                    );
                } else {
                    let limit = binding_limit(
                        state.holders,
                        self.slots,
                        state.reserved.saturating_add(state.others.bytes),
                        bytes,
                        look.map(|look| look.share),
                    );
                    info!(
                        bytes,
                        limit,
                        reserved = state.reserved,
                        other_processes_bytes = state.others.bytes,
                        jobs = state.holders,
                        slots = self.slots,
                        available = look.map(|look| look.available),
                        idle_available = look.map(|look| look.idle_available),
                        window_low = look.map(|look| look.window_low),
                        share = look.map(|look| look.share),
                        ahead = state
                            .waiting
                            .iter()
                            .position(|waiting| waiting.ticket == ticket)
                            .unwrap_or(0),
                        due = urgency == Urgency::Due,
                        "storage job waits to start: `limit` is what binds: memory (the \
                         reservations held plus this job exceed the share), job_slots (every \
                         slot is held) or queue_order (it would fit, but a job ahead of it in \
                         order waits for memory and holds its place); an expected wait that \
                         ends when a job ends"
                    );
                }
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
            ticket,
            labelling: false,
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
    /// - work ahead that could be done when needed passes work ahead that
    ///   could not only while none is asked to give memory back to it, and
    ///   counts as no pass of it: it fills the memory the other cannot use,
    ///   and gives it back once the other would fit;
    /// - labelling ahead waits while as many leaves are labelled ahead as
    ///   may be ([`Self::ahead_cap`]), whatever the memory, and is not
    ///   counted as passed meanwhile;
    /// - nothing of its rank passes one passed [`PASS_LIMIT`] times by its
    ///   rank, or first passed [`PASS_WINDOW`] ago. It holds its place until
    ///   it fits beside the jobs holding memory, at the latest once they end
    ///   and it runs alone. Work ahead that does not fit with no job holding
    ///   memory holds no place: no job ending will make it fit.
    ///
    /// Then asks work ahead holding memory to give it back, as much as the
    /// first in line lack ([`Self::ask_yields`]).
    ///
    /// All of it in this process's turn to decide among the host's
    /// ([`Self::grant_turn`]), ending once its record is written; when
    /// another process has the turn the pass is put off, what changed stays
    /// [`State::stale`], and the next one looks after [`RECHECK`].
    fn admit_waiting(&self, state: &mut State) {
        state.last_pass = Some(Instant::now());
        let Some(_turn) = self.grant_turn(state) else {
            return;
        };
        state.stale = false;
        self.read_others(state);
        self.yield_to_elsewhere(state);
        self.ask_yields(state);
        let asked = state.yielding.values().any(|yielding| yielding.asked);
        let mut skipped: Vec<(u64, u8)> = Vec::new();
        // The rank of one holding its place: nothing of its rank passes it.
        let mut holding: Option<u8> = None;
        let mut granted = false;
        // Work ahead granted, and the bytes of work ahead that did not fit
        // with no job holding memory.
        let (mut ahead_granted, mut alone_short) = (false, None);
        let mut index = 0;
        while index < state.waiting.len() && state.holders < self.slots {
            let waiting = state.waiting[index];
            let rank = waiting.rank();
            let most_urgent_skipped = skipped.iter().map(|&(_, rank)| rank).min();
            if most_urgent_skipped.is_some_and(|skipped| skipped < rank && (skipped == 0 || asked))
            {
                break;
            }
            if holding == Some(rank) {
                index += 1;
                continue;
            }
            if waiting.yields && self.ahead_full(state, waiting.parallel) {
                index += 1;
                continue;
            }
            let alone = state.holders == 0;
            if self.fits(state, waiting.bytes, waiting.urgency) {
                ahead_granted |= waiting.urgency == Urgency::Ahead;
                state.waiting.remove(index);
                state.reserved = state.reserved.saturating_add(waiting.bytes);
                state.holders += 1;
                state.granted.insert(waiting.ticket);
                if let Some(lock) = state.alone_pending.take() {
                    state.alone = Some((waiting.ticket, lock));
                }
                if waiting.yields {
                    state.yielding.insert(
                        waiting.ticket,
                        Yielding {
                            rank,
                            bytes: waiting.bytes,
                            millionths: 0,
                            asked: false,
                            parallel: waiting.parallel,
                        },
                    );
                }
                let now = Instant::now();
                for &(passed, _) in skipped.iter().filter(|&&(_, skipped)| skipped == rank) {
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
            if alone && waiting.urgency == Urgency::Ahead {
                alone_short.get_or_insert(waiting.bytes);
            } else if self.holds_place(state, waiting.ticket, waiting.urgency, waiting.bytes) {
                holding = Some(rank);
            }
            skipped.push((waiting.ticket, rank));
            index += 1;
        }
        self.note_held_back(state, ahead_granted, alone_short);
        if granted {
            self.ask_yields(state);
            self.changed.notify_all();
        }
        self.publish(state);
    }

    /// Note work ahead held back for memory ([`State::held_back`]) after a
    /// pass: it began to be when work ahead of `alone_short` bytes did not
    /// fit with no job holding memory, and ends once work ahead is granted
    /// or none waits. Logged as it begins and ends, and warned of once it
    /// lasted [`AHEAD_HELD_BACK_WARN`], at most once as long.
    fn note_held_back(&self, state: &mut State, ahead_granted: bool, alone_short: Option<u64>) {
        let ahead_waits = state
            .waiting
            .iter()
            .any(|waiting| waiting.urgency == Urgency::Ahead);
        if ahead_granted || !ahead_waits {
            let outcome = if ahead_granted {
                "work ahead has its memory"
            } else {
                "no work ahead waits: done, or given up at its epoch's snapshot frame"
            };
            self.end_held_back(state, outcome);
            return;
        }
        let look = state.last_look;
        let (available, share) = (look.map(|look| look.available), look.map(|look| look.share));
        match (state.held_back.is_some(), alone_short) {
            (true, Some(bytes)) => {
                if let Some(held_back) = state.held_back.as_mut() {
                    held_back.bytes = bytes;
                }
            }
            (true, None) => {}
            (false, None) => return,
            (false, Some(bytes)) => {
                info!(
                    bytes,
                    available,
                    share,
                    needs_available = needs_available(bytes),
                    waiting_ahead = state
                        .waiting
                        .iter()
                        .filter(|waiting| waiting.urgency == Urgency::Ahead)
                        .count(),
                    "storage jobs ahead held back for memory: no job holds memory, yet the work \
                     ahead needs more than the jobs' share of what this host has available; work \
                     due now still runs whatever its size. It starts once this host has \
                     needs_available bytes available, or is given up at its epoch's snapshot \
                     frame, from which the snapshot labels its leaves itself: an expected wait \
                     on a host short of memory"
                );
                state.held_back = Some(HeldBack {
                    since: Instant::now(),
                    bytes,
                    warned: None,
                });
            }
        }
        let Some(held_back) = state.held_back.as_mut() else {
            return;
        };
        let last = held_back.warned.unwrap_or(held_back.since);
        if last.elapsed() < self.held_back_warn {
            return;
        }
        held_back.warned = Some(Instant::now());
        warn!(
            bytes = held_back.bytes,
            available,
            share,
            needs_available = needs_available(held_back.bytes),
            seconds = held_back.since.elapsed().as_secs_f64(),
            "storage jobs ahead held back for memory for a whole epoch: this host has too little \
             memory available to label leaves ahead, so each snapshot labels its leaves itself \
             within its renewal's grace, and a seat whose leaf cannot be labelled in time renews \
             without a storage registration that epoch; free memory on this host (fewer data workers, other \
             processes) so that needs_available bytes are available"
        );
    }

    /// End work ahead held back for memory ([`Self::note_held_back`]),
    /// logged with `outcome`.
    fn end_held_back(&self, state: &mut State, outcome: &'static str) {
        let Some(held_back) = state.held_back.take() else {
            return;
        };
        info!(
            seconds = held_back.since.elapsed().as_secs_f64(),
            bytes = held_back.bytes,
            available = state.last_look.map(|look| look.available),
            outcome,
            "storage jobs ahead no longer held back for memory"
        );
    }

    /// Ask work ahead holding memory ([`State::yielding`]) less urgent than
    /// the first in line to give it back, as much as those of that rank
    /// lack: the least urgent first, of those the least advanced
    /// ([`Reservation::progress`]), until as many of them as can fit would.
    /// None when even all of it would not let the first fit (work due now
    /// holds the rest): it would give its memory back for nothing.
    fn ask_yields(&self, state: &mut State) {
        let Some(head) = state.waiting.front().map(Waiting::rank) else {
            return;
        };
        let mut candidates: Vec<(u64, Yielding)> = state
            .yielding
            .iter()
            .filter(|(_, yielding)| yielding.rank > head)
            .map(|(&ticket, &yielding)| (ticket, yielding))
            .collect();
        if candidates.is_empty() {
            return;
        }
        // Those asked already first: they are leaving.
        candidates.sort_by_key(|&(ticket, yielding)| {
            (
                !yielding.asked,
                std::cmp::Reverse(yielding.rank),
                yielding.millionths,
                std::cmp::Reverse(ticket),
            )
        });
        let wanted: Vec<(u64, bool, bool)> = state
            .waiting
            .iter()
            .take_while(|waiting| waiting.rank() == head)
            .map(|waiting| (waiting.bytes, waiting.yields, waiting.parallel))
            .collect();
        let share = self.share(state);
        let (holders, reserved, slots) = (state.holders, state.reserved, self.slots);
        let (labelling, cap) = (state.yielding.len(), self.ahead_cap(state, true));
        let capped = self.ahead_holding(state, false);
        let capped_cap = self.ahead_cap(state, false);
        // Whether the first `count` wanted fit once `freed` bytes of `jobs`
        // holders, `capped_jobs` of them counted against [`AHEAD_JOBS`],
        // are given back. Labelling ahead wanted beyond its cap also needs
        // places given back: each holder of its class that yields gives one.
        let fit = |jobs: usize, capped_jobs: usize, freed: u64, count: usize| {
            let labelling_wanted = wanted[..count]
                .iter()
                .filter(|&&(_, yields, _)| yields)
                .count();
            if labelling_wanted > 0 && labelling.saturating_sub(jobs) + labelling_wanted > cap {
                return false;
            }
            let capped_wanted = wanted[..count]
                .iter()
                .filter(|&&(_, yields, parallel)| yields && !parallel)
                .count();
            if capped_wanted > 0 && capped.saturating_sub(capped_jobs) + capped_wanted > capped_cap
            {
                return false;
            }
            let wanted = wanted[..count]
                .iter()
                .fold(0u128, |sum, &(b, _, _)| sum + u128::from(b));
            let holders = holders.saturating_sub(jobs);
            let reserved = u128::from(reserved.saturating_sub(freed));
            if holders == 0 {
                // Alone, work due now runs whatever its size; work ahead
                // only within the share ([`Self::fits`]).
                let alone = count == 1
                    && (head == 0 || share.is_none_or(|share| wanted <= u128::from(share)));
                return alone
                    || (count <= slots && share.is_some_and(|share| wanted <= u128::from(share)));
            }
            holders + count <= slots
                && share.is_some_and(|share| reserved + wanted <= u128::from(share))
        };
        let all = candidates.iter().map(|(_, yielding)| yielding.bytes).sum();
        let all_capped = candidates
            .iter()
            .filter(|(_, yielding)| !yielding.parallel)
            .count();
        let Some(count) = (1..=wanted.len())
            .rev()
            .find(|&count| fit(candidates.len(), all_capped, all, count))
        else {
            return;
        };
        let (mut jobs, mut capped_jobs, mut freed) = (0, 0, 0u64);
        let mut newly: Vec<u64> = Vec::new();
        for &(ticket, yielding) in &candidates {
            if fit(jobs, capped_jobs, freed, count) {
                break;
            }
            jobs += 1;
            capped_jobs += usize::from(!yielding.parallel);
            freed = freed.saturating_add(yielding.bytes);
            if !yielding.asked {
                newly.push(ticket);
            }
        }
        if newly.is_empty() {
            return;
        }
        let mut bytes = 0u64;
        for ticket in &newly {
            if let Some(yielding) = state.yielding.get_mut(ticket) {
                yielding.asked = true;
                bytes = bytes.saturating_add(yielding.bytes);
            }
        }
        info!(
            asked = newly.len(),
            bytes,
            holding = candidates.len(),
            waiting = count,
            waiting_bytes = wanted[..count]
                .iter()
                .fold(0u64, |sum, &(b, _, _)| sum.saturating_add(b)),
            due = head == 0,
            reserved,
            share,
            "storage jobs ahead asked to give their memory back: more urgent work waits for \
             it; the least advanced go first, only as many as it lacks, and each asks for its \
             memory again at once in its place: an expected wait"
        );
    }

    /// How many leaves labelled ahead may hold memory at once: in parallel
    /// ([`ahead_in_parallel`]) every slot, counting all work ahead; else
    /// [`ahead_jobs_for`], counting only work ahead not in parallel
    /// ([`Self::ahead_holding`]). [`ahead_beside_due`] while a leaf is
    /// labelled now ([`Reservation::labelling_now`]). Less the leaves the
    /// host's other processes label ahead ([`State::others`]), of either
    /// class: their records do not tell them apart.
    fn ahead_cap(&self, state: &State, parallel: bool) -> usize {
        let cap = if parallel {
            self.parallel_ahead_jobs
        } else {
            self.ahead_jobs.min(self.parallel_ahead_jobs)
        };
        let cap = if state.labelling_now > 0 {
            cap.min(self.ahead_beside_due)
        } else {
            cap
        };
        let others = usize::try_from(state.others.ahead).unwrap_or(usize::MAX);
        cap.saturating_sub(others)
    }

    /// Work ahead holding memory that counts against [`Self::ahead_cap`]
    /// of work ahead in parallel or not: all of it, or what is not.
    fn ahead_holding(&self, state: &State, parallel: bool) -> usize {
        if parallel {
            state.yielding.len()
        } else {
            state
                .yielding
                .values()
                .filter(|yielding| !yielding.parallel)
                .count()
        }
    }

    /// Whether labelling ahead, in parallel or not, waits for a place: as
    /// much work ahead holds memory as may in all, or of its own class.
    fn ahead_full(&self, state: &State, parallel: bool) -> bool {
        state.yielding.len() >= self.ahead_cap(state, true)
            || self.ahead_holding(state, parallel) >= self.ahead_cap(state, parallel)
    }

    /// Whether the labelling ahead holding `ticket` pauses
    /// ([`Reservation::wait_while_paused`]): a leaf is labelled now and
    /// [`ahead_beside_due`] leaves labelled ahead go on before it, the
    /// more urgent first, then the more advanced
    /// ([`Reservation::progress`]). Never one asked to give its memory back:
    /// it is leaving.
    fn pauses(&self, state: &State, ticket: u64) -> bool {
        if state.labelling_now == 0 {
            return false;
        }
        let Some(own) = state.yielding.get(&ticket).filter(|own| !own.asked) else {
            return false;
        };
        let key =
            |ticket: u64, held: &Yielding| (held.rank, std::cmp::Reverse(held.millionths), ticket);
        let own = key(ticket, own);
        state
            .yielding
            .iter()
            .filter(|&(&other, held)| !held.asked && key(other, held) < own)
            .count()
            >= self.ahead_beside_due
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
        if let Some(index) = state
            .waiting
            .iter()
            .position(|waiting| waiting.ticket == ticket)
        {
            state.waiting.remove(index);
        } else if state.granted.remove(&ticket) {
            state.reserved = state.reserved.saturating_sub(bytes);
            state.holders = state.holders.saturating_sub(1);
            state.yielding.remove(&ticket);
            if state
                .alone
                .as_ref()
                .is_some_and(|(holder, _)| *holder == ticket)
            {
                state.alone = None;
            }
        }
        state.passed.remove(&ticket);
        state.stale = true;
        self.publish(&state);
        if !state
            .waiting
            .iter()
            .any(|waiting| waiting.urgency == Urgency::Ahead)
        {
            self.end_held_back(
                &mut state,
                "no work ahead waits: given up at its epoch's snapshot frame",
            );
        }
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

    /// Reserve `bytes` for a settlement ([`reserve_settlement`]).
    pub fn reserve_settlement(&'static self, bytes: u64) -> Reservation {
        let mut state = self.state();
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        // In this process's turn, as a pass: the others' jobs count as its
        // own. No turn now: it asks as any job does.
        let Some(turn) = self.grant_turn(&mut state) else {
            drop(state);
            return self.reserve(bytes);
        };
        self.read_others(&mut state);
        let now = (self.available)();
        let headroom =
            now.map(|now| u128::from(now) * u128::from(100 - MEMORY_SHARE_PERCENT) / 100);
        let beside = state.holders > 0 || state.others.bytes > 0;
        if beside && headroom.is_none_or(|room| u128::from(bytes) > room) {
            drop(turn);
            drop(state);
            return self.reserve(bytes);
        }
        if state.holders == 0 {
            state.idle_available = now;
        }
        state.reserved = state.reserved.saturating_add(bytes);
        state.holders += 1;
        self.publish(&state);
        drop(turn);
        drop(state);
        self.changed.notify_all();
        Reservation {
            admission: self,
            bytes,
            ticket,
            labelling: false,
        }
    }

    /// Whether `bytes` more for work of `urgency` fit beside the reservations
    /// held.
    ///
    /// Alone, work due now runs whatever its size, and what is available then
    /// is the most the jobs could have. Work ahead is optional: alone, it
    /// runs only within the share of what is available then, as beside
    /// others, or one at a time when the node cannot tell its memory; held
    /// back, it holds no memory, so work due now never waits for it, and it
    /// starts once the memory is available ([`RECHECK`]). Beside others, the
    /// jobs share [`MEMORY_SHARE_PERCENT`] of the less of two bounds, looked
    /// at again whenever a reservation asks or waits:
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
    ///
    /// The host's other processes' reservations count as held
    /// ([`install_host_ledger`]). Work due now beyond the share runs alone
    /// on the host: while no other process's jobs hold memory and it holds
    /// the host's alone lock, so one process at a time decides it. Work
    /// ahead starts nowhere while another process's work due now waits for
    /// memory or runs alone.
    fn fits(&self, state: &mut State, bytes: u64, urgency: Urgency) -> bool {
        let now = Instant::now();
        let others = state.others.bytes;
        if urgency == Urgency::Ahead && (state.others.due_waiting || state.alone_elsewhere) {
            return false;
        }
        if state.holders == 0 {
            state.idle_available = (self.available)();
            state.looks.clear();
            if let Some(idle) = state.idle_available {
                state.looks.push_back((now, idle));
            }
            let within = state.idle_available.is_some()
                && self.share(state).is_none_or(|share| {
                    u128::from(others) + u128::from(bytes) <= u128::from(share)
                });
            return match urgency {
                // Alone on the host, beyond the share: one process at a time.
                Urgency::Due => within || (others == 0 && self.take_alone(state)),
                // Unknown memory: one at a time on the host.
                Urgency::Ahead => within || (state.idle_available.is_none() && others == 0),
            };
        }
        if state.holders >= self.slots {
            return false;
        }
        self.share(state).is_some_and(|share| {
            u128::from(state.reserved) + u128::from(others) + u128::from(bytes) <= u128::from(share)
        })
    }

    /// Take the host's alone lock for work due now beyond the share
    /// ([`Self::fits`]), bound to its reservation once granted; true
    /// without a ledger, as this process alone decides then.
    fn take_alone(&self, state: &mut State) -> bool {
        let Some(ledger) = self.ledger.get() else {
            return true;
        };
        if state.alone.is_some() {
            return false;
        }
        match ledger.try_alone() {
            Ok(Some(lock)) => {
                state.alone_pending = Some(lock);
                true
            }
            Ok(None) => false,
            // A directory that cannot be used holds no one's lock or record:
            // this process decides alone, as without a ledger.
            Err(_) => true,
        }
    }

    /// The jobs' share beside reservations held ([`Self::fits`]), looked at
    /// now; `None` when the memory available cannot be told.
    fn share(&self, state: &mut State) -> Option<u64> {
        let now = Instant::now();
        let available = (self.available)()?;
        let idle = state
            .idle_available
            .map_or(available, |idle| idle.max(available));
        state.idle_available = Some(idle);
        // The reservations held are mostly allocated, so what is available
        // now plus them is what the jobs could have: the other processes'
        // too, which the window's lowest look holds to what they allocated.
        let bound = available
            .saturating_add(state.reserved)
            .saturating_add(state.others.bytes);
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
        let share = u64::try_from(share).unwrap_or(u64::MAX);
        state.last_look = Some(Look {
            available,
            idle_available: idle,
            window_low,
            share,
        });
        Some(share)
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

    /// An admission of `slots` jobs sharing what the returned bytes say is
    /// available, its memory alone: without the cap on labelling ahead
    /// ([`AHEAD_JOBS`]), which [`admission_capped`]'s tests hold.
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
        admission.ahead_jobs = usize::MAX;
        (Box::leak(Box::new(admission)), memory)
    }

    /// An admission of `slots` jobs sharing a constant `available`, with the
    /// node's cap on labelling ahead ([`AHEAD_JOBS`]).
    fn admission_capped(slots: usize, available: u64) -> &'static Admission {
        Box::leak(Box::new(Admission::new(
            slots,
            Box::new(move || Some(available)),
        )))
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

    fn until_no_jobs(admission: &Admission) {
        let deadline = Instant::now() + SOON;
        while admission.held_bytes() > 0 {
            assert!(Instant::now() < deadline, "a job still holds memory");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Two processes of a node on one host ([`install_host_ledger`]):
    /// admissions of `slots` jobs, each seeing a constant `available`, their
    /// records in one directory.
    fn host_pair(
        name: &str,
        slots: usize,
        available: u64,
    ) -> (&'static Admission, &'static Admission, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("quil-storage-host-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let [a, b] = ["a", "b"].map(|id| {
            let admission = admission_capped(slots, available);
            assert!(admission.use_ledger(HostLedger::open_as(&dir, id).unwrap()));
            admission
        });
        (a, b, dir)
    }

    /// Work due now in a second process waits while the first holds the
    /// jobs' share of the host's memory, though the memory available does
    /// not show it yet, and starts once the first gives it back.
    #[test]
    fn a_second_process_waits_for_the_share_the_first_holds() {
        let (a, b, dir) = host_pair("share", 4, 10 * GIB);
        let first = hold(a, 6 * GIB);
        assert!(granted(&first));
        let second = hold(b, 6 * GIB);
        assert!(
            still_waiting(&second),
            "two processes together hold more than the jobs' share of the host"
        );
        drop(first.release);
        assert!(granted(&second), "the second starts once the first ends");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Work due now beyond the share runs alone on the host: a second
    /// process's waits until the first one's ends.
    #[test]
    fn work_due_now_beyond_the_share_runs_alone_on_the_host() {
        let (a, b, dir) = host_pair("alone", 4, 10 * GIB);
        let first = hold(a, 9 * GIB);
        assert!(granted(&first), "alone, it runs whatever its size");
        let second = hold(b, 9 * GIB);
        assert!(
            still_waiting(&second),
            "one runs beyond the share at a time"
        );
        drop(first.release);
        assert!(granted(&second));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Labelling ahead in one process gives its memory back to work due now
    /// waiting in another, which then starts, and labelling ahead starts
    /// again once that has its memory.
    #[test]
    fn labelling_ahead_gives_memory_back_to_another_processs_work_due_now() {
        let (a, b, dir) = host_pair("yield", 4, 10 * GIB);
        let ahead_work = reserve_now(a, 6 * GIB, ahead(false, 1, 0));
        let due = hold(b, 6 * GIB);
        assert!(still_waiting(&due));
        let deadline = Instant::now() + SOON;
        while !ahead_work.yield_requested() {
            assert!(
                Instant::now() < deadline,
                "labelling ahead was not asked to give memory back"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(ahead_work);
        assert!(
            granted(&due),
            "work due now starts once the memory is given back"
        );
        let again = reserve_now(a, GIB, ahead(false, 1, 1));
        assert!(!again.yield_requested(), "no work due now waits any more");
        drop(due.release);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The master of a cluster proves the node's epoch proofs (400 MiB per
    /// sealed leaf) beside its standalone workers, which share a ledger: a
    /// master outside it ran its proof beside a worker's job, both over the
    /// share (2026-11-05, the first #1225 devnet: no master record).
    #[test]
    fn a_master_beside_standalone_workers_waits_for_the_share_they_hold() {
        set_available_for_test(Some(10 * GIB));
        set_job_slots_for_test(4);
        let labels = std::env::temp_dir()
            .join(format!("quil-storage-master-{}", std::process::id()))
            .join("storage-labels");
        let ledger = crate::storage_labels::host_ledger_dir(&labels);
        let _ = std::fs::remove_dir_all(&ledger);
        let worker = admission_capped(4, 10 * GIB);
        assert!(worker.use_ledger(HostLedger::open_as(&ledger, "worker").unwrap()));
        let first = hold(worker, 6 * GIB);
        assert!(granted(&first));
        install_master_ledger(&labels);
        let proof = hold(super::admission(), 6 * GIB);
        assert!(
            still_waiting(&proof),
            "the master's proof and a worker's job together hold more than the jobs' share"
        );
        drop(first.release);
        assert!(
            granted(&proof),
            "the master's proof starts once the worker's job ends"
        );
        let _ = std::fs::remove_dir_all(ledger.parent().unwrap());
    }

    /// Two processes asking in the same instant decide one after the other:
    /// reading the records before either wrote its own, both took the share
    /// (21 of 24 rounds, 2026-11-05).
    #[test]
    fn two_processes_asking_at_once_do_not_both_take_the_share() {
        const ROUNDS: usize = 24;
        let (a, b, dir) = host_pair("at-once", 4, 10 * GIB);
        let mut both = 0;
        for _ in 0..ROUNDS {
            let gate = Arc::new(std::sync::Barrier::new(2));
            let ask = |admission: &'static Admission, gate: Arc<std::sync::Barrier>| {
                let (granted_tx, granted) = mpsc::channel();
                let (release, released) = mpsc::channel::<()>();
                let thread = std::thread::spawn(move || {
                    gate.wait();
                    let _reservation = admission.reserve_with(6 * GIB, Urgency::Due);
                    granted_tx.send(()).unwrap();
                    let _ = released.recv();
                });
                (granted, release, thread)
            };
            let (first, first_release, first_thread) = ask(a, gate.clone());
            let (second, second_release, second_thread) = ask(b, gate);
            let first_granted = first.recv_timeout(NOT_YET / 2).is_ok();
            let second_granted = second.recv_timeout(NOT_YET / 2).is_ok();
            both += usize::from(first_granted && second_granted);
            drop((first_release, second_release));
            // The other one's next look, without its wait for it.
            while !(first_thread.is_finished() && second_thread.is_finished()) {
                for admission in [a, b] {
                    admission.admit_waiting(&mut admission.state());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            first_thread.join().unwrap();
            second_thread.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            both, 0,
            "both processes took the share in {both} of {ROUNDS} rounds"
        );
    }

    /// While another process keeps the turn to decide, nothing is granted
    /// here; once it gives it up the next pass goes on.
    #[test]
    fn a_process_waits_while_another_keeps_the_turn_to_decide() {
        let (a, b, dir) = host_pair("turn", 4, 10 * GIB);
        let turn = b.ledger.get().unwrap().grant_turn(Duration::ZERO).unwrap();
        assert!(turn.is_some());
        let held = hold(a, GIB);
        assert!(still_waiting(&held), "granted while the turn was taken");
        drop(turn);
        a.admit_waiting(&mut a.state());
        assert!(
            granted(&held),
            "the next pass goes on once the turn is free"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bound on another process's turn: past it this one decides without
    /// it, says so, and is back in turn once it is free.
    #[test]
    fn a_turn_kept_past_its_bound_stops_no_jobs() {
        let dir =
            std::env::temp_dir().join(format!("quil-storage-host-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut admission = Admission::new(4, Box::new(|| Some(10 * GIB)));
        admission.grant_patience = Duration::from_millis(600);
        let admission: &'static Admission = Box::leak(Box::new(admission));
        assert!(admission.use_ledger(HostLedger::open_as(&dir, "a").unwrap()));
        let other = HostLedger::open_as(&dir, "stopped").unwrap();
        let turn = other.grant_turn(Duration::ZERO).unwrap();
        assert!(turn.is_some());
        let held = hold(admission, GIB);
        assert!(still_waiting(&held), "granted within the bound");
        let deadline = Instant::now() + SOON;
        while held.granted.recv_timeout(NOT_YET).is_err() {
            assert!(Instant::now() < deadline, "a kept turn stopped the jobs");
            admission.admit_waiting(&mut admission.state());
        }
        assert!(admission
            .state()
            .grant_busy
            .is_some_and(|(_, warned)| warned));
        drop(turn);
        admission.admit_waiting(&mut admission.state());
        assert!(
            admission.state().grant_busy.is_none(),
            "back in turn once it is free"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory that can no longer be used stops no jobs: they are
    /// admitted without the other processes, as when it could not be opened.
    #[test]
    fn jobs_go_on_when_the_ledger_directory_cannot_be_used() {
        let (a, _b, dir) = host_pair("gone", 4, 10 * GIB);
        std::fs::remove_dir_all(&dir).unwrap();
        // A file in its place: not a directory, for any user.
        std::fs::write(&dir, b"").unwrap();
        let held = hold(a, GIB);
        assert!(
            granted(&held),
            "the jobs wait on a directory they cannot use"
        );
        drop(held.release);
        until_no_jobs(a);
        let beyond = hold(a, 20 * GIB);
        assert!(
            granted(&beyond),
            "work due now beyond the share waits on a directory it cannot use"
        );
        drop(beyond.release);
        until_no_jobs(a);
        let ahead = hold_with(a, GIB, Urgency::Ahead);
        assert!(
            granted(&ahead),
            "work ahead waits on a directory it cannot use"
        );
        let _ = std::fs::remove_file(&dir);
    }

    /// A settlement takes its turn and counts the other processes' jobs as
    /// it counts its own: it waits beyond the headroom beside them, as
    /// beside this process's.
    #[test]
    fn a_settlement_counts_what_other_processes_hold() {
        let (a, b, dir) = host_pair("settle", 4, 10 * GIB);
        let holding = hold(b, 6 * GIB);
        assert!(granted(&holding));
        let (settled_tx, settled) = mpsc::channel();
        std::thread::spawn(move || {
            let _reservation = a.reserve_settlement(4 * GIB);
            settled_tx.send(()).unwrap();
        });
        assert!(
            settled.recv_timeout(NOT_YET).is_err(),
            "a settlement beyond the headroom ran beside another process's jobs"
        );
        drop(holding.release);
        assert!(
            settled.recv_timeout(SOON).is_ok(),
            "the settlement starts once the other process's job ends"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_bytes_held_are_those_of_the_reservations_granted() {
        let (admission, _) = admission(8, 40 * GIB);
        assert_eq!(admission.held_bytes(), 0);
        let first = hold(admission, 3 * GIB);
        assert!(granted(&first));
        let second = hold(admission, 2 * GIB);
        assert!(granted(&second));
        assert_eq!(admission.held_bytes(), 5 * GIB);
        drop(first.release);
        let deadline = Instant::now() + Duration::from_secs(5);
        while admission.held_bytes() != 2 * GIB {
            assert!(
                Instant::now() < deadline,
                "{} bytes still held",
                admission.held_bytes()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(second.release);
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
                .map(|waiting| waiting.urgency)
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

    fn ahead(deferrable: bool, seat: u64, leaf: u64) -> AheadOrder {
        AheadOrder {
            deferrable,
            seat_leaves: 1,
            seat,
            leaf,
        }
    }

    /// Reserve `bytes` for work ahead in `order` on this thread: it fits now.
    fn reserve_now(admission: &'static Admission, bytes: u64, order: AheadOrder) -> Reservation {
        admission
            .reserve_ordered(bytes, Urgency::Ahead, Some(order), true, &|| false)
            .expect("a reservation that never expires")
    }

    /// Work ahead in `order` holding `bytes` on a thread of its own, giving
    /// them back once asked to ([`Reservation::yield_requested`]): `yielded`
    /// hears when it does.
    struct Yielder {
        granted: mpsc::Receiver<()>,
        yielded: mpsc::Receiver<()>,
        release: mpsc::Sender<()>,
    }

    fn hold_yielding(admission: &'static Admission, bytes: u64, order: AheadOrder) -> Yielder {
        let (granted_tx, granted) = mpsc::channel();
        let (yielded_tx, yielded) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let reservation = admission
                .reserve_ordered(bytes, Urgency::Ahead, Some(order), true, &|| false)
                .unwrap();
            granted_tx.send(()).unwrap();
            loop {
                if reservation.yield_requested() {
                    drop(reservation);
                    let _ = yielded_tx.send(());
                    return;
                }
                match released.recv_timeout(Duration::from_millis(5)) {
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    _ => return,
                }
            }
        });
        Yielder {
            granted,
            yielded,
            release,
        }
    }

    /// Work due now waiting for memory asks only as much work ahead to give
    /// its memory back as it lacks, the least advanced first, and none while
    /// even all of it would not let the work fit (2026-11-01: every leaf
    /// labelled ahead gave its memory back whenever any work due now waited,
    /// 13 of them for epoch proof parts of a few GB).
    #[test]
    fn work_due_now_asks_only_the_least_advanced_work_ahead_it_needs_to_yield() {
        // 40 GiB available: the jobs share 30.
        let (admission, _) = admission(8, 40 * GIB);
        let [a, b, c] =
            [0, 1, 2].map(|leaf| reserve_now(admission, 10 * GIB, ahead(false, 1, leaf)));
        a.progress(5, 10);
        b.progress(1, 10);
        c.progress(9, 10);
        let due = hold(admission, 5 * GIB);
        until_waiting(admission, 1);
        let deadline = Instant::now() + SOON;
        while !b.yield_requested() {
            assert!(
                Instant::now() < deadline,
                "the least advanced is asked to yield"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !a.yield_requested() && !c.yield_requested(),
            "35 GiB less one of 10 fit in 30: only one is asked"
        );
        drop(b);
        assert!(
            granted(&due),
            "it runs once the one asked gives its memory back"
        );
        // 25 GiB held, 5 of them due now: 31 do not fit even once the work
        // ahead gives all of its memory back.
        let large = hold(admission, 26 * GIB);
        until_waiting(admission, 1);
        assert!(still_waiting(&large));
        assert!(
            !a.yield_requested() && !c.yield_requested(),
            "work ahead is not asked to yield for nothing"
        );
        drop(due.release);
        let deadline = Instant::now() + SOON;
        while !(a.yield_requested() && c.yield_requested()) {
            assert!(
                Instant::now() < deadline,
                "alone it fits once all of it yields"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        drop((a, c));
        assert!(granted(&large));
        drop(large.release);
    }

    /// Work ahead that gave its memory back asks for it again in its place
    /// in line, not behind work ahead asked for after it.
    #[test]
    fn work_ahead_that_yielded_keeps_its_place_in_line() {
        let (admission, _) = admission(8, 40 * GIB);
        let first = reserve_now(admission, 15 * GIB, ahead(false, 1, 0));
        let other = reserve_now(admission, 15 * GIB, ahead(false, 3, 0));
        other.progress(9, 10);
        let (later_tx, later) = mpsc::channel();
        std::thread::spawn(move || {
            let reservation = admission
                .reserve_ordered(
                    15 * GIB,
                    Urgency::Ahead,
                    Some(ahead(false, 4, 0)),
                    true,
                    &|| false,
                )
                .unwrap();
            later_tx.send(()).unwrap();
            drop(reservation);
        });
        until_waiting(admission, 1);
        let due = hold(admission, 5 * GIB);
        until_waiting(admission, 2);
        let deadline = Instant::now() + SOON;
        while !first.yield_requested() {
            assert!(
                Instant::now() < deadline,
                "the least advanced is asked to yield"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!other.yield_requested());
        drop(first);
        assert!(granted(&due));
        // It asks again for its memory at once, as labelling ahead does.
        let again = hold_yielding(admission, 15 * GIB, ahead(false, 1, 0));
        until_waiting(admission, 2);
        assert_eq!(
            admission
                .state()
                .waiting
                .front()
                .map(|waiting| waiting.place.2),
            Some(1),
            "it waits before work ahead asked for after it"
        );
        drop(other);
        assert!(again.granted.recv_timeout(SOON).is_ok(), "20 GiB fit in 30");
        assert!(
            later.recv_timeout(NOT_YET).is_err(),
            "35 GiB do not: the one asked for later waits"
        );
        drop(again.release);
        drop(due.release);
        assert!(later.recv_timeout(SOON).is_ok());
    }

    /// Work ahead waits in its order whenever asked: what could not be done
    /// when needed first, a seat's together, seats needing fewer first.
    #[test]
    fn work_ahead_waits_in_its_order() {
        let (admission, _) = admission(8, 40 * GIB);
        let first = reserve_now(admission, 20 * GIB, ahead(false, 1, 0));
        let orders = [
            ahead(true, 1, 0),
            AheadOrder {
                seat_leaves: 2,
                ..ahead(false, 2, 0)
            },
            ahead(false, 3, 1),
            ahead(false, 3, 0),
        ];
        let (tx, rx) = mpsc::channel();
        for (index, order) in orders.into_iter().enumerate() {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let reservation =
                    admission
                        .reserve_ordered(40 * GIB, Urgency::Ahead, Some(order), true, &|| false);
                let _ = tx.send(index);
                drop(reservation);
            });
            until_waiting(admission, index + 1);
        }
        let places: Vec<_> = admission
            .state()
            .waiting
            .iter()
            .map(|waiting| {
                (
                    waiting.place.0,
                    waiting.place.1,
                    waiting.place.2,
                    waiting.place.3,
                )
            })
            .collect();
        assert_eq!(
            places,
            vec![(1, 1, 3, 0), (1, 1, 3, 1), (1, 2, 2, 0), (2, 1, 1, 0)],
            "work that could not wait first, a seat's together, seats needing fewer first"
        );
        drop(rx);
        drop(first);
    }

    /// Work ahead that could be done when needed passes work ahead that
    /// could not when only it fits, and gives its memory back once that
    /// would fit.
    #[test]
    fn work_ahead_that_could_wait_fills_what_is_left_and_gives_it_back() {
        let (admission, _) = admission(8, 40 * GIB);
        let first = reserve_now(admission, 20 * GIB, ahead(false, 1, 0));
        let (large_tx, large) = mpsc::channel();
        std::thread::spawn(move || {
            let reservation = admission
                .reserve_ordered(
                    25 * GIB,
                    Urgency::Ahead,
                    Some(ahead(false, 2, 0)),
                    true,
                    &|| false,
                )
                .unwrap();
            large_tx.send(()).unwrap();
            std::thread::sleep(NOT_YET);
            drop(reservation);
        });
        until_waiting(admission, 1);
        let small = hold_yielding(admission, 8 * GIB, ahead(true, 3, 0));
        assert!(
            small.granted.recv_timeout(SOON).is_ok(),
            "28 GiB fit in 30, and yielding would not let the large one fit beside the first"
        );
        assert!(small.yielded.recv_timeout(NOT_YET).is_err());
        drop(first);
        assert!(
            small.yielded.recv_timeout(SOON).is_ok(),
            "33 GiB do not fit in 30: the small one gives its memory back"
        );
        assert!(large.recv_timeout(SOON).is_ok());
        drop(small.release);
    }

    /// Reserve `bytes` for work due now on this thread, labelling a leaf
    /// now ([`Reservation::labelling_now`]): it fits now.
    fn labelling_now(admission: &'static Admission, bytes: u64) -> Reservation {
        let mut due = admission.reserve(bytes);
        due.labelling_now();
        due
    }

    /// A reservation for work ahead in `order` that is never asked to give
    /// its memory back (reading a leaf), held on a thread of its own.
    fn hold_brief(admission: &'static Admission, bytes: u64, order: AheadOrder) -> Held {
        let (granted_tx, granted) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let _reservation = admission
                .reserve_ordered(bytes, Urgency::Ahead, Some(order), false, &|| false)
                .unwrap();
            granted_tx.send(()).unwrap();
            let _ = released.recv();
        });
        Held { granted, release }
    }

    /// The wait line names what binds: the slots, the memory, or the order.
    #[test]
    fn the_binding_limit_is_named() {
        assert_eq!(binding_limit(4, 4, 10, 1, Some(100)), "job_slots");
        assert_eq!(binding_limit(4, 4, 10, 1, None), "job_slots");
        assert_eq!(binding_limit(2, 4, 90, 11, Some(100)), "memory");
        assert_eq!(binding_limit(2, 4, 10, 1, None), "memory");
        assert_eq!(binding_limit(2, 4, 90, 10, Some(100)), "queue_order");
    }

    /// A job waiting because every slot is held, or because the memory is,
    /// logs which, with the slots and holders.
    #[test]
    fn a_waiting_job_logs_its_binding_limit() {
        let logs = crate::outage::test_logs::CapturedLogs::default();
        // Releases `held` once the reserving thread has logged its wait.
        let waits = |admission: &'static Admission, bytes: u64, held: Held| {
            let logs = logs.clone();
            let (started_tx, started) = mpsc::channel();
            let waiting = std::thread::spawn(move || {
                let _logging = logs.install();
                let reservation = admission.reserve(bytes);
                started_tx.send(()).unwrap();
                drop(reservation);
            });
            assert!(started.recv_timeout(NOT_YET).is_err(), "it waits");
            drop(held.release);
            started.recv_timeout(SOON).unwrap();
            waiting.join().unwrap();
        };
        // One slot, held.
        let admission = admission_capped(1, 1 << 50);
        let held = hold(admission, GIB);
        assert!(granted(&held));
        waits(admission, GIB, held);
        let lines = logs.lines_with("storage job waits to start");
        assert_eq!(lines.len(), 1, "{lines:?}");
        for field in ["limit=\"job_slots\"", "slots=1", "jobs=1"] {
            assert!(lines[0].contains(field), "{field}: {}", lines[0]);
        }
        // Slots to spare, memory not: a request over the share waits.
        let admission = admission_capped(8, 2 * GIB);
        let held = hold(admission, GIB);
        assert!(granted(&held));
        waits(admission, 4 * GIB, held);
        let lines = logs.lines_with("storage job waits to start");
        assert_eq!(lines.len(), 2, "{lines:?}");
        for field in ["limit=\"memory\"", "slots=8", "jobs=1"] {
            assert!(lines[1].contains(field), "{field}: {}", lines[1]);
        }
    }

    /// Before persistent storage holds, a host of many slots and ample
    /// memory still labels [`AHEAD_JOBS`] leaves ahead at once, by default
    /// ([`Admission::new`]): the cap the legacy leaves were measured with.
    #[test]
    fn before_persistent_storage_two_leaves_are_labelled_ahead_on_any_host() {
        let admission = Box::leak(Box::new(Admission::new(9, Box::new(|| Some(128 * GIB)))));
        let first = reserve_now(admission, GIB, ahead(false, 1, 0));
        let _second = reserve_now(admission, GIB, ahead(false, 1, 1));
        let third = hold_yielding(admission, GIB, ahead(false, 1, 2));
        assert!(
            third.granted.recv_timeout(NOT_YET).is_err(),
            "a third leaf waits though seven slots and the memory are free"
        );
        assert_eq!(admission.state().holders, 2);
        drop(first);
        assert!(
            third.granted.recv_timeout(SOON).is_ok(),
            "it starts once one ends"
        );
        drop(third.release);
    }

    /// Where persistent storage holds, sectors labelled ahead run on every
    /// slot the memory admits, and one beyond them starts once one ends.
    #[test]
    fn persistent_sectors_are_labelled_ahead_on_every_slot() {
        let admission = Box::leak(Box::new(Admission::new(9, Box::new(|| Some(128 * GIB)))));
        let mut held: Vec<Held> = (0..9)
            .map(|leaf| hold_parallel(admission, GIB, ahead(false, 1, leaf)))
            .collect();
        for sector in &held {
            assert!(granted(sector), "each sector starts on its own slot");
        }
        assert_eq!(admission.state().holders, 9);
        let tenth = hold_parallel(admission, GIB, ahead(false, 1, 9));
        assert!(
            still_waiting(&tenth),
            "a tenth sector waits: every slot is held"
        );
        drop(held.pop());
        assert!(granted(&tenth), "the tenth sector starts once one ends");
        drop((held, tenth.release));
    }

    /// Sectors labelled ahead in parallel do not count against the legacy
    /// leaves' [`AHEAD_JOBS`], and those leaves stay capped beside them.
    #[test]
    fn legacy_leaves_keep_their_cap_beside_parallel_sectors() {
        let admission = Box::leak(Box::new(Admission::new(9, Box::new(|| Some(128 * GIB)))));
        let sectors: Vec<Held> = (0..3)
            .map(|leaf| hold_parallel(admission, GIB, ahead(false, 1, leaf)))
            .collect();
        for sector in &sectors {
            assert!(granted(sector), "each sector starts on its own slot");
        }
        let leaves = [
            hold_yielding(admission, GIB, ahead(false, 2, 0)),
            hold_yielding(admission, GIB, ahead(false, 2, 1)),
        ];
        for leaf in &leaves {
            assert!(
                leaf.granted.recv_timeout(SOON).is_ok(),
                "two legacy leaves start beside three sectors"
            );
        }
        let third = hold_yielding(admission, GIB, ahead(false, 2, 2));
        assert!(
            third.granted.recv_timeout(NOT_YET).is_err(),
            "a third legacy leaf waits beside the sectors"
        );
        let sector = hold_parallel(admission, GIB, ahead(false, 3, 0));
        assert!(
            granted(&sector),
            "a sector after it in order does not wait for it"
        );
    }

    /// Work ahead runs in parallel only for an epoch where persistent
    /// storage holds; a disabled or future activation keeps the legacy cap.
    #[test]
    fn work_ahead_runs_in_parallel_only_once_persistent_storage_holds() {
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(u64::MAX));
        assert!(!ahead_in_parallel(1500));
        assert!(!ahead_in_parallel(u64::MAX - 1));
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(1500));
        assert!(!ahead_in_parallel(1499));
        assert!(ahead_in_parallel(1500));
        quil_types::consensus::set_persistent_storage_epoch_for_thread(None);
    }

    /// Work ahead in parallel in `order` holding `bytes` on a thread of its
    /// own ([`hold`]): `granted` hears when it is, and dropping `release`
    /// gives it back.
    fn hold_parallel(admission: &'static Admission, bytes: u64, order: AheadOrder) -> Held {
        let (granted_tx, granted) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let _reservation = admission
                .reserve_ahead_in(bytes, Some(order), true, true, &|| false)
                .expect("a reservation that never expires");
            granted_tx.send(()).unwrap();
            let _ = released.recv();
        });
        Held { granted, release }
    }

    /// At most [`AHEAD_JOBS`] leaves are labelled ahead at once whatever the
    /// memory and slots let, and one asking beyond them starts once one of
    /// them ends; reading a leaf ahead and work due now do not wait for them
    /// (2026-11-01: four leaves labelled ahead held 17.9 GB of a 32 GB
    /// node's 20.5 GB).
    #[test]
    fn at_most_two_leaves_are_labelled_ahead_at_once() {
        assert_eq!(AHEAD_JOBS, 2);
        let admission = admission_capped(8, 1 << 50);
        let first = reserve_now(admission, GIB, ahead(false, 1, 0));
        let second = reserve_now(admission, GIB, ahead(false, 1, 1));
        let third = hold_yielding(admission, GIB, ahead(false, 1, 2));
        assert!(
            third.granted.recv_timeout(NOT_YET).is_err(),
            "a third leaf waits though memory and slots are free"
        );
        let read = hold_brief(admission, GIB, ahead(false, 1, 3));
        assert!(
            granted(&read),
            "reading a leaf ahead does not wait for them"
        );
        let due = hold(admission, GIB);
        assert!(granted(&due), "work due now does not wait for them");
        drop(second);
        assert!(
            third.granted.recv_timeout(SOON).is_ok(),
            "it starts once one of them ends"
        );
        assert!(!first.yield_requested());
        drop((first, third.release, read.release, due.release));
    }

    /// The cap on labelling ahead follows the node: one leaf per four CPUs,
    /// and as many of the largest leaves as the jobs' share of its memory
    /// holds at what labelling one ahead reserves, beside one labelled now;
    /// never fewer than two.
    #[test]
    fn a_larger_node_labels_more_leaves_ahead_at_once() {
        const GB: u64 = 1_000_000_000;
        for (cpus, memory, jobs, beside) in [
            (4, 8 * GB, 2, 1),
            (8, 32 * GB, 2, 1),
            (16, 16 * GB, 2, 1),
            (16, 32 * GB, 2, 1),
            (16, 32 * GIB, 3, 1),
            (16, 1024 * GB, 4, 2),
            (2, 1024 * GB, 2, 1),
            (24, 62 * GIB, 6, 3),
            (32, 64 * GB, 7, 3),
            (64, 256 * GB, 16, 8),
            (256, 1024 * GB, 64, 32),
        ] {
            let got = ahead_jobs_for(cpus, memory);
            assert_eq!(got, jobs, "ahead misjudged: {cpus} CPUs, {memory} bytes");
            assert_eq!(ahead_beside_due(got), beside, "beside {got} leaves");
        }
    }

    /// A 16-thread node of 31 GiB, sharing about 25 GB, labels three of its
    /// largest leaves ahead at once: 5.4 GB each beside 8.0 GB for one
    /// labelled now. Sized by 16 GiB a leaf it labelled two, and gave up 8
    /// of its 10 seats of such leaves in an epoch (2026-11-06, epoch 1420).
    #[test]
    fn the_memory_term_counts_what_labelling_a_leaf_ahead_reserves() {
        // The node's MemTotal: 32,729,092 kB.
        let memory: u64 = 32_729_092 * 1024;
        let each = crate::storage_labels::label_ahead_bytes(AHEAD_JOB_NODES);
        let now = crate::storage_snapshot::encoding_bytes(AHEAD_JOB_NODES);
        assert_eq!(each, 5_428_614_204, "ahead misjudged: the reservation");
        assert_eq!(now, 8_020_283_296, "ahead misjudged: a leaf labelled now");
        assert!(
            u128::from(memory) * 75 / 100 >= u128::from(now) + 3 * u128::from(each),
            "ahead misjudged: three fit beside one labelled now"
        );
        assert_eq!(ahead_jobs_for(16, memory), 3, "ahead misjudged: the cap");
    }

    /// A node sized for four leaves labels four ahead and starts no fifth;
    /// beside a leaf labelled now the two most advanced go on and the others
    /// pause.
    #[test]
    fn a_larger_nodes_cap_bounds_its_labelling_ahead_and_pauses_half_beside_a_renewal() {
        let mut sized = Admission::new(16, Box::new(|| Some(1 << 50)));
        sized.ahead_jobs = 4;
        sized.ahead_beside_due = ahead_beside_due(4);
        let admission: &'static Admission = Box::leak(Box::new(sized));
        let leaves: Vec<Reservation> = (0..4u32)
            .map(|leaf| {
                let held = reserve_now(admission, GIB, ahead(false, 1, u64::from(leaf)));
                held.progress(u64::from(9 - leaf), 10);
                held
            })
            .collect();
        let fifth = hold_yielding(admission, GIB, ahead(false, 1, 4));
        assert!(
            fifth.granted.recv_timeout(NOT_YET).is_err(),
            "a fifth waits though memory and slots are free"
        );
        let due = labelling_now(admission, GIB);
        let paused: Vec<bool> = leaves.iter().map(|leaf| leaf.paused()).collect();
        assert_eq!(
            paused,
            [false, false, true, true],
            "the two most advanced go on beside a leaf labelled now"
        );
        drop(due);
        assert!(leaves.iter().all(|leaf| !leaf.paused()));
        drop(leaves);
        assert!(
            fifth.granted.recv_timeout(SOON).is_ok(),
            "it starts once they end"
        );
        drop(fifth.release);
    }

    /// Beside a leaf labelled now, a node sized for four leaves ahead starts
    /// labelling ahead while fewer than half of them hold memory
    /// ([`ahead_beside_due`]), not while one does.
    #[test]
    fn beside_a_leaf_labelled_now_a_larger_node_starts_half_its_cap() {
        let mut sized = Admission::new(16, Box::new(|| Some(1 << 50)));
        sized.ahead_jobs = 4;
        sized.ahead_beside_due = ahead_beside_due(4);
        let admission: &'static Admission = Box::leak(Box::new(sized));
        let due = labelling_now(admission, GIB);
        let first = reserve_now(admission, GIB, ahead(false, 1, 0));
        let second = hold_yielding(admission, GIB, ahead(false, 1, 1));
        assert!(
            second.granted.recv_timeout(SOON).is_ok(),
            "a second starts beside the leaf labelled now"
        );
        let third = hold_yielding(admission, GIB, ahead(false, 1, 2));
        assert!(
            third.granted.recv_timeout(NOT_YET).is_err(),
            "a third waits while it is labelled"
        );
        drop(due);
        assert!(
            third.granted.recv_timeout(SOON).is_ok(),
            "it starts once the leaf labelled now ends"
        );
        drop((first, second.release, third.release));
    }

    /// While a renewal's leaf is labelled now, labelling ahead goes on beside
    /// it for [`AHEAD_JOBS_BESIDE_DUE`] leaf only, the most urgent, then the
    /// most advanced; the others pause, holding their memory, and go on once
    /// it ends. Work due now that labels nothing pauses nothing (2026-11-01:
    /// beside three or four leaves labelled ahead, a renewal's leaf estimated
    /// at 37 minutes was still labelled at its grace, 3,137 s in).
    #[test]
    fn labelling_ahead_pauses_beside_a_leaf_labelled_now_and_goes_on_after() {
        assert_eq!(AHEAD_JOBS_BESIDE_DUE, 1);
        let admission = admission_capped(8, 1 << 50);
        let advanced = reserve_now(admission, GIB, ahead(false, 1, 0));
        advanced.progress(5, 10);
        let behind = reserve_now(admission, GIB, ahead(false, 1, 1));
        behind.progress(2, 10);
        let encode = admission.reserve(GIB);
        assert!(
            !advanced.paused() && !behind.paused(),
            "work due now that labels nothing pauses nothing"
        );
        drop(encode);
        let due = labelling_now(admission, GIB);
        assert!(!advanced.paused(), "the most advanced goes on beside it");
        assert!(behind.paused(), "the other pauses");
        let (resumed_tx, resumed) = mpsc::channel();
        let pausing = std::thread::spawn(move || {
            let paused = behind.wait_while_paused(&|| false);
            resumed_tx.send(paused).unwrap();
            behind
        });
        // Once it pauses, it stays paused while the leaf is labelled now:
        // held for NOT_YET from then, it paused for at least that long.
        let deadline = Instant::now() + SOON;
        while admission.state().pausing == 0 {
            assert!(
                Instant::now() < deadline,
                "it pauses while the leaf is labelled now"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            resumed.recv_timeout(NOT_YET).is_err(),
            "it stays paused while the leaf is labelled now"
        );
        assert_eq!(admission.state().pausing, 1);
        drop(due);
        let paused = resumed
            .recv_timeout(SOON)
            .expect("it goes on once the leaf labelled now ends");
        assert!(paused >= NOT_YET, "it paused for {paused:?}");
        let behind = pausing.join().unwrap();
        assert!(!behind.paused());
        assert_eq!(admission.state().pausing, 0);
        drop((advanced, behind));
        // The more urgent goes on before the more advanced.
        let could_wait = reserve_now(admission, GIB, ahead(true, 3, 0));
        could_wait.progress(9, 10);
        let could_not = reserve_now(admission, GIB, ahead(false, 4, 0));
        could_not.progress(1, 10);
        let due = labelling_now(admission, GIB);
        assert!(
            could_wait.paused() && !could_not.paused(),
            "work ahead that could not be done when needed goes on"
        );
        drop(due);
        assert!(!could_wait.paused());
    }

    /// Labelling ahead that pauses beside a leaf labelled now still gives its
    /// memory back to work due now waiting for it, and stops pausing to.
    #[test]
    fn labelling_ahead_that_pauses_gives_its_memory_back_when_asked() {
        // 8 GiB available: the jobs share 6.
        let admission = admission_capped(8, 8 * GIB);
        let advanced = reserve_now(admission, 2 * GIB, ahead(false, 1, 0));
        advanced.progress(5, 10);
        let behind = reserve_now(admission, 2 * GIB, ahead(false, 1, 1));
        let due = labelling_now(admission, GIB);
        assert!(behind.paused());
        let (resumed_tx, resumed) = mpsc::channel();
        std::thread::spawn(move || {
            behind.wait_while_paused(&|| false);
            resumed_tx.send(behind.yield_requested()).unwrap();
        });
        assert!(resumed.recv_timeout(NOT_YET).is_err());
        let more = hold(admission, 2 * GIB);
        until_waiting(admission, 1);
        assert_eq!(
            resumed.recv_timeout(SOON),
            Ok(true),
            "asked to give its memory back to the 2 GiB waiting, it stops pausing"
        );
        assert!(granted(&more), "7 GiB less 2 fit in 6");
        drop((advanced, due, more.release));
    }

    /// While a leaf is labelled now, no more labelling ahead starts than may
    /// go on beside it ([`ahead_beside_due`]); once it ends,
    /// [`AHEAD_JOBS`] again.
    #[test]
    fn beside_a_leaf_labelled_now_no_more_labelling_ahead_starts_than_goes_on() {
        let admission = admission_capped(8, 1 << 50);
        let due = labelling_now(admission, GIB);
        let first = reserve_now(admission, GIB, ahead(false, 1, 0));
        assert!(!first.paused(), "one goes on beside it");
        let second = hold_yielding(admission, GIB, ahead(false, 1, 1));
        assert!(
            second.granted.recv_timeout(NOT_YET).is_err(),
            "a second waits rather than start to pause"
        );
        drop(due);
        assert!(
            second.granted.recv_timeout(SOON).is_ok(),
            "it starts once the leaf labelled now ends"
        );
        drop((first, second.release));
    }

    /// Labelling ahead that could be done when needed gives its place to
    /// labelling that could not as it gives its memory ([`AHEAD_JOBS`]):
    /// the least advanced, only as many as lack a place.
    #[test]
    fn labelling_ahead_that_could_wait_gives_its_place_to_labelling_that_could_not() {
        let admission = admission_capped(8, 1 << 50);
        let first = hold_yielding(admission, GIB, ahead(true, 1, 0));
        assert!(first.granted.recv_timeout(SOON).is_ok());
        let second = hold_yielding(admission, GIB, ahead(true, 1, 1));
        assert!(second.granted.recv_timeout(SOON).is_ok());
        let urgent = hold_with_order(admission, GIB, ahead(false, 2, 0));
        assert!(
            second.yielded.recv_timeout(SOON).is_ok(),
            "the one asked last gives its place"
        );
        assert!(
            granted(&urgent),
            "the leaf only labelling ahead registers starts"
        );
        assert!(
            first.yielded.recv_timeout(NOT_YET).is_err(),
            "only as many as lack a place"
        );
        drop((first.release, urgent.release));
    }

    /// Labelling ahead in `order` held on a thread of its own.
    fn hold_with_order(admission: &'static Admission, bytes: u64, order: AheadOrder) -> Held {
        let (granted_tx, granted) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let _reservation = admission
                .reserve_ordered(bytes, Urgency::Ahead, Some(order), true, &|| false)
                .unwrap();
            granted_tx.send(()).unwrap();
            let _ = released.recv();
        });
        Held { granted, release }
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
                .map(|waiting| (waiting.urgency, waiting.bytes / GIB))
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

    /// Work ahead is optional: with no job holding memory it runs only
    /// within the jobs' share of what is available, reading a leaf as
    /// labelling one; work due now still runs alone whatever its size, and
    /// the work ahead starts once the memory is there (2026-11-03: a leaf
    /// labelled ahead reserving 8.0 GB started on a 16 GB host with 0.54 GB
    /// available, and held the host's memory for hours).
    #[test]
    fn work_ahead_alone_runs_only_within_the_share_of_what_is_available() {
        // 2 GiB available: the jobs share 1.5.
        let (admission, memory) = admission(8, 2 * GIB);
        let labelling = hold_with_order(admission, 8 * GIB, ahead(false, 1, 0));
        assert!(
            still_waiting(&labelling),
            "over-admission: 8 GiB of labelling ahead granted with 2 GiB available and no job \
             holding memory"
        );
        let read = hold_brief(admission, 4 * GIB, ahead(false, 1, 1));
        assert!(
            still_waiting(&read),
            "over-admission: 4 GiB of reading a leaf ahead granted with 2 GiB available and no \
             job holding memory"
        );
        let due = hold(admission, 8 * GIB);
        assert!(granted(&due), "work due now runs alone whatever its size");
        assert!(still_waiting(&labelling), "nothing runs beside it");
        drop(due.release);
        assert!(
            still_waiting(&labelling),
            "alone, 8 GiB still do not fit in 1.5"
        );
        // The host frees memory: 12 GiB available, the jobs share 9.
        memory.store(12 * GIB, Ordering::SeqCst);
        assert!(granted(&labelling), "it starts once the memory is there");
        assert!(still_waiting(&read), "12 GiB do not fit in 9");
        drop(labelling.release);
        assert!(granted(&read), "it starts once the labelling ends");
        drop(read.release);
    }

    /// Work ahead that could be done when needed is not asked to give its
    /// memory back to more urgent work ahead that would not fit even alone:
    /// it would give it back for nothing.
    #[test]
    fn work_ahead_does_not_yield_to_work_ahead_too_large_for_what_is_available() {
        // 8 GiB available: the jobs share 6.
        let (admission, _) = admission(8, 8 * GIB);
        let filler = reserve_now(admission, GIB, ahead(true, 1, 0));
        let urgent = hold_with_order(admission, 7 * GIB, ahead(false, 2, 0));
        until_waiting(admission, 1);
        assert!(still_waiting(&urgent), "8 GiB do not fit in 6");
        assert!(
            !filler.yield_requested(),
            "asked to give its memory back to 7 GiB of work ahead that do not fit in 6 even \
             alone"
        );
        drop(filler);
        assert!(still_waiting(&urgent), "alone, 7 GiB still do not fit in 6");
    }

    /// Work ahead that does not fit with no job holding memory holds no
    /// place, however long ago it was first passed: no job ending would let
    /// it fit, and smaller work ahead that fits goes on.
    #[test]
    fn work_ahead_held_back_for_memory_holds_no_place() {
        let window = Duration::from_millis(100);
        // 8 GiB available: the jobs share 6.
        let admission = admission_passing(8, 8 * GIB, window);
        let large = hold_with_order(admission, 7 * GIB, ahead(false, 1, 0));
        until_waiting(admission, 1);
        let small = hold_with_order(admission, GIB, ahead(false, 1, 1));
        assert!(granted(&small), "it passes the large one");
        std::thread::sleep(window * 2);
        drop(small.release);
        let late = hold_with_order(admission, GIB, ahead(false, 1, 2));
        assert!(
            granted(&late),
            "the large one was first passed a window ago, but holds no place while no job \
             ending would let it fit"
        );
        assert!(still_waiting(&large), "8 GiB do not fit in 6");
        drop(late.release);
    }

    /// An admission of `slots` jobs sharing what the returned bytes say is
    /// available, warning of work ahead held back for memory after `period`
    /// ([`AHEAD_HELD_BACK_WARN`]).
    fn admission_warning(
        slots: usize,
        available: u64,
        period: Duration,
    ) -> (&'static Admission, Arc<AtomicU64>) {
        let memory = Arc::new(AtomicU64::new(available));
        let probe = memory.clone();
        let mut admission = Admission::new(
            slots,
            Box::new(move || Some(probe.load(Ordering::SeqCst)).filter(|&bytes| bytes > 0)),
        );
        admission.held_back_warn = period;
        (Box::leak(Box::new(admission)), memory)
    }

    /// When the warning of work ahead held back for memory was last given.
    fn held_back_warned(admission: &Admission) -> Option<Instant> {
        let mut state = admission.state();
        admission.admit_waiting(&mut state);
        state.held_back.expect("work ahead is held back").warned
    }

    /// Work ahead held back for memory is noted from the first look that
    /// finds it too large with no job holding memory, warned of once it
    /// lasted [`AHEAD_HELD_BACK_WARN`] (a storage epoch), at most once as
    /// long, and no longer held back once it has its memory.
    #[test]
    fn work_ahead_held_back_for_memory_is_warned_of_at_most_once_an_epoch() {
        let period = Duration::from_millis(300);
        let (admission, memory) = admission_warning(8, 2 * GIB, period);
        let labelling = hold_with_order(admission, 8 * GIB, ahead(false, 1, 0));
        until_waiting(admission, 1);
        assert_eq!(held_back_warned(admission), None, "not warned of at once");
        std::thread::sleep(period + period / 2);
        let first = held_back_warned(admission).expect("warned of once it lasted the period");
        assert_eq!(
            held_back_warned(admission),
            Some(first),
            "warned of at most once a period"
        );
        std::thread::sleep(period + period / 2);
        let second = held_back_warned(admission).expect("still held back");
        assert!(second > first, "warned of again a period later");
        memory.store(12 * GIB, Ordering::SeqCst);
        // Look now: the looks above count as the waiting one's own.
        admission.admit_waiting(&mut admission.state());
        assert!(granted(&labelling), "it starts once the memory is there");
        assert!(
            admission.state().held_back.is_none(),
            "no longer held back once it has its memory"
        );
        drop(labelling.release);
    }

    /// Work ahead held back for memory whose window passes leaves the
    /// queue, and with no other work ahead waiting nothing is held back.
    #[test]
    fn work_ahead_is_no_longer_held_back_once_none_waits() {
        let (admission, _) = admission(8, 2 * GIB);
        let expired = Arc::new(AtomicBool::new(false));
        let flag = expired.clone();
        let (left_tx, left) = mpsc::channel();
        std::thread::spawn(move || {
            let reservation = admission.reserve_ordered(
                8 * GIB,
                Urgency::Ahead,
                Some(ahead(false, 1, 0)),
                true,
                &|| flag.load(Ordering::SeqCst),
            );
            left_tx.send(reservation.is_none()).unwrap();
        });
        until_waiting(admission, 1);
        assert!(admission.state().held_back.is_some(), "it is held back");
        expired.store(true, Ordering::SeqCst);
        assert_eq!(left.recv_timeout(SOON), Ok(true), "it leaves the queue");
        assert!(
            admission.state().held_back.is_none(),
            "nothing is held back once no work ahead waits"
        );
    }

    /// An admission of `slots` jobs sharing a constant `available`, whose
    /// waiting reservations may be passed for `window` after first being.
    fn admission_passing(slots: usize, available: u64, window: Duration) -> &'static Admission {
        let admission = Box::leak(Box::new(Admission::new(
            slots,
            Box::new(move || Some(available)),
        )));
        admission.pass_window = window;
        admission.ahead_jobs = usize::MAX;
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
        // Work ahead alone runs within the share (30 GiB): it takes all of it.
        let large = hold_with(admission, 30 * GIB, Urgency::Ahead);
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
        assert!(still_waiting(&large), "38 GiB do not fit in 30");
        assert!(still_waiting(&late), "nor does anything pass it");
        drop(passers);
        assert!(granted(&large), "it runs alone once no job holds memory");
        assert!(
            still_waiting(&late),
            "nothing runs beside a job that takes the whole share"
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
        assert_eq!(waiting(admission), 0);
        drop(first.release);
        drop(ahead.release);
    }

    /// Regression for the 64 GiB Mac whose sysinfo estimate saturated to zero
    /// despite normal kernel pressure, silently serializing nine cold sectors.
    #[test]
    fn macos_normal_pressure_admits_nine_cold_sectors() {
        let snapshot = macos_memory::Snapshot {
            total: 64 * GIB,
            wired: 7 * GIB,
            footprint: 3 * GIB,
            pressure: 1,
        };
        let admission = Box::leak(Box::new(Admission::new(
            9,
            Box::new(move || Some(snapshot.headroom())),
        )));
        let cold_bytes = quil_crypto::storage_proof::labelling_peak_bytes(
            1 << 24,
            &quil_crypto::sdr::SdrParams::default(),
        ) + (400 << 20);
        let held: Vec<_> = (0..9)
            .map(|leaf| {
                let held = hold_parallel(admission, cold_bytes, ahead(false, 1, leaf));
                assert!(
                    granted(&held),
                    "every cold sector fits alongside the others"
                );
                held
            })
            .collect();
        assert_eq!(admission.state().holders, 9);
        let extra = hold_parallel(admission, cold_bytes, ahead(false, 1, 9));
        assert!(still_waiting(&extra), "the CPU slot limit still applies");
        drop(held);
        assert!(granted(&extra));
    }

    #[test]
    fn macos_pressure_stops_admission_and_normal_pressure_resumes_it() {
        let pressure = Arc::new(std::sync::atomic::AtomicU32::new(1));
        let probe = pressure.clone();
        let mut admission = Admission::new(
            9,
            Box::new(move || {
                Some(
                    macos_memory::Snapshot {
                        total: 64 * GIB,
                        wired: 7 * GIB,
                        footprint: 3 * GIB,
                        pressure: probe.load(Ordering::SeqCst),
                    }
                    .headroom(),
                )
            }),
        );
        admission.window = Duration::ZERO;
        let admission = Box::leak(Box::new(admission));
        // Pressure with no holders must be known zero, not unknown memory:
        // unknown memory deliberately admits one ahead job as a fallback.
        pressure.store(2, Ordering::SeqCst);
        let ahead = hold_with(admission, GIB, Urgency::Ahead);
        assert!(still_waiting(&ahead));
        let due = hold(admission, GIB);
        assert!(
            granted(&due),
            "urgent work retains its one-job escape hatch"
        );
        assert!(still_waiting(&ahead), "no extra work starts under pressure");
        pressure.store(1, Ordering::SeqCst);
        admission.changed.notify_all();
        assert!(granted(&ahead), "normal pressure resumes parallel work");
        drop(due);
        drop(ahead);
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

    /// A seat's leaves run on named threads, so a crash on one (a stack
    /// overflow, say) names the work it ran.
    #[test]
    fn a_seats_leaves_run_on_named_threads() {
        let names = for_each_parallel(&[(); 4], |_| {
            Ok(std::thread::current().name().map(str::to_owned))
        })
        .unwrap();
        for name in &names {
            assert!(
                name.as_deref()
                    .is_some_and(|name| name.starts_with("stor-leaf-")),
                "the leaves ran on threads named {names:?}"
            );
        }
    }
}

#[cfg(test)]
mod profile_context_tests {
    use super::*;
    use quil_types::consensus::*;
    #[test]
    fn parallel_jobs_receive_profile_and_sector_floor() {
        let old_profile = storage_seal_profile_thread_override();
        let old_minimum = min_sector_nodes_thread_override();
        set_storage_seal_profile_for_thread(Some(StorageSealProfile::Three));
        set_min_sector_nodes_for_thread(Some(64));
        let values = for_each_parallel(&[0u8, 1], |_| {
            Ok((storage_seal_profile(1500), min_sector_nodes()))
        })
        .unwrap();
        set_storage_seal_profile_for_thread(old_profile);
        set_min_sector_nodes_for_thread(old_minimum);
        assert_eq!(values, vec![(StorageSealProfile::Three, 64); 2]);
    }
}
