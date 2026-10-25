//! The storage watch of this process's stores
//! ([`quil_forest::storage_health`]) with the operator's `db` thresholds,
//! and the recovery of a store whose writes stopped: after a failed write,
//! or when free space fell below the floor
//! ([`storage_health::FLOOR_FREE_BYTES`]). The store cannot be repaired in
//! place, since a failed write's durable effect is unknown: it is closed
//! and reopened, which replays its WAL. A thread worker's store is reopened
//! by stopping the worker and restarting it once its disk has room again;
//! the master's store, or a separate worker process's, by exiting for the
//! service manager to restart the process.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use quil_forest::storage_health::{self, describe_stores, FsUsage};
use quil_forest::{DiskThresholds, StoreRole};
use tracing::{error, info, warn};

static THRESHOLDS: OnceLock<DiskThresholds> = OnceLock::new();

/// Start this process's storage watch with `db`'s disk usage thresholds,
/// or the defaults when they are not ordered percentages.
pub(crate) fn start(db: &quil_config::DbConfig) {
    let thresholds =
        DiskThresholds::new(db.notice_percentage, db.warn_percentage, db.terminate_percentage).unwrap_or_else(|error| {
            let defaults = DiskThresholds::default();
            warn!(
                %error,
                notice_pct = defaults.notice,
                warn_pct = defaults.warn,
                terminate_pct = defaults.terminate,
                "invalid db disk usage thresholds in the node config; using the defaults"
            );
            defaults
        });
    let _ = THRESHOLDS.set(thresholds);
    storage_health::spawn_storage_watch(thresholds);
}

/// Whether a filesystem has room to reopen a store
/// ([`storage_health::has_headroom`]).
pub(crate) fn has_space(usage: Option<FsUsage>) -> bool {
    usage.is_some_and(|usage| storage_health::has_headroom(&usage))
}

/// How often recovery looks at the stores.
const RECOVERY_INTERVAL: Duration = Duration::from_secs(10);
/// How often a wait is repeated in the log.
const REMIND: Duration = Duration::from_secs(600);
/// How long a stopped worker's thread may take to end.
pub(crate) const STOP_DEADLINE: Duration = Duration::from_secs(30);
/// How long a reopened store must go without stopping again to count as
/// recovered, which resets its restart count.
const STABLE_AFTER: Duration = Duration::from_secs(1_800);
/// Restarts of one worker in a row before recovery leaves it to the operator.
pub(crate) const MAX_RESTARTS: u32 = 3;

/// What recovery needs from the node to reopen a thread worker's store.
pub(crate) trait WorkerControl: Send + Sync {
    /// Stop the worker's thread, keeping its allocation, so its stores
    /// close; whether the thread ended within [`STOP_DEADLINE`].
    fn stop(&self, core: u32) -> bool;
    /// Drop the master's own handles on the worker's store.
    fn release(&self, core: u32);
    /// Start the worker again with its allocation, reopening its store.
    fn restart(&self, core: u32) -> anyhow::Result<()>;
    /// Whether the restarted worker's stores serve its shard again, so its
    /// confirm can be prepared from them and not from the master's.
    fn ready(&self, core: u32) -> bool;
    /// Whether the node is shutting down: no worker restarts then.
    fn shutting_down(&self) -> bool;
    /// Whether the worker's thread still runs, opening its stores or
    /// serving: a restart then would replace a live thread.
    fn running(&self, core: u32) -> bool;
}

enum Step {
    /// The worker was stopped; its store has not closed yet.
    Closing { since: Instant, reminded: Instant },
    /// The store is closed and waits for its disk to have room.
    AwaitingSpace { since: Instant, reminded: Instant },
    /// The worker was restarted; its store has not reopened, or its worker
    /// does not serve its shard from it, yet.
    Reopening { at: Instant, reminded: Instant },
    /// The store reopened.
    Reopened { at: Instant },
    /// Left to the operator, who restarts the node.
    GaveUp { reminded: Instant },
}

struct Recovering {
    /// The store's directory, probed for its filesystem; never logged.
    path: PathBuf,
    step: Step,
    restarts: u32,
}

/// What one look at the worker stores did, by worker, logged as one line
/// per kind.
#[derive(Default)]
struct Events {
    stopped: Vec<u32>,
    stuck: Vec<u32>,
    closed: Vec<u32>,
    still_closing: Vec<(u32, u64)>,
    still_waiting: Vec<(u32, u64)>,
    waiting_for_master: Vec<(u32, u64)>,
    still_opening: Vec<(u32, u64)>,
    restart_failed: Vec<(u32, String)>,
    reopened: Vec<u32>,
    not_ready: Vec<(u32, u64)>,
    reopen_retry: Vec<u32>,
    not_reopened: Vec<u32>,
    recovered: Vec<u32>,
    exhausted: Vec<u32>,
    abandoned: Vec<u32>,
}

fn workers(cores: impl IntoIterator<Item = u32>) -> String {
    describe_stores(&cores.into_iter().map(StoreRole::Worker).collect::<Vec<_>>())
}

impl Events {
    fn log(self) {
        let headroom = storage_health::headroom_text();
        let longest = |waits: &[(u32, u64)]| waits.iter().map(|(_, secs)| *secs).max().unwrap_or(0);
        if !self.stopped.is_empty() {
            let workers = workers(self.stopped);
            info!(%workers, scope = "this node",
                "worker stores stopped writing (a failed write, or free space below the floor): stopping {workers}, \
                 keeping their allocations, to reopen their stores once their disk has {headroom}");
        }
        if !self.stuck.is_empty() {
            let workers = workers(self.stuck);
            warn!(%workers, deadline_secs = STOP_DEADLINE.as_secs(), scope = "this node",
                "worker threads did not stop in time: {workers}; their stores reopen only after the threads end");
        }
        if !self.closed.is_empty() {
            let workers = workers(self.closed);
            info!(%workers, scope = "this node",
                "worker stores closed: {workers} restart once their disk has {headroom}");
        }
        if !self.still_closing.is_empty() {
            let waited_secs = longest(&self.still_closing);
            let workers = workers(self.still_closing.into_iter().map(|(core, _)| core));
            warn!(%workers, waited_secs, scope = "this node",
                "worker stores stay open after their workers stopped, so they cannot be reopened yet: {workers}; \
                 something in this node still holds them; restart the node if this persists");
        }
        if !self.still_waiting.is_empty() {
            let waited_secs = longest(&self.still_waiting);
            let workers = workers(self.still_waiting.into_iter().map(|(core, _)| core));
            warn!(%workers, waited_secs, scope = "this node",
                "workers still wait for disk space to reopen their stores: {workers}; free space on their disk; \
                 they restart once it has {headroom}");
        }
        if !self.waiting_for_master.is_empty() {
            let waited_secs = longest(&self.waiting_for_master);
            let workers = workers(self.waiting_for_master.into_iter().map(|(core, _)| core));
            warn!(%workers, waited_secs, scope = "this node",
                "workers wait to reopen their stores while the master's store has stopped writing: {workers}; they \
                 restart only once the master's store is back (see the master store's lines)");
        }
        if !self.still_opening.is_empty() {
            let waited_secs = longest(&self.still_opening);
            let workers = workers(self.still_opening.into_iter().map(|(core, _)| core));
            warn!(%workers, waited_secs, scope = "this node",
                "restarted workers are still opening their stores: {workers}; a large store replays its log and \
                 opens its files first");
        }
        let first_error = self.restart_failed.first().map(|(_, error)| error.clone());
        if let Some(error) = first_error {
            let workers = workers(self.restart_failed.into_iter().map(|(core, _)| core));
            warn!(%workers, %error, scope = "this node",
                "could not restart workers to reopen their stores: {workers}; retrying in {}s",
                RECOVERY_INTERVAL.as_secs());
        }
        if !self.reopened.is_empty() {
            let workers = workers(self.reopened);
            info!(%workers, scope = "this node", "workers restarted and their stores reopened: {workers}");
        }
        if !self.not_ready.is_empty() {
            let waited_secs = longest(&self.not_ready);
            let workers = workers(self.not_ready.into_iter().map(|(core, _)| core));
            warn!(%workers, waited_secs, scope = "this node",
                "worker stores reopened but their workers do not serve their shards from them yet: {workers}; their \
                 confirm seats stay left out until they do");
        }
        if !self.reopen_retry.is_empty() {
            let workers = workers(self.reopen_retry);
            warn!(%workers, scope = "this node",
                "restarted workers ended before serving their shards from their reopened stores: {workers}; they \
                 stay stopped, and are restarted again");
        }
        if !self.not_reopened.is_empty() {
            let workers = workers(self.not_reopened);
            error!(%workers, restarts = MAX_RESTARTS, scope = "this node",
                "restarted workers ended before serving their shards from their reopened stores: {workers}; they \
                 stay stopped rather than run on the master's stores: check the disk and the store files, then \
                 restart the node");
        }
        if !self.recovered.is_empty() {
            let workers = workers(self.recovered);
            info!(%workers, stable_secs = STABLE_AFTER.as_secs(), scope = "this node",
                "worker stores recovered: {workers} have not stopped writing since they were reopened");
        }
        if !self.exhausted.is_empty() {
            let workers = workers(self.exhausted);
            error!(%workers, restarts = MAX_RESTARTS, scope = "this node",
                "worker stores stopped writing again after {MAX_RESTARTS} restarts in a row: {workers}; the node \
                 keeps these workers stopped: check the disk and the store files, then restart the node");
        }
        if !self.abandoned.is_empty() {
            let workers = workers(self.abandoned);
            error!(%workers, scope = "this node",
                "worker stores are not recovered automatically: {workers}: restart the node");
        }
    }
}

/// The recovery of the stores of this process's thread workers.
pub(crate) struct WorkerRecovery {
    workers: BTreeMap<u32, Recovering>,
}

impl WorkerRecovery {
    pub(crate) fn new() -> Self {
        Self { workers: BTreeMap::new() }
    }

    /// Whether no worker store is being recovered.
    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        self.workers.is_empty()
    }

    /// One look at the worker stores at `now`: stop the worker of a store
    /// whose writes stopped, and restart it once the store closed and its
    /// disk has room, at most [`MAX_RESTARTS`] times in a row.
    pub(crate) fn tick(&mut self, now: Instant, control: &dyn WorkerControl, probe: &dyn Fn(&Path) -> Option<FsUsage>) {
        let mut events = Events::default();
        for role in storage_health::latched_stores() {
            let StoreRole::Worker(core) = role else { continue };
            let restarts = match self.workers.get(&core) {
                None => 0,
                // Reopened, or reopened but not serving its shard yet.
                Some(Recovering { step: Step::Reopened { .. } | Step::Reopening { .. }, restarts, .. }) => *restarts,
                Some(_) => continue,
            };
            if restarts >= MAX_RESTARTS {
                // Stopped as on its first stop, and never restarted: left
                // running on a store that refuses writes, its seat would be
                // renewed and its confirm fail.
                storage_health::hold_store(role);
                if !control.stop(core) {
                    events.stuck.push(core);
                }
                control.release(core);
                events.exhausted.push(core);
                self.workers.insert(core, Recovering { path: PathBuf::new(), step: Step::GaveUp { reminded: now }, restarts });
                continue;
            }
            let Some(path) = storage_health::store_path(role) else { continue };
            storage_health::hold_store(role);
            events.stopped.push(core);
            if !control.stop(core) {
                events.stuck.push(core);
            }
            control.release(core);
            self.workers.insert(core, Recovering { path, step: Step::Closing { since: now, reminded: now }, restarts });
        }

        for (&core, entry) in &mut self.workers {
            let role = StoreRole::Worker(core);
            let since_secs = |since: Instant| now.saturating_duration_since(since).as_secs();
            match entry.step {
                Step::Closing { since, reminded } => {
                    if !storage_health::store_open(role) {
                        events.closed.push(core);
                        entry.step = Step::AwaitingSpace { since: now, reminded: now };
                    } else if now.saturating_duration_since(reminded) >= REMIND {
                        // Not final: a holder that outlasts the stop (a long
                        // encode, a stream) lets go eventually.
                        events.still_closing.push((core, since_secs(since)));
                        entry.step = Step::Closing { since, reminded: now };
                    }
                }
                Step::AwaitingSpace { since, reminded } => {
                    // A master store that stopped writing exits this process
                    // once space returns: no worker store opens before.
                    let master_stopped = storage_health::store_latched(StoreRole::Master);
                    if !master_stopped && !control.shutting_down() && has_space(probe(&entry.path)) {
                        entry.restarts += 1;
                        match control.restart(core) {
                            Ok(()) => entry.step = Step::Reopening { at: now, reminded: now },
                            Err(error) if entry.restarts < MAX_RESTARTS => {
                                events.restart_failed.push((core, error.to_string()))
                            }
                            Err(_) => {
                                events.abandoned.push(core);
                                entry.step = Step::GaveUp { reminded: now };
                            }
                        }
                    } else if now.saturating_duration_since(reminded) >= REMIND {
                        if master_stopped {
                            events.waiting_for_master.push((core, since_secs(since)));
                        } else {
                            events.still_waiting.push((core, since_secs(since)));
                        }
                        entry.step = Step::AwaitingSpace { since, reminded: now };
                    }
                }
                Step::Reopening { at, reminded } => {
                    let open = storage_health::store_open(role);
                    if open && control.ready(core) {
                        storage_health::release_store(role);
                        events.reopened.push(core);
                        entry.step = Step::Reopened { at: now };
                    } else if open && !control.running(core) {
                        // The thread ended after opening the store but before
                        // serving its shard (a panic): the store stays open
                        // with no worker on it. Stopped and released again,
                        // as a counted restart, and retried once it closes.
                        storage_health::hold_store(role);
                        if !control.stop(core) {
                            events.stuck.push(core);
                        }
                        control.release(core);
                        if entry.restarts >= MAX_RESTARTS {
                            events.not_reopened.push(core);
                            entry.step = Step::GaveUp { reminded: now };
                        } else {
                            events.reopen_retry.push(core);
                            entry.step = Step::Closing { since: now, reminded: now };
                        }
                    } else if open {
                        if now.saturating_duration_since(reminded) >= REMIND {
                            events.not_ready.push((core, since_secs(at)));
                            entry.step = Step::Reopening { at, reminded: now };
                        }
                    } else if control.running(core) {
                        // Still opening its store (a WAL replay after a
                        // failed write can take long): never replaced.
                        if now.saturating_duration_since(reminded) >= REMIND {
                            events.still_opening.push((core, since_secs(at)));
                            entry.step = Step::Reopening { at, reminded: now };
                        }
                    } else {
                        // The thread ended without opening the store, so the
                        // worker stays stopped: it never runs on the master's
                        // stores. A counted restart, retried.
                        if entry.restarts >= MAX_RESTARTS {
                            events.not_reopened.push(core);
                            entry.step = Step::GaveUp { reminded: now };
                        } else {
                            events.reopen_retry.push(core);
                            entry.step = Step::AwaitingSpace { since: now, reminded: now };
                        }
                    }
                }
                Step::Reopened { at } => {
                    if now.saturating_duration_since(at) >= STABLE_AFTER && !storage_health::store_latched(role) {
                        events.recovered.push(core);
                    }
                }
                Step::GaveUp { reminded } => {
                    if now.saturating_duration_since(reminded) >= REMIND {
                        events.abandoned.push(core);
                        entry.step = Step::GaveUp { reminded: now };
                    }
                }
            }
        }
        for core in &events.recovered {
            self.workers.remove(core);
        }
        events.log();
    }
}

/// Run [`WorkerRecovery`] for this process's thread workers on its own
/// thread, every [`RECOVERY_INTERVAL`], until `shutdown` is cancelled.
pub(crate) fn spawn_worker_recovery(control: Arc<dyn WorkerControl>, shutdown: tokio_util::sync::CancellationToken) {
    let spawned = std::thread::Builder::new().name("storage-recovery".into()).spawn(move || {
        let mut recovery = WorkerRecovery::new();
        loop {
            std::thread::sleep(RECOVERY_INTERVAL);
            if shutdown.is_cancelled() {
                return;
            }
            recovery.tick(Instant::now(), control.as_ref(), &storage_health::fs_usage);
        }
    });
    if let Err(error) = spawned {
        warn!(%error, "could not start the recovery of worker stores: a worker store that stops writing stays \
            stopped until the node restarts");
    }
}

/// What a process whose own store stopped writing waits for before it
/// exits for its service manager to restart it and reopen the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reopen {
    /// An error more space does not resolve: the operator acts.
    Never,
    /// A space error on a filesystem that showed no room: its headroom.
    Headroom,
    /// A space error on a filesystem that showed room (a disk quota,
    /// filesystem metadata, or space released after the failed write):
    /// its headroom and a test reservation next to the store
    /// ([`storage_health::can_reserve`]), so a limit the free counts do
    /// not show is not met again at once by the restarted process.
    Reservation,
}

/// How often a test reservation next to a stopped store is tried.
const RESERVE_INTERVAL: Duration = Duration::from_secs(60);

/// When a process whose own store stopped writing exits: once the store's
/// disk has room again, so that its service manager restarts it and the
/// store is reopened.
pub(crate) struct ProcessExit {
    role: StoreRole,
    /// The store's directory, when it stopped and what its reopening
    /// waits for.
    latched: Option<(PathBuf, Instant, Reopen)>,
    reminded: Instant,
    /// When the last test reservation was tried.
    reserved_at: Option<Instant>,
    reserve: fn(&Path, u64) -> Option<bool>,
}

impl ProcessExit {
    pub(crate) fn new(role: StoreRole, now: Instant) -> Self {
        Self { role, latched: None, reminded: now, reserved_at: None, reserve: storage_health::can_reserve }
    }

    /// Whether a test reservation next to the store succeeds at `now`, at
    /// most once per [`RESERVE_INTERVAL`]. Where the filesystem cannot
    /// reserve space without writing it, its headroom is all there is.
    fn reserved(&mut self, now: Instant, path: &Path) -> bool {
        if self.reserved_at.is_some_and(|at| now.saturating_duration_since(at) < RESERVE_INTERVAL) {
            return false;
        }
        self.reserved_at = Some(now);
        (self.reserve)(path, storage_health::REOPEN_RESERVE_BYTES).unwrap_or(true)
    }

    /// One look at the store at `now`; the reason to exit, once due.
    pub(crate) fn tick(&mut self, now: Instant, probe: &dyn Fn(&Path) -> Option<FsUsage>) -> Option<String> {
        let (store, headroom) = (self.role.to_string(), storage_health::headroom_text());
        let reserve_mb = storage_health::REOPEN_RESERVE_BYTES >> 20;
        if self.latched.is_none() {
            if !storage_health::store_latched(self.role) {
                return None;
            }
            // Read once the failure is recorded: the latch sets its flag first.
            let (class, no_room) = storage_health::store_failure(self.role)?;
            let reopen = if !storage_health::space_class(class) {
                Reopen::Never
            } else if storage_health::recovers_with_space(class, no_room) {
                Reopen::Headroom
            } else {
                Reopen::Reservation
            };
            self.latched = Some((storage_health::store_path(self.role)?, now, reopen));
            self.reminded = now;
            match reopen {
                Reopen::Never => {
                    // A restart would fail again at once: the operator acts.
                    error!(
                        store = %store,
                        error_class = class,
                        scope = "this node",
                        "store stopped writing after an error more space does not resolve: this process does not \
                         exit for it; check the disk and the store files, then restart the node"
                    );
                    return None;
                }
                Reopen::Reservation => info!(
                    store = %store,
                    error_class = class,
                    reserve_mb,
                    scope = "this node",
                    "store ran out of space although its filesystem shows room (a disk quota, filesystem metadata, \
                     or space released after the failed write): this process exits once its disk has {headroom} \
                     and {reserve_mb} MiB can be reserved next to the store, for its service manager to restart it \
                     and reopen the store; the service needs a restart policy (systemd Restart=on-failure, launchd \
                     KeepAlive)"
                ),
                Reopen::Headroom => info!(
                    store = %store,
                    scope = "this node",
                    "store stopped writing (a failed write, or free space below the floor): this process exits once \
                     its disk has {headroom}, for its service manager to restart it and reopen the store; the \
                     service needs a restart policy (systemd Restart=on-failure, launchd KeepAlive)"
                ),
            }
        }
        let (path, since, reopen) = self.latched.clone()?;
        if reopen == Reopen::Never {
            return None;
        }
        let usage = probe(&path);
        let waited_secs = now.saturating_duration_since(since).as_secs();
        let room = has_space(usage);
        if room && (reopen == Reopen::Headroom || self.reserved(now, &path)) {
            error!(
                store = %store,
                free_mb = usage.map(|usage| usage.free_mb()),
                waited_secs,
                scope = "this node",
                "store stopped writing and its disk has {headroom} again: exiting so that the service manager \
                 restarts this process and reopens the store"
            );
            return Some(format!("the {store} store stopped writing; exiting to reopen it"));
        }
        if now.saturating_duration_since(self.reminded) >= REMIND {
            self.reminded = now;
            if room {
                warn!(
                    store = %store,
                    free_mb = usage.map(|usage| usage.free_mb()),
                    reserve_mb,
                    waited_secs,
                    scope = "this node",
                    "store still stopped: its disk shows room but {reserve_mb} MiB cannot be reserved next to the \
                     store; check the disk quota and the filesystem's metadata space; this process exits for a \
                     restart once the reservation succeeds"
                );
            } else {
                warn!(
                    store = %store,
                    free_mb = usage.map(|usage| usage.free_mb()),
                    free_inodes = usage.map(|usage| usage.free_inodes),
                    waited_secs,
                    scope = "this node",
                    "store still stopped and waits for disk space: free space on its disk; this process exits for \
                     a restart once it has {headroom}"
                );
            }
        }
        None
    }
}

/// A supervised task that fails, so the process exits non-zero, once the
/// stopped store of `role` can be reopened ([`ProcessExit`]).
pub(crate) async fn exit_when_store_reopenable(role: StoreRole) -> anyhow::Result<()> {
    let mut exit = ProcessExit::new(role, Instant::now());
    loop {
        tokio::time::sleep(RECOVERY_INTERVAL).await;
        if let Some(reason) = exit.tick(Instant::now(), &storage_health::fs_usage) {
            return Err(anyhow::anyhow!(reason));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    fn usage(free_gib: u64) -> FsUsage {
        FsUsage {
            device: 1,
            total_bytes: 1_000 << 30,
            used_bytes: (1_000 - free_gib) << 30,
            free_bytes: free_gib << 30,
            total_inodes: 1_000_000,
            used_inodes: 1_000,
            free_inodes: 999_000,
        }
    }

    /// Thread workers as the node runs them: each opens its own store on
    /// its thread, which closes when the worker stops, unless something
    /// still holds it; a restart may fail to reopen it.
    struct Workers {
        dirs: BTreeMap<u32, tempfile::TempDir>,
        open: Mutex<BTreeMap<u32, quil_store::RocksDb>>,
        holders: Mutex<Vec<quil_forest::CoordinatedDb>>,
        reopen: std::sync::atomic::AtomicBool,
        serving: std::sync::atomic::AtomicBool,
        running: std::sync::atomic::AtomicBool,
        calls: Mutex<Vec<String>>,
    }

    impl Workers {
        fn new(cores: &[u32]) -> Self {
            let workers = Self {
                dirs: cores.iter().map(|core| (*core, tempfile::tempdir().unwrap())).collect(),
                open: Mutex::new(BTreeMap::new()),
                holders: Mutex::new(Vec::new()),
                reopen: std::sync::atomic::AtomicBool::new(true),
                serving: std::sync::atomic::AtomicBool::new(true),
                running: std::sync::atomic::AtomicBool::new(false),
                calls: Mutex::new(Vec::new()),
            };
            for core in cores {
                workers.open(*core);
            }
            workers
        }

        fn open(&self, core: u32) {
            let db = quil_store::RocksDb::open(self.dirs[&core].path()).unwrap();
            assert!(db.inner().register_store(StoreRole::Worker(core)));
            self.open.lock().unwrap().insert(core, db);
        }

        fn write(&self, core: u32) -> bool {
            self.open.lock().unwrap()[&core].inner().put([0xee, core as u8], b"v").is_ok()
        }

        fn latch(&self, core: u32) {
            self.open.lock().unwrap()[&core].inner().refuse_writes("IO error: No space left on device");
        }

        /// Something else keeps `core`'s store open until `let_go`.
        fn hold(&self, core: u32) {
            let db = self.open.lock().unwrap()[&core].inner();
            self.holders.lock().unwrap().push(db);
        }

        fn let_go(&self) {
            self.holders.lock().unwrap().clear();
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl WorkerControl for Workers {
        fn stop(&self, core: u32) -> bool {
            if self.dirs.contains_key(&core) {
                self.calls.lock().unwrap().push(format!("stop {core}"));
                drop(self.open.lock().unwrap().remove(&core));
            }
            true
        }
        fn release(&self, core: u32) {
            if self.dirs.contains_key(&core) {
                self.calls.lock().unwrap().push(format!("release {core}"));
            }
        }
        fn restart(&self, core: u32) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push(format!("restart {core}"));
            if self.reopen.load(Ordering::SeqCst) {
                self.open(core);
            }
            Ok(())
        }
        fn ready(&self, _core: u32) -> bool {
            self.serving.load(Ordering::SeqCst)
        }
        fn shutting_down(&self) -> bool {
            false
        }
        fn running(&self, _core: u32) -> bool {
            self.running.load(Ordering::SeqCst)
        }
    }

    fn probe_of(free_gib: &Arc<AtomicU64>) -> impl Fn(&Path) -> Option<FsUsage> {
        let free_gib = free_gib.clone();
        move |_: &Path| Some(usage(free_gib.load(Ordering::SeqCst)))
    }

    /// A worker whose store stopped writing is stopped with its allocation,
    /// waits for its disk to have room, and is restarted to reopen the
    /// store, which takes writes again; the master's store is untouched.
    #[test]
    fn a_stopped_worker_store_is_reopened_once_its_disk_has_room() {
        let master_dir = tempfile::tempdir().unwrap();
        let master = quil_store::RocksDb::open(master_dir.path()).unwrap();
        assert!(master.inner().register_store(StoreRole::Master));
        let core = 8_101;
        let workers = Workers::new(&[core, 8_102]);
        let free_gib = Arc::new(AtomicU64::new(1));
        let probe = probe_of(&free_gib);
        let mut recovery = WorkerRecovery::new();
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        recovery.tick(at(0), &workers, &probe);
        assert!(workers.calls().is_empty() && recovery.is_idle(), "stores that take writes are left alone");

        workers.latch(core);
        assert!(!workers.write(core));
        recovery.tick(at(10), &workers, &probe);
        assert_eq!(workers.calls(), ["stop 8101", "release 8101"]);
        let held = quil_engine::worker_execution::with_store_state(core, None).expect("a stopped worker is reported");
        assert_eq!((held.state.as_str(), held.blocker.as_str()),
            ("stopped", quil_engine::worker_execution::STORAGE_WRITE_FAILED));
        for secs in [20, 30, 700] {
            recovery.tick(at(secs), &workers, &probe);
        }
        free_gib.store(3, Ordering::SeqCst);
        recovery.tick(at(710), &workers, &probe);
        assert_eq!(workers.calls().len(), 2, "no restart below twice the floor");

        free_gib.store(4, Ordering::SeqCst);
        recovery.tick(at(720), &workers, &probe);
        assert_eq!(workers.calls(), ["stop 8101", "release 8101", "restart 8101"]);
        assert!(storage_health::store_held(StoreRole::Worker(core)), "held until the store is seen open");
        recovery.tick(at(730), &workers, &probe);
        assert!(!storage_health::store_held(StoreRole::Worker(core)));
        assert!(workers.write(core), "the reopened store takes writes");
        assert_eq!(quil_engine::worker_execution::with_store_state(core, None), None);
        assert!(workers.write(8_102), "another worker's store is untouched");
        assert!(master.inner().put([0xee], b"v").is_ok() && !master.inner().write_failed(),
            "the master's store is untouched");
        recovery.tick(at(730 + STABLE_AFTER.as_secs()), &workers, &probe);
        assert!(recovery.is_idle(), "a store that has not stopped since it was reopened is recovered");
    }

    /// A store something still holds after its worker stopped is waited for,
    /// not given up on, and reopened once it is let go.
    #[test]
    fn a_store_held_past_its_workers_stop_is_waited_for() {
        let core = 8_111;
        let workers = Workers::new(&[core]);
        let probe = |_: &Path| Some(usage(500));
        let mut recovery = WorkerRecovery::new();
        let t0 = Instant::now();
        workers.hold(core);
        workers.latch(core);
        for secs in [0, 10, 300, 900, 3_600] {
            recovery.tick(t0 + Duration::from_secs(secs), &workers, &probe);
        }
        assert_eq!(workers.calls(), ["stop 8111", "release 8111"], "no restart while the store is open");
        workers.let_go();
        recovery.tick(t0 + Duration::from_secs(3_610), &workers, &probe);
        recovery.tick(t0 + Duration::from_secs(3_620), &workers, &probe);
        assert_eq!(workers.calls().last().map(String::as_str), Some("restart 8111"));
    }

    /// A restart that does not reopen the store keeps the worker stopped and
    /// held, instead of reporting a recovery; it counts as a restart, retried
    /// up to the bound.
    #[test]
    fn a_restart_that_does_not_reopen_the_store_keeps_the_worker_stopped() {
        let core = 8_121;
        let workers = Workers::new(&[core]);
        workers.reopen.store(false, Ordering::SeqCst);
        let probe = |_: &Path| Some(usage(500));
        let mut recovery = WorkerRecovery::new();
        let t0 = Instant::now();
        workers.latch(core);
        for secs in (0..=400).step_by(10) {
            recovery.tick(t0 + Duration::from_secs(secs), &workers, &probe);
        }
        let restarts = workers.calls().iter().filter(|call| call.starts_with("restart")).count();
        assert_eq!(restarts, MAX_RESTARTS as usize, "{:?}", workers.calls());
        assert!(storage_health::store_held(StoreRole::Worker(core)), "it stays stopped");
        assert!(!recovery.is_idle());
    }

    /// A restarted worker still opening its store, however long, is waited
    /// for and never replaced by another restart; once its thread ends
    /// without opening the store, it is restarted again.
    #[test]
    fn a_worker_still_opening_its_store_is_not_restarted_again() {
        let core = 8_151;
        let workers = Workers::new(&[core]);
        workers.reopen.store(false, Ordering::SeqCst);
        workers.running.store(true, Ordering::SeqCst);
        let probe = |_: &Path| Some(usage(500));
        let mut recovery = WorkerRecovery::new();
        let t0 = Instant::now();
        workers.latch(core);
        for secs in [0, 10, 40, 100, 700, 3_600] {
            recovery.tick(t0 + Duration::from_secs(secs), &workers, &probe);
        }
        let restarts = || workers.calls().iter().filter(|call| call.starts_with("restart")).count();
        assert_eq!(restarts(), 1, "one restart while its thread runs: {:?}", workers.calls());
        workers.running.store(false, Ordering::SeqCst);
        recovery.tick(t0 + Duration::from_secs(3_610), &workers, &probe);
        recovery.tick(t0 + Duration::from_secs(3_620), &workers, &probe);
        assert_eq!(restarts(), 2, "restarted again once it ended without its store");
    }

    /// A reopened store stays held, its seat left out, until its worker
    /// serves the shard from it again.
    #[test]
    fn a_reopened_store_is_held_until_its_worker_serves_its_shard() {
        let core = 8_131;
        let workers = Workers::new(&[core]);
        workers.serving.store(false, Ordering::SeqCst);
        workers.running.store(true, Ordering::SeqCst);
        let probe = |_: &Path| Some(usage(500));
        let mut recovery = WorkerRecovery::new();
        let t0 = Instant::now();
        workers.latch(core);
        for secs in [0, 10, 20, 700] {
            recovery.tick(t0 + Duration::from_secs(secs), &workers, &probe);
        }
        assert!(workers.write(core), "the store reopened");
        assert!(storage_health::store_held(StoreRole::Worker(core)), "but its worker does not serve the shard yet");
        workers.serving.store(true, Ordering::SeqCst);
        recovery.tick(t0 + Duration::from_secs(710), &workers, &probe);
        assert!(!storage_health::store_held(StoreRole::Worker(core)));
    }

    /// A restarted worker whose thread ended after reopening its store but
    /// before serving its shard is stopped and released again, as a counted
    /// restart, and retried once the store closes, up to the bound.
    #[test]
    fn a_worker_that_dies_after_reopening_its_store_is_retried() {
        let core = 8_161;
        let workers = Workers::new(&[core]);
        workers.serving.store(false, Ordering::SeqCst);
        let probe = |_: &Path| Some(usage(500));
        let mut recovery = WorkerRecovery::new();
        let t0 = Instant::now();
        workers.latch(core);
        for secs in (0..=300).step_by(10) {
            recovery.tick(t0 + Duration::from_secs(secs), &workers, &probe);
        }
        let count = |prefix: &str| workers.calls().iter().filter(|call| call.starts_with(prefix)).count();
        assert_eq!(count("restart"), MAX_RESTARTS as usize, "{:?}", workers.calls());
        assert_eq!(count("stop"), 1 + MAX_RESTARTS as usize, "each dead thread is stopped: {:?}", workers.calls());
        assert!(storage_health::store_held(StoreRole::Worker(core)), "it stays stopped");
        assert!(!storage_health::store_open(StoreRole::Worker(core)), "with its store closed");
    }

    /// A store that stops writing again while its worker reopens it (open,
    /// not yet serving its shard) is stopped again and counted.
    #[test]
    fn a_relatch_while_reopening_stops_the_worker_again() {
        let core = 8_171;
        let workers = Workers::new(&[core]);
        workers.serving.store(false, Ordering::SeqCst);
        workers.running.store(true, Ordering::SeqCst);
        let probe = |_: &Path| Some(usage(500));
        let mut recovery = WorkerRecovery::new();
        let t0 = Instant::now();
        workers.latch(core);
        for secs in [0, 10, 20] {
            recovery.tick(t0 + Duration::from_secs(secs), &workers, &probe);
        }
        assert_eq!(workers.calls(), ["stop 8171", "release 8171", "restart 8171"]);
        workers.latch(core);
        for secs in [30, 40] {
            recovery.tick(t0 + Duration::from_secs(secs), &workers, &probe);
        }
        assert_eq!(workers.calls(), ["stop 8171", "release 8171", "restart 8171", "stop 8171", "release 8171",
            "restart 8171"], "stopped again and restarted as a second, counted restart");
    }

    /// While the master's store has stopped writing, no worker restarts: the
    /// process exits for the master's store once space returns.
    #[test]
    fn no_worker_restarts_while_the_master_store_is_stopped() {
        let master_dir = tempfile::tempdir().unwrap();
        let master = quil_store::RocksDb::open(master_dir.path()).unwrap();
        assert!(master.inner().register_store(StoreRole::Master));
        let core = 8_141;
        let workers = Workers::new(&[core]);
        let probe = |_: &Path| Some(usage(500));
        let mut recovery = WorkerRecovery::new();
        let t0 = Instant::now();
        master.inner().refuse_writes("IO error: No space left on device");
        workers.latch(core);
        for secs in [0, 10, 20, 30] {
            recovery.tick(t0 + Duration::from_secs(secs), &workers, &probe);
        }
        assert_eq!(workers.calls(), ["stop 8141", "release 8141"]);
    }

    /// A worker store that keeps stopping is restarted at most MAX_RESTARTS
    /// times, then left to the operator.
    #[test]
    fn a_worker_store_failing_again_is_restarted_a_bounded_number_of_times() {
        let core = 8_201;
        let workers = Workers::new(&[core]);
        let probe = |_: &Path| Some(usage(500));
        let mut recovery = WorkerRecovery::new();
        let t0 = Instant::now();
        for round in 0..=MAX_RESTARTS as u64 {
            workers.latch(core);
            for step in 0..3 {
                recovery.tick(t0 + Duration::from_secs(40 * round + 10 * step), &workers, &probe);
            }
        }
        let restarts = workers.calls().iter().filter(|call| call.starts_with("restart")).count();
        assert_eq!(restarts, MAX_RESTARTS as usize, "{:?}", workers.calls());
        assert_eq!(workers.calls().len(), 3 * MAX_RESTARTS as usize + 2, "{:?}", workers.calls());
        assert_eq!(workers.calls()[3 * MAX_RESTARTS as usize..], ["stop 8201", "release 8201"],
            "stopped once more and kept stopped");
        assert!(storage_health::store_held(StoreRole::Worker(core)), "it reads as stopped");
        recovery.tick(t0 + Duration::from_secs(10_000), &workers, &probe);
        assert_eq!(workers.calls().len(), 3 * MAX_RESTARTS as usize + 2, "never restarted");
        assert!(!recovery.is_idle());
    }

    /// A process whose own store stopped writing exits once its disk has
    /// room again, not before.
    #[test]
    fn a_process_whose_store_stopped_exits_once_its_disk_has_room() {
        let dir = tempfile::tempdir().unwrap();
        let store = quil_store::RocksDb::open(dir.path()).unwrap();
        let role = StoreRole::Worker(8_301);
        assert!(store.inner().register_store(role));
        let free_gib = Arc::new(AtomicU64::new(1));
        let probe = probe_of(&free_gib);
        let t0 = Instant::now();
        let mut exit = ProcessExit::new(role, t0);
        assert_eq!(exit.tick(t0 + Duration::from_secs(10), &probe), None, "a store that takes writes keeps it");
        // The storage watch stops the store below the floor.
        let mut watch = storage_health::StorageWatch::new(DiskThresholds::default());
        storage_health::check_stores(&mut watch, t0 + Duration::from_secs(15), &probe);
        assert!(store.inner().write_failed());
        assert_eq!(exit.tick(t0 + Duration::from_secs(20), &probe), None, "no exit while the disk is full");
        free_gib.store(4, Ordering::SeqCst);
        let reason = exit.tick(t0 + Duration::from_secs(30), &probe).expect("exits once the disk has room");
        assert!(reason.contains("worker 8301 store"), "{reason}");
    }

    /// A process whose own store stopped for an error more space does not
    /// resolve never exits for it: a restart would fail again at once.
    #[test]
    fn a_process_whose_store_failed_for_another_error_does_not_exit() {
        let probe = |_: &Path| Some(usage(500));
        for (core, cause) in [(8_311, "IO error: Input/output error"), (8_314, "IO error: Read-only file system")] {
            let dir = tempfile::tempdir().unwrap();
            let store = quil_store::RocksDb::open(dir.path()).unwrap();
            let role = StoreRole::Worker(core);
            assert!(store.inner().register_store(role));
            store.inner().refuse_writes(cause);
            let t0 = Instant::now();
            let mut exit = ProcessExit::new(role, t0);
            for secs in [10, 20, 700, 3_600] {
                assert_eq!(exit.tick(t0 + Duration::from_secs(secs), &probe), None, "{cause} at {secs}s");
            }
        }
    }

    /// A store whose filesystem showed room when it ran out of space (a
    /// failed compaction released its output, a disk quota) is reopened
    /// by an exit too, once space can be reserved next to it: it does not
    /// wait for an operator's restart (#665).
    #[test]
    fn a_process_whose_store_ran_out_of_space_with_room_showing_exits() {
        let probe = |_: &Path| Some(usage(500));
        for (core, cause) in [(8_321, "IO error: No space left on device"), (8_322, "IO error: Disk quota exceeded")] {
            let dir = tempfile::tempdir().unwrap();
            let store = quil_store::RocksDb::open(dir.path()).unwrap();
            let role = StoreRole::Worker(core);
            assert!(store.inner().register_store(role));
            store.inner().refuse_writes(cause);
            let (_, no_room) = storage_health::store_failure(role).expect("latched");
            if no_room {
                // The test's own filesystem is short of the headroom: the
                // store then waits for it, which other tests cover.
                continue;
            }
            let t0 = Instant::now();
            let mut exit = ProcessExit::new(role, t0);
            let reason = exit.tick(t0 + Duration::from_secs(10), &probe).expect("exits once space can be reserved");
            assert!(reason.contains(&format!("worker {core} store")), "{reason}");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().filter(|entry| {
                entry.as_ref().unwrap().file_name().to_string_lossy().starts_with(".reserve-")
            }).count(), 0, "the reservation is removed");
        }
    }

    /// While space cannot be reserved next to such a store (a quota that
    /// still holds), the process keeps waiting, trying once a minute.
    #[test]
    fn a_process_waits_while_space_cannot_be_reserved_next_to_its_store() {
        static RESERVABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        static TRIED: AtomicU64 = AtomicU64::new(0);
        fn reserve(_: &Path, bytes: u64) -> Option<bool> {
            assert_eq!(bytes, storage_health::REOPEN_RESERVE_BYTES);
            TRIED.fetch_add(1, Ordering::SeqCst);
            Some(RESERVABLE.load(Ordering::SeqCst))
        }
        let dir = tempfile::tempdir().unwrap();
        let store = quil_store::RocksDb::open(dir.path()).unwrap();
        let role = StoreRole::Worker(8_331);
        assert!(store.inner().register_store(role));
        store.inner().refuse_writes("IO error: Disk quota exceeded");
        if storage_health::store_failure(role).expect("latched").1 {
            return; // No room showing on the test's filesystem: covered elsewhere.
        }
        let full = |_: &Path| Some(usage(1));
        let room = |_: &Path| Some(usage(500));
        let t0 = Instant::now();
        let mut exit = ProcessExit::new(role, t0);
        exit.reserve = reserve;
        assert_eq!(exit.tick(t0 + Duration::from_secs(10), &full), None, "no room showing now");
        assert_eq!(TRIED.load(Ordering::SeqCst), 0, "nothing reserved without room");
        assert_eq!(exit.tick(t0 + Duration::from_secs(20), &room), None, "the quota still holds");
        assert_eq!(exit.tick(t0 + Duration::from_secs(30), &room), None);
        assert_eq!(TRIED.load(Ordering::SeqCst), 1, "tried once a minute");
        RESERVABLE.store(true, Ordering::SeqCst);
        assert_eq!(exit.tick(t0 + Duration::from_secs(40), &room), None, "not before the minute is up");
        let reason = exit.tick(t0 + Duration::from_secs(80), &room).expect("exits once space can be reserved");
        assert!(reason.contains("worker 8331 store"), "{reason}");
        assert_eq!(TRIED.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn room_means_twice_the_floor() {
        assert!(has_space(Some(usage(4))));
        assert!(!has_space(Some(usage(3))));
        assert!(!has_space(None));
        assert!(!has_space(Some(FsUsage { free_inodes: 19_000, ..usage(500) })));
    }
}
