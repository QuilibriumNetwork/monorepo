//! What this node's stores tell its operator about their disks: a write
//! that failed and latched a store ([`CoordinatedDb`](crate::CoordinatedDb)
//! refuses every later write, since the failed write's durable effect is
//! unknown), and how full each store's filesystem is against the configured
//! thresholds ([`DiskThresholds`]).
//!
//! The node registers each store it runs with its role ([`StoreRole`]).
//! Reports name the role and the filesystem's free space and inodes, never
//! the store's path; stores on one filesystem share one headroom report.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use crate::database::DatabaseInner;

/// Which of this node's stores a database is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StoreRole {
    /// The master's store.
    Master,
    /// A data worker's own store, by core id.
    Worker(u32),
}

impl fmt::Display for StoreRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreRole::Master => f.write_str("master"),
            StoreRole::Worker(core) => write!(f, "worker {core}"),
        }
    }
}

/// `roles` for a log line: master first, consecutive workers as one range
/// (`master, workers 1-3, worker 7`).
pub fn describe_stores(roles: &[StoreRole]) -> String {
    fn close(run: &mut Option<(u32, u32)>, parts: &mut Vec<String>) {
        if let Some((first, last)) = run.take() {
            parts.push(if first == last { format!("worker {first}") } else { format!("workers {first}-{last}") });
        }
    }
    let mut roles = roles.to_vec();
    roles.sort();
    roles.dedup();
    let (mut parts, mut run) = (Vec::new(), None);
    for role in roles {
        match role {
            StoreRole::Master => parts.push("master".to_string()),
            StoreRole::Worker(core) => match run {
                Some((first, last)) if u32::checked_add(last, 1) == Some(core) => run = Some((first, core)),
                _ => {
                    close(&mut run, &mut parts);
                    run = Some((core, core));
                }
            },
        }
    }
    close(&mut run, &mut parts);
    parts.join(", ")
}

/// A filesystem's size and free space, as `statvfs` reports them to an
/// unprivileged process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsUsage {
    /// The filesystem's device: stores on one filesystem share a report.
    pub device: u64,
    pub total_bytes: u64,
    /// What an unprivileged writer may still use.
    pub free_bytes: u64,
    pub used_bytes: u64,
    /// 0 where the filesystem does not count inodes.
    pub total_inodes: u64,
    pub free_inodes: u64,
    pub used_inodes: u64,
}

fn percent(used: u64, free: u64) -> u8 {
    let all = u128::from(used) + u128::from(free);
    if all == 0 {
        return 0;
    }
    (u128::from(used) * 100).div_ceil(all).min(100) as u8
}

impl FsUsage {
    /// Used space as `df` shows it: used over used plus available, rounded up.
    pub fn bytes_used_percent(&self) -> u8 {
        percent(self.used_bytes, self.free_bytes)
    }

    /// Used inodes likewise; `None` where the filesystem does not count them.
    pub fn inodes_used_percent(&self) -> Option<u8> {
        (self.total_inodes > 0).then(|| percent(self.used_inodes, self.free_inodes))
    }

    /// The fuller of space and inodes: running out of either stops writes.
    pub fn used_percent(&self) -> u8 {
        self.bytes_used_percent().max(self.inodes_used_percent().unwrap_or(0))
    }

    pub fn free_mb(&self) -> u64 {
        self.free_bytes / (1024 * 1024)
    }
}

/// The filesystem holding `path`, or `None` where it cannot be read.
#[cfg(unix)]
pub fn fs_usage(path: &Path) -> Option<FsUsage> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let device = std::fs::metadata(path).ok()?.dev();
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs reads the NUL-terminated path and writes only into
    // `stat`, which outlives the call; all-zero bytes are a valid statvfs.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let unit = if stat.f_frsize > 0 { stat.f_frsize as u64 } else { stat.f_bsize as u64 };
    let (blocks, files) = (stat.f_blocks as u64, stat.f_files as u64);
    Some(FsUsage {
        device,
        total_bytes: blocks.saturating_mul(unit),
        free_bytes: (stat.f_bavail as u64).saturating_mul(unit),
        used_bytes: blocks.saturating_sub(stat.f_bfree as u64).saturating_mul(unit),
        total_inodes: files,
        free_inodes: stat.f_favail as u64,
        used_inodes: files.saturating_sub(stat.f_ffree as u64),
    })
}

#[cfg(not(unix))]
pub fn fs_usage(_path: &Path) -> Option<FsUsage> {
    None
}

/// The errno class a store error's text names (RocksDB reports the
/// operating system's message, not its code).
pub fn error_class(cause: &str) -> &'static str {
    let lowered = cause.to_ascii_lowercase();
    [
        ("free space fell below the floor", "FLOOR"),
        ("no space left", "ENOSPC"),
        ("storage full", "ENOSPC"),
        ("quota exceeded", "EDQUOT"),
        ("input/output error", "EIO"),
        ("read-only file system", "EROFS"),
        ("too many open files", "EMFILE"),
        ("file too large", "EFBIG"),
    ]
    .iter()
    .find(|(text, _)| lowered.contains(text))
    .map_or("other", |(_, class)| class)
}

/// Whether more free space or inodes on the store's filesystem resolves
/// a failure of `class` (FLOOR: the storage watch stopped the store's
/// writes when free space fell below [`FLOOR_FREE_BYTES`]).
pub fn space_class(class: &str) -> bool {
    matches!(class, "ENOSPC" | "EDQUOT" | "FLOOR")
}

/// Below this much free space, or [`FLOOR_FREE_INODES`] free inodes, a
/// write is about to fail: the storage watch stops the stores on that
/// filesystem first, so they are reopened like a store whose write failed.
/// Percentages only report (see [`DiskThresholds`]): a high percentage of
/// a large disk leaves ample room.
pub const FLOOR_FREE_BYTES: u64 = 2 << 30;
pub const FLOOR_FREE_INODES: u64 = 10_000;

/// Whether `usage` is below the floor where the stores stop writing.
pub fn below_floor(usage: &FsUsage) -> bool {
    usage.free_bytes < FLOOR_FREE_BYTES || (usage.total_inodes > 0 && usage.free_inodes < FLOOR_FREE_INODES)
}

/// Whether `usage` leaves room to reopen a stopped store: twice the floor.
pub fn has_headroom(usage: &FsUsage) -> bool {
    usage.free_bytes >= 2 * FLOOR_FREE_BYTES && (usage.total_inodes == 0 || usage.free_inodes >= 2 * FLOOR_FREE_INODES)
}

/// The headroom [`has_headroom`] requires, for log lines.
pub fn headroom_text() -> String {
    format!("{} MiB and {} inodes free", 2 * FLOOR_FREE_BYTES >> 20, 2 * FLOOR_FREE_INODES)
}

/// What a process reserves next to its stopped store before it exits to
/// reopen it, after a space error on a filesystem that showed room: about
/// what reopening writes (a recovery flush, a new log and manifest).
pub const REOPEN_RESERVE_BYTES: u64 = 256 << 20;

/// Whether `bytes` can be reserved in `dir` now: a new file there is
/// given that much space and removed at once, so a disk quota or a
/// filesystem's metadata limit that its free counts do not show counts.
/// `None` where the filesystem cannot reserve space without writing it.
#[cfg(target_os = "linux")]
pub fn can_reserve(dir: &Path, bytes: u64) -> Option<bool> {
    use std::os::unix::io::AsRawFd;
    // Removed when dropped, also when the reservation fails.
    let Ok(file) = tempfile::Builder::new().prefix(".reserve-").tempfile_in(dir) else {
        return Some(false);
    };
    let length = libc::off_t::try_from(bytes).ok()?;
    // SAFETY: fallocate reads only its integer arguments, and the file's
    // descriptor stays open for the call.
    if unsafe { libc::fallocate(file.as_file().as_raw_fd(), 0, 0, length) } == 0 {
        return Some(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EOPNOTSUPP | libc::ENOSYS) => None,
        _ => Some(false),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn can_reserve(_dir: &Path, _bytes: u64) -> Option<bool> {
    None
}

/// `cause` without file paths: RocksDB names the file it was writing.
pub fn redact_paths(cause: &str) -> String {
    let word = |word: &str| -> String {
        if word.contains('/') && !word.eq_ignore_ascii_case("input/output") {
            "<path>".to_string()
        } else {
            word.to_string()
        }
    };
    cause
        .split(": ")
        .map(|part| part.split(' ').map(word).collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join(": ")
}

/// How often the operator is reminded while a store keeps refusing writes.
pub const FAILED_WRITE_REPEAT: Duration = Duration::from_secs(600);

/// What the first failed write was, and how many writes it has stopped since.
/// RocksDB keeps refusing writes after an I/O error until the database is
/// reopened, and callers only see one per-call error, so the store names
/// the cause and the operator action once; the storage watch repeats it at a
/// bounded interval, one line per filesystem ([`check_stores`]).
struct WriteFailure {
    cause: String,
    /// Whether the store's filesystem showed less than the reopening
    /// headroom when its writes stopped ([`has_headroom`]). A space error on
    /// a filesystem that shows room (a disk quota, filesystem metadata) is
    /// not resolved by the free space the node can see alone.
    no_room: bool,
    since: Instant,
    refused: u64,
    last_logged: Instant,
}

impl WriteFailure {
    /// Whether the reminder is due at `now`; marks it logged when it is.
    fn due(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.last_logged) < FAILED_WRITE_REPEAT {
            return false;
        }
        self.last_logged = now;
        true
    }
}

/// A store's identity and failed-write latch, shared by its database and
/// this process's registry of stores.
pub(crate) struct StoreState {
    /// Only probed for its filesystem's usage, never logged.
    path: PathBuf,
    role: OnceLock<StoreRole>,
    failed: AtomicBool,
    failure: Mutex<Option<WriteFailure>>,
    /// The error the next write fails with, for tests of the write path.
    #[cfg(test)]
    fault: Mutex<Option<rocksdb::Error>>,
}

impl StoreState {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            role: OnceLock::new(),
            failed: AtomicBool::new(false),
            failure: Mutex::new(None),
            #[cfg(test)]
            fault: Mutex::new(None),
        }
    }

    pub(crate) fn role(&self) -> Option<StoreRole> {
        self.role.get().copied()
    }

    pub(crate) fn is_latched(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    /// Refuse every later write, and report the first cause once.
    pub(crate) fn latch(&self, cause: String) {
        self.failed.store(true, Ordering::Release);
        let now = Instant::now();
        let mut failure = self.failure.lock().unwrap_or_else(PoisonError::into_inner);
        if failure.is_some() {
            return;
        }
        let usage = fs_usage(&self.path);
        let no_room = usage.is_some_and(|usage| !has_headroom(&usage));
        report_failed_write(self.role(), &cause, no_room, usage);
        *failure = Some(WriteFailure { cause, no_room, since: now, refused: 0, last_logged: now });
    }

    /// [`Self::latch`] without its line, for a caller that reports a group
    /// of stores at once, when free space fell below the floor; whether the
    /// store was not latched before.
    pub(crate) fn latch_quietly(&self, cause: String) -> bool {
        let now = Instant::now();
        let mut failure = self.failure.lock().unwrap_or_else(PoisonError::into_inner);
        self.failed.store(true, Ordering::Release);
        if failure.is_some() {
            return false;
        }
        *failure = Some(WriteFailure { cause, no_room: true, since: now, refused: 0, last_logged: now });
        true
    }

    /// Count one refused write.
    pub(crate) fn refuse(&self) {
        if let Some(failure) = self.failure.lock().unwrap_or_else(PoisonError::into_inner).as_mut() {
            failure.refused += 1;
        }
    }

    /// The error class, whether the filesystem showed no room, seconds since
    /// the failure and refused writes of a latched store whose reminder is
    /// due at `now`.
    fn reminder(&self, now: Instant) -> Option<(&'static str, bool, u64, u64)> {
        let mut failure = self.failure.lock().unwrap_or_else(PoisonError::into_inner);
        let failure = failure.as_mut().filter(|_| self.is_latched())?;
        failure.due(now).then(|| {
            let failed_secs = now.saturating_duration_since(failure.since).as_secs();
            (error_class(&failure.cause), failure.no_room, failed_secs, failure.refused)
        })
    }

    #[cfg(test)]
    pub(crate) fn arm_fault(&self, error: rocksdb::Error) {
        *self.fault.lock().unwrap() = Some(error);
    }

    /// The armed fault of a test; never one outside tests.
    #[cfg(test)]
    pub(crate) fn take_fault(&self) -> Option<rocksdb::Error> {
        self.fault.lock().unwrap().take()
    }

    #[cfg(not(test))]
    pub(crate) fn take_fault(&self) -> Option<rocksdb::Error> {
        None
    }
}

fn store_name(role: Option<StoreRole>) -> String {
    role.map_or_else(|| "unregistered".to_string(), |role| role.to_string())
}

/// What the operator does about stores whose writes stopped for `class`,
/// and what the node does next: it restarts a thread worker to reopen the
/// worker's store, and a process whose own store it is (the master, or a
/// separate worker process) exits to be restarted. `no_room`: the store's
/// filesystem showed no room when its writes stopped.
fn action(class: &str, no_room: bool, role: Option<StoreRole>) -> String {
    let operator = match class {
        "FLOOR" => "free space or inodes on its disk fell below the floor: free space there",
        class if space_class(class) && no_room => "its disk is full: free space and inodes there",
        class if space_class(class) => {
            "it ran out of space although its filesystem shows room: check the disk quota and the filesystem's \
             metadata space"
        }
        _ => "check the disk and the store files",
    };
    format!("{operator}; {}", next_step(class, no_room, role))
}

/// Whether more free space the node can see resolves a store's failure:
/// a space class on a filesystem that showed no room when writes stopped.
pub fn recovers_with_space(class: &str, no_room: bool) -> bool {
    space_class(class) && no_room
}

/// What the node does next about a store of `role` stopped for `class`. A
/// thread worker is restarted, at most a few times in a row. A process
/// whose own store it is exits only for a space error, once that space
/// returns: when its filesystem showed room, only once space can also be
/// reserved next to the store ([`can_reserve`]), since a disk quota or a
/// metadata limit would fail the restarted process again at once. Other
/// errors leave it to the operator, who restarts the node.
fn next_step(class: &str, no_room: bool, role: Option<StoreRole>) -> String {
    let headroom = headroom_text();
    match role {
        Some(StoreRole::Worker(_)) if master_in_process() => format!(
            "the node stops the worker, keeping its allocation, and restarts it to reopen the store once the disk \
             has {headroom}, at most three times in a row"
        ),
        Some(_) if !space_class(class) => "then restart the node".to_string(),
        Some(_) if !recovers_with_space(class, no_room) => format!(
            "this process exits once the disk has {headroom} and {} MiB can be reserved next to the store, for its \
             service manager to restart it and reopen the store (the service needs a restart policy: systemd \
             Restart=on-failure, launchd KeepAlive)",
            REOPEN_RESERVE_BYTES >> 20
        ),
        Some(_) => format!(
            "this process exits once the disk has {headroom}, for its service manager to restart it and reopen \
             the store (the service needs a restart policy: systemd Restart=on-failure, launchd KeepAlive)"
        ),
        None => "then restart the node".to_string(),
    }
}

fn master_in_process() -> bool {
    open_stores().iter().any(|store| store.role() == Some(StoreRole::Master))
}

fn report_failed_write(role: Option<StoreRole>, cause: &str, no_room: bool, usage: Option<FsUsage>) {
    let store = store_name(role);
    let class = error_class(cause);
    tracing::error!(
        scope = "this node",
        store,
        error_class = class,
        free_mb = usage.map(|usage| usage.free_mb()),
        free_inodes = usage.map(|usage| usage.free_inodes),
        used_pct = usage.map(|usage| usage.used_percent()),
        first_error = %redact_paths(cause),
        "store write failed: this node's {store} store refuses further writes until it is reopened; {}",
        action(class, no_room, role),
    );
}

/// The reminder of the latched stores on one filesystem: the longest time
/// since a store's write failed and the writes refused since, in all.
fn report_still_refused(
    roles: &[StoreRole],
    class: &str,
    no_room: bool,
    failed_secs: u64,
    refused: u64,
    usage: Option<FsUsage>,
) {
    let stores = describe_stores(roles);
    tracing::error!(
        scope = "this node",
        stores = %stores,
        error_class = class,
        failed_secs,
        refused,
        free_mb = usage.map(|usage| usage.free_mb()),
        free_inodes = usage.map(|usage| usage.free_inodes),
        used_pct = usage.map(|usage| usage.used_percent()),
        "stores still refuse writes: this node's {stores} store(s) have refused {refused} writes since their \
         writes stopped {failed_secs}s ago; {}",
        action(class, no_room, roles.first().copied()),
    );
}

struct Registered {
    state: Arc<StoreState>,
    database: Weak<DatabaseInner>,
}

static STORES: Mutex<Vec<Registered>> = Mutex::new(Vec::new());

/// Name a database as one of this node's stores. A database is registered
/// once; a later call keeps its first role.
pub(crate) fn register(state: &Arc<StoreState>, database: Weak<DatabaseInner>, role: StoreRole) -> bool {
    if state.role.set(role).is_err() {
        return false;
    }
    let mut stores = STORES.lock().unwrap_or_else(PoisonError::into_inner);
    stores.retain(|store| store.database.strong_count() > 0);
    stores.push(Registered { state: state.clone(), database });
    true
}

/// This process's registered stores that are still open.
fn open_stores() -> Vec<Arc<StoreState>> {
    open_databases().into_iter().map(|(state, _)| state).collect()
}

fn open_databases() -> Vec<(Arc<StoreState>, Weak<DatabaseInner>)> {
    let mut stores = STORES.lock().unwrap_or_else(PoisonError::into_inner);
    stores.retain(|store| store.database.strong_count() > 0);
    stores.iter().map(|store| (store.state.clone(), store.database.clone())).collect()
}

/// The error class of the open store of `role` that stopped writing, and
/// whether its filesystem showed no room then; `None` until both are known.
pub fn store_failure(role: StoreRole) -> Option<(&'static str, bool)> {
    open_stores().into_iter().find(|store| store.role() == Some(role) && store.is_latched()).and_then(|store| {
        let failure = store.failure.lock().unwrap_or_else(PoisonError::into_inner);
        failure.as_ref().map(|failure| (error_class(&failure.cause), failure.no_room))
    })
}

/// Whether this process has an open store of `role`.
pub fn store_open(role: StoreRole) -> bool {
    open_stores().iter().any(|store| store.role() == Some(role))
}

/// The directory of this process's open store of `role`, to watch its
/// filesystem once the store has closed; never logged.
pub fn store_path(role: StoreRole) -> Option<PathBuf> {
    open_stores().iter().find(|store| store.role() == Some(role)).map(|store| store.path.clone())
}

static HELD: Mutex<BTreeSet<StoreRole>> = Mutex::new(BTreeSet::new());

/// Mark the store of `role` as stopped for its recovery, until
/// [`release_store`]: its worker reads as stopped by it.
pub fn hold_store(role: StoreRole) {
    HELD.lock().unwrap_or_else(PoisonError::into_inner).insert(role);
}

pub fn release_store(role: StoreRole) {
    HELD.lock().unwrap_or_else(PoisonError::into_inner).remove(&role);
}

/// Whether the store of `role` is held stopped for its recovery.
pub fn store_held(role: StoreRole) -> bool {
    HELD.lock().unwrap_or_else(PoisonError::into_inner).contains(&role)
}

/// Whether this process's open store of `role` refuses writes after a
/// failed write.
pub fn store_latched(role: StoreRole) -> bool {
    open_stores().iter().any(|store| store.role() == Some(role) && store.is_latched())
}

/// The roles of this process's open stores that refuse writes.
pub fn latched_stores() -> Vec<StoreRole> {
    open_stores().iter().filter(|store| store.is_latched()).filter_map(|store| store.role()).collect()
}

/// How full a store's filesystem may get before the operator hears of it
/// (`db.noticePercentage`, `db.warnPercentage`, `db.terminatePercentage`).
/// They only report: writes stop at an absolute floor ([`below_floor`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskThresholds {
    pub notice: u8,
    pub warn: u8,
    pub terminate: u8,
}

impl Default for DiskThresholds {
    fn default() -> Self {
        Self { notice: 70, warn: 90, terminate: 95 }
    }
}

/// How full a store's filesystem is against [`DiskThresholds`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiskLevel {
    Normal,
    Notice,
    Warn,
    Terminate,
}

impl DiskLevel {
    pub fn name(self) -> &'static str {
        match self {
            DiskLevel::Normal => "normal",
            DiskLevel::Notice => "notice",
            DiskLevel::Warn => "warn",
            DiskLevel::Terminate => "terminate",
        }
    }
}

impl DiskThresholds {
    /// Percentages from 1 to 100 with notice <= warn < terminate.
    pub fn new(notice: i32, warn: i32, terminate: i32) -> Result<Self, String> {
        let percent = |value: i32| u8::try_from(value).ok().filter(|value| (1..=100).contains(value));
        match (percent(notice), percent(warn), percent(terminate)) {
            (Some(notice), Some(warn), Some(terminate)) if notice <= warn && warn < terminate => {
                Ok(Self { notice, warn, terminate })
            }
            _ => Err(format!(
                "disk usage thresholds must be percentages from 1 to 100 with notice <= warn < terminate \
                 (got {notice}, {warn}, {terminate})"
            )),
        }
    }

    /// The percentage at which `level` begins.
    pub fn threshold(&self, level: DiskLevel) -> u8 {
        match level {
            DiskLevel::Normal => 0,
            DiskLevel::Notice => self.notice,
            DiskLevel::Warn => self.warn,
            DiskLevel::Terminate => self.terminate,
        }
    }

    /// The level at `used` percent, coming from `previous`: a level is kept
    /// until usage falls a full point below it, so it does not flap.
    pub fn level(&self, used: u8, previous: DiskLevel) -> DiskLevel {
        let reached = [DiskLevel::Terminate, DiskLevel::Warn, DiskLevel::Notice]
            .into_iter()
            .find(|level| used >= self.threshold(*level))
            .unwrap_or(DiskLevel::Normal);
        if reached < previous && used.saturating_add(1) >= self.threshold(previous) {
            previous
        } else {
            reached
        }
    }
}

/// How a filesystem's level changed in one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskChange {
    Raised,
    /// The reminder of a warn or terminate level that holds.
    Holding,
    Lowered,
}

/// One headroom report: a filesystem holding some of this node's stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskReport {
    pub change: DiskChange,
    pub level: DiskLevel,
    /// The level before the change (the same while it holds).
    pub from: DiskLevel,
    pub stores: Vec<StoreRole>,
    pub usage: FsUsage,
    /// How long the filesystem has been at `from`.
    pub held_secs: u64,
}

/// How often a warn or terminate level is repeated while it holds.
pub const DISK_REPEAT: Duration = Duration::from_secs(600);

struct Watched {
    level: DiskLevel,
    since: Instant,
    last_logged: Instant,
}

/// The level of each filesystem holding this node's stores, for reports
/// of its transitions and bounded reminders.
pub struct StorageWatch {
    thresholds: DiskThresholds,
    filesystems: BTreeMap<u64, Watched>,
}

impl StorageWatch {
    pub fn new(thresholds: DiskThresholds) -> Self {
        Self { thresholds, filesystems: BTreeMap::new() }
    }

    pub fn thresholds(&self) -> DiskThresholds {
        self.thresholds
    }

    /// One check of the filesystems of `stores`: their level changes, and
    /// reminders of a warn or terminate level due at `now`.
    pub fn observe(&mut self, stores: &[(StoreRole, FsUsage)], now: Instant) -> Vec<DiskReport> {
        // A filesystem left out of this check (its statvfs failed) keeps its
        // level, so its next reading is no new transition.
        let mut filesystems: BTreeMap<u64, (Vec<StoreRole>, FsUsage)> = BTreeMap::new();
        for (role, usage) in stores {
            let entry = filesystems.entry(usage.device).or_insert_with(|| (Vec::new(), *usage));
            entry.0.push(*role);
            entry.1 = *usage;
        }
        let mut reports = Vec::new();
        for (device, (mut roles, usage)) in filesystems {
            roles.sort();
            let watched = self
                .filesystems
                .entry(device)
                .or_insert(Watched { level: DiskLevel::Normal, since: now, last_logged: now });
            let from = watched.level;
            let level = self.thresholds.level(usage.used_percent(), from);
            let held_secs = now.saturating_duration_since(watched.since).as_secs();
            let change = if level > from {
                DiskChange::Raised
            } else if level < from {
                DiskChange::Lowered
            } else if level >= DiskLevel::Warn && now.saturating_duration_since(watched.last_logged) >= DISK_REPEAT {
                DiskChange::Holding
            } else {
                continue;
            };
            if change != DiskChange::Holding {
                watched.level = level;
                watched.since = now;
            }
            watched.last_logged = now;
            reports.push(DiskReport { change, level, from, stores: roles, usage, held_secs });
        }
        reports
    }
}

/// Log `report` at its level's severity.
pub fn log_disk_report(report: &DiskReport, thresholds: &DiskThresholds) {
    let stores = describe_stores(&report.stores);
    let used = report.usage.used_percent();
    let threshold = thresholds.threshold(if report.change == DiskChange::Lowered { report.from } else { report.level });
    let (floor_mb, floor_inodes) = (FLOOR_FREE_BYTES >> 20, FLOOR_FREE_INODES);
    macro_rules! disk_line {
        ($level:ident, $($message:tt)+) => {
            tracing::$level!(
                scope = "this node",
                stores = %stores,
                level = report.level.name(),
                used_pct = used,
                bytes_used_pct = report.usage.bytes_used_percent(),
                inodes_used_pct = report.usage.inodes_used_percent(),
                free_mb = report.usage.free_mb(),
                free_inodes = report.usage.free_inodes,
                threshold_pct = threshold,
                held_secs = report.held_secs,
                $($message)+
            )
        };
    }
    match (report.change, report.level) {
        (DiskChange::Lowered, _) => disk_line!(info,
            "store disk usage back below the {} level: {used}% of the filesystem holding this node's {stores} \
             store(s) is used ({} at {threshold}%)", report.from.name(), report.from.name()),
        (_, DiskLevel::Notice) => disk_line!(info,
            "store disk usage passed the notice level: {used}% of the filesystem holding this node's {stores} \
             store(s) is used (notice at {threshold}%); plan more space before it fills"),
        (_, DiskLevel::Warn) => disk_line!(warn,
            "store disk nearly full: {used}% of the filesystem holding this node's {stores} store(s) is used \
             (warn at {threshold}%); free space there: below {floor_mb} MiB or {floor_inodes} inodes free the \
             stores stop writing until the disk has room again; repeats every 10 minutes while it holds"),
        (_, DiskLevel::Terminate) => disk_line!(error,
            "store disk usage at the terminate level: {used}% of the filesystem holding this node's {stores} \
             store(s) is used (terminate at {threshold}%); free space there: the stores stop writing only below \
             {floor_mb} MiB or {floor_inodes} inodes free, until the disk has room again; repeats every 10 minutes \
             while it holds"),
        (_, DiskLevel::Normal) => {}
    }
}

/// One pass over this process's registered stores: the headroom reports of
/// their filesystems, and the reminders of latched stores, one line per
/// filesystem. Stores on a filesystem below the floor ([`below_floor`])
/// stop writing, as after a failed write, so they are recovered like one
/// instead of running into ENOSPC. `probe` reads a store's filesystem
/// ([`fs_usage`] outside tests).
pub fn check_stores(watch: &mut StorageWatch, now: Instant, probe: &dyn Fn(&Path) -> Option<FsUsage>) -> Vec<DiskReport> {
    let mut usages = Vec::new();
    // Due reminders by filesystem (None: unreadable), class and whether the
    // store is the master's (its next step differs): roles, longest failure,
    // refused writes and the filesystem's usage.
    let mut due: BTreeMap<(Option<u64>, &'static str, bool, bool), (Vec<StoreRole>, u64, u64, Option<FsUsage>)> =
        BTreeMap::new();
    // Stores to stop at the floor, by filesystem.
    let mut floor: BTreeMap<u64, (Vec<(StoreRole, Weak<DatabaseInner>)>, FsUsage)> = BTreeMap::new();
    for (store, database) in open_databases() {
        let Some(role) = store.role() else { continue };
        let usage = probe(&store.path);
        if let Some(usage) = usage.filter(|usage| below_floor(usage) && !store.is_latched()) {
            floor.entry(usage.device).or_insert_with(|| (Vec::new(), usage)).0.push((role, database));
        }
        if let Some((class, no_room, failed_secs, refused)) = store.reminder(now) {
            let key = (usage.map(|usage| usage.device), class, no_room, role == StoreRole::Master);
            let entry = due.entry(key).or_insert((Vec::new(), 0, 0, usage));
            entry.0.push(role);
            entry.1 = entry.1.max(failed_secs);
            entry.2 += refused;
        }
        if let Some(usage) = usage {
            usages.push((role, usage));
        }
    }
    for ((_, class, no_room, _), (roles, failed_secs, refused, usage)) in due {
        report_still_refused(&roles, class, no_room, failed_secs, refused, usage);
    }
    let reports = watch.observe(&usages, now);
    for report in &reports {
        log_disk_report(report, &watch.thresholds());
    }
    for (stopping, usage) in floor.into_values() {
        let cause = format!(
            "free space fell below the floor: {} MiB and {} inodes free (floor {} MiB or {} inodes)",
            usage.free_mb(),
            usage.free_inodes,
            FLOOR_FREE_BYTES >> 20,
            FLOOR_FREE_INODES
        );
        let roles: Vec<StoreRole> = stopping
            .iter()
            .filter(|(_, database)| crate::database::stop_writes(database, cause.clone()))
            .map(|(role, _)| *role)
            .collect();
        if roles.is_empty() {
            continue;
        }
        let stores = describe_stores(&roles);
        let next =
            next_step("FLOOR", true, roles.iter().find(|role| **role == StoreRole::Master).or(roles.first()).copied());
        tracing::error!(
            scope = "this node",
            stores = %stores,
            error_class = "FLOOR",
            free_mb = usage.free_mb(),
            free_inodes = usage.free_inodes,
            used_pct = usage.used_percent(),
            "store writes stopped: free space on the filesystem holding this node's {stores} store(s) fell below \
             the floor ({} MiB or {} inodes free), so they stop writing before a write fails; free space there; \
             {next}",
            FLOOR_FREE_BYTES >> 20,
            FLOOR_FREE_INODES,
        );
    }
    reports
}

/// How often the storage watch checks this process's stores.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(60);

/// Start this process's storage watch: [`check_stores`] at start and every
/// [`WATCH_INTERVAL`] on its own thread. Only the first call starts one.
pub fn spawn_storage_watch(thresholds: DiskThresholds) -> bool {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return false;
    }
    std::thread::Builder::new()
        .name("storage-watch".into())
        .spawn(move || {
            let mut watch = StorageWatch::new(thresholds);
            loop {
                check_stores(&mut watch, Instant::now(), &fs_usage);
                std::thread::sleep(WATCH_INTERVAL);
            }
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoordinatedDb, DatabaseCommitError};

    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn logged(run: impl FnOnce()) -> String {
        let lines = Lines::default();
        let writer = lines.clone();
        let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
        tracing::subscriber::with_default(subscriber, run);
        let bytes = lines.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    fn open(dir: &Path) -> CoordinatedDb {
        CoordinatedDb::new(rocksdb::DB::open_default(dir).unwrap())
    }

    /// A real RocksDB error whose text carries `name`: opening a missing
    /// database under a directory of that name fails, naming the path.
    fn rocksdb_error(dir: &Path, name: &str) -> rocksdb::Error {
        let missing = dir.join(name);
        rocksdb::DB::open_for_read_only(&rocksdb::Options::default(), &missing, false).err().expect("no database")
    }

    /// A store's first failed write is reported once, naming the store, the
    /// errno class and its filesystem's free space without the store's path;
    /// later writes are refused without a line each.
    #[test]
    fn a_failed_write_names_its_store_class_and_free_space_once_without_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(dir.path());
        assert!(db.register_store(StoreRole::Worker(7_001)));
        assert!(!db.register_store(StoreRole::Master), "a store keeps its first role");
        db.fail_next_write(rocksdb_error(dir.path(), "No space left on device"));
        let lines = logged(|| {
            assert!(matches!(db.put([1], b"v"), Err(DatabaseCommitError::Storage(_))), "the write's own error");
            assert!(matches!(db.put([2], b"v"), Err(DatabaseCommitError::PriorWriteFailed)));
            assert!(db.lock_writes().is_err());
        });
        assert_eq!(lines.matches("store write failed").count(), 1, "{lines}");
        assert!(!lines.contains("still refuses"), "{lines}");
        assert!(lines.contains("worker 7001 store refuses further writes"), "{lines}");
        // The action depends on whether the test's filesystem shows room.
        assert!(lines.contains("ENOSPC") && (lines.contains("its disk is full") || lines.contains("shows room")),
            "{lines}");
        for field in ["free_mb=", "free_inodes=", "used_pct=", "first_error=IO error: "] {
            assert!(lines.contains(field), "{field}: {lines}");
        }
        assert!(lines.contains("<path>"), "{lines}");
        assert!(!lines.contains(&dir.path().display().to_string()), "the path leaked: {lines}");
        assert!(db.write_failed());
        assert!(store_latched(StoreRole::Worker(7_001)));
        assert!(latched_stores().contains(&StoreRole::Worker(7_001)));
        assert!(!store_latched(StoreRole::Worker(7_002)));
        drop(db);
        assert!(!store_latched(StoreRole::Worker(7_001)), "a closed store is not reported");
    }

    /// While stores refuse writes, the watch repeats their report once per
    /// interval and filesystem, with how long and how many writes, whether
    /// or not writes keep arriving.
    #[test]
    fn a_latched_store_is_repeated_at_a_bounded_interval() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(&dir.path().join("a"));
        let other = open(&dir.path().join("b"));
        db.register_store(StoreRole::Worker(7_011));
        other.register_store(StoreRole::Worker(7_012));
        db.fail_next_write(rocksdb_error(dir.path(), "Input/output error"));
        other.fail_next_write(rocksdb_error(dir.path(), "Input/output error"));
        let first = logged(|| {
            assert!(db.put([1], b"v").is_err());
            assert!(other.put([1], b"v").is_err());
            for key in 0..50u8 {
                assert!(db.put([key], b"v").is_err());
            }
        });
        assert_eq!(first.matches("store write failed").count(), 2, "one line per store's failure: {first}");
        assert!(!first.contains("still refuse"), "refused writes log nothing: {first}");
        assert!(first.contains("EIO") && first.contains("check the disk"), "{first}");
        let start = Instant::now();
        let mut watch = StorageWatch::new(DiskThresholds::default());
        let probe = |_: &Path| -> Option<FsUsage> { Some(usage(7_010, 50, 1)) };
        let early = logged(|| {
            check_stores(&mut watch, start + FAILED_WRITE_REPEAT / 2, &probe);
        });
        assert!(!early.contains("worker 7011"), "{early}");
        let due = logged(|| {
            check_stores(&mut watch, start + FAILED_WRITE_REPEAT + Duration::from_secs(5), &probe);
            check_stores(&mut watch, start + FAILED_WRITE_REPEAT + Duration::from_secs(65), &probe);
        });
        assert_eq!(due.matches("still refuse writes").count(), 1, "one line per filesystem: {due}");
        assert!(due.contains("workers 7011-7012 store(s) have refused 50 writes"), "{due}");
        assert!(due.contains("failed_secs=") && due.contains("free_mb=51200"), "{due}");
    }

    fn usage(device: u64, used: u64, inodes_used: u64) -> FsUsage {
        FsUsage {
            device,
            total_bytes: 100 << 30,
            used_bytes: used << 30,
            free_bytes: (100 - used) << 30,
            total_inodes: 1_000,
            used_inodes: inodes_used * 10,
            free_inodes: 1_000 - inodes_used * 10,
        }
    }

    /// Each filesystem holding stores is reported as it reaches a level
    /// (by space or inodes), reminded every interval at warn or terminate,
    /// and reported again when it falls a point below its level.
    #[test]
    fn disk_levels_are_reported_on_transitions_with_bounded_reminders() {
        let mut watch = StorageWatch::new(DiskThresholds::default());
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let stores = |usage: FsUsage| {
            [StoreRole::Worker(4), StoreRole::Master, StoreRole::Worker(2), StoreRole::Worker(1)].map(|role| (role, usage))
        };
        let changes = |reports: Vec<DiskReport>| -> Vec<(DiskChange, DiskLevel, DiskLevel, u64)> {
            reports.iter().map(|r| (r.change, r.from, r.level, r.held_secs)).collect()
        };
        assert!(watch.observe(&stores(usage(1, 50, 1)), at(0)).is_empty());
        let notice = watch.observe(&stores(usage(1, 70, 1)), at(60));
        assert_eq!(describe_stores(&notice[0].stores), "master, workers 1-2, worker 4");
        assert_eq!(changes(notice), [(DiskChange::Raised, DiskLevel::Normal, DiskLevel::Notice, 60)]);
        assert!(watch.observe(&stores(usage(1, 80, 1)), at(60 + 3_600)).is_empty(), "notice is not repeated");
        assert_eq!(changes(watch.observe(&stores(usage(1, 91, 1)), at(4_000))),
            [(DiskChange::Raised, DiskLevel::Notice, DiskLevel::Warn, 4_000 - 60)]);
        assert!(watch.observe(&stores(usage(1, 91, 1)), at(4_300)).is_empty());
        assert_eq!(changes(watch.observe(&stores(usage(1, 92, 1)), at(4_600))),
            [(DiskChange::Holding, DiskLevel::Warn, DiskLevel::Warn, 600)]);
        assert_eq!(changes(watch.observe(&stores(usage(1, 96, 1)), at(4_700))),
            [(DiskChange::Raised, DiskLevel::Warn, DiskLevel::Terminate, 700)]);
        assert!(watch.observe(&stores(usage(1, 94, 1)), at(4_760)).is_empty(), "a point of hysteresis");
        assert!(watch.observe(&[], at(4_770)).is_empty(), "an unreadable filesystem changes nothing");
        assert!(watch.observe(&stores(usage(1, 96, 1)), at(4_780)).is_empty(), "and keeps its level");
        assert_eq!(changes(watch.observe(&stores(usage(1, 80, 1)), at(4_800))),
            [(DiskChange::Lowered, DiskLevel::Terminate, DiskLevel::Notice, 100)]);
        // Inodes count as much as space; another filesystem is its own report.
        let mixed = [(StoreRole::Master, usage(1, 80, 1)), (StoreRole::Worker(9), usage(2, 10, 92))];
        let reports = watch.observe(&mixed, at(4_900));
        assert_eq!(reports.len(), 1);
        assert_eq!((reports[0].stores.as_slice(), reports[0].level), ([StoreRole::Worker(9)].as_slice(), DiskLevel::Warn));
        assert_eq!(reports[0].usage.inodes_used_percent(), Some(92));
        let lines = logged(|| log_disk_report(&reports[0], &watch.thresholds()));
        assert!(lines.contains("WARN") && lines.contains("store disk nearly full: 92%"), "{lines}");
        assert!(lines.contains("worker 9 store(s)") && lines.contains("inodes_used_pct=92"), "{lines}");
    }

    fn free(device: u64, free_gib: u64) -> FsUsage {
        FsUsage {
            device,
            total_bytes: 1_000 << 30,
            used_bytes: (1_000 - free_gib) << 30,
            free_bytes: free_gib << 30,
            total_inodes: 1_000_000,
            used_inodes: 1_000,
            free_inodes: 999_000,
        }
    }

    /// Stores on a filesystem below the free-space floor stop writing as
    /// after a failed write, reported in one line; a filesystem at 99% with
    /// ample space left keeps writing however full it is in percent.
    #[test]
    fn stores_stop_writing_below_the_floor_and_not_at_a_percentage() {
        let (roomy, full) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let roomy_db = open(roomy.path());
        let (full_a, full_b) = (open(&full.path().join("a")), open(&full.path().join("b")));
        roomy_db.register_store(StoreRole::Worker(7_021));
        full_a.register_store(StoreRole::Worker(7_022));
        full_b.register_store(StoreRole::Worker(7_023));
        let (roomy_path, full_path) = (roomy.path().to_path_buf(), full.path().to_path_buf());
        let probe = move |path: &Path| -> Option<FsUsage> {
            (path == roomy_path.as_path()).then(|| free(70_021, 10))
                .or_else(|| path.starts_with(&full_path).then(|| free(70_022, 1)))
        };
        let mut watch = StorageWatch::new(DiskThresholds::default());
        let lines = logged(|| {
            check_stores(&mut watch, Instant::now(), &probe);
            check_stores(&mut watch, Instant::now(), &probe);
        });
        assert!(!roomy_db.write_failed() && roomy_db.put([1], b"v").is_ok(), "99% used, 10 GiB free: {lines}");
        assert!(full_a.write_failed() && full_b.write_failed(), "{lines}");
        assert!(matches!(full_a.put([1], b"v"), Err(DatabaseCommitError::PriorWriteFailed)));
        assert_eq!(lines.matches("store writes stopped").count(), 1, "one line per filesystem: {lines}");
        assert!(lines.contains("workers 7022-7023 store(s) fell below the floor (2048 MiB or 10000 inodes free)"),
            "{lines}");
        assert!(lines.contains("this process exits once the disk has 4096 MiB and 20000 inodes free"), "{lines}");
        assert!(!lines.contains("store write failed"), "no write failed: {lines}");
        assert!(lines.contains("store disk usage at the terminate level: 99%"), "the percentage only reports: {lines}");
        assert!(store_open(StoreRole::Worker(7_022)) && store_path(StoreRole::Worker(7_022)).is_some());
        drop(full_a);
        assert!(!store_open(StoreRole::Worker(7_022)) && store_path(StoreRole::Worker(7_022)).is_none());
    }

    #[test]
    fn the_floor_and_the_headroom_are_absolute() {
        assert!(below_floor(&free(1, 1)) && !below_floor(&free(1, 2)));
        assert!(below_floor(&FsUsage { free_inodes: 9_999, ..free(1, 500) }), "inodes count too");
        assert!(!has_headroom(&free(1, 3)) && has_headroom(&free(1, 4)));
        assert!(!has_headroom(&FsUsage { free_inodes: 19_999, ..free(1, 500) }));
        assert!(has_headroom(&FsUsage { total_inodes: 0, free_inodes: 0, ..free(1, 5) }), "no inode count");
        assert_eq!(error_class("free space fell below the floor: 1 MiB"), "FLOOR");
        assert!(space_class("FLOOR"));
    }

    #[test]
    fn a_held_store_is_reported_until_released() {
        let role = StoreRole::Worker(7_031);
        assert!(!store_held(role));
        hold_store(role);
        assert!(store_held(role) && !store_held(StoreRole::Worker(7_032)));
        release_store(role);
        assert!(!store_held(role));
    }

    #[test]
    fn thresholds_must_be_ordered_percentages() {
        assert_eq!(DiskThresholds::new(70, 90, 95), Ok(DiskThresholds::default()));
        assert_eq!(DiskThresholds::new(80, 80, 100).map(|t| t.terminate), Ok(100));
        for (notice, warn, terminate) in [(0, 90, 95), (90, 70, 95), (70, 96, 95), (70, 95, 95), (70, 90, 101), (-1, 90, 95)] {
            assert!(DiskThresholds::new(notice, warn, terminate).is_err(), "{notice} {warn} {terminate}");
        }
    }

    #[test]
    fn errors_are_classed_and_their_paths_redacted() {
        let full = "IO error: No space left on device: While appending to file: /home/op/.config/store/000123.log: \
                    No space left on device";
        assert_eq!(error_class(full), "ENOSPC");
        assert_eq!(redact_paths(full),
            "IO error: No space left on device: While appending to file: <path>: No space left on device");
        let eio = "IO error: While open a file for appending: worker-store/3/000005.log: Input/output error";
        assert_eq!(error_class(eio), "EIO");
        assert_eq!(redact_paths(eio), "IO error: While open a file for appending: <path>: Input/output error");
        assert_eq!(error_class("IO error: Disk quota exceeded"), "EDQUOT");
        assert_eq!(error_class("IO error: Storage full"), "ENOSPC");
        assert_eq!(error_class("Corruption: bad block"), "other");
        assert!(space_class("ENOSPC") && space_class("EDQUOT") && !space_class("EIO"));
    }

    #[test]
    fn a_store_filesystem_is_read_without_privileges() {
        let dir = tempfile::tempdir().unwrap();
        let usage = fs_usage(dir.path()).expect("statvfs of a temporary directory");
        assert!(usage.total_bytes > 0 && usage.used_bytes <= usage.total_bytes, "{usage:?}");
        assert!(usage.used_percent() <= 100);
        assert!(fs_usage(&dir.path().join("missing")).is_none());
    }

    /// A reservation next to a store leaves nothing behind; one where no
    /// file can be made fails.
    #[test]
    fn a_reservation_next_to_a_store_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        assert_ne!(can_reserve(dir.path(), 1 << 20), Some(false));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "the reservation is removed");
        assert_eq!(can_reserve(&dir.path().join("missing"), 1 << 20), Some(false));
    }

    /// A space error on a filesystem that showed room is reopened by an
    /// exit once space can be reserved; other errors are left to the
    /// operator.
    #[test]
    fn a_process_store_names_what_its_exit_waits_for() {
        let master = Some(StoreRole::Master);
        assert!(next_step("ENOSPC", true, master).starts_with("this process exits once the disk has 4096 MiB"));
        let reserve = next_step("EDQUOT", false, master);
        assert!(reserve.contains("and 256 MiB can be reserved next to the store"), "{reserve}");
        assert_eq!(next_step("EIO", true, master), "then restart the node");
    }
}
