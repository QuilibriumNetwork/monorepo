//! What this node's stores tell its operator about their disks: a write
//! that failed and latched a store ([`CoordinatedDb`](crate::CoordinatedDb)
//! refuses every later write, since the failed write's durable effect is
//! unknown), and how full each store's filesystem is against the configured
//! thresholds ([`DiskThresholds`]).
//!
//! The node registers each store it runs with its role ([`StoreRole`]).
//! Reports name the role and the filesystem's free space and inodes, never
//! the store's path; stores on one filesystem share one headroom report.

use std::collections::BTreeMap;
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
/// a failure of `class`.
pub fn space_class(class: &str) -> bool {
    matches!(class, "ENOSPC" | "EDQUOT")
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

    fn name(&self) -> String {
        self.role().map_or_else(|| "unregistered".to_string(), |role| role.to_string())
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
        report_failed_write(&self.name(), &cause, fs_usage(&self.path));
        *failure = Some(WriteFailure { cause, since: now, refused: 0, last_logged: now });
    }

    /// Count one refused write.
    pub(crate) fn refuse(&self) {
        if let Some(failure) = self.failure.lock().unwrap_or_else(PoisonError::into_inner).as_mut() {
            failure.refused += 1;
        }
    }

    /// The error class, seconds since the failure and refused writes of a
    /// latched store whose reminder is due at `now`.
    fn reminder(&self, now: Instant) -> Option<(&'static str, u64, u64)> {
        let mut failure = self.failure.lock().unwrap_or_else(PoisonError::into_inner);
        let failure = failure.as_mut().filter(|_| self.is_latched())?;
        failure.due(now).then(|| {
            (error_class(&failure.cause), now.saturating_duration_since(failure.since).as_secs(), failure.refused)
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

fn action(class: &str) -> &'static str {
    if space_class(class) {
        "its disk is full: free space and inodes there, then restart the node"
    } else {
        "check the disk and the store files, then restart the node"
    }
}

fn report_failed_write(store: &str, cause: &str, usage: Option<FsUsage>) {
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
        action(class),
    );
}

/// The reminder of the latched stores on one filesystem: the longest time
/// since a store's write failed and the writes refused since, in all.
fn report_still_refused(roles: &[StoreRole], class: &str, failed_secs: u64, refused: u64, usage: Option<FsUsage>) {
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
        "stores still refuse writes: this node's {stores} store(s) have refused {refused} writes since a write \
         failed {failed_secs}s ago; {}",
        action(class),
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
    let mut stores = STORES.lock().unwrap_or_else(PoisonError::into_inner);
    stores.retain(|store| store.database.strong_count() > 0);
    stores.iter().map(|store| store.state.clone()).collect()
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
             (warn at {threshold}%); free space there before writes fail and stop the stores until the node \
             restarts; repeats every 10 minutes while it holds"),
        (_, DiskLevel::Terminate) => disk_line!(error,
            "store disk critically full: {used}% of the filesystem holding this node's {stores} store(s) is \
             used (terminate at {threshold}%); writes will soon fail for lack of space and stop the stores until \
             the node restarts: free space there now; repeats every 10 minutes while it holds"),
        (_, DiskLevel::Normal) => {}
    }
}

/// One pass over this process's registered stores: the headroom reports of
/// their filesystems, and the reminders of latched stores, one line per
/// filesystem. `probe` reads a store's filesystem ([`fs_usage`] outside
/// tests).
pub fn check_stores(watch: &mut StorageWatch, now: Instant, probe: &dyn Fn(&Path) -> Option<FsUsage>) -> Vec<DiskReport> {
    let mut usages = Vec::new();
    // Due reminders by filesystem (None: unreadable): roles, class, longest
    // failure, refused writes and the filesystem's usage.
    let mut due: BTreeMap<Option<u64>, (Vec<StoreRole>, &'static str, u64, u64, Option<FsUsage>)> = BTreeMap::new();
    for store in open_stores() {
        let Some(role) = store.role() else { continue };
        let usage = probe(&store.path);
        if let Some((class, failed_secs, refused)) = store.reminder(now) {
            let entry = due.entry(usage.map(|usage| usage.device)).or_insert((Vec::new(), class, 0, 0, usage));
            entry.0.push(role);
            entry.2 = entry.2.max(failed_secs);
            entry.3 += refused;
        }
        if let Some(usage) = usage {
            usages.push((role, usage));
        }
    }
    for (roles, class, failed_secs, refused, usage) in due.into_values() {
        report_still_refused(&roles, class, failed_secs, refused, usage);
    }
    let reports = watch.observe(&usages, now);
    for report in &reports {
        log_disk_report(report, &watch.thresholds());
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
        assert!(lines.contains("ENOSPC") && lines.contains("its disk is full"), "{lines}");
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
}
