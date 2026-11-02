//! Whether this node's disk is fast enough for its store.
//!
//! A canary thread reads one entry of the master store every
//! [`CANARY_PERIOD`], at a random position of a table file picked by size,
//! without filling the block cache, so its reads meet the disk as the
//! store's own cold reads do. It takes no lock: neither the write barrier
//! nor any commit lock a writer holds. A summary thread closes an interval
//! every [`INTERVAL`]: the canary reads' p50, p99 and max, a read still
//! pending at its end, and, on Linux, the mean time per completed read and
//! write (await) of the device under the store, from `/proc/diskstats`.
//!
//! An interval over a slow threshold ([`IoInterval::slow_reason`]) for
//! [`START_AFTER`] intervals in a row starts a slow episode: one warning,
//! repeated every [`REPEAT`] with its duration, and one line once
//! [`END_AFTER`] intervals in a row are under every threshold. Otherwise
//! one summary line every [`SUMMARY_EVERY`]. The latest interval and the
//! verdict ([`latest`]) feed the node's health report and status RPC.
//! Lines name the store's role and the disk's kernel name, never a path.

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use quil_types::proto::diagnostics::{StoreIoHealth, StoreIoReason, StoreIoVerdict};
use tracing::{info, warn};

use crate::database::{CoordinatedDb, WeakCoordinatedDb};

/// How often the canary reads the store.
pub const CANARY_PERIOD: Duration = Duration::from_secs(1);
/// The interval the verdict and the health report cover.
pub const INTERVAL: Duration = Duration::from_secs(60);
/// How often a summary line is logged while no slow episode holds.
pub const SUMMARY_EVERY: Duration = Duration::from_secs(600);
/// How often the warning repeats while a slow episode holds.
pub const REPEAT: Duration = Duration::from_secs(600);
/// Slow intervals in a row that start an episode.
pub const START_AFTER: u32 = 2;
/// Intervals in a row under every threshold that end one.
pub const END_AFTER: u32 = 3;

// Proposed defaults. In the 2026-11-01 survey of 19 regular nodes, the
// retention pruner's longest master commit-lock hold, a unit of 64 key
// seeks, was 166-803 ms on the 10 healthy nodes (at most ~13 ms a seek),
// 1.1-10.8 s on the 7 slow ones (~17-170 ms a seek) and 247-506 s on the
// 2 severe ones (seconds a seek). A canary read is one such seek without
// the pruning work.

/// Canary reads' p99 at or over this: a slow store.
pub const SLOW_CANARY_P99: Duration = Duration::from_millis(50);
/// A canary read unfinished this long at an interval's end: the disk
/// stalls (a lower bound of that read's latency).
pub const SLOW_CANARY_PENDING: Duration = Duration::from_secs(1);
/// Disk awaits at or over these, beside a healthy SSD's ~0.1-2 ms per read
/// and ~1-20 ms per (merged, flushed) write: a saturated, failing or
/// untrimmed disk.
pub const SLOW_DISK_READ_AWAIT: Duration = Duration::from_millis(20);
pub const SLOW_DISK_WRITE_AWAIT: Duration = Duration::from_millis(100);
/// Fewer operations of a kind in an interval give no await verdict.
pub const MIN_DISK_OPS: u64 = 20;

/// Canary reads kept per interval and per summary window, at most.
const MAX_SAMPLES: usize = 4096;
/// How often the canary re-lists the store's table files.
const FILES_REFRESH: Duration = Duration::from_secs(60);
/// Deleted or superseded entries a canary seek steps over, at most: it
/// measures the disk, not a run of tombstones.
const MAX_SKIPPED_KEYS: u64 = 1000;
/// A published interval older than this is not reported.
const STALE_AFTER: Duration = Duration::from_secs(3 * 60);

/// Latency of an interval's finished canary reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadLatency {
    pub reads: u32,
    pub p50: Duration,
    pub p99: Duration,
    pub max: Duration,
}

/// Nearest-rank p50, p99 and max of `samples` (sorted in place); `None`
/// without samples.
pub fn summarise(samples: &mut [Duration]) -> Option<ReadLatency> {
    samples.sort_unstable();
    let max = *samples.last()?;
    let rank = |pct: usize| samples[(samples.len() * pct).div_ceil(100).max(1) - 1];
    Some(ReadLatency {
        reads: u32::try_from(samples.len()).unwrap_or(u32::MAX),
        p50: rank(50),
        p99: rank(99),
        max,
    })
}

/// A block device, by its kernel numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    pub major: u32,
    pub minor: u32,
}

impl Device {
    /// The numbers of a Linux `dev_t` (glibc's encoding).
    pub fn from_dev(dev: u64) -> Self {
        Device {
            major: (((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0fff)) as u32,
            minor: (((dev >> 12) & 0xffff_ff00) | (dev & 0x00ff)) as u32,
        }
    }
}

/// A device's cumulative counters in `/proc/diskstats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskCounters {
    pub reads: u64,
    pub read_ms: u64,
    pub writes: u64,
    pub write_ms: u64,
    /// Time the device had I/O in flight.
    pub io_ms: u64,
}

/// The kernel name and counters of `device` in the text of
/// `/proc/diskstats`; `None` when it is absent or its line is malformed.
pub fn parse_diskstats(text: &str, device: Device) -> Option<(String, DiskCounters)> {
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 14 {
            continue;
        }
        if fields[0].parse::<u32>().ok() != Some(device.major)
            || fields[1].parse::<u32>().ok() != Some(device.minor)
        {
            continue;
        }
        let n = |i: usize| fields[i].parse::<u64>().ok();
        let counters = DiskCounters {
            reads: n(3)?,
            read_ms: n(6)?,
            writes: n(7)?,
            write_ms: n(10)?,
            io_ms: n(12)?,
        };
        let name = fields[2];
        let name = if name.len() <= 32
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            name.to_string()
        } else {
            "unnamed".to_string()
        };
        return Some((name, counters));
    }
    None
}

/// A device's work between two counter readings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskAwait {
    pub reads: u64,
    pub writes: u64,
    /// Mean time per completed read and write, queueing included; `None`
    /// without any.
    pub read_await: Option<Duration>,
    pub write_await: Option<Duration>,
    /// Share of the time the device had I/O in flight.
    pub busy_pct: u32,
}

impl DiskAwait {
    /// `None` when a counter went back (the device was replaced or its
    /// counters reset).
    pub fn between(before: &DiskCounters, after: &DiskCounters, elapsed: Duration) -> Option<Self> {
        let reads = after.reads.checked_sub(before.reads)?;
        let writes = after.writes.checked_sub(before.writes)?;
        let read_ms = after.read_ms.checked_sub(before.read_ms)?;
        let write_ms = after.write_ms.checked_sub(before.write_ms)?;
        let io_ms = after.io_ms.checked_sub(before.io_ms)?;
        let per_op = |ms: u64, ops: u64| {
            (ops > 0).then(|| Duration::from_micros(ms.saturating_mul(1000) / ops))
        };
        let elapsed_ms = u64::try_from(elapsed.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        Some(DiskAwait {
            reads,
            writes,
            read_await: per_op(read_ms, reads),
            write_await: per_op(write_ms, writes),
            busy_pct: (io_ms.saturating_mul(100) / elapsed_ms).min(100) as u32,
        })
    }
}

/// The mount in the text of `/proc/self/mountinfo` whose mount point holds
/// `path` most closely: its device numbers and its source.
pub fn mount_of<'a>(mountinfo: &'a str, path: &Path) -> Option<(Device, &'a str)> {
    let mut best: Option<(usize, Device, &str)> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(dash) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        if dash < 6 || fields.len() < dash + 3 {
            continue;
        }
        let Some((major, minor)) = fields[2].split_once(':') else {
            continue;
        };
        let (Ok(major), Ok(minor)) = (major.parse(), minor.parse()) else {
            continue;
        };
        let point = fields[4]
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        if !path.starts_with(&point) {
            continue;
        }
        // A later mount on the same point covers an earlier one.
        if best.is_none_or(|(len, ..)| point.len() >= len) {
            best = Some((point.len(), Device { major, minor }, fields[dash + 2]));
        }
    }
    best.map(|(_, device, source)| (device, source))
}

/// The device under a store whose directory is on `st_dev`: that device
/// when `/proc/diskstats` counts it, else its mount's, else (btrfs and
/// other filesystems on an anonymous device) its mount source's.
pub fn resolve_device(
    path: &Path,
    st_dev: u64,
    diskstats: &str,
    mountinfo: &str,
    rdev_of: impl Fn(&str) -> Option<u64>,
) -> Option<Device> {
    let counted = |device: Device| parse_diskstats(diskstats, device).is_some();
    let own = Device::from_dev(st_dev);
    if counted(own) {
        return Some(own);
    }
    let (mounted, source) = mount_of(mountinfo, path)?;
    if counted(mounted) {
        return Some(mounted);
    }
    if source.starts_with("/dev/") {
        let device = Device::from_dev(rdev_of(source)?);
        if counted(device) {
            return Some(device);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn store_device(dir: &Path) -> Option<Device> {
    use std::os::unix::fs::MetadataExt;
    let dir = std::fs::canonicalize(dir).ok()?;
    let st_dev = std::fs::metadata(&dir).ok()?.dev();
    resolve_device(
        &dir,
        st_dev,
        &std::fs::read_to_string("/proc/diskstats").ok()?,
        &std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default(),
        |source| std::fs::metadata(source).ok().map(|m| m.rdev()),
    )
}

#[cfg(not(target_os = "linux"))]
fn store_device(_dir: &Path) -> Option<Device> {
    None
}

fn disk_counters(device: Option<Device>) -> Option<DiskCounters> {
    let device = device?;
    let text = std::fs::read_to_string("/proc/diskstats").ok()?;
    parse_diskstats(&text, device).map(|(_, counters)| counters)
}

/// Which slow threshold an interval crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowReason {
    CanaryP99,
    CanaryPending,
    DiskReadAwait,
    DiskWriteAwait,
}

impl SlowReason {
    pub fn label(self) -> &'static str {
        match self {
            SlowReason::CanaryP99 => "canary_p99",
            SlowReason::CanaryPending => "canary_pending",
            SlowReason::DiskReadAwait => "disk_read_await",
            SlowReason::DiskWriteAwait => "disk_write_await",
        }
    }

    fn to_proto(self) -> StoreIoReason {
        match self {
            SlowReason::CanaryP99 => StoreIoReason::CanaryP99,
            SlowReason::CanaryPending => StoreIoReason::CanaryPending,
            SlowReason::DiskReadAwait => StoreIoReason::DiskReadAwait,
            SlowReason::DiskWriteAwait => StoreIoReason::DiskWriteAwait,
        }
    }
}

/// What one interval (or summary window) measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoInterval {
    pub length: Duration,
    /// The canary reads that finished in it.
    pub canary: Option<ReadLatency>,
    /// How long a canary read unfinished at its end had run.
    pub pending: Option<Duration>,
    /// The device under the store; `None` off Linux or when unresolved.
    pub disk: Option<DiskAwait>,
}

impl IoInterval {
    /// Whether it measured anything.
    pub fn measured(&self) -> bool {
        self.canary.is_some() || self.pending.is_some() || self.disk.is_some()
    }

    /// The first slow threshold it crossed, if any.
    pub fn slow_reason(&self) -> Option<SlowReason> {
        if self.pending.is_some_and(|p| p >= SLOW_CANARY_PENDING) {
            return Some(SlowReason::CanaryPending);
        }
        if self.canary.is_some_and(|c| c.p99 >= SLOW_CANARY_P99) {
            return Some(SlowReason::CanaryP99);
        }
        let disk = self.disk?;
        if disk.reads >= MIN_DISK_OPS && disk.read_await.is_some_and(|a| a >= SLOW_DISK_READ_AWAIT)
        {
            return Some(SlowReason::DiskReadAwait);
        }
        if disk.writes >= MIN_DISK_OPS
            && disk.write_await.is_some_and(|a| a >= SLOW_DISK_WRITE_AWAIT)
        {
            return Some(SlowReason::DiskWriteAwait);
        }
        None
    }
}

/// What the caller logs after an interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoAction {
    None,
    /// No episode holds and the last line is [`SUMMARY_EVERY`] old.
    Summary,
    /// An episode starts: `slow` since its first slow interval began.
    SlowStart {
        slow: Duration,
        reason: SlowReason,
    },
    /// It still holds, [`REPEAT`] after the last warning.
    SlowRepeat {
        slow: Duration,
        reason: SlowReason,
    },
    /// It ended: `slow` from its start to its first interval under every
    /// threshold.
    SlowEnd {
        slow: Duration,
    },
}

/// The slow-episode state of a store.
#[derive(Debug, Default)]
pub struct IoWatch {
    slow_run: u32,
    first_slow: Option<Instant>,
    ok_run: u32,
    first_ok: Option<Instant>,
    slow_since: Option<Instant>,
    last_warn: Option<Instant>,
    last_line: Option<Instant>,
}

impl IoWatch {
    /// Take the interval that ended at `now`.
    pub fn observe(&mut self, interval: &IoInterval, now: Instant) -> IoAction {
        let began = now.checked_sub(interval.length).unwrap_or(now);
        let action = match (interval.measured(), interval.slow_reason()) {
            (false, _) => self.summary_due(now),
            (true, Some(reason)) => {
                self.ok_run = 0;
                self.first_ok = None;
                self.slow_run = self.slow_run.saturating_add(1);
                let first = *self.first_slow.get_or_insert(began);
                match self.slow_since {
                    None if self.slow_run >= START_AFTER => {
                        self.slow_since = Some(first);
                        self.last_warn = Some(now);
                        IoAction::SlowStart {
                            slow: now.saturating_duration_since(first),
                            reason,
                        }
                    }
                    None => IoAction::None,
                    Some(since) => {
                        if self
                            .last_warn
                            .is_none_or(|t| now.saturating_duration_since(t) >= REPEAT)
                        {
                            self.last_warn = Some(now);
                            IoAction::SlowRepeat {
                                slow: now.saturating_duration_since(since),
                                reason,
                            }
                        } else {
                            IoAction::None
                        }
                    }
                }
            }
            (true, None) => {
                self.slow_run = 0;
                self.first_slow = None;
                match self.slow_since {
                    None => self.summary_due(now),
                    Some(since) => {
                        self.ok_run = self.ok_run.saturating_add(1);
                        let ended = *self.first_ok.get_or_insert(began);
                        if self.ok_run >= END_AFTER {
                            self.slow_since = None;
                            self.last_warn = None;
                            self.ok_run = 0;
                            self.first_ok = None;
                            IoAction::SlowEnd {
                                slow: ended.saturating_duration_since(since),
                            }
                        } else {
                            IoAction::None
                        }
                    }
                }
            }
        };
        if action != IoAction::None {
            self.last_line = Some(now);
        }
        action
    }

    fn summary_due(&self, now: Instant) -> IoAction {
        if self.slow_since.is_none()
            && self
                .last_line
                .is_none_or(|t| now.saturating_duration_since(t) >= SUMMARY_EVERY)
        {
            IoAction::Summary
        } else {
            IoAction::None
        }
    }

    /// Since when a slow episode holds.
    pub fn slow_since(&self) -> Option<Instant> {
        self.slow_since
    }
}

/// The latest interval of the master store and its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreIoReport {
    pub interval: IoInterval,
    /// How long a slow episode has held; `None` while none does.
    pub slow_for: Option<Duration>,
    pub ended_unix_ms: u64,
}

impl StoreIoReport {
    pub fn to_proto(&self) -> StoreIoHealth {
        let us = |d: Duration| u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        let mut health = StoreIoHealth {
            slow_secs: self.slow_for.map_or(0, |d| d.as_secs()),
            interval_secs: u32::try_from(self.interval.length.as_secs()).unwrap_or(u32::MAX),
            ended_unix_ms: self.ended_unix_ms,
            canary_pending_us: self.interval.pending.map_or(0, us),
            ..Default::default()
        };
        health.set_verdict(match (self.slow_for, self.interval.measured()) {
            (Some(_), _) => StoreIoVerdict::Slow,
            (None, true) => StoreIoVerdict::Ok,
            (None, false) => StoreIoVerdict::Unspecified,
        });
        health.set_slow_reason(
            self.interval
                .slow_reason()
                .map_or(StoreIoReason::None, SlowReason::to_proto),
        );
        if let Some(canary) = self.interval.canary {
            health.canary_reads = canary.reads;
            health.canary_p50_us = us(canary.p50);
            health.canary_p99_us = us(canary.p99);
            health.canary_max_us = us(canary.max);
        }
        if let Some(disk) = self.interval.disk {
            health.disk_reads = Some(disk.reads);
            health.disk_writes = Some(disk.writes);
            health.disk_read_await_us = disk.read_await.map(us);
            health.disk_write_await_us = disk.write_await.map(us);
            health.disk_busy_pct = Some(disk.busy_pct);
        }
        health
    }
}

type Published = Arc<Mutex<Option<(Instant, StoreIoReport)>>>;

fn master_report() -> &'static Published {
    static LATEST: OnceLock<Published> = OnceLock::new();
    LATEST.get_or_init(Default::default)
}

/// The master store's latest interval, unless none was published in the
/// last three intervals.
pub fn latest() -> Option<StoreIoReport> {
    read_published(master_report())
}

fn read_published(published: &Published) -> Option<StoreIoReport> {
    let latest = *published.lock().unwrap_or_else(PoisonError::into_inner);
    latest
        .filter(|(at, _)| at.elapsed() <= STALE_AFTER)
        .map(|(_, report)| report)
}

/// The canary's reads not yet summarised, and the one in flight.
#[derive(Debug, Default)]
struct Probe {
    samples: Vec<Duration>,
    pending_since: Option<Instant>,
    stopped: bool,
}

fn lock(probe: &Mutex<Probe>) -> std::sync::MutexGuard<'_, Probe> {
    probe.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A table file's key range, with the running total of file sizes.
struct TableFile {
    weight_end: u64,
    start: Vec<u8>,
    end: Vec<u8>,
}

fn table_files(db: &CoordinatedDb) -> Vec<TableFile> {
    let mut total = 0u64;
    db.live_files()
        .unwrap_or_default()
        .into_iter()
        .filter(|f| f.column_family_name == "default")
        .filter_map(|f| {
            let (start, end) = (f.start_key?, f.end_key?);
            total = total.saturating_add((f.size as u64).max(1));
            Some(TableFile {
                weight_end: total,
                start,
                end,
            })
        })
        .collect()
}

/// The file holding byte `r` of the files' total size.
fn pick(files: &[TableFile], r: u64) -> Option<&TableFile> {
    let at = r % files.last()?.weight_end;
    files.get(files.partition_point(|f| f.weight_end <= at))
}

/// A key to seek to within `start..=end`: their common prefix, a byte
/// between theirs at the first difference, then random bytes from `r`.
pub fn seek_target(start: &[u8], end: &[u8], r: u64) -> Vec<u8> {
    let common = start.iter().zip(end).take_while(|(a, b)| a == b).count();
    let Some(&high) = end.get(common) else {
        return start.to_vec();
    };
    let low = start.get(common).copied().unwrap_or(0);
    let span = u64::from(high.saturating_sub(low)) + 1;
    let mut key = start[..common].to_vec();
    key.push(low + (r % span) as u8);
    key.extend_from_slice(&r.rotate_left(17).to_be_bytes());
    key
}

/// One canary read: a seek at a random position of a random table file
/// and the entry it lands on, or the first entry while the store has no
/// table file. Whether it landed on one.
fn canary_read(db: &CoordinatedDb, files: &[TableFile], r: u64) -> bool {
    let mut opts = rocksdb::ReadOptions::default();
    opts.fill_cache(false);
    opts.set_max_skippable_internal_keys(MAX_SKIPPED_KEYS);
    let file = pick(files, r);
    if let Some(file) = file {
        let mut upper = file.end.clone();
        upper.push(0);
        opts.set_iterate_upper_bound(upper);
    }
    let mut it = db.raw_iterator_opt(opts);
    match file {
        Some(file) => it.seek(seek_target(&file.start, &file.end, r.rotate_left(29))),
        None => it.seek_to_first(),
    }
    let landed = it.valid();
    if landed {
        std::hint::black_box(it.value());
    }
    landed
}

/// xorshift64*: canary positions need spread, not secrecy.
fn next_random(state: &mut u64) -> u64 {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    state.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

fn run_canary(db: WeakCoordinatedDb, probe: Arc<Mutex<Probe>>, period: Duration) {
    let mut rng = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0x9e37_79b9_7f4a_7c15, |d| d.as_nanos() as u64)
        | 1;
    let mut files = Vec::new();
    let mut listed: Option<Instant> = None;
    while let Some(store) = db.upgrade() {
        if listed.is_none_or(|t| t.elapsed() >= FILES_REFRESH) {
            files = table_files(&store);
            listed = Some(Instant::now());
        }
        let started = Instant::now();
        lock(&probe).pending_since = Some(started);
        canary_read(&store, &files, next_random(&mut rng));
        let took = started.elapsed();
        drop(store);
        {
            let mut probe = lock(&probe);
            probe.pending_since = None;
            if probe.samples.len() < MAX_SAMPLES {
                probe.samples.push(took);
            }
        }
        std::thread::sleep(period);
    }
    lock(&probe).stopped = true;
}

/// The reads and disk work since the last line.
struct Window {
    started: Instant,
    samples: Vec<Duration>,
    pending: Option<Duration>,
    disk: Option<DiskCounters>,
    intervals: u32,
    slow_intervals: u32,
}

impl Window {
    fn new(now: Instant, disk: Option<DiskCounters>) -> Self {
        Window {
            started: now,
            samples: Vec::new(),
            pending: None,
            disk,
            intervals: 0,
            slow_intervals: 0,
        }
    }

    fn summary(&mut self, now: Instant, disk: Option<DiskCounters>) -> IoInterval {
        let length = now.saturating_duration_since(self.started);
        IoInterval {
            length,
            canary: summarise(&mut self.samples),
            pending: self.pending,
            disk: self
                .disk
                .zip(disk)
                .and_then(|(before, after)| DiskAwait::between(&before, &after, length)),
        }
    }
}

fn ms(d: Duration) -> String {
    format!("{:.1}", d.as_secs_f64() * 1000.0)
}

/// Which store and disk a line is about.
struct Subject {
    store: &'static str,
    disk: Option<String>,
}

fn log_action(
    subject: &Subject,
    action: IoAction,
    latest: &IoInterval,
    window: &mut Window,
    now: Instant,
    disk_now: Option<DiskCounters>,
) {
    let disk = subject.disk.as_deref().unwrap_or("unresolved");
    match action {
        IoAction::None => {}
        IoAction::Summary => {
            let w = window.summary(now, disk_now);
            info!(
                store = subject.store,
                window_secs = w.length.as_secs(),
                intervals = window.intervals,
                slow_intervals = window.slow_intervals,
                canary_reads = w.canary.map_or(0, |c| c.reads),
                canary_p50_ms = w.canary.map(|c| ms(c.p50)),
                canary_p99_ms = w.canary.map(|c| ms(c.p99)),
                canary_max_ms = w.canary.map(|c| ms(c.max)),
                canary_pending_ms = w.pending.map(ms),
                disk,
                disk_reads = w.disk.map(|d| d.reads),
                disk_writes = w.disk.map(|d| d.writes),
                disk_read_await_ms = w.disk.and_then(|d| d.read_await).map(ms),
                disk_write_await_ms = w.disk.and_then(|d| d.write_await).map(ms),
                disk_busy_pct = w.disk.map(|d| d.busy_pct),
                "store i/o summary"
            );
        }
        IoAction::SlowStart { slow, reason } | IoAction::SlowRepeat { slow, reason } => warn!(
            scope = "this node's disk",
            store = subject.store,
            reason = reason.label(),
            slow_secs = slow.as_secs(),
            interval_secs = latest.length.as_secs(),
            canary_reads = latest.canary.map_or(0, |c| c.reads),
            canary_p50_ms = latest.canary.map(|c| ms(c.p50)),
            canary_p99_ms = latest.canary.map(|c| ms(c.p99)),
            canary_max_ms = latest.canary.map(|c| ms(c.max)),
            canary_pending_ms = latest.pending.map(ms),
            disk,
            disk_reads = latest.disk.map(|d| d.reads),
            disk_writes = latest.disk.map(|d| d.writes),
            disk_read_await_ms = latest.disk.and_then(|d| d.read_await).map(ms),
            disk_write_await_ms = latest.disk.and_then(|d| d.write_await).map(ms),
            disk_busy_pct = latest.disk.map(|d| d.busy_pct),
            "store reads slow: reads of this node's store, or its disk's \
             response times, are over the slow thresholds (canary p99 50 ms, \
             a read pending 1 s, disk await 20 ms a read or 100 ms a write); \
             work that reads the store falls behind and seats may lapse. This \
             node's disk is the cause: check that TRIM runs (fstrim.timer or \
             the discard mount option), the disk's health (SMART) and other \
             I/O load on the same disk. Repeats every 10 minutes while it holds"
        ),
        IoAction::SlowEnd { slow } => info!(
            scope = "this node's disk",
            store = subject.store,
            slow_secs = slow.as_secs(),
            canary_p99_ms = latest.canary.map(|c| ms(c.p99)),
            disk,
            disk_read_await_ms = latest.disk.and_then(|d| d.read_await).map(ms),
            disk_write_await_ms = latest.disk.and_then(|d| d.write_await).map(ms),
            "store reads recovered: reads of this node's store and its disk's \
             response times are back under the slow thresholds"
        ),
    }
}

/// Close an interval every `interval` until the canary has stopped.
fn run_summary(
    probe: Arc<Mutex<Probe>>,
    subject: Subject,
    device: Option<Device>,
    interval: Duration,
    published: Published,
) {
    let mut watch = IoWatch::default();
    let mut started = Instant::now();
    let mut disk_before = disk_counters(device);
    let mut window = Window::new(started, disk_before);
    loop {
        std::thread::sleep(interval);
        let now = Instant::now();
        let (mut samples, pending, stopped) = {
            let mut probe = lock(&probe);
            (
                std::mem::take(&mut probe.samples),
                probe
                    .pending_since
                    .map(|t| now.saturating_duration_since(t)),
                probe.stopped,
            )
        };
        if stopped && samples.is_empty() {
            *published.lock().unwrap_or_else(PoisonError::into_inner) = None;
            return;
        }
        let disk_now = disk_counters(device);
        let length = now.saturating_duration_since(started);
        if window.samples.len() + samples.len() <= MAX_SAMPLES {
            window.samples.extend_from_slice(&samples);
        }
        window.pending = window.pending.max(pending);
        let latest = IoInterval {
            length,
            canary: summarise(&mut samples),
            pending,
            disk: disk_before
                .zip(disk_now)
                .and_then(|(before, after)| DiskAwait::between(&before, &after, length)),
        };
        window.intervals += 1;
        window.slow_intervals += u32::from(latest.slow_reason().is_some());
        let action = watch.observe(&latest, now);
        let report = StoreIoReport {
            interval: latest,
            slow_for: watch
                .slow_since()
                .map(|since| now.saturating_duration_since(since)),
            ended_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
        };
        *published.lock().unwrap_or_else(PoisonError::into_inner) = Some((now, report));
        log_action(&subject, action, &latest, &mut window, now, disk_now);
        if action != IoAction::None {
            window = Window::new(now, disk_now);
        }
        started = now;
        disk_before = disk_now;
    }
}

/// Start the canary and summary threads of `db`, publishing to `published`.
fn spawn_watch(
    db: &CoordinatedDb,
    store: &'static str,
    period: Duration,
    interval: Duration,
    published: Published,
) -> bool {
    let device = store_device(db.path());
    let disk = device.and_then(|device| {
        let text = std::fs::read_to_string("/proc/diskstats").ok()?;
        parse_diskstats(&text, device).map(|(name, _)| name)
    });
    info!(
        store,
        disk = disk.as_deref().unwrap_or("unresolved"),
        canary_period_ms = period.as_millis() as u64,
        interval_secs = interval.as_secs(),
        "store i/o watch started"
    );
    let probe = Arc::new(Mutex::new(Probe::default()));
    let canary = {
        let (probe, weak) = (probe.clone(), db.downgrade());
        std::thread::Builder::new()
            .name("store-io-canary".into())
            .spawn(move || run_canary(weak, probe, period))
    };
    if canary.is_err() {
        return false;
    }
    std::thread::Builder::new()
        .name("store-io-summary".into())
        .spawn(move || run_summary(probe, Subject { store, disk }, device, interval, published))
        .is_ok()
}

/// Start the store I/O watch of the master store ([`latest`]). Only the
/// first call starts one; it stops once the store closes.
pub fn start_master(db: &CoordinatedDb) -> bool {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return false;
    }
    spawn_watch(
        db,
        "master",
        CANARY_PERIOD,
        INTERVAL,
        master_report().clone(),
    )
}

#[cfg(test)]
#[path = "store_io_tests.rs"]
mod tests;
