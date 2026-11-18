//! One line per epoch at the master: what this process wrote to disk that
//! epoch, by subsystem, beside what the disks holding its stores wrote, with
//! the rate per day an operator compares against the drive's rated TBW.
//!
//! Sources, each counted since the process started: RocksDB's statistics
//! per class of store ([`quil_store::write_stats`]), the replica bytes put
//! into the worker stores, the label and sector files written
//! ([`quil_engine::storage_labels::file_bytes_written`]), the kernel's
//! `write_bytes` of this process (`/proc/self/io`) and the sectors written
//! of each disk (`/sys/dev/block`, readable without root).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use quil_store::write_stats::{StoreClass, StoreWrites};
use tracing::info;

/// The shortest span a line covers: while the node catches up on frames,
/// epochs pass in seconds, and their rate says nothing of a day's writes.
const MIN_SPAN: Duration = Duration::from_secs(600);

/// Bytes this process wrote since it started, by subsystem.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Written {
    pub master: StoreWrites,
    pub workers: StoreWrites,
    /// Replica bytes put into the worker stores: part of their writes.
    pub replicas: u64,
    pub label_files: u64,
    pub sector_files: u64,
    /// The kernel's `write_bytes` for this process; `None` where unreadable.
    pub process: Option<u64>,
    /// What the disks holding this node's stores wrote, every process's
    /// writes included; `None` where no disk could be read.
    pub disks: Option<u64>,
}

impl Written {
    /// This process's counts now, and what `disks` (their `stat` files)
    /// wrote.
    fn sample(disks: &[PathBuf]) -> Self {
        let (label_files, sector_files) = quil_engine::storage_labels::file_bytes_written();
        Self {
            master: StoreClass::Master.written(),
            workers: StoreClass::Workers.written(),
            replicas: quil_store::replica_store::replica_bytes_written(),
            label_files,
            sector_files,
            process: std::fs::read_to_string("/proc/self/io")
                .ok()
                .and_then(|text| proc_write_bytes(&text)),
            disks: disks_written(disks),
        }
    }

    /// What was written between `earlier` and `self`.
    fn since(self, earlier: Written) -> Written {
        let diff = |now: Option<u64>, then: Option<u64>| Some(now?.saturating_sub(then?));
        Written {
            master: self.master.since(earlier.master),
            workers: self.workers.since(earlier.workers),
            replicas: self.replicas.saturating_sub(earlier.replicas),
            label_files: self.label_files.saturating_sub(earlier.label_files),
            sector_files: self.sector_files.saturating_sub(earlier.sector_files),
            process: diff(self.process, earlier.process),
            disks: diff(self.disks, earlier.disks),
        }
    }
}

/// `write_bytes` of `/proc/<pid>/io`: bytes this process caused to be
/// written to storage, whole pages as they were dirtied.
fn proc_write_bytes(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix("write_bytes:"))
        .and_then(|value| value.trim().parse().ok())
}

/// Sectors written, the seventh field of a block device's `stat` file, in
/// bytes: the kernel counts them in 512-byte units whatever the disk's own.
fn stat_written_bytes(text: &str) -> Option<u64> {
    let sectors: u64 = text.split_whitespace().nth(6)?.parse().ok()?;
    sectors.checked_mul(512)
}

/// What the disks of these `stat` files wrote: `None` unless every one
/// read.
fn disks_written(disks: &[PathBuf]) -> Option<u64> {
    if disks.is_empty() {
        return None;
    }
    disks.iter().try_fold(0u64, |sum, stat| {
        let bytes = stat_written_bytes(&std::fs::read_to_string(stat).ok()?)?;
        sum.checked_add(bytes)
    })
}

/// The major and minor numbers of a device number (glibc's encoding).
fn major_minor(dev: u64) -> (u64, u64) {
    let major = ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0xfff);
    let minor = ((dev >> 12) & 0xffff_ff00) | (dev & 0xff);
    (major, minor)
}

/// The `stat` file under `sys` (`/sys`) of the whole disk holding the
/// filesystem of device number `dev`: through a device mapper stacked on
/// one device (dm-crypt, single-disk LVM) to it, then from a partition to
/// its disk. `None` for a filesystem without a block device of its own
/// (btrfs, tmpfs, overlay), or stacked on several (RAID, LVM over disks).
fn disk_stat(sys: &Path, dev: u64) -> Option<PathBuf> {
    let (major, minor) = major_minor(dev);
    if major == 0 {
        return None;
    }
    let mut at = std::fs::canonicalize(sys.join(format!("dev/block/{major}:{minor}"))).ok()?;
    loop {
        let under: Vec<PathBuf> = std::fs::read_dir(at.join("slaves"))
            .map(|dir| dir.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        match under.as_slice() {
            [] => break,
            [one] => at = std::fs::canonicalize(one).ok()?,
            _ => return None,
        }
    }
    if at.join("partition").exists() {
        at = at.parent()?.to_path_buf();
    }
    let stat = at.join("stat");
    stat.exists().then_some(stat)
}

/// The `stat` files of the disks holding this process's stores, each once.
fn store_disks() -> Vec<PathBuf> {
    let mut disks: Vec<PathBuf> = quil_forest::storage_health::store_dirs()
        .iter()
        .filter_map(|dir| disk_stat(Path::new("/sys"), device_of(dir)?))
        .collect();
    disks.sort();
    disks.dedup();
    disks
}

#[cfg(unix)]
fn device_of(dir: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dir).ok().map(|meta| meta.dev())
}

#[cfg(not(unix))]
fn device_of(_dir: &Path) -> Option<u64> {
    None
}

/// Where the current span started.
struct Mark {
    epoch: u64,
    at: Instant,
    written: Written,
    disks: Vec<PathBuf>,
    /// Whether it started as an epoch began, not mid-epoch at start-up.
    whole: bool,
}

/// The master's per-epoch disk-write line: fed the epoch at each status
/// tick, it logs once the epoch moves on, at least [`MIN_SPAN`] after the
/// span began.
#[derive(Default)]
pub(crate) struct EpochWrites {
    mark: Option<Mark>,
}

impl EpochWrites {
    /// At a status tick in `epoch`: log the line for the span that ended,
    /// if one did.
    pub(crate) fn observe(&mut self, epoch: u64, now: Instant) {
        if !self.due(epoch, now) {
            return;
        }
        let disks = self.mark.as_ref().map(|mark| mark.disks.clone());
        let end = disks.as_deref().map(Written::sample);
        let next = store_disks();
        let start = match end {
            Some(end) if disks.as_deref() == Some(next.as_slice()) => end,
            _ => Written::sample(&next),
        };
        if let Some(report) = self.advance(epoch, now, end, start, next) {
            report.log();
        }
    }

    /// Whether a tick in `epoch` ends the span: the first sets its start.
    fn due(&self, epoch: u64, now: Instant) -> bool {
        self.mark.as_ref().is_none_or(|mark| {
            epoch > mark.epoch && now.saturating_duration_since(mark.at) >= MIN_SPAN
        })
    }

    /// Start a span at `epoch` with `start` counted on `disks`; the report
    /// of the span `end` closes, if one was open.
    fn advance(
        &mut self,
        epoch: u64,
        now: Instant,
        end: Option<Written>,
        start: Written,
        disks: Vec<PathBuf>,
    ) -> Option<Report> {
        let previous = self.mark.replace(Mark {
            epoch,
            at: now,
            written: start,
            disks,
            whole: true,
        });
        let Some(previous) = previous else {
            if let Some(mark) = &mut self.mark {
                mark.whole = false;
            }
            return None;
        };
        Some(Report {
            epoch: epoch.saturating_sub(1),
            epochs: epoch.saturating_sub(previous.epoch),
            span: now.saturating_duration_since(previous.at),
            whole: previous.whole,
            wrote: end?.since(previous.written),
        })
    }
}

/// What this process wrote over a span of whole epochs (the first may
/// start mid-epoch).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Report {
    /// The last epoch the span covers.
    epoch: u64,
    epochs: u64,
    span: Duration,
    /// Whether the span started as its first epoch began.
    whole: bool,
    wrote: Written,
}

const MB: u64 = 1_000_000;

impl Report {
    /// Each subsystem's bytes, the replicas left out (part of the
    /// workers'), and the rest of the process's writes.
    fn parts(&self) -> [(&'static str, u64); 9] {
        let w = &self.wrote;
        [
            ("master_wal", w.master.wal),
            ("master_flush", w.master.flush),
            ("master_compaction", w.master.compaction),
            ("workers_wal", w.workers.wal),
            ("workers_flush", w.workers.flush),
            ("workers_compaction", w.workers.compaction),
            ("label_files", w.label_files),
            ("sector_files", w.sector_files),
            ("other", self.other().unwrap_or(0)),
        ]
    }

    /// The process's writes no subsystem counted (logs, scratch files, the
    /// kernel's whole pages over RocksDB's bytes); `None` where unreadable.
    fn other(&self) -> Option<u64> {
        let w = &self.wrote;
        let counted = [
            w.master.wal,
            w.master.flush,
            w.master.compaction,
            w.workers.wal,
            w.workers.flush,
            w.workers.compaction,
            w.label_files,
            w.sector_files,
        ]
        .iter()
        .fold(0u64, |sum, bytes| sum.saturating_add(*bytes));
        Some(w.process?.saturating_sub(counted))
    }

    /// The largest part and its share of the whole, in percent: of the
    /// process's writes, or of the parts where they sum to more.
    fn largest(&self) -> (&'static str, u64) {
        let parts = self.parts();
        let sum = parts
            .iter()
            .fold(0u64, |sum, (_, bytes)| sum.saturating_add(*bytes));
        let whole = sum.max(self.wrote.process.unwrap_or(0));
        let mut top = ("none", 0);
        for part in parts {
            if part.1 > top.1 {
                top = part;
            }
        }
        let (name, bytes) = top;
        let pct = if whole == 0 {
            0
        } else {
            (u128::from(bytes) * 100 / u128::from(whole)) as u64
        };
        (name, pct)
    }

    /// `bytes` over the span as GB (10^9 bytes) a day, the unit drives'
    /// TBW ratings divide into.
    fn gb_per_day(&self, bytes: u64) -> f64 {
        let secs = self.span.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        bytes as f64 / secs * 86_400.0 / 1e9
    }

    fn log(&self) {
        let w = &self.wrote;
        let (largest, largest_pct) = self.largest();
        let mb = |bytes: u64| bytes / MB;
        let unread = || "unreadable".to_string();
        let per_day = |bytes: Option<u64>| {
            bytes.map_or_else(unread, |bytes| format!("{:.1}", self.gb_per_day(bytes)))
        };
        info!(
            epoch = self.epoch,
            epochs = self.epochs,
            minutes = self.span.as_secs() / 60,
            whole_epoch = self.whole,
            gb_per_day = %per_day(w.process),
            device_gb_per_day = %per_day(w.disks),
            process_mb = %w.process.map_or_else(unread, |b| mb(b).to_string()),
            device_mb = %w.disks.map_or_else(unread, |b| mb(b).to_string()),
            largest,
            largest_pct,
            master_wal_mb = mb(w.master.wal),
            master_flush_mb = mb(w.master.flush),
            master_compaction_mb = mb(w.master.compaction),
            workers_wal_mb = mb(w.workers.wal),
            workers_flush_mb = mb(w.workers.flush),
            workers_compaction_mb = mb(w.workers.compaction),
            replica_put_mb = mb(w.replicas),
            label_files_mb = mb(w.label_files),
            sector_files_mb = mb(w.sector_files),
            other_mb = %self.other().map_or_else(unread, |b| mb(b).to_string()),
            scope = "this process",
            "disk writes this epoch by subsystem: this process wrote `process_mb`, about \
             `gb_per_day` GB/day at this rate, `largest` the largest share; `device_mb` is \
             what the disks holding this node's stores were sent, every process's writes \
             included, as a drive's TBW rating counts them. Compare `device_gb_per_day` \
             with the drive's TBW over its warranty days (600 TBW over 5 years: about 330 \
             GB/day). `replica_put_mb` is part of the workers' figures; `other` holds logs, \
             scratch files and the kernel's whole pages over RocksDB's bytes. MB = 10^6 bytes"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(wal: u64, flush: u64, compaction: u64) -> StoreWrites {
        StoreWrites {
            wal,
            flush,
            compaction,
        }
    }

    /// Counts at a span's start and end give each subsystem its bytes, the
    /// process's uncounted rest, the largest share and the rate a day.
    #[test]
    fn a_span_gives_each_subsystem_its_bytes_and_names_the_largest() {
        let start = Written {
            master: class(10 * MB, 20 * MB, 30 * MB),
            workers: class(100 * MB, 200 * MB, 300 * MB),
            replicas: 50 * MB,
            label_files: 5 * MB,
            sector_files: 0,
            process: Some(1_000 * MB),
            disks: Some(5_000 * MB),
        };
        let end = Written {
            master: class(110 * MB, 70 * MB, 90 * MB),
            workers: class(2_100 * MB, 1_200 * MB, 3_300 * MB),
            replicas: 1_050 * MB,
            label_files: 1_005 * MB,
            sector_files: 400 * MB,
            process: Some(11_000 * MB),
            disks: Some(25_000 * MB),
        };
        let mut spans = EpochWrites::default();
        let at = Instant::now();
        assert_eq!(spans.advance(7, at, None, start, Vec::new()), None);
        let report = spans
            .advance(
                8,
                at + Duration::from_secs(7_200),
                Some(end),
                end,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            (report.epoch, report.epochs, report.whole),
            (7, 1, false),
            "span_misdated"
        );
        assert_eq!(
            report.wrote.workers,
            class(2_000 * MB, 1_000 * MB, 3_000 * MB),
            "class_delta"
        );
        assert_eq!(
            (
                report.wrote.replicas,
                report.wrote.label_files,
                report.wrote.sector_files
            ),
            (1_000 * MB, 1_000 * MB, 400 * MB),
            "file_delta"
        );
        // 100 + 50 + 60 + 2000 + 1000 + 3000 + 1000 + 400 counted of 10000.
        assert_eq!(report.other(), Some(2_390 * MB), "other_miscounted");
        assert_eq!(
            report.largest(),
            ("workers_compaction", 30),
            "largest_share"
        );
        // 10 GB in 2 h: 120 GB a day; the disks' 20 GB: 240.
        let per_day = (
            report.gb_per_day(report.wrote.process.unwrap()),
            report.gb_per_day(report.wrote.disks.unwrap()),
        );
        assert!(
            (per_day.0 - 120.0).abs() < 1e-6 && (per_day.1 - 240.0).abs() < 1e-6,
            "per_day_rate: {per_day:?}"
        );
    }

    /// Without the process's own count, nothing is called its rest, and the
    /// share is of what the subsystems counted.
    #[test]
    fn an_unreadable_process_count_leaves_shares_of_the_counted() {
        let end = Written {
            master: class(MB, 0, 0),
            label_files: 3 * MB,
            ..Written::default()
        };
        let mut spans = EpochWrites::default();
        let at = Instant::now();
        spans.advance(3, at, None, Written::default(), Vec::new());
        let report = spans
            .advance(4, at + MIN_SPAN, Some(end), end, Vec::new())
            .unwrap();
        assert_eq!(report.other(), None, "other_without_process");
        assert_eq!(report.largest(), ("label_files", 75), "share_of_counted");
    }

    /// The first tick starts a span mid-epoch; a span ends once the epoch
    /// has moved on and at least [`MIN_SPAN`] has passed, covering every
    /// epoch since; the next span starts as an epoch begins.
    #[test]
    fn a_span_ends_with_its_epoch_once_long_enough() {
        let at = Instant::now();
        let mut spans = EpochWrites::default();
        assert!(spans.due(5, at), "first_tick_not_due");
        spans.advance(5, at, None, Written::default(), Vec::new());
        assert!(!spans.due(5, at + 2 * MIN_SPAN), "same_epoch_due");
        assert!(!spans.due(9, at + MIN_SPAN / 2), "short_span_due");
        assert!(spans.due(9, at + MIN_SPAN), "long_span_not_due");
        let first = spans
            .advance(
                9,
                at + MIN_SPAN,
                Some(Written::default()),
                Written::default(),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            (first.epoch, first.epochs, first.whole),
            (8, 4, false),
            "first_span"
        );
        let next = spans
            .advance(
                10,
                at + 3 * MIN_SPAN,
                Some(Written::default()),
                Written::default(),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            (next.epoch, next.epochs, next.whole, next.span),
            (9, 1, true, 2 * MIN_SPAN),
            "next_span"
        );
    }

    /// The process's count is the `write_bytes` line, not the
    /// `cancelled_write_bytes` one, wherever either stands.
    #[test]
    fn written_bytes_come_from_the_write_bytes_line() {
        let io = "rchar: 9\nwchar: 8\ncancelled_write_bytes: 4096\nread_bytes: 7\n\
                  write_bytes: 123456\nsyscw: 3\n";
        assert_eq!(proc_write_bytes(io), Some(123_456), "PROC-IO write_bytes");
        assert_eq!(proc_write_bytes("rchar: 1\n"), None, "PROC-IO missing");
    }

    /// A disk's written bytes are its sectors written, the seventh field, at
    /// 512 bytes each.
    #[test]
    fn disk_bytes_are_its_sectors_written() {
        let stat = "  4 0 800 9  21 3 4000 50 0 30 60 0 0 0 0 0 0\n";
        assert_eq!(stat_written_bytes(stat), Some(4_000 * 512), "sectors_field");
        assert_eq!(stat_written_bytes("1 2 3"), None, "short_stat");
        assert_eq!(major_minor((259 << 8) | 3), (259, 3), "dev_numbers");
        assert_eq!(
            major_minor((253u64 << 8) | (1 << 20) | 1),
            (253, 256 + 1),
            "large_minor"
        );
    }

    /// The disk of a store is found from its filesystem's device: a
    /// partition's disk, through a device mapper on one partition; none for
    /// a device on several, or without a block device.
    #[test]
    fn a_stores_disk_is_found_through_partitions_and_device_mappers() {
        let sys = tempfile::tempdir().unwrap();
        let root = sys.path();
        let mk = |rel: &str| std::fs::create_dir_all(root.join(rel)).unwrap();
        let write = |rel: &str, text: &str| std::fs::write(root.join(rel), text).unwrap();
        let link = |target: &str, rel: &str| {
            std::os::unix::fs::symlink(root.join(target), root.join(rel)).unwrap()
        };
        mk("devices/nvme0n1/nvme0n1p3");
        write("devices/nvme0n1/stat", "0 0 0 0 0 0 8 0\n");
        write("devices/nvme0n1/nvme0n1p3/partition", "3\n");
        write("devices/nvme0n1/nvme0n1p3/stat", "0 0 0 0 0 0 2 0\n");
        mk("devices/sda/sda1");
        write("devices/sda/stat", "0 0 0 0 0 0 4 0\n");
        write("devices/sda/sda1/partition", "1\n");
        mk("devices/virtual/dm-0/slaves");
        write("devices/virtual/dm-0/stat", "0 0 0 0 0 0 1 0\n");
        link(
            "devices/nvme0n1/nvme0n1p3",
            "devices/virtual/dm-0/slaves/nvme0n1p3",
        );
        mk("devices/virtual/md0/slaves");
        write("devices/virtual/md0/stat", "0 0 0 0 0 0 1 0\n");
        link(
            "devices/nvme0n1/nvme0n1p3",
            "devices/virtual/md0/slaves/nvme0n1p3",
        );
        link("devices/sda/sda1", "devices/virtual/md0/slaves/sda1");
        mk("dev/block");
        link("devices/nvme0n1/nvme0n1p3", "dev/block/259:3");
        link("devices/virtual/dm-0", "dev/block/253:0");
        link("devices/virtual/md0", "dev/block/9:0");
        let disk = std::fs::canonicalize(root.join("devices/nvme0n1/stat")).ok();
        let dev = |major: u64, minor: u64| (major << 8) | minor;
        assert_eq!(disk_stat(root, dev(259, 3)), disk, "partition_not_its_disk");
        assert_eq!(disk_stat(root, dev(253, 0)), disk, "mapper_not_its_disk");
        assert_eq!(disk_stat(root, dev(9, 0)), None, "several_disks_named_one");
        assert_eq!(disk_stat(root, dev(0, 42)), None, "no_block_device");
        assert_eq!(
            disks_written(&[disk.unwrap()]),
            Some(8 * 512),
            "disk_bytes_unread"
        );
        assert_eq!(disks_written(&[]), None, "no_disk_read_as_zero");
    }
}
