use super::*;
use std::path::PathBuf;

const MS: Duration = Duration::from_millis(1);

fn ms_n(n: u64) -> Duration {
    Duration::from_millis(n)
}

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
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, run);
    let bytes = lines.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

/// Nearest-rank percentiles: p50 of 1..=100 ms is 50 ms, p99 99 ms; of 60
/// reads (one interval at one a second) p99 is the slowest.
#[test]
fn summarise_takes_nearest_rank_percentiles() {
    assert_eq!(summarise(&mut []), None);
    let mut one = [ms_n(7)];
    assert_eq!(
        summarise(&mut one),
        Some(ReadLatency {
            reads: 1,
            p50: ms_n(7),
            p99: ms_n(7),
            max: ms_n(7)
        })
    );
    let mut hundred: Vec<Duration> = (1..=100).rev().map(ms_n).collect();
    assert_eq!(
        summarise(&mut hundred),
        Some(ReadLatency {
            reads: 100,
            p50: ms_n(50),
            p99: ms_n(99),
            max: ms_n(100)
        })
    );
    let mut sixty: Vec<Duration> = (1..=60).map(ms_n).collect();
    sixty.swap(0, 59);
    let sixty = summarise(&mut sixty).unwrap();
    assert_eq!(
        (sixty.reads, sixty.p50, sixty.p99),
        (60, ms_n(30), ms_n(60))
    );
}

/// Linux 6.x lines (20 fields), a pre-4.18 line (14 fields), a partition.
const DISKSTATS: &str = "\
 259       0 nvme0n1 231591353 130038475 18350124652 253519018 75373210 91628197 24877510645 2222875224 0 37279993 2480516321 399494 0 670135624 691714 3598146 3430364
 259       2 nvme0n1p2 5000 0 2736 10000 400 0 0 2000 0 6000 12000 0 0 0 0 0 0
   8       0 sda 100 0 800 2500 50 0 400 9000 1 3000 11500
 253       0 dm-0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17
";

#[test]
fn diskstats_lines_parse_by_device_numbers() {
    let nvme = Device {
        major: 259,
        minor: 2,
    };
    assert_eq!(
        parse_diskstats(DISKSTATS, nvme),
        Some((
            "nvme0n1p2".to_string(),
            DiskCounters {
                reads: 5000,
                read_ms: 10000,
                writes: 400,
                write_ms: 2000,
                io_ms: 6000
            }
        ))
    );
    let sda = parse_diskstats(DISKSTATS, Device { major: 8, minor: 0 }).unwrap();
    assert_eq!(sda.0, "sda");
    assert_eq!(
        (
            sda.1.reads,
            sda.1.read_ms,
            sda.1.writes,
            sda.1.write_ms,
            sda.1.io_ms
        ),
        (100, 2500, 50, 9000, 3000)
    );
    assert_eq!(
        parse_diskstats(DISKSTATS, Device { major: 8, minor: 1 }),
        None
    );
    assert_eq!(parse_diskstats("", nvme), None);
}

/// Malformed input yields no counters and never panics: short lines and
/// garbage are skipped, a matching line with a non-number gives `None`, a
/// strange device name is not repeated.
#[test]
fn malformed_diskstats_give_no_counters() {
    let nvme = Device {
        major: 259,
        minor: 2,
    };
    let short = " 259 2 nvme0n1p2 5000 0 2736 10000 400\n";
    assert_eq!(parse_diskstats(short, nvme), None);
    let garbage = "\u{0}\u{1}xx\n\n   \n259:2 nvme\n";
    assert_eq!(parse_diskstats(garbage, nvme), None);
    let word = " 259 2 nvme0n1p2 5000 0 2736 ten 400 0 0 2000 0 6000 12000\n";
    assert_eq!(parse_diskstats(word, nvme), None);
    let negative = " 259 2 nvme0n1p2 -5 0 2736 10 400 0 0 2000 0 6000 12000\n";
    assert_eq!(parse_diskstats(negative, nvme), None);
    let odd = " 259 2 /home/me/disk 5 0 2736 10 400 0 0 2000 0 6000 12000\n";
    assert_eq!(parse_diskstats(odd, nvme).unwrap().0, "unnamed");
    // A malformed earlier line does not hide a good one for another device.
    let mixed = format!("{word}{DISKSTATS}");
    assert!(parse_diskstats(&mixed, Device { major: 8, minor: 0 }).is_some());
}

#[test]
fn disk_await_is_time_per_completed_operation() {
    let before = DiskCounters {
        reads: 1000,
        read_ms: 500,
        writes: 200,
        write_ms: 1000,
        io_ms: 10_000,
    };
    let after = DiskCounters {
        reads: 1100,
        read_ms: 2500,
        writes: 200,
        write_ms: 1000,
        io_ms: 40_000,
    };
    let disk = DiskAwait::between(&before, &after, Duration::from_secs(60)).unwrap();
    assert_eq!(disk.reads, 100);
    assert_eq!(disk.read_await, Some(ms_n(20)));
    assert_eq!((disk.writes, disk.write_await), (0, None));
    assert_eq!(disk.busy_pct, 50);
    // Busy time over the interval (rounding of the counters) is capped.
    let busier = DiskCounters {
        io_ms: 90_000,
        ..after
    };
    let disk = DiskAwait::between(&before, &busier, Duration::from_secs(60)).unwrap();
    assert_eq!(disk.busy_pct, 100);
    // Sub-millisecond awaits keep microseconds.
    let fast = DiskCounters {
        reads: 4000,
        read_ms: 1500,
        ..before
    };
    assert_eq!(
        DiskAwait::between(&before, &fast, Duration::from_secs(60))
            .unwrap()
            .read_await,
        Some(Duration::from_micros(333))
    );
    // Counters that went back (a reset) give no figures.
    assert_eq!(
        DiskAwait::between(&after, &before, Duration::from_secs(60)),
        None
    );
}

#[test]
fn device_numbers_decode_like_glibc() {
    // makedev(259, 2) and makedev(8, 300): minor bits above 8 sit at 20+.
    assert_eq!(
        Device::from_dev((259 << 8) | 2),
        Device {
            major: 259,
            minor: 2
        }
    );
    let dev = (8 << 8) | (300 & 0xff) | ((300 & !0xff) << 12);
    assert_eq!(
        Device::from_dev(dev),
        Device {
            major: 8,
            minor: 300
        }
    );
    let big = ((4096u64 & !0xfff) << 32) | ((4096 & 0xfff) << 8) | 1;
    assert_eq!(
        Device::from_dev(big),
        Device {
            major: 4096,
            minor: 1
        }
    );
}

const MOUNTINFO: &str = "\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
30 22 0:45 /@home /home rw,relatime shared:2 - btrfs /dev/nvme0n1p3 rw,subvol=/@home
31 22 0:46 / /mnt/my\\040disk rw - xfs /dev/sdb1 rw
32 22 0:47 / /tank rw - zfs tank/data rw
garbage line without a dash
33 22 x:y / /home/bad rw - ext4 /dev/sdz rw
34 22 0:48 / /short - ext4
35 22 0:49 / /home/me/over rw - tmpfs tmpfs rw
36 22 0:50 / /home/me/over rw - ext4 /dev/sdc1 rw
";

#[test]
fn mounts_resolve_by_longest_mount_point() {
    let (device, source) = mount_of(MOUNTINFO, Path::new("/home/me/.config/store")).unwrap();
    assert_eq!(
        (device, source),
        (
            Device {
                major: 0,
                minor: 45
            },
            "/dev/nvme0n1p3"
        )
    );
    let (device, _) = mount_of(MOUNTINFO, Path::new("/var/store")).unwrap();
    assert_eq!(
        device,
        Device {
            major: 259,
            minor: 2
        }
    );
    // Escaped spaces, and a later mount over the same point.
    assert_eq!(
        mount_of(MOUNTINFO, Path::new("/mnt/my disk/store"))
            .unwrap()
            .1,
        "/dev/sdb1"
    );
    assert_eq!(
        mount_of(MOUNTINFO, Path::new("/home/me/over/store"))
            .unwrap()
            .1,
        "/dev/sdc1"
    );
    // Components, not string prefixes; malformed lines are skipped.
    assert_eq!(
        mount_of(MOUNTINFO, Path::new("/homes/store")).unwrap().1,
        "/dev/nvme0n1p2"
    );
    assert_eq!(
        mount_of(MOUNTINFO, Path::new("/home/bad/store")).unwrap().1,
        "/dev/nvme0n1p3"
    );
    assert_eq!(mount_of("", Path::new("/")), None);
    assert_eq!(mount_of("garbage\n- - -\n", Path::new("/")), None);
}

#[test]
fn the_store_device_is_its_own_its_mounts_or_its_sources() {
    let stats = "\
 259 2 nvme0n1p2 1 0 0 0 0 0 0 0 0 0 0
 259 3 nvme0n1p3 1 0 0 0 0 0 0 0 0 0 0
";
    let rdev = |source: &str| match source {
        "/dev/nvme0n1p3" => Some((259 << 8) | 3),
        _ => None,
    };
    // ext4: the directory's own device is counted.
    let ext4 = resolve_device(
        Path::new("/var/store"),
        (259 << 8) | 2,
        stats,
        MOUNTINFO,
        rdev,
    );
    assert_eq!(
        ext4,
        Some(Device {
            major: 259,
            minor: 2
        })
    );
    // btrfs: an anonymous device; its mount source is the disk.
    let btrfs = resolve_device(Path::new("/home/me/store"), 45, stats, MOUNTINFO, rdev);
    assert_eq!(
        btrfs,
        Some(Device {
            major: 259,
            minor: 3
        })
    );
    // zfs, or no mount information: unresolved.
    assert_eq!(
        resolve_device(Path::new("/tank/store"), 47, stats, MOUNTINFO, rdev),
        None
    );
    assert_eq!(
        resolve_device(Path::new("/home/me/store"), 45, stats, "", rdev),
        None
    );
    assert_eq!(
        resolve_device(Path::new("/var/store"), (259 << 8) | 2, "", MOUNTINFO, rdev),
        None
    );
}

fn latency(p50: u64, p99: u64) -> Option<ReadLatency> {
    Some(ReadLatency {
        reads: 60,
        p50: ms_n(p50),
        p99: ms_n(p99),
        max: ms_n(p99),
    })
}

fn disk(reads: u64, read_ms: u64, writes: u64, write_ms: u64) -> Option<DiskAwait> {
    Some(DiskAwait {
        reads,
        writes,
        read_await: (reads > 0).then(|| ms_n(read_ms)),
        write_await: (writes > 0).then(|| ms_n(write_ms)),
        busy_pct: 10,
    })
}

fn interval(
    canary: Option<ReadLatency>,
    pending: Option<Duration>,
    disk: Option<DiskAwait>,
) -> IoInterval {
    IoInterval {
        length: INTERVAL,
        canary,
        pending,
        disk,
    }
}

const fn ok() -> IoInterval {
    IoInterval {
        length: INTERVAL,
        canary: Some(ReadLatency {
            reads: 60,
            p50: Duration::from_micros(300),
            p99: Duration::from_millis(4),
            max: Duration::from_millis(4),
        }),
        pending: None,
        disk: None,
    }
}

fn slow() -> IoInterval {
    interval(latency(30, 400), None, None)
}

#[test]
fn each_threshold_marks_an_interval_slow() {
    assert_eq!(ok().slow_reason(), None);
    assert!(ok().measured());
    assert!(!interval(None, None, None).measured());
    assert_eq!(interval(latency(1, 49), None, None).slow_reason(), None);
    assert_eq!(
        interval(latency(1, 50), None, None).slow_reason(),
        Some(SlowReason::CanaryP99)
    );
    // A read still unfinished: slow even with no finished read.
    assert_eq!(interval(None, Some(999 * MS), None).slow_reason(), None);
    assert_eq!(
        interval(None, Some(ms_n(1000)), None).slow_reason(),
        Some(SlowReason::CanaryPending)
    );
    assert_eq!(
        interval(latency(1, 400), Some(ms_n(5000)), None).slow_reason(),
        Some(SlowReason::CanaryPending)
    );
    assert_eq!(
        interval(latency(1, 2), None, disk(20, 19, 0, 0)).slow_reason(),
        None
    );
    assert_eq!(
        interval(latency(1, 2), None, disk(20, 20, 0, 0)).slow_reason(),
        Some(SlowReason::DiskReadAwait)
    );
    // Too few operations for an await verdict.
    assert_eq!(
        interval(latency(1, 2), None, disk(19, 900, 19, 900)).slow_reason(),
        None
    );
    assert_eq!(
        interval(latency(1, 2), None, disk(0, 0, 50, 99)).slow_reason(),
        None
    );
    assert_eq!(
        interval(latency(1, 2), None, disk(0, 0, 50, 100)).slow_reason(),
        Some(SlowReason::DiskWriteAwait)
    );
    // The disk alone measures an interval (no canary, e.g. a closed store).
    assert_eq!(
        interval(None, None, disk(30, 25, 0, 0)).slow_reason(),
        Some(SlowReason::DiskReadAwait)
    );
}

/// Summary lines: the first interval, then every 10 minutes.
#[test]
fn a_healthy_store_logs_one_summary_every_ten_minutes() {
    let t0 = Instant::now();
    let mut watch = IoWatch::default();
    assert_eq!(watch.observe(&ok(), t0), IoAction::Summary);
    for minute in 1..10 {
        assert_eq!(watch.observe(&ok(), t0 + INTERVAL * minute), IoAction::None);
    }
    assert_eq!(watch.observe(&ok(), t0 + INTERVAL * 10), IoAction::Summary);
    // Unmeasured intervals keep the cadence.
    assert_eq!(
        watch.observe(&interval(None, None, None), t0 + INTERVAL * 11),
        IoAction::None
    );
    assert_eq!(
        watch.observe(&interval(None, None, None), t0 + INTERVAL * 20),
        IoAction::Summary
    );
    assert_eq!(watch.slow_since(), None);
}

/// Start after two slow intervals in a row (not one), repeats every 10
/// minutes with the episode's duration, ends after three good intervals in
/// a row with the duration up to the first of them.
#[test]
fn a_slow_episode_starts_repeats_and_ends() {
    let t0 = Instant::now();
    let at = |minute: u32| t0 + INTERVAL * minute;
    let mut watch = IoWatch::default();
    assert_eq!(watch.observe(&ok(), at(0)), IoAction::Summary);
    // One slow interval alone starts nothing.
    assert_eq!(watch.observe(&slow(), at(1)), IoAction::None);
    assert_eq!(watch.observe(&ok(), at(2)), IoAction::None);
    assert_eq!(watch.slow_since(), None);
    assert_eq!(watch.observe(&slow(), at(3)), IoAction::None);
    assert_eq!(
        watch.observe(&slow(), at(4)),
        IoAction::SlowStart {
            slow: INTERVAL * 2,
            reason: SlowReason::CanaryP99
        }
    );
    assert_eq!(watch.slow_since(), Some(at(2)));
    for minute in 5..14 {
        assert_eq!(
            watch.observe(&slow(), at(minute)),
            IoAction::None,
            "minute {minute}"
        );
    }
    // No summary while slow, even when one would be due.
    assert_eq!(
        watch.observe(&interval(None, None, None), at(13)),
        IoAction::None
    );
    assert_eq!(
        watch.observe(&interval(None, Some(ms_n(90_000)), None), at(14)),
        IoAction::SlowRepeat {
            slow: INTERVAL * 12,
            reason: SlowReason::CanaryPending
        }
    );
    // Two good intervals, a slow one: still slow, the good run restarts.
    assert_eq!(watch.observe(&ok(), at(15)), IoAction::None);
    assert_eq!(watch.observe(&ok(), at(16)), IoAction::None);
    assert_eq!(watch.observe(&slow(), at(17)), IoAction::None);
    assert_eq!(watch.slow_since(), Some(at(2)));
    assert_eq!(watch.observe(&ok(), at(18)), IoAction::None);
    assert_eq!(watch.observe(&ok(), at(19)), IoAction::None);
    // Unmeasured intervals do not end it.
    assert_eq!(
        watch.observe(&interval(None, None, None), at(20)),
        IoAction::None
    );
    assert_eq!(watch.slow_since(), Some(at(2)));
    assert_eq!(
        watch.observe(&ok(), at(21)),
        IoAction::SlowEnd {
            slow: INTERVAL * 15
        }
    );
    assert_eq!(watch.slow_since(), None);
    // The end line restarts the summary cadence.
    assert_eq!(watch.observe(&ok(), at(22)), IoAction::None);
    assert_eq!(watch.observe(&ok(), at(31)), IoAction::Summary);
}

#[test]
fn the_report_carries_the_latest_interval_and_verdict() {
    let report = StoreIoReport {
        interval: interval(latency(3, 120), Some(ms_n(1500)), disk(40, 25, 0, 0)),
        slow_for: Some(Duration::from_secs(185)),
        ended_unix_ms: 1_700_000_000_000,
    };
    let health = report.to_proto();
    assert_eq!(health.verdict(), StoreIoVerdict::Slow);
    assert_eq!(health.slow_reason(), StoreIoReason::CanaryPending);
    assert_eq!(health.slow_secs, 185);
    assert_eq!(
        (health.interval_secs, health.ended_unix_ms),
        (60, 1_700_000_000_000)
    );
    assert_eq!(
        (
            health.canary_reads,
            health.canary_p50_us,
            health.canary_p99_us,
            health.canary_max_us,
            health.canary_pending_us
        ),
        (60, 3_000, 120_000, 120_000, 1_500_000)
    );
    assert_eq!(
        (
            health.disk_reads,
            health.disk_writes,
            health.disk_read_await_us,
            health.disk_write_await_us,
            health.disk_busy_pct
        ),
        (Some(40), Some(0), Some(25_000), None, Some(10))
    );
    // A slow interval before an episode starts still reads OK.
    let first = StoreIoReport {
        interval: slow(),
        slow_for: None,
        ended_unix_ms: 1,
    }
    .to_proto();
    assert_eq!(
        (first.verdict(), first.slow_reason(), first.slow_secs),
        (StoreIoVerdict::Ok, StoreIoReason::CanaryP99, 0)
    );
    // No disk: its fields stay unset. Nothing measured: unspecified.
    let bare = StoreIoReport {
        interval: interval(None, None, None),
        slow_for: None,
        ended_unix_ms: 1,
    }
    .to_proto();
    assert_eq!(bare.verdict(), StoreIoVerdict::Unspecified);
    assert_eq!(
        (bare.disk_reads, bare.disk_read_await_us, bare.disk_busy_pct),
        (None, None, None)
    );
}

#[test]
fn lines_say_whose_problem_and_what_to_check() {
    let subject = Subject {
        store: "master",
        disk: Some("nvme0n1p2".into()),
    };
    let t0 = Instant::now();
    let latest = interval(latency(30, 400), None, disk(40, 25, 10, 3));
    let mut window = Window::new(t0, None);
    let start = logged(|| {
        log_action(
            &subject,
            IoAction::SlowStart {
                slow: INTERVAL * 2,
                reason: SlowReason::CanaryP99,
            },
            &latest,
            &mut window,
            t0,
            None,
        )
    });
    assert!(start.contains("WARN"), "{start}");
    for text in [
        "store reads slow",
        "This node's disk is the cause",
        "TRIM",
        "SMART",
        "other I/O load",
        "Repeats every 10 minutes",
        "reason=\"canary_p99\"",
        "slow_secs=120",
        "canary_p99_ms=\"400.0\"",
        "disk=\"nvme0n1p2\"",
        "disk_read_await_ms=\"25.0\"",
        "disk_reads=40",
    ] {
        assert!(start.contains(text), "{text} missing: {start}");
    }
    let end = logged(|| {
        log_action(
            &subject,
            IoAction::SlowEnd {
                slow: INTERVAL * 15,
            },
            &ok(),
            &mut window,
            t0,
            None,
        )
    });
    assert!(
        end.contains("INFO") && end.contains("store reads recovered"),
        "{end}"
    );
    assert!(end.contains("slow_secs=900"), "{end}");
    let mut window = Window::new(t0, None);
    window.samples = (1..=600).map(|n| Duration::from_micros(n * 10)).collect();
    window.intervals = 10;
    let summary = logged(|| {
        log_action(
            &subject,
            IoAction::Summary,
            &ok(),
            &mut window,
            t0 + SUMMARY_EVERY,
            None,
        )
    });
    for text in [
        "INFO",
        "store i/o summary",
        "window_secs=600",
        "intervals=10",
        "slow_intervals=0",
        "canary_reads=600",
        "canary_p50_ms=\"3.0\"",
        "canary_p99_ms=\"5.9\"",
        "canary_max_ms=\"6.0\"",
    ] {
        assert!(summary.contains(text), "{text} missing: {summary}");
    }
    assert!(!summary.contains("disk_read_await_ms"), "{summary}");
    assert!(
        logged(|| log_action(&subject, IoAction::None, &ok(), &mut window, t0, None)).is_empty()
    );
}

#[test]
fn seek_targets_fall_in_the_files_range() {
    for r in [0u64, 1, 7, 255, 256, 0xdead_beef, u64::MAX] {
        let target = seek_target(&[1, 2, 3, 10], &[1, 2, 3, 20], r);
        assert_eq!(&target[..3], &[1, 2, 3]);
        assert!((10..=20).contains(&target[3]), "{target:?}");
        assert_eq!(target.len(), 4 + 8);
    }
    assert_eq!(seek_target(b"same", b"same", 9), b"same".to_vec());
    // The start is a prefix of the end.
    let target = seek_target(&[5], &[5, 9, 9], 3);
    assert_eq!(target[0], 5);
    assert!(target[1] <= 9);
}

#[test]
fn files_are_picked_by_size() {
    let file = |weight_end: u64, tag: u8| TableFile {
        weight_end,
        start: vec![tag],
        end: vec![tag],
    };
    let files = [file(10, 1), file(11, 2), file(100, 3)];
    let tag = |r: u64| pick(&files, r).unwrap().start[0];
    assert_eq!(
        (tag(0), tag(9), tag(10), tag(11), tag(99), tag(100)),
        (1, 1, 2, 3, 3, 1)
    );
    assert!(pick(&[], 5).is_none());
}

fn store(dir: &Path, keys: u32) -> CoordinatedDb {
    let db = CoordinatedDb::new(rocksdb::DB::open_default(dir).unwrap());
    for key in 0..keys {
        let key = (key.wrapping_mul(2_654_435_761)).to_be_bytes();
        db.put(key, [7u8; 100]).unwrap();
    }
    db.flush().unwrap();
    db
}

/// The canary reads table files of the store: most seeks land on an entry.
#[test]
fn canary_reads_land_on_the_stores_entries() {
    let dir = tempfile::tempdir().unwrap();
    let empty = CoordinatedDb::new(rocksdb::DB::open_default(dir.path().join("empty")).unwrap());
    assert!(table_files(&empty).is_empty());
    assert!(!canary_read(&empty, &[], 3));
    empty.put(b"k", b"v").unwrap();
    assert!(
        canary_read(&empty, &[], 3),
        "memtable only: the first entry"
    );
    let db = store(&dir.path().join("full"), 5000);
    let files = table_files(&db);
    assert!(!files.is_empty());
    let mut rng = 12345u64;
    let landed = (0..200)
        .filter(|_| canary_read(&db, &files, next_random(&mut rng)))
        .count();
    assert!(landed >= 150, "{landed} of 200 seeks landed");
}

fn wait_for(deadline: Duration, mut done: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    done()
}

/// The threads publish intervals with canary reads, and stop, keeping the
/// store open no longer, once its other owners drop it.
#[test]
fn the_watch_publishes_intervals_and_stops_with_its_store() {
    let dir = tempfile::tempdir().unwrap();
    let db = store(dir.path(), 2000);
    let published = Published::default();
    assert!(spawn_watch(
        &db,
        "test",
        Duration::from_millis(5),
        Duration::from_millis(100),
        published.clone()
    ));
    assert!(
        wait_for(Duration::from_secs(20), || read_published(&published)
            .is_some_and(|r| r.interval.canary.is_some_and(|c| c.reads > 0))),
        "no interval with canary reads"
    );
    let report = read_published(&published).unwrap();
    assert!(report.interval.measured());
    assert!(report.ended_unix_ms > 0);
    let weak = db.downgrade();
    drop(db);
    assert!(
        wait_for(Duration::from_secs(20), || weak.upgrade().is_none()),
        "the canary keeps the store open"
    );
    assert!(
        wait_for(Duration::from_secs(20), || read_published(&published)
            .is_none()),
        "the summary thread kept publishing after its store closed"
    );
}

/// Off Linux, or for a directory the kernel counts no device under, the
/// store has no disk figures; never a panic.
#[test]
fn an_unresolved_store_device_is_absent() {
    let missing = PathBuf::from("/nonexistent/store/dir");
    assert_eq!(store_device(&missing), None);
    assert_eq!(disk_counters(None), None);
}
