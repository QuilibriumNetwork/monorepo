//! Tells a slow disk from lock contention, in warn-level lines a log request
//! returns. Slow stores and long lock waits look alike from the threads they
//! block, and a warn-only export carried neither an I/O metric nor a write time.
//!
//! Each minute it samples a small fsync on the store's disk, the kernel's
//! pressure stall figures and how long the node's store writes took; one info
//! line carries them, and a warn line, at most every
//! [`WARN_EVERY`], only when one is past its bound.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quil_forest::WriteTimesSample;
use tracing::{info, warn};

/// A 4 KiB write and fsync past this costs this node certificate signatures.
/// A frame's two votes wait on about eight fsyncs in series: the proposal's
/// sealed body (file, directory), the view's new consensus journal file (file,
/// directory, header) and the journal sync before the notarize vote, then two
/// journal syncs before the finalize vote. Past this they take most of a second
/// of a ~10 s frame, while members on disks syncing in 2-4 ms spend tens of
/// milliseconds; an operator's node syncing in about 1 s signed half its
/// certificates, and nearly all of them on a faster disk (2026-11).
const FSYNC_BOUND_MS: u64 = 100;
/// A store write past this outlasts most of a worker thread's 6 s budget.
const WRITE_BOUND_MS: u64 = 5000;
/// A wait for a store's write barrier past this is contention worth naming.
const BARRIER_BOUND_MS: u64 = 5000;
/// Share of the last minute all tasks stalled on I/O. Full stall means nothing
/// else on the host could run meanwhile.
const IO_FULL_BOUND: f32 = 20.0;
/// Pending compaction past this leaves point reads searching many levels: a
/// quarter of RocksDB's default soft limit, so it warns well before a stall.
const PENDING_COMPACTION_BOUND_MB: u64 = 16 * 1024;
/// How long the fsync probe may take before it counts as this long.
const FSYNC_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a store past its bounds warns.
const WARN_EVERY: Duration = Duration::from_secs(10 * 60);

/// The kernel's pressure stall figures, percent of the last minute. `None`
/// where this kernel has none.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(super) struct Pressure {
    pub io_some: Option<f32>,
    pub io_full: Option<f32>,
    pub cpu_some: Option<f32>,
    pub memory_full: Option<f32>,
}

impl Pressure {
    pub(super) fn read() -> Self {
        let file = |name: &str| std::fs::read_to_string(format!("/proc/pressure/{name}")).ok();
        let (io, cpu, memory) = (file("io"), file("cpu"), file("memory"));
        Self {
            io_some: io.as_deref().and_then(|text| avg60(text, "some")),
            io_full: io.as_deref().and_then(|text| avg60(text, "full")),
            cpu_some: cpu.as_deref().and_then(|text| avg60(text, "some")),
            memory_full: memory.as_deref().and_then(|text| avg60(text, "full")),
        }
    }
}

/// `avg60` of the `kind` line of a `/proc/pressure` file; `None` when absent
/// or malformed.
fn avg60(text: &str, kind: &str) -> Option<f32> {
    text.lines()
        .find(|line| line.split_whitespace().next() == Some(kind))?
        .split_whitespace()
        .find_map(|field| field.strip_prefix("avg60="))?
        .parse()
        .ok()
        .filter(|value: &f32| value.is_finite())
}

/// A small fsync on the store's disk, run off the runtime's threads; one at a
/// time, so a disk that hangs costs one thread.
pub(super) struct FsyncProbe {
    file: PathBuf,
    running: Arc<AtomicBool>,
}

impl FsyncProbe {
    pub(super) fn new(store: &Path) -> Self {
        Self {
            file: store.join(".latency-probe"),
            running: Arc::default(),
        }
    }

    /// The probe's milliseconds: past the timeout, the timeout's; `None` when
    /// it could not run, or the last one has not returned.
    pub(super) async fn measure(&self) -> Option<u64> {
        if self.running.swap(true, Ordering::AcqRel) {
            return Some(FSYNC_TIMEOUT.as_millis() as u64);
        }
        let (file, running) = (self.file.clone(), self.running.clone());
        let probe = tokio::task::spawn_blocking(move || {
            let took = fsync_once(&file);
            running.store(false, Ordering::Release);
            took
        });
        match tokio::time::timeout(FSYNC_TIMEOUT, probe).await {
            Ok(Ok(took)) => took.map(|took| took.as_millis() as u64),
            Ok(Err(_)) => None,
            Err(_) => Some(FSYNC_TIMEOUT.as_millis() as u64),
        }
    }
}

fn fsync_once(path: &Path) -> Option<Duration> {
    use std::io::Write;
    let started = Instant::now();
    let mut file = std::fs::File::create(path).ok()?;
    file.write_all(&[0u8; 4096]).ok()?;
    file.sync_all().ok()?;
    let took = started.elapsed();
    let _ = std::fs::remove_file(path);
    Some(took)
}

/// One minute's figures.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Sample {
    pub fsync_ms: Option<u64>,
    pub pressure: Pressure,
    /// The master's store.
    pub master: WriteTimesSample,
    /// Every store of this process, workers' too.
    pub all_stores: WriteTimesSample,
    pub pending_compaction_mb: u64,
    pub level0_files: u64,
    pub write_stopped: bool,
}

/// Whose problem a sample past its bounds points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reading {
    /// The disk itself: its fsync or the kernel's I/O stall.
    Disk,
    /// The disk answers quickly but writes queue for a store's barrier.
    Contention,
    /// Compaction is behind, or stopped writes.
    Compaction,
    /// Writes are slow with a quick disk and no queue.
    SlowWrites,
}

impl Reading {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disk => "disk",
            Self::Contention => "write barrier contention",
            Self::Compaction => "compaction behind",
            Self::SlowWrites => "slow store writes on a responsive disk",
        }
    }

    fn action(self) -> &'static str {
        match self {
            Self::Disk => "this node's disk is slow enough to delay its votes: check it with iostat and what else uses it; a DRAM-less drive under load, storage label writes included, is a common cause; move the store to a drive with a DRAM cache, or run fewer seats",
            Self::Contention => "the disk answers quickly while writers queue for one store: report this line with any 'GLOBAL frame writer lock held for seconds' line",
            Self::Compaction => "the store's compaction is behind its writes, which slows every read: check the disk's throughput; report this line if the disk is idle",
            Self::SlowWrites => "report this line with its 'worker thread blocked' lines",
        }
    }
}

impl Sample {
    /// What this sample points at, when past a bound. The disk's own figures
    /// come first: a saturated disk also makes writes slow and queue.
    pub(super) fn reading(&self) -> Option<Reading> {
        let write = self.master.max_write_ms.max(self.all_stores.max_write_ms);
        let barrier = self
            .master
            .max_barrier_wait_ms
            .max(self.all_stores.max_barrier_wait_ms);
        if self.fsync_ms.is_some_and(|ms| ms >= FSYNC_BOUND_MS)
            || self.pressure.io_full.is_some_and(|p| p >= IO_FULL_BOUND)
        {
            Some(Reading::Disk)
        } else if self.write_stopped || self.pending_compaction_mb >= PENDING_COMPACTION_BOUND_MB {
            Some(Reading::Compaction)
        } else if barrier >= BARRIER_BOUND_MS {
            Some(Reading::Contention)
        } else if write >= WRITE_BOUND_MS {
            Some(Reading::SlowWrites)
        } else {
            None
        }
    }
}

/// What the last samples warned of.
#[derive(Default)]
pub(super) struct StoreLatency {
    warned: Option<Instant>,
    /// Past a bound since the last clear sample.
    past: bool,
}

impl StoreLatency {
    pub(super) fn observe(&mut self, sample: Sample) {
        let reading = sample.reading();
        self.observe_at(sample, reading, Instant::now());
    }

    fn observe_at(&mut self, sample: Sample, reading: Option<Reading>, now: Instant) -> Logged {
        let Sample {
            fsync_ms,
            pressure,
            master,
            all_stores,
            pending_compaction_mb,
            level0_files,
            write_stopped,
        } = sample;
        let fsync = fsync_ms.map_or_else(|| "unavailable".to_string(), |ms| ms.to_string());
        let percent =
            |p: Option<f32>| p.map_or_else(|| "unavailable".to_string(), |p| format!("{p:.1}"));
        info!(fsync_probe_ms = %fsync, io_some_pct = %percent(pressure.io_some),
            io_full_pct = %percent(pressure.io_full), cpu_some_pct = %percent(pressure.cpu_some),
            memory_full_pct = %percent(pressure.memory_full),
            writes = master.writes, write_ms = master.write_ms, max_write_ms = master.max_write_ms,
            max_barrier_wait_ms = master.max_barrier_wait_ms,
            max_barrier_hold_ms = master.max_barrier_hold_ms,
            all_writes = all_stores.writes, all_write_ms = all_stores.write_ms,
            all_max_write_ms = all_stores.max_write_ms,
            all_max_barrier_wait_ms = all_stores.max_barrier_wait_ms,
            all_max_barrier_hold_ms = all_stores.max_barrier_hold_ms,
            "store latency");
        let Some(reading) = reading else {
            let ended = std::mem::take(&mut self.past);
            if ended {
                info!(fsync_probe_ms = %fsync, "store latency back within its bounds");
            }
            return if ended {
                Logged::Ended
            } else {
                Logged::Nothing
            };
        };
        self.past = true;
        if self
            .warned
            .is_some_and(|warned| now.saturating_duration_since(warned) < WARN_EVERY)
        {
            return Logged::Nothing;
        }
        self.warned = Some(now);
        warn!(reading = reading.as_str(), fsync_probe_ms = %fsync,
            io_some_pct = %percent(pressure.io_some), io_full_pct = %percent(pressure.io_full),
            cpu_some_pct = %percent(pressure.cpu_some), memory_full_pct = %percent(pressure.memory_full),
            max_write_ms = master.max_write_ms, max_barrier_wait_ms = master.max_barrier_wait_ms,
            max_barrier_hold_ms = master.max_barrier_hold_ms, all_max_write_ms = all_stores.max_write_ms,
            all_max_barrier_wait_ms = all_stores.max_barrier_wait_ms,
            pending_compaction_mb, level0_files, write_stopped,
            fsync_bound_ms = FSYNC_BOUND_MS, write_bound_ms = WRITE_BOUND_MS, io_full_bound_pct = IO_FULL_BOUND,
            scope = "this node", action = reading.action(),
            "store latency past its bound");
        Logged::Warned
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Logged {
    Nothing,
    Warned,
    Ended,
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = "some avg10=1.36 avg60=1.61 avg300=2.24 total=56790384188\n\
                        full avg10=0.00 avg60=0.12 avg300=0.23 total=9389564507\n";

    #[test]
    fn pressure_lines_parse_and_malformed_ones_give_nothing() {
        assert_eq!(avg60(REAL, "some"), Some(1.61));
        assert_eq!(avg60(REAL, "full"), Some(0.12));
        for bad in [
            "",
            "garbage",
            "some avg10=1.0",
            "some avg60=x total=1",
            "some avg60=NaN",
            "full avg60=1.0",
        ] {
            assert_eq!(avg60(bad, "some"), None, "{bad}");
        }
    }

    fn writes(max_write_ms: u64, max_barrier_wait_ms: u64) -> WriteTimesSample {
        WriteTimesSample {
            max_write_ms,
            max_barrier_wait_ms,
            ..Default::default()
        }
    }

    /// Each kind of slowness reads as its own, the disk's figures first; at
    /// the bound it counts, below it nothing does.
    #[test]
    fn a_sample_reads_as_the_problem_it_shows() {
        let quick = Sample {
            fsync_ms: Some(5),
            ..Default::default()
        };
        assert_eq!(quick.reading(), None);
        let cases = [
            (
                Sample {
                    fsync_ms: Some(FSYNC_BOUND_MS),
                    ..quick
                },
                Reading::Disk,
            ),
            (
                Sample {
                    pressure: Pressure {
                        io_full: Some(IO_FULL_BOUND),
                        ..Default::default()
                    },
                    ..quick
                },
                Reading::Disk,
            ),
            (
                Sample {
                    fsync_ms: Some(FSYNC_BOUND_MS),
                    master: writes(60_000, 60_000),
                    ..quick
                },
                Reading::Disk,
            ),
            (
                Sample {
                    master: writes(0, BARRIER_BOUND_MS),
                    ..quick
                },
                Reading::Contention,
            ),
            (
                Sample {
                    all_stores: writes(0, BARRIER_BOUND_MS),
                    ..quick
                },
                Reading::Contention,
            ),
            (
                Sample {
                    master: writes(WRITE_BOUND_MS, 0),
                    ..quick
                },
                Reading::SlowWrites,
            ),
            (
                Sample {
                    all_stores: writes(WRITE_BOUND_MS, 0),
                    ..quick
                },
                Reading::SlowWrites,
            ),
            (
                Sample {
                    pending_compaction_mb: PENDING_COMPACTION_BOUND_MB,
                    ..quick
                },
                Reading::Compaction,
            ),
            (
                Sample {
                    write_stopped: true,
                    ..quick
                },
                Reading::Compaction,
            ),
        ];
        for (sample, reading) in cases {
            assert_eq!(sample.reading(), Some(reading), "{sample:?}");
        }
        assert_eq!(
            Sample {
                master: writes(WRITE_BOUND_MS - 1, BARRIER_BOUND_MS - 1),
                ..quick
            }
            .reading(),
            None
        );
        assert_eq!(
            Sample::default().reading(),
            None,
            "nothing known, nothing claimed"
        );
    }

    /// A probe at the bound warns and one a millisecond under it does not: at
    /// 100 ms, not 1 s, a frame's eight vote-path fsyncs stay within a tenth of
    /// the frame.
    #[test]
    fn a_probe_at_the_signing_bound_warns_and_one_below_does_not() {
        let at = Sample {
            fsync_ms: Some(100),
            ..Default::default()
        };
        let below = Sample {
            fsync_ms: Some(99),
            ..Default::default()
        };
        let now = Instant::now();
        assert_eq!(
            StoreLatency::default().observe_at(at, at.reading(), now),
            Logged::Warned,
            "fsync_at_bound_did_not_warn"
        );
        assert_eq!(
            StoreLatency::default().observe_at(below, below.reading(), now),
            Logged::Nothing,
            "fsync_below_bound_warned"
        );
    }

    /// The first past its bound warns, then at most every interval however
    /// long it lasts; its end is said once.
    #[test]
    fn warnings_are_bounded_and_their_end_is_said() {
        let mut latency = StoreLatency::default();
        let start = Instant::now();
        let past = Some(Reading::Disk);
        let at = |secs| start + Duration::from_secs(secs);
        let sample = Sample::default();
        assert_eq!(latency.observe_at(sample, None, at(0)), Logged::Nothing);
        assert_eq!(latency.observe_at(sample, past, at(60)), Logged::Warned);
        assert_eq!(latency.observe_at(sample, past, at(120)), Logged::Nothing);
        assert_eq!(latency.observe_at(sample, None, at(180)), Logged::Ended);
        assert_eq!(latency.observe_at(sample, None, at(240)), Logged::Nothing);
        assert_eq!(latency.observe_at(sample, past, at(300)), Logged::Nothing);
        assert_eq!(latency.observe_at(sample, past, at(660)), Logged::Warned);
    }

    /// The probe measures a real fsync, leaves no file behind, and says so
    /// when it cannot run.
    #[tokio::test]
    async fn the_probe_measures_and_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let probe = FsyncProbe::new(dir.path());
        assert!(probe.measure().await.is_some());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let gone = FsyncProbe::new(&dir.path().join("no-such-directory"));
        assert_eq!(gone.measure().await, None);
    }
}
