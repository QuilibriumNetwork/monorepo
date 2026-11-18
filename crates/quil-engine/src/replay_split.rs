//! What an archive recovery's local replay spent its time on, for its batch
//! line ("archive recovery batch complete"), so that a node whose seats wait
//! on their recoveries shows whose problem the wait is.
//!
//! The parts of a turn's `replay_ms`, none of them taking a lock:
//! - `global_sync_wait_ms`: refused requests while this node's GLOBAL state
//!   sync installs, and the polls between them.
//! - `engine_queue_ms`: the request queued behind the shard engine's other
//!   messages.
//! - `prepare_ms`: GLOBAL anchors, the historical committee and storage
//!   history a frame's validation needs, which may wait on other work or peers.
//! - `preverify_ms`: the frame's proofs, verified on helper threads.
//! - `store_write_ms`: this worker's store writes.
//! - `store_wait_ms`: the materializing thread off CPU while it executes,
//!   other than in a write and not waiting for a CPU.
//! - `commit_wait_ms`: the same during the frame's commit, which also waits for
//!   helper threads computing its tree commitments.
//! - `cpu_ms`: the materializing thread on CPU; a virtual machine's stolen
//!   time counts here.
//! - `run_wait_ms`: that thread runnable, waiting for a CPU.
//! - `other_ms`: what is left, on the engine's own thread: frame validation,
//!   pre-state roots and the wait for a blocking thread.
//!
//! Store reads are not timed. Execution reads through dozens of point-read and
//! iterator call sites, and a raw iterator's steps have no call to put a timer
//! around, so `store_wait_ms` stands in for them; it also holds any lock wait
//! on that thread. Slow-disk lines ("store reads slow") and `iostat` tell the
//! two apart. Around each step of a frame the thread's CPU time comes from its
//! CPU clock and its run-queue time from one small read of
//! `/proc/thread-self/schedstat`; where that is unavailable those parts are
//! absent from the line and their time falls to `other_ms`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// A turn replays slowly at this much time per frame, on average. Regular
/// replays take about 10 ms a frame (median of 12 batches of 8 frames or more
/// on one regular node, 2026-11-05, longest 1,060 ms); a node whose seats
/// stayed blocked took about 2,300 ms.
pub(crate) const SLOW_REPLAY_PER_FRAME: Duration = Duration::from_secs(1);

/// Fewer frames in a turn say nothing about its replay's pace.
pub(crate) const SLOW_REPLAY_MIN_FRAMES: u64 = 8;

/// How often slow replays warn again while they continue.
const SLOW_REPLAY_REPEAT: Duration = Duration::from_secs(10 * 60);

fn micros(took: Duration) -> u64 {
    took.as_micros().min(u128::from(u64::MAX)) as u64
}

/// This thread's scheduler counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreadTimes {
    on_cpu: Duration,
    run_wait: Duration,
}

impl ThreadTimes {
    /// The on-CPU counter in schedstat advances only at a scheduler tick or a
    /// switch, so it can miss up to a tick of the CPU time before a read; the
    /// thread's CPU clock brings it up to date as it reads. The run-queue wait
    /// grows only while the thread waits, so it is current while it runs.
    fn now() -> Option<Self> {
        let times = Self::parse(&std::fs::read_to_string("/proc/thread-self/schedstat").ok()?)?;
        Some(Self {
            on_cpu: thread_cpu_time()?,
            ..times
        })
    }

    /// `<on-CPU ns> <run-queue wait ns> <timeslices>`. A kernel keeping no
    /// scheduler statistics reports zeros. A running thread has had a
    /// timeslice, but a new one may show no time on CPU: the counter catches
    /// up only at a scheduler tick or a switch.
    fn parse(text: &str) -> Option<Self> {
        let mut fields = text.split_ascii_whitespace();
        let on_cpu: u64 = fields.next()?.parse().ok()?;
        let run_wait: u64 = fields.next()?.parse().ok()?;
        let timeslices: u64 = fields.next()?.parse().ok()?;
        (fields.next().is_none() && timeslices > 0).then(|| Self {
            on_cpu: Duration::from_nanos(on_cpu),
            run_wait: Duration::from_nanos(run_wait),
        })
    }

    fn since(self, earlier: Self) -> Self {
        Self {
            on_cpu: self.on_cpu.saturating_sub(earlier.on_cpu),
            run_wait: self.run_wait.saturating_sub(earlier.run_wait),
        }
    }
}

/// This thread's CPU time, from its CPU clock.
#[cfg(target_os = "linux")]
fn thread_cpu_time() -> Option<Duration> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes only the timespec it is given.
    let read = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now) };
    if read != 0 {
        return None;
    }
    Some(Duration::new(
        u64::try_from(now.tv_sec).ok()?,
        u32::try_from(now.tv_nsec).ok()?,
    ))
}

#[cfg(not(target_os = "linux"))]
fn thread_cpu_time() -> Option<Duration> {
    None
}

/// One step of a frame's materialization, on the thread that ran it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreadStep {
    wall: Duration,
    store_write: Duration,
    times: Option<ThreadTimes>,
}

impl ThreadStep {
    /// Off CPU and not waiting for one, other than in a store write. Part of
    /// a write runs on CPU, so this is short of the truth by that much.
    fn waited(&self) -> Option<Duration> {
        self.times.map(|times| {
            self.wall
                .saturating_sub(times.on_cpu)
                .saturating_sub(times.run_wait)
                .saturating_sub(self.store_write)
        })
    }
}

/// Times a [`ThreadStep`]; it ends on the thread it started on.
pub(crate) struct ThreadStepTimer {
    started: Instant,
    store_write: Duration,
    times: Option<ThreadTimes>,
}

impl ThreadStepTimer {
    /// The wall clock starts first and stops last, so that the counters'
    /// window, their reads' cost included, nests inside the wall's.
    pub(crate) fn start() -> Self {
        Self {
            started: Instant::now(),
            store_write: quil_forest::thread_store_write_time(),
            times: ThreadTimes::now(),
        }
    }

    pub(crate) fn end(self) -> ThreadStep {
        let times = self
            .times
            .zip(ThreadTimes::now())
            .map(|(before, after)| after.since(before));
        let store_write = quil_forest::thread_store_write_time().saturating_sub(self.store_write);
        ThreadStep {
            wall: self.started.elapsed(),
            store_write,
            times,
        }
    }
}

/// Microseconds of an engine's replays, by what they went to.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayCosts {
    /// The engine handling replay requests, every part below included.
    pub(crate) engine_us: u64,
    pub(crate) prepare_us: u64,
    pub(crate) preverify_us: u64,
    pub(crate) store_write_us: u64,
    pub(crate) store_wait_us: u64,
    pub(crate) commit_wait_us: u64,
    pub(crate) cpu_us: u64,
    pub(crate) run_wait_us: u64,
    /// Materialized frames whose thread times were read.
    pub(crate) sampled_frames: u64,
}

const REPLAY_COSTS: usize = 9;

impl ReplayCosts {
    pub(crate) fn engine(took: Duration) -> Self {
        Self {
            engine_us: micros(took),
            ..Self::default()
        }
    }

    pub(crate) fn prepare(took: Duration) -> Self {
        Self {
            prepare_us: micros(took),
            ..Self::default()
        }
    }

    pub(crate) fn store_write(took: Duration) -> Self {
        Self {
            store_write_us: micros(took),
            ..Self::default()
        }
    }

    /// A materialized frame: its proofs' time, its execution and its commit.
    pub(crate) fn materialized(
        preverify: Duration,
        execute: &ThreadStep,
        commit: &ThreadStep,
    ) -> Self {
        let on_thread = |part: fn(&ThreadTimes) -> Duration| {
            micros(
                [execute, commit]
                    .iter()
                    .filter_map(|step| step.times.as_ref())
                    .map(part)
                    .sum(),
            )
        };
        Self {
            preverify_us: micros(preverify),
            store_write_us: micros(execute.store_write + commit.store_write),
            store_wait_us: micros(execute.waited().unwrap_or_default()),
            commit_wait_us: micros(commit.waited().unwrap_or_default()),
            cpu_us: on_thread(|times| times.on_cpu),
            run_wait_us: on_thread(|times| times.run_wait),
            sampled_frames: u64::from(execute.times.is_some() && commit.times.is_some()),
            ..Self::default()
        }
    }

    fn to_array(self) -> [u64; REPLAY_COSTS] {
        [
            self.engine_us,
            self.prepare_us,
            self.preverify_us,
            self.store_write_us,
            self.store_wait_us,
            self.commit_wait_us,
            self.cpu_us,
            self.run_wait_us,
            self.sampled_frames,
        ]
    }

    fn from_array(costs: [u64; REPLAY_COSTS]) -> Self {
        let [engine_us, prepare_us, preverify_us, store_write_us, store_wait_us, commit_wait_us, cpu_us, run_wait_us, sampled_frames] =
            costs;
        Self {
            engine_us,
            prepare_us,
            preverify_us,
            store_write_us,
            store_wait_us,
            commit_wait_us,
            cpu_us,
            run_wait_us,
            sampled_frames,
        }
    }

    /// What was added after `before`. A request that timed out adds its cost
    /// late, to the turn that reads it next.
    pub(crate) fn since(self, before: Self) -> Self {
        let mut costs = self.to_array();
        for (cost, before) in costs.iter_mut().zip(before.to_array()) {
            *cost = cost.saturating_sub(before);
        }
        Self::from_array(costs)
    }
}

/// An engine's [`ReplayCosts`] so far, which its handle reads.
#[derive(Debug, Default)]
pub(crate) struct SharedReplayCosts {
    counters: [AtomicU64; REPLAY_COSTS],
}

impl SharedReplayCosts {
    pub(crate) fn add(&self, costs: &ReplayCosts) {
        for (counter, cost) in self.counters.iter().zip(costs.to_array()) {
            counter.fetch_add(cost, Ordering::Relaxed);
        }
    }

    pub(crate) fn read(&self) -> ReplayCosts {
        ReplayCosts::from_array(
            self.counters
                .each_ref()
                .map(|counter| counter.load(Ordering::Relaxed)),
        )
    }
}

/// A turn's `replay_ms` by part (this module's list). The parts add up to it,
/// but for the CPU part of a store write, which counts in both `store_write_ms`
/// and `cpu_ms`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplaySplit {
    pub(crate) global_sync_wait_ms: u64,
    pub(crate) engine_queue_ms: u64,
    pub(crate) prepare_ms: u64,
    pub(crate) preverify_ms: u64,
    pub(crate) store_write_ms: u64,
    pub(crate) store_wait_ms: Option<u64>,
    pub(crate) commit_wait_ms: Option<u64>,
    pub(crate) cpu_ms: Option<u64>,
    pub(crate) run_wait_ms: Option<u64>,
    pub(crate) other_ms: u64,
}

impl ReplaySplit {
    /// `replay_ms` went to `global_sync_wait_ms` of refused requests and to
    /// the requests the engine answered, which `costs` split.
    pub(crate) fn of(replay_ms: u64, global_sync_wait_ms: u64, costs: ReplayCosts) -> Self {
        let ms = |us: u64| us / 1000;
        let sampled = |us: u64| (costs.sampled_frames > 0).then_some(ms(us));
        let on_thread = costs
            .store_wait_us
            .saturating_add(costs.commit_wait_us)
            .saturating_add(costs.cpu_us)
            .saturating_add(costs.run_wait_us);
        Self {
            global_sync_wait_ms,
            engine_queue_ms: replay_ms
                .saturating_sub(global_sync_wait_ms)
                .saturating_sub(ms(costs.engine_us)),
            prepare_ms: ms(costs.prepare_us),
            preverify_ms: ms(costs.preverify_us),
            store_write_ms: ms(costs.store_write_us),
            store_wait_ms: sampled(costs.store_wait_us),
            commit_wait_ms: sampled(costs.commit_wait_us),
            cpu_ms: sampled(costs.cpu_us),
            run_wait_ms: sampled(costs.run_wait_us),
            other_ms: ms(costs
                .engine_us
                .saturating_sub(costs.prepare_us)
                .saturating_sub(costs.preverify_us)
                .saturating_sub(costs.store_write_us)
                .saturating_sub(on_thread)),
        }
    }

    /// The part that took longest, if any took time.
    pub(crate) fn mostly(&self) -> Option<ReplayPart> {
        [
            (ReplayPart::GlobalSync, self.global_sync_wait_ms),
            (ReplayPart::EngineBusy, self.engine_queue_ms),
            (ReplayPart::Prepare, self.prepare_ms),
            (ReplayPart::Proofs, self.preverify_ms),
            (ReplayPart::StoreWrites, self.store_write_ms),
            (ReplayPart::StoreReads, self.store_wait_ms.unwrap_or(0)),
            (ReplayPart::CommitWait, self.commit_wait_ms.unwrap_or(0)),
            (ReplayPart::Cpu, self.cpu_ms.unwrap_or(0)),
            (ReplayPart::CpuContention, self.run_wait_ms.unwrap_or(0)),
            (ReplayPart::Other, self.other_ms),
        ]
        .into_iter()
        .filter(|&(_, ms)| ms > 0)
        .max_by_key(|&(_, ms)| ms)
        .map(|(part, _)| part)
    }
}

/// A part of [`ReplaySplit`], as a line names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayPart {
    GlobalSync,
    EngineBusy,
    Prepare,
    Proofs,
    StoreWrites,
    StoreReads,
    CommitWait,
    Cpu,
    CpuContention,
    Other,
}

impl ReplayPart {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::GlobalSync => "global_sync",
            Self::EngineBusy => "engine_busy",
            Self::Prepare => "prepare",
            Self::Proofs => "proofs",
            Self::StoreWrites => "store_writes",
            Self::StoreReads => "store_reads",
            Self::CommitWait => "commit_wait",
            Self::Cpu => "cpu",
            Self::CpuContention => "cpu_contention",
            Self::Other => "validation",
        }
    }

    /// Whose problem it is, and what to check.
    pub(crate) fn guidance(self) -> (&'static str, &'static str) {
        match self {
            Self::GlobalSync => (
                "this node",
                "this node's master installs the GLOBAL prover tree from an archive, which \
                 withholds committed GLOBAL state; check how long its installs take",
            ),
            Self::EngineBusy => (
                "this node",
                "the shard engine answered its other messages first; check this worker's stall \
                 warnings; report it with this line if it persists",
            ),
            Self::Prepare => (
                "this node or its peers",
                "frames wait for GLOBAL anchors, historical committees or storage history; check \
                 that GLOBAL frames arrive and that peers are connected",
            ),
            Self::Proofs => (
                "this node's CPU",
                "the frames' proofs take this long to verify; check the host's free CPU and the \
                 proofWorker settings",
            ),
            Self::StoreWrites | Self::StoreReads => (
                "this node's disk",
                "check 'store reads slow' warnings, iostat -x while it catches up, that TRIM \
                 runs, and other I/O load on the same disk",
            ),
            Self::CommitWait => (
                "this node's CPU or disk",
                "frame commits wait for tree commitments on helper threads or for tree reads; \
                 check the host's free CPU, then iostat -x while it catches up",
            ),
            Self::Cpu => (
                "this node's CPU",
                "executing the frames takes this long on CPU; compare parallel_replays with the \
                 host's cores, and report it with this line if the host has CPU to spare",
            ),
            Self::CpuContention => (
                "this node's host",
                "replays wait for a CPU: too many workers or other load for the host's cores; \
                 check nproc, dataWorkerCount, load and any virtual machine's steal time",
            ),
            Self::Other => (
                "this node",
                "frame validation on the engine's thread takes this long; check the host's free \
                 CPU; report it with this line if the host has CPU to spare",
            ),
        }
    }
}

/// What a [`SlowReplays`] observation logs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SlowReplayLog {
    /// Slow turns for `duration`, `turns` of them since the last line.
    Slow { turns: u64, duration: Duration },
    /// A turn at pace, or with nobody waiting, after warned slow turns.
    Ended { duration: Duration },
}

/// Replays slow while workers wait for a turn, across this process's workers:
/// one warning, repeated at most every [`SLOW_REPLAY_REPEAT`], and one line
/// once they end.
#[derive(Debug)]
pub(crate) struct SlowReplays {
    since_ms: AtomicU64,
    warned_ms: AtomicU64,
    unreported: AtomicU64,
}

impl SlowReplays {
    pub(crate) const fn new() -> Self {
        Self {
            since_ms: AtomicU64::new(0),
            warned_ms: AtomicU64::new(0),
            unreported: AtomicU64::new(0),
        }
    }

    /// A turn of `frames` frames took `replay_ms` with `queue_len` waiting as
    /// it started. Too few frames say nothing. Two workers racing may shift a
    /// count to the next line; neither repeats one.
    pub(crate) fn observe(
        &self,
        frames: u64,
        replay_ms: u64,
        queue_len: u32,
        now_ms: u64,
    ) -> Option<SlowReplayLog> {
        if frames < SLOW_REPLAY_MIN_FRAMES {
            return None;
        }
        let slow = queue_len > 0
            && replay_ms >= frames.saturating_mul(SLOW_REPLAY_PER_FRAME.as_millis() as u64);
        if !slow {
            let warned = self.warned_ms.swap(0, Ordering::Relaxed);
            let since = self.since_ms.swap(0, Ordering::Relaxed);
            self.unreported.store(0, Ordering::Relaxed);
            return (warned != 0).then(|| SlowReplayLog::Ended {
                duration: Duration::from_millis(now_ms.saturating_sub(since)),
            });
        }
        let _ = self
            .since_ms
            .compare_exchange(0, now_ms, Ordering::Relaxed, Ordering::Relaxed);
        self.unreported.fetch_add(1, Ordering::Relaxed);
        let warned = self.warned_ms.load(Ordering::Relaxed);
        let repeat = SLOW_REPLAY_REPEAT.as_millis() as u64;
        if warned != 0 && now_ms < warned.saturating_add(repeat) {
            return None;
        }
        self.warned_ms
            .compare_exchange(warned, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .ok()?;
        let since = self.since_ms.load(Ordering::Relaxed);
        Some(SlowReplayLog::Slow {
            turns: self.unreported.swap(0, Ordering::Relaxed),
            duration: Duration::from_millis(now_ms.saturating_sub(since)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(wall: u64, on_cpu: u64, run_wait: u64, store_write: u64) -> ThreadStep {
        ThreadStep {
            wall: Duration::from_millis(wall),
            store_write: Duration::from_millis(store_write),
            times: Some(ThreadTimes {
                on_cpu: Duration::from_millis(on_cpu),
                run_wait: Duration::from_millis(run_wait),
            }),
        }
    }

    #[test]
    fn schedstat_parses_its_three_counters_and_refuses_anything_else() {
        assert_eq!(
            ThreadTimes::parse("1500000 2500000 7\n"),
            Some(ThreadTimes {
                on_cpu: Duration::from_micros(1500),
                run_wait: Duration::from_micros(2500),
            })
        );
        // A new thread before its first tick or switch.
        assert_eq!(
            ThreadTimes::parse("0 0 1\n"),
            Some(ThreadTimes {
                on_cpu: Duration::ZERO,
                run_wait: Duration::ZERO,
            })
        );
        for malformed in [
            "",
            "\n",
            "1500000",
            "1500000 2500000",
            "1500000 2500000 7 9",
            "x 2500000 7",
            "1500000 y 7",
            "1500000 2500000 z",
            "-1 2500000 7",
            // A kernel that keeps no scheduler statistics.
            "0 0 0\n",
        ] {
            assert_eq!(ThreadTimes::parse(malformed), None, "{malformed:?}");
        }
    }

    /// Replays run on blocking threads, which may be new: a thread reads its
    /// times before its first tick or switch.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_new_thread_reads_its_times() {
        for _ in 0..20 {
            let times = std::thread::spawn(ThreadTimes::now).join().unwrap();
            assert!(times.is_some(), "a new thread read no times");
        }
    }

    /// A thread spinning shows on CPU, and one sleeping does not. The spin
    /// waits on the counter, within a cap, so that load slows it and a hang
    /// still fails. Before its timer starts, the test's new thread runs on CPU
    /// with no tick or switch to bring schedstat's counter up to date.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_step_tells_time_on_cpu_from_time_off_it() {
        let on_cpu = |step: &ThreadStep| step.times.expect("thread times").on_cpu;
        let spin = Duration::from_millis(150);
        let before = ThreadTimes::now().expect("this thread's times");
        let spinning = ThreadStepTimer::start();
        while ThreadTimes::now().unwrap().since(before).on_cpu < spin {
            assert!(
                spinning.started.elapsed() < Duration::from_secs(120),
                "the on-CPU counter stopped"
            );
        }
        let spun = spinning.end();
        // The CPU clock runs on the scheduler's clock and the wall on the
        // monotonic one, which time sync may slow by up to 500 ppm; a build
        // host's scheduler clock ran 200-260 ppm slower than its monotonic one.
        assert!(on_cpu(&spun) <= spun.wall + spun.wall / 1000, "{spun:?}");
        assert!(on_cpu(&spun) >= spin / 2, "{spun:?}");

        let sleep = Duration::from_millis(200);
        let sleeping = ThreadStepTimer::start();
        std::thread::sleep(sleep);
        let slept = sleeping.end();
        assert!(slept.wall >= sleep, "{slept:?}");
        assert!(on_cpu(&slept) < sleep / 2, "{slept:?}");
        assert!(slept.waited().unwrap() >= sleep / 2, "{slept:?}");
    }

    /// A frame's steps land in their parts: what is off CPU in execution, in
    /// the store's wait; in its commit, in the commit's; a write in neither.
    #[test]
    fn a_materialized_frame_splits_cpu_run_queue_writes_and_waits() {
        let costs = ReplayCosts::materialized(
            Duration::from_millis(7),
            &step(100, 30, 10, 5),
            &step(50, 11, 2, 20),
        );
        assert_eq!(
            costs,
            ReplayCosts {
                preverify_us: 7_000,
                store_write_us: 25_000,
                store_wait_us: 55_000,
                commit_wait_us: 17_000,
                cpu_us: 41_000,
                run_wait_us: 12_000,
                sampled_frames: 1,
                ..ReplayCosts::default()
            }
        );
    }

    #[test]
    fn a_frame_without_thread_times_counts_only_what_was_timed() {
        let unsampled = ThreadStep {
            times: None,
            ..step(100, 0, 0, 5)
        };
        assert_eq!(
            ReplayCosts::materialized(Duration::from_millis(7), &unsampled, &unsampled),
            ReplayCosts {
                preverify_us: 7_000,
                store_write_us: 10_000,
                ..ReplayCosts::default()
            }
        );
    }

    fn engine_costs() -> ReplayCosts {
        ReplayCosts {
            engine_us: 100_000,
            prepare_us: 10_000,
            preverify_us: 5_000,
            store_write_us: 8_000,
            store_wait_us: 40_000,
            commit_wait_us: 4_000,
            cpu_us: 20_000,
            run_wait_us: 3_000,
            sampled_frames: 2,
        }
    }

    #[test]
    fn the_parts_add_up_to_the_replay_time() {
        let split = ReplaySplit::of(130, 12, engine_costs());
        assert_eq!(
            split,
            ReplaySplit {
                global_sync_wait_ms: 12,
                engine_queue_ms: 18,
                prepare_ms: 10,
                preverify_ms: 5,
                store_write_ms: 8,
                store_wait_ms: Some(40),
                commit_wait_ms: Some(4),
                cpu_ms: Some(20),
                run_wait_ms: Some(3),
                other_ms: 10,
            }
        );
        let parts = split.global_sync_wait_ms
            + split.engine_queue_ms
            + split.prepare_ms
            + split.preverify_ms
            + split.store_write_ms
            + split.store_wait_ms.unwrap()
            + split.commit_wait_ms.unwrap()
            + split.cpu_ms.unwrap()
            + split.run_wait_ms.unwrap()
            + split.other_ms;
        assert_eq!(parts, 130);
    }

    /// A request timing out at the handle leaves the engine working: its cost
    /// can outrun the turn's replay time, and no part goes negative.
    #[test]
    fn a_split_never_underflows() {
        let split = ReplaySplit::of(50, 60, engine_costs());
        assert_eq!(split.engine_queue_ms, 0);
        let parts_over_engine = ReplayCosts {
            engine_us: 1_000,
            ..engine_costs()
        };
        assert_eq!(ReplaySplit::of(50, 0, parts_over_engine).other_ms, 0);
        assert_eq!(ReplaySplit::of(0, 0, ReplayCosts::default()).mostly(), None);
    }

    #[test]
    fn without_thread_times_the_thread_parts_are_absent() {
        let split = ReplaySplit::of(
            130,
            12,
            ReplayCosts {
                sampled_frames: 0,
                store_wait_us: 0,
                commit_wait_us: 0,
                cpu_us: 0,
                run_wait_us: 0,
                ..engine_costs()
            },
        );
        assert_eq!(
            (
                split.store_wait_ms,
                split.commit_wait_ms,
                split.cpu_ms,
                split.run_wait_ms
            ),
            (None, None, None, None)
        );
        assert_eq!(split.other_ms, 77);
    }

    /// Sets one part of a split, and the part it sets.
    type PartSetter = (fn(&mut ReplaySplit), ReplayPart);

    #[test]
    fn the_longest_part_names_whose_problem_it_is() {
        let parts: [PartSetter; 10] = [
            (|s| s.global_sync_wait_ms = 9, ReplayPart::GlobalSync),
            (|s| s.engine_queue_ms = 9, ReplayPart::EngineBusy),
            (|s| s.prepare_ms = 9, ReplayPart::Prepare),
            (|s| s.preverify_ms = 9, ReplayPart::Proofs),
            (|s| s.store_write_ms = 9, ReplayPart::StoreWrites),
            (|s| s.store_wait_ms = Some(9), ReplayPart::StoreReads),
            (|s| s.commit_wait_ms = Some(9), ReplayPart::CommitWait),
            (|s| s.cpu_ms = Some(9), ReplayPart::Cpu),
            (|s| s.run_wait_ms = Some(9), ReplayPart::CpuContention),
            (|s| s.other_ms = 9, ReplayPart::Other),
        ];
        let mut labels = std::collections::BTreeSet::new();
        for (set, part) in parts {
            let mut split = ReplaySplit {
                global_sync_wait_ms: 1,
                engine_queue_ms: 1,
                other_ms: 1,
                ..ReplaySplit::default()
            };
            set(&mut split);
            assert_eq!(split.mostly(), Some(part));
            assert!(labels.insert(part.label()), "{part:?}");
            let (scope, action) = part.guidance();
            assert!(!scope.is_empty() && !action.is_empty(), "{part:?}");
        }
    }

    #[test]
    fn costs_read_as_added_and_a_later_read_gives_the_difference() {
        let shared = SharedReplayCosts::default();
        shared.add(&ReplayCosts::prepare(Duration::from_millis(3)));
        let before = shared.read();
        shared.add(&engine_costs());
        shared.add(&ReplayCosts::store_write(Duration::from_millis(1)));
        shared.add(&ReplayCosts::engine(Duration::from_millis(2)));
        assert_eq!(
            shared.read().since(before),
            ReplayCosts {
                engine_us: 102_000,
                store_write_us: 9_000,
                ..engine_costs()
            }
        );
        assert_eq!(before.since(shared.read()), ReplayCosts::default());
    }

    /// One warning for an episode, a repeat only after its interval with the
    /// turns and time since, and one line as it ends.
    #[test]
    fn slow_replays_warn_bounded_and_end_once() {
        const MIN: u64 = 60_000;
        let slow = SlowReplays::new();
        let frames = SLOW_REPLAY_MIN_FRAMES;
        let at_limit = frames * 1000;
        let (start, repeat) = (1_000 * MIN, 10 * MIN);
        // At pace, or too few frames, or with nobody waiting: nothing starts.
        assert_eq!(slow.observe(frames, at_limit - 1, 3, start), None);
        assert_eq!(slow.observe(frames - 1, at_limit * 9, 3, start), None);
        assert_eq!(slow.observe(frames, at_limit, 0, start), None);

        assert_eq!(
            slow.observe(frames, at_limit, 3, start),
            Some(SlowReplayLog::Slow {
                turns: 1,
                duration: Duration::ZERO
            })
        );
        assert_eq!(slow.observe(frames, at_limit, 3, start + MIN), None);
        assert_eq!(
            slow.observe(frames, at_limit, 3, start + repeat - 1),
            None,
            "not before its interval"
        );
        assert_eq!(
            slow.observe(frames, at_limit, 3, start + repeat),
            Some(SlowReplayLog::Slow {
                turns: 3,
                duration: Duration::from_secs(600)
            })
        );
        // Too few frames say nothing: the episode goes on.
        assert_eq!(slow.observe(frames - 1, 0, 3, start + repeat + 1), None);
        assert_eq!(
            slow.observe(frames, 0, 3, start + repeat + MIN),
            Some(SlowReplayLog::Ended {
                duration: Duration::from_secs(660)
            })
        );
        assert_eq!(
            slow.observe(frames, 0, 3, start + repeat + 2 * MIN),
            None,
            "it ended once"
        );
        // The next episode starts afresh.
        assert_eq!(
            slow.observe(frames, at_limit, 3, start + 3 * repeat),
            Some(SlowReplayLog::Slow {
                turns: 1,
                duration: Duration::ZERO
            })
        );
    }
}
