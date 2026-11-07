//! How an archive executes GLOBAL frames while its execution trails the head
//! by more than the voting window, and how it reports the catch-up.
//!
//! An atomic attempt captures a branch, executes the frame privately and
//! commits only if no other write landed since the capture. While an archive
//! catches up, its poller, gap fetches and application-frame ingest write
//! constantly: on mainnet (2026-10-24) about 95% of a lagging archive's
//! attempts failed at commit, each frame executed 3.5 to 4 times at ~3.4 s,
//! and a capture after an in-place frame re-read every prover row (~10 s).
//! It executed about 2 frames a minute while the network made 6, so it never
//! caught up, and an archive this far behind cannot vote or propose.
//!
//! A catch-up begins when execution trails the head by more than the window
//! and ends once it is back within half of it. During one, frames execute in
//! place without atomic attempts; otherwise each frame keeps its attempts.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::info;

use crate::frame_materializer::CanonicalAttempt;

/// Frames GLOBAL execution may trail the head and still vote and propose: a
/// selected parent further above the executed frame is outside the execution
/// window (`GlobalParentLimits::default().max_ancestors`). A catch-up begins
/// beyond it.
pub const CATCH_UP_WINDOW: u64 = 32;

/// A catch-up ends at this lag or less, so a lag hovering at the window does
/// not switch the policy back and forth.
pub const CATCH_UP_END_LAG: u64 = CATCH_UP_WINDOW / 2;

/// Atomic attempts per frame outside a catch-up. A commit conflict with a
/// brief concurrent writer usually clears on retry; the finalization
/// pipeline makes as many before its legacy fallback.
pub const AT_HEAD_ATOMIC_ATTEMPTS: u32 = 3;

/// Least time between two catch-up progress lines.
pub const PROGRESS_INTERVAL: Duration = Duration::from_secs(60);

/// Make up to `attempts` atomic attempts, stopping at the first that is not
/// [`CanonicalAttempt::Unavailable`]. `None` when none was made; the caller
/// then executes in place.
pub fn attempt_atomically(
    attempts: u32,
    mut attempt: impl FnMut() -> CanonicalAttempt,
) -> Option<CanonicalAttempt> {
    let mut last = None;
    for _ in 0..attempts {
        let outcome = attempt();
        let unavailable = matches!(outcome, CanonicalAttempt::Unavailable(_));
        last = Some(outcome);
        if !unavailable {
            break;
        }
    }
    last
}

/// Atomic execution work since start: publications, attempts that published
/// nothing, captures that took a second or more (a full prover-registry read)
/// and full registry reads around in-place frames.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutionCounts {
    pub atomic_published: u64,
    pub atomic_failed: u64,
    pub slow_captures: u64,
    pub registry_reads: u64,
}

impl ExecutionCounts {
    fn since(self, base: Self) -> Self {
        Self {
            atomic_published: self.atomic_published.saturating_sub(base.atomic_published),
            atomic_failed: self.atomic_failed.saturating_sub(base.atomic_failed),
            slow_captures: self.slow_captures.saturating_sub(base.slow_captures),
            registry_reads: self.registry_reads.saturating_sub(base.registry_reads),
        }
    }
}

#[derive(Default)]
pub(crate) struct ExecutionCounters {
    atomic_published: AtomicU64,
    atomic_failed: AtomicU64,
    slow_captures: AtomicU64,
    registry_reads: AtomicU64,
}

impl ExecutionCounters {
    /// One atomic attempt's outcome: `Ok(None)` is a replay, neither.
    pub(crate) fn attempted<T, E>(&self, result: &Result<Option<T>, E>) {
        match result {
            Ok(Some(_)) => self.atomic_published.fetch_add(1, Ordering::Relaxed),
            Ok(None) => return,
            Err(_) => self.atomic_failed.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub(crate) fn captured(&self, took: Duration) {
        if took >= crate::stage_clock::SLOW_EXECUTION {
            self.slow_captures.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn registry_read(&self) {
        self.registry_reads.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn counts(&self) -> ExecutionCounts {
        ExecutionCounts {
            atomic_published: self.atomic_published.load(Ordering::Relaxed),
            atomic_failed: self.atomic_failed.load(Ordering::Relaxed),
            slow_captures: self.slow_captures.load(Ordering::Relaxed),
            registry_reads: self.registry_reads.load(Ordering::Relaxed),
        }
    }
}

/// One interval of a catch-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatchUpReport {
    pub executed: u64,
    pub head: u64,
    /// Frames executed, and frames the head advanced, in the interval.
    pub frames: u64,
    pub head_frames: u64,
    pub secs: u64,
    /// Zero when no frame executed.
    pub ms_per_frame: u64,
    pub in_place: u64,
    /// Time frames waited for the application frames they reward.
    pub ingest_wait_ms: u64,
    pub counts: ExecutionCounts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatchUpEvent {
    /// At most once per interval during a catch-up.
    Progress(CatchUpReport),
    /// The catch-up ended after `frames` in `secs`.
    CaughtUp {
        executed: u64,
        head: u64,
        frames: u64,
        secs: u64,
    },
}

#[derive(Clone, Copy)]
struct Mark {
    at: Instant,
    executed: u64,
    head: u64,
    in_place: u64,
    ingest_wait: Duration,
    counts: ExecutionCounts,
}

/// One archive's catch-up state: the execution policy and its operator
/// lines. The clock is the caller's.
pub struct CatchUp {
    interval: Duration,
    in_place: u64,
    ingest_wait: Duration,
    ingest_waiting: Option<Instant>,
    /// Where the catch-up began, and where the current interval began.
    lagging: Option<(Mark, Mark)>,
}

impl Default for CatchUp {
    fn default() -> Self {
        Self::with_interval(PROGRESS_INTERVAL)
    }
}

impl CatchUp {
    pub fn with_interval(interval: Duration) -> Self {
        Self {
            interval,
            in_place: 0,
            ingest_wait: Duration::ZERO,
            ingest_waiting: None,
            lagging: None,
        }
    }

    /// Whether a catch-up is under way, as of the last [`Self::observe`].
    pub fn catching_up(&self) -> bool {
        self.lagging.is_some()
    }

    /// Atomic attempts for the next frame: none during a catch-up.
    pub fn atomic_attempts(&self) -> u32 {
        if self.catching_up() {
            0
        } else {
            AT_HEAD_ATOMIC_ATTEMPTS
        }
    }

    /// A frame executed in place.
    pub fn record_in_place(&mut self) {
        self.in_place += 1;
    }

    /// Whether the next frame's application frames were ingested at `now`.
    pub fn note_ingest(&mut self, now: Instant, ready: bool) {
        match (ready, self.ingest_waiting) {
            (false, None) => self.ingest_waiting = Some(now),
            (true, Some(since)) => {
                self.ingest_wait += now.saturating_duration_since(since);
                self.ingest_waiting = None;
            }
            _ => {}
        }
    }

    /// Update the state for execution at `executed` with the head at `head`
    /// and the materializer's `counts` at `now`; the event to log, if any.
    pub fn observe(
        &mut self,
        now: Instant,
        executed: u64,
        head: u64,
        counts: ExecutionCounts,
    ) -> Option<CatchUpEvent> {
        let lag = head.saturating_sub(executed);
        let mark = Mark {
            at: now,
            executed,
            head,
            in_place: self.in_place,
            ingest_wait: self.ingest_wait,
            counts,
        };
        if self.lagging.is_none() {
            if lag > CATCH_UP_WINDOW {
                self.lagging = Some((mark, mark));
            }
            return None;
        }
        if lag <= CATCH_UP_END_LAG {
            let (start, _) = self.lagging.take()?;
            return Some(CatchUpEvent::CaughtUp {
                executed,
                head,
                frames: executed.saturating_sub(start.executed),
                secs: now.saturating_duration_since(start.at).as_secs(),
            });
        }
        let (_, interval) = self.lagging.as_mut()?;
        let elapsed = now.saturating_duration_since(interval.at);
        if elapsed < self.interval {
            return None;
        }
        let previous = std::mem::replace(interval, mark);
        let frames = executed.saturating_sub(previous.executed);
        let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        let waited = self.ingest_wait.saturating_sub(previous.ingest_wait);
        Some(CatchUpEvent::Progress(CatchUpReport {
            executed,
            head,
            frames,
            head_frames: head.saturating_sub(previous.head),
            secs: elapsed.as_secs(),
            ms_per_frame: if frames == 0 { 0 } else { ms / frames },
            in_place: self.in_place - previous.in_place,
            ingest_wait_ms: u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
            counts: counts.since(previous.counts),
        }))
    }

    /// [`Self::observe`], logging the event.
    pub fn observe_and_log(
        &mut self,
        now: Instant,
        executed: u64,
        head: u64,
        counts: ExecutionCounts,
    ) {
        if let Some(event) = self.observe(now, executed, head, counts) {
            log(&event);
        }
    }
}

/// One `info!` line per event. Progress compares `frames` with `head_frames`
/// (whether the archive gains on the head) and says how frames executed.
pub fn log(event: &CatchUpEvent) {
    match *event {
        CatchUpEvent::Progress(r) => info!(
            scope = "local",
            executed = r.executed,
            head = r.head,
            lag = r.head.saturating_sub(r.executed),
            window = CATCH_UP_WINDOW,
            ends_at_lag = CATCH_UP_END_LAG,
            frames = r.frames,
            head_frames = r.head_frames,
            secs = r.secs,
            ms_per_frame = r.ms_per_frame,
            atomic_published = r.counts.atomic_published,
            atomic_failed = r.counts.atomic_failed,
            in_place = r.in_place,
            slow_captures = r.counts.slow_captures,
            registry_reads = r.counts.registry_reads,
            ingest_wait_ms = r.ingest_wait_ms,
            "GLOBAL catch-up progress: this archive cannot vote or propose while it trails the head beyond the window; frames execute in place until the lag is back to ends_at_lag"
        ),
        CatchUpEvent::CaughtUp { executed, head, frames, secs } => info!(
            scope = "local",
            executed,
            head,
            frames,
            secs,
            window = CATCH_UP_WINDOW,
            "GLOBAL catch-up done: execution is back within the voting window"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::error::QuilError;

    /// Captures and executions (atomic attempts plus the in-place one after
    /// none published) for one frame whose atomic attempts all fail.
    fn execute(catch_up: &CatchUp) -> (u32, u32) {
        let mut captures = 0;
        let outcome = attempt_atomically(catch_up.atomic_attempts(), || {
            captures += 1;
            CanonicalAttempt::Unavailable(QuilError::ExecutionUnavailable(
                "canonical execution commit: execution base changed".into(),
            ))
        });
        let in_place = !matches!(
            outcome,
            Some(CanonicalAttempt::Published(_) | CanonicalAttempt::Replayed)
        );
        (captures, captures + u32::from(in_place))
    }

    fn at(catch_up: &mut CatchUp, executed: u64, head: u64) -> Option<CatchUpEvent> {
        catch_up.observe(Instant::now(), executed, head, ExecutionCounts::default())
    }

    #[test]
    fn far_behind_a_frame_executes_once_in_place() {
        let mut catch_up = CatchUp::default();
        at(&mut catch_up, 930_718, 931_009);
        assert_eq!(execute(&catch_up), (0, 1));
    }

    #[test]
    fn near_the_head_a_frame_keeps_three_attempts() {
        let mut catch_up = CatchUp::default();
        at(&mut catch_up, 1_000, 1_000 + CATCH_UP_WINDOW);
        assert_eq!(execute(&catch_up), (3, 4));
        // The first attempt that does not fail ends the attempts.
        let mut calls = 0;
        let outcome = attempt_atomically(AT_HEAD_ATOMIC_ATTEMPTS, || {
            calls += 1;
            CanonicalAttempt::Replayed
        });
        assert!(matches!(outcome, Some(CanonicalAttempt::Replayed)));
        assert_eq!(calls, 1);
    }

    /// Beyond the window a catch-up begins; it lasts until the lag is back to
    /// half the window, with one line at its end.
    #[test]
    fn a_catch_up_begins_beyond_the_window_and_ends_within_half_of_it() {
        let mut catch_up = CatchUp::default();
        assert_eq!(at(&mut catch_up, 1_000, 1_000 + CATCH_UP_WINDOW), None);
        assert!(!catch_up.catching_up());
        assert_eq!(at(&mut catch_up, 1_000, 1_001 + CATCH_UP_WINDOW), None);
        assert_eq!(catch_up.atomic_attempts(), 0);
        for lag in [CATCH_UP_WINDOW, 20, CATCH_UP_END_LAG + 1] {
            assert_eq!(at(&mut catch_up, 1_100, 1_100 + lag), None, "lag {lag}");
            assert_eq!(catch_up.atomic_attempts(), 0, "lag {lag}");
        }
        assert!(matches!(
            at(&mut catch_up, 1_100, 1_100 + CATCH_UP_END_LAG),
            Some(CatchUpEvent::CaughtUp {
                executed: 1_100,
                frames: 100,
                ..
            })
        ));
        assert_eq!(catch_up.atomic_attempts(), AT_HEAD_ATOMIC_ATTEMPTS);
        assert_eq!(
            at(&mut catch_up, 1_100, 1_100 + CATCH_UP_WINDOW),
            None,
            "one line per catch-up"
        );
        assert_eq!(catch_up.atomic_attempts(), AT_HEAD_ATOMIC_ATTEMPTS);
        at(&mut catch_up, 1_100, 1_101 + CATCH_UP_WINDOW);
        assert!(catch_up.catching_up(), "a new catch-up");
    }

    #[test]
    fn the_window_is_the_selected_parent_execution_window() {
        assert_eq!(
            CATCH_UP_WINDOW,
            crate::frame_materializer::GlobalParentLimits::default().max_ancestors as u64
        );
    }

    #[test]
    fn progress_is_reported_once_per_interval_while_behind_and_once_when_caught_up() {
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let counts = |published, failed, slow| ExecutionCounts {
            atomic_published: published,
            atomic_failed: failed,
            slow_captures: slow,
            registry_reads: 0,
        };
        let mut progress = CatchUp::default();
        // Within the window nothing is reported.
        assert_eq!(progress.observe(at(0), 1_000, 1_010, counts(0, 0, 0)), None);
        // Falling behind starts the first interval silently.
        assert_eq!(progress.observe(at(1), 1_000, 1_100, counts(0, 0, 0)), None);
        progress.record_in_place();
        progress.record_in_place();
        progress.note_ingest(at(10), false);
        progress.note_ingest(at(12), false);
        progress.note_ingest(at(13), true);
        assert_eq!(
            progress.observe(at(30), 1_010, 1_105, counts(1, 1, 0)),
            None
        );
        assert_eq!(
            progress.observe(at(60), 1_020, 1_106, counts(1, 2, 1)),
            None
        );
        let Some(CatchUpEvent::Progress(report)) =
            progress.observe(at(61), 1_021, 1_107, counts(2, 2, 1))
        else {
            panic!("a progress line after the interval");
        };
        assert_eq!(
            report,
            CatchUpReport {
                executed: 1_021,
                head: 1_107,
                frames: 21,
                head_frames: 7,
                secs: 60,
                ms_per_frame: 60_000 / 21,
                in_place: 2,
                ingest_wait_ms: 3_000,
                counts: counts(2, 2, 1),
            }
        );
        // The next interval starts at that line.
        progress.record_in_place();
        assert_eq!(
            progress.observe(at(120), 1_040, 1_110, counts(2, 3, 1)),
            None
        );
        let Some(CatchUpEvent::Progress(report)) =
            progress.observe(at(121), 1_041, 1_111, counts(2, 3, 1))
        else {
            panic!("the next progress line");
        };
        assert_eq!(
            (
                report.frames,
                report.in_place,
                report.ingest_wait_ms,
                report.counts
            ),
            (20, 1, 0, counts(0, 1, 0))
        );
        // Back within half the window: one line, then nothing.
        assert_eq!(
            progress.observe(at(130), 1_100, 1_112, counts(2, 3, 1)),
            Some(CatchUpEvent::CaughtUp {
                executed: 1_100,
                head: 1_112,
                frames: 100,
                secs: 129
            })
        );
        assert_eq!(
            progress.observe(at(200), 1_110, 1_112, counts(2, 3, 1)),
            None
        );
    }

    #[test]
    fn an_interval_without_execution_reports_no_rate() {
        let start = Instant::now();
        let mut progress = CatchUp::with_interval(Duration::from_secs(10));
        let none = ExecutionCounts::default();
        assert_eq!(progress.observe(start, 1_000, 1_100, none), None);
        let Some(CatchUpEvent::Progress(report)) =
            progress.observe(start + Duration::from_secs(10), 1_000, 1_110, none)
        else {
            panic!("a progress line");
        };
        assert_eq!(
            (report.frames, report.head_frames, report.ms_per_frame),
            (0, 10, 0)
        );
    }
}
