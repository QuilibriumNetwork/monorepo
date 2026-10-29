//! Step timing for GLOBAL work that is normally a second or two. A clock
//! records the time spent in each named step. Work that ran longer than the
//! clock's `slow` is counted in a summary logged every `SUMMARY_INTERVAL`
//! (count, max and median per kind of work); only work that ran longer than
//! `WARN_AFTER` is warned about with its steps. It logs nothing for fast
//! work, so it can stay on everywhere.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Work that took longer than this is logged with its steps.
const SLOW: Duration = Duration::from_secs(5);

/// Work that took longer than this is warned about with its steps: a whole
/// frame interval (10 s on mainnet), so the next frame's votes and proposal
/// were late. Work between a clock's `slow` and this is only counted in the
/// summary: on a loaded archive that is most frames, and a warn each is noise.
pub(crate) const WARN_AFTER: Duration = Duration::from_secs(10);

/// How often slow work is summarized (as `inclusion_summary` does).
const SUMMARY_INTERVAL: Duration = Duration::from_secs(600);

/// For work that holds this node's single GLOBAL execution slot: at a 10 s
/// frame cadence, a second of it already delays votes and proposals.
pub(crate) const SLOW_EXECUTION: Duration = Duration::from_secs(1);

/// Slow work seen since the last summary, by kind.
struct SlowSummary {
    since: Instant,
    durations_ms: BTreeMap<&'static str, Vec<u64>>,
}

/// One kind of slow work in a summary.
#[derive(Debug, PartialEq, Eq)]
struct KindSummary {
    what: &'static str,
    count: usize,
    max_ms: u64,
    p50_ms: u64,
}

impl SlowSummary {
    fn new(now: Instant) -> Self {
        Self {
            since: now,
            durations_ms: BTreeMap::new(),
        }
    }

    fn note(&mut self, what: &'static str, elapsed: Duration) {
        self.durations_ms
            .entry(what)
            .or_default()
            .push(elapsed.as_millis() as u64);
    }

    /// The summary of the interval ending at `now`, if it is over and slow
    /// work was seen; starts the next interval.
    fn take_due(&mut self, now: Instant, interval: Duration) -> Option<(u64, Vec<KindSummary>)> {
        let window = now.saturating_duration_since(self.since);
        if window < interval {
            return None;
        }
        self.since = now;
        let kinds = std::mem::take(&mut self.durations_ms)
            .into_iter()
            .map(|(what, mut ms)| {
                ms.sort_unstable();
                KindSummary {
                    what,
                    count: ms.len(),
                    max_ms: ms.last().copied().unwrap_or(0),
                    p50_ms: ms[ms.len() / 2],
                }
            })
            .collect::<Vec<_>>();
        (!kinds.is_empty()).then_some((window.as_secs(), kinds))
    }
}

static SLOW_STEPS: Mutex<Option<SlowSummary>> = Mutex::new(None);

fn with_summary<T>(f: impl FnOnce(&mut SlowSummary) -> T) -> T {
    let mut guard = SLOW_STEPS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(guard.get_or_insert_with(|| SlowSummary::new(Instant::now())))
}

/// Counts work of kind `what` that took `elapsed`, over its `slow`, in the
/// summary; logs the summary when its interval is over.
pub(crate) fn note_slow(what: &'static str, elapsed: Duration) {
    let due = with_summary(|summary| {
        summary.note(what, elapsed);
        summary.take_due(Instant::now(), SUMMARY_INTERVAL)
    });
    log_summary(due);
}

fn log_summary(due: Option<(u64, Vec<KindSummary>)>) {
    let Some((window_secs, kinds)) = due else {
        return;
    };
    for kind in kinds {
        tracing::info!(
            what = kind.what,
            window_secs,
            count = kind.count,
            max_ms = kind.max_ms,
            p50_ms = kind.p50_ms,
            warn_after_ms = WARN_AFTER.as_millis() as u64,
            scope = "local",
            "slow GLOBAL steps in the last interval: this node's GLOBAL work ran past its usual second or \
             two; a step over warn_after_ms is warned about separately, and a rising count or max with \
             late votes or proposals points at this node's load (CPU, disk) or a large frame"
        );
    }
}

pub(crate) struct StageClock {
    what: &'static str,
    frame: u64,
    started: Instant,
    last: Instant,
    steps: Vec<(&'static str, u128)>,
    slow: Duration,
}

impl StageClock {
    pub(crate) fn start(what: &'static str, frame: u64) -> Self {
        Self::start_after(what, frame, SLOW)
    }

    /// Logs when the work took longer than `slow`.
    pub(crate) fn start_after(what: &'static str, frame: u64, slow: Duration) -> Self {
        let now = Instant::now();
        Self {
            what,
            frame,
            started: now,
            last: now,
            steps: Vec::new(),
            slow,
        }
    }

    /// Close the step that ends now.
    pub(crate) fn mark(&mut self, step: &'static str) {
        let now = Instant::now();
        self.steps
            .push((step, now.duration_since(self.last).as_millis()));
        self.last = now;
    }
}

impl Drop for StageClock {
    fn drop(&mut self) {
        let total = self.started.elapsed();
        if total < self.slow {
            let due = with_summary(|summary| summary.take_due(Instant::now(), SUMMARY_INTERVAL));
            log_summary(due);
            return;
        }
        note_slow(self.what, total);
        if total >= WARN_AFTER.max(self.slow) {
            let unfinished = self.last.elapsed().as_millis();
            tracing::warn!(
                what = self.what,
                frame = self.frame,
                total_ms = total.as_millis() as u64,
                steps = ?self.steps,
                after_last_step_ms = unfinished as u64,
                "slow GLOBAL step"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_are_recorded_in_order() {
        let mut clock = StageClock::start("test", 7);
        clock.mark("first");
        clock.mark("second");
        let names: Vec<_> = clock.steps.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, ["first", "second"]);
        assert!(
            clock.started.elapsed() < SLOW,
            "a fast clock logs nothing when dropped"
        );
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn slow_work_is_summarized_once_per_interval_with_count_max_and_median() {
        let start = Instant::now();
        let interval = Duration::from_secs(600);
        let mut summary = SlowSummary::new(start);
        for n in [1500, 1100, 4000, 2000, 1200] {
            summary.note("proposal", ms(n));
        }
        summary.note("execution", ms(1300));
        assert!(
            summary
                .take_due(start + Duration::from_secs(599), interval)
                .is_none(),
            "nothing before the interval is over"
        );
        let (window, kinds) = summary
            .take_due(start + interval, interval)
            .expect("due once the interval is over");
        assert_eq!(window, 600);
        assert_eq!(
            kinds,
            vec![
                KindSummary {
                    what: "execution",
                    count: 1,
                    max_ms: 1300,
                    p50_ms: 1300
                },
                KindSummary {
                    what: "proposal",
                    count: 5,
                    max_ms: 4000,
                    p50_ms: 1500
                },
            ]
        );
        assert!(
            summary.take_due(start + interval * 2, interval).is_none(),
            "an interval without slow work logs nothing and the counts restart"
        );
    }
}
