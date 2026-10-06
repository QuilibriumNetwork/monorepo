//! Step timing for GLOBAL work that is normally a second or two. A clock
//! records the time spent in each named step and, when dropped after running
//! longer than `SLOW`, logs every step. It logs nothing otherwise, so it can
//! stay on everywhere.

use std::time::{Duration, Instant};

/// Work that took longer than this is logged with its steps.
const SLOW: Duration = Duration::from_secs(5);

/// For work that holds this node's single GLOBAL execution slot: at a 10 s
/// frame cadence, a second of it already delays votes and proposals.
pub(crate) const SLOW_EXECUTION: Duration = Duration::from_secs(1);

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
        Self { what, frame, started: now, last: now, steps: Vec::new(), slow }
    }

    /// Close the step that ends now.
    pub(crate) fn mark(&mut self, step: &'static str) {
        let now = Instant::now();
        self.steps.push((step, now.duration_since(self.last).as_millis()));
        self.last = now;
    }
}

impl Drop for StageClock {
    fn drop(&mut self) {
        let total = self.started.elapsed();
        if total >= self.slow {
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
        assert!(clock.started.elapsed() < SLOW, "a fast clock logs nothing when dropped");
    }
}
