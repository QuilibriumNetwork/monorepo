//! Whether an archive node's GLOBAL execution keeps up with the GLOBAL head.
//!
//! An archive's frame materializer executes each GLOBAL frame it receives,
//! and its message collector verifies submitted shard frames against the
//! state it leaves. A materializer that stops while frames keep arriving
//! leaves the archive judging submissions by old state without a line saying
//! so. Each status tick compares the executed frame with the head; a lag over
//! [`LAG_FRAMES`] for [`LAG_TICKS`] ticks in a row is an outage. Nodes that do
//! not execute GLOBAL frames (no materializer) report nothing.

use std::time::Instant;

use quil_engine::outage::{Outage, OutageEvent};
use tracing::{info, warn};

/// Frames GLOBAL execution may trail the head before it counts as behind.
pub(crate) const LAG_FRAMES: u64 = 30;
/// Consecutive status ticks behind before the first warning.
const LAG_TICKS: u64 = 4;

/// The GLOBAL execution lag across status ticks.
#[derive(Debug)]
pub(crate) struct GlobalExecution {
    outage: Outage,
}

impl Default for GlobalExecution {
    fn default() -> Self {
        Self {
            outage: Outage::begin_after(LAG_TICKS),
        }
    }
}

impl GlobalExecution {
    /// Record one tick's executed frame and head; returns the transition.
    /// Nothing executed is a node without a materializer, or one starting.
    pub(crate) fn assess(&mut self, now: Instant, executed: u64, head: u64) -> Option<OutageEvent> {
        if executed == 0 {
            return None;
        }
        self.outage
            .observe(now, head.saturating_sub(executed) <= LAG_FRAMES)
    }

    /// [`Self::assess`], logging the outage's start, repeats and end.
    pub(crate) fn observe(&mut self, now: Instant, executed: u64, head: u64) {
        let lag = head.saturating_sub(executed);
        match self.assess(now, executed, head) {
            Some(OutageEvent::Began) => warn!(
                scope = "local",
                action = "report",
                executed,
                head,
                lag,
                "GLOBAL execution trails the GLOBAL head: this archive judges submitted shard frames by old state; report with the frame after `executed`"
            ),
            Some(OutageEvent::Continues { secs, .. }) => warn!(
                scope = "local",
                action = "report",
                executed,
                head,
                lag,
                secs,
                "GLOBAL execution still trails the GLOBAL head"
            ),
            Some(OutageEvent::Ended { secs, .. }) => {
                info!(executed, head, secs, "GLOBAL execution caught up with the GLOBAL head")
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_lag_warns_after_four_ticks_and_ends_when_execution_catches_up() {
        let mut g = GlobalExecution::default();
        let t = Instant::now();
        let tick = |n: u64| t + Duration::from_secs(30 * n);
        assert_eq!(g.assess(tick(0), 1_000, 1_000 + LAG_FRAMES), None);
        for n in 1..4 {
            assert_eq!(g.assess(tick(n), 1_000, 1_100), None);
        }
        assert_eq!(g.assess(tick(4), 1_000, 1_100), Some(OutageEvent::Began));
        assert_eq!(g.assess(tick(5), 1_000, 1_101), None);
        assert_eq!(
            g.assess(tick(5) + Duration::from_secs(600), 1_000, 1_130),
            Some(OutageEvent::Continues {
                secs: 720,
                failures: 6
            })
        );
        assert_eq!(
            g.assess(tick(30), 1_129, 1_130),
            Some(OutageEvent::Ended {
                secs: 870,
                failures: 6
            })
        );
    }

    #[test]
    fn a_node_that_has_executed_nothing_is_not_behind() {
        let mut g = GlobalExecution::default();
        let t = Instant::now();
        for n in 0..10 {
            assert_eq!(g.assess(t + Duration::from_secs(30 * n), 0, 899_041), None);
        }
    }
}
