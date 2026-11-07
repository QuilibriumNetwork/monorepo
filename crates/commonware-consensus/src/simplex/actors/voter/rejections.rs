//! QUILIBRIUM: one bounded summary of the proposals this member refused to
//! vote for.
//!
//! Upstream warns "proposal failed verification" per refused proposal, with
//! only its round: no reason, leader or engine. A regular node logged 700 a
//! day, about 600 of them without any other line saying why. This counts
//! each refusal by reason, leader and view, and logs one summary per
//! [`SUMMARY_EVERY`] that saw one, naming the engine's journal partition
//! (`app-<shard filter>` on app shards); a warning only when this member
//! refused most of the proposals it checked in the window.

use crate::types::Participant;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime},
};

/// How often refusals are summarized at most.
pub(super) const SUMMARY_EVERY: Duration = Duration::from_secs(300);

/// The fewest refusals in a window that warn, once they outnumber the
/// proposals this member accepted: one refusal now and then is routine.
pub(super) const WARN_MIN: u64 = 10;

/// Distinct leaders and views remembered per window.
const DISTINCT: usize = 1024;

/// Refusals and acceptances of one window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Summary {
    /// Seconds the window lasted.
    pub secs: u64,
    /// Refusals, counting a view refused again once more.
    pub rejected: u64,
    /// Distinct views refused (at most [`DISTINCT`] are counted).
    pub views: usize,
    /// Proposals this member verified.
    pub accepted: u64,
    /// Refusals by reason.
    pub reasons: BTreeMap<&'static str, u64>,
    /// Distinct leaders refused (at most [`DISTINCT`] are counted).
    pub leaders: usize,
    /// The leader refused most often, with its count.
    pub top_leader: Option<(Participant, u64)>,
    /// Lowest and highest view refused.
    pub range: Option<(u64, u64)>,
}

impl Summary {
    /// Whether this member refused most proposals of the window.
    pub(super) const fn warns(&self) -> bool {
        self.rejected >= WARN_MIN && self.rejected > self.accepted
    }

    /// Log the summary for a member in epoch `epoch` of the engine
    /// journaling to `partition`.
    pub(super) fn log(&self, partition: &str, epoch: u64) {
        let reasons = self
            .reasons
            .iter()
            .map(|(reason, count)| format!("{reason}: {count}"))
            .collect::<Vec<_>>()
            .join(", ");
        let (top_leader, top_leader_rejected) = self
            .top_leader
            .map_or((String::new(), 0), |(leader, count)| {
                (leader.to_string(), count)
            });
        let (lowest_view, highest_view) = self.range.unwrap_or_default();
        if self.warns() {
            tracing::warn!(
                scope = "this node or the proposers",
                partition,
                epoch,
                rejected = self.rejected,
                views = self.views,
                accepted = self.accepted,
                reasons = %reasons,
                leaders = self.leaders,
                top_leader = %top_leader,
                top_leader_rejected,
                lowest_view,
                highest_view,
                secs = self.secs,
                action = "if one leader accounts for most refusals, it is likely behind or faulty: \
                          report its index with the partition to the maintainer; otherwise this node \
                          is likely behind: run `qclient node diagnostics health --self` for an app \
                          shard, or check this node's GLOBAL sync for the GLOBAL engine",
                "this node refused most proposals of a consensus engine; their views were skipped"
            );
        } else {
            tracing::info!(
                scope = "this node or the proposers",
                partition,
                epoch,
                rejected = self.rejected,
                views = self.views,
                accepted = self.accepted,
                reasons = %reasons,
                leaders = self.leaders,
                top_leader = %top_leader,
                top_leader_rejected,
                lowest_view,
                highest_view,
                secs = self.secs,
                action = "no action needed: consensus skips a refused proposal's view and the next \
                          leader proposes; an app shard's worker logs the application's reasons \
                          ('this worker refused some proposals')",
                "this node refused some proposals; consensus skipped their views and continued"
            );
        }
    }
}

/// Refusals since the window began; see the module docs.
#[derive(Debug, Default)]
pub(super) struct Rejections {
    since: Option<SystemTime>,
    pending: Summary,
    leaders: BTreeMap<Participant, u64>,
    views: BTreeSet<u64>,
}

impl Rejections {
    /// This member refused the proposal of `leader` in `view` for `reason`.
    pub(super) fn rejected(
        &mut self,
        now: SystemTime,
        reason: &'static str,
        leader: Option<Participant>,
        view: u64,
    ) {
        self.since.get_or_insert(now);
        self.pending.rejected += 1;
        *self.pending.reasons.entry(reason).or_default() += 1;
        if let Some(leader) = leader {
            if self.leaders.len() < DISTINCT || self.leaders.contains_key(&leader) {
                *self.leaders.entry(leader).or_default() += 1;
            }
        }
        if self.views.len() < DISTINCT {
            self.views.insert(view);
        }
        let (low, high) = self.pending.range.unwrap_or((view, view));
        self.pending.range = Some((low.min(view), high.max(view)));
    }

    /// This member verified a proposal.
    pub(super) fn accepted(&mut self, now: SystemTime) {
        self.since.get_or_insert(now);
        self.pending.accepted += 1;
    }

    /// The window's summary once [`SUMMARY_EVERY`] passed since it began
    /// and it saw a refusal; a due window without one ends quietly.
    pub(super) fn due(&mut self, now: SystemTime) -> Option<Summary> {
        let elapsed = now.duration_since(self.since?).unwrap_or_default();
        if elapsed < SUMMARY_EVERY {
            return None;
        }
        self.since = None;
        let mut summary = std::mem::take(&mut self.pending);
        let leaders = std::mem::take(&mut self.leaders);
        summary.views = std::mem::take(&mut self.views).len();
        if summary.rejected == 0 {
            return None;
        }
        summary.secs = elapsed.as_secs();
        summary.leaders = leaders.len();
        summary.top_leader = leaders.into_iter().max_by_key(|(_, count)| *count);
        Some(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000 + secs)
    }

    fn p(index: u32) -> Participant {
        Participant::new(index)
    }

    /// Refusals log one summary per window, by reason and leader, with the
    /// distinct views beside the count (a view refused again counts again),
    /// and a window without one logs nothing.
    #[test]
    fn refusals_are_summarized_once_per_window_by_reason_and_leader() {
        let mut r = Rejections::default();
        r.accepted(at(0));
        for view in 10..14 {
            r.rejected(at(view), "the application refused it", Some(p(2)), view);
        }
        r.rejected(at(20), "the application refused it", Some(p(2)), 13);
        r.rejected(
            at(30),
            "parent below the last finalized view",
            Some(p(4)),
            15,
        );
        for n in 1..=6 {
            r.accepted(at(40 + n));
        }
        assert_eq!(r.due(at(299)), None, "inside the window");
        let summary = r.due(at(300)).expect("a window with refusals");
        assert_eq!(
            summary,
            Summary {
                secs: 300,
                rejected: 6,
                views: 5,
                accepted: 7,
                reasons: [
                    ("parent below the last finalized view", 1),
                    ("the application refused it", 5)
                ]
                .into(),
                leaders: 2,
                top_leader: Some((p(2), 5)),
                range: Some((10, 15)),
            }
        );
        assert!(!summary.warns(), "6 refusals beside 7 acceptances");
        assert_eq!(r.due(at(900)), None, "nothing since");
        r.accepted(at(1_000));
        assert_eq!(
            r.due(at(1_300)),
            None,
            "a window without a refusal logs nothing"
        );
        r.rejected(at(1_400), "the application refused it", None, 99);
        let summary = r.due(at(1_700)).expect("a new window");
        assert_eq!(
            (summary.rejected, summary.accepted, summary.leaders),
            (1, 0, 0)
        );
    }

    /// Refusing most proposals of a window warns, from [`WARN_MIN`].
    #[test]
    fn refusing_most_proposals_warns() {
        let mut r = Rejections::default();
        for view in 0..WARN_MIN {
            r.rejected(at(view), "the application refused it", Some(p(1)), view);
        }
        r.accepted(at(20));
        assert!(r.due(at(300)).expect("refusals").warns());
        let mut few = Rejections::default();
        for view in 0..WARN_MIN - 1 {
            few.rejected(at(view), "the application refused it", Some(p(1)), view);
        }
        assert!(
            !few.due(at(300)).expect("refusals").warns(),
            "below the minimum"
        );
        let mut balanced = Rejections::default();
        for view in 0..WARN_MIN {
            balanced.rejected(at(view), "the application refused it", Some(p(1)), view);
            balanced.accepted(at(view));
        }
        assert!(
            !balanced.due(at(300)).expect("refusals").warns(),
            "not most"
        );
    }
}
