//! Operator signal for an app shard whose consensus stops finalizing: one
//! line once the running session host has finalized nothing for
//! [`STALL_AFTER`], a repeat every [`STALL_REPEAT`] with the duration, and
//! one line when a view finalizes again.
//!
//! A shard frame needs a quorum of members that applied its parent. While
//! too few have, its views time out one after another and a member's log
//! shows only nullified views: nothing says which members hold back. Each
//! line names, for the recent view whose proposal drew the most notarize
//! votes, the members that notarized it, those that nullified without
//! notarizing and those no vote of which reached this node, against the
//! quorum, and this member's own refused proposals and declined turns since
//! the last finalization, by reason. Nullify votes carry no reason, so the
//! other members' reasons are not known here.
//!
//! Logging state only: nothing here feeds consensus. It reads the tallies
//! the session's [`quil_cw_consensus::adapters::Liveness`] already keeps,
//! from the engine's retry timer.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use quil_cw_consensus::adapters::{Decisions, ViewSigners};

/// The shortest time without a finalization that is logged: shard frames
/// finalize about every 10 s, and a gap past 40 s is rarer than one in a
/// hundred.
pub(crate) const STALL_AFTER: Duration = Duration::from_secs(120);
/// How often a continuing stall is logged again.
pub(crate) const STALL_REPEAT: Duration = Duration::from_secs(300);
/// Views examined: [`quil_cw_consensus::adapters::Liveness`] keeps the
/// votes of its last 16.
const SCAN_VIEWS: u64 = 16;
/// Member indices listed per vote class; the rest are counted.
const LISTED: usize = 64;

/// One look at the running session host.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Look<'a> {
    /// The host: its session generation and the engine's host count.
    pub host: (u64, u64),
    /// The highest finalized view.
    pub finalized: u64,
    /// This member's decisions in the host so far.
    pub decided: &'a Decisions,
}

/// This member's decisions since the last finalization.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OwnDecisions {
    pub accepted: u64,
    pub refused: BTreeMap<&'static str, u64>,
    pub proposed: u64,
    pub declined: BTreeMap<&'static str, u64>,
}

impl OwnDecisions {
    pub(crate) fn refused_total(&self) -> u64 {
        self.refused.values().sum()
    }
}

/// What [`ViewStall::check`] logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StallLog {
    /// Nothing finalized for `stalled`; views after `since_view` belong to
    /// the stall.
    Stalled {
        stalled: Duration,
        repeat: bool,
        since_view: u64,
        own: OwnDecisions,
    },
    /// A logged stall ended after `stalled`, `how`.
    Ended {
        stalled: Duration,
        how: &'static str,
    },
}

/// When the running session host last finalized a view, and whether the
/// stall since was logged.
#[derive(Default)]
pub(crate) struct ViewStall {
    host: Option<(u64, u64)>,
    finalized: u64,
    progressed: Option<Instant>,
    base: Decisions,
    warned: Option<Instant>,
}

fn since(
    now: &BTreeMap<&'static str, u64>,
    then: &BTreeMap<&'static str, u64>,
) -> BTreeMap<&'static str, u64> {
    now.iter()
        .filter_map(|(reason, count)| {
            let new = count.saturating_sub(then.get(reason).copied().unwrap_or(0));
            (new > 0).then_some((*reason, new))
        })
        .collect()
}

impl ViewStall {
    /// Look at the host at `now`; `None` while no session host runs.
    pub(crate) fn check(&mut self, now: Instant, look: Option<Look<'_>>) -> Option<StallLog> {
        let Some(look) = look else {
            return self.stop(now, "its consensus host stopped");
        };
        if self.host != Some(look.host) {
            let ended = self.stop(now, "its consensus host was replaced");
            self.restart(now, look);
            return ended;
        }
        let progressed = self.progressed?;
        let stalled = now.saturating_duration_since(progressed);
        if look.finalized > self.finalized {
            let ended = self.warned.take().map(|_| StallLog::Ended {
                stalled,
                how: "a view finalized",
            });
            self.restart(now, look);
            return ended;
        }
        if stalled < STALL_AFTER {
            return None;
        }
        if self
            .warned
            .is_some_and(|warned| now.saturating_duration_since(warned) < STALL_REPEAT)
        {
            return None;
        }
        let repeat = self.warned.replace(now).is_some();
        let decided = look.decided;
        Some(StallLog::Stalled {
            stalled,
            repeat,
            since_view: self.finalized,
            own: OwnDecisions {
                accepted: decided.accepted.saturating_sub(self.base.accepted),
                refused: since(&decided.refused, &self.base.refused),
                proposed: decided.proposed.saturating_sub(self.base.proposed),
                declined: since(&decided.declined, &self.base.declined),
            },
        })
    }

    fn restart(&mut self, now: Instant, look: Look<'_>) {
        *self = Self {
            host: Some(look.host),
            finalized: look.finalized,
            progressed: Some(now),
            base: look.decided.clone(),
            warned: None,
        };
    }

    /// The host stopped at `now`, `how`: ends a logged stall.
    fn stop(&mut self, now: Instant, how: &'static str) -> Option<StallLog> {
        let ended = match (self.warned, self.progressed) {
            (Some(_), Some(progressed)) => Some(StallLog::Ended {
                stalled: now.saturating_duration_since(progressed),
                how,
            }),
            _ => None,
        };
        *self = Self::default();
        ended
    }
}

/// How the members voted in one recent view of a stall.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct StallVotes {
    /// The view whose proposal drew the most notarize votes (with more
    /// votes in all, then the later, on a tie); `None` without any vote.
    pub view: Option<u64>,
    /// Voted for its best proposal (a finalize vote counts).
    pub notarized: Vec<u32>,
    /// Voted to nullify it and for none of its proposals that were counted.
    pub nullified: Vec<u32>,
    /// No vote of theirs in it reached this node.
    pub silent: Vec<u32>,
    /// Views of the stall examined, and those with a notarize vote.
    pub views: u64,
    pub proposed_views: u64,
}

/// The members of `members` by their vote in the best of the views after
/// `since_view` up to `view`, of the last [`SCAN_VIEWS`].
pub(crate) fn stall_votes(
    members: usize,
    since_view: u64,
    view: u64,
    signers: impl Fn(u64) -> Option<ViewSigners>,
) -> StallVotes {
    let first = (since_view + 1).max(view.saturating_sub(SCAN_VIEWS - 1));
    let mut result = StallVotes::default();
    let mut best: Option<((usize, usize, u64), BTreeSet<u32>, BTreeSet<u32>)> = None;
    for scanned in first..=view {
        let Some(signers) = signers(scanned) else {
            continue;
        };
        result.views += 1;
        let notarized: BTreeSet<u32> = signers.notarize.union(&signers.finalize).copied().collect();
        if !notarized.is_empty() {
            result.proposed_views += 1;
        }
        let nullified: BTreeSet<u32> = signers.nullify.difference(&notarized).copied().collect();
        let key = (notarized.len(), notarized.len() + nullified.len(), scanned);
        if best.as_ref().is_none_or(|(best, _, _)| key > *best) {
            best = Some((key, notarized, nullified));
        }
    }
    if let Some(((_, _, at), notarized, nullified)) = best {
        result.view = Some(at);
        result.silent = (0..members as u32)
            .filter(|member| !notarized.contains(member) && !nullified.contains(member))
            .collect();
        result.notarized = notarized.into_iter().collect();
        result.nullified = nullified.into_iter().collect();
    } else {
        result.silent = (0..members as u32).collect();
    }
    result
}

/// Why a stall lasts, as one member sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StallCause {
    /// No recent view drew a notarize vote: no proposal reached the members.
    NoProposal,
    /// A proposal drew a quorum of notarize votes, yet nothing finalized.
    NotFinalizing,
    /// This member refused the proposals.
    ThisNode,
    /// Too few members notarized the proposals this member accepted.
    Members,
}

impl StallCause {
    pub(crate) fn of(
        votes: &StallVotes,
        quorum: usize,
        me: Option<u32>,
        own: &OwnDecisions,
    ) -> Self {
        if votes.notarized.is_empty() {
            StallCause::NoProposal
        } else if votes.notarized.len() >= quorum {
            StallCause::NotFinalizing
        } else if me.is_some_and(|me| !votes.notarized.contains(&me)) && own.refused_total() > 0 {
            StallCause::ThisNode
        } else {
            StallCause::Members
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            StallCause::NoProposal => "no proposal",
            StallCause::NotFinalizing => "notarized, not finalized",
            StallCause::ThisNode => "this node refuses",
            StallCause::Members => "members hold back",
        }
    }
}

/// Member indices as `0,3,7`, at most [`LISTED`] of them, then `+N`.
pub(crate) fn indices(members: &[u32]) -> String {
    let mut listed = members
        .iter()
        .take(LISTED)
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if members.len() > LISTED {
        listed.push_str(&format!(",+{}", members.len() - LISTED));
    }
    listed
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    fn decided(accepted: u64, refused: &[(&'static str, u64)]) -> Decisions {
        Decisions {
            accepted,
            refused: refused.iter().copied().collect(),
            ..Decisions::default()
        }
    }

    fn look(host: (u64, u64), finalized: u64, decided: &Decisions) -> Option<Look<'_>> {
        Some(Look {
            host,
            finalized,
            decided,
        })
    }

    /// Nothing is logged before the threshold; at it, one stall line that
    /// counts only this member's decisions since the last finalization.
    #[test]
    fn a_stall_is_logged_once_nothing_finalized_for_its_threshold() {
        let start = Instant::now();
        let at = |secs: u32| start + SECOND * secs;
        let mut stall = ViewStall::default();
        let before = decided(40, &[("not at the parent frame", 2)]);
        assert_eq!(stall.check(at(0), look((7, 1), 90, &before)), None);
        let lagging = decided(
            41,
            &[("not at the parent frame", 9), ("block not delivered", 1)],
        );
        for secs in [10, 60, 119] {
            assert_eq!(
                stall.check(at(secs), look((7, 1), 90, &lagging)),
                None,
                "no line before 120 s ({secs})"
            );
        }
        assert_eq!(
            stall.check(at(120), look((7, 1), 90, &lagging)),
            Some(StallLog::Stalled {
                stalled: SECOND * 120,
                repeat: false,
                since_view: 90,
                own: OwnDecisions {
                    accepted: 1,
                    refused: [("block not delivered", 1), ("not at the parent frame", 7)].into(),
                    proposed: 0,
                    declined: Default::default(),
                },
            })
        );
    }

    /// A continuing stall is logged again only once the repeat interval
    /// has passed since its previous line, each time with its duration.
    #[test]
    fn a_continuing_stall_repeats_at_most_once_per_interval() {
        let start = Instant::now();
        let at = |secs: u32| start + SECOND * secs;
        let mut stall = ViewStall::default();
        let none = Decisions::default();
        assert_eq!(stall.check(at(0), look((7, 1), 90, &none)), None);
        let mut lines = Vec::new();
        for secs in (10..=1_000).step_by(10) {
            if let Some(StallLog::Stalled {
                stalled, repeat, ..
            }) = stall.check(at(secs), look((7, 1), 90, &none))
            {
                lines.push((stalled.as_secs(), repeat));
            }
        }
        assert_eq!(
            lines,
            vec![(120, false), (420, true), (720, true)],
            "a line at the threshold, then one per 300 s"
        );
    }

    /// A logged stall ends with one line when a view finalizes, or when its
    /// host stops or is replaced; a finalization after no line is quiet,
    /// and a new stall counts from it.
    #[test]
    fn a_logged_stall_ends_once_when_a_view_finalizes_or_its_host_goes() {
        let start = Instant::now();
        let at = |secs: u32| start + SECOND * secs;
        let mut stall = ViewStall::default();
        let none = Decisions::default();
        assert_eq!(stall.check(at(0), look((7, 1), 90, &none)), None);
        assert_eq!(
            stall.check(at(60), look((7, 1), 91, &none)),
            None,
            "an unlogged finalization is quiet"
        );
        assert!(matches!(
            stall.check(at(180), look((7, 1), 91, &none)),
            Some(StallLog::Stalled { stalled, repeat: false, since_view: 91, .. })
                if stalled == SECOND * 120
        ));
        assert_eq!(
            stall.check(at(250), look((7, 1), 95, &none)),
            Some(StallLog::Ended {
                stalled: SECOND * 190,
                how: "a view finalized"
            })
        );
        assert_eq!(
            stall.check(at(260), look((7, 1), 96, &none)),
            None,
            "ended once"
        );
        assert!(stall.check(at(380), look((7, 1), 96, &none)).is_some());
        assert_eq!(
            stall.check(at(390), look((8, 2), 0, &none)),
            Some(StallLog::Ended {
                stalled: SECOND * 130,
                how: "its consensus host was replaced"
            })
        );
        assert_eq!(
            stall.check(at(509), look((8, 2), 0, &none)),
            None,
            "the new host counts from its start"
        );
        assert!(stall.check(at(510), look((8, 2), 0, &none)).is_some());
        assert_eq!(
            stall.check(at(520), None),
            Some(StallLog::Ended {
                stalled: SECOND * 130,
                how: "its consensus host stopped"
            })
        );
        assert_eq!(stall.check(at(530), None), None);
    }

    fn view(notarize: &[u32], nullify: &[u32], finalize: &[u32]) -> ViewSigners {
        ViewSigners {
            view: 0,
            notarize: notarize.iter().copied().collect(),
            nullify: nullify.iter().copied().collect(),
            finalize: finalize.iter().copied().collect(),
        }
    }

    /// Members are named by their vote in the stalled view closest to a
    /// quorum: a member that notarized and later nullified, as every member
    /// does once the view times out, notarized; one that only nullified
    /// held back; one without a vote here was silent. The cause follows.
    #[test]
    fn members_are_attributed_by_their_vote_in_the_view_closest_to_a_quorum() {
        // 7 members, quorum 5. View 100 finalized; views 101-104 stall.
        let recent = |at: u64| match at {
            101 => Some(view(&[0, 1], &[0, 1, 2, 3, 4], &[])),
            102 => Some(view(&[0, 1, 2, 5], &[0, 1, 2, 3, 4, 5], &[])),
            103 => Some(view(&[], &[0, 1, 2, 3], &[])),
            104 => Some(view(&[0, 2], &[], &[1])),
            _ => None,
        };
        let votes = stall_votes(7, 100, 105, recent);
        assert_eq!(
            votes,
            StallVotes {
                view: Some(102),
                notarized: vec![0, 1, 2, 5],
                nullified: vec![3, 4],
                silent: vec![6],
                views: 4,
                proposed_views: 3,
            }
        );
        let accepted = OwnDecisions {
            accepted: 3,
            ..Default::default()
        };
        assert_eq!(
            StallCause::of(&votes, 5, Some(0), &accepted),
            StallCause::Members
        );
        let refused = OwnDecisions {
            refused: [("not at the parent frame", 3)].into(),
            ..Default::default()
        };
        assert_eq!(
            StallCause::of(&votes, 5, Some(3), &refused),
            StallCause::ThisNode
        );
        assert_eq!(
            StallCause::of(&votes, 4, Some(0), &accepted),
            StallCause::NotFinalizing
        );
        assert_eq!(indices(&votes.nullified), "3,4");
        assert_eq!(
            indices(&(0..70).collect::<Vec<_>>()),
            format!("{},+6", indices(&(0..64).collect::<Vec<_>>()))
        );

        // Only nullify votes: the view with the most votes, all held back.
        let skipped = |at: u64| match at {
            101 => Some(view(&[], &[0, 1, 2], &[])),
            102 => Some(view(&[], &[0, 1], &[])),
            _ => None,
        };
        let votes = stall_votes(4, 100, 102, skipped);
        assert_eq!(
            (votes.view, votes.nullified.clone(), votes.silent.clone()),
            (Some(101), vec![0, 1, 2], vec![3])
        );
        assert_eq!(
            StallCause::of(&votes, 3, Some(0), &accepted),
            StallCause::NoProposal
        );
        // No votes at all: every member is silent.
        assert_eq!(
            stall_votes(3, 100, 120, |_| None),
            StallVotes {
                silent: vec![0, 1, 2],
                ..Default::default()
            }
        );
    }

    /// Only the views of the stall that liveness still keeps are examined.
    #[test]
    fn only_the_stalls_kept_views_are_examined() {
        let scanned = std::cell::RefCell::new(Vec::new());
        stall_votes(4, 10, 1_000, |at| {
            scanned.borrow_mut().push(at);
            None
        });
        assert_eq!(scanned.into_inner(), (985..=1_000).collect::<Vec<_>>());
        let scanned = std::cell::RefCell::new(Vec::new());
        stall_votes(4, 995, 1_000, |at| {
            scanned.borrow_mut().push(at);
            None
        });
        assert_eq!(scanned.into_inner(), (996..=1_000).collect::<Vec<_>>());
    }
}
