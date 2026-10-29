//! When a closing member republishes its seal while GLOBAL drains the sealed
//! session in parts (#699).
//!
//! A seal whose session GLOBAL has not executed through its checkpoint
//! carries the next [`MAX_DRAIN_HEADERS`] frames GLOBAL lacks, built from the
//! member's own committed view of GLOBAL (`app_handoff::drained_seal`): a
//! partial drain. GLOBAL executes one copy per seal and frame; every copy
//! built from the same view is a duplicate. On the resubmission timer alone
//! (60-89 s) a drain moved about five frames a minute and a shard that
//! sealed hundreds of frames ahead of GLOBAL spent hours draining.
//!
//! [`SealFollow`] publishes the next part as soon as this member's view shows
//! the previous one executed, in turns: the member first in line for the new
//! tip publishes at once, each next one [`FOLLOW_STEP`] later, and a turn
//! lapses when the view moves again before it comes. The line rotates with
//! the tip, so an absent member delays only the parts it heads. The timer
//! stays the fallback, counted from the last publish or view move.
//!
//! [`DrainProgress`] reports a drain that stops moving: a member whose view
//! shows no part executed for [`DRAIN_STALL_AFTER`] warns, at bounded
//! intervals while the stall lasts, and logs its end.

use crate::outage::{Outage, OutageEvent};
use quil_execution::global_intrinsic::handoff::MAX_DRAIN_HEADERS;
use std::time::{Duration, Instant};

/// Time between members' turns to publish the next part after the view
/// moves. A copy published at once lands in the next GLOBAL frame or the
/// one after (frames about 10 s apart) and each member reads its view on a
/// 10 s tick, so the first copy normally moves every member's view before
/// the second turn comes: about one copy per part while the drain moves. If
/// it does not land, the next members publish 20 s apart; from the third
/// turn (60 s) the resubmission timer covers the committee as before.
pub(crate) const FOLLOW_STEP: Duration = Duration::from_secs(20);

/// The partial drain this member last published and the view moves since.
#[derive(Debug, Default)]
pub(crate) struct SealFollow {
    /// The executed source frame the last published copy was built from,
    /// while that copy was a partial drain; `None` otherwise.
    built_from: Option<u64>,
    /// The newer executed frame this member's view shows, and when it first
    /// showed it.
    moved: Option<(u64, Instant)>,
}

impl SealFollow {
    /// A copy of the seal was published, its drain built from `executed`
    /// (`app_handoff::DrainedSeal::reason`, `executed`).
    pub(crate) fn published(&mut self, reason: &str, executed: u64) {
        self.built_from = (reason == "partial").then_some(executed);
        self.moved = None;
    }

    /// No seal to publish (none, or a successor runs).
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }

    /// Whether the last published copy was a partial drain, so the view's
    /// executed frame is worth reading.
    pub(crate) fn following(&self) -> bool {
        self.built_from.is_some()
    }

    /// When this member's view last showed the drain move: progress, from
    /// which the resubmission timer counts.
    pub(crate) fn moved_at(&self) -> Option<Instant> {
        self.moved.map(|(_, at)| at)
    }

    /// Observe the sealed session's executed frame in this member's view
    /// (`None` when unreadable: nothing changes). True when the view shows
    /// a part executed since the last published copy and this member's turn
    /// for that frame has come: at most once per executed frame, since the
    /// publish that follows records it.
    pub(crate) fn due(
        &mut self,
        executed: Option<u64>,
        rank: usize,
        members: usize,
        now: Instant,
    ) -> bool {
        let (Some(from), Some(tip)) = (self.built_from, executed) else {
            return false;
        };
        if tip <= from {
            self.moved = None;
            return false;
        }
        let since = match self.moved {
            Some((seen, at)) if seen == tip => at,
            _ => {
                self.moved = Some((tip, now));
                now
            }
        };
        now.saturating_duration_since(since) >= turn(tip, rank, members)
    }

    /// Move the recorded view move `by` into the past, as if the view had
    /// moved that much earlier.
    #[cfg(test)]
    pub(crate) fn backdate(&mut self, by: Duration) {
        if let Some((_, at)) = self.moved.as_mut() {
            *at = at.checked_sub(by).expect("an instant that far back");
        }
    }
}

/// How long the member at `rank` of `members` waits, after its view shows
/// the sealed session executed through `tip`, before it publishes the next
/// part: its place in a line that starts at a member chosen by the tip, so
/// every member computes the same line from the same view and the head of
/// the line rotates part by part.
pub(crate) fn turn(tip: u64, rank: usize, members: usize) -> Duration {
    let members = members.max(1) as u64;
    let first = (tip / MAX_DRAIN_HEADERS as u64) % members;
    let place = (rank as u64 % members + members - first) % members;
    FOLLOW_STEP.saturating_mul(u32::try_from(place).unwrap_or(u32::MAX))
}

/// How long a seal drain may go without a part executed in this member's
/// committed view of GLOBAL before it is reported as stalled: over three
/// resubmission periods (60-89 s), in which every member republished the
/// part at least twice and GLOBAL ran about thirty frames.
pub(crate) const DRAIN_STALL_AFTER: Duration = Duration::from_secs(300);

/// Whether this member's seal drain moves: from its first copy with drain
/// headers until its view shows the session executed through the
/// checkpoint, when the view last showed a part executed. A drain that
/// shows none for [`DRAIN_STALL_AFTER`] is a stall, logged at its start, at
/// most every [`OUTAGE_LOG_EVERY`](crate::outage::OUTAGE_LOG_EVERY) while it
/// lasts, and at its end ([`crate::outage`]).
#[derive(Debug, Default)]
pub(crate) struct DrainProgress {
    drain: Option<Drain>,
    stall: Outage,
}

/// A drain in progress.
#[derive(Debug)]
struct Drain {
    /// The executed frame the first copy was built from: parts count from it.
    start: u64,
    checkpoint: u64,
    /// The executed frame this member's view last showed, and since when.
    executed: u64,
    since: Instant,
    /// The committed GLOBAL frame of the view that first showed `executed`.
    global_frame: Option<u64>,
}

impl Drain {
    fn state(&self, executed: u64, now: Instant, global_frame: Option<u64>) -> DrainState {
        let part = MAX_DRAIN_HEADERS as u64;
        let parts_total = self.checkpoint.saturating_sub(self.start).div_ceil(part);
        DrainState {
            executed,
            checkpoint: self.checkpoint,
            parts_drained: executed
                .saturating_sub(self.start)
                .div_ceil(part)
                .min(parts_total),
            parts_total,
            stalled_secs: now.saturating_duration_since(self.since).as_secs(),
            global_frames: global_frame
                .zip(self.global_frame)
                .map(|(now, then)| now.saturating_sub(then)),
        }
    }
}

/// A seal drain's progress, for its stall lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DrainState {
    /// The session frame GLOBAL has executed, in this member's view.
    pub(crate) executed: u64,
    /// The sealed checkpoint frame the drain runs to.
    pub(crate) checkpoint: u64,
    /// Parts of [`MAX_DRAIN_HEADERS`] frames executed since the first copy,
    /// of the parts the drain needs.
    pub(crate) parts_drained: u64,
    pub(crate) parts_total: u64,
    /// Seconds since this member's view last showed a part executed, or
    /// since the first copy.
    pub(crate) stalled_secs: u64,
    /// GLOBAL frames this member's view advanced in that time; `None` when
    /// unknown.
    pub(crate) global_frames: Option<u64>,
}

/// A transition of a seal drain's stall worth logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainStall {
    /// No part executed for [`DRAIN_STALL_AFTER`].
    Began(DrainState),
    /// Still none, at most every
    /// [`OUTAGE_LOG_EVERY`](crate::outage::OUTAGE_LOG_EVERY).
    Continues(DrainState),
    /// The stall ended: `part_executed` when the view showed the next part
    /// executed, `drain_ended` when the seal no longer waits on a drain
    /// (recorded, published without one, or cleared).
    Ended {
        state: DrainState,
        outcome: &'static str,
    },
}

impl DrainProgress {
    /// A copy of the seal was published (`app_handoff::DrainedSeal`
    /// `reason`, `executed` and `checkpoint`): one with drain headers
    /// (`partial` or `attached`) starts tracking the drain, or shows its
    /// executed frame; any other ends it.
    pub(crate) fn published(
        &mut self,
        reason: &str,
        executed: u64,
        checkpoint: u64,
        now: Instant,
    ) -> Option<DrainStall> {
        if !matches!(reason, "partial" | "attached") {
            return self.clear(now);
        }
        if self.drain.is_none() {
            self.drain = Some(Drain {
                start: executed,
                checkpoint,
                executed,
                since: now,
                global_frame: None,
            });
            return None;
        }
        self.observe(Some(executed), None, now)
    }

    /// Whether a drain is tracked, so the view's executed frame is worth
    /// reading.
    pub(crate) fn draining(&self) -> bool {
        self.drain.is_some()
    }

    /// Observe the sealed session's executed frame in this member's
    /// committed view of GLOBAL at `global_frame` (`None` when unreadable:
    /// nothing changes). The view showing the checkpoint executed ends the
    /// drain.
    pub(crate) fn observe(
        &mut self,
        executed: Option<u64>,
        global_frame: Option<u64>,
        now: Instant,
    ) -> Option<DrainStall> {
        let (drain, executed) = (self.drain.as_mut()?, executed?);
        if executed > drain.executed {
            let state = drain.state(executed, now, global_frame);
            if executed >= drain.checkpoint {
                self.drain = None;
            } else {
                drain.executed = executed;
                drain.since = now;
                drain.global_frame = global_frame;
            }
            return self.stall.observe(now, true).map(|_| DrainStall::Ended {
                state,
                outcome: "part_executed",
            });
        }
        if drain.global_frame.is_none() {
            drain.global_frame = global_frame;
        }
        if now.saturating_duration_since(drain.since) < DRAIN_STALL_AFTER {
            return None;
        }
        let state = drain.state(drain.executed, now, global_frame);
        match self.stall.observe(now, false)? {
            OutageEvent::Began => Some(DrainStall::Began(state)),
            OutageEvent::Continues { .. } => Some(DrainStall::Continues(state)),
            OutageEvent::Ended { .. } => None,
        }
    }

    /// The seal no longer waits on a drain: stop tracking it, ending a
    /// stall.
    pub(crate) fn clear(&mut self, now: Instant) -> Option<DrainStall> {
        let drain = self.drain.take()?;
        let state = drain.state(drain.executed, now, None);
        self.stall.observe(now, true).map(|_| DrainStall::Ended {
            state,
            outcome: "drain_ended",
        })
    }

    /// Move the drain's last progress `by` into the past.
    #[cfg(test)]
    pub(crate) fn backdate(&mut self, by: Duration) {
        if let Some(drain) = self.drain.as_mut() {
            drain.since = drain
                .since
                .checked_sub(by)
                .expect("an instant that far back");
        }
    }
}

/// Whose problem a stalled drain is, from this member's committed view of
/// GLOBAL: the `scope` and `action` of [`crate::outage`], and what the drain
/// waits on. GLOBAL frames advancing without the next part mean GLOBAL does
/// not execute the committee's copies; a view stuck behind this node's
/// latest GLOBAL frame means this worker's view lags; otherwise GLOBAL has
/// not advanced in this node's view.
pub(crate) fn stall_scope(
    global_frames: Option<u64>,
    committed_frame: Option<u64>,
    latest_global_frame: Option<u64>,
) -> (&'static str, &'static str, &'static str) {
    if global_frames.is_some_and(|frames| frames > 0) {
        return (
            "network",
            "report",
            "GLOBAL to execute the next part: GLOBAL frames advance without it, so the \
             committee's seal copies are not executed; report this line",
        );
    }
    match (committed_frame, latest_global_frame) {
        (Some(committed), Some(latest)) if latest > committed => (
            "local",
            "check",
            "this worker's committed GLOBAL view, which trails this node's latest GLOBAL \
             frame; check this worker's prover-tree sync",
        ),
        _ => (
            "network",
            "wait",
            "GLOBAL frames, which have not advanced in this node's view; ends when GLOBAL \
             executes the next part",
        ),
    }
}

/// GLOBAL frames after the latest one this node holds a header of within
/// which a seal copy published then lands: the next or the one after
/// ([`FOLLOW_STEP`]).
pub(crate) const SEAL_LANDS_WITHIN: u64 = 2;

/// The GLOBAL frame an early pull for a sealed session awaiting its
/// successor must reach (`crate::global_view_refresh`): the frame below the
/// latest header `head`, whose prover root binds the state before it, but
/// no earlier than the frame the last seal copy lands by, published while
/// `published_head` was the latest. A pull reaching an earlier frame can
/// show neither the seal nor the drain part it carried, and the next
/// request waits a minute behind it.
pub(crate) fn successor_pull_through(head: u64, published_head: Option<u64>) -> u64 {
    let reach = head.saturating_sub(1);
    published_head.map_or(reach, |published| {
        reach.max(published.saturating_add(SEAL_LANDS_WITHIN))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The members' turns for one tip are 0, 20, 40, … s, one member each,
    /// and the head of the line moves to the next member with the next part.
    #[test]
    fn turns_are_a_rotating_line_one_step_apart() {
        let members = 7;
        for tip in [0u64, 8, 16, 24, 23_266, 23_274] {
            let mut turns: Vec<Duration> =
                (0..members).map(|rank| turn(tip, rank, members)).collect();
            turns.sort();
            assert_eq!(
                turns,
                (0..members as u32)
                    .map(|place| FOLLOW_STEP * place)
                    .collect::<Vec<_>>(),
                "tip {tip}: one member per turn"
            );
            let head = (0..members)
                .find(|&rank| turn(tip, rank, members).is_zero())
                .unwrap();
            let next = (0..members)
                .find(|&rank| turn(tip + 8, rank, members).is_zero())
                .unwrap();
            assert_eq!(
                next,
                (head + 1) % members,
                "the next part has the next head"
            );
        }
        assert_eq!(turn(40, 3, 1), Duration::ZERO, "a lone member never waits");
        assert_eq!(turn(40, 3, 0), Duration::ZERO, "no member list: no wait");
    }

    /// The bound: a member follows once per executed frame its view shows,
    /// only after a partial drain, only once its turn comes, and its turn
    /// restarts when the view moves again first.
    #[test]
    fn a_member_follows_once_per_view_move_in_its_turn() {
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let members = 4;
        // Rank whose turn for tip 16 is the second (20 s).
        let rank = (0..members)
            .find(|&rank| turn(16, rank, members) == FOLLOW_STEP)
            .unwrap();
        let mut follow = SealFollow::default();
        assert!(
            !follow.due(Some(16), rank, members, at(0)),
            "nothing published yet"
        );
        follow.published("attached", 8);
        assert!(
            !follow.due(Some(16), rank, members, at(0)),
            "a full drain is not followed"
        );
        follow.published("partial", 8);
        assert!(follow.following());
        assert!(
            !follow.due(Some(8), rank, members, at(1)),
            "the view has not moved"
        );
        assert!(
            !follow.due(None, rank, members, at(2)),
            "an unreadable view changes nothing"
        );
        assert_eq!(follow.moved_at(), None);
        assert!(
            !follow.due(Some(16), rank, members, at(3)),
            "moved: the turn starts"
        );
        assert_eq!(follow.moved_at(), Some(at(3)));
        assert!(
            !follow.due(Some(16), rank, members, at(22)),
            "19 s into a 20 s turn"
        );
        assert!(follow.due(Some(16), rank, members, at(23)), "the turn came");
        // The publish records the new part; the same view is not followed again.
        follow.published("partial", 16);
        for secs in 23..200 {
            assert!(
                !follow.due(Some(16), rank, members, at(secs)),
                "once per view move"
            );
        }
        // The view moves twice before this member's turn: the turn restarts
        // with each move, so a moving drain needs no copy from this member.
        let rank24 = (0..members)
            .find(|&rank| turn(24, rank, members) == FOLLOW_STEP * 2)
            .unwrap();
        follow.published("partial", 16);
        assert!(!follow.due(Some(24), rank24, members, at(200)));
        assert!(!follow.due(Some(24), rank24, members, at(230)));
        assert!(
            !follow.due(Some(32), rank24, members, at(235)),
            "moved again"
        );
        assert_eq!(follow.moved_at(), Some(at(235)));
        assert_eq!(turn(32, rank24, members), FOLLOW_STEP);
        assert!(!follow.due(Some(32), rank24, members, at(254)));
        assert!(follow.due(Some(32), rank24, members, at(255)));
        follow.clear();
        assert!(!follow.following());
        assert!(!follow.due(Some(64), rank24, members, at(300)), "cleared");
    }

    /// Worst case per executed frame: a committee of `members` sends at most
    /// one copy per member, and only `elapsed / FOLLOW_STEP + 1` before the
    /// view moves again, against one per member per 60-89 s on the timer.
    #[test]
    fn a_committee_sends_at_most_one_copy_per_turn_elapsed() {
        let members = 16;
        let t0 = Instant::now();
        for lived in [0u64, 10, 19, 20, 45, 59, 600] {
            let mut copies = 0;
            for rank in 0..members {
                let mut follow = SealFollow::default();
                follow.published("partial", 8);
                let mut sent = false;
                for secs in (0..=lived).step_by(10) {
                    if follow.due(Some(16), rank, members, t0 + Duration::from_secs(secs)) {
                        assert!(!sent, "at most once per view move");
                        sent = true;
                        follow.published("partial", 16);
                    }
                }
                copies += usize::from(sent);
            }
            let bound = (lived / FOLLOW_STEP.as_secs() + 1).min(members as u64) as usize;
            assert_eq!(copies, bound, "the view stayed {lived} s on one part");
        }
    }

    /// A drain whose view shows no part executed for [`DRAIN_STALL_AFTER`]
    /// stalls: it begins once, repeats at most every ten minutes with its
    /// duration, and ends when a part executes; the bound then counts from
    /// that part. The checkpoint executed, or a seal without a drain, ends
    /// the drain.
    #[test]
    fn a_drain_without_a_part_executed_past_the_bound_stalls_and_recovers() {
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let bound = DRAIN_STALL_AFTER.as_secs();
        let repeat = crate::outage::OUTAGE_LOG_EVERY.as_secs();
        let state = |executed, parts_drained, stalled_secs, global_frames| DrainState {
            executed,
            checkpoint: 40,
            parts_drained,
            parts_total: 5,
            stalled_secs,
            global_frames,
        };
        let mut progress = DrainProgress::default();
        assert_eq!(
            progress.observe(Some(0), Some(100), at(0)),
            None,
            "no drain"
        );
        assert!(!progress.draining());
        assert_eq!(progress.published("partial", 0, 40, at(0)), None);
        assert!(progress.draining());
        // Republished on the timer; GLOBAL halted at frame 100.
        assert_eq!(progress.published("partial", 0, 40, at(70)), None);
        for secs in (10..bound).step_by(10) {
            assert_eq!(progress.observe(Some(0), Some(100), at(secs)), None);
        }
        assert_eq!(progress.observe(None, None, at(bound)), None, "unreadable");
        assert_eq!(
            progress.observe(Some(0), Some(100), at(bound)),
            Some(DrainStall::Began(state(0, 0, bound, Some(0))))
        );
        for secs in (bound + 10..bound + repeat).step_by(10) {
            assert_eq!(
                progress.observe(Some(0), Some(100), at(secs)),
                None,
                "{secs}"
            );
        }
        assert_eq!(
            progress.observe(Some(0), Some(100), at(bound + repeat)),
            Some(DrainStall::Continues(state(0, 0, bound + repeat, Some(0))))
        );
        // GLOBAL resumes and executes the first part.
        let moved = bound + repeat + 5;
        assert_eq!(
            progress.observe(Some(8), Some(101), at(moved)),
            Some(DrainStall::Ended {
                state: state(8, 1, moved, Some(1)),
                outcome: "part_executed",
            })
        );
        assert_eq!(progress.published("partial", 8, 40, at(moved)), None);
        // The bound counts from that part. GLOBAL advances without the next.
        assert_eq!(
            progress.observe(Some(8), Some(110), at(moved + bound - 1)),
            None
        );
        assert_eq!(
            progress.observe(Some(8), Some(131), at(moved + bound)),
            Some(DrainStall::Began(state(8, 1, bound, Some(30))))
        );
        // Parts executed a minute apart: no stall.
        let mut secs = moved + bound;
        for executed in [16u64, 24, 32] {
            secs += 60;
            let event = progress.observe(Some(executed), Some(140), at(secs));
            assert_eq!(event.is_some(), executed == 16, "{executed}: {event:?}");
        }
        assert_eq!(progress.published("attached", 32, 40, at(secs)), None);
        assert!(progress.draining(), "the last part is still a part");
        assert_eq!(progress.observe(Some(40), Some(150), at(secs + 10)), None);
        assert!(!progress.draining(), "executed through the checkpoint");
        assert_eq!(progress.observe(Some(40), Some(150), at(secs + 900)), None);

        // A stall the seal settles without a part: its end is logged.
        let mut progress = DrainProgress::default();
        assert_eq!(progress.published("partial", 0, 40, at(0)), None);
        assert!(progress.observe(Some(0), Some(100), at(bound)).is_some());
        assert_eq!(
            progress.published("executed", 0, 40, at(bound + 1)),
            Some(DrainStall::Ended {
                state: state(0, 0, bound + 1, None),
                outcome: "drain_ended",
            })
        );
        assert!(!progress.draining());
        assert_eq!(progress.published("attached", 32, 40, at(0)), None);
        assert_eq!(progress.clear(at(10)), None, "no stall, nothing to log");
    }

    /// The stall's scope: GLOBAL moving without the part, this worker's
    /// view behind, or GLOBAL not moving here.
    #[test]
    fn a_stall_names_whose_problem_it_is() {
        assert_eq!(stall_scope(Some(3), Some(10), Some(10)).0, "network");
        assert_eq!(stall_scope(Some(3), Some(10), Some(10)).1, "report");
        assert_eq!(stall_scope(Some(0), Some(10), Some(40)).0, "local");
        assert_eq!(stall_scope(None, Some(10), Some(40)).1, "check");
        assert_eq!(stall_scope(Some(0), Some(10), Some(10)).1, "wait");
        assert_eq!(stall_scope(Some(0), Some(10), None).1, "wait");
    }

    /// A sealed member's early pull reaches no GLOBAL frame before the one
    /// its last seal copy lands by: such a pull shows neither the seal nor
    /// the drain part it carried.
    #[test]
    fn a_successor_pull_reaches_no_frame_before_the_seal_copy_lands() {
        use crate::global_view_refresh::{Decision, EarlyPull, Reason, ViewRefresh};
        assert_eq!(successor_pull_through(1001, None), 1000);
        assert_eq!(successor_pull_through(1001, Some(1000)), 1002);
        assert_eq!(successor_pull_through(1010, Some(1000)), 1009);
        let refresh = ViewRefresh::default();
        refresh.enable(720);
        let now = Instant::now();
        // Asked just after the copy went out with header 1000 the latest.
        refresh.request(
            Reason::SealedSessionAwaitsSuccessor,
            successor_pull_through(1001, Some(1000)),
            now,
        );
        assert_eq!(
            refresh.decide(Some(990), Some(1001), now),
            Decision::Idle,
            "a pull now reaches frame 1000, before the copy can have executed"
        );
        assert_eq!(
            refresh.decide(Some(990), Some(1003), now),
            Decision::Pull(EarlyPull {
                reason: Reason::SealedSessionAwaitsSuccessor,
                through: 1002,
            }),
            "once a header binds the frame the copy lands by"
        );
    }
}
