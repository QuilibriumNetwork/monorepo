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
}
