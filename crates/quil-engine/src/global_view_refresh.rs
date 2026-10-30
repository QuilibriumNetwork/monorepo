//! Early refreshes of a regular node's committed GLOBAL view.
//!
//! A node that does not execute GLOBAL frames reads committee handoff state
//! (closing requests, seals, successor activations) from the prover shard it
//! pulls from an archive, pinned to a finalized header's prover root. The
//! periodic pull runs every few minutes, so at an epoch boundary this node's
//! in-process workers saw the boundary's closing requests minutes after
//! leaders whose view was fresher, refused their seals, and started their
//! successors a pull later still.
//!
//! [`ViewRefresh`] lets the sync task pull early: when the GLOBAL head has
//! passed an epoch boundary the committed view has not, when a seal arrives
//! whose closing request the view lacks, and (at most every
//! [`SUCCESSOR_INTERVAL`]) while a sealed session awaits its successor, also
//! for a worker the closing session does not seat and the successor does, and
//! while a hash storage proof record this node waits for is not in its view:
//! its shard's snapshot, which a renewal encodes, its own registration, which
//! it seals, or a seal or settlement it sent (its proposals commit roots only
//! once it sees its seal). Early
//! pulls are capped per epoch, with sub-caps for seals and successors; they
//! start [`MIN_GAP`] after the previous pull ended, except once for each frame
//! a waiting seal needs.

use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Idle time between the end of a pull and the start of an early one. A seal
/// waiting for its vote skips it once for each frame it needs, whichever
/// reason the pull is for.
pub const MIN_GAP: Duration = Duration::from_secs(20);

/// Early pulls per epoch (of the frame the pull reaches); the periodic pull
/// continues after them.
pub const MAX_PER_EPOCH: u32 = 16;

/// Of [`MAX_PER_EPOCH`], the pulls sealed sessions awaiting their successors
/// may use: one a minute covers a twelve-minute wait for a slow frame, and
/// the rest stays for seals and the boundary.
pub const SUCCESSOR_PER_EPOCH: u32 = 12;

/// Of [`MAX_PER_EPOCH`], the pulls waiting seals may use, so a leader whose
/// seals no closing request ever authorizes cannot spend the pulls of the
/// epoch's boundary and successors.
pub const SEAL_PER_EPOCH: u32 = 8;

/// Shortest time between two requests of sealed sessions awaiting their
/// successors (they ask on every start retry).
pub const SUCCESSOR_INTERVAL: Duration = Duration::from_secs(60);

/// Of [`MAX_PER_EPOCH`], the pulls hash storage proof records may use: a
/// shard's snapshot, this node's registration, and the seals and settlements
/// it sent, each recorded once per epoch. A request names the frame the view
/// must reach; requests add up, and [`MIN_GAP`] spaces the pulls.
pub const STORAGE_PER_EPOCH: u32 = 12;

/// How often the sync task checks whether an early pull is due.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    EpochBoundary,
    SealBeforeClosingRequest,
    SealedSessionAwaitsSuccessor,
    StorageRecordAwaited,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EpochBoundary => "epoch boundary",
            Self::SealBeforeClosingRequest => "seal before its closing request",
            Self::SealedSessionAwaitsSuccessor => "sealed session awaits its successor",
            Self::StorageRecordAwaited => {
                "storage snapshot, seal or settlement not in the view yet"
            }
        }
    }
}

/// An early pull: why, and the GLOBAL frame the committed view must reach
/// (the state after executing it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EarlyPull {
    pub reason: Reason,
    pub through: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Nothing newer is needed, or the last pull ended too recently.
    Idle,
    Pull(EarlyPull),
    /// A pull is wanted but its budget for this epoch is spent; reported once
    /// per epoch.
    Exhausted {
        epoch: u64,
        wanted: EarlyPull,
        max: u32,
    },
}

#[derive(Debug, Default)]
struct State {
    /// Set once this process's sync task honours requests.
    epoch_length: Option<u64>,
    seal: Option<u64>,
    successor: Option<u64>,
    successor_asked: Option<Instant>,
    storage: Option<u64>,
    /// The frame the pull in progress reaches.
    running: Option<u64>,
    last_end: Option<Instant>,
    epoch: u64,
    used: u32,
    successor_used: u32,
    seal_used: u32,
    storage_used: u32,
    /// The highest seal frame a pull already skipped the gap for.
    seal_skipped: Option<u64>,
    /// Spent budgets reported this epoch: all early pulls, the successors',
    /// the seals', the storage records'.
    reported: [bool; 4],
}

/// The sync task's early-pull state, shared with the sessions that ask.
#[derive(Debug, Default)]
pub struct ViewRefresh {
    state: Mutex<State>,
}

static SHARED: LazyLock<Arc<ViewRefresh>> = LazyLock::new(Default::default);

/// This process's instance: its sync task and in-process workers share it.
pub fn shared() -> Arc<ViewRefresh> {
    SHARED.clone()
}

/// Marks a pull as running until dropped.
pub struct PullGuard(Arc<ViewRefresh>);

impl Drop for PullGuard {
    fn drop(&mut self) {
        self.0.end(Instant::now());
    }
}

impl ViewRefresh {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether this process's sync task honours requests.
    pub fn enabled(&self) -> bool {
        self.lock().epoch_length.is_some()
    }

    /// The sync task of this process pulls early on request: a regular node
    /// with committee sessions. Elsewhere requests are not honoured.
    pub fn enable(&self, epoch_length: u64) {
        self.lock().epoch_length = Some(epoch_length.max(1));
    }

    /// Ask for a pull whose committed view reaches `through`. Returns whether
    /// one is expected within moments: the pull in progress reaches it, or
    /// none runs and the epoch's budget allows one. A sealed session's
    /// request inside [`SUCCESSOR_INTERVAL`] of the last is dropped.
    pub fn request(&self, reason: Reason, through: u64, now: Instant) -> bool {
        let mut guard = self.lock();
        let state = &mut *guard;
        let Some(length) = state.epoch_length else {
            return false;
        };
        let slot = match reason {
            Reason::EpochBoundary => return false,
            Reason::SealBeforeClosingRequest => &mut state.seal,
            Reason::SealedSessionAwaitsSuccessor => {
                if state
                    .successor_asked
                    .is_some_and(|at| now.saturating_duration_since(at) < SUCCESSOR_INTERVAL)
                {
                    return false;
                }
                state.successor_asked = Some(now);
                &mut state.successor
            }
            Reason::StorageRecordAwaited => &mut state.storage,
        };
        let wanted = slot.map_or(through, |frame| frame.max(through));
        *slot = Some(wanted);
        if let Some(reach) = state.running {
            return reach >= through;
        }
        if state.epoch != through / length {
            // The epoch's budgets reset at the next decision.
            return true;
        }
        let gap_over = state
            .last_end
            .map_or(true, |end| now.saturating_duration_since(end) >= MIN_GAP);
        state.used < MAX_PER_EPOCH
            && (reason != Reason::StorageRecordAwaited || state.storage_used < STORAGE_PER_EPOCH)
            && (reason != Reason::SealBeforeClosingRequest
                || (state.seal_used < SEAL_PER_EPOCH
                    && (gap_over || state.seal_skipped.map_or(true, |skipped| wanted > skipped))))
    }

    /// The pending request of `reason`, if any.
    pub fn requested(&self, reason: Reason) -> Option<u64> {
        let state = self.lock();
        match reason {
            Reason::EpochBoundary => None,
            Reason::SealBeforeClosingRequest => state.seal,
            Reason::SealedSessionAwaitsSuccessor => state.successor,
            Reason::StorageRecordAwaited => state.storage,
        }
    }

    /// Drop the requests a committed view at `view` satisfies.
    pub fn settle(&self, view: u64) {
        let mut guard = self.lock();
        let state = &mut *guard;
        for slot in [&mut state.seal, &mut state.successor, &mut state.storage] {
            if slot.is_some_and(|through| through <= view) {
                *slot = None;
            }
        }
    }

    /// A pull reaching `reach` started (periodic or early).
    pub fn begin(&self, reach: u64) {
        self.lock().running = Some(reach);
    }

    /// The pull in progress ended at `now`.
    pub fn end(&self, now: Instant) {
        let mut state = self.lock();
        state.running = None;
        state.last_end = Some(now);
    }

    /// [`Self::begin`], ended when the guard drops.
    pub fn pull(self: &Arc<Self>, reach: u64) -> PullGuard {
        self.begin(reach);
        PullGuard(self.clone())
    }

    /// Whether an early pull should start now. `view` is the committed view's
    /// frame, `head` the latest finalized GLOBAL header (whose prover root
    /// binds the state before it, so a pull now reaches `head - 1`). Counts a
    /// returned pull against the budget.
    pub fn decide(&self, view: Option<u64>, head: Option<u64>, now: Instant) -> Decision {
        let mut guard = self.lock();
        let state = &mut *guard;
        let Some(length) = state.epoch_length else {
            return Decision::Idle;
        };
        // Without a committed view the periodic pull establishes one.
        let (Some(view), Some(head)) = (view, head) else {
            return Decision::Idle;
        };
        let reach = head.saturating_sub(1);
        if state.running.is_some() || reach <= view {
            return Decision::Idle;
        }
        let epoch = reach / length;
        if epoch != state.epoch {
            state.epoch = epoch;
            state.used = 0;
            state.successor_used = 0;
            state.seal_used = 0;
            state.storage_used = 0;
            state.reported = [false; 4];
        }
        let boundary = epoch * length;
        let pending =
            |slot: Option<u64>| slot.filter(|through| *through > view && *through <= reach);
        let wanted = if view < boundary {
            EarlyPull {
                reason: Reason::EpochBoundary,
                through: boundary,
            }
        } else if let Some(through) = pending(state.seal) {
            EarlyPull {
                reason: Reason::SealBeforeClosingRequest,
                through,
            }
        } else if let Some(through) = pending(state.successor) {
            EarlyPull {
                reason: Reason::SealedSessionAwaitsSuccessor,
                through,
            }
        } else if let Some(through) = pending(state.storage) {
            EarlyPull {
                reason: Reason::StorageRecordAwaited,
                through,
            }
        } else {
            return Decision::Idle;
        };
        // A waiting seal skips the gap once for each frame it needs, while its
        // budget lasts, whichever reason the pull is for: any pull reaches it.
        let seal_skip = pending(state.seal).filter(|through| {
            state.seal_used < SEAL_PER_EPOCH
                && state
                    .seal_skipped
                    .map_or(true, |skipped| *through > skipped)
        });
        let gap_over = state
            .last_end
            .map_or(true, |end| now.saturating_duration_since(end) >= MIN_GAP);
        if !gap_over && seal_skip.is_none() {
            return Decision::Idle;
        }
        let successor = wanted.reason == Reason::SealedSessionAwaitsSuccessor;
        let seal = wanted.reason == Reason::SealBeforeClosingRequest;
        let storage = wanted.reason == Reason::StorageRecordAwaited;
        // A sub-budget that is spent drops its request, so it does not wait
        // ahead of the epoch's other handoffs.
        let spent = if state.used >= MAX_PER_EPOCH {
            Some((0, MAX_PER_EPOCH))
        } else if successor && state.successor_used >= SUCCESSOR_PER_EPOCH {
            state.successor = None;
            Some((1, SUCCESSOR_PER_EPOCH))
        } else if seal && state.seal_used >= SEAL_PER_EPOCH {
            state.seal = None;
            Some((2, SEAL_PER_EPOCH))
        } else if storage && state.storage_used >= STORAGE_PER_EPOCH {
            state.storage = None;
            Some((3, STORAGE_PER_EPOCH))
        } else {
            None
        };
        if let Some((budget, max)) = spent {
            if std::mem::replace(&mut state.reported[budget], true) {
                return Decision::Idle;
            }
            return Decision::Exhausted { epoch, wanted, max };
        }
        state.used += 1;
        if successor {
            state.successor_used += 1;
        }
        if seal {
            state.seal_used += 1;
        }
        if storage {
            state.storage_used += 1;
        }
        if !gap_over {
            state.seal_skipped = seal_skip;
        }
        Decision::Pull(wanted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: u64 = 720;
    const SEAL: Reason = Reason::SealBeforeClosingRequest;
    const SUCCESSOR: Reason = Reason::SealedSessionAwaitsSuccessor;

    fn enabled() -> ViewRefresh {
        let refresh = ViewRefresh::default();
        refresh.enable(EPOCH);
        refresh
    }

    fn pull(reason: Reason, through: u64) -> Decision {
        Decision::Pull(EarlyPull { reason, through })
    }

    #[test]
    fn a_head_past_an_epoch_boundary_pulls_once_the_boundary_frame_is_bindable() {
        let refresh = enabled();
        let now = Instant::now();
        // The boundary frame 922320's own header binds the state before it.
        assert_eq!(
            refresh.decide(Some(922315), Some(922320), now),
            Decision::Idle
        );
        assert_eq!(
            refresh.decide(Some(922315), Some(922321), now),
            pull(Reason::EpochBoundary, 922320)
        );
        refresh.begin(922320);
        assert_eq!(
            refresh.decide(Some(922315), Some(922322), now),
            Decision::Idle,
            "one pull at a time"
        );
        refresh.end(now);
        // Once the view holds the boundary, the head moving on is periodic work.
        assert_eq!(
            refresh.decide(Some(922320), Some(922330), now + MIN_GAP * 2),
            Decision::Idle
        );
    }

    /// A storage record this node waits for (a renewal's snapshot, its
    /// registration, a seal it sent) pulls early once the view can reach the
    /// frame asked for, [`MIN_GAP`] after the last pull and at most
    /// [`STORAGE_PER_EPOCH`] times an epoch; a view holding that frame drops
    /// the request.
    #[test]
    fn an_awaited_storage_record_pulls_early_within_its_budget() {
        const SNAPSHOT: Reason = Reason::StorageRecordAwaited;
        let refresh = enabled();
        let mut now = Instant::now();
        let view = 922330;
        assert!(refresh.request(SNAPSHOT, 922340, now));
        assert!(refresh.request(SNAPSHOT, 922338, now), "requests add up");
        assert_eq!(refresh.requested(SNAPSHOT), Some(922340));
        assert_eq!(
            refresh.decide(Some(view), Some(922340), now),
            Decision::Idle,
            "not bindable yet"
        );
        assert_eq!(
            refresh.decide(Some(view), Some(922341), now),
            pull(SNAPSHOT, 922340)
        );
        refresh.begin(922340);
        refresh.end(now);
        refresh.settle(922340);
        assert_eq!(refresh.requested(SNAPSHOT), None, "the view reached it");
        assert!(refresh.request(SNAPSHOT, 922341, now));
        assert_eq!(
            refresh.decide(Some(922340), Some(922342), now),
            Decision::Idle,
            "a pull just ended"
        );
        assert_eq!(
            refresh.decide(Some(922340), Some(922342), now + MIN_GAP),
            pull(SNAPSHOT, 922341)
        );
        for pulls in 2..STORAGE_PER_EPOCH {
            now += MIN_GAP;
            let through = 922340 + u64::from(pulls);
            assert!(refresh.request(SNAPSHOT, through, now));
            assert_eq!(
                refresh.decide(Some(view), Some(through + 1), now + MIN_GAP),
                pull(SNAPSHOT, through)
            );
        }
        now += MIN_GAP;
        assert!(
            !refresh.request(SNAPSHOT, 922360, now),
            "the epoch's storage pulls are spent"
        );
        assert!(matches!(
            refresh.decide(Some(view), Some(922361), now + MIN_GAP),
            Decision::Exhausted {
                max: STORAGE_PER_EPOCH,
                ..
            }
        ));
        assert_eq!(
            refresh.requested(SNAPSHOT),
            None,
            "a spent budget drops its request"
        );
    }

    /// A record awaited on every frame (a renewal waiting for its snapshot)
    /// asks for the frame before the head each time: a pull reaches it, so
    /// pulls repeat [`MIN_GAP`] apart, where asking for the head itself
    /// stayed one frame out of reach.
    #[test]
    fn a_record_awaited_every_frame_pulls_every_gap() {
        const STORAGE: Reason = Reason::StorageRecordAwaited;
        let refresh = enabled();
        let mut now = Instant::now();
        let (mut view, mut pulls) = (922330u64, 0);
        for head in 922331..922350u64 {
            refresh.request(STORAGE, head - 1, now);
            if let Decision::Pull(EarlyPull { through, .. }) =
                refresh.decide(Some(view), Some(head), now)
            {
                assert_eq!(through, head - 1);
                pulls += 1;
                refresh.begin(head - 1);
                refresh.end(now);
                view = head - 1;
                refresh.settle(view);
            }
            now += MIN_GAP / 2;
        }
        assert_eq!(
            pulls, 9,
            "one pull per gap (every other frame here) while the record is awaited"
        );
    }

    #[test]
    fn a_node_that_does_not_honour_requests_never_pulls_early_or_waits() {
        let refresh = ViewRefresh::default();
        let now = Instant::now();
        assert!(!refresh.request(SEAL, 922330, now));
        assert_eq!(refresh.requested(SEAL), None);
        assert_eq!(
            refresh.decide(Some(922315), Some(922331), now),
            Decision::Idle
        );
    }

    #[test]
    fn the_gap_runs_from_the_end_of_a_long_pull() {
        let refresh = enabled();
        let start = Instant::now();
        // A 35 s pull that did not converge: the view is still before the boundary.
        refresh.begin(922320);
        refresh.end(start + Duration::from_secs(35));
        let ended = start + Duration::from_secs(35);
        assert_eq!(
            refresh.decide(Some(922315), Some(922322), start + MIN_GAP),
            Decision::Idle
        );
        assert_eq!(
            refresh.decide(Some(922315), Some(922322), ended + MIN_GAP / 2),
            Decision::Idle
        );
        assert_eq!(
            refresh.decide(Some(922315), Some(922322), ended + MIN_GAP),
            pull(Reason::EpochBoundary, 922320)
        );
    }

    #[test]
    fn a_seal_request_pulls_without_the_gap_once_the_head_can_reach_it() {
        let refresh = enabled();
        let now = Instant::now();
        refresh.end(now);
        assert!(refresh.request(SEAL, 922330, now));
        assert_eq!(
            refresh.decide(Some(922325), Some(922330), now),
            Decision::Idle,
            "frame 922330 not bindable yet"
        );
        assert_eq!(
            refresh.decide(Some(922325), Some(922331), now),
            pull(SEAL, 922330)
        );
        // A view that already holds the frame needs nothing.
        refresh.settle(922330);
        assert_eq!(refresh.requested(SEAL), None);
        assert_eq!(
            refresh.decide(Some(922330), Some(922340), now + MIN_GAP),
            Decision::Idle
        );
    }

    #[test]
    fn a_request_says_whether_a_pull_will_reach_it_soon() {
        let refresh = enabled();
        let now = Instant::now();
        refresh.begin(922330);
        assert!(
            refresh.request(SEAL, 922330, now),
            "the running pull reaches it"
        );
        assert!(
            !refresh.request(SEAL, 922331, now),
            "the next pull starts only after this one"
        );
        refresh.end(now);
        assert!(refresh.request(SEAL, 922331, now));
        assert_eq!(
            refresh.requested(SEAL),
            Some(922331),
            "the highest frame is kept"
        );
    }

    #[test]
    fn a_sealed_session_asks_at_most_once_a_minute_within_its_own_budget() {
        let refresh = enabled();
        let mut now = Instant::now();
        refresh.request(SUCCESSOR, 922330, now);
        refresh.request(SUCCESSOR, 922340, now + SUCCESSOR_INTERVAL / 2);
        assert_eq!(
            refresh.requested(SUCCESSOR),
            Some(922330),
            "a retry inside the interval is dropped"
        );
        let mut view = 922325;
        for _ in 0..SUCCESSOR_PER_EPOCH {
            refresh.request(SUCCESSOR, view + 5, now);
            assert_eq!(
                refresh.decide(Some(view), Some(view + 6), now),
                pull(SUCCESSOR, view + 5)
            );
            refresh.end(now);
            view += 5;
            refresh.settle(view);
            now += SUCCESSOR_INTERVAL;
        }
        refresh.request(SUCCESSOR, view + 5, now);
        let spent = Decision::Exhausted {
            epoch: 922320 / EPOCH,
            wanted: EarlyPull {
                reason: SUCCESSOR,
                through: view + 5,
            },
            max: SUCCESSOR_PER_EPOCH,
        };
        assert_eq!(refresh.decide(Some(view), Some(view + 6), now), spent);
        // The epoch's other handoffs keep their pulls.
        refresh.request(SEAL, view + 5, now);
        assert_eq!(
            refresh.decide(Some(view), Some(view + 6), now),
            pull(SEAL, view + 5)
        );
    }

    #[test]
    fn successor_waits_pull_a_minute_apart_for_twelve_minutes_within_the_total() {
        let refresh = enabled();
        let mut now = Instant::now();
        let mut view = 922325;
        for n in 0..12 {
            refresh.request(SUCCESSOR, view + 5, now);
            assert_eq!(
                refresh.decide(Some(view), Some(view + 6), now),
                pull(SUCCESSOR, view + 5),
                "successor pull {}",
                n + 1
            );
            refresh.end(now);
            view += 5;
            now += SUCCESSOR_INTERVAL;
        }
        refresh.request(SUCCESSOR, view + 5, now);
        let spent = Decision::Exhausted {
            epoch: 922320 / EPOCH,
            wanted: EarlyPull {
                reason: SUCCESSOR,
                through: view + 5,
            },
            max: 12,
        };
        assert_eq!(refresh.decide(Some(view), Some(view + 6), now), spent);
        // Seals keep the rest of the total, and the total still stops.
        for _ in 0..4 {
            refresh.request(SEAL, view + 1, now);
            assert_eq!(
                refresh.decide(Some(view), Some(view + 2), now),
                pull(SEAL, view + 1)
            );
            refresh.end(now);
            view += 1;
            now += MIN_GAP;
        }
        refresh.request(SEAL, view + 1, now);
        let all = Decision::Exhausted {
            epoch: 922320 / EPOCH,
            wanted: EarlyPull {
                reason: SEAL,
                through: view + 1,
            },
            max: 16,
        };
        assert_eq!(refresh.decide(Some(view), Some(view + 2), now), all);
    }

    #[test]
    fn early_pulls_stop_at_the_epoch_budget_and_resume_next_epoch() {
        let refresh = enabled();
        let mut now = Instant::now();
        let boundary = 1281 * EPOCH;
        // Boundary pulls that do not converge, then seals.
        for head in boundary + 1..boundary + 1 + 8 {
            assert_eq!(
                refresh.decide(Some(boundary - 5), Some(head), now),
                pull(Reason::EpochBoundary, boundary)
            );
            refresh.end(now);
            now += MIN_GAP;
        }
        let mut view = boundary;
        for _ in 0..SEAL_PER_EPOCH {
            refresh.request(SEAL, view + 1, now);
            assert_eq!(
                refresh.decide(Some(view), Some(view + 2), now),
                pull(SEAL, view + 1)
            );
            refresh.end(now);
            view += 1;
            now += MIN_GAP;
        }
        assert!(
            !refresh.request(SUCCESSOR, view + 1, now),
            "no pull is coming this epoch"
        );
        assert_eq!(
            refresh.decide(Some(view), Some(view + 2), now),
            Decision::Exhausted {
                epoch: boundary / EPOCH,
                wanted: EarlyPull {
                    reason: SUCCESSOR,
                    through: view + 1
                },
                max: MAX_PER_EPOCH,
            },
        );
        assert_eq!(
            refresh.decide(Some(view), Some(view + 2), now + MIN_GAP),
            Decision::Idle
        );
        // The next boundary pulls despite the spent budget.
        assert_eq!(
            refresh.decide(Some(view), Some(923041), now + MIN_GAP * 2),
            pull(Reason::EpochBoundary, 923040)
        );
    }

    #[test]
    fn a_waiting_seal_skips_the_gap_once_for_each_frame_it_needs() {
        let refresh = enabled();
        let now = Instant::now();
        refresh.end(now);
        assert!(refresh.request(SEAL, 922330, now));
        assert_eq!(
            refresh.decide(Some(922325), Some(922331), now),
            pull(SEAL, 922330)
        );
        // That pull did not converge: the same frame waits out the gap.
        refresh.end(now + Duration::from_secs(1));
        assert!(!refresh.request(SEAL, 922330, now + Duration::from_secs(2)));
        assert_eq!(
            refresh.decide(Some(922325), Some(922331), now + Duration::from_secs(2)),
            Decision::Idle
        );
        assert_eq!(
            refresh.decide(
                Some(922325),
                Some(922331),
                now + Duration::from_secs(1) + MIN_GAP
            ),
            pull(SEAL, 922330)
        );
        // A later frame skips it again.
        refresh.end(now + Duration::from_secs(22));
        assert!(refresh.request(SEAL, 922331, now + Duration::from_secs(23)));
        assert_eq!(
            refresh.decide(Some(922325), Some(922332), now + Duration::from_secs(23)),
            pull(SEAL, 922331)
        );
    }

    #[test]
    fn unauthorized_seals_cannot_spend_the_pulls_of_other_handoffs() {
        let refresh = enabled();
        let mut now = Instant::now();
        let mut view = 922330;
        // A leader proposing seals no request authorizes, every turn, while
        // GLOBAL advances: each new frame skips the gap, up to the seals' budget.
        for _ in 0..SEAL_PER_EPOCH {
            assert!(refresh.request(SEAL, view + 1, now));
            assert_eq!(
                refresh.decide(Some(view), Some(view + 2), now),
                pull(SEAL, view + 1)
            );
            view += 1;
            refresh.end(now);
            refresh.settle(view);
            now += Duration::from_secs(1);
        }
        assert!(
            !refresh.request(SEAL, view + 1, now),
            "the seals' budget is spent"
        );
        assert_eq!(
            refresh.decide(Some(view), Some(view + 2), now + MIN_GAP),
            Decision::Exhausted {
                epoch: 922320 / EPOCH,
                wanted: EarlyPull {
                    reason: SEAL,
                    through: view + 1
                },
                max: SEAL_PER_EPOCH,
            }
        );
        // A successor still pulls, after the gap.
        refresh.request(SUCCESSOR, view + 1, now + MIN_GAP);
        assert_eq!(
            refresh.decide(Some(view), Some(view + 2), now + MIN_GAP),
            pull(SUCCESSOR, view + 1)
        );
    }

    #[test]
    fn a_seal_waiting_behind_an_unconverged_boundary_pull_does_not_wait_out_the_gap() {
        let refresh = enabled();
        let now = Instant::now();
        assert_eq!(
            refresh.decide(Some(922315), Some(922321), now),
            pull(Reason::EpochBoundary, 922320)
        );
        let ended = now + Duration::from_secs(35);
        refresh.end(ended);
        // The view is still behind the boundary; a seal needs frame 922321.
        assert!(refresh.request(SEAL, 922321, ended + Duration::from_secs(1)));
        assert_eq!(
            refresh.decide(Some(922315), Some(922322), ended + Duration::from_secs(1)),
            pull(Reason::EpochBoundary, 922320),
        );
    }
}
