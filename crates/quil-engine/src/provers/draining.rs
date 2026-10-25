//! Workers above the configured count drain: they take no new seat or join,
//! their seats leave only through the surplus leave (lowest reward first,
//! never one the halt-risk shield holds), and each is retired once it holds
//! no seat and no join. This module says where each draining worker stands,
//! for the summary the lifecycle logs once per epoch.

use quil_types::consensus::{
    epoch_for_frame, epoch_length_frames, AllocationPhase, EffectiveStatus, ProverAllocationInfo,
};


/// Whether `allocation` holds one of this node's allocation slots at `frame`
/// for the configured worker count, bound to a worker or not: Active,
/// Paused, Activating, or Leaving with its leave not yet confirmed. A
/// confirmed leave (Departing) already frees its slot at the boundary and
/// is counted only with `departing`; a join not yet confirmed holds none.
pub fn holds_seat(allocation: &ProverAllocationInfo, frame: u64, departing: bool) -> bool {
    match allocation.phase(frame) {
        Some(AllocationPhase::Active | AllocationPhase::Paused | AllocationPhase::Activating
            | AllocationPhase::Leaving) => true,
        Some(AllocationPhase::Departing) => departing,
        Some(AllocationPhase::Joining) | None => false,
    }
}

/// Where a draining worker's seat stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainSeat {
    /// No seat and no join: retired at the next lifecycle tick.
    Idle,
    /// A join that waits for its confirmation or activation, or expires.
    Joining,
    /// The leave is in the registry; it departs at the start of
    /// `departs_epoch` once confirmed in the epoch before.
    Leaving { departs_epoch: u64 },
    /// The leave is confirmed; it departs at the start of `departs_epoch`.
    Departing { departs_epoch: u64 },
    /// This node proposed the leave at frame `since`; the registry does not
    /// show it yet.
    Proposed { since: u64 },
    /// The halt-risk shield holds it: its shard has `active` active provers,
    /// and our leave would leave it at the halt-risk count or below.
    Shielded { active: u64 },
    /// The surplus leave chose it; it publishes when its cooldown ends.
    Selected,
    /// No surplus leave names it: no Active seat is surplus, or seats of
    /// lower reward make up the surplus.
    Kept,
    /// Missed its epoch renewal: not counted Active, so the surplus leave does
    /// not name it; it is renewed or its worker released.
    Lapsed,
    /// Paused, or no live allocation of this prover holds its filter.
    Other,
}

impl DrainSeat {
    /// Where the seat of a draining worker bound to `filter` (empty when
    /// idle) with `pending_join` stands at `frame`.
    pub(crate) fn of(
        filter: &[u8],
        pending_join: bool,
        allocation: Option<&ProverAllocationInfo>,
        frame: u64,
        proposed: Option<u64>,
        shield_active: Option<u64>,
        selected: bool,
    ) -> Self {
        if filter.is_empty() {
            return if pending_join { DrainSeat::Joining } else { DrainSeat::Idle };
        }
        let Some(allocation) = allocation else {
            return if pending_join { DrainSeat::Joining } else { DrainSeat::Other };
        };
        match allocation.effective_status(frame) {
            EffectiveStatus::Joining => DrainSeat::Joining,
            EffectiveStatus::Leaving if allocation.leave_confirm_frame_number > 0 => DrainSeat::Departing {
                departs_epoch: epoch_for_frame(allocation.leave_confirm_frame_number) + 1,
            },
            EffectiveStatus::Leaving => DrainSeat::Leaving {
                departs_epoch: epoch_for_frame(allocation.leave_frame_number) + 2,
            },
            EffectiveStatus::ExpiredEpoch => DrainSeat::Lapsed,
            EffectiveStatus::Active => match (proposed, shield_active) {
                (Some(since), _) => DrainSeat::Proposed { since },
                (None, Some(active)) => DrainSeat::Shielded { active },
                (None, None) if selected => DrainSeat::Selected,
                (None, None) => DrainSeat::Kept,
            },
            _ => DrainSeat::Other,
        }
    }

    /// The seat's state in the summary line; the line's message says what
    /// each state waits for.
    pub(crate) fn describe(self) -> String {
        match self {
            DrainSeat::Idle => "idle, retires at the next lifecycle tick".into(),
            DrainSeat::Joining => "joining".into(),
            DrainSeat::Leaving { departs_epoch } => format!("leaving, departs at epoch {departs_epoch} once confirmed"),
            DrainSeat::Departing { departs_epoch } => format!("departing at epoch {departs_epoch}"),
            DrainSeat::Proposed { since } => format!("leave proposed at frame {since}, not in the registry yet"),
            DrainSeat::Shielded { active } => format!("shielded ({active} active provers)"),
            DrainSeat::Selected => "selected for the surplus leave".into(),
            DrainSeat::Kept => "kept, not surplus".into(),
            DrainSeat::Lapsed => "lapsed renewal".into(),
            DrainSeat::Other => "no live allocation".into(),
        }
    }

    /// The epoch the seat departs at, when its leave is under way: a
    /// proposed leave that lands in its epoch departs two epochs on.
    pub(crate) fn departs_epoch(self) -> Option<u64> {
        match self {
            DrainSeat::Leaving { departs_epoch } | DrainSeat::Departing { departs_epoch } => Some(departs_epoch),
            DrainSeat::Proposed { since } => Some(epoch_for_frame(since) + 2),
            _ => None,
        }
    }

    /// A proposed leave the registry has not shown for over an epoch.
    pub(crate) fn stalled(self, frame: u64) -> bool {
        matches!(self, DrainSeat::Proposed { since } if frame.saturating_sub(since) > epoch_length_frames())
    }
}

/// The once-per-epoch summary of the draining workers.
pub(crate) struct DrainSummary {
    pub configured: usize,
    pub running: usize,
    /// Active seats above the configured count.
    pub surplus: usize,
    /// Seats the surplus leave may leave (not shielded, not manual).
    pub eligible: usize,
    /// Bound seats the halt-risk shield holds, on any worker.
    pub shielded: usize,
    /// Each draining worker, by core, with its filter and seat.
    pub seats: Vec<(u32, Vec<u8>, DrainSeat)>,
}

impl DrainSummary {
    pub(crate) fn log(&self, frame: u64) {
        let count = |pred: fn(&DrainSeat) -> bool| self.seats.iter().filter(|(_, _, seat)| pred(seat)).count();
        let leaving = count(|seat| matches!(seat, DrainSeat::Leaving { .. } | DrainSeat::Departing { .. }));
        let proposed = count(|seat| matches!(seat, DrainSeat::Proposed { .. }));
        let held = count(|seat| matches!(seat, DrainSeat::Shielded { .. }));
        let seats: Vec<String> = self.seats.iter().map(|(core_id, filter, seat)| {
            let filter = if filter.is_empty() { "-".to_string() } else { hex::encode(filter) };
            format!("core {core_id} {filter}: {}", seat.describe())
        }).collect();
        let last_departure_epoch = self.seats.iter().filter_map(|(_, _, seat)| seat.departs_epoch()).max();
        tracing::info!(
            frame,
            epoch = epoch_for_frame(frame),
            configured = self.configured,
            running = self.running,
            draining = self.seats.len(),
            surplus_leave = %format!("eligible {} of {} surplus; {} held by the shield",
                self.eligible.min(self.surplus), self.surplus, self.shielded),
            draining_leaving = leaving,
            draining_proposed = proposed,
            draining_shielded = held,
            last_departure_epoch = ?last_departure_epoch,
            epochs_to_last_departure = ?last_departure_epoch.map(|last| last.saturating_sub(epoch_for_frame(frame))),
            seats = ?seats,
            scope = "this node",
            "workers above the configured count are draining: they take no new seat, their seats leave through \
             the surplus leave (eligible seats, lowest reward first), and each stops once it holds no seat or \
             join. Expected waits: a leave departs at its epoch once confirmed; a shielded seat is held until its \
             shard has more than 4 active provers; a kept seat is not surplus (lower-reward seats make up the \
             surplus, or none is) and stays until it departs; a joining seat drains once its join is confirmed \
             or expires"
        );
        let stalled: Vec<String> = self.seats.iter().filter(|(_, _, seat)| seat.stalled(frame))
            .map(|(core_id, filter, seat)| format!("core {core_id} {}: {}", hex::encode(filter), seat.describe()))
            .collect();
        if !stalled.is_empty() {
            tracing::warn!(
                frame,
                stalled = ?stalled,
                scope = "this node",
                action = "check that the GLOBAL head advances and that this node's lifecycle plans are submitted \
                          and included (lifecycle plan and submission lines); report it with these frames if they \
                          are and the leave still does not land",
                "a draining worker's leave was proposed over an epoch ago and the registry still shows the seat \
                 active"
            );
        }
    }
}
