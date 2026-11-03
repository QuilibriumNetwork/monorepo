//! Tells the operator when this node's storage registration lands, and when
//! a renewal it published did not land in its epoch. A `ProverConfirm` that
//! carries a seat's leaf roots registers them for the next epoch; GLOBAL
//! applies the confirm a few frames after it is published and the node
//! learns that from its registry view, where the seat's allocation epoch
//! reaches the registration epoch. A confirm GLOBAL has not applied when the
//! epoch it was signed in ends never applies, and the seat reads expired.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// GLOBAL frames into an epoch for this node's registry view to show the
/// renewals applied at the end of the epoch before, which it pulls early
/// once the head passes the boundary (`crate::global_view_refresh`); at most
/// half the epoch.
const VIEW_LAG_FRAMES: u64 = 16;

/// A seat's renewal the node published and has not yet seen applied.
struct Pending {
    leaf_entries: usize,
    submitted_frame: u64,
    submissions: u32,
}

/// A registration observed applied.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Landed {
    pub(crate) filter: Vec<u8>,
    pub(crate) epoch: u64,
    pub(crate) leaf_entries: usize,
    pub(crate) submitted_frame: u64,
}

/// A renewal for `epoch` that the epoch began without: the seat's
/// allocation is still confirmed only for `allocation_epoch`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Missed {
    pub(crate) filter: Vec<u8>,
    pub(crate) epoch: u64,
    pub(crate) allocation_epoch: u64,
    pub(crate) leaf_entries: usize,
    pub(crate) submitted_frame: u64,
    pub(crate) submissions: u32,
}

#[derive(Default)]
pub(crate) struct Tracker {
    /// By seat and registration epoch.
    pending: HashMap<(Vec<u8>, u64), Pending>,
    /// Reported already, so a later confirm of the same seat and epoch
    /// (a retry, a renewal after a pending seat) is not reported again.
    landed: HashSet<(Vec<u8>, u64)>,
    /// Renewals waiting for their storage snapshot, not yet published: the
    /// GLOBAL frame first seen waiting, by seat and registration epoch.
    awaiting: HashMap<(Vec<u8>, u64), u64>,
}

/// A renewal withdrawn before it was published: the seat stopped being
/// Active while its snapshot was pending, so no confirm registers it for
/// `epoch`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Withdrawn {
    pub(crate) filter: Vec<u8>,
    pub(crate) epoch: u64,
    pub(crate) status: quil_types::consensus::ProverStatus,
    pub(crate) waiting_since: u64,
}

impl Tracker {
    /// Records a published confirm's renewal of `filter` for `epoch`,
    /// registering `leaf_entries` leaves (none when it renews without a
    /// registration).
    pub(crate) fn submitted(&mut self, filter: &[u8], epoch: u64, leaf_entries: usize, frame: u64) {
        let key = (filter.to_vec(), epoch);
        self.awaiting.remove(&key);
        if self.landed.contains(&key) {
            return;
        }
        let pending = self.pending.entry(key).or_insert(Pending {
            leaf_entries,
            submitted_frame: frame,
            submissions: 0,
        });
        pending.leaf_entries = leaf_entries;
        pending.submitted_frame = frame;
        pending.submissions = pending.submissions.saturating_add(1);
    }

    /// The registrations applied and the renewals missed according to
    /// `seats` (each of this node's seats with the epoch its allocation was
    /// last confirmed for) at `frames_into_epoch` frames of `current_epoch`.
    /// Each seat and epoch is returned once: applied with leaves, or missed
    /// once the view has had [`VIEW_LAG_FRAMES`] (at most half of
    /// `epoch_length`) to show it applied. A renewal of a seat the view no
    /// longer holds is dropped an epoch after its own.
    pub(crate) fn observed(
        &mut self,
        seats: &[(&[u8], u64)],
        current_epoch: u64,
        frames_into_epoch: u64,
        epoch_length: u64,
    ) -> (Vec<Landed>, Vec<Missed>) {
        let mut landed = Vec::new();
        let mut missed = Vec::new();
        let settled = frames_into_epoch >= VIEW_LAG_FRAMES.min(epoch_length / 2);
        for (filter, allocation_epoch) in seats {
            let mine: Vec<u64> = self
                .pending
                .keys()
                .filter(|(pending, _)| pending.as_slice() == *filter)
                .map(|(_, epoch)| *epoch)
                .collect();
            for epoch in mine {
                let late = epoch < current_epoch || (epoch == current_epoch && settled);
                if epoch > *allocation_epoch && !late {
                    continue;
                }
                let key = (filter.to_vec(), epoch);
                let Some(pending) = self.pending.remove(&key) else {
                    continue;
                };
                if epoch <= *allocation_epoch {
                    self.landed.insert(key);
                    if pending.leaf_entries > 0 {
                        landed.push(Landed {
                            filter: filter.to_vec(),
                            epoch,
                            leaf_entries: pending.leaf_entries,
                            submitted_frame: pending.submitted_frame,
                        });
                    }
                } else {
                    missed.push(Missed {
                        filter: filter.to_vec(),
                        epoch,
                        allocation_epoch: *allocation_epoch,
                        leaf_entries: pending.leaf_entries,
                        submitted_frame: pending.submitted_frame,
                        submissions: pending.submissions,
                    });
                }
            }
        }
        self.pending
            .retain(|(_, epoch), _| epoch.saturating_add(1) >= current_epoch);
        self.landed.retain(|(_, epoch)| *epoch >= current_epoch);
        (landed, missed)
    }

    /// Records a renewal of `filter` for `epoch` held back at `frame` while
    /// its storage snapshot encodes.
    pub(crate) fn waiting(&mut self, filter: &[u8], epoch: u64, frame: u64) {
        let key = (filter.to_vec(), epoch);
        if !self.pending.contains_key(&key) && !self.landed.contains(&key) {
            self.awaiting.entry(key).or_insert(frame);
        }
    }

    /// The held-back renewals whose seat `statuses` no longer shows Active
    /// or Joining (absent: no longer held), each returned once; waits for
    /// an epoch that has begun are dropped. An empty view (the node could
    /// not read its allocations) withdraws nothing.
    pub(crate) fn withdrawn(
        &mut self,
        statuses: &[(&[u8], quil_types::consensus::ProverStatus)],
        current_epoch: u64,
    ) -> Vec<Withdrawn> {
        use quil_types::consensus::ProverStatus;
        self.awaiting.retain(|(_, epoch), _| *epoch > current_epoch);
        if statuses.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        self.awaiting.retain(|(filter, epoch), since| {
            let status = statuses
                .iter()
                .find(|(seat, _)| *seat == filter.as_slice())
                .map_or(ProverStatus::Unknown, |(_, status)| *status);
            if matches!(status, ProverStatus::Active | ProverStatus::Joining) {
                return true;
            }
            out.push(Withdrawn {
                filter: filter.clone(),
                epoch: *epoch,
                status,
                waiting_since: *since,
            });
            false
        });
        out.sort_by(|a, b| (&a.filter, a.epoch).cmp(&(&b.filter, b.epoch)));
        out
    }
}

static TRACKER: Mutex<Option<Tracker>> = Mutex::new(None);

fn tracker<T>(f: impl FnOnce(&mut Tracker) -> T) -> T {
    let mut guard = TRACKER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(guard.get_or_insert_with(Tracker::default))
}

/// Notes the renewals of a confirm this node published at `frame`: each seat
/// it confirms with a leaf-root group, with leaves or without.
pub(crate) fn note_submitted(
    groups: &[quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots],
    seats: &[Vec<u8>],
    frame: u64,
) {
    let epoch = quil_types::consensus::epoch_for_frame(frame) + 1;
    tracker(|tracker| {
        for group in groups.iter().filter(|g| seats.contains(&g.filter)) {
            tracker.submitted(&group.filter, epoch, group.entries.len(), frame);
        }
    });
}

/// Notes the seats a confirm at `frame` held back for their snapshot.
pub(crate) fn note_waiting(filters: &[Vec<u8>], frame: u64) {
    let epoch = quil_types::consensus::epoch_for_frame(frame) + 1;
    tracker(|tracker| {
        for filter in filters {
            tracker.waiting(filter, epoch, frame);
        }
    });
}

/// Logs each registration that landed, each renewal that missed its epoch
/// and each held-back renewal its seat's leave or pause withdrew, given this
/// node's allocations at `frame`.
pub(crate) fn log_observed(
    allocations: &[quil_types::consensus::ProverAllocationInfo],
    frame: u64,
) {
    let seats: Vec<(&[u8], u64)> = allocations
        .iter()
        .filter(|a| !a.confirmation_filter.is_empty())
        .map(|a| (a.confirmation_filter.as_slice(), a.epoch))
        .collect();
    let current_epoch = quil_types::consensus::epoch_for_frame(frame);
    let frames_into_epoch =
        frame.saturating_sub(quil_types::consensus::epoch_start_frame(current_epoch));
    let statuses: Vec<(&[u8], quil_types::consensus::ProverStatus)> = allocations
        .iter()
        .filter(|a| !a.confirmation_filter.is_empty())
        .map(|a| (a.confirmation_filter.as_slice(), a.status))
        .collect();
    let status_of = |filter: &[u8]| {
        statuses
            .iter()
            .find(|(seat, _)| *seat == filter)
            .map_or(quil_types::consensus::ProverStatus::Unknown, |(_, s)| *s)
    };
    let (landed, missed, withdrawn) = tracker(|tracker| {
        let (landed, missed) = tracker.observed(
            &seats,
            current_epoch,
            frames_into_epoch,
            quil_types::consensus::epoch_length_frames(),
        );
        (landed, missed, tracker.withdrawn(&statuses, current_epoch))
    });
    for withdrawn in withdrawn {
        tracing::info!(
            frame,
            registration_epoch = withdrawn.epoch,
            filter = %hex::encode(&withdrawn.filter),
            status = ?withdrawn.status,
            waiting_since = withdrawn.waiting_since,
            scope = "local",
            "storage renewal withdrawn before it was sent: the seat stopped being Active while its \
             storage snapshot was pending (status Leaving or Paused: its own leave or pause landed; \
             otherwise GLOBAL moved or removed the seat), so no confirm renews it for the epoch; \
             expected after a leave or pause (reported once a seat per epoch)"
        );
    }
    for landed in landed {
        tracing::info!(
            frame,
            registration_epoch = landed.epoch,
            filter = %hex::encode(&landed.filter),
            leaf_entries = landed.leaf_entries,
            submitted_frame = landed.submitted_frame,
            scope = "local",
            "storage registration landed: GLOBAL applied this seat's confirm and its leaf roots are \
             registered for the epoch (reported once a seat per epoch)"
        );
    }
    for missed in missed {
        let boundary = quil_types::consensus::epoch_start_frame(missed.epoch);
        let status = status_of(&missed.filter);
        let action = match status {
            quil_types::consensus::ProverStatus::Leaving
            | quil_types::consensus::ProverStatus::Paused
            | quil_types::consensus::ProverStatus::Kicked => {
                "this seat stopped being Active before GLOBAL applied the confirm (see status): a \
                 Leaving seat's confirm confirms its leave or is refused ('confirm: leave must be \
                 confirmed in epoch'), a Paused seat's is refused ('invalid allocation status') and \
                 a Kicked seat is gone, so none renews; expected after a leave or pause, no action"
            }
            _ => {
                "check that GLOBAL produced frames after submitted_frame, and archive logs \
                 for 'signed frame must be in the inclusion epoch' (a confirm signed too \
                 close to the boundary); a renewed seat renews again in this epoch"
            }
        };
        tracing::warn!(
            frame,
            status = ?status,
            registration_epoch = missed.epoch,
            allocation_epoch = missed.allocation_epoch,
            filter = %hex::encode(&missed.filter),
            leaf_entries = missed.leaf_entries,
            submitted_frame = missed.submitted_frame,
            frames_before_boundary = boundary.saturating_sub(missed.submitted_frame),
            submissions = missed.submissions,
            scope = "local",
            action,
            "prover confirm did not land: GLOBAL did not apply this seat's published confirm \
             before the epoch it was signed in ended, so a renewed seat reads expired this epoch \
             (reported once a seat per epoch)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEAT: &[u8] = &[7u8; 3];
    const LENGTH: u64 = 720;

    #[test]
    fn a_registration_is_reported_once_when_the_allocation_reaches_its_epoch() {
        let mut tracker = Tracker::default();
        tracker.submitted(SEAT, 5, 12, 400);
        let (landed, missed) = tracker.observed(&[(SEAT, 4)], 4, 400, LENGTH);
        assert!(
            landed.is_empty() && missed.is_empty(),
            "not applied while the allocation is an epoch behind"
        );
        let (landed, missed) = tracker.observed(&[(SEAT, 5)], 4, 410, LENGTH);
        assert_eq!(
            landed,
            vec![Landed {
                filter: SEAT.to_vec(),
                epoch: 5,
                leaf_entries: 12,
                submitted_frame: 400,
            }]
        );
        assert!(missed.is_empty());
        let (landed, _) = tracker.observed(&[(SEAT, 5)], 4, 411, LENGTH);
        assert!(landed.is_empty(), "once");
        tracker.submitted(SEAT, 5, 12, 410);
        let (landed, missed) = tracker.observed(&[(SEAT, 5)], 4, 412, LENGTH);
        assert!(
            landed.is_empty() && missed.is_empty(),
            "a retry of an applied registration is not reported again"
        );
        let (_, missed) = tracker.observed(&[(SEAT, 5)], 5, 100, LENGTH);
        assert!(missed.is_empty(), "an applied renewal never misses");
    }

    #[test]
    fn a_renewal_without_leaves_lands_silently() {
        let mut tracker = Tracker::default();
        tracker.submitted(SEAT, 5, 0, 400);
        let (landed, missed) = tracker.observed(&[(SEAT, 5)], 4, 401, LENGTH);
        assert!(landed.is_empty() && missed.is_empty());
        let (landed, missed) = tracker.observed(&[(SEAT, 5)], 5, 100, LENGTH);
        assert!(landed.is_empty() && missed.is_empty());
    }

    /// A renewal the epoch began without is reported once the view had time
    /// to show it, with its last submission; one the view showed applied
    /// within that time is not.
    #[test]
    fn a_renewal_the_epoch_began_without_is_reported_once_as_missed() {
        let mut tracker = Tracker::default();
        tracker.submitted(SEAT, 5, 0, 3_598);
        tracker.submitted(SEAT, 5, 0, 3_599);
        let (_, missed) = tracker.observed(&[(SEAT, 4)], 5, VIEW_LAG_FRAMES - 1, LENGTH);
        assert!(missed.is_empty(), "the view may still trail the boundary");
        let (landed, missed) = tracker.observed(&[(SEAT, 4)], 5, VIEW_LAG_FRAMES, LENGTH);
        assert!(landed.is_empty());
        assert_eq!(
            missed,
            vec![Missed {
                filter: SEAT.to_vec(),
                epoch: 5,
                allocation_epoch: 4,
                leaf_entries: 0,
                submitted_frame: 3_599,
                submissions: 2,
            }]
        );
        let (_, missed) = tracker.observed(&[(SEAT, 4)], 5, VIEW_LAG_FRAMES + 1, LENGTH);
        assert!(missed.is_empty(), "once");

        // Short epochs wait half of one.
        let mut tracker = Tracker::default();
        tracker.submitted(SEAT, 5, 3, 149);
        let (_, missed) = tracker.observed(&[(SEAT, 4)], 5, 14, 30);
        assert!(missed.is_empty());
        let (_, missed) = tracker.observed(&[(SEAT, 4)], 5, 15, 30);
        assert_eq!(missed.len(), 1);

        // Applied while the view caught up: landed, never missed.
        let mut tracker = Tracker::default();
        tracker.submitted(SEAT, 5, 3, 3_599);
        let (_, missed) = tracker.observed(&[(SEAT, 4)], 5, 2, LENGTH);
        assert!(missed.is_empty());
        let (landed, missed) = tracker.observed(&[(SEAT, 5)], 5, 3, LENGTH);
        assert_eq!(landed.len(), 1);
        assert!(missed.is_empty());
    }

    #[test]
    fn a_held_back_renewal_is_reported_withdrawn_once_when_its_seat_leaves() {
        use quil_types::consensus::ProverStatus;
        let mut tracker = Tracker::default();
        tracker.waiting(SEAT, 18, 510);
        tracker.waiting(SEAT, 18, 511);
        assert!(
            tracker
                .withdrawn(&[(SEAT, ProverStatus::Active)], 17)
                .is_empty(),
            "still Active: still waiting"
        );
        assert_eq!(
            tracker.withdrawn(&[(SEAT, ProverStatus::Leaving)], 17),
            vec![Withdrawn {
                filter: SEAT.to_vec(),
                epoch: 18,
                status: ProverStatus::Leaving,
                waiting_since: 510,
            }]
        );
        assert!(
            tracker
                .withdrawn(&[(SEAT, ProverStatus::Leaving)], 17)
                .is_empty(),
            "once"
        );
        tracker.waiting(SEAT, 18, 512);
        assert!(
            tracker.withdrawn(&[], 17).is_empty(),
            "an unread view withdraws nothing"
        );
        assert_eq!(
            tracker
                .withdrawn(&[(&[8u8; 3][..], ProverStatus::Active)], 17)
                .len(),
            1,
            "a seat the view no longer holds is withdrawn"
        );
        tracker.waiting(SEAT, 19, 540);
        tracker.submitted(SEAT, 19, 1, 556);
        assert!(
            tracker
                .withdrawn(&[(SEAT, ProverStatus::Paused)], 18)
                .is_empty(),
            "a renewal sent is the missed report's, not a withdrawal"
        );
        tracker.waiting(SEAT, 20, 570);
        assert!(
            tracker
                .withdrawn(&[(SEAT, ProverStatus::Leaving)], 20)
                .is_empty(),
            "a wait for an epoch that has begun is dropped unreported"
        );
    }

    #[test]
    fn a_renewal_of_a_seat_the_view_no_longer_holds_is_dropped_unreported() {
        let mut tracker = Tracker::default();
        tracker.submitted(SEAT, 5, 3, 3_599);
        let (_, missed) = tracker.observed(&[], 5, 100, LENGTH);
        assert!(missed.is_empty());
        let (_, missed) = tracker.observed(&[], 6, 100, LENGTH);
        assert!(missed.is_empty());
        let (_, missed) = tracker.observed(&[], 7, 0, LENGTH);
        assert!(missed.is_empty());
        assert!(tracker.pending.is_empty(), "dropped an epoch after its own");
        let (_, missed) = tracker.observed(&[(SEAT, 4)], 7, 100, LENGTH);
        assert!(missed.is_empty());
    }
}
