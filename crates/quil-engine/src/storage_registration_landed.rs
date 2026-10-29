//! Tells the operator when this node's storage registration lands. A
//! `ProverConfirm` that carries a seat's leaf roots registers them for the
//! next epoch; GLOBAL applies the confirm a few frames after it is published
//! and the node learns that from its registry view, where the seat's
//! allocation epoch reaches the registration epoch.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// A seat's registration the node published and has not yet seen applied.
struct Pending {
    leaf_entries: usize,
    submitted_frame: u64,
}

/// A registration observed applied.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Landed {
    pub(crate) filter: Vec<u8>,
    pub(crate) epoch: u64,
    pub(crate) leaf_entries: usize,
    pub(crate) submitted_frame: u64,
}

#[derive(Default)]
pub(crate) struct Tracker {
    /// By seat and registration epoch.
    pending: HashMap<(Vec<u8>, u64), Pending>,
    /// Reported already, so a later confirm of the same seat and epoch
    /// (a retry, a renewal after a pending seat) is not reported again.
    landed: HashSet<(Vec<u8>, u64)>,
}

impl Tracker {
    /// Records a published confirm's registration of `leaf_entries` leaves
    /// for `filter` in `epoch`. A seat without leaves registers nothing.
    pub(crate) fn submitted(&mut self, filter: &[u8], epoch: u64, leaf_entries: usize, frame: u64) {
        let key = (filter.to_vec(), epoch);
        if leaf_entries == 0 || self.landed.contains(&key) {
            return;
        }
        self.pending.insert(
            key,
            Pending {
                leaf_entries,
                submitted_frame: frame,
            },
        );
    }

    /// The registrations applied according to `seats` (each of this node's
    /// seats with the epoch its allocation was last confirmed for) at a
    /// frame of `current_epoch`. Each seat and epoch is returned once; one
    /// the epoch outlived without landing is dropped.
    pub(crate) fn observed(&mut self, seats: &[(&[u8], u64)], current_epoch: u64) -> Vec<Landed> {
        let mut landed = Vec::new();
        for (filter, allocation_epoch) in seats {
            let applied: Vec<u64> = self
                .pending
                .keys()
                .filter(|(pending, epoch)| {
                    pending.as_slice() == *filter && epoch <= allocation_epoch
                })
                .map(|(_, epoch)| *epoch)
                .collect();
            for epoch in applied {
                let key = (filter.to_vec(), epoch);
                if let Some(pending) = self.pending.remove(&key) {
                    self.landed.insert(key);
                    landed.push(Landed {
                        filter: filter.to_vec(),
                        epoch,
                        leaf_entries: pending.leaf_entries,
                        submitted_frame: pending.submitted_frame,
                    });
                }
            }
        }
        self.pending.retain(|(_, epoch), _| *epoch > current_epoch);
        self.landed.retain(|(_, epoch)| *epoch >= current_epoch);
        landed
    }
}

static TRACKER: Mutex<Option<Tracker>> = Mutex::new(None);

fn tracker<T>(f: impl FnOnce(&mut Tracker) -> T) -> T {
    let mut guard = TRACKER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(guard.get_or_insert_with(Tracker::default))
}

/// Notes the registrations of a confirm this node published at `frame`.
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

/// Logs each registration that landed, given this node's allocations at `frame`.
pub(crate) fn log_observed(
    allocations: &[quil_types::consensus::ProverAllocationInfo],
    frame: u64,
) {
    let seats: Vec<(&[u8], u64)> = allocations
        .iter()
        .filter(|a| !a.confirmation_filter.is_empty())
        .map(|a| (a.confirmation_filter.as_slice(), a.epoch))
        .collect();
    let landed =
        tracker(|tracker| tracker.observed(&seats, quil_types::consensus::epoch_for_frame(frame)));
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEAT: &[u8] = &[7u8; 3];

    #[test]
    fn a_registration_is_reported_once_when_the_allocation_reaches_its_epoch() {
        let mut tracker = Tracker::default();
        tracker.submitted(SEAT, 5, 12, 400);
        assert!(
            tracker.observed(&[(SEAT, 4)], 4).is_empty(),
            "not applied while the allocation is an epoch behind"
        );
        let landed = tracker.observed(&[(SEAT, 5)], 4);
        assert_eq!(
            landed,
            vec![Landed {
                filter: SEAT.to_vec(),
                epoch: 5,
                leaf_entries: 12,
                submitted_frame: 400,
            }]
        );
        assert!(tracker.observed(&[(SEAT, 5)], 4).is_empty(), "once");
        tracker.submitted(SEAT, 5, 12, 410);
        assert!(
            tracker.observed(&[(SEAT, 5)], 4).is_empty(),
            "a retry of an applied registration is not reported again"
        );
    }

    #[test]
    fn a_seat_without_leaves_or_one_the_epoch_outlived_is_not_reported() {
        let mut tracker = Tracker::default();
        tracker.submitted(SEAT, 5, 0, 400);
        assert!(tracker.observed(&[(SEAT, 5)], 4).is_empty());
        tracker.submitted(SEAT, 5, 3, 400);
        assert!(tracker.observed(&[(SEAT, 4)], 5).is_empty());
        assert!(
            tracker.observed(&[(SEAT, 6)], 5).is_empty(),
            "dropped when its epoch began without it landing"
        );
    }
}
