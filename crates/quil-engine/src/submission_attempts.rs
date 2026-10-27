//! Shared ownership of asynchronous shard operations. Reservations survive
//! preparation and block other operation kinds until completion; successful
//! publication retains a bounded retry fence, not a registry acknowledgement.
//! An epoch fence holds off only operations of its own kind.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const RETRY_FRAMES: u64 = 30;
type Key = (u64, Vec<u8>, OpKind);

/// What an attempt submits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum OpKind {
    Join,
    /// A confirm that registers storage: a join's or an epoch renewal.
    Confirm,
    /// A leave, or the confirm of one.
    Leave,
    Reject,
}

#[derive(Default)]
pub(crate) struct SubmissionAttempts(Mutex<HashMap<Key, Attempt>>);

struct Attempt {
    frame: u64,
    in_flight: bool,
    /// Fenced until its epoch ends rather than for the retry fence.
    for_epoch: bool,
}

impl Attempt {
    /// Whether this attempt of `attempt_epoch` still owns its filter at
    /// `frame` of `epoch`: in flight, or inside its fence.
    fn owns(&self, attempt_epoch: u64, epoch: u64, frame: u64) -> bool {
        self.in_flight
            || (attempt_epoch == epoch
                && (self.for_epoch || frame.saturating_sub(self.frame) < RETRY_FRAMES))
    }

    /// Whether this attempt of `attempt_kind` holds off an operation of
    /// `kind`: as [`Self::owns`], except that an epoch fence past the retry
    /// fence holds off only its own kind. A renewal fenced for the epoch
    /// must not keep the seat from being left.
    fn holds_off(
        &self,
        attempt_kind: OpKind,
        kind: OpKind,
        attempt_epoch: u64,
        epoch: u64,
        frame: u64,
    ) -> bool {
        self.owns(attempt_epoch, epoch, frame)
            && (attempt_kind == kind
                || self.in_flight
                || frame.saturating_sub(self.frame) < RETRY_FRAMES)
    }
}

pub(crate) struct SubmissionAttempt {
    owner: Arc<SubmissionAttempts>,
    keys: Vec<Key>,
    published_frames: HashMap<Vec<u8>, u64>,
    /// Filters fenced until the epoch ends (`fence_for_epoch`).
    epoch_fenced: Vec<Vec<u8>>,
}

impl SubmissionAttempts {
    /// Whether a local operation still owns `filter` at `frame` against an
    /// operation of `kind`: one in flight, a publication of this epoch inside
    /// its retry fence, or an epoch fence of the same kind.
    pub(crate) fn owned(&self, filter: &[u8], frame: u64, kind: OpKind) -> bool {
        let epoch = quil_types::consensus::epoch_for_frame(frame);
        self.0.lock().is_ok_and(|attempts| {
            attempts.iter().any(|((e, owned, k), a)| {
                owned.as_slice() == filter && a.holds_off(*k, kind, *e, epoch, frame)
            })
        })
    }

    /// Whether a local confirm still owns `filter` at `frame`: one in
    /// flight, or fenced. A leave or another kind does not count.
    pub(crate) fn confirming(&self, filter: &[u8], frame: u64) -> bool {
        let epoch = quil_types::consensus::epoch_for_frame(frame);
        self.0.lock().is_ok_and(|attempts| {
            attempts.iter().any(|((e, owned, k), a)| {
                *k == OpKind::Confirm && owned.as_slice() == filter && a.owns(*e, epoch, frame)
            })
        })
    }

    /// Release the published joins of each `(filter, frames)` whose attempt
    /// frame lies in `frames`, returning them with that frame. A join still
    /// in flight keeps its filter.
    pub(crate) fn release_published_joins(
        &self,
        joins: &[(Vec<u8>, std::ops::Range<u64>)],
    ) -> Vec<(Vec<u8>, u64)> {
        let Ok(mut attempts) = self.0.lock() else {
            return Vec::new();
        };
        let mut released = Vec::new();
        attempts.retain(|(_, filter, kind), attempt| {
            let release = *kind == OpKind::Join
                && !attempt.in_flight
                && joins
                    .iter()
                    .any(|(held, frames)| held == filter && frames.contains(&attempt.frame));
            if release {
                released.push((filter.clone(), attempt.frame));
            }
            !release
        });
        released
    }

    pub(crate) fn begin(
        self: &Arc<Self>,
        filters: &[Vec<u8>],
        frame: u64,
        kind: OpKind,
    ) -> Option<SubmissionAttempt> {
        if filters.is_empty() {
            return None;
        }
        let epoch = quil_types::consensus::epoch_for_frame(frame);
        let mut attempts = self.0.lock().ok()?;
        attempts.retain(|(e, _, _), a| a.owns(*e, epoch, frame));
        if filters.iter().any(|f| {
            attempts.iter().any(|((e, existing, k), a)| {
                existing == f && a.holds_off(*k, kind, *e, epoch, frame)
            })
        }) {
            return None;
        }
        let keys: Vec<Key> = filters.iter().map(|f| (epoch, f.clone(), kind)).collect();
        for key in &keys {
            attempts.insert(
                key.clone(),
                Attempt {
                    frame,
                    in_flight: true,
                    for_epoch: false,
                },
            );
        }
        Some(SubmissionAttempt {
            owner: self.clone(),
            keys,
            published_frames: HashMap::new(),
            epoch_fenced: Vec::new(),
        })
    }
}

impl SubmissionAttempt {
    /// Every filter published at `frame`; senders record each message's
    /// filters with `published_subset` as it goes out.
    #[cfg(test)]
    pub(crate) fn published(mut self, frame: u64) {
        for (_, filter, _) in &self.keys {
            self.published_frames.insert(filter.clone(), frame);
        }
    }

    /// Release `filters` before the rest of the attempt finishes: the attempt
    /// left them out and neither prepares nor submits them any more, so the
    /// next cycle may retry them while the others are still published.
    pub(crate) fn release(&mut self, filters: &[Vec<u8>]) {
        let (released, kept): (Vec<Key>, Vec<Key>) = std::mem::take(&mut self.keys)
            .into_iter()
            .partition(|(_, owned, _)| filters.contains(owned));
        self.keys = kept;
        if let Ok(mut attempts) = self.owner.0.lock() {
            for key in &released {
                attempts.remove(key);
            }
        }
    }

    /// A later chunk failure cannot erase ownership of an already published
    /// subset. Unpublished filters are released when this guard is dropped.
    pub(crate) fn published_subset(&mut self, filters: &[Vec<u8>], frame: u64) {
        self.fence(filters, frame);
    }

    /// Keep `filters` owned for the retry fence from `frame`, as if
    /// published: the attempt refused them for a reason retrying them on the
    /// next cycle would not change (an op no node decodes).
    pub(crate) fn fence(&mut self, filters: &[Vec<u8>], frame: u64) {
        for filter in filters {
            if self.keys.iter().any(|(_, owned, _)| owned == filter) {
                self.published_frames.insert(filter.clone(), frame);
            }
        }
    }

    /// Keep `filters` owned until the attempt's epoch ends: the attempt left
    /// them out for a reason that holds for the whole epoch (a seat over the
    /// decode limits), so preparing them again within it would only leave
    /// them out again. The next epoch's attempt retries them.
    pub(crate) fn fence_for_epoch(&mut self, filters: &[Vec<u8>], frame: u64) {
        self.fence(filters, frame);
        for filter in filters {
            if self.published_frames.contains_key(filter) {
                self.epoch_fenced.push(filter.clone());
            }
        }
    }
}

impl Drop for SubmissionAttempt {
    fn drop(&mut self) {
        if let Ok(mut attempts) = self.owner.0.lock() {
            for key in &self.keys {
                if let Some(&frame) = self.published_frames.get(&key.1) {
                    if let Some(a) = attempts.get_mut(key) {
                        a.in_flight = false;
                        a.frame = a.frame.max(frame);
                        a.for_epoch |= self.epoch_fenced.contains(&key.1);
                    }
                } else {
                    attempts.remove(key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_failure_success_and_epoch_retry() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let filters = vec![vec![1]];
        let first = attempts.begin(&filters, 10, OpKind::Confirm).unwrap();
        assert!(attempts.begin(&filters, 100, OpKind::Confirm).is_none());
        drop(first); // Cancellation/failure releases the reservation.
        attempts
            .begin(&filters, 100, OpKind::Confirm)
            .unwrap()
            .published(100);
        assert!(attempts.begin(&filters, 101, OpKind::Confirm).is_none());
        assert!(attempts.begin(&filters, 130, OpKind::Confirm).is_some());
        attempts
            .begin(&filters, 719, OpKind::Confirm)
            .unwrap()
            .published(719);
        assert!(attempts.begin(&filters, 720, OpKind::Confirm).is_some());
    }

    #[test]
    fn cooldown_starts_when_preparation_and_publication_finish() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let filters = vec![vec![1]];
        attempts
            .begin(&filters, 10, OpKind::Confirm)
            .unwrap()
            .published(50);
        assert!(attempts.begin(&filters, 79, OpKind::Confirm).is_none());
        assert!(attempts.begin(&filters, 80, OpKind::Confirm).is_some());
    }

    #[test]
    fn later_chunk_failure_keeps_published_subset_reserved() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let mut guard = attempts
            .begin(&[vec![1], vec![2]], 10, OpKind::Confirm)
            .unwrap();
        guard.published_subset(&[vec![1]], 12);
        drop(guard); // The other chunk failed before publication.
        assert!(attempts.begin(&[vec![1]], 13, OpKind::Confirm).is_none());
        assert!(attempts.begin(&[vec![2]], 13, OpKind::Confirm).is_some());
        assert!(attempts.begin(&[vec![1]], 42, OpKind::Confirm).is_some());
    }

    #[test]
    fn a_released_filter_is_free_while_the_rest_stays_reserved() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let mut guard = attempts
            .begin(&[vec![1], vec![2]], 10, OpKind::Confirm)
            .unwrap();
        guard.release(&[vec![2]]);
        assert!(
            attempts.begin(&[vec![2]], 11, OpKind::Confirm).is_some(),
            "released at once"
        );
        assert!(
            attempts.begin(&[vec![1]], 11, OpKind::Confirm).is_none(),
            "still in flight"
        );
        guard.published(12);
        assert!(
            attempts.begin(&[vec![1]], 13, OpKind::Confirm).is_none(),
            "published: fenced"
        );
        assert!(
            attempts.begin(&[vec![2]], 13, OpKind::Confirm).is_some(),
            "released: not fenced"
        );
    }

    #[test]
    fn an_epoch_fence_lasts_until_the_epoch_ends() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let mut guard = attempts
            .begin(&[vec![1], vec![2]], 10, OpKind::Confirm)
            .unwrap();
        guard.fence_for_epoch(&[vec![1]], 12);
        guard.fence(&[vec![2]], 12);
        drop(guard);
        assert!(
            attempts.begin(&[vec![2]], 42, OpKind::Confirm).is_some(),
            "the retry fence lapses"
        );
        assert!(
            attempts.owned(&[1], 719, OpKind::Confirm),
            "the epoch fence holds to the epoch's last frame"
        );
        assert!(attempts.begin(&[vec![1]], 719, OpKind::Confirm).is_none());
        assert!(
            !attempts.owned(&[1], 720, OpKind::Confirm),
            "and lapses with it"
        );
        assert!(
            attempts.begin(&[vec![1]], 720, OpKind::Confirm).is_some(),
            "the next epoch retries it"
        );
    }

    #[test]
    fn running_task_retains_ownership_across_epoch_boundaries() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let running = attempts.begin(&[vec![1]], 719, OpKind::Confirm).unwrap();
        assert!(attempts.begin(&[vec![1]], 720, OpKind::Confirm).is_none());
        assert!(attempts.begin(&[vec![1]], 1440, OpKind::Confirm).is_none());
        drop(running);
        assert!(attempts.begin(&[vec![1]], 1440, OpKind::Confirm).is_some());
    }

    #[test]
    fn ownership_covers_running_and_fenced_attempts() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let running = attempts.begin(&[vec![1]], 10, OpKind::Confirm).unwrap();
        assert!(
            attempts.owned(&[1], 2000, OpKind::Confirm),
            "a running attempt owns its filter across epochs"
        );
        assert!(!attempts.owned(&[2], 10, OpKind::Confirm));
        running.published(20);
        assert!(attempts.owned(&[1], 49, OpKind::Confirm));
        assert!(
            !attempts.owned(&[1], 50, OpKind::Confirm),
            "the fence ends ownership"
        );
    }

    #[test]
    fn overlapping_batches_cannot_encode_the_same_filter_concurrently() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let guard = attempts
            .begin(&[vec![1], vec![2]], 10, OpKind::Confirm)
            .unwrap();
        assert!(attempts
            .begin(&[vec![2], vec![3]], 11, OpKind::Confirm)
            .is_none());
        assert!(attempts.begin(&[vec![3]], 11, OpKind::Confirm).is_some());
        drop(guard);
        assert!(attempts.begin(&[vec![2]], 12, OpKind::Confirm).is_some());
    }

    /// An epoch fence holds off only its own kind once the retry fence
    /// lapses: a renewal over the decode limits does not keep its seat from
    /// being left. A running attempt and the retry fence hold off every kind.
    #[test]
    fn an_epoch_fence_holds_off_only_its_own_kind() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let running = attempts.begin(&[vec![1]], 10, OpKind::Confirm).unwrap();
        assert!(
            attempts.begin(&[vec![1]], 11, OpKind::Leave).is_none(),
            "a running confirm holds off a leave"
        );
        assert!(attempts.owned(&[1], 11, OpKind::Leave));
        drop(running);
        let mut renewal = attempts.begin(&[vec![1]], 12, OpKind::Confirm).unwrap();
        renewal.fence_for_epoch(&[vec![1]], 12);
        drop(renewal);
        assert!(
            attempts.owned(&[1], 41, OpKind::Leave),
            "inside the retry fence"
        );
        assert!(attempts.begin(&[vec![1]], 41, OpKind::Leave).is_none());
        assert!(
            attempts.owned(&[1], 42, OpKind::Confirm),
            "the epoch fence holds the renewal off"
        );
        assert!(attempts.begin(&[vec![1]], 42, OpKind::Confirm).is_none());
        assert!(!attempts.owned(&[1], 42, OpKind::Leave), "but not a leave");
        let leave = attempts
            .begin(&[vec![1]], 42, OpKind::Leave)
            .expect("the seat can be left");
        assert!(
            attempts.begin(&[vec![1]], 43, OpKind::Confirm).is_none(),
            "the running leave holds off a confirm"
        );
        drop(leave);
        assert!(
            attempts.confirming(&[1], 719),
            "the renewal's epoch fence is kept beside the leave"
        );
        assert!(!attempts.confirming(&[1], 720), "until its epoch ends");
    }

    /// Only a confirm counts as a running renewal: a leave in flight does not.
    #[test]
    fn only_a_confirm_is_confirming() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let leave = attempts.begin(&[vec![1]], 10, OpKind::Leave).unwrap();
        assert!(
            attempts.owned(&[1], 10, OpKind::Confirm),
            "the leave owns the filter"
        );
        assert!(!attempts.confirming(&[1], 10), "but is no renewal");
        drop(leave);
        let confirm = attempts.begin(&[vec![1]], 11, OpKind::Confirm).unwrap();
        assert!(
            attempts.confirming(&[1], 2000),
            "a running confirm counts across epochs"
        );
        confirm.published(20);
        assert!(attempts.confirming(&[1], 49));
        assert!(!attempts.confirming(&[1], 50), "the fence ends it");
    }

    /// Releasing published joins frees only fenced joins whose frame lies in
    /// the given window: a join in flight, one outside the window and other
    /// kinds keep their filters.
    #[test]
    fn released_joins_no_longer_hold_off_a_confirm() {
        let attempts = Arc::new(SubmissionAttempts::default());
        attempts
            .begin(&[vec![1]], 130, OpKind::Join)
            .unwrap()
            .published(130);
        assert!(
            attempts.begin(&[vec![1]], 131, OpKind::Confirm).is_none(),
            "the join's retry fence holds a confirm off"
        );
        let running = attempts.begin(&[vec![2]], 130, OpKind::Join).unwrap();
        attempts
            .begin(&[vec![3]], 120, OpKind::Join)
            .unwrap()
            .published(120);
        attempts
            .begin(&[vec![4]], 130, OpKind::Leave)
            .unwrap()
            .published(130);
        let window = |filter: u8| (vec![filter], 121u64..841);
        assert_eq!(
            attempts.release_published_joins(&[window(1), window(2), window(3), window(4)]),
            vec![(vec![1], 130)]
        );
        assert!(attempts.begin(&[vec![1]], 131, OpKind::Confirm).is_some());
        assert!(
            attempts.owned(&[2], 131, OpKind::Confirm),
            "a join in flight keeps its filter"
        );
        assert!(
            attempts.owned(&[3], 131, OpKind::Confirm),
            "so does one outside the window"
        );
        assert!(
            attempts.owned(&[4], 131, OpKind::Confirm),
            "and an operation of another kind"
        );
        drop(running);
    }
}
