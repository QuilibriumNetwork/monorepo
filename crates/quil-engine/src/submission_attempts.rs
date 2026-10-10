//! Shared ownership of asynchronous shard operations. Reservations survive
//! preparation and block other operation kinds until completion; successful
//! publication retains a bounded retry fence, not a registry acknowledgement.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const RETRY_FRAMES: u64 = 30;
type Key = (u64, Vec<u8>);

#[derive(Default)]
pub(crate) struct SubmissionAttempts(Mutex<HashMap<Key, Attempt>>);

struct Attempt {
    frame: u64,
    in_flight: bool,
}

pub(crate) struct SubmissionAttempt {
    owner: Arc<SubmissionAttempts>,
    keys: Vec<Key>,
    published_frames: HashMap<Vec<u8>, u64>,
}

impl SubmissionAttempts {
    pub(crate) fn begin(
        self: &Arc<Self>,
        filters: &[Vec<u8>],
        frame: u64,
    ) -> Option<SubmissionAttempt> {
        if filters.is_empty() {
            return None;
        }
        let epoch = quil_types::consensus::epoch_for_frame(frame);
        let mut attempts = self.0.lock().ok()?;
        attempts.retain(|(e, _), a| {
            a.in_flight || (*e == epoch && frame.saturating_sub(a.frame) < RETRY_FRAMES)
        });
        if filters.iter().any(|f| {
            attempts
                .iter()
                .any(|((e, existing), a)| existing == f && (a.in_flight || *e == epoch))
        }) {
            return None;
        }
        let keys: Vec<Key> = filters.iter().map(|f| (epoch, f.clone())).collect();
        for key in &keys {
            attempts.insert(
                key.clone(),
                Attempt {
                    frame,
                    in_flight: true,
                },
            );
        }
        Some(SubmissionAttempt {
            owner: self.clone(),
            keys,
            published_frames: HashMap::new(),
        })
    }
}

impl SubmissionAttempt {
    pub(crate) fn published(mut self, frame: u64) {
        for (_, filter) in &self.keys {
            self.published_frames.insert(filter.clone(), frame);
        }
    }

    /// A later chunk failure cannot erase ownership of an already published
    /// subset. Unpublished filters are released when this guard is dropped.
    pub(crate) fn published_subset(&mut self, filters: &[Vec<u8>], frame: u64) {
        for filter in filters {
            if self.keys.iter().any(|(_, owned)| owned == filter) {
                self.published_frames.insert(filter.clone(), frame);
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
        let first = attempts.begin(&filters, 10).unwrap();
        assert!(attempts.begin(&filters, 100).is_none());
        drop(first); // Cancellation/failure releases the reservation.
        attempts.begin(&filters, 100).unwrap().published(100);
        assert!(attempts.begin(&filters, 101).is_none());
        assert!(attempts.begin(&filters, 130).is_some());
        attempts.begin(&filters, 719).unwrap().published(719);
        assert!(attempts.begin(&filters, 720).is_some());
    }

    #[test]
    fn cooldown_starts_when_preparation_and_publication_finish() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let filters = vec![vec![1]];
        attempts.begin(&filters, 10).unwrap().published(50);
        assert!(attempts.begin(&filters, 79).is_none());
        assert!(attempts.begin(&filters, 80).is_some());
    }

    #[test]
    fn later_chunk_failure_keeps_published_subset_reserved() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let mut guard = attempts.begin(&[vec![1], vec![2]], 10).unwrap();
        guard.published_subset(&[vec![1]], 12);
        drop(guard); // The other chunk failed before publication.
        assert!(attempts.begin(&[vec![1]], 13).is_none());
        assert!(attempts.begin(&[vec![2]], 13).is_some());
        assert!(attempts.begin(&[vec![1]], 42).is_some());
    }

    #[test]
    fn running_task_retains_ownership_across_epoch_boundaries() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let running = attempts.begin(&[vec![1]], 719).unwrap();
        assert!(attempts.begin(&[vec![1]], 720).is_none());
        assert!(attempts.begin(&[vec![1]], 1440).is_none());
        drop(running);
        assert!(attempts.begin(&[vec![1]], 1440).is_some());
    }

    #[test]
    fn overlapping_batches_cannot_encode_the_same_filter_concurrently() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let guard = attempts.begin(&[vec![1], vec![2]], 10).unwrap();
        assert!(attempts.begin(&[vec![2], vec![3]], 11).is_none());
        assert!(attempts.begin(&[vec![3]], 11).is_some());
        drop(guard);
        assert!(attempts.begin(&[vec![2]], 12).is_some());
    }
}
