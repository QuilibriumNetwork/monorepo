//! One in-flight confirmation per filter, with cooldown only after publication.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const RETRY_FRAMES: u64 = 30;
type Key = (u64, Vec<u8>);

#[derive(Default)]
pub(crate) struct ConfirmationAttempts(Mutex<HashMap<Key, Attempt>>);

struct Attempt {
    frame: u64,
    in_flight: bool,
}

pub(crate) struct ConfirmationAttempt {
    owner: Arc<ConfirmationAttempts>,
    keys: Vec<Key>,
    published_frame: Option<u64>,
}

impl ConfirmationAttempts {
    pub(crate) fn begin(
        self: &Arc<Self>,
        filters: &[Vec<u8>],
        frame: u64,
    ) -> Option<ConfirmationAttempt> {
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
        Some(ConfirmationAttempt {
            owner: self.clone(),
            keys,
            published_frame: None,
        })
    }
}

impl ConfirmationAttempt {
    pub(crate) fn published(mut self, frame: u64) {
        self.published_frame = Some(frame);
    }
}

impl Drop for ConfirmationAttempt {
    fn drop(&mut self) {
        if let Ok(mut attempts) = self.owner.0.lock() {
            for key in &self.keys {
                if let Some(frame) = self.published_frame {
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
        let attempts = Arc::new(ConfirmationAttempts::default());
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
        let attempts = Arc::new(ConfirmationAttempts::default());
        let filters = vec![vec![1]];
        attempts.begin(&filters, 10).unwrap().published(50);
        assert!(attempts.begin(&filters, 79).is_none());
        assert!(attempts.begin(&filters, 80).is_some());
    }

    #[test]
    fn overlapping_batches_cannot_encode_the_same_filter_concurrently() {
        let attempts = Arc::new(ConfirmationAttempts::default());
        let guard = attempts.begin(&[vec![1], vec![2]], 10).unwrap();
        assert!(attempts.begin(&[vec![2], vec![3]], 11).is_none());
        assert!(attempts.begin(&[vec![3]], 11).is_some());
        drop(guard);
        assert!(attempts.begin(&[vec![2]], 12).is_some());
    }
}
