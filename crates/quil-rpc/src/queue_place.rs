//! A place in a bounded wait queue, counted until it is dropped.
//!
//! A request handler that waits for a worker slot is a future the server
//! drops when its caller resets the stream or the connection ends. A count
//! raised before such a wait and lowered after it would then never be
//! lowered. Once the leaked count reached its bound, a read that found
//! every slot busy was refused at once instead of waiting. The place
//! lowers the count on drop instead.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub(crate) struct QueuePlace<'a> {
    waiting: &'a AtomicUsize,
    queued: usize,
    /// Counts the place as abandoned on drop, unless it left the queue.
    abandoned: Option<&'a AtomicU64>,
}

impl<'a> QueuePlace<'a> {
    /// A place in the queue `waiting` counts, unless `max` are taken.
    pub(crate) fn take(waiting: &'a AtomicUsize, max: usize) -> Option<Self> {
        let before = waiting
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()?;
        Some(Self {
            waiting,
            queued: before + 1,
            abandoned: None,
        })
    }

    /// The queue's count as this place joined it, this place included.
    pub(crate) fn queued(&self) -> usize {
        self.queued
    }

    /// Count into `abandoned` a place dropped before it leaves the queue
    /// (its request cancelled while waiting).
    pub(crate) fn abandoned_into(mut self, abandoned: &'a AtomicU64) -> Self {
        self.abandoned = Some(abandoned);
        self
    }

    /// Leave the queue: the wait ended, with or without a slot.
    pub(crate) fn leave(mut self) {
        self.abandoned = None;
    }
}

impl Drop for QueuePlace<'_> {
    fn drop(&mut self) {
        self.waiting.fetch_sub(1, Ordering::Relaxed);
        if let Some(abandoned) = self.abandoned {
            abandoned.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_place_is_counted_until_dropped_and_the_bound_holds() {
        let waiting = AtomicUsize::new(0);
        let abandoned = AtomicU64::new(0);
        let first = QueuePlace::take(&waiting, 2).unwrap();
        let second = QueuePlace::take(&waiting, 2)
            .unwrap()
            .abandoned_into(&abandoned);
        assert_eq!((first.queued(), second.queued()), (1, 2));
        assert!(QueuePlace::take(&waiting, 2).is_none(), "the bound holds");
        assert_eq!(waiting.load(Ordering::Relaxed), 2);
        first.leave();
        drop(second);
        assert_eq!(waiting.load(Ordering::Relaxed), 0);
        assert_eq!(
            abandoned.load(Ordering::Relaxed),
            1,
            "dropped while waiting"
        );
    }
}
