//! In-memory event distributor. Partial port of
//! `node/consensus/events/global_event_distributor.go`.
//!
//! Fan-out distribution of [`ControlEvent`]s to registered
//! subscribers via per-subscriber tokio mpsc channels.
//!
//! Semantics (matching Go):
//! - **Subscribe** allocates a buffered mpsc channel (capacity 100
//!   matches Go's hard-coded buffer) and returns the receiver to
//!   the caller. Subscribers are keyed by an opaque string id.
//! - **Publish** is non-blocking: for each subscriber, the distributor
//!   `try_send`s the event and silently drops on full/closed channel.
//!   This prevents a slow subscriber from deadlocking the event loop.
//! - **Unsubscribe** removes the subscriber from the map and drops
//!   the sender (causing the subscriber's receiver to close on next
//!   poll).
//!
//! Not ported from Go: the prometheus metrics wiring, the background
//! event-stream processor (time-reel integration), and the uptime
//! tracker. These are wire/monitoring concerns best added when the
//! broader engine integration lands.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::mpsc;

use quil_types::consensus::{ControlEvent, EventDistributor};

/// Default per-subscriber channel capacity. Matches Go's hard-coded
/// buffer in `GlobalEventDistributor::Subscribe`.
pub const DEFAULT_SUBSCRIBER_BUFFER: usize = 100;

/// In-memory tokio-backed implementation of [`EventDistributor`].
pub struct InMemoryEventDistributor {
    subscribers: Mutex<HashMap<String, mpsc::Sender<ControlEvent>>>,
    /// Per-subscriber channel buffer capacity. Configurable for tests
    /// that want to exercise the drop-on-full path with a small
    /// buffer.
    buffer_size: usize,
}

impl Default for InMemoryEventDistributor {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryEventDistributor {
    /// Build a distributor with the default buffer size.
    pub fn new() -> Self {
        Self::with_buffer(DEFAULT_SUBSCRIBER_BUFFER)
    }

    /// Build a distributor with a custom buffer size.
    pub fn with_buffer(buffer_size: usize) -> Self {
        Self {
            subscribers: Mutex::new(HashMap::new()),
            buffer_size,
        }
    }

    /// Number of currently registered subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().unwrap().len()
    }

    /// `true` if `id` is currently subscribed.
    pub fn has_subscriber(&self, id: &str) -> bool {
        self.subscribers.lock().unwrap().contains_key(id)
    }
}

impl EventDistributor for InMemoryEventDistributor {
    fn subscribe(&self, id: &str) -> mpsc::Receiver<ControlEvent> {
        let (tx, rx) = mpsc::channel(self.buffer_size);
        let mut guard = self.subscribers.lock().unwrap();
        // If the id already existed, the old sender is dropped, which
        // closes the previous receiver. This matches Go's overwrite
        // semantics (map insertion clobbers the existing entry).
        guard.insert(id.to_string(), tx);
        rx
    }

    fn publish(&self, event: ControlEvent) {
        // Snapshot the sender list under the lock, then release the
        // lock before firing the sends — matches Go's `RLock` pattern
        // and prevents reentrant deadlocks if a subscriber's channel
        // is backed by a task that might re-enter the distributor.
        let senders: Vec<(String, mpsc::Sender<ControlEvent>)> = {
            let guard = self.subscribers.lock().unwrap();
            guard
                .iter()
                .map(|(id, tx)| (id.clone(), tx.clone()))
                .collect()
        };

        for (_id, tx) in senders {
            // try_send is non-blocking: drops the event for this
            // subscriber if the channel is full or closed.
            let _ = tx.try_send(event.clone());
        }
    }

    fn unsubscribe(&self, id: &str) {
        let mut guard = self.subscribers.lock().unwrap();
        guard.remove(id); // drops the sender, closing the receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::consensus::{ControlEventData, ControlEventType};

    fn fresh_event(event_type: ControlEventType) -> ControlEvent {
        ControlEvent {
            event_type,
            data: ControlEventData::None,
        }
    }

    #[tokio::test]
    async fn subscribe_returns_receiver_with_events() {
        let d = InMemoryEventDistributor::new();
        let mut rx = d.subscribe("sub-a");
        d.publish(fresh_event(ControlEventType::Start));
        let evt = rx.recv().await.unwrap();
        assert_eq!(evt.event_type, ControlEventType::Start);
    }

    #[tokio::test]
    async fn publish_fans_out_to_all_subscribers() {
        let d = InMemoryEventDistributor::new();
        let mut rx_a = d.subscribe("a");
        let mut rx_b = d.subscribe("b");
        let mut rx_c = d.subscribe("c");
        d.publish(fresh_event(ControlEventType::GlobalNewHead));
        assert_eq!(rx_a.recv().await.unwrap().event_type, ControlEventType::GlobalNewHead);
        assert_eq!(rx_b.recv().await.unwrap().event_type, ControlEventType::GlobalNewHead);
        assert_eq!(rx_c.recv().await.unwrap().event_type, ControlEventType::GlobalNewHead);
    }

    #[tokio::test]
    async fn unsubscribe_closes_receiver() {
        let d = InMemoryEventDistributor::new();
        let mut rx = d.subscribe("ephemeral");
        d.unsubscribe("ephemeral");
        // Receiver should see a channel close on the next recv.
        assert!(rx.recv().await.is_none());
        assert_eq!(d.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn publish_after_unsubscribe_does_not_reach_dropped_sub() {
        let d = InMemoryEventDistributor::new();
        let mut rx_a = d.subscribe("a");
        let mut rx_b = d.subscribe("b");
        d.unsubscribe("a");
        d.publish(fresh_event(ControlEventType::CoverageHalt));
        // a should see the closed channel on its next recv.
        assert!(rx_a.recv().await.is_none());
        // b should see the event.
        assert_eq!(
            rx_b.recv().await.unwrap().event_type,
            ControlEventType::CoverageHalt
        );
    }

    #[tokio::test]
    async fn full_channel_drops_events_for_slow_subscriber() {
        // Small buffer so we can easily exhaust it. Publish N+2 events
        // without draining — the last 2 must be dropped silently,
        // the first N are still in the channel.
        let d = InMemoryEventDistributor::with_buffer(2);
        let mut rx = d.subscribe("slow");
        d.publish(fresh_event(ControlEventType::Start)); // buffered
        d.publish(fresh_event(ControlEventType::Stop)); // buffered
        d.publish(fresh_event(ControlEventType::Halt)); // dropped
        d.publish(fresh_event(ControlEventType::Resume)); // dropped

        // Drain — only the first two should be visible, in order.
        assert_eq!(rx.recv().await.unwrap().event_type, ControlEventType::Start);
        assert_eq!(rx.recv().await.unwrap().event_type, ControlEventType::Stop);
        // No third event available without blocking forever — use
        // try_recv to confirm.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn resubscribe_same_id_replaces_old_sender() {
        let d = InMemoryEventDistributor::new();
        let mut rx_old = d.subscribe("sub");
        let mut rx_new = d.subscribe("sub"); // clobbers old
        d.publish(fresh_event(ControlEventType::GlobalFork));
        // Old receiver sees the channel close (sender was dropped).
        assert!(rx_old.recv().await.is_none());
        // New receiver gets the event.
        assert_eq!(
            rx_new.recv().await.unwrap().event_type,
            ControlEventType::GlobalFork
        );
        // Still only one logical subscriber.
        assert_eq!(d.subscriber_count(), 1);
    }

    #[tokio::test]
    async fn subscriber_count_and_has_subscriber_track_membership() {
        let d = InMemoryEventDistributor::new();
        assert_eq!(d.subscriber_count(), 0);
        assert!(!d.has_subscriber("x"));
        let _rx = d.subscribe("x");
        assert_eq!(d.subscriber_count(), 1);
        assert!(d.has_subscriber("x"));
        d.unsubscribe("x");
        assert_eq!(d.subscriber_count(), 0);
        assert!(!d.has_subscriber("x"));
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_noop() {
        let d = InMemoryEventDistributor::new();
        // Should not panic or error.
        d.publish(fresh_event(ControlEventType::CoverageResume));
    }

    #[tokio::test]
    async fn concurrent_publish_and_subscribe_is_safe() {
        use std::sync::Arc;
        let d = Arc::new(InMemoryEventDistributor::new());
        let d2 = Arc::clone(&d);

        let mut rx = d.subscribe("observer");

        // Spawn 10 publishers, each firing 10 events concurrently.
        let mut handles = vec![];
        for i in 0..10u8 {
            let d3 = Arc::clone(&d2);
            handles.push(tokio::spawn(async move {
                for _ in 0..10 {
                    let event_type = match i % 4 {
                        0 => ControlEventType::Start,
                        1 => ControlEventType::Stop,
                        2 => ControlEventType::Halt,
                        _ => ControlEventType::Resume,
                    };
                    d3.publish(fresh_event(event_type));
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // The observer should receive at least some events (some may
        // have been dropped if the channel filled up — default buffer
        // is 100 and 100 events were published, so all should fit).
        let mut received = 0;
        while rx.try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(received, 100);
    }
}
