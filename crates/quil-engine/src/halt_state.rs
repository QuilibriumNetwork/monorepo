//! Shared halt-state view consumed by the worker allocator / prover
//! lifecycle. Populated by a subscriber task that listens to the
//! `EventDistributor` for `CoverageHalt` / `CoverageResume` events.
//!
//! Mirrors the Go node's gate at `global_consensus_engine.go`:
//! - join proposals block while any shard is halted (so a struggling
//!   shard doesn't get flooded with new joiners before recovery)
//! - archive-node eviction skips entirely while any halt is active
//!   (otherwise evictions would cascade during the halt window)

use std::collections::HashSet;
use std::sync::RwLock;

use tokio::sync::watch;

use quil_types::consensus::{ControlEvent, ControlEventData, ControlEventType};

/// Tracks which shard filters are currently in a `CoverageHalt` window.
/// Shared across the subscriber task (writer) and the lifecycle /
/// eviction scheduler (readers).
///
/// Exposes both a polling API (`any_halted`, `is_halted`) for sites
/// that check on their own cadence and a `watch::Receiver<bool>`
/// (via [`watch_any_halted`](Self::watch_any_halted)) so async
/// consumers can wake on halt transitions instead of busy-checking.
#[derive(Debug)]
pub struct HaltState {
    halted_shards: RwLock<HashSet<Vec<u8>>>,
    /// Sender side of an `any_halted` boolean watch channel. Updated
    /// after every state mutation (idempotent updates with the same
    /// value are still issued; `watch` deduplicates internally).
    any_halted_tx: watch::Sender<bool>,
}

impl Default for HaltState {
    fn default() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self {
            halted_shards: RwLock::new(HashSet::new()),
            any_halted_tx: tx,
        }
    }
}

impl HaltState {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` iff at least one shard is currently halted. This is the
    /// gate used by `ProverLifecycle::join_proposal_ready` and the
    /// eviction scheduler.
    pub fn any_halted(&self) -> bool {
        !self.halted_shards.read().unwrap().is_empty()
    }

    /// Subscribe to halt-state transitions. The receiver yields the
    /// current value immediately on first read; subsequent `changed`
    /// awaits resolve when `any_halted()` flips. Multiple consumers
    /// can subscribe independently.
    pub fn watch_any_halted(&self) -> watch::Receiver<bool> {
        self.any_halted_tx.subscribe()
    }

    /// Specifically check whether `filter` is in a halt window.
    pub fn is_halted(&self, filter: &[u8]) -> bool {
        self.halted_shards.read().unwrap().contains(filter)
    }

    pub fn mark_halted(&self, filter: Vec<u8>) {
        let became_halted = {
            let mut guard = self.halted_shards.write().unwrap();
            let was_empty = guard.is_empty();
            guard.insert(filter);
            was_empty
        };
        if became_halted {
            let _ = self.any_halted_tx.send(true);
        }
    }

    pub fn mark_resumed(&self, filter: &[u8]) {
        let now_empty = {
            let mut guard = self.halted_shards.write().unwrap();
            guard.remove(filter);
            guard.is_empty()
        };
        if now_empty {
            let _ = self.any_halted_tx.send(false);
        }
    }

    pub fn halted_count(&self) -> usize {
        self.halted_shards.read().unwrap().len()
    }

    /// Hard halt — triggered by a verified `GlobalAlert`. Inserts a
    /// sentinel entry that `any_halted()` will always see as true,
    /// and fires the watch channel so every shard engine's
    /// `set_halted(true)` fires immediately. Unlike per-shard halts,
    /// a hard halt is permanent for this process lifetime — there is
    /// no "resume" path for a global alert. The operator must restart
    /// the node after the alert is resolved.
    pub fn hard_halt(&self) {
        let sentinel = b"__GLOBAL_ALERT_HARD_HALT__".to_vec();
        let mut guard = self.halted_shards.write().unwrap();
        guard.insert(sentinel);
        let _ = self.any_halted_tx.send(true);
    }

    /// Apply a single control event to the state. Returns `true` if
    /// the event changed state (so callers can decide whether to log).
    /// Sends the new `any_halted()` value on the watch channel when
    /// the boolean transitions; consumers awaiting `changed()` wake
    /// up automatically.
    pub fn apply(&self, event: &ControlEvent) -> bool {
        let (changed, new_any) = match (event.event_type, &event.data) {
            (ControlEventType::CoverageHalt, ControlEventData::Coverage { filter, .. }) => {
                let mut guard = self.halted_shards.write().unwrap();
                let was_empty = guard.is_empty();
                let inserted = guard.insert(filter.clone());
                (inserted, !guard.is_empty() && was_empty)
            }
            (ControlEventType::CoverageResume, ControlEventData::Coverage { filter, .. })
            | (ControlEventType::Resume, ControlEventData::Coverage { filter, .. }) => {
                let mut guard = self.halted_shards.write().unwrap();
                let removed = guard.remove(filter);
                let now_empty = guard.is_empty();
                (removed, removed && now_empty)
            }
            _ => (false, false),
        };
        if new_any {
            // Sender::send is a no-op when no receivers exist, so
            // the watch channel is safe to fire unconditionally.
            let _ = self
                .any_halted_tx
                .send(!self.halted_shards.read().unwrap().is_empty());
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn halt_event(filter: Vec<u8>) -> ControlEvent {
        ControlEvent {
            event_type: ControlEventType::CoverageHalt,
            data: ControlEventData::Coverage { filter, duration: u64::MAX },
        }
    }

    fn resume_event(filter: Vec<u8>) -> ControlEvent {
        ControlEvent {
            event_type: ControlEventType::CoverageResume,
            data: ControlEventData::Coverage { filter, duration: 0 },
        }
    }

    #[test]
    fn halt_then_resume_clears_state() {
        let s = HaltState::new();
        assert!(!s.any_halted());

        s.apply(&halt_event(vec![0x01]));
        assert!(s.any_halted());
        assert!(s.is_halted(&[0x01]));

        s.apply(&resume_event(vec![0x01]));
        assert!(!s.any_halted());
    }

    #[test]
    fn multiple_halts_are_independent() {
        let s = HaltState::new();
        s.apply(&halt_event(vec![0x01]));
        s.apply(&halt_event(vec![0x02]));
        assert_eq!(s.halted_count(), 2);

        s.apply(&resume_event(vec![0x01]));
        assert_eq!(s.halted_count(), 1);
        assert!(!s.is_halted(&[0x01]));
        assert!(s.is_halted(&[0x02]));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn watch_channel_fires_on_first_halt_and_full_resume() {
        let s = HaltState::new();
        let mut rx = s.watch_any_halted();
        assert!(!*rx.borrow_and_update());

        // First halt — transitions from "no halts" to "any halted".
        s.apply(&halt_event(vec![0x01]));
        rx.changed().await.unwrap();
        assert!(*rx.borrow_and_update());

        // Adding a second halt while one is already active should NOT
        // re-fire the channel — the boolean didn't transition.
        s.apply(&halt_event(vec![0x02]));
        let polled = tokio::time::timeout(std::time::Duration::from_millis(10), rx.changed()).await;
        assert!(polled.is_err(), "channel should not fire when boolean is unchanged");

        // Resuming one of two leaves any_halted=true — still no fire.
        s.apply(&resume_event(vec![0x01]));
        let polled = tokio::time::timeout(std::time::Duration::from_millis(10), rx.changed()).await;
        assert!(polled.is_err(), "channel should not fire while another halt is active");

        // Resuming the last one transitions back to false.
        s.apply(&resume_event(vec![0x02]));
        rx.changed().await.unwrap();
        assert!(!*rx.borrow_and_update());
    }

    #[test]
    fn unrelated_events_are_ignored() {
        let s = HaltState::new();
        let warn_event = ControlEvent {
            event_type: ControlEventType::CoverageWarn,
            data: ControlEventData::Coverage { filter: vec![0x01], duration: 120 },
        };
        assert!(!s.apply(&warn_event));
        assert!(!s.any_halted());
    }
}
