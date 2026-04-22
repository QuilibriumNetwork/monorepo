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

use quil_types::consensus::{ControlEvent, ControlEventData, ControlEventType};

/// Tracks which shard filters are currently in a `CoverageHalt` window.
/// Shared across the subscriber task (writer) and the lifecycle /
/// eviction scheduler (readers).
#[derive(Debug, Default)]
pub struct HaltState {
    halted_shards: RwLock<HashSet<Vec<u8>>>,
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

    /// Specifically check whether `filter` is in a halt window.
    pub fn is_halted(&self, filter: &[u8]) -> bool {
        self.halted_shards.read().unwrap().contains(filter)
    }

    pub fn mark_halted(&self, filter: Vec<u8>) {
        self.halted_shards.write().unwrap().insert(filter);
    }

    pub fn mark_resumed(&self, filter: &[u8]) {
        self.halted_shards.write().unwrap().remove(filter);
    }

    pub fn halted_count(&self) -> usize {
        self.halted_shards.read().unwrap().len()
    }

    /// Apply a single control event to the state. Returns `true` if
    /// the event changed state (so callers can decide whether to log).
    pub fn apply(&self, event: &ControlEvent) -> bool {
        match (event.event_type, &event.data) {
            (ControlEventType::CoverageHalt, ControlEventData::Coverage { filter, .. }) => {
                let mut guard = self.halted_shards.write().unwrap();
                guard.insert(filter.clone())
            }
            (ControlEventType::CoverageResume, ControlEventData::Coverage { filter, .. })
            | (ControlEventType::Resume, ControlEventData::Coverage { filter, .. }) => {
                let mut guard = self.halted_shards.write().unwrap();
                guard.remove(filter)
            }
            _ => false,
        }
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
