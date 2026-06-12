//! Thread-safe engine lifecycle state machine. Mirrors the
//! atomic-state transitions in Go's per-engine
//! `state.CompareAndSwap` calls used across
//! `node/consensus/global/global_consensus_engine.go` and its app
//! counterpart.
//!
//! The state machine enforces a partial order over [`EngineState`]
//! values:
//!
//! ```text
//!     Stopped
//!       |
//!       v
//!     Starting -> Loading
//!                   |
//!                   v
//!     Collecting <-> LivenessCheck <-> Proving <-> Publishing
//!                         |
//!                         v
//!                     Voting <-> Finalizing <-> Verifying
//!                                     |
//!                                     v
//!                                 Stopping -> Stopped
//! ```
//!
//! Rather than encode the DAG exactly, we allow any forward-or-backward
//! transition within the "active" states and block transitions from
//! `Stopped` → anything except `Starting` or from `Stopping` →
//! anything except `Stopped`. This matches Go's looser semantics:
//! the engine can bounce between `Collecting`, `Proving`, `Voting`,
//! etc. as messages arrive.
//!
//! All transitions go through [`EngineStateMachine::transition_to`]
//! which returns the previous state on success or a
//! `QuilError::Consensus` on invalid transitions.

use std::sync::atomic::{AtomicU8, Ordering};

use quil_types::consensus::EngineState;
use quil_types::error::{QuilError, Result};

/// Thread-safe wrapper around [`EngineState`] storage, backed by an
/// `AtomicU8`. Reads are lock-free; transitions use compare-and-swap
/// to guarantee serializability without a mutex.
pub struct EngineStateMachine {
    state: AtomicU8,
}

impl Default for EngineStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineStateMachine {
    /// Construct a fresh state machine in `EngineState::Stopped`.
    pub fn new() -> Self {
        Self::from_state(EngineState::Stopped)
    }

    /// Construct a state machine initialized at the given state.
    /// Useful for restart / migration paths.
    pub fn from_state(state: EngineState) -> Self {
        Self {
            state: AtomicU8::new(state as u8),
        }
    }

    /// Load the current state (lock-free).
    pub fn current(&self) -> EngineState {
        Self::state_from_u8(self.state.load(Ordering::Acquire))
    }

    /// Attempt a state transition. Returns the previous state on
    /// success, or a `QuilError::Consensus` if the transition is
    /// invalid from the current state.
    ///
    /// Uses compare-and-swap internally, retrying once on a spurious
    /// race to accommodate concurrent readers.
    pub fn transition_to(&self, new_state: EngineState) -> Result<EngineState> {
        loop {
            let current_raw = self.state.load(Ordering::Acquire);
            let current = Self::state_from_u8(current_raw);
            if !Self::is_valid_transition(current, new_state) {
                return Err(QuilError::Consensus(format!(
                    "invalid engine state transition: {} -> {}",
                    current, new_state
                )));
            }
            // Identity transition is a no-op but not an error — the
            // engine loop can "re-enter" the current state (e.g. from
            // a retry path). We still consume the loop iteration so
            // the CAS semantics stay consistent.
            if current == new_state {
                return Ok(current);
            }
            match self.state.compare_exchange(
                current_raw,
                new_state as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(current),
                Err(_) => continue, // racy transition — retry with latest state
            }
        }
    }

    /// Convenience: unconditional state set. Used by shutdown paths
    /// that must force the engine into `Stopped` regardless of its
    /// current state.
    pub fn force_set(&self, new_state: EngineState) {
        self.state.store(new_state as u8, Ordering::Release);
    }

    /// Check whether transitioning `from -> to` is valid under the
    /// engine lifecycle rules.
    fn is_valid_transition(from: EngineState, to: EngineState) -> bool {
        use EngineState::*;
        // Self-transitions are always valid (reentering the same state).
        if from == to {
            return true;
        }
        match (from, to) {
            // Stopped can only transition to Starting.
            (Stopped, Starting) => true,
            (Stopped, _) => false,
            // Starting can go to Loading (normal path) or Stopping
            // (early shutdown).
            (Starting, Loading) | (Starting, Stopping) => true,
            (Starting, _) => false,
            // From Loading we enter the active phase at Collecting
            // (first state after genesis load) or bail to Stopping.
            (Loading, Collecting) | (Loading, Stopping) => true,
            (Loading, _) => false,
            // Stopping can only go to Stopped.
            (Stopping, Stopped) => true,
            (Stopping, _) => false,
            // All "active" states (Collecting through Verifying) can
            // transition to each other freely, or into Stopping.
            (
                Collecting | LivenessCheck | Proving | Publishing | Voting | Finalizing
                | Verifying,
                Collecting
                | LivenessCheck
                | Proving
                | Publishing
                | Voting
                | Finalizing
                | Verifying
                | Stopping,
            ) => true,
            (_, _) => false,
        }
    }

    fn state_from_u8(raw: u8) -> EngineState {
        match raw {
            0 => EngineState::Stopped,
            1 => EngineState::Starting,
            2 => EngineState::Loading,
            3 => EngineState::Collecting,
            4 => EngineState::LivenessCheck,
            5 => EngineState::Proving,
            6 => EngineState::Publishing,
            7 => EngineState::Voting,
            8 => EngineState::Finalizing,
            9 => EngineState::Verifying,
            10 => EngineState::Stopping,
            // Anything else indicates memory corruption; default to
            // Stopped so the engine can at least report a clean
            // shutdown state rather than panicking.
            _ => EngineState::Stopped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =================================================================
    // Construction
    // =================================================================

    #[test]
    fn new_starts_in_stopped() {
        let sm = EngineStateMachine::new();
        assert_eq!(sm.current(), EngineState::Stopped);
    }

    #[test]
    fn from_state_honors_initial() {
        let sm = EngineStateMachine::from_state(EngineState::Collecting);
        assert_eq!(sm.current(), EngineState::Collecting);
    }

    // =================================================================
    // Display / string round-trip
    // =================================================================

    #[test]
    fn engine_state_display_matches_go() {
        assert_eq!(EngineState::Stopped.to_string(), "stopped");
        assert_eq!(EngineState::Starting.to_string(), "starting");
        assert_eq!(EngineState::Loading.to_string(), "loading");
        assert_eq!(EngineState::Collecting.to_string(), "collecting");
        assert_eq!(
            EngineState::LivenessCheck.to_string(),
            "liveness_check"
        );
        assert_eq!(EngineState::Proving.to_string(), "proving");
        assert_eq!(EngineState::Publishing.to_string(), "publishing");
        assert_eq!(EngineState::Voting.to_string(), "voting");
        assert_eq!(EngineState::Finalizing.to_string(), "finalizing");
        assert_eq!(EngineState::Verifying.to_string(), "verifying");
        assert_eq!(EngineState::Stopping.to_string(), "stopping");
    }

    // =================================================================
    // Valid transitions
    // =================================================================

    #[test]
    fn stopped_can_start() {
        let sm = EngineStateMachine::new();
        let prev = sm.transition_to(EngineState::Starting).unwrap();
        assert_eq!(prev, EngineState::Stopped);
        assert_eq!(sm.current(), EngineState::Starting);
    }

    #[test]
    fn full_startup_chain() {
        let sm = EngineStateMachine::new();
        sm.transition_to(EngineState::Starting).unwrap();
        sm.transition_to(EngineState::Loading).unwrap();
        sm.transition_to(EngineState::Collecting).unwrap();
        sm.transition_to(EngineState::LivenessCheck).unwrap();
        sm.transition_to(EngineState::Proving).unwrap();
        sm.transition_to(EngineState::Publishing).unwrap();
        sm.transition_to(EngineState::Voting).unwrap();
        sm.transition_to(EngineState::Finalizing).unwrap();
        sm.transition_to(EngineState::Verifying).unwrap();
        sm.transition_to(EngineState::Stopping).unwrap();
        sm.transition_to(EngineState::Stopped).unwrap();
        assert_eq!(sm.current(), EngineState::Stopped);
    }

    #[test]
    fn active_states_are_freely_interconnected() {
        use EngineState::*;
        let active = [
            Collecting,
            LivenessCheck,
            Proving,
            Publishing,
            Voting,
            Finalizing,
            Verifying,
        ];
        for from in active {
            for to in active {
                let sm = EngineStateMachine::from_state(from);
                assert!(
                    sm.transition_to(to).is_ok(),
                    "expected {} -> {} to be valid",
                    from,
                    to
                );
            }
        }
    }

    #[test]
    fn self_transition_is_idempotent() {
        let sm = EngineStateMachine::from_state(EngineState::Proving);
        let prev = sm.transition_to(EngineState::Proving).unwrap();
        assert_eq!(prev, EngineState::Proving);
        assert_eq!(sm.current(), EngineState::Proving);
    }

    // =================================================================
    // Invalid transitions
    // =================================================================

    #[test]
    fn stopped_to_proving_rejected() {
        let sm = EngineStateMachine::new();
        let err = sm.transition_to(EngineState::Proving).unwrap_err();
        assert!(matches!(err, QuilError::Consensus(_)));
        // State must be unchanged after rejection.
        assert_eq!(sm.current(), EngineState::Stopped);
    }

    #[test]
    fn stopped_to_loading_rejected() {
        let sm = EngineStateMachine::new();
        assert!(sm.transition_to(EngineState::Loading).is_err());
    }

    #[test]
    fn stopping_to_proving_rejected() {
        let sm = EngineStateMachine::from_state(EngineState::Stopping);
        assert!(sm.transition_to(EngineState::Proving).is_err());
    }

    #[test]
    fn starting_cannot_skip_to_voting() {
        let sm = EngineStateMachine::from_state(EngineState::Starting);
        assert!(sm.transition_to(EngineState::Voting).is_err());
    }

    #[test]
    fn loading_cannot_skip_to_verifying() {
        let sm = EngineStateMachine::from_state(EngineState::Loading);
        assert!(sm.transition_to(EngineState::Verifying).is_err());
    }

    // =================================================================
    // Force set
    // =================================================================

    #[test]
    fn force_set_overrides_transition_rules() {
        let sm = EngineStateMachine::new();
        // Normally Stopped -> Proving would be rejected.
        sm.force_set(EngineState::Proving);
        assert_eq!(sm.current(), EngineState::Proving);
    }

    // =================================================================
    // Concurrency
    // =================================================================

    #[tokio::test]
    async fn concurrent_transitions_converge() {
        use std::sync::Arc;
        let sm = Arc::new(EngineStateMachine::from_state(EngineState::Collecting));
        let mut handles = vec![];
        for _ in 0..50 {
            let sm2 = Arc::clone(&sm);
            handles.push(tokio::spawn(async move {
                // Bounce between Proving and Voting concurrently.
                let _ = sm2.transition_to(EngineState::Proving);
                let _ = sm2.transition_to(EngineState::Voting);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        // Final state should be one of Proving or Voting.
        let final_state = sm.current();
        assert!(
            matches!(
                final_state,
                EngineState::Proving | EngineState::Voting
            ),
            "final state was {:?}",
            final_state
        );
    }

    #[test]
    fn transition_returns_previous_state() {
        let sm = EngineStateMachine::from_state(EngineState::Collecting);
        let prev = sm.transition_to(EngineState::Proving).unwrap();
        assert_eq!(prev, EngineState::Collecting);
        let prev2 = sm.transition_to(EngineState::Voting).unwrap();
        assert_eq!(prev2, EngineState::Proving);
    }
}
