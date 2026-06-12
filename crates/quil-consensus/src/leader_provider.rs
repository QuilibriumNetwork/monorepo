//! Leader provider trait. Mirror of
//! `consensus/consensus_leader.go::LeaderProvider`.
//!
//! The leader provider is the application's hook for:
//! 1. Selecting leaders for upcoming ranks.
//! 2. Producing a new state proposal as the current leader.
//!
//! Concrete implementations live in adapter crates (e.g. `quil-engine`).

use crate::models::{Identity, State, Unique};
use quil_types::error::Result;

/// Abstracts leader selection and state production. Parameterized
/// over the application state type `S`; PeerID identities are just
/// `Identity` strings.
pub trait LeaderProvider<S: Unique>: Send + Sync {
    /// Return the priority-ordered list of leader peer IDs for the
    /// next rank. If `prior` is `None`, use the genesis / bootstrap
    /// list. Must return a non-empty list on success.
    fn get_next_leaders(&self, prior: Option<&State<S>>) -> Result<Vec<Identity>>;

    /// Prepare a new un-finalized state at the given rank. Called by
    /// the state producer when this node is elected leader for `rank`.
    fn prove_next_state(
        &self,
        rank: u64,
        filter: &[u8],
        prior_state: &Identity,
    ) -> Result<State<S>>;
}
