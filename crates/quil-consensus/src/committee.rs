use crate::models::{Identity, WeightedIdentity};
use quil_types::error::Result;

/// The consensus committee: determines leaders, quorum thresholds, and
/// participant weights. Provided by the application layer.
pub trait Replicas: Send + Sync {
    /// Get the leader for the given rank.
    fn leader_for_rank(&self, rank: u64) -> Result<Identity>;

    /// Get the quorum threshold (>2/3 weight) for the given rank.
    fn quorum_threshold_for_rank(&self, rank: u64) -> Result<u64>;

    /// Get the timeout threshold (>1/3 weight) for the given rank.
    fn timeout_threshold_for_rank(&self, rank: u64) -> Result<u64>;

    /// Get this node's identity.
    fn self_identity(&self) -> &Identity;

    /// Get all committee members for a rank with their weights.
    fn identities_by_rank(&self, rank: u64) -> Result<Vec<Box<dyn WeightedIdentity>>>;

    /// Look up a specific committee member by rank and participant ID.
    fn identity_by_rank(
        &self,
        rank: u64,
        participant_id: &Identity,
    ) -> Result<Box<dyn WeightedIdentity>>;
}

/// Extended committee that supports dynamic membership based on state.
pub trait DynamicCommittee: Replicas {
    /// Get members by state ID (for proposal validation in dynamic committees).
    fn identities_by_state(
        &self,
        state_id: &Identity,
    ) -> Result<Vec<Box<dyn WeightedIdentity>>>;

    fn identity_by_state(
        &self,
        state_id: &Identity,
        participant_id: &Identity,
    ) -> Result<Box<dyn WeightedIdentity>>;
}
