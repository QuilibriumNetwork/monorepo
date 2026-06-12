//! Voting provider trait. Mirror of
//! `consensus/consensus_voting.go::VotingProvider`.
//!
//! The voting provider is the application's hook for signing votes and
//! finalizing QCs / TCs once the signature aggregators have collected a
//! supermajority. Concrete impls live in adapter crates.

use std::sync::Arc;

use crate::models::{AggregatedSignature, QuorumCertificate, State, TimeoutCertificate, Unique};
use crate::signature_aggregator::TimeoutSignerInfo;
use quil_types::error::Result;

/// Delegates vote / QC / TC construction to the application layer.
/// Parameterized over state `S` and vote `V` types (same as Go's
/// `VotingProvider[StateT, VoteT, PeerIDT]`; we drop the PeerIDT
/// parameter since it's only used by consumers that don't touch this
/// trait).
pub trait VotingProvider<S: Unique, V: Unique>: Send + Sync {
    /// Sign the given state and produce a single vote for aggregation.
    fn sign_vote(&self, state: &State<S>) -> Result<V>;

    /// Sign a timeout vote. Used by safety-rules when declaring a
    /// timeout for the current rank.
    fn sign_timeout_vote(
        &self,
        filter: &[u8],
        current_rank: u64,
        newest_qc_rank: u64,
    ) -> Result<V>;

    /// Finalize a QC from an aggregated signature. Called by the
    /// vote processor once the aggregator reaches quorum weight.
    fn finalize_quorum_certificate(
        &self,
        state: &State<S>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn QuorumCertificate>>;

    /// Finalize a TC from an aggregated timeout signature plus
    /// per-signer QC-rank contributions.
    fn finalize_timeout(
        &self,
        rank: u64,
        latest_qc: Arc<dyn QuorumCertificate>,
        signers_info: Vec<TimeoutSignerInfo>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn TimeoutCertificate>>;
}

/// Callback fired by the vote processor on successful QC construction.
/// Mirror of Go's `OnQuorumCertificateCreated`.
pub type OnQuorumCertificateCreated = Arc<dyn Fn(Arc<dyn QuorumCertificate>) + Send + Sync>;

/// Callback fired by the timeout processor on successful TC construction.
pub type OnTimeoutCertificateCreated = Arc<dyn Fn(Arc<dyn TimeoutCertificate>) + Send + Sync>;
