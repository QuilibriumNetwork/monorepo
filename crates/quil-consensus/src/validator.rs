//! Consensus validator trait. Mirror of
//! `consensus/consensus_validator.go::Validator`.
//!
//! A `Validator` checks the structural and cryptographic validity of
//! QCs, TCs, proposals, and votes. The concrete implementation lives in
//! the engine crate and usually delegates to the
//! [`WeightedSignatureAggregator`](crate::signature_aggregator::WeightedSignatureAggregator)
//! for signature verification.

use crate::models::{QuorumCertificate, SignedProposal, TimeoutCertificate, Unique, WeightedIdentity};
use quil_types::error::Result;

/// Validates consensus artifacts. Mirror of Go's
/// `Validator[StateT, VoteT]`.
///
/// All expected errors during normal operations are returned as
/// sentinel variants on [`QuilError`](quil_types::error::QuilError):
/// `InvalidQuorumCertificate`, `InvalidTimeoutCertificate`,
/// `InvalidProposal`, `InvalidVote`, and `RankUnknown`.
pub trait Validator<S: Unique, V: Unique>: Send + Sync {
    fn validate_quorum_certificate(&self, qc: &dyn QuorumCertificate) -> Result<()>;
    fn validate_timeout_certificate(&self, tc: &dyn TimeoutCertificate) -> Result<()>;
    fn validate_proposal(&self, proposal: &SignedProposal<S, V>) -> Result<()>;
    /// Validate a vote and return the weighted identity of its signer.
    fn validate_vote(&self, vote: &V) -> Result<Box<dyn WeightedIdentity>>;
}
