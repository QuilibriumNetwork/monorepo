//! Consensus verifier trait. Mirror of
//! `consensus/consensus_verifier.go::Verifier`.
//!
//! The `Verifier` checks the cryptographic integrity of votes, QCs,
//! and TCs. Unlike the [`Validator`](crate::validator::Validator),
//! the verifier focuses exclusively on signature-layer validity —
//! the validator does structural checks + authorization + delegates
//! to the verifier for the crypto.
//!
//! Concrete implementations live in crypto adapter crates and are
//! typically built on top of a
//! [`WeightedSignatureAggregator`](crate::signature_aggregator::WeightedSignatureAggregator).

use crate::models::{QuorumCertificate, TimeoutCertificate, Unique};
use quil_types::error::Result;

/// Cryptographic verifier for votes, QCs, and TCs. Mirror of Go's
/// `Verifier[VoteT]`.
///
/// All expected errors during normal operation are returned as
/// sentinel variants on [`quil_types::error::QuilError`]:
/// - `InvalidSignature` — a signature failed cryptographic verification.
/// - `InsufficientSignatures` — a QC/TC carries no signatures.
/// - `InvalidQuorumCertificate` / `InvalidTimeoutCertificate` — structural.
pub trait Verifier<V: Unique>: Send + Sync {
    /// Verify a vote's signature data. The caller is responsible for
    /// confirming the voter is authorized to participate at the vote's
    /// rank — this method only checks cryptographic validity.
    fn verify_vote(&self, vote: &V) -> Result<()>;

    /// Verify a QC's aggregate signature. The caller is responsible
    /// for ensuring all signers are authorized committee members for
    /// the QC's rank.
    fn verify_quorum_certificate(&self, qc: &dyn QuorumCertificate) -> Result<()>;

    /// Verify a TC's aggregate signature. Since each signer may have
    /// contributed a different `newest_qc_rank`, the verifier must
    /// reconstruct the per-signer message before checking.
    fn verify_timeout_certificate(&self, tc: &dyn TimeoutCertificate) -> Result<()>;
}
