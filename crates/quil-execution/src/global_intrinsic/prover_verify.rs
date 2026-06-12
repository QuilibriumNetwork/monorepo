//! Prover op signing-message construction and domain-hash computation.
//!
//! Each prover op builds a signing message and a Poseidon-hashed domain
//! separator, then uses BLS48-581 G1 signature verification via the
//! `KeyManager`. This module ports the pure functions that construct
//! those bytes:
//!
//! - `prover_pause_signing_message` / `prover_pause_domain`
//! - `prover_resume_signing_message` / `prover_resume_domain`
//! - `prover_leave_signing_message` / `prover_leave_domain`
//! - `prover_join_signing_message` / `prover_join_domain`
//! - `prover_confirm_signing_message` / `prover_confirm_domain`
//! - `prover_reject_signing_message` / `prover_reject_domain`
//!
//! Domain computation: `poseidon_hash(GLOBAL_INTRINSIC_ADDRESS || "PROVER_<OP>")`
//!
//! Signing message: varies per op but typically `filter || frame_number_be_u64`.
//!
//! These are the exact bytes a valid BLS48-581 G1 signature must cover.

use quil_crypto::poseidon::hash_bytes_to_32;
use quil_types::error::Result;

use crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;

// =====================================================================
// Domain tags — the strings Go uses in `slices.Concat(GLOBAL_INTRINSIC_ADDRESS, []byte(TAG))`
// =====================================================================

pub const PROVER_PAUSE_TAG: &[u8] = b"PROVER_PAUSE";
pub const PROVER_RESUME_TAG: &[u8] = b"PROVER_RESUME";
pub const PROVER_LEAVE_TAG: &[u8] = b"PROVER_LEAVE";
pub const PROVER_JOIN_TAG: &[u8] = b"PROVER_JOIN";
pub const PROVER_CONFIRM_TAG: &[u8] = b"PROVER_CONFIRM";
pub const PROVER_REJECT_TAG: &[u8] = b"PROVER_REJECT";

// =====================================================================
// Domain hash computation
// =====================================================================

/// Compute `poseidon_hash(GLOBAL_INTRINSIC_ADDRESS || tag)` → 32 bytes.
/// This is the BLS domain separator used in `sign_with_domain` / `ValidateSignature`.
fn compute_domain(tag: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(32 + tag.len());
    preimage.extend_from_slice(&GLOBAL_INTRINSIC_ADDRESS);
    preimage.extend_from_slice(tag);
    hash_bytes_to_32(&preimage)
}

/// Domain separator for ProverPause signatures.
pub fn prover_pause_domain() -> Result<[u8; 32]> {
    compute_domain(PROVER_PAUSE_TAG)
}

/// Domain separator for ProverResume signatures.
pub fn prover_resume_domain() -> Result<[u8; 32]> {
    compute_domain(PROVER_RESUME_TAG)
}

/// Domain separator for ProverLeave signatures.
pub fn prover_leave_domain() -> Result<[u8; 32]> {
    compute_domain(PROVER_LEAVE_TAG)
}

/// Domain separator for ProverJoin signatures.
pub fn prover_join_domain() -> Result<[u8; 32]> {
    compute_domain(PROVER_JOIN_TAG)
}

/// Domain separator for ProverConfirm signatures.
pub fn prover_confirm_domain() -> Result<[u8; 32]> {
    compute_domain(PROVER_CONFIRM_TAG)
}

/// Domain separator for ProverReject signatures.
pub fn prover_reject_domain() -> Result<[u8; 32]> {
    compute_domain(PROVER_REJECT_TAG)
}

// =====================================================================
// Signing-message construction
// =====================================================================
//
// All prover filter ops share the same shape:
//   message = filter(s) || frame_number_be_u64
//
// ProverJoin also includes the delegate_address and merge target data
// in its signing message, but the base shape is filters + frame_number.

/// Build the signing message for a single-filter op (Pause, Resume).
/// `message = filter || frame_number_be_u64`
pub fn single_filter_signing_message(filter: &[u8], frame_number: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(filter.len() + 8);
    msg.extend_from_slice(filter);
    msg.extend_from_slice(&frame_number.to_be_bytes());
    msg
}

/// Build the signing message for a multi-filter op (Leave, Confirm, Reject).
/// For Leave: `message = concat(filters) || frame_number_be_u64`
/// For Confirm/Reject: the Go code uses a similar construction but the
/// older `filter` field is deprecated and `filters` is the canonical list.
pub fn multi_filter_signing_message(filters: &[Vec<u8>], frame_number: u64) -> Vec<u8> {
    let total: usize = filters.iter().map(|f| f.len()).sum::<usize>() + 8;
    let mut msg = Vec::with_capacity(total);
    for f in filters {
        msg.extend_from_slice(f);
    }
    msg.extend_from_slice(&frame_number.to_be_bytes());
    msg
}

/// Build the signing message for ProverJoin.
/// `message = concat(filters) || frame_number_be_u64`
///
/// Note: the Go code builds the join message similarly — filters
/// concatenated, then frame number. The delegate_address and merge
/// targets are NOT part of the signed message — they're verified
/// structurally but not covered by the BLS signature.
pub fn prover_join_signing_message(filters: &[Vec<u8>], frame_number: u64) -> Vec<u8> {
    multi_filter_signing_message(filters, frame_number)
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Domain hashes — deterministic and distinct
    // -----------------------------------------------------------------

    #[test]
    fn all_domains_are_32_bytes() {
        assert_eq!(prover_pause_domain().unwrap().len(), 32);
        assert_eq!(prover_resume_domain().unwrap().len(), 32);
        assert_eq!(prover_leave_domain().unwrap().len(), 32);
        assert_eq!(prover_join_domain().unwrap().len(), 32);
        assert_eq!(prover_confirm_domain().unwrap().len(), 32);
        assert_eq!(prover_reject_domain().unwrap().len(), 32);
    }

    #[test]
    fn join_domain_matches_go() {
        // Go output: 119f001807263a15cb88c6e36c7377ddfecfcca1992d5b1aa711a9a372e075cb
        let domain = prover_join_domain().unwrap();
        assert_eq!(
            hex::encode(domain),
            "119f001807263a15cb88c6e36c7377ddfecfcca1992d5b1aa711a9a372e075cb",
            "Poseidon domain hash must match Go exactly"
        );
    }

    #[test]
    fn all_domains_are_distinct() {
        let domains = [
            prover_pause_domain().unwrap(),
            prover_resume_domain().unwrap(),
            prover_leave_domain().unwrap(),
            prover_join_domain().unwrap(),
            prover_confirm_domain().unwrap(),
            prover_reject_domain().unwrap(),
        ];
        for (i, a) in domains.iter().enumerate() {
            for (j, b) in domains.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "domains {} and {} collide", i, j);
                }
            }
        }
    }

    #[test]
    fn domains_are_deterministic() {
        assert_eq!(prover_pause_domain().unwrap(), prover_pause_domain().unwrap());
        assert_eq!(prover_join_domain().unwrap(), prover_join_domain().unwrap());
    }

    #[test]
    fn domains_are_nonzero() {
        for d in [
            prover_pause_domain().unwrap(),
            prover_resume_domain().unwrap(),
            prover_leave_domain().unwrap(),
        ] {
            assert!(d.iter().any(|&b| b != 0));
        }
    }

    // -----------------------------------------------------------------
    // Signing messages
    // -----------------------------------------------------------------

    #[test]
    fn single_filter_signing_message_layout() {
        let filter = vec![0xAAu8; 32];
        let msg = single_filter_signing_message(&filter, 42);
        assert_eq!(msg.len(), 32 + 8);
        assert_eq!(&msg[..32], &filter[..]);
        assert_eq!(&msg[32..], &42u64.to_be_bytes());
    }

    #[test]
    fn multi_filter_signing_message_concatenates_all() {
        let filters = vec![vec![1u8; 32], vec![2u8; 32]];
        let msg = multi_filter_signing_message(&filters, 100);
        assert_eq!(msg.len(), 64 + 8);
        assert_eq!(&msg[..32], &[1u8; 32][..]);
        assert_eq!(&msg[32..64], &[2u8; 32][..]);
        assert_eq!(&msg[64..], &100u64.to_be_bytes());
    }

    #[test]
    fn single_filter_empty_filter_still_has_frame_number() {
        let msg = single_filter_signing_message(&[], 0);
        assert_eq!(msg.len(), 8);
        assert_eq!(&msg[..], &0u64.to_be_bytes());
    }

    #[test]
    fn prover_join_signing_message_matches_multi_filter() {
        let filters = vec![vec![0xBBu8; 48]];
        assert_eq!(
            prover_join_signing_message(&filters, 7),
            multi_filter_signing_message(&filters, 7)
        );
    }
}
