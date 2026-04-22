//! Token transaction verification. Ports the crypto-level checks
//! from `token_intrinsic_transaction.go:1471-1601`.
//!
//! What's implemented:
//! - Structural validation (input/output counts, fee bounds)
//! - Bulletproof range proof verification
//! - Bulletproof sum check (inputs == outputs + fees)
//!
//! What's NOT implemented (needs state lookups):
//! - Per-input signature verification (needs traversal proof)
//! - Double-spend check (needs vertex lookup)
//! - Verification key uniqueness check (needs vertex lookup)
//! - Traversal proof verification (needs shard commits)

use num_bigint::BigInt;
use num_traits::One;
use quil_types::crypto::BulletproofProver;
use quil_types::error::{QuilError, Result};


/// Maximum number of inputs or outputs in a single transaction.
pub const MAX_IO_COUNT: usize = 100;
/// Range proof bit size (128 bits — covers values up to 2^128).
pub const RANGE_PROOF_BIT_SIZE: u64 = 128;

// =====================================================================
// Transaction input hidden signature verification
// =====================================================================

/// Verify the hidden Schnorr signature on a single transaction input.
///
/// The 336-byte signature decomposes as 6×56 DECAF448 scalars/points:
/// - `[0..56]`: challenge (c)
/// - `[56..112]`: s1
/// - `[112..168]`: s2
/// - `[168..224]`: s3
/// - `[224..280]`: point (verification key)
/// - `[280..336]`: commitment
///
/// The `transcript` is the transaction's challenge bytes (computed
/// from SHA3 of the domain + input commitments + output commitments).
pub fn verify_input_hidden_signature(
    bp: &dyn BulletproofProver,
    signature: &[u8],
    transcript: &[u8],
) -> Result<bool> {
    if signature.len() != 336 {
        return Err(QuilError::InvalidArgument(format!(
            "input signature: expected 336 bytes, got {}", signature.len()
        )));
    }

    let c = &signature[0..56];
    let s1 = &signature[56..112];
    let s2 = &signature[112..168];
    let s3 = &signature[168..224];
    let point = &signature[224..280];
    let commitment = &signature[280..336];

    Ok(bp.verify_hidden(c, transcript, s1, s2, s3, point, commitment))
}

/// Validate structural properties of a transaction input.
///
/// Checks:
/// - Commitment is 56 bytes
/// - Signature is 336 bytes
/// - Commitment matches the commitment embedded in the signature
///   (bytes [280..336] must equal the commitment field)
pub fn validate_input_structural(
    commitment: &[u8],
    signature: &[u8],
) -> Result<()> {
    if commitment.len() != 56 {
        return Err(QuilError::InvalidArgument(format!(
            "input: commitment is {} bytes (expected 56)", commitment.len()
        )));
    }
    if signature.len() != 336 {
        return Err(QuilError::InvalidArgument(format!(
            "input: signature is {} bytes (expected 336)", signature.len()
        )));
    }
    // Commitment must match the commitment embedded in signature[280..336]
    if commitment != &signature[280..336] {
        return Err(QuilError::InvalidArgument(
            "input: commitment doesn't match signature".into(),
        ));
    }
    Ok(())
}

/// Structural validation of a transaction's input/output counts and
/// fee values.
pub fn validate_transaction_structural(
    input_count: usize,
    output_count: usize,
    fees: &[Vec<u8>],
    behavior: u16,
    traversal_proof_subproof_count: usize,
) -> Result<()> {
    if input_count == 0 || output_count == 0 {
        return Err(QuilError::InvalidArgument(
            "transaction: zero inputs or outputs".into(),
        ));
    }
    if input_count > MAX_IO_COUNT || output_count > MAX_IO_COUNT {
        return Err(QuilError::InvalidArgument(format!(
            "transaction: too many inputs ({}) or outputs ({})",
            input_count, output_count
        )));
    }
    if input_count != traversal_proof_subproof_count {
        return Err(QuilError::InvalidArgument(format!(
            "transaction: input count ({}) != subproof count ({})",
            input_count, traversal_proof_subproof_count
        )));
    }

    // Validate fee values are in [0, 2^128]
    let max_fee = BigInt::one() << 128u32;
    for (i, fee_bytes) in fees.iter().enumerate() {
        let fee = BigInt::from_bytes_be(num_bigint::Sign::Plus, fee_bytes);
        if fee > max_fee || fee < BigInt::from(0) {
            return Err(QuilError::InvalidArgument(format!(
                "transaction: fee {} out of range", i
            )));
        }
    }

    // Non-divisible tokens require matching input/output counts
    if behavior & super::constants::DIVISIBLE == 0 && input_count != output_count {
        return Err(QuilError::InvalidArgument(
            "transaction: non-divisible token has mismatching inputs and outputs".into(),
        ));
    }

    Ok(())
}

/// Verify the bulletproof range proof and sum check for a transaction.
///
/// This is the core crypto verification that doesn't need state lookups:
/// 1. Verify range proof: all output commitments are in [0, 2^128]
/// 2. Verify sum check: input commitments == output commitments + fees
///
/// `input_commitments`: 56-byte DECAF448 point per input
/// `output_commitments`: 56-byte DECAF448 point per output
/// `fees`: big-endian serialized fee values (for QUIL token domain)
/// `range_proof`: the serialized bulletproof
pub fn verify_transaction_crypto(
    bulletproof_prover: &dyn BulletproofProver,
    input_commitments: &[Vec<u8>],
    output_commitments: &[Vec<u8>],
    fees: &[Vec<u8>],
    range_proof: &[u8],
    is_quil_domain: bool,
) -> Result<bool> {
    // Build the concatenated commitment bytes for range proof verification
    let mut commitment_bytes = Vec::with_capacity(output_commitments.len() * 56);
    for c in output_commitments {
        if c.len() != 56 {
            return Err(QuilError::InvalidArgument(format!(
                "transaction: output commitment is {} bytes (expected 56)",
                c.len()
            )));
        }
        commitment_bytes.extend_from_slice(c);
    }

    // 1. Range proof: verify all outputs are in valid range
    if !bulletproof_prover.verify_range_proof(range_proof, &commitment_bytes, RANGE_PROOF_BIT_SIZE) {
        return Ok(false);
    }

    // 2. Sum check: inputs == outputs + fees
    let sumcheck_fees = if is_quil_domain {
        fees.to_vec()
    } else {
        vec![]
    };

    if !bulletproof_prover.sum_check(
        input_commitments,
        &[], // no additional inputs
        output_commitments,
        &sumcheck_fees,
    ) {
        return Ok(false);
    }

    Ok(true)
}

/// Structural validation for a MintTransaction. Same checks but
/// without traversal proof subproof count (mints have no traversal).
pub fn validate_mint_transaction_structural(
    input_count: usize,
    output_count: usize,
    fees: &[Vec<u8>],
    behavior: u16,
) -> Result<()> {
    if input_count == 0 || output_count == 0 {
        return Err(QuilError::InvalidArgument("mint: zero inputs or outputs".into()));
    }
    if input_count > MAX_IO_COUNT || output_count > MAX_IO_COUNT {
        return Err(QuilError::InvalidArgument(format!("mint: too many I/O ({}/{})", input_count, output_count)));
    }
    let max_fee = BigInt::one() << 128u32;
    for (i, fb) in fees.iter().enumerate() {
        let fee = BigInt::from_bytes_be(num_bigint::Sign::Plus, fb);
        if fee > max_fee { return Err(QuilError::InvalidArgument(format!("mint: fee {} out of range", i))); }
    }
    if behavior & super::constants::DIVISIBLE == 0 && input_count != output_count {
        return Err(QuilError::InvalidArgument("mint: non-divisible mismatched I/O".into()));
    }
    Ok(())
}

/// Verify bulletproof crypto for MintTransaction. No fees in sum check.
pub fn verify_mint_transaction_crypto(
    bp: &dyn BulletproofProver,
    input_commitments: &[Vec<u8>],
    output_commitments: &[Vec<u8>],
    range_proof: &[u8],
) -> Result<bool> {
    let mut cb = Vec::with_capacity(output_commitments.len() * 56);
    for c in output_commitments {
        if c.len() != 56 { return Err(QuilError::InvalidArgument("mint: bad commitment size".into())); }
        cb.extend_from_slice(c);
    }
    if !bp.verify_range_proof(range_proof, &cb, RANGE_PROOF_BIT_SIZE) { return Ok(false); }
    if !bp.sum_check(input_commitments, &[], output_commitments, &[]) { return Ok(false); }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_intrinsic::constants::QUIL_BEHAVIOR;
    use quil_types::crypto::RangeProofResult;

    // Stub prover that always accepts/rejects
    struct AcceptProver;
    impl BulletproofProver for AcceptProver {
        fn generate_range_proof(&self, _: &[Vec<u8>], _: &[u8], _: u64) -> Result<RangeProofResult> { Err(QuilError::Internal("range proof generation not supported".into())) }
        fn generate_input_commitments(&self, _: &[Vec<u8>], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_range_proof(&self, _: &[u8], _: &[u8], _: u64) -> bool { true }
        fn sum_check(&self, _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>]) -> bool { true }
        fn sign_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
        fn simple_sign(&self, _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn simple_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
    }

    struct RejectProver;
    impl BulletproofProver for RejectProver {
        fn generate_range_proof(&self, _: &[Vec<u8>], _: &[u8], _: u64) -> Result<RangeProofResult> { Err(QuilError::Internal("range proof generation not supported".into())) }
        fn generate_input_commitments(&self, _: &[Vec<u8>], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_range_proof(&self, _: &[u8], _: &[u8], _: u64) -> bool { false }
        fn sum_check(&self, _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>]) -> bool { false }
        fn sign_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool { false }
        fn simple_sign(&self, _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn simple_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool { false }
    }

    // -- Structural validation --

    #[test]
    fn structural_accepts_valid() {
        assert!(validate_transaction_structural(2, 3, &[], QUIL_BEHAVIOR, 2).is_ok());
    }

    #[test]
    fn structural_rejects_zero_inputs() {
        assert!(validate_transaction_structural(0, 1, &[], QUIL_BEHAVIOR, 0).is_err());
    }

    #[test]
    fn structural_rejects_zero_outputs() {
        assert!(validate_transaction_structural(1, 0, &[], QUIL_BEHAVIOR, 1).is_err());
    }

    #[test]
    fn structural_rejects_too_many_inputs() {
        assert!(validate_transaction_structural(101, 1, &[], QUIL_BEHAVIOR, 101).is_err());
    }

    #[test]
    fn structural_rejects_mismatched_subproof_count() {
        assert!(validate_transaction_structural(2, 2, &[], QUIL_BEHAVIOR, 3).is_err());
    }

    #[test]
    fn structural_rejects_oversized_fee() {
        let huge = vec![0xFFu8; 32]; // way over 2^128
        assert!(validate_transaction_structural(1, 1, &[huge], QUIL_BEHAVIOR, 1).is_err());
    }

    #[test]
    fn structural_non_divisible_rejects_mismatched_io() {
        // behavior=0 means not divisible
        assert!(validate_transaction_structural(2, 3, &[], 0, 2).is_err());
    }

    #[test]
    fn structural_non_divisible_accepts_matched_io() {
        assert!(validate_transaction_structural(2, 2, &[], 0, 2).is_ok());
    }

    // -- Crypto verification --

    #[test]
    fn crypto_accepts_with_accept_prover() {
        let inputs = vec![vec![0xAAu8; 56], vec![0xBBu8; 56]];
        let outputs = vec![vec![0xCCu8; 56]];
        let result = verify_transaction_crypto(
            &AcceptProver, &inputs, &outputs, &[], b"proof", true,
        ).unwrap();
        assert!(result);
    }

    #[test]
    fn crypto_rejects_with_reject_prover() {
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 56]];
        let result = verify_transaction_crypto(
            &RejectProver, &inputs, &outputs, &[], b"proof", true,
        ).unwrap();
        assert!(!result);
    }

    #[test]
    fn crypto_rejects_wrong_commitment_size() {
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 32]]; // wrong size
        assert!(verify_transaction_crypto(
            &AcceptProver, &inputs, &outputs, &[], b"proof", true,
        ).is_err());
    }

    #[test]
    fn crypto_passes_fees_only_for_quil_domain() {
        // This just exercises the code path — actual sum_check behavior
        // depends on the prover.
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 56]];
        let fees = vec![vec![0, 100]]; // 100 in big-endian
        assert!(verify_transaction_crypto(
            &AcceptProver, &inputs, &outputs, &fees, b"proof", true,
        ).unwrap());
        assert!(verify_transaction_crypto(
            &AcceptProver, &inputs, &outputs, &fees, b"proof", false,
        ).unwrap());
    }

    // -- Mint structural validation --

    #[test]
    fn mint_structural_accepts_valid() {
        assert!(validate_mint_transaction_structural(2, 3, &[], QUIL_BEHAVIOR).is_ok());
    }

    #[test]
    fn mint_structural_rejects_zero_inputs() {
        assert!(validate_mint_transaction_structural(0, 1, &[], QUIL_BEHAVIOR).is_err());
    }

    #[test]
    fn mint_structural_rejects_too_many() {
        assert!(validate_mint_transaction_structural(101, 1, &[], QUIL_BEHAVIOR).is_err());
    }

    // -- Input signature verification --

    #[test]
    fn input_structural_accepts_valid() {
        let mut sig = vec![0u8; 336];
        let commitment = vec![0xAAu8; 56];
        sig[280..336].copy_from_slice(&commitment);
        assert!(validate_input_structural(&commitment, &sig).is_ok());
    }

    #[test]
    fn input_structural_rejects_wrong_commitment_size() {
        assert!(validate_input_structural(&[0u8; 32], &[0u8; 336]).is_err());
    }

    #[test]
    fn input_structural_rejects_wrong_sig_size() {
        assert!(validate_input_structural(&[0u8; 56], &[0u8; 100]).is_err());
    }

    #[test]
    fn input_structural_rejects_mismatched_commitment() {
        let commitment = vec![0xAAu8; 56];
        let sig = vec![0xBBu8; 336]; // commitment in sig is 0xBB, not 0xAA
        assert!(validate_input_structural(&commitment, &sig).is_err());
    }

    #[test]
    fn input_hidden_sig_accepts_with_accept_prover() {
        let sig = vec![0xAAu8; 336];
        assert!(verify_input_hidden_signature(&AcceptProver, &sig, b"transcript").unwrap());
    }

    #[test]
    fn input_hidden_sig_rejects_with_reject_prover() {
        let sig = vec![0xAAu8; 336];
        assert!(!verify_input_hidden_signature(&RejectProver, &sig, b"transcript").unwrap());
    }

    #[test]
    fn input_hidden_sig_rejects_wrong_size() {
        assert!(verify_input_hidden_signature(&AcceptProver, &[0u8; 100], b"transcript").is_err());
    }

    // -- PendingTransaction --

    #[test]
    fn pending_structural_accepts_valid() {
        assert!(validate_transaction_structural(2, 3, &[], QUIL_BEHAVIOR, 2).is_ok());
    }

    #[test]
    fn pending_crypto_accepts_with_accept_prover() {
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 56]];
        // PendingTransaction sum check includes fees for QUIL domain
        assert!(verify_transaction_crypto(&AcceptProver, &inputs, &outputs, &[vec![0, 50]], b"proof", true).unwrap());
    }

    // -- Mint crypto verification --

    #[test]
    fn mint_crypto_accepts_with_accept_prover() {
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 56]];
        assert!(verify_mint_transaction_crypto(&AcceptProver, &inputs, &outputs, b"proof").unwrap());
    }

    #[test]
    fn mint_crypto_rejects_with_reject_prover() {
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 56]];
        assert!(!verify_mint_transaction_crypto(&RejectProver, &inputs, &outputs, b"proof").unwrap());
    }
}
