//! Token spent-coin and traversal proof verification. Port of the
//! state-dependent checks from `token_intrinsic_transaction.go`.
//!
//! These checks require CRDT state lookups:
//! - Spent coin check: verification key must not already exist as a vertex
//! - Traversal proof: proves the input coins exist in the shard tree

use quil_types::error::{QuilError, Result};

use crate::hypergraph_state::HypergraphState;

/// Check that a transaction output's verification key has not already
/// been spent (i.e., does not exist as a vertex in the hypergraph).
pub fn check_output_not_spent(
    state: &HypergraphState,
    domain: &[u8],
    verification_key: &[u8],
) -> Result<bool> {
    if verification_key.len() != 56 {
        return Err(QuilError::InvalidArgument(format!(
            "spent check: verification key must be 56 bytes, got {}",
            verification_key.len()
        )));
    }

    // Compute the spent address: poseidon(verification_key) → 32 bytes
    let spent_addr = quil_crypto::poseidon::hash_bytes_to_32(verification_key)?;

    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;

    // If the vertex exists, the coin has already been spent
    match state.get(domain, &spent_addr, &va_disc)? {
        Some(_) => Ok(false), // already spent!
        None => Ok(true),     // not spent, valid
    }
}

/// Check that a transaction input's verification key has not already
/// been spent. The verification key is extracted from the 336-byte
/// signature at bytes [224..280].
pub fn check_input_not_double_spent(
    state: &HypergraphState,
    domain: &[u8],
    signature: &[u8],
) -> Result<bool> {
    if signature.len() != 336 {
        return Err(QuilError::InvalidArgument(
            "spent check: signature must be 336 bytes".into(),
        ));
    }

    let verification_key = &signature[56 * 4..56 * 5];
    let spent_addr = quil_crypto::poseidon::hash_bytes_to_32(verification_key)?;

    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;

    match state.get(domain, &spent_addr, &va_disc)? {
        Some(_) => Ok(false), // already spent
        None => Ok(true),     // not yet spent
    }
}

/// Verify a traversal proof against the shard's commitment root.
///
/// This is a placeholder — full traversal proof verification requires
/// the CRDT's inclusion prover and the frame's shard commits. The
/// actual verification calls `hypergraph.VerifyTraversalProof()`.
///
/// For now, this validates the structural presence of the proof data.
pub fn validate_traversal_proof_structural(
    traversal_proof: &[u8],
) -> Result<()> {
    if traversal_proof.is_empty() {
        return Err(QuilError::InvalidArgument(
            "traversal proof: empty proof data".into(),
        ));
    }
    // Structural minimum: the proof must contain at least a type prefix
    if traversal_proof.len() < 4 {
        return Err(QuilError::InvalidArgument(
            "traversal proof: too short".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use quil_types::crypto::NoopInclusionProver;
    use quil_hypergraph::testing::MemStore;

    fn stub_state() -> HypergraphState {
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(MemStore::new()), Arc::new(NoopInclusionProver),
        ));
        HypergraphState::new(crdt)
    }

    #[test]
    fn unspent_output_passes() {
        let state = stub_state();
        let vk = vec![0xAAu8; 56];
        assert!(check_output_not_spent(&state, &[0u8; 32], &vk).unwrap());
    }

    #[test]
    fn spent_output_fails() {
        let state = stub_state();
        let vk = vec![0xAAu8; 56];
        let domain = vec![0u8; 32];
        let addr = quil_crypto::poseidon::hash_bytes_to_32(&vk).unwrap();
        let disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        state.set(&domain, &addr, &disc, 1, b"spent".to_vec()).unwrap();
        assert!(!check_output_not_spent(&state, &domain, &vk).unwrap());
    }

    #[test]
    fn wrong_vk_length_rejected() {
        let state = stub_state();
        assert!(check_output_not_spent(&state, &[0u8; 32], &[0u8; 32]).is_err());
    }

    #[test]
    fn traversal_proof_structural_rejects_empty() {
        assert!(validate_traversal_proof_structural(&[]).is_err());
    }

    #[test]
    fn traversal_proof_structural_accepts_nonempty() {
        assert!(validate_traversal_proof_structural(&[0x01, 0x02, 0x03, 0x04]).is_ok());
    }
}
