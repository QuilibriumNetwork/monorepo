//! Token transaction materialize — creates coin vertices for outputs
//! and marks inputs as spent.

use num_bigint::BigInt;
use quil_types::error::{QuilError, Result};

use crate::token_intrinsic::transaction::RecipientBundle;

/// A transaction output ready for materialization.
pub struct TransactionOutput {
    pub frame_number: Vec<u8>,
    pub commitment: Vec<u8>,
    pub recipient: RecipientBundle,
}

/// Create a coin vertex tree for a single transaction output.
///
/// Coin tree layout (single-byte key encoding, order << 2):
/// - 0x00: FrameNumber (8 bytes)
/// - 0x04: Commitment (56 bytes)
/// - 0x08: OneTimeKey (56 bytes)
/// - 0x0C: VerificationKey (56 bytes)
/// - 0x10: CoinBalance (56 bytes, encrypted)
/// - 0x14: Mask (56 bytes, encrypted)
/// - 0x18: AdditionalReference (64 bytes, optional)
/// - 0x1C: AdditionalReferenceKey (56 bytes, optional)
/// - [0xFF; 32]: Type hash
pub fn create_coin_vertex_tree(
    output: &TransactionOutput,
    coin_type_hash: &[u8; 32],
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();

    // FrameNumber at index 0
    tree.insert(&[0x00], &output.frame_number, &[], &BigInt::from(8))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // Commitment at index 1
    tree.insert(&[1 << 2], &output.commitment, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // OneTimeKey at index 2
    tree.insert(&[2 << 2], &output.recipient.one_time_key, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // VerificationKey at index 3
    tree.insert(&[3 << 2], &output.recipient.verification_key, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // CoinBalance at index 4
    tree.insert(&[4 << 2], &output.recipient.coin_balance, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // Mask at index 5
    tree.insert(&[5 << 2], &output.recipient.mask, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // Optional additional references (non-divisible tokens)
    if output.recipient.additional_reference.len() == 64
        && output.recipient.additional_reference_key.len() == 56
    {
        tree.insert(&[6 << 2], &output.recipient.additional_reference, &[], &BigInt::from(64))
            .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;
        tree.insert(&[7 << 2], &output.recipient.additional_reference_key, &[], &BigInt::from(56))
            .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;
    }

    // Type hash at [0xFF; 32]
    tree.insert(&[0xFFu8; 32], coin_type_hash, &[], &BigInt::from(32))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    Ok(tree)
}

/// Compute the coin type hash for a domain.
/// `poseidon(domain || "coin:Coin")` → 32 bytes.
pub fn coin_type_hash(domain: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(domain.len() + 9);
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(b"coin:Coin");
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Create a spent marker tree for an input's verification key.
/// The marker is a minimal tree with a single `{0x01}` entry at key 0.
pub fn create_spent_marker_tree() -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0x00], &[0x01], &[], &BigInt::from(0))
        .map_err(|e| QuilError::Internal(format!("spent marker: {}", e)))?;
    Ok(tree)
}

/// Compute the pending transaction type hash for a domain.
/// `poseidon(domain || "pending:PendingTransaction")` → 32 bytes.
pub fn pending_type_hash(domain: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(domain.len() + 27);
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(b"pending:PendingTransaction");
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Compute the spent address from an input's verification key.
/// `poseidon(verification_key)` → 32 bytes.
pub fn spent_address(verification_key: &[u8]) -> Result<[u8; 32]> {
    quil_crypto::poseidon::hash_bytes_to_32(verification_key)
}

/// Extract the verification key from a standard transaction input
/// signature. The signature is 336 bytes (6 × 56), and the
/// verification key is at bytes [224..280] (56*4 to 56*5).
pub fn extract_verification_key_from_signature(signature: &[u8]) -> Option<&[u8]> {
    if signature.len() == 336 {
        Some(&signature[56 * 4..56 * 5])
    } else {
        None
    }
}

/// Full materialize output for a token transaction.
pub struct TransactionMaterializeOutput {
    /// (coin_address, coin_tree) pairs — one per output.
    pub coins: Vec<([u8; 32], quil_tries::VectorCommitmentTree)>,
    /// (spent_address, spent_marker_tree) pairs — one per input.
    pub spent_markers: Vec<([u8; 32], quil_tries::VectorCommitmentTree)>,
}

/// Materialize a token transaction: create coin vertices for outputs,
/// spent markers for inputs.
///
/// The caller writes these to the CRDT via HypergraphState.set().
pub fn materialize_transaction(
    domain: &[u8],
    outputs: &[TransactionOutput],
    input_signatures: &[Vec<u8>],
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> Result<TransactionMaterializeOutput> {
    let type_hash = coin_type_hash(domain)?;

    let mut coins = Vec::with_capacity(outputs.len());
    for output in outputs {
        let mut tree = create_coin_vertex_tree(output, &type_hash)?;
        let commit = tree.commit(inclusion_prover);
        let addr = quil_crypto::poseidon::hash_bytes_to_32(&commit)?;
        coins.push((addr, tree));
    }

    let mut spent_markers = Vec::with_capacity(input_signatures.len());
    for sig in input_signatures {
        if let Some(vk) = extract_verification_key_from_signature(sig) {
            let addr = spent_address(vk)?;
            let marker = create_spent_marker_tree()?;
            spent_markers.push((addr, marker));
        }
    }

    Ok(TransactionMaterializeOutput { coins, spent_markers })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::NoopInclusionProver;

    fn sample_output() -> TransactionOutput {
        TransactionOutput {
            frame_number: vec![0, 0, 0, 0, 0, 0, 0, 42],
            commitment: vec![0xAAu8; 56],
            recipient: RecipientBundle {
                one_time_key: vec![0x11u8; 56],
                verification_key: vec![0x22u8; 56],
                coin_balance: vec![0x33u8; 56],
                mask: vec![0x44u8; 56],
                additional_reference: vec![],
                additional_reference_key: vec![],
            },
        }
    }

    #[test]
    fn coin_type_hash_is_deterministic() {
        let h1 = coin_type_hash(&[0xAAu8; 32]).unwrap();
        let h2 = coin_type_hash(&[0xAAu8; 32]).unwrap();
        assert_eq!(h1, h2);
        assert!(h1.iter().any(|&b| b != 0));
    }

    #[test]
    fn coin_type_hash_differs_by_domain() {
        let h1 = coin_type_hash(&[0xAAu8; 32]).unwrap();
        let h2 = coin_type_hash(&[0xBBu8; 32]).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn create_coin_vertex_tree_has_all_fields() {
        let output = sample_output();
        let type_hash = coin_type_hash(&[0xAAu8; 32]).unwrap();
        let tree = create_coin_vertex_tree(&output, &type_hash).unwrap();

        assert_eq!(tree.get(&[0x00]).unwrap(), &output.frame_number[..]);
        assert_eq!(tree.get(&[1 << 2]).unwrap(), &output.commitment[..]);
        assert_eq!(tree.get(&[2 << 2]).unwrap(), &output.recipient.one_time_key[..]);
        assert_eq!(tree.get(&[3 << 2]).unwrap(), &output.recipient.verification_key[..]);
        assert_eq!(tree.get(&[4 << 2]).unwrap(), &output.recipient.coin_balance[..]);
        assert_eq!(tree.get(&[5 << 2]).unwrap(), &output.recipient.mask[..]);
        assert_eq!(tree.get(&[0xFFu8; 32]).unwrap(), &type_hash[..]);
    }

    #[test]
    fn create_coin_with_additional_references() {
        let mut output = sample_output();
        output.recipient.additional_reference = vec![0x55u8; 64];
        output.recipient.additional_reference_key = vec![0x66u8; 56];
        let type_hash = coin_type_hash(&[0xAAu8; 32]).unwrap();
        let tree = create_coin_vertex_tree(&output, &type_hash).unwrap();
        assert_eq!(tree.get(&[6 << 2]).unwrap(), &[0x55u8; 64][..]);
        assert_eq!(tree.get(&[7 << 2]).unwrap(), &[0x66u8; 56][..]);
    }

    #[test]
    fn spent_marker_tree_has_marker() {
        let tree = create_spent_marker_tree().unwrap();
        assert_eq!(tree.get(&[0x00]).unwrap(), &[0x01][..]);
    }

    #[test]
    fn extract_vk_from_336_byte_signature() {
        let mut sig = vec![0u8; 336];
        sig[56 * 4..56 * 5].copy_from_slice(&[0xAAu8; 56]);
        let vk = extract_verification_key_from_signature(&sig).unwrap();
        assert_eq!(vk, &[0xAAu8; 56][..]);
    }

    #[test]
    fn extract_vk_from_wrong_size_returns_none() {
        assert!(extract_verification_key_from_signature(&[0u8; 100]).is_none());
    }

    #[test]
    fn materialize_transaction_creates_coins_and_spent() {
        let outputs = vec![sample_output(), sample_output()];
        let sigs = vec![vec![0xBBu8; 336], vec![0xCCu8; 336]];
        let result = materialize_transaction(
            &[0xAAu8; 32], &outputs, &sigs, &NoopInclusionProver,
        ).unwrap();

        assert_eq!(result.coins.len(), 2);
        assert_eq!(result.spent_markers.len(), 2);
        for (addr, _tree) in &result.coins {
            assert_eq!(addr.len(), 32);
            assert!(addr.iter().any(|&b| b != 0));
        }
        for (addr, tree) in &result.spent_markers {
            assert_eq!(addr.len(), 32);
            assert_eq!(tree.get(&[0x00]).unwrap(), &[0x01][..]);
        }
    }

    #[test]
    fn materialize_empty_transaction() {
        let result = materialize_transaction(
            &[0xAAu8; 32], &[], &[], &NoopInclusionProver,
        ).unwrap();
        assert!(result.coins.is_empty());
        assert!(result.spent_markers.is_empty());
    }
}
