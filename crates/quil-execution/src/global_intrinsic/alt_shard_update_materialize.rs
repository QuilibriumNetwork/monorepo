//! AltShardUpdate Validate + Materialize. Port of
//! `node/execution/intrinsics/global/global_alt_shard_update.go`.
//!
//! An `AltShardUpdate` is a signed commitment by an external shard
//! owner to the root hashes of their four hypergraph trees
//! (vertex/hyperedge adds/removes). The shard address is
//! `poseidon(PublicKey)` — ownership is proved by a BLS48-581
//! signature.
//!
//! In Go, `Materialize` is a no-op (`return state, nil`): the actual
//! persistence of alt shard roots happens in the global consensus
//! engine's `persistAltShardUpdates`, not the intrinsic. We preserve
//! that: `materialize_alt_shard_update` performs validation and
//! returns without mutating state, and a separate
//! `AltShardUpdateCommit` helper surfaces the derived shard address +
//! roots for the caller (frame materializer) to persist.

use quil_crypto::poseidon::hash_bytes_to_32;
use quil_types::crypto::{KeyManager, KeyType};
use quil_types::error::{QuilError, Result};

use super::consensus_types::AltShardUpdate;
use crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;

/// The domain-separator tag Go uses when hashing the BLS signing
/// domain: `poseidon(GLOBAL_INTRINSIC_ADDRESS || "ALT_SHARD_UPDATE")`.
pub const ALT_SHARD_UPDATE_TAG: &[u8] = b"ALT_SHARD_UPDATE";

/// Compute the BLS signing domain for AltShardUpdate.
/// Go equivalent: `global_alt_shard_update.go:117-125` (prove) and
/// `:201-208` (verify).
pub fn alt_shard_update_domain() -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(32 + ALT_SHARD_UPDATE_TAG.len());
    preimage.extend_from_slice(&GLOBAL_INTRINSIC_ADDRESS);
    preimage.extend_from_slice(ALT_SHARD_UPDATE_TAG);
    hash_bytes_to_32(&preimage)
}

/// Build the signed message: `frame_number_be_u64 || VertexAddsRoot ||
/// VertexRemovesRoot || HyperedgeAddsRoot || HyperedgeRemovesRoot`.
///
/// Go equivalent: `getSignedMessage` at
/// `global_alt_shard_update.go:82`.
pub fn alt_shard_update_signed_message(op: &AltShardUpdate) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        8 + op.vertex_adds_root.len()
            + op.vertex_removes_root.len()
            + op.hyperedge_adds_root.len()
            + op.hyperedge_removes_root.len(),
    );
    msg.extend_from_slice(&op.frame_number.to_be_bytes());
    msg.extend_from_slice(&op.vertex_adds_root);
    msg.extend_from_slice(&op.vertex_removes_root);
    msg.extend_from_slice(&op.hyperedge_adds_root);
    msg.extend_from_slice(&op.hyperedge_removes_root);
    msg
}

/// Derive the shard address from the public key:
/// `poseidon(PublicKey) → 32 bytes`.
///
/// Go equivalent: `getShardAddress` at
/// `global_alt_shard_update.go:96`.
pub fn alt_shard_update_shard_address(public_key: &[u8]) -> Result<[u8; 32]> {
    if public_key.is_empty() {
        return Err(QuilError::InvalidArgument(
            "alt shard update: public key is empty".into(),
        ));
    }
    hash_bytes_to_32(public_key)
}

/// Validate an `AltShardUpdate`. Checks structural invariants, frame-
/// number window, and BLS48-581 G1 signature.
///
/// Go equivalent: `AltShardUpdate::Verify` at
/// `global_alt_shard_update.go:141`.
pub fn validate_alt_shard_update(
    op: &AltShardUpdate,
    frame_number: u64,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    // Public key length: BLS48-581 pubkey is 585 bytes.
    if op.public_key.len() != 585 {
        return Err(QuilError::InvalidArgument(format!(
            "alt shard update: invalid public key length: expected 585, got {}",
            op.public_key.len()
        )));
    }

    // Signature length: BLS48-581 signature is 74 bytes.
    if op.signature.len() != 74 {
        return Err(QuilError::InvalidArgument(format!(
            "alt shard update: invalid signature length: expected 74, got {}",
            op.signature.len()
        )));
    }

    // Root lengths: 64 (leaf/empty commitment) or 74 (elliptic curve point).
    let is_valid_root_len = |n: usize| n == 64 || n == 74;
    if !is_valid_root_len(op.vertex_adds_root.len()) {
        return Err(QuilError::InvalidArgument(format!(
            "alt shard update: vertex adds root must be 64 or 74 bytes, got {}",
            op.vertex_adds_root.len()
        )));
    }
    if !is_valid_root_len(op.vertex_removes_root.len()) {
        return Err(QuilError::InvalidArgument(format!(
            "alt shard update: vertex removes root must be 64 or 74 bytes, got {}",
            op.vertex_removes_root.len()
        )));
    }
    if !is_valid_root_len(op.hyperedge_adds_root.len()) {
        return Err(QuilError::InvalidArgument(format!(
            "alt shard update: hyperedge adds root must be 64 or 74 bytes, got {}",
            op.hyperedge_adds_root.len()
        )));
    }
    if !is_valid_root_len(op.hyperedge_removes_root.len()) {
        return Err(QuilError::InvalidArgument(format!(
            "alt shard update: hyperedge removes root must be 64 or 74 bytes, got {}",
            op.hyperedge_removes_root.len()
        )));
    }

    // Frame-number window: must be current or at most 2 frames behind.
    if op.frame_number > frame_number {
        return Err(QuilError::InvalidArgument(
            "alt shard update: frame number is in the future".into(),
        ));
    }
    if frame_number - op.frame_number > 2 {
        return Err(QuilError::InvalidArgument(
            "alt shard update: frame number is too old (more than 2 frames)".into(),
        ));
    }

    // BLS signature verification.
    let domain = alt_shard_update_domain()?;
    let message = alt_shard_update_signed_message(op);

    let valid = key_manager.validate_signature(
        KeyType::Bls48581G1,
        &op.public_key,
        &message,
        &op.signature,
        &domain,
    )?;
    if !valid {
        return Err(QuilError::InvalidArgument(
            "alt shard update: invalid signature".into(),
        ));
    }

    Ok(true)
}

/// A parsed and validated `AltShardUpdate` surfaced for persistence by
/// the frame materializer. Mirrors the fields consumed by
/// `HypergraphStore::SetAltShardCommit` in Go
/// (`node/consensus/global/frame_materializer.go:400`).
#[derive(Debug, Clone)]
pub struct AltShardUpdateCommit {
    /// `poseidon(PublicKey)` — 32 bytes.
    pub shard_address: [u8; 32],
    pub vertex_adds_root: Vec<u8>,
    pub vertex_removes_root: Vec<u8>,
    pub hyperedge_adds_root: Vec<u8>,
    pub hyperedge_removes_root: Vec<u8>,
}

/// Materialize an `AltShardUpdate`. In Go this is a no-op — the real
/// state transition happens in the global consensus engine when it
/// iterates frame requests and calls
/// `hypergraphStore.SetAltShardCommit`. This function preserves that
/// semantics: returns the derived commit record without mutating any
/// state. The caller is responsible for handing the record to the
/// alt-shard commit store.
///
/// Go equivalent: `AltShardUpdate::Materialize` at
/// `global_alt_shard_update.go:253` (no-op `return state, nil`) +
/// `persistAltShardUpdates` at `frame_materializer.go:350`.
pub fn materialize_alt_shard_update(op: &AltShardUpdate) -> Result<AltShardUpdateCommit> {
    let shard_address = alt_shard_update_shard_address(&op.public_key)?;
    Ok(AltShardUpdateCommit {
        shard_address,
        vertex_adds_root: op.vertex_adds_root.clone(),
        vertex_removes_root: op.vertex_removes_root.clone(),
        hyperedge_adds_root: op.hyperedge_adds_root.clone(),
        hyperedge_removes_root: op.hyperedge_removes_root.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AcceptAll;
    impl KeyManager for AcceptAll {
        fn validate_signature(&self, _: KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> {
            Ok(true)
        }
    }

    struct RejectAll;
    impl KeyManager for RejectAll {
        fn validate_signature(&self, _: KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> {
            Ok(false)
        }
    }

    fn valid_op(frame_number: u64) -> AltShardUpdate {
        AltShardUpdate {
            public_key: vec![0xAAu8; 585],
            frame_number,
            vertex_adds_root: vec![0x01u8; 64],
            vertex_removes_root: vec![0x02u8; 64],
            hyperedge_adds_root: vec![0x03u8; 74],
            hyperedge_removes_root: vec![0x04u8; 64],
            signature: vec![0x05u8; 74],
        }
    }

    #[test]
    fn domain_is_deterministic_and_32_bytes() {
        let d1 = alt_shard_update_domain().unwrap();
        let d2 = alt_shard_update_domain().unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
    }

    #[test]
    fn signed_message_layout() {
        let op = valid_op(42);
        let msg = alt_shard_update_signed_message(&op);
        assert_eq!(&msg[..8], &42u64.to_be_bytes());
        assert_eq!(&msg[8..8 + 64], &op.vertex_adds_root[..]);
    }

    #[test]
    fn shard_address_matches_poseidon() {
        let pk = vec![0xAAu8; 585];
        let addr = alt_shard_update_shard_address(&pk).unwrap();
        let expected = hash_bytes_to_32(&pk).unwrap();
        assert_eq!(addr, expected);
    }

    #[test]
    fn validate_ok_with_valid_op() {
        let op = valid_op(100);
        assert!(validate_alt_shard_update(&op, 100, &AcceptAll).unwrap());
    }

    #[test]
    fn validate_accepts_2_frame_delay() {
        let op = valid_op(98);
        assert!(validate_alt_shard_update(&op, 100, &AcceptAll).unwrap());
    }

    #[test]
    fn validate_rejects_too_old_frame() {
        let op = valid_op(97);
        assert!(validate_alt_shard_update(&op, 100, &AcceptAll).is_err());
    }

    #[test]
    fn validate_rejects_future_frame() {
        let op = valid_op(101);
        assert!(validate_alt_shard_update(&op, 100, &AcceptAll).is_err());
    }

    #[test]
    fn validate_rejects_bad_pubkey_length() {
        let mut op = valid_op(100);
        op.public_key = vec![0xAAu8; 584];
        assert!(validate_alt_shard_update(&op, 100, &AcceptAll).is_err());
    }

    #[test]
    fn validate_rejects_bad_sig_length() {
        let mut op = valid_op(100);
        op.signature = vec![0x05u8; 73];
        assert!(validate_alt_shard_update(&op, 100, &AcceptAll).is_err());
    }

    #[test]
    fn validate_rejects_bad_root_length() {
        let mut op = valid_op(100);
        op.vertex_adds_root = vec![0x01u8; 63];
        assert!(validate_alt_shard_update(&op, 100, &AcceptAll).is_err());
    }

    #[test]
    fn validate_accepts_root_len_74() {
        let mut op = valid_op(100);
        op.vertex_adds_root = vec![0x01u8; 74];
        assert!(validate_alt_shard_update(&op, 100, &AcceptAll).unwrap());
    }

    #[test]
    fn validate_rejects_bad_signature() {
        let op = valid_op(100);
        assert!(validate_alt_shard_update(&op, 100, &RejectAll).is_err());
    }

    #[test]
    fn materialize_returns_shard_address_and_roots() {
        let op = valid_op(50);
        let commit = materialize_alt_shard_update(&op).unwrap();
        assert_eq!(
            commit.shard_address,
            alt_shard_update_shard_address(&op.public_key).unwrap()
        );
        assert_eq!(commit.vertex_adds_root, op.vertex_adds_root);
        assert_eq!(commit.vertex_removes_root, op.vertex_removes_root);
        assert_eq!(commit.hyperedge_adds_root, op.hyperedge_adds_root);
        assert_eq!(commit.hyperedge_removes_root, op.hyperedge_removes_root);
    }

    #[test]
    fn materialize_empty_pubkey_fails() {
        let mut op = valid_op(100);
        op.public_key = Vec::new();
        assert!(materialize_alt_shard_update(&op).is_err());
    }
}
