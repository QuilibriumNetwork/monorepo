//! ProverUpdate Validate + Materialize. Port of
//! `node/execution/intrinsics/global/global_prover_update.go`.
//!
//! A `ProverUpdate` lets a registered prover change the
//! `DelegateAddress` field on its reward vertex. The new delegate is
//! signed by the prover's BLS48-581 key; the signature binds
//! `DelegateAddress` against the domain
//! `poseidon(GLOBAL_INTRINSIC_ADDRESS || "PROVER_UPDATE")`.

use quil_crypto::poseidon::hash_bytes_to_32;
use quil_types::crypto::{KeyManager, KeyType};
use quil_types::error::{QuilError, Result};

use super::materialize::{reward_address, set_reward_delegate_address};
use super::prover_ops::ProverUpdate;
use crate::global_schema::{read_field, read_type, GLOBAL_INTRINSIC_ADDRESS};
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use crate::prover_registry::{rebuild_vertex_tree_from_blob, vertex_tree_to_blob};

/// Domain-separator tag Go uses: `"PROVER_UPDATE"`.
pub const PROVER_UPDATE_TAG: &[u8] = b"PROVER_UPDATE";

/// Compute the BLS signing domain for ProverUpdate.
/// `poseidon(GLOBAL_INTRINSIC_ADDRESS || "PROVER_UPDATE")`.
///
/// Go equivalent: `global_prover_update.go:243-250` (Prove) and
/// `:378-384` (Verify).
pub fn prover_update_domain() -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(32 + PROVER_UPDATE_TAG.len());
    preimage.extend_from_slice(&GLOBAL_INTRINSIC_ADDRESS);
    preimage.extend_from_slice(PROVER_UPDATE_TAG);
    hash_bytes_to_32(&preimage)
}

/// Validate a `ProverUpdate` against the live hypergraph state.
///
/// Steps (mirroring Go's `Verify` at
/// `global_prover_update.go:306`):
///
/// 1. Addressed signature + delegate address must be present.
/// 2. `PublicKeySignatureBLS48581.Address` must be 32 bytes.
/// 3. `DelegateAddress` must be 32 bytes.
/// 4. The prover vertex must exist at `(GLOBAL_INTRINSIC_ADDRESS,
///    Address)` under `vertex_adds`.
/// 5. `poseidon(prover.PublicKey) == Address` (address binds to pubkey).
/// 6. BLS48-581 G1 signature verifies over `DelegateAddress` with
///    domain `PROVER_UPDATE`.
pub fn validate_prover_update(
    op: &ProverUpdate,
    state: &HypergraphState,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("prover update: missing addressed signature".into())
    })?;
    if sig.address.len() != 32 {
        return Err(QuilError::InvalidArgument(format!(
            "prover update: invalid prover address length: {}",
            sig.address.len()
        )));
    }
    if op.delegate_address.len() != 32 {
        return Err(QuilError::InvalidArgument(format!(
            "prover update: delegate address must be 32 bytes, got {}",
            op.delegate_address.len()
        )));
    }

    let va_disc = vertex_adds_discriminator()?;
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];

    // Load prover vertex.
    let prover_data = state
        .get(domain, &sig.address, &va_disc)?
        .ok_or_else(|| QuilError::InvalidArgument("prover update: prover not found".into()))?;
    if prover_data.is_empty() {
        return Err(QuilError::InvalidArgument(
            "prover update: prover has no data".into(),
        ));
    }

    let prover_tree = rebuild_vertex_tree_from_blob(&prover_data);

    // Confirm type tag matches prover:Prover.
    let vertex_type = read_type(&prover_tree).ok_or_else(|| {
        QuilError::InvalidArgument("prover update: prover vertex has no type hash".into())
    })?;
    if vertex_type != "prover:Prover" {
        return Err(QuilError::InvalidArgument(format!(
            "prover update: expected prover:Prover, got {}",
            vertex_type
        )));
    }

    // Read registered public key.
    let pubkey = read_field(&prover_tree, "prover:Prover", "PublicKey").ok_or_else(|| {
        QuilError::InvalidArgument("prover update: prover public key missing".into())
    })?;
    if pubkey.is_empty() {
        return Err(QuilError::InvalidArgument(
            "prover update: prover public key missing".into(),
        ));
    }

    // Address binding check: poseidon(pubkey) == signed address.
    let addr_check = hash_bytes_to_32(&pubkey)?;
    if addr_check.as_slice() != sig.address.as_slice() {
        return Err(QuilError::InvalidArgument(
            "prover update: address does not match registered pubkey".into(),
        ));
    }

    // BLS signature over DelegateAddress with PROVER_UPDATE domain.
    let domain_bytes = prover_update_domain()?;
    let valid = key_manager.validate_signature(
        KeyType::Bls48581G1,
        &pubkey,
        &op.delegate_address,
        &sig.signature,
        &domain_bytes,
    )?;
    if !valid {
        return Err(QuilError::InvalidArgument(
            "prover update: invalid update signature".into(),
        ));
    }

    Ok(true)
}

/// Materialize a `ProverUpdate`. Mirrors Go's
/// `ProverUpdate::Materialize` at `global_prover_update.go:60`.
///
/// Steps:
/// 1. Decode prover address from the addressed signature; compute the
///    reward address `poseidon(QUIL_TOKEN || proverAddress)`.
/// 2. Load the prover vertex; confirm `poseidon(PublicKey) ==
///    proverAddress` (defense-in-depth).
/// 3. Load (or create) the reward vertex.
/// 4. Write the new `DelegateAddress` field on the reward vertex.
/// 5. Persist the updated reward vertex back to the hypergraph state.
///
/// The `Balance` field is preserved — only `DelegateAddress` is
/// rewritten.
pub fn materialize_prover_update(
    op: &ProverUpdate,
    frame_number: u64,
    state: &HypergraphState,
) -> Result<()> {
    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("prover update materialize: missing signature".into())
    })?;
    if sig.address.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "prover update materialize: invalid prover address length".into(),
        ));
    }
    if op.delegate_address.is_empty() {
        return Err(QuilError::InvalidArgument(
            "prover update materialize: missing delegate address".into(),
        ));
    }

    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = vertex_adds_discriminator()?;
    let prover_address = &sig.address;

    // Load prover vertex to cross-check the address binding.
    let prover_data = state.get(domain, prover_address, &va_disc)?.ok_or_else(|| {
        QuilError::InvalidArgument("prover update materialize: prover not found".into())
    })?;
    if prover_data.is_empty() {
        return Err(QuilError::InvalidArgument(
            "prover update materialize: prover has no data".into(),
        ));
    }
    let prover_tree = rebuild_vertex_tree_from_blob(&prover_data);

    let pubkey = read_field(&prover_tree, "prover:Prover", "PublicKey").ok_or_else(|| {
        QuilError::InvalidArgument("prover update materialize: prover pubkey missing".into())
    })?;
    if pubkey.is_empty() {
        return Err(QuilError::InvalidArgument(
            "prover update materialize: prover pubkey missing".into(),
        ));
    }
    let addr_check = hash_bytes_to_32(&pubkey)?;
    if addr_check.as_slice() != prover_address.as_slice() {
        return Err(QuilError::InvalidArgument(
            "prover update materialize: address mismatch with registered pubkey".into(),
        ));
    }

    // Compute reward address and load (or create) its vertex tree.
    let reward_addr = reward_address(prover_address)?;
    let reward_existing = state.get(domain, &reward_addr, &va_disc)?;
    let mut reward_tree = match reward_existing {
        Some(blob) if !blob.is_empty() => rebuild_vertex_tree_from_blob(&blob),
        _ => quil_tries::VectorCommitmentTree::new(),
    };

    // Overwrite just DelegateAddress — Balance (if present) is kept
    // because we rebuilt the tree from the existing blob.
    set_reward_delegate_address(&mut reward_tree, &op.delegate_address)?;

    // Persist the updated reward vertex.
    let reward_blob = vertex_tree_to_blob(&reward_tree);
    state.set(domain, &reward_addr, &va_disc, frame_number, reward_blob)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global_schema::{write_field, write_type};
    use crate::hypergraph_state::HypergraphState;
    use quil_hypergraph::HypergraphCrdt;
    use quil_types::crypto::{InclusionProver, Multiproof};
    use std::sync::Arc;

    use super::super::addressed_signature::AddressedSignature;

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

    struct StubProver;
    impl InclusionProver for StubProver {
        fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> { Ok(vec![0u8; 64]) }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
        fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> {
            Err(QuilError::Internal("batch not supported".into()))
        }
        fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
    }

    fn make_state() -> HypergraphState {
        let store = Arc::new(crate::hypergraph_state::InMemoryHypergraphStore::new());
        let crdt = Arc::new(HypergraphCrdt::new(store, Arc::new(StubProver)));
        HypergraphState::new(crdt)
    }

    fn make_prover_tree(public_key: &[u8]) -> quil_tries::VectorCommitmentTree {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_type(&mut tree, "prover:Prover").unwrap();
        write_field(&mut tree, "prover:Prover", "PublicKey", public_key).unwrap();
        write_field(&mut tree, "prover:Prover", "Status", &[1u8]).unwrap();
        tree
    }

    fn seed_prover(state: &HypergraphState, pubkey: &[u8]) -> [u8; 32] {
        let prover_addr = hash_bytes_to_32(pubkey).unwrap();
        let tree = make_prover_tree(pubkey);
        let blob = vertex_tree_to_blob(&tree);
        let va_disc = vertex_adds_discriminator().unwrap();
        state.set(
            &GLOBAL_INTRINSIC_ADDRESS[..],
            &prover_addr,
            &va_disc,
            1,
            blob,
        ).unwrap();
        prover_addr
    }

    fn build_update(addr: [u8; 32], delegate: Vec<u8>) -> ProverUpdate {
        ProverUpdate {
            delegate_address: delegate,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: addr.to_vec(),
            }),
        }
    }

    #[test]
    fn domain_is_deterministic_and_32_bytes() {
        assert_eq!(prover_update_domain().unwrap().len(), 32);
        assert_eq!(prover_update_domain().unwrap(), prover_update_domain().unwrap());
    }

    #[test]
    fn validate_ok_with_matching_pubkey() {
        let state = make_state();
        let pk = vec![0xAAu8; 585];
        let addr = seed_prover(&state, &pk);
        let op = build_update(addr, vec![0xCCu8; 32]);
        assert!(validate_prover_update(&op, &state, &AcceptAll).unwrap());
    }

    #[test]
    fn validate_rejects_missing_sig() {
        let state = make_state();
        let op = ProverUpdate {
            delegate_address: vec![0xCCu8; 32],
            public_key_signature_bls48581: None,
        };
        assert!(validate_prover_update(&op, &state, &AcceptAll).is_err());
    }

    #[test]
    fn validate_rejects_wrong_address_length() {
        let state = make_state();
        let op = ProverUpdate {
            delegate_address: vec![0xCCu8; 32],
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xAAu8; 31], // wrong
            }),
        };
        assert!(validate_prover_update(&op, &state, &AcceptAll).is_err());
    }

    #[test]
    fn validate_rejects_wrong_delegate_length() {
        let state = make_state();
        let pk = vec![0xAAu8; 585];
        let addr = seed_prover(&state, &pk);
        let op = build_update(addr, vec![0xCCu8; 31]); // wrong
        assert!(validate_prover_update(&op, &state, &AcceptAll).is_err());
    }

    #[test]
    fn validate_rejects_missing_prover() {
        let state = make_state();
        let op = build_update([0xAAu8; 32], vec![0xCCu8; 32]);
        assert!(validate_prover_update(&op, &state, &AcceptAll).is_err());
    }

    #[test]
    fn validate_rejects_invalid_signature() {
        let state = make_state();
        let pk = vec![0xAAu8; 585];
        let addr = seed_prover(&state, &pk);
        let op = build_update(addr, vec![0xCCu8; 32]);
        assert!(validate_prover_update(&op, &state, &RejectAll).is_err());
    }

    #[test]
    fn validate_rejects_address_mismatch() {
        // Seed a prover with pubkey A, but craft an addressed-sig with a
        // DIFFERENT address that isn't poseidon(A). The vertex is loaded
        // via the wrong address, so validate first hits "prover not found".
        let state = make_state();
        let pk = vec![0xAAu8; 585];
        let _addr = seed_prover(&state, &pk);
        let wrong_addr = [0xDDu8; 32];
        let op = build_update(wrong_addr, vec![0xCCu8; 32]);
        assert!(validate_prover_update(&op, &state, &AcceptAll).is_err());
    }

    #[test]
    fn materialize_writes_delegate_to_reward_vertex() {
        let state = make_state();
        let pk = vec![0xAAu8; 585];
        let addr = seed_prover(&state, &pk);
        let delegate = vec![0xCCu8; 32];

        let op = build_update(addr, delegate.clone());
        materialize_prover_update(&op, 42, &state).unwrap();

        // Read back from changeset
        let reward_addr = reward_address(&addr).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        let blob = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &reward_addr, &va_disc)
            .unwrap()
            .expect("reward vertex should exist");
        let tree = rebuild_vertex_tree_from_blob(&blob);
        let got = read_field(&tree, "reward:ProverReward", "DelegateAddress").unwrap();
        assert_eq!(got, delegate);
    }

    #[test]
    fn materialize_rejects_empty_delegate() {
        let state = make_state();
        let pk = vec![0xAAu8; 585];
        let addr = seed_prover(&state, &pk);
        let op = build_update(addr, vec![]);
        assert!(materialize_prover_update(&op, 1, &state).is_err());
    }

    #[test]
    fn materialize_rejects_missing_prover() {
        let state = make_state();
        let op = build_update([0xAAu8; 32], vec![0xCCu8; 32]);
        assert!(materialize_prover_update(&op, 1, &state).is_err());
    }

    #[test]
    fn materialize_rejects_address_mismatch() {
        let state = make_state();
        let pk = vec![0xAAu8; 585];
        let _real_addr = seed_prover(&state, &pk);
        let op = build_update([0xDDu8; 32], vec![0xCCu8; 32]);
        assert!(materialize_prover_update(&op, 1, &state).is_err());
    }
}
