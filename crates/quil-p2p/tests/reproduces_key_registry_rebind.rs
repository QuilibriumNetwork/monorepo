//! A/B reproducer (KeyRegistry, H4): when an identity rebinds to another
//! prover key, the replaced key's peer ID must stop resolving to it; it
//! used to stay authorized, one entry per rebinding, without bound.
use quil_types::crypto::{BlsConstructor as _, Signer as _};

/// A binding of the identity `seed_byte` to a fresh prover key, with valid
/// cross-signatures, and that key.
fn binding(seed_byte: u8, last_updated_ms: u64) -> (quil_p2p::CanonicalKeyRegistry, Vec<u8>) {
    quil_crypto::init();
    let seed = [seed_byte; 57];
    let identity = quil_crypto::Ed448Signer::from_bytes(
        &seed,
        &quil_crypto::Ed448Signer::derive_public(&seed).unwrap(),
    )
    .unwrap();
    let ed448 = identity.public_key().to_vec();
    let (prover, prover_key) = quil_crypto::FalconKeyConstructor.new_key().unwrap();
    let domain = quil_p2p::signer_registry::KEY_REGISTRY_DOMAIN;
    let mut identity_msg = domain.to_vec();
    identity_msg.extend_from_slice(&prover_key);
    let reg = quil_p2p::CanonicalKeyRegistry {
        ed448_pubkey: ed448.clone(),
        bls_pubkey: prover_key.clone(),
        identity_to_prover_sig: identity.sign(&identity_msg).unwrap(),
        prover_to_identity_sig: prover.sign_with_domain(&ed448, domain).unwrap(),
        last_updated_ms,
        ..Default::default()
    };
    (reg, prover_key)
}

#[test]
fn reproduces_key_registry_rebind_keeps_old_peer_id() {
    let registry = quil_p2p::SignerRegistry::new();
    let (first, first_key) = binding(0x5A, 1);
    let (second, second_key) = binding(0x5A, 2);
    assert!(registry.update(first));
    assert!(registry.update(second));
    let old_peer = quil_p2p::peer_id_from_falcon_pubkey(&first_key);
    assert_eq!(
        registry.prover_key_for_peer_id(&old_peer),
        None,
        "the replaced prover key's peer ID still resolves to it after its identity rebound to another key"
    );
    let new_peer = quil_p2p::peer_id_from_falcon_pubkey(&second_key);
    assert_eq!(registry.prover_key_for_peer_id(&new_peer), Some(second_key));
}
