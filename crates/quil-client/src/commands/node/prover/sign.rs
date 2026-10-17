//! Inner Falcon-512 signing for prover lifecycle ops.
//!
//! Each op signs a per-op message under a Poseidon-hashed domain with the
//! `q-prover-key` (Falcon-512, the post-quantum replacement for the former
//! BLS48-581 prover key), then wraps the signature + prover address in a
//! `Bls48581AddressedSignature` (legacy proto name; carries Falcon bytes).
//!
//! The exact messages and domains are taken from the node's verify path
//! (`quil_execution::global_intrinsic::verify`), so a signature produced
//! here is accepted by the running node. See the round-trip test below,
//! which checks the produced signature against the same
//! `KeyManager::validate_signature` the node uses.

use quil_keys::FileKeyManager;
use quil_types::crypto::Signer;
use quil_types::proto::keys::Bls48581AddressedSignature;

use quil_execution::global_intrinsic::prover_update_materialize::prover_update_domain;
use quil_execution::global_intrinsic::prover_verify::{
    multi_filter_signing_message, prover_confirm_domain, prover_leave_domain, prover_pause_domain,
    prover_reject_domain, prover_resume_domain, single_filter_signing_message,
};

/// Build the `Bls48581AddressedSignature` for a prover op: sign `message`
/// under `domain` with `q-prover-key`, and attach the prover address
/// (`poseidon(pubkey)`).
fn addressed_sig(
    km: &FileKeyManager,
    message: &[u8],
    domain: &[u8],
) -> anyhow::Result<Bls48581AddressedSignature> {
    let signer: Box<dyn Signer> = km
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get q-prover-key: {e}"))?;
    let pubkey = signer.public_key().to_vec();
    let address = quil_crypto::poseidon::hash_bytes_to_32(&pubkey)
        .map_err(|e| anyhow::anyhow!("prover address: {e}"))?
        .to_vec();
    let signature = signer
        .sign_with_domain(message, domain)
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;
    Ok(Bls48581AddressedSignature { signature, address })
}

/// ProverPause signature (single filter).
pub fn pause_sig(km: &FileKeyManager, filter: &[u8], frame: u64) -> anyhow::Result<Bls48581AddressedSignature> {
    let msg = single_filter_signing_message(filter, frame);
    let domain = prover_pause_domain().map_err(|e| anyhow::anyhow!("pause domain: {e}"))?;
    addressed_sig(km, &msg, &domain)
}

/// ProverResume signature (single filter).
pub fn resume_sig(km: &FileKeyManager, filter: &[u8], frame: u64) -> anyhow::Result<Bls48581AddressedSignature> {
    let msg = single_filter_signing_message(filter, frame);
    let domain = prover_resume_domain().map_err(|e| anyhow::anyhow!("resume domain: {e}"))?;
    addressed_sig(km, &msg, &domain)
}

/// ProverLeave signature (multi filter).
pub fn leave_sig(km: &FileKeyManager, filters: &[Vec<u8>], frame: u64) -> anyhow::Result<Bls48581AddressedSignature> {
    let msg = multi_filter_signing_message(filters, frame);
    let domain = prover_leave_domain().map_err(|e| anyhow::anyhow!("leave domain: {e}"))?;
    addressed_sig(km, &msg, &domain)
}

/// ProverConfirm signature (multi filter; CLI registers no leaf roots, so
/// the confirm message is byte-identical to the multi-filter message).
pub fn confirm_sig(km: &FileKeyManager, filters: &[Vec<u8>], frame: u64) -> anyhow::Result<Bls48581AddressedSignature> {
    let msg = multi_filter_signing_message(filters, frame);
    let domain = prover_confirm_domain().map_err(|e| anyhow::anyhow!("confirm domain: {e}"))?;
    addressed_sig(km, &msg, &domain)
}

/// ProverReject signature (multi filter).
pub fn reject_sig(km: &FileKeyManager, filters: &[Vec<u8>], frame: u64) -> anyhow::Result<Bls48581AddressedSignature> {
    let msg = multi_filter_signing_message(filters, frame);
    let domain = prover_reject_domain().map_err(|e| anyhow::anyhow!("reject domain: {e}"))?;
    addressed_sig(km, &msg, &domain)
}

/// ProverUpdate (delegate) signature. The signed message is just the
/// 32-byte delegate address.
pub fn update_sig(km: &FileKeyManager, delegate_address: &[u8]) -> anyhow::Result<Bls48581AddressedSignature> {
    let domain = prover_update_domain().map_err(|e| anyhow::anyhow!("update domain: {e}"))?;
    addressed_sig(km, delegate_address, &domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_crypto::FalconKeyConstructor;
    use quil_keys::FileKeyManager;
    use quil_types::crypto::KeyType;

    fn km_with_prover_key() -> (FileKeyManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let km = FileKeyManager::new(
            dir.path().join("keys.yml"),
            "",
            "q-prover-key".to_string(),
            Box::new(FalconKeyConstructor),
        )
        .unwrap();
        km.create_falcon_key("q-prover-key").unwrap();
        (km, dir)
    }

    /// The signature this module produces must be accepted by the exact
    /// `validate_signature` the node's verify path calls.
    #[test]
    fn leave_signature_verifies_against_node_primitive() {
        let (km, _d) = km_with_prover_key();
        let filters = vec![vec![0xFFu8; 32]];
        let frame = 12345u64;

        let sig = leave_sig(&km, &filters, frame).unwrap();

        let pubkey = km.get_signer_by_id("q-prover-key").unwrap().public_key().to_vec();
        let message = multi_filter_signing_message(&filters, frame);
        let domain = prover_leave_domain().unwrap();

        let ok = km
            .validate_signature(KeyType::Falcon512, &pubkey, &message, &sig.signature, &domain)
            .unwrap();
        assert!(ok, "leave signature must verify against KeyManager::validate_signature");

        // Address is poseidon(pubkey), 32 bytes.
        assert_eq!(sig.address.len(), 32);
        assert_eq!(
            sig.address,
            quil_crypto::poseidon::hash_bytes_to_32(&pubkey).unwrap().to_vec()
        );
    }

    #[test]
    fn pause_and_update_signatures_verify() {
        let (km, _d) = km_with_prover_key();
        let filter = vec![0xAAu8; 32];
        let frame = 7u64;
        let pubkey = km.get_signer_by_id("q-prover-key").unwrap().public_key().to_vec();

        let ps = pause_sig(&km, &filter, frame).unwrap();
        let pmsg = single_filter_signing_message(&filter, frame);
        assert!(km
            .validate_signature(KeyType::Falcon512, &pubkey, &pmsg, &ps.signature, &prover_pause_domain().unwrap())
            .unwrap());

        let delegate = vec![0x11u8; 32];
        let us = update_sig(&km, &delegate).unwrap();
        assert!(km
            .validate_signature(KeyType::Falcon512, &pubkey, &delegate, &us.signature, &prover_update_domain().unwrap())
            .unwrap());
    }
}
