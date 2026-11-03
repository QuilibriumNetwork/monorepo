//! Inner Falcon-512 signing for prover lifecycle ops.
//!
//! Each op signs a per-op message under a Poseidon-hashed domain with the
//! `q-prover-key` (Falcon-512, the post-quantum replacement for the former
//! BLS48-581 prover key), then wraps the signature + prover address in a
//! `Bls48581AddressedSignature` (legacy proto name; carries Falcon bytes).
//!
//! The exact messages and domains are taken from the node's verify path
//! (`quil_execution::global_intrinsic::verify`), so a signature produced
//! here is accepted by the running node. The tests below send each op through
//! its encoding and the verifier every node runs.

use quil_keys::FileKeyManager;
use quil_types::crypto::Signer;
use quil_types::proto::global::ProverConfirm;
use quil_types::proto::keys::Bls48581AddressedSignature;

use quil_execution::global_intrinsic::prover_update_materialize::prover_update_domain;
use quil_execution::global_intrinsic::prover_verify::{
    multi_filter_signing_message, prover_confirm_domain, prover_leave_domain,
    prover_leave_signing_message, prover_pause_domain, prover_reject_domain, prover_resume_domain,
    prover_update_signing_message, single_filter_signing_message,
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

/// Split `filters` into the lists one lifecycle op carries, at most
/// `MAX_FILTERS_PER_OP` each: callers sign and send one op per list, so a
/// longer selection still goes out as ops every node decodes.
pub fn op_chunks(filters: &[Vec<u8>]) -> std::slice::Chunks<'_, Vec<u8>> {
    filters.chunks(quil_execution::global_intrinsic::prover_ops::MAX_FILTERS_PER_OP)
}

/// Refuse to sign one op over the filters no node decodes: every node drops
/// such a message, so the command would report success while nothing
/// changes. A filter over the length limit cannot be split off; callers
/// split longer lists with [`op_chunks`].
fn check_filters(op: &str, filters: &[Vec<u8>]) -> anyhow::Result<()> {
    quil_execution::global_intrinsic::prover_ops::check_filters(filters).map_err(|e| {
        anyhow::anyhow!(
            "{op}: {e}; no node decodes such a message: one op carries at most {} filters of at most {} bytes",
            quil_execution::global_intrinsic::prover_ops::MAX_FILTERS_PER_OP,
            quil_execution::global_intrinsic::prover_ops::MAX_FILTER_LEN
        )
    })
}

/// ProverPause signature (single filter).
pub fn pause_sig(
    km: &FileKeyManager,
    filter: &[u8],
    frame: u64,
) -> anyhow::Result<Bls48581AddressedSignature> {
    check_filters("pause", &[filter.to_vec()])?;
    let msg = single_filter_signing_message(filter, frame);
    let domain = prover_pause_domain().map_err(|e| anyhow::anyhow!("pause domain: {e}"))?;
    addressed_sig(km, &msg, &domain)
}

/// ProverResume signature (single filter).
pub fn resume_sig(
    km: &FileKeyManager,
    filter: &[u8],
    frame: u64,
) -> anyhow::Result<Bls48581AddressedSignature> {
    check_filters("resume", &[filter.to_vec()])?;
    let msg = single_filter_signing_message(filter, frame);
    let domain = prover_resume_domain().map_err(|e| anyhow::anyhow!("resume domain: {e}"))?;
    addressed_sig(km, &msg, &domain)
}

/// ProverLeave signature (multi filter).
pub fn leave_sig(
    km: &FileKeyManager,
    filters: &[Vec<u8>],
    frame: u64,
) -> anyhow::Result<Bls48581AddressedSignature> {
    check_filters("leave", filters)?;
    let msg = prover_leave_signing_message(filters, frame);
    let domain = prover_leave_domain().map_err(|e| anyhow::anyhow!("leave domain: {e}"))?;
    addressed_sig(km, &msg, &domain)
}

/// A signed ProverConfirm as qclient sends it: no leaf roots and no
/// release, so it signs and encodes as a legacy confirm. qclient is not the
/// node and cannot attest the node's build; it never consults the confirm
/// release frame. A confirm without a release keeps the allocation's
/// recorded one.
// `filter` is deprecated in global.proto in favour of the repeated `filters`,
// but it is still on the wire; it is sent empty, as before.
#[allow(deprecated)]
pub fn confirm_op(
    km: &FileKeyManager,
    filters: &[Vec<u8>],
    frame: u64,
) -> anyhow::Result<ProverConfirm> {
    Ok(ProverConfirm {
        filter: Vec::new(),
        frame_number: frame,
        public_key_signature_bls48581: Some(confirm_sig(km, filters, frame)?),
        filters: filters.to_vec(),
        leaf_roots: Vec::new(),
        release: None,
    })
}

/// ProverConfirm signature (multi filter; CLI registers no leaf roots, so
/// the confirm message is byte-identical to the multi-filter message).
pub fn confirm_sig(
    km: &FileKeyManager,
    filters: &[Vec<u8>],
    frame: u64,
) -> anyhow::Result<Bls48581AddressedSignature> {
    check_filters("confirm", filters)?;
    let msg = multi_filter_signing_message(filters, frame);
    let domain = prover_confirm_domain().map_err(|e| anyhow::anyhow!("confirm domain: {e}"))?;
    addressed_sig(km, &msg, &domain)
}

/// ProverReject signature (multi filter).
pub fn reject_sig(
    km: &FileKeyManager,
    filters: &[Vec<u8>],
    frame: u64,
) -> anyhow::Result<Bls48581AddressedSignature> {
    check_filters("reject", filters)?;
    let msg = multi_filter_signing_message(filters, frame);
    let domain = prover_reject_domain().map_err(|e| anyhow::anyhow!("reject domain: {e}"))?;
    addressed_sig(km, &msg, &domain)
}

/// ProverUpdate (delegate) signature over the 32-byte delegate address, then
/// `frame` (the frame the update carries from the prover operation replay
/// guard epoch); a `frame` of 0 signs the delegate address alone.
pub fn update_sig(
    km: &FileKeyManager,
    delegate_address: &[u8],
    frame: u64,
) -> anyhow::Result<Bls48581AddressedSignature> {
    let domain = prover_update_domain().map_err(|e| anyhow::anyhow!("update domain: {e}"))?;
    let msg = prover_update_signing_message(delegate_address, frame);
    addressed_sig(km, &msg, &domain)
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

    /// A prover vertex as every node reads it: this key's.
    fn prover_tree(km: &FileKeyManager) -> quil_tries::VectorCommitmentTree {
        let pubkey = km
            .get_signer_by_id("q-prover-key")
            .unwrap()
            .public_key()
            .to_vec();
        let mut tree = quil_tries::VectorCommitmentTree::new();
        quil_execution::global_schema::write_type(&mut tree, "prover:Prover").unwrap();
        quil_execution::global_schema::write_field(
            &mut tree,
            "prover:Prover",
            "PublicKey",
            &pubkey,
        )
        .unwrap();
        tree
    }

    /// An allocation vertex in raw execution status `status`.
    fn allocation_tree(status: u8) -> quil_tries::VectorCommitmentTree {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        let class = "allocation:ProverAllocation";
        quil_execution::global_schema::write_type(&mut tree, class).unwrap();
        quil_execution::global_schema::write_field(&mut tree, class, "Status", &[status]).unwrap();
        tree
    }

    /// Filter lists a message framing could treat alike: several of differing
    /// lengths, whose concatenation does not show where each ends, and one.
    fn filter_lists() -> [Vec<Vec<u8>>; 2] {
        [
            vec![vec![0x08; 32], vec![0x09; 40], vec![0x0A; 35]],
            vec![vec![0x08; 32]],
        ]
    }

    /// The network's verdict on a leave `qclient` signs, after its wire
    /// encoding. The manager builds its leave through the same `leave_sig`
    /// (`manage::actions::build_request`), whose test sends it here too.
    #[test]
    fn a_leave_passes_the_network_verifier() {
        use quil_execution::global_intrinsic::{
            conversions, prover_filter_ops::ProverLeave, verify,
        };
        let (km, _d) = km_with_prover_key();
        let tree = prover_tree(&km);
        for filters in filter_lists() {
            let pb = quil_types::proto::global::ProverLeave {
                filters: filters.clone(),
                frame_number: 777,
                public_key_signature_bls48581: Some(leave_sig(&km, &filters, 777).unwrap()),
            };
            let wire = conversions::prover_leave_from_proto(&pb)
                .to_canonical_bytes()
                .unwrap();
            let op = ProverLeave::from_canonical_bytes(&wire).unwrap();
            assert_eq!(op.filters, filters);
            assert!(
                verify::verify_prover_leave(&op, &tree, &quil_crypto::DefaultKeyManager::new())
                    .unwrap(),
                "the network refuses a leave signed by qclient: verify_prover_leave returned \
                 false for {} filter(s), so every node drops it while the command reports it sent",
                filters.len()
            );
        }
    }

    #[test]
    fn a_pause_passes_the_network_verifier() {
        use quil_execution::global_intrinsic::{
            conversions, prover_filter_ops::ProverPause, verify,
        };
        let (km, _d) = km_with_prover_key();
        let filter = vec![0x08; 35];
        let pb = quil_types::proto::global::ProverPause {
            filter: filter.clone(),
            frame_number: 777,
            public_key_signature_bls48581: Some(pause_sig(&km, &filter, 777).unwrap()),
        };
        let wire = conversions::prover_pause_from_proto(&pb)
            .to_canonical_bytes()
            .unwrap();
        let op = ProverPause::from_canonical_bytes(&wire).unwrap();
        assert_eq!(op.filter, filter);
        let active = allocation_tree(1);
        assert!(verify::verify_prover_pause(
            &op,
            &prover_tree(&km),
            Some(&active),
            &quil_crypto::DefaultKeyManager::new()
        )
        .unwrap());
    }

    #[test]
    fn a_resume_passes_the_network_verifier() {
        use quil_execution::global_intrinsic::{
            conversions, prover_filter_ops::ProverResume, verify,
        };
        let (km, _d) = km_with_prover_key();
        let filter = vec![0x08; 35];
        let pb = quil_types::proto::global::ProverResume {
            filter: filter.clone(),
            frame_number: 777,
            public_key_signature_bls48581: Some(resume_sig(&km, &filter, 777).unwrap()),
        };
        let wire = conversions::prover_resume_from_proto(&pb)
            .to_canonical_bytes()
            .unwrap();
        let op = ProverResume::from_canonical_bytes(&wire).unwrap();
        assert_eq!(op.filter, filter);
        let paused = allocation_tree(2);
        assert!(verify::verify_prover_resume(
            &op,
            &prover_tree(&km),
            Some(&paused),
            &quil_crypto::DefaultKeyManager::new()
        )
        .unwrap());
    }

    #[test]
    fn a_confirm_passes_the_network_verifier() {
        use quil_execution::global_intrinsic::{conversions, prover_ops::ProverConfirm, verify};
        let (km, _d) = km_with_prover_key();
        let tree = prover_tree(&km);
        for filters in filter_lists() {
            let pb = confirm_op(&km, &filters, 777).unwrap();
            let wire = conversions::prover_confirm_from_proto(&pb)
                .to_canonical_bytes()
                .unwrap();
            let op = ProverConfirm::from_canonical_bytes(&wire).unwrap();
            assert_eq!(op.filters, filters);
            assert!(verify::verify_prover_confirm(
                &op,
                &tree,
                &quil_crypto::DefaultKeyManager::new()
            )
            .unwrap());
        }
    }

    #[test]
    #[allow(deprecated)] // ProverReject.filter is a deprecated wire field.
    fn a_reject_passes_the_network_verifier() {
        use quil_execution::global_intrinsic::{conversions, prover_ops::ProverReject, verify};
        let (km, _d) = km_with_prover_key();
        let tree = prover_tree(&km);
        for filters in filter_lists() {
            let pb = quil_types::proto::global::ProverReject {
                filter: Vec::new(),
                frame_number: 777,
                public_key_signature_bls48581: Some(reject_sig(&km, &filters, 777).unwrap()),
                filters: filters.clone(),
            };
            let wire = conversions::prover_reject_from_proto(&pb)
                .to_canonical_bytes()
                .unwrap();
            let op = ProverReject::from_canonical_bytes(&wire).unwrap();
            assert_eq!(op.filters, filters);
            assert!(verify::verify_prover_reject(
                &op,
                &tree,
                &quil_crypto::DefaultKeyManager::new()
            )
            .unwrap());
        }
    }

    /// Both forms `delegate` sends: the frame it signs from the replay guard
    /// epoch, and none before it.
    #[test]
    fn an_update_passes_the_network_verifier() {
        use quil_execution::global_intrinsic::{conversions, prover_ops::ProverUpdate, verify};
        let (km, _d) = km_with_prover_key();
        let tree = prover_tree(&km);
        let delegate = vec![0x11; 32];
        quil_types::consensus::set_prover_op_replay_guard_epoch_for_thread(Some(1));
        let epoch = quil_types::consensus::epoch_length_frames();
        for head in [epoch - 1, epoch + 7] {
            let frame = ProverUpdate::signed_frame(head);
            assert_eq!(frame == 0, head < epoch);
            let pb = quil_types::proto::global::ProverUpdate {
                delegate_address: delegate.clone(),
                public_key_signature_bls48581: Some(update_sig(&km, &delegate, frame).unwrap()),
                frame_number: frame,
            };
            let wire = conversions::prover_update_from_proto(&pb)
                .to_canonical_bytes()
                .unwrap();
            let op = ProverUpdate::from_canonical_bytes(&wire).unwrap();
            assert!(verify::verify_prover_update(
                &op,
                &tree,
                head,
                &quil_crypto::DefaultKeyManager::new()
            )
            .unwrap());
        }
        quil_types::consensus::set_prover_op_replay_guard_epoch_for_thread(None);
    }

    /// The signature this module produces must be accepted by the exact
    /// `validate_signature` the node's verify path calls.
    #[test]
    fn leave_signature_verifies_against_node_primitive() {
        let (km, _d) = km_with_prover_key();
        let filters = vec![vec![0xFFu8; 32]];
        let frame = 12345u64;

        let sig = leave_sig(&km, &filters, frame).unwrap();

        let pubkey = km
            .get_signer_by_id("q-prover-key")
            .unwrap()
            .public_key()
            .to_vec();
        let message = prover_leave_signing_message(&filters, frame);
        let domain = prover_leave_domain().unwrap();

        let ok = km
            .validate_signature(
                KeyType::Falcon512,
                &pubkey,
                &message,
                &sig.signature,
                &domain,
            )
            .unwrap();
        assert!(
            ok,
            "leave signature must verify against KeyManager::validate_signature"
        );

        // Address is poseidon(pubkey), 32 bytes.
        assert_eq!(sig.address.len(), 32);
        assert_eq!(
            sig.address,
            quil_crypto::poseidon::hash_bytes_to_32(&pubkey)
                .unwrap()
                .to_vec()
        );
    }

    /// A qclient confirm carries no release and signs and encodes as a legacy
    /// confirm, whatever the environment sets for the node's release frames.
    #[test]
    #[allow(deprecated)] // the legacy encoding writes the deprecated `filter` placeholder
    fn a_qclient_confirm_signs_and_encodes_as_legacy_whatever_the_environment_says() {
        use quil_execution::global_intrinsic::{
            addressed_signature::AddressedSignature, conversions, prover_release,
        };
        // Nextest runs each test in its own process; qclient calls no `init_*`.
        std::env::set_var("QUIL_CONFIRM_RELEASE_FRAME", "0");
        std::env::set_var("QUIL_RELEASE_ELIGIBILITY", "0=2.1.0.25.0");
        let (km, _d) = km_with_prover_key();
        let filters = vec![vec![0xFFu8; 32], vec![0xEEu8; 32]];
        let frame = 4242u64;
        let op = confirm_op(&km, &filters, frame).unwrap();
        assert_eq!(op.release, None);
        assert!(op.leaf_roots.is_empty() && op.filter.is_empty());
        assert_eq!(
            prover_release::confirm_release_frame(),
            u64::MAX,
            "the environment is not read"
        );

        let pubkey = km
            .get_signer_by_id("q-prover-key")
            .unwrap()
            .public_key()
            .to_vec();
        let sig = op.public_key_signature_bls48581.clone().unwrap();
        let legacy_message = multi_filter_signing_message(&filters, frame);
        assert!(km
            .validate_signature(
                KeyType::Falcon512,
                &pubkey,
                &legacy_message,
                &sig.signature,
                &prover_confirm_domain().unwrap()
            )
            .unwrap());

        let mut legacy = Vec::new();
        legacy.extend_from_slice(&0x0305u32.to_be_bytes());
        legacy.extend_from_slice(&32u32.to_be_bytes());
        legacy.extend_from_slice(b"reservedreservedreservedreserved");
        legacy.extend_from_slice(&frame.to_be_bytes());
        let sig_bytes = AddressedSignature {
            signature: sig.signature,
            address: sig.address,
        }
        .to_canonical_bytes()
        .unwrap();
        legacy.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
        legacy.extend_from_slice(&sig_bytes);
        legacy.extend_from_slice(&(filters.len() as u32).to_be_bytes());
        for filter in &filters {
            legacy.extend_from_slice(&(filter.len() as u32).to_be_bytes());
            legacy.extend_from_slice(filter);
        }
        assert_eq!(
            conversions::prover_confirm_from_proto(&op)
                .to_canonical_bytes()
                .unwrap(),
            legacy
        );
    }

    /// qclient refuses to sign an op no node decodes instead of reporting
    /// a send that changes nothing.
    #[test]
    fn an_op_over_the_decode_limits_is_refused() {
        let (km, _d) = km_with_prover_key();
        let filters = |n: usize| vec![vec![0xFFu8; 32]; n];
        assert!(leave_sig(&km, &filters(100), 7).is_ok());
        for refused in [
            leave_sig(&km, &filters(101), 7).map(drop),
            reject_sig(&km, &filters(101), 7).map(drop),
            confirm_op(&km, &filters(101), 7).map(drop),
            pause_sig(&km, &[1; 65], 7).map(drop),
        ] {
            let error = refused.unwrap_err().to_string();
            assert!(
                error.contains("one op carries at most 100 filters of at most 64 bytes"),
                "{error}"
            );
        }
        let chunks: Vec<usize> = op_chunks(&filters(250)).map(<[Vec<u8>]>::len).collect();
        assert_eq!(
            chunks,
            vec![100, 100, 50],
            "a longer selection is signed as several ops"
        );
    }

    #[test]
    fn pause_and_update_signatures_verify() {
        let (km, _d) = km_with_prover_key();
        let filter = vec![0xAAu8; 32];
        let frame = 7u64;
        let pubkey = km
            .get_signer_by_id("q-prover-key")
            .unwrap()
            .public_key()
            .to_vec();

        let ps = pause_sig(&km, &filter, frame).unwrap();
        let pmsg = single_filter_signing_message(&filter, frame);
        assert!(km
            .validate_signature(
                KeyType::Falcon512,
                &pubkey,
                &pmsg,
                &ps.signature,
                &prover_pause_domain().unwrap()
            )
            .unwrap());

        let delegate = vec![0x11u8; 32];
        let us = update_sig(&km, &delegate, 0).unwrap();
        assert!(km
            .validate_signature(
                KeyType::Falcon512,
                &pubkey,
                &delegate,
                &us.signature,
                &prover_update_domain().unwrap()
            )
            .unwrap());
        let us = update_sig(&km, &delegate, frame).unwrap();
        assert!(km
            .validate_signature(
                KeyType::Falcon512,
                &pubkey,
                &prover_update_signing_message(&delegate, frame),
                &us.signature,
                &prover_update_domain().unwrap()
            )
            .unwrap());
    }
}
