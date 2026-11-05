use super::super::storage_epoch_proof::StorageEpochProof;
use super::super::storage_epoch_proof::{SealedLeaf, SeatClaim, SeatWitness};
use super::*;
use quil_crypto::{storage_hash as hash, storage_proof as proof};
use std::sync::Arc;

fn state() -> HypergraphState {
    HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(crate::hypergraph_state::InMemoryHypergraphStore::new()),
        Arc::new(quil_hypergraph::testing::StubProver),
    )))
}
fn gates(on: bool) {
    quil_types::consensus::set_persistent_storage_epoch_for_thread(on.then_some(1500));
    quil_types::consensus::set_stable_replica_key_epoch_for_thread(on.then_some(1393));
}
fn fixture(
    member: [u8; 32],
) -> (
    sector::Registration,
    proof::SealProof,
    proof::SealProof,
    Vec<u8>,
) {
    let n = 32;
    let id = [5; 32];
    let params = quil_crypto::sdr::SdrParams::default();
    let (last, columns) = proof::label_leaf(
        n,
        &quil_crypto::sdr::stable_replica_key(&member, &id),
        &params,
        &mut |_, _| {},
    );
    let labels = proof::MerkleCap::from_digests(&last, 3);
    let bytes = hash::digests_to_bytes(&last);
    let columns = proof::MerkleCap::from_digests(&columns, 3).commitment(proof::Tree::Column);
    let encoded = proof::encode_with_labels(
        b"new useful bytes",
        n,
        &last,
        labels.commitment(proof::Tree::Replica),
    )
    .unwrap();
    let root = sector::Registration {
        data: encoded.comm_d,
        labels: labels.commitment(proof::Tree::Replica),
        replica: encoded.comm_r,
        sector: id,
        columns,
    };
    let mut data = proof::data_nodes(b"new useful bytes");
    data.resize(n as usize * 32, 0);
    let fresh = sector::prove(
        &member,
        b"leaf",
        1500,
        n,
        &root,
        b"beacon",
        &|tree, i| match tree {
            proof::Tree::Data => sector::open(&encoded.data_cap, &data, i),
            proof::Tree::Replica => sector::open(&encoded.replica_cap, &encoded.replica, i),
            proof::Tree::Column => sector::open(&labels, &bytes, i),
        },
    )
    .unwrap();
    let beacon = sector::certificate_beacon(&member, b"leaf", 1500, n, &root, b"beacon");
    let statement = proof::SealStatement {
        member: &member,
        leaf_id: &id,
        epoch: 1500,
        n,
        registered: root.certificate(n).registered().unwrap(),
        beacon: &beacon,
    };
    let plain = proof::prove_seal(&bytes, &statement, &params, sector::CHALLENGES).unwrap();
    (root, fresh, plain, bytes)
}
fn claim(member: [u8; 32], root: sector::Registration) -> EpochClaim {
    EpochClaim {
        member,
        seats: vec![SeatClaim {
            seal_epoch: 1500,
            seals: vec![SealedLeaf {
                leaf_id: b"leaf".to_vec(),
                n: 32,
                registered: root.registered(),
                beacon: b"beacon".to_vec(),
                persistent: Some(root),
            }],
            ..Default::default()
        }],
    }
}

#[test]
fn certified_labels_do_not_skip_fresh_possession_or_allow_double_use() {
    gates(true);
    let member = [3; 32];
    let (root, fresh, _, _) = fixture(member);
    let claim = claim(member, root);
    let witness = SeatWitness {
        seals: vec![fresh],
        certificates: vec![Vec::new()],
        opened: Vec::new(),
    };
    let bytes = prove(&claim, &[witness.clone()]).unwrap();
    assert!(
        verify(&claim, &bytes, &|_| Ok(None)).is_err(),
        "a local flag cannot certify labels"
    );
    let state = state();
    let cert = root.certificate(32);
    apply(
        &state,
        1,
        &[StateRecord {
            address: certificate_address(&member, &root.sector),
            member,
            sector: root.sector,
            certificate: cert.to_bytes(),
            usage: Vec::new(),
        }],
    )
    .unwrap();
    let records = check(&state, &claim, &bytes).unwrap();
    assert_eq!(records.len(), 1);
    apply(&state, 2, &records).unwrap();
    assert!(check(&state, &claim, &bytes).is_err(), "cross-batch reuse");
    let mut duplicate = claim.clone();
    duplicate.seats.push(claim.seats[0].clone());
    let packet = prove(&duplicate, &[witness.clone(), witness.clone()]).unwrap();
    assert!(check(&state, &duplicate, &packet).is_err());
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(verify(&claim, &bad, &|_| Ok(Some(cert))).is_err());
    let mut bad = bytes.clone();
    bad[7] ^= 1;
    assert!(verify(&claim, &bad, &|_| Ok(Some(cert))).is_err());
    let mut changed = cert;
    changed.columns[0] ^= 1;
    assert!(verify(&claim, &bytes, &|_| Ok(Some(changed))).is_err());
    quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(1501));
    assert!(verify(&claim, &bytes, &|_| Ok(Some(cert))).is_err());
    gates(false);
}

#[test]
fn initial_certificate_uses_existing_stark_and_binds_identity_and_roots() {
    gates(true);
    let member = [3; 32];
    let (root, fresh, plain, _) = fixture(member);
    let cert = prove_certificate(&member, b"leaf", 1500, 32, &root, b"beacon", &plain).unwrap();
    quil_storage_stark::persistent::verify(&member, b"leaf", 1500, 32, &root, b"beacon", &cert)
        .unwrap();
    for (m, l, b) in [
        ([4; 32], b"leaf".as_slice(), b"beacon".as_slice()),
        (member, b"other".as_slice(), b"beacon".as_slice()),
        (member, b"leaf".as_slice(), b"changed".as_slice()),
    ] {
        assert!(quil_storage_stark::persistent::verify(&m, l, 1500, 32, &root, b, &cert).is_err());
    }
    let bytes = prove(
        &claim(member, root),
        &[SeatWitness {
            seals: vec![fresh],
            certificates: vec![cert],
            opened: Vec::new(),
        }],
    )
    .unwrap();
    assert_eq!(
        verify(&claim(member, root), &bytes, &|_| Ok(None)).unwrap(),
        vec![root.certificate(32)]
    );
    gates(false);
}

struct Signature(bool);
impl quil_types::crypto::KeyManager for Signature {
    fn validate_signature(
        &self,
        key: quil_types::crypto::KeyType,
        _pk: &[u8],
        _msg: &[u8],
        _sig: &[u8],
        domain: &[u8],
    ) -> Result<bool> {
        assert_eq!(key, quil_types::crypto::KeyType::Falcon512);
        assert_eq!(domain, capacity_domain()?.as_slice());
        Ok(self.0)
    }
}
#[test]
fn capacity_precommits_are_signed_bounded_idempotent_and_create_no_seat() {
    gates(true);
    let state = state();
    let pubkey = [7; 897];
    let member = super::super::materialize::prover_address_from_pubkey(&pubkey).unwrap();
    let tree = super::super::materialize::create_prover_vertex_tree(&pubkey, 1).unwrap();
    state
        .set(
            &GLOBAL_INTRINSIC_ADDRESS,
            &member,
            &crate::hypergraph_state::vertex_adds_discriminator().unwrap(),
            1,
            crate::prover_registry::vertex_tree_to_blob(&tree),
        )
        .unwrap();
    let (root, _, _, _) = fixture(member);
    let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
    let message = CapacityMessage {
        member,
        epoch: 1500,
        certificate: root.certificate(32),
        signed_at: frame,
        signature: vec![1; 666],
        proof: Vec::new(),
    };
    let outer = message.envelope();
    let unavailable = |_| Err(QuilError::ExecutionUnavailable("no beacon".into()));
    assert!(capacity_message(&outer));
    assert_eq!(
        StorageEpochProof::from_canonical_bytes(&outer.to_canonical_bytes()).unwrap(),
        outer
    );
    assert!(check_capacity(frame, &outer, &state, &Signature(false), &unavailable).is_err());
    let records = check_capacity(frame, &outer, &state, &Signature(true), &unavailable).unwrap();
    assert_eq!(records.len(), 1);
    apply(&state, frame, &records).unwrap();
    assert_eq!(
        pending_certificate(&state, &member, &message.certificate, 1500)
            .unwrap()
            .unwrap()
            .committed_at,
        frame
    );
    assert!(certificate(&state, &member, &root.sector)
        .unwrap()
        .is_none());
    assert!(
        check_capacity(frame + 1, &outer, &state, &Signature(true), &unavailable)
            .unwrap()
            .is_empty(),
        "retry preserves original beacon frame"
    );
    let mut collide = message.clone();
    collide.certificate.sector[1] ^= 1;
    assert!(check_capacity(
        frame,
        &collide.envelope(),
        &state,
        &Signature(true),
        &unavailable
    )
    .is_err());
    assert!(check_capacity(frame + 11, &outer, &state, &Signature(true), &unavailable).is_err());
    let mut far = message.clone();
    far.epoch += 100;
    assert!(check_capacity(
        frame,
        &far.envelope(),
        &state,
        &Signature(true),
        &unavailable
    )
    .is_err());
    let mut unregistered = message.clone();
    unregistered.member = [0; 32];
    assert!(check_capacity(
        frame,
        &unregistered.envelope(),
        &state,
        &Signature(true),
        &unavailable
    )
    .is_err());
    // The only record is a bounded pending slot, not eligibility or rewards.
    assert!(records[0].usage.len() == 16);

    let output = vec![9; 516];
    let beacon = quil_crypto::porep::derive_storage_beacon(frame + 1, &output);
    let root = message.root();
    let (_, _, _, last) = fixture(member);
    let challenge = sector::certificate_beacon(&member, &root.sector, 1500, 32, &root, &beacon);
    let statement = proof::SealStatement {
        member: &member,
        leaf_id: &root.sector,
        epoch: 1500,
        n: 32,
        registered: message.certificate.registered().unwrap(),
        beacon: &challenge,
    };
    let plain = proof::prove_seal(
        &last,
        &statement,
        &quil_crypto::sdr::SdrParams::default(),
        sector::CHALLENGES,
    )
    .unwrap();
    let bytes = prove_certificate(&member, &root.sector, 1500, 32, &root, &beacon, &plain).unwrap();
    let mut certification = message.clone();
    certification.signature.clear();
    certification.proof = bytes;
    assert!(check_capacity(
        frame + 1,
        &certification.envelope(),
        &state,
        &Signature(false),
        &|_| Ok(output.clone())
    )
    .is_err());
    let accepted = check_capacity(
        frame + 2,
        &certification.envelope(),
        &state,
        &Signature(false),
        &|_| Ok(output.clone()),
    )
    .unwrap();
    assert_eq!(accepted.len(), 1);
    assert!(accepted[0].usage.is_empty());
    apply(&state, frame + 2, &accepted).unwrap();
    assert_eq!(
        certificate(&state, &member, &root.sector).unwrap(),
        Some(message.certificate)
    );
    assert!(check_capacity(
        frame + 3,
        &certification.envelope(),
        &state,
        &Signature(false),
        &unavailable
    )
    .unwrap()
    .is_empty());
    gates(false);
}

#[test]
fn confirm_root_codec_and_semantics_switch_only_at_coordinated_epoch() {
    use super::super::{
        leaf_root_registration as wire, prover_ops::ProverConfirm,
        verify::validate_confirm_leaf_roots,
    };
    gates(true);
    quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(1314));
    let root = sector::Registration {
        data: [0; 32],
        labels: [0; 32],
        replica: [0; 32],
        sector: [5; 32],
        columns: [0; 32],
    };
    let mut op = ProverConfirm::default();
    op.leaf_roots = vec![wire::ConfirmLeafRoots {
        filter: vec![2; 32],
        entries: vec![wire::LeafRootEntry {
            prefix: Vec::new(),
            leaf_root: root.to_bytes(),
            num_blocks: 32,
        }],
    }];
    wire::check_confirm_leaf_roots(&op.leaf_roots).unwrap();
    let mut bytes = Vec::new();
    wire::append_confirm_leaf_roots(&mut bytes, &op.leaf_roots);
    assert_eq!(
        wire::read_confirm_leaf_roots(&bytes, &mut 0).unwrap(),
        op.leaf_roots
    );
    let frame = 1499 * quil_types::consensus::epoch_length_frames();
    assert!(validate_confirm_leaf_roots(&op, frame - 1).is_err());
    validate_confirm_leaf_roots(&op, frame).unwrap();
    op.leaf_roots[0].entries[0].num_blocks = 33;
    assert!(validate_confirm_leaf_roots(&op, frame).is_err());
    op.leaf_roots[0].entries[0].leaf_root = vec![0; 96];
    op.leaf_roots[0].entries[0].num_blocks = 32;
    validate_confirm_leaf_roots(&op, frame - 1).unwrap();
    assert!(validate_confirm_leaf_roots(&op, frame).is_err());
    gates(false);
    quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
}
