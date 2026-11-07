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
    quil_types::consensus::set_min_sector_nodes_for_thread(on.then_some(32));
    quil_types::consensus::set_storage_seal_profile_for_thread(
        on.then_some(sector::Profile::Eleven),
    );
}
fn fixture(
    member: [u8; 32],
) -> (
    sector::Registration,
    proof::SealProof,
    proof::SealProof,
    Vec<u8>,
) {
    fixture_for_profile(member, sector::Profile::Eleven)
}
fn fixture_for_profile(
    member: [u8; 32],
    profile: sector::Profile,
) -> (
    sector::Registration,
    proof::SealProof,
    proof::SealProof,
    Vec<u8>,
) {
    let n = 32;
    let id = [5; 32];
    let params = quil_crypto::sdr::SdrParams::for_profile(profile);
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
        profile,
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
    assert_eq!(accepted.len(), 2, "the certificate and the member's count");
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
        profile: quil_types::consensus::StorageSealProfile::Eleven,
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

fn member_with_key(state: &HypergraphState, key: u8) -> ([u8; 32], Vec<u8>) {
    let pubkey = vec![key; 897];
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
    (member, pubkey)
}

fn set_seat(state: &HypergraphState, member: [u8; 32], key: &[u8], filter: &[u8], status: u8) {
    use super::super::materialize as m;
    let address = m::allocation_address(key, filter).unwrap();
    let mut tree = m::create_allocation_vertex_tree(&member, filter, 1).unwrap();
    write_field(
        &mut tree,
        "allocation:ProverAllocation",
        "Status",
        &[status],
    )
    .unwrap();
    state
        .set(
            &GLOBAL_INTRINSIC_ADDRESS,
            &address,
            &crate::hypergraph_state::vertex_adds_discriminator().unwrap(),
            1,
            crate::prover_registry::vertex_tree_to_blob(&tree),
        )
        .unwrap();
    let links = crate::hypergraph_state::hyperedge_adds_discriminator().unwrap();
    let existing = state
        .get(&GLOBAL_INTRINSIC_ADDRESS, &member, &links)
        .unwrap()
        .unwrap_or_default();
    let blob = m::extend_prover_allocation_hyperedge_blob(&existing, &[(address, &tree)]).unwrap();
    state
        .set(&GLOBAL_INTRINSIC_ADDRESS, &member, &links, 1, blob)
        .unwrap();
}

/// A member with `seats` active seats on distinct shards, `held` sectors counted.
fn member_at(state: &HypergraphState, key: u8, seats: u8, held: u64) -> ([u8; 32], Vec<u8>) {
    let (member, pubkey) = member_with_key(state, key);
    for seat in 0..seats {
        set_seat(
            state,
            member,
            &pubkey,
            &[seat; 32],
            super::super::materialize::STATUS_ACTIVE,
        );
    }
    hold(state, member, held);
    (member, pubkey)
}

fn hold(state: &HypergraphState, member: [u8; 32], held: u64) {
    apply(state, 1, &[sector_count_record(&member, held)]).unwrap();
}

fn room(state: &HypergraphState, member: [u8; 32]) -> SectorRoom {
    sector_room_in(state, &member).unwrap()
}

/// A precommit needs no labels: its slot is the sector's first byte % 16.
fn precommit_for(member: [u8; 32], id: [u8; 32], n: u64, frame: u64) -> CapacityMessage {
    CapacityMessage {
        member,
        epoch: 1500,
        certificate: sector::Certificate {
            profile: quil_types::consensus::StorageSealProfile::Eleven,
            sector: id,
            n,
            columns: [0; 32],
            labels: [0; 32],
        },
        signed_at: frame,
        signature: vec![1; 666],
        proof: Vec::new(),
    }
}

fn precommit(
    state: &HypergraphState,
    message: &CapacityMessage,
    frame: u64,
) -> Result<Vec<StateRecord>> {
    check_capacity(frame, &message.envelope(), state, &Signature(true), &|_| {
        Err(QuilError::ExecutionUnavailable("no beacon".into()))
    })
}

/// Precommit a really labelled sector and return its certificate message, due
/// from `frame + 2`.
fn pending_certification(
    state: &HypergraphState,
    member: [u8; 32],
    id: [u8; 32],
    frame: u64,
) -> CapacityMessage {
    let (certificate, last) = labelled_sector(&member, id, 32);
    let mut message = precommit_for(member, id, 32, frame);
    message.certificate = certificate;
    apply(state, frame, &precommit(state, &message, frame).unwrap()).unwrap();
    let beacon = quil_crypto::porep::derive_storage_beacon(frame + 1, &CERTIFY_OUTPUT);
    let root = message.root();
    let challenge = sector::certificate_beacon(&member, &id, 1500, 32, &root, &beacon);
    let statement = proof::SealStatement {
        member: &member,
        leaf_id: &id,
        epoch: 1500,
        n: 32,
        registered: certificate.registered().unwrap(),
        beacon: &challenge,
    };
    let plain = proof::prove_seal(
        &last,
        &statement,
        &quil_crypto::sdr::SdrParams::default(),
        sector::CHALLENGES,
    )
    .unwrap();
    message.signature.clear();
    message.proof = prove_certificate(&member, &id, 1500, 32, &root, &beacon, &plain).unwrap();
    message
}
const CERTIFY_OUTPUT: [u8; 516] = [9; 516];

fn certify(
    state: &HypergraphState,
    message: &CapacityMessage,
    frame: u64,
) -> Result<Vec<StateRecord>> {
    check_capacity(
        frame,
        &message.envelope(),
        state,
        &Signature(false),
        &|_| Ok(CERTIFY_OUTPUT.to_vec()),
    )
}

fn first_frame() -> u64 {
    1499 * quil_types::consensus::epoch_length_frames() + 20
}

fn over_cap(error: QuilError) -> bool {
    error.to_string().contains("certified sectors")
}

#[test]
fn capacity_precommit_is_refused_at_the_cap() {
    gates(true);
    let state = state();
    let frame = first_frame();
    let (full, _) = member_at(&state, 11, 2, 136);
    let (under, _) = member_at(&state, 12, 2, 135);
    let (more_seats, _) = member_at(&state, 13, 3, 136);
    let (seatless, _) = member_at(&state, 14, 0, 8);
    let id = [1; 32];
    let refused = precommit(&state, &precommit_for(full, id, 32, frame), frame).unwrap_err();
    assert!(over_cap(refused));
    assert!(pending_certificate(
        &state,
        &full,
        &precommit_for(full, id, 32, frame).certificate,
        1500
    )
    .unwrap()
    .is_none());
    assert_eq!(room(&state, full).held, 136, "a refusal costs no state");
    assert!(over_cap(
        precommit(&state, &precommit_for(seatless, id, 32, frame), frame).unwrap_err()
    ));
    for member in [under, more_seats] {
        let records = precommit(&state, &precommit_for(member, id, 32, frame), frame).unwrap();
        assert_eq!(records.len(), 1, "a precommit does not count as a sector");
    }
    gates(false);
}

#[test]
fn capacity_certificate_is_refused_at_the_cap() {
    gates(true);
    let state = state();
    let frame = first_frame();
    let (member, _) = member_at(&state, 21, 1, 71);
    let first = pending_certification(&state, member, [1; 32], frame);
    let second = pending_certification(&state, member, [2; 32], frame);
    let records = certify(&state, &first, frame + 2).unwrap();
    assert_eq!(records.len(), 2);
    apply(&state, frame + 2, &records).unwrap();
    assert_eq!(room(&state, member).held, 72, "at the cap");
    // Both precommits fitted; the same frame's second certificate does not.
    assert!(over_cap(certify(&state, &second, frame + 2).unwrap_err()));
    assert!(certificate(&state, &member, &[2; 32]).unwrap().is_none());
    assert_eq!(room(&state, member).held, 72);
    gates(false);
}

#[test]
fn capacity_cap_recovers_when_a_seat_opens_room() {
    gates(true);
    let state = state();
    let frame = first_frame();
    let (member, key) = member_at(&state, 22, 1, 72);
    let id = [3; 32];
    assert!(over_cap(
        precommit(&state, &precommit_for(member, id, 32, frame), frame).unwrap_err()
    ));
    set_seat(
        &state,
        member,
        &key,
        &[9; 32],
        super::super::materialize::STATUS_JOINING,
    );
    let message = pending_certification(&state, member, id, frame);
    let records = certify(&state, &message, frame + 2).unwrap();
    apply(&state, frame + 2, &records).unwrap();
    assert_eq!(certificate(&state, &member, &id).unwrap().unwrap().n, 32);
    assert_eq!(room(&state, member).held, 73);
    // A second materialization or a retry counts nothing twice.
    assert!(certify(&state, &message, frame + 3).unwrap().is_empty());
    assert_eq!(room(&state, member).held, 73);
    gates(false);
}

#[test]
fn capacity_counts_held_seats_and_a_shrunk_member_keeps_its_sectors() {
    use super::super::materialize as m;
    gates(true);
    let state = state();
    let frame = first_frame();
    let (member, key) = member_with_key(&state, 31);
    for (tag, status) in [
        (1, m::STATUS_ACTIVE),
        (2, m::STATUS_JOINING),
        (3, m::STATUS_PAUSED),
        (4, m::STATUS_LEAVING),
        (5, 4), // rejected
        (6, 5), // kicked
        (7, m::STATUS_HISTORIC),
    ] {
        set_seat(&state, member, &key, &[tag; 32], status);
    }
    hold(&state, member, 250);
    assert_eq!(room(&state, member).seats, 4);
    assert_eq!(room(&state, member).cap(), 264);
    // Its reassignment ends a seat: 200 are allowed, 250 stay held.
    set_seat(&state, member, &key, &[1; 32], m::STATUS_HISTORIC);
    assert_eq!(room(&state, member).cap(), 200);
    let new = precommit_for(member, [8; 32], 32, frame);
    assert!(over_cap(precommit(&state, &new, frame).unwrap_err()));
    // Its certified sector serves on: no new certificate, nothing counted.
    let (root, fresh, _, _) = fixture(member);
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
    let mut known = precommit_for(member, root.sector, 32, frame);
    known.certificate = cert;
    assert!(precommit(&state, &known, frame).unwrap().is_empty());
    let claim = claim(member, root);
    let bytes = prove(
        &claim,
        &[SeatWitness {
            seals: vec![fresh],
            certificates: vec![Vec::new()],
            opened: Vec::new(),
        }],
    )
    .unwrap();
    let records = check(&state, &claim, &bytes).unwrap();
    assert_eq!(records.len(), 1, "only the epoch's usage record");
    assert_eq!(room(&state, member).held, 250);
    // A merge back reactivates the seat, and room returns.
    set_seat(&state, member, &key, &[1; 32], m::STATUS_ACTIVE);
    assert_eq!(precommit(&state, &new, frame).unwrap().len(), 1);
    gates(false);
}

fn fresh_epoch_proof(member: [u8; 32]) -> (EpochClaim, Vec<u8>, sector::Certificate) {
    let (root, fresh, plain, _) = fixture(member);
    let cert = prove_certificate(&member, b"leaf", 1500, 32, &root, b"beacon", &plain).unwrap();
    let claim = claim(member, root);
    let bytes = prove(
        &claim,
        &[SeatWitness {
            seals: vec![fresh],
            certificates: vec![cert],
            opened: Vec::new(),
        }],
    )
    .unwrap();
    (claim, bytes, root.certificate(32))
}

#[test]
fn epoch_proof_fresh_certificates_count_against_the_cap() {
    gates(true);
    let state = state();
    let (member, _) = member_at(&state, 41, 0, 8);
    let (claim, bytes, cert) = fresh_epoch_proof(member);
    let refused = check(&state, &claim, &bytes).unwrap_err();
    assert!(refused.contains("certified sectors"), "{refused}");
    hold(&state, member, 7);
    let records = check(&state, &claim, &bytes).unwrap();
    assert_eq!(records.len(), 3, "certificate, count and usage");
    apply(&state, 2, &records).unwrap();
    assert_eq!(
        certificate(&state, &member, &cert.sector).unwrap(),
        Some(cert)
    );
    assert_eq!(room(&state, member).held, 8);
    gates(false);
}

#[test]
fn epoch_proof_fresh_certificates_keep_the_floor() {
    gates(true);
    let state = state();
    let (member, _) = member_at(&state, 42, 1, 0);
    let (claim, bytes, _) = fresh_epoch_proof(member);
    quil_types::consensus::set_min_sector_nodes_for_thread(Some(64));
    let refused = check(&state, &claim, &bytes).unwrap_err();
    assert!(refused.contains("64-node floor"), "{refused}");
    gates(false);
}

#[test]
fn capacity_floor_holds_at_the_proposed_value() {
    gates(true);
    quil_types::consensus::set_min_sector_nodes_for_thread(Some(
        quil_types::consensus::MIN_SECTOR_NODES,
    ));
    let state = state();
    let frame = first_frame();
    let (member, _) = member_at(&state, 43, 1, 0);
    let below = quil_types::consensus::MIN_SECTOR_NODES / 2;
    let refused = precommit(&state, &precommit_for(member, [1; 32], below, frame), frame);
    assert!(refused.unwrap_err().to_string().contains("floor"));
    let at = quil_types::consensus::MIN_SECTOR_NODES;
    assert_eq!(
        precommit(&state, &precommit_for(member, [1; 32], at, frame), frame)
            .unwrap()
            .len(),
        1
    );
    gates(false);
}

/// Sectors a shard needs, by the sizing model of the storage snapshot's
/// mainnet test: live bytes plus index, split into 2^24-node leaves 3/4 full.
fn shard_sectors(live: u64, records: u64) -> u64 {
    let model = live + 60 * records + 120;
    model
        .div_ceil((1u64 << 24) * 30 * 3 / 4)
        .next_power_of_two()
}

#[test]
fn capacity_cap_covers_the_largest_mainnet_members() {
    use quil_types::consensus::max_certified_sectors;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-data/storage-mainnet-2026-11-04.json"
    )))
    .unwrap();
    let shards = fixture["shards"].as_array().unwrap();
    let mut needs: Vec<(u64, Vec<u8>)> = shards
        .iter()
        .map(|shard| {
            (
                shard_sectors(
                    shard["live_bytes"].as_u64().unwrap(),
                    shard["vertex_records"].as_u64().unwrap(),
                ),
                hex::decode(shard["filter"].as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    needs.sort_by_key(|need| std::cmp::Reverse(need.0));
    let per_seat = max_certified_sectors(1) - max_certified_sectors(0);
    assert_eq!(needs[0].0, 16, "the fixture's largest shard");
    assert!(needs[0].0 * 4 <= per_seat, "a seat has room to grow 4x");
    let merge_limit = shard_sectors(16 << 30, (16u64 << 30) * 5_033_438 / 3_344_541_858);
    assert_eq!(merge_limit, 64, "a shard at the merge size limit");
    assert!(merge_limit <= per_seat);
    // Every member profile, if its seats were the largest shards.
    let mut largest = 0u64;
    for prover in fixture["provers"].as_array().unwrap() {
        let seats = prover["seats"].as_u64().unwrap();
        let need: u64 = needs.iter().take(seats as usize).map(|n| n.0).sum();
        assert!(
            need <= max_certified_sectors(seats),
            "{seats} seats need {need}"
        );
        largest = largest.max(seats);
    }
    assert_eq!(largest, 109);
    let need: u64 = needs.iter().map(|n| n.0).sum();
    assert_eq!(need, 395);

    // The largest profile, on its real shards, against a one-seat member.
    gates(true);
    let state = state();
    let frame = first_frame();
    let (big, key) = member_with_key(&state, 51);
    for (_, filter) in needs.iter().take(largest as usize) {
        set_seat(
            &state,
            big,
            &key,
            filter,
            super::super::materialize::STATUS_ACTIVE,
        );
    }
    let (small, _) = member_at(&state, 52, 1, 71);
    assert_eq!(room(&state, big).seats, 109);
    assert_eq!(room(&state, big).cap(), 6984);
    // Today's need is well under its cap, and the cap still bites.
    hold(&state, big, need);
    let id = [1; 32];
    assert_eq!(
        precommit(&state, &precommit_for(big, id, 32, frame), frame)
            .unwrap()
            .len(),
        1
    );
    hold(&state, big, 6983);
    let message = pending_certification(&state, big, id, frame);
    let records = certify(&state, &message, frame + 2).unwrap();
    apply(&state, frame + 2, &records).unwrap();
    assert_eq!(room(&state, big).held, 6984);
    assert!(over_cap(
        precommit(&state, &precommit_for(big, [2; 32], 32, frame), frame).unwrap_err()
    ));
    // Counts are per member: the large member's says nothing of the small one's.
    let message = pending_certification(&state, small, id, frame);
    let records = certify(&state, &message, frame + 2).unwrap();
    apply(&state, frame + 2, &records).unwrap();
    assert_eq!(room(&state, small).held, 72);
    assert!(over_cap(
        precommit(&state, &precommit_for(small, [2; 32], 32, frame), frame).unwrap_err()
    ));
    gates(false);
}

fn registered_member(state: &HypergraphState) -> [u8; 32] {
    member_with_key(state, 7).0
}

fn labelled_sector(member: &[u8; 32], id: [u8; 32], n: u64) -> (sector::Certificate, Vec<u8>) {
    let params = quil_crypto::sdr::SdrParams::default();
    let (last, columns) = proof::label_leaf(
        n,
        &quil_crypto::sdr::stable_replica_key(member, &id),
        &params,
        &mut |_, _| {},
    );
    let height = proof::seal_cap_height(n);
    let labels = proof::MerkleCap::from_digests(&last, height);
    let columns = proof::MerkleCap::from_digests(&columns, height).commitment(proof::Tree::Column);
    (
        sector::Certificate {
            profile: quil_types::consensus::StorageSealProfile::Eleven,
            sector: id,
            n,
            columns,
            labels: labels.commitment(proof::Tree::Replica),
        },
        hash::digests_to_bytes(&last),
    )
}

/// Precommit at `frame` and certify at `frame + 2`, through the real checks.
/// `controls` also shows the slot refuses while pending and the STARK verifier
/// refuses a changed proof, so an acceptance here means the checks ran.
fn precommit_and_certify(
    state: &HypergraphState,
    member: [u8; 32],
    id: [u8; 32],
    n: u64,
    frame: u64,
    controls: bool,
) -> std::result::Result<sector::Certificate, String> {
    let output = vec![9; 516];
    let unavailable = |_| Err(QuilError::ExecutionUnavailable("no beacon".into()));
    let (cert, last) = labelled_sector(&member, id, n);
    let message = CapacityMessage {
        member,
        epoch: 1500,
        certificate: cert,
        signed_at: frame,
        signature: vec![1; 666],
        proof: Vec::new(),
    };
    let records = check_capacity(
        frame,
        &message.envelope(),
        state,
        &Signature(true),
        &unavailable,
    )
    .map_err(|e| format!("precommit refused: {e}"))?;
    assert_eq!(records.len(), 1, "harness: one pending record");
    apply(state, frame, &records).unwrap();
    if controls {
        let mut collide = message.clone();
        collide.certificate.sector[1] = 0xFF;
        assert!(
            check_capacity(
                frame,
                &collide.envelope(),
                state,
                &Signature(true),
                &unavailable
            )
            .is_err(),
            "harness: an occupied pending slot was not refused"
        );
    }
    let beacon = quil_crypto::porep::derive_storage_beacon(frame + 1, &output);
    let root = message.root();
    let challenge = sector::certificate_beacon(&member, &id, 1500, n, &root, &beacon);
    let statement = proof::SealStatement {
        member: &member,
        leaf_id: &id,
        epoch: 1500,
        n,
        registered: cert.registered().unwrap(),
        beacon: &challenge,
    };
    let plain = proof::prove_seal(
        &last,
        &statement,
        &quil_crypto::sdr::SdrParams::default(),
        sector::CHALLENGES,
    )
    .map_err(|e| format!("seal not provable: {e}"))?;
    let bytes = prove_certificate(&member, &id, 1500, n, &root, &beacon, &plain)
        .map_err(|e| format!("certificate not provable: {e}"))?;
    let mut certification = message.clone();
    certification.signature.clear();
    certification.proof = bytes;
    if controls {
        let mut forged = certification.clone();
        let middle = forged.proof.len() / 2;
        forged.proof[middle] ^= 1;
        assert!(
            check_capacity(
                frame + 2,
                &forged.envelope(),
                state,
                &Signature(false),
                &|_| Ok(output.clone())
            )
            .is_err(),
            "harness: a changed certificate proof was accepted"
        );
    }
    let accepted = check_capacity(
        frame + 2,
        &certification.envelope(),
        state,
        &Signature(false),
        &|_| Ok(output.clone()),
    )
    .map_err(|e| format!("certificate refused: {e}"))?;
    assert_eq!(accepted.len(), 2, "harness: certificate and count records");
    apply(state, frame + 2, &accepted).unwrap();
    Ok(cert)
}

#[test]
fn capacity_sectors_have_a_per_member_bound() {
    const TRIED: u8 = 20;
    const RING: usize = 16;
    gates(true);
    let state = state();
    let member = registered_member(&state);
    let first = 1499 * quil_types::consensus::epoch_length_frames() + 20;
    let id = |i: u8| {
        let mut id = [5; 32];
        id[1] = i;
        id
    };
    let mut frame = first;
    let mut accepted = 0usize;
    let mut refusal = String::from("none");
    for i in 0..TRIED {
        match precommit_and_certify(&state, member, id(i), 32, frame, i == 0) {
            Ok(_) => accepted += 1,
            Err(error) => {
                refusal = error;
                break;
            }
        }
        frame += 3;
    }
    let held = (0..accepted as u8)
        .filter(|i| certificate(&state, &member, &id(*i)).unwrap().is_some())
        .count();
    gates(false);
    assert!(
        accepted < RING,
        "no per-member bound: one member certified {accepted} of {TRIED} sectors through \
         one pending slot in {} frames of one epoch, {held} records held, refusal: {refusal}",
        frame - first
    );
}

#[test]
fn capacity_certificate_floor_is_useful() {
    gates(true);
    let state = state();
    let member = registered_member(&state);
    let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
    let outcome = precommit_and_certify(&state, member, [6; 32], 2, frame, false);
    let held = certificate(&state, &member, &[6; 32]).unwrap();
    gates(false);
    assert!(
        outcome.is_err() && held.is_none(),
        "no capacity floor: a sector of n=2 nodes was certified, outcome {outcome:?}"
    );
}

#[test]
fn new_profiles_are_gated_and_known_legacy_capacity_survives_profile_changes() {
    gates(true);
    let member = [13; 32];
    for profile in [sector::Profile::Two, sector::Profile::Three] {
        quil_types::consensus::set_storage_seal_profile_for_thread(Some(sector::Profile::Eleven));
        let (root, fresh, plain, _) = fixture_for_profile(member, profile);
        let claim = claim(member, root);
        let certificate =
            prove_certificate(&member, b"leaf", 1500, 32, &root, b"beacon", &plain).unwrap();
        let witness = SeatWitness {
            certificates: vec![certificate],
            seals: vec![fresh],
            opened: vec![],
        };
        let bytes = prove(&claim, &[witness]).unwrap();
        assert!(verify(&claim, &bytes, &|_| Ok(None))
            .unwrap_err()
            .contains("not activated"));
        quil_types::consensus::set_storage_seal_profile_for_thread(Some(profile));
        assert_eq!(
            verify(&claim, &bytes, &|_| Ok(None)).unwrap(),
            vec![root.certificate(32)]
        );
        quil_types::consensus::set_storage_seal_profile_for_thread(None);
    }
    let (root, fresh, _, _) = fixture(member);
    let claim = claim(member, root);
    let bytes = prove(
        &claim,
        &[SeatWitness {
            certificates: vec![vec![]],
            seals: vec![fresh],
            opened: vec![],
        }],
    )
    .unwrap();
    quil_types::consensus::set_storage_seal_profile_for_thread(Some(sector::Profile::Three));
    assert!(verify(&claim, &bytes, &|_| Ok(Some(root.certificate(32))))
        .unwrap()
        .is_empty());
    quil_types::consensus::set_storage_seal_profile_for_thread(None);
    gates(false);
}

#[test]
fn mainnet_1444_precommits_use_three_layers_within_the_coordinated_warmup() {
    use quil_types::consensus::{
        set_min_sector_nodes_for_thread, set_persistent_storage_epoch_for_thread,
        set_storage_seal_profile_for_thread, EPOCH_LENGTH_FRAMES,
    };
    set_persistent_storage_epoch_for_thread(None);
    set_storage_seal_profile_for_thread(None);
    set_min_sector_nodes_for_thread(Some(32));
    let state = state();
    let member = registered_member(&state);
    let (root, _, _, _) = fixture_for_profile(member, sector::Profile::Three);
    let mut message = CapacityMessage {
        member,
        epoch: 1444,
        certificate: root.certificate(32),
        signed_at: 0,
        signature: vec![1; 666],
        proof: Vec::new(),
    };
    let before = 1411 * EPOCH_LENGTH_FRAMES + 20;
    message.signed_at = before;
    assert!(check_capacity(
        before,
        &message.envelope(),
        &state,
        &Signature(true),
        &|_| unreachable!()
    )
    .unwrap_err()
    .to_string()
    .contains("warmup"));
    let warmup = 1412 * EPOCH_LENGTH_FRAMES + 20;
    message.signed_at = warmup;
    assert_eq!(
        check_capacity(
            warmup,
            &message.envelope(),
            &state,
            &Signature(true),
            &|_| unreachable!()
        )
        .unwrap()
        .len(),
        1
    );
    message.epoch = 1443;
    assert!(check_capacity(
        warmup,
        &message.envelope(),
        &state,
        &Signature(true),
        &|_| unreachable!()
    )
    .unwrap_err()
    .to_string()
    .contains("inactive"));
    message.epoch = 1444;
    message.certificate.profile = sector::Profile::Two;
    assert!(check_capacity(
        warmup,
        &message.envelope(),
        &state,
        &Signature(true),
        &|_| unreachable!()
    )
    .unwrap_err()
    .to_string()
    .contains("not activated"));
    set_min_sector_nodes_for_thread(None);
}
