//! Real Falcon certificates and RocksDB authorization through the production
//! frame validator, archive ingress and global FrameHeader admission paths.
//! Empty app frames use test inclusion/execution dependencies, not token proofs.

use std::{collections::HashMap, sync::Arc};

use num_bigint::BigInt;
use quil_cw_consensus::{
    _consensus::{
        simplex::{
            scheme::Namespace,
            types::{Finalization, Proposal, Subject},
        },
        types::{Epoch, Round, View},
    },
    _crypto::{sha256::Digest, Signer as _},
    _utils::{ordered::Set, N3f1},
    app_cert::{encode_finalization, wrap_cert_for_header},
    falcon_base::FalconPrivateKey,
    falcon_scheme::Generic,
    falcon_simplex::SimplexFalconScheme,
    handoff::{Checkpoint, Seal, Session},
};
use quil_engine::{
    archive_ingest::ArchiveAppShardIngest, frame_validator::BlsAppFrameValidator,
    test_support::TestProverRegistry,
};
use quil_execution::{
    global_intrinsic::{
        frame_header::FrameHeader as CanonicalHeader,
        handoff::{self, CertificateSubmission, DesiredCommittee},
        intrinsic::GlobalIntrinsic,
        prover_shard_update::verify_frame_header_in_state,
    },
    hypergraph_state::HypergraphState,
};
use quil_types::{
    consensus::{
        AppFrameValidator as _, ProverAllocation, ProverInfo, ProverRegistry as _, ProverStatus,
        RewardIssuance,
    },
    crypto::Signer as _,
    error::Result,
    proto::{
        global::{AppShardFrame, FrameHeader},
        keys::Bls48581AggregateSignature,
    },
};

fn keys() -> Vec<FalconPrivateKey> {
    (0..4)
        .map(|_| {
            let key = quil_crypto::FalconSigner::generate();
            FalconPrivateKey::from_bytes(key.private_key(), key.public_key()).unwrap()
        })
        .collect()
}

fn session(keys: &[FalconPrivateKey], filter: Vec<u8>) -> Session {
    let mut members: Vec<_> = keys
        .iter()
        .map(|key| key.public_key().as_ref().to_vec())
        .collect();
    members.sort();
    Session {
        chain_id: [0x21; 32],
        filter,
        generation: 1,
        genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
        base_frame: 0,
        authorization: [0x34; 32],
        members,
    }
}

fn sign(
    session: &Session,
    keys: &[FalconPrivateKey],
    view: u64,
    parent: u64,
    digest: [u8; 32],
) -> Vec<u8> {
    let proposal = Proposal::new(
        Round::new(Epoch::new(session.generation), View::new(view)),
        View::new(parent),
        Digest(digest),
    );
    let participants: Set<_> = keys
        .iter()
        .map(|key| key.public_key())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let schemes: Vec<Generic<Namespace>> = keys
        .iter()
        .cloned()
        .map(|key| {
            Generic::signer(&session.namespace().unwrap(), participants.clone(), key).unwrap()
        })
        .collect();
    let votes: Vec<_> = schemes[..3]
        .iter()
        .map(|scheme| {
            scheme
                .sign::<SimplexFalconScheme, Digest>(Subject::Finalize {
                    proposal: &proposal,
                })
                .unwrap()
        })
        .collect();
    let certificate = schemes[0]
        .assemble::<SimplexFalconScheme, _, N3f1>(votes)
        .unwrap();
    encode_finalization(&Finalization {
        proposal,
        certificate,
    })
}

fn stamp(header: &mut FrameHeader) {
    header.output = quil_crypto::porep::deterministic_app_frame_output(
        &header.parent_selector,
        &header.requests_root,
        &header.state_roots,
        &quil_crypto::porep::derive_storage_beacon(0, &[]),
        header.frame_number,
        header.rank,
        &header.prover,
        header.difficulty,
        header.fee_multiplier_vote,
        header.timestamp,
        &header.storage_attestation_root,
        0,
        &header.settlements,
        &header.accumulator,
        &header.spends,
    );
}

fn certify(
    header: &mut FrameHeader,
    session: &Session,
    keys: &[FalconPrivateKey],
    parent_view: u64,
) {
    stamp(header);
    let certificate = sign(
        session,
        keys,
        header.rank,
        parent_view,
        quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap(),
    );
    header.public_key_signature_bls48581 = Some(Bls48581AggregateSignature {
        signature: wrap_cert_for_header(&certificate),
        ..Default::default()
    });
}

fn first_frame(session: &Session, keys: &[FalconPrivateKey]) -> AppShardFrame {
    let mut header = FrameHeader {
        address: session.filter.clone(),
        frame_number: session.base_frame + 1,
        rank: 5,
        difficulty: 1,
        parent_selector: session.genesis.to_vec(),
        requests_root: vec![0; 32],
        state_roots: vec![vec![0; 32]; 4],
        ..Default::default()
    };
    certify(&mut header, session, keys, 0);
    AppShardFrame {
        header: Some(header),
        ..Default::default()
    }
}

fn canonical(frame: &AppShardFrame) -> CanonicalHeader {
    let h = frame.header.as_ref().unwrap();
    CanonicalHeader {
        address: h.address.clone(),
        frame_number: h.frame_number,
        rank: h.rank,
        timestamp: h.timestamp,
        difficulty: h.difficulty,
        output: h.output.clone(),
        parent_selector: h.parent_selector.clone(),
        requests_root: h.requests_root.clone(),
        state_roots: h.state_roots.clone(),
        prover: h.prover.clone(),
        public_key_signature_bls48581: h
            .public_key_signature_bls48581
            .as_ref()
            .map_or_else(Vec::new, |s| s.signature.clone()),
        ..Default::default()
    }
}

fn commit(state: &HypergraphState, number: u64) {
    state.commit().unwrap();
    state.abort();
    state
        .crdt()
        .commit_with_global_cursor(
            number,
            &quil_store::encoding::global_materialized_cursor_key(),
        )
        .unwrap();
}

struct ZeroRewards;
impl RewardIssuance for ZeroRewards {
    fn calculate(
        &self,
        _: u64,
        _: u64,
        _: u64,
        provers: &[HashMap<String, ProverAllocation>],
    ) -> Result<Vec<BigInt>> {
        Ok(vec![BigInt::from(0); provers.len()])
    }
}

struct Fixture {
    _db: quil_store::RocksDb,
    store: Arc<quil_store::RocksHypergraphStore>,
    state: HypergraphState,
    registry: Arc<TestProverRegistry>,
    clock: Arc<quil_store::RocksClockStore>,
    inclusion: Arc<quil_hypergraph::testing::StubProver>,
    prover: Arc<quil_crypto::WesolowskiFrameProver>,
}

impl Fixture {
    fn new(session: &Session) -> Self {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let inclusion = Arc::new(quil_hypergraph::testing::StubProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            inclusion.clone(),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        let state = HypergraphState::new(crdt);
        commit(&state, 1);
        let registry = Arc::new(TestProverRegistry::with_provers(
            session
                .members
                .iter()
                .map(|key| ProverInfo {
                    address: quil_crypto::poseidon::hash_bytes_to_32(key)
                        .unwrap()
                        .to_vec(),
                    public_key: key.clone(),
                    // Historical members need not be in today's active set.
                    status: ProverStatus::Historic,
                    kick_frame_number: 0,
                    allocations: Vec::new(),
                    available_storage: 0,
                    seniority: 0,
                    delegate_address: Vec::new(),
                })
                .collect(),
        ));
        Self {
            clock: Arc::new(quil_store::RocksClockStore::new(db.inner())),
            _db: db,
            state,
            store,
            registry,
            inclusion,
            prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        }
    }

    fn validator(&self) -> BlsAppFrameValidator {
        BlsAppFrameValidator::new(
            self.registry.clone(),
            Arc::new(quil_crypto::FalconKeyConstructor),
            self.prover.clone(),
        )
        .with_clock_store(self.clock.clone())
        .with_handoff_authority(self.state.crdt().clone())
    }

    fn intrinsic(&self) -> GlobalIntrinsic {
        GlobalIntrinsic::new_with_stores(
            Arc::new(quil_execution::testing::NoopKeyManager),
            Some(self.prover.clone()),
            Some(self.clock.clone()),
            None,
            None,
        )
        .with_kick_verify_deps(
            Arc::new(quil_crypto::FalconKeyConstructor),
            self.state.crdt().clone(),
            self.inclusion.clone(),
        )
        .with_frame_header_deps(self.registry.clone(), Arc::new(ZeroRewards))
    }

    fn archive(&self) -> ArchiveAppShardIngest {
        let crypto = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
            self.inclusion.clone(),
            crypto.key_manager,
            self.state.crdt().clone(),
            crypto.circuit_compiler,
            self.clock.clone(),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            false,
        ));
        ArchiveAppShardIngest::new(
            self.registry.clone(),
            Arc::new(quil_crypto::FalconKeyConstructor),
            self.prover.clone(),
            manager,
            self.inclusion.clone(),
            self.state.crdt().clone(),
            self.clock.clone(),
        )
    }

    fn cursor(&self, filter: &[u8]) -> u64 {
        self.state
            .crdt()
            .read_frame_cursor(&quil_store::encoding::consensus_materialized_cursor_key(
                filter,
            ))
            .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn historical_certificate_reaches_archive_and_global_admission_after_committee_rotation() {
    let keys = keys();
    let original = session(&keys, vec![0x61; 32]);
    let fixture = Fixture::new(&original);
    let frame = first_frame(&original, &keys);
    let validator = fixture.validator();
    let intrinsic = fixture.intrinsic();
    let op = canonical(&frame);
    let wire = op.to_canonical_bytes().unwrap();
    assert!(validator.validate(&frame).is_err());
    handoff::initialize(&fixture.state, 2, &original).unwrap();
    assert!(
        validator.validate(&frame).is_err(),
        "uncommitted authorization cannot admit a network frame"
    );
    fixture.state.commit().unwrap();
    fixture.state.abort();
    fixture.store.fail_commit_for_test(true);
    assert!(fixture
        .state
        .crdt()
        .commit_with_global_cursor(2, &quil_store::encoding::global_materialized_cursor_key())
        .is_err());
    assert!(validator.validate(&frame).is_err());
    fixture.store.fail_commit_for_test(false);
    fixture
        .state
        .crdt()
        .commit_with_global_cursor(2, &quil_store::encoding::global_materialized_cursor_key())
        .unwrap();
    assert!(validator.validate(&frame).unwrap());
    assert!(intrinsic.validate(3, &wire, None, None).unwrap());
    assert!(fixture
        .registry
        .get_active_provers(&original.filter, 3)
        .unwrap()
        .is_empty());

    let next_keys = self::keys();
    let desired = session(&next_keys, original.filter.clone());
    let request = handoff::schedule(
        &fixture.state,
        3,
        vec![original.filter.clone()],
        vec![DesiredCommittee {
            filter: original.filter.clone(),
            members: desired.members,
        }],
    )
    .unwrap();
    let seal = Seal {
        request: request.id().unwrap(),
        session: original.id().unwrap(),
        view: 8,
        checkpoint: Checkpoint {
            frame: 1,
            view: 5,
            digest: quil_crypto::poseidon::hash_bytes_to_32(&op.output).unwrap(),
            state_roots: [[0; 32]; 4],
            history_root: [0x66; 32],
        },
    };
    let submission = CertificateSubmission {
        certificate: sign(&original, &keys, 8, 5, seal.digest()),
        seal,
    };
    // GLOBAL executed the source through its checkpoint.
    handoff::record_session_tip(&fixture.state, 4, &submission.seal.session, &submission.seal.checkpoint).unwrap();
    assert!(handoff::apply_submission(&fixture.state, 4, &submission).unwrap());
    commit(&fixture.state, 4);
    assert_eq!(
        handoff::head(&fixture.state, &original.filter)
            .unwrap()
            .unwrap()
            .generation,
        2
    );
    assert!(validator.validate(&frame).unwrap());
    assert!(intrinsic.validate(5, &wire, None, None).unwrap());
    let mut beyond = frame.clone();
    let h = beyond.header.as_mut().unwrap();
    h.frame_number = 2;
    h.rank = 7;
    h.parent_selector = submission.seal.checkpoint.digest.to_vec();
    certify(h, &original, &keys, 5);
    assert!(validator.validate(&beyond).is_err());
    let beyond_wire = canonical(&beyond).to_canonical_bytes().unwrap();
    assert!(intrinsic.validate(5, &beyond_wire, None, None).is_err());
    assert!(intrinsic
        .invoke_step(5, &beyond_wire, &fixture.state)
        .is_err());
    let (members, bitmap) = verify_frame_header_in_state(
        &fixture.state,
        &op,
        fixture.prover.as_ref(),
        &quil_crypto::FalconKeyConstructor,
        fixture.registry.as_ref(),
        5,
        5,
    )
    .unwrap();
    assert_eq!(
        members
            .iter()
            .map(|p| p.public_key.clone())
            .collect::<Vec<_>>(),
        original.members
    );
    assert_eq!(quil_consensus::bitmask::set_bit_indices(&bitmap).count(), 3);

    let mut archive = fixture.archive();
    archive.ingest(&prost::Message::encode_to_vec(&frame));
    assert_eq!(
        fixture.cursor(&original.filter),
        1,
        "archive executes a certified historical frame despite a different current committee"
    );
    archive.ingest(&prost::Message::encode_to_vec(&frame));
    assert_eq!(fixture.cursor(&original.filter), 1);
    // The real archive materializer persisted the outgoing-history records.
    let snapshot = fixture
        .state
        .crdt()
        .capture_committed_shard(&original.filter)
        .unwrap();
    assert!(handoff::history::root(snapshot.records.as_ref(), &original, 1).is_ok());
    fixture.registry.set_provers(Vec::new());
    assert!(
        validator.validate(&frame).unwrap(),
        "frame authentication needs the authorized keys, not live metadata"
    );
    assert!(
        intrinsic.validate(5, &wire, None, None).is_err(),
        "reward attribution must not silently omit missing members"
    );
}

/// A sealed session's last headers can miss their lockstep window for good,
/// and GLOBAL accepts a seal only at its executed tip (#699). The seal brings
/// them: GLOBAL checks each against the session and executes it, from the
/// drain frame, before accepting the seal. A gap, a forged or foreign header,
/// or a run not ending at the checkpoint is refused, and before the drain
/// frame so is any drain.
#[test]
fn a_seal_brings_the_drain_headers_global_never_executed() {
    let keys = keys();
    let source = session(&keys, vec![0x62; 32]);
    let fixture = Fixture::new(&source);
    let intrinsic = fixture.intrinsic();
    handoff::initialize(&fixture.state, 2, &source).unwrap();
    commit(&fixture.state, 2);

    // Frames 1–3 at views 5, 7, 9, each extending the last.
    let mut frames = vec![first_frame(&source, &keys)];
    for (number, view, parent_view) in [(2u64, 7u64, 5u64), (3, 9, 7)] {
        let previous = frames.last().unwrap().header.as_ref().unwrap();
        let mut header = FrameHeader {
            address: source.filter.clone(),
            frame_number: number,
            rank: view,
            difficulty: 1,
            parent_selector: quil_crypto::poseidon::hash_bytes_to_32(&previous.output).unwrap().to_vec(),
            requests_root: vec![0; 32],
            state_roots: vec![vec![0; 32]; 4],
            ..Default::default()
        };
        certify(&mut header, &source, &keys, parent_view);
        frames.push(AppShardFrame { header: Some(header), ..Default::default() });
    }
    let wire = |frame: &AppShardFrame| canonical(frame).to_canonical_bytes().unwrap();
    // GLOBAL executed frame 1 only; 2 and 3 missed their window.
    intrinsic.invoke_step(3, &wire(&frames[0]), &fixture.state).unwrap();
    commit(&fixture.state, 3);
    assert_eq!(handoff::session_tip(&fixture.state, &source.id().unwrap()).unwrap().unwrap().frame, 1);

    let next_keys = self::keys();
    let request = handoff::schedule(
        &fixture.state, 4, vec![source.filter.clone()],
        vec![DesiredCommittee { filter: source.filter.clone(), members: session(&next_keys, source.filter.clone()).members }],
    ).unwrap();
    commit(&fixture.state, 4);
    let last = canonical(&frames[2]);
    let seal = Seal {
        request: request.id().unwrap(),
        session: source.id().unwrap(),
        view: 11,
        checkpoint: Checkpoint {
            frame: 3,
            view: 9,
            digest: quil_crypto::poseidon::hash_bytes_to_32(&last.output).unwrap(),
            state_roots: [[0; 32]; 4],
            history_root: [0x66; 32],
        },
    };
    let submission = CertificateSubmission { certificate: sign(&source, &keys, 11, 9, seal.digest()), seal };
    let sealed = |drain: Vec<Vec<u8>>| handoff::SealSubmission { submission: submission.clone(), drain }
        .to_canonical_bytes().unwrap();
    let refused = |bytes: &[u8], frame: u64, expect: &str| {
        let error = intrinsic.invoke_step(frame, bytes, &fixture.state).unwrap_err();
        assert!(error.to_string().contains(expect), "expected {expect:?}, got {error}");
        assert!(intrinsic.validate(frame, bytes, None, None).is_err());
    };

    // The seal alone waits for frames GLOBAL never executed.
    refused(&submission.to_canonical_bytes().unwrap(), 5, "not yet executed");
    // Before the drain frame a drain is refused, as an older build would.
    handoff::set_seal_drain_frame_for_thread(Some(6));
    refused(&sealed(vec![wire(&frames[1]), wire(&frames[2])]), 5, "not active");

    // Malformed drains, from the drain frame on.
    refused(&sealed(vec![wire(&frames[2])]), 6, "gap after the executed tip");
    refused(&sealed(vec![wire(&frames[1])]), 6, "do not end at the sealed checkpoint");
    refused(&sealed(vec![wire(&frames[0]), wire(&frames[2])]), 6, "not consecutive");
    let mut forged = canonical(&frames[1]);
    forged.spends = vec![1, 2, 3];
    refused(&sealed(vec![forged.to_canonical_bytes().unwrap(), wire(&frames[2])]), 6, "");
    let other = session(&keys, vec![0x63; 32]);
    let mut foreign = frames[1].clone();
    foreign.header.as_mut().unwrap().address = other.filter.clone();
    refused(&sealed(vec![wire(&foreign), wire(&frames[2])]), 6, "another shard");
    assert_eq!(handoff::session_tip(&fixture.state, &source.id().unwrap()).unwrap().unwrap().frame, 1,
        "a refused drain executes nothing");

    // The full drain, an already-executed header included, is accepted.
    let drain = sealed(vec![wire(&frames[0]), wire(&frames[1]), wire(&frames[2])]);
    assert!(intrinsic.validate(6, &drain, None, None).unwrap());
    intrinsic.invoke_step(6, &drain, &fixture.state).unwrap();
    commit(&fixture.state, 6);
    let tip = handoff::session_tip(&fixture.state, &source.id().unwrap()).unwrap().unwrap();
    assert_eq!((tip.frame, tip.view, tip.digest), (3, 9, submission.seal.checkpoint.digest));
    assert_eq!(handoff::head(&fixture.state, &source.filter).unwrap().unwrap().generation, 2,
        "the seal authorized the successor");
    handoff::set_seal_drain_frame_for_thread(None);
}

#[test]
fn production_validators_reject_namespace_downgrades_and_unauthorized_coordinates() {
    let keys = keys();
    let original = session(&keys, vec![0x62; 32]);
    let fixture = Fixture::new(&original);
    handoff::initialize(&fixture.state, 2, &original).unwrap();
    commit(&fixture.state, 2);
    let validator = fixture.validator();
    let intrinsic = fixture.intrinsic();
    let good = first_frame(&original, &keys);
    assert!(validator.validate(&good).unwrap());
    let no_authority = BlsAppFrameValidator::new(
        fixture.registry.clone(),
        Arc::new(quil_crypto::FalconKeyConstructor),
        fixture.prover.clone(),
    );
    assert!(no_authority.validate(&good).is_err());
    let mut bad = Vec::new();
    let mut legacy = original.clone();
    legacy.generation = 0;
    bad.push(first_frame(&legacy, &keys));
    let mut unknown = original.clone();
    unknown.generation = 3;
    bad.push(first_frame(&unknown, &keys));
    let mut other_chain = original.clone();
    other_chain.chain_id[0] ^= 1;
    bad.push(first_frame(&other_chain, &keys));
    // A different filter in the same managed app cannot create a legacy
    // child before the authenticated split authorizes it.
    legacy.filter.extend_from_slice(&[0, 1, 0]);
    bad.push(first_frame(&legacy, &keys));
    let mut wrong_parent = good.clone();
    wrong_parent.header.as_mut().unwrap().parent_selector[0] ^= 1;
    certify(wrong_parent.header.as_mut().unwrap(), &original, &keys, 0);
    bad.push(wrong_parent);
    let mut wrong_height = good.clone();
    wrong_height.header.as_mut().unwrap().frame_number = 2;
    certify(wrong_height.header.as_mut().unwrap(), &original, &keys, 0);
    bad.push(wrong_height);
    let mut wrong_view = good.clone();
    wrong_view.header.as_mut().unwrap().rank = 6;
    stamp(wrong_view.header.as_mut().unwrap());
    let h = wrong_view.header.as_mut().unwrap();
    h.public_key_signature_bls48581.as_mut().unwrap().signature = wrap_cert_for_header(&sign(
        &original,
        &keys,
        5,
        0,
        quil_crypto::poseidon::hash_bytes_to_32(&h.output).unwrap(),
    ));
    bad.push(wrong_view);
    let mut trailing = good.clone();
    trailing
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581
        .as_mut()
        .unwrap()
        .signature
        .push(0);
    bad.push(trailing);
    let mut unsigned_genesis = good.clone();
    let h = unsigned_genesis.header.as_mut().unwrap();
    h.frame_number = 0;
    h.public_key_signature_bls48581 = None;
    stamp(h);
    bad.push(unsigned_genesis);
    for frame in bad {
        assert!(validator.validate(&frame).is_err());
        let wire = canonical(&frame).to_canonical_bytes().unwrap();
        assert!(intrinsic.validate(3, &wire, None, None).is_err());
        assert!(intrinsic.invoke_step(3, &wire, &fixture.state).is_err());
    }
}
