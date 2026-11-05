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

/// Pays nothing, recording the difficulty each calculation was priced at.
#[derive(Default)]
struct DifficultyProbe(std::sync::Mutex<Vec<u64>>);
impl RewardIssuance for DifficultyProbe {
    fn calculate(
        &self,
        difficulty: u64,
        _: u64,
        _: u64,
        provers: &[HashMap<String, ProverAllocation>],
    ) -> Result<Vec<BigInt>> {
        self.0.lock().unwrap().push(difficulty);
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
        self.intrinsic_with(Arc::new(ZeroRewards))
    }

    fn intrinsic_with(&self, issuance: Arc<dyn RewardIssuance>) -> GlobalIntrinsic {
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
        .with_frame_header_deps(self.registry.clone(), issuance)
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
    handoff::record_session_tip(
        &fixture.state,
        4,
        &submission.seal.session,
        &submission.seal.checkpoint,
    )
    .unwrap();
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

/// Frame `number` of `session` at `view`, extending `parent` (certified at
/// `parent_view`), anchored to GLOBAL frame `anchor` whose output is
/// `anchor_output`, certified by `keys` under the session's generation.
#[allow(clippy::too_many_arguments)]
fn anchored_frame(
    session: &Session,
    keys: &[FalconPrivateKey],
    number: u64,
    view: u64,
    parent_view: u64,
    parent: Vec<u8>,
    anchor: u64,
    anchor_output: &[u8],
) -> AppShardFrame {
    let mut header = FrameHeader {
        address: session.filter.clone(),
        frame_number: number,
        rank: view,
        difficulty: 1,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
        global_frame_number: anchor,
        parent_selector: parent,
        requests_root: vec![0; 32],
        state_roots: vec![vec![0; 32]; 4],
        ..Default::default()
    };
    header.output = quil_crypto::porep::deterministic_app_frame_output(
        &header.parent_selector,
        &header.requests_root,
        &header.state_roots,
        &quil_crypto::porep::derive_storage_beacon(anchor, anchor_output),
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
    AppShardFrame {
        header: Some(header),
        ..Default::default()
    }
}

/// The first frame of `session`, anchored as [`anchored_frame`].
fn anchored_first_frame(
    session: &Session,
    keys: &[FalconPrivateKey],
    anchor: u64,
    anchor_output: &[u8],
) -> AppShardFrame {
    let number = session.base_frame + 1;
    anchored_frame(
        session,
        keys,
        number,
        5,
        0,
        session.genesis.to_vec(),
        anchor,
        anchor_output,
    )
}

/// Store GLOBAL frame `number` with `output`, without executing it.
fn store_global_frame(fixture: &Fixture, number: u64, output: &[u8]) {
    store_global_frame_at(fixture, number, output, 0);
}

/// [`store_global_frame`] at `difficulty`.
fn store_global_frame_at(fixture: &Fixture, number: u64, output: &[u8], difficulty: u32) {
    use quil_types::store::ClockStore as _;
    let txn = fixture.clock.new_transaction(false).unwrap();
    fixture
        .clock
        .put_global_clock_frame(
            &quil_types::proto::global::GlobalFrame {
                header: Some(quil_types::proto::global::GlobalFrameHeader {
                    frame_number: number,
                    output: output.to_vec(),
                    difficulty,
                    ..Default::default()
                }),
                requests: Vec::new(),
            },
            txn.as_ref(),
        )
        .unwrap();
    txn.commit().unwrap();
}

// Committee-handoff seal copies. Every member of a closing committee gossips
// the same seal, and any peer can gossip another copy of it: a seal is
// identified by its request and session alone, both public in every copy. A
// GLOBAL leader carries one copy per seal, the one whose drain reaches
// furthest that validates (`order_handoff_copies` in the leader), trying the
// copies in that order.

/// The GLOBAL frame the crowding rigs' leader proposes, on stored frame
/// [`CROWD_FRAME`] - 1; seal drains are active from it.
const CROWD_FRAME: u64 = 6;

/// A structure-only VDF: the rigs check which messages a proposal carries.
struct CrowdFrameProver;
impl quil_types::crypto::FrameProver for CrowdFrameProver {
    fn prove_frame_header(
        &self,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[Vec<u8>],
        _: &[u8],
        _: i64,
        _: u32,
        _: u64,
        _: u64,
        _: &[u8],
        _: u64,
    ) -> Result<FrameHeader> {
        unreachable!("the crowding rigs prove only GLOBAL frames")
    }
    fn prove_global_frame_header(
        &self,
        parent: &quil_types::proto::global::GlobalFrameHeader,
        commitments: &[Vec<u8>],
        root: &[u8],
        auxiliary: &[Vec<u8>],
        requests: &[u8],
        size: u64,
        _: &dyn quil_types::crypto::Signer,
        timestamp: i64,
        difficulty: u32,
        _: u8,
    ) -> Result<quil_types::proto::global::GlobalFrameHeader> {
        Ok(quil_types::proto::global::GlobalFrameHeader {
            frame_number: parent.frame_number + 1,
            output: vec![0x5a; 516],
            parent_selector: quil_crypto::poseidon::hash_bytes_to_32(&parent.output)
                .unwrap()
                .to_vec(),
            timestamp,
            difficulty,
            prover_tree_commitment: root.to_vec(),
            prover_tree_aux_roots: auxiliary.to_vec(),
            global_commitments: commitments.to_vec(),
            requests_root: requests.to_vec(),
            world_state_size: size,
            ..Default::default()
        })
    }
    fn verify_global_frame_header(
        &self,
        header: &quil_types::proto::global::GlobalFrameHeader,
    ) -> Result<Vec<u8>> {
        Ok(header.output.clone())
    }
    fn calculate_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: u32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
    fn verify_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: &[&[u8]]) -> Result<bool> {
        Ok(true)
    }
}

/// One closing session's seal and the drain its members send with it.
struct CrowdSeal {
    filter: Vec<u8>,
    submission: CertificateSubmission,
    /// Its frames 1 to 3; GLOBAL executed frame 1 only.
    drain: Vec<CanonicalHeader>,
}

/// A GLOBAL archive leader and `n` closing sessions. Each session's frame 1
/// GLOBAL executed at frame 3; its frames 2 and 3 missed their window; a
/// request at GLOBAL frame 4 closes each, and each seal at frame 3 brings
/// frames 2 and 3 as its drain. The leader proposes GLOBAL frame
/// [`CROWD_FRAME`] with the engine manager validating, as an archive does.
struct CrowdRig {
    _fixture: Fixture,
    manager: Arc<quil_execution::ExecutionEngineManager>,
    collector: Arc<quil_engine::message_collector::MessageCollector>,
    leader: quil_engine::leader_provider::GlobalLeaderProvider,
    /// Identity of stored GLOBAL frame [`CROWD_FRAME`] - 1.
    parent: Vec<u8>,
    seals: Vec<CrowdSeal>,
}

impl CrowdRig {
    fn new(n: usize) -> Self {
        Self::with_frames(n, 3, 1)
    }

    /// As [`CrowdRig::new`], with each session's frames 1 to `last`, each
    /// seal at `last` draining all of them, and GLOBAL having executed frames
    /// 1 to `executed` (from frame 2 as in their lockstep windows).
    fn with_frames(n: usize, last: u64, executed: u64) -> Self {
        let keys = keys();
        let sources: Vec<Session> = (0..n)
            .map(|i| session(&keys, vec![0x70 + i as u8; 32]))
            .collect();
        let fixture = Fixture::new(&sources[0]);
        let intrinsic = fixture.intrinsic();
        handoff::set_presence_report_frame_for_thread(Some(0));
        for source in &sources {
            handoff::initialize(&fixture.state, 2, source).unwrap();
        }
        commit(&fixture.state, 2);
        let mut frames = Vec::new();
        for source in &sources {
            let mut chain = vec![first_frame(source, &keys)];
            for number in 2..=last {
                let (view, parent_view) = (2 * number + 3, 2 * number + 1);
                let previous = chain.last().unwrap().header.as_ref().unwrap();
                let mut header = FrameHeader {
                    address: source.filter.clone(),
                    frame_number: number,
                    rank: view,
                    difficulty: 1,
                    parent_selector: quil_crypto::poseidon::hash_bytes_to_32(&previous.output)
                        .unwrap()
                        .to_vec(),
                    requests_root: vec![0; 32],
                    state_roots: vec![vec![0; 32]; 4],
                    ..Default::default()
                };
                certify(&mut header, source, &keys, parent_view);
                chain.push(AppShardFrame {
                    header: Some(header),
                    ..Default::default()
                });
            }
            intrinsic
                .invoke_step(
                    3,
                    &canonical(&chain[0]).to_canonical_bytes().unwrap(),
                    &fixture.state,
                )
                .unwrap();
            if executed > 1 {
                let tip = canonical(&chain[executed as usize - 1]);
                handoff::record_session_tip(
                    &fixture.state,
                    3,
                    &source.id().unwrap(),
                    &Checkpoint {
                        frame: executed,
                        view: tip.rank,
                        digest: quil_crypto::poseidon::hash_bytes_to_32(&tip.output).unwrap(),
                        state_roots: [[0; 32]; 4],
                        history_root: [0; 32],
                    },
                )
                .unwrap();
            }
            frames.push(chain);
        }
        commit(&fixture.state, 3);
        // One membership request per session: the sessions' shards belong to
        // different applications, which one transition cannot span.
        let next_keys = self::keys();
        let requests: Vec<_> = sources
            .iter()
            .map(|source| {
                handoff::schedule(
                    &fixture.state,
                    4,
                    vec![source.filter.clone()],
                    vec![DesiredCommittee {
                        filter: source.filter.clone(),
                        members: session(&next_keys, source.filter.clone()).members,
                    }],
                )
                .unwrap()
            })
            .collect();
        commit(&fixture.state, 4);
        let seals = sources
            .iter()
            .zip(&frames)
            .zip(&requests)
            .map(|((source, chain), request)| {
                let sealed = canonical(&chain[last as usize - 1]);
                let seal = Seal {
                    request: request.id().unwrap(),
                    session: source.id().unwrap(),
                    view: 2 * last + 5,
                    checkpoint: Checkpoint {
                        frame: last,
                        view: 2 * last + 3,
                        digest: quil_crypto::poseidon::hash_bytes_to_32(&sealed.output).unwrap(),
                        state_roots: [[0; 32]; 4],
                        history_root: [0x66; 32],
                    },
                };
                CrowdSeal {
                    filter: source.filter.clone(),
                    submission: CertificateSubmission {
                        certificate: sign(source, &keys, 2 * last + 5, 2 * last + 3, seal.digest()),
                        seal,
                    },
                    drain: chain.iter().map(canonical).collect(),
                }
            })
            .collect();
        handoff::set_seal_drain_frame_for_thread(Some(CROWD_FRAME));

        let crypto = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
            fixture.inclusion.clone(),
            crypto.key_manager,
            fixture.state.crdt().clone(),
            crypto.circuit_compiler,
            fixture.clock.clone(),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            true,
        ));
        manager
            .install_global_frame_header_deps(
                fixture.registry.clone(),
                Arc::new(ZeroRewards),
                Arc::new(quil_crypto::FalconKeyConstructor),
                fixture.inclusion.clone(),
                fixture.prover.clone(),
            )
            .unwrap();
        // The parent the leader builds on, as its materializer recorded it.
        let parent_output = vec![0x55; 516];
        store_global_frame(&fixture, CROWD_FRAME - 1, &parent_output);
        fixture
            .state
            .crdt()
            .record_prover_root(CROWD_FRAME - 1, vec![0x77; 32]);
        let signer = Arc::new(quil_crypto::FalconSigner::generate());
        let address = quil_crypto::poseidon::hash_bytes_to_32(signer.public_key())
            .unwrap()
            .to_vec();
        let registry = Arc::new(TestProverRegistry::with_provers(vec![ProverInfo {
            address: address.clone(),
            public_key: signer.public_key().to_vec(),
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: Vec::new(),
            available_storage: 0,
            seniority: 1,
            delegate_address: Vec::new(),
        }]));
        let collector = Arc::new(quil_engine::message_collector::MessageCollector::new());
        let leader = quil_engine::leader_provider::GlobalLeaderProvider::new(
            registry,
            Arc::new(CrowdFrameProver),
            Arc::new(quil_engine::difficulty::AsertDifficultyAdjuster::new(
                0, 0, 100,
            )),
            fixture.clock.clone(),
            collector.clone(),
            address,
            signer.public_key().to_vec(),
            signer,
            Arc::new(quil_tries::ShaInclusionProver),
            Some(manager.clone()),
            Some(fixture.state.crdt().clone()),
        );
        Self {
            _fixture: fixture,
            manager,
            collector,
            leader,
            parent: quil_crypto::poseidon::hash_bytes_to_32(&parent_output)
                .unwrap()
                .to_vec(),
            seals,
        }
    }

    fn bundle(requests: Vec<Vec<u8>>, timestamp: i64) -> Vec<u8> {
        quil_execution::message_envelope::CanonicalMessageBundle {
            requests: requests
                .into_iter()
                .map(|inner_bytes| {
                    Some(quil_execution::message_envelope::CanonicalMessageRequest {
                        inner_type_prefix: handoff::TYPE_COMMITTEE_HANDOFF,
                        inner_bytes,
                    })
                })
                .collect(),
            timestamp,
        }
        .to_canonical_bytes()
        .unwrap()
    }

    fn sealed(submission: &CertificateSubmission, drain: Vec<Vec<u8>>) -> Vec<u8> {
        handoff::SealSubmission {
            submission: submission.clone(),
            drain,
        }
        .to_canonical_bytes()
        .unwrap()
    }

    /// A closing member's copy of seal `seal` whose drain starts at frame
    /// `from` (headers GLOBAL executed are passed over).
    fn member(&self, seal: usize, from: usize, timestamp: i64) -> Vec<u8> {
        let sealed = &self.seals[seal];
        let drain = sealed.drain[from - 1..]
            .iter()
            .map(|header| header.to_canonical_bytes().unwrap())
            .collect();
        Self::bundle(vec![Self::sealed(&sealed.submission, drain)], timestamp)
    }

    /// Two members' copies of seal `seal`, both valid, gossiped at `rank`:
    /// one draining frames 2 and 3, a later one 1 to 3, which reaches as far
    /// with one header more and so is the one that rides. (Copies differing
    /// only by timestamp are one message to the mempool.)
    fn gossip_members(&self, seal: usize, rank: u64) -> Vec<Vec<u8>> {
        let copies = vec![self.member(seal, 2, 10), self.member(seal, 1, 11)];
        for copy in &copies {
            assert!(
                self.collector.add_message(rank, copy.clone()),
                "SETUP: the mempool must take a member's copy"
            );
        }
        copies
    }

    /// A header of seal `seal`'s shard numbered `frame_number`, nothing else set.
    fn junk_header(&self, seal: usize, frame_number: u64) -> Vec<u8> {
        CanonicalHeader {
            address: self.seals[seal].filter.clone(),
            frame_number,
            ..Default::default()
        }
        .to_canonical_bytes()
        .unwrap()
    }

    /// What any peer makes of a member's gossiped copy: the same submission
    /// and drain with one more header, numbered one past the checkpoint.
    fn extended(&self, seal: usize, timestamp: i64) -> Vec<u8> {
        let sealed = &self.seals[seal];
        let mut drain: Vec<_> = sealed
            .drain
            .iter()
            .map(|header| header.to_canonical_bytes().unwrap())
            .collect();
        drain.push(self.junk_header(seal, 4));
        Self::bundle(vec![Self::sealed(&sealed.submission, drain)], timestamp)
    }

    /// What any peer makes of a member's gossiped copy, its certificate
    /// included: one more header, numbered 0 (GLOBAL executed frame 1, so it
    /// is passed over), and the last header altered. The copy claims the
    /// members' reach with more headers than any of theirs, and validation
    /// checks the certificate before it refuses the altered header.
    fn padded(&self, seal: usize, timestamp: i64) -> Vec<u8> {
        let sealed = &self.seals[seal];
        let mut headers = sealed.drain.clone();
        headers.last_mut().unwrap().spends = vec![timestamp as u8];
        let drain = std::iter::once(self.junk_header(seal, 0))
            .chain(
                headers
                    .iter()
                    .map(|header| header.to_canonical_bytes().unwrap()),
            )
            .collect();
        Self::bundle(vec![Self::sealed(&sealed.submission, drain)], timestamp)
    }

    /// A copy of each of `seals` made from their request and session alone:
    /// a certificate nobody signed and one header numbered `reach`, all in
    /// one bundle.
    fn forged(&self, seals: &[usize], reach: u64, timestamp: i64) -> Vec<u8> {
        let requests = seals
            .iter()
            .map(|&seal| {
                let submission = CertificateSubmission {
                    seal: self.seals[seal].submission.seal.clone(),
                    certificate: vec![0xee; 64],
                };
                Self::sealed(&submission, vec![self.junk_header(seal, reach)])
            })
            .collect();
        Self::bundle(requests, timestamp)
    }

    /// A member's copy of seal `seal` with a certificate nobody signed in
    /// place of the members' and one more header, numbered 0 (GLOBAL
    /// executed frame 1, so it is passed over): it claims the members' reach
    /// with more headers than any of theirs, every header it carries passes,
    /// and validation refuses it on its certificate.
    fn unsigned(&self, seal: usize, timestamp: i64) -> Vec<u8> {
        let sealed = &self.seals[seal];
        let submission = CertificateSubmission {
            seal: sealed.submission.seal.clone(),
            certificate: vec![0xee; 64],
        };
        let drain = std::iter::once(self.junk_header(seal, 0))
            .chain(
                sealed
                    .drain
                    .iter()
                    .map(|header| header.to_canonical_bytes().unwrap()),
            )
            .collect();
        Self::bundle(vec![Self::sealed(&submission, drain)], timestamp)
    }

    fn validate(&self, bundle: &[u8]) -> Result<()> {
        self.manager
            .validate_message(CROWD_FRAME, &quil_execution::domains::GLOBAL, bundle)
    }

    /// Members' copies pass the leader's validation and `forged` does not, so
    /// a seal missing from a proposal is the choice's doing.
    fn check_setup(&self, members: &[Vec<u8>], forged: &[&[u8]]) {
        for copy in members {
            if let Err(error) = self.validate(copy) {
                panic!("SETUP: GLOBAL frame {CROWD_FRAME} must admit a member's copy: {error}");
            }
        }
        for copy in forged {
            assert!(
                self.validate(copy).is_err(),
                "UNEXPECTED: GLOBAL frame {CROWD_FRAME} admitted a forged copy"
            );
        }
    }

    /// The canonical bundles this leader's proposal of [`CROWD_FRAME`] at
    /// `rank` carries.
    fn propose(&self, rank: u64) -> Vec<Vec<u8>> {
        use quil_consensus::leader_provider::LeaderProvider as _;
        let state = self
            .leader
            .prove_next_state(rank, &[], CROWD_FRAME - 1, &self.parent)
            .unwrap_or_else(|error| {
                panic!("SETUP: the leader must propose GLOBAL frame {CROWD_FRAME}: {error}")
            });
        assert_eq!(state.state.frame_number, CROWD_FRAME);
        state
            .state
            .messages
            .iter()
            .map(|bundle| {
                quil_engine::consensus_wire::proto_message_bundle_to_canonical_bytes_at(
                    bundle,
                    Some(CROWD_FRAME),
                )
                .unwrap()
            })
            .collect()
    }
}

impl Drop for CrowdRig {
    fn drop(&mut self) {
        handoff::set_seal_recovery_frame_for_thread(None);
        handoff::set_seal_drain_frame_for_thread(None);
        handoff::set_presence_report_frame_for_thread(None);
    }
}

/// How many of `members` (one seal's copies) `proposal` carries.
fn carried(proposal: &[Vec<u8>], members: &[Vec<u8>]) -> usize {
    proposal
        .iter()
        .filter(|bundle| members.contains(bundle))
        .count()
}

/// Every seal whose members' copies are in `members` rides `proposals`.
fn assert_seals_ride(proposals: &[Vec<Vec<u8>>], members: &[Vec<Vec<u8>>], what: &str) {
    let missing: Vec<String> = proposals
        .iter()
        .enumerate()
        .flat_map(|(n, proposal)| {
            members
                .iter()
                .enumerate()
                .filter(|(_, copies)| carried(proposal, copies) == 0)
                .map(move |(seal, _)| format!("proposal {} seal {seal}", n + 1))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "CROWDED: GLOBAL frame {CROWD_FRAME}'s proposals carry no copy of a seal whose \
         members' copies validate, after {what} reached the mempool: the leader chose the \
         forged copy before validating any, validation refused it and the members' copies \
         stayed back. {} of {} seal slots missed: {missing:?}",
        missing.len(),
        proposals.len() * members.len()
    );
}

/// Members' copies of a seal alone in the mempool: exactly one rides, the
/// one reaching furthest with the most headers.
#[test]
fn seal_crowding_control_one_members_copy_rides() {
    let rig = CrowdRig::new(1);
    let members = rig.gossip_members(0, 1);
    rig.check_setup(&members, &[]);
    let proposal = rig.propose(1);
    assert_eq!(
        carried(&proposal, &members),
        1,
        "SETUP: one member's copy must ride, got {} of {} bundles",
        carried(&proposal, &members),
        proposal.len()
    );
    assert!(
        proposal.contains(&members[1]),
        "SETUP: the member's copy with the most headers must ride"
    );
}

/// A later copy reaching no further than the members' (its last header
/// altered) does not change which copy rides: the choice is by reach.
#[test]
fn seal_crowding_control_a_copy_reaching_no_further_leaves_the_members_copy() {
    let rig = CrowdRig::new(1);
    let members = rig.gossip_members(0, 1);
    let mut altered = rig.seals[0].drain.clone();
    altered[2].spends = vec![1, 2, 3];
    let equal = CrowdRig::bundle(
        vec![CrowdRig::sealed(
            &rig.seals[0].submission,
            altered
                .iter()
                .map(|header| header.to_canonical_bytes().unwrap())
                .collect(),
        )],
        12,
    );
    rig.check_setup(&members, &[&equal]);
    assert!(rig.collector.add_message(1, equal.clone()));
    let proposal = rig.propose(1);
    assert!(!proposal.contains(&equal));
    assert_eq!(
        carried(&proposal, &members),
        1,
        "SETUP: a copy reaching no further must leave a member's copy riding"
    );
}

/// A member's copy with one more header, numbered one past the checkpoint,
/// reaches further than every member's own copy.
#[test]
fn seal_crowding_a_members_copy_with_one_more_header_keeps_the_seal_out() {
    let rig = CrowdRig::new(1);
    let members = rig.gossip_members(0, 1);
    let extended = rig.extended(0, 12);
    rig.check_setup(&members, &[&extended]);
    assert!(rig.collector.add_message(1, extended.clone()));
    let proposal = rig.propose(1);
    assert!(
        !proposal.contains(&extended),
        "UNEXPECTED: the forged copy rode"
    );
    assert_seals_ride(
        &[proposal],
        &[members],
        "a member's copy with one header numbered past the checkpoint",
    );
}

/// A drain whose numbers cannot pass is refused on them, before any header
/// or certificate it carries is verified: a member's copy with one more
/// header, numbered past the checkpoint, is refused as running past it, not
/// on that header's missing certificate after the others were verified.
#[test]
fn a_drain_numbered_past_the_checkpoint_is_refused_before_any_header_is_verified() {
    let rig = CrowdRig::new(1);
    let refusal = rig.validate(&rig.extended(0, 12)).unwrap_err().to_string();
    assert!(
        refusal.contains("headers run past the sealed checkpoint"),
        "VERIFIED FIRST: GLOBAL frame {CROWD_FRAME} verified drain headers before refusing \
         a drain numbered past the checkpoint: {refusal}"
    );
}

/// No valid certificate is needed: a member's gossiped copy with its
/// certificate replaced, refused only on that certificate.
#[test]
fn seal_crowding_a_copy_with_no_valid_certificate_keeps_the_seal_out() {
    let rig = CrowdRig::new(1);
    let members = rig.gossip_members(0, 1);
    let forged = rig.unsigned(0, 12);
    rig.check_setup(&members, &[&forged]);
    let refusal = rig.validate(&forged).unwrap_err().to_string();
    assert!(
        refusal.contains("invalid source finalization certificate"),
        "SETUP: the copy must be refused on its certificate: {refusal}"
    );
    assert!(rig.collector.add_message(1, forged.clone()));
    let proposal = rig.propose(1);
    assert!(
        !proposal.contains(&forged),
        "UNEXPECTED: the forged copy rode"
    );
    assert_seals_ride(
        &[proposal],
        &[members],
        "a member's copy with an unsigned certificate and one more header",
    );
}

/// Three forged copies sent once hold the seal out of three proposals; the
/// leader drops one per proposal. Once they are spent a member's copy rides.
#[test]
fn seal_crowding_forged_copies_sent_once_keep_the_seal_out_of_as_many_proposals() {
    let rig = CrowdRig::new(1);
    let members = rig.gossip_members(0, 1);
    let forged: Vec<_> = (0..3)
        .map(|n| rig.forged(&[0], u64::MAX - n, 12 + n as i64))
        .collect();
    rig.check_setup(
        &members,
        &forged.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    );
    for copy in &forged {
        assert!(rig.collector.add_message(1, copy.clone()));
    }
    let proposals: Vec<_> = (1..=4).map(|rank| rig.propose(rank)).collect();
    assert_eq!(
        carried(&proposals[3], &members),
        1,
        "SETUP: once the forged copies are spent a member's copy must ride"
    );
    assert_seals_ride(&proposals[..3], &[members], "three forged copies sent once");
}

/// One forged bundle naming two seals keeps both out.
#[test]
fn seal_crowding_one_forged_bundle_keeps_every_seal_it_names_out() {
    let rig = CrowdRig::new(2);
    let members: Vec<_> = (0..2).map(|seal| rig.gossip_members(seal, 1)).collect();
    let forged = rig.forged(&[0, 1], u64::MAX, 12);
    rig.check_setup(&members.concat(), &[&forged]);
    assert!(rig.collector.add_message(1, forged.clone()));
    let proposal = rig.propose(1);
    assert!(
        !proposal.contains(&forged),
        "UNEXPECTED: the forged bundle rode"
    );
    assert_seals_ride(&[proposal], &members, "one forged bundle naming both seals");
}

/// A forged copy is validated once, in the proposal that tries it, and
/// leaves the mempool; the seal rides that proposal. The other forged copies
/// wait unvalidated, as the seal rides: an attacker pays a message per
/// validation, and the members' copies stay until GLOBAL records the seal.
#[test]
fn seal_crowding_fix_refused_copies_leave_the_mempool_in_the_proposal_that_tries_them() {
    let rig = CrowdRig::new(1);
    let members = rig.gossip_members(0, 1);
    let forged: Vec<_> = (0..3)
        .map(|n| rig.forged(&[0], u64::MAX - n, 12 + n as i64))
        .collect();
    for copy in &forged {
        assert!(rig.collector.add_message(1, copy.clone()));
    }
    assert_eq!(rig.collector.total_pending(), 5);
    for rank in 1..=3 {
        let proposal = rig.propose(rank);
        assert_eq!(
            carried(&proposal, &members),
            1,
            "REFUSED ONCE: the seal rides"
        );
        assert!(forged.iter().all(|copy| !proposal.contains(copy)));
        assert_eq!(
            rig.collector.total_pending(),
            members.len() + forged.len() - rank as usize,
            "REFUSED ONCE: each proposal refuses one forged copy, which leaves the mempool; \
             the members' stay"
        );
    }
}

/// Forged copies made from a member's gossiped copy, its certificate
/// included, each with more headers than any member's copy and so tried
/// ahead of theirs: the leader validates one, refuses it, and then takes the
/// seal's copies in collection order, so a member's copy rides and the other
/// forged copies are never validated. Uncapped, each forged copy cost a
/// certificate check before a member's copy was reached, and enough of them
/// spent the proposal's validation budget.
#[test]
fn forged_copies_with_a_members_certificate_cost_one_refusal_before_a_members_copy_rides() {
    const FORGED: usize = 8;
    let rig = CrowdRig::new(1);
    let members = rig.gossip_members(0, 1);
    let forged: Vec<_> = (0..FORGED).map(|n| rig.padded(0, 20 + n as i64)).collect();
    rig.check_setup(
        &members,
        &forged.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    );
    for copy in &forged {
        assert!(rig.collector.add_message(1, copy.clone()));
    }
    let proposal = rig.propose(1);
    assert!(
        forged.iter().all(|copy| !proposal.contains(copy)),
        "UNEXPECTED: a forged copy rode"
    );
    assert_eq!(
        carried(&proposal, &members),
        1,
        "CROWDED: GLOBAL frame {CROWD_FRAME}'s proposal carries no member's copy"
    );
    let validated = members.len() + FORGED - rig.collector.total_pending();
    assert_eq!(
        validated, 1,
        "VALIDATED AHEAD: GLOBAL frame {CROWD_FRAME}'s leader validated and refused \
         {validated} of {FORGED} forged copies before a member's copy of the seal rode: \
         a copy claiming more headers than the members' is tried first, so each one costs \
         a certificate check ahead of theirs"
    );
}

/// Members whose view of GLOBAL lags send the seal with a partial drain of
/// frames GLOBAL already executed in their lockstep windows (mainnet,
/// 2026-11-05: eight headers ending three below the checkpoint), which GLOBAL
/// refuses. It reaches further than a copy without a drain, so a leader that
/// chooses by reach before validating carries only it, and the seal misses
/// the proposal with no forged copy anywhere.
#[test]
fn a_stale_partial_drain_does_not_crowd_out_a_valid_seal_copy() {
    let rig = CrowdRig::with_frames(1, 11, 11);
    handoff::set_seal_recovery_frame_for_thread(Some(CROWD_FRAME));
    let valid = rig.member(0, 12, 10);
    let stale = CrowdRig::bundle(
        vec![CrowdRig::sealed(
            &rig.seals[0].submission,
            rig.seals[0].drain[..handoff::MAX_DRAIN_HEADERS]
                .iter()
                .map(|header| header.to_canonical_bytes().unwrap())
                .collect(),
        )],
        11,
    );
    rig.check_setup(std::slice::from_ref(&valid), &[&stale]);
    let refusal = rig.validate(&stale).unwrap_err().to_string();
    assert!(
        refusal.contains(handoff::superseded::PARTIAL_DRAIN_EXECUTED),
        "SETUP: GLOBAL must refuse the stale copy as already executed: {refusal}"
    );
    for copy in [&valid, &stale] {
        assert!(rig.collector.add_message(1, copy.clone()));
    }
    let proposal = rig.propose(1);
    assert!(
        !proposal.contains(&stale),
        "UNEXPECTED: the stale copy rode"
    );
    assert!(
        proposal.contains(&valid),
        "CROWDED: GLOBAL frame {CROWD_FRAME}'s proposal carries no copy of the seal: \
         the leader chose a lagging member's stale partial drain over the valid copy \
         without a drain, validation refused it and the valid copy stayed back"
    );
}

/// An archive whose GLOBAL execution trails its stored head verifies a frame
/// against executed state, which does not hold the session a later GLOBAL
/// frame authorized. A frame anchored past executed state that names its
/// shard's next generation waits for execution to reach its anchor instead
/// of being refused, and is admitted once it does; a frame naming any other
/// generation, or that no session authorizes by then, is refused.
#[test]
fn a_frame_anchored_past_executed_global_state_waits_for_execution() {
    use quil_engine::archive_ingest::FrameCheck;
    let keys = keys();
    let authorized = session(&keys, vec![0x63; 32]);
    let unauthorized = session(&keys, vec![0x64; 32]);
    let fixture = Fixture::new(&authorized);
    // GLOBAL frame 2 is stored; execution is at frame 1.
    let anchor_output = vec![0x42; 32];
    store_global_frame(&fixture, 2, &anchor_output);
    let frame = anchored_first_frame(&authorized, &keys, 2, &anchor_output);
    let stranger = anchored_first_frame(&unauthorized, &keys, 2, &anchor_output);
    let far = anchored_first_frame(
        &Session {
            generation: 9,
            ..authorized.clone()
        },
        &keys,
        2,
        &anchor_output,
    );
    let archive = fixture.archive();
    let verifier = archive.verifier();
    assert_eq!(
        verifier.check(&frame),
        FrameCheck::AwaitExecution {
            anchor: 2,
            executed: 1
        }
    );
    assert_eq!(
        verifier.check(&stranger),
        FrameCheck::AwaitExecution {
            anchor: 2,
            executed: 1
        },
        "unknown until GLOBAL frame 2 executes"
    );
    assert_eq!(
        verifier.check(&far),
        FrameCheck::Refused,
        "not the shard's next generation, which GLOBAL frames not yet executed could authorize"
    );

    // GLOBAL frame 2 executes and authorizes the session.
    handoff::initialize(&fixture.state, 2, &authorized).unwrap();
    commit(&fixture.state, 2);
    assert_eq!(
        verifier.check(&frame),
        FrameCheck::Admit { certified: true }
    );
    assert_eq!(
        verifier.check(&stranger),
        FrameCheck::Refused,
        "still unauthorized once execution reached its anchor"
    );
}

/// A forged header naming a shard's next generation and anchored past
/// executed GLOBAL state waits for execution, through ingest as through the
/// gap fetch, but cannot hold back the GLOBAL frame that needs the shard's
/// real frame at its height: that frame is asked for at once. A forged header
/// naming any other generation is refused, so it does not wait.
#[tokio::test(flavor = "multi_thread")]
async fn a_forged_frame_waiting_for_execution_does_not_hold_back_global_execution() {
    let keys = keys();
    let authorized = session(&keys, vec![0x65; 32]);
    let fixture = Fixture::new(&authorized);
    handoff::initialize(&fixture.state, 2, &authorized).unwrap();
    commit(&fixture.state, 2);
    // GLOBAL frame 3 is stored; execution is at frame 2.
    let anchor_output = vec![0x43; 32];
    store_global_frame(&fixture, 3, &anchor_output);
    let (gap_tx, mut gap_rx) = tokio::sync::mpsc::channel(64);
    let (prefetch_tx, mut prefetch_rx) = tokio::sync::mpsc::channel(64);
    let mut archive = fixture
        .archive()
        .with_gap_fetch(gap_tx)
        .with_prefetch(prefetch_tx)
        .sequenced();
    let drain = |rx: &mut tokio::sync::mpsc::Receiver<(Vec<u8>, u64)>| {
        let mut frames = Vec::new();
        while let Ok((_, number)) = rx.try_recv() {
            frames.push(number);
        }
        frames
    };
    // The archive holds the shard's first frame.
    let first = first_frame(&authorized, &keys);
    archive.ingest(&prost::Message::encode_to_vec(&first));
    assert!(archive.materialize_through(&authorized.filter, 1).unwrap());
    assert_eq!(fixture.cursor(&authorized.filter), 1);
    drain(&mut gap_rx);
    drain(&mut prefetch_rx);
    let parent = quil_crypto::poseidon::hash_bytes_to_32(&first.header.as_ref().unwrap().output)
        .unwrap()
        .to_vec();

    // A forged frame 2 names generation 2, which no GLOBAL frame executed so
    // far authorized; it is anchored to GLOBAL frame 3.
    let successor = Session {
        generation: 2,
        ..authorized.clone()
    };
    let forged = anchored_frame(
        &successor,
        &keys,
        2,
        7,
        5,
        parent.clone(),
        3,
        &anchor_output,
    );
    archive.ingest(&prost::Message::encode_to_vec(&forged));
    assert_eq!(
        archive.prefetch_through(&authorized.filter, 2).unwrap(),
        0,
        "the forged frame waits"
    );
    assert!(drain(&mut prefetch_rx).is_empty());
    assert!(!archive.materialize_through(&authorized.filter, 2).unwrap());
    assert_eq!(
        drain(&mut gap_rx),
        vec![2],
        "the GLOBAL frame waiting for frame 2 asks for it at once"
    );

    // The gap fetch does not count a frame that waits as recovered.
    let ingest = std::sync::Mutex::new(archive);
    let verifier = ingest.lock().unwrap().verifier();
    assert_eq!(
        quil_engine::archive_ingest::admit_fetched(
            &ingest,
            &verifier,
            &authorized.filter,
            vec![forged]
        ),
        quil_engine::archive_ingest::FetchedFrames::AwaitsExecution {
            anchor: 3,
            executed: 2
        }
    );
    let mut archive = ingest.into_inner().unwrap();

    // A forged frame 3 naming generation 9 is refused, not parked.
    let far = Session {
        generation: 9,
        ..authorized.clone()
    };
    let refused = anchored_frame(&far, &keys, 3, 9, 7, vec![0x77; 32], 3, &anchor_output);
    archive.ingest(&prost::Message::encode_to_vec(&refused));
    archive.prefetch_through(&authorized.filter, 3).unwrap();
    assert_eq!(
        drain(&mut prefetch_rx),
        vec![3],
        "asked for as any missing frame"
    );
}

/// A shard leader's header difficulty is bound into the certified output, but
/// no voter compares it with GLOBAL's: one below 10,000 prices issuance with
/// no square root, about 32 times as much at a 1 TiB world. And GLOBAL
/// executes a certified header again whenever a GLOBAL frame includes it.
/// From the anchored issuance epoch GLOBAL prices the header at the
/// difficulty of the GLOBAL frame it anchors to and credits each frame of a
/// session once; before it, both stay as they were.
#[test]
fn global_prices_a_header_at_its_anchor_and_credits_each_frame_once() {
    let keys = keys();
    let source = session(&keys, vec![0x67; 32]);
    let anchor_output = vec![0x45; 32];
    // The leader wrote difficulty 1 into the header; its GLOBAL anchor,
    // frame 2, has 160,000.
    let frame = anchored_first_frame(&source, &keys, 2, &anchor_output);
    let mut op = canonical(&frame);
    op.global_frame_number = 2;
    assert_eq!(op.difficulty, 1);
    let wire = op.to_canonical_bytes().unwrap();
    // GLOBAL frames 3 and 4 both include the header.
    let priced = |epoch: u64| {
        quil_types::consensus::set_anchored_issuance_epoch_for_thread(Some(epoch));
        let fixture = Fixture::new(&source);
        handoff::initialize(&fixture.state, 2, &source).unwrap();
        commit(&fixture.state, 2);
        store_global_frame_at(&fixture, 2, &anchor_output, 160_000);
        let probe = Arc::new(DifficultyProbe::default());
        let intrinsic = fixture.intrinsic_with(probe.clone());
        for number in [3, 4] {
            intrinsic
                .invoke_step(number, &wire, &fixture.state)
                .unwrap();
            commit(&fixture.state, number);
        }
        quil_types::consensus::set_anchored_issuance_epoch_for_thread(None);
        let difficulties = probe.0.lock().unwrap().clone();
        difficulties
    };
    assert_eq!(
        priced(u64::MAX),
        vec![1, 1],
        "before the epoch: the leader's difficulty, credited in every GLOBAL frame"
    );
    assert_eq!(
        priced(0),
        vec![160_000],
        "from the epoch: the anchor's difficulty, credited once"
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
    // Tip advances record their GLOBAL frame from here on.
    handoff::set_presence_report_frame_for_thread(Some(0));
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
            parent_selector: quil_crypto::poseidon::hash_bytes_to_32(&previous.output)
                .unwrap()
                .to_vec(),
            requests_root: vec![0; 32],
            state_roots: vec![vec![0; 32]; 4],
            ..Default::default()
        };
        certify(&mut header, &source, &keys, parent_view);
        frames.push(AppShardFrame {
            header: Some(header),
            ..Default::default()
        });
    }
    let wire = |frame: &AppShardFrame| canonical(frame).to_canonical_bytes().unwrap();
    // GLOBAL executed frame 1 only; 2 and 3 missed their window.
    intrinsic
        .invoke_step(3, &wire(&frames[0]), &fixture.state)
        .unwrap();
    commit(&fixture.state, 3);
    assert_eq!(
        handoff::session_tip(&fixture.state, &source.id().unwrap())
            .unwrap()
            .unwrap()
            .frame,
        1
    );
    assert_eq!(
        handoff::session_tip_frame(&fixture.state, &source.id().unwrap()).unwrap(),
        Some(3),
        "the executing GLOBAL frame, not the header's anchor"
    );

    let next_keys = self::keys();
    let request = handoff::schedule(
        &fixture.state,
        4,
        vec![source.filter.clone()],
        vec![DesiredCommittee {
            filter: source.filter.clone(),
            members: session(&next_keys, source.filter.clone()).members,
        }],
    )
    .unwrap();
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
    let submission = CertificateSubmission {
        certificate: sign(&source, &keys, 11, 9, seal.digest()),
        seal,
    };
    let sealed = |drain: Vec<Vec<u8>>| {
        handoff::SealSubmission {
            submission: submission.clone(),
            drain,
        }
        .to_canonical_bytes()
        .unwrap()
    };
    let refused = |bytes: &[u8], frame: u64, expect: &str| {
        let error = intrinsic
            .invoke_step(frame, bytes, &fixture.state)
            .unwrap_err();
        assert!(
            error.to_string().contains(expect),
            "expected {expect:?}, got {error}"
        );
        assert!(intrinsic.validate(frame, bytes, None, None).is_err());
    };

    // The seal alone waits for frames GLOBAL never executed.
    refused(
        &submission.to_canonical_bytes().unwrap(),
        5,
        "not yet executed",
    );
    // Before the drain frame a drain is refused, as an older build would.
    handoff::set_seal_drain_frame_for_thread(Some(6));
    refused(
        &sealed(vec![wire(&frames[1]), wire(&frames[2])]),
        5,
        "not active",
    );

    // Malformed drains, from the drain frame on.
    refused(
        &sealed(vec![wire(&frames[2])]),
        6,
        "gap after the executed tip",
    );
    refused(
        &sealed(vec![wire(&frames[1])]),
        6,
        "do not end at the sealed checkpoint",
    );
    refused(
        &sealed(vec![wire(&frames[0]), wire(&frames[2])]),
        6,
        "not consecutive",
    );
    let mut forged = canonical(&frames[1]);
    forged.spends = vec![1, 2, 3];
    refused(
        &sealed(vec![forged.to_canonical_bytes().unwrap(), wire(&frames[2])]),
        6,
        "",
    );
    let other = session(&keys, vec![0x63; 32]);
    let mut foreign = frames[1].clone();
    foreign.header.as_mut().unwrap().address = other.filter.clone();
    refused(
        &sealed(vec![wire(&foreign), wire(&frames[2])]),
        6,
        "another shard",
    );
    assert_eq!(
        handoff::session_tip(&fixture.state, &source.id().unwrap())
            .unwrap()
            .unwrap()
            .frame,
        1,
        "a refused drain executes nothing"
    );

    // The full drain, an already-executed header included, is accepted.
    let drain = sealed(vec![wire(&frames[0]), wire(&frames[1]), wire(&frames[2])]);
    assert!(intrinsic.validate(6, &drain, None, None).unwrap());
    // Checking it against the execution state stages nothing, the tip's
    // GLOBAL frame included.
    let staged = fixture.state.changeset_len();
    let checked = handoff::SealSubmission {
        submission: submission.clone(),
        drain: vec![wire(&frames[0]), wire(&frames[1]), wire(&frames[2])],
    };
    intrinsic
        .verify_seal_submission(6, &checked, &fixture.state)
        .unwrap();
    assert_eq!(
        fixture.state.changeset_len(),
        staged,
        "a checked drain stages nothing"
    );
    assert_eq!(
        handoff::session_tip_frame(&fixture.state, &source.id().unwrap()).unwrap(),
        Some(3)
    );
    intrinsic.invoke_step(6, &drain, &fixture.state).unwrap();
    commit(&fixture.state, 6);
    let tip = handoff::session_tip(&fixture.state, &source.id().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        (tip.frame, tip.view, tip.digest),
        (3, 9, submission.seal.checkpoint.digest)
    );
    assert_eq!(
        handoff::session_tip_frame(&fixture.state, &source.id().unwrap()).unwrap(),
        Some(6),
        "the executed drain records its GLOBAL frame"
    );
    assert_eq!(
        handoff::head(&fixture.state, &source.filter)
            .unwrap()
            .unwrap()
            .generation,
        2,
        "the seal authorized the successor"
    );
    handoff::set_seal_drain_frame_for_thread(None);
    handoff::set_presence_report_frame_for_thread(None);
}

/// A closing session whose frame 1 GLOBAL executed (at frame 3) and whose
/// frames 2 to `last` are only notarized, frame n at view 2n + 3, sealed at
/// frame `last` by its members under a request GLOBAL made at frame 4.
struct NotarizedSeal {
    keys: Vec<FalconPrivateKey>,
    source: Session,
    fixture: Fixture,
    intrinsic: GlobalIntrinsic,
    frames: Vec<AppShardFrame>,
    submission: CertificateSubmission,
}

impl NotarizedSeal {
    fn new(filter: u8, last: u64) -> Self {
        let keys = keys();
        let source = session(&keys, vec![filter; 32]);
        let fixture = Fixture::new(&source);
        let intrinsic = fixture.intrinsic();
        handoff::initialize(&fixture.state, 2, &source).unwrap();
        commit(&fixture.state, 2);
        let mut frames = vec![first_frame(&source, &keys)];
        for number in 2..=last {
            let previous = frames.last().unwrap().header.as_ref().unwrap();
            let mut header = FrameHeader {
                address: source.filter.clone(),
                frame_number: number,
                rank: 2 * number + 3,
                difficulty: 1,
                parent_selector: quil_crypto::poseidon::hash_bytes_to_32(&previous.output)
                    .unwrap()
                    .to_vec(),
                requests_root: vec![0; 32],
                state_roots: vec![vec![0; 32]; 4],
                ..Default::default()
            };
            stamp(&mut header);
            frames.push(AppShardFrame {
                header: Some(header),
                ..Default::default()
            });
        }
        intrinsic
            .invoke_step(
                3,
                &canonical(&frames[0]).to_canonical_bytes().unwrap(),
                &fixture.state,
            )
            .unwrap();
        commit(&fixture.state, 3);
        let request = handoff::schedule(
            &fixture.state,
            4,
            vec![source.filter.clone()],
            vec![DesiredCommittee {
                filter: source.filter.clone(),
                members: session(&self::keys(), source.filter.clone()).members,
            }],
        )
        .unwrap();
        commit(&fixture.state, 4);
        let checkpoint = canonical(&frames[last as usize - 1]);
        let seal = Seal {
            request: request.id().unwrap(),
            session: source.id().unwrap(),
            view: 2 * last + 5,
            checkpoint: Checkpoint {
                frame: last,
                view: 2 * last + 3,
                digest: quil_crypto::poseidon::hash_bytes_to_32(&checkpoint.output).unwrap(),
                state_roots: [[0; 32]; 4],
                history_root: [0x66; 32],
            },
        };
        let submission = CertificateSubmission {
            certificate: sign(&source, &keys, 2 * last + 5, 2 * last + 3, seal.digest()),
            seal,
        };
        Self {
            keys,
            source,
            fixture,
            intrinsic,
            frames,
            submission,
        }
    }
}

/// A seal built on a notarized checkpoint finalizes that frame, and a
/// notarized frame under it, with no certificate of their own: no proof
/// carries them to GLOBAL, and a session-certified drain cannot either (eight
/// sessions refused until the fence, 2026-10-15). From the checkpoint drain
/// frame the seal's certificate authenticates them: the checkpoint by its
/// frame and digest, the frame under it by its child's parent link. A forged
/// seal, a header the chain does not name, or one outside a drain reaching
/// the checkpoint stays refused.
#[test]
fn a_seal_drains_the_notarized_frames_its_certificate_finalized() {
    // Frame 1 certified; frames 2 and 3 (views 7 and 9) only notarized.
    let NotarizedSeal {
        keys,
        source,
        fixture,
        intrinsic,
        frames,
        submission,
    } = NotarizedSeal::new(0x65, 3);
    // Frames 1 to 10 of another, for a drain stopping short of its checkpoint.
    let longer = NotarizedSeal::new(0x66, 10);
    let wire = |frame: &AppShardFrame| canonical(frame).to_canonical_bytes().unwrap();
    let sealed = |submission: &CertificateSubmission, drain: Vec<Vec<u8>>| {
        handoff::SealSubmission {
            submission: submission.clone(),
            drain,
        }
        .to_canonical_bytes()
        .unwrap()
    };
    let refused = |bytes: &[u8], frame: u64, expect: &str| {
        let error = intrinsic
            .invoke_step(frame, bytes, &fixture.state)
            .unwrap_err();
        assert!(
            error.to_string().contains(expect),
            "expected {expect:?}, got {error}"
        );
        assert!(intrinsic.validate(frame, bytes, None, None).is_err());
    };
    // What refuses a header the seal does not authenticate.
    let uncertified = "authorized session requires its Simplex certificate";
    let tip = || {
        handoff::session_tip(&fixture.state, &source.id().unwrap())
            .unwrap()
            .unwrap()
            .frame
    };
    handoff::set_seal_drain_frame_for_thread(Some(5));
    let drain = sealed(&submission, vec![wire(&frames[1]), wire(&frames[2])]);

    // Before the checkpoint drain frame they need certificates of their own.
    handoff::set_seal_checkpoint_drain_frame_for_thread(Some(7));
    refused(&drain, 6, uncertified);
    // From it: a forged seal certifies nothing.
    let mut forged = submission.clone();
    forged.certificate = sign(&source, &keys, 11, 8, forged.seal.digest());
    refused(
        &sealed(&forged, vec![wire(&frames[1]), wire(&frames[2])]),
        7,
        "invalid source finalization certificate",
    );
    // A checkpoint header whose fields differ from the sealed frame's.
    let mut altered = frames[2].clone();
    altered.header.as_mut().unwrap().timestamp = 1;
    stamp(altered.header.as_mut().unwrap());
    refused(
        &sealed(&submission, vec![wire(&frames[1]), wire(&altered)]),
        7,
        uncertified,
    );
    // A frame under the checkpoint that it does not name as its parent.
    let mut stranger = frames[1].clone();
    stranger.header.as_mut().unwrap().timestamp = 1;
    stamp(stranger.header.as_mut().unwrap());
    refused(
        &sealed(&submission, vec![wire(&stranger), wire(&frames[2])]),
        7,
        uncertified,
    );
    // A drain stopping short of the checkpoint has nothing to chain to. Its
    // numbering must pass, so it is a partial drain (eight headers, from the
    // seal recovery frame) of a session sealed further on: frames 2 to 9 of
    // one sealed at frame 10.
    handoff::set_seal_recovery_frame_for_thread(Some(7));
    let partial = sealed(
        &longer.submission,
        longer.frames[1..=8].iter().map(wire).collect(),
    );
    let error = longer
        .intrinsic
        .invoke_step(7, &partial, &longer.fixture.state)
        .expect_err("UNANCHORED: a drain stopping short of the sealed checkpoint executed");
    assert!(
        error.to_string().contains(uncertified),
        "expected {uncertified:?}, got {error}"
    );
    assert!(longer.intrinsic.validate(7, &partial, None, None).is_err());
    handoff::set_seal_recovery_frame_for_thread(None);
    assert_eq!(
        handoff::session_tip(&longer.fixture.state, &longer.source.id().unwrap())
            .unwrap()
            .unwrap()
            .frame,
        1,
        "a refused partial drain executes nothing"
    );
    assert_eq!(tip(), 1, "a refused drain executes nothing");

    assert!(intrinsic.validate(7, &drain, None, None).unwrap());
    intrinsic.invoke_step(7, &drain, &fixture.state).unwrap();
    commit(&fixture.state, 7);
    let executed = handoff::session_tip(&fixture.state, &source.id().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        (executed.frame, executed.view, executed.digest),
        (3, 9, submission.seal.checkpoint.digest)
    );
    assert_eq!(
        handoff::head(&fixture.state, &source.filter)
            .unwrap()
            .unwrap()
            .generation,
        2,
        "the seal authorized the successor"
    );
    handoff::set_seal_checkpoint_drain_frame_for_thread(None);
    handoff::set_seal_drain_frame_for_thread(None);
}

/// More frames missing than one submission carries (a live shard: checkpoint
/// 575, GLOBAL executed 566) left the seal to the fence, which discarded nine
/// certified frames. From the partial drain frame a submission carries the
/// next eight; GLOBAL executes them under a valid closing certificate and
/// leaves the seal for the submission whose headers reach the checkpoint.
#[test]
fn a_seal_further_behind_than_one_drain_is_drained_in_parts() {
    let keys = keys();
    let source = session(&keys, vec![0x64; 32]);
    let fixture = Fixture::new(&source);
    let intrinsic = fixture.intrinsic();
    handoff::initialize(&fixture.state, 2, &source).unwrap();
    commit(&fixture.state, 2);
    // Frames 1–11 at views 5, 7, …, 25, each extending the last.
    let mut frames = vec![first_frame(&source, &keys)];
    for number in 2u64..=11 {
        let previous = frames.last().unwrap().header.as_ref().unwrap();
        let mut header = FrameHeader {
            address: source.filter.clone(),
            frame_number: number,
            rank: 2 * number + 3,
            difficulty: 1,
            parent_selector: quil_crypto::poseidon::hash_bytes_to_32(&previous.output)
                .unwrap()
                .to_vec(),
            requests_root: vec![0; 32],
            state_roots: vec![vec![0; 32]; 4],
            ..Default::default()
        };
        certify(&mut header, &source, &keys, 2 * number + 1);
        frames.push(AppShardFrame {
            header: Some(header),
            ..Default::default()
        });
    }
    let wire = |frame: &AppShardFrame| canonical(frame).to_canonical_bytes().unwrap();
    // GLOBAL executed frame 1 only.
    intrinsic
        .invoke_step(3, &wire(&frames[0]), &fixture.state)
        .unwrap();
    commit(&fixture.state, 3);
    let request = handoff::schedule(
        &fixture.state,
        4,
        vec![source.filter.clone()],
        vec![DesiredCommittee {
            filter: source.filter.clone(),
            members: session(&self::keys(), source.filter.clone()).members,
        }],
    )
    .unwrap();
    commit(&fixture.state, 4);
    let last = canonical(&frames[10]);
    let seal = Seal {
        request: request.id().unwrap(),
        session: source.id().unwrap(),
        view: 27,
        checkpoint: Checkpoint {
            frame: 11,
            view: 25,
            digest: quil_crypto::poseidon::hash_bytes_to_32(&last.output).unwrap(),
            state_roots: [[0; 32]; 4],
            history_root: [0x66; 32],
        },
    };
    let submission = CertificateSubmission {
        certificate: sign(&source, &keys, 27, 25, seal.digest()),
        seal,
    };
    let sealed = |submission: &CertificateSubmission, range: std::ops::RangeInclusive<usize>| {
        handoff::SealSubmission {
            submission: submission.clone(),
            drain: frames[range].iter().map(wire).collect(),
        }
        .to_canonical_bytes()
        .unwrap()
    };
    let refused = |bytes: &[u8], frame: u64, expect: &str| {
        let error = intrinsic
            .invoke_step(frame, bytes, &fixture.state)
            .unwrap_err();
        assert!(
            error.to_string().contains(expect),
            "expected {expect:?}, got {error}"
        );
        assert!(intrinsic.validate(frame, bytes, None, None).is_err());
    };
    let tip = || {
        handoff::session_tip(&fixture.state, &source.id().unwrap())
            .unwrap()
            .unwrap()
            .frame
    };
    let generation = || {
        handoff::head(&fixture.state, &source.filter)
            .unwrap()
            .unwrap()
            .generation
    };
    handoff::set_seal_drain_frame_for_thread(Some(5));

    // Frames 2–9: eight headers short of the checkpoint. Refused as before
    // until the partial drain frame.
    handoff::set_seal_recovery_frame_for_thread(Some(7));
    refused(
        &sealed(&submission, 1..=8),
        6,
        "do not end at the sealed checkpoint",
    );
    // From it: fewer than eight short of it, or a forged closing certificate,
    // executes nothing.
    refused(&sealed(&submission, 1..=7), 7, "exactly the most headers");
    let mut forged = submission.clone();
    forged.certificate = sign(&source, &keys, 27, 24, forged.seal.digest());
    refused(
        &sealed(&forged, 1..=8),
        7,
        "invalid source finalization certificate",
    );
    assert_eq!(tip(), 1, "a refused partial drain executes nothing");

    let first = sealed(&submission, 1..=8);
    assert!(intrinsic.validate(7, &first, None, None).unwrap());
    intrinsic.invoke_step(7, &first, &fixture.state).unwrap();
    commit(&fixture.state, 7);
    assert_eq!(
        (tip(), generation()),
        (9, 1),
        "drained through frame 9; the seal waits"
    );
    // The same part again moves nothing and is refused.
    refused(&first, 8, "already executed");
    // The rest reaches the checkpoint: drained and sealed together.
    let rest = sealed(&submission, 9..=10);
    assert!(intrinsic.validate(8, &rest, None, None).unwrap());
    intrinsic.invoke_step(8, &rest, &fixture.state).unwrap();
    commit(&fixture.state, 8);
    assert_eq!(
        (tip(), generation()),
        (11, 2),
        "the seal authorized the successor"
    );
    handoff::set_seal_recovery_frame_for_thread(None);
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

/// An archive stored frame 3 as its session certified it at view 10, before
/// GLOBAL sealed the session at frame 3's copy of view 9 (three archives
/// held generation 46's frame 16207 of …091000 after that session ended at
/// 16206, and GLOBAL halted at 944,910, 2026-10-27). After a restart the
/// stored copy is the first the gap fetch tries, and verification refuses it
/// as outside the terminal checkpoint. That refusal must not end the round:
/// the copy an endpoint serves, the one GLOBAL executed, is admitted and
/// replaces the stored one. A copy that cannot be verified yet still ends it.
#[test]
fn a_refused_stored_copy_does_not_end_the_gap_fetch_before_the_valid_one() {
    use quil_engine::archive_ingest::{admit_fetched, gap_fetch_asks_next_source, FetchedFrames};
    use quil_types::store::ClockStore as _;
    let keys = keys();
    let source = session(&keys, vec![0x68; 32]);
    let fixture = Fixture::new(&source);
    let intrinsic = fixture.intrinsic();
    handoff::set_presence_report_frame_for_thread(Some(0));
    handoff::initialize(&fixture.state, 2, &source).unwrap();
    commit(&fixture.state, 2);

    // Frames 1–3 at views 5, 7, 9, and another frame 3 at view 10, both
    // extending frame 2.
    let extend = |previous: &AppShardFrame, number: u64, view: u64, parent_view: u64| {
        let previous = previous.header.as_ref().unwrap();
        let mut header = FrameHeader {
            address: source.filter.clone(),
            frame_number: number,
            rank: view,
            difficulty: 1,
            parent_selector: quil_crypto::poseidon::hash_bytes_to_32(&previous.output)
                .unwrap()
                .to_vec(),
            requests_root: vec![0; 32],
            state_roots: vec![vec![0; 32]; 4],
            ..Default::default()
        };
        certify(&mut header, &source, &keys, parent_view);
        AppShardFrame {
            header: Some(header),
            ..Default::default()
        }
    };
    let mut frames = vec![first_frame(&source, &keys)];
    frames.push(extend(&frames[0], 2, 7, 5));
    frames.push(extend(&frames[1], 3, 9, 7));
    let other = extend(&frames[1], 3, 10, 7);
    let output = |frame: &AppShardFrame| frame.header.as_ref().unwrap().output.clone();
    let stored = |fixture: &Fixture| {
        fixture
            .clock
            .get_shard_clock_frame(&source.filter, 3, false)
            .unwrap()
    };

    // Before the seal the other frame 3 verifies, and the archive stores it.
    let archive = fixture.archive();
    let verifier = archive.verifier();
    let ingest = std::sync::Mutex::new(archive);
    assert_eq!(
        admit_fetched(&ingest, &verifier, &source.filter, vec![other.clone()]),
        FetchedFrames::Admitted
    );
    assert_eq!(output(&stored(&fixture)), output(&other));
    drop(ingest);

    // GLOBAL executes frame 1, then the seal at frame 3 of view 9 drains
    // frames 2 and 3.
    let wire = |frame: &AppShardFrame| canonical(frame).to_canonical_bytes().unwrap();
    intrinsic
        .invoke_step(3, &wire(&frames[0]), &fixture.state)
        .unwrap();
    commit(&fixture.state, 3);
    let request = handoff::schedule(
        &fixture.state,
        4,
        vec![source.filter.clone()],
        vec![DesiredCommittee {
            filter: source.filter.clone(),
            members: session(&self::keys(), source.filter.clone()).members,
        }],
    )
    .unwrap();
    commit(&fixture.state, 4);
    let seal = Seal {
        request: request.id().unwrap(),
        session: source.id().unwrap(),
        view: 11,
        checkpoint: Checkpoint {
            frame: 3,
            view: 9,
            digest: quil_crypto::poseidon::hash_bytes_to_32(&output(&frames[2])).unwrap(),
            state_roots: [[0; 32]; 4],
            history_root: [0x66; 32],
        },
    };
    let submission = CertificateSubmission {
        certificate: sign(&source, &keys, 11, 9, seal.digest()),
        seal,
    };
    let drain = handoff::SealSubmission {
        submission,
        drain: frames.iter().map(wire).collect(),
    }
    .to_canonical_bytes()
    .unwrap();
    handoff::set_seal_drain_frame_for_thread(Some(6));
    intrinsic.invoke_step(6, &drain, &fixture.state).unwrap();
    commit(&fixture.state, 6);
    handoff::set_seal_drain_frame_for_thread(None);
    handoff::set_presence_report_frame_for_thread(None);
    assert_eq!(
        handoff::head(&fixture.state, &source.filter)
            .unwrap()
            .unwrap()
            .generation,
        2,
        "the seal authorized the successor"
    );

    // After a restart the gap fetch tries the stored copy first: refused.
    let archive = fixture.archive();
    let verifier = archive.verifier();
    let ingest = std::sync::Mutex::new(archive);
    assert_eq!(
        admit_fetched(&ingest, &verifier, &source.filter, vec![stored(&fixture)]),
        FetchedFrames::Refused
    );
    let refusal = fixture.validator().validate(&stored(&fixture)).unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("data frame is outside the terminal checkpoint"),
        "{refusal}"
    );
    assert!(
        gap_fetch_asks_next_source(Some(&refusal)),
        "the stored copy's refusal ({refusal}) ended the gap fetch's round: \
         the copy GLOBAL executed was never asked for"
    );
    // Nothing else could verify yet either: the round ends, and the ingest
    // asks again later.
    assert!(!gap_fetch_asks_next_source(Some(
        &quil_types::error::QuilError::ExecutionUnavailable(
            "peer lacks historical storage registration".into()
        )
    )));
    assert!(gap_fetch_asks_next_source(None));

    // The endpoints' copies are admitted, and frame 3 GLOBAL executed
    // replaces the stored one.
    for frame in &frames {
        assert_eq!(
            admit_fetched(&ingest, &verifier, &source.filter, vec![frame.clone()]),
            FetchedFrames::Admitted
        );
    }
    assert_eq!(fixture.cursor(&source.filter), 3);
    assert_eq!(output(&stored(&fixture)), output(&frames[2]));
}

// Seal-drain anchors. A seal submission's drain headers are frames that
// missed their GLOBAL window, so no window bounds the GLOBAL frame each names
// as its anchor, and each header's output check reads that frame from the
// clock store. The session certificate (or, for a notarized checkpoint, the
// seal's) signs the header's output digest, which commits to the anchor only
// through the anchor frame's output: a genuine header with its anchor
// rewritten to a frame no node holds still passes the certificate, and the
// read reports it unavailable. The materializer fails the whole GLOBAL frame
// on an unavailable error and retries it for ever (`frame_materializer.rs`).
// Validation checks the drain before the seal's own closing certificate.

/// The GLOBAL frame that checks the rigs' seals.
const DRAIN_FRAME: u64 = 10;
/// The GLOBAL frame the rigs' drain header is anchored to.
const DRAIN_ANCHOR: u64 = 3;
/// The oldest GLOBAL frame the rigs hold, as a network's first frame: they
/// hold frames 2 to 9 (`QUIL_SEAL_DRAIN_ANCHOR_FLOOR`, which a build without
/// a floor ignores).
const DRAIN_HISTORY_START: u64 = 2;
/// Anchors no store in the rigs holds at [`DRAIN_FRAME`]: the frame itself,
/// the next, far ahead, the largest number, and one below the held history.
const DRAIN_UNHELD_ANCHORS: [u64; 5] = [DRAIN_FRAME, DRAIN_FRAME + 1, 1_000_000, u64::MAX, 1];
/// Validations and executions of each submission, as the materializer
/// retries a failed frame.
const DRAIN_RETRIES: usize = 3;

/// The output GLOBAL frame `number` has in the rigs' clock stores.
fn drain_global_output(number: u64) -> Vec<u8> {
    vec![0x40 ^ (number as u8); 32]
}

/// `frame` as GLOBAL carries it, its anchor included.
fn canonical_anchored(frame: &AppShardFrame) -> CanonicalHeader {
    let mut header = canonical(frame);
    header.global_frame_number = frame.header.as_ref().unwrap().global_frame_number;
    header
}

/// One submission as the GLOBAL message bundle a leader packs.
fn handoff_bundle(sealed: &[u8]) -> Vec<u8> {
    quil_execution::message_envelope::CanonicalMessageBundle {
        requests: vec![Some(
            quil_execution::message_envelope::CanonicalMessageRequest {
                inner_type_prefix: handoff::TYPE_COMMITTEE_HANDOFF,
                inner_bytes: sealed.to_vec(),
            },
        )],
        timestamp: 0,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// A session whose frame 1 GLOBAL executed and whose frame 2, anchored to
/// GLOBAL frame `anchor`, missed its window; a successor scheduled and the
/// session's seal at frame 2. GLOBAL runs it as an archive does: the clock
/// store holds GLOBAL frames 2 to 9, the engine manager has the frame-header
/// dependencies, and seal drains are active from GLOBAL frame 6.
struct DrainRig {
    keys: Vec<FalconPrivateKey>,
    source: Session,
    fixture: Fixture,
    intrinsic: GlobalIntrinsic,
    manager: quil_execution::ExecutionEngineManager,
    /// Frame 1, which GLOBAL executed.
    first: CanonicalHeader,
    /// Frame 2: certified by the session, or only notarized, which the seal
    /// certifies from the checkpoint drain frame.
    header: CanonicalHeader,
    submission: CertificateSubmission,
}

impl DrainRig {
    fn new(anchor: u64, certified: bool) -> Self {
        Self::with_hole(anchor, certified, None)
    }

    /// [`Self::new`] on a store that lacks GLOBAL frame `hole`.
    fn with_hole(anchor: u64, certified: bool, hole: Option<u64>) -> Self {
        std::env::set_var(
            "QUIL_SEAL_DRAIN_ANCHOR_FLOOR",
            DRAIN_HISTORY_START.to_string(),
        );
        let keys = keys();
        let source = session(&keys, vec![0x66; 32]);
        let fixture = Fixture::new(&source);
        for number in DRAIN_HISTORY_START..DRAIN_FRAME {
            if Some(number) != hole {
                store_global_frame(&fixture, number, &drain_global_output(number));
            }
        }
        let intrinsic = fixture.intrinsic();
        handoff::initialize(&fixture.state, 2, &source).unwrap();
        commit(&fixture.state, 2);
        let first = first_frame(&source, &keys);
        let first_wire = canonical(&first);
        intrinsic
            .invoke_step(3, &first_wire.to_canonical_bytes().unwrap(), &fixture.state)
            .unwrap();
        commit(&fixture.state, 3);
        let parent = first.header.as_ref().unwrap();
        let mut frame = anchored_frame(
            &source,
            &keys,
            2,
            7,
            5,
            quil_crypto::poseidon::hash_bytes_to_32(&parent.output)
                .unwrap()
                .to_vec(),
            anchor,
            &if anchor == 0 {
                Vec::new()
            } else {
                drain_global_output(anchor)
            },
        );
        if !certified {
            frame.header.as_mut().unwrap().public_key_signature_bls48581 = None;
        }
        let header = canonical_anchored(&frame);
        let request = handoff::schedule(
            &fixture.state,
            4,
            vec![source.filter.clone()],
            vec![DesiredCommittee {
                filter: source.filter.clone(),
                members: session(&self::keys(), source.filter.clone()).members,
            }],
        )
        .unwrap();
        commit(&fixture.state, 4);
        let seal = Seal {
            request: request.id().unwrap(),
            session: source.id().unwrap(),
            view: 11,
            checkpoint: Checkpoint {
                frame: 2,
                view: 7,
                digest: quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap(),
                state_roots: [[0; 32]; 4],
                history_root: [0x66; 32],
            },
        };
        let submission = CertificateSubmission {
            certificate: sign(&source, &keys, 11, 7, seal.digest()),
            seal,
        };
        handoff::set_seal_drain_frame_for_thread(Some(6));
        handoff::set_seal_checkpoint_drain_frame_for_thread(if certified { None } else { Some(6) });
        let crypto = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = quil_execution::ExecutionEngineManager::new(
            fixture.inclusion.clone(),
            crypto.key_manager,
            fixture.state.crdt().clone(),
            crypto.circuit_compiler,
            fixture.clock.clone(),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            true,
        );
        manager
            .install_global_frame_header_deps(
                fixture.registry.clone(),
                Arc::new(ZeroRewards),
                Arc::new(quil_crypto::FalconKeyConstructor),
                fixture.inclusion.clone(),
                fixture.prover.clone(),
            )
            .unwrap();
        Self {
            keys,
            source,
            fixture,
            intrinsic,
            manager,
            first: first_wire,
            header,
            submission,
        }
    }

    /// The rig's frame 2 with its anchor rewritten, nothing else changed.
    fn rewritten(&self, anchor: u64) -> CanonicalHeader {
        let mut header = self.header.clone();
        header.global_frame_number = anchor;
        header
    }

    fn sealed(&self, submission: &CertificateSubmission, drain: &[&CanonicalHeader]) -> Vec<u8> {
        handoff::SealSubmission {
            submission: submission.clone(),
            drain: drain
                .iter()
                .map(|header| header.to_canonical_bytes().unwrap())
                .collect(),
        }
        .to_canonical_bytes()
        .unwrap()
    }

    /// The rig's seal with a closing certificate the session never signed.
    fn forged(&self) -> CertificateSubmission {
        let mut forged = self.submission.clone();
        forged.certificate = sign(&self.source, &self.keys, 11, 6, forged.seal.digest());
        forged
    }

    /// What GLOBAL frame [`DRAIN_FRAME`] makes of `sealed` on each retry:
    /// the engine's validation (the leader's filter and the materializer's
    /// first step), then the intrinsic's execution (rolled back on error).
    fn outcomes(&self, sealed: &[u8]) -> Vec<Result<()>> {
        let global = quil_execution::domains::GLOBAL;
        let bundle = handoff_bundle(sealed);
        let mut outcomes = Vec::new();
        for _ in 0..DRAIN_RETRIES {
            outcomes.push(self.manager.validate_message(DRAIN_FRAME, &global, &bundle));
            outcomes.push(
                self.intrinsic
                    .invoke_step(DRAIN_FRAME, sealed, &self.fixture.state),
            );
        }
        outcomes
    }

    /// The genuine seal and header pass validation where the rig checks
    /// them, so a refusal below is the anchor's doing.
    fn check_setup(&self) {
        let honest = self.sealed(&self.submission, &[&self.header]);
        let global = quil_execution::domains::GLOBAL;
        let engine = self
            .manager
            .validate_message(DRAIN_FRAME, &global, &handoff_bundle(&honest));
        let intrinsic = self.intrinsic.validate(DRAIN_FRAME, &honest, None, None);
        assert!(
            engine.is_ok() && matches!(intrinsic, Ok(true)),
            "SD SETUP: GLOBAL frame {DRAIN_FRAME} must admit the genuine seal and drain \
             header (engine {engine:?}, intrinsic {intrinsic:?})"
        );
    }
}

/// Which of `anchors` fail GLOBAL frame [`DRAIN_FRAME`] as unavailable on
/// every retry when `rig`'s drain header names them, under `submission`.
fn drain_halts(
    rig: &DrainRig,
    submission: &CertificateSubmission,
    anchors: &[u64],
) -> Vec<(u64, String)> {
    let mut halts = Vec::new();
    for &anchor in anchors {
        let outcomes = rig.outcomes(&rig.sealed(submission, &[&rig.rewritten(anchor)]));
        if let Some(admitted) = outcomes.iter().position(|outcome| outcome.is_ok()) {
            panic!(
                "SD UNEXPECTED: GLOBAL frame {DRAIN_FRAME} admitted the drain header with its \
                 anchor rewritten to {anchor} (outcome {admitted})"
            );
        }
        let unavailable = outcomes
            .iter()
            .filter(|outcome| {
                outcome
                    .as_ref()
                    .is_err_and(|error| error.is_execution_unavailable())
            })
            .count();
        if unavailable == outcomes.len() {
            halts.push((anchor, outcomes[0].as_ref().unwrap_err().to_string()));
        } else if unavailable > 0 {
            panic!(
                "SD UNEXPECTED: anchor {anchor} is unavailable on {unavailable} of {} \
                 retries only: {outcomes:?}",
                outcomes.len()
            );
        }
    }
    halts
}

fn assert_no_drain_halt(halts: &[(u64, String)], what: &str) {
    assert!(
        halts.is_empty(),
        "SD HALT: GLOBAL frame {DRAIN_FRAME} fails as unavailable on every retry ({DRAIN_RETRIES} \
         engine validations and executions each) for {what}, for {} of {} anchors no node \
         holds; the materializer fails the whole frame on such an error, so every archive \
         stops there: {:?}",
        halts.len(),
        DRAIN_UNHELD_ANCHORS.len(),
        halts
            .iter()
            .map(|(anchor, error)| format!("{anchor}: {error}"))
            .collect::<Vec<_>>()
    );
}

/// A genuine session-certified drain header, its anchor rewritten to a frame
/// no node holds: the certificate does not cover the anchor, and the output
/// check reads it first.
#[test]
fn seal_drain_halt_a_certified_header_with_its_anchor_rewritten_fails_every_retry() {
    let rig = DrainRig::new(DRAIN_ANCHOR, true);
    rig.check_setup();
    let halts = drain_halts(&rig, &rig.submission, &DRAIN_UNHELD_ANCHORS);
    assert_no_drain_halt(
        &halts,
        "a genuine certified drain header with its anchor rewritten",
    );
}

/// The same header under a closing certificate the session never signed: the
/// drain is checked before the seal, so no valid seal is needed. The genuine
/// header under that certificate is refused deterministically.
#[test]
fn seal_drain_halt_the_drain_is_read_before_the_closing_certificate() {
    let rig = DrainRig::new(DRAIN_ANCHOR, true);
    rig.check_setup();
    let forged = rig.forged();
    for outcome in rig.outcomes(&rig.sealed(&forged, &[&rig.header])) {
        match outcome {
            Err(error) if !error.is_execution_unavailable() => {}
            other => panic!(
                "SD SETUP: the genuine header under a forged closing certificate must be \
                 refused deterministically, got {other:?}"
            ),
        }
    }
    let halts = drain_halts(&rig, &forged, &DRAIN_UNHELD_ANCHORS);
    assert_no_drain_halt(
        &halts,
        "a genuine certified drain header with its anchor rewritten, under a forged closing \
         certificate",
    );
}

/// A notarized checkpoint header the seal certifies by its output digest,
/// its anchor rewritten.
#[test]
fn seal_drain_halt_a_seal_certified_checkpoint_header_with_its_anchor_rewritten_fails() {
    let rig = DrainRig::new(DRAIN_ANCHOR, false);
    rig.check_setup();
    let halts = drain_halts(&rig, &rig.submission, &DRAIN_UNHELD_ANCHORS);
    assert_no_drain_halt(
        &halts,
        "a notarized checkpoint header the seal certifies, with its anchor rewritten",
    );
}

/// A frame the hole rigs' stores lack, above the network's first frame.
const DRAIN_HOLE: u64 = 8;
/// The oldest anchor once drain anchors are raised past [`DRAIN_HOLE`].
const DRAIN_RAISED_FLOOR: u64 = 9;

/// Every archive's history has holes above its first frame, so a floor at
/// that first frame leaves them: a genuine header, its anchor rewritten into
/// one, fails the frame as unavailable on every retry. Raising the floor
/// past the hole from a frame before [`DRAIN_FRAME`] refuses it. The
/// settings are environment variables, which a build without the raise
/// ignores, so this runs on that build too and halts there.
#[test]
fn seal_drain_halt_an_anchor_in_a_hole_of_the_history_fails_every_retry() {
    std::env::set_var("QUIL_SEAL_DRAIN_ANCHOR_RAISE_FRAME", "6");
    std::env::set_var(
        "QUIL_SEAL_DRAIN_ANCHOR_RAISED_FLOOR_FRAME",
        DRAIN_RAISED_FLOOR.to_string(),
    );
    for certified in [true, false] {
        let rig = DrainRig::with_hole(DRAIN_RAISED_FLOOR, certified, Some(DRAIN_HOLE));
        rig.check_setup();
        let halts = drain_halts(&rig, &rig.submission, &[DRAIN_HOLE]);
        assert_no_drain_halt(
            &halts,
            "a genuine drain header with its anchor rewritten into a hole of the history",
        );
    }
    eprintln!("SD HOLE: an anchor in a hole of the history is refused");
}

/// From the raise's frame a genuine header anchored to a held frame under the
/// raised floor is refused, deterministically; one at the floor still executes.
#[test]
fn seal_drain_raise_refuses_a_held_anchor_below_it_and_admits_its_edge() {
    for certified in [true, false] {
        let below = DrainRig::new(DRAIN_ANCHOR, certified);
        handoff::set_drain_anchor_raise_for_thread(Some((6, DRAIN_RAISED_FLOOR)));
        let genuine = below.sealed(&below.submission, &[&below.header]);
        for outcome in below.outcomes(&genuine) {
            match outcome {
                Err(quil_types::error::QuilError::InvalidArgument(reason))
                    if reason.contains("older than any committee session") => {}
                other => panic!(
                    "SD RAISE: anchor {DRAIN_ANCHOR} (certified {certified}) must be refused \
                     as older than any session, got {other:?}"
                ),
            }
        }
        let edge = DrainRig::new(DRAIN_RAISED_FLOOR, certified);
        edge.check_setup();
        edge.intrinsic
            .invoke_step(
                DRAIN_FRAME,
                &edge.sealed(&edge.submission, &[&edge.header]),
                &edge.fixture.state,
            )
            .unwrap_or_else(|error| {
                panic!("SD RAISE: a drain anchored at the raised floor must execute: {error}")
            });
        handoff::set_drain_anchor_raise_for_thread(None);
    }
}

/// Before the raise's frame every build agrees as before: a genuine header
/// under the raised floor executes, and an anchor in a hole stays unavailable.
#[test]
fn seal_drain_raise_changes_nothing_before_its_frame() {
    for certified in [true, false] {
        let rig = DrainRig::with_hole(DRAIN_ANCHOR, certified, Some(DRAIN_HOLE));
        handoff::set_drain_anchor_raise_for_thread(Some((DRAIN_FRAME + 1, DRAIN_RAISED_FLOOR)));
        rig.check_setup();
        let halts = drain_halts(&rig, &rig.submission, &[DRAIN_HOLE]);
        assert_eq!(
            halts.len(),
            1,
            "SD RAISE: a hole stays unavailable before the raise's frame"
        );
        rig.intrinsic
            .invoke_step(
                DRAIN_FRAME,
                &rig.sealed(&rig.submission, &[&rig.header]),
                &rig.fixture.state,
            )
            .unwrap_or_else(|error| {
                panic!("SD RAISE: a genuine drain under the floor must execute before: {error}")
            });
        handoff::set_drain_anchor_raise_for_thread(None);
    }
}

/// From the raise's frame a drain header must name an anchor, as voters have
/// required of every frame since the required-anchor epoch; a quorum's header
/// naming none is refused deterministically, and before the frame it is
/// admitted as before. A build without the rule executes it.
#[test]
fn seal_drain_raise_refuses_a_header_naming_no_anchor() {
    for certified in [true, false] {
        let rig = DrainRig::new(0, certified);
        handoff::set_drain_anchor_raise_for_thread(Some((DRAIN_FRAME + 1, DRAIN_RAISED_FLOOR)));
        rig.check_setup();
        handoff::set_drain_anchor_raise_for_thread(Some((6, DRAIN_RAISED_FLOOR)));
        let sealed = rig.sealed(&rig.submission, &[&rig.header]);
        for outcome in rig.outcomes(&sealed) {
            match outcome {
                Err(quil_types::error::QuilError::InvalidArgument(reason))
                    if reason.contains("anchor 0, which names no frame") => {}
                other => panic!(
                    "SD ZERO: GLOBAL frame {DRAIN_FRAME}, past the raise's frame, must refuse \
                     a drain header naming no anchor (certified {certified}), got {other:?}"
                ),
            }
        }
        handoff::set_drain_anchor_raise_for_thread(None);
    }
    eprintln!("SD ZERO: a drain header naming no anchor is refused from the raise's frame");
}

/// A genuine drain, certified by the session or by the seal, is admitted
/// and executed: the session's tip moves to the checkpoint.
#[test]
fn seal_drain_control_a_genuine_drain_header_is_admitted_and_executed() {
    for certified in [true, false] {
        let rig = DrainRig::new(DRAIN_ANCHOR, certified);
        rig.check_setup();
        let honest = rig.sealed(&rig.submission, &[&rig.header]);
        rig.intrinsic
            .invoke_step(DRAIN_FRAME, &honest, &rig.fixture.state)
            .unwrap_or_else(|error| {
                panic!("control: the genuine drain (certified {certified}) must execute: {error}")
            });
        let tip = handoff::session_tip(&rig.fixture.state, &rig.source.id().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(tip.frame, 2, "control: the drain reached the checkpoint");
    }
    eprintln!("SD CONTROL: genuine drains are admitted and executed");
}

/// A rewritten anchor that the node holds is refused deterministically: the
/// output no longer matches its frame's.
#[test]
fn seal_drain_control_a_held_wrong_anchor_is_refused_deterministically() {
    for certified in [true, false] {
        let rig = DrainRig::new(DRAIN_ANCHOR, certified);
        rig.check_setup();
        for anchor in [DRAIN_HISTORY_START, 7, DRAIN_FRAME - 1] {
            let sealed = rig.sealed(&rig.submission, &[&rig.rewritten(anchor)]);
            for outcome in rig.outcomes(&sealed) {
                match outcome {
                    Err(error) if !error.is_execution_unavailable() => {}
                    other => panic!(
                        "control: a held wrong anchor {anchor} (certified {certified}) must be \
                         refused deterministically, got {other:?}"
                    ),
                }
            }
        }
    }
    eprintln!("SD CONTROL: held wrong anchors are refused deterministically");
}

/// A drain header GLOBAL already executed is passed over unread, its anchor
/// included: the submission is admitted whatever that anchor names.
#[test]
fn seal_drain_control_a_passed_over_header_is_never_read() {
    let rig = DrainRig::new(DRAIN_ANCHOR, true);
    rig.check_setup();
    let global = quil_execution::domains::GLOBAL;
    for anchor in DRAIN_UNHELD_ANCHORS {
        let mut first = rig.first.clone();
        first.global_frame_number = anchor;
        let sealed = rig.sealed(&rig.submission, &[&first, &rig.header]);
        let engine = rig
            .manager
            .validate_message(DRAIN_FRAME, &global, &handoff_bundle(&sealed));
        assert!(
            engine.is_ok(),
            "control: an executed header anchored to {anchor} is passed over: {engine:?}"
        );
    }
    eprintln!("SD CONTROL: passed-over drain headers are never read");
}

/// Every anchor no node holds is refused before it is read, by a
/// deterministic error naming it, whichever certificate covers the header.
#[test]
fn seal_drain_fix_refuses_anchors_no_node_holds_before_reading_them() {
    for certified in [true, false] {
        let rig = DrainRig::new(DRAIN_ANCHOR, certified);
        rig.check_setup();
        for anchor in DRAIN_UNHELD_ANCHORS {
            let sealed = rig.sealed(&rig.submission, &[&rig.rewritten(anchor)]);
            for outcome in rig.outcomes(&sealed) {
                match outcome {
                    Err(quil_types::error::QuilError::InvalidArgument(reason))
                        if reason.contains("a frame no node holds")
                            && reason.contains(&format!("anchor {anchor},")) => {}
                    other => panic!(
                        "SD FIX: anchor {anchor} (certified {certified}) must be refused as one \
                         no node holds, got {other:?}"
                    ),
                }
            }
        }
    }
    eprintln!("SD FIX: anchors no node holds are refused before the read");
}

/// Genuine drain headers anchored at both edges of what GLOBAL frame
/// [`DRAIN_FRAME`] admits, the network's first frame and the frame before
/// it, are admitted and executed.
#[test]
fn seal_drain_fix_admits_genuine_anchors_at_both_edges() {
    for anchor in [DRAIN_HISTORY_START, DRAIN_FRAME - 1] {
        for certified in [true, false] {
            let rig = DrainRig::new(anchor, certified);
            rig.check_setup();
            let honest = rig.sealed(&rig.submission, &[&rig.header]);
            rig.intrinsic
                .invoke_step(DRAIN_FRAME, &honest, &rig.fixture.state)
                .unwrap_or_else(|error| {
                    panic!(
                        "SD FIX: a genuine drain anchored to {anchor} (certified {certified}) \
                         must execute: {error}"
                    )
                });
        }
    }
    eprintln!("SD FIX: genuine anchors at both edges are admitted and executed");
}
