use super::*;
use crate::cw_global_seams::GlobalSeamProposer;
use crate::frame_validator::GlobalFrameVerifier;
use crate::leader_provider::GlobalLeaderProvider;
use crate::message_collector::MessageCollector;
use quil_cw_consensus::adapters::{
    digest_from_identity, BlockStore, Digest, GlobalProposer, ProposalContext,
};
use quil_types::crypto::{FrameProver, Signer};
use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};

#[path = "frame_materializer_finalization_tests.rs"]
mod finalization_tests;
#[path = "frame_materializer_pipeline_tests.rs"]
mod pipeline_tests;

// Structure-only VDF service: these tests exercise actual state execution and
// the consensus adapter, not the cryptographic VDF implementation.
struct TestFrameProver;
impl FrameProver for TestFrameProver {
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
    ) -> Result<quil_types::proto::global::FrameHeader> {
        unreachable!()
    }
    fn prove_global_frame_header(
        &self,
        parent: &GlobalFrameHeader,
        commitments: &[Vec<u8>],
        root: &[u8],
        auxiliary: &[Vec<u8>],
        requests: &[u8],
        size: u64,
        _: &dyn Signer,
        timestamp: i64,
        difficulty: u32,
        _: u8,
    ) -> Result<GlobalFrameHeader> {
        Ok(GlobalFrameHeader {
            frame_number: parent.frame_number + 1,
            output: vec![(parent.frame_number + 33) as u8; 516],
            parent_selector: id_header(parent).as_ref().to_vec(),
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
    fn verify_global_frame_header(&self, h: &GlobalFrameHeader) -> Result<Vec<u8>> {
        if h.output.len() != 516 || h.output[0] == 0xfe {
            return Err(QuilError::InvalidArgument("test VDF rejected".into()));
        }
        Ok(h.output.clone())
    }
    fn calculate_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: u32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
    fn verify_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: &[&[u8]]) -> Result<bool> {
        Ok(true)
    }
}

fn id_header(header: &GlobalFrameHeader) -> Digest {
    digest_from_identity(quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap())
}
fn id(frame: &GlobalFrame) -> Digest {
    id_header(frame.header.as_ref().unwrap())
}
fn body_root(frame: &mut GlobalFrame) {
    let bytes: Vec<_> = frame
        .requests
        .iter()
        .map(|b| crate::consensus_wire::proto_message_bundle_to_canonical_bytes(b).unwrap())
        .collect();
    frame.header.as_mut().unwrap().requests_root =
        crate::leader_provider::compute_global_requests_root(
            &bytes,
            &quil_tries::ShaInclusionProver,
        );
}
fn state_frame(source: &FrameMaterializer, number: u64, rank: u64, parent: Digest) -> GlobalFrame {
    let crdt = &source.hypergraph;
    let mut result = frame(
        number,
        crdt.current_forest_phase_root(&[0xff; 32], 0).unwrap(),
    );
    let h = result.header.as_mut().unwrap();
    h.rank = rank;
    h.parent_selector = parent.as_ref().to_vec();
    h.prover_tree_aux_roots = vec![
        crdt.current_forest_phase_root(&[0xff; 32], 1)
            .unwrap()
            .to_vec(),
        Vec::new(),
        crdt.current_forest_phase_root(&[0xff; 32], 3)
            .unwrap()
            .to_vec(),
    ];
    h.global_commitments = crdt.global_commitments_checked().unwrap();
    h.world_state_size = crdt.total_size().to_u64().unwrap();
    result.requests.clear();
    body_root(&mut result);
    result
}
fn save(clock: &dyn ClockStore, frame: &GlobalFrame) {
    let txn = clock.new_transaction(false).unwrap();
    clock.put_global_clock_frame(frame, txn.as_ref()).unwrap();
    txn.commit().unwrap();
}

struct Rig {
    db: Arc<quil_store::RocksDb>,
    source: Arc<FrameMaterializer>,
    clock: Arc<quil_store::RocksClockStore>,
    collector: Arc<MessageCollector>,
    signer: Arc<quil_crypto::FalconSigner>,
    leader: Arc<GlobalLeaderProvider>,
    verifier: Arc<GlobalFrameVerifier>,
    executor: Arc<GlobalParentExecutor>,
    blocks: BlockStore,
    genesis: Digest,
}
impl Rig {
    fn new() -> Self {
        let signer = Arc::new(quil_crypto::FalconSigner::generate());
        let fixture = Fixture::new(Some(signer.public_key()));
        let source = Arc::new(fixture.source);
        let genesis_frame = state_frame(&source, 0, 0, digest_from_identity([0; 32]));
        let genesis = id(&genesis_frame);
        save(fixture.clock.as_ref(), &genesis_frame);
        let collector = Arc::new(MessageCollector::new());
        let leader = Arc::new(GlobalLeaderProvider::new(
            source.prover_registry.clone(),
            Arc::new(TestFrameProver),
            Arc::new(crate::difficulty::AsertDifficultyAdjuster::new(0, 0, 100)),
            fixture.clock.clone(),
            collector.clone(),
            quil_crypto::poseidon::hash_bytes_to_32(signer.public_key())
                .unwrap()
                .to_vec(),
            signer.public_key().to_vec(),
            signer.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
            Some(source.execution_manager.clone()),
            Some(source.hypergraph.clone()),
        ));
        let verifier = Arc::new(
            GlobalFrameVerifier::new(Arc::new(TestFrameProver))
                .with_global_committee(vec![signer.public_key().to_vec()]),
        );
        let executor = Arc::new(GlobalParentExecutor::new(
            source.clone(),
            leader.clone(),
            0,
            0,
            genesis,
            GlobalParentLimits {
                branch: limits(),
                ..GlobalParentLimits::default()
            },
        ));
        Self {
            db: fixture.db,
            source,
            clock: fixture.clock,
            collector,
            signer,
            leader,
            verifier,
            executor,
            blocks: BlockStore::new(),
            genesis,
        }
    }
    fn context(&self, parent: &GlobalFrame) -> ProposalContext {
        ProposalContext {
            epoch: 0,
            view: 73,
            parent_view: parent.header.as_ref().unwrap().rank,
            parent: id(parent),
        }
    }
    fn put(&self, frame: &GlobalFrame) {
        self.blocks.put(
            id(frame),
            crate::consensus_wire::encode_global_frame(frame).unwrap(),
        );
    }
    fn seam(&self, parent: &GlobalFrame) -> GlobalSeamProposer {
        let seam = GlobalSeamProposer::new(
            self.leader.clone(),
            self.verifier.clone(),
            vec![],
            self.clock.clone(),
            None,
        )
        .with_block_store(self.blocks.clone())
        .with_selected_execution(self.executor.clone());
        seam.note_frame(id(parent), parent.header.as_ref().unwrap().frame_number);
        seam
    }
    fn deploy(&self) -> GlobalFrame {
        let config = quil_execution::token_intrinsic::config::TokenConfiguration {
            behavior: quil_execution::token_intrinsic::constants::DIVISIBLE as u32,
            name: b"selected-parent token".to_vec(),
            owner_public_key: vec![1; 32],
            ..Default::default()
        };
        let deploy = quil_execution::token_intrinsic::TokenDeploy {
            config: config.to_canonical_bytes().unwrap(),
            rdf_schema: Vec::new(),
        };
        let mut frame = state_frame(&self.source, 1, 41, self.genesis);
        frame
            .requests
            .push(quil_types::proto::global::MessageBundle {
                requests: vec![quil_types::proto::global::MessageRequest {
                    request: Some(
                        quil_types::proto::global::message_request::Request::TokenDeploy(
                            quil_execution::token_intrinsic::conversions::token_deploy_to_proto(
                                &deploy,
                            )
                            .unwrap(),
                        ),
                    ),
                    ..Default::default()
                }],
                ..Default::default()
            });
        body_root(&mut frame);
        frame
    }
}

#[test]
fn selected_parent_proposal_and_vote_use_executed_state_without_publishing_it() {
    let _tracing = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .finish(),
    );
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let expected = Fixture::new(Some(rig.signer.public_key()));
    let outcome = expected.source.materialize(&parent).unwrap();
    assert_eq!(outcome.processed, 1);
    let context = rig.context(&parent);
    let expected_child = state_frame(&expected.source, 2, context.view, context.parent);
    assert_ne!(
        expected_child.header.as_ref().unwrap().global_commitments,
        parent.header.as_ref().unwrap().global_commitments
    );
    let raw = crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&parent.requests[0])
        .unwrap();
    assert!(rig.collector.add_message(1, raw));
    assert!(rig.collector.add_message(1, vec![1, 2, 3]));
    let sequence = rig.db.inner().latest_sequence_number();
    {
        let lease = rig
            .executor
            .prepare(context, 1, &rig.blocks, &rig.verifier, true)
            .unwrap();
        assert!(lease.matches_child(expected_child.header.as_ref().unwrap()));
        assert!(rig
            .executor
            .prepare(context, 1, &rig.blocks, &rig.verifier, false)
            .is_err());
        let state = lease.prove(&[]).unwrap();
        assert_eq!(
            state.state.prover_tree_aux_roots,
            expected_child
                .header
                .as_ref()
                .unwrap()
                .prover_tree_aux_roots
        );
        assert_eq!(
            state.state.prover_tree_commitment,
            expected_child
                .header
                .as_ref()
                .unwrap()
                .prover_tree_commitment
        );
        assert_eq!(
            state.state.world_state_size,
            expected_child.header.as_ref().unwrap().world_state_size
        );
        assert!(
            state.state.messages.is_empty(),
            "ancestor input and invalid bytes only leave the private pool"
        );
        assert_eq!(
            state.state.global_commitments,
            expected_child.header.as_ref().unwrap().global_commitments
        );
        assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    }
    let seam = rig.seam(&parent);
    assert!(
        seam.propose(context.view, context.parent).is_none(),
        "full Simplex context is mandatory"
    );
    let (digest, bytes) = seam
        .propose_with_context(context)
        .expect("build on executed unfinalized parent");
    let proposed = crate::consensus_wire::decode_global_frame(&bytes).unwrap();
    assert_eq!(
        proposed.header.as_ref().unwrap().global_commitments,
        expected_child.header.as_ref().unwrap().global_commitments
    );
    assert!(seam.verify_with_context(context, digest, Some(bytes)));
    assert_eq!(rig.source.last_materialized_frame(), 0);
    assert_eq!(rig.source.current_frame.as_ref().unwrap().materialized(), 0);
    assert_eq!(
        rig.clock
            .get_latest_global_clock_frame()
            .unwrap()
            .header
            .unwrap()
            .frame_number,
        0
    );
    assert_eq!(
        rig.collector.total_pending(),
        2,
        "private proposal must not remove or age out public messages"
    );
    assert_eq!(
        rig.source.hypergraph.global_commitments_checked().unwrap(),
        parent.header.unwrap().global_commitments
    );
}

// After the split at 837360 each proposal for 837364 validated the same 36
// refused messages again: proposals validate a private copy of the mempool,
// and the public pool keeps what they refuse.
#[test]
fn a_refusal_in_one_proposal_spares_the_next_on_the_same_parent() {
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let context = rig.context(&parent);
    let confirm = quil_execution::global_intrinsic::ProverConfirm {
        filter: Vec::new(),
        // Signed far outside the inclusion epoch.
        frame_number: 10_000_000,
        public_key_signature_bls48581: Some(quil_execution::global_intrinsic::AddressedSignature {
            signature: vec![0; quil_execution::global_intrinsic::AddressedSignature::SIG_LEN_SINGLE],
            address: vec![9; 32],
        }),
        filters: vec![vec![1; 32]],
        leaf_roots: Vec::new(),
    };
    let bundle = quil_types::proto::global::MessageBundle {
        requests: vec![quil_types::proto::global::MessageRequest {
            request: Some(quil_types::proto::global::message_request::Request::Confirm(
                quil_execution::global_intrinsic::conversions::prover_confirm_to_proto(&confirm),
            )),
            ..Default::default()
        }],
        ..Default::default()
    };
    let once = crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&bundle).unwrap();
    let decoded = crate::consensus_wire::decode_message_bundle(&once).unwrap();
    let raw = crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&decoded).unwrap();
    assert_eq!(raw, once, "a canonical bundle reaches validation");
    assert!(rig.collector.add_message(1, raw.clone()));
    for proposal in 0..2 {
        let lease = rig
            .executor
            .prepare(context, 1, &rig.blocks, &rig.verifier, true)
            .unwrap();
        let state = lease.prove(&[]).unwrap();
        assert!(state.state.messages.is_empty());
        let reason = rig.leader.refused_message(&raw).expect("the branch's refusal is the node's");
        assert!(reason.contains("inclusion epoch"), "{reason}");
        assert_eq!(rig.leader.refusals_reused(), proposal, "validated only by the first proposal");
    }
    assert_eq!(rig.collector.total_pending(), 1, "the public pool keeps it");
}

#[test]
fn selected_parent_rejects_context_ancestry_body_and_state_substitution() {
    let rig = Rig::new();
    let parent = rig.deploy();
    let context = rig.context(&parent);
    let sequence = rig.db.inner().latest_sequence_number();
    rig.put(&parent);
    for field in 0..3 {
        let mut bad = context;
        match field {
            0 => bad.epoch += 1,
            1 => bad.parent_view += 1,
            _ => bad.parent_view = bad.view,
        }
        assert!(rig
            .executor
            .prepare(bad, 1, &rig.blocks, &rig.verifier, false)
            .is_err());
    }
    for field in 0..8 {
        let mut bad = parent.clone();
        let h = bad.header.as_mut().unwrap();
        match field {
            0 => h.frame_number += 1,
            1 => h.parent_selector[0] ^= 1,
            2 => h.rank = context.view,
            3 => h.prover_tree_commitment[7] ^= 1,
            4 => h.prover_tree_aux_roots[0][0] ^= 1,
            5 => h.prover_tree_aux_roots[2][0] ^= 1,
            6 => bad.requests.clear(),
            _ => h.output = vec![0xfe; 516],
        }
        let blocks = BlockStore::new();
        blocks.put(
            context.parent,
            crate::consensus_wire::encode_global_frame(&bad).unwrap(),
        );
        assert!(
            rig.executor
                .prepare(context, 1, &blocks, &rig.verifier, false)
                .is_err(),
            "substitution {field}"
        );
        // A rejected attempt must release both storage and admission.
        assert!(rig
            .executor
            .prepare(context, 1, &rig.blocks, &rig.verifier, false)
            .is_ok());
        // That attempt authenticated the real parent; the next substitution
        // must be read to be rejected.
        rig.executor.forget_authenticated_ancestors();
    }
    // Once authenticated, the parent is used as it is: a substituted body
    // at its identity is never read.
    assert!(rig.executor.prepare(context, 1, &rig.blocks, &rig.verifier, false).is_ok());
    let mut bad = parent.clone();
    bad.requests.clear();
    let blocks = BlockStore::new();
    blocks.put(context.parent, crate::consensus_wire::encode_global_frame(&bad).unwrap());
    assert!(rig.executor.prepare(context, 1, &blocks, &rig.verifier, false).is_ok());
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
}

/// A leader waits out its interval pacing before preparing a proposal, so it
/// does not hold the execution lease through it: the wait runs until the
/// selected parent's timestamp, at most one interval.
#[test]
fn proposal_pacing_runs_until_the_parent_timestamp_and_no_longer_than_an_interval() {
    use quil_cw_consensus::adapters::GlobalProposer as _;
    let rig = Rig::new();
    let parent = rig.deploy();
    let seam = rig.seam(&parent);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let pacing = |timestamp: i64| {
        let mut paced = parent.clone();
        paced.header.as_mut().unwrap().timestamp = timestamp;
        rig.put(&paced);
        seam.proposal_pacing(rig.context(&paced))
    };
    let wait = pacing(now_ms + 5_000).expect("a parent five seconds ahead");
    assert!(wait > std::time::Duration::from_millis(4_000) && wait <= std::time::Duration::from_millis(5_000), "{wait:?}");
    assert_eq!(pacing(now_ms + 60_000), Some(std::time::Duration::from_millis(10_000)), "one interval at most");
    assert_eq!(pacing(now_ms - 1_000), None, "a parent in the past needs none");
    assert_eq!(crate::leader_provider::proposal_pacing_wait(0, 5), std::time::Duration::ZERO);
}

/// A voter whose own execution is busy (a proposal, verification or
/// publication holds the lease, or the materializer holds the frame lock)
/// defers instead of rejecting, then votes on the same proposal once free.
/// A proposal that fails its checks is still rejected at once.
#[test]
fn a_busy_voter_defers_and_then_votes_on_the_same_proposal() {
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let context = rig.context(&parent);
    let child = state_frame(&expected.source, 2, context.view, context.parent);
    let encoded = crate::consensus_wire::encode_global_frame(&child).unwrap();
    let seam = rig.seam(&parent);

    let lease = rig.executor.prepare(context, 1, &rig.blocks, &rig.verifier, false).unwrap();
    assert!(rig.executor.busy());
    assert!(seam.verify_or_defer(context, id(&child), Some(encoded.clone())).is_err());
    assert!(!seam.verify_with_context(context, id(&child), Some(encoded.clone())), "no deferral: no vote");
    drop(lease);

    let frame_lock = rig.source.frame_execution.lock().unwrap();
    assert!(rig.executor.busy());
    assert!(seam.verify_or_defer(context, id(&child), Some(encoded.clone())).is_err());
    drop(frame_lock);

    assert!(!rig.executor.busy());
    let mut bad = child.clone();
    bad.header.as_mut().unwrap().frame_number += 1;
    let bad_bytes = crate::consensus_wire::encode_global_frame(&bad).unwrap();
    assert_eq!(seam.verify_or_defer(context, id(&bad), Some(bad_bytes)), Ok(false));
    assert_eq!(seam.verify_or_defer(context, id(&child), Some(encoded)), Ok(true));
    assert!(!rig.executor.busy(), "a vote releases the lease");
}

#[test]
fn selected_parent_bounds_ancestry_and_releases_admission_on_unwind() {
    let rig = Rig::new();
    let parent = rig.deploy();
    let context = rig.context(&parent);
    rig.put(&parent);
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let second = state_frame(&expected.source, 2, 42, id(&parent));
    rig.put(&second);
    assert!(rig
        .executor
        .prepare(rig.context(&second), 2, &rig.blocks, &rig.verifier, false)
        .is_ok());
    for policy in 0..3 {
        let mut bounded = GlobalParentLimits {
            branch: limits(),
            ..GlobalParentLimits::default()
        };
        match policy {
            0 => bounded.max_ancestors = 1,
            1 => bounded.max_ancestry_bytes = 1,
            _ => bounded.branch.max_frame_bytes = 1,
        }
        let executor = GlobalParentExecutor::new(
            rig.source.clone(),
            rig.leader.clone(),
            0,
            0,
            rig.genesis,
            bounded,
        );
        assert!(executor
            .prepare(rig.context(&second), 2, &rig.blocks, &rig.verifier, false)
            .is_err());
    }
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _lease = rig
            .executor
            .prepare(context, 1, &rig.blocks, &rig.verifier, false)
            .unwrap();
        panic!("injected proposal unwind");
    }))
    .is_err());
    assert!(rig
        .executor
        .prepare(context, 1, &rig.blocks, &rig.verifier, false)
        .is_ok());
}

fn certify(frame: &mut GlobalFrame, signer: &quil_crypto::FalconSigner, epoch: u64) {
    certify_parent(frame, signer, epoch, 0);
}

fn certify_parent(frame: &mut GlobalFrame, signer: &quil_crypto::FalconSigner, epoch: u64, parent_view: u64) {
    use quil_cw_consensus::{
        _consensus::{
            simplex::{
                scheme::Namespace,
                types::{Finalization, Proposal, Subject},
            },
            types::{Epoch, Round, View},
        },
        _crypto::{sha256::Digest as CwDigest, Signer as _},
        _utils::{ordered::Set, N3f1},
        app_cert::{encode_finalization, wrap_cert_for_header},
        falcon_base::FalconPrivateKey,
        falcon_scheme::Generic,
        falcon_simplex::SimplexFalconScheme,
    };
    let h = frame.header.as_mut().unwrap();
    let key = FalconPrivateKey::from_bytes(signer.private_key(), signer.public_key()).unwrap();
    let participants: Set<_> = vec![key.public_key()].try_into().unwrap();
    let scheme = Generic::<Namespace>::signer(b"global", participants, key).unwrap();
    let proposal = Proposal::new(
        Round::new(Epoch::new(epoch), View::new(h.rank)),
        View::new(parent_view),
        CwDigest(quil_crypto::poseidon::hash_bytes_to_32(&h.output).unwrap()),
    );
    let vote = scheme
        .sign::<SimplexFalconScheme, CwDigest>(Subject::Finalize {
            proposal: &proposal,
        })
        .unwrap();
    let certificate = scheme
        .assemble::<SimplexFalconScheme, _, N3f1>(vec![vote])
        .unwrap();
    h.public_key_signature_bls48581 = Some(quil_types::proto::keys::Bls48581AggregateSignature {
        signature: wrap_cert_for_header(&encode_finalization(&Finalization {
            proposal,
            certificate,
        })),
        ..Default::default()
    });
}

#[test]
fn canonical_execution_base_requires_a_certificate_in_the_current_epoch_and_a_matching_or_absent_receipt() {
    let rig = Rig::new();
    let mut parent = rig.deploy();
    save(rig.clock.as_ref(), &parent);
    let context = rig.context(&parent);
    assert!(
        rig.executor
            .prepare(context, 1, &rig.blocks, &rig.verifier, false)
            .is_err(),
        "clock ahead of state"
    );
    rig.source.materialize(&parent).unwrap();
    assert!(
        rig.executor
            .prepare(context, 1, &rig.blocks, &rig.verifier, false)
            .is_err(),
        "receipt alone is not finality"
    );
    certify(&mut parent, &rig.signer, 1);
    save(rig.clock.as_ref(), &parent);
    assert!(
        rig.executor
            .prepare(context, 1, &rig.blocks, &rig.verifier, false)
            .is_err(),
        "wrong certificate epoch"
    );
    certify(&mut parent, &rig.signer, 0);
    save(rig.clock.as_ref(), &parent);
    assert!(rig
        .executor
        .prepare(context, 1, &rig.blocks, &rig.verifier, false)
        .is_ok());
    // An older store without a receipt uses its certified head; no receipt is
    // written until a certified child authenticates the state.
    let txn = rig.source.hypergraph_store.new_transaction(false).unwrap();
    txn.delete(&quil_store::encoding::global_execution_checkpoint_key())
        .unwrap();
    txn.commit().unwrap();
    let sequence = rig.db.inner().latest_sequence_number();
    assert!(rig
        .executor
        .prepare(context, 1, &rig.blocks, &rig.verifier, false)
        .is_ok());
    assert!(rig
        .db
        .inner()
        .get(quil_store::encoding::global_execution_checkpoint_key())
        .unwrap()
        .is_none());
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    // Without its certificate the receipt-less head is not a base.
    let mut uncertified = parent.clone();
    uncertified.header.as_mut().unwrap().public_key_signature_bls48581 = None;
    save(rig.clock.as_ref(), &uncertified);
    assert!(
        rig.executor
            .prepare(context, 1, &rig.blocks, &rig.verifier, false)
            .is_err(),
        "receipt-less head needs its certificate"
    );
    save(rig.clock.as_ref(), &parent);
    // An unfinished attempt, or a receipt for another input, still refuses.
    let txn = rig.source.hypergraph_store.new_transaction(false).unwrap();
    txn.set(&quil_store::encoding::global_execution_pending_key(), b"attempt")
        .unwrap();
    txn.commit().unwrap();
    assert!(
        rig.executor
            .prepare(context, 1, &rig.blocks, &rig.verifier, false)
            .is_err(),
        "unfinished execution"
    );
}

#[test]
fn selected_vote_binds_child_height_roots_body_and_full_consensus_context() {
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let context = rig.context(&parent);
    let child = state_frame(&expected.source, 2, context.view, context.parent);
    let seam = rig.seam(&parent);
    let encoded = crate::consensus_wire::encode_global_frame(&child).unwrap();
    assert!(!seam.verify(
        context.view,
        context.parent,
        id(&child),
        Some(encoded.clone())
    ));
    for field in 0..3 {
        let mut bad = context;
        match field {
            0 => bad.epoch += 1,
            1 => bad.parent_view += 1,
            _ => bad.parent = rig.genesis,
        }
        assert!(!seam.verify_with_context(bad, id(&child), Some(encoded.clone())));
    }
    for field in 0..7 {
        let mut bad = child.clone();
        let h = bad.header.as_mut().unwrap();
        match field {
            0 => h.frame_number += 1,
            1 => h.rank += 1,
            2 => h.parent_selector[0] ^= 1,
            3 => h.prover_tree_commitment[3] ^= 1,
            4 => h.prover_tree_aux_roots[0][0] ^= 1,
            5 => h.prover_tree_aux_roots[2][0] ^= 1,
            _ => bad.requests.push(Default::default()),
        }
        assert!(
            !seam.verify_with_context(
                context,
                id(&bad),
                Some(crate::consensus_wire::encode_global_frame(&bad).unwrap())
            ),
            "child substitution {field}"
        );
    }
    assert!(seam.verify_with_context(context, id(&child), Some(encoded)));
    assert_eq!(rig.source.last_materialized_frame(), 0);
    assert!(
        !rig.source.prover_root_mismatch_detected(),
        "tentative inputs cannot retarget canonical sync"
    );
}

#[test]
fn proposal_message_limits_preserve_the_public_pool_and_do_not_prevent_parent_verification() {
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let context = rig.context(&parent);
    assert!(rig.collector.add_message(1, vec![1, 2, 3]));
    let bounded = GlobalParentExecutor::new(
        rig.source.clone(),
        rig.leader.clone(),
        0,
        0,
        rig.genesis,
        GlobalParentLimits {
            branch: limits(),
            max_proposal_message_bytes: 1,
            ..GlobalParentLimits::default()
        },
    );
    let sequence = rig.db.inner().latest_sequence_number();
    // A backlog over the budget no longer fails the proposal: it carries what
    // fits (here nothing) and the rest waits in the untouched public pool.
    assert!(bounded
        .prepare(context, 1, &rig.blocks, &rig.verifier, true)
        .is_ok());
    assert_eq!(rig.collector.total_pending(), 1);
    assert!(bounded
        .prepare(context, 1, &rig.blocks, &rig.verifier, false)
        .is_ok());
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn selected_execution_rejects_foreign_leaders_and_candidate_stores() {
    let rig = Rig::new();
    let foreign = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let context = rig.context(&parent);
    let executor = GlobalParentExecutor::new(
        rig.source.clone(),
        foreign.leader.clone(),
        0,
        0,
        rig.genesis,
        GlobalParentLimits {
            branch: limits(),
            ..GlobalParentLimits::default()
        },
    );
    let sequence = rig.db.inner().latest_sequence_number();
    let foreign_sequence = foreign.db.inner().latest_sequence_number();
    assert!(executor
        .prepare(context, 1, &rig.blocks, &rig.verifier, false)
        .is_err());
    let seam = GlobalSeamProposer::new(
        rig.leader.clone(),
        rig.verifier.clone(),
        vec![],
        foreign.clock.clone(),
        None,
    )
    .with_block_store(rig.blocks.clone())
    .with_selected_execution(rig.executor.clone());
    seam.note_frame(context.parent, 1);
    assert!(seam.propose_with_context(context).is_none());
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    assert_eq!(
        foreign.db.inner().latest_sequence_number(),
        foreign_sequence
    );
}

#[test]
fn authenticated_peer_body_can_replace_a_stale_selected_candidate_without_promoting_it() {
    let rig = Rig::new();
    let parent = rig.deploy();
    let context = rig.context(&parent);
    rig.put(&parent);
    let mut stale = parent.clone();
    stale.requests.clear(); // Same output identity, body no longer matches.
    let txn = rig.clock.new_transaction(false).unwrap();
    rig.clock
        .put_global_clock_frame_candidate(&stale, txn.as_ref())
        .unwrap();
    txn.commit().unwrap();
    let sequence = rig.db.inner().latest_sequence_number();
    assert!(rig
        .executor
        .prepare(context, 1, &rig.blocks, &rig.verifier, false)
        .is_ok());
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    let seam = rig.seam(&parent);
    assert!(seam.propose_with_context(context).is_some());
    assert_eq!(
        rig.clock
            .get_global_clock_frame_candidate(1, context.parent.as_ref())
            .unwrap(),
        parent
    );
    assert_eq!(
        rig.clock
            .get_latest_global_clock_frame()
            .unwrap()
            .header
            .unwrap()
            .frame_number,
        0
    );
    assert_eq!(rig.source.last_materialized_frame(), 0);
}

#[test]
fn private_snapshot_and_failed_budget_checks_preserve_public_retention_until_finalization() {
    let collector = MessageCollector::new();
    assert!(collector.add_message(1, b"old".to_vec()));
    assert!(collector.add_message(41, b"boundary".to_vec()));
    assert!(collector.add_message(60, b"future".to_vec()));
    assert_eq!(
        collector.snapshot_for_execution(51, 4096, 100).unwrap(),
        vec![b"old".to_vec(), b"boundary".to_vec()]
    );
    // Over the budget the copy keeps the newest messages that fit, in
    // collection order, and still leaves the public buffers untouched.
    assert_eq!(collector.snapshot_for_execution(51, 1, 100).unwrap(), Vec::<Vec<u8>>::new());
    assert_eq!(collector.snapshot_for_execution(51, 8, 100).unwrap(), vec![b"boundary".to_vec()]);
    assert_eq!(collector.snapshot_for_execution(51, 4096, 1).unwrap(), vec![b"boundary".to_vec()]);
    assert_eq!(collector.total_pending(), 3);
    collector.prune_after_finalization(51);
    assert_eq!(collector.pending_count(1), 0);
    assert_eq!(collector.pending_count(41), 1);
    assert_eq!(collector.pending_count(60), 1);
}

#[test]
fn only_an_unreceipted_voter_reconciles_toward_the_proposers_parent_root() {
    let rig = Rig::new();
    let mut parent = rig.deploy();
    certify(&mut parent, &rig.signer, 0);
    rig.source.materialize(&parent).unwrap();
    save(rig.clock.as_ref(), &parent);
    let context = rig.context(&parent);
    let mut child = state_frame(&rig.source, 2, context.view, context.parent);
    child.header.as_mut().unwrap().prover_tree_commitment[0] ^= 1;
    let declared = child.header.as_ref().unwrap().prover_tree_commitment.clone();
    let encoded = crate::consensus_wire::encode_global_frame(&child).unwrap();
    let flagged = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let seam = GlobalSeamProposer::new(
        rig.leader.clone(),
        rig.verifier.clone(),
        vec![],
        rig.clock.clone(),
        Some({
            let flagged = flagged.clone();
            Arc::new(move |root: Vec<u8>| flagged.lock().unwrap().push(root))
        }),
    )
    .with_block_store(rig.blocks.clone())
    .with_selected_execution(rig.executor.clone());
    seam.note_frame(id(&parent), 1);
    // This member executed the parent itself: it keeps its state.
    assert!(!seam.verify_with_context(context, id(&child), Some(encoded.clone())));
    assert!(flagged.lock().unwrap().is_empty());
    // After a re-sync its receipt no longer describes the tree: it reconciles
    // toward the root the proposers declare.
    rig.db
        .inner()
        .delete(quil_store::encoding::global_execution_checkpoint_key())
        .unwrap();
    assert!(!seam.verify_with_context(context, id(&child), Some(encoded)));
    assert_eq!(*flagged.lock().unwrap(), vec![declared]);
}
