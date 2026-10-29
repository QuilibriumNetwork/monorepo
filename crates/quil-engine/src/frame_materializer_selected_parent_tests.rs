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
            leader: None,
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
            signature: vec![
                0;
                quil_execution::global_intrinsic::AddressedSignature::SIG_LEN_SINGLE
            ],
            address: vec![9; 32],
        }),
        filters: vec![vec![1; 32]],
        leaf_roots: Vec::new(),
        release: None,
    };
    let bundle = quil_types::proto::global::MessageBundle {
        requests: vec![quil_types::proto::global::MessageRequest {
            request: Some(
                quil_types::proto::global::message_request::Request::Confirm(
                    quil_execution::global_intrinsic::conversions::prover_confirm_to_proto(
                        &confirm,
                    ),
                ),
            ),
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
        let reason = rig
            .leader
            .refused_message(&raw)
            .expect("the branch's refusal is the node's");
        assert!(reason.contains("inclusion epoch"), "{reason}");
        assert_eq!(
            rig.leader.refusals_reused(),
            proposal,
            "validated only by the first proposal"
        );
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
    assert!(rig
        .executor
        .prepare(context, 1, &rig.blocks, &rig.verifier, false)
        .is_ok());
    let mut bad = parent.clone();
    bad.requests.clear();
    let blocks = BlockStore::new();
    blocks.put(
        context.parent,
        crate::consensus_wire::encode_global_frame(&bad).unwrap(),
    );
    assert!(rig
        .executor
        .prepare(context, 1, &blocks, &rig.verifier, false)
        .is_ok());
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
    assert!(
        wait > std::time::Duration::from_millis(4_000)
            && wait <= std::time::Duration::from_millis(5_000),
        "{wait:?}"
    );
    assert_eq!(
        pacing(now_ms + 60_000),
        Some(std::time::Duration::from_millis(10_000)),
        "one interval at most"
    );
    assert_eq!(
        pacing(now_ms - 1_000),
        None,
        "a parent in the past needs none"
    );
    assert_eq!(
        crate::leader_provider::proposal_pacing_wait(0, 5),
        std::time::Duration::ZERO
    );
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

    let lease = rig
        .executor
        .prepare(context, 1, &rig.blocks, &rig.verifier, false)
        .unwrap();
    assert!(rig.executor.busy());
    assert!(seam
        .verify_or_defer(context, id(&child), Some(encoded.clone()))
        .is_err());
    assert!(
        !seam.verify_with_context(context, id(&child), Some(encoded.clone())),
        "no deferral: no vote"
    );
    drop(lease);

    let frame_lock = rig.source.frame_execution.lock().unwrap();
    assert!(rig.executor.busy());
    assert!(seam
        .verify_or_defer(context, id(&child), Some(encoded.clone()))
        .is_err());
    drop(frame_lock);

    assert!(!rig.executor.busy());
    let mut bad = child.clone();
    bad.header.as_mut().unwrap().frame_number += 1;
    let bad_bytes = crate::consensus_wire::encode_global_frame(&bad).unwrap();
    assert_eq!(
        seam.verify_or_defer(context, id(&bad), Some(bad_bytes)),
        Ok(false)
    );
    assert_eq!(
        seam.verify_or_defer(context, id(&child), Some(encoded)),
        Ok(true)
    );
    assert!(!rig.executor.busy(), "a vote releases the lease");
}

/// A reader of the engines (a gossip validation or an RPC cost query) can
/// overlap a vote's capture with no lease or frame lock held, so `busy()`
/// reads false. The voter defers instead of refusing, then votes on the same
/// proposal once the reader lets go.
#[test]
fn a_voter_whose_engines_are_in_use_defers_instead_of_refusing() {
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let context = rig.context(&parent);
    let child = state_frame(&expected.source, 2, context.view, context.parent);
    let encoded = crate::consensus_wire::encode_global_frame(&child).unwrap();
    let seam = rig.seam(&parent);

    let reader = rig.source.execution_manager.hold_engines_for_test();
    assert!(!rig.executor.busy(), "neither the lease nor the frame lock");
    let error = rig
        .executor
        .prepare(context, 1, &rig.blocks, &rig.verifier, false)
        .err()
        .expect("the capture cannot take the engines");
    assert!(quil_execution::source_busy(&error), "{error}");
    assert!(seam
        .verify_or_defer(context, id(&child), Some(encoded.clone()))
        .is_err());
    assert!(!rig.executor.busy(), "deferring holds nothing");
    drop(reader);

    assert_eq!(
        seam.verify_or_defer(context, id(&child), Some(encoded)),
        Ok(true)
    );
}

/// The busy defer is bounded: a reader that keeps the engines past the
/// adapter's patience (20 s) costs this voter its vote on that view and no
/// more. Every check returns at once, since a capture never waits for the
/// engines, and the adapter declines when its patience runs out. A reader
/// that lets go within it gets the vote.
#[test]
fn a_voter_whose_engines_stay_in_use_declines_once_its_patience_runs_out() {
    use crate::outage::test_logs::CapturedLogs;
    use quil_cw_consensus::_consensus::simplex::types::Context;
    use quil_cw_consensus::_consensus::types::{Epoch, Round, View};
    use quil_cw_consensus::_consensus::Automaton as _;
    use quil_cw_consensus::_runtime::{deterministic, Clock as _, Runner as _, Supervisor as _};
    use std::time::Duration;
    let logs = CapturedLogs::default();
    let _logs = logs.install();
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let context = rig.context(&parent);
    let child = state_frame(&expected.source, 2, context.view, context.parent);
    let digest = id(&child);
    let store = BlockStore::new();
    store.put(
        digest,
        crate::consensus_wire::encode_global_frame(&child).unwrap(),
    );
    let seam = Arc::new(rig.seam(&parent));
    let leader =
        quil_cw_consensus::falcon_base::FalconPublicKey::from_bytes(rig.signer.public_key())
            .unwrap();
    // The reader holds the engines until `released_after`, or until the
    // adapter answers. Returns the answer and when it came.
    let verify = |released_after: Option<Duration>| {
        let (rig, seam, store, leader) = (&rig, &seam, &store, &leader);
        deterministic::Runner::timed(Duration::from_secs(120)).start(|runtime| async move {
            let mut automaton = quil_cw_consensus::adapters::FalconAutomaton::new(
                runtime.child("automaton"),
                seam.clone(),
                store.clone(),
            );
            let reader = rig.source.execution_manager.hold_engines_for_test();
            let started = runtime.current();
            let pending = automaton
                .verify(
                    Context {
                        round: Round::new(Epoch::new(context.epoch), View::new(context.view)),
                        leader: leader.clone(),
                        parent: (View::new(context.parent_view), context.parent),
                    },
                    digest,
                )
                .await;
            if let Some(after) = released_after {
                runtime.sleep(after).await;
                drop(reader);
                let verdict = pending.await.ok();
                (verdict, runtime.current().duration_since(started).unwrap())
            } else {
                let verdict = pending.await.ok();
                let answered = runtime.current().duration_since(started).unwrap();
                drop(reader);
                (verdict, answered)
            }
        })
    };

    let (verdict, answered) = verify(None);
    assert_eq!(verdict, Some(false), "a reader past its patience: no vote");
    assert!(
        answered >= Duration::from_secs(20) && answered < Duration::from_secs(21),
        "declined when its patience ran out, not later: {answered:?}"
    );
    assert!(!rig.executor.busy(), "the refusal leaves nothing held");

    let (verdict, answered) = verify(Some(Duration::from_secs(2)));
    assert_eq!(verdict, Some(true), "a reader within its patience: a vote");
    assert!(answered < Duration::from_secs(3), "{answered:?}");

    // About 110 deferrals over two checks of one view: one line says the
    // vote waits and for what, and one says it was declined.
    let deferred = logs.lines_with("GLOBAL vote deferred");
    assert_eq!(deferred.len(), 1, "one line per view: {deferred:?}");
    assert!(
        deferred[0].contains("execution branch engines: busy elsewhere")
            && deferred[0].contains("view=73")
            && deferred[0].contains("waits_up_to_s=20"),
        "{}",
        deferred[0]
    );
    let declined = logs.lines_with("GLOBAL vote declined");
    assert_eq!(
        declined.len(),
        1,
        "one line per declined vote: {declined:?}"
    );
    assert!(
        declined[0].contains("WARN")
            && declined[0].contains("view=73")
            && declined[0].contains("waited_s=20")
            && declined[0].contains("execution branch engines: busy elsewhere")
            && declined[0].contains("check this node's RPC and gossip load"),
        "{}",
        declined[0]
    );
}

/// A leader whose proposal finds the engines in use retries each second
/// while the view lasts. The retries log as one outage, not a warn each.
#[test]
fn a_proposal_that_finds_the_engines_in_use_logs_one_outage_not_a_warn_per_retry() {
    use crate::outage::test_logs::CapturedLogs;
    let logs = CapturedLogs::default();
    let _logs = logs.install();
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let context = rig.context(&parent);
    let seam = rig.seam(&parent);

    let reader = rig.source.execution_manager.hold_engines_for_test();
    for _ in 0..3 {
        assert!(seam.propose_with_context(context).is_none());
    }
    drop(reader);
    assert!(seam.propose_with_context(context).is_some());

    assert!(logs
        .lines_with("selected GLOBAL parent execution unavailable")
        .is_empty());
    let began = logs.lines_with("GLOBAL proposal waits for an execution source");
    assert_eq!(began.len(), 1, "{began:?}");
    assert!(
        began[0].contains("execution branch engines: busy elsewhere"),
        "{}",
        began[0]
    );
    let ended = logs.lines_with("GLOBAL proposal no longer waits");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert!(ended[0].contains("retries=3"), "{}", ended[0]);
}

/// A busy proposal outage repeats at most every 10 s with its duration and
/// retry count, and a new view ends the last view's at its last busy retry.
#[test]
fn a_busy_proposal_outage_repeats_boundedly_and_ends_with_its_view() {
    use crate::outage::test_logs::CapturedLogs;
    use std::time::{Duration, Instant};
    let logs = CapturedLogs::default();
    let _logs = logs.install();
    let rig = Rig::new();
    let parent = rig.deploy();
    let seam = rig.seam(&parent);
    let busy = quil_execution::busy_unavailable("execution branch engines");
    let start = Instant::now();
    let at = |secs: u64| start + Duration::from_secs(secs);

    // View 73's proposal retries each second for 20 s, all busy.
    for secs in 0..20 {
        seam.note_proposal_prepare(73, 1, Some(&busy), at(secs));
    }
    // View 74's first retry is busy, its second is not.
    seam.note_proposal_prepare(74, 1, Some(&busy), at(30));
    seam.note_proposal_prepare(74, 1, None, at(32));
    // Nothing was busy for view 75.
    seam.note_proposal_prepare(75, 1, None, at(40));

    let began = logs.lines_with("GLOBAL proposal waits for an execution source");
    assert_eq!(began.len(), 2, "one per view: {began:?}");
    let repeated = logs.lines_with("GLOBAL proposal still waits");
    assert_eq!(repeated.len(), 1, "every 10 s at most: {repeated:?}");
    assert!(
        repeated[0].contains("WARN")
            && repeated[0].contains("view=73")
            && repeated[0].contains("busy_s=10")
            && repeated[0].contains("retries=11"),
        "{}",
        repeated[0]
    );
    let view_ended = logs.lines_with("its view ended");
    assert_eq!(view_ended.len(), 1, "{view_ended:?}");
    assert!(
        view_ended[0].contains("view=73")
            && view_ended[0].contains("busy_s=19")
            && view_ended[0].contains("retries=20"),
        "{}",
        view_ended[0]
    );
    let cleared = logs.lines_with("GLOBAL proposal no longer waits");
    assert_eq!(cleared.len(), 1, "{cleared:?}");
    assert!(
        cleared[0].contains("view=74")
            && cleared[0].contains("busy_s=2")
            && cleared[0].contains("retries=1"),
        "{}",
        cleared[0]
    );
}

/// A source poisoned by an earlier panic does not clear by waiting: the
/// voter refuses at once and its warn says to restart the node.
#[test]
fn a_voter_whose_engines_are_poisoned_refuses_at_once() {
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let context = rig.context(&parent);
    let child = state_frame(&expected.source, 2, context.view, context.parent);
    let encoded = crate::consensus_wire::encode_global_frame(&child).unwrap();
    let seam = rig.seam(&parent);

    rig.source.execution_manager.poison_engines_for_test();
    let error = rig
        .executor
        .prepare(context, 1, &rig.blocks, &rig.verifier, false)
        .err()
        .expect("the capture cannot take the engines");
    assert!(error.to_string().contains("poisoned"), "{error}");
    assert!(error.to_string().contains("restart the node"), "{error}");
    assert!(!quil_execution::source_busy(&error), "{error}");
    assert!(!rig.executor.busy());
    assert_eq!(
        seam.verify_or_defer(context, id(&child), Some(encoded)),
        Ok(false)
    );
}

/// A finalized parent this node has not published yet is published first:
/// executing it privately for the proposal executes it twice, one after the
/// other on the single execution lease. The wait is bounded per view: past it
/// the voter executes the parent privately and votes, so a finalizer that
/// cannot publish never costs the vote.
#[test]
fn a_voter_lets_its_finalized_parent_publish_before_executing_it_privately() {
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let context = rig.context(&parent);
    let child = state_frame(&expected.source, 2, context.view, context.parent);
    let encoded = crate::consensus_wire::encode_global_frame(&child).unwrap();

    assert!(
        !rig.executor.publication_pending(1),
        "nothing finalized yet"
    );
    rig.executor.note_finalized(1);
    assert!(rig.executor.publication_pending(1));
    let seam = rig.seam(&parent);
    assert!(
        seam.verify_or_defer(context, id(&child), Some(encoded.clone()))
            .is_err(),
        "defers to publication"
    );
    assert!(
        seam.verify_or_defer(context, id(&child), Some(encoded.clone()))
            .is_err(),
        "within the view's wait"
    );
    assert!(!rig.executor.busy(), "deferring takes no lease");

    let impatient = rig
        .seam(&parent)
        .with_publication_priority(std::time::Duration::ZERO);
    assert!(
        impatient
            .verify_or_defer(context, id(&child), Some(encoded.clone()))
            .is_err(),
        "the wait starts"
    );
    assert_eq!(
        impatient.verify_or_defer(context, id(&child), Some(encoded)),
        Ok(true),
        "then it votes"
    );
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

/// A node far below a proposal's parent learns it cannot execute it before
/// capturing any state: one catching up 5,300 frames behind spent ~5 s
/// capturing for every proposal, holding the frame lock its catch-up needed
/// (2026-10-12).
#[test]
fn a_parent_outside_the_window_is_refused_without_a_capture() {
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let executor = GlobalParentExecutor::new(
        rig.source.clone(),
        rig.leader.clone(),
        0,
        0,
        rig.genesis,
        GlobalParentLimits {
            branch: limits(),
            max_ancestors: 1,
            ..GlobalParentLimits::default()
        },
    );
    let refusal = |number| {
        executor
            .prepare(
                rig.context(&parent),
                number,
                &rig.blocks,
                &rig.verifier,
                false,
            )
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default()
    };
    // A capture reports the held frame lock.
    let held = rig.source.frame_execution.lock().unwrap();
    assert!(
        refusal(2).contains("outside the execution window"),
        "{}",
        refusal(2)
    );
    assert!(
        refusal(1).contains("busy"),
        "inside the window it captures: {}",
        refusal(1)
    );
    drop(held);
    assert!(executor
        .prepare(rig.context(&parent), 1, &rig.blocks, &rig.verifier, false)
        .is_ok());
}

/// While a notarized chain stays unfinalized, each proposal and vote builds
/// on it. It is executed once and kept: a slower archive that executed two
/// such frames for every view took 30 s of a 35 s view and never voted, and
/// GLOBAL halted at 874,880 (2026-10-11).
#[test]
fn an_unfinalized_ancestry_is_executed_once_and_extended_in_children() {
    let rig = Rig::new();
    let sequence = rig.db.inner().latest_sequence_number();
    let first = rig.deploy();
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&first).unwrap();
    let second = state_frame(&expected.source, 2, 42, id(&first));
    expected.source.materialize(&second).unwrap();
    let child_of_second = state_frame(&expected.source, 3, 73, id(&second));
    let third = state_frame(&expected.source, 3, 43, id(&second));
    expected.source.materialize(&third).unwrap();
    let child_of_third = state_frame(&expected.source, 4, 73, id(&third));
    for frame in [&first, &second, &third] {
        rig.put(frame);
    }
    let prepare = |executor: &GlobalParentExecutor, parent: &GlobalFrame, for_proposal: bool| {
        let number = parent.header.as_ref().unwrap().frame_number;
        executor
            .prepare(
                rig.context(parent),
                number,
                &rig.blocks,
                &rig.verifier,
                for_proposal,
            )
            .unwrap()
    };
    let kept = |parent: &GlobalFrame, child: &GlobalFrame| {
        let lease = prepare(&rig.executor, parent, false);
        assert!(lease.matches_child(child.header.as_ref().unwrap()));
        lease.kept_ancestors()
    };

    assert_eq!(
        kept(&second, &child_of_second),
        0,
        "executed the first time"
    );
    assert_eq!(kept(&second, &child_of_second), 2, "then kept");
    let proposal = prepare(&rig.executor, &second, true);
    assert_eq!(proposal.kept_ancestors(), 2);
    let proved = proposal.prove(&[]).unwrap();
    assert_eq!(
        proved.state.prover_tree_commitment,
        child_of_second
            .header
            .as_ref()
            .unwrap()
            .prover_tree_commitment
    );
    assert_eq!(
        proved.state.prover_tree_aux_roots,
        child_of_second
            .header
            .as_ref()
            .unwrap()
            .prover_tree_aux_roots
    );
    drop(proposal);
    assert_eq!(
        kept(&second, &child_of_second),
        2,
        "proving leaves the kept execution unchanged"
    );

    assert_eq!(
        kept(&third, &child_of_third),
        2,
        "a longer chain executes only its new frame"
    );
    assert_eq!(kept(&third, &child_of_third), 3);
    assert_eq!(
        kept(&second, &child_of_second),
        0,
        "a chain the kept one runs past is executed again"
    );

    // The kept execution is used only for exactly the frames it executed: a
    // substituted body at the same identity is executed, and refused.
    rig.executor.forget_authenticated_ancestors();
    let mut forged = second.clone();
    forged.header.as_mut().unwrap().prover_tree_commitment[7] ^= 1;
    let blocks = BlockStore::new();
    blocks.put(
        id(&first),
        crate::consensus_wire::encode_global_frame(&first).unwrap(),
    );
    blocks.put(
        id(&second),
        crate::consensus_wire::encode_global_frame(&forged).unwrap(),
    );
    assert!(rig
        .executor
        .prepare(rig.context(&second), 2, &blocks, &rig.verifier, false)
        .is_err());
    assert_eq!(
        kept(&second, &child_of_second),
        2,
        "a refused preparation leaves it"
    );

    let unkept = GlobalParentExecutor::new(
        rig.source.clone(),
        rig.leader.clone(),
        0,
        0,
        rig.genesis,
        GlobalParentLimits {
            branch: limits(),
            max_kept_age: std::time::Duration::ZERO,
            ..GlobalParentLimits::default()
        },
    );
    for _ in 0..2 {
        assert_eq!(
            prepare(&unkept, &second, false).kept_ancestors(),
            0,
            "past its age it is executed again"
        );
    }
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
}

fn certify(frame: &mut GlobalFrame, signer: &quil_crypto::FalconSigner, epoch: u64) {
    certify_parent(frame, signer, epoch, 0);
}

fn certify_parent(
    frame: &mut GlobalFrame,
    signer: &quil_crypto::FalconSigner,
    epoch: u64,
    parent_view: u64,
) {
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
fn canonical_execution_base_requires_a_certificate_in_the_current_epoch_and_a_matching_or_absent_receipt(
) {
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
    uncertified
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581 = None;
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
    txn.set(
        &quil_store::encoding::global_execution_pending_key(),
        b"attempt",
    )
    .unwrap();
    txn.commit().unwrap();
    assert!(
        rig.executor
            .prepare(context, 1, &rig.blocks, &rig.verifier, false)
            .is_err(),
        "unfinished execution"
    );
}

/// The GLOBAL committee succession frame every test in this crate uses: far
/// above any other test's frames, and never unset (see `current_frame` tests).
const TEST_SUCCESSION: u64 = 1_000_000_000_000;

/// Each GLOBAL frame has one committee and one epoch: the genesis committee
/// in epoch 0 below the succession frame, the successor in epoch 1 from it.
#[test]
fn a_global_frame_verifies_only_against_the_committee_of_its_frame() {
    quil_types::consensus::set_global_committee_succession_frame(TEST_SUCCESSION);
    let genesis = quil_crypto::FalconSigner::generate();
    let successor = quil_crypto::FalconSigner::generate();
    let verifier = GlobalFrameVerifier::new(Arc::new(TestFrameProver))
        .with_global_committee(vec![genesis.public_key().to_vec()])
        .with_global_committee_successor(vec![successor.public_key().to_vec()]);
    let signed = |number: u64, signer: &quil_crypto::FalconSigner, epoch: u64| {
        let mut frame = GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: number,
                rank: 9,
                output: vec![3; 32],
                ..Default::default()
            }),
            requests: Vec::new(),
        };
        certify_parent(&mut frame, signer, epoch, 8);
        frame.header.unwrap()
    };
    let last = TEST_SUCCESSION - 1;
    assert!(verifier.verify_global_finalization_cert(&signed(last, &genesis, 0)));
    assert_eq!(
        verifier.global_finalization_parent(&signed(last, &genesis, 0)),
        Some(8)
    );
    assert!(verifier.verify_global_finalization_cert(&signed(TEST_SUCCESSION, &successor, 1)));
    assert_eq!(
        verifier.global_finalization_parent(&signed(TEST_SUCCESSION, &successor, 1)),
        Some(8)
    );
    for (number, signer, epoch) in [
        (last, &genesis, 1),
        (last, &successor, 0),
        (last, &successor, 1),
        (TEST_SUCCESSION, &genesis, 0),
        (TEST_SUCCESSION, &genesis, 1),
        (TEST_SUCCESSION, &successor, 0),
    ] {
        assert!(
            !verifier.verify_global_finalization_cert(&signed(number, signer, epoch)),
            "frame {number} epoch {epoch}"
        );
    }
    let no_successor = GlobalFrameVerifier::new(Arc::new(TestFrameProver))
        .with_global_committee(vec![genesis.public_key().to_vec()]);
    assert!(!no_successor.verify_global_finalization_cert(&signed(TEST_SUCCESSION, &successor, 1)));
    assert!(no_successor.verify_global_finalization_cert(&signed(last, &genesis, 0)));
}

/// A consensus instance builds and votes only on its own committee's frames,
/// and the frame it starts from is its view 0, whatever that frame's rank.
#[test]
fn a_consensus_instance_starts_at_view_zero_on_its_first_frame_and_keeps_to_its_committee() {
    quil_types::consensus::set_global_committee_succession_frame(TEST_SUCCESSION);
    let rig = Rig::new();
    let mut parent = rig.deploy();
    save(rig.clock.as_ref(), &parent);
    rig.source.materialize(&parent).unwrap();
    certify(&mut parent, &rig.signer, 0);
    save(rig.clock.as_ref(), &parent);
    let number = parent.header.as_ref().unwrap().frame_number;
    let instance = |epoch: u64| {
        GlobalParentExecutor::new(
            rig.source.clone(),
            rig.leader.clone(),
            epoch,
            number,
            id(&parent),
            GlobalParentLimits {
                branch: limits(),
                ..GlobalParentLimits::default()
            },
        )
    };
    let at_rank = rig.context(&parent);
    let at_view_zero = ProposalContext {
        parent_view: 0,
        ..at_rank
    };
    let seeded = instance(0);
    assert!(seeded
        .prepare(at_rank, number, &rig.blocks, &rig.verifier, false)
        .is_err());
    assert!(seeded
        .prepare(at_view_zero, number, &rig.blocks, &rig.verifier, false)
        .is_ok());
    assert!(
        rig.executor
            .prepare(at_rank, number, &rig.blocks, &rig.verifier, false)
            .is_ok(),
        "an instance started elsewhere sees the frame at its rank"
    );

    fn refused<T>(result: Result<T>) -> bool {
        result
            .err()
            .is_some_and(|error: QuilError| error.to_string().contains("another committee"))
    }
    assert!(
        refused(rig.executor.prepare(
            at_rank,
            TEST_SUCCESSION - 1,
            &rig.blocks,
            &rig.verifier,
            false
        )),
        "epoch 0 builds nothing from the succession frame on"
    );
    assert!(
        refused(instance(1).prepare(
            ProposalContext {
                epoch: 1,
                ..at_view_zero
            },
            number,
            &rig.blocks,
            &rig.verifier,
            false
        )),
        "epoch 1 builds nothing below it"
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
    assert_eq!(
        collector.snapshot_for_execution(51, 1, 100).unwrap(),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(
        collector.snapshot_for_execution(51, 8, 100).unwrap(),
        vec![b"boundary".to_vec()]
    );
    assert_eq!(
        collector.snapshot_for_execution(51, 4096, 1).unwrap(),
        vec![b"boundary".to_vec()]
    );
    assert_eq!(collector.total_pending(), 3);
    // Retention counts finalized frames: ten after rank 41 keep it.
    for rank in 41..51 {
        collector.prune_after_finalization(rank);
    }
    assert_eq!(collector.pending_count(1), 1);
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
    let declared = child
        .header
        .as_ref()
        .unwrap()
        .prover_tree_commitment
        .clone();
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
