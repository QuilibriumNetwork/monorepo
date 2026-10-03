//! Private execution of an unfinalized selected application parent over real
//! RocksDB stores. Proposal validation is injected; the canonical and branch
//! voter checks are the production closures.
use super::*;
use quil_types::proto::global::{FrameHeader, GlobalFrame, GlobalFrameHeader};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

const RANK: u64 = 5;

struct Rig {
    db: Arc<quil_store::RocksDb>,
    clock: Arc<quil_store::RocksClockStore>,
    manager: Arc<quil_execution::ExecutionEngineManager>,
    materialized: Arc<AtomicU64>,
    outflows: Arc<FrameOutflows>,
    blocks: BlockStore,
    filter: Vec<u8>,
}

fn rig() -> Rig {
    let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
    let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
    let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
    let prover = Arc::new(quil_tries::ShaInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, prover.clone()));
    crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
    crdt.set_unified_tree(true);
    crdt.warm_sizes(&[]).unwrap();
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let manager = Arc::new(quil_execution::ExecutionEngineManager::new_with_shards(
        prover,
        crypto.key_manager,
        crdt.clone(),
        crypto.circuit_compiler,
        clock.clone(),
        Arc::new(quil_execution::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(crdt)),
        false,
        None,
        None,
    ));
    Rig {
        db,
        clock,
        manager,
        materialized: Arc::new(AtomicU64::new(0)),
        outflows: Arc::new(std::sync::Mutex::new(Default::default())),
        blocks: BlockStore::new(),
        filter: quil_execution::domains::QUIL_TOKEN.to_vec(),
    }
}

fn leader(rig: &Rig, anchor: Arc<dyn ClockStore>) -> Arc<AppLeaderProvider> {
    Arc::new(AppLeaderProvider {
        filter: rig.filter.clone(),
        clock_store: rig.clock.clone(),
        frame_outflows: rig.outflows.clone(),
        global_anchor_store: anchor,
        frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
        message_collector: Arc::new(MessageCollector::new()),
        mempool: Arc::new(MessageCollector::new()),
        fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
        local_prover_address: vec![1; 32],
        local_public_key: vec![],
        current_difficulty: Arc::new(AtomicU32::new(0)),
        reward_greedy: false,
        hypergraph: Some(rig.manager.crdt()),
        storage_source_hypergraph: None, shard_drain: None,
        execution_engine: Some(rig.manager.clone()),
        inclusion_prover: Some(Arc::new(quil_tries::ShaInclusionProver)),
        app_address: rig.filter.clone(),
        halted: Arc::new(AtomicBool::new(false)),
        min_active_provers_for_propose: 1,
        shard_mat_frame: rig.materialized.clone(),
        frame_requests: Arc::new(std::sync::Mutex::new(Default::default())),
        kv_db: None,
        frame_attestations: Arc::new(std::sync::Mutex::new(Default::default())),
        routing_seen: Arc::new(std::sync::Mutex::new(Default::default())),
        instance_committee_fp: None,
        session_genesis: None,
        under_session: false,
        session_closing: Arc::new(AtomicBool::new(false)),
        private_parent: false,
    })
}

fn canonical_check(rig: &Rig) -> AppRequestsRootCheck {
    build_requests_root_check(
        rig.manager.clone(),
        Arc::new(quil_tries::ShaInclusionProver),
        rig.manager.crdt(),
        rig.filter.clone(),
        rig.materialized.clone(),
        rig.outflows.clone(),
        rig.clock.clone(),
        rig.filter.clone(),
        None,
        None,
    )
}

fn executor(
    rig: &Rig,
    anchor: Arc<dyn ClockStore>,
    valid: bool,
    parent_check: AppRequestsRootCheck,
) -> AppParentExecutor {
    let executor = AppParentExecutor::new(
        rig.filter.clone(),
        rig.filter.clone(),
        rig.manager.clone(),
        rig.manager.crdt(),
        rig.clock.clone(),
        anchor.clone(),
        rig.outflows.clone(),
        Arc::new(quil_tries::ShaInclusionProver),
        Arc::new(move |_: &AppShardFrame| Ok(valid)),
        parent_check,
        rig.materialized.clone(),
        leader(rig, anchor),
        None,
    );
    executor.bind_blocks(rig.blocks.clone());
    executor
}

fn genesis() -> [u8; 32] {
    quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap()
}

fn parent(rig: &Rig, global_frame_number: u64) -> (AppShardFrame, Digest) {
    let frame = AppShardFrame {
        header: Some(FrameHeader {
            address: rig.filter.clone(),
            frame_number: 1,
            rank: RANK,
            output: vec![9; 32],
            parent_selector: digest_from_identity(genesis()).as_ref().to_vec(),
            global_frame_number,
            ..Default::default()
        }),
        ..Default::default()
    };
    let digest = app_frame_digest(&frame).unwrap();
    (frame, digest)
}

fn offer(rig: &Rig, frame: &AppShardFrame) -> Digest {
    let digest = app_frame_digest(frame).unwrap();
    rig.blocks.put(digest, prost::Message::encode_to_vec(frame));
    digest
}

fn cursor(crdt: &quil_hypergraph::HypergraphCrdt, filter: &[u8]) -> Option<u64> {
    crdt.capture_committed_shard(filter)
        .unwrap()
        .records
        .read_record(&quil_store::encoding::consensus_materialized_cursor_key(filter))
        .unwrap()
        .map(|bytes| u64::from_be_bytes(bytes.as_slice().try_into().unwrap()))
}

/// The child a leader over the branch would build, with the deterministic
/// output the proposal validator recomputes (zero GLOBAL anchor).
fn child_of(rig: &Rig, prepared: &PrivateAppParent, parent: Digest) -> AppShardFrame {
    let crdt = &prepared.crdt;
    let zero = vec![0u8; if crdt.has_forest() { 32 } else { 64 }];
    let state_roots = [("vertex", "adds"), ("vertex", "removes"), ("hyperedge", "adds"), ("hyperedge", "removes")]
        .iter()
        .map(|(set, phase)| {
            let root = crdt.sub_shard_commitment_for_filter(set, phase, &rig.filter);
            if root.is_empty() { zero.clone() } else { root }
        })
        .collect();
    let requests_root = compute_requests_root(
        &[],
        &rig.filter,
        prepared.frame_number + 1,
        Some(prepared.manager.as_ref()),
        Some(&quil_tries::ShaInclusionProver),
        crdt.has_forest(),
    )
    .unwrap();
    let outflows = prepared.outflows.as_ref();
    let clock = prepared.clock.as_ref();
    let number = prepared.frame_number + 1;
    let mut header = FrameHeader {
        address: rig.filter.clone(),
        frame_number: number,
        rank: RANK + 1,
        parent_selector: parent.as_ref().to_vec(),
        requests_root,
        state_roots,
        fee_total: materialized_fee_total(outflows, clock, &rig.filter, number - 1).unwrap().to_be_bytes().to_vec(),
        settlements: settlement_relay(outflows, clock, &rig.filter, number).unwrap(),
        accumulator: accumulator_field(outflows, clock, &rig.filter, number).unwrap(),
        spends: spend_relay(outflows, clock, &rig.filter, number).unwrap(),
        ..Default::default()
    };
    header.output = quil_crypto::porep::deterministic_app_frame_output(
        &header.parent_selector, &header.requests_root, &header.state_roots,
        &quil_crypto::porep::derive_storage_beacon(0, &[]),
        header.frame_number, header.rank, &header.prover, header.difficulty,
        header.fee_multiplier_vote, header.timestamp, &header.storage_attestation_root,
        0, &header.settlements, &header.accumulator, &header.spends,
    );
    AppShardFrame { header: Some(header), ..Default::default() }
}

#[test]
fn the_seam_leader_waits_before_a_private_parent_and_voters_use_it_at_once() {
    use crate::cw_app_seams::AppSeamProposer;
    use quil_cw_consensus::adapters::{GlobalProposer as _, ProposalContext};
    let rig = rig();
    let parents = Arc::new(executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| true)));
    let (frame, digest) = parent(&rig, 0);
    offer(&rig, &frame);
    let validator = || Arc::new(BlsAppFrameValidator::new(
        Arc::new(crate::test_support::TestProverRegistry::default()),
        Arc::new(quil_crypto::FalconKeyConstructor),
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
    ));
    let seam = |private: bool| {
        let proposer = AppSeamProposer::new(
            leader(&rig, rig.clock.clone()),
            validator(),
            Arc::new(|_| None),
            rig.filter.clone(),
            Some(canonical_check(&rig)),
            Arc::new(AtomicBool::new(true)),
        );
        proposer.note_frame(digest, 1);
        if private { proposer.with_private_parents(parents.clone(), true) } else { proposer }
    };
    let leader_seam = seam(true);
    let context = ProposalContext { epoch: 0, view: RANK + 1, parent_view: RANK, parent: digest };
    // A plain host keeps waiting for the canonical parent before executing it.
    for _ in 0..12 {
        assert!(leader_seam.propose_with_context(context).is_none());
        assert!(leader_seam.propose_retry().is_some());
        assert!(parents.prepared.lock().unwrap().is_none());
    }
    // Then it builds on a private execution (this rig has no active provers,
    // so the proposal itself is declined after the parent is prepared).
    assert!(leader_seam.propose_with_context(context).is_none());
    let prepared = parents.prepared.lock().unwrap().clone().expect("parent executed privately");
    let child = child_of(&rig, &prepared, digest);
    let child_digest = app_frame_digest(&child).unwrap();
    let bytes = prost::Message::encode_to_vec(&child);
    // A voter checks the child against the private parent at once.
    let voter = seam(true);
    assert!(voter.verify_with_context(context, child_digest, Some(bytes.clone())));
    // Without private parents the vote is refused.
    assert!(!seam(false).verify_with_context(context, child_digest, Some(bytes)));
}

#[test]
fn an_unfinalized_parent_executes_privately_without_touching_canonical_state() {
    let rig = rig();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| true));
    let (frame, digest) = parent(&rig, 0);
    offer(&rig, &frame);
    assert!(!executor.is_canonical_parent(digest).unwrap());
    assert!(executor.is_canonical_parent(digest_from_identity(genesis())).unwrap());
    let sequence = rig.db.inner().latest_sequence_number();
    let prepared = executor.prepare(digest, RANK).unwrap();
    assert_eq!((prepared.base, prepared.frame_number, prepared.view), (0, 1, RANK));
    assert_eq!(cursor(&prepared.crdt, &rig.filter), Some(1));
    assert_eq!(
        prepared.clock.get_latest_shard_clock_frame(&rig.filter).unwrap().header,
        frame.header
    );
    assert_eq!(
        materialized_fee_total(&prepared.outflows, prepared.clock.as_ref(), &rig.filter, 1),
        Some(0)
    );
    // Nothing canonical changed: no cursor, frame, outflow or database write.
    assert_eq!(cursor(&rig.manager.crdt(), &rig.filter), None);
    assert!(rig.clock.get_shard_clock_frame(&rig.filter, 1, false).is_err());
    assert!(rig.outflows.lock().unwrap().get(&1).is_none());
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    // One execution serves the leader and every vote until canonical passes it.
    assert!(Arc::ptr_eq(&prepared, &executor.prepare(digest, RANK).unwrap()));
    assert!(executor.prepare(digest, RANK + 1).is_err());
    assert!(executor.leader_for(&prepared, RANK + 1).is_ok());
    executor.retire_through(0);
    let again = executor.prepare(digest, RANK).unwrap();
    executor.retire_through(1);
    assert!(executor.prepared.lock().unwrap().is_none());
    assert!(!Arc::ptr_eq(&again, &executor.prepare(digest, RANK).unwrap()));
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
}

/// A restart can leave several frames notarized but not finalized above the
/// materialized tip (e.g. 5403 and 5404 above 5402, with every member
/// abstaining). The chain up to the selected parent executes privately,
/// oldest first, without touching canonical state; a missing link or views
/// that do not rise refuse it.
#[test]
fn an_unfinalized_chain_above_the_tip_executes_privately() {
    let rig = rig();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| true));
    let (first, first_digest) = parent(&rig, 0);
    offer(&rig, &first);
    // The second frame is a real child of the first: its requests root is
    // checked against the branch the first leaves behind.
    let second = child_of(&rig, &executor.prepare(first_digest, RANK).unwrap(), first_digest);
    let second_digest = offer(&rig, &second);
    let sequence = rig.db.inner().latest_sequence_number();
    let prepared = executor.prepare(second_digest, RANK + 1).unwrap();
    assert_eq!((prepared.base, prepared.frame_number, prepared.view), (0, 2, RANK + 1));
    assert_eq!(prepared.request_free_below, vec![true], "the frame between counts toward a session's drain");
    assert_eq!(cursor(&prepared.crdt, &rig.filter), Some(2));
    assert_eq!(prepared.clock.get_shard_clock_frame(&rig.filter, 1, false).unwrap().header, first.header);
    assert_eq!(prepared.clock.get_latest_shard_clock_frame(&rig.filter).unwrap().header, second.header);
    assert_eq!(materialized_fee_total(&prepared.outflows, prepared.clock.as_ref(), &rig.filter, 2), Some(0));
    assert_eq!(cursor(&rig.manager.crdt(), &rig.filter), None);
    assert!(rig.clock.get_shard_clock_frame(&rig.filter, 1, false).is_err());
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    // The second frame's requests root is checked against the branch.
    let mut forged = second.clone();
    let header = forged.header.as_mut().unwrap();
    header.requests_root = vec![7; 32];
    header.output = vec![12; 32];
    let forged_digest = offer(&rig, &forged);
    assert!(executor.prepare(forged_digest, RANK + 1).is_err());
    // Views must rise along the chain.
    let mut stale = second.clone();
    let header = stale.header.as_mut().unwrap();
    header.rank = RANK;
    header.output = vec![11; 32];
    let stale_digest = offer(&rig, &stale);
    assert!(executor.prepare(stale_digest, RANK).is_err());
    // A node holding the second frame but not the first cannot walk down.
    let other = self::rig();
    let lone = self::executor(&other, other.clock.clone(), true, Arc::new(|_: &AppShardFrame| true));
    assert!(lone.prepare(offer(&other, &second), RANK + 1).is_err());
}

#[test]
fn only_a_validated_child_of_the_materialized_tip_is_executed() {
    let rig = rig();
    let accept = || Arc::new(|_: &AppShardFrame| true) as AppRequestsRootCheck;
    let sequence = rig.db.inner().latest_sequence_number();
    let executor = executor(&rig, rig.clock.clone(), true, accept());
    // The tip itself uses the canonical path.
    assert!(executor.prepare(digest_from_identity(genesis()), 0).is_err());
    // An unknown body cannot be executed.
    let (frame, digest) = parent(&rig, 0);
    assert!(executor.prepare(digest, RANK).is_err());
    let mut variants = Vec::new();
    for field in 0..4 {
        let mut bad = frame.clone();
        let header = bad.header.as_mut().unwrap();
        match field {
            0 => header.frame_number = 2,
            1 => header.parent_selector = vec![3; 32],
            2 => header.rank = 0,
            _ => header.address = vec![4; 32],
        }
        variants.push(bad);
    }
    for bad in &variants {
        let digest = offer(&rig, bad);
        let rank = bad.header.as_ref().unwrap().rank;
        assert!(executor.prepare(digest, rank).is_err());
    }
    offer(&rig, &frame);
    // The selected view must be the parent's own.
    assert!(executor.prepare(digest, RANK + 1).is_err());
    let invalid = self::executor(&rig, rig.clock.clone(), false, accept());
    assert!(invalid.prepare(digest, RANK).is_err());
    let refused = self::executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| false));
    assert!(refused.prepare(digest, RANK).is_err());
    // Canonical materialization in progress refuses a private copy.
    rig.materialized.store(1, Ordering::SeqCst);
    assert!(executor.prepare(digest, RANK).is_err());
    rig.materialized.store(0, Ordering::SeqCst);
    assert!(executor.prepare(digest, RANK).is_ok());
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn a_child_is_checked_against_the_private_parent_state() {
    let rig = rig();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| true));
    let (frame, digest) = parent(&rig, 0);
    offer(&rig, &frame);
    let prepared = executor.prepare(digest, RANK).unwrap();
    let child = child_of(&rig, &prepared, digest);
    assert!((prepared.check)(&child));
    // The canonical checks, one height behind, refuse it.
    assert!(!(canonical_check(&rig))(&child));
    // A child declaring another fee total is refused on the branch too.
    let mut changed = child.clone();
    changed.header.as_mut().unwrap().fee_total = 7u128.to_be_bytes().to_vec();
    assert!(!(prepared.check)(&changed));
}

#[test]
fn a_thread_worker_parent_reads_global_frames_through_a_bounded_anchor() {
    let mut rig = rig();
    // The master's clock holds GLOBAL frames; the worker's engines read it.
    let master_db = quil_store::RocksDb::open_in_memory().unwrap();
    let master = Arc::new(quil_store::RocksClockStore::new(master_db.inner()));
    for number in 0..=5u64 {
        let txn = master.new_transaction(false).unwrap();
        master
            .put_global_clock_frame(
                &GlobalFrame {
                    header: Some(GlobalFrameHeader {
                        frame_number: number,
                        world_state_size: 1000 + number,
                        output: vec![number as u8; 516],
                        ..Default::default()
                    }),
                    requests: vec![],
                },
                txn.as_ref(),
            )
            .unwrap();
        txn.commit().unwrap();
    }
    let manager = Arc::try_unwrap(rig.manager).ok().unwrap();
    rig.manager = Arc::new(manager.with_global_clock_store(master.clone()).unwrap());
    let executor = executor(&rig, master.clone(), true, Arc::new(|_: &AppShardFrame| true));
    let (frame, digest) = parent(&rig, 3);
    offer(&rig, &frame);
    let master_sequence = master_db.inner().latest_sequence_number();
    let prepared = executor.prepare(digest, RANK).unwrap();
    assert_eq!(cursor(&prepared.crdt, &rig.filter), Some(1));
    assert_eq!(master_db.inner().latest_sequence_number(), master_sequence);
    assert_eq!(cursor(&rig.manager.crdt(), &rig.filter), None);
}

#[test]
fn a_private_session_parent_reads_as_the_committed_checkpoint_it_will_become() {
    use quil_cw_consensus::adapters::ProposalContext;
    use quil_cw_consensus::handoff::Session;
    use quil_execution::global_intrinsic::handoff;
    use quil_types::crypto::Signer as _;
    let rig = rig();
    // A committee session over this shard, authorized in GLOBAL state.
    let global_db = quil_store::RocksDb::open_in_memory().unwrap();
    let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_store::RocksHypergraphStore::new(global_db.inner())),
        Arc::new(quil_hypergraph::testing::StubProver),
    ));
    global.set_forest(quil_forest::Forest::with_namespace(global_db.inner(), quil_store::FOREST_NAMESPACE));
    let state = quil_execution::hypergraph_state::HypergraphState::new(global.clone());
    let commit = |frame: u64| {
        state.commit().unwrap();
        state.abort();
        global.commit_with_global_cursor(frame, &quil_store::encoding::global_materialized_cursor_key()).unwrap();
    };
    let mut members: Vec<Vec<u8>> = (0..3)
        .map(|_| quil_crypto::FalconSigner::generate().public_key().to_vec())
        .collect();
    members.sort();
    let session = Session {
        chain_id: [7; 32], filter: rig.filter.clone(), generation: 1, genesis: genesis(),
        base_frame: 0, authorization: [0; 32], members,
    };
    commit(1);
    handoff::initialize(&state, 2, &session).unwrap();
    commit(2);
    let source = crate::app_handoff::ParentSource::new(
        session.clone(), global, rig.manager.crdt(), rig.clock.clone(), Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| true));
    let (frame, digest) = parent(&rig, 0);
    offer(&rig, &frame);
    let context = ProposalContext { epoch: 1, view: RANK + 1, parent_view: RANK, parent: digest };
    let committed = source.reader();
    assert!(committed(context).is_err(), "the parent is not materialized yet");
    let prepared = executor.prepare(digest, RANK).unwrap();
    let private = source.read_private(context, &prepared).unwrap();
    assert_eq!((private.checkpoint.frame, private.checkpoint.view), (1, RANK));
    assert_eq!(private.checkpoint.digest, digest.0);
    // A different selection is refused.
    let other = ProposalContext { parent_view: RANK - 1, ..context };
    assert!(source.read_private(other, &prepared).is_err());
    // Finalize and materialize the same parent canonically: the committed
    // reader then returns exactly the privately derived checkpoint.
    let selector = quil_crypto::poseidon::hash_bytes_to_32(&frame.header.as_ref().unwrap().output).unwrap().to_vec();
    let txn = rig.clock.new_transaction(false).unwrap();
    rig.clock.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
    txn.commit().unwrap();
    let txn = rig.clock.new_transaction(false).unwrap();
    rig.clock.commit_shard_clock_frame(&rig.filter, 1, &selector, txn.as_ref(), false).unwrap();
    txn.commit().unwrap();
    materialize_app_shard_requests(rig.manager.as_ref(), &frame.requests, 1, 0, 0, 0, &rig.filter, 0).unwrap();
    let canonical = committed(context).unwrap();
    assert_eq!(canonical.checkpoint, private.checkpoint);
    assert_eq!(canonical.closing_request, private.closing_request);
}
