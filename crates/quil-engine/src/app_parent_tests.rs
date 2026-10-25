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
    leader_with(rig, anchor, Arc::new(crate::test_support::TestProverRegistry::new()))
}

fn leader_with(
    rig: &Rig,
    anchor: Arc<dyn ClockStore>,
    registry: Arc<crate::test_support::TestProverRegistry>,
) -> Arc<AppLeaderProvider> {
    Arc::new(AppLeaderProvider {
        filter: rig.filter.clone(),
        clock_store: rig.clock.clone(),
        frame_outflows: rig.outflows.clone(),
        global_anchor_store: anchor,
        frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        prover_registry: registry,
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
        replicas_retired_below: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
    executor_with(rig, anchor, Arc::new(move |_: &AppShardFrame| Ok(valid)), parent_check)
}

fn executor_with(
    rig: &Rig,
    anchor: Arc<dyn ClockStore>,
    validate: ProposalValidation,
    parent_check: AppRequestsRootCheck,
) -> AppParentExecutor {
    let led = leader(rig, anchor.clone());
    executor_full(rig, anchor, validate, parent_check, led)
}

fn executor_led(
    rig: &Rig,
    anchor: Arc<dyn ClockStore>,
    valid: bool,
    parent_check: AppRequestsRootCheck,
    led: Arc<AppLeaderProvider>,
) -> AppParentExecutor {
    executor_full(rig, anchor, Arc::new(move |_: &AppShardFrame| Ok(valid)), parent_check, led)
}

fn executor_full(
    rig: &Rig,
    anchor: Arc<dyn ClockStore>,
    validate: ProposalValidation,
    parent_check: AppRequestsRootCheck,
    led: Arc<AppLeaderProvider>,
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
        validate,
        parent_check,
        rig.materialized.clone(),
        led,
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
    let parents = Arc::new(executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(()))));
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

fn validator() -> Arc<BlsAppFrameValidator> {
    Arc::new(BlsAppFrameValidator::new(
        Arc::new(crate::test_support::TestProverRegistry::default()),
        Arc::new(quil_crypto::FalconKeyConstructor),
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
    ))
}

/// A host's proposer over `parents`, bound as the host binds it, with its
/// re-sends going to `sent`.
fn seam(
    rig: &Rig,
    led: Arc<AppLeaderProvider>,
    parents: Arc<AppParentExecutor>,
    sent: Arc<Sent>,
) -> crate::cw_app_seams::AppSeamProposer {
    let proposer = crate::cw_app_seams::AppSeamProposer::new(
        led,
        validator(),
        Arc::new(|state: &quil_consensus::models::State<crate::app_types::AppShardState>| {
            Some(crate::cw_app_seams::app_frame_from_state(state, Vec::new(), Vec::new()))
        }),
        rig.filter.clone(),
        Some(canonical_check(rig)),
        Arc::new(AtomicBool::new(true)),
    );
    crate::cw_app_seams::bind_private_parents(proposer, Some(parents), &rig.blocks, sent, false)
}

/// What a leader sends on the block channel: digest, bytes, and whether to
/// the whole committee.
#[derive(Default)]
struct Sent(std::sync::Mutex<Vec<(Digest, Vec<u8>, bool)>>);

impl quil_cw_consensus::adapters::FrameSink for Sent {
    fn broadcast(
        &self,
        digest: Digest,
        bytes: Vec<u8>,
        recipients: quil_cw_consensus::adapters::Recipients<quil_cw_consensus::falcon_base::FalconPublicKey>,
    ) {
        let all = matches!(recipients, quil_cw_consensus::adapters::Recipients::All);
        self.0.lock().unwrap().push((digest, bytes, all));
    }
}

/// A rig whose shard has this node's prover active, so a leader proposes.
fn active_registry() -> Arc<crate::test_support::TestProverRegistry> {
    Arc::new(crate::test_support::TestProverRegistry::with_prover(quil_types::consensus::ProverInfo {
        public_key: Vec::new(),
        address: vec![1; 32],
        status: quil_types::consensus::ProverStatus::Active,
        kick_frame_number: 0,
        allocations: Vec::new(),
        available_storage: 0,
        seniority: 0,
        delegate_address: Vec::new(),
    }))
}

/// A member that missed a notarized parent's body refuses every child of it:
/// no peer serves bodies and archives hold only finalized frames. Once the
/// body arrives on the block channel, stored as peer ingress stores it, the
/// same member checks the child in full and votes for it. Unchanged by the
/// re-send itself: it shows an earlier release takes the re-sent body.
#[test]
fn a_member_missing_the_parent_body_votes_once_the_body_arrives() {
    use quil_cw_consensus::adapters::{GlobalProposer as _, ProposalContext};
    let holder = rig();
    let holder_parents = executor(&holder, holder.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
    let (frame, digest) = parent(&holder, 0);
    offer(&holder, &frame);
    let child = child_of(&holder, &holder_parents.prepare(digest, RANK).unwrap(), digest);
    let child_digest = app_frame_digest(&child).unwrap();
    let bytes = prost::Message::encode_to_vec(&child);
    let context = ProposalContext { epoch: 0, view: RANK + 1, parent_view: RANK, parent: digest };

    let member = rig();
    let led = leader(&member, member.clock.clone());
    let parents = Arc::new(executor_led(&member, member.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())), led.clone()));
    let voter = seam(&member, led, parents.clone(), Arc::new(Sent::default()));
    assert!(!voter.verify_with_context(context, child_digest, Some(bytes.clone())));
    let missing = parents.prepare(digest, RANK).err().map(|error| error.to_string()).unwrap_or_default();
    assert!(missing.contains("selected parent body is not available"), "{missing}");
    offer(&member, &frame);
    assert!(voter.verify_with_context(context, child_digest, Some(bytes)));
}

/// A leader building on an unfinalized parent after a nullified view queues
/// the parent's unfinalized chain, oldest first, for the whole committee
/// with its proposal. Right after the parent's view it sends nothing: every
/// member that voted for the parent holds it.
#[test]
fn a_leader_after_a_nullified_view_resends_the_unfinalized_chain() {
    use quil_cw_consensus::adapters::{GlobalProposer as _, ProposalContext};
    let rig = rig();
    let led = leader_with(&rig, rig.clock.clone(), active_registry());
    let parents = Arc::new(executor_led(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())), led.clone()));
    let (first, first_digest) = parent(&rig, 0);
    offer(&rig, &first);
    let second = child_of(&rig, &parents.prepare(first_digest, RANK).unwrap(), first_digest);
    let second_digest = offer(&rig, &second);
    let sent = Arc::new(Sent::default());
    let proposer = seam(&rig, led, parents, sent.clone());
    proposer.note_frame(second_digest, 2);
    let next = ProposalContext { epoch: 0, view: RANK + 2, parent_view: RANK + 1, parent: second_digest };
    assert!(proposer.propose_with_context(next).is_some(), "the leader proposes over the private parent");
    assert!(sent.0.lock().unwrap().is_empty(), "nothing re-sent right after the parent's view");
    let later = ProposalContext { view: RANK + 4, ..next };
    assert!(proposer.propose_with_context(later).is_some());
    let encoded = |frame: &AppShardFrame| prost::Message::encode_to_vec(frame);
    assert_eq!(
        *sent.0.lock().unwrap(),
        vec![(first_digest, encoded(&first), true), (second_digest, encoded(&second), true)],
    );
}

/// Nothing is re-sent by a turn that proposes nothing, though it executed
/// the parent after a nullified view: a declined turn is asked again every
/// 250 ms.
#[test]
fn a_declined_turn_resends_nothing() {
    use quil_cw_consensus::adapters::{GlobalProposer as _, ProposalContext};
    let rig = rig();
    let led = leader(&rig, rig.clock.clone());
    let parents = Arc::new(executor_led(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())), led.clone()));
    let (frame, digest) = parent(&rig, 0);
    offer(&rig, &frame);
    let sent = Arc::new(Sent::default());
    let proposer = seam(&rig, led, parents.clone(), sent.clone());
    proposer.note_frame(digest, 1);
    let context = ProposalContext { epoch: 0, view: RANK + 2, parent_view: RANK, parent: digest };
    // This rig has no active provers: each turn is declined after the parent
    // executed privately.
    for _ in 0..3 {
        assert!(proposer.propose_with_context(context).is_none());
    }
    assert!(parents.prepared.lock().unwrap().is_some(), "the parent executed privately");
    assert!(sent.0.lock().unwrap().is_empty());
}

#[test]
fn an_unfinalized_parent_executes_privately_without_touching_canonical_state() {
    let rig = rig();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
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

/// A retained parent can outlive its execution view while canonical
/// materialization stays at the same base. Rebuild it from authenticated
/// bodies instead of returning the unusable cache entry forever.
#[test]
fn a_closed_or_failed_private_parent_is_rebuilt_without_canonical_writes() {
    let rig = rig();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
    let (frame, digest) = parent(&rig, 0);
    offer(&rig, &frame);
    let sequence = rig.db.inner().latest_sequence_number();
    let prepared = executor.prepare(digest, RANK).unwrap();
    assert!(Arc::ptr_eq(&prepared, &executor.prepare(digest, RANK).unwrap()));
    prepared._branch.overlay().close();
    let fresh = executor.prepare(digest, RANK).unwrap();
    assert!(!Arc::ptr_eq(&prepared, &fresh));
    assert_eq!(cursor(&fresh.crdt, &rig.filter), Some(1));
    assert!(fresh._branch.overlay().ensure_readable().is_ok());
    assert!(Arc::ptr_eq(&fresh, &executor.prepare(digest, RANK).unwrap()));

    fresh._branch.overlay().record_execution_failure();
    let recovered = executor.prepare(digest, RANK).unwrap();
    assert!(!Arc::ptr_eq(&fresh, &recovered));
    assert_eq!(cursor(&recovered.crdt, &rig.filter), Some(1));
    assert!(recovered._branch.overlay().ensure_readable().is_ok());
    assert!(Arc::ptr_eq(&recovered, &executor.prepare(digest, RANK).unwrap()));
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    assert!(cursor(&rig.manager.crdt(), &rig.filter).is_none());
    assert!(rig.clock.get_shard_clock_frame(&rig.filter, 1, false).is_err());
}

/// A restart can leave several frames notarized but not finalized above the
/// materialized tip (e.g. 5403 and 5404 above 5402, with every member
/// abstaining). The chain up to the selected parent executes privately,
/// oldest first, without touching canonical state; a missing link or views
/// that do not rise refuse it.
#[test]
fn an_unfinalized_chain_above_the_tip_executes_privately() {
    let rig = rig();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
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
    let lone = self::executor(&other, other.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
    assert!(lone.prepare(offer(&other, &second), RANK + 1).is_err());
}

#[test]
fn only_a_validated_child_of_the_materialized_tip_is_executed() {
    let rig = rig();
    let accept = || Arc::new(|_: &AppShardFrame| Ok(())) as AppRequestsRootCheck;
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
    let refused = self::executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Err(("refused", String::new()))));
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
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
    let (frame, digest) = parent(&rig, 0);
    offer(&rig, &frame);
    let prepared = executor.prepare(digest, RANK).unwrap();
    let child = child_of(&rig, &prepared, digest);
    assert!((prepared.check)(&child).is_ok());
    // The canonical checks, one height behind, refuse it.
    assert!((canonical_check(&rig))(&child).is_err());
    // A child declaring another fee total is refused on the branch too.
    let mut changed = child.clone();
    changed.header.as_mut().unwrap().fee_total = 7u128.to_be_bytes().to_vec();
    assert_eq!((prepared.check)(&changed).map_err(|(reason, _)| reason), Err("fee total differs"));
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
    let executor = executor(&rig, master.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
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
        Arc::new(AtomicBool::new(true)),
    )
    .unwrap();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
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


#[test]
fn seal_checkpoint_executes_its_data_view_privately_and_keeps_canonical_state() {
    let rig = rig();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
    let (frame, digest) = parent(&rig, 0);
    offer(&rig, &frame);
    let checkpoint = quil_cw_consensus::handoff::Checkpoint {
        frame: 1, view: RANK + 20, digest: digest.0,
        state_roots: [[0; 32]; 4], history_root: [0; 32],
    };
    let sequence = rig.db.inner().latest_sequence_number();
    let prepared = executor.prepare_checkpoint(&checkpoint).unwrap();
    assert_eq!(prepared.view, RANK, "a re-seal's view is not the underlying data view");
    assert_eq!(prepared.frame_number, 1);
    assert_eq!(prepared.digest, digest);
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    assert!(cursor(&rig.manager.crdt(), &rig.filter).is_none());
    assert_eq!(cursor(&prepared.crdt, &rig.filter), Some(1));
    let wrong_height = quil_cw_consensus::handoff::Checkpoint { frame: 2, ..checkpoint.clone() };
    assert!(executor.prepare_checkpoint(&wrong_height).is_err());
    let absent = quil_cw_consensus::handoff::Checkpoint { digest: [42; 32], ..checkpoint };
    assert!(executor.prepare_checkpoint(&absent).is_err());
}

#[test]
fn seal_checkpoint_rejects_terminal_and_malformed_bodies_without_execution() {
    use quil_cw_consensus::handoff::{Checkpoint, Seal};
    let rig = rig();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
    let checkpoint = Checkpoint {
        frame: 1, view: 5, digest: [42; 32],
        state_roots: [[0; 32]; 4], history_root: [0; 32],
    };
    let seal = Seal { request: [1; 32], session: [2; 32], view: 6, checkpoint: checkpoint.clone() };
    let sequence = rig.db.inner().latest_sequence_number();
    for bytes in [seal.encode(), b"QHSL\x02".to_vec(), vec![0xff], prost::Message::encode_to_vec(&AppShardFrame::default())] {
        rig.blocks.put(digest_from_identity(checkpoint.digest), bytes);
        assert!(executor.prepare_checkpoint(&checkpoint).is_err());
        assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
        assert!(executor.prepared.lock().unwrap().is_none());
        assert!(cursor(&rig.manager.crdt(), &rig.filter).is_none());
    }
}

/// `count` linked unfinalized frames above the genesis tip, one height and one
/// view apart, stored but never executed; their digests, lowest first.
fn linked_frames(rig: &Rig, count: u64) -> Vec<Digest> {
    let mut below = digest_from_identity(genesis());
    (1..=count)
        .map(|number| {
            let frame = AppShardFrame {
                header: Some(FrameHeader {
                    address: rig.filter.clone(),
                    frame_number: number,
                    rank: RANK + number - 1,
                    output: vec![number as u8; 32],
                    parent_selector: below.as_ref().to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            below = offer(rig, &frame);
            below
        })
        .collect()
}

/// Commit `frame` as the materialized tip at its height.
fn materialize(rig: &Rig, frame: &AppShardFrame) {
    let header = frame.header.as_ref().unwrap();
    let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap().to_vec();
    let txn = rig.clock.new_transaction(false).unwrap();
    rig.clock.stage_shard_clock_frame(&selector, frame, txn.as_ref()).unwrap();
    txn.commit().unwrap();
    let txn = rig.clock.new_transaction(false).unwrap();
    rig.clock.commit_shard_clock_frame(&rig.filter, header.frame_number, &selector, txn.as_ref(), false).unwrap();
    txn.commit().unwrap();
    rig.manager.commit_frame_with_app_cursor(header.frame_number, &rig.filter).unwrap();
    rig.materialized.store(header.frame_number, Ordering::SeqCst);
}

#[test]
fn a_nullified_parent_needs_room_for_a_child_and_is_judged_without_execution() {
    let rig = rig();
    let validated = Arc::new(AtomicU32::new(0));
    let counted = validated.clone();
    let executor = executor_with(
        &rig,
        rig.clock.clone(),
        Arc::new(move |_: &AppShardFrame| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }),
        Arc::new(|_: &AppShardFrame| Ok(())),
    );
    let frames = linked_frames(&rig, MAX_PRIVATE_CHAIN as u64 + 1);
    let sequence = rig.db.inner().latest_sequence_number();
    let tip = executor.tip().unwrap();
    // Eight frames above the tip are within one private execution's reach...
    assert_eq!(executor.unfinalized_chain(&tip, frames[7], RANK + 7).unwrap().0.len(), MAX_PRIVATE_CHAIN);
    // ...but a child of the eighth would be the last frame anyone can extend,
    // so a leader falls back past it, to the seventh.
    assert!(executor.extendable(frames[6], RANK + 6));
    assert_eq!(executor.refusal(frames[7], RANK + 7), Some(Refused { depth: 8 }));
    // The ninth is refused by the chain walk, and so by the leader's check.
    let error = executor.unfinalized_chain(&tip, frames[8], RANK + 8).unwrap_err().to_string();
    assert!(error.contains("does not extend the materialized tip"), "{error}");
    assert_eq!(executor.refusal(frames[8], RANK + 8), Some(Refused { depth: 9 }));
    // A parent of another view than the one it was certified at is refused.
    assert!(!executor.extendable(frames[0], RANK + 1));
    // Judged from the bodies alone: nothing validated, executed or written.
    assert_eq!(validated.load(Ordering::SeqCst), 0);
    assert!(executor.prepared.lock().unwrap().is_none());
    assert_eq!(rig.db.inner().latest_sequence_number(), sequence);
    assert_eq!(executor.verdicts.lock().unwrap().len(), 4);
}

#[test]
fn a_verdict_follows_the_materialized_tip() {
    let rig = rig();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
    let frames = linked_frames(&rig, MAX_PRIVATE_CHAIN as u64 + 1);
    executor.tip().unwrap();
    assert_eq!(executor.refusal(frames[7], RANK + 7), Some(Refused { depth: 8 }));
    // The first frame materializes.
    let first = decode_app_frame(&rig.blocks.get(&frames[0]).unwrap()).unwrap();
    materialize(&rig, &first);
    // Until a proposal or vote reads the new tip, the cached verdict is not
    // used and none is given.
    assert!(executor.extendable(frames[7], RANK + 7));
    assert!(executor.extendable(frames[8], RANK + 8));
    assert_eq!(executor.verdicts.lock().unwrap().len(), 1);
    assert!(executor.is_canonical_parent(frames[0]).unwrap());
    // One frame lower: the eighth now leaves room, the ninth does not.
    assert_eq!(executor.refusal(frames[7], RANK + 7), None);
    assert_eq!(executor.refusal(frames[8], RANK + 8), Some(Refused { depth: 8 }));
}

#[test]
fn a_parent_this_member_cannot_judge_stays_extendable() {
    use quil_cw_consensus::handoff::{Checkpoint, Seal};
    let rig = rig();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
    let frames = linked_frames(&rig, MAX_PRIVATE_CHAIN as u64 + 1);
    // No proposal or vote has read the tip yet.
    assert!(executor.extendable(frames[8], RANK + 8));
    assert!(executor.verdicts.lock().unwrap().is_empty());
    executor.tip().unwrap();
    // The materialized tip itself.
    assert!(executor.extendable(digest_from_identity(genesis()), 0));
    // A body this member does not hold, one it cannot decode, and a seal.
    let unknown = digest_from_identity([77; 32]);
    assert!(executor.extendable(unknown, RANK));
    let garbage = digest_from_identity([3; 32]);
    rig.blocks.put(garbage, vec![0xff; 7]);
    assert!(executor.extendable(garbage, RANK));
    let checkpoint = Checkpoint { frame: 1, view: 5, digest: [42; 32], state_roots: [[0; 32]; 4], history_root: [0; 32] };
    let seal = Seal { request: [1; 32], session: [2; 32], view: 6, checkpoint };
    let sealed = digest_from_identity(seal.digest());
    rig.blocks.put(sealed, seal.encode());
    assert!(executor.extendable(sealed, 6));
    // None of these is cached: the body may still arrive.
    assert_eq!(executor.verdicts.lock().unwrap().len(), 1);
    // A tip read at another height than the engine's is not used.
    rig.materialized.store(1, Ordering::SeqCst);
    assert!(executor.extendable(frames[8], RANK + 8));
    rig.materialized.store(0, Ordering::SeqCst);
    assert!(!executor.extendable(frames[8], RANK + 8));
    // An executor without a body store yet.
    let unbound = AppParentExecutor::new(
        rig.filter.clone(),
        rig.filter.clone(),
        rig.manager.clone(),
        rig.manager.crdt(),
        rig.clock.clone(),
        rig.clock.clone(),
        rig.outflows.clone(),
        Arc::new(quil_tries::ShaInclusionProver),
        Arc::new(|_: &AppShardFrame| Ok(true)),
        Arc::new(|_: &AppShardFrame| Ok(())),
        rig.materialized.clone(),
        leader(&rig, rig.clock.clone()),
        None,
    );
    unbound.tip().unwrap();
    assert!(unbound.extendable(frames[8], RANK + 8));
}

#[test]
fn a_parent_that_cannot_be_executed_keeps_the_prepared_one() {
    let rig = rig();
    let executor = executor(&rig, rig.clock.clone(), true, Arc::new(|_: &AppShardFrame| Ok(())));
    let (frame, digest) = parent(&rig, 0);
    offer(&rig, &frame);
    let prepared = executor.prepare(digest, RANK).unwrap();
    // Another leader's proposal on a parent this member cannot execute.
    let frames = linked_frames(&rig, MAX_PRIVATE_CHAIN as u64 + 1);
    assert!(executor.prepare(frames[8], RANK + 8).is_err());
    assert!(Arc::ptr_eq(&executor.prepared.lock().unwrap().clone().unwrap(), &prepared));
    assert!(Arc::ptr_eq(&executor.prepare(digest, RANK).unwrap(), &prepared));
}
