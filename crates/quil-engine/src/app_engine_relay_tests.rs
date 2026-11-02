//! A confidential bundle whose spend relay GLOBAL skipped. These tests use only
//! interfaces of the release base, so they show its outcome there. GLOBAL's
//! part is real: its commit runs on the relay of each header it executes, and
//! the session tip moves as `invoke_frame_header` moves it. The bounds are
//! `relay_reoffer`'s: 180 frames below the tip, 32 frames a tick, 3 re-offers.
use super::*;
use quil_execution::global_intrinsic::handoff;
use quil_execution::hypergraph_state::HypergraphState;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_execution::token_intrinsic::global_commit::{self, SpendEntry};
use quil_types::crypto::Signer as _;

const APP: [u8; 32] = quil_execution::domains::QUIL_TOKEN;

/// One operation of the QUIL token, distinct per `n`: a valid carrier header,
/// so a bundle of it survives the wire conversion, and an arbitrary body.
fn operation(n: u32) -> Vec<u8> {
    let mut inner = quil_execution::token_engine::TYPE_LATTICE_TRANSACTION
        .to_be_bytes()
        .to_vec();
    inner.extend_from_slice(b"QCT3TX\0\x02");
    inner.extend_from_slice(&[1; 32]);
    inner.extend_from_slice(&APP);
    inner.extend_from_slice(&n.to_le_bytes());
    inner.extend_from_slice(&[0x44; 64]);
    inner
}

fn bundle_of(operations: &[Vec<u8>]) -> Vec<u8> {
    CanonicalMessageBundle {
        requests: operations
            .iter()
            .map(|inner| {
                Some(CanonicalMessageRequest {
                    inner_type_prefix: quil_execution::token_engine::TYPE_LATTICE_TRANSACTION,
                    inner_bytes: inner.clone(),
                })
            })
            .collect(),
        timestamp: 1,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// The spend entry a frame records for `inner` executed at `source_frame`.
fn entry(inner: &[u8], source_frame: u64) -> Vec<u8> {
    let tx_id = global_commit::tx_id(inner);
    let mut output = tx_id;
    output[0] = 0b0000_0100;
    SpendEntry {
        kind: quil_execution::token_engine::TYPE_LATTICE_TRANSACTION,
        tx_id,
        source_frame,
        context: [8; 32],
        root_digest: None,
        consumptions: vec![tx_id],
        outputs: vec![output],
        escrow_create: None,
        escrow_claim: None,
        fee: 5,
        settlement: None,
    }
    .encode()
    .unwrap()
}

/// A committee member of the QUIL token shard, with GLOBAL's state and the
/// shard's clock store underneath, and frames `1..=frames` recorded empty.
struct Member {
    engine: AppConsensusEngine,
    collector: Arc<MessageCollector>,
    clock: Arc<quil_store::RocksClockStore>,
    global: Arc<quil_hypergraph::HypergraphCrdt>,
    session: [u8; 32],
    outflows: FrameOutflows,
    global_frame: u64,
    _global_db: quil_store::RocksDb,
    _clock_db: quil_store::RocksDb,
}

fn member(frames: u64) -> Member {
    let global_db = quil_store::RocksDb::open_in_memory().unwrap();
    let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_store::RocksHypergraphStore::new(global_db.inner())),
        Arc::new(quil_hypergraph::testing::StubProver),
    ));
    global.set_forest(quil_forest::Forest::with_namespace(
        global_db.inner(),
        quil_store::FOREST_NAMESPACE,
    ));
    let clock_db = quil_store::RocksDb::open_in_memory().unwrap();
    let clock = Arc::new(quil_store::RocksClockStore::new(clock_db.inner()));
    let mut keys: Vec<Vec<u8>> = (0..4)
        .map(|_| quil_crypto::FalconSigner::generate().public_key().to_vec())
        .collect();
    keys.sort();
    let session = quil_cw_consensus::handoff::Session {
        chain_id: [7; 32],
        filter: APP.to_vec(),
        generation: 1,
        genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
        base_frame: 0,
        authorization: [0; 32],
        members: keys.clone(),
    };
    let state = HypergraphState::new(global.clone());
    handoff::initialize(&state, 1, &session).unwrap();
    state.commit().unwrap();
    state.abort();
    global
        .commit_with_global_cursor(1, &quil_store::encoding::global_materialized_cursor_key())
        .unwrap();
    let collector = Arc::new(MessageCollector::new());
    let (events, _received) = mpsc::unbounded_channel();
    let private = [7; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
    let deps = AppEngineDeps {
        delivery_frame_source: None,
        clock_store: clock.clone(),
        global_anchor_store: None,
        global_hypergraph: Some(global.clone()),
        prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
        frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        message_collector: collector.clone(),
        fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
        local_prover_address: vec![1; 32],
        local_bls_pubkey: keys[0].clone(),
        bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
        reward_greedy: false,
        min_active_provers_for_propose: 1,
        coverage_publish: Some(Arc::new(|_: Vec<u8>| {})),
        hypergraph: None,
        storage_source_hypergraph: None,
        topology: None,
        execution_engine: None,
        inclusion_prover: None,
        kv_db: None,
        app_consensus_cw: false,
        db_config: Default::default(),
        unified_cutover_hook: None,
    };
    let (mut engine, _handle) = AppConsensusEngine::new(1, APP.to_vec(), deps, events);
    let id = session.id().unwrap();
    engine.cw_session = Some(session);
    engine.last_materialized_frame = frames;
    let outflows = FrameOutflows::default();
    for frame in 1..=frames {
        record_frame_spends(&outflows, &*clock, &APP, frame, &[]);
    }
    Member {
        engine,
        collector,
        clock,
        global,
        session: id,
        outflows,
        global_frame: 10,
        _global_db: global_db,
        _clock_db: clock_db,
    }
}

impl Member {
    /// Frame `number` of the shard: its certified body and the spend entries
    /// it recorded, as materializing it leaves them, its taken bundles
    /// consumed from the mempool.
    fn frame(&mut self, number: u64, body: &[&Vec<u8>], taken: &[&Vec<u8>], entries: Vec<Vec<u8>>) {
        let header = quil_types::proto::global::FrameHeader {
            address: APP.to_vec(),
            frame_number: number,
            rank: number,
            output: vec![number as u8; 516],
            ..Default::default()
        };
        let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap();
        let requests = body
            .iter()
            .map(|bundle| {
                let proto = crate::consensus_wire::decode_app_message_bundle(bundle).unwrap();
                assert_eq!(
                    crate::consensus_wire::app_bundle_to_canonical_bytes(&proto).unwrap(),
                    **bundle,
                    "the fixture's bundle survives the wire conversion"
                );
                proto
            })
            .collect();
        let frame = quil_types::proto::global::AppShardFrame {
            header: Some(header),
            requests,
            ..Default::default()
        };
        // Separate transactions, as the engine does: the commit reads what was
        // staged from the store.
        let txn = self.clock.new_transaction(false).unwrap();
        self.clock
            .stage_shard_clock_frame(&selector, &frame, txn.as_ref())
            .unwrap();
        txn.commit().unwrap();
        let txn = self.clock.new_transaction(false).unwrap();
        self.clock
            .commit_shard_clock_frame(&APP, number, &selector, txn.as_ref(), false)
            .unwrap();
        txn.commit().unwrap();
        record_frame_spends(&self.outflows, &*self.clock, &APP, number, &entries);
        let taken: Vec<Vec<u8>> = taken.iter().map(|bundle| bundle.to_vec()).collect();
        self.collector.mark_finalized(&taken);
        self.engine.last_materialized_frame = self.engine.last_materialized_frame.max(number);
    }

    /// GLOBAL executes the shard's header `number`: its commit on the header's
    /// relay and the session tip, as one committed frame. Returns the fees of
    /// the operations that committed.
    fn execute_header(&mut self, number: u64) -> u128 {
        self.global_frame += 1;
        let relay = spend_relay(&self.outflows, &*self.clock, &APP, number)
            .expect("the fixture records every frame of a header's window");
        let state = HypergraphState::new(self.global.clone());
        let fees =
            global_commit::materialize_relay(&state, self.global_frame, &APP, number, &relay)
                .unwrap();
        let tip = quil_cw_consensus::handoff::Checkpoint {
            frame: number,
            view: number,
            digest: [0; 32],
            state_roots: [[0; 32]; 4],
            history_root: [0; 32],
        };
        handoff::record_session_tip(&state, self.global_frame, &self.session, &tip).unwrap();
        state.commit().unwrap();
        state.abort();
        self.global
            .commit_with_global_cursor(
                self.global_frame,
                &quil_store::encoding::global_materialized_cursor_key(),
            )
            .unwrap();
        fees
    }

    fn decided(&self, inner: &[u8]) -> bool {
        global_commit::is_decided(
            &HypergraphState::new(self.global.clone()),
            &APP,
            &global_commit::tx_id(inner),
        )
        .unwrap()
    }

    /// What a proposal would collect now, leaving it held: arrivals are filed
    /// at rank 0 here, since no proposal moved the collector's newest rank.
    fn offered(&self) -> Vec<Vec<u8>> {
        self.collector.collect_for_rank(0)
    }
}

/// GLOBAL executes header 4 and then header 14, whose relay covers 6..=13, so
/// no executed header relays frame 5: its operation never commits and the
/// shard holds its bundle as consumed. It has to come back, and then commit
/// exactly once.
#[tokio::test]
async fn a_bundle_whose_spend_relay_global_skipped_is_offered_again() {
    let mut member = member(40);
    let inner = operation(1);
    let bundle = bundle_of(std::slice::from_ref(&inner));
    member.frame(5, &[&bundle], &[&bundle], vec![entry(&inner, 5)]);

    assert_eq!(member.execute_header(4), 0);
    member.engine.maintain_committee_session().await;
    assert!(member.offered().is_empty(), "nothing is skipped yet");
    assert_eq!(member.execute_header(14), 0, "header 14 relays 6..=13");
    assert!(
        !member.decided(&inner),
        "no executed header relayed frame 5"
    );

    member.engine.maintain_committee_session().await;
    assert_eq!(
        member.offered(),
        vec![bundle.clone()],
        "STRANDED: GLOBAL executed headers 4 and 14, so frame 5's spend never committed and no \
         executed header can relay it, yet the bundle stays consumed in the shard's mempool: only \
         its sender can still commit it"
    );

    // A later frame executes it again, from which later headers relay it.
    member.frame(16, &[&bundle], &[&bundle], vec![entry(&inner, 16)]);
    assert!(member.offered().is_empty(), "the frame consumed it");
    assert_eq!(member.execute_header(17), 5, "it commits, and pays, once");
    assert!(member.decided(&inner));
    assert_eq!(
        member.execute_header(18),
        0,
        "the relay re-carried adds nothing"
    );
    member.execute_header(30);
    member.engine.maintain_committee_session().await;
    assert!(member.offered().is_empty(), "decided, it stays out");
}

/// A successor up to 8 frames above a header relays everything since; the next
/// frame leaves the header's own frame to nobody, which is the first the
/// watch must take.
#[tokio::test]
async fn the_previous_headers_own_frame_is_the_first_a_skip_leaves() {
    let mut within = member(40);
    let inner = operation(1);
    let bundle = bundle_of(std::slice::from_ref(&inner));
    within.frame(5, &[&bundle], &[&bundle], vec![entry(&inner, 5)]);
    within.execute_header(5);
    within.engine.maintain_committee_session().await;
    assert_eq!(within.execute_header(13), 5, "header 13 relays 5..=12");
    within.engine.maintain_committee_session().await;
    assert!(within.offered().is_empty(), "committed by its window");

    let mut past = member(40);
    past.frame(5, &[&bundle], &[&bundle], vec![entry(&inner, 5)]);
    past.execute_header(5);
    past.engine.maintain_committee_session().await;
    assert_eq!(past.execute_header(14), 0, "header 14 relays 6..=13");
    past.engine.maintain_committee_session().await;
    assert_eq!(past.offered(), vec![bundle], "advance 9 skips frame 5");
}

/// Ticks miss headers GLOBAL executes between them. A tip seen jumping past the
/// window does not prove a skip: what a missed header relayed is decided.
#[tokio::test]
async fn a_bundle_a_missed_header_relayed_is_not_offered() {
    let mut member = member(40);
    let inner = operation(1);
    let bundle = bundle_of(std::slice::from_ref(&inner));
    member.frame(5, &[&bundle], &[&bundle], vec![entry(&inner, 5)]);
    member.execute_header(4);
    member.engine.maintain_committee_session().await;
    assert_eq!(member.execute_header(9), 5, "header 9 relays 1..=8");
    member.execute_header(14);
    member.engine.maintain_committee_session().await;
    assert!(member.offered().is_empty(), "GLOBAL decided it");
}

/// A frame that executed the operation again owns it now: the older frame's
/// skip, seen late by a member that has not caught up with its tip, does not
/// bring it back while that frame's relay is in flight.
#[tokio::test]
async fn a_bundle_a_later_frame_executed_again_is_not_offered_for_the_older_frame() {
    let mut member = member(40);
    let inner = operation(1);
    let bundle = bundle_of(std::slice::from_ref(&inner));
    member.frame(5, &[&bundle], &[&bundle], vec![entry(&inner, 5)]);
    member.frame(16, &[&bundle], &[&bundle], vec![entry(&inner, 16)]);
    member.execute_header(4);
    member.engine.maintain_committee_session().await;
    member.execute_header(14);
    member.engine.maintain_committee_session().await;
    assert!(member.offered().is_empty(), "frame 16 carries it");
    assert!(!member.decided(&inner));
    assert_eq!(member.execute_header(17), 5, "and its relay commits it");
}

/// Executing a bundle again applies all of it again. One with an operation
/// that took no relay entry, which commits on the shard itself, stays out, and
/// so does one the frame skipped, which took effect nowhere.
#[tokio::test]
async fn only_a_bundle_every_operation_of_which_was_relayed_is_offered() {
    let mut member = member(40);
    let (first, second, skipped) = (operation(1), operation(2), operation(3));
    let mixed = bundle_of(&[first.clone(), second]);
    let left_out = bundle_of(std::slice::from_ref(&skipped));
    member.frame(5, &[&mixed, &left_out], &[&mixed], vec![entry(&first, 5)]);
    member.execute_header(4);
    member.engine.maintain_committee_session().await;
    member.execute_header(14);
    member.engine.maintain_committee_session().await;
    assert!(!member.decided(&first));
    assert!(member.offered().is_empty());
}

/// Each re-offer needs GLOBAL to skip the bundle's new source frame too, and
/// stops at the cap with one warning, leaving a sender's new submission free.
#[tokio::test]
async fn re_offers_of_a_bundle_stop_at_the_cap_and_a_new_submission_still_runs() {
    use crate::outage::test_logs::CapturedLogs;
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let mut member = member(100);
    let inner = operation(1);
    let bundle = bundle_of(std::slice::from_ref(&inner));
    let mut source = 5;
    member.frame(source, &[&bundle], &[&bundle], vec![entry(&inner, source)]);
    member.execute_header(source - 1);
    member.engine.maintain_committee_session().await;
    for attempt in 1..=3 {
        let tip = source + 9;
        member.execute_header(tip);
        member.engine.maintain_committee_session().await;
        assert_eq!(member.offered(), vec![bundle.clone()], "attempt {attempt}");
        let line = logs.lines_with("re-offering a confidential bundle");
        assert_eq!(line.len(), attempt as usize, "{line:?}");
        assert!(line[attempt as usize - 1].contains(&format!("attempt={attempt}")));
        source = tip + 1;
        member.frame(source, &[&bundle], &[&bundle], vec![entry(&inner, source)]);
        assert!(member.offered().is_empty(), "the frame consumed it");
        member.execute_header(source - 1);
        member.engine.maintain_committee_session().await;
    }
    for _ in 0..2 {
        let tip = source + 9;
        member.execute_header(tip);
        member.engine.maintain_committee_session().await;
        assert!(member.offered().is_empty(), "at the cap");
        source = tip + 1;
        member.frame(source, &[&bundle], &[&bundle], vec![entry(&inner, source)]);
        member.execute_header(source - 1);
        member.engine.maintain_committee_session().await;
    }
    let given_up = logs.lines_with("giving up re-offering");
    assert_eq!(given_up.len(), 1, "{given_up:?}");
    assert!(given_up[0].contains("WARN"), "{}", given_up[0]);
    assert!(!member.decided(&inner));
    // The sender's new submission is another bundle: nothing stands in its way.
    let again = bundle_of(&[operation(2)]);
    assert!(member.collector.add_message_newest(again.clone()));
    assert_eq!(member.offered(), vec![again]);
}

/// A skip older than the horizon stays uncommitted and is reported as such; a
/// skipped frame within it still comes back.
#[tokio::test]
async fn a_skip_past_the_horizon_is_reported_and_a_newer_one_still_comes_back() {
    use crate::outage::test_logs::CapturedLogs;
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let mut member = member(520);
    let (old, new) = (operation(1), operation(2));
    let (old_bundle, new_bundle) = (
        bundle_of(std::slice::from_ref(&old)),
        bundle_of(std::slice::from_ref(&new)),
    );
    member.frame(5, &[&old_bundle], &[&old_bundle], vec![entry(&old, 5)]);
    member.frame(400, &[&new_bundle], &[&new_bundle], vec![entry(&new, 400)]);
    member.execute_header(4);
    member.engine.maintain_committee_session().await;
    member.execute_header(500);
    for _ in 0..6 {
        member.engine.maintain_committee_session().await;
    }
    assert_eq!(member.offered(), vec![new_bundle]);
    let line = logs.lines_with("left the spend re-offer horizon");
    assert_eq!(line.len(), 1, "{line:?}");
    assert!(line[0].contains("INFO"), "{}", line[0]);
    assert!(
        line[0].contains("frames=316"),
        "4..=319 are past 320: {}",
        line[0]
    );
}

/// After a start nothing says where the tip was: the first tick looks back over
/// the horizon, at a bounded pace, once.
#[tokio::test]
async fn a_start_looks_back_over_the_horizon_at_a_bounded_pace_and_once() {
    let mut member = member(320);
    let inner = operation(1);
    let bundle = bundle_of(std::slice::from_ref(&inner));
    member.frame(290, &[&bundle], &[&bundle], vec![entry(&inner, 290)]);
    member.execute_header(300);
    // Frames 120..=291: at 32 a tick the sixth reaches frame 290.
    for tick in 1..=5 {
        member.engine.maintain_committee_session().await;
        assert!(member.offered().is_empty(), "tick {tick}");
    }
    member.engine.maintain_committee_session().await;
    assert_eq!(member.offered(), vec![bundle.clone()]);
    member.frame(310, &[&bundle], &[&bundle], vec![entry(&inner, 310)]);
    assert!(member.offered().is_empty());
    member.engine.maintain_committee_session().await;
    assert!(member.offered().is_empty(), "the look back ran once");
}

/// A mempool whose rank is full refuses the bundle; the frame stays queued and
/// the bundle comes back once there is room.
#[tokio::test]
async fn a_full_mempool_delays_a_re_offer_until_there_is_room() {
    let mut member = member(40);
    let inner = operation(1);
    let bundle = bundle_of(std::slice::from_ref(&inner));
    member.frame(5, &[&bundle], &[&bundle], vec![entry(&inner, 5)]);
    member.execute_header(4);
    member.engine.maintain_committee_session().await;
    let fillers: Vec<Vec<u8>> = (0..65_536u64).map(|i| i.to_be_bytes().to_vec()).collect();
    for filler in &fillers {
        assert!(member.collector.add_message_newest(filler.clone()));
    }
    member.execute_header(14);
    member.engine.maintain_committee_session().await;
    member.engine.maintain_committee_session().await;
    assert!(!member.offered().contains(&bundle), "refused while full");
    member.collector.remove(&fillers);
    member.engine.maintain_committee_session().await;
    assert_eq!(member.offered(), vec![bundle], "room, and it is back");
}

/// A member that reached a skipped frame by sync holds its entries but not its
/// body. It says so once and goes on; the frame does not hold up the rest.
#[tokio::test]
async fn a_frame_without_its_body_is_passed_over() {
    use crate::outage::test_logs::CapturedLogs;
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let mut member = member(40);
    let (lost, held) = (operation(1), operation(2));
    let held_bundle = bundle_of(std::slice::from_ref(&held));
    record_frame_spends(
        &member.outflows,
        &*member.clock,
        &APP,
        5,
        &[entry(&lost, 5)],
    );
    member.frame(6, &[&held_bundle], &[&held_bundle], vec![entry(&held, 6)]);
    member.execute_header(4);
    member.engine.maintain_committee_session().await;
    member.execute_header(15);
    member.engine.maintain_committee_session().await;
    member.engine.maintain_committee_session().await;
    assert_eq!(member.offered(), vec![held_bundle]);
    let line = logs.lines_with("cannot examine a frame");
    assert_eq!(line.len(), 1, "{line:?}");
    assert!(line[0].contains("source_frame=5"), "{}", line[0]);
}
