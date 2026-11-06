//! What an arriving submission costs this node before anything checked it
//! could still execute. These tests use only interfaces of the release
//! base, so they show its outcome there. They count what the node's
//! admission queue took ([`crate::admission_verify::global`]), so each runs
//! in its own process (nextest).
use super::*;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// An application engine over an execution manager with no proof worker,
/// and its collector.
fn engine_with_execution() -> (AppConsensusEngine, Arc<MessageCollector>) {
    let collector = Arc::new(MessageCollector::new());
    let engine = engine_on(
        quil_execution::domains::QUIL_TOKEN.to_vec(),
        collector.clone(),
    );
    (engine, collector)
}

/// [`engine_with_execution`] for shard `filter` over `collector`, as a worker
/// keeps its pool when it moves to another shard of the application.
fn engine_on(filter: Vec<u8>, collector: Arc<MessageCollector>) -> AppConsensusEngine {
    let rocks = quil_store::RocksDb::open_in_memory().unwrap();
    let store = Arc::new(quil_store::RocksHypergraphStore::new(rocks.inner()));
    let prover = Arc::new(quil_types::crypto::NoopInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, prover.clone()));
    let clock = Arc::new(quil_store::RocksClockStore::new(rocks.inner()));
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
        prover.clone(),
        crypto.key_manager,
        crdt.clone(),
        crypto.circuit_compiler,
        clock.clone(),
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
        false,
    ));
    // Jobs the node's admission queue still holds keep this manager, and
    // its stores, alive; its thread may drop the last one while the test
    // process exits, closing RocksDB during static teardown ("pthread lock:
    // Invalid argument"). Keep it for the process instead, as the node's
    // own exit does.
    std::mem::forget(manager.clone());
    let (events, _received) = mpsc::unbounded_channel();
    let private = [7; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
    let deps = AppEngineDeps {
        delivery_frame_source: None,
        clock_store: clock,
        global_anchor_store: None,
        global_hypergraph: None,
        prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
        frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        message_collector: collector.clone(),
        fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
        local_prover_address: vec![1; 32],
        local_bls_pubkey: vec![],
        bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
        reward_greedy: false,
        min_active_provers_for_propose: 1,
        coverage_publish: None,
        hypergraph: Some(crdt),
        storage_source_hypergraph: None,
        topology: None,
        execution_engine: Some(manager),
        inclusion_prover: Some(prover),
        kv_db: None,
        db_config: Default::default(),
        unified_cutover_hook: None,
    };
    let (engine, _) = AppConsensusEngine::new(1, filter, deps, events);
    engine
}

/// A canonical bundle of one confidential transfer of the QUIL token,
/// distinct per `n`: a valid carrier header (type, version, network,
/// application), so the bundle survives the wire conversion an arrival goes
/// through, and an arbitrary body.
fn transfer_bundle(n: u32) -> Vec<u8> {
    let tp = quil_execution::token_engine::TYPE_LATTICE_TRANSACTION;
    let mut inner = tp.to_be_bytes().to_vec();
    inner.extend_from_slice(b"QCT3TX\0\x02");
    inner.extend_from_slice(&[1; 32]);
    inner.extend_from_slice(&quil_execution::domains::QUIL_TOKEN);
    inner.extend_from_slice(&n.to_le_bytes());
    inner.extend_from_slice(&[0x44; 2048]);
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest {
            inner_type_prefix: tp,
            inner_bytes: inner,
        })],
        timestamp: 1,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// Whether this build counts confidential operations (the workspace builds
/// `quil-execution` with its native prover).
fn counts_confidential(bundle: &[u8]) -> bool {
    quil_execution::ExecutionEngineManager::confidential_operation_count(
        &quil_execution::domains::QUIL_TOKEN,
        bundle,
    ) > 0
}

/// A submission a finalized frame already consumed is not verified again
/// when it arrives again; a new one is.
#[tokio::test]
async fn a_submission_a_finalized_frame_consumed_is_not_verified_again_on_arrival() {
    let (mut engine, collector) = engine_with_execution();
    if !counts_confidential(&transfer_bundle(0)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let queue = crate::admission_verify::global();
    let before = queue.stats().queued;
    engine.add_app_message(&transfer_bundle(1));
    assert_eq!(
        queue.stats().queued,
        before + 1,
        "a new confidential submission is queued on arrival"
    );
    let replay = transfer_bundle(2);
    collector.mark_finalized(&[canonical_app_message(&replay)]);
    engine.add_app_message(&replay);
    assert_eq!(
        queue.stats().queued,
        before + 1,
        "a replayed finalized op was verified again: its arrival was queued for proof verification"
    );
}

/// Arrivals queue at most the admission queue's budget of estimated
/// verification time per window: one thread, 600 worker-seconds, at the
/// 8 s estimate of an operation of a size class not measured yet.
#[tokio::test]
async fn arrivals_queue_at_most_their_budget_of_verification_time() {
    let (mut engine, _collector) = engine_with_execution();
    if !counts_confidential(&transfer_bundle(0)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let queue = crate::admission_verify::global();
    let before = queue.stats().queued;
    const ARRIVALS: u32 = 200;
    for n in 0..ARRIVALS {
        engine.add_app_message(&transfer_bundle(1000 + n));
    }
    let queued = queue.stats().queued - before;
    assert!(
        queued <= 80,
        "arrival verification exceeded its per-interval budget: {queued} of {ARRIVALS} arrivals \
         queued at about 8 s each against 600 worker-seconds"
    );
    assert!(queued >= 70, "the budget admits what fits: {queued} queued");
}

/// The longest shield this test sends: a carrier of 1 MiB does not pass the
/// wire conversion an arrival goes through.
const LONG_SHIELD: usize = (1 << 20) - (1 << 10);
/// Long shields that overflow the 64 MiB rank buffer.
const OVERFLOW: u32 = 66;

/// A canonical bundle of one batch shield of the QUIL token consuming
/// `source` first, distinct per `n`, about `bytes` long: its carrier header,
/// type and version tags and its source are what routing reads, and the rest
/// is arbitrary.
fn shield_bundle(source: [u8; 32], n: u32, bytes: usize) -> Vec<u8> {
    let mut inner = shield_inner(source, n);
    inner.resize(bytes.max(inner.len()), 0x44);
    token_bundle(inner)
}

fn shield_inner(source: [u8; 32], n: u32) -> Vec<u8> {
    let tp = quil_execution::token_engine::TYPE_LATTICE_SHIELD;
    let mut inner = tp.to_be_bytes().to_vec();
    inner.extend_from_slice(b"QCT3SH\0\x03");
    inner.extend_from_slice(&[1; 32]);
    inner.extend_from_slice(&quil_execution::domains::QUIL_TOKEN);
    inner.extend_from_slice(&[0x22; 57]);
    inner.extend_from_slice(&96u16.to_be_bytes());
    inner.extend_from_slice(&source);
    inner.extend_from_slice(&n.to_le_bytes());
    inner
}

fn token_bundle(inner: Vec<u8>) -> Vec<u8> {
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest {
            inner_type_prefix: quil_execution::token_engine::TYPE_LATTICE_SHIELD,
            inner_bytes: inner,
        })],
        timestamp: 1,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// Shard filter of the QUIL token at `bits`.
fn token_shard(bits: &[bool]) -> Vec<u8> {
    quil_forest::encode_shard_bit_path(&quil_execution::domains::QUIL_TOKEN, bits)
}

/// A coin address whose first bits are `bits`.
fn source_under(bits: &[bool], n: u8) -> [u8; 32] {
    let mut source = [n; 32];
    for (index, bit) in bits.iter().enumerate() {
        if *bit {
            source[index / 8] |= 0x80 >> (index % 8);
        } else {
            source[index / 8] &= !(0x80 >> (index % 8));
        }
    }
    source
}

/// 2026-11-02: every worker held bundles only another shard can propose until
/// its 64 MiB rank buffer refused the ones its own shard had to propose,
/// which were lost on that worker and skipped their arrival verification.
#[tokio::test]
async fn shields_only_another_shard_proposes_do_not_refuse_this_shards_own() {
    let shard = token_shard(&[false]);
    let (elsewhere, own) = (source_under(&[true], 1), source_under(&[false], 2));
    let collector = Arc::new(MessageCollector::new());
    let mut engine = engine_on(shard, collector.clone());
    if !counts_confidential(&shield_bundle(own, 0, 1 << 10)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    for n in 0..OVERFLOW {
        engine.add_app_message(&shield_bundle(elsewhere, n, LONG_SHIELD));
    }
    let held = collector.total_pending();
    engine.add_app_message(&shield_bundle(own, 1000, LONG_SHIELD));
    assert_eq!(
        collector.total_pending(),
        held + 1,
        "this shard's own shield was refused: {held} bundles only another shard can propose \
         filled its rank buffer"
    );
}

/// A shield is held only where it can be proposed; a submission that any
/// shard may carry past the routing fallback, and a shield whose source this
/// node cannot read, are held on every shard as before.
#[tokio::test]
async fn a_shield_is_collected_only_on_the_shard_holding_its_source() {
    let holding = [false, true];
    let source = source_under(&holding, 3);
    let shards: Vec<Vec<bool>> = vec![
        vec![false, false],
        vec![false, true],
        vec![true, false],
        vec![true, true],
    ];
    if !counts_confidential(&shield_bundle(source, 0, 1 << 10)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    for bits in &shards {
        let collector = Arc::new(MessageCollector::new());
        let mut engine = engine_on(token_shard(bits), collector.clone());
        engine.add_app_message(&shield_bundle(source, 1, 1 << 10));
        assert_eq!(
            collector.total_pending(),
            usize::from(bits.as_slice() == holding),
            "shard {bits:?} of a shield whose source is under {holding:?}"
        );
        engine.add_app_message(&transfer_bundle(1));
        // Cut before its source: the carrier passes, the source cannot be read.
        let mut unreadable = shield_inner(source, 2);
        unreadable.truncate(100);
        engine.add_app_message(&token_bundle(unreadable));
        assert_eq!(
            collector.total_pending(),
            usize::from(bits.as_slice() == holding) + 2,
            "shard {bits:?} dropped a transfer or a shield with no readable source"
        );
    }
    // The application's one shard holds every source.
    let collector = Arc::new(MessageCollector::new());
    let mut engine = engine_on(
        quil_execution::domains::QUIL_TOKEN.to_vec(),
        collector.clone(),
    );
    engine.add_app_message(&shield_bundle(source, 1, 1 << 10));
    assert_eq!(collector.total_pending(), 1, "an unsplit application");
}

/// A split while a shield is held: the members' pools go with them, so the
/// child holding the source proposes it, and it never leaves a sibling's pool
/// for this; a merge brings it back within the merged shard's range. New
/// arrivals on a child follow the child's range.
#[tokio::test]
async fn a_held_shield_follows_splits_and_merges_to_its_proposer() {
    let (parent, left, right) = (
        token_shard(&[false]),
        token_shard(&[false, false]),
        token_shard(&[false, true]),
    );
    let (under_left, under_right) = (
        source_under(&[false, false], 4),
        source_under(&[false, true], 5),
    );
    let collector = Arc::new(MessageCollector::new());
    if !counts_confidential(&shield_bundle(under_left, 0, 1 << 10)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let mut engine = engine_on(parent.clone(), collector.clone());
    engine.add_app_message(&shield_bundle(under_left, 1, 1 << 10));
    engine.add_app_message(&shield_bundle(under_right, 2, 1 << 10));
    assert_eq!(collector.total_pending(), 2, "the parent holds both");
    // The worker moves to the left child with its pool (`thread_worker`).
    collector.rebase_ranks();
    let mut child = engine_on(left.clone(), collector.clone());
    assert_eq!(collector.total_pending(), 2, "a split drops nothing");
    let proposes = |shard: &[u8], source: [u8; 32]| {
        routed_selection(
            shard,
            &[left.clone(), right.clone()],
            &[[9; 32]],
            &[1],
            &[Some(source)],
            &[std::time::Duration::ZERO],
            ROUTED_FALLBACK,
        )[0]
    };
    assert!(proposes(&left, under_left));
    assert!(!proposes(&left, under_right));
    assert!(proposes(&right, under_right));
    child.add_app_message(&shield_bundle(under_right, 3, 1 << 10));
    assert_eq!(collector.total_pending(), 2, "the sibling's new arrival");
    child.add_app_message(&shield_bundle(under_left, 4, 1 << 10));
    assert_eq!(collector.total_pending(), 3, "its own new arrival");
    // The children merge: the merged shard proposes what either held.
    collector.rebase_ranks();
    let _merged = engine_on(parent.clone(), collector.clone());
    assert_eq!(collector.total_pending(), 3, "a merge drops nothing");
    assert!(routed_selection(
        &parent,
        std::slice::from_ref(&parent),
        &[[9; 32], [8; 32]],
        &[1, 1],
        &[Some(under_left), Some(under_right)],
        &[std::time::Duration::ZERO; 2],
        ROUTED_FALLBACK,
    )
    .iter()
    .all(|keep| *keep));
}

/// The rank buffer still bounds a shard's own shields, and it recovers: past
/// the cap they are refused, and once a frame consumed some, arrivals are
/// collected again.
#[tokio::test]
async fn a_shard_full_of_its_own_shields_collects_again_once_one_executes() {
    let own = source_under(&[false], 6);
    let collector = Arc::new(MessageCollector::new());
    let mut engine = engine_on(token_shard(&[false]), collector.clone());
    if !counts_confidential(&shield_bundle(own, 0, 1 << 10)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let first = shield_bundle(own, 0, LONG_SHIELD);
    engine.add_app_message(&first);
    for n in 1..OVERFLOW {
        engine.add_app_message(&shield_bundle(own, n, LONG_SHIELD));
    }
    let held = collector.total_pending();
    assert!(
        held > 1 && held < OVERFLOW as usize,
        "the cap held {held} of {OVERFLOW} long shields"
    );
    engine.add_app_message(&shield_bundle(own, 1000, LONG_SHIELD));
    assert_eq!(collector.total_pending(), held, "full: refused");
    collector.mark_finalized(&[canonical_app_message(&first)]);
    assert_eq!(collector.total_pending(), held - 1);
    engine.add_app_message(&shield_bundle(own, 1000, LONG_SHIELD));
    assert_eq!(
        collector.total_pending(),
        held,
        "a frame consumed one, and the shard still refuses its shields"
    );
}

/// The arrival lines are bounded, so what came after the last one must reach
/// the log when arrivals stop, or a flood's end is lost.
#[tokio::test]
async fn the_last_count_of_shields_left_to_other_shards_is_logged_when_they_stop() {
    let every = SHIELDS_ELSEWHERE_LOG_EVERY;
    let elsewhere = source_under(&[true], 1);
    let collector = Arc::new(MessageCollector::new());
    let mut engine = engine_on(token_shard(&[false]), collector);
    if !counts_confidential(&shield_bundle(elsewhere, 0, 1 << 10)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let logs = crate::outage::test_logs::CapturedLogs::default();
    let _guard = logs.install();
    let text = "shields for other shards left uncollected";
    for n in 0..3 {
        engine.add_app_message(&shield_bundle(elsewhere, n, 1 << 10));
    }
    assert_eq!(logs.lines_with(text).len(), 1, "the first one reports");
    engine.report_arrivals_left();
    assert_eq!(
        logs.lines_with(text).len(),
        1,
        "bounded: none before it is due"
    );
    engine.shields_elsewhere.logged = std::time::Instant::now().checked_sub(every);
    engine.report_arrivals_left();
    let lines = logs.lines_with(text);
    assert_eq!(lines.len(), 2, "the last count was lost: {lines:?}");
    assert!(lines[1].contains("shields=2"), "{}", lines[1]);
    engine.shields_elsewhere.logged = std::time::Instant::now().checked_sub(every);
    engine.report_arrivals_left();
    assert_eq!(logs.lines_with(text).len(), 2, "nothing left to report");
}

#[test]
fn the_last_count_of_refused_arrivals_is_logged_when_they_stop() {
    let every = SHIELDS_ELSEWHERE_LOG_EVERY;
    let logs = crate::outage::test_logs::CapturedLogs::default();
    let _guard = logs.install();
    let text = "refused on arrival since the last line";
    let mut refused = MalformedArrivals::default();
    for _ in 0..3 {
        refused.note(b"filter", 10);
    }
    assert_eq!(logs.lines_with(text).len(), 1, "the first one reports");
    refused.report(b"filter");
    assert_eq!(
        logs.lines_with(text).len(),
        1,
        "bounded: none before it is due"
    );
    refused.logged = std::time::Instant::now().checked_sub(every);
    refused.report(b"filter");
    let lines = logs.lines_with(text);
    assert_eq!(lines.len(), 2, "the last count was lost: {lines:?}");
    assert!(lines[1].contains("submissions=2"), "{}", lines[1]);
    assert!(lines[1].contains("bytes=20"), "{}", lines[1]);
    refused.logged = std::time::Instant::now().checked_sub(every);
    refused.report(b"filter");
    assert_eq!(logs.lines_with(text).len(), 2, "nothing left to report");
}
