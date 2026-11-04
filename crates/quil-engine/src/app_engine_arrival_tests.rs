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
    let collector = Arc::new(MessageCollector::new());
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
    let app = quil_execution::domains::QUIL_TOKEN;
    let (engine, _) = AppConsensusEngine::new(1, app.to_vec(), deps, events);
    (engine, collector)
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
