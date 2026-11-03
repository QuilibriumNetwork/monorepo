//! The consensus retry tick on a worker store where a point read of a
//! small record costs a storage replica's read: a replica written after the
//! record lands in a table whose key range covers the record, in one table
//! block with a small record below it, and without a bloom filter every
//! read of the record that reaches that table copies the whole block. A
//! mainnet worker's tick read about 1 GB so four times, holding its thread
//! 6 to 40 s (2026-10-31).
use super::*;
use quil_types::store::KvDb as _;

/// Bytes this thread has read through system calls (`rchar`), page cache
/// hits included.
fn thread_read_bytes() -> u64 {
    std::fs::read_to_string("/proc/thread-self/io")
        .expect("/proc/thread-self/io")
        .lines()
        .find_map(|line| line.strip_prefix("rchar:")?.trim().parse().ok())
        .expect("rchar")
}

/// Incompressible bytes, as a replica's are.
fn replica_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut bytes = Vec::with_capacity(len + 8);
    while bytes.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}

struct RestorePolicy(Option<quil_types::consensus::CommitteeHandoffPolicy>);

impl Drop for RestorePolicy {
    fn drop(&mut self) {
        quil_types::consensus::set_committee_handoff_policy(self.0);
    }
}

fn engine_on(clock: Arc<dyn ClockStore>) -> AppConsensusEngine {
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
        message_collector: Arc::new(MessageCollector::new()),
        fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
        local_prover_address: vec![1; 32],
        local_bls_pubkey: vec![],
        bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
        reward_greedy: false,
        min_active_provers_for_propose: 1,
        coverage_publish: None,
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
    AppConsensusEngine::new(
        1,
        quil_execution::domains::QUIL_TOKEN.to_vec(),
        deps,
        events,
    )
    .0
}

/// Past the committee-handoff flag day, a retry tick checks the legacy
/// history discard twice (its own check and its start attempt's) and its
/// start attempt's finalized-records scan reads the same record. The record
/// is written once and never removed: an engine reads it once.
#[tokio::test(flavor = "current_thread")]
async fn retry_ticks_read_the_legacy_history_record_once_per_engine() {
    use quil_types::consensus::{CommitteeHandoffPolicy, LegacyHistory};
    const REPLICA: usize = 64 << 20;
    const TICKS: usize = 3;
    let _restore = RestorePolicy(quil_types::consensus::committee_handoff_policy());
    quil_types::consensus::set_committee_handoff_policy(Some(CommitteeHandoffPolicy {
        activation_frame: 0,
        chain_id: [7; 32],
        legacy_history: LegacyHistory::Discard,
        membership_boundary_frame: u64::MAX,
        first_session_boundary_frame: u64::MAX,
    }));
    let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
    let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
    // The flag day's record, compacted to the bottom level.
    clock.discard_app_frame_history(1).unwrap();
    db.inner().flush().unwrap();
    db.compact_all().unwrap();
    // A small record below it and a replica above it, flushed together.
    let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
    db.set(
        &quil_store::encoding::consensus_materialized_cursor_key(&filter),
        &5u64.to_be_bytes(),
    )
    .unwrap();
    quil_store::replica_store::ReplicaStore::new(db.clone())
        .put(3, &[0xab; 32], &replica_bytes(REPLICA))
        .unwrap();
    db.inner().flush().unwrap();

    let mut engine = engine_on(clock);
    let read_before = thread_read_bytes();
    let started = std::time::Instant::now();
    for _ in 0..TICKS {
        engine.discard_legacy_history_if_due().await.unwrap();
        engine.discard_legacy_history_if_due().await.unwrap();
        engine.drop_discarded_finalized_records().unwrap();
    }
    let held = started.elapsed();
    let read = thread_read_bytes() - read_before;
    assert!(
        read < 2 * REPLICA as u64,
        "{TICKS} consensus retry ticks held the worker thread {held:?}: their legacy history checks read \
         {} MiB from the store, {:.1} times the {} MiB replica the record's table block holds; one read of \
         the record per engine is expected",
        read >> 20,
        read as f64 / REPLICA as f64,
        REPLICA >> 20,
    );
    assert_eq!(
        engine.clock_store.app_frame_history_discarded().unwrap(),
        Some(1)
    );
}

/// [`engine_on`] for a shard engine whose trees and records share `db`.
fn shard_engine_on(
    db: &quil_store::RocksDb,
    clock: Arc<quil_store::RocksClockStore>,
) -> AppConsensusEngine {
    let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
    let prover = Arc::new(quil_types::crypto::NoopInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, prover.clone()));
    crdt.set_forest(quil_forest::Forest::with_namespace(
        db.inner(),
        quil_store::FOREST_NAMESPACE,
    ));
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
        message_collector: Arc::new(MessageCollector::new()),
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
        app_consensus_cw: false,
        db_config: Default::default(),
        unified_cutover_hook: None,
    };
    AppConsensusEngine::new(
        1,
        quil_execution::domains::QUIL_TOKEN.to_vec(),
        deps,
        events,
    )
    .0
}

/// An engine's start and each consensus start attempt check the legacy
/// history discard, the re-anchor marker and the dropped-lineage record.
/// Their keys sort just below the storage replicas, so each read on the
/// worker thread copied a replica stored whole in their table block: 7 to
/// 14 s a read on a regular node of 47 workers starting together
/// (2026-11-01). The engine reads them off the worker thread, once.
#[tokio::test(flavor = "current_thread")]
async fn start_checks_read_their_records_off_the_worker_thread() {
    use quil_types::consensus::{CommitteeHandoffPolicy, LegacyHistory};
    const REPLICA: usize = 64 << 20;
    const STARTS: usize = 3;
    let _restore = RestorePolicy(quil_types::consensus::committee_handoff_policy());
    quil_types::consensus::set_committee_handoff_policy(Some(CommitteeHandoffPolicy {
        activation_frame: 0,
        chain_id: [7; 32],
        legacy_history: LegacyHistory::Discard,
        membership_boundary_frame: u64::MAX,
        first_session_boundary_frame: u64::MAX,
    }));
    let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
    let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
    // The flag day's record, compacted to the bottom level.
    clock.discard_app_frame_history(1).unwrap();
    db.inner().flush().unwrap();
    db.compact_all().unwrap();
    // A small record below the start records' keys and a replica above
    // them, flushed together: no re-anchor marker, no dropped lineage.
    let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
    db.set(
        &quil_store::encoding::consensus_materialized_cursor_key(&filter),
        &5u64.to_be_bytes(),
    )
    .unwrap();
    quil_store::replica_store::ReplicaStore::new(db.clone())
        .put(3, &[0xab; 32], &replica_bytes(REPLICA))
        .unwrap();
    db.inner().flush().unwrap();

    let mut engine = shard_engine_on(&db, clock);
    let read_before = thread_read_bytes();
    let started = std::time::Instant::now();
    // The engine's start, then its consensus start attempts.
    for _ in 0..=STARTS {
        engine.prefetch_start_records().await;
        engine.discard_legacy_history_if_due().await.unwrap();
        engine.drop_discarded_finalized_records().unwrap();
        assert!(!engine.rewind_past_fence().unwrap());
    }
    let held = started.elapsed();
    let read = thread_read_bytes() - read_before;
    assert!(
        read < REPLICA as u64,
        "an engine start and {STARTS} consensus start attempts held the worker thread {held:?}: their start \
         checks read {} MiB from the store on it, {:.1} times the {} MiB replica their records' table block \
         holds; none is expected on the worker thread",
        read >> 20,
        read as f64 / REPLICA as f64,
        REPLICA >> 20,
    );
    assert!(engine.lineage_record_absent, "no dropped lineage recorded");
    assert_eq!(
        engine.fence_reanchor.marker,
        Some(None),
        "no re-anchor owed"
    );
    assert_eq!(engine.legacy_history_discarded().unwrap(), Some(1));
}
