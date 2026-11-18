use super::*;
use quil_execution::{
    global_intrinsic::handoff, hypergraph_state::HypergraphState, ExecutionBranchLimits,
    ExecutionEngineManager,
};
use quil_hypergraph::addressing::Location;
use quil_types::{crypto::Signer as _, store::ShardKey};

fn limits() -> ExecutionBranchLimits {
    ExecutionBranchLimits {
        state: quil_hypergraph::ExecutionForkLimits {
            overlay: quil_forest::OverlayLimits {
                max_delta_bytes: 16 << 20,
                max_delta_entries: 100_000,
                max_record_bytes: 2 << 20,
                max_read_bytes: 128 << 20,
                max_read_operations: 2_000_000,
                max_cursors: 128,
            },
            max_metadata_entries: 10_000,
            max_metadata_bytes: 4 << 20,
        },
        registry: quil_execution::RegistryLimits {
            max_vertices: 10_000,
            max_record_bytes: 2 << 20,
            max_input_bytes: 16 << 20,
            max_cache_entries: 100_000,
            max_cache_bytes: 16 << 20,
        },
        max_summary_rebuilds: 1000,
    }
}

struct Fixture {
    db: Arc<quil_store::RocksDb>,
    store: Arc<quil_store::RocksHypergraphStore>,
    crdt: Arc<HypergraphCrdt>,
    manager: ExecutionEngineManager,
}
impl Fixture {
    fn new() -> Self {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let prover = Arc::new(quil_tries::ShaInclusionProver);
        let crdt = Arc::new(HypergraphCrdt::new(store.clone(), prover.clone()));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(true);
        crdt.warm_sizes(&[]).unwrap();
        let stubs = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = ExecutionEngineManager::new_with_shards(
            prover,
            stubs.key_manager,
            crdt.clone(),
            stubs.circuit_compiler,
            Arc::new(quil_store::RocksClockStore::new(db.inner())),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            true,
            Some(Arc::new(quil_store::RocksShardsStore::new(db.inner()))),
            Some(db.clone()),
        );
        Self {
            db,
            store,
            crdt,
            manager,
        }
    }

    fn seed(&self) -> (Vec<Vec<u8>>, quil_cw_consensus::handoff::Session, Vec<u8>) {
        let mut members: Vec<_> = (0..2)
            .map(|_| quil_crypto::FalconSigner::generate().public_key().to_vec())
            .collect();
        members.sort();
        let session = quil_cw_consensus::handoff::Session {
            chain_id: [7; 32],
            filter: vec![0x61; 32],
            generation: 1,
            genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
            base_frame: 0,
            authorization: [0; 32],
            members: members.clone(),
        };
        crate::genesis::seed_active_prover_on_filter(&self.crdt, &members[1], 5, 1, &[]).unwrap();
        let state = HypergraphState::new(self.crdt.clone());
        handoff::initialize(&state, 1, &session).unwrap();
        state.commit().unwrap();
        state.abort();
        let tree = quil_execution::global_intrinsic::materialize::create_prover_vertex_tree(
            &members[0],
            0,
        )
        .unwrap();
        let blob = quil_execution::prover_registry::vertex_tree_to_blob(&tree);
        self.crdt
            .add_vertex(
                &Location {
                    app_address: [9; 32],
                    data_address: [1; 32],
                },
                &blob,
            )
            .unwrap();
        self.crdt
            .commit_with_global_cursor(1, &quil_store::encoding::global_materialized_cursor_key())
            .unwrap();
        (members, session, blob)
    }
}

#[test]
fn branch_reset_preserves_sessions_other_apps_and_primary_and_marks_its_store() {
    let fixture = Fixture::new();
    let (members, session, app_blob) = fixture.seed();
    let branch = fixture.manager.capture_execution_branch(limits()).unwrap();
    let crdt = branch.manager().crdt();
    let store = branch.hypergraph_store();
    let sequence = fixture.db.inner().latest_sequence_number();
    let root = fixture
        .crdt
        .current_forest_phase_root(&[0xff; 32], 0)
        .unwrap();
    let policy = GlobalMaintenance::new(1, hex::encode(&members[0]), vec![]);
    {
        let guard = crdt.lock_forest_writes();
        policy.reset(&crdt, store.as_ref(), &guard, 2).unwrap();
    }
    crdt.commit_with_global_cursor(2, &quil_store::encoding::global_materialized_cursor_key())
        .unwrap();
    let view = handoff::CommittedView::capture(&crdt).unwrap();
    assert_eq!(
        handoff::head(&view, &session.filter).unwrap(),
        Some(session.clone())
    );
    assert_eq!(
        handoff::status(&view, &session.id().unwrap()).unwrap(),
        handoff::Status::Active
    );
    let active = |state: &HypergraphCrdt| {
        quil_execution::prover_registry::CommittedProverScan::try_scan(state)
            .unwrap()
            .active_on_filter(&[], 2)
            .into_iter()
            .map(|(_, address)| address)
            .collect::<Vec<_>>()
    };
    let kept =
        quil_execution::global_intrinsic::materialize::prover_address_from_pubkey(&members[0])
            .unwrap();
    let dropped =
        quil_execution::global_intrinsic::materialize::prover_address_from_pubkey(&members[1])
            .unwrap();
    assert_eq!(active(&crdt), vec![kept.to_vec()]);
    assert_eq!(active(&fixture.crdt), vec![dropped.to_vec()]);
    let app = ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(&[9; 32], 256, 3),
        l2: [9; 32],
    };
    assert_eq!(
        store
            .load_vertex_underlying_at(
                "vertex",
                "adds",
                &app,
                &[[9; 32], [1; 32]].concat(),
                u64::MAX
            )
            .unwrap(),
        Some(app_blob)
    );
    assert_eq!(crdt.total_size(), fixture.crdt.total_size());
    assert_eq!(
        crdt.read_execution_record(reset_marker(2)).unwrap(),
        Some(vec![1])
    );
    assert_eq!(
        fixture.crdt.read_execution_record(reset_marker(2)).unwrap(),
        None
    );
    assert_ne!(reset_marker(2), BOOT_RESET_MARKER_KEY);
    assert_eq!(
        crdt.read_execution_record(BOOT_RESET_MARKER_KEY).unwrap(),
        None,
        "a runtime prover reset does not certify the boot grid reset"
    );
    assert_eq!(
        fixture
            .crdt
            .current_forest_phase_root(&[0xff; 32], 0)
            .unwrap(),
        root
    );
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);

    // Once marked, a retry must preserve subsequent prover joins.
    crate::genesis::seed_active_prover_on_filter(&crdt, &members[1], 5, 3, &[]).unwrap();
    let before = branch.overlay().stats();
    {
        let guard = crdt.lock_forest_writes();
        policy.reset(&crdt, store.as_ref(), &guard, 2).unwrap();
    }
    assert_eq!(branch.overlay().stats().delta_entries, before.delta_entries);
    assert_eq!(branch.overlay().stats().delta_bytes, before.delta_bytes);
    assert!(active(&crdt).contains(&dropped.to_vec()));
    let retained = store.clone();
    drop(branch);
    assert!(retained.new_transaction(false).is_err());
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn boot_reset_marker_suppresses_only_the_initial_runtime_reset() {
    let fixture = Fixture::new();
    fixture.seed();
    let branch = fixture.manager.capture_execution_branch(limits()).unwrap();
    let crdt = branch.manager().crdt();
    let store = branch.hypergraph_store();
    let txn = store.new_transaction(false).unwrap();
    txn.set(BOOT_RESET_MARKER_KEY, &[1]).unwrap();
    txn.commit().unwrap();
    let captured = branch.overlay().stats();
    let sequence = fixture.db.inner().latest_sequence_number();
    let root = crdt.current_forest_phase_root(&[0xff; 32], 0).unwrap();
    let policy = GlobalMaintenance::new(1, "invalid seed".into(), vec![]);
    {
        let guard = crdt.lock_forest_writes();
        // An already-complete boot reset requires no runtime reseeding.
        policy.reset(&crdt, store.as_ref(), &guard, 2).unwrap();
        let second = quil_execution::global_intrinsic::materialize::quil_grid_reset_v2_frame();
        assert_ne!(reset_marker(second), FRAME_PROVER_RESET_V1_MARKER_KEY);
        assert!(
            policy.reset(&crdt, store.as_ref(), &guard, second).is_err(),
            "the initial boot marker must not suppress a later reset"
        );
    }
    assert_eq!(
        crdt.current_forest_phase_root(&[0xff; 32], 0).unwrap(),
        root,
        "invalid genesis is rejected before wiping state"
    );
    assert_eq!(
        branch.overlay().stats().delta_entries,
        captured.delta_entries
    );
    assert_eq!(branch.overlay().stats().delta_bytes, captured.delta_bytes);
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn branch_reset_rejects_foreign_guard_store_and_unfinished_mutations() {
    let fixture = Fixture::new();
    let (members, _, blob) = fixture.seed();
    let branch = fixture.manager.capture_execution_branch(limits()).unwrap();
    let crdt = branch.manager().crdt();
    let policy = GlobalMaintenance::new(1, hex::encode(&members[0]), vec![]);
    let sequence = fixture.db.inner().latest_sequence_number();
    let captured = branch.overlay().stats();
    {
        let foreign = fixture.crdt.lock_forest_writes();
        assert!(policy
            .reset(&crdt, branch.hypergraph_store().as_ref(), &foreign, 2)
            .unwrap_err()
            .to_string()
            .contains("foreign CRDT forest guard"));
    }
    let guard = crdt.lock_forest_writes();
    assert!(policy
        .reset(&crdt, fixture.store.as_ref(), &guard, 2)
        .unwrap_err()
        .to_string()
        .contains("store mismatch"));
    assert_eq!(
        branch.overlay().stats().delta_entries,
        captured.delta_entries
    );
    assert_eq!(branch.overlay().stats().delta_bytes, captured.delta_bytes);
    crdt.add_vertex(
        &Location {
            app_address: [9; 32],
            data_address: [2; 32],
        },
        &blob,
    )
    .unwrap();
    let before = branch.overlay().stats();
    assert!(policy
        .reset(&crdt, branch.hypergraph_store().as_ref(), &guard, 2)
        .unwrap_err()
        .to_string()
        .contains("unfinished CRDT mutations"));
    assert_eq!(branch.overlay().stats().delta_entries, before.delta_entries);
    assert_eq!(branch.overlay().stats().delta_bytes, before.delta_bytes);
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn failed_branch_reset_has_no_marker_and_owner_discards_partial_writes() {
    let fixture = Fixture::new();
    let (members, _, _) = fixture.seed();
    let mut budget = limits();
    budget.state.overlay.max_delta_entries = 3;
    let branch = fixture.manager.capture_execution_branch(budget).unwrap();
    let crdt = branch.manager().crdt();
    let store = branch.hypergraph_store().clone();
    let sequence = fixture.db.inner().latest_sequence_number();
    let policy = GlobalMaintenance::new(1, hex::encode(&members[0]), vec![]);
    let captured = branch.overlay().stats();
    {
        let guard = crdt.lock_forest_writes();
        assert!(policy.reset(&crdt, store.as_ref(), &guard, 2).is_err());
    }
    assert_eq!(crdt.read_execution_record(reset_marker(2)).unwrap(), None);
    assert!(branch.overlay().stats().delta_entries > captured.delta_entries);
    assert!(branch.overlay().stats().delta_entries <= 3);
    drop(branch);
    assert!(store.new_transaction(false).is_err());
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn materializer_stops_before_cutover_publication_on_maintenance_error() {
    let fixture = Fixture::new();
    let branch = fixture.manager.capture_execution_branch(limits()).unwrap();
    let crdt = branch.manager().crdt();
    crdt.set_unified_tree(false);
    let cutover = quil_execution::global_intrinsic::materialize::unified_tree_cutover_frame();
    let materializer = crate::frame_materializer::FrameMaterializer::new(
        branch.manager().clone(),
        Arc::new(branch.registry().clone()),
        branch.clock_store().clone(),
        crdt.clone(),
        branch.hypergraph_store().clone(),
        Arc::new(crate::rewards::OptRewardIssuance),
        vec![],
        true,
    )
    .with_global_maintenance(GlobalMaintenance::new(1, "invalid seed".into(), vec![]));
    materializer.seed_cursor(cutover - 1);
    let sequence = fixture.db.inner().latest_sequence_number();
    let frame = quil_types::proto::global::GlobalFrame {
        header: Some(quil_types::proto::global::GlobalFrameHeader {
            frame_number: cutover,
            output: vec![4; 516],
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(materializer.materialize(&frame).is_err());
    assert!(!crdt.unified_tree());
    assert_eq!(materializer.last_materialized_frame(), cutover - 1);
    assert_eq!(
        crdt.read_execution_record(reset_marker(cutover)).unwrap(),
        None
    );
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn skipped_frames_do_not_invoke_cutover_or_reset_hooks() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let fixture = Fixture::new();
    fixture.crdt.set_unified_tree(false);
    let cutover = quil_execution::global_intrinsic::materialize::unified_tree_cutover_frame();
    let calls = Arc::new(AtomicUsize::new(0));
    let hook = {
        let calls = calls.clone();
        Arc::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            true
        })
    };
    let materializer = crate::frame_materializer::FrameMaterializer::new(
        Arc::new(fixture.manager),
        Arc::new(quil_execution::prover_registry::SharedProverRegistry::new()),
        Arc::new(quil_store::RocksClockStore::new(fixture.db.inner())),
        fixture.crdt.clone(),
        fixture.store,
        Arc::new(crate::rewards::OptRewardIssuance),
        vec![],
        true,
    )
    .with_unified_cutover_consolidate(hook.clone())
    .with_prover_tree_reset(hook);
    materializer.seed_cursor(cutover);
    let sequence = fixture.db.inner().latest_sequence_number();
    for number in [cutover, cutover + 2] {
        let frame = quil_types::proto::global::GlobalFrame {
            header: Some(quil_types::proto::global::GlobalFrameHeader {
                frame_number: number,
                ..Default::default()
            }),
            ..Default::default()
        };
        materializer.materialize(&frame).unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!fixture.crdt.unified_tree());
    assert_eq!(materializer.last_materialized_frame(), cutover);
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn consolidated_branch_heads_can_be_committed_and_captured_again() {
    let fixture = Fixture::new();
    fixture.crdt.set_unified_tree(false);
    fixture
        .crdt
        .set_app_shard_prefixes([9; 32], vec![vec![0], vec![1]]);
    let (_, _, app_blob) = fixture.seed();
    let shards = quil_store::RocksShardsStore::new(fixture.db.inner());
    let txn = fixture.store.new_transaction(false).unwrap();
    for prefix in [vec![0], vec![1]] {
        shards
            .put_app_shard(
                txn.as_ref(),
                &quil_types::store::ShardInfo {
                    shard_key: [
                        quil_hypergraph::addressing::get_bloom_filter_indices(&[9; 32], 256, 3)
                            .as_slice(),
                        &[9; 32],
                    ]
                    .concat(),
                    prefix,
                    size: vec![],
                    data_shards: 0,
                    commitment: vec![],
                },
            )
            .unwrap();
    }
    txn.commit().unwrap();
    let branch = fixture.manager.capture_execution_branch(limits()).unwrap();
    let crdt = branch.manager().crdt();
    let sequence = fixture.db.inner().latest_sequence_number();
    {
        let guard = crdt.lock_forest_writes();
        GlobalMaintenance::new(1, String::new(), vec![])
            .consolidate(
                &crdt,
                branch.hypergraph_store().as_ref(),
                branch.shards_store().unwrap().as_ref(),
                &guard,
                2,
            )
            .unwrap();
        crdt.set_unified_tree(true);
        crdt.commit(2).unwrap();
    }
    let expected = quil_forest::Forest::in_memory()
        .commit_shard_phase_raw(
            &[9; 32],
            quil_forest::Phase::VertexAdds,
            0,
            vec![(
                vec![1; 32],
                quil_tries::vertex_leaf_value(&app_blob).unwrap(),
            )],
        )
        .unwrap();
    assert_eq!(
        crdt.current_forest_phase_root(&[9; 32], 0).unwrap(),
        expected
    );
    let child = branch.manager().capture_execution_branch(limits()).unwrap();
    drop(branch);
    assert_eq!(
        child
            .manager()
            .crdt()
            .current_forest_phase_root(&[9; 32], 0)
            .unwrap(),
        expected
    );
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}
