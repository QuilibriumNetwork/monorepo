use super::*;
use quil_types::consensus::{ProverRegistry, ProverStatus};
use quil_types::store::{ClockStore, ShardInfo, ShardKey};

fn publication_context(f: &Fixture, registry: &SharedProverRegistry) -> ExecutionForkContext {
    ExecutionForkContext {
        crdt: f.source.crdt(),
        clock_store: f.clock.clone(),
        global_clock_store: f.clock.clone(),
        shards_store: f.source.shards_store(),
        prover_registry: Arc::new(registry.clone()),
    }
}

#[test]
fn guarded_publication_retains_writer_barriers_and_adopts_all_manager_caches() {
    let f = Fixture::new(true);
    f.seed_prover(1, 1);
    put_frame(f.clock.as_ref(), 0);
    f.clock.warm_global_frame_cache().unwrap();
    let registry = SharedProverRegistry::new();
    registry.refresh_from_store(f.store.as_ref()).unwrap();
    let sibling = f.source.capture_execution_branch(limits()).unwrap();
    let (mut branch, mut guard) = f.source.capture_execution_branch_guarded(limits()).unwrap();
    assert!(f.source.engines.try_read().is_err());
    assert!(f.source.global_venue_fee.try_read().is_err());
    put_frame(branch.clock_store().as_ref(), 1);
    let txn = branch.hypergraph_store().new_transaction(false).unwrap();
    branch
        .hypergraph_store()
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &registry_shard(),
            &vertex(2),
            &prover_blob(1),
        )
        .unwrap();
    txn.commit().unwrap();
    let fee = crate::pricing::GlobalQuilFeeSnapshot {
        frame_number: 1,
        difficulty: 100,
        world_state_bytes: 42,
    };
    branch.manager().publish_global_quil_fee_snapshot(Some(fee));
    branch.manager().publish_global_venue_fee_snapshot(fee);
    branch
        .manager
        .summary_rebuilds
        .write()
        .unwrap()
        .insert([7; 32]);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let db = f.db.inner();
    std::thread::scope(|scope| {
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        scope.spawn(move || {
            start_rx.recv().unwrap();
            ready_tx.send(()).unwrap();
            db.put(b"publication-concurrent-writer", b"done").unwrap();
            done_tx.send(()).unwrap();
        });
        guard
            .publish(
                &mut branch,
                publication_context(&f, &registry),
                &registry,
                |_| {
                    start_tx.send(()).unwrap();
                    ready_rx.recv().unwrap();
                    assert!(matches!(
                        done_rx.recv_timeout(std::time::Duration::from_millis(30)),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    ));
                    assert!(f.source.engines.try_read().is_err());
                    assert!(f.source.global_venue_fee.try_read().is_err());
                },
            )
            .unwrap();
        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
    });
    drop(guard);
    assert!(branch.overlay().stats().closed);
    assert!(registry.get_prover_info(&[2; 32]).unwrap().is_some());
    assert!(sibling
        .registry()
        .get_prover_info(&[2; 32])
        .unwrap()
        .is_none());
    assert_eq!(f.source.global_quil_fee_snapshot(1).unwrap(), Some(fee));
    assert_eq!(f.source.global_venue_fee_snapshot(1).unwrap(), Some(fee));
    assert!(f.source.summary_rebuilds.read().unwrap().contains(&[7; 32]));
    assert_eq!(f.clock.get_latest_global_clock_frame().unwrap(), frame(1));
    assert_eq!(
        sibling
            .clock_store()
            .get_latest_global_clock_frame()
            .unwrap(),
        frame(0)
    );
    // The freshly rebound canonical engines remain capturable on this database.
    assert!(f.source.capture_execution_branch(limits()).is_ok());
}

#[test]
fn guarded_publication_rejects_foreign_providers_before_durable_changes() {
    let f = Fixture::new(true);
    let foreign = Fixture::new(true);
    let registry = SharedProverRegistry::new();
    let (mut branch, mut guard) = f.source.capture_execution_branch_guarded(limits()).unwrap();
    put_frame(branch.clock_store().as_ref(), 1);
    let before = f.db.inner().latest_sequence_number();
    let mut context = publication_context(&f, &registry);
    context.clock_store = foreign.clock.clone();
    assert!(guard
        .publish(&mut branch, context, &registry, |_| panic!(
            "must not adopt"
        ))
        .is_err());
    assert_eq!(f.db.inner().latest_sequence_number(), before);
    assert!(branch.overlay().stats().closed);
    drop(guard);
    assert!(f.source.capture_execution_branch(limits()).is_ok());
}

#[test]
fn adoption_panic_poison_blocks_further_execution_until_reopen() {
    let f = Fixture::new(true);
    let registry = SharedProverRegistry::new();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (mut branch, mut guard) = f.source.capture_execution_branch_guarded(limits()).unwrap();
        put_frame(branch.clock_store().as_ref(), 1);
        guard
            .publish(
                &mut branch,
                publication_context(&f, &registry),
                &registry,
                |_| panic!("adoption interrupted"),
            )
            .unwrap();
    }));
    assert!(panic.is_err());
    assert!(f.db.inner().lock_writes().is_err());
    assert!(f.source.capture_execution_branch(limits()).is_err());
    // The batch was durable before the panic. Recovery must reconcile it;
    // returning an error cannot be interpreted as evidence of an absent write.
    assert!(f
        .db
        .inner()
        .get(quil_store::encoding::clock_global_frame_key(1))
        .unwrap()
        .is_some());
}

fn limits() -> ExecutionBranchLimits {
    ExecutionBranchLimits {
        state: ExecutionForkLimits {
            overlay: quil_forest::OverlayLimits {
                max_delta_bytes: 8 << 20,
                max_delta_entries: 50_000,
                max_record_bytes: 2 << 20,
                max_read_bytes: 64 << 20,
                max_read_operations: 1_000_000,
                max_cursors: 32,
            },
            max_metadata_entries: 10_000,
            max_metadata_bytes: 4 << 20,
        },
        registry: RegistryLimits {
            max_vertices: 1_000,
            max_record_bytes: 1 << 20,
            max_input_bytes: 8 << 20,
            max_cache_entries: 10_000,
            max_cache_bytes: 8 << 20,
        },
        max_summary_rebuilds: 100,
    }
}

fn prover_blob(status: u8) -> Vec<u8> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    for (key, value) in [
        (
            vec![255; 32],
            crate::global_schema::TYPE_HASH_PROVER.to_vec(),
        ),
        (
            crate::global_schema::field_key("prover:Prover", "PublicKey").unwrap(),
            vec![9; 57],
        ),
        (
            crate::global_schema::field_key("prover:Prover", "Status").unwrap(),
            vec![status],
        ),
    ] {
        tree.insert(&key, &value, &[], &BigInt::from(value.len()))
            .unwrap();
    }
    quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()
}
fn registry_shard() -> ShardKey {
    ShardKey {
        l1: [0; 3],
        l2: [255; 32],
    }
}
fn vertex(n: u8) -> Vec<u8> {
    [[255; 32], [n; 32]].concat()
}
fn frame(n: u64) -> quil_types::proto::global::GlobalFrame {
    quil_types::proto::global::GlobalFrame {
        header: Some(quil_types::proto::global::GlobalFrameHeader {
            frame_number: n,
            output: vec![n as u8; 516],
            ..Default::default()
        }),
        ..Default::default()
    }
}
fn put_frame(clock: &dyn ClockStore, n: u64) {
    let txn = clock.new_transaction(false).unwrap();
    clock
        .put_global_clock_frame(&frame(n), txn.as_ref())
        .unwrap();
    txn.commit().unwrap();
}

struct Fixture {
    source: ExecutionEngineManager,
    store: Arc<quil_store::RocksHypergraphStore>,
    clock: Arc<quil_store::RocksClockStore>,
    db: Arc<quil_store::RocksDb>,
    _dir: tempfile::TempDir,
}
impl Fixture {
    fn new(include_global: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        let prover = Arc::new(quil_tries::ShaInclusionProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            prover.clone(),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(true);
        crdt.warm_sizes(&[]).unwrap();
        let stubs = crate::testing::NoopExecutionCrypto::new();
        let source = ExecutionEngineManager::new_with_shards(
            prover,
            stubs.key_manager,
            crdt.clone(),
            stubs.circuit_compiler,
            clock.clone(),
            Arc::new(crate::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(crdt)),
            include_global,
            include_global.then(|| {
                Arc::new(quil_store::RocksShardsStore::new(db.inner())) as Arc<dyn ShardsStore>
            }),
            include_global.then(|| db.clone() as Arc<dyn quil_types::store::KvDb>),
        );
        Self {
            source,
            store,
            clock,
            db,
            _dir: dir,
        }
    }
    fn seed_prover(&self, n: u8, status: u8) {
        self.store
            .save_vertex_underlying(
                "vertex",
                "adds",
                &registry_shard(),
                &vertex(n),
                &prover_blob(status),
            )
            .unwrap();
    }
}

#[test]
fn complete_capture_pins_every_provider_and_rebuilds_an_independent_registry() {
    let f = Fixture::new(true);
    f.seed_prover(1, 1);
    put_frame(f.clock.as_ref(), 1);
    let branch = f.source.capture_execution_branch(limits()).unwrap();
    let identity = branch.manager().crdt().backing_store_identity().unwrap();
    assert!(branch.hypergraph_store().backing_store_identity().as_ref() == Some(&identity));
    assert!(branch.clock_store().backing_store_identity().as_ref() == Some(&identity));
    assert!(
        branch
            .shards_store()
            .unwrap()
            .backing_store_identity()
            .as_ref()
            == Some(&identity)
    );
    assert!(f.source.crdt().backing_store_identity().as_ref() != Some(&identity));
    assert_eq!(branch.registry_usage().vertices, 1);
    assert!(branch.registry_usage().cache_bytes > 4096);

    f.seed_prover(1, 2);
    f.seed_prover(2, 1);
    put_frame(f.clock.as_ref(), 2);
    let sibling = f.source.capture_execution_branch(limits()).unwrap();
    let sequence = f.db.inner().latest_sequence_number();
    branch
        .registry()
        .refresh_from_store(branch.hypergraph_store().as_ref())
        .unwrap();
    assert_eq!(
        branch
            .registry()
            .get_prover_info(&[1; 32])
            .unwrap()
            .unwrap()
            .status,
        ProverStatus::Active
    );
    assert!(branch
        .registry()
        .get_prover_info(&[2; 32])
        .unwrap()
        .is_none());
    assert_eq!(
        sibling
            .registry()
            .get_prover_info(&[1; 32])
            .unwrap()
            .unwrap()
            .status,
        ProverStatus::Paused
    );
    assert_eq!(
        branch
            .clock_store()
            .get_latest_global_clock_frame()
            .unwrap(),
        frame(1)
    );
    assert_eq!(
        sibling
            .clock_store()
            .get_latest_global_clock_frame()
            .unwrap(),
        frame(2)
    );
    assert!(branch
        .registry()
        .refresh_from_store(f.store.as_ref())
        .is_err());
    assert!(branch
        .registry()
        .refresh_from_store(sibling.hypergraph_store().as_ref())
        .is_err());
    assert!(branch
        .registry()
        .evict_inactive_provers(
            100,
            1,
            &HashMap::new(),
            &crate::hypergraph_state::HypergraphState::new(f.source.crdt()),
            Some(f.store.as_ref())
        )
        .is_err());

    let txn = branch.hypergraph_store().new_transaction(false).unwrap();
    branch
        .hypergraph_store()
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &registry_shard(),
            &vertex(3),
            &prover_blob(1),
        )
        .unwrap();
    let row = ShardInfo {
        shard_key: vec![3; 35],
        prefix: vec![0],
        size: vec![],
        data_shards: 1,
        commitment: vec![],
    };
    branch
        .shards_store()
        .unwrap()
        .put_app_shard(txn.as_ref(), &row)
        .unwrap();
    branch
        .clock_store()
        .put_global_clock_frame(&frame(3), txn.as_ref())
        .unwrap();
    txn.commit().unwrap();
    branch
        .registry()
        .refresh_from_store(branch.hypergraph_store().as_ref())
        .unwrap();
    assert!(branch
        .registry()
        .get_prover_info(&[3; 32])
        .unwrap()
        .is_some());
    assert!(sibling
        .registry()
        .get_prover_info(&[3; 32])
        .unwrap()
        .is_none());
    assert_eq!(
        branch
            .shards_store()
            .unwrap()
            .range_app_shards()
            .unwrap()
            .len(),
        1
    );
    assert!(sibling
        .shards_store()
        .unwrap()
        .range_app_shards()
        .unwrap()
        .is_empty());
    assert!(f
        .source
        .shards_store
        .as_ref()
        .unwrap()
        .range_app_shards()
        .unwrap()
        .is_empty());
    assert_eq!(f.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn dropping_branch_invalidates_retained_handles_but_preserves_captured_child() {
    for include_global in [false, true] {
        let f = Fixture::new(include_global);
        let sequence = f.db.inner().latest_sequence_number();
        let branch = f.source.capture_execution_branch(limits()).unwrap();
        put_frame(branch.clock_store().as_ref(), 4);
        let retained = branch.clock_store().clone();
        let registry = branch.registry().clone();
        let store = branch.hypergraph_store().clone();
        let child = branch.manager().capture_execution_branch(limits()).unwrap();
        assert_eq!(branch.overlay().stats().descendant_branches, 1);
        put_frame(branch.clock_store().as_ref(), 5);
        assert_eq!(
            child.clock_store().get_latest_global_clock_frame().unwrap(),
            frame(4)
        );
        drop(branch);
        assert!(retained.get_latest_global_clock_frame().is_err());
        assert!(retained.new_transaction(false).is_err());
        assert!(registry.refresh_from_store(store.as_ref()).is_err());
        put_frame(child.clock_store().as_ref(), 6);
        assert_eq!(
            child.clock_store().get_latest_global_clock_frame().unwrap(),
            frame(6)
        );
        assert_eq!(f.db.inner().latest_sequence_number(), sequence);
    }
}

#[test]
fn capture_rejects_provider_mismatches_and_busy_engines_without_waiting() {
    let mut f = Fixture::new(true);
    let other = Fixture::new(true);
    let sequence = f.db.inner().latest_sequence_number();
    let guard = f.source.engines.read().unwrap();
    let error = f
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("busy"), "{error}");
    drop(guard);
    f.source = f
        .source
        .with_global_clock_store(other.clock.clone())
        .unwrap();
    let error = f
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("captured anchor context"), "{error}");
    f.source = f.source.with_global_clock_store(f.clock.clone()).unwrap();
    f.source.shards_store = Some(Arc::new(quil_store::RocksShardsStore::new(
        other.db.inner(),
    )));
    let error = f
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("shard store mismatch"), "{error}");
    f.source.shards_store = Some(Arc::new(quil_store::RocksShardsStore::new(f.db.inner())));
    let stubs = crate::testing::NoopExecutionCrypto::new();
    f.source.engines.write().unwrap().insert(
        "token".into(),
        Box::new(TokenExecutionEngine::new_with_state(
            crate::engines::ExecutionMode::Global,
            Arc::new(quil_tries::ShaInclusionProver),
            other.source.crdt(),
            stubs.key_manager,
            f.clock.clone(),
        )),
    );
    let error = f
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("engine state mismatch"), "{error}");
    assert_eq!(f.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn failed_context_construction_releases_child_admission_and_preserves_parent() {
    let f = Fixture::new(true);
    f.seed_prover(1, 1);
    let parent = f.source.capture_execution_branch(limits()).unwrap();
    let sequence = f.db.inner().latest_sequence_number();
    let mut small = limits();
    small.registry.max_cache_bytes = 4095;
    assert!(parent.manager().capture_execution_branch(small).is_err());
    assert_eq!(parent.overlay().stats().descendant_branches, 0);
    parent
        .manager()
        .summary_rebuilds
        .write()
        .unwrap()
        .insert([7; 32]);
    small = limits();
    small.max_summary_rebuilds = 0;
    assert!(parent.manager().capture_execution_branch(small).is_err());
    assert_eq!(parent.overlay().stats().descendant_branches, 0);
    small = limits();
    small.state.overlay.max_read_bytes = 0;
    assert!(parent.manager().capture_execution_branch(small).is_err());
    assert_eq!(parent.overlay().stats().descendant_branches, 0);
    let child = parent.manager().capture_execution_branch(limits()).unwrap();
    assert_eq!(parent.overlay().stats().descendant_branches, 1);
    assert!(child
        .manager()
        .summary_rebuilds
        .read()
        .unwrap()
        .contains(&[7; 32]));
    drop(child);
    assert_eq!(parent.overlay().stats().descendant_branches, 0);
    assert!(parent
        .registry()
        .get_prover_info(&[1; 32])
        .unwrap()
        .is_some());
    assert_eq!(f.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn branch_registry_refresh_cannot_outgrow_its_capture_budget() {
    let f = Fixture::new(true);
    f.seed_prover(1, 1);
    let mut bounded = limits();
    bounded.registry.max_vertices = 1;
    let branch = f.source.capture_execution_branch(bounded).unwrap();
    let usage = branch.registry_usage();
    let txn = branch.hypergraph_store().new_transaction(false).unwrap();
    branch
        .hypergraph_store()
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &registry_shard(),
            &vertex(2),
            &prover_blob(1),
        )
        .unwrap();
    txn.commit().unwrap();
    assert!(branch
        .registry()
        .refresh_from_store(branch.hypergraph_store().as_ref())
        .is_err());
    assert_eq!(branch.registry_usage(), usage);
    assert!(branch
        .registry()
        .get_prover_info(&[1; 32])
        .unwrap()
        .is_some());
    assert!(branch
        .registry()
        .get_prover_info(&[2; 32])
        .unwrap()
        .is_none());
}

#[test]
fn capture_rejects_an_intrinsic_clock_even_when_other_anchors_match() {
    let f = Fixture::new(true);
    let other = Fixture::new(true);
    let stubs = crate::testing::NoopExecutionCrypto::new();
    let global = GlobalExecutionEngine::new_with_intrinsic(
        Arc::new(quil_tries::ShaInclusionProver),
        stubs.key_manager,
        f.source.crdt(),
        other.clock.clone(),
        f.source.shards_store.clone(),
        Some(f.db.clone()),
    );
    f.source
        .engines
        .write()
        .unwrap()
        .insert("global".into(), Box::new(global));
    let sequence = f.db.inner().latest_sequence_number();
    let error = f
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("intrinsic capture provider mismatch"),
        "{error}"
    );
    assert_eq!(f.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn anchored_capture_reads_bounded_global_frames_from_a_separate_store() {
    // A thread worker's engines read GLOBAL frames from the master's store.
    let mut worker = Fixture::new(false);
    let master = Fixture::new(false);
    for n in 0..=5 {
        put_frame(master.clock.as_ref(), n);
    }
    worker.source = worker
        .source
        .with_global_clock_store(master.clock.clone())
        .unwrap();
    let error = worker
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("captured anchor context"), "{error}");
    let foreign = Fixture::new(false);
    assert!(worker
        .source
        .capture_anchored_execution_branch(limits(), foreign.clock.clone(), 3)
        .is_err());
    let master_sequence = master.db.inner().latest_sequence_number();
    let worker_sequence = worker.db.inner().latest_sequence_number();
    let branch = worker
        .source
        .capture_anchored_execution_branch(limits(), master.clock.clone(), 3)
        .unwrap();
    let clock = branch
        .manager()
        .engines
        .read()
        .unwrap()
        .get("token")
        .and_then(|engine| engine.as_any())
        .and_then(|engine| engine.downcast_ref::<TokenExecutionEngine>())
        .unwrap()
        .global_clock_for_tests();
    assert_eq!(clock.get_global_clock_frame(3).unwrap(), frame(3));
    assert_eq!(clock.get_latest_global_clock_frame().unwrap(), frame(3));
    assert_eq!(clock.get_earliest_global_clock_frame().unwrap(), frame(0));
    assert!(clock.get_global_clock_frame(4).is_err());
    assert!(clock.backing_store_identity().is_none());
    assert!(clock.new_transaction(false).is_err());
    assert!(clock
        .put_global_clock_frame(&frame(9), &crate::testing::NoopTxn)
        .is_err());
    assert!(clock.put_shard_frame_fee_total(&[1; 32], 1, 5).is_err());
    assert!(clock.get_shard_frame_fee_total(&[1; 32], 1).is_err());
    assert!(clock.get_global_clock_frame_candidate(3, &[0; 32]).is_err());
    // The branch's own frame chain and state stay in the worker's overlay.
    assert!(
        branch.clock_store().backing_store_identity()
            == branch.manager().crdt().backing_store_identity()
    );
    put_frame(branch.clock_store().as_ref(), 7);
    assert_eq!(branch.clock_store().get_global_clock_frame(7).unwrap(), frame(7));
    assert!(clock.get_global_clock_frame(7).is_err());
    assert_eq!(master.db.inner().latest_sequence_number(), master_sequence);
    assert_eq!(worker.db.inner().latest_sequence_number(), worker_sequence);
}
