use super::*;
use quil_types::crypto::Signer as _;
use std::sync::atomic::AtomicUsize;

#[path = "frame_materializer_selected_parent_tests.rs"]
mod selected_parent_tests;

#[path = "frame_materializer_publication_tests.rs"]
mod publication_tests;

fn limits() -> MaterializerBranchLimits {
    MaterializerBranchLimits {
        execution: ExecutionBranchLimits {
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
        },
        max_metadata_entries: 1000,
        max_metadata_bytes: 1 << 20,
        max_frame_bytes: 4 << 20,
        max_frame_items: 10_000,
    }
}

fn frame(number: u64, root: [u8; 32]) -> quil_types::proto::global::GlobalFrame {
    quil_types::proto::global::GlobalFrame {
        header: Some(quil_types::proto::global::GlobalFrameHeader {
            frame_number: number,
            difficulty: 200_000,
            prover_tree_commitment: root.to_vec(),
            output: vec![number as u8; 516],
            parent_selector: vec![0; 32],
            ..Default::default()
        }),
        requests: vec![quil_types::proto::global::MessageBundle::default()],
    }
}

struct Fixture {
    db: Arc<quil_store::RocksDb>,
    store: Arc<quil_store::RocksHypergraphStore>,
    clock: Arc<quil_store::RocksClockStore>,
    source: FrameMaterializer,
    current: Arc<CurrentFrame>,
    notifications: Arc<AtomicUsize>,
    catchup: tokio::sync::mpsc::UnboundedReceiver<(quil_types::proto::global::GlobalFrame, u64)>,
}
impl Fixture {
    fn new(key: Option<&[u8]>) -> Self {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
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
        if let Some(key) = key {
            crate::genesis::seed_active_prover_on_filter(&crdt, key, 1000, 0, &[]).unwrap();
        }
        let stubs = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = Arc::new(
            quil_execution::ExecutionEngineManager::new_with_shards(
                prover,
                stubs.key_manager,
                crdt.clone(),
                stubs.circuit_compiler,
                clock.clone(),
                Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
                true,
                Some(Arc::new(quil_store::RocksShardsStore::new(db.inner()))),
                Some(db.clone()),
            )
            .with_pricing_network(1),
        );
        crdt.commit_with_global_cursor(0, &quil_store::encoding::global_materialized_cursor_key())
            .unwrap();
        let root = crdt.current_forest_phase_root(&[0xff; 32], 0).unwrap();
        crdt.record_prover_root(0, root.to_vec());
        let registry = Arc::new(ConcreteProverRegistry::new());
        registry.refresh_from_store(store.as_ref()).unwrap();
        let current = CurrentFrame::new();
        let notifications = Arc::new(AtomicUsize::new(0));
        let source = FrameMaterializer::new(
            manager,
            registry.clone(),
            clock.clone(),
            crdt,
            store.clone(),
            Arc::new(crate::rewards::OptRewardIssuance),
            vec![8; 32],
            true,
        )
        .with_eviction_registry(registry)
        .with_current_frame(current.clone())
        .with_shard_admission_refresh({
            let calls = notifications.clone();
            Arc::new(move || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });
        let (tx, catchup) = tokio::sync::mpsc::unbounded_channel();
        *source.catchup_tx.lock().unwrap() = Some(tx);
        Self {
            db,
            store,
            clock,
            source,
            current,
            notifications,
            catchup,
        }
    }

    fn advance_checkpoint(&self, cursor: u64) {
        self.source
            .hypergraph
            .commit_with_global_cursor(
                cursor,
                &quil_store::encoding::global_materialized_cursor_key(),
            )
            .unwrap();
        self.source.seed_cursor(cursor);
        self.source.record_current_prover_root();
        self.current.materialize(cursor);
    }
}

#[test]
fn captured_materializer_matches_durable_execution_without_publication() {
    let key = quil_crypto::FalconSigner::generate().public_key().to_vec();
    let mut primary = Fixture::new(Some(&key));
    let expected = Fixture::new(Some(&key));
    primary.source.flag_prover_root_mismatch(vec![77; 32]);
    primary
        .source
        .set_coverage_halt_durations(std::collections::HashMap::from([(vec![6; 32], 41)]));
    let sequence = primary.db.inner().latest_sequence_number();
    let notifications = primary.notifications.load(Ordering::SeqCst);
    let mut branch = primary.source.capture_execution_branch(limits()).unwrap();
    assert!(branch.materializer.current_frame.is_none());
    assert!(branch.materializer.shard_admission_refresh.is_none());
    assert!(branch.materializer.catchup_tx.lock().unwrap().is_none());
    assert!(!branch.materializer.prover_root_mismatch_detected());
    primary
        .source
        .set_coverage_halt_durations(std::collections::HashMap::new());
    assert_eq!(
        branch
            .materializer
            .coverage_halt_durations
            .lock()
            .unwrap()
            .get(&vec![6; 32]),
        Some(&41)
    );
    let input = frame(1, branch.prover_root().unwrap());
    let result = branch.materialize(&input).unwrap();
    let expected_result = expected.source.materialize(&input).unwrap();
    assert_eq!(
        (result.processed, result.skipped),
        (expected_result.processed, expected_result.skipped)
    );
    assert_eq!(
        result.prover_root,
        expected
            .source
            .hypergraph
            .current_forest_phase_root(&[0xff; 32], 0)
            .unwrap()
    );
    assert_eq!(
        branch
            .execution
            .clock_store()
            .get_global_clock_frame_outcomes(1)
            .unwrap(),
        expected.clock.get_global_clock_frame_outcomes(1).unwrap()
    );
    assert_eq!(branch.cursor().unwrap(), 1);
    assert_eq!(read_cursor(primary.store.as_ref()).unwrap(), 0);
    assert_eq!(primary.source.last_materialized_frame(), 0);
    assert_eq!(primary.current.materialized(), 0);
    assert_eq!(primary.notifications.load(Ordering::SeqCst), notifications);
    assert!(primary.catchup.try_recv().is_err());
    assert!(primary.source.prover_root_mismatch_detected());
    assert_eq!(primary.source.fork_target_root(), Some(vec![77; 32]));
    assert!(primary
        .source
        .execution_manager
        .global_venue_fee_snapshot(1)
        .unwrap()
        .is_none());
    assert!(branch
        .execution
        .manager()
        .global_venue_fee_snapshot(1)
        .unwrap()
        .is_some());
    let retained = branch.execution.hypergraph_store().clone();
    let mut child = branch.capture_child(limits()).unwrap();
    drop(branch);
    assert!(retained.new_transaction(false).is_err());
    let input = frame(2, child.prover_root().unwrap());
    let next = child.materialize(&input).unwrap();
    expected.source.materialize(&input).unwrap();
    assert_eq!(
        next.prover_root,
        expected
            .source
            .hypergraph
            .current_forest_phase_root(&[0xff; 32], 0)
            .unwrap()
    );
    assert_eq!(child.cursor().unwrap(), 2);
    assert_eq!(primary.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn tentative_deployment_matches_durable_application_state_and_continues_in_child() {
    let fixture = Fixture::new(None);
    let expected = Fixture::new(None);
    let sequence = fixture.db.inner().latest_sequence_number();
    let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
    let config = quil_execution::token_intrinsic::config::TokenConfiguration {
        behavior: quil_execution::token_intrinsic::constants::DIVISIBLE as u32,
        name: b"materializer branch token".to_vec(),
        owner_public_key: vec![1; 32],
        ..Default::default()
    };
    let app = quil_execution::token_intrinsic::materialize::token_deploy_domain(&config).unwrap();
    let deploy = quil_execution::token_intrinsic::TokenDeploy {
        config: config.to_canonical_bytes().unwrap(),
        rdf_schema: Vec::new(),
    };
    let mut input = frame(1, branch.prover_root().unwrap());
    input.requests[0]
        .requests
        .push(quil_types::proto::global::MessageRequest {
            timestamp: 0,
            request: Some(
                quil_types::proto::global::message_request::Request::TokenDeploy(
                    quil_execution::token_intrinsic::conversions::token_deploy_to_proto(&deploy)
                        .unwrap(),
                ),
            ),
        });
    let result = branch.materialize(&input).unwrap();
    let outcomes = branch
        .execution
        .clock_store()
        .get_global_clock_frame_outcomes(1)
        .unwrap();
    assert_eq!(result.processed, 1, "{outcomes:?}");
    assert_eq!(result.skipped, 0);
    assert_eq!(
        result.consumed_bundles,
        vec![
            crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&input.requests[0])
                .unwrap()
        ]
    );
    expected.source.materialize(&input).unwrap();
    let metadata = quil_hypergraph::addressing::Location {
        app_address: app,
        data_address: [0xff; 32],
    };
    let deployed = branch
        .materializer
        .hypergraph
        .get_vertex_data_checked(&metadata)
        .unwrap()
        .unwrap();
    assert_eq!(
        expected
            .source
            .hypergraph
            .get_vertex_data_checked(&metadata)
            .unwrap(),
        Some(deployed.clone())
    );
    assert!(fixture
        .source
        .hypergraph
        .get_vertex_data_checked(&metadata)
        .unwrap()
        .is_none());
    let application_root = branch
        .materializer
        .hypergraph
        .current_forest_phase_root(&app, 0)
        .unwrap();
    assert_eq!(
        application_root,
        expected
            .source
            .hypergraph
            .current_forest_phase_root(&app, 0)
            .unwrap()
    );
    assert_eq!(
        branch.materializer.hypergraph.total_size(),
        expected.source.hypergraph.total_size()
    );
    assert!(branch.materializer.hypergraph.total_size() > fixture.source.hypergraph.total_size());
    let mut child = branch.capture_child(limits()).unwrap();
    drop(branch);
    assert_eq!(
        child
            .materializer
            .hypergraph
            .get_vertex_data_checked(&metadata)
            .unwrap(),
        Some(deployed)
    );
    // Replaying the deployment in a different frame must have the same
    // acceptance/state behavior as the independent durable executor.
    input.header = frame(2, child.prover_root().unwrap()).header;
    let child_result = child.materialize(&input).unwrap();
    let durable_result = expected.source.materialize(&input).unwrap();
    assert_eq!(
        (child_result.processed, child_result.skipped),
        (durable_result.processed, durable_result.skipped)
    );
    assert_eq!(
        child
            .materializer
            .hypergraph
            .current_forest_phase_root(&app, 0)
            .unwrap(),
        expected
            .source
            .hypergraph
            .current_forest_phase_root(&app, 0)
            .unwrap()
    );
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn capture_rejects_busy_opaque_foreign_and_inconsistent_sources() {
    let mut fixture = Fixture::new(None);
    let sequence = fixture.db.inner().latest_sequence_number();
    {
        let _busy = fixture.source.frame_execution.lock().unwrap();
        assert!(fixture
            .source
            .capture_execution_branch(limits())
            .err()
            .unwrap()
            .to_string()
            .contains("busy"));
    }
    let calls = Arc::new(AtomicUsize::new(0));
    fixture.source.prover_tree_reset = Some({
        let calls = calls.clone();
        Arc::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            true
        })
    });
    assert!(fixture
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string()
        .contains("opaque"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    fixture.source.prover_tree_reset = None;
    let registry = fixture.source.eviction_registry.take();
    fixture.source.eviction_registry = Some(Arc::new(ConcreteProverRegistry::new()));
    assert!(fixture
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string()
        .contains("registry differs"));
    fixture.source.eviction_registry = registry;
    let other = Fixture::new(None);
    fixture.source.clock_store = other.clock.clone();
    assert!(fixture
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string()
        .contains("provider store mismatch"));
    fixture.source.clock_store = fixture.clock.clone();
    fixture.source.seed_cursor(1);
    assert!(fixture
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string()
        .contains("durable cursor differs"));
    fixture
        .source
        .last_materialized_frame
        .store(0, Ordering::SeqCst);
    fixture
        .source
        .hypergraph
        .record_prover_root(0, vec![99; 32]);
    assert!(fixture
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string()
        .contains("prover root differs"));
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
    assert_eq!(
        fixture
            .db
            .inner()
            .property_int_value("rocksdb.num-snapshots")
            .unwrap(),
        Some(0)
    );
}

#[test]
fn materializer_metadata_and_captured_cursor_are_bounded_and_checked() {
    let fixture = Fixture::new(None);
    fixture
        .source
        .set_coverage_halt_durations(std::collections::HashMap::from([(vec![5; 37], 17)]));
    let branch = fixture.source.capture_execution_branch(limits()).unwrap();
    let usage = branch.metadata_usage();
    drop(branch);
    let mut budget = limits();
    budget.max_metadata_entries = usage.entries - 1;
    assert!(fixture.source.capture_execution_branch(budget).is_err());
    budget.max_metadata_entries = usage.entries;
    budget.max_metadata_bytes = usage.bytes - 1;
    assert!(fixture.source.capture_execution_branch(budget).is_err());
    budget.max_metadata_bytes = usage.bytes;
    assert!(fixture.source.capture_execution_branch(budget).is_ok());
    let txn = fixture.store.new_transaction(false).unwrap();
    txn.set(
        &quil_store::encoding::global_materialized_cursor_key(),
        &[1, 2, 3],
    )
    .unwrap();
    txn.commit().unwrap();
    assert!(fixture
        .source
        .capture_execution_branch(limits())
        .err()
        .unwrap()
        .to_string()
        .contains("invalid captured materializer cursor"));
    assert_eq!(
        fixture
            .db
            .inner()
            .property_int_value("rocksdb.num-snapshots")
            .unwrap(),
        Some(0)
    );
}

#[test]
fn skipped_or_mismatched_frames_close_the_branch_even_when_clock_is_ahead() {
    let fixture = Fixture::new(None);
    let txn = fixture.clock.new_transaction(false).unwrap();
    fixture
        .clock
        .put_global_clock_frame(&frame(100, [0; 32]), txn.as_ref())
        .unwrap();
    txn.commit().unwrap();
    let sequence = fixture.db.inner().latest_sequence_number();
    for (number, bad_root) in [(2, false), (0, false), (1, true)] {
        let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
        let root = if bad_root {
            [99; 32]
        } else {
            branch.prover_root().unwrap()
        };
        assert!(branch.materialize(&frame(number, root)).is_err());
        assert!(branch.storage_usage().closed);
        assert!(branch.cursor().is_err());
        assert!(branch.capture_child(limits()).is_err());
    }
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn frame_input_limits_reject_before_execution_and_accept_the_exact_boundary() {
    let fixture = Fixture::new(None);
    let root = fixture
        .source
        .hypergraph
        .current_forest_phase_root(&[0xff; 32], 0)
        .unwrap();
    let input = frame(1, root);
    let bytes = prost::Message::encoded_len(&input);
    let sequence = fixture.db.inner().latest_sequence_number();
    for budget in [
        MaterializerBranchLimits {
            max_frame_bytes: bytes - 1,
            ..limits()
        },
        MaterializerBranchLimits {
            max_frame_items: 0,
            ..limits()
        },
    ] {
        let mut branch = fixture.source.capture_execution_branch(budget).unwrap();
        assert!(branch
            .materialize(&input)
            .unwrap_err()
            .to_string()
            .contains("input budget"));
        assert!(branch.storage_usage().closed);
    }
    let mut branch = fixture
        .source
        .capture_execution_branch(MaterializerBranchLimits {
            max_frame_bytes: bytes,
            max_frame_items: 1,
            ..limits()
        })
        .unwrap();
    branch.materialize(&input).unwrap();
    assert_eq!(branch.cursor().unwrap(), 1);
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn swallowed_storage_failure_prevents_reuse_but_not_existing_children() {
    let fixture = Fixture::new(None);
    let sequence = fixture.db.inner().latest_sequence_number();
    let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
    let mut child = branch.capture_child(limits()).unwrap();
    let root = child.prover_root().unwrap();
    let retained = branch.execution.hypergraph_store().clone();
    // Simulate a caller swallowing a staging error before commit.
    let txn = retained.new_transaction(false).unwrap();
    assert!(txn.set(b"oversized", &vec![0; (2 << 20) + 1]).is_err());
    txn.abort().unwrap();
    assert!(branch.materialize(&frame(1, root)).is_err());
    assert!(branch.storage_usage().closed);
    assert!(retained.new_transaction(false).is_err());
    child.materialize(&frame(1, root)).unwrap();
    assert_eq!(child.cursor().unwrap(), 1);
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn late_registry_failure_discards_the_frame_and_its_cursor() {
    let fixture = Fixture::new(None);
    let sequence = fixture.db.inner().latest_sequence_number();
    let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
    let root = branch.prover_root().unwrap();
    let retained = branch.execution.hypergraph_store().clone();
    let txn = retained.new_transaction(false).unwrap();
    retained
        .save_root(
            txn.as_ref(),
            "vertex",
            "adds",
            &quil_types::store::ShardKey {
                l1: [0; 3],
                l2: [0xff; 32],
            },
            b"invalid legacy registry blob",
        )
        .unwrap();
    txn.commit().unwrap();
    assert!(branch.materialize(&frame(1, root)).is_err());
    assert!(branch.storage_usage().closed);
    assert!(retained.new_transaction(false).is_err());
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 0);
    assert!(fixture
        .clock
        .get_global_clock_frame_outcomes(1)
        .unwrap()
        .is_empty());
    assert_eq!(fixture.current.materialized(), 0);
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn captured_materializer_runs_bound_reset_before_publishing_only_private_state() {
    let old_key = quil_crypto::FalconSigner::generate().public_key().to_vec();
    let new_key = quil_crypto::FalconSigner::generate().public_key().to_vec();
    let mut fixture = Fixture::new(Some(&old_key));
    let mut expected = Fixture::new(Some(&old_key));
    fixture.source.frozen_era_recovery_enabled = false;
    expected.source.frozen_era_recovery_enabled = false;
    let policy = crate::frame_maintenance::GlobalMaintenance::new(1, hex::encode(&new_key), vec![]);
    fixture.source.global_maintenance = Some(policy.clone());
    expected.source.global_maintenance = Some(policy);
    let reset = quil_execution::global_intrinsic::materialize::quil_grid_reset_v2_frame();
    fixture.advance_checkpoint(reset - 1);
    expected.advance_checkpoint(reset - 1);
    // A reset may fall inside an epoch whose census already ran. Its registry
    // must still refresh, including before a descendant reconstructs its cache.
    let epoch = quil_types::consensus::epoch_for_frame(reset);
    fixture
        .source
        .last_eviction_pass_epoch
        .store(epoch, Ordering::SeqCst);
    expected
        .source
        .last_eviction_pass_epoch
        .store(epoch, Ordering::SeqCst);
    let sequence = fixture.db.inner().latest_sequence_number();
    let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
    let parent = branch.prover_root().unwrap();
    let input = frame(reset, parent);
    let result = branch.materialize(&input).unwrap();
    expected.source.materialize(&input).unwrap();
    assert_ne!(result.prover_root, parent);
    let old_address =
        quil_execution::global_intrinsic::materialize::prover_address_from_pubkey(&old_key)
            .unwrap();
    let new_address =
        quil_execution::global_intrinsic::materialize::prover_address_from_pubkey(&new_key)
            .unwrap();
    for materializer in [&branch.materializer, &expected.source] {
        assert!(
            materializer
                .prover_registry
                .get_prover_info(&old_address)
                .unwrap()
                .is_none(),
            "the reset must discard the old registry cache within the current epoch"
        );
        assert!(materializer
            .prover_registry
            .get_prover_info(&new_address)
            .unwrap()
            .is_some());
    }
    let marker = crate::frame_maintenance::GRID_RESET_V2_MARKER_KEY;
    assert_eq!(
        branch
            .materializer
            .hypergraph
            .read_execution_record(marker)
            .unwrap(),
        Some(vec![1])
    );
    assert_eq!(
        fixture
            .source
            .hypergraph
            .read_execution_record(marker)
            .unwrap(),
        None
    );
    assert_eq!(
        fixture
            .source
            .hypergraph
            .current_forest_phase_root(&[0xff; 32], 0)
            .unwrap(),
        parent
    );
    assert_eq!(fixture.current.materialized(), reset - 1);
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
    let mut child = branch.capture_child(limits()).unwrap();
    assert_eq!(child.cursor().unwrap(), reset);
    let next = frame(reset + 1, result.prover_root);
    let continued = branch.materialize(&next).unwrap();
    let descendant = child.materialize(&next).unwrap();
    expected.source.materialize(&next).unwrap();
    assert_eq!(continued.prover_root, descendant.prover_root);
    assert_eq!(
        continued.prover_root,
        expected
            .source
            .hypergraph
            .current_forest_phase_root(&[0xff; 32], 0)
            .unwrap()
    );
    assert_eq!(expected.source.last_materialized_frame(), reset + 1);
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn frozen_tentative_frame_keeps_state_and_outcomes_private() {
    let mut fixture = Fixture::new(None);
    fixture.source.frozen_era_recovery_enabled = true;
    fixture.advance_checkpoint(FROZEN_ERA_RECOVERY_START - 1);
    let sequence = fixture.db.inner().latest_sequence_number();
    let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
    let parent = branch.prover_root().unwrap();
    let result = branch
        .materialize(&frame(FROZEN_ERA_RECOVERY_START, parent))
        .unwrap();
    assert_eq!(result.prover_root, parent);
    assert_eq!(result.skipped, 1);
    let outcomes = branch
        .execution
        .clock_store()
        .get_global_clock_frame_outcomes(FROZEN_ERA_RECOVERY_START)
        .unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].status, quil_types::store::RequestStatus::Failed);
    assert_eq!(
        fixture.current.materialized(),
        FROZEN_ERA_RECOVERY_START - 1
    );
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn unwound_frame_closes_private_state_and_leaves_existing_children_usable() {
    let fixture = Fixture::new(None);
    let sequence = fixture.db.inner().latest_sequence_number();
    let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
    let mut child = branch.capture_child(limits()).unwrap();
    let retained = branch.execution.hypergraph_store().clone();
    let input = frame(1, branch.prover_root().unwrap());
    // This lock is consulted after the private state/cursor batch commits.
    // Poisoning it exercises unwinding beyond the ordinary Result paths.
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = branch.materializer.coverage_halt_durations.lock().unwrap();
        panic!("injected coverage failure");
    }))
    .is_err());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        branch.materialize(&input)
    }))
    .is_err());
    assert!(branch.storage_usage().closed);
    assert!(retained.new_transaction(false).is_err());
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 0);
    assert!(fixture
        .clock
        .get_global_clock_frame_outcomes(1)
        .unwrap()
        .is_empty());
    assert_eq!(fixture.current.materialized(), 0);
    assert!(fixture.source.frame_execution.try_lock().is_ok());
    assert!(fixture.source.coverage_halt_durations.lock().is_ok());
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
    assert_eq!(child.materialize(&input).unwrap().frame_number, 1);
}

#[test]
fn tentative_maintenance_requires_a_bound_policy_before_state_changes() {
    use quil_execution::global_intrinsic::materialize as m;
    for (number, unified) in [
        (m::unified_tree_cutover_frame(), false),
        (m::quil_grid_reset_v2_frame(), true),
    ] {
        let fixture = Fixture::new(None);
        fixture.source.hypergraph.set_unified_tree(unified);
        fixture.advance_checkpoint(number - 1);
        let sequence = fixture.db.inner().latest_sequence_number();
        let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
        let root = branch.prover_root().unwrap();
        assert!(matches!(branch.materialize(&frame(number, root)),
            Err(QuilError::ExecutionUnavailable(message)) if message.contains("bound policy")));
        assert!(branch.storage_usage().closed);
        assert_eq!(fixture.source.hypergraph.unified_tree(), unified);
        assert_eq!(fixture.current.materialized(), number - 1);
        assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), number - 1);
        assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
    }
}

#[test]
fn completed_execution_binds_header_and_body_without_binding_the_certificate_carrier() {
    let fixture = Fixture::new(None);
    let expected = Fixture::new(None);
    let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
    assert_eq!(
        branch.completed_checkpoint().unwrap(),
        None,
        "a legacy cursor cannot invent an executed frame identity"
    );
    let input = frame(1, branch.prover_root().unwrap());
    let result = branch.materialize(&input).unwrap();
    let checkpoint = branch.completed_checkpoint().unwrap().unwrap();
    assert_eq!(checkpoint, result.checkpoint);
    assert_eq!(checkpoint.frame_number(), 1);
    assert_eq!(
        checkpoint.frame_identity(),
        quil_crypto::poseidon::hash_bytes_to_32(&input.header.as_ref().unwrap().output).unwrap()
    );
    assert!(checkpoint.matches_frame(&input).unwrap());
    let mut certified = input.clone();
    certified
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581
        .get_or_insert_with(Default::default)
        .signature = vec![1, 2, 3];
    assert!(
        checkpoint.matches_frame(&certified).unwrap(),
        "matching execution input does not itself validate a certificate"
    );
    for changed in 0..4 {
        let mut foreign = input.clone();
        match changed {
            0 => foreign.header.as_mut().unwrap().rank += 1,
            1 => foreign.header.as_mut().unwrap().parent_selector = vec![9; 32],
            2 => foreign.requests.push(Default::default()),
            _ => foreign.header.as_mut().unwrap().output[0] ^= 1,
        }
        assert!(!checkpoint.matches_frame(&foreign).unwrap());
    }
    expected.source.materialize(&input).unwrap();
    let persisted = expected.source.capture_execution_branch(limits()).unwrap();
    assert_eq!(
        persisted.completed_checkpoint().unwrap(),
        Some(checkpoint.clone())
    );
    let child = branch.capture_child(limits()).unwrap();
    drop(branch);
    assert_eq!(child.completed_checkpoint().unwrap(), Some(checkpoint));
    assert!(fixture
        .source
        .capture_execution_branch(limits())
        .unwrap()
        .completed_checkpoint()
        .unwrap()
        .is_none());
}

#[test]
fn pending_execution_prevents_blind_retry_and_cannot_authorize_a_parent() {
    let mut fixture = Fixture::new(None);
    fixture.source.global_maintenance = Some(crate::frame_maintenance::GlobalMaintenance::new(
        1,
        "invalid genesis key".into(),
        vec![],
    ));
    let reset = quil_execution::global_intrinsic::materialize::quil_grid_reset_v2_frame();
    fixture.advance_checkpoint(reset - 1);
    let root = fixture
        .source
        .hypergraph
        .current_forest_phase_root(&[0xff; 32], 0)
        .unwrap();
    let input = frame(reset, root);
    assert!(fixture.source.materialize(&input).is_err());
    let pending = quil_store::encoding::global_execution_pending_key();
    assert!(fixture
        .source
        .hypergraph
        .read_execution_record(&pending)
        .unwrap()
        .is_some());
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), reset - 1);
    let sequence = fixture.db.inner().latest_sequence_number();
    // Even repairing the input policy cannot prove that arbitrary prior
    // maintenance or request writes were rolled back.
    fixture.source.global_maintenance = Some(crate::frame_maintenance::GlobalMaintenance::new(
        1,
        hex::encode(quil_crypto::FalconSigner::generate().public_key()),
        vec![],
    ));
    assert!(matches!(fixture.source.materialize(&input),
        Err(QuilError::ExecutionUnavailable(message)) if message.contains("recovery before retry")));
    let captured = fixture.source.capture_execution_branch(limits()).unwrap();
    assert!(matches!(captured.completed_checkpoint(),
        Err(QuilError::ExecutionUnavailable(message)) if message.contains("unfinished GLOBAL")));
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);

    // A crash can leave the state/cursor batch committed without its completion
    // record. Startup seeding that cursor must not turn a replay into success.
    fixture.advance_checkpoint(reset);
    let sequence = fixture.db.inner().latest_sequence_number();
    for retry in [input, frame(reset + 1, root), frame(reset + 2, root)] {
        assert!(matches!(fixture.source.materialize(&retry),
            Err(QuilError::ExecutionUnavailable(message)) if message.contains("recovery before retry")));
    }
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn completed_frame_replay_rejects_different_execution_input_without_writes() {
    let fixture = Fixture::new(None);
    let root = fixture
        .source
        .hypergraph
        .current_forest_phase_root(&[0xff; 32], 0)
        .unwrap();
    let input = frame(1, root);
    fixture.source.materialize(&input).unwrap();
    let sequence = fixture.db.inner().latest_sequence_number();
    fixture.source.materialize(&input).unwrap();

    let mut certified = input.clone();
    certified
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581
        .get_or_insert_with(Default::default)
        .signature = vec![1, 2, 3];
    fixture.source.materialize(&certified).unwrap();
    for changed in 0..4 {
        let mut foreign = input.clone();
        match changed {
            0 => foreign.header.as_mut().unwrap().rank += 1,
            1 => foreign.header.as_mut().unwrap().parent_selector = vec![9; 32],
            2 => foreign.requests.push(Default::default()),
            _ => foreign.header.as_mut().unwrap().output[0] ^= 1,
        }
        assert!(matches!(fixture.source.materialize(&foreign),
            Err(QuilError::ExecutionUnavailable(message)) if message.contains("replay differs")));
    }
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
    assert!(fixture
        .source
        .hypergraph
        .read_execution_record(&quil_store::encoding::global_execution_pending_key())
        .unwrap()
        .is_none());
}

#[test]
fn frozen_missing_frame_skip_cannot_bypass_unfinished_execution() {
    let mut fixture = Fixture::new(None);
    fixture.source.frozen_era_recovery_enabled = true;
    fixture.advance_checkpoint(FROZEN_ERA_RECOVERY_START - 1);
    let root = fixture
        .source
        .hypergraph
        .current_forest_phase_root(&[0xff; 32], 0)
        .unwrap();
    let input = frame(FROZEN_ERA_RECOVERY_START, root);
    fixture.source.begin_execution_checkpoint(&input).unwrap();
    fixture.advance_checkpoint(FROZEN_ERA_RECOVERY_START);
    let sequence = fixture.db.inner().latest_sequence_number();
    for cursor in [FROZEN_ERA_RECOVERY_START, FROZEN_ERA_RECOVERY_START + 1] {
        assert!(matches!(fixture.source.frozen_era_skip(cursor),
            Err(QuilError::ExecutionUnavailable(message)) if message.contains("recovery before retry")));
    }
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn execution_checkpoint_rejects_malformed_records_and_ignores_one_for_changed_state() {
    let fixture = Fixture::new(None);
    let mut parent = fixture.source.capture_execution_branch(limits()).unwrap();
    let input = frame(1, parent.prover_root().unwrap());
    parent.materialize(&input).unwrap();
    let key = quil_store::encoding::global_execution_checkpoint_key();
    let bytes = parent
        .materializer
        .hypergraph
        .read_execution_record(&key)
        .unwrap()
        .unwrap();
    for bad in [Vec::new(), bytes[..bytes.len() - 1].to_vec(), {
        let mut bad = bytes.clone();
        bad[0] ^= 0xff;
        bad
    }] {
        let branch = parent.capture_child(limits()).unwrap();
        let txn = branch
            .execution
            .hypergraph_store()
            .new_transaction(false)
            .unwrap();
        txn.set(&key, &bad).unwrap();
        txn.commit().unwrap();
        assert!(branch.completed_checkpoint().is_err());
    }
    let branch = parent.capture_child(limits()).unwrap();
    let key = quil_crypto::FalconSigner::generate().public_key().to_vec();
    crate::genesis::seed_active_prover_on_filter(
        &branch.materializer.hypergraph,
        &key,
        1000,
        2,
        &[],
    )
    .unwrap();
    // A prover tree changed outside execution (a peer reconcile) makes the
    // receipt stale: it reads as absent, never as authority for this state.
    assert!(branch.completed_checkpoint().unwrap().is_none());
    assert!(parent.completed_checkpoint().unwrap().is_some());
}

#[test]
fn checkpoint_and_unfinished_execution_survive_database_reopen() {
    for interrupted in [false, true] {
        let fixture = Fixture::new(None);
        let path = fixture.db.inner().path().to_path_buf();
        let input = frame(
            1,
            fixture
                .source
                .hypergraph
                .current_forest_phase_root(&[0xff; 32], 0)
                .unwrap(),
        );
        fixture.source.materialize(&input).unwrap();
        let complete = fixture
            .source
            .capture_execution_branch(limits())
            .unwrap()
            .completed_checkpoint()
            .unwrap()
            .unwrap();
        if interrupted {
            let next = frame(
                2,
                fixture
                    .source
                    .hypergraph
                    .current_forest_phase_root(&[0xff; 32], 0)
                    .unwrap(),
            );
            // Simulate exit after the main cursor batch, before post-commit
            // stages finish and the completion transaction clears the marker.
            fixture.source.begin_execution_checkpoint(&next).unwrap();
            fixture
                .source
                .execution_manager
                .commit_frame_with_global_cursor(2)
                .unwrap();
        }
        drop(fixture);
        let db = quil_store::RocksDb::open_for_read_only(&path).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        );
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(true);
        crdt.warm_sizes(&[]).unwrap();
        let cursor = read_cursor(store.as_ref()).unwrap();
        let recovered = execution_checkpoint::read_completed(store.as_ref(), &crdt, cursor);
        if interrupted {
            assert_eq!(cursor, 2);
            assert!(
                matches!(recovered, Err(QuilError::ExecutionUnavailable(message))
                if message.contains("unfinished GLOBAL"))
            );
        } else {
            assert_eq!(cursor, 1);
            assert_eq!(recovered.unwrap(), Some(complete));
        }
    }
}

#[test]
fn unavailable_global_bucket_cannot_be_checkpointed_as_empty() {
    let fixture = Fixture::new(None);
    let mut branch = fixture.source.capture_execution_branch(limits()).unwrap();
    let input = frame(1, branch.prover_root().unwrap());
    let forest =
        quil_forest::Forest::with_namespace(fixture.db.inner(), quil_store::FOREST_NAMESPACE);
    let (key, value) = forest.global_head_version_put(17, 900).unwrap();
    let txn = branch
        .execution
        .hypergraph_store()
        .new_transaction(false)
        .unwrap();
    txn.set(&key, &value).unwrap();
    txn.commit().unwrap();
    assert!(
        matches!(branch.materialize(&input), Err(QuilError::ExecutionUnavailable(message))
        if message.contains("global commitment"))
    );
    assert!(branch.storage_usage().closed);
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 0);
}

/// A process stopped inside the in-place path leaves an unfinished-execution
/// marker that refuses every later execution. Startup resolves it by the
/// durable cursor, which lands in one batch with the frame's state.
#[test]
fn startup_recovers_an_unfinished_execution_by_its_cursor() {
    let root = |fixture: &Fixture| {
        fixture.source.hypergraph.current_forest_phase_root(&[0xff; 32], 0).unwrap()
    };
    let receipt = |fixture: &Fixture| {
        fixture
            .source
            .hypergraph
            .read_execution_record(&quil_store::encoding::global_execution_checkpoint_key())
            .unwrap()
    };
    let pending = |fixture: &Fixture| {
        fixture
            .source
            .hypergraph
            .read_execution_record(&quil_store::encoding::global_execution_pending_key())
            .unwrap()
    };

    // Stopped before the state batch: the frame runs again on its receipted base.
    let fixture = Fixture::new(None);
    fixture.source.materialize(&frame(1, root(&fixture))).unwrap();
    let base_receipt = receipt(&fixture);
    let second = frame(2, root(&fixture));
    fixture.source.begin_execution_checkpoint(&second).unwrap();
    assert!(matches!(fixture.source.materialize(&second),
        Err(QuilError::ExecutionUnavailable(message)) if message.contains("recovery before retry")));
    assert_eq!(fixture.source.recover_unfinished_execution().unwrap(),
        Some(UnfinishedExecution::NotApplied(2)));
    assert!(pending(&fixture).is_none());
    assert_eq!(receipt(&fixture), base_receipt, "a receipt describing the state is kept");
    fixture.source.materialize(&second).unwrap();
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 2);
    assert_eq!(fixture.source.recover_unfinished_execution().unwrap(), None);

    // Stopped after the state batch: the frame is not applied again, and the
    // stale receipt is dropped so a certified child authenticates the state.
    let fixture = Fixture::new(None);
    fixture.source.materialize(&frame(1, root(&fixture))).unwrap();
    let second = frame(2, root(&fixture));
    fixture.source.begin_execution_checkpoint(&second).unwrap();
    fixture.source.execution_manager.commit_frame_with_global_cursor(2).unwrap();
    assert_eq!(fixture.source.recover_unfinished_execution().unwrap(),
        Some(UnfinishedExecution::Applied(2)));
    assert!(pending(&fixture).is_none());
    assert!(receipt(&fixture).is_none());
    assert_eq!(fixture.source.last_materialized_frame(), 2);
    let sequence = fixture.db.inner().latest_sequence_number();
    fixture.source.materialize(&second).unwrap();
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence, "not applied twice");
    fixture.source.materialize(&frame(3, root(&fixture))).unwrap();
    assert_eq!(read_cursor(fixture.store.as_ref()).unwrap(), 3);

    // A cursor that is neither is refused, and the marker stays.
    let fixture = Fixture::new(None);
    fixture.source.materialize(&frame(1, root(&fixture))).unwrap();
    fixture.source.begin_execution_checkpoint(&frame(2, root(&fixture))).unwrap();
    fixture.source.execution_manager.commit_frame_with_global_cursor(5).unwrap();
    assert!(matches!(fixture.source.recover_unfinished_execution(),
        Err(QuilError::ExecutionUnavailable(message)) if message.contains("must be resynced")));
    assert!(pending(&fixture).is_some());

    // Mutations a failed attempt left staged in this process would be
    // published by any later commit: only a restart recovers.
    let fixture = Fixture::new(None);
    fixture.source.materialize(&frame(1, root(&fixture))).unwrap();
    fixture.source.begin_execution_checkpoint(&frame(2, root(&fixture))).unwrap();
    fixture
        .source
        .hypergraph
        .add_vertex(
            &quil_hypergraph::Location { app_address: [0xff; 32], data_address: [7; 32] },
            b"staged by a failed attempt",
        )
        .unwrap();
    assert!(matches!(fixture.source.recover_unfinished_execution(),
        Err(QuilError::ExecutionUnavailable(message)) if message.contains("restart to recover")));
    assert!(pending(&fixture).is_some());
}
