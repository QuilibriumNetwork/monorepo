use super::*;
use quil_hypergraph::HypergraphCrdt;
use quil_types::store::{ClockStore, HypergraphStore, ShardsStore};

fn memory_crdt() -> Arc<HypergraphCrdt> {
    Arc::new(HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(quil_tries::ShaInclusionProver),
    ))
}

fn fork_context(crdt: Arc<HypergraphCrdt>) -> ExecutionForkContext {
    ExecutionForkContext {
        crdt,
        clock_store: Arc::new(crate::testing::NoopClockStore),
        global_clock_store: Arc::new(crate::testing::NoopClockStore),
        shards_store: None,
        prover_registry: Arc::new(crate::prover_registry::SharedProverRegistry::new()),
    }
}

fn manager(crdt: Arc<HypergraphCrdt>, include_global: bool) -> ExecutionEngineManager {
    let crypto = crate::testing::NoopExecutionCrypto::new();
    let resolver =
        Arc::new(crate::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(crdt.clone()));
    ExecutionEngineManager::new(
        Arc::new(quil_tries::ShaInclusionProver),
        crypto.key_manager,
        crdt,
        crypto.circuit_compiler,
        crypto.clock_store,
        resolver,
        include_global,
    )
}

#[test]
fn fork_executes_deploy_rewards_and_maintenance_only_in_its_overlay() {
    // Hold the CRDT capture barrier until the dependent manager is constructed.
    // Clock, shard and hypergraph stores share this branch's captured generation.
    for unified in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
        let primary_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let prover = Arc::new(quil_tries::ShaInclusionProver);
        let primary = Arc::new(HypergraphCrdt::new(primary_store.clone(), prover.clone()));
        primary.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        primary.set_unified_tree(unified);
        primary.warm_sizes(&[]).unwrap();
        let primary_shards = Arc::new(quil_store::RocksShardsStore::new(db.inner()));
        let primary_clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        let parent_frame = quil_types::proto::global::GlobalFrame {
            header: Some(quil_types::proto::global::GlobalFrameHeader {
                frame_number: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        let txn = primary_clock.new_transaction(false).unwrap();
        primary_clock
            .put_global_clock_frame(&parent_frame, txn.as_ref())
            .unwrap();
        txn.commit().unwrap();
        let crypto = crate::testing::NoopExecutionCrypto::new();
        let source = ExecutionEngineManager::new_with_shards(
            prover.clone(),
            crypto.key_manager,
            primary.clone(),
            crypto.circuit_compiler,
            primary_clock.clone(),
            Arc::new(crate::testing::NoopHypergraphConfigResolver),
            true,
            Some(primary_shards.clone()),
            Some(db.clone()),
        );
        let sequence = db.inner().latest_sequence_number();
        let limits = ExecutionBranchLimits {
            state: quil_hypergraph::ExecutionForkLimits {
                overlay: quil_forest::OverlayLimits {
                    max_delta_bytes: 8 << 20,
                    max_delta_entries: 50_000,
                    max_record_bytes: 2 << 20,
                    max_read_bytes: 64 << 20,
                    max_read_operations: 1_000_000,
                    max_cursors: 64,
                },
                max_metadata_entries: 10_000,
                max_metadata_bytes: 4 << 20,
            },
            registry: crate::prover_registry::RegistryLimits {
                max_vertices: 10_000,
                max_record_bytes: 2 << 20,
                max_input_bytes: 16 << 20,
                max_cache_entries: 100_000,
                max_cache_bytes: 16 << 20,
            },
            max_summary_rebuilds: 10_000,
        };
        let make_branch = || {
            let owner = source.capture_execution_branch(limits).unwrap();
            let overlay = owner.overlay().clone();
            let branch = owner.manager().clone();
            let crdt = branch.crdt();
            let store = owner.hypergraph_store().clone();
            let shards = owner.shards_store().unwrap().clone();
            let clock = owner.clock_store().clone();
            (owner, branch, crdt, store, shards, overlay, clock)
        };
        let (_owner, branch, branch_crdt, branch_store, branch_shards, overlay, branch_clock) =
            make_branch();
        let (_sibling_owner, sibling, sibling_crdt, _, _, sibling_overlay, sibling_clock) =
            make_branch();
        assert_eq!(
            branch_clock.get_global_clock_frame(1).unwrap(),
            parent_frame
        );
        let cfg = crate::token_intrinsic::config::TokenConfiguration {
            behavior: crate::token_intrinsic::constants::DIVISIBLE as u32,
            name: b"branch token".to_vec(),
            owner_public_key: vec![1; 32],
            ..Default::default()
        };
        let app = crate::token_intrinsic::materialize::token_deploy_domain(&cfg).unwrap();
        let deploy = crate::token_intrinsic::TokenDeploy {
            config: cfg.to_canonical_bytes().unwrap(),
            rdf_schema: Vec::new(),
        }
        .to_canonical_bytes()
        .unwrap();
        let message = crate::message_envelope::CanonicalMessageBundle {
            requests: vec![Some(
                crate::message_envelope::CanonicalMessageRequest::wrap(deploy).unwrap(),
            )],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap();
        branch
            .process_message(
                2,
                &BigInt::from(0),
                &crate::token_intrinsic::constants::token_base_domain(),
                &message,
            )
            .unwrap();
        let public_key = [7; 57];
        assert!(branch
            .credit_global_frame_fees(2, &public_key, 123)
            .unwrap());
        assert!(!branch
            .credit_global_frame_fees(2, &public_key, 123)
            .unwrap());
        branch.apply_global_due_shard_changes(2).unwrap();
        branch.commit_frame_with_global_cursor(2).unwrap();
        assert_eq!(branch.select_engine(&app).unwrap(), "token");
        assert!(source.select_engine(&app).is_err());
        assert!(sibling.select_engine(&app).is_err());
        assert_eq!(
            branch_crdt
                .read_execution_record(b"quil/global/due-shard-changes/frame/v1")
                .unwrap(),
            Some(2u64.to_be_bytes().to_vec())
        );
        assert!(primary
            .read_execution_record(b"quil/global/due-shard-changes/frame/v1")
            .unwrap()
            .is_none());
        assert!(sibling_crdt
            .read_execution_record(b"quil/global/due-shard-changes/frame/v1")
            .unwrap()
            .is_none());
        let address =
            crate::global_intrinsic::materialize::prover_address_from_pubkey(&public_key).unwrap();
        let reward_address =
            crate::global_intrinsic::materialize::reward_address(&address).unwrap();
        let reward = quil_hypergraph::Location {
            app_address: domains::GLOBAL,
            data_address: reward_address,
        };
        let blob = branch_crdt
            .get_vertex_data_checked(&reward)
            .unwrap()
            .unwrap();
        let tree = quil_tries::VectorCommitmentTree {
            root: quil_tries::deserialize_go_tree(&blob).unwrap(),
        };
        assert_eq!(
            BigInt::from_bytes_be(
                num_bigint::Sign::Plus,
                &crate::global_schema::read_field(&tree, "reward:ProverReward", "Balance").unwrap()
            ),
            BigInt::from(123)
        );
        assert!(primary.get_vertex_data_checked(&reward).unwrap().is_none());
        assert!(sibling_crdt
            .get_vertex_data_checked(&reward)
            .unwrap()
            .is_none());

        // A child must capture actual committed forest and record writes, not
        // only the empty genesis forest or clock records.
        let child = branch.capture_execution_branch(limits).unwrap();
        assert_eq!(child.manager().select_engine(&app).unwrap(), "token");
        assert_eq!(
            child
                .manager()
                .crdt()
                .get_vertex_data_checked(&reward)
                .unwrap(),
            Some(blob)
        );

        // The manager's shard-grid handle must also address its branch. The
        // first refresh records a prefix without a rescan; the next detects
        // a changed grid. Another manager must not see either row.
        let shard_key = [vec![0; 3], app.to_vec()].concat();
        let row = |prefix| quil_types::store::ShardInfo {
            shard_key: shard_key.clone(),
            prefix,
            size: vec![],
            data_shards: 1,
            commitment: vec![],
        };
        let txn = branch_store.new_transaction(false).unwrap();
        branch_shards
            .put_app_shard(txn.as_ref(), &row(vec![0]))
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(branch.refresh_shard_prefixes(), 0);
        let txn = branch_store.new_transaction(false).unwrap();
        branch_shards
            .put_app_shard(txn.as_ref(), &row(vec![1]))
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(branch.refresh_shard_prefixes(), 1);
        assert_eq!(source.refresh_shard_prefixes(), 0);
        assert!(primary_shards.range_app_shards().unwrap().is_empty());
        branch_clock
            .put_global_clock_frame_outcomes(
                2,
                &[quil_types::store::RequestOutcome {
                    status: quil_types::store::RequestStatus::Succeeded,
                    error: String::new(),
                }],
            )
            .unwrap();
        assert_eq!(
            branch_clock
                .get_global_clock_frame_outcomes(2)
                .unwrap()
                .len(),
            1
        );
        assert!(primary_clock
            .get_global_clock_frame_outcomes(2)
            .unwrap()
            .is_empty());
        assert!(sibling_clock
            .get_global_clock_frame_outcomes(2)
            .unwrap()
            .is_empty());
        assert_eq!(db.inner().latest_sequence_number(), sequence);
        overlay.close();
        sibling_overlay.close();
        assert!(child
            .manager()
            .credit_global_frame_fees(3, &public_key, 5)
            .unwrap());
        child.manager().commit_frame_with_global_cursor(3).unwrap();
        assert_eq!(db.inner().latest_sequence_number(), sequence);
    }
}

#[test]
fn fork_keeps_venue_fee_snapshots_and_rebuild_tracking_independent() {
    for include_global in [false, true] {
        let source = manager(memory_crdt(), include_global)
            .with_application_venue()
            .unwrap()
            .with_pricing_network(7);
        let fee = crate::pricing::GlobalQuilFeeSnapshot {
            frame_number: 9,
            difficulty: 1234,
            world_state_bytes: 5678,
        };
        source.publish_global_quil_fee_snapshot(Some(fee));
        source.publish_global_venue_fee_snapshot(fee);
        source.summary_rebuilds.write().unwrap().insert([3; 32]);
        let branch = source
            .fork_with_context(fork_context(memory_crdt()))
            .unwrap();
        assert_eq!(branch.pricing_network(), 7);
        assert_eq!(branch.get_engine("global").is_some(), include_global);
        let engines = branch.engines.read().unwrap();
        let token = engines
            .get("token")
            .unwrap()
            .as_any()
            .unwrap()
            .downcast_ref::<TokenExecutionEngine>()
            .unwrap();
        assert_eq!(token.mode(), ExecutionMode::Application);
        assert_eq!(branch.global_quil_fee_snapshot(9).unwrap(), Some(fee));
        assert_eq!(branch.global_venue_fee_snapshot(9).unwrap(), Some(fee));
        branch.publish_global_quil_fee_snapshot(None);
        source.publish_global_venue_fee_snapshot(crate::pricing::GlobalQuilFeeSnapshot {
            frame_number: 10,
            ..fee
        });
        assert_eq!(source.global_quil_fee_snapshot(9).unwrap(), Some(fee));
        assert_eq!(branch.global_venue_fee_snapshot(9).unwrap(), Some(fee));
        assert!(branch.summary_rebuilds.write().unwrap().remove(&[3; 32]));
        assert!(source.summary_rebuilds.read().unwrap().contains(&[3; 32]));
    }
}

#[test]
fn fork_rejects_primary_crdt_missing_or_unrecognized_engines_and_shards() {
    let mut source = manager(memory_crdt(), true);
    assert!(source
        .fork_with_context(fork_context(source.crdt.clone()))
        .is_err());
    let compute = source.engines.get_mut().unwrap().remove("compute").unwrap();
    assert!(source
        .fork_with_context(fork_context(memory_crdt()))
        .is_err());
    source
        .engines
        .get_mut()
        .unwrap()
        .insert("compute".into(), compute);
    source.engines.get_mut().unwrap().insert(
        "custom".into(),
        Box::new(GlobalExecutionEngine::new(Arc::new(
            quil_tries::ShaInclusionProver,
        ))),
    );
    assert!(source
        .fork_with_context(fork_context(memory_crdt()))
        .is_err());
    source.engines.get_mut().unwrap().remove("custom");
    let dir = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(dir.path()).unwrap();
    source.shards_store = Some(Arc::new(quil_store::RocksShardsStore::new(db.inner())));
    assert!(source
        .fork_with_context(fork_context(memory_crdt()))
        .is_err());
}

#[test]
fn fork_rejects_a_custom_resolver_that_cannot_rebind_state() {
    struct CustomResolver;
    impl crate::hypergraph_intrinsic::HypergraphConfigResolver for CustomResolver {
        fn write_public_key(&self, _: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }
    let crypto = crate::testing::NoopExecutionCrypto::new();
    let source = ExecutionEngineManager::new(
        Arc::new(quil_tries::ShaInclusionProver),
        crypto.key_manager,
        memory_crdt(),
        crypto.circuit_compiler,
        crypto.clock_store,
        Arc::new(CustomResolver),
        false,
    );
    assert!(
        matches!(source.fork_with_context(fork_context(memory_crdt())),
        Err(QuilError::ExecutionUnavailable(message)) if message.contains("resolver"))
    );
}
