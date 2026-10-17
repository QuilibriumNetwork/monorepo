use super::*;

struct TestIssuance;
impl quil_types::consensus::RewardIssuance for TestIssuance {
    fn calculate(
        &self,
        _: u64,
        _: u64,
        _: u64,
        _: &[std::collections::HashMap<String, quil_types::consensus::ProverAllocation>],
    ) -> Result<Vec<num_bigint::BigInt>> {
        unreachable!("dependency construction does not issue rewards")
    }
}

fn memory_crdt() -> Arc<quil_hypergraph::HypergraphCrdt> {
    Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(quil_tries::ShaInclusionProver),
    ))
}

#[test]
fn fork_preserves_global_verification_reward_and_reset_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
    let primary_crdt = memory_crdt();
    let primary_shards: Arc<dyn ShardsStore> =
        Arc::new(quil_store::RocksShardsStore::new(db.inner()));
    let primary_clock: Arc<dyn ClockStore> = Arc::new(crate::testing::NoopClockStore);
    let primary_registry: Arc<dyn quil_types::consensus::ProverRegistry> =
        Arc::new(crate::prover_registry::SharedProverRegistry::new());
    let key_manager: Arc<dyn KeyManager> = Arc::new(crate::testing::NoopKeyManager);
    let frame_prover: Arc<dyn quil_types::crypto::FrameProver> =
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048));
    let bls: Arc<dyn quil_types::crypto::BlsConstructor> =
        Arc::new(quil_crypto::FalconKeyConstructor);
    let inclusion: Arc<dyn quil_types::crypto::InclusionProver> =
        Arc::new(quil_tries::ShaInclusionProver);
    let issuance: Arc<dyn quil_types::consensus::RewardIssuance> = Arc::new(TestIssuance);
    let keep = Arc::new(
        [vec![6; 32]]
            .into_iter()
            .collect::<std::collections::HashSet<_>>(),
    );
    let prefixes = Arc::new(vec![vec![3], vec![4]]);
    let source = GlobalIntrinsic::new_with_stores(
        key_manager.clone(),
        Some(frame_prover.clone()),
        Some(primary_clock.clone()),
        Some(primary_shards.clone()),
        Some(db.clone()),
    )
    .with_kick_verify_deps(bls.clone(), primary_crdt.clone(), inclusion.clone())
    .with_frame_header_deps(primary_registry.clone(), issuance.clone())
    .with_archive_prover_addresses(keep.clone())
    .with_reset_genesis_prefixes(prefixes.clone());
    assert_eq!(
        Arc::strong_count(&db),
        1,
        "the intrinsic must not retain a writable primary DB handle"
    );
    let overlay = Arc::new(quil_forest::ExecutionOverlay::capture(
        db.inner(),
        quil_forest::OverlayLimits {
            max_delta_bytes: 1 << 20,
            max_delta_entries: 1000,
            max_record_bytes: 1 << 16,
            max_read_bytes: 1 << 20,
            max_read_operations: 1000,
            max_cursors: 8,
        },
    ).unwrap());
    let target = crate::manager::ExecutionForkContext {
        crdt: memory_crdt(),
        clock_store: Arc::new(crate::testing::NoopClockStore),
        global_clock_store: Arc::new(crate::testing::NoopClockStore),
        shards_store: Some(Arc::new(quil_store::OverlayShardsStore::new(
            overlay.clone(),
        ))),
        prover_registry: Arc::new(crate::prover_registry::SharedProverRegistry::new()),
    };
    let branch = source.fork_with_context(&target).unwrap();
    assert!(branch.shard_metadata_writes_enabled);
    assert!(Arc::ptr_eq(&branch.key_manager, &key_manager));
    assert!(Arc::ptr_eq(
        branch.frame_prover.as_ref().unwrap(),
        &frame_prover
    ));
    assert!(Arc::ptr_eq(branch.bls_constructor.as_ref().unwrap(), &bls));
    assert!(Arc::ptr_eq(
        branch.inclusion_prover.as_ref().unwrap(),
        &inclusion
    ));
    assert!(Arc::ptr_eq(
        branch.reward_issuance.as_ref().unwrap(),
        &issuance
    ));
    assert!(Arc::ptr_eq(
        branch.archive_prover_addresses.as_ref().unwrap(),
        &keep
    ));
    assert!(Arc::ptr_eq(
        branch.reset_genesis_prefixes.as_ref().unwrap(),
        &prefixes
    ));
    assert!(Arc::ptr_eq(
        branch.hypergraph.as_ref().unwrap(),
        &target.crdt
    ));
    assert!(!Arc::ptr_eq(
        branch.hypergraph.as_ref().unwrap(),
        &primary_crdt
    ));
    assert!(Arc::ptr_eq(
        branch.clock_store.as_ref().unwrap(),
        &target.clock_store
    ));
    assert!(!Arc::ptr_eq(
        branch.clock_store.as_ref().unwrap(),
        &target.global_clock_store
    ));
    assert!(Arc::ptr_eq(
        branch.shards_store.as_ref().unwrap(),
        target.shards_store.as_ref().unwrap()
    ));
    assert!(!Arc::ptr_eq(
        branch.shards_store.as_ref().unwrap(),
        &primary_shards
    ));
    assert!(Arc::ptr_eq(
        branch.prover_registry.as_ref().unwrap(),
        &target.prover_registry
    ));
    assert!(!Arc::ptr_eq(
        branch.prover_registry.as_ref().unwrap(),
        &primary_registry
    ));
    let mut missing = target;
    missing.shards_store = None;
    assert!(source.fork_with_context(&missing).is_err());
    let minimal = GlobalIntrinsic::new(key_manager)
        .fork_with_context(&missing)
        .unwrap();
    assert!(!minimal.shard_metadata_writes_enabled);
    assert!(minimal.clock_store.is_none());
    assert!(minimal.shards_store.is_none());
    assert!(minimal.hypergraph.is_none());
    assert!(minimal.frame_prover.is_none());
    assert!(minimal.bls_constructor.is_none());
    assert!(minimal.inclusion_prover.is_none());
    assert!(minimal.prover_registry.is_none());
    assert!(minimal.reward_issuance.is_none());
    assert!(minimal.archive_prover_addresses.is_none());
    assert!(minimal.reset_genesis_prefixes.is_none());
    overlay.close();
}
