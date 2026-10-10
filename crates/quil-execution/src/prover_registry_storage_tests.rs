// Included in prover_registry::tests to share the real registry record fixtures.

#[test]
fn registry_limits_cover_input_and_every_decoded_cache_without_partial_replacement() {
    let (_tmp, store) = temp_store();
    let shard = ShardKey {
        l1: [0; 3],
        l2: [255; 32],
    };
    store
        .save_vertex_underlying(
            "vertex",
            "adds",
            &shard,
            &make_vertex_key(9),
            &registry_prover_blob(1),
        )
        .unwrap();
    let mut prior = InMemoryProverRegistry::new();
    prior.refresh(store.as_ref()).unwrap();
    let prior_usage = prior.resource_usage();
    seed_active_filler(store.as_ref(), &shard, &[5; 32], 100, 1);
    let root = crate::global_intrinsic::materialize::create_leaf_root_vertex_tree(
        &[1; 32],
        &[5; 32],
        &[0],
        7,
        &[3; 74],
        12,
        100,
    )
    .unwrap();
    store
        .save_vertex_underlying(
            "vertex",
            "adds",
            &shard,
            &make_vertex_key(44),
            &vertex_tree_to_blob(&root),
        )
        .unwrap();
    store
        .save_vertex_underlying(
            "vertex",
            "removes",
            &shard,
            &make_vertex_key(90),
            b"removed",
        )
        .unwrap();
    let snapshot = store.capture_tree_snapshot().unwrap().unwrap();
    let mut complete = InMemoryProverRegistry::new();
    complete.refresh_from_snapshot(snapshot.as_ref()).unwrap();
    let usage = complete.resource_usage();
    assert_eq!(usage.vertices, 5);
    assert_eq!(complete.distinct_provers(), 2);
    assert_eq!(complete.leaf_root_count(), 1);
    assert_eq!(
        complete
            .get_prover_info(&[1; 32])
            .unwrap()
            .allocations
            .len(),
        1
    );
    let rows = snapshot
        .page_vertex_underlying_fixed(
            "vertex",
            "adds",
            &shard,
            &shard.l2,
            None,
            VertexPageLimits {
                max_entries: 100,
                max_bytes: 16 << 20,
            },
        )
        .unwrap();
    let max_record_bytes = rows
        .entries
        .iter()
        .map(|(_, blob)| 64 + blob.len())
        .max()
        .unwrap();
    let exact = RegistryLimits {
        max_vertices: usage.vertices,
        max_record_bytes,
        max_input_bytes: usage.input_bytes,
        max_cache_entries: usage.cache_entries,
        max_cache_bytes: usage.cache_bytes,
    };
    for which in 0..5 {
        let mut limited = exact;
        match which {
            0 => limited.max_vertices -= 1,
            1 => limited.max_record_bytes -= 1,
            2 => limited.max_input_bytes -= 1,
            3 => limited.max_cache_entries -= 1,
            _ => limited.max_cache_bytes -= 1,
        }
        assert!(
            prior
                .refresh_from_snapshot_with_limits(snapshot.as_ref(), limited)
                .is_err(),
            "limit {which}"
        );
        assert_eq!(prior.resource_usage(), prior_usage);
        assert_eq!(prior.distinct_provers(), 1);
        assert!(prior.get_prover_info(&[1; 32]).is_none());
    }
    prior
        .refresh_from_snapshot_with_limits(snapshot.as_ref(), exact)
        .unwrap();
    assert_eq!(prior.resource_usage(), usage);
    assert_eq!(prior.distinct_provers(), 2);
    assert_eq!(prior.leaf_root_count(), 1);
}

#[test]
fn bounded_registry_legacy_fallback_accounts_before_cloning_and_rejects_forged_lengths() {
    let (_tmp, store) = temp_store();
    let shard = ShardKey {
        l1: [0; 3],
        l2: [255; 32],
    };
    let mut tree = VectorCommitmentTree::new();
    tree.insert(
        &make_vertex_key(1),
        &registry_prover_blob(1),
        &[],
        &BigInt::from(0),
    )
    .unwrap();
    let blob = quil_tries::serialize_tree(tree.root.as_ref()).unwrap();
    let save = |bytes: &[u8]| {
        let txn = store.new_transaction(false).unwrap();
        store
            .save_root(txn.as_ref(), "vertex", "adds", &shard, bytes)
            .unwrap();
        txn.commit().unwrap();
    };
    save(&blob);
    let limits = RegistryLimits {
        max_vertices: 1,
        max_record_bytes: blob.len(),
        max_input_bytes: 1 << 20,
        max_cache_entries: 100,
        max_cache_bytes: 1 << 20,
    };
    let mut registry = InMemoryProverRegistry::new();
    registry
        .refresh_with_limits(store.as_ref(), limits)
        .unwrap();
    let usage = registry.resource_usage();
    assert_eq!(usage.vertices, 1);
    assert!(usage.input_bytes > blob.len());
    assert!(registry
        .refresh_with_limits(
            store.as_ref(),
            RegistryLimits {
                max_vertices: 0,
                ..limits
            }
        )
        .is_err());
    assert!(registry
        .refresh_with_limits(
            store.as_ref(),
            RegistryLimits {
                max_record_bytes: blob.len() - 1,
                ..limits
            }
        )
        .is_err());
    assert!(registry
        .refresh_with_limits(
            store.as_ref(),
            RegistryLimits {
                max_input_bytes: usage.input_bytes - 1,
                ..limits
            }
        )
        .is_err());
    // A short legacy leaf claiming a 16 MiB key must not allocate that amount.
    let forged = [vec![1], (1u64 << 24).to_be_bytes().to_vec()].concat();
    save(&forged);
    let error = registry
        .refresh_with_limits(store.as_ref(), limits)
        .unwrap_err()
        .to_string();
    assert!(error.contains("truncated tree field"), "{error}");
    assert_eq!(registry.resource_usage(), usage);
    assert!(registry.get_prover_info(&[1; 32]).is_some());
}

fn registry_overlay_limits() -> quil_forest::OverlayLimits {
    quil_forest::OverlayLimits {
        max_delta_bytes: 16 << 20,
        max_delta_entries: 100_000,
        max_record_bytes: 2 << 20,
        max_read_bytes: 128 << 20,
        max_read_operations: 2_000_000,
        max_cursors: 128,
    }
}

fn registry_prover_blob(status: u8) -> Vec<u8> {
    build_sub_tree(vec![
        type_hash_leaf("prover:Prover"),
        field_leaf("prover:Prover", "PublicKey", vec![0xcd; 57]),
        field_leaf("prover:Prover", "Status", vec![status]),
        field_leaf(
            "prover:Prover",
            "KickFrameNumber",
            0u64.to_be_bytes().to_vec(),
        ),
    ])
}

#[test]
fn registry_refresh_reads_a_stopped_store_without_copying_or_writing_it() {
    let dir = tempfile::tempdir().unwrap();
    let shard = ShardKey {
        l1: [0; 3],
        l2: [0xff; 32],
    };
    let sequence = {
        let db = quil_store::RocksDb::open(dir.path()).unwrap();
        let store = RocksHypergraphStore::new(db.inner());
        store
            .save_vertex_underlying(
                "vertex",
                "adds",
                &shard,
                &make_vertex_key(8),
                &registry_prover_blob(1),
            )
            .unwrap();
        db.inner().latest_sequence_number()
    };
    let db = quil_store::RocksDb::open_for_read_only(dir.path()).unwrap();
    let store = RocksHypergraphStore::new(db.inner());
    let shared = SharedProverRegistry::new();
    shared.refresh_from_store(&store).unwrap();
    assert_eq!(db.inner().latest_sequence_number(), sequence);
    assert!(shared.read(|r| r.get_prover_info(&[8; 32]).is_some()));
    drop(shared);
    drop(store);
    drop(db);
    let reopened = quil_store::RocksDb::open(dir.path()).unwrap();
    assert_eq!(reopened.inner().latest_sequence_number(), sequence);
}

#[test]
fn registry_overlay_refresh_uses_its_own_generation_and_tombstones() {
    let dir = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(dir.path()).unwrap();
    let canonical = RocksHypergraphStore::new(db.inner());
    let shard = ShardKey {
        l1: [0; 3],
        l2: [0xff; 32],
    };
    for n in [1, 2] {
        canonical
            .save_vertex_underlying(
                "vertex",
                "adds",
                &shard,
                &make_vertex_key(n),
                &registry_prover_blob(1),
            )
            .unwrap();
    }
    let canonical_registry = SharedProverRegistry::new();
    canonical_registry.refresh_from_store(&canonical).unwrap();
    let overlay = Arc::new(quil_forest::ExecutionOverlay::capture(
        db.inner(),
        registry_overlay_limits(),
    ).unwrap());
    let branch = quil_store::OverlayHypergraphStore::new(overlay.clone());
    let before = branch.capture_tree_snapshot().unwrap().unwrap();
    let sequence = db.inner().latest_sequence_number();
    let txn = branch.new_transaction(false).unwrap();
    branch
        .save_vertex_underlying_versioned(
            txn.as_ref(),
            "vertex",
            "adds",
            &shard,
            &make_vertex_key(1),
            &registry_prover_blob(2),
            7,
        )
        .unwrap();
    branch
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &shard,
            &make_vertex_key(3),
            &registry_prover_blob(1),
        )
        .unwrap();
    branch
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "removes",
            &shard,
            &make_vertex_key(2),
            b"removed",
        )
        .unwrap();
    txn.commit().unwrap();

    let branch_registry = SharedProverRegistry::new();
    branch_registry.refresh_from_store(&branch).unwrap();
    branch_registry.read(|r| {
        assert_eq!(r.distinct_provers(), 2);
        assert_eq!(
            r.get_prover_info(&[1; 32]).unwrap().status,
            ProverStatus::Paused
        );
        assert!(r.get_prover_info(&[2; 32]).is_none());
        assert!(r.get_prover_info(&[3; 32]).is_some());
    });
    let mut frozen = InMemoryProverRegistry::new();
    frozen.refresh_from_snapshot(before.as_ref()).unwrap();
    assert_eq!(
        frozen.get_prover_info(&[1; 32]).unwrap().status,
        ProverStatus::Active
    );
    assert!(frozen.get_prover_info(&[2; 32]).is_some());
    assert!(frozen.get_prover_info(&[3; 32]).is_none());
    assert_eq!(
        db.inner().latest_sequence_number(),
        sequence,
        "all branch writes stay isolated"
    );
    canonical_registry.read(|r| {
        assert_eq!(
            r.get_prover_info(&[1; 32]).unwrap().status,
            ProverStatus::Active
        );
        assert!(r.get_prover_info(&[2; 32]).is_some());
    });

    // A later primary write is invisible to both the branch and its old view.
    canonical
        .save_vertex_underlying(
            "vertex",
            "adds",
            &shard,
            &make_vertex_key(4),
            &registry_prover_blob(1),
        )
        .unwrap();
    branch_registry.refresh_from_store(&branch).unwrap();
    assert!(branch_registry.read(|r| r.get_prover_info(&[4; 32]).is_none()));
    overlay.close();
    assert!(branch_registry.refresh_from_store(&branch).is_err());
    assert!(
        branch_registry.read(|r| r.get_prover_info(&[3; 32]).is_some()),
        "failed refresh preserves cache"
    );
}

#[test]
fn registry_refresh_pages_one_snapshot_and_preserves_cache_after_late_failure() {
    let dir = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(dir.path()).unwrap();
    let store = RocksHypergraphStore::new(db.inner());
    let shard = ShardKey {
        l1: [0; 3],
        l2: [0xff; 32],
    };
    let address = |n: u16| {
        let mut a = [0; 32];
        a[..2].copy_from_slice(&n.to_be_bytes());
        a
    };
    let key = |n: u16| [shard.l2, address(n)].concat();
    let txn = store.new_transaction(false).unwrap();
    for n in 0..300 {
        <RocksHypergraphStore as HypergraphStore>::save_vertex_underlying(
            &store,
            txn.as_ref(),
            "vertex",
            "adds",
            &shard,
            &key(n),
            &registry_prover_blob(1),
        )
        .unwrap();
    }
    txn.commit().unwrap();
    let snapshot = store.capture_tree_snapshot().unwrap().unwrap();
    store
        .save_vertex_underlying("vertex", "removes", &shard, &key(270), b"removed")
        .unwrap();
    let mut old = InMemoryProverRegistry::new();
    old.refresh_from_snapshot(snapshot.as_ref()).unwrap();
    assert_eq!(
        old.distinct_provers(),
        300,
        "removals share the additions' captured generation"
    );
    assert!(old.get_prover_info(&address(270)).is_some());
    old.refresh(&store).unwrap();
    assert_eq!(old.distinct_provers(), 299);

    // Let a real overlay read the whole scan, then give a second one just too
    // few read operations. It must fail at the end, after its additions pages.
    let good = Arc::new(quil_forest::ExecutionOverlay::capture(
        db.inner(),
        registry_overlay_limits(),
    ).unwrap());
    let good_store = quil_store::OverlayHypergraphStore::new(good.clone());
    let shared = SharedProverRegistry::new();
    shared.refresh_from_store(&good_store).unwrap();
    let reads = good.stats().read_operations;
    assert!(reads > 300);
    store
        .save_vertex_underlying(
            "vertex",
            "adds",
            &shard,
            &key(400),
            &registry_prover_blob(1),
        )
        .unwrap();
    let limited = Arc::new(quil_forest::ExecutionOverlay::capture(
        db.inner(),
        quil_forest::OverlayLimits {
            max_read_operations: reads - 1,
            ..registry_overlay_limits()
        },
    ).unwrap());
    let limited_store = quil_store::OverlayHypergraphStore::new(limited.clone());
    assert!(shared.refresh_from_store(&limited_store).is_err());
    assert!(
        limited.stats().read_operations > 300,
        "failure follows multiple pages"
    );
    shared.read(|r| {
        assert_eq!(r.distinct_provers(), 299);
        assert!(r.get_prover_info(&address(400)).is_none());
        assert!(r.get_prover_info(&address(270)).is_none());
    });
    shared.refresh_from_store(&store).unwrap();
    assert_eq!(
        shared.read(|r| r.distinct_provers()),
        300,
        "retry publishes the complete new cache"
    );
}

#[test]
fn registry_refresh_requires_snapshot_admission_and_rejects_bad_legacy_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(dir.path()).unwrap();
    let store = RocksHypergraphStore::new(db.inner());
    let shard = ShardKey {
        l1: [0; 3],
        l2: [0xff; 32],
    };
    store
        .save_vertex_underlying(
            "vertex",
            "adds",
            &shard,
            &make_vertex_key(1),
            &registry_prover_blob(1),
        )
        .unwrap();
    let shared = SharedProverRegistry::new();
    shared.refresh_from_store(&store).unwrap();
    let denied =
        quil_store::OverlayHypergraphStore::new(Arc::new(quil_forest::ExecutionOverlay::capture(
            db.inner(),
            quil_forest::OverlayLimits {
                max_cursors: 0,
                ..registry_overlay_limits()
            },
        ).unwrap()));
    assert!(shared.refresh_from_store(&denied).is_err());
    assert_eq!(shared.read(|r| r.distinct_provers()), 1);

    let empty_dir = tempfile::tempdir().unwrap();
    let empty_db = quil_store::RocksDb::open(empty_dir.path()).unwrap();
    let empty = RocksHypergraphStore::new(empty_db.inner());
    let txn = empty.new_transaction(false).unwrap();
    empty
        .save_root(
            txn.as_ref(),
            "vertex",
            "adds",
            &shard,
            b"malformed legacy tree",
        )
        .unwrap();
    txn.commit().unwrap();
    assert!(shared.refresh_from_store(&empty).is_err());
    assert_eq!(
        shared.read(|r| r.distinct_provers()),
        1,
        "corrupt fallback cannot empty the registry"
    );

    let mut legacy = VectorCommitmentTree::new();
    legacy
        .insert(
            &make_vertex_key(9),
            &registry_prover_blob(1),
            &[],
            &BigInt::from(0),
        )
        .unwrap();
    let txn = empty.new_transaction(false).unwrap();
    empty
        .save_root(
            txn.as_ref(),
            "vertex",
            "adds",
            &shard,
            &quil_tries::serialize_tree(legacy.root.as_ref()).unwrap(),
        )
        .unwrap();
    txn.commit().unwrap();
    shared.refresh_from_store(&empty).unwrap();
    shared.read(|r| {
        assert_eq!(r.distinct_provers(), 1);
        assert!(
            r.get_prover_info(&[9; 32]).is_some(),
            "valid tree-only legacy state still refreshes"
        );
        assert!(r.get_prover_info(&[1; 32]).is_none());
    });
}

#[test]
fn registry_eviction_commits_only_to_its_overlay_with_versioned_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(dir.path()).unwrap();
    let store = RocksHypergraphStore::new(db.inner());
    let shard = ShardKey {
        l1: [0; 3],
        l2: [0xff; 32],
    };
    let filter = vec![0x33; 64];
    let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900;
    let target = 0x55;
    seed_active_filler(&store, &shard, &filter, frame, target);
    top_up_shard_quorum(&store, &shard, &filter, frame, 1, 0xe0);
    let base = quil_hypergraph::HypergraphCrdt::new(
        Arc::new(RocksHypergraphStore::new(db.inner())),
        Arc::new(quil_types::crypto::NoopInclusionProver),
    );
    base.set_forest(quil_forest::Forest::with_namespace(
        db.inner(),
        quil_store::FOREST_NAMESPACE,
    ));
    base.set_unified_tree(true);
    base.warm_sizes(&[]).unwrap();
    store
        .for_each_vertex_underlying("vertex", "adds", &shard, |key, blob| {
            let id: [u8; 64] = key.try_into().unwrap();
            base.add_vertex(&quil_hypergraph::addressing::Location::from_id(&id), &blob)
                .unwrap();
        })
        .unwrap();
    base.commit(0).unwrap();
    let canonical = SharedProverRegistry::new();
    canonical.refresh_from_store(&store).unwrap();
    assert!(canonical
        .find_eviction_candidates(frame, 500, &HashMap::new())
        .is_empty());

    let sequence = db.inner().latest_sequence_number();
    let overlay = Arc::new(quil_forest::ExecutionOverlay::capture(
        db.inner(),
        registry_overlay_limits(),
    ).unwrap());
    let branch = Arc::new(quil_store::OverlayHypergraphStore::new(overlay));
    let hg = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        branch.clone(),
        Arc::new(quil_types::crypto::NoopInclusionProver),
    ));
    hg.set_forest(branch.forest());
    hg.set_unified_tree(true);
    hg.warm_sizes(&[]).unwrap();
    // The tentative latest allocation is stale; its primary/legacy record is
    // fresh. An eviction fallback reading only legacy data would lose this.
    let alloc = build_sub_tree(vec![
        type_hash_leaf("allocation:ProverAllocation"),
        field_leaf("allocation:ProverAllocation", "Prover", vec![target; 32]),
        field_leaf("allocation:ProverAllocation", "Status", vec![1]),
        field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter),
        field_leaf(
            "allocation:ProverAllocation",
            "LastActiveFrameNumber",
            100u64.to_be_bytes().to_vec(),
        ),
        field_leaf(
            "allocation:ProverAllocation",
            "Epoch",
            quil_types::consensus::epoch_for_frame(frame)
                .to_be_bytes()
                .to_vec(),
        ),
    ]);
    hg.add_vertex(
        &quil_hypergraph::addressing::Location {
            app_address: shard.l2,
            data_address: [target ^ 0x80; 32],
        },
        &alloc,
    )
    .unwrap();
    hg.commit(1).unwrap();

    // Exercise the flat-store fallback with a CRDT that has no local vertices.
    // The fallback must read the branch's latest MVCC value, not legacy bytes.
    let missing = crate::hypergraph_state::HypergraphState::new(Arc::new(
        quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ),
    ));
    let fallback_registry = SharedProverRegistry::new();
    fallback_registry
        .refresh_from_store(branch.as_ref())
        .unwrap();
    assert_eq!(
        fallback_registry
            .evict_inactive_provers(frame, 500, &HashMap::new(), &missing, Some(branch.as_ref()))
            .unwrap(),
        vec![vec![target; 32]]
    );
    let data = missing
        .get(
            &crate::domains::GLOBAL,
            &[target ^ 0x80; 32],
            &crate::hypergraph_state::vertex_adds_discriminator().unwrap(),
        )
        .unwrap()
        .unwrap();
    let tree = rebuild_vertex_tree_from_blob(&data);
    assert_eq!(
        crate::global_schema::read_field(
            &tree,
            "allocation:ProverAllocation",
            "LastActiveFrameNumber"
        )
        .unwrap(),
        100u64.to_be_bytes()
    );
    let registry = SharedProverRegistry::new();
    registry.refresh_from_store(branch.as_ref()).unwrap();
    assert_eq!(
        registry.find_eviction_candidates(frame, 500, &HashMap::new()),
        vec![vec![target; 32]]
    );
    let state = crate::hypergraph_state::HypergraphState::new(hg.clone());
    let evicted = registry
        .evict_inactive_provers(frame, 500, &HashMap::new(), &state, Some(branch.as_ref()))
        .unwrap();
    assert_eq!(evicted, vec![vec![target; 32]]);
    state.commit().unwrap();
    hg.commit(frame).unwrap();
    registry.refresh_from_store(branch.as_ref()).unwrap();
    registry.read(|r| {
        let prover = r.get_prover_info(&[target; 32]).unwrap();
        // Terminal prover vertices are excluded by the legacy decoder; an
        // allocation still supplies an Unknown stub for diagnostics.
        assert_eq!(prover.status, ProverStatus::Unknown);
        assert_eq!(prover.allocations.len(), 1);
        // Preserve the existing wire encoding: the kick helper writes byte 4,
        // which the allocation decoder classifies as terminal Rejected.
        assert_eq!(prover.allocations[0].status, ProverStatus::Rejected);
        assert_eq!(prover.allocations[0].last_active_frame_number, 100);
    });
    let kicked = branch
        .load_vertex_underlying_raw("vertex", "adds", &shard, &make_vertex_key(target))
        .unwrap()
        .unwrap();
    let tree = rebuild_vertex_tree_from_blob(&kicked);
    assert_eq!(
        crate::global_schema::read_field(&tree, "prover:Prover", "Status").unwrap(),
        vec![4]
    );
    assert_eq!(
        crate::global_schema::read_field(&tree, "prover:Prover", "KickFrameNumber").unwrap(),
        frame.to_be_bytes()
    );
    assert!(registry
        .find_eviction_candidates(frame, 500, &HashMap::new())
        .is_empty());
    assert_eq!(db.inner().latest_sequence_number(), sequence);
    canonical.refresh_from_store(&store).unwrap();
    canonical.read(|r| {
        let prover = r.get_prover_info(&[target; 32]).unwrap();
        assert_eq!(prover.status, ProverStatus::Active);
        assert_eq!(prover.allocations[0].last_active_frame_number, frame);
    });
}

/// A registry may seed a branch only while no write reached the prover rows
/// since its scan, and only when a bounded refresh of those rows would
/// succeed: the predicate must agree with an actual refresh on every limit.
#[test]
fn registry_seed_needs_an_unchanged_scan_and_limits_a_refresh_would_accept() {
    let dir = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(dir.path()).unwrap();
    let store = RocksHypergraphStore::new(db.inner());
    let capture = || {
        quil_forest::ExecutionOverlay::capture(db.inner(), registry_overlay_limits())
            .unwrap()
            .capture_point()
            .unwrap()
    };
    let mut empty = InMemoryProverRegistry::new();
    empty.refresh(&store).unwrap();
    assert!(
        !empty.reproduces(&capture(), RegistryLimits::UNBOUNDED),
        "an empty read may have come from the unwatched legacy tree fallback"
    );

    let shard = quil_store::encoding::prover_registry_shard();
    for (n, status) in [(1, 1), (2, 1)] {
        store
            .save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(n), &registry_prover_blob(status))
            .unwrap();
    }
    store
        .save_vertex_underlying("vertex", "removes", &shard, &make_vertex_key(2), b"removed")
        .unwrap();
    let mut registry = InMemoryProverRegistry::new();
    registry.refresh(&store).unwrap();
    let usage = registry.resource_usage();
    let exact = RegistryLimits {
        max_vertices: usage.vertices,
        max_record_bytes: registry.largest_row,
        max_input_bytes: usage.input_bytes,
        max_cache_entries: usage.cache_entries,
        max_cache_bytes: usage.cache_bytes,
    };
    let refreshes = |limits: RegistryLimits| {
        let snapshot = store.capture_tree_snapshot().unwrap().unwrap();
        InMemoryProverRegistry::new()
            .refresh_from_snapshot_with_limits(snapshot.as_ref(), limits)
            .is_ok()
    };
    assert!(registry.reproduces(&capture(), exact) && refreshes(exact));
    for which in 0..5 {
        let mut limited = exact;
        match which {
            0 => limited.max_vertices -= 1,
            1 => limited.max_record_bytes -= 1,
            2 => limited.max_input_bytes -= 1,
            3 => limited.max_cache_entries -= 1,
            _ => limited.max_cache_bytes -= 1,
        }
        assert!(!registry.reproduces(&capture(), limited), "limit {which}");
        assert!(!refreshes(limited), "limit {which}");
    }

    // Writes elsewhere leave the scan current; any prover-row write does not,
    // including a removal and a range deletion that only overlaps the rows.
    db.inner().put(b"unrelated", b"value").unwrap();
    assert!(registry.reproduces(&capture(), exact));
    let point = capture();
    store
        .save_vertex_underlying("vertex", "removes", &shard, &make_vertex_key(1), b"removed")
        .unwrap();
    assert!(!registry.reproduces(&capture(), exact));
    assert!(registry.reproduces(&point, exact), "a view captured before the write still matches");
    registry.refresh(&store).unwrap();
    assert!(registry.reproduces(&capture(), RegistryLimits::UNBOUNDED));
    let mut range = rocksdb::WriteBatch::default();
    range.delete_range(&[0u8][..], &quil_store::encoding::prover_registry_key_prefixes()[0][..]);
    db.inner().write(range).unwrap();
    assert!(registry.reproduces(&capture(), RegistryLimits::UNBOUNDED), "a range ending at the rows");
    let mut range = rocksdb::WriteBatch::default();
    let mut end = quil_store::encoding::prover_registry_key_prefixes()[0].clone();
    end.push(0);
    range.delete_range(&[0u8][..], &end[..]);
    db.inner().write(range).unwrap();
    assert!(!registry.reproduces(&capture(), RegistryLimits::UNBOUNDED), "a range reaching them");

    // Only a branch's registry reads go through its overlay here: a copy
    // reads nothing, and a seed being refreshed is skipped, not waited for.
    let seed = SharedProverRegistry::new();
    seed.refresh_from_store(&store).unwrap();
    let expected = seed.read(|r| (r.distinct_provers(), r.resource_usage()));
    let branch_reads = |busy: bool| {
        let overlay = Arc::new(
            quil_forest::ExecutionOverlay::capture(db.inner(), registry_overlay_limits()).unwrap(),
        );
        let branch = quil_store::OverlayHypergraphStore::new(overlay.clone());
        let _refreshing = busy.then(|| seed.inner.write().unwrap());
        let registry = SharedProverRegistry::for_execution_capture(
            &branch,
            RegistryLimits::UNBOUNDED,
            Some(&seed),
            overlay.capture_point(),
        )
        .unwrap();
        assert_eq!(registry.read(|r| (r.distinct_provers(), r.resource_usage())), expected);
        overlay.stats().read_operations
    };
    assert_eq!(branch_reads(false), 0);
    assert!(branch_reads(true) > 0);

    // A store that watches nothing never yields a capture point.
    let plain_dir = tempfile::tempdir().unwrap();
    let plain = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(plain_dir.path()).unwrap());
    let overlay = quil_forest::ExecutionOverlay::capture(plain, registry_overlay_limits()).unwrap();
    assert!(overlay.capture_point().is_none());
}
