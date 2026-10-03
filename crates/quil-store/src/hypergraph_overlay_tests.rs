use super::*;
use quil_forest::{ExecutionOverlay, OverlayLimits};
use quil_types::store::{HypergraphStore, VertexPageLimits};
use std::collections::BTreeMap;

fn limits() -> OverlayLimits {
    OverlayLimits {
        max_delta_bytes: 16 << 20,
        max_delta_entries: 100_000,
        max_record_bytes: 2 << 20,
        max_read_bytes: 128 << 20,
        max_read_operations: 2_000_000,
        max_cursors: 128,
    }
}

#[test]
fn shard_reset_clears_all_flat_versions_atomically_only_in_its_overlay() {
    let directory = tempfile::tempdir().unwrap();
    let db = open(directory.path());
    let primary = RocksHypergraphStore::new(db.clone());
    let target = shard();
    let neighbor = ShardKey { l2: [8; 32], ..target.clone() };
    let phases = [("vertex", "adds"), ("vertex", "removes"),
        ("hyperedge", "adds"), ("hyperedge", "removes")];
    let txn = primary.new_transaction(false).unwrap();
    for (set, phase) in phases {
        for shard in [&target, &neighbor] {
            let key = [shard.l2, [1; 32]].concat();
            HypergraphStore::save_vertex_underlying(&primary, txn.as_ref(), set, phase, shard, &key, b"legacy").unwrap();
            for version in 0..=2 {
                primary.save_vertex_underlying_versioned(txn.as_ref(), set, phase, shard, &key, &[version as u8], version).unwrap();
            }
        }
    }
    txn.commit().unwrap();
    let before = rows(&db);
    let sequence = db.latest_sequence_number();
    for budget in [OverlayLimits { max_delta_entries: 1, ..limits() }, limits()] {
        let overlay = Arc::new(ExecutionOverlay::capture(db.clone(), budget).unwrap());
        let store = OverlayHypergraphStore::new(overlay.clone());
        let cleared = store.clear_shard_underlying(&target).is_ok();
        assert_eq!(cleared, budget.max_delta_entries > 1);
        if !cleared {
            assert_eq!(overlay.stats().delta_entries, 0, "a failed transaction publishes no phase deletions");
        }
        for (set, phase) in phases {
            for shard in [&target, &neighbor] {
                let key = [shard.l2, [1; 32]].concat();
                let removed = cleared && shard == &target;
                assert_eq!(store.load_vertex_underlying(set, phase, shard, &key).unwrap(),
                    (!removed).then(|| b"legacy".to_vec()));
                for version in 0..=2 {
                    assert_eq!(store.load_vertex_underlying_at(set, phase, shard, &key, version).unwrap(),
                        (!removed).then(|| vec![version as u8]));
                }
            }
        }
        overlay.close();
        assert_eq!(db.latest_sequence_number(), sequence);
        assert_eq!(rows(&db), before);
    }
}
fn open(path: &std::path::Path) -> quil_forest::CoordinatedDb {
    quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(path).unwrap())
}
fn shard() -> ShardKey {
    let l2 = [7; 32];
    ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(&l2, 256, 3),
        l2,
    }
}
fn vertex(n: u8) -> Vec<u8> {
    [[7; 32], [n; 32]].concat()
}
fn rows(db: &quil_forest::CoordinatedDb) -> Vec<(Box<[u8]>, Box<[u8]>)> {
    db.iterator(rocksdb::IteratorMode::Start)
        .collect::<std::result::Result<_, _>>()
        .unwrap()
}
fn seed(store: &dyn HypergraphStore) {
    let txn = store.new_transaction(false).unwrap();
    let sk = shard();
    store
        .save_root(txn.as_ref(), "vertex", "adds", &sk, b"legacy tree")
        .unwrap();
    store
        .insert_node(
            txn.as_ref(),
            "vertex",
            "adds",
            &sk,
            b"node-key",
            &[1, 2, 3],
            b"node-data",
        )
        .unwrap();
    for n in 1..=3 {
        store
            .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &sk, &vertex(n), b"legacy")
            .unwrap();
    }
    for version in 0..=3 {
        for n in 1..=2 {
            store
                .save_vertex_underlying_versioned(
                    txn.as_ref(),
                    "vertex",
                    "adds",
                    &sk,
                    &vertex(n),
                    &[n, version as u8],
                    version,
                )
                .unwrap();
        }
        store
            .put_root_version(
                txn.as_ref(),
                "vertex",
                "adds",
                &sk.l2,
                &[version as u8; 32],
                version,
                10 + version * 10,
            )
            .unwrap();
        store
            .put_app_manifest(
                txn.as_ref(),
                "vertex",
                "adds",
                &sk.l2,
                &[version as u8; 32],
                &[(vec![0], [version as u8; 32], version)],
                10 + version * 10,
            )
            .unwrap();
        store
            .track_change(
                txn.as_ref(),
                b"changed",
                Some(&[version as u8]),
                version,
                "adds",
                "vertex",
                &sk,
            )
            .unwrap();
    }
    let (mut legacy_root, _) = crate::encoding::hypergraph_tree_roots_iter_bounds();
    legacy_root.extend_from_slice(&sk.l1);
    legacy_root.extend_from_slice(&sk.l2);
    txn.set(&legacy_root, b"root index").unwrap();
    store
        .set_alt_shard_commit(
            txn.as_ref(),
            1,
            &sk.l2,
            &[1; 64],
            &[2; 64],
            &[3; 64],
            &[4; 64],
        )
        .unwrap();
    store
        .set_shard_commit(txn.as_ref(), 1, "adds", "vertex", &sk.l2, &[1; 32])
        .unwrap();
    txn.set(b"checkpoint", b"base").unwrap();
    txn.commit().unwrap();
}

fn update(store: &dyn HypergraphStore) {
    let sk = shard();
    let txn = store.new_transaction(false).unwrap();
    store
        .save_vertex_underlying_versioned(
            txn.as_ref(),
            "vertex",
            "adds",
            &sk,
            &vertex(1),
            b"branch",
            4,
        )
        .unwrap();
    store
        .delete_node(txn.as_ref(), "vertex", "adds", &sk, b"node-key", &[1, 2, 3])
        .unwrap();
    store
        .insert_node(
            txn.as_ref(),
            "vertex",
            "adds",
            &sk,
            b"new-node",
            &[1, 2, 4],
            b"new-data",
        )
        .unwrap();
    store
        .set_alt_shard_commit(
            txn.as_ref(),
            2,
            &sk.l2,
            &[5; 64],
            &[6; 64],
            &[7; 64],
            &[8; 64],
        )
        .unwrap();
    txn.set(b"checkpoint", b"branch").unwrap();
    txn.commit().unwrap();
}

#[test]
fn tentative_store_matches_durable_encodings_and_retains_snapshot_generation() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let base_db = open(a.path());
    let reference_db = open(b.path());
    let base = RocksHypergraphStore::new(base_db.clone());
    let reference = RocksHypergraphStore::new(reference_db.clone());
    seed(&base);
    seed(&reference);
    let before = rows(&base_db);
    let overlay = Arc::new(ExecutionOverlay::capture(base_db.clone(), limits()).unwrap());
    let branch = OverlayHypergraphStore::new(overlay.clone());
    let old = branch.capture_tree_snapshot().unwrap().unwrap();
    update(&branch);
    update(&reference);
    let sk = shard();
    for (key, value) in rows(&reference_db) {
        assert_eq!(
            overlay.get(&key).unwrap().as_deref(),
            Some(value.as_ref()),
            "key {}",
            hex::encode(key)
        );
    }
    // Keys deleted from the reference are absent from the branch as well.
    for (key, _) in &before {
        assert_eq!(overlay.get(key).unwrap(), reference_db.get(key).unwrap());
    }
    assert_eq!(rows(&base_db), before);
    assert_eq!(
        branch
            .get_node_by_path("vertex", "adds", &sk, &[1, 2])
            .unwrap(),
        Some(b"new-data".to_vec())
    );
    assert_eq!(
        old.get_node_by_path("vertex", "adds", &sk, &[1, 2])
            .unwrap(),
        Some(b"node-data".to_vec())
    );
    assert_eq!(
        old.read_record(b"checkpoint").unwrap(),
        Some(b"base".to_vec())
    );
    assert_eq!(
        old.load_vertex_underlying_raw("vertex", "adds", &sk, &vertex(1))
            .unwrap(),
        Some(vec![1, 3])
    );
    assert_eq!(
        branch
            .load_vertex_underlying_at("vertex", "adds", &sk, &vertex(1), 1)
            .unwrap(),
        Some(vec![1, 1])
    );
    assert_eq!(
        branch
            .load_vertex_underlying_raw("vertex", "adds", &sk, &vertex(1))
            .unwrap(),
        Some(b"branch".to_vec())
    );
    assert_eq!(
        branch.get_latest_alt_shard_commit(&sk.l2).unwrap(),
        reference.get_latest_alt_shard_commit(&sk.l2).unwrap()
    );
    assert_eq!(
        branch.range_alt_shard_addresses().unwrap(),
        reference.range_alt_shard_addresses().unwrap()
    );
    assert_eq!(
        branch.get_root_commits(1).unwrap(),
        reference.get_root_commits(1).unwrap()
    );
    assert_eq!(
        branch
            .get_app_manifest("vertex", "adds", &sk.l2, &[1; 32])
            .unwrap(),
        reference
            .get_app_manifest("vertex", "adds", &sk.l2, &[1; 32])
            .unwrap()
    );
    let mut actual = Vec::new();
    branch
        .for_each_vertex_underlying("vertex", "adds", &sk, &mut |k, v| actual.push((k, v)))
        .unwrap();
    actual.sort();
    assert_eq!(
        actual,
        vec![
            (vertex(1), b"branch".to_vec()),
            (vertex(2), vec![2, 3]),
            (vertex(3), b"legacy".to_vec())
        ]
    );
    // Paging and point lookups on a retained view see the same generation.
    let page = old
        .page_vertex_underlying_fixed(
            "vertex",
            "adds",
            &sk,
            &[7; 32],
            None,
            VertexPageLimits {
                max_entries: 2,
                max_bytes: 4096,
            },
        )
        .unwrap();
    assert!(page.has_more);
    assert_eq!(
        page.entries,
        vec![([1; 32], vec![1, 3]), ([2; 32], vec![2, 3])]
    );
    let last = old
        .page_vertex_underlying_fixed(
            "vertex",
            "adds",
            &sk,
            &[7; 32],
            Some(&[2; 32]),
            VertexPageLimits {
                max_entries: 2,
                max_bytes: 4096,
            },
        )
        .unwrap();
    assert_eq!(last.entries, vec![([3; 32], b"legacy".to_vec())]);
    assert!(!last.has_more);
    overlay.close();
    assert!(old.read_record(b"checkpoint").is_err());
    assert_eq!(rows(&base_db), before);
}

#[test]
fn tentative_pruning_and_changeset_ranges_match_durable_maintenance() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let db = open(a.path());
    let reference_db = open(b.path());
    let base = RocksHypergraphStore::new(db.clone());
    let reference = RocksHypergraphStore::new(reference_db.clone());
    seed(&base);
    seed(&reference);
    let before = rows(&db);
    let overlay = Arc::new(ExecutionOverlay::capture(db.clone(), limits()).unwrap());
    let branch = OverlayHypergraphStore::new(overlay.clone());
    let mut actual = branch.prune_versioned(30).unwrap();
    let mut expected = reference.prune_versioned(30).unwrap();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
    for store in [
        &branch as &dyn HypergraphStore,
        &reference as &dyn HypergraphStore,
    ] {
        let txn = store.new_transaction(false).unwrap();
        store.reap_old_changesets(txn.as_ref(), 3).unwrap();
        txn.commit().unwrap();
        store.delete_shard_commits(1, &shard().l2).unwrap();
        let changes = store.get_changes(0, 4, "adds", "vertex", &shard()).unwrap();
        assert_eq!(changes.iter().map(|c| c.frame).collect::<Vec<_>>(), vec![3]);
    }
    for (key, _) in &before {
        assert_eq!(overlay.get(key).unwrap(), reference_db.get(key).unwrap());
    }
    for (key, value) in rows(&reference_db) {
        assert_eq!(overlay.get(&key).unwrap().as_deref(), Some(value.as_ref()));
    }
    assert_eq!(rows(&db), before);
}

#[test]
fn tentative_transactions_reject_foreign_branches_abort_and_poison_failed_batches() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let first = Arc::new(ExecutionOverlay::capture(db.clone(), limits()).unwrap());
    let second = Arc::new(ExecutionOverlay::capture(db.clone(), limits()).unwrap());
    let a = OverlayHypergraphStore::new(first.clone());
    let b = OverlayHypergraphStore::new(second);
    let txn = a.new_transaction(false).unwrap();
    assert!(b
        .save_root(txn.as_ref(), "vertex", "adds", &shard(), b"foreign")
        .is_err());
    assert!(b.reap_old_changesets(txn.as_ref(), 1).is_err());
    let durable = RocksHypergraphStore::new(db.clone());
    assert!(durable
        .save_root(txn.as_ref(), "vertex", "adds", &shard(), b"foreign")
        .is_err());
    txn.set(b"aborted", b"value").unwrap();
    assert_eq!(
        txn.get(b"aborted").unwrap(),
        None,
        "same unindexed read semantics as RocksTxn"
    );
    txn.abort().unwrap();
    assert_eq!(first.get(b"aborted").unwrap(), None);
    let small = Arc::new(ExecutionOverlay::capture(
        db.clone(),
        OverlayLimits {
            max_delta_entries: 1,
            ..limits()
        },
    ).unwrap());
    let store = OverlayHypergraphStore::new(small.clone());
    let txn = store.new_transaction(false).unwrap();
    txn.set(b"first", b"accepted").unwrap();
    assert!(txn.set(b"second", b"too many").is_err());
    assert!(txn.commit().is_err());
    assert_eq!(small.get(b"first").unwrap(), None);
    // The shared codec uses WriteBatch-style void puts: failure still poisons
    // the transaction and prevents the first index entry from committing.
    let txn = store.new_transaction(false).unwrap();
    store
        .insert_node(
            txn.as_ref(),
            "vertex",
            "adds",
            &shard(),
            b"key",
            &[1],
            b"data",
        )
        .unwrap();
    assert!(txn.commit().is_err());
    assert_eq!(small.stats().delta_entries, 0);
    assert!(rows(&db).is_empty());
}

#[test]
fn tentative_budget_failures_are_errors_not_absent_records_or_empty_pages() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    seed(&RocksHypergraphStore::new(db.clone()));
    let overlay = Arc::new(ExecutionOverlay::capture(
        db.clone(),
        OverlayLimits {
            max_read_operations: 0,
            ..limits()
        },
    ).unwrap());
    let branch = OverlayHypergraphStore::new(overlay);
    assert!(branch
        .get_node_by_path("vertex", "adds", &shard(), &[])
        .is_err());
    assert!(branch
        .load_vertex_underlying_raw("vertex", "adds", &shard(), &vertex(1))
        .is_err());
    let txn = branch.new_transaction(false).unwrap();
    assert!(branch
        .set_alt_shard_commit(
            txn.as_ref(),
            2,
            &shard().l2,
            &[0; 64],
            &[0; 64],
            &[0; 64],
            &[0; 64]
        )
        .is_err());
    assert!(branch.get_root_commits(1).is_err());
    assert!(branch
        .page_vertex_underlying_fixed(
            "vertex",
            "adds",
            &shard(),
            &[7; 32],
            None,
            VertexPageLimits {
                max_entries: 1,
                max_bytes: 4096
            }
        )
        .is_err());
    let snapshot = branch.capture_tree_snapshot().unwrap().unwrap();
    assert!(snapshot
        .get_node_by_path("vertex", "adds", &shard(), &[])
        .is_err());
    assert!(snapshot
        .load_vertex_underlying_raw("vertex", "adds", &shard(), &vertex(1))
        .is_err());
    let denied = OverlayHypergraphStore::new(Arc::new(ExecutionOverlay::capture(
        db,
        OverlayLimits {
            max_cursors: 0,
            ..limits()
        },
    ).unwrap()));
    assert!(denied.capture_tree_snapshot().is_err());
    assert!(denied
        .page_vertex_underlying_fixed(
            "vertex",
            "adds",
            &shard(),
            &[7; 32],
            None,
            VertexPageLimits {
                max_entries: 1,
                max_bytes: 4096
            }
        )
        .is_err());
}

#[test]
fn malformed_manifest_count_is_rejected_by_both_backends_before_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let key = crate::encoding::hypergraph_app_manifest_key("vertex", "adds", &shard().l2, &[1; 32]);
    db.put(
        &key,
        [
            1u64.to_be_bytes().as_slice(),
            u32::MAX.to_be_bytes().as_slice(),
        ]
        .concat(),
    )
    .unwrap();
    let overlay = Arc::new(ExecutionOverlay::capture(db.clone(), limits()).unwrap());
    let branch = OverlayHypergraphStore::new(overlay);
    let durable = RocksHypergraphStore::new(db);
    assert!(branch
        .get_app_manifest("vertex", "adds", &shard().l2, &[1; 32])
        .is_err());
    assert!(durable
        .get_app_manifest("vertex", "adds", &shard().l2, &[1; 32])
        .is_err());
}

#[test]
fn real_crdt_commits_forest_blobs_history_and_cursor_only_to_the_branch() {
    use quil_hypergraph::{HypergraphCrdt, Location};
    for unified in [false, true] {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let db = open(a.path());
        let reference_db = open(b.path());
        let app = shard().l2;
        let filter = [app.as_slice(), &[0]].concat();
        let cursor = crate::encoding::consensus_materialized_cursor_key(&filter);
        let history = crate::encoding::clock_shard_frame_fee_total_key(&filter, 2);
        let make = |store: Arc<dyn HypergraphStore>, forest| {
            let crdt =
                HypergraphCrdt::new(store, Arc::new(quil_types::crypto::NoopInclusionProver));
            crdt.set_forest(forest);
            crdt.set_app_shard_prefixes(app, (0..64).map(|n| vec![n]).collect());
            crdt.set_unified_tree(unified);
            crdt
        };
        let original = make(
            Arc::new(RocksHypergraphStore::new(db.clone())),
            quil_forest::Forest::with_namespace(db.clone(), FOREST_NAMESPACE),
        );
        let reference = make(
            Arc::new(RocksHypergraphStore::new(reference_db.clone())),
            quil_forest::Forest::with_namespace(reference_db.clone(), FOREST_NAMESPACE),
        );
        let one = Location {
            app_address: app,
            data_address: [1; 32],
        };
        let two = Location {
            app_address: app,
            data_address: [2; 32],
        };
        for crdt in [&original, &reference] {
            crdt.add_vertex(&one, b"first").unwrap();
            crdt.commit_with_frame_cursor(1, &cursor).unwrap();
        }
        let before = rows(&db);
        let overlay = Arc::new(ExecutionOverlay::capture(db.clone(), limits()).unwrap());
        let store = Arc::new(OverlayHypergraphStore::new(overlay.clone()));
        let branch = make(store.clone(), store.forest());
        // Rehydrate the persisted size accounting, as on a node restart.
        branch.warm_sizes(&[app]).unwrap();
        let snapshot = branch.capture_committed_shard(&filter).unwrap();
        for crdt in [&branch, &reference] {
            crdt.add_vertex(&two, b"second").unwrap();
            crdt.commit_with_frame_cursor_and_records(
                2,
                &cursor,
                &[(history.clone(), 23u128.to_be_bytes().to_vec())],
            )
            .unwrap();
        }
        let checkpoint = branch.capture_committed_shard(&filter).unwrap();
        assert_eq!(
            checkpoint.roots,
            reference.capture_committed_shard(&filter).unwrap().roots
        );
        assert_ne!(checkpoint.roots, snapshot.roots);
        assert_eq!(
            checkpoint.records.read_record(&cursor).unwrap(),
            Some(2u64.to_be_bytes().to_vec())
        );
        assert_eq!(
            snapshot.records.read_record(&cursor).unwrap(),
            Some(1u64.to_be_bytes().to_vec())
        );
        assert_eq!(snapshot.records.read_record(&history).unwrap(), None);
        assert_eq!(
            checkpoint.records.read_record(&history).unwrap(),
            Some(23u128.to_be_bytes().to_vec())
        );
        assert!(checkpoint
            .records
            .load_vertex_underlying_raw("vertex", "adds", &shard(), &vertex(2))
            .unwrap()
            .is_some());
        for (key, value) in rows(&reference_db) {
            assert_eq!(
                overlay.get(&key).unwrap().as_deref(),
                Some(value.as_ref()),
                "key {}",
                hex::encode(key)
            );
        }
        assert_eq!(rows(&db), before);
        overlay.close();
        assert!(checkpoint.records.read_record(&cursor).is_err());
        assert_eq!(rows(&db), before);
    }
}

#[test]
fn failed_size_initialization_remains_uninitialized_on_retry() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let overlay = Arc::new(ExecutionOverlay::capture(
        db,
        OverlayLimits {
            max_read_operations: 0,
            ..limits()
        },
    ).unwrap());
    let store = Arc::new(OverlayHypergraphStore::new(overlay));
    let crdt = quil_hypergraph::HypergraphCrdt::new(
        store.clone(),
        Arc::new(quil_types::crypto::NoopInclusionProver),
    );
    crdt.set_forest(store.forest());
    for _ in 0..2 {
        assert!(
            crdt.warm_sizes(&[shard().l2]).is_err(),
            "a failed read must not mark size accounting as initialized"
        );
    }
}

#[test]
fn durable_hypergraph_rejects_transactions_from_a_different_database() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let a = RocksHypergraphStore::new(open(a.path()));
    let b = RocksHypergraphStore::new(open(b.path()));
    let txn = a.new_transaction(false).unwrap();
    assert!(b
        .save_root(txn.as_ref(), "vertex", "adds", &shard(), b"wrong store")
        .is_err());
    assert!(b
        .save_tree_blob_txn(txn.as_ref(), "vertex", "adds", &shard(), b"wrong store")
        .is_err());
    txn.commit().unwrap();
    assert!(a
        .load_tree_blob("vertex", "adds", &shard())
        .unwrap()
        .is_none());
    assert!(b
        .load_tree_blob("vertex", "adds", &shard())
        .unwrap()
        .is_none());
}

#[test]
fn tentative_topology_and_maintenance_marker_share_the_hypergraph_batch() {
    use crate::{OverlayShardsStore, RocksShardsStore, ShardMetadataBatch};
    use quil_types::store::{PendingShardChange, ShardChangeKind, ShardInfo, ShardsStore};
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let db = open(a.path());
    let reference_db = open(b.path());
    let base = RocksHypergraphStore::new(db.clone());
    let reference = RocksHypergraphStore::new(reference_db.clone());
    let base_shards = RocksShardsStore::new(db.clone());
    let reference_shards = Arc::new(RocksShardsStore::new(reference_db.clone()));
    let shard_key = [shard().l1.as_slice(), shard().l2.as_slice()].concat();
    let old = ShardInfo {
        shard_key: shard_key.clone(),
        prefix: vec![0],
        size: Vec::new(),
        data_shards: 0,
        commitment: Vec::new(),
    };
    for (store, metadata) in [
        (&base, &base_shards),
        (&reference, reference_shards.as_ref()),
    ] {
        let txn = store.new_transaction(false).unwrap();
        metadata.put_app_shard(txn.as_ref(), &old).unwrap();
        txn.commit().unwrap();
    }
    let before = rows(&db);
    let overlay = Arc::new(ExecutionOverlay::capture(db.clone(), limits()).unwrap());
    let branch = OverlayHypergraphStore::new(overlay.clone());
    let branch_shards = Arc::new(OverlayShardsStore::new(overlay.clone()));
    let next = ShardInfo {
        prefix: vec![0xffff_ffff, 0x8000_0000],
        ..old.clone()
    };
    let pending = PendingShardChange {
        kind: ShardChangeKind::Split,
        parent: vec![1; 32],
        children: vec![vec![2; 32], vec![3; 32]],
        effective_epoch: 3,
        proposed_frame: 45,
    };
    for (store, metadata) in [
        (
            &branch as &dyn HypergraphStore,
            branch_shards.clone() as Arc<dyn ShardsStore>,
        ),
        (
            &reference as &dyn HypergraphStore,
            reference_shards.clone() as Arc<dyn ShardsStore>,
        ),
    ] {
        let staged = ShardMetadataBatch::new(metadata.clone(), BTreeMap::new());
        metadata
            .delete_app_shard(&staged, &shard_key, &[0])
            .unwrap();
        metadata.put_app_shard(&staged, &next).unwrap();
        metadata
            .put_pending_shard_change(&staged, &pending)
            .unwrap();
        assert_eq!(staged.range_app_shards().unwrap()[0].prefix, next.prefix);
        assert_eq!(metadata.range_app_shards().unwrap()[0].prefix, old.prefix);
        let txn = store.new_transaction(false).unwrap();
        for record in staged.into_records() {
            match record.value {
                Some(value) => txn.set(&record.key, &value).unwrap(),
                None => txn.delete(&record.key).unwrap(),
            }
        }
        txn.set(b"maintenance/cursor", &46u64.to_be_bytes())
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(
            metadata.get_app_shards(&shard_key, &[]).unwrap()[0].prefix,
            next.prefix
        );
        assert_eq!(
            metadata.get_pending_shard_changes(3).unwrap(),
            vec![pending.clone()]
        );
        assert!(metadata.get_pending_shard_changes(2).unwrap().is_empty());
        assert_eq!(
            metadata.all_pending_shard_changes().unwrap(),
            vec![pending.clone()]
        );
    }
    for (key, _) in &before {
        assert_eq!(overlay.get(key).unwrap(), reference_db.get(key).unwrap());
    }
    for (key, value) in rows(&reference_db) {
        assert_eq!(overlay.get(&key).unwrap().as_deref(), Some(value.as_ref()));
    }
    assert_eq!(rows(&db), before);
    let txn = base.new_transaction(false).unwrap();
    assert!(branch_shards.put_app_shard(txn.as_ref(), &next).is_err());
    txn.abort().unwrap();
    let limited = OverlayShardsStore::new(Arc::new(ExecutionOverlay::capture(
        db,
        OverlayLimits {
            max_read_operations: 0,
            ..limits()
        },
    ).unwrap()));
    assert!(limited.range_app_shards().is_err());
    assert!(limited.all_pending_shard_changes().is_err());
}

#[test]
fn pending_change_epoch_ranges_include_zero_and_u64_max_on_both_backends() {
    use crate::{OverlayShardsStore, RocksShardsStore};
    use quil_types::store::{PendingShardChange, ShardChangeKind, ShardsStore};
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let overlay = Arc::new(ExecutionOverlay::capture(db.clone(), limits()).unwrap());
    let branch = OverlayHypergraphStore::new(overlay.clone());
    let branch_shards = OverlayShardsStore::new(overlay);
    let durable = RocksHypergraphStore::new(db.clone());
    let durable_shards = RocksShardsStore::new(db);
    for (store, metadata) in [
        (
            &durable as &dyn HypergraphStore,
            &durable_shards as &dyn ShardsStore,
        ),
        (
            &branch as &dyn HypergraphStore,
            &branch_shards as &dyn ShardsStore,
        ),
    ] {
        let changes: Vec<_> = [0, 1, u64::MAX]
            .into_iter()
            .map(|epoch| PendingShardChange {
                kind: ShardChangeKind::Split,
                parent: vec![1; 32],
                children: vec![vec![2; 32], vec![3; 32]],
                effective_epoch: epoch,
                proposed_frame: 0,
            })
            .collect();
        let txn = store.new_transaction(false).unwrap();
        for change in &changes {
            metadata
                .put_pending_shard_change(txn.as_ref(), change)
                .unwrap();
        }
        txn.commit().unwrap();
        for change in &changes {
            assert_eq!(
                metadata
                    .get_pending_shard_changes(change.effective_epoch)
                    .unwrap(),
                vec![change.clone()]
            );
        }
        assert!(metadata.get_pending_shard_changes(2).unwrap().is_empty());
        assert_eq!(metadata.all_pending_shard_changes().unwrap(), changes);
    }
}
