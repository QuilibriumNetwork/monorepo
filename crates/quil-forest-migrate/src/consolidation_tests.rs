use super::*;
use quil_forest::{ExecutionOverlay, OverlayLimits};
use quil_store::{
    OverlayHypergraphStore, OverlayShardsStore, RocksDb, RocksHypergraphStore, RocksShardsStore,
};
use quil_types::store::ShardInfo;
use std::sync::Arc;

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

fn blob(value: &[u8]) -> Vec<u8> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(
        &[0xff; 32],
        value,
        &[],
        &num_bigint::BigInt::from(value.len()),
    )
    .unwrap();
    quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()
}

struct Fixture {
    db: RocksDb,
    store: RocksHypergraphStore,
    shards: RocksShardsStore,
    shard: ShardKey,
}
impl Fixture {
    fn new() -> Self {
        let db = RocksDb::open_in_memory().unwrap();
        let store = RocksHypergraphStore::new(db.inner());
        let shards = RocksShardsStore::new(db.inner());
        let app = [0x42; 32];
        let shard = ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3),
            l2: app,
        };
        let txn = store.new_transaction(false).unwrap();
        for prefix in [vec![0], vec![1]] {
            shards
                .put_app_shard(
                    txn.as_ref(),
                    &ShardInfo {
                        shard_key: [shard.l1.as_slice(), app.as_slice()].concat(),
                        prefix,
                        size: vec![],
                        data_shards: 0,
                        commitment: vec![],
                    },
                )
                .unwrap();
        }
        txn.commit().unwrap();
        Self {
            db,
            store,
            shards,
            shard,
        }
    }

    fn seed(&self) -> Vec<Vec<(Vec<u8>, Vec<u8>)>> {
        let store: &dyn HypergraphStore = &self.store;
        let txn = store.new_transaction(false).unwrap();
        let rows = PHASES
            .into_iter()
            .map(|phase| {
                let (set, name) = phase_names(phase);
                let key = |n| [self.shard.l2, [n; 32]].concat();
                let old = blob(b"superseded");
                let updated = blob(b"latest version");
                let middle = if matches!(phase, Phase::VertexRemoves | Phase::HyperedgeRemoves) {
                    Vec::new()
                } else {
                    blob(b"second address")
                };
                let legacy = blob(b"legacy only");
                store
                    .save_vertex_underlying(txn.as_ref(), set, name, &self.shard, &key(1), &old)
                    .unwrap();
                store
                    .save_vertex_underlying_versioned(
                        txn.as_ref(),
                        set,
                        name,
                        &self.shard,
                        &key(1),
                        &old,
                        0,
                    )
                    .unwrap();
                store
                    .save_vertex_underlying_versioned(
                        txn.as_ref(),
                        set,
                        name,
                        &self.shard,
                        &key(1),
                        &updated,
                        8,
                    )
                    .unwrap();
                store
                    .save_vertex_underlying_versioned(
                        txn.as_ref(),
                        set,
                        name,
                        &self.shard,
                        &key(2),
                        &middle,
                        4,
                    )
                    .unwrap();
                store
                    .save_vertex_underlying(txn.as_ref(), set, name, &self.shard, &key(3), &legacy)
                    .unwrap();
                vec![(key(1), updated), (key(2), middle), (key(3), legacy)]
            })
            .collect();
        txn.commit().unwrap();
        rows
    }
}

#[test]
fn overlay_fold_merges_versions_and_tombstones_without_changing_primary() {
    let fixture = Fixture::new();
    let expected = fixture.seed();
    let overlay = Arc::new(ExecutionOverlay::capture(fixture.db.inner(), limits()).unwrap());
    let store = OverlayHypergraphStore::new(overlay.clone());
    let shards = OverlayShardsStore::new(overlay.clone());
    let forest = store.forest();
    // A later primary update must not enter the captured consolidation.
    let txn = fixture.store.new_transaction(false).unwrap();
    HypergraphStore::save_vertex_underlying_versioned(
        &fixture.store,
        txn.as_ref(),
        "vertex",
        "adds",
        &fixture.shard,
        &[fixture.shard.l2, [2; 32]].concat(),
        &blob(b"later primary"),
        9,
    )
    .unwrap();
    txn.commit().unwrap();
    let sequence = fixture.db.inner().latest_sequence_number();
    let expected_forest = Forest::in_memory();
    for (phase, rows) in PHASES.into_iter().zip(&expected) {
        expected_forest
            .commit_shard_phase_raw(
                &fixture.shard.l2,
                phase,
                0,
                rows.iter().map(|(key, value)| {
                    (
                        key[32..].to_vec(),
                        quil_tries::vertex_leaf_value(value).unwrap(),
                    )
                }),
            )
            .unwrap();
    }
    // Retry reproduces the same root; small pages force version chaining.
    for _ in 0..2 {
        assert_eq!(
            run_unified_consolidation(&store, &forest, &shards, 9, 2).unwrap(),
            1
        );
        for (phase, rows) in PHASES.into_iter().zip(&expected) {
            let head = forest
                .read_head_version(&fixture.shard.l2, phase)
                .unwrap()
                .unwrap();
            assert_eq!(head, 1);
            let root = forest
                .app_subtree_root(&fixture.shard.l2, phase, head, &[])
                .unwrap();
            assert_eq!(
                root,
                expected_forest
                    .app_subtree_root(&fixture.shard.l2, phase, 0, &[])
                    .unwrap()
            );
            for (key, value) in rows {
                let expected_leaf = quil_tries::vertex_leaf_value(value).unwrap();
                let (found, proof) = forest
                    .shard_phase_get_with_proof_raw(&fixture.shard.l2, phase, head, &key[32..])
                    .unwrap();
                assert_eq!(found.as_deref(), Some(expected_leaf.as_slice()));
                proof
                    .verify_existence(
                        jmt::RootHash(root),
                        quil_forest::shard_path_key_hash(&key[32..]),
                        &expected_leaf,
                    )
                    .unwrap();
            }
        }
        assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
    }
    overlay.close();
    assert!(store.new_transaction(false).is_err());
}

#[test]
fn overlay_fold_rejects_foreign_providers_and_resource_exhaustion() {
    let fixture = Fixture::new();
    fixture.seed();
    let sequence = fixture.db.inner().latest_sequence_number();
    let overlay = Arc::new(ExecutionOverlay::capture(fixture.db.inner(), limits()).unwrap());
    let store = OverlayHypergraphStore::new(overlay.clone());
    let shards = OverlayShardsStore::new(overlay.clone());
    let primary_forest = Forest::with_namespace(fixture.db.inner(), quil_store::FOREST_NAMESPACE);
    assert!(
        run_unified_consolidation(&store, &primary_forest, &shards, 9, 2)
            .unwrap_err()
            .to_string()
            .contains("forest/store mismatch")
    );
    assert!(
        run_unified_consolidation(&store, &store.forest(), &fixture.shards, 9, 2)
            .unwrap_err()
            .to_string()
            .contains("shard store mismatch")
    );
    assert_eq!(overlay.stats().delta_entries, 0);
    overlay.close();
    for budget in [
        OverlayLimits {
            max_read_operations: 1,
            ..limits()
        },
        OverlayLimits {
            max_read_bytes: 1,
            ..limits()
        },
        OverlayLimits {
            max_delta_entries: 1,
            ..limits()
        },
        OverlayLimits {
            max_delta_bytes: 1,
            ..limits()
        },
    ] {
        let overlay = Arc::new(ExecutionOverlay::capture(fixture.db.inner(), budget).unwrap());
        let store = OverlayHypergraphStore::new(overlay.clone());
        let shards = OverlayShardsStore::new(overlay.clone());
        assert!(run_unified_consolidation(&store, &store.forest(), &shards, 9, 2).is_err());
        assert!(overlay.stats().delta_entries <= budget.max_delta_entries);
        assert!(overlay.stats().delta_bytes <= budget.max_delta_bytes);
        overlay.close();
    }
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
}

#[test]
fn overlay_fold_preserves_legacy_tree_fallback_and_rejects_partial_bad_input() {
    let fixture = Fixture::new();
    let mut tree = quil_tries::VectorCommitmentTree::new();
    let inner = blob(b"whole-tree leaf");
    for n in 1..=3 {
        tree.insert(
            &[fixture.shard.l2, [n; 32]].concat(),
            &inner,
            &[],
            &num_bigint::BigInt::from(inner.len()),
        )
        .unwrap();
    }
    let txn = fixture.store.new_transaction(false).unwrap();
    fixture
        .store
        .save_root(
            txn.as_ref(),
            "vertex",
            "adds",
            &fixture.shard,
            &quil_tries::serialize_tree(tree.root.as_ref()).unwrap(),
        )
        .unwrap();
    txn.commit().unwrap();
    let overlay = Arc::new(ExecutionOverlay::capture(fixture.db.inner(), limits()).unwrap());
    let store = OverlayHypergraphStore::new(overlay.clone());
    let shards = OverlayShardsStore::new(overlay.clone());
    let sequence = fixture.db.inner().latest_sequence_number();
    assert_eq!(
        run_unified_consolidation(&store, &store.forest(), &shards, 0, 1).unwrap(),
        1
    );
    assert_eq!(
        store
            .forest()
            .read_head_version(&fixture.shard.l2, Phase::VertexAdds)
            .unwrap(),
        Some(2)
    );
    overlay.close();
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);

    let txn = fixture.store.new_transaction(false).unwrap();
    let mut truncated = quil_tries::serialize_tree(tree.root.as_ref()).unwrap();
    truncated.truncate(truncated.len() / 2);
    assert!(quil_tries::deserialize_tree(&truncated).is_err());
    fixture
        .store
        .save_root(
            txn.as_ref(),
            "vertex",
            "removes",
            &fixture.shard,
            &truncated,
        )
        .unwrap();
    txn.commit().unwrap();
    let sequence = fixture.db.inner().latest_sequence_number();
    let overlay = Arc::new(ExecutionOverlay::capture(fixture.db.inner(), limits()).unwrap());
    let store = OverlayHypergraphStore::new(overlay.clone());
    let shards = OverlayShardsStore::new(overlay.clone());
    assert!(run_unified_consolidation(&store, &store.forest(), &shards, 9, 1).is_err());
    assert!(
        overlay.stats().delta_entries > 0,
        "failure occurs after an earlier page was staged"
    );
    assert_eq!(fixture.db.inner().latest_sequence_number(), sequence);
    overlay.close();
    assert!(store.new_transaction(false).is_err());
}
