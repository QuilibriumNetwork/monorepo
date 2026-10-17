use super::*;
use quil_hypergraph::{HypergraphCrdt, Location};
use quil_types::store::HypergraphStore;

const APP: [u8; 32] = [9; 32];

struct Fixture {
    _dir: tempfile::TempDir,
    db: quil_forest::CoordinatedDb,
    store: Arc<RocksHypergraphStore>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
        let store = Arc::new(RocksHypergraphStore::new(db.clone()));
        Self { _dir: dir, db, store }
    }

    /// A fresh CRDT over the same database, as after a restart.
    fn crdt(&self) -> Arc<HypergraphCrdt> {
        let crdt = Arc::new(HypergraphCrdt::new(self.store.clone(), Arc::new(quil_tries::ShaInclusionProver)));
        crdt.set_forest(quil_forest::Forest::with_namespace(self.db.clone(), FOREST_NAMESPACE));
        crdt.set_unified_tree(true);
        crdt.set_app_shard_prefixes(APP, vec![vec![]]);
        crdt
    }

    fn blob_versions(&self, location: &Location) -> Vec<u64> {
        let shard = quil_hypergraph::shard_key_for_location(location);
        let prefix = crate::encoding::hypergraph_vertex_data_v2_vk_prefix("vertex", "adds", &shard, &location.to_id());
        self.db
            .iterator(rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward))
            .map(|entry| entry.unwrap().0)
            .take_while(|key| key.starts_with(&prefix) && key.len() == prefix.len() + 8)
            .map(|key| u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap()))
            .collect()
    }
}

fn record() -> Location {
    Location { app_address: APP, data_address: [1; 32] }
}

/// Commit `record` = "value {frame}" (and one untouched vertex) at each frame;
/// returns each frame's vertex-adds root.
fn commit_frames(crdt: &HypergraphCrdt, frames: std::ops::RangeInclusive<u64>) -> Vec<(u64, [u8; 32])> {
    let shard = quil_hypergraph::shard_key_for_location(&record());
    frames
        .map(|frame| {
            crdt.add_vertex(&record(), format!("value {frame}").as_bytes()).unwrap();
            if frame == 1 {
                crdt.add_vertex(&Location { app_address: APP, data_address: [2; 32] }, b"untouched").unwrap();
            }
            let roots = crdt.commit(frame).unwrap();
            (frame, roots[&shard][0].as_slice().try_into().unwrap())
        })
        .collect()
}

#[test]
fn retention_keeps_recent_roots_and_every_newest_value_and_reclaims_the_rest() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    let roots = commit_frames(&crdt, 1..=10);
    assert_eq!(fixture.blob_versions(&record()).len(), 10);

    // Keep the last 3 frames: cull at frame 7, whose state stays readable.
    let (trees, nodes) = crdt.prune_retaining(3, usize::MAX).unwrap();
    assert_eq!(trees, 1);
    assert!(nodes > 0, "superseded forest nodes are reclaimed");
    assert_eq!(fixture.blob_versions(&record()).len(), 4, "frames 7..=10 remain");
    assert_eq!(crdt.get_vertex_data_checked(&record()).unwrap().as_deref(), Some(&b"value 10"[..]));
    let untouched = Location { app_address: APP, data_address: [2; 32] };
    assert_eq!(crdt.get_vertex_data_checked(&untouched).unwrap().as_deref(), Some(&b"untouched"[..]));
    let forest = quil_forest::Forest::with_namespace(fixture.db.clone(), FOREST_NAMESPACE);
    for (frame, root) in &roots {
        let resolved = crdt.resolve_root(&APP, 0, *root);
        if *frame >= 7 {
            let (version, _) = resolved.unwrap_or_else(|| panic!("frame {frame} root must stay resolvable"));
            assert_eq!(
                forest.shard_phase_root(&APP, quil_forest::Phase::VertexAdds, version).unwrap(),
                Some(*root),
                "frame {frame} tree must stay readable"
            );
        } else {
            assert!(resolved.is_none(), "frame {frame} is past retention");
        }
    }

    // A later pass over the same history finds nothing more to do.
    assert_eq!(crdt.prune_retaining(3, usize::MAX).unwrap().1, 0);
    assert_eq!(fixture.blob_versions(&record()).len(), 4);
}

/// Versions restarted without a wipe (the old version-zero rebuild): the
/// index holds a history that fell back. Nothing is pruned, because stale
/// records of the old history may name node keys the rebuild reused.
#[test]
fn retention_leaves_a_tree_whose_versions_restarted_untouched() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=6);
    let txn = fixture.store.new_transaction(false).unwrap();
    for (version, frame) in [(40u64, 1u64), (41, 2), (42, 3)] {
        fixture.store.put_root_version(txn.as_ref(), "vertex", "adds", &APP, &[version as u8; 32], version, frame).unwrap();
    }
    txn.commit().unwrap();
    let before = fixture.blob_versions(&record());
    assert_eq!(crdt.prune_retaining(1, usize::MAX).unwrap(), (0, 0));
    assert_eq!(fixture.blob_versions(&record()), before);
    assert_eq!(crdt.get_vertex_data_checked(&record()).unwrap().as_deref(), Some(&b"value 6"[..]));
}

/// A reset that wipes the tree and its blobs (the prover reset) also drops its
/// index, so the rebuilt tree's history is clean and prunable again.
#[test]
fn a_wiping_reset_drops_its_index_and_the_rebuilt_tree_can_be_pruned() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    let old = commit_frames(&crdt, 1..=5);
    crdt.reset_shard_forest_trees(&APP).unwrap();
    fixture.store.clear_shard_underlying(&quil_hypergraph::shard_key_for_location(&record())).unwrap();
    assert!(old.iter().all(|(_, root)| crdt.resolve_root(&APP, 0, *root).is_none()));
    commit_frames(&crdt, 6..=12);
    let (trees, _) = crdt.prune_retaining(3, usize::MAX).unwrap();
    assert_eq!(trees, 1);
    assert_eq!(fixture.blob_versions(&record()).len(), 4, "frames 9..=12 remain");
    assert_eq!(crdt.get_vertex_data_checked(&record()).unwrap().as_deref(), Some(&b"value 12"[..]));
}

/// A tree head below the watermark (a store whose versions ran backwards
/// without a new index entry) keeps all its nodes.
#[test]
fn retention_refuses_a_forest_watermark_above_the_tree_head() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=6);
    drop(crdt);
    let forest = quil_forest::Forest::with_namespace(fixture.db.clone(), FOREST_NAMESPACE);
    forest.write_head_version(&APP, quil_forest::Phase::VertexAdds, 0).unwrap();
    let crdt = fixture.crdt();
    assert_eq!(crdt.prune_retaining(1, usize::MAX).unwrap(), (0, 0));
}

/// Blob deletions are bounded per pass and resume on the next.
#[test]
fn retention_blob_deletions_are_bounded_per_pass() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=10);
    crdt.prune_retaining(2, 2).unwrap();
    assert_eq!(fixture.blob_versions(&record()).len(), 8);
    crdt.prune_retaining(2, 100).unwrap();
    assert_eq!(fixture.blob_versions(&record()).len(), 3);
    assert_eq!(crdt.get_vertex_data_checked(&record()).unwrap().as_deref(), Some(&b"value 10"[..]));
}

/// Superseded leaf values go with the retention pass, but every retained
/// root still reads each vertex's value: the record rewritten every frame and
/// the vertex written once, whose only value lies below the watermark.
#[test]
fn retention_drops_superseded_leaf_values_and_retained_roots_still_read_every_leaf() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    let roots = commit_frames(&crdt, 1..=10);
    let untouched = Location { app_address: APP, data_address: [2; 32] };
    let keys = || fixture.db.iterator(rocksdb::IteratorMode::Start).count();

    let nodes_only = crdt.prune_retaining_with(3, usize::MAX, None).unwrap();
    assert_eq!(nodes_only.values, 0, "values are kept unless asked for");
    let before = keys();
    let pass = crdt.prune_retaining_with(3, usize::MAX, Some(usize::MAX)).unwrap();
    assert!(pass.values > 0, "the record's superseded values go");
    assert_eq!(before - keys(), pass.values, "only value keys were deleted");
    assert_eq!(crdt.prune_retaining_with(3, usize::MAX, Some(usize::MAX)).unwrap().values, 0);

    let forest = quil_forest::Forest::with_namespace(fixture.db.clone(), FOREST_NAMESPACE);
    for (frame, root) in roots.iter().filter(|(frame, _)| *frame >= 7) {
        let (version, _) = crdt.resolve_root(&APP, 0, *root).unwrap();
        assert_eq!(forest.shard_phase_root(&APP, quil_forest::Phase::VertexAdds, version).unwrap(), Some(*root));
        let read = |location: &Location| {
            forest.shard_phase_get_with_proof_raw(&APP, quil_forest::Phase::VertexAdds, version, &location.data_address)
                .unwrap().0
        };
        let expected = quil_tries::vertex_leaf_value(format!("value {frame}").as_bytes()).unwrap();
        assert_eq!(read(&record()), Some(expected), "frame {frame}: the record's value at its version");
        assert_eq!(read(&untouched), Some(quil_tries::vertex_leaf_value(b"untouched").unwrap()),
            "frame {frame}: a value written once, below the watermark, stays readable");
    }
    assert_eq!(crdt.get_vertex_data_checked(&record()).unwrap().as_deref(), Some(&b"value 10"[..]));
}

/// A value pass bounded by its budget deletes at most that many, never a
/// partially scanned key's floor, and a later pass finishes the job.
#[test]
fn retention_value_deletions_are_bounded_per_pass() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=10);
    let first = crdt.prune_retaining_with(3, usize::MAX, Some(2)).unwrap();
    assert!(first.values <= 2);
    let rest = crdt.prune_retaining_with(3, usize::MAX, Some(usize::MAX)).unwrap();
    assert!(rest.values > 0);
    assert_eq!(crdt.prune_retaining_with(3, usize::MAX, Some(usize::MAX)).unwrap().values, 0);
    assert_eq!(crdt.get_vertex_data_checked(&record()).unwrap().as_deref(), Some(&b"value 10"[..]));
}
