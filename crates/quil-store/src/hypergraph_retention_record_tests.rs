//! Each deletion step of a retention pass ends after the record at which its
//! caller asks it to stop, and a later call resumes there: a pass holding the
//! commit lock ends its hold within one record of a commit or a reader asking
//! for the lock, and the records it deletes across holds are exactly those
//! one call deletes.
use super::*;
use quil_forest::Phase::VertexAdds;
use quil_types::store::HypergraphStore;

const APP: [u8; 32] = [7; 32];
/// The tree keeps versions 7..=10 readable.
const WATERMARK: u64 = 7;

fn database() -> (tempfile::TempDir, quil_forest::CoordinatedDb) {
    let dir = tempfile::tempdir().unwrap();
    let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
    (dir, db)
}

/// Every key the database holds.
fn keys(db: &quil_forest::CoordinatedDb) -> Vec<Box<[u8]>> {
    db.iterator(rocksdb::IteratorMode::Start)
        .map(|entry| entry.unwrap().0)
        .collect()
}

/// A tree whose eight leaves are rewritten at each of versions 1..=10.
fn rewritten_tree(db: &quil_forest::CoordinatedDb) -> quil_forest::Forest {
    let forest = quil_forest::Forest::with_namespace(db.clone(), FOREST_NAMESPACE);
    for version in 1..=10u64 {
        forest
            .commit_shard_phase_raw(
                &APP,
                VertexAdds,
                version,
                (0..8u8).map(|leaf| {
                    (
                        vec![leaf; 32],
                        format!("leaf {leaf} version {version}").into_bytes(),
                    )
                }),
            )
            .unwrap();
    }
    forest
}

#[test]
fn a_node_prune_batch_ends_after_one_record_when_asked_and_resumes() {
    let (_whole_dir, whole_db) = database();
    let (all, rest) = rewritten_tree(&whole_db)
        .prune_shard_phase_batch(&APP, VertexAdds, WATERMARK, None, 1 << 20, &|| false)
        .unwrap();
    assert!(all > 1 && rest.is_none(), "{all} records, rest {rest:?}");

    let (_dir, db) = database();
    let forest = rewritten_tree(&db);
    let (mut from, mut deleted, mut calls) = (None::<Vec<u8>>, 0usize, 0usize);
    loop {
        let (records, next) = forest
            .prune_shard_phase_batch(
                &APP,
                VertexAdds,
                WATERMARK,
                from.as_deref(),
                1 << 20,
                &|| true,
            )
            .unwrap();
        calls += 1;
        assert!(
            records <= 1,
            "call {calls} deleted {records} stale node records after its caller asked it to stop"
        );
        deleted += records;
        match next {
            Some(next) => from = Some(next),
            None => break,
        }
    }
    assert_eq!(deleted, all, "the resumed batches delete every record");
    assert!(calls >= all, "{calls} calls for {all} records");
    assert!(keys(&db) == keys(&whole_db), "the same keys remain");
}

#[test]
fn a_leaf_value_prune_ends_after_one_key_when_asked_and_resumes() {
    let candidates = |forest: &quil_forest::Forest| {
        let mut budget = usize::MAX;
        forest
            .shard_phase_value_candidates(&APP, VertexAdds, WATERMARK, &mut budget)
            .unwrap()
            .0
    };
    let (_whole_dir, whole_db) = database();
    let whole = rewritten_tree(&whole_db);
    let key_hashes = candidates(&whole);
    assert_eq!(key_hashes.len(), 8);
    let mut budget = usize::MAX;
    let (all, judged) = whole
        .prune_shard_phase_values_of(
            &APP,
            VertexAdds,
            WATERMARK,
            &key_hashes,
            &mut budget,
            &|| false,
        )
        .unwrap();
    assert_eq!((all, judged), (8 * 6, 8), "versions 1..=6 of each key go");

    let (_dir, db) = database();
    let forest = rewritten_tree(&db);
    let key_hashes = candidates(&forest);
    let (mut next, mut deleted) = (0usize, 0usize);
    let mut budget = usize::MAX;
    while next < key_hashes.len() {
        let (values, judged) = forest
            .prune_shard_phase_values_of(
                &APP,
                VertexAdds,
                WATERMARK,
                &key_hashes[next..],
                &mut budget,
                &|| true,
            )
            .unwrap();
        assert_eq!(
            judged, 1,
            "the prune judged {judged} keys after its caller asked it to stop at key {next}"
        );
        deleted += values;
        next += judged;
    }
    assert_eq!(deleted, all, "the resumed calls delete every value");
    assert!(keys(&db) == keys(&whole_db), "the same keys remain");
}

#[test]
fn a_blob_version_prune_ends_after_one_vertex_when_asked_and_resumes() {
    // Eight vertices, each with versions 1..=3 below the watermark: 1 and 2 go.
    let build = || {
        let (dir, db) = database();
        let store = RocksHypergraphStore::new(db.clone());
        let shard = retention_shard(&APP);
        let txn = store.new_transaction(false).unwrap();
        for vertex in 0..8u8 {
            let mut id = [vertex; 64];
            id[..32].copy_from_slice(&APP);
            for version in 1..=3 {
                store
                    .save_vertex_underlying_versioned(
                        txn.as_ref(),
                        "vertex",
                        "adds",
                        &shard,
                        &id,
                        b"blob",
                        version,
                    )
                    .unwrap();
            }
        }
        txn.commit().unwrap();
        let keyspace = quil_types::store::RetentionKeyspace {
            set: 0,
            phase: 0,
            application: APP,
            watermark: WATERMARK,
        };
        let mut budget = usize::MAX;
        let (vertices, _) = store
            .retention_blob_candidates(&keyspace, &mut budget)
            .unwrap();
        assert_eq!(vertices.len(), 8);
        (dir, db, store, keyspace, vertices)
    };
    let (_whole_dir, whole_db, whole, keyspace, vertices) = build();
    let mut budget = usize::MAX;
    let txn = whole.new_transaction(false).unwrap();
    let (all, judged) = whole
        .retention_prune_vertices(txn.as_ref(), &keyspace, &vertices, &mut budget, &|| false)
        .unwrap();
    txn.commit().unwrap();
    assert_eq!((all, judged), (16, 8));

    let (_dir, db, store, keyspace, vertices) = build();
    let (mut next, mut deleted) = (0usize, 0usize);
    let mut budget = usize::MAX;
    while next < vertices.len() {
        let txn = store.new_transaction(false).unwrap();
        let (staged, judged) = store
            .retention_prune_vertices(
                txn.as_ref(),
                &keyspace,
                &vertices[next..],
                &mut budget,
                &|| true,
            )
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(
            judged, 1,
            "the prune judged {judged} vertices after its caller asked it to stop at vertex {next}"
        );
        deleted += staged;
        next += judged;
    }
    assert_eq!(
        deleted, all,
        "the resumed calls delete every superseded version"
    );
    assert!(keys(&db) == keys(&whole_db), "the same keys remain");
}
