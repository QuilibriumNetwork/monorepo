use quil_forest::{CoordinatedDb, ExecutionOverlay, OverlayLimits, OverlayMutation};
use quil_store::{coin_changes, encoding, RocksDb, RocksHypergraphSnapshot};
use quil_types::store::{HypergraphStore, ShardKey};

fn memory_store() -> CoordinatedDb {
    RocksDb::open_in_memory().unwrap().inner()
}

fn overlay_limits() -> OverlayLimits {
    OverlayLimits {
        max_delta_bytes: 1 << 20,
        max_delta_entries: 100,
        max_record_bytes: 1 << 16,
        max_read_bytes: 1 << 20,
        max_read_operations: 1000,
        max_cursors: 4,
    }
}

fn row(domain: u8, address: u8, version: u64) -> Vec<u8> {
    let domain = [domain; 32];
    let shard = ShardKey {
        l1: [7; 3],
        l2: domain,
    };
    let mut key = domain.to_vec();
    key.extend_from_slice(&[address; 32]);
    encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard, &key, version)
}

fn cursor(db: &quil_forest::CoordinatedDb, domain: u8) -> Vec<u8> {
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    let cursor = coin_changes::snapshot_cursor(&snapshot, &[domain; 32]).unwrap();
    assert!(
        !cursor.is_empty(),
        "writable stores initialize the journal before snapshots"
    );
    cursor
}

#[test]
fn ordinary_non_coin_rows_do_not_consume_change_history() {
    let db = memory_store();
    let start = cursor(&db, 1);
    for size in [4096, 16_384, 65_536] {
        let key = row(1, 3, size);
        let leaf = quil_tries::VectorCommitmentNode::Leaf(quil_tries::LeafNode {
            key: vec![0],
            value: vec![3; size as usize - 64],
            hash_target: Vec::new(),
            commitment: Vec::new(),
            size: 0.into(),
        });
        let mut blob = quil_tries::serialize_go_tree(Some(&leaf)).unwrap();
        blob.resize(size as usize, 0);
        assert!(quil_tries::deserialize_go_tree(&blob).is_ok());
        let before = db.latest_sequence_number();
        db.put(&key, &blob).unwrap();
        assert_eq!(db.get(&key).unwrap().unwrap(), blob);
        assert_eq!(
            db.latest_sequence_number() - before,
            1,
            "a provably non-Coin row needs only its canonical write"
        );
    }
    let page = coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000).unwrap();
    assert!(!page.reset && !page.has_more && page.records.is_empty());
    assert_eq!(page.cursor, start);
}

#[test]
fn event_batches_do_not_rewrite_unchanged_installation_state() {
    let db = memory_store();
    let start = cursor(&db, 1);
    let mut blob = vec![3; 4096];
    blob[..18].copy_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 14, 64]);
    let before = db.latest_sequence_number();
    db.put(row(1, 3, 1), &blob).unwrap();
    let page = coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000).unwrap();
    assert!(!page.reset);
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].blob, blob);
    // The row, its event and its watermark; no installation tombstone.
    assert_eq!(db.latest_sequence_number() - before, 3);
}

#[test]
fn unchanged_installation_metadata_is_not_rewritten() {
    let db = memory_store();
    let initial = cursor(&db, 1);
    let meta_key = b"quil/local/coin-changes/v1/meta";
    coin_changes::begin_install(&db, b"retry").unwrap();
    let installing_meta = db.get(meta_key).unwrap();

    let before = db.latest_sequence_number();
    coin_changes::begin_install(&db, b"retry").unwrap();
    assert_eq!(db.get(meta_key).unwrap(), installing_meta);
    // The request is consumed in the same batch; META stays untouched.
    assert_eq!(db.latest_sequence_number() - before, 2);

    let before = db.latest_sequence_number();
    db.put(row(1, 3, 1), vec![3; 4096]).unwrap();
    assert_eq!(db.get(meta_key).unwrap(), installing_meta);
    assert_eq!(db.latest_sequence_number() - before, 1);
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_err());

    coin_changes::finish_install(&db, b"retry").unwrap();
    let resumed = cursor(&db, 1);
    assert_ne!(resumed, initial);
    assert!(coin_changes::cursor_head(&db, &[1; 32], &resumed)
        .unwrap()
        .is_some());
    let before = db.latest_sequence_number();
    coin_changes::finish_install(&db, b"retry").unwrap();
    assert_eq!(db.latest_sequence_number() - before, 2);
    assert_eq!(cursor(&db, 1), resumed);
    assert!(
        coin_changes::read_page(&db, &[1; 32], &initial, 8, 100_000)
            .unwrap()
            .reset
    );
}

#[test]
fn candidate_filter_preserves_unparseable_rows_and_type_markers() {
    let db = memory_store();
    let start = cursor(&db, 1);
    let marker = quil_tries::VectorCommitmentNode::Leaf(quil_tries::LeafNode {
        key: vec![0xff; 32],
        value: vec![3; 32],
        hash_target: Vec::new(),
        commitment: Vec::new(),
        size: 0.into(),
    });
    let mut marked = quil_tries::serialize_go_tree(Some(&marker)).unwrap();
    marked.resize(4096, 0);
    let malformed = vec![3; 4096];
    assert!(quil_tries::deserialize_go_tree(&malformed).is_err());
    // Keep uncertain records for authoritative Coin decoding, including
    // malformed encodings and type-marked records with missing fields.
    for (index, blob) in [malformed.clone(), marked.clone()].iter().enumerate() {
        db.put(row(1, index as u8 + 1, 1), blob).unwrap();
    }
    let page = coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000).unwrap();
    assert!(!page.reset && !page.has_more);
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records[0].blob, malformed);
    assert_eq!(page.records[1].blob, marked);
}

#[test]
fn a_transactional_reset_is_discarded_on_abort_and_published_with_state() {
    let db = memory_store();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    let start = cursor(&db, 1);
    let before = db.latest_sequence_number();
    let txn = hypergraph.new_transaction(false).unwrap();
    hypergraph
        .invalidate_coin_changes_in_transaction(txn.as_ref())
        .unwrap();
    assert_eq!(db.latest_sequence_number(), before);
    txn.abort().unwrap();
    assert_eq!(cursor(&db, 1), start);

    let foreign = RocksDb::open_in_memory().unwrap();
    let foreign_store = quil_store::RocksHypergraphStore::new(foreign.inner());
    let foreign_txn = foreign_store.new_transaction(false).unwrap();
    assert!(hypergraph
        .invalidate_coin_changes_in_transaction(foreign_txn.as_ref())
        .is_err());
    foreign_txn.abort().unwrap();
    assert_eq!(cursor(&db, 1), start);

    let txn = hypergraph.new_transaction(false).unwrap();
    txn.set(b"test/canonical", b"updated").unwrap();
    hypergraph
        .invalidate_coin_changes_in_transaction(txn.as_ref())
        .unwrap();
    let held = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    txn.commit().unwrap();
    assert_eq!(
        db.get(b"test/canonical").unwrap().as_deref(),
        Some(b"updated".as_slice())
    );
    assert!(
        coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000)
            .unwrap()
            .reset
    );
    assert_eq!(
        coin_changes::snapshot_cursor(&held, &[1; 32]).unwrap(),
        start
    );
}

#[test]
fn a_private_transactional_reset_waits_for_overlay_publication() {
    let db = memory_store();
    let start = cursor(&db, 1);
    let overlay =
        std::sync::Arc::new(ExecutionOverlay::capture(db.clone(), overlay_limits()).unwrap());
    let branch = quil_store::OverlayHypergraphStore::new(overlay.clone());
    let txn = branch.new_transaction(false).unwrap();
    branch
        .invalidate_coin_changes_in_transaction(txn.as_ref())
        .unwrap();
    txn.commit().unwrap();
    assert_eq!(cursor(&db, 1), start);
    overlay.prepare_commit().unwrap().commit(&db).unwrap();
    assert!(
        coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000)
            .unwrap()
            .reset
    );
}

#[test]
fn journal_tracks_arrival_order_and_resumes_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    let start = cursor(&db, 1);
    db.put(row(1, 9, 900), vec![9; 4096]).unwrap();
    let first = coin_changes::read_page(&db, &[1; 32], &start, 1, 100_000).unwrap();
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.records[0].key[32..], [9; 32]);
    assert!(!first.reset);
    // A late older frame/version is a later local arrival.
    db.put(row(1, 2, 2), vec![2; 4096]).unwrap();
    let continued = first.cursor;
    drop(db);
    drop(store);
    let store = RocksDb::open(directory.path()).unwrap();
    let page = coin_changes::read_page(&store.inner(), &[1; 32], &continued, 8, 100_000).unwrap();
    assert!(!page.reset);
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].key[32..], [2; 32]);
    assert_eq!(page.records[0].blob, vec![2; 4096]);
}

#[test]
fn snapshot_watermark_uses_the_same_database_snapshot_as_the_rows() {
    let db = memory_store();
    let before = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    db.put(row(1, 3, 1), vec![3; 4096]).unwrap();
    let old = coin_changes::snapshot_cursor(&before, &[1; 32]).unwrap();
    let page = coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000).unwrap();
    assert_eq!(page.records.len(), 1);
    let current = cursor(&db, 1);
    assert!(coin_changes::read_page(&db, &[1; 32], &current, 8, 100_000)
        .unwrap()
        .records
        .is_empty());
}

#[test]
fn domain_filter_advances_over_other_domains_without_losing_matching_records() {
    let db = memory_store();
    let start = cursor(&db, 1);
    let mut batch = rocksdb::WriteBatch::default();
    batch.put(row(2, 1, 1), vec![2; 4096]);
    batch.put(row(1, 3, 1), vec![3; 4096]);
    batch.put(row(1, 4, 1), vec![4; 4096]);
    db.write(batch).unwrap();
    let first = coin_changes::read_page(&db, &[1; 32], &start, 1, 100_000).unwrap();
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.records[0].key[32..], [3; 32]);
    assert!(first.has_more);
    let next = coin_changes::read_page(&db, &[1; 32], &first.cursor, 8, 100_000).unwrap();
    assert_eq!(next.records.len(), 1);
    assert_eq!(next.records[0].key[32..], [4; 32]);
    assert!(!next.has_more);
    assert!(coin_changes::read_page(&db, &[2; 32], &start, 8, 100_000).is_err());
}

#[test]
fn discarded_overlay_is_invisible_and_published_overlay_is_journaled() {
    let db = memory_store();
    let start = cursor(&db, 1);
    let limits = overlay_limits();
    let discarded = ExecutionOverlay::capture(db.clone(), limits).unwrap();
    discarded
        .apply(&[OverlayMutation::Put(row(1, 1, 1), vec![1; 4096])])
        .unwrap();
    drop(discarded);
    assert!(coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000)
        .unwrap()
        .records
        .is_empty());
    let branch = ExecutionOverlay::capture(db.clone(), limits).unwrap();
    branch
        .apply(&[OverlayMutation::Put(row(1, 2, 1), vec![2; 4096])])
        .unwrap();
    branch.prepare_commit().unwrap().commit(&db).unwrap();
    let page = coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000).unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].key[32..], [2; 32]);
}

#[test]
fn overlarge_record_resets_continuity_without_refusing_the_state_write() {
    let db = memory_store();
    let old = cursor(&db, 1);
    let mut oversized = vec![1; 65_537];
    // A possible Coin owner leaf: tag, key length, key[4], value length 3648.
    oversized[..18].copy_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 14, 64]);
    db.put(row(1, 1, 1), oversized).unwrap();
    assert!(db.get(row(1, 1, 1)).unwrap().is_some());
    let page = coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000).unwrap();
    assert!(page.reset);
    assert!(page.records.is_empty());
    assert!(page.cursor.is_empty());
    let fresh = cursor(&db, 1);
    db.put(row(1, 2, 2), vec![2; 4096]).unwrap();
    assert_eq!(
        coin_changes::read_page(&db, &[1; 32], &fresh, 8, 100_000)
            .unwrap()
            .records
            .len(),
        1
    );
}

#[test]
fn explicit_reset_and_missing_retained_record_never_silently_skip_history() {
    let db = memory_store();
    let old = cursor(&db, 1);
    coin_changes::reset(&db).unwrap();
    let reset = coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000).unwrap();
    assert!(reset.reset);
    assert!(reset.cursor.is_empty());
    let start = cursor(&db, 1);
    db.put(row(1, 2, 2), vec![2; 4096]).unwrap();
    // Removing retained history simulates corrupted/restored local metadata.
    let mut key = b"quil/local/coin-changes/v1/events/".to_vec();
    key.extend_from_slice(&1u64.to_be_bytes());
    db.delete(key).unwrap();
    assert!(
        coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000)
            .unwrap()
            .reset
    );
}

#[test]
fn retention_of_old_blob_versions_does_not_reset_a_valid_feed() {
    let db = memory_store();
    let start = cursor(&db, 1);
    db.put(row(1, 2, 1), vec![2; 4096]).unwrap();
    db.delete(row(1, 2, 1)).unwrap();
    let page = coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000).unwrap();
    assert!(!page.reset);
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].blob, vec![2; 4096]);
}

#[test]
fn a_page_bounds_work_even_when_every_record_belongs_to_another_domain() {
    let db = memory_store();
    let start = cursor(&db, 1);
    let mut batch = rocksdb::WriteBatch::default();
    for version in 0..1025 {
        batch.put(row(2, 3, version), vec![3; 4096]);
    }
    batch.put(row(1, 4, 1), vec![4; 4096]);
    db.write(batch).unwrap();
    let first = coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000).unwrap();
    assert!(first.records.is_empty());
    assert!(first.has_more);
    assert_ne!(first.cursor, start);
    let mut page = first;
    let mut pages = 1;
    while page.has_more {
        let next = coin_changes::read_page(&db, &[1; 32], &page.cursor, 8, 100_000).unwrap();
        assert_ne!(next.cursor, page.cursor);
        page = next;
        pages += 1;
        assert!(pages < 100);
    }
    assert_eq!(page.records.len(), 1);
}

#[test]
fn snapshot_import_resets_and_excludes_another_nodes_local_continuity() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    let old = cursor(&db, 1);
    let source = rocksdb::DB::open_default(directory.path().join("snapshot")).unwrap();
    source
        .put(b"quil/local/coin-changes/v1/foreign", b"not-local")
        .unwrap();
    source
        .put(b"\0quil/node/coin-feed-proxy/routes/v1", b"foreign-route")
        .unwrap();
    source.put(row(1, 4, 1), vec![4; 4096]).unwrap();
    drop(source);
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    hypergraph
        .apply_snapshot(directory.path().to_str().unwrap())
        .unwrap();
    assert!(
        coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000)
            .unwrap()
            .reset
    );
    assert!(db
        .get(b"quil/local/coin-changes/v1/foreign")
        .unwrap()
        .is_none());
    assert!(db
        .get(b"\0quil/node/coin-feed-proxy/routes/v1")
        .unwrap()
        .is_none());
    assert!(db.get(row(1, 4, 1)).unwrap().is_some());
}

#[test]
fn tiny_response_budget_cannot_advance_past_a_matching_record() {
    let db = memory_store();
    let start = cursor(&db, 1);
    db.put(row(1, 1, 1), vec![1; 4096]).unwrap();
    assert!(coin_changes::read_page(&db, &[1; 32], &start, 8, 64).is_err());
    assert_eq!(
        coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000)
            .unwrap()
            .records
            .len(),
        1
    );
}

#[test]
fn scoped_installation_stays_unavailable_until_every_started_scope_finishes() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    let old = cursor(&db, 1);
    coin_changes::begin_install(&db, b"rewind/one").unwrap();
    coin_changes::begin_install(&db, b"rewind/one").unwrap();
    coin_changes::begin_install(&db, b"wipe/two").unwrap();
    coin_changes::finish_install(&db, b"rewind/one").unwrap();
    coin_changes::finish_install(&db, b"rewind/one").unwrap();
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_err());
    drop(snapshot);
    drop(db);
    drop(store);
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_err());
    assert!(
        coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000)
            .unwrap()
            .reset
    );
    coin_changes::finish_install(&db, b"wipe/two").unwrap();
    assert!(!cursor(&db, 1).is_empty());
}

#[test]
fn completing_an_inactive_scope_preserves_an_existing_cursor() {
    let db = memory_store();
    let start = cursor(&db, 1);
    db.put(row(1, 3, 1), vec![3; 4096]).unwrap();
    coin_changes::finish_install(&db, b"scope-never-started").unwrap();
    assert!(coin_changes::cursor_head(&db, &[1; 32], &start)
        .unwrap()
        .is_some());
    let page = coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000).unwrap();
    assert!(
        !page.reset,
        "an inactive completion must preserve continuity"
    );
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].key[32..], [3; 32]);
}

#[test]
fn installation_scope_query_is_precise_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    assert!(!hypergraph.is_coin_changes_installing(b"one").unwrap());
    coin_changes::begin_install(&db, b"one").unwrap();
    assert!(hypergraph.is_coin_changes_installing(b"one").unwrap());
    assert!(!hypergraph.is_coin_changes_installing(b"two").unwrap());
    drop(hypergraph);
    drop(db);
    drop(store);
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    assert!(hypergraph.is_coin_changes_installing(b"one").unwrap());
    coin_changes::finish_install(&db, b"one").unwrap();
    assert!(!hypergraph.is_coin_changes_installing(b"one").unwrap());
}

#[test]
fn installation_scope_query_never_hides_a_durable_begin_or_unknown_recovery() {
    let db = memory_store();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    // The failed projector leaves the original begin request and INVALID.
    db.put(b"quil/local/coin-changes/v1/installing", b"bad-count")
        .unwrap();
    coin_changes::begin_install(&db, b"pending-begin").unwrap();
    assert!(hypergraph
        .is_coin_changes_installing(b"pending-begin")
        .unwrap());
    assert!(hypergraph.is_coin_changes_installing(b"unknown").is_err());
}

#[test]
fn installation_scope_query_does_not_treat_a_failed_finish_as_completed() {
    let db = memory_store();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    coin_changes::begin_install(&db, b"unfinished").unwrap();
    db.put(b"quil/local/coin-changes/v1/installing", b"bad-count")
        .unwrap();
    coin_changes::finish_install(&db, b"unfinished").unwrap();
    assert!(hypergraph
        .is_coin_changes_installing(b"unfinished")
        .unwrap());
    assert!(hypergraph.is_coin_changes_installing(b"unknown").is_err());
}

#[test]
fn installation_scope_query_sees_tentative_begins_without_publishing_them() {
    let db = memory_store();
    let durable = quil_store::RocksHypergraphStore::new(db.clone());
    let limits = overlay_limits();
    let branch = ExecutionOverlay::capture(db.clone(), limits).unwrap();
    let tentative = quil_store::OverlayHypergraphStore::new(std::sync::Arc::new(branch));
    tentative
        .set_coin_changes_installing(b"tentative", true)
        .unwrap();
    assert!(tentative.is_coin_changes_installing(b"tentative").unwrap());
    assert!(!durable.is_coin_changes_installing(b"tentative").unwrap());
}

#[test]
fn installation_scope_query_refuses_malformed_fence_state() {
    for (key, value) in [
        (
            b"quil/local/coin-changes/v1/install-overflow".as_slice(),
            b"1".to_vec(),
        ),
        (
            b"quil/local/coin-changes/v1/installing".as_slice(),
            b"bad-count".to_vec(),
        ),
        (
            b"quil/local/coin-changes/v1/installing".as_slice(),
            0u64.to_be_bytes().to_vec(),
        ),
        (
            b"quil/local/coin-changes/v1/installing".as_slice(),
            129u64.to_be_bytes().to_vec(),
        ),
        (
            b"quil/local/coin-changes/v1/install-scopes/unknown".as_slice(),
            b"bad-marker".to_vec(),
        ),
        (
            b"quil/local/coin-changes/v1/install-requests/unknown".as_slice(),
            b"bad-request".to_vec(),
        ),
    ] {
        let db = memory_store();
        db.put(key, value).unwrap();
        let hypergraph = quil_store::RocksHypergraphStore::new(db);
        assert!(
            hypergraph.is_coin_changes_installing(b"unknown").is_err(),
            "{} must be rejected",
            String::from_utf8_lossy(key)
        );
    }
}

#[test]
fn snapshot_import_missing_staging_is_an_error_while_its_scope_is_active() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    // A repeated call without any started import remains a harmless no-op.
    hypergraph
        .apply_snapshot(directory.path().to_str().unwrap())
        .unwrap();
    coin_changes::begin_install(&db, b"snapshot-install").unwrap();
    assert!(
        hypergraph
            .apply_snapshot(directory.path().to_str().unwrap())
            .is_err(),
        "a missing retry source must not report successful installation"
    );
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_err());
}

#[test]
fn snapshot_import_missing_staging_does_not_finish_another_scope() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    coin_changes::begin_install(&db, b"unrelated-maintenance").unwrap();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    hypergraph
        .apply_snapshot(directory.path().to_str().unwrap())
        .unwrap();
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_err());
    coin_changes::finish_install(&db, b"unrelated-maintenance").unwrap();
    assert!(!cursor(&db, 1).is_empty());
}

#[cfg(feature = "test-utils")]
#[test]
fn snapshot_import_failed_final_write_retains_staging_and_retries_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("snapshot");
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    let old = cursor(&db, 1);
    let source = rocksdb::DB::open_default(&staging).unwrap();
    for version in 0..101 {
        source.put(row(1, 4, version), vec![4; 4096]).unwrap();
    }
    drop(source);
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    hypergraph.fail_commit_for_test(true);
    let result = hypergraph.apply_snapshot(directory.path().to_str().unwrap());
    assert!(result.is_err(), "the injected final write must fail");
    assert!(db.get(row(1, 4, 0)).unwrap().is_some());
    assert!(db.get(row(1, 4, 100)).unwrap().is_none());
    assert!(
        staging.is_dir(),
        "failed import must retain its retry source"
    );
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_err());
    drop(snapshot);
    drop(hypergraph);
    drop(db);
    drop(store);

    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_err());
    drop(snapshot);
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    hypergraph
        .apply_snapshot(directory.path().to_str().unwrap())
        .unwrap();
    assert!(db.get(row(1, 4, 100)).unwrap().is_some());
    assert!(!staging.exists());
    assert!(!cursor(&db, 1).is_empty());
    assert!(coin_changes::cursor_head(&db, &[1; 32], &old)
        .unwrap()
        .is_none());
}

#[test]
fn snapshot_import_unfinished_projection_retains_staging_and_reports_failure() {
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("snapshot");
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    let source = rocksdb::DB::open_default(&staging).unwrap();
    source.put(row(1, 4, 1), vec![4; 4096]).unwrap();
    drop(source);
    // The original import writes can succeed while their local projection
    // fails. Completing that write alone must not discard the retry source.
    db.put(b"quil/local/coin-changes/v1/installing", b"bad-count")
        .unwrap();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    assert!(hypergraph
        .apply_snapshot(directory.path().to_str().unwrap())
        .is_err());
    assert!(staging.is_dir());
    let snapshot = RocksHypergraphSnapshot::capture(db).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_err());
}

#[test]
fn large_reserved_root_history_does_not_reset_the_feed() {
    let db = memory_store();
    let old = cursor(&db, 1);
    let mut root = row(1, 2, 1);
    root[70..102].fill(0xff);
    root[101] = 0xfc;
    db.put(root, vec![4; 300_000]).unwrap();
    let page = coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000).unwrap();
    assert!(!page.reset);
    assert!(page.records.is_empty());
    assert_eq!(page.cursor, old);
}

#[test]
fn one_batch_over_the_journal_capacity_resets_without_losing_canonical_rows() {
    let db = memory_store();
    let old = cursor(&db, 1);
    let mut batch = rocksdb::WriteBatch::default();
    for version in 0..1024 {
        batch.put(row(1, 2, version), vec![4; 65_536]);
    }
    db.write(batch).unwrap();
    assert!(db.get(row(1, 2, 1023)).unwrap().is_some());
    assert!(
        coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000)
            .unwrap()
            .reset
    );
    assert!(!cursor(&db, 1).is_empty());
}

#[test]
fn same_batch_overwrites_and_deletions_emit_only_the_final_stored_row() {
    let db = memory_store();
    let start = cursor(&db, 1);
    let mut batch = rocksdb::WriteBatch::default();
    batch.put(row(1, 1, 1), vec![1; 4096]);
    batch.put(row(1, 1, 1), vec![2; 4096]);
    batch.put(row(1, 2, 1), vec![3; 4096]);
    batch.delete(row(1, 2, 1));
    batch.put(row(1, 3, 1), vec![4; 4096]);
    batch.put(row(1, 3, 1), b"too-small");
    db.write(batch).unwrap();
    let page = coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000).unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].blob, vec![2; 4096]);
}

#[test]
fn cursor_head_checks_epoch_domain_future_and_unfinished_installation_without_scanning() {
    let db = memory_store();
    let start = cursor(&db, 1);
    db.put(row(1, 1, 1), vec![1; 4096]).unwrap();
    assert_eq!(
        coin_changes::cursor_head(&db, &[1; 32], &start).unwrap(),
        Some(cursor(&db, 1))
    );
    assert!(coin_changes::cursor_head(&db, &[2; 32], &start).is_err());
    let mut future = start.clone();
    future[52..60].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(coin_changes::cursor_head(&db, &[1; 32], &future)
        .unwrap()
        .is_none());
    coin_changes::begin_install(&db, b"first").unwrap();
    assert!(coin_changes::cursor_head(&db, &[1; 32], &start)
        .unwrap()
        .is_none());
    coin_changes::finish_install(&db, b"first").unwrap();
    assert!(coin_changes::cursor_head(&db, &[1; 32], &start)
        .unwrap()
        .is_none());
    assert!(coin_changes::cursor_head(&db, &[1; 32], &cursor(&db, 1))
        .unwrap()
        .is_some());
}

#[test]
fn failed_projection_replays_a_durable_begin_before_another_scope_finishes() {
    let db = memory_store();
    // Corrupt count bytes make the projector fail after the original scope
    // request is staged. The original request and invalid marker must survive.
    db.put(b"quil/local/coin-changes/v1/installing", b"bad-count")
        .unwrap();
    coin_changes::begin_install(&db, b"still-running").unwrap();
    assert!(db
        .get(b"quil/local/coin-changes/v1/invalid")
        .unwrap()
        .is_some());
    db.put(b"quil/local/coin-changes/v1/installing", 0u64.to_be_bytes())
        .unwrap();
    coin_changes::finish_install(&db, b"unrelated").unwrap();
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_err());
    coin_changes::finish_install(&db, b"still-running").unwrap();
    assert!(!cursor(&db, 1).is_empty());
}

#[test]
fn journal_retention_expires_old_cursors_but_keeps_recent_continuations() {
    let db = memory_store();
    let old = cursor(&db, 1);
    let mut first = rocksdb::WriteBatch::default();
    for version in 0..900 {
        first.put(row(1, 2, version), vec![4; 65_536]);
    }
    db.write(first).unwrap();
    let recent = cursor(&db, 1);
    let mut second = rocksdb::WriteBatch::default();
    for version in 900..1100 {
        second.put(row(1, 2, version), vec![5; 65_536]);
    }
    db.write(second).unwrap();
    assert!(coin_changes::cursor_head(&db, &[1; 32], &old)
        .unwrap()
        .is_none());
    assert!(
        coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000)
            .unwrap()
            .reset
    );
    assert!(coin_changes::cursor_head(&db, &[1; 32], &recent)
        .unwrap()
        .is_some());
    let page = coin_changes::read_page(&db, &[1; 32], &recent, 1, 100_000).unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].blob, vec![5; 65_536]);
    assert!(page.has_more);
}

#[test]
fn concurrent_writers_share_one_durable_arrival_sequence() {
    let db = memory_store();
    let start = cursor(&db, 1);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(5));
    let threads: Vec<_> = (0..4u8)
        .map(|worker| {
            let db = db.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                for address in (worker * 16 + 1)..=(worker * 16 + 16) {
                    db.put(row(1, address, 1), vec![address; 4096]).unwrap();
                }
            })
        })
        .collect();
    barrier.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    let page = coin_changes::read_page(&db, &[1; 32], &start, 64, 1 << 20).unwrap();
    assert_eq!(page.records.len(), 64);
    let addresses: std::collections::BTreeSet<_> =
        page.records.iter().map(|record| record.key[32]).collect();
    assert_eq!(addresses, (1..=64).collect());
    assert!(!page.has_more);
}

#[test]
fn refused_state_write_cannot_advance_the_durable_feed() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    let before = cursor(&db, 1);
    db.refuse_writes("injected storage failure");
    assert!(db.put(row(1, 1, 1), vec![1; 4096]).is_err());
    assert!(db.get(row(1, 1, 1)).unwrap().is_none());
    assert_eq!(cursor(&db, 1), before);
    drop(db);
    drop(store);
    let reopened = RocksDb::open(directory.path()).unwrap();
    let page = coin_changes::read_page(&reopened.inner(), &[1; 32], &before, 8, 100_000).unwrap();
    assert!(page.records.is_empty());
    assert_eq!(page.cursor, before);
}

#[test]
fn truncated_retained_blob_resets_before_it_reaches_the_coin_decoder() {
    let db = memory_store();
    let start = cursor(&db, 1);
    db.put(row(1, 1, 1), vec![1; 4096]).unwrap();
    let mut event = [1; 32].to_vec();
    event.extend_from_slice(&[1; 32]);
    event.extend_from_slice(b"short");
    let mut key = b"quil/local/coin-changes/v1/events/".to_vec();
    key.extend_from_slice(&1u64.to_be_bytes());
    db.put(key, event).unwrap();
    let page = coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000).unwrap();
    assert!(
        page.reset,
        "truncated history must require a fresh snapshot"
    );
    assert!(page.records.is_empty());
    assert!(page.cursor.is_empty());
}

#[test]
fn unrelated_large_raw_payload_and_go_tree_do_not_reset_coin_continuity() {
    let db = memory_store();
    let start = cursor(&db, 1);
    db.put(row(1, 1, 1), vec![9; 300_000]).unwrap();
    let mut tree = quil_tries::VectorCommitmentTree { root: None };
    let application_data = vec![9; 300_000];
    tree.insert(
        b"application-data",
        &application_data,
        &[],
        &num_bigint::BigInt::from(application_data.len()),
    )
    .unwrap();
    let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
    db.put(row(1, 2, 1), blob).unwrap();
    let page = coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000).unwrap();
    assert!(
        !page.reset,
        "unrelated application data must preserve Coin continuity"
    );
    assert!(page.records.is_empty());
    assert_eq!(page.cursor, start);
}
