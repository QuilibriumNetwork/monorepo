use quil_forest::{CoordinatedDb, ExecutionOverlay, OverlayLimits, OverlayMutation};
use quil_store::{coin_changes, encoding, RocksDb, RocksHypergraphSnapshot};
use quil_types::store::{HypergraphStore, ShardKey};

fn memory_store() -> CoordinatedDb {
    RocksDb::open_in_memory_with_coin_changes(true)
        .unwrap()
        .inner()
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
        "enabled stores initialize the journal before snapshots"
    );
    cursor
}

#[test]
fn unavailable_journal_omits_the_cursor_without_failing_the_snapshot() {
    for (key, value) in [
        (
            b"quil/local/coin-changes/v1/invalid".as_slice(),
            b"1".to_vec(),
        ),
        (
            b"quil/local/coin-changes/v1/install-overflow".as_slice(),
            b"1".to_vec(),
        ),
        (
            b"quil/local/coin-changes/v1/installing".as_slice(),
            1u64.to_be_bytes().to_vec(),
        ),
    ] {
        let db = memory_store();
        db.put(b"test/canonical", b"retained").unwrap();
        db.put(key, value).unwrap();
        let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
        assert!(
            coin_changes::snapshot_cursor(&snapshot, &[1; 32])
                .unwrap()
                .is_empty(),
            "{} must disable incremental discovery without refusing the snapshot",
            String::from_utf8_lossy(key)
        );
        assert_eq!(
            db.get(b"test/canonical").unwrap().as_deref(),
            Some(b"retained".as_slice())
        );
    }
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
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());

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

    let foreign = RocksDb::open_in_memory_with_coin_changes(true).unwrap();
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
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
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
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
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
        if version > 0 && version % 32 == 0 {
            db.write(batch).unwrap();
            batch = rocksdb::WriteBatch::default();
        }
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
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
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
fn snapshot_install_markers_share_the_required_import_batches() {
    for enabled in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let staging = directory.path().join("snapshot");
        let store = RocksDb::open_with_coin_changes(directory.path(), enabled).unwrap();
        let db = store.inner();
        let source = rocksdb::DB::open_default(&staging).unwrap();
        source.put(row(1, 4, 1), vec![4; 4096]).unwrap();
        drop(source);
        let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
        db.take_write_times();

        hypergraph
            .apply_snapshot(directory.path().to_str().unwrap())
            .unwrap();

        assert_eq!(db.take_write_times().writes, 2, "enabled={enabled}");
        assert_eq!(db.get(row(1, 4, 1)).unwrap(), Some(vec![4; 4096]));
        assert_eq!(
            db.get(coin_changes::SNAPSHOT_INSTALL_STATE)
                .unwrap()
                .as_deref(),
            Some(b"0".as_slice())
        );
        let mut events = db.raw_iterator();
        events.seek(b"quil/local/coin-changes/v1/events/");
        assert!(!events
            .key()
            .is_some_and(|key| key.starts_with(b"quil/local/coin-changes/v1/events/")));
        events.status().unwrap();
        assert!(!staging.exists());
    }
}

#[test]
fn optional_hooks_do_not_consume_the_overlay_read_budget() {
    for mode in ["off", "on", "off-after-on"] {
        let directory = tempfile::tempdir().unwrap();
        if mode == "off-after-on" {
            drop(RocksDb::open_with_coin_changes(directory.path(), true).unwrap());
        }
        let store = RocksDb::open_with_coin_changes(directory.path(), mode == "on").unwrap();
        let db = store.inner();
        let branch = std::sync::Arc::new(
            ExecutionOverlay::capture(
                db.clone(),
                OverlayLimits {
                    max_read_operations: 0,
                    max_delta_entries: 1,
                    max_delta_bytes: b"test/canonical".len() + b"state".len(),
                    max_record_bytes: b"test/canonical".len() + b"state".len(),
                    ..overlay_limits()
                },
            )
            .unwrap(),
        );
        let tentative = quil_store::OverlayHypergraphStore::new(branch.clone());
        let before = db.latest_sequence_number();
        tentative
            .set_coin_changes_installing(b"test-scope", true)
            .unwrap();
        tentative
            .set_coin_changes_installing(b"test-scope", false)
            .unwrap();
        tentative
            .begin_coin_changes_rewind(b"rewind/test-scope", &[[0; 32]; 4])
            .unwrap();
        assert!(!tentative.is_coin_changes_installing(b"test-scope").unwrap());
        let txn = tentative.new_transaction(false).unwrap();
        txn.set(b"test/canonical", b"state").unwrap();
        tentative
            .invalidate_coin_changes_in_transaction(txn.as_ref())
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(branch.stats().delta_entries, 1, "mode={mode}");
        assert_eq!(
            branch.stats().delta_bytes,
            b"test/canonical".len() + b"state".len(),
            "mode={mode}"
        );
        assert_eq!(branch.stats().read_operations, 0, "mode={mode}");
        assert_eq!(branch.stats().read_bytes, 0, "mode={mode}");
        assert!(branch.execution_healthy());
        assert!(db.get(b"test/canonical").unwrap().is_none());

        branch.prepare_commit().unwrap().commit(&db).unwrap();

        assert_eq!(
            db.get(b"test/canonical").unwrap().as_deref(),
            Some(b"state".as_slice())
        );
        if mode != "on" {
            assert_eq!(db.latest_sequence_number() - before, 1);
        }
    }
}

#[test]
fn optional_hooks_reject_closed_and_expired_overlays() {
    for mode in ["closed", "expired", "released"] {
        let store = RocksDb::open_in_memory().unwrap();
        let admission = quil_forest::ExecutionViewAdmission::new(
            4,
            if mode == "closed" {
                std::time::Duration::from_secs(60)
            } else {
                std::time::Duration::ZERO
            },
        );
        let branch = std::sync::Arc::new(
            ExecutionOverlay::capture_admitted(store.inner(), overlay_limits(), &admission)
                .unwrap(),
        );
        if mode == "closed" {
            branch.close();
        } else if mode == "released" {
            assert_eq!(admission.release_expired(), 1);
        }
        let tentative = quil_store::OverlayHypergraphStore::new(branch.clone());
        assert!(tentative
            .set_coin_changes_installing(b"test-scope", true)
            .is_err());
        assert!(!branch.execution_healthy());
        assert!(branch.prepare_commit().is_err());
    }
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
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let old = cursor(&db, 1);
    coin_changes::begin_install(&db, b"rewind/one").unwrap();
    coin_changes::begin_install(&db, b"rewind/one").unwrap();
    coin_changes::begin_install(&db, b"wipe/two").unwrap();
    coin_changes::finish_install(&db, b"rewind/one").unwrap();
    coin_changes::finish_install(&db, b"rewind/one").unwrap();
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
    drop(snapshot);
    drop(db);
    drop(store);
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
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
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    assert!(!hypergraph.is_coin_changes_installing(b"one").unwrap());
    coin_changes::begin_install(&db, b"one").unwrap();
    assert!(hypergraph.is_coin_changes_installing(b"one").unwrap());
    assert!(!hypergraph.is_coin_changes_installing(b"two").unwrap());
    drop(hypergraph);
    drop(db);
    drop(store);
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
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
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
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
fn opening_an_unfinished_import_without_staging_reports_recovery_failure() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open(directory.path()).unwrap();
    store
        .inner()
        .put(coin_changes::SNAPSHOT_INSTALL_STATE, b"1")
        .unwrap();
    drop(store);

    let error = RocksDb::open(directory.path()).err().unwrap();
    assert!(error
        .to_string()
        .contains("unfinished installation has no retry source"));
}

#[test]
fn snapshot_import_missing_staging_does_not_finish_another_scope() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    coin_changes::begin_install(&db, b"unrelated-maintenance").unwrap();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    hypergraph
        .apply_snapshot(directory.path().to_str().unwrap())
        .unwrap();
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
    coin_changes::finish_install(&db, b"unrelated-maintenance").unwrap();
    assert!(!cursor(&db, 1).is_empty());
}

#[cfg(feature = "test-utils")]
#[test]
fn snapshot_import_failed_final_write_retains_staging_and_resumes_at_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("snapshot");
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
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

    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_ok());
    assert!(db.get(row(1, 4, 100)).unwrap().is_some());
    assert!(!staging.exists());
    assert!(!cursor(&db, 1).is_empty());
    assert!(coin_changes::cursor_head(&db, &[1; 32], &old)
        .unwrap()
        .is_none());
}

#[test]
fn snapshot_import_completion_is_independent_of_its_optional_projection() {
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("snapshot");
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let source = rocksdb::DB::open_default(&staging).unwrap();
    source.put(row(1, 4, 1), vec![4; 4096]).unwrap();
    drop(source);
    // Inject a projection failure without rejecting the canonical writes.
    db.put(b"quil/local/coin-changes/v1/installing", b"bad-count")
        .unwrap();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    hypergraph
        .apply_snapshot(directory.path().to_str().unwrap())
        .unwrap();
    assert!(!staging.exists());
    let snapshot = RocksHypergraphSnapshot::capture(db).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
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
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
    db.put(b"test/canonical", b"recover").unwrap();
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
    // A bad count leaves the begin request and INVALID durable.
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
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
    coin_changes::finish_install(&db, b"still-running").unwrap();
    assert!(!cursor(&db, 1).is_empty());
}

#[test]
fn journal_retention_expires_old_cursors_but_keeps_recent_continuations() {
    let db = memory_store();
    let old = cursor(&db, 1);
    for start in (0..900).step_by(4) {
        let mut batch = rocksdb::WriteBatch::default();
        for version in start..(start + 4).min(900) {
            batch.put(row(1, 2, version), vec![4; 65_536]);
        }
        db.write(batch).unwrap();
    }
    let recent = cursor(&db, 1);
    for start in (900..1100).step_by(4) {
        let mut batch = rocksdb::WriteBatch::default();
        for version in start..(start + 4).min(1100) {
            batch.put(row(1, 2, version), vec![5; 65_536]);
        }
        db.write(batch).unwrap();
    }
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
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let before = cursor(&db, 1);
    db.refuse_writes("injected storage failure");
    assert!(db.put(row(1, 1, 1), vec![1; 4096]).is_err());
    assert!(db.get(row(1, 1, 1)).unwrap().is_none());
    assert_eq!(cursor(&db, 1), before);
    drop(db);
    drop(store);
    let reopened = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
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

#[test]
fn stores_leave_the_projector_off_unless_explicitly_enabled() {
    let store = RocksDb::open_in_memory().unwrap();
    let db = store.inner();
    assert!(!db.has_local_projection(coin_changes::NAMESPACE).unwrap());
    let before = db.latest_sequence_number();
    db.put(row(1, 4, 1), vec![4; 4096]).unwrap();
    assert_eq!(db.latest_sequence_number() - before, 1);
    let snapshot = RocksHypergraphSnapshot::capture(db).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
}

#[test]
fn scope_overflow_recovers_after_all_recorded_requests_finish() {
    let db = memory_store();
    let old = cursor(&db, 1);
    for index in 0..129 {
        coin_changes::begin_install(&db, format!("scope/{index:03}").as_bytes()).unwrap();
    }
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
    for index in 0..128 {
        coin_changes::finish_install(&db, format!("scope/{index:03}").as_bytes()).unwrap();
    }
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
    coin_changes::finish_install(&db, b"scope/128").unwrap();
    assert!(!cursor(&db, 1).is_empty());
    assert!(
        coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000)
            .unwrap()
            .reset
    );
}

#[test]
fn disabling_then_reenabling_resets_old_cursors_but_retains_canonical_rows() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let old = cursor(&store.inner(), 1);
    store.inner().put(row(1, 1, 1), vec![1; 4096]).unwrap();
    drop(store);
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    assert!(coin_changes::cursor_head(&store.inner(), &[1; 32], &old)
        .unwrap()
        .is_some());
    drop(store);
    let store = RocksDb::open(directory.path()).unwrap();
    let db = store.inner();
    assert!(!db.has_local_projection(coin_changes::NAMESPACE).unwrap());
    db.put(row(1, 2, 2), vec![2; 4096]).unwrap();
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
    let before = db.latest_sequence_number();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    hypergraph
        .set_coin_changes_installing(b"unrelated", true)
        .unwrap();
    assert_eq!(db.latest_sequence_number(), before);
    drop(hypergraph);
    drop(snapshot);
    drop(db);
    drop(store);
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    assert!(db.get(row(1, 1, 1)).unwrap().is_some());
    assert!(db.get(row(1, 2, 2)).unwrap().is_some());
    assert!(!cursor(&db, 1).is_empty());
    assert!(
        coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000)
            .unwrap()
            .reset
    );
}

#[test]
fn verified_completed_maintenance_is_recovered_at_open() {
    for kind in ["wipe", "reset", "rewind"] {
        let directory = tempfile::tempdir().unwrap();
        let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
        let db = store.inner();
        let old = cursor(&db, 1);
        let mut scope = format!("{kind}/").into_bytes();
        scope.extend([7; 32]);
        if kind == "wipe" {
            scope.push(0);
        }
        if kind == "rewind" {
            let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
            hypergraph
                .begin_coin_changes_rewind(&scope, &[[0; 32]; 4])
                .unwrap();
        } else {
            coin_changes::begin_install(&db, &scope).unwrap();
        }
        drop(db);
        drop(store);
        let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
        let db = store.inner();
        let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
        assert!(
            !hypergraph.is_coin_changes_installing(&scope).unwrap(),
            "{kind}"
        );
        assert!(!cursor(&db, 1).is_empty(), "{kind}");
        assert!(
            coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000)
                .unwrap()
                .reset
        );
    }
}

#[cfg(feature = "test-utils")]
#[test]
fn a_partial_import_resumes_at_open_with_the_feed_disabled() {
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("snapshot");
    let store = RocksDb::open(directory.path()).unwrap();
    let source = rocksdb::DB::open_default(&staging).unwrap();
    for version in 0..101 {
        source.put(row(1, 4, version), vec![4; 4096]).unwrap();
    }
    drop(source);
    let hypergraph = quil_store::RocksHypergraphStore::new(store.inner());
    hypergraph.fail_commit_for_test(true);
    assert!(hypergraph
        .apply_snapshot(directory.path().to_str().unwrap())
        .is_err());
    assert!(store.inner().get(row(1, 4, 0)).unwrap().is_some());
    assert!(store.inner().get(row(1, 4, 100)).unwrap().is_none());
    drop(hypergraph);
    drop(store);
    let store = RocksDb::open(directory.path()).unwrap();
    let snapshot = RocksHypergraphSnapshot::capture(store.inner()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
    assert!(!staging.exists());
    for version in 0..101 {
        assert_eq!(
            store.inner().get(row(1, 4, version)).unwrap(),
            Some(vec![4; 4096])
        );
    }
}

#[test]
fn opening_with_stale_snapshot_staging_and_coin_maintenance_does_not_invent_an_import() {
    for (key, value) in [
        (
            b"quil/local/coin-changes/v1/install-overflow".as_slice(),
            b"1".to_vec(),
        ),
        (
            b"quil/local/coin-changes/v1/installing".as_slice(),
            1u64.to_be_bytes().to_vec(),
        ),
        (
            b"quil/local/coin-changes/v1/invalid".as_slice(),
            b"1".to_vec(),
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
        store.inner().put(key, value).unwrap();
        let staging = directory.path().join("snapshot");
        let source = rocksdb::DB::open_default(&staging).unwrap();
        source.put(b"test/canonical", b"staged").unwrap();
        drop(source);
        drop(store);

        let store = RocksDb::open(directory.path()).unwrap();
        assert!(store
            .inner()
            .get(coin_changes::SNAPSHOT_INSTALL_STATE)
            .unwrap()
            .is_none());
        let snapshot = RocksHypergraphSnapshot::capture(store.inner()).unwrap();
        assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
            .unwrap()
            .is_empty());
        assert!(staging.is_dir());
    }
}

#[test]
fn completed_import_does_not_become_pending_again_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("snapshot");
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let source = rocksdb::DB::open_default(&staging).unwrap();
    source.put(b"test/canonical", b"imported").unwrap();
    drop(source);
    store
        .inner()
        .put(b"quil/local/coin-changes/v1/installing", b"bad-count")
        .unwrap();
    let hypergraph = quil_store::RocksHypergraphStore::new(store.inner());
    hypergraph
        .apply_snapshot(directory.path().to_str().unwrap())
        .unwrap();
    store.inner().put(b"test/canonical", b"newer").unwrap();
    drop(hypergraph);
    drop(store);
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let snapshot = RocksHypergraphSnapshot::capture(store.inner()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_ok());
    let hypergraph = quil_store::RocksHypergraphStore::new(store.inner());
    hypergraph
        .apply_snapshot(directory.path().to_str().unwrap())
        .unwrap();
    assert_eq!(
        store.inner().get(b"test/canonical").unwrap().as_deref(),
        Some(b"newer".as_slice())
    );
}

#[test]
fn a_completed_import_allows_a_new_explicit_snapshot_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("snapshot");
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let hypergraph = quil_store::RocksHypergraphStore::new(store.inner());
    for value in [b"first".as_slice(), b"replacement".as_slice()] {
        let source = rocksdb::DB::open_default(&staging).unwrap();
        source.put(b"test/canonical", value).unwrap();
        drop(source);
        hypergraph
            .apply_snapshot(directory.path().to_str().unwrap())
            .unwrap();
        assert_eq!(
            store.inner().get(b"test/canonical").unwrap().as_deref(),
            Some(value)
        );
        assert!(!staging.exists());
        let snapshot = RocksHypergraphSnapshot::capture(store.inner()).unwrap();
        assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32]).is_ok());
    }
}

#[test]
fn deferred_scope_overflow_recovers_across_a_bounded_startup_scan() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let old = cursor(&store.inner(), 1);
    for index in 0..257 {
        coin_changes::begin_install(&store.inner(), format!("scope/{index:03}").as_bytes())
            .unwrap();
    }
    drop(store);
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    for index in 0..257 {
        coin_changes::finish_install(&db, format!("scope/{index:03}").as_bytes()).unwrap();
    }
    assert!(db
        .get(b"quil/local/coin-changes/v1/install-overflow")
        .unwrap()
        .is_none());
    assert!(!cursor(&db, 1).is_empty());
    assert!(
        coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000)
            .unwrap()
            .reset
    );
}

#[test]
fn ordinary_writes_during_scope_overflow_do_not_rotate_the_journal() {
    let db = memory_store();
    for index in 0..129 {
        coin_changes::begin_install(&db, format!("scope/{index:03}").as_bytes()).unwrap();
    }
    let before = db.latest_sequence_number();
    db.put(b"test/canonical", b"ordinary").unwrap();
    assert_eq!(db.latest_sequence_number() - before, 1);
}

#[test]
fn completed_resets_drain_deferred_requests_after_reopen() {
    for count in [257u64, 1025] {
        let directory = tempfile::tempdir().unwrap();
        let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
        for index in 0..count {
            let mut app = [7; 32];
            app[..8].copy_from_slice(&index.to_be_bytes());
            let scope = [b"reset/".as_slice(), app.as_slice()].concat();
            // The reset trees are already physically empty; only finish was lost.
            coin_changes::begin_install(&store.inner(), &scope).unwrap();
        }
        drop(store);
        let mut recovered = false;
        for attempt in 0..4 {
            let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
            let snapshot = RocksHypergraphSnapshot::capture(store.inner()).unwrap();
            let cursor = coin_changes::snapshot_cursor(&snapshot, &[1; 32]).unwrap();
            if count == 257 && attempt == 0 {
                assert!(
                    !cursor.is_empty(),
                    "257 completed scopes fit one recovery open"
                );
            }
            if !cursor.is_empty() {
                assert!(store
                    .inner()
                    .get(b"quil/local/coin-changes/v1/install-overflow")
                    .unwrap()
                    .is_none());
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "{count} completed reset scopes must make progress"
        );
    }
}

#[test]
fn one_batch_of_deferred_begins_writes_overflow_only_once() {
    let db = memory_store();
    for index in 0..128 {
        coin_changes::begin_install(&db, format!("scope/{index:03}").as_bytes()).unwrap();
    }
    let mut batch = rocksdb::WriteBatch::default();
    for index in 128..256 {
        let key = format!("quil/local/coin-changes/v1/install-requests/scope/{index:03}");
        batch.put(key, [1]);
    }
    let before = db.latest_sequence_number();
    db.write(batch).unwrap();
    // 128 original requests and one auxiliary overflow marker.
    assert_eq!(db.latest_sequence_number() - before, 129);
    for index in 128..256 {
        let key = format!("quil/local/coin-changes/v1/install-requests/scope/{index:03}");
        assert_eq!(db.get(key).unwrap().as_deref(), Some([1].as_slice()));
    }
}

#[test]
fn an_unreadable_journal_does_not_duplicate_coin_blobs_while_fenced() {
    for tracked in [false, true] {
        let db = memory_store();
        let old = cursor(&db, 1);
        if tracked {
            for index in 0..257 {
                coin_changes::begin_install(&db, format!("scope/{index:03}").as_bytes()).unwrap();
            }
            for index in 0..128 {
                coin_changes::finish_install(&db, format!("scope/{index:03}").as_bytes()).unwrap();
            }
        } else {
            db.put(b"quil/local/coin-changes/v1/install-overflow", b"1")
                .unwrap();
        }
        assert!(db
            .get(b"quil/local/coin-changes/v1/installing")
            .unwrap()
            .is_none());
        let before = db.latest_sequence_number();
        db.put(row(1, 4, 1), vec![4; 4096]).unwrap();
        assert_eq!(db.latest_sequence_number() - before, 1);
        assert_eq!(db.get(row(1, 4, 1)).unwrap(), Some(vec![4; 4096]));
        let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
        assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
            .unwrap()
            .is_empty());
        if tracked {
            for index in 128..257 {
                coin_changes::finish_install(&db, format!("scope/{index:03}").as_bytes()).unwrap();
            }
            assert!(
                coin_changes::read_page(&db, &[1; 32], &old, 8, 100_000)
                    .unwrap()
                    .reset
            );
            let resumed = cursor(&db, 1);
            db.put(row(1, 5, 1), vec![5; 4096]).unwrap();
            let page = coin_changes::read_page(&db, &[1; 32], &resumed, 8, 100_000).unwrap();
            assert!(!page.reset);
            assert_eq!(page.records.len(), 1);
            assert_eq!(page.records[0].key[32..], [5; 32]);
        }
    }
}

#[test]
fn malformed_optional_snapshot_scope_does_not_become_a_canonical_import() {
    for enabled in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
        store.inner().put(row(1, 4, 1), vec![4; 4096]).unwrap();
        store
            .inner()
            .put(
                b"quil/local/coin-changes/v1/install-scopes/snapshot-install",
                b"malformed",
            )
            .unwrap();
        drop(store);
        let store = RocksDb::open_with_coin_changes(directory.path(), enabled).unwrap();
        assert!(store
            .inner()
            .get(coin_changes::SNAPSHOT_INSTALL_STATE)
            .unwrap()
            .is_none());
        let snapshot = RocksHypergraphSnapshot::capture(store.inner()).unwrap();
        assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
            .unwrap()
            .is_empty());
        assert_eq!(
            store.inner().get(row(1, 4, 1)).unwrap(),
            Some(vec![4; 4096])
        );
    }
}

#[test]
fn startup_verifies_recorded_rewind_roots_without_changing_the_tree() {
    for case in ["matching", "different", "headless"] {
        let directory = tempfile::tempdir().unwrap();
        let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
        let db = store.inner();
        let app = [7; 32];
        let phase = quil_forest::Phase::VertexAdds;
        let forest = quil_forest::Forest::with_namespace(db.clone(), quil_store::FOREST_NAMESPACE);
        let staged = forest
            .stage_synced_phase(
                &app,
                phase,
                0,
                [(quil_forest::KeyHash([1; 32]), Some(vec![9]))],
                &[],
                None,
            )
            .unwrap();
        let root = staged.root();
        let mut batch = rocksdb::WriteBatch::default();
        for (key, value) in staged.puts() {
            batch.put(key, value);
        }
        if case != "headless" {
            let (key, value) = forest.head_version_put(&app, phase, 0).unwrap();
            batch.put(key, value);
        }
        db.write(batch).unwrap();
        staged.publish_memory().unwrap();
        let scope = [b"rewind/".as_slice(), app.as_slice()].concat();
        let mut targets = [root, [0; 32], [0; 32], [0; 32]];
        if case == "different" {
            targets[0] = [99; 32];
        }
        let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
        hypergraph
            .begin_coin_changes_rewind(&scope, &targets)
            .unwrap();
        drop(hypergraph);
        drop(forest);
        drop(db);
        drop(store);
        let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
        let db = store.inner();
        let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
        assert_eq!(
            hypergraph.is_coin_changes_installing(&scope).unwrap(),
            case != "matching"
        );
        let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
        assert_eq!(
            coin_changes::snapshot_cursor(&snapshot, &[7; 32])
                .unwrap()
                .is_empty(),
            case != "matching"
        );
        let forest = quil_forest::Forest::with_namespace(db, quil_store::FOREST_NAMESPACE);
        assert_eq!(
            forest.shard_phase_root(&app, phase, 0).unwrap(),
            Some(root),
            "{case}"
        );
    }
}

#[test]
fn private_reset_hints_follow_transaction_abort_and_fork_ownership() {
    for (publish_hint, finish, use_earlier_child) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        let db = memory_store();
        let start = cursor(&db, 1);
        let parent =
            std::sync::Arc::new(ExecutionOverlay::capture(db.clone(), overlay_limits()).unwrap());
        let branch = quil_store::OverlayHypergraphStore::new(parent.clone());
        let clean_child = parent.fork(overlay_limits()).unwrap();
        let txn = branch.new_transaction(false).unwrap();
        branch
            .invalidate_coin_changes_in_transaction(txn.as_ref())
            .unwrap();
        txn.abort().unwrap();
        if publish_hint {
            branch
                .set_coin_changes_installing(b"private-reset", true)
                .unwrap();
        }
        if finish {
            branch
                .set_coin_changes_installing(b"private-reset", false)
                .unwrap();
        }
        let child = parent.fork(overlay_limits()).unwrap();
        assert_eq!(parent.stats().delta_entries, 0);
        assert_eq!(parent.stats().delta_bytes, 0);
        assert_eq!(cursor(&db, 1), start);
        // A child captured before its parent's hint must remain independent.
        parent.close();
        if use_earlier_child {
            clean_child.prepare_commit().unwrap().commit(&db).unwrap();
        } else {
            child.prepare_commit().unwrap().commit(&db).unwrap();
        }
        assert_eq!(
            coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000)
                .unwrap()
                .reset,
            publish_hint && !use_earlier_child
        );
    }
}

#[test]
fn private_maintenance_keeps_prior_durable_scope_visible_without_read_budget() {
    let db = memory_store();
    coin_changes::begin_install(&db, b"prior-wipe").unwrap();
    db.put(
        b"quil/local/coin-changes/v1/install-scopes/oversized",
        vec![0; 256 << 10],
    )
    .unwrap();
    let parent = std::sync::Arc::new(
        ExecutionOverlay::capture(
            db.clone(),
            OverlayLimits {
                max_read_operations: 0,
                ..overlay_limits()
            },
        )
        .unwrap(),
    );
    let branch = quil_store::OverlayHypergraphStore::new(parent.clone());
    assert!(branch.is_coin_changes_installing(b"prior-wipe").unwrap());
    assert!(branch.is_coin_changes_installing(b"oversized").is_err());
    assert!(parent.execution_healthy());

    branch
        .set_coin_changes_installing(b"private-reset", true)
        .unwrap();
    branch
        .set_coin_changes_installing(b"private-reset", false)
        .unwrap();
    assert!(branch.is_coin_changes_installing(b"prior-wipe").unwrap());
    assert_eq!(parent.stats().read_operations, 0);
    parent.prepare_commit().unwrap().commit(&db).unwrap();
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
    assert_eq!(
        db.get(b"quil/local/coin-changes/v1/installing")
            .unwrap()
            .unwrap(),
        1u64.to_be_bytes()
    );
}

#[test]
fn projection_work_limits_preserve_canonical_rows_and_force_rescan() {
    for large_input in [false, true] {
        let db = memory_store();
        let start = cursor(&db, 1);
        let mut batch = rocksdb::WriteBatch::default();
        let expected = if large_input {
            let value = vec![6; 9 << 20];
            batch.put(b"test/canonical-large", &value);
            vec![(b"test/canonical-large".to_vec(), value)]
        } else {
            (0..40)
                .map(|index| {
                    let key = row(1, index, 1);
                    let value = vec![6; 32 << 10];
                    batch.put(&key, &value);
                    (key, value)
                })
                .collect::<Vec<_>>()
        };
        db.write(batch).unwrap();
        for (key, value) in expected {
            assert_eq!(db.get(key).unwrap(), Some(value));
        }
        assert!(!db.write_failed());
        assert!(db
            .get(b"quil/local/coin-changes/v1/invalid")
            .unwrap()
            .is_some());
        assert!(
            coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000)
                .unwrap()
                .reset
        );
        // Recovery rotates the epoch; subsequent small arrivals remain discoverable.
        db.put(b"test/canonical", b"recovery").unwrap();
        let resumed = cursor(&db, 1);
        db.put(row(1, 99, 1), vec![7; 4096]).unwrap();
        let page = coin_changes::read_page(&db, &[1; 32], &resumed, 8, 100_000).unwrap();
        assert!(!page.reset);
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].key[32..], [99; 32]);
    }
}

#[test]
fn private_shard_clear_uses_only_the_eight_canonical_range_entries() {
    let db = memory_store();
    let parent = std::sync::Arc::new(
        ExecutionOverlay::capture(
            db.clone(),
            OverlayLimits {
                max_delta_entries: 8,
                ..overlay_limits()
            },
        )
        .unwrap(),
    );
    let branch = quil_store::OverlayHypergraphStore::new(parent.clone());
    branch
        .clear_shard_underlying(&ShardKey {
            l1: [7; 3],
            l2: [1; 32],
        })
        .unwrap();
    assert!(parent.execution_healthy());
    assert_eq!(parent.stats().delta_entries, 8);
    parent.prepare_commit().unwrap().commit(&db).unwrap();
}

#[test]
fn private_recovery_can_finish_a_prior_durable_scope() {
    for cancel in [false, true] {
        let db = memory_store();
        let start = cursor(&db, 1);
        coin_changes::begin_install(&db, b"prior-wipe").unwrap();
        let parent = std::sync::Arc::new(
            ExecutionOverlay::capture(
                db.clone(),
                OverlayLimits {
                    max_read_operations: 0,
                    max_delta_entries: 0,
                    ..overlay_limits()
                },
            )
            .unwrap(),
        );
        let branch = quil_store::OverlayHypergraphStore::new(parent.clone());
        assert!(branch.is_coin_changes_installing(b"prior-wipe").unwrap());
        branch
            .set_coin_changes_installing(b"prior-wipe", false)
            .unwrap();
        if cancel {
            branch
                .set_coin_changes_installing(b"prior-wipe", true)
                .unwrap();
        }
        assert!(db
            .get(b"quil/local/coin-changes/v1/installing")
            .unwrap()
            .is_some());
        parent.prepare_commit().unwrap().commit(&db).unwrap();
        assert_eq!(
            db.get(b"quil/local/coin-changes/v1/installing")
                .unwrap()
                .is_some(),
            cancel
        );
        let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
        assert_eq!(
            coin_changes::snapshot_cursor(&snapshot, &[1; 32])
                .unwrap()
                .is_empty(),
            cancel
        );
        assert!(
            coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000)
                .unwrap()
                .reset
        );
    }
}

#[test]
fn a_persisted_untracked_fence_survives_recovery_of_old_tracked_overflow() {
    let db = memory_store();
    let start = cursor(&db, 1);
    db.put(b"quil/local/coin-changes/v1/install-overflow", b"2")
        .unwrap();
    let mut batch = rocksdb::WriteBatch::default();
    batch.put(b"quil/local/coin-changes/v1/install-overflow", b"1");
    batch.put(b"test/canonical", b"state");
    db.write(batch).unwrap();
    assert_eq!(
        db.get(b"test/canonical").unwrap().as_deref(),
        Some(b"state".as_slice())
    );
    assert_eq!(
        db.get(b"quil/local/coin-changes/v1/install-overflow")
            .unwrap()
            .as_deref(),
        Some(b"1".as_slice())
    );
    let snapshot = RocksHypergraphSnapshot::capture(db.clone()).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
    assert!(
        coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000)
            .unwrap()
            .reset
    );
}

#[test]
fn invalid_recovery_without_maintenance_completion_keeps_untracked_overflow() {
    let db = memory_store();
    let overflow_key = b"quil/local/coin-changes/v1/install-overflow";
    db.put(overflow_key, b"1").unwrap();
    db.put(b"quil/local/coin-changes/v1/invalid", b"1").unwrap();
    db.put(b"test/canonical", b"ordinary").unwrap();
    assert_eq!(
        db.get(overflow_key).unwrap().as_deref(),
        Some(b"1".as_slice())
    );
}

#[test]
fn finishing_tracked_scope_does_not_clear_new_untracked_overlay_scope() {
    let db = memory_store();
    let overflow_key = b"quil/local/coin-changes/v1/install-overflow";
    coin_changes::begin_install(&db, b"tracked").unwrap();
    db.put(overflow_key, b"1").unwrap();
    db.put(b"test/canonical", b"state").unwrap();
    coin_changes::finish_install(&db, b"tracked").unwrap();

    assert_eq!(
        db.get(overflow_key).unwrap().as_deref(),
        Some(b"1".as_slice())
    );
    let snapshot = RocksHypergraphSnapshot::capture(db).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &[1; 32])
        .unwrap()
        .is_empty());
}

#[test]
fn private_rewind_hints_beyond_tracked_slots_recover_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let start = cursor(&db, 1);
    let parent =
        std::sync::Arc::new(ExecutionOverlay::capture(db.clone(), overlay_limits()).unwrap());
    let branch = quil_store::OverlayHypergraphStore::new(parent.clone());
    let scopes: Vec<Vec<u8>> = (0..129)
        .map(|index| {
            let mut app = [0; 32];
            app[0] = index as u8;
            [b"rewind/".as_slice(), app.as_slice()].concat()
        })
        .collect();
    for scope in &scopes {
        branch
            .begin_coin_changes_rewind(scope, &[[7; 32]; 4])
            .unwrap();
    }
    parent.prepare_commit().unwrap().commit(&db).unwrap();
    assert_eq!(
        db.get(b"quil/local/coin-changes/v1/install-overflow")
            .unwrap()
            .as_deref(),
        Some(b"2".as_slice()),
    );
    drop(branch);
    drop(parent);
    drop(db);
    drop(store);

    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    for scope in &scopes {
        coin_changes::finish_install(&db, scope).unwrap();
    }
    assert!(db
        .get(b"quil/local/coin-changes/v1/install-overflow")
        .unwrap()
        .is_none());
    assert!(
        coin_changes::read_page(&db, &[1; 32], &start, 8, 100_000)
            .unwrap()
            .reset
    );
    assert!(!cursor(&db, 1).is_empty());
}

#[test]
fn private_maintenance_hint_budget_rejects_canonical_commit() {
    let db = memory_store();
    let parent = ExecutionOverlay::capture(db.clone(), overlay_limits()).unwrap();
    parent
        .apply(&[OverlayMutation::Put(
            b"test/canonical".to_vec(),
            b"state".to_vec(),
        )])
        .unwrap();
    let mut rejected = false;
    for index in 0..513 {
        let key = format!("quil/local/coin-changes/v1/install-requests/scope/{index:03}");
        if parent
            .stage_local_projection_records(
                coin_changes::NAMESPACE,
                b"quil/local/coin-changes/v1/reset-request",
                &[(key.as_bytes(), &[1])],
            )
            .is_err()
        {
            rejected = true;
            break;
        }
    }
    assert!(rejected);
    assert!(parent.prepare_commit().is_err());
    assert!(db.get(b"test/canonical").unwrap().is_none());
    assert!(db
        .get(b"quil/local/coin-changes/v1/install-overflow")
        .unwrap()
        .is_none());
}

#[test]
fn durable_requests_after_a_projection_limit_remain_recoverable() {
    for reopen in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
        let db = store.inner();
        let mut batch = rocksdb::WriteBatch::default();
        for index in 0..129 {
            let key = format!("quil/local/coin-changes/v1/install-requests/scope/{index:03}");
            batch.put(key, [1]);
        }
        batch.put(b"test/oversized-canonical", vec![7; 9 << 20]);
        db.write(batch).unwrap();
        assert!(db
            .get(b"quil/local/coin-changes/v1/invalid")
            .unwrap()
            .is_some());
        if reopen {
            drop(db);
            drop(store);
            let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
            assert_eq!(
                store
                    .inner()
                    .get(b"quil/local/coin-changes/v1/install-overflow")
                    .unwrap()
                    .as_deref(),
                Some(b"2".as_slice()),
            );
        } else {
            db.put(b"test/recover", b"1").unwrap();
            assert_eq!(
                db.get(b"quil/local/coin-changes/v1/install-overflow")
                    .unwrap()
                    .as_deref(),
                Some(b"2".as_slice()),
            );
        }
    }
}

#[test]
fn completed_durable_requests_drain_at_first_recovery_open() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let mut batch = rocksdb::WriteBatch::default();
    for index in 0..129 {
        let key = format!("quil/local/coin-changes/v1/install-requests/scope/{index:03}");
        batch.put(key, [0]);
    }
    batch.put(b"test/oversized-canonical", vec![7; 9 << 20]);
    db.write(batch).unwrap();
    drop(db);
    drop(store);

    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    assert!(db
        .get(b"quil/local/coin-changes/v1/install-overflow")
        .unwrap()
        .is_none());
    assert!(!cursor(&db, 1).is_empty());
}

#[test]
fn malformed_overflow_remains_an_untracked_fence_during_deferred_recovery() {
    for reopen in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
        let db = store.inner();
        let overflow_key = b"quil/local/coin-changes/v1/install-overflow";
        db.put(overflow_key, b"unexpected").unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        for index in 0..129 {
            let key = format!("quil/local/coin-changes/v1/install-requests/scope/{index:03}");
            batch.put(key, [0]);
        }
        batch.put(b"test/oversized-canonical", vec![7; 9 << 20]);
        db.write(batch).unwrap();
        if reopen {
            drop(db);
            drop(store);
            let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
            assert_eq!(
                store.inner().get(overflow_key).unwrap().as_deref(),
                Some(b"1".as_slice()),
            );
        } else {
            db.put(b"test/recover", b"1").unwrap();
            assert_eq!(
                db.get(overflow_key).unwrap().as_deref(),
                Some(b"1".as_slice())
            );
        }
    }
}

#[test]
fn snapshot_retry_does_not_finish_another_scope_from_partial_canonical_state() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let app = [7; 32];
    let scope = [b"wipe/".as_slice(), app.as_slice(), &[0]].concat();
    coin_changes::begin_install(&db, &scope).unwrap();
    db.put(coin_changes::SNAPSHOT_INSTALL_STATE, b"1").unwrap();

    let source = rocksdb::DB::open_default(directory.path().join("snapshot")).unwrap();
    let forest = quil_forest::Forest::with_namespace(db.clone(), quil_store::FOREST_NAMESPACE);
    let phase = quil_forest::Phase::VertexAdds;
    let staged = forest
        .stage_synced_phase(
            &app,
            phase,
            0,
            [(quil_forest::KeyHash([1; 32]), Some(vec![9]))],
            &[],
            None,
        )
        .unwrap();
    for (key, value) in staged.puts() {
        source.put(key, value).unwrap();
    }
    let (head_key, head_value) = forest.head_version_put(&app, phase, 0).unwrap();
    source.put(head_key, head_value).unwrap();
    drop(source);
    drop(forest);
    drop(db);
    drop(store);

    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    assert!(hypergraph.is_coin_changes_installing(&scope).unwrap());
    let snapshot = RocksHypergraphSnapshot::capture(db).unwrap();
    assert!(coin_changes::snapshot_cursor(&snapshot, &app)
        .unwrap()
        .is_empty());
}

#[test]
fn snapshot_retry_finishes_a_rewind_only_after_imported_roots_match() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let app = [8; 32];
    let scope = [b"rewind/".as_slice(), app.as_slice()].concat();
    let source = rocksdb::DB::open_default(directory.path().join("snapshot")).unwrap();
    let forest = quil_forest::Forest::with_namespace(db.clone(), quil_store::FOREST_NAMESPACE);
    let phase = quil_forest::Phase::VertexAdds;
    let staged = forest
        .stage_synced_phase(
            &app,
            phase,
            0,
            [(quil_forest::KeyHash([1; 32]), Some(vec![9]))],
            &[],
            None,
        )
        .unwrap();
    for (key, value) in staged.puts() {
        source.put(key, value).unwrap();
    }
    let (head_key, head_value) = forest.head_version_put(&app, phase, 0).unwrap();
    source.put(head_key, head_value).unwrap();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    hypergraph
        .begin_coin_changes_rewind(&scope, &[staged.root(), [0; 32], [0; 32], [0; 32]])
        .unwrap();
    db.put(coin_changes::SNAPSHOT_INSTALL_STATE, b"1").unwrap();
    drop(hypergraph);
    drop(source);
    drop(forest);
    drop(db);
    drop(store);

    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let hypergraph = quil_store::RocksHypergraphStore::new(db.clone());
    assert!(!hypergraph.is_coin_changes_installing(&scope).unwrap());
    assert!(!cursor(&db, 8).is_empty());
}

#[test]
fn snapshot_retry_drains_completed_deferred_requests_at_open() {
    let directory = tempfile::tempdir().unwrap();
    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    let source = rocksdb::DB::open_default(directory.path().join("snapshot")).unwrap();
    source.put(b"test/snapshot-source", b"complete").unwrap();
    drop(source);
    let mut batch = rocksdb::WriteBatch::default();
    batch.put(coin_changes::SNAPSHOT_INSTALL_STATE, b"1");
    for index in 0..400 {
        let key = format!("quil/local/coin-changes/v1/install-requests/scope/{index:03}");
        batch.put(key, [0]);
    }
    batch.put(b"test/oversized-canonical", vec![7; 9 << 20]);
    db.write(batch).unwrap();
    drop(db);
    drop(store);

    let store = RocksDb::open_with_coin_changes(directory.path(), true).unwrap();
    let db = store.inner();
    assert!(db
        .get(b"quil/local/coin-changes/v1/install-overflow")
        .unwrap()
        .is_none());
    assert!(!cursor(&db, 1).is_empty());
}
