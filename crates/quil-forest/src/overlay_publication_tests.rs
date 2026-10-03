use super::*;
use crate::{CoordinatedDb, DatabaseCommitError};
use std::io::{BufRead, Write};
use std::sync::{mpsc, Barrier};
use std::time::Duration;

fn limits() -> OverlayLimits {
    OverlayLimits {
        max_delta_bytes: 1 << 20,
        max_delta_entries: 10_000,
        max_record_bytes: 1 << 16,
        max_read_bytes: 1 << 20,
        max_read_operations: 100_000,
        max_cursors: 8,
    }
}

fn open(path: &std::path::Path) -> CoordinatedDb {
    CoordinatedDb::new(rocksdb::DB::open_default(path).unwrap())
}

fn put(key: &[u8], value: &[u8]) -> OverlayMutation {
    OverlayMutation::Put(key.to_vec(), value.to_vec())
}

fn rows(db: &CoordinatedDb) -> Vec<(Vec<u8>, Vec<u8>)> {
    db.iterator(rocksdb::IteratorMode::Start)
        .map(|row| {
            let (k, v) = row.unwrap();
            (k.to_vec(), v.to_vec())
        })
        .collect()
}

#[test]
fn publication_preserves_range_order_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    for key in [b"a", b"b", b"c", b"d", b"e", b"z"] {
        db.put(key, b"old").unwrap();
    }
    let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    overlay
        .apply(&[
            put(b"b", b"discarded"),
            OverlayMutation::DeleteRange(b"a".to_vec(), b"d".to_vec()),
            put(b"c", b"restored"),
            OverlayMutation::Delete(b"e".to_vec()),
            put(b"f", b"new"),
            OverlayMutation::DeleteRange(b"d".to_vec(), b"e".to_vec()),
        ])
        .unwrap();
    let before = rows(&db);
    let plan = overlay.prepare_commit().unwrap();
    assert!(overlay.stats().closed);
    assert!(overlay.get(b"c").is_err());
    assert!(overlay.apply(&[put(b"late", b"write")]).is_err());
    assert_eq!(rows(&db), before);
    plan.commit(&db).unwrap();
    let expected = vec![
        (b"c".to_vec(), b"restored".to_vec()),
        (b"f".to_vec(), b"new".to_vec()),
        (b"z".to_vec(), b"old".to_vec()),
    ];
    assert_eq!(rows(&db), expected);
    drop(db);
    assert_eq!(rows(&open(dir.path())), expected);
}

#[test]
fn publication_rejects_intervening_writes_including_aba_without_partial_effects() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    db.put(b"state", b"base").unwrap();
    let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    overlay
        .apply(&[put(b"state", b"executed"), put(b"cursor", b"1")])
        .unwrap();
    db.put(b"state", b"changed").unwrap();
    db.put(b"state", b"base").unwrap();
    let sequence = db.latest_sequence_number();
    assert!(matches!(
        overlay.prepare_commit().unwrap().commit(&db),
        Err(DatabaseCommitError::Stale { .. })
    ));
    assert_eq!(db.latest_sequence_number(), sequence);
    assert_eq!(
        db.get(b"state").unwrap().as_deref(),
        Some(b"base".as_slice())
    );
    assert_eq!(db.get(b"cursor").unwrap(), None);
}

static CANDIDATES: &[[u8; 2]] = &[[0x00, 0x0f], [0x00, 0xf8]];

fn candidate_write(db: &CoordinatedDb, key: &[u8]) -> Result<(), DatabaseCommitError> {
    let mut batch = crate::DisjointBatch::new(CANDIDATES);
    batch.put(key, b"candidate")?;
    db.write_disjoint(batch, &rocksdb::WriteOptions::default())
}

#[test]
fn disjoint_writes_outside_the_branch_footprint_do_not_invalidate_publication() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    db.put(b"\x00\x00frame", b"base").unwrap();
    let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    assert!(overlay.get(b"\x00\x00frame").unwrap().is_some());
    {
        let mut cursor = overlay.cursor(b"\x00\x00", b"\x00\x01").unwrap();
        cursor.seek(b"\x00\x00").unwrap();
        assert!(cursor.valid());
    }
    overlay
        .apply(&[put(b"\x00\x00frame", b"executed"), put(b"\x00\x09cursor", b"1")])
        .unwrap();
    candidate_write(&db, b"\x00\x0fnext").unwrap();
    candidate_write(&db, b"\x00\xf8next-body").unwrap();
    overlay.prepare_commit().unwrap().commit(&db).unwrap();
    assert_eq!(
        rows(&db),
        vec![
            (b"\x00\x00frame".to_vec(), b"executed".to_vec()),
            (b"\x00\x09cursor".to_vec(), b"1".to_vec()),
            (b"\x00\x0fnext".to_vec(), b"candidate".to_vec()),
            (b"\x00\xf8next-body".to_vec(), b"candidate".to_vec()),
        ]
    );
    // A later general write still invalidates a new plan.
    let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    overlay.apply(&[put(b"\x00\x09cursor", b"2")]).unwrap();
    db.put(b"unrelated", b"general").unwrap();
    assert!(matches!(
        overlay.prepare_commit().unwrap().commit(&db),
        Err(DatabaseCommitError::Stale { .. })
    ));
    assert_eq!(db.get(b"\x00\x09cursor").unwrap().as_deref(), Some(b"1".as_slice()));
}

#[test]
fn disjoint_write_to_a_read_scanned_written_or_inherited_prefix_rejects_publication() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let read = |overlay: &ExecutionOverlay| {
        overlay.get(b"\x00\x0fparent").unwrap();
    };
    let scan = |overlay: &ExecutionOverlay| {
        // The scan's upper bound marks its own prefix conservatively.
        overlay.cursor(b"\x00\x0e", b"\x00\x0f\x00").unwrap();
    };
    let write = |overlay: &ExecutionOverlay| {
        overlay
            .apply(&[OverlayMutation::DeleteRange(b"\x00\x0e".to_vec(), b"\x00\x0fzz".to_vec())])
            .unwrap();
    };
    let touches: [&dyn Fn(&ExecutionOverlay); 3] = [&read, &scan, &write];
    for touch in touches {
        let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
        touch(&overlay);
        overlay.apply(&[put(b"\x00\x09cursor", b"1")]).unwrap();
        candidate_write(&db, b"\x00\x0fparent").unwrap();
        let sequence = db.latest_sequence_number();
        assert!(matches!(
            overlay.prepare_commit().unwrap().commit(&db),
            Err(DatabaseCommitError::Stale { .. })
        ));
        assert_eq!(db.latest_sequence_number(), sequence);
        assert_eq!(db.get(b"\x00\x09cursor").unwrap(), None);
    }
    // A child inherits the prefixes its parent touched before the fork.
    let parent = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    read(&parent);
    let child = parent.fork(limits()).unwrap();
    child.apply(&[put(b"\x00\x09cursor", b"1")]).unwrap();
    candidate_write(&db, b"\x00\x0fparent").unwrap();
    assert!(matches!(
        child.prepare_commit().unwrap().commit(&db),
        Err(DatabaseCommitError::Stale { .. })
    ));
    assert_eq!(db.get(b"\x00\x09cursor").unwrap(), None);
}

#[test]
fn disjoint_batches_refuse_keys_and_ranges_outside_their_prefixes() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let mut batch = crate::DisjointBatch::new(CANDIDATES);
    assert!(matches!(batch.put(b"\x00\x00frame", b"x"), Err(DatabaseCommitError::OutsideKeyspace)));
    assert!(matches!(batch.delete(b"\x00"), Err(DatabaseCommitError::OutsideKeyspace)));
    assert!(matches!(
        batch.delete_range(b"\x00\x0f", b"\x00\x10"),
        Err(DatabaseCommitError::OutsideKeyspace)
    ));
    assert!(matches!(
        batch.delete_range(b"\x00\x0fz", b"\x00\x0fa"),
        Err(DatabaseCommitError::OutsideKeyspace)
    ));
    assert!(batch.is_empty());
    batch.delete_range(b"\x00\xf8a", b"\x00\xf8\xff").unwrap();
    db.write_disjoint(batch, &rocksdb::WriteOptions::default()).unwrap();
    assert!(rows(&db).is_empty());
}

#[test]
fn publication_rejects_an_identical_but_foreign_database() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let source = open(a.path());
    let foreign = open(b.path());
    let overlay = ExecutionOverlay::capture(source.clone(), limits()).unwrap();
    overlay.apply(&[put(b"cursor", b"1")]).unwrap();
    assert_eq!(
        source.latest_sequence_number(),
        foreign.latest_sequence_number()
    );
    assert!(matches!(
        overlay.prepare_commit().unwrap().commit(&foreign),
        Err(DatabaseCommitError::ForeignDatabase)
    ));
    assert!(rows(&source).is_empty());
    assert!(rows(&foreign).is_empty());
}

#[test]
fn publication_failure_and_abandonment_release_snapshots_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    overlay.apply(&[put(b"cursor", b"1")]).unwrap();
    let plan = overlay.prepare_commit().unwrap();
    assert_eq!(
        db.property_int_value("rocksdb.num-snapshots").unwrap(),
        Some(0)
    );
    assert!(overlay.prepare_commit().is_err());
    drop(plan);
    assert!(rows(&db).is_empty());

    let failed = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    failed.apply(&[put(b"cursor", b"1")]).unwrap();
    assert!(failed
        .apply(&[OverlayMutation::Put(
            vec![9; limits().max_record_bytes + 1],
            vec![]
        )])
        .is_err());
    assert!(failed.prepare_commit().is_err());
    failed.close();
    assert!(rows(&db).is_empty());
}

#[test]
fn publication_holds_shared_barrier_through_following_metadata_adoption() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    overlay
        .apply(&[put(b"state", b"executed"), put(b"cursor", b"1")])
        .unwrap();
    let plan = overlay.prepare_commit().unwrap();
    let mut guard = db.lock_writes().unwrap();
    let writer = db.clone();
    let (starting_tx, starting_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        starting_tx.send(()).unwrap();
        writer.put(b"state", b"later").unwrap();
        finished_tx.send(()).unwrap();
    });
    starting_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    plan.commit_locked(&mut guard).unwrap();
    assert_eq!(
        db.get(b"state").unwrap().as_deref(),
        Some(b"executed".as_slice())
    );
    assert!(finished_rx.recv_timeout(Duration::from_millis(30)).is_err());
    // An execution owner adopts its already-prepared metadata here, while
    // every other writer is still excluded by this same guard.
    drop(guard);
    finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    thread.join().unwrap();
    assert_eq!(
        db.get(b"state").unwrap().as_deref(),
        Some(b"later".as_slice())
    );
    assert_eq!(db.get(b"cursor").unwrap().as_deref(), Some(b"1".as_slice()));
}

#[test]
fn publication_allows_only_one_competing_sibling() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let parent = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    let child = parent.fork(limits()).unwrap();
    parent
        .apply(&[put(b"state", b"parent"), put(b"cursor", b"1")])
        .unwrap();
    child
        .apply(&[put(b"state", b"child"), put(b"cursor", b"2")])
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = [
        parent.prepare_commit().unwrap(),
        child.prepare_commit().unwrap(),
    ]
    .into_iter()
    .map(|plan| {
        let barrier = barrier.clone();
        let db = db.clone();
        std::thread::spawn(move || {
            barrier.wait();
            plan.commit(&db)
        })
    })
    .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(DatabaseCommitError::Stale { .. })))
            .count(),
        1
    );
    let state = db.get(b"state").unwrap().unwrap();
    let cursor = db.get(b"cursor").unwrap().unwrap();
    assert!((state == b"parent" && cursor == b"1") || (state == b"child" && cursor == b"2"));
}

#[test]
fn publication_write_failure_leaves_all_records_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    {
        let db = open(dir.path());
        db.put(b"state", b"base").unwrap();
    }
    let db = CoordinatedDb::new(
        rocksdb::DB::open_for_read_only(&rocksdb::Options::default(), dir.path(), false).unwrap(),
    );
    let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    overlay
        .apply(&[put(b"state", b"executed"), put(b"cursor", b"1")])
        .unwrap();
    let before = rows(&db);
    assert!(matches!(
        overlay.prepare_commit().unwrap().commit(&db),
        Err(DatabaseCommitError::Storage(_))
    ));
    assert_eq!(rows(&db), before);
    assert!(matches!(
        db.put(b"retry", b"unsafe"),
        Err(DatabaseCommitError::PriorWriteFailed)
    ));
    assert!(ExecutionOverlay::capture(db.clone(), limits()).is_err());
}

#[test]
fn poisoned_database_barrier_blocks_writes_and_new_execution() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    overlay.apply(&[put(b"state", b"executed")]).unwrap();
    let plan = overlay.prepare_commit().unwrap();
    let source = db.clone();
    assert!(std::thread::spawn(move || {
        let _guard = source.lock_writes().unwrap();
        panic!("injected owner panic");
    })
    .join()
    .is_err());
    assert!(matches!(
        db.put(b"state", b"bad"),
        Err(DatabaseCommitError::Poisoned)
    ));
    assert!(matches!(
        plan.commit(&db),
        Err(DatabaseCommitError::Poisoned)
    ));
    assert!(ExecutionOverlay::capture(db.clone(), limits()).is_err());
    assert!(rows(&db).is_empty());
}

/// The parent kills this subprocess after observing its explicit boundary.
#[test]
#[ignore = "subprocess helper for publication_survives_process_death"]
fn publication_crash_child() {
    let path = std::env::var_os("QUIL_PUBLICATION_CRASH_PATH").expect("child path");
    let stage = std::env::var("QUIL_PUBLICATION_CRASH_STAGE").expect("child stage");
    let db = open(std::path::Path::new(&path));
    let mut base = rocksdb::WriteBatch::default();
    base.put(b"cursor", b"0");
    base.put(b"state", b"old");
    let mut options = rocksdb::WriteOptions::default();
    options.set_sync(true);
    db.write_opt(base, &options).unwrap();
    let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
    overlay
        .apply(&[
            put(b"cursor", b"1"),
            put(b"state", b"new"),
            put(b"receipt", b"complete"),
            put(b"outcomes", b"saved"),
        ])
        .unwrap();
    let plan = overlay.prepare_commit().unwrap();
    if stage == "after" {
        plan.commit(&db).unwrap();
    }
    println!("PUBLICATION_READY:{stage}");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn publication_survives_process_death_before_and_after_synced_commit() {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for stage in ["before", "after"] {
        let dir = tempfile::tempdir().unwrap();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "overlay::publication_tests::publication_crash_child",
                    "--nocapture",
                ])
                .env("QUIL_PUBLICATION_CRASH_PATH", dir.path())
                .env("QUIL_PUBLICATION_CRASH_STAGE", stage)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if line.starts_with("PUBLICATION_READY:") {
                    let _ = tx.send(line);
                    return;
                }
            }
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(30)).unwrap(),
            format!("PUBLICATION_READY:{stage}")
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        reader.join().unwrap();
        let db = open(dir.path());
        if stage == "before" {
            assert_eq!(db.get(b"cursor").unwrap().as_deref(), Some(b"0".as_slice()));
            assert_eq!(
                db.get(b"state").unwrap().as_deref(),
                Some(b"old".as_slice())
            );
            assert_eq!(db.get(b"receipt").unwrap(), None);
            assert_eq!(db.get(b"outcomes").unwrap(), None);
        } else {
            assert_eq!(db.get(b"cursor").unwrap().as_deref(), Some(b"1".as_slice()));
            assert_eq!(
                db.get(b"state").unwrap().as_deref(),
                Some(b"new".as_slice())
            );
            assert_eq!(
                db.get(b"receipt").unwrap().as_deref(),
                Some(b"complete".as_slice())
            );
            assert_eq!(
                db.get(b"outcomes").unwrap().as_deref(),
                Some(b"saved".as_slice())
            );
        }
    }
}
