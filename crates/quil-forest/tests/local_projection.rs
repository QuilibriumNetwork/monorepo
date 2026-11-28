use std::sync::Arc;

use quil_forest::{CoordinatedDb, LocalBatchProjection, LocalProjectionBatch, LocalProjectionRead};

enum Projector {
    Commit,
    Error,
    Panic,
    EscapeNamespace,
    OutputLimit,
    ReadLimit,
}

impl LocalBatchProjection for Projector {
    fn namespace(&self) -> &'static [u8] {
        b"local-test/"
    }

    fn project(
        &self,
        view: &LocalProjectionRead<'_>,
        _: &[u8],
        output: &mut LocalProjectionBatch,
    ) -> Result<(), String> {
        assert_eq!(view.get(b"canonical").unwrap(), None);
        if matches!(self, Self::EscapeNamespace) {
            // Ignoring a rejected mutation must still invalidate the projection.
            let _ = output.put(b"canonical", b"corrupted");
            return Ok(());
        }
        output.put_owned(b"local-test/projected".to_vec(), b"same-batch".to_vec())?;
        if matches!(self, Self::OutputLimit) {
            output.put(b"local-test/oversized", vec![0; 2 << 20])?;
        }
        if matches!(self, Self::ReadLimit) {
            view.get(b"oversized-read")?;
        }
        if matches!(self, Self::Error) {
            return Err("projection error after staging output".into());
        }
        if matches!(self, Self::Panic) {
            panic!("projection failed after staging its output");
        }
        Ok(())
    }
}

#[test]
fn projection_error_keeps_the_canonical_write_and_the_write_barrier_usable() {
    let directory = tempfile::tempdir().unwrap();
    let db = CoordinatedDb::new(rocksdb::DB::open_default(directory.path()).unwrap());
    db.register_local_projection(Arc::new(Projector::Error))
        .unwrap();
    db.put(b"canonical", b"state").unwrap();
    assert_eq!(
        db.get(b"canonical").unwrap().as_deref(),
        Some(b"state".as_slice())
    );
    assert!(db.get(b"local-test/projected").unwrap().is_none());
    assert!(db.get(b"local-test/invalid").unwrap().is_some());
    assert!(!db.write_failed());
    assert!(db.lock_writes().is_ok());
}

#[test]
fn successful_projection_and_canonical_write_are_visible_together() {
    let directory = tempfile::tempdir().unwrap();
    let db = CoordinatedDb::new(rocksdb::DB::open_default(directory.path()).unwrap());
    db.register_local_projection(Arc::new(Projector::Commit))
        .unwrap();
    let before = db.snapshot();
    db.put(b"canonical", b"state").unwrap();
    assert_eq!(before.get(b"canonical").unwrap(), None);
    assert_eq!(before.get(b"local-test/projected").unwrap(), None);
    let after = db.snapshot();
    assert_eq!(
        after.get(b"canonical").unwrap().as_deref(),
        Some(b"state".as_slice())
    );
    assert_eq!(
        after.get(b"local-test/projected").unwrap().as_deref(),
        Some(b"same-batch".as_slice())
    );
}

#[test]
fn projection_panic_discards_partial_output_and_durably_invalidates_with_state() {
    let directory = tempfile::tempdir().unwrap();
    let db = CoordinatedDb::new(rocksdb::DB::open_default(directory.path()).unwrap());
    db.register_local_projection(Arc::new(Projector::Panic))
        .unwrap();
    db.put(b"canonical", b"state").unwrap();
    assert!(db.get(b"canonical").unwrap().is_some());
    assert_eq!(db.get(b"local-test/projected").unwrap(), None);
    assert!(db.get(b"local-test/invalid").unwrap().is_some());
    drop(db);
    let reopened = CoordinatedDb::new(rocksdb::DB::open_default(directory.path()).unwrap());
    assert!(reopened.get(b"local-test/invalid").unwrap().is_some());
}

#[test]
fn projection_cannot_write_outside_its_registered_namespace() {
    let directory = tempfile::tempdir().unwrap();
    let db = CoordinatedDb::new(rocksdb::DB::open_default(directory.path()).unwrap());
    db.register_local_projection(Arc::new(Projector::EscapeNamespace))
        .unwrap();
    db.put(b"canonical", b"state").unwrap();
    assert_eq!(
        db.get(b"canonical").unwrap().as_deref(),
        Some(b"state".as_slice())
    );
    assert!(db.get(b"local-test/invalid").unwrap().is_some());
}

#[test]
fn projection_work_overruns_discard_partial_output_without_failing_state() {
    for projector in [Projector::OutputLimit, Projector::ReadLimit] {
        let directory = tempfile::tempdir().unwrap();
        let db = CoordinatedDb::new(rocksdb::DB::open_default(directory.path()).unwrap());
        db.put(b"oversized-read", vec![0; 256 << 10]).unwrap();
        db.register_local_projection(Arc::new(projector)).unwrap();
        db.put(b"canonical", b"state").unwrap();
        assert_eq!(
            db.get(b"canonical").unwrap().as_deref(),
            Some(b"state".as_slice())
        );
        assert!(db.get(b"local-test/projected").unwrap().is_none());
        assert!(db.get(b"local-test/invalid").unwrap().is_some());
        assert!(!db.write_failed());
    }
}

#[test]
fn private_projection_metadata_cannot_overwrite_canonical_records() {
    let directory = tempfile::tempdir().unwrap();
    let db = CoordinatedDb::new(rocksdb::DB::open_default(directory.path()).unwrap());
    db.register_local_projection(Arc::new(Projector::Commit))
        .unwrap();
    let overlay = quil_forest::ExecutionOverlay::capture(
        db.clone(),
        quil_forest::OverlayLimits {
            max_delta_bytes: 1024,
            max_delta_entries: 4,
            max_record_bytes: 1024,
            max_read_bytes: 1024,
            max_read_operations: 4,
            max_cursors: 4,
        },
    )
    .unwrap();
    assert!(overlay
        .stage_local_projection_records(b"local-test/", b"canonical", &[])
        .is_err());
    assert!(overlay.prepare_commit().is_err());
    assert!(db.get(b"canonical").unwrap().is_none());
}
