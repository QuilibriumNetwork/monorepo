use std::sync::Arc;

use quil_forest::{CoordinatedDb, LocalBatchProjection, LocalProjectionBatch, LocalProjectionRead};

enum Projector {
    Commit,
    Panic,
    EscapeNamespace,
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
        if matches!(self, Self::Panic) {
            panic!("projection failed after staging its output");
        }
        Ok(())
    }
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
