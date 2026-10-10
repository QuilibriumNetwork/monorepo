use super::*;
use crate::CoordinatedDb;

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
    let db = CoordinatedDb::new(rocksdb::DB::open_default(path).unwrap());
    db.put(b"k", b"v").unwrap();
    db
}

/// Views are admitted per captured family: a fork shares its parent's view,
/// and a family frees its admission only when its last branch closes.
#[test]
fn held_views_are_bounded_across_databases_and_freed_by_their_last_branch() {
    let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a_db, b_db) = (open(first.path()), open(second.path()));
    let admission = ExecutionViewAdmission::new(2, Duration::from_secs(3600));
    let a = ExecutionOverlay::capture_admitted(a_db.clone(), limits(), &admission).unwrap();
    let b = ExecutionOverlay::capture_admitted(b_db.clone(), limits(), &admission).unwrap();
    assert_eq!(admission.active(), 2);
    let refused = ExecutionOverlay::capture_admitted(a_db.clone(), limits(), &admission);
    assert!(refused.err().unwrap().to_string().contains("admission limit"));

    let child = a.fork(limits()).unwrap();
    assert_eq!(admission.active(), 2, "a fork shares its family's view");
    a.close();
    assert_eq!(admission.active(), 2, "the child still reads the family's view");
    assert!(ExecutionOverlay::capture_admitted(b_db.clone(), limits(), &admission).is_err());
    assert_eq!(child.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
    child.close();
    assert_eq!(admission.active(), 1);
    let c = ExecutionOverlay::capture_admitted(b_db, limits(), &admission).unwrap();
    assert_eq!(admission.active(), 2);
    drop((b, c));
    assert_eq!(admission.active(), 0, "dropping a branch releases its view");
}

/// A view past its age fails every later read, is released at once, and marks
/// the branch failed so its delta can never be published.
#[test]
fn an_expired_view_fails_its_reads_and_cannot_publish() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let admission = ExecutionViewAdmission::new(4, Duration::from_millis(50));
    let overlay = ExecutionOverlay::capture_admitted(db.clone(), limits(), &admission).unwrap();
    overlay.apply(&[OverlayMutation::Put(b"x".to_vec(), b"y".to_vec())]).unwrap();
    assert_eq!(overlay.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
    std::thread::sleep(Duration::from_millis(80));

    assert!(overlay.get(b"k").unwrap_err().to_string().contains("expired"));
    assert_eq!(admission.active(), 0);
    assert!(overlay.stats().closed);
    let mut cursor_failed = overlay.cursor(b"a", b"z").unwrap();
    assert!(cursor_failed.seek(b"a").is_err());
    drop(cursor_failed);
    assert!(!overlay.execution_healthy());
    assert!(overlay.prepare_commit().is_err());
}

/// A branch its owner keeps but no longer reads is released by the next
/// capture's sweep, so an idle holder cannot pin its view forever.
#[test]
fn a_new_capture_releases_an_idle_holders_expired_view() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(dir.path());
    let admission = ExecutionViewAdmission::new(1, Duration::from_millis(50));
    let idle = ExecutionOverlay::capture_admitted(db.clone(), limits(), &admission).unwrap();
    assert!(ExecutionOverlay::capture_admitted(db.clone(), limits(), &admission).is_err());
    std::thread::sleep(Duration::from_millis(80));

    let fresh = ExecutionOverlay::capture_admitted(db.clone(), limits(), &admission).unwrap();
    assert_eq!(admission.active(), 1);
    assert_eq!(fresh.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
    assert!(idle.get(b"k").unwrap_err().to_string().contains("expired"));
    assert_eq!(admission.release_expired(), 0, "nothing else is held past its age");
}
