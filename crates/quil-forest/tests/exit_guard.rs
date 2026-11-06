//! A store whose last handle drops while the process exits (a thread's,
//! after the test returned) must not abort the process in RocksDB's static
//! teardown ("pthread lock: Invalid argument").
#![cfg(target_os = "linux")]

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Asks the child's closing thread to drop its store, and hears it done.
struct LateClose {
    close: SyncSender<()>,
    closed: Receiver<()>,
}

static LATE_CLOSE: OnceLock<Mutex<LateClose>> = OnceLock::new();

/// Runs before RocksDB's static constructors, so the exit handler it
/// registers runs after RocksDB's static destructors.
#[used]
#[link_section = ".init_array.00101"]
static REGISTER_LATE_CLOSE: extern "C" fn() = register_late_close;

extern "C" fn register_late_close() {
    extern "C" fn close_late() {
        let Some(late) = LATE_CLOSE.get() else {
            return;
        };
        let late = late.lock().unwrap();
        late.close.send(()).unwrap();
        let _ = late.closed.recv_timeout(Duration::from_secs(30));
    }
    // SAFETY: registers a plain function with no captured state.
    unsafe { libc::atexit(close_late) };
}

#[test]
#[ignore = "subprocess helper for a_store_dropped_as_the_process_exits_does_not_abort_it"]
fn store_dropped_as_the_process_exits_child() {
    let dir = std::env::var_os("QUIL_EXIT_GUARD_DIR").expect("child dir");
    let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir).unwrap());
    let (close, told) = sync_channel(1);
    let (done, closed) = sync_channel(1);
    std::thread::spawn(move || {
        if told.recv().is_ok() {
            drop(db);
            let _ = done.send(());
        }
    });
    assert!(
        LATE_CLOSE
            .set(Mutex::new(LateClose { close, closed }))
            .is_ok(),
        "one late close per process"
    );
}

/// The child's store is dropped once its exit has run RocksDB's static
/// destructors: it is left open rather than closed under them.
#[test]
fn a_store_dropped_as_the_process_exits_does_not_abort_it() {
    let dir = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "store_dropped_as_the_process_exits_child",
            "--test-threads=1",
        ])
        .env("QUIL_EXIT_GUARD_DIR", dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "the child test runs and passes: {stdout}{stderr}"
    );
    assert!(
        output.status.success(),
        "the store dropped as the process exited aborted it ({}): {stderr}",
        output.status
    );
}
