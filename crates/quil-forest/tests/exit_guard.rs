//! A store whose last handle drops while the process exits (a thread's,
//! after the test returned) must not abort the process in RocksDB's static
//! teardown ("pthread lock: Invalid argument"), nor may a store left open
//! keep RocksDB's own threads working under it (SIGSEGV).
#![cfg(target_os = "linux")]

use std::process::Output;
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

/// Opens a store and has a thread drop it `linger` after the process's
/// exit has run RocksDB's static destructors.
fn open_and_drop_late(options: &rocksdb::Options, linger: Duration) {
    let dir = std::env::var_os("QUIL_EXIT_GUARD_DIR").expect("child dir");
    let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open(options, dir).unwrap());
    let (close, told) = sync_channel(1);
    let (done, closed) = sync_channel(1);
    std::thread::spawn(move || {
        if told.recv().is_ok() {
            std::thread::sleep(linger);
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

/// Runs the ignored child test `name` in a new process of this binary.
fn run_child(name: &str) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", name, "--test-threads=1"])
        .env("QUIL_EXIT_GUARD_DIR", dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "the child test runs and passes: {stdout}{stderr}"
    );
    output
}

#[test]
#[ignore = "subprocess helper for a_store_dropped_as_the_process_exits_does_not_abort_it"]
fn store_dropped_as_the_process_exits_child() {
    let mut options = rocksdb::Options::default();
    options.create_if_missing(true);
    open_and_drop_late(&options, Duration::ZERO);
}

/// The child's store is dropped once its exit has run RocksDB's static
/// destructors: it is left open rather than closed under them.
#[test]
fn a_store_dropped_as_the_process_exits_does_not_abort_it() {
    let output = run_child("store_dropped_as_the_process_exits_child");
    assert!(
        output.status.success(),
        "the store dropped as the process exited aborted it ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "subprocess helper for a_store_open_through_the_exit_runs_no_work_under_its_teardown"]
fn store_open_through_the_exit_child() {
    let mut options = rocksdb::Options::default();
    options.create_if_missing(true);
    // RocksDB's timer thread, which its teardown leaves running, dumps the
    // store's stats every second.
    options.set_stats_dump_period_sec(1);
    open_and_drop_late(&options, Duration::from_millis(2500));
}

/// The child's store stays open for 2.5 s after its exit ran RocksDB's
/// static destructors: none of RocksDB's own work for it (its stats dump
/// here) runs in that time, as it would read the statics freed.
#[test]
fn a_store_open_through_the_exit_runs_no_work_under_its_teardown() {
    let output = run_child("store_open_through_the_exit_child");
    assert!(
        output.status.success(),
        "RocksDB's work for a store open through the exit crashed it ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
