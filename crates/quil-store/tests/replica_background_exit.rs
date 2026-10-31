//! A process that starts a replica compaction and then ends must wait for it.
//! Ending under it cuts the compaction short, and a thread that closes a store
//! during RocksDB's static teardown aborts the process ("pthread lock: Invalid
//! argument"). The test runs itself as a child that starts one and returns,
//! then checks the child exited cleanly with the compaction done.
use std::sync::Arc;
use std::time::Duration;

use quil_store::replica_store::{wait_for_background_work, ReplicaStore};
use quil_types::store::KvDb;

const CHILD: &str = "QUIL_REPLICA_EXIT_CHILD";
const NAME: &str = "a_process_ends_only_after_the_replica_compaction_it_started";

/// The replica keys of epochs below 5, where the child stores and evicts one.
fn evicted_range() -> (Vec<u8>, Vec<u8>) {
    let key = |epoch: u64| {
        let mut key = vec![quil_store::encoding::STORAGE_REPLICA];
        key.extend_from_slice(&epoch.to_be_bytes());
        key
    };
    (key(0), key(5))
}

#[test]
fn a_process_ends_only_after_the_replica_compaction_it_started() {
    if let Some(dir) = std::env::var_os(CHILD) {
        return child(std::path::Path::new(&dir));
    }
    for round in 0..2 {
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads", "1"])
            .env(CHILD, dir.path())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "round {round}: the child ended badly: {status}"
        );
        let db = quil_store::RocksDb::open(dir.path()).unwrap();
        let (lo, hi) = evicted_range();
        assert!(
            !db.holds_file_of(&lo, &hi, 128 << 20).unwrap(),
            "round {round}: the process ended before the compaction it started dropped the \
             evicted replica"
        );
    }
}

/// Store a whole replica past the size a table file is cut at, evict it,
/// which starts its compaction, and end without waiting for it.
fn child(dir: &std::path::Path) {
    let db = Arc::new(quil_store::RocksDb::open(dir).unwrap());
    let mut x = 0x2545_F491u32;
    let value: Vec<u8> = std::iter::once(0xA5u8)
        .chain((0..(160usize << 20) / 4).flat_map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x.to_le_bytes()
        }))
        .collect();
    let mut key = evicted_range().0;
    key.truncate(1);
    key.extend_from_slice(&3u64.to_be_bytes());
    key.extend_from_slice(b"old");
    db.set(&key, &value).unwrap();
    db.inner().flush().unwrap();
    let replicas = ReplicaStore::new(db.clone());
    replicas.evict_below_epoch(5).unwrap();
    drop(replicas);
    drop(db);
    assert!(
        wait_for_background_work(Duration::ZERO) > 0,
        "no compaction started"
    );
}
