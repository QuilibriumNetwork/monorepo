//! A lookup of a small key that sorts beside a stored replica must not read
//! the replica. Stored whole, a replica is one data block of up to 1 GB, and
//! every point read of a key its index range covers (consensus records sort
//! just before replica keys) read all of it. Uses only APIs the release base
//! has, so it fails there.
use std::sync::Arc;

use quil_store::replica_store::ReplicaStore;

/// Bytes this process has read from files so far (`rchar`: page-cache hits
/// included). The block cache cannot show a read of a block larger than one
/// of its shards: such a block is read and dropped.
fn bytes_read() -> u64 {
    std::fs::read_to_string("/proc/self/io")
        .ok()
        .and_then(|io| {
            io.lines()
                .find_map(|line| line.strip_prefix("rchar: ")?.trim().parse().ok())
        })
        .expect("/proc/self/io")
}

#[test]
fn a_lookup_beside_a_stored_replica_reads_none_of_it() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
    // Records that sort just before the replica keys, as consensus ones do.
    for i in 0..64u8 {
        db.inner().put([0x0C, 0x07, i], [i; 64]).unwrap();
    }
    let replicas = ReplicaStore::new(db.clone());
    let mut x = 0x9E37_79B9u32;
    let nodes: Vec<u8> = (0..(32usize << 20) / 4)
        .flat_map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 2).to_le_bytes()
        })
        .collect();
    replicas
        .put_hash(7, b"leaf", &nodes, &[1u8; 1024], &[2u8; 96])
        .unwrap();
    db.inner().flush().unwrap();
    for key in [&[0x0C, 0x09, 1, 2, 3][..], &[0x0C, 0xFF], &[0x0D]] {
        let before = bytes_read();
        assert!(db.inner().get(key).unwrap().is_none());
        let read = bytes_read() - before;
        println!(
            "key={key:02x?} read_bytes={read} replica_bytes={}",
            nodes.len()
        );
        assert!(
            read < 1 << 20,
            "a lookup of {key:02x?} beside a {}-byte stored replica read {read} bytes of it",
            nodes.len()
        );
    }
}
