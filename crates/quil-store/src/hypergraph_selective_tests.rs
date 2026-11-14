use super::*;
use crate::rocksdb_store::RocksDb;
use tempfile::TempDir;

#[test]
fn selective_vertex_walk_preserves_versions_legacy_and_overlay() {
    use quil_types::store::HypergraphStore;
    let db = RocksDb::open_in_memory().unwrap();
    let store = RocksHypergraphStore::new(db.inner());
    let shard = ShardKey {
        l1: [1, 2, 3],
        l2: [0x42; 32],
    };
    let keys = [vec![0x10; 64], vec![0x20; 64], vec![0x30; 64]];
    for key in &keys {
        store
            .save_vertex_underlying("vertex", "adds", &shard, key, b"legacy")
            .unwrap();
    }
    for version in 0..12 {
        for key in &keys[..2] {
            let encoded = crate::encoding::hypergraph_vertex_data_v2_key(
                "vertex", "adds", &shard, key, version,
            );
            db.inner().put(encoded, [version as u8]).unwrap();
        }
    }
    // An empty newest blob still overrides the legacy value.
    let encoded =
        crate::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard, &keys[0], 20);
    db.inner().put(encoded, []).unwrap();
    let verify = |backend: &dyn HypergraphStore| {
        let predicates: [&dyn Fn(&[u8]) -> bool; 3] = [
            &|k: &[u8]| k[0] != 0x20,
            &|_: &[u8]| false,
            &|_: &[u8]| true,
        ];
        for matches in predicates {
            let mut reference = Vec::new();
            backend
                .for_each_vertex_underlying("vertex", "adds", &shard, &mut |k, v| {
                    if matches(&k) {
                        reference.push((k, v));
                    }
                })
                .unwrap();
            let mut selected = Vec::new();
            let count = backend
                .for_each_vertex_underlying_matching(
                    "vertex",
                    "adds",
                    &shard,
                    matches,
                    &mut |k, v| selected.push((k, v)),
                )
                .unwrap();
            reference.sort();
            selected.sort();
            assert_eq!(count, reference.len());
            assert_eq!(selected, reference);
        }
    };
    // Exercise the canonical leaf serializer against the durable backend.
    let hg = quil_hypergraph::HypergraphCrdt::new(
        std::sync::Arc::new(RocksHypergraphStore::new(db.inner())),
        std::sync::Arc::new(quil_tries::ShaInclusionProver),
    );
    let mut expected = vec![0];
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.extend_from_slice(&64u32.to_be_bytes());
    expected.extend_from_slice(&keys[0]);
    expected.extend_from_slice(&0u32.to_be_bytes());
    for phase in 1..4 {
        expected.push(phase);
        expected.extend_from_slice(&0u32.to_be_bytes());
    }
    assert_eq!(hg.serialize_phase_subtrees(&shard, &[4]).unwrap(), expected);
    verify(&store);
    let overlay = std::sync::Arc::new(
        quil_forest::ExecutionOverlay::capture(
            db.inner(),
            quil_forest::OverlayLimits {
                max_delta_bytes: 16 << 20,
                max_delta_entries: 100_000,
                max_record_bytes: 2 << 20,
                max_read_bytes: 128 << 20,
                max_read_operations: 2_000_000,
                max_cursors: 128,
            },
        )
        .unwrap(),
    );
    verify(&OverlayHypergraphStore::new(overlay));
    // Mixed lengths force the map fallback, including when the shorter key
    // is rejected and the longer key sorts between its versions.
    for (key, version, blob) in [
        (vec![1], 0, b"short".as_slice()),
        (vec![1, 0, 0], 2, b"long".as_slice()),
        (vec![1], u64::MAX, b"newest".as_slice()),
    ] {
        db.inner()
            .put(
                crate::encoding::hypergraph_vertex_data_v2_key(
                    "vertex", "adds", &shard, &key, version,
                ),
                blob,
            )
            .unwrap();
    }
    let mut selected = Vec::new();
    HypergraphStore::for_each_vertex_underlying_matching(
        &store,
        "vertex",
        "adds",
        &shard,
        &|k| k.len() == 3,
        &mut |k, v| selected.push((k, v)),
    )
    .unwrap();
    assert_eq!(selected, vec![(vec![1, 0, 0], b"long".to_vec())]);
    verify(&store);
    let overlay = std::sync::Arc::new(
        quil_forest::ExecutionOverlay::capture(
            db.inner(),
            quil_forest::OverlayLimits {
                max_delta_bytes: 16 << 20,
                max_delta_entries: 100_000,
                max_record_bytes: 2 << 20,
                max_read_bytes: 128 << 20,
                max_read_operations: 2_000_000,
                max_cursors: 128,
            },
        )
        .unwrap(),
    );
    verify(&OverlayHypergraphStore::new(overlay));
}

/// Run in a fresh process with a small block cache. Compare the same API
/// against the default filtering fallback to measure payload retention.
#[test]
#[ignore = "measurement"]
fn measure_selective_vertex_materialization() {
    use quil_types::store::HypergraphStore;
    let directory = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
    let shard = ShardKey {
        l1: [1, 2, 3],
        l2: [0x42; 32],
    };
    {
        let db = RocksDb::open(directory.path()).unwrap();
        let blob = vec![7; 512 * 1024];
        for index in 0u64..512 {
            let mut key = vec![1; 64];
            key[56..].copy_from_slice(&index.to_be_bytes());
            db.inner()
                .put(
                    crate::encoding::hypergraph_vertex_data_v2_key(
                        "vertex", "adds", &shard, &key, 1,
                    ),
                    &blob,
                )
                .unwrap();
        }
        db.inner()
            .put(
                crate::encoding::hypergraph_vertex_data_v2_key(
                    "vertex", "adds", &shard, &[0; 64], 1,
                ),
                b"selected",
            )
            .unwrap();
        db.inner().flush().unwrap();
    }
    // Return fixture-creation allocations before measuring the walk.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::malloc_trim(0);
    }
    let db = RocksDb::open(directory.path()).unwrap();
    let store = RocksHypergraphStore::new(db.inner());
    let count = HypergraphStore::for_each_vertex_underlying_matching(
        &store,
        "vertex",
        "adds",
        &shard,
        &|k| k[0] == 0,
        &mut |key, blob| {
            assert_eq!(key, vec![0; 64]);
            assert_eq!(blob, b"selected");
            #[cfg(target_os = "linux")]
            eprintln!(
                "selective walk retained RSS: {}",
                std::fs::read_to_string("/proc/self/status")
                    .unwrap()
                    .lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .unwrap()
            );
        },
    )
    .unwrap();
    assert_eq!(count, 1);
}
