use super::*;
use crate::rocksdb_store::RocksDb;
use tempfile::TempDir;

// These tests own their cache rather than relying on the process-wide cache or
// environment overrides. Flushing makes the measurements exercise SST reads.
fn sweep_test_db(path: &std::path::Path) -> (quil_forest::CoordinatedDb, rocksdb::Cache) {
    let cache = rocksdb::Cache::new_lru_cache(32 << 20);
    let mut table = rocksdb::BlockBasedOptions::default();
    table.set_block_cache(&cache);
    let mut options = rocksdb::Options::default();
    options.create_if_missing(true);
    options.set_disable_auto_compactions(true);
    options.set_block_based_table_factory(&table);
    (
        quil_forest::CoordinatedDb::new(rocksdb::DB::open(&options, path).unwrap()),
        cache,
    )
}

#[test]
fn scan_pages_preserve_regular_page_cache_policy() {
    check_snapshot_page_cache(false);
    check_snapshot_page_cache(true);
}

fn check_snapshot_page_cache(fill_cache: bool) {
    use quil_types::store::VertexPageLimits;

    const ROWS: usize = 64;
    const BLOB_BYTES: usize = 64 << 10;
    let directory = TempDir::new().unwrap();
    let (db, cache) = sweep_test_db(directory.path());
    let store = RocksHypergraphStore::new(db.clone());
    let domain = [0x42; 32];
    let shard = ShardKey {
        l1: [1, 2, 3],
        l2: domain,
    };
    for number in 0..ROWS {
        let mut id = domain.to_vec();
        let mut address = [0; 32];
        address[..8].copy_from_slice(&(number as u64).to_be_bytes());
        id.extend_from_slice(&address);
        let key = if number % 2 == 0 {
            crate::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard, &id, 3)
        } else {
            hypergraph_vertex_data_key("vertex", "adds", &shard, &id)
        };
        db.put(key, vec![number as u8; BLOB_BYTES]).unwrap();
    }
    db.flush().unwrap();
    let snapshot = store.capture_snapshot().unwrap();
    let before = cache.get_usage();
    let mut after = None;
    let mut seen = 0;
    loop {
        let limits = VertexPageLimits {
            max_entries: 7,
            max_bytes: 1 << 20,
        };
        let page = if fill_cache {
            snapshot.page_vertex_underlying_fixed(
                "vertex",
                "adds",
                &shard,
                &domain,
                after.as_ref(),
                limits,
            )
        } else {
            snapshot.page_vertex_underlying_fixed_for_scan(
                "vertex",
                "adds",
                &shard,
                &domain,
                after.as_ref(),
                limits,
            )
        }
        .unwrap();
        for (address, blob) in &page.entries {
            assert_eq!(
                u64::from_be_bytes(address[..8].try_into().unwrap()),
                seen as u64
            );
            assert_eq!(*blob, vec![seen as u8; BLOB_BYTES]);
            seen += 1;
        }
        if !page.has_more {
            break;
        }
        after = page.entries.last().map(|(address, _)| *address);
        assert!(after.is_some());
    }
    assert_eq!(seen, ROWS);
    let swept = cache.get_usage().saturating_sub(before);
    if fill_cache {
        assert!(
            swept > 2 << 20,
            "ordinary snapshot paging did not fill its cache: {swept} bytes"
        );
    } else {
        assert!(
            swept < 512 << 10,
            "snapshot paging 4 MiB of payloads added {swept} bytes to the block cache"
        );
    }
    // Positive control: the same persisted payloads fill this private cache
    // when explicitly read through an ordinary cache-filling iterator.
    for entry in db.iterator(rocksdb::IteratorMode::Start) {
        let _ = entry.unwrap();
    }
    assert!(cache.get_usage().saturating_sub(before) > 2 << 20);
}

#[test]
fn domain_discovery_does_not_cache_legacy_tree_payloads() {
    let directory = TempDir::new().unwrap();
    let (db, cache) = sweep_test_db(directory.path());
    let store = RocksHypergraphStore::new(db.clone());
    for number in 1..=64 {
        let shard = ShardKey {
            l1: [1, 2, 3],
            l2: [number; 32],
        };
        db.put(
            hypergraph_tree_blob_key("vertex", "adds", &shard),
            vec![number; 64 << 10],
        )
        .unwrap();
    }
    // The other two root formats contribute domains too, and duplicates from
    // different formats still produce just one sorted domain.
    for number in [1, 65] {
        let mut old = vec![
            crate::encoding::HYPERGRAPH_SHARD,
            crate::encoding::HG_VERTEX_ADDS_TREE_ROOT,
        ];
        old.extend_from_slice(&[1, 2, 3]);
        old.extend_from_slice(&[number; 32]);
        db.put(old, [0; 32]).unwrap();
    }
    let mut forest = vec![
        crate::FOREST_NAMESPACE[0],
        0xfe,
        3,
        33,
        quil_forest::Phase::VertexAdds as u8,
    ];
    forest.extend_from_slice(&[66; 32]);
    db.put(forest, [0; 8]).unwrap();
    // A neighboring phase must not be mistaken for an adds root or have its
    // large value copied merely because the iterator reached the range end.
    db.put(
        hypergraph_tree_blob_key(
            "vertex",
            "removes",
            &ShardKey {
                l1: [1, 2, 3],
                l2: [67; 32],
            },
        ),
        vec![67; 64 << 10],
    )
    .unwrap();
    db.flush().unwrap();
    let before = cache.get_usage();
    let domains = store.range_vertex_adds_domains().unwrap();
    assert_eq!(
        domains,
        (1..=66).map(|number| [number; 32]).collect::<Vec<_>>()
    );
    let swept = cache.get_usage().saturating_sub(before);
    assert!(
        swept < 512 << 10,
        "domain key enumeration cached {swept} bytes of legacy tree payloads"
    );
    for entry in db.iterator(rocksdb::IteratorMode::Start) {
        let _ = entry.unwrap();
    }
    let control = cache.get_usage().saturating_sub(before);
    assert!(
        control > 2 << 20,
        "ordinary reads cached only {control} bytes; domain sweep cached {swept}"
    );
}

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
