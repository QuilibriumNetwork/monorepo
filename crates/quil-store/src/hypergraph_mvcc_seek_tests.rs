//! MVCC reads of the versioned vertex blob keyspace stay within the read
//! vertex's own keys. A worker payload eviction range-deletes a shard's
//! blobs and compacts, while snapshots taken before it keep every deleted
//! record; a reverse seek then stepped over each of them.

use super::*;
use quil_forest::{ExecutionOverlay, OverlayLimits};
use rocksdb::perf::{PerfContext, PerfMetric, PerfStatsLevel};

/// Records the eviction deletes; enough to separate a walk over them from
/// a bounded read by orders of magnitude.
const EVICTED: u32 = 200_000;

/// Blocks one bounded read may visit: a few per positioning step, plus the
/// legacy fallback's point lookup.
const MAX_BLOCKS: u64 = 100;

fn open(path: &std::path::Path) -> quil_forest::CoordinatedDb {
    quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(path).unwrap())
}

fn limits() -> OverlayLimits {
    OverlayLimits {
        max_delta_bytes: 16 << 20,
        max_delta_entries: 100_000,
        max_record_bytes: 2 << 20,
        max_read_bytes: 128 << 20,
        max_read_operations: 2_000_000,
        max_cursors: 128,
    }
}

/// The evicted shard's adds phase sorts just below the read shard's
/// removes phase and just above the low shard's adds phase: no other key
/// lies between them.
fn evicted_shard() -> ShardKey {
    ShardKey {
        l1: [0, 0, 1],
        l2: [0x11; 32],
    }
}

fn read_shard() -> ShardKey {
    ShardKey {
        l1: [0, 0, 1],
        l2: [0x22; 32],
    }
}

fn low_shard() -> ShardKey {
    ShardKey {
        l1: [0, 0, 1],
        l2: [0x05; 32],
    }
}

/// Lowest key of the read shard's removes phase: only an overlay writes it.
const DELTA_ONLY: [u8; 32] = [0x02; 32];
/// Stored versions an overlay deletes; the lowest stored key of the read
/// shard in the fixture that writes it.
const TARGET: [u8; 32] = [0x04; 32];
/// Absent.
const ABSENT: [u8; 32] = [0x08; 32];
/// One version, the lowest stored record above the evicted range.
const SINGLE: [u8; 32] = [0x10; 32];
/// Several versions.
const MULTI: [u8; 32] = [0x20; 32];
const MULTI_VERSIONS: [u64; 3] = [3, 7, 11];
/// Only a legacy (unversioned) blob.
const LEGACY: [u8; 32] = [0x30; 32];
/// Versions only an overlay writes.
const BRANCH: [u8; 32] = [0x40; 32];
/// Stored versions an overlay interleaves with, rewrites and deletes.
const MIXED: [u8; 32] = [0x50; 32];
/// Stored versions an overlay range-deletes within the vertex.
const CLEARED: [u8; 32] = [0x60; 32];
/// Stored versions an overlay range-deletes from the vertex's lowest key.
const FLOORED: [u8; 32] = [0x70; 32];
/// In the low shard: one version, then the highest key, absent, the last
/// below the evicted range.
const LOW_SINGLE: [u8; 32] = [0x10; 32];
const LOW_ABSENT: [u8; 32] = [0x20; 32];

fn v2(shard: &ShardKey, phase: &str, vertex: &[u8], version: u64) -> Vec<u8> {
    crate::encoding::hypergraph_vertex_data_v2_key("vertex", phase, shard, vertex, version)
}

/// The stored records most tests read.
fn records() -> Vec<(Vec<u8>, Vec<u8>)> {
    let shard = read_shard();
    let mut records = vec![(v2(&shard, "removes", &SINGLE, 5), b"single-5".to_vec())];
    for version in MULTI_VERSIONS {
        records.push((
            v2(&shard, "removes", &MULTI, version),
            format!("multi-{version}").into_bytes(),
        ));
    }
    records.push((
        crate::encoding::hypergraph_vertex_data_key("vertex", "removes", &shard, &LEGACY),
        b"legacy".to_vec(),
    ));
    records.push((
        v2(&low_shard(), "adds", &LOW_SINGLE, 5),
        b"low-single-5".to_vec(),
    ));
    records
}

/// Writes `records`, then the evicted shard's blobs, pins them with a
/// snapshot, and range-deletes and compacts them as the worker payload
/// eviction does. Returns the pin, which must outlive the reads.
fn evict_under_pin<'a>(
    db: &'a quil_forest::CoordinatedDb,
    records: &[(Vec<u8>, Vec<u8>)],
) -> rocksdb::Snapshot<'a> {
    for (key, value) in records {
        db.put(key.as_slice(), value.as_slice()).unwrap();
    }
    let evicted = evicted_shard();
    let mut batch = rocksdb::WriteBatch::default();
    for n in 0..EVICTED {
        let vertex = [[0x11; 28].as_slice(), &n.to_be_bytes()].concat();
        batch.put(v2(&evicted, "adds", &vertex, 1), [0x5a; 96]);
        if batch.len() == 10_000 {
            db.write(std::mem::take(&mut batch)).unwrap();
        }
    }
    db.write(batch).unwrap();
    db.flush().unwrap();
    let pin = db.snapshot();

    let lower = crate::encoding::hypergraph_vertex_data_v2_shard_prefix("vertex", "adds", &evicted);
    let mut upper = lower.clone();
    *upper.last_mut().unwrap() += 1;
    let mut batch = rocksdb::WriteBatch::default();
    batch.delete_range(&lower, &upper);
    db.write(batch).unwrap();
    db.compact_range(Some(&lower), Some(&upper));
    let mut options = rocksdb::CompactOptions::default();
    options.set_bottommost_level_compaction(rocksdb::BottommostLevelCompaction::ForceOptimized);
    db.compact_range_opt(Some(&lower), Some(&upper), &options);
    pin
}

fn overlay_on(db: &quil_forest::CoordinatedDb) -> OverlayHypergraphStore {
    OverlayHypergraphStore::new(Arc::new(
        ExecutionOverlay::capture(db.clone(), limits()).unwrap(),
    ))
}

enum Write {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    Range(Vec<u8>, Vec<u8>),
}

/// Commits each write in its own transaction, in order, so a later put
/// overrides an earlier range delete.
fn write_delta(overlay: &OverlayHypergraphStore, writes: &[Write]) {
    for write in writes {
        let txn = overlay.new_transaction(false).unwrap();
        match write {
            Write::Put(key, value) => txn.set(key, value).unwrap(),
            Write::Delete(key) => txn.delete(key).unwrap(),
            Write::Range(lower, upper) => txn.delete_range(lower, upper).unwrap(),
        }
        txn.commit().unwrap();
    }
}

/// A named read and the blob it must return.
type Read<'a> = (
    String,
    Box<dyn FnOnce() -> Option<Vec<u8>> + 'a>,
    Option<Vec<u8>>,
);

fn read<'a>(
    name: String,
    run: impl FnOnce() -> Option<Vec<u8>> + 'a,
    expected: Option<&[u8]>,
) -> Read<'a> {
    (name, Box::new(run), expected.map(<[u8]>::to_vec))
}

/// Every way a vertex blob is read: the live store, a captured snapshot of
/// it, an execution overlay over it and a captured snapshot of the overlay.
struct Readers {
    store: RocksHypergraphStore,
    snapshot: Arc<dyn SnapshotReadable>,
    overlay: OverlayHypergraphStore,
    overlay_snapshot: Arc<dyn SnapshotReadable>,
}

impl Readers {
    /// Captures the snapshots; the overlay's delta is complete.
    fn new(db: &quil_forest::CoordinatedDb, overlay: OverlayHypergraphStore) -> Self {
        let store = RocksHypergraphStore::new(db.clone());
        let snapshot = store.capture_tree_snapshot().unwrap().unwrap();
        let overlay_snapshot = overlay.capture_tree_snapshot().unwrap().unwrap();
        Self {
            store,
            snapshot,
            overlay,
            overlay_snapshot,
        }
    }

    /// Reads of `vertex` at version `at` on every path: the snapshots read
    /// only the newest version. `stored` is the answer of the store and its
    /// snapshot, `merged` that of the overlay and its snapshot.
    fn reads(
        &self,
        shard: &ShardKey,
        phase: &'static str,
        vertex: [u8; 32],
        at: u64,
        stored: Option<&[u8]>,
        merged: Option<&[u8]>,
    ) -> Vec<Read<'_>> {
        let name = |path: &str| format!("{path} read of {phase} {:02x}.. at {at}", vertex[0]);
        let (live, overlay) = (shard.clone(), shard.clone());
        let mut reads = vec![
            read(
                name("live"),
                move || {
                    self.store
                        .load_vertex_underlying_at("vertex", phase, &live, &vertex, at)
                        .unwrap()
                },
                stored,
            ),
            read(
                name("overlay"),
                move || {
                    self.overlay
                        .load_vertex_underlying_at("vertex", phase, &overlay, &vertex, at)
                        .unwrap()
                },
                merged,
            ),
        ];
        if at == u64::MAX {
            let (snapshot, overlay_snapshot) = (shard.clone(), shard.clone());
            reads.push(read(
                name("snapshot"),
                move || {
                    self.snapshot
                        .load_vertex_underlying_raw("vertex", phase, &snapshot, &vertex)
                        .unwrap()
                },
                stored,
            ));
            reads.push(read(
                name("overlay snapshot"),
                move || {
                    self.overlay_snapshot
                        .load_vertex_underlying_raw("vertex", phase, &overlay_snapshot, &vertex)
                        .unwrap()
                },
                merged,
            ));
        }
        reads
    }
}

/// Blocks a read visits. A record stepped over below the merging iterator,
/// as a range-deleted one is, counts in no skip counter of RocksDB's perf
/// context; the blocks holding it do.
fn visited_blocks<T>(read: impl FnOnce() -> T) -> (T, u64, String) {
    quil_forest::store_io::with_perf_level(PerfStatsLevel::EnableCount, || {
        let mut context = PerfContext::default();
        context.reset();
        let out = read();
        let blocks = context.metric(PerfMetric::BlockCacheHitCount)
            + context.metric(PerfMetric::BlockReadCount);
        let report = context.report(true);
        (out, blocks, report)
    })
}

/// Runs each read, checks its answer, and fails naming every read that
/// visited `MAX_BLOCKS` blocks or more.
fn assert_bounded(reads: Vec<Read<'_>>) {
    let mut over = Vec::new();
    for (name, run, expected) in reads {
        let (blob, blocks, report) = visited_blocks(run);
        assert_eq!(blob, expected, "{name}");
        eprintln!("{name}: {blocks} blocks; {report}");
        if blocks >= MAX_BLOCKS {
            over.push((name, blocks));
        }
    }
    assert!(
        over.is_empty(),
        "reads visiting >= {MAX_BLOCKS} blocks: {over:#?}"
    );
}

/// A read of a vertex just above the evicted range, absent, with one
/// version (read at it or below it) or with only overlay versions, or of
/// one just below the range, visits a bounded number of blocks on every
/// path.
#[test]
fn a_vertex_read_next_to_an_evicted_range_stays_within_its_versions() {
    let directory = tempfile::tempdir().unwrap();
    let db = open(directory.path());
    let _pin = evict_under_pin(&db, &records());
    let shard = read_shard();
    let overlay = overlay_on(&db);
    write_delta(
        &overlay,
        &[
            Write::Put(
                v2(&shard, "removes", &DELTA_ONLY, 2),
                b"delta-only-2".to_vec(),
            ),
            Write::Put(
                v2(&shard, "removes", &DELTA_ONLY, 9),
                b"delta-only-9".to_vec(),
            ),
        ],
    );
    let readers = Readers::new(&db, overlay);
    let (low, single, delta) = (
        low_shard(),
        Some(&b"single-5"[..]),
        Some(&b"delta-only-9"[..]),
    );
    let mut reads = Vec::new();
    for (shard, phase, vertex, at, stored, merged) in [
        (&shard, "removes", DELTA_ONLY, u64::MAX, None, delta),
        (&shard, "removes", DELTA_ONLY, 1, None, None),
        (&shard, "removes", ABSENT, u64::MAX, None, None),
        (&shard, "removes", SINGLE, u64::MAX, single, single),
        (&shard, "removes", SINGLE, 4, None, None),
        (
            &low,
            "adds",
            LOW_SINGLE,
            u64::MAX,
            Some(&b"low-single-5"[..]),
            Some(&b"low-single-5"[..]),
        ),
        (&low, "adds", LOW_SINGLE, 4, None, None),
        (&low, "adds", LOW_ABSENT, u64::MAX, None, None),
    ] {
        reads.extend(readers.reads(shard, phase, vertex, at, stored, merged));
    }
    assert_bounded(reads);
}

/// An overlay that deletes a vertex's stored versions and writes newer
/// ones reads them without looking below the vertex, whether its delta
/// deletes each stored version, a range within the vertex, or a range
/// starting below it.
#[test]
fn an_overlay_read_over_deleted_stored_versions_stays_within_its_versions() {
    let directory = tempfile::tempdir().unwrap();
    let db = open(directory.path());
    let shard = read_shard();
    let key = |version| v2(&shard, "removes", &TARGET, version);
    let _pin = evict_under_pin(
        &db,
        &[
            (key(1), b"target-1".to_vec()),
            (key(2), b"target-2".to_vec()),
        ],
    );
    let lower =
        crate::encoding::hypergraph_vertex_data_v2_shard_prefix("vertex", "removes", &shard);
    let mut upper = lower.clone();
    *upper.last_mut().unwrap() += 1;
    let deletes = [
        (
            "point deletes",
            vec![Write::Delete(key(1)), Write::Delete(key(2))],
        ),
        (
            "a range within the vertex",
            vec![Write::Range(key(1), key(3))],
        ),
        ("the shard's range", vec![Write::Range(lower, upper)]),
    ];
    let readers: Vec<_> = deletes
        .into_iter()
        .map(|(deleted_by, mut writes)| {
            writes.push(Write::Put(key(3), b"target-3-delta".to_vec()));
            writes.push(Write::Put(key(5), b"target-5-delta".to_vec()));
            let overlay = overlay_on(&db);
            write_delta(&overlay, &writes);
            (deleted_by, Readers::new(&db, overlay))
        })
        .collect();
    let mut reads = Vec::new();
    for (deleted_by, readers) in &readers {
        for (at, stored, merged) in [
            (1, Some(&b"target-1"[..]), None),
            (2, Some(&b"target-2"[..]), None),
            (4, Some(&b"target-2"[..]), Some(&b"target-3-delta"[..])),
            (
                u64::MAX,
                Some(&b"target-2"[..]),
                Some(&b"target-5-delta"[..]),
            ),
        ] {
            reads.extend(
                readers
                    .reads(&shard, "removes", TARGET, at, stored, merged)
                    .into_iter()
                    .map(|(name, run, expected)| (format!("{deleted_by}: {name}"), run, expected)),
            );
        }
    }
    assert_bounded(reads);
}

/// Present versions resolve to the newest ≤ V, absent ones fall back to the
/// legacy blob, on the live store, a captured snapshot, an execution overlay
/// whose delta adds, rewrites and deletes stored versions, and a snapshot
/// of that overlay.
#[test]
fn a_bounded_vertex_read_returns_the_newest_version_at_or_below() {
    let directory = tempfile::tempdir().unwrap();
    let db = open(directory.path());
    let shard = read_shard();
    let key = |vertex: &[u8; 32], version| v2(&shard, "removes", vertex, version);
    let stored = |name: &str, version: u64| (version, format!("{name}-{version}").into_bytes());
    let written =
        |name: &str, version: u64| (version, format!("{name}-{version}-delta").into_bytes());
    let mut records = records();
    for (vertex, name, versions) in [
        (MIXED, "mixed", &[3, 7, 11][..]),
        (CLEARED, "cleared", &[1, 2, 3, 4]),
        (FLOORED, "floored", &[2, 6]),
    ] {
        records.extend(versions.iter().map(|v| {
            let (version, blob) = stored(name, *v);
            (key(&vertex, version), blob)
        }));
    }
    let _pin = evict_under_pin(&db, &records);
    let put = |vertex: &[u8; 32], name: &str, version: u64| {
        Write::Put(key(vertex, version), written(name, version).1)
    };
    let overlay = overlay_on(&db);
    write_delta(
        &overlay,
        &[
            put(&BRANCH, "branch", 2),
            put(&BRANCH, "branch", 9),
            // Between, equal to and above stored versions, and a deleted one.
            put(&MIXED, "mixed", 5),
            put(&MIXED, "mixed", 7),
            put(&MIXED, "mixed", 13),
            Write::Delete(key(&MIXED, 11)),
            // A range deleting two stored versions, one rewritten after it.
            Write::Range(key(&CLEARED, 2), key(&CLEARED, 4)),
            put(&CLEARED, "cleared", 3),
            // A range from the vertex's lowest key over every stored version.
            Write::Range(
                crate::encoding::hypergraph_vertex_data_v2_vk_prefix(
                    "vertex", "removes", &shard, &FLOORED,
                ),
                key(&FLOORED, 7),
            ),
            put(&FLOORED, "floored", 4),
        ],
    );
    let readers = Readers::new(&db, overlay);

    // (vertex, versions the store holds, versions the overlay reads)
    let vertices = [
        (ABSENT, vec![], vec![]),
        (SINGLE, vec![stored("single", 5)], vec![stored("single", 5)]),
        (
            MULTI,
            MULTI_VERSIONS.map(|v| stored("multi", v)).to_vec(),
            MULTI_VERSIONS.map(|v| stored("multi", v)).to_vec(),
        ),
        (
            BRANCH,
            vec![],
            vec![written("branch", 2), written("branch", 9)],
        ),
        (
            MIXED,
            [3, 7, 11].map(|v| stored("mixed", v)).to_vec(),
            vec![
                stored("mixed", 3),
                written("mixed", 5),
                written("mixed", 7),
                written("mixed", 13),
            ],
        ),
        (
            CLEARED,
            [1, 2, 3, 4].map(|v| stored("cleared", v)).to_vec(),
            vec![
                stored("cleared", 1),
                written("cleared", 3),
                stored("cleared", 4),
            ],
        ),
        (
            FLOORED,
            [2, 6].map(|v| stored("floored", v)).to_vec(),
            vec![written("floored", 4)],
        ),
    ];
    let newest = |versions: &[(u64, Vec<u8>)], at: u64| {
        versions
            .iter()
            .rev()
            .find(|(v, _)| *v <= at)
            .map(|(_, blob)| blob.clone())
    };
    for at in (0..15).chain([u64::MAX]) {
        let mut reads = readers.reads(
            &shard,
            "removes",
            LEGACY,
            at,
            Some(&b"legacy"[..]),
            Some(&b"legacy"[..]),
        );
        for (vertex, held, merged) in &vertices {
            reads.extend(readers.reads(
                &shard,
                "removes",
                *vertex,
                at,
                newest(&held[..], at).as_deref(),
                newest(&merged[..], at).as_deref(),
            ));
        }
        for (name, run, expected) in reads {
            assert_eq!(run(), expected, "{name}");
        }
    }
}

/// A publication's version batch answers each row its execution read
/// without reading the store again, unless the read showed a stored
/// version newer than the staged one, and returns what a batch on a branch
/// that read nothing returns: for a delta-only vertex just above the
/// evicted range, a vertex whose stored versions the delta deletes, point
/// or range, a staged delete, a stored version newer than the staged one,
/// one only a read at an older version saw, and rows execution never read.
#[test]
fn a_publication_batch_after_execution_reads_returns_what_a_cold_one_does() {
    let directory = tempfile::tempdir().unwrap();
    let db = open(directory.path());
    let shard = read_shard();
    // Below every stored vertex of the read shard: the first address is its
    // lowest key, just above the evicted range.
    let domain = [0x01; 32];
    let address = |n: u8| [n; 32];
    let key = |n: u8, version: u64| v2(&shard, "removes", &[domain, address(n)].concat(), version);
    let value = |n: u8, version: u64| format!("{n:02x}-{version}").into_bytes();
    let (delta_only, staged_newer, base_newer, point_deleted) = (0x00, 0x10, 0x20, 0x30);
    let (range_deleted, read_older, not_read, staged_delete, same_version) =
        (0x40, 0x50, 0x60, 0x70, 0x80);
    let mut stored = records();
    for (n, version) in [
        (staged_newer, 1),
        (staged_newer, 2),
        (base_newer, 1),
        (base_newer, 5),
        (point_deleted, 1),
        (range_deleted, 1),
        (range_deleted, 2),
        (read_older, 1),
        (read_older, 5),
        (not_read, 1),
        (staged_delete, 1),
        (same_version, 3),
    ] {
        stored.push((key(n, version), value(n, version)));
    }
    let _pin = evict_under_pin(&db, &stored);
    let writes = || {
        vec![
            Write::Put(key(delta_only, 2), b"staged".to_vec()),
            Write::Put(key(staged_newer, 3), b"staged".to_vec()),
            Write::Put(key(base_newer, 3), b"staged".to_vec()),
            Write::Delete(key(point_deleted, 1)),
            Write::Put(key(point_deleted, 2), b"staged".to_vec()),
            Write::Range(key(range_deleted, 1), key(range_deleted, 3)),
            Write::Put(key(range_deleted, 4), b"staged".to_vec()),
            Write::Put(key(read_older, 4), b"staged".to_vec()),
            Write::Put(key(not_read, 2), b"staged".to_vec()),
            Write::Delete(key(staged_delete, 1)),
            Write::Put(key(same_version, 3), b"staged".to_vec()),
        ]
    };
    let published = [
        (delta_only, Some(b"staged".to_vec())),
        (staged_newer, Some(b"staged".to_vec())),
        (base_newer, Some(value(base_newer, 5))),
        (point_deleted, Some(b"staged".to_vec())),
        (range_deleted, Some(b"staged".to_vec())),
        (read_older, Some(value(read_older, 5))),
        (not_read, Some(b"staged".to_vec())),
        (staged_delete, None),
        (same_version, Some(b"staged".to_vec())),
    ];
    let addresses: Vec<[u8; 32]> = published.iter().map(|(n, _)| address(*n)).collect();
    let expected: Vec<Option<Vec<u8>>> = published.iter().map(|(_, v)| v.clone()).collect();
    // Each branch publishes twice, to show what a batch's own seeks record.
    let publish = |executed: bool| {
        let store = OverlayHypergraphStore::new(Arc::new(
            ExecutionOverlay::capture(db.clone(), limits()).unwrap(),
        ));
        if executed {
            for (n, _) in &published {
                let vertex = [domain, address(*n)].concat();
                let row = if *n == read_older {
                    store.load_vertex_underlying_at("vertex", "removes", &shard, &vertex, 3)
                } else if *n == not_read {
                    continue;
                } else {
                    HypergraphStore::load_vertex_underlying_raw(
                        &store, "vertex", "removes", &shard, &vertex,
                    )
                };
                row.unwrap();
            }
        }
        write_delta(&store, &writes());
        let snapshot = store.capture_tree_snapshot().unwrap().unwrap();
        let batch = || {
            let ((rows, blocks, report), counted) = quil_forest::count_batch_rows(|| {
                visited_blocks(|| {
                    snapshot
                        .vertex_batch(
                            "removes",
                            &shard,
                            &domain,
                            &addresses,
                            quil_types::store::VertexBatchRead::Registry { max_bytes: 1 << 20 },
                        )
                        .unwrap()
                })
            });
            let bound = MAX_BLOCKS * addresses.len() as u64;
            assert!(blocks < bound, "{blocks} blocks; {report}");
            (rows, (counted.unread, counted.sought))
        };
        let (first, first_rows) = batch();
        let (second, second_rows) = batch();
        ([first, second], first_rows, second_rows)
    };
    let (cold, cold_first, cold_second) = publish(false);
    let (warm, warm_first, warm_second) = publish(true);
    for rows in cold.iter().chain(&warm) {
        assert_eq!(rows, &expected, "published rows differ from a cold read");
    }
    // Seven rows reach the batch's lookup; the range-deleted and the
    // staged-delete rows resolve without it.
    assert_eq!(cold_first, (0, 7), "cold branch, first batch");
    // Rows execution read with nothing stored above the staged version:
    // the delta-only, staged-newer, point-deleted and same-version rows.
    assert_eq!(warm_first, (4, 3), "executed branch, first batch");
    // A batch's seek past a staged version learns only that nothing lies
    // above it; the stored versions newer than the staged ones it found
    // still need reading.
    assert_eq!(cold_second, (0, 7), "cold branch, second batch");
    assert_eq!(warm_second, (4, 3), "executed branch, second batch");
}
