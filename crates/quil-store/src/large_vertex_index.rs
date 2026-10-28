//! Index of the large vertex-adds rows, by domain and address.
//!
//! A scan for confidential coins or escrows wants only rows of at least
//! [`LARGE_VERTEX_MIN_BYTES`] (a confidential coin is over 11 KB, an escrow
//! larger), yet QUIL's keyspace also holds about 122 million migrated
//! transparent coins of a few hundred bytes. Walking all of them failed every
//! wallet scan once QUIL had a coin root. The index names the large rows, so a
//! scan reads only those.
//!
//! The index is node-local and part of no commitment. Every store write of a
//! large row adds its entry in the same batch (the `live` keyspace). The rows a
//! store held before it kept the index are walked once, in the background,
//! from a cursor that survives restarts (the `walked` keyspace). The two are
//! kept apart so the walk's writes never touch a prefix an execution branch
//! wrote, and cannot fail its publication. An entry outlives its row when a
//! rewind, eviction or wipe drops the row; readers pass over such entries.
//!
//! A binary without this index writes rows without entries: a store that ran
//! one after its walk completed needs the walk again (delete the state key).

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use quil_types::error::{QuilError, Result};
use quil_types::store::{IndexedVertexPage, LargeVertexIndexState, ShardKey, VertexPageLimits};

use crate::overlay::{BoundedCursorSource, PageCursor};

/// The smallest row the index names: well under a confidential coin (over
/// 11 KB) or an escrow, well over a transparent coin (a few hundred bytes).
pub const LARGE_VERTEX_MIN_BYTES: usize = 4096;

const INDEX: u8 = 0x37;
/// `[INDEX, STATE]` holds the walk's state (see [`WalkState`]).
const STATE: u8 = 0x00;
const LIVE: u8 = 0x01;
const WALKED: u8 = 0x02;
const STATE_KEY: [u8; 2] = [INDEX, STATE];
/// The prefixes the background walk writes.
static WALK_PREFIXES: [[u8; 2]; 2] = [[INDEX, STATE], [INDEX, WALKED]];

/// The vertex-adds row keyspaces, unversioned then versioned:
/// `prefix(3) ‖ l1(3) ‖ l2(32) ‖ domain(32) ‖ address(32) [‖ version(8)]`.
const ROW_RANGES: [[u8; 3]; 2] = [
    [crate::encoding::HG_VERTEX_DATA_PREFIX, 0, 0],
    [crate::encoding::HG_VERTEX_DATA_V2, 0, 0],
];
const ROW_SHARD_PREFIX: usize = 3 + 3 + 32;
const VERTEX_KEY: usize = 64;

/// Rows one walk step reads at most, and how long it reads before it writes.
const WALK_STEP_ROWS: usize = 200_000;
const WALK_STEP_TIME: Duration = Duration::from_millis(250);
/// Pause after each step, so the walk leaves the disk to the node's own work.
const WALK_YIELD: Duration = Duration::from_millis(50);
const WALK_REPORT_EVERY: Duration = Duration::from_secs(300);
const WALK_RETRY_MAX: Duration = Duration::from_secs(300);

/// Index entries one page examines at most, so stale entries cannot make a
/// page unbounded.
pub const MAX_EXAMINED_PER_PAGE: usize = 1024;

fn entry_key(source: u8, vertex_key: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + vertex_key.len());
    key.extend_from_slice(&[INDEX, source]);
    key.extend_from_slice(vertex_key);
    key
}

/// The entry a store write of `len` bytes adds beside its row, if it is large.
pub(crate) fn live_entry(
    set_type: &str,
    phase_type: &str,
    vertex_key: &[u8],
    len: usize,
) -> Option<Vec<u8>> {
    (set_type == "vertex"
        && phase_type == "adds"
        && vertex_key.len() == VERTEX_KEY
        && len >= LARGE_VERTEX_MIN_BYTES)
        .then(|| entry_key(LIVE, vertex_key))
}

/// The entry for a raw row key and value, for writers that copy rows by key.
pub(crate) fn live_entry_for_row(key: &[u8], len: usize) -> Option<Vec<u8>> {
    let vertex_key = row_vertex_key(key)?;
    (len >= LARGE_VERTEX_MIN_BYTES).then(|| entry_key(LIVE, vertex_key))
}

fn row_vertex_key(key: &[u8]) -> Option<&[u8]> {
    let versioned = match key.get(..3)? {
        prefix if prefix == ROW_RANGES[0] => false,
        prefix if prefix == ROW_RANGES[1] => true,
        _ => return None,
    };
    let len = ROW_SHARD_PREFIX + VERTEX_KEY + if versioned { 8 } else { 0 };
    (key.len() == len).then(|| &key[ROW_SHARD_PREFIX..ROW_SHARD_PREFIX + VERTEX_KEY])
}

/// The state key and the value that marks the index complete.
pub(crate) fn complete_record() -> ([u8; 2], Vec<u8>) {
    (STATE_KEY, WalkState::Complete { rows: 0 }.encode())
}

pub(crate) fn state_key() -> &'static [u8] {
    &STATE_KEY
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum WalkState {
    /// Rows before `cursor` (a row key, exclusive) have been walked.
    Walking {
        rows: u64,
        indexed: u64,
        cursor: Vec<u8>,
    },
    Complete {
        rows: u64,
    },
}

impl WalkState {
    fn encode(&self) -> Vec<u8> {
        match self {
            WalkState::Complete { rows } => [&[1u8][..], &rows.to_be_bytes()].concat(),
            WalkState::Walking {
                rows,
                indexed,
                cursor,
            } => [
                &[0u8][..],
                &rows.to_be_bytes(),
                &indexed.to_be_bytes(),
                cursor,
            ]
            .concat(),
        }
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let rows = u64::from_be_bytes(bytes.get(1..9)?.try_into().ok()?);
        match bytes[0] {
            1 if bytes.len() == 9 => Some(WalkState::Complete { rows }),
            0 if bytes.len() >= 17 => Some(WalkState::Walking {
                rows,
                indexed: u64::from_be_bytes(bytes[9..17].try_into().ok()?),
                cursor: bytes[17..].to_vec(),
            }),
            _ => None,
        }
    }
}

fn upper_bound(prefix: &[u8]) -> Vec<u8> {
    let mut upper = prefix.to_vec();
    *upper.last_mut().unwrap() += 1;
    upper
}

/// Whether `source` holds any vertex-adds row.
fn has_rows<S: BoundedCursorSource>(source: &S) -> Result<bool> {
    for range in ROW_RANGES {
        let mut cursor = source.cursor_within(range.to_vec(), upper_bound(&range));
        cursor.seek(range);
        cursor.status()?;
        if cursor.valid() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The index state `source` records. A store without a state record is
/// complete only when it holds no row at all.
pub(crate) fn state_at<S: BoundedCursorSource>(
    source: &S,
    state: Option<&[u8]>,
) -> Result<LargeVertexIndexState> {
    match state.map(WalkState::decode) {
        Some(Some(WalkState::Complete { .. })) => Ok(LargeVertexIndexState::Complete),
        Some(Some(WalkState::Walking { rows, .. })) => {
            Ok(LargeVertexIndexState::Building { rows_walked: rows })
        }
        Some(None) => Err(QuilError::Store(
            "large vertex index: malformed state".into(),
        )),
        None if has_rows(source)? => Ok(LargeVertexIndexState::Building { rows_walked: 0 }),
        None => Ok(LargeVertexIndexState::Complete),
    }
}

/// Whether a store opened over `db` starts empty, so its first write can mark
/// the index complete.
pub(crate) fn opens_empty(db: &quil_forest::CoordinatedDb) -> bool {
    matches!(db.get(STATE_KEY), Ok(None)) && matches!(has_rows(db), Ok(false))
}

/// One page of the rows the index names in `domain` after `after`; `load`
/// reads a row by its vertex key.
pub(crate) fn page<S: BoundedCursorSource>(
    source: &S,
    load: &dyn Fn(&[u8]) -> Result<Option<Vec<u8>>>,
    domain: &[u8; 32],
    after: Option<&[u8; 32]>,
    limits: VertexPageLimits,
    skip: &dyn Fn(&[u8; 32]) -> bool,
) -> Result<IndexedVertexPage> {
    if limits.max_entries == 0 || limits.max_bytes < 64 {
        return Err(QuilError::InvalidArgument(
            "invalid vertex page limits".into(),
        ));
    }
    let mut page = IndexedVertexPage {
        entries: Vec::new(),
        cursor: after.copied(),
        examined: 0,
        has_more: false,
    };
    let lower = match after {
        None => [0u8; 32],
        Some(address) => {
            let mut next = *address;
            let Some(index) = next.iter().rposition(|&b| b != 255) else {
                return Ok(page);
            };
            next[index] += 1;
            next[index + 1..].fill(0);
            next
        }
    };
    let mut cursors = [LIVE, WALKED].map(|source_byte| {
        let prefix = entry_key(source_byte, domain);
        let mut upper = prefix.clone();
        upper.extend_from_slice(&[0xff; 32]);
        upper.push(0);
        let mut start = prefix.clone();
        start.extend_from_slice(&lower);
        let mut cursor = source.cursor_within(start.clone(), upper);
        cursor.seek(&start);
        (cursor, prefix.len())
    });
    let mut used = 0usize;
    loop {
        let live = head(&cursors[0].0, cursors[0].1)?;
        let walked = head(&cursors[1].0, cursors[1].1)?;
        let address = match (live, walked) {
            (None, None) => break,
            (Some(a), None) | (None, Some(a)) => a,
            (Some(a), Some(b)) => a.min(b),
        };
        if page.entries.len() == limits.max_entries || page.examined == MAX_EXAMINED_PER_PAGE {
            page.has_more = true;
            break;
        }
        for (cursor, prefix) in cursors.iter_mut() {
            if head(cursor, *prefix)? == Some(address) {
                cursor.next();
            }
        }
        page.examined += 1;
        if skip(&address) {
            page.cursor = Some(address);
            continue;
        }
        let mut vertex_key = domain.to_vec();
        vertex_key.extend_from_slice(&address);
        // An entry whose row a rewind, eviction or wipe dropped.
        let Some(blob) = load(&vertex_key)? else {
            page.cursor = Some(address);
            continue;
        };
        let cost = used.checked_add(64 + blob.len());
        if cost.is_none_or(|bytes| bytes > limits.max_bytes) {
            if page.entries.is_empty() {
                return Err(QuilError::InvalidArgument(
                    "vertex row exceeds page byte limit".into(),
                ));
            }
            page.has_more = true;
            break;
        }
        used = cost.unwrap();
        page.entries.push((address, blob));
        page.cursor = Some(address);
    }
    Ok(page)
}

/// Load a row as the snapshot reads it: the newest version, else the
/// unversioned row.
pub(crate) fn load_row<S: BoundedCursorSource>(
    source: &S,
    legacy: &dyn Fn(&[u8]) -> Result<Option<Vec<u8>>>,
    shard: &ShardKey,
    vertex_key: &[u8],
) -> Result<Option<Vec<u8>>> {
    if let Some(blob) =
        crate::hypergraph::vertex_version_at(source, "vertex", "adds", shard, vertex_key, u64::MAX)?
    {
        return Ok(Some(blob));
    }
    legacy(&crate::encoding::hypergraph_vertex_data_key(
        "vertex", "adds", shard, vertex_key,
    ))
}

/// The address at a domain-bounded index cursor: every entry is exactly
/// `prefix ‖ address`.
fn head<C: PageCursor>(cursor: &C, prefix: usize) -> Result<Option<[u8; 32]>> {
    cursor.status()?;
    if !cursor.valid() {
        return Ok(None);
    }
    Ok(cursor.key().and_then(|key| key[prefix..].try_into().ok()))
}

fn store_error(error: impl std::fmt::Display) -> QuilError {
    QuilError::Store(format!("large vertex index: {error}"))
}

fn read_state(db: &quil_forest::CoordinatedDb) -> Result<Option<WalkState>> {
    match db.get(STATE_KEY).map_err(store_error)? {
        None => Ok(None),
        Some(bytes) => WalkState::decode(&bytes)
            .map(Some)
            .ok_or_else(|| store_error("malformed state")),
    }
}

/// Progress of the walk after one step.
#[derive(Debug, PartialEq, Eq)]
pub struct WalkProgress {
    pub rows: u64,
    pub indexed: u64,
    pub complete: bool,
}

/// One step of the walk [`start`] runs: at most `max_rows` rows (and
/// [`WALK_STEP_TIME`]) from the saved cursor, their entries and the new
/// cursor written in one batch.
pub fn walk_step(db: &quil_forest::CoordinatedDb, max_rows: usize) -> Result<WalkProgress> {
    let (mut rows, mut indexed, mut cursor) = match read_state(db)? {
        Some(WalkState::Complete { rows }) => {
            return Ok(WalkProgress {
                rows,
                indexed: 0,
                complete: true,
            })
        }
        Some(WalkState::Walking {
            rows,
            indexed,
            cursor,
        }) => (rows, indexed, Some(cursor)),
        None => (0, 0, None),
    };
    let started = Instant::now();
    let mut batch = quil_forest::DisjointBatch::new(&WALK_PREFIXES);
    let mut read = 0usize;
    let mut finished = true;
    'ranges: for range in ROW_RANGES {
        let upper = upper_bound(&range);
        if cursor
            .as_ref()
            .is_some_and(|c| c.as_slice() >= upper.as_slice())
        {
            continue;
        }
        let mut options = rocksdb::ReadOptions::default();
        options.set_iterate_lower_bound(range.to_vec());
        options.set_iterate_upper_bound(upper.clone());
        // A walk reads each block once: keep the node's working set cached.
        options.fill_cache(false);
        let mut iterator = db.raw_iterator_opt(options);
        match &cursor {
            Some(c) if c.as_slice() >= range.as_slice() => {
                iterator.seek(c);
                if iterator.valid() && iterator.key() == Some(c.as_slice()) {
                    iterator.next();
                }
            }
            _ => iterator.seek(range),
        }
        while iterator.valid() {
            if read == max_rows || started.elapsed() >= WALK_STEP_TIME {
                finished = false;
                break 'ranges;
            }
            let key = iterator.key().unwrap();
            let len = iterator.value().map_or(0, <[u8]>::len);
            if let Some(vertex_key) = row_vertex_key(key) {
                if len >= LARGE_VERTEX_MIN_BYTES {
                    batch
                        .put(entry_key(WALKED, vertex_key), b"")
                        .map_err(store_error)?;
                    indexed += 1;
                }
            }
            rows += 1;
            read += 1;
            cursor = Some(key.to_vec());
            iterator.next();
        }
        iterator.status().map_err(store_error)?;
    }
    let state = if finished {
        WalkState::Complete { rows }
    } else {
        WalkState::Walking {
            rows,
            indexed,
            cursor: cursor.unwrap_or_default(),
        }
    };
    batch.put(STATE_KEY, state.encode()).map_err(store_error)?;
    db.write_disjoint(batch, &rocksdb::WriteOptions::default())
        .map_err(store_error)?;
    Ok(WalkProgress {
        rows,
        indexed,
        complete: finished,
    })
}

static WALKING: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

/// Make the index of `db` complete: at once for a store without rows, else by
/// a background walk of the rows it holds, resumed from its cursor. Returns
/// at once; a walk already running on `db` is not started twice. `store` names
/// the store in the walk's log lines.
pub fn start(db: &quil_forest::CoordinatedDb, store: String) {
    match read_state(db) {
        Ok(Some(WalkState::Complete { .. })) => return,
        Ok(None) if matches!(has_rows(db), Ok(false)) => {
            let (key, value) = complete_record();
            let mut batch = quil_forest::DisjointBatch::new(&WALK_PREFIXES);
            if batch.put(key, value).is_ok()
                && db
                    .write_disjoint(batch, &rocksdb::WriteOptions::default())
                    .is_ok()
            {
                return;
            }
        }
        _ => {}
    }
    if !WALKING.lock().unwrap().insert(db.instance()) {
        return;
    }
    let instance = db.instance();
    let weak = db.downgrade();
    let spawned = std::thread::Builder::new()
        .name("vertex-index".into())
        .spawn(move || {
            walk(weak, &store);
            WALKING.lock().unwrap().remove(&instance);
        });
    if let Err(error) = spawned {
        WALKING.lock().unwrap().remove(&instance);
        tracing::warn!(%error, "large vertex index: cannot start its walk; coin and escrow scans of this store stay unavailable until a restart");
    }
}

fn walk(weak: quil_forest::WeakCoordinatedDb, store: &str) {
    let started = Instant::now();
    let mut reported = Instant::now();
    let mut retry = Duration::from_secs(1);
    let mut first = true;
    loop {
        // Stop once the store's other owners have closed it.
        let Some(db) = weak.upgrade() else {
            return;
        };
        if first {
            first = false;
            let resumed = match read_state(&db) {
                Ok(Some(WalkState::Walking { rows, .. })) => rows,
                _ => 0,
            };
            tracing::info!(
                store,
                rows_walked_before = resumed,
                "large vertex index: walking this store's vertex rows once, so coin and escrow scans read only large rows; scans of it answer unavailable until the walk ends"
            );
        }
        match walk_step(&db, WALK_STEP_ROWS) {
            Ok(progress) if progress.complete => {
                tracing::info!(
                    store,
                    rows_walked = progress.rows,
                    elapsed_secs = started.elapsed().as_secs(),
                    "large vertex index: walk complete; coin and escrow scans of this store are served"
                );
                return;
            }
            Ok(progress) => {
                retry = Duration::from_secs(1);
                if reported.elapsed() >= WALK_REPORT_EVERY {
                    reported = Instant::now();
                    let secs = started.elapsed().as_secs().max(1);
                    tracing::info!(
                        store,
                        rows_walked = progress.rows,
                        large_rows_indexed = progress.indexed,
                        elapsed_secs = secs,
                        "large vertex index: walk in progress; coin and escrow scans of this store answer unavailable until it ends"
                    );
                }
                drop(db);
                std::thread::sleep(WALK_YIELD);
            }
            Err(error) => {
                tracing::warn!(
                    store,
                    %error,
                    retry_secs = retry.as_secs(),
                    "large vertex index: walk step failed; it resumes from its saved cursor"
                );
                drop(db);
                std::thread::sleep(retry);
                retry = (retry * 2).min(WALK_RETRY_MAX);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RocksDb, RocksHypergraphStore};
    use quil_types::store::{HypergraphStore as _, SnapshotReadable as _};

    fn shard() -> ShardKey {
        ShardKey {
            l1: [1, 2, 3],
            l2: [4; 32],
        }
    }
    const DOMAIN: [u8; 32] = [4; 32];

    fn vertex_key(n: u32) -> Vec<u8> {
        let mut key = DOMAIN.to_vec();
        let mut address = [0u8; 32];
        address[..4].copy_from_slice(&n.to_be_bytes());
        key.extend_from_slice(&address);
        key
    }

    fn address(n: u32) -> [u8; 32] {
        vertex_key(n)[32..].try_into().unwrap()
    }

    fn limits() -> VertexPageLimits {
        VertexPageLimits {
            max_entries: 8,
            max_bytes: 240 * 1024,
        }
    }

    /// Every page of the domain, as a wallet continues a scan.
    fn page_all(store: &RocksHypergraphStore) -> (Vec<[u8; 32]>, usize) {
        let snapshot = store.capture_snapshot().unwrap();
        assert_eq!(
            snapshot.large_vertex_index_state().unwrap(),
            LargeVertexIndexState::Complete
        );
        let mut after = None;
        let mut found = Vec::new();
        let mut pages = 0;
        loop {
            let page = snapshot
                .page_large_vertices_skipping(
                    "vertex",
                    "adds",
                    &shard(),
                    &DOMAIN,
                    after.as_ref(),
                    limits(),
                    &|_| false,
                )
                .unwrap();
            pages += 1;
            assert!(page.examined <= MAX_EXAMINED_PER_PAGE);
            found.extend(page.entries.iter().map(|(address, _)| *address));
            if !page.has_more {
                return (found, pages);
            }
            assert!(page.cursor > after, "every page moves the scan on");
            after = page.cursor;
        }
    }

    /// The store write every commit, sync chunk and rewind goes through adds
    /// a large row's entry in the same batch, and a small row none; a store
    /// that opened empty is complete without a walk.
    #[test]
    fn store_writes_add_large_rows_entries_in_their_batch() {
        let db = RocksDb::open_in_memory().unwrap();
        let store = RocksHypergraphStore::new(db.inner());
        let txn = store.new_transaction(false).unwrap();
        for n in 0..20u32 {
            let blob = vec![
                n as u8;
                if n % 2 == 0 {
                    LARGE_VERTEX_MIN_BYTES
                } else {
                    300
                }
            ];
            if n < 10 {
                store
                    .save_vertex_underlying_versioned(
                        txn.as_ref(),
                        "vertex",
                        "adds",
                        &shard(),
                        &vertex_key(n),
                        &blob,
                        1,
                    )
                    .unwrap();
            } else {
                store
                    .save_vertex_underlying_txn(
                        txn.as_ref(),
                        "vertex",
                        "adds",
                        &shard(),
                        &vertex_key(n),
                        &blob,
                    )
                    .unwrap();
            }
        }
        // Not committed: neither the rows nor their entries exist.
        drop(txn);
        assert_eq!(page_all(&store).0, Vec::<[u8; 32]>::new());
        let txn = store.new_transaction(false).unwrap();
        for n in 0..20u32 {
            let blob = vec![
                n as u8;
                if n % 2 == 0 {
                    LARGE_VERTEX_MIN_BYTES
                } else {
                    300
                }
            ];
            store
                .save_vertex_underlying_versioned(
                    txn.as_ref(),
                    "vertex",
                    "adds",
                    &shard(),
                    &vertex_key(n),
                    &blob,
                    1,
                )
                .unwrap();
        }
        txn.commit().unwrap();
        let (found, _) = page_all(&store);
        assert_eq!(found, (0..20).step_by(2).map(address).collect::<Vec<_>>());
        // A rewind that drops a row leaves its entry, which pages pass over.
        let txn = store.new_transaction(false).unwrap();
        store
            .delete_vertex_underlying_versions_from(
                txn.as_ref(),
                "vertex",
                "adds",
                &shard(),
                &vertex_key(0),
                0,
            )
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(page_all(&store).0[0], address(2));
    }

    /// Entries without a row (dropped by an eviction) cannot make a page
    /// unbounded: a page stops at the examined bound and still moves on, and
    /// the scan reaches the rows behind them.
    #[test]
    fn pages_stop_at_the_examined_bound_and_still_progress() {
        let db = RocksDb::open_in_memory().unwrap();
        let store = RocksHypergraphStore::new(db.inner());
        let stale = 3 * MAX_EXAMINED_PER_PAGE as u32 + 5;
        for n in 0..stale {
            db.inner()
                .put(entry_key(WALKED, &vertex_key(n)), b"")
                .unwrap();
        }
        let txn = store.new_transaction(false).unwrap();
        for n in [stale, stale + 1] {
            store
                .save_vertex_underlying_versioned(
                    txn.as_ref(),
                    "vertex",
                    "adds",
                    &shard(),
                    &vertex_key(n),
                    &[7; LARGE_VERTEX_MIN_BYTES],
                    1,
                )
                .unwrap();
        }
        txn.commit().unwrap();
        let snapshot = store.capture_snapshot().unwrap();
        let first = snapshot
            .page_large_vertices_skipping(
                "vertex",
                "adds",
                &shard(),
                &DOMAIN,
                None,
                limits(),
                &|_| false,
            )
            .unwrap();
        assert!(first.entries.is_empty() && first.has_more);
        assert_eq!(first.examined, MAX_EXAMINED_PER_PAGE);
        assert_eq!(
            first.cursor,
            Some(address(MAX_EXAMINED_PER_PAGE as u32 - 1))
        );
        let (found, pages) = page_all(&store);
        assert_eq!(found, vec![address(stale), address(stale + 1)]);
        assert_eq!(pages, 4);
    }

    /// Rows a store held before it kept the index (written here without
    /// entries) are found by the walk: interrupted, resumed after a reopen
    /// from its saved cursor, and complete; until then the state says so.
    #[test]
    fn the_walk_resumes_after_a_reopen_and_completes_the_index() {
        let dir = tempfile::TempDir::new().unwrap();
        let rows = 1_000u32;
        {
            let db = RocksDb::open(dir.path()).unwrap();
            for n in 0..rows {
                let len = if n % 100 <= 1 {
                    LARGE_VERTEX_MIN_BYTES
                } else {
                    200
                };
                let key = if n % 2 == 0 {
                    crate::encoding::hypergraph_vertex_data_v2_key(
                        "vertex",
                        "adds",
                        &shard(),
                        &vertex_key(n),
                        3,
                    )
                } else {
                    crate::encoding::hypergraph_vertex_data_key(
                        "vertex",
                        "adds",
                        &shard(),
                        &vertex_key(n),
                    )
                };
                db.inner().put(key, vec![1u8; len]).unwrap();
            }
            let store = RocksHypergraphStore::new(db.inner());
            let state = || store.capture_snapshot().unwrap().large_vertex_index_state();
            assert_eq!(
                state().unwrap(),
                LargeVertexIndexState::Building { rows_walked: 0 }
            );
            let progress = walk_step(&db.inner(), 300).unwrap();
            assert_eq!(
                progress,
                WalkProgress {
                    rows: 300,
                    indexed: 6,
                    complete: false
                }
            );
            assert_eq!(
                state().unwrap(),
                LargeVertexIndexState::Building { rows_walked: 300 }
            );
        }
        let db = RocksDb::open(dir.path()).unwrap();
        let store = RocksHypergraphStore::new(db.inner());
        let mut steps = 0;
        while !walk_step(&db.inner(), 300).unwrap().complete {
            steps += 1;
            assert!(steps < 10);
        }
        assert_eq!(
            walk_step(&db.inner(), 300).unwrap(),
            WalkProgress {
                rows: u64::from(rows),
                indexed: 0,
                complete: true
            }
        );
        let (found, _) = page_all(&store);
        assert_eq!(
            found,
            (0..rows)
                .filter(|n| n % 100 <= 1)
                .map(address)
                .collect::<Vec<_>>()
        );
    }

    /// A content-address-like spread of `n`.
    fn spread(n: u32) -> [u8; 32] {
        let mut address = [0u8; 32];
        let mut x = u64::from(n);
        for chunk in address.chunks_mut(8) {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            chunk.copy_from_slice(&(z ^ (z >> 31)).to_be_bytes());
        }
        address
    }

    /// The walk's rate over many small rows and a few large ones, the shape
    /// of QUIL's keyspace on a store holding all of it. `QUIL_INDEX_ROWS`
    /// rows (default 1,000,000) of `QUIL_INDEX_ROW_BYTES` (default 280).
    #[test]
    #[ignore = "measurement"]
    fn measure_the_walk_and_an_index_page() {
        let env = |name: &str, default: usize| {
            std::env::var(name)
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(default)
        };
        let rows = env("QUIL_INDEX_ROWS", 1_000_000) as u32;
        let row_bytes = env("QUIL_INDEX_ROW_BYTES", 280);
        let dir = tempfile::TempDir::new().unwrap();
        let db = RocksDb::open(dir.path()).unwrap();
        let started = Instant::now();
        let mut batch = rocksdb::WriteBatch::default();
        for n in 0..rows {
            // Spread like content addresses, so rows interleave with the
            // few large ones.
            let mut key = DOMAIN.to_vec();
            key.extend_from_slice(&spread(n));
            let len = if n % 10_000 == 0 {
                12 * 1024
            } else {
                row_bytes
            };
            batch.put(
                crate::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard(), &key, 1),
                vec![(n % 251) as u8; len],
            );
            if batch.len() == 10_000 {
                db.inner().write(std::mem::take(&mut batch)).unwrap();
            }
        }
        db.inner().write(batch).unwrap();
        db.inner().flush().unwrap();
        eprintln!(
            "seeded {rows} rows of {row_bytes} bytes in {:?}",
            started.elapsed()
        );
        let store = RocksHypergraphStore::new(db.inner());
        let started = Instant::now();
        let mut steps = 0;
        let progress = loop {
            steps += 1;
            let progress = walk_step(&db.inner(), WALK_STEP_ROWS).unwrap();
            if progress.complete {
                break progress;
            }
        };
        let walked = started.elapsed();
        eprintln!(
            "walk: {} rows in {:?} over {steps} steps: {:.0} rows/s; 121,863,414 rows at that rate: {:.0} s",
            progress.rows,
            walked,
            progress.rows as f64 / walked.as_secs_f64(),
            121_863_414.0 * walked.as_secs_f64() / progress.rows as f64,
        );
        let started = Instant::now();
        let (found, pages) = page_all(&store);
        let paged = started.elapsed();
        eprintln!(
            "index scan: {} large rows in {pages} pages, {:?} ({:?} per page)",
            found.len(),
            paged,
            paged / pages as u32
        );
        assert_eq!(found.len(), (rows as usize).div_ceil(10_000));
    }
}
