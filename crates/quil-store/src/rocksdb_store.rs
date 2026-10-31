use std::path::Path;

use quil_types::error::{QuilError, Result};
use quil_types::store;

/// Detected on-disk layout of a key-value store directory. The Rust
/// node uses RocksDB; the Go node used Pebble. Both write SST/MANIFEST
/// files but their `OPTIONS-*` file headers identify the engine. We
/// scan the OPTIONS file rather than trying to open with RocksDB
/// because opening a Pebble store as RocksDB produces a confusing
/// "Corruption" error far from the actual cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFormat {
    /// Directory does not exist, is empty, or has no OPTIONS file.
    Empty,
    /// `OPTIONS-NNNNNN` file contains `rocksdb_version=` — this is a
    /// store the Rust node wrote and can reopen directly.
    RocksDb,
    /// `OPTIONS-NNNNNN` file contains `pebble_version=` — this is the
    /// Go node's old format.
    Pebble,
    /// Directory exists and has files but no recognizable OPTIONS
    /// header. Treat as unknown to avoid clobbering user data.
    Unknown,
}

/// Sniff the on-disk format of a key-value store directory.
///
/// Looks for the Pebble/RocksDB `OPTIONS-NNNNNN` file (both engines
/// write one) and reads its `[Version]` block to distinguish them.
/// Pebble emits `pebble_version=` and RocksDB emits `rocksdb_version=`
/// in the same `[Version]` section.
pub fn detect_store_format(path: &Path) -> StoreFormat {
    if !path.exists() {
        return StoreFormat::Empty;
    }
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return StoreFormat::Unknown,
    };
    let mut had_any_file = false;
    let mut had_options = false;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Hidden files such as the proof-worker admission lock files
        // (`.proof-worker-admission.lock`, `.1`, ...) are created in the base
        // directory before the store is opened; they are not store content.
        if name.starts_with('.') {
            continue;
        }
        had_any_file = true;
        if !name.starts_with("OPTIONS-") {
            continue;
        }
        had_options = true;
        // Only need the first few KB — version section is at the top.
        let mut buf = Vec::with_capacity(8 * 1024);
        if let Ok(f) = std::fs::File::open(entry.path()) {
            use std::io::Read;
            let _ = f.take(8 * 1024).read_to_end(&mut buf);
        }
        let head = String::from_utf8_lossy(&buf);
        if head.contains("rocksdb_version=") {
            return StoreFormat::RocksDb;
        }
        if head.contains("pebble_version=") {
            return StoreFormat::Pebble;
        }
    }
    if !had_any_file {
        StoreFormat::Empty
    } else if had_options {
        // OPTIONS file existed but had neither version marker.
        StoreFormat::Unknown
    } else {
        // Files but no OPTIONS — could be partial init.
        StoreFormat::Unknown
    }
}

/// RocksDB-backed key-value store.
pub struct RocksDb {
    db: quil_forest::CoordinatedDb,
    /// Its block cache is the process's shared one ([`shared_block_cache`]).
    shared_block_cache: bool,
}

/// Per-instance RocksDB read health. See [`RocksDb::health`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RocksDbHealth {
    pub level0_files: u64,
    pub pending_compaction_bytes: u64,
    pub running_compactions: u64,
    pub write_stopped: bool,
    pub delayed_write_rate: u64,
    pub block_cache: u64,
    pub block_cache_capacity: u64,
}

/// Per-instance RocksDB memory accounting (bytes). See [`RocksDb::memory_usage`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RocksDbMemory {
    pub block_cache: u64,
    pub block_cache_pinned: u64,
    pub memtables: u64,
    pub table_readers: u64,
    /// `block_cache` is the process's shared cache, which every store
    /// sharing it reports ([`shared_block_cache_memory`]).
    pub block_cache_shared: bool,
}

impl RocksDbMemory {
    /// Total bytes this instance accounts for: a shared block cache is
    /// counted once for the process, not per store.
    pub fn total(&self) -> u64 {
        // block_cache_pinned is a subset of block_cache — don't double count.
        let block_cache = if self.block_cache_shared {
            0
        } else {
            self.block_cache
        };
        block_cache + self.memtables + self.table_readers
    }
}

/// Block cache of a store that is not an archive's: enough for the hot
/// working set of a regular node, which also runs a store per worker.
pub(crate) const DEFAULT_BLOCK_CACHE_BYTES: usize = 256 << 20;
/// What the stores of one process that are not an archive's share as block
/// cache at most ([`shared_block_cache`]); `QUIL_ROCKSDB_BLOCK_CACHE_TOTAL_MB`
/// overrides it. A cache per store took 256 MB for every worker's store: 4
/// GB on a node of 15 workers, 7 GB on one of 28 (2026-10-31).
const DEFAULT_SHARED_BLOCK_CACHE_BYTES: usize = 1 << 30;

/// The block cache this process's stores that are not an archive's share:
/// [`DEFAULT_BLOCK_CACHE_BYTES`] per store opened, up to the budget
/// (`QUIL_ROCKSDB_BLOCK_CACHE_TOTAL_MB`, default 1 GB), so a process of one
/// store keeps what it had and one of many workers holds the budget however
/// many it runs.
fn shared_block_cache() -> rocksdb::Cache {
    let budget = shared_block_cache_budget();
    let mut shared = SHARED_BLOCK_CACHE
        .get_or_init(|| {
            std::sync::Mutex::new(SharedBlockCache {
                cache: rocksdb::Cache::new_lru_cache(0),
                stores: 0,
            })
        })
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    shared.stores += 1;
    let capacity = shared_capacity(shared.stores, budget);
    shared.cache.set_capacity(capacity);
    shared.cache.clone()
}

/// The shared cache's capacity once `stores` stores have opened on it.
fn shared_capacity(stores: usize, budget: usize) -> usize {
    stores.saturating_mul(DEFAULT_BLOCK_CACHE_BYTES).min(budget)
}

/// The shared cache's budget: `QUIL_ROCKSDB_BLOCK_CACHE_TOTAL_MB`, else
/// [`DEFAULT_SHARED_BLOCK_CACHE_BYTES`].
fn shared_block_cache_budget() -> usize {
    std::env::var("QUIL_ROCKSDB_BLOCK_CACHE_TOTAL_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(DEFAULT_SHARED_BLOCK_CACHE_BYTES, |mb| {
            mb.saturating_mul(1024 * 1024)
        })
}

/// `QUIL_ROCKSDB_BLOCK_CACHE_MB`, in bytes, when it gives every store a
/// block cache of its own of that size.
fn own_block_cache_override() -> Option<usize> {
    std::env::var("QUIL_ROCKSDB_BLOCK_CACHE_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|mb| mb.saturating_mul(1024 * 1024))
}

/// The block cache `stores` stores of this process that are not an
/// archive's hold together once open, in bytes: the shared cache's capacity
/// for that many; `None` when `QUIL_ROCKSDB_BLOCK_CACHE_MB` gives each store
/// its own cache instead. For reports of the effective configuration.
pub fn shared_block_cache_bytes(stores: usize) -> Option<usize> {
    if own_block_cache_override().is_some() {
        return None;
    }
    Some(shared_capacity(stores, shared_block_cache_budget()))
}

struct SharedBlockCache {
    cache: rocksdb::Cache,
    /// Stores opened on it in this process (reopened ones again).
    stores: usize,
}

static SHARED_BLOCK_CACHE: std::sync::OnceLock<std::sync::Mutex<SharedBlockCache>> =
    std::sync::OnceLock::new();

/// The shared block cache's `(usage, capacity)` bytes, once a store opened
/// on it: what its stores' [`RocksDbMemory::total`] leave out.
pub fn shared_block_cache_memory() -> Option<(u64, u64)> {
    let shared = SHARED_BLOCK_CACHE
        .get()?
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let capacity = shared_capacity(shared.stores, shared_block_cache_budget());
    Some((shared.cache.get_usage() as u64, capacity as u64))
}
/// Bounds of an archive's block cache ([`archive_block_cache_bytes`]).
const MIN_ARCHIVE_BLOCK_CACHE_BYTES: usize = DEFAULT_BLOCK_CACHE_BYTES;
const MAX_ARCHIVE_BLOCK_CACHE_BYTES: usize = 32 << 30;

/// An archive's block cache: a quarter of the memory this process may use,
/// within 256 MB and 32 GB. An archive's store holds every application's
/// history (280 GB on one), its index blocks are cached alongside its data,
/// and peers' reads reach all of it; at 256 MB one archive spent 68% of 32
/// cores decompressing blocks it had just evicted (2026-10-13).
pub fn archive_block_cache_bytes() -> usize {
    archive_block_cache_for(memory_budget_bytes())
}

fn archive_block_cache_for(memory: Option<u64>) -> usize {
    memory
        .map(|bytes| usize::try_from(bytes / 4).unwrap_or(usize::MAX))
        .unwrap_or(MIN_ARCHIVE_BLOCK_CACHE_BYTES)
        .clamp(MIN_ARCHIVE_BLOCK_CACHE_BYTES, MAX_ARCHIVE_BLOCK_CACHE_BYTES)
}

/// Physical memory, or the process's cgroup limit when lower (a container
/// sees the host's memory but may use only its limit).
fn memory_budget_bytes() -> Option<u64> {
    // SAFETY: sysconf reads system configuration and has no preconditions.
    let (pages, page) = unsafe {
        (
            libc::sysconf(libc::_SC_PHYS_PAGES),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    let physical = u64::try_from(pages)
        .ok()?
        .checked_mul(u64::try_from(page).ok()?)?;
    // cgroup v2, then v1; "max" (no limit) does not parse.
    let limit = [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ]
    .iter()
    .find_map(|path| {
        std::fs::read_to_string(path)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    });
    Some(limit.map_or(physical, |limit| limit.min(physical)).max(1))
}

impl RocksDb {
    /// Open a RocksDB database at the given path.
    /// Runs pending migrations automatically.
    /// Its block cache is the process's shared one ([`shared_block_cache`]),
    /// unless `QUIL_ROCKSDB_BLOCK_CACHE_MB` gives each store its own of that
    /// size, as before the shared cache.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_block_cache(path, None)
    }

    /// [`Self::open`] for an archive's store, with its own block cache sized
    /// from memory ([`archive_block_cache_bytes`]).
    pub fn open_archive(path: &Path) -> Result<Self> {
        Self::open_with_block_cache(path, Some(archive_block_cache_bytes()))
    }

    /// A store with its own block cache of `block_cache_bytes`, or the
    /// shared one (`None`); `QUIL_ROCKSDB_BLOCK_CACHE_MB` gives every store
    /// its own of that size.
    fn open_with_block_cache(path: &Path, block_cache_bytes: Option<usize>) -> Result<Self> {
        let (opts, shared) = Self::store_options_for(block_cache_bytes);
        let db = rocksdb::DB::open(&opts, path)
            .map_err(|e| QuilError::Store(format!("failed to open rocksdb: {}", e)))?;

        // Run pending migrations
        let migrations = crate::migration::rust_node_migrations();
        crate::migration::run_migrations(&db, &migrations)?;

        Ok(Self {
            db: Self::coordinated(db),
            shared_block_cache: shared,
        })
    }

    /// The options a node store opens with, with a block cache of its own
    /// of `block_cache_bytes`; tests that measure the store's own behaviour
    /// open with them too.
    #[cfg(test)]
    pub(crate) fn store_options(block_cache_bytes: usize) -> rocksdb::Options {
        Self::store_options_for(Some(block_cache_bytes)).0
    }

    /// [`Self::store_options`], with the process's shared block cache for
    /// `None`; and whether the cache is the shared one.
    fn store_options_for(block_cache_bytes: Option<usize>) -> (rocksdb::Options, bool) {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);

        opts.set_write_buffer_size(64 * 1024 * 1024);

        opts.set_max_open_files(1000);
        opts.set_level_zero_file_num_compaction_trigger(8);
        opts.set_level_zero_slowdown_writes_trigger(16);
        opts.set_level_zero_stop_writes_trigger(32);

        // WRITE-STALL AVOIDANCE. The per-frame materialize commit is a synchronous
        // `db.write` (memtable + WAL). Normally fast, but RocksDB THROTTLES writes
        // once L0 files pile up faster than compaction drains them (the
        // slowdown/stop triggers above) or once all memtables are full awaiting a
        // flush. On slower machines compaction can't keep up under bursty frame
        // commits, so `db.write` blocks — surfacing as transient, payload-agnostic
        // "parent (N-1) prover root not materialized before deadline" proposer
        // misses (materialization lag). Give background flush+compaction enough
        // threads to keep up, plus extra memtable headroom to absorb bursts.
        // Threads scale with cores (compaction is the bottleneck on weak HW);
        // env-overridable for constrained nodes.
        let bg_threads: i32 = std::env::var("QUIL_ROCKSDB_BG_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| (n.get() as i32).clamp(2, 8))
                    .unwrap_or(4)
            });
        opts.increase_parallelism(bg_threads);
        opts.set_max_background_jobs(bg_threads);
        // More memtables in flight (default 2) so a flush stall doesn't immediately
        // block writes; the commit can keep filling a fresh buffer while older ones
        // flush in the background.
        opts.set_max_write_buffer_number(4);

        // LZ4 compression: ~50% size reduction at ~5% CPU cost.
        // RocksDB's default is Snappy (worse ratio); LZ4 is the
        // standard pick for write-heavy workloads.
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        // Block-cache budget. Without an explicit cache RocksDB
        // grows an internal cache that can balloon under churn.
        let own_bytes = own_block_cache_override().or(block_cache_bytes);
        let shared = own_bytes.is_none();
        let block_cache = match own_bytes {
            Some(bytes) => rocksdb::Cache::new_lru_cache(bytes),
            None => shared_block_cache(),
        };
        let mut block_opts = rocksdb::BlockBasedOptions::default();
        block_opts.set_block_cache(&block_cache);
        // Account index + filter blocks against the cache budget,
        // and pin L0 filter+index blocks so a cold sweep can't
        // evict the hot consensus working set.
        block_opts.set_cache_index_and_filter_blocks(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        // Partitioned index: a table file's index is cut into 4 KB blocks
        // under a small top level, pinned while the file is open, so a read
        // loads one partition instead of the file's whole index. Whole
        // indexes of a 280 GB store did not fit a 256 MB cache: every read
        // that missed re-read and decompressed one (2026-10-13). Files keep
        // the index they were written with, so this reaches older data as
        // compaction rewrites it, and any build reads either kind.
        block_opts.set_index_type(rocksdb::BlockBasedIndexType::TwoLevelIndexSearch);
        block_opts.set_metadata_block_size(4096);
        block_opts.set_pin_top_level_index_and_filter(true);
        opts.set_block_based_table_factory(&block_opts);
        (opts, shared)
    }

    /// Inspect an existing, stopped database without writes or migrations.
    /// Unlike secondary mode this supports snapshots; it does not follow a
    /// running primary. Existing WAL records are included in the read view.
    pub fn open_for_read_only(path: &Path) -> Result<Self> {
        let mut opts = rocksdb::Options::default();
        opts.set_max_open_files(64);
        let db = rocksdb::DB::open_for_read_only(&opts, path, false)
            .map_err(|e| QuilError::Store(format!("failed to open rocksdb read-only: {e}")))?;
        Ok(Self {
            db: quil_forest::CoordinatedDb::new(db),
            shared_block_cache: false,
        })
    }

    /// Open a database another process is running, read-only, as the
    /// point-in-time view of its files and WAL at open. It takes no lock and
    /// writes nothing. Every table file is opened up front, so a compaction
    /// by the running process cannot delete a file this view still needs
    /// (the open handles keep it readable); snapshots work, unlike on a
    /// secondary instance.
    pub fn open_for_read_only_live(path: &Path) -> Result<Self> {
        let mut opts = rocksdb::Options::default();
        opts.set_max_open_files(-1);
        let db = rocksdb::DB::open_for_read_only(&opts, path, false).map_err(|e| {
            QuilError::Store(format!("failed to open rocksdb read-only (live): {e}"))
        })?;
        Ok(Self {
            db: quil_forest::CoordinatedDb::new(db),
            shared_block_cache: false,
        })
    }

    /// Open the database at `primary_path` as a read-only secondary
    /// instance. Lets us read from a store that another process holds
    /// the primary lock on — used by `--node-info` so a running node
    /// doesn't block the CLI inspection. `secondary_path` is a separate
    /// writable directory where the secondary instance stores its
    /// catch-up bookkeeping; pass a temp dir.
    ///
    /// Callers should invoke
    /// [`rocksdb::DB::try_catch_up_with_primary`] before reading to
    /// pick up the primary's latest committed state.
    pub fn open_as_secondary(primary_path: &Path, secondary_path: &Path) -> Result<Self> {
        let mut opts = rocksdb::Options::default();
        opts.set_max_open_files(64);
        let db = rocksdb::DB::open_as_secondary(&opts, primary_path, secondary_path)
            .map_err(|e| QuilError::Store(format!("failed to open rocksdb as secondary: {}", e)))?;
        // Skip migrations on secondary — only the primary may write.
        Ok(Self {
            db: quil_forest::CoordinatedDb::new(db),
            shared_block_cache: false,
        })
    }

    /// Open an in-memory RocksDB instance (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let tmp = tempfile::TempDir::new()
            .map_err(|e| QuilError::Store(format!("failed to create temp dir: {}", e)))?;
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, tmp.path())
            .map_err(|e| QuilError::Store(format!("failed to open rocksdb: {}", e)))?;
        // Leak the TempDir so it's not cleaned up while DB is open.
        // This is intentional for in-memory test stores.
        std::mem::forget(tmp);
        Ok(Self {
            db: Self::coordinated(db),
            shared_block_cache: false,
        })
    }

    /// A writable store watches the prover registry's keys, so execution
    /// branches can reuse a registry scan no write has changed.
    fn coordinated(db: rocksdb::DB) -> quil_forest::CoordinatedDb {
        quil_forest::CoordinatedDb::with_watched_prefixes(
            db,
            crate::encoding::prover_registry_key_prefixes(),
        )
    }

    /// Share the database and its write barrier across store implementations.
    pub fn inner(&self) -> quil_forest::CoordinatedDb {
        self.db.clone()
    }

    /// RocksDB's own memory accounting for this instance, in bytes. Each
    /// open DB holds a block cache (256 MB default) + live memtables +
    /// table-reader (index/filter) memory. A node runs one of these per
    /// store (master) plus one per worker, so summing these across all
    /// instances attributes the RocksDB share of process RSS — the key
    /// number when diagnosing OOM on a node running many workers.
    pub fn memory_usage(&self) -> RocksDbMemory {
        let prop = |name: &str| self.db.property_int_value(name).ok().flatten().unwrap_or(0);
        RocksDbMemory {
            block_cache: prop("rocksdb.block-cache-usage"),
            block_cache_pinned: prop("rocksdb.block-cache-pinned-usage"),
            memtables: prop("rocksdb.cur-size-all-mem-tables"),
            table_readers: prop("rocksdb.estimate-table-readers-mem"),
            block_cache_shared: self.shared_block_cache,
        }
    }

    /// Compaction and cache state that slows every read when it backs up:
    /// each level-0 file is searched on every point read, and a block cache
    /// smaller than the index blocks turns reads into disk seeks.
    pub fn health(&self) -> RocksDbHealth {
        let prop = |name: &str| self.db.property_int_value(name).ok().flatten().unwrap_or(0);
        RocksDbHealth {
            level0_files: prop("rocksdb.num-files-at-level0"),
            pending_compaction_bytes: prop("rocksdb.estimate-pending-compaction-bytes"),
            running_compactions: prop("rocksdb.num-running-compactions"),
            write_stopped: prop("rocksdb.is-write-stopped") != 0,
            delayed_write_rate: prop("rocksdb.actual-delayed-write-rate"),
            block_cache: prop("rocksdb.block-cache-usage"),
            block_cache_capacity: prop("rocksdb.block-cache-capacity"),
        }
    }

    /// Create an owned iterator over a key range.
    fn make_iter(&self, lower: &[u8], upper: &[u8]) -> Result<Box<dyn store::Iterator>> {
        Ok(Box::new(RocksIterator::new(self.db.clone(), lower, upper)))
    }
}

#[cfg(test)]
mod read_only_tests {
    use super::*;

    #[test]
    fn read_only_inspection_supports_snapshots_and_cannot_write_or_migrate() {
        let directory = tempfile::tempdir().unwrap();
        // Bypass our migrating open path so a surprise migration is observable.
        {
            let primary = rocksdb::DB::open_default(directory.path()).unwrap();
            primary.put(b"saved", b"checkpoint").unwrap();
        }
        {
            let read_only = RocksDb::open_for_read_only(directory.path()).unwrap();
            let db = read_only.inner();
            let snapshot = db.snapshot();
            assert_eq!(
                snapshot.get(b"saved").unwrap(),
                Some(b"checkpoint".to_vec())
            );
            assert_eq!(snapshot.iterator(rocksdb::IteratorMode::Start).count(), 1);
            assert!(db.put(b"saved", b"changed").is_err());
        }
        let reopened = rocksdb::DB::open_default(directory.path()).unwrap();
        assert_eq!(
            reopened.get(b"saved").unwrap(),
            Some(b"checkpoint".to_vec())
        );
        assert_eq!(reopened.iterator(rocksdb::IteratorMode::Start).count(), 1);
    }

    #[test]
    fn an_archive_block_cache_is_a_quarter_of_memory_within_bounds() {
        const GB: u64 = 1 << 30;
        assert_eq!(
            archive_block_cache_for(Some(123 * GB)),
            (123 * GB / 4) as usize
        );
        assert_eq!(archive_block_cache_for(Some(8 * GB)), (2 * GB) as usize);
        assert_eq!(
            archive_block_cache_for(Some(GB / 2)),
            MIN_ARCHIVE_BLOCK_CACHE_BYTES
        );
        assert_eq!(
            archive_block_cache_for(Some(1024 * GB)),
            MAX_ARCHIVE_BLOCK_CACHE_BYTES
        );
        assert_eq!(archive_block_cache_for(None), MIN_ARCHIVE_BLOCK_CACHE_BYTES);
        assert!(memory_budget_bytes().is_some_and(|bytes| bytes > 0));
    }

    /// The stores of a process that are not an archive's share one block
    /// cache: what one store reads into it every store's usage shows, and
    /// its capacity does not grow with the number of stores (workers).
    #[test]
    fn stores_share_one_block_cache_whatever_their_number() {
        if std::env::var_os("QUIL_ROCKSDB_BLOCK_CACHE_MB").is_some() {
            return; // every store has its own cache by request
        }
        const MB: u64 = 1 << 20;
        let dirs: Vec<_> = (0..12).map(|_| tempfile::tempdir().unwrap()).collect();
        let mut stores: Vec<RocksDb> = dirs[..8]
            .iter()
            .map(|dir| RocksDb::open(dir.path()).unwrap())
            .collect();
        let capacity = |stores: &[RocksDb]| stores[0].health().block_cache_capacity;
        let with_eight = capacity(&stores);
        let db = stores[0].inner();
        let key = |i: u32| format!("key-{i:08}").into_bytes();
        for i in 0..4_000 {
            db.put(key(i), [5u8; 1024]).unwrap();
        }
        db.flush().unwrap();
        let before = stores[7].memory_usage().block_cache;
        for i in 0..4_000 {
            assert!(db.get(key(i)).unwrap().is_some());
        }
        let shown = stores[7].memory_usage();
        assert!(
            shown.block_cache >= before + 2 * MB,
            "another store's reads did not reach this store's block cache: {} then {} bytes",
            before,
            shown.block_cache
        );
        assert_eq!(
            shown.total(),
            shown.memtables + shown.table_readers,
            "a store's total leaves the shared cache out"
        );
        stores.extend(
            dirs[8..]
                .iter()
                .map(|dir| RocksDb::open(dir.path()).unwrap()),
        );
        assert_eq!(capacity(&stores), with_eight, "more stores, the same cache");
        assert!(stores
            .iter()
            .all(|store| store.health().block_cache_capacity == with_eight));
        assert!(with_eight <= 1024 * MB, "{with_eight} bytes");
    }

    #[test]
    fn the_shared_block_cache_grows_per_store_up_to_its_budget() {
        const MB: usize = 1 << 20;
        assert_eq!(shared_capacity(1, 1024 * MB), 256 * MB);
        if std::env::var_os("QUIL_ROCKSDB_BLOCK_CACHE_MB").is_none()
            && std::env::var_os("QUIL_ROCKSDB_BLOCK_CACHE_TOTAL_MB").is_none()
        {
            // What a report of the configuration reads: the master and 15
            // workers hold the 1 GB budget, a lone worker process 256 MB.
            assert_eq!(shared_block_cache_bytes(16), Some(1024 * MB));
            assert_eq!(shared_block_cache_bytes(1), Some(256 * MB));
        }
        assert_eq!(shared_capacity(3, 1024 * MB), 768 * MB);
        assert_eq!(shared_capacity(4, 1024 * MB), 1024 * MB);
        assert_eq!(shared_capacity(28, 1024 * MB), 1024 * MB);
        assert_eq!(shared_capacity(28, 64 * MB), 64 * MB);
    }

    /// New table files carry a partitioned index; files written without one
    /// (an older build) still read.
    #[test]
    fn new_table_files_have_a_partitioned_index_and_older_ones_still_read() {
        let directory = tempfile::tempdir().unwrap();
        let key = |i: u32| format!("key-{i:08}").into_bytes();
        {
            let older = rocksdb::DB::open_default(directory.path()).unwrap();
            for i in 0..20_000 {
                older.put(key(i), [7u8; 64]).unwrap();
            }
            older.flush().unwrap();
        }
        {
            let store = RocksDb::open_archive(directory.path()).unwrap();
            let db = store.inner();
            for i in 20_000..40_000 {
                db.put(key(i), [9u8; 64]).unwrap();
            }
            db.flush().unwrap();
            assert_eq!(db.get(key(7)).unwrap(), Some(vec![7u8; 64]));
            assert_eq!(db.get(key(30_000)).unwrap(), Some(vec![9u8; 64]));
            assert!(store.health().block_cache_capacity >= MIN_ARCHIVE_BLOCK_CACHE_BYTES as u64);
        }
        // Table properties live in the files: read them under default options.
        let reopened = rocksdb::DB::open_default(directory.path()).unwrap();
        let properties = reopened
            .property_value("rocksdb.aggregated-table-properties")
            .unwrap()
            .unwrap();
        let partitions = properties
            .split(';')
            .find_map(|field| {
                field
                    .trim()
                    .strip_prefix("# index partitions=")?
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
            .unwrap_or(0);
        assert!(
            partitions > 0,
            "the new file has a partitioned index: {properties}"
        );
        assert_eq!(reopened.get(key(7)).unwrap(), Some(vec![7u8; 64]));
        assert_eq!(reopened.get(key(30_000)).unwrap(), Some(vec![9u8; 64]));
    }
}

impl store::KvDb for RocksDb {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db
            .get(key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn get_with(&self, key: &[u8], read: &mut dyn FnMut(&[u8])) -> Result<bool> {
        let value = self
            .db
            .get_pinned(key)
            .map_err(|e| QuilError::Store(e.to_string()))?;
        Ok(value.map(|value| read(&value)).is_some())
    }

    fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.db
            .put(key, value)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        self.db
            .delete(key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn new_batch(&self, _indexed: bool) -> Result<Box<dyn store::Transaction>> {
        Ok(Box::new(RocksTransaction {
            db: self.db.clone(),
            batch: std::sync::Mutex::new(rocksdb::WriteBatch::default()),
        }))
    }

    fn new_iter(&self, lower: &[u8], upper: &[u8]) -> Result<Box<dyn store::Iterator>> {
        self.make_iter(lower, upper)
    }

    fn compact(&self, start: &[u8], end: &[u8], _parallelize: bool) -> Result<()> {
        self.db.compact_range(Some(start), Some(end));
        Ok(())
    }

    fn holds_file_of(&self, start: &[u8], end: &[u8], min_file_bytes: u64) -> Result<bool> {
        let files = self
            .db
            .live_files()
            .map_err(|e| QuilError::Store(e.to_string()))?;
        Ok(files.iter().any(|file| {
            file.size as u64 >= min_file_bytes
                && match (file.start_key.as_deref(), file.end_key.as_deref()) {
                    (Some(first), Some(last)) => first < end && last >= start,
                    _ => false,
                }
        }))
    }

    fn compact_reclaiming(&self, start: &[u8], end: &[u8], min_file_bytes: u64) -> Result<bool> {
        if !self.holds_file_of(start, end, min_file_bytes)? {
            return Ok(false);
        }
        let mut options = rocksdb::CompactOptions::default();
        options.set_exclusive_manual_compaction(false);
        options.set_bottommost_level_compaction(rocksdb::BottommostLevelCompaction::ForceOptimized);
        self.db.compact_range_opt(Some(start), Some(end), &options);
        Ok(true)
    }

    fn compact_all(&self) -> Result<()> {
        self.db.compact_range::<&[u8], &[u8]>(None, None);
        Ok(())
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }

    fn delete_range(&self, start: &[u8], end: &[u8]) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete_range(start, end);
        self.db
            .write(batch)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn approximate_memory_bytes(&self) -> u64 {
        self.memory_usage().total()
    }
}

/// A write batch acting as a transaction.
pub struct RocksTransaction {
    pub(crate) db: quil_forest::CoordinatedDb,
    pub(crate) batch: std::sync::Mutex<rocksdb::WriteBatch>,
}

impl store::Transaction for RocksTransaction {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db
            .get(key)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().put(key, value);
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<()> {
        let batch = self.batch.into_inner().unwrap();
        self.db
            .write(batch)
            .map_err(|e| QuilError::Store(e.to_string()))
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().delete(key);
        Ok(())
    }

    fn abort(self: Box<Self>) -> Result<()> {
        Ok(())
    }

    fn new_iter(&self, lower: &[u8], upper: &[u8]) -> Result<Box<dyn store::Iterator>> {
        Ok(Box::new(RocksIterator::new(self.db.clone(), lower, upper)))
    }

    fn delete_range(&self, lower: &[u8], upper: &[u8]) -> Result<()> {
        self.batch.lock().unwrap().delete_range(lower, upper);
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// An owned iterator that holds an Arc to the DB and materializes
/// key/value pairs so it can be Send + 'static.
pub struct RocksIterator {
    db: quil_forest::CoordinatedDb,
    lower: Vec<u8>,
    upper: Vec<u8>,
    /// Materialized entries: (key, value) pairs.
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// Current position in entries (-1 = before first).
    pos: i64,
    loaded: bool,
}

impl RocksIterator {
    fn new(db: quil_forest::CoordinatedDb, lower: &[u8], upper: &[u8]) -> Self {
        Self {
            db,
            lower: lower.to_vec(),
            upper: upper.to_vec(),
            entries: Vec::new(),
            pos: -1,
            loaded: false,
        }
    }

    fn ensure_loaded(&mut self) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(self.lower.clone());
        read_opts.set_iterate_upper_bound(self.upper.clone());

        let iter = self
            .db
            .iterator_opt(rocksdb::IteratorMode::Start, read_opts);
        for item in iter {
            match item {
                Ok((k, v)) => {
                    self.entries.push((k.to_vec(), v.to_vec()));
                }
                Err(_) => break,
            }
        }
    }

    fn valid_pos(&self) -> bool {
        self.pos >= 0 && (self.pos as usize) < self.entries.len()
    }
}

impl store::Iterator for RocksIterator {
    fn key(&self) -> &[u8] {
        if self.valid_pos() {
            &self.entries[self.pos as usize].0
        } else {
            &[]
        }
    }

    fn value(&self) -> &[u8] {
        if self.valid_pos() {
            &self.entries[self.pos as usize].1
        } else {
            &[]
        }
    }

    fn first(&mut self) -> bool {
        self.ensure_loaded();
        if self.entries.is_empty() {
            self.pos = -1;
            return false;
        }
        self.pos = 0;
        true
    }

    fn next(&mut self) -> bool {
        self.ensure_loaded();
        self.pos += 1;
        self.valid_pos()
    }

    fn prev(&mut self) -> bool {
        self.ensure_loaded();
        self.pos -= 1;
        self.valid_pos()
    }

    fn valid(&self) -> bool {
        self.valid_pos()
    }

    fn close(&mut self) -> Result<()> {
        self.entries.clear();
        self.pos = -1;
        Ok(())
    }

    fn seek_ge(&mut self, target: &[u8]) -> bool {
        self.ensure_loaded();
        match self
            .entries
            .binary_search_by(|(k, _)| k.as_slice().cmp(target))
        {
            Ok(idx) => {
                self.pos = idx as i64;
                true
            }
            Err(idx) => {
                self.pos = idx as i64;
                self.valid_pos()
            }
        }
    }

    fn seek_lt(&mut self, target: &[u8]) -> bool {
        self.ensure_loaded();
        match self
            .entries
            .binary_search_by(|(k, _)| k.as_slice().cmp(target))
        {
            Ok(idx) => {
                self.pos = idx as i64 - 1;
                self.valid_pos()
            }
            Err(idx) => {
                self.pos = idx as i64 - 1;
                self.valid_pos()
            }
        }
    }

    fn last(&mut self) -> bool {
        self.ensure_loaded();
        if self.entries.is_empty() {
            self.pos = -1;
            return false;
        }
        self.pos = self.entries.len() as i64 - 1;
        true
    }
}
