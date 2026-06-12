use std::path::Path;
use std::sync::Arc;

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
        had_any_file = true;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("OPTIONS-") {
            continue;
        }
        had_options = true;
        // Only need the first few KB — version section is at the top.
        let mut buf = Vec::with_capacity(8 * 1024);
        if let Ok(mut f) = std::fs::File::open(entry.path()) {
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
    db: Arc<rocksdb::DB>,
}

impl RocksDb {
    /// Open a RocksDB database at the given path.
    /// Runs pending migrations automatically.
    pub fn open(path: &Path) -> Result<Self> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);

        opts.set_write_buffer_size(64 * 1024 * 1024);

        opts.set_max_open_files(1000);
        opts.set_level_zero_file_num_compaction_trigger(8);
        opts.set_level_zero_slowdown_writes_trigger(16);
        opts.set_level_zero_stop_writes_trigger(32);

        // LZ4 compression: ~50% size reduction at ~5% CPU cost.
        // RocksDB's default is Snappy (worse ratio); LZ4 is the
        // standard pick for write-heavy workloads.
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        // Block-cache budget. Without an explicit cache RocksDB
        // grows an internal cache that can balloon under churn.
        // 256 MB is enough for the hot working set on a typical
        // mainnet archive node; tune via env if needed.
        const DEFAULT_BLOCK_CACHE_MB: usize = 256;
        let cache_mb: usize = std::env::var("QUIL_ROCKSDB_BLOCK_CACHE_MB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_BLOCK_CACHE_MB);
        let block_cache = rocksdb::Cache::new_lru_cache(cache_mb * 1024 * 1024);
        let mut block_opts = rocksdb::BlockBasedOptions::default();
        block_opts.set_block_cache(&block_cache);
        // Account index + filter blocks against the cache budget,
        // and pin L0 filter+index blocks so a cold sweep can't
        // evict the hot consensus working set.
        block_opts.set_cache_index_and_filter_blocks(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        opts.set_block_based_table_factory(&block_opts);

        let db = rocksdb::DB::open(&opts, path)
            .map_err(|e| QuilError::Store(format!("failed to open rocksdb: {}", e)))?;

        // Run pending migrations
        let migrations = crate::migration::rust_node_migrations();
        crate::migration::run_migrations(&db, &migrations)?;

        Ok(Self { db: Arc::new(db) })
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
        Ok(Self { db: Arc::new(db) })
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
        Ok(Self { db: Arc::new(db) })
    }

    /// Get the inner Arc for sharing across store implementations.
    pub fn inner(&self) -> Arc<rocksdb::DB> {
        self.db.clone()
    }

    /// Create an owned iterator over a key range.
    fn make_iter(&self, lower: &[u8], upper: &[u8]) -> Result<Box<dyn store::Iterator>> {
        Ok(Box::new(RocksIterator::new(self.db.clone(), lower, upper)))
    }
}

impl store::KvDb for RocksDb {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db
            .get(key)
            .map_err(|e| QuilError::Store(e.to_string()))
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
}

/// A write batch acting as a transaction.
pub struct RocksTransaction {
    pub(crate) db: Arc<rocksdb::DB>,
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

    fn as_any(&self) -> &dyn std::any::Any { self }
}

/// An owned iterator that holds an Arc to the DB and materializes
/// key/value pairs so it can be Send + 'static.
pub struct RocksIterator {
    db: Arc<rocksdb::DB>,
    lower: Vec<u8>,
    upper: Vec<u8>,
    /// Materialized entries: (key, value) pairs.
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// Current position in entries (-1 = before first).
    pos: i64,
    loaded: bool,
}

impl RocksIterator {
    fn new(db: Arc<rocksdb::DB>, lower: &[u8], upper: &[u8]) -> Self {
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

        let iter = self.db.iterator_opt(rocksdb::IteratorMode::Start, read_opts);
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
        match self.entries.binary_search_by(|(k, _)| k.as_slice().cmp(target)) {
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
        match self.entries.binary_search_by(|(k, _)| k.as_slice().cmp(target)) {
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
