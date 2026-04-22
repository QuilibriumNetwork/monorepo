use std::path::Path;
use std::sync::Arc;

use quil_types::error::{QuilError, Result};
use quil_types::store;

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
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB memtable
        opts.set_max_open_files(1000);
        opts.set_level_zero_file_num_compaction_trigger(8);
        opts.set_level_zero_slowdown_writes_trigger(16);
        opts.set_level_zero_stop_writes_trigger(32);

        let db = rocksdb::DB::open(&opts, path)
            .map_err(|e| QuilError::Store(format!("failed to open rocksdb: {}", e)))?;

        // Run pending migrations
        let migrations = crate::migration::rust_node_migrations();
        crate::migration::run_migrations(&db, &migrations)?;

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
