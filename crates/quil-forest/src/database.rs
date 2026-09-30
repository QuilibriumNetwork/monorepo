//! One write barrier for every handle to a live RocksDB instance.
//!
//! This owns the raw DB rather than accepting/exposing an `Arc<DB>`: a raw
//! writable alias could bypass the sequence check used for atomic publication.
//! Reads retain RocksDB's normal snapshot semantics. CRDT metadata and runtime
//! cache publication still require the execution owner's higher-level locks.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use quil_types::store::BackingStoreIdentity;
use rocksdb::{
    DBIterator, DBRawIterator, IteratorMode, ReadOptions, Snapshot, WriteBatch, WriteOptions, DB,
};

#[derive(Debug, thiserror::Error)]
pub enum DatabaseCommitError {
    #[error("database write barrier is poisoned")]
    Poisoned,
    #[error(
        "database has a failed write; reopen and reconcile durable state before writing again"
    )]
    PriorWriteFailed,
    #[error("execution publication belongs to another database")]
    ForeignDatabase,
    #[error("execution base changed (captured sequence {expected}, current {actual})")]
    Stale { expected: u64, actual: u64 },
    #[error("disjoint write outside its declared key prefixes")]
    OutsideKeyspace,
    #[error(transparent)]
    Storage(#[from] rocksdb::Error),
}

struct DatabaseInner {
    db: DB,
    writes: Mutex<WriteLedger>,
    failed_write: AtomicBool,
}

/// Sequence numbers recorded under the write barrier. A write confined to
/// declared two-byte prefixes is recorded per prefix; every other write is
/// general. Execution publication compares these against its own footprint.
#[derive(Default)]
struct WriteLedger {
    general: u64,
    disjoint: BTreeMap<[u8; 2], u64>,
}

/// Two-byte key prefixes a branch read, scanned or wrote. Marking is
/// conservative: any key or range that could fall in a prefix marks it.
#[derive(Clone)]
pub struct KeyPrefixSet(Box<[u64; 1024]>);

impl Default for KeyPrefixSet {
    fn default() -> Self {
        Self(Box::new([0; 1024]))
    }
}

impl KeyPrefixSet {
    fn index(first: u8, second: u8) -> usize {
        usize::from(first) << 8 | usize::from(second)
    }

    fn set(&mut self, index: usize) {
        self.0[index >> 6] |= 1 << (index & 63);
    }

    /// Inclusive, one word at a time: a wide cursor costs at most 1,024 ORs.
    fn set_span(&mut self, start: usize, end: usize) {
        for word in start >> 6..=end >> 6 {
            let low = if word == start >> 6 { start & 63 } else { 0 };
            let high = if word == end >> 6 { end & 63 } else { 63 };
            self.0[word] |= (u64::MAX >> (63 - high)) & (u64::MAX << low);
        }
    }

    pub fn contains(&self, prefix: [u8; 2]) -> bool {
        let index = Self::index(prefix[0], prefix[1]);
        self.0[index >> 6] & (1 << (index & 63)) != 0
    }

    /// A key shorter than two bytes conservatively marks the first prefix
    /// that it precedes.
    pub fn mark_key(&mut self, key: &[u8]) {
        let first = key.first().copied().unwrap_or(0);
        self.set(Self::index(first, key.get(1).copied().unwrap_or(0)));
    }

    /// Half-open range. Every prefix from the lower bound's prefix through the
    /// upper bound's prefix is marked, including one the upper bound excludes.
    pub fn mark_range(&mut self, lower: &[u8], upper: &[u8]) {
        let start = Self::index(
            lower.first().copied().unwrap_or(0),
            lower.get(1).copied().unwrap_or(0),
        );
        let end = match upper.first() {
            Some(first) => Self::index(*first, upper.get(1).copied().unwrap_or(u8::MAX)),
            None => return,
        };
        self.set_span(start, end.max(start));
    }
}

/// A batch whose keys and range endpoints are checked, as they are added, to
/// lie within declared two-byte prefixes. Use it only for records execution
/// does not need (for example consensus candidate bodies). The declaration
/// does not have to be trusted: a plan that touched a written prefix still
/// conflicts.
pub struct DisjointBatch {
    allowed: &'static [[u8; 2]],
    touched: Vec<[u8; 2]>,
    batch: WriteBatch,
}

impl DisjointBatch {
    pub fn new(allowed: &'static [[u8; 2]]) -> Self {
        Self {
            allowed,
            touched: Vec::new(),
            batch: WriteBatch::default(),
        }
    }

    fn prefix(&mut self, key: &[u8]) -> Result<[u8; 2], DatabaseCommitError> {
        let prefix = match key {
            [first, second, ..] => [*first, *second],
            _ => return Err(DatabaseCommitError::OutsideKeyspace),
        };
        if !self.allowed.contains(&prefix) {
            return Err(DatabaseCommitError::OutsideKeyspace);
        }
        if !self.touched.contains(&prefix) {
            self.touched.push(prefix);
        }
        Ok(prefix)
    }

    pub fn put(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), DatabaseCommitError> {
        self.prefix(key.as_ref())?;
        self.batch.put(key, value);
        Ok(())
    }

    pub fn delete(&mut self, key: impl AsRef<[u8]>) -> Result<(), DatabaseCommitError> {
        self.prefix(key.as_ref())?;
        self.batch.delete(key);
        Ok(())
    }

    /// Both endpoints must share one declared prefix, so the range cannot
    /// cover keys outside it.
    pub fn delete_range(
        &mut self,
        start: impl AsRef<[u8]>,
        end: impl AsRef<[u8]>,
    ) -> Result<(), DatabaseCommitError> {
        let (start, end) = (start.as_ref(), end.as_ref());
        if start > end || self.prefix(start)? != self.prefix(end)? {
            return Err(DatabaseCommitError::OutsideKeyspace);
        }
        self.batch.delete_range(start, end);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }
}

/// Clones share both the database and its mutation barrier. There is deliberately
/// no `Deref<Target = DB>`, raw-handle accessor or conversion from a shared DB.
#[derive(Clone)]
pub struct CoordinatedDb(Arc<DatabaseInner>);

impl CoordinatedDb {
    pub fn new(db: DB) -> Self {
        let general = db.latest_sequence_number();
        Self(Arc::new(DatabaseInner {
            db,
            writes: Mutex::new(WriteLedger {
                general,
                disjoint: BTreeMap::new(),
            }),
            failed_write: AtomicBool::new(false),
        }))
    }

    pub fn backing_store_identity(&self) -> BackingStoreIdentity {
        BackingStoreIdentity::of(&self.0)
    }

    pub fn same_database(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Lock order: the caller's frame/forest/commit/engine/cache locks first,
    /// then this barrier. Never call another DB writer while holding the guard.
    pub fn lock_writes(&self) -> Result<DatabaseWriteGuard<'_>, DatabaseCommitError> {
        let guard = self
            .0
            .writes
            .lock()
            .map_err(|_| DatabaseCommitError::Poisoned)?;
        if self.0.failed_write.load(Ordering::Acquire) {
            return Err(DatabaseCommitError::PriorWriteFailed);
        }
        Ok(DatabaseWriteGuard {
            database: self,
            ledger: guard,
        })
    }

    pub fn write(&self, batch: WriteBatch) -> Result<(), DatabaseCommitError> {
        self.write_opt(batch, &WriteOptions::default())
    }

    pub fn write_opt(
        &self,
        batch: WriteBatch,
        options: &WriteOptions,
    ) -> Result<(), DatabaseCommitError> {
        self.lock_writes()?.write_batch(batch, options)
    }

    pub fn put(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), DatabaseCommitError> {
        let mut batch = WriteBatch::default();
        batch.put(key, value);
        self.write(batch)
    }

    pub fn delete(&self, key: impl AsRef<[u8]>) -> Result<(), DatabaseCommitError> {
        let mut batch = WriteBatch::default();
        batch.delete(key);
        self.write(batch)
    }

    /// Write a batch confined to its declared prefixes. It invalidates only
    /// execution plans that touched one of the prefixes it wrote.
    pub fn write_disjoint(
        &self,
        batch: DisjointBatch,
        options: &WriteOptions,
    ) -> Result<(), DatabaseCommitError> {
        let mut guard = self.lock_writes()?;
        guard.write_raw(batch.batch, options)?;
        let sequence = self.0.db.latest_sequence_number();
        for prefix in batch.touched {
            guard.ledger.disjoint.insert(prefix, sequence);
        }
        Ok(())
    }

    /// Capture the exact sequence under the same barrier used by every writer.
    pub(crate) fn execution_snapshot(&self) -> Result<(Snapshot<'_>, u64), DatabaseCommitError> {
        let _guard = self.lock_writes()?;
        let sequence = self.0.db.latest_sequence_number();
        Ok((self.0.db.snapshot(), sequence))
    }

    pub fn snapshot(&self) -> Snapshot<'_> {
        self.0.db.snapshot()
    }
    pub fn latest_sequence_number(&self) -> u64 {
        self.0.db.latest_sequence_number()
    }
    pub fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        self.0.db.get(key)
    }
    pub fn get_opt(
        &self,
        key: impl AsRef<[u8]>,
        options: &ReadOptions,
    ) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        self.0.db.get_opt(key, options)
    }
    pub fn raw_iterator(&self) -> DBRawIterator<'_> {
        self.0.db.raw_iterator()
    }
    pub fn raw_iterator_opt(&self, options: ReadOptions) -> DBRawIterator<'_> {
        self.0.db.raw_iterator_opt(options)
    }
    pub fn iterator(&self, mode: IteratorMode<'_>) -> DBIterator<'_> {
        self.0.db.iterator(mode)
    }
    pub fn iterator_opt(&self, mode: IteratorMode<'_>, options: ReadOptions) -> DBIterator<'_> {
        self.0.db.iterator_opt(mode, options)
    }
    pub fn prefix_iterator(&self, prefix: impl AsRef<[u8]>) -> DBIterator<'_> {
        self.0.db.prefix_iterator(prefix)
    }
    pub fn property_int_value(&self, name: &str) -> Result<Option<u64>, rocksdb::Error> {
        self.0.db.property_int_value(name)
    }
    pub fn path(&self) -> &Path {
        self.0.db.path()
    }
    pub fn flush(&self) -> Result<(), rocksdb::Error> {
        self.0.db.flush()
    }
    pub fn flush_wal(&self, sync: bool) -> Result<(), rocksdb::Error> {
        self.0.db.flush_wal(sync)
    }
    pub fn compact_range<S: AsRef<[u8]>, E: AsRef<[u8]>>(&self, start: Option<S>, end: Option<E>) {
        self.0.db.compact_range(start, end);
    }
    pub fn try_catch_up_with_primary(&self) -> Result<(), DatabaseCommitError> {
        let mut guard = self.lock_writes()?;
        self.0.db.try_catch_up_with_primary()?;
        guard.ledger.general = self.0.db.latest_sequence_number();
        Ok(())
    }
}

/// Hold through metadata adoption when a higher-level owner publishes state.
/// A storage-only commit does not update CRDT metadata or authenticate a frame.
pub struct DatabaseWriteGuard<'a> {
    database: &'a CoordinatedDb,
    ledger: MutexGuard<'a, WriteLedger>,
}

impl DatabaseWriteGuard<'_> {
    fn write_raw(
        &mut self,
        batch: WriteBatch,
        options: &WriteOptions,
    ) -> Result<(), DatabaseCommitError> {
        if self.database.0.failed_write.load(Ordering::Acquire) {
            return Err(DatabaseCommitError::PriorWriteFailed);
        }
        if let Err(error) = self.database.0.db.write_opt(batch, options) {
            // An I/O/WAL-sync error is not proof that no durable bytes exist.
            // Never reuse execution metadata against an ambiguous write result.
            self.database.0.failed_write.store(true, Ordering::Release);
            return Err(DatabaseCommitError::Storage(error));
        }
        Ok(())
    }

    fn write_batch(
        &mut self,
        batch: WriteBatch,
        options: &WriteOptions,
    ) -> Result<(), DatabaseCommitError> {
        self.write_raw(batch, options)?;
        self.ledger.general = self.database.0.db.latest_sequence_number();
        Ok(())
    }

    /// Accept the plan when nothing was written since its capture, or when
    /// every intervening write was confined to prefixes it never touched.
    pub(crate) fn commit_execution(
        &mut self,
        source: &CoordinatedDb,
        expected: u64,
        touched: &KeyPrefixSet,
        batch: WriteBatch,
    ) -> Result<(), DatabaseCommitError> {
        if !self.database.same_database(source) {
            return Err(DatabaseCommitError::ForeignDatabase);
        }
        let actual = self.database.latest_sequence_number();
        if actual != expected
            && (self.ledger.general > expected
                || self
                    .ledger
                    .disjoint
                    .iter()
                    .any(|(prefix, sequence)| *sequence > expected && touched.contains(*prefix)))
        {
            return Err(DatabaseCommitError::Stale { expected, actual });
        }
        let mut options = WriteOptions::default();
        options.set_sync(true);
        self.write_batch(batch, &options)
    }
}

#[cfg(test)]
mod prefix_set_tests {
    use super::KeyPrefixSet;

    #[test]
    fn ranges_mark_exactly_the_spanned_prefixes_across_word_boundaries() {
        for (lower, upper, first, last) in [
            (&[0x00, 0x3e][..], &[0x00, 0x41, 0x00][..], [0x00, 0x3e], [0x00, 0x41]),
            (&[][..], &[0x00][..], [0x00, 0x00], [0x00, 0xff]),
            (&[0x7f, 0xff][..], &[0x80][..], [0x7f, 0xff], [0x80, 0xff]),
            (&[0x05][..], &[0x05, 0x00, 0x01][..], [0x05, 0x00], [0x05, 0x00]),
            (&[0xff, 0xff][..], &[0xff, 0xff, 0x01][..], [0xff, 0xff], [0xff, 0xff]),
        ] {
            let mut set = KeyPrefixSet::default();
            set.mark_range(lower, upper);
            let index = |p: [u8; 2]| usize::from(p[0]) << 8 | usize::from(p[1]);
            for i in 0..=0xffff_usize {
                let prefix = [(i >> 8) as u8, i as u8];
                let inside = (index(first)..=index(last)).contains(&i);
                assert_eq!(set.contains(prefix), inside, "{lower:?}..{upper:?} at {prefix:?}");
            }
        }
        let mut whole = KeyPrefixSet::default();
        whole.mark_range(&[], &[0xff, 0xff, 0xff]);
        assert!((0..=0xffff_usize).all(|i| whole.contains([(i >> 8) as u8, i as u8])));
        let mut key = KeyPrefixSet::default();
        key.mark_key(&[0x12]);
        assert!(key.contains([0x12, 0x00]) && !key.contains([0x12, 0x01]));
    }
}
