//! One write barrier for every handle to a live RocksDB instance.
//!
//! This owns the raw DB rather than accepting/exposing an `Arc<DB>`: a raw
//! writable alias could bypass the sequence check used for atomic publication.
//! Reads retain RocksDB's normal snapshot semantics. CRDT metadata and runtime
//! cache publication still require the execution owner's higher-level locks.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use quil_types::store::{BackingStoreIdentity, CapturePoint, ScanPoint};
use crate::storage_health::{StoreRole, StoreState};
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

pub(crate) struct DatabaseInner {
    db: DB,
    writes: Mutex<WriteLedger>,
    /// The failed-write latch and the store's role in the operator log.
    state: Arc<StoreState>,
    /// Process-unique, never reused: a scan of one instance never matches a
    /// later database, even one reopened at the same path.
    instance: u64,
    watched: Option<Vec<Vec<u8>>>,
}

static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

/// Sequence numbers recorded under the write barrier. A write confined to
/// declared two-byte prefixes is recorded per prefix; every other write is
/// general. Execution publication compares these against its own footprint.
#[derive(Default)]
struct WriteLedger {
    general: u64,
    disjoint: BTreeMap<[u8; 2], u64>,
    /// Sequence after the last write that may have written a watched key.
    watched: u64,
    /// The watched keys those writes wrote, once a reader has asked for them
    /// ([`CoordinatedDb::watched_writes_since`]); a database nobody asks
    /// keeps no journal and lists no keys.
    journal: Option<WatchedJournal>,
}

/// Distinct watched keys the journal keeps (those written since the reader's
/// previous request) before it starts over; the reader then reads every row.
const MAX_JOURNALED_KEYS: usize = 32_768;

/// The watched keys written after `floor`, each with the sequence after its
/// last write, so a cache of those rows can re-read only what changed. A
/// write that cannot be listed (a range deletion reaching a watched key, a
/// batch that does not parse, a write whose outcome is unknown) or a journal
/// past its bound starts it over at that sequence.
struct WatchedJournal {
    floor: u64,
    keys: BTreeMap<Vec<u8>, u64>,
}

impl WatchedJournal {
    fn starting_at(sequence: u64) -> Self {
        Self { floor: sequence, keys: BTreeMap::new() }
    }

    fn record(&mut self, sequence: u64, write: WatchedWrite) {
        match write {
            WatchedWrite::None => {}
            WatchedWrite::Unlisted => *self = Self::starting_at(sequence),
            WatchedWrite::Keys(keys) => {
                for key in keys {
                    self.keys.insert(key, sequence);
                }
                if self.keys.len() > MAX_JOURNALED_KEYS {
                    *self = Self::starting_at(sequence);
                }
            }
        }
    }

    /// Every watched key written after `sequence`; `None` when the journal
    /// does not reach back that far. The reader's caches are at `sequence`
    /// or later from now on, so what was written up to it is forgotten.
    fn take_since(&mut self, sequence: u64) -> Option<Vec<Vec<u8>>> {
        if self.floor > sequence {
            return None;
        }
        self.keys.retain(|_, written| *written > sequence);
        self.floor = sequence;
        Some(self.keys.keys().cloned().collect())
    }
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

/// A handle that does not keep the database open (see [`CoordinatedDb::downgrade`]).
#[derive(Clone)]
pub struct WeakCoordinatedDb(Weak<DatabaseInner>);

impl WeakCoordinatedDb {
    /// The database, unless every [`CoordinatedDb`] clone has been dropped.
    pub fn upgrade(&self) -> Option<CoordinatedDb> {
        self.0.upgrade().map(CoordinatedDb)
    }
}

impl CoordinatedDb {
    pub fn new(db: DB) -> Self {
        Self::open(db, None)
    }

    /// Also record the last write that may have written a key under one of
    /// `prefixes`, so a reader can prove a scan of them is still current (see
    /// [`CapturePoint`](quil_types::store::CapturePoint)). Every batch is
    /// parsed; one that cannot be fully accounted for counts as such a write.
    pub fn with_watched_prefixes(db: DB, prefixes: Vec<Vec<u8>>) -> Self {
        Self::open(db, Some(prefixes))
    }

    fn open(db: DB, watched: Option<Vec<Vec<u8>>>) -> Self {
        let general = db.latest_sequence_number();
        let state = Arc::new(StoreState::new(db.path().to_path_buf()));
        Self(Arc::new(DatabaseInner {
            db,
            writes: Mutex::new(WriteLedger {
                general,
                disjoint: BTreeMap::new(),
                // Nothing written before the watch is known to be unwatched.
                watched: general,
                journal: None,
            }),
            state,
            instance: NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
            watched,
        }))
    }

    pub fn instance(&self) -> u64 {
        self.0.instance
    }

    pub(crate) fn watched_prefixes(&self) -> Option<&[Vec<u8>]> {
        self.0.watched.as_deref()
    }

    pub fn backing_store_identity(&self) -> BackingStoreIdentity {
        BackingStoreIdentity::of(&self.0)
    }

    pub fn same_database(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// For background work that should stop, rather than keep the database
    /// open, once its other owners drop it.
    pub fn downgrade(&self) -> WeakCoordinatedDb {
        WeakCoordinatedDb(Arc::downgrade(&self.0))
    }

    /// Lock order: the caller's frame/forest/commit/engine/cache locks first,
    /// then this barrier. Never call another DB writer while holding the guard.
    pub fn lock_writes(&self) -> Result<DatabaseWriteGuard<'_>, DatabaseCommitError> {
        let guard = self
            .0
            .writes
            .lock()
            .map_err(|_| DatabaseCommitError::Poisoned)?;
        if self.0.state.is_latched() {
            return Err(self.refuse_write());
        }
        Ok(DatabaseWriteGuard {
            database: self,
            ledger: guard,
        })
    }

    /// Count a write refused after an earlier failure; the store repeats
    /// its report at a bounded interval. Callers hold only the write barrier.
    fn refuse_write(&self) -> DatabaseCommitError {
        self.0.state.refuse();
        DatabaseCommitError::PriorWriteFailed
    }

    /// Name this database as one of the node's stores, for the reports of a
    /// failed write and of its disk headroom ([`crate::storage_health`]).
    /// Returns false when it already has a role, which it keeps.
    pub fn register_store(&self, role: StoreRole) -> bool {
        crate::storage_health::register(&self.0.state, Arc::downgrade(&self.0), role)
    }

    /// Whether a write failed, so the database refuses every later write
    /// until it is reopened.
    pub fn write_failed(&self) -> bool {
        self.0.state.is_latched()
    }

    /// Latch the database as if a write had failed with `cause`: report it
    /// once and refuse every later write until it is reopened. For fault
    /// injection in tests of what owns the store. Takes the write barrier,
    /// so never call it while holding a [`DatabaseWriteGuard`].
    #[doc(hidden)]
    pub fn refuse_writes(&self, cause: impl Into<String>) {
        let _barrier = self.0.writes.lock();
        self.0.state.latch(cause.into());
    }

    /// Fail the next write with `error`, as if RocksDB had returned it.
    #[cfg(test)]
    pub(crate) fn fail_next_write(&self, error: rocksdb::Error) {
        self.0.state.arm_fault(error);
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

    /// Capture the exact sequence under the same barrier used by every writer,
    /// with the last watched write at that sequence when keys are watched.
    pub(crate) fn execution_snapshot(
        &self,
    ) -> Result<(Snapshot<'_>, u64, Option<u64>), DatabaseCommitError> {
        let guard = self.lock_writes()?;
        let sequence = self.0.db.latest_sequence_number();
        let watched = self.0.watched.as_ref().map(|_| guard.ledger.watched);
        Ok((self.0.db.snapshot(), sequence, watched))
    }

    /// The capture point an execution capture taken now would record, without
    /// taking a snapshot: `None` when this database watches no keys. Holds the
    /// write barrier only to read the ledger, as a capture does.
    pub fn current_capture_point(&self) -> Result<Option<CapturePoint>, DatabaseCommitError> {
        let guard = self.lock_writes()?;
        Ok(guard.watched_write_sequence().map(|watched| CapturePoint {
            database: self.0.instance,
            sequence: self.0.db.latest_sequence_number(),
            watched,
        }))
    }

    /// Start the journal now, at the last watched write, rather than at the
    /// first [`Self::watched_writes_since`]. A no-op when no keys are watched
    /// or the journal runs.
    pub fn enable_watched_journal(&self) -> Result<(), DatabaseCommitError> {
        let mut guard = self.lock_writes()?;
        if self.0.watched.is_some() {
            let last = guard.ledger.watched;
            guard.ledger.journal.get_or_insert_with(|| WatchedJournal::starting_at(last));
        }
        Ok(())
    }

    /// The watched keys written after `sequence` (a [`ScanPoint`]'s `from`),
    /// or `None` when they cannot all be listed or no keys are watched. The
    /// first request starts the journal at the last watched write, which
    /// lists exactly what follows it; one reader is assumed, whose caches
    /// are at `sequence` or later from now on.
    pub fn watched_writes_since(&self, sequence: u64) -> Result<Option<Vec<Vec<u8>>>, DatabaseCommitError> {
        let mut guard = self.lock_writes()?;
        if self.0.watched.is_none() {
            return Ok(None);
        }
        let last = guard.ledger.watched;
        Ok(guard
            .ledger
            .journal
            .get_or_insert_with(|| WatchedJournal::starting_at(last))
            .take_since(sequence))
    }

    pub fn snapshot(&self) -> Snapshot<'_> {
        self.0.db.snapshot()
    }

    /// A snapshot and the sequences bracketing it, without the write barrier
    /// (callers may already hold it).
    pub fn snapshot_with_scan_point(&self) -> (Snapshot<'_>, ScanPoint) {
        let from = self.0.db.latest_sequence_number();
        let snapshot = self.0.db.snapshot();
        let to = self.0.db.latest_sequence_number();
        (snapshot, ScanPoint { database: self.0.instance, from, to })
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
    /// SST file metadata, for maintenance that needs per-range file sizes.
    pub fn live_files(&self) -> Result<Vec<rocksdb::LiveFile>, rocksdb::Error> {
        self.0.db.live_files()
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
    pub fn compact_range_opt<S: AsRef<[u8]>, E: AsRef<[u8]>>(
        &self,
        start: Option<S>,
        end: Option<E>,
        opts: &rocksdb::CompactOptions,
    ) {
        self.0.db.compact_range_opt(start, end, opts);
    }
    pub fn try_catch_up_with_primary(&self) -> Result<(), DatabaseCommitError> {
        let mut guard = self.lock_writes()?;
        let caught_up = self.0.db.try_catch_up_with_primary();
        let sequence = self.0.db.latest_sequence_number();
        guard.ledger.watched = sequence;
        if let Some(journal) = guard.ledger.journal.as_mut() {
            *journal = WatchedJournal::starting_at(sequence);
        }
        caught_up?;
        guard.ledger.general = sequence;
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
        if self.database.0.state.is_latched() {
            return Err(self.database.refuse_write());
        }
        // Keys are listed only for a journal someone reads.
        let list = self.ledger.journal.is_some();
        let watched = self
            .database
            .0
            .watched
            .as_ref()
            .map_or(WatchedWrite::None, |prefixes| watched_writes(batch.data(), prefixes, list));
        let written = match self.database.0.state.take_fault() {
            Some(fault) => Err(fault),
            None => self.database.0.db.write_opt(batch, options),
        };
        if !matches!(watched, WatchedWrite::None) {
            // Recorded even for a failed write, whose durable effect is unknown.
            let sequence = self.database.0.db.latest_sequence_number();
            self.ledger.watched = sequence;
            if let Some(journal) = self.ledger.journal.as_mut() {
                journal.record(sequence, if written.is_ok() { watched } else { WatchedWrite::Unlisted });
            }
        }
        if let Err(error) = written {
            // An I/O/WAL-sync error is not proof that no durable bytes exist.
            // Never reuse execution metadata against an ambiguous write result.
            self.database.0.state.latch(error.to_string());
            return Err(DatabaseCommitError::Storage(error));
        }
        Ok(())
    }

    /// The sequence after the last write that may have written a watched key,
    /// or `None` when this database watches no keys.
    pub fn watched_write_sequence(&self) -> Option<u64> {
        self.database.0.watched.as_ref().map(|_| self.ledger.watched)
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

/// Stop the database's writes, under its write barrier, as after a failed
/// write with `cause`, without its own log line (the caller reports a group
/// of stores at once). Whether it was open and not stopped before.
pub(crate) fn stop_writes(database: &Weak<DatabaseInner>, cause: String) -> bool {
    let Some(inner) = database.upgrade() else { return false };
    let _barrier = inner.writes.lock();
    inner.state.latch_quietly(cause)
}

pub(crate) fn key_under(prefixes: &[Vec<u8>], key: &[u8]) -> bool {
    prefixes.iter().any(|p| key.starts_with(p))
}

/// Whether `[begin, end)` holds a key under one of `prefixes`. It meets
/// `[p, successor(p))` exactly when begin < successor(p) and end > p; every key
/// in that interval starts with p.
pub(crate) fn range_meets(prefixes: &[Vec<u8>], begin: &[u8], end: &[u8]) -> bool {
    begin < end
        && prefixes.iter().any(|p| {
            let below_successor = match p.iter().rposition(|&b| b != 0xff) {
                Some(i) => {
                    let mut successor = p[..=i].to_vec();
                    successor[i] += 1;
                    begin < successor.as_slice()
                }
                None => true,
            };
            below_successor && end > p.as_slice()
        })
}

/// What a write batch wrote under the watched prefixes.
#[derive(Debug, PartialEq, Eq)]
enum WatchedWrite {
    /// Nothing under them.
    None,
    /// These keys (puts, merges and deletions); empty when not listed.
    Keys(Vec<Vec<u8>>),
    /// Something that cannot be listed key by key.
    Unlisted,
}

/// Whether a RocksDB `WriteBatch` representation may write a key under one of
/// `prefixes`.
#[cfg(test)]
fn batch_may_write_under(batch: &[u8], prefixes: &[Vec<u8>]) -> bool {
    watched_writes(batch, prefixes, false) != WatchedWrite::None
}

/// The keys a RocksDB `WriteBatch` representation writes under `prefixes`,
/// collected only when `list`. The encoding is a 12-byte header (sequence, record count) and tagged
/// records of varint-length-prefixed slices. An unknown tag, a malformed
/// record or a count mismatch counts as an unlisted write under every prefix,
/// as does a range deletion reaching one.
fn watched_writes(batch: &[u8], prefixes: &[Vec<u8>], list: bool) -> WatchedWrite {
    fn varint(rest: &mut &[u8]) -> Option<usize> {
        let mut value = 0u32;
        for shift in (0..35).step_by(7) {
            let (&byte, tail) = rest.split_first()?;
            *rest = tail;
            value |= u32::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return usize::try_from(value).ok();
            }
        }
        None
    }
    fn slice<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
        let len = varint(rest)?;
        if rest.len() < len {
            return None;
        }
        let (head, tail) = rest.split_at(len);
        *rest = tail;
        Some(head)
    }
    let parse = || -> Option<WatchedWrite> {
        let count = u32::from_le_bytes(batch.get(8..12)?.try_into().ok()?);
        let mut rest = batch.get(12..)?;
        let mut records = 0u32;
        let mut keys = Vec::new();
        let mut touched = false;
        let mut unlisted = false;
        let mut key = |k: &[u8]| {
            if key_under(prefixes, k) {
                touched = true;
                if list {
                    keys.push(k.to_vec());
                }
            }
        };
        let mut range = |begin: &[u8], end: &[u8]| unlisted |= range_meets(prefixes, begin, end);
        while let Some((&tag, tail)) = rest.split_first() {
            rest = tail;
            match tag {
                // Deletion, single deletion.
                0x0 | 0x7 => key(slice(&mut rest)?),
                // Value, merge.
                0x1 | 0x2 => {
                    key(slice(&mut rest)?);
                    slice(&mut rest)?;
                }
                // Range deletion.
                0xF => {
                    let begin = slice(&mut rest)?;
                    range(begin, slice(&mut rest)?);
                }
                // Column-family deletion, single deletion.
                0x4 | 0x8 => {
                    varint(&mut rest)?;
                    key(slice(&mut rest)?);
                }
                // Column-family value, merge.
                0x5 | 0x6 => {
                    varint(&mut rest)?;
                    key(slice(&mut rest)?);
                    slice(&mut rest)?;
                }
                // Column-family range deletion.
                0xE => {
                    varint(&mut rest)?;
                    let begin = slice(&mut rest)?;
                    range(begin, slice(&mut rest)?);
                }
                // Log data: not a record and never applied.
                0x3 => {
                    slice(&mut rest)?;
                    continue;
                }
                _ => return None,
            }
            records += 1;
        }
        (records == count).then(|| match (unlisted, touched) {
            (true, _) => WatchedWrite::Unlisted,
            (false, false) => WatchedWrite::None,
            (false, true) => WatchedWrite::Keys(keys),
        })
    };
    parse().unwrap_or(WatchedWrite::Unlisted)
}

#[cfg(test)]
mod watched_write_tests {
    use super::*;

    fn prefixes() -> Vec<Vec<u8>> {
        vec![vec![0x20, 0x01, 0xff], vec![0x21, 0x01]]
    }

    #[test]
    fn batches_are_attributed_by_key_and_range() {
        let may_write = |build: &dyn Fn(&mut WriteBatch)| {
            let mut batch = WriteBatch::default();
            build(&mut batch);
            batch_may_write_under(batch.data(), &prefixes())
        };
        assert!(!may_write(&|_| {}));
        assert!(may_write(&|b| b.put([0x20, 0x01, 0xff, 7], b"v")));
        assert!(may_write(&|b| b.put([0x21, 0x01], b"v")));
        assert!(!may_write(&|b| b.put([0x20, 0x01, 0xfe, 7], b"v")));
        assert!(!may_write(&|b| b.put([0x21], b"v")));
        assert!(may_write(&|b| {
            b.put([0x05], b"v");
            b.delete([0x20, 0x01, 0xff]);
        }));
        assert!(may_write(&|b| b.merge([0x21, 0x01, 9], b"v")));
        assert!(!may_write(&|b| b.delete([0x22])));
        // Range deletions intersecting a prefix, or spanning it.
        assert!(may_write(&|b| b.delete_range(&[0x20, 0x01, 0xff, 5][..], &[0x20, 0x02][..])));
        assert!(may_write(&|b| b.delete_range(&[0x00][..], &[0xff][..])));
        assert!(may_write(&|b| b.delete_range(&[0x20, 0x01, 0xfe][..], &[0x20, 0x01, 0xff, 0][..])));
        // Ranges ending at a prefix or starting after it do not.
        assert!(!may_write(&|b| b.delete_range(&[0x20][..], &[0x20, 0x01, 0xff][..])));
        assert!(!may_write(&|b| b.delete_range(&[0x20, 0x02][..], &[0x21, 0x01][..])));
        assert!(!may_write(&|b| b.delete_range(&[0x21, 0x02][..], &[0x30][..])));
        // An empty or reversed range writes nothing.
        assert!(!may_write(&|b| b.delete_range(&[0x21, 0x01, 5][..], &[0x21, 0x01, 5][..])));
        // Large values use multi-byte lengths.
        assert!(!may_write(&|b| b.put([0x30], vec![1u8; 70_000])));
        assert!(may_write(&|b| {
            b.put([0x30], vec![1u8; 70_000]);
            b.put([0x21, 0x01, 0xff], vec![2u8; 300]);
        }));
    }

    #[test]
    fn anything_unaccounted_for_counts_as_a_watched_write() {
        let mut batch = WriteBatch::default();
        batch.put([0x05], b"v");
        let data = batch.data().to_vec();
        assert!(!batch_may_write_under(&data, &prefixes()));
        // Truncated record, unknown tag, record count mismatch, short header.
        assert!(batch_may_write_under(&data[..data.len() - 1], &prefixes()));
        let mut unknown = data.clone();
        unknown[12] = 0x16;
        assert!(batch_may_write_under(&unknown, &prefixes()));
        let mut miscounted = data.clone();
        miscounted[8] = 2;
        assert!(batch_may_write_under(&miscounted, &prefixes()));
        assert!(batch_may_write_under(&data[..6], &prefixes()));
    }

    #[test]
    fn the_ledger_records_only_watched_writes() {
        let dir = tempfile::tempdir().unwrap();
        let db = CoordinatedDb::with_watched_prefixes(DB::open_default(dir.path()).unwrap(), prefixes());
        let watched = |db: &CoordinatedDb| db.lock_writes().unwrap().watched_write_sequence().unwrap();
        let start = watched(&db);
        db.put([0x05], b"v").unwrap();
        assert_eq!(watched(&db), start, "an unwatched write leaves the ledger alone");
        db.put([0x21, 0x01, 3], b"v").unwrap();
        let after = db.latest_sequence_number();
        assert_eq!(watched(&db), after);
        db.delete([0x07]).unwrap();
        assert_eq!(watched(&db), after);
        let (_snapshot, sequence, recorded) = db.execution_snapshot().unwrap();
        assert_eq!((sequence, recorded), (db.latest_sequence_number(), Some(after)));
        // The point a capture would record, without capturing.
        assert_eq!(
            db.current_capture_point().unwrap(),
            Some(CapturePoint { database: db.instance(), sequence, watched: after })
        );

        let plain_dir = tempfile::tempdir().unwrap();
        let plain = CoordinatedDb::new(DB::open_default(plain_dir.path()).unwrap());
        assert_eq!(plain.lock_writes().unwrap().watched_write_sequence(), None);
        assert_eq!(plain.current_capture_point().unwrap(), None);
        assert_ne!(plain.instance(), db.instance());
    }

    /// A reader of the watched rows can list exactly the keys written since
    /// the sequence its cache is at; what it no longer needs is forgotten,
    /// and a write that cannot be listed starts the journal over.
    #[test]
    fn the_journal_lists_watched_keys_written_after_a_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let db = CoordinatedDb::with_watched_prefixes(DB::open_default(dir.path()).unwrap(), prefixes());
        let listed = |since| db.watched_writes_since(since).unwrap();
        // Nothing is journaled before a reader asks.
        db.put([0x21, 0x01, 1], b"v").unwrap();
        assert!(db.lock_writes().unwrap().ledger.journal.is_none());
        let start = db.latest_sequence_number();
        assert_eq!(listed(start - 1), None, "a write before the first request is not listed");
        assert_eq!(listed(start), Some(Vec::new()));

        db.put([0x21, 0x01, 3], b"v").unwrap();
        db.put([0x05], b"v").unwrap();
        let first = db.latest_sequence_number();
        db.delete([0x20, 0x01, 0xff, 9]).unwrap();
        db.put([0x21, 0x01, 3], b"w").unwrap();
        assert_eq!(listed(start), Some(vec![vec![0x20, 0x01, 0xff, 9], vec![0x21, 0x01, 3]]));
        assert_eq!(listed(first), Some(vec![vec![0x20, 0x01, 0xff, 9], vec![0x21, 0x01, 3]]),
            "a key written again after the sequence is listed once");
        let latest = db.latest_sequence_number();
        assert_eq!(listed(latest), Some(Vec::new()));
        assert_eq!(listed(first), None, "the reader's caches are past `first` now");

        let mut range = WriteBatch::default();
        range.delete_range(&[0x21, 0x01][..], &[0x21, 0x02][..]);
        db.write(range).unwrap();
        let reset = db.latest_sequence_number();
        assert_eq!(listed(latest), None, "a range deletion cannot be listed key by key");
        db.put([0x21, 0x01, 4], b"v").unwrap();
        assert_eq!(listed(reset), Some(vec![vec![0x21, 0x01, 4]]));

        let plain_dir = tempfile::tempdir().unwrap();
        let plain = CoordinatedDb::new(DB::open_default(plain_dir.path()).unwrap());
        assert_eq!(plain.watched_writes_since(0).unwrap(), None);
    }

    /// Versioned rows write a new key per version. The bound counts only keys
    /// written since the reader's previous request, so a reader that asks
    /// every frame never sees the journal start over; one batch past it does.
    #[test]
    fn the_journal_bound_counts_keys_since_the_last_request() {
        let dir = tempfile::tempdir().unwrap();
        let db = CoordinatedDb::with_watched_prefixes(DB::open_default(dir.path()).unwrap(), prefixes());
        let versioned = |address: u8, version: u64| {
            let mut key = vec![0x21, 0x01, address];
            key.extend_from_slice(&version.to_be_bytes());
            key
        };
        db.enable_watched_journal().unwrap();
        let mut seen = db.latest_sequence_number();
        // Three rounds would outgrow a journal that never forgets.
        let third = (MAX_JOURNALED_KEYS / 3) as u64 + 1;
        for round in 0..5u64 {
            let mut batch = WriteBatch::default();
            for version in round * third..(round + 1) * third {
                batch.put(versioned((version % 7) as u8, version), b"v");
            }
            db.write(batch).unwrap();
            let listed = db.watched_writes_since(seen).unwrap().expect("within the bound since the last request");
            assert_eq!(listed.len() as u64, third, "every version is its own key");
            seen = db.latest_sequence_number();
        }

        let mut batch = WriteBatch::default();
        for version in 0..=MAX_JOURNALED_KEYS as u64 {
            batch.put(versioned(9, version), b"v");
        }
        db.write(batch).unwrap();
        assert_eq!(db.watched_writes_since(seen).unwrap(), None, "past its bound the journal starts over");
        let after = db.latest_sequence_number();
        assert_eq!(db.watched_writes_since(after).unwrap(), Some(Vec::new()));
    }

    #[test]
    fn a_weak_handle_does_not_keep_the_database_open() {
        let dir = tempfile::tempdir().unwrap();
        let db = CoordinatedDb::new(DB::open_default(dir.path()).unwrap());
        let weak = db.downgrade();
        assert!(weak.upgrade().unwrap().same_database(&db));
        drop(db);
        assert!(weak.upgrade().is_none());
        // The RocksDB lock is released: the path opens again.
        let _reopened = DB::open_default(dir.path()).unwrap();
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
