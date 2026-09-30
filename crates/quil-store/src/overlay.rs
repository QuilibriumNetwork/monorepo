//! Storage adapters for a tentative execution branch. These adapters cannot
//! obtain a writable RocksDB handle. Their encoded records are shared with the
//! durable hypergraph implementation in `hypergraph.rs`.

use std::sync::{Arc, Mutex};

use quil_forest::{ExecutionOverlay, OverlayLimits, OverlayMutation, OverlayReadView};
use quil_types::error::{QuilError, Result};
use quil_types::store::Transaction;

fn error(e: impl std::fmt::Display) -> QuilError {
    QuilError::Store(e.to_string())
}

#[derive(Clone)]
pub(crate) struct OverlayDb(pub(crate) Arc<ExecutionOverlay>);

impl OverlayDb {
    pub(crate) fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        self.0.get(key.as_ref()).map_err(error)
    }

    pub(crate) fn put(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<()> {
        let txn = OverlayTxn::new(self.clone());
        txn.set(key.as_ref(), value.as_ref())?;
        Box::new(txn).commit()
    }

    pub(crate) fn delete(&self, key: impl AsRef<[u8]>) -> Result<()> {
        let txn = OverlayTxn::new(self.clone());
        txn.delete(key.as_ref())?;
        Box::new(txn).commit()
    }

    pub(crate) fn snapshot(&self) -> OverlayDbSnapshot {
        OverlayDbSnapshot {
            view: self.0.read_view().map(Arc::new).map_err(|e| e.to_string()),
        }
    }

    pub(crate) fn raw_iterator(&self) -> OverlayRawCursor {
        self.snapshot().raw_iterator()
    }

    pub(crate) fn iterator(&self, mode: rocksdb::IteratorMode<'_>) -> OverlayIterator {
        self.snapshot().iterator(mode)
    }

    pub(crate) fn range(&self, lower: Vec<u8>, upper: Vec<u8>) -> OverlayIterator {
        self.snapshot().range(lower, upper)
    }
}

impl OverlayDbSnapshot {
    pub(crate) fn range(&self, lower: Vec<u8>, upper: Vec<u8>) -> OverlayIterator {
        let mut cursor = self.raw_iterator();
        cursor.bounds = Some((lower.clone(), upper));
        cursor.position(&lower, false, true, false);
        OverlayIterator {
            cursor,
            reverse: false,
            first: true,
            done: false,
        }
    }
}

impl OverlayDbSnapshot {
    pub(crate) fn iterator(&self, mode: rocksdb::IteratorMode<'_>) -> OverlayIterator {
        let mut cursor = self.raw_iterator();
        let reverse = match mode {
            rocksdb::IteratorMode::From(key, rocksdb::Direction::Forward) => {
                cursor.seek(key);
                false
            }
            rocksdb::IteratorMode::From(key, rocksdb::Direction::Reverse) => {
                cursor.seek_for_prev(key);
                true
            }
            _ => {
                self.record_failure();
                cursor.failure =
                    Some("tentative hypergraph scans require an explicit key range".into());
                false
            }
        };
        OverlayIterator {
            cursor,
            reverse,
            first: true,
            done: false,
        }
    }
}

#[derive(Clone)]
pub(crate) struct OverlayDbSnapshot {
    // Remember capture failures; no reader may interpret exhausted admission as
    // an empty snapshot. The Rocks-like factory API cannot return a Result.
    view: std::result::Result<Arc<OverlayReadView>, String>,
}

impl OverlayDbSnapshot {
    fn record_failure(&self) {
        if let Ok(view) = &self.view { view.record_execution_failure(); }
    }

    pub(crate) fn check(&self) -> Result<()> {
        self.view.as_ref().map(|_| ()).map_err(error)
    }

    pub(crate) fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        self.view
            .as_ref()
            .map_err(error)?
            .get(key.as_ref())
            .map_err(error)
    }

    pub(crate) fn raw_iterator(&self) -> OverlayRawCursor {
        OverlayRawCursor {
            snapshot: self.clone(),
            row: None,
            failure: None,
            bounds: None,
        }
    }
}

/// Same fallible cursor convention as RocksDB: every user must check status
/// after a seek or walk, including when `valid` is false. This adapter is only
/// for the hypergraph schema, whose range keys all have a tag below 0xff.
pub(crate) struct OverlayRawCursor {
    snapshot: OverlayDbSnapshot,
    row: Option<(Vec<u8>, Vec<u8>)>,
    failure: Option<String>,
    bounds: Option<(Vec<u8>, Vec<u8>)>,
}

impl OverlayRawCursor {
    pub(crate) fn valid(&self) -> bool {
        self.row.is_some()
    }
    pub(crate) fn key(&self) -> Option<&[u8]> {
        self.row.as_ref().map(|(k, _)| k.as_slice())
    }
    pub(crate) fn value(&self) -> Option<&[u8]> {
        self.row.as_ref().map(|(_, v)| v.as_slice())
    }
    pub(crate) fn status(&self) -> Result<()> {
        self.snapshot.check()?;
        match &self.failure {
            Some(e) => Err(error(e)),
            None => Ok(()),
        }
    }
    pub(crate) fn seek(&mut self, key: impl AsRef<[u8]>) {
        self.position(key.as_ref(), false, true, true);
    }
    pub(crate) fn seek_for_prev(&mut self, key: impl AsRef<[u8]>) {
        self.position(key.as_ref(), true, true, true);
    }
    pub(crate) fn next(&mut self) {
        if let Some((key, _)) = self.row.take() {
            self.position(&key, false, false, false);
        }
    }
    pub(crate) fn prev(&mut self) {
        if let Some((key, _)) = self.row.take() {
            self.position(&key, true, false, false);
        }
    }
    fn position(&mut self, key: &[u8], reverse: bool, inclusive: bool, new_bounds: bool) {
        self.row = None;
        self.failure = None;
        if new_bounds {
            match key.first().copied() {
                Some(tag) if tag < 0xff => self.bounds = Some((vec![tag], vec![tag + 1])),
                _ => {
                    self.snapshot.record_failure();
                    self.failure =
                        Some("tentative hypergraph scans require a schema tag below 0xff".into());
                    return;
                }
            }
        }
        let read = || -> Result<Option<(Vec<u8>, Vec<u8>)>> {
            let view = self.snapshot.view.as_ref().map_err(error)?;
            let (lower, upper) = self
                .bounds
                .as_ref()
                .ok_or_else(|| error("missing tentative scan bounds"))?;
            let mut cursor = view.cursor(lower, upper).map_err(error)?;
            if reverse {
                cursor.seek_for_prev(key).map_err(error)?;
            } else {
                cursor.seek(key).map_err(error)?;
            }
            if !inclusive && cursor.key() == Some(key) {
                if reverse {
                    cursor.prev().map_err(error)?;
                } else {
                    cursor.next().map_err(error)?;
                }
            }
            Ok(cursor
                .key()
                .zip(cursor.value())
                .map(|(k, v)| (k.to_vec(), v.to_vec())))
        };
        match read() {
            Ok(row) => self.row = row,
            Err(e) => {
                self.snapshot.record_failure();
                self.failure = Some(e.to_string());
            },
        }
    }
}

pub(crate) struct OverlayIterator {
    cursor: OverlayRawCursor,
    reverse: bool,
    first: bool,
    done: bool,
}

impl Iterator for OverlayIterator {
    type Item = Result<(Box<[u8]>, Box<[u8]>)>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if !self.first {
            if self.reverse {
                self.cursor.prev();
            } else {
                self.cursor.next();
            }
        }
        self.first = false;
        if let Err(e) = self.cursor.status() {
            self.done = true;
            return Some(Err(e));
        }
        match self.cursor.key().zip(self.cursor.value()) {
            Some((key, value)) => Some(Ok((key.into(), value.into()))),
            None => {
                self.done = true;
                None
            }
        }
    }
}

/// Bounds the pending input batch as well as the overlay's retained delta.
/// A failed staging operation poisons the entire transaction. Even callers
/// using the WriteBatch-style void methods cannot commit a truncated batch.
pub(crate) struct OverlayBatch {
    mutations: Vec<OverlayMutation>,
    bytes: usize,
    failure: Option<String>,
    limits: OverlayLimits,
}

impl OverlayBatch {
    fn admit(&mut self, key: &[u8], value: &[u8]) -> bool {
        if self.failure.is_some() {
            return false;
        }
        let size = key.len().checked_add(value.len());
        let total = size.and_then(|size| self.bytes.checked_add(size));
        let problem = if size.is_none_or(|size| size > self.limits.max_record_bytes) {
            Some("tentative transaction record byte limit")
        } else if total.is_none_or(|bytes| bytes > self.limits.max_delta_bytes) {
            Some("tentative transaction byte limit")
        } else if self.mutations.len() >= self.limits.max_delta_entries {
            Some("tentative transaction entry limit")
        } else {
            None
        };
        if let Some(problem) = problem {
            self.failure = Some(problem.into());
            return false;
        }
        self.bytes = total.unwrap();
        true
    }
    pub(crate) fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        let (key, value) = (key.as_ref(), value.as_ref());
        if self.admit(key, value) {
            self.mutations
                .push(OverlayMutation::Put(key.to_vec(), value.to_vec()));
        }
    }
    pub(crate) fn delete(&mut self, key: impl AsRef<[u8]>) {
        let key = key.as_ref();
        if self.admit(key, &[]) {
            self.mutations.push(OverlayMutation::Delete(key.to_vec()));
        }
    }
    fn delete_range(&mut self, lower: &[u8], upper: &[u8]) {
        if lower > upper {
            self.failure = Some("tentative transaction reversed range".into());
        }
        if self.admit(lower, upper) {
            self.mutations
                .push(OverlayMutation::DeleteRange(lower.to_vec(), upper.to_vec()));
        }
    }
    fn check(&self) -> Result<()> {
        match &self.failure {
            Some(e) => Err(error(e)),
            None => Ok(()),
        }
    }
}

pub(crate) struct OverlayTxn {
    pub(crate) batch: Mutex<OverlayBatch>,
    db: OverlayDb,
}

impl OverlayTxn {
    pub(crate) fn new(db: OverlayDb) -> Self {
        Self {
            batch: Mutex::new(OverlayBatch {
                mutations: Vec::new(),
                bytes: 0,
                failure: None,
                limits: db.0.limits(),
            }),
            db,
        }
    }
    pub(crate) fn for_store<'a>(txn: &'a dyn Transaction, db: &OverlayDb) -> Result<&'a Self> {
        let txn = txn
            .as_any()
            .downcast_ref::<Self>()
            .ok_or_else(|| {
                db.0.record_execution_failure();
                error("tentative hypergraph write requires an OverlayTxn")
            })?;
        if !Arc::ptr_eq(&txn.db.0, &db.0) {
            db.0.record_execution_failure();
            return Err(error(
                "tentative hypergraph transaction belongs to another branch",
            ));
        }
        Ok(txn)
    }

    /// Read our own staged writes when updating clock indices or committing a
    /// staged frame. The legacy Transaction::get contract remains unchanged.
    pub(crate) fn get_staged(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let batch = self.batch.lock().unwrap();
        self.check_batch(&batch)?;
        for mutation in batch.mutations.iter().rev() {
            match mutation {
                OverlayMutation::Put(k, v) if k == key => return Ok(Some(v.clone())),
                OverlayMutation::Delete(k) if k == key => return Ok(None),
                OverlayMutation::DeleteRange(a, b) if a.as_slice() <= key && key < b.as_slice() => return Ok(None),
                _ => {},
            }
        }
        self.db.get(key)
    }

    pub(crate) fn poison(&self, cause: impl std::fmt::Display) {
        self.db.0.record_execution_failure();
        self.batch.lock().unwrap().failure.get_or_insert_with(|| cause.to_string());
    }

    fn check_batch(&self, batch: &OverlayBatch) -> Result<()> {
        batch.check().map_err(|error| {
            self.db.0.record_execution_failure();
            error
        })
    }
}

impl Transaction for OverlayTxn {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.get(key)
    }
    fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut batch = self.batch.lock().unwrap();
        batch.put(key, value);
        self.check_batch(&batch)
    }
    fn delete(&self, key: &[u8]) -> Result<()> {
        let mut batch = self.batch.lock().unwrap();
        batch.delete(key);
        self.check_batch(&batch)
    }
    fn delete_range(&self, lower: &[u8], upper: &[u8]) -> Result<()> {
        let mut batch = self.batch.lock().unwrap();
        batch.delete_range(lower, upper);
        self.check_batch(&batch)
    }
    fn commit(self: Box<Self>) -> Result<()> {
        let batch = self.batch.into_inner().unwrap();
        batch.check().map_err(|error| {
            self.db.0.record_execution_failure();
            error
        })?;
        self.db.0.apply(&batch.mutations).map_err(error)
    }
    fn abort(self: Box<Self>) -> Result<()> {
        Ok(())
    }
    fn new_iter(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn quil_types::store::Iterator>> {
        // As with RocksTxn, this legacy iterator trait cannot represent read
        // failures. Do not turn exhausted budgets into successful end-of-data.
        self.db.0.record_execution_failure();
        Err(error(
            "OverlayTxn iterator not implemented; use a retained store read view",
        ))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Minimal common reader used by the fixed-vertex page merge. Both backends
/// retain the same key ordering, exact-length checks and MVCC precedence.
pub(crate) trait PageCursor {
    fn valid(&self) -> bool;
    fn key(&self) -> Option<&[u8]>;
    fn value(&self) -> Option<&[u8]>;
    fn seek(&mut self, key: impl AsRef<[u8]>);
    fn seek_for_prev(&mut self, key: impl AsRef<[u8]>);
    fn next(&mut self);
    fn prev(&mut self);
    fn status(&self) -> Result<()>;
}

pub(crate) trait PageSnapshot {
    type Cursor<'a>: PageCursor
    where
        Self: 'a;
    fn raw_cursor(&self) -> Self::Cursor<'_>;
}

impl PageSnapshot for rocksdb::SnapshotWithThreadMode<'_, rocksdb::DB> {
    type Cursor<'a>
        = rocksdb::DBRawIterator<'a>
    where
        Self: 'a;
    fn raw_cursor(&self) -> Self::Cursor<'_> {
        self.raw_iterator()
    }
}
impl PageSnapshot for OverlayDbSnapshot {
    type Cursor<'a>
        = OverlayRawCursor
    where
        Self: 'a;
    fn raw_cursor(&self) -> Self::Cursor<'_> {
        self.raw_iterator()
    }
}

impl PageCursor for rocksdb::DBRawIterator<'_> {
    fn valid(&self) -> bool {
        self.valid()
    }
    fn key(&self) -> Option<&[u8]> {
        self.key()
    }
    fn value(&self) -> Option<&[u8]> {
        self.value()
    }
    fn seek(&mut self, key: impl AsRef<[u8]>) {
        self.seek(key);
    }
    fn seek_for_prev(&mut self, key: impl AsRef<[u8]>) {
        self.seek_for_prev(key);
    }
    fn next(&mut self) {
        self.next();
    }
    fn prev(&mut self) {
        self.prev();
    }
    fn status(&self) -> Result<()> {
        self.status().map_err(error)
    }
}
impl PageCursor for OverlayRawCursor {
    fn valid(&self) -> bool {
        self.valid()
    }
    fn key(&self) -> Option<&[u8]> {
        self.key()
    }
    fn value(&self) -> Option<&[u8]> {
        self.value()
    }
    fn seek(&mut self, key: impl AsRef<[u8]>) {
        self.seek(key);
    }
    fn seek_for_prev(&mut self, key: impl AsRef<[u8]>) {
        self.seek_for_prev(key);
    }
    fn next(&mut self) {
        self.next();
    }
    fn prev(&mut self) {
        self.prev();
    }
    fn status(&self) -> Result<()> {
        self.status()
    }
}
