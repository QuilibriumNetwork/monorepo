//! Bounded tentative writes over a pinned RocksDB sequence, without copying
//! the database. Publication consumes a frozen delta and checks its base
//! sequence under the database's shared write barrier before one synced batch.
//! Only writes confined to key prefixes this branch never read, scanned or
//! wrote may intervene. Frame authentication and in-memory state adoption
//! belong to the caller.
//!
//! Limits cover logical records and operations, not RocksDB's internal cache
//! or physical I/O. A snapshot also retains superseded versions on disk, and
//! the iterators parked on it retain the table files they read. Its
//! owner must call `close` when abandoning a branch (and enforce a lifetime
//! policy); memory limits alone do not bound that disk retention.
//! Inputs and JMT batch construction belong to the execution owner's frame
//! budget; this layer bounds the retained delta and returned read records.

use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Result};

#[cfg(test)]
#[path = "overlay_publication_tests.rs"]
mod publication_tests;

#[cfg(test)]
#[path = "overlay_admission_tests.rs"]
mod admission_tests;

/// No production defaults: the execution owner must choose a resource policy.
#[derive(Clone, Copy, Debug)]
pub struct OverlayLimits {
    /// Key/value and range-endpoint bytes in the current delta.
    pub max_delta_bytes: usize,
    /// Points (including tombstones) plus disjoint deleted ranges.
    pub max_delta_entries: usize,
    pub max_record_bytes: usize,
    /// Cumulative bytes returned by reads, including key bytes.
    pub max_read_bytes: u64,
    /// Point reads, iterator seeks/steps and examined delta entries.
    pub max_read_operations: u64,
    /// Cursors and retained read views pin earlier delta generations. At most
    /// this many old generations plus the current delta and one atomic write
    /// candidate can coexist per branch. The original capture's same limit
    /// separately bounds all descendant branches sharing its DB snapshot.
    pub max_cursors: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlayStats {
    pub delta_bytes: usize,
    pub delta_entries: usize,
    pub read_bytes: u64,
    pub read_operations: u64,
    pub cursors: usize,
    /// Descendant branches retained in this snapshot family, including closed
    /// branches whose handles/read views have not yet been dropped.
    pub descendant_branches: usize,
    pub closed: bool,
}

#[derive(Clone, Debug)]
pub enum OverlayMutation {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    /// Half-open interval, matching RocksDB's DeleteRange.
    DeleteRange(Vec<u8>, Vec<u8>),
}

/// Admission for pinned execution views across every database in a process:
/// the GLOBAL pipeline, selected-parent execution and each thread worker's
/// application parents. Each captured branch family holds one RocksDB
/// snapshot, and a snapshot keeps every version superseded after it on disk
/// until it is released, so both how many are held and for how long are
/// bounded. Descendant forks share their family's view and count once.
///
/// A view older than the age limit is released: by its own next read, or by
/// the sweep each new capture runs, which also covers a branch its owner holds
/// but no longer uses. Every later read of that branch fails and marks it
/// failed, so it can never publish.
pub struct ExecutionViewAdmission {
    active: AtomicUsize,
    max_views: AtomicUsize,
    max_age_ms: AtomicU64,
    live: Mutex<Vec<Weak<PinnedSnapshot>>>,
}

/// Views held when no policy is configured: generous for one per worker core
/// plus the GLOBAL paths, small enough to stop a leak.
fn default_max_views() -> usize {
    std::thread::available_parallelism().map_or(16, |n| n.get()).saturating_mul(4).max(64)
}

/// A private parent is released once canonical execution passes it, and a
/// GLOBAL execution completes within its frame; ten minutes is only reached
/// by a stalled holder.
pub const DEFAULT_EXECUTION_VIEW_MAX_AGE: Duration = Duration::from_secs(600);

static PROCESS_ADMISSION: LazyLock<Arc<ExecutionViewAdmission>> = LazyLock::new(|| {
    let setting = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok()).filter(|v| *v > 0);
    ExecutionViewAdmission::new(
        setting("QUIL_EXECUTION_VIEW_MAX").map_or_else(default_max_views, |v| v as usize),
        setting("QUIL_EXECUTION_VIEW_MAX_AGE_SECS").map_or(DEFAULT_EXECUTION_VIEW_MAX_AGE, Duration::from_secs),
    )
});

impl ExecutionViewAdmission {
    pub fn new(max_views: usize, max_age: Duration) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicUsize::new(0),
            max_views: AtomicUsize::new(max_views),
            max_age_ms: AtomicU64::new(max_age.as_millis().min(u64::MAX as u128) as u64),
            live: Mutex::new(Vec::new()),
        })
    }

    /// The admission `ExecutionOverlay::capture` uses (`QUIL_EXECUTION_VIEW_MAX`,
    /// `QUIL_EXECUTION_VIEW_MAX_AGE_SECS`, else the defaults).
    pub fn process() -> &'static Arc<Self> {
        &PROCESS_ADMISSION
    }

    /// Applies to captures from now on; held views keep their admission but
    /// expire under the new age.
    pub fn set_policy(&self, max_views: usize, max_age: Duration) {
        self.max_views.store(max_views, Ordering::Release);
        self.max_age_ms.store(max_age.as_millis().min(u64::MAX as u128) as u64, Ordering::Release);
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn max_age(&self) -> Duration {
        Duration::from_millis(self.max_age_ms.load(Ordering::Acquire))
    }

    /// Release every held view older than the age limit; returns how many.
    /// Also drops the idle iterators parked on every held view.
    pub fn release_expired(&self) -> usize {
        let views: Vec<Arc<PinnedSnapshot>> = {
            let mut live = self.live.lock().unwrap_or_else(|p| p.into_inner());
            live.retain(|view| view.strong_count() > 0);
            live.iter().filter_map(Weak::upgrade).collect()
        };
        for view in &views {
            view.drop_idle_iterators();
        }
        let max_age = self.max_age();
        views.iter().filter(|view| view.captured.elapsed() > max_age && view.release()).count()
    }

    fn acquire(&self) -> Result<()> {
        let limit = self.max_views.load(Ordering::Acquire);
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1).filter(|next| *next <= limit))
            .map(|_| ())
            .map_err(|_| anyhow::anyhow!("execution view admission limit ({limit} held views)"))
    }
}

// As in quil-store's RocksHypergraphSnapshot: the snapshot borrows the Arc's
// stable pointee. Declaration order MUST release the snapshot before the DB.
struct PinnedSnapshot {
    // Emptied before the snapshot is released (see `release`).
    iterators: Mutex<Vec<ParkedIterator>>,
    snapshot: Mutex<Option<rocksdb::SnapshotWithThreadMode<'static, rocksdb::DB>>>,
    captured: Instant,
    admission: Arc<ExecutionViewAdmission>,
    _db: crate::CoordinatedDb,
    sequence: u64,
    /// The database's last watched write at `sequence`, if it watches keys.
    watched: Option<u64>,
    #[cfg(test)]
    iterators_created: AtomicUsize,
}

type HeldView<'a> = MutexGuard<'a, Option<rocksdb::SnapshotWithThreadMode<'static, rocksdb::DB>>>;

/// Idle iterators kept per snapshot family. A scan uses one or two bounds at a
/// time; the rest only bound what an unusual caller can hold.
const MAX_PARKED_ITERATORS: usize = 8;

/// A parked iterator pins the memtables and table files current when it was
/// created, which the snapshot alone does not. A scan retakes its iterator
/// within microseconds; one idle longer than this is dropped by the next
/// capture's sweep, so a long-held branch does not retain flushed memtables.
const MAX_PARKED_IDLE: Duration = Duration::from_secs(1);

/// A snapshot iterator kept between cursor steps. A step seeks unless the
/// iterator already sits on the step's key, where that seek would leave it, so
/// reuse changes only the cost: a fresh iterator reads a data block from each
/// L0 file and level on its first seek, and a next/prev from the row just
/// returned becomes one RocksDB step. On a mainnet-sized store, building one
/// per step made each GLOBAL parent capture take ~27 s.
struct ParkedIterator {
    lower: Vec<u8>,
    upper: Vec<u8>,
    parked_at: Instant,
    iterator: rocksdb::DBRawIteratorWithThreadMode<'static, rocksdb::DB>,
}

impl PinnedSnapshot {
    fn new(db: crate::CoordinatedDb, admission: &Arc<ExecutionViewAdmission>) -> Result<Arc<Self>> {
        admission.release_expired();
        admission.acquire()?;
        let (snapshot, sequence, watched) = match db.execution_snapshot() {
            Ok(captured) => captured,
            Err(error) => {
                admission.active.fetch_sub(1, Ordering::AcqRel);
                return Err(error.into());
            }
        };
        // SAFETY: the owning Arc keeps the DB at its stable address; the
        // private snapshot cannot escape and drops before that Arc.
        let snapshot = unsafe { std::mem::transmute(snapshot) };
        let view = Arc::new(Self {
            iterators: Mutex::new(Vec::new()),
            snapshot: Mutex::new(Some(snapshot)),
            captured: Instant::now(),
            admission: admission.clone(),
            _db: db,
            sequence,
            watched,
            #[cfg(test)]
            iterators_created: AtomicUsize::new(0),
        });
        admission.live.lock().unwrap_or_else(|p| p.into_inner()).push(Arc::downgrade(&view));
        Ok(view)
    }

    /// The pinned view for one read, released first if it outlived its age.
    fn view(&self) -> Result<HeldView<'_>> {
        let held = self.snapshot.lock().map_err(|_| anyhow::anyhow!("execution view lock poisoned"))?;
        ensure!(held.is_some(), "execution view expired and was released");
        if self.captured.elapsed() > self.admission.max_age() {
            drop(held);
            self.release();
            bail!("execution view expired and was released");
        }
        Ok(held)
    }

    /// A parked iterator with exactly these bounds, else a new one. The caller
    /// holds `view` and parks the iterator again before dropping it.
    fn take_iterator(&self, view: &HeldView<'_>, lower: &[u8], upper: &[u8]) -> Result<ParkedIterator> {
        let mut parked = self.iterators.lock().map_err(|_| anyhow::anyhow!("execution view lock poisoned"))?;
        if let Some(index) = parked.iter().position(|p| p.lower == lower && p.upper == upper) {
            return Ok(parked.swap_remove(index));
        }
        drop(parked);
        let mut options = rocksdb::ReadOptions::default();
        options.set_iterate_lower_bound(lower.to_vec());
        options.set_iterate_upper_bound(upper.to_vec());
        let iterator = view.as_ref().expect("view() holds the snapshot").raw_iterator_opt(options);
        #[cfg(test)]
        self.iterators_created.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the iterator reads through the DB, which `_db` keeps alive
        // and which drops after `iterators`, and through the snapshot, which
        // `release` takes only after emptying `iterators`.
        let iterator = unsafe { std::mem::transmute(iterator) };
        Ok(ParkedIterator { lower: lower.to_vec(), upper: upper.to_vec(), parked_at: Instant::now(), iterator })
    }

    /// Keep a healthy iterator for the next step. The caller still holds the
    /// view, so a concurrent `release` cannot miss it.
    fn park(&self, mut iterator: ParkedIterator, _view: &HeldView<'_>) {
        if iterator.iterator.status().is_err() {
            return;
        }
        iterator.parked_at = Instant::now();
        let mut parked = self.iterators.lock().unwrap_or_else(|p| p.into_inner());
        if parked.len() < MAX_PARKED_ITERATORS {
            parked.push(iterator);
        }
    }

    /// Dropping an iterator touches neither the snapshot nor another reader.
    fn drop_idle_iterators(&self) {
        let mut parked = self.iterators.lock().unwrap_or_else(|p| p.into_inner());
        parked.retain(|p| p.parked_at.elapsed() <= MAX_PARKED_IDLE);
    }

    /// Drop the RocksDB snapshot now; returns whether it was still held.
    fn release(&self) -> bool {
        let released = {
            let mut snapshot = self.snapshot.lock().unwrap_or_else(|p| p.into_inner());
            // Parked iterators pin table files and refer to the snapshot.
            self.iterators.lock().unwrap_or_else(|p| p.into_inner()).clear();
            snapshot.take()
        };
        let held = released.is_some();
        drop(released);
        if held {
            self.admission.active.fetch_sub(1, Ordering::AcqRel);
        }
        held
    }
}

impl Drop for PinnedSnapshot {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Clone, Default)]
struct Delta {
    points: BTreeMap<Vec<u8>, Option<Arc<[u8]>>>,
    // Disjoint, non-adjacent ranges. Point puts override these ranges; a later
    // range delete removes every earlier point within its interval.
    ranges: BTreeMap<Vec<u8>, Vec<u8>>,
    bytes: usize,
}

impl Delta {
    fn entries(&self) -> usize {
        self.points.len() + self.ranges.len()
    }

    /// Whether a tentative write here covers a key under one of `prefixes`.
    fn writes_under(&self, prefixes: &[Vec<u8>]) -> bool {
        prefixes.iter().any(|p| {
            self.points
                .range::<[u8], _>((Bound::Included(p.as_slice()), Bound::Unbounded))
                .next()
                .is_some_and(|(key, _)| key.starts_with(p))
        }) || self
            .ranges
            .iter()
            .any(|(start, end)| crate::database::range_meets(prefixes, start, end))
    }

    fn covering_range(&self, key: &[u8]) -> Option<(&[u8], &[u8])> {
        self.ranges
            .range::<[u8], _>((Bound::Unbounded, Bound::Included(key)))
            .next_back()
            .filter(|(_, end)| key < end.as_slice())
            .map(|(start, end)| (start.as_slice(), end.as_slice()))
    }

    fn point(&mut self, key: &[u8], value: Option<&[u8]>, limits: OverlayLimits) -> Result<()> {
        let size = key
            .len()
            .checked_add(value.map_or(0, <[u8]>::len))
            .ok_or_else(|| anyhow::anyhow!("overlay record size overflow"))?;
        ensure!(size <= limits.max_record_bytes, "overlay record byte limit");
        let old = self.points.get(key);
        let old_size = old.map_or(0, |v| key.len() + v.as_ref().map_or(0, |v| v.len()));
        let bytes = self
            .bytes
            .checked_sub(old_size)
            .and_then(|n| n.checked_add(size))
            .ok_or_else(|| anyhow::anyhow!("overlay delta size overflow"))?;
        ensure!(bytes <= limits.max_delta_bytes, "overlay delta byte limit");
        ensure!(
            self.entries() + usize::from(old.is_none()) <= limits.max_delta_entries,
            "overlay delta entry limit"
        );
        self.points.insert(key.to_vec(), value.map(Arc::from));
        self.bytes = bytes;
        Ok(())
    }

    fn delete_range(&mut self, start: &[u8], end: &[u8], limits: OverlayLimits) -> Result<()> {
        ensure!(start <= end, "overlay reversed delete range");
        ensure!(
            start.len().saturating_add(end.len()) <= limits.max_record_bytes,
            "overlay record byte limit"
        );
        if start == end {
            return Ok(());
        }
        // This edits only an unpublished candidate; any later limit failure
        // discards the whole candidate, including these removals.
        self.points.retain(|key, value| {
            let keep = key.as_slice() < start || key.as_slice() >= end;
            if !keep {
                self.bytes -= key.len() + value.as_ref().map_or(0, |v| v.len());
            }
            keep
        });
        let mut lower = start.to_vec();
        let mut upper = end.to_vec();
        self.ranges.retain(|a, b| {
            if b.as_slice() < lower.as_slice() || a.as_slice() > upper.as_slice() {
                return true;
            }
            if a < &lower {
                lower = a.clone();
            }
            if b.as_slice() > upper.as_slice() {
                upper = b.clone();
            }
            self.bytes -= a.len() + b.len();
            false
        });
        let bytes = self
            .bytes
            .checked_add(lower.len())
            .and_then(|n| n.checked_add(upper.len()))
            .ok_or_else(|| anyhow::anyhow!("overlay delta size overflow"))?;
        ensure!(
            lower.len().saturating_add(upper.len()) <= limits.max_record_bytes,
            "overlay record byte limit"
        );
        ensure!(bytes <= limits.max_delta_bytes, "overlay delta byte limit");
        ensure!(
            self.entries() < limits.max_delta_entries,
            "overlay delta entry limit"
        );
        self.ranges.insert(lower, upper);
        self.bytes = bytes;
        Ok(())
    }
}

#[derive(Default)]
struct ReadBudget {
    operations: u64,
    bytes: u64,
}

impl ReadBudget {
    fn operation(&mut self, limits: OverlayLimits) -> Result<()> {
        ensure!(
            self.operations < limits.max_read_operations,
            "overlay read operation limit: {} reads allowed, {} bytes read",
            limits.max_read_operations,
            self.bytes
        );
        self.operations += 1;
        Ok(())
    }

    fn record(&mut self, key: &[u8], value: &[u8], limits: OverlayLimits) -> Result<()> {
        let size = key
            .len()
            .checked_add(value.len())
            .ok_or_else(|| anyhow::anyhow!("overlay record size overflow"))?;
        ensure!(size <= limits.max_record_bytes, "overlay record byte limit");
        let bytes = self
            .bytes
            .checked_add(size as u64)
            .ok_or_else(|| anyhow::anyhow!("overlay read size overflow"))?;
        ensure!(
            bytes <= limits.max_read_bytes,
            "overlay read byte limit: {} bytes allowed, {} read in {} reads",
            limits.max_read_bytes,
            bytes,
            self.operations
        );
        self.bytes = bytes;
        Ok(())
    }
}

struct Inner {
    base: Option<Arc<PinnedSnapshot>>,
    delta: Arc<Delta>,
    /// Counts the delta's changes, so a reader can prove it read the delta a
    /// later commit publishes.
    generation: u64,
    reads: ReadBudget,
    cursors: usize,
    // Every prefix this branch or its ancestors (before the fork) read,
    // scanned or wrote. Publication tolerates only disjoint writes outside it.
    touched: crate::KeyPrefixSet,
}

struct ForkAdmission {
    active: AtomicUsize,
    limit: usize,
}

struct ForkPermit(Arc<ForkAdmission>);

impl ForkAdmission {
    fn acquire(self: &Arc<Self>, limit: usize) -> Result<ForkPermit> {
        let limit = limit.min(self.limit);
        self.active.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |n| n.checked_add(1).filter(|next| *next <= limit))
            .map_err(|_| anyhow::anyhow!("overlay descendant branch limit"))?;
        Ok(ForkPermit(self.clone()))
    }
}

impl Drop for ForkPermit {
    fn drop(&mut self) { self.0.active.fetch_sub(1, Ordering::AcqRel); }
}

/// One mutable execution branch. Clones of its Arc share that branch; they do
/// not fork it. Cursors read a stable delta generation against the same pinned
/// DB sequence. Closing invalidates its cursors and releases its snapshot
/// reference immediately. Independently forked children retain their captured
/// state until they too close; a parent's close never rewinds a child.
pub struct ExecutionOverlay {
    limits: OverlayLimits,
    failed_execution: AtomicBool,
    inner: Mutex<Inner>,
    family: Arc<ForkAdmission>,
    // Release only after the overlay and all its retained views are dropped;
    // close() alone may leave their bounded delta allocations alive.
    _fork_permit: Option<ForkPermit>,
}

/// A single-use delta. The storage operation is crash atomic, but it neither
/// authenticates consensus nor updates live CRDT/registry/clock caches. The
/// runtime owner must prepare their adoption before committing this plan.
pub struct PreparedOverlayCommit {
    database: crate::CoordinatedDb,
    sequence: u64,
    generation: u64,
    touched: crate::KeyPrefixSet,
    batch: rocksdb::WriteBatch,
}

impl PreparedOverlayCommit {
    /// The database sequence the branch was captured at.
    pub fn base_sequence(&self) -> u64 {
        self.sequence
    }

    /// The branch's [`ExecutionOverlay::delta_generation`] this plan froze.
    pub fn delta_generation(&self) -> u64 {
        self.generation
    }

    pub fn commit(self, destination: &crate::CoordinatedDb) -> Result<(), crate::DatabaseCommitError> {
        self.commit_locked(&mut destination.lock_writes()?)
    }

    /// Retain the caller's write barrier through infallible metadata adoption.
    /// Any intervening general write rejects this plan before publication, as
    /// does a disjoint write (for example a clock candidate) to a prefix this
    /// branch touched. The owner must recapture/re-execute on conflict.
    pub fn commit_locked(self, guard: &mut crate::DatabaseWriteGuard<'_>) -> Result<(), crate::DatabaseCommitError> {
        guard.commit_execution(&self.database, self.sequence, &self.touched, self.batch)
    }
}

impl ExecutionOverlay {
    /// Capture under the process-wide [`ExecutionViewAdmission`].
    pub fn capture(db: crate::CoordinatedDb, limits: OverlayLimits) -> Result<Self> {
        Self::capture_admitted(db, limits, ExecutionViewAdmission::process())
    }

    pub fn capture_admitted(
        db: crate::CoordinatedDb,
        limits: OverlayLimits,
        admission: &Arc<ExecutionViewAdmission>,
    ) -> Result<Self> {
        Ok(Self {
            limits,
            failed_execution: AtomicBool::new(false),
            inner: Mutex::new(Inner {
                base: Some(PinnedSnapshot::new(db, admission)?),
                delta: Arc::new(Delta::default()),
                generation: 0,
                reads: ReadBudget::default(),
                cursors: 0,
                touched: crate::KeyPrefixSet::default(),
            }),
            family: Arc::new(ForkAdmission { active: AtomicUsize::new(0), limit: limits.max_cursors }),
            _fork_permit: None,
        })
    }

    /// Freeze and close a healthy branch for one atomic durable write. No
    /// further reads, writes or forks can use this owner; existing independent
    /// children retain their original base and will conflict after publication.
    /// Abandoning the returned plan makes no durable changes.
    pub fn prepare_commit(&self) -> Result<PreparedOverlayCommit> {
        self.observe((|| {
            ensure!(self.execution_healthy(), "failed execution overlay cannot publish");
            let mut inner = self.lock_inner()?;
            let base = inner.base.as_ref().ok_or_else(|| anyhow::anyhow!("execution overlay closed"))?;
            let mut batch = rocksdb::WriteBatch::default();
            // Points override range tombstones in the delta, including a put
            // following a delete range. Preserve that ordering in RocksDB.
            for (start, end) in &inner.delta.ranges { batch.delete_range(start, end); }
            for (key, value) in &inner.delta.points {
                match value {
                    Some(value) => batch.put(key, value.as_ref()),
                    None => batch.delete(key),
                }
            }
            ensure!(self.execution_healthy(), "failed execution overlay cannot publish");
            let plan = PreparedOverlayCommit {
                database: base._db.clone(),
                sequence: base.sequence,
                generation: inner.generation,
                touched: inner.touched.clone(),
                batch,
            };
            inner.base = None;
            inner.delta = Arc::new(Delta::default());
            Ok(plan)
        })())
    }

    /// Fork the current delta over the same pinned database sequence. Limits
    /// may only tighten; the inherited delta counts toward the child's budget.
    /// Deltas are shared until a write, without layering reads through parents.
    /// The snapshot family's descendant limit also applies across generations.
    pub fn fork(&self, limits: OverlayLimits) -> Result<Self> {
        ensure!(limits.max_delta_bytes <= self.limits.max_delta_bytes
            && limits.max_delta_entries <= self.limits.max_delta_entries
            && limits.max_record_bytes <= self.limits.max_record_bytes
            && limits.max_read_bytes <= self.limits.max_read_bytes
            && limits.max_read_operations <= self.limits.max_read_operations
            && limits.max_cursors <= self.limits.max_cursors,
            "overlay fork cannot increase resource limits");
        let inner = self.lock_inner()?;
        let base = inner.base.as_ref().ok_or_else(|| anyhow::anyhow!("execution overlay closed"))?;
        ensure!(inner.delta.bytes <= limits.max_delta_bytes, "inherited overlay delta byte limit");
        ensure!(inner.delta.entries() <= limits.max_delta_entries, "inherited overlay delta entry limit");
        let mut reads = ReadBudget::default();
        for (key, value) in &inner.delta.points {
            reads.operation(limits)?;
            ensure!(key.len().saturating_add(value.as_ref().map_or(0, |v| v.len())) <= limits.max_record_bytes,
                "inherited overlay record byte limit");
        }
        for (start, end) in &inner.delta.ranges {
            reads.operation(limits)?;
            ensure!(start.len().saturating_add(end.len()) <= limits.max_record_bytes,
                "inherited overlay range byte limit");
        }
        let permit = self.family.acquire(self.limits.max_cursors)?;
        Ok(Self {
            limits,
            failed_execution: AtomicBool::new(!self.execution_healthy()),
            inner: Mutex::new(Inner {
                base: Some(base.clone()),
                delta: inner.delta.clone(),
                generation: 0,
                reads,
                cursors: 0,
                touched: inner.touched.clone(),
            }),
            family: self.family.clone(), _fork_permit: Some(permit),
        })
    }

    pub fn close(&self) {
        let mut inner = self.lock_cleanup();
        inner.base = None;
        inner.delta = Arc::new(Delta::default());
    }

    pub fn stats(&self) -> OverlayStats {
        let inner = self.lock_cleanup();
        OverlayStats {
            delta_bytes: inner.delta.bytes,
            delta_entries: inner.delta.entries(),
            read_bytes: inner.reads.bytes,
            read_operations: inner.reads.operations,
            cursors: inner.cursors,
            descendant_branches: self.family.active.load(Ordering::Acquire),
            closed: inner.base.as_ref().is_none_or(|base| {
                base.snapshot.lock().unwrap_or_else(|p| p.into_inner()).is_none()
            }),
        }
    }

    pub fn limits(&self) -> OverlayLimits {
        self.limits
    }

    /// Changes each time this branch's delta changes; fixed once it is frozen
    /// for publication.
    pub fn delta_generation(&self) -> u64 {
        self.lock_cleanup().generation
    }

    /// The captured database view whose watched keys this branch still reads
    /// unchanged: `None` once it has written one, is closed, or when its
    /// database watches no keys.
    pub fn capture_point(&self) -> Option<quil_types::store::CapturePoint> {
        let inner = self.lock_cleanup();
        let base = inner.base.as_ref()?;
        if inner.delta.writes_under(base._db.watched_prefixes()?) {
            return None;
        }
        Some(quil_types::store::CapturePoint {
            database: base._db.instance(),
            sequence: base.sequence,
            watched: base.watched?,
        })
    }

    /// Every key this branch put or deleted under `prefixes`; `None` when a
    /// deleted range reaches into one of them, whose keys cannot be listed.
    pub fn written_keys_under(&self, prefixes: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        let inner = self.lock_cleanup();
        if inner.delta.ranges.iter().any(|(start, end)| crate::database::range_meets(prefixes, start, end)) {
            return None;
        }
        let mut keys = Vec::new();
        for prefix in prefixes {
            keys.extend(
                inner.delta.points
                    .range::<[u8], _>((Bound::Included(prefix.as_slice()), Bound::Unbounded))
                    .take_while(|(key, _)| key.starts_with(prefix))
                    .map(|(key, _)| key.clone()),
            );
        }
        Some(keys)
    }

    /// Sticky storage-failure evidence, independent of whether a caller
    /// propagates the error. Reads may still inspect a failed overlay, but an
    /// execution owner must discard it. Low-level recapture remains available
    /// for inspection/recovery but carries the failure evidence into the child.
    pub fn execution_healthy(&self) -> bool {
        !self.failed_execution.load(Ordering::Acquire) && !self.inner.is_poisoned()
    }

    /// Storage adapters call this when staging fails before reaching `apply`.
    pub fn record_execution_failure(&self) {
        self.failed_execution.store(true, Ordering::Release);
    }

    fn observe<T>(&self, result: Result<T>) -> Result<T> {
        if result.is_err() { self.record_execution_failure(); }
        result
    }

    fn lock_inner(&self) -> Result<MutexGuard<'_, Inner>> {
        self.inner.lock().map_err(|_| {
            self.record_execution_failure();
            anyhow::anyhow!("execution overlay lock poisoned")
        })
    }

    // Cleanup and diagnostics may inspect poisoned state solely to release
    // retained storage and handles. Execution must never recover that state.
    fn lock_cleanup(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            self.record_execution_failure();
            poisoned.into_inner()
        })
    }

    /// Retain one delta generation for related point reads and scans. This
    /// shares the cursor admission limit; cloning an Arc to the view does not
    /// create another generation. `close` invalidates this view too.
    pub fn read_view(self: &Arc<Self>) -> Result<OverlayReadView> {
        self.observe(self.read_view_inner())
    }

    fn read_view_inner(self: &Arc<Self>) -> Result<OverlayReadView> {
        let mut inner = self.lock_inner()?;
        ensure!(inner.base.is_some(), "execution overlay closed");
        ensure!(
            inner.cursors < self.limits.max_cursors,
            "overlay read handle limit"
        );
        inner.cursors += 1;
        Ok(OverlayReadView {
            overlay: self.clone(),
            delta: inner.delta.clone(),
        })
    }

    /// Publish all mutations to this branch or none. The limit is checked
    /// throughout construction, including intermediate states within a batch.
    /// Previously opened cursors keep their earlier view.
    pub fn apply(&self, mutations: &[OverlayMutation]) -> Result<()> {
        self.observe(self.apply_inner(mutations))
    }

    fn apply_inner(&self, mutations: &[OverlayMutation]) -> Result<()> {
        let mut inner = self.lock_inner()?;
        ensure!(inner.base.is_some(), "execution overlay closed");
        if mutations.is_empty() {
            return Ok(());
        }
        let mut candidate = (*inner.delta).clone();
        // Marking before a failed mutation is harmless: failure closes the
        // branch to publication, and extra marks only add conflicts.
        for mutation in mutations {
            match mutation {
                OverlayMutation::Put(k, v) => {
                    inner.touched.mark_key(k);
                    candidate.point(k, Some(v), self.limits)?
                }
                OverlayMutation::Delete(k) => {
                    inner.touched.mark_key(k);
                    candidate.point(k, None, self.limits)?
                }
                OverlayMutation::DeleteRange(a, b) => {
                    inner.touched.mark_range(a, b);
                    candidate.delete_range(a, b, self.limits)?
                }
            }
        }
        inner.delta = Arc::new(candidate);
        inner.generation += 1;
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_at(key, None)
    }

    fn get_at(&self, key: &[u8], captured: Option<&Delta>) -> Result<Option<Vec<u8>>> {
        self.observe(self.get_at_inner(key, captured))
    }

    fn get_at_inner(&self, key: &[u8], captured: Option<&Delta>) -> Result<Option<Vec<u8>>> {
        ensure!(
            key.len() <= self.limits.max_record_bytes,
            "overlay record byte limit"
        );
        let mut inner = self.lock_inner()?;
        let Inner {
            base, delta, reads, touched, ..
        } = &mut *inner;
        touched.mark_key(key);
        let delta = captured.unwrap_or(delta);
        let base = base
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("execution overlay closed"))?;
        reads.operation(self.limits)?;
        if let Some(value) = delta.points.get(key) {
            return match value {
                Some(value) => {
                    reads.record(key, value, self.limits)?;
                    Ok(Some(value.to_vec()))
                }
                None => Ok(None),
            };
        }
        if delta.covering_range(key).is_some() {
            return Ok(None);
        }
        // Pin first, inspect length, then copy. An oversized stored value must
        // not allocate an unbounded Vec before the limit can reject it. Reads
        // fill the block cache like canonical ones: skipping it re-reads and
        // decompresses index blocks from disk on every read of a large store.
        let options = rocksdb::ReadOptions::default();
        let view = base.view()?;
        let value = view.as_ref().expect("view() holds the snapshot").get_pinned_opt(key, options)?;
        match value {
            Some(value) => {
                reads.record(key, &value, self.limits)?;
                Ok(Some(value.to_vec()))
            }
            None => Ok(None),
        }
    }

    /// Cursor restricted to [lower, upper). Its bounds and current record are
    /// individually byte bounded; the cursor count bounds retained generations.
    pub fn cursor(&self, lower: &[u8], upper: &[u8]) -> Result<OverlayCursor<'_>> {
        self.cursor_at(lower, upper, None)
    }

    fn cursor_at(
        &self,
        lower: &[u8],
        upper: &[u8],
        captured: Option<&Arc<Delta>>,
    ) -> Result<OverlayCursor<'_>> {
        self.observe(self.cursor_at_inner(lower, upper, captured))
    }

    fn cursor_at_inner(
        &self,
        lower: &[u8],
        upper: &[u8],
        captured: Option<&Arc<Delta>>,
    ) -> Result<OverlayCursor<'_>> {
        ensure!(lower < upper, "overlay empty or reversed cursor bounds");
        ensure!(
            lower.len().saturating_add(upper.len()) <= self.limits.max_record_bytes,
            "overlay cursor bound byte limit"
        );
        let mut inner = self.lock_inner()?;
        ensure!(inner.base.is_some(), "execution overlay closed");
        ensure!(
            inner.cursors < self.limits.max_cursors,
            "overlay cursor limit"
        );
        inner.touched.mark_range(lower, upper);
        inner.cursors += 1;
        Ok(OverlayCursor {
            overlay: self,
            delta: captured.unwrap_or(&inner.delta).clone(),
            lower: lower.to_vec(),
            upper: upper.to_vec(),
            row: None,
        })
    }
}

/// Stable reads of both the captured RocksDB sequence and one overlay delta.
pub struct OverlayReadView {
    overlay: Arc<ExecutionOverlay>,
    delta: Arc<Delta>,
}

impl OverlayReadView {
    /// Let a bound adapter report an unsupported or failed scan even when it
    /// cannot return the error through its legacy iterator interface.
    pub fn record_execution_failure(&self) {
        self.overlay.record_execution_failure();
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.overlay.get_at(key, Some(&self.delta))
    }

    pub fn cursor(&self, lower: &[u8], upper: &[u8]) -> Result<OverlayCursor<'_>> {
        self.overlay.cursor_at(lower, upper, Some(&self.delta))
    }

    /// Reads of this view's watched keys read its database at the captured
    /// sequence while the view holds no tentative write to them.
    pub fn scan_point(&self) -> Option<quil_types::store::ScanPoint> {
        let inner = self.overlay.lock_cleanup();
        let base = inner.base.as_ref()?;
        if self.delta.writes_under(base._db.watched_prefixes()?) {
            return None;
        }
        Some(quil_types::store::ScanPoint {
            database: base._db.instance(),
            from: base.sequence,
            to: base.sequence,
        })
    }
}

impl Drop for OverlayReadView {
    fn drop(&mut self) {
        let mut inner = self.overlay.lock_cleanup();
        inner.cursors = inner.cursors.saturating_sub(1);
    }
}

pub struct OverlayCursor<'a> {
    overlay: &'a ExecutionOverlay,
    delta: Arc<Delta>,
    lower: Vec<u8>,
    upper: Vec<u8>,
    row: Option<(Vec<u8>, Vec<u8>)>,
}

impl Drop for OverlayCursor<'_> {
    fn drop(&mut self) {
        let mut inner = self.overlay.lock_cleanup();
        inner.cursors = inner.cursors.saturating_sub(1);
    }
}

impl OverlayCursor<'_> {
    pub fn key(&self) -> Option<&[u8]> {
        self.row.as_ref().map(|(k, _)| k.as_slice())
    }
    pub fn value(&self) -> Option<&[u8]> {
        self.row.as_ref().map(|(_, v)| v.as_slice())
    }
    pub fn valid(&self) -> bool {
        self.row.is_some()
    }

    pub fn seek(&mut self, key: &[u8]) -> Result<()> {
        self.position(key, false, true)
    }
    pub fn seek_for_prev(&mut self, key: &[u8]) -> Result<()> {
        self.position(key, true, true)
    }
    pub fn next(&mut self) -> Result<()> {
        if let Some((key, _)) = self.row.take() {
            self.position(&key, false, false)?;
        }
        Ok(())
    }
    pub fn prev(&mut self) -> Result<()> {
        if let Some((key, _)) = self.row.take() {
            self.position(&key, true, false)?;
        }
        Ok(())
    }

    fn position(&mut self, key: &[u8], reverse: bool, inclusive: bool) -> Result<()> {
        let result = self.position_inner(key, reverse, inclusive);
        self.overlay.observe(result)
    }

    fn position_inner(&mut self, key: &[u8], reverse: bool, inclusive: bool) -> Result<()> {
        // Clear before a fallible read: a failure must never expose the old row
        // as though it were the result of a new seek.
        self.row = None;
        ensure!(
            key.len() <= self.overlay.limits.max_record_bytes,
            "overlay seek byte limit"
        );
        let mut inner = self.overlay.lock_inner()?;
        let Inner { base, reads, .. } = &mut *inner;
        let base = base
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("execution overlay closed"))?;
        reads.operation(self.overlay.limits)?;
        let (key, inclusive) = if reverse {
            if key < self.lower.as_slice() {
                return Ok(());
            }
            if key >= self.upper.as_slice() {
                (self.upper.as_slice(), false)
            } else {
                (key, inclusive)
            }
        } else {
            if key >= self.upper.as_slice() {
                return Ok(());
            }
            if key < self.lower.as_slice() {
                (self.lower.as_slice(), true)
            } else {
                (key, inclusive)
            }
        };
        let bound = if inclusive {
            Bound::Included(key)
        } else {
            Bound::Excluded(key)
        };
        let mut points = if reverse {
            self.delta
                .points
                .range::<[u8], _>((Bound::Included(self.lower.as_slice()), bound))
        } else {
            self.delta
                .points
                .range::<[u8], _>((bound, Bound::Excluded(self.upper.as_slice())))
        };
        let point = loop {
            let item = if reverse {
                points.next_back()
            } else {
                points.next()
            };
            match item {
                Some((key, value)) => {
                    reads.operation(self.overlay.limits)?;
                    if let Some(value) = value {
                        break Some((key.as_slice(), value.as_ref()));
                    }
                }
                None => break None,
            }
        };
        // Reads fill the block cache: without it every seek re-reads each
        // level's index block from disk. A parked iterator already on `key`
        // is where either seek would put it (the key exists in this snapshot),
        // so the usual step from the row just returned skips the seek.
        let view = base.view()?;
        let mut parked = base.take_iterator(&view, &self.lower, &self.upper)?;
        let it = &mut parked.iterator;
        if it.key() != Some(key) {
            if reverse {
                it.seek_for_prev(key);
            } else {
                it.seek(key);
            }
        }
        if !inclusive && it.key() == Some(key) {
            reads.operation(self.overlay.limits)?;
            if reverse {
                it.prev();
            } else {
                it.next();
            }
        }
        // Jump over deleted ranges rather than visiting all their base keys.
        // Only individual overridden points require individual steps.
        while let Some(k) = it.key() {
            if let Some((start, end)) = self.delta.covering_range(k) {
                reads.operation(self.overlay.limits)?;
                if reverse {
                    it.seek_for_prev(start);
                    if it.key() == Some(start) {
                        reads.operation(self.overlay.limits)?;
                        it.prev();
                    }
                } else {
                    it.seek(end);
                }
            } else if self.delta.points.contains_key(k) {
                reads.operation(self.overlay.limits)?;
                if reverse {
                    it.prev();
                } else {
                    it.next();
                }
            } else {
                break;
            }
        }
        it.status()?;
        let stored = it.key().zip(it.value());
        let chosen = match (point, stored) {
            (Some(a), Some(b)) => Some(if if reverse { a.0 > b.0 } else { a.0 < b.0 } {
                a
            } else {
                b
            }),
            (a, b) => a.or(b),
        };
        if let Some((k, v)) = chosen {
            reads.record(k, v, self.overlay.limits)?;
            self.row = Some((k.to_vec(), v.to_vec()));
        }
        base.park(parked, &view);
        Ok(())
    }
}

// The forest uses the same encodings on both backends. A separate batch type
// preserves range deletes; RocksDB's WriteBatch::iterate only exposes point
// puts/deletes and must not be used to translate an arbitrary batch.
#[derive(Clone)]
pub(crate) enum KvStore {
    Rocks(crate::CoordinatedDb),
    Overlay(Arc<ExecutionOverlay>),
}

pub(crate) enum KvBatch {
    Rocks(rocksdb::WriteBatch),
    Overlay(Vec<OverlayMutation>),
}

impl KvBatch {
    pub(crate) fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        match self {
            Self::Rocks(b) => b.put(key, value),
            Self::Overlay(b) => b.push(OverlayMutation::Put(
                key.as_ref().to_vec(),
                value.as_ref().to_vec(),
            )),
        }
    }
    pub(crate) fn delete(&mut self, key: impl AsRef<[u8]>) {
        match self {
            Self::Rocks(b) => b.delete(key),
            Self::Overlay(b) => b.push(OverlayMutation::Delete(key.as_ref().to_vec())),
        }
    }
    pub(crate) fn delete_range(&mut self, lower: impl AsRef<[u8]>, upper: impl AsRef<[u8]>) {
        match self {
            Self::Rocks(b) => b.delete_range(lower.as_ref(), upper.as_ref()),
            Self::Overlay(b) => b.push(OverlayMutation::DeleteRange(
                lower.as_ref().to_vec(),
                upper.as_ref().to_vec(),
            )),
        }
    }
}

impl KvStore {
    pub(crate) fn db(&self) -> Option<&crate::CoordinatedDb> {
        match self {
            Self::Rocks(db) => Some(db),
            Self::Overlay(_) => None,
        }
    }
    pub(crate) fn batch(&self) -> KvBatch {
        match self {
            Self::Rocks(_) => KvBatch::Rocks(rocksdb::WriteBatch::default()),
            Self::Overlay(_) => KvBatch::Overlay(Vec::new()),
        }
    }
    pub(crate) fn write(&self, batch: KvBatch) -> Result<()> {
        match (self, batch) {
            (Self::Rocks(db), KvBatch::Rocks(b)) => Ok(db.write(b)?),
            (Self::Overlay(db), KvBatch::Overlay(b)) => db.apply(&b),
            _ => bail!("forest write batch backend mismatch"),
        }
    }
    pub(crate) fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Rocks(db) => Ok(db.get(key)?),
            Self::Overlay(db) => db.get(key.as_ref()),
        }
    }
    pub(crate) fn put(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<()> {
        let mut batch = self.batch();
        batch.put(key, value);
        self.write(batch)
    }
    pub(crate) fn delete(&self, key: impl AsRef<[u8]>) -> Result<()> {
        let mut batch = self.batch();
        batch.delete(key);
        self.write(batch)
    }
    pub(crate) fn flush(&self) -> Result<()> {
        match self {
            Self::Rocks(db) => Ok(db.flush()?),
            Self::Overlay(_) => Ok(()),
        }
    }
    pub(crate) fn iterator(
        &self,
        lower: &[u8],
        upper: &[u8],
        mut options: rocksdb::ReadOptions,
    ) -> Result<KvIterator<'_>> {
        match self {
            Self::Rocks(db) => {
                options.set_iterate_lower_bound(lower.to_vec());
                options.set_iterate_upper_bound(upper.to_vec());
                Ok(KvIterator::Rocks(db.raw_iterator_opt(options)))
            }
            Self::Overlay(db) => Ok(KvIterator::Overlay(db.cursor(lower, upper)?)),
        }
    }
}

pub(crate) enum KvIterator<'a> {
    Rocks(rocksdb::DBRawIterator<'a>),
    Overlay(OverlayCursor<'a>),
}

impl KvIterator<'_> {
    pub(crate) fn key(&self) -> Option<&[u8]> {
        match self {
            Self::Rocks(i) => i.key(),
            Self::Overlay(i) => i.key(),
        }
    }
    pub(crate) fn value(&self) -> Option<&[u8]> {
        match self {
            Self::Rocks(i) => i.value(),
            Self::Overlay(i) => i.value(),
        }
    }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Rocks(i) => i.valid(),
            Self::Overlay(i) => i.valid(),
        }
    }
    pub(crate) fn seek(&mut self, key: &[u8]) -> Result<()> {
        match self {
            Self::Rocks(i) => {
                i.seek(key);
                Ok(i.status()?)
            }
            Self::Overlay(i) => i.seek(key),
        }
    }
    pub(crate) fn seek_for_prev(&mut self, key: &[u8]) -> Result<()> {
        match self {
            Self::Rocks(i) => {
                i.seek_for_prev(key);
                Ok(i.status()?)
            }
            Self::Overlay(i) => i.seek_for_prev(key),
        }
    }
    pub(crate) fn next(&mut self) -> Result<()> {
        match self {
            Self::Rocks(i) => {
                i.next();
                Ok(i.status()?)
            }
            Self::Overlay(i) => i.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    include!("overlay_fork_tests.rs");

    #[test]
    fn poisoned_storage_closes_without_a_second_panic_and_rejects_reads() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        db.put(b"a", b"value").unwrap();
        let sequence = db.latest_sequence_number();
        let overlay = Arc::new(ExecutionOverlay::capture(db.clone(), limits()).unwrap());
        let child = overlay.fork(limits()).unwrap();
        let view = overlay.read_view().unwrap();
        let cursor = overlay.cursor(b"a", b"z").unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _guard = overlay.inner.lock().unwrap();
            panic!("injected storage panic");
        })).is_err());
        let read = catch_unwind(AssertUnwindSafe(|| overlay.get(b"a")));
        // Collect each cleanup result before asserting: a failing destructor
        // must not cause another destructor to panic during test unwinding.
        let closed = catch_unwind(AssertUnwindSafe(|| overlay.close()));
        let cursor_dropped = catch_unwind(AssertUnwindSafe(|| drop(cursor)));
        let view_dropped = catch_unwind(AssertUnwindSafe(|| drop(view)));
        assert!(closed.is_ok(), "closing poisoned storage must not panic");
        assert!(cursor_dropped.is_ok() && view_dropped.is_ok());
        assert!(matches!(read, Ok(Err(_))), "poisoned reads must return an error");
        assert!(!overlay.execution_healthy());
        assert!(overlay.stats().closed);
        assert_eq!(overlay.stats().cursors, 0);
        assert!(overlay.fork(limits()).is_err());
        assert!(overlay.read_view().is_err());
        assert!(overlay.get(b"a").is_err());
        assert!(overlay.apply(&[]).is_err());
        assert!(child.execution_healthy());
        assert_eq!(child.get(b"a").unwrap(), Some(b"value".to_vec()));
        assert_eq!(db.latest_sequence_number(), sequence);
        drop(child);
        assert_eq!(db.property_int_value("rocksdb.num-snapshots").unwrap(), Some(0));
    }

    #[test]
    fn swallowed_storage_failures_are_sticky_and_cannot_seed_a_healthy_child() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        db.put(b"a", b"value").unwrap();
        db.put(b"huge", [0; 1024]).unwrap();
        let sequence = db.latest_sequence_number();
        for failure in 0..6 {
            let budget = OverlayLimits { max_record_bytes: 32, max_cursors: 1, ..limits() };
            let overlay = Arc::new(ExecutionOverlay::capture(db.clone(), budget).unwrap());
            assert!(overlay.execution_healthy());
            match failure {
                0 => { assert!(overlay.get(b"huge").is_err()); },
                1 => {
                    let view = overlay.read_view().unwrap();
                    assert!(view.get(b"huge").is_err());
                },
                2 => {
                    let mut cursor = overlay.cursor(b"a", b"z").unwrap();
                    cursor.seek(b"a").unwrap();
                    assert!(cursor.next().is_err());
                    assert!(!cursor.valid());
                },
                3 => {
                    let _view = overlay.read_view().unwrap();
                    assert!(overlay.read_view().is_err());
                },
                4 => { assert!(overlay.cursor(b"z", b"a").is_err()); },
                _ => { assert!(overlay.apply(&[OverlayMutation::Put(b"b".to_vec(), vec![0; 33])]).is_err()); },
            }
            assert!(!overlay.execution_healthy());
            assert_eq!(overlay.get(b"a").unwrap(), Some(b"value".to_vec()), "inspection remains possible");
            assert!(!overlay.execution_healthy(), "successful reads cannot clear failure evidence");
            assert!(!overlay.fork(budget).unwrap().execution_healthy());
            assert_eq!(overlay.stats().delta_entries, 0);
        }
        assert_eq!(db.latest_sequence_number(), sequence);
    }

    fn limits() -> OverlayLimits {
        OverlayLimits {
            max_delta_bytes: 1 << 20,
            max_delta_entries: 4096,
            max_record_bytes: 4096,
            max_read_bytes: 64 << 20,
            max_read_operations: 2_000_000,
            max_cursors: 4,
        }
    }

    fn database(path: &std::path::Path) -> crate::CoordinatedDb {
        crate::CoordinatedDb::new(rocksdb::DB::open_default(path).unwrap())
    }

    fn collect(overlay: &ExecutionOverlay, reverse: bool) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut cursor = overlay.cursor(&[0, 0], &[1, 0]).unwrap();
        if reverse {
            cursor.seek_for_prev(&[1, 0]).unwrap();
        } else {
            cursor.seek(&[]).unwrap();
        }
        let mut out = BTreeMap::new();
        let mut previous: Option<Vec<u8>> = None;
        while cursor.valid() {
            let key = cursor.key().unwrap().to_vec();
            if let Some(p) = previous {
                assert!(if reverse { p > key } else { p < key });
            }
            previous = Some(key.clone());
            out.insert(key, cursor.value().unwrap().to_vec());
            if reverse {
                cursor.prev().unwrap();
            } else {
                cursor.next().unwrap();
            }
        }
        out
    }

    /// Branch reads fill the block cache like canonical reads. Skipping it made
    /// every seek re-read and decompress index blocks from disk, which on a
    /// mainnet-sized store took each GLOBAL parent capture 30–58 s.
    #[test]
    fn branch_reads_fill_the_block_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = rocksdb::Cache::new_lru_cache(64 << 20);
        let mut table = rocksdb::BlockBasedOptions::default();
        table.set_block_cache(&cache);
        table.set_cache_index_and_filter_blocks(true);
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        options.set_block_based_table_factory(&table);
        let raw = rocksdb::DB::open(&options, dir.path()).unwrap();
        for i in 0u32..20_000 {
            raw.put(i.to_be_bytes(), [7u8; 64]).unwrap();
        }
        raw.flush().unwrap();
        let overlay = ExecutionOverlay::capture(crate::CoordinatedDb::new(raw), limits()).unwrap();

        let before = cache.get_usage();
        assert!(overlay.get(&10_000u32.to_be_bytes()).unwrap().is_some());
        let after_get = cache.get_usage();
        assert!(after_get > before, "a branch point read must cache the block it read");
        let mut cursor = overlay.cursor(&[0; 4], &[0xff; 4]).unwrap();
        cursor.seek(&19_000u32.to_be_bytes()).unwrap();
        assert!(cursor.valid());
        assert!(cache.get_usage() > after_get, "a branch seek must cache the blocks it read");
    }

    /// Stepping through fresh cursors, as the store adapter does for every
    /// seek/next/prev, reuses one parked RocksDB iterator per bounds. Building
    /// one per step made each mainnet GLOBAL parent capture take ~27 s.
    #[test]
    fn cursor_steps_reuse_a_parked_iterator() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        for i in 0u16..512 {
            db.put(i.to_be_bytes(), [1u8; 8]).unwrap();
        }
        db.flush().unwrap();
        let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
        overlay
            .apply(&[
                OverlayMutation::Delete(7u16.to_be_bytes().to_vec()),
                OverlayMutation::DeleteRange(100u16.to_be_bytes().to_vec(), 200u16.to_be_bytes().to_vec()),
                OverlayMutation::Put(150u16.to_be_bytes().to_vec(), b"branch".to_vec()),
            ])
            .unwrap();
        let expected: Vec<Vec<u8>> = (0u16..512)
            .filter(|i| *i != 7 && !(100..200).contains(i) || *i == 150)
            .map(|i| i.to_be_bytes().to_vec())
            .collect();
        let step = |from: Option<&[u8]>, reverse: bool| {
            let mut cursor = overlay.cursor(&[0, 0], &[0xff, 0xff]).unwrap();
            match (from, reverse) {
                (None, false) => cursor.seek(&[0, 0]).unwrap(),
                (None, true) => cursor.seek_for_prev(&[0xff, 0xff]).unwrap(),
                (Some(key), false) => {
                    cursor.seek(key).unwrap();
                    cursor.next().unwrap();
                }
                (Some(key), true) => {
                    cursor.seek_for_prev(key).unwrap();
                    cursor.prev().unwrap();
                }
            }
            cursor.key().map(<[u8]>::to_vec)
        };
        for reverse in [false, true] {
            let mut seen = Vec::new();
            while let Some(key) = step(seen.last().map(Vec::as_slice), reverse) {
                seen.push(key);
            }
            if reverse {
                seen.reverse();
            }
            assert_eq!(seen, expected);
        }
        let base = overlay.lock_inner().unwrap().base.clone().unwrap();
        assert_eq!(base.iterators_created.load(Ordering::Relaxed), 1);
        assert_eq!(base.iterators.lock().unwrap().len(), 1);

        // A capture's sweep drops iterators left idle, which pin memtables.
        ExecutionViewAdmission::process().release_expired();
        assert_eq!(base.iterators.lock().unwrap().len(), 1, "a recently used iterator stays parked");
        base.iterators.lock().unwrap()[0].parked_at -= MAX_PARKED_IDLE + Duration::from_secs(1);
        ExecutionViewAdmission::process().release_expired();
        assert!(base.iterators.lock().unwrap().is_empty(), "an idle iterator is dropped");
        assert_eq!(step(None, false), expected.first().cloned(), "a step after the sweep reopens one");
        assert_eq!(base.iterators_created.load(Ordering::Relaxed), 2);

        base.release();
        assert!(base.iterators.lock().unwrap().is_empty(), "release drops parked iterators");
        assert!(overlay.cursor(&[0, 0], &[0xff, 0xff]).unwrap().seek(&[0, 0]).is_err());
        drop(base);
        overlay.close();
        assert_eq!(db.property_int_value("rocksdb.num-snapshots").unwrap(), Some(0));
    }

    /// A branch keeps its capture point, and its views their scan point, until
    /// a tentative write covers a watched key; a database that watches nothing
    /// has neither.
    // A branch's registry is updated from the rows it wrote, so those keys
    // must be listed exactly, and a range deletion over them reported.
    #[test]
    fn written_keys_are_listed_per_prefix_unless_a_range_covers_one() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        db.put([0x40, 0x01, 1], b"row").unwrap();
        let prefixes = vec![vec![0x40, 0x01], vec![0x41]];
        let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
        assert_eq!(overlay.written_keys_under(&prefixes), Some(vec![]));
        overlay
            .apply(&[
                OverlayMutation::Put(vec![0x40, 0x01, 2], b"new".to_vec()),
                OverlayMutation::Delete(vec![0x40, 0x01, 1]),
                OverlayMutation::Put(vec![0x41, 7], b"other".to_vec()),
                OverlayMutation::Put(vec![0x40, 0x02], b"outside".to_vec()),
                OverlayMutation::DeleteRange(vec![0x30], vec![0x40, 0x01]),
            ])
            .unwrap();
        assert_eq!(
            overlay.written_keys_under(&prefixes),
            Some(vec![vec![0x40, 0x01, 1], vec![0x40, 0x01, 2], vec![0x41, 7]])
        );
        overlay.apply(&[OverlayMutation::DeleteRange(vec![0x41, 0], vec![0x41, 5])]).unwrap();
        assert_eq!(overlay.written_keys_under(&prefixes), None);
    }

    #[test]
    fn capture_and_scan_points_hold_until_a_watched_key_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::CoordinatedDb::with_watched_prefixes(
            rocksdb::DB::open_default(dir.path()).unwrap(),
            vec![vec![0x40, 0x01]],
        );
        db.put([0x40, 0x01, 1], b"row").unwrap();
        let watched = db.lock_writes().unwrap().watched_write_sequence().unwrap();
        db.put([0x05], b"other").unwrap();
        let overlay = Arc::new(ExecutionOverlay::capture(db.clone(), limits()).unwrap());
        let point = quil_types::store::CapturePoint {
            database: db.instance(),
            sequence: db.latest_sequence_number(),
            watched,
        };
        let scan = quil_types::store::ScanPoint { database: db.instance(), from: point.sequence, to: point.sequence };
        assert_eq!(overlay.capture_point(), Some(point));
        overlay
            .apply(&[
                OverlayMutation::Put(vec![0x05], b"branch".to_vec()),
                OverlayMutation::DeleteRange(vec![0x30], vec![0x40, 0x01]),
            ])
            .unwrap();
        assert_eq!(overlay.capture_point(), Some(point), "writes outside the watched keys");
        let before = overlay.read_view().unwrap();
        assert_eq!(before.scan_point(), Some(scan));
        let generation = overlay.delta_generation();
        overlay.apply(&[OverlayMutation::Delete(vec![0x40, 0x01, 9])]).unwrap();
        assert_ne!(overlay.delta_generation(), generation);
        assert_eq!(overlay.capture_point(), None);
        assert_eq!(overlay.read_view().unwrap().scan_point(), None);
        assert_eq!(before.scan_point(), Some(scan), "an earlier view keeps its generation");
        let ranged = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
        ranged.apply(&[OverlayMutation::DeleteRange(vec![0x40], vec![0x40, 0x01, 0])]).unwrap();
        assert_eq!(ranged.capture_point(), None, "a range reaching the watched keys");
        drop(before);
        overlay.close();
        assert_eq!(overlay.capture_point(), None);

        let plain_dir = tempfile::tempdir().unwrap();
        let plain = ExecutionOverlay::capture(database(plain_dir.path()), limits()).unwrap();
        assert_eq!(plain.capture_point(), None);
    }

    #[test]
    fn mixed_writes_and_bidirectional_scans_match_independent_map() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        let mut expected = BTreeMap::new();
        for i in 0u16..128 {
            let key = i.to_be_bytes().to_vec();
            let value = vec![i as u8; 5];
            db.put(&key, &value).unwrap();
            expected.insert(key, value);
        }
        let overlay = ExecutionOverlay::capture(db.clone(), limits()).unwrap();
        let mut seed = 0x73656c6563746564u64;
        for i in 0..1500 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let k = ((seed % 128) as u16).to_be_bytes().to_vec();
            let mutation = match i % 3 {
                0 => {
                    let value = seed.to_be_bytes().to_vec();
                    expected.insert(k.clone(), value.clone());
                    OverlayMutation::Put(k.clone(), value)
                }
                1 => {
                    expected.remove(&k);
                    OverlayMutation::Delete(k.clone())
                }
                _ => {
                    let end = ((seed % 128 + (seed >> 8) % 17) as u16)
                        .to_be_bytes()
                        .to_vec();
                    expected.retain(|key, _| key < &k || key >= &end);
                    OverlayMutation::DeleteRange(k.clone(), end)
                }
            };
            overlay.apply(&[mutation]).unwrap();
            // These concurrent canonical changes must never leak into the branch.
            if i % 17 == 0 {
                db.put(&k, b"later canonical value").unwrap();
            }
            assert_eq!(overlay.get(&k).unwrap(), expected.get(&k).cloned());
            if i % 13 == 0 {
                assert_eq!(collect(&overlay, false), expected);
                assert_eq!(collect(&overlay, true), expected);
                let mut cursor = overlay.cursor(&[0, 0], &[1, 0]).unwrap();
                cursor.seek(&k).unwrap();
                assert_eq!(
                    cursor.key(),
                    expected
                        .range(k.clone()..)
                        .next()
                        .map(|(k, _)| k.as_slice())
                );
                cursor.seek_for_prev(&k).unwrap();
                assert_eq!(
                    cursor.key(),
                    expected.range(..=k).next_back().map(|(k, _)| k.as_slice())
                );
            }
        }
        assert_eq!(collect(&overlay, false), expected);
    }

    #[test]
    fn range_delete_jumps_over_base_and_later_put_overrides_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        let mut batch = rocksdb::WriteBatch::default();
        for k in 0u32..16_384 {
            batch.put(k.to_be_bytes(), b"base");
        }
        db.write(batch).unwrap();
        let overlay = ExecutionOverlay::capture(
            db.clone(),
            OverlayLimits {
                max_read_operations: 32,
                ..limits()
            },
        ).unwrap();
        overlay
            .apply(&[
                OverlayMutation::DeleteRange(
                    0u32.to_be_bytes().to_vec(),
                    16_383u32.to_be_bytes().to_vec(),
                ),
                OverlayMutation::Put(500u32.to_be_bytes().to_vec(), b"branch".to_vec()),
            ])
            .unwrap();
        let mut cursor = overlay
            .cursor(&0u32.to_be_bytes(), &16_384u32.to_be_bytes())
            .unwrap();
        cursor.seek(&[]).unwrap();
        assert_eq!(cursor.key(), Some(500u32.to_be_bytes().as_slice()));
        cursor.next().unwrap();
        assert_eq!(cursor.key(), Some(16_383u32.to_be_bytes().as_slice()));
        cursor.prev().unwrap();
        assert_eq!(cursor.key(), Some(500u32.to_be_bytes().as_slice()));
        cursor.prev().unwrap();
        assert!(!cursor.valid());
        assert!(overlay.stats().read_operations < 20);
        assert_eq!(
            db.get(500u32.to_be_bytes()).unwrap().as_deref(),
            Some(b"base".as_slice())
        );
    }

    #[test]
    fn cursors_keep_old_delta_and_close_releases_snapshot_with_live_cursors() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        db.put(b"a", b"base").unwrap();
        let overlay = ExecutionOverlay::capture(
            db.clone(),
            OverlayLimits {
                max_cursors: 1,
                ..limits()
            },
        ).unwrap();
        assert_eq!(
            db.property_int_value("rocksdb.num-snapshots").unwrap(),
            Some(1)
        );
        let mut old = overlay.cursor(b"a", b"z").unwrap();
        assert!(overlay.cursor(b"a", b"z").is_err());
        overlay
            .apply(&[OverlayMutation::Put(b"a".to_vec(), b"new".to_vec())])
            .unwrap();
        old.seek(b"a").unwrap();
        assert_eq!(old.value(), Some(b"base".as_slice()));
        assert_eq!(
            overlay.get(b"a").unwrap().as_deref(),
            Some(b"new".as_slice())
        );
        drop(db);
        assert!(rocksdb::DB::open_default(dir.path()).is_err(), "snapshot keeps the DB open");
        overlay.close();
        drop(rocksdb::DB::open_default(dir.path()).expect("close releases the DB even with a cursor"));
        assert!(old.seek(b"a").is_err());
        assert!(!old.valid(), "failed seek clears the earlier result");
        assert!(overlay.get(b"a").is_err());
        assert!(overlay.apply(&[]).is_err());
        drop(old);
        assert_eq!(overlay.stats().cursors, 0);
        let reopened = database(dir.path());
        assert_eq!(
            reopened.get(b"a").unwrap().as_deref(),
            Some(b"base".as_slice())
        );
    }

    #[test]
    fn failed_batch_is_atomic_for_points_ranges_and_budgets() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        db.put(b"b", b"base").unwrap();
        let overlay = ExecutionOverlay::capture(
            db,
            OverlayLimits {
                max_delta_bytes: 10,
                max_delta_entries: 2,
                max_record_bytes: 8,
                ..limits()
            },
        ).unwrap();
        overlay
            .apply(&[OverlayMutation::Put(b"a".to_vec(), b"old".to_vec())])
            .unwrap();
        for failure in [
            OverlayMutation::Put(b"z".to_vec(), vec![0; 8]), // record bound
            OverlayMutation::Put(b"zz".to_vec(), vec![0; 6]), // delta bytes
            OverlayMutation::DeleteRange(b"z".to_vec(), b"a".to_vec()),
        ] {
            assert!(overlay
                .apply(&[
                    OverlayMutation::DeleteRange(b"a".to_vec(), b"c".to_vec()),
                    OverlayMutation::Put(b"a".to_vec(), b"new".to_vec()),
                    failure,
                ])
                .is_err());
            assert_eq!(
                overlay.get(b"a").unwrap().as_deref(),
                Some(b"old".as_slice())
            );
            assert_eq!(
                overlay.get(b"b").unwrap().as_deref(),
                Some(b"base".as_slice())
            );
            assert_eq!(overlay.stats().delta_bytes, 4);
            assert_eq!(overlay.stats().delta_entries, 1);
        }
        assert!(overlay
            .apply(&[
                OverlayMutation::Delete(b"b".to_vec()),
                OverlayMutation::Delete(b"c".to_vec())
            ])
            .is_err());
        assert_eq!(overlay.stats().delta_entries, 1);
        overlay
            .apply(&[OverlayMutation::DeleteRange(b"a".to_vec(), b"z".to_vec())])
            .unwrap();
        assert_eq!(overlay.stats().delta_entries, 1);
        assert_eq!(overlay.stats().delta_bytes, 2);
        assert_eq!(overlay.get(b"b").unwrap(), None);
    }

    #[test]
    fn read_limits_cover_points_cursor_records_and_absent_lookups() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        db.put(b"a", b"value").unwrap();
        db.put(b"huge", [0; 1024]).unwrap();
        let overlay = ExecutionOverlay::capture(
            db.clone(),
            OverlayLimits {
                max_record_bytes: 32,
                ..limits()
            },
        ).unwrap();
        assert!(overlay.get(b"huge").is_err());
        let mut cursor = overlay.cursor(b"a", b"z").unwrap();
        cursor.seek(b"a").unwrap();
        assert!(cursor.next().is_err());
        assert!(!cursor.valid());
        assert_eq!(overlay.stats().read_bytes, 6);

        let overlay = ExecutionOverlay::capture(
            db.clone(),
            OverlayLimits {
                max_read_bytes: 6,
                ..limits()
            },
        ).unwrap();
        assert_eq!(overlay.get(b"a").unwrap(), Some(b"value".to_vec()));
        // The refusal says how far over the cap the branch went.
        assert_eq!(
            overlay.get(b"a").unwrap_err().to_string(),
            "overlay read byte limit: 6 bytes allowed, 12 read in 2 reads"
        );
        assert_eq!(overlay.stats().read_bytes, 6);
        let overlay = ExecutionOverlay::capture(
            db,
            OverlayLimits {
                max_read_operations: 1,
                ..limits()
            },
        ).unwrap();
        assert_eq!(overlay.get(b"absent").unwrap(), None);
        assert!(overlay.get(b"absent").is_err());
    }
}
