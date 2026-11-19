//! Background supply index maintained from committed snapshots.
//! The commit observer only queues vertex keys for this worker.

use std::cell::RefCell;
use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use quil_hypergraph::{shard_key_for_location, HypergraphCrdt, Location};
use quil_types::error::{QuilError, Result};
use quil_types::store::{
    HypergraphStore, KvDb, LocalVertexCommitObserver, RecordMutation, ShardKey, SnapshotReadable,
    VertexPageLimits,
};

const QUIL: [u8; 32] = quil_execution::domains::QUIL_TOKEN;
const GLOBAL: [u8; 32] = quil_execution::domains::GLOBAL;
const INDEX_PREFIX: &[u8] = &[quil_store::encoding::EXPLORER_SUPPLY, 1];
const INDEX_END: &[u8] = &[quil_store::encoding::EXPLORER_SUPPLY, 2];
const LEGACY_INDEX_PREFIX: &[u8] = b"\0explorer-supply-v1/";
// Exclusive prefix bound: advance the trailing '/' to '0'.
const LEGACY_INDEX_END: &[u8] = b"\0explorer-supply-v10";
// All mutations, including legacy cleanup, use the existing conflict ledger.
const INDEX_WRITE_PREFIXES: &[[u8; 2]] = &[[quil_store::encoding::EXPLORER_SUPPLY, 1], [0, b'e']];
const EVENT_KEYS_LIMIT: usize = 16_384;
const EVENT_QUEUE_LIMIT: usize = 256;
// At most 16 MiB of raw addresses, plus the set's allocation overhead.
const REBUILD_KEYS_LIMIT: usize = 262_144;
const LOST_EVENT_KEYS: u64 = 1;
const LOST_QUEUE_FULL: u64 = 2;
const LOST_DISCONNECTED: u64 = 4;
const LOST_SYNC: u64 = 8;
const LOST_UPDATE: u64 = 16;
const LOST_REBUILD_KEYS: u64 = 32;
const LOST_WORKER: u64 = 64;
static TOKEN_TYPES: OnceLock<(Option<[u8; 32]>, Option<[u8; 32]>)> = OnceLock::new();

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SupplyCounts {
    pub transparent_coins: u64,
    pub transparent_subunits: u128,
    pub reward_provers: u64,
    pub reward_subunits: u128,
    pub value_hidden_coins: u64,
    pub scanned: usize,
}

impl SupplyCounts {
    fn change(&mut self, old: Option<Contribution>, new: Option<Contribution>) {
        if let Some(old) = old {
            self.scanned = self.scanned.saturating_sub(1);
            match old {
                Contribution::Other => {}
                Contribution::Transparent(amount) => {
                    self.transparent_coins = self.transparent_coins.saturating_sub(1);
                    self.transparent_subunits = self.transparent_subunits.saturating_sub(amount);
                }
                Contribution::Hidden => {
                    self.value_hidden_coins = self.value_hidden_coins.saturating_sub(1);
                }
                Contribution::Reward(amount) => {
                    self.reward_provers = self.reward_provers.saturating_sub(1);
                    self.reward_subunits = self.reward_subunits.saturating_sub(amount);
                }
            }
        }
        if let Some(new) = new {
            self.scanned = self.scanned.saturating_add(1);
            match new {
                Contribution::Other => {}
                Contribution::Transparent(amount) => {
                    self.transparent_coins = self.transparent_coins.saturating_add(1);
                    self.transparent_subunits = self.transparent_subunits.saturating_add(amount);
                }
                Contribution::Hidden => {
                    self.value_hidden_coins = self.value_hidden_coins.saturating_add(1);
                }
                Contribution::Reward(amount) => {
                    self.reward_provers = self.reward_provers.saturating_add(1);
                    self.reward_subunits = self.reward_subunits.saturating_add(amount);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Contribution {
    Other,
    Transparent(u128),
    Hidden,
    Reward(u128),
}

impl Contribution {
    fn encode(self) -> Vec<u8> {
        match self {
            Self::Other => vec![0],
            Self::Transparent(amount) => {
                let mut bytes = vec![1];
                bytes.extend_from_slice(&amount.to_le_bytes());
                bytes
            }
            Self::Hidden => vec![2],
            Self::Reward(amount) => {
                let mut bytes = vec![3];
                bytes.extend_from_slice(&amount.to_le_bytes());
                bytes
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes {
            [0] => Ok(Self::Other),
            [2] => Ok(Self::Hidden),
            [1, amount @ ..] if amount.len() == 16 => Ok(Self::Transparent(u128::from_le_bytes(
                amount.try_into().unwrap(),
            ))),
            [3, amount @ ..] if amount.len() == 16 => Ok(Self::Reward(u128::from_le_bytes(
                amount.try_into().unwrap(),
            ))),
            _ => Err(QuilError::Store(
                "invalid explorer supply index entry".into(),
            )),
        }
    }
}

struct Event {
    sequence: u64,
    keys: Vec<[u8; 64]>,
}

#[derive(Default)]
struct RebuildProgress {
    at_snapshot: u64,
    pending: BTreeSet<[u8; 64]>,
    vertices: usize,
    writes: usize,
    deletes: usize,
}

#[derive(Default)]
struct RebuildBackoff {
    last_finished: Option<Instant>,
    retries: u32,
}

impl RebuildBackoff {
    fn delay(&mut self, now: Instant) -> Duration {
        let Some(last_finished) = self.last_finished else {
            return Duration::ZERO;
        };
        if now.duration_since(last_finished) >= Duration::from_secs(120) {
            self.retries = 0;
            return Duration::ZERO;
        }
        self.retries = (self.retries + 1).min(6);
        Duration::from_secs((1u64 << self.retries).min(60))
    }

    fn finished(&mut self, now: Instant) {
        self.last_finished = Some(now);
    }
}

pub struct SupplyIndex {
    counts: RwLock<Option<SupplyCounts>>,
    lost: AtomicBool,
    lost_reasons: AtomicU64,
    sequence: AtomicU64,
    sender: SyncSender<Event>,
    pub(crate) scan_gate: Arc<tokio::sync::Semaphore>,
}

impl SupplyIndex {
    pub fn start(
        crdt: Arc<HypergraphCrdt>,
        _store: Arc<dyn HypergraphStore>,
        db: Arc<dyn KvDb>,
    ) -> (Arc<Self>, SupplyIndexRunner) {
        let (sender, receiver) = mpsc::sync_channel(EVENT_QUEUE_LIMIT);
        let index = Arc::new(Self {
            counts: RwLock::new(None),
            lost: AtomicBool::new(false),
            lost_reasons: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
            sender,
            scan_gate: Arc::new(tokio::sync::Semaphore::new(1)),
        });
        crdt.add_local_vertex_observer(index.clone());
        (
            index.clone(),
            SupplyIndexRunner {
                crdt,
                db,
                index,
                receiver,
                deferred: RefCell::new(None),
                #[cfg(test)]
                page_hook: None,
                #[cfg(test)]
                after_update_hook: None,
                #[cfg(test)]
                replay_capture_hook: None,
            },
        )
    }

    pub(crate) fn read(&self) -> Option<SupplyCounts> {
        let counts = self.counts.read();
        if self.lost.load(Ordering::Acquire) {
            None
        } else {
            *counts
        }
    }

    fn mark_lost(&self, reason: u64) {
        // Record loss atomically; the worker logs the cause and read() withholds counts.
        self.lost_reasons.fetch_or(reason, Ordering::AcqRel);
        self.lost.store(true, Ordering::Release);
    }

    fn log_invalidations(&self) {
        let reasons = self.lost_reasons.swap(0, Ordering::AcqRel);
        for (flag, reason) in [
            (LOST_EVENT_KEYS, "commit_key_limit"),
            (LOST_QUEUE_FULL, "commit_queue_full"),
            (LOST_DISCONNECTED, "commit_queue_disconnected"),
            (LOST_SYNC, "canonical_sync"),
            (LOST_UPDATE, "index_update_error"),
            (LOST_REBUILD_KEYS, "rebuild_key_limit"),
            (LOST_WORKER, "worker_stopped"),
        ] {
            if reasons & flag != 0 {
                tracing::warn!(reason, "explorer supply index invalidated");
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn ready_for_test(counts: SupplyCounts) -> Arc<Self> {
        let (sender, _receiver) = mpsc::sync_channel(1);
        Arc::new(Self {
            counts: RwLock::new(Some(counts)),
            lost: AtomicBool::new(false),
            lost_reasons: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
            sender,
            scan_gate: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }
}

impl LocalVertexCommitObserver for SupplyIndex {
    fn committed<'a>(&self, vertices: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>) {
        self.enqueue(&mut vertices.map(|(key, _)| key));
    }

    fn removed<'a>(&self, keys: &mut dyn Iterator<Item = &'a [u8]>) {
        self.enqueue(keys);
    }

    fn execution_key_domains(&self) -> &'static [[u8; 32]] {
        &[QUIL, GLOBAL]
    }

    fn committed_keys(&self, mut keys: Vec<[u8; 64]>) {
        if self.lost.load(Ordering::Acquire) {
            return;
        }
        keys.retain(|key| key[..32] == QUIL || key[..32] == GLOBAL);
        self.enqueue_owned(keys);
    }

    fn watches_sync(&self, app: &[u8]) -> bool {
        app.len() >= 32 && (app[..32] == QUIL || app[..32] == GLOBAL)
    }

    fn invalidated(&self) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.mark_lost(LOST_SYNC);
    }
}

impl SupplyIndex {
    fn enqueue<'a>(&self, vertices: &mut dyn Iterator<Item = &'a [u8]>) {
        if self.lost.load(Ordering::Acquire) {
            return;
        }
        let mut keys = Vec::new();
        for key in vertices {
            if key.len() != 64 || (key[..32] != QUIL && key[..32] != GLOBAL) {
                continue;
            }
            let mut id = [0u8; 64];
            id.copy_from_slice(key);
            keys.push(id);
            if keys.len() > EVENT_KEYS_LIMIT {
                self.sequence.fetch_add(1, Ordering::AcqRel);
                self.mark_lost(LOST_EVENT_KEYS);
                return;
            }
        }
        self.enqueue_owned(keys);
    }

    fn enqueue_owned(&self, keys: Vec<[u8; 64]>) {
        if self.lost.load(Ordering::Acquire) || keys.is_empty() {
            return;
        }
        if keys.len() > EVENT_KEYS_LIMIT {
            self.sequence.fetch_add(1, Ordering::AcqRel);
            self.mark_lost(LOST_EVENT_KEYS);
            return;
        }
        let sequence = self.sequence.fetch_add(1, Ordering::AcqRel) + 1;
        match self.sender.try_send(Event { sequence, keys }) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => self.mark_lost(LOST_QUEUE_FULL),
            Err(mpsc::TrySendError::Disconnected(_)) => self.mark_lost(LOST_DISCONNECTED),
        }
    }
}

pub struct SupplyIndexRunner {
    crdt: Arc<HypergraphCrdt>,
    db: Arc<dyn KvDb>,
    index: Arc<SupplyIndex>,
    receiver: Receiver<Event>,
    // One event newer than a retained read point. Only the blocking worker
    // consumes events; Receiver already makes this runner non-Sync.
    deferred: RefCell<Option<Event>>,
    #[cfg(test)]
    page_hook: Option<Box<dyn Fn() + Send>>,
    #[cfg(test)]
    after_update_hook: Option<Box<dyn Fn() + Send>>,
    #[cfg(test)]
    replay_capture_hook: Option<Box<dyn Fn() + Send>>,
}

/// Bounded key-only merge cursor. Canonical pages visit ids in the same order
/// as these cache keys, so stale cleanup needs no second vertex payload scan.
struct IndexKeys {
    lower: Vec<u8>,
    page: VecDeque<Vec<u8>>,
    exhausted: bool,
}

impl IndexKeys {
    fn new() -> Self {
        Self {
            lower: INDEX_PREFIX.to_vec(),
            page: VecDeque::new(),
            exhausted: false,
        }
    }

    fn peek(&mut self, db: &dyn KvDb) -> Result<Option<&[u8]>> {
        if self.page.is_empty() && !self.exhausted {
            self.page = db.key_page(&self.lower, INDEX_END, 256)?.into();
            self.exhausted = self.page.len() < 256;
            if let Some(last) = self.page.back() {
                self.lower = last.clone();
                self.lower.push(0);
            }
        }
        Ok(self.page.front().map(Vec::as_slice))
    }
}

impl SupplyIndexRunner {
    /// Run on a blocking worker. A failed or missed notification discards the
    /// summary; the next pass rebuilds it from a fresh committed snapshot.
    pub fn run(self, stop: &AtomicBool) {
        // Covers normal stop and unwinding: a dead optional worker must never
        // leave its last summary readable indefinitely.
        struct Availability(Arc<SupplyIndex>);
        impl Drop for Availability {
            fn drop(&mut self) {
                self.0.mark_lost(LOST_WORKER);
            }
        }
        let _availability = Availability(self.index.clone());
        let mut counts = None;
        let mut backoff = RebuildBackoff::default();
        while !stop.load(Ordering::Acquire) {
            if counts.is_none() || self.index.lost.load(Ordering::Acquire) {
                self.index.log_invalidations();
                let delay = backoff.delay(Instant::now());
                let deadline = Instant::now() + delay;
                while Instant::now() < deadline {
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::sleep(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_secs(1)),
                    );
                }
                counts = None;
                self.deferred.borrow_mut().take();
                // These notifications precede the fresh snapshot. Retire them
                // before reenabling collection so a stale full queue cannot
                // immediately invalidate the next rebuild.
                for _ in 0..EVENT_QUEUE_LIMIT {
                    if self.receiver.try_recv().is_err() {
                        break;
                    }
                }
                *self.index.counts.write() = None;
                // mark_lost is lock-free and leaves the old counts in place.
                // Clear them before reopening reads/notification collection.
                self.index.lost.store(false, Ordering::Release);
                let rebuilt = self.rebuild(stop);
                backoff.finished(Instant::now());
                match rebuilt {
                    Ok(Some(rebuilt)) => {
                        counts = Some(rebuilt);
                        tracing::info!("explorer supply index ready");
                    }
                    Ok(None) => continue,
                    Err(error) => {
                        tracing::warn!(%error, "explorer supply index rebuild failed");
                        continue;
                    }
                }
            }
            match self.next_event() {
                Ok(event) => {
                    if let Some(current) = counts.as_mut() {
                        let mut pending = BTreeSet::new();
                        match self.replay_at_snapshot(Some(event), &mut pending, current, stop) {
                            Err(error) => {
                                tracing::warn!(%error, "explorer supply index update failed");
                                self.index.mark_lost(LOST_UPDATE);
                                counts = None;
                            }
                            Ok(false) => counts = None,
                            Ok(true) => {
                                let mut published = self.index.counts.write();
                                if !self.index.lost.load(Ordering::Acquire) {
                                    *published = Some(*current);
                                }
                                drop(published);
                                #[cfg(test)]
                                if let Some(hook) = &self.after_update_hook {
                                    hook();
                                }
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    fn rebuild(&self, stop: &AtomicBool) -> Result<Option<SupplyCounts>> {
        // Share the existing full-scan permit with HTTP. Bootstrap and fallback
        // must not each walk the archive concurrently.
        let Ok(_scan) = self.index.scan_gate.try_acquire() else {
            return Ok(None);
        };
        let started = Instant::now();
        let mut progress = RebuildProgress::default();
        let result = self.rebuild_inner(stop, &mut progress);
        self.index.log_invalidations();
        tracing::info!(
            duration_ms = started.elapsed().as_millis() as u64,
            vertices = progress.vertices,
            writes = progress.writes,
            deletes = progress.deletes,
            ready = matches!(&result, Ok(Some(_))),
            cancelled = stop.load(Ordering::Acquire),
            "explorer supply index rebuild finished"
        );
        result
    }

    fn rebuild_inner(
        &self,
        stop: &AtomicBool,
        progress: &mut RebuildProgress,
    ) -> Result<Option<SupplyCounts>> {
        // The snapshot and notification sequence must describe the same
        // committed point; later notifications are replayed after the scan.
        let (snapshot, at_snapshot) = self.index_snapshot()?;
        require_vertex_snapshot(snapshot.as_ref())?;
        progress.at_snapshot = at_snapshot;
        // Index records are not part of the canonical transaction. Reconcile
        // them from canonical state after a restart or missed notification.
        let mut lower = LEGACY_INDEX_PREFIX.to_vec();
        while self.collect_changes(progress, stop) {
            let keys = self.db.key_page(&lower, LEGACY_INDEX_END, 256)?;
            let Some(last) = keys.last() else {
                break;
            };
            lower = last.clone();
            lower.push(0);
            let deletes: Vec<_> = keys
                .into_iter()
                .map(|key| RecordMutation { key, value: None })
                .collect();
            self.db.write_disjoint(INDEX_WRITE_PREFIXES, &deletes)?;
            progress.deletes += deletes.len();
        }
        let mut counts = SupplyCounts::default();
        let mut indexed = IndexKeys::new();
        let mut domains = [QUIL, GLOBAL];
        domains.sort();
        for domain in domains {
            self.scan_domain(
                snapshot.as_ref(),
                &domain,
                &mut counts,
                stop,
                progress,
                &mut indexed,
            )?;
        }
        self.prune_before(&mut indexed, None, stop, progress)?;
        drop(snapshot);
        if stop.load(Ordering::Acquire) || self.index.lost.load(Ordering::Acquire) {
            return Ok(None);
        }
        if !self.replay_at_snapshot(None, &mut progress.pending, &mut counts, stop)? {
            return Ok(None);
        }
        let mut published = self.index.counts.write();
        if self.index.lost.load(Ordering::Acquire) {
            return Ok(None);
        }
        *published = Some(counts);
        Ok(Some(counts))
    }

    fn collect_changes(&self, progress: &mut RebuildProgress, stop: &AtomicBool) -> bool {
        if stop.load(Ordering::Acquire) || self.index.lost.load(Ordering::Acquire) {
            return false;
        }
        // Bounded even when producers keep sending concurrently.
        for _ in 0..EVENT_QUEUE_LIMIT {
            let Ok(event) = self.receiver.try_recv() else {
                break;
            };
            if event.sequence <= progress.at_snapshot {
                continue;
            }
            for key in event.keys {
                if !progress.pending.contains(&key) && progress.pending.len() == REBUILD_KEYS_LIMIT
                {
                    self.index.mark_lost(LOST_REBUILD_KEYS);
                    return false;
                }
                progress.pending.insert(key);
            }
        }
        !stop.load(Ordering::Acquire) && !self.index.lost.load(Ordering::Acquire)
    }

    fn scan_domain(
        &self,
        snapshot: &dyn SnapshotReadable,
        domain: &[u8; 32],
        counts: &mut SupplyCounts,
        stop: &AtomicBool,
        progress: &mut RebuildProgress,
        indexed: &mut IndexKeys,
    ) -> Result<()> {
        if !self.collect_changes(progress, stop) {
            return Ok(());
        }
        scan_pages(snapshot, domain, |entries| {
            let mut mutations = Vec::new();
            for (id, value) in entries {
                let key = index_key(id);
                if !self.prune_before(indexed, Some(&key), stop, progress)? {
                    return Ok(false);
                }
                if indexed.peek(self.db.as_ref())? == Some(key.as_slice()) {
                    indexed.page.pop_front();
                }
                let encoded = value.encode();
                if self.db.get(&key)?.as_deref() != Some(encoded.as_slice()) {
                    mutations.push(RecordMutation {
                        key,
                        value: Some(encoded),
                    });
                    progress.writes += 1;
                }
                counts.change(None, Some(*value));
                progress.vertices += 1;
            }
            self.db.write_disjoint(INDEX_WRITE_PREFIXES, &mutations)?;
            #[cfg(test)]
            if let Some(hook) = &self.page_hook {
                hook();
            }
            Ok(self.collect_changes(progress, stop))
        })
    }

    fn prune_before(
        &self,
        indexed: &mut IndexKeys,
        before: Option<&[u8]>,
        stop: &AtomicBool,
        progress: &mut RebuildProgress,
    ) -> Result<bool> {
        let mut deletes = Vec::new();
        loop {
            let stale = indexed
                .peek(self.db.as_ref())?
                .is_some_and(|key| before.is_none_or(|end| key < end));
            if !stale {
                break;
            }
            deletes.push(RecordMutation {
                key: indexed.page.pop_front().unwrap(),
                value: None,
            });
            if deletes.len() == 256 {
                self.db.write_disjoint(INDEX_WRITE_PREFIXES, &deletes)?;
                progress.deletes += deletes.len();
                deletes.clear();
                if !self.collect_changes(progress, stop) {
                    return Ok(false);
                }
            }
        }
        self.db.write_disjoint(INDEX_WRITE_PREFIXES, &deletes)?;
        progress.deletes += deletes.len();
        Ok(self.collect_changes(progress, stop))
    }

    fn next_event(&self) -> std::result::Result<Event, mpsc::RecvTimeoutError> {
        if let Some(event) = self.deferred.borrow_mut().take() {
            return Ok(event);
        }
        self.receiver.recv_timeout(Duration::from_secs(1))
    }

    fn index_snapshot(&self) -> Result<(Arc<dyn SnapshotReadable>, u64)> {
        self.crdt
            .capture_fresh_committed_snapshot_with(|| self.index.sequence.load(Ordering::Acquire))
    }

    fn retain_keys(&self, event: Event, pending: &mut BTreeSet<[u8; 64]>) -> bool {
        for key in event.keys {
            if !pending.contains(&key) && pending.len() == REBUILD_KEYS_LIMIT {
                self.index.mark_lost(LOST_REBUILD_KEYS);
                return false;
            }
            pending.insert(key);
        }
        true
    }

    /// Publish an aggregate at one captured canonical point. Reading each
    /// queued event against a different latest snapshot can combine balances
    /// that never existed together, even when every notification arrives.
    fn replay_at_snapshot(
        &self,
        first: Option<Event>,
        pending: &mut BTreeSet<[u8; 64]>,
        counts: &mut SupplyCounts,
        stop: &AtomicBool,
    ) -> Result<bool> {
        let (snapshot, through) = self.index_snapshot()?;
        require_vertex_snapshot(snapshot.as_ref())?;
        #[cfg(test)]
        if let Some(hook) = &self.replay_capture_hook {
            hook();
        }
        if let Some(event) = first {
            if !self.retain_keys(event, pending) {
                return Ok(false);
            }
        }
        // Every notification through this point was enqueued before capture
        // released its barriers. The bounded queue holds at most this many;
        // later commits stay queued (or one event is deferred) for the next pass.
        for _ in 0..=EVENT_QUEUE_LIMIT {
            let event = self
                .deferred
                .borrow_mut()
                .take()
                .or_else(|| self.receiver.try_recv().ok());
            let Some(event) = event else {
                break;
            };
            if event.sequence > through {
                *self.deferred.borrow_mut() = Some(event);
                break;
            }
            if !self.retain_keys(event, pending) {
                return Ok(false);
            }
        }
        while !pending.is_empty() {
            if stop.load(Ordering::Acquire) || self.index.lost.load(Ordering::Acquire) {
                return Ok(false);
            }
            let keys: Vec<_> = (0..EVENT_KEYS_LIMIT)
                .filter_map(|_| pending.pop_first())
                .collect();
            self.apply_snapshot_keys(snapshot.as_ref(), &keys, counts)?;
        }
        Ok(!stop.load(Ordering::Acquire) && !self.index.lost.load(Ordering::Acquire))
    }

    #[cfg(test)]
    fn apply_keys(&self, keys: &[[u8; 64]], counts: &mut SupplyCounts) -> Result<()> {
        let snapshot = self.crdt.capture_fresh_committed_snapshot()?;
        require_vertex_snapshot(snapshot.as_ref())?;
        self.apply_snapshot_keys(snapshot.as_ref(), keys, counts)
    }

    fn apply_snapshot_keys(
        &self,
        snapshot: &dyn SnapshotReadable,
        keys: &[[u8; 64]],
        counts: &mut SupplyCounts,
    ) -> Result<()> {
        let mut mutations = Vec::new();
        let mut next = *counts;
        let mut seen = std::collections::HashSet::new();
        for key in keys {
            if !seen.insert(*key) {
                continue;
            }
            let indexed = index_key(key);
            let old = self
                .db
                .get(&indexed)?
                .map(|bytes| Contribution::decode(&bytes))
                .transpose()?;
            let domain = &key[..32];
            let shard = shard_key_for_location(&Location {
                app_address: domain.try_into().unwrap(),
                data_address: [0; 32],
            });
            let new = snapshot
                .load_vertex_underlying_raw("vertex", "adds", &shard, key)?
                .map(|blob| classify_snapshot(snapshot, &shard, key, &blob))
                .transpose()?;
            if old == new {
                continue;
            }
            next.change(old, new);
            mutations.push(RecordMutation {
                key: indexed,
                value: new.map(Contribution::encode),
            });
        }
        self.db.write_disjoint(INDEX_WRITE_PREFIXES, &mutations)?;
        *counts = next;
        Ok(())
    }
}

fn require_vertex_snapshot(snapshot: &dyn SnapshotReadable) -> Result<()> {
    if !snapshot.has_snapshot_vertex_reads() {
        return Err(QuilError::ExecutionUnavailable(
            "supply scan requires isolated vertex reads".into(),
        ));
    }
    for domain in [QUIL, GLOBAL] {
        if quil_hypergraph::crdt::snapshot_sync_incomplete(snapshot, &domain)? {
            return Err(QuilError::ExecutionUnavailable(
                "supply state sync is incomplete".into(),
            ));
        }
    }
    Ok(())
}

fn classify_snapshot(
    snapshot: &dyn SnapshotReadable,
    shard: &ShardKey,
    id: &[u8; 64],
    blob: &[u8],
) -> Result<Contribution> {
    // Keep the raw adds-row count, but a tombstone never contributes supply.
    if snapshot
        .load_vertex_underlying_raw("vertex", "removes", shard, id)?
        .is_some()
    {
        Ok(Contribution::Other)
    } else {
        Ok(classify(id, blob))
    }
}

fn scan_pages(
    snapshot: &dyn SnapshotReadable,
    domain: &[u8; 32],
    mut visit: impl FnMut(&[([u8; 64], Contribution)]) -> Result<bool>,
) -> Result<()> {
    require_vertex_snapshot(snapshot)?;
    let shard = shard_key_for_location(&Location {
        app_address: *domain,
        data_address: [0; 32],
    });
    let mut after = None;
    loop {
        let page = snapshot.page_vertex_underlying_fixed_for_scan(
            "vertex",
            "adds",
            &shard,
            domain,
            after.as_ref(),
            VertexPageLimits {
                max_entries: 256,
                max_bytes: 64 * 1024 * 1024,
            },
        )?;
        let mut entries = Vec::with_capacity(page.entries.len());
        for (address, blob) in &page.entries {
            let mut id = [0; 64];
            id[..32].copy_from_slice(domain);
            id[32..].copy_from_slice(address);
            entries.push((id, classify_snapshot(snapshot, &shard, &id, blob)?));
        }
        if !visit(&entries)? || !page.has_more {
            return Ok(());
        }
        after = page.entries.last().map(|(address, _)| *address);
        if after.is_none() {
            return Err(QuilError::Store("supply page made no progress".into()));
        }
    }
}

/// Scan both supply domains from one committed snapshot using the index's
/// classification. Read failures must not become partial supply.
pub(crate) fn scan_supply(crdt: &HypergraphCrdt) -> Result<SupplyCounts> {
    let snapshot = crdt.capture_fresh_committed_snapshot()?;
    let mut counts = SupplyCounts::default();
    for domain in [QUIL, GLOBAL] {
        scan_pages(snapshot.as_ref(), &domain, |entries| {
            for (_, value) in entries {
                counts.change(None, Some(*value));
            }
            Ok(true)
        })?;
    }
    Ok(counts)
}

fn index_key(key: &[u8; 64]) -> Vec<u8> {
    let mut index = Vec::with_capacity(INDEX_PREFIX.len() + key.len());
    index.extend_from_slice(INDEX_PREFIX);
    index.extend_from_slice(key);
    index
}

fn classify(key: &[u8; 64], blob: &[u8]) -> Contribution {
    if key[..32] == QUIL {
        if crate::handlers::is_reserved_token_addr(&key[32..]) {
            return Contribution::Other;
        }
        let root = quil_tries::deserialize_go_tree(blob).ok().flatten();
        let tree = quil_tries::VectorCommitmentTree { root };
        let (transparent, private) = TOKEN_TYPES.get_or_init(|| {
            (
                quil_execution::token_intrinsic::legacy_migration::transparent_type_hash(&QUIL)
                    .ok(),
                quil_execution::token_intrinsic::materialize::coin_type_hash(&QUIL).ok(),
            )
        });
        match tree.get(&[0xff; 32]) {
            Some(ty)
                if transparent
                    .as_ref()
                    .is_some_and(|hash| ty == hash.as_slice()) =>
            {
                let Some(amount) = tree.get(&[4]) else {
                    return Contribution::Other;
                };
                let mut bytes = [0u8; 16];
                let n = amount.len().min(16);
                bytes[..n].copy_from_slice(&amount[..n]);
                Contribution::Transparent(u128::from_le_bytes(bytes))
            }
            Some(ty) if private.as_ref().is_some_and(|hash| ty == hash.as_slice()) => {
                Contribution::Hidden
            }
            _ => Contribution::Other,
        }
    } else if key[..32] == GLOBAL {
        let tree = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(blob);
        if quil_execution::global_schema::read_type(&tree) != Some("reward:ProverReward") {
            return Contribution::Other;
        }
        let balance = quil_execution::global_intrinsic::materialize::read_reward_balance(&tree);
        let amount = crate::handlers::be_bytes_to_u128(&balance);
        if amount == 0 {
            Contribution::Other
        } else {
            Contribution::Reward(amount)
        }
    } else {
        Contribution::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Query, State};
    use axum::http::Method;
    use quil_execution::token_intrinsic::legacy_migration::{
        create_transparent_coin_tree, transparent_type_hash, TransparentCoin,
    };
    use std::collections::HashMap;

    #[test]
    fn queued_reward_commits_publish_one_coherent_snapshot() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        add_reward(&crdt, 1, 100);
        add_reward(&crdt, 2, 100);
        crdt.commit(1).unwrap();
        let (index, mut runner) = SupplyIndex::start(crdt.clone(), store, db);
        let (observed_tx, observed_rx) = mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = mpsc::sync_channel(1);
        runner.after_update_hook = Some(Box::new({
            let index = index.clone();
            move || {
                observed_tx.send(index.read().unwrap()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(30)).unwrap();
            }
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || runner.run(&worker_stop));
        wait_until(&index, |counts| counts.reward_subunits == 200);
        // The worker receives event 1 but must wait until both commits have
        // become visible. Its first published update must cover both keys.
        {
            let _guard = crdt.lock_forest_writes();
            add_reward(&crdt, 1, 200);
            crdt.commit(2).unwrap(); // canonical total 300
            add_reward(&crdt, 1, 300);
            add_reward(&crdt, 2, 200);
            crdt.commit(3).unwrap(); // canonical total 500
        }
        let observed = observed_rx.recv_timeout(Duration::from_secs(30));
        stop.store(true, Ordering::Release);
        let _ = resume_tx.send(());
        worker.join().unwrap();
        assert_eq!(
            observed.unwrap().reward_subunits,
            500,
            "published a mixed total that never existed canonically"
        );
    }

    #[test]
    fn replay_preserves_future_events_and_drains_a_full_queue() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        add_reward(&crdt, 1, 100);
        add_reward(&crdt, 2, 100);
        crdt.commit(1).unwrap();
        let (index, mut runner) = SupplyIndex::start(crdt.clone(), store, db);
        let stop = AtomicBool::new(false);
        let mut counts = runner.rebuild(&stop).unwrap().unwrap();
        add_reward(&crdt, 1, 200);
        crdt.commit(2).unwrap();
        let first = runner.receiver.try_recv().unwrap();
        runner.replay_capture_hook = Some(Box::new({
            let crdt = crdt.clone();
            let once = AtomicBool::new(false);
            move || {
                if !once.swap(true, Ordering::AcqRel) {
                    add_reward(&crdt, 1, 300);
                    add_reward(&crdt, 2, 200);
                    crdt.commit(3).unwrap();
                }
            }
        }));
        assert!(runner
            .replay_at_snapshot(Some(first), &mut BTreeSet::new(), &mut counts, &stop)
            .unwrap());
        assert_eq!(
            counts.reward_subunits, 300,
            "later keys leaked into an older read point"
        );
        assert!(runner.deferred.borrow().is_some());
        // A saved future event plus a completely full queue must still be
        // processed through the captured point, including the changed B key.
        for number in 0..EVENT_QUEUE_LIMIT {
            add_reward(&crdt, 1, 1000 + number as u64);
            crdt.commit(4 + number as u64).unwrap();
        }
        assert!(!index.lost.load(Ordering::Acquire));
        assert!(runner
            .replay_at_snapshot(None, &mut BTreeSet::new(), &mut counts, &stop)
            .unwrap());
        assert_eq!(counts.reward_subunits, 1455);
        assert_eq!(counts, scan_supply(&crdt).unwrap());
        assert!(runner.deferred.borrow().is_none());
        assert!(runner.receiver.try_recv().is_err());
    }

    fn publication_branch(db: quil_forest::CoordinatedDb) -> quil_forest::ExecutionOverlay {
        quil_forest::ExecutionOverlay::capture(
            db,
            quil_forest::OverlayLimits {
                max_delta_bytes: 1 << 20,
                max_delta_entries: 10_000,
                max_record_bytes: 1 << 16,
                max_read_bytes: 1 << 20,
                max_read_operations: 100_000,
                max_cursors: 8,
            },
        )
        .unwrap()
    }

    #[test]
    fn stopped_worker_withholds_its_last_summary() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> = Arc::new(quil_store::RocksHypergraphStore::new(raw));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        let (index, runner) = SupplyIndex::start(crdt, store, db);
        *index.counts.write() = Some(SupplyCounts::default());
        assert!(index.read().is_some());
        runner.run(&AtomicBool::new(true));
        assert!(index.read().is_none());
        assert_eq!(index.lost_reasons.load(Ordering::Acquire), LOST_WORKER);
    }

    #[test]
    fn atomic_adoption_updates_supply_without_exposing_private_state() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw.clone(),
            quil_store::FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(true);
        for domain in [QUIL, GLOBAL] {
            crdt.set_app_shard_prefixes(domain, vec![vec![]]);
        }
        crdt.warm_sizes(&[QUIL, GLOBAL]).unwrap();
        add_coin(&crdt, 1, 7);
        add_reward(&crdt, 2, 8);
        crdt.commit(1).unwrap();
        let (index, runner) = SupplyIndex::start(crdt.clone(), store, db);
        let mut counts = runner.rebuild(&AtomicBool::new(false)).unwrap().unwrap();
        let sequence = index.sequence.load(Ordering::Acquire);
        let limits = quil_hypergraph::ExecutionForkLimits {
            overlay: quil_forest::OverlayLimits {
                max_delta_bytes: 16 << 20,
                max_delta_entries: 100_000,
                max_record_bytes: 2 << 20,
                max_read_bytes: 128 << 20,
                max_read_operations: 100_000,
                max_cursors: 32,
            },
            max_metadata_entries: 100_000,
            max_metadata_bytes: 16 << 20,
        };
        let record_store = |overlay| -> Result<Arc<dyn HypergraphStore>> {
            Ok(Arc::new(quil_store::OverlayHypergraphStore::new(overlay)))
        };
        let branch = crdt
            .lock_execution_capture()
            .unwrap()
            .fork(limits, record_store)
            .unwrap();
        add_reward(&branch.crdt, 2, 42);
        branch
            .crdt
            .remove_vertex(&Location {
                app_address: QUIL,
                data_address: [1; 32],
            })
            .unwrap();
        branch.crdt.commit(2).unwrap();
        assert_eq!(index.sequence.load(Ordering::Acquire), sequence);
        assert_eq!(scan_supply(&crdt).unwrap(), counts);
        {
            let capture = crdt.lock_execution_capture().unwrap();
            let mut adoption = capture
                .prepare_adoption(&branch.crdt, &branch.overlay, limits, record_store)
                .unwrap();
            let plan = branch.overlay.prepare_commit().unwrap();
            let mut write = raw.lock_writes().unwrap();
            plan.commit_locked(&mut write).unwrap();
            adoption.adopt();
        }
        assert!(index.sequence.load(Ordering::Acquire) > sequence);
        assert!(
            !index.lost.load(Ordering::Acquire),
            "normal atomic publication must update incrementally"
        );
        for event in runner.receiver.try_iter() {
            runner.apply_keys(&event.keys, &mut counts).unwrap();
        }
        assert_eq!(counts.transparent_subunits, 0);
        assert_eq!(counts.reward_subunits, 42);
        assert_eq!(counts, scan_supply(&crdt).unwrap());
    }

    #[test]
    fn reset_removes_indexed_rewards_and_bootstrap_shares_full_scan_permit() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        add_reward(&crdt, 1, 42);
        crdt.commit(1).unwrap();
        let (index, runner) = SupplyIndex::start(crdt.clone(), store.clone(), db);
        let permit = index.scan_gate.try_acquire().unwrap();
        assert!(runner.rebuild(&AtomicBool::new(false)).unwrap().is_none());
        drop(permit);
        assert_eq!(
            runner
                .rebuild(&AtomicBool::new(false))
                .unwrap()
                .unwrap()
                .reward_subunits,
            42
        );
        {
            let guard = crdt.lock_forest_writes();
            let shard = shard_key_for_location(&Location {
                app_address: GLOBAL,
                data_address: [0; 32],
            });
            crdt.reset_shard_forest_trees_with_guard(&guard, &GLOBAL)
                .unwrap();
            store.clear_shard_underlying(&shard).unwrap();
            crdt.invalidate_local_vertex_observer_for_app(&GLOBAL);
        }
        assert!(index.read().is_none());
        let counts = runner.rebuild(&AtomicBool::new(false)).unwrap();
        assert!(
            counts.is_none(),
            "invalidated rebuild must not publish until worker starts a fresh pass"
        );
        index.lost.store(false, Ordering::Release);
        let counts = runner.rebuild(&AtomicBool::new(false)).unwrap().unwrap();
        assert_eq!(counts.reward_provers, 0);
        assert_eq!(counts.reward_subunits, 0);
        assert_eq!(counts, scan_supply(&crdt).unwrap());
    }

    #[test]
    fn partial_sync_never_publishes_a_plausible_supply_total() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        add_reward(&crdt, 1, 42);
        crdt.commit(1).unwrap();
        let (_, runner) = SupplyIndex::start(crdt.clone(), store, db.clone());
        for domain in [QUIL, GLOBAL] {
            let mut marker = b"quil/forest-sync/incomplete/v1/".to_vec();
            marker.extend_from_slice(&32u16.to_be_bytes());
            marker.extend_from_slice(&domain);
            db.set(&marker, &[0, 0, 0]).unwrap();
            let before = db.inner().latest_sequence_number();
            assert!(scan_supply(&crdt).is_err());
            assert!(runner.rebuild(&AtomicBool::new(false)).is_err());
            assert_eq!(db.inner().latest_sequence_number(), before);
            db.delete(&marker).unwrap();
        }
        assert_eq!(scan_supply(&crdt).unwrap().reward_subunits, 42);
    }

    #[test]
    fn index_writes_preserve_unrelated_publication_and_real_conflicts() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw.clone(),
            quil_store::FOREST_NAMESPACE,
        ));
        add_coin(&crdt, 1, 7);
        crdt.commit(1).unwrap();
        let mut legacy = LEGACY_INDEX_PREFIX.to_vec();
        legacy.extend_from_slice(b"old");
        db.set(&legacy, &[0]).unwrap();
        let stale = index_key(&[9; 64]);
        db.set(&stale, &[0]).unwrap();
        let (_, runner) = SupplyIndex::start(crdt.clone(), store, db.clone());

        let publish = |branch: quil_forest::ExecutionOverlay| {
            branch
                .apply(&[quil_forest::OverlayMutation::Put(
                    b"canonical-frame".to_vec(),
                    vec![1],
                )])
                .unwrap();
            let result = branch.prepare_commit().unwrap().commit(&raw);
            assert!(
                result.is_ok(),
                "cache maintenance invalidated canonical publication: {result:?}"
            );
        };
        let branch = publication_branch(raw.clone());
        let mut counts = runner.rebuild(&AtomicBool::new(false)).unwrap().unwrap();
        publish(branch);
        assert!(db.get(&legacy).unwrap().is_none());
        assert!(db.get(&stale).unwrap().is_none());

        add_coin(&crdt, 1, 11);
        crdt.commit(2).unwrap();
        let branch = publication_branch(raw.clone());
        let mut id = [1; 64];
        id[..32].copy_from_slice(&QUIL);
        runner.apply_keys(&[id], &mut counts).unwrap();
        publish(branch);
        assert_eq!(counts.transparent_subunits, 11);

        // Declared disjoint writes must still conflict with a branch that
        // actually read the cache prefix. Canonical conflict rules stay intact.
        add_coin(&crdt, 1, 13);
        crdt.commit(3).unwrap();
        let branch = publication_branch(raw.clone());
        branch.get(&index_key(&id)).unwrap();
        runner.apply_keys(&[id], &mut counts).unwrap();
        assert!(matches!(
            branch.prepare_commit().unwrap().commit(&raw),
            Err(quil_forest::DatabaseCommitError::Stale { .. })
        ));
    }

    #[test]
    fn large_commit_notifications_preserve_all_keys() {
        let (sender, receiver) = mpsc::sync_channel(4);
        let index = SupplyIndex {
            counts: RwLock::new(Some(SupplyCounts::default())),
            lost: AtomicBool::new(false),
            lost_reasons: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
            sender,
            scan_gate: Arc::new(tokio::sync::Semaphore::new(1)),
        };
        // Observed mainnet GLOBAL syncs have reached 10,405 changed leaves.
        let keys = (0u64..10_405)
            .map(|number| {
                let mut key = [0u8; 64];
                key[..32].copy_from_slice(&QUIL);
                key[32..40].copy_from_slice(&number.to_be_bytes());
                key
            })
            .collect::<Vec<_>>();
        index.committed(&mut keys.iter().map(|key| (key.as_slice(), &[][..])));
        let legacy_event = receiver.try_recv().unwrap();
        assert_eq!(legacy_event.keys, keys);
        assert_eq!(legacy_event.sequence, 1);

        let allocation = keys.as_ptr();
        index.committed_keys(keys);
        let owned_event = receiver.try_recv().unwrap();
        assert_eq!(owned_event.keys, legacy_event.keys);
        assert_eq!(
            owned_event.keys.as_ptr(),
            allocation,
            "publication copied the prepared notification buffer"
        );
        assert_eq!(owned_event.sequence, 2);
        assert!(!index.lost.load(Ordering::Acquire));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn distinct_rebuild_key_limit_invalidates_instead_of_publishing_partial_counts() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        let (index, runner) = SupplyIndex::start(crdt, store, db);
        let mut progress = RebuildProgress::default();
        for number in 0..REBUILD_KEYS_LIMIT {
            let mut key = [0; 64];
            key[..32].copy_from_slice(&QUIL);
            key[32..40].copy_from_slice(&(number as u64).to_be_bytes());
            progress.pending.insert(key);
        }
        let existing = *progress.pending.first().unwrap();
        index.committed_keys(vec![existing]);
        assert!(runner.collect_changes(&mut progress, &AtomicBool::new(false)));
        assert_eq!(progress.pending.len(), REBUILD_KEYS_LIMIT);
        let mut extra = [0xff; 64];
        extra[..32].copy_from_slice(&QUIL);
        index.committed_keys(vec![extra]);
        assert!(!runner.collect_changes(&mut progress, &AtomicBool::new(false)));
        assert_eq!(progress.pending.len(), REBUILD_KEYS_LIMIT);
        assert!(index.read().is_none());
        assert_eq!(
            index.lost_reasons.load(Ordering::Acquire),
            LOST_REBUILD_KEYS
        );
    }

    #[test]
    fn saturated_commit_queue_invalidates_without_collecting_more_keys() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        let (index, runner) = SupplyIndex::start(crdt.clone(), store, db);
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&QUIL);
        for _ in 0..=256 {
            index.committed(&mut std::iter::once((key.as_slice(), &[][..])));
        }
        assert!(index.lost.load(Ordering::Acquire));
        let sequence = index.sequence.load(Ordering::Acquire);
        index.committed(&mut std::iter::once((key.as_slice(), &[][..])));
        assert_eq!(index.sequence.load(Ordering::Acquire), sequence);

        add_coin(&crdt, 1, 16_000_000_000);
        crdt.commit(1).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || runner.run(&worker_stop));
        assert_eq!(wait_for(&index, 1).transparent_subunits, 16_000_000_000);
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[test]
    fn repeated_rebuilds_back_off_and_reset_after_a_quiet_period() {
        let mut backoff = RebuildBackoff::default();
        let now = std::time::Instant::now();
        assert_eq!(backoff.delay(now), Duration::ZERO);
        backoff.finished(now);
        for seconds in [2, 4, 8, 16, 32, 60, 60] {
            assert_eq!(backoff.delay(now), Duration::from_secs(seconds));
            backoff.finished(now);
        }
        assert_eq!(
            backoff.delay(now + Duration::from_secs(120)),
            Duration::ZERO
        );
    }

    #[test]
    fn unchanged_contributions_do_not_write_to_store() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw.clone(),
            quil_store::FOREST_NAMESPACE,
        ));
        add_coin(&crdt, 1, 16_000_000_000);
        crdt.commit(1).unwrap();

        let (_, runner) = SupplyIndex::start(crdt, store, db);
        let mut counts = runner.rebuild(&AtomicBool::new(false)).unwrap().unwrap();
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&QUIL);
        key[32..].fill(1);
        let before = raw.latest_sequence_number();
        runner.apply_keys(&[key], &mut counts).unwrap();
        assert_eq!(raw.latest_sequence_number(), before);
        assert_eq!(counts.transparent_subunits, 16_000_000_000);

        key[32..].fill(2);
        runner.apply_keys(&[key], &mut counts).unwrap();
        assert_eq!(raw.latest_sequence_number(), before);
        assert_eq!(counts.scanned, 1);
    }

    #[test]
    fn clean_rebuild_writes_nothing_and_reconciles_stale_keys() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw.clone(),
            quil_store::FOREST_NAMESPACE,
        ));
        add_coin(&crdt, 1, 16_000_000_000);
        crdt.commit(1).unwrap();
        let (_, runner) = SupplyIndex::start(crdt, store, db.clone());
        let stop = AtomicBool::new(false);
        let mut legacy = LEGACY_INDEX_PREFIX.to_vec();
        legacy.extend_from_slice(&[7; 64]);
        db.set(&legacy, &[0]).unwrap();
        let neighbors: [&[u8]; 2] = [
            b"\0explorer-supply-v1:metadata",
            b"\0explorer-supply-v10/other",
        ];
        for key in neighbors {
            db.set(key, b"keep").unwrap();
        }
        let first = runner.rebuild(&stop).unwrap().unwrap();
        assert!(db.get(&legacy).unwrap().is_none());
        for key in neighbors {
            assert_eq!(
                db.get(key).unwrap().as_deref(),
                Some(b"keep".as_slice()),
                "legacy cleanup deleted a key outside its prefix"
            );
        }
        let before = raw.latest_sequence_number();
        assert_eq!(runner.rebuild(&stop).unwrap(), Some(first));
        assert_eq!(
            raw.latest_sequence_number(),
            before,
            "clean rebuild wrote index keys"
        );

        let mut stale = [9; 64];
        stale[..32].copy_from_slice(&QUIL);
        db.set(&index_key(&stale), &Contribution::Transparent(123).encode())
            .unwrap();
        let mut current = [1; 64];
        current[..32].copy_from_slice(&QUIL);
        db.set(&index_key(&current), &[0xff]).unwrap();
        // More than one key page, including keys before/between/after the
        // canonical domains and malformed suffixes. The merge must remove all.
        let mut obsolete = Vec::new();
        for number in 0u64..600 {
            let mut key = INDEX_PREFIX.to_vec();
            key.extend_from_slice(&number.to_be_bytes());
            db.set(&key, &[0]).unwrap();
            obsolete.push(key);
        }
        let mut malformed = index_key(&current);
        malformed.push(1);
        db.set(&malformed, &[0]).unwrap();
        obsolete.push(malformed);
        assert_eq!(runner.rebuild(&stop).unwrap(), Some(first));
        assert!(obsolete.iter().all(|key| db.get(key).unwrap().is_none()));
        assert!(db.get(&index_key(&stale)).unwrap().is_none());
        assert_eq!(
            db.get(&index_key(&current)).unwrap(),
            Some(Contribution::Transparent(16_000_000_000).encode())
        );
    }

    #[test]
    fn pure_removal_is_notified_and_rebuild_excludes_tombstones() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        add_coin(&crdt, 1, 16_000_000_000);
        crdt.commit(1).unwrap();
        let (index, runner) = SupplyIndex::start(crdt.clone(), store, db);
        let stop = AtomicBool::new(false);
        let mut counts = runner.rebuild(&stop).unwrap().unwrap();
        crdt.remove_vertex(&Location {
            app_address: QUIL,
            data_address: [1; 32],
        })
        .unwrap();
        crdt.commit(2).unwrap();
        let event = runner
            .receiver
            .try_recv()
            .expect("pure deletion must notify the supply index");
        runner.apply_keys(&event.keys, &mut counts).unwrap();
        assert_eq!(counts.transparent_coins, 0);
        assert_eq!(counts.transparent_subunits, 0);
        assert_eq!(counts.scanned, 1, "scanned remains the raw adds-row count");
        assert_eq!(runner.rebuild(&stop).unwrap(), Some(counts));
        assert!(!index.lost.load(Ordering::Acquire));
    }

    #[test]
    fn startup_excludes_preexisting_coin_and_reward_tombstones() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        add_coin(&crdt, 1, 16_000_000_000);
        add_hidden_coin(&crdt, 2);
        add_reward(&crdt, 3, 8_000_000_000);
        crdt.commit(1).unwrap();
        for (app_address, address) in [(QUIL, 1), (QUIL, 2), (GLOBAL, 3)] {
            crdt.remove_vertex(&Location {
                app_address,
                data_address: [address; 32],
            })
            .unwrap();
        }
        crdt.commit(2).unwrap();
        let (_, runner) = SupplyIndex::start(crdt, store, db);
        let counts = runner.rebuild(&AtomicBool::new(false)).unwrap().unwrap();
        assert_eq!(counts.transparent_coins, 0);
        assert_eq!(counts.value_hidden_coins, 0);
        assert_eq!(counts.reward_provers, 0);
        assert_eq!(counts.scanned, 3);
    }

    #[test]
    fn rebuild_drains_more_than_queue_capacity_across_pages_and_replays_changes() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        let tree = create_transparent_coin_tree(
            &TransparentCoin {
                owner_address: [1; 32],
                amount: 1,
            },
            &transparent_type_hash(&QUIL).unwrap(),
            &[1; 32],
        )
        .unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        for number in 0u64..600 {
            let mut address = [0; 32];
            address[..8].copy_from_slice(&number.to_be_bytes());
            crdt.add_vertex(
                &Location {
                    app_address: QUIL,
                    data_address: address,
                },
                &blob,
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let (index, mut runner) = SupplyIndex::start(crdt.clone(), store, db.clone());
        let pages = Arc::new(AtomicU64::new(0));
        runner.page_hook = Some(Box::new({
            let crdt = crdt.clone();
            let index = index.clone();
            let pages = pages.clone();
            move || {
                if pages.fetch_add(1, Ordering::AcqRel) < 3 {
                    let mut key = [0; 64];
                    key[..32].copy_from_slice(&QUIL);
                    // More than 256 distinct notifications across pages, with
                    // duplicate addresses too: collection must keep both safe.
                    for number in 0u64..200 {
                        let distinct = pages.load(Ordering::Acquire) * 200 + number;
                        key[32..40].copy_from_slice(&distinct.to_be_bytes());
                        index.committed(&mut std::iter::once((key.as_slice(), &[][..])));
                    }
                    if pages.load(Ordering::Acquire) == 1 {
                        crdt.remove_vertex(&Location {
                            app_address: QUIL,
                            data_address: [0; 32],
                        })
                        .unwrap();
                        add_coin(&crdt, 9, 42);
                        crdt.commit(2).unwrap();
                        // This newer key is absent from the scan snapshot. Stale
                        // cleanup must precede replay so it cannot erase it.
                    }
                }
            }
        }));
        let counts = runner.rebuild(&AtomicBool::new(false)).unwrap().unwrap();
        assert!(index.sequence.load(Ordering::Acquire) > EVENT_QUEUE_LIMIT as u64);
        assert!(!index.lost.load(Ordering::Acquire));
        assert_eq!(counts.transparent_coins, 600);
        assert_eq!(counts.transparent_subunits, 641);
        assert_eq!(counts.scanned, 601);
        assert_eq!(counts, scan_supply(&crdt).unwrap());
        runner.page_hook = None;
        let before = db.inner().latest_sequence_number();
        assert_eq!(
            runner.rebuild(&AtomicBool::new(false)).unwrap(),
            Some(counts)
        );
        assert_eq!(db.inner().latest_sequence_number(), before);
    }

    #[test]
    fn existing_adds_observer_never_receives_removal_blobs() {
        struct AddsOnly(Arc<AtomicU64>);
        impl LocalVertexCommitObserver for AddsOnly {
            fn committed<'a>(&self, vertices: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>) {
                for (_, blob) in vertices {
                    // Callback panics are isolated by the CRDT. Record delivery
                    // first so a leaked tombstone still fails the outer assert.
                    self.0.fetch_add(1, Ordering::AcqRel);
                    assert!(
                        !blob.is_empty(),
                        "a tombstone reached the old adds callback"
                    );
                }
            }
        }
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        let adds = Arc::new(AtomicU64::new(0));
        crdt.set_local_vertex_observer(Arc::new(AddsOnly(adds.clone())));
        let (index, runner) = SupplyIndex::start(crdt.clone(), store, db);
        add_coin(&crdt, 1, 1);
        crdt.commit(1).unwrap();
        runner.receiver.try_recv().unwrap();
        crdt.remove_vertex(&Location {
            app_address: QUIL,
            data_address: [1; 32],
        })
        .unwrap();
        crdt.commit(2).unwrap();
        let removed = runner.receiver.try_recv().unwrap();
        assert_eq!(removed.keys.len(), 1);
        assert_eq!(adds.load(Ordering::Acquire), 1);
        assert!(!index.lost.load(Ordering::Acquire));
    }

    #[test]
    fn a_tombstone_read_failure_cannot_be_counted_as_live_supply() {
        struct FailingSnapshot;
        impl SnapshotReadable for FailingSnapshot {
            fn load_tree_blob(&self, _: &str, _: &str, _: &ShardKey) -> Result<Option<Vec<u8>>> {
                Ok(None)
            }
            fn has_snapshot_vertex_reads(&self) -> bool {
                true
            }
            fn load_vertex_underlying_raw(
                &self,
                _: &str,
                phase: &str,
                _: &ShardKey,
                _: &[u8],
            ) -> Result<Option<Vec<u8>>> {
                assert_eq!(phase, "removes");
                Err(QuilError::Store("injected tombstone read failure".into()))
            }
            fn page_vertex_underlying_fixed(
                &self,
                _: &str,
                _: &str,
                _: &ShardKey,
                _: &[u8; 32],
                _: Option<&[u8; 32]>,
                _: VertexPageLimits,
            ) -> Result<quil_types::store::VertexDataPage> {
                Ok(quil_types::store::VertexDataPage {
                    entries: vec![([1; 32], Vec::new())],
                    has_more: false,
                })
            }
        }
        let mut published = false;
        let result = scan_pages(&FailingSnapshot, &QUIL, |_| {
            published = true;
            Ok(true)
        });
        assert!(result.is_err());
        assert!(!published);
    }

    fn add_coin(crdt: &HypergraphCrdt, address: u8, amount: u128) {
        let coin = TransparentCoin {
            owner_address: [address; 32],
            amount,
        };
        let ty = transparent_type_hash(&QUIL).unwrap();
        let tree = create_transparent_coin_tree(&coin, &ty, &[address; 32]).unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        crdt.add_vertex(
            &Location {
                app_address: QUIL,
                data_address: [address; 32],
            },
            &blob,
        )
        .unwrap();
    }

    fn add_hidden_coin(crdt: &HypergraphCrdt, address: u8) {
        let ty = quil_execution::token_intrinsic::materialize::coin_type_hash(&QUIL).unwrap();
        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.insert(&[0xff; 32], &ty, &[], &num_bigint::BigInt::from(32))
            .unwrap();
        crdt.add_vertex(
            &Location {
                app_address: QUIL,
                data_address: [address; 32],
            },
            &quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
        )
        .unwrap();
    }

    fn add_reward(crdt: &HypergraphCrdt, address: u8, amount: u64) {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        let mut balance = [0u8; 32];
        balance[24..].copy_from_slice(&amount.to_be_bytes());
        quil_execution::global_intrinsic::materialize::set_reward_balance(&mut tree, &balance)
            .unwrap();
        crdt.add_vertex(
            &Location {
                app_address: GLOBAL,
                data_address: [address; 32],
            },
            &quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
        )
        .unwrap();
    }

    async fn live_supply(state: crate::ExplorerState) -> serde_json::Value {
        let response = crate::handlers::handle_token_supply(
            Method::GET,
            State(state),
            Query(HashMap::from([("scan".to_string(), "1".to_string())])),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["live_public"].clone()
    }

    fn wait_for(index: &SupplyIndex, coins: u64) -> SupplyCounts {
        wait_until(index, |counts| counts.transparent_coins == coins)
    }

    fn wait_until(index: &SupplyIndex, predicate: impl Fn(SupplyCounts) -> bool) -> SupplyCounts {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Some(counts) = index.read() {
                if predicate(counts) {
                    return counts;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "supply index did not reach expected state: {:?}",
            index.read()
        );
    }

    #[test]
    fn committed_coins_build_and_update_the_supply_summary() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let mut legacy_key = LEGACY_INDEX_PREFIX.to_vec();
        legacy_key.extend_from_slice(&[0; 64]);
        db.set(&legacy_key, &[0]).unwrap();
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        add_coin(&crdt, 1, 16_000_000_000);
        crdt.commit(1).unwrap();

        let (index, runner) = SupplyIndex::start(crdt.clone(), store, db.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || runner.run(&worker_stop));
        let first = wait_for(&index, 1);
        assert_eq!(first.transparent_subunits, 16_000_000_000);
        assert!(db.get(&legacy_key).unwrap().is_none());

        add_coin(&crdt, 2, 8_000_000_000);
        crdt.commit(2).unwrap();
        let second = wait_for(&index, 2);
        assert_eq!(second.transparent_subunits, 24_000_000_000);
        assert_eq!(second.scanned, 2);
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn indexed_supply_matches_full_scan_after_coin_removal() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw.clone(),
            quil_store::FOREST_NAMESPACE,
        ));
        add_coin(&crdt, 1, 16_000_000_000);
        add_hidden_coin(&crdt, 2);
        add_reward(&crdt, 3, 8_000_000_000);
        crdt.commit(1).unwrap();

        let (index, runner) = SupplyIndex::start(crdt.clone(), store, db);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || runner.run(&worker_stop));
        let initial = wait_for(&index, 1);
        assert_eq!(initial.reward_subunits, 8_000_000_000);
        assert_eq!(initial.value_hidden_coins, 1);

        crdt.remove_vertex(&Location {
            app_address: QUIL,
            data_address: [1; 32],
        })
        .unwrap();
        add_reward(&crdt, 3, 16_000_000_000);
        crdt.commit(2).unwrap();
        let updated = wait_until(&index, |counts| {
            counts.reward_subunits == 16_000_000_000 && counts.transparent_coins == 0
        });
        assert_eq!(updated.transparent_subunits, 0);

        let make_state = || {
            crate::ExplorerState::new(
                Arc::new(quil_store::RocksClockStore::new(raw.clone())),
                crdt.clone(),
                Arc::new(quil_execution::prover_registry::SharedProverRegistry::new()),
                Arc::new(quil_store::RocksKeyStore::new(raw.clone())),
                Arc::new(quil_store::RocksShardsStore::new(raw.clone())),
                None,
                None,
                Arc::new(parking_lot::RwLock::new(HashMap::new())),
                Arc::new(crate::RecentMessageRing::new(16)),
                Arc::new(AtomicU64::new(2)),
            )
        };
        let full_scan = live_supply(make_state()).await;
        let indexed = live_supply(make_state().with_supply_index(index)).await;
        assert_eq!(full_scan["transparent_coins"], 0);
        assert_eq!(full_scan["value_hidden_coins"], 1);
        assert_eq!(full_scan["reward_provers"], 1);
        assert_eq!(full_scan["reward_subunits"], "16000000000");
        assert_eq!(indexed, full_scan);
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }
}
