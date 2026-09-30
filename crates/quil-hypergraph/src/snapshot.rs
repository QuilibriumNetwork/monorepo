//! Snapshot manager — port of `hypergraph/snapshot_manager.go`.
//!
//! Tracks recent published roots so sync clients can request data
//! against a specific historical commitment. The Go version pairs
//! each generation with a Pebble DB snapshot (point-in-time consistent
//! reads); this Rust port keeps the (root, frame_number) registry and
//! optionally pairs each generation with a `SnapshotReadable` —
//! a frozen-bytes copy of all tree blobs at publish time, captured
//! via `HypergraphStore::capture_tree_snapshot`. With a bound
//! snapshot, sync clients reading via the handle see only the
//! state at publish time, immune to concurrent writes through the
//! live store.
//!
//! Behavioural parity with Go:
//!
//! - `publish(root, frame)` adds a new generation. Duplicate roots
//! are no-ops (matches Go's "same root → no change").
//! - `publish_with_snapshot(root, frame, snap)` is the same but
//! binds an opaque DB-snapshot reference to the generation, which
//! `acquire` returns to the caller for point-in-time reads.
//! - `acquire(expected_root)` returns the matching generation handle
//! or `None` if the requested root is unknown. With no
//! `expected_root`, returns the latest generation.
//! - Up to `MAX_GENERATIONS` retained — older entries evicted FIFO.
//! Evicted generations drop their snapshot Arc, releasing the
//! underlying frozen bytes.
//! - Closed managers reject all subsequent operations.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock, RwLockWriteGuard};

use quil_types::store::SnapshotReadable;

/// Maximum number of historical snapshot generations retained.
///
/// Go uses `maxSnapshotGenerations = 10`, but with publishing roughly
/// once per frame that's only ~10 frames of retention. A follower whose
/// prover-tree sync runs on a multi-minute cadence (tens of frames apart)
/// then requests a root the archive has already evicted, gets
/// `failed to acquire snapshot`, and falls back to a perpetually-lagging
/// incremental sync — leaving its registry stale and the node stuck in
/// degraded-coverage prover-only mode. Widened to
/// 64 (~64 frames ≈ ~10 min at 10s/frame) so a follower a sync-cycle or
/// two behind can still acquire the snapshot for a clean full resync.
///
/// Widened again to 128 (~128 frames ≈ ~21 min at 10s/frame) to support the
/// far-behind archive STATE-JUMP: that recovery syncs the prover tree PLUS
/// every app-shard tree (× 4 phases) — all pinned to a SINGLE target frame's
/// snapshot generation for cross-tree consistency — which is a sequential,
/// multi-minute operation. The target generation must survive on the SERVING
/// archive for the whole jump, so retention has to comfortably exceed the jump
/// duration (a mismatch would evict the generation mid-jump → `failed to
/// acquire snapshot`, aborting the jump). 128 leaves ample headroom over a
/// realistic sequential jump (mostly-small shards + one QUIL shard).
///
/// Each generation now binds a REAL RocksDB point-in-time snapshot (see
/// `RocksHypergraphSnapshot`), which pins the superseded key versions it
/// covers until released. Release is driven by `Drop`: a generation
/// evicted past this cap (FIFO `pop_back`) or cleared on `close()` drops
/// its handle and releases the snapshot — unless an in-flight sync
/// session still holds an `Arc` clone, in which case release waits for
/// that session to finish. So this count bounds disk-version retention;
/// raising it widens the catch-up window at the cost of pinning more
/// versions on a busy archive.
///
/// Widened to TWO FULL EPOCHS (2 × `EPOCH_LENGTH_FRAMES` = 1440 frames ≈ ~4h at
/// 10s/frame) to CLOSE THE STATE-JUMP DEAD ZONE. At 128 a node lagging 128–1000
/// frames could neither incrementally sync — its target prover-tree version was
/// already pruned past this cap, so `resolve_root` returns a `(version, frame)`
/// from the persistent index whose tree DATA is gone → the pulled tree hashes to
/// a different root → `phase root != anchor` forever — nor state-jump, since the
/// gap was below `state_jump_min_gap` (1000). The prover tree churns EVERY frame
/// now, so historical roots don't otherwise persist. Making retention (1440) >
/// the state-jump threshold (1000) guarantees a node anywhere below the jump
/// trigger still finds its target retained, so it can always incrementally
/// converge. Costs ~11× the pinned RocksDB versions on a busy archive.
pub const MAX_GENERATIONS: usize = 2 * quil_types::consensus::EPOCH_LENGTH_FRAMES as usize;

/// One snapshot generation: a (root, frame_number) pair the manager
/// has seen, plus an optional point-in-time snapshot of the underlying
/// store. Returned by `acquire` so callers can confirm the generation
/// exists and read against the bound snapshot if present.
#[derive(Clone)]
pub struct GenerationHandle {
    /// Opaque scan identity, distinct from a root that might later be republished.
    /// None disables wallet scans if OS entropy was unavailable at publication.
    pub scan_id: Option<[u8; 32]>,
    pub root: Vec<u8>,
    pub frame_number: u64,
    /// When `Some`, sync requests against this generation should read
    /// tree data from the snapshot rather than the live store. The
    /// `Arc` keeps the underlying frozen bytes alive for the duration
    /// of any held handle, so an outstanding sync session keeps using
    /// consistent data even after eviction from the manager.
    pub db_snapshot: Option<Arc<dyn SnapshotReadable>>,
}

impl std::fmt::Debug for GenerationHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerationHandle")
            .field("root", &hex::encode(&self.root))
            .field("frame_number", &self.frame_number)
            .field("has_db_snapshot", &self.db_snapshot.is_some())
            .finish()
    }
}

impl PartialEq for GenerationHandle {
    fn eq(&self, other: &Self) -> bool {
        // Snapshot Arc identity is irrelevant for equality — root +
        // frame uniquely identify a generation.
        self.root == other.root && self.frame_number == other.frame_number
    }
}

impl Eq for GenerationHandle {}

/// Thread-safe snapshot generation tracker.
pub struct SnapshotManager {
    inner: RwLock<SnapshotManagerInner>,
}

/// Holds publication capacity and the generation lock before a durable write.
/// Dropping without adoption leaves the advertised generations unchanged.
pub struct PreparedSnapshotPublication<'a> {
    inner: RwLockWriteGuard<'a, SnapshotManagerInner>,
    generation: Option<GenerationHandle>,
}

impl PreparedSnapshotPublication<'_> {
    /// Bind the exact post-commit read view without allocation or new locking.
    /// Keep this guard until the other live execution metadata is adopted.
    pub fn adopt(&mut self, snapshot: Arc<dyn SnapshotReadable>) {
        if let Some(mut generation) = self.generation.take() {
            generation.db_snapshot = Some(snapshot);
            self.inner.generations.push_front(generation);
            while self.inner.generations.len() > MAX_GENERATIONS {
                self.inner.generations.pop_back();
            }
            self.inner.release_old_pins();
        }
    }
}

struct SnapshotManagerInner {
    /// Newest first. Bounded by [`MAX_GENERATIONS`].
    generations: VecDeque<GenerationHandle>,
    /// Scan-only generations (empty root), newest first, bounded by
    /// [`MAX_SCAN_GENERATIONS`]. Captured on demand for wallet scans when no
    /// root generation carries a store snapshot; never advertised as roots
    /// and never returned by [`SnapshotManager::acquire`].
    scans: VecDeque<GenerationHandle>,
    closed: bool,
    /// Generations, newest first, that keep their store snapshot; older ones
    /// keep only their `(root, frame)` entry. Default [`MAX_GENERATIONS`].
    pinned_limit: usize,
}

impl SnapshotManagerInner {
    /// Release the store snapshots of generations past `pinned_limit`.
    ///
    /// Each held RocksDB snapshot keeps every key version overwritten or
    /// deleted after it on disk, so the oldest pinned generation sets how long
    /// pruned and superseded data stays. Only wallet scans read a generation's
    /// snapshot (`acquire_scan`); sync serving resolves a root through the
    /// root-version index and reads versioned data, never the snapshot. A scan
    /// already holding a handle keeps its snapshot alive through its own `Arc`;
    /// continuing a scan whose generation lost its snapshot reports it expired.
    fn release_old_pins(&mut self) {
        let limit = self.pinned_limit;
        for generation in self.generations.iter_mut().skip(limit) {
            generation.db_snapshot = None;
        }
    }
}

/// Retained on-demand scan snapshots (continuations of recent scans).
pub const MAX_SCAN_GENERATIONS: usize = 16;

impl Default for SnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotManager {
    pub fn prepare_publication(
        &self,
        root: Vec<u8>,
        frame_number: u64,
    ) -> quil_types::error::Result<PreparedSnapshotPublication<'_>> {
        use quil_types::error::QuilError;
        let mut inner = self.inner.try_write().map_err(|_| {
            QuilError::ExecutionUnavailable("snapshot publication is busy or poisoned".into())
        })?;
        if inner.closed {
            return Err(QuilError::ExecutionUnavailable("snapshot manager is closed".into()));
        }
        let generation = if inner.generations.iter().any(|h| h.root == root) {
            None
        } else {
            inner.generations.try_reserve(1).map_err(|_| {
                QuilError::ExecutionUnavailable("snapshot publication allocation failed".into())
            })?;
            let mut scan_id = [0; 32];
            let scan_id = getrandom::getrandom(&mut scan_id).ok().map(|()| scan_id);
            Some(GenerationHandle { scan_id, root, frame_number, db_snapshot: None })
        };
        Ok(PreparedSnapshotPublication { inner, generation })
    }

    pub fn new() -> Self {
        Self {
            inner: RwLock::new(SnapshotManagerInner {
                generations: VecDeque::with_capacity(MAX_GENERATIONS),
                scans: VecDeque::with_capacity(MAX_SCAN_GENERATIONS),
                closed: false,
                pinned_limit: MAX_GENERATIONS,
            }),
        }
    }

    /// Keep store snapshots only on the newest `limit` generations (at least
    /// one); older generations keep their `(root, frame)` entry.
    pub fn set_pinned_limit(&self, limit: usize) {
        let mut inner = self.inner.write().unwrap();
        inner.pinned_limit = limit.clamp(1, MAX_GENERATIONS);
        inner.release_old_pins();
    }

    /// Generations currently holding a store snapshot.
    pub fn pinned_count(&self) -> usize {
        self.inner.read().unwrap().generations.iter().filter(|g| g.db_snapshot.is_some()).count()
    }

    /// Add a new generation tagged by `root` at `frame_number` with no
    /// bound DB-snapshot — sync clients fall back to the live store.
    /// Mirror of Go `snapshotManager.publish` for the no-snapshot case.
    pub fn publish(&self, root: Vec<u8>, frame_number: u64) {
        self.publish_internal(root, frame_number, None);
    }

    /// Add a new generation tagged by `root` at `frame_number` and
    /// bind `snapshot` to it. Sync requests with `expected_root = root`
    /// will receive a handle whose `db_snapshot` is `snapshot`, which
    /// the sync server can use for point-in-time reads independent of
    /// the live store. Mirrors Go `snapshotManager.publish` with a
    /// non-nil `dbSnapshot`.
    pub fn publish_with_snapshot(
        &self,
        root: Vec<u8>,
        frame_number: u64,
        snapshot: Arc<dyn SnapshotReadable>,
    ) {
        self.publish_internal(root, frame_number, Some(snapshot));
    }

    fn publish_internal(
        &self,
        root: Vec<u8>,
        frame_number: u64,
        snapshot: Option<Arc<dyn SnapshotReadable>>,
    ) {
        let mut g = self.inner.write().unwrap();
        if g.closed {
            return;
        }
        // Duplicate root → no-op. Matches Go's behaviour: a later
        // publish with the same root must NOT shadow the original
        // generation. (See `hypergraph/snapshot_manager.go:206-218`
        // for the rationale — a same-root re-publish during message
        // application would otherwise rebind the wrong DB state.)
        if g.generations.iter().any(|h| h.root == root) {
            return;
        }
        let mut scan_id = [0; 32];
        let scan_id = getrandom::getrandom(&mut scan_id).ok().map(|()| scan_id);
        g.generations.push_front(GenerationHandle {
            scan_id,
            root,
            frame_number,
            db_snapshot: snapshot,
        });
        while g.generations.len() > MAX_GENERATIONS {
            // Pop the back; the dropped `GenerationHandle` releases its
            // `Arc<dyn SnapshotReadable>`, which (when no other
            // references exist) frees the frozen bytes.
            g.generations.pop_back();
        }
        g.release_old_pins();
    }

    /// Look up a generation by `expected_root`. Mirrors Go
    /// `snapshotManager.acquire`.
    ///
    /// - If `expected_root` is empty, returns the latest generation.
    /// - Otherwise, returns the generation matching `expected_root`,
    /// or `None` if no such generation exists.
    pub fn acquire(&self, expected_root: &[u8]) -> Option<GenerationHandle> {
        let g = self.inner.read().unwrap();
        if g.closed || g.generations.is_empty() {
            return None;
        }
        if expected_root.is_empty() {
            return g.generations.front().cloned();
        }
        g.generations
            .iter()
            .find(|h| h.root.as_slice() == expected_root)
            .cloned()
    }

    /// Acquire the latest generation for a new scan, or the exact retained
    /// identity for continuation. Never fall back to live state or a new root.
    pub fn acquire_scan(&self, id: Option<&[u8; 32]>) -> Option<GenerationHandle> {
        let g = self.inner.read().unwrap();
        if g.closed { return None; }
        let scannable = |h: &&GenerationHandle| h.scan_id.is_some() && h.db_snapshot.is_some();
        let generation = match id {
            // Newest root generation that can serve a scan.
            None => g.generations.iter().find(scannable),
            Some(id) => g.generations.iter().chain(g.scans.iter())
                .filter(scannable)
                .find(|h| h.scan_id.as_ref() == Some(id)),
        }?;
        Some(generation.clone())
    }

    /// Register a scan-only generation over `snapshot` and return it. `None`
    /// when closed or OS entropy for the scan identity is unavailable.
    pub fn publish_scan_only(&self, frame_number: u64, snapshot: Arc<dyn SnapshotReadable>) -> Option<GenerationHandle> {
        let mut g = self.inner.write().unwrap();
        if g.closed { return None; }
        let mut id = [0; 32];
        getrandom::getrandom(&mut id).ok()?;
        let handle = GenerationHandle { scan_id: Some(id), root: Vec::new(), frame_number, db_snapshot: Some(snapshot) };
        g.scans.push_front(handle.clone());
        while g.scans.len() > MAX_SCAN_GENERATIONS {
            g.scans.pop_back();
        }
        Some(handle)
    }

    /// Latest published root, if any.
    pub fn latest_root(&self) -> Option<Vec<u8>> {
        self.inner.read().unwrap().generations.front().map(|h| h.root.clone())
    }

    /// All known roots, newest first.
    pub fn known_roots(&self) -> Vec<Vec<u8>> {
        self.inner
            .read()
            .unwrap()
            .generations
            .iter()
            .map(|h| h.root.clone())
            .collect()
    }

    /// Number of retained generations.
    pub fn generation_count(&self) -> usize {
        self.inner.read().unwrap().generations.len()
    }

    /// Mark closed. All subsequent operations become no-ops.
    pub fn close(&self) {
        let mut g = self.inner.write().unwrap();
        g.closed = true;
        g.generations.clear();
        g.scans.clear();
    }

    /// Reopen after close (Go's `reopen` semantic for in-process
    /// engine respawn).
    pub fn reopen(&self) {
        self.inner.write().unwrap().closed = false;
    }

    pub fn is_closed(&self) -> bool {
        self.inner.read().unwrap().closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::error::Result as QuilResult;
    use quil_types::store::{ShardKey, SnapshotReadable};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn prepared_publication_can_be_abandoned_and_keeps_duplicate_root_identity() {
        let manager = SnapshotManager::new();
        let original = snap_with("vertex", "adds", shard(1), vec![1]);
        manager.publish_with_snapshot(vec![1; 32], 1, original.clone());
        {
            let _prepared = manager.prepare_publication(vec![2; 32], 2).unwrap();
            assert!(manager.inner.try_read().is_err());
            assert!(manager.prepare_publication(vec![3; 32], 3).is_err());
        }
        assert!(manager.acquire(&[2; 32]).is_none());
        let mut duplicate = manager.prepare_publication(vec![1; 32], 9).unwrap();
        duplicate.adopt(snap_with("vertex", "adds", shard(1), vec![9]));
        drop(duplicate);
        let retained = manager.acquire(&[1; 32]).unwrap();
        assert_eq!(retained.frame_number, 1);
        assert!(Arc::ptr_eq(retained.db_snapshot.as_ref().unwrap(), &original));
        manager.close();
        assert!(manager.prepare_publication(vec![2; 32], 2).is_err());
    }

    #[test]
    fn prepared_publication_adopts_exact_view_and_retains_existing_generation_cap() {
        let manager = SnapshotManager::new();
        for n in 0..MAX_GENERATIONS {
            manager.publish((n as u64).to_be_bytes().to_vec(), n as u64);
        }
        let view = snap_with("vertex", "adds", shard(2), vec![2]);
        let mut prepared = manager.prepare_publication(vec![7; 32], 9999).unwrap();
        prepared.adopt(view.clone());
        // Adoption retains the lock until the other caches are ready.
        assert!(manager.inner.try_read().is_err());
        drop(prepared);
        assert_eq!(manager.inner.read().unwrap().generations.len(), MAX_GENERATIONS);
        assert!(manager.acquire(&0u64.to_be_bytes()).is_none());
        let latest = manager.acquire(&[]).unwrap();
        assert_eq!(latest.frame_number, 9999);
        assert!(Arc::ptr_eq(latest.db_snapshot.as_ref().unwrap(), &view));
    }

    /// A `SnapshotReadable` that maps `(set, phase, shard) → blob`
    /// from a fixed in-memory dictionary. Lets tests verify that
    /// reads through a generation handle reflect the publish-time
    /// state regardless of subsequent mutations.
    struct StubSnapshot {
        blobs: HashMap<(String, String, ShardKey), Vec<u8>>,
    }
    impl SnapshotReadable for StubSnapshot {
        fn load_tree_blob(
            &self,
            set_type: &str,
            phase_type: &str,
            shard_key: &ShardKey,
        ) -> QuilResult<Option<Vec<u8>>> {
            Ok(self
                .blobs
                .get(&(set_type.to_string(), phase_type.to_string(), shard_key.clone()))
                .cloned())
        }
    }

    fn shard(b: u8) -> ShardKey {
        let mut l2 = [0u8; 32];
        l2[0] = b;
        ShardKey { l1: [b, 0, 0], l2 }
    }

    fn snap_with(set: &str, phase: &str, sk: ShardKey, blob: Vec<u8>) -> Arc<dyn SnapshotReadable> {
        let mut blobs = HashMap::new();
        blobs.insert((set.to_string(), phase.to_string(), sk), blob);
        Arc::new(StubSnapshot { blobs })
    }

    /// Drop tracker for snapshot-eviction tests: counts `Drop` calls
    /// so we can confirm an evicted generation actually releases
    /// its underlying handle.
    struct CountingSnapshot {
        counter: Arc<Mutex<usize>>,
    }
    impl SnapshotReadable for CountingSnapshot {
        fn load_tree_blob(
            &self,
            _: &str,
            _: &str,
            _: &ShardKey,
        ) -> QuilResult<Option<Vec<u8>>> {
            Ok(None)
        }
    }
    impl Drop for CountingSnapshot {
        fn drop(&mut self) {
            *self.counter.lock().unwrap() += 1;
        }
    }

    #[test]
    fn publish_adds_generation() {
        let m = SnapshotManager::new();
        m.publish(vec![0xAA; 32], 100);
        assert_eq!(m.generation_count(), 1);
        assert_eq!(m.latest_root(), Some(vec![0xAA; 32]));
    }

    #[test]
    fn publish_duplicate_root_is_noop() {
        let m = SnapshotManager::new();
        m.publish(vec![0xAA; 32], 100);
        m.publish(vec![0xAA; 32], 200);
        // Still only one generation, frame_number stayed at 100.
        assert_eq!(m.generation_count(), 1);
        let h = m.acquire(&[0xAA; 32]).unwrap();
        assert_eq!(h.frame_number, 100);
    }

    #[test]
    fn acquire_finds_by_root() {
        let m = SnapshotManager::new();
        m.publish(vec![0x11; 32], 1);
        m.publish(vec![0x22; 32], 2);
        m.publish(vec![0x33; 32], 3);
        assert_eq!(m.acquire(&[0x22; 32]).unwrap().frame_number, 2);
    }

    #[test]
    fn acquire_unknown_returns_none() {
        let m = SnapshotManager::new();
        m.publish(vec![0xAA; 32], 1);
        assert!(m.acquire(&[0xBB; 32]).is_none());
    }

    #[test]
    fn acquire_empty_expected_root_returns_latest() {
        let m = SnapshotManager::new();
        m.publish(vec![0x11; 32], 1);
        m.publish(vec![0x22; 32], 2);
        let h = m.acquire(&[]).unwrap();
        assert_eq!(h.root, vec![0x22; 32]);
    }

    #[test]
    fn acquire_empty_when_no_generations() {
        let m = SnapshotManager::new();
        assert!(m.acquire(&[]).is_none());
        assert!(m.acquire(&[0xAA; 32]).is_none());
    }

    #[test]
    fn evicts_oldest_beyond_max_generations() {
        let m = SnapshotManager::new();
        // Encode the index across 4 bytes — MAX_GENERATIONS (1440) exceeds a
        // single byte's range, so a `u8` index would collide roots.
        let root_for = |i: u64| {
            let mut root = vec![0u8; 32];
            root[28..32].copy_from_slice(&(i as u32).to_be_bytes());
            root
        };
        for i in 0..(MAX_GENERATIONS as u64 + 5) {
            m.publish(root_for(i), i);
        }
        assert_eq!(m.generation_count(), MAX_GENERATIONS);
        // The oldest 5 should have been evicted.
        assert!(m.acquire(&root_for(0)).is_none());
        // The newest should still be available.
        assert!(m.acquire(&root_for(MAX_GENERATIONS as u64 + 4)).is_some());
    }

    #[test]
    fn close_clears_and_blocks_publish() {
        let m = SnapshotManager::new();
        m.publish(vec![0xAA; 32], 1);
        m.close();
        assert!(m.is_closed());
        assert!(m.acquire(&[0xAA; 32]).is_none());
        // Publish becomes a no-op while closed.
        m.publish(vec![0xBB; 32], 2);
        assert_eq!(m.generation_count(), 0);
        m.reopen();
        m.publish(vec![0xBB; 32], 2);
        assert_eq!(m.generation_count(), 1);
    }

    #[test]
    fn known_roots_returns_newest_first() {
        let m = SnapshotManager::new();
        m.publish(vec![0x11; 32], 1);
        m.publish(vec![0x22; 32], 2);
        m.publish(vec![0x33; 32], 3);
        let roots = m.known_roots();
        assert_eq!(roots.len(), 3);
        assert_eq!(roots[0], vec![0x33; 32]);
        assert_eq!(roots[1], vec![0x22; 32]);
        assert_eq!(roots[2], vec![0x11; 32]);
    }

    // -------- DB-snapshot binding tests (Tier 3) --------

    #[test]
    fn scan_identity_never_rebinds_after_republication() {
        let m = SnapshotManager::new();
        m.publish(vec![1; 32], 1);
        assert!(m.acquire_scan(None).is_none());
        m.publish_with_snapshot(vec![2; 32], 2, snap_with("vertex", "adds", shard(1), vec![1]));
        let first = m.acquire_scan(None).unwrap();
        let id = first.scan_id.unwrap();
        assert!(m.acquire_scan(Some(&id)).is_some());
        m.close(); m.reopen();
        m.publish_with_snapshot(vec![2; 32], 2, snap_with("vertex", "adds", shard(1), vec![2]));
        assert!(m.acquire_scan(Some(&id)).is_none());
        assert_ne!(m.acquire_scan(None).unwrap().scan_id, Some(id));
        // In-flight holders retain the original data after eviction.
        assert_eq!(first.db_snapshot.unwrap().load_tree_blob("vertex", "adds", &shard(1)).unwrap(), Some(vec![1]));
    }

    /// Scans prefer the newest ROOT generation that carries a store snapshot
    /// (not merely the newest generation), and on-demand scan-only
    /// generations serve continuation without ever surfacing as roots.
    #[test]
    fn scan_only_generations_serve_scans_without_becoming_roots() {
        let m = SnapshotManager::new();
        m.publish_with_snapshot(vec![2; 32], 2, snap_with("vertex", "adds", shard(1), vec![1]));
        m.publish(vec![3; 32], 3);
        assert_eq!(m.acquire_scan(None).unwrap().root, vec![2; 32], "newest scannable, not newest");

        let m = SnapshotManager::new();
        assert!(m.acquire_scan(None).is_none());
        let scan = m.publish_scan_only(9, snap_with("vertex", "adds", shard(1), vec![7])).unwrap();
        let id = scan.scan_id.unwrap();
        assert!(scan.root.is_empty());
        assert!(m.acquire_scan(None).is_none(), "scan-only generations never start a scan by themselves");
        assert_eq!(m.acquire_scan(Some(&id)).unwrap().frame_number, 9);
        assert!(m.known_roots().is_empty());
        assert!(m.acquire(&[]).is_none());
        for frame in 10..10 + MAX_SCAN_GENERATIONS as u64 {
            m.publish_scan_only(frame, snap_with("vertex", "adds", shard(1), vec![8])).unwrap();
        }
        assert!(m.acquire_scan(Some(&id)).is_none(), "bounded retention evicts the oldest scan");
        m.close();
        assert!(m.publish_scan_only(1, snap_with("vertex", "adds", shard(1), vec![1])).is_none());
    }

    #[test]
    fn acquire_with_snapshot_returns_bound_snapshot_for_pre_publish_state() {
        // The snapshot we publish reflects the "pre-write" tree blob.
        // After the publish, simulate a subsequent live-store mutation
        // by doing nothing here — the snapshot is frozen at publish
        // time, so reads through the handle MUST see the pre-publish
        // bytes regardless of any later writes outside the snapshot.
        let m = SnapshotManager::new();
        let sk = shard(0xAB);
        let pre_blob = b"pre-write-tree-blob".to_vec();
        let snap = snap_with("vertex", "adds", sk.clone(), pre_blob.clone());

        m.publish_with_snapshot(vec![0xAA; 32], 7, snap);

        let handle = m.acquire(&[0xAA; 32]).expect("generation present");
        let bound = handle.db_snapshot.as_ref().expect("snapshot bound");
        let read = bound
            .load_tree_blob("vertex", "adds", &sk)
            .unwrap()
            .unwrap();
        assert_eq!(read, pre_blob);

        // Querying for a different shard / phase returns None — the
        // snapshot only knows what the publisher captured.
        assert!(bound
            .load_tree_blob("vertex", "removes", &sk)
            .unwrap()
            .is_none());
    }

    #[test]
    fn evicted_generation_drops_its_snapshot_handle() {
        let counter = Arc::new(Mutex::new(0usize));
        let m = SnapshotManager::new();

        // First publish: bind a counting snapshot to root [0x01; 32].
        let snap_arc: Arc<dyn SnapshotReadable> =
            Arc::new(CountingSnapshot { counter: counter.clone() });
        m.publish_with_snapshot(vec![0x01; 32], 1, snap_arc);
        // No other Arc references → Drop has not fired yet.
        assert_eq!(*counter.lock().unwrap(), 0);

        // Push enough new generations to evict the first. Encode the index across
        // 4 bytes (MAX_GENERATIONS exceeds a single byte's range).
        for i in 2..=(MAX_GENERATIONS as u64 + 1) {
            let mut root = vec![0u8; 32];
            root[28..32].copy_from_slice(&(i as u32).to_be_bytes());
            m.publish(root, i);
        }
        // Generation [0x01; 32] should have been evicted, dropping
        // the only Arc reference to its snapshot.
        assert!(m.acquire(&[0x01; 32]).is_none());
        assert_eq!(*counter.lock().unwrap(), 1);
    }

    /// With a pin limit, only the newest generations keep a store snapshot;
    /// older ones keep their root and frame. A scan holding a handle keeps its
    /// snapshot until it lets go, and continuing a scan whose generation lost
    /// its snapshot finds nothing (reported expired).
    #[test]
    fn a_pin_limit_releases_snapshots_of_older_generations_only() {
        let counter = Arc::new(Mutex::new(0usize));
        let m = SnapshotManager::new();
        let publish = |i: u8| {
            let snapshot: Arc<dyn SnapshotReadable> = Arc::new(CountingSnapshot { counter: counter.clone() });
            m.publish_with_snapshot(vec![i; 32], i as u64, snapshot);
        };
        for i in 1..=4 {
            publish(i);
        }
        let held = m.acquire_scan(None).unwrap();
        assert_eq!(held.root, vec![4; 32]);
        let oldest_scan = m.acquire(&[1; 32]).unwrap().scan_id;
        m.set_pinned_limit(2);
        assert_eq!(m.pinned_count(), 2);
        assert_eq!(*counter.lock().unwrap(), 2, "generations 1 and 2 released their snapshots");
        assert_eq!(m.generation_count(), 4, "every root stays registered");
        assert_eq!(m.acquire(&[1; 32]).unwrap().frame_number, 1);
        assert!(m.acquire_scan(oldest_scan.as_ref()).is_none(), "an unpinned generation serves no scan");

        publish(5);
        publish(6);
        assert_eq!(m.pinned_count(), 2);
        assert!(m.acquire(&[4; 32]).unwrap().db_snapshot.is_none());
        assert_eq!(*counter.lock().unwrap(), 3, "generation 4's snapshot lives on in the held scan");
        assert!(held.db_snapshot.is_some());
        drop(held);
        assert_eq!(*counter.lock().unwrap(), 4);
        assert_eq!(m.acquire_scan(None).unwrap().root, vec![6; 32]);
    }

    #[test]
    fn close_releases_bound_snapshots() {
        let counter = Arc::new(Mutex::new(0usize));
        let m = SnapshotManager::new();
        let snap_arc: Arc<dyn SnapshotReadable> =
            Arc::new(CountingSnapshot { counter: counter.clone() });
        m.publish_with_snapshot(vec![0x42; 32], 1, snap_arc);
        assert_eq!(*counter.lock().unwrap(), 0);
        m.close();
        // close() clears the deque, dropping the only reference.
        assert_eq!(*counter.lock().unwrap(), 1);
    }
}
