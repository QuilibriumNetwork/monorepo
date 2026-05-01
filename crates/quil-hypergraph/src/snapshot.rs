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
//!   are no-ops (matches Go's "same root → no change").
//! - `publish_with_snapshot(root, frame, snap)` is the same but
//!   binds an opaque DB-snapshot reference to the generation, which
//!   `acquire` returns to the caller for point-in-time reads.
//! - `acquire(expected_root)` returns the matching generation handle
//!   or `None` if the requested root is unknown. With no
//!   `expected_root`, returns the latest generation.
//! - Up to `MAX_GENERATIONS` retained — older entries evicted FIFO.
//!   Evicted generations drop their snapshot Arc, releasing the
//!   underlying frozen bytes.
//! - Closed managers reject all subsequent operations.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use quil_types::store::SnapshotReadable;

/// Maximum number of historical snapshot generations retained.
/// Mirrors Go's `maxSnapshotGenerations = 10`.
pub const MAX_GENERATIONS: usize = 10;

/// One snapshot generation: a (root, frame_number) pair the manager
/// has seen, plus an optional point-in-time snapshot of the underlying
/// store. Returned by `acquire` so callers can confirm the generation
/// exists and read against the bound snapshot if present.
#[derive(Clone)]
pub struct GenerationHandle {
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

struct SnapshotManagerInner {
    /// Newest first. Bounded by [`MAX_GENERATIONS`].
    generations: VecDeque<GenerationHandle>,
    closed: bool,
}

impl Default for SnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotManager {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(SnapshotManagerInner {
                generations: VecDeque::with_capacity(MAX_GENERATIONS),
                closed: false,
            }),
        }
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
        g.generations.push_front(GenerationHandle {
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
    }

    /// Look up a generation by `expected_root`. Mirrors Go
    /// `snapshotManager.acquire`.
    ///
    /// - If `expected_root` is empty, returns the latest generation.
    /// - Otherwise, returns the generation matching `expected_root`,
    ///   or `None` if no such generation exists.
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
        for i in 0..(MAX_GENERATIONS as u64 + 5) {
            let mut root = vec![0u8; 32];
            root[31] = i as u8;
            m.publish(root, i);
        }
        assert_eq!(m.generation_count(), MAX_GENERATIONS);
        // The oldest 5 should have been evicted.
        let mut oldest_root = vec![0u8; 32];
        oldest_root[31] = 0u8;
        assert!(m.acquire(&oldest_root).is_none());
        // The newest should still be available.
        let mut newest_root = vec![0u8; 32];
        newest_root[31] = (MAX_GENERATIONS as u64 + 4) as u8;
        assert!(m.acquire(&newest_root).is_some());
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

        // Push enough new generations to evict the first.
        for i in 2..=(MAX_GENERATIONS as u64 + 1) {
            let mut root = vec![0u8; 32];
            root[31] = i as u8;
            m.publish(root, i);
        }
        // Generation [0x01; 32] should have been evicted, dropping
        // the only Arc reference to its snapshot.
        assert!(m.acquire(&[0x01; 32]).is_none());
        assert_eq!(*counter.lock().unwrap(), 1);
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
