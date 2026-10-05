//! `RemoteTreeReader` — a [`jmt::storage::TreeReader`] backed by a peer's
//! `GetForestNode`/`GetForestValue` gRPC, so [`quil_forest::diff_leaves`] can
//! walk a remote shard/phase tree and pull only the nodes whose hash differs
//! from the local one.
//!
//! # Sync-over-async
//!
//! jmt's `TreeReader` is synchronous; the gRPC client is async. Each read
//! blocks the calling thread on the gRPC via a [`tokio::runtime::Handle`], so
//! `RemoteTreeReader` MUST be used from a blocking context (run the diff inside
//! `tokio::task::spawn_blocking`) — never on a runtime worker thread, where
//! `block_on` would panic.

use anyhow::Result;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

const PREFETCH_CONCURRENCY: usize = 8;
const PREFETCH_MAX_ENTRIES: usize = 1024;
const PREFETCH_MAX_BYTES: usize = 1024 * 1024;

#[async_trait::async_trait]
trait ForestReadSource: Send + Sync {
    async fn node(
        &self,
        shard: Vec<u8>,
        phase: u32,
        key: Vec<u8>,
        limit: usize,
    ) -> Result<Option<Vec<u8>>>;
    async fn value(
        &self,
        shard: Vec<u8>,
        phase: u32,
        version: Version,
        key: KeyHash,
        limit: usize,
    ) -> Result<Option<Vec<u8>>>;
}

#[async_trait::async_trait]
impl ForestReadSource for ArchiveClient {
    async fn node(
        &self,
        shard: Vec<u8>,
        phase: u32,
        key: Vec<u8>,
        limit: usize,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .clone()
            .with_decoding_limit(limit)
            .get_forest_node(shard, phase, key)
            .await?)
    }
    async fn value(
        &self,
        shard: Vec<u8>,
        phase: u32,
        version: Version,
        key: KeyHash,
        limit: usize,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .clone()
            .with_decoding_limit(limit)
            .get_forest_value(shard, phase, version, key.0.to_vec())
            .await?)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum ReadKey {
    Node(Vec<u8>),
    Value(Version, [u8; 32]),
}
impl ReadKey {
    fn bytes(&self) -> usize {
        match self {
            Self::Node(key) => key.len(),
            Self::Value(..) => 40,
        }
    }
}

/// Only unconsumed read-ahead is retained; both metadata and payload are bounded.
#[derive(Default)]
struct ReadAhead {
    entries: HashMap<ReadKey, Option<Vec<u8>>>,
    bytes: usize,
}
impl ReadAhead {
    fn take(&mut self, key: &ReadKey) -> Option<Option<Vec<u8>>> {
        let value = self.entries.remove(key)?;
        self.bytes -= key.bytes() + value.as_ref().map_or(0, Vec::len);
        Some(value)
    }
    fn insert(&mut self, key: ReadKey, value: Option<Vec<u8>>) {
        let bytes = key.bytes() + value.as_ref().map_or(0, Vec::len);
        if self.entries.contains_key(&key)
            || self.entries.len() >= PREFETCH_MAX_ENTRIES
            || bytes > PREFETCH_MAX_BYTES.saturating_sub(self.bytes)
        {
            return;
        }
        self.bytes += bytes;
        self.entries.insert(key, value);
    }
}

fn counted(reads: &AtomicU64, started: Instant, shard: &[u8], phase: u32) {
    let reads = reads.fetch_add(1, Ordering::Relaxed) + 1;
    if reads >= 1024 && reads.is_power_of_two() {
        tracing::info!(shard = %hex::encode(&shard[..shard.len().min(8)]), phase, reads,
            elapsed_secs = started.elapsed().as_secs(), "remote tree walk in progress");
    }
}
use jmt::storage::{LeafNode, Node, NodeKey, TreeReader};
use jmt::{KeyHash, OwnedValue, Version};

use crate::archive_client::ArchiveClient;

/// A remote view of ONE shard/phase tree on a peer archive, addressed by
/// `(shard_id, phase)`. Clone-cheap (the client shares one h2 channel).
pub struct RemoteTreeReader {
    source: Arc<dyn ForestReadSource>,
    handle: tokio::runtime::Handle,
    shard_id: Vec<u8>,
    phase: u32,
    /// Remote reads so far and when the walk started, for progress lines.
    reads: Arc<AtomicU64>,
    started: Instant,
    prefetch_version: Option<Version>,
    ahead: Mutex<ReadAhead>,
}

impl RemoteTreeReader {
    /// `handle` is the runtime to drive gRPC on; the reader must be *called*
    /// from a blocking thread (`spawn_blocking`), not a worker of `handle`.
    pub fn new(
        client: ArchiveClient,
        handle: tokio::runtime::Handle,
        shard_id: Vec<u8>,
        phase: u32,
    ) -> Self {
        Self::from_source(Arc::new(client), handle, shard_id, phase)
    }

    fn from_source(
        source: Arc<dyn ForestReadSource>,
        handle: tokio::runtime::Handle,
        shard_id: Vec<u8>,
        phase: u32,
    ) -> Self {
        Self {
            source,
            handle,
            shard_id,
            phase,
            reads: Arc::new(AtomicU64::new(0)),
            started: Instant::now(),
            prefetch_version: None,
            ahead: Mutex::new(ReadAhead::default()),
        }
    }

    /// Read ahead only for a full-tree cold sync. Incremental and subtree
    /// callers must keep demand reads so matching/out-of-scope branches stay
    /// unfetched. Leaf values are pinned to the same selected snapshot version.
    pub fn with_cold_prefetch(mut self, version: Version) -> Self {
        self.prefetch_version = Some(version);
        self
    }

    fn decode_limit(&self) -> usize {
        if self.prefetch_version.is_some() {
            PREFETCH_MAX_BYTES + 128
        } else {
            64 * 1024 * 1024
        }
    }

    fn prefetch_children(&self, key: &NodeKey, node: &Node) {
        let (Some(version), Node::Internal(internal)) = (self.prefetch_version, node) else {
            return;
        };
        let keys: Vec<_> = internal
            .children_sorted()
            .map(|(nibble, child)| key.gen_child_node_key(child.version, nibble))
            .filter_map(|key| borsh::to_vec(&key).ok())
            .filter(|key| {
                !self
                    .ahead
                    .lock()
                    .entries
                    .contains_key(&ReadKey::Node(key.clone()))
            })
            .collect();
        self.handle.block_on(async {
            for batch in keys.chunks(PREFETCH_CONCURRENCY) {
                let mut tasks = tokio::task::JoinSet::new();
                for key in batch {
                    let source = self.source.clone();
                    let shard = self.shard_id.clone();
                    let phase = self.phase;
                    let reads = self.reads.clone();
                    let started = self.started;
                    let key = key.clone();
                    tasks.spawn(async move {
                        counted(&reads, started, &shard, phase);
                        let node = source
                            .node(shard.clone(), phase, key.clone(), PREFETCH_MAX_BYTES + 128)
                            .await?;
                        let mut value = None;
                        if let Some(bytes) = &node {
                            if let Ok(Node::Leaf(leaf)) = borsh::from_slice::<Node>(bytes) {
                                counted(&reads, started, &shard, phase);
                                // A speculative failure is retried on demand;
                                // it cannot make an unused branch fatal.
                                if let Ok(bytes) = source
                                    .value(
                                        shard,
                                        phase,
                                        version,
                                        leaf.key_hash(),
                                        PREFETCH_MAX_BYTES + 128,
                                    )
                                    .await
                                {
                                    value =
                                        Some((ReadKey::Value(version, leaf.key_hash().0), bytes));
                                }
                            }
                        }
                        Ok::<_, anyhow::Error>((ReadKey::Node(key), node, value))
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    if let Ok(Ok((key, node, value))) = result {
                        let mut cache = self.ahead.lock();
                        cache.insert(key, node);
                        if let Some((key, value)) = value {
                            cache.insert(key, value);
                        }
                    }
                }
            }
        });
    }
}

impl TreeReader for RemoteTreeReader {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let key = borsh::to_vec(node_key)?;
        let cached = self.ahead.lock().take(&ReadKey::Node(key.clone()));
        let bytes = match cached {
            Some(bytes) => bytes,
            None => {
                counted(&self.reads, self.started, &self.shard_id, self.phase);
                self.handle.block_on(self.source.node(
                    self.shard_id.clone(),
                    self.phase,
                    key,
                    self.decode_limit(),
                ))?
            }
        };
        let node = bytes.map(|b| borsh::from_slice::<Node>(&b)).transpose()?;
        if let Some(node) = &node {
            self.prefetch_children(node_key, node);
        }
        Ok(node)
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        if let Some(value) = self
            .ahead
            .lock()
            .take(&ReadKey::Value(max_version, key_hash.0))
        {
            return Ok(value);
        }
        counted(&self.reads, self.started, &self.shard_id, self.phase);
        self.handle.block_on(self.source.value(
            self.shard_id.clone(),
            self.phase,
            max_version,
            key_hash,
            self.decode_limit(),
        ))
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        // Used only by jmt's restore path, which the Merkle-diff sync never
        // exercises — the diff walk addresses nodes explicitly.
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmt::{mock::MockTreeStore, JellyfishMerkleTree};
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    struct FakeSource {
        tree: MockTreeStore,
        calls: AtomicUsize,
        active: AtomicUsize,
        peak: AtomicUsize,
        fail_once: AtomicBool,
        corrupt_values: bool,
        limits: Mutex<Vec<usize>>,
    }

    impl FakeSource {
        fn new(corrupt_values: bool) -> Self {
            let tree = MockTreeStore::new(true);
            for version in 0..=1 {
                let kvs = (0..16).map(|i| {
                    let mut key = [0u8; 32];
                    key[0] = i * 16;
                    (KeyHash(key), Some(vec![i, version as u8]))
                });
                let (_, batch) = JellyfishMerkleTree::<_, sha2::Sha256>::new(&tree)
                    .put_value_set(kvs, version)
                    .unwrap();
                tree.write_tree_update_batch(batch).unwrap();
            }
            Self {
                tree,
                calls: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                fail_once: AtomicBool::new(false),
                corrupt_values,
                limits: Mutex::new(Vec::new()),
            }
        }
        async fn delay(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl ForestReadSource for FakeSource {
        async fn node(
            &self,
            _: Vec<u8>,
            _: u32,
            key: Vec<u8>,
            limit: usize,
        ) -> Result<Option<Vec<u8>>> {
            self.limits.lock().push(limit);
            self.delay().await;
            let key: NodeKey = borsh::from_slice(&key)?;
            // Fail one child read, not the demanded root. Prefetch must defer
            // the error and let the subsequent demand retry it.
            if key.nibble_path().num_nibbles() > 0 && self.fail_once.swap(false, Ordering::SeqCst) {
                anyhow::bail!("transient child read failure");
            }
            Ok(self
                .tree
                .get_node_option(&key)?
                .map(|n| borsh::to_vec(&n))
                .transpose()?)
        }
        async fn value(
            &self,
            _: Vec<u8>,
            _: u32,
            version: Version,
            key: KeyHash,
            limit: usize,
        ) -> Result<Option<Vec<u8>>> {
            self.limits.lock().push(limit);
            self.delay().await;
            let mut value = self.tree.get_value_option(version, key)?;
            if self.corrupt_values {
                if let Some(v) = &mut value {
                    v.push(0xff);
                }
            }
            Ok(value)
        }
    }

    async fn walk(
        source: Arc<FakeSource>,
        prefetch: bool,
    ) -> Result<(Vec<(KeyHash, OwnedValue)>, [u8; 32])> {
        let mut remote = RemoteTreeReader::from_source(
            source,
            tokio::runtime::Handle::current(),
            vec![0xff; 32],
            0,
        );
        if prefetch {
            remote = remote.with_cold_prefetch(0);
        }
        tokio::task::spawn_blocking(move || {
            let empty = MockTreeStore::new(true);
            quil_forest::diff_leaves_under_prefix(&remote, 0, &empty, 0, &[], None)
        })
        .await?
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cold_prefetch_matches_demand_reads_without_extra_requests() {
        let serial = Arc::new(FakeSource::new(false));
        let parallel = Arc::new(FakeSource::new(false));
        let start = Instant::now();
        let expected = walk(serial.clone(), false).await.unwrap();
        let serial_elapsed = start.elapsed();
        let start = Instant::now();
        let actual = walk(parallel.clone(), true).await.unwrap();
        let parallel_elapsed = start.elapsed();
        assert_eq!(actual, expected);
        assert_eq!(actual.0.len(), 16);
        assert!(
            actual.0.iter().all(|(_, v)| v[1] == 0),
            "snapshot version must remain pinned"
        );
        assert_eq!(
            serial.calls.load(Ordering::SeqCst),
            parallel.calls.load(Ordering::SeqCst)
        );
        assert!(serial
            .limits
            .lock()
            .iter()
            .all(|limit| *limit == 64 * 1024 * 1024));
        assert!(parallel
            .limits
            .lock()
            .iter()
            .all(|limit| *limit == PREFETCH_MAX_BYTES + 128));
        assert_eq!(serial.peak.load(Ordering::SeqCst), 1);
        assert!(parallel.peak.load(Ordering::SeqCst) > 1);
        assert!(parallel.peak.load(Ordering::SeqCst) <= PREFETCH_CONCURRENCY);
        eprintln!("same API cold walk: serial={serial_elapsed:?}, prefetch={parallel_elapsed:?}, reads={}",
            parallel.calls.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn speculative_failure_is_retried_on_demand() {
        let source = Arc::new(FakeSource::new(false));
        source.fail_once.store(true, Ordering::SeqCst);
        let leaves = walk(source.clone(), true).await.unwrap().0;
        assert_eq!(leaves.len(), 16);
        assert!(!source.fail_once.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prefetched_values_still_require_authentication() {
        for prefetch in [false, true] {
            let error = walk(Arc::new(FakeSource::new(true)), prefetch)
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("value does not match its committed leaf"),
                "{error}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn demand_mode_skips_matching_and_out_of_scope_branches() {
        let source = Arc::new(FakeSource::new(false));
        let remote = RemoteTreeReader::from_source(
            source.clone(),
            tokio::runtime::Handle::current(),
            vec![0xff; 32],
            0,
        );
        let same = source.clone();
        let leaves = tokio::task::spawn_blocking(move || {
            quil_forest::diff_leaves_under_prefix(&remote, 0, &same.tree, 0, &[], None)
        })
        .await
        .unwrap()
        .unwrap()
        .0;
        assert!(leaves.is_empty());
        assert_eq!(
            source.calls.load(Ordering::SeqCst),
            1,
            "matching branches must not be prefetched"
        );
        source.calls.store(0, Ordering::SeqCst);
        let remote = RemoteTreeReader::from_source(
            source.clone(),
            tokio::runtime::Handle::current(),
            vec![0xff; 32],
            0,
        );
        let leaves = tokio::task::spawn_blocking(move || {
            let empty = MockTreeStore::new(true);
            quil_forest::diff_leaves_under_prefix(&remote, 0, &empty, 0, &[false; 6], None)
        })
        .await
        .unwrap()
        .unwrap()
        .0;
        assert_eq!(leaves.len(), 1);
        assert_eq!(
            source.calls.load(Ordering::SeqCst),
            3,
            "only root, covered leaf and its value are needed"
        );
        assert_eq!(source.peak.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn read_ahead_bounds_bytes_metadata_and_consumption() {
        let mut cache = ReadAhead::default();
        cache.insert(ReadKey::Node(vec![1]), Some(vec![0; PREFETCH_MAX_BYTES]));
        assert!(
            cache.entries.is_empty(),
            "oversized entries include key bytes"
        );
        for i in 0..(PREFETCH_MAX_ENTRIES + 10) as u64 {
            cache.insert(ReadKey::Node(i.to_le_bytes().to_vec()), None);
        }
        assert_eq!(cache.entries.len(), PREFETCH_MAX_ENTRIES);
        assert!(cache.bytes <= PREFETCH_MAX_BYTES);
        assert_eq!(
            cache.take(&ReadKey::Node(0u64.to_le_bytes().to_vec())),
            Some(None)
        );
        assert_eq!(cache.entries.len(), PREFETCH_MAX_ENTRIES - 1);
        assert_eq!(
            cache.take(&ReadKey::Node(0u64.to_le_bytes().to_vec())),
            None
        );
        cache.insert(
            ReadKey::Value(0, [0; 32]),
            Some(vec![0; PREFETCH_MAX_BYTES - cache.bytes - 40]),
        );
        assert_eq!(cache.bytes, PREFETCH_MAX_BYTES);
        cache.insert(ReadKey::Value(0, [1; 32]), Some(vec![1]));
        assert!(!cache.entries.contains_key(&ReadKey::Value(0, [1; 32])));
    }
}
