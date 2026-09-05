//! Tree stores for the forest: an in-memory store (bench/tests) and a
//! RocksDB store scoped to one tree by a [`TreeId`] prefix, plus the
//! [`ForestStore`] extension that persists JMT's stale-node index so a
//! later [`ForestStore::prune`] can reclaim overwritten nodes.
//!
//! JMT's `put_value_set` returns a `TreeUpdateBatch` whose
//! `stale_node_index_batch` records, for every node the write superseded,
//! the version at which it became unreachable. Persisting those records is
//! the whole basis for pruning: to drop all history readable only below
//! version `V`, delete every node whose `stale_since_version <= V` (and the
//! record itself). The base spike discarded that index, so it could grow
//! but never shrink — this module closes that gap.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use anyhow::Result;
use jmt::storage::{
    LeafNode, NibblePath, Node, NodeBatch, NodeKey, StaleNodeIndex, TreeReader, TreeUpdateBatch, TreeWriter,
};
use jmt::{KeyHash, OwnedValue, Version};

use crate::TreeId;

/// A store that can persist a full JMT [`TreeUpdateBatch`] (nodes, values,
/// and the stale-node index) and later prune superseded nodes. This is the
/// capability the forest needs beyond raw [`TreeReader`]/[`TreeWriter`]:
/// bounded on-disk growth for a mutable, versioned tree.
pub trait ForestStore: TreeReader + TreeWriter {
    /// Persist a commit's node/value batch **and** its stale-node index.
    /// Nodes and values go in via the normal writer path; the stale records
    /// are indexed by `stale_since_version` so [`prune`](Self::prune) can
    /// range-scan them.
    fn apply_update(&self, batch: &TreeUpdateBatch) -> Result<()>;

    /// Reclaim every node marked stale at or before `min_readable_version`
    /// — i.e. every node no read at a version `>= min_readable_version` can
    /// reach — together with its stale record. Returns the node count
    /// reclaimed. Nodes stale only at higher versions are retained so reads
    /// pinned below the watermark still resolve.
    fn prune(&self, min_readable_version: Version) -> Result<usize>;
}

// ===========================================================================
// In-memory store
// ===========================================================================

/// A minimal in-memory [`TreeReader`]/[`TreeWriter`], mirroring JMT's own
/// mock store but without the `mocks` feature. Used by the CPU bench so the
/// hash-vs-KZG comparison excludes disk I/O, and by unit tests.
#[derive(Default)]
pub struct MemTreeStore {
    nodes: RwLock<HashMap<NodeKey, Node>>,
    values: RwLock<HashMap<KeyHash, Vec<(Version, Option<OwnedValue>)>>>,
    /// Stale records keyed by `(stale_since_version, node_key)` for pruning.
    stale: RwLock<BTreeMap<(Version, NodeKey), ()>>,
    /// Per-node memoized subtree size sums (the in-memory analogue of the
    /// RocksDB [`TAG_SIZE`] side column).
    sizes: RwLock<HashMap<NodeKey, u128>>,
}

impl SizeIndex for MemTreeStore {
    fn get_size_sum(&self, node_key: &NodeKey) -> Result<Option<u128>> {
        Ok(self.sizes.read().unwrap().get(node_key).copied())
    }

    fn put_size_sum(&self, node_key: &NodeKey, size: u128) -> Result<()> {
        self.sizes.write().unwrap().insert(node_key.clone(), size);
        Ok(())
    }
}

impl MemTreeStore {
    /// Wipe the whole tree back to empty (the in-memory analogue of
    /// [`RocksTreeStore::clear`]). Used by the shard-scoped prover-tree reset.
    pub fn clear(&self) {
        self.nodes.write().unwrap().clear();
        self.values.write().unwrap().clear();
        self.stale.write().unwrap().clear();
        self.sizes.write().unwrap().clear();
    }
}

impl TreeReader for MemTreeStore {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        Ok(self.nodes.read().unwrap().get(node_key).cloned())
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        Ok(self.values.read().unwrap().get(&key_hash).and_then(|hist| {
            hist.iter()
                .rev()
                .find(|(v, _)| *v <= max_version)
                .and_then(|(_, val)| val.clone())
        }))
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        // Only used during tree restore, which the forest does not use.
        Ok(None)
    }
}

impl TreeWriter for MemTreeStore {
    fn write_node_batch(&self, batch: &NodeBatch) -> Result<()> {
        let mut nodes = self.nodes.write().unwrap();
        for (k, n) in batch.nodes() {
            nodes.insert(k.clone(), n.clone());
        }
        drop(nodes);
        let mut values = self.values.write().unwrap();
        for ((version, key_hash), val) in batch.values() {
            let hist = values.entry(*key_hash).or_default();
            match hist.last_mut() {
                Some((lv, lval)) if *lv == *version => *lval = val.clone(),
                _ => hist.push((*version, val.clone())),
            }
        }
        drop(values);
        // Maintain the size index in lockstep (nodes + values are now visible
        // to the child/value lookups inside `batch_size_sums`).
        let sums = batch_size_sums(self, batch)?;
        let mut sizes = self.sizes.write().unwrap();
        for (nk, s) in sums {
            sizes.insert(nk, s);
        }
        Ok(())
    }
}

impl ForestStore for MemTreeStore {
    fn apply_update(&self, batch: &TreeUpdateBatch) -> Result<()> {
        self.write_node_batch(&batch.node_batch)?;
        let mut stale = self.stale.write().unwrap();
        for idx in &batch.stale_node_index_batch {
            stale.insert((idx.stale_since_version, idx.node_key.clone()), ());
        }
        Ok(())
    }

    fn prune(&self, min_readable_version: Version) -> Result<usize> {
        // Collect the keys to drop first to avoid holding both locks. The map
        // is version-ordered, so we can stop at the first record above the
        // watermark.
        let doomed: Vec<(Version, NodeKey)> = {
            let stale = self.stale.read().unwrap();
            stale
                .keys()
                .take_while(|(v, _)| *v <= min_readable_version)
                .cloned()
                .collect()
        };
        let mut nodes = self.nodes.write().unwrap();
        let mut stale = self.stale.write().unwrap();
        let mut reclaimed = 0usize;
        for (v, nk) in doomed {
            if nodes.remove(&nk).is_some() {
                reclaimed += 1;
            }
            stale.remove(&(v, nk));
        }
        Ok(reclaimed)
    }
}

// ===========================================================================
// RocksDB store — one shared DB, per-tree-id namespacing.
// ===========================================================================

const TAG_NODE: u8 = b'n';
const TAG_VALUE: u8 = b'v';
/// Stale-node index tag: `prefix ++ 's' ++ stale_since_version_be(8) ++
/// borsh(node_key)`. The version prefix makes "prune everything stale at or
/// before V" a single ordered range scan.
const TAG_STALE: u8 = b's';
/// Preimage tag: `prefix ++ 'p' ++ key_hash(32) -> raw l3 leaf key`. JMT keys
/// leaves by `SHA-256(l3_leaf_key)`, discarding the raw key; the sync needs it
/// to map a diff's changed leaves back to their `(vertex_id, field_key)` so it
/// can fetch the changed vertices' blobs. Written at commit time (which has the
/// raw keys); read by the sync server.
const TAG_PREIMAGE: u8 = b'p';
/// Merkle-sum size-index tag: `prefix ++ 'z' ++ borsh(node_key) -> u128 BE`.
/// A per-node memo of the summed leaf `size` (each vertex leaf's `[32..40]`
/// u64, via [`crate::vertex_leaf_size`]) under that node. JMT maintains a
/// per-node `leaf_count` natively but NOT size; this recovers the verkle-style
/// per-branch size aggregate the QUIL shard/reward basis needs, WITHOUT
/// changing any node hash — it is off-consensus, local telemetry only. Keyed
/// by the version-stamped [`NodeKey`], so an unchanged subtree's memo stays
/// valid across later commits (JMT is copy-on-write): a read after an insert
/// recomputes only the freshly-rewritten root-to-leaf path, reusing every
/// cached sibling, so per-shard size is O(depth) once warm instead of the
/// O(all-leaves) rescan `rebucket_app` does today.
const TAG_SIZE: u8 = b'z';

/// Nodes per `WriteBatch` flush during the one-time size-index backfill
/// ([`RocksTreeStore::seed_size_index_batched`]). Large enough to amortize the
/// per-batch WAL write across many nodes, small enough to bound peak memory.
const SEED_BATCH: usize = 65_536;

/// A store that can memoize per-node subtree size sums (the [`TAG_SIZE`]
/// side column). Split from [`TreeReader`] so the generic
/// [`crate::subtree_size`] / [`crate::node_size_sum`] walkers work over both
/// the RocksDB store and the in-memory test store.
pub trait SizeIndex {
    /// The memoized summed leaf size under `node_key`, or `None` if not yet
    /// computed.
    fn get_size_sum(&self, node_key: &NodeKey) -> Result<Option<u128>>;
    /// Memoize `size` as the summed leaf size under `node_key`.
    fn put_size_sum(&self, node_key: &NodeKey, size: u128) -> Result<()>;
}

/// Compute the `size_sum` for **every** node in a commit's [`NodeBatch`],
/// bottom-up, so the [`TAG_SIZE`] side index can be persisted in the SAME
/// atomic write as the nodes it summarizes. This is what keeps the Merkle-sum
/// size index permanently warm at head: each freshly-written node gets its sum
/// computed from its children's sums right now — the children are either in
/// this batch (a child's nibble path is its parent's plus one nibble, so
/// deepest-first ordering computes them before their parent) or already carry a
/// persisted sum from an earlier commit. Without this, the index was populated
/// only lazily on read; after an epoch of churn essentially every node at head
/// was a fresh (unmemoized) `NodeKey`, so the next `rebucket_app` degenerated
/// into a cold O(all-leaves) re-walk with random I/O — the epoch-boundary halt.
///
/// The `node_size_sum` fallback (a cold child not yet in the index) only fires
/// before the one-time [`crate::Forest::seed_size_index`] backfill has run over
/// a pre-existing tree; it self-heals by memoizing what it visits. Once the
/// tree is seeded, every child is a hit and this is O(nodes written per frame).
pub(crate) fn batch_size_sums<S: TreeReader + SizeIndex>(
    store: &S,
    batch: &NodeBatch,
) -> Result<Vec<(NodeKey, u128)>> {
    // Deepest nibble path first: a child's path is its parent's + one nibble,
    // so processing longest paths first guarantees each internal node's
    // in-batch children are already computed when we reach it.
    let mut ordered: Vec<(&NodeKey, &Node)> = batch.nodes().iter().collect();
    ordered.sort_by(|a, b| {
        b.0.nibble_path()
            .num_nibbles()
            .cmp(&a.0.nibble_path().num_nibbles())
    });
    let mut computed: HashMap<NodeKey, u128> = HashMap::with_capacity(ordered.len());
    let mut out: Vec<(NodeKey, u128)> = Vec::with_capacity(ordered.len());
    for (nk, node) in ordered {
        let s: u128 = match node {
            Node::Null => 0,
            Node::Leaf(leaf) => {
                let kh = leaf.key_hash();
                // The leaf's value is normally written in THIS commit; if the
                // node moved version without its value changing (a sibling
                // insert re-keys the leaf), read the still-current value.
                let val = match batch.values().get(&(nk.version(), kh)) {
                    Some(Some(v)) => Some(v.clone()),
                    Some(None) => None, // tombstone written this commit
                    None => store.get_value_option(nk.version(), kh)?,
                };
                val.map(|b| crate::vertex_leaf_size(&b)).unwrap_or(0)
            }
            Node::Internal(int) => {
                let mut acc = 0u128;
                for (nibble, child) in int.children_sorted() {
                    let ck = nk.gen_child_node_key(child.version, nibble);
                    let cs = match computed.get(&ck) {
                        Some(v) => *v,
                        None => match store.get_size_sum(&ck)? {
                            Some(v) => v,
                            None => crate::node_size_sum(store, &ck)?,
                        },
                    };
                    acc = acc.saturating_add(cs);
                }
                acc
            }
        };
        computed.insert(nk.clone(), s);
        out.push((nk.clone(), s));
    }
    Ok(out)
}

/// A [`TreeReader`]/[`TreeWriter`]/[`ForestStore`] over a shared RocksDB,
/// scoped to one tree by a [`TreeId`] prefix. Node keys:
/// `prefix ++ 'n' ++ borsh(NodeKey)`. Value keys:
/// `prefix ++ 'v' ++ key_hash[32] ++ version_be[8]`, so the newest value
/// `<= max_version` is a single reverse seek. This is the adapter that lets
/// thousands of independent forest trees live in one DB.
pub struct RocksTreeStore {
    db: Arc<rocksdb::DB>,
    prefix: Vec<u8>,
}

impl RocksTreeStore {
    /// Standalone forest DB: keys are `TreeId::prefix ++ …`, starting at the
    /// tree-level byte (`0x01/0x02/0x03`). Use [`with_namespace`] when the
    /// forest shares a DB with other data whose keys could collide with those
    /// level bytes.
    pub fn new(db: Arc<rocksdb::DB>, tree: &TreeId) -> Self {
        Self::with_namespace(db, &[], tree)
    }

    /// Forest embedded in a shared DB: every key is prefixed by `namespace`
    /// (a reserved byte-string the surrounding schema never emits), so the
    /// whole forest occupies one disjoint sub-range and cannot collide with
    /// the node's clock / shard / registry keys. All node/value/stale keys
    /// inherit it via `self.prefix`.
    pub fn with_namespace(db: Arc<rocksdb::DB>, namespace: &[u8], tree: &TreeId) -> Self {
        let mut prefix = Vec::with_capacity(namespace.len() + 2 + tree.id.len());
        prefix.extend_from_slice(namespace);
        prefix.extend_from_slice(&tree.prefix());
        RocksTreeStore { db, prefix }
    }

    fn node_key_bytes(&self, node_key: &NodeKey) -> Vec<u8> {
        let mut k = self.prefix.clone();
        k.push(TAG_NODE);
        k.extend_from_slice(&borsh::to_vec(node_key).expect("NodeKey borsh"));
        k
    }

    fn value_prefix(&self, key_hash: &KeyHash) -> Vec<u8> {
        let mut k = self.prefix.clone();
        k.push(TAG_VALUE);
        k.extend_from_slice(&key_hash.0);
        k
    }

    fn size_key_bytes(&self, node_key: &NodeKey) -> Vec<u8> {
        let mut k = self.prefix.clone();
        k.push(TAG_SIZE);
        k.extend_from_slice(&borsh::to_vec(node_key).expect("NodeKey borsh"));
        k
    }

    /// A read-only iterator tuned for a one-shot sequential sweep of a tag range:
    /// checksums off (this rebuilds a LOCAL side index — a corrupt block would fail
    /// borsh decode anyway, and XXH3 was ~3% of the boot CPU), block cache untouched
    /// (a full-tree sweep must not evict the live working set), and a wide readahead
    /// so the kernel streams whole SST files instead of faulting a block at a time.
    fn seq_iter(&self, tag: u8) -> (rocksdb::DBRawIterator<'_>, Vec<u8>) {
        let mut lo = self.prefix.clone();
        lo.push(tag);
        let mut hi = self.prefix.clone();
        hi.push(tag + 1); // next tag byte — exclusive upper bound
        let mut ro = rocksdb::ReadOptions::default();
        ro.set_verify_checksums(false);
        ro.fill_cache(false);
        ro.set_readahead_size(8 << 20);
        let mut it = self.db.raw_iterator_opt(ro);
        it.seek(&lo);
        (it, hi)
    }

    /// One-time backfill of the `TAG_SIZE` Merkle-sum index over the whole tree at
    /// `version` — the FAST path for the boot seed.
    ///
    /// The obvious implementation, a top-down recursive walk, is pathological here:
    /// node keys sort by `(version, num_nibbles, path)`, so a node and its children
    /// sit in DISJOINT regions of the keyspace (they differ in `num_nibbles`). A
    /// depth-first walk therefore bounces between regions on every step, and since
    /// each ~KB SST block holds hundreds of nodes it gets evicted and re-decompressed
    /// O(depth) times — on NVMe the disk is idle and the CPU melts in LZ4 (the
    /// multi-day archive boot: ~300 nodes/s, 27% in `LZ4_decompress`). Parallelism
    /// only multiplies the block-cache thrash and allocator/memcg contention.
    ///
    /// Instead: two SEQUENTIAL scans (each block decompressed exactly once), then a
    /// bottom-up compute entirely in memory —
    ///   1. sweep the value column → `key_hash → live leaf size` (latest write
    ///      `<= version`; tombstone ⇒ 0);
    ///   2. sweep the node column: LEAF sizes resolve immediately from (1) and are
    ///      written inline; INTERNAL nodes are stashed with their child keys;
    ///   3. sort the stashed internals by `num_nibbles` DESCENDING — a child always
    ///      has one more nibble than its parent, so deepest-first guarantees every
    ///      child's size is known before its parent (the same topological order
    ///      [`batch_size_sums`] uses) — and sum each from its children.
    /// All writes go through `WriteBatch`es flushed every [`SEED_BATCH`] nodes. Peak
    /// memory is one `u128`/leaf plus the internal adjacency (internals are ~1/15th
    /// of nodes), i.e. a few GB for a ~100M-node tree — fine for an archive host, and
    /// the trade that turns days of random I/O into minutes of sequential streaming.
    ///
    /// Resumable at the whole-tree granularity via the root memo (mid-seed crashes
    /// re-run from scratch, but the run is now minutes). Returns the tree's total
    /// size; caller flushes + sets its `seeded` marker AFTER this returns.
    /// `on_flush(cumulative_nodes_written)` fires per batch flush for a live heartbeat.
    pub fn seed_size_index_batched(
        &self,
        version: u64,
        on_flush: &(dyn Fn(u64) + Sync),
    ) -> Result<u128> {
        let root_key = NodeKey::new(version, NibblePath::new(vec![]));
        // Whole-tree resume: root memo present ⇒ already seeded.
        if let Some(s) = self.get_size_sum(&root_key)? {
            on_flush(0);
            return Ok(s);
        }

        // ---- Pass 1: value column → live leaf size by key_hash. -------------
        // Keys: prefix ++ 'v' ++ key_hash(32) ++ version_be(8); values sort ascending
        // by version within a key_hash, so the last entry `<= version` wins.
        let khs = self.prefix.len() + 1;
        let mut leaf_size: HashMap<[u8; 32], u128> = HashMap::new();
        {
            let (mut it, hi) = self.seq_iter(TAG_VALUE);
            while it.valid() {
                let k = match it.key() {
                    Some(k) if k < hi.as_slice() => k,
                    _ => break,
                };
                if k.len() >= khs + 40 {
                    let mut vb = [0u8; 8];
                    vb.copy_from_slice(&k[khs + 32..khs + 40]);
                    if u64::from_be_bytes(vb) <= version {
                        let mut kh = [0u8; 32];
                        kh.copy_from_slice(&k[khs..khs + 32]);
                        // Payload: 0x01 ++ value, or 0x00/empty tombstone.
                        let sz = match it.value() {
                            Some(v) if v.first() == Some(&0x01) => crate::vertex_leaf_size(&v[1..]),
                            _ => 0,
                        };
                        leaf_size.insert(kh, sz);
                    }
                }
                it.next();
            }
        }

        // ---- Pass 2: node column → write leaf sizes, stash internals. -------
        let mut node_size: HashMap<NodeKey, u128> = HashMap::new();
        let mut internals: Vec<(NodeKey, Vec<NodeKey>)> = Vec::new();
        let mut wb = rocksdb::WriteBatch::default();
        let mut pending = 0u64;
        let mut written = 0u64;
        {
            let (mut it, hi) = self.seq_iter(TAG_NODE);
            while it.valid() {
                let (k, v) = match (it.key(), it.value()) {
                    (Some(k), Some(v)) if k < hi.as_slice() => (k, v),
                    _ => break,
                };
                let nk: NodeKey = borsh::from_slice(&k[khs..])?;
                match borsh::from_slice::<Node>(v)? {
                    Node::Null => {}
                    Node::Leaf(leaf) => {
                        let s = leaf_size.get(&leaf.key_hash().0).copied().unwrap_or(0);
                        node_size.insert(nk.clone(), s);
                        wb.put(self.size_key_bytes(&nk), s.to_be_bytes());
                        pending += 1;
                    }
                    Node::Internal(int) => {
                        let kids = int
                            .children_sorted()
                            .map(|(nibble, child)| nk.gen_child_node_key(child.version, nibble))
                            .collect();
                        internals.push((nk, kids));
                    }
                }
                if pending >= SEED_BATCH as u64 {
                    self.db.write(std::mem::take(&mut wb))?;
                    written += pending;
                    pending = 0;
                    on_flush(written);
                }
                it.next();
            }
        }
        drop(leaf_size); // no longer needed once leaves are summed

        // ---- Pass 3: sum internals bottom-up (deepest nibble path first). ---
        internals.sort_unstable_by(|a, b| {
            b.0.nibble_path()
                .num_nibbles()
                .cmp(&a.0.nibble_path().num_nibbles())
        });
        let mut root_size = 0u128;
        for (nk, kids) in &internals {
            let mut acc = 0u128;
            for ck in kids {
                acc = acc.saturating_add(node_size.get(ck).copied().unwrap_or(0));
            }
            node_size.insert(nk.clone(), acc);
            wb.put(self.size_key_bytes(nk), acc.to_be_bytes());
            pending += 1;
            if nk.nibble_path().num_nibbles() == 0 {
                root_size = acc; // the root (empty path) — its sum is the tree total
            }
            if pending >= SEED_BATCH as u64 {
                self.db.write(std::mem::take(&mut wb))?;
                written += pending;
                pending = 0;
                on_flush(written);
            }
        }
        // A single-leaf tree has no internal root: take the root memo directly.
        if internals.iter().all(|(nk, _)| nk.nibble_path().num_nibbles() != 0) {
            root_size = node_size.get(&root_key).copied().unwrap_or(0);
        }

        self.db.write(std::mem::take(&mut wb))?;
        written += pending;
        // Force memtable→SST so the index is durable BEFORE the caller sets the
        // `seeded` marker (else a crash could leave the marker over an index still
        // only in an unflushed memtable).
        self.db.flush()?;
        on_flush(written);
        Ok(root_size)
    }

    /// The preimage key for a leaf's `KeyHash` (see [`TAG_PREIMAGE`]).
    pub fn preimage_key(&self, key_hash: &KeyHash) -> Vec<u8> {
        let mut k = self.prefix.clone();
        k.push(TAG_PREIMAGE);
        k.extend_from_slice(&key_hash.0);
        k
    }

    /// The `(key, value)` put recording that `raw_key` hashes to its `KeyHash` —
    /// staged alongside the tree's node/value puts so a later sync can recover
    /// the raw l3 key from a diff's `KeyHash`.
    pub fn preimage_put(&self, raw_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let kh = KeyHash::with::<sha2::Sha256>(raw_key);
        (self.preimage_key(&kh), raw_key.to_vec())
    }

    /// Read the raw l3 leaf key a `KeyHash` was committed from, if recorded.
    pub fn get_preimage(&self, key_hash: &KeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self.db.get(self.preimage_key(key_hash))?)
    }

    /// Write a leaf's raw-key preimage directly (for the migration converter,
    /// which commits outside a staged batch).
    pub fn put_preimage(&self, raw_key: &[u8]) -> Result<()> {
        let (k, v) = self.preimage_put(raw_key);
        self.db.put(k, v)?;
        Ok(())
    }

    /// Delete EVERY key of this tree — nodes, values, stale index, preimages,
    /// and the head-version marker all live under `self.prefix`, so a single
    /// range delete wipes the tree back to empty (next commit rebuilds from
    /// version 0). Used by the shard-scoped prover-tree reset. NOT for pruning
    /// (which keeps the live version) — this discards the whole tree.
    pub fn clear(&self) -> Result<()> {
        let lower = self.prefix.clone();
        // Exclusive upper bound covering all `prefix`-prefixed keys: increment
        // the last byte < 0xFF, dropping trailing 0xFF bytes. `prefix` starts
        // with the non-0xFF tree-level byte, so an upper bound always exists.
        let upper = {
            let mut u = self.prefix.clone();
            while matches!(u.last(), Some(&0xff)) {
                u.pop();
            }
            match u.last_mut() {
                Some(b) => {
                    *b += 1;
                    u
                }
                None => return Ok(()), // empty prefix — nothing scoped to clear
            }
        };
        let mut wb = rocksdb::WriteBatch::default();
        wb.delete_range(&lower, &upper);
        self.db.write(wb)?;
        Ok(())
    }

    /// Delete this tree's entire `TAG_SIZE` Merkle-sum side index (leaving the
    /// nodes/values intact), forcing the next [`seed_size_index_batched`] to do a
    /// full cold re-seed. Used to (re)build the index for a legacy tree written
    /// before the index existed, and by tests to exercise the cold seed path.
    pub fn clear_size_index(&self) -> Result<()> {
        let mut lower = self.prefix.clone();
        lower.push(TAG_SIZE);
        let mut upper = self.prefix.clone();
        upper.push(TAG_SIZE + 1); // TAG_SIZE ('z') + 1 — exclusive upper bound
        let mut wb = rocksdb::WriteBatch::default();
        wb.delete_range(&lower, &upper);
        self.db.write(wb)?;
        Ok(())
    }

    fn stale_key_bytes(&self, idx: &StaleNodeIndex) -> Vec<u8> {
        let nk = borsh::to_vec(&idx.node_key).expect("NodeKey borsh");
        let mut k = Vec::with_capacity(self.prefix.len() + 1 + 8 + nk.len());
        k.extend_from_slice(&self.prefix);
        k.push(TAG_STALE);
        k.extend_from_slice(&idx.stale_since_version.to_be_bytes());
        k.extend_from_slice(&nk);
        k
    }

    /// Lower/upper bounds of this tree's stale-index keyspace.
    fn stale_scan_bounds(&self) -> (Vec<u8>, Vec<u8>) {
        let mut lo = self.prefix.clone();
        lo.push(TAG_STALE);
        let mut hi = lo.clone();
        // `TAG_STALE` (=='s') + 1: the next tag byte, an exclusive upper bound.
        *hi.last_mut().unwrap() = TAG_STALE + 1;
        (lo, hi)
    }
}

impl SizeIndex for RocksTreeStore {
    fn get_size_sum(&self, node_key: &NodeKey) -> Result<Option<u128>> {
        match self.db.get(self.size_key_bytes(node_key))? {
            Some(b) if b.len() == 16 => {
                Ok(Some(u128::from_be_bytes(b.as_slice().try_into().unwrap())))
            }
            _ => Ok(None),
        }
    }

    fn put_size_sum(&self, node_key: &NodeKey, size: u128) -> Result<()> {
        self.db.put(self.size_key_bytes(node_key), size.to_be_bytes())?;
        Ok(())
    }
}

impl TreeReader for RocksTreeStore {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        match self.db.get(self.node_key_bytes(node_key))? {
            Some(bytes) => Ok(Some(borsh::from_slice::<Node>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let vp = self.value_prefix(&key_hash);
        let mut seek = vp.clone();
        seek.extend_from_slice(&max_version.to_be_bytes());
        let mut it = self.db.raw_iterator();
        it.seek_for_prev(&seek);
        if !it.valid() {
            return Ok(None);
        }
        let k = match it.key() {
            Some(k) => k,
            None => return Ok(None),
        };
        // Must still be the same key_hash bucket (prefix match).
        if !k.starts_with(&vp) {
            return Ok(None);
        }
        match it.value() {
            // payload: 0x00 = tombstone (deleted), 0x01 ++ value.
            Some([0x00]) | Some([]) => Ok(None),
            Some(v) if v[0] == 0x01 => Ok(Some(v[1..].to_vec())),
            _ => Ok(None),
        }
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        Ok(None)
    }
}

impl TreeWriter for RocksTreeStore {
    fn write_node_batch(&self, batch: &NodeBatch) -> Result<()> {
        let mut wb = rocksdb::WriteBatch::default();
        for (node_key, node) in batch.nodes() {
            wb.put(self.node_key_bytes(node_key), borsh::to_vec(node)?);
        }
        for ((version, key_hash), val) in batch.values() {
            let mut k = self.value_prefix(key_hash);
            k.extend_from_slice(&version.to_be_bytes());
            let payload = match val {
                Some(v) => {
                    let mut p = Vec::with_capacity(1 + v.len());
                    p.push(0x01);
                    p.extend_from_slice(v);
                    p
                }
                None => vec![0x00],
            };
            wb.put(k, payload);
        }
        // Maintain the Merkle-sum size index in lockstep with the nodes.
        for (nk, s) in batch_size_sums(self, batch)? {
            wb.put(self.size_key_bytes(&nk), s.to_be_bytes());
        }
        self.db.write(wb)?;
        Ok(())
    }
}

impl RocksTreeStore {
    /// Build the raw `(key, value)` puts for a commit (nodes, values, and the
    /// stale-node index). **Every** forest commit write is a put — deletes only
    /// happen during [`prune`](ForestStore::prune) — so a caller can stage
    /// these into ANY key-value transaction, e.g. the hypergraph CRDT's
    /// `Transaction::set`, without this crate depending on that transaction
    /// type. This is how forest writes join the CRDT's atomic batch (the one
    /// that also carries the durable materialization cursor).
    pub fn update_puts(&self, batch: &TreeUpdateBatch) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        for (node_key, node) in batch.node_batch.nodes() {
            out.push((self.node_key_bytes(node_key), borsh::to_vec(node)?));
        }
        for ((version, key_hash), val) in batch.node_batch.values() {
            let mut k = self.value_prefix(key_hash);
            k.extend_from_slice(&version.to_be_bytes());
            let payload = match val {
                Some(v) => {
                    let mut p = Vec::with_capacity(1 + v.len());
                    p.push(0x01);
                    p.extend_from_slice(v);
                    p
                }
                None => vec![0x00],
            };
            out.push((k, payload));
        }
        for idx in &batch.stale_node_index_batch {
            // Value is empty — the key carries everything the pruner needs.
            out.push((self.stale_key_bytes(idx), Vec::new()));
        }
        // Stage the Merkle-sum size index alongside the nodes/values so the
        // side column is written in the SAME atomic batch as the commit it
        // summarizes (the CRDT's cursor-carrying write). Keeps head warm.
        for (nk, s) in batch_size_sums(self, &batch.node_batch)? {
            out.push((self.size_key_bytes(&nk), s.to_be_bytes().to_vec()));
        }
        Ok(out)
    }

    /// Stage a commit's nodes/values/stale-index into `wb` instead of writing
    /// immediately, so forest writes land atomically with the caller's own
    /// batch. Convenience over [`update_puts`](Self::update_puts) for callers
    /// that already hold a `rocksdb::WriteBatch`.
    pub fn stage_update(
        &self,
        wb: &mut rocksdb::WriteBatch,
        batch: &TreeUpdateBatch,
    ) -> Result<()> {
        for (k, v) in self.update_puts(batch)? {
            wb.put(k, v);
        }
        Ok(())
    }
}

impl ForestStore for RocksTreeStore {
    fn apply_update(&self, batch: &TreeUpdateBatch) -> Result<()> {
        // Nodes, values, and stale records all land in one atomic write.
        let mut wb = rocksdb::WriteBatch::default();
        self.stage_update(&mut wb, batch)?;
        self.db.write(wb)?;
        Ok(())
    }

    fn prune(&self, min_readable_version: Version) -> Result<usize> {
        let (lo, hi) = self.stale_scan_bounds();
        // Collect stale records with stale_since_version <= min first.
        let mut doomed_nodes: Vec<Vec<u8>> = Vec::new();
        let mut doomed_sizes: Vec<Vec<u8>> = Vec::new();
        let mut doomed_stale: Vec<Vec<u8>> = Vec::new();
        {
            let mut it = self.db.raw_iterator();
            it.seek(&lo);
            let vstart = self.prefix.len() + 1; // after prefix + TAG_STALE
            while it.valid() {
                let k = match it.key() {
                    Some(k) if k < hi.as_slice() => k,
                    _ => break,
                };
                // Parse the 8-byte stale_since_version prefix.
                if k.len() < vstart + 8 {
                    it.next();
                    continue;
                }
                let mut vb = [0u8; 8];
                vb.copy_from_slice(&k[vstart..vstart + 8]);
                let stale_since = Version::from_be_bytes(vb);
                if stale_since > min_readable_version {
                    // Records are version-ordered; nothing beyond is prunable.
                    break;
                }
                // Reconstruct the node key: prefix ++ 'n' ++ borsh(node_key).
                // The borsh(node_key) bytes are exactly the tail after the
                // 8-byte version.
                let nk_borsh = &k[vstart + 8..];
                let mut node_k = self.prefix.clone();
                node_k.push(TAG_NODE);
                node_k.extend_from_slice(nk_borsh);
                doomed_nodes.push(node_k);
                // The parallel size-index memo (TAG_SIZE) for the same NodeKey
                // is pruned in lockstep so the side column can't outgrow the
                // node column.
                let mut size_k = self.prefix.clone();
                size_k.push(TAG_SIZE);
                size_k.extend_from_slice(nk_borsh);
                doomed_sizes.push(size_k);
                doomed_stale.push(k.to_vec());
                it.next();
            }
        }
        let mut wb = rocksdb::WriteBatch::default();
        for nk in &doomed_nodes {
            wb.delete(nk);
        }
        for sk in &doomed_sizes {
            wb.delete(sk);
        }
        for sk in &doomed_stale {
            wb.delete(sk);
        }
        self.db.write(wb)?;
        Ok(doomed_nodes.len())
    }
}
