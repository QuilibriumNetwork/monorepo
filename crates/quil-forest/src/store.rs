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
    LeafNode, Node, NodeBatch, NodeKey, StaleNodeIndex, TreeReader, TreeUpdateBatch, TreeWriter,
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
