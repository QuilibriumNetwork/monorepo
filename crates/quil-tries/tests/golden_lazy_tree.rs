//! Golden snapshot tests for `LazyVectorCommitmentTree`.
//!
//! These tests pin down the externally-observable behaviour of the
//! tree across the swap from "load whole tree as blob" to "per-node
//! lazy walk." The math (KZG/SHA-512 commitments, prefix-compressed
//! radix-64 tree shape) is identical in both implementations, so the
//! captured invariants — root commitment, per-key get values, size,
//! `(leaf_count, longest_branch)` — must come out byte-for-byte
//! identical.
//!
//! ## Workflow
//!
//! 1. The `_capture_*` tests (all marked `#[ignore]`) build a tree from
//!    deterministic inputs and `eprintln!` the captured invariants in
//!    a paste-able format. Run with:
//!    ```
//!    cargo test -p quil-tries --test golden_lazy_tree -- \
//!        --ignored --nocapture
//!    ```
//! 2. The hex strings inside `GoldenVector::*` constants below were
//!    captured from the legacy (whole-tree-blob) implementation. Any
//!    drift in either implementation flips the corresponding test.
//! 3. After the per-node port lands, the same constants must still
//!    match. If they don't, the port has changed observable behaviour.
//!
//! Test data is generated via a tiny deterministic stream
//! (`KeyStream`) so the inputs themselves are reproducible without
//! seeding an RNG crate.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use num_bigint::BigInt;
use quil_tries::{LazyVectorCommitmentTree, NodeMetadata};
use quil_types::crypto::{InclusionProver, Multiproof};
use quil_types::error::{QuilError, Result};
use quil_types::store::{
    ChangeRecord, HypergraphStore, ShardKey, SnapshotReadable, Transaction,
};
use sha2::{Digest as Sha2Digest, Sha512};

// ---------------------------------------------------------------------------
// Deterministic test data generator
// ---------------------------------------------------------------------------

/// Pseudo-random byte stream seeded by `seed`. NOT cryptographically
/// random — just a stable function so test inputs reproduce across
/// machines without a `rand` dev-dep. Each call extends the internal
/// state with SHA-512 and yields the next 32 bytes.
struct KeyStream {
    state: [u8; 64],
}

impl KeyStream {
    fn new(seed: &[u8]) -> Self {
        let mut state = [0u8; 64];
        let h = Sha512::digest(seed);
        state.copy_from_slice(&h);
        Self { state }
    }

    /// Next 32 bytes (a typical "key" length).
    fn next_key(&mut self) -> [u8; 32] {
        let h = Sha512::digest(self.state);
        self.state.copy_from_slice(&h);
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.state[..32]);
        out
    }
}

// ---------------------------------------------------------------------------
// Deterministic stub `InclusionProver`. Uses SHA-512 so commitments
// are reproducible across machines without bls48581 init. The real
// prover gets exercised in `hypergraph_sync_probe` end-to-end tests.
// ---------------------------------------------------------------------------

struct StubProver;

impl InclusionProver for StubProver {
    fn commit_raw(&self, data: &[u8], _poly_size: u64) -> Result<Vec<u8>> {
        Ok(Sha512::digest(data).to_vec())
    }
    fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    fn verify_raw(
        &self,
        _: &[u8],
        _: &[u8],
        _: u64,
        _: &[u8],
        _: u64,
    ) -> Result<bool> {
        Ok(true)
    }
    fn prove_multiple(
        &self,
        _: &[&[u8]],
        _: &[&[u8]],
        _: &[u64],
        _: u64,
    ) -> Result<Box<dyn Multiproof>> {
        Err(QuilError::Internal(
            "stub prover: batch multiproof generation not supported".into(),
        ))
    }
    fn verify_multiple(
        &self,
        _: &[&[u8]],
        _: &[&[u8]],
        _: &[u64],
        _: u64,
        _: &[u8],
        _: &[u8],
    ) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// BTreeMap-backed `HypergraphStore`. Implements enough of the trait
// for the lazy tree's read/write paths (`get_node_by_key`,
// `get_node_by_path` with SeekGE, `insert_node`, `save_root`,
// `delete_node`, per-vertex underlying). Methods unused by the lazy
// tree (snapshots, alt-shard commits, changesets, etc.) panic so an
// accidental new dependency is loud.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct BTreeStoreInner {
    /// Flat key-value map. Keys here are the FULL composite keys
    /// (`hypergraph_tree_node_by_key`-style etc.) so the lazy tree's
    /// `insert_node`/`get_node_by_key` paths pass through unchanged.
    ///
    /// We use BTreeMap rather than HashMap so we can range-iterate by
    /// prefix to implement `get_node_by_path`'s SeekGE.
    kv: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Per-vertex underlying data (separate logical namespace).
    per_vertex: BTreeMap<Vec<u8>, Vec<u8>>,
}

#[derive(Default)]
struct BTreeStore {
    inner: Mutex<BTreeStoreInner>,
}

impl BTreeStore {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    // Key builders. These MUST match `quil_store::encoding`:
    //   HG_TREE_NODE_BY_KEY  = 0x33
    //   HG_TREE_NODE_BY_PATH = 0x34
    //   HG_TREE_BLOB         = 0x2F (legacy whole-tree path)
    // set_byte: "vertex"=0 / "hyperedge"=1
    // phase_byte: "adds"=0 / "removes"=1
    // After the per-node port lands, the lazy tree will hit 0x33/0x34;
    // before then it uses the [0xFF; 32] sentinel which `get_node_by_key`
    // routes to `load_tree_blob` (0x2F). Both code paths share this map.

    fn set_byte(set: &str) -> u8 {
        match set {
            "vertex" => 0,
            "hyperedge" => 1,
            _ => 0xFF,
        }
    }
    fn phase_byte(phase: &str) -> u8 {
        match phase {
            "adds" => 0,
            "removes" => 1,
            _ => 0xFF,
        }
    }

    fn tree_node_by_key_key(
        set: &str,
        phase: &str,
        shard: &ShardKey,
        node_key: &[u8],
    ) -> Vec<u8> {
        let mut k = Vec::with_capacity(3 + 32 + node_key.len());
        k.push(0x33);
        k.push(Self::set_byte(set));
        k.push(Self::phase_byte(phase));
        k.extend_from_slice(&shard.l1);
        k.extend_from_slice(&shard.l2);
        k.extend_from_slice(node_key);
        k
    }
    fn tree_node_by_path_prefix(
        set: &str,
        phase: &str,
        shard: &ShardKey,
    ) -> Vec<u8> {
        let mut k = Vec::with_capacity(3 + 32);
        k.push(0x34);
        k.push(Self::set_byte(set));
        k.push(Self::phase_byte(phase));
        k.extend_from_slice(&shard.l1);
        k.extend_from_slice(&shard.l2);
        k
    }
    fn tree_node_by_path_key(
        set: &str,
        phase: &str,
        shard: &ShardKey,
        path: &[i32],
    ) -> Vec<u8> {
        let mut k = Self::tree_node_by_path_prefix(set, phase, shard);
        for &p in path {
            k.extend_from_slice(&p.to_be_bytes());
        }
        k
    }
    fn tree_blob_key(set: &str, phase: &str, shard: &ShardKey) -> Vec<u8> {
        let mut k = Vec::with_capacity(3 + 32);
        k.push(0x2F);
        k.push(Self::set_byte(set));
        k.push(Self::phase_byte(phase));
        k.extend_from_slice(&shard.l1);
        k.extend_from_slice(&shard.l2);
        k
    }
}

/// No-op transaction: writes go directly to the BTreeMap. Tests don't
/// need atomic batching, so a single shared lock is fine.
struct NoopTxn {
    store: Arc<BTreeStore>,
}
impl Transaction for NoopTxn {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.store.inner.lock().unwrap().kv.get(key).cloned())
    }
    fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.store
            .inner
            .lock()
            .unwrap()
            .kv
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    fn delete(&self, key: &[u8]) -> Result<()> {
        self.store.inner.lock().unwrap().kv.remove(key);
        Ok(())
    }
    fn commit(self: Box<Self>) -> Result<()> {
        Ok(())
    }
    fn abort(self: Box<Self>) -> Result<()> {
        Ok(())
    }
    fn new_iter(
        &self,
        _lower: &[u8],
        _upper: &[u8],
    ) -> Result<Box<dyn quil_types::store::Iterator>> {
        Err(QuilError::Internal(
            "BTreeStore txn iter not implemented".into(),
        ))
    }
    fn delete_range(&self, _lower: &[u8], _upper: &[u8]) -> Result<()> {
        Err(QuilError::Internal(
            "BTreeStore txn delete_range not implemented".into(),
        ))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl HypergraphStore for BTreeStore {
    fn new_transaction(&self, _indexed: bool) -> Result<Box<dyn Transaction>> {
        // `self` is borrowed but `NoopTxn` needs `Arc<BTreeStore>`. We
        // build the txn separately in tests via `arc_new_transaction`.
        // To satisfy the trait we route through a tombstone txn that
        // refuses writes — tests use the helper instead.
        let _ = _indexed;
        Err(QuilError::Internal(
            "use BTreeStore::arc_txn() to obtain a transaction".into(),
        ))
    }

    fn get_node_by_key(
        &self,
        set: &str,
        phase: &str,
        shard: &ShardKey,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // Legacy whole-tree blob path: the lazy tree (pre-port) reads
        // the root sentinel and expects the entire serialized tree.
        if key == [0xFFu8; 32] {
            let k = Self::tree_blob_key(set, phase, shard);
            return Ok(self.inner.lock().unwrap().kv.get(&k).cloned());
        }
        // Per-node path.
        let k = Self::tree_node_by_key_key(set, phase, shard, key);
        Ok(self.inner.lock().unwrap().kv.get(&k).cloned())
    }

    fn get_node_by_path(
        &self,
        set: &str,
        phase: &str,
        shard: &ShardKey,
        path: &[i32],
    ) -> Result<Option<Vec<u8>>> {
        let prefix = Self::tree_node_by_path_prefix(set, phase, shard);
        let requested = Self::tree_node_by_path_key(set, phase, shard, path);
        let inner = self.inner.lock().unwrap();
        // SeekGE: first entry with key >= requested. Must extend
        // `prefix` (still in our shard's namespace) AND must extend
        // `requested` (covers the requested path).
        if let Some((found_key, value)) = inner.kv.range(requested.clone()..).next() {
            if !found_key.starts_with(&prefix) {
                return Ok(None);
            }
            if !found_key.starts_with(&requested) {
                return Ok(None);
            }
            // Value is the by-key key (pointer). Deref.
            let by_key = value.clone();
            Ok(inner.kv.get(&by_key).cloned())
        } else {
            Ok(None)
        }
    }

    fn insert_node(
        &self,
        _txn: &dyn Transaction,
        set: &str,
        phase: &str,
        shard: &ShardKey,
        key: &[u8],
        path: &[i32],
        data: &[u8],
    ) -> Result<()> {
        // Legacy whole-tree blob path.
        if key == [0xFFu8; 32] {
            let k = Self::tree_blob_key(set, phase, shard);
            self.inner.lock().unwrap().kv.insert(k, data.to_vec());
            return Ok(());
        }
        let by_key = Self::tree_node_by_key_key(set, phase, shard, key);
        let by_path = Self::tree_node_by_path_key(set, phase, shard, path);
        let mut inner = self.inner.lock().unwrap();
        inner.kv.insert(by_key.clone(), data.to_vec());
        inner.kv.insert(by_path, by_key);
        Ok(())
    }

    fn save_root(
        &self,
        _txn: &dyn Transaction,
        set: &str,
        phase: &str,
        shard: &ShardKey,
        data: &[u8],
    ) -> Result<()> {
        let k = Self::tree_blob_key(set, phase, shard);
        self.inner.lock().unwrap().kv.insert(k, data.to_vec());
        Ok(())
    }

    fn delete_node(
        &self,
        _txn: &dyn Transaction,
        set: &str,
        phase: &str,
        shard: &ShardKey,
        key: &[u8],
        path: &[i32],
    ) -> Result<()> {
        if key == [0xFFu8; 32] {
            let k = Self::tree_blob_key(set, phase, shard);
            self.inner.lock().unwrap().kv.remove(&k);
            return Ok(());
        }
        let by_key = Self::tree_node_by_key_key(set, phase, shard, key);
        let by_path = Self::tree_node_by_path_key(set, phase, shard, path);
        let mut inner = self.inner.lock().unwrap();
        inner.kv.remove(&by_key);
        inner.kv.remove(&by_path);
        Ok(())
    }

    fn set_covered_prefix(&self, _: &[i32]) -> Result<()> {
        Ok(())
    }
    fn set_shard_commit(
        &self,
        _: &dyn Transaction,
        _: u64,
        _: &str,
        _: &str,
        _: &[u8],
        _: &[u8],
    ) -> Result<()> {
        Ok(())
    }
    fn get_shard_commit(&self, _: u64, _: &str, _: &str, _: &[u8]) -> Result<Vec<u8>> {
        Err(QuilError::NotFound("not implemented in test stub".into()))
    }
    fn get_root_commits(
        &self,
        _: u64,
    ) -> Result<std::collections::HashMap<ShardKey, Vec<Vec<u8>>>> {
        Ok(std::collections::HashMap::new())
    }
    fn load_vertex_underlying_raw(
        &self,
        _set: &str,
        _phase: &str,
        _shard: &ShardKey,
        vertex_key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .per_vertex
            .get(vertex_key)
            .cloned())
    }
    fn save_vertex_underlying(
        &self,
        _set: &str,
        _phase: &str,
        _shard: &ShardKey,
        vertex_key: &[u8],
        data: &[u8],
    ) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .per_vertex
            .insert(vertex_key.to_vec(), data.to_vec());
        Ok(())
    }
    fn for_each_vertex_underlying(
        &self,
        _: &str,
        _: &str,
        _: &ShardKey,
        callback: &mut dyn FnMut(Vec<u8>, Vec<u8>),
    ) -> Result<usize> {
        let inner = self.inner.lock().unwrap();
        let mut n = 0;
        for (k, v) in inner.per_vertex.iter() {
            callback(k.clone(), v.clone());
            n += 1;
        }
        Ok(n)
    }
    fn apply_snapshot(&self, _: &str) -> Result<()> {
        unimplemented!("apply_snapshot not used by lazy tree tests")
    }
    fn set_alt_shard_commit(
        &self,
        _: &dyn Transaction,
        _: u64,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<()> {
        Ok(())
    }
    fn get_latest_alt_shard_commit(
        &self,
        _: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        Err(QuilError::NotFound("not implemented in test stub".into()))
    }
    fn range_alt_shard_addresses(&self) -> Result<Vec<Vec<u8>>> {
        Ok(vec![])
    }
    fn reap_old_changesets(&self, _: &dyn Transaction, _: u64) -> Result<()> {
        Ok(())
    }
    fn track_change(
        &self,
        _: &dyn Transaction,
        _: &[u8],
        _: Option<&[u8]>,
        _: u64,
        _: &str,
        _: &str,
        _: &ShardKey,
    ) -> Result<()> {
        Ok(())
    }
    fn get_changes(
        &self,
        _: u64,
        _: u64,
        _: &str,
        _: &str,
        _: &ShardKey,
    ) -> Result<Vec<ChangeRecord>> {
        Ok(vec![])
    }
    fn untrack_change(
        &self,
        _: &dyn Transaction,
        _: &[u8],
        _: u64,
        _: &str,
        _: &str,
        _: &ShardKey,
    ) -> Result<()> {
        Ok(())
    }
    fn capture_tree_snapshot(
        &self,
    ) -> Result<Option<Arc<dyn SnapshotReadable>>> {
        Ok(None)
    }
}

/// Owning helper to make `Arc<BTreeStore>`-flavored txn calls
/// ergonomic.
fn arc_txn(store: Arc<BTreeStore>) -> Box<dyn Transaction> {
    Box::new(NoopTxn { store })
}

// ---------------------------------------------------------------------------
// Test data + capture helpers
// ---------------------------------------------------------------------------

fn shard_key_zero() -> ShardKey {
    ShardKey {
        l1: [0u8; 3],
        l2: [0u8; 32],
    }
}

/// Insert a deterministic set of N (key, value) pairs into a freshly
/// built `LazyVectorCommitmentTree`, commit, and return the root
/// commitment + size + (leaf_count, longest_branch) + every key's
/// post-commit get value. The function is generic over how it
/// constructs keys: callers feed a `KeyStream` seed string.
struct CapturedRun {
    root_commitment: Vec<u8>,
    size: BigInt,
    leaf_count: usize,
    longest_branch: usize,
    /// (key, value) pairs in insertion order.
    inserted: Vec<(Vec<u8>, Vec<u8>)>,
    /// For each inserted key, the value `tree.get` returns AFTER
    /// commit. Should equal the inserted value.
    gets: Vec<Option<Vec<u8>>>,
    /// Metadata for a handful of sample paths so we exercise the
    /// `get_node_metadata_at_path` walker on captured trees.
    sample_path_metadata: Vec<(Vec<i32>, Option<(usize, String)>)>,
}

/// Production invariant: leaves carry a non-empty `hash_target` so
/// the commitment depends on it rather than `value`. That's what
/// lets serialize_tree strip values from the blob without disturbing
/// root commitments — and it's exactly what `crdt.rs::commit_set`
/// does for every leaf (`hash_target = SHA-512(domain || address)`).
/// Tests must mirror that to be representative.
fn deterministic_hash_target(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut h = Sha512::new();
    h.update(b"golden-hash-target");
    h.update(key);
    h.update(value);
    h.finalize().to_vec()
}

fn run_scenario(seed: &str, n: usize, value_factor: u64) -> CapturedRun {
    let store = BTreeStore::new();
    let tree = LazyVectorCommitmentTree::new(
        store.clone() as Arc<dyn HypergraphStore>,
        "vertex",
        "adds",
        shard_key_zero(),
        vec![],
    );

    let mut ks = KeyStream::new(seed.as_bytes());
    let mut inserted: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(n);
    for i in 0..n {
        let key = ks.next_key().to_vec();
        let mut value = key.clone();
        value.reverse();
        // Make value deterministic but distinct from key bytes.
        value[0] ^= (i as u8).wrapping_mul(value_factor as u8);
        let hash_target = deterministic_hash_target(&key, &value);
        let size = BigInt::from((i as u64) + 1);
        tree.insert(&key, &value, &hash_target, &size).unwrap();
        inserted.push((key, value));
    }

    let txn = arc_txn(store.clone());
    let root_commitment = tree.commit(txn.as_ref(), &StubProver).unwrap();

    let size = tree.get_size();
    let (leaf_count, longest_branch) = tree.get_metadata();

    let gets: Vec<Option<Vec<u8>>> = inserted
        .iter()
        .map(|(k, _)| tree.get(k).unwrap())
        .collect();

    // Sample paths: empty (root), one nibble, two nibbles. We don't
    // care about the specific nibble values — we just want to confirm
    // that the path walker returns the same metadata for the same
    // inputs under both impls.
    let sample_paths: Vec<Vec<i32>> = vec![vec![], vec![0], vec![0, 0], vec![1, 2, 3]];
    let sample_path_metadata: Vec<(Vec<i32>, Option<(usize, String)>)> = sample_paths
        .into_iter()
        .map(|p| {
            let m = tree.get_node_metadata_at_path(&p).unwrap();
            let summary = m.map(|md: NodeMetadata| {
                (md.leaf_count as usize, hex::encode(&md.commitment))
            });
            (p, summary)
        })
        .collect();

    CapturedRun {
        root_commitment,
        size,
        leaf_count,
        longest_branch,
        inserted,
        gets,
        sample_path_metadata,
    }
}

/// Print captured run in a paste-able Rust literal form. Used by the
/// `#[ignore]` capture tests so we can rebase golden vectors when
/// the deterministic input generator or scenario shape changes.
fn print_capture(label: &str, run: &CapturedRun) {
    eprintln!("---- begin capture: {} ----", label);
    eprintln!(
        "root_commitment_hex = \"{}\";",
        hex::encode(&run.root_commitment)
    );
    eprintln!("size_decimal = \"{}\";", run.size);
    eprintln!("leaf_count = {};", run.leaf_count);
    eprintln!("longest_branch = {};", run.longest_branch);
    eprintln!("// {} get round-trips:", run.gets.len());
    let mismatches: Vec<usize> = run
        .gets
        .iter()
        .enumerate()
        .filter_map(|(i, g)| {
            let expected = &run.inserted[i].1;
            match g {
                Some(v) if v == expected => None,
                _ => Some(i),
            }
        })
        .collect();
    eprintln!("get_mismatches = {:?};", mismatches);
    eprintln!("sample_path_metadata = [");
    for (p, m) in &run.sample_path_metadata {
        eprintln!("    ({:?}, {:?}),", p, m);
    }
    eprintln!("];");
    eprintln!("---- end capture: {} ----", label);
}

// ---------------------------------------------------------------------------
// Golden vectors — populated from the CURRENT (whole-tree-blob) impl.
// These values are the contract the per-node port must preserve.
// ---------------------------------------------------------------------------

/// Each scenario's expected outputs. The vectors below were captured
/// by running the corresponding `_capture_*` test with `--ignored
/// --nocapture` against the legacy implementation. If they need
/// re-capturing (e.g. because the input generator or commitment math
/// changed), regenerate from the capture tests and paste in.
struct GoldenVector {
    label: &'static str,
    seed: &'static str,
    n: usize,
    value_factor: u64,
    root_commitment_hex: &'static str,
    size_decimal: &'static str,
    leaf_count: usize,
    longest_branch: usize,
}

/// Golden values captured 2026-05-19 against the load-all-as-blob
/// implementation. After the per-node port lands these MUST still
/// match — diff is a regression, not a "vector refresh."
const GOLDENS: &[GoldenVector] = &[
    GoldenVector {
        label: "single_leaf",
        seed: "single-leaf",
        n: 1,
        value_factor: 0,
        root_commitment_hex: "4e61dbcbfd76200ea94ebc48f026a6879e3db9741b22a8a773b9b717def3170c002be87cdf1a43dbf0d4f3885aeee36d72095f55332e2cfe120b698c32bb600e",
        size_decimal: "1",
        leaf_count: 1,
        longest_branch: 1,
    },
    GoldenVector {
        label: "two_keys",
        seed: "two-keys-different-prefix",
        n: 2,
        value_factor: 7,
        root_commitment_hex: "93108d4bdfcb12161a432d51b9a8e273d67672ffb7bcbfa94f822ccc4ad06dd7904324816458224585a129e6e47705ffe90ee54f68dfb8211b2032b473a7db4e",
        size_decimal: "3",
        // `KeyStream` happens to produce two keys diverging on the
        // first nibble — root is a single branch with both leaves as
        // direct children, so `longest_branch = 0` (no nested
        // branches).
        leaf_count: 2,
        longest_branch: 0,
    },
    GoldenVector {
        label: "small_scatter",
        seed: "scatter-32",
        n: 32,
        value_factor: 13,
        root_commitment_hex: "a172fa11a404314ac64cf28b6d834872ef0f0bf288c17877fd61d847e5ab3066ef26bb0b2fdf341eccf5da012caeb492b786fbab106a856801bdb34498b2b36f",
        size_decimal: "528", // sum 1..=32
        leaf_count: 32,
        longest_branch: 2,
    },
    GoldenVector {
        label: "medium_scatter",
        seed: "scatter-256",
        n: 256,
        value_factor: 19,
        root_commitment_hex: "60703353780e3dea0942efe12e02404426b4c7153798d2b6087d89e13139f2d4a8c0ffef96d65c57e8170d3b42bbbc3585899bbb4ae5be875d1e2a6d0695e2e2",
        size_decimal: "32896", // sum 1..=256
        leaf_count: 256,
        longest_branch: 2,
    },
];

/// Sample-path metadata vectors captured at the same time as
/// `GOLDENS`. Each entry: `(label, path, expected leaf_count under
/// that path, expected commitment hex)`. `None` means the path lands
/// outside the tree (no covering node). Asserts only the medium
/// scenario's `[0]` path that turned out non-empty — the smaller
/// scenarios have nothing under any of the sample paths beyond the
/// root.
const SAMPLE_PATHS: &[(&str, &[i32], Option<(u64, &str)>)] = &[
    ("medium_scatter", &[0], Some((
        2,
        "1f122dd0cf5f7c392a9b7225544d6bca5ff762a816f3cb40f2cf8dce882abbe647b9192f0873fd833e4734d7f712b68f469581a2310d8ecac2fc2718aa025b57",
    ))),
];

// ---------------------------------------------------------------------------
// Capture tests — ignored by default. Run on demand to refresh GOLDENS.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "capture-only: run with --ignored --nocapture to regenerate GOLDENS"]
fn capture_single_leaf() {
    let g = &GOLDENS[0];
    let run = run_scenario(g.seed, g.n, g.value_factor);
    print_capture(g.label, &run);
}

#[test]
#[ignore = "capture-only"]
fn capture_two_keys() {
    let g = &GOLDENS[1];
    let run = run_scenario(g.seed, g.n, g.value_factor);
    print_capture(g.label, &run);
}

#[test]
#[ignore = "capture-only"]
fn capture_small_scatter() {
    let g = &GOLDENS[2];
    let run = run_scenario(g.seed, g.n, g.value_factor);
    print_capture(g.label, &run);
}

#[test]
#[ignore = "capture-only"]
fn capture_medium_scatter() {
    let g = &GOLDENS[3];
    let run = run_scenario(g.seed, g.n, g.value_factor);
    print_capture(g.label, &run);
}

// ---------------------------------------------------------------------------
// Always-on golden assertions. These run on every `cargo test` and pin
// the externally-observable behaviour of `LazyVectorCommitmentTree`.
// Per-node port must keep them passing. They skip the root-commitment
// check when the corresponding `GoldenVector::root_commitment_hex` is
// still empty (PLACEHOLDER) so the file compiles before captures are
// pasted in.
// ---------------------------------------------------------------------------

fn assert_matches_golden(g: &GoldenVector) {
    let run = run_scenario(g.seed, g.n, g.value_factor);

    // Size and leaf_count are cheap, deterministic invariants of the
    // input — if they drift, the test data generator changed or the
    // tree miscounted leaves.
    assert_eq!(
        run.size.to_string(),
        g.size_decimal,
        "[{}] size mismatch",
        g.label
    );
    assert_eq!(
        run.leaf_count, g.leaf_count,
        "[{}] leaf_count mismatch",
        g.label
    );
    assert_eq!(
        run.longest_branch, g.longest_branch,
        "[{}] longest_branch mismatch",
        g.label
    );

    // Root commitment — the most important invariant. SHA-512 of the
    // (KZG-replacement) polynomial vector covers every leaf, every
    // branch, every nibble of prefix compression in one number.
    let actual = hex::encode(&run.root_commitment);
    assert_eq!(
        actual, g.root_commitment_hex,
        "[{}] root commitment drift",
        g.label,
    );

    // Every inserted key must round-trip. The lazy tree drops the
    // leaf-value field from the serialized blob and falls back to
    // `load_vertex_underlying_raw` for non-empty values; this test
    // doesn't write per-vertex data, so we accept the in-tree value
    // (which is what the trip returns).
    for (i, (_key, want_value)) in run.inserted.iter().enumerate() {
        match &run.gets[i] {
            Some(v) => assert_eq!(
                v, want_value,
                "[{}] get key #{} returned wrong value",
                g.label, i
            ),
            None => panic!(
                "[{}] get key #{} returned None (expected the inserted value)",
                g.label, i,
            ),
        }
    }

    // Sample-path metadata: only checked for scenarios with a matching
    // entry in `SAMPLE_PATHS`. Per-path leaf_count + commitment is a
    // strong shape check — if the per-node port walks paths
    // differently, this will fail loudly.
    for (label, path, expected) in SAMPLE_PATHS {
        if *label != g.label {
            continue;
        }
        let got = run
            .sample_path_metadata
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, m)| m.clone());
        match (got.flatten(), expected) {
            (Some((leaf_count, commit_hex)), Some((want_leaves, want_commit))) => {
                assert_eq!(
                    leaf_count as u64, *want_leaves,
                    "[{}] sample path {:?} leaf_count drift",
                    g.label, path,
                );
                assert_eq!(
                    commit_hex, *want_commit,
                    "[{}] sample path {:?} commitment drift",
                    g.label, path,
                );
            }
            (None, None) => {}
            (got_some, want) => panic!(
                "[{}] sample path {:?} mismatch: got {:?}, want {:?}",
                g.label, path, got_some, want,
            ),
        }
    }
}

/// Build a tree, commit, drop the in-memory state, reopen against the
/// same store, and confirm the persisted view yields identical
/// invariants. This is the litmus test for the per-node port: if
/// `commit` writes the wrong nodes or `ensure_loaded` misreads them,
/// the second tree's commitments / metadata / gets will drift.
fn assert_persistence_roundtrip(g: &GoldenVector) {
    let store = BTreeStore::new();
    let dyn_store = store.clone() as Arc<dyn HypergraphStore>;

    // Phase 1 — build the tree, commit, capture invariants.
    let (root1, size1, lc1, lb1, inserted) = {
        let tree = LazyVectorCommitmentTree::new(
            dyn_store.clone(),
            "vertex",
            "adds",
            shard_key_zero(),
            vec![],
        );
        let mut ks = KeyStream::new(g.seed.as_bytes());
        let mut inserted: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(g.n);
        for i in 0..g.n {
            let key = ks.next_key().to_vec();
            let mut value = key.clone();
            value.reverse();
            value[0] ^= (i as u8).wrapping_mul(g.value_factor as u8);
            let hash_target = deterministic_hash_target(&key, &value);
            tree.insert(&key, &value, &hash_target, &BigInt::from((i as u64) + 1))
                .unwrap();
            inserted.push((key, value));
        }
        let txn = arc_txn(store.clone());
        let root = tree.commit(txn.as_ref(), &StubProver).unwrap();
        let (lc, lb) = tree.get_metadata();
        (root, tree.get_size(), lc, lb, inserted)
        // `tree` drops here — every in-memory node is released.
    };

    // Phase 2 — fresh tree, same store, no inserts. Must match.
    let tree2 = LazyVectorCommitmentTree::new(
        dyn_store.clone(),
        "vertex",
        "adds",
        shard_key_zero(),
        vec![],
    );
    let txn2 = arc_txn(store.clone());
    // Re-commit (no mutations) — should yield the SAME root commitment
    // since no leaves changed.
    let root2 = tree2.commit(txn2.as_ref(), &StubProver).unwrap();
    let size2 = tree2.get_size();
    let (lc2, lb2) = tree2.get_metadata();

    assert_eq!(
        hex::encode(&root1),
        hex::encode(&root2),
        "[{}] root commitment drift after reload",
        g.label,
    );
    assert_eq!(size1, size2, "[{}] size drift after reload", g.label);
    assert_eq!(lc1, lc2, "[{}] leaf_count drift after reload", g.label);
    assert_eq!(lb1, lb2, "[{}] longest_branch drift after reload", g.label);

    // And every inserted key still resolves to its inserted value.
    for (i, (key, want_value)) in inserted.iter().enumerate() {
        match tree2.get(key).unwrap() {
            Some(v) => assert_eq!(
                &v, want_value,
                "[{}] reload: get key #{} returned wrong value",
                g.label, i,
            ),
            None => panic!(
                "[{}] reload: get key #{} returned None",
                g.label, i
            ),
        }
    }
}

#[test]
fn persistence_single_leaf() {
    assert_persistence_roundtrip(&GOLDENS[0]);
}

#[test]
fn persistence_two_keys() {
    assert_persistence_roundtrip(&GOLDENS[1]);
}

#[test]
fn persistence_small_scatter() {
    assert_persistence_roundtrip(&GOLDENS[2]);
}

#[test]
fn persistence_medium_scatter() {
    assert_persistence_roundtrip(&GOLDENS[3]);
}

#[test]
fn golden_single_leaf() {
    assert_matches_golden(&GOLDENS[0]);
}

#[test]
fn golden_two_keys() {
    assert_matches_golden(&GOLDENS[1]);
}

#[test]
fn golden_small_scatter() {
    assert_matches_golden(&GOLDENS[2]);
}

#[test]
fn golden_medium_scatter() {
    assert_matches_golden(&GOLDENS[3]);
}

