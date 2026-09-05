//! quil-forest — a three-tier authenticated Merkle forest built over a
//! battle-tested Jellyfish Merkle Tree (JMT) primitive.
//!
//! # Architecture (the shape the node needs)
//!
//! * **Level 1 — 256 global trees.** Keyed by app address; the tree index is
//! the first address byte (`0..=255`). Each leaf holds an [`AppEntry`]:
//! the app's current tree root, total leaf count, total leaf size, and
//! intrinsic-specific metadata. **Every node holds all 256.**
//! * **Level 2 — per-app "shard-commitment" tree.** One leaf per shard, a
//! [`ShardEntry`] holding the shard's commitment (the rollup of its
//! Level-3 phase roots), leaf count and total size. Splits/merges as the
//! app subdivides. **Held by any prover under that app.**
//! * **Level 3 — per-shard state tree(s).** The actual state leaves. The CRDT
//! keeps four *phase* trees per shard (vertex/hyperedge × adds/removes) for
//! OR-set merge semantics, so a shard is four JMT instances tagged by
//! [`Phase`]; their four roots are the header `state_roots` and roll up
//! (via [`rollup_phase_roots`]) into the Level-2 [`ShardEntry`]. **Held by
//! that shard's provers.** Archives hold all three levels.
//!
//! Every tree in the forest is an *independent* JMT instance, so a party
//! holds exactly the trees relevant to its role. All trees share one RocksDB;
//! each tree's nodes/values are namespaced by a [`TreeId`] prefix — see
//! [`RocksTreeStore`]. Commit uses hash commitments (SHA-256) instead of the
//! KZG/BLS48-581 vector commitment, which is the point of the swap: a branch
//! commit becomes a hash, not a G1 multiexp. Overwritten nodes are recorded
//! in a stale-node index ([`ForestStore::apply_update`]) so history can be
//! reclaimed with [`ForestStore::prune`].

use anyhow::Result;
use jmt::storage::{TreeUpdateBatch, TreeWriter};
use jmt::{RootHash, Sha256Jmt, Version};
use sha2::Sha256;

mod forest;
mod membership_proof;
mod store;
// Efficient JMT Merkle-diff sync — enabled via the vendored jmt visibility patch
// (crates/jmt: gen_child_node_key + NibblePath::new made pub).
mod sync;

pub use forest::{
    node_size_sum, rollup_phase_roots, subtree_leaf_count, subtree_size, Forest, Phase,
    ShardRoots, PHASES,
};
pub use sync::{diff_leaves, diff_leaves_under_prefix};
// Re-export so sync callers can name the diff's key type + the reader bound
// without depending on jmt directly.
pub use jmt::storage::TreeReader;
pub use jmt::KeyHash;
pub use membership_proof::{
    verify_vertex_membership, MembershipProof, ShardAggregation, VertexMembershipProof,
};
pub use store::{ForestStore, MemTreeStore, RocksTreeStore, SizeIndex};

/// Namespaces a single tree within the shared RocksDB. The `level` (1/2/3)
/// plus an `id` (app address, shard id, …) uniquely identifies a tree; its
/// bytes prefix every node/value key so all forest trees coexist in one DB.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeId {
    pub level: u8,
    pub id: Vec<u8>,
}

impl TreeId {
    pub fn global(index: u8) -> Self {
        TreeId { level: 1, id: vec![index] }
    }
    pub fn app(app_address: &[u8]) -> Self {
        TreeId { level: 2, id: app_address.to_vec() }
    }
    /// A shard's single-tree id (used when a shard has one undivided state
    /// tree). For the CRDT's four phase trees use [`TreeId::shard_phase`].
    pub fn shard(shard_id: &[u8]) -> Self {
        TreeId { level: 3, id: shard_id.to_vec() }
    }
    /// A shard's per-[`Phase`] state tree. The phase byte prefixes the shard
    /// id so the four phase trees are distinct JMT instances that never
    /// collide, yet stay grouped under the shard for scans.
    pub fn shard_phase(shard_id: &[u8], phase: Phase) -> Self {
        let mut id = Vec::with_capacity(1 + shard_id.len());
        id.push(phase as u8);
        id.extend_from_slice(shard_id);
        TreeId { level: 3, id }
    }

    /// The key-space prefix for this tree: `level ++ len(id) ++ id`. The
    /// length guard keeps `id`s of different lengths from colliding.
    pub(crate) fn prefix(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(2 + self.id.len());
        p.push(self.level);
        p.push(self.id.len() as u8);
        p.extend_from_slice(&self.id);
        p
    }
}

/// The Level-1 global tree index for an app address: the first byte selects
/// one of the 256 global trees.
pub fn global_tree_index(app_address: &[u8]) -> u8 {
    app_address.first().copied().unwrap_or(0)
}

/// Level-3 leaf key for a flattened vertex field: `vertex_address ++
/// field_key`. Under the flattened state model, a vertex is **not** a nested
/// per-vertex tree; every field is its own L3 leaf, all sharing the vertex's
/// (fixed-width) address prefix. Because JMT hashes the leaf key, a vertex's
/// fields are not raw-key-adjacent on disk — read a vertex with point lookups
/// on its known field keys (the class schema enumerates them), not a prefix
/// scan. Enumeration comes from walking the source tree during conversion.
pub fn l3_leaf_key(vertex_address: &[u8], field_key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(vertex_address.len() + field_key.len());
    k.extend_from_slice(vertex_address);
    k.extend_from_slice(field_key);
    k
}

/// Extract the per-vertex `size` field from a `vertex_leaf_value` (the shard
/// leaf under the per-vertex-subtree model), which is `commitment(32) ‖
/// size(u64 BE)` = 40 bytes. Returns 0 for a malformed/short value. Used to
/// aggregate `ShardEntry`/`AppEntry` `total_size` from the committed leaves.
pub fn vertex_leaf_size(value: &[u8]) -> u128 {
    if value.len() >= 40 {
        u64::from_be_bytes(value[32..40].try_into().unwrap()) as u128
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Three-tier leaf encodings
// ---------------------------------------------------------------------------

/// Level-1 leaf value: an app's rolled-up commitment + aggregates + metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppEntry {
    pub app_root: [u8; 32],
    pub num_leaves: u64,
    pub total_size: u128,
    /// Intrinsic-specific metadata (token supply, compute limits, …).
    pub metadata: Vec<u8>,
}

impl AppEntry {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(32 + 8 + 16 + self.metadata.len());
        b.extend_from_slice(&self.app_root);
        b.extend_from_slice(&self.num_leaves.to_be_bytes());
        b.extend_from_slice(&self.total_size.to_be_bytes());
        b.extend_from_slice(&self.metadata);
        b
    }

    /// Parse the fixed 56-byte header; the remainder is `metadata`.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 56 {
            return None;
        }
        let app_root: [u8; 32] = b[..32].try_into().ok()?;
        let num_leaves = u64::from_be_bytes(b[32..40].try_into().ok()?);
        let total_size = u128::from_be_bytes(b[40..56].try_into().ok()?);
        Some(AppEntry { app_root, num_leaves, total_size, metadata: b[56..].to_vec() })
    }
}

/// Level-2 leaf value: a single shard's commitment + aggregates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardEntry {
    pub shard_commitment: [u8; 32],
    pub num_leaves: u64,
    pub total_size: u128,
}

impl ShardEntry {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(32 + 8 + 16);
        b.extend_from_slice(&self.shard_commitment);
        b.extend_from_slice(&self.num_leaves.to_be_bytes());
        b.extend_from_slice(&self.total_size.to_be_bytes());
        b
    }

    /// Parse the fixed 56-byte encoding.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 56 {
            return None;
        }
        let shard_commitment: [u8; 32] = b[..32].try_into().ok()?;
        let num_leaves = u64::from_be_bytes(b[32..40].try_into().ok()?);
        let total_size = u128::from_be_bytes(b[40..56].try_into().ok()?);
        Some(ShardEntry { shard_commitment, num_leaves, total_size })
    }
}

// ---------------------------------------------------------------------------
// Commit primitives
// ---------------------------------------------------------------------------

/// Compute a commit without writing: returns the new root and the full
/// [`TreeUpdateBatch`] (nodes, values, and the stale-node index). Callers
/// that want pruning persist the batch via [`ForestStore::apply_update`];
/// callers that don't can use [`commit`].
pub fn commit_update<S: TreeReader>(
    store: &S,
    version: Version,
    leaves: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
) -> Result<(RootHash, TreeUpdateBatch)> {
    let tree = Sha256Jmt::new(store);
    let value_set = leaves
        .into_iter()
        .map(|(k, v)| (KeyHash::with::<Sha256>(&k), Some(v)));
    let (root, batch) = tree.put_value_set(value_set, version)?;
    Ok((root, batch))
}

/// Map a leaf key to a **raw-key** `KeyHash` — the key's own bytes become the
/// JMT nibble path (left-aligned into 32 bytes, zero-padded), instead of
/// `SHA-256(key)`. This is the D-4 address-path sharding foundation: with a
/// vertex address as the key, a leaf's tree path IS its address, so the
/// address's top `k` bits select the shard subtree — matching
/// `assign_child_index` / `ConfirmationFilter` (which shard by address top bits:
/// binary@0x80, quaternary@top-2-bits, … 64 shards = top 6 bits, min height 6).
/// A shard's l3 is then the JMT subtree at that address-path prefix within the
/// app tree.
pub fn shard_path_key_hash(key: &[u8]) -> KeyHash {
    let mut b = [0u8; 32];
    let n = key.len().min(32);
    b[..n].copy_from_slice(&key[..n]);
    KeyHash(b)
}

/// Like [`commit_update`] but positions leaves by [`shard_path_key_hash`] (raw
/// address path) instead of `SHA-256(key)`. The building block for the
/// address-path forest: leaves cluster by address, so a shard = the subtree at
/// the address-prefix. (Keys MUST be pre-disambiguated — under raw-key paths a
/// 32-byte address fills the whole `KeyHash`, so per-vertex granularity is
/// required; distinct vertices differ in their address, not a field suffix.)
pub fn commit_update_raw<S: TreeReader>(
    store: &S,
    version: Version,
    leaves: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
) -> Result<(RootHash, TreeUpdateBatch)> {
    let tree = Sha256Jmt::new(store);
    let value_set = leaves.into_iter().map(|(k, v)| (shard_path_key_hash(&k), Some(v)));
    let (root, batch) = tree.put_value_set(value_set, version)?;
    Ok((root, batch))
}

/// Like [`commit_update`] but the leaves are ALREADY keyed by `KeyHash` — the
/// client half of [`sync`](crate::diff_leaves), which receives `(key_hash,
/// value)` diffs from a peer. The raw key is neither recoverable from a JMT nor
/// needed: applying the peer's hashed leaves reconstructs the identical tree, so
/// the post-apply root equals the peer's (the caller verifies that equality).
pub fn commit_update_keyhash<S: TreeReader>(
    store: &S,
    version: Version,
    leaves: impl IntoIterator<Item = (KeyHash, Vec<u8>)>,
) -> Result<(RootHash, TreeUpdateBatch)> {
    let tree = Sha256Jmt::new(store);
    let value_set = leaves.into_iter().map(|(k, v)| (k, Some(v)));
    let (root, batch) = tree.put_value_set(value_set, version)?;
    Ok((root, batch))
}

/// The shard index of a leaf address: its top `shard_depth` bits, MSB-first —
/// exactly `assign_child_index(address, 2^shard_depth)`. `shard_depth = 6` gives
/// the 64-way QUIL split (min height 6). Empty address ⇒ shard 0.
pub fn shard_index(address: &[u8], shard_depth: u32) -> u32 {
    debug_assert!(shard_depth <= 32);
    let mut idx = 0u32;
    for i in 0..shard_depth {
        let byte = (i / 8) as usize;
        let bit = 7 - (i % 8);
        let set = address.get(byte).map(|b| (b >> bit) & 1 == 1).unwrap_or(false);
        idx = (idx << 1) | (set as u32);
    }
    idx
}

/// Aggregate the per-shard subtree roots into the **app root**: a complete
/// binary Merkle tree of height `shard_depth` over the `2^shard_depth` shard
/// positions (SHA-256 of `left ‖ right`; an absent shard hashes as the all-zero
/// node). This is the L2 = app-over-shards layer of the address-path forest —
/// the shard at index [`shard_index`] sits at its address-bit path, so the app
/// root is deterministic over the whole app's state regardless of which prover
/// holds which shard subtree.
pub fn app_root_from_shards(
    shard_depth: u32,
    shard_roots: &std::collections::BTreeMap<u32, [u8; 32]>,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let n = 1u32 << shard_depth;
    let mut level: Vec<[u8; 32]> =
        (0..n).map(|i| shard_roots.get(&i).copied().unwrap_or([0u8; 32])).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let mut h = Sha256::new();
                h.update(pair[0]);
                h.update(pair[1]);
                h.finalize().into()
            })
            .collect();
    }
    level.first().copied().unwrap_or([0u8; 32])
}

/// Convert a shard `prefix` (the `ShardInfo.prefix` — a sequence of 64-way level
/// indices, each `0..64`) into its binary bit-path, MSB-first, `bits_per_level`
/// bits per element. QUIL uses one level (6 bits, 64 shards); an unsplit app has
/// an empty prefix (the whole app is one shard at the root); apps split as needed,
/// growing the prefix. `bits_per_level = 6` (64-way = 2^6).
pub fn prefix_to_bits(prefix: &[u32], bits_per_level: u32) -> Vec<bool> {
    let mut bits = Vec::with_capacity(prefix.len() * bits_per_level as usize);
    for &lvl in prefix {
        for i in (0..bits_per_level).rev() {
            bits.push((lvl >> i) & 1 == 1);
        }
    }
    bits
}

// ---------------------------------------------------------------------------
// Deep-bifurcation shard addressing codec (DEEP_BIFURCATION_ENCODING_SCOPE.md,
// Phase 1). A shard's identity is its canonical address BIT-PATH (arbitrary
// length) — not a `Vec<u32>` run through `canonical_shard_bit_paths` (which
// collapses single-valued levels, so it can't skip the uniform bits a skewed
// shard shares before it branches). These are the PURE codec + bit-prefix
// helpers; the routing/proposal/migration that consume them are later phases.
//
// Wire form of a shard filter/address: `app ‖ bit_len(u16 BE) ‖ packed bits`,
// where the packed bits are MSB-first, zero-padded to `ceil(bit_len/8)` bytes.
// Fixed-width `bit_len` (not a varint) keeps the encoding trivially canonical:
// exactly one byte string per `(app, bit_path)`, so every node routes identically.
// (256-bit addresses ⇒ `bit_len ≤ 256`, well within `u16`.)

/// The 2-byte big-endian bit-length header that follows the app address.
const SHARD_BIT_LEN_BYTES: usize = 2;

/// Pack a bit-path into `ceil(n/8)` bytes, MSB-first, zero-padded.
fn pack_bits(bit_path: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bit_path.len().div_ceil(8)];
    for (i, &b) in bit_path.iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    out
}

/// Encode a shard as `app ‖ bit_len(u16 BE) ‖ packed bits` — the deep-bifurcation
/// shard filter/address. `bit_path` is the shard's canonical address bit-path
/// (empty ⇒ the whole app is one shard at the root). Inverse of
/// [`decode_shard_bit_path`].
pub fn encode_shard_bit_path(app: &[u8], bit_path: &[bool]) -> Vec<u8> {
    let mut out = Vec::with_capacity(app.len() + SHARD_BIT_LEN_BYTES + bit_path.len().div_ceil(8));
    out.extend_from_slice(app);
    out.extend_from_slice(&(bit_path.len() as u16).to_be_bytes());
    out.extend_from_slice(&pack_bits(bit_path));
    out
}

/// Decode a shard filter `app(app_len) ‖ bit_len(u16 BE) ‖ packed bits` into
/// `(app, bit_path)`. Returns `None` if malformed: too short, a length that
/// doesn't match the packed-byte count, or a non-canonical form (any padding bit
/// beyond `bit_len` set). Inverse of [`encode_shard_bit_path`].
pub fn decode_shard_bit_path(filter: &[u8], app_len: usize) -> Option<(Vec<u8>, Vec<bool>)> {
    if filter.len() < app_len + SHARD_BIT_LEN_BYTES {
        return None;
    }
    let app = filter[..app_len].to_vec();
    let n = u16::from_be_bytes(filter[app_len..app_len + SHARD_BIT_LEN_BYTES].try_into().ok()?) as usize;
    let n_bytes = n.div_ceil(8);
    if filter.len() != app_len + SHARD_BIT_LEN_BYTES + n_bytes {
        return None;
    }
    let packed = &filter[app_len + SHARD_BIT_LEN_BYTES..];
    let mut bits = Vec::with_capacity(n);
    for i in 0..n {
        bits.push((packed[i / 8] >> (7 - (i % 8))) & 1 == 1);
    }
    // Canonical form: every padding bit beyond `n` must be zero.
    for i in n..n_bytes * 8 {
        if (packed[i / 8] >> (7 - (i % 8))) & 1 == 1 {
            return None;
        }
    }
    Some((app, bits))
}

/// Whether `parent` is a bit-prefix of `child` — i.e. `child` extends `parent`.
/// The bit-path counterpart of `slice::starts_with`, since a bit-path is NOT a
/// byte prefix (`materialize_shard_split`'s `starts_with(parent)` check moves to
/// this once shards carry bit-paths).
pub fn bit_path_starts_with(child: &[bool], parent: &[bool]) -> bool {
    child.len() >= parent.len() && child[..parent.len()] == *parent
}

/// Decode a shard filter to `(app, bit_path)`, treating a BARE app-address filter
/// (exactly `app_len` bytes, no encoded suffix) as the ROOT shard (empty
/// bit-path). The root/unsplit shard's on-chain filter is just its 32-byte app
/// address (its `ConfirmationFilter` / `ShardInfo`), NOT an encoded
/// `app ‖ bit_len ‖ packed` — so a root split's parent must be accepted as the
/// empty-bit-path parent. Deeper shards always carry an encoded bit-path.
///
/// LEGACY BYTE-SUFFIX (`app ‖ level-byte`, `app_len + 1` bytes): the QUIL 64-way
/// genesis grid registers each shard as a plain byte-suffix filter (`app ‖ [i]`,
/// `i` in `0..64`), NOT a bit-path — too short to be `app ‖ u16 ‖ packed`. When a
/// genesis shard takes its FIRST deep split, its parent filter arrives in this
/// form, so decode it to the 6-bit binary of the byte (`bits_per_level = 6`,
/// 64-way = 2^6). This is IDENTICAL to `canonical_shard_bit_paths` for the intact
/// uniform 64-way set (prefix `[i]` → 6-bit `binary(i)`), which is exactly what
/// the split proposer (`canonical_bits_for_prefix`) and `migrate_app_shards_to_sentinel`
/// use — so the child-extends-parent check and the parent removal both line up.
/// Only the intact uniform genesis grid produces a byte-suffix parent (the first
/// deep split migrates the whole set to sentinel bit-paths), where this holds.
pub fn decode_shard_filter_or_root(filter: &[u8], app_len: usize) -> Option<(Vec<u8>, Vec<bool>)> {
    if filter.len() == app_len {
        return Some((filter[..app_len].to_vec(), Vec::new()));
    }
    if filter.len() > app_len && filter.len() < app_len + SHARD_BIT_LEN_BYTES {
        // `app ‖ level-byte(s)` legacy byte-suffix (single-byte for the QUIL
        // 64-way genesis): 6 bits/level, MSB-first = binary of each level byte.
        let app = filter[..app_len].to_vec();
        let prefix: Vec<u32> = filter[app_len..].iter().map(|&b| b as u32).collect();
        return Some((app, prefix_to_bits(&prefix, 6)));
    }
    decode_shard_bit_path(filter, app_len)
}

/// Whether `child_filter` is a valid child of `parent_filter`: same app, and the
/// child's bit-path extends the parent's. The bit-path replacement for the
/// materialize `proposed.starts_with(shard_address)` structural check. Both sides
/// are decoded via [`decode_shard_filter_or_root`] so a bare 32-byte app address
/// (the root shard being split) is treated as the empty-bit-path parent.
pub fn shard_filter_extends(child_filter: &[u8], parent_filter: &[u8], app_len: usize) -> bool {
    match (
        decode_shard_filter_or_root(child_filter, app_len),
        decode_shard_filter_or_root(parent_filter, app_len),
    ) {
        (Some((ca, cb)), Some((pa, pb))) => ca == pa && bit_path_starts_with(&cb, &pb),
        _ => false,
    }
}

/// THE canonical `ShardInfo.prefix` → wire shard FILTER conversion — the single
/// source of truth every consumer MUST use instead of `l2 ‖ (prefix as u8)*`.
///
/// A legacy prefix is small level indices appended as low bytes (`l2 ‖ p₀ ‖ …`,
/// the historical byte-suffix filter). A deep-bifurcation prefix is a SENTINEL
/// bit-path (`[0xFFFF_FFFF, b0, …]`) and MUST become the encoded bit-path filter
/// (`app ‖ bit_len ‖ packed`) — a raw `p as u8` on the sentinel (`0xFFFF_FFFF` →
/// `0xFF`) garbles it, the bug class that recurred across ~11 independent call
/// sites (inventory, world-size, worker-allocator, submit-check, archive-sync).
/// Route ALL of them through here so the sentinel is handled in exactly one place.
pub fn shard_prefix_to_filter(l2: &[u8], prefix: &[u32]) -> Vec<u8> {
    if let Some(bits) = shard_bit_path_from_prefix(prefix) {
        encode_shard_bit_path(l2, &bits)
    } else {
        let mut f = l2.to_vec();
        for &p in prefix {
            f.push(p as u8);
        }
        f
    }
}

/// The co-path SPINE of a deep split: the off-path sibling bit-paths passed while
/// descending from the parent shard `parent` down to the `branch` (the common
/// prefix of the two data-bearing children, i.e. a child with its last bit
/// dropped). For each bit stepped from `parent` to `branch`, the sibling is the
/// path taken so far with the OPPOSITE next bit. Registering these siblings
/// alongside the two leaf children makes the shard set COMPLETE and PREFIX-FREE:
/// every address routes to exactly one shard, no fallback. The spine shards start
/// EMPTY (they cover the regions the split descended past, which held no data) —
/// latent placeholders excluded from halt-risk / proposal until data lands.
///
/// `parent` MUST be a bit-prefix of `branch`. Example: `parent=[]`,
/// `branch=[0,0]` (children `[0,0,0]`/`[0,0,1]`) → spine `[[1], [0,1]]`.
/// An immediate (1-bit) split has `branch == parent` → empty spine.
pub fn split_spine_siblings(parent: &[bool], branch: &[bool]) -> Vec<Vec<bool>> {
    let mut out = Vec::new();
    for i in parent.len()..branch.len() {
        let mut sib = branch[..i].to_vec();
        sib.push(!branch[i]);
        out.push(sib);
    }
    out
}

/// Sentinel first `Vec<u32>` level marking a deep-bifurcation bit-path prefix.
/// Legacy `ShardInfo.prefix` levels are QUIL 6-bit indices (`0..64`) or split
/// markers (`0..256`), never `0xFFFF_FFFF` — so the sentinel disambiguates a
/// bit-path prefix from a legacy one WITHOUT changing the `ShardInfo` type or its
/// serialization: a deep shard rides the existing `prefix: Vec<u32>` as
/// `[SENTINEL, b0, b1, …]` (each bit a `0`/`1` level). The unified routing decodes
/// it (via [`shard_bit_path_from_prefix`]); pre-unified paths never see it.
pub const BIT_PATH_PREFIX_SENTINEL: u32 = 0xFFFF_FFFF;

/// Encode a shard's bit-path into a `ShardInfo.prefix` `Vec<u32>` as
/// `[SENTINEL, b0, b1, …]`. Inverse of [`shard_bit_path_from_prefix`].
pub fn bit_path_to_prefix(bit_path: &[bool]) -> Vec<u32> {
    let mut p = Vec::with_capacity(1 + bit_path.len());
    p.push(BIT_PATH_PREFIX_SENTINEL);
    p.extend(bit_path.iter().map(|&b| b as u32));
    p
}

/// Canonical QUIL genesis shard-grid prefixes for `network`, in the ONE forward
/// format: SENTINEL bit-path prefixes. Mainnet (network 0) is the fixed 64-way
/// pre-split — the 6-bit paths `000000`..`111111`; every other network is a
/// single root shard (empty prefix == the whole app). The legacy byte-suffix
/// `[i]` form is deliberately NOT produced: every grid seeder (genesis, boot
/// reset, split-reset config, dry-run) routes through here so a node's local
/// grid — and the confirmation filters derived from it via
/// [`shard_prefix_to_filter`] — are sentinel everywhere. A root shard's `[]`
/// is not the byte-suffix genesis format; its filter is the bare app address.
pub fn genesis_grid_prefixes(network: u8) -> Vec<Vec<u32>> {
    if network == 0 {
        (0..64u32)
            .map(|i| bit_path_to_prefix(&prefix_to_bits(&[i], 6)))
            .collect()
    } else {
        vec![vec![]]
    }
}

/// If `prefix` is a sentinel-tagged bit-path prefix, decode it to the bit-path;
/// otherwise `None` (a legacy prefix — resolve via [`canonical_shard_bit_paths`]).
/// Rejects a malformed tagged prefix (any level after the sentinel not `0`/`1`).
pub fn shard_bit_path_from_prefix(prefix: &[u32]) -> Option<Vec<bool>> {
    let (&head, rest) = prefix.split_first()?;
    if head != BIT_PATH_PREFIX_SENTINEL {
        return None;
    }
    let mut bits = Vec::with_capacity(rest.len());
    for &lvl in rest {
        match lvl {
            0 => bits.push(false),
            1 => bits.push(true),
            _ => return None, // malformed: a tagged prefix's levels are bits
        }
    }
    Some(bits)
}

/// Derive the canonical address **bit-path** of every shard in an app from the
/// COMPLETE shard-prefix set, resolving the `ShardInfo.prefix` overload.
///
/// The `prefix: Vec<u32>` field carries two incompatible encodings in the same
/// bytes (see the sharding-encoding reconciliation):
/// - **QUIL genesis**: `[i]`, `i ∈ 0..64` — an *unshifted* 6-bit index (`assign_child_index(_, 64)` = top 6 bits = `i`).
/// - **Dynamic split** (`compute_proposed_shards`): a filter suffix byte cast
/// `b as u32` — the child index *shifted into the high bits*: binary `0x80=128`,
/// quaternary `{0x40,0x80,0xC0}={64,128,192}`, octal `{0x20..0xE0}` in a
/// leading byte followed by a `0x00` padding byte.
///
/// Both are ultimately "the top-k address bits select the shard". This resolves
/// them uniformly by looking at each level's COMPLETE sibling set: a level with
/// `N` distinct values is a `log2(N)`-bit split, and the per-value child index is
/// the *dense* value (QUIL, siblings `{0..N-1}`) or the *marker* value scaled by
/// `N/256` (splits, siblings `{0, 256/N, …}`). A single-sibling level (e.g. the
/// octal `0x00` padding byte, or an unsplit tail) contributes 0 bits. Absent /
/// child-`0` widths are inferred from the nonzero siblings, so `[0]` under a
/// binary split → `"0"` while QUIL `[0]` → `"000000"`.
///
/// Returns one bit-path per input prefix, IN ORDER. The set MUST be complete +
/// prefix-free (every split writes all its children); the result is then a valid
/// input to [`app_root_from_shard_paths`]. An empty prefix → an empty bit-path
/// (the whole app is one shard at the root).
pub fn canonical_shard_bit_paths(prefixes: &[Vec<u32>]) -> Vec<Vec<bool>> {
    let mut out = vec![Vec::new(); prefixes.len()];
    let active: Vec<usize> = (0..prefixes.len()).collect();
    canonical_bit_paths_rec(prefixes, &active, 0, &mut out);
    out
}

/// `log2(N)` split width + a value→child-index map for one level, from the
/// distinct sibling values. `N` is expected to be a power of two (2/4/8 for
/// dynamic splits, 64 for QUIL, 1 for a padding/unsplit tail).
fn level_partition(values: &[u32]) -> (u32, std::collections::HashMap<u32, u32>) {
    let mut vs: Vec<u32> = values.to_vec();
    vs.sort_unstable();
    vs.dedup();
    let n = vs.len() as u32;
    if n <= 1 {
        return (0, vs.into_iter().map(|v| (v, 0)).collect());
    }
    // log2(N), rounded up so a non-power-of-2 sibling count (shouldn't happen for
    // a complete split set) still yields a wide-enough, deterministic path.
    let width = 32 - (n - 1).leading_zeros();
    let dense: Vec<u32> = (0..n).collect();
    let is_dense = vs == dense;
    // Marker values are multiples of `256 / N`; recover the index by that scale.
    let scale = (256u32 / n).max(1);
    let map = vs
        .iter()
        .map(|&v| (v, if is_dense { v } else { v / scale }))
        .collect();
    (width, map)
}

fn canonical_bit_paths_rec(
    prefixes: &[Vec<u32>],
    active: &[usize],
    depth: usize,
    out: &mut Vec<Vec<bool>>,
) {
    // Shards whose prefix extends past `depth` split further here; those whose
    // prefix ends at `depth` terminate (their bit-path is already complete).
    let continuing: Vec<usize> =
        active.iter().copied().filter(|&i| prefixes[i].len() > depth).collect();
    if continuing.is_empty() {
        return;
    }
    let values: Vec<u32> = continuing.iter().map(|&i| prefixes[i][depth]).collect();
    let (width, index_map) = level_partition(&values);
    // Group the continuing shards by this level's value, deterministic order.
    let mut groups: std::collections::BTreeMap<u32, Vec<usize>> = Default::default();
    for &i in &continuing {
        groups.entry(prefixes[i][depth]).or_default().push(i);
    }
    for (value, group) in groups {
        let idx = *index_map.get(&value).unwrap_or(&0);
        for &i in &group {
            for b in (0..width).rev() {
                out[i].push((idx >> b) & 1 == 1);
            }
        }
        canonical_bit_paths_rec(prefixes, &group, depth + 1, out);
    }
}

/// Whether the leading `path.len()` bits of `data` (MSB-first) equal `path`.
fn addr_has_bit_prefix(data: &[u8], path: &[bool]) -> bool {
    path.iter().enumerate().all(|(i, &want)| {
        let byte = i / 8;
        let bit = 7 - (i % 8);
        data.get(byte).map(|b| (b >> bit) & 1 == 1).unwrap_or(false) == want
    })
}

/// The index of the sub-shard a leaf belongs to, given the leaf's data address
/// and the app's COMPLETE canonical bit-path set (from
/// [`canonical_shard_bit_paths`], in the SAME order as its prefix set). Exactly
/// one path is a prefix of the address bits (the empty path matches everything ⇒
/// a single-shard app routes to index 0). Mirrors `assign_child_index` (the top
/// address bits select the shard). Falls back to 0 if nothing matches.
pub fn address_shard_index(data_addr: &[u8], bit_paths: &[Vec<bool>]) -> usize {
    bit_paths.iter().position(|p| addr_has_bit_prefix(data_addr, p)).unwrap_or(0)
}

/// Aggregate shards at ARBITRARY (variable) depths into the app root — a sparse
/// binary Merkle tree where each shard is a leaf at its own bit-path
/// ([`prefix_to_bits`]). Handles dynamic sharding (an unsplit app = one shard at
/// the empty path = the app root itself; QUIL = 64 shards at depth 6; a
/// non-uniformly split app = shards at mixed depths). Paths MUST be prefix-free
/// (a shard and its split children never coexist). Absent siblings hash as the
/// all-zero node. Generalizes [`app_root_from_shards`] (which is the uniform-depth
/// special case).
pub fn app_root_from_shard_paths(shards: &[(Vec<bool>, [u8; 32])]) -> [u8; 32] {
    fn build(shards: &[(&[bool], [u8; 32])], depth: usize) -> [u8; 32] {
        match shards.len() {
            0 => [0u8; 32],
            1 if shards[0].0.len() == depth => shards[0].1,
            _ => {
                let (mut left, mut right): (Vec<_>, Vec<_>) = (Vec::new(), Vec::new());
                for &(path, root) in shards {
                    if path[depth] {
                        right.push((path, root));
                    } else {
                        left.push((path, root));
                    }
                }
                hash_pair(&build(&left, depth + 1), &build(&right, depth + 1))
            }
        }
    }
    if shards.is_empty() {
        return [0u8; 32];
    }
    // A single unsplit shard (empty path) IS the app root.
    if shards.len() == 1 && shards[0].0.is_empty() {
        return shards[0].1;
    }
    let refs: Vec<(&[bool], [u8; 32])> = shards.iter().map(|(p, r)| (p.as_slice(), *r)).collect();
    build(&refs, 0)
}

fn hash_pair(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// The variable-depth membership co-path for the shard at bit-path `target`: the
/// sibling-subtree root at each level along the path from the app root down to
/// that shard, so [`app_root_from_shard_path`] can recompute the app root from
/// the shard's own root. Pairs with [`app_root_from_shard_paths`]. `shards` is
/// the COMPLETE app shard set (all `(prefix_bits, shard_root)`). The co-path is
/// top-down, one sibling per level of `target`.
pub fn app_membership_path_dynamic(
    shards: &[(Vec<bool>, [u8; 32])],
    target: &[bool],
) -> Vec<[u8; 32]> {
    (0..target.len())
        .map(|d| {
            // Shards in the sibling subtree at depth d: they agree with `target`
            // on the first d bits but diverge at bit d. Their paths within that
            // subtree drop the shared prefix (bits 0..=d).
            let sib: Vec<(Vec<bool>, [u8; 32])> = shards
                .iter()
                .filter(|(p, _)| p.len() > d && p[..d] == target[..d] && p[d] != target[d])
                .map(|(p, r)| (p[d + 1..].to_vec(), *r))
                .collect();
            app_root_from_shard_paths(&sib)
        })
        .collect()
}

/// Recompute the app root from a shard's own root + its
/// [`app_membership_path_dynamic`] co-path — the verifier half. Equals
/// [`app_root_from_shard_paths`] over the full set iff `shard_root` and `siblings`
/// are that shard's. A full leaf membership proof against the signed app root is
/// the shard-JMT `SparseMerkleProof` (leaf → `shard_root`) composed with this.
pub fn app_root_from_shard_path(
    target: &[bool],
    shard_root: [u8; 32],
    siblings: &[[u8; 32]],
) -> [u8; 32] {
    let mut h = shard_root;
    // Defensive: never index `siblings` out of bounds (callers should also check
    // `siblings.len() == target.len()`; a short copath here just yields a root
    // that won't match the trusted app root and is rejected — no panic).
    let depth = target.len().min(siblings.len());
    for d in (0..depth).rev() {
        h = if target[d] { hash_pair(&siblings[d], &h) } else { hash_pair(&h, &siblings[d]) };
    }
    h
}

/// The app-root membership co-path for the shard at `shard_index`: the sibling
/// hashes (bottom-up) along the binary-Merkle path from that shard's leaf to the
/// app root. A full leaf membership proof against the app root is a shard-JMT
/// `SparseMerkleProof` (leaf → `shard_root`) PLUS this co-path (`shard_root` →
/// `app_root`). Producer-side helper; pairs with [`app_root_from_shard`].
pub fn app_membership_path(
    shard_depth: u32,
    shard_index: u32,
    shard_roots: &std::collections::BTreeMap<u32, [u8; 32]>,
) -> Vec<[u8; 32]> {
    let n = 1u32 << shard_depth;
    let mut level: Vec<[u8; 32]> =
        (0..n).map(|i| shard_roots.get(&i).copied().unwrap_or([0u8; 32])).collect();
    let mut idx = shard_index as usize;
    let mut siblings = Vec::with_capacity(shard_depth as usize);
    while level.len() > 1 {
        siblings.push(level[idx ^ 1]);
        level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
        idx >>= 1;
    }
    siblings
}

/// Recompute the app root from one shard's root + its [`app_membership_path`]
/// co-path — the verifier half. `app_root_from_shard(d, i, root, path) ==
/// app_root_from_shards(d, roots)` iff `roots[i] == root` and `path` is that
/// shard's co-path. Lets a light client verify a leaf against the signed app
/// root while holding only the leaf's shard subtree.
pub fn app_root_from_shard(
    shard_index: u32,
    shard_root: [u8; 32],
    siblings: &[[u8; 32]],
) -> [u8; 32] {
    let mut h = shard_root;
    let mut idx = shard_index as usize;
    for sib in siblings {
        h = if idx & 1 == 0 { hash_pair(&h, sib) } else { hash_pair(sib, &h) };
        idx >>= 1;
    }
    h
}

/// Commit a set of `(key, value)` leaves into `store` at `version`, returning
/// the new root. `store` must already hold the tree at `version - 1` (JMT
/// reads the prior root from the reader). Persists nodes/values but **not**
/// the stale-node index — use [`commit_pruning`] when history reclamation
/// matters.
pub fn commit<S: TreeReader + TreeWriter>(
    store: &S,
    version: Version,
    leaves: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
) -> Result<RootHash> {
    let (root, batch) = commit_update(store, version, leaves)?;
    store.write_node_batch(&batch.node_batch)?;
    Ok(root)
}

/// Like [`commit`], but persists the stale-node index too (via
/// [`ForestStore::apply_update`]) so [`ForestStore::prune`] can later reclaim
/// the nodes this write superseded. This is the write path the node uses.
pub fn commit_pruning<S: ForestStore>(
    store: &S,
    version: Version,
    leaves: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
) -> Result<RootHash> {
    let (root, batch) = commit_update(store, version, leaves)?;
    store.apply_update(&batch)?;
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_index_is_first_byte() {
        assert_eq!(global_tree_index(&[0x2a, 0xff]), 0x2a);
        assert_eq!(global_tree_index(&[]), 0);
    }

    #[test]
    fn app_root_from_shard_path_short_copath_does_not_panic() {
        // Regression (Forest F1): `prefix_bits`/`copath` come from the wire and
        // are attacker-controlled. A copath shorter than the prefix must never
        // index out of bounds (which was a remote consensus-halt panic); it just
        // yields some root that won't match the trusted app root.
        let target = vec![true, false, true, true];
        let siblings: Vec<[u8; 32]> = vec![[1u8; 32]]; // deliberately too short
        let _ = app_root_from_shard_path(&target, [7u8; 32], &siblings);
        // Empty copath against a non-empty prefix is also fine (returns shard_root).
        assert_eq!(app_root_from_shard_path(&target, [7u8; 32], &[]), [7u8; 32]);
    }

    // ---- canonical_shard_bit_paths: resolve the ShardInfo.prefix overload ----

    fn bits(s: &str) -> Vec<bool> {
        s.chars().map(|c| c == '1').collect()
    }

    // ---- deep-bifurcation shard codec (Phase 1) ----

    #[test]
    fn shard_bit_path_codec_round_trips() {
        let app = [0xABu8; 32];
        // Cover: empty, 1 bit, sub-byte (6, the QUIL width), byte boundary (8),
        // multi-byte (13), and a deep skewed-style path.
        for p in [
            "", "0", "1", "000000", "000001", "10101010", "1010101011010",
            "0000000000001", // the "descend K uniform bits then branch" shape
        ] {
            let bp = bits(p);
            let enc = encode_shard_bit_path(&app, &bp);
            // Layout: 32 app + 2 len + ceil(n/8) packed.
            assert_eq!(enc.len(), 32 + 2 + bp.len().div_ceil(8), "len for {p:?}");
            assert_eq!(&enc[..32], &app, "app preserved for {p:?}");
            let (a, b) = decode_shard_bit_path(&enc, 32).expect("decodes");
            assert_eq!(a, app.to_vec());
            assert_eq!(b, bp, "round-trip for {p:?}");
        }
    }

    #[test]
    fn shard_bit_path_codec_rejects_malformed_and_noncanonical() {
        let app = [0x11u8; 32];
        // Too short (no room for the length header).
        assert!(decode_shard_bit_path(&app, 32).is_none());
        // Length says 3 bits (1 packed byte) but no packed byte present.
        let mut short = app.to_vec();
        short.extend_from_slice(&3u16.to_be_bytes());
        assert!(decode_shard_bit_path(&short, 32).is_none());
        // Trailing bytes beyond the declared length.
        let mut long = encode_shard_bit_path(&app, &bits("010"));
        long.push(0x00);
        assert!(decode_shard_bit_path(&long, 32).is_none());
        // Non-canonical: a padding bit beyond bit_len is set (3 bits, but the
        // packed byte has a low bit set).
        let mut noncanon = app.to_vec();
        noncanon.extend_from_slice(&3u16.to_be_bytes());
        noncanon.push(0b010_00001); // bits[0..3]=010, bit at position 7 (padding) set
        assert!(decode_shard_bit_path(&noncanon, 32).is_none(), "padding bit must be zero");
    }

    #[test]
    fn sentinel_prefix_codec_round_trips_and_disambiguates() {
        for p in ["", "0", "1", "000000", "0000001", "1010"] {
            let bp = bits(p);
            let prefix = bit_path_to_prefix(&bp);
            assert_eq!(prefix[0], BIT_PATH_PREFIX_SENTINEL);
            assert_eq!(shard_bit_path_from_prefix(&prefix), Some(bp.clone()), "round-trip {p:?}");
        }
        // Legacy prefixes are NOT sentinel-tagged → None (resolve via canonical).
        assert_eq!(shard_bit_path_from_prefix(&[]), None);
        assert_eq!(shard_bit_path_from_prefix(&[0]), None); // QUIL shard 0 / binary child 0
        assert_eq!(shard_bit_path_from_prefix(&[63]), None); // QUIL shard 63
        assert_eq!(shard_bit_path_from_prefix(&[128]), None); // binary split marker
        // Malformed tagged prefix (a level after the sentinel isn't a bit).
        assert_eq!(shard_bit_path_from_prefix(&[BIT_PATH_PREFIX_SENTINEL, 0, 2]), None);
    }

    #[test]
    fn bit_path_prefix_and_extends() {
        assert!(bit_path_starts_with(&bits("0001"), &bits("000")));
        assert!(bit_path_starts_with(&bits("000"), &bits("000")));
        assert!(bit_path_starts_with(&bits("0"), &bits(""))); // everything extends the root
        assert!(!bit_path_starts_with(&bits("001"), &bits("000")));
        assert!(!bit_path_starts_with(&bits("00"), &bits("000"))); // shorter can't extend

        let app = [0x2Au8; 32];
        let other = [0x2Bu8; 32];
        let parent = encode_shard_bit_path(&app, &bits("000"));
        let child = encode_shard_bit_path(&app, &bits("0001"));
        let sibling = encode_shard_bit_path(&app, &bits("0000"));
        let wrong_app = encode_shard_bit_path(&other, &bits("0001"));
        let non_ext = encode_shard_bit_path(&app, &bits("001"));
        assert!(shard_filter_extends(&child, &parent, 32));
        assert!(shard_filter_extends(&sibling, &parent, 32));
        assert!(!shard_filter_extends(&wrong_app, &parent, 32), "different app");
        assert!(!shard_filter_extends(&non_ext, &parent, 32), "not a bit-prefix");
        assert!(!shard_filter_extends(&parent, &child, 32), "parent does not extend child");

        // ROOT split: the parent is the BARE 32-byte app address (empty bit-path),
        // NOT an encoded filter — a bit-path child must still be accepted.
        let root_parent = app.to_vec(); // bare app, len == app_len
        let root_child0 = encode_shard_bit_path(&app, &bits("000000"));
        let root_child1 = encode_shard_bit_path(&app, &bits("000001"));
        assert_eq!(decode_shard_filter_or_root(&root_parent, 32), Some((app.to_vec(), vec![])));
        assert!(shard_filter_extends(&root_child0, &root_parent, 32), "deep child extends bare-app root");
        assert!(shard_filter_extends(&root_child1, &root_parent, 32));
        // A child under a DIFFERENT bare-app root is rejected.
        assert!(!shard_filter_extends(&root_child0, &other.to_vec(), 32), "wrong app root");
    }

    #[test]
    fn shard_prefix_to_filter_handles_legacy_and_sentinel() {
        let app = [0x2Au8; 32];
        // Legacy: small level indices → l2 ‖ low bytes.
        assert_eq!(shard_prefix_to_filter(&app, &[5]), {
            let mut f = app.to_vec();
            f.push(5);
            f
        });
        assert_eq!(shard_prefix_to_filter(&app, &[]), app.to_vec()); // unsplit = bare app
        // Sentinel bit-path → the ENCODED filter (NOT l2 ‖ 0xFF ‖ bits).
        let sentinel = bit_path_to_prefix(&bits("000001"));
        assert_eq!(shard_prefix_to_filter(&app, &sentinel), encode_shard_bit_path(&app, &bits("000001")));
        // Round-trips: the produced filter decodes back to the same bit-path.
        let (dec_app, dec_bits) =
            decode_shard_bit_path(&shard_prefix_to_filter(&app, &sentinel), 32).unwrap();
        assert_eq!(dec_app, app.to_vec());
        assert_eq!(dec_bits, bits("000001"));
    }

    #[test]
    fn split_spine_is_the_complete_prefix_free_cover() {
        // Root split descending to branch [0,0] (children [0,0,0]/[0,0,1]):
        // co-path siblings are [1] (bit 0) and [0,1] (bit 1).
        let spine = split_spine_siblings(&[], &bits("00"));
        assert_eq!(spine, vec![bits("1"), bits("01")]);

        // Spine + the two leaves = a COMPLETE prefix-free partition: every 8-bit
        // address matches exactly one shard.
        let mut shards = spine.clone();
        shards.push(bits("000"));
        shards.push(bits("001"));
        for a in 0u16..256 {
            let byte = [a as u8];
            let matches: Vec<&Vec<bool>> =
                shards.iter().filter(|p| addr_has_bit_prefix(&byte, p)).collect();
            assert_eq!(matches.len(), 1, "addr {a:08b} must match exactly one shard, got {matches:?}");
        }

        // Immediate (1-bit) split: branch == parent → no spine.
        assert!(split_spine_siblings(&bits("0"), &bits("0")).is_empty());
        // Deeper parent: descend from [0,1] to [0,1,0,0] → siblings [0,1,1], [0,1,0,1].
        assert_eq!(
            split_spine_siblings(&bits("01"), &bits("0100")),
            vec![bits("011"), bits("0101")]
        );
    }

    #[test]
    fn canonical_unsplit_app_is_root() {
        // A single unsplit shard (empty prefix) = the whole app at the root.
        assert_eq!(canonical_shard_bit_paths(&[vec![]]), vec![Vec::<bool>::new()]);
    }

    #[test]
    fn size_index_maintained_at_write_time_and_survives_churn() {
        // The regression this guards: the Merkle-sum size index used to be
        // populated only LAZILY on read (`node_size_sum` cold-walk). After an
        // epoch of churn the head version's nodes were all fresh, un-memoized
        // NodeKeys, so the next per-shard size read cold-walked the whole tree —
        // the epoch-boundary halt. Now every commit maintains the index in the
        // same batch, so the head root's sum is always present and correct with
        // NO lazy recompute. This asserts exactly that: read `get_size_sum` at
        // the head root DIRECTLY (never calling `node_size_sum`) and require it.
        use jmt::storage::{NibblePath, NodeKey};

        // A vertex leaf value: commitment(32) ‖ size(u64 BE) = 40 bytes.
        let leaf = |size: u64| {
            let mut v = vec![0u8; 40];
            v[32..40].copy_from_slice(&size.to_be_bytes());
            v
        };
        let store = MemTreeStore::default();

        // v0: three leaves, sizes 10/20/30.
        let leaves_v0: Vec<(Vec<u8>, Vec<u8>)> = [10u64, 20, 30]
            .iter()
            .enumerate()
            .map(|(i, &s)| (format!("k{i}").into_bytes(), leaf(s)))
            .collect();
        commit(&store, 0, leaves_v0).unwrap();
        let root0 = NodeKey::new(0, NibblePath::new(vec![]));
        assert_eq!(
            store.get_size_sum(&root0).unwrap(),
            Some(60u128),
            "v0 root sum must be persisted at WRITE time (10+20+30), not lazily"
        );

        // v1 (churn): rewrite k1 20→200 and add k3=5. JMT is copy-on-write, so
        // the v1 root is a FRESH NodeKey whose sum this commit must maintain by
        // combining the new child (k1/k3) with the UNCHANGED v0 children (k0/k2)
        // via their already-persisted sums — the exact cross-version reuse that
        // keeps head warm without a walk.
        let leaves_v1: Vec<(Vec<u8>, Vec<u8>)> =
            vec![(b"k1".to_vec(), leaf(200)), (b"k3".to_vec(), leaf(5))];
        commit(&store, 1, leaves_v1).unwrap();
        let root1 = NodeKey::new(1, NibblePath::new(vec![]));
        assert_eq!(
            store.get_size_sum(&root1).unwrap(),
            Some(245u128),
            "v1 head root sum stays warm+correct after churn (10+200+30+5)"
        );

        // The public read path agrees (and, being warm, is O(depth)).
        assert_eq!(subtree_size(&store, 1, &[]).unwrap(), 245u128);
    }

    #[test]
    fn genesis_grid_prefixes_are_sentinel_and_never_byte_suffix() {
        // Mainnet: 64 rows, every one a SENTINEL bit-path prefix (leading marker),
        // never the legacy byte-suffix `[i]`. Each decodes to its 6-bit index, so
        // routing is identical to the old form — only the stored bytes changed.
        let mainnet = genesis_grid_prefixes(0);
        assert_eq!(mainnet.len(), 64);
        for (i, p) in mainnet.iter().enumerate() {
            assert!(
                shard_bit_path_from_prefix(p).is_some(),
                "row {i} must be sentinel-encoded, got {p:?}"
            );
            assert_ne!(*p, vec![i as u32], "row {i} must NOT be legacy byte-suffix");
            assert_eq!(
                shard_bit_path_from_prefix(p).unwrap(),
                prefix_to_bits(&[i as u32], 6),
                "row {i} routes to its 6-bit index"
            );
        }
        // Testnet/localnet: a single root shard (bare-app filter, not byte-suffix).
        assert_eq!(genesis_grid_prefixes(1), vec![Vec::<u32>::new()]);
    }

    // Faithful model of the multi-node valid-shard flow that the single-shard
    // localnet could NEVER exercise (network 1 = one root shard, always matches
    // itself). Reproduces the mainnet 64-way fleet divergence using the REAL
    // functions each side uses:
    //   * archive valid-set  = { shard_prefix_to_filter(l2, row.prefix) }   (archive_sync.rs:2828)
    //   * prover join/coverage address = shard_prefix_to_filter(l2, row.prefix) over the
    //                                    joiner's OWN local grid              (lifecycle.rs:1083)
    //   * collector reject    = !valid.contains(&address)                    (message_collector.rs:305)
    // The grid is per-node and does NOT sync, so two nodes seeding genesis in
    // different encodings produce non-matching filters → reject. This test would
    // have FAILED before the seeder unification (byte-suffix boot/genesis seed vs
    // sentinel v4 reset), which is exactly what shipped to prod uncaught.
    #[test]
    fn heterogeneous_fleet_grids_diverge_but_unified_seeders_agree() {
        let l2 = [0x11u8; 32]; // stand-in QUIL app address (l2)
        // Build a node's valid-shard address set the way the archive does.
        let valid_set = |grid: &[Vec<u32>]| -> std::collections::HashSet<Vec<u8>> {
            grid.iter().map(|p| shard_prefix_to_filter(&l2, p)).collect()
        };
        // The coverage/join address a prover on shard `k` submits, derived from
        // ITS OWN local grid (same call the lifecycle join path makes).
        let coverage_addr = |grid: &[Vec<u32>], k: usize| shard_prefix_to_filter(&l2, &grid[k]);

        // Node grids: OLD binary seeds legacy byte-suffix `[i]`; FIXED binary
        // seeds via the canonical helper (sentinel). Both are 64-way mainnet.
        let grid_old: Vec<Vec<u32>> = (0..64u32).map(|i| vec![i]).collect();
        let grid_fixed = genesis_grid_prefixes(0);

        // Sanity: the two encodings are genuinely different bytes for the SAME
        // shard, but route to the same bit-path (so it "looks" fine until the
        // byte-exact valid-set check runs).
        assert_ne!(grid_old[5], grid_fixed[5], "encodings differ byte-wise");
        assert_eq!(
            canonical_shard_bit_paths(&grid_old),
            canonical_shard_bit_paths(&grid_fixed),
            "…yet both route identically"
        );

        let archive_fixed = valid_set(&grid_fixed);

        // REGRESSION (the prod bug): an OLD-binary prover's byte-suffix coverage
        // address is NOT in a FIXED-binary archive's sentinel valid-set → the
        // collector rejects it (`!valid.contains`) → 0 rewards.
        let addr_old = coverage_addr(&grid_old, 5);
        assert!(
            !archive_fixed.contains(&addr_old),
            "byte-suffix prover MUST be rejected by the sentinel archive — this is the bug"
        );

        // FIX (positive case): a FIXED-binary prover's address IS in the archive's
        // valid-set for every shard → accepted.
        for k in 0..64 {
            assert!(
                archive_fixed.contains(&coverage_addr(&grid_fixed, k)),
                "fixed-binary prover accepted on shard {k}"
            );
        }

        // INVARIANT the fix guarantees: any two nodes that seed via the helper
        // produce BYTE-IDENTICAL valid-sets, so the fleet can never diverge as
        // long as everyone runs the fixed seeder.
        assert_eq!(
            archive_fixed,
            valid_set(&genesis_grid_prefixes(0)),
            "two fixed-binary nodes agree byte-for-byte"
        );

        // And a HOMOGENEOUS old fleet is internally consistent (why it silently
        // "worked" until one archive updated and flipped to sentinel).
        assert!(valid_set(&grid_old).contains(&addr_old), "old fleet self-consistent");
    }

    #[test]
    fn canonical_quil_64way_matches_6bit_index() {
        // QUIL genesis: prefixes [0]..[63], dense → each is its 6-bit index.
        let prefixes: Vec<Vec<u32>> = (0..64u32).map(|i| vec![i]).collect();
        let paths = canonical_shard_bit_paths(&prefixes);
        for i in 0..64u32 {
            // Identical to the legacy 6-bit mapping — QUIL is unchanged.
            assert_eq!(paths[i as usize], prefix_to_bits(&[i], 6), "QUIL shard {i}");
        }
    }

    #[test]
    fn canonical_binary_split_is_top_bit() {
        // Non-QUIL binary split: filter suffix 0x00/0x80 → prefix [0]/[128].
        let paths = canonical_shard_bit_paths(&[vec![0], vec![128]]);
        assert_eq!(paths[0], bits("0"));
        assert_eq!(paths[1], bits("1"));
    }

    #[test]
    fn canonical_quaternary_split_is_top_two_bits() {
        // Suffixes 0x00/0x40/0x80/0xC0 → prefix [0]/[64]/[128]/[192].
        let paths = canonical_shard_bit_paths(&[vec![0], vec![64], vec![128], vec![192]]);
        assert_eq!(paths[0], bits("00"));
        assert_eq!(paths[1], bits("01"));
        assert_eq!(paths[2], bits("10"));
        assert_eq!(paths[3], bits("11"));
    }

    #[test]
    fn canonical_octal_split_padding_byte_adds_no_bits() {
        // Octal: leading byte 0x20-step + a 0x00 padding byte → prefix [hi, 0].
        let prefixes: Vec<Vec<u32>> =
            [0u32, 32, 64, 96, 128, 160, 192, 224].iter().map(|&hi| vec![hi, 0]).collect();
        let paths = canonical_shard_bit_paths(&prefixes);
        for (i, p) in paths.iter().enumerate() {
            // 3 bits from the leading byte, 0 from the padding byte.
            assert_eq!(p.len(), 3, "octal shard {i} width");
            let mut expected = Vec::new();
            for b in (0..3u32).rev() {
                expected.push((i as u32 >> b) & 1 == 1);
            }
            assert_eq!(*p, expected, "octal shard {i}");
        }
    }

    /// A QUIL genesis shard's FIRST deep split: the parent arrives as a legacy
    /// byte-suffix filter (`app ‖ [i]`, 33 bytes) while the children are bit-path
    /// filters. `decode_shard_filter_or_root` must decode the byte-suffix parent to
    /// the SAME 6-bit binary the proposer/migrate use, so `shard_filter_extends`
    /// accepts the split (the mainnet bug: byte-suffix parent → decode None →
    /// "bit-path child must extend parent bit-path" rejection).
    #[test]
    fn byte_suffix_genesis_parent_decodes_and_children_extend() {
        let app = [0x11u8; 32];
        // Parent = QUIL genesis shard 3, byte-suffix `app ‖ 0x03` (33 bytes).
        let mut parent = app.to_vec();
        parent.push(0x03);

        // It decodes to the 6-bit binary of 3 — identical to canonical bits for
        // the intact uniform 64-way set.
        let (pa, pb) = decode_shard_filter_or_root(&parent, 32).expect("byte-suffix decodes");
        assert_eq!(pa, app.to_vec());
        assert_eq!(pb, bits("000011"), "byte 3 → 6-bit binary");
        let quil64: Vec<Vec<u32>> = (0..64u32).map(|i| vec![i]).collect();
        assert_eq!(
            canonical_shard_bit_paths(&quil64)[3],
            bits("000011"),
            "decode matches canonical_shard_bit_paths[3]"
        );

        // Children = 7-bit paths 0000110 / 0000111 (proposer's deep bifurcation),
        // encoded as bit-path filters. Both must extend the parent.
        for child_bits in [bits("0000110"), bits("0000111")] {
            let child = encode_shard_bit_path(&app, &child_bits);
            assert!(
                shard_filter_extends(&child, &parent, 32),
                "bit-path child {child_bits:?} must extend byte-suffix parent [3]"
            );
        }

        // A child under a DIFFERENT genesis shard (shard 4 = 000100) must NOT
        // extend parent [3] — the fix stays a bit-prefix check, not a byte one.
        let foreign = encode_shard_bit_path(&app, &bits("0001000"));
        assert!(!shard_filter_extends(&foreign, &parent, 32), "shard-4 child ⊄ shard-3");
    }

    #[test]
    fn canonical_child_zero_width_inferred_from_siblings() {
        // The child-0 marker [0] is ambiguous alone; its width comes from siblings.
        // Binary sibling {0,128} → [0] is 1 bit "0".
        assert_eq!(canonical_shard_bit_paths(&[vec![0], vec![128]])[0], bits("0"));
        // Quaternary sibling set → [0] is 2 bits "00".
        assert_eq!(
            canonical_shard_bit_paths(&[vec![0], vec![64], vec![128], vec![192]])[0],
            bits("00")
        );
        // QUIL dense set → [0] is 6 bits "000000".
        let quil: Vec<Vec<u32>> = (0..64u32).map(|i| vec![i]).collect();
        assert_eq!(canonical_shard_bit_paths(&quil)[0], bits("000000"));
    }

    #[test]
    fn canonical_nonuniform_nested_binary_is_prefix_free() {
        // App splits binary → {[0],[128]}; the [128] shard splits binary again →
        // {[128,0],[128,128]}. Full set = {[0],[128,0],[128,128]}.
        let paths = canonical_shard_bit_paths(&[vec![0], vec![128, 0], vec![128, 128]]);
        assert_eq!(paths[0], bits("0")); // shallow shard, depth 1
        assert_eq!(paths[1], bits("10")); // deep shard, depth 2
        assert_eq!(paths[2], bits("11"));
        // Prefix-free: no path is a prefix of another.
        assert!(!paths[1].starts_with(&paths[0]));
        assert!(!paths[2].starts_with(&paths[0]));
    }

    #[test]
    fn canonical_paths_feed_app_root_aggregation() {
        // The derived paths must be valid input to app_root_from_shard_paths, and a
        // quaternary set must aggregate identically to the uniform depth-2 helper.
        let prefixes = vec![vec![0u32], vec![64], vec![128], vec![192]];
        let paths = canonical_shard_bit_paths(&prefixes);
        let roots: [[u8; 32]; 4] = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let shard_paths: Vec<(Vec<bool>, [u8; 32])> =
            paths.iter().cloned().zip(roots).collect();
        let via_paths = app_root_from_shard_paths(&shard_paths);
        let uniform: std::collections::BTreeMap<u32, [u8; 32]> =
            (0..4u32).map(|i| (i, roots[i as usize])).collect();
        let via_uniform = app_root_from_shards(2, &uniform);
        assert_eq!(via_paths, via_uniform, "canonical quaternary == uniform depth-2");
    }

    #[test]
    fn mem_commit_is_deterministic_and_readable() {
        let leaves: Vec<(Vec<u8>, Vec<u8>)> =
            (0u32..50).map(|i| (i.to_be_bytes().to_vec(), vec![i as u8; 40])).collect();

        let s1 = MemTreeStore::default();
        let r1 = commit(&s1, 0, leaves.clone()).unwrap();
        let s2 = MemTreeStore::default();
        let r2 = commit(&s2, 0, leaves.clone()).unwrap();
        assert_eq!(r1.0, r2.0, "same leaves must give same root");

        // Value round-trips through the reader.
        let tree = Sha256Jmt::new(&s1);
        let got = tree
            .get(KeyHash::with::<Sha256>(3u32.to_be_bytes()), 0)
            .unwrap();
        assert_eq!(got, Some(vec![3u8; 40]));
    }

    #[test]
    fn l3_leaf_key_is_addr_prefixed() {
        let addr = [0xABu8; 32];
        let k1 = l3_leaf_key(&addr, &[0x00]);
        let k2 = l3_leaf_key(&addr, &[0x04]);
        // Same vertex, different fields → distinct keys sharing the 32B prefix.
        assert_ne!(k1, k2);
        assert_eq!(&k1[..32], &addr[..]);
        assert_eq!(&k2[..32], &addr[..]);
        assert_eq!(&k1[32..], &[0x00]);
    }

    #[test]
    fn raw_key_hash_is_the_address_so_top_bits_select_the_shard() {
        // The crux of the D-4 direction: raw-key positioning makes a leaf's JMT
        // path equal its address, so `assign_child_index`-style top-bit sharding
        // (binary@0x80, … 64 shards = top 6 bits) maps 1:1 onto the tree.
        let addr = [0xABu8; 32];
        assert_eq!(shard_path_key_hash(&addr).0, addr, "KeyHash == address bytes");

        // Two addresses in the SAME shard (top 6 bits equal: 0xAB = 1010_1011,
        // top-6 = 101010) vs a DIFFERENT shard (top byte 0x2B: 001010_11).
        let same_shard = {
            let mut a = addr;
            a[31] ^= 0xFF; // differ only below the shard-selector bits
            a
        };
        let diff_shard = {
            let mut a = addr;
            a[0] = 0x2B; // top 6 bits differ → different shard subtree
            a
        };
        // top-6-bit shard selector (mirrors assign_child_index for n=64).
        let shard6 = |a: &[u8; 32]| a[0] >> 2;
        assert_eq!(shard6(&addr), shard6(&same_shard), "same top-6-bits ⇒ same shard");
        assert_ne!(shard6(&addr), shard6(&diff_shard), "differing top-6-bits ⇒ different shard");

        // Raw-key commit round-trips (values readable at their raw path) and
        // produces a DIFFERENT root than SHA-256 keying (proves the path changed).
        let leaves: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (addr.to_vec(), vec![1u8; 16]),
            (same_shard.to_vec(), vec![2u8; 16]),
            (diff_shard.to_vec(), vec![3u8; 16]),
        ];
        let sr = MemTreeStore::default();
        let (raw_root, batch) = commit_update_raw(&sr, 0, leaves.clone()).unwrap();
        sr.write_node_batch(&batch.node_batch).unwrap();
        let tree = Sha256Jmt::new(&sr);
        assert_eq!(
            tree.get(shard_path_key_hash(&addr), 0).unwrap(),
            Some(vec![1u8; 16]),
            "value readable at its raw address path"
        );
        let hashed_root = commit(&MemTreeStore::default(), 0, leaves).unwrap();
        assert_ne!(raw_root.0, hashed_root.0, "raw-key path differs from SHA-256 keying");
    }

    #[test]
    fn shard_index_matches_top_bits() {
        // MSB-first top-6-bits (64-way). 0xAB = 1010_1011 → top6 = 101010 = 42.
        assert_eq!(shard_index(&[0xAB, 0xFF], 6), 0b101010);
        assert_eq!(shard_index(&[0x80], 1), 1); // binary split @ 0x80
        assert_eq!(shard_index(&[0x7F], 1), 0);
        assert_eq!(shard_index(&[0xC0], 2), 3); // quaternary top-2-bits
        assert_eq!(shard_index(&[], 6), 0);
        // Lower bits below the shard depth don't change the shard.
        assert_eq!(shard_index(&[0xAB, 0x00], 6), shard_index(&[0xAB, 0xFF], 6));
    }

    #[test]
    fn app_root_aggregates_shards_deterministically() {
        use std::collections::BTreeMap;
        let mut roots = BTreeMap::new();
        roots.insert(0u32, [1u8; 32]);
        roots.insert(42u32, [2u8; 32]);
        roots.insert(63u32, [3u8; 32]);

        let r1 = app_root_from_shards(6, &roots);
        let r2 = app_root_from_shards(6, &roots);
        assert_eq!(r1, r2, "deterministic over the same shard set");

        // A different shard root ⇒ a different app root (binding).
        let mut roots2 = roots.clone();
        roots2.insert(42u32, [9u8; 32]);
        assert_ne!(app_root_from_shards(6, &roots2), r1, "app root binds each shard");

        // All-empty app ⇒ a fixed all-zero-leaves root, not itself zero.
        let empty = app_root_from_shards(6, &BTreeMap::new());
        assert_ne!(empty, [0u8; 32], "aggregated empty root is a hash, not zero");
        // Depth-0 app (single shard) = that shard's root verbatim.
        let mut one = BTreeMap::new();
        one.insert(0u32, [7u8; 32]);
        assert_eq!(app_root_from_shards(0, &one), [7u8; 32]);
    }

    #[test]
    fn variable_depth_shard_paths_aggregate_and_generalize_uniform() {
        use std::collections::BTreeMap;

        // prefix_to_bits: 64-way index 42 (=101010) at 6 bits/level, MSB-first.
        assert_eq!(
            prefix_to_bits(&[42], 6),
            vec![true, false, true, false, true, false]
        );
        assert_eq!(prefix_to_bits(&[], 6), Vec::<bool>::new()); // unsplit app

        // (1) An unsplit app (one shard, empty prefix) IS the app root.
        let only = [7u8; 32];
        assert_eq!(app_root_from_shard_paths(&[(vec![], only)]), only);

        // (2) A COMPLETE split (every position present — the real case, since a
        // 64-way split creates all 64 children) matches the uniform
        // `app_root_from_shards`. Use a complete depth-2 (4-shard) tree: with no
        // empty positions the two empty-node conventions never diverge.
        let mut roots = BTreeMap::new();
        for i in 0u32..4 {
            roots.insert(i, [i as u8 + 1; 32]);
        }
        let uniform = app_root_from_shards(2, &roots);
        let paths: Vec<(Vec<bool>, [u8; 32])> =
            roots.iter().map(|(&i, &r)| (prefix_to_bits(&[i], 2), r)).collect();
        assert_eq!(
            app_root_from_shard_paths(&paths),
            uniform,
            "complete split: variable-depth == uniform"
        );

        // (3) Non-uniform split: shard [5] stayed at depth 6 while [0] split
        // further into [0,3] and [0,17] at depth 12. Deterministic + binds.
        let mixed = vec![
            (prefix_to_bits(&[5], 6), [50u8; 32]),
            (prefix_to_bits(&[0, 3], 6), [60u8; 32]),
            (prefix_to_bits(&[0, 17], 6), [70u8; 32]),
        ];
        let r = app_root_from_shard_paths(&mixed);
        assert_eq!(app_root_from_shard_paths(&mixed), r, "deterministic");
        let mut tampered = mixed.clone();
        tampered[1].1 = [0xEE; 32];
        assert_ne!(app_root_from_shard_paths(&tampered), r, "binds each shard");
    }

    #[test]
    fn dynamic_membership_copath_reconstructs_the_app_root() {
        // A COMPLETE, non-uniform shard set: [0] and [1] at depth 6, while [2]
        // split further into [2,10] and [2,40] at depth 12. (Prefix-free.)
        let mk = |p: &[u32], b: u8| (prefix_to_bits(p, 6), [b; 32]);
        let shards = vec![
            mk(&[0], 1),
            mk(&[1], 2),
            mk(&[2, 10], 3),
            mk(&[2, 40], 4),
        ];
        let app_root = app_root_from_shard_paths(&shards);

        // Every shard's co-path reconstructs the app root from its own root...
        for (path, root) in &shards {
            let siblings = app_membership_path_dynamic(&shards, path);
            assert_eq!(siblings.len(), path.len(), "one sibling per level");
            assert_eq!(
                app_root_from_shard_path(path, *root, &siblings),
                app_root,
                "co-path reconstructs the app root for path {path:?}"
            );
        }
        // ...and a tampered shard root does NOT (binding).
        let (p0, _) = &shards[0];
        let sib0 = app_membership_path_dynamic(&shards, p0);
        assert_ne!(app_root_from_shard_path(p0, [0xEE; 32], &sib0), app_root);
    }

    #[test]
    fn app_membership_path_reconstructs_the_app_root() {
        use std::collections::BTreeMap;
        let mut roots = BTreeMap::new();
        for i in [0u32, 1, 5, 42, 63] {
            roots.insert(i, [i as u8 + 1; 32]);
        }
        let app_root = app_root_from_shards(6, &roots);

        // For every present shard, its co-path reconstructs the app root...
        for (&idx, &sr) in &roots {
            let path = app_membership_path(6, idx, &roots);
            assert_eq!(path.len(), 6, "co-path has one sibling per level");
            assert_eq!(
                app_root_from_shard(idx, sr, &path),
                app_root,
                "shard {idx} co-path reconstructs the app root"
            );
        }
        // ...and a wrong shard root does NOT (binding).
        let path42 = app_membership_path(6, 42, &roots);
        assert_ne!(app_root_from_shard(42, [0xEE; 32], &path42), app_root);
        // ...nor a leaf claimed under the wrong shard index.
        assert_ne!(app_root_from_shard(41, roots[&42], &path42), app_root);
    }

    #[test]
    fn app_and_shard_entry_round_trip() {
        let ae = AppEntry {
            app_root: [7u8; 32],
            num_leaves: 42,
            total_size: 1 << 40,
            metadata: b"QUIL:token".to_vec(),
        };
        assert_eq!(AppEntry::from_bytes(&ae.to_bytes()).unwrap(), ae);
        let se = ShardEntry { shard_commitment: [9u8; 32], num_leaves: 3, total_size: 999 };
        assert_eq!(ShardEntry::from_bytes(&se.to_bytes()).unwrap(), se);
        // Short buffers reject.
        assert!(AppEntry::from_bytes(&[0u8; 10]).is_none());
        assert!(ShardEntry::from_bytes(&[0u8; 55]).is_none());
    }
}
