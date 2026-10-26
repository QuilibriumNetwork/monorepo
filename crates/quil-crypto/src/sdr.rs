//! SDR (Stacked Depth-Robust Graph) replica encoding — the per-member leaf
//! "sealing" that the storage-attestation scheme proves possession of.
//!
//! A leaf's public data is encoded into a member-unique replica
//! `R = data ⊕ labels_L`, where `labels_L` is the final layer of a stacked
//! depth-robust labeling keyed by `key = H(member_id ‖ shard ‖ epoch)`:
//! - the graph (each node's parents) is **fixed** and key-independent — DRSample
//! back-edges within a layer + a bipartite expander from the prior layer;
//! - the labels are keyed, so two members get replicas that differ in every node
//! (the per-member uniqueness the Sybil argument needs);
//! - it is **decodable** (regenerate `labels_L` from the key, XOR back), so the
//! storage is *useful* — a member can serve the real data.
//!
//! SECURITY NOTE (load-bearing): the depth-robust graph distribution and
//! parameters ARE the regen-on-demand resistance. This is a CLEAN-ROOM
//! implementation of the DRSample + stacked-expander STRUCTURE with the
//! finalized parameters (DRG in-degree 6, expander degree 8, L = 11). The tests
//! here cover FUNCTIONAL correctness: deterministic, decodable, unique-per-key,
//! and that the replica feeds the KZG possession path end-to-end.
//!
//! MEMORY: this keeps two layers resident (`2·N·node_bytes`). For GiB leaves
//! production needs a streaming / disk-backed labeler; the in-memory version
//! here is for correctness + small-leaf tests.

use sha3::{Digest, Sha3_256};

/// Stacked-DRG parameters. Defaults are the finalized values.
#[derive(Clone, Debug)]
pub struct SdrParams {
    /// DRSample in-degree within a layer (incl. the chain edge).
    pub drg_degree: usize,
    /// Bipartite-expander in-degree from the prior layer.
    pub expander_degree: usize,
    /// Number of stacked layers.
    pub layers: usize,
    /// Bytes per node (= the label hash output width).
    pub node_bytes: usize,
}

impl Default for SdrParams {
    fn default() -> Self {
        // Finalized: DRSample degree 6, expander 8, L = 11, 32-byte nodes.
        Self { drg_degree: 6, expander_degree: 8, layers: 11, node_bytes: 32 }
    }
}

pub(crate) const DST_LABEL: &[u8] = b"quil/porep/sdr-label/v1";
const DST_GRAPH: &[u8] = b"quil/porep/sdr-graph/v1";

/// Two 64-bit values deterministically derived for a graph edge. `kind` = 0 for
/// DRG (in-layer) edges, 1 for expander (prior-layer) edges. Key-INDEPENDENT:
/// the graph is fixed across all replicas.
fn graph_rng(v: u64, kind: u8, edge_idx: u32) -> (u64, u64) {
    let mut h = Sha3_256::new();
    h.update(DST_GRAPH);
    h.update(v.to_be_bytes());
    h.update([kind]);
    h.update(edge_idx.to_be_bytes());
    let d = h.finalize();
    let mut a = [0u8; 8];
    let mut b = [0u8; 8];
    a.copy_from_slice(&d[0..8]);
    b.copy_from_slice(&d[8..16]);
    (u64::from_be_bytes(a), u64::from_be_bytes(b))
}

/// In-layer DRG parents of node `v`: the chain edge `(v-1)` plus `drg_degree-1`
/// DRSample back-edges with the log-uniform "bucket" distribution.
///
/// AUDIT: this is the distribution to validate against the reference. The bucket
/// `j ∈ [1, ⌊log2 v⌋+1]`, then a node uniformly in `[2^(j-1), min(v, 2^j))`.
pub(crate) fn drg_parents(v: u64, drg_degree: usize, out: &mut Vec<u64>) {
    out.clear();
    if v == 0 {
        return;
    }
    out.push(v - 1); // chain edge guarantees a Hamiltonian path
    let logv = (64 - v.leading_zeros()) as u64; // ⌊log2 v⌋ + 1
    for e in 1..drg_degree {
        let (a, b) = graph_rng(v, 0, e as u32);
        let j = 1 + (a % logv.max(1));
        let lo = 1u64 << (j - 1);
        let hi = (1u64 << j).min(v);
        let span = hi.saturating_sub(lo).max(1);
        let dist = (lo + (b % span)).min(v);
        out.push(v - dist);
    }
}

/// Expander parents of node `v` in the PRIOR layer: `expander_degree` uniformly
/// random nodes in `[0, n)`.
pub(crate) fn expander_parents(v: u64, expander_degree: usize, n: u64, out: &mut Vec<u64>) {
    out.clear();
    if n == 0 {
        return;
    }
    for e in 0..expander_degree {
        let (a, _) = graph_rng(v, 1, e as u32);
        out.push(a % n);
    }
}

#[inline]
fn node<'a>(buf: &'a [u8], idx: u64, nb: usize) -> &'a [u8] {
    let s = idx as usize * nb;
    &buf[s..s + nb]
}

/// In-layer and expander parents of every node, `width` entries per node
/// (`drg` DRG parents, absent for node 0, then `expander_degree` expander
/// parents). The graph is key-independent and the same in every layer, so it
/// is derived once per leaf, in parallel, rather than once per layer; it costs
/// `4·width` bytes per node. `None` when node indices do not fit in `u32`.
pub(crate) fn graph_parents(n: usize, params: &SdrParams) -> Option<(Vec<u32>, usize, usize)> {
    use rayon::prelude::*;
    if u32::try_from(n).is_err() {
        return None;
    }
    let drg = params.drg_degree.max(1);
    let width = drg + params.expander_degree;
    let mut table = vec![0u32; n * width];
    table.par_chunks_mut(width).enumerate().for_each_init(
        || (Vec::with_capacity(drg), Vec::with_capacity(params.expander_degree)),
        |(dpar, epar), (v, row)| {
            drg_parents(v as u64, params.drg_degree, dpar);
            expander_parents(v as u64, params.expander_degree, n as u64, epar);
            let (drg_row, expander_row) = row.split_at_mut(drg);
            for (slot, p) in drg_row.iter_mut().zip(dpar.iter()) {
                *slot = *p as u32; // node 0 has no DRG parents
            }
            for (slot, p) in expander_row.iter_mut().zip(epar.iter()) {
                *slot = *p as u32;
            }
        },
    );
    Some((table, drg, width))
}

/// Compute the final-layer labels (the key-stream) for a leaf of `n` nodes.
/// Two layers resident at a time, plus the parent table of [`graph_parents`].
/// Labelling stays sequential: every label depends on its predecessor.
fn final_layer_labels(n: usize, key: &[u8], params: &SdrParams) -> Vec<u8> {
    label_layers(n, key, params, &mut |_, _| {})
}

/// [`final_layer_labels`], handing every finished layer to `on_layer` (its
/// index and labels) before the next one is computed. The hash-based storage
/// proofs fold each layer into the column commitment and keep the labels of
/// the nodes a seal proof opens; the labels themselves are unchanged.
pub(crate) fn label_layers(
    n: usize,
    key: &[u8],
    params: &SdrParams,
    on_layer: &mut dyn FnMut(usize, &[u8]),
) -> Vec<u8> {
    let Some((parents, drg, width)) = graph_parents(n, params) else {
        return label_layers_uncached(n, key, params, on_layer);
    };
    let nb = params.node_bytes;
    let mut prev = vec![0u8; n * nb]; // layer -1: no expander parents on layer 0
    let mut cur = vec![0u8; n * nb];
    for layer in 0..params.layers {
        for v in 0..n {
            let row = &parents[v * width..(v + 1) * width];
            let (dpar, epar) = row.split_at(drg);
            let mut h = Sha3_256::new();
            h.update(DST_LABEL);
            h.update((key.len() as u32).to_be_bytes());
            h.update(key);
            h.update((layer as u32).to_be_bytes());
            h.update((v as u64).to_be_bytes());
            if v > 0 {
                for &p in dpar {
                    h.update(node(&cur, p as u64, nb)); // DRG parents are < v ⇒ already labelled
                }
            }
            if layer > 0 {
                for &p in epar {
                    h.update(node(&prev, p as u64, nb)); // expander parents from the prior layer
                }
            }
            let lbl = h.finalize();
            cur[v * nb..v * nb + nb].copy_from_slice(&lbl[..nb]);
        }
        on_layer(layer, &cur);
        std::mem::swap(&mut prev, &mut cur);
    }
    prev // after the final swap, `prev` holds layer L-1
}

/// [`final_layer_labels`] deriving parents on every layer, for leaves whose
/// node indices exceed `u32` and as the reference the cached path must match.
#[cfg(test)]
fn final_layer_labels_uncached(n: usize, key: &[u8], params: &SdrParams) -> Vec<u8> {
    label_layers_uncached(n, key, params, &mut |_, _| {})
}

/// [`label_layers`] deriving parents on every layer.
fn label_layers_uncached(
    n: usize,
    key: &[u8],
    params: &SdrParams,
    on_layer: &mut dyn FnMut(usize, &[u8]),
) -> Vec<u8> {
    let nb = params.node_bytes;
    let mut prev = vec![0u8; n * nb]; // layer -1: no expander parents on layer 0
    let mut cur = vec![0u8; n * nb];
    let mut dpar: Vec<u64> = Vec::with_capacity(params.drg_degree);
    let mut epar: Vec<u64> = Vec::with_capacity(params.expander_degree);

    for layer in 0..params.layers {
        for v in 0..n as u64 {
            drg_parents(v, params.drg_degree, &mut dpar);
            if layer == 0 {
                epar.clear();
            } else {
                expander_parents(v, params.expander_degree, n as u64, &mut epar);
            }
            let mut h = Sha3_256::new();
            h.update(DST_LABEL);
            h.update((key.len() as u32).to_be_bytes());
            h.update(key);
            h.update((layer as u32).to_be_bytes());
            h.update(v.to_be_bytes());
            for &p in &dpar {
                h.update(node(&cur, p, nb)); // DRG parents are < v ⇒ already labelled
            }
            for &p in &epar {
                h.update(node(&prev, p, nb)); // expander parents from the prior layer
            }
            let lbl = h.finalize();
            cur[v as usize * nb..v as usize * nb + nb].copy_from_slice(&lbl[..nb]);
        }
        on_layer(layer, &cur);
        std::mem::swap(&mut prev, &mut cur);
    }
    prev // after the final swap, `prev` holds layer L-1
}

/// Pad `len` up to a multiple of `node_bytes`.
fn padded_len(len: usize, nb: usize) -> usize {
    len.div_ceil(nb) * nb
}

/// Encode a leaf's `data` into a member-unique replica `R = data ⊕ labels_L`.
/// `key = H(member_id ‖ shard ‖ epoch)`. Output length is `data` padded up to a
/// whole number of nodes.
pub fn sdr_encode(data: &[u8], key: &[u8], params: &SdrParams) -> Vec<u8> {
    let nb = params.node_bytes;
    let plen = padded_len(data.len(), nb);
    let n = plen / nb;
    let labels = final_layer_labels(n, key, params);
    let mut out = vec![0u8; plen];
    for i in 0..data.len() {
        out[i] = data[i] ^ labels[i];
    }
    for i in data.len()..plen {
        out[i] = labels[i]; // padding XOR 0
    }
    out
}

/// Decode a replica back to its (padded) data: regenerate `labels_L`, XOR.
pub fn sdr_decode(replica: &[u8], key: &[u8], params: &SdrParams) -> Vec<u8> {
    let nb = params.node_bytes;
    let n = replica.len() / nb;
    let labels = final_layer_labels(n, key, params);
    replica.iter().zip(labels.iter()).map(|(r, l)| r ^ l).collect()
}

// ── Leaf commitment: a KZG vector-commitment tree over ≤256-element blocks ───
//
// The KZG ceremony domains cap at 256, so a ≤1 GB leaf cannot be a single
// polynomial. A leaf is committed exactly like the hypergraph's vector
// commitment tree (`hypergraph_state.rs`): chunk into blocks of `poly_size`
// nodes, KZG-commit each block, then build internal nodes whose `poly_size`
// leaves are the field-reduced commitments of the level below — recursing until
// one commitment (the `root`) remains. The fan-out equals the block polynomial
// size, so every commitment in the tree (blocks and internal nodes alike) is a
// KZG opening over the SAME domain. That uniformity lets the whole
// `point → block → … → root` authentication path fold into the same aggregate
// pairing batch as the possession opening (one final exponentiation per frame),
// and makes `root` a first-class KZG commitment — the same kind of object the
// rest of the system registers and binds into consensus.

/// Field elements per block / internal-node fan-out = the KZG ceremony cap.
pub const BLOCK_POLY_SIZE: u64 = 256;
/// Domain-separation tag for reducing a child commitment to a parent leaf value.
const DST_NODE: &[u8] = b"quil/porep/leaf-node/v1";

/// Reduce a (block or internal-node) KZG commitment to a 32-byte field-scalar
/// digest (< the curve order) — the value a parent node's vector commitment
/// holds at the child's slot. Mirrors the hypergraph tree's `hash_target`.
pub fn commit_to_scalar(commit: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DST_NODE);
    h.update((commit.len() as u32).to_be_bytes());
    h.update(commit);
    h.finalize().into()
}

/// Pack a replica byte slice (32-byte nodes) into full-width (73-byte) KZG
/// scalars, zero-padding up to `block_poly_size` elements. Each 32-byte node
/// (< the curve order) lands in the low bytes of its scalar.
pub fn pack_block(chunk: &[u8], block_poly_size: u64) -> Vec<u8> {
    const MB: usize = 73;
    const NB: usize = 32;
    let mut full = vec![0u8; block_poly_size as usize * MB];
    let nodes = chunk.len().div_ceil(NB);
    for i in 0..nodes {
        let s = i * NB;
        let e = (s + NB).min(chunk.len());
        let node = &chunk[s..e];
        let dst = i * MB + (MB - NB);
        full[dst..dst + node.len()].copy_from_slice(node);
    }
    full
}

/// Build one internal node's full-width KZG polynomial: its `poly_size` leaves
/// are the field-reduced commitments of (up to) `poly_size` children, the rest
/// zero-padded. Shared by commit + path so they pack identically.
fn node_poly(children: &[Vec<u8>], poly_size: u64) -> Vec<u8> {
    let mut chunk = Vec::with_capacity(children.len() * 32);
    for c in children {
        chunk.extend_from_slice(&commit_to_scalar(c));
    }
    pack_block(&chunk, poly_size)
}

/// A leaf's vector-commitment tree: every level's KZG commitments, bottom→top.
/// `levels[0]` = per-block commitments (kept so the prover can rebuild node
/// polynomials and openings); `levels.last() == [root]`.
pub struct LeafCommitment {
    pub root: Vec<u8>,
    pub levels: Vec<Vec<Vec<u8>>>,
    pub poly_size: u64,
}

impl LeafCommitment {
    /// The per-block KZG commitments (tree level 0).
    pub fn block_commitments(&self) -> &[Vec<u8>] {
        &self.levels[0]
    }
}

/// Number of internal-node levels above the blocks for a leaf of `num_blocks`
/// blocks with the given fan-out (0 when the leaf is a single block — the block
/// commitment is then the root). Matches [`commit_leaf`]'s level count exactly.
pub fn leaf_levels(num_blocks: u64, poly_size: u64) -> usize {
    let mut n = num_blocks.max(1);
    let mut l = 0usize;
    while n > 1 {
        n = n.div_ceil(poly_size);
        l += 1;
    }
    l
}

/// Commit a replica leaf as a KZG vector-commitment tree (see module note).
/// `poly_size` must be a supported ceremony domain (≤ [`BLOCK_POLY_SIZE`]) and
/// is both the block size and the internal-node fan-out. Requires
/// `bls48581::init()`.
pub fn commit_leaf(replica: &[u8], poly_size: u64) -> LeafCommitment {
    use rayon::prelude::*;
    const NB: usize = 32;
    let block_bytes = poly_size as usize * NB;

    // Level 0: per-block KZG commitments over the replica bytes.
    // Every block, like every internal node below, commits independently of
    // its siblings, so each level is committed in parallel, in order.
    let mut blocks: Vec<Vec<u8>> = replica
        .par_chunks(block_bytes)
        .map(|block| bls48581::commit_raw_full(&pack_block(block, poly_size), poly_size))
        .collect();
    if blocks.is_empty() {
        blocks.push(bls48581::commit_raw_full(&pack_block(&[], poly_size), poly_size));
    }

    // Internal levels: each node commits the field-reduced child commitments.
    let mut levels = vec![blocks];
    while levels.last().unwrap().len() > 1 {
        let cur = levels.last().unwrap();
        let next: Vec<Vec<u8>> = cur
            .par_chunks(poly_size as usize)
            .map(|group| bls48581::commit_raw_full(&node_poly(group, poly_size), poly_size))
            .collect();
        levels.push(next);
    }

    let root = levels.last().unwrap()[0].clone();
    LeafCommitment { root, levels, poly_size }
}

/// A leaf authentication path for one block: bottom→top, each level's parent
/// node commitment and the KZG proof opening it at the child's domain index to
/// the field-reduced child commitment. `node_commits.last() == root`.
pub struct LeafPath {
    /// Parent node commitments C_1..C_L (C_L == root). The block commitment C_0
    /// is carried separately by the caller.
    pub node_commits: Vec<Vec<u8>>,
    /// KZG proofs π_1..π_L; π_ℓ opens C_ℓ at the level-ℓ child index.
    pub proofs: Vec<Vec<u8>>,
}

/// Build the authentication path binding `block_index`'s block commitment up to
/// the leaf root. Empty for a single-block leaf (root == block commitment).
pub fn leaf_path(leaf: &LeafCommitment, block_index: u64) -> LeafPath {
    let poly = leaf.poly_size as usize;
    let mut node_commits = Vec::new();
    let mut proofs = Vec::new();
    let mut idx = block_index as usize;
    for lvl in 0..leaf.levels.len() - 1 {
        let cur = &leaf.levels[lvl];
        let parent_idx = idx / poly;
        let child_idx = idx % poly;
        let group_start = parent_idx * poly;
        let group_end = (group_start + poly).min(cur.len());
        let full = node_poly(&cur[group_start..group_end], leaf.poly_size);
        proofs.push(bls48581::prove_raw_full(&full, child_idx as u64, leaf.poly_size));
        node_commits.push(leaf.levels[lvl + 1][parent_idx].clone());
        idx = parent_idx;
    }
    LeafPath { node_commits, proofs }
}

/// Producer helper: SDR-encode a leaf's data into the member's unique replica
/// and commit it. `leaf_id` is `leaf_id_bytes(shard_filter, prefix)` — the same
/// id the registration and the storage openings key on. Returns the replica
/// bytes (held by the member to answer challenges) and its [`LeafCommitment`]
/// (whose `.root` is registered). Requires `bls48581::init()`.
pub fn build_leaf_replica(
    leaf_data: &[u8],
    member_id: &[u8],
    leaf_id: &[u8],
    epoch: u64,
    block_poly_size: u64,
    params: &SdrParams,
) -> (Vec<u8>, LeafCommitment) {
    let key = replica_key(member_id, leaf_id, epoch);
    let replica = sdr_encode(leaf_data, &key, params);
    let leaf = commit_leaf(&replica, block_poly_size);
    (replica, leaf)
}

/// Derive a member's replica key from its identity, shard, and epoch.
pub fn replica_key(member_id: &[u8], shard_id: &[u8], epoch: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"quil/porep/replica-key/v1");
    h.update((member_id.len() as u32).to_be_bytes());
    h.update(member_id);
    h.update((shard_id.len() as u32).to_be_bytes());
    h.update(shard_id);
    h.update(epoch.to_be_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_params() -> SdrParams {
        // Small leaf so tests run fast; structure identical to production.
        SdrParams { drg_degree: 6, expander_degree: 8, layers: 11, node_bytes: 32 }
    }

    fn data(n_nodes: usize) -> Vec<u8> {
        (0..n_nodes * 32).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect()
    }

    #[test]
    fn encode_decode_round_trips() {
        let p = small_params();
        let key = replica_key(b"member0", b"shardA", 7);
        let d = data(64);
        let r = sdr_encode(&d, &key, &p);
        let back = sdr_decode(&r, &key, &p);
        assert_eq!(&back[..d.len()], &d[..], "decode(encode(data)) must equal data");
    }

    #[test]
    fn deterministic() {
        let p = small_params();
        let key = replica_key(b"member0", b"shardA", 7);
        let d = data(64);
        assert_eq!(sdr_encode(&d, &key, &p), sdr_encode(&d, &key, &p), "encode must be deterministic");
    }

    #[test]
    fn unique_per_key() {
        let p = small_params();
        let d = data(64);
        let r0 = sdr_encode(&d, &replica_key(b"member0", b"shardA", 7), &p);
        let r1 = sdr_encode(&d, &replica_key(b"member1", b"shardA", 7), &p); // different member
        let r2 = sdr_encode(&d, &replica_key(b"member0", b"shardB", 7), &p); // different shard
        let r3 = sdr_encode(&d, &replica_key(b"member0", b"shardA", 8), &p); // different epoch
        // Each distinct key yields a replica that differs in (essentially) every
        // node — no two members can share storage.
        let diff = |a: &[u8], b: &[u8]| a.iter().zip(b).filter(|(x, y)| x != y).count();
        assert!(diff(&r0, &r1) > r0.len() * 9 / 10, "different member ⇒ replica differs everywhere");
        assert!(diff(&r0, &r2) > r0.len() * 9 / 10, "different shard ⇒ replica differs everywhere");
        assert!(diff(&r0, &r3) > r0.len() * 9 / 10, "different epoch ⇒ replica differs everywhere");
    }

    /// End-to-end: the encoder's replica is committed via KZG and a possession
    /// opening at a ρ_N-derived point verifies through the storage-attestation
    /// path. Closes the encoder → commitment → opening → verify loop.
    ///
    /// NOTE: limited to a single ≤256-element block (the KZG ceremony domain
    /// cap). A full ≤1 GB leaf is a TREE of such blocks — see the integration
    /// note; this proves one block end-to-end.
    #[test]
    fn replica_block_feeds_porep_possession() {
        bls48581::init();
        let p = small_params();
        let poly_size = 64u64; // one block = 64 nodes (≤256 ceremony cap)
        let key = replica_key(b"member0", b"shardA", 7);
        // One full block of replica data (num_blocks == 1, so block index 0).
        let replica = sdr_encode(&data(poly_size as usize), &key, &p);
        let leaf = commit_leaf(&replica, poly_size);
        assert_eq!(leaf.block_commitments().len(), 1, "single block expected");
        // Single-block leaf: the root IS the block commitment, path is empty.
        assert_eq!(leaf.root, leaf.block_commitments()[0]);
        assert_eq!(leaf_levels(1, poly_size), 0);

        // Pack the (only) block and open it at the ρ_N-derived point.
        const MB: usize = 73;
        let full = pack_block(&replica, poly_size);
        let rho_n = [0xA1u8; 32];
        let bitmask = [0x01u8];
        let block = crate::porep::derive_block_index(&rho_n, b"shardA", 7, b"member0", 0, 1);
        assert_eq!(block, 0, "single-block leaf must challenge block 0");
        let idx = crate::porep::derive_challenge_index(&rho_n, b"shardA", 7, b"member0", 0, poly_size);
        let proof = bls48581::prove_raw_full(&full, idx, poly_size);
        let value = full[idx as usize * MB..idx as usize * MB + MB].to_vec();
        let path = leaf_path(&leaf, block);
        let opening = crate::porep::StorageOpening {
            shard_id: b"shardA".to_vec(),
            epoch: 7,
            member_id: b"member0".to_vec(),
            query: 0,
            leaf_root: leaf.root.clone(),
            num_blocks: 1,
            path_commits: path.node_commits,
            path_proofs: path.proofs,
            commitment: leaf.block_commitments()[0].clone(),
            value,
            proof,
        };
        assert!(
            crate::porep::verify_storage_attestation(&[opening], 100, &rho_n, &bitmask, poly_size),
            "an SDR replica block must produce a verifiable possession opening"
        );
    }

    #[test]
    fn cached_parents_label_exactly_like_per_layer_derivation() {
        let variants = [
            small_params(),
            SdrParams { drg_degree: 0, expander_degree: 8, layers: 3, node_bytes: 32 },
            SdrParams { drg_degree: 1, expander_degree: 0, layers: 2, node_bytes: 32 },
            SdrParams { drg_degree: 6, expander_degree: 8, layers: 1, node_bytes: 16 },
        ];
        let key = replica_key(b"member0", b"shardA", 7);
        for p in &variants {
            for n in [0usize, 1, 2, 3, 7, 64, 257, 1000] {
                assert_eq!(
                    final_layer_labels(n, &key, p),
                    final_layer_labels_uncached(n, &key, p),
                    "labels differ for n={n} params={p:?}"
                );
            }
        }
    }

    #[test]
    fn parallel_commitment_matches_sequential_tree() {
        bls48581::init();
        // Sequential construction as committed before parallelisation.
        fn sequential(replica: &[u8], poly_size: u64) -> Vec<Vec<Vec<u8>>> {
            let block_bytes = poly_size as usize * 32;
            let mut blocks = Vec::new();
            let mut off = 0;
            while off < replica.len() {
                let end = (off + block_bytes).min(replica.len());
                blocks.push(bls48581::commit_raw_full(&pack_block(&replica[off..end], poly_size), poly_size));
                off = end;
            }
            if blocks.is_empty() {
                blocks.push(bls48581::commit_raw_full(&pack_block(&[], poly_size), poly_size));
            }
            let mut levels = vec![blocks];
            while levels.last().unwrap().len() > 1 {
                let next = levels.last().unwrap().chunks(poly_size as usize)
                    .map(|group| bls48581::commit_raw_full(&node_poly(group, poly_size), poly_size))
                    .collect();
                levels.push(next);
            }
            levels
        }
        let poly = 16u64;
        // 259 blocks, the last one partial: 259 → 17 → 2 → root.
        for len in [0usize, 100, 16 * 32 * 259 - 200] {
            let replica = data(len.div_ceil(32))[..len].to_vec();
            let leaf = commit_leaf(&replica, poly);
            let expected = sequential(&replica, poly);
            assert_eq!(leaf.levels, expected, "tree differs for {len} bytes");
            assert_eq!(&leaf.root, &expected.last().unwrap()[0]);
        }
        assert_eq!(commit_leaf(&data(259 * 16), poly).levels.len(), 4);
    }
}
