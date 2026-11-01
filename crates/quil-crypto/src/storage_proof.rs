//! Hash-based storage proofs: Poseidon2 Merkle commitments over a member's SDR
//! replica, single-node possession openings, and the seal proof that a
//! registered replica is the member's own encoding of the registered data.
//! They replace KZG over BLS48-581 (`sdr::commit_leaf` and the openings in
//! `porep`), which is not post-quantum, from
//! [`quil_types::consensus::hash_storage_proof_epoch`]. Nothing here uses a
//! pairing or a trusted setup. Every hash is [`crate::storage_hash`]'s
//! Poseidon2, so a STARK can recompute it.
//!
//! Per member, leaf and epoch:
//! - `D`: the leaf's canonical data, 30 bytes per node packed into 8 field
//!   elements ([`data_nodes`]);
//! - labels: the stacked depth-robust labelling over [`crate::sdr`]'s graph,
//!   keyed by [`sdr::replica_key`]`(member, leaf_id, epoch)`, which from the
//!   stable replica key epoch no longer depends on the epoch: a leaf's labels
//!   then depend on the member, the leaf and its node count alone;
//! - `R = D + labels[L-1]` element-wise, unique to the member and leaf (and,
//!   before that epoch, the epoch);
//! - `comm_D`, `comm_C`, `comm_R`: Merkle commitments over `D`, over the column
//!   digests (each node's labels on every layer, chained) and over `R`. The
//!   member registers all three.
//!
//! The seal proof answers challenges drawn from a GLOBAL beacon that postdates
//! the registration: for each challenged node it opens `D` and `R` there, and
//! the columns of the node and of its parents, and the verifier recomputes the
//! node's labels with the member's own key. A replica copied from another
//! member, shared between identities or filled with cheap junk does not pass.
//! Each frame a member then opens one beacon-chosen node of `R` per query,
//! against its registered `comm_R`. Both bind the epoch ([`seal_challenges`],
//! [`opening_index`]): with a stable key an unchanged leaf registers the same
//! commitments every epoch, and only the epoch and the beacon set one epoch's
//! proofs apart from another's.
//!
//! A node serializes as 32 bytes ([`NODE_BYTES`]): its 8 elements as
//! little-endian canonical `u32`s.

use rayon::prelude::*;
use sha3::{Digest as _, Sha3_256};

use crate::sdr::{self, SdrParams};
use crate::storage_hash::{self as hash, Digest, Domain};

pub const NODE_BYTES: usize = hash::DIGEST_BYTES;
pub type Node = [u8; NODE_BYTES];

/// Height of the subtrees a member recomputes from its replica to open a node.
/// It keeps only the levels above ([`MerkleCap`], ~2 MiB for a 1 GiB replica).
pub const CAP_HEIGHT: usize = 10;

/// A registration's leaf root: `comm_D ‖ comm_C ‖ comm_R`.
pub const REGISTRATION_ROOT_BYTES: usize = 3 * NODE_BYTES;

/// Leaves are kept small enough that a node index is one field element.
const MAX_NODES: u64 = 1 << 30;

/// Every leaf has at least two nodes, so every Merkle path has a level.
pub const MIN_NODES: usize = 2;

const DST_SEAL: &[u8] = b"quil/porep/v3/seal-challenge";
const DST_OPEN: &[u8] = b"quil/porep/v3/challenge";
const DST_ATTESTATION: &[u8] = b"quil/porep/v3/attestation-root";

/// Which commitment a tree is; bound into its root so a path for one tree
/// never verifies against another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tree {
    Data = 0,
    Column = 1,
    Replica = 2,
}

// ── Merkle trees ─────────────────────────────────────────────────────────────
//
// The leaves are the nodes themselves (a column tree's are column digests):
// every path has the depth its leaf count gives it, so no inner node can pose
// as a leaf.

/// The root of a subtree of `height` with no leaves: what stands in for the
/// missing right child at the end of a level.
fn empty_subtree(height: usize) -> Digest {
    static EMPTY: std::sync::OnceLock<Vec<Digest>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(|| {
        let mut levels = Vec::with_capacity(65);
        levels.push(hash::sponge(Domain::Empty, &[]));
        for height in 0..64 {
            let below = levels[height];
            levels.push(hash::compress(&below, &below, Domain::Node));
        }
        levels
    })[height]
}

/// Levels above the leaves of a tree of `n` leaves (0 for one leaf).
pub fn tree_depth(n: u64) -> usize {
    if n <= 1 {
        0
    } else {
        (64 - (n - 1).leading_zeros()) as usize
    }
}

/// The commitment: the root bound to which tree it is and how many leaves it
/// has, so neither a padding position nor another tree's path can open it.
fn bind(tree: Tree, n: u64, root: &Digest) -> Digest {
    debug_assert!(n < MAX_NODES);
    let mut header = hash::ZERO;
    header[0] = hash::felt(tree as u32);
    header[1] = hash::felt(n as u32);
    let mut absorber = hash::Absorber::new(Domain::Root, 2 * hash::DIGEST_ELEMS);
    absorber.absorb_digest(&header);
    absorber.absorb_digest(root);
    absorber.finish()
}

/// The level above `level`, which sits at `height`.
fn parent_level(level: &[Digest], height: usize) -> Vec<Digest> {
    level
        .par_chunks(2)
        .map(|pair| {
            let right = pair
                .get(1)
                .copied()
                .unwrap_or_else(|| empty_subtree(height));
            hash::compress(&pair[0], &right, Domain::Node)
        })
        .collect()
}

/// A whole tree, every level held.
pub struct MerkleTree {
    n: u64,
    levels: Vec<Vec<Digest>>,
}

impl MerkleTree {
    /// The tree over serialized nodes; `None` unless a whole, non-zero number
    /// of canonical 32-byte nodes.
    pub fn from_nodes(nodes: &[u8]) -> Option<Self> {
        let leaves = hash::digests_from_bytes(nodes)?;
        (!leaves.is_empty() && (leaves.len() as u64) < MAX_NODES)
            .then(|| Self::from_digests(leaves))
    }

    /// The tree over `leaves`, at least one.
    pub fn from_digests(leaves: Vec<Digest>) -> Self {
        assert!(!leaves.is_empty(), "a storage tree needs a leaf");
        assert!(
            (leaves.len() as u64) < MAX_NODES,
            "a storage tree of {} leaves is too large",
            leaves.len()
        );
        let n = leaves.len() as u64;
        let mut levels = vec![leaves];
        for height in 0..tree_depth(n) {
            let next = parent_level(levels.last().expect("a level"), height);
            levels.push(next);
        }
        Self { n, levels }
    }

    pub fn n(&self) -> u64 {
        self.n
    }

    pub fn commitment(&self, tree: Tree) -> Node {
        hash::to_bytes(&bind(tree, self.n, &self.levels.last().expect("a root")[0]))
    }

    /// Sibling nodes from leaf `index` up to the root.
    pub fn path(&self, index: u64) -> Vec<Node> {
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        let mut i = index as usize;
        for (height, level) in self.levels[..self.levels.len() - 1].iter().enumerate() {
            path.push(hash::to_bytes(
                &level
                    .get(i ^ 1)
                    .copied()
                    .unwrap_or_else(|| empty_subtree(height)),
            ));
            i >>= 1;
        }
        path
    }

    /// The levels from `height` up (all of them above a shallower tree's leaves).
    pub fn cap(&self, height: usize) -> MerkleCap {
        let height = height.min(self.levels.len() - 1);
        MerkleCap {
            n: self.n,
            height,
            levels: self.levels[height..].to_vec(),
        }
    }
}

/// Whether `path` opens leaf `index` of the `tree` committed as `commitment`,
/// with `n` leaves, to `value`.
pub fn verify_path(
    tree: Tree,
    n: u64,
    commitment: &Node,
    index: u64,
    value: &Node,
    path: &[Node],
) -> bool {
    if index >= n || n >= MAX_NODES || path.len() != tree_depth(n) {
        return false;
    }
    let Some(mut acc) = hash::from_bytes(value) else {
        return false;
    };
    let mut i = index;
    for sibling in path {
        let Some(sibling) = hash::from_bytes(sibling) else {
            return false;
        };
        acc = if i & 1 == 0 {
            hash::compress(&acc, &sibling, Domain::Node)
        } else {
            hash::compress(&sibling, &acc, Domain::Node)
        };
        i >>= 1;
    }
    hash::to_bytes(&bind(tree, n, &acc)) == *commitment
}

/// The upper levels of a tree: with the leaves themselves they give any path,
/// recomputing only the subtree of `2^height` leaves below the cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleCap {
    pub n: u64,
    pub height: usize,
    /// Tree levels from `height` to the root.
    pub levels: Vec<Vec<Digest>>,
}

impl MerkleCap {
    pub fn commitment(&self, tree: Tree) -> Node {
        hash::to_bytes(&bind(tree, self.n, &self.levels.last().expect("a root")[0]))
    }

    /// The path for leaf `index`, `nodes` being the tree's serialized leaves
    /// (the replica). `None` when `index` or `nodes` do not fit the tree.
    pub fn path(&self, nodes: &[u8], index: u64) -> Option<Vec<Node>> {
        if index >= self.n || nodes.len() as u64 != self.n * NODE_BYTES as u64 {
            return None;
        }
        let below = self.subtree(index)?;
        self.subtree_path(
            &nodes[below.start as usize * NODE_BYTES..below.end as usize * NODE_BYTES],
            index,
        )
    }

    /// The leaves below the cap that a path for `index` is recomputed from:
    /// all a member reads of its replica to open that node.
    pub fn subtree(&self, index: u64) -> Option<std::ops::Range<u64>> {
        if index >= self.n {
            return None;
        }
        let start = (index >> self.height) << self.height;
        Some(start..(start + (1u64 << self.height)).min(self.n))
    }

    /// [`Self::path`] from only the leaves [`Self::subtree`] names for
    /// `index` (`subtree`, serialized). `None` when they do not fit the tree.
    pub fn subtree_path(&self, subtree: &[u8], index: u64) -> Option<Vec<Node>> {
        let below = self.subtree(index)?;
        if subtree.len() as u64 != (below.end - below.start) * NODE_BYTES as u64 {
            return None;
        }
        let start = below.start as usize;
        let mut level = hash::digests_from_bytes(subtree)?;
        let mut path = Vec::with_capacity(tree_depth(self.n));
        let mut i = index as usize - start;
        for height in 0..self.height {
            path.push(hash::to_bytes(
                &level
                    .get(i ^ 1)
                    .copied()
                    .unwrap_or_else(|| empty_subtree(height)),
            ));
            level = parent_level(&level, height);
            i >>= 1;
        }
        let mut i = (index >> self.height) as usize;
        if level.first() != self.levels[0].get(i) {
            return None; // `nodes` are not this tree's leaves
        }
        for (above, cap_level) in self.levels[..self.levels.len() - 1].iter().enumerate() {
            path.push(hash::to_bytes(
                &cap_level
                    .get(i ^ 1)
                    .copied()
                    .unwrap_or_else(|| empty_subtree(self.height + above)),
            ));
            i >>= 1;
        }
        Some(path)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let nodes: usize = self.levels.iter().map(Vec::len).sum();
        let mut out = Vec::with_capacity(9 + nodes * NODE_BYTES);
        out.extend_from_slice(&self.n.to_be_bytes());
        out.push(self.height as u8);
        for level in &self.levels {
            out.extend_from_slice(&hash::digests_to_bytes(level));
        }
        out
    }

    /// Strict inverse of [`Self::to_bytes`]: every level must have exactly the
    /// size the leaf count gives it, every node be canonical, and the levels
    /// hash up to the root.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let n = u64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
        let height = *bytes.get(8)? as usize;
        let depth = tree_depth(n);
        if n == 0 || n >= MAX_NODES || height > depth {
            return None;
        }
        let mut rest = &bytes[9..];
        let mut levels = Vec::with_capacity(depth - height + 1);
        for at in height..=depth {
            let len = n.div_ceil(1u64 << at) as usize;
            levels.push(hash::digests_from_bytes(rest.get(..len * NODE_BYTES)?)?);
            rest = &rest[len * NODE_BYTES..];
        }
        if !rest.is_empty() {
            return None;
        }
        for (above, pair) in levels.windows(2).enumerate() {
            if parent_level(&pair[0], height + above) != pair[1] {
                return None;
            }
        }
        Some(Self { n, height, levels })
    }
}

// ── Encoding ─────────────────────────────────────────────────────────────────

/// A node's label on `layer`: the sponge over the member's key, the layer and
/// node (`[layer, v, 0, …]`), its DRG parents' labels on this layer and its
/// expander parents' on the layer below, 8 elements each, so every block of
/// 16 absorbs two whole digests. The input has a fixed shape: absent parents
/// (node 0 has no DRG parents, layer 0 reads no layer below) are zero
/// digests.
fn label(
    key: &Digest,
    layer: usize,
    v: u64,
    same_layer: &mut dyn Iterator<Item = Digest>,
    layer_below: &mut dyn Iterator<Item = Digest>,
    params: &SdrParams,
) -> Digest {
    let length = hash::DIGEST_ELEMS * (2 + params.drg_degree + params.expander_degree);
    let mut absorber = hash::Absorber::new(Domain::Label, length);
    absorber.absorb_digest(key);
    let mut header = hash::ZERO;
    header[0] = hash::felt(layer as u32);
    header[1] = hash::felt(v as u32);
    absorber.absorb_digest(&header);
    for _ in 0..params.drg_degree {
        let parent = if v > 0 {
            same_layer.next().unwrap_or(hash::ZERO)
        } else {
            hash::ZERO
        };
        absorber.absorb_digest(&parent);
    }
    for _ in 0..params.expander_degree {
        let parent = if layer > 0 {
            layer_below.next().unwrap_or(hash::ZERO)
        } else {
            hash::ZERO
        };
        absorber.absorb_digest(&parent);
    }
    absorber.finish()
}

/// Nodes [`label_leaf_until`] labels between looks at whether to stop: a
/// few milliseconds of a core's work.
pub const STOP_CHECK_NODES: usize = 1024;

/// Every node's labels, layer by layer, handing each finished layer to
/// `on_layer`; returns the last. Two layers resident at a time, plus the
/// parent table of [`sdr::graph_parents`]. Labelling is sequential within a
/// layer: every label depends on its predecessor.
fn label_layers(
    n: usize,
    key: &Digest,
    params: &SdrParams,
    on_layer: &mut dyn FnMut(usize, &[Digest]),
) -> Vec<Digest> {
    label_layers_until(n, key, params, on_layer, &|| false)
        .expect("labelling that never stops ends")
}

/// [`label_layers`], given up (`None`) once `stop` says so, looked at every
/// [`STOP_CHECK_NODES`] nodes.
fn label_layers_until(
    n: usize,
    key: &Digest,
    params: &SdrParams,
    on_layer: &mut dyn FnMut(usize, &[Digest]),
    stop: &dyn Fn() -> bool,
) -> Option<Vec<Digest>> {
    let (parents, drg, width) =
        sdr::graph_parents(n, params).expect("a leaf's node indices fit in u32");
    let mut prev = vec![hash::ZERO; n];
    let mut cur = vec![hash::ZERO; n];
    for layer in 0..params.layers {
        for v in 0..n {
            if v % STOP_CHECK_NODES == 0 && stop() {
                return None;
            }
            let row = &parents[v * width..(v + 1) * width];
            let (dpar, epar) = row.split_at(drg);
            let lbl = label(
                key,
                layer,
                v as u64,
                &mut dpar.iter().map(|&p| cur[p as usize]),
                &mut epar.iter().map(|&p| prev[p as usize]),
                params,
            );
            cur[v] = lbl;
        }
        on_layer(layer, &cur);
        std::mem::swap(&mut prev, &mut cur);
    }
    Some(prev) // after the final swap, `prev` holds layer L-1
}

fn column_step(previous: &Digest, label: &Digest) -> Digest {
    hash::compress(previous, label, Domain::Column)
}

/// A node's column digest: its labels on every layer, bottom first, chained.
pub fn column_digest(labels: &[Node]) -> Option<Node> {
    let mut acc = hash::ZERO;
    for label in labels {
        acc = column_step(&acc, &hash::from_bytes(label)?);
    }
    Some(hash::to_bytes(&acc))
}

fn fold_layer(columns: &mut [Digest], layer: &[Digest]) {
    columns
        .par_iter_mut()
        .zip(layer.par_iter())
        .for_each(|(column, label)| *column = column_step(column, label));
}

/// The leaf's data as serialized nodes: 30 bytes per node, zero-padded to at
/// least [`MIN_NODES`].
pub fn data_nodes(data: &[u8]) -> Vec<u8> {
    hash::digests_to_bytes(&packed_data(data))
}

fn packed_data(data: &[u8]) -> Vec<Digest> {
    let mut nodes: Vec<Digest> = data
        .par_chunks(hash::DATA_BYTES_PER_NODE)
        .map(hash::pack_node)
        .collect();
    nodes.resize(nodes.len().max(MIN_NODES), hash::ZERO);
    nodes
}

/// A member's encoded leaf: what it stores and what it registers.
pub struct EncodedLeaf {
    pub n: u64,
    /// The replica's serialized nodes.
    pub replica: Vec<u8>,
    pub comm_d: Node,
    pub comm_c: Node,
    pub comm_r: Node,
    /// What, with the replica, opens any node of it.
    pub replica_cap: MerkleCap,
}

impl EncodedLeaf {
    pub fn registration_root(&self) -> Vec<u8> {
        registration_root(&self.comm_d, &self.comm_c, &self.comm_r)
    }
}

fn check_params(params: &SdrParams) {
    assert_eq!(
        params.node_bytes, NODE_BYTES,
        "hash storage proofs use 32-byte nodes"
    );
}

/// Nodes a leaf of `bytes` data bytes takes ([`data_nodes`]).
pub fn data_node_count(bytes: u64) -> u64 {
    bytes
        .div_ceil(hash::DATA_BYTES_PER_NODE as u64)
        .max(MIN_NODES as u64)
}

/// Bytes [`encode_leaf`] or [`prove_seal`] holds at its peak for a leaf of
/// `n` nodes: the leaf's nodes six times over (its data or replica as given
/// and as digests, the column digests, two label layers, and the trees built
/// after) and the parent table.
pub fn labelling_peak_bytes(n: u64, params: &SdrParams) -> u64 {
    let parents = 4 * (params.drg_degree.max(1) + params.expander_degree);
    n.saturating_mul((6 * NODE_BYTES + parents) as u64)
}

/// Nodes a registration may pad a leaf's data with, with zeros, beyond its
/// own ([`data_node_count`]): an eighth of them and this many more. A member
/// labels a leaf ahead of its snapshot ([`label_leaf`]) at a count it picks
/// then ([`precompute_nodes`]), so the data may have grown or shrunk a little
/// by the snapshot (decided 2026-10-26).
pub const PAD_FLOOR_NODES: u64 = 4096;

/// The most nodes a leaf whose data takes `exact` may register.
pub fn max_padded_nodes(exact: u64) -> u64 {
    exact
        .saturating_add(exact / 8)
        .saturating_add(PAD_FLOOR_NODES)
}

/// Whether a leaf whose data takes `exact` nodes may register `n`.
pub fn padded_nodes_allowed(exact: u64, n: u64) -> bool {
    exact <= n && n <= max_padded_nodes(exact) && n < MAX_NODES
}

/// The node count to label a leaf at ahead of its snapshot, its data taking
/// `exact` nodes now: registrable for data that grows by up to a sixteenth or
/// shrinks by up to about a twentieth by then.
pub fn precompute_nodes(exact: u64) -> u64 {
    exact + exact / 16 + PAD_FLOOR_NODES / 2
}

/// Encode `data` into the replica keyed by `key`
/// ([`sdr::replica_key`]`(member, leaf_id, epoch)`) and commit to it.
pub fn encode_leaf(data: &[u8], key: &[u8], params: &SdrParams) -> EncodedLeaf {
    let n = data_node_count(data.len() as u64);
    encode_leaf_at(data, key, params, n, &mut |_, _| {})
}

/// [`encode_leaf`] at `n` nodes, the data zero-padded to them, handing each
/// finished layer to `on_layer` (to keep for the seal,
/// [`prove_seal_with_labels`]).
pub fn encode_leaf_at(
    data: &[u8],
    key: &[u8],
    params: &SdrParams,
    n: u64,
    on_layer: &mut dyn FnMut(usize, &[Digest]),
) -> EncodedLeaf {
    let mut data = packed_data(data);
    assert!(
        n as usize >= data.len(),
        "a leaf of {} nodes encoded at {n}",
        data.len()
    );
    data.resize(n as usize, hash::ZERO);
    let comm_d = MerkleTree::from_digests(data.clone()).commitment(Tree::Data);
    let (last, columns) = label_leaf(n, key, params, on_layer);
    let comm_c = MerkleTree::from_digests(columns).commitment(Tree::Column);
    assemble(data, &last, comm_d, comm_c)
}

/// A leaf's labels, which depend on its key and node count alone, never on
/// its data: each finished layer goes to `on_layer`; returns the last layer
/// and every node's column digest.
pub fn label_leaf(
    n: u64,
    key: &[u8],
    params: &SdrParams,
    on_layer: &mut dyn FnMut(usize, &[Digest]),
) -> (Vec<Digest>, Vec<Digest>) {
    label_leaf_until(n, key, params, on_layer, &|| false).expect("labelling that never stops ends")
}

/// [`label_leaf`], given up (`None`, the layers handed to `on_layer` so far
/// partial) once `stop` says so, looked at every [`STOP_CHECK_NODES`] nodes:
/// for work that must give its memory back to other work.
pub fn label_leaf_until(
    n: u64,
    key: &[u8],
    params: &SdrParams,
    on_layer: &mut dyn FnMut(usize, &[Digest]),
    stop: &dyn Fn() -> bool,
) -> Option<(Vec<Digest>, Vec<Digest>)> {
    check_params(params);
    assert!(
        (MIN_NODES as u64..MAX_NODES).contains(&n),
        "a leaf of {n} nodes"
    );
    let n = n as usize;
    let mut columns = vec![hash::ZERO; n];
    let last = label_layers_until(
        n,
        &hash::key_digest(key),
        params,
        &mut |index, layer| {
            fold_layer(&mut columns, layer);
            on_layer(index, layer);
        },
        stop,
    )?;
    Some((last, columns))
}

/// [`encode_leaf_at`] from the leaf's labels at `n` nodes ([`label_leaf`],
/// keyed alike): its `last` layer and column commitment. What is left is the
/// data's part: its tree, the replica and the replica's tree.
pub fn encode_with_labels(
    data: &[u8],
    n: u64,
    last: &[Digest],
    comm_c: Node,
) -> Result<EncodedLeaf, String> {
    let mut data = packed_data(data);
    if n >= MAX_NODES || (n as usize) < data.len() || last.len() as u64 != n {
        return Err(format!(
            "labels of {} nodes at {n} for data of {}",
            last.len(),
            data.len()
        ));
    }
    data.resize(n as usize, hash::ZERO);
    let comm_d = MerkleTree::from_digests(data.clone()).commitment(Tree::Data);
    Ok(assemble(data, last, comm_d, comm_c))
}

/// The replica, `data + last`, with its tree.
fn assemble(data: Vec<Digest>, last: &[Digest], comm_d: Node, comm_c: Node) -> EncodedLeaf {
    let n = data.len() as u64;
    let replica: Vec<Digest> = data
        .par_iter()
        .zip(last.par_iter())
        .map(|(d, l)| hash::add(d, l))
        .collect();
    drop(data);
    let replica_bytes = hash::digests_to_bytes(&replica);
    let replica_tree = MerkleTree::from_digests(replica);
    EncodedLeaf {
        n,
        comm_d,
        comm_c,
        comm_r: replica_tree.commitment(Tree::Replica),
        replica_cap: replica_tree.cap(CAP_HEIGHT),
        replica: replica_bytes,
    }
}

/// The leaf root a registration carries.
pub fn registration_root(comm_d: &Node, comm_c: &Node, comm_r: &Node) -> Vec<u8> {
    [comm_d.as_slice(), comm_c, comm_r].concat()
}

/// The three commitments of a registration's leaf root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registered {
    pub comm_d: Node,
    pub comm_c: Node,
    pub comm_r: Node,
}

pub fn parse_registration_root(root: &[u8]) -> Option<Registered> {
    if root.len() != REGISTRATION_ROOT_BYTES {
        return None;
    }
    let node = |at: usize| -> Option<Node> {
        let bytes: Node = root[at..at + NODE_BYTES].try_into().expect("32 bytes");
        hash::from_bytes(&bytes).map(|_| bytes)
    };
    Some(Registered {
        comm_d: node(0)?,
        comm_c: node(NODE_BYTES)?,
        comm_r: node(2 * NODE_BYTES)?,
    })
}

// ── Seal proofs ──────────────────────────────────────────────────────────────

/// What a seal proof is about: one member's registration of one leaf.
#[derive(Clone, Copy, Debug)]
pub struct SealStatement<'a> {
    pub member: &'a [u8],
    pub leaf_id: &'a [u8],
    pub epoch: u64,
    pub n: u64,
    pub registered: Registered,
    /// The storage beacon of the GLOBAL frame after the one that recorded the
    /// registration, which the member could not know when it committed.
    pub beacon: &'a [u8],
}

fn put_bytes(h: &mut Sha3_256, bytes: &[u8]) {
    h.update((bytes.len() as u32).to_be_bytes());
    h.update(bytes);
}

/// The nodes a seal proof opens, `count` of them, from its beacon.
pub fn seal_challenges(statement: &SealStatement, count: usize) -> Vec<u64> {
    (0..count as u32)
        .map(|c| {
            let mut h = Sha3_256::new();
            h.update(DST_SEAL);
            put_bytes(&mut h, statement.beacon);
            put_bytes(&mut h, statement.member);
            put_bytes(&mut h, statement.leaf_id);
            h.update(statement.epoch.to_be_bytes());
            h.update(statement.n.to_be_bytes());
            h.update(statement.registered.comm_d);
            h.update(statement.registered.comm_c);
            h.update(statement.registered.comm_r);
            h.update(c.to_be_bytes());
            let digest = h.finalize();
            u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) % statement.n.max(1)
        })
        .collect()
}

/// The parents whose labels give node `v`'s, in labelling order: those in its
/// own layer, then those in the layer below.
pub fn parents_of(v: u64, n: u64, params: &SdrParams) -> (Vec<u64>, Vec<u64>) {
    let mut same_layer = Vec::new();
    if v > 0 {
        sdr::drg_parents(v, params.drg_degree, &mut same_layer);
    }
    let mut layer_below = Vec::new();
    sdr::expander_parents(v, params.expander_degree, n, &mut layer_below);
    (same_layer, layer_below)
}

/// One node's labels on every layer, with its path in `comm_C`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnOpening {
    pub labels: Vec<Node>,
    pub path: Vec<Node>,
}

/// The answer to one seal challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealOpening {
    pub data: Node,
    pub data_path: Vec<Node>,
    pub replica: Node,
    pub replica_path: Vec<Node>,
    pub column: ColumnOpening,
    /// The parents' columns, in [`parents_of`] order.
    pub parents: Vec<ColumnOpening>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealProof {
    pub openings: Vec<SealOpening>,
}

/// Prove that `replica` (its serialized nodes) is the member's encoding
/// committed in `statement`. Relabels the leaf once, keeping the challenged
/// nodes' and their parents' labels, and recovers the data as
/// `replica - labels[L-1]`. Fails when the commitments are not this
/// replica's.
pub fn prove_seal(
    replica: &[u8],
    statement: &SealStatement,
    params: &SdrParams,
    count: usize,
) -> Result<SealProof, String> {
    let mut seal = Seal::new(replica, statement, params, count)?;
    let key = hash::key_digest(&sdr::replica_key(
        statement.member,
        statement.leaf_id,
        statement.epoch,
    ));
    let mut columns = vec![hash::ZERO; seal.replica.len()];
    let last = label_layers(seal.replica.len(), &key, params, &mut |_, layer| {
        fold_layer(&mut columns, layer);
        for (v, labels) in seal.kept.iter_mut() {
            labels.push(hash::to_bytes(&layer[*v as usize]));
        }
    });
    seal.finish(statement, columns, last)
}

/// Labels a member kept when it labelled a leaf ([`label_leaf`]), which a
/// seal opens instead of labelling the leaf again.
pub trait LabelSource {
    /// Node `v`'s label on `layer`.
    fn label(&self, layer: usize, v: u64) -> Option<Node>;
    /// Every node's column digest.
    fn columns(&self) -> Option<Vec<Digest>>;
    /// The last layer.
    fn last_layer(&self) -> Option<Vec<Digest>>;
}

/// [`prove_seal`] from the labels kept when the leaf was labelled, with no
/// labelling. Fails, as it does, when they are not the registration's.
pub fn prove_seal_with_labels(
    replica: &[u8],
    statement: &SealStatement,
    params: &SdrParams,
    count: usize,
    labels: &dyn LabelSource,
) -> Result<SealProof, String> {
    let mut seal = Seal::new(replica, statement, params, count)?;
    let n = seal.replica.len();
    let columns = labels
        .columns()
        .filter(|columns| columns.len() == n)
        .ok_or("no kept column digests for the leaf")?;
    for (v, kept) in seal.kept.iter_mut() {
        for layer in 0..params.layers {
            kept.push(
                labels
                    .label(layer, *v)
                    .ok_or("a kept label is missing or not canonical")?,
            );
        }
        if column_digest(kept) != Some(hash::to_bytes(&columns[*v as usize])) {
            return Err("the kept labels are not the kept columns'".into());
        }
    }
    let last = labels
        .last_layer()
        .filter(|last| last.len() == n)
        .ok_or("no kept last layer for the leaf")?;
    seal.finish(statement, columns, last)
}

/// A seal proof being made: the replica, the challenges and their parents,
/// and the labels kept for each node they name.
struct Seal {
    replica: Vec<Digest>,
    challenges: Vec<u64>,
    parents: Vec<(Vec<u64>, Vec<u64>)>,
    kept: std::collections::BTreeMap<u64, Vec<Node>>,
}

impl Seal {
    fn new(
        replica: &[u8],
        statement: &SealStatement,
        params: &SdrParams,
        count: usize,
    ) -> Result<Self, String> {
        check_params(params);
        let n = statement.n as usize;
        if n < MIN_NODES || statement.n >= MAX_NODES || replica.len() != n * NODE_BYTES {
            return Err(format!(
                "replica is {} bytes, the registration has {n} nodes",
                replica.len()
            ));
        }
        let replica =
            hash::digests_from_bytes(replica).ok_or("the replica holds a non-canonical node")?;
        let challenges = seal_challenges(statement, count);
        let parents: Vec<(Vec<u64>, Vec<u64>)> = challenges
            .iter()
            .map(|&j| parents_of(j, statement.n, params))
            .collect();
        let mut kept = std::collections::BTreeMap::new();
        for (j, (same_layer, layer_below)) in challenges.iter().zip(&parents) {
            for v in std::iter::once(j).chain(same_layer).chain(layer_below) {
                kept.entry(*v).or_insert_with(Vec::new);
            }
        }
        Ok(Self {
            replica,
            challenges,
            parents,
            kept,
        })
    }

    /// The proof, from every node's column digest and the last layer.
    fn finish(
        self,
        statement: &SealStatement,
        columns: Vec<Digest>,
        last: Vec<Digest>,
    ) -> Result<SealProof, String> {
        let Self {
            replica,
            challenges,
            parents,
            kept,
        } = self;
        let column_tree = MerkleTree::from_digests(columns);
        if column_tree.commitment(Tree::Column) != statement.registered.comm_c {
            return Err("the registered column commitment is not this replica's labelling".into());
        }
        let column = |v: u64| ColumnOpening {
            labels: kept[&v].clone(),
            path: column_tree.path(v),
        };
        let column_openings: Vec<(ColumnOpening, Vec<ColumnOpening>)> = challenges
            .iter()
            .zip(&parents)
            .map(|(&j, (same_layer, layer_below))| {
                (
                    column(j),
                    same_layer
                        .iter()
                        .chain(layer_below)
                        .map(|&p| column(p))
                        .collect(),
                )
            })
            .collect();
        drop(column_tree);

        let data: Vec<Digest> = replica
            .par_iter()
            .zip(last.par_iter())
            .map(|(r, l)| hash::sub(r, l))
            .collect();
        drop(last);
        let data_tree = MerkleTree::from_digests(data);
        if data_tree.commitment(Tree::Data) != statement.registered.comm_d {
            return Err("the registered data commitment is not this replica's data".into());
        }
        let data_openings: Vec<(Node, Vec<Node>)> = challenges
            .iter()
            .map(|&j| {
                (
                    hash::to_bytes(&data_tree.levels[0][j as usize]),
                    data_tree.path(j),
                )
            })
            .collect();
        drop(data_tree);

        let replica_tree = MerkleTree::from_digests(replica);
        if replica_tree.commitment(Tree::Replica) != statement.registered.comm_r {
            return Err("the registered replica commitment is not this replica".into());
        }
        let openings = challenges
            .iter()
            .zip(data_openings)
            .zip(column_openings)
            .map(|((&j, (data, data_path)), (column, parents))| SealOpening {
                data,
                data_path,
                replica: hash::to_bytes(&replica_tree.levels[0][j as usize]),
                replica_path: replica_tree.path(j),
                column,
                parents,
            })
            .collect();
        Ok(SealProof { openings })
    }
}

/// Check a seal proof: every challenged node's data, replica and column open
/// against the registered commitments, its labels recompute from its parents'
/// with the member's own key, and its replica node is its data node plus its
/// final label.
pub fn verify_seal(
    statement: &SealStatement,
    proof: &SealProof,
    params: &SdrParams,
    count: usize,
) -> Result<(), String> {
    let n = statement.n;
    if n < MIN_NODES as u64 || n >= MAX_NODES {
        return Err(format!("a registration of {n} nodes"));
    }
    if proof.openings.len() != count {
        return Err(format!(
            "{} seal openings, {count} required",
            proof.openings.len()
        ));
    }
    let key = hash::key_digest(&sdr::replica_key(
        statement.member,
        statement.leaf_id,
        statement.epoch,
    ));
    let registered = &statement.registered;
    let layers = params.layers;
    let column_ok = |v: u64, opening: &ColumnOpening| {
        opening.labels.len() == layers
            && column_digest(&opening.labels).is_some_and(|digest| {
                verify_path(
                    Tree::Column,
                    n,
                    &registered.comm_c,
                    v,
                    &digest,
                    &opening.path,
                )
            })
    };
    for (c, (j, opening)) in seal_challenges(statement, count)
        .into_iter()
        .zip(&proof.openings)
        .enumerate()
    {
        if !verify_path(
            Tree::Data,
            n,
            &registered.comm_d,
            j,
            &opening.data,
            &opening.data_path,
        ) {
            return Err(format!(
                "challenge {c}: data node {j} does not open the registered data"
            ));
        }
        if !verify_path(
            Tree::Replica,
            n,
            &registered.comm_r,
            j,
            &opening.replica,
            &opening.replica_path,
        ) {
            return Err(format!(
                "challenge {c}: replica node {j} does not open the registered replica"
            ));
        }
        if !column_ok(j, &opening.column) {
            return Err(format!(
                "challenge {c}: column {j} does not open the registered columns"
            ));
        }
        let (same_layer, layer_below) = parents_of(j, n, params);
        if opening.parents.len() != same_layer.len() + layer_below.len() {
            return Err(format!(
                "challenge {c}: {} parent columns, {} required",
                opening.parents.len(),
                same_layer.len() + layer_below.len()
            ));
        }
        for (p, parent) in same_layer.iter().chain(&layer_below).zip(&opening.parents) {
            if !column_ok(*p, parent) {
                return Err(format!(
                    "challenge {c}: parent column {p} does not open the registered columns"
                ));
            }
        }
        // Every label below is canonical: its column digest parsed above.
        let digest = |node: &Node| hash::from_bytes(node).expect("checked canonical");
        let (same_columns, below_columns) = opening.parents.split_at(same_layer.len());
        for layer in 0..layers {
            let expected = label(
                &key,
                layer,
                j,
                &mut same_columns.iter().map(|p| digest(&p.labels[layer])),
                &mut below_columns
                    .iter()
                    .map(|p| digest(&p.labels[layer.saturating_sub(1)])),
                params,
            );
            if hash::to_bytes(&expected) != opening.column.labels[layer] {
                return Err(format!(
                    "challenge {c}: node {j}'s layer-{layer} label is not this member's"
                ));
            }
        }
        let last = digest(&opening.column.labels[layers - 1]);
        let (Some(data), Some(replica)) = (
            hash::from_bytes(&opening.data),
            hash::from_bytes(&opening.replica),
        ) else {
            return Err(format!("challenge {c}: a non-canonical node"));
        };
        if hash::add(&data, &last) != replica {
            return Err(format!(
                "challenge {c}: replica node {j} is not its data under this member's labels"
            ));
        }
    }
    Ok(())
}

fn put_nodes(out: &mut Vec<u8>, nodes: &[Node]) {
    for node in nodes {
        out.extend_from_slice(node);
    }
}

/// `count` canonical nodes off the front of `bytes`.
fn take_nodes(bytes: &mut &[u8], count: usize) -> Option<Vec<Node>> {
    let raw = bytes.get(..count * NODE_BYTES)?;
    hash::digests_from_bytes(raw)?;
    *bytes = &bytes[count * NODE_BYTES..];
    Some(
        raw.chunks(NODE_BYTES)
            .map(|c| c.try_into().expect("32 bytes"))
            .collect(),
    )
}

fn take_node(bytes: &mut &[u8]) -> Option<Node> {
    take_nodes(bytes, 1).map(|mut nodes| nodes.remove(0))
}

impl SealProof {
    /// `u32` opening count, then per opening: data node and path, replica node
    /// and path, the column's labels and path, a `u16` parent count and each
    /// parent's labels and path. Paths and label counts are implied by the
    /// registration's node count and the labelling's layers.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.openings.len() as u32).to_be_bytes());
        for opening in &self.openings {
            out.extend_from_slice(&opening.data);
            put_nodes(&mut out, &opening.data_path);
            out.extend_from_slice(&opening.replica);
            put_nodes(&mut out, &opening.replica_path);
            put_nodes(&mut out, &opening.column.labels);
            put_nodes(&mut out, &opening.column.path);
            out.extend_from_slice(&(opening.parents.len() as u16).to_be_bytes());
            for parent in &opening.parents {
                put_nodes(&mut out, &parent.labels);
                put_nodes(&mut out, &parent.path);
            }
        }
        out
    }

    /// Strict inverse of [`Self::to_bytes`] for a registration of `n` nodes:
    /// at most `max_openings` openings and 64 parents each, every node
    /// canonical, every byte used.
    pub fn from_bytes(
        mut bytes: &[u8],
        n: u64,
        layers: usize,
        max_openings: usize,
    ) -> Option<Self> {
        let depth = tree_depth(n);
        let count = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        bytes = &bytes[4..];
        if count > max_openings {
            return None;
        }
        let mut openings = Vec::with_capacity(count);
        for _ in 0..count {
            let data = take_node(&mut bytes)?;
            let data_path = take_nodes(&mut bytes, depth)?;
            let replica = take_node(&mut bytes)?;
            let replica_path = take_nodes(&mut bytes, depth)?;
            let column = ColumnOpening {
                labels: take_nodes(&mut bytes, layers)?,
                path: take_nodes(&mut bytes, depth)?,
            };
            let parent_count = u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?) as usize;
            bytes = &bytes[2..];
            if parent_count > 64 {
                return None;
            }
            let mut parents = Vec::with_capacity(parent_count);
            for _ in 0..parent_count {
                parents.push(ColumnOpening {
                    labels: take_nodes(&mut bytes, layers)?,
                    path: take_nodes(&mut bytes, depth)?,
                });
            }
            openings.push(SealOpening {
                data,
                data_path,
                replica,
                replica_path,
                column,
                parents,
            });
        }
        bytes.is_empty().then_some(Self { openings })
    }
}

// ── Possession openings ──────────────────────────────────────────────────────

/// The replica node a member opens for `query` in the frame whose beacon is
/// `rho_n`: unpredictable until that GLOBAL frame exists, and distinct per
/// leaf, epoch and member.
pub fn opening_index(
    rho_n: &[u8],
    leaf_id: &[u8],
    epoch: u64,
    member: &[u8],
    query: u32,
    n: u64,
) -> u64 {
    let mut h = Sha3_256::new();
    h.update(DST_OPEN);
    put_bytes(&mut h, rho_n);
    put_bytes(&mut h, leaf_id);
    h.update(epoch.to_be_bytes());
    put_bytes(&mut h, member);
    h.update(query.to_be_bytes());
    h.update(n.to_be_bytes());
    let digest = h.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) % n.max(1)
}

/// One member's opening for `query`, from its stored replica and cap. The
/// opening's `leaf_root` is the registration root and `num_blocks` the node
/// count; the KZG fields stay empty.
#[allow(clippy::too_many_arguments)]
pub fn build_opening(
    replica: &[u8],
    cap: &MerkleCap,
    registration_root: &[u8],
    leaf_id: &[u8],
    epoch: u64,
    member: &[u8],
    query: u32,
    rho_n: &[u8],
) -> Option<crate::porep::StorageOpening> {
    let index = opening_index(rho_n, leaf_id, epoch, member, query, cap.n);
    let path = cap.path(replica, index)?;
    let at = index as usize * NODE_BYTES;
    Some(crate::porep::StorageOpening {
        shard_id: leaf_id.to_vec(),
        epoch,
        member_id: member.to_vec(),
        query,
        leaf_root: registration_root.to_vec(),
        num_blocks: cap.n,
        path_commits: path.iter().map(|node| node.to_vec()).collect(),
        path_proofs: Vec::new(),
        commitment: Vec::new(),
        value: replica[at..at + NODE_BYTES].to_vec(),
        proof: Vec::new(),
    })
}

/// Whether `opening` opens the beacon-chosen node of the replica its
/// registration root commits to.
pub fn verify_opening(opening: &crate::porep::StorageOpening, rho_n: &[u8]) -> bool {
    let Some(registered) = parse_registration_root(&opening.leaf_root) else {
        return false;
    };
    let n = opening.num_blocks;
    if n == 0
        || !opening.commitment.is_empty()
        || !opening.proof.is_empty()
        || !opening.path_proofs.is_empty()
    {
        return false;
    }
    let Ok(value) = <Node>::try_from(opening.value.as_slice()) else {
        return false;
    };
    let Some(path) = opening
        .path_commits
        .iter()
        .map(|node| <Node>::try_from(node.as_slice()).ok())
        .collect::<Option<Vec<Node>>>()
    else {
        return false;
    };
    let index = opening_index(
        rho_n,
        &opening.shard_id,
        opening.epoch,
        &opening.member_id,
        opening.query,
        n,
    );
    verify_path(Tree::Replica, n, &registered.comm_r, index, &value, &path)
}

/// What a frame commits to for its possession openings, which an epoch's
/// STARK later proves: the sponge over `[frame_number, count, 0, …]` and the
/// opened replica nodes in the frame's canonical order. `None` for a
/// non-canonical node.
pub fn openings_root(frame_number: u64, values: &[Node]) -> Option<Node> {
    let mut header = hash::ZERO;
    header[0] = hash::felt(frame_number as u32);
    header[1] = hash::felt(values.len() as u32);
    let mut absorber =
        hash::Absorber::new(Domain::Openings, hash::DIGEST_ELEMS * (1 + values.len()));
    absorber.absorb_digest(&header);
    for value in values {
        absorber.absorb_digest(&hash::from_bytes(value)?);
    }
    Some(hash::to_bytes(&absorber.finish()))
}

/// The committee-signed `storage_attestation_root`: a hash over the frame, its
/// beacon and bitmask and every opening in canonical order (shard, epoch,
/// member, query), so the signature binds exactly this opening set. Empty for
/// no openings.
pub fn attestation_root(
    openings: &[crate::porep::StorageOpening],
    frame_number: u64,
    rho_n: &[u8],
    bitmask: &[u8],
) -> Vec<u8> {
    if openings.is_empty() {
        return Vec::new();
    }
    let mut ordered: Vec<&crate::porep::StorageOpening> = openings.iter().collect();
    ordered.sort_by(|a, b| {
        a.shard_id
            .cmp(&b.shard_id)
            .then(a.epoch.cmp(&b.epoch))
            .then(a.member_id.cmp(&b.member_id))
            .then(a.query.cmp(&b.query))
    });
    let mut h = Sha3_256::new();
    h.update(DST_ATTESTATION);
    h.update(frame_number.to_be_bytes());
    put_bytes(&mut h, rho_n);
    put_bytes(&mut h, bitmask);
    h.update((ordered.len() as u32).to_be_bytes());
    for o in ordered {
        put_bytes(&mut h, &o.shard_id);
        h.update(o.epoch.to_be_bytes());
        put_bytes(&mut h, &o.member_id);
        h.update(o.query.to_be_bytes());
        put_bytes(&mut h, &o.leaf_root);
        h.update(o.num_blocks.to_be_bytes());
        put_bytes(&mut h, &o.value);
        h.update((o.path_commits.len() as u32).to_be_bytes());
        for node in &o.path_commits {
            put_bytes(&mut h, node);
        }
    }
    h.finalize().to_vec()
}

#[cfg(test)]
#[path = "storage_proof_tests.rs"]
mod tests;
