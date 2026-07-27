//! SIS (module-lattice) Merkle accumulator over the coin set — the non-ZK half
//! of the whole-set sender-anonymity design (see
//! `docs/accumulator_membership_spec.md`). Coins are inserted as leaves; the
//! committed root anchors the `O(log T)` zero-knowledge membership proof built
//! on top of this (in `membership.rs`).
//!
//! # Hash (estimator-pinned, §8a of the spec)
//!
//! Node values live in `R_q^κ` (`κ=6`). The compression is the Ajtai/LLNW
//! "decompose-then-hash":
//! ```text
//!   H_B(u_L, u_R) = B · [ g_b^{-1}(u_L) ; g_b^{-1}(u_R) ] (mod q)
//! ```
//! with gadget base `b = 2^14`, `δ = 2` limbs (top limb in `[0, 16385]` since
//! `q` is a hair above `2^28`), so the decomposition is short and the hash input
//! width is `2κδ = 24`. Collision ⇒ a short kernel vector of `B` ⇒ M-SIS, which
//! the estimator put at `~2^383` core-SVP — a deliberate, huge margin.

use crate::module::{PolyMatrix, PolyVec};
use crate::rq::Poly;

/// Gadget base `b = 2^7` (as a bit width). Chosen so the limbs are small enough
/// (`< 2^7`, top limb `≤ 128`) that a message-shortness proof (`crate::shortness`)
/// keeps the extracted collision norm inside the H_B M-SIS margin — the estimator
/// showed `b=2^14` is UNSOUND once shortness is enforced (`2^12`) while
/// `b=2^7` holds (`2^183`).
pub const ACC_GADGET_BASE_BITS: u32 = 7;
/// Number of gadget limbs `δ` (`δ·7 = 42 ≥ log2 q = 36`; limbs stay `< 2^7`).
pub const ACC_GADGET_LIMBS: usize = 6;
/// Node output rank `κ` (`= SIS_RANK_KAPPA`); a node is an element of `R_q^κ`.
pub const ACC_NODE_RANK: usize = crate::params::SIS_RANK_KAPPA;
/// `H_B` input width `2κδ`.
pub const ACC_HASH_WIDTH: usize = 2 * ACC_NODE_RANK * ACC_GADGET_LIMBS;

const SEED_B: u64 = 0x4143_435f_425f_4831; // "ACC_B_H1"
const SEED_D: u64 = 0x4143_435f_445f_4c31; // "ACC_D_L1"

/// A Merkle node — an element of `R_q^κ`.
pub type Node = PolyVec;

/// Public accumulator parameters: the hash key `B` and the leaf key `D`, both
/// `R_q^{κ × 2κδ}`, seed-expanded (à la Dilithium).
#[derive(Clone)]
pub struct AccumulatorParams {
    /// `B = [B_L | B_R]` — internal-node compression `H_B`.
    pub b_hash: PolyMatrix,
    /// `D = [D_L | D_R]` — leaf hash over `(one-time key, amount commitment)`.
    pub d_leaf: PolyMatrix,
    /// Fixed tree depth `L`.
    pub depth: usize,
}

impl AccumulatorParams {
    /// Production keys at the pinned dimensions, for a tree of the given depth.
    pub fn production(depth: usize) -> Self {
        AccumulatorParams {
            b_hash: PolyMatrix::from_seed(ACC_NODE_RANK, ACC_HASH_WIDTH, SEED_B),
            d_leaf: PolyMatrix::from_seed(ACC_NODE_RANK, ACC_HASH_WIDTH, SEED_D),
            depth,
        }
    }
}

// ── Gadget decomposition ────────────────────────────────────────────────────

/// Decompose one ring element into `δ` base-`2^b` limbs (per coefficient: `b`
/// bits per limb; the TOP limb is unmasked so it captures the remaining bits —
/// `δ·b = 28` covers `[0, 2^28)` and `q`'s tiny excess lands in the top limb,
/// `≤ ⌈q/2^{(δ-1)b}⌉`). Reconstruct via [`gadget_recompose`].
fn decompose_poly(u: &Poly) -> Vec<Poly> {
    let base = ACC_GADGET_BASE_BITS;
    let mask = (1u64 << base) - 1;
    (0..ACC_GADGET_LIMBS)
        .map(|k| {
            let shift = k as u32 * base;
            let top = k == ACC_GADGET_LIMBS - 1;
            Poly { c: u.c.iter().map(|&c| if top { c >> shift } else { (c >> shift) & mask }).collect() }
        })
        .collect()
}

/// `g_b^{-1}(node)`: a node in `R_q^κ` → its `2κ` short limbs in `R_q^{κδ}`
/// (interleaved: `limb0(u_0), limb1(u_0), limb0(u_1), …`).
pub fn gadget_decompose(node: &Node) -> PolyVec {
    let mut out = Vec::with_capacity(node.0.len() * ACC_GADGET_LIMBS);
    for p in &node.0 {
        out.extend(decompose_poly(p));
    }
    PolyVec(out)
}

/// `G_b · limbs`: recompose the interleaved limbs back to a node (inverse of
/// [`gadget_decompose`]). `u = Σ_k b^k · limb_k (mod q)`.
pub fn gadget_recompose(limbs: &PolyVec) -> Node {
    let q = Poly::Q;
    let node = limbs
        .0
        .chunks_exact(ACC_GADGET_LIMBS)
        .map(|chunk| {
            let c = (0..Poly::D)
                .map(|ci| {
                    let mut acc = 0u64;
                    for (k, limb) in chunk.iter().enumerate() {
                        acc = (acc + (limb.c[ci] << (k as u32 * ACC_GADGET_BASE_BITS))) % q;
                    }
                    acc
                })
                .collect();
            Poly { c }
        })
        .collect();
    PolyVec(node)
}

// ── Hashes ──────────────────────────────────────────────────────────────────

/// Internal-node compression `H_B(u_L, u_R) = B · [g^{-1}(u_L); g^{-1}(u_R)]`.
pub fn hash_node(p: &AccumulatorParams, left: &Node, right: &Node) -> Node {
    let x = gadget_decompose(left).concat(&gadget_decompose(right));
    p.b_hash.matvec(&x)
}

/// Leaf hash of a coin: `D · [g^{-1}(one_time_key); g^{-1}(commitment_binding)]`.
/// `one_time_key` is `P = A·sk' ∈ R_q^κ`; `commit_binding` is the amount
/// commitment's binding part `C_v.t1 ∈ R_q^κ`.
pub fn hash_leaf(p: &AccumulatorParams, one_time_key: &Node, commit_binding: &Node) -> Node {
    let x = gadget_decompose(one_time_key).concat(&gadget_decompose(commit_binding));
    p.d_leaf.matvec(&x)
}

/// The empty-leaf sentinel (the all-zero node).
pub fn empty_leaf() -> Node {
    PolyVec::zero(ACC_NODE_RANK)
}

// ── Incremental Merkle accumulator ──────────────────────────────────────────

/// A fixed-depth Merkle accumulator. Leaves are appended left-to-right; empty
/// subtrees fold to precomputed `zeros[level]`, so a depth-32 tree holding a few
/// coins costs `O(#coins + depth)`, not `O(2^depth)`.
///
/// This stores the inserted leaves (`O(T)`), which is what the coin-tracking
/// wallet / a materialize-time indexer needs to serve authentication paths. A
/// node that only needs the *root* can keep the `O(depth)` frontier instead
/// (noted in the spec; not required for correctness).
pub struct Accumulator {
    params: AccumulatorParams,
    leaves: Vec<Node>,
    zeros: Vec<Node>, // zeros[level], length depth+1
}

impl Accumulator {
    /// A new empty accumulator with the given parameters.
    pub fn new(params: AccumulatorParams) -> Self {
        let mut zeros = Vec::with_capacity(params.depth + 1);
        zeros.push(empty_leaf());
        for level in 1..=params.depth {
            let below = zeros[level - 1].clone();
            zeros.push(hash_node(&params, &below, &below));
        }
        Accumulator { params, leaves: Vec::new(), zeros }
    }

    /// Number of coins inserted.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The accumulator parameters (for `hash_leaf`/`hash_node` at this depth).
    pub fn params(&self) -> &AccumulatorParams {
        &self.params
    }
    /// The inserted leaves in order — the only non-derived state (for persistence).
    pub fn leaves(&self) -> &[Node] {
        &self.leaves
    }

    /// Append a coin leaf; returns its index.
    pub fn insert(&mut self, leaf: Node) -> usize {
        let idx = self.leaves.len();
        assert!(idx < (1usize << self.params.depth), "accumulator full");
        self.leaves.push(leaf);
        idx
    }

    /// The subtree root at `(level, index)`, folding empty regions to `zeros`.
    fn subtree(&self, level: usize, index: usize) -> Node {
        let span = 1usize << level;
        let start = index * span;
        if start >= self.leaves.len() {
            return self.zeros[level].clone();
        }
        if level == 0 {
            return self.leaves[start].clone();
        }
        let l = self.subtree(level - 1, 2 * index);
        let r = self.subtree(level - 1, 2 * index + 1);
        hash_node(&self.params, &l, &r)
    }

    /// The committed accumulator root (at the full configured depth).
    pub fn root(&self) -> Node {
        self.subtree(self.params.depth, 0)
    }

    /// The authentication path (sibling node per level, bottom→top) for a leaf
    /// at the full configured depth. Together with the leaf and its index it
    /// folds to the root ([`fold_auth_path`]) — the membership witness.
    pub fn auth_path(&self, leaf_index: usize) -> Vec<Node> {
        self.auth_path_at(self.params.depth, leaf_index)
    }

    // ── Log-growing (dynamic-depth) support ──────────────────────────────────
    //
    // The tree is provisioned to a maximum depth (`params.depth`) but only needs
    // to be as *deep* as the current leaf count requires. Proving/committing at
    // `current_depth()` instead of the full depth makes early proofs cheap and
    // grows the cost only as the real coin set grows. The depth is a public,
    // deterministic function of the leaf count (all nodes agree), and each root
    // is meaningful only together with the depth it was taken at.

    /// The shallowest depth that holds every current leaf: `ceil(log2(len))`,
    /// clamped to `[1, params.depth]`. Grows by one each time the leaf count
    /// crosses a power of two.
    pub fn current_depth(&self) -> usize {
        let n = self.leaves.len();
        let ceil_log2 =
            if n <= 1 { 0 } else { (usize::BITS - (n - 1).leading_zeros()) as usize };
        ceil_log2.max(1).min(self.params.depth)
    }

    /// The root of the tree truncated to `depth` levels (`depth ≤ params.depth`).
    /// Empty regions fold to `zeros`, so `root_at(current_depth())` is the
    /// log-growing root.
    pub fn root_at(&self, depth: usize) -> Node {
        debug_assert!(depth <= self.params.depth);
        self.subtree(depth, 0)
    }

    /// The authentication path for a leaf in the tree truncated to `depth`
    /// levels — the witness matching [`root_at`](Self::root_at).
    pub fn auth_path_at(&self, depth: usize, leaf_index: usize) -> Vec<Node> {
        debug_assert!(depth <= self.params.depth);
        let mut path = Vec::with_capacity(depth);
        let mut idx = leaf_index;
        for level in 0..depth {
            path.push(self.subtree(level, idx ^ 1));
            idx >>= 1;
        }
        path
    }
}

/// Fold a leaf up an authentication path to the root it certifies. `leaf_index`
/// supplies the left/right direction bit at each level.
pub fn fold_auth_path(
    params: &AccumulatorParams,
    leaf: &Node,
    leaf_index: usize,
    path: &[Node],
) -> Node {
    let mut node = leaf.clone();
    let mut idx = leaf_index;
    for sib in path {
        node = if idx & 1 == 0 {
            hash_node(params, &node, sib)
        } else {
            hash_node(params, sib, &node)
        };
        idx >>= 1;
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::SplitMix64;

    fn rand_node(tag: u64) -> Node {
        let mut prg = SplitMix64::new(tag);
        PolyVec(
            (0..ACC_NODE_RANK)
                .map(|_| Poly {
                    c: (0..Poly::D).map(|_| prg.uniform_below(Poly::Q as u128) as u64).collect(),
                })
                .collect(),
        )
    }

    #[test]
    fn gadget_round_trips() {
        let u = rand_node(1);
        let limbs = gadget_decompose(&u);
        assert_eq!(limbs.0.len(), ACC_NODE_RANK * ACC_GADGET_LIMBS);
        // Limbs are short: low limb < 2^14, high limb <= ceil(q/2^14) = 16385.
        let base = 1u64 << ACC_GADGET_BASE_BITS;
        for (i, p) in limbs.0.iter().enumerate() {
            let bound = if i % 2 == 0 { base } else { (Poly::Q >> ACC_GADGET_BASE_BITS) + 1 };
            assert!(p.c.iter().all(|&c| c < bound), "limb {i} within digit range");
        }
        assert_eq!(gadget_recompose(&limbs), u, "recompose ∘ decompose = id");
    }

    #[test]
    fn hash_is_deterministic_and_sensitive() {
        let p = AccumulatorParams::production(8);
        let a = rand_node(2);
        let b = rand_node(3);
        assert_eq!(hash_node(&p, &a, &b), hash_node(&p, &a, &b), "deterministic");
        assert_ne!(hash_node(&p, &a, &b), hash_node(&p, &b, &a), "order-sensitive");
        let c = rand_node(4);
        assert_ne!(hash_node(&p, &a, &b), hash_node(&p, &a, &c), "input-sensitive");
    }

    #[test]
    fn empty_root_is_the_zero_subtree() {
        let p = AccumulatorParams::production(6);
        let acc = Accumulator::new(p.clone());
        // Root of an empty depth-6 tree = zeros[6].
        let mut z = empty_leaf();
        for _ in 0..6 {
            z = hash_node(&p, &z, &z);
        }
        assert_eq!(acc.root(), z);
    }

    #[test]
    fn auth_paths_fold_to_root() {
        let p = AccumulatorParams::production(5);
        let mut acc = Accumulator::new(p.clone());
        // Insert several coins into a mostly-empty depth-5 tree (32 slots).
        let leaves: Vec<Node> = (0..5).map(|i| rand_node(100 + i)).collect();
        for l in &leaves {
            acc.insert(l.clone());
        }
        let root = acc.root();
        // Every inserted leaf's authentication path must fold to the same root.
        for (i, leaf) in leaves.iter().enumerate() {
            let path = acc.auth_path(i);
            assert_eq!(path.len(), 5);
            assert_eq!(fold_auth_path(&p, leaf, i, &path), root, "leaf {i} path folds to root");
        }
    }

    #[test]
    fn wrong_leaf_does_not_fold_to_root() {
        let p = AccumulatorParams::production(4);
        let mut acc = Accumulator::new(p.clone());
        for i in 0..3 {
            acc.insert(rand_node(200 + i));
        }
        let root = acc.root();
        let path = acc.auth_path(0);
        // A different leaf at index 0 must NOT reproduce the root.
        assert_ne!(fold_auth_path(&p, &rand_node(999), 0, &path), root);
    }

    #[test]
    fn current_depth_grows_with_leaf_count() {
        let mut acc = Accumulator::new(AccumulatorParams::production(16));
        assert_eq!(acc.current_depth(), 1, "empty/one → min depth 1");
        for (n, want) in [(1usize, 1), (2, 1), (3, 2), (4, 2), (5, 3), (8, 3), (9, 4)] {
            while acc.len() < n {
                acc.insert(rand_node(500 + acc.len() as u64));
            }
            assert_eq!(acc.current_depth(), want, "len {n} ⇒ depth {want}");
        }
    }

    #[test]
    fn root_at_matches_a_native_depth_tree() {
        // A max-depth-16 tree truncated to depth d must give the SAME root and
        // auth paths as a natively depth-d tree over the same leaves — so
        // log-growing is just "prove at current_depth".
        let leaves: Vec<Node> = (0..5).map(|i| rand_node(700 + i)).collect();
        let big = {
            let mut a = Accumulator::new(AccumulatorParams::production(16));
            for l in &leaves {
                a.insert(l.clone());
            }
            a
        };
        let d = big.current_depth();
        assert_eq!(d, 3, "5 leaves ⇒ depth 3");
        let small_p = AccumulatorParams::production(d);
        let small = {
            let mut a = Accumulator::new(small_p.clone());
            for l in &leaves {
                a.insert(l.clone());
            }
            a
        };
        assert_eq!(big.root_at(d), small.root(), "truncated root == native depth-d root");
        for i in 0..leaves.len() {
            assert_eq!(big.auth_path_at(d, i), small.auth_path(i), "auth path {i} matches");
            assert_eq!(
                fold_auth_path(&small_p, &leaves[i], i, &big.auth_path_at(d, i)),
                big.root_at(d),
                "leaf {i} folds to the log-growing root"
            );
        }
    }

    #[test]
    fn leaf_hash_binds_key_and_commitment() {
        let p = AccumulatorParams::production(8);
        let otk = rand_node(7);
        let cv = rand_node(8);
        let leaf = hash_leaf(&p, &otk, &cv);
        assert_eq!(leaf.0.len(), ACC_NODE_RANK);
        assert_ne!(leaf, hash_leaf(&p, &cv, &otk), "key/commitment positions bound");
        assert_ne!(leaf, hash_leaf(&p, &otk, &rand_node(9)), "commitment bound");
    }
}
