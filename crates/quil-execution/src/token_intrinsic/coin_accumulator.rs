//! Per-domain SIS coin accumulator — the "shadow tree" that shadows the coin
//! set so the post-quantum spend can prove *whole-set membership* (Lelantus/
//! Spark-style, no decoy ring).
//!
//! At materialize, every newly created coin's leaf
//! `H(one_time_key P, value_commitment cv)` is appended here; the accumulator
//! **root** is committed per frame and is what
//! [`super::lattice_ct::verify_input_membership`] checks a spend proof against.
//! The wallet/prover reads a coin's [`auth_path`](CoinAccumulator::auth_path) to
//! build its membership witness.
//!
//! # Persistence
//!
//! The accumulator's only non-derived state is the ordered list of inserted
//! leaves (the `zeros` frontier is a pure function of the params). So a domain's
//! accumulator serializes to a length-prefixed list of leaf nodes and reloads by
//! replaying the inserts — [`serialize`](CoinAccumulator::serialize) /
//! [`load`](CoinAccumulator::load). The caller stores that blob wherever the
//! domain's execution state lives and reloads it on shard take-over / restart.

use quil_lattice_ct::accumulator::{hash_leaf, Accumulator, AccumulatorParams, Node};
use quil_lattice_ct::wire;
use quil_types::error::{QuilError, Result};

use super::lattice_ct::ACC_DEPTH;

/// A per-domain coin accumulator at [`ACC_DEPTH`].
pub struct CoinAccumulator {
    acc: Accumulator,
    depth: usize,
}

impl Default for CoinAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl CoinAccumulator {
    /// A fresh, empty accumulator at the production depth.
    pub fn new() -> Self {
        Self::with_depth(ACC_DEPTH)
    }

    /// A fresh accumulator provisioned to a MAXIMUM depth (tests use a small
    /// max so the depth-scaled membership *prove* cost stays cheap).
    pub fn with_depth(max_depth: usize) -> Self {
        CoinAccumulator {
            acc: Accumulator::new(AccumulatorParams::production(max_depth)),
            depth: max_depth,
        }
    }

    /// The provisioned MAXIMUM depth (`ACC_DEPTH`) — the tree never grows past
    /// this. See [`current_depth`](Self::current_depth) for the live depth.
    pub fn max_depth(&self) -> usize {
        self.depth
    }

    /// The live (log-growing) depth: `ceil(log2(#coins))`, clamped to
    /// `[1, max_depth]`. This is what proofs are built/verified at and what is
    /// committed alongside the root — small sets prove cheaply; cost grows only
    /// with the real coin count.
    pub fn current_depth(&self) -> usize {
        self.acc.current_depth()
    }

    /// Number of coins inserted.
    pub fn len(&self) -> usize {
        self.acc.len()
    }
    pub fn is_empty(&self) -> bool {
        self.acc.is_empty()
    }

    /// Decode a wire node (`Node = PolyVec`).
    fn node(bytes: &[u8], what: &str) -> Result<Node> {
        wire::decode_polyvec(bytes)
            .map_err(|e| QuilError::InvalidArgument(format!("coin-acc: {what} decode: {e:?}")))
    }

    /// Append a coin. `one_time_key` is the lattice one-time key `P` and
    /// `value_commitment` the coin's value commitment `cv`, both wire-encoded
    /// nodes; the leaf is `H(P, cv)`. Returns the coin's leaf index.
    pub fn insert_coin(&mut self, one_time_key: &[u8], value_commitment: &[u8]) -> Result<usize> {
        let p = Self::node(one_time_key, "one_time_key")?;
        let cv = Self::node(value_commitment, "value_commitment")?;
        let leaf = hash_leaf(self.acc.params(), &p, &cv);
        Ok(self.acc.insert(leaf))
    }

    /// The committed accumulator root at the current (log-growing) depth,
    /// wire-encoded. Commit this per frame **together with** [`current_depth`]
    /// (a root is only meaningful at its depth); the pair feeds
    /// [`super::lattice_ct::verify_input_membership`].
    ///
    /// [`current_depth`]: Self::current_depth
    pub fn root_bytes(&self) -> Vec<u8> {
        wire::encode_polyvec(&self.acc.root_at(self.current_depth()))
    }

    /// `(current_depth, wire-encoded root)` — the pair to commit per frame.
    pub fn root_with_depth(&self) -> (usize, Vec<u8>) {
        (self.current_depth(), self.root_bytes())
    }

    /// The authentication path for a coin at the current depth (wire-encoded
    /// sibling nodes, bottom→top) — the wallet's membership witness. Its length
    /// equals [`current_depth`](Self::current_depth).
    pub fn auth_path(&self, leaf_index: usize) -> Vec<Vec<u8>> {
        self.acc
            .auth_path_at(self.current_depth(), leaf_index)
            .iter()
            .map(wire::encode_polyvec)
            .collect()
    }

    /// Serialize the accumulator (length-prefixed leaf list) for persistence.
    pub fn serialize(&self) -> Vec<u8> {
        let leaves = self.acc.leaves();
        let mut out = Vec::with_capacity(4 + leaves.len() * 64);
        out.extend_from_slice(&(leaves.len() as u32).to_le_bytes());
        for leaf in leaves {
            let b = wire::encode_polyvec(leaf);
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(&b);
        }
        out
    }

    /// Reload a domain's accumulator (at `depth`) from
    /// [`serialize`](Self::serialize) output.
    pub fn load(depth: usize, bytes: &[u8]) -> Result<Self> {
        let mut acc = Accumulator::new(AccumulatorParams::production(depth));
        let err = || QuilError::InvalidArgument("coin-acc: truncated accumulator blob".into());
        if bytes.len() < 4 {
            return Err(err());
        }
        let n = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let mut p = 4usize;
        for _ in 0..n {
            if p + 4 > bytes.len() {
                return Err(err());
            }
            let len = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
            p += 4;
            let end = p.checked_add(len).ok_or_else(err)?;
            if end > bytes.len() {
                return Err(err());
            }
            acc.insert(Self::node(&bytes[p..end], "leaf")?);
            p = end;
        }
        Ok(CoinAccumulator { acc, depth })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::arith::SplitMix64;
    use quil_lattice_ct::module::{PolyVec, ETA};
    use quil_lattice_ct::membership::MembershipParams;

    // A random wire-encoded node (κ ring elements).
    fn rand_node(seed: u64) -> Vec<u8> {
        let mut prg = SplitMix64::new(seed);
        wire::encode_polyvec(&PolyVec::sample_short(
            quil_lattice_ct::accumulator::ACC_NODE_RANK,
            ETA,
            &mut prg,
        ))
    }

    #[test]
    fn insert_root_changes_and_persists() {
        let mut a = CoinAccumulator::new();
        let r0 = a.root_bytes();
        let i0 = a.insert_coin(&rand_node(1), &rand_node(2)).unwrap();
        let i1 = a.insert_coin(&rand_node(3), &rand_node(4)).unwrap();
        assert_eq!((i0, i1), (0, 1));
        let r2 = a.root_bytes();
        assert_ne!(r0, r2, "root advances as coins are inserted");

        // Round-trip through persistence: same leaves ⇒ same root + auth paths.
        let blob = a.serialize();
        let b = CoinAccumulator::load(a.max_depth(), &blob).unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b.current_depth(), 1, "2 coins ⇒ log-growing depth 1");
        assert_eq!(b.root_bytes(), r2, "reloaded accumulator has the same root");
        assert_eq!(b.auth_path(0), a.auth_path(0), "auth paths survive reload");
    }

    #[test]
    fn auth_path_folds_to_root_and_proves_membership() {
        // A coin inserted with a known spend key must produce a membership proof
        // that verifies against the LOG-GROWING root at the CURRENT depth —
        // end-to-end with the shadow tree feeding lattice_ct's verify path.
        // The accumulator is provisioned to a large max_depth but proves at the
        // small current_depth the coin count implies.
        let mut prg = SplitMix64::new(42);
        let mut a = CoinAccumulator::with_depth(16); // provisioned deep, proves shallow
        // Fill to 5 coins ⇒ current_depth 3; our coin sits at index 3.
        a.insert_coin(&rand_node(7), &rand_node(8)).unwrap();
        a.insert_coin(&rand_node(9), &rand_node(10)).unwrap();
        a.insert_coin(&rand_node(11), &rand_node(12)).unwrap();
        // Spender's short secret + derived one-time key P and a value commitment.
        // A_otk is depth-independent, so params at any depth derive the same P.
        let mp0 = MembershipParams::production(1);
        let sk = PolyVec::sample_short(quil_lattice_ct::params::LWE_RANK_LAMBDA, ETA, &mut prg);
        let p_otk = mp0.a_otk.matvec(&sk);
        let cv = PolyVec::sample_short(quil_lattice_ct::accumulator::ACC_NODE_RANK, ETA, &mut prg);
        let idx = a
            .insert_coin(&wire::encode_polyvec(&p_otk), &wire::encode_polyvec(&cv))
            .unwrap();
        a.insert_coin(&rand_node(13), &rand_node(14)).unwrap(); // pad to 5 total

        // Prove at the CURRENT depth (all of mp/root/path agree on it).
        let d = a.current_depth();
        assert_eq!(d, 3, "5 coins ⇒ current_depth 3");
        let mp = MembershipParams::production(d);
        let root = wire::decode_polyvec(&a.root_bytes()).unwrap();
        let path: Vec<Node> =
            a.auth_path(idx).iter().map(|b| wire::decode_polyvec(b).unwrap()).collect();
        assert_eq!(path.len(), d, "auth path length == current depth");
        let mu = b"spend";
        let proof =
            quil_lattice_ct::membership::prove_membership(&mp, &root, &sk, &cv, idx, &path, mu, 5)
                .expect("honest coin proves membership");
        assert_eq!(
            quil_lattice_ct::membership::verify_membership(&mp, &root, &proof, mu),
            Some(mp.bk.matvec(&sk)),
            "membership verifies against the shadow-tree root + yields the key image"
        );
    }
}
