//! Range proof: a committed value `v` lies in `[0, 2^N)` — in zero-knowledge.
//! This is the confidential-amount guard (no negative amounts, no overflow of
//! the balance check), the lattice analogue of a Bulletproof.
//!
//! # Construction (assembles the atoms)
//!
//! Given a scalar value commitment `C_v = Commit([v]; r_v)`:
//! 1. **decompose** `v = Σ 2^i b_i` (`N` bits),
//! 2. **commit the bit-vector** `C_b = Commit(b; r_b)` (`ℓ = N`, short `r_b`),
//! under a key sharing the same binding block `A1`,
//! 3. **per-coordinate binary proof** — each coordinate of `C_b` is a bit
//! (loop [`crate::prove_bit`] over the message rows `A2_i`),
//! 4. **value binding** — `v = ⟨(1,2,…,2^{N-1}), b⟩` WITHOUT the randomness
//! blow-up that naive commitment-scaling would cause: fold `C_b` by the
//! gadget `g` so `(C_b.t1, g·C_b.t2)` is a commitment to `v` under
//! `[A1; g·A2]` with the SHORT `r_b`, and prove it commits the same `v` as
//! `C_v` via a short-opening over the combined block matrix
//! `Nmat = [A1 | −A1 ; a2 | −g·A2]` with short witness `(r_v; r_b)`.
//!
//! Every sub-proof is a [`crate::sigma`] short-opening (steps 3–4), so soundness
//! and ZK inherit from the audited-later engine.
//!
//! `N` defaults to 32 to stay far below `q = 2^61−1` (a 2^64 range needs a
//! larger `q`; amounts must not wrap mod `q`). Parameters are illustrative.

use crate::arith::SplitMix64;
#[cfg(test)]
use crate::arith::matvec;
use crate::binary::{prove_bit, verify_bit, BinaryProof};
use crate::commitment::{CommitKey, CommitParams, Commitment};
use crate::sigma::{prove_short_opening, verify_short_opening, ShortOpeningProof, SigmaParams};

/// A range key: one binding block `A1`, a scalar value row `a2_val`, and `N`
/// bit-vector message rows `A2_bits`, all deterministic from a seed and sharing
/// `A1` so the value commitment and the bit commitment can be folded together.
#[derive(Clone, Debug)]
pub struct RangeKey {
    params: CommitParams, // carries q, n, m, beta (ℓ is overridden per sub-key)
    n_bits: usize,
    a1: Vec<Vec<u128>>,       // n × m
    a2_val: Vec<u128>,        // 1 × m (the value message row)
    a2_bits: Vec<Vec<u128>>,  // N × m (bit-vector message rows)
}

impl RangeKey {
    /// Illustrative range key: `n_bits` bits, sharing the commitment's `n, m,
    /// q, β`. `n_bits ≤ 60` keeps `2^{n_bits} < q`.
    pub fn from_seed(n_bits: usize, seed: u64) -> Self {
        let params = CommitParams::illustrative_scalar();
        assert!(n_bits <= 60, "n_bits must keep 2^n_bits < q");
        let mut prg = SplitMix64::new(seed);
        let a1 = (0..params.n)
            .map(|_| (0..params.m).map(|_| prg.uniform_below(params.q)).collect())
            .collect();
        let a2_val = (0..params.m).map(|_| prg.uniform_below(params.q)).collect();
        let a2_bits = (0..n_bits)
            .map(|_| (0..params.m).map(|_| prg.uniform_below(params.q)).collect())
            .collect();
        RangeKey { params, n_bits, a1, a2_val, a2_bits }
    }

    pub fn n_bits(&self) -> usize {
        self.n_bits
    }

    /// The scalar value commitment key `[A1; a2_val]` (`ℓ = 1`). Callers commit
    /// amounts under this; the same key feeds the balance proof.
    pub fn value_key(&self) -> CommitKey {
        let mut p = self.params.clone();
        p.ell = 1;
        CommitKey::from_parts(p, self.a1.clone(), vec![self.a2_val.clone()])
    }

    /// Scalar key `[A1; A2_bits[i]]` for proving bit-coordinate `i`.
    fn bit_coord_key(&self, i: usize) -> CommitKey {
        let mut p = self.params.clone();
        p.ell = 1;
        CommitKey::from_parts(p, self.a1.clone(), vec![self.a2_bits[i].clone()])
    }

    /// Vector key `[A1; A2_bits]` (`ℓ = N`) for the bit-vector commitment.
    fn bit_vector_key(&self) -> CommitKey {
        let mut p = self.params.clone();
        p.ell = self.n_bits;
        CommitKey::from_parts(p, self.a1.clone(), self.a2_bits.clone())
    }

    fn q(&self) -> u128 {
        self.params.q
    }
    fn m(&self) -> usize {
        self.params.m
    }
    fn n(&self) -> usize {
        self.params.n
    }
    /// The gadget `g_i = 2^i mod q`.
    fn gadget(&self) -> Vec<u128> {
        (0..self.n_bits).map(|i| (1u128 << i) % self.q()).collect()
    }
    /// `g·A2_bits` — the folded value row (`1 × m`).
    fn folded_row(&self) -> Vec<u128> {
        let (q, g) = (self.q(), self.gadget());
        (0..self.m())
            .map(|j| {
                let mut acc = 0u128;
                for (i, gi) in g.iter().enumerate() {
                    acc = (acc + gi * self.a2_bits[i][j]) % q;
                }
                acc
            })
            .collect()
    }
    /// The combined block matrix `Nmat = [A1 | −A1 ; a2_val | −(g·A2)]`,
    /// `(n+1) × 2m`, over which `(r_v; r_b)` opens `C_v − fold(C_b)` to zero.
    fn combined_matrix(&self) -> Vec<Vec<u128>> {
        let q = self.q();
        let neg = |v: &[u128]| -> Vec<u128> { v.iter().map(|&x| (q - x % q) % q).collect() };
        let mut mat = Vec::with_capacity(self.n() + 1);
        for row in &self.a1 {
            let mut r = row.clone();
            r.extend(neg(row));
            mat.push(r);
        }
        let mut last = self.a2_val.clone();
        last.extend(neg(&self.folded_row()));
        mat.push(last);
        mat
    }
}

/// A range proof for a value commitment.
#[derive(Clone, Debug)]
pub struct RangeProof {
    /// The bit-vector commitment.
    pub c_b: Commitment,
    /// One binary proof per bit coordinate.
    pub bit_proofs: Vec<BinaryProof>,
    /// The value-binding short-opening over the combined matrix.
    pub bind: ShortOpeningProof,
}

/// The `(t1, t2[i])` view of the bit-vector commitment as a scalar commitment
/// to coordinate `i`.
fn coord_view(c_b: &Commitment, i: usize) -> Commitment {
    Commitment { t1: c_b.t1.clone(), t2: vec![c_b.t2[i]] }
}

/// `g·t2` — fold the bit-commitment's message part by the gadget.
fn fold_t2(g: &[u128], t2: &[u128], q: u128) -> u128 {
    let mut acc = 0u128;
    for (gi, ti) in g.iter().zip(t2) {
        acc = (acc + gi * ti) % q;
    }
    acc
}

/// `D = C_v − fold(C_b)` as a stacked `(n+1)` target for the combined opening.
fn bind_target(key: &RangeKey, c_v: &Commitment, c_b: &Commitment) -> Vec<u128> {
    let q = key.q();
    let mut d: Vec<u128> = (0..key.n()).map(|j| (c_v.t1[j] + q - c_b.t1[j]) % q).collect();
    let folded = fold_t2(&key.gadget(), &c_b.t2, q);
    d.push((c_v.t2[0] + q - folded) % q);
    d
}

/// Prove that `c_v = Commit([v]; r_v)` (under `key.value_key()`) has `v ∈
/// [0, 2^N)`. Returns `None` if `v` is out of range or no transcript is found.
pub fn prove_range(
    key: &RangeKey,
    c_v: &Commitment,
    v: u128,
    r_v: &[i128],
    params: &SigmaParams,
    seed: u64,
) -> Option<RangeProof> {
    if v >= (1u128 << key.n_bits) {
        return None;
    }
    // Fresh short (ternary) randomness for the bit-vector commitment.
    let mut prg = SplitMix64::new(seed ^ 0xB175);
    let r_b: Vec<i128> = (0..key.m()).map(|_| (prg.next_u64() % 3) as i128 - 1).collect();

    let bits: Vec<u128> = (0..key.n_bits).map(|i| (v >> i) & 1).collect();
    let bk = key.bit_vector_key();
    let c_b = bk.commit(&bits, &r_b);

    // (3) per-coordinate binary proofs.
    let mut bit_proofs = Vec::with_capacity(key.n_bits);
    for i in 0..key.n_bits {
        let ck = key.bit_coord_key(i);
        let cv = coord_view(&c_b, i);
        let p = prove_bit(&ck, &cv, bits[i] as u8, &r_b, params, seed ^ (i as u64 + 1))?;
        bit_proofs.push(p);
    }

    // (4) value binding: N·(r_v; r_b) = D, a commitment-to-zero opening.
    let nmat = key.combined_matrix();
    let mut s = r_v.to_vec();
    s.extend_from_slice(&r_b);
    let d = bind_target(key, c_v, &c_b);
    let bind = prove_short_opening(&nmat, &d, &s, params, seed ^ 0xB19D)?;

    Some(RangeProof { c_b, bit_proofs, bind })
}

/// Verify a [`RangeProof`] for value commitment `c_v`.
pub fn verify_range(
    key: &RangeKey,
    c_v: &Commitment,
    proof: &RangeProof,
    params: &SigmaParams,
) -> bool {
    if proof.bit_proofs.len() != key.n_bits || proof.c_b.t2.len() != key.n_bits {
        return false;
    }
    // (3) every coordinate of C_b is a bit.
    for i in 0..key.n_bits {
        let ck = key.bit_coord_key(i);
        let cv = coord_view(&proof.c_b, i);
        if !verify_bit(&ck, &cv, &proof.bit_proofs[i], params) {
            return false;
        }
    }
    // (4) v = ⟨g, bits⟩ binds C_v to C_b.
    let nmat = key.combined_matrix();
    let d = bind_target(key, c_v, &proof.c_b);
    verify_short_opening(&nmat, &d, &proof.bind, params)
}

/// Sanity self-check used by tests: `Nmat·(r_v;r_b)` really equals `D` when the
/// value binds (exposed so the algebraic identity is pinned, not just the ZK).
#[cfg(test)]
fn bind_identity_holds(key: &RangeKey, c_v: &Commitment, c_b: &Commitment, r_v: &[i128], r_b: &[i128]) -> bool {
    let mut s = r_v.to_vec();
    s.extend_from_slice(r_b);
    matvec(&key.combined_matrix(), &s, key.q()) == bind_target(key, c_v, c_b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::SplitMix64;
    use crate::commitment::Opening;

    fn params() -> SigmaParams {
        SigmaParams::illustrative((1u128 << 61) - 1)
    }
    fn ternary(m: usize, tag: u64) -> Vec<i128> {
        let mut prg = SplitMix64::new(tag);
        (0..m).map(|_| (prg.next_u64() % 3) as i128 - 1).collect()
    }

    #[test]
    fn in_range_value_verifies() {
        let key = RangeKey::from_seed(16, 0x9E17);
        let vk = key.value_key();
        let r_v = ternary(key.m(), 1);
        let v = 40_000u128; // < 2^16 = 65536
        let c_v = vk.commit(&[v], &r_v);
        let proof = prove_range(&key, &c_v, v, &r_v, &params(), 3).expect("in range");
        assert!(verify_range(&key, &c_v, &proof, &params()));
    }

    #[test]
    fn bind_identity_is_exact() {
        let key = RangeKey::from_seed(16, 5);
        let vk = key.value_key();
        let r_v = ternary(key.m(), 2);
        let v = 12_345u128;
        let c_v = vk.commit(&[v], &r_v);
        // Reconstruct the same r_b prove_range would use, and check N·s = D.
        let mut prg = SplitMix64::new(3u64 ^ 0xB175);
        let r_b: Vec<i128> = (0..key.m()).map(|_| (prg.next_u64() % 3) as i128 - 1).collect();
        let bits: Vec<u128> = (0..key.n_bits()).map(|i| (v >> i) & 1).collect();
        let c_b = key.bit_vector_key().commit(&bits, &r_b);
        assert!(bind_identity_holds(&key, &c_v, &c_b, &r_v, &r_b));
    }

    #[test]
    fn out_of_range_value_is_unprovable() {
        let key = RangeKey::from_seed(16, 9);
        let vk = key.value_key();
        let r_v = ternary(key.m(), 4);
        let v = 1u128 << 16; // == 2^16, just out of [0, 2^16)
        let c_v = vk.commit(&[v], &r_v);
        assert!(prove_range(&key, &c_v, v, &r_v, &params(), 4).is_none());
    }

    #[test]
    fn proof_does_not_verify_against_a_different_value() {
        let key = RangeKey::from_seed(16, 11);
        let vk = key.value_key();
        let r_v = ternary(key.m(), 6);
        let v = 1000u128;
        let c_v = vk.commit(&[v], &r_v);
        let proof = prove_range(&key, &c_v, v, &r_v, &params(), 6).unwrap();
        // A commitment to a different value must not accept this proof.
        let c_other = vk.commit(&[2000u128], &ternary(key.m(), 7));
        assert!(!verify_range(&key, &c_other, &proof, &params()));
        // Sanity that c_v really opens to v.
        assert!(vk.open_verify(&c_v, &Opening { msg: vec![v], r: r_v }, key.params.beta));
    }
}
