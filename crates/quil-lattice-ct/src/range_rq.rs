//! Ring-form range proof — the **value-binding component** at production
//! parameters. `⚠` This is NOT a complete range proof on its own (see below).
//!
//! # What ports mechanically, and what does not
//!
//! A range proof `v ∈ [0, 2^N)` has two halves:
//!
//! 1. **Value binding** — `v = ⟨(1,2,…,2^{N-1}), m⟩` for committed limbs/bits
//! `m`, done *without* the randomness blow-up naive scaling causes, via the
//! folded combined-matrix short opening. This is a direct short-opening
//! statement, so it re-instantiates over [`crate::sigma_rq`] cleanly — it is
//! what this module implements.
//! 2. **Bit validity** — each committed `mᵢ ∈ {0,1}`. In the reference this was
//! a CDS OR-proof; that does **not** port (the structured ring challenge has
//! no additive split — see the crate notes). The ring-form version needs a
//! **product/quadratic argument** `b(b−1)=0`, which is genuine protocol
//! work, left as an explicit gap here.
//!
//! **Without (2), this component provides NO range guarantee** — it binds `v`
//! to committed values that could be anything. It is included because the
//! binding *is* correct and mechanical, isolating the exact remaining protocol.
//!
//! # The target identity for (2) (worked out, for whoever implements it)
//!
//! For a committed constant-poly bit `b` (so `b∈{0,1}` ⟺ `b²=b` mod q), a
//! masked-evaluation Σ-protocol reveals `f = x·b + α` (mask `α`, challenge `x`)
//! and exploits
//! ```text
//! f·(f − x) = x²·(b² − b) + x·α·(2b − 1) + α² .
//! ```
//! When `b` is a bit the `x²` term vanishes, leaving a value **linear in `x`**;
//! a cheating non-bit `b` leaves a nonzero `x²` coefficient that fails for a
//! random `x`. Making this zero-knowledge (hide `α(2b−1)`, `α²`) and sound
//! (bind `f` to `C_b`, rejection-sample) is the BDLOP/MatRiCT product proof.

use crate::module::{PolyMatrix, PolyVec, RingCommitKey, RingCommitment};
use crate::params::{LWE_RANK_LAMBDA as LAMBDA, SIS_RANK_KAPPA as KAPPA};
use crate::rq::Poly;
use crate::sigma_rq::{prove_ring_opening, verify_ring_opening, RingOpeningProof, RingSigmaParams};

/// A range key: shared binding block `A1`, a scalar value row, and `N` bit
/// rows — mirroring the reference `RangeKey`, over `R_q`.
pub struct RingRangeKey {
    n_bits: usize,
    a1: PolyMatrix,        // κ × λ
    a2_val: Vec<Poly>,     // 1 × λ (value message row)
    a2_bits: Vec<Vec<Poly>>, // N × λ (bit message rows)
}

impl RingRangeKey {
    pub fn production(n_bits: usize, seed: u64) -> Self {
        let a1 = PolyMatrix::from_seed(KAPPA, LAMBDA, seed);
        let a2 = PolyMatrix::from_seed(1 + n_bits, LAMBDA, seed ^ 0xA2);
        let a2_val = a2.m[0].clone();
        let a2_bits = a2.m[1..].to_vec();
        RingRangeKey { n_bits, a1, a2_val, a2_bits }
    }
    pub fn n_bits(&self) -> usize {
        self.n_bits
    }
    /// Value commitment key `[A1; a2_val]` (ℓ=1) — commit amounts here.
    pub fn value_key(&self) -> RingCommitKey {
        RingCommitKey {
            a1: self.a1.clone(),
            a2: PolyMatrix { rows: 1, cols: LAMBDA, m: vec![self.a2_val.clone()] },
            ell: 1,
        }
    }
    /// Bit-vector key `[A1; A2_bits]` (ℓ=N).
    pub fn bit_key(&self) -> RingCommitKey {
        RingCommitKey {
            a1: self.a1.clone(),
            a2: PolyMatrix { rows: self.n_bits, cols: LAMBDA, m: self.a2_bits.clone() },
            ell: self.n_bits,
        }
    }
    /// Scalar key `[A1; A2_bits[i]]` (ℓ=1) for proving bit-coordinate `i`.
    pub fn bit_coord_key(&self, i: usize) -> RingCommitKey {
        RingCommitKey {
            a1: self.a1.clone(),
            a2: PolyMatrix { rows: 1, cols: LAMBDA, m: vec![self.a2_bits[i].clone()] },
            ell: 1,
        }
    }
    /// Gadget-folded value row `g·A2_bits = Σ 2^i · A2_bits[i]` (1 × λ).
    fn folded_row(&self) -> Vec<Poly> {
        (0..LAMBDA)
            .map(|j| {
                let mut acc = Poly::zero();
                for i in 0..self.n_bits {
                    acc = acc.add(&self.a2_bits[i][j].scalar_mul(1i64 << i));
                }
                acc
            })
            .collect()
    }
    /// Combined matrix `[A1 | −A1 ; a2_val | −(g·A2)]`, `(κ+1) × 2λ`.
    fn combined_matrix(&self) -> PolyMatrix {
        let mut m: Vec<Vec<Poly>> = Vec::with_capacity(KAPPA + 1);
        for row in &self.a1.m {
            let mut r = row.clone();
            r.extend(row.iter().map(|p| p.neg()));
            m.push(r);
        }
        let mut last = self.a2_val.clone();
        last.extend(self.folded_row().iter().map(|p| p.neg()));
        m.push(last);
        PolyMatrix { rows: KAPPA + 1, cols: 2 * LAMBDA, m }
    }
}

/// `⟨g, C_b.t2⟩` — fold the bit-commitment message part by the gadget.
fn fold_t2(t2: &PolyVec) -> Poly {
    let mut acc = Poly::zero();
    for (i, ti) in t2.0.iter().enumerate() {
        acc = acc.add(&ti.scalar_mul(1i64 << i));
    }
    acc
}

/// `D = C_v − fold_g(C_b)` stacked `(κ+1)`.
fn bind_target(c_v: &RingCommitment, c_b: &RingCommitment) -> PolyVec {
    let d_t1 = c_v.t1.sub(&c_b.t1);
    let d_t2 = PolyVec(vec![c_v.t2.0[0].sub(&fold_t2(&c_b.t2))]);
    d_t1.concat(&d_t2)
}

/// Prove the **value binding** `v = ⟨2ⁱ, bits⟩` linking `c_v` to a fresh
/// bit-vector commitment `c_b`. Returns `(c_b, proof)`. Callers MUST also prove
/// each coordinate of `c_b` is a bit (the product-proof gap) for a real range
/// guarantee.
pub fn prove_value_binding(
    key: &RingRangeKey,
    c_v: &RingCommitment,
    v: u64,
    r_v: &PolyVec,
    eta: i64,
    mask_bound: i64,
    seed: u64,
) -> Option<(RingCommitment, RingOpeningProof)> {
    use crate::arith::SplitMix64;
    let mut prg = SplitMix64::new(seed ^ 0xB175);
    let r_b = PolyVec::sample_short(LAMBDA, eta, &mut prg);
    // Bits as constant-poly messages.
    let bits: Vec<Poly> = (0..key.n_bits)
        .map(|i| {
            let mut p = Poly::zero();
            p.c[0] = ((v >> i) & 1) % Poly::Q;
            p
        })
        .collect();
    let c_b = key.bit_key().commit(&PolyVec(bits), &r_b);

    let s = r_v.concat(&r_b); // witness (r_v; r_b), both short
    let d = bind_target(c_v, &c_b);
    let p = RingSigmaParams { mask_bound, eta, tau: crate::params::CHALLENGE_WEIGHT_TAU };
    let proof = prove_ring_opening(&key.combined_matrix(), &d, &s, &p, b"", seed ^ 0x81)?;
    Some((c_b, proof))
}

/// Verify the value binding (NOT a range guarantee without the bit proofs).
pub fn verify_value_binding(
    key: &RingRangeKey,
    c_v: &RingCommitment,
    c_b: &RingCommitment,
    proof: &RingOpeningProof,
    eta: i64,
    mask_bound: i64,
) -> bool {
    let d = bind_target(c_v, c_b);
    let p = RingSigmaParams { mask_bound, eta, tau: crate::params::CHALLENGE_WEIGHT_TAU };
    verify_ring_opening(&key.combined_matrix(), &d, proof, &p, b"")
}

// ── Complete range proof: value binding + per-coordinate bit validity ──────

use crate::binary_rq::{prove_bit_rq, verify_bit_rq, BinRqParams, BinaryProofRq};

/// A complete ring-form range proof: the bit-vector commitment, one binary
/// proof per coordinate (bit validity), and the value-binding opening.
pub struct RangeProofRq {
    pub c_b: RingCommitment,
    pub bit_proofs: Vec<BinaryProofRq>,
    pub binding: RingOpeningProof,
}

/// The `(c_b.t1, c_b.t2[i])` coordinate view as a scalar commitment.
fn coord_view(c_b: &RingCommitment, i: usize) -> RingCommitment {
    RingCommitment { t1: c_b.t1.clone(), t2: PolyVec(vec![c_b.t2.0[i].clone()]) }
}

/// Prove `v ∈ [0, 2^N)` — the full range proof. Commits the bit-vector, proves
/// each coordinate is a bit, and binds `v = ⟨2ⁱ, bits⟩`.
pub fn prove_range_rq(
    key: &RingRangeKey,
    c_v: &RingCommitment,
    v: u64,
    r_v: &PolyVec,
    eta: i64,
    mask_bound: i64,
    seed: u64,
) -> Option<RangeProofRq> {
    if v >= (1u64 << key.n_bits) {
        return None;
    }
    use crate::arith::SplitMix64;
    let mut prg = SplitMix64::new(seed ^ 0xB175);
    let r_b = PolyVec::sample_short(LAMBDA, eta, &mut prg);
    let bits_u: Vec<u64> = (0..key.n_bits).map(|i| (v >> i) & 1).collect();
    let bit_polys: Vec<Poly> = bits_u
        .iter()
        .map(|&bi| {
            let mut p = Poly::zero();
            p.c[0] = bi;
            p
        })
        .collect();
    let c_b = key.bit_key().commit(&PolyVec(bit_polys), &r_b);

    // (a) per-coordinate bit validity.
    let bin = BinRqParams { mask_bound, eta, tau: crate::params::CHALLENGE_WEIGHT_TAU };
    let mut bit_proofs = Vec::with_capacity(key.n_bits);
    for i in 0..key.n_bits {
        let ck = key.bit_coord_key(i);
        let cvi = coord_view(&c_b, i);
        let bp = prove_bit_rq(&ck, &cvi, bits_u[i] as u8, &r_b, &bin, b"", seed ^ (i as u64 + 1))?;
        bit_proofs.push(bp);
    }

    // (b) value binding: N·(r_v; r_b) = D, a commitment-to-zero opening.
    let s = r_v.concat(&r_b);
    let d = bind_target(c_v, &c_b);
    let p = RingSigmaParams { mask_bound, eta, tau: crate::params::CHALLENGE_WEIGHT_TAU };
    let binding = prove_ring_opening(&key.combined_matrix(), &d, &s, &p, b"", seed ^ 0x81)?;

    Some(RangeProofRq { c_b, bit_proofs, binding })
}

/// Verify a complete range proof.
pub fn verify_range_rq(
    key: &RingRangeKey,
    c_v: &RingCommitment,
    proof: &RangeProofRq,
    eta: i64,
    mask_bound: i64,
) -> bool {
    if proof.bit_proofs.len() != key.n_bits || proof.c_b.t2.0.len() != key.n_bits {
        return false;
    }
    let bin = BinRqParams { mask_bound, eta, tau: crate::params::CHALLENGE_WEIGHT_TAU };
    for i in 0..key.n_bits {
        let ck = key.bit_coord_key(i);
        let cvi = coord_view(&proof.c_b, i);
        if !verify_bit_rq(&ck, &cvi, &proof.bit_proofs[i], &bin, b"") {
            return false;
        }
    }
    let d = bind_target(c_v, &proof.c_b);
    let p = RingSigmaParams { mask_bound, eta, tau: crate::params::CHALLENGE_WEIGHT_TAU };
    verify_ring_opening(&key.combined_matrix(), &d, &proof.binding, &p, b"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::SplitMix64;
    use crate::module::ETA;

    const B: i64 = 1 << 17;

    fn commit_v(key: &RingRangeKey, v: u64, tag: u64) -> (RingCommitment, PolyVec) {
        let mut prg = SplitMix64::new(tag);
        let r = PolyVec::sample_short(LAMBDA, ETA, &mut prg);
        let mut m = Poly::zero();
        m.c[0] = v % Poly::Q;
        (key.value_key().commit(&PolyVec(vec![m]), &r), r)
    }

    #[test]
    fn value_binding_verifies_at_production_params() {
        // v = 12345, N=16. The binding proves v = ⟨2ⁱ, bits⟩ for the committed
        // bit-vector, at d=256, κ=λ=6 over R_q.
        let key = RingRangeKey::production(16, 5);
        let v = 12345u64;
        let (c_v, r_v) = commit_v(&key, v, 1);
        let (c_b, proof) = prove_value_binding(&key, &c_v, v, &r_v, ETA, B, 3).expect("binds");
        assert!(verify_value_binding(&key, &c_v, &c_b, &proof, ETA, B));
    }

    #[test]
    fn full_range_proof_verifies_in_range() {
        // v = 100 ∈ [0, 2^8). Full proof: bit validity + value binding, over
        // R_q at κ=λ=6. This is a REAL range guarantee (not just binding).
        let key = RingRangeKey::production(8, 7);
        let v = 100u64;
        let (c_v, r_v) = commit_v(&key, v, 1);
        let proof = prove_range_rq(&key, &c_v, v, &r_v, ETA, B, 3).expect("in range");
        assert!(verify_range_rq(&key, &c_v, &proof, ETA, B));
        assert_eq!(proof.bit_proofs.len(), 8);
    }

    #[test]
    fn full_range_proof_out_of_range_unprovable() {
        let key = RingRangeKey::production(8, 9);
        let v = 1u64 << 8; // == 256, just out of [0, 2^8)
        let (c_v, r_v) = commit_v(&key, v, 4);
        assert!(prove_range_rq(&key, &c_v, v, &r_v, ETA, B, 4).is_none());
    }

    #[test]
    fn binding_rejects_a_mismatched_value_commitment() {
        // The proof binds THIS c_v; a commitment to a different value must fail.
        let key = RingRangeKey::production(16, 9);
        let v = 1000u64;
        let (c_v, r_v) = commit_v(&key, v, 2);
        let (c_b, proof) = prove_value_binding(&key, &c_v, v, &r_v, ETA, B, 4).unwrap();
        let (c_other, _r) = commit_v(&key, 2000, 3);
        assert!(!verify_value_binding(&key, &c_other, &c_b, &proof, ETA, B));
    }
}
