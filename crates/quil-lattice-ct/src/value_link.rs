//! Value-linking proof (the coin/spend capstone — see `COIN_SPEND_PROTOCOL.md`).
//!
//! Binds the value hidden inside a coin's accumulator entry to a *revealed,
//! re-randomized* value commitment `C'`, so the balance can be checked without
//! revealing the coin. Proves knowledge of short `(v, r, r', x_C)` with:
//!
//! - **(a)** `C = Commit(v; r)` recomposes from its short gadget limbs `x_C`
//! (`G·x_C = C.stacked() = (A1·r, A2·r + v)`);
//! - **(b)** `cv = H_B(C) = B·x_C` — the SIS-compress that is the coin's
//! accumulator value-node (bound in the membership proof; here `cv` is public);
//! - **(c)** `C' = Commit(v; r')` commits the **same** `v`.
//!
//! All three are affine over the short witness, so the whole thing is one
//! `prove_ring_opening` over a public relation matrix `M` with `M·w = t`,
//! `w = (v ‖ r ‖ r' ‖ x_C)`, `t = (cv ‖ C'.t1 ‖ C'.t2 ‖ 0 ‖ 0)`.
//!
//! Soundness (special-soundness extractor): the extracted short `w̄` satisfies the
//! relaxed relations; `B` binding forces `x_C` unique given `cv`, `G` forces the
//! unique `C`, and `Commit` binding forces the unique `v` ⇒ the value balanced is
//! the coin's value (no mint). The `cv → membership` link (that this `cv` is the
//! one in the leaf) is added when this is folded into `CombinedOpening`.
//!
//! Amounts are per-limb (base `2^8`); this proves ONE limb — apply per limb.

use crate::accumulator::{gadget_decompose, ACC_GADGET_BASE_BITS, ACC_GADGET_LIMBS};
use crate::module::{PolyVec, RingCommitKey, RingCommitment};
use crate::params::{LWE_RANK_LAMBDA as LAMBDA, SIS_RANK_KAPPA as KAPPA};
use crate::rq::Poly;
use crate::sigma_rq::{prove_ring_opening, verify_ring_opening, RingOpeningProof, RingSigmaParams};

/// NUMS seed for the value-compress SIS matrix `B` (domain-separated from the
/// accumulator's node-hash `b_hash`/`d_leaf`).
const SEED_B_VAL: u64 = 0x5175_4c43_5643_4d50; // "QuLCVCMP"
/// NUMS seed for the value commitment key `(A1, A2)` used by the coin.
const SEED_VAL_KEY: u64 = 0x5175_4c43_5641_4c4b; // "QuLCVALK"

/// Number of base-`2^8` value limbs per coin (128-bit amounts: `128/8 = 16`).
/// **Fixed** (not amount-dependent) so a coin's proof size/shape leaks nothing
/// about its magnitude — every coin commits exactly `VALUE_LIMBS` limbs, high
/// limbs simply `0`. Matches [`crate::limb_balance`] at `n_limbs = 16`.
pub const VALUE_LIMBS: usize = 16;

/// Stacked commitment width (`t1: κ`, `t2: ℓ = VALUE_LIMBS`) and its gadget-limb
/// count. The value commitment is one ℓ=`VALUE_LIMBS` vector-message commitment
/// holding all limbs; `cv = H_B` compresses the whole stack.
pub(crate) const STACK: usize = KAPPA + VALUE_LIMBS;
pub(crate) const XC_LEN: usize = STACK * ACC_GADGET_LIMBS;

/// Σ-params: witness `∞`-norm is bounded by the base-`2^8` amount limb (`< 2^8`)
/// and the gadget limbs (`< 2^7`); mask sized so acceptance is reasonable over
/// the `≈ (1+2λ+XC_LEN)·256` witness coordinates while the extracted norm stays
/// `≪ q` (see the core-SVP note / `COIN_SPEND_PROTOCOL.md` §8.2).
const LINK_ETA: i64 = 1 << 8;
const LINK_MASK: i64 = 1 << 28;

fn link_params() -> RingSigmaParams {
    RingSigmaParams { mask_bound: LINK_MASK, eta: LINK_ETA, tau: crate::params::CHALLENGE_WEIGHT_TAU }
}

fn cpoly(v: i64) -> Poly {
    let q = Poly::Q as i64;
    let mut p = Poly::zero();
    p.c[0] = (((v % q) + q) % q) as u64;
    p
}
fn neg(p: &Poly) -> Poly {
    Poly::zero().sub(p)
}

/// Public parameters for the value-linking proof.
pub struct ValueLinkParams {
    /// Value commitment key `(A1: κ×λ, A2: 1×λ)`.
    pub vkey: RingCommitKey,
    /// SIS-compress matrix `B: κ × (κ+1)δ`.
    pub b_val: crate::module::PolyMatrix,
    /// Gadget recompose matrix `G: (κ+1) × (κ+1)δ`, `G[i][iδ+k] = 2^{7k}`.
    pub(crate) g: crate::module::PolyMatrix,
}

impl ValueLinkParams {
    /// With an explicit value-commitment key `(A1, A2)`. **The coin's value
    /// commitment `C`, the spend's `C'`, the range proofs, and the balance must
    /// all use this same key** — the caller passes the network value key.
    pub fn with_vkey(vkey: RingCommitKey) -> Self {
        let b_val = crate::module::PolyMatrix::from_seed(KAPPA, XC_LEN, SEED_B_VAL);
        // G: block-diagonal recompose, matching `gadget_recompose`.
        let base = ACC_GADGET_BASE_BITS;
        let mut m = vec![vec![Poly::zero(); XC_LEN]; STACK];
        for i in 0..STACK {
            for k in 0..ACC_GADGET_LIMBS {
                m[i][i * ACC_GADGET_LIMBS + k] = cpoly(1i64 << (k as u32 * base));
            }
        }
        let g = crate::module::PolyMatrix { rows: STACK, cols: XC_LEN, m };
        ValueLinkParams { vkey, b_val, g }
    }
    /// Standalone default key (crate tests / self-contained use).
    pub fn production() -> Self {
        Self::with_vkey(RingCommitKey::production(VALUE_LIMBS, SEED_VAL_KEY))
    }

    /// `cv = H_B(C) = B · g^{-1}(C.stacked())` — the coin's accumulator value-node.
    pub fn compress(&self, c: &RingCommitment) -> PolyVec {
        self.b_val.matvec(&gadget_decompose(&c.t1.concat(&c.t2)))
    }
}

// Column layout of the witness `w = (v[L] ‖ r ‖ r' ‖ x_C)` (`L = VALUE_LIMBS`).
const COL_V: usize = 0;
const COL_R: usize = VALUE_LIMBS;
const COL_RP: usize = VALUE_LIMBS + LAMBDA;
const COL_XC: usize = VALUE_LIMBS + 2 * LAMBDA;
const NCOLS: usize = VALUE_LIMBS + 2 * LAMBDA + XC_LEN;
// Row layout of `M`: [R1:κ | R2:κ | R3:L | R4:κ | R5:L].
const NROWS: usize = 3 * KAPPA + 2 * VALUE_LIMBS;

/// Build the public relation matrix `M` and target `t` for statement `(cv, C')`,
/// where `C = Commit(v; r)` / `C' = Commit(v; r')` are ℓ=`VALUE_LIMBS`
/// vector-message commitments (`v` = the amount's base-`2^8` limbs).
fn build_relation(p: &ValueLinkParams, cv: &PolyVec, c_prime: &RingCommitment) -> (crate::module::PolyMatrix, PolyVec) {
    let a1 = &p.vkey.a1; // κ×λ
    let a2 = &p.vkey.a2; // L×λ (one message row per limb)
    let b = &p.b_val; // κ×XC_LEN
    let g = &p.g; // STACK×XC_LEN (STACK = κ+L)
    let mut m = vec![vec![Poly::zero(); NCOLS]; NROWS];
    let r3 = 2 * KAPPA; // R3 offset
    let r4 = 2 * KAPPA + VALUE_LIMBS; // R4 offset
    let r5 = 3 * KAPPA + VALUE_LIMBS; // R5 offset

    // R1 (rows 0..κ): B·x_C = cv.
    for i in 0..KAPPA {
        for j in 0..XC_LEN {
            m[i][COL_XC + j] = b.m[i][j].clone();
        }
    }
    // R2 (rows κ..2κ): A1·r' = C'.t1.
    for i in 0..KAPPA {
        for j in 0..LAMBDA {
            m[KAPPA + i][COL_RP + j] = a1.m[i][j].clone();
        }
    }
    // R3 (rows 2κ..2κ+L): v_l + A2[l]·r' = C'.t2[l], one per limb.
    for l in 0..VALUE_LIMBS {
        m[r3 + l][COL_V + l] = cpoly(1);
        for j in 0..LAMBDA {
            m[r3 + l][COL_RP + j] = a2.m[l][j].clone();
        }
    }
    // R4 (rows 2κ+L..3κ+L): G_top·x_C − A1·r = 0 (recompose the κ randomness polys).
    for i in 0..KAPPA {
        for j in 0..LAMBDA {
            m[r4 + i][COL_R + j] = neg(&a1.m[i][j]);
        }
        for j in 0..XC_LEN {
            m[r4 + i][COL_XC + j] = g.m[i][j].clone();
        }
    }
    // R5 (rows 3κ+L..3κ+2L): G[κ+l]·x_C − A2[l]·r − v_l = 0, one per limb.
    for l in 0..VALUE_LIMBS {
        m[r5 + l][COL_V + l] = cpoly(-1);
        for j in 0..LAMBDA {
            m[r5 + l][COL_R + j] = neg(&a2.m[l][j]);
        }
        for j in 0..XC_LEN {
            m[r5 + l][COL_XC + j] = g.m[KAPPA + l][j].clone();
        }
    }

    let mm = crate::module::PolyMatrix { rows: NROWS, cols: NCOLS, m };

    // t = (cv ‖ C'.t1 ‖ C'.t2[0..L] ‖ 0 ‖ 0).
    let mut t = vec![Poly::zero(); NROWS];
    for i in 0..KAPPA {
        t[i] = cv.0[i].clone();
        t[KAPPA + i] = c_prime.t1.0[i].clone();
    }
    for l in 0..VALUE_LIMBS {
        t[r3 + l] = c_prime.t2.0[l].clone();
    }
    (mm, PolyVec(t))
}

/// Prove the value link for a coin `C = Commit(v; r)` and a fresh re-randomized
/// `C' = Commit(v; r')`. Returns `(cv, C', proof)` — the public statement plus
/// the proof. Caller supplies the coin's `(v, r)` and a fresh short `r'`.
pub fn prove_value_link(
    p: &ValueLinkParams,
    v: &PolyVec,       // ℓ=VALUE_LIMBS message (the amount's base-2^8 limbs)
    r: &PolyVec,       // coin randomness (λ, short)
    r_prime: &PolyVec, // fresh randomness (λ, short)
    seed: u64,
) -> Option<(PolyVec, RingCommitment, RingOpeningProof)> {
    let c = p.vkey.commit(v, r);
    let c_prime = p.vkey.commit(v, r_prime);
    let cv = p.compress(&c);
    let x_c = gadget_decompose(&c.t1.concat(&c.t2));

    // w = v[0..L] ‖ r ‖ r' ‖ x_C
    let mut w = Vec::with_capacity(NCOLS);
    w.extend(v.0.iter().cloned());
    w.extend(r.0.iter().cloned());
    w.extend(r_prime.0.iter().cloned());
    w.extend(x_c.0.iter().cloned());
    let w = PolyVec(w);

    let (m, t) = build_relation(p, &cv, &c_prime);
    let proof = prove_ring_opening(&m, &t, &w, &link_params(), b"quil-ct/value-link", seed)?;
    Some((cv, c_prime, proof))
}

/// Verify a value-linking proof for public `(cv, C')`.
pub fn verify_value_link(
    p: &ValueLinkParams,
    cv: &PolyVec,
    c_prime: &RingCommitment,
    proof: &RingOpeningProof,
) -> bool {
    let (m, t) = build_relation(p, cv, c_prime);
    verify_ring_opening(&m, &t, proof, &link_params(), b"quil-ct/value-link")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::SplitMix64;
    use crate::module::ETA;

    fn short(len: usize, seed: u64) -> PolyVec {
        let mut prg = SplitMix64::new(seed);
        PolyVec::sample_short(len, ETA, &mut prg)
    }
    fn amount(v: u64) -> PolyVec {
        // The amount's base-2^8 limbs as an ℓ=VALUE_LIMBS message.
        let limbs = crate::limb_balance::limbs_of(v as u128, VALUE_LIMBS);
        PolyVec(limbs.iter().map(|&l| cpoly(l as i64)).collect())
    }

    #[test]
    fn honest_value_link_verifies() {
        let p = ValueLinkParams::production();
        let (r, rp) = (short(LAMBDA, 1), short(LAMBDA, 2));
        let (cv, c_prime, proof) = prove_value_link(&p, &amount(100), &r, &rp, 7).unwrap();
        assert!(verify_value_link(&p, &cv, &c_prime, &proof));
    }

    #[test]
    fn wrong_value_in_c_prime_rejected() {
        // C' commits a DIFFERENT value than the coin ⇒ no witness satisfies the
        // relation (v is shared between (b/leaf) and (c/C')), so it cannot verify.
        let p = ValueLinkParams::production();
        let (r, rp) = (short(LAMBDA, 3), short(LAMBDA, 4));
        let (cv, _c_prime, proof) = prove_value_link(&p, &amount(100), &r, &rp, 8).unwrap();
        // Forge C' committing 101 instead of 100.
        let c_prime_bad = p.vkey.commit(&amount(101), &rp);
        assert!(!verify_value_link(&p, &cv, &c_prime_bad, &proof), "different C' value must reject");
    }

    #[test]
    fn tampered_cv_rejected() {
        let p = ValueLinkParams::production();
        let (r, rp) = (short(LAMBDA, 5), short(LAMBDA, 6));
        let (mut cv, c_prime, proof) = prove_value_link(&p, &amount(42), &r, &rp, 9).unwrap();
        cv.0[0].c[0] ^= 1; // corrupt the claimed accumulator value-node
        assert!(!verify_value_link(&p, &cv, &c_prime, &proof), "tampered cv must reject");
    }

    #[test]
    fn compress_matches_recompose() {
        // Sanity: G·x_C recomposes to C.stacked() (so R4/R5 are satisfiable).
        let p = ValueLinkParams::production();
        let c = p.vkey.commit(&amount(7), &short(LAMBDA, 11));
        let x = gadget_decompose(&c.t1.concat(&c.t2));
        assert_eq!(p.g.matvec(&x), c.t1.concat(&c.t2), "G is the gadget recompose of C.stacked()");
    }
}
