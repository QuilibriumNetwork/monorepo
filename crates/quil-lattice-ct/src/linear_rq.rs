//! Ring-form linear-relation / **balance** proof at production parameters —
//! the module-layer instantiation of [`crate::linear`].
//!
//! Proves `Σ α_i·v_i = τ` for ring commitments `C_i` with small public
//! coefficients `α_i`, in zero-knowledge. With `α = +1` inputs / `−1` outputs,
//! `τ = fee`, this is the balance check (no value creation), now over `R_q` at
//! `d=256, κ=λ=6`.
//!
//! Construction (unchanged in spirit): `D = Σ α_i·C_i − Commit(τ; 0)` is a
//! commitment to `Σ α_i·v_i − τ` with randomness `ρ = Σ α_i·r_i`; when the
//! relation holds the message is zero, so `D = M·ρ` and the proof is a
//! [`crate::sigma_rq`] short opening. `ρ` stays short for small `α`
//! (`‖ρ‖∞ ≤ Σ|α_i|·η`), which sets the protocol's witness-norm bound.

use crate::module::{PolyVec, RingCommitKey, RingCommitment};
use crate::params::CHALLENGE_WEIGHT_TAU;
use crate::sigma_rq::{prove_ring_opening, verify_ring_opening, RingOpeningProof, RingSigmaParams};

fn rho_norm_bound(coeffs: &[i64], base_eta: i64) -> i64 {
    coeffs.iter().map(|a| a.abs()).sum::<i64>() * base_eta
}

/// Ring-Σ params for the balance opening: witness `ρ` has norm `≤ Σ|α_i|·η`.
fn sigma_params(coeffs: &[i64], base_eta: i64, mask_bound: i64) -> RingSigmaParams {
    RingSigmaParams { mask_bound, eta: rho_norm_bound(coeffs, base_eta), tau: CHALLENGE_WEIGHT_TAU }
}

/// `D = Σ α_i·C_i − Commit(τ; 0)`, stacked `(κ+ℓ)` vector.
fn combined_target(
    key: &RingCommitKey,
    commitments: &[RingCommitment],
    coeffs: &[i64],
    target: &PolyVec,
) -> PolyVec {
    let mut t1 = PolyVec::zero(key.a1.rows);
    let mut t2 = PolyVec::zero(key.ell);
    for (c, &a) in commitments.iter().zip(coeffs) {
        t1 = t1.add(&c.t1.scalar_mul(a));
        t2 = t2.add(&c.t2.scalar_mul(a));
    }
    t2 = t2.sub(target); // − Commit(τ;0) (its t1 is zero)
    t1.concat(&t2)
}

/// Prove `Σ α_i·v_i = τ`. `rand[i]` are the commitments' randomness vectors,
/// `base_eta` their per-coefficient norm (`η`), `mask_bound` the ring-Σ `B`.
pub fn prove_linear_rq(
    key: &RingCommitKey,
    commitments: &[RingCommitment],
    coeffs: &[i64],
    target: &PolyVec,
    rand: &[PolyVec],
    base_eta: i64,
    mask_bound: i64,
    seed: u64,
) -> Option<RingOpeningProof> {
    let mut rho = PolyVec::zero(key.a1.cols); // λ
    for (r, &a) in rand.iter().zip(coeffs) {
        rho = rho.add(&r.scalar_mul(a));
    }
    let p = sigma_params(coeffs, base_eta, mask_bound);
    prove_ring_opening(&key.stacked_matrix(), &combined_target(key, commitments, coeffs, target), &rho, &p, b"", seed)
}

/// Verify a ring-form balance proof.
pub fn verify_linear_rq(
    key: &RingCommitKey,
    commitments: &[RingCommitment],
    coeffs: &[i64],
    target: &PolyVec,
    proof: &RingOpeningProof,
    base_eta: i64,
    mask_bound: i64,
) -> bool {
    let p = sigma_params(coeffs, base_eta, mask_bound);
    verify_ring_opening(&key.stacked_matrix(), &combined_target(key, commitments, coeffs, target), proof, &p, b"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::SplitMix64;
    use crate::module::ETA;
    use crate::rq::Poly;

    const B: i64 = 1 << 17;

    /// A commitment to an integer amount, encoded as a constant polynomial.
    fn commit_amount(key: &RingCommitKey, v: u64, tag: u64) -> (RingCommitment, PolyVec) {
        let mut prg = SplitMix64::new(tag);
        let r = PolyVec::sample_short(key.a1.cols, ETA, &mut prg);
        let mut m = Poly::zero();
        m.c[0] = v % Poly::Q;
        let msg = PolyVec(vec![m]);
        (key.commit(&msg, &r), r)
    }

    fn const_target(v: u64) -> PolyVec {
        let mut m = Poly::zero();
        m.c[0] = v % Poly::Q;
        PolyVec(vec![m])
    }

    #[test]
    fn balance_holds_at_production_params() {
        // inputs {30,12} outputs {35,5} fee 2 → 42 = 40 + 2, over R_q, κ=λ=6.
        let key = RingCommitKey::production(1, 0xBA1A);
        let (c1, r1) = commit_amount(&key, 30, 1);
        let (c2, r2) = commit_amount(&key, 12, 2);
        let (o1, s1) = commit_amount(&key, 35, 3);
        let (o2, s2) = commit_amount(&key, 5, 4);
        let commits = vec![c1, c2, o1, o2];
        let coeffs = vec![1i64, 1, -1, -1];
        let rand = vec![r1, r2, s1, s2];
        let proof =
            prove_linear_rq(&key, &commits, &coeffs, &const_target(2), &rand, ETA, B, 7).expect("balances");
        assert!(verify_linear_rq(&key, &commits, &coeffs, &const_target(2), &proof, ETA, B));
    }

    #[test]
    fn unbalanced_is_rejected() {
        // 30 in, 35 out, fee 2 → 30 ≠ 37: value would be created.
        let key = RingCommitKey::production(1, 0xBAD);
        let (ci, ri) = commit_amount(&key, 30, 11);
        let (co, ro) = commit_amount(&key, 35, 12);
        let commits = vec![ci, co];
        let coeffs = vec![1i64, -1];
        let rand = vec![ri, ro];
        if let Some(proof) =
            prove_linear_rq(&key, &commits, &coeffs, &const_target(2), &rand, ETA, B, 3)
        {
            assert!(
                !verify_linear_rq(&key, &commits, &coeffs, &const_target(2), &proof, ETA, B),
                "unbalanced must reject"
            );
        }
    }

    #[test]
    fn wrong_fee_is_rejected() {
        let key = RingCommitKey::production(1, 0xFEE);
        let (ci, ri) = commit_amount(&key, 10, 21);
        let (co, ro) = commit_amount(&key, 8, 22);
        let commits = vec![ci, co];
        let coeffs = vec![1i64, -1];
        let rand = vec![ri, ro];
        let proof =
            prove_linear_rq(&key, &commits, &coeffs, &const_target(2), &rand, ETA, B, 5).unwrap();
        assert!(verify_linear_rq(&key, &commits, &coeffs, &const_target(2), &proof, ETA, B));
        assert!(!verify_linear_rq(&key, &commits, &coeffs, &const_target(3), &proof, ETA, B));
    }
}
