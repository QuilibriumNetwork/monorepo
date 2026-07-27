//! Linear-relation proof: given commitments `C_i = Commit([v_i]; r_i)`, public
//! small coefficients `α_i`, and a public target `τ`, prove in zero-knowledge
//! that `Σ α_i·v_i = τ` — without revealing any `v_i`.
//!
//! # This is the balance proof
//!
//! A confidential transaction is valid iff `Σ inputs = Σ outputs + fee`. Take
//! `α = +1` for inputs, `α = -1` for outputs, `τ = fee`: this proof *is* the
//! balance check — the guarantee that no value is created.
//!
//! # Construction — a commitment-to-zero opening (reuses the Σ-engine)
//!
//! The commitment is homomorphic, so
//! ```text
//! D := Σ α_i·C_i − Commit(τ; 0)
//! ```
//! is a commitment to `Σ α_i·v_i − τ` with randomness `ρ = Σ α_i·r_i`. When the
//! relation holds the message is **zero**, so `D = M·ρ` for the stacked
//! commitment matrix `M = [A1; a2]` — and proving knowledge of the short `ρ` is
//! exactly [`crate::prove_short_opening`]. **Soundness/ZK precondition:** `ρ`
//! must be short (`‖ρ‖∞ ≤ Σ|α_i|·β ≤ params.r_bound`). Small coefficients (the
//! `±1` of balance) keep it short; the `2^i` gadget of a *range* proof does
//! not, which is why range binds its bits through a folded-matrix opening
//! rather than through this proof directly .

use crate::arith::signed_mod;
use crate::commitment::{CommitKey, Commitment, Opening};
use crate::sigma::{prove_short_opening, verify_short_opening, ShortOpeningProof, SigmaParams};

/// `α·x mod q` for a small signed `α` and `x ∈ [0,q)` (`|α|·x` fits `i128`).
fn scalar_mul_mod(a: i128, x: u128, q: u128) -> u128 {
    signed_mod(a * (x as i128), q)
}

/// Compute `D = Σ α_i·C_i − Commit(τ; 0)` as a stacked `(n+ℓ)` vector.
fn combined_target(
    key: &CommitKey,
    commitments: &[Commitment],
    coeffs: &[i128],
    target: u128,
    q: u128,
) -> Vec<u128> {
    let n = key.n();
    let ell = key.params.ell;
    let mut t1 = vec![0u128; n];
    let mut t2 = vec![0u128; ell];
    for (c, &a) in commitments.iter().zip(coeffs) {
        for (j, v) in c.t1.iter().enumerate() {
            t1[j] = (t1[j] + scalar_mul_mod(a, *v, q)) % q;
        }
        for (j, v) in c.t2.iter().enumerate() {
            t2[j] = (t2[j] + scalar_mul_mod(a, *v, q)) % q;
        }
    }
    // − Commit(τ;0): Commit(τ;0) has t1 = 0, t2 = (τ, 0, …). Subtract from t2[0].
    t2[0] = (t2[0] + q - target % q) % q;
    let mut d = t1;
    d.extend(t2);
    d
}

/// Prove `Σ α_i·v_i = τ` for the given commitments and their openings.
/// `params.r_bound` must be ≥ `Σ|α_i|·β` (the norm of the combined randomness).
/// Returns `None` if no accepting transcript is found.
pub fn prove_linear(
    key: &CommitKey,
    commitments: &[Commitment],
    coeffs: &[i128],
    target: u128,
    openings: &[Opening],
    params: &SigmaParams,
    seed: u64,
) -> Option<ShortOpeningProof> {
    let q = params.q;
    let m = key.params.m;
    // ρ = Σ α_i·r_i (short when the coefficients are small).
    let mut rho = vec![0i128; m];
    for (o, &a) in openings.iter().zip(coeffs) {
        for (j, ri) in o.r.iter().enumerate() {
            rho[j] += a * ri;
        }
    }
    let d = combined_target(key, commitments, coeffs, target, q);
    prove_short_opening(&key.commit_matrix(), &d, &rho, params, seed)
}

/// Verify a linear-relation proof: recompute `D` from the public commitments,
/// coefficients and target, and check the commitment-to-zero opening.
pub fn verify_linear(
    key: &CommitKey,
    commitments: &[Commitment],
    coeffs: &[i128],
    target: u128,
    proof: &ShortOpeningProof,
    params: &SigmaParams,
) -> bool {
    let d = combined_target(key, commitments, coeffs, target, params.q);
    verify_short_opening(&key.commit_matrix(), &d, proof, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::SplitMix64;
    use crate::commitment::{CommitKey, CommitParams};

    fn key() -> CommitKey {
        CommitKey::from_seed(CommitParams::illustrative_scalar(), 0xBA1)
    }

    /// Balance params: combined randomness of up to `k` ±1 terms has norm ≤ k·β.
    fn balance_params(k: usize) -> SigmaParams {
        SigmaParams { q: (1u128 << 61) - 1, rounds: 16, mask_bound: 1 << 20, r_bound: k as i128 }
    }

    fn ternary_r(m: usize, tag: u64) -> Vec<i128> {
        let mut prg = SplitMix64::new(tag);
        (0..m).map(|_| (prg.next_u64() % 3) as i128 - 1).collect()
    }

    /// Build a commitment + its opening for value `v`.
    fn commit_value(k: &CommitKey, v: u128, tag: u64) -> (Commitment, Opening) {
        let r = ternary_r(k.params.m, tag);
        let c = k.commit(&[v], &r);
        (c, Opening { msg: vec![v], r })
    }

    #[test]
    fn balance_holds_inputs_equal_outputs_plus_fee() {
        // inputs {30, 12} ; outputs {35, 5} ; fee 2 → 42 = 40 + 2. ✓
        let k = key();
        let inputs = [30u128, 12];
        let outputs = [35u128, 5];
        let fee = 2u128;

        let mut commits = Vec::new();
        let mut opens = Vec::new();
        let mut coeffs = Vec::new();
        for (i, &v) in inputs.iter().enumerate() {
            let (c, o) = commit_value(&k, v, 1000 + i as u64);
            commits.push(c);
            opens.push(o);
            coeffs.push(1i128); // +input
        }
        for (i, &v) in outputs.iter().enumerate() {
            let (c, o) = commit_value(&k, v, 2000 + i as u64);
            commits.push(c);
            opens.push(o);
            coeffs.push(-1i128); // −output
        }
        let p = balance_params(commits.len());
        let proof = prove_linear(&k, &commits, &coeffs, fee, &opens, &p, 7).expect("balances");
        assert!(verify_linear(&k, &commits, &coeffs, fee, &proof, &p));
    }

    #[test]
    fn unbalanced_transaction_is_rejected() {
        // inputs {30} ; outputs {35} ; fee 2 → 30 ≠ 37 : money would be created.
        let k = key();
        let (ci, oi) = commit_value(&k, 30, 11);
        let (co, oo) = commit_value(&k, 35, 12);
        let commits = [ci, co];
        let opens = [oi, oo];
        let coeffs = [1i128, -1];
        let fee = 2u128;
        let p = balance_params(2);
        // A cheating prover still produces a transcript, but D commits to a
        // nonzero message (30−35−2 = −7), so the opening check fails.
        if let Some(proof) = prove_linear(&k, &commits, &coeffs, fee, &opens, &p, 3) {
            assert!(!verify_linear(&k, &commits, &coeffs, fee, &proof, &p), "unbalanced must reject");
        }
    }

    #[test]
    fn tampered_balance_proof_is_rejected() {
        let k = key();
        let (ci, oi) = commit_value(&k, 10, 21);
        let (co, oo) = commit_value(&k, 8, 22);
        let commits = [ci, co];
        let opens = [oi, oo];
        let coeffs = [1i128, -1];
        let fee = 2u128;
        let p = balance_params(2);
        let mut proof = prove_linear(&k, &commits, &coeffs, fee, &opens, &p, 4).unwrap();
        proof.z[0][0] += 1;
        assert!(!verify_linear(&k, &commits, &coeffs, fee, &proof, &p));
    }

    #[test]
    fn wrong_fee_is_rejected() {
        // Correct balance for fee=2, but verify against fee=3 → reject.
        let k = key();
        let (ci, oi) = commit_value(&k, 10, 31);
        let (co, oo) = commit_value(&k, 8, 32);
        let commits = [ci, co];
        let opens = [oi, oo];
        let coeffs = [1i128, -1];
        let p = balance_params(2);
        let proof = prove_linear(&k, &commits, &coeffs, 2, &opens, &p, 5).unwrap();
        assert!(verify_linear(&k, &commits, &coeffs, 2, &proof, &p));
        assert!(!verify_linear(&k, &commits, &coeffs, 3, &proof, &p), "wrong fee rejects");
    }
}
