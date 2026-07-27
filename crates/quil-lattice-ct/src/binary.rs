//! Binary proof: a commitment `C = Commit(b; r)` opens to a **bit** `b ∈
//! {0,1}`, in zero-knowledge (without revealing `b`). This is the constraint
//! that turns a bit-vector commitment into a range proof.
//!
//! # Construction — a CDS OR-proof over the Σ-engine
//!
//! Rather than a product argument for `b·(b−1)=0`, reduce to a **disjunction**
//! of two *linear* opening statements against the stacked commitment matrix
//! `M = [A1; a2]` (see [`crate::CommitKey::commit_matrix`]):
//!
//! * branch 0 ("`b=0`"): `∃ short r : M·r = T0`, where `T0 = (t1, t2)`;
//! * branch 1 ("`b=1`"): `∃ short r : M·r = T1`, where `T1 = (t1, t2 − 1)`.
//!
//! A commitment to bit `b` satisfies exactly branch `b`. The
//! Cramer–Damgård–Schoenmakers OR-proof proves "branch 0 OR branch 1" while
//! hiding which: the **false** branch is produced by the Σ-protocol
//! *simulator* (pick response+challenge, derive the commitment), the **true**
//! branch is a real transcript, and the Fiat-Shamir challenge is *split*
//! `c0 + c1 ≡ H(C, w0, w1) (mod 3)` so the prover freely chooses the fake
//! branch's challenge and is forced on the real one.
//!
//! Challenges are `Z_3 = {0,1,2}` here (so the split is addition mod 3), and
//! each response is bound-rejected to `‖z‖∞ ≤ B − 2β`, keeping it uniform on a
//! box independent of the witness — the zero-knowledge, identical for the real
//! and simulated branches, which is what hides `b`.
//!
//! Soundness is `3^{-rounds}` (illustrative); production uses a structured
//! challenge space and the ring form. The protocol *structure* — OR-simulation,
//! challenge split, bounded rejection — is the real thing.

use sha2::{Digest, Sha256};

use crate::arith::{inf_norm, matvec, signed_mod, SplitMix64};
use crate::commitment::{CommitKey, Commitment};
use crate::sigma::SigmaParams;

/// A binary (bit-membership) OR-proof. Both branches are always present; which
/// one is real is hidden.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryProof {
    /// `w[branch][round]` — the `(n+1)`-vector commitment `M·y`.
    w: [Vec<Vec<u128>>; 2],
    /// `c[branch][round]` — the per-branch challenge in `{0,1,2}`.
    c: [Vec<i128>; 2],
    /// `z[branch][round]` — the `m`-vector response.
    z: [Vec<Vec<i128>>; 2],
}

/// The two branch targets `T0 = (t1, t2)` and `T1 = (t1, t2 − 1)` for a
/// single-value commitment (`ℓ = 1`).
fn targets(c: &Commitment, q: u128) -> [Vec<u128>; 2] {
    assert_eq!(c.t2.len(), 1, "binary proof is for a scalar (ℓ=1) commitment");
    let mut t0 = c.t1.clone();
    t0.push(c.t2[0]);
    let mut t1 = c.t1.clone();
    t1.push((c.t2[0] + q - 1) % q); // t2 − 1 mod q
    [t0, t1]
}

/// Fiat-Shamir challenge: `rounds` values in `{0,1,2}` from `(C, w0, w1)`.
fn challenges(c: &Commitment, w: &[Vec<Vec<u128>>; 2], rounds: usize) -> Vec<i128> {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/binary/v1");
    for x in c.t1.iter().chain(&c.t2) {
        h.update(x.to_le_bytes());
    }
    for branch in w {
        for wk in branch {
            for &x in wk {
                h.update(x.to_le_bytes());
            }
        }
    }
    let mut out = Vec::with_capacity(rounds);
    let mut ctr = 0u32;
    while out.len() < rounds {
        let mut hi = h.clone();
        hi.update(ctr.to_le_bytes());
        for b in hi.finalize() {
            if out.len() == rounds {
                break;
            }
            out.push((b % 3) as i128); // {0,1,2}
        }
        ctr += 1;
    }
    out
}

/// `w + c·T mod q`, the per-round verification RHS.
fn rhs(w: &[u128], c: i128, t: &[u128], q: u128) -> Vec<u128> {
    w.iter()
        .zip(t)
        .map(|(wi, ti)| (wi + signed_mod(c * *ti as i128, q)) % q)
        .collect()
}

/// Prove that `commitment = Commit([b]; r)` opens to a bit `b ∈ {0,1}`.
/// Returns `None` only if no accepting transcript is found (astronomically
/// unlikely for sane params) — or if `b ∉ {0,1}` (a caller error).
pub fn prove_bit(
    key: &CommitKey,
    commitment: &Commitment,
    b: u8,
    r: &[i128],
    params: &SigmaParams,
    seed: u64,
) -> Option<BinaryProof> {
    if b > 1 {
        return None;
    }
    let q = params.q;
    let m = matrix_and_bound(key, params);
    let mmat = m.0;
    let zb = m.1;
    let t = targets(commitment, q);
    let real = b as usize;
    let fake = 1 - real;

    let max_attempts = 10_000;
    for attempt in 0..max_attempts {
        let mut prg = SplitMix64::new(seed ^ (attempt as u64).wrapping_mul(0x9_0001));

        // --- Simulate the FALSE branch: pick c_fake and z_fake, derive w_fake
        //     = M·z_fake − c_fake·T_fake, which verifies by construction. ---
        let c_fake: Vec<i128> = (0..params.rounds).map(|_| (prg.next_u64() % 3) as i128).collect();
        let mut z_fake = Vec::with_capacity(params.rounds);
        let mut w_fake = Vec::with_capacity(params.rounds);
        for k in 0..params.rounds {
            let zk: Vec<i128> = (0..r.len()).map(|_| prg.uniform_pm(zb)).collect();
            let mz = matvec(&mmat, &zk, q);
            let ct = rhs(&vec![0u128; mz.len()], c_fake[k], &t[fake], q); // c_fake·T_fake
            let wk: Vec<u128> = mz.iter().zip(&ct).map(|(a, b)| (a + q - b) % q).collect();
            z_fake.push(zk);
            w_fake.push(wk);
        }

        // --- REAL branch: commit y → w_real; FS forces c_real = c − c_fake. ---
        let mut y_real = Vec::with_capacity(params.rounds);
        let mut w_real = Vec::with_capacity(params.rounds);
        for _ in 0..params.rounds {
            let yk: Vec<i128> = (0..r.len()).map(|_| prg.uniform_pm(params.mask_bound)).collect();
            w_real.push(matvec(&mmat, &yk, q));
            y_real.push(yk);
        }

        // Place branch-indexed w and compute the split challenge.
        let mut w = [Vec::new(), Vec::new()];
        w[real] = w_real.clone();
        w[fake] = w_fake.clone();
        let c_total = challenges(commitment, &w, params.rounds);
        let c_real: Vec<i128> =
            (0..params.rounds).map(|k| (c_total[k] - c_fake[k]).rem_euclid(3)).collect();

        // z_real = y_real + c_real·r, with bounded rejection.
        let z_real: Vec<Vec<i128>> = (0..params.rounds)
            .map(|k| y_real[k].iter().zip(r).map(|(yi, ri)| yi + c_real[k] * ri).collect())
            .collect();
        if !z_real.iter().all(|zk| inf_norm(zk) <= zb) {
            continue; // reject → resample (fake branch may stay, but we resample all)
        }

        let mut c = [Vec::new(), Vec::new()];
        let mut z = [Vec::new(), Vec::new()];
        c[real] = c_real;
        c[fake] = c_fake;
        z[real] = z_real;
        z[fake] = z_fake;
        return Some(BinaryProof { w, c, z });
    }
    None
}

/// Verify a [`BinaryProof`] for `commitment`.
pub fn verify_bit(
    key: &CommitKey,
    commitment: &Commitment,
    proof: &BinaryProof,
    params: &SigmaParams,
) -> bool {
    let q = params.q;
    let (mmat, zb) = matrix_and_bound(key, params);
    let t = targets(commitment, q);

    for branch in 0..2 {
        if proof.w[branch].len() != params.rounds
            || proof.c[branch].len() != params.rounds
            || proof.z[branch].len() != params.rounds
        {
            return false;
        }
    }

    // Challenge split: c0 + c1 ≡ H(C, w0, w1) (mod 3).
    let c_total = challenges(commitment, &proof.w, params.rounds);
    for k in 0..params.rounds {
        if (proof.c[0][k] + proof.c[1][k]).rem_euclid(3) != c_total[k] {
            return false;
        }
    }

    // Each branch, each round: M·z ≡ w + c·T (mod q) and ‖z‖∞ ≤ B − 2β.
    for branch in 0..2 {
        for k in 0..params.rounds {
            let zk = &proof.z[branch][k];
            if inf_norm(zk) > zb {
                return false;
            }
            let lhs = matvec(&mmat, zk, q);
            let expect = rhs(&proof.w[branch][k], proof.c[branch][k], &t[branch], q);
            if lhs != expect {
                return false;
            }
        }
    }
    true
}

/// `(M = [A1; a2], z-bound = B − 2β)`. The `2β` slack accounts for the `{0,1,2}`
/// challenge magnitude.
fn matrix_and_bound(key: &CommitKey, params: &SigmaParams) -> (Vec<Vec<u128>>, i128) {
    (key.commit_matrix(), params.mask_bound - 2 * params.r_bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::SplitMix64 as Prg;
    use crate::commitment::{CommitKey, CommitParams, Opening};

    fn key() -> CommitKey {
        CommitKey::from_seed(CommitParams::illustrative_scalar(), 0xB17)
    }
    fn params() -> SigmaParams {
        SigmaParams::illustrative((1u128 << 61) - 1)
    }
    fn ternary_r(m: usize, tag: u64) -> Vec<i128> {
        let mut prg = Prg::new(tag);
        (0..m).map(|_| (prg.next_u64() % 3) as i128 - 1).collect()
    }

    #[test]
    fn completeness_both_bits_verify() {
        let k = key();
        let p = params();
        for b in [0u8, 1u8] {
            let r = ternary_r(k.params.m, 10 + b as u64);
            let c = k.commit(&[b as u128], &r);
            let proof = prove_bit(&k, &c, b, &r, &p, 20 + b as u64).expect("prover accepts");
            assert!(verify_bit(&k, &c, &proof, &p), "bit {b} proof verifies");
        }
    }

    #[test]
    fn soundness_non_bit_cannot_prove() {
        // A commitment to 2 (not a bit): a cheating prover claiming b=0 (or
        // b=1) produces a transcript, but its short r opens the commitment to
        // message 2, matching NEITHER T0 nor T1 — so verification fails.
        let k = key();
        let p = params();
        let r = ternary_r(k.params.m, 99);
        let c = k.commit(&[2u128], &r);
        for claimed in [0u8, 1u8] {
            if let Some(proof) = prove_bit(&k, &c, claimed, &r, &p, 77) {
                assert!(!verify_bit(&k, &c, &proof, &p), "non-bit must not verify");
            }
            // (prove_bit may also simply fail to find an accepting transcript.)
        }
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let k = key();
        let p = params();
        let r = ternary_r(k.params.m, 5);
        let c = k.commit(&[1u128], &r);
        let mut proof = prove_bit(&k, &c, 1, &r, &p, 5).unwrap();
        proof.z[0][0][0] += 1; // break one response
        assert!(!verify_bit(&k, &c, &proof, &p));
    }

    #[test]
    fn wrong_commitment_is_rejected() {
        // A valid bit proof must not verify against a DIFFERENT commitment.
        let k = key();
        let p = params();
        let r = ternary_r(k.params.m, 6);
        let c = k.commit(&[1u128], &r);
        let proof = prove_bit(&k, &c, 1, &r, &p, 6).unwrap();
        let other = k.commit(&[0u128], &ternary_r(k.params.m, 7));
        assert!(!verify_bit(&k, &other, &proof, &p));
        // Sanity: the opening we used is a real bit opening.
        assert!(k.open_verify(&c, &Opening { msg: vec![1], r }, k.params.beta));
    }
}
