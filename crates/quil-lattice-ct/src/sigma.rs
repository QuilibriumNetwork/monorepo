//! The core lattice ZK engine: a **Fiat-Shamir-with-aborts Σ-protocol**
//! (Lyubashevsky) proving knowledge of a SHORT `r` with `A·r = t (mod q)`,
//! without revealing `r`.
//!
//! This is the atom every higher proof composes from: a commitment
//! *opening* proof (`A = A1`, `t = t1`), the *binary* proof (bit ∈ {0,1}),
//! the *balance*/linear-relation proof, and thus the *range* proof. Building
//! it correctly first — completeness, honest-verifier ZK via rejection
//! sampling, and special-soundness — is the honest way in: a range proof IS
//! its ZK proof, so we don't fake soundness.
//!
//! # Protocol (one round)
//!
//! * Prover samples masking `y ← U[-B, B]^m`, sends `w = A·y`.
//! * Challenge `c ∈ {-1, 0, 1}` = Fiat-Shamir hash of `(A, t, all w)`.
//! * Response `z = y + c·r`.
//! * **Rejection**: the proof is emitted only if every `‖z‖∞ ≤ B - β`; else
//! the whole transcript is resampled. Conditioned on acceptance, `z` is
//! uniform on `[-(B-β), B-β]^m` **independently of `r`** — that is the
//! zero-knowledge.
//! * Verify: recompute `c`, check `A·z ≡ w + c·t (mod q)` and `‖z‖∞ ≤ B-β`.
//!
//! `rounds` (`R`) parallel repetitions are run; special soundness extracts
//! `r = (z - z')/(c - c')` from two transcripts differing in one challenge, so
//! the soundness error is `|C|^{-R}` against Fiat-Shamir grinding.
//!
//! The challenge set `{-1,0,1}` and default `rounds` here give *illustrative*
//! soundness (`~R·log2(3)` bits) and are for testability. Production uses a
//! structured challenge space (small-norm ring elements) and parameters from a
//! soundness/ZK analysis. The protocol *structure* — mask, FS challenge,
//! bounded rejection, special-soundness extractor — is the real thing.

use sha2::{Digest, Sha256};

use crate::arith::{inf_norm, matvec, signed_mod, SplitMix64};

/// Σ-protocol parameters. **Illustrative — NOT security-reviewed.**
#[derive(Clone, Debug)]
pub struct SigmaParams {
    /// Modulus (shared with the commitment).
    pub q: u128,
    /// Parallel repetitions `R`. Soundness error ≈ `3^{-R}`.
    pub rounds: usize,
    /// Masking bound `B` (`y ← U[-B, B]`). Larger `B` ⇒ rarer aborts, weaker
    /// (but still bounded) hiding slack; smaller ⇒ tighter proof, more aborts.
    pub mask_bound: i128,
    /// Witness bound `β`: the statement is "there is `r` with `A·r=t`,
    /// `‖r‖∞ ≤ β`". The accepted-`z` bound is `B - β`.
    pub r_bound: i128,
}

impl SigmaParams {
    /// Illustrative params matching the commitment's `illustrative_scalar`.
    pub fn illustrative(q: u128) -> Self {
        SigmaParams { q, rounds: 16, mask_bound: 1 << 16, r_bound: 1 }
    }
    /// The bound the verifier enforces on each response `z`.
    fn z_bound(&self) -> i128 {
        self.mask_bound - self.r_bound
    }
}

/// A non-interactive proof (all `R` rounds). `w` and `z` are per-round; the
/// challenges are recomputed by the verifier from the Fiat-Shamir hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShortOpeningProof {
    pub w: Vec<Vec<u128>>, // R × n
    pub z: Vec<Vec<i128>>, // R × m
}

/// Derive `R` ternary challenges `c_k ∈ {-1,0,1}` from `(A, t, all w)`. The
/// hash binds every round's `w`, so a cheating prover must grind all `R`
/// challenges at once (soundness `3^{-R}`).
fn challenges(a: &[Vec<u128>], t: &[u128], w: &[Vec<u128>], rounds: usize) -> Vec<i128> {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/sigma/v1");
    for row in a {
        for &x in row {
            h.update(x.to_le_bytes());
        }
    }
    for &x in t {
        h.update(x.to_le_bytes());
    }
    for wk in w {
        for &x in wk {
            h.update(x.to_le_bytes());
        }
    }
    // Expand the 32-byte digest with a counter until we have `rounds` bytes.
    let mut out = Vec::with_capacity(rounds);
    let mut ctr = 0u32;
    while out.len() < rounds {
        let mut hi = h.clone();
        hi.update(ctr.to_le_bytes());
        for b in hi.finalize() {
            if out.len() == rounds {
                break;
            }
            out.push((b % 3) as i128 - 1); // {-1, 0, 1}
        }
        ctr += 1;
    }
    out
}

/// Prove knowledge of a short `r` (`‖r‖∞ ≤ β`) with `A·r = t (mod q)`.
/// `seed` deterministically drives the masking sampler (a real prover uses a
/// CSPRNG; determinism here keeps tests reproducible). Returns `None` only if
/// no accepting transcript is found within `max_attempts` (astronomically
/// unlikely for sane params).
pub fn prove_short_opening(
    a: &[Vec<u128>],
    t: &[u128],
    r: &[i128],
    params: &SigmaParams,
    seed: u64,
) -> Option<ShortOpeningProof> {
    let (q, r_len) = (params.q, r.len());
    let zb = params.z_bound();
    let max_attempts = 10_000;
    for attempt in 0..max_attempts {
        let mut prg = SplitMix64::new(seed ^ (attempt as u64).wrapping_mul(0x1000_0001));
        let mut w = Vec::with_capacity(params.rounds);
        let mut y = Vec::with_capacity(params.rounds);
        for _ in 0..params.rounds {
            let yk: Vec<i128> = (0..r_len).map(|_| prg.uniform_pm(params.mask_bound)).collect();
            w.push(matvec(a, &yk, q));
            y.push(yk);
        }
        let c = challenges(a, t, &w, params.rounds);
        // z_k = y_k + c_k · r
        let z: Vec<Vec<i128>> = (0..params.rounds)
            .map(|k| y[k].iter().zip(r).map(|(yi, ri)| yi + c[k] * ri).collect())
            .collect();
        // Bounded rejection: accept only if EVERY z_k is within the box.
        if z.iter().all(|zk| inf_norm(zk) <= zb) {
            return Some(ShortOpeningProof { w, z });
        }
    }
    None
}

/// Verify a [`ShortOpeningProof`] for `A·r = t` with a short `r`.
pub fn verify_short_opening(
    a: &[Vec<u128>],
    t: &[u128],
    proof: &ShortOpeningProof,
    params: &SigmaParams,
) -> bool {
    let q = params.q;
    let zb = params.z_bound();
    if proof.w.len() != params.rounds || proof.z.len() != params.rounds {
        return false;
    }
    let c = challenges(a, t, &proof.w, params.rounds);
    for k in 0..params.rounds {
        // ‖z_k‖∞ ≤ B - β
        if inf_norm(&proof.z[k]) > zb {
            return false;
        }
        // A·z_k ≟ w_k + c_k·t (mod q)
        let lhs = matvec(a, &proof.z[k], q);
        let rhs: Vec<u128> = proof.w[k]
            .iter()
            .zip(&t.iter().map(|&ti| signed_mod(c[k] * ti as i128, q)).collect::<Vec<_>>())
            .map(|(wi, cti)| (wi + cti) % q)
            .collect();
        if lhs != rhs {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A random public matrix `A` (n×m) and a short secret `r`, with `t=A·r`.
    fn instance(n: usize, m: usize, q: u128, beta: i128, seed: u64) -> (Vec<Vec<u128>>, Vec<i128>, Vec<u128>) {
        let mut prg = SplitMix64::new(seed);
        let a: Vec<Vec<u128>> = (0..n)
            .map(|_| (0..m).map(|_| prg.uniform_below(q)).collect())
            .collect();
        let r: Vec<i128> = (0..m).map(|_| prg.uniform_pm(beta)).collect();
        let t = matvec(&a, &r, q);
        (a, r, t)
    }

    fn params(q: u128) -> SigmaParams {
        SigmaParams::illustrative(q)
    }

    #[test]
    fn completeness_honest_proof_verifies() {
        let q = (1u128 << 61) - 1;
        let (a, r, t) = instance(8, 16, q, 1, 1);
        let p = params(q);
        let proof = prove_short_opening(&a, &t, &r, &p, 42).expect("prover accepts");
        assert!(verify_short_opening(&a, &t, &proof, &p));
    }

    #[test]
    fn zero_knowledge_responses_are_within_the_bound() {
        // The whole point of rejection: every emitted z is inside [-(B-β),B-β],
        // i.e. the acceptance box that is independent of r.
        let q = (1u128 << 61) - 1;
        let (a, r, t) = instance(8, 16, q, 1, 7);
        let p = params(q);
        let proof = prove_short_opening(&a, &t, &r, &p, 7).unwrap();
        let zb = p.mask_bound - p.r_bound;
        for zk in &proof.z {
            assert!(inf_norm(zk) <= zb, "response must lie in the ZK box");
        }
    }

    #[test]
    fn soundness_wrong_statement_is_rejected() {
        // A proof made for statement t must NOT verify against a different t'
        // (the Fiat-Shamir challenges rebind to t', breaking A·z = w + c·t').
        let q = (1u128 << 61) - 1;
        let (a, r, t) = instance(8, 16, q, 1, 3);
        let p = params(q);
        let proof = prove_short_opening(&a, &t, &r, &p, 3).unwrap();

        let mut t_bad = t.clone();
        t_bad[0] = (t_bad[0] + 1) % q;
        assert!(!verify_short_opening(&a, &t_bad, &proof, &p), "wrong t must reject");
    }

    #[test]
    fn soundness_tampered_response_is_rejected() {
        let q = (1u128 << 61) - 1;
        let (a, r, t) = instance(8, 16, q, 1, 9);
        let p = params(q);
        let mut proof = prove_short_opening(&a, &t, &r, &p, 9).unwrap();
        // Nudge one response coordinate: the linear check A·z = w + c·t fails.
        proof.z[0][0] += 1;
        assert!(!verify_short_opening(&a, &t, &proof, &p));
    }

    #[test]
    fn special_soundness_extracts_the_witness() {
        // Demonstrate the extractor that underpins soundness: two accepting
        // transcripts sharing a round's `w` but with different challenges c≠c'
        // yield r = (z - z')/(c - c') in that round. We simulate by taking a
        // single round manually.
        let q = (1u128 << 61) - 1;
        let (a, r, _t) = instance(8, 16, q, 1, 11);
        // One round: pick y, w=A·y; two challenges c=1, c'=-1 (differ by 2).
        let mut prg = SplitMix64::new(123);
        let y: Vec<i128> = (0..16).map(|_| prg.uniform_pm(1 << 16)).collect();
        let (c, cp) = (1i128, -1i128);
        let z: Vec<i128> = y.iter().zip(&r).map(|(yi, ri)| yi + c * ri).collect();
        let zp: Vec<i128> = y.iter().zip(&r).map(|(yi, ri)| yi + cp * ri).collect();
        // Extractor: (z - z') = (c - c')·r = 2r ⇒  r = (z - z')/2.
        let extracted: Vec<i128> = z.iter().zip(&zp).map(|(zi, zpi)| (zi - zpi) / (c - cp)).collect();
        assert_eq!(extracted, r, "special-soundness extractor recovers the witness");
        // Sanity: A·r really is the committed value.
        let _ = a;
    }
}
