//! Ring-form Fiat-Shamir-with-aborts Σ-protocol — the production instantiation
//! of [`crate::sigma`], over the module layer (`R_q`, `d=256`, ranks `κ=λ=6`).
//!
//! Proves knowledge of a SHORT `r ∈ R_q^m` with `A·r = t (mod q)` without
//! revealing `r`. Two things change from the plain-`Z_q` reference, both from
//! moving to the ring:
//!
//! * **One structured ring challenge, not 16 rounds.** `c` is a single ring
//! element with exactly `τ=39` `±1` coefficients (Dilithium `SampleInBall`),
//! `|C| = C(256,39)·2^39 ≈ 2^176` — a single shot already gives soundness
//! ≫128-bit, so no parallel repetition.
//! * **`z = y + c·r` is a ring product** (`c·r`, a negacyclic convolution),
//! with `‖c·r‖∞ ≤ τ·η`, so the rejection box is `‖z‖∞ ≤ B − τ·η`.
//!
//! Special soundness extracts a *relaxed* opening `r̄ = z − z'` for the
//! challenge difference `c − c'` (short, invertible in `R_q` w.h.p.), of norm
//! `≈ 2B`. **That `≈ 2B` is the exact M-SIS extracted-witness norm** the final
//! lattice-estimator pass needs — no longer the reference's `2^20` guess.
//!
//! # Zero-knowledge: the rejection is PERFECT-ZK (analyzed)
//!
//! With `y` uniform on `[-B, B]^dim` and `s = c·r` (`‖s‖∞ ≤ S = τ·η`), the
//! proof is emitted only when `z = y + s ∈ [-(B-S), B-S]^dim`. For any fixed
//! `s` with `‖s‖∞ ≤ S`, the shifted box `[-(B-S), B-S] − s ⊆ [-B, B]`, so every
//! accepted `z` is reachable by exactly one `y` uniformly — hence the accepted
//! `z` is **uniform on `[-(B-S), B-S]^dim`, independent of `s` (and of `r`)**,
//! and the acceptance probability `((2(B-S)+1)/(2B+1))^dim` is **also
//! witness-independent**. That is *perfect* honest-verifier ZK, not merely
//! statistical — the simulator samples `z` uniformly from the box and programs
//! the challenge. [`rejection_is_perfect_zk_witness_independent`] confirms the
//! witness-independence empirically. (This narrows the audit to soundness-slack
//! parameter selection, not the ZK argument itself.)

use sha2::{Digest, Sha256};

use crate::module::{PolyMatrix, PolyVec};
use crate::params::{CHALLENGE_WEIGHT_TAU, RING_DEGREE_D, SECRET_NORM_ETA};
use crate::rq::Poly;

/// Ring-Σ parameters.
#[derive(Clone, Debug)]
pub struct RingSigmaParams {
    /// Masking bound `B` (`y` coefficients uniform in `[-B, B]`). Sized so
    /// rejections are few (`≈ 2-3` restarts at `d·m` coefficients).
    pub mask_bound: i64,
    /// Secret norm `η` (`‖r‖∞ ≤ η`).
    pub eta: i64,
    /// Challenge weight `τ`.
    pub tau: usize,
}

impl RingSigmaParams {
    /// Production defaults: `η=2`, `τ=39`, `B=2^17` (a few restarts).
    pub fn production() -> Self {
        RingSigmaParams { mask_bound: 1 << 17, eta: SECRET_NORM_ETA, tau: CHALLENGE_WEIGHT_TAU }
    }
    /// The accepted-`z` bound `B − τ·η`.
    pub fn z_bound(&self) -> u64 {
        (self.mask_bound - self.tau as i64 * self.eta) as u64
    }
}

/// A non-interactive ring-Σ proof: the commitment `w` and response `z` (the
/// challenge is recomputed by the verifier via Fiat-Shamir).
#[derive(Clone, Debug)]
pub struct RingOpeningProof {
    pub w: PolyVec,
    pub z: PolyVec,
}

/// Dilithium `SampleInBall`: a ring challenge with exactly `τ` `±1`
/// coefficients at pseudo-random positions, from a byte stream keyed by
/// `(A, t, w)`.
fn challenge(a: &PolyMatrix, t: &PolyVec, w: &PolyVec, tau: usize, aux: &[u8]) -> Poly {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/sigma-rq/v1");
    h.update((aux.len() as u64).to_le_bytes());
    h.update(aux);
    for row in &a.m {
        for p in row {
            for &x in &p.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    for v in t.0.iter().chain(&w.0) {
        for &x in &v.c {
            h.update(x.to_le_bytes());
        }
    }
    // Byte stream: SHA256(seed || ctr).
    let seed = h.finalize();
    let mut stream: Vec<u8> = Vec::new();
    let mut ctr = 0u32;
    let mut next = |stream: &mut Vec<u8>, pos: &mut usize| -> u8 {
        if *pos >= stream.len() {
            let mut hh = Sha256::new();
            hh.update(seed);
            hh.update(ctr.to_le_bytes());
            stream.extend_from_slice(&hh.finalize());
            ctr += 1;
        }
        let b = stream[*pos];
        *pos += 1;
        b
    };
    let d = RING_DEGREE_D;
    let mut c = vec![0i64; d];
    let mut pos = 0usize;
    // Fisher-Yates placement of τ signed units in the top τ slots.
    for i in (d - tau)..d {
        // rejection-sample j in [0, i].
        let j = loop {
            let b = next(&mut stream, &mut pos) as usize;
            if b <= i {
                break b;
            }
        };
        c[i] = c[j];
        let sign = next(&mut stream, &mut pos) & 1;
        c[j] = if sign == 1 { 1 } else { -1 };
    }
    Poly::from_signed(&c)
}

/// Prove knowledge of short `r` (`‖r‖∞ ≤ η`) with `A·r = t`.
pub fn prove_ring_opening(
    a: &PolyMatrix,
    t: &PolyVec,
    r: &PolyVec,
    p: &RingSigmaParams,
    aux: &[u8],
    seed: u64,
) -> Option<RingOpeningProof> {
    use crate::arith::SplitMix64;
    let zb = p.z_bound();
    let m = a.cols;
    for attempt in 0..1000u64 {
        let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x5171));
        let y = PolyVec::sample_uniform_pm(m, p.mask_bound, &mut prg);
        let w = a.matvec(&y);
        let c = challenge(a, t, &w, p.tau, aux);
        let z = y.add(&r.mul_poly(&c)); // z = y + c·r
        if z.inf_norm() <= zb {
            return Some(RingOpeningProof { w, z });
        }
        // else reject → resample (Dilithium-style abort).
    }
    None
}

/// Verify a ring-Σ proof: `A·z ≟ w + c·t` and `‖z‖∞ ≤ B − τ·η`.
pub fn verify_ring_opening(
    a: &PolyMatrix,
    t: &PolyVec,
    proof: &RingOpeningProof,
    p: &RingSigmaParams,
    aux: &[u8],
) -> bool {
    if proof.z.inf_norm() > p.z_bound() {
        return false;
    }
    let c = challenge(a, t, &proof.w, p.tau, aux);
    a.matvec(&proof.z) == proof.w.add(&t.mul_poly(&c))
}

/// Derive a batch coefficient `ρ_j` (a `SampleInBall` element) from a transcript
/// seed and index — small, so the random-linear combination stays sound
/// (Schwartz-Zippel over `R_q`) without inflating norms.
fn batch_coeff(seed: &[u8; 32], j: usize, tau: usize) -> Poly {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/batch-rho/v1");
    h.update((j as u64).to_le_bytes());
    h.update(seed);
    let s = h.finalize();
    let mut stream: Vec<u8> = Vec::new();
    let mut ctr = 0u32;
    let mut pos = 0usize;
    let mut next = |st: &mut Vec<u8>, p: &mut usize| -> u8 {
        if *p >= st.len() {
            let mut hh = Sha256::new();
            hh.update(s);
            hh.update(ctr.to_le_bytes());
            st.extend_from_slice(&hh.finalize());
            ctr += 1;
        }
        let b = st[*p];
        *p += 1;
        b
    };
    let d = RING_DEGREE_D;
    let mut c = vec![0i64; d];
    for i in (d - tau)..d {
        let jj = loop {
            let b = next(&mut stream, &mut pos) as usize;
            if b <= i {
                break b;
            }
        };
        c[i] = c[jj];
        c[jj] = if next(&mut stream, &mut pos) & 1 == 1 { 1 } else { -1 };
    }
    Poly::from_signed(&c)
}

/// One item in a batch: the public target `t`, the proof, and its FS aux.
pub struct BatchItem<'a> {
    pub t: PolyVec,
    pub proof: &'a RingOpeningProof,
    pub aux: Vec<u8>,
}

/// Batch-verify many openings that share the **same** matrix `A`. Instead of
/// `M` separate `A·z_j` matvecs, checks one random-linear combination:
/// `A·(Σ ρ_j z_j) = Σ ρ_j (w_j + c_j·t_j)`. Sound by Schwartz-Zippel: any single
/// invalid opening makes the combined residual nonzero w.h.p. over the `ρ_j`.
/// This is the consensus lever — the per-`A` matvec is paid once for the whole
/// batch (a tx's inputs, or a block's).
pub fn batch_verify_openings(a: &PolyMatrix, items: &[BatchItem], p: &RingSigmaParams) -> bool {
    if items.is_empty() {
        return true;
    }
    // Per-item norm gate (cheap, not batchable).
    for it in items {
        if it.proof.z.inf_norm() > p.z_bound() {
            return false;
        }
    }
    // Transcript seed over all items (binds ρ to the batch).
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/batch-seed/v1");
    for it in items {
        for v in it.t.0.iter().chain(&it.proof.w.0).chain(&it.proof.z.0) {
            for &x in &v.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    let seed: [u8; 32] = h.finalize().into();

    let mut zsum = PolyVec::zero(a.cols);
    let mut rhs = PolyVec::zero(a.rows);
    for (j, it) in items.iter().enumerate() {
        let rho = batch_coeff(&seed, j, p.tau);
        zsum = zsum.add(&it.proof.z.mul_poly(&rho));
        let c = challenge(a, &it.t, &it.proof.w, p.tau, &it.aux);
        // ρ_j·(w_j + c_j·t_j).
        let term = it.proof.w.add(&it.t.mul_poly(&c));
        rhs = rhs.add(&term.mul_poly(&rho));
    }
    a.matvec(&zsum) == rhs
}

/// Batch of plain matvec-equality checks `A·z_j = rhs_j` sharing `A`. Checks the
/// random-linear combination `A·(Σ ρ_j z_j) = Σ ρ_j rhs_j` in one matvec (used to
/// amortize the `prod_zero` opening checks across a whole block's chaining proofs).
pub fn batch_matvec_eq(a: &PolyMatrix, items: &[(PolyVec, PolyVec)]) -> bool {
    if items.is_empty() {
        return true;
    }
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/batch-matvec/v1");
    for (z, rhs) in items {
        for v in z.0.iter().chain(&rhs.0) {
            for &x in &v.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    let seed: [u8; 32] = h.finalize().into();
    let mut zsum = PolyVec::zero(a.cols);
    let mut rsum = PolyVec::zero(a.rows);
    for (j, (z, rhs)) in items.iter().enumerate() {
        let rho = batch_coeff(&seed, j, CHALLENGE_WEIGHT_TAU);
        zsum = zsum.add(&z.mul_poly(&rho));
        rsum = rsum.add(&rhs.mul_poly(&rho));
    }
    a.matvec(&zsum) == rsum
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::SplitMix64;
    use crate::module::ETA;

    /// A random module statement `A·r = t` with short `r`, at ranks `(n, m)`.
    fn instance(n: usize, m: usize, seed: u64) -> (PolyMatrix, PolyVec, PolyVec) {
        let a = PolyMatrix::from_seed(n, m, seed);
        let mut prg = SplitMix64::new(seed ^ 0xBEEF);
        let r = PolyVec::sample_short(m, ETA, &mut prg);
        let t = a.matvec(&r);
        (a, r, t)
    }

    #[test]
    fn completeness_single_challenge() {
        // Production ranks κ=λ=6, one structured challenge — no rounds.
        let (a, r, t) = instance(6, 6, 1);
        let p = RingSigmaParams::production();
        let proof = prove_ring_opening(&a, &t, &r, &p, b"", 7).expect("prover accepts");
        assert!(verify_ring_opening(&a, &t, &proof, &p, b""));
    }

    #[test]
    fn zero_knowledge_response_in_box() {
        let (a, r, t) = instance(6, 6, 2);
        let p = RingSigmaParams::production();
        let proof = prove_ring_opening(&a, &t, &r, &p, b"", 3).unwrap();
        assert!(proof.z.inf_norm() <= p.z_bound(), "z lies in the ZK box");
    }

    #[test]
    fn soundness_wrong_target_rejected() {
        let (a, r, t) = instance(6, 6, 4);
        let p = RingSigmaParams::production();
        let proof = prove_ring_opening(&a, &t, &r, &p, b"", 5).unwrap();
        // Perturb one coefficient of t: FS challenge rebinds, A·z ≠ w + c·t'.
        let mut t_bad = t.clone();
        t_bad.0[0].c[0] = (t_bad.0[0].c[0] + 1) % Poly::Q;
        assert!(!verify_ring_opening(&a, &t_bad, &proof, &p, b""));
    }

    #[test]
    fn soundness_tampered_response_rejected() {
        let (a, r, t) = instance(6, 6, 8);
        let p = RingSigmaParams::production();
        let mut proof = prove_ring_opening(&a, &t, &r, &p, b"", 9).unwrap();
        proof.z.0[0].c[0] = (proof.z.0[0].c[0] + 1) % Poly::Q;
        assert!(!verify_ring_opening(&a, &t, &proof, &p, b""));
    }

    #[test]
    fn rejection_is_perfect_zk_witness_independent() {
        // The perfect-ZK crux: the single-attempt acceptance probability must be
        // the SAME for different witnesses (it depends only on B, S, dim — not on
        // r). Measure it for two independent witnesses; the rates must match and
        // every accepted z must lie in the box.
        let p = RingSigmaParams::production();
        let zb = p.z_bound();
        let measure = |a: &PolyMatrix, t: &PolyVec, r: &PolyVec| -> f64 {
            let trials = 160u64;
            let mut acc = 0u64;
            for s in 0..trials {
                let mut prg = SplitMix64::new(0xADD ^ s.wrapping_mul(0x9E37_79B1));
                let y = PolyVec::sample_uniform_pm(a.cols, p.mask_bound, &mut prg);
                let w = a.matvec(&y);
                let c = challenge(a, t, &w, p.tau, b"");
                let z = y.add(&r.mul_poly(&c));
                if z.inf_norm() <= zb {
                    acc += 1;
                }
            }
            acc as f64 / trials as f64
        };
        let (a1, r1, t1) = instance(6, 6, 100);
        let (a2, r2, t2) = instance(6, 6, 200); // a different witness/statement
        let rate1 = measure(&a1, &t1, &r1);
        let rate2 = measure(&a2, &t2, &r2);
        assert!(rate1 > 0.15 && rate1 < 0.85, "acceptance in a sane band: {rate1}");
        assert!(
            (rate1 - rate2).abs() < 0.15,
            "acceptance must be witness-independent (perfect ZK): {rate1} vs {rate2}"
        );
    }

    #[test]
    #[ignore] // timing report; run with `--ignored --nocapture`
    fn timing_report() {
        use std::time::Instant;
        let reps = 50;

        // One ring-Σ short opening (the atom every membership level is built from).
        let (a, r, t) = instance(6, 6, 1);
        let p = RingSigmaParams::production();
        let t0 = Instant::now();
        let mut proofs = Vec::new();
        for i in 0..reps {
            proofs.push(prove_ring_opening(&a, &t, &r, &p, b"", i).unwrap());
        }
        let prove_us = t0.elapsed().as_micros() as f64 / reps as f64;
        let t1 = Instant::now();
        for pf in &proofs {
            assert!(verify_ring_opening(&a, &t, pf, &p, b""));
        }
        let verify_us = t1.elapsed().as_micros() as f64 / reps as f64;
        println!("sigma_rq opening:  prove {prove_us:.0} us  verify {verify_us:.0} us");

        // One binary proof (the direction-bit atom at each Merkle level).
        use crate::binary_rq::{prove_bit_rq, verify_bit_rq, BinRqParams};
        use crate::module::{RingCommitKey, ETA};
        let k = RingCommitKey::production(1, 0xB17B);
        let mut prg = SplitMix64::new(1);
        let rb = PolyVec::sample_short(k.a1.cols, ETA, &mut prg);
        let cb = k.commit(&PolyVec(vec![{ let mut z = crate::rq::Poly::zero(); z.c[0] = 1; z }]), &rb);
        let bp = BinRqParams::production();
        let t2 = Instant::now();
        let mut bproofs = Vec::new();
        for i in 0..reps {
            bproofs.push(prove_bit_rq(&k, &cb, 1, &rb, &bp, b"", i).unwrap());
        }
        let bprove_us = t2.elapsed().as_micros() as f64 / reps as f64;
        let t3 = Instant::now();
        for pf in &bproofs {
            assert!(verify_bit_rq(&k, &cb, pf, &bp, b""));
        }
        let bverify_us = t3.elapsed().as_micros() as f64 / reps as f64;
        println!("binary_rq proof:   prove {bprove_us:.0} us  verify {bverify_us:.0} us");

        // Extrapolate: a membership level ≈ 1 opening (path-chain) + 1 binary
        // (left/right direction) + a little. Report per-depth verify cost.
        let level_verify = verify_us + bverify_us;
        let level_prove = prove_us + bprove_us;
        for depth in [20usize, 30] {
            println!(
                "  accumulator depth {depth} (~2^{depth} coins): prove ~{:.1} ms  verify ~{:.1} ms",
                level_prove * depth as f64 / 1000.0,
                level_verify * depth as f64 / 1000.0,
            );
        }
    }

    #[test]
    fn challenge_has_exact_weight_and_norm() {
        let (a, _r, t) = instance(6, 6, 11);
        let mut prg = SplitMix64::new(1);
        let w = a.matvec(&PolyVec::sample_short(6, ETA, &mut prg));
        let c = challenge(&a, &t, &w, CHALLENGE_WEIGHT_TAU, b"");
        let nonzero = c.c.iter().filter(|&&x| x != 0).count();
        assert_eq!(nonzero, CHALLENGE_WEIGHT_TAU, "exactly τ nonzero coeffs");
        assert_eq!(c.inf_norm(), 1, "‖c‖∞ = 1");
    }
}
