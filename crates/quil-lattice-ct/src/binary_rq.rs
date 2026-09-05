//! Ring-form binary proof — a committed constant-poly `b` satisfies `b ∈
//! {0,1}` (`⟺ b²=b (mod q)`), in zero-knowledge, at production parameters.
//!
//! # Why this exists (and is NOT the reference's OR-proof)
//!
//! The reference's CDS OR-proof has no ring-form analogue (the structured
//! challenge has no additive split — see the crate notes). This is instead a
//! **masked-evaluation product argument**, derived and reasoned through here
//! rather than recalled, using
//! ```text
//!   f·(f − x) = x²·(b² − b) + x·α·(2b − 1) + α² (identity over R_q)
//! ```
//! with `f = x·b + α`, mask `α`, and a ring challenge `x`.
//!
//! **Soundness (the load-bearing argument).** The prover commits `C_b, C_α,
//! C_1, C_0` *before* `x`, then reveals `f` and short openings `z_f, z_g`. The
//! verifier binds `f = x·b + α` (via `z_f`) and `f·(f−x) = x·v1 + v0` (via
//! `z_g`, computing `f(f−x)` from the public `f`). Substituting,
//! `x²(b²−b) + x(α(2b−1)−v1) + (α²−v0) = 0` at the challenge `x`. This is a
//! degree-2 polynomial in `x` whose leading coefficient is `b²−b` — **fixed by
//! the committed `b`** and independent of whatever `v1, v0` a cheat commits. A
//! random `x` (over the invertible-difference `SampleInBall` set) is a root
//! only with probability `≤ 2/|C|`, so `b²−b` must be 0. No product proof for
//! `v1, v0` is needed.
//!
//! **Zero-knowledge.** `g = x·v1 + v0` is *never revealed* (it would leak `b`
//! via the `±x·α` term); only the short opening `z_g` is, and the verifier
//! recomputes `f(f−x)` itself. `f` is masked by a wide `α`; `z_f, z_g` are
//! rejection-sampled. The rejection bounds here are the most error-prone part.
//! The tests below validate COMPLETENESS and SOUNDNESS (the parts a unit test
//! *can* check); statistical ZK / tight rejection tuning is analysed separately.

use sha2::{Digest, Sha256};

use crate::arith::SplitMix64;
use crate::module::{PolyVec, RingCommitKey, RingCommitment};
use crate::params::CHALLENGE_WEIGHT_TAU;
use crate::rq::Poly;

/// Parameters. `B` masks both `f` and the openings; `eta` is `C_b`'s randomness
/// norm; `tau` the challenge weight.
#[derive(Clone, Debug)]
pub struct BinRqParams {
    pub mask_bound: i64,
    pub eta: i64,
    pub tau: usize,
}
impl BinRqParams {
    pub fn production() -> Self {
        BinRqParams { mask_bound: 1 << 17, eta: crate::module::ETA, tau: CHALLENGE_WEIGHT_TAU }
    }
    fn z_bound(&self) -> u64 {
        (self.mask_bound - self.tau as i64 * self.eta) as u64
    }
    fn f_bound(&self) -> u64 {
        (self.mask_bound - self.tau as i64) as u64
    }
}

/// A ring-form binary proof. `g = x·v1+v0` is deliberately absent (ZK).
#[derive(Clone, Debug)]
pub struct BinaryProofRq {
    pub c_alpha: RingCommitment,
    pub c1: RingCommitment,
    pub c0: RingCommitment,
    pub f: Poly,
    pub z_f: PolyVec,
    pub z_g: PolyVec,
}

/// Challenge `x = SampleInBall(H(C_b, C_α, C_1, C_0))` (weight `τ`, `‖x‖∞=1`).
fn challenge(cs: &[&RingCommitment], tau: usize, aux: &[u8]) -> Poly {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/binary-rq/v1");
    h.update((aux.len() as u64).to_le_bytes());
    h.update(aux);
    for c in cs {
        for p in c.t1.0.iter().chain(&c.t2.0) {
            for &x in &p.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    let seed = h.finalize();
    let mut stream: Vec<u8> = Vec::new();
    let mut ctr = 0u32;
    let mut pos = 0usize;
    let mut next = |st: &mut Vec<u8>, p: &mut usize| -> u8 {
        if *p >= st.len() {
            let mut hh = Sha256::new();
            hh.update(seed);
            hh.update(ctr.to_le_bytes());
            st.extend_from_slice(&hh.finalize());
            ctr += 1;
        }
        let b = st[*p];
        *p += 1;
        b
    };
    let d = Poly::D;
    let mut c = vec![0i64; d];
    for i in (d - tau)..d {
        let j = loop {
            let b = next(&mut stream, &mut pos) as usize;
            if b <= i {
                break b;
            }
        };
        c[i] = c[j];
        c[j] = if next(&mut stream, &mut pos) & 1 == 1 { 1 } else { -1 };
    }
    Poly::from_signed(&c)
}

/// Single scalar (constant-poly) `s`.
fn constant(s: i64) -> Poly {
    let mut p = Poly::zero();
    p.c[0] = ((s % Poly::Q as i64 + Poly::Q as i64) % Poly::Q as i64) as u64;
    p
}
fn commit1(key: &RingCommitKey, m: &Poly, r: &PolyVec) -> RingCommitment {
    key.commit(&PolyVec(vec![m.clone()]), r)
}

/// Prove `c_b = Commit([b]; r_b)` opens to a bit `b ∈ {0,1}`.
pub fn prove_bit_rq(
    key: &RingCommitKey,
    c_b: &RingCommitment,
    b: u8,
    r_b: &PolyVec,
    p: &BinRqParams,
    aux: &[u8],
    seed: u64,
) -> Option<BinaryProofRq> {
    if b > 1 {
        return None;
    }
    let lambda = key.a1.cols;
    for attempt in 0..2000u64 {
        let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x71C1));
        // Masks: α wide; r_α, r0 wide (mask the openings); r1 short.
        let alpha = PolyVec::sample_uniform_pm(1, p.mask_bound, &mut prg).0[0].clone();
        let r_alpha = PolyVec::sample_uniform_pm(lambda, p.mask_bound, &mut prg);
        let r1 = PolyVec::sample_short(lambda, p.eta, &mut prg);
        let r0 = PolyVec::sample_uniform_pm(lambda, p.mask_bound, &mut prg);
        // v1 = α(2b−1), v0 = α².
        let v1 = alpha.mul_ntt(&constant(2 * b as i64 - 1));
        let v0 = alpha.mul_ntt(&alpha);
        let c_alpha = commit1(key, &alpha, &r_alpha);
        let c1 = commit1(key, &v1, &r1);
        let c0 = commit1(key, &v0, &r0);

        let x = challenge(&[c_b, &c_alpha, &c1, &c0], p.tau, aux);
        // f = x·b + α ; z_f = x·r_b + r_α ; z_g = x·r1 + r0.
        let f = x.mul_ntt(&constant(b as i64)).add(&alpha);
        let z_f = r_b.mul_poly(&x).add(&r_alpha);
        let z_g = r1.mul_poly(&x).add(&r0);
        // Bounded rejection.
        if f.inf_norm() <= p.f_bound() && z_f.inf_norm() <= p.z_bound() && z_g.inf_norm() <= p.z_bound()
        {
            return Some(BinaryProofRq { c_alpha, c1, c0, f, z_f, z_g });
        }
    }
    None
}

/// Verify a ring-form binary proof.
pub fn verify_bit_rq(
    key: &RingCommitKey,
    c_b: &RingCommitment,
    pf: &BinaryProofRq,
    p: &BinRqParams,
    aux: &[u8],
) -> bool {
    if pf.z_f.inf_norm() > p.z_bound() || pf.z_g.inf_norm() > p.z_bound() || pf.f.inf_norm() > p.f_bound()
    {
        return false;
    }
    let x = challenge(&[c_b, &pf.c_alpha, &pf.c1, &pf.c0], p.tau, aux);
    let a1_zf = key.a1.matvec(&pf.z_f);
    let a2_zf = key.a2.matvec(&pf.z_f).0[0].clone();
    let a1_zg = key.a1.matvec(&pf.z_g);
    let a2_zg = key.a2.matvec(&pf.z_g).0[0].clone();

    // f binds to x·C_b + C_α.
    if a1_zf != c_b.t1.mul_poly(&x).add(&pf.c_alpha.t1) {
        return false;
    }
    if a2_zf.add(&pf.f) != x.mul_ntt(&c_b.t2.0[0]).add(&pf.c_alpha.t2.0[0]) {
        return false;
    }
    // z_g opens (x·C_1 + C_0) − Commit(f(f−x); 0) to zero:
    //   A1·z_g = x·C_1.t1 + C_0.t1 ; a2·z_g = x·C_1.t2 + C_0.t2 − f(f−x).
    if a1_zg != pf.c1.t1.mul_poly(&x).add(&pf.c0.t1) {
        return false;
    }
    let f_ffx = pf.f.mul_ntt(&pf.f.sub(&x)); // f·(f − x), public
    let rhs = x.mul_ntt(&pf.c1.t2.0[0]).add(&pf.c0.t2.0[0]).sub(&f_ffx);
    a2_zg == rhs
}

// ── AMORTIZED (commit-once) binary proof over an ℓ-coordinate vector ────────

/// One proof that EVERY coordinate of a length-`ℓ` committed vector `c_b` is a
/// bit `{0,1}` — replacing `ℓ` independent [`prove_bit_rq`]s for a range.
///
/// **Same soundness, shared randomness.** Each coordinate is the identical
/// masked-evaluation product relation as [`prove_bit_rq`] (`fᵢ = x·bᵢ + αᵢ`,
/// `fᵢ(fᵢ−x) = x·v1ᵢ + v0ᵢ`), verified per-coordinate; the load-bearing
/// `bᵢ²−bᵢ` leading term is fixed by the committed `bᵢ` and a single random `x`
/// catches a non-bit in ANY coordinate (module header). The ONLY change is
/// standard BDLOP *commit-once*: `α`, `v1`, `v0` are each committed as ONE
/// ℓ-vector (one shared `t1 = A1·r`, one opening `z`) instead of `ℓ` separate
/// commitments — so the extracted-norm / challenge structure, hence the M-SIS
/// margins, are UNCHANGED from `prove_bit_rq`. This removes the dominant
/// redundancy (the per-bit replication of `t1` and of `z_f/z_g`).
pub struct BitsProofRq {
    pub c_alpha: RingCommitment,
    pub c1: RingCommitment,
    pub c0: RingCommitment,
    pub f: PolyVec,   // ℓ masked evaluations fᵢ
    pub z_f: PolyVec, // λ opening binding f to x·c_b + c_alpha
    pub z_g: PolyVec, // λ opening binding the garbage
}

/// Prove all `ℓ = key.ell` coordinates of `c_b` (message `bits`, randomness
/// `r_b`) are bits, in one proof. `bits`/`c_b` are produced by
/// `key.commit(bits, r_b)` with each `bitsᵢ` a constant-poly `{0,1}`.
pub fn prove_bits_rq(
    key: &RingCommitKey,
    c_b: &RingCommitment,
    bits: &PolyVec,
    r_b: &PolyVec,
    p: &BinRqParams,
    aux: &[u8],
    seed: u64,
) -> Option<BitsProofRq> {
    let n = key.ell;
    let lambda = key.a1.cols;
    let one = Poly::one();
    let two_b_minus_one: Vec<Poly> = bits.0.iter().map(|b| b.scalar_mul(2).sub(&one)).collect();
    for attempt in 0..2000u64 {
        let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x71C1));
        let alpha = PolyVec::sample_uniform_pm(n, p.mask_bound, &mut prg);
        let r_alpha = PolyVec::sample_uniform_pm(lambda, p.mask_bound, &mut prg);
        let r1 = PolyVec::sample_short(lambda, p.eta, &mut prg);
        let r0 = PolyVec::sample_uniform_pm(lambda, p.mask_bound, &mut prg);
        let v1 = PolyVec(alpha.0.iter().zip(&two_b_minus_one).map(|(a, tb)| a.mul_ntt(tb)).collect());
        let v0 = PolyVec(alpha.0.iter().map(|a| a.mul_ntt(a)).collect());
        let c_alpha = key.commit(&alpha, &r_alpha);
        let c1 = key.commit(&v1, &r1);
        let c0 = key.commit(&v0, &r0);
        let x = challenge(&[c_b, &c_alpha, &c1, &c0], p.tau, aux);
        let f = PolyVec(bits.0.iter().zip(&alpha.0).map(|(b, a)| x.mul_ntt(b).add(a)).collect());
        let z_f = r_b.mul_poly(&x).add(&r_alpha);
        let z_g = r1.mul_poly(&x).add(&r0);
        if f.inf_norm() <= p.f_bound() && z_f.inf_norm() <= p.z_bound() && z_g.inf_norm() <= p.z_bound()
        {
            return Some(BitsProofRq { c_alpha, c1, c0, f, z_f, z_g });
        }
    }
    None
}

/// Verify an amortized bit-vector proof.
pub fn verify_bits_rq(
    key: &RingCommitKey,
    c_b: &RingCommitment,
    pf: &BitsProofRq,
    p: &BinRqParams,
    aux: &[u8],
) -> bool {
    let n = key.ell;
    if pf.f.len() != n
        || pf.c_alpha.t2.0.len() != n
        || pf.c1.t2.0.len() != n
        || pf.c0.t2.0.len() != n
        || c_b.t2.0.len() != n
    {
        return false;
    }
    if pf.f.inf_norm() > p.f_bound()
        || pf.z_f.inf_norm() > p.z_bound()
        || pf.z_g.inf_norm() > p.z_bound()
    {
        return false;
    }
    let x = challenge(&[c_b, &pf.c_alpha, &pf.c1, &pf.c0], p.tau, aux);
    // Shared t1 bindings.
    if key.a1.matvec(&pf.z_f) != c_b.t1.mul_poly(&x).add(&pf.c_alpha.t1) {
        return false;
    }
    if key.a1.matvec(&pf.z_g) != pf.c1.t1.mul_poly(&x).add(&pf.c0.t1) {
        return false;
    }
    // Per-coordinate t2 bindings + the quadratic (public f(f−x)).
    let a2_zf = key.a2.matvec(&pf.z_f);
    let a2_zg = key.a2.matvec(&pf.z_g);
    for i in 0..n {
        if a2_zf.0[i].add(&pf.f.0[i]) != x.mul_ntt(&c_b.t2.0[i]).add(&pf.c_alpha.t2.0[i]) {
            return false;
        }
        let f_ffx = pf.f.0[i].mul_ntt(&pf.f.0[i].sub(&x));
        let rhs = x.mul_ntt(&pf.c1.t2.0[i]).add(&pf.c0.t2.0[i]).sub(&f_ffx);
        if a2_zg.0[i] != rhs {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::ETA;

    fn key() -> RingCommitKey {
        RingCommitKey::production(1, 0xB17B)
    }
    fn commit_bit(key: &RingCommitKey, b: u64, tag: u64) -> (RingCommitment, PolyVec) {
        let mut prg = SplitMix64::new(tag);
        let r = PolyVec::sample_short(key.a1.cols, ETA, &mut prg);
        (commit1(key, &constant(b as i64), &r), r)
    }

    #[test]
    fn completeness_both_bits() {
        let k = key();
        let p = BinRqParams::production();
        for b in [0u8, 1u8] {
            let (c, r) = commit_bit(&k, b as u64, 10 + b as u64);
            let proof = prove_bit_rq(&k, &c, b, &r, &p, b"", 20 + b as u64).expect("prover accepts");
            assert!(verify_bit_rq(&k, &c, &proof, &p, b""), "bit {b} verifies");
        }
    }

    #[test]
    fn soundness_non_bit_rejected() {
        // A commitment to 2 (not a bit): the x² coefficient b²−b = 2 ≠ 0, so the
        // proof cannot verify for the (random) challenge.
        let k = key();
        let p = BinRqParams::production();
        let (c, r) = commit_bit(&k, 2, 99);
        // Attempt to prove it as a bit (best effort; b clamped to a bit input).
        // Prove with the true value path by forging: use b index that fails.
        if let Some(proof) = prove_bit_rq(&k, &c, 1, &r, &p, b"", 77) {
            assert!(!verify_bit_rq(&k, &c, &proof, &p, b""), "value 2 must not verify as a bit");
        }
        if let Some(proof) = prove_bit_rq(&k, &c, 0, &r, &p, b"", 78) {
            assert!(!verify_bit_rq(&k, &c, &proof, &p, b""));
        }
    }

    #[test]
    fn tampered_response_rejected() {
        let k = key();
        let p = BinRqParams::production();
        let (c, r) = commit_bit(&k, 1, 5);
        let mut proof = prove_bit_rq(&k, &c, 1, &r, &p, b"", 5).unwrap();
        proof.z_f.0[0].c[0] = (proof.z_f.0[0].c[0] + 1) % Poly::Q;
        assert!(!verify_bit_rq(&k, &c, &proof, &p, b""));
    }

    // ── Amortized (commit-once) bit-vector proof ─────────────────────────────
    fn bit_vec(key: &RingCommitKey, vals: &[u64], tag: u64) -> (RingCommitment, PolyVec, PolyVec) {
        let mut prg = SplitMix64::new(tag);
        let r = PolyVec::sample_short(key.a1.cols, ETA, &mut prg);
        let msg = PolyVec(vals.iter().map(|&v| constant(v as i64)).collect());
        (key.commit(&msg, &r), msg, r)
    }

    #[test]
    fn amortized_completeness() {
        let n = 16;
        let key = RingCommitKey::production(n, 0xB175);
        let p = BinRqParams::production();
        let bits: Vec<u64> = (0..n).map(|i| (0x9E3Fu64 >> i) & 1).collect();
        let (c, msg, r) = bit_vec(&key, &bits, 1);
        let proof = prove_bits_rq(&key, &c, &msg, &r, &p, b"", 2).expect("prover accepts");
        assert!(verify_bits_rq(&key, &c, &proof, &p, b""), "all-bit vector verifies in ONE proof");
    }

    #[test]
    fn amortized_soundness_non_bit_rejected() {
        let n = 16;
        let key = RingCommitKey::production(n, 0xB175);
        let p = BinRqParams::production();
        let mut bits: Vec<u64> = vec![1; n];
        bits[5] = 2; // NOT a bit
        let (c, msg, r) = bit_vec(&key, &bits, 3);
        if let Some(proof) = prove_bits_rq(&key, &c, &msg, &r, &p, b"", 4) {
            assert!(!verify_bits_rq(&key, &c, &proof, &p, b""), "a non-bit coordinate MUST reject");
        }
    }

    #[test]
    fn amortized_tampered_f_rejected() {
        let n = 8;
        let key = RingCommitKey::production(n, 0xB175);
        let p = BinRqParams::production();
        let bits: Vec<u64> = vec![0, 1, 1, 0, 1, 0, 0, 1];
        let (c, msg, r) = bit_vec(&key, &bits, 5);
        let mut proof = prove_bits_rq(&key, &c, &msg, &r, &p, b"", 6).unwrap();
        proof.f.0[0].c[0] = (proof.f.0[0].c[0] + 1) % Poly::Q;
        assert!(!verify_bits_rq(&key, &c, &proof, &p, b""));
    }

    #[test]
    fn amortized_size_vs_per_bit() {
        use crate::wire::{encode_binary, encode_commitment, encode_polyvec};
        let n = 13; // one range = RANGE_BITS bit-proofs today
        let key = RingCommitKey::production(n, 0xB175);
        let p = BinRqParams::production();
        let bits: Vec<u64> = (0..n).map(|i| (i & 1) as u64).collect();
        let (c, msg, r) = bit_vec(&key, &bits, 7);
        let proof = prove_bits_rq(&key, &c, &msg, &r, &p, b"", 8).unwrap();
        let agg = encode_commitment(&proof.c_alpha).len()
            + encode_commitment(&proof.c1).len()
            + encode_commitment(&proof.c0).len()
            + encode_polyvec(&proof.f).len()
            + encode_polyvec(&proof.z_f).len()
            + encode_polyvec(&proof.z_g).len();
        let bkey = RingCommitKey::production(1, 0xB175);
        let mut prg = SplitMix64::new(9);
        let rr = PolyVec::sample_short(bkey.a1.cols, ETA, &mut prg);
        let cb = commit1(&bkey, &constant(1), &rr);
        let one_bit = encode_binary(&prove_bit_rq(&bkey, &cb, 1, &rr, &p, b"", 10).unwrap()).len();
        println!(
            "AMORT range_bits={n} agg_bytes={agg} per_bit_x{n}={} ratio={:.1}x",
            one_bit * n,
            (one_bit * n) as f64 / agg as f64
        );
    }

    #[test]
    #[ignore = "KNOWN TO FAIL at ℓ=611: rejection-sampling wall — f has ℓ·256 coeffs, \
                per-coeff accept ≈1−τ/mask_bound, so accept ≈0.9997^(611·256)≈1e-20 at \
                mask_bound=2^17 (prove_bits_rq → None). Tier-1 ℓ=13 is fine (accept≈0.37). \
                Cross-range 'one giant bit proof' needs a WIDER mask (bigger proof + tighter \
                soundness margin) or the LaBRADOR path. Kept as a \
                documented negative result; do not un-ignore without widening the mask."]
    fn amortized_tier2_whole_balance_one_proof() {
        // Tier 2: commit ALL of a balance proof's bits (15 carry + 2 outputs ×
        // 16 limbs, ×13 bits ≈ 611) and prove them in ONE proof — the whole
        // bit-validity half of the 52 MB balance proof. Also a completeness test
        // at production width.
        use crate::wire::{encode_commitment, encode_polyvec};
        let n = 611;
        let key = RingCommitKey::production(n, 0xB175);
        let p = BinRqParams::production();
        let bits: Vec<u64> = (0..n).map(|i| ((i * 7 + 1) & 1) as u64).collect();
        let (c, msg, r) = bit_vec(&key, &bits, 11);
        let proof = prove_bits_rq(&key, &c, &msg, &r, &p, b"", 12).expect("prover accepts");
        assert!(verify_bits_rq(&key, &c, &proof, &p, b""), "611-bit vector verifies in ONE proof");
        let agg = encode_commitment(&proof.c_alpha).len()
            + encode_commitment(&proof.c1).len()
            + encode_commitment(&proof.c0).len()
            + encode_polyvec(&proof.f).len()
            + encode_polyvec(&proof.z_f).len()
            + encode_polyvec(&proof.z_g).len();
        println!("AMORT_TIER2 all_bits={n} one_proof_bytes={agg} (bit-validity half; was ~52MB across 611 per-bit proofs)");
    }
}
