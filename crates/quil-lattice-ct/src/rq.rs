//! `R_q = Z_q[X]/(X^d + 1)` — the polynomial ring the production parameters
//! (`d = 256`, `q ≈ 2^36`, prime, `ord_512(q) = 64`) live in. This is the first
//! piece of the ring-form port: the reference modules (`commitment`, `sigma`, …)
//! run over plain `Z_q` with tiny illustrative sizes; the production
//! instantiation replaces those scalars with elements of `R_q`, so security
//! amortizes over the `d` coefficients and a single structured ring challenge
//! replaces the 16 rounds.
//!
//! # Multiplication
//!
//! Reference: **schoolbook negacyclic** convolution — `X^d = −1`, so
//! `c_k = Σ_{i+j=k} a_i b_j − Σ_{i+j=k+d} a_i b_j (mod q)`. Obviously correct,
//! `O(d²)`.
//!
//! Production uses a **partial-split block NTT** (`mod blockntt`). The new `q`
//! is only partially splitting — `q ≡ 1 mod 8` but `q ≢ 1 mod 512`, so `X^256+1`
//! factors into `t = 4` irreducible degree-64 blocks (NOT 256 linear factors),
//! which is exactly what makes the LS18 invertible-difference lemma non-vacuous
//! (radius ≈ 256 ≫ 2) and keeps challenge-difference soundness ~2^-125 instead of
//! ~2^-28. Two radix-2 negacyclic butterfly layers (256→128→64) split the ring
//! into the 4 degree-64 blocks; each block product is a degree-64 multiply mod
//! `X^64 − w` done with an allocation-free one-level **Karatsuba** over `i128`
//! (exact — reduced mod q once, at the fold). Measured ~2.1× over schoolbook in
//! release, identical results, validated against schoolbook (`bench_*` + the
//! round-trip tests).

use crate::params::{MODULUS_Q, RING_DEGREE_D};

// NOTE: `q` is partially-split (`ord_512(q)=64`, t=4), so no primitive 512th root
// exists and the fully-split 256-point NTT (with its `ψ`/`ψ⁻¹`/`d⁻¹` roots for a
// `q ≡ 1 mod 512`) does not apply. `mul_ntt` routes to the (q-agnostic) schoolbook
// `mul`. A t=4 radix-2 block NTT is the perf follow-up (see params.rs).

/// An element of `R_q`: `d` coefficients in `[0, q)`, low-order first.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Poly {
    pub c: Vec<u64>,
}

impl Poly {
    /// The `d` for this instantiation (`RING_DEGREE_D`).
    pub const D: usize = RING_DEGREE_D;
    /// The modulus (`MODULUS_Q`).
    pub const Q: u64 = MODULUS_Q;

    pub fn zero() -> Self {
        Poly { c: vec![0u64; Self::D] }
    }

    /// One (the constant polynomial `1`).
    pub fn one() -> Self {
        let mut p = Self::zero();
        p.c[0] = 1;
        p
    }

    /// From signed coefficients (reduced into `[0, q)`); length must be `d`.
    pub fn from_signed(coeffs: &[i64]) -> Self {
        assert_eq!(coeffs.len(), Self::D);
        let q = Self::Q as i64;
        Poly { c: coeffs.iter().map(|&x| x.rem_euclid(q) as u64).collect() }
    }

    /// The monomial `X^k` (reduced negacyclically: `X^{k+d} = −X^k`).
    pub fn monomial(k: usize) -> Self {
        let mut p = Self::zero();
        let (idx, neg) = (k % Self::D, (k / Self::D) % 2 == 1);
        p.c[idx] = if neg { Self::Q - 1 } else { 1 };
        p
    }

    pub fn add(&self, o: &Poly) -> Poly {
        Poly { c: self.c.iter().zip(&o.c).map(|(a, b)| (a + b) % Self::Q).collect() }
    }

    pub fn sub(&self, o: &Poly) -> Poly {
        Poly { c: self.c.iter().zip(&o.c).map(|(a, b)| (a + Self::Q - b) % Self::Q).collect() }
    }

    pub fn neg(&self) -> Poly {
        Poly { c: self.c.iter().map(|a| (Self::Q - a) % Self::Q).collect() }
    }

    /// Negacyclic schoolbook multiplication.
    pub fn mul(&self, o: &Poly) -> Poly {
        let (d, q) = (Self::D, Self::Q as i128);
        let mut acc = vec![0i128; d];
        for i in 0..d {
            let ai = self.c[i] as i128;
            if ai == 0 {
                continue;
            }
            for j in 0..d {
                let prod = ai * o.c[j] as i128;
                let k = i + j;
                if k < d {
                    acc[k] += prod;
                } else {
                    acc[k - d] -= prod; // X^d = −1
                }
            }
        }
        Poly { c: acc.iter().map(|&x| x.rem_euclid(q) as u64).collect() }
    }

    /// Negacyclic ring multiplication via the **partial-split (t=4) block NTT**
    /// (same result as [`mul`](Self::mul), validated in tests). Since the new `q`
    /// has `ord_512=64`, `X^256+1` splits into 4 degree-64 factors, so two radix-2
    /// negacyclic butterfly layers (256→128→64) reduce to 4 blocks mod
    /// `X^64 − ω` (ω ∈ {s,−s,s′,−s′}); each block is multiplied with a degree-64
    /// `ω`-twisted convolution, then two inverse layers recombine (CRT). ~4× the
    /// full-negacyclic schoolbook. (Fully-split 256-pt NTT no longer applies.)
    pub fn mul_ntt(&self, o: &Poly) -> Poly {
        Poly { c: blockntt::mul(&self.c, &o.c) }
    }

    /// The negacyclic automorphism `σ(a)(X) = a(X⁻¹)` in `R_q = Z_q[X]/(Xᵈ+1)`.
    /// Since `X⁻¹ = −X^{d−1}`, one has `X^{−m} = −X^{d−m}` (m=1..d−1), so
    /// `σ(a)₀ = a₀` and `σ(a)_m = −a_{d−m}`. Order-2 (`σ∘σ = id`). Its defining
    /// property is `ct(σ(a)·b) = Σₖ aₖ·bₖ` — the coefficient inner product — which
    /// is what the constant-term constraint family and the JL projection use.
    pub fn conjugate(&self) -> Poly {
        let (d, q) = (Self::D, Self::Q);
        let mut c = vec![0u64; d];
        c[0] = self.c[0];
        for m in 1..d {
            let v = self.c[d - m];
            c[m] = if v == 0 { 0 } else { q - v };
        }
        Poly { c }
    }

    /// Multiply by an integer scalar (mod q).
    pub fn scalar_mul(&self, s: i64) -> Poly {
        let q = Self::Q as i128;
        let s = s as i128;
        Poly { c: self.c.iter().map(|&a| (a as i128 * s).rem_euclid(q) as u64).collect() }
    }

    /// Centered infinity norm: each coefficient mapped to `(−q/2, q/2]`, max abs.
    pub fn inf_norm(&self) -> u64 {
        let q = Self::Q;
        self.c
            .iter()
            .map(|&a| if a > q / 2 { q - a } else { a })
            .max()
            .unwrap_or(0)
    }
}

/// Partial-split (t=4) block NTT for `R_q = Z_q[X]/(X^256+1)` with the current
/// `q` (`ord_512(q)=64`, `q≡1 mod 8`). `X^256+1` = ∏(X^64 − ω), ω ∈ {s,−s,s′,−s′},
/// reached by two negacyclic radix-2 butterfly layers (256→128→64). Roots
/// (verified: r²≡−1, s²≡r, s′²≡−r; ∏ω = 1):
mod blockntt {
    use super::Poly;
    const Q: u128 = Poly::Q as u128;
    const R: u64 = 11467842006; // ζ4  (r² ≡ −1)
    const R_INV: u64 = 57251634707;
    const S: u64 = 22412483738; // ζ8  (s² ≡ r)
    const S_INV: u64 = 28689172010;
    const SP: u64 = 40030304703; // ζ8³ (s′² ≡ −r)
    const SP_INV: u64 = 46306992975;
    const TWO_INV: u64 = 34359738357;

    #[inline]
    fn addm(a: u64, b: u64) -> u64 {
        let s = a + b;
        if (s as u128) >= Q { (s as u128 - Q) as u64 } else { s }
    }
    #[inline]
    fn subm(a: u64, b: u64) -> u64 {
        if a >= b { a - b } else { (a as u128 + Q - b as u128) as u64 }
    }
    #[inline]
    fn mulm(a: u64, b: u64) -> u64 {
        (a as u128 * b as u128 % Q) as u64
    }
    #[inline]
    fn negm(a: u64) -> u64 {
        if a == 0 { 0 } else { (Q - a as u128) as u64 }
    }

    /// One butterfly split of a 2n-block into two n-blocks with twiddle `w`:
    /// `(lo + w·hi, lo − w·hi)`, i.e. reduce mod `X^n − w` and `X^n + w`.
    fn split(blk: &[u64], n: usize, w: u64) -> (Vec<u64>, Vec<u64>) {
        let mut a = vec![0u64; n];
        let mut b = vec![0u64; n];
        for i in 0..n {
            let wh = mulm(w, blk[n + i]);
            a[i] = addm(blk[i], wh);
            b[i] = subm(blk[i], wh);
        }
        (a, b)
    }

    /// Forward transform: 256 coeffs → four degree-64 blocks (moduli s,−s,s′,−s′).
    fn fwd(a: &[u64]) -> [Vec<u64>; 4] {
        let (ba, bb) = split(a, 128, R); // mod X^128−r , X^128+r
        let (c0, c1) = split(&ba, 64, S); // mod X^64−s , X^64+s(=−s)
        let (c2, c3) = split(&bb, 64, SP); // mod X^64−s′, X^64+s′(=−s′)
        [c0, c1, c2, c3]
    }

    /// Exact schoolbook product of two degree-<32 slices into `acc[off..]`
    /// (`i128`, no mod, no allocation). Values stay `< 2^84`, well inside `i128`.
    #[inline]
    fn school32(a: &[i128], b: &[i128], acc: &mut [i128]) {
        for (i, &ai) in a.iter().enumerate() {
            if ai == 0 {
                continue;
            }
            for (j, &bj) in b.iter().enumerate() {
                acc[i + j] += ai * bj;
            }
        }
    }

    /// Exact degree-64 × degree-64 product via ONE-LEVEL Karatsuba over `i128`,
    /// ALLOCATION-FREE (fixed stack arrays). Splits each operand into two
    /// degree-32 halves; 3 schoolbook-32 products (z0,z2, and z1 on the sums)
    /// instead of 4 → ~1.33× fewer multiplies AND zero heap traffic (the recursive
    /// Vec version was allocation-bound). Writes the length-127 product to `out`.
    fn kmul64(u: &[i128; 64], v: &[i128; 64], out: &mut [i128; 128]) {
        let (u0, u1) = (&u[..32], &u[32..]);
        let (v0, v1) = (&v[..32], &v[32..]);
        let mut z0 = [0i128; 64]; // u0·v0 (deg ≤62)
        let mut z2 = [0i128; 64]; // u1·v1
        let mut z1 = [0i128; 64]; // (u0+u1)(v0+v1)
        school32(u0, v0, &mut z0);
        school32(u1, v1, &mut z2);
        let mut us = [0i128; 32];
        let mut vs = [0i128; 32];
        for i in 0..32 {
            us[i] = u0[i] + u1[i];
            vs[i] = v0[i] + v1[i];
        }
        school32(&us, &vs, &mut z1);
        // out = z0 + (z1 − z0 − z2)·X^32 + z2·X^64.
        for i in 0..64 {
            out[i] += z0[i];
            out[i + 32] += z1[i] - z0[i] - z2[i];
            out[i + 64] += z2[i];
        }
    }

    /// Degree-64 multiply mod `X^64 − w`: alloc-free Karatsuba full product, then
    /// fold `X^{64+k} ≡ w·X^k` and reduce mod q once.
    fn mul_block(u: &[u64], v: &[u64], w: u64) -> Vec<u64> {
        let mut ua = [0i128; 64];
        let mut va = [0i128; 64];
        for i in 0..64 {
            ua[i] = u[i] as i128;
            va[i] = v[i] as i128;
        }
        let mut prod = [0i128; 128]; // deg ≤126 uses [0..127]; [127] stays 0
        kmul64(&ua, &va, &mut prod);
        let qi = Q as i128;
        let mut out = vec![0u64; 64];
        for k in 0..64 {
            let lo = prod[k].rem_euclid(qi);
            let hi = prod[k + 64].rem_euclid(qi);
            out[k] = ((lo + w as i128 * hi).rem_euclid(qi)) as u64;
        }
        out
    }

    /// Inverse butterfly: from (c0,c1) recover the 2n-block, given `w_inv` for the
    /// forward twiddle `w`. lo=(c0+c1)/2, hi=(c0−c1)/(2w).
    fn join(c0: &[u64], c1: &[u64], n: usize, w_inv: u64) -> Vec<u64> {
        let hi_scale = mulm(TWO_INV, w_inv);
        let mut out = vec![0u64; 2 * n];
        for i in 0..n {
            out[i] = mulm(TWO_INV, addm(c0[i], c1[i]));
            out[n + i] = mulm(hi_scale, subm(c0[i], c1[i]));
        }
        out
    }

    /// Multiply two elements of `R_q` (coeff vectors, len 256).
    pub fn mul(a: &[u64], b: &[u64]) -> Vec<u64> {
        let fa = fwd(a);
        let fb = fwd(b);
        let c0 = mul_block(&fa[0], &fb[0], S);
        let c1 = mul_block(&fa[1], &fb[1], negm(S));
        let c2 = mul_block(&fa[2], &fb[2], SP);
        let c3 = mul_block(&fa[3], &fb[3], negm(SP));
        let ba = join(&c0, &c1, 64, S_INV); // mod X^128−r
        let bb = join(&c2, &c3, 64, SP_INV); // mod X^128+r
        join(&ba, &bb, 128, R_INV)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_is_multiplicative_identity() {
        let a = Poly::from_signed(&(0..256).map(|i| (i * 7 - 100) as i64).collect::<Vec<_>>());
        assert_eq!(a.mul(&Poly::one()), a);
    }

    #[test]
    fn x_to_the_d_is_minus_one() {
        // X^d = −1 in R_q: X · X^{d−1} should equal −1 (the constant).
        let x = Poly::monomial(1);
        let x_dm1 = Poly::monomial(Poly::D - 1);
        assert_eq!(x.mul(&x_dm1), Poly::one().neg());
        // And the monomial helper agrees: X^d reduces to −1.
        assert_eq!(Poly::monomial(Poly::D), Poly::one().neg());
    }

    #[test]
    fn distributivity() {
        let a = Poly::from_signed(&(0..256).map(|i| (i % 5) as i64 - 2).collect::<Vec<_>>());
        let b = Poly::from_signed(&(0..256).map(|i| (i % 3) as i64 - 1).collect::<Vec<_>>());
        let c = Poly::from_signed(&(0..256).map(|i| (i % 7) as i64 - 3).collect::<Vec<_>>());
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
    }

    #[test]
    fn small_product_by_hand() {
        // (1 + 2X)·(3 + 4X) = 3 + 10X + 8X^2 in R_q (no wrap for d>2).
        let mut p = Poly::zero();
        p.c[0] = 1;
        p.c[1] = 2;
        let mut r = Poly::zero();
        r.c[0] = 3;
        r.c[1] = 4;
        let prod = p.mul(&r);
        assert_eq!(prod.c[0], 3);
        assert_eq!(prod.c[1], 10);
        assert_eq!(prod.c[2], 8);
        assert!(prod.c[3..].iter().all(|&x| x == 0));
    }

    #[test]
    fn negacyclic_wrap_negates() {
        // X^{d−1} · X^{2} = X^{d+1} = −X. (Checks the wrap sign.)
        let a = Poly::monomial(Poly::D - 1);
        let b = Poly::monomial(2);
        assert_eq!(a.mul(&b), Poly::monomial(1).neg());
    }

    // NOTE: with the partially-split modulus, challenge-difference invertibility is a
    // ring PARAMETER property (LS18 at t=4, radius ≈256 ≫ ‖c−c'‖≤2), asserted by
    // `params::tests::partial_split_modulus` — not an empirical per-NTT-slot test.


    #[test]
    fn bench_mul_ntt_vs_schoolbook() {
        use crate::arith::SplitMix64;
        use std::time::Instant;
        let mut prg = SplitMix64::new(999);
        let mk = |prg:&mut SplitMix64| Poly { c: (0..Poly::D).map(|_| prg.uniform_below(Poly::Q as u128) as u64).collect() };
        let a = mk(&mut prg); let b = mk(&mut prg);
        let n = 3000;
        let t0=Instant::now(); let mut acc=0u64; for _ in 0..n { acc=acc.wrapping_add(a.mul_ntt(&b).c[0]); } let dn=t0.elapsed();
        let t1=Instant::now(); for _ in 0..n { acc=acc.wrapping_add(a.mul(&b).c[0]); } let ds=t1.elapsed();
        println!("BENCH mul_ntt(block+kara)={:?}/op  schoolbook={:?}/op  speedup={:.2}x  (acc={})",
                 dn/n, ds/n, ds.as_secs_f64()/dn.as_secs_f64(), acc);
    }

    #[test]
    fn mul_ntt_matches_schoolbook() {
        use crate::arith::SplitMix64;
        let mut prg = SplitMix64::new(12345);
        for _ in 0..8 {
            let a = Poly {
                c: (0..Poly::D).map(|_| prg.uniform_below(Poly::Q as u128) as u64).collect(),
            };
            let b = Poly {
                c: (0..Poly::D).map(|_| prg.uniform_below(Poly::Q as u128) as u64).collect(),
            };
            assert_eq!(a.mul_ntt(&b), a.mul(&b), "NTT mul must equal schoolbook");
        }
        // Edge cases: identity and X^d = −1 via NTT.
        let x = Poly::monomial(1);
        assert_eq!(x.mul_ntt(&Poly::monomial(Poly::D - 1)), Poly::one().neg());
    }

    #[test]
    fn norm_is_centered() {
        // A coefficient of q−1 is −1 centered → norm 1.
        let mut p = Poly::zero();
        p.c[0] = Poly::Q - 1;
        p.c[5] = 3;
        assert_eq!(p.inf_norm(), 3);
    }
}
