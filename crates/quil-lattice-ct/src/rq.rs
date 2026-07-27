//! `R_q = Z_q[X]/(X^d + 1)` — the polynomial ring the production parameters
//! (`d = 256`, `q ≈ 2^28`) live in. This is the first piece of the ring-form
//! port: the reference modules (`commitment`, `sigma`, …) run over plain `Z_q`
//! with tiny illustrative sizes; the production instantiation replaces those
//! scalars with elements of `R_q`, so security amortizes over the `d`
//! coefficients and a single structured ring challenge replaces the 16 rounds.
//!
//! # Multiplication
//!
//! Reference: **schoolbook negacyclic** convolution — `X^d = −1`, so
//! `c_k = Σ_{i+j=k} a_i b_j − Σ_{i+j=k+d} a_i b_j (mod q)`. Obviously correct,
//! `O(d²)`. Production uses the **NTT** (constants below; `q ≡ 1 mod 2d`, so a
//! primitive `2d`-th root of unity exists) for `O(d log d)` — a speedup with
//! identical results, validated against schoolbook.

use crate::params::{MODULUS_Q, RING_DEGREE_D};

// ── NTT constants for q = 68719484929 (≈2^36), d = 256 (Sage-computed) ──────
/// Primitive `2d`-th root of unity `ψ` (`ψ^{2d}=1`, `ψ^d ≡ −1`) — the
/// negacyclic twist for the production NTT.
pub const NTT_PSI: u64 = 44700427896;
/// `ψ^{-1} mod q`.
pub const NTT_PSI_INV: u64 = 23224804001;
/// `d^{-1} mod q` (inverse-NTT scaling).
pub const NTT_D_INV: u64 = 68451049441;

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

    /// Negacyclic multiplication via the **NTT** — `O(d log d)`, identical
    /// result to [`mul`](Self::mul) (validated in tests). This is the hot-path
    /// multiplication the module layer uses at production dimensions.
    pub fn mul_ntt(&self, o: &Poly) -> Poly {
        let ah = ntt::fwd(&self.c);
        let bh = ntt::fwd(&o.c);
        let ch = ntt::pointwise(&ah, &bh);
        Poly { c: ntt::inv(&ch) }
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

/// Negacyclic NTT over `R_q` (`q ≡ 1 mod 2d`). Twisted transform: pre-scale by
/// `ψ^j`, run a radix-2 `d`-point NTT with `ω = ψ²`, pointwise-multiply,
/// inverse, post-scale by `ψ^{-j}` and `d^{-1}`.
///
/// # Optimization
///
/// The inner butterfly runs in the **Montgomery domain** (`q ≈ 2^28 < 2^32`, so
/// `R = 2^32` and every product fits `u64` after a division-free REDC), with
/// **branchless** modular add/sub and **precomputed** twist/twiddle tables in a
/// [`OnceLock`]. This removes both the per-multiply `u128 % q` division and the
/// per-call `modpow` twiddle recomputation of the reference. Result is identical
/// to schoolbook (`ntt_multiplication_matches_schoolbook`).
mod ntt {
    use super::{Poly, NTT_D_INV, NTT_PSI, NTT_PSI_INV};
    use std::sync::OnceLock;

    const Q: u64 = Poly::Q;
    const N: usize = Poly::D;
    const STAGES: usize = N.trailing_zeros() as usize; // log2(N) = 8

    /// Precomputed Montgomery context + twist/twiddle tables (built once).
    struct Ctx {
        nprime: u64,          // −q^{-1} mod 2^64 (REDC constant; q≈2^36 needs R=2^64)
        psi_r2: [u64; N],     // ψ^j · R² mod q (fwd pre-scale: normal → Montgomery(c·ψ^j))
        psi_inv_d: [u64; N],  // ψ^{-j} · d^{-1} mod q (inv post-scale: Montgomery → normal)
        tw_fwd: [u64; N - 1], // all fwd twiddles ω^{n/len·j}, Montgomery, stage s at offset 2^s−1
        tw_inv: [u64; N - 1], // all inv twiddles, same layout
    }

    static CTX: OnceLock<Ctx> = OnceLock::new();
    fn ctx() -> &'static Ctx {
        CTX.get_or_init(build)
    }

    // ── Montgomery arithmetic (R = 2^52; q≈2^36 so a·b < 2^72 needs u128). R=2^52
    //    (not 2^64) so the scalar path shares the domain with the AVX-512 IFMA
    //    kernel, whose madd52 multiply-accumulate is 52-bit. ────────────────────
    const R_BITS: u32 = 52;
    const MASK52: u64 = (1u64 << 52) - 1;
    #[inline(always)]
    fn redc(t: u128, nprime: u64) -> u64 {
        // t < q·R. m = (t mod R)·n' mod R; then (t + m·q)/R < 2q.
        let m = ((t as u64) & MASK52).wrapping_mul(nprime) & MASK52;
        let t2 = ((t + (m as u128) * (Q as u128)) >> R_BITS) as u64;
        if t2 >= Q {
            t2 - Q
        } else {
            t2
        }
    }
    #[inline(always)]
    fn montmul(a: u64, b: u64, nprime: u64) -> u64 {
        redc((a as u128) * (b as u128), nprime)
    }
    #[inline(always)]
    fn modadd(a: u64, b: u64) -> u64 {
        let s = a + b;
        if s >= Q {
            s - Q
        } else {
            s
        }
    }
    #[inline(always)]
    fn modsub(a: u64, b: u64) -> u64 {
        let s = a + Q - b;
        if s >= Q {
            s - Q
        } else {
            s
        }
    }

    // ── One-time table construction (u128 math, runs once) ──────────────────
    fn pow_mod(mut b: u128, mut e: u128, q: u128) -> u128 {
        let mut r = 1u128;
        b %= q;
        while e > 0 {
            if e & 1 == 1 {
                r = r * b % q;
            }
            b = b * b % q;
            e >>= 1;
        }
        r
    }

    fn build() -> Ctx {
        let q = Q as u128;
        // n' = −q^{-1} mod 2^52 via Newton's iteration (q odd; 6 doublings ⇒ 64 bits ⊃ 52).
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(Q.wrapping_mul(inv)));
        }
        let nprime = inv.wrapping_neg() & MASK52; // q·n' ≡ −1 mod 2^52
        let r = (1u128 << R_BITS) % q; // R mod q
        let r2 = r * r % q; // R² mod q
        let to_mont = |x: u128| -> u64 { (x * r % q) as u64 };

        // ψ^j and its inverse ladders.
        let mut psi_r2 = [0u64; N];
        let mut psi_inv_d = [0u64; N];
        let mut psi_j = 1u128; // ψ^j
        let mut psi_inv_j = 1u128; // ψ^{-j}
        let d_inv = NTT_D_INV as u128;
        for j in 0..N {
            psi_r2[j] = (psi_j * r2 % q) as u64; // ψ^j · R² (montmul(c, ·) = mont(c·ψ^j))
            psi_inv_d[j] = (psi_inv_j * d_inv % q) as u64; // ψ^{-j} · d^{-1} (montmul(mont, ·) = normal)
            psi_j = psi_j * NTT_PSI as u128 % q;
            psi_inv_j = psi_inv_j * NTT_PSI_INV as u128 % q;
        }

        // Full twiddle tables: stage s (len = 2^(s+1)) holds ω^{(n/len)·j} for
        // j in 0..2^s, laid out flat at offset 2^s−1. No per-butterfly chain.
        let omega = (NTT_PSI as u128 * NTT_PSI as u128) % q;
        let omega_inv = (NTT_PSI_INV as u128 * NTT_PSI_INV as u128) % q;
        let mut tw_fwd = [0u64; N - 1];
        let mut tw_inv = [0u64; N - 1];
        for s in 0..STAGES {
            let len = 1u128 << (s + 1);
            let exp = (N as u128) / len;
            let wlen_f = pow_mod(omega, exp, q);
            let wlen_i = pow_mod(omega_inv, exp, q);
            let base = (1usize << s) - 1;
            let mut wf = 1u128;
            let mut wi = 1u128;
            for j in 0..(1usize << s) {
                tw_fwd[base + j] = to_mont(wf);
                tw_inv[base + j] = to_mont(wi);
                wf = wf * wlen_f % q;
                wi = wi * wlen_i % q;
            }
        }

        Ctx { nprime, psi_r2, psi_inv_d, tw_fwd, tw_inv }
    }

    fn bit_reverse(a: &mut [u64]) {
        let n = a.len();
        let mut j = 0usize;
        for i in 1..n {
            let mut bit = n >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;
            if i < j {
                a.swap(i, j);
            }
        }
    }

    /// One radix-2 butterfly block. Scalar `u128` Montgomery, with an **AVX-512
    /// IFMA** 8-lane path on capable x86 (Ice Lake+/Zen4+ — "most nodes"):
    /// `_mm512_madd52lo/hi_epu64` give 52-bit multiply-accumulate, and `q<2^52`
    /// fits, so the whole `R=2^52` Montgomery vectorizes 8-wide.
    ///
    /// **NEON (Opt B3, reconsidered on throughput — still no good path at `q≈2^36`):**
    /// * 2-limb schoolbook Montgomery: ~15 instr/result, dependency-chain-bound —
    /// a wash-to-loss vs native `u128` even accounting for 2-lane throughput.
    /// * `vqdmulh` high-multiply (Dilithium NEON): signed-32-bit moduli only
    /// (`q<2^23`) — doesn't fit.
    /// * `f64` FP-NTT (52-bit mantissa): needs `q<2^25` (product `<2^50` fits the
    /// mantissa); at `q≈2^36` the product `<2^72` overflows it — doesn't fit.
    /// The soundness floor (`q≥2^36`) and a NEON-friendly modulus (`q<2^25`) are
    /// mutually exclusive, so native `u128` is the right ARM path. IFMA is the win,
    /// and it's x86-only.
    #[inline]
    fn butterfly(a: &mut [u64], i: usize, half: usize, tw: &[u64], base: usize, nprime: u64) {
        #[cfg(target_arch = "x86_64")]
        {
            if half >= 8 && std::is_x86_feature_detected!("avx512ifma") {
                // SAFETY: avx512ifma verified present; indices in-bounds; half≥8 ⇒
                // multiple of 8 (power-of-two), so 8-lane steps tile the block.
                unsafe { ifma::butterfly(a, i, half, tw, base, nprime) };
                return;
            }
        }
        for j in 0..half {
            let u = a[i + j];
            let v = montmul(a[i + j + half], tw[base + j], nprime);
            a[i + j] = modadd(u, v);
            a[i + j + half] = modsub(u, v);
        }
    }

    /// AVX-512 IFMA kernels (`R=2^52` Montgomery, 8-lane). Cross-compile-verified;
    /// the `ntt_multiplication_matches_schoolbook` test validates it at runtime on
    /// AVX-512-IFMA x86 (native validation pending such hardware — this host is
    /// aarch64).
    #[cfg(target_arch = "x86_64")]
    mod ifma {
        use super::Q;
        use std::arch::x86_64::*;

        /// 8-lane `R=2^52` Montgomery multiply `REDC(a·b)` for `a, b < q < 2^36`.
        #[inline]
        #[target_feature(enable = "avx512ifma,avx512f")]
        unsafe fn montmul_x8(a: __m512i, b: __m512i, np: __m512i, q: __m512i) -> __m512i {
            let z = _mm512_setzero_si512();
            let p_lo = _mm512_madd52lo_epu64(z, a, b); // a·b mod 2^52
            let p_hi = _mm512_madd52hi_epu64(z, a, b); // a·b >> 52
            let m = _mm512_madd52lo_epu64(z, p_lo, np); // (p_lo·n') mod 2^52
            let mq_lo = _mm512_madd52lo_epu64(z, m, q); // (m·q) mod 2^52
            let mq_hi = _mm512_madd52hi_epu64(z, m, q); // (m·q) >> 52
            // carry = (p_lo + mq_lo) >> 52 (each < 2^52 ⇒ sum < 2^53).
            let carry = _mm512_srli_epi64::<52>(_mm512_add_epi64(p_lo, mq_lo));
            let t = _mm512_add_epi64(_mm512_add_epi64(p_hi, mq_hi), carry); // < 2q
            let ge = _mm512_cmpge_epu64_mask(t, q);
            _mm512_mask_blend_epi64(ge, t, _mm512_sub_epi64(t, q)) // conditional − q
        }

        #[inline]
        #[target_feature(enable = "avx512ifma,avx512f")]
        unsafe fn cond_sub(x: __m512i, q: __m512i) -> __m512i {
            let ge = _mm512_cmpge_epu64_mask(x, q);
            _mm512_mask_blend_epi64(ge, x, _mm512_sub_epi64(x, q))
        }

        #[target_feature(enable = "avx512ifma,avx512f")]
        pub(super) unsafe fn butterfly(a: &mut [u64], i: usize, half: usize, tw: &[u64], base: usize, nprime: u64) {
            let np = _mm512_set1_epi64(nprime as i64);
            let q = _mm512_set1_epi64(Q as i64);
            let mut j = 0;
            while j < half {
                let bh = _mm512_loadu_si512(a.as_ptr().add(i + j + half) as *const _);
                let tw8 = _mm512_loadu_si512(tw.as_ptr().add(base + j) as *const _);
                let v = montmul_x8(bh, tw8, np, q);
                let u = _mm512_loadu_si512(a.as_ptr().add(i + j) as *const _);
                let add = cond_sub(_mm512_add_epi64(u, v), q); // (u+v) mod q
                let sub = cond_sub(_mm512_sub_epi64(_mm512_add_epi64(u, q), v), q); // (u+q−v) mod q
                _mm512_storeu_si512(a.as_mut_ptr().add(i + j) as *mut _, add);
                _mm512_storeu_si512(a.as_mut_ptr().add(i + j + half) as *mut _, sub);
                j += 8;
            }
        }

        #[target_feature(enable = "avx512ifma,avx512f")]
        pub(super) unsafe fn montmul_slice(out: &mut [u64], a: &[u64], b: &[u64], nprime: u64) {
            let np = _mm512_set1_epi64(nprime as i64);
            let q = _mm512_set1_epi64(Q as i64);
            let n = out.len();
            let mut k = 0;
            while k + 8 <= n {
                let av = _mm512_loadu_si512(a.as_ptr().add(k) as *const _);
                let bv = _mm512_loadu_si512(b.as_ptr().add(k) as *const _);
                _mm512_storeu_si512(out.as_mut_ptr().add(k) as *mut _, montmul_x8(av, bv, np, q));
                k += 8;
            }
            while k < n {
                out[k] = super::montmul(a[k], b[k], nprime);
                k += 1;
            }
        }
    }

    /// In-place radix-2 Cooley-Tukey NTT in the Montgomery domain, using the
    /// fully precomputed flat twiddle table (one `montmul` per butterfly, no
    /// twiddle-accumulation dependency chain).
    fn ntt_inplace(a: &mut [u64], tw: &[u64; N - 1], nprime: u64) {
        let n = a.len();
        bit_reverse(a);
        let mut len = 2;
        let mut s = 0;
        while len <= n {
            let base = (1usize << s) - 1;
            let half = len / 2;
            let mut i = 0;
            while i < n {
                butterfly(a, i, half, tw, base, nprime);
                i += len;
            }
            len <<= 1;
            s += 1;
        }
    }


    /// Forward negacyclic transform (returns values in the Montgomery domain).
    pub(super) fn fwd(c: &[u64]) -> Vec<u64> {
        let cx = ctx();
        // b[j] = montmul(c[j], ψ^j·R²) = Montgomery(c[j]·ψ^j).
        let mut b: Vec<u64> =
            c.iter().enumerate().map(|(j, &cj)| montmul(cj, cx.psi_r2[j], cx.nprime)).collect();
        ntt_inplace(&mut b, &cx.tw_fwd, cx.nprime);
        b
    }

    /// Pointwise product of two Montgomery-domain spectra (stays Montgomery).
    pub(super) fn pointwise(ah: &[u64], bh: &[u64]) -> Vec<u64> {
        let np = ctx().nprime;
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx512ifma") {
                let mut out = vec![0u64; ah.len()];
                // SAFETY: avx512ifma present; slices length N; kernel handles the tail.
                unsafe { ifma::montmul_slice(&mut out, ah, bh, np) };
                return out;
            }
        }
        ah.iter().zip(bh).map(|(&x, &y)| montmul(x, y, np)).collect()
    }

    /// Inverse negacyclic transform (Montgomery input → normal coefficients).
    pub(super) fn inv(ah: &[u64]) -> Vec<u64> {
        let cx = ctx();
        let mut c = ah.to_vec();
        ntt_inplace(&mut c, &cx.tw_inv, cx.nprime);
        // c[j] = montmul(Montgomery(v), ψ^{-j}·d^{-1}) = v·ψ^{-j}·d^{-1} (normal).
        for (j, cj) in c.iter_mut().enumerate() {
            *cj = montmul(*cj, cx.psi_inv_d[j], cx.nprime);
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_constants_are_consistent() {
        // ψ·ψ^{-1} ≡ 1, and d·d^{-1} ≡ 1 (mod q). (Sage already checked ψ^d≡−1.)
        let q = Poly::Q as u128;
        assert_eq!((NTT_PSI as u128 * NTT_PSI_INV as u128) % q, 1);
        assert_eq!((Poly::D as u128 * NTT_D_INV as u128) % q, 1);
    }

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

    #[test]
    fn challenge_differences_are_invertible() {
        // the special-soundness extractor of sigma_rq/prod_zero needs the
        // challenge DIFFERENCE (c − c') invertible in R_q. c is a weight-τ ternary
        // poly (SampleInBall). An element is invertible iff all its NTT slots are
        // nonzero. Empirically: over many random weight-τ challenge pairs, every
        // difference is invertible. (q splits completely — X^256+1 factors into
        // 256 linear terms — so a nonzero low-degree element vanishes at a slot
        // only with negligible probability; τ=39 differences never do here.)
        use crate::arith::SplitMix64;
        let tau = crate::params::CHALLENGE_WEIGHT_TAU;
        let mut prg = SplitMix64::new(0x1_C0DE);
        let sample = |prg: &mut SplitMix64| -> Poly {
            // τ signed units at random positions (à la SampleInBall).
            let mut c = vec![0i64; Poly::D];
            let mut placed = 0;
            while placed < tau {
                let idx = (prg.next_u64() as usize) % Poly::D;
                if c[idx] == 0 {
                    c[idx] = if prg.next_u64() & 1 == 1 { 1 } else { -1 };
                    placed += 1;
                }
            }
            Poly::from_signed(&c)
        };
        let (mut min_nz, mut trials) = (Poly::D, 0);
        for _ in 0..500 {
            let a = sample(&mut prg);
            let b = sample(&mut prg);
            if a == b {
                continue;
            }
            trials += 1;
            let diff = a.sub(&b);
            let slots = ntt::fwd(&diff.c); // NTT (Montgomery domain; 0 stays 0)
            let nz = slots.iter().filter(|&&s| s != 0).count();
            min_nz = min_nz.min(nz);
            assert_eq!(nz, Poly::D, "c−c' must have all 256 NTT slots nonzero (invertible)");
        }
        assert!(trials > 400, "enough distinct pairs");
        assert_eq!(min_nz, Poly::D, "every challenge difference invertible ({trials} pairs)");
    }

    #[test]
    fn ntt_multiplication_matches_schoolbook() {
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
