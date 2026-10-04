// Copyright 2018 Chia Network Inc and POA Networks Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![deny(unsafe_code)]
use super::ClassGroup;
use super::gmp::mpz::Mpz;
use super::gmp::mpz::ProbabPrimeResult::NotPrime;
use num_traits::{One, Zero};
use std::{
    borrow::Borrow,
    cell::RefCell,
    mem::swap,
    ops::{Mul, MulAssign},
};
use std::convert::TryInto;

mod congruence;
pub(super) mod ffi;

#[derive(PartialEq, PartialOrd, Eq, Ord, Hash, Debug, Clone)]
pub struct GmpClassGroup {
    a: Mpz,
    b: Mpz,
    c: Mpz,
    discriminant: Mpz,
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Hash, Debug)]
pub struct Ctx {
    negative_a: Mpz,
    r: Mpz,
    denom: Mpz,
    old_a: Mpz,
    old_b: Mpz,
    ra: Mpz,
    s: Mpz,
    x: Mpz,
    congruence_context: congruence::CongruenceContext,
    h: Mpz,
    w: Mpz,
    m: Mpz,
    u: Mpz,
    a: Mpz,
    l: Mpz,
    j: Mpz,
    b: Mpz,
    k: Mpz,
    t: Mpz,
    mu: Mpz,
    v: Mpz,
    sigma: Mpz,
    lambda: Mpz,
}

thread_local! {
    static CTX: RefCell<Ctx> = Default::default();
}

impl GmpClassGroup {
    pub fn into_raw(self) -> (Mpz, Mpz) {
        (self.a, self.b)
    }

    /// True if the form's `a` coefficient is zero — a DEGENERATE, invalid form
    /// that a real proof never contains. Callers decoding untrusted proof bytes
    /// must reject such a form BEFORE any arithmetic: `pow`/reduce divide by
    /// `2·a` in raw GMP FFI, and `2·a == 0` is a C-level divide-by-zero (SIGFPE
    /// abort) that `catch_unwind` cannot trap.
    pub fn a_is_zero(&self) -> bool {
        self.a == Mpz::from(0u64)
    }

    fn inner_multiply(&mut self, rhs: &Self, ctx: &mut Ctx) {
        self.assert_valid();
        rhs.assert_valid();

        self.inner_compose(rhs, ctx);
        self.inner_reduce_fast(ctx);
    }

    fn inner_reduce_fast(&mut self, ctx: &mut Ctx) {
        ffi::gmp_reduce(&mut self.a, &mut self.b, &mut self.c);
        // The native reducer permits b == -a. Rust's canonical convention is
        // -a < b <= a, so normalize that boundary before serialization/hashing.
        self.inner_normalize(ctx);
    }

    #[cfg(test)]
    fn inner_multiply_general(&mut self, rhs: &Self, ctx: &mut Ctx) {
        self.inner_compose(rhs, ctx);
        self.inner_reduce(ctx);
    }

    fn inner_compose(&mut self, rhs: &Self, ctx: &mut Ctx) {
        // g = (b1 + b2) / 2
        ffi::mpz_add(&mut ctx.congruence_context.g, &self.b, &rhs.b);
        ffi::mpz_fdiv_q_ui_self(&mut ctx.congruence_context.g, 2);

        // h = (b2 - b1) / 2
        ffi::mpz_sub(&mut ctx.h, &rhs.b, &self.b);
        ffi::mpz_fdiv_q_ui_self(&mut ctx.h, 2);

        debug_assert!(&ctx.h + &ctx.congruence_context.g == rhs.b);
        debug_assert!(&ctx.congruence_context.g - &ctx.h == self.b);

        // w = gcd(a1, a2, g)
        ffi::three_gcd(&mut ctx.w, &self.a, &rhs.a, &ctx.congruence_context.g);

        // j = w
        ctx.j.set(&ctx.w);

        // s = a1/w
        ffi::mpz_fdiv_q(&mut ctx.s, &self.a, &ctx.w);

        // t = a2/w
        ffi::mpz_fdiv_q(&mut ctx.t, &rhs.a, &ctx.w);

        // u = g/w
        ffi::mpz_fdiv_q(&mut ctx.u, &ctx.congruence_context.g, &ctx.w);

        // a = t*u
        ffi::mpz_mul(&mut ctx.a, &ctx.t, &ctx.u);

        // b = h*u - s*c1
        ffi::mpz_mul(&mut ctx.b, &ctx.h, &ctx.u);
        ffi::mpz_mul(&mut ctx.m, &ctx.s, &self.c);
        ctx.b += &ctx.m;

        // m = s*t
        ffi::mpz_mul(&mut ctx.m, &ctx.s, &ctx.t);
        ctx.congruence_context.solve_linear_congruence(
            &mut ctx.mu,
            Some(&mut ctx.v),
            &ctx.a,
            &ctx.b,
            &ctx.m,
        );

        // a = t*v
        ffi::mpz_mul(&mut ctx.a, &ctx.t, &ctx.v);

        // b = h - t * mu
        ffi::mpz_mul(&mut ctx.m, &ctx.t, &ctx.mu);
        ffi::mpz_sub(&mut ctx.b, &ctx.h, &ctx.m);

        // m = s
        ctx.m.set(&ctx.s);

        ctx.congruence_context.solve_linear_congruence(
            &mut ctx.lambda,
            Some(&mut ctx.sigma),
            &ctx.a,
            &ctx.b,
            &ctx.m,
        );

        // k = mu + v*lambda
        ffi::mpz_mul(&mut ctx.a, &ctx.v, &ctx.lambda);
        ffi::mpz_add(&mut ctx.k, &ctx.mu, &ctx.a);

        // l = (k*t - h)/s
        ffi::mpz_mul(&mut ctx.l, &ctx.k, &ctx.t);
        ffi::mpz_sub(&mut ctx.v, &ctx.l, &ctx.h);
        ffi::mpz_fdiv_q(&mut ctx.l, &ctx.v, &ctx.s);

        // m = (t*u*k - h*u - c*s) / s*t
        ffi::mpz_mul(&mut ctx.m, &ctx.t, &ctx.u);
        ctx.m *= &ctx.k;
        ffi::mpz_mul(&mut ctx.a, &ctx.h, &ctx.u);
        ctx.m -= &ctx.a;
        ffi::mpz_mul(&mut ctx.a, &self.c, &ctx.s);
        ctx.m -= &ctx.a;
        ffi::mpz_mul(&mut ctx.a, &ctx.s, &ctx.t);
        ffi::mpz_fdiv_q(&mut ctx.lambda, &ctx.m, &ctx.a);

        // A = s*t - r*u
        ffi::mpz_mul(&mut self.a, &ctx.s, &ctx.t);

        // B = ju + mr - (kt + ls)
        ffi::mpz_mul(&mut self.b, &ctx.j, &ctx.u);
        ffi::mpz_mul(&mut ctx.a, &ctx.k, &ctx.t);
        self.b -= &ctx.a;
        ffi::mpz_mul(&mut ctx.a, &ctx.l, &ctx.s);
        self.b -= &ctx.a;

        // C = kl - jm
        ffi::mpz_mul(&mut self.c, &ctx.k, &ctx.l);
        ffi::mpz_mul(&mut ctx.a, &ctx.j, &ctx.lambda);
        self.c -= &ctx.a;
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn new(a: Mpz, b: Mpz, c: Mpz, discriminant: Mpz) -> Self {
        let s = GmpClassGroup {
            a,
            b,
            c,
            discriminant,
        };
        s.assert_valid();
        s
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn assert_valid(&self) {
        if cfg!(debug_assertions) {
            let four: Mpz = 4u64.into();
            let four_ac: Mpz = four * &self.a * &self.c;
            assert!(&self.discriminant + four_ac == &self.b * &self.b);
        }
    }

    fn inner_normalize(&mut self, ctx: &mut Ctx) {
        self.assert_valid();
        ctx.negative_a = -&self.a;
        if self.b > ctx.negative_a && self.b <= self.a {
            return;
        }
        ffi::mpz_sub(&mut ctx.r, &self.a, &self.b);
        ffi::mpz_mul_2exp(&mut ctx.denom, &self.a, 1);
        ffi::mpz_fdiv_q(&mut ctx.negative_a, &ctx.r, &ctx.denom);
        swap(&mut ctx.negative_a, &mut ctx.r);
        swap(&mut ctx.old_b, &mut self.b);
        ffi::mpz_mul(&mut ctx.ra, &ctx.r, &self.a);
        ffi::mpz_mul_2exp(&mut ctx.negative_a, &ctx.ra, 1);
        ffi::mpz_add(&mut self.b, &ctx.old_b, &ctx.negative_a);

        ffi::mpz_mul(&mut ctx.negative_a, &ctx.ra, &ctx.r);
        ffi::mpz_add(&mut ctx.old_a, &self.c, &ctx.negative_a);

        ffi::mpz_mul(&mut ctx.ra, &ctx.r, &ctx.old_b);
        ffi::mpz_add(&mut self.c, &ctx.old_a, &ctx.ra);

        self.assert_valid();
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn inner_reduce(&mut self, ctx: &mut Ctx) {
        self.inner_normalize(ctx);

        while if ffi::mpz_is_negative(&self.b) {
            self.a >= self.c
        } else {
            self.a > self.c
        } {
            debug_assert!(!self.c.is_zero());
            ffi::mpz_add(&mut ctx.s, &self.c, &self.b);
            ffi::mpz_add(&mut ctx.x, &self.c, &self.c);
            swap(&mut self.b, &mut ctx.old_b);
            ffi::mpz_fdiv_q(&mut self.b, &ctx.s, &ctx.x);
            swap(&mut self.b, &mut ctx.s);
            swap(&mut self.a, &mut self.c);

            // x = 2sc
            ffi::mpz_mul(&mut self.b, &ctx.s, &self.a);
            ffi::mpz_mul_2exp(&mut ctx.x, &self.b, 1);

            // b = x - old_b
            ffi::mpz_sub(&mut self.b, &ctx.x, &ctx.old_b);

            // x = b*s
            ffi::mpz_mul(&mut ctx.x, &ctx.old_b, &ctx.s);

            // s = c*s^2
            ffi::mpz_mul(&mut ctx.old_b, &ctx.s, &ctx.s);
            ffi::mpz_mul(&mut ctx.s, &self.a, &ctx.old_b);

            // c = s - x
            ffi::mpz_sub(&mut ctx.old_a, &ctx.s, &ctx.x);

            // c += a
            self.c += &ctx.old_a;
        }
        self.inner_normalize(ctx);
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn inner_square_impl(&mut self, ctx: &mut Ctx) {
        self.assert_valid();
        ffi::gmp_nudupl(&mut self.a, &mut self.b, &mut self.c, 1, true);
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn inner_square(&mut self, ctx: &mut Ctx) {
        if cfg!(debug_assertions) {
            let mut q = self.clone();
            q.inner_multiply(self, ctx);
            self.inner_square_impl(ctx);
            assert_eq!(*self, q);
        } else {
            self.inner_square_impl(ctx);
        }
    }

    /// Call `cb` with a mutable reference to the context of type `Ctx`.
    ///
    /// The reference cannot escape the closure and cannot be sent across
    /// threads.
    ///
    /// # Panics
    ///
    /// Panics if called recursively.  This library guarantees that it will
    /// never call this function from any function that takes a parameter of
    /// type `&mut Ctx`.
    pub fn with_context<T, U>(cb: T) -> U
    where
        T: FnOnce(&mut Ctx) -> U,
    {
        let mut opt = None;
        CTX.with(|x| opt = Some(cb(&mut x.borrow_mut())));
        opt.unwrap()
    }
}

impl Default for GmpClassGroup {
    fn default() -> Self {
        GmpClassGroup {
            a: Mpz::new(),
            b: Mpz::new(),
            c: Mpz::new(),
            discriminant: Mpz::new(),
        }
    }
}

impl<B: Borrow<GmpClassGroup>> MulAssign<B> for GmpClassGroup {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn mul_assign(&mut self, rhs: B) {
        let rhs = rhs.borrow();
        debug_assert!(self.discriminant == rhs.discriminant);
        GmpClassGroup::with_context(|ctx| self.inner_multiply(rhs, ctx));
    }
}

impl super::BigNum for Mpz {
    fn probab_prime(&self, iterations: u32) -> bool {
        let reps: i32 = iterations.try_into().expect("Iterations fits into i32");
        self.probab_prime(reps) != NotPrime
    }

    fn setbit(&mut self, bit_index: usize) {
        self.setbit(bit_index)
    }

    fn mod_powm(&mut self, base: &Self, exponent: &Self, modulus: &Self) {
        ffi::mpz_powm(self, base, exponent, modulus)
    }
}

impl super::BigNumExt for Mpz {
    fn frem_u32(&self, modulus: u32) -> u32 {
        ffi::mpz_frem_u32(self, modulus)
    }
    fn crem_u16(&mut self, modulus: u16) -> u16 {
        ffi::mpz_crem_u16(self, modulus)
    }
}

impl<B: Borrow<Self>> Mul<B> for GmpClassGroup {
    type Output = Self;
    #[inline]
    fn mul(mut self, rhs: B) -> Self {
        self *= rhs.borrow();
        self
    }
}

impl<'a, B: Borrow<GmpClassGroup>> Mul<B> for &'a GmpClassGroup {
    type Output = GmpClassGroup;

    #[inline(always)]
    fn mul(self, rhs: B) -> Self::Output {
        let mut s = Clone::clone(self.borrow());
        s *= rhs;
        s
    }
}

impl ClassGroup for GmpClassGroup {
    type BigNum = Mpz;

    /// Normalize `self`.
    ///
    /// # Panics
    ///
    /// Panics if called within a call to `Self::with_context`.
    fn normalize(&mut self) {
        Self::with_context(|x| self.inner_normalize(x))
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn inverse(&mut self) {
        self.assert_valid();
        self.b = -self.b.clone();
    }

    fn serialize(&self, buf: &mut [u8]) -> Result<(), usize> {
        self.assert_valid();
        if buf.len() & 1 == 1 {
            // odd lengths do not make sense
            Err(0)
        } else {
            let len = buf.len() >> 1;
            ffi::export_obj(&self.a, &mut buf[..len])?;
            ffi::export_obj(&self.b, &mut buf[len..])
        }
    }

    fn from_bytes(bytearray: &[u8], discriminant: Self::BigNum) -> Self {
        let len = (ffi::size_in_bits(&discriminant) + 16) >> 4;
        let a = ffi::import_obj(&bytearray[..len]);
        let b = ffi::import_obj(&bytearray[len..]);
        Self::from_ab_discriminant(a, b, discriminant)
    }

    fn from_ab_discriminant(a: Self::BigNum, b: Self::BigNum, discriminant: Self::BigNum) -> Self {
        let mut four_a: Self::BigNum = 4u64.into();
        four_a *= &a;
        // SECURITY: `a` may be decoded from untrusted proof/output bytes; `a == 0`
        // makes `four_a == 0` and the division below a divide-by-zero PANIC —
        // a remote DoS on every VDF verify path. Produce a deterministic
        // (invalid, `a == 0`) form instead; verification compares against a
        // canonically-recomputed value, so such a form simply fails to verify.
        let c = if four_a == Self::BigNum::from(0u64) {
            Self::BigNum::from(0u64)
        } else {
            (&b * &b - &discriminant) / four_a
        };
        Self {
            a,
            b,
            c,
            discriminant,
        }
    }

    /// Returns the discriminant of `self`.
    #[inline(always)]
    fn discriminant(&self) -> &Self::BigNum {
        &self.discriminant
    }

    fn size_in_bits(num: &Self::BigNum) -> usize {
        ffi::size_in_bits(num)
    }

    /// Reduce `self`.
    ///
    /// # Panics
    ///
    /// Panics if called within a call to `Self::with_context`.
    fn reduce(&mut self) {
        Self::with_context(|x| self.inner_reduce(x))
    }

    fn deserialize(buf: &[u8], discriminant: Self::BigNum) -> Self {
        let len = buf.len();
        debug_assert!(len != 0, "Cannot deserialize an empty buffer!");
        debug_assert!(len & 1 == 0, "Buffer must be of even length");
        let half_len = len >> 1;
        Self::from_ab_discriminant(
            ffi::import_obj(&buf[..half_len]),
            ffi::import_obj(&buf[half_len..]),
            discriminant,
        )
    }

    /// Square `self`.ClassGroupPartial
    ///
    /// # Panics
    ///
    /// Panics if called within the scope of a call to `with_context`.
    fn square(&mut self) {
        Self::with_context(|ctx| self.inner_square(ctx))
    }

    fn unsigned_deserialize_bignum(buf: &[u8]) -> Self::BigNum {
        buf.into()
    }

    /// Square `self` `iterations` times.
    ///
    /// # Panics
    ///
    /// Panics if called within the scope of a call to `with_context`.
    fn repeated_square(&mut self, iterations: u64) {
        Self::with_context(|_| {
            ffi::gmp_nudupl(&mut self.a, &mut self.b, &mut self.c, iterations, true);
        })
    }

    fn generator_for_discriminant(discriminant: Self::BigNum) -> Self {
        let one: Mpz = One::one();
        let x: Mpz = &one - &discriminant;
        let mut form = Self::new(2.into(), one, x.div_floor(&8.into()), discriminant);
        form.reduce();
        form
    }

    fn pow(&mut self, mut exponent: Mpz) {
        self.assert_valid();
        debug_assert!(exponent >= Mpz::zero());
        let mut state = self.identity();
        loop {
            let is_odd = exponent.tstbit(0);
            exponent >>= 1;
            if is_odd {
                state *= &*self
            }
            if exponent.is_zero() {
                *self = state;
                break;
            }
            self.square();
        }
    }
}

impl Default for Ctx {
    fn default() -> Self {
        Self {
            negative_a: Mpz::new(),
            r: Mpz::new(),
            denom: Mpz::new(),
            old_a: Mpz::new(),
            old_b: Mpz::new(),
            ra: Mpz::new(),
            s: Mpz::new(),
            x: Mpz::new(),
            congruence_context: Default::default(),
            w: Mpz::new(),
            m: Mpz::new(),
            u: Mpz::new(),
            l: Mpz::new(),
            j: Mpz::new(),
            t: Mpz::new(),
            a: Mpz::new(),
            b: Mpz::new(),
            k: Mpz::new(),
            h: Mpz::new(),
            mu: Mpz::new(),
            v: Mpz::new(),
            sigma: Mpz::new(),
            lambda: Mpz::new(),
        }
    }
}

pub fn do_compute(discriminant: Mpz, iterations: u64) -> GmpClassGroup {
    debug_assert!(discriminant < Zero::zero());
    debug_assert!(discriminant.probab_prime(50) != NotPrime);
    let mut f = GmpClassGroup::generator_for_discriminant(discriminant);
    f.repeated_square(iterations);
    f
}

#[cfg(test)]
mod test {
    #![allow(unused_imports)]
    use super::*;

    fn discriminants() -> Vec<Mpz> {
        use std::str::FromStr;
        vec![
            (-23i64).into(),
            (-47i64).into(),
            (-167i64).into(),
            (-685_537_176_559i64).into(),
            Mpz::from_str("-20149392707186525162590355071292053575364559848351567085354700987844093330948936280039379742871107183330808146182415920691586415080574829617024503722195777232804427670557174581127121229242207584973924825787037130000131358603651587961876409377224876056238680407347843315752681629521613772380379341182886747008940959623895895000737071932595957989286658892888724991242968836440986789551081768017186919005412288127429935094766982059615711599441803409172888758437372755538407566562462485676644100997464269306675140005421720998149066720895066941777378563169387978299301916769407006303085854796535778826115224633447713584423").unwrap(),
        ]
    }

    #[test]
    fn native_squaring_matches_general_composition_bytes() {
        for discriminant in discriminants() {
            let mut native = GmpClassGroup::generator_for_discriminant(discriminant);
            let mut general = native.clone();
            for count in [0, 1, 2, 7, 8, 9, 63, 64, 65, 127] {
                native.repeated_square(count);
                GmpClassGroup::with_context(|ctx| {
                    for _ in 0..count {
                        let rhs = general.clone();
                        general.inner_multiply_general(&rhs, ctx);
                    }
                });
                assert_eq!(native, general, "repeated squaring batch {count}");
                let mut actual = vec![0; 2 * ((native.discriminant.size_in_base(2) + 16) >> 4)];
                let mut expected = actual.clone();
                native.serialize(&mut actual).unwrap();
                general.serialize(&mut expected).unwrap();
                assert_eq!(actual, expected);
            }
        }
    }

    /// The old native square can retain either sign at |b| == a. Preserve
    /// its exact bytes even for composite discriminants and unreduced inputs.
    #[test]
    fn native_squaring_preserves_original_boundary_representatives() {
        let cases = [
            (form(4, -1, 6, -95), 1, form(5, -5, 6, -95)),
            (form(4, -1, 7, -111), 1, form(3, 3, 10, -111)),
            (form(4, 1, 7, -111), 1, form(3, -3, 10, -111)),
            (form(12, 9, 3, -63), 1, form(1, 1, 16, -63)),
            (form(4, -1, 7, -111), 2, form(1, -1, 28, -111)),
            (form(4, -1, 7, -111), 7, form(1, -1, 28, -111)),
        ];
        for (mut actual, iterations, expected) in cases {
            actual.repeated_square(iterations);
            assert_eq!(actual, expected);
            let mut actual_bytes = [0; 4];
            let mut expected_bytes = [0; 4];
            actual.serialize(&mut actual_bytes).unwrap();
            expected.serialize(&mut expected_bytes).unwrap();
            assert_eq!(actual_bytes, expected_bytes);
        }
    }

    #[test]
    fn native_composition_matches_rust_reduction() {
        for discriminant in discriminants() {
            let generator = GmpClassGroup::generator_for_discriminant(discriminant);
            let mut powers = vec![generator.identity(), generator.clone()];
            GmpClassGroup::with_context(|ctx| {
                for _ in 0..18 {
                    let mut next = powers.last().unwrap().clone();
                    next.inner_multiply_general(&generator, ctx);
                    powers.push(next);
                }
                for left in &powers {
                    for right in &powers {
                        let mut actual = left.clone();
                        actual.inner_multiply(right, ctx);
                        let mut expected = left.clone();
                        expected.inner_multiply_general(right, ctx);
                        assert_eq!(actual, expected);
                    }
                }
            });
        }
    }

    #[test]
    fn native_reduction_matches_rust_at_canonical_boundaries() {
        let forms = [
            GmpClassGroup::from_ab_discriminant(1.into(), (-1).into(), (-23).into()),
            GmpClassGroup::from_ab_discriminant(1.into(), (-1).into(), (-3).into()),
            GmpClassGroup::from_ab_discriminant(2.into(), (-2).into(), (-4).into()),
            GmpClassGroup::generator_for_discriminant(discriminants().pop().unwrap()),
        ];
        GmpClassGroup::with_context(|ctx| {
            for form in &forms {
                for shift in [-1000i64, -33, -1, 0, 1, 33, 1000] {
                    // An integral change of variables preserves the discriminant
                    // but forces normalization and highly unbalanced reduction.
                    let r = Mpz::from(shift);
                    let mut actual = form.clone();
                    actual.b += &(&form.a * &r * &Mpz::from(2u64));
                    actual.c += &(&form.b * &r + &form.a * &r * &r);
                    let mut expected = actual.clone();
                    actual.inner_reduce_fast(ctx);
                    expected.inner_reduce(ctx);
                    assert_eq!(actual, expected, "shift {shift}");
                }
            }
        });
    }

    fn form(a: i64, b: i64, c: i64, discriminant: i64) -> GmpClassGroup {
        GmpClassGroup { a: a.into(), b: b.into(), c: c.into(), discriminant: discriminant.into() }
    }

    #[test]
    fn normalize() {
        let mut s = GmpClassGroup::new(
            16.into(),
            (-23).into(),
            5837_3892.into(),
            (-0xdead_beefi64).into(),
        );
        let mut new = GmpClassGroup {
            b: 9.into(),
            c: 5837_3885.into(),
            ..s.clone()
        };
        s.normalize();
        assert_eq!(s, new);

        s = GmpClassGroup {
            a: (1 << 16).into(),
            b: (-76951).into(),
            c: 36840.into(),
            ..s
        };
        new = GmpClassGroup {
            b: 54121.into(),
            c: 25425.into(),
            ..s.clone()
        };
        s.normalize();
        assert_eq!(s, new);
    }
}
