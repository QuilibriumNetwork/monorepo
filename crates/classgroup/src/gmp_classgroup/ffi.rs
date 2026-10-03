// Copyright 2018 POA Networks Ltd.
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

//! FFI bindings to GMP.  This module exists because the `rust-gmp` crate
//! is too high-level.  High-performance bignum computation requires that
//! bignums be modified in-place, so that their storage can be reused.
//! Furthermore, the `rust-gmp` crate doesn’t support many operations that
//! this library requires.
#![allow(unsafe_code)]
pub use super::super::gmp::mpz::Mpz;
// `__gmpz_cmpabs`, `__gmpz_export` and `__gmpz_sizeinbase` are imported from
// `gmp::mpz` rather than redeclared here. Declaring the same symbol twice with
// different signatures is `clashing_extern_declarations`, and rustc is entitled
// to assume either one; `__gmpz_cmpabs` in particular used to be declared here
// as returning `usize`, which cannot represent the negative value GMP returns
// when |op1| < |op2|.
use super::super::gmp::mpz::{
    __gmpz_cmpabs, __gmpz_export, __gmpz_sizeinbase, mp_bitcnt_t, mp_limb_t,
};
use libc::{c_int, c_long, c_ulong, c_void, size_t};
// pub use c_ulong;
use std::cmp::Ordering;
use std::usize;
// We use the unsafe versions to avoid unnecessary allocations.
extern "C" {
    fn adapted_nudupl(a: *mut Mpz, b: *mut Mpz, c: *mut Mpz, times: c_ulong);
}
// We use the unsafe versions to avoid unnecessary allocations.
#[link(name = "gmp")]
extern "C" {
    fn __gmpz_gcdext(gcd: *mut Mpz, s: *mut Mpz, t: *mut Mpz, a: *const Mpz, b: *const Mpz);
    fn __gmpz_gcd(rop: *mut Mpz, op1: *const Mpz, op2: *const Mpz);
    fn __gmpz_fdiv_qr(q: *mut Mpz, r: *mut Mpz, b: *const Mpz, g: *const Mpz);
    fn __gmpz_fdiv_q(q: *mut Mpz, n: *const Mpz, d: *const Mpz);
    fn __gmpz_divexact(q: *mut Mpz, n: *const Mpz, d: *const Mpz);
    fn __gmpz_tdiv_q(q: *mut Mpz, n: *const Mpz, d: *const Mpz);
    fn __gmpz_mul(p: *mut Mpz, a: *const Mpz, b: *const Mpz);
    fn __gmpz_mod(p: *mut Mpz, a: *const Mpz, b: *const Mpz);
    fn __gmpz_neg(rop: *mut Mpz, op: *const Mpz);
    fn __gmpz_mul_ui(p: *mut Mpz, a: *const Mpz, b: c_ulong);
    fn __gmpz_addmul(rop: *mut Mpz, op1: *const Mpz, op2: *const Mpz);
    fn __gmpz_set(rop: *mut Mpz, op: *const Mpz);
    //fn __fmpz_set_mpz(rop: *mut Mpz, op: *const Mpz);
    //fn __fmpz_get_mpz(rop: *mut Mpz, op: *const Mpz);
    //fn __gmpz_sgn(rop: *const Mpz) -> usize;
    fn __gmpz_mul_2exp(rop: *mut Mpz, op1: *const Mpz, op2: mp_bitcnt_t);
    fn __gmpz_sub(rop: *mut Mpz, op1: *const Mpz, op2: *const Mpz);
    fn __gmpz_submul(rop: *mut Mpz, op1: *const Mpz, op2: *const Mpz);
    fn __gmpz_import(
        rop: *mut Mpz,
        count: size_t,
        order: c_int,
        size: size_t,
        endian: c_int,
        nails: size_t,
        op: *const c_void,
    );
    fn __gmpz_tdiv_r(r: *mut Mpz, n: *const Mpz, d: *const Mpz);
    fn __gmpz_fdiv_q_ui(rop: *mut Mpz, op1: *const Mpz, op2: c_ulong) -> c_ulong;
    fn __gmpz_add(rop: *mut Mpz, op1: *const Mpz, op2: *const Mpz);
    fn __gmpz_add_ui(rop: *mut Mpz, op1: *const Mpz, op2: c_ulong);
    fn __gmpz_set_ui(rop: &mut Mpz, op: c_ulong);
    fn __gmpz_set_si(rop: &mut Mpz, op: c_long);
    fn __gmpz_cdiv_ui(n: &Mpz, d: c_ulong) -> c_ulong;
    fn __gmpz_fdiv_ui(n: &Mpz, d: c_ulong) -> c_ulong;
    fn __gmpz_tdiv_ui(n: &Mpz, d: c_ulong) -> c_ulong;
    fn __gmpz_powm(rop: *mut Mpz, base: *const Mpz, exp: *const Mpz, modulus: *const Mpz);
}

// MEGA HACK: rust-gmp doesn’t expose the fields of this struct, so we must define
// it ourselves and cast.
//
// Should be stable though, as only GMP can change it, and doing would break binary compatibility.
#[repr(C)]
struct MpzStruct {
    mp_alloc: c_int,
    mp_size: c_int,
    mp_d: *mut mp_limb_t,
}

macro_rules! impl_div_ui {
    ($t:ident, $i:ident, $f:expr) => {
        pub fn $i(n: &Mpz, d: $t) -> $t {
            use std::$t;
            let res = unsafe { $f(n, c_ulong::from(d)) };
            assert!(res <= $t::MAX.into());
            res as $t
        }
    };
}

impl_div_ui!(u16, mpz_crem_u16, __gmpz_cdiv_ui);
impl_div_ui!(u32, mpz_frem_u32, __gmpz_fdiv_ui);

/// Returns `true` if `z` is negative and not zero.  Otherwise,
/// returns `false`.
#[inline]
pub fn mpz_is_negative(z: &Mpz) -> bool {
    unsafe { (*(z as *const _ as *const MpzStruct)).mp_size < 0 }
}

#[inline]
pub fn mpz_powm(rop: &mut Mpz, base: &Mpz, exponent: &Mpz, modulus: &Mpz) {
    unsafe { __gmpz_powm(rop, base, exponent, modulus) }
}

#[inline]
pub fn mpz_tdiv_r(r: &mut Mpz, n: &Mpz, d: &Mpz) {
    unsafe { __gmpz_tdiv_r(r, n, d) }
}

/// Sets `g` to the GCD of `a` and `b`.
#[inline]
pub fn mpz_gcdext(gcd: &mut Mpz, s: &mut Mpz, t: &mut Mpz, a: &Mpz, b: &Mpz) {
    unsafe { __gmpz_gcdext(gcd, s, t, a, b) }
}

//#[inline]
//pub fn fmpz_xgcd_partial(gcd: &mut Mpz, s: &mut Mpz, t: &mut Mpz, a: &Mpz, b: &Mpz) {
//    unsafe { __fmpz_xgcd_partial(gcd, s, t, a, b) }
//}

#[inline]
pub fn mpz_gcdext_null(gcd: &mut Mpz, s: &mut Mpz, a: &Mpz, b: &Mpz) {
    unsafe { __gmpz_gcdext(gcd, s, std::ptr::null_mut(), a, b) }
}

/// Doubles `rop` in-place
#[inline]
pub fn mpz_double(rop: &mut Mpz) {
    if true {
        // slightly faster
        unsafe { __gmpz_mul_2exp(rop, rop, 1) }
    } else {
        unsafe { __gmpz_add(rop, rop, rop) }
    }
}

#[inline]
pub fn mpz_fdiv_qr(q: &mut Mpz, r: &mut Mpz, b: &Mpz, g: &Mpz) {
    unsafe { __gmpz_fdiv_qr(q, r, b, g) }
}

#[inline]
pub fn mpz_fdiv_q_ui_self(rop: &mut Mpz, op: c_ulong) -> c_ulong {
    unsafe { __gmpz_fdiv_q_ui(rop, rop, op) }
}

/// Unmarshals a buffer to an `Mpz`.  `buf` is interpreted as a 2’s complement,
/// big-endian integer.  If the buffer is empty, zero is returned.
pub fn import_obj(buf: &[u8]) -> Mpz {
    fn raw_import(buf: &[u8]) -> Mpz {
        let mut obj = Mpz::new();

        unsafe { __gmpz_import(&mut obj, buf.len(), 1, 1, 1, 0, buf.as_ptr() as *const _) }
        obj
    }
    let is_negative = match buf.first() {
        None => return Mpz::zero(),
        Some(x) => x & 0x80 != 0,
    };
    if !is_negative {
        raw_import(buf)
    } else {
        let mut new_buf: Vec<_> = buf.iter().cloned().skip_while(|&x| x == 0xFF).collect();
        if new_buf.is_empty() {
            (-1).into()
        } else {
            for i in &mut new_buf {
                *i ^= 0xFF
            }
            !raw_import(&new_buf)
        }
    }
}

pub fn three_gcd(rop: &mut Mpz, a: &Mpz, b: &Mpz, c: &Mpz) {
    unsafe {
        __gmpz_gcd(rop, a, b);
        __gmpz_gcd(rop, rop, c)
    }
}

#[inline]
pub fn size_in_bits(obj: &Mpz) -> usize {
    unsafe { __gmpz_sizeinbase(obj.inner(), 2) }
}

#[inline]
pub fn mpz_add(rop: &mut Mpz, op1: &Mpz, op2: &Mpz) {
    unsafe { __gmpz_add(rop, op1, op2) }
}

#[inline]
pub fn mpz_mul(rop: &mut Mpz, op1: &Mpz, op2: &Mpz) {
    unsafe { __gmpz_mul(rop, op1, op2) }
}

#[inline]
pub fn mpz_mod(rop: &mut Mpz, op1: &Mpz, op2: &Mpz) {
    unsafe { __gmpz_mod(rop, op1, op2) }
}

#[inline]
pub fn mpz_submul(rop: &mut Mpz, op1: &Mpz, op2: *const Mpz) {
    unsafe { __gmpz_submul(rop, op1, op2) }
}

#[inline]
pub fn mpz_addmul(rop: &mut Mpz, op1: &Mpz, op2: *const Mpz) {
    unsafe { __gmpz_addmul(rop, op1, op2) }
}

#[inline]
pub fn mpz_mul_ui(rop: &mut Mpz, op1: &Mpz, op2: u64) {
    unsafe { __gmpz_mul_ui(rop, op1, op2) }
}

//#[inline]
//pub fn mpz_sgn(rop: &Mpz) -> usize {
//    unsafe { __gmpz_sgn(rop) }
//}

#[inline]
pub fn gmp_nudupl(a: &mut Mpz, b: &mut Mpz, c: &mut Mpz, times: u64) {
    unsafe {
        adapted_nudupl(a, b, c, times);
    }
}

/// Compares |`op1`| with |`op2`|, returning the `Ordering` between them.
///
/// GMP's `mpz_cmpabs` returns a signed `int` — negative when |op1| < |op2| —
/// which is why this cannot return `usize`, as it once did.
#[inline]
pub fn mpz_cmpabs(op1: &Mpz, op2: &Mpz) -> Ordering {
    unsafe { __gmpz_cmpabs(op1.inner(), op2.inner()).cmp(&0) }
}

//#[inline]
//pub fn fmpz_get_mpz(rop: &mut Mpz, op1: &Mpz) {
//    unsafe { __fmpz_get_mpz(rop, op1) }
//}
//
//#[inline]
//pub fn fmpz_set_mpz(rop: &mut Mpz, op1: &Mpz) {
//    unsafe { __fmpz_set_mpz(rop, op1) }
//}

#[inline]
pub fn mpz_set(rop: &mut Mpz, op1: &Mpz) {
    unsafe { __gmpz_set(rop, op1) }
}

#[inline]
pub fn mpz_neg(rop: &mut Mpz, op1: &Mpz) {
    unsafe { __gmpz_neg(rop, op1) }
}

#[inline]
pub fn mpz_divexact(q: &mut Mpz, n: &Mpz, d: &Mpz) {
    unsafe { __gmpz_divexact(q, n, d) }
}

#[inline]
pub fn mpz_mul_2exp(rop: &mut Mpz, op1: &Mpz, op2: mp_bitcnt_t) {
    unsafe { __gmpz_mul_2exp(rop as *mut _ as *mut Mpz, op1, op2) }
}

/// Divide `n` by `d`.  Round towards -∞ and place the result in `q`.
#[inline]
pub fn mpz_fdiv_q(q: &mut Mpz, n: &Mpz, d: &Mpz) {
    if mpz_is_negative(n) == mpz_is_negative(d) {
        unsafe { __gmpz_tdiv_q(q, n, d) }
    } else {
        unsafe { __gmpz_fdiv_q(q, n, d) }
    }
}

/// Sets `rop` to `(-1) * op`
#[inline]
#[cfg(none)]
pub fn mpz_neg(rop: &mut Mpz) {
    assert!(std::mem::size_of::<Mpz>() == std::mem::size_of::<MpzStruct>());
    unsafe {
        let ptr = rop as *mut _ as *mut MpzStruct;
        let v = (*ptr).mp_size;
        (*ptr).mp_size = -v;
    }
}

/// Subtracts `op2` from `op1` and stores the result in `rop`.
#[inline]
pub fn mpz_sub(rop: &mut Mpz, op1: &Mpz, op2: &Mpz) {
    unsafe { __gmpz_sub(rop as *mut _ as *mut Mpz, op1, op2) }
}

/// Exports `obj` to `v` as an array of 2’s complement, big-endian
/// bytes.  If `v` is too small to hold the result, returns `Err(s)`,
/// where `s` is the size needed to hold the exported version of `obj`.
pub fn export_obj(obj: &Mpz, v: &mut [u8]) -> Result<(), usize> {
    // Requires: offset < v.len() and v[offset..] be able to hold all of `obj`
    unsafe fn raw_export(v: &mut [u8], offset: usize, obj: &Mpz) -> usize {
        // SAFE as `offset` will always be in-bounds, since byte_len always <=
        // byte_len_needed and we check that v.len() >= byte_len_needed.
        let ptr = v.as_mut_ptr().add(offset) as *mut c_void;

        // Necessary ― this byte may not be fully overwritten
        *(ptr as *mut u8) = 0;

        // `__gmpz_export` always writes the word count through `countp`, and
        // writes 0 when `obj` is zero, so this initial value is never observed.
        // It is a plain `0` rather than `mem::uninitialized()` because handing
        // an uninitialised scalar to safe code is UB the moment it exists.
        let mut s: usize = 0;
        let ptr2 = __gmpz_export(ptr, &mut s, 1, 1, 1, 0, obj.inner());
        assert_eq!(ptr, ptr2);
        if 0 == s {
            1
        } else {
            s
        }
    }

    let size = size_in_bits(obj);
    assert!(size > 0);

    // Check to avoid integer overflow in later operations.
    if size > usize::MAX - 8 || v.len() > usize::MAX >> 3 {
        return Err(usize::MAX);
    }

    // One additional bit is needed for the sign bit.
    let byte_len_needed = (size + 8) >> 3;
    if v.len() < byte_len_needed {
        return if v.is_empty() && obj.is_zero() {
            Ok(())
        } else {
            Err(byte_len_needed)
        };
    }
    let is_negative = mpz_is_negative(obj);

    if is_negative {
        // MEGA HACK: GMP does not have a function to perform 2's complement
        let obj = !obj;
        debug_assert!(
            !mpz_is_negative(&obj),
            "bitwise negation of a negative number produced a negative number"
        );
        let new_byte_size = (size_in_bits(&obj) + 7) >> 3;
        let offset = v.len() - new_byte_size;

        for i in &mut v[..offset] {
            *i = 0xFF
        }
        unsafe {
            assert_eq!(raw_export(v, offset, &obj), new_byte_size);
        }

        // We had to do a one’s complement to get the data in a decent format,
        // so now we need to flip all of the bits back.  LLVM should be able to
        // vectorize this loop easily.
        for i in &mut v[offset..] {
            *i ^= 0xFF
        }
    } else {
        // ...but GMP will not include that in the number of bytes it writes
        // (except for negative numbers)
        let byte_len = (size + 7) >> 3;
        assert!(byte_len > 0);

        let offset = v.len() - byte_len;

        // Zero out any leading bytes
        for i in &mut v[..offset] {
            *i = 0
        }
        unsafe {
            assert_eq!(raw_export(v, offset, &obj), byte_len);
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn check_expected_bit_width() {
        let mut s: Mpz = (-2).into();
        assert_eq!(size_in_bits(&s), 2);
        s = !s;
        assert_eq!(s, 1.into());
        s.setbit(2);
        assert_eq!(s, 5.into());
    }

    #[test]
    fn check_export() {
        let mut s: Mpz = 0x100.into();
        s = !s;
        let mut buf = [0, 0, 0];
        export_obj(&s, &mut buf).expect("buffer should be large enough");
        assert_eq!(buf, [0xFF, 0xFE, 0xFF]);
        export_obj(&Mpz::zero(), &mut []).unwrap();
    }

    #[test]
    fn check_rem() {
        assert_eq!(mpz_crem_u16(&(-100i64).into(), 3), 1);
        assert_eq!(mpz_crem_u16(&(100i64).into(), 3), 2);
    }

    /// `mpz_cmpabs` must be able to report "less than".
    ///
    /// GMP's `mpz_cmpabs` returns a signed `int`, negative when |op1| < |op2|.
    /// This function was previously declared as returning `usize`, so the
    /// less-than case came back as a nonsensical large unsigned value and the
    /// signature could not express the answer at all. Any regression to an
    /// unsigned return type fails to compile against this test; any regression
    /// to the wrong operand order fails it at runtime.
    #[test]
    fn cmpabs_orders_by_magnitude() {
        let small: Mpz = 5i64.into();
        let big: Mpz = 7i64.into();

        assert_eq!(mpz_cmpabs(&small, &big), Ordering::Less);
        assert_eq!(mpz_cmpabs(&big, &small), Ordering::Greater);
        assert_eq!(mpz_cmpabs(&small, &small), Ordering::Equal);
    }

    /// The "abs" half of `mpz_cmpabs`: sign is ignored, magnitude is not.
    #[test]
    fn cmpabs_ignores_sign() {
        let neg_nine: Mpz = (-9i64).into();
        let pos_nine: Mpz = 9i64.into();
        let neg_two: Mpz = (-2i64).into();

        assert_eq!(mpz_cmpabs(&neg_nine, &pos_nine), Ordering::Equal);
        assert_eq!(mpz_cmpabs(&pos_nine, &neg_nine), Ordering::Equal);

        // -9 < -2 as signed values, but |-9| > |-2|.
        assert_eq!(mpz_cmpabs(&neg_nine, &neg_two), Ordering::Greater);
        assert_eq!(mpz_cmpabs(&neg_two, &neg_nine), Ordering::Less);
    }

    /// Magnitudes wider than one limb, where a truncated or half-read return
    /// register would be most likely to show up.
    #[test]
    fn cmpabs_handles_multi_limb_values() {
        let a = Mpz::from_str_radix("123456789012345678901234567890123456789", 10).unwrap();
        let mut b = a.clone();
        b.setbit(200);

        assert_eq!(mpz_cmpabs(&a, &b), Ordering::Less);
        assert_eq!(mpz_cmpabs(&b, &a), Ordering::Greater);
        assert_eq!(mpz_cmpabs(&a, &a.clone()), Ordering::Equal);

        let neg_b = {
            let mut t = Mpz::zero();
            mpz_neg(&mut t, &b);
            t
        };
        assert_eq!(mpz_cmpabs(&neg_b, &b), Ordering::Equal);
    }

    /// `export_obj` reports the byte length it actually wrote.
    ///
    /// The count is written by `__gmpz_export` through `countp`. That local was
    /// previously `mem::uninitialized()`; it is now `0`, which is also the value
    /// GMP writes for a zero input — so the zero case below pins both the fix
    /// and the documented GMP behaviour it relies on.
    #[test]
    fn export_obj_round_trips() {
        let values = [
            "1",
            "255",
            "256",
            "65535",
            "123456789012345678901234567890",
            "-1",
            "-255",
            "-256",
            "-123456789012345678901234567890",
        ];

        for value in &values {
            let obj = Mpz::from_str_radix(value, 10).unwrap();
            let byte_len = (size_in_bits(&obj) + 8) >> 3;

            let mut buf = vec![0u8; byte_len];
            export_obj(&obj, &mut buf).expect("buffer sized from size_in_bits should fit");

            assert_eq!(import_obj(&buf), obj, "round trip failed for {}", value);
        }
    }

    /// A buffer too small must report the size needed rather than write past it.
    #[test]
    fn export_obj_reports_required_size() {
        let obj = Mpz::from_str_radix("65535", 10).unwrap();
        let mut too_small = [0u8; 1];
        let needed = export_obj(&obj, &mut too_small).unwrap_err();
        assert!(
            needed > 1,
            "expected a required size larger than the buffer, got {}",
            needed
        );
    }
}