// Copyright 2021 Lolo_32
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

use core::{
    convert::TryInto,
    ops::{Add, Div, Mul, Neg, Sub},
};

use lazy_static::lazy_static;
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};

use crate::{Ed448Error, KEY_LENGTH};
use subtle::{Choice, ConstantTimeEq};

lazy_static! {
    // 2 ^ 448 - 2 ^224 - 1
    static ref p: BigInt = BigInt::from(2).pow(448).sub(BigInt::from(2).pow(224)) - 1;
    static ref d: Field = Field::new(BigInt::from(-39081));
    static ref f0: Field = Field::new(BigInt::zero());
    static ref f1: Field = Field::new(BigInt::one());
    static ref xb: Field = Field::new(BigInt::from_bytes_be(
        Sign::Plus,
        &[
            0x4F, 0x19, 0x70, 0xC6, 0x6B, 0xED, 0x0D, 0xED, 0x22, 0x1D, 0x15, 0xA6, 0x22, 0xBF,
            0x36, 0xDA, 0x9E, 0x14, 0x65, 0x70, 0x47, 0x0F, 0x17, 0x67, 0xEA, 0x6D, 0xE3, 0x24,
            0xA3, 0xD3, 0xA4, 0x64, 0x12, 0xAE, 0x1A, 0xF7, 0x2A, 0xB6, 0x65, 0x11, 0x43, 0x3B,
            0x80, 0xE1, 0x8B, 0x00, 0x93, 0x8E, 0x26, 0x26, 0xA8, 0x2B, 0xC7, 0x0C, 0xC0, 0x5E,
        ]
    ));
    static ref yb: Field = Field::new(BigInt::from_bytes_be(
        Sign::Plus,
        &[
            0x69, 0x3F, 0x46, 0x71, 0x6E, 0xB6, 0xBC, 0x24, 0x88, 0x76, 0x20, 0x37, 0x56, 0xC9,
            0xC7, 0x62, 0x4B, 0xEA, 0x73, 0x73, 0x6C, 0xA3, 0x98, 0x40, 0x87, 0x78, 0x9C, 0x1E,
            0x05, 0xA0, 0xC2, 0xD7, 0x3A, 0xD3, 0xFF, 0x1C, 0xE6, 0x7C, 0x39, 0xC4, 0xFD, 0xBD,
            0x13, 0x2C, 0x4E, 0xD7, 0xC8, 0xAD, 0x98, 0x08, 0x79, 0x5B, 0xF2, 0x30, 0xFA, 0x14,
        ]
    ));

    static ref l: BigInt = BigInt::from_bytes_be(
        Sign::Plus,
        &[
            0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x7c, 0xca, 0x23, 0xe9, 0xc4, 0x4e, 0xdb, 0x49, 0xae, 0xd6, 0x36, 0x90, 0x21, 0x6c,
            0xc2, 0x72, 0x8d, 0xc5, 0x8f, 0x55, 0x23, 0x78, 0xc2, 0x92, 0xab, 0x58, 0x44, 0xf3,
        ]
    );
}

#[derive(Debug, Clone)]
pub struct Field(BigInt);

impl Field {
    pub fn new(value: BigInt) -> Self {
        if value < BigInt::zero() {
            Self((&p as &BigInt) + value)
        } else {
            Self(value % &p as &BigInt)
        }
    }

    /// Field inverse (inverse of 0 is 0).
    #[inline]
    pub fn inv(self) -> Self {
        Self::new(self.0.modpow(&(&p as &BigInt - 2), &p))
    }

    /// Compute sign of number, 0 or 1.  The sign function
    /// has the following property:
    /// sign(x) = 1 - sign(-x) if x != 0.
    #[inline]
    pub fn sign(&self) -> BigInt {
        &self.0 % 2
    }

    /// Field square root.  Returns none if square root does not exist.
    /// Note: not presently implemented for p mod 8 = 1 case.
    pub fn sqrt(self) -> crate::Result<Self> {
        // Compute candidate square root.
        let y = self
            .0
            .modpow(&((&p as &BigInt).add(1_u32).div(&4)), &p as &BigInt);
        let y = Self::new(y);
        // Check square root candidate valid.
        if &y * &y == self {
            Ok(y)
        } else {
            Err(Ed448Error::InvalidPoint)
        }
    }

    /// Is the field element the additive identity?
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl PartialEq for Field {
    fn eq(&self, other: &Self) -> bool {
        fn sign_to_choice(sign: Sign) -> Choice {
            match sign {
                Sign::Plus => 1,
                Sign::Minus => 0,
                Sign::NoSign => unreachable!(),
            }
            .into()
        }

        let me = self.0.to_u64_digits();
        let other = other.0.to_u64_digits();
        let val = me.1.ct_eq(&other.1);
        let sign_me = sign_to_choice(me.0);
        let sign_other = sign_to_choice(other.0);
        let sign = sign_me ^ sign_other;
        (val & !sign).into()
    }
}

impl Add for Field {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        self + &other
    }
}

impl Add<&'_ Self> for Field {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self {
        Self::new(self.0 + &rhs.0)
    }
}

impl Add<&'_ Field> for &'_ Field {
    type Output = Field;

    #[inline]
    fn add(self, other: &Field) -> Self::Output {
        self.clone() + other
    }
}

impl Sub for Field {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        self - &other
    }
}

impl Sub<&'_ Self> for Field {
    type Output = Self;

    #[inline]
    fn sub(self, other: &Self) -> Self {
        Self::new(self.0 + &p as &BigInt - &other.0)
    }
}

impl Sub<&'_ Field> for &'_ Field {
    type Output = Field;

    #[inline]
    fn sub(self, other: &Field) -> Field {
        self.clone() - other
    }
}

impl Mul for Field {
    type Output = Self;

    #[inline]
    fn mul(self, other: Self) -> Self {
        self * &other
    }
}

impl Mul<&'_ Self> for Field {
    type Output = Self;

    #[inline]
    fn mul(self, other: &Self) -> Self {
        Self::new(self.0 * &other.0)
    }
}

impl Mul<&'_ Field> for &'_ Field {
    type Output = Field;

    #[inline]
    fn mul(self, other: &Field) -> Field {
        self.clone() * other
    }
}

impl Neg for Field {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self::new(&p as &BigInt - self.0)
    }
}

impl Div for Field {
    type Output = Self;

    #[inline]
    fn div(self, other: Self) -> Self {
        self / &other
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div<&'_ Self> for Field {
    type Output = Self;

    #[inline]
    fn div(self, other: &Self) -> Self {
        self * other.clone().inv()
    }
}

impl Div<&'_ Field> for &'_ Field {
    type Output = Field;

    #[inline]
    fn div(self, other: &'_ Field) -> Field {
        self.clone() / other
    }
}

#[derive(Debug, Clone)]
pub struct Point {
    x: Field,
    y: Field,
    z: Field,
}

impl Point {
    pub fn new(x: &Field, y: &Field) -> crate::Result<Self> {
        // Check that the point is actually on the curve.
        if y * y + x * x == (&f1 as &Field) + &((&d as &Field) * x * x * y * y) {
            Ok(Self {
                x: x.clone(),
                y: y.clone(),
                ..Self::default()
            })
        } else {
            Err(Ed448Error::InvalidPoint)
        }
    }

    /// Order of basepoint.
    #[inline]
    pub fn l() -> &'static BigInt {
        &l as &BigInt
    }

    #[inline]
    pub fn new_stdbase() -> Self {
        Self::new(&f0, &f1).unwrap()
    }

    /// Point doubling.
    pub fn double(self) -> Self {
        // The formulas are from EFD.
        let (x1s, y1s, z1s) = (&self.x * &self.x, &self.y * &self.y, &self.z * &self.z);
        let xys = &self.x + &self.y;
        let F = &x1s + &y1s;
        let J = &F - &(&z1s + &z1s);
        let (x, y, z) = (
            (&xys * &xys - &x1s - &y1s) * &J,
            &F * &(&x1s - &y1s),
            &F * &J,
        );

        Self { x, y, z }
    }

    /// Encode a point representation.
    pub fn encode(&self) -> [u8; KEY_LENGTH] {
        let (xp, yp) = (&self.x / &self.z, &self.y / &self.z);

        // Encode y.
        let mut tmp = yp.0.magnitude().to_bytes_le();
        tmp.resize_with(KEY_LENGTH, Default::default);
        let mut s: [u8; KEY_LENGTH] = tmp.try_into().unwrap();

        // Add sign bit of x to encoding.
        if !xp.sign().is_zero() {
            s[56] |= 0b1000_0000;
        }
        s
    }

    /// Decode a point representation.
    pub fn decode(s: &[u8]) -> crate::Result<Self> {
        // Extract signbit.
        let xs = BigInt::from(s[56] >> 7);
        // Decode y.  If this fails, fail.
        let y = Self::frombytes(s)?;
        // Try to recover x.  If it does not exist, or if zero and xs
        // are wrong, fail.
        let mut x = Self::solve_x2(&y).sqrt()?;
        if x.is_zero() && xs != x.sign() {
            return Err(Ed448Error::InvalidPoint);
        }
        // If sign of x isn't correct, flip it.
        if x.sign() != xs {
            x = -x;
        }
        // Return the constructed point.
        Self::new(&x, &y)
    }

    /// Unserialize number from bits.
    fn frombytes(x: &[u8]) -> crate::Result<Field> {
        let rv = BigInt::from_bytes_le(Sign::Plus, x) % BigInt::from(2).pow(455);
        if &rv < &p as &BigInt {
            Ok(Field::new(rv))
        } else {
            Err(Ed448Error::InvalidPoint)
        }
    }

    /// Solve for x^2.
    #[inline]
    fn solve_x2(y: &Field) -> Field {
        (y * y - &f1 as &Field) / (&d as &Field * y * y - &f1 as &Field)
    }
}

impl Mul<&'_ BigInt> for Point {
    type Output = Self;

    #[inline]
    fn mul(self, x: &BigInt) -> Self {
        self * x.clone()
    }
}

impl Mul<BigInt> for Point {
    type Output = Self;

    fn mul(mut self, mut x: BigInt) -> Self {
        let mut r = Self::new_stdbase();
        while !x.is_zero() {
            if !((&x % 2) as BigInt).is_zero() {
                r = r + &self;
            }
            self = self.double();
            x /= 2;
        }
        r
    }
}

impl Add for Point {
    type Output = Self;

    fn add(self, y: Self) -> Self {
        // The formulas are from EFD.
        let (xcp, ycp, zcp) = (&self.x * &y.x, &self.y * &y.y, &self.z * &y.z);
        let B = &zcp * &zcp;
        let E = &d as &Field * &xcp * &ycp;
        let (F, G) = (&B - &E, B + E);

        let x = &zcp * &F * ((self.x + self.y) * (y.x + y.y) - &xcp - &ycp);
        let (y, z) = (zcp * &G * (ycp - xcp), F * G);

        Self { x, y, z }
    }
}

impl Add<&'_ Self> for Point {
    type Output = Self;

    #[inline]
    fn add(self, other: &Self) -> Self {
        self + other.clone()
    }
}

impl Add<&'_ Point> for &'_ Point {
    type Output = Point;

    #[inline]
    fn add(self, other: &Point) -> Point {
        self.clone() + other.clone()
    }
}

impl PartialEq<Self> for Point {
    fn eq(&self, other: &Self) -> bool {
        // Need to check x1/z1 == x2/z2 and similarly for y, so cross
        // multiply to eliminate divisions.
        let xn1 = &self.x * &other.z;
        let xn2 = &other.x * &self.z;
        let yn1 = &self.y * &other.z;
        let yn2 = &other.y * &self.z;
        xn1 == xn2 && yn1 == yn2
    }
}

impl Default for Point {
    #[inline]
    fn default() -> Self {
        Self {
            x: xb.clone(),
            y: yb.clone(),
            z: Field::new(BigInt::one()),
        }
    }
}

#[cfg(test)]
mod point_encode_round_trip {
    use super::*;
    use crate::private_key::PrivateKey;
    use crate::public_key::PublicKey;
    use core::convert::TryFrom;

    /// Pubkey bytes round-trip: encode → decode → encode must be
    /// idempotent. Otherwise verify fails for any pubkey loaded
    /// from bytes — the verify path internally re-encodes
    /// (`self.as_byte()`) and decodes again, and any drift breaks
    /// the shake256 hash input.
    #[test]
    fn pubkey_encode_decode_round_trip() {
        let mut seed = [0u8; 57];
        seed[0] = 0xAA;
        let sk = PrivateKey::from(seed);
        let pk: PublicKey = (&sk).into();
        let bytes_a = pk.as_byte();
        let pk2 = PublicKey::try_from(&bytes_a[..]).unwrap();
        let bytes_b = pk2.as_byte();
        assert_eq!(bytes_a, bytes_b, "encode → decode → encode must be idempotent");
    }
}
