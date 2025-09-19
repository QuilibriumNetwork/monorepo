// This module provides adapter types to transition from curve25519-dalek to ed448_goldilocks_plus

extern crate alloc;

#[cfg(feature = "clear_on_drop")]
use clear_on_drop::clear::Clear;
use ed448_goldilocks_plus::elliptic_curve::hash2curve::ExpandMsgXmd;
use ed448_goldilocks_plus::sha3::Sha3_256;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use digest::{ExtendableOutput, Input, XofReader};
use ed448_goldilocks_plus::{
    CompressedDecaf, DecafPoint, Scalar as DecafScalar, ScalarBytes, WideScalarBytes,
};
use rand_core::{CryptoRng, RngCore};
use std::borrow::Borrow;
use subtle::{Choice, ConstantTimeEq};

// Point adapter for use in place of DecafPoint
#[derive(Copy, Clone, Debug)]
pub struct Point(pub DecafPoint);

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        // Compare the compressed representations for equality
        self.compress().as_bytes() == other.compress().as_bytes()
    }
}

// Compressed point adapter for use in place of CompressedDecaf
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct CompressedPoint(pub CompressedDecaf);

// Implement ConditionallySelectable for Point
impl subtle::ConditionallySelectable for Point {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // Manual implementation using a mask
        if choice.unwrap_u8() == 1 {
            *b
        } else {
            *a
        }
    }

    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        // Manual implementation using conditional_select
        if choice.unwrap_u8() == 1 {
            *self = *other;
        }
    }
}

// For serde compatibility
impl serde::Serialize for Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let compressed = self.compress();
        let bytes = compressed.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

// For serde compatibility
impl<'de> serde::Deserialize<'de> for Point {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PointVisitor;

        impl<'de> serde::de::Visitor<'de> for PointVisitor {
            type Value = Point;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a 56-byte compressed point")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 56 {
                    return Err(E::custom("compressed point must be 56 bytes"));
                }

                let compressed = CompressedPoint::from_slice(v);
                compressed
                    .decompress()
                    .ok_or_else(|| E::custom("invalid compressed point"))
            }
        }

        deserializer.deserialize_bytes(PointVisitor)
    }
}

// For serde compatibility
impl serde::Serialize for CompressedPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

// For serde compatibility
impl<'de> serde::Deserialize<'de> for CompressedPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CompressedPointVisitor;

        impl<'de> serde::de::Visitor<'de> for CompressedPointVisitor {
            type Value = CompressedPoint;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a 56-byte compressed point")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 56 {
                    return Err(E::custom("compressed point must be 56 bytes"));
                }

                Ok(CompressedPoint::from_slice(v))
            }
        }

        deserializer.deserialize_bytes(CompressedPointVisitor)
    }
}

// Scalar adapter for use in place of curve25519_dalek::scalar::Scalar
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Scalar(pub DecafScalar);

// Constants to replace RISTRETTO_BASEPOINT_POINT and RISTRETTO_BASEPOINT_COMPRESSED
lazy_static::lazy_static! {
    pub static ref BASEPOINT_POINT: Point = {
        let point = DecafPoint::GENERATOR;

        Point(point)
    };
    pub static ref BASEPOINT_COMPRESSED: CompressedPoint = BASEPOINT_POINT.compress();
}

// Implementation for Point to replicate ed25519's RistrettoPoint's API
impl Point {
    pub fn from_uniform_bytes(bytes: &[u8; 112]) -> Self {
        Point(DecafPoint::hash::<ExpandMsgXmd<Sha3_256>>(bytes, &[]))
    }

    pub fn compress(&self) -> CompressedPoint {
        CompressedPoint(self.0.compress())
    }

    pub fn hash_from_bytes<D>(bytes: &[u8]) -> Self
    where
        D: Input + ExtendableOutput + Default,
    {
        // Generate uniform bytes from the hash and convert to a point
        let mut hash = D::default();
        hash.input(bytes);
        let mut output = [0u8; 112];
        hash.xof_result().read(&mut output);
        Self::from_uniform_bytes(&output)
    }

    pub fn multiscalar_mul<I, J>(scalars: I, points: J) -> Self
    where
        I: IntoIterator,
        I::Item: core::borrow::Borrow<Scalar>,
        J: IntoIterator,
        J::Item: core::borrow::Borrow<Point>,
    {
        // Implement multiscalar multiplication for Decaf
        let mut result = DecafPoint::IDENTITY;

        for (scalar, point) in scalars.into_iter().zip(points.into_iter()) {
            let scalar_ref = scalar.borrow().0;
            let point_ref = point.borrow().0;
            result = result + (scalar_ref * point_ref);
        }

        Point(result)
    }

    pub fn vartime_multiscalar_mul<I, J>(scalars: I, points: J) -> Self
    where
        I: IntoIterator,
        I::Item: core::borrow::Borrow<Scalar>,
        J: IntoIterator,
        J::Item: core::borrow::Borrow<Point>,
    {
        // For Decaf, we'll use the same implementation as regular multiscalar_mul
        // since there's no vartime-specific implementation
        Self::multiscalar_mul(scalars, points)
    }

    pub fn identity() -> Self {
        Point(DecafPoint::IDENTITY)
    }

    pub fn is_identity(&self) -> Choice {
        self.0.ct_eq(&DecafPoint::IDENTITY)
    }
}

// Implementation for point operation traits
impl Add<Point> for Point {
    type Output = Point;

    fn add(self, other: Point) -> Point {
        Point(self.0 + other.0)
    }
}

impl Add<&Point> for Point {
    type Output = Point;

    fn add(self, other: &Point) -> Point {
        Point(self.0 + other.0)
    }
}

impl Add<Point> for &Point {
    type Output = Point;

    fn add(self, other: Point) -> Point {
        Point(self.0 + other.0)
    }
}

impl Add<&Point> for &Point {
    type Output = Point;

    fn add(self, other: &Point) -> Point {
        Point(self.0 + other.0)
    }
}

impl AddAssign<Point> for Point {
    fn add_assign(&mut self, other: Point) {
        self.0 = self.0 + other.0;
    }
}

impl AddAssign<&Point> for Point {
    fn add_assign(&mut self, other: &Point) {
        self.0 = self.0 + other.0;
    }
}

impl Sub<Point> for Point {
    type Output = Point;

    fn sub(self, other: Point) -> Point {
        Point(self.0 - other.0)
    }
}

impl Sub<&Point> for Point {
    type Output = Point;

    fn sub(self, other: &Point) -> Point {
        Point(self.0 - other.0)
    }
}

impl Sub<Point> for &Point {
    type Output = Point;

    fn sub(self, other: Point) -> Point {
        Point(self.0 - other.0)
    }
}

impl Sub<&Point> for &Point {
    type Output = Point;

    fn sub(self, other: &Point) -> Point {
        Point(self.0 - other.0)
    }
}

impl SubAssign<Point> for Point {
    fn sub_assign(&mut self, other: Point) {
        self.0 = self.0 - other.0;
    }
}

impl SubAssign<&Point> for Point {
    fn sub_assign(&mut self, other: &Point) {
        self.0 = self.0 - other.0;
    }
}

impl Mul<Scalar> for Point {
    type Output = Point;

    fn mul(self, scalar: Scalar) -> Point {
        Point(self.0 * scalar.0)
    }
}

impl Mul<&Scalar> for Point {
    type Output = Point;

    fn mul(self, scalar: &Scalar) -> Point {
        Point(self.0 * scalar.0)
    }
}

impl Mul<Scalar> for &Point {
    type Output = Point;

    fn mul(self, scalar: Scalar) -> Point {
        Point(self.0 * scalar.0)
    }
}

impl Mul<&Scalar> for &Point {
    type Output = Point;

    fn mul(self, scalar: &Scalar) -> Point {
        Point(self.0 * scalar.0)
    }
}

// Implement the Neg trait for Point
impl Neg for Point {
    type Output = Point;

    fn neg(self) -> Point {
        Point(-self.0)
    }
}

impl Neg for &Point {
    type Output = Point;

    fn neg(self) -> Point {
        Point(-self.0)
    }
}

impl MulAssign<Scalar> for Point {
    fn mul_assign(&mut self, scalar: Scalar) {
        self.0 = self.0 * scalar.0;
    }
}

impl MulAssign<&Scalar> for Point {
    fn mul_assign(&mut self, scalar: &Scalar) {
        self.0 = self.0 * scalar.0;
    }
}

impl Sum for Point {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        iter.fold(Self::identity(), |acc, x| acc + x)
    }
}

impl<'a> Sum<&'a Point> for Point {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        iter.fold(Self::identity(), |acc, x| acc + *x)
    }
}

// Implementation for CompressedPoint to replicate CompressedDecaf's API
impl CompressedPoint {
    pub fn from_slice(bytes: &[u8]) -> Self {
        if bytes.len() != 56 {
          return CompressedPoint(CompressedDecaf::IDENTITY)
        }
        let mut buf = [0u8; 56];
        buf[..56].copy_from_slice(&bytes[..56]);

        CompressedPoint(CompressedDecaf(buf))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn decompress(&self) -> Option<Point> {
        self.0.decompress().map(Point).into_option()
    }

    pub fn decompress_or<F>(&self, or_else: F) -> Point
    where
        F: FnOnce() -> Point,
    {
        self.decompress().unwrap_or_else(or_else)
    }

    pub fn to_bytes(&self) -> [u8; 56] {
        // Ed448 points are 56 bytes
        let mut bytes = [0u8; 56];
        bytes.copy_from_slice(self.0.as_bytes());
        bytes
    }
}

// Implementation for Scalar to replicate curve25519_dalek::scalar::Scalar's API
impl Scalar {
    pub fn random<
        R: RngCore
            + CryptoRng
            + ed448_goldilocks_plus::rand_core::RngCore
            + ed448_goldilocks_plus::rand_core::CryptoRng,
    >(
        rng: &mut R,
    ) -> Self {
        // Generate a random scalar for Decaf
        Scalar(DecafScalar::random(rng))
    }

    pub fn hash_from_bytes<D>(bytes: &[u8]) -> Self
    where
        D: Input + ExtendableOutput + Default,
    {
        // Generate uniform bytes from the hash and convert to a point
        let mut hash = D::default();
        hash.input(bytes);
        let mut output = [0u8; 56];
        hash.xof_result().read(&mut output);
        Self::from_bits(output)
    }

    pub fn from_bytes_mod_order(bytes: [u8; 56]) -> Self {
        let mut buf: [u8; 57] = [0; 57];
        buf[..56].copy_from_slice(&bytes);
        Scalar(DecafScalar::from_bytes_mod_order(
            &ScalarBytes::clone_from_slice(&buf),
        ))
    }

    pub fn from_bytes_mod_order_wide(bytes: [u8; 114]) -> Self {
        Scalar(DecafScalar::from_bytes_mod_order_wide(
            &WideScalarBytes::clone_from_slice(&bytes),
        ))
    }

    pub fn from_canonical_bytes(bytes: [u8; 56]) -> Option<Self> {
        let mut buf: [u8; 57] = [0; 57];
        buf[..56].copy_from_slice(&bytes);
        DecafScalar::from_canonical_bytes(&ScalarBytes::clone_from_slice(&buf))
            .into_option()
            .map(|s| Scalar(s))
    }

    pub fn from_bits(bytes: [u8; 56]) -> Self {
        Scalar(DecafScalar::from_bytes(&bytes))
    }

    pub fn invert(&self) -> Self {
        // Invert the scalar
        Scalar(self.0.invert())
    }

    pub fn batch_invert(scalars: &mut [Scalar]) -> Scalar {
        // Simple implementation: invert each scalar individually
        // TODO: implement an actual batch inversion algorithm
        let mut res = Scalar::one();
        for scalar in scalars.iter_mut() {
            *scalar = scalar.invert();
            res *= *scalar;
        }

        // There is a subtlety to how ed25519-dalek implements this, we need to calculate
        // the product of all inverted elements and return that value.
        res
    }

    pub fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    pub fn to_bytes(&self) -> [u8; 56] {
        self.0.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8] {
        static mut CACHED_BYTES: [u8; 56] = [0u8; 56];
        unsafe {
            CACHED_BYTES.copy_from_slice(&self.0.to_bytes());
            &CACHED_BYTES
        }
    }

    pub fn zero() -> Self {
        // Create a zero scalar using u64 conversion
        Scalar(DecafScalar::from(0u64))
    }

    pub fn one() -> Self {
        // Create a one scalar using u64 conversion
        Scalar(DecafScalar::from(1u64))
    }

    pub fn from(value: u64) -> Self {
        // Convert a u64 to a scalar
        Scalar(DecafScalar::from(value))
    }
}

// Implement From<u64> for Scalar
impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Scalar::from(value)
    }
}

// For serde compatibility
impl serde::Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

// For serde compatibility
impl<'de> serde::Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ScalarVisitor;

        impl<'de> serde::de::Visitor<'de> for ScalarVisitor {
            type Value = Scalar;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a 56-byte scalar")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 56 {
                    return Err(E::custom("scalar must be 56 bytes"));
                }

                let mut bytes = [0u8; 56];
                bytes.copy_from_slice(v);
                Ok(Scalar::from_bits(bytes))
            }
        }

        deserializer.deserialize_bytes(ScalarVisitor)
    }
}

// Implement scalar operation traits
impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        Scalar(self.0 + other.0)
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar(self.0 + other.0)
    }
}

impl Add<Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        Scalar(self.0 + other.0)
    }
}

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar(self.0 + other.0)
    }
}

impl AddAssign<Scalar> for Scalar {
    fn add_assign(&mut self, other: Scalar) {
        self.0 = self.0 + other.0;
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, other: &Scalar) {
        self.0 = self.0 + other.0;
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Scalar {
        Scalar(self.0 * other.0)
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar(self.0 * other.0)
    }
}

// Add Scalar * Point implementation
impl Mul<Point> for Scalar {
    type Output = Point;

    fn mul(self, point: Point) -> Point {
        point * self
    }
}

impl Mul<&Point> for Scalar {
    type Output = Point;

    fn mul(self, point: &Point) -> Point {
        point.clone() * self
    }
}

impl Mul<Point> for &Scalar {
    type Output = Point;

    fn mul(self, point: Point) -> Point {
        point * self
    }
}

impl Mul<&Point> for &Scalar {
    type Output = Point;

    fn mul(self, point: &Point) -> Point {
        Point(self.0 * point.0)
    }
}

impl Mul<Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Scalar {
        Scalar(self.0 * other.0)
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar(self.0 * other.0)
    }
}

impl MulAssign<Scalar> for Scalar {
    fn mul_assign(&mut self, other: Scalar) {
        self.0 = self.0 * other.0;
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, other: &Scalar) {
        self.0 = self.0 * other.0;
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        Scalar(self.0 - other.0)
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Scalar(self.0 - other.0)
    }
}

impl Sub<Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        Scalar(self.0 - other.0)
    }
}

impl Sub<&Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Scalar(self.0 - other.0)
    }
}

impl SubAssign<Scalar> for Scalar {
    fn sub_assign(&mut self, other: Scalar) {
        self.0 = self.0 - other.0;
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, other: &Scalar) {
        self.0 = self.0 - other.0;
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Scalar(-self.0)
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Scalar(-self.0)
    }
}

impl Sum for Scalar {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        iter.fold(Self::zero(), |acc, x| acc + x)
    }
}

impl<'a> Sum<&'a Scalar> for Scalar {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        iter.fold(Self::zero(), |acc, x| acc + *x)
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(feature = "clear_on_drop")]
impl Clear for Scalar {
    fn clear(&mut self) {
        // Create a default zero value
        self.0 = DecafScalar::from(0u64);
    }
}

// Utility function for inner product
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut result = Scalar::zero();
    for (a_i, b_i) in a.iter().zip(b.iter()) {
        result = result + (*a_i * *b_i);
    }
    result
}
