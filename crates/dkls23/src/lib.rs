//! A library for dealing with the `DKLs23` protocol (see <https://eprint.iacr.org/2023/765.pdf>)
//! and related protocols.
//!
//! Written and used by Alore.
#![recursion_limit = "512"]
#![forbid(unsafe_code)]

pub mod protocols;
pub mod utilities;

// The following constants should not be changed!
// They are the same as the reference implementation of DKLs19:
// https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/lib.rs

/// Computational security parameter `lambda_c` from `DKLs23`.
/// We take it to be the same as the parameter `kappa`.
pub const RAW_SECURITY: u16 = 256;
/// `RAW_SECURITY` divided by 8 (used for arrays of bytes)
pub const SECURITY: u16 = 32;

/// Statistical security parameter `lambda_s` from `DKLs23`.
pub const STAT_SECURITY: u16 = 80;

// ---------------------------------------------------------------------------
// Curve-generic support
// ---------------------------------------------------------------------------

use elliptic_curve::group::Group;
use elliptic_curve::{Curve, CurveArithmetic};

/// Trait alias that captures all elliptic-curve bounds required by DKLs23.
///
/// It is implemented for [`k256::Secp256k1`] and [`p256::NistP256`].
///
/// Because Rust does not propagate `where` clauses from a trait definition to
/// its users, every generic function `fn foo<C: DklsCurve>(...)` must repeat
/// the associated-type bounds it actually needs (e.g.
/// `C::Scalar: Reduce<U256>`).  The trait itself is intentionally kept narrow
/// so that adding a new curve only requires one `impl` line.
pub trait DklsCurve: CurveArithmetic + Curve + 'static {}

impl DklsCurve for k256::Secp256k1 {}
impl DklsCurve for p256::NistP256 {}

/// Returns the canonical generator of the curve in affine coordinates.
///
/// This abstracts over `ProjectivePoint::generator().to_affine()` which is the
/// idiomatic way to obtain the generator in the RustCrypto ecosystem (the
/// generator lives on `ProjectivePoint` via [`group::Group::generator`] and is
/// converted to affine via [`group::Curve::to_affine`]).
pub fn generator<C: DklsCurve>() -> C::AffinePoint
where
    C::ProjectivePoint: Group,
{
    use elliptic_curve::group::Curve as _;
    C::ProjectivePoint::generator().to_affine()
}

/// Returns the identity (point at infinity) in affine coordinates.
///
/// In the RustCrypto elliptic-curve crates, `AffinePoint::default()` yields
/// the identity element.
pub fn identity<C: DklsCurve>() -> C::AffinePoint
where
    C::AffinePoint: Default,
{
    C::AffinePoint::default()
}
