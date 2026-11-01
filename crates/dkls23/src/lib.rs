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
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use elliptic_curve::{Curve, CurveArithmetic};
use k256::sha2::Sha256;

/// Trait alias that captures all elliptic-curve bounds required by DKLs23.
///
/// It is implemented for [`k256::Secp256k1`] and [`p256::NistP256`].
///
/// Because Rust does not propagate `where` clauses from a trait definition to
/// its users, every generic function `fn foo<C: DklsCurve>(...)` must repeat
/// the associated-type bounds it actually needs (e.g.
/// `C::Scalar: Reduce<U256>`).  The trait itself is intentionally kept narrow
/// so that adding a new curve only requires one `impl`.
pub trait DklsCurve: CurveArithmetic + Curve + 'static {
    /// Hashes the concatenation of `msgs` to a point on the curve with the
    /// `XMD:SHA-256_SSWU_RO_` suite of RFC 9380, domain-separated by `dst`.
    ///
    /// Nobody knows the discrete logarithm of the result with respect to
    /// the generator, which the base OT requires of its point `h`.
    fn hash_to_curve(msgs: &[&[u8]], dst: &[u8]) -> Self::AffinePoint;
}

impl DklsCurve for k256::Secp256k1 {
    fn hash_to_curve(msgs: &[&[u8]], dst: &[u8]) -> k256::AffinePoint {
        <Self as GroupDigest>::hash_from_bytes::<ExpandMsgXmd<Sha256>>(msgs, &[dst])
            .expect("hash-to-curve only fails for an empty domain separation tag")
            .to_affine()
    }
}

impl DklsCurve for p256::NistP256 {
    fn hash_to_curve(msgs: &[&[u8]], dst: &[u8]) -> p256::AffinePoint {
        <Self as GroupDigest>::hash_from_bytes::<ExpandMsgXmd<Sha256>>(msgs, &[dst])
            .expect("hash-to-curve only fails for an empty domain separation tag")
            .to_affine()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::point::AffineCoordinates;

    /// Checks [`DklsCurve::hash_to_curve`] against a test vector of
    /// RFC 9380, Appendix J (the curve's `XMD:SHA-256_SSWU_RO_` suite).
    fn check_vector<C: DklsCurve>(dst: &[u8], msg: &[u8], x: &str, y: &str) {
        let point = C::hash_to_curve(&[msg], dst);
        let point_x = point.x();
        let expected_x = hex::decode(x).unwrap();
        let y = hex::decode(y).unwrap();

        assert_eq!(AsRef::<[u8]>::as_ref(&point_x), expected_x.as_slice());
        assert_eq!(bool::from(point.y_is_odd()), y[y.len() - 1] % 2 == 1);
    }

    #[test]
    fn test_hash_to_curve_secp256k1() {
        let dst = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";
        check_vector::<k256::Secp256k1>(
            dst,
            b"",
            "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
            "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067",
        );
        check_vector::<k256::Secp256k1>(
            dst,
            b"abc",
            "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
            "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6",
        );
    }

    #[test]
    fn test_hash_to_curve_p256() {
        let dst = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
        check_vector::<p256::NistP256>(
            dst,
            b"",
            "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
            "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
        );
        check_vector::<p256::NistP256>(
            dst,
            b"abc",
            "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
            "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
        );
    }
}
