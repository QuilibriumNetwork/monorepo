//! Packed BDLOP commitment and amount-relation reference.
//!
//! This module supplies commitments and relation components, not a standalone
//! spend verifier. Default node/wallet builds use its QCT3 submodules; execution
//! performs state/authorization checks and delegates amount-proof verification
//! to the isolated worker. Ring arithmetic is variable-time; timing resistance
//! and complete secret erasure are not established.

use crate::rq::Poly;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroize;

pub mod relation;
pub mod transfer;
pub mod shield;
pub mod mint;
pub mod custom_mint;
pub mod mint_claim;
pub mod pending_claim;
pub mod pending_create;
pub mod settlement;
pub mod memo;
pub mod address;
pub mod coin_tree;
pub mod sharded_tree;

pub const BINDING_RANK: usize = 8;
pub const SECRET_RANK: usize = 9;
pub const OPENING_RANK: usize = BINDING_RANK + 1 + SECRET_RANK;
pub const PACKED_POLY_BYTES: usize = 1152;
pub const COMMITMENT_BYTES: usize = (BINDING_RANK + 1) * PACKED_POLY_BYTES;
pub const MAX_PRIVATE_COINS: usize = 128;
const SUITE: &[u8] = b"quil/token/packed-bdlop/v2";
// Fail compilation if the arithmetic backend's ring changes underneath this suite.
const _: () = assert!(Poly::Q == 68_719_476_713 && Poly::D == 256);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Length,
    NoncanonicalCoefficient,
    TooManyCoins,
    Unbalanced,
    InvalidCarry,
    OpeningMismatch,
    InvalidMembership,
    DuplicateKeyImage,
}

fn stream(context: &[u8; 32], purpose: &[u8], seed: Option<&[u8; 32]>) -> impl XofReader {
    let mut h = Shake256::default();
    h.update(SUITE);
    h.update(&Poly::Q.to_le_bytes());
    for dimension in [Poly::D, BINDING_RANK, 1, SECRET_RANK] {
        h.update(&(dimension as u32).to_le_bytes());
    }
    h.update(context);
    h.update(&(purpose.len() as u32).to_le_bytes());
    h.update(purpose);
    if let Some(seed) = seed {
        h.update(seed);
    }
    h.finalize_xof()
}

fn uniform_poly(reader: &mut impl XofReader) -> Poly {
    let mut p = Poly::zero();
    for c in &mut p.c {
        loop {
            let mut bytes = [0u8; 8];
            reader.read(&mut bytes[..5]);
            let v = u64::from_le_bytes(bytes) & ((1u64 << 36) - 1);
            if v < Poly::Q {
                *c = v;
                break;
            }
        }
    }
    p
}

/// Secret opening. Deliberately has no Debug, Clone or wire serialization.
/// Dropping clears coefficient storage; temporary arithmetic/XOF state is not
/// guaranteed to be erased by the current backend.
pub struct AmountOpening {
    r: [Poly; OPENING_RANK],
}

impl AmountOpening {
    /// Expand a fresh independently random private seed, encrypted in the memo.
    /// The caller supplies cryptographic randomness; public fixtures and seed
    /// reuse are unsuitable for real coins. Context is fixed by the suite/network.
    pub fn from_seed(context: &[u8; 32], seed: &[u8; 32]) -> Self {
        let mut reader = stream(context, b"private-opening", Some(seed));
        let r = std::array::from_fn(|_| {
            let mut p = Poly::zero();
            for c in &mut p.c {
                let signed = loop {
                    let mut byte = [0];
                    reader.read(&mut byte);
                    // 250 is divisible by 5: exact uniformity, unlike byte % 5.
                    if byte[0] < 250 {
                        break i64::from(byte[0] % 5) - 2;
                    }
                };
                *c = signed.rem_euclid(Poly::Q as i64) as u64;
            }
            p
        });
        Self { r }
    }
}

impl Drop for AmountOpening {
    fn drop(&mut self) {
        for p in &mut self.r {
            p.c.zeroize();
        }
    }
}

/// Public commitment; the only public wire object supplied by this module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmountCommitment {
    t: [Poly; BINDING_RANK + 1],
}

impl AmountCommitment {
    /// Low coefficient first; each adjacent pair uses nine little-endian bytes.
    /// The polynomial order is t_a[0..8], t_b.
    pub fn to_bytes(&self) -> [u8; COMMITMENT_BYTES] {
        let mut out = [0; COMMITMENT_BYTES];
        encode_polys(&self.t, &mut out);
        out
    }

    /// Check exact size before allocating; reject rather than reduce residues.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        Ok(Self {
            t: decode_polys(bytes)?,
        })
    }
}

fn encode_polys(polys: &[Poly], out: &mut [u8]) {
    assert_eq!(out.len(), polys.len() * PACKED_POLY_BYTES);
    for (p, bytes) in polys.iter().zip(out.chunks_exact_mut(PACKED_POLY_BYTES)) {
        for (pair, dst) in p.c.chunks_exact(2).zip(bytes.chunks_exact_mut(9)) {
            let packed = u128::from(pair[0]) | (u128::from(pair[1]) << 36);
            dst.copy_from_slice(&packed.to_le_bytes()[..9]);
        }
    }
}

fn decode_polys<const N: usize>(bytes: &[u8]) -> Result<[Poly; N], TokenError> {
    if bytes.len() != N * PACKED_POLY_BYTES {
        return Err(TokenError::Length);
    }
    let mut result = std::array::from_fn(|_| Poly::zero());
    for (p, bytes) in result.iter_mut().zip(bytes.chunks_exact(PACKED_POLY_BYTES)) {
        for (pair, src) in p.c.chunks_exact_mut(2).zip(bytes.chunks_exact(9)) {
            let mut raw = [0; 16];
            raw[..9].copy_from_slice(src);
            let packed = u128::from_le_bytes(raw);
            pair[0] = (packed & ((1u128 << 36) - 1)) as u64;
            pair[1] = (packed >> 36) as u64;
            if pair.iter().any(|&c| c >= Poly::Q) {
                return Err(TokenError::NoncanonicalCoefficient);
            }
        }
    }
    Ok(result)
}

/// Public structured matrices A=[I|U|V], B=[0|1|W]. Matrices are private to
/// prevent changing their dimensions or injecting arbitrary caller parameters.
pub struct CommitmentKey {
    u: [Poly; BINDING_RANK],
    v: [[Poly; SECRET_RANK]; BINDING_RANK],
    w: [Poly; SECRET_RANK],
}

impl CommitmentKey {
    /// Deterministic public expansion for this suite.
    pub fn derive(context: &[u8; 32]) -> Self {
        let mut u = stream(context, b"public-U", None);
        let mut v = stream(context, b"public-V", None);
        let mut w = stream(context, b"public-W", None);
        Self {
            u: std::array::from_fn(|_| uniform_poly(&mut u)),
            v: std::array::from_fn(|_| std::array::from_fn(|_| uniform_poly(&mut v))),
            w: std::array::from_fn(|_| uniform_poly(&mut w)),
        }
    }

    pub fn commit(&self, amount: u128, opening: &AmountOpening) -> AmountCommitment {
        let r = &opening.r;
        let mut t = std::array::from_fn(|_| Poly::zero());
        for i in 0..BINDING_RANK {
            t[i] = r[i].add(&self.u[i].mul_ntt(&r[BINDING_RANK]));
            for j in 0..SECRET_RANK {
                t[i] = t[i].add(&self.v[i][j].mul_ntt(&r[BINDING_RANK + 1 + j]));
            }
        }
        t[BINDING_RANK] = r[BINDING_RANK].add(&amount_message(amount));
        for j in 0..SECRET_RANK {
            t[BINDING_RANK] = t[BINDING_RANK].add(&self.w[j].mul_ntt(&r[BINDING_RANK + 1 + j]));
        }
        AmountCommitment { t }
    }
}

fn amount_message(amount: u128) -> Poly {
    let mut p = Poly::zero();
    for j in 0..128 {
        p.c[j] = ((amount >> j) & 1) as u64;
    }
    p
}

/// Prover-side exact carry witness. Never send this in place of a ZK proof.
/// Carries contain information about the private amounts.
pub struct BalanceTrace {
    carries: [i16; 17],
}

impl Drop for BalanceTrace {
    fn drop(&mut self) {
        self.carries.zeroize();
    }
}

fn limb_difference(
    inputs: &[u128],
    outputs: &[u128],
    inflow: u128,
    outflow: u128,
    j: usize,
) -> i32 {
    let limb = |v: u128| ((v >> (8 * j)) & 255) as i32;
    inputs.iter().map(|&v| limb(v)).sum::<i32>() + limb(inflow)
        - outputs.iter().map(|&v| limb(v)).sum::<i32>()
        - limb(outflow)
}

fn check_count(inputs: &[u128], outputs: &[u128]) -> Result<(), TokenError> {
    if inputs.len().saturating_add(outputs.len()) > MAX_PRIVATE_COINS {
        Err(TokenError::TooManyCoins)
    } else {
        Ok(())
    }
}

impl BalanceTrace {
    /// Supports equal totals exceeding u128::MAX without wrapping either side.
    /// Public inflow/outflow are single u128 aggregates validated by execution.
    pub fn build(
        inputs: &[u128],
        outputs: &[u128],
        inflow: u128,
        outflow: u128,
    ) -> Result<Self, TokenError> {
        check_count(inputs, outputs)?;
        let mut result = Self { carries: [0; 17] };
        for j in 0..16 {
            let residual =
                limb_difference(inputs, outputs, inflow, outflow, j) + i32::from(result.carries[j]);
            if residual % 256 != 0 {
                return Err(TokenError::Unbalanced);
            }
            let next = residual / 256;
            if !(-256..=255).contains(&next) {
                return Err(TokenError::InvalidCarry);
            }
            result.carries[j + 1] = next as i16;
        }
        result.check(inputs, outputs, inflow, outflow)?;
        Ok(result)
    }

    /// Reference check over integers; a proof compiler must constrain the same
    /// endpoint, binary-range and limb equations inside its proof relation.
    pub fn check(
        &self,
        inputs: &[u128],
        outputs: &[u128],
        inflow: u128,
        outflow: u128,
    ) -> Result<(), TokenError> {
        check_count(inputs, outputs)?;
        if self.carries[0] != 0 || self.carries[16] != 0 {
            return Err(TokenError::Unbalanced);
        }
        if self.carries.iter().any(|&c| !(-256..=255).contains(&c)) {
            return Err(TokenError::InvalidCarry);
        }
        for j in 0..16 {
            let residual = limb_difference(inputs, outputs, inflow, outflow, j)
                + i32::from(self.carries[j])
                - 256 * i32::from(self.carries[j + 1]);
            if residual != 0 {
                return Err(TokenError::Unbalanced);
            }
        }
        Ok(())
    }
}

/// Local witness consistency only. Input commitments are PRIVATE in the
/// eventual transaction proof. This function does not verify membership,
/// ownership, authorization or a zero-knowledge proof.
pub fn check_amount_witness(
    key: &CommitmentKey,
    inputs: &[(u128, &AmountOpening, &AmountCommitment)],
    outputs: &[(u128, &AmountOpening, &AmountCommitment)],
    inflow: u128,
    outflow: u128,
) -> Result<BalanceTrace, TokenError> {
    if inputs.len().saturating_add(outputs.len()) > MAX_PRIVATE_COINS {
        return Err(TokenError::TooManyCoins);
    }
    for &(amount, opening, commitment) in inputs.iter().chain(outputs) {
        if key.commit(amount, opening) != *commitment {
            return Err(TokenError::OpeningMismatch);
        }
    }
    let mut input_amounts: Vec<_> = inputs.iter().map(|v| v.0).collect();
    let mut output_amounts: Vec<_> = outputs.iter().map(|v| v.0).collect();
    let result = BalanceTrace::build(&input_amounts, &output_amounts, inflow, outflow);
    input_amounts.zeroize();
    output_amounts.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn matches_independent_python_vector() {
        // Generated independently by a reference script using hashlib and
        // integer schoolbook arithmetic.
        let key = CommitmentKey::derive(&[7; 32]);
        let opening = AmountOpening::from_seed(&[7; 32], &[9; 32]);
        let commitment = key.commit((1u128 << 127) + 123456789, &opening);
        let hash = |bytes: &[u8]| {
            Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            hash(&commitment.to_bytes()),
            "f2837d5b19403d60686a8ccfe82c19a45e918eeaddf1e0e10ca0879bbbbaaca3"
        );
        let signed: Vec<u8> = opening
            .r
            .iter()
            .flat_map(|p| {
                p.c.iter().map(|&c| {
                    let x = if c > Poly::Q / 2 {
                        c as i64 - Poly::Q as i64
                    } else {
                        c as i64
                    };
                    x as i8 as u8
                })
            })
            .collect();
        assert_eq!(
            hash(&signed),
            "a7685e36f677fef97756dc0245a44328e5dff03e050324e5cbcf14996fa9920c"
        );
    }

    #[test]
    fn canonical_encoding_boundaries() {
        let mut c = AmountCommitment {
            t: std::array::from_fn(|_| Poly::zero()),
        };
        for p in &mut c.t {
            for (i, v) in p.c.iter_mut().enumerate() {
                *v = [0, 1, (1 << 35) + 19, Poly::Q - 1][i % 4];
            }
        }
        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), 10_368);
        assert_eq!(AmountCommitment::from_bytes(&bytes).unwrap(), c);
        assert_eq!(
            AmountCommitment::from_bytes(&bytes[..bytes.len() - 1]),
            Err(TokenError::Length)
        );
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(
            AmountCommitment::from_bytes(&trailing),
            Err(TokenError::Length)
        );
        for index in [0, 1, 255, 256, 2303] {
            let mut bad = c.clone();
            bad.t[index / Poly::D].c[index % Poly::D] = Poly::Q;
            assert_eq!(
                AmountCommitment::from_bytes(&bad.to_bytes()),
                Err(TokenError::NoncanonicalCoefficient)
            );
        }
    }

    #[test]
    fn structured_commitment_matches_schoolbook_and_joint_identity() {
        let key = CommitmentKey::derive(&[7; 32]);
        let opening = AmountOpening::from_seed(&[7; 32], &[9; 32]);
        assert!(opening.r.iter().all(|p| p.inf_norm() <= 2));
        let amount = (1u128 << 127) + 123456789;
        let c = key.commit(amount, &opening);
        let r = &opening.r;
        for i in 0..BINDING_RANK {
            let mut a = r[i].add(&key.u[i].mul(&r[BINDING_RANK]));
            let mut transformed = r[i].sub(&key.u[i].mul(&amount_message(amount)));
            for j in 0..SECRET_RANK {
                a = a.add(&key.v[i][j].mul(&r[BINDING_RANK + 1 + j]));
                transformed = transformed.add(
                    &key.v[i][j]
                        .sub(&key.u[i].mul(&key.w[j]))
                        .mul(&r[BINDING_RANK + 1 + j]),
                );
            }
            assert_eq!(a, c.t[i]);
            assert_eq!(transformed, c.t[i].sub(&key.u[i].mul(&c.t[BINDING_RANK])));
        }
        let mut b = r[BINDING_RANK].add(&amount_message(amount));
        for j in 0..SECRET_RANK {
            b = b.add(&key.w[j].mul(&r[BINDING_RANK + 1 + j]));
        }
        assert_eq!(b, c.t[BINDING_RANK]);
    }

    #[test]
    fn amounts_and_seed_context_are_not_truncated() {
        let key = CommitmentKey::derive(&[0; 32]);
        let opening = AmountOpening::from_seed(&[0; 32], &[0; 32]);
        let c = key.commit(0, &opening);
        for j in 0..128 {
            let other = key.commit(1u128 << j, &opening);
            assert_eq!(&c.t[..BINDING_RANK], &other.t[..BINDING_RANK]);
            assert_eq!(
                other.t[BINDING_RANK].sub(&c.t[BINDING_RANK]),
                Poly::monomial(j)
            );
        }
        for j in [0, 8, 16, 31] {
            let mut seed = [0; 32];
            seed[j] = 1;
            assert!(opening.r != AmountOpening::from_seed(&[0; 32], &seed).r);
        }
        assert!(opening.r != AmountOpening::from_seed(&[1; 32], &[0; 32]).r);
        assert_ne!(c, CommitmentKey::derive(&[1; 32]).commit(0, &opening));
    }

    #[test]
    fn conservation_handles_large_totals_and_both_carry_signs() {
        for (inputs, outputs) in [
            (vec![255, 1], vec![256]),
            (vec![256], vec![255, 1]),
            (vec![u128::MAX; 64], vec![u128::MAX; 64]),
            (vec![u128::MAX, 1], vec![u128::MAX - 1, 2]),
        ] {
            let mut trace = BalanceTrace::build(&inputs, &outputs, 0, 0).unwrap();
            trace.check(&inputs, &outputs, 0, 0).unwrap();
            trace.carries[1] += 1;
            assert!(trace.check(&inputs, &outputs, 0, 0).is_err());
        }
        assert!(BalanceTrace::build(&[u128::MAX, 1], &[0], 0, 0).is_err());
        assert!(BalanceTrace::build(&[0], &[u128::MAX, 1], 0, 0).is_err());
        assert!(BalanceTrace::build(&[1; 129], &[129], 0, 0).is_err());
        assert!(BalanceTrace::build(&[9], &[7], 0, 2).is_ok());
        assert!(BalanceTrace::build(&[], &[7], 7, 0).is_ok());
    }

    #[test]
    fn two_input_two_output_amount_witness() {
        let key = CommitmentKey::derive(&[4; 32]);
        let openings: [_; 4] =
            std::array::from_fn(|i| AmountOpening::from_seed(&[4; 32], &[i as u8; 32]));
        let amounts = [9, 17, 6, 18];
        let commitments: [_; 4] = std::array::from_fn(|i| key.commit(amounts[i], &openings[i]));
        let inputs = [
            (9, &openings[0], &commitments[0]),
            (17, &openings[1], &commitments[1]),
        ];
        let outputs = [
            (6, &openings[2], &commitments[2]),
            (18, &openings[3], &commitments[3]),
        ];
        assert!(check_amount_witness(&key, &inputs, &outputs, 0, 2).is_ok());
        assert!(check_amount_witness(&key, &inputs, &outputs, 0, 1).is_err());
        let changed = [
            (7, &openings[2], &commitments[2]),
            (17, &openings[3], &commitments[3]),
        ];
        assert!(matches!(
            check_amount_witness(&key, &inputs, &changed, 0, 2),
            Err(TokenError::OpeningMismatch)
        ));
    }
}
