//! Shared modular arithmetic over `Z_q` (`q < 2^62`, so a product of two
//! residues is `< 2^124` and fits `u128`; accumulate mod `q` to keep every
//! intermediate `< 2^128`), plus a tiny deterministic PRG.

/// `(a + b) mod q`.
// Retained scalar arithmetic helpers; confidential relations use rq operations.
#[allow(dead_code)]
pub(crate) fn add_mod(a: u128, b: u128, q: u128) -> u128 {
    (a + b) % q
}

/// Element-wise `(a + b) mod q`.
// Retained scalar arithmetic helpers; confidential relations use rq operations.
#[allow(dead_code)]
pub(crate) fn add_vec_mod(a: &[u128], b: &[u128], q: u128) -> Vec<u128> {
    a.iter().zip(b).map(|(x, y)| (x + y) % q).collect()
}

/// `Σ_j a[j]·r[j] mod q`, with signed `r` mapped into `[0, q)`.
// Retained scalar arithmetic helpers; confidential relations use rq operations.
#[allow(dead_code)]
pub(crate) fn dot_mod(a: &[u128], r: &[i128], q: u128) -> u128 {
    let mut acc: u128 = 0;
    for (aj, rj) in a.iter().zip(r) {
        acc = (acc + aj % q * signed_mod(*rj, q)) % q;
    }
    acc
}

/// Matrix-vector product `A·v mod q` (signed `v`).
// Retained scalar arithmetic helpers; confidential relations use rq operations.
#[allow(dead_code)]
pub(crate) fn matvec(a: &[Vec<u128>], v: &[i128], q: u128) -> Vec<u128> {
    a.iter().map(|row| dot_mod(row, v, q)).collect()
}

/// Map a signed integer into `[0, q)`.
// Retained scalar arithmetic helpers; confidential relations use rq operations.
#[allow(dead_code)]
pub(crate) fn signed_mod(x: i128, q: u128) -> u128 {
    let qi = q as i128;
    (((x % qi) + qi) % qi) as u128
}

/// Infinity norm of a signed vector.
// Retained scalar arithmetic helpers; confidential relations use rq operations.
#[allow(dead_code)]
pub(crate) fn inf_norm(v: &[i128]) -> i128 {
    v.iter().map(|x| x.abs()).max().unwrap_or(0)
}

/// SplitMix64 — a tiny deterministic PRG for reproducible public data and
/// test randomness (no external RNG dependency).
pub struct SplitMix64(u64, Option<SecretStream>);

/// Full-width prover entropy. Integer conversion is for deterministic fixtures
/// and public experiments only; wallets must supply 32 bytes from their CSPRNG.
#[derive(Clone, Copy)]
pub struct ProofSeed([u8; 32]);

impl From<[u8; 32]> for ProofSeed {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<u64> for ProofSeed {
    fn from(fixture: u64) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/fixture-seed/v2");
        h.update(fixture.to_le_bytes());
        Self(h.finalize().into())
    }
}

impl ProofSeed {
    pub fn to_le_bytes(self) -> [u8; 32] {
        self.0
    }
}

// Existing prover call sites use XOR to label child streams. Hash the label
// with all 256 seed bits instead of truncating or algebraically mixing keys.
impl std::ops::BitXor<u64> for ProofSeed {
    type Output = Self;
    fn bitxor(self, label: u64) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/prover-child/v2");
        h.update(self.0);
        h.update(label.to_le_bytes());
        Self(h.finalize().into())
    }
}

struct SecretStream {
    seed: ProofSeed,
    counter: u64,
    block: [u8; 32],
    offset: usize,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        SplitMix64(seed, None)
    }
    /// Cryptographic stream for witness openings and proof masks. Public CRS
    /// expansion continues to use `new`, so this does not change public keys.
    pub fn from_seed(seed: impl Into<ProofSeed>) -> Self {
        Self(
            0,
            Some(SecretStream {
                seed: seed.into(),
                counter: 0,
                block: [0; 32],
                offset: 32,
            }),
        )
    }
    pub fn next_u64(&mut self) -> u64 {
        if let Some(stream) = self.1.as_mut() {
            if stream.offset == 32 {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(b"quil-lattice-ct/prover-stream/v2");
                h.update(stream.seed.0);
                h.update(stream.counter.to_le_bytes());
                stream.block = h.finalize().into();
                stream.counter = stream
                    .counter
                    .checked_add(1)
                    .expect("prover stream exhausted");
                stream.offset = 0;
            }
            let start = stream.offset;
            stream.offset += 8;
            return u64::from_le_bytes(stream.block[start..start + 8].try_into().unwrap());
        }
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in `[0, q)` by rejection (`q < 2^62`, bias-free over u64).
    pub fn uniform_below(&mut self, q: u128) -> u128 {
        let limit = (u64::MAX as u128 + 1) / q * q;
        loop {
            let v = self.next_u64() as u128;
            if v < limit {
                return v % q;
            }
        }
    }
    /// Uniform signed integer in `[-b, b]`.
    pub fn uniform_pm(&mut self, b: i128) -> i128 {
        let span = (2 * b + 1) as u128;
        (self.uniform_below(span) as i128) - b
    }
}

#[cfg(test)]
mod seed_tests {
    use super::*;

    #[test]
    fn proof_stream_uses_full_seed_and_separates_children() {
        let seed = ProofSeed::from([7; 32]);
        let mut changed = [7; 32];
        changed[31] ^= 1;
        let sample = |seed: ProofSeed| {
            let mut rng = SplitMix64::from_seed(seed);
            (0..12).map(|_| rng.next_u64()).collect::<Vec<_>>()
        };
        assert_eq!(sample(seed), sample(seed));
        assert_ne!(sample(seed), sample(changed.into()));
        assert_ne!(sample(seed ^ 1), sample(seed ^ 2));
        assert_ne!(sample(seed), sample(seed ^ 0));
    }

    #[test]
    fn public_crs_stream_remains_compatible() {
        let mut rng = SplitMix64::new(0);
        assert_eq!(rng.next_u64(), 0xe220a8397b1dcdaf);
        assert_eq!(rng.next_u64(), 0x6e789e6aa1b965f4);
    }
}
