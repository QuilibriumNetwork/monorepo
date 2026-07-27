//! Shared modular arithmetic over `Z_q` (`q < 2^62`, so a product of two
//! residues is `< 2^124` and fits `u128`; accumulate mod `q` to keep every
//! intermediate `< 2^128`), plus a tiny deterministic PRG.

/// `(a + b) mod q`.
pub(crate) fn add_mod(a: u128, b: u128, q: u128) -> u128 {
    (a + b) % q
}

/// Element-wise `(a + b) mod q`.
pub(crate) fn add_vec_mod(a: &[u128], b: &[u128], q: u128) -> Vec<u128> {
    a.iter().zip(b).map(|(x, y)| (x + y) % q).collect()
}

/// `Σ_j a[j]·r[j] mod q`, with signed `r` mapped into `[0, q)`.
pub(crate) fn dot_mod(a: &[u128], r: &[i128], q: u128) -> u128 {
    let mut acc: u128 = 0;
    for (aj, rj) in a.iter().zip(r) {
        acc = (acc + aj % q * signed_mod(*rj, q)) % q;
    }
    acc
}

/// Matrix-vector product `A·v mod q` (signed `v`).
pub(crate) fn matvec(a: &[Vec<u128>], v: &[i128], q: u128) -> Vec<u128> {
    a.iter().map(|row| dot_mod(row, v, q)).collect()
}

/// Map a signed integer into `[0, q)`.
pub(crate) fn signed_mod(x: i128, q: u128) -> u128 {
    let qi = q as i128;
    (((x % qi) + qi) % qi) as u128
}

/// Infinity norm of a signed vector.
pub(crate) fn inf_norm(v: &[i128]) -> i128 {
    v.iter().map(|x| x.abs()).max().unwrap_or(0)
}

/// SplitMix64 — a tiny deterministic PRG for reproducible public data and
/// test randomness (no external RNG dependency).
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
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
