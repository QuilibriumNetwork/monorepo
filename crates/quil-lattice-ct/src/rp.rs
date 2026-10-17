//! Polynomials over the proof ring R_p = Z_p[X]/(X^256 + 1), p = 2^38 − 107,
//! the modulus of the native LaBRADOR backend. Used for the coin accumulator
//! hash and note identities so their rows are native proof-ring equations
//! that need no integer lifting from the commitment ring R_q.
//!
//! Multiplication of a public matrix by short digit vectors is exact: every
//! product of a coefficient below 2^38 with a digit below 2^7 summed over
//! 256 positions and up to 128 columns stays below 2^60, so the integer
//! convolution is recovered by CRT over two NTT-friendly 31-bit primes and
//! reduced modulo p once (P1·P2 ≈ 2^61.7 > 2^60 + 2^59). This is not a general R_p multiplier for large
//! operands; `mul_short` checks its operand bounds.

/// The native backend's proof modulus.
pub const P: u64 = (1u64 << 38) - 107;
pub const D: usize = 256;
/// Packed encoding: four 38-bit coefficients in 19 bytes.
pub const PACKED_BYTES: usize = D * 38 / 8;

const P1: u64 = 2_013_265_921; // 15·2^27 + 1, generator 31
const P2: u64 = 1_811_939_329; // 27·2^26 + 1, generator 13
/// Sums are recovered as x + OFFSET in [0, P1·P2); |x| must stay below 2^59.
const OFFSET: u128 = 1u128 << 60;
const _: () = assert!((P1 as u128) * (P2 as u128) > (1u128 << 61));

/// Four 38-bit coefficients into 19 bytes: 128 low bits then the 24 high bits
/// of the fourth coefficient.
fn pack_group(group: &[u64], dst: &mut [u8]) {
    let low = u128::from(group[0]) | (u128::from(group[1]) << 38) | (u128::from(group[2]) << 76) | (u128::from(group[3] & 0x3FFF) << 114);
    let high = (group[3] >> 14) as u32;
    dst[..16].copy_from_slice(&low.to_le_bytes());
    dst[16..19].copy_from_slice(&high.to_le_bytes()[..3]);
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PolyP {
    pub c: Vec<u64>,
}

fn pow_mod(mut b: u64, mut e: u64, m: u64) -> u64 {
    let mut r = 1u64;
    b %= m;
    while e > 0 {
        if e & 1 == 1 {
            r = ((r as u128 * b as u128) % m as u128) as u64;
        }
        b = ((b as u128 * b as u128) % m as u128) as u64;
        e >>= 1;
    }
    r
}

struct Field {
    m: u64,
    /// psi^i for the negacyclic twist, psi a primitive 512-th root of unity.
    psi: Vec<u64>,
    psi_inv: Vec<u64>,
    /// omega = psi^2 powers for the length-256 cyclic transform.
    omega: Vec<u64>,
    omega_inv: Vec<u64>,
    n_inv: u64,
}

impl Field {
    fn new(m: u64, generator: u64) -> Self {
        let psi = pow_mod(generator, (m - 1) / 512, m);
        let psi_inv = pow_mod(psi, m - 2, m);
        let omega = ((psi as u128 * psi as u128) % m as u128) as u64;
        let omega_inv = pow_mod(omega, m - 2, m);
        let powers = |b: u64| (0..D).scan(1u64, |s, _| { let v = *s; *s = ((*s as u128 * b as u128) % m as u128) as u64; Some(v) }).collect::<Vec<_>>();
        Self { m, psi: powers(psi), psi_inv: powers(psi_inv), omega: powers(omega), omega_inv: powers(omega_inv), n_inv: pow_mod(D as u64, m - 2, m) }
    }

    fn mulm(&self, a: u64, b: u64) -> u64 {
        ((a as u128 * b as u128) % self.m as u128) as u64
    }

    /// In-place iterative radix-2 transform with the given root powers.
    fn transform(&self, a: &mut [u64], roots: &[u64]) {
        let mut j = 0usize;
        for i in 1..D {
            let mut bit = D >> 1;
            while j & bit != 0 { j ^= bit; bit >>= 1; }
            j |= bit;
            if i < j { a.swap(i, j); }
        }
        let mut len = 2;
        while len <= D {
            let step = D / len;
            for start in (0..D).step_by(len) {
                for k in 0..len / 2 {
                    let w = roots[k * step];
                    let u = a[start + k];
                    let v = self.mulm(a[start + k + len / 2], w);
                    a[start + k] = if u + v >= self.m { u + v - self.m } else { u + v };
                    a[start + k + len / 2] = if u >= v { u - v } else { u + self.m - v };
                }
            }
            len <<= 1;
        }
    }

    /// Forward negacyclic transform of coefficients already reduced mod m.
    fn forward(&self, coefficients: &[u64]) -> Vec<u64> {
        let mut a: Vec<u64> = coefficients.iter().enumerate().map(|(i, &c)| self.mulm(c % self.m, self.psi[i])).collect();
        self.transform(&mut a, &self.omega);
        a
    }

    fn inverse(&self, mut a: Vec<u64>) -> Vec<u64> {
        self.transform(&mut a, &self.omega_inv);
        for (i, v) in a.iter_mut().enumerate() {
            *v = self.mulm(self.mulm(*v, self.n_inv), self.psi_inv[i]);
        }
        a
    }
}

fn fields() -> &'static (Field, Field) {
    static FIELDS: std::sync::OnceLock<(Field, Field)> = std::sync::OnceLock::new();
    FIELDS.get_or_init(|| (Field::new(P1, 31), Field::new(P2, 13)))
}

/// A public polynomial held in both NTT domains for repeated multiplication.
#[derive(Clone)]
pub struct PreparedP {
    f1: Vec<u64>,
    f2: Vec<u64>,
}

/// Accumulator for Σ prepared_i · short_i over one output row.
pub struct RowAccumulator {
    s1: Vec<u64>,
    s2: Vec<u64>,
    terms: usize,
}

impl PolyP {
    pub fn zero() -> Self {
        Self { c: vec![0; D] }
    }

    pub fn is_canonical(&self) -> bool {
        self.c.len() == D && self.c.iter().all(|&v| v < P)
    }

    pub fn prepare(&self) -> PreparedP {
        let (f1, f2) = fields();
        PreparedP { f1: f1.forward(&self.c), f2: f2.forward(&self.c) }
    }

    /// Exact integer negacyclic product with a short operand (coefficients
    /// below 2^8), reduced modulo p. Panics on out-of-bound operands.
    pub fn mul_short(&self, short: &PolyP) -> PolyP {
        let mut acc = RowAccumulator::new();
        acc.add(&self.prepare(), short);
        acc.finish()
    }

    pub fn add(&self, other: &PolyP) -> PolyP {
        PolyP { c: self.c.iter().zip(&other.c).map(|(&a, &b)| { let s = a + b; if s >= P { s - P } else { s } }).collect() }
    }

    /// Base-128 limbs: limb i holds bits 7i..7i+7 of every coefficient.
    pub fn limbs(&self, count: usize) -> Vec<PolyP> {
        (0..count).map(|limb| PolyP { c: self.c.iter().map(|&v| (v >> (7 * limb)) & 127).collect() }).collect()
    }

    pub fn encode(&self, out: &mut [u8]) {
        // Any 38-bit value packs; `decode` rejects non-canonical coefficients.
        assert!(self.c.len() == D && self.c.iter().all(|&v| v < (1 << 38)) && out.len() == PACKED_BYTES);
        for (group, dst) in self.c.chunks_exact(4).zip(out.chunks_exact_mut(19)) {
            pack_group(group, dst);
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<PolyP> {
        if bytes.len() != PACKED_BYTES { return None; }
        let mut c = Vec::with_capacity(D);
        for src in bytes.chunks_exact(19) {
            let mut raw = [0u8; 16]; raw.copy_from_slice(&src[..16]);
            let low = u128::from_le_bytes(raw);
            let mut raw2 = [0u8; 16]; raw2[..3].copy_from_slice(&src[16..]);
            let high = u128::from_le_bytes(raw2);
            let packed_low = low; // bits 0..128
            let mask = (1u128 << 38) - 1;
            c.push((packed_low & mask) as u64);
            c.push(((packed_low >> 38) & mask) as u64);
            c.push(((packed_low >> 76) & mask) as u64);
            // coefficient 3 spans bits 114..152: 14 bits from low, 24 from high
            c.push((((packed_low >> 114) | (high << 14)) & mask) as u64);
        }
        let p = PolyP { c };
        p.is_canonical().then_some(p)
    }
}

impl RowAccumulator {
    pub fn new() -> Self {
        Self { s1: vec![0; D], s2: vec![0; D], terms: 0 }
    }

    /// Add prepared · short. `short` coefficients must be below 2^8.
    pub fn add(&mut self, prepared: &PreparedP, short: &PolyP) {
        assert!(short.c.len() == D && short.c.iter().all(|&v| v < 256), "short operand out of bounds");
        assert!(self.terms < 128, "row accumulator term bound");
        let (f1, f2) = fields();
        let t1 = f1.forward(&short.c);
        let t2 = f2.forward(&short.c);
        for i in 0..D {
            self.s1[i] = (self.s1[i] + f1.mulm(prepared.f1[i], t1[i])) % P1;
            self.s2[i] = (self.s2[i] + f2.mulm(prepared.f2[i], t2[i])) % P2;
        }
        self.terms += 1;
    }

    /// Recover the exact integer sum by CRT and reduce modulo p.
    pub fn finish(self) -> PolyP {
        let (f1, f2) = fields();
        let r1 = f1.inverse(self.s1);
        let r2 = f2.inverse(self.s2);
        // x + OFFSET ≡ r_i + OFFSET (mod P_i); recover in [0, P1·P2).
        let o1 = (OFFSET % P1 as u128) as u64;
        let o2 = (OFFSET % P2 as u128) as u64;
        let inv_p1_mod_p2 = pow_mod(P1 % P2, P2 - 2, P2);
        let c: Vec<u64> = r1.iter().zip(&r2).map(|(&a, &b)| {
            let a = (a + o1) % P1;
            let b = (b + o2) % P2;
            // x = a + P1 * ((b - a) * inv(P1) mod P2)
            let diff = (b + P2 - a % P2) % P2;
            let k = ((diff as u128 * inv_p1_mod_p2 as u128) % P2 as u128) as u64;
            let x = a as u128 + P1 as u128 * k as u128;
            let signed = x as i128 - OFFSET as i128;
            signed.rem_euclid(P as i128) as u64
        }).collect();
        PolyP { c }
    }
}

impl Default for RowAccumulator {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schoolbook(a: &PolyP, b: &PolyP) -> PolyP {
        let mut out = vec![0i128; D];
        for i in 0..D { for j in 0..D {
            let v = a.c[i] as i128 * b.c[j] as i128;
            if i + j < D { out[i + j] += v } else { out[i + j - D] -= v }
        }}
        PolyP { c: out.iter().map(|v| v.rem_euclid(P as i128) as u64).collect() }
    }

    fn pseudo(seed: u64, bound: u64) -> PolyP {
        let mut s = seed;
        PolyP { c: (0..D).map(|_| { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s % bound }).collect() }
    }

    #[test]
    fn ntt_crt_product_matches_schoolbook_and_accumulates_rows() {
        for seed in 1..6u64 {
            let a = pseudo(seed, P);
            let b = pseudo(seed + 100, 128);
            assert_eq!(a.mul_short(&b), schoolbook(&a, &b));
        }
        // 128 accumulated worst-case terms stay exact.
        let mut acc = RowAccumulator::new();
        let big = PolyP { c: vec![P - 1; D] };
        let digit = PolyP { c: vec![127; D] };
        let mut expected = PolyP::zero();
        for _ in 0..128 { acc.add(&big.prepare(), &digit); expected = expected.add(&schoolbook(&big, &digit)); }
        assert_eq!(acc.finish(), expected);
    }

    #[test]
    fn packed_encoding_roundtrips_and_rejects_noncanonical() {
        let p = pseudo(9, P);
        let mut bytes = [0u8; PACKED_BYTES];
        p.encode(&mut bytes);
        assert_eq!(PolyP::decode(&bytes).unwrap(), p);
        let mut bad = PolyP { c: vec![0; D] }; bad.c[255] = P;
        let mut raw = [0u8; PACKED_BYTES];
        // encode manually with an out-of-range coefficient
        for (group, dst) in bad.c.chunks_exact(4).zip(raw.chunks_exact_mut(19)) {
            pack_group(group, dst);
        }
        assert!(PolyP::decode(&raw).is_none());
        assert!(PolyP::decode(&bytes[..PACKED_BYTES - 1]).is_none());
        assert_eq!(p.limbs(6).len(), 6);
        assert!(p.limbs(6).iter().all(|l| l.c.iter().all(|&v| v < 128)));
        assert!(p.limbs(6)[5].c.iter().all(|&v| v < 8));
    }
}
