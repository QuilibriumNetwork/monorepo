//! Canonical wire serialization for the confidential-transaction proofs — a
//! prerequisite for the token-layer integration (which is itself **audit-gated**
//! and not done here). Deterministic length-prefixed encoding; touches no
//! consensus code.
//!
//! Format is the plain reference layout (`u64` coefficient arrays). The
//! production ring form will use a compact NTT/bit-packed encoding; this is the
//! interface, round-trip-tested.

use crate::binary_rq::{BinaryProofRq, BitsProofRq};
use crate::memo::AmountMemo;
use crate::module::{PolyVec, RingCommitment};
use crate::range_rq::RangeProofRq;
use crate::ring_rq::RingSigRq;
use crate::rq::Poly;
use crate::sigma_rq::RingOpeningProof;

// ── Writer / Reader ────────────────────────────────────────────────────────

#[derive(Default)]
struct W(Vec<u8>);
impl W {
    fn u32(&mut self, x: u32) {
        self.0.extend_from_slice(&x.to_le_bytes());
    }
    fn poly(&mut self, p: &Poly) {
        self.u32(p.c.len() as u32);
        for &c in &p.c {
            self.0.extend_from_slice(&c.to_le_bytes());
        }
    }
    fn polyvec(&mut self, v: &PolyVec) {
        self.u32(v.0.len() as u32);
        for p in &v.0 {
            self.poly(p);
        }
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
    fn commit(&mut self, c: &RingCommitment) {
        self.polyvec(&c.t1);
        self.polyvec(&c.t2);
    }
    fn opening(&mut self, o: &RingOpeningProof) {
        self.polyvec(&o.w);
        self.polyvec(&o.z);
    }
    fn i128le(&mut self, x: i128) {
        self.0.extend_from_slice(&x.to_le_bytes());
    }
    fn polyvecs(&mut self, vs: &[PolyVec]) {
        self.u32(vs.len() as u32);
        for v in vs {
            self.polyvec(v);
        }
    }
    fn commits(&mut self, cs: &[RingCommitment]) {
        self.u32(cs.len() as u32);
        for c in cs {
            self.commit(c);
        }
    }
}

struct R<'a> {
    b: &'a [u8],
    p: usize,
}
#[derive(Debug)]
pub struct DecodeError(&'static str);

impl<'a> R<'a> {
    fn new(b: &'a [u8]) -> Self {
        R { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let s = self.b.get(self.p..self.p + n).ok_or(DecodeError("eof"))?;
        self.p += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.p)
    }
    /// Read a length prefix and reject it if `n` elements — each consuming at
    /// least `min_elem_bytes` on the wire — could not possibly fit in the
    /// remaining input. This prevents an adversarial count (up to `u32::MAX`)
    /// from driving a multi-gigabyte `Vec::with_capacity` OOM abort at block
    /// execution (H-1). It never rejects a well-formed message.
    fn count(&mut self, min_elem_bytes: usize) -> Result<usize, DecodeError> {
        let n = self.u32()? as usize;
        let need = n.checked_mul(min_elem_bytes.max(1));
        if need.map_or(true, |need| need > self.remaining()) {
            return Err(DecodeError("length prefix exceeds remaining bytes"));
        }
        Ok(n)
    }
    fn poly(&mut self) -> Result<Poly, DecodeError> {
        let n = self.count(8)?;
        // Every polynomial in this ring is EXACTLY degree `Poly::D` (256). A
        // decoded poly of any other length is malformed and, if let through,
        // panics downstream: an oversized poly indexes the fixed `[u64; 256]` NTT
        // twiddle table out of bounds, and a wrong module rank trips `matvec`'s
        // `assert_eq!`. Reject here (same canonical-form-hardening class as the
        // coefficient-value check below).
        if n != Poly::D {
            return Err(DecodeError("wrong polynomial degree"));
        }
        let mut c = Vec::with_capacity(n);
        for _ in 0..n {
            let coeff = u64::from_le_bytes(self.take(8)?.try_into().unwrap());
            // C-1: reject non-canonical coefficients (must be reduced mod q).
            // Otherwise `t` and `t+q` decode to DISTINCT `Poly` values that hash
            // to different key-image nullifiers while verifying identically (only
            // `.sub()`, which reduces mod q, touches the key image) — an unlimited
            // double-spend. Canonical form here also hardens every `Eq`-based check.
            if coeff >= Poly::Q {
                return Err(DecodeError("non-canonical coefficient (>= q)"));
            }
            c.push(coeff);
        }
        Ok(Poly { c })
    }
    fn polyvec(&mut self) -> Result<PolyVec, DecodeError> {
        // Each poly is >= 4 bytes on the wire (its own u32 length prefix).
        let n = self.count(4)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.poly()?);
        }
        Ok(PolyVec(v))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn commit(&mut self) -> Result<RingCommitment, DecodeError> {
        Ok(RingCommitment { t1: self.polyvec()?, t2: self.polyvec()? })
    }
    fn opening(&mut self) -> Result<RingOpeningProof, DecodeError> {
        Ok(RingOpeningProof { w: self.polyvec()?, z: self.polyvec()? })
    }
    fn i128le(&mut self) -> Result<i128, DecodeError> {
        Ok(i128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    fn polyvecs(&mut self) -> Result<Vec<PolyVec>, DecodeError> {
        let n = self.count(4)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.polyvec()?);
        }
        Ok(out)
    }
    fn commits(&mut self) -> Result<Vec<RingCommitment>, DecodeError> {
        let n = self.count(8)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.commit()?);
        }
        Ok(out)
    }
}

// ── Public encode/decode ───────────────────────────────────────────────────

pub fn encode_binary(p: &BinaryProofRq) -> Vec<u8> {
    let mut w = W::default();
    w.commit(&p.c_alpha);
    w.commit(&p.c1);
    w.commit(&p.c0);
    w.poly(&p.f);
    w.polyvec(&p.z_f);
    w.polyvec(&p.z_g);
    w.0
}
pub fn decode_binary(b: &[u8]) -> Result<BinaryProofRq, DecodeError> {
    let mut r = R::new(b);
    Ok(BinaryProofRq {
        c_alpha: r.commit()?,
        c1: r.commit()?,
        c0: r.commit()?,
        f: r.poly()?,
        z_f: r.polyvec()?,
        z_g: r.polyvec()?,
    })
}

pub fn encode_range(p: &RangeProofRq) -> Vec<u8> {
    let mut w = W::default();
    w.commit(&p.c_b);
    // The amortized bit-vector proof: 3 commitments + 3 response vectors.
    w.commit(&p.bits_proof.c_alpha);
    w.commit(&p.bits_proof.c1);
    w.commit(&p.bits_proof.c0);
    w.polyvec(&p.bits_proof.f);
    w.polyvec(&p.bits_proof.z_f);
    w.polyvec(&p.bits_proof.z_g);
    w.opening(&p.binding);
    w.0
}
pub fn decode_range(b: &[u8]) -> Result<RangeProofRq, DecodeError> {
    let mut r = R::new(b);
    let c_b = r.commit()?;
    let bits_proof = BitsProofRq {
        c_alpha: r.commit()?,
        c1: r.commit()?,
        c0: r.commit()?,
        f: r.polyvec()?,
        z_f: r.polyvec()?,
        z_g: r.polyvec()?,
    };
    Ok(RangeProofRq { c_b, bits_proof, binding: r.opening()? })
}

pub fn encode_ring_sig(s: &RingSigRq) -> Vec<u8> {
    let mut w = W::default();
    w.polyvec(&s.tag);
    w.commit(&s.c_m);
    w.u32(s.bit_proofs.len() as u32);
    for bp in &s.bit_proofs {
        w.bytes(&encode_binary(bp));
    }
    w.opening(&s.sel);
    w.opening(&s.ki);
    w.opening(&s.sum);
    w.0
}
pub fn decode_ring_sig(b: &[u8]) -> Result<RingSigRq, DecodeError> {
    let mut r = R::new(b);
    let tag = r.polyvec()?;
    let c_m = r.commit()?;
    let n = r.count(4)?;
    let mut bit_proofs = Vec::with_capacity(n);
    for _ in 0..n {
        bit_proofs.push(decode_binary(&r.bytes()?)?);
    }
    Ok(RingSigRq { tag, c_m, bit_proofs, sel: r.opening()?, ki: r.opening()?, sum: r.opening()? })
}

pub fn encode_commitment(c: &RingCommitment) -> Vec<u8> {
    let mut w = W::default();
    w.commit(c);
    w.0
}
pub fn decode_commitment(b: &[u8]) -> Result<RingCommitment, DecodeError> {
    R::new(b).commit()
}

pub fn encode_polyvec(v: &PolyVec) -> Vec<u8> {
    let mut w = W::default();
    w.polyvec(v);
    w.0
}
pub fn decode_polyvec(b: &[u8]) -> Result<PolyVec, DecodeError> {
    R::new(b).polyvec()
}

// ── Compact bit-level packing (coeffs are < 2^MODULUS_Q_BITS, not 64 bits) ────

const QBITS: u32 = crate::params::MODULUS_Q_BITS; // 36

/// Little-endian bit writer (LSB-first). Values are masked to `bits`.
struct BitW {
    out: Vec<u8>,
    acc: u128,
    n: u32,
}
impl BitW {
    fn new() -> Self {
        BitW { out: Vec::new(), acc: 0, n: 0 }
    }
    fn push(&mut self, v: u64, bits: u32) {
        let m = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        self.acc |= ((v & m) as u128) << self.n;
        self.n += bits;
        while self.n >= 8 {
            self.out.push((self.acc & 0xff) as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }
    fn poly(&mut self, p: &Poly) {
        for &c in &p.c {
            self.push(c, QBITS);
        }
    }
    fn polyvec(&mut self, v: &PolyVec) {
        self.push(v.0.len() as u64, 32);
        for p in &v.0 {
            self.poly(p);
        }
    }
    fn polyvecs(&mut self, vs: &[PolyVec]) {
        self.push(vs.len() as u64, 32);
        for v in vs {
            self.polyvec(v);
        }
    }
    fn commit(&mut self, c: &RingCommitment) {
        self.polyvec(&c.t1);
        self.polyvec(&c.t2);
    }
    fn commits(&mut self, cs: &[RingCommitment]) {
        self.push(cs.len() as u64, 32);
        for c in cs {
            self.commit(c);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push((self.acc & 0xff) as u8);
        }
        self.out
    }
}

/// Little-endian bit reader; fail-closed on EOF and non-canonical coeffs.
struct BitR<'a> {
    b: &'a [u8],
    pos: usize,
    acc: u128,
    n: u32,
}
impl<'a> BitR<'a> {
    fn new(b: &'a [u8]) -> Self {
        BitR { b, pos: 0, acc: 0, n: 0 }
    }
    fn take(&mut self, bits: u32) -> Result<u64, DecodeError> {
        while self.n < bits {
            let byte = *self.b.get(self.pos).ok_or(DecodeError("eof"))?;
            self.acc |= (byte as u128) << self.n;
            self.pos += 1;
            self.n += 8;
        }
        let m = if bits >= 64 { u64::MAX as u128 } else { (1u128 << bits) - 1 };
        let v = (self.acc & m) as u64;
        self.acc >>= bits;
        self.n -= bits;
        Ok(v)
    }
    fn count(&mut self, min_elem_bits: u32) -> Result<usize, DecodeError> {
        let n = self.take(32)? as usize;
        // Reject a count that cannot fit in the remaining bits (H-1 OOM guard).
        let rem_bits = (self.b.len() - self.pos) as u128 * 8 + self.n as u128;
        if (n as u128) * (min_elem_bits.max(1) as u128) > rem_bits {
            return Err(DecodeError("length prefix exceeds remaining bits"));
        }
        Ok(n)
    }
    fn poly(&mut self) -> Result<Poly, DecodeError> {
        let mut c = Vec::with_capacity(Poly::D);
        for _ in 0..Poly::D {
            let coeff = self.take(QBITS)?;
            if coeff >= Poly::Q {
                return Err(DecodeError("non-canonical coefficient (>= q)"));
            }
            c.push(coeff);
        }
        Ok(Poly { c })
    }
    fn polyvec(&mut self) -> Result<PolyVec, DecodeError> {
        let n = self.count(QBITS * Poly::D as u32)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.poly()?);
        }
        Ok(PolyVec(v))
    }
    fn polyvecs(&mut self) -> Result<Vec<PolyVec>, DecodeError> {
        let n = self.count(32)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.polyvec()?);
        }
        Ok(out)
    }
    fn commit(&mut self) -> Result<RingCommitment, DecodeError> {
        Ok(RingCommitment { t1: self.polyvec()?, t2: self.polyvec()? })
    }
    fn commits(&mut self) -> Result<Vec<RingCommitment>, DecodeError> {
        let n = self.count(32)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.commit()?);
        }
        Ok(out)
    }
}

// ── The amortized money-path IPA ZK proof (FullCtZkIpaProof) ─────────────────

use crate::labrador::{FullCtZkIpaProof, IpaGeneralZkProof};

fn write_ipa(w: &mut W, b: &IpaGeneralZkProof) {
    w.polyvecs(&b.t);
    w.polyvec(&b.t_w);
    w.polyvec(&b.zp);
    w.commit(&b.u_g);
    w.polyvec(&b.c_yr);
    w.polyvec(&b.z_r);
    w.commits(&b.c_t);
    w.polyvecs(&b.r_t);
    for &x in b.p.iter() {
        w.i128le(x);
    }
    w.commits(&b.c_nu);
    w.commits(&b.c_ctnu);
    w.commits(&b.c_tct);
    w.polyvec(&PolyVec(b.zeta.clone())); // per-round ζ, as a length-prefixed poly list
    w.polyvecs(&b.z_ctr);
    w.polyvecs(&b.r_ctnu);
}
fn read_ipa(r: &mut R) -> Result<IpaGeneralZkProof, DecodeError> {
    let t = r.polyvecs()?;
    let t_w = r.polyvec()?;
    let zp = r.polyvec()?;
    let u_g = r.commit()?;
    let c_yr = r.polyvec()?;
    let z_r = r.polyvec()?;
    let c_t = r.commits()?;
    let r_t = r.polyvecs()?;
    let mut p = [0i128; 256];
    for x in p.iter_mut() {
        *x = r.i128le()?;
    }
    let c_nu = r.commits()?;
    let c_ctnu = r.commits()?;
    let c_tct = r.commits()?;
    let zeta = r.polyvec()?.0; // per-round ζ
    let z_ctr = r.polyvecs()?;
    let r_ctnu = r.polyvecs()?;
    Ok(IpaGeneralZkProof { t, t_w, zp, u_g, c_yr, z_r, c_t, r_t, p, c_nu, c_ctnu, c_tct, zeta, z_ctr, r_ctnu })
}

/// Encode the amortized money-path IPA proof (the bytes a tx carries).
pub fn encode_full_ct_zk_ipa(pf: &FullCtZkIpaProof) -> Vec<u8> {
    let mut w = W::default();
    w.u32(pf.u1s.len() as u32);
    for (a, b) in &pf.u1s {
        w.polyvec(a);
        w.polyvec(b);
    }
    write_ipa(&mut w, &pf.base);
    w.u32(pf.n_last as u32);
    w.0
}
/// Decode (fail-closed) an amortized money-path IPA proof.
pub fn decode_full_ct_zk_ipa(bytes: &[u8]) -> Result<FullCtZkIpaProof, DecodeError> {
    let mut r = R::new(bytes);
    // Each u1 pair is ≥ 8 bytes (two length-prefixed polyvecs).
    let n = r.count(8)?;
    let mut u1s = Vec::with_capacity(n);
    for _ in 0..n {
        let a = r.polyvec()?;
        let b = r.polyvec()?;
        u1s.push((a, b));
    }
    let base = read_ipa(&mut r)?;
    let n_last = r.u32()? as usize;
    Ok(FullCtZkIpaProof { u1s, base, n_last })
}

// ── Compact (bit-packed) variant of the IPA money proof ─────────────────────
// Same field layout as the byte codec, but every coefficient rides QBITS (=36)
// bits instead of a padded 8 bytes → ~1.78× smaller on the wire.

fn write_ipa_compact(w: &mut BitW, b: &IpaGeneralZkProof) {
    w.polyvecs(&b.t);
    w.polyvec(&b.t_w);
    w.polyvec(&b.zp);
    w.commit(&b.u_g);
    w.polyvec(&b.c_yr);
    w.polyvec(&b.z_r);
    w.commits(&b.c_t);
    w.polyvecs(&b.r_t);
    for &x in b.p.iter() {
        // Exact i128 (JL projections can be negative): two 64-bit limbs.
        w.push(x as u64, 64);
        w.push((x >> 64) as u64, 64);
    }
    w.commits(&b.c_nu);
    w.commits(&b.c_ctnu);
    w.commits(&b.c_tct);
    w.polyvec(&PolyVec(b.zeta.clone())); // per-round ζ, as a length-prefixed poly list
    w.polyvecs(&b.z_ctr);
    w.polyvecs(&b.r_ctnu);
}
fn read_ipa_compact(r: &mut BitR) -> Result<IpaGeneralZkProof, DecodeError> {
    let t = r.polyvecs()?;
    let t_w = r.polyvec()?;
    let zp = r.polyvec()?;
    let u_g = r.commit()?;
    let c_yr = r.polyvec()?;
    let z_r = r.polyvec()?;
    let c_t = r.commits()?;
    let r_t = r.polyvecs()?;
    let mut p = [0i128; 256];
    for x in p.iter_mut() {
        let lo = r.take(64)? as u128;
        let hi = r.take(64)? as u128;
        *x = (lo | (hi << 64)) as i128;
    }
    let c_nu = r.commits()?;
    let c_ctnu = r.commits()?;
    let c_tct = r.commits()?;
    let zeta = r.polyvec()?.0; // per-round ζ
    let z_ctr = r.polyvecs()?;
    let r_ctnu = r.polyvecs()?;
    Ok(IpaGeneralZkProof { t, t_w, zp, u_g, c_yr, z_r, c_t, r_t, p, c_nu, c_ctnu, c_tct, zeta, z_ctr, r_ctnu })
}

/// Bit-packed encoding of the amortized money-path IPA proof.
pub fn encode_full_ct_zk_ipa_compact(pf: &FullCtZkIpaProof) -> Vec<u8> {
    let mut w = BitW::new();
    w.push(pf.u1s.len() as u64, 32);
    for (a, b) in &pf.u1s {
        w.polyvec(a);
        w.polyvec(b);
    }
    write_ipa_compact(&mut w, &pf.base);
    w.push(pf.n_last as u64, 32);
    w.finish()
}
/// Decode (fail-closed) a bit-packed amortized money-path IPA proof.
pub fn decode_full_ct_zk_ipa_compact(bytes: &[u8]) -> Result<FullCtZkIpaProof, DecodeError> {
    let mut r = BitR::new(bytes);
    let n = r.count(64)?; // each u1 pair ≥ two 32-bit length prefixes
    let mut u1s = Vec::with_capacity(n);
    for _ in 0..n {
        let a = r.polyvec()?;
        let b = r.polyvec()?;
        u1s.push((a, b));
    }
    let base = read_ipa_compact(&mut r)?;
    let n_last = r.take(32)? as usize;
    Ok(FullCtZkIpaProof { u1s, base, n_last })
}

pub fn encode_opening(o: &RingOpeningProof) -> Vec<u8> {
    let mut w = W::default();
    w.opening(o);
    w.0
}
pub fn decode_opening(b: &[u8]) -> Result<RingOpeningProof, DecodeError> {
    R::new(b).opening()
}

// ── ZK packed range proof (opening + binary) ────────────────────────────────

use crate::labrador_ct::binary_zk::{PackedBinaryZkProof, Shot};

/// Encode the ZK packed-binary proof: a fixed number of shots, each
/// `(c_alpha, c1, c0, f, z_f, z_g)`.
pub fn encode_packed_binary_zk(p: &PackedBinaryZkProof) -> Vec<u8> {
    let mut w = W::default();
    w.u32(p.shots.len() as u32);
    for sh in &p.shots {
        w.commit(&sh.c_alpha);
        w.commit(&sh.c1);
        w.commit(&sh.c0);
        w.poly(&sh.f);
        w.polyvec(&sh.z_f);
        w.polyvec(&sh.z_g);
    }
    w.0
}

/// Decode a ZK packed-binary proof. Fail-closed: the shot count MUST equal the
/// protocol's fixed `REPS` (a short/long proof is rejected, not silently
/// accepted with weaker soundness), and every poly is canonical-checked by `R`.
pub fn decode_packed_binary_zk(b: &[u8]) -> Result<PackedBinaryZkProof, DecodeError> {
    let mut r = R::new(b);
    // Each shot is >= 6 length-prefixed fields → a generous per-shot floor.
    let n = r.count(6 * 4)?;
    if n != PackedBinaryZkProof::expected_shots() {
        return Err(DecodeError("wrong shot count"));
    }
    let mut shots = Vec::with_capacity(n);
    for _ in 0..n {
        let c_alpha = r.commit()?;
        let c1 = r.commit()?;
        let c0 = r.commit()?;
        let f = r.poly()?;
        let z_f = r.polyvec()?;
        let z_g = r.polyvec()?;
        shots.push(Shot::from_parts(c_alpha, c1, c0, f, z_f, z_g));
    }
    if r.remaining() != 0 {
        return Err(DecodeError("trailing bytes"));
    }
    Ok(PackedBinaryZkProof::from_shots(shots))
}

/// Encode the COMPLETE ZK packed range proof: opening ‖ binary.
pub fn encode_packed_range_zk(p: &crate::labrador_ct::PackedRangeZkProof) -> Vec<u8> {
    let mut w = W::default();
    w.opening(&p.opening);
    let bin = encode_packed_binary_zk(&p.binary);
    w.bytes(&bin);
    w.0
}

/// Decode the complete ZK packed range proof. Fail-closed throughout.
pub fn decode_packed_range_zk(b: &[u8]) -> Result<crate::labrador_ct::PackedRangeZkProof, DecodeError> {
    let mut r = R::new(b);
    let opening = r.opening()?;
    let bin_bytes = r.bytes()?;
    if r.remaining() != 0 {
        return Err(DecodeError("trailing bytes"));
    }
    let binary = decode_packed_binary_zk(&bin_bytes)?;
    Ok(crate::labrador_ct::PackedRangeZkProof { opening, binary })
}

/// Encode a value-link proof (binds a packed `c_b` to a value commitment).
pub fn encode_value_link(p: &crate::labrador_ct::balance_zk::ValueLinkProof) -> Vec<u8> {
    let mut w = W::default();
    w.commit(&p.c_yb);
    w.commit(&p.c_yv);
    w.commit(&p.c_t);
    w.poly(&p.z_b);
    w.poly(&p.z_v);
    w.polyvec(&p.r_zb);
    w.polyvec(&p.r_zv);
    w.polyvec(&p.r_t);
    w.0
}

/// Decode a value-link proof. Fail-closed.
pub fn decode_value_link(b: &[u8]) -> Result<crate::labrador_ct::balance_zk::ValueLinkProof, DecodeError> {
    let mut r = R::new(b);
    let p = crate::labrador_ct::balance_zk::ValueLinkProof {
        c_yb: r.commit()?,
        c_yv: r.commit()?,
        c_t: r.commit()?,
        z_b: r.poly()?,
        z_v: r.poly()?,
        r_zb: r.polyvec()?,
        r_zv: r.polyvec()?,
        r_t: r.polyvec()?,
    };
    if r.remaining() != 0 {
        return Err(DecodeError("trailing bytes"));
    }
    Ok(p)
}

/// Encode a ZK packed-balance proof `(c_y, c_t, z, r_z, r_t)`.
pub fn encode_packed_balance(p: &crate::labrador_ct::balance_zk::PackedBalanceProof) -> Vec<u8> {
    let mut w = W::default();
    w.commit(&p.c_y);
    w.commit(&p.c_t);
    w.poly(&p.z);
    w.polyvec(&p.r_z);
    w.polyvec(&p.r_t);
    w.0
}

/// Decode a ZK packed-balance proof. Fail-closed (canonical polys, no trailing).
pub fn decode_packed_balance(b: &[u8]) -> Result<crate::labrador_ct::balance_zk::PackedBalanceProof, DecodeError> {
    let mut r = R::new(b);
    let c_y = r.commit()?;
    let c_t = r.commit()?;
    let z = r.poly()?;
    let r_z = r.polyvec()?;
    let r_t = r.polyvec()?;
    if r.remaining() != 0 {
        return Err(DecodeError("trailing bytes"));
    }
    Ok(crate::labrador_ct::balance_zk::PackedBalanceProof { c_y, c_t, z, r_z, r_t })
}

// ── Versioned range-proof envelope (protobuf `bytes range_proof` payload) ────
//
// The protobuf field is already `bytes`, so NO schema change is needed to carry
// the new packed ZK proof — only a 1-byte version tag so the two formats can
// never be confused (fail-closed on an unknown tag). v1 is retained for decode only.

/// Legacy `RangeProofRq` (value-binding + amortized bits).
pub const RANGE_PROOF_V_LEGACY: u8 = 1;
/// Packed zero-knowledge range proof ([`crate::labrador_ct::PackedRangeZkProof`]).
pub const RANGE_PROOF_V_PACKED_ZK: u8 = 2;

/// A decoded range proof, tagged by wire version.
pub enum RangeProofKind {
    Legacy(RangeProofRq),
    PackedZk(crate::labrador_ct::PackedRangeZkProof),
}

/// Wrap a packed ZK range proof in the versioned envelope.
pub fn encode_range_versioned_packed_zk(p: &crate::labrador_ct::PackedRangeZkProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4);
    out.push(RANGE_PROOF_V_PACKED_ZK);
    out.extend(encode_packed_range_zk(p));
    out
}

/// Decode a versioned range proof; fail-closed on an unknown/absent tag.
pub fn decode_range_versioned(b: &[u8]) -> Result<RangeProofKind, DecodeError> {
    match b.split_first() {
        Some((&RANGE_PROOF_V_LEGACY, rest)) => Ok(RangeProofKind::Legacy(decode_range(rest)?)),
        Some((&RANGE_PROOF_V_PACKED_ZK, rest)) => {
            Ok(RangeProofKind::PackedZk(decode_packed_range_zk(rest)?))
        }
        _ => Err(DecodeError("unknown range-proof version")),
    }
}

pub fn encode_memo(m: &AmountMemo) -> Vec<u8> {
    let mut w = W::default();
    w.bytes(&m.enc_v);
    w.bytes(&m.enc_r);
    w.0
}
pub fn decode_memo(b: &[u8]) -> Result<AmountMemo, DecodeError> {
    let mut r = R::new(b);
    Ok(AmountMemo { enc_v: r.bytes()?, enc_r: r.bytes()? })
}

/// Accumulator [`crate::membership::MembershipProof`] — the whole-set anonymity
/// spend proof (combined shared-challenge opening + hash-chain).
pub fn encode_membership(p: &crate::membership::MembershipProof) -> Vec<u8> {
    let mut w = W::default();
    w.commit(&p.commitment);
    w.polyvec(&p.key_image);
    // combined opening
    w.polyvec(&p.combined.w_lin);
    w.u32(p.combined.b.len() as u32);
    for poly in &p.combined.b {
        w.poly(poly);
    }
    w.polyvec(&p.combined.z);
    // hash-chain (one ProdZeroVecProof per level)
    w.u32(p.chain.len() as u32);
    for pz in &p.chain {
        w.commit(&pz.c_alpha);
        w.commit(&pz.c_beta);
        w.commit(&pz.c1);
        w.commit(&pz.c0);
        w.polyvec(&pz.f_a);
        w.polyvec(&pz.f_b);
        w.polyvec(&pz.z_fa);
        w.polyvec(&pz.z_fb);
        w.polyvec(&pz.z_g);
    }
    // _shortness is retained-but-empty in the combined design.
    w.u32(p._shortness.len() as u32);
    w.0
}
pub fn decode_membership(b: &[u8]) -> Result<crate::membership::MembershipProof, DecodeError> {
    let mut r = R::new(b);
    let commitment = r.commit()?;
    let key_image = r.polyvec()?;
    let w_lin = r.polyvec()?;
    let nb = r.count(4)?;
    let mut bvec = Vec::with_capacity(nb);
    for _ in 0..nb {
        bvec.push(r.poly()?);
    }
    let z = r.polyvec()?;
    let combined = crate::membership::CombinedOpening { w_lin, b: bvec, z };
    let nchain = r.count(4)?;
    let mut chain = Vec::with_capacity(nchain);
    for _ in 0..nchain {
        chain.push(crate::membership::ProdZeroVecProof {
            c_alpha: r.commit()?,
            c_beta: r.commit()?,
            c1: r.commit()?,
            c0: r.commit()?,
            f_a: r.polyvec()?,
            f_b: r.polyvec()?,
            z_fa: r.polyvec()?,
            z_fb: r.polyvec()?,
            z_g: r.polyvec()?,
        });
    }
    let ns = r.count(4)?;
    if ns != 0 {
        return Err(DecodeError("membership _shortness must be empty in combined design"));
    }
    Ok(crate::membership::MembershipProof {
        commitment,
        key_image,
        combined,
        chain,
        _shortness: Vec::new(),
    })
}

// Shared chain encoding (one ProdZeroVecProof per level).
fn write_chain(w: &mut W, chain: &[crate::membership::ProdZeroVecProof]) {
    w.u32(chain.len() as u32);
    for pz in chain {
        w.commit(&pz.c_alpha);
        w.commit(&pz.c_beta);
        w.commit(&pz.c1);
        w.commit(&pz.c0);
        w.polyvec(&pz.f_a);
        w.polyvec(&pz.f_b);
        w.polyvec(&pz.z_fa);
        w.polyvec(&pz.z_fb);
        w.polyvec(&pz.z_g);
    }
}
fn read_chain(r: &mut R) -> Result<Vec<crate::membership::ProdZeroVecProof>, DecodeError> {
    let n = r.count(4)?;
    let mut chain = Vec::with_capacity(n);
    for _ in 0..n {
        chain.push(crate::membership::ProdZeroVecProof {
            c_alpha: r.commit()?,
            c_beta: r.commit()?,
            c1: r.commit()?,
            c0: r.commit()?,
            f_a: r.polyvec()?,
            f_b: r.polyvec()?,
            z_fa: r.polyvec()?,
            z_fb: r.polyvec()?,
            z_g: r.polyvec()?,
        });
    }
    Ok(chain)
}

/// Full confidential [`crate::membership::SpendProof`] (membership ⊕ value-link).
pub fn encode_spend(p: &crate::membership::SpendProof) -> Vec<u8> {
    let mut w = W::default();
    w.commit(&p.commitment);
    w.polyvec(&p.key_image);
    w.commit(&p.c_prime);
    // combined opening
    w.polyvec(&p.combined.w_lin);
    w.u32(p.combined.b.len() as u32);
    for poly in &p.combined.b {
        w.poly(poly);
    }
    w.polyvec(&p.combined.z);
    write_chain(&mut w, &p.chain);
    w.0
}
pub fn decode_spend(b: &[u8]) -> Result<crate::membership::SpendProof, DecodeError> {
    let mut r = R::new(b);
    let commitment = r.commit()?;
    let key_image = r.polyvec()?;
    let c_prime = r.commit()?;
    let w_lin = r.polyvec()?;
    let nb = r.count(4)?;
    let mut bvec = Vec::with_capacity(nb);
    for _ in 0..nb {
        bvec.push(r.poly()?);
    }
    let z = r.polyvec()?;
    let combined = crate::membership::CombinedOpening { w_lin, b: bvec, z };
    let chain = read_chain(&mut r)?;
    Ok(crate::membership::SpendProof { commitment, key_image, c_prime, combined, chain })
}

/// Full-width [`crate::limb_balance::LimbBalanceProof`] (Gap-2 balance).
pub fn encode_limb_balance(p: &crate::limb_balance::LimbBalanceProof) -> Vec<u8> {
    let mut w = W::default();
    w.u32(p.carries.len() as u32);
    for c in &p.carries {
        w.commit(c);
    }
    w.u32(p.carry_ranges.len() as u32);
    for rp in &p.carry_ranges {
        w.bytes(&encode_range(rp));
    }
    w.u32(p.out_ranges.len() as u32);
    for row in &p.out_ranges {
        w.u32(row.len() as u32);
        for rp in row {
            w.bytes(&encode_range(rp));
        }
    }
    w.u32(p.per_limb.len() as u32);
    for pl in &p.per_limb {
        w.bytes(pl);
    }
    w.0
}
pub fn decode_limb_balance(b: &[u8]) -> Result<crate::limb_balance::LimbBalanceProof, DecodeError> {
    let mut r = R::new(b);
    let nc = r.count(4)?;
    let mut carries = Vec::with_capacity(nc);
    for _ in 0..nc {
        carries.push(r.commit()?);
    }
    let ncr = r.count(4)?;
    let mut carry_ranges = Vec::with_capacity(ncr);
    for _ in 0..ncr {
        carry_ranges.push(decode_range(&r.bytes()?)?);
    }
    let nor = r.count(4)?;
    let mut out_ranges = Vec::with_capacity(nor);
    for _ in 0..nor {
        let k = r.count(4)?;
        let mut row = Vec::with_capacity(k);
        for _ in 0..k {
            row.push(decode_range(&r.bytes()?)?);
        }
        out_ranges.push(row);
    }
    let npl = r.count(4)?;
    let mut per_limb = Vec::with_capacity(npl);
    for _ in 0..npl {
        per_limb.push(r.bytes()?);
    }
    Ok(crate::limb_balance::LimbBalanceProof { carries, carry_ranges, out_ranges, per_limb })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::SplitMix64;
    use crate::binary_rq::{prove_bit_rq, BinRqParams};
    use crate::memo::encrypt_memo;
    use crate::module::{RingCommitKey, ETA};
    use crate::range_rq::{prove_range_rq, RingRangeKey};
    use crate::ring_rq::{sign, RingSigKeyRq};

    fn constant(v: u64) -> Poly {
        let mut p = Poly::zero();
        p.c[0] = v;
        p
    }

    #[test]
    fn packed_binary_zk_round_trips_and_rejects_wrong_shot_count() {
        use crate::labrador_ct::binary_zk::prove_packed_binary_zk;
        use crate::labrador_ct::packed::commit_packed;
        let (stmt, wit) = commit_packed(64, 0xABCDu64, 55);
        let pf = prove_packed_binary_zk(&stmt.key, &stmt.c_b, &wit.bit_poly, &wit.r_b, 7).unwrap();
        let bytes = encode_packed_binary_zk(&pf);
        let back = decode_packed_binary_zk(&bytes).expect("round-trips");
        assert_eq!(encode_packed_binary_zk(&back), bytes, "re-encode is byte-identical");
        // Truncating a shot (wrong count) must fail-closed, not verify weaker.
        let mut short = bytes.clone();
        short.truncate(bytes.len() - 100);
        assert!(decode_packed_binary_zk(&short).is_err());
    }

    #[test]
    fn complete_packed_range_zk_round_trips_and_verifies() {
        use crate::labrador_ct::{prove_range_zk, verify_range_zk};
        use crate::labrador_ct::packed::commit_packed;
        let (stmt, wit) = commit_packed(64, 0x0BEEFu64, 61);
        let pf = prove_range_zk(&stmt, &wit, 3).unwrap();
        let bytes = encode_packed_range_zk(&pf);
        let back = decode_packed_range_zk(&bytes).expect("round-trips");
        // Decoded proof still verifies against the public statement.
        assert!(verify_range_zk(&stmt, &back), "decoded ZK range proof must verify");
        assert_eq!(encode_packed_range_zk(&back), bytes, "re-encode byte-identical");
    }

    #[test]
    fn versioned_range_envelope_dispatches_and_fails_closed() {
        use crate::labrador_ct::{prove_range_zk, verify_range_zk};
        use crate::labrador_ct::packed::commit_packed;
        let (stmt, wit) = commit_packed(64, 42u64, 63);
        let pf = prove_range_zk(&stmt, &wit, 3).unwrap();
        let env = encode_range_versioned_packed_zk(&pf);
        assert_eq!(env[0], RANGE_PROOF_V_PACKED_ZK);
        match decode_range_versioned(&env).expect("v2 decodes") {
            RangeProofKind::PackedZk(p) => assert!(verify_range_zk(&stmt, &p)),
            _ => panic!("wrong kind"),
        }
        // Unknown version tag → fail-closed.
        let mut bad = env.clone();
        bad[0] = 99;
        assert!(decode_range_versioned(&bad).is_err());
        assert!(decode_range_versioned(&[]).is_err());
    }

    /// C-1 regression: the decoder must reject a polynomial coefficient that is
    /// not reduced mod q (>= q). Otherwise `t` and `t+q` decode to distinct
    /// key images that verify identically but hash to different nullifiers —
    /// an unlimited double-spend.
    #[test]
    fn decoder_rejects_non_canonical_coefficient() {
        // A canonical single-coefficient polyvec round-trips.
        let good = PolyVec(vec![constant(1)]);
        let bytes = encode_polyvec(&good);
        assert!(decode_polyvec(&bytes).is_ok());

        // Now forge a coefficient == q (non-canonical). Layout of encode_polyvec:
        // [u32 vec_len=1][u32 poly_len=D][coeff0 u64][coeff1 u64]...
        let mut forged = bytes.clone();
        let coeff0_off = 4 + 4; // skip vec_len + poly_len prefixes
        forged[coeff0_off..coeff0_off + 8].copy_from_slice(&Poly::Q.to_le_bytes());
        assert!(
            decode_polyvec(&forged).is_err(),
            "coefficient == q must be rejected as non-canonical"
        );

        // q+1 too.
        let mut forged2 = bytes;
        forged2[coeff0_off..coeff0_off + 8].copy_from_slice(&(Poly::Q + 1).to_le_bytes());
        assert!(decode_polyvec(&forged2).is_err());
    }

    /// F-A regression: a polynomial of the wrong DEGREE (coefficient count != D)
    /// is rejected — otherwise it panics downstream (NTT twiddle-table OOB /
    /// matvec dimension assert) on adversarial input at block execution.
    #[test]
    fn decoder_rejects_wrong_degree_polynomial() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_le_bytes()); // polyvec len = 1
        buf.extend_from_slice(&((Poly::D as u32) + 1).to_le_bytes()); // poly len = D+1
        buf.extend(std::iter::repeat(0u8).take((Poly::D + 1) * 8)); // enough bytes
        assert!(
            decode_polyvec(&buf).is_err(),
            "a poly of degree != D must be rejected"
        );
    }

    /// H-1 regression: an adversarial length prefix that cannot fit in the
    /// remaining bytes is rejected before any allocation (no OOM abort).
    #[test]
    fn decoder_rejects_oversized_length_prefix() {
        // A tiny buffer whose first u32 claims 4 billion elements.
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_le_bytes()); // vec_len = 2^32-1
        buf.extend_from_slice(&[0u8; 8]); // a few trailing bytes
        assert!(
            decode_polyvec(&buf).is_err(),
            "must reject before Vec::with_capacity(u32::MAX)"
        );
    }

    #[test]
    fn binary_proof_round_trips() {
        let k = RingCommitKey::production(1, 0xB17B);
        let mut prg = SplitMix64::new(1);
        let r = PolyVec::sample_short(k.a1.cols, ETA, &mut prg);
        let c = k.commit(&PolyVec(vec![constant(1)]), &r);
        let p = BinRqParams::production();
        let proof = prove_bit_rq(&k, &c, 1, &r, &p, b"", 5).unwrap();
        let bytes = encode_binary(&proof);
        assert_eq!(decode_binary(&bytes).unwrap().f, proof.f);
        assert_eq!(encode_binary(&decode_binary(&bytes).unwrap()), bytes, "round-trip stable");
    }

    #[test]
    fn range_proof_round_trips() {
        let key = RingRangeKey::production(8, 7);
        let mut prg = SplitMix64::new(2);
        let r_v = PolyVec::sample_short(key.value_key().a1.cols, ETA, &mut prg);
        let c_v = key.value_key().commit(&PolyVec(vec![constant(100)]), &r_v);
        let proof = prove_range_rq(&key, &c_v, 100, &r_v, ETA, 1 << 17, 3).unwrap();
        let bytes = encode_range(&proof);
        let back = decode_range(&bytes).unwrap();
        assert_eq!(back.bits_proof.f, proof.bits_proof.f);
        assert_eq!(encode_range(&back), bytes, "range round-trip stable");
    }

    #[test]
    fn limb_balance_round_trips() {
        let rk = RingRangeKey::production(13, 0x5A18);
        let (in_c, out_c, pf) = crate::limb_balance::prove_limb_balance(
            &rk, &[(1u128 << 40) + 5], &[(1u128 << 40) - 100, 103], 2, 8, 7,
        )
        .unwrap();
        let bytes = encode_limb_balance(&pf);
        let back = decode_limb_balance(&bytes).unwrap();
        assert_eq!(encode_limb_balance(&back), bytes, "limb-balance round-trip stable");
        // The decoded proof still verifies against the same commitments.
        assert!(crate::limb_balance::verify_limb_balance(&rk, &in_c, &out_c, 2, 8, &back));
    }

    #[test]
    fn ring_sig_round_trips() {
        let key = RingSigKeyRq::production(4, 0x2146);
        let (sk, pk) = key.keygen(1);
        let mut ring = Vec::new();
        for i in 0..4 {
            ring.push(if i == 1 { pk.clone() } else { key.keygen(100 + i).1 });
        }
        let sig = sign(&key, &ring, 1, &sk, b"m", 1).unwrap();
        let bytes = encode_ring_sig(&sig);
        let back = decode_ring_sig(&bytes).unwrap();
        assert_eq!(back.tag, sig.tag);
        assert_eq!(encode_ring_sig(&back), bytes, "ring-sig round-trip stable");
    }

    #[test]
    fn memo_round_trips() {
        let r: Vec<i128> = (0..16).map(|i| i - 8).collect();
        let memo = encrypt_memo(b"ss", 12345, &r);
        let bytes = encode_memo(&memo);
        assert_eq!(decode_memo(&bytes).unwrap(), memo);
    }
}
