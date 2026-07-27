//! Canonical wire serialization for the confidential-transaction proofs — a
//! prerequisite for the token-layer integration (which is itself **audit-gated**
//! and not done here). Deterministic length-prefixed encoding; touches no
//! consensus code.
//!
//! Format is the plain reference layout (`u64` coefficient arrays). The
//! production ring form will use a compact NTT/bit-packed encoding; this is the
//! interface, round-trip-tested.

use crate::binary_rq::BinaryProofRq;
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
    w.u32(p.bit_proofs.len() as u32);
    for bp in &p.bit_proofs {
        w.bytes(&encode_binary(bp));
    }
    w.opening(&p.binding);
    w.0
}
pub fn decode_range(b: &[u8]) -> Result<RangeProofRq, DecodeError> {
    let mut r = R::new(b);
    let c_b = r.commit()?;
    let n = r.count(4)?;
    let mut bit_proofs = Vec::with_capacity(n);
    for _ in 0..n {
        bit_proofs.push(decode_binary(&r.bytes()?)?);
    }
    Ok(RangeProofRq { c_b, bit_proofs, binding: r.opening()? })
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

pub fn encode_opening(o: &RingOpeningProof) -> Vec<u8> {
    let mut w = W::default();
    w.opening(o);
    w.0
}
pub fn decode_opening(b: &[u8]) -> Result<RingOpeningProof, DecodeError> {
    R::new(b).opening()
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
        assert_eq!(back.bit_proofs.len(), proof.bit_proofs.len());
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
