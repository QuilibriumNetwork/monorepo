//! Full-width confidential-amount balance — the MatRiCT-style
//! limb-with-carry-chain balance that lets amounts be 64/128-bit while every
//! committed value stays `< q ≈ 2^36`.
//!
//! # Why single-coefficient amounts don't work
//!
//! A value in one ring coefficient is sound only for `v < q`, and the *aggregate*
//! `Σin − Σout − fee` must also not wrap `q` — so single-coefficient amounts cap
//! at `~2^28` (with the overflow guard). Real money needs 64/128-bit.
//!
//! # Construction
//!
//! Represent an amount as `L` base-`2^16` limbs: `v = Σ_j 2^{16j}·limb_j`,
//! `limb_j ∈ [0, 2^16)`. Conservation `Σin_v = Σout_v + fee` (over the integers)
//! is `Σ_j 2^{16j}·D_j = 0` where `D_j = Σin limb_j − Σout limb_j − fee_j`. This
//! holds iff there are carries `c_j` with
//! ```text
//!   D_j + c_{j-1} = 2^16·c_j (c_{-1} = 0),   and   c_{L-1} = 0 .
//! ```
//! Each per-limb relation is LINEAR over the committed limbs + carries (proved by
//! [`crate::linear_rq`]) — no `2^{8j}` positional weight ever appears, so nothing
//! wraps `q`. Carries are small (`|c_j| ≤ #io`), range-proved, and the top carry
//! is fixed to `0`.
//!
//! # Base choice (`2^8`, not `2^16`) — soundness-critical
//!
//! The one large coefficient is the `−B·c_j` carry term. Its `B·η` witness norm
//! sets the rejection mask: acceptance `≈ (1 − τ·B·η / mask)^{λ·256}`, so a
//! `B = 2^16` coefficient needs `mask ≈ 2^33` for non-negligible acceptance,
//! pushing the extracted norm to `≈ 2^35 ≈ q` and BREAKING M-SIS binding. With
//! `B = 2^8` the mask `2^26` gives ~½ acceptance and extracted norm `≈ 2^27 ≪ q`,
//! keeping H_B/commit M-SIS strong. Cost: 8 limbs for 64-bit (16 for 128-bit).

use crate::linear_rq::{prove_linear_rq, verify_linear_rq};
use crate::module::{PolyVec, RingCommitKey, RingCommitment, ETA};
use crate::range_rq::{prove_range_rq, verify_range_rq, RangeProofRq, RingRangeKey};
use crate::rq::Poly;

/// Bits per limb. `2^8` (not `2^16`) keeps the `−B·c_j` carry coefficient small
/// enough that the balance mask `2^26` gives good rejection acceptance and a
/// `≪ q` extracted norm — see the module-level "Base choice" note.
pub const LIMB_BITS: u32 = 8;
/// Limb base `2^8`.
pub const LIMB_BASE: i64 = 1 << LIMB_BITS;
/// Range-proof width for limbs and offset carries (`> 2·MAX_CARRY`). Callers must
/// build the [`RingRangeKey`] at this width (`verify_limb_balance` enforces it).
pub const RANGE_BITS: usize = 13;
/// Carry magnitude bound (`≥ #io·2^(RANGE_BITS-LIMB_BITS)`); carries range-proved
/// in `[0, 2·MAX_CARRY)` after a `+MAX_CARRY` offset.
pub const MAX_CARRY: i64 = 1 << 12;
/// Balance-proof mask (wide enough for the `2^8·c_j` term's `2^8·η` norm, small
/// enough that the extracted norm stays `≈ 2^27 ≪ q = 2^36`).
const BAL_MASK: i64 = 1 << 26;

/// Split an amount into `n_limbs` base-`2^8` limbs (low-order first).
pub fn limbs_of(v: u128, n_limbs: usize) -> Vec<u64> {
    let mask = (LIMB_BASE - 1) as u128;
    (0..n_limbs).map(|j| ((v >> (LIMB_BITS as usize * j)) & mask) as u64).collect()
}

fn const_poly(v: i64) -> Poly {
    let q = Poly::Q as i64;
    let mut p = Poly::zero();
    p.c[0] = ((v % q + q) % q) as u64;
    p
}

/// A full-width balance proof: the carry commitments, their range proofs, and one
/// per-limb balance opening.
pub struct LimbBalanceProof {
    pub carries: Vec<RingCommitment>,   // c_0 .. c_{L-2} (c_{L-1}=0 implicit)
    pub carry_ranges: Vec<RangeProofRq>, // range of (c_j + MAX_CARRY)
    pub out_ranges: Vec<Vec<RangeProofRq>>, // each output limb ∈ [0, 2^RANGE_BITS) — no inflation
    pub per_limb: Vec<Vec<u8>>,          // L wire-encoded per-limb balance openings
}

/// Commit one scalar value under `vkey` with fresh short randomness.
fn commit_scalar(vkey: &RingCommitKey, v: i64, prg: &mut crate::arith::SplitMix64) -> (RingCommitment, PolyVec) {
    let r = PolyVec::sample_short(vkey.a1.cols, ETA, prg);
    (vkey.commit(&PolyVec(vec![const_poly(v)]), &r), r)
}

/// Prove `Σ in = Σ out + fee` at full width. Returns the per-limb input/output
/// value commitments (row-major `[amount][limb]`) and the balance proof.
#[allow(clippy::type_complexity)]
pub fn prove_limb_balance(
    range_key: &RingRangeKey,
    in_amounts: &[u128],
    out_amounts: &[u128],
    fee: u128,
    n_limbs: usize,
    seed: u64,
) -> Option<(Vec<Vec<RingCommitment>>, Vec<Vec<RingCommitment>>, LimbBalanceProof)> {
    use crate::arith::SplitMix64;
    // The commit key MUST share (a1, a2_val) with the range key, else range
    // proofs on these commitments reject.
    let vkey = &range_key.value_key();
    let mut prg = SplitMix64::new(seed);
    // Commit every limb of every amount, keeping the randomness.
    let commit_amounts = |amts: &[u128], prg: &mut SplitMix64| {
        amts.iter()
            .map(|&v| {
                limbs_of(v, n_limbs)
                    .into_iter()
                    .map(|l| commit_scalar(vkey, l as i64, prg))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    };
    let in_c = commit_amounts(in_amounts, &mut prg);
    let out_c = commit_amounts(out_amounts, &mut prg);
    let proof = prove_limb_balance_core(range_key, &in_c, &out_c, in_amounts, out_amounts, fee, n_limbs, seed)?;
    Some((
        in_c.iter().map(|a| a.iter().map(|x| x.0.clone()).collect()).collect(),
        out_c.iter().map(|a| a.iter().map(|x| x.0.clone()).collect()).collect(),
        proof,
    ))
}

/// Prove a full-width balance binding **externally-supplied** commitments — the
/// spend's revealed pseudo-inputs `C'` and the coin outputs — rather than
/// self-generated ones. Each amount's `L` virtual per-limb commitments share the
/// amount's randomness `r` (they are `(C.t1, C.t2[j])` slices of one ℓ=`L`
/// vector-message commitment). Used by the confidential-transfer path so the
/// balance is over the same commitments the value-link proof bound.
#[allow(clippy::too_many_arguments)]
pub fn prove_limb_balance_bound(
    range_key: &RingRangeKey,
    in_virtual: &[Vec<RingCommitment>], // per input: L limb commitments (share `in_rand[i]`)
    in_rand: &[PolyVec],                // per input: the shared randomness
    out_virtual: &[Vec<RingCommitment>],
    out_rand: &[PolyVec],
    in_amounts: &[u128],
    out_amounts: &[u128],
    fee: u128,
    n_limbs: usize,
    seed: u64,
) -> Option<LimbBalanceProof> {
    // Pair each limb commitment with its amount's shared randomness.
    let pair = |vc: &[Vec<RingCommitment>], rand: &[PolyVec]| -> Vec<Vec<(RingCommitment, PolyVec)>> {
        vc.iter()
            .zip(rand)
            .map(|(limbs, r)| limbs.iter().map(|c| (c.clone(), r.clone())).collect())
            .collect()
    };
    let in_c = pair(in_virtual, in_rand);
    let out_c = pair(out_virtual, out_rand);
    prove_limb_balance_core(range_key, &in_c, &out_c, in_amounts, out_amounts, fee, n_limbs, seed)
}

/// The carry-chain + range + per-limb-opening core, over pre-built commitments
/// (each `(commitment, randomness)`). Shared by [`prove_limb_balance`] (fresh
/// commitments) and [`prove_limb_balance_bound`] (externally-supplied).
#[allow(clippy::too_many_arguments)]
fn prove_limb_balance_core(
    range_key: &RingRangeKey,
    in_c: &[Vec<(RingCommitment, PolyVec)>],
    out_c: &[Vec<(RingCommitment, PolyVec)>],
    in_amounts: &[u128],
    out_amounts: &[u128],
    fee: u128,
    n_limbs: usize,
    seed: u64,
) -> Option<LimbBalanceProof> {
    use crate::arith::SplitMix64;
    let vkey = &range_key.value_key();
    let mut prg = SplitMix64::new(seed ^ 0xCA22_1E5);
    let fee_limbs = limbs_of(fee, n_limbs);

    // Per-limb integer difference D_j and the carry chain.
    let mut carries_val = vec![0i64; n_limbs]; // c_0..c_{L-1}; c_{L-1} must be 0
    let mut prev = 0i64;
    for j in 0..n_limbs {
        let sum_in: i64 = in_amounts.iter().map(|&v| limbs_of(v, n_limbs)[j] as i64).sum();
        let sum_out: i64 = out_amounts.iter().map(|&v| limbs_of(v, n_limbs)[j] as i64).sum();
        let d = sum_in - sum_out - fee_limbs[j] as i64;
        let t = d + prev;
        if t % LIMB_BASE != 0 {
            return None; // not balanced
        }
        carries_val[j] = t / LIMB_BASE;
        prev = carries_val[j];
    }
    if carries_val[n_limbs - 1] != 0 {
        return None; // top carry must vanish ⇒ balanced
    }

    // Range-prove each OUTPUT limb ∈ [0, 2^RANGE_BITS): bounds amounts non-negative
    // so no output can inflate value. (Inputs are pre-validated coins.)
    debug_assert_eq!(range_key.n_bits(), RANGE_BITS);
    let mut out_ranges = Vec::with_capacity(out_c.len());
    for (i, a) in out_c.iter().enumerate() {
        let vlimbs = limbs_of(out_amounts[i], n_limbs);
        let mut row = Vec::with_capacity(n_limbs);
        for (j, (cc, cr)) in a.iter().enumerate() {
            let rp = prove_range_rq(range_key, cc, vlimbs[j], cr, ETA, BAL_MASK, seed ^ (0xD00 + (i * n_limbs + j) as u64))?;
            row.push(rp);
        }
        out_ranges.push(row);
    }

    // Commit the carries c_0..c_{L-2} and range-prove (c_j + MAX_CARRY) ∈ [0, 2·MAX_CARRY).
    let mut carries = Vec::new();
    let mut carry_r = Vec::new();
    let mut carry_ranges = Vec::new();
    for j in 0..n_limbs - 1 {
        let (cc, cr) = commit_scalar(vkey, carries_val[j], &mut prg);
        // shifted commitment for the range proof: c_j + MAX_CARRY
        let shifted = RingCommitment {
            t1: cc.t1.clone(),
            t2: PolyVec(vec![cc.t2.0[0].add(&const_poly(MAX_CARRY))]),
        };
        let rp = prove_range_rq(range_key, &shifted, (carries_val[j] + MAX_CARRY) as u64, &cr, ETA, BAL_MASK, seed ^ (0xCA1 + j as u64))?;
        carry_ranges.push(rp);
        carries.push(cc);
        carry_r.push(cr);
    }

    // Per-limb balance opening: Σin limb_j − Σout limb_j + c_{j-1} − 2^8·c_j = fee_j.
    let mut per_limb = Vec::new();
    for j in 0..n_limbs {
        let mut commitments = Vec::new();
        let mut coeffs = Vec::new();
        let mut rand = Vec::new();
        for a in in_c {
            commitments.push(a[j].0.clone());
            coeffs.push(1i64);
            rand.push(a[j].1.clone());
        }
        for a in out_c {
            commitments.push(a[j].0.clone());
            coeffs.push(-1i64);
            rand.push(a[j].1.clone());
        }
        if j > 0 {
            commitments.push(carries[j - 1].clone());
            coeffs.push(1i64);
            rand.push(carry_r[j - 1].clone());
        }
        if j < n_limbs - 1 {
            commitments.push(carries[j].clone());
            coeffs.push(-LIMB_BASE);
            rand.push(carry_r[j].clone());
        }
        let target = PolyVec(vec![const_poly(fee_limbs[j] as i64)]);
        let proof = prove_linear_rq(vkey, &commitments, &coeffs, &target, &rand, ETA, BAL_MASK, seed ^ (0xB17 + j as u64))?;
        per_limb.push(crate::wire::encode_opening(&proof));
    }

    Some(LimbBalanceProof { carries, carry_ranges, out_ranges, per_limb })
}

/// Verify a full-width limb balance.
pub fn verify_limb_balance(
    range_key: &RingRangeKey,
    in_c: &[Vec<RingCommitment>],
    out_c: &[Vec<RingCommitment>],
    fee: u128,
    n_limbs: usize,
    proof: &LimbBalanceProof,
) -> bool {
    let vkey = &range_key.value_key();
    if proof.carries.len() != n_limbs - 1
        || proof.carry_ranges.len() != n_limbs - 1
        || proof.per_limb.len() != n_limbs
        || proof.out_ranges.len() != out_c.len()
        || range_key.n_bits() != RANGE_BITS
    {
        return false;
    }
    let fee_limbs = limbs_of(fee, n_limbs);

    // Output-limb range proofs: each out limb ∈ [0, 2^RANGE_BITS) ⇒ non-negative,
    // bounded amounts ⇒ no output inflates value.
    for (i, a) in out_c.iter().enumerate() {
        if proof.out_ranges[i].len() != n_limbs || a.len() != n_limbs {
            return false;
        }
        for (j, cc) in a.iter().enumerate() {
            if !verify_range_rq(range_key, cc, &proof.out_ranges[i][j], ETA, BAL_MASK) {
                return false;
            }
        }
    }

    // Carry range proofs: (c_j + MAX_CARRY) ∈ [0, 2·MAX_CARRY).
    for (j, rp) in proof.carry_ranges.iter().enumerate() {
        let shifted = RingCommitment {
            t1: proof.carries[j].t1.clone(),
            t2: PolyVec(vec![proof.carries[j].t2.0[0].add(&const_poly(MAX_CARRY))]),
        };
        if !verify_range_rq(range_key, &shifted, rp, ETA, BAL_MASK) {
            return false;
        }
    }

    // Per-limb balance.
    for j in 0..n_limbs {
        let mut commitments = Vec::new();
        let mut coeffs = Vec::new();
        for a in in_c {
            commitments.push(a[j].clone());
            coeffs.push(1i64);
        }
        for a in out_c {
            commitments.push(a[j].clone());
            coeffs.push(-1i64);
        }
        if j > 0 {
            commitments.push(proof.carries[j - 1].clone());
            coeffs.push(1i64);
        }
        if j < n_limbs - 1 {
            commitments.push(proof.carries[j].clone());
            coeffs.push(-LIMB_BASE);
        }
        let target = PolyVec(vec![const_poly(fee_limbs[j] as i64)]);
        let op = match crate::wire::decode_opening(&proof.per_limb[j]) {
            Ok(o) => o,
            Err(_) => return false,
        };
        if !verify_linear_rq(vkey, &commitments, &coeffs, &target, &op, ETA, BAL_MASK) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: usize = 8; // 64-bit amounts in base-2^8 limbs

    fn rkey() -> RingRangeKey {
        // range key at RANGE_BITS=13 (⊃ limbs and 2·MAX_CARRY); its value_key()
        // is the shared commit key.
        RingRangeKey::production(13, 0x5A18)
    }

    #[test]
    fn full_width_balanced_verifies() {
        // 64-bit amounts spanning multiple limbs, with real carries:
        //   in {2^40 + 5} = out {2^40 − 100, 103} + fee 2.
        let rk = rkey();
        let v_in = (1u128 << 40) + 5;
        let (o1, o2, fee) = ((1u128 << 40) - 100, 103u128, 2u128);
        assert_eq!(v_in, o1 + o2 + fee);
        let (in_c, out_c, pf) =
            prove_limb_balance(&rk, &[v_in], &[o1, o2], fee, L, 7).expect("balances");
        assert!(verify_limb_balance(&rk, &in_c, &out_c, fee, L, &pf));
    }

    #[test]
    fn unbalanced_is_unprovable() {
        // Outputs exceed inputs+fee ⇒ the carry chain's top carry ≠ 0 ⇒ no proof.
        let rk = rkey();
        let v_in = 1u128 << 40;
        assert!(prove_limb_balance(&rk, &[v_in], &[v_in, 1000], 0, L, 8).is_none());
    }

    #[test]
    fn full_128bit_balanced_verifies() {
        // 128-bit amounts (16 limbs) — beyond u64, the headline width.
        let rk = rkey();
        let v_in = (1u128 << 100) + 42;
        let (o1, o2, fee) = ((1u128 << 100) - 1000, 957u128, 85u128);
        assert_eq!(v_in, o1 + o2 + fee);
        let (in_c, out_c, pf) =
            prove_limb_balance(&rk, &[v_in], &[o1, o2], fee, 16, 11).expect("balances");
        assert!(verify_limb_balance(&rk, &in_c, &out_c, fee, 16, &pf));
    }

    #[test]
    fn inflated_output_rejected() {
        // A valid balance, then swap an output commitment for one of a larger
        // amount: the balance opening no longer holds ⇒ reject.
        let rk = rkey();
        let v_in = (1u128 << 40) + 5;
        let (in_c, mut out_c, pf) =
            prove_limb_balance(&rk, &[v_in], &[(1u128 << 40) - 100, 103], 2, L, 13).unwrap();
        // Re-commit output 1 limb 0 as a much larger value (inflation attempt).
        let vk = rk.value_key();
        let mut prg = crate::arith::SplitMix64::new(999);
        let (bad, _r) = commit_scalar(&vk, 9999, &mut prg);
        out_c[1][0] = bad;
        assert!(!verify_limb_balance(&rk, &in_c, &out_c, 2, L, &pf));
    }

    #[test]
    fn tampered_carry_range_rejected() {
        let rk = rkey();
        let v_in = (1u128 << 32) + 7;
        let (in_c, out_c, mut pf) =
            prove_limb_balance(&rk, &[v_in], &[v_in - 2, 2], 0, L, 9).unwrap();
        // Corrupt a carry commitment ⇒ its range proof / balance no longer holds.
        pf.carries[1].t2.0[0].c[0] ^= 1;
        assert!(!verify_limb_balance(&rk, &in_c, &out_c, 0, L, &pf));
    }
}
