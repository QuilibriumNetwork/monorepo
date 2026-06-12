//! Rust port of `node/consensus/reward/proof_of_meaningful_work.go` and
//! `node/consensus/reward/baseline_fee.go`.
//!
//! Quilibrium's reward issuance uses a Proof-of-Meaningful-Work (PoMW)
//! formula that's nonlinear in `world_state_bytes` and the prover's
//! per-allocation `state_size`. Go computes this using
//! `shopspring/decimal` with 53 bits of precision.
//!
//! **Precision strategy.** We use a hybrid approach:
//!
//! - Pure big-integer ops where Go uses pure big-integer ops
//!   (`GetBaselineFee`'s Sub/Exp/Quo pipeline).
//! - Integer nth-root for the `result^(1/2^n)` step in `pomw_basis`
//!   (`num_integer::Roots::nth_root`). For `n=1` (mainnet typical)
//!   this is an integer square root. For larger `n` it's integer
//!   2^n-th root.
//! - Scaling by a large fixed-point factor (`POMW_SCALE = 1 << 53`)
//!   inside the root so we retain ~53 bits of fractional precision,
//!   then dividing back out after the final multiply. This matches
//!   shopspring/decimal's effective precision bound.
//!
//! This approach is **not guaranteed** byte-identical to Go in the
//! least-significant digits under all inputs, because shopspring's
//! `PowWithPrecision` uses a specific rounding mode and internal
//! algorithm we don't fully replicate. For the ranges seen on
//! mainnet (difficulty ~50k-200k → generation=1 → pure square root)
//! the low-order deviation is bounded to a few wei-equivalents and
//! can be driven to zero by switching the backing library. This is
//! called out in the crate README and revisited before any write-back
//! path is wired.

use std::collections::HashMap;

use num_bigint::BigInt;
#[allow(unused_imports)]
use num_integer::Roots; // used via `BigInt::sqrt()` and `BigInt::nth_root()`
use num_traits::{One, ToPrimitive, Zero};

use quil_types::consensus::{ProverAllocation, RewardIssuance};
use quil_types::error::Result;

/// Shopspring-equivalent working precision: 53 bits.
const POMW_SCALE_BITS: u32 = 53;

/// The hard-coded PoMW numerator from
/// `proof_of_meaningful_work.go:95`:
/// `1_125_899_906_842_624 = 2^50`, i.e. the world-state divisor
/// (1 MB = 2^20) scaled by the bytes-in-a-GB (2^30). Go inverts the
/// relation ahead of time for fewer steps and higher precision.
pub const POMW_NUMERATOR: u64 = 1_125_899_906_842_624;

/// QUIL token units: 8_000_000_000 (8 billion sub-units per QUIL).
pub const QUIL_TOKEN_UNITS: u64 = 8_000_000_000;

/// Compute the PoMW basis: `(POMW_NUMERATOR / world_state_bytes) ^
/// (1/2^generation)` x `units`, where `generation` is the number of
/// 10_000-factor reductions from `difficulty` to 0.
///
/// Returns `BigInt::zero()` for degenerate inputs (world_state_bytes = 0).
pub fn pomw_basis(difficulty: u64, world_state_bytes: u64, units: u64) -> BigInt {
    if world_state_bytes == 0 {
        return BigInt::zero();
    }

    // Count generations: loop `difflog /= 10000` until < 10000.
    let mut difflog = difficulty;
    let mut generation: u32 = 0;
    while difflog >= 10_000 {
        difflog /= 10_000;
        generation += 1;
    }

    // Scaled normalized value: POMW_NUMERATOR / world_state_bytes,
    // multiplied by 2^(2^generation * POMW_SCALE_BITS) so the
    // integer nth-root preserves ~53 bits of fractional precision.
    // For generation=0 the exponent is 0 and we skip the root
    // entirely; for generation=1 it's a square root of the scaled
    // value; for generation=k it's the 2^k-th root.
    let numerator = BigInt::from(POMW_NUMERATOR);
    let denominator = BigInt::from(world_state_bytes);

    if generation == 0 {
        // Pure division by world_state_bytes, no root. Matches
        // `result ^ (1/1) == result`.
        let normalized = &numerator / &denominator;
        return &normalized * BigInt::from(units);
    }

    // Root exponent: 2^generation.
    let exp_denom: u32 = 1u32 << generation;
    // Total pre-root scaling: multiply normalized by 2^(exp_denom *
    // POMW_SCALE_BITS) so the nth-root preserves precision bits.
    let pre_scale_bits: u32 = exp_denom * POMW_SCALE_BITS;
    let pre_scale = BigInt::one() << pre_scale_bits;

    let scaled = (&numerator << pre_scale_bits) / &denominator;
    let rooted = scaled.nth_root(exp_denom);

    // After the root, the result has `POMW_SCALE_BITS` fractional
    // bits. Multiply by units, then shift right to remove them.
    let mul = &rooted * BigInt::from(units);
    let _ = pre_scale; // kept for clarity; shift is equivalent
    mul >> POMW_SCALE_BITS
}

/// Scaled baseline fee. Mirror of
/// `node/consensus/reward/baseline_fee.go::GetBaselineFee`.
///
/// The math is:
/// ```text
/// current  = pomw_basis(difficulty, world_state_bytes, units)
/// affected = pomw_basis(difficulty, world_state_bytes + total_added, units)
/// delta    = current - affected
/// lhs      = delta^2 / world_state_bytes
/// rhs      = total_added
/// result   = max(lhs, rhs)
/// ```
pub fn get_baseline_fee(
    difficulty: u64,
    world_state_bytes: u64,
    total_added: u64,
    units: u64,
) -> BigInt {
    let current = pomw_basis(difficulty, world_state_bytes, units);
    let affected = pomw_basis(difficulty, world_state_bytes + total_added, units);
    let delta = &current - &affected;

    if world_state_bytes == 0 {
        return BigInt::from(total_added);
    }
    let num = &delta * &delta;
    let denom = BigInt::from(world_state_bytes);
    let lhs = num / denom;
    let rhs = BigInt::from(total_added);
    if lhs >= rhs {
        lhs
    } else {
        rhs
    }
}

/// PoMW reward issuance.
pub struct OptRewardIssuance;

impl RewardIssuance for OptRewardIssuance {
    fn calculate(
        &self,
        difficulty: u64,
        world_state_bytes: u64,
        units: u64,
        provers: &[HashMap<String, ProverAllocation>],
    ) -> Result<Vec<BigInt>> {
        let basis = pomw_basis(difficulty, world_state_bytes, units);
        if world_state_bytes == 0 {
            return Ok(provers.iter().map(|_| BigInt::zero()).collect());
        }
        let world_bi = BigInt::from(world_state_bytes);

        let mut out: Vec<BigInt> = Vec::with_capacity(provers.len());
        for allocs in provers {
            let mut total = BigInt::zero();
            for alloc in allocs.values() {
                // divisor = 2^(ring + 1). u8 fits up to ring 62.
                let ring = alloc.ring.min(62);
                let divisor_u64: u64 = 1u64 << (ring as u32 + 1);
                let divisor_bi = BigInt::from(divisor_u64);

                if alloc.shards == 0 {
                    continue;
                }

                // shard_factor = shards^(1/2) carrying POMW_SCALE_BITS
                // fractional bits. Same trick as `pomw_basis`
                // generation=1.
                let shards_scaled =
                    BigInt::from(alloc.shards) << (2u32 * POMW_SCALE_BITS);
                let shards_sqrt = shards_scaled.sqrt();
                if shards_sqrt.is_zero() {
                    continue;
                }

                // Match Go's `decimal.Decimal` chain (88-104 of
                // `optimized_proof_of_meaningful_work.go`): each
                // intermediate `Div` keeps full decimal precision and
                // only the final `result.BigInt()` truncates. To match
                // this in integer arithmetic, fuse the chain into a
                // single division and pre-scale by `POMW_SCALE_BITS` so
                // the `shards_sqrt` factor cancels:
                //
                //   step3 = (state_size * basis * 2^POMW_SCALE_BITS)
                //         / (world * divisor * shards_sqrt)
                //
                // shards_sqrt carries POMW_SCALE_BITS fractional bits;
                // dividing by it removes those bits, so we pre-multiply
                // by 2^POMW_SCALE_BITS to land back at integer scale.
                // The fused division has at most one truncation —
                // matching Go's "single BigInt() conversion at the end"
                // far more closely than the previous three sequential
                // truncations.
                let num = BigInt::from(alloc.state_size)
                    * &basis
                    << POMW_SCALE_BITS;
                let denom = &world_bi * &divisor_bi * &shards_sqrt;
                if denom.is_zero() {
                    continue;
                }
                let step3 = num / denom;

                total += step3;
            }
            out.push(total);
        }
        Ok(out)
    }
}

/// Hint for callers: `pomw_basis` returns a BigInt that may not
/// fit in u64 for small world-state sizes. Use this helper if you
/// want a non-panicking truncation for logging.
pub fn big_to_u64_saturating(n: &BigInt) -> u64 {
    n.to_u64().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generation 0: difficulty < 10000. Exponent is `1/1`, so
    /// `pomw_basis` reduces to `(POMW_NUMERATOR / world) * units`.
    #[test]
    fn pomw_basis_generation_zero() {
        let difficulty = 5_000u64;
        let world = 1 << 30; // 1 GB
        let units = 1_000_000u64;

        let basis = pomw_basis(difficulty, world, units);
        // Expected: (2^50 / 2^30) * 10^6 = 2^20 * 10^6 = 1_048_576_000_000
        assert_eq!(basis, BigInt::from(1_048_576_000_000u64));
    }

    /// Generation 1: difficulty 10000..99_999_999. Exponent `1/2`,
    /// integer sqrt with 53-bit fractional precision.
    #[test]
    fn pomw_basis_generation_one_is_sqrt_like() {
        let difficulty = 50_000u64;
        let world = 1 << 30;
        let units = 1_000_000u64;

        // generation=1 → sqrt(POMW_NUMERATOR / world) × units
        // = sqrt(2^20) × 10^6 = 1024 × 10^6 = 1_024_000_000
        let basis = pomw_basis(difficulty, world, units);
        assert_eq!(basis, BigInt::from(1_024_000_000u64));
    }

    /// Basis is monotone non-decreasing in `world_state_bytes` IFF
    /// we invert the relation correctly. Actually here it should be
    /// NON-INCREASING in world: more world → each unit smaller →
    /// smaller basis.
    #[test]
    fn pomw_basis_is_non_increasing_in_world() {
        let a = pomw_basis(5_000, 1 << 20, 1_000);
        let b = pomw_basis(5_000, 1 << 30, 1_000);
        let c = pomw_basis(5_000, 1 << 40, 1_000);
        assert!(a >= b, "a={} b={}", a, b);
        assert!(b >= c, "b={} c={}", b, c);
    }

    /// `get_baseline_fee` returns at least `total_added` — the `rhs`
    /// branch of the `max` — so the fee is always non-zero for any
    /// nonzero allocation growth.
    #[test]
    fn baseline_fee_min_is_total_added() {
        let fee = get_baseline_fee(5_000, 1 << 30, 1024, 1_000);
        assert!(fee >= BigInt::from(1024u64));
    }

    /// Degenerate: world_state_bytes = 0 short-circuits to
    /// `total_added` to avoid a divide-by-zero.
    #[test]
    fn baseline_fee_zero_world_returns_added() {
        let fee = get_baseline_fee(5_000, 0, 1024, 1_000);
        assert_eq!(fee, BigInt::from(1024u64));
    }

    /// Reward calculator returns a vector of the same length as the
    /// input, and zero contribution for empty allocations.
    #[test]
    fn opt_reward_zero_provers_returns_zeros() {
        let r = OptRewardIssuance;
        let provers: Vec<HashMap<String, ProverAllocation>> =
            vec![HashMap::new(), HashMap::new()];
        let out = r.calculate(5_000, 1 << 30, 1_000, &provers).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|v| v.is_zero()));
    }

    /// Reward calculator with one prover holding one allocation
    /// should produce a positive reward.
    #[test]
    fn opt_reward_single_allocation_positive() {
        use quil_types::consensus::ProverAllocation;
        let r = OptRewardIssuance;

        let mut allocs = HashMap::new();
        allocs.insert(
            "shard-1".to_string(),
            ProverAllocation {
                ring: 0,                   // divisor = 2
                shards: 1,                 // sqrt = 1
                state_size: 1 << 20,       // 1 MB
            },
        );
        let out = r
            .calculate(5_000, 1 << 30, 1_000_000, &[allocs])
            .unwrap();
        assert_eq!(out.len(), 1);
        assert!(
            !out[0].is_zero(),
            "expected positive reward, got {}",
            out[0]
        );
    }

    /// Reward scales linearly with state_size (same ring, same
    /// shards, same world). Double the state → double the reward.
    #[test]
    fn opt_reward_scales_with_state_size() {
        use quil_types::consensus::ProverAllocation;
        let r = OptRewardIssuance;

        let alloc_small = {
            let mut m = HashMap::new();
            m.insert(
                "s".to_string(),
                ProverAllocation {
                    ring: 0,
                    shards: 1,
                    state_size: 1 << 20,
                },
            );
            m
        };
        let alloc_big = {
            let mut m = HashMap::new();
            m.insert(
                "s".to_string(),
                ProverAllocation {
                    ring: 0,
                    shards: 1,
                    state_size: 1 << 21, // 2x
                },
            );
            m
        };

        let small = r
            .calculate(5_000, 1 << 30, 1_000_000, &[alloc_small])
            .unwrap()[0]
            .clone();
        let big = r
            .calculate(5_000, 1 << 30, 1_000_000, &[alloc_big])
            .unwrap()[0]
            .clone();
        assert_eq!(&big, &(&small * 2), "big={} small={}", big, small);
    }
}
