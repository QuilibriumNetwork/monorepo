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
//! (`GetBaselineFee`'s Sub/Exp/Quo pipeline).
//! - Integer nth-root for the `result^(1/2^n)` step in `pomw_basis`
//! (`num_integer::Roots::nth_root`). For `n=1` (mainnet typical)
//! this is an integer square root. For larger `n` it's integer
//! 2^n-th root.
//! - Scaling by a large fixed-point factor (`POMW_SCALE = 1 << 53`)
//! inside the root so we retain ~53 bits of fractional precision,
//! then dividing back out after the final multiply. This matches
//! shopspring/decimal's effective precision bound.
//!
//! This approach is **not guaranteed** byte-identical to Go in the
//! least-significant digits under all inputs, because shopspring's
//! `PowWithPrecision` uses a specific rounding mode and internal
//! algorithm we don't fully replicate. For the ranges seen on
//! mainnet (difficulty ~50k-200k → generation=1 → pure square root)
//! the low-order deviation is bounded to a few wei-equivalents and
//! can be driven to zero by switching the backing library. Revisit
//! this before any write-back path is wired.

#[cfg(test)]
use num_traits::One;
use std::collections::HashMap;

use num_bigint::BigInt;
#[allow(unused_imports)]
use num_integer::Roots; // used via `BigInt::sqrt()` and `BigInt::nth_root()`
use num_traits::{ToPrimitive, Zero};

use quil_types::consensus::{ProverAllocation, RewardIssuance};
use quil_types::error::Result;

// Keep the existing engine API while execution, RPC and wallet code share one
// implementation of the consensus pricing arithmetic.
pub use quil_execution::pricing::{
    fee_multiplier_for_cost, get_baseline_fee, pomw_basis, POMW_NUMERATOR, QUIL_TOKEN_UNITS,
};
use quil_execution::pricing::allocation_ring_reward;

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
                let step3 = allocation_ring_reward(
                    &basis, &BigInt::from(alloc.state_size), &world_bi,
                    alloc.ring, alloc.shards,
                );

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
    fn frame_fee_cost_bounds_and_vote_are_consistent() {
        assert_eq!(fee_multiplier_for_cost(quil_execution::pricing::MAINNET_NETWORK, 50_000, u64::MAX, &BigInt::zero(), 7).unwrap(), BigInt::zero());
        for cost in [1, 1024, 195_907, u64::MAX] {
            assert_eq!(fee_multiplier_for_cost(quil_execution::pricing::MAINNET_NETWORK, 50_000, 0, &BigInt::from(cost), 1).unwrap(), BigInt::one());
            assert_eq!(fee_multiplier_for_cost(quil_execution::pricing::MAINNET_NETWORK, 50_000, 0, &BigInt::from(cost), 7).unwrap(), BigInt::from(7));
        }
        assert!(fee_multiplier_for_cost(quil_execution::pricing::MAINNET_NETWORK, 50_000, 0, &BigInt::from(-1), 1).is_err());
        assert!(fee_multiplier_for_cost(quil_execution::pricing::MAINNET_NETWORK, 50_000, 0, &(BigInt::from(u64::MAX) + 1u8), 1).is_err());
        assert!(fee_multiplier_for_cost(quil_execution::pricing::MAINNET_NETWORK, 50_000, u64::MAX, &BigInt::one(), 1).is_err());
        let base = fee_multiplier_for_cost(quil_execution::pricing::MAINNET_NETWORK, 50_000, 1 << 30, &BigInt::from(1024), 1).unwrap();
        assert!(base >= BigInt::one());
        assert_eq!(fee_multiplier_for_cost(quil_execution::pricing::MAINNET_NETWORK, 50_000, 1 << 30, &BigInt::from(1024), 7).unwrap(), base * 7);
    }

    #[test]
    fn frame_fee_multiplier_covers_baseline_without_extra_whole_units() {
        let mut non_divisible = 0;
        for difficulty in [5_000, 50_000, 100_000_000] {
            for world in [1, 1_024, 1 << 20, 1 << 30] {
                for added in [1u64, 3, 1_024, 195_907, 200_771] {
                    let cost = BigInt::from(added);
                    let baseline = get_baseline_fee(difficulty, world, added, QUIL_TOKEN_UNITS);
                    let multiplier = fee_multiplier_for_cost(quil_execution::pricing::MAINNET_NETWORK, difficulty, world, &cost, 1).unwrap();
                    assert!(&multiplier * &cost >= baseline);
                    assert!((&multiplier - BigInt::one()) * &cost < baseline);
                    if &baseline % &cost != BigInt::zero() { non_divisible += 1; }
                    for vote in [0u64, 1, 7] {
                        let voted = fee_multiplier_for_cost(quil_execution::pricing::MAINNET_NETWORK, difficulty, world, &cost, vote).unwrap();
                        assert!(voted * &cost >= &baseline * BigInt::from(vote));
                    }
                }
            }
        }
        assert!(non_divisible > 0, "fixtures must exercise rounding");
    }

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

    /// Basis is NON-INCREASING in `world_state_bytes`: more world →
    /// each unit smaller → smaller basis.
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

    // ---- Issuance-path ring + shard scaling.
    // The 2^(ring+1) divisor and the sqrt-shards branch were untested in the
    // ACTUAL issuance path (every prior opt_reward test used ring=0, shards=1 —
    // only the `shard_info` estimate copy covered them). Relationships are exact
    // by the floor-division identity floor(floor(N/a)/b) == floor(N/(ab)).

    fn one_alloc(
        ring: u8,
        shards: u64,
        state_size: u64,
    ) -> Vec<HashMap<String, quil_types::consensus::ProverAllocation>> {
        use quil_types::consensus::ProverAllocation;
        let mut m = HashMap::new();
        m.insert("s".to_string(), ProverAllocation { ring, shards, state_size });
        vec![m]
    }

    #[test]
    fn opt_reward_halves_each_ring() {
        let r = OptRewardIssuance;
        // Large state so rewards stay non-zero through ring 2.
        let calc =
            |ring| r.calculate(5_000, 1 << 30, 1_000_000, &one_alloc(ring, 1, 1 << 28)).unwrap()[0].clone();
        let r0 = calc(0);
        let r1 = calc(1);
        let r2 = calc(2);
        assert!(!r0.is_zero(), "ring-0 reward must be positive");
        assert_eq!(r1, &r0 / 2, "ring 1 = ring 0 / 2 (divisor 2^(ring+1))");
        assert_eq!(r2, &r1 / 2, "ring 2 = ring 1 / 2");
    }

    /// Generation 2 (difficulty >= 1e8) exercises the 2^k-th-root branch
    /// (`nth_root(4)`), previously untested (only gen 0/1 covered). More roots
    /// → strictly smaller basis, so gen0 > gen1 > gen2 for the same world.
    #[test]
    fn pomw_basis_generation_two_fourth_root() {
        let world = 1u64 << 30;
        let units = 1_000_000u64;
        let g0 = pomw_basis(5_000, world, units); // gen 0 (no root)
        let g1 = pomw_basis(50_000, world, units); // gen 1 (sqrt)
        let g2 = pomw_basis(100_000_000, world, units); // gen 2 (4th root)
        assert!(g2 > BigInt::zero(), "gen-2 basis must be positive, got {g2}");
        assert!(g0 > g1 && g1 > g2, "more roots → smaller basis: g0={g0} g1={g1} g2={g2}");
    }

    #[test]
    fn opt_reward_scales_inversely_with_sqrt_shards() {
        let r = OptRewardIssuance;
        // Perfect-square shard counts → exact integer sqrt, so reward ∝ 1/sqrt(shards).
        let calc =
            |shards| r.calculate(5_000, 1 << 30, 1_000_000, &one_alloc(0, shards, 1 << 28)).unwrap()[0].clone();
        let s1 = calc(1);
        let s4 = calc(4); // sqrt = 2
        let s16 = calc(16); // sqrt = 4
        assert!(!s1.is_zero());
        assert_eq!(s4, &s1 / 2, "shards=4 (sqrt 2) → half");
        assert_eq!(s16, &s1 / 4, "shards=16 (sqrt 4) → quarter");
    }

    /// PoMW rewards STORED DATA: a shard with materialized state earns a
    /// positive reward, while an EMPTY shard (state_size==0) — the localnet's
    /// case — correctly earns ZERO. This confirms rewards_visited=0 on the
    /// empty-shard localnet is the RIGHT answer, not a bug: inject shard data
    /// (state_size>0) and the exact same path pays out. Covers both zero
    /// sources: empty shard allocation AND empty world.
    #[test]
    fn opt_reward_zero_for_empty_nonzero_for_data() {
        let r = OptRewardIssuance;
        let world: u64 = 1 << 30;
        let units = 1_000_000u64;
        let difficulty = 5_000u64;

        // Data present (state_size > 0, world > 0) → positive reward.
        let with_data =
            r.calculate(difficulty, world, units, &one_alloc(0, 1, 1 << 28)).unwrap()[0].clone();
        assert!(
            with_data > BigInt::zero(),
            "a shard with materialized state must earn a reward, got {with_data}"
        );

        // Empty shard (state_size == 0) → zero. This is exactly the localnet:
        // no token/compute/hg data → state_size 0 → no PoMW reward.
        let empty_shard =
            r.calculate(difficulty, world, units, &one_alloc(0, 1, 0)).unwrap()[0].clone();
        assert!(
            empty_shard.is_zero(),
            "empty shard (state_size=0) must earn 0, got {empty_shard}"
        );

        // Empty world (world_state_bytes == 0) → zero for everyone (early return).
        let empty_world =
            r.calculate(difficulty, 0, units, &one_alloc(0, 1, 1 << 28)).unwrap()[0].clone();
        assert!(empty_world.is_zero(), "empty world → 0 reward, got {empty_world}");
    }
}

#[cfg(test)]
mod allocation_arithmetic_characterization {
    use super::*;

    // Frozen pre-extraction issuance path, deliberately independent of the
    // shared helper. Covers accumulation and ring clamping as well as roots.
    #[test]
    fn shared_arithmetic_preserves_previous_issuance() {
        for difficulty in [0, 5_000, 50_000, 100_000_000] {
            for world in [0, 1, 17, 1 << 30, u64::MAX] {
                for ring in [0, 1, 2, 62, 63, 255] {
                    let mut allocations = HashMap::new();
                    let basis = pomw_basis(difficulty, world, QUIL_TOKEN_UNITS);
                    let mut expected = BigInt::zero();
                    for (index, shards) in [0, 1, 2, 3, 4, 5, 7, 16, u64::MAX].into_iter().enumerate() {
                        let state_size = [0, 1, 17, u64::MAX][index % 4];
                        allocations.insert(index.to_string(), ProverAllocation { ring, shards, state_size });
                        if world != 0 && shards != 0 {
                            let sqrt = (BigInt::from(shards) << 106u32).sqrt();
                            let divisor = BigInt::from(1u64 << (u32::from(ring.min(62)) + 1));
                            expected += (BigInt::from(state_size) * &basis << 53u32)
                                / (BigInt::from(world) * divisor * sqrt);
                        }
                    }
                    let actual = OptRewardIssuance.calculate(difficulty, world, QUIL_TOKEN_UNITS, &[allocations, HashMap::new()]).unwrap();
                    assert_eq!(actual, vec![expected, BigInt::zero()], "difficulty={difficulty}, world={world}, ring={ring}");
                }
            }
        }
    }
}
