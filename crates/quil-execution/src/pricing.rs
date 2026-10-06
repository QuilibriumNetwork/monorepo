//! Shared deterministic QUIL fee arithmetic for execution and fee estimation.
//! Estimates require the executor's pricing snapshot; a shard-info summary is
//! not a substitute for that snapshot. Frame inclusion can change the price.

use num_bigint::BigInt;
use num_traits::{One, ToPrimitive, Zero};
use quil_types::error::Result;

/// Shopspring-equivalent working precision: 53 bits.
pub const POMW_SCALE_BITS: u32 = 53;

/// The hard-coded PoMW numerator from
/// `proof_of_meaningful_work.go:95`:
/// `1_125_899_906_842_624 = 2^50`, i.e. the world-state divisor
/// (1 MB = 2^20) scaled by the bytes-in-a-GB (2^30). Go inverts the
/// relation ahead of time for fewer steps and higher precision.
pub const POMW_NUMERATOR: u64 = 1_125_899_906_842_624;

/// QUIL token units: 8_000_000_000 (8 billion sub-units per QUIL).
pub const QUIL_TOKEN_UNITS: u64 = 8_000_000_000;

/// Network selector of mainnet, the only network priced on the PoMW curve.
pub const MAINNET_NETWORK: u8 = 0;

/// Charge per byte of state growth on every non-mainnet network, before the
/// fee-multiplier vote. The PoMW curve is only meaningful at mainnet's world
/// size; a young test network would otherwise price growth beyond any reward.
pub const NON_MAINNET_UNITS_PER_BYTE: u64 = 1;

/// The `u8` network selector of a 32-byte network identifier (big-endian zero
/// extension, see `confidential::transfer::network_identifier`). `None` if
/// the identifier is not such an extension.
pub fn network_selector(identifier: &[u8]) -> Option<u8> {
    let (prefix, last) = identifier.split_at(identifier.len().checked_sub(1)?);
    (identifier.len() == 32 && prefix.iter().all(|b| *b == 0)).then_some(last[0])
}

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

/// PoMW reward for one allocation's ring, before dividing among its eight
/// prover slots. This is the issuance arithmetic: retain 53 fractional bits
/// for sqrt(data_shards), fuse divisions, and truncate only at the end.
/// Rings above 62 retain issuance's historical clamp. Nonpositive sizes,
/// basis or world size and zero data-shard counts have no reward.
pub fn allocation_ring_reward(
    basis: &BigInt,
    state_size: &BigInt,
    world_bytes: &BigInt,
    ring: u8,
    data_shards: u64,
) -> BigInt {
    if basis <= &BigInt::zero() || state_size <= &BigInt::zero()
        || world_bytes <= &BigInt::zero() || data_shards == 0
    {
        return BigInt::zero();
    }
    let divisor = BigInt::from(1u64 << (u32::from(ring.min(62)) + 1));
    let sqrt = (BigInt::from(data_shards) << (2 * POMW_SCALE_BITS)).sqrt();
    let numerator = state_size * basis << POMW_SCALE_BITS;
    numerator / (world_bytes * divisor * sqrt)
}

/// Project one prover slot's share using the same allocation arithmetic as
/// issuance. Even a partially filled ring splits its reward by eight.
/// Callers supply the confirmed ring for a holding or predicted ring for a
/// candidate; this function does not infer membership or eligibility.
pub fn allocation_prover_reward(
    basis: &BigInt,
    state_size: &BigInt,
    world_bytes: &BigInt,
    ring: u8,
    data_shards: u64,
) -> BigInt {
    allocation_ring_reward(basis, state_size, world_bytes, ring, data_shards) / 8
}

/// Scaled baseline fee. Mirror of
/// `node/consensus/reward/baseline_fee.go::GetBaselineFee`.
///
/// The math is:
/// ```text
/// current = pomw_basis(difficulty, world_state_bytes, units)
/// affected = pomw_basis(difficulty, world_state_bytes + total_added, units)
/// delta = current - affected
/// lhs = delta^2 / world_state_bytes
/// rhs = total_added
/// result = max(lhs, rhs)
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

/// Shared frame-execution pricing conversion. Do not truncate a BigInt cost,
/// substitute a default for overflow, or let world-state addition wrap.
/// `vote` is one for global frames and the existing multiplier vote for app frames.
/// `world_state_bytes` must be the network size certified by global consensus
/// (the anchored global frame's `world_state_size`), never a local CRDT size.
pub fn fee_multiplier_for_cost(network: u8, difficulty: u64, world_state_bytes: u64, cost: &BigInt, vote: u64) -> Result<BigInt> {
    if cost.is_zero() { return Ok(BigInt::zero()); }
    let invalid = || quil_types::error::QuilError::InvalidArgument("fee cost is outside the supported u64 state-size range".into());
    let added = cost.to_u64().ok_or_else(invalid)?;
    world_state_bytes.checked_add(added).ok_or_else(invalid)?;
    if network != MAINNET_NETWORK {
        return Ok(BigInt::from(NON_MAINNET_UNITS_PER_BYTE) * BigInt::from(vote));
    }
    let baseline = get_baseline_fee(difficulty, world_state_bytes, added, QUIL_TOKEN_UNITS);
    // An integral price per cost unit must cover the baseline when multiplied
    // back by the cost. Flooring here undercharges every non-divisible case.
    // BigInt keeps the ceiling addition exact even at the u64 cost boundary.
    let per_unit = (baseline + cost - BigInt::one()) / cost;
    Ok(per_unit * BigInt::from(vote))
}

/// Conservative fee budget for a standalone operation whose eventual encoded
/// cost is in `1..=payload_limit`, at a fixed pricing snapshot and vote.
///
/// Native proof lengths need not be known before selecting inputs and binding
/// the fee. Baseline(c) is nondecreasing in c: the PoMW basis is nonincreasing
/// with positive world size, so its nonnegative squared decrease is nondecreasing.
/// At zero world size the baseline is exactly the cost.
/// Integer ceiling adds at most c-1 units to baseline(c). Thus this bound covers
/// every permitted cost, including rounding. It is not an inclusion guarantee,
/// a mixed-bundle quote, or permission to debit the wallet automatically.
pub fn fee_budget_for_payload_limit(
    network: u8, difficulty: u64, world_state_bytes: u64, payload_limit: u64, vote: u64,
) -> Result<BigInt> {
    if payload_limit == 0 { return Ok(BigInt::zero()); }
    world_state_bytes.checked_add(payload_limit).ok_or_else(||
        quil_types::error::QuilError::InvalidArgument("fee payload limit exceeds state-size range".into()))?;
    if network != MAINNET_NETWORK {
        return Ok(BigInt::from(payload_limit) * BigInt::from(NON_MAINNET_UNITS_PER_BYTE) * BigInt::from(vote));
    }
    let baseline = get_baseline_fee(difficulty, world_state_bytes, payload_limit, QUIL_TOKEN_UNITS);
    Ok((baseline + BigInt::from(payload_limit - 1)) * BigInt::from(vote))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_reward_vectors_cover_fractional_roots_and_rounding() {
        // Independent integer expectations: basis=1600, size=world gives
        // floor(800/sqrt(shards)) ring units, then eight prover slots.
        for (shards, ring_reward, prover_reward) in [
            (1, 800, 100), (2, 565, 70), (3, 461, 57),
            (4, 400, 50), (5, 357, 44), (7, 302, 37), (9, 266, 33),
        ] {
            assert_eq!(allocation_ring_reward(&1600.into(), &100.into(), &100.into(), 0, shards), ring_reward.into());
            assert_eq!(allocation_prover_reward(&1600.into(), &100.into(), &100.into(), 0, shards), prover_reward.into());
        }
        // Dividing size*basis/world first loses a reward unit here.
        assert_eq!(allocation_prover_reward(&229.into(), &1.into(), &10.into(), 0, 2), 1.into());
    }

    #[test]
    fn allocation_reward_boundaries_and_monotonicity() {
        for (basis, size, world, shards) in [(0, 1, 1, 1), (1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0), (-1, 1, 1, 1), (1, 1, -1, 1)] {
            assert!(allocation_ring_reward(&basis.into(), &size.into(), &world.into(), 0, shards).is_zero());
        }
        let basis = BigInt::one() << 100;
        // Preserve issuance's ring clamp, including unusual legacy inputs.
        for ring in [62, 63, 255] {
            assert_eq!(allocation_ring_reward(&basis, &1.into(), &1.into(), ring, 1), BigInt::one() << 37);
        }
        let mut previous = allocation_prover_reward(&basis, &100.into(), &1000.into(), 0, 1);
        for count in 2..=256 {
            let next = allocation_prover_reward(&basis, &100.into(), &1000.into(), 0, count);
            assert!(next <= previous, "count={count}");
            previous = next;
        }
    }

    #[test]
    fn payload_budget_covers_every_cost_at_the_same_snapshot() {
        for difficulty in [5_000, 50_000, 100_000_000] {
            for world in [0, 1, 1 << 20, 1 << 30] {
                for vote in [0, 1, 100] {
                    let budget = fee_budget_for_payload_limit(MAINNET_NETWORK, difficulty, world, 128, vote).unwrap();
                    for size in 1..=128u64 {
                        let cost = BigInt::from(size);
                        let charge = fee_multiplier_for_cost(MAINNET_NETWORK, difficulty, world, &cost, vote).unwrap() * cost;
                        assert!(budget >= charge, "difficulty={difficulty} world={world} vote={vote} size={size}");
                    }
                }
            }
        }
    }

    #[test]
    fn non_mainnet_prices_growth_at_a_small_fixed_rate() {
        for network in [1u8, 2, 255] {
            for world in [0, 1, 1 << 20, 1 << 40] {
                let multiplier = fee_multiplier_for_cost(network, 50_000, world, &BigInt::from(16_053), 1).unwrap();
                assert_eq!(multiplier, BigInt::from(NON_MAINNET_UNITS_PER_BYTE));
                assert_eq!(fee_multiplier_for_cost(network, 50_000, world, &BigInt::from(16_053), 7).unwrap(), multiplier * 7);
                let budget = fee_budget_for_payload_limit(network, 50_000, world, 128, 3).unwrap();
                for size in 1..=128u64 {
                    let cost = BigInt::from(size);
                    assert!(budget >= fee_multiplier_for_cost(network, 50_000, world, &cost, 3).unwrap() * cost);
                }
            }
            assert!(fee_multiplier_for_cost(network, 50_000, u64::MAX, &BigInt::one(), 1).is_err());
        }
        // Mainnet keeps the PoMW curve: a 1 MB world prices 16 KB far above
        // the fixed rate.
        assert!(fee_multiplier_for_cost(MAINNET_NETWORK, 50_000, 1 << 20, &BigInt::from(16_053), 1).unwrap()
            > BigInt::from(NON_MAINNET_UNITS_PER_BYTE));
    }

    #[test]
    fn payload_budget_checks_bounds_and_recorded_transaction_sizes() {
        assert_eq!(fee_budget_for_payload_limit(MAINNET_NETWORK, 50_000, u64::MAX, 0, 1).unwrap(), BigInt::zero());
        assert!(fee_budget_for_payload_limit(MAINNET_NETWORK, 50_000, u64::MAX, 1, 1).is_err());
        let limit = (1 << 20) - 1;
        for world in [0, 1 << 30] {
            let budget = fee_budget_for_payload_limit(MAINNET_NETWORK, 50_000, world, limit, 100).unwrap();
            for size in [1, 195_907, 198_948, 200_771, 256 * 1024, limit] {
                let cost = BigInt::from(size);
                assert!(budget >= fee_multiplier_for_cost(MAINNET_NETWORK, 50_000, world, &cost, 100).unwrap() * cost);
            }
        }
    }
}


/// Inputs actually used by a durably materialized global frame while QUIL was
/// eligible for uncovered-application execution. Advisory, not consensus state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalQuilFeeSnapshot {
    pub frame_number: u64,
    pub difficulty: u64,
    pub world_state_bytes: u64,
}


/// Pricing inputs observed during an application frame's successful state commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppFeeSnapshot {
    pub application: [u8; 32],
    pub frame_number: u64,
    pub global_frame_number: u64,
    pub difficulty: u64,
    pub world_state_bytes: u64,
    pub fee_multiplier_vote: u64,
}
