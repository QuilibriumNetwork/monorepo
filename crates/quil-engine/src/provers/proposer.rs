//! Prover shard scoring and join/leave decision logic.
//!
//! Pure computation with no I/O, making it easy to unit test in isolation.
//!
//! Port of `node/consensus/provers/proposer.go`.

use num_bigint::BigInt;
use num_traits::Zero;
use std::collections::HashMap;

// Re-export the canonical PoMW basis from the rewards module so all
// scoring callers use the same algorithm as Go's `reward.PomwBasis`.
// The local `pomw_basis` below is preserved for backward compatibility
// with existing callers but delegates to the canonical implementation.
use crate::rewards::pomw_basis as canonical_pomw_basis;

/// Reward strategy for shard selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Maximize expected reward per unit of work.
    RewardGreedy,
    /// Maximize data coverage (larger shards first).
    DataGreedy,
}

impl Default for Strategy {
    fn default() -> Self {
        Self::RewardGreedy
    }
}

/// Description of a shard for scoring purposes.
#[derive(Debug, Clone)]
pub struct ShardDescriptor {
    /// Confirmation filter for the shard (routing key).
    pub filter: Vec<u8>,
    /// Size in bytes of this shard's state.
    pub size: u64,
    /// Ring attenuation factor (reward divided by 2^(Ring+1)).
    pub ring: u8,
    /// Logical shard-group count for sqrt divisor (>=1).
    pub shards: u64,
    /// Number of provers sharing this ring (including joiner if applicable).
    pub active_on_ring: u64,
    /// Total Active+Joining provers on the shard (independent of
    /// ring assignment). Used for halt-risk prioritization in
    /// `plan_and_allocate`: shards at or below
    /// `HALT_RISK_PROVER_COUNT` are picked before any reward-greedy
    /// candidate, since losing a prover from such a shard halts the
    /// network and zeroes everyone's reward.
    pub total_active_joining: u64,
}

/// Provers-per-shard ceiling that classifies a shard as halt-risk.
/// At/under this count, losing a single prover risks dropping below
/// the consensus quorum and halting the shard. Auto-allocation
/// prioritizes joining these shards over picking the highest
/// reward-greedy candidate.
pub const HALT_RISK_PROVER_COUNT: u64 = 3;

/// A proposed shard allocation.
#[derive(Debug, Clone)]
pub struct Proposal {
    pub worker_id: u32,
    pub filter: Vec<u8>,
    pub expected_reward: BigInt,
    pub world_state_bytes: u64,
    pub shard_size_bytes: u64,
    pub ring: u8,
    pub shards_denominator: u64,
}

struct Scored {
    idx: usize,
    score: BigInt,
}

/// Shard ring info — how rings are structured for a shard with N active+joining provers.
#[derive(Debug, Clone)]
pub struct ShardRingInfo {
    pub current_ring: u8,
    pub joiner_ring: u8,
    pub active_on_current_ring: u64,
    pub active_on_joiner_ring: u64,
}

/// Compute ring info from total active+joining prover count.
///
/// Port of Go's `computeShardRingInfo` at `node/consensus/global/worker_allocator.go:540-546`.
pub fn compute_shard_ring_info(total_active_joining: usize) -> ShardRingInfo {
    let mut ri = ShardRingInfo {
        current_ring: 0,
        joiner_ring: 0,
        active_on_current_ring: 0,
        active_on_joiner_ring: 0,
    };

    if total_active_joining > 0 {
        ri.current_ring = ((total_active_joining - 1) / 8) as u8;
    }
    ri.joiner_ring = (total_active_joining / 8) as u8;

    ri.active_on_current_ring = (total_active_joining % 8) as u64;
    if ri.active_on_current_ring == 0 && total_active_joining > 0 {
        ri.active_on_current_ring = 8;
    }

    ri.active_on_joiner_ring = (total_active_joining % 8) as u64 + 1;

    ri
}

/// PoMW basis calculation.
///
/// Compute the PoMW basis. Delegates to the canonical implementation
/// in `crate::rewards::pomw_basis` so proposer scoring matches the
/// reward issuance calculator (Go's `reward.PomwBasis`).
///
/// Previously this module had its own implementation that differed
/// in scaling at generation ≥ 2. That divergence caused different
/// nodes to produce different `plan_and_allocate`/`decide_joins`
/// outcomes for the same difficulty + world bytes. Forwarding to the
/// canonical version eliminates that drift.
pub fn pomw_basis(difficulty: u64, world_state_bytes: u64, units: u64) -> BigInt {
    canonical_pomw_basis(difficulty, world_state_bytes, units)
}

/// 53-bit precision integer square root, mirroring Go's
/// `decimal.PowWithPrecision(1/2, 53)` used in
/// `node/consensus/provers/proposer.go:367-373`. Pre-scales the input
/// by 2^(2*53) before integer sqrt so the result carries 53 fractional
/// bits — matching shopspring's effective working precision.
///
/// Used by `score_shards` to divide reward by `sqrt(shards)`. The
/// integer-only Newton's method we previously used produced visibly
/// different scores for `shards > 1`, which can flip the `bestScore *
/// 67/100` threshold in `decide_joins` and cause split-brain
/// confirm/reject decisions across nodes.
fn shards_sqrt_53bit(shards: u64) -> BigInt {
    if shards == 0 {
        return BigInt::zero();
    }
    let scaled = BigInt::from(shards) << (2u32 * 53u32);
    scaled.sqrt()
}

#[cfg(test)]
mod sqrt_tests {
    use super::*;
    use num_traits::ToPrimitive;

    /// Tier-5 #4: 53-bit-precision sqrt mirrors Go's
    /// `decimal.PowWithPrecision(1/2, 53)`. For perfect squares the
    /// post-shift integer should equal sqrt(shards) within rounding.
    #[test]
    fn shards_sqrt_53bit_perfect_squares() {
        for shards in [1u64, 4, 9, 16, 100, 1024, 10_000] {
            let r = shards_sqrt_53bit(shards);
            // r ≈ sqrt(shards) << 53; shift back to compare.
            let approx = (&r >> 53u32).to_u64().unwrap_or(0);
            let expected = (shards as f64).sqrt() as u64;
            // Allow off-by-one rounding either direction.
            assert!(
                approx + 1 >= expected && expected + 1 >= approx,
                "shards={shards} expected~{expected} got {approx}"
            );
        }
    }

    /// Sqrt monotonic and non-zero for non-zero input.
    #[test]
    fn shards_sqrt_53bit_monotonic() {
        let a = shards_sqrt_53bit(4);
        let b = shards_sqrt_53bit(16);
        let c = shards_sqrt_53bit(64);
        assert!(a < b);
        assert!(b < c);
        assert!(!a.is_zero());
        // Zero in → zero out (degenerate path).
        assert!(shards_sqrt_53bit(0).is_zero());
    }
}

/// Returns `(filter, score)` ascending. Filters in `excluded` are
/// dropped from the result.
pub fn rank_allocated_by_score_ascending(
    allocated_shards: &[ShardDescriptor],
    difficulty: u64,
    world_bytes: &BigInt,
    units: u64,
    strategy: Strategy,
    excluded: &std::collections::HashSet<Vec<u8>>,
) -> Vec<(Vec<u8>, BigInt)> {
    if allocated_shards.is_empty() {
        return Vec::new();
    }
    let basis = pomw_basis(difficulty, world_bytes.try_into().unwrap_or(1), units);
    let scores = score_shards(allocated_shards, &basis, world_bytes, strategy);
    let mut out: Vec<(Vec<u8>, BigInt)> = scores
        .into_iter()
        .filter_map(|sc| {
            let filter = allocated_shards[sc.idx].filter.clone();
            if excluded.contains(&filter) {
                None
            } else {
                Some((filter, sc.score))
            }
        })
        .collect();
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

/// Score shards by expected reward.
///
/// Port of Go's `scoreShards` at `node/consensus/provers/proposer.go:326-392`.
fn score_shards(
    shards: &[ShardDescriptor],
    basis: &BigInt,
    world_bytes: &BigInt,
    strategy: Strategy,
) -> Vec<Scored> {
    let mut scores = Vec::with_capacity(shards.len());

    for (i, s) in shards.iter().enumerate() {
        if s.filter.is_empty() || s.size == 0 {
            continue;
        }

        let effective_shards = if s.shards == 0 { 1u64 } else { s.shards };

        let score = match strategy {
            Strategy::DataGreedy => BigInt::from(s.size),
            Strategy::RewardGreedy => {
                // factor = (sizeBytes * basis) / worldBytes
                let factor = BigInt::from(s.size) * basis / world_bytes;

                // ring divisor = 2^(Ring+1)
                let divisor: u64 = 1u64.checked_shl((s.ring as u32) + 1).unwrap_or(0);
                if divisor == 0 {
                    scores.push(Scored { idx: i, score: BigInt::zero() });
                    continue;
                }

                // shards sqrt with 53-bit fractional precision —
                // matches Go's `decimal.PowWithPrecision(1/2, 53)` at
                // `proposer.go:367-373`. The result has 53 fractional
                // bits, so we shift `factor` left by 53 before dividing
                // and the final score lands at integer scale.
                let shards_sqrt = shards_sqrt_53bit(effective_shards);
                if shards_sqrt.is_zero() {
                    scores.push(Scored { idx: i, score: BigInt::zero() });
                    continue;
                }

                // score = (factor << 53) / divisor / shards_sqrt / 8
                let score = (factor << 53u32)
                    / BigInt::from(divisor)
                    / &shards_sqrt
                    / BigInt::from(8);
                score
            }
        };

        scores.push(Scored { idx: i, score });
    }

    scores
}

/// Plan which shards to join. Returns proposals for free workers.
///
/// Port of Go's `PlanAndAllocate` at `node/consensus/provers/proposer.go:98-269`.
pub fn plan_and_allocate(
    shards: &[ShardDescriptor],
    difficulty: u64,
    world_bytes: &BigInt,
    units: u64,
    free_worker_ids: &[u32],
    max_allocations: usize,
    strategy: Strategy,
) -> Vec<Proposal> {
    if free_worker_ids.is_empty() || shards.is_empty() {
        return Vec::new();
    }

    let basis = pomw_basis(difficulty, world_bytes.try_into().unwrap_or(1), units);
    let mut scores = score_shards(shards, &basis, world_bytes, strategy);

    // Sort by score descending, then by filter lexicographically (matches Go)
    scores.sort_by(|a, b| {
        let cmp = b.score.cmp(&a.score);
        if cmp != std::cmp::Ordering::Equal {
            return cmp;
        }
        shards[a.idx].filter.cmp(&shards[b.idx].filter)
    });

    // For reward-greedy: shuffle equal-score groups (Fisher-Yates)
    if strategy != Strategy::DataGreedy && scores.len() > 1 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut start = 0;
        while start < scores.len() {
            let mut end = start + 1;
            while end < scores.len() && scores[end].score == scores[start].score {
                end += 1;
            }
            if end - start > 1 {
                for i in (start + 1..end).rev() {
                    let j = rng.gen_range(start..=i);
                    scores.swap(i, j);
                }
            }
            start = end;
        }
    }

    // Halt-risk priority: any shard at or under
    // `HALT_RISK_PROVER_COUNT` (with size > 0) jumps to the front of
    // the picking order regardless of its reward-greedy score. The
    // scored ordering is preserved within each bucket so internal
    // tie-breaking still flows from `score_shards`. Without this
    // pass, a high-size 8-prover shard outscores a 3-prover shard
    // and the auto-allocator continues piling onto already-healthy
    // shards while halt-risk ones lose their last prover and the
    // network halts.
    let mut halt_risk: Vec<Scored> = Vec::new();
    let mut other: Vec<Scored> = Vec::new();
    for s in scores {
        let d = &shards[s.idx];
        if d.size > 0 && d.total_active_joining <= HALT_RISK_PROVER_COUNT {
            halt_risk.push(s);
        } else {
            other.push(s);
        }
    }
    let halt_risk_total = halt_risk.len();
    let other_total = other.len();
    let halt_risk_top: Vec<String> = halt_risk
        .iter()
        .take(8)
        .map(|s| {
            let d = &shards[s.idx];
            format!(
                "{}:provers={},size={}",
                hex::encode(&d.filter[..d.filter.len().min(8)]),
                d.total_active_joining,
                d.size,
            )
        })
        .collect();
    let mut scores = halt_risk;
    scores.extend(other);

    let limit = max_allocations
        .min(free_worker_ids.len())
        .min(scores.len());

    // Sort worker IDs deterministically so top-k shards go to lowest core IDs
    let mut sorted_workers = free_worker_ids.to_vec();
    sorted_workers.sort();

    let wb = world_bytes.try_into().unwrap_or(0u64);
    let proposals: Vec<Proposal> = (0..limit)
        .map(|k| {
            let sel = &shards[scores[k].idx];
            Proposal {
                worker_id: sorted_workers[k],
                filter: sel.filter.clone(),
                expected_reward: scores[k].score.clone(),
                world_state_bytes: wb,
                shard_size_bytes: sel.size,
                ring: sel.ring,
                shards_denominator: sel.shards,
            }
        })
        .collect();

    // Surface the halt-risk partition outcome so operators can
    // confirm prioritization is working when halt-risk shards exist
    // among the candidates. Picked entries are listed with their
    // halt-risk classification so deviations from "halt-risk first"
    // are visible in the log without needing per-shard debug.
    let halt_risk_picked = proposals
        .iter()
        .filter(|p| {
            let d = shards
                .iter()
                .find(|s| s.filter == p.filter);
            matches!(d, Some(d) if d.size > 0 && d.total_active_joining <= HALT_RISK_PROVER_COUNT)
        })
        .count();
    let picks_summary: Vec<String> = proposals
        .iter()
        .map(|p| {
            let halt = shards
                .iter()
                .any(|s| s.filter == p.filter
                    && s.size > 0
                    && s.total_active_joining <= HALT_RISK_PROVER_COUNT);
            format!(
                "core={}:filter={}{}",
                p.worker_id,
                hex::encode(&p.filter[..p.filter.len().min(8)]),
                if halt { ":halt-risk" } else { "" },
            )
        })
        .collect();
    if halt_risk_total > 0 || !proposals.is_empty() {
        tracing::info!(
            free_workers = free_worker_ids.len(),
            candidates = shards.len(),
            halt_risk_total,
            halt_risk_picked,
            other_total,
            picked = proposals.len(),
            ?halt_risk_top,
            ?picks_summary,
            strategy = ?strategy,
            "plan_and_allocate decision"
        );
    }
    proposals
}

/// Decide whether to confirm or reject pending joins.
///
/// Returns `(reject, confirm)` filter lists.
///
/// `candidate_shards` must be the union of **unallocated shards** (using
/// `joiner_ring`) and the **pending-to-decide shards** (using `current_ring`),
/// matching Go's `decideCandidates` at `worker_allocator.go:268-283`.
/// Passing self's active allocations here causes perpetual rejection of
/// pending joins (they score < 67% of the allocations' inflated bestScore).
///
/// `available_workers` is the count of unallocated worker slots. When
/// nothing is rejected (all pending pass the threshold), Go caps
/// confirms at this number and drops the rest — see
/// `proposer.go:518-531`. `usize::MAX` disables the cap.
pub fn decide_joins(
    candidate_shards: &[ShardDescriptor],
    pending: &[Vec<u8>],
    difficulty: u64,
    world_bytes: &BigInt,
    units: u64,
    strategy: Strategy,
    available_workers: usize,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    if pending.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let basis = pomw_basis(difficulty, world_bytes.try_into().unwrap_or(1), units);
    let scores = score_shards(candidate_shards, &basis, world_bytes, strategy);

    let mut by_hex: HashMap<String, BigInt> = HashMap::new();
    let mut best_score: Option<BigInt> = None;
    for sc in &scores {
        let key = hex::encode(&candidate_shards[sc.idx].filter);
        by_hex.insert(key, sc.score.clone());
        if best_score.as_ref().map_or(true, |b| sc.score > *b) {
            best_score = Some(sc.score.clone());
        }
    }

    let best = match best_score {
        Some(b) => b,
        None => {
            let reject: Vec<Vec<u8>> = pending.iter()
                .filter(|p| !p.is_empty())
                .take(100)
                .cloned()
                .collect();
            return (reject, Vec::new());
        }
    };

    // Threshold = best * 67 / 100
    let threshold = &best * BigInt::from(67) / BigInt::from(100);

    let mut reject = Vec::new();
    let mut confirm = Vec::new();

    for p in pending {
        if p.is_empty() { continue; }
        if reject.len() > 99 || confirm.len() > 99 { break; }

        let key = hex::encode(p);
        match by_hex.get(&key) {
            None => reject.push(p.clone()),
            Some(score) => {
                if *score < threshold {
                    reject.push(p.clone());
                } else {
                    confirm.push(p.clone());
                }
            }
        }
    }

    // availableWorkers cap (Go `proposer.go:518-531`): only applied when
    // no rejections — Go submits reject XOR confirm in a single
    // DecideAllocations call, so the cap is consulted only on the
    // confirm path. If we have zero free workers, drop all confirms; if
    // we have some, truncate to capacity.
    if reject.is_empty() && !confirm.is_empty() && available_workers != usize::MAX {
        if available_workers == 0 {
            confirm.clear();
        } else if confirm.len() > available_workers {
            confirm.truncate(available_workers);
        }
    }

    (reject, confirm)
}

/// Identify shards to leave (overcrowded / poor reward).
///
/// Returns up to 3 filter candidates for ProverLeave.
///
/// Port of Go's `PlanLeaves` at `proposer.go:558-646`.
pub fn plan_leaves(
    allocated_shards: &[ShardDescriptor],
    unallocated_shards: &[ShardDescriptor],
    difficulty: u64,
    world_bytes: &BigInt,
    units: u64,
    strategy: Strategy,
) -> Vec<Vec<u8>> {
    if allocated_shards.is_empty() || unallocated_shards.is_empty() {
        return Vec::new();
    }

    let basis = pomw_basis(difficulty, world_bytes.try_into().unwrap_or(1), units);

    let unalloc_scores = score_shards(unallocated_shards, &basis, world_bytes, strategy);
    let best_unalloc = unalloc_scores.iter().map(|s| &s.score).max();
    let best_unalloc = match best_unalloc {
        Some(b) if !b.is_zero() => b.clone(),
        _ => return Vec::new(),
    };

    // Leave threshold = best_unalloc * 67 / 100
    let threshold = &best_unalloc * BigInt::from(67) / BigInt::from(100);

    let alloc_scores = score_shards(allocated_shards, &basis, world_bytes, strategy);

    let mut candidates: Vec<(Vec<u8>, BigInt)> = alloc_scores
        .iter()
        .filter(|sc| sc.score < threshold)
        .map(|sc| (allocated_shards[sc.idx].filter.clone(), sc.score.clone()))
        .collect();

    // Sort worst first
    candidates.sort_by(|a, b| a.1.cmp(&b.1));

    // Cap at 3 (matches Go's `limit := 3`)
    let picks: Vec<Vec<u8>> = candidates.iter().take(3).map(|(f, _)| f.clone()).collect();

    if !picks.is_empty() {
        let picks_summary: Vec<String> = candidates
            .iter()
            .take(3)
            .map(|(f, score)| {
                format!(
                    "{}:score={}",
                    hex::encode(&f[..f.len().min(8)]),
                    score.to_str_radix(10),
                )
            })
            .collect();
        tracing::info!(
            allocated = allocated_shards.len(),
            unallocated = unallocated_shards.len(),
            best_unalloc_score = %best_unalloc.to_str_radix(10),
            threshold = %threshold.to_str_radix(10),
            below_threshold = candidates.len(),
            picked = picks.len(),
            ?picks_summary,
            strategy = ?strategy,
            "plan_leaves: proposing score-driven leaves (allocated shards below 67% of best unallocated)"
        );
    }

    picks
}

/// Decide whether to confirm or reject pending leaves.
///
/// Returns `(reject, confirm)` filter lists.
///
/// Port of Go's `DecideLeaves` at `proposer.go:655-773`.
pub fn decide_leaves(
    shards: &[ShardDescriptor],
    pending_leaves: &[Vec<u8>],
    difficulty: u64,
    world_bytes: &BigInt,
    units: u64,
    strategy: Strategy,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    if pending_leaves.is_empty() {
        return (Vec::new(), Vec::new());
    }

    if shards.is_empty() {
        let confirm: Vec<Vec<u8>> = pending_leaves.iter()
            .filter(|p| !p.is_empty())
            .take(100)
            .cloned()
            .collect();
        return (Vec::new(), confirm);
    }

    let basis = pomw_basis(difficulty, world_bytes.try_into().unwrap_or(1), units);
    let scores = score_shards(shards, &basis, world_bytes, strategy);

    let mut by_hex: HashMap<String, BigInt> = HashMap::new();
    let mut best_score: Option<BigInt> = None;
    for sc in &scores {
        let key = hex::encode(&shards[sc.idx].filter);
        by_hex.insert(key, sc.score.clone());
        if best_score.as_ref().map_or(true, |b| sc.score > *b) {
            best_score = Some(sc.score.clone());
        }
    }

    let best = match best_score {
        Some(b) => b,
        None => {
            let confirm: Vec<Vec<u8>> = pending_leaves.iter()
                .filter(|p| !p.is_empty())
                .take(100)
                .cloned()
                .collect();
            return (Vec::new(), confirm);
        }
    };

    // Threshold = best * 67 / 100
    // Reject leave (stay) if score >= threshold; confirm if < threshold.
    let threshold = &best * BigInt::from(67) / BigInt::from(100);

    let mut reject = Vec::new();
    let mut confirm = Vec::new();

    for p in pending_leaves {
        if p.is_empty() { continue; }
        if reject.len() > 99 || confirm.len() > 99 { break; }

        let key = hex::encode(p);
        match by_hex.get(&key) {
            None => confirm.push(p.clone()),
            Some(score) => {
                if *score >= threshold {
                    reject.push(p.clone());
                } else {
                    confirm.push(p.clone());
                }
            }
        }
    }

    (reject, confirm)
}

/// Default issuance units constant (matches Go's 8_000_000_000).
pub const DEFAULT_UNITS: u64 = 8_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_info_empty() {
        let ri = compute_shard_ring_info(0);
        assert_eq!(ri.current_ring, 0);
        assert_eq!(ri.joiner_ring, 0);
        assert_eq!(ri.active_on_current_ring, 0);
        assert_eq!(ri.active_on_joiner_ring, 1);
    }

    #[test]
    fn ring_info_single() {
        let ri = compute_shard_ring_info(1);
        assert_eq!(ri.current_ring, 0);
        assert_eq!(ri.joiner_ring, 0);
        assert_eq!(ri.active_on_current_ring, 1);
        assert_eq!(ri.active_on_joiner_ring, 2);
    }

    #[test]
    fn ring_info_full_ring() {
        let ri = compute_shard_ring_info(8);
        assert_eq!(ri.current_ring, 0);
        assert_eq!(ri.joiner_ring, 1);
        assert_eq!(ri.active_on_current_ring, 8);
        assert_eq!(ri.active_on_joiner_ring, 1);
    }

    #[test]
    fn ring_info_second_ring() {
        let ri = compute_shard_ring_info(9);
        assert_eq!(ri.current_ring, 1);
        assert_eq!(ri.joiner_ring, 1);
        assert_eq!(ri.active_on_current_ring, 1);
        assert_eq!(ri.active_on_joiner_ring, 2);
    }

    #[test]
    fn ring_info_16_provers() {
        let ri = compute_shard_ring_info(16);
        assert_eq!(ri.current_ring, 1);
        assert_eq!(ri.joiner_ring, 2);
        assert_eq!(ri.active_on_current_ring, 8);
        assert_eq!(ri.active_on_joiner_ring, 1);
    }

    #[test]
    fn pomw_basis_nonzero() {
        let b = pomw_basis(50000, 10_000_000_000, DEFAULT_UNITS);
        assert!(b > BigInt::zero(), "basis should be positive");
    }

    #[test]
    fn score_empty_shards() {
        let scores = score_shards(
            &[],
            &BigInt::from(1),
            &BigInt::from(1),
            Strategy::RewardGreedy,
        );
        assert!(scores.is_empty());
    }

    #[test]
    fn score_data_greedy_by_size() {
        let shards = vec![
            ShardDescriptor { filter: vec![1], size: 100, ring: 0, shards: 1, active_on_ring: 1, total_active_joining: 16 },
            ShardDescriptor { filter: vec![2], size: 200, ring: 0, shards: 1, active_on_ring: 1, total_active_joining: 16 },
        ];
        let scores = score_shards(
            &shards,
            &BigInt::from(1),
            &BigInt::from(1),
            Strategy::DataGreedy,
        );
        assert_eq!(scores.len(), 2);
        assert_eq!(scores[0].score, BigInt::from(100));
        assert_eq!(scores[1].score, BigInt::from(200));
    }

    #[test]
    fn decide_joins_all_reject_when_no_valid_scores() {
        let pending = vec![vec![1, 2, 3]];
        let (reject, confirm) = decide_joins(
            &[],
            &pending,
            50000,
            &BigInt::from(1_000_000),
            DEFAULT_UNITS,
            Strategy::RewardGreedy,
            usize::MAX,
        );
        assert_eq!(reject.len(), 1);
        assert!(confirm.is_empty());
    }

    #[test]
    fn plan_leaves_empty_when_no_unallocated() {
        let allocated = vec![
            ShardDescriptor { filter: vec![1], size: 100, ring: 0, shards: 1, active_on_ring: 1, total_active_joining: 16 },
        ];
        let result = plan_leaves(&allocated, &[], 50000, &BigInt::from(1_000_000), DEFAULT_UNITS, Strategy::RewardGreedy);
        assert!(result.is_empty());
    }

    fn make_shard(filter: Vec<u8>, size: u64, ring: u8, shards: u64) -> ShardDescriptor {
        // Default `total_active_joining` = 16 so the shard is NOT
        // halt-risk in tests that don't care about that bucket.
        ShardDescriptor {
            filter,
            size,
            ring,
            shards,
            active_on_ring: 1,
            total_active_joining: 16,
        }
    }

    #[test]
    fn plan_and_allocate_prefers_halt_risk_over_higher_reward() {
        // A high-size, healthy (8-prover) shard would normally
        // outscore a small 3-prover shard. Verify the halt-risk
        // bucket pulls the 3-prover shard ahead of it.
        let healthy = ShardDescriptor {
            filter: vec![1],
            size: 10_000_000,
            ring: 1,
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 8,
        };
        let halt_risk = ShardDescriptor {
            filter: vec![2],
            size: 1_000_000,
            ring: 0,
            shards: 1,
            active_on_ring: 4,
            total_active_joining: 3,
        };
        let result = plan_and_allocate(
            &[healthy, halt_risk],
            50_000,
            &BigInt::from(20_000_000u64),
            DEFAULT_UNITS,
            &[1],
            1,
            Strategy::RewardGreedy,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].filter, vec![2], "halt-risk shard must be picked first");
    }

    #[test]
    fn plan_and_allocate_falls_back_to_reward_after_halt_risk_filled() {
        // Two halt-risk shards + one healthy. With 3 free workers and
        // max_allocations=3, all three should be picked. Halt-risk
        // first, healthy last.
        let healthy = ShardDescriptor {
            filter: vec![3],
            size: 10_000_000,
            ring: 1,
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 8,
        };
        let halt_a = ShardDescriptor {
            filter: vec![1],
            size: 500_000,
            ring: 0,
            shards: 1,
            active_on_ring: 2,
            total_active_joining: 1,
        };
        let halt_b = ShardDescriptor {
            filter: vec![2],
            size: 700_000,
            ring: 0,
            shards: 1,
            active_on_ring: 3,
            total_active_joining: 2,
        };
        let result = plan_and_allocate(
            &[healthy, halt_a, halt_b],
            50_000,
            &BigInt::from(20_000_000u64),
            DEFAULT_UNITS,
            &[1, 2, 3],
            3,
            Strategy::RewardGreedy,
        );
        assert_eq!(result.len(), 3);
        // First two picks must be the halt-risk shards (order between
        // them depends on score; both fall in the halt-risk bucket).
        let first_two: std::collections::HashSet<Vec<u8>> = result[0..2]
            .iter()
            .map(|p| p.filter.clone())
            .collect();
        assert!(first_two.contains(&vec![1u8]));
        assert!(first_two.contains(&vec![2u8]));
        assert_eq!(result[2].filter, vec![3], "healthy shard last");
    }

    #[test]
    fn plan_and_allocate_skips_zero_size_halt_risk_shards() {
        // size=0 must NOT be promoted into the halt-risk bucket —
        // a shard with no data isn't worth saving.
        let zero_halt = ShardDescriptor {
            filter: vec![1],
            size: 0,
            ring: 0,
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 1,
        };
        let normal = ShardDescriptor {
            filter: vec![2],
            size: 100_000,
            ring: 0,
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 16,
        };
        let result = plan_and_allocate(
            &[zero_halt, normal],
            50_000,
            &BigInt::from(1_000_000u64),
            DEFAULT_UNITS,
            &[1],
            1,
            Strategy::RewardGreedy,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].filter, vec![2]);
    }

    #[test]
    fn plan_and_allocate_unequal_scores_picks_max() {
        let best = make_shard(vec![0x0A], 200_000, 0, 1);
        let other1 = make_shard(vec![0x01], 50_000, 0, 1);
        let other2 = make_shard(vec![0x02], 50_000, 0, 1);
        let shards = vec![other1, other2, best];

        let proposals = plan_and_allocate(
            &shards, 50000, &BigInt::from(300_000), 1, &[1], 1, Strategy::RewardGreedy,
        );
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].filter, vec![0x0A], "best shard 0x0A should be selected");
    }

    #[test]
    fn plan_and_allocate_data_greedy_deterministic_lexicographic() {
        let shards = vec![
            make_shard(vec![0x02], 10_000, 0, 1),
            make_shard(vec![0x01], 10_000, 0, 1),
            make_shard(vec![0x04], 10_000, 0, 1),
            make_shard(vec![0x03], 10_000, 0, 1),
        ];
        for _ in 0..16 {
            let proposals = plan_and_allocate(
                &shards, 50000, &BigInt::from(40_000), 1, &[1], 1, Strategy::DataGreedy,
            );
            assert_eq!(proposals.len(), 1);
            assert_eq!(proposals[0].filter, vec![0x01],
                "DataGreedy with equal sizes should pick lexicographic first (0x01)");
        }
    }

    #[test]
    fn decide_joins_confirm_when_best_reward_greedy() {
        let shards = vec![
            make_shard(vec![0x01], 50_000, 0, 1),
            make_shard(vec![0x02], 200_000, 0, 1),
            make_shard(vec![0x03], 50_000, 0, 1),
        ];
        let pending = vec![vec![0x02]];
        let (reject, confirm) = decide_joins(
            &shards, &pending, 50000, &BigInt::from(300_000), DEFAULT_UNITS, Strategy::RewardGreedy,
            usize::MAX,
        );
        assert!(reject.is_empty(), "best shard should not be rejected");
        assert_eq!(confirm.len(), 1);
        assert_eq!(confirm[0], vec![0x02]);
    }

    #[test]
    fn decide_joins_reject_when_better_exists_reward_greedy() {
        let shards = vec![
            make_shard(vec![0x0A], 200_000, 0, 1),
            make_shard(vec![0x01], 50_000, 0, 1),
        ];
        let pending = vec![vec![0x01]];
        let (reject, confirm) = decide_joins(
            &shards, &pending, 50000, &BigInt::from(250_000), DEFAULT_UNITS, Strategy::RewardGreedy,
            usize::MAX,
        );
        assert_eq!(reject.len(), 1);
        assert_eq!(reject[0], vec![0x01], "inferior shard should be rejected");
        assert!(confirm.is_empty());
    }

    #[test]
    fn decide_joins_tie_confirms_reward_greedy() {
        let shards = vec![
            make_shard(vec![0x01], 100_000, 1, 4),
            make_shard(vec![0x02], 100_000, 1, 4),
        ];
        let pending = vec![vec![0x02]];
        let (reject, confirm) = decide_joins(
            &shards, &pending, 50000, &BigInt::from(200_000), DEFAULT_UNITS, Strategy::RewardGreedy,
            usize::MAX,
        );
        assert!(reject.is_empty(), "tied shard should not be rejected");
        assert_eq!(confirm.len(), 1);
        assert_eq!(confirm[0], vec![0x02]);
    }

    #[test]
    fn decide_joins_data_greedy_size_only() {
        let shards = vec![
            make_shard(vec![0xAA], 10_000, 3, 16),
            make_shard(vec![0xBB], 80_000, 0, 1),
            make_shard(vec![0xCC], 80_000, 5, 64),
        ];
        let pending = vec![vec![0xAA], vec![0xBB], vec![0xCC]];
        let (reject, confirm) = decide_joins(
            &shards, &pending, 50000, &BigInt::from(170_000), DEFAULT_UNITS, Strategy::DataGreedy,
            usize::MAX,
        );
        let reject_hex: Vec<String> = reject.iter().map(hex::encode).collect();
        let confirm_hex: Vec<String> = confirm.iter().map(hex::encode).collect();
        assert!(reject_hex.contains(&"aa".to_string()),
            "aa should be rejected; got reject={reject_hex:?} confirm={confirm_hex:?}");
        assert!(!reject_hex.contains(&"bb".to_string()), "bb should not be rejected");
        assert!(!reject_hex.contains(&"cc".to_string()), "cc should not be rejected");
    }

    #[test]
    fn decide_joins_pending_missing_or_invalid_reject() {
        let shards = vec![make_shard(vec![0x01], 100_000, 0, 1)];
        let pending = vec![vec![0xDE, 0xAD, 0xBE, 0xEF]];
        let (reject, confirm) = decide_joins(
            &shards, &pending, 50000, &BigInt::from(100_000), DEFAULT_UNITS, Strategy::RewardGreedy,
            usize::MAX,
        );
        assert!(confirm.is_empty());
        assert_eq!(reject.len(), 1);
        assert_eq!(reject[0], vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    /// Tier-5 #5: when no rejections, confirms cap at `available_workers`.
    /// `0` workers → drop all confirms; `N` workers → truncate to N.
    #[test]
    fn decide_joins_caps_confirms_by_available_workers() {
        let shards = vec![
            make_shard(vec![0x01], 100_000, 0, 1),
            make_shard(vec![0x02], 100_000, 0, 1),
            make_shard(vec![0x03], 100_000, 0, 1),
        ];
        let pending = vec![vec![0x01], vec![0x02], vec![0x03]];

        // available_workers = 0 → all confirms dropped.
        let (reject0, confirm0) = decide_joins(
            &shards, &pending, 50000, &BigInt::from(300_000),
            DEFAULT_UNITS, Strategy::RewardGreedy, 0,
        );
        assert!(reject0.is_empty());
        assert!(confirm0.is_empty(), "no workers → no confirms");

        // available_workers = 1 → exactly 1 confirm.
        let (reject1, confirm1) = decide_joins(
            &shards, &pending, 50000, &BigInt::from(300_000),
            DEFAULT_UNITS, Strategy::RewardGreedy, 1,
        );
        assert!(reject1.is_empty());
        assert_eq!(confirm1.len(), 1);

        // usize::MAX disables the cap (parity with prior behavior).
        let (_, confirm_max) = decide_joins(
            &shards, &pending, 50000, &BigInt::from(300_000),
            DEFAULT_UNITS, Strategy::RewardGreedy, usize::MAX,
        );
        assert_eq!(confirm_max.len(), 3);
    }

    #[test]
    fn plan_leaves_leaves_when_better_exists() {
        let allocated = vec![make_shard(vec![0xAA], 50_000, 3, 1)];
        let unallocated = vec![make_shard(vec![0xBB], 200_000, 0, 1)];
        let filters = plan_leaves(
            &allocated, &unallocated, 50000, &BigInt::from(250_000), DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0], vec![0xAA]);
    }

    #[test]
    fn plan_leaves_stays_when_competitive() {
        let allocated = vec![make_shard(vec![0xAA], 100_000, 0, 1)];
        let unallocated = vec![make_shard(vec![0xBB], 100_000, 0, 1)];
        let filters = plan_leaves(
            &allocated, &unallocated, 50000, &BigInt::from(200_000), DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert!(filters.is_empty(), "should not leave a competitive shard");
    }

    #[test]
    fn plan_leaves_caps_at_3() {
        let allocated = vec![
            make_shard(vec![0xA1], 50_000, 4, 1),
            make_shard(vec![0xA2], 50_000, 4, 1),
            make_shard(vec![0xA3], 50_000, 4, 1),
            make_shard(vec![0xA4], 50_000, 4, 1),
            make_shard(vec![0xA5], 50_000, 4, 1),
        ];
        let unallocated = vec![make_shard(vec![0xBB], 200_000, 0, 1)];
        let filters = plan_leaves(
            &allocated, &unallocated, 50000, &BigInt::from(450_000), DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert_eq!(filters.len(), 3, "should cap at 3 leave proposals");
    }

    #[test]
    fn plan_leaves_worst_first() {
        let allocated = vec![
            make_shard(vec![0xA1], 50_000, 2, 1),
            make_shard(vec![0xA2], 50_000, 4, 1),
        ];
        let unallocated = vec![make_shard(vec![0xBB], 200_000, 0, 1)];
        let filters = plan_leaves(
            &allocated, &unallocated, 50000, &BigInt::from(300_000), DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert!(filters.len() >= 2, "should leave at least 2 bad shards");
        assert_eq!(filters[0], vec![0xA2], "worst shard (ring 4) should be first");
    }

    #[test]
    fn decide_leaves_confirm_when_still_bad() {
        let shards = vec![
            make_shard(vec![0xAA], 50_000, 3, 1),
            make_shard(vec![0xBB], 200_000, 0, 1),
        ];
        let pending = vec![vec![0xAA]];
        let (reject, confirm) = decide_leaves(
            &shards, &pending, 50000, &BigInt::from(250_000), DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert!(reject.is_empty(), "bad shard leave should not be rejected");
        assert_eq!(confirm.len(), 1);
        assert_eq!(confirm[0], vec![0xAA]);
    }

    #[test]
    fn decide_leaves_reject_when_shard_improved() {
        let shards = vec![
            make_shard(vec![0xAA], 100_000, 0, 1),
            make_shard(vec![0xBB], 100_000, 0, 1),
        ];
        let pending = vec![vec![0xAA]];
        let (reject, confirm) = decide_leaves(
            &shards, &pending, 50000, &BigInt::from(200_000), DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert_eq!(reject.len(), 1, "improved shard leave should be rejected");
        assert_eq!(reject[0], vec![0xAA]);
        assert!(confirm.is_empty());
    }

    #[test]
    fn decide_leaves_confirm_when_shard_disappeared() {
        let shards = vec![make_shard(vec![0xBB], 100_000, 0, 1)];
        let pending = vec![vec![0xAA]];
        let (reject, confirm) = decide_leaves(
            &shards, &pending, 50000, &BigInt::from(100_000), DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert!(reject.is_empty());
        assert_eq!(confirm.len(), 1);
        assert_eq!(confirm[0], vec![0xAA], "disappeared shard should be confirmed for leave");
    }

    #[test]
    fn decide_leaves_confirm_all_when_no_shards() {
        let pending = vec![vec![0xAA], vec![0xBB]];
        let (reject, confirm) = decide_leaves(
            &[], &pending, 50000, &BigInt::from(100_000), DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert!(reject.is_empty());
        assert_eq!(confirm.len(), 2, "all leaves should be confirmed when no shards exist");
    }

    #[test]
    fn decide_leaves_mixed_decisions() {
        let shards = vec![
            make_shard(vec![0xAA], 150_000, 0, 1),
            make_shard(vec![0xBB], 50_000, 3, 1),
            make_shard(vec![0xCC], 200_000, 0, 1),
        ];
        let pending = vec![vec![0xAA], vec![0xBB]];
        let (reject, confirm) = decide_leaves(
            &shards, &pending, 50000, &BigInt::from(400_000), DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        let reject_hex: Vec<String> = reject.iter().map(hex::encode).collect();
        let confirm_hex: Vec<String> = confirm.iter().map(hex::encode).collect();
        assert!(reject_hex.contains(&"aa".to_string()),
            "aa should be rejected (shard improved), got reject={reject_hex:?} confirm={confirm_hex:?}");
        assert!(confirm_hex.contains(&"bb".to_string()),
            "bb should be confirmed (still bad), got reject={reject_hex:?} confirm={confirm_hex:?}");
    }

    #[test]
    fn decide_leaves_no_pending() {
        let (reject, confirm) = decide_leaves(
            &[], &[], 50000, &BigInt::from(100_000), DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert!(reject.is_empty());
        assert!(confirm.is_empty());
    }

    #[test]
    fn decide_leaves_data_greedy() {
        let shards = vec![
            make_shard(vec![0xAA], 10_000, 0, 1),
            make_shard(vec![0xBB], 80_000, 0, 1),
        ];
        let pending = vec![vec![0xAA]];
        let (reject, confirm) = decide_leaves(
            &shards, &pending, 50000, &BigInt::from(90_000), DEFAULT_UNITS, Strategy::DataGreedy,
        );
        assert!(reject.is_empty());
        assert_eq!(confirm.len(), 1);
        assert_eq!(confirm[0], vec![0xAA], "small shard should be confirmed for leave in DataGreedy");
    }
}
