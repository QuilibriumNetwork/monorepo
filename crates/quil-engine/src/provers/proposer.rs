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
    /// ring assignment). Used for **ring math** (joiner-ring
    /// computation in `compute_shard_ring_info`) — NOT for
    /// halt-risk classification. Use `active_count` for that.
    pub total_active_joining: u64,
    /// Active-only prover count on the shard. Used for halt-risk
    /// prioritization in `plan_and_allocate`, the confirm/leave
    /// bypasses in `decide_joins`/`plan_leaves`/`decide_leaves`,
    /// and `select_excess_active_filters`'s halt-risk exclusion.
    ///
    /// Joining provers MUST NOT count for halt-risk: they haven't
    /// proven anything yet, and most pending joins on a small shard
    /// get auto-rejected at the 67% threshold before reaching
    /// Active. Counting them as coverage masked real halt-risk
    /// shards in the wild (observed 2026-06-02: 107 shards with
    /// `active ≤ 3 && size > 0` were invisible to the halt-risk
    /// bucket because joiners pushed `active+joining` above 3).
    pub active_count: u64,
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
        if d.size > 0 && d.active_count <= HALT_RISK_PROVER_COUNT {
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
                "{}:active={},joining={},size={}",
                hex::encode(&d.filter),
                d.active_count,
                d.total_active_joining.saturating_sub(d.active_count),
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
            matches!(d, Some(d) if d.size > 0 && d.active_count <= HALT_RISK_PROVER_COUNT)
        })
        .count();
    let picks_summary: Vec<String> = proposals
        .iter()
        .map(|p| {
            let halt = shards
                .iter()
                .any(|s| s.filter == p.filter
                    && s.size > 0
                    && s.active_count <= HALT_RISK_PROVER_COUNT);
            format!(
                "core={}:filter={}{}",
                p.worker_id,
                hex::encode(&p.filter),
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

    // Two indexes by hex-filter:
    // - `by_hex`: score, for the threshold comparison
    // - `desc_by_hex`: descriptor, for the halt-risk bypass below
    // Indexing once keeps the per-pending loop O(1).
    let mut by_hex: HashMap<String, BigInt> = HashMap::new();
    let mut desc_by_hex: HashMap<String, &ShardDescriptor> = HashMap::new();
    let mut best_score: Option<BigInt> = None;
    for sc in &scores {
        let d = &candidate_shards[sc.idx];
        let key = hex::encode(&d.filter);
        by_hex.insert(key.clone(), sc.score.clone());
        desc_by_hex.insert(key, d);
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
                // Halt-risk bypass: confirm regardless of score when the
                // shard is at or below the halt-risk prover threshold and
                // has real data (size > 0). Without this, `plan_and_allocate`
                // proposes joins for halt-risk shards by overriding score
                // ordering, then `decide_joins` immediately auto-rejects
                // them ~360 frames later because a larger non-halt-risk
                // shard's score sits above the 67% threshold. The two paths
                // disagree on policy, joins are wasted, and halt-risk shards
                // can still lose their last prover.
                //
                // Rust-only divergence from Go's `proposer.go:DecideJoins`,
                // which applies a flat threshold. Decision pinned 2026-06-01
                // by operator (caheart).
                let is_halt_risk = desc_by_hex
                    .get(&key)
                    .map(|d| d.size > 0 && d.active_count <= HALT_RISK_PROVER_COUNT)
                    .unwrap_or(false);

                if is_halt_risk || *score >= threshold {
                    confirm.push(p.clone());
                } else {
                    reject.push(p.clone());
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

    // When any unallocated shard is halt-risk, the 67% score threshold
    // is superseded: even a competitively-scoring active is worth
    // shedding to free a worker slot so the propose path can grab the
    // halt-risk shard. Otherwise a node fully bound to healthy shards
    // (active_count == worker_count) wedges — `allow_proposals` is
    // false (no free workers), `plan_leaves`' threshold protects every
    // holding, and halt-risk shards stay uncovered. The protection on
    // halt-risk holdings (above) still applies — we only shed
    // non-halt-risk actives.
    let halt_risk_in_unalloc = unallocated_shards.iter()
        .any(|d| d.size > 0 && d.active_count <= HALT_RISK_PROVER_COUNT);

    let alloc_scores = score_shards(allocated_shards, &basis, world_bytes, strategy);

    let mut candidates: Vec<(Vec<u8>, BigInt)> = alloc_scores
        .iter()
        // Halt-risk bypass: never propose a leave when the shard is
        // already halt-risk OR our departure would push it into halt
        // risk. `active_count` already includes us (we're Active on
        // this shard); after we leave it drops by 1, so the post-
        // leave Active count is `active_count - 1`. To keep
        // `post_leave > HALT_RISK_PROVER_COUNT` we need
        // `active_count > HALT_RISK_PROVER_COUNT + 1` — i.e. skip
        // any shard at or below `HALT_RISK_PROVER_COUNT + 1`.
        // Mirrors the join-time priority in `plan_and_allocate`
        // and the confirm-time bypass in `decide_joins`. Joining
        // provers are intentionally NOT counted — they haven't
        // proven anything yet.
        .filter(|sc| {
            let d = &allocated_shards[sc.idx];
            !(d.size > 0 && d.active_count <= HALT_RISK_PROVER_COUNT + 1)
        })
        .filter(|sc| halt_risk_in_unalloc || sc.score < threshold)
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
                    hex::encode(f),
                    score.to_str_radix(10),
                )
            })
            .collect();
        tracing::info!(
            allocated = allocated_shards.len(),
            unallocated = unallocated_shards.len(),
            best_unalloc_score = %best_unalloc.to_str_radix(10),
            threshold = %threshold.to_str_radix(10),
            halt_risk_in_unalloc,
            below_threshold = candidates.len(),
            picked = picks.len(),
            ?picks_summary,
            strategy = ?strategy,
            "plan_leaves: proposing leaves (halt-risk override or below 67% of best unallocated)"
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

    // Two indexes by hex-filter, matching `decide_joins`:
    // - `by_hex`: score, for the threshold comparison
    // - `desc_by_hex`: descriptor, for the halt-risk bypass below
    let mut by_hex: HashMap<String, BigInt> = HashMap::new();
    let mut desc_by_hex: HashMap<String, &ShardDescriptor> = HashMap::new();
    let mut best_score: Option<BigInt> = None;
    for sc in &scores {
        let d = &shards[sc.idx];
        let key = hex::encode(&d.filter);
        by_hex.insert(key.clone(), sc.score.clone());
        desc_by_hex.insert(key, d);
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
                // Halt-risk bypass: reject (stay on shard) when the
                // pending leave targets a halt-risk shard OR would
                // push it into halt risk on confirm. `<=
                // HALT_RISK_PROVER_COUNT + 1` matches `plan_leaves`
                // and `select_excess_active_filters`: a Leaving
                // prover is still contributing coverage to the shard
                // until the leave is confirmed, so the effective
                // safety margin we should preserve is one above the
                // strict halt-risk floor.
                let is_halt_risk = desc_by_hex
                    .get(&key)
                    .map(|d| d.size > 0 && d.active_count <= HALT_RISK_PROVER_COUNT + 1)
                    .unwrap_or(false);

                if is_halt_risk || *score >= threshold {
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
            ShardDescriptor { filter: vec![1], size: 100, ring: 0, shards: 1, active_on_ring: 1, total_active_joining: 16, active_count: 16 },
            ShardDescriptor { filter: vec![2], size: 200, ring: 0, shards: 1, active_on_ring: 1, total_active_joining: 16, active_count: 16 },
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

    /// Data-greedy and reward-greedy must produce DIFFERENT picking
    /// orders on inputs where the two metrics diverge. Reward-greedy
    /// divides by `2^(ring+1)`, so a big shard at a high enough ring
    /// loses to a smaller low-ring shard. Data-greedy ignores ring
    /// and picks the biggest. This pins the behavioral split that
    /// the `Strategy` flag exists to express — regressing it would
    /// silently make both strategies behave the same and the
    /// operator's choice would stop mattering.
    #[test]
    fn strategies_diverge_when_ring_and_size_disagree() {
        // Size ratio 100×; ring penalty ratio 2^9 / 2 = 256×.
        // Reward-greedy: big = 1_000_000 / 512 ≈ 1953;
        //                small = 10_000 / 2 = 5000 → small wins.
        // Data-greedy: 1_000_000 > 10_000 → big wins.
        let big_high_ring = ShardDescriptor {
            filter: vec![0xAA],
            size: 1_000_000,
            ring: 8,             // divisor = 2^9 = 512
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 16,
            active_count: 16,        };
        let small_low_ring = ShardDescriptor {
            filter: vec![0xBB],
            size: 10_000,
            ring: 0,             // divisor = 2
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 16,
            active_count: 16,        };
        let shards = vec![big_high_ring, small_low_ring];
        let basis = BigInt::from(1u64) << 50;
        let world_bytes = BigInt::from(1u64) << 30;

        // Data-greedy: score = size, so the big shard wins.
        let data_scored = score_shards(&shards, &basis, &world_bytes, Strategy::DataGreedy);
        assert_eq!(data_scored[0].score, BigInt::from(1_000_000u64));
        assert_eq!(data_scored[1].score, BigInt::from(10_000u64));
        let data_winner = data_scored
            .iter()
            .max_by(|a, b| a.score.cmp(&b.score))
            .unwrap()
            .idx;
        assert_eq!(data_winner, 0, "data-greedy picks the big shard");

        // Reward-greedy: the ring penalty beats the size advantage.
        let reward_scored = score_shards(&shards, &basis, &world_bytes, Strategy::RewardGreedy);
        let reward_winner = reward_scored
            .iter()
            .max_by(|a, b| a.score.cmp(&b.score))
            .unwrap()
            .idx;
        assert_eq!(reward_winner, 1, "reward-greedy picks the small low-ring shard");

        // The winners are DIFFERENT — the strategy flag matters.
        assert_ne!(data_winner, reward_winner);
    }

    /// Inputs where size and ring agree on the same winner: both
    /// strategies converge. Pins the no-divergence regime so a
    /// future scoring tweak that *adds* divergence here would also
    /// be caught.
    #[test]
    fn strategies_agree_when_ring_and_size_align() {
        // Both shards at ring=0; size differs. Reward-greedy and
        // data-greedy should agree on which is better.
        let big = ShardDescriptor {
            filter: vec![0xAA],
            size: 1_000_000,
            ring: 0,
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 16,
            active_count: 16,        };
        let small = ShardDescriptor {
            filter: vec![0xBB],
            size: 10_000,
            ring: 0,
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 16,
            active_count: 16,        };
        let shards = vec![big, small];
        let basis = BigInt::from(1u64) << 50;
        let world_bytes = BigInt::from(1u64) << 30;

        for strategy in [Strategy::DataGreedy, Strategy::RewardGreedy] {
            let scored = score_shards(&shards, &basis, &world_bytes, strategy);
            let winner = scored
                .iter()
                .max_by(|a, b| a.score.cmp(&b.score))
                .unwrap()
                .idx;
            assert_eq!(
                winner, 0,
                "{strategy:?} should pick the big shard when ring matches"
            );
        }
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
            ShardDescriptor { filter: vec![1], size: 100, ring: 0, shards: 1, active_on_ring: 1, total_active_joining: 16, active_count: 16 },
        ];
        let result = plan_leaves(&allocated, &[], 50000, &BigInt::from(1_000_000), DEFAULT_UNITS, Strategy::RewardGreedy);
        assert!(result.is_empty());
    }

    fn make_shard(filter: Vec<u8>, size: u64, ring: u8, shards: u64) -> ShardDescriptor {
        // Default `total_active_joining` and `active_count` = 16 so
        // the shard is NOT
        // halt-risk in tests that don't care about that bucket.
        ShardDescriptor {
            filter,
            size,
            ring,
            shards,
            active_on_ring: 1,
            total_active_joining: 16,
            active_count: 16,
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
            active_count: 8,        };
        let halt_risk = ShardDescriptor {
            filter: vec![2],
            size: 1_000_000,
            ring: 0,
            shards: 1,
            active_on_ring: 4,
            total_active_joining: 3,
            active_count: 3,        };
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
            active_count: 8,        };
        let halt_a = ShardDescriptor {
            filter: vec![1],
            size: 500_000,
            ring: 0,
            shards: 1,
            active_on_ring: 2,
            total_active_joining: 1,
            active_count: 1,        };
        let halt_b = ShardDescriptor {
            filter: vec![2],
            size: 700_000,
            ring: 0,
            shards: 1,
            active_on_ring: 3,
            total_active_joining: 2,
            active_count: 2,        };
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
            active_count: 1,        };
        let normal = ShardDescriptor {
            filter: vec![2],
            size: 100_000,
            ring: 0,
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 16,
            active_count: 16,        };
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

    /// Joining provers do NOT count toward halt-risk classification.
    /// A shard with `active=2, joining=10` (12 total) is still halt-risk
    /// because joiners haven't confirmed and may not — coverage is
    /// `active` only. Catches the 2026-06-02 regression where 107
    /// real halt-risk shards on mainnet were invisible to
    /// `plan_and_allocate` because pending joins masked the low active
    /// count.
    #[test]
    fn plan_and_allocate_treats_active_only_as_halt_risk_metric() {
        // `total_active_joining` = 12 (high), `active_count` = 2 (low).
        // Under the old `total_active_joining`-based check this would
        // NOT be halt-risk; with `active_count` it IS.
        let crowded_joiners_few_active = ShardDescriptor {
            filter: vec![0xAA],
            size: 1_000_000,
            ring: 1,
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 12,
            active_count: 2, // ← halt-risk
        };
        let healthy = ShardDescriptor {
            filter: vec![0xBB],
            size: 10_000_000,
            ring: 1,
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 8,
            active_count: 8,
        };
        let result = plan_and_allocate(
            &[healthy, crowded_joiners_few_active],
            50_000,
            &BigInt::from(20_000_000u64),
            DEFAULT_UNITS,
            &[1],
            1,
            Strategy::RewardGreedy,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].filter, vec![0xAA],
            "shard with active=2 (despite joining=10) must be picked as halt-risk");
    }

    /// Halt-risk pending shard with score below the 67% threshold is
    /// CONFIRMED, not rejected. Mirrors `plan_and_allocate`'s halt-risk
    /// priority so the propose→confirm pipeline stays coherent.
    #[test]
    fn decide_joins_confirms_halt_risk_below_threshold() {
        // 0xBB is a big healthy shard (high score), 0xAA is a tiny
        // halt-risk shard (low score, 2 provers).
        let shards = vec![
            ShardDescriptor {
                filter: vec![0xAA],
                size: 5_000,
                ring: 0,
                shards: 1,
                active_on_ring: 1,
                total_active_joining: 2, // ← halt-risk (≤ HALT_RISK_PROVER_COUNT)
                active_count: 2,
            },
            ShardDescriptor {
                filter: vec![0xBB],
                size: 500_000,
                ring: 0,
                shards: 1,
                active_on_ring: 1,
                total_active_joining: 16,
                active_count: 16,            },
        ];
        let pending = vec![vec![0xAA]];
        let (reject, confirm) = decide_joins(
            &shards, &pending, 50000, &BigInt::from(600_000),
            DEFAULT_UNITS, Strategy::RewardGreedy, usize::MAX,
        );
        assert!(reject.is_empty(),
            "halt-risk pending should bypass the 67% threshold; got reject={reject:?}");
        assert_eq!(confirm, vec![vec![0xAA]]);
    }

    /// Halt-risk bypass requires size > 0 — a halt-risk-by-prover-count
    /// shard with zero data shouldn't be confirmed (no point allocating
    /// a worker to a shard with nothing to prove).
    #[test]
    fn decide_joins_does_not_confirm_zero_size_halt_risk() {
        let shards = vec![
            ShardDescriptor {
                filter: vec![0xAA],
                size: 0,                // ← no data
                ring: 0,
                shards: 1,
                active_on_ring: 1,
                total_active_joining: 2, // halt-risk by count
                active_count: 2,
            },
            ShardDescriptor {
                filter: vec![0xBB],
                size: 500_000,
                ring: 0,
                shards: 1,
                active_on_ring: 1,
                total_active_joining: 16,
                active_count: 16,            },
        ];
        let pending = vec![vec![0xAA]];
        let (reject, confirm) = decide_joins(
            &shards, &pending, 50000, &BigInt::from(600_000),
            DEFAULT_UNITS, Strategy::RewardGreedy, usize::MAX,
        );
        assert_eq!(reject, vec![vec![0xAA]],
            "zero-size halt-risk should still be rejected; got confirm={confirm:?}");
        assert!(confirm.is_empty());
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

    /// Halt-risk allocated shard MUST NOT be picked as a leave
    /// candidate even when its score sits below the 67% threshold —
    /// mirrors `decide_joins`' confirm-side bypass to keep the
    /// lifecycle coherent across propose/confirm/leave/decide_leave.
    #[test]
    fn plan_leaves_skips_halt_risk() {
        let allocated = vec![
            ShardDescriptor {
                filter: vec![0xAA],
                size: 5_000,
                ring: 3,
                shards: 1,
                active_on_ring: 1,
                total_active_joining: 2, // ← halt-risk
                active_count: 2,
            },
        ];
        let unallocated = vec![make_shard(vec![0xBB], 500_000, 0, 1)];
        let filters = plan_leaves(
            &allocated, &unallocated, 50000, &BigInt::from(600_000),
            DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert!(filters.is_empty(),
            "halt-risk allocated shard must not be a leave candidate; got {filters:?}");
    }

    /// Leaving a shard with `active_count == HALT_RISK_PROVER_COUNT
    /// + 1` would drop its Active count to `HALT_RISK_PROVER_COUNT`
    /// = halt-risk. The protection extends one prover above the
    /// threshold to forbid that transition.
    #[test]
    fn plan_leaves_skips_shard_one_above_halt_risk_threshold() {
        let allocated = vec![ShardDescriptor {
            filter: vec![0xAA],
            size: 5_000,
            ring: 3,
            shards: 1,
            active_on_ring: 1,
            // Exactly HALT_RISK_PROVER_COUNT + 1 = 4. Leaving makes
            // it halt-risk.
            total_active_joining: HALT_RISK_PROVER_COUNT + 1,
            active_count: HALT_RISK_PROVER_COUNT + 1,
        }];
        let unallocated = vec![make_shard(vec![0xBB], 500_000, 0, 1)];
        let filters = plan_leaves(
            &allocated, &unallocated, 50_000, &BigInt::from(600_000),
            DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert!(filters.is_empty(),
            "shard at threshold+1 must be protected — leaving would push it into halt-risk");
    }

    /// When ANY unallocated shard is halt-risk, the 67% score
    /// threshold is bypassed and competitive non-halt-risk actives
    /// become leave candidates. Otherwise a node bound to healthy
    /// shards wedges — no free worker, threshold protects every
    /// holding, halt-risk shards stay uncovered. The halt-risk
    /// protection on allocated shards still applies.
    #[test]
    fn plan_leaves_supersedes_threshold_when_unallocated_halt_risk_exists() {
        let allocated = vec![
            make_shard(vec![0xA1], 100_000, 0, 1),
            make_shard(vec![0xA2], 100_000, 0, 1),
        ];
        // Halt-risk unallocated: active_count <= HALT_RISK_PROVER_COUNT (3).
        let unallocated = vec![ShardDescriptor {
            filter: vec![0xBB],
            size: 90_000,
            ring: 0,
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 2,
            active_count: 2,
        }];
        let filters = plan_leaves(
            &allocated, &unallocated, 50_000, &BigInt::from(300_000),
            DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert!(!filters.is_empty(),
            "halt-risk in unallocated must supersede the 67% threshold");
    }

    /// Held halt-risk actives stay protected even when the threshold
    /// bypass triggers — bypass relaxes the score floor on non-halt-risk
    /// actives, it doesn't unblock leaving halt-risk holdings.
    #[test]
    fn plan_leaves_bypass_still_protects_held_halt_risk() {
        let allocated = vec![
            // Held halt-risk — must be protected.
            ShardDescriptor {
                filter: vec![0xA1],
                size: 5_000,
                ring: 3,
                shards: 1,
                active_on_ring: 1,
                total_active_joining: 2,
                active_count: 2,
            },
            // Healthy active — leave candidate under bypass.
            make_shard(vec![0xA2], 100_000, 0, 1),
        ];
        let unallocated = vec![ShardDescriptor {
            filter: vec![0xBB],
            size: 90_000,
            ring: 0,
            shards: 1,
            active_on_ring: 1,
            total_active_joining: 2,
            active_count: 2,
        }];
        let filters = plan_leaves(
            &allocated, &unallocated, 50_000, &BigInt::from(300_000),
            DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert_eq!(filters, vec![vec![0xA2]],
            "bypass must shed healthy A2 but spare held halt-risk A1");
    }

    /// plan_leaves DOES leave a non-halt-risk shard even when a
    /// halt-risk allocated is present — bypass is per-shard, not
    /// blanket-disabling.
    #[test]
    fn plan_leaves_leaves_non_halt_risk_when_halt_risk_present() {
        let allocated = vec![
            ShardDescriptor {
                filter: vec![0xAA],
                size: 5_000,
                ring: 3,
                shards: 1,
                active_on_ring: 1,
                total_active_joining: 2, // halt-risk: protected
                active_count: 2,
            },
            make_shard(vec![0xBB], 30_000, 4, 1), // non-halt-risk, low score
        ];
        let unallocated = vec![make_shard(vec![0xCC], 500_000, 0, 1)];
        let filters = plan_leaves(
            &allocated, &unallocated, 50000, &BigInt::from(600_000),
            DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert_eq!(filters, vec![vec![0xBB]],
            "non-halt-risk poor performer should still be a leave candidate");
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

    /// Pending leave on a halt-risk shard gets REJECTED (stay) even
    /// when the shard's score sits below the 67% threshold. Handles
    /// the case where a pending leave was queued before the halt-risk
    /// bypass was deployed, or where the operator manually triggered
    /// a leave for a shard the network has since become dependent on.
    #[test]
    fn decide_leaves_rejects_halt_risk_pending() {
        let shards = vec![
            ShardDescriptor {
                filter: vec![0xAA],
                size: 5_000,
                ring: 3,
                shards: 1,
                active_on_ring: 1,
                total_active_joining: 2, // ← halt-risk
                active_count: 2,
            },
            make_shard(vec![0xBB], 500_000, 0, 1),
        ];
        let pending = vec![vec![0xAA]];
        let (reject, confirm) = decide_leaves(
            &shards, &pending, 50000, &BigInt::from(600_000),
            DEFAULT_UNITS, Strategy::RewardGreedy,
        );
        assert_eq!(reject, vec![vec![0xAA]],
            "halt-risk pending leave must be rejected (stay); got confirm={confirm:?}");
        assert!(confirm.is_empty());
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
