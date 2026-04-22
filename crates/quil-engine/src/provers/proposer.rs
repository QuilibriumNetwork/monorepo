//! Prover shard scoring and join/leave decision logic.
//!
//! Pure computation with no I/O, making it easy to unit test in isolation.
//!
//! Port of `node/consensus/provers/proposer.go`.

use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};
use std::collections::HashMap;

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
}

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
/// Returns `(1_125_899_906_842_624 / world_state_bytes) ^ (1 / 2^generation) * units`
/// where `generation` = number of times difficulty can be divided by 10000.
///
/// Port of Go's `reward.PomwBasis` at `node/consensus/reward/proof_of_meaningful_work.go:87-126`.
pub fn pomw_basis(difficulty: u64, world_state_bytes: u64, units: u64) -> BigInt {
    if world_state_bytes == 0 {
        return BigInt::zero();
    }

    // Work in fixed-point with 53-bit precision (matches Go's decimal library precision arg).
    let normalized_num = BigInt::from(1_125_899_906_842_624u64);
    let scale = BigInt::from(1u64 << 53);
    let normalized_scaled = (&normalized_num * &scale) / BigInt::from(world_state_bytes);

    // Compute generation from difficulty (log_10000 count)
    let mut generation = 0u32;
    let mut difflog = difficulty;
    while difflog >= 10_000 {
        difflog /= 10_000;
        generation += 1;
    }

    // Apply integer sqrt `generation` times to approximate (normalized)^(1/2^generation).
    let mut result = normalized_scaled;
    for _ in 0..generation {
        result = integer_sqrt(&(&result * &scale));
    }

    let final_result = (&result * BigInt::from(units)) / &scale;
    final_result
}

/// Integer square root via Newton's method.
fn integer_sqrt(n: &BigInt) -> BigInt {
    if n.is_zero() || n.is_negative() {
        return BigInt::zero();
    }
    let mut x: BigInt = n.clone();
    let mut y: BigInt = (&x + BigInt::one()) >> 1u32;
    while y < x {
        x = y.clone();
        y = (&x + n / &x) >> 1u32;
    }
    x
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

                // shards sqrt (integer approximation)
                let shards_sqrt = integer_sqrt(&BigInt::from(effective_shards));
                if shards_sqrt.is_zero() {
                    scores.push(Scored { idx: i, score: BigInt::zero() });
                    continue;
                }

                // score = factor / divisor / shards_sqrt / 8
                let score = factor / BigInt::from(divisor) / &shards_sqrt / BigInt::from(8);
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

    let limit = max_allocations
        .min(free_worker_ids.len())
        .min(scores.len());

    // Sort worker IDs deterministically so top-k shards go to lowest core IDs
    let mut sorted_workers = free_worker_ids.to_vec();
    sorted_workers.sort();

    let wb = world_bytes.try_into().unwrap_or(0u64);
    (0..limit)
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
        .collect()
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
pub fn decide_joins(
    candidate_shards: &[ShardDescriptor],
    pending: &[Vec<u8>],
    difficulty: u64,
    world_bytes: &BigInt,
    units: u64,
    strategy: Strategy,
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
    candidates.into_iter().take(3).map(|(f, _)| f).collect()
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
            ShardDescriptor { filter: vec![1], size: 100, ring: 0, shards: 1, active_on_ring: 1 },
            ShardDescriptor { filter: vec![2], size: 200, ring: 0, shards: 1, active_on_ring: 1 },
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
        );
        assert_eq!(reject.len(), 1);
        assert!(confirm.is_empty());
    }

    #[test]
    fn plan_leaves_empty_when_no_unallocated() {
        let allocated = vec![
            ShardDescriptor { filter: vec![1], size: 100, ring: 0, shards: 1, active_on_ring: 1 },
        ];
        let result = plan_leaves(&allocated, &[], 50000, &BigInt::from(1_000_000), DEFAULT_UNITS, Strategy::RewardGreedy);
        assert!(result.is_empty());
    }

    fn make_shard(filter: Vec<u8>, size: u64, ring: u8, shards: u64) -> ShardDescriptor {
        ShardDescriptor { filter, size, ring, shards, active_on_ring: 1 }
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
        );
        assert!(confirm.is_empty());
        assert_eq!(reject.len(), 1);
        assert_eq!(reject[0], vec![0xDE, 0xAD, 0xBE, 0xEF]);
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
