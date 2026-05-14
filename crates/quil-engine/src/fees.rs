//! Rust port of `node/consensus/fees/dynamic_fee_manager.go`.
//!
//! Tracks fee-multiplier votes from frames on a sliding window and
//! returns the arithmetic mean as the next fee multiplier. Matches
//! Go's behaviour bit-for-bit except for the Prometheus metrics
//! (handled at a higher layer in Rust) and the "filter as hex string"
//! key encoding (we use `Vec<u8>` directly since `HashMap<Vec<u8>, _>`
//! is equivalent and avoids the allocation).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use quil_types::consensus::DynamicFeeManager;
use quil_types::error::{QuilError, Result};

/// Maximum number of votes retained per filter (matches Go's
/// `maxWindowSize = 360`).
pub const MAX_WINDOW_SIZE: usize = 360;

/// Default fee multiplier returned when a filter has no votes yet
/// (matches Go's `defaultFeeMultiplier = 100`).
pub const DEFAULT_FEE_MULTIPLIER: u64 = 100;

/// One sliding-window vote entry.
#[derive(Debug, Clone, Copy)]
struct FeeVote {
    frame_number: u64,
    fee_multiplier_vote: u64,
}

/// Per-filter state: the sliding window of votes, the running sum,
/// and the last-updated timestamp used by `prune_old_data`.
struct FilterFeeData {
    votes: Vec<FeeVote>,
    sum_votes: u64,
    last_updated: Instant,
}

impl FilterFeeData {
    fn new() -> Self {
        Self {
            votes: Vec::with_capacity(MAX_WINDOW_SIZE),
            sum_votes: 0,
            last_updated: Instant::now(),
        }
    }
}

/// In-memory dynamic fee manager with sliding window averaging.
///
/// The `window_size` argument is a soft cap. It is clamped to
/// `MAX_WINDOW_SIZE` to match Go's fixed cap, but smaller values are
/// accepted for tests.
pub struct InMemoryDynamicFeeManager {
    filter_data: RwLock<HashMap<Vec<u8>, FilterFeeData>>,
    window_size: usize,
}

impl InMemoryDynamicFeeManager {
    pub fn new(window_size: usize) -> Self {
        Self {
            filter_data: RwLock::new(HashMap::new()),
            window_size: window_size.min(MAX_WINDOW_SIZE),
        }
    }
}

impl DynamicFeeManager for InMemoryDynamicFeeManager {
    /// Add a fee multiplier vote from a frame. Returns an error if
    /// `frame_number` is not strictly newer than the most recent
    /// vote for this filter (Go's `AddFrameFeeVote` rejects
    /// out-of-order frames with the same error shape).
    fn add_frame_fee_vote(
        &self,
        filter: &[u8],
        frame_number: u64,
        fee_multiplier_vote: u64,
    ) -> Result<()> {
        let mut map = self.filter_data.write().unwrap();
        let data = map
            .entry(filter.to_vec())
            .or_insert_with(FilterFeeData::new);

        if let Some(last) = data.votes.last() {
            if frame_number <= last.frame_number {
                return Err(QuilError::InvalidArgument(format!(
                    "frame {} is not newer than last frame {}",
                    frame_number, last.frame_number
                )));
            }
        }

        data.votes.push(FeeVote {
            frame_number,
            fee_multiplier_vote,
        });
        data.sum_votes = data.sum_votes.wrapping_add(fee_multiplier_vote);
        data.last_updated = Instant::now();

        // Enforce the sliding window — drop the oldest vote if we're
        // above the cap.
        if data.votes.len() > self.window_size {
            let old = data.votes.remove(0);
            data.sum_votes = data.sum_votes.wrapping_sub(old.fee_multiplier_vote);
        }
        Ok(())
    }

    /// Return the arithmetic mean of the current window. If the
    /// filter has no votes, return `DEFAULT_FEE_MULTIPLIER`.
    fn get_next_fee_multiplier(&self, filter: &[u8]) -> Result<u64> {
        let map = self.filter_data.read().unwrap();
        match map.get(filter) {
            Some(data) if !data.votes.is_empty() => {
                Ok(data.sum_votes / data.votes.len() as u64)
            }
            _ => Ok(DEFAULT_FEE_MULTIPLIER),
        }
    }

    /// Snapshot of the current vote window (multipliers only).
    fn get_vote_history(&self, filter: &[u8]) -> Result<Vec<u64>> {
        let map = self.filter_data.read().unwrap();
        Ok(map
            .get(filter)
            .map(|d| d.votes.iter().map(|v| v.fee_multiplier_vote).collect())
            .unwrap_or_default())
    }

    /// Number of votes currently in the sliding window.
    fn get_average_window_size(&self, filter: &[u8]) -> Result<usize> {
        let map = self.filter_data.read().unwrap();
        Ok(map.get(filter).map(|d| d.votes.len()).unwrap_or(0))
    }

    /// Drop filters whose `last_updated` is older than `max_age`
    /// milliseconds.
    fn prune_old_data(&self, max_age: u64) -> Result<()> {
        let mut map = self.filter_data.write().unwrap();
        let Some(cutoff) = Instant::now().checked_sub(Duration::from_millis(max_age)) else {
            return Ok(());
        };
        map.retain(|_, data| data.last_updated >= cutoff);
        Ok(())
    }

    /// Remove every vote in the window whose `frame_number` is
    /// strictly greater than `frame_number`. Returns the number of
    /// votes removed. Mirror of Go's `RewindToFrame` at
    /// `dynamic_fee_manager.go:249`.
    fn rewind_to_frame(&self, filter: &[u8], frame_number: u64) -> Result<usize> {
        let mut map = self.filter_data.write().unwrap();
        let Some(data) = map.get_mut(filter) else {
            return Ok(0);
        };
        if data.votes.is_empty() {
            return Ok(0);
        }

        // Find the first vote with `frameNumber > frame_number`.
        // Everything before it is kept; everything from it onward is
        // dropped. `votes` is kept sorted by `frame_number` by the
        // append-only insertion pattern plus the out-of-order guard
        // in `add_frame_fee_vote`.
        let keep_index = data
            .votes
            .iter()
            .position(|v| v.frame_number > frame_number)
            .unwrap_or(data.votes.len());

        let removed_count = data.votes.len() - keep_index;
        if removed_count == 0 {
            return Ok(0);
        }

        // Update the running sum by subtracting each removed vote.
        for v in &data.votes[keep_index..] {
            data.sum_votes = data.sum_votes.wrapping_sub(v.fee_multiplier_vote);
        }
        data.votes.truncate(keep_index);
        Ok(removed_count)
    }
}

// =====================================================================
// Fee traffic adjustment — matches Go's adjustFeeForTraffic()
// =====================================================================

/// Target frame production time in milliseconds (10 seconds).
const TARGET_FRAME_TIME_MS: i64 = 10_000;

/// Maximum percentage adjustment per frame (capped at 10%).
const MAX_ADJUSTMENT_PERCENT: i64 = 10;

/// Adjust the base fee multiplier based on actual frame production
/// timing vs the 10-second target.
///
/// If frames are produced faster than target, the fee decreases
/// (incentivizing more transactions). If slower, the fee increases
/// (reducing load). Adjustment is capped at ±10% per frame.
///
/// Only applies when the node is in "reward-greedy" strategy. For
/// other strategies, returns base_fee unchanged.
///
/// # Arguments
/// * `base_fee` — the average fee from the sliding window
/// * `current_timestamp_ms` — this frame's timestamp (ms since epoch)
/// * `previous_timestamp_ms` — previous frame's timestamp (ms since epoch)
/// * `reward_greedy` — whether the node uses reward-greedy strategy
///
/// # Returns
/// The adjusted fee multiplier (always >= 1).
pub fn adjust_fee_for_traffic(
    base_fee: u64,
    current_timestamp_ms: i64,
    previous_timestamp_ms: i64,
    reward_greedy: bool,
) -> u64 {
    if !reward_greedy {
        return base_fee;
    }

    if base_fee == 0 {
        return 1;
    }

    let time_diff = current_timestamp_ms - previous_timestamp_ms;

    if time_diff < TARGET_FRAME_TIME_MS {
        // Frames are faster than target → decrease fee
        let mut percent_faster =
            (TARGET_FRAME_TIME_MS - time_diff) * 100 / TARGET_FRAME_TIME_MS;
        if percent_faster > MAX_ADJUSTMENT_PERCENT {
            percent_faster = MAX_ADJUSTMENT_PERCENT;
        }
        let adjustment = base_fee * percent_faster as u64 / 100;
        let adjusted = base_fee.saturating_sub(adjustment);
        adjusted.max(1) // minimum fee is 1
    } else if time_diff > TARGET_FRAME_TIME_MS {
        // Frames are slower than target → increase fee
        let mut percent_slower =
            (time_diff - TARGET_FRAME_TIME_MS) * 100 / TARGET_FRAME_TIME_MS;
        if percent_slower > MAX_ADJUSTMENT_PERCENT {
            percent_slower = MAX_ADJUSTMENT_PERCENT;
        }
        let adjustment = base_fee * percent_slower as u64 / 100;
        base_fee.saturating_add(adjustment)
    } else {
        // Exactly on target
        base_fee
    }
}

/// Compute the full fee multiplier for a new frame: base from the
/// sliding window, then traffic-adjusted.
///
/// This is the value that goes into `FrameHeader.fee_multiplier_vote`.
pub fn compute_fee_multiplier_vote(
    fee_manager: &dyn DynamicFeeManager,
    filter: &[u8],
    current_timestamp_ms: i64,
    previous_timestamp_ms: i64,
    reward_greedy: bool,
) -> u64 {
    let base = fee_manager
        .get_next_fee_multiplier(filter)
        .unwrap_or(DEFAULT_FEE_MULTIPLIER);
    adjust_fee_for_traffic(base, current_timestamp_ms, previous_timestamp_ms, reward_greedy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr(window: usize) -> InMemoryDynamicFeeManager {
        InMemoryDynamicFeeManager::new(window)
    }

    #[test]
    fn default_fee_returned_when_no_votes() {
        let m = mgr(10);
        assert_eq!(
            m.get_next_fee_multiplier(&[0x01]).unwrap(),
            DEFAULT_FEE_MULTIPLIER
        );
    }

    #[test]
    fn add_then_average() {
        let m = mgr(10);
        m.add_frame_fee_vote(&[0x01], 1, 100).unwrap();
        m.add_frame_fee_vote(&[0x01], 2, 200).unwrap();
        m.add_frame_fee_vote(&[0x01], 3, 300).unwrap();
        assert_eq!(m.get_next_fee_multiplier(&[0x01]).unwrap(), 200);
        assert_eq!(m.get_average_window_size(&[0x01]).unwrap(), 3);
    }

    #[test]
    fn out_of_order_frame_rejected() {
        let m = mgr(10);
        m.add_frame_fee_vote(&[0x01], 5, 100).unwrap();
        assert!(m.add_frame_fee_vote(&[0x01], 5, 100).is_err());
        assert!(m.add_frame_fee_vote(&[0x01], 3, 100).is_err());
    }

    #[test]
    fn sliding_window_evicts_oldest() {
        let m = mgr(3);
        m.add_frame_fee_vote(&[0x01], 1, 100).unwrap();
        m.add_frame_fee_vote(&[0x01], 2, 200).unwrap();
        m.add_frame_fee_vote(&[0x01], 3, 300).unwrap();
        m.add_frame_fee_vote(&[0x01], 4, 400).unwrap();
        assert_eq!(m.get_average_window_size(&[0x01]).unwrap(), 3);
        assert_eq!(m.get_next_fee_multiplier(&[0x01]).unwrap(), 300);
        assert_eq!(
            m.get_vote_history(&[0x01]).unwrap(),
            vec![200u64, 300, 400]
        );
    }

    #[test]
    fn rewind_drops_newer_votes_only() {
        let m = mgr(10);
        for (f, v) in &[(1u64, 100u64), (2, 200), (3, 300), (4, 400), (5, 500)] {
            m.add_frame_fee_vote(&[0x01], *f, *v).unwrap();
        }
        let removed = m.rewind_to_frame(&[0x01], 3).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(
            m.get_vote_history(&[0x01]).unwrap(),
            vec![100u64, 200, 300]
        );
        assert_eq!(m.get_next_fee_multiplier(&[0x01]).unwrap(), 200);
    }

    #[test]
    fn rewind_past_all_frames_keeps_everything() {
        let m = mgr(10);
        m.add_frame_fee_vote(&[0x01], 1, 100).unwrap();
        m.add_frame_fee_vote(&[0x01], 2, 200).unwrap();
        assert_eq!(m.rewind_to_frame(&[0x01], 1000).unwrap(), 0);
        assert_eq!(m.get_average_window_size(&[0x01]).unwrap(), 2);
    }

    #[test]
    fn rewind_on_missing_filter() {
        let m = mgr(10);
        assert_eq!(m.rewind_to_frame(&[0xFF], 100).unwrap(), 0);
    }

    #[test]
    fn per_filter_isolation() {
        let m = mgr(10);
        m.add_frame_fee_vote(&[0x01], 1, 100).unwrap();
        m.add_frame_fee_vote(&[0x02], 1, 500).unwrap();
        assert_eq!(m.get_next_fee_multiplier(&[0x01]).unwrap(), 100);
        assert_eq!(m.get_next_fee_multiplier(&[0x02]).unwrap(), 500);
    }

    #[test]
    fn window_size_is_clamped_to_max() {
        let m = mgr(10_000);
        assert!(m.window_size <= MAX_WINDOW_SIZE);
    }

    #[test]
    fn prune_old_data_noop_on_empty() {
        let m = mgr(10);
        m.prune_old_data(100).unwrap();
    }

    // === adjust_fee_for_traffic tests ===

    #[test]
    fn traffic_no_adjustment_when_not_reward_greedy() {
        assert_eq!(adjust_fee_for_traffic(100, 5000, 0, false), 100);
    }

    #[test]
    fn traffic_exactly_on_target() {
        // 10s between frames → no adjustment
        assert_eq!(adjust_fee_for_traffic(100, 20_000, 10_000, true), 100);
    }

    #[test]
    fn traffic_faster_than_target_decreases_fee() {
        // 5s between frames = 50% faster, but capped at 10%
        let adjusted = adjust_fee_for_traffic(100, 15_000, 10_000, true);
        assert_eq!(adjusted, 90); // 100 - (100 * 10 / 100) = 90 (capped at 10%)
    }

    #[test]
    fn traffic_slower_than_target_increases_fee() {
        // 15s between frames = 50% slower, but capped at 10%
        let adjusted = adjust_fee_for_traffic(100, 25_000, 10_000, true);
        assert_eq!(adjusted, 110); // 100 + (100 * 10 / 100) = 110 (capped at 10%)
    }

    #[test]
    fn traffic_slightly_faster_proportional() {
        // 9s = 10% faster → exactly at cap
        let adjusted = adjust_fee_for_traffic(1000, 19_000, 10_000, true);
        assert_eq!(adjusted, 900); // 1000 - (1000 * 10 / 100) = 900
    }

    #[test]
    fn traffic_slightly_slower_proportional() {
        // 11s = 10% slower → exactly at cap
        let adjusted = adjust_fee_for_traffic(1000, 21_000, 10_000, true);
        assert_eq!(adjusted, 1100); // 1000 + (1000 * 10 / 100) = 1100
    }

    #[test]
    fn traffic_minimum_fee_is_one() {
        // Very fast frames with low base fee
        let adjusted = adjust_fee_for_traffic(1, 1000, 0, true);
        assert_eq!(adjusted, 1); // can't go below 1
    }

    #[test]
    fn traffic_zero_base_fee_returns_one() {
        assert_eq!(adjust_fee_for_traffic(0, 5000, 0, true), 1);
    }

    #[test]
    fn compute_fee_multiplier_vote_uses_base_and_traffic() {
        let m = mgr(10);
        m.add_frame_fee_vote(&[1], 1, 200).unwrap();
        m.add_frame_fee_vote(&[1], 2, 200).unwrap();
        // Base = 200, frames exactly on target → 200
        let vote = compute_fee_multiplier_vote(&m, &[1], 20_000, 10_000, true);
        assert_eq!(vote, 200);
        // Base = 200, frames faster → decrease
        let vote = compute_fee_multiplier_vote(&m, &[1], 15_000, 10_000, true);
        assert_eq!(vote, 180); // 200 - 10% = 180
    }

    /// Side-by-side comparison: with identical inputs (fee manager
    /// state, timestamps), `reward_greedy=true` adjusts the fee toward
    /// the protocol target while `reward_greedy=false` leaves the
    /// base unchanged. This is the "data-greedy vs reward-greedy"
    /// behavioral divergence — the same chain state can yield two
    /// distinct `fee_multiplier_vote` numbers depending on the local
    /// node's strategy. Frame headers carry whichever value the
    /// proposing node chose, so a mixed-strategy committee will see
    /// vote spread.
    #[test]
    fn reward_greedy_vs_data_greedy_diverge_on_off_target_cadence() {
        let m = mgr(10);
        // Prime the sliding window so base_fee > 1.
        for f in 1..=3u64 {
            m.add_frame_fee_vote(&[7], f, 500).unwrap();
        }
        // Off-target cadence: 5s (50% faster than 10s target → capped
        // at 10% drop).
        let now = 30_000i64;
        let prev = 25_000i64;
        let reward_greedy = compute_fee_multiplier_vote(&m, &[7], now, prev, true);
        let data_greedy = compute_fee_multiplier_vote(&m, &[7], now, prev, false);
        assert_ne!(
            reward_greedy, data_greedy,
            "strategies must produce different votes on off-target cadence"
        );
        // Reward-greedy applies the 10% downward cap on a base of 500.
        assert_eq!(reward_greedy, 450, "reward_greedy=500 - 10% = 450");
        // Data-greedy passes the base through untouched.
        assert_eq!(data_greedy, 500, "data_greedy passes base through");

        // Symmetry check: on slower-than-target cadence the
        // reward-greedy strategy raises the fee while data-greedy
        // again leaves it alone.
        let now_slow = 50_000i64;
        let prev_slow = 30_000i64; // 20s gap
        let rg_slow = compute_fee_multiplier_vote(&m, &[7], now_slow, prev_slow, true);
        let dg_slow = compute_fee_multiplier_vote(&m, &[7], now_slow, prev_slow, false);
        assert_eq!(rg_slow, 550, "reward_greedy raises 500 → 550 on slow cadence");
        assert_eq!(dg_slow, 500, "data_greedy untouched on slow cadence");
    }

    /// On-target cadence: the two strategies *agree*. This is the
    /// no-arbitrage case — if everyone proposes exactly on target,
    /// reward-greedy has no incentive to deviate from data-greedy.
    /// Useful as a regression sentinel: if a future refactor makes
    /// reward-greedy diverge here, fee dispersion would creep in even
    /// when the chain is healthy.
    #[test]
    fn reward_greedy_vs_data_greedy_agree_on_target_cadence() {
        let m = mgr(10);
        m.add_frame_fee_vote(&[9], 1, 750).unwrap();
        let now = 20_000i64;
        let prev = 10_000i64; // exactly 10s
        let rg = compute_fee_multiplier_vote(&m, &[9], now, prev, true);
        let dg = compute_fee_multiplier_vote(&m, &[9], now, prev, false);
        assert_eq!(rg, dg, "strategies agree on target cadence");
        assert_eq!(rg, 750);
    }
}
