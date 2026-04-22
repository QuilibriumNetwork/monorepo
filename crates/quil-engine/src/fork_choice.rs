//! Fork choice algorithm. Port of
//! `node/consensus/time/fork_choice.go`.
//!
//! Given a set of candidate branches (each a sequence of [`Frame`]s
//! with a per-frame distance-from-target and prover seniority), the
//! algorithm picks the branch an honest player should extend. The
//! scoring is:
//!
//! ```text
//!     score(branch) = blend_bonus × Σ_i α^{n-i} · frame_score(i)
//!     frame_score(i) = (w_r · ρ(dist_i) + w_p · π(seniority_i)) / w_denom
//!     blend_bonus = 1 + (β · unique_provers_in_last_m / m)
//! ```
//!
//! - `ρ` (rho) maps distance `r ∈ [0, R_max]` to `[0, SCALE]`, with
//!   smaller distance → higher ρ. Closer frames to the target score
//!   better.
//! - `π` (pi) maps seniority to `[0, SCALE]`, clamped.
//! - `α` is the exponential-decay factor applied frame-by-frame —
//!   older frames matter less.
//! - The blend bonus rewards branches that are extended by diverse
//!   sets of provers within a sliding window of the last `m` frames,
//!   penalizing single-prover forks.
//!
//! The result is compared across branches with a tie-break
//! tolerance ε: a new candidate must beat the incumbent by strictly
//! more than ε to unseat it. This gives hysteresis — the "stick to
//! your last choice" bias that keeps consensus stable when scores
//! are close.
//!
//! All arithmetic is big-integer to match Go exactly.

use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};

/// Scale factor for fixed-point arithmetic. `SCALE = 2^64 - 1`.
/// Distances and seniorities are normalized to `[0, SCALE]` before
/// being combined.
pub const SCALE: u64 = u64::MAX;

/// A single frame contributing to a branch's score.
#[derive(Debug, Clone)]
pub struct Frame {
    /// 256-bit distance to the target (0 is the best possible).
    pub distance: BigInt,
    /// Prover seniority in `[0, SCALE]`. Zero means evicted or
    /// blacklisted — the blend bonus skips these entirely.
    pub seniority: u64,
    /// Raw address bytes for the prover that produced the frame —
    /// used to compute branch diversity (unique provers in the
    /// blend window).
    pub prover_address: Vec<u8>,
}

/// A candidate branch: an ordered list of frames from oldest to
/// newest.
#[derive(Debug, Clone)]
pub struct Branch {
    pub frames: Vec<Frame>,
}

/// Tunable parameters for the fork-choice algorithm. Mirror of Go's
/// `Params` struct.
#[derive(Debug, Clone)]
pub struct Params {
    /// Maximum distance — a distance at or above this value maps to
    /// ρ = 0. Set to `u64::MAX` by default.
    pub r_max: BigInt,
    /// Distance weight numerator.
    pub wr_numer: u64,
    /// Seniority weight numerator.
    pub wp_numer: u64,
    /// Common weight denominator.
    pub w_denom: u64,
    /// α numerator (exponential decay factor for older frames).
    pub al_numer: u64,
    /// α denominator.
    pub al_denom: u64,
    /// Blend window size — the bonus looks at the last `m` frames.
    pub blend_window: usize,
    /// β numerator (blend-bonus weight).
    pub beta_numer: u64,
    /// β denominator.
    pub beta_denom: u64,
    /// Tie margin in SCALE units. A new branch must beat the
    /// incumbent by strictly more than this to switch.
    pub epsilon: u64,
}

impl Params {
    /// Default parameters matching `DefaultForkChoiceParams` in Go.
    /// `r_max = u64::MAX`, distance/seniority weights 7:3/10,
    /// α = 9/10, blend window 5, β = 1/10, ε = 0.
    pub fn default_params() -> Self {
        Self {
            r_max: BigInt::from(u64::MAX),
            wr_numer: 7,
            wp_numer: 3,
            w_denom: 10,
            al_numer: 9,
            al_denom: 10,
            blend_window: 5,
            beta_numer: 1,
            beta_denom: 10,
            epsilon: 0,
        }
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::default_params()
    }
}

/// Fork-choice algorithm entry point. Mirror of Go's `ForkChoice`.
///
/// Returns the index of the branch this replica should extend. The
/// result is biased toward `prev_choice` (hysteresis): a new branch
/// must beat it by strictly more than `cfg.epsilon` to unseat it.
///
/// If `prev_choice` is out of range, it's treated as if no prior
/// choice existed — the first branch will be selected unless another
/// branch beats it.
pub fn fork_choice(branches: &[Branch], cfg: &Params, prev_choice: usize) -> usize {
    let mut best_idx = prev_choice;
    let mut best_score = BigInt::zero();
    if prev_choice < branches.len() {
        best_score = branch_score(&branches[prev_choice], cfg);
    }

    let epsilon_bi = BigInt::from(cfg.epsilon);
    for (i, br) in branches.iter().enumerate() {
        let score = branch_score(br, cfg);
        // A new branch must beat `best_score + epsilon` to unseat
        // the incumbent.
        if score > &best_score + &epsilon_bi {
            best_score = score;
            best_idx = i;
        }
    }
    best_idx
}

/// Compute the score of a single branch.
///
/// Score = blend_bonus × Σ_i α^{n-i} · frame_score(i) where the sum
/// is in the fixed-point `[0, SCALE]` space. Mirror of Go's
/// `branchScore`.
pub fn branch_score(br: &Branch, cfg: &Params) -> BigInt {
    if br.frames.is_empty() {
        return BigInt::zero();
    }

    // Step 1: exponentially-decayed raw score.
    let mut raw = BigInt::zero();
    let w_denom_bi = BigInt::from(cfg.w_denom);
    let wr_numer_bi = BigInt::from(cfg.wr_numer);
    let wp_numer_bi = BigInt::from(cfg.wp_numer);
    let al_numer_bi = BigInt::from(cfg.al_numer);
    let al_denom_bi = BigInt::from(cfg.al_denom);

    for frame in &br.frames {
        let rho = BigInt::from(rho_scaled(&frame.distance, &cfg.r_max));
        let pi = BigInt::from(clamp(frame.seniority, 0, SCALE));
        // frame_score = (wr·rho + wp·pi) / w_denom
        let frame_score = (&wr_numer_bi * &rho + &wp_numer_bi * &pi) / &w_denom_bi;
        // raw = (raw · al_numer / al_denom) + frame_score
        raw = (&raw * &al_numer_bi) / &al_denom_bi + frame_score;
    }

    // Step 2: blend bonus.
    let m = cfg.blend_window.min(br.frames.len());
    if m == 0 {
        return BigInt::zero();
    }

    // Count unique active provers in the last `m` frames.
    let start = br.frames.len() - m;
    let mut seen = std::collections::HashSet::new();
    for frame in &br.frames[start..] {
        if frame.seniority > 0 {
            seen.insert(frame.prover_address.clone());
        }
    }
    let unique = seen.len() as u64;

    // blend_scaled = unique · SCALE / m
    let scale_bi = BigInt::from(SCALE);
    let blend_scaled = (BigInt::from(unique) * &scale_bi) / BigInt::from(m as u64);
    // div_bonus = SCALE + (beta_numer · blend_scaled / beta_denom)
    let div_bonus = &scale_bi
        + (BigInt::from(cfg.beta_numer) * &blend_scaled) / BigInt::from(cfg.beta_denom);

    // Step 3: final = raw · div_bonus / SCALE
    (raw * div_bonus) / scale_bi
}

/// ρ(rank) = (r_max − rank) · SCALE / r_max, clamped to `[0, SCALE]`.
/// Closer-to-zero distance produces a value near SCALE; distance at
/// or above `r_max` produces 0.
pub fn rho_scaled(rank: &BigInt, r_max: &BigInt) -> u64 {
    // numerator = (r_max - rank) * SCALE
    let mut tmp = r_max - rank;
    tmp *= BigInt::from(SCALE);
    // quotient = numerator / r_max
    let result = tmp / r_max;
    if result.is_negative() {
        return 0;
    }
    let scale_bi = BigInt::from(SCALE);
    if result > scale_bi {
        return SCALE;
    }
    result.to_u64().unwrap_or(SCALE)
}

/// Clamp `x` to `[lo, hi]`.
fn clamp(x: u64, lo: u64, hi: u64) -> u64 {
    if x < lo {
        lo
    } else if x > hi {
        hi
    } else {
        x
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(distance: u64, seniority: u64, prover: &str) -> Frame {
        Frame {
            distance: BigInt::from(distance),
            seniority,
            prover_address: prover.as_bytes().to_vec(),
        }
    }

    fn branch(frames: Vec<Frame>) -> Branch {
        Branch { frames }
    }

    // =================================================================
    // rho_scaled
    // =================================================================

    #[test]
    fn rho_at_zero_distance_is_scale() {
        let r_max = BigInt::from(1000u64);
        assert_eq!(rho_scaled(&BigInt::zero(), &r_max), SCALE);
    }

    #[test]
    fn rho_at_r_max_is_zero() {
        let r_max = BigInt::from(1000u64);
        assert_eq!(rho_scaled(&r_max, &r_max), 0);
    }

    #[test]
    fn rho_at_half_r_max_is_half_scale() {
        let r_max = BigInt::from(1000u64);
        let half = BigInt::from(500u64);
        let rho = rho_scaled(&half, &r_max);
        // (1000 - 500) * SCALE / 1000 = SCALE / 2
        assert_eq!(rho, SCALE / 2);
    }

    #[test]
    fn rho_clamps_below_zero() {
        let r_max = BigInt::from(100u64);
        // rank > r_max → (r_max - rank) < 0 → rho = 0
        assert_eq!(rho_scaled(&BigInt::from(200u64), &r_max), 0);
    }

    // =================================================================
    // clamp
    // =================================================================

    #[test]
    fn clamp_respects_bounds() {
        assert_eq!(clamp(5, 0, 10), 5);
        assert_eq!(clamp(15, 0, 10), 10);
        assert_eq!(clamp(0, 1, 10), 1);
    }

    // =================================================================
    // branch_score
    // =================================================================

    #[test]
    fn empty_branch_score_is_zero() {
        let cfg = Params::default_params();
        let b = branch(vec![]);
        assert_eq!(branch_score(&b, &cfg), BigInt::zero());
    }

    #[test]
    fn single_frame_branch_has_positive_score() {
        let cfg = Params::default_params();
        let b = branch(vec![frame(0, SCALE, "alice")]);
        assert!(branch_score(&b, &cfg) > BigInt::zero());
    }

    #[test]
    fn branch_with_more_active_provers_beats_one_prover_branch() {
        // Two branches of equal length. One is extended by a single
        // prover; the other by several distinct provers. The blend
        // bonus rewards diversity, so the multi-prover branch should
        // win (all else equal).
        let cfg = Params::default_params();
        let monoculture = branch(vec![
            frame(0, SCALE, "alice"),
            frame(0, SCALE, "alice"),
            frame(0, SCALE, "alice"),
            frame(0, SCALE, "alice"),
            frame(0, SCALE, "alice"),
        ]);
        let diverse = branch(vec![
            frame(0, SCALE, "alice"),
            frame(0, SCALE, "bob"),
            frame(0, SCALE, "carol"),
            frame(0, SCALE, "dave"),
            frame(0, SCALE, "eve"),
        ]);
        let mono_score = branch_score(&monoculture, &cfg);
        let diverse_score = branch_score(&diverse, &cfg);
        assert!(
            diverse_score > mono_score,
            "diverse={} mono={}",
            diverse_score,
            mono_score
        );
    }

    #[test]
    fn zero_seniority_provers_dont_count_toward_blend() {
        // Two 5-frame branches, one with all-evicted provers (seniority=0)
        // and one with all-active. The active branch wins by the blend
        // bonus even though the raw frame scores are equal.
        let cfg = Params::default_params();
        let evicted = branch(vec![
            frame(0, 0, "alice"),
            frame(0, 0, "bob"),
            frame(0, 0, "carol"),
            frame(0, 0, "dave"),
            frame(0, 0, "eve"),
        ]);
        let active = branch(vec![
            frame(0, SCALE, "alice"),
            frame(0, SCALE, "bob"),
            frame(0, SCALE, "carol"),
            frame(0, SCALE, "dave"),
            frame(0, SCALE, "eve"),
        ]);
        assert!(branch_score(&active, &cfg) > branch_score(&evicted, &cfg));
    }

    #[test]
    fn closer_distance_beats_farther_distance() {
        let cfg = Params::default_params();
        let close = branch(vec![frame(0, SCALE, "alice")]);
        let far = branch(vec![frame(u64::MAX / 2, SCALE, "alice")]);
        assert!(branch_score(&close, &cfg) > branch_score(&far, &cfg));
    }

    // =================================================================
    // fork_choice top-level
    // =================================================================

    #[test]
    fn fork_choice_picks_best_score() {
        let cfg = Params::default_params();
        let branches = vec![
            // Branch 0: 1 frame, far distance.
            branch(vec![frame(u64::MAX / 2, SCALE, "a")]),
            // Branch 1: 1 frame, zero distance → best.
            branch(vec![frame(0, SCALE, "b")]),
        ];
        assert_eq!(fork_choice(&branches, &cfg, 0), 1);
    }

    #[test]
    fn fork_choice_sticks_with_prev_on_tie() {
        // Both branches identical — algorithm should stick with
        // prev_choice.
        let cfg = Params::default_params();
        let branches = vec![
            branch(vec![frame(0, SCALE, "a")]),
            branch(vec![frame(0, SCALE, "a")]),
        ];
        assert_eq!(fork_choice(&branches, &cfg, 0), 0);
        assert_eq!(fork_choice(&branches, &cfg, 1), 1);
    }

    #[test]
    fn fork_choice_respects_epsilon_hysteresis() {
        // New branch is strictly better, but not by more than ε.
        // Algorithm should stick with prev_choice.
        let mut cfg = Params::default_params();
        cfg.epsilon = SCALE; // huge tie-break tolerance → never switch
        let branches = vec![
            branch(vec![frame(u64::MAX / 2, SCALE, "a")]),
            branch(vec![frame(0, SCALE, "b")]),
        ];
        // Starting with prev_choice = 0, even though branch 1 has
        // better distance, the huge epsilon prevents the switch.
        assert_eq!(fork_choice(&branches, &cfg, 0), 0);
    }

    #[test]
    fn fork_choice_out_of_range_prev_falls_through() {
        let cfg = Params::default_params();
        let branches = vec![
            branch(vec![frame(0, SCALE, "a")]),
            branch(vec![frame(u64::MAX / 2, SCALE, "b")]),
        ];
        // prev_choice=999 is out of range; algorithm starts with
        // best_score=0 and picks whichever branch beats it.
        assert_eq!(fork_choice(&branches, &cfg, 999), 0);
    }

    #[test]
    fn fork_choice_empty_branches_returns_prev_choice() {
        let cfg = Params::default_params();
        let branches: Vec<Branch> = vec![];
        // No branches → no update → prev_choice returned.
        assert_eq!(fork_choice(&branches, &cfg, 42), 42);
    }

    // =================================================================
    // Parameter sanity
    // =================================================================

    #[test]
    fn default_params_match_go() {
        let p = Params::default_params();
        assert_eq!(p.r_max, BigInt::from(u64::MAX));
        assert_eq!(p.wr_numer, 7);
        assert_eq!(p.wp_numer, 3);
        assert_eq!(p.w_denom, 10);
        assert_eq!(p.al_numer, 9);
        assert_eq!(p.al_denom, 10);
        assert_eq!(p.blend_window, 5);
        assert_eq!(p.beta_numer, 1);
        assert_eq!(p.beta_denom, 10);
        assert_eq!(p.epsilon, 0);
    }

    // =================================================================
    // Exponential decay
    // =================================================================

    #[test]
    fn older_frames_contribute_less_than_newer() {
        // Two branches with identical per-frame scores; the decayed
        // sum should reward newer frames more. A 3-frame branch has
        // raw sum roughly (1 + 0.9 + 0.81) × f0 ≈ 2.71 × f0, while
        // a 1-frame branch has raw sum ≈ f0. So the 3-frame branch
        // beats the 1-frame branch.
        let cfg = Params::default_params();
        let long = branch(vec![
            frame(0, SCALE, "a"),
            frame(0, SCALE, "b"),
            frame(0, SCALE, "c"),
        ]);
        let short = branch(vec![frame(0, SCALE, "a")]);
        assert!(branch_score(&long, &cfg) > branch_score(&short, &cfg));
    }

    #[test]
    fn decay_keeps_branch_scores_bounded() {
        // Even an arbitrarily long branch of ideal frames has a
        // bounded score under exponential decay. The sum of
        // α^i · f0 converges; no panic or overflow should occur.
        let cfg = Params::default_params();
        let frames: Vec<Frame> = (0..100).map(|i| frame(0, SCALE, &format!("p-{}", i))).collect();
        let b = branch(frames);
        let score = branch_score(&b, &cfg);
        assert!(score > BigInt::zero());
        // Not strict, but verify it didn't blow up into something
        // absurd that would hint at a missing div step.
        assert!(score < BigInt::from(SCALE) * BigInt::from(SCALE));
    }
}
