//! The bound on an application shard frame's fee vote. A frame prices its
//! application writes at the `fee_multiplier_vote` its leader chose, so a
//! leader voting zero would let them commit without payment. From
//! [`fee_vote_bound_frame`] every node refuses a frame whose vote lies
//! outside [`MIN_FEE_MULTIPLIER_VOTE`]..=[`MAX_FEE_MULTIPLIER_VOTE`]: app
//! shard members when they vote and sync, and GLOBAL, which never executes
//! such a frame. Given its session's certificate, GLOBAL fences that session
//! at its executed tip instead (`global_intrinsic::handoff::fee_fence`), so a
//! quorum of older builds extending the frame cannot strand the members that
//! refused it. Here, not in the engine, so GLOBAL execution reads the same
//! process setting.

use quil_types::error::{QuilError, Result};

/// Lowest `fee_multiplier_vote` an app-shard frame may carry from
/// [`fee_vote_bound_frame`]: the default multiplier (100) lowered by the
/// largest traffic adjustment (10%), which `quil_engine::fees` checks at
/// compile time. No node records frame votes into the fee window, so every
/// leader computes its vote from the default and moves it at most that far:
/// an honest vote is 90 to 110. Recording votes would let the base drift, and
/// must revise these bounds first.
pub const MIN_FEE_MULTIPLIER_VOTE: u64 = 90;

/// Highest `fee_multiplier_vote` an app-shard frame may carry from
/// [`fee_vote_bound_frame`]; see [`MIN_FEE_MULTIPLIER_VOTE`].
pub const MAX_FEE_MULTIPLIER_VOTE: u64 = 110;

/// From this GLOBAL frame, members refuse an app-shard frame whose fee vote
/// lies outside [`MIN_FEE_MULTIPLIER_VOTE`]..=[`MAX_FEE_MULTIPLIER_VOTE`],
/// a leader keeps its own vote inside them, and GLOBAL never executes the
/// frame: certified, its header fences its session at the executed tip.
/// Validation, sync and GLOBAL judge a frame by its anchored GLOBAL frame; a
/// voter also by its own latest GLOBAL frame, so an older anchor does not
/// evade the bounds. A validation change for members: one on an older build
/// still accepts such a frame, and a quorum of them certifies it; GLOBAL
/// then fences the session rather than strand the others. Every archive
/// must run a build carrying the value before the frame, as GLOBAL state
/// differs from it on with such a frame, and most members of every
/// committee should, so that such frames stay rare.
/// Mainnet: the first frame of GLOBAL epoch 1,524;
/// `QUIL_FEE_VOTE_BOUND_FRAME` elsewhere, never by default.
pub const MAINNET_FEE_VOTE_BOUND_FRAME: Option<u64> = Some(1_097_280);

static FEE_VOTE_BOUND_FRAME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

#[cfg(any(test, feature = "testing-stubs"))]
thread_local! {
    static FEE_VOTE_BOUND_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

fn fee_vote_bound_frame_for(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_FEE_VOTE_BOUND_FRAME.unwrap_or(u64::MAX);
    }
    setting
        .and_then(|value| value.parse().ok())
        .unwrap_or(u64::MAX)
}

/// Fix this process's fee vote bound frame from its network, and return it.
/// Called at startup before any shard or GLOBAL engine runs; the first call
/// decides.
pub fn init_fee_vote_bound_frame(network: u8) -> u64 {
    *FEE_VOTE_BOUND_FRAME.get_or_init(|| {
        fee_vote_bound_frame_for(
            network,
            std::env::var("QUIL_FEE_VOTE_BOUND_FRAME").ok().as_deref(),
        )
    })
}

/// The frame fixed by [`init_fee_vote_bound_frame`]; the mainnet frame in a
/// process that never called it. `u64::MAX`: never.
pub fn fee_vote_bound_frame() -> u64 {
    #[cfg(any(test, feature = "testing-stubs"))]
    if let Some(frame) = FEE_VOTE_BOUND_OVERRIDE.with(|cell| cell.get()) {
        return frame;
    }
    FEE_VOTE_BOUND_FRAME
        .get()
        .copied()
        .unwrap_or_else(|| fee_vote_bound_frame_for(0, None))
}

/// Set the fee vote bound frame for the calling thread only (tests).
/// `Some(u64::MAX)` disables it; `None` restores the process setting.
#[cfg(any(test, feature = "testing-stubs"))]
pub fn set_fee_vote_bound_frame_for_thread(frame: Option<u64>) {
    FEE_VOTE_BOUND_OVERRIDE.with(|cell| cell.set(frame));
}

/// Whether frame votes are bounded at GLOBAL frame `global_frame`.
pub fn fee_vote_bounded_at(global_frame: u64) -> bool {
    let from = fee_vote_bound_frame();
    from != u64::MAX && global_frame >= from
}

/// Whether `vote` lies inside the bounds every leader computes.
pub fn fee_vote_in_bounds(vote: u64) -> bool {
    (MIN_FEE_MULTIPLIER_VOTE..=MAX_FEE_MULTIPLIER_VOTE).contains(&vote)
}

/// Whether a frame anchored at `global_frame` voting `vote` is out of bounds
/// there: members and sync refuse it, and GLOBAL, given its certificate,
/// fences its session instead of executing it
/// (`global_intrinsic::handoff::fee_fence`).
pub fn fee_vote_out_of_bounds_at(global_frame: u64, vote: u64) -> bool {
    fee_vote_bounded_at(global_frame) && !fee_vote_in_bounds(vote)
}

/// Refuse app-shard frame `frame_number`, anchored at `global_frame`, when
/// its `vote` is out of bounds there.
pub fn check_fee_vote(frame_number: u64, global_frame: u64, vote: u64) -> Result<()> {
    if fee_vote_out_of_bounds_at(global_frame, vote) {
        return Err(QuilError::InvalidArgument(format!(
            "app shard frame {frame_number}: fee multiplier vote {vote} outside \
             {MIN_FEE_MULTIPLIER_VOTE}..={MAX_FEE_MULTIPLIER_VOTE} (anchor {global_frame})"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mainnet takes the constant whatever the setting; another network the
    /// setting, else never. A process that never fixed its frame, as a test
    /// process, runs the mainnet frame: a vote out of bounds passes anchored
    /// one frame before it and is refused from it, at each edge.
    #[test]
    fn the_bound_frame_is_the_mainnet_constant_by_default() {
        const BOUND: u64 = 1_097_280;
        assert_eq!(BOUND % quil_types::consensus::EPOCH_LENGTH_FRAMES, 0);
        let mainnet = fee_vote_bound_frame_for(0, Some("5"));
        assert_eq!(mainnet, BOUND, "mainnet takes the constant");
        assert_eq!(fee_vote_bound_frame_for(1, Some("5")), 5);
        assert_eq!(fee_vote_bound_frame_for(1, None), u64::MAX);
        assert_eq!(fee_vote_bound_frame(), BOUND, "the process default");
        for vote in [0, 89, 111, u64::MAX] {
            assert!(check_fee_vote(7, BOUND - 1, vote).is_ok(), "vote {vote}");
            let refused = check_fee_vote(7, BOUND, vote).unwrap_err().to_string();
            assert!(refused.contains("fee multiplier vote"), "{refused}");
        }
        for vote in [90, 100, 110] {
            assert!(check_fee_vote(7, BOUND, vote).is_ok(), "vote {vote}");
        }
        set_fee_vote_bound_frame_for_thread(Some(u64::MAX));
        assert!(!fee_vote_bounded_at(u64::MAX), "never");
        set_fee_vote_bound_frame_for_thread(None);
        assert!(fee_vote_bounded_at(BOUND));
    }
}
