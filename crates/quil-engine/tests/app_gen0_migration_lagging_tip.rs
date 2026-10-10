//! In-place generation-zero migration, tip behind the members' heads: frames
//! the legacy instance finalized past the tip become generation-0 frames, and
//! the instance seals once it restarts under generation 0. See `gen0_support`.
//!
//! One test per binary: the committee-handoff policy is process-global.

mod common;
mod gen0_support;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn frames_past_a_lagging_legacy_tip_become_generation_zero_frames() {
    gen0_support::migrate_in_place(gen0_support::Tip::Lagging).await;
}
