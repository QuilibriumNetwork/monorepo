//! In-place generation-zero migration, tip at every member's head: generation
//! 0's own hosts extend the registered legacy tip, drain and seal. See
//! `gen0_support`.
//!
//! One test per binary: the committee-handoff policy is process-global.

mod common;
mod gen0_support;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn generation_zero_extends_a_tip_at_every_members_head_and_hands_off() {
    gen0_support::migrate_in_place(gen0_support::Tip::AtEveryHead).await;
}
