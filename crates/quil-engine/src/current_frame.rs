//! Single source of truth for "what frame is this node on right now."
//!
//! Before this module, the answer was computed independently at five+
//! sites with subtly different rules:
//!
//! - `LocalShardInfoProvider::get_shard_info` (server-side RPC) read
//!   `registry.current_frame()`, falling back to a clock-store load,
//!   falling back to `last_received_frame`. Each iteration of the
//!   resolution rule introduced a new bug.
//! - `NodeRpcServer::get_node_info` re-implemented the same idiom
//!   with slightly different semantics.
//! - `prover_registry::current_frame()` only advanced when the
//!   materializer called `process_state_transition` — stale on
//!   observer nodes.
//! - The frame-receive sites in `main.rs` used a mix of plain `store`
//!   (which could regress) and `fetch_max` (which can't).
//!
//! `CurrentFrame` collapses all of these into one shared atomic
//! triple. Every site that needs "the current frame" reads
//! `current_frame.effective()`. Every site that observes a frame
//! advancing calls one of `observe`, `materialize`, or `verify`
//! depending on the role.
//!
//! The three counters are monotonic (`fetch_max` only), so a stale
//! or bogus frame can never regress the value. Reads are
//! `Ordering::Relaxed` because the value is advisory — slightly
//! stale reads are tolerated by every consumer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Three monotonic frame counters representing different stages of
/// the receive→materialize→verify pipeline. Every consumer reads
/// the one appropriate to its concern; most should use
/// `effective()`.
#[derive(Debug, Default)]
pub struct CurrentFrame {
    /// Latest frame observed via ANY source: BlossomSub receive,
    /// archive poller, clock-store load at startup. Updated by
    /// `observe()`. Always >= `materialized` and `verified`.
    observed: AtomicU64,
    /// Latest frame whose state was successfully materialized
    /// (executed through the message pipeline + state-transition
    /// applied). Lags `observed` by validation/replay work.
    /// Updated by `materialize()`.
    materialized: AtomicU64,
    /// Latest frame whose prover-tree commitment was verified
    /// against an archive snapshot. The gate the lifecycle's
    /// `tree_synced` reads. Updated by `verify()`.
    verified: AtomicU64,
}

impl CurrentFrame {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record that a frame was observed (any source). Idempotent
    /// and monotonic — passing a smaller value than the current
    /// observed frame is a no-op. Safe to call from any thread.
    pub fn observe(&self, frame_number: u64) {
        if frame_number == 0 {
            // 0 is a sentinel for "no frame" / cold start.
            return;
        }
        self.observed.fetch_max(frame_number, Ordering::Relaxed);
    }

    /// Record that a frame's state has been materialized. Implies
    /// `observe(frame_number)` — the materializer needed to have
    /// the frame first.
    pub fn materialize(&self, frame_number: u64) {
        if frame_number == 0 {
            return;
        }
        self.observed.fetch_max(frame_number, Ordering::Relaxed);
        self.materialized.fetch_max(frame_number, Ordering::Relaxed);
    }

    /// Record that a frame's prover-tree root commitment has been
    /// successfully verified against an archive snapshot. Implies
    /// `observe(frame_number)`.
    pub fn verify(&self, frame_number: u64) {
        if frame_number == 0 {
            return;
        }
        self.observed.fetch_max(frame_number, Ordering::Relaxed);
        self.verified.fetch_max(frame_number, Ordering::Relaxed);
    }

    /// The freshest frame this node has any evidence of.
    /// Returns 0 only when no frame has been observed yet.
    /// **This is what most downstream consumers should call** —
    /// expiry checks, RPC `frame_number` fields, halt-risk
    /// classification, TUI displays.
    pub fn effective(&self) -> u64 {
        self.observed.load(Ordering::Relaxed)
    }

    /// Latest materialized frame. Use for state-machine
    /// transitions and per-frame side-effects (registry updates,
    /// alt-shard commits) that should only fire post-materialize.
    pub fn materialized(&self) -> u64 {
        self.materialized.load(Ordering::Relaxed)
    }

    /// Latest verified frame. Use for lifecycle propose-gating —
    /// `tree_synced` requires this to be at or past the frame the
    /// caller wants to act on.
    pub fn verified(&self) -> u64 {
        self.verified.load(Ordering::Relaxed)
    }

    /// True iff at least one frame has been observed.
    pub fn is_ready(&self) -> bool {
        self.effective() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_current_frame_reads_zero() {
        let cf = CurrentFrame::new();
        assert_eq!(cf.effective(), 0);
        assert_eq!(cf.materialized(), 0);
        assert_eq!(cf.verified(), 0);
        assert!(!cf.is_ready());
    }

    #[test]
    fn observe_is_monotonic() {
        let cf = CurrentFrame::new();
        cf.observe(100);
        assert_eq!(cf.effective(), 100);
        cf.observe(50); // older — no regression
        assert_eq!(cf.effective(), 100);
        cf.observe(200);
        assert_eq!(cf.effective(), 200);
    }

    #[test]
    fn observe_ignores_zero() {
        let cf = CurrentFrame::new();
        cf.observe(100);
        cf.observe(0); // bogus
        assert_eq!(cf.effective(), 100);
    }

    #[test]
    fn materialize_and_verify_imply_observe() {
        let cf = CurrentFrame::new();
        cf.materialize(100);
        assert_eq!(cf.effective(), 100);
        assert_eq!(cf.materialized(), 100);
        cf.verify(150);
        assert_eq!(cf.effective(), 150);
        assert_eq!(cf.verified(), 150);
        // Materialized stayed at 100 (verify doesn't imply
        // materialize).
        assert_eq!(cf.materialized(), 100);
    }

    #[test]
    fn each_counter_is_independently_monotonic() {
        let cf = CurrentFrame::new();
        cf.observe(200);
        cf.materialize(100);
        cf.verify(50);
        assert_eq!(cf.effective(), 200);
        assert_eq!(cf.materialized(), 100);
        assert_eq!(cf.verified(), 50);
        // Try to regress each.
        cf.observe(150);
        cf.materialize(50);
        cf.verify(25);
        assert_eq!(cf.effective(), 200);
        assert_eq!(cf.materialized(), 100);
        assert_eq!(cf.verified(), 50);
    }
}
