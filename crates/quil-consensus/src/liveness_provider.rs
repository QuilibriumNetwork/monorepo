//! Liveness provider trait. Mirror of
//! `consensus/consensus_liveness.go::LivenessProvider`.
//!
//! The liveness provider announces that this node is alive ahead of
//! the next rank's proving window. The pacemaker consults the
//! liveness-announcement set to decide whether the expected leader is
//! still online — if an honest leader drops offline, another replica
//! can jump ahead and publish the next state without waiting for the
//! pacemaker timeout.
//!
//! Liveness is an **optimization**, not a correctness requirement:
//! consensus safety holds even if every replica reports `NoopLiveness`.
//! An application-specific impl is only needed when operators want
//! to reduce tail latency during leader failover.
//!
//! Mirror of Go's `LivenessProvider[StateT, PeerIDT, CollectedT]`.
//! The `CollectedT` type is the intermediate data a replica accumulates
//! between rounds (mutation operations, partial blocks, etc.) and
//! broadcasts alongside the liveness ping.

use crate::models::{State, Unique};
use quil_types::error::Result;

/// Trait surface for a liveness provider. Parameterized over the
/// application state `S`, the peer identity type `P`, and the
/// collected-data type `C`.
pub trait LivenessProvider<S: Unique, C: Send + Sync + 'static>: Send + Sync {
    /// Collect the mutation operations (or other app-specific
    /// intermediate state) ahead of the liveness announcement for
    /// `frame_number`, `rank`.
    ///
    /// Implementations typically batch pending mempool entries or
    /// grab a snapshot of an in-memory accumulator.
    fn collect(&self, frame_number: u64, rank: u64) -> Result<C>;

    /// Broadcast the liveness announcement. `prior` is the parent
    /// state this node is about to build on (if known); `collected`
    /// is the output of [`collect`]. Returns `Ok(())` when the
    /// announcement has been dispatched — implementations typically
    /// use fire-and-forget semantics and don't block on network
    /// acknowledgement.
    fn send_liveness(&self, prior: Option<&State<S>>, collected: C) -> Result<()>;
}

/// No-op liveness provider. Satisfies the trait with stub semantics:
/// `collect` returns `C::default()`; `send_liveness` is a no-op.
///
/// Useful for nodes that don't care about leader-failover latency
/// optimization — consensus safety is preserved regardless.
pub struct NoopLivenessProvider<S: Unique, C: Default + Send + Sync + 'static> {
    _marker: std::marker::PhantomData<(fn() -> S, fn() -> C)>,
}

impl<S: Unique, C: Default + Send + Sync + 'static> Default for NoopLivenessProvider<S, C> {
    fn default() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S: Unique, C: Default + Send + Sync + 'static> NoopLivenessProvider<S, C> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S: Unique, C: Default + Send + Sync + 'static> LivenessProvider<S, C>
    for NoopLivenessProvider<S, C>
{
    fn collect(&self, _frame_number: u64, _rank: u64) -> Result<C> {
        Ok(C::default())
    }

    fn send_liveness(&self, _prior: Option<&State<S>>, _collected: C) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Identity;

    #[derive(Debug, Clone)]
    struct AppState {
        id: Identity,
        rank: u64,
    }
    impl Unique for AppState {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &[] }
    }

    #[test]
    fn noop_liveness_provider_collect_returns_default() {
        let p: NoopLivenessProvider<AppState, Vec<u8>> = NoopLivenessProvider::new();
        let collected = p.collect(1, 5).unwrap();
        assert!(collected.is_empty());
    }

    #[test]
    fn noop_liveness_provider_send_is_noop() {
        let p: NoopLivenessProvider<AppState, Vec<u8>> = NoopLivenessProvider::new();
        let state = State {
            rank: 5,
            identifier: "s-5".into(),
            proposer_id: "leader".into(),
            parent_qc_identity: "parent".into(),
            parent_qc_rank: 4,
            parent_quorum_certificate: None,
            timestamp: 0,
            state: AppState { id: "s-5".into(), rank: 5 },
        };
        // None variant.
        p.send_liveness(None, vec![1, 2, 3]).unwrap();
        // Some variant.
        p.send_liveness(Some(&state), vec![4, 5, 6]).unwrap();
    }

    #[test]
    fn noop_is_send_and_sync() {
        // Verify the trait bounds let it cross thread boundaries.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopLivenessProvider<AppState, ()>>();
    }

    // Recording impl to verify a real adapter would compose cleanly.
    struct RecordingLiveness {
        collect_calls: std::sync::Mutex<Vec<(u64, u64)>>,
        send_calls: std::sync::Mutex<Vec<u64>>,
    }
    impl LivenessProvider<AppState, u64> for RecordingLiveness {
        fn collect(&self, frame_number: u64, rank: u64) -> Result<u64> {
            self.collect_calls
                .lock()
                .unwrap()
                .push((frame_number, rank));
            Ok(frame_number * 1000 + rank)
        }
        fn send_liveness(&self, _prior: Option<&State<AppState>>, collected: u64) -> Result<()> {
            self.send_calls.lock().unwrap().push(collected);
            Ok(())
        }
    }

    #[test]
    fn concrete_liveness_impl_round_trips_collected() {
        let p = RecordingLiveness {
            collect_calls: std::sync::Mutex::new(vec![]),
            send_calls: std::sync::Mutex::new(vec![]),
        };
        let collected = p.collect(3, 7).unwrap();
        assert_eq!(collected, 3007);
        p.send_liveness(None, collected).unwrap();
        assert_eq!(p.collect_calls.lock().unwrap().len(), 1);
        assert_eq!(p.send_calls.lock().unwrap().as_slice(), &[3007]);
    }
}
