//! "Newest by rank" trackers. Mirror of `consensus/tracker/tracker.go`.
//!
//! These are tiny concurrency-safe helpers the pacemaker and event loop
//! use to collapse a stream of QCs / TCs / states / partial TCs into "the
//! single newest one we've seen". Go uses an atomic pointer + CAS loop;
//! in Rust we use `RwLock<Option<Arc<T>>>` which gives equivalent
//! semantics without the `unsafe` pointer gymnastics.
//!
//! All four trackers share the same shape:
//! - `new()` constructs an empty tracker.
//! - `track(x)` installs `x` as the newest IFF its rank is strictly
//!   greater than the currently-stored value's rank. Returns `true` if
//!   the install happened.
//! - The getter returns `Option<Arc<T>>`.

use std::sync::{Arc, RwLock};

use crate::models::{QuorumCertificate, State, TimeoutCertificate, Unique};
use crate::timeout_aggregator::PartialTimeoutCertificateCreated;

/// Tracks the newest [`QuorumCertificate`] observed (by rank).
pub struct NewestQcTracker {
    inner: RwLock<Option<Arc<dyn QuorumCertificate>>>,
}

impl Default for NewestQcTracker {
    fn default() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }
}

impl NewestQcTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install `qc` iff its rank is strictly greater than the currently
    /// stored QC's rank. Returns `true` if the install happened.
    pub fn track(&self, qc: Arc<dyn QuorumCertificate>) -> bool {
        let mut guard = self.inner.write().unwrap();
        if let Some(existing) = guard.as_ref() {
            if existing.rank() >= qc.rank() {
                return false;
            }
        }
        *guard = Some(qc);
        true
    }

    /// Retrieve the newest QC tracked, if any.
    pub fn newest_qc(&self) -> Option<Arc<dyn QuorumCertificate>> {
        self.inner.read().unwrap().as_ref().map(Arc::clone)
    }
}

/// Tracks the newest [`TimeoutCertificate`] observed (by rank).
pub struct NewestTcTracker {
    inner: RwLock<Option<Arc<dyn TimeoutCertificate>>>,
}

impl Default for NewestTcTracker {
    fn default() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }
}

impl NewestTcTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn track(&self, tc: Arc<dyn TimeoutCertificate>) -> bool {
        let mut guard = self.inner.write().unwrap();
        if let Some(existing) = guard.as_ref() {
            if existing.rank() >= tc.rank() {
                return false;
            }
        }
        *guard = Some(tc);
        true
    }

    pub fn newest_tc(&self) -> Option<Arc<dyn TimeoutCertificate>> {
        self.inner.read().unwrap().as_ref().map(Arc::clone)
    }
}

/// Tracks the newest application-state [`State<S>`] observed (by rank).
pub struct NewestStateTracker<S: Unique> {
    inner: RwLock<Option<Arc<State<S>>>>,
}

impl<S: Unique> Default for NewestStateTracker<S> {
    fn default() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }
}

impl<S: Unique> NewestStateTracker<S> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn track(&self, state: Arc<State<S>>) -> bool {
        let mut guard = self.inner.write().unwrap();
        if let Some(existing) = guard.as_ref() {
            if existing.rank >= state.rank {
                return false;
            }
        }
        *guard = Some(state);
        true
    }

    pub fn newest_state(&self) -> Option<Arc<State<S>>> {
        self.inner.read().unwrap().as_ref().map(Arc::clone)
    }
}

/// Tracks the newest "partial TC" event (>1/3 but <2/3 weight). Used by
/// the event loop to rate-limit timeout rebroadcasts.
pub struct NewestPartialTimeoutCertificateTracker {
    inner: RwLock<Option<PartialTimeoutCertificateCreated>>,
}

impl Default for NewestPartialTimeoutCertificateTracker {
    fn default() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }
}

impl NewestPartialTimeoutCertificateTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn track(&self, partial: PartialTimeoutCertificateCreated) -> bool {
        let mut guard = self.inner.write().unwrap();
        if let Some(existing) = guard.as_ref() {
            if existing.rank >= partial.rank {
                return false;
            }
        }
        *guard = Some(partial);
        true
    }

    pub fn newest_partial(&self) -> Option<PartialTimeoutCertificateCreated> {
        self.inner.read().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AggregatedSignature, Identity};

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

    #[derive(Debug)]
    struct StubAgg;
    impl AggregatedSignature for StubAgg {
        fn signature(&self) -> &[u8] { &[] }
        fn public_key(&self) -> &[u8] { &[] }
        fn bitmask(&self) -> &[u8] { &[] }
    }

    #[derive(Debug)]
    struct StubQc { rank: u64, id: Identity }
    impl QuorumCertificate for StubQc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn frame_number(&self) -> u64 { 0 }
        fn identity(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, o: &dyn QuorumCertificate) -> bool {
            self.rank == o.rank() && self.id == *o.identity()
        }
    }

    #[derive(Debug)]
    struct StubTc { rank: u64, latest_qc: StubQc }
    impl TimeoutCertificate for StubTc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn latest_ranks(&self) -> &[u64] { &[] }
        fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { &self.latest_qc }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, o: &dyn TimeoutCertificate) -> bool {
            self.rank == o.rank()
        }
    }

    fn qc(rank: u64, id: &str) -> Arc<dyn QuorumCertificate> {
        Arc::new(StubQc { rank, id: id.into() })
    }
    fn tc(rank: u64, qc_rank: u64) -> Arc<dyn TimeoutCertificate> {
        Arc::new(StubTc {
            rank,
            latest_qc: StubQc { rank: qc_rank, id: format!("qc-{}", qc_rank).into_bytes() },
        })
    }

    #[test]
    fn newest_qc_installs_higher_rank() {
        let t = NewestQcTracker::new();
        assert!(t.track(qc(5, "a")));
        assert_eq!(t.newest_qc().unwrap().rank(), 5);
        assert!(t.track(qc(7, "b")));
        assert_eq!(t.newest_qc().unwrap().rank(), 7);
    }

    #[test]
    fn newest_qc_rejects_lower_or_equal() {
        let t = NewestQcTracker::new();
        assert!(t.track(qc(10, "a")));
        assert!(!t.track(qc(10, "b"))); // equal
        assert!(!t.track(qc(5, "c")));  // lower
        assert_eq!(t.newest_qc().unwrap().rank(), 10);
    }

    #[test]
    fn newest_qc_empty_returns_none() {
        let t = NewestQcTracker::new();
        assert!(t.newest_qc().is_none());
    }

    #[test]
    fn newest_tc_works() {
        let t = NewestTcTracker::new();
        assert!(t.track(tc(5, 4)));
        assert!(!t.track(tc(5, 4)));
        assert!(t.track(tc(6, 5)));
        assert_eq!(t.newest_tc().unwrap().rank(), 6);
    }

    #[test]
    fn newest_state_works() {
        let t: NewestStateTracker<AppState> = NewestStateTracker::new();
        let s1 = Arc::new(crate::models::State {
            rank: 3,
            identifier: "s1".into(),
            proposer_id: "p".into(),
            parent_qc_identity: "p".into(),
            parent_qc_rank: 2,
            parent_quorum_certificate: None,
            timestamp: 0,
            state: AppState { id: "s1".into(), rank: 3 },
        });
        let s2 = Arc::new(crate::models::State {
            rank: 5,
            identifier: "s2".into(),
            proposer_id: "p".into(),
            parent_qc_identity: "p".into(),
            parent_qc_rank: 4,
            parent_quorum_certificate: None,
            timestamp: 0,
            state: AppState { id: "s2".into(), rank: 5 },
        });
        assert!(t.track(s1));
        assert!(t.track(s2));
        assert_eq!(t.newest_state().unwrap().rank, 5);
    }

    #[test]
    fn newest_partial_tc_works() {
        let t = NewestPartialTimeoutCertificateTracker::new();
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 4,
            id: "qc-4".into(),
        });
        assert!(t.track(PartialTimeoutCertificateCreated {
            rank: 5,
            newest_quorum_certificate: Arc::clone(&qc),
            prior_rank_timeout_certificate: None,
        }));
        assert!(!t.track(PartialTimeoutCertificateCreated {
            rank: 5,
            newest_quorum_certificate: Arc::clone(&qc),
            prior_rank_timeout_certificate: None,
        }));
        let qc8: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 7,
            id: "qc-7".into(),
        });
        assert!(t.track(PartialTimeoutCertificateCreated {
            rank: 8,
            newest_quorum_certificate: qc8,
            prior_rank_timeout_certificate: None,
        }));
        assert_eq!(t.newest_partial().unwrap().rank, 8);
    }
}
