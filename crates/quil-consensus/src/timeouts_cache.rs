//! Per-rank timeout dedup cache. Mirror of
//! `consensus/timeoutcollector/timeout_cache.go::TimeoutStatesCache`.
//!
//! Parallel to [`VotesCache`](crate::votes_cache::VotesCache), but for
//! timeout states. Stores the first timeout seen from each voter and
//! detects equivocation.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::models::{Identity, TimeoutState, Unique};
use quil_types::error::{QuilError, Result};

/// Equality check for two timeout states. Mirror of Go's
/// `TimeoutState.Equals`.
///
/// Two timeouts are "equal" when they share rank, the same latest-QC
/// (rank + identity), the same prior-TC rank (if any), and the same
/// vote identity + signature.
fn timeouts_equal<V: Unique>(a: &TimeoutState<V>, b: &TimeoutState<V>) -> bool {
    if a.rank != b.rank {
        return false;
    }
    if a.latest_quorum_certificate.rank() != b.latest_quorum_certificate.rank()
        || a.latest_quorum_certificate.identity() != b.latest_quorum_certificate.identity()
    {
        return false;
    }
    match (
        a.prior_rank_timeout_certificate.as_ref(),
        b.prior_rank_timeout_certificate.as_ref(),
    ) {
        (None, None) => {}
        (Some(ap), Some(bp)) if ap.rank() == bp.rank() => {}
        _ => return false,
    }
    a.vote.identity() == b.vote.identity() && a.vote.signature() == b.vote.signature()
}

/// Per-rank cache of timeout states, concurrency-safe.
pub struct TimeoutStatesCache<V: Unique> {
    rank: u64,
    /// `signer_id → first timeout seen`.
    inner: RwLock<HashMap<Identity, TimeoutState<V>>>,
}

impl<V: Unique> TimeoutStatesCache<V> {
    pub fn new(rank: u64) -> Self {
        Self {
            rank,
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn rank(&self) -> u64 {
        self.rank
    }

    /// Add a timeout state. Error variants:
    /// - `IncompatibleRank` — wrong rank
    /// - `DoubleTimeout` — replica equivocation (Byzantine evidence)
    /// - `RepeatedTimeout` — exact duplicate (benign)
    pub fn add_timeout(&self, timeout: TimeoutState<V>) -> Result<()> {
        if timeout.rank != self.rank {
            return Err(QuilError::IncompatibleRank(format!(
                "timeout rank {} != cache rank {}",
                timeout.rank, self.rank
            )));
        }
        let voter = timeout.vote.identity().clone();
        let mut guard = self.inner.write().unwrap();
        if let Some(first) = guard.get(&voter) {
            if timeouts_equal(first, &timeout) {
                return Err(QuilError::RepeatedTimeout(format!(
                    "duplicate timeout from {} at rank {}",
                    hex::encode(&voter), self.rank
                )));
            }
            return Err(QuilError::DoubleTimeout(format!(
                "timeout equivocation by replica {} at rank {}",
                hex::encode(&voter), self.rank
            )));
        }
        guard.insert(voter, timeout);
        Ok(())
    }

    /// Retrieve the stored timeout state for a signer.
    pub fn get_timeout(&self, signer_id: &Identity) -> Option<TimeoutState<V>> {
        self.inner.read().unwrap().get(signer_id).cloned()
    }

    /// Count of cached timeout states.
    pub fn size(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// All cached timeouts. Ordering is nondeterministic (matches Go
    /// since the Go version also iterates a map).
    pub fn all(&self) -> Vec<TimeoutState<V>> {
        self.inner.read().unwrap().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AggregatedSignature, QuorumCertificate};
    use std::sync::Arc;

    #[derive(Debug, Clone)]
    struct V {
        id: Identity,
        rank: u64,
        sig: Vec<u8>,
    }
    impl Unique for V {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &self.sig }
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

    fn make_to(voter: &str, rank: u64, qc_rank: u64, sig: &[u8]) -> TimeoutState<V> {
        TimeoutState {
            rank,
            latest_quorum_certificate: Arc::new(StubQc {
                rank: qc_rank,
                id: format!("qc-{}", qc_rank).into_bytes(),
            }),
            prior_rank_timeout_certificate: None,
            vote: V {
                id: voter.into(),
                rank,
                sig: sig.to_vec(),
            },
            timeout_tick: 0,
        }
    }

    #[test]
    fn add_new_timeout() {
        let c: TimeoutStatesCache<V> = TimeoutStatesCache::new(5);
        c.add_timeout(make_to("alice", 5, 4, b"sig1")).unwrap();
        assert_eq!(c.size(), 1);
    }

    #[test]
    fn wrong_rank_rejected() {
        let c: TimeoutStatesCache<V> = TimeoutStatesCache::new(5);
        let err = c.add_timeout(make_to("alice", 7, 6, b"sig1")).unwrap_err();
        assert!(err.is_incompatible_rank());
    }

    #[test]
    fn exact_duplicate_is_repeated() {
        let c: TimeoutStatesCache<V> = TimeoutStatesCache::new(5);
        c.add_timeout(make_to("alice", 5, 4, b"sig1")).unwrap();
        let err = c.add_timeout(make_to("alice", 5, 4, b"sig1")).unwrap_err();
        assert!(err.is_repeated_timeout());
    }

    #[test]
    fn different_signature_is_double_timeout() {
        let c: TimeoutStatesCache<V> = TimeoutStatesCache::new(5);
        c.add_timeout(make_to("alice", 5, 4, b"sig1")).unwrap();
        let err = c.add_timeout(make_to("alice", 5, 4, b"sig2")).unwrap_err();
        assert!(err.is_double_timeout());
    }

    #[test]
    fn different_qc_rank_is_double_timeout() {
        let c: TimeoutStatesCache<V> = TimeoutStatesCache::new(5);
        c.add_timeout(make_to("alice", 5, 4, b"sig1")).unwrap();
        // Same voter, same signature, but different QC rank → equivocation.
        let err = c.add_timeout(make_to("alice", 5, 3, b"sig1")).unwrap_err();
        assert!(err.is_double_timeout());
    }

    #[test]
    fn get_and_all_return_stored_timeouts() {
        let c: TimeoutStatesCache<V> = TimeoutStatesCache::new(5);
        c.add_timeout(make_to("alice", 5, 4, b"s1")).unwrap();
        c.add_timeout(make_to("bob", 5, 4, b"s2")).unwrap();
        assert_eq!(c.size(), 2);
        assert!(c.get_timeout(&b"alice".to_vec()).is_some());
        assert_eq!(c.all().len(), 2);
    }
}
