//! Timeout aggregation. Mirror of `consensus/timeoutaggregator/`.
//!
//! Like `vote_aggregator`, the Go timeout aggregator sits on top of Go's
//! lifecycle / worker machinery. For the initial Rust port we keep the
//! rank-indexed collector registry + a synchronous façade; the async
//! dispatch layer moves into the event-loop crate.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::models::{TimeoutState, Unique};
use quil_types::error::{QuilError, Result};

/// Collects timeout states for a specific rank and aggregates them into a
/// TC. Mirror of Go's `TimeoutCollector[VoteT]`.
pub trait TimeoutCollector<V: Unique>: Send + Sync {
    /// Add a timeout state to the collector.
    fn add_timeout(&self, timeout: TimeoutState<V>) -> Result<()>;

    /// Rank this collector was created for.
    fn rank(&self) -> u64;
}

/// Factory that creates a timeout collector for a given rank.
pub type TimeoutCollectorFactory<V> =
    Arc<dyn Fn(u64) -> Result<Arc<dyn TimeoutCollector<V>>> + Send + Sync>;

/// Rank-indexed registry of timeout collectors. Mirror of Go's
/// `TimeoutCollectors`.
pub struct TimeoutCollectors<V: Unique> {
    inner: RwLock<TimeoutCollectorsInner<V>>,
    factory: TimeoutCollectorFactory<V>,
}

struct TimeoutCollectorsInner<V: Unique> {
    lowest_retained_rank: u64,
    newest_rank_cached_collector: u64,
    collectors: HashMap<u64, Arc<dyn TimeoutCollector<V>>>,
}

impl<V: Unique> TimeoutCollectors<V> {
    pub fn new(lowest_retained_rank: u64, factory: TimeoutCollectorFactory<V>) -> Self {
        Self {
            inner: RwLock::new(TimeoutCollectorsInner {
                lowest_retained_rank,
                newest_rank_cached_collector: lowest_retained_rank,
                collectors: HashMap::new(),
            }),
            factory,
        }
    }

    /// Retrieve or create the collector for `rank`. See Go's
    /// `GetOrCreateCollector` for semantics.
    /// - `Ok((collector, created))`
    /// - `Err(QuilError::NotFound)` if `rank` is below the prune threshold
    pub fn get_or_create(&self, rank: u64) -> Result<(Arc<dyn TimeoutCollector<V>>, bool)> {
        {
            let guard = self.inner.read().unwrap();
            if rank < guard.lowest_retained_rank {
                return Err(QuilError::NotFound(format!(
                    "cannot retrieve collector for pruned rank {} (lowest retained rank {})",
                    rank, guard.lowest_retained_rank
                )));
            }
            // Mirror VoteCollectors::MAX_RANK_LOOKAHEAD: reject ranks far
            // above the prune cursor so a peer can't flood our map with
            // attacker-set future ranks (e.g., u64::MAX).
            if rank > guard.lowest_retained_rank.saturating_add(
                crate::vote_aggregator::MAX_RANK_LOOKAHEAD,
            ) {
                return Err(QuilError::NotFound(format!(
                    "rank {} exceeds lookahead {} above lowest retained rank {}",
                    rank,
                    crate::vote_aggregator::MAX_RANK_LOOKAHEAD,
                    guard.lowest_retained_rank
                )));
            }
            if let Some(clr) = guard.collectors.get(&rank) {
                return Ok((Arc::clone(clr), false));
            }
        }

        let collector = (self.factory)(rank).map_err(|e| {
            QuilError::Consensus(format!(
                "could not create timeout collector for rank {}: {}",
                rank, e
            ))
        })?;

        let mut guard = self.inner.write().unwrap();
        if rank < guard.lowest_retained_rank {
            return Err(QuilError::NotFound(format!(
                "cannot retrieve collector for pruned rank {} (lowest retained rank {})",
                rank, guard.lowest_retained_rank
            )));
        }
        if rank > guard.lowest_retained_rank.saturating_add(
            crate::vote_aggregator::MAX_RANK_LOOKAHEAD,
        ) {
            return Err(QuilError::NotFound(format!(
                "rank {} exceeds lookahead {} above lowest retained rank {}",
                rank,
                crate::vote_aggregator::MAX_RANK_LOOKAHEAD,
                guard.lowest_retained_rank
            )));
        }
        if let Some(clr) = guard.collectors.get(&rank) {
            return Ok((Arc::clone(clr), false));
        }
        guard.collectors.insert(rank, Arc::clone(&collector));
        if guard.newest_rank_cached_collector < rank {
            guard.newest_rank_cached_collector = rank;
        }
        Ok((collector, true))
    }

    /// Monotonic prune. Same optimization as `VoteCollectors::prune_up_to_rank`:
    /// iterate over the smaller of the collector set or the rank range.
    pub fn prune_up_to_rank(&self, new_lowest: u64) {
        let mut guard = self.inner.write().unwrap();
        if guard.lowest_retained_rank >= new_lowest {
            return;
        }
        if guard.collectors.is_empty() {
            guard.lowest_retained_rank = new_lowest;
            return;
        }
        let range_span = new_lowest - guard.lowest_retained_rank;
        if (guard.collectors.len() as u64) < range_span {
            guard.collectors.retain(|&r, _| r >= new_lowest);
        } else {
            for w in guard.lowest_retained_rank..new_lowest {
                guard.collectors.remove(&w);
            }
        }
        guard.lowest_retained_rank = new_lowest;
    }

    pub fn lowest_retained_rank(&self) -> u64 {
        self.inner.read().unwrap().lowest_retained_rank
    }

    pub fn newest_cached_rank(&self) -> u64 {
        self.inner.read().unwrap().newest_rank_cached_collector
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().collectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().collectors.is_empty()
    }
}

/// Synchronous façade for Go's `TimeoutAggregator`.
pub struct TimeoutAggregator<V: Unique> {
    collectors: Arc<TimeoutCollectors<V>>,
    lowest_retained_rank: Mutex<u64>,
}

impl<V: Unique> TimeoutAggregator<V> {
    pub fn new(
        lowest_retained_rank: u64,
        collectors: Arc<TimeoutCollectors<V>>,
    ) -> Self {
        Self {
            collectors,
            lowest_retained_rank: Mutex::new(lowest_retained_rank),
        }
    }

    /// Inline version of Go's `processQueuedTimeout`. Silently drops stale
    /// timeouts (below the current prune cursor) and "unknown-rank"
    /// factory failures, matching Go.
    pub fn add_timeout(&self, timeout: TimeoutState<V>) -> Result<()> {
        if timeout.rank < *self.lowest_retained_rank.lock().unwrap() {
            return Ok(());
        }
        match self.collectors.get_or_create(timeout.rank) {
            Ok((collector, _created)) => collector.add_timeout(timeout),
            Err(e) if matches!(e, QuilError::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Monotonic prune cursor update. Unlike `VoteAggregator`, Go's
    /// `TimeoutAggregator.PruneUpToRank` delegates *unconditionally* to
    /// the collectors (the collectors themselves enforce the monotonic
    /// check). We do the same.
    pub fn prune_up_to_rank(&self, new_lowest: u64) {
        {
            let mut cursor = self.lowest_retained_rank.lock().unwrap();
            if new_lowest > *cursor {
                *cursor = new_lowest;
            }
        }
        self.collectors.prune_up_to_rank(new_lowest);
    }

    /// Rank-change hook. Mirror of Go's `OnRankChange` — the aggregator
    /// advances its prune cursor to match the new rank. This is invoked
    /// by the event loop when the pacemaker advances.
    pub fn on_rank_change(&self, new_rank: u64) {
        let mut cursor = self.lowest_retained_rank.lock().unwrap();
        if new_rank > *cursor {
            *cursor = new_rank;
            // Drop the mutex before calling into collectors to avoid
            // potential reentrancy issues.
            drop(cursor);
            self.collectors.prune_up_to_rank(new_rank);
        }
    }

    pub fn lowest_retained_rank(&self) -> u64 {
        *self.lowest_retained_rank.lock().unwrap()
    }
}

/// Notification for a partial TC (>1/3 but <2/3 weight reached). This
/// triggers re-broadcast of the node's own timeout to help the network
/// converge faster. Mirror of Go's
/// `consensus.PartialTimeoutCertificateCreated`.
///
/// Carries the newest QC observed during timeout collection and
/// optionally the prior-rank TC contributed by one of the signers.
/// The event handler feeds both into the pacemaker, which may advance
/// the current rank as a side effect.
#[derive(Debug, Clone)]
pub struct PartialTimeoutCertificateCreated {
    pub rank: u64,
    pub newest_quorum_certificate: Arc<dyn crate::models::QuorumCertificate>,
    pub prior_rank_timeout_certificate: Option<Arc<dyn crate::models::TimeoutCertificate>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AggregatedSignature, Identity, QuorumCertificate};
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ---------- test Unique ----------
    #[derive(Debug, Clone)]
    struct V {
        id: Identity,
        src: Identity,
        rank: u64,
    }
    impl Unique for V {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.src }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &[] }
    }

    // ---------- QC stub (needed to construct TimeoutState) ----------
    #[derive(Debug)]
    struct StubAgg;
    impl AggregatedSignature for StubAgg {
        fn signature(&self) -> &[u8] { &[] }
        fn public_key(&self) -> &[u8] { &[] }
        fn bitmask(&self) -> &[u8] { &[] }
    }

    #[derive(Debug)]
    struct StubQc {
        rank: u64,
        id: Identity,
    }
    impl QuorumCertificate for StubQc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn frame_number(&self) -> u64 { 0 }
        fn identity(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, other: &dyn QuorumCertificate) -> bool {
            self.rank == other.rank() && self.id == *other.identity()
        }
    }

    fn make_timeout(rank: u64) -> TimeoutState<V> {
        TimeoutState {
            rank,
            latest_quorum_certificate: Arc::new(StubQc {
                rank: rank.saturating_sub(1),
                id: format!("qc-{}", rank - 1).into_bytes(),
            }),
            prior_rank_timeout_certificate: None,
            vote: V {
                id: format!("to-{}", rank).into_bytes(),
                src: b"self".to_vec(),
                rank,
            },
            timeout_tick: 0,
        }
    }

    // ---------- stub collector ----------
    struct StubCollector {
        rank: u64,
        added: Mutex<usize>,
    }
    impl TimeoutCollector<V> for StubCollector {
        fn add_timeout(&self, _t: TimeoutState<V>) -> Result<()> {
            *self.added.lock().unwrap() += 1;
            Ok(())
        }
        fn rank(&self) -> u64 { self.rank }
    }

    fn stub_factory() -> (TimeoutCollectorFactory<V>, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&count);
        let f: TimeoutCollectorFactory<V> = Arc::new(move |rank| {
            c2.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(StubCollector {
                rank,
                added: Mutex::new(0),
            }) as Arc<dyn TimeoutCollector<V>>)
        });
        (f, count)
    }

    #[test]
    fn timeout_collectors_lazy_create_reuse() {
        let (f, count) = stub_factory();
        let c = TimeoutCollectors::<V>::new(0, f);
        c.get_or_create(5).unwrap();
        c.get_or_create(5).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn timeout_collectors_track_newest_rank() {
        let (f, _) = stub_factory();
        let c = TimeoutCollectors::<V>::new(0, f);
        c.get_or_create(3).unwrap();
        c.get_or_create(8).unwrap();
        c.get_or_create(5).unwrap();
        assert_eq!(c.newest_cached_rank(), 8);
    }

    #[test]
    fn timeout_collectors_reject_pruned() {
        let (f, _) = stub_factory();
        let c = TimeoutCollectors::<V>::new(10, f);
        match c.get_or_create(5) {
            Err(QuilError::NotFound(_)) => {}
            r => panic!("expected NotFound, got {:?}", r.is_ok()),
        }
    }

    #[test]
    fn timeout_collectors_prune_removes_older() {
        let (f, _) = stub_factory();
        let c = TimeoutCollectors::<V>::new(0, f);
        for r in 1..=5 {
            c.get_or_create(r).unwrap();
        }
        assert_eq!(c.len(), 5);
        c.prune_up_to_rank(3);
        assert_eq!(c.len(), 3); // 3, 4, 5
        assert_eq!(c.lowest_retained_rank(), 3);
    }

    #[test]
    fn timeout_collectors_prune_is_monotonic() {
        let (f, _) = stub_factory();
        let c = TimeoutCollectors::<V>::new(5, f);
        c.prune_up_to_rank(3);
        assert_eq!(c.lowest_retained_rank(), 5);
    }

    #[test]
    fn timeout_aggregator_drops_stale() {
        let (f, count) = stub_factory();
        let c = Arc::new(TimeoutCollectors::<V>::new(0, f));
        let agg = TimeoutAggregator::new(5, c);
        agg.add_timeout(make_timeout(2)).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 0); // stale, factory never called
        agg.add_timeout(make_timeout(10)).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn timeout_aggregator_on_rank_change_prunes() {
        let (f, _) = stub_factory();
        let c = Arc::new(TimeoutCollectors::<V>::new(0, f));
        let agg = TimeoutAggregator::new(0, c.clone());
        agg.add_timeout(make_timeout(1)).unwrap();
        agg.add_timeout(make_timeout(2)).unwrap();
        agg.add_timeout(make_timeout(3)).unwrap();
        assert_eq!(c.len(), 3);
        agg.on_rank_change(3);
        assert_eq!(c.len(), 1); // only rank 3 retained
        assert_eq!(agg.lowest_retained_rank(), 3);
    }
}
