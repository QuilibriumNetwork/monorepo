//! Vote aggregation. Mirror of `consensus/voteaggregator/`.
//!
//! The Go vote aggregator sits on top of a component-manager lifecycle and
//! channels messages between AddVote/AddState callers and internal workers.
//! For the initial Rust port we expose a **synchronous** facade — correct
//! aggregation logic without the async dispatch layer — which an eventual
//! event loop can wrap with channels when the runtime arrives.
//!
//! Portable pieces:
//! - [`PendingVotes`] — per-source pending vote cache (Go:
//!   `voteaggregator/pending_status.go`).
//! - [`VoteCollectors`] — rank-keyed registry of per-state vote collectors
//!   with a "lowest retained rank" pruning cursor (Go:
//!   `voteaggregator/vote_collectors.go::VoteCollectors`).
//! - [`VoteAggregator`] — high-level façade with `add_vote` / `add_state`
//!   / `prune_up_to_rank`, delegating to the collectors.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::models::{Identity, SignedProposal, Unique};
use quil_types::error::{QuilError, Result};

/// Status of a per-state vote collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteCollectorStatus {
    /// Caching votes before the state is known.
    Caching,
    /// Processing votes for a known-valid state.
    Verifying,
    /// Collecting votes on an invalid state (for slashing evidence).
    Invalid,
}

/// Per-source pending-vote cache. Mirror of Go's `PendingStatus`.
///
/// Each source may submit multiple votes before we know the state, but any
/// given vote identity is stored exactly once. Ordered-vote list preserves
/// arrival order so re-delivery to a late-arriving state consumer is
/// deterministic.
#[derive(Debug)]
pub struct PendingStatus<V: Unique> {
    ordered_votes: Vec<V>,
    /// Seen vote identities, to reject duplicates.
    vote_ids: HashMap<Identity, ()>,
}

impl<V: Unique> Default for PendingStatus<V> {
    fn default() -> Self {
        Self {
            ordered_votes: Vec::new(),
            vote_ids: HashMap::new(),
        }
    }
}

impl<V: Unique> PendingStatus<V> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pending vote. Returns `true` if the vote was newly added,
    /// `false` if a duplicate (same identity) was already present.
    pub fn add_vote(&mut self, vote: V) -> bool {
        if self.vote_ids.contains_key(vote.identity()) {
            return false;
        }
        self.vote_ids.insert(vote.identity().clone(), ());
        self.ordered_votes.push(vote);
        true
    }

    /// All pending votes in arrival order.
    pub fn ordered_votes(&self) -> &[V] {
        &self.ordered_votes
    }

    /// Drain all pending votes, leaving the cache empty. Useful when a
    /// state arrives and we want to flush queued votes to a consumer.
    pub fn drain(&mut self) -> Vec<V> {
        self.vote_ids.clear();
        std::mem::take(&mut self.ordered_votes)
    }
}

/// Pending votes indexed by source. Mirror of Go's `PendingVotes`.
#[derive(Debug)]
pub struct PendingVotes<V: Unique> {
    by_source: HashMap<Identity, PendingStatus<V>>,
}

impl<V: Unique> Default for PendingVotes<V> {
    fn default() -> Self {
        Self {
            by_source: HashMap::new(),
        }
    }
}

impl<V: Unique> PendingVotes<V> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vote, routing to the per-source `PendingStatus`. Returns
    /// `true` if newly added.
    pub fn add_vote(&mut self, vote: V) -> bool {
        self.by_source
            .entry(vote.source().clone())
            .or_default()
            .add_vote(vote)
    }

    pub fn is_empty(&self) -> bool {
        self.by_source.is_empty()
    }

    pub fn sources(&self) -> impl Iterator<Item = &Identity> {
        self.by_source.keys()
    }

    /// Take ownership of the pending status for a particular source (if
    /// present). Used when consuming cached votes for a specific voter.
    pub fn take_source(&mut self, source: &Identity) -> Option<PendingStatus<V>> {
        self.by_source.remove(source)
    }
}

/// Collects votes for a specific state and aggregates them into a QC.
/// Mirror of Go's `consensus.VoteCollector[StateT, VoteT]`.
pub trait VoteCollector<S: Unique, V: Unique>: Send + Sync {
    /// Supply the state so the collector can transition from `Caching` to
    /// `Verifying`. Must be called before votes can be verified.
    fn process_state(&self, proposal: &SignedProposal<S, V>) -> Result<()>;

    /// Add a vote to the collector.
    fn add_vote(&self, vote: V) -> Result<()>;

    /// Rank this collector was created for.
    fn rank(&self) -> u64;

    /// Current lifecycle status.
    fn status(&self) -> VoteCollectorStatus;
}

/// Factory that creates a vote collector for a given rank. Mirror of Go's
/// `NewCollectorFactoryMethod[StateT, VoteT]`.
pub type VoteCollectorFactory<S, V> =
    Arc<dyn Fn(u64) -> Result<Arc<dyn VoteCollector<S, V>>> + Send + Sync>;

/// Rank-indexed registry of vote collectors with lazy creation and
/// lowest-retained-rank pruning. Mirror of Go's `VoteCollectors` struct.
pub struct VoteCollectors<S: Unique, V: Unique> {
    inner: RwLock<VoteCollectorsInner<S, V>>,
    factory: VoteCollectorFactory<S, V>,
}

struct VoteCollectorsInner<S: Unique, V: Unique> {
    lowest_retained_rank: u64,
    collectors: HashMap<u64, Arc<dyn VoteCollector<S, V>>>,
}

/// Upper bound on how far ahead of `lowest_retained_rank` a peer-supplied
/// rank may go before we refuse to allocate a collector for it. Without
/// this, a misbehaving peer can flood proposals/votes at attacker-set
/// ranks (`u64::MAX`) and balloon `collectors` because pruning only
/// catches up when QCs finalize. 1024 ranks is generous for any
/// realistic pipeline depth while keeping the per-shard map bounded.
pub const MAX_RANK_LOOKAHEAD: u64 = 1024;

impl<S: Unique, V: Unique> VoteCollectors<S, V> {
    pub fn new(lowest_retained_rank: u64, factory: VoteCollectorFactory<S, V>) -> Self {
        Self {
            inner: RwLock::new(VoteCollectorsInner {
                lowest_retained_rank,
                collectors: HashMap::new(),
            }),
            factory,
        }
    }

    /// Retrieve or create the collector for `rank`. Returns:
    /// - `Ok((collector, created))` — `created == true` if the collector
    ///   was newly constructed.
    /// - `Err(QuilError::NotFound)` — if `rank` is below the pruning
    ///   threshold or above `lowest_retained_rank + MAX_RANK_LOOKAHEAD`.
    ///   The Go side uses a dedicated `BelowPrunedThresholdError`
    ///   sentinel; we reuse `NotFound` for now and the caller is expected
    ///   to swallow it.
    pub fn get_or_create(&self, rank: u64) -> Result<(Arc<dyn VoteCollector<S, V>>, bool)> {
        // Fast path: read lock, check for existing.
        {
            let guard = self.inner.read().unwrap();
            if rank < guard.lowest_retained_rank {
                return Err(QuilError::NotFound(format!(
                    "cannot retrieve collector for pruned rank {} (lowest retained rank {})",
                    rank, guard.lowest_retained_rank
                )));
            }
            if rank > guard.lowest_retained_rank.saturating_add(MAX_RANK_LOOKAHEAD) {
                return Err(QuilError::NotFound(format!(
                    "rank {} exceeds lookahead {} above lowest retained rank {}",
                    rank, MAX_RANK_LOOKAHEAD, guard.lowest_retained_rank
                )));
            }
            if let Some(clr) = guard.collectors.get(&rank) {
                return Ok((Arc::clone(clr), false));
            }
        }

        // Slow path: build collector outside the lock, then re-check under
        // a write lock. Matches Go's double-check pattern.
        let collector = (self.factory)(rank).map_err(|e| {
            QuilError::Consensus(format!(
                "could not create vote collector for rank {}: {}",
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
        if rank > guard.lowest_retained_rank.saturating_add(MAX_RANK_LOOKAHEAD) {
            return Err(QuilError::NotFound(format!(
                "rank {} exceeds lookahead {} above lowest retained rank {}",
                rank, MAX_RANK_LOOKAHEAD, guard.lowest_retained_rank
            )));
        }
        if let Some(clr) = guard.collectors.get(&rank) {
            return Ok((Arc::clone(clr), false));
        }
        guard.collectors.insert(rank, Arc::clone(&collector));
        Ok((collector, true))
    }

    /// Prune collectors strictly below `lowest_retained_rank`. No-op if
    /// the new cursor is not strictly greater than the current one.
    pub fn prune_up_to_rank(&self, new_lowest: u64) {
        let mut guard = self.inner.write().unwrap();
        if guard.lowest_retained_rank >= new_lowest {
            return;
        }
        if guard.collectors.is_empty() {
            guard.lowest_retained_rank = new_lowest;
            return;
        }
        // Iterate the smaller dimension (collectors vs rank range).
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

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().collectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().collectors.is_empty()
    }
}

/// Synchronous façade for the Go `VoteAggregator`. Processes votes and
/// states inline (no channels, no workers) — the async dispatch layer will
/// live in the future event loop crate and wrap this type.
pub struct VoteAggregator<S: Unique, V: Unique> {
    collectors: Arc<VoteCollectors<S, V>>,
    /// Protects the mutable pruning cursor for stale-vote fast-rejection.
    /// The monotonic-counter semantics of Go's `counters.StrictMonotonicCounter`
    /// are enforced manually: set() only succeeds when the new value is
    /// strictly greater.
    lowest_retained_rank: Mutex<u64>,
}

impl<S: Unique, V: Unique> VoteAggregator<S, V> {
    pub fn new(
        lowest_retained_rank: u64,
        collectors: Arc<VoteCollectors<S, V>>,
    ) -> Self {
        Self {
            collectors,
            lowest_retained_rank: Mutex::new(lowest_retained_rank),
        }
    }

    /// Inline version of `VoteAggregator.processQueuedVote`.
    pub fn add_vote(&self, vote: V) -> Result<()> {
        let rank = vote.rank();
        if rank < *self.lowest_retained_rank.lock().unwrap() {
            // Silently drop stale votes — matches Go.
            return Ok(());
        }
        match self.collectors.get_or_create(rank) {
            Ok((collector, _created)) => collector.add_vote(vote),
            // Pruned-threshold errors are expected during normal
            // operation; swallow them.
            Err(e) if matches!(e, QuilError::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Inline version of `VoteAggregator.processQueuedState`.
    pub fn add_state(&self, proposal: &SignedProposal<S, V>) -> Result<()> {
        let rank = proposal.proposal.state.rank;
        if rank < *self.lowest_retained_rank.lock().unwrap() {
            return Ok(());
        }
        match self.collectors.get_or_create(rank) {
            Ok((collector, _)) => collector.process_state(proposal),
            Err(e) if matches!(e, QuilError::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Monotonic prune cursor update. Delegates to collectors only when
    /// the cursor actually advanced.
    pub fn prune_up_to_rank(&self, new_lowest: u64) {
        let mut cursor = self.lowest_retained_rank.lock().unwrap();
        if new_lowest > *cursor {
            *cursor = new_lowest;
            drop(cursor); // release before calling into collectors
            self.collectors.prune_up_to_rank(new_lowest);
        }
    }

    /// Current pruning cursor.
    pub fn lowest_retained_rank(&self) -> u64 {
        *self.lowest_retained_rank.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Minimal Unique impl for tests.
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

    fn vote(id: &str, src: &str, rank: u64) -> V {
        V {
            id: id.into(),
            src: src.into(),
            rank,
        }
    }

    #[test]
    fn pending_status_dedupes_by_identity() {
        let mut s: PendingStatus<V> = PendingStatus::new();
        assert!(s.add_vote(vote("v1", "alice", 10)));
        assert!(!s.add_vote(vote("v1", "alice", 10))); // duplicate
        assert!(s.add_vote(vote("v2", "alice", 10)));
        assert_eq!(s.ordered_votes().len(), 2);
        assert_eq!(s.ordered_votes()[0].id, b"v1".to_vec());
        assert_eq!(s.ordered_votes()[1].id, b"v2".to_vec());
    }

    #[test]
    fn pending_status_drain_clears() {
        let mut s: PendingStatus<V> = PendingStatus::new();
        s.add_vote(vote("v1", "alice", 1));
        s.add_vote(vote("v2", "alice", 1));
        let drained = s.drain();
        assert_eq!(drained.len(), 2);
        assert!(s.ordered_votes().is_empty());
        // After drain, re-adding the same identity must succeed again.
        assert!(s.add_vote(vote("v1", "alice", 1)));
    }

    #[test]
    fn pending_votes_groups_by_source() {
        let mut pv: PendingVotes<V> = PendingVotes::new();
        pv.add_vote(vote("v1", "alice", 1));
        pv.add_vote(vote("v2", "bob", 1));
        pv.add_vote(vote("v3", "alice", 1));
        let sources: Vec<_> = pv.sources().cloned().collect();
        assert_eq!(sources.len(), 2);
        let alice = pv.take_source(&b"alice".to_vec()).unwrap();
        assert_eq!(alice.ordered_votes().len(), 2);
    }

    // Stub collector that just counts votes.
    struct StubCollector {
        rank: u64,
        votes: Mutex<usize>,
    }
    impl VoteCollector<V, V> for StubCollector {
        fn process_state(&self, _p: &SignedProposal<V, V>) -> Result<()> {
            Ok(())
        }
        fn add_vote(&self, _v: V) -> Result<()> {
            *self.votes.lock().unwrap() += 1;
            Ok(())
        }
        fn rank(&self) -> u64 { self.rank }
        fn status(&self) -> VoteCollectorStatus { VoteCollectorStatus::Caching }
    }

    fn stub_factory() -> (VoteCollectorFactory<V, V>, Arc<AtomicUsize>) {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc2 = Arc::clone(&call_count);
        let f: VoteCollectorFactory<V, V> = Arc::new(move |rank| {
            cc2.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(StubCollector {
                rank,
                votes: Mutex::new(0),
            }) as Arc<dyn VoteCollector<V, V>>)
        });
        (f, call_count)
    }

    #[test]
    fn vote_collectors_lazy_create_and_reuse() {
        let (factory, count) = stub_factory();
        let vcs = VoteCollectors::<V, V>::new(0, factory);
        let (_, created1) = vcs.get_or_create(5).unwrap();
        assert!(created1);
        let (_, created2) = vcs.get_or_create(5).unwrap();
        assert!(!created2);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn vote_collectors_reject_below_pruned_threshold() {
        let (factory, _) = stub_factory();
        let vcs = VoteCollectors::<V, V>::new(10, factory);
        match vcs.get_or_create(5) {
            Ok(_) => panic!("expected NotFound for pruned rank"),
            Err(QuilError::NotFound(_)) => {}
            Err(e) => panic!("expected NotFound, got {:?}", e),
        }
    }

    #[test]
    fn vote_collectors_prune_removes_older_ranks() {
        let (factory, _) = stub_factory();
        let vcs = VoteCollectors::<V, V>::new(0, factory);
        vcs.get_or_create(1).unwrap();
        vcs.get_or_create(2).unwrap();
        vcs.get_or_create(3).unwrap();
        vcs.get_or_create(4).unwrap();
        assert_eq!(vcs.len(), 4);
        vcs.prune_up_to_rank(3);
        assert_eq!(vcs.len(), 2); // only 3 and 4 remain
        assert_eq!(vcs.lowest_retained_rank(), 3);
    }

    #[test]
    fn vote_collectors_prune_is_monotonic() {
        let (factory, _) = stub_factory();
        let vcs = VoteCollectors::<V, V>::new(5, factory);
        vcs.prune_up_to_rank(3); // no-op (< current)
        assert_eq!(vcs.lowest_retained_rank(), 5);
        vcs.prune_up_to_rank(10);
        assert_eq!(vcs.lowest_retained_rank(), 10);
    }

    #[test]
    fn vote_aggregator_drops_stale_votes() {
        let (factory, count) = stub_factory();
        let vcs = Arc::new(VoteCollectors::<V, V>::new(0, factory));
        let va = VoteAggregator::new(5, vcs.clone());
        va.add_vote(vote("v1", "alice", 2)).unwrap(); // stale, dropped
        assert_eq!(count.load(Ordering::SeqCst), 0);
        va.add_vote(vote("v2", "alice", 10)).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn vote_aggregator_monotonic_prune() {
        let (factory, _) = stub_factory();
        let vcs = Arc::new(VoteCollectors::<V, V>::new(0, factory));
        let va = VoteAggregator::new(0, vcs.clone());
        va.prune_up_to_rank(5);
        assert_eq!(va.lowest_retained_rank(), 5);
        va.prune_up_to_rank(3); // no-op
        assert_eq!(va.lowest_retained_rank(), 5);
        va.prune_up_to_rank(10);
        assert_eq!(va.lowest_retained_rank(), 10);
    }
}
