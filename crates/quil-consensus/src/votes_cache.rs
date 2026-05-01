//! Per-rank vote deduplication cache. Mirror of
//! `consensus/votecollector/vote_cache.go::VotesCache`.
//!
//! `VotesCache` stores the first vote seen from each voter at a
//! particular rank, preserves arrival order, and detects equivocation:
//!
//! - **Repeated vote** (same voter, same identifier & signature) is
//!   silently dropped with [`QuilError::RepeatedVote`].
//! - **Double vote** (same voter, different identifier OR signature at
//!   the same rank) yields Byzantine evidence via [`QuilError::DoubleVote`].
//! - **Wrong rank** yields [`QuilError::IncompatibleRank`].
//!
//! The cache is concurrency-safe and supports lazy consumer registration:
//! newly-registered consumers are backfilled with all previously-cached
//! votes in arrival order.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::models::{Identity, Unique};
use quil_types::error::{QuilError, Result};

/// Callback invoked for each vote added to the cache. Called once per
/// vote on registration (for already-cached entries) and then on every
/// subsequent successful `add_vote`.
///
/// Per Go's API contract: consumers MUST be non-blocking and consume the
/// vote without noteworthy delay, since the cache holds its write lock
/// while invoking them.
pub type VoteConsumer<V> = Arc<dyn Fn(&V) + Send + Sync>;

/// Internal record: the vote plus its arrival index for stable ordering.
struct VoteEntry<V: Unique> {
    vote: V,
    index: usize,
}

struct Inner<V: Unique> {
    /// `signer_id → first vote seen from this signer`.
    votes: HashMap<Identity, VoteEntry<V>>,
    /// Registered consumers, called on each fresh vote.
    consumers: Vec<VoteConsumer<V>>,
}

/// Per-rank vote cache. Mirror of Go's `VotesCache[VoteT]`.
pub struct VotesCache<V: Unique> {
    rank: u64,
    // RwLock matches Go's `sync.RWMutex` semantics. Nested Mutex is only
    // used for consumer interior mutability during backfill.
    inner: RwLock<Inner<V>>,
    /// Lock for consumer invocation during add_vote — we drop the main
    /// write lock before calling consumers to prevent reentrant deadlocks,
    /// but we still need a consistent consumer list. This second mutex
    /// serializes consumer iteration.
    consumer_lock: Mutex<()>,
}

impl<V: Unique> VotesCache<V> {
    pub fn new(rank: u64) -> Self {
        Self {
            rank,
            inner: RwLock::new(Inner {
                votes: HashMap::new(),
                consumers: Vec::new(),
            }),
            consumer_lock: Mutex::new(()),
        }
    }

    pub fn rank(&self) -> u64 {
        self.rank
    }

    /// Add a vote. Returns the error variants described in the module
    /// docs.
    pub fn add_vote(&self, vote: V) -> Result<()> {
        if vote.rank() != self.rank {
            return Err(QuilError::IncompatibleRank(format!(
                "vote rank {} != cache rank {}",
                vote.rank(),
                self.rank
            )));
        }
        // Lock the main state.
        let consumers_to_fire = {
            let mut guard = self.inner.write().unwrap();
            if let Some(first) = guard.votes.get(vote.identity()) {
                // Same identity already stored — check for repeat vs
                // equivocation.
                let same_source = first.vote.source() == vote.source();
                let same_sig = first.vote.signature() == vote.signature();
                if same_source && same_sig {
                    return Err(QuilError::RepeatedVote(format!(
                        "duplicate vote {} at rank {}",
                        hex::encode(vote.identity()),
                        self.rank
                    )));
                }
                // Different source or different signature → byzantine.
                return Err(QuilError::DoubleVote(format!(
                    "vote equivocation at rank {}: voter {} (existing signed_by={}, new signed_by={})",
                    self.rank,
                    hex::encode(vote.identity()),
                    hex::encode(first.vote.source()),
                    hex::encode(vote.source())
                )));
            }
            let idx = guard.votes.len();
            guard.votes.insert(
                vote.identity().clone(),
                VoteEntry {
                    vote: vote.clone(),
                    index: idx,
                },
            );
            guard.consumers.clone()
        };

        // Fire consumers outside the main lock. `consumer_lock` serializes
        // concurrent consumer dispatch but allows other `add_vote` calls
        // that don't trigger consumers to proceed.
        let _guard = self.consumer_lock.lock().unwrap();
        for consumer in &consumers_to_fire {
            consumer(&vote);
        }
        Ok(())
    }

    /// Look up the stored vote for a signer. Returns `None` if unknown.
    pub fn get_vote(&self, signer_id: &Identity) -> Option<V> {
        let guard = self.inner.read().unwrap();
        guard.votes.get(signer_id).map(|e| e.vote.clone())
    }

    /// Number of cached votes.
    pub fn size(&self) -> usize {
        self.inner.read().unwrap().votes.len()
    }

    /// Register a consumer. On registration, the consumer is fed every
    /// currently-cached vote in arrival order.
    pub fn register_consumer(&self, consumer: VoteConsumer<V>) {
        // Snapshot cached votes in index order, then register & drain.
        let snapshot = {
            let mut guard = self.inner.write().unwrap();
            guard.consumers.push(consumer.clone());
            Self::ordered_snapshot(&guard.votes)
        };
        let _guard = self.consumer_lock.lock().unwrap();
        for v in snapshot {
            consumer(&v);
        }
    }

    /// All currently cached votes in arrival order.
    pub fn all(&self) -> Vec<V> {
        let guard = self.inner.read().unwrap();
        Self::ordered_snapshot(&guard.votes)
    }

    fn ordered_snapshot(votes: &HashMap<Identity, VoteEntry<V>>) -> Vec<V> {
        let mut out: Vec<Option<V>> = vec![None; votes.len()];
        for entry in votes.values() {
            if entry.index < out.len() {
                out[entry.index] = Some(entry.vote.clone());
            }
        }
        out.into_iter().flatten().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Clone)]
    struct V {
        id: Identity,
        src: Identity,
        rank: u64,
        sig: Vec<u8>,
    }
    impl Unique for V {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.src }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &self.sig }
    }

    fn vote(id: &str, src: &str, rank: u64, sig: &[u8]) -> V {
        V {
            id: id.into(),
            src: src.into(),
            rank,
            sig: sig.to_vec(),
        }
    }

    #[test]
    fn add_new_vote_succeeds() {
        let c: VotesCache<V> = VotesCache::new(5);
        c.add_vote(vote("v1", "alice", 5, b"sig1")).unwrap();
        assert_eq!(c.size(), 1);
    }

    #[test]
    fn wrong_rank_rejected() {
        let c: VotesCache<V> = VotesCache::new(5);
        let err = c.add_vote(vote("v1", "alice", 7, b"sig1")).unwrap_err();
        assert!(matches!(err, QuilError::IncompatibleRank(_)));
    }

    #[test]
    fn exact_duplicate_is_repeated_vote() {
        let c: VotesCache<V> = VotesCache::new(5);
        c.add_vote(vote("v1", "alice", 5, b"sig1")).unwrap();
        let err = c.add_vote(vote("v1", "alice", 5, b"sig1")).unwrap_err();
        assert!(err.is_repeated_vote());
    }

    #[test]
    fn different_signature_is_double_vote() {
        let c: VotesCache<V> = VotesCache::new(5);
        c.add_vote(vote("v1", "alice", 5, b"sig1")).unwrap();
        // Same id + source but different signature → equivocation.
        let err = c.add_vote(vote("v1", "alice", 5, b"sig2")).unwrap_err();
        assert!(err.is_double_vote());
    }

    #[test]
    fn different_source_is_double_vote() {
        let c: VotesCache<V> = VotesCache::new(5);
        c.add_vote(vote("v1", "alice", 5, b"sig1")).unwrap();
        // Same id but different source → equivocation.
        let err = c.add_vote(vote("v1", "bob", 5, b"sig1")).unwrap_err();
        assert!(err.is_double_vote());
    }

    #[test]
    fn get_vote_returns_first_seen() {
        let c: VotesCache<V> = VotesCache::new(5);
        let v1 = vote("v1", "alice", 5, b"sig1");
        c.add_vote(v1.clone()).unwrap();
        let got = c.get_vote(&b"v1".to_vec()).unwrap();
        assert_eq!(got.sig, v1.sig);
    }

    #[test]
    fn all_preserves_arrival_order() {
        let c: VotesCache<V> = VotesCache::new(5);
        c.add_vote(vote("v1", "alice", 5, b"s1")).unwrap();
        c.add_vote(vote("v2", "bob", 5, b"s2")).unwrap();
        c.add_vote(vote("v3", "carol", 5, b"s3")).unwrap();
        let all = c.all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].id, b"v1".to_vec());
        assert_eq!(all[1].id, b"v2".to_vec());
        assert_eq!(all[2].id, b"v3".to_vec());
    }

    #[test]
    fn register_consumer_backfills_cached_votes() {
        let c: VotesCache<V> = VotesCache::new(5);
        c.add_vote(vote("v1", "alice", 5, b"s1")).unwrap();
        c.add_vote(vote("v2", "bob", 5, b"s2")).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&count);
        c.register_consumer(Arc::new(move |_v: &V| {
            c2.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(count.load(Ordering::SeqCst), 2);
        // New vote should also trigger the consumer.
        c.add_vote(vote("v3", "carol", 5, b"s3")).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}
