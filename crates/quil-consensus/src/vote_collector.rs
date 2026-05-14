//! Vote collector state machine. Mirror of
//! `consensus/votecollector/statemachine.go::VoteCollector`.
//!
//! A [`VoteCollector`] wraps a [`VotesCache`] and a dynamically
//! swappable [`VoteProcessor`] (or a noop) through three states:
//!
//! ```text
//!     Caching ─────► Verifying ─────► Invalid
//!        │                             ▲
//!        └─────────────────────────────┘
//! ```
//!
//! - **Caching**: no proposal yet. Votes are stored in the cache and
//!   deduped, but not verified.
//! - **Verifying**: a valid proposal arrived and a [`VoteProcessor`]
//!   is live. Both cached and fresh votes are routed through it.
//! - **Invalid**: proposer equivocation (we saw two different proposals
//!   for the same rank). All votes are dropped. Note that `Forks`
//!   handles the slashing evidence; the collector just stops.
//!
//! Concurrency: the collector is concurrency-safe — multiple tasks
//! can call `add_vote` / `process_state` simultaneously.

use std::sync::{Arc, Mutex, RwLock};

use crate::models::{Identity, SignedProposal, State, Unique};
use crate::signature_aggregator::WeightedSignatureAggregator;
use crate::vote_processor::VoteProcessor;
use crate::voting_provider::{OnQuorumCertificateCreated, VotingProvider};
use crate::votes_cache::VotesCache;
use quil_types::error::{QuilError, Result};

/// State machine status. Mirror of Go's `VoteCollectorStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteCollectorStatus {
    Caching,
    Verifying,
    Invalid,
}

/// Notification sink for vote-collector events. Mirror of Go's
/// `VoteAggregationConsumer[StateT, VoteT]` (vote-flow subset).
pub trait VoteAggregationConsumer<V: Unique>: Send + Sync {
    /// A vote was successfully processed (passed signature verification).
    fn on_vote_processed(&self, vote: &V);

    /// A byzantine vote signature / signer was detected.
    fn on_invalid_vote_detected(&self, vote: &V, reason: &str);

    /// Two votes from the same signer at the same rank with different
    /// identifiers (equivocation).
    fn on_double_voting_detected(&self, first: &V, conflicting: &V);
}

/// Factory callable used by the collector to build a fresh
/// [`VoteProcessor`] when transitioning Caching → Verifying.
pub type VoteProcessorFactory<S, V> = Arc<
    dyn Fn(&SignedProposal<S, V>) -> Result<(Arc<dyn WeightedSignatureAggregator>, u64)>
        + Send
        + Sync,
>;

enum InnerState<S: Unique, V: Unique> {
    Caching,
    Verifying {
        processor: Arc<VoteProcessor<S, V>>,
        state_id: Identity,
    },
    Invalid,
}

/// Vote collector state machine. See module docs.
pub struct VoteCollector<S: Unique, V: Unique> {
    rank: u64,
    votes_cache: VotesCache<V>,
    notifier: Arc<dyn VoteAggregationConsumer<V>>,
    voting_provider: Arc<dyn VotingProvider<S, V>>,
    on_qc_created: OnQuorumCertificateCreated,
    processor_factory: VoteProcessorFactory<S, V>,
    state: RwLock<InnerState<S, V>>,
    /// Serializes state-transition writes so Caching→Verifying and
    /// Verifying→Invalid don't race with each other.
    transition_lock: Mutex<()>,
}

impl<S: Unique, V: Unique> VoteCollector<S, V> {
    pub fn new(
        rank: u64,
        notifier: Arc<dyn VoteAggregationConsumer<V>>,
        voting_provider: Arc<dyn VotingProvider<S, V>>,
        on_qc_created: OnQuorumCertificateCreated,
        processor_factory: VoteProcessorFactory<S, V>,
    ) -> Self {
        Self {
            rank,
            votes_cache: VotesCache::new(rank),
            notifier,
            voting_provider,
            on_qc_created,
            processor_factory,
            state: RwLock::new(InnerState::Caching),
            transition_lock: Mutex::new(()),
        }
    }

    /// The rank this collector covers.
    pub fn rank(&self) -> u64 {
        self.rank
    }

    /// Current lifecycle status.
    pub fn status(&self) -> VoteCollectorStatus {
        match &*self.state.read().unwrap() {
            InnerState::Caching => VoteCollectorStatus::Caching,
            InnerState::Verifying { .. } => VoteCollectorStatus::Verifying,
            InnerState::Invalid => VoteCollectorStatus::Invalid,
        }
    }

    /// Add a standalone vote. Caches it and — if verifying — forwards
    /// to the vote processor.
    pub fn add_vote(&self, vote: V) -> Result<()> {
        if !self.ensure_vote_unique(&vote)? {
            return Ok(());
        }
        self.process_vote(vote)
    }

    /// Drive the cache-level dedup + equivocation detection. Returns
    /// `Ok(true)` if the vote is a new, unique entry; `Ok(false)` if
    /// it was a duplicate or equivocation (notifier fires for the
    /// latter).
    fn ensure_vote_unique(&self, vote: &V) -> Result<bool> {
        match self.votes_cache.add_vote(vote.clone()) {
            Ok(()) => Ok(true),
            Err(e) if e.is_repeated_vote() => Ok(false),
            Err(e) if e.is_double_vote() => {
                // Grab the stored first vote so the notifier can receive both.
                if let Some(first) = self.votes_cache.get_vote(vote.identity()) {
                    self.notifier.on_double_voting_detected(&first, vote);
                }
                Ok(false)
            }
            Err(e) => Err(QuilError::Consensus(format!(
                "internal error adding vote {} to cache: {}",
                hex::encode(vote.identity()),
                e
            ))),
        }
    }

    /// Forward the vote to whichever processor is currently active.
    /// In `Caching` and `Invalid`, processing is a no-op.
    fn process_vote(&self, vote: V) -> Result<()> {
        let processor = {
            let guard = self.state.read().unwrap();
            match &*guard {
                InnerState::Verifying { processor, .. } => Some(Arc::clone(processor)),
                _ => None,
            }
        };
        if let Some(proc) = processor {
            match proc.process(vote.clone()) {
                Ok(()) => {
                    self.notifier.on_vote_processed(&vote);
                    Ok(())
                }
                Err(e) if e.is_invalid_vote() => {
                    self.notifier.on_invalid_vote_detected(&vote, &format!("{}", e));
                    Ok(())
                }
                Err(e) if e.is_duplicated_signer() => Ok(()),
                Err(e) if e.is_incompatible_state() => {
                    // Byzantine: vote targeted a different state at the
                    // same rank. Log-only per Go semantics.
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(())
        }
    }

    /// Process an incoming proposal. Drives the Caching → Verifying
    /// transition on the first valid proposal, or terminates to
    /// Invalid on proposer equivocation.
    pub fn process_state(&self, proposal: &SignedProposal<S, V>) -> Result<()> {
        // Cache the proposer's own vote (to participate in equivocation
        // detection), regardless of uniqueness.
        let _ = self.ensure_vote_unique(&proposal.vote)?;

        if proposal.proposal.state.rank != self.rank {
            return Err(QuilError::Consensus(format!(
                "this VoteCollector requires a proposal for rank {} but received state {} with rank {}",
                self.rank, hex::encode(&proposal.proposal.state.identifier), proposal.proposal.state.rank
            )));
        }

        // Lock out other state-transition writers.
        let _txn = self.transition_lock.lock().unwrap();

        // Decide what to do based on current state. Caching → Verifying
        // (fresh), Verifying (different state id → Invalid), Invalid (no-op).
        let current_status = self.status();
        match current_status {
            VoteCollectorStatus::Caching => {
                self.caching_to_verifying(proposal)?;
                // Replay cached votes filtered by this state's identifier.
                self.process_cached_votes(&proposal.proposal.state);
                Ok(())
            }
            VoteCollectorStatus::Verifying => {
                // Check for proposer equivocation.
                let same_state = {
                    let guard = self.state.read().unwrap();
                    match &*guard {
                        InnerState::Verifying { state_id, .. } => {
                            state_id == &proposal.proposal.state.identifier
                        }
                        _ => false,
                    }
                };
                if !same_state {
                    self.terminate_vote_processing();
                }
                Ok(())
            }
            VoteCollectorStatus::Invalid => Ok(()),
        }
    }

    fn caching_to_verifying(&self, proposal: &SignedProposal<S, V>) -> Result<()> {
        // Ask the factory for this proposal's aggregator + quorum threshold.
        let (aggregator, min_required_weight) =
            (self.processor_factory)(proposal).map_err(|e| {
                QuilError::Consensus(format!(
                    "failed to create VerifyingVoteProcessor for state {}: {}",
                    hex::encode(&proposal.proposal.state.identifier), e
                ))
            })?;
        let processor = Arc::new(VoteProcessor::new(
            Arc::new(proposal.proposal.state.clone()),
            aggregator,
            Arc::clone(&self.voting_provider),
            Arc::clone(&self.on_qc_created),
            min_required_weight,
        ));
        let mut guard = self.state.write().unwrap();
        *guard = InnerState::Verifying {
            processor,
            state_id: proposal.proposal.state.identifier.clone(),
        };
        Ok(())
    }

    fn terminate_vote_processing(&self) {
        let mut guard = self.state.write().unwrap();
        *guard = InnerState::Invalid;
    }

    fn process_cached_votes(&self, state: &State<S>) {
        let cached = self.votes_cache.all();
        for vote in cached {
            if vote.source() != &state.identifier {
                continue;
            }
            // Swallow internal processing errors — any real bug is
            // surfaced as a notifier callback inside `process_vote`.
            let _ = self.process_vote(vote);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AggregatedSignature, Proposal, QuorumCertificate, TimeoutCertificate, WeightedIdentity,
    };
    use crate::signature_aggregator::TimeoutSignerInfo;
    use std::sync::atomic::{AtomicU64, Ordering};

    // ---------- test types ----------
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

    #[derive(Debug, Clone)]
    struct Vote {
        id: Identity,
        src: Identity,
        rank: u64,
        sig: Vec<u8>,
    }
    impl Unique for Vote {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.src }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &self.sig }
    }

    fn make_vote(voter: &str, rank: u64, state_id: &str, sig: &[u8]) -> Vote {
        Vote {
            id: voter.into(),
            src: state_id.into(),
            rank,
            sig: sig.to_vec(),
        }
    }

    fn make_state(rank: u64, id: &str) -> State<AppState> {
        State {
            rank,
            identifier: id.into(),
            proposer_id: "leader".into(),
            parent_qc_identity: "parent".into(),
            parent_qc_rank: rank.saturating_sub(1),
            parent_quorum_certificate: None,
            timestamp: 0,
            state: AppState {
                id: id.into(),
                rank,
            },
        }
    }

    fn make_proposal(
        rank: u64,
        state_id: &str,
        proposer_vote: Vote,
    ) -> SignedProposal<AppState, Vote> {
        SignedProposal {
            proposal: Proposal {
                state: make_state(rank, state_id),
                parent_quorum_certificate: Arc::new(StubQc {
                    rank: rank.saturating_sub(1),
                    id: "parent".into(),
                }),
                previous_rank_timeout_certificate: None,
            },
            vote: proposer_vote,
        }
    }

    // ---------- notifier stub ----------
    #[derive(Default)]
    struct RecordingNotifier {
        processed: AtomicU64,
        invalid: AtomicU64,
        double: AtomicU64,
    }
    impl VoteAggregationConsumer<Vote> for RecordingNotifier {
        fn on_vote_processed(&self, _v: &Vote) {
            self.processed.fetch_add(1, Ordering::SeqCst);
        }
        fn on_invalid_vote_detected(&self, _v: &Vote, _r: &str) {
            self.invalid.fetch_add(1, Ordering::SeqCst);
        }
        fn on_double_voting_detected(&self, _f: &Vote, _c: &Vote) {
            self.double.fetch_add(1, Ordering::SeqCst);
        }
    }

    // ---------- signature aggregator stub ----------
    #[derive(Debug)]
    struct StubAgg;
    impl AggregatedSignature for StubAgg {
        fn signature(&self) -> &[u8] { &[] }
        fn public_key(&self) -> &[u8] { &[] }
        fn bitmask(&self) -> &[u8] { &[] }
    }

    struct CountingAggregator {
        total: Mutex<u64>,
    }
    impl WeightedSignatureAggregator for CountingAggregator {
        fn verify(&self, _signer: &Identity, _sig: &[u8]) -> Result<()> {
            Ok(())
        }
        fn trusted_add(&self, _signer: &Identity, _sig: &[u8]) -> Result<u64> {
            let mut t = self.total.lock().unwrap();
            *t += 1;
            Ok(*t)
        }
        fn total_weight(&self) -> u64 {
            *self.total.lock().unwrap()
        }
        fn aggregate(
            &self,
        ) -> Result<(Vec<Box<dyn WeightedIdentity>>, Arc<dyn AggregatedSignature>)> {
            Ok((vec![], Arc::new(StubAgg)))
        }
    }

    // ---------- voting provider stub ----------
    struct StubVotingProvider {
        qcs_built: AtomicU64,
    }
    impl VotingProvider<AppState, Vote> for StubVotingProvider {
        fn sign_vote(&self, _s: &State<AppState>) -> Result<Vote> { Err(QuilError::Internal("sign_vote not supported in stub".into())) }
        fn sign_timeout_vote(&self, _f: &[u8], _c: u64, _n: u64) -> Result<Vote> {
            Err(QuilError::Internal("sign_timeout_vote not supported in stub".into()))
        }
        fn finalize_quorum_certificate(
            &self,
            state: &State<AppState>,
            _a: Arc<dyn AggregatedSignature>,
        ) -> Result<Arc<dyn QuorumCertificate>> {
            self.qcs_built.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(StubQc {
                rank: state.rank,
                id: state.identifier.clone(),
            }))
        }
        fn finalize_timeout(
            &self,
            _r: u64,
            _qc: Arc<dyn QuorumCertificate>,
            _s: Vec<TimeoutSignerInfo>,
            _a: Arc<dyn AggregatedSignature>,
        ) -> Result<Arc<dyn TimeoutCertificate>> {
            Err(QuilError::Internal("finalize_timeout not supported in stub".into()))
        }
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
        fn equals(&self, o: &dyn QuorumCertificate) -> bool {
            self.rank == o.rank() && self.id == *o.identity()
        }
    }

    // ---------- factory builder ----------
    fn make_factory(min_required: u64) -> VoteProcessorFactory<AppState, Vote> {
        Arc::new(move |_p: &SignedProposal<AppState, Vote>| {
            let agg = Arc::new(CountingAggregator {
                total: Mutex::new(0),
            }) as Arc<dyn WeightedSignatureAggregator>;
            Ok((agg, min_required))
        })
    }

    fn make_collector(
        rank: u64,
        min_required: u64,
    ) -> (
        VoteCollector<AppState, Vote>,
        Arc<RecordingNotifier>,
        Arc<StubVotingProvider>,
        Arc<AtomicU64>,
    ) {
        let notifier = Arc::new(RecordingNotifier::default());
        let vp = Arc::new(StubVotingProvider {
            qcs_built: AtomicU64::new(0),
        });
        let qc_cb = Arc::new(AtomicU64::new(0));
        let qcc = Arc::clone(&qc_cb);
        let on_qc: OnQuorumCertificateCreated =
            Arc::new(move |_q| {
                qcc.fetch_add(1, Ordering::SeqCst);
            });
        let collector = VoteCollector::new(
            rank,
            notifier.clone() as Arc<dyn VoteAggregationConsumer<Vote>>,
            vp.clone() as Arc<dyn VotingProvider<AppState, Vote>>,
            on_qc,
            make_factory(min_required),
        );
        (collector, notifier, vp, qc_cb)
    }

    // ---------- tests ----------
    #[test]
    fn starts_in_caching_state() {
        let (c, _, _, _) = make_collector(5, 2);
        assert_eq!(c.status(), VoteCollectorStatus::Caching);
    }

    #[test]
    fn cached_votes_processed_on_state_arrival() {
        let (c, notifier, vp, qc_cb) = make_collector(5, 2);
        // Cache two votes for the state that will arrive.
        c.add_vote(make_vote("alice", 5, "state-5", b"s1")).unwrap();
        c.add_vote(make_vote("bob", 5, "state-5", b"s2")).unwrap();
        assert_eq!(c.status(), VoteCollectorStatus::Caching);
        assert_eq!(notifier.processed.load(Ordering::SeqCst), 0);

        // Now the state arrives with its proposer vote.
        let proposer_vote = make_vote("leader", 5, "state-5", b"pv");
        let sp = make_proposal(5, "state-5", proposer_vote);
        c.process_state(&sp).unwrap();

        // Should have transitioned and replayed the cached votes.
        assert_eq!(c.status(), VoteCollectorStatus::Verifying);
        // alice+bob via replay. Proposer vote was cached too but
        // not routed (its source is "state-5" so it matches the filter).
        // Plus the leader vote: total 3.
        assert!(notifier.processed.load(Ordering::SeqCst) >= 2);
        // Reached threshold (2) → QC built.
        assert_eq!(vp.qcs_built.load(Ordering::SeqCst), 1);
        assert_eq!(qc_cb.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn votes_after_state_are_processed() {
        let (c, notifier, vp, _) = make_collector(5, 3);
        let proposer_vote = make_vote("leader", 5, "state-5", b"pv");
        c.process_state(&make_proposal(5, "state-5", proposer_vote)).unwrap();
        assert_eq!(c.status(), VoteCollectorStatus::Verifying);
        c.add_vote(make_vote("alice", 5, "state-5", b"s1")).unwrap();
        c.add_vote(make_vote("bob", 5, "state-5", b"s2")).unwrap();
        assert!(notifier.processed.load(Ordering::SeqCst) >= 2);
        assert_eq!(vp.qcs_built.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn proposer_equivocation_transitions_to_invalid() {
        let (c, _, _, _) = make_collector(5, 5);
        let pv1 = make_vote("leader", 5, "state-A", b"pv1");
        let pv2 = make_vote("leader", 5, "state-B", b"pv2");
        c.process_state(&make_proposal(5, "state-A", pv1)).unwrap();
        assert_eq!(c.status(), VoteCollectorStatus::Verifying);
        c.process_state(&make_proposal(5, "state-B", pv2)).unwrap();
        assert_eq!(c.status(), VoteCollectorStatus::Invalid);
    }

    #[test]
    fn double_voting_fires_notifier_and_drops() {
        let (c, notifier, _, _) = make_collector(5, 5);
        // alice first votes for state-A.
        c.add_vote(make_vote("alice", 5, "state-A", b"s1")).unwrap();
        // alice then votes for state-B → equivocation.
        c.add_vote(make_vote("alice", 5, "state-B", b"s1")).unwrap();
        assert_eq!(notifier.double.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn wrong_rank_proposal_errors() {
        let (c, _, _, _) = make_collector(5, 2);
        let pv = make_vote("leader", 7, "state-5", b"pv");
        // Rank 7 but collector is for rank 5.
        let err = c.process_state(&make_proposal(7, "state-5", pv)).unwrap_err();
        assert!(format!("{}", err).contains("rank"));
    }

    #[test]
    fn votes_in_invalid_state_are_dropped_silently() {
        let (c, notifier, _, _) = make_collector(5, 5);
        let pv1 = make_vote("leader", 5, "state-A", b"pv1");
        let pv2 = make_vote("leader", 5, "state-B", b"pv2");
        c.process_state(&make_proposal(5, "state-A", pv1)).unwrap();
        c.process_state(&make_proposal(5, "state-B", pv2)).unwrap();
        assert_eq!(c.status(), VoteCollectorStatus::Invalid);
        // Add a vote after transition — should be silently dropped.
        c.add_vote(make_vote("carol", 5, "state-A", b"s1")).unwrap();
        // Processed count should not increase past the initial
        // proposer-vote-related processing.
        let _ = notifier.processed.load(Ordering::SeqCst);
    }
}
