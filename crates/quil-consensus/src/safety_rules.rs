//! HotStuff safety rules. Mirror of
//! `consensus/safetyrules/safety_rules.go`.
//!
//! SafetyRules is the sole authority on producing votes and timeouts for a
//! replica. It enforces the HotStuff voting / timeout rules so the signer
//! never mints an artifact that could break consensus safety.
//!
//! # Voting rules
//!
//! 1. Replicas vote in strictly increasing ranks, at most one vote per rank.
//!    The leader's own-proposal signature is formally a vote for its own
//!    state.
//! 2. Each state must include either a QC or a TC from the previous rank:
//!    - **Happy path:** the previous rank resulted in a QC, which the new
//!      proposer includes in its state. No TC is allowed.
//!    - **Recovery path:** the previous rank did not result in a QC; the
//!      new proposer must include a valid TC for the previous rank.
//!
//! # Safety theorem
//!
//! Condition 1 + 2 together imply: **for each rank, there can be at most
//! one certified state**. This is the foundational safety invariant of
//! HotStuff / DiemBFT / Jolteon.
//!
//! # Concurrency
//!
//! `SafetyRules` is **not safe for concurrent use**. The event-loop
//! serializes all calls on a single task.

use std::sync::Arc;

use crate::committee::DynamicCommittee;
use crate::event_handler::ConsensusStore;
use crate::models::{
    Identity, Proposal, QuorumCertificate, SignedProposal, TimeoutCertificate,
    TimeoutState, Unique,
};
use crate::signer::Signer;
use quil_types::error::{QuilError, Result};

/// Trait surface for safety-rules implementations (so tests and engines can
/// swap in stubs). The concrete impl is `SafetyRules` below.
pub trait SafetyRulesT<S: Unique, V: Unique>: Send + Sync {
    /// Produce a vote for a valid proposal, or return a sentinel
    /// `QuilError::NoVote` if safety rules prevent it.
    fn produce_vote(
        &mut self,
        proposal: &SignedProposal<S, V>,
        current_rank: u64,
    ) -> Result<V>;

    /// Produce a timeout for the current rank, or `QuilError::NoTimeout` if
    /// this node is not authorized to participate.
    fn produce_timeout(
        &mut self,
        current_rank: u64,
        newest_qc: Arc<dyn QuorumCertificate>,
        previous_rank_timeout_certificate: Option<Arc<dyn TimeoutCertificate>>,
    ) -> Result<TimeoutState<V>>;

    /// Sign our own unsigned proposal (the leader votes for its own block).
    fn sign_own_proposal(&mut self, proposal: &Proposal<S>) -> Result<V>;
}

/// Concrete HotStuff safety-rules implementation. Mirror of Go's
/// `safetyrules.SafetyRules[StateT, VoteT]`.
///
/// The struct is parameterized over the application state type `S` and
/// vote type `V`, both of which must implement [`Unique`].
pub struct SafetyRules<S: Unique, V: Unique> {
    filter: Vec<u8>,
    signer: Arc<dyn Signer<S, V>>,
    store: Arc<dyn ConsensusStore<V>>,
    committee: Arc<dyn DynamicCommittee>,
    finalized_rank: u64,
    latest_acknowledged_rank: u64,
    latest_timeout: Option<TimeoutState<V>>,
}

impl<S: Unique, V: Unique> SafetyRules<S, V> {
    /// Load persisted consensus state for `filter` from `store` and build
    /// a new `SafetyRules`. Mirror of `NewSafetyRules`.
    pub fn new(
        filter: Vec<u8>,
        signer: Arc<dyn Signer<S, V>>,
        store: Arc<dyn ConsensusStore<V>>,
        committee: Arc<dyn DynamicCommittee>,
    ) -> Result<Self> {
        let state = store.get_consensus_state(&filter).map_err(|e| {
            QuilError::Consensus(format!("could not load safety data: {}", e))
        })?;
        Ok(Self {
            filter,
            signer,
            store,
            committee,
            finalized_rank: state.finalized_rank,
            latest_acknowledged_rank: state.latest_acknowledged_rank,
            latest_timeout: state.latest_timeout,
        })
    }

    /// Persist the current in-memory consensus state. Mirror of
    /// `store.PutConsensusState`.
    fn persist_state(&self) -> Result<()> {
        let snapshot = crate::models::ConsensusState {
            filter: self.filter.clone(),
            finalized_rank: self.finalized_rank,
            latest_acknowledged_rank: self.latest_acknowledged_rank,
            latest_timeout: self.latest_timeout.clone(),
        };
        self.store.put_consensus_state(&snapshot)
    }

    /// Core vote-production logic used both for other leaders' proposals
    /// and for signing this node's own proposals. Mirror of
    /// `SafetyRules.produceVote`.
    fn produce_vote_inner(
        &mut self,
        proposal: &Proposal<S>,
        cur_rank: u64,
    ) -> Result<V> {
        let state = &proposal.state;

        // Sanity: proposal rank must equal current rank.
        if cur_rank != state.rank {
            return Err(QuilError::Consensus(format!(
                "expecting state for current rank {}, but state's rank is {}",
                cur_rank, state.rank,
            )));
        }

        self.is_safe_to_vote(proposal)?;

        // Proposer sanity: the proposal must come from the rank's leader.
        let current_leader = self
            .committee
            .leader_for_rank(state.rank)
            .map_err(|e| {
                QuilError::Consensus(format!(
                    "expect to have a valid leader for rank {}: {}",
                    cur_rank, e
                ))
            })?;
        if state.proposer_id != current_leader {
            return Err(QuilError::Consensus(format!(
                "incorrect proposal, proposer {} differs from leader {} for rank {}",
                hex::encode(&state.proposer_id), hex::encode(&current_leader), cur_rank
            )));
        }

        // If we're not the leader, verify membership of proposer and self.
        // When we ARE the leader, the committee membership check would only
        // reject on self-ejection (already harmless) so we skip it.
        let self_id = self.committee.self_identity().clone();
        if current_leader != self_id {
            // (i) Proposer must be an active committee member for this
            // state. Ejected → NoVote sentinel.
            match self
                .committee
                .identity_by_state(&state.identifier, &state.proposer_id)
            {
                Ok(_) => {}
                Err(e) if e.is_invalid_signer() => {
                    return Err(QuilError::NoVote(format!(
                        "proposer ejected: {}",
                        e
                    )));
                }
                Err(e) => {
                    return Err(QuilError::Consensus(format!(
                        "internal error retrieving identity of proposer {} at state {}: {}",
                        hex::encode(&state.proposer_id), hex::encode(&state.identifier), e
                    )));
                }
            }

            // (ii) We ourselves must be an active committee member.
            match self
                .committee
                .identity_by_state(&state.identifier, &self_id)
            {
                Ok(_) => {}
                Err(e) if e.is_invalid_signer() => {
                    return Err(QuilError::NoVote(format!(
                        "I am not authorized to vote for state {}: {}",
                        hex::encode(&state.identifier), e
                    )));
                }
                Err(e) => {
                    return Err(QuilError::Consensus(format!(
                        "could not get self identity: {}",
                        e
                    )));
                }
            }
        }

        let vote = self
            .signer
            .create_vote(state)
            .map_err(|e| QuilError::Consensus(format!("could not vote for state: {}", e)))?;

        // Successfully produced a vote — update persisted state.
        self.latest_acknowledged_rank = cur_rank;
        if self.finalized_rank < state.parent_qc_rank {
            self.finalized_rank = state.parent_qc_rank;
        }
        self.persist_state()?;

        Ok(vote)
    }

    /// Voting rule 1: a replica votes at strictly increasing ranks, and at
    /// most once per rank. Mirror of `isSafeToVote`.
    fn is_safe_to_vote(&self, proposal: &Proposal<S>) -> Result<()> {
        let state_rank = proposal.state.rank;

        // Voting rule 2 (evidence for entering rank).
        self.validate_evidence_for_entering_rank(
            state_rank,
            proposal.state.parent_qc_rank,
            proposal.previous_rank_timeout_certificate.as_deref(),
        )
        .map_err(|e| {
            // Pre-validated states should never hit this path — treat it
            // as an internal bug rather than a sentinel.
            QuilError::Consensus(format!("proposal failed consensus validity check: {}", e))
        })?;

        let ac_rank = self.latest_acknowledged_rank;
        if state_rank == ac_rank {
            return Err(QuilError::NoVote(format!(
                "already voted or generated timeout in rank {}",
                state_rank
            )));
        }
        if state_rank < ac_rank {
            return Err(QuilError::Consensus(format!(
                "already acted during rank {} but got proposal for lower rank {}",
                ac_rank, state_rank
            )));
        }
        Ok(())
    }

    /// Rank-entry evidence check. Mirror of
    /// `validateEvidenceForEnteringRank`.
    ///
    /// Uses `newest_qc_rank` directly rather than a `&dyn QuorumCertificate`
    /// because the `State` model carries only the parent QC rank — the full
    /// QC is held in the forest.
    fn validate_evidence_for_entering_rank(
        &self,
        rank: u64,
        newest_qc_rank: u64,
        previous_rank_timeout_cert: Option<&dyn TimeoutCertificate>,
    ) -> Result<()> {
        // Condition 2: happy path. newestQC.Rank + 1 == rank.
        if newest_qc_rank + 1 == rank {
            if let Some(tc) = previous_rank_timeout_cert {
                return Err(QuilError::Consensus(format!(
                    "when QC is for prior round ({}), no TC should be provided ({})",
                    newest_qc_rank,
                    tc.rank(),
                )));
            }
            return Ok(());
        }

        // Condition 4: recovery path.
        let tc = match previous_rank_timeout_cert {
            Some(tc) => tc,
            None => {
                return Err(QuilError::Consensus(format!(
                    "expecting TC because QC ({}) is not for prior rank ({} - 1); but didn't get any TC",
                    newest_qc_rank, rank
                )));
            }
        };
        if tc.rank() + 1 != rank {
            return Err(QuilError::Consensus(format!(
                "neither QC (rank {}) nor TC (rank {}) allows to transition to rank {}",
                newest_qc_rank,
                tc.rank(),
                rank
            )));
        }
        if newest_qc_rank >= rank {
            return Err(QuilError::Consensus(format!(
                "still at rank {}, despite knowing a QC for rank {}",
                rank, newest_qc_rank
            )));
        }
        let tc_latest_qc_rank = tc.latest_quorum_cert().rank();
        if newest_qc_rank < tc_latest_qc_rank {
            return Err(QuilError::Consensus(format!(
                "failed to update newest QC (still at rank {}) despite a newer QC (rank {}) being included in TC",
                newest_qc_rank, tc_latest_qc_rank
            )));
        }
        Ok(())
    }

    /// Timeout-rule precheck. Mirror of `IsSafeToTimeout`.
    pub fn is_safe_to_timeout(
        &self,
        cur_rank: u64,
        newest_qc: &dyn QuorumCertificate,
        previous_rank_timeout_cert: Option<&dyn TimeoutCertificate>,
    ) -> Result<()> {
        self.validate_evidence_for_entering_rank(
            cur_rank,
            newest_qc.rank(),
            previous_rank_timeout_cert,
        )
        .map_err(|e| QuilError::Consensus(format!("not safe to timeout: {}", e)))?;

        if newest_qc.rank() < self.finalized_rank {
            return Err(QuilError::Consensus(format!(
                "have already seen QC for rank {}, but newest QC is reported to be for rank {}",
                self.finalized_rank,
                newest_qc.rank()
            )));
        }
        if cur_rank + 1 <= self.latest_acknowledged_rank {
            return Err(QuilError::Consensus(format!(
                "cannot generate timeout for past rank {}",
                cur_rank
            )));
        }
        Ok(())
    }

    /// Convenience: expose the latest acknowledged rank for tests/diagnostics.
    pub fn latest_acknowledged_rank(&self) -> u64 {
        self.latest_acknowledged_rank
    }

    /// Convenience: expose the finalized rank for tests/diagnostics.
    pub fn finalized_rank(&self) -> u64 {
        self.finalized_rank
    }
}

impl<S: Unique, V: Unique> SafetyRulesT<S, V> for SafetyRules<S, V> {
    fn produce_vote(
        &mut self,
        proposal: &SignedProposal<S, V>,
        current_rank: u64,
    ) -> Result<V> {
        self.produce_vote_inner(&proposal.proposal, current_rank)
    }

    fn produce_timeout(
        &mut self,
        cur_rank: u64,
        newest_qc: Arc<dyn QuorumCertificate>,
        previous_rank_timeout_certificate: Option<Arc<dyn TimeoutCertificate>>,
    ) -> Result<TimeoutState<V>> {
        // Idempotent re-broadcast: if we've already timed out for this
        // exact rank, just bump the tick counter.
        if let Some(last) = &self.latest_timeout {
            if last.rank == cur_rank {
                let updated = TimeoutState {
                    rank: last.rank,
                    latest_quorum_certificate: Arc::clone(&last.latest_quorum_certificate),
                    prior_rank_timeout_certificate: last
                        .prior_rank_timeout_certificate
                        .as_ref()
                        .map(Arc::clone),
                    timeout_tick: last.timeout_tick + 1,
                    vote: last.vote.clone(),
                };
                self.latest_timeout = Some(updated.clone());
                self.persist_state()?;
                return Ok(updated);
            }
        }

        self.is_safe_to_timeout(
            cur_rank,
            newest_qc.as_ref(),
            previous_rank_timeout_certificate.as_deref(),
        )
        .map_err(|e| {
            QuilError::Consensus(format!(
                "local, trusted inputs failed safety rules: {}",
                e
            ))
        })?;

        // Not an active committee member → NoTimeout sentinel.
        let self_id = self.committee.self_identity().clone();
        match self.committee.identity_by_rank(cur_rank, &self_id) {
            Ok(_) => {}
            Err(e) if e.is_invalid_signer() => {
                return Err(QuilError::NoTimeout(format!(
                    "I am not authorized to timeout for rank {}: {}",
                    cur_rank, e
                )));
            }
            Err(e) => {
                return Err(QuilError::Consensus(format!(
                    "could not get self identity: {}",
                    e
                )));
            }
        }

        let timeout = self
            .signer
            .create_timeout(
                cur_rank,
                Arc::clone(&newest_qc),
                previous_rank_timeout_certificate.as_ref().map(Arc::clone),
            )
            .map_err(|e| {
                QuilError::Consensus(format!(
                    "could not create timeout at rank {}: {}",
                    cur_rank, e
                ))
            })?;

        self.latest_acknowledged_rank = cur_rank;
        self.latest_timeout = Some(timeout.clone());
        self.persist_state()?;
        Ok(timeout)
    }

    fn sign_own_proposal(&mut self, unsigned: &Proposal<S>) -> Result<V> {
        let self_id: &Identity = self.committee.self_identity();
        if &unsigned.state.proposer_id != self_id {
            return Err(QuilError::Consensus(format!(
                "can't sign proposal for someone else's state, proposer: {}, self: {}",
                hex::encode(&unsigned.state.proposer_id), hex::encode(self_id)
            )));
        }
        let rank = unsigned.state.rank;
        self.produce_vote_inner(unsigned, rank)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AggregatedSignature, ConsensusState, LivenessState, State, WeightedIdentity,
    };
    use std::fmt::Debug;
    use std::sync::Mutex;

    // ---------- Unique state/vote stubs ----------

    #[derive(Debug, Clone)]
    struct TestState {
        id: Identity,
        source: Identity,
        rank: u64,
    }
    impl Unique for TestState {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.source }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &[] }
    }

    #[derive(Debug, Clone)]
    struct TestVote {
        id: Identity,
        source: Identity,
        rank: u64,
    }
    impl Unique for TestVote {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.source }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &[] }
    }

    // ---------- Aggregated sig stub ----------

    #[derive(Debug)]
    struct StubAgg;
    impl AggregatedSignature for StubAgg {
        fn signature(&self) -> &[u8] { &[] }
        fn public_key(&self) -> &[u8] { &[] }
        fn bitmask(&self) -> &[u8] { &[] }
    }

    // ---------- QC / TC stubs ----------

    #[derive(Debug)]
    struct StubQc {
        rank: u64,
        identity: Identity,
    }
    impl QuorumCertificate for StubQc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn frame_number(&self) -> u64 { 0 }
        fn identity(&self) -> &Identity { &self.identity }
        fn timestamp(&self) -> u64 { 0 }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, other: &dyn QuorumCertificate) -> bool {
            self.rank == other.rank() && self.identity == *other.identity()
        }
    }

    #[derive(Debug)]
    struct StubTc {
        rank: u64,
        latest_qc: StubQc,
    }
    impl TimeoutCertificate for StubTc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn latest_ranks(&self) -> &[u64] { &[] }
        fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { &self.latest_qc }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, other: &dyn TimeoutCertificate) -> bool {
            self.rank == other.rank()
        }
    }

    // ---------- Committee stub ----------

    #[derive(Debug)]
    struct StubIdentity {
        id: Identity,
    }
    impl WeightedIdentity for StubIdentity {
        fn public_key(&self) -> &[u8] { &[] }
        fn identity(&self) -> &Identity { &self.id }
        fn weight(&self) -> u64 { 1 }
    }

    struct StubCommittee {
        self_id: Identity,
        leader: Identity,
        /// Identities that should trigger InvalidSigner in
        /// `identity_by_state` / `identity_by_rank`.
        ejected: Vec<Identity>,
    }
    impl crate::committee::Replicas for StubCommittee {
        fn leader_for_rank(&self, _rank: u64) -> Result<Identity> {
            Ok(self.leader.clone())
        }
        fn quorum_threshold_for_rank(&self, _rank: u64) -> Result<u64> { Ok(2) }
        fn timeout_threshold_for_rank(&self, _rank: u64) -> Result<u64> { Ok(1) }
        fn self_identity(&self) -> &Identity { &self.self_id }
        fn identities_by_rank(&self, _r: u64) -> Result<Vec<Box<dyn WeightedIdentity>>> {
            Ok(vec![])
        }
        fn identity_by_rank(
            &self,
            _r: u64,
            pid: &Identity,
        ) -> Result<Box<dyn WeightedIdentity>> {
            if self.ejected.contains(pid) {
                return Err(QuilError::InvalidSigner(format!(
                    "{} ejected",
                    hex::encode(pid)
                )));
            }
            Ok(Box::new(StubIdentity { id: pid.clone() }))
        }
    }
    impl DynamicCommittee for StubCommittee {
        fn identities_by_state(
            &self,
            _s: &Identity,
        ) -> Result<Vec<Box<dyn WeightedIdentity>>> {
            Ok(vec![])
        }
        fn identity_by_state(
            &self,
            _s: &Identity,
            pid: &Identity,
        ) -> Result<Box<dyn WeightedIdentity>> {
            if self.ejected.contains(pid) {
                return Err(QuilError::InvalidSigner(format!("{} ejected", hex::encode(pid))));
            }
            Ok(Box::new(StubIdentity { id: pid.clone() }))
        }
    }

    // ---------- ConsensusStore stub ----------

    #[derive(Default)]
    struct StubStore {
        saved: Mutex<Option<ConsensusState<TestVote>>>,
    }
    impl ConsensusStore<TestVote> for StubStore {
        fn get_consensus_state(&self, filter: &[u8]) -> Result<ConsensusState<TestVote>> {
            Ok(ConsensusState {
                filter: filter.to_vec(),
                finalized_rank: 0,
                latest_acknowledged_rank: 0,
                latest_timeout: None,
            })
        }
        fn put_consensus_state(
            &self,
            state: &ConsensusState<TestVote>,
        ) -> Result<()> {
            *self.saved.lock().unwrap() = Some(state.clone());
            Ok(())
        }
        fn get_liveness_state(&self, filter: &[u8]) -> Result<LivenessState> {
            Ok(LivenessState {
                filter: filter.to_vec(),
                current_rank: 0,
                latest_quorum_certificate: Arc::new(StubQc {
                    rank: 0,
                    identity: "genesis".into(),
                }),
                prior_rank_timeout_certificate: None,
            })
        }
        fn put_liveness_state(&self, _s: &LivenessState) -> Result<()> { Ok(()) }
    }

    // ---------- Signer stub ----------

    struct StubSigner;
    impl Signer<TestState, TestVote> for StubSigner {
        fn create_vote(&self, state: &State<TestState>) -> Result<TestVote> {
            Ok(TestVote {
                id: state.identifier.clone(),
                source: state.proposer_id.clone(),
                rank: state.rank,
            })
        }
        fn create_timeout(
            &self,
            cur_rank: u64,
            newest_qc: Arc<dyn QuorumCertificate>,
            prior: Option<Arc<dyn TimeoutCertificate>>,
        ) -> Result<TimeoutState<TestVote>> {
            Ok(TimeoutState {
                rank: cur_rank,
                latest_quorum_certificate: newest_qc,
                prior_rank_timeout_certificate: prior,
                vote: TestVote {
                    id: format!("timeout-{}", cur_rank).into_bytes(),
                    source: b"self".to_vec(),
                    rank: cur_rank,
                },
                timeout_tick: 0,
            })
        }
    }

    // ---------- Builders ----------

    fn make_proposal(rank: u64, parent_qc_rank: u64, leader: &str) -> Proposal<TestState> {
        Proposal {
            state: State {
                rank,
                identifier: format!("state-{}", rank).into_bytes(),
                proposer_id: leader.into(),
                parent_qc_identity: format!("qc-{}", parent_qc_rank).into_bytes(),
                parent_qc_rank,
                parent_quorum_certificate: None,
                timestamp: 0,
                state: TestState {
                    id: format!("state-{}", rank).into_bytes(),
                    source: leader.into(),
                    rank,
                },
            },
            parent_quorum_certificate: Arc::new(StubQc {
                rank: parent_qc_rank,
                identity: format!("qc-{}", parent_qc_rank).into_bytes(),
            }),
            previous_rank_timeout_certificate: None,
        }
    }

    fn make_signed_proposal(
        rank: u64,
        parent_qc_rank: u64,
        leader: &str,
    ) -> SignedProposal<TestState, TestVote> {
        SignedProposal {
            proposal: make_proposal(rank, parent_qc_rank, leader),
            vote: TestVote {
                id: format!("vote-{}", rank).into_bytes(),
                source: leader.into(),
                rank,
            },
        }
    }

    fn make_rules(
        self_id: &str,
        leader: &str,
        ejected: Vec<Identity>,
    ) -> SafetyRules<TestState, TestVote> {
        let committee: Arc<dyn DynamicCommittee> = Arc::new(StubCommittee {
            self_id: self_id.into(),
            leader: leader.into(),
            ejected,
        });
        let store: Arc<dyn ConsensusStore<TestVote>> = Arc::new(StubStore::default());
        let signer: Arc<dyn Signer<TestState, TestVote>> = Arc::new(StubSigner);
        SafetyRules::new(b"filter".to_vec(), signer, store, committee).unwrap()
    }

    // ---------- Tests ----------

    #[test]
    fn happy_path_vote_is_produced() {
        let mut rules = make_rules("self", "leader", vec![]);
        let sp = make_signed_proposal(5, 4, "leader");
        let vote = rules.produce_vote(&sp, 5).expect("vote should be produced");
        assert_eq!(vote.rank, 5);
        assert_eq!(rules.latest_acknowledged_rank(), 5);
        assert_eq!(rules.finalized_rank(), 4);
    }

    #[test]
    fn double_vote_same_rank_is_no_vote() {
        let mut rules = make_rules("self", "leader", vec![]);
        let sp = make_signed_proposal(5, 4, "leader");
        rules.produce_vote(&sp, 5).unwrap();
        let err = rules.produce_vote(&sp, 5).unwrap_err();
        assert!(err.is_no_vote(), "expected NoVote, got {:?}", err);
    }

    #[test]
    fn vote_for_lower_rank_after_action_is_internal_error() {
        let mut rules = make_rules("self", "leader", vec![]);
        rules.produce_vote(&make_signed_proposal(5, 4, "leader"), 5).unwrap();
        // Proposal at an older rank — this should NOT be NoVote, it should
        // be a hard error (stale states bypassed pre-validation).
        let err = rules
            .produce_vote(&make_signed_proposal(4, 3, "leader"), 4)
            .unwrap_err();
        assert!(!err.is_no_vote(), "expected hard error, got {:?}", err);
    }

    #[test]
    fn proposer_not_leader_errors() {
        let mut rules = make_rules("self", "leader", vec![]);
        let sp = make_signed_proposal(5, 4, "not-the-leader");
        let err = rules.produce_vote(&sp, 5).unwrap_err();
        // Sanity check: message mentions leader mismatch.
        assert!(format!("{}", err).contains("proposer"));
    }

    #[test]
    fn rank_mismatch_errors() {
        let mut rules = make_rules("self", "leader", vec![]);
        let sp = make_signed_proposal(5, 4, "leader");
        let err = rules.produce_vote(&sp, 6).unwrap_err();
        assert!(format!("{}", err).contains("current rank 6"));
    }

    #[test]
    fn ejected_proposer_yields_no_vote() {
        let mut rules = make_rules("self", "leader", vec!["leader".into()]);
        let sp = make_signed_proposal(5, 4, "leader");
        let err = rules.produce_vote(&sp, 5).unwrap_err();
        assert!(err.is_no_vote(), "expected NoVote, got {:?}", err);
    }

    #[test]
    fn ejected_self_yields_no_vote() {
        let mut rules = make_rules("self", "leader", vec!["self".into()]);
        let sp = make_signed_proposal(5, 4, "leader");
        let err = rules.produce_vote(&sp, 5).unwrap_err();
        assert!(err.is_no_vote(), "expected NoVote, got {:?}", err);
    }

    #[test]
    fn happy_path_missing_tc_required_errors() {
        // Proposal at rank 5 with parent QC at rank 2 → recovery path
        // requires a TC. Missing TC → internal error.
        let mut rules = make_rules("self", "leader", vec![]);
        let sp = make_signed_proposal(5, 2, "leader");
        let err = rules.produce_vote(&sp, 5).unwrap_err();
        assert!(format!("{}", err).contains("TC"));
    }

    #[test]
    fn recovery_path_with_valid_tc_votes() {
        let mut rules = make_rules("self", "leader", vec![]);
        let mut sp = make_signed_proposal(5, 2, "leader");
        // TC at rank 4, containing a QC at rank 2 — consistent with
        // newest_qc_rank (2).
        sp.proposal.previous_rank_timeout_certificate = Some(Arc::new(StubTc {
            rank: 4,
            latest_qc: StubQc { rank: 2, identity: "qc".into() },
        }));
        let v = rules.produce_vote(&sp, 5).unwrap();
        assert_eq!(v.rank, 5);
    }

    #[test]
    fn recovery_path_tc_with_stale_newest_qc_errors() {
        // TC advertises a newer QC (rank 4) than our own (rank 2) → bug.
        let mut rules = make_rules("self", "leader", vec![]);
        let mut sp = make_signed_proposal(5, 2, "leader");
        sp.proposal.previous_rank_timeout_certificate = Some(Arc::new(StubTc {
            rank: 4,
            latest_qc: StubQc { rank: 4, identity: "qc".into() },
        }));
        let err = rules.produce_vote(&sp, 5).unwrap_err();
        assert!(format!("{}", err).contains("newest QC"));
    }

    #[test]
    fn produce_timeout_happy_path() {
        let mut rules = make_rules("self", "leader", vec![]);
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 4,
            identity: "qc-4".into(),
        });
        let t = rules.produce_timeout(5, qc, None).unwrap();
        assert_eq!(t.rank, 5);
        assert_eq!(rules.latest_acknowledged_rank(), 5);
    }

    #[test]
    fn produce_timeout_rebroadcast_bumps_tick() {
        let mut rules = make_rules("self", "leader", vec![]);
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 4,
            identity: "qc-4".into(),
        });
        let first = rules.produce_timeout(5, qc.clone(), None).unwrap();
        assert_eq!(first.timeout_tick, 0);
        let second = rules.produce_timeout(5, qc, None).unwrap();
        assert_eq!(second.timeout_tick, 1);
    }

    #[test]
    fn produce_timeout_ejected_self_is_no_timeout() {
        let mut rules = make_rules("self", "leader", vec!["self".into()]);
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 4,
            identity: "qc-4".into(),
        });
        let err = rules.produce_timeout(5, qc, None).unwrap_err();
        assert!(err.is_no_timeout(), "expected NoTimeout, got {:?}", err);
    }

    #[test]
    fn sign_own_proposal_rejects_other_proposer() {
        let mut rules = make_rules("self", "leader", vec![]);
        let p = make_proposal(5, 4, "someone-else");
        let err = rules.sign_own_proposal(&p).unwrap_err();
        assert!(format!("{}", err).contains("someone else"));
    }

    #[test]
    fn sign_own_proposal_self_leader_happy() {
        let mut rules = make_rules("self", "self", vec![]);
        let p = make_proposal(5, 4, "self");
        let v = rules.sign_own_proposal(&p).unwrap();
        assert_eq!(v.rank, 5);
    }
}
