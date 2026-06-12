//! State producer. Mirror of
//! `consensus/stateproducer/state_producer.go`.
//!
//! The `StateProducer` mediates concurrent signing requests to the
//! embedded [`SafetyRules`](crate::safety_rules::SafetyRulesT) during
//! state production. The Go version uses an atomic-flag wrapper to
//! allow a non-event-loop thread to sign while guaranteeing memory
//! ordering; the Rust port uses an `Arc<Mutex<_>>` around the safety
//! rules, which provides the same guarantee without manual fences.
//!
//! The producer's core flow is:
//!
//! 1. Ask the [`LeaderProvider`] to build an unsigned next state.
//! 2. Wrap the new state in a proposal with the parent's QC and
//!    (optionally) the previous rank's TC.
//! 3. Use safety-rules to sign our own proposal — the signature is
//!    conceptually a vote.

use std::sync::{Arc, Mutex};

use crate::leader_provider::LeaderProvider;
use crate::models::{
    Proposal, QuorumCertificate, SignedProposal, State, TimeoutCertificate, Unique,
};
use crate::safety_rules::SafetyRulesT;
use quil_types::error::{QuilError, Result};

/// Concrete state producer. Mirror of Go's `StateProducer`.
pub struct StateProducer<S: Unique, V: Unique> {
    safety_rules: Arc<Mutex<dyn SafetyRulesT<S, V>>>,
    leader_provider: Arc<dyn LeaderProvider<S>>,
}

impl<S: Unique, V: Unique> StateProducer<S, V> {
    pub fn new(
        safety_rules: Arc<Mutex<dyn SafetyRulesT<S, V>>>,
        leader_provider: Arc<dyn LeaderProvider<S>>,
    ) -> Self {
        Self {
            safety_rules,
            leader_provider,
        }
    }

    /// Build a new signed HotStuff state proposal on top of `qc`, with
    /// an optional TC for the previous rank.
    ///
    /// Error returns:
    /// - `QuilError::NoVote` — safety rules refused to sign (we've
    ///   already proposed or timed out for `rank`).
    /// - Wrapped generic error on any other failure.
    pub fn make_state_proposal(
        &self,
        rank: u64,
        qc: Arc<dyn QuorumCertificate>,
        previous_rank_timeout_cert: Option<Arc<dyn TimeoutCertificate>>,
    ) -> Result<SignedProposal<S, V>> {
        let new_state = self
            .leader_provider
            .prove_next_state(rank, qc.filter(), qc.identity())
            .map_err(|e| {
                if e.is_no_vote() {
                    QuilError::NoVote(format!(
                        "unsafe to vote for own proposal on top of {}: {}",
                        hex::encode(qc.identity()),
                        e
                    ))
                } else {
                    QuilError::Consensus(format!(
                        "could not build state proposal on top of {}: {}",
                        hex::encode(qc.identity()),
                        e
                    ))
                }
            })?;

        // Wrap the state in a Proposal linked back to the parent QC
        // and (optionally) the prior TC.
        let proposal = state_from(new_state, &qc, previous_rank_timeout_cert);

        // Sign our own proposal through safety rules. Conceptually
        // a vote.
        let vote = {
            let mut sr = self.safety_rules.lock().unwrap();
            sr.sign_own_proposal(&proposal).map_err(|e| {
                if e.is_no_vote() {
                    QuilError::NoVote(format!(
                        "unsafe to sign own proposal on top of {}: {}",
                        hex::encode(qc.identity()),
                        e
                    ))
                } else {
                    QuilError::Consensus(format!(
                        "could not vote on state proposal on top of {}: {}",
                        hex::encode(qc.identity()),
                        e
                    ))
                }
            })?
        };

        Ok(SignedProposal { proposal, vote })
    }
}

/// Build a [`Proposal`] from a fresh state + its parent QC, plus an
/// optional TC reference. Mirror of Go's `models.ProposalFrom` +
/// `models.StateFrom` helpers.
///
/// `state` is expected to carry application fields for the new rank;
/// `parent_qc` gives the identifier/rank of the state it builds on.
fn state_from<S: Unique>(
    mut state: State<S>,
    parent_qc: &Arc<dyn QuorumCertificate>,
    previous_rank_timeout_cert: Option<Arc<dyn TimeoutCertificate>>,
) -> Proposal<S> {
    // Ensure the state's parent-QC fields match the actual QC that's
    // linking it back. Go reconstructs this via `StateFrom`.
    state.parent_qc_identity = parent_qc.identity().clone();
    state.parent_qc_rank = parent_qc.rank();
    // Note: `state.parent_quorum_certificate` stays as the leader
    // provider left it (typically `None`). Populating it here would
    // mean the leader's locally-held State carries the QC arc, but
    // peers' wire-decoded copies don't — divergence we'd rather
    // avoid since it complicates equality checks. Receivers populate
    // the field on the wire-decode side (`consensus_types.rs`).
    Proposal {
        state,
        parent_quorum_certificate: Arc::clone(parent_qc),
        previous_rank_timeout_certificate: previous_rank_timeout_cert,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AggregatedSignature, Identity};
    use crate::safety_rules::SafetyRulesT;
    use std::sync::Mutex as StdMutex;

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
    struct TVote {
        id: Identity,
        rank: u64,
    }
    impl Unique for TVote {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &[] }
    }

    // ---------- stubs ----------
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
        filter: Vec<u8>,
    }
    impl QuorumCertificate for StubQc {
        fn filter(&self) -> &[u8] { &self.filter }
        fn rank(&self) -> u64 { self.rank }
        fn frame_number(&self) -> u64 { 0 }
        fn identity(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, o: &dyn QuorumCertificate) -> bool {
            self.rank == o.rank() && self.id == *o.identity()
        }
    }

    // Leader provider that returns a canned State.
    struct StubLeaderProvider {
        calls: StdMutex<Vec<(u64, Vec<u8>, Identity)>>,
        return_err: Option<QuilError>,
    }
    impl StubLeaderProvider {
        fn new() -> Self {
            Self {
                calls: StdMutex::new(vec![]),
                return_err: None,
            }
        }
        fn with_err(err: QuilError) -> Self {
            Self {
                calls: StdMutex::new(vec![]),
                return_err: Some(err),
            }
        }
    }
    impl LeaderProvider<AppState> for StubLeaderProvider {
        fn get_next_leaders(&self, _prior: Option<&State<AppState>>) -> Result<Vec<Identity>> {
            Ok(vec!["leader".into()])
        }
        fn prove_next_state(
            &self,
            rank: u64,
            filter: &[u8],
            prior_state: &Identity,
        ) -> Result<State<AppState>> {
            self.calls
                .lock()
                .unwrap()
                .push((rank, filter.to_vec(), prior_state.clone()));
            if let Some(e) = &self.return_err {
                // Clone-by-match since QuilError isn't Clone.
                return Err(match e {
                    QuilError::NoVote(s) => QuilError::NoVote(s.clone()),
                    QuilError::Consensus(s) => QuilError::Consensus(s.clone()),
                    _ => QuilError::Consensus("test".into()),
                });
            }
            Ok(State {
                rank,
                identifier: format!("state-{}", rank).into_bytes(),
                proposer_id: b"leader".to_vec(),
                parent_qc_identity: prior_state.clone(),
                parent_qc_rank: rank.saturating_sub(1),
                parent_quorum_certificate: None,
                timestamp: 0,
                state: AppState {
                    id: format!("state-{}", rank).into_bytes(),
                    rank,
                },
            })
        }
    }

    // Safety rules stub that always votes successfully unless configured to fail.
    struct StubSafetyRules {
        sign_own_count: u64,
        fail_with: Option<QuilError>,
    }
    impl SafetyRulesT<AppState, TVote> for StubSafetyRules {
        fn produce_vote(
            &mut self,
            _proposal: &SignedProposal<AppState, TVote>,
            _current_rank: u64,
        ) -> Result<TVote> {
            Err(QuilError::Internal("produce_vote not supported in stub".into()))
        }
        fn produce_timeout(
            &mut self,
            _cur_rank: u64,
            _newest_qc: Arc<dyn QuorumCertificate>,
            _prior: Option<Arc<dyn TimeoutCertificate>>,
        ) -> Result<crate::models::TimeoutState<TVote>> {
            Err(QuilError::Internal("produce_timeout not supported in stub".into()))
        }
        fn sign_own_proposal(&mut self, proposal: &Proposal<AppState>) -> Result<TVote> {
            self.sign_own_count += 1;
            if let Some(e) = &self.fail_with {
                return Err(match e {
                    QuilError::NoVote(s) => QuilError::NoVote(s.clone()),
                    _ => QuilError::Consensus("test".into()),
                });
            }
            Ok(TVote {
                id: format!("vote-{}", proposal.state.rank).into_bytes(),
                rank: proposal.state.rank,
            })
        }
    }

    fn make_qc(rank: u64, id: &str) -> Arc<dyn QuorumCertificate> {
        Arc::new(StubQc {
            rank,
            id: id.into(),
            filter: b"filter".to_vec(),
        })
    }

    // ---------- tests ----------
    #[test]
    fn make_state_proposal_happy_path() {
        let sr = Arc::new(Mutex::new(StubSafetyRules {
            sign_own_count: 0,
            fail_with: None,
        })) as Arc<Mutex<dyn SafetyRulesT<AppState, TVote>>>;
        let lp = Arc::new(StubLeaderProvider::new());
        let producer = StateProducer::new(sr.clone(), lp.clone());
        let qc = make_qc(4, "parent-4");
        let sp = producer.make_state_proposal(5, qc, None).unwrap();
        assert_eq!(sp.proposal.state.rank, 5);
        assert_eq!(sp.proposal.state.parent_qc_rank, 4);
        assert_eq!(sp.proposal.state.parent_qc_identity, b"parent-4".to_vec());
        assert_eq!(sp.vote.rank, 5);
        let calls = lp.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 5);
        assert_eq!(calls[0].1, b"filter");
        assert_eq!(calls[0].2, b"parent-4".to_vec());
    }

    #[test]
    fn leader_provider_no_vote_bubbles_as_no_vote() {
        let sr = Arc::new(Mutex::new(StubSafetyRules {
            sign_own_count: 0,
            fail_with: None,
        })) as Arc<Mutex<dyn SafetyRulesT<AppState, TVote>>>;
        let lp = Arc::new(StubLeaderProvider::with_err(QuilError::NoVote(
            "unsafe".into(),
        )));
        let producer = StateProducer::new(sr, lp);
        let qc = make_qc(4, "parent-4");
        let err = producer.make_state_proposal(5, qc, None).unwrap_err();
        assert!(err.is_no_vote());
    }

    #[test]
    fn safety_rules_no_vote_bubbles_as_no_vote() {
        let sr = Arc::new(Mutex::new(StubSafetyRules {
            sign_own_count: 0,
            fail_with: Some(QuilError::NoVote("already voted".into())),
        })) as Arc<Mutex<dyn SafetyRulesT<AppState, TVote>>>;
        let lp = Arc::new(StubLeaderProvider::new());
        let producer = StateProducer::new(sr, lp);
        let qc = make_qc(4, "parent-4");
        let err = producer.make_state_proposal(5, qc, None).unwrap_err();
        assert!(err.is_no_vote());
    }

    #[test]
    fn includes_prior_rank_timeout_cert() {
        use crate::models::TimeoutCertificate;
        #[derive(Debug)]
        struct StubTc { rank: u64, latest_qc: StubQc }
        impl TimeoutCertificate for StubTc {
            fn filter(&self) -> &[u8] { &[] }
            fn rank(&self) -> u64 { self.rank }
            fn latest_ranks(&self) -> &[u64] { &[] }
            fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { &self.latest_qc }
            fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
            fn equals(&self, o: &dyn TimeoutCertificate) -> bool { self.rank == o.rank() }
        }

        let sr = Arc::new(Mutex::new(StubSafetyRules {
            sign_own_count: 0,
            fail_with: None,
        })) as Arc<Mutex<dyn SafetyRulesT<AppState, TVote>>>;
        let lp = Arc::new(StubLeaderProvider::new());
        let producer = StateProducer::new(sr, lp);
        let qc = make_qc(4, "parent-4");
        let tc: Arc<dyn TimeoutCertificate> = Arc::new(StubTc {
            rank: 4,
            latest_qc: StubQc { rank: 3, id: "qc-3".into(), filter: vec![] },
        });
        let sp = producer.make_state_proposal(5, qc, Some(tc)).unwrap();
        assert!(sp.proposal.previous_rank_timeout_certificate.is_some());
    }
}
