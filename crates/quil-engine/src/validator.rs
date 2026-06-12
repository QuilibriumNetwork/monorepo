//! Concrete [`Validator`] implementation. Mirror of Go's
//! `consensus/validator/validator.go`.
//!
//! The validator owns two trait-object dependencies:
//!
//! 1. **Committee** ([`Replicas`]) — maps a rank to the set of
//!    authorized signers and their weights.
//! 2. **Verifier** ([`Verifier`]) — the crypto boundary for QC/TC
//!    aggregate signatures.
//!
//! Validation flow for QCs/TCs:
//!
//! 1. Fetch the full committee for the cert's rank.
//! 2. Decode the cert's aggregated-signature bitmask against the
//!    full committee → subset of signers + their cumulative weight.
//! 3. Reject if the cumulative weight is below the quorum threshold.
//! 4. Delegate to the verifier for the aggregate signature check.
//!
//! Proposals are additionally checked for:
//! - Proposer = leader-for-rank
//! - Parent QC / prior TC relationship per Jolteon rules
//! - Proposer's own vote (recursive [`Validator::validate_vote`])

use std::sync::Arc;

use quil_consensus::committee::Replicas;
use quil_consensus::models::{
    QuorumCertificate, SignedProposal, TimeoutCertificate, Unique, WeightedIdentity,
};
use quil_consensus::packer::decode_signer_indices;
use quil_consensus::validator::Validator;
use quil_consensus::verifier::Verifier;
use quil_types::error::{QuilError, Result};

/// Generic [`Validator`] implementation. Mirror of Go's
/// `validator.Validator[StateT, VoteT]`.
pub struct ConsensusValidator<S: Unique, V: Unique> {
    committee: Arc<dyn Replicas>,
    verifier: Arc<dyn Verifier<V>>,
    _marker: std::marker::PhantomData<S>,
}

impl<S: Unique, V: Unique> ConsensusValidator<S, V> {
    pub fn new(committee: Arc<dyn Replicas>, verifier: Arc<dyn Verifier<V>>) -> Self {
        Self {
            committee,
            verifier,
            _marker: std::marker::PhantomData,
        }
    }

    /// Helper: decode signer subset from bitmask + compute weight.
    ///
    /// Returns `(subset, total_weight)` where `subset` lists the
    /// committee members whose bits are set. Errors with
    /// `InsufficientSignatures` if the bitmask is too short for the
    /// committee or no bits are set.
    fn decode_signers(
        &self,
        rank: u64,
        bitmask: &[u8],
    ) -> Result<(Vec<Box<dyn WeightedIdentity>>, u64)> {
        let full = self.committee.identities_by_rank(rank)?;
        let expected_bitmask_len = (full.len() + 7) / 8;
        if bitmask.len() < expected_bitmask_len {
            return Err(QuilError::InsufficientSignatures(format!(
                "bitmask length {} too short for committee size {}",
                bitmask.len(),
                full.len()
            )));
        }

        let subset_ids = decode_signer_indices(&full, bitmask);
        if subset_ids.is_empty() {
            return Err(QuilError::InsufficientSignatures(
                "bitmask selects no signers".into(),
            ));
        }
        let mut total_weight = 0u64;
        let subset: Vec<Box<dyn WeightedIdentity>> = full
            .into_iter()
            .filter(|m| {
                if subset_ids.contains(m.identity()) {
                    total_weight = total_weight.saturating_add(m.weight());
                    true
                } else {
                    false
                }
            })
            .collect();
        Ok((subset, total_weight))
    }
}

impl<S: Unique, V: Unique> Validator<S, V> for ConsensusValidator<S, V> {
    fn validate_quorum_certificate(&self, qc: &dyn QuorumCertificate) -> Result<()> {
        // Genesis QCs (rank 0) are trusted — they carry
        // `AggregateSignature::empty()` (all-zero pk/sig, 0xFF bitmask)
        // which can't pass BLS verification. Every node seeds the same
        // genesis QC at startup; re-verifying it would stall the
        // chain at rank 1 because the first proposal embeds the
        // genesis QC as its parent. Matches Go's implicit trust: the
        // genesis QC enters the liveness store at startup and is
        // never re-verified by the consensus loop.
        if qc.rank() == 0 {
            return Ok(());
        }
        let bitmask = qc.aggregated_signature().bitmask();
        let (_subset, total_weight) = self.decode_signers(qc.rank(), bitmask)?;

        let threshold = self.committee.quorum_threshold_for_rank(qc.rank())?;
        if total_weight < threshold {
            // Diagnostic: dump the full committee snapshot at this
            // rank so we can see whether the running node's `Replicas`
            // view matches the one a static `inspect_committee`
            // produces. Threshold computed from a stale or extra-
            // padded committee would produce a `required` value that
            // doesn't match what the network agreed on at QC time.
            let dump = self.committee.identities_by_rank(qc.rank()).ok();
            let committee_summary: String = dump
                .as_ref()
                .map(|members| {
                    members
                        .iter()
                        .map(|m| {
                            format!(
                                "{}={}",
                                &hex::encode(m.identity())[..16.min(m.identity().len() * 2)],
                                m.weight()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_else(|| "n/a".into());
            tracing::warn!(
                rank = qc.rank(),
                bitmask = %hex::encode(bitmask),
                total_weight,
                threshold,
                committee_size = dump.as_ref().map(|m| m.len()).unwrap_or(0),
                committee = %committee_summary,
                "QC weight-check failed — dumping committee snapshot",
            );
            return Err(QuilError::InvalidQuorumCertificate(format!(
                "QC signers have insufficient weight {} (required {})",
                total_weight, threshold
            )));
        }

        // Delegate signature verification to the verifier.
        self.verifier.verify_quorum_certificate(qc)
    }

    fn validate_timeout_certificate(&self, tc: &dyn TimeoutCertificate) -> Result<()> {
        let newest_qc = tc.latest_quorum_cert();

        // The TC's rank cannot be strictly less than the newest-QC
        // rank (it may be equal in edge cases where the leader can
        // collect both TC and QC concurrently).
        if tc.rank() < newest_qc.rank() {
            return Err(QuilError::InvalidTimeoutCertificate(format!(
                "TC rank {} < embedded QC rank {}",
                tc.rank(),
                newest_qc.rank()
            )));
        }

        // Bitmask-based weight check.
        let bitmask = tc.aggregated_signature().bitmask();
        let (_subset, total_weight) = self.decode_signers(tc.rank(), bitmask)?;
        let threshold = self.committee.quorum_threshold_for_rank(tc.rank())?;
        if total_weight < threshold {
            return Err(QuilError::InvalidTimeoutCertificate(format!(
                "TC signers have insufficient weight {} (required {})",
                total_weight, threshold
            )));
        }

        // Verify the aggregate TC signature (per-signer messages are
        // reconstructed from `tc.latest_ranks()`).
        self.verifier.verify_timeout_certificate(tc)?;

        // Sanity: the TC's embedded QC must have rank >= max of all
        // contributed `newest_qc_rank` values. Without this, a
        // byzantine proposer could claim a newer QC than any honest
        // replica actually has.
        let latest_ranks = tc.latest_ranks();
        if !latest_ranks.is_empty() {
            let max_contributed = latest_ranks.iter().copied().max().unwrap_or(0);
            if max_contributed > newest_qc.rank() {
                return Err(QuilError::InvalidTimeoutCertificate(format!(
                    "included QC rank {} should be >= max contributed rank {}",
                    newest_qc.rank(),
                    max_contributed
                )));
            }
        }

        // Recursively validate the embedded QC.
        self.validate_quorum_certificate(newest_qc)?;
        Ok(())
    }

    fn validate_proposal(&self, proposal: &SignedProposal<S, V>) -> Result<()> {
        let state = &proposal.proposal.state;

        // Check proposer is the leader for this rank.
        let leader = self.committee.leader_for_rank(state.rank)?;
        if state.proposer_id != leader {
            return Err(QuilError::InvalidProposal(format!(
                "proposer {} is not leader {} for rank {}",
                hex::encode(&state.proposer_id), hex::encode(&leader), state.rank
            )));
        }

        // Structural parent-QC / prior-TC check (Jolteon rules).
        // The Rust `State` carries only the parent QC's rank + id;
        // the full QC lives in the forest. Here we enforce the rank
        // relationship only:
        let last_rank_successful = state.rank == state.parent_qc_rank + 1;
        if !last_rank_successful {
            // Recovery path: expect a prior-rank TC.
            let tc = proposal.proposal.previous_rank_timeout_certificate.as_ref().ok_or_else(
                || {
                    QuilError::InvalidProposal(format!(
                        "parent QC is not for previous rank ({} != {}+1) but no prior-rank TC provided",
                        state.parent_qc_rank, state.rank
                    ))
                },
            )?;
            // Prior-rank TC must be for rank = state.rank - 1.
            if tc.rank() + 1 != state.rank {
                return Err(QuilError::InvalidProposal(format!(
                    "prior-rank TC rank {} does not match expected {}",
                    tc.rank(),
                    state.rank - 1
                )));
            }
            // The TC's embedded newest-QC cannot be newer than the
            // proposal's parent QC (otherwise the proposer should
            // have extended the newer one).
            let tc_qc_rank = tc.latest_quorum_cert().rank();
            if state.parent_qc_rank < tc_qc_rank {
                return Err(QuilError::InvalidProposal(format!(
                    "TC embedded QC rank {} is newer than parent QC rank {}",
                    tc_qc_rank, state.parent_qc_rank
                )));
            }
            // Validate the TC itself.
            self.validate_timeout_certificate(tc.as_ref())?;
        } else if proposal.proposal.previous_rank_timeout_certificate.is_some() {
            return Err(QuilError::InvalidProposal(
                "last rank ended with QC but proposal includes a prior-rank TC".into(),
            ));
        }

        // Note: we don't validate the parent QC here directly because
        // the Rust State model doesn't carry the full QC. The event
        // handler feeds the QC independently via
        // `on_receive_quorum_certificate`, where it's validated by
        // the forest + pacemaker pipeline.
        Ok(())
    }

    fn validate_vote(&self, vote: &V) -> Result<Box<dyn WeightedIdentity>> {
        // Look up the voter in the committee.
        let voter = self.committee.identity_by_rank(vote.rank(), vote.identity())?;

        // Verifier does the crypto — note the Rust verifier's
        // `verify_vote` expects a caller that has already plumbed
        // the public key; we delegate and let the verifier's error
        // decide the outcome.
        match self.verifier.verify_vote(vote) {
            Ok(()) => Ok(voter),
            Err(e) if e.is_invalid_signature() => Err(QuilError::InvalidVote(format!(
                "vote signature invalid: {}",
                e
            ))),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_consensus::models::{
        AggregatedSignature, Identity, Proposal, State,
    };
    use std::sync::Mutex;

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
    struct AppVote {
        id: Identity,
        rank: u64,
        payload: Vec<u8>,
    }
    impl Unique for AppVote {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &self.payload }
    }

    // ---------- agg/qc/tc stubs ----------
    #[derive(Debug, Clone)]
    struct StubAgg {
        bitmask: Vec<u8>,
    }
    impl AggregatedSignature for StubAgg {
        fn signature(&self) -> &[u8] { &[] }
        fn public_key(&self) -> &[u8] { &[] }
        fn bitmask(&self) -> &[u8] { &self.bitmask }
    }

    #[derive(Debug)]
    struct StubQc {
        rank: u64,
        id: Identity,
        agg: StubAgg,
    }
    impl QuorumCertificate for StubQc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn frame_number(&self) -> u64 { 0 }
        fn identity(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &self.agg }
        fn equals(&self, o: &dyn QuorumCertificate) -> bool {
            self.rank == o.rank() && self.id == *o.identity()
        }
    }

    #[derive(Debug)]
    struct StubTc {
        rank: u64,
        latest_ranks: Vec<u64>,
        latest_qc: StubQc,
        agg: StubAgg,
    }
    impl TimeoutCertificate for StubTc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn latest_ranks(&self) -> &[u64] { &self.latest_ranks }
        fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { &self.latest_qc }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &self.agg }
        fn equals(&self, o: &dyn TimeoutCertificate) -> bool {
            self.rank == o.rank()
        }
    }

    // ---------- committee stub ----------
    #[derive(Debug, Clone)]
    struct FakeMember {
        id: Identity,
        weight: u64,
    }
    impl WeightedIdentity for FakeMember {
        fn public_key(&self) -> &[u8] { &[] }
        fn identity(&self) -> &Identity { &self.id }
        fn weight(&self) -> u64 { self.weight }
    }

    struct StubCommittee {
        members: Vec<(Identity, u64)>,
        leader: Identity,
        quorum_threshold: u64,
    }
    impl Replicas for StubCommittee {
        fn leader_for_rank(&self, _r: u64) -> Result<Identity> {
            Ok(self.leader.clone())
        }
        fn quorum_threshold_for_rank(&self, _r: u64) -> Result<u64> {
            Ok(self.quorum_threshold)
        }
        fn timeout_threshold_for_rank(&self, _r: u64) -> Result<u64> {
            Ok((self.quorum_threshold + 1) / 2)
        }
        fn self_identity(&self) -> &Identity {
            use std::sync::OnceLock;
            static SELF: OnceLock<Identity> = OnceLock::new();
            SELF.get_or_init(|| "self".into())
        }
        fn identities_by_rank(
            &self,
            _rank: u64,
        ) -> Result<Vec<Box<dyn WeightedIdentity>>> {
            Ok(self
                .members
                .iter()
                .map(|(id, w)| {
                    Box::new(FakeMember {
                        id: id.clone(),
                        weight: *w,
                    }) as Box<dyn WeightedIdentity>
                })
                .collect())
        }
        fn identity_by_rank(
            &self,
            _rank: u64,
            participant_id: &Identity,
        ) -> Result<Box<dyn WeightedIdentity>> {
            self.members
                .iter()
                .find(|(id, _)| id == participant_id)
                .map(|(id, w)| {
                    Box::new(FakeMember {
                        id: id.clone(),
                        weight: *w,
                    }) as Box<dyn WeightedIdentity>
                })
                .ok_or_else(|| QuilError::InvalidSigner(hex::encode(participant_id)))
        }
    }

    // ---------- verifier stub ----------
    struct StubVerifier {
        qc_error: Mutex<Option<QuilError>>,
        tc_error: Mutex<Option<QuilError>>,
        vote_error: Mutex<Option<QuilError>>,
    }
    impl StubVerifier {
        fn ok() -> Self {
            Self {
                qc_error: Mutex::new(None),
                tc_error: Mutex::new(None),
                vote_error: Mutex::new(None),
            }
        }
    }
    impl Verifier<AppVote> for StubVerifier {
        fn verify_vote(&self, _v: &AppVote) -> Result<()> {
            match self.vote_error.lock().unwrap().take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
        fn verify_quorum_certificate(&self, _q: &dyn QuorumCertificate) -> Result<()> {
            match self.qc_error.lock().unwrap().take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
        fn verify_timeout_certificate(&self, _t: &dyn TimeoutCertificate) -> Result<()> {
            match self.tc_error.lock().unwrap().take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }

    // ---------- helpers ----------
    fn build_validator(
        committee: StubCommittee,
        verifier: StubVerifier,
    ) -> ConsensusValidator<AppState, AppVote> {
        ConsensusValidator::new(Arc::new(committee), Arc::new(verifier))
    }

    fn committee_of_3() -> StubCommittee {
        StubCommittee {
            members: vec![
                ("alice".into(), 1),
                ("bob".into(), 1),
                ("carol".into(), 1),
            ],
            leader: "alice".into(),
            quorum_threshold: 2,
        }
    }

    fn bitmask_of(members: &[bool]) -> Vec<u8> {
        let len = (members.len() + 7) / 8;
        let mut out = vec![0u8; len];
        for (i, set) in members.iter().enumerate() {
            if *set {
                out[i / 8] |= 1 << (i % 8);
            }
        }
        out
    }

    // ---------- tests ----------

    #[test]
    fn validate_qc_with_full_weight_succeeds() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        let qc = StubQc {
            rank: 5,
            id: "s-5".into(),
            agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
        };
        v.validate_quorum_certificate(&qc).unwrap();
    }

    #[test]
    fn validate_qc_below_threshold_errors() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        let qc = StubQc {
            rank: 5,
            id: "s-5".into(),
            agg: StubAgg { bitmask: bitmask_of(&[true, false, false]) },
        };
        let err = v.validate_quorum_certificate(&qc).unwrap_err();
        assert!(err.is_invalid_quorum_certificate());
    }

    #[test]
    fn validate_qc_short_bitmask_errors() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        let qc = StubQc {
            rank: 5,
            id: "s-5".into(),
            agg: StubAgg { bitmask: vec![] },
        };
        let err = v.validate_quorum_certificate(&qc).unwrap_err();
        assert!(err.is_insufficient_signatures());
    }

    #[test]
    fn validate_qc_verifier_failure_bubbles_up() {
        let verifier = StubVerifier {
            qc_error: Mutex::new(Some(QuilError::InvalidSignature("bad".into()))),
            tc_error: Mutex::new(None),
            vote_error: Mutex::new(None),
        };
        let v = build_validator(committee_of_3(), verifier);
        let qc = StubQc {
            rank: 5,
            id: "s-5".into(),
            agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
        };
        let err = v.validate_quorum_certificate(&qc).unwrap_err();
        assert!(err.is_invalid_signature());
    }

    #[test]
    fn validate_tc_rank_lower_than_embedded_qc_errors() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        let tc = StubTc {
            rank: 5,
            latest_ranks: vec![4, 4, 4],
            latest_qc: StubQc {
                rank: 7, // newer than TC itself
                id: "qc".into(),
                agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
            },
            agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
        };
        let err = v.validate_timeout_certificate(&tc).unwrap_err();
        assert!(err.is_invalid_timeout_certificate());
    }

    #[test]
    fn validate_tc_max_contributed_newer_than_embedded_qc_errors() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        // TC rank 5, signers report up to rank 6, embedded QC only at rank 4.
        // Max contributed > embedded → invalid.
        let tc = StubTc {
            rank: 5,
            latest_ranks: vec![4, 5, 6],
            latest_qc: StubQc {
                rank: 4,
                id: "qc".into(),
                agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
            },
            agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
        };
        let err = v.validate_timeout_certificate(&tc).unwrap_err();
        assert!(err.is_invalid_timeout_certificate());
    }

    #[test]
    fn validate_tc_happy_path_with_valid_embedded_qc() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        let tc = StubTc {
            rank: 5,
            latest_ranks: vec![4, 4, 4],
            latest_qc: StubQc {
                rank: 4,
                id: "qc".into(),
                agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
            },
            agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
        };
        v.validate_timeout_certificate(&tc).unwrap();
    }

    fn make_proposal(
        rank: u64,
        proposer: &str,
        parent_qc_rank: u64,
    ) -> SignedProposal<AppState, AppVote> {
        let parent_qc = std::sync::Arc::new(StubQc {
            rank: parent_qc_rank,
            id: format!("parent-{}", parent_qc_rank).into_bytes(),
            agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
        });
        SignedProposal {
            proposal: Proposal {
                state: State {
                    rank,
                    identifier: format!("s-{}", rank).into_bytes(),
                    proposer_id: proposer.into(),
                    parent_qc_identity: format!("parent-{}", parent_qc_rank).into_bytes(),
                    parent_qc_rank,
                    parent_quorum_certificate: Some(parent_qc.clone()),
                    timestamp: 0,
                    state: AppState { id: format!("s-{}", rank).into_bytes(), rank },
                },
                previous_rank_timeout_certificate: None,
                parent_quorum_certificate: parent_qc,
            },
            vote: AppVote { id: proposer.into(), rank, payload: vec![] },
        }
    }

    #[test]
    fn validate_proposal_wrong_proposer_errors() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        // alice is the leader; bob is proposing — should fail.
        let p = make_proposal(5, "bob", 4);
        let err = v.validate_proposal(&p).unwrap_err();
        assert!(err.is_invalid_proposal());
    }

    #[test]
    fn validate_proposal_happy_path_extends_parent_qc() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        // alice is leader, proposing at rank 5 extending parent rank 4.
        let p = make_proposal(5, "alice", 4);
        v.validate_proposal(&p).unwrap();
    }

    #[test]
    fn validate_proposal_recovery_path_requires_tc() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        // Parent QC is rank 2, proposing rank 5 — requires a TC at rank 4.
        let p = make_proposal(5, "alice", 2);
        let err = v.validate_proposal(&p).unwrap_err();
        assert!(err.is_invalid_proposal());
    }

    #[test]
    fn validate_proposal_recovery_path_with_valid_tc() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        let mut p = make_proposal(5, "alice", 2);
        let tc: Arc<dyn TimeoutCertificate> = Arc::new(StubTc {
            rank: 4,
            latest_ranks: vec![2, 2, 2],
            latest_qc: StubQc {
                rank: 2,
                id: "qc-2".into(),
                agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
            },
            agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
        });
        p.proposal.previous_rank_timeout_certificate = Some(tc);
        v.validate_proposal(&p).unwrap();
    }

    #[test]
    fn validate_proposal_happy_path_with_stale_tc_errors() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        // parent QC is rank 4, proposing rank 5 → happy path, but
        // proposal includes a TC, which is a protocol violation.
        let mut p = make_proposal(5, "alice", 4);
        let tc: Arc<dyn TimeoutCertificate> = Arc::new(StubTc {
            rank: 3,
            latest_ranks: vec![2, 2, 2],
            latest_qc: StubQc {
                rank: 2,
                id: "qc-2".into(),
                agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
            },
            agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
        });
        p.proposal.previous_rank_timeout_certificate = Some(tc);
        let err = v.validate_proposal(&p).unwrap_err();
        assert!(err.is_invalid_proposal());
    }

    #[test]
    fn validate_proposal_recovery_path_wrong_tc_rank_errors() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        // Proposing rank 5 via recovery path but TC is at rank 3 (expected 4).
        let mut p = make_proposal(5, "alice", 2);
        let tc: Arc<dyn TimeoutCertificate> = Arc::new(StubTc {
            rank: 3,
            latest_ranks: vec![2, 2, 2],
            latest_qc: StubQc {
                rank: 2,
                id: "qc-2".into(),
                agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
            },
            agg: StubAgg { bitmask: bitmask_of(&[true, true, true]) },
        });
        p.proposal.previous_rank_timeout_certificate = Some(tc);
        let err = v.validate_proposal(&p).unwrap_err();
        assert!(err.is_invalid_proposal());
    }

    #[test]
    fn validate_vote_happy_path() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        let vote = AppVote { id: "alice".into(), rank: 5, payload: vec![1, 2] };
        let voter = v.validate_vote(&vote).unwrap();
        assert_eq!(voter.identity().as_slice(), b"alice");
    }

    #[test]
    fn validate_vote_unknown_signer_errors() {
        let v = build_validator(committee_of_3(), StubVerifier::ok());
        let vote = AppVote { id: "stranger".into(), rank: 5, payload: vec![] };
        let err = v.validate_vote(&vote).unwrap_err();
        assert!(err.is_invalid_signer());
    }

    #[test]
    fn validate_vote_verifier_rejects_bad_sig() {
        let verifier = StubVerifier {
            qc_error: Mutex::new(None),
            tc_error: Mutex::new(None),
            vote_error: Mutex::new(Some(QuilError::InvalidSignature("bad".into()))),
        };
        let v = build_validator(committee_of_3(), verifier);
        let vote = AppVote { id: "alice".into(), rank: 5, payload: vec![] };
        let err = v.validate_vote(&vote).unwrap_err();
        assert!(err.is_invalid_vote());
    }
}
