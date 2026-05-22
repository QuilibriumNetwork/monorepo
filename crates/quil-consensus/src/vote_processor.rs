//! Per-state vote processor. Mirror of
//! `consensus/votecollector/vote_processor.go`.
//!
//! A [`VoteProcessor`] verifies individual votes against a single
//! known state and aggregates their signatures. Once the running
//! weight crosses the quorum threshold, the processor mints a
//! [`QuorumCertificate`] via the [`VotingProvider`] and fires the
//! registered `on_qc_created` callback exactly once.
//!
//! This is the inner state machine the vote collector drives; it's
//! concurrency-safe so multiple vote-processing tasks can hit it in
//! parallel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::models::{State, Unique};
use crate::signature_aggregator::WeightedSignatureAggregator;
use crate::voting_provider::{OnQuorumCertificateCreated, VotingProvider};
use quil_types::error::{QuilError, Result};

/// Ensure a vote is for a given state. Mirror of Go's
/// `votecollector/common.go::EnsureVoteForState`.
///
/// Returns:
/// - `Ok(())` on success
/// - `Err(QuilError::IncompatibleRank)` if the vote's rank doesn't match
/// - `Err(QuilError::IncompatibleState)` if the vote's source (state
///   reference) doesn't match
pub fn ensure_vote_for_state<S: Unique, V: Unique>(
    vote: &V,
    state: &State<S>,
) -> Result<()> {
    if vote.rank() != state.rank {
        return Err(QuilError::IncompatibleRank(format!(
            "vote {} has rank {} while state's rank is {}",
            hex::encode(vote.identity()),
            vote.rank(),
            state.rank
        )));
    }
    if vote.source() != &state.identifier {
        return Err(QuilError::IncompatibleState(format!(
            "expecting votes for state {}, but vote {} is for state {}",
            hex::encode(&state.identifier),
            hex::encode(vote.identity()),
            hex::encode(vote.source())
        )));
    }
    Ok(())
}

/// Verifies votes for a particular state and aggregates them into a QC
/// when the quorum weight threshold is reached. Mirror of Go's
/// `VoteProcessor[StateT, VoteT, PeerIDT]`.
///
/// Concurrency-safe: `process` may be called from multiple tasks
/// concurrently. The `done` flag + CAS ensure the QC is built at most
/// once.
pub struct VoteProcessor<S: Unique, V: Unique> {
    state: Arc<State<S>>,
    proving_sig_aggregator: Arc<dyn WeightedSignatureAggregator>,
    voting_provider: Arc<dyn VotingProvider<S, V>>,
    on_qc_created: OnQuorumCertificateCreated,
    min_required_weight: u64,
    done: AtomicBool,
}

impl<S: Unique, V: Unique> VoteProcessor<S, V> {
    pub fn new(
        state: Arc<State<S>>,
        proving_sig_aggregator: Arc<dyn WeightedSignatureAggregator>,
        voting_provider: Arc<dyn VotingProvider<S, V>>,
        on_qc_created: OnQuorumCertificateCreated,
        min_required_weight: u64,
    ) -> Self {
        Self {
            state,
            proving_sig_aggregator,
            voting_provider,
            on_qc_created,
            min_required_weight,
            done: AtomicBool::new(false),
        }
    }

    /// The state this processor is verifying votes for.
    pub fn state(&self) -> &Arc<State<S>> {
        &self.state
    }

    /// Process a single vote. On quorum-weight crossover, builds the QC
    /// and fires `on_qc_created` exactly once.
    ///
    /// Expected error returns during normal operation:
    /// - `IncompatibleRank` / `IncompatibleState` — sentinels, caller
    ///   treats as non-fatal
    /// - `InvalidVote` — wraps InvalidSigner / InvalidSignature; the
    ///   voter is Byzantine
    ///
    /// All other errors indicate internal bugs.
    pub fn process(&self, vote: V) -> Result<()> {
        ensure_vote_for_state(&vote, &self.state)
            .map_err(|e| QuilError::Consensus(format!("received incompatible vote: {}", e)))?;

        // Fast path: QC already built.
        if self.done.load(Ordering::Acquire) {
            return Ok(());
        }

        // Verify signature.
        if let Err(e) = self
            .proving_sig_aggregator
            .verify(vote.identity(), vote.signature())
        {
            return Err(if e.is_invalid_signer() {
                QuilError::InvalidVote(format!(
                    "vote {} for rank {} is not signed by an authorized participant: {}",
                    hex::encode(vote.identity()),
                    vote.rank(),
                    e
                ))
            } else if e.is_invalid_signature() {
                QuilError::InvalidVote(format!(
                    "vote {} for rank {} has an invalid proving signature: {}",
                    hex::encode(vote.identity()),
                    vote.rank(),
                    e
                ))
            } else {
                QuilError::Consensus(format!("internal error checking signature validity: {}", e))
            });
        }

        if self.done.load(Ordering::Acquire) {
            return Ok(());
        }

        // Add to aggregator. TrustedAdd returns the new total. Pass
        // the vote's aux payload through so app-shard votes' VDF
        // multi-proof contributions get stored alongside their BLS
        // sig and packed into the aggregate blob at QC time. Global
        // votes (no aux) take the empty-slice default and behave
        // identically to plain `trusted_add`.
        let total_weight = self
            .proving_sig_aggregator
            .trusted_add_with_aux(vote.identity(), vote.signature(), vote.aux())
            .map_err(|e| {
                QuilError::Consensus(format!(
                    "unexpected exception adding signature from vote {} to proving aggregator: {}",
                    hex::encode(vote.identity()),
                    e
                ))
            })?;

        if total_weight < self.min_required_weight {
            return Ok(());
        }

        // Crossed the quorum threshold. Only one caller proceeds.
        if self
            .done
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }

        let qc = self.build_qc()?;
        (self.on_qc_created)(qc);
        Ok(())
    }

    /// Aggregate signatures and finalize the QC via the voting provider.
    /// Called exactly once per processor.
    fn build_qc(&self) -> Result<Arc<dyn crate::models::QuorumCertificate>> {
        let (_signers, aggregated_sig) = self.proving_sig_aggregator.aggregate().map_err(|e| {
            QuilError::Consensus(format!("could not aggregate proving signature: {}", e))
        })?;
        self.voting_provider
            .finalize_quorum_certificate(&self.state, aggregated_sig)
            .map_err(|e| QuilError::Consensus(format!("could not build quorum certificate: {}", e)))
    }

    /// `true` once the QC has been built.
    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AggregatedSignature, Identity, QuorumCertificate, TimeoutCertificate, WeightedIdentity};
    use crate::signature_aggregator::TimeoutSignerInfo;
    use std::sync::atomic::AtomicU64;
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

    fn make_state(rank: u64, id: &str) -> Arc<State<AppState>> {
        Arc::new(State {
            rank,
            identifier: id.into(),
            proposer_id: "leader".into(),
            parent_qc_identity: "parent".into(),
            parent_qc_rank: rank.saturating_sub(1),
            parent_quorum_certificate: None,
            timestamp: 0,
            state: AppState { id: id.into(), rank },
        })
    }

    fn make_vote(voter: &str, rank: u64, state_id: &str, sig: &[u8]) -> Vote {
        Vote {
            id: voter.into(),
            src: state_id.into(),
            rank,
            sig: sig.to_vec(),
        }
    }

    // ---------- signature aggregator stub ----------
    struct StubAgg {
        valid_signers: Vec<Identity>,
        invalid_sigs: Vec<Vec<u8>>,
        /// Simulated per-signer weight (all = 1 for the happy-path test).
        weight: u64,
        total: Mutex<u64>,
        added: Mutex<Vec<Identity>>,
    }
    impl WeightedSignatureAggregator for StubAgg {
        fn verify(&self, signer_id: &Identity, sig: &[u8]) -> Result<()> {
            if !self.valid_signers.contains(signer_id) {
                return Err(QuilError::InvalidSigner(hex::encode(signer_id)));
            }
            if self.invalid_sigs.iter().any(|s| s == sig) {
                return Err(QuilError::InvalidSignature("bad sig".into()));
            }
            Ok(())
        }
        fn trusted_add(&self, signer_id: &Identity, _sig: &[u8]) -> Result<u64> {
            let mut added = self.added.lock().unwrap();
            if added.contains(signer_id) {
                return Err(QuilError::DuplicatedSigner(hex::encode(signer_id)));
            }
            added.push(signer_id.clone());
            let mut t = self.total.lock().unwrap();
            *t += self.weight;
            Ok(*t)
        }
        fn total_weight(&self) -> u64 {
            *self.total.lock().unwrap()
        }
        fn aggregate(
            &self,
        ) -> Result<(Vec<Box<dyn WeightedIdentity>>, Arc<dyn AggregatedSignature>)> {
            Ok((vec![], Arc::new(StubAggSig)))
        }
    }

    #[derive(Debug)]
    struct StubAggSig;
    impl AggregatedSignature for StubAggSig {
        fn signature(&self) -> &[u8] { &[] }
        fn public_key(&self) -> &[u8] { &[] }
        fn bitmask(&self) -> &[u8] { &[] }
    }

    // ---------- voting provider stub ----------
    struct StubVotingProvider {
        qc_built: AtomicU64,
    }
    impl VotingProvider<AppState, Vote> for StubVotingProvider {
        fn sign_vote(&self, _s: &State<AppState>) -> Result<Vote> {
            Err(QuilError::Internal("sign_vote not supported in stub".into()))
        }
        fn sign_timeout_vote(&self, _f: &[u8], _c: u64, _n: u64) -> Result<Vote> {
            Err(QuilError::Internal("sign_timeout_vote not supported in stub".into()))
        }
        fn finalize_quorum_certificate(
            &self,
            state: &State<AppState>,
            _agg: Arc<dyn AggregatedSignature>,
        ) -> Result<Arc<dyn QuorumCertificate>> {
            self.qc_built.fetch_add(1, Ordering::SeqCst);
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
            _agg: Arc<dyn AggregatedSignature>,
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
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAggSig }
        fn equals(&self, o: &dyn QuorumCertificate) -> bool {
            self.rank == o.rank() && self.id == *o.identity()
        }
    }

    // ---------- helpers ----------
    fn make_processor(
        state: Arc<State<AppState>>,
        valid_signers: Vec<Identity>,
        invalid_sigs: Vec<Vec<u8>>,
        weight_each: u64,
        min_required: u64,
    ) -> (
        VoteProcessor<AppState, Vote>,
        Arc<StubVotingProvider>,
        Arc<AtomicU64>,
    ) {
        let agg = Arc::new(StubAgg {
            valid_signers,
            invalid_sigs,
            weight: weight_each,
            total: Mutex::new(0),
            added: Mutex::new(vec![]),
        });
        let vp = Arc::new(StubVotingProvider {
            qc_built: AtomicU64::new(0),
        });
        let qc_callback_count = Arc::new(AtomicU64::new(0));
        let qcc = Arc::clone(&qc_callback_count);
        let on_qc: OnQuorumCertificateCreated = Arc::new(move |_qc| {
            qcc.fetch_add(1, Ordering::SeqCst);
        });
        let proc = VoteProcessor::new(
            state,
            agg as Arc<dyn WeightedSignatureAggregator>,
            vp.clone() as Arc<dyn VotingProvider<AppState, Vote>>,
            on_qc,
            min_required,
        );
        (proc, vp, qc_callback_count)
    }

    // ---------- ensure_vote_for_state ----------
    #[test]
    fn ensure_vote_for_state_happy() {
        let state = make_state(5, "state-5");
        let vote = make_vote("voter-A", 5, "state-5", b"sig1");
        assert!(ensure_vote_for_state(&vote, &state).is_ok());
    }

    #[test]
    fn ensure_vote_for_state_wrong_rank() {
        let state = make_state(5, "state-5");
        let vote = make_vote("voter-A", 7, "state-5", b"sig1");
        let err = ensure_vote_for_state(&vote, &state).unwrap_err();
        assert!(err.is_incompatible_rank());
    }

    #[test]
    fn ensure_vote_for_state_wrong_state() {
        let state = make_state(5, "state-5");
        let vote = make_vote("voter-A", 5, "different-state", b"sig1");
        let err = ensure_vote_for_state(&vote, &state).unwrap_err();
        assert!(err.is_incompatible_state());
    }

    // ---------- process ----------
    #[test]
    fn process_below_threshold_no_qc() {
        let state = make_state(5, "state-5");
        let (proc, vp, qc_count) = make_processor(
            Arc::clone(&state),
            vec!["voter-A".into(), "voter-B".into()],
            vec![],
            1, // each vote weight = 1
            3, // need 3 for quorum
        );
        proc.process(make_vote("voter-A", 5, "state-5", b"sig1")).unwrap();
        proc.process(make_vote("voter-B", 5, "state-5", b"sig2")).unwrap();
        assert!(!proc.is_done());
        assert_eq!(vp.qc_built.load(Ordering::SeqCst), 0);
        assert_eq!(qc_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn process_reaches_threshold_mints_qc() {
        let state = make_state(5, "state-5");
        let (proc, vp, qc_count) = make_processor(
            Arc::clone(&state),
            vec!["voter-A".into(), "voter-B".into(), "voter-C".into()],
            vec![],
            1,
            3,
        );
        proc.process(make_vote("voter-A", 5, "state-5", b"sig1")).unwrap();
        proc.process(make_vote("voter-B", 5, "state-5", b"sig2")).unwrap();
        proc.process(make_vote("voter-C", 5, "state-5", b"sig3")).unwrap();
        assert!(proc.is_done());
        assert_eq!(vp.qc_built.load(Ordering::SeqCst), 1);
        assert_eq!(qc_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn process_further_votes_after_done_are_noop() {
        let state = make_state(5, "state-5");
        let (proc, vp, _) = make_processor(
            Arc::clone(&state),
            vec!["voter-A".into(), "voter-B".into()],
            vec![],
            2, // weight=2 each, so first vote hits threshold=2
            2,
        );
        proc.process(make_vote("voter-A", 5, "state-5", b"sig1")).unwrap();
        assert!(proc.is_done());
        assert_eq!(vp.qc_built.load(Ordering::SeqCst), 1);
        // Second vote: fast-path return, no additional QC.
        proc.process(make_vote("voter-B", 5, "state-5", b"sig2")).unwrap();
        assert_eq!(vp.qc_built.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn process_invalid_signer_is_invalid_vote() {
        let state = make_state(5, "state-5");
        let (proc, _, _) = make_processor(
            Arc::clone(&state),
            vec!["voter-A".into()],
            vec![],
            1,
            2,
        );
        let err = proc
            .process(make_vote("stranger", 5, "state-5", b"sig"))
            .unwrap_err();
        assert!(err.is_invalid_vote());
    }

    #[test]
    fn process_invalid_signature_is_invalid_vote() {
        let state = make_state(5, "state-5");
        let (proc, _, _) = make_processor(
            Arc::clone(&state),
            vec!["voter-A".into()],
            vec![b"bad-sig".to_vec()],
            1,
            2,
        );
        let err = proc
            .process(make_vote("voter-A", 5, "state-5", b"bad-sig"))
            .unwrap_err();
        assert!(err.is_invalid_vote());
    }

    #[test]
    fn process_wrong_rank_errors() {
        let state = make_state(5, "state-5");
        let (proc, _, _) = make_processor(
            Arc::clone(&state),
            vec!["voter-A".into()],
            vec![],
            1,
            2,
        );
        // Wrong rank — wrapped in Consensus error per port spec.
        let err = proc
            .process(make_vote("voter-A", 7, "state-5", b"sig"))
            .unwrap_err();
        let s = format!("{}", err);
        assert!(s.contains("incompatible") || s.contains("rank"));
    }
}
