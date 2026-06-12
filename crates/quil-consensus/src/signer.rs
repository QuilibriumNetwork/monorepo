//! Consensus signer trait. Mirror of Go's `consensus/consensus_signer.go`.
//!
//! The signer is the sole authority on producing votes and timeouts. Safety
//! rules call into this trait to mint the signed artifacts after validating
//! that the action is safe to take. Concrete impls live in adapter crates
//! (e.g. a BLS-based signer in `quil-engine`).
//!
//! [`VotingProviderSigner`] is a generic concrete implementation that
//! wraps a [`VotingProvider`](crate::voting_provider::VotingProvider) —
//! it's the Rust equivalent of
//! `consensus/verification/signer.go::Signer`. The voting provider
//! supplies the actual signing crypto; the signer handles the
//! [`TimeoutState`] assembly and error wrapping.

use std::sync::Arc;

use quil_types::error::{QuilError, Result};

use crate::models::{QuorumCertificate, State, TimeoutCertificate, TimeoutState, Unique};
use crate::voting_provider::VotingProvider;

/// Creates votes and timeouts for a consensus replica. `StateT`/`VoteT` are
/// the application's concrete state and vote types; `Signer` is generic over
/// both to match Go's `Signer[StateT, VoteT]`.
///
/// No errors are expected from these methods under honest-operator
/// operation (including the presence of Byzantine peers), so callers treat
/// any `Err` as a symptom of an internal bug.
pub trait Signer<S: Unique, V: Unique>: Send + Sync {
    /// Produce a vote for the given state. Called by safety rules after the
    /// proposal has been verified to be safe to vote for.
    fn create_vote(&self, state: &State<S>) -> Result<V>;

    /// Produce a timeout for the given rank. Called by safety rules after
    /// the replica has decided the current rank should be abandoned.
    fn create_timeout(
        &self,
        cur_rank: u64,
        newest_qc: Arc<dyn QuorumCertificate>,
        previous_rank_timeout_certificate: Option<Arc<dyn TimeoutCertificate>>,
    ) -> Result<TimeoutState<V>>;
}

/// Concrete [`Signer`] that wraps a [`VotingProvider`]. Mirror of Go's
/// `consensus/verification/signer.go::Signer`.
///
/// Both `create_vote` and `create_timeout` delegate to the voting
/// provider for the actual signing; `create_timeout` then assembles
/// the resulting vote into a [`TimeoutState`] with `timeout_tick == 0`.
pub struct VotingProviderSigner<S: Unique, V: Unique> {
    voter: Arc<dyn VotingProvider<S, V>>,
}

impl<S: Unique, V: Unique> VotingProviderSigner<S, V> {
    pub fn new(voter: Arc<dyn VotingProvider<S, V>>) -> Self {
        Self { voter }
    }
}

impl<S: Unique, V: Unique> Signer<S, V> for VotingProviderSigner<S, V> {
    fn create_vote(&self, state: &State<S>) -> Result<V> {
        self.voter
            .sign_vote(state)
            .map_err(|e| QuilError::Consensus(format!("could not create signature: {}", e)))
    }

    fn create_timeout(
        &self,
        cur_rank: u64,
        newest_qc: Arc<dyn QuorumCertificate>,
        previous_rank_timeout_certificate: Option<Arc<dyn TimeoutCertificate>>,
    ) -> Result<TimeoutState<V>> {
        let filter = newest_qc.filter().to_vec();
        let newest_qc_rank = newest_qc.rank();
        let vote = self
            .voter
            .sign_timeout_vote(&filter, cur_rank, newest_qc_rank)
            .map_err(|e| {
                QuilError::Consensus(format!(
                    "could not generate signature for timeout state at rank {}: {}",
                    cur_rank, e
                ))
            })?;

        Ok(TimeoutState {
            rank: cur_rank,
            latest_quorum_certificate: newest_qc,
            prior_rank_timeout_certificate: previous_rank_timeout_certificate,
            vote,
            timeout_tick: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AggregatedSignature, Identity};
    use crate::signature_aggregator::TimeoutSignerInfo;
    use std::sync::atomic::{AtomicU64, Ordering};
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
        rank: u64,
        payload: Vec<u8>,
    }
    impl Unique for Vote {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &self.payload }
    }

    // ---------- QC stub ----------
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

    // ---------- voting provider stub ----------
    #[derive(Default)]
    struct RecordingVoter {
        sign_vote_calls: AtomicU64,
        sign_timeout_calls: AtomicU64,
        last_filter: Mutex<Vec<u8>>,
        last_cur_rank: AtomicU64,
        last_newest_qc_rank: AtomicU64,
        vote_error: bool,
        timeout_error: bool,
    }

    impl VotingProvider<AppState, Vote> for RecordingVoter {
        fn sign_vote(&self, state: &State<AppState>) -> Result<Vote> {
            self.sign_vote_calls.fetch_add(1, Ordering::SeqCst);
            if self.vote_error {
                return Err(QuilError::Consensus("sign_vote failed".into()));
            }
            Ok(Vote {
                id: format!("vote-{}", state.rank).into_bytes(),
                rank: state.rank,
                payload: format!("sig-for-{}", hex::encode(&state.identifier)).into_bytes(),
            })
        }

        fn sign_timeout_vote(
            &self,
            filter: &[u8],
            cur_rank: u64,
            newest_qc_rank: u64,
        ) -> Result<Vote> {
            self.sign_timeout_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_filter.lock().unwrap() = filter.to_vec();
            self.last_cur_rank.store(cur_rank, Ordering::SeqCst);
            self.last_newest_qc_rank
                .store(newest_qc_rank, Ordering::SeqCst);
            if self.timeout_error {
                return Err(QuilError::Consensus("sign_timeout failed".into()));
            }
            Ok(Vote {
                id: format!("to-vote-{}", cur_rank).into_bytes(),
                rank: cur_rank,
                payload: format!("to-sig-{}:{}", cur_rank, newest_qc_rank).into_bytes(),
            })
        }

        fn finalize_quorum_certificate(
            &self,
            _s: &State<AppState>,
            _agg: Arc<dyn AggregatedSignature>,
        ) -> Result<Arc<dyn QuorumCertificate>> {
            Err(QuilError::Internal("finalize_quorum_certificate not supported in stub".into()))
        }

        fn finalize_timeout(
            &self,
            _r: u64,
            _qc: Arc<dyn QuorumCertificate>,
            _signers: Vec<TimeoutSignerInfo>,
            _agg: Arc<dyn AggregatedSignature>,
        ) -> Result<Arc<dyn TimeoutCertificate>> {
            Err(QuilError::Internal("finalize_timeout not supported in stub".into()))
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
            state: AppState { id: id.into(), rank },
        }
    }

    fn make_qc(rank: u64, id: &str, filter: &[u8]) -> Arc<dyn QuorumCertificate> {
        Arc::new(StubQc {
            rank,
            id: id.into(),
            filter: filter.to_vec(),
        })
    }

    // ---------- tests ----------

    #[test]
    fn create_vote_delegates_to_voting_provider() {
        let voter = Arc::new(RecordingVoter::default());
        let signer: VotingProviderSigner<AppState, Vote> =
            VotingProviderSigner::new(voter.clone());
        let state = make_state(5, "state-5");
        let vote = signer.create_vote(&state).unwrap();
        assert_eq!(vote.rank, 5);
        // Note: the test stub formats the payload as `sig-for-<hex(identity)>`,
        // so for an identifier of b"state-5" the payload is the bytes of
        // "sig-for-7374617465-35" (hex of "state-5").
        assert_eq!(vote.payload, format!("sig-for-{}", hex::encode(b"state-5")).into_bytes());
        assert_eq!(voter.sign_vote_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn create_vote_wraps_provider_errors() {
        let voter = Arc::new(RecordingVoter {
            vote_error: true,
            ..Default::default()
        });
        let signer: VotingProviderSigner<AppState, Vote> =
            VotingProviderSigner::new(voter);
        let state = make_state(5, "state-5");
        let err = signer.create_vote(&state).unwrap_err();
        assert!(matches!(err, QuilError::Consensus(_)));
    }

    #[test]
    fn create_timeout_assembles_timeout_state() {
        let voter = Arc::new(RecordingVoter::default());
        let signer: VotingProviderSigner<AppState, Vote> =
            VotingProviderSigner::new(voter.clone());
        let qc = make_qc(4, "state-4", b"filter-bytes");
        let to = signer.create_timeout(5, Arc::clone(&qc), None).unwrap();
        assert_eq!(to.rank, 5);
        assert_eq!(to.timeout_tick, 0);
        assert!(to.prior_rank_timeout_certificate.is_none());
        // Provider was called with the QC's filter + cur_rank + qc_rank.
        assert_eq!(voter.sign_timeout_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*voter.last_filter.lock().unwrap(), b"filter-bytes");
        assert_eq!(voter.last_cur_rank.load(Ordering::SeqCst), 5);
        assert_eq!(voter.last_newest_qc_rank.load(Ordering::SeqCst), 4);
        // Arc<QC> threaded through unchanged.
        assert_eq!(to.latest_quorum_certificate.rank(), 4);
        // Vote payload matches the stub's format.
        assert_eq!(to.vote.payload, b"to-sig-5:4");
    }

    #[test]
    fn create_timeout_preserves_prior_rank_tc() {
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
            fn equals(&self, o: &dyn TimeoutCertificate) -> bool { self.rank == o.rank() }
        }
        let voter = Arc::new(RecordingVoter::default());
        let signer: VotingProviderSigner<AppState, Vote> =
            VotingProviderSigner::new(voter);
        let qc = make_qc(3, "state-3", b"f");
        let tc: Arc<dyn TimeoutCertificate> = Arc::new(StubTc {
            rank: 4,
            latest_qc: StubQc {
                rank: 3,
                id: "state-3".into(),
                filter: b"f".to_vec(),
            },
        });
        let to = signer.create_timeout(5, qc, Some(Arc::clone(&tc))).unwrap();
        assert!(to.prior_rank_timeout_certificate.is_some());
        assert_eq!(
            to.prior_rank_timeout_certificate.unwrap().rank(),
            4
        );
    }

    #[test]
    fn create_timeout_wraps_provider_errors() {
        let voter = Arc::new(RecordingVoter {
            timeout_error: true,
            ..Default::default()
        });
        let signer: VotingProviderSigner<AppState, Vote> =
            VotingProviderSigner::new(voter);
        let qc = make_qc(4, "state-4", b"f");
        let err = signer.create_timeout(5, qc, None).unwrap_err();
        assert!(matches!(err, QuilError::Consensus(_)));
    }
}
