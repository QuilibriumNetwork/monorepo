//! BLS-backed [`VotingProvider`] implementation. Mirror of
//! `node/consensus/global/consensus_voting_provider.go::GlobalVotingProvider`
//! + `node/consensus/app/consensus_voting_provider.go::AppVotingProvider`.
//!
//! The voting provider is the application's signing hook. Given a
//! state or a rank, it produces a vote using the local BLS proving
//! key. It also wraps aggregate signatures from the vote / timeout
//! collectors into concrete [`QuorumCertificate`] /
//! [`TimeoutCertificate`] artifacts.
//!
//! Since the concrete shape of `V` (vote), QC, and TC is
//! application-specific — Quilibrium's global shard uses
//! `protobufs::QuorumCertificate`, while the app shards use a
//! different wrapper — the voting provider delegates all
//! struct-construction to a pluggable [`VotingProviderFactory`] trait.
//! The reusable parts (message hashing + signing + address derivation)
//! live in this crate; the application-specific glue is a thin factory
//! impl.

use std::sync::Arc;

use quil_consensus::models::{
    AggregatedSignature, Identity, QuorumCertificate, State, TimeoutCertificate, Unique,
};
use quil_consensus::signature_aggregator::TimeoutSignerInfo;
use quil_consensus::verification::{make_timeout_message, make_vote_message};
use quil_consensus::voting_provider::VotingProvider;
use quil_types::crypto::Signer;
use quil_types::error::{QuilError, Result};

/// Application-specific construction hooks for votes, QCs, and TCs.
/// Each method is invoked exactly once by [`BlsVotingProvider`] with
/// the relevant metadata and raw signature bytes; the factory
/// assembles the concrete artifact.
pub trait VotingProviderFactory<S: Unique, V: Unique>: Send + Sync {
    /// Build a concrete vote from a state signature. `voter_address`
    /// is derived from the local BLS public key (application-defined
    /// encoding — typically the 32-byte hash of the pubkey).
    fn make_vote(
        &self,
        state_rank: u64,
        state_id: &Identity,
        signature: Vec<u8>,
        voter_address: &[u8],
    ) -> Result<V>;

    /// Build a concrete timeout vote from a timeout signature.
    fn make_timeout_vote(
        &self,
        rank: u64,
        newest_qc_rank: u64,
        signature: Vec<u8>,
        voter_address: &[u8],
    ) -> Result<V>;

    /// Assemble a concrete [`QuorumCertificate`] from an aggregate
    /// signature. Called by the vote collector once the quorum
    /// threshold is reached.
    fn make_quorum_certificate(
        &self,
        state: &State<S>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn QuorumCertificate>>;

    /// Assemble a concrete [`TimeoutCertificate`] from an aggregate
    /// signature. Called by the timeout collector. `signers` is the
    /// per-signer `(newest_qc_rank, signer)` pair list.
    fn make_timeout_certificate(
        &self,
        rank: u64,
        newest_qc: Arc<dyn QuorumCertificate>,
        signers: Vec<TimeoutSignerInfo>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn TimeoutCertificate>>;
}

/// Address derivation from a BLS public key. Quilibrium uses the
/// last 32 bytes of SHA3-256(pubkey) by convention. For flexibility
/// the voting provider takes the derivation as a function pointer,
/// so adapter crates can plug in any scheme.
pub type AddressDerivation = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// Generic BLS voting provider. Mirror of Go's `GlobalVotingProvider`.
///
/// Construction takes:
/// - a local `Signer` (usually `Bls48581Signer`)
/// - a vote / timeout domain separation tag pair
/// - an [`AddressDerivation`] callback
/// - a factory that builds concrete vote/QC/TC instances
pub struct BlsVotingProvider<S: Unique, V: Unique, F: VotingProviderFactory<S, V>> {
    signer: Box<dyn Signer>,
    vote_domain: Vec<u8>,
    timeout_domain: Vec<u8>,
    derive_address: AddressDerivation,
    factory: Arc<F>,
    _marker: std::marker::PhantomData<(fn() -> S, fn() -> V)>,
}

impl<S: Unique, V: Unique, F: VotingProviderFactory<S, V>> BlsVotingProvider<S, V, F> {
    pub fn new(
        signer: Box<dyn Signer>,
        vote_domain: Vec<u8>,
        timeout_domain: Vec<u8>,
        derive_address: AddressDerivation,
        factory: Arc<F>,
    ) -> Self {
        Self {
            signer,
            vote_domain,
            timeout_domain,
            derive_address,
            factory,
            _marker: std::marker::PhantomData,
        }
    }

    fn voter_address(&self) -> Vec<u8> {
        (self.derive_address)(self.signer.public_key())
    }
}

impl<S: Unique, V: Unique, F: VotingProviderFactory<S, V>> VotingProvider<S, V>
    for BlsVotingProvider<S, V, F>
{
    fn sign_vote(&self, state: &State<S>) -> Result<V> {
        // Canonical vote message: Go mirrors use `nil` as filter for
        // the global shard; we preserve that (empty filter here).
        let msg = make_vote_message(&[], state.rank, &state.identifier);
        let sig = self
            .signer
            .sign_with_domain(&msg, &self.vote_domain)
            .map_err(|e| QuilError::Crypto(format!("could not sign vote: {}", e)))?;
        let voter_address = self.voter_address();
        self.factory
            .make_vote(state.rank, &state.identifier, sig, &voter_address)
    }

    fn sign_timeout_vote(
        &self,
        _filter: &[u8],
        current_rank: u64,
        newest_qc_rank: u64,
    ) -> Result<V> {
        // Go's global voting provider also ignores the filter and
        // uses `nil` — we match that exactly.
        let msg = make_timeout_message(&[], current_rank, newest_qc_rank);
        let sig = self
            .signer
            .sign_with_domain(&msg, &self.timeout_domain)
            .map_err(|e| QuilError::Crypto(format!("could not sign timeout: {}", e)))?;
        let voter_address = self.voter_address();
        self.factory
            .make_timeout_vote(current_rank, newest_qc_rank, sig, &voter_address)
    }

    fn finalize_quorum_certificate(
        &self,
        state: &State<S>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn QuorumCertificate>> {
        self.factory.make_quorum_certificate(state, aggregated_sig)
    }

    fn finalize_timeout(
        &self,
        rank: u64,
        latest_qc: Arc<dyn QuorumCertificate>,
        signers_info: Vec<TimeoutSignerInfo>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn TimeoutCertificate>> {
        self.factory
            .make_timeout_certificate(rank, latest_qc, signers_info, aggregated_sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_crypto::Bls48581KeyConstructor;
    use quil_types::crypto::BlsConstructor;
    use std::sync::Mutex;

    // =================================================================
    // Test types
    // =================================================================

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
    struct TestVote {
        id: Identity,
        source: Identity,
        rank: u64,
        sig: Vec<u8>,
        voter_address: Vec<u8>,
    }
    impl Unique for TestVote {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.source }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &self.sig }
    }

    // =================================================================
    // Recording factory — captures every call for assertion.
    // =================================================================

    #[derive(Default)]
    struct RecordingFactory {
        votes: Mutex<Vec<TestVote>>,
        timeouts: Mutex<Vec<TestVote>>,
        qcs: Mutex<Vec<(u64, Identity)>>,
        tcs: Mutex<Vec<(u64, Vec<TimeoutSignerInfo>)>>,
    }

    impl VotingProviderFactory<AppState, TestVote> for RecordingFactory {
        fn make_vote(
            &self,
            state_rank: u64,
            state_id: &Identity,
            signature: Vec<u8>,
            voter_address: &[u8],
        ) -> Result<TestVote> {
            let v = TestVote {
                id: format!("vote-{}", state_rank),
                source: state_id.clone(),
                rank: state_rank,
                sig: signature,
                voter_address: voter_address.to_vec(),
            };
            self.votes.lock().unwrap().push(v.clone());
            Ok(v)
        }

        fn make_timeout_vote(
            &self,
            rank: u64,
            newest_qc_rank: u64,
            signature: Vec<u8>,
            voter_address: &[u8],
        ) -> Result<TestVote> {
            let v = TestVote {
                id: format!("to-{}-{}", rank, newest_qc_rank),
                source: format!("to-source-{}", rank),
                rank,
                sig: signature,
                voter_address: voter_address.to_vec(),
            };
            self.timeouts.lock().unwrap().push(v.clone());
            Ok(v)
        }

        fn make_quorum_certificate(
            &self,
            state: &State<AppState>,
            aggregated_sig: Arc<dyn AggregatedSignature>,
        ) -> Result<Arc<dyn QuorumCertificate>> {
            self.qcs
                .lock()
                .unwrap()
                .push((state.rank, state.identifier.clone()));
            Ok(Arc::new(FakeQc {
                rank: state.rank,
                id: state.identifier.clone(),
                agg_sig: aggregated_sig.signature().to_vec(),
                agg_pk: aggregated_sig.public_key().to_vec(),
            }))
        }

        fn make_timeout_certificate(
            &self,
            rank: u64,
            newest_qc: Arc<dyn QuorumCertificate>,
            signers: Vec<TimeoutSignerInfo>,
            aggregated_sig: Arc<dyn AggregatedSignature>,
        ) -> Result<Arc<dyn TimeoutCertificate>> {
            self.tcs
                .lock()
                .unwrap()
                .push((rank, signers.clone()));
            Ok(Arc::new(FakeTc {
                rank,
                latest_ranks: signers.iter().map(|s| s.newest_qc_rank).collect(),
                latest_qc_rank: newest_qc.rank(),
                latest_qc_id: newest_qc.identity().clone(),
                agg_sig: aggregated_sig.signature().to_vec(),
                agg_pk: aggregated_sig.public_key().to_vec(),
            }))
        }
    }

    // =================================================================
    // Fake QC/TC that report the aggregate bytes back for assertion
    // =================================================================

    #[derive(Debug)]
    struct FakeAgg {
        sig: Vec<u8>,
        pk: Vec<u8>,
    }
    impl AggregatedSignature for FakeAgg {
        fn signature(&self) -> &[u8] { &self.sig }
        fn public_key(&self) -> &[u8] { &self.pk }
        fn bitmask(&self) -> &[u8] { &[] }
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    struct FakeQc {
        rank: u64,
        id: Identity,
        agg_sig: Vec<u8>,
        agg_pk: Vec<u8>,
    }
    impl QuorumCertificate for FakeQc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn frame_number(&self) -> u64 { 0 }
        fn identity(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature {
            // Shim: a per-call FakeAgg stored inline would require
            // interior mutability. We just expose a static empty
            // for tests.
            &FAKE_AGG_EMPTY
        }
        fn equals(&self, o: &dyn QuorumCertificate) -> bool {
            self.rank == o.rank() && self.id == *o.identity()
        }
    }

    // Static empty AggregatedSignature for FakeQc::aggregated_signature().
    static FAKE_AGG_EMPTY: FakeAggEmpty = FakeAggEmpty;
    #[derive(Debug)]
    struct FakeAggEmpty;
    impl AggregatedSignature for FakeAggEmpty {
        fn signature(&self) -> &[u8] { &[] }
        fn public_key(&self) -> &[u8] { &[] }
        fn bitmask(&self) -> &[u8] { &[] }
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    struct FakeTc {
        rank: u64,
        latest_ranks: Vec<u64>,
        latest_qc_rank: u64,
        latest_qc_id: Identity,
        agg_sig: Vec<u8>,
        agg_pk: Vec<u8>,
    }
    impl FakeTc {
        fn latest_qc_fake(&self) -> FakeQc {
            FakeQc {
                rank: self.latest_qc_rank,
                id: self.latest_qc_id.clone(),
                agg_sig: vec![],
                agg_pk: vec![],
            }
        }
    }
    impl TimeoutCertificate for FakeTc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn latest_ranks(&self) -> &[u64] { &self.latest_ranks }
        fn latest_quorum_cert(&self) -> &dyn QuorumCertificate {
            // This is tricky because we can't return a reference to a
            // local. For tests, we box-leak a fake and return a
            // reference with the same lifetime as the TC. Acceptable
            // for tests; a real TC would carry an owned QC struct.
            Box::leak(Box::new(self.latest_qc_fake()))
        }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature {
            &FAKE_AGG_EMPTY
        }
        fn equals(&self, o: &dyn TimeoutCertificate) -> bool {
            self.rank == o.rank()
        }
    }

    // =================================================================
    // Helpers
    // =================================================================

    fn identity_derive() -> AddressDerivation {
        Arc::new(|pk: &[u8]| {
            // Derivation for tests: take the last 32 bytes of the pk
            // (or pad to 32).
            let mut out = vec![0u8; 32];
            let n = pk.len().min(32);
            out[32 - n..].copy_from_slice(&pk[pk.len() - n..]);
            out
        })
    }

    fn build_provider(
        factory: Arc<RecordingFactory>,
    ) -> BlsVotingProvider<AppState, TestVote, RecordingFactory> {
        let bls = Bls48581KeyConstructor;
        let (signer, _pk) = bls.new_key().unwrap();
        BlsVotingProvider::new(
            signer,
            b"test-vote".to_vec(),
            b"test-timeout".to_vec(),
            identity_derive(),
            factory,
        )
    }

    fn make_state(rank: u64, id: &str) -> State<AppState> {
        State {
            rank,
            identifier: id.into(),
            proposer_id: "leader".into(),
            parent_qc_identity: "parent".into(),
            parent_qc_rank: rank.saturating_sub(1),
            timestamp: 0,
            state: AppState { id: id.into(), rank },
        }
    }

    // =================================================================
    // Tests
    // =================================================================

    #[test]
    fn sign_vote_calls_factory_with_real_bls_signature() {
        let factory = Arc::new(RecordingFactory::default());
        let provider = build_provider(factory.clone());
        let state = make_state(5, "state-5");
        let vote = provider.sign_vote(&state).unwrap();
        assert_eq!(vote.rank, 5);
        assert_eq!(vote.source, "state-5");
        // Signature was actually produced — it's non-empty.
        assert!(!vote.sig.is_empty());
        // Voter address was derived from the BLS public key.
        assert_eq!(vote.voter_address.len(), 32);
        // Factory observed exactly one call.
        assert_eq!(factory.votes.lock().unwrap().len(), 1);
    }

    #[test]
    fn sign_vote_produces_verifiable_signature() {
        // End-to-end: sign a vote, then verify the signature against
        // the local public key using the canonical vote message.
        let factory = Arc::new(RecordingFactory::default());
        let bls = Bls48581KeyConstructor;
        let (signer, pk) = bls.new_key().unwrap();
        let provider = BlsVotingProvider::new(
            signer,
            b"test-vote".to_vec(),
            b"test-timeout".to_vec(),
            identity_derive(),
            factory.clone(),
        );
        let state = make_state(42, "s-42");
        let vote = provider.sign_vote(&state).unwrap();

        // Reconstruct the canonical message and verify.
        let msg = make_vote_message(&[], 42, &"s-42".to_string());
        assert!(bls.verify_signature_raw(&pk, &vote.sig, &msg, b"test-vote"));
    }

    #[test]
    fn sign_timeout_vote_produces_verifiable_signature() {
        let factory = Arc::new(RecordingFactory::default());
        let bls = Bls48581KeyConstructor;
        let (signer, pk) = bls.new_key().unwrap();
        let provider = BlsVotingProvider::new(
            signer,
            b"test-vote".to_vec(),
            b"test-timeout".to_vec(),
            identity_derive(),
            factory.clone(),
        );
        let vote = provider.sign_timeout_vote(&[], 10, 9).unwrap();
        assert_eq!(vote.rank, 10);
        assert!(!vote.sig.is_empty());

        let msg = make_timeout_message(&[], 10, 9);
        assert!(bls.verify_signature_raw(&pk, &vote.sig, &msg, b"test-timeout"));
    }

    #[test]
    fn sign_vote_and_timeout_use_different_domains() {
        let factory = Arc::new(RecordingFactory::default());
        let bls = Bls48581KeyConstructor;
        let (signer, pk) = bls.new_key().unwrap();
        let provider = BlsVotingProvider::new(
            signer,
            b"dom-A".to_vec(),
            b"dom-B".to_vec(),
            identity_derive(),
            factory.clone(),
        );
        // Same byte content signed under different domains must
        // produce different signatures.
        let vote_sig = {
            let vote = provider.sign_vote(&make_state(1, "x")).unwrap();
            vote.sig
        };
        // Sign a timeout with the "same" canonical bytes (not strictly
        // possible since timeout has a different layout, but the
        // domain separation is the point — different domain → a
        // signature over `msg_timeout` does NOT verify as a signature
        // over `msg_vote` under the vote domain).
        let msg_vote = make_vote_message(&[], 1, &"x".to_string());
        assert!(bls.verify_signature_raw(&pk, &vote_sig, &msg_vote, b"dom-A"));
        // Cross-domain verify fails.
        assert!(!bls.verify_signature_raw(&pk, &vote_sig, &msg_vote, b"dom-B"));
    }

    #[test]
    fn finalize_quorum_certificate_delegates_to_factory() {
        let factory = Arc::new(RecordingFactory::default());
        let provider = build_provider(factory.clone());
        let state = make_state(7, "st-7");
        let agg: Arc<dyn AggregatedSignature> = Arc::new(FakeAgg {
            sig: vec![1, 2, 3],
            pk: vec![4, 5, 6],
        });
        let qc = provider.finalize_quorum_certificate(&state, agg).unwrap();
        assert_eq!(qc.rank(), 7);
        assert_eq!(factory.qcs.lock().unwrap().len(), 1);
        assert_eq!(factory.qcs.lock().unwrap()[0], (7, "st-7".into()));
    }

    #[test]
    fn finalize_timeout_threads_signers_through() {
        let factory = Arc::new(RecordingFactory::default());
        let provider = build_provider(factory.clone());
        let qc: Arc<dyn QuorumCertificate> = Arc::new(FakeQc {
            rank: 8,
            id: "qc-8".into(),
            agg_sig: vec![],
            agg_pk: vec![],
        });
        let signers = vec![
            TimeoutSignerInfo { newest_qc_rank: 8, signer: "a".into() },
            TimeoutSignerInfo { newest_qc_rank: 7, signer: "b".into() },
        ];
        let agg: Arc<dyn AggregatedSignature> = Arc::new(FakeAgg {
            sig: vec![0xAA],
            pk: vec![0xBB],
        });
        let tc = provider.finalize_timeout(9, qc, signers, agg).unwrap();
        assert_eq!(tc.rank(), 9);
        assert_eq!(tc.latest_ranks(), &[8, 7]);
        let recorded = factory.tcs.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, 9);
        assert_eq!(recorded[0].1.len(), 2);
    }

    #[test]
    fn voter_address_is_stable_across_calls() {
        let factory = Arc::new(RecordingFactory::default());
        let provider = build_provider(factory.clone());
        let v1 = provider.sign_vote(&make_state(1, "a")).unwrap();
        let v2 = provider.sign_vote(&make_state(2, "b")).unwrap();
        // Same signer → same voter address.
        assert_eq!(v1.voter_address, v2.voter_address);
    }
}
