//! Per-rank timeout processor. Mirror of
//! `consensus/timeoutcollector/timeout_processor.go`.
//!
//! A `TimeoutProcessor` verifies individual timeout states for a single
//! rank, tracks the newest QC it sees across all timeouts, and
//! aggregates signatures until the partial-TC (>1/3 weight) or full-TC
//! (>2/3 weight) thresholds are crossed. Both thresholds fire their
//! respective callbacks **exactly once**.
//!
//! Concurrency-safe: `process` may be called from multiple tasks.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::models::{QuorumCertificate, TimeoutCertificate, TimeoutState, Unique};
use crate::signature_aggregator::TimeoutSignatureAggregator;
use crate::timeout_aggregator::PartialTimeoutCertificateCreated;
use crate::tracker::NewestQcTracker;
use crate::validator::Validator;
use crate::voting_provider::{OnTimeoutCertificateCreated, VotingProvider};
use quil_types::error::{QuilError, Result};

/// Tracks a one-time "weight reached threshold" event using an atomic
/// boolean flag. Mirror of Go's `accumulatedWeightTracker`.
#[derive(Debug)]
pub struct AccumulatedWeightTracker {
    min_required: u64,
    done: AtomicBool,
}

impl AccumulatedWeightTracker {
    pub fn new(min_required: u64) -> Self {
        Self {
            min_required,
            done: AtomicBool::new(false),
        }
    }

    pub fn done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Returns `true` iff `weight >= min_required` AND this is the first
    /// call to observe the threshold crossing. All subsequent calls
    /// return `false`.
    pub fn track(&self, weight: u64) -> bool {
        if weight < self.min_required {
            return false;
        }
        self.done
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

/// Per-rank timeout processor. Mirror of Go's `TimeoutProcessor`.
///
/// The processor carries a [`TimeoutSignatureAggregator`] (which binds
/// to a specific rank), a partial-TC threshold, and a full-TC threshold.
/// On crossing the partial threshold we fire
/// `on_partial_tc_created` with the newest observed QC; on crossing the
/// full threshold we build the TC via the voting provider and fire
/// `on_tc_created`.
pub struct TimeoutProcessor<S: Unique, V: Unique> {
    rank: u64,
    validator: Arc<dyn Validator<S, V>>,
    sig_aggregator: Arc<dyn TimeoutSignatureAggregator>,
    voting: Arc<dyn VotingProvider<S, V>>,
    partial_tc_tracker: AccumulatedWeightTracker,
    tc_tracker: AccumulatedWeightTracker,
    newest_qc_tracker: NewestQcTracker,
    on_partial_tc_created: OnPartialTimeoutCertificateCreated,
    on_tc_created: OnTimeoutCertificateCreated,
}

/// Partial-TC callback. Fires once, when the weight crosses the 1/3
/// threshold. Receives the rank and the newest QC seen so far.
pub type OnPartialTimeoutCertificateCreated =
    Arc<dyn Fn(PartialTimeoutCertificateCreated) + Send + Sync>;

impl<S: Unique, V: Unique> TimeoutProcessor<S, V> {
    pub fn new(
        rank: u64,
        validator: Arc<dyn Validator<S, V>>,
        sig_aggregator: Arc<dyn TimeoutSignatureAggregator>,
        voting: Arc<dyn VotingProvider<S, V>>,
        qc_threshold: u64,
        timeout_threshold: u64,
        on_partial_tc_created: OnPartialTimeoutCertificateCreated,
        on_tc_created: OnTimeoutCertificateCreated,
    ) -> Self {
        Self {
            rank,
            validator,
            sig_aggregator,
            voting,
            partial_tc_tracker: AccumulatedWeightTracker::new(timeout_threshold),
            tc_tracker: AccumulatedWeightTracker::new(qc_threshold),
            newest_qc_tracker: NewestQcTracker::new(),
            on_partial_tc_created,
            on_tc_created,
        }
    }

    /// The rank this processor covers.
    pub fn rank(&self) -> u64 {
        self.rank
    }

    /// `true` once the full TC has been built.
    pub fn is_done(&self) -> bool {
        self.tc_tracker.done()
    }

    /// Process a single timeout state. Expected error returns:
    /// - `IncompatibleRank` — timeout is for a different rank
    /// - `InvalidTimeout` — wraps InvalidSigner / InvalidSignature / structural bugs
    /// - `DuplicatedSigner` — same signer already added (benign)
    pub fn process(&self, timeout: TimeoutState<V>) -> Result<()> {
        if self.rank != timeout.rank {
            return Err(QuilError::IncompatibleRank(format!(
                "received incompatible timeout, expected {} got {}",
                self.rank, timeout.rank
            )));
        }

        if self.tc_tracker.done() {
            return Ok(());
        }

        self.validate_timeout(&timeout)?;

        if self.tc_tracker.done() {
            return Ok(());
        }

        // CRITICAL: update the newest-QC tracker BEFORE adding the
        // signature to the aggregator. The TC consistency invariant
        // requires: newestQC.rank ≥ max(signer's latest_qc_ranks).
        // Updating the tracker first guarantees that property.
        self.newest_qc_tracker
            .track(Arc::clone(&timeout.latest_quorum_certificate));

        let vote = &timeout.vote;
        let newest_qc_rank = timeout.latest_quorum_certificate.rank();
        let total_weight = match self.sig_aggregator.verify_and_add(
            vote.identity(),
            vote.signature(),
            newest_qc_rank,
        ) {
            Ok(w) => w,
            Err(e) if e.is_invalid_signer() => {
                return Err(QuilError::InvalidTimeout(format!(
                    "invalid signer for timeout: {}",
                    e
                )))
            }
            Err(e) if e.is_invalid_signature() => {
                return Err(QuilError::InvalidTimeout(format!(
                    "timeout is from valid signer but has cryptographically invalid signature: {}",
                    e
                )))
            }
            Err(e) => {
                // DuplicatedSigner bubbles up; caller treats as benign.
                return Err(e);
            }
        };

        // Partial-TC threshold crossover (one-shot).
        if self.partial_tc_tracker.track(total_weight) {
            if let Some(newest_qc) = self.newest_qc_tracker.newest_qc() {
                (self.on_partial_tc_created)(PartialTimeoutCertificateCreated {
                    rank: self.rank,
                    newest_quorum_certificate: newest_qc,
                    prior_rank_timeout_certificate: timeout
                        .prior_rank_timeout_certificate
                        .as_ref()
                        .map(Arc::clone),
                });
            }
        }

        // Full TC threshold crossover (one-shot).
        if !self.tc_tracker.track(total_weight) {
            return Ok(());
        }
        let tc = self.build_tc()?;
        (self.on_tc_created)(tc);
        Ok(())
    }

    /// Structural + signature validation of a timeout state. Mirror of
    /// Go's `validateTimeout`.
    fn validate_timeout(&self, timeout: &TimeoutState<V>) -> Result<()> {
        let qc_rank = timeout.latest_quorum_certificate.rank();

        // (a) Every TO must contain a QC with rank strictly below the TO.
        if timeout.rank <= qc_rank {
            return Err(QuilError::InvalidTimeout(format!(
                "TO's QC {} cannot be newer than the TO's rank {}",
                qc_rank, timeout.rank
            )));
        }

        // (b) If a TC is included, validate its structure.
        if let Some(tc) = &timeout.prior_rank_timeout_certificate {
            if timeout.rank != tc.rank() + 1 {
                return Err(QuilError::InvalidTimeout(format!(
                    "invalid TC for non-previous rank, expected {}, got {}",
                    timeout.rank - 1,
                    tc.rank()
                )));
            }
            let tc_embedded_qc_rank = tc.latest_quorum_cert().rank();
            if qc_rank < tc_embedded_qc_rank {
                return Err(QuilError::InvalidTimeout(format!(
                    "timeout.LatestQuorumCertificate is older (rank={}) than the QC in timeout.PriorRankTimeoutCertificate (rank={})",
                    qc_rank, tc_embedded_qc_rank
                )));
            }
        }

        // (c) Must have a proof of entering this rank: either a QC from
        //     the previous rank (happy path) or a TC for the previous
        //     rank.
        let last_rank_successful = timeout.rank == qc_rank + 1;
        if !last_rank_successful && timeout.prior_rank_timeout_certificate.is_none() {
            return Err(QuilError::InvalidTimeout("timeout must include TC".into()));
        }

        // (2) Validate embedded QC.
        self.validator
            .validate_quorum_certificate(timeout.latest_quorum_certificate.as_ref())
            .map_err(|e| {
                if e.is_invalid_quorum_certificate() {
                    QuilError::InvalidTimeout(format!("included QC is invalid: {}", e))
                } else {
                    QuilError::Consensus(format!("unexpected error when validating QC: {}", e))
                }
            })?;

        // (3) Validate embedded TC if present.
        if let Some(tc) = &timeout.prior_rank_timeout_certificate {
            self.validator
                .validate_timeout_certificate(tc.as_ref())
                .map_err(|e| {
                    if e.is_invalid_timeout_certificate() {
                        QuilError::InvalidTimeout(format!("included TC is invalid: {}", e))
                    } else {
                        QuilError::Consensus(format!("unexpected error when validating TC: {}", e))
                    }
                })?;
        }
        Ok(())
    }

    /// Aggregate signatures and finalize the TC via the voting provider.
    fn build_tc(&self) -> Result<Arc<dyn TimeoutCertificate>> {
        let (signers_info, aggregated_sig) = self.sig_aggregator.aggregate().map_err(|e| {
            QuilError::Consensus(format!("could not aggregate multi message signature: {}", e))
        })?;

        let newest_qc: Arc<dyn QuorumCertificate> = match self.newest_qc_tracker.newest_qc() {
            Some(q) => q,
            None => {
                return Err(QuilError::Consensus(
                    "no newest QC tracked — TO processor reached build without any QC".into(),
                ))
            }
        };

        self.voting
            .finalize_timeout(self.rank, newest_qc, signers_info, aggregated_sig)
            .map_err(|e| QuilError::Consensus(format!("could not construct timeout certificate: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AggregatedSignature, Identity, QuorumCertificate, SignedProposal, WeightedIdentity,
    };
    use crate::signature_aggregator::TimeoutSignerInfo;
    use std::sync::atomic::AtomicU64;
    use std::sync::Mutex;

    // ---------- types ----------
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
        sig: Vec<u8>,
    }
    impl Unique for TVote {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &self.sig }
    }

    // ---------- crypto stubs ----------
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
        fn equals(&self, o: &dyn QuorumCertificate) -> bool {
            self.rank == o.rank() && self.id == *o.identity()
        }
    }

    #[derive(Debug)]
    struct StubTc {
        rank: u64,
        #[allow(dead_code)]
        id: Identity,
        latest_qc: StubQc,
    }
    impl TimeoutCertificate for StubTc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn latest_ranks(&self) -> &[u64] { &[] }
        fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { &self.latest_qc }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, o: &dyn TimeoutCertificate) -> bool {
            self.rank == o.rank()
        }
    }

    // ---------- validator stub ----------
    struct AlwaysValidValidator;
    impl Validator<AppState, TVote> for AlwaysValidValidator {
        fn validate_quorum_certificate(&self, _qc: &dyn QuorumCertificate) -> Result<()> {
            Ok(())
        }
        fn validate_timeout_certificate(&self, _tc: &dyn TimeoutCertificate) -> Result<()> {
            Ok(())
        }
        fn validate_proposal(&self, _p: &SignedProposal<AppState, TVote>) -> Result<()> {
            Ok(())
        }
        fn validate_vote(&self, _v: &TVote) -> Result<Box<dyn WeightedIdentity>> {
            Err(QuilError::Internal("validate_vote not supported in stub".into()))
        }
    }

    // ---------- timeout sig aggregator stub ----------
    struct StubTimeoutAggregator {
        rank: u64,
        valid_signers: Vec<Identity>,
        weight_each: u64,
        total: Mutex<u64>,
        added: Mutex<Vec<Identity>>,
    }
    impl TimeoutSignatureAggregator for StubTimeoutAggregator {
        fn verify_and_add(
            &self,
            signer_id: &Identity,
            _sig: &[u8],
            _newest_qc_rank: u64,
        ) -> Result<u64> {
            if !self.valid_signers.contains(signer_id) {
                return Err(QuilError::InvalidSigner(hex::encode(signer_id)));
            }
            let mut added = self.added.lock().unwrap();
            if added.contains(signer_id) {
                return Err(QuilError::DuplicatedSigner(hex::encode(signer_id)));
            }
            added.push(signer_id.clone());
            let mut t = self.total.lock().unwrap();
            *t += self.weight_each;
            Ok(*t)
        }
        fn total_weight(&self) -> u64 {
            *self.total.lock().unwrap()
        }
        fn rank(&self) -> u64 {
            self.rank
        }
        fn aggregate(
            &self,
        ) -> Result<(Vec<TimeoutSignerInfo>, Arc<dyn AggregatedSignature>)> {
            let signers = self
                .added
                .lock()
                .unwrap()
                .iter()
                .map(|s| TimeoutSignerInfo {
                    newest_qc_rank: 0,
                    signer: s.clone(),
                })
                .collect();
            Ok((signers, Arc::new(StubAgg)))
        }
    }

    // ---------- voting provider stub ----------
    struct StubVotingProvider {
        tc_built: AtomicU64,
    }
    impl VotingProvider<AppState, TVote> for StubVotingProvider {
        fn sign_vote(&self, _s: &crate::models::State<AppState>) -> Result<TVote> {
            Err(QuilError::Internal("sign_vote not supported in stub".into()))
        }
        fn sign_timeout_vote(&self, _f: &[u8], _c: u64, _n: u64) -> Result<TVote> {
            Err(QuilError::Internal("sign_timeout_vote not supported in stub".into()))
        }
        fn finalize_quorum_certificate(
            &self,
            _s: &crate::models::State<AppState>,
            _a: Arc<dyn AggregatedSignature>,
        ) -> Result<Arc<dyn QuorumCertificate>> {
            Err(QuilError::Internal("finalize_quorum_certificate not supported in stub".into()))
        }
        fn finalize_timeout(
            &self,
            rank: u64,
            _qc: Arc<dyn QuorumCertificate>,
            _signers: Vec<TimeoutSignerInfo>,
            _agg: Arc<dyn AggregatedSignature>,
        ) -> Result<Arc<dyn TimeoutCertificate>> {
            self.tc_built.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(StubTc {
                rank,
                id: format!("tc-{}", rank).into_bytes(),
                latest_qc: StubQc {
                    rank: rank.saturating_sub(1),
                    id: format!("qc-{}", rank - 1).into_bytes(),
                },
            }))
        }
    }

    // ---------- builders ----------
    fn make_timeout(rank: u64, voter: &str, qc_rank: u64, sig: &[u8]) -> TimeoutState<TVote> {
        TimeoutState {
            rank,
            latest_quorum_certificate: Arc::new(StubQc {
                rank: qc_rank,
                id: format!("qc-{}", qc_rank).into_bytes(),
            }),
            prior_rank_timeout_certificate: None,
            vote: TVote {
                id: voter.into(),
                rank,
                sig: sig.to_vec(),
            },
            timeout_tick: 0,
        }
    }

    fn make_processor(
        rank: u64,
        valid_signers: Vec<Identity>,
        qc_threshold: u64,
        timeout_threshold: u64,
        weight_each: u64,
    ) -> (
        TimeoutProcessor<AppState, TVote>,
        Arc<AtomicU64>, // partial count
        Arc<AtomicU64>, // full tc count
        Arc<StubVotingProvider>,
    ) {
        let validator: Arc<dyn Validator<AppState, TVote>> = Arc::new(AlwaysValidValidator);
        let agg = Arc::new(StubTimeoutAggregator {
            rank,
            valid_signers,
            weight_each,
            total: Mutex::new(0),
            added: Mutex::new(vec![]),
        }) as Arc<dyn TimeoutSignatureAggregator>;
        let vp = Arc::new(StubVotingProvider {
            tc_built: AtomicU64::new(0),
        });
        let partial_count = Arc::new(AtomicU64::new(0));
        let tc_count = Arc::new(AtomicU64::new(0));
        let pc = Arc::clone(&partial_count);
        let tcc = Arc::clone(&tc_count);
        let on_partial: OnPartialTimeoutCertificateCreated =
            Arc::new(move |_| {
                pc.fetch_add(1, Ordering::SeqCst);
            });
        let on_tc: OnTimeoutCertificateCreated = Arc::new(move |_| {
            tcc.fetch_add(1, Ordering::SeqCst);
        });
        let proc = TimeoutProcessor::new(
            rank,
            validator,
            agg,
            vp.clone() as Arc<dyn VotingProvider<AppState, TVote>>,
            qc_threshold,
            timeout_threshold,
            on_partial,
            on_tc,
        );
        (proc, partial_count, tc_count, vp)
    }

    // ---------- tests ----------
    #[test]
    fn weight_tracker_crosses_once() {
        let t = AccumulatedWeightTracker::new(10);
        assert!(!t.track(5));
        assert!(!t.done());
        assert!(t.track(10));
        assert!(t.done());
        // Subsequent crossings don't re-fire.
        assert!(!t.track(20));
    }

    #[test]
    fn wrong_rank_is_incompatible_rank() {
        let (proc, _, _, _) = make_processor(5, vec!["alice".into()], 2, 1, 1);
        let err = proc.process(make_timeout(7, "alice", 4, b"sig")).unwrap_err();
        assert!(err.is_incompatible_rank());
    }

    #[test]
    fn qc_rank_geq_to_rank_is_invalid_timeout() {
        let (proc, _, _, _) = make_processor(5, vec!["alice".into()], 2, 1, 1);
        // QC rank 5 == timeout rank 5 → invalid.
        let err = proc.process(make_timeout(5, "alice", 5, b"sig")).unwrap_err();
        assert!(err.is_invalid_timeout());
    }

    #[test]
    fn missing_tc_for_nonconsecutive_qc_is_invalid() {
        let (proc, _, _, _) = make_processor(5, vec!["alice".into()], 2, 1, 1);
        // QC at rank 2, timeout at rank 5, no TC — invalid.
        let err = proc.process(make_timeout(5, "alice", 2, b"sig")).unwrap_err();
        assert!(err.is_invalid_timeout());
    }

    #[test]
    fn partial_threshold_fires_once() {
        let (proc, partial, tc, _) = make_processor(5, vec!["alice".into(), "bob".into()], 4, 1, 1);
        // 1st timeout crosses partial threshold (weight 1 >= 1).
        proc.process(make_timeout(5, "alice", 4, b"sig1")).unwrap();
        assert_eq!(partial.load(Ordering::SeqCst), 1);
        // 2nd does not refire partial.
        proc.process(make_timeout(5, "bob", 4, b"sig2")).unwrap();
        assert_eq!(partial.load(Ordering::SeqCst), 1);
        // TC threshold 4 not yet reached.
        assert_eq!(tc.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn full_threshold_builds_tc_once() {
        let (proc, _partial, tc, vp) =
            make_processor(5, vec!["alice".into(), "bob".into(), "carol".into()], 3, 1, 1);
        proc.process(make_timeout(5, "alice", 4, b"sig1")).unwrap();
        proc.process(make_timeout(5, "bob", 4, b"sig2")).unwrap();
        proc.process(make_timeout(5, "carol", 4, b"sig3")).unwrap();
        assert!(proc.is_done());
        assert_eq!(tc.load(Ordering::SeqCst), 1);
        assert_eq!(vp.tc_built.load(Ordering::SeqCst), 1);
        // Further timeouts are no-ops.
        // (Can't add more — signers exhausted. Fine.)
    }

    #[test]
    fn invalid_signer_is_invalid_timeout() {
        let (proc, _, _, _) = make_processor(5, vec!["alice".into()], 3, 1, 1);
        let err = proc
            .process(make_timeout(5, "stranger", 4, b"sig"))
            .unwrap_err();
        assert!(err.is_invalid_timeout());
    }
}
