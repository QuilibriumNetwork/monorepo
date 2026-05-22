//! Per-rank timeout aggregation for global consensus.
//!
//! Mirrors [`vote_aggregation`](crate::vote_aggregation) but for
//! `TimeoutState` messages. On reaching the partial-TC (>=1/3 weight)
//! or full-TC (>=2/3 weight) threshold for a rank, the processor fires
//! callbacks that forward into the HotStuff event loop via
//! `submit_partial_timeout_certificate` /
//! `submit_timeout_certificate`.
//!
//! Structurally simpler than the vote aggregator — no Caching/Verifying
//! state machine, because a timeout vote doesn't need to be matched
//! against a proposal first. The `TimeoutProcessor` itself handles
//! both the signature aggregation and the TC finalization.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{debug, info, warn};

use quil_consensus::event_loop::EventLoopHandle;
use quil_consensus::models::{TimeoutCertificate, TimeoutState, Unique};
use quil_consensus::signature_aggregator::{
    SignatureAggregator, TimeoutSignatureAggregator, TimeoutSignatureAggregatorImpl,
};
use quil_consensus::timeout_processor::{
    OnPartialTimeoutCertificateCreated, TimeoutProcessor,
};
use quil_consensus::committee::Replicas;
use quil_consensus::validator::Validator;
use quil_consensus::voting_provider::{OnTimeoutCertificateCreated, VotingProvider};
use quil_types::crypto::BlsConstructor;
use quil_types::error::Result;

use crate::bls_signature_aggregator::BlsSignatureAggregator;
use crate::bls_verifier::BlsConsensusVerifier;
use crate::committee::ProverRegistryCommittee;
use crate::consensus_types::{GlobalState, GlobalVote};
use crate::validator::ConsensusValidator;

/// Owns the per-rank timeout-processor map and the glue that turns
/// sufficient weighted timeout signatures into a `TimeoutCertificate`
/// that's submitted back to the HotStuff event loop.
pub struct TimeoutAggregation {
    committee: Arc<ProverRegistryCommittee>,
    voting_provider: Arc<dyn VotingProvider<GlobalState, GlobalVote>>,
    validator: Arc<dyn Validator<GlobalState, GlobalVote>>,
    consensus_handle: Arc<OnceLock<EventLoopHandle<GlobalState, GlobalVote>>>,
    bls: Arc<dyn BlsConstructor>,
    timeout_domain: Vec<u8>,
    processors: Mutex<HashMap<u64, Arc<TimeoutProcessor<GlobalState, GlobalVote>>>>,
    min_active_rank: AtomicU64,
}

impl TimeoutAggregation {
    pub fn new(
        committee: Arc<ProverRegistryCommittee>,
        voting_provider: Arc<dyn VotingProvider<GlobalState, GlobalVote>>,
        consensus_handle: Arc<OnceLock<EventLoopHandle<GlobalState, GlobalVote>>>,
        bls: Arc<dyn BlsConstructor>,
        vote_domain: Vec<u8>,
        timeout_domain: Vec<u8>,
    ) -> Self {
        // The validator needs a Verifier that can check both QCs
        // (signed with vote_domain) and TCs (signed with timeout_domain).
        // Pre-fix it used vote_domain for both, which silently broke
        // TC validation as soon as a real TC arrived.
        let raw: Arc<dyn SignatureAggregator> =
            Arc::new(BlsSignatureAggregator::new(bls.clone()));
        let verifier = Arc::new(BlsConsensusVerifier::new_with_timeout_domain(
            raw,
            vote_domain,
            timeout_domain.clone(),
        ));
        let committee_as_replicas: Arc<dyn Replicas> = committee.clone();
        let validator: Arc<dyn Validator<GlobalState, GlobalVote>> = Arc::new(
            ConsensusValidator::<GlobalState, GlobalVote>::new(
                committee_as_replicas,
                verifier,
            ),
        );
        Self {
            committee,
            voting_provider,
            validator,
            consensus_handle,
            bls,
            timeout_domain,
            processors: Mutex::new(HashMap::new()),
            min_active_rank: AtomicU64::new(0),
        }
    }

    /// Feed a reconstructed `TimeoutState` to its rank's processor.
    pub fn handle_timeout(&self, ts: TimeoutState<GlobalVote>) {
        let rank = ts.rank;
        let voter = hex::encode(ts.vote.identity());
        let qc_rank = ts.latest_quorum_certificate.rank();
        let min_active = self.min_active_rank.load(Ordering::Relaxed);
        if rank < min_active {
            info!(rank, min_active, voter = %voter, "dropping timeout below finalized rank");
            return;
        }
        info!(rank, qc_rank, voter = %voter, "ingesting timeout");
        let proc = match self.get_or_create(rank) {
            Ok(p) => p,
            Err(e) => {
                warn!(rank, error = %e, "timeout processor build failed");
                return;
            }
        };
        if let Err(e) = proc.process(ts) {
            // Surface rejections at info: a stuck chain usually means
            // every peer's timeout is being rejected for the same
            // reason (sig domain mismatch, identity not in registry,
            // etc.), and the only way to spot that without recompiling
            // for debug logs is to print it here.
            info!(rank, voter = %voter, error = %e, "timeout processor rejected timeout");
        }
    }

    pub fn advance_min_active_rank(&self, rank: u64) {
        let prev = self.min_active_rank.fetch_max(rank, Ordering::Relaxed);
        if rank <= prev {
            return;
        }
        let mut map = self.processors.lock().unwrap();
        map.retain(|r, _| *r >= rank);
    }

    fn get_or_create(
        &self,
        rank: u64,
    ) -> Result<Arc<TimeoutProcessor<GlobalState, GlobalVote>>> {
        // Fast path: already instantiated.
        {
            let map = self.processors.lock().unwrap();
            if let Some(p) = map.get(&rank) {
                return Ok(p.clone());
            }
        }

        // Slow path: build a fresh processor for this rank. This involves
        // a registry snapshot via `identities_by_rank`, so we keep the
        // lock released during construction to avoid blocking other
        // callers on a potentially-slow store read.
        let ids = self.committee.identities_by_rank(rank)?;
        let raw: Arc<dyn SignatureAggregator> =
            Arc::new(BlsSignatureAggregator::new(self.bls.clone()));
        let sig_agg: Arc<dyn TimeoutSignatureAggregator> = Arc::new(
            TimeoutSignatureAggregatorImpl::new(
                raw,
                Vec::new(), // global filter
                rank,
                ids,
                self.timeout_domain.clone(),
            )?,
        );

        let qc_threshold = self.committee.quorum_threshold_for_rank(rank)?;
        let timeout_threshold = self.committee.timeout_threshold_for_rank(rank)?;

        let on_partial = self.make_on_partial_tc_created();
        let on_full = self.make_on_tc_created();

        let proc = Arc::new(TimeoutProcessor::new(
            rank,
            self.validator.clone(),
            sig_agg,
            self.voting_provider.clone(),
            qc_threshold,
            timeout_threshold,
            on_partial,
            on_full,
        ));

        let mut map = self.processors.lock().unwrap();
        // Race: another caller may have inserted a processor for this
        // rank. Return that one instead of ours to keep a single
        // source-of-truth per rank.
        if let Some(existing) = map.get(&rank) {
            return Ok(existing.clone());
        }
        map.insert(rank, proc.clone());
        Ok(proc)
    }

    fn make_on_partial_tc_created(&self) -> OnPartialTimeoutCertificateCreated {
        let handle_cell = self.consensus_handle.clone();
        Arc::new(move |partial| {
            if let Some(handle) = handle_cell.get() {
                info!(
                    rank = partial.rank,
                    newest_qc_rank = partial.newest_quorum_certificate.rank(),
                    "submitting partial TC to event loop"
                );
                handle.submit_partial_timeout_certificate(partial);
            }
        })
    }

    fn make_on_tc_created(&self) -> OnTimeoutCertificateCreated {
        let handle_cell = self.consensus_handle.clone();
        Arc::new(move |tc: Arc<dyn TimeoutCertificate>| {
            if let Some(handle) = handle_cell.get() {
                info!(
                    rank = tc.rank(),
                    "submitting locally-aggregated TC to event loop"
                );
                handle.submit_timeout_certificate(tc);
            }
        })
    }
}

/// Convert a wire `TimeoutState` (plus its embedded QC/TC already in
/// trait-object form) into the typed `TimeoutState<GlobalVote>` the
/// processor accepts.
pub fn wire_timeout_to_typed(
    wire: crate::consensus_wire::TimeoutState,
) -> TimeoutState<GlobalVote> {
    let latest_qc = wire.latest_quorum_certificate.into_trait_object();
    let prior_tc = wire
        .prior_rank_timeout_certificate
        .map(|tc| tc.into_trait_object());
    let vote = crate::vote_aggregation::wire_vote_to_global_vote(wire.vote);
    TimeoutState {
        rank: vote.rank(),
        latest_quorum_certificate: latest_qc,
        prior_rank_timeout_certificate: prior_tc,
        vote,
        timeout_tick: wire.timeout_tick,
    }
}
