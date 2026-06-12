//! Per-rank timeout aggregation for a single app shard.
//!
//! Parallel of [`timeout_aggregation`](crate::timeout_aggregation) but
//! typed for `AppShardState`/`AppShardVote` and parameterised by the
//! shard filter. Multi-prover shards need this so peer timeout votes
//! aggregate into a TC; until it was wired the engine observed
//! timeouts but never advanced consensus through them.
//!
//! Structurally mirrors `TimeoutAggregation` 1:1 — only the typed
//! generics and the per-shard filter (used by the signature aggregator
//! when binding to the shard's vote domain) differ.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{debug, info};

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

use crate::app_types::{AppShardState, AppShardVote};
use crate::bls_signature_aggregator::BlsSignatureAggregator;
use crate::bls_verifier::BlsConsensusVerifier;
use crate::committee::ProverRegistryCommittee;
use crate::validator::ConsensusValidator;

/// Per-shard timeout aggregator. One per `AppConsensusEngine`.
pub struct AppTimeoutAggregation {
    filter: Vec<u8>,
    committee: Arc<ProverRegistryCommittee>,
    voting_provider: Arc<dyn VotingProvider<AppShardState, AppShardVote>>,
    validator: Arc<dyn Validator<AppShardState, AppShardVote>>,
    consensus_handle: Arc<OnceLock<EventLoopHandle<AppShardState, AppShardVote>>>,
    bls: Arc<dyn BlsConstructor>,
    timeout_domain: Vec<u8>,
    processors:
        Mutex<HashMap<u64, Arc<TimeoutProcessor<AppShardState, AppShardVote>>>>,
    min_active_rank: AtomicU64,
}

impl AppTimeoutAggregation {
    pub fn new(
        filter: Vec<u8>,
        committee: Arc<ProverRegistryCommittee>,
        voting_provider: Arc<dyn VotingProvider<AppShardState, AppShardVote>>,
        consensus_handle: Arc<OnceLock<EventLoopHandle<AppShardState, AppShardVote>>>,
        bls: Arc<dyn BlsConstructor>,
        vote_domain: Vec<u8>,
        timeout_domain: Vec<u8>,
    ) -> Self {
        // Validator wraps a Verifier built from BLS + distinct
        // vote/timeout domains so that both QC validation (signed under
        // vote_domain) and TC validation (signed under timeout_domain)
        // succeed inside `TimeoutProcessor::process`.
        let raw: Arc<dyn SignatureAggregator> =
            Arc::new(BlsSignatureAggregator::new(bls.clone()));
        let verifier = Arc::new(BlsConsensusVerifier::new_with_timeout_domain(
            raw,
            vote_domain,
            timeout_domain.clone(),
        ));
        let committee_as_replicas: Arc<dyn Replicas> = committee.clone();
        let validator: Arc<dyn Validator<AppShardState, AppShardVote>> = Arc::new(
            ConsensusValidator::<AppShardState, AppShardVote>::new(
                committee_as_replicas,
                verifier,
            ),
        );
        Self {
            filter,
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
    pub fn handle_timeout(&self, ts: TimeoutState<AppShardVote>) {
        let rank = ts.rank;
        if rank < self.min_active_rank.load(Ordering::Relaxed) {
            debug!(rank, "dropping shard timeout below finalized rank");
            return;
        }
        let proc = match self.get_or_create(rank) {
            Ok(p) => p,
            Err(e) => {
                debug!(rank, error = %e, "shard timeout processor build failed");
                return;
            }
        };
        if let Err(e) = proc.process(ts) {
            debug!(rank, error = %e, "shard timeout processor rejected timeout");
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
    ) -> Result<Arc<TimeoutProcessor<AppShardState, AppShardVote>>> {
        // Fast path.
        {
            let map = self.processors.lock().unwrap();
            if let Some(p) = map.get(&rank) {
                return Ok(p.clone());
            }
        }

        // Slow path: build a fresh processor for this rank. Identity
        // snapshot is held briefly, then committee lock is released
        // before constructing the processor so concurrent callers don't
        // serialize on a potentially-slow registry read.
        let ids = self.committee.identities_by_rank(rank)?;
        let raw: Arc<dyn SignatureAggregator> =
            Arc::new(BlsSignatureAggregator::new(self.bls.clone()));
        let sig_agg: Arc<dyn TimeoutSignatureAggregator> = Arc::new(
            TimeoutSignatureAggregatorImpl::new(
                raw,
                self.filter.clone(),
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
        // Race: another caller may have inserted between the fast-path
        // miss and our acquire. Return that one.
        if let Some(existing) = map.get(&rank) {
            return Ok(existing.clone());
        }
        map.insert(rank, proc.clone());
        Ok(proc)
    }

    fn make_on_partial_tc_created(&self) -> OnPartialTimeoutCertificateCreated {
        let handle_cell = self.consensus_handle.clone();
        let filter_for_log = hex::encode(&self.filter);
        Arc::new(move |partial| {
            if let Some(handle) = handle_cell.get() {
                info!(
                    filter = %filter_for_log,
                    rank = partial.rank,
                    newest_qc_rank = partial.newest_quorum_certificate.rank(),
                    "submitting shard partial TC to event loop"
                );
                handle.submit_partial_timeout_certificate(partial);
            }
        })
    }

    fn make_on_tc_created(&self) -> OnTimeoutCertificateCreated {
        let handle_cell = self.consensus_handle.clone();
        let filter_for_log = hex::encode(&self.filter);
        Arc::new(move |tc: Arc<dyn TimeoutCertificate>| {
            if let Some(handle) = handle_cell.get() {
                info!(
                    filter = %filter_for_log,
                    rank = tc.rank(),
                    "submitting locally-aggregated shard TC to event loop"
                );
                handle.submit_timeout_certificate(tc);
            }
        })
    }
}

/// Convert a wire `TimeoutState` (whose embedded QC/TC are already in
/// trait-object form) into the typed `TimeoutState<AppShardVote>` that
/// `AppTimeoutAggregation::handle_timeout` accepts. `filter` is the
/// shard's bitmask filter, used to bind the embedded vote.
pub fn wire_timeout_to_app_typed(
    wire: crate::consensus_wire::TimeoutState,
    filter: Vec<u8>,
) -> TimeoutState<AppShardVote> {
    let latest_qc = wire.latest_quorum_certificate.into_trait_object();
    let prior_tc = wire
        .prior_rank_timeout_certificate
        .map(|tc| tc.into_trait_object());
    let vote = crate::app_vote_aggregation::wire_vote_to_app_shard_vote(wire.vote, filter);
    TimeoutState {
        rank: vote.rank(),
        latest_quorum_certificate: latest_qc,
        prior_rank_timeout_certificate: prior_tc,
        vote,
        timeout_tick: wire.timeout_tick,
    }
}
