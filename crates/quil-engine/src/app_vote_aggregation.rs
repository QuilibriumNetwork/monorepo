//! Per-rank vote aggregation for app shard consensus, parameterised
//! by a 32-byte shard filter. The leader's self-vote and any peer
//! votes flow through this aggregator; once a rank's collector
//! reaches its weighted quorum the resulting `QuorumCertificate` is
//! fed into the shard's HotStuff event loop via
//! `submit_quorum_certificate`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use quil_consensus::committee::Replicas;
use quil_consensus::event_loop::EventLoopHandle;
use quil_consensus::models::{QuorumCertificate, SignedProposal, Unique};
use quil_consensus::signature_aggregator::{
    SignatureAggregator, WeightedSignatureAggregator, WeightedSignatureAggregatorImpl,
};
use quil_consensus::verification::make_vote_message;
use quil_consensus::vote_collector::{VoteAggregationConsumer, VoteCollector, VoteProcessorFactory};
use quil_consensus::voting_provider::{OnQuorumCertificateCreated, VotingProvider};
use quil_types::crypto::BlsConstructor;
use quil_types::error::QuilError;

use crate::app_glue::QcStore;
use crate::app_types::{AppShardState, AppShardVote};
use crate::bls_signature_aggregator::BlsSignatureAggregator;
use crate::committee::ProverRegistryCommittee;

/// Owns the per-rank vote-collector map for a single app shard plus
/// the glue that turns sufficient weighted signatures into a
/// `QuorumCertificate` submitted to the shard's HotStuff event loop.
pub struct AppVoteAggregation {
    filter: Vec<u8>,
    /// Wire FrameHeader.address; equal to `filter`. Used as the
    /// payload-address field in `make_vote_message`.
    app_address: Vec<u8>,
    committee: Arc<ProverRegistryCommittee>,
    voting_provider: Arc<dyn VotingProvider<AppShardState, AppShardVote>>,
    consensus_handle: Arc<OnceLock<EventLoopHandle<AppShardState, AppShardVote>>>,
    bls: Arc<dyn BlsConstructor>,
    vote_domain: Vec<u8>,
    collectors: Mutex<HashMap<u64, Arc<VoteCollector<AppShardState, AppShardVote>>>>,
    min_active_rank: AtomicU64,
    /// Floor on the wall-clock interval between observing a rank's
    /// proposal and submitting its QC — paces single-prover shards.
    proposal_duration: Duration,
    /// Rank → first-observed instant, consulted at QC formation to
    /// defer submission until `entry + proposal_duration`.
    rank_entry_times: Arc<Mutex<HashMap<u64, Instant>>>,
    /// QC cache shared with `AppFollower::on_finalized_state` for
    /// certifying-QC rehydration.
    qc_store: Arc<QcStore>,
}

impl AppVoteAggregation {
    pub fn new(
        filter: Vec<u8>,
        app_address: Vec<u8>,
        committee: Arc<ProverRegistryCommittee>,
        voting_provider: Arc<dyn VotingProvider<AppShardState, AppShardVote>>,
        consensus_handle: Arc<OnceLock<EventLoopHandle<AppShardState, AppShardVote>>>,
        bls: Arc<dyn BlsConstructor>,
        vote_domain: Vec<u8>,
        proposal_duration: Duration,
        qc_store: Arc<QcStore>,
    ) -> Self {
        Self {
            filter,
            app_address,
            committee,
            voting_provider,
            consensus_handle,
            bls,
            vote_domain,
            collectors: Mutex::new(HashMap::new()),
            min_active_rank: AtomicU64::new(0),
            proposal_duration,
            rank_entry_times: Arc::new(Mutex::new(HashMap::new())),
            qc_store,
        }
    }

    /// Feed a decoded inbound `ProposalVote` (already converted to
    /// [`AppShardVote`]) to the collector for its rank.
    pub fn handle_vote(&self, vote: AppShardVote) {
        let rank = vote.rank();
        if rank < self.min_active_rank.load(Ordering::Relaxed) {
            debug!(rank, "dropping shard vote below finalized rank");
            return;
        }
        let collector = self.get_or_create(rank);
        if let Err(e) = collector.add_vote(vote) {
            debug!(rank, error = %e, "shard vote collector rejected vote");
        }
    }

    /// Feed a reconstructed `SignedProposal` to its rank's collector.
    pub fn handle_proposal(&self, sp: &SignedProposal<AppShardState, AppShardVote>) {
        let rank = sp.proposal.state.rank;
        if rank < self.min_active_rank.load(Ordering::Relaxed) {
            debug!(rank, "dropping shard proposal below finalized rank");
            return;
        }
        // First-observed instant pegs the QC submission floor.
        self.rank_entry_times
            .lock()
            .unwrap()
            .entry(rank)
            .or_insert_with(Instant::now);
        // Cache the parent QC; the forest doesn't carry it through
        // to `on_finalized_state`.
        self.qc_store
            .insert(Arc::clone(&sp.proposal.parent_quorum_certificate));
        let collector = self.get_or_create(rank);
        if let Err(e) = collector.process_state(sp) {
            debug!(rank, error = %e, "shard vote collector rejected proposal");
        }
    }

    /// Raise the finalized-rank watermark and drop older collectors.
    pub fn advance_min_active_rank(&self, rank: u64) {
        let prev = self.min_active_rank.fetch_max(rank, Ordering::Relaxed);
        if rank <= prev {
            return;
        }
        let mut map = self.collectors.lock().unwrap();
        map.retain(|r, _| *r >= rank);
        let mut times = self.rank_entry_times.lock().unwrap();
        times.retain(|r, _| *r >= rank);
        self.qc_store.advance_min_active_rank(rank);
    }

    fn get_or_create(&self, rank: u64) -> Arc<VoteCollector<AppShardState, AppShardVote>> {
        let mut map = self.collectors.lock().unwrap();
        if let Some(c) = map.get(&rank) {
            return c.clone();
        }
        let collector = Arc::new(VoteCollector::new(
            rank,
            self.make_consumer(),
            self.voting_provider.clone(),
            self.make_on_qc_created(),
            self.make_processor_factory(),
        ));
        map.insert(rank, collector.clone());
        collector
    }

    fn make_consumer(&self) -> Arc<dyn VoteAggregationConsumer<AppShardVote>> {
        Arc::new(LoggingShardVoteConsumer)
    }

    fn make_on_qc_created(&self) -> OnQuorumCertificateCreated {
        let handle_cell = self.consensus_handle.clone();
        let filter_for_log = hex::encode(&self.filter);
        let app_address_for_log = hex::encode(
            &self.app_address[..self.app_address.len().min(8)],
        );
        let proposal_duration = self.proposal_duration;
        let rank_entry_times = Arc::clone(&self.rank_entry_times);
        let qc_store = Arc::clone(&self.qc_store);
        Arc::new(move |qc: Arc<dyn QuorumCertificate>| {
            qc_store.insert(Arc::clone(&qc));
            let rank = qc.rank();
            let agg = qc.aggregated_signature();
            tracing::debug!(
                filter = %filter_for_log,
                app_address = %app_address_for_log,
                rank,
                bitmask_hex = %hex::encode(agg.bitmask()),
                sig_len = agg.signature().len(),
                "shard QC formed"
            );
            let entry = rank_entry_times
                .lock()
                .unwrap()
                .get(&rank)
                .copied();
            let target = entry.map(|t| t + proposal_duration);
            let now = Instant::now();
            let delay = target
                .map(|t| t.saturating_duration_since(now))
                .unwrap_or(Duration::ZERO);

            let handle_cell = handle_cell.clone();
            let filter_for_log = filter_for_log.clone();
            let frame = qc.frame_number();
            if delay.is_zero() {
                if let Some(handle) = handle_cell.get() {
                    tracing::debug!(
                        filter = %filter_for_log,
                        rank,
                        frame,
                        "submitting locally-aggregated shard QC to event loop"
                    );
                    handle.submit_quorum_certificate(qc);
                } else {
                    warn!(rank, "shard QC formed but event loop handle not yet published");
                }
                return;
            }
            // Pace single-prover shards: defer QC submission until
            // `proposal_duration` after the rank was entered.
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if let Some(handle) = handle_cell.get() {
                    tracing::debug!(
                        filter = %filter_for_log,
                        rank,
                        frame,
                        delayed_ms = delay.as_millis() as u64,
                        "submitting locally-aggregated shard QC after proposal-duration delay"
                    );
                    handle.submit_quorum_certificate(qc);
                } else {
                    warn!(rank, "shard QC formed but event loop handle not yet published");
                }
            });
        })
    }

    fn make_processor_factory(&self) -> VoteProcessorFactory<AppShardState, AppShardVote> {
        let committee = self.committee.clone();
        let bls = self.bls.clone();
        let vote_domain = self.vote_domain.clone();
        let app_address = self.app_address.clone();
        Arc::new(move |sp: &SignedProposal<AppShardState, AppShardVote>| {
            let rank = sp.proposal.state.rank;
            let identity = &sp.proposal.state.identifier;

            let message = make_vote_message(&app_address, rank, identity);

            let ids = committee.identities_by_rank(rank)?;
            let pks: Vec<Vec<u8>> = ids.iter().map(|id| id.public_key().to_vec()).collect();

            let raw: Arc<dyn SignatureAggregator> =
                Arc::new(BlsSignatureAggregator::new(bls.clone()));
            let agg = WeightedSignatureAggregatorImpl::new(
                ids,
                pks,
                message,
                vote_domain.clone(),
                raw,
            )?;
            let threshold = committee
                .quorum_threshold_for_rank(rank)
                .map_err(|e| QuilError::Consensus(format!("shard quorum threshold: {}", e)))?;
            Ok((
                Arc::new(agg) as Arc<dyn WeightedSignatureAggregator>,
                threshold,
            ))
        })
    }
}

struct LoggingShardVoteConsumer;

impl VoteAggregationConsumer<AppShardVote> for LoggingShardVoteConsumer {
    fn on_vote_processed(&self, vote: &AppShardVote) {
        debug!(
            rank = vote.rank(),
            source = %hex::encode(vote.source()),
            "shard vote processed by aggregator"
        );
    }

    fn on_invalid_vote_detected(&self, vote: &AppShardVote, reason: &str) {
        warn!(
            rank = vote.rank(),
            source = %hex::encode(vote.source()),
            reason,
            "invalid shard vote from peer"
        );
    }

    fn on_double_voting_detected(&self, first: &AppShardVote, conflicting: &AppShardVote) {
        warn!(
            rank = conflicting.rank(),
            source = %hex::encode(conflicting.source()),
            first_id = %hex::encode(first.identity()),
            conflicting_id = %hex::encode(conflicting.identity()),
            "shard double-voting detected"
        );
    }
}

/// Convert a wire `ProposalVote` into the `AppShardVote` shape the
/// aggregator accepts. The shard filter is preserved on the vote so
/// the BLS verify path uses the shard's vote domain.
pub fn wire_vote_to_app_shard_vote(
    wire: crate::consensus_wire::ProposalVote,
    filter: Vec<u8>,
) -> AppShardVote {
    AppShardVote::new(
        wire.selector.clone(),
        wire.rank,
        wire.address.clone(),
        wire.timestamp,
        wire.signature,
        Vec::new(),
        filter,
    )
}
