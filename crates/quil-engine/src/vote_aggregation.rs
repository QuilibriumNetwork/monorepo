//! Per-rank vote aggregation for global consensus.
//!
//! Inbound `ProposalVote` messages from peers need to be verified and
//! tallied until they reach a weighted quorum, at which point we can
//! finalize a `QuorumCertificate` and feed it back into the HotStuff
//! event loop. Mirror of Go's per-rank `VoteCollector` wiring at
//! `consensus/votecollector/statemachine.go` + the node-side
//! aggregator bootstrap in `global_consensus_engine.go`.
//!
//! The [`VoteAggregation`] type owns:
//!
//! - a map of live `VoteCollector<GlobalState, GlobalVote>` indexed by
//!   rank (lazily created on first touch),
//! - a factory that builds a `WeightedSignatureAggregator` scoped to a
//!   specific proposal,
//! - a QC-creation callback that forwards to `EventLoopHandle::submit_quorum_certificate`,
//! - a byzantine-vote notifier that logs double-voting / invalid-signer
//!   events at WARN.
//!
//! Collectors below the latest finalized rank are pruned so the map
//! doesn't grow unboundedly — the cutoff is driven from the QC the
//! consumer layer observes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

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

use crate::bls_signature_aggregator::BlsSignatureAggregator;
use crate::committee::ProverRegistryCommittee;
use crate::consensus_types::{GlobalState, GlobalVote};

/// Owns the per-rank vote-collector map and the glue that turns
/// sufficient weighted signatures into a `QuorumCertificate` that's
/// submitted to the HotStuff event loop.
pub struct VoteAggregation {
    committee: Arc<ProverRegistryCommittee>,
    voting_provider: Arc<dyn VotingProvider<GlobalState, GlobalVote>>,
    consensus_handle: Arc<OnceLock<EventLoopHandle<GlobalState, GlobalVote>>>,
    bls: Arc<dyn BlsConstructor>,
    vote_domain: Vec<u8>,
    collectors: Mutex<HashMap<u64, Arc<VoteCollector<GlobalState, GlobalVote>>>>,
    /// Highest rank we've seen finalized via a QC. Collectors below
    /// this are pruned.
    min_active_rank: AtomicU64,
}

impl VoteAggregation {
    pub fn new(
        committee: Arc<ProverRegistryCommittee>,
        voting_provider: Arc<dyn VotingProvider<GlobalState, GlobalVote>>,
        consensus_handle: Arc<OnceLock<EventLoopHandle<GlobalState, GlobalVote>>>,
        bls: Arc<dyn BlsConstructor>,
        vote_domain: Vec<u8>,
    ) -> Self {
        Self {
            committee,
            voting_provider,
            consensus_handle,
            bls,
            vote_domain,
            collectors: Mutex::new(HashMap::new()),
            min_active_rank: AtomicU64::new(0),
        }
    }

    /// Feed a decoded inbound `ProposalVote` (already converted to
    /// [`GlobalVote`]) to the collector for its rank.
    pub fn handle_vote(&self, vote: GlobalVote) {
        let rank = vote.rank();
        let voter_hex = hex::encode(<GlobalVote as quil_consensus::models::Unique>::identity(&vote));
        let min = self.min_active_rank.load(Ordering::Relaxed);
        if rank < min {
            tracing::info!(rank, voter = %voter_hex, min, "vote dropped: below finalized rank");
            return;
        }
        if rank > min.saturating_add(quil_consensus::vote_aggregator::MAX_RANK_LOOKAHEAD) {
            tracing::info!(rank, voter = %voter_hex, min, "vote dropped: far above finalized rank");
            return;
        }
        let collector = self.get_or_create(rank);
        match collector.add_vote(vote) {
            Ok(()) => tracing::info!(rank, voter = %voter_hex, "ingesting vote"),
            Err(e) => tracing::info!(rank, voter = %voter_hex, error = %e, "vote rejected by collector"),
        }
    }

    /// Feed a reconstructed `SignedProposal` to its rank's collector.
    /// Triggers the Caching → Verifying transition which spins up the
    /// underlying weighted aggregator on the first valid proposal.
    pub fn handle_proposal(&self, sp: &SignedProposal<GlobalState, GlobalVote>) {
        let rank = sp.proposal.state.rank;
        let min = self.min_active_rank.load(Ordering::Relaxed);
        if rank < min {
            debug!(rank, "dropping proposal below finalized rank");
            return;
        }
        if rank > min.saturating_add(quil_consensus::vote_aggregator::MAX_RANK_LOOKAHEAD) {
            debug!(rank, min, "dropping proposal far above finalized rank (lookahead exceeded)");
            return;
        }
        let collector = self.get_or_create(rank);
        if let Err(e) = collector.process_state(sp) {
            debug!(rank, error = %e, "vote collector rejected proposal");
        }
    }

    /// Raise the finalized-rank watermark and drop older collectors.
    /// Called whenever the consumer layer sees a new committed QC.
    pub fn advance_min_active_rank(&self, rank: u64) {
        let prev = self.min_active_rank.fetch_max(rank, Ordering::Relaxed);
        if rank <= prev {
            return;
        }
        let mut map = self.collectors.lock().unwrap();
        map.retain(|r, _| *r >= rank);
    }

    fn get_or_create(&self, rank: u64) -> Arc<VoteCollector<GlobalState, GlobalVote>> {
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

    fn make_consumer(&self) -> Arc<dyn VoteAggregationConsumer<GlobalVote>> {
        Arc::new(LoggingVoteConsumer)
    }

    fn make_on_qc_created(&self) -> OnQuorumCertificateCreated {
        let handle_cell = self.consensus_handle.clone();
        Arc::new(move |qc: Arc<dyn QuorumCertificate>| {
            if let Some(handle) = handle_cell.get() {
                tracing::info!(
                    rank = qc.rank(),
                    frame = qc.frame_number(),
                    "submitting locally-aggregated QC to event loop"
                );
                handle.submit_quorum_certificate(qc);
            } else {
                warn!(rank = qc.rank(), "QC formed but event loop handle not yet published");
            }
        })
    }

    fn make_processor_factory(&self) -> VoteProcessorFactory<GlobalState, GlobalVote> {
        let committee = self.committee.clone();
        let bls = self.bls.clone();
        let vote_domain = self.vote_domain.clone();
        Arc::new(move |sp: &SignedProposal<GlobalState, GlobalVote>| {
            let rank = sp.proposal.state.rank;
            let identity = &sp.proposal.state.identifier;

            // Message = MakeVoteMessage(filter=[], rank, identity). Matches Go's
            // voting provider for the global chain.
            let message = make_vote_message(&[], rank, identity);

            // Fresh snapshot of the committee at this rank.
            let ids = committee.identities_by_rank(rank)?;
            let pks: Vec<Vec<u8>> = ids.iter().map(|id| id.public_key().to_vec()).collect();

            let raw: Arc<dyn SignatureAggregator> = Arc::new(
                BlsSignatureAggregator::new(bls.clone()),
            );
            let agg = WeightedSignatureAggregatorImpl::new(
                ids,
                pks,
                message,
                vote_domain.clone(),
                raw,
            )?;
            let threshold = committee
                .quorum_threshold_for_rank(rank)
                .map_err(|e| QuilError::Consensus(format!("quorum threshold: {}", e)))?;
            Ok((
                Arc::new(agg) as Arc<dyn WeightedSignatureAggregator>,
                threshold,
            ))
        })
    }
}

struct LoggingVoteConsumer;

impl VoteAggregationConsumer<GlobalVote> for LoggingVoteConsumer {
    fn on_vote_processed(&self, vote: &GlobalVote) {
        debug!(
            rank = vote.rank(),
            source = %hex::encode(vote.source()),
            "vote processed by aggregator"
        );
    }

    fn on_invalid_vote_detected(&self, vote: &GlobalVote, reason: &str) {
        warn!(
            rank = vote.rank(),
            source = %hex::encode(vote.source()),
            reason,
            "invalid vote from peer"
        );
    }

    fn on_double_voting_detected(&self, first: &GlobalVote, conflicting: &GlobalVote) {
        warn!(
            rank = conflicting.rank(),
            source = %hex::encode(conflicting.source()),
            first_id = %hex::encode(first.identity()),
            conflicting_id = %hex::encode(conflicting.identity()),
            "double-voting detected"
        );
    }
}

/// Convert a wire `ProposalVote` into the typed `GlobalVote` the
/// aggregator accepts. The selector bytes (the proposal id this
/// vote points at) populate `GlobalVote::source`, and the voter's
/// raw 32-byte address populates `GlobalVote::identity` — matching
/// Go's `ProposalVote.Source()` / `Identity()` semantics. Signature
/// is the raw BLS bytes already unwrapped from
/// `BLS48581AddressedSignature`.
pub fn wire_vote_to_global_vote(
    wire: crate::consensus_wire::ProposalVote,
) -> GlobalVote {
    GlobalVote::new(
        wire.selector.clone(),
        wire.rank,
        wire.address.clone(),
        wire.timestamp,
        wire.signature,
        Vec::new(),
    )
}
