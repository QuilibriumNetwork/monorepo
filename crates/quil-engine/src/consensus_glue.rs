//! Concrete implementations bridging quil-consensus generic traits to
//! Quilibrium's global chain. These are the "glue" types that the
//! bootstrap code needs to instantiate the HotStuff event loop.

use std::sync::Arc;
use std::time::Instant;

use quil_consensus::event_handler::Consumer;
use quil_consensus::forest::{Finalizer, FollowerConsumer};
use quil_consensus::models::{
    AggregatedSignature, CertifiedState, FinalityProof, Identity,
    QuorumCertificate, SignedProposal, State, TimeoutCertificate,
    TimeoutState, Unique,
};
use quil_consensus::pacemaker::ParticipantConsumer;
use quil_consensus::signature_aggregator::TimeoutSignerInfo;
use quil_types::error::{QuilError, Result};

use crate::consensus_types::{GlobalState, GlobalVote};
use crate::voting_provider::VotingProviderFactory;

// =====================================================================
// VotingProviderFactory — builds GlobalVote, QC, TC
// =====================================================================

/// Builds concrete `GlobalVote`/QC/TC instances from raw BLS signatures.
pub struct GlobalVotingProviderFactory;

impl VotingProviderFactory<GlobalState, GlobalVote> for GlobalVotingProviderFactory {
    fn make_vote(
        &self,
        state_rank: u64,
        state_id: &Identity,
        signature: Vec<u8>,
        voter_address: &[u8],
    ) -> Result<GlobalVote> {
        Ok(GlobalVote::new(
            state_id.clone(),
            state_rank,
            voter_address.to_vec(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            signature,
            Vec::new(),
        ))
    }

    fn make_timeout_vote(
        &self,
        rank: u64,
        newest_qc_rank: u64,
        signature: Vec<u8>,
        voter_address: &[u8],
    ) -> Result<GlobalVote> {
        Ok(GlobalVote::new(
            format!("timeout-{}-{}", rank, newest_qc_rank).into_bytes(),
            rank,
            voter_address.to_vec(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            signature,
            Vec::new(),
        ))
    }

    fn make_quorum_certificate(
        &self,
        state: &State<GlobalState>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn QuorumCertificate>> {
        Ok(Arc::new(GlobalQC {
            filter: Vec::new(),
            rank: state.rank,
            frame_number: state.state.frame_number,
            identity: state.identifier.clone(),
            timestamp: state.timestamp,
            agg_sig: aggregated_sig,
        }))
    }

    fn make_timeout_certificate(
        &self,
        rank: u64,
        newest_qc: Arc<dyn QuorumCertificate>,
        signers: Vec<TimeoutSignerInfo>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn TimeoutCertificate>> {
        let latest_ranks: Vec<u64> = signers.iter().map(|s| s.newest_qc_rank).collect();
        Ok(Arc::new(GlobalTC {
            filter: Vec::new(),
            rank,
            latest_ranks,
            latest_qc: newest_qc,
            agg_sig: aggregated_sig,
        }))
    }
}

// =====================================================================
// Concrete QC / TC types
// =====================================================================

#[derive(Debug)]
struct GlobalQC {
    filter: Vec<u8>,
    rank: u64,
    frame_number: u64,
    identity: Identity,
    timestamp: u64,
    agg_sig: Arc<dyn AggregatedSignature>,
}

impl QuorumCertificate for GlobalQC {
    fn filter(&self) -> &[u8] { &self.filter }
    fn rank(&self) -> u64 { self.rank }
    fn frame_number(&self) -> u64 { self.frame_number }
    fn identity(&self) -> &Identity { &self.identity }
    fn timestamp(&self) -> u64 { self.timestamp }
    fn aggregated_signature(&self) -> &dyn AggregatedSignature { self.agg_sig.as_ref() }
    fn equals(&self, other: &dyn QuorumCertificate) -> bool {
        self.rank == other.rank() && self.identity == *other.identity()
    }
}

#[derive(Debug)]
struct GlobalTC {
    filter: Vec<u8>,
    rank: u64,
    latest_ranks: Vec<u64>,
    latest_qc: Arc<dyn QuorumCertificate>,
    agg_sig: Arc<dyn AggregatedSignature>,
}

impl TimeoutCertificate for GlobalTC {
    fn filter(&self) -> &[u8] { &self.filter }
    fn rank(&self) -> u64 { self.rank }
    fn latest_ranks(&self) -> &[u64] { &self.latest_ranks }
    fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { self.latest_qc.as_ref() }
    fn aggregated_signature(&self) -> &dyn AggregatedSignature { self.agg_sig.as_ref() }
    fn equals(&self, other: &dyn TimeoutCertificate) -> bool {
        self.rank == other.rank()
    }
}

// =====================================================================
// Consumer — publishes events to BlossomSub
// =====================================================================

/// Consumer that handles consensus lifecycle events. In production
/// Handles committed consensus states — serializes proposals/votes/timeouts
/// and publishes them via BlossomSub bitmasks.
pub struct GlobalConsumer {
    /// Publisher for broadcasting consensus messages. If None, messages are
    /// logged but not sent (useful for testing).
    publisher: Option<std::sync::Arc<dyn ConsensusPublisher>>,
    /// Optional hook fired on every QC observation (received or
    /// locally-constructed). Used by `quil-node/src/main.rs` to
    /// persist QCs to the clock store so the leader's
    /// `prove_next_state` for rank+1 can resolve the correct prior
    /// frame. Mirrors Go's `OnQuorumCertificateTriggeredRankChange`
    /// at `consensus_protocol.go:622`.
    on_qc_observed: Option<QcObservedHook>,
}

/// Trait for publishing consensus messages to the network.
/// Implemented by the node binary to bridge to the P2P layer.
pub trait ConsensusPublisher: Send + Sync {
    /// Publish a frame proposal to GLOBAL_FRAME bitmask.
    fn publish_frame(&self, data: Vec<u8>);
    /// Publish a vote/timeout to GLOBAL_CONSENSUS bitmask.
    fn publish_consensus(&self, data: Vec<u8>);
    /// Publish a prover-admin message (e.g. ProverKick) to GLOBAL_PROVER
    /// bitmask. Default: no-op so existing test/stub publishers compile
    /// without changes; production publisher in `quil-node/src/main.rs`
    /// overrides to wrap the inner payload in a MessageBundle and send
    /// over BlossomSub + archive gRPC, matching Go's `publishProverMessage`.
    fn publish_prover_message(&self, _data: Vec<u8>) {}
}

impl GlobalConsumer {
    pub fn new() -> Self {
        Self {
            publisher: None,
            on_qc_observed: None,
        }
    }

    pub fn with_publisher(publisher: std::sync::Arc<dyn ConsensusPublisher>) -> Self {
        Self {
            publisher: Some(publisher),
            on_qc_observed: None,
        }
    }

    pub fn with_publisher_and_qc_hook(
        publisher: std::sync::Arc<dyn ConsensusPublisher>,
        on_qc_observed: QcObservedHook,
    ) -> Self {
        Self {
            publisher: Some(publisher),
            on_qc_observed: Some(on_qc_observed),
        }
    }
}

impl Consumer<GlobalState, GlobalVote> for GlobalConsumer {
    fn on_start(&self, current_rank: u64) {
        tracing::info!(rank = current_rank, "consensus started");
    }

    fn on_receive_proposal(&self, current_rank: u64, _proposal: &SignedProposal<GlobalState, GlobalVote>) {
        tracing::debug!(rank = current_rank, "received proposal");
    }

    fn on_receive_quorum_certificate(&self, current_rank: u64, qc: &dyn QuorumCertificate) {
        tracing::info!(rank = current_rank, qc_rank = qc.rank(), "received QC");
        if let Some(ref hook) = self.on_qc_observed {
            hook(qc);
        }
    }

    fn on_receive_timeout_certificate(&self, current_rank: u64, tc: &dyn TimeoutCertificate) {
        tracing::info!(rank = current_rank, tc_rank = tc.rank(), "received TC");
    }

    fn on_local_timeout(&self, current_rank: u64) {
        tracing::warn!(rank = current_rank, "local timeout");
    }

    fn on_own_vote(&self, vote: &GlobalVote, recipient_id: &Identity) {
        tracing::info!(rank = vote.rank(), recipient = %hex::encode(recipient_id), "produced vote");
        if let Some(ref pub_) = self.publisher {
            // Match Go's `ProposalVote` semantics:
            //   - `selector` = proposal id (i.e. what the vote points
            //     at), exposed by `Source()` on the typed vote.
            //   - `address`  = voter id, exposed by `Identity()`.
            let wire_vote = crate::consensus_wire::ProposalVote {
                filter: Vec::new(), // global chain has no filter
                rank: vote.rank(),
                frame_number: vote.rank(), // frame_number == rank for votes
                selector: vote.source().clone(),
                timestamp: vote.timestamp(),
                signature: vote.signature_bytes.clone(),
                address: vote.identity().clone(),
            };
            if let Ok(bytes) = wire_vote.to_canonical_bytes() {
                pub_.publish_consensus(bytes);
            }
        }
    }

    fn on_own_timeout(&self, timeout: &TimeoutState<GlobalVote>) {
        tracing::info!(
            rank = timeout.rank,
            tick = timeout.timeout_tick,
            qc_rank = timeout.latest_quorum_certificate.rank(),
            "produced timeout vote"
        );
        if let Some(ref pub_) = self.publisher {
            // Build wire-format TimeoutState mirroring Go's
            // `consensus_protocol.go:OnOwnTimeout` (`pbTimeout`):
            //   - LatestQuorumCertificate ← timeout.latest_quorum_certificate
            //   - PriorRankTimeoutCertificate ← timeout.prior_rank_timeout_certificate
            //   - Vote ← timeout.vote (an inner ProposalVote)
            //   - TimeoutTick ← timeout.timeout_tick (rebroadcast counter,
            //     bumped each call by SafetyRules::produce_timeout)
            //   - Timestamp ← time.Now().UnixMilli()
            let wire_qc = crate::consensus_wire::QuorumCertificate::from_trait_object(
                timeout.latest_quorum_certificate.as_ref(),
            );
            let wire_prior_tc = timeout
                .prior_rank_timeout_certificate
                .as_ref()
                .map(|tc| crate::consensus_wire::TimeoutCertificate::from_trait_object(tc.as_ref()));

            // The inner `vote` is a timeout-vote: it carries the BLS
            // signature over `MakeTimeoutMessage(filter, rank, newest_qc_rank)`
            // signed under the `timeout_domain`. The vote's `identity()` is
            // synthesized by `GlobalVoteFactory::make_timeout_vote` (empty
            // selector to match Go's wire shape — the timeout vote's
            // `selector` field on the wire is zero-valued because it is
            // tied to `(rank, newest_qc_rank)` rather than a specific
            // proposal identity).
            let now_millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            // Match Go's `ProposalVote` semantics: selector = proposal
            // id (Source()), address = voter id (Identity()). For a
            // timeout vote the proposal-id slot is conceptually nil
            // (Go writes an empty selector — see
            // `consensus_protocol.go:OnOwnTimeout`).
            let wire_vote = crate::consensus_wire::ProposalVote {
                filter: Vec::new(),
                rank: timeout.rank,
                // `frame_number` for a timeout vote is unused by the
                // aggregator; Go zeroes it on the inner ProposalVote of a
                // TimeoutState.
                frame_number: 0,
                selector: timeout.vote.source().clone(),
                timestamp: timeout.vote.timestamp(),
                signature: timeout.vote.signature_bytes.clone(),
                address: timeout.vote.identity().clone(),
            };
            let wire_ts = crate::consensus_wire::TimeoutState {
                latest_quorum_certificate: wire_qc,
                prior_rank_timeout_certificate: wire_prior_tc,
                vote: wire_vote,
                timeout_tick: timeout.timeout_tick,
                timestamp: now_millis,
            };
            match wire_ts.to_canonical_bytes() {
                Ok(bytes) => pub_.publish_consensus(bytes),
                Err(e) => {
                    tracing::error!(error = %e, "could not serialize TimeoutState");
                }
            }
        }
    }

    fn on_own_proposal(
        &self,
        proposal: &SignedProposal<GlobalState, GlobalVote>,
        target_publication_time: Instant,
    ) {
        tracing::info!(
            rank = proposal.proposal.state.rank,
            frame = proposal.proposal.state.state.frame_number,
            "produced proposal"
        );
        let Some(ref pub_) = self.publisher else { return; };

        // Build the wire `GlobalProposal` so receivers on the
        // GLOBAL_CONSENSUS bitmask see the same shape Go produces:
        // `GlobalProposal { state: <serialized GlobalFrame canonical bytes>,
        //   parent_qc, prior_tc, vote }`. The previous implementation
        // proto-encoded a bare `GlobalFrame` and published on
        // GLOBAL_FRAME — receivers' GLOBAL_CONSENSUS handler never saw
        // the proposal, so frame 1 was proved but never voted on.
        let state = &proposal.proposal.state.state;
        let header = quil_types::proto::global::GlobalFrameHeader {
            frame_number: state.frame_number,
            rank: state.rank,
            timestamp: state.timestamp,
            difficulty: state.difficulty,
            output: state.output.clone(),
            parent_selector: state.parent_selector.clone(),
            prover: state.prover.clone(),
            prover_tree_commitment: state.prover_tree_commitment.clone(),
            requests_root: state.requests_root.clone(),
            ..Default::default()
        };
        let header = if !state.signature.is_empty() {
            quil_types::proto::global::GlobalFrameHeader {
                public_key_signature_bls48581: Some(
                    quil_types::proto::keys::Bls48581AggregateSignature {
                        signature: state.signature.clone(),
                        ..Default::default()
                    },
                ),
                ..header
            }
        } else {
            header
        };
        // Attach `state.messages` to `frame.requests` so peers
        // see the same set of bundles the leader hashed into
        // `requests_root`. Without this the requests Vec ships empty
        // and every replica's materializer sees zero work on
        // finalization — ProverJoin/Confirm/Leave never enters the
        // registry, token/compute/hypergraph dispatches never apply.
        let frame = quil_types::proto::global::GlobalFrame {
            header: Some(header),
            requests: state.messages.clone(),
        };
        // Encode the frame as canonical bytes for embedding in the
        // wire proposal. Use the existing global-frame canonical
        // encoder rather than prost's protobuf encoder; receivers
        // decode via `decode_global_frame`.
        let frame_canonical = match crate::consensus_wire::encode_global_frame(&frame) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "could not canonical-encode proposal frame");
                return;
            }
        };

        // Convert parent QC + optional prior TC to wire form.
        let parent_qc_wire = crate::consensus_wire::QuorumCertificate::from_trait_object(
            proposal.proposal.parent_quorum_certificate.as_ref(),
        );
        let prior_tc_wire = proposal
            .proposal
            .previous_rank_timeout_certificate
            .as_ref()
            .map(|tc| crate::consensus_wire::TimeoutCertificate::from_trait_object(tc.as_ref()));

        // Build the proposer's own ProposalVote from the SignedProposal's
        // vote (the proposer always self-signs at proposal time).
        // GlobalVote's rank/timestamp are private — use the Unique
        // trait methods explicitly. The proposal's frame_number comes
        // from the state we just built.
        use quil_consensus::models::Unique;
        let v = &proposal.vote;
        // Match Go's `ProposalVote` semantics: selector = proposal id
        // (Source()), address = voter id (Identity()).
        let prop_vote = crate::consensus_wire::ProposalVote {
            filter: Vec::new(),
            rank: v.rank(),
            frame_number: state.frame_number,
            selector: v.source().clone(),
            timestamp: v.timestamp(),
            address: v.identity().clone(),
            signature: v.signature_bytes.clone(),
        };

        let global_proposal = crate::consensus_wire::GlobalProposal {
            state: frame_canonical,
            parent_quorum_certificate: parent_qc_wire,
            prior_rank_timeout_certificate: prior_tc_wire,
            vote: prop_vote,
        };
        match global_proposal.to_canonical_bytes() {
            Ok(bytes) => {
                // Defer the broadcast (and self-loopback) to the
                // pacemaker's `target_publication_time` so the chain
                // advances at the configured cadence (10s mainnet)
                // rather than VDF-as-fast. Mirror of Go's MessageHub
                // sleeping until `targetPublicationTime` before
                // calling `Publish`.
                //
                // Cap the wait at min_timeout-2s. If the pacemaker
                // hands us a target much further out (e.g. because
                // proposal_duration was misconfigured or the clock
                // drifted), we'd sleep past our own local timeout and
                // never publish — peers would then time out at this
                // rank, no TC would form (we never voted on our own
                // proposal because we never broadcast it), and the
                // chain stalls. Two seconds before the rank's local
                // timeout is the latest we can safely publish.
                let pub_clone: Arc<dyn ConsensusPublisher> = Arc::clone(pub_);
                let target = target_publication_time;
                tokio::spawn(async move {
                    let now = Instant::now();
                    let max_wait = std::time::Duration::from_secs(8);
                    let cap = now + max_wait;
                    let effective = std::cmp::min(target, cap);
                    if effective > now {
                        tokio::time::sleep_until(effective.into()).await;
                    }
                    pub_clone.publish_consensus(bytes);
                });
            }
            Err(e) => tracing::error!(error = %e, "could not serialize GlobalProposal"),
        }
    }

    fn on_event_processed(&self) {}

    fn on_current_rank_details(
        &self,
        current_rank: u64,
        finalized_rank: u64,
        leader: &Identity,
    ) {
        tracing::info!(
            rank = current_rank,
            finalized = finalized_rank,
            leader = %hex::encode(leader),
            "rank details"
        );
    }

    fn on_rank_change(&self, old_rank: u64, new_rank: u64) {
        tracing::info!(old = old_rank, new = new_rank, "rank change");
    }

    fn on_finalization(&self, proof: &FinalityProof<GlobalState>) {
        tracing::info!(
            frame = proof.state.state.frame_number,
            rank = proof.state.rank,
            "state finalized"
        );
    }

    fn on_qc_constructed(&self, qc: &dyn QuorumCertificate) {
        tracing::debug!(rank = qc.rank(), "QC constructed");
        if let Some(ref hook) = self.on_qc_observed {
            hook(qc);
        }
    }

    fn on_tc_constructed(&self, tc: &dyn TimeoutCertificate) {
        tracing::debug!(rank = tc.rank(), "TC constructed");
    }
}

// =====================================================================
// ParticipantConsumer — pacemaker callbacks
// =====================================================================

/// Handles pacemaker lifecycle events (rank changes, timeouts).
pub struct GlobalParticipantConsumer;

impl ParticipantConsumer<GlobalState, GlobalVote> for GlobalParticipantConsumer {
    fn on_quorum_certificate_triggered_rank_change(
        &self,
        old_rank: u64,
        new_rank: u64,
        _qc: &dyn QuorumCertificate,
    ) {
        tracing::debug!(old = old_rank, new = new_rank, "QC triggered rank change");
    }

    fn on_timeout_certificate_triggered_rank_change(
        &self,
        old_rank: u64,
        new_rank: u64,
        _tc: &dyn TimeoutCertificate,
    ) {
        tracing::debug!(old = old_rank, new = new_rank, "TC triggered rank change");
    }

    fn on_rank_change(&self, old_rank: u64, new_rank: u64) {
        tracing::debug!(old = old_rank, new = new_rank, "pacemaker rank change");
    }

    fn on_starting_timeout(&self, _start: Instant, _end: Instant) {
        tracing::debug!("pacemaker starting timeout");
    }
}

// =====================================================================
// Finalizer + FollowerConsumer — fork tree callbacks
// =====================================================================

/// Called when the fork tree needs to commit a finalized state.
pub struct GlobalFinalizer;

impl Finalizer for GlobalFinalizer {
    fn make_final(&self, state_id: &Identity) -> Result<()> {
        tracing::debug!(state = %hex::encode(state_id), "make_final");
        Ok(())
    }
}

/// Hook invoked whenever the forks tree finalizes a state. Used to
/// drive pruning of per-rank aggregators (vote / timeout) and any
/// other rank-indexed caches the caller owns.
pub type FinalizedStateHook = std::sync::Arc<dyn Fn(&State<GlobalState>) + Send + Sync>;

/// Hook invoked when a new state is added to the forks tree but not
/// yet finalized. Wired from the node bootstrap to write the
/// corresponding `GlobalFrame` to the clock store as a candidate so
/// that subsequent `prove_next_state` calls (the leader chaining a
/// rank+1 proposal on top of this state) can resolve the prior
/// frame from the store. Without this, the leader's event loop
/// crashes with "building on fork or needs sync" the moment its own
/// QC arrives, because `clock_store.get_global_clock_frame_candidate`
/// returns the genesis frame.
pub type IncorporatedStateHook =
    std::sync::Arc<dyn Fn(&State<GlobalState>) + Send + Sync>;

/// Hook fired whenever the consumer observes a fresh QC — either
/// constructed locally by the vote-aggregator or received over the
/// wire. Wired from the node bootstrap to persist the QC to the
/// clock store so the leader's `prove_next_state` for rank+1 finds
/// it via `get_latest_quorum_certificate`. Mirrors Go's
/// `OnQuorumCertificateTriggeredRankChange` at
/// `consensus_protocol.go:622`.
pub type QcObservedHook = std::sync::Arc<
    dyn Fn(&dyn QuorumCertificate) + Send + Sync,
>;

/// Called by the fork tree as it incorporates and finalizes states.
pub struct GlobalFollower {
    on_finalized: Option<FinalizedStateHook>,
    on_incorporated: Option<IncorporatedStateHook>,
    /// Publisher for broadcasting ProverKick messages on equivocation.
    /// When `None`, equivocation is logged only.
    publisher: Option<Arc<dyn ConsensusPublisher>>,
}

impl GlobalFollower {
    pub fn new() -> Self {
        Self {
            on_finalized: None,
            on_incorporated: None,
            publisher: None,
        }
    }

    pub fn with_on_finalized(on_finalized: FinalizedStateHook) -> Self {
        Self {
            on_finalized: Some(on_finalized),
            on_incorporated: None,
            publisher: None,
        }
    }

    /// Construct with both a finalization hook and a publisher.
    /// The publisher is used by `on_double_propose_detected` to broadcast
    /// a `ProverKick` message on the GLOBAL_PROVER bitmask. Mirrors
    /// Go's `event_distributor.go:114-208` handling of
    /// `ControlEventGlobalEquivocation`.
    pub fn with_on_finalized_and_publisher(
        on_finalized: Option<FinalizedStateHook>,
        publisher: Option<Arc<dyn ConsensusPublisher>>,
    ) -> Self {
        Self {
            on_finalized,
            on_incorporated: None,
            publisher,
        }
    }

    pub fn with_hooks(
        on_finalized: Option<FinalizedStateHook>,
        on_incorporated: Option<IncorporatedStateHook>,
        publisher: Option<Arc<dyn ConsensusPublisher>>,
    ) -> Self {
        Self {
            on_finalized,
            on_incorporated,
            publisher,
        }
    }
}

impl Default for GlobalFollower {
    fn default() -> Self {
        Self::new()
    }
}

impl FollowerConsumer<GlobalState> for GlobalFollower {
    fn on_state_incorporated(&self, state: &State<GlobalState>) {
        tracing::debug!(
            frame = state.state.frame_number,
            rank = state.rank,
            "state incorporated"
        );
        if let Some(ref hook) = self.on_incorporated {
            hook(state);
        }
    }

    fn on_finalized_state(&self, certified: &CertifiedState<GlobalState>) {
        let state = &certified.state;
        tracing::info!(
            frame = state.state.frame_number,
            rank = state.rank,
            "state finalized (follower)"
        );
        if let Some(ref hook) = self.on_finalized {
            hook(state);
        }
    }

    fn on_double_propose_detected(&self, first: &State<GlobalState>, second: &State<GlobalState>) {
        // Log full equivocation evidence and broadcast a ProverKick.
        // Mirrors Go's `event_distributor.go:114-208` handling of
        // `ControlEventGlobalEquivocation`: serialize both conflicting
        // headers as canonical bytes, build a `ProverKick` payload,
        // wrap in `MessageRequest` (envelope), and publish on the
        // GLOBAL_PROVER bitmask via `publishProverMessage`.
        //
        // Note: ProverKick has no outer BLS signature in Go — the
        // proof-of-equivocation lives in the two `conflicting_frame_*`
        // payloads (each carries the kicked prover's BLS aggregate
        // signature). Receivers verify both signatures match the same
        // public key and the frames have different outputs.
        tracing::warn!(
            first_frame = first.state.frame_number,
            first_rank = first.state.rank,
            first_identity = %hex::encode(&first.identifier),
            first_proposer = %hex::encode(&first.proposer_id),
            first_output_hex = hex::encode(&first.state.output[..std::cmp::min(first.state.output.len(), 32)]),
            second_frame = second.state.frame_number,
            second_rank = second.state.rank,
            second_identity = %hex::encode(&second.identifier),
            second_proposer = %hex::encode(&second.proposer_id),
            second_output_hex = hex::encode(&second.state.output[..std::cmp::min(second.state.output.len(), 32)]),
            "DOUBLE PROPOSE DETECTED — broadcasting ProverKick"
        );

        let kick_bytes = match build_prover_kick_bytes(first, second) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "failed to build prover kick payload");
                return;
            }
        };

        if let Some(ref publisher) = self.publisher {
            // Wrap the inner ProverKick canonical bytes in a
            // MessageRequest envelope. The production publisher in
            // `quil-node/src/main.rs` further wraps in MessageBundle
            // before sending.
            match crate::consensus_glue::wrap_message_request(&kick_bytes) {
                Ok(req_bytes) => publisher.publish_prover_message(req_bytes),
                Err(e) => tracing::error!(error = %e, "failed to wrap kick message request"),
            }
        } else {
            tracing::warn!("no publisher configured — kick not broadcast");
        }
    }
}

/// Build the canonical `ProverKick` payload for two conflicting global
/// frame headers. Mirrors Go's `NewProverKick` + the partial fields
/// populated by `event_distributor.go` before `Prove`.
///
/// The `commitment`, `proof`, and `traversal_proof` fields are left
/// empty here — those require hypergraph access for `ProverKick.Prove`.
/// Receivers fall back to the structural-equivocation check at
/// `global_intrinsic::intrinsic.rs:283-317` when the cryptographic
/// dependencies are absent on the receiver side; full verify (with
/// multiproof) runs when they are. This is the same staged-rollout
/// approach used elsewhere in the Rust port.
pub(crate) fn build_prover_kick_bytes(
    first: &State<GlobalState>,
    second: &State<GlobalState>,
) -> Result<Vec<u8>> {
    use quil_execution::global_intrinsic::frame_header::GlobalFrameHeader as CanonicalGlobalFrameHeader;
    use quil_execution::global_intrinsic::prover_ops::ProverKick as CanonicalProverKick;

    // Build canonical `GlobalFrameHeader` bytes from each State. The
    // `prover` field on State is the 32-byte prover address; the
    // `signature` field carries the BLS aggregate signature bytes.
    let to_canonical = |s: &State<GlobalState>| -> Result<Vec<u8>> {
        let h = CanonicalGlobalFrameHeader {
            frame_number: s.state.frame_number,
            rank: s.state.rank,
            timestamp: s.state.timestamp,
            difficulty: s.state.difficulty,
            output: s.state.output.clone(),
            parent_selector: s.state.parent_selector.clone(),
            global_commitments: Vec::new(),
            prover_tree_commitment: s.state.prover_tree_commitment.clone(),
            requests_root: s.state.requests_root.clone(),
            prover: s.state.prover.clone(),
            public_key_signature_bls48581: s.state.signature.clone(),
        };
        h.to_canonical_bytes()
    };

    let cf1 = to_canonical(first)?;
    let cf2 = to_canonical(second)?;

    // The kicked-prover key field. Go's event_distributor pulls this
    // from `Header.PublicKeySignatureBls48581.PublicKey.KeyValue` (the
    // raw BLS48-581 pubkey). State<GlobalState> carries the prover
    // address only, not the public key. Pass the address bytes here as
    // a placeholder — receivers re-derive the address by hashing the
    // pubkey embedded in `conflicting_frame_*`'s signature struct, so
    // structural verify still succeeds.
    let kicked_prover_public_key = first.state.prover.clone();

    let kick = CanonicalProverKick {
        frame_number: first.state.frame_number,
        kicked_prover_public_key,
        conflicting_frame_1: cf1,
        conflicting_frame_2: cf2,
        commitment: Vec::new(),
        proof: Vec::new(),
        traversal_proof: Vec::new(),
    };

    kick.to_canonical_bytes()
}

/// Wrap inner canonical bytes (e.g. a `ProverKick` payload) in a
/// `MessageRequest` envelope (type prefix `0x0311`).
pub(crate) fn wrap_message_request(inner: &[u8]) -> Result<Vec<u8>> {
    let req = quil_execution::message_envelope::CanonicalMessageRequest::wrap(inner.to_vec())?;
    req.to_canonical_bytes()
}

// =====================================================================
// ConsensusStateCodec — persistence codec
// =====================================================================

use crate::consensus_store::ConsensusStateCodec;
use quil_consensus::models::{ConsensusState, LivenessState};

/// Placeholder codec that serializes consensus/liveness state using
/// a simple binary encoding. A production codec would use protobuf
/// for Go wire compatibility.
pub struct GlobalConsensusCodec;

impl ConsensusStateCodec<GlobalVote> for GlobalConsensusCodec {
    fn encode_consensus_state(&self, state: &ConsensusState<GlobalVote>) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&(state.filter.len() as u32).to_be_bytes());
        out.extend_from_slice(&state.filter);
        out.extend_from_slice(&state.finalized_rank.to_be_bytes());
        out.extend_from_slice(&state.latest_acknowledged_rank.to_be_bytes());
        Ok(out)
    }

    fn decode_consensus_state(&self, bytes: &[u8]) -> Result<ConsensusState<GlobalVote>> {
        if bytes.len() < 4 {
            return Err(QuilError::InvalidArgument("consensus state too short".into()));
        }
        let filter_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + filter_len + 16 {
            return Err(QuilError::InvalidArgument("consensus state truncated".into()));
        }
        let filter = bytes[4..4 + filter_len].to_vec();
        let off = 4 + filter_len;
        let finalized_rank = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        let latest_rank = u64::from_be_bytes(bytes[off + 8..off + 16].try_into().unwrap());
        Ok(ConsensusState {
            filter,
            finalized_rank,
            latest_acknowledged_rank: latest_rank,
            latest_timeout: None,
        })
    }

    fn encode_liveness_state(&self, state: &LivenessState) -> Result<Vec<u8>> {
        // Layout: filter_len(u32) + filter + current_rank(u64) +
        // qc_bytes_len(u32) + qc_canonical_bytes +
        // tc_bytes_len(u32) + tc_canonical_bytes (0 if absent)
        let mut out = Vec::new();
        out.extend_from_slice(&(state.filter.len() as u32).to_be_bytes());
        out.extend_from_slice(&state.filter);
        out.extend_from_slice(&state.current_rank.to_be_bytes());

        let qc = crate::consensus_wire::QuorumCertificate::from_trait_object(
            state.latest_quorum_certificate.as_ref(),
        );
        let qc_bytes = qc.to_canonical_bytes()?;
        out.extend_from_slice(&(qc_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&qc_bytes);

        match state.prior_rank_timeout_certificate.as_ref() {
            Some(tc) => {
                let wire_tc = crate::consensus_wire::TimeoutCertificate::from_trait_object(tc.as_ref());
                let tc_bytes = wire_tc.to_canonical_bytes()?;
                out.extend_from_slice(&(tc_bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&tc_bytes);
            }
            None => {
                out.extend_from_slice(&0u32.to_be_bytes());
            }
        }
        Ok(out)
    }

    fn decode_liveness_state(&self, bytes: &[u8]) -> Result<LivenessState> {
        fn need(bytes: &[u8], off: usize, n: usize, what: &str) -> Result<()> {
            if off + n > bytes.len() {
                return Err(QuilError::InvalidArgument(format!(
                    "liveness decode: short read at {} (need {})", what, n
                )));
            }
            Ok(())
        }
        need(bytes, 0, 4, "filter_len")?;
        let filter_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let mut off = 4;
        need(bytes, off, filter_len, "filter")?;
        let filter = bytes[off..off + filter_len].to_vec();
        off += filter_len;
        need(bytes, off, 8, "current_rank")?;
        let current_rank = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        need(bytes, off, 4, "qc_len")?;
        let qc_len = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        need(bytes, off, qc_len, "qc_bytes")?;
        let qc_bytes = &bytes[off..off + qc_len];
        off += qc_len;
        let qc = crate::consensus_wire::QuorumCertificate::from_canonical_bytes(qc_bytes)?;
        need(bytes, off, 4, "tc_len")?;
        let tc_len = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let prior_tc = if tc_len == 0 {
            None
        } else {
            need(bytes, off, tc_len, "tc_bytes")?;
            let tc_bytes = &bytes[off..off + tc_len];
            let tc = crate::consensus_wire::TimeoutCertificate::from_canonical_bytes(tc_bytes)?;
            // Compat: an older binary persisted TCs without a populated
            // signer bitmask (the `BlsAggregatedSignature` wrapper used
            // to return `&[]`). Restoring such a TC into the pacemaker
            // would embed it as `prior_rank_TC` in our next outgoing
            // timeout, and peers running the bitmask-aware build would
            // reject it for "bitmask length 0 too short for committee
            // size N". Drop it on restore; local timeout aggregation
            // will re-form a valid TC once enough peer timeouts arrive
            // for the recovery rank.
            if tc.aggregate_signature.bitmask.is_empty() {
                tracing::warn!(
                    rank = tc.rank,
                    "dropping persisted prior_rank_TC with empty bitmask (old format)",
                );
                None
            } else {
                Some(tc.into_trait_object())
            }
        };
        Ok(LivenessState {
            filter,
            current_rank,
            latest_quorum_certificate: qc.into_trait_object(),
            prior_rank_timeout_certificate: prior_tc,
        })
    }
}

// =====================================================================
// Trusted root construction from synced frames
// =====================================================================

/// Build a `CertifiedState<GlobalState>` from a `GlobalFrame` proto.
/// Used as the trusted root for initializing the consensus event loop
/// after the node has synced its first frame from the network.
pub fn certified_state_from_frame(
    frame: &quil_types::proto::global::GlobalFrame,
) -> Option<CertifiedState<GlobalState>> {
    let header = frame.header.as_ref()?;
    let gs = GlobalState::from_header(header);
    let identity = gs.compute_identity();

    Some(CertifiedState {
        state: State {
            rank: header.rank,
            identifier: identity.clone(),
            proposer_id: header.prover.clone(),
            parent_qc_identity: header.parent_selector.clone(),
            parent_qc_rank: header.rank.saturating_sub(1),
            // Frame-only reconstruction — the parent QC trait object
            // isn't available without a clock-store lookup. Callers
            // that need the QC arc should reconstruct it via the
            // wire-decoded Proposal path instead.
            parent_quorum_certificate: None,
            timestamp: header.timestamp as u64,
            state: gs,
        },
        certifying_qc_identity: identity,
        certifying_qc_rank: header.rank,
        certifying_quorum_certificate: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voting_factory_make_vote() {
        let f = GlobalVotingProviderFactory;
        let vote = f.make_vote(5, &"state-5".into(), vec![0xAAu8; 74], &[0xBBu8; 32]).unwrap();
        assert_eq!(vote.rank(), 5);
        assert_eq!(vote.signature(), &[0xAAu8; 74][..]);
    }

    #[test]
    fn voting_factory_make_timeout_vote() {
        let f = GlobalVotingProviderFactory;
        let vote = f.make_timeout_vote(10, 8, vec![0xCCu8; 74], &[0xDDu8; 32]).unwrap();
        assert_eq!(vote.rank(), 10);
    }

    #[test]
    fn certified_state_from_frame_builds_root() {
        let frame = quil_types::proto::global::GlobalFrame {
            header: Some(quil_types::proto::global::GlobalFrameHeader {
                frame_number: 539000,
                rank: 0,
                timestamp: 1700000000,
                difficulty: 100000,
                output: vec![0xAAu8; 516],
                parent_selector: vec![0xBBu8; 32],
                prover: vec![0xCCu8; 32],
                ..Default::default()
            }),
            ..Default::default()
        };
        let cs = certified_state_from_frame(&frame).unwrap();
        assert_eq!(cs.state.state.frame_number, 539000);
        assert_eq!(cs.state.rank, 0);
        assert!(!cs.certifying_qc_identity.is_empty());
    }

    #[test]
    fn certified_state_from_empty_frame_returns_none() {
        let frame = quil_types::proto::global::GlobalFrame::default();
        assert!(certified_state_from_frame(&frame).is_none());
    }

    /// Test publisher that captures published messages for inspection.
    struct CapturePublisher {
        prover_msgs: std::sync::Mutex<Vec<Vec<u8>>>,
        consensus_msgs: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl CapturePublisher {
        fn new() -> Self {
            Self {
                prover_msgs: std::sync::Mutex::new(Vec::new()),
                consensus_msgs: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl ConsensusPublisher for CapturePublisher {
        fn publish_frame(&self, _data: Vec<u8>) {}
        fn publish_consensus(&self, data: Vec<u8>) {
            self.consensus_msgs.lock().unwrap().push(data);
        }
        fn publish_prover_message(&self, data: Vec<u8>) {
            self.prover_msgs.lock().unwrap().push(data);
        }
    }

    fn make_state(frame_number: u64, output: u8) -> State<GlobalState> {
        let inner = GlobalState::new(
            frame_number,
            0,
            1700000000,
            100000,
            vec![output; 516],
            vec![0xAAu8; 32],
            vec![0xCCu8; 32],
            vec![0xDDu8; 32],
            vec![0xEEu8; 32],
            vec![0x11u8; 74],
        );
        let identifier = inner.compute_identity();
        let proposer_id = inner.source().to_vec();
        State {
            rank: 0,
            identifier,
            proposer_id,
            parent_qc_identity: vec![0u8; 32],
            parent_qc_rank: 0,
            parent_quorum_certificate: None,
            timestamp: 1700000000,
            state: inner,
        }
    }

    #[test]
    fn build_prover_kick_bytes_has_correct_type_prefix() {
        // Two states with the same frame_number but different outputs —
        // the canonical equivocation pattern (a single proposer
        // produced two different headers at the same height).
        let s1 = make_state(100, 0xAA);
        let s2 = make_state(100, 0xBB);

        let bytes = build_prover_kick_bytes(&s1, &s2).expect("kick bytes");

        // Type prefix is the first 4 bytes (u32 BE) and must match
        // `TYPE_PROVER_KICK = 0x0307`.
        assert!(bytes.len() >= 4);
        let mut tp_buf = [0u8; 4];
        tp_buf.copy_from_slice(&bytes[..4]);
        let tp = u32::from_be_bytes(tp_buf);
        assert_eq!(
            tp,
            quil_execution::global_intrinsic::prover_ops::TYPE_PROVER_KICK,
            "kick payload must start with TYPE_PROVER_KICK type prefix"
        );

        // Round-trip decode and verify the conflicting frames decode
        // to GlobalFrameHeaders with different outputs (structural
        // equivocation evidence).
        let decoded = quil_execution::global_intrinsic::prover_ops::ProverKick::from_canonical_bytes(&bytes)
            .expect("decode kick");
        assert_eq!(decoded.frame_number, 100);
        assert!(!decoded.conflicting_frame_1.is_empty());
        assert!(!decoded.conflicting_frame_2.is_empty());

        let h1 = quil_execution::global_intrinsic::frame_header::GlobalFrameHeader::from_canonical_bytes(&decoded.conflicting_frame_1)
            .expect("decode cf1");
        let h2 = quil_execution::global_intrinsic::frame_header::GlobalFrameHeader::from_canonical_bytes(&decoded.conflicting_frame_2)
            .expect("decode cf2");
        assert_eq!(h1.frame_number, h2.frame_number);
        assert_ne!(h1.output, h2.output, "outputs must differ for equivocation");
    }

    #[test]
    fn on_double_propose_publishes_kick_message() {
        let publisher = Arc::new(CapturePublisher::new());
        let follower = GlobalFollower::with_on_finalized_and_publisher(
            None,
            Some(publisher.clone() as Arc<dyn ConsensusPublisher>),
        );

        let s1 = make_state(200, 0x11);
        let s2 = make_state(200, 0x22);
        follower.on_double_propose_detected(&s1, &s2);

        let captured = publisher.prover_msgs.lock().unwrap();
        assert_eq!(captured.len(), 1, "exactly one prover message published");

        // Captured payload is a MessageRequest envelope (0x0311) whose
        // inner payload is the ProverKick.
        let req = quil_execution::message_envelope::CanonicalMessageRequest::from_canonical_bytes(
            &captured[0],
        )
        .expect("decode MessageRequest");
        assert_eq!(
            req.inner_type_prefix,
            quil_execution::global_intrinsic::prover_ops::TYPE_PROVER_KICK,
            "inner type prefix must be TYPE_PROVER_KICK"
        );
    }

    // =====================================================================
    // on_own_timeout — pacemaker-fired timeout broadcast
    // =====================================================================

    /// Build a TimeoutState<GlobalVote> with a real BLS signature over
    /// `make_timeout_message(filter, rank, newest_qc_rank)` under the
    /// GLOBAL_CONSENSUS_TIMEOUT domain.
    fn build_signed_timeout(
        rank: u64,
        newest_qc_rank: u64,
        timeout_tick: u64,
    ) -> (
        quil_consensus::models::TimeoutState<GlobalVote>,
        Vec<u8>, // public key
    ) {
        use quil_crypto::Bls48581KeyConstructor;
        use quil_types::crypto::BlsConstructor;

        let bls = Bls48581KeyConstructor;
        let (signer, pubkey) = bls.new_key().expect("new bls key");

        let timeout_domain =
            quil_crypto::poseidon::hash_bytes_to_32(b"GLOBAL_CONSENSUS_TIMEOUT")
                .unwrap()
                .to_vec();
        let msg = quil_consensus::verification::make_timeout_message(&[], rank, newest_qc_rank);
        let sig = signer
            .sign_with_domain(&msg, &timeout_domain)
            .expect("sign");

        // Voter address = poseidon(pubkey)[..32]
        let voter_address =
            quil_crypto::poseidon::hash_bytes_to_32(&pubkey)
                .unwrap()
                .to_vec();

        let vote = GlobalVote::new(
            // empty selector — timeout votes have no proposal identity;
            // matches `BlsVotingProvider::sign_timeout_vote` + the
            // `GlobalVoteFactory::make_timeout_vote` shape.
            Vec::new(),
            rank,
            voter_address,
            1700000000_000,
            sig,
            Vec::new(),
        );

        // Use the wire genesis QC (with a non-empty 32-byte selector so
        // round-trip equality is meaningful) as `latest_quorum_certificate`.
        let wire_qc = crate::consensus_wire::QuorumCertificate::genesis(
            42,
            vec![0xABu8; 32],
        );
        let latest_qc: Arc<dyn quil_consensus::models::QuorumCertificate> =
            wire_qc.into_trait_object();

        let ts = quil_consensus::models::TimeoutState {
            rank,
            latest_quorum_certificate: latest_qc,
            prior_rank_timeout_certificate: None,
            vote,
            timeout_tick,
        };
        (ts, pubkey)
    }

    #[test]
    fn on_own_timeout_publishes_canonical_timeout_state() {
        let publisher = Arc::new(CapturePublisher::new());
        let consumer = GlobalConsumer::with_publisher(
            publisher.clone() as Arc<dyn ConsensusPublisher>,
        );

        let (timeout, _pubkey) = build_signed_timeout(7, 6, 0);
        // Simulate the pacemaker firing — produce_timeout in SafetyRules
        // calls `on_own_timeout` on the Consumer.
        consumer.on_own_timeout(&timeout);

        let captured = publisher.consensus_msgs.lock().unwrap();
        assert_eq!(captured.len(), 1, "exactly one consensus message published");

        // Type prefix must be TIMEOUT_STATE_TYPE (0x031C).
        let bytes = &captured[0];
        assert!(bytes.len() >= 4);
        let mut tp_buf = [0u8; 4];
        tp_buf.copy_from_slice(&bytes[..4]);
        let tp = u32::from_be_bytes(tp_buf);
        assert_eq!(
            tp,
            crate::consensus_wire::TIMEOUT_STATE_TYPE,
            "timeout payload must start with TIMEOUT_STATE_TYPE prefix"
        );

        // Round-trip decode and assert structural equality.
        let decoded = crate::consensus_wire::TimeoutState::from_canonical_bytes(bytes)
            .expect("decode TimeoutState");
        assert_eq!(decoded.timeout_tick, 0);
        assert_eq!(decoded.vote.rank, 7);
        assert_eq!(decoded.latest_quorum_certificate.rank, 0);
        assert_eq!(decoded.latest_quorum_certificate.frame_number, 42);
        assert_eq!(
            decoded.latest_quorum_certificate.selector,
            vec![0xABu8; 32],
            "embedded QC selector preserved through to_canonical_bytes"
        );
        assert!(decoded.prior_rank_timeout_certificate.is_none());
        assert!(!decoded.vote.signature.is_empty());
        assert_eq!(decoded.vote.address.len(), 32);
    }

    #[test]
    fn on_own_timeout_signature_verifies_under_local_pubkey() {
        use quil_crypto::Bls48581KeyConstructor;
        use quil_types::crypto::BlsConstructor;

        let publisher = Arc::new(CapturePublisher::new());
        let consumer = GlobalConsumer::with_publisher(
            publisher.clone() as Arc<dyn ConsensusPublisher>,
        );

        let (timeout, pubkey) = build_signed_timeout(11, 10, 3);
        consumer.on_own_timeout(&timeout);

        let captured = publisher.consensus_msgs.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let decoded =
            crate::consensus_wire::TimeoutState::from_canonical_bytes(&captured[0]).unwrap();

        // The inner ProposalVote signature must be a valid BLS sig over
        // `make_timeout_message(filter=[], rank=11, newest_qc_rank=10)`
        // under the GLOBAL_CONSENSUS_TIMEOUT domain.
        let timeout_domain =
            quil_crypto::poseidon::hash_bytes_to_32(b"GLOBAL_CONSENSUS_TIMEOUT")
                .unwrap()
                .to_vec();
        let msg = quil_consensus::verification::make_timeout_message(&[], 11, 10);
        let bls = Bls48581KeyConstructor;
        assert!(
            bls.verify_signature_raw(
                &pubkey,
                &decoded.vote.signature,
                &msg,
                &timeout_domain,
            ),
            "timeout signature must verify under local pubkey + timeout domain"
        );
        // Tick is the rebroadcast counter — must propagate from
        // SafetyRules::produce_timeout's tick-bump path.
        assert_eq!(decoded.timeout_tick, 3);
    }

    #[test]
    fn on_own_timeout_without_publisher_is_noop() {
        // Sanity: with no publisher attached, on_own_timeout should not
        // panic and should not crash even though we built a real timeout.
        let consumer = GlobalConsumer::new();
        let (timeout, _pk) = build_signed_timeout(2, 1, 0);
        consumer.on_own_timeout(&timeout);
    }

    #[test]
    fn consensus_codec_roundtrip() {
        let codec = GlobalConsensusCodec;
        let state = ConsensusState {
            filter: vec![0x00],
            finalized_rank: 42,
            latest_acknowledged_rank: 50,
            latest_timeout: None,
        };
        let bytes = codec.encode_consensus_state(&state).unwrap();
        let decoded = codec.decode_consensus_state(&bytes).unwrap();
        assert_eq!(decoded.filter, vec![0x00]);
        assert_eq!(decoded.finalized_rank, 42);
        assert_eq!(decoded.latest_acknowledged_rank, 50);
    }
}
