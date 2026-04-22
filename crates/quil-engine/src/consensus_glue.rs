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
            hex::encode(voter_address),
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
            format!("timeout-{}-{}", rank, newest_qc_rank),
            rank,
            hex::encode(voter_address),
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
}

/// Trait for publishing consensus messages to the network.
/// Implemented by the node binary to bridge to the P2P layer.
pub trait ConsensusPublisher: Send + Sync {
    /// Publish a frame proposal to GLOBAL_FRAME bitmask.
    fn publish_frame(&self, data: Vec<u8>);
    /// Publish a vote/timeout to GLOBAL_CONSENSUS bitmask.
    fn publish_consensus(&self, data: Vec<u8>);
}

impl GlobalConsumer {
    pub fn new() -> Self {
        Self { publisher: None }
    }

    pub fn with_publisher(publisher: std::sync::Arc<dyn ConsensusPublisher>) -> Self {
        Self { publisher: Some(publisher) }
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
    }

    fn on_receive_timeout_certificate(&self, current_rank: u64, tc: &dyn TimeoutCertificate) {
        tracing::info!(rank = current_rank, tc_rank = tc.rank(), "received TC");
    }

    fn on_local_timeout(&self, current_rank: u64) {
        tracing::warn!(rank = current_rank, "local timeout");
    }

    fn on_own_vote(&self, vote: &GlobalVote, recipient_id: &Identity) {
        tracing::info!(rank = vote.rank(), recipient = %recipient_id, "produced vote");
        if let Some(ref pub_) = self.publisher {
            let wire_vote = crate::consensus_wire::ProposalVote {
                filter: Vec::new(), // global chain has no filter
                rank: vote.rank(),
                frame_number: vote.rank(), // frame_number == rank for votes
                selector: hex::decode(vote.identity()).unwrap_or_default(),
                timestamp: vote.timestamp(),
                signature: vote.signature_bytes.clone(),
                address: hex::decode(vote.source()).unwrap_or_default(),
            };
            if let Ok(bytes) = wire_vote.to_canonical_bytes() {
                pub_.publish_consensus(bytes);
            }
        }
    }

    fn on_own_timeout(&self, timeout: &TimeoutState<GlobalVote>) {
        tracing::info!(rank = timeout.rank, "produced timeout vote");
        if let Some(ref pub_) = self.publisher {
            // Build wire-format TimeoutState from the generic timeout
            let wire_qc = crate::consensus_wire::QuorumCertificate::genesis(0, Vec::new());
            let wire_vote = crate::consensus_wire::ProposalVote {
                filter: Vec::new(),
                rank: timeout.rank,
                frame_number: timeout.rank,
                selector: Vec::new(),
                timestamp: 0,
                signature: timeout.vote.signature_bytes.clone(),
                address: hex::decode(timeout.vote.source()).unwrap_or_default(),
            };
            let wire_ts = crate::consensus_wire::TimeoutState {
                latest_quorum_certificate: wire_qc,
                prior_rank_timeout_certificate: None,
                vote: wire_vote,
                timeout_tick: timeout.rank,
                timestamp: timeout.vote.timestamp(),
            };
            if let Ok(bytes) = wire_ts.to_canonical_bytes() {
                pub_.publish_consensus(bytes);
            }
        }
    }

    fn on_own_proposal(
        &self,
        proposal: &SignedProposal<GlobalState, GlobalVote>,
        _target_publication_time: Instant,
    ) {
        tracing::info!(
            rank = proposal.proposal.state.rank,
            frame = proposal.proposal.state.state.frame_number,
            "produced proposal"
        );
        if let Some(ref pub_) = self.publisher {
            // Build a GlobalFrame proto from the proposal state and publish
            // its proto-encoded bytes on the GLOBAL_FRAME bitmask.
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
            // Attach the BLS signature if present
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
            let frame = quil_types::proto::global::GlobalFrame {
                header: Some(header),
                requests: Vec::new(),
            };
            let bytes = prost::Message::encode_to_vec(&frame);
            pub_.publish_frame(bytes);
        }
    }

    fn on_event_processed(&self) {}

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
        tracing::info!(state = %state_id, "make_final");
        Ok(())
    }
}

/// Hook invoked whenever the forks tree finalizes a state. Used to
/// drive pruning of per-rank aggregators (vote / timeout) and any
/// other rank-indexed caches the caller owns.
pub type FinalizedStateHook = std::sync::Arc<dyn Fn(&State<GlobalState>) + Send + Sync>;

/// Called by the fork tree as it incorporates and finalizes states.
pub struct GlobalFollower {
    on_finalized: Option<FinalizedStateHook>,
}

impl GlobalFollower {
    pub fn new() -> Self {
        Self { on_finalized: None }
    }

    pub fn with_on_finalized(on_finalized: FinalizedStateHook) -> Self {
        Self {
            on_finalized: Some(on_finalized),
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
    }

    fn on_finalized_state(&self, state: &State<GlobalState>) {
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
        // Log full equivocation evidence so operators can verify the double-propose.
        // Publishing a ProverKick over the network requires the full P2P broadcast
        // pipeline (bitmask routing, signed kick message). For now, log the evidence
        // at warn level; the network-level kick will be wired when the P2P layer
        // integration is complete.
        tracing::warn!(
            first_frame = first.state.frame_number,
            first_rank = first.state.rank,
            first_identity = %first.identifier,
            first_proposer = %first.proposer_id,
            first_output_hex = hex::encode(&first.state.output[..std::cmp::min(first.state.output.len(), 32)]),
            second_frame = second.state.frame_number,
            second_rank = second.state.rank,
            second_identity = %second.identifier,
            second_proposer = %second.proposer_id,
            second_output_hex = hex::encode(&second.state.output[..std::cmp::min(second.state.output.len(), 32)]),
            "DOUBLE PROPOSE DETECTED — equivocation evidence logged, ProverKick pending P2P integration"
        );
    }
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
        let mut out = Vec::new();
        out.extend_from_slice(&(state.filter.len() as u32).to_be_bytes());
        out.extend_from_slice(&state.filter);
        out.extend_from_slice(&state.current_rank.to_be_bytes());
        Ok(out)
    }

    fn decode_liveness_state(&self, _bytes: &[u8]) -> Result<LivenessState> {
        // LivenessState requires a non-optional Arc<dyn QuorumCertificate>.
        // For bootstrap/cold-start, we'd need a genesis QC. For now,
        // return an error — the store falls back to the bootstrap closure.
        Err(QuilError::InvalidArgument(
            "liveness decode: use bootstrap closure for cold start".into(),
        ))
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
            proposer_id: hex::encode(&header.prover),
            parent_qc_identity: hex::encode(&header.parent_selector),
            parent_qc_rank: header.rank.saturating_sub(1),
            timestamp: header.timestamp as u64,
            state: gs,
        },
        certifying_qc_identity: identity,
        certifying_qc_rank: header.rank,
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
                prover: vec![0xCCu8; 585],
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
