//! App shard consensus glue: concrete implementations of the
//! quil-consensus trait callbacks for per-shard HotStuff.
//!
//! Mirrors `consensus_glue.rs` (GlobalConsumer etc.) but for app shards.
//! Each shard engine gets its own set of these callbacks.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use quil_consensus::event_handler::Consumer;
use quil_consensus::forest::{Finalizer, FollowerConsumer};
use quil_consensus::models::{
    FinalityProof, Identity, QuorumCertificate, SignedProposal,
    State, TimeoutCertificate, TimeoutState, Unique,
};
use quil_consensus::pacemaker::ParticipantConsumer;
use quil_types::error::Result;

use crate::app_types::{AppShardState, AppShardVote};

// =====================================================================
// Events emitted by the consensus layer to the app engine
// =====================================================================

/// Events from the HotStuff consensus layer to the app engine's
/// main loop. These drive frame finalization, equivocation detection,
/// and rank tracking.
#[derive(Debug)]
pub enum AppConsensusEvent {
    /// A new state was finalized (2-chain rule satisfied).
    Finalized {
        frame_number: u64,
        rank: u64,
        state_id: Identity,
    },
    /// A double-propose was detected — equivocation evidence.
    DoublePropose {
        first_frame: u64,
        second_frame: u64,
    },
    /// Rank changed (QC or TC triggered advance).
    RankChange {
        old_rank: u64,
        new_rank: u64,
    },
    /// Own vote was produced and needs publishing.
    OwnVote {
        data: Vec<u8>,
        recipient: Identity,
    },
    /// Own timeout was produced and needs publishing.
    OwnTimeout {
        data: Vec<u8>,
    },
    /// Own proposal was produced and needs publishing.
    OwnProposal {
        data: Vec<u8>,
        frame_number: u64,
        rank: u64,
    },
}

// =====================================================================
// AppConsumer — handles HotStuff lifecycle events
// =====================================================================

/// Consumer for app shard consensus events. Serializes votes,
/// timeouts, and proposals for network publication and emits events
/// to the engine's main loop. The aggregator is held in a `OnceLock`
/// because it depends on the event-loop handle, which itself is only
/// available after the consumer has been constructed.
pub struct AppConsumer {
    filter: Vec<u8>,
    event_tx: mpsc::UnboundedSender<AppConsensusEvent>,
    aggregator: std::sync::OnceLock<std::sync::Arc<crate::app_vote_aggregation::AppVoteAggregation>>,
}

impl AppConsumer {
    pub fn new(filter: Vec<u8>, event_tx: mpsc::UnboundedSender<AppConsensusEvent>) -> Self {
        Self {
            filter,
            event_tx,
            aggregator: std::sync::OnceLock::new(),
        }
    }

    /// Install the per-shard vote aggregator. Idempotent — only the
    /// first set takes effect.
    pub fn set_aggregator(
        &self,
        agg: std::sync::Arc<crate::app_vote_aggregation::AppVoteAggregation>,
    ) {
        let _ = self.aggregator.set(agg);
    }
}

impl Consumer<AppShardState, AppShardVote> for AppConsumer {
    fn on_start(&self, current_rank: u64) {
        info!(
            filter = hex::encode(&self.filter),
            rank = current_rank,
            "app shard consensus started"
        );
    }

    fn on_receive_proposal(
        &self,
        current_rank: u64,
        _proposal: &SignedProposal<AppShardState, AppShardVote>,
    ) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = current_rank,
            "received shard proposal"
        );
    }

    fn on_receive_quorum_certificate(
        &self,
        current_rank: u64,
        qc: &dyn QuorumCertificate,
    ) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = current_rank,
            qc_rank = qc.rank(),
            "received shard QC"
        );
    }

    fn on_receive_timeout_certificate(
        &self,
        current_rank: u64,
        tc: &dyn TimeoutCertificate,
    ) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = current_rank,
            tc_rank = tc.rank(),
            "received shard TC"
        );
    }

    fn on_local_timeout(&self, current_rank: u64) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = current_rank,
            "shard local timeout"
        );
    }

    fn on_own_vote(&self, vote: &AppShardVote, recipient_id: &Identity) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = vote.rank(),
            recipient = %hex::encode(recipient_id),
            "produced shard vote"
        );

        // Tally the local vote so a small or single-member committee
        // can form a QC without a network round-trip.
        if let Some(agg) = self.aggregator.get() {
            agg.handle_vote(vote.clone());
        }

        // Wire encoding: selector = proposal id (Source()), address =
        // voter id (Identity()).
        let wire_vote = crate::consensus_wire::ProposalVote {
            filter: self.filter.clone(),
            rank: vote.rank(),
            frame_number: vote.rank(),
            selector: vote.source().clone(),
            timestamp: vote.timestamp(),
            signature: vote.signature_bytes.clone(),
            address: vote.identity().clone(),
        };
        if let Ok(bytes) = wire_vote.to_canonical_bytes() {
            let _ = self.event_tx.send(AppConsensusEvent::OwnVote {
                data: bytes,
                recipient: recipient_id.clone(),
            });
        }
    }

    fn on_own_timeout(&self, timeout: &TimeoutState<AppShardVote>) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = timeout.rank,
            "produced shard timeout"
        );
        let wire_qc = crate::consensus_wire::QuorumCertificate::genesis(0, self.filter.clone());
        // Timeout vote: selector is empty (the timeout binds to
        // (rank, newest_qc_rank), not a specific proposal); address
        // is the voter's identity.
        let wire_vote = crate::consensus_wire::ProposalVote {
            filter: self.filter.clone(),
            rank: timeout.rank,
            frame_number: timeout.rank,
            selector: Vec::new(),
            timestamp: 0,
            signature: timeout.vote.signature_bytes.clone(),
            address: timeout.vote.identity().clone(),
        };
        let wire_ts = crate::consensus_wire::TimeoutState {
            latest_quorum_certificate: wire_qc,
            prior_rank_timeout_certificate: None,
            vote: wire_vote,
            timeout_tick: timeout.rank,
            timestamp: timeout.vote.timestamp(),
        };
        if let Ok(bytes) = wire_ts.to_canonical_bytes() {
            let _ = self.event_tx.send(AppConsensusEvent::OwnTimeout {
                data: bytes,
            });
        }
    }

    fn on_own_proposal(
        &self,
        proposal: &SignedProposal<AppShardState, AppShardVote>,
        _target_publication_time: Instant,
    ) {
        let frame = proposal.proposal.state.state.frame_number;
        let rank = proposal.proposal.state.rank;
        debug!(
            filter = hex::encode(&self.filter),
            frame,
            rank,
            "produced shard proposal"
        );

        // Hand the proposal to the rank's vote collector so it can
        // transition to the verifying state and tally subsequent
        // votes against this proposal's identifier.
        if let Some(agg) = self.aggregator.get() {
            agg.handle_proposal(proposal);
        }

        // The frame data is the VDF output, published on the shard's
        // frame bitmask. The full AppShardFrame (header + requests)
        // is assembled and serialized by the leader provider.
        let frame_data = proposal.proposal.state.state.output.clone();
        let _ = self.event_tx.send(AppConsensusEvent::OwnProposal {
            data: frame_data,
            frame_number: frame,
            rank,
        });
    }

    fn on_event_processed(&self) {}

    fn on_rank_change(&self, old_rank: u64, new_rank: u64) {
        debug!(
            filter = hex::encode(&self.filter),
            old = old_rank,
            new = new_rank,
            "shard rank change"
        );
        let _ = self.event_tx.send(AppConsensusEvent::RankChange {
            old_rank,
            new_rank,
        });
    }

    fn on_finalization(&self, proof: &FinalityProof<AppShardState>) {
        info!(
            filter = hex::encode(&self.filter),
            frame = proof.state.state.frame_number,
            rank = proof.state.rank,
            "shard state finalized"
        );
        let _ = self.event_tx.send(AppConsensusEvent::Finalized {
            frame_number: proof.state.state.frame_number,
            rank: proof.state.rank,
            state_id: proof.state.identifier.clone(),
        });
    }

    fn on_qc_constructed(&self, qc: &dyn QuorumCertificate) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = qc.rank(),
            "shard QC constructed"
        );
    }

    fn on_tc_constructed(&self, tc: &dyn TimeoutCertificate) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = tc.rank(),
            "shard TC constructed"
        );
    }
}

// =====================================================================
// AppParticipantConsumer — pacemaker callbacks
// =====================================================================

pub struct AppParticipantConsumer {
    filter: Vec<u8>,
}

impl AppParticipantConsumer {
    pub fn new(filter: Vec<u8>) -> Self {
        Self { filter }
    }
}

impl ParticipantConsumer<AppShardState, AppShardVote> for AppParticipantConsumer {
    fn on_quorum_certificate_triggered_rank_change(
        &self,
        old_rank: u64,
        new_rank: u64,
        _qc: &dyn QuorumCertificate,
    ) {
        debug!(
            filter = hex::encode(&self.filter),
            old = old_rank,
            new = new_rank,
            "shard QC triggered rank change"
        );
    }

    fn on_timeout_certificate_triggered_rank_change(
        &self,
        old_rank: u64,
        new_rank: u64,
        _tc: &dyn TimeoutCertificate,
    ) {
        debug!(
            filter = hex::encode(&self.filter),
            old = old_rank,
            new = new_rank,
            "shard TC triggered rank change"
        );
    }

    fn on_rank_change(&self, old_rank: u64, new_rank: u64) {
        debug!(
            filter = hex::encode(&self.filter),
            old = old_rank,
            new = new_rank,
            "shard pacemaker rank change"
        );
    }

    fn on_starting_timeout(&self, _start: Instant, _end: Instant) {
        debug!(filter = hex::encode(&self.filter), "shard pacemaker starting timeout");
    }
}

// =====================================================================
// AppFinalizer — called when fork tree commits a finalized state
// =====================================================================

pub struct AppFinalizer {
    filter: Vec<u8>,
}

impl AppFinalizer {
    pub fn new(filter: Vec<u8>) -> Self {
        Self { filter }
    }
}

impl Finalizer for AppFinalizer {
    fn make_final(&self, state_id: &Identity) -> Result<()> {
        info!(
            filter = hex::encode(&self.filter),
            state = %hex::encode(state_id),
            "shard make_final"
        );
        Ok(())
    }
}

// =====================================================================
// AppFollower — fork tree incorporation/finalization notifications
// =====================================================================

pub struct AppFollower {
    filter: Vec<u8>,
    /// Internal consensus events (proposal/vote/timeout/etc).
    consensus_event_tx: mpsc::UnboundedSender<AppConsensusEvent>,
    /// Direct publisher for finalized-frame canonical bytes. Invoked
    /// synchronously from `on_finalized_state` so the rewards path
    /// doesn't depend on internal channel scheduling.
    coverage_publish: Option<std::sync::Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
}

impl AppFollower {
    pub fn new(
        filter: Vec<u8>,
        consensus_event_tx: mpsc::UnboundedSender<AppConsensusEvent>,
        coverage_publish: Option<std::sync::Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    ) -> Self {
        Self {
            filter,
            consensus_event_tx,
            coverage_publish,
        }
    }
}

impl FollowerConsumer<AppShardState> for AppFollower {
    fn on_state_incorporated(&self, state: &State<AppShardState>) {
        debug!(
            filter = hex::encode(&self.filter),
            frame = state.state.frame_number,
            rank = state.rank,
            "shard state incorporated"
        );
    }

    fn on_finalized_state(&self, state: &State<AppShardState>) {
        info!(
            filter = hex::encode(&self.filter),
            frame = state.state.frame_number,
            rank = state.rank,
            "shard state finalized"
        );

        // Build the canonical FrameHeader directly from the finalized
        // state's fields and emit `ShardFrameFinalized` to the master.
        // Avoids hopping through the consensus event loop, which keeps
        // coverage publication unblocked during peak load.
        let canonical_header = quil_execution::global_intrinsic::frame_header::FrameHeader {
            address: state.state.filter.clone(),
            frame_number: state.state.frame_number,
            rank: state.rank,
            timestamp: state.state.timestamp,
            difficulty: state.state.difficulty,
            output: state.state.output.clone(),
            parent_selector: state.state.parent_selector.clone(),
            requests_root: state.state.requests_root.clone(),
            state_roots: state.state.state_roots.clone(),
            prover: state.state.prover.clone(),
            fee_multiplier_vote: state.state.fee_multiplier as i64,
            public_key_signature_bls48581: state.state.signature.clone(),
        };
        match canonical_header.to_canonical_bytes() {
            Ok(bytes) => {
                if let Some(publisher) = self.coverage_publish.as_ref() {
                    publisher(bytes);
                }
            }
            Err(e) => warn!(
                filter = hex::encode(&self.filter),
                error = %e,
                "failed to encode finalized FrameHeader for coverage publish"
            ),
        }

        // Also feed the bookkeeping event into the consensus loop —
        // a future caller might depend on the `Finalized` arm in
        // `handle_consensus_event` (currently a no-op for publish).
        let _ = self.consensus_event_tx.send(AppConsensusEvent::Finalized {
            frame_number: state.state.frame_number,
            rank: state.rank,
            state_id: state.identifier.clone(),
        });
    }

    fn on_double_propose_detected(
        &self,
        first: &State<AppShardState>,
        second: &State<AppShardState>,
    ) {
        warn!(
            filter = hex::encode(&self.filter),
            first_frame = first.state.frame_number,
            second_frame = second.state.frame_number,
            "SHARD DOUBLE PROPOSE DETECTED — equivocation"
        );
        let _ = self.consensus_event_tx.send(AppConsensusEvent::DoublePropose {
            first_frame: first.state.frame_number,
            second_frame: second.state.frame_number,
        });
    }
}

// =====================================================================
// AppConsensusCodec — persistence codec for app shard consensus state
// =====================================================================

use crate::app_types::AppGenesisQC;
use crate::consensus_store::ConsensusStateCodec;
use quil_consensus::models::{ConsensusState, LivenessState};

pub struct AppConsensusCodec {
    pub filter: Vec<u8>,
}

impl ConsensusStateCodec<AppShardVote> for AppConsensusCodec {
    fn encode_consensus_state(&self, state: &ConsensusState<AppShardVote>) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&(state.filter.len() as u32).to_be_bytes());
        out.extend_from_slice(&state.filter);
        out.extend_from_slice(&state.finalized_rank.to_be_bytes());
        out.extend_from_slice(&state.latest_acknowledged_rank.to_be_bytes());
        Ok(out)
    }

    fn decode_consensus_state(&self, bytes: &[u8]) -> Result<ConsensusState<AppShardVote>> {
        use quil_types::error::QuilError;
        if bytes.len() < 4 {
            return Err(QuilError::InvalidArgument("app consensus state too short".into()));
        }
        let filter_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + filter_len + 16 {
            return Err(QuilError::InvalidArgument("app consensus state truncated".into()));
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

    fn decode_liveness_state(&self, bytes: &[u8]) -> Result<LivenessState> {
        use quil_types::error::QuilError;
        if bytes.len() < 4 {
            return Err(QuilError::InvalidArgument("app liveness state too short".into()));
        }
        let filter_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + filter_len + 8 {
            return Err(QuilError::InvalidArgument("app liveness state truncated".into()));
        }
        let filter = bytes[4..4 + filter_len].to_vec();
        let off = 4 + filter_len;
        let current_rank = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        Ok(LivenessState {
            filter: filter.clone(),
            current_rank,
            latest_quorum_certificate: Arc::new(
                AppGenesisQC::for_output(filter, &vec![0u8; 32]),
            ),
            prior_rank_timeout_certificate: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_codec_roundtrip() {
        let codec = AppConsensusCodec { filter: vec![1, 2, 3] };
        let state = ConsensusState::<AppShardVote> {
            filter: vec![1, 2, 3],
            finalized_rank: 42,
            latest_acknowledged_rank: 50,
            latest_timeout: None,
        };
        let bytes = codec.encode_consensus_state(&state).unwrap();
        let decoded = codec.decode_consensus_state(&bytes).unwrap();
        assert_eq!(decoded.filter, vec![1, 2, 3]);
        assert_eq!(decoded.finalized_rank, 42);
        assert_eq!(decoded.latest_acknowledged_rank, 50);
    }

    #[test]
    fn liveness_codec_roundtrip() {
        let codec = AppConsensusCodec { filter: vec![4, 5] };
        let state = LivenessState {
            filter: vec![4, 5],
            current_rank: 99,
            latest_quorum_certificate: Arc::new(
                AppGenesisQC::for_output(vec![4, 5], &vec![0u8; 32]),
            ),
            prior_rank_timeout_certificate: None,
        };
        let bytes = codec.encode_liveness_state(&state).unwrap();
        let decoded = codec.decode_liveness_state(&bytes).unwrap();
        assert_eq!(decoded.filter, vec![4, 5]);
        assert_eq!(decoded.current_rank, 99);
    }
}
