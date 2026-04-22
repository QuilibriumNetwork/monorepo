//! Message routing for incoming consensus messages. Classifies
//! canonical-bytes messages by type prefix and routes to the
//! appropriate handler (consensus event loop, execution engine, etc.).
//!
//! Mirror of `node/consensus/global/message_router.go`.

use quil_types::error::{QuilError, Result};

use quil_execution::global_engine::{
    TYPE_PROVER_JOIN, TYPE_PROVER_LEAVE,
    TYPE_PROVER_PAUSE, TYPE_PROVER_RESUME, TYPE_PROVER_CONFIRM,
    TYPE_PROVER_REJECT, TYPE_PROVER_KICK, TYPE_PROVER_UPDATE,
    TYPE_FRAME_HEADER, TYPE_SENIORITY_MERGE, TYPE_SHARD_SPLIT,
    TYPE_SHARD_MERGE,
};
use quil_execution::global_intrinsic::consensus_types::{
    TYPE_GLOBAL_PROPOSAL, TYPE_APP_SHARD_PROPOSAL,
    TYPE_QUORUM_CERTIFICATE, TYPE_TIMEOUT_STATE, TYPE_TIMEOUT_CERTIFICATE,
};
use quil_execution::hypergraph_engine::is_hypergraph_type_prefix;
use quil_execution::message_envelope::{
    CanonicalMessageRequest,
    TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST,
};

/// Classification of an incoming message for routing purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRoute {
    /// A consensus protocol message (proposal, vote, timeout).
    Consensus,
    /// A global prover operation (join, leave, pause, etc.).
    GlobalProverOp,
    /// A shard management message (frame header, split, merge).
    ShardManagement,
    /// A hypergraph operation (vertex/hyperedge add/remove).
    HypergraphOp,
    /// A token or compute operation.
    AppShardOp,
    /// A message bundle containing multiple operations.
    Bundle,
    /// Unrecognized message type.
    Unknown,
}

/// Consensus-specific message sub-types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusMessageKind {
    GlobalProposal,
    AppShardProposal,
    QuorumCertificate,
    TimeoutState,
    TimeoutCertificate,
    ProposalVote,
}

/// ProposalVote type prefix (0x030C) — also defined in consensus_wire.rs
/// as PROPOSAL_VOTE_TYPE.
const TYPE_PROPOSAL_VOTE: u32 = 0x030C;

/// Classify an incoming message by peeking at its type prefix.
pub fn classify_message(data: &[u8]) -> Result<MessageRoute> {
    if data.len() < 4 {
        return Err(QuilError::InvalidArgument("message too short".into()));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[..4]);
    let tp = u32::from_be_bytes(buf);

    match tp {
        TYPE_MESSAGE_BUNDLE => Ok(MessageRoute::Bundle),
        TYPE_MESSAGE_REQUEST => {
            // Peek inside the request to classify
            if let Ok(req) = CanonicalMessageRequest::from_canonical_bytes(data) {
                classify_inner_type(req.inner_type_prefix)
            } else {
                Ok(MessageRoute::Unknown)
            }
        }
        _ => classify_inner_type(tp),
    }
}

fn classify_inner_type(tp: u32) -> Result<MessageRoute> {
    // Consensus messages
    if matches!(tp,
        TYPE_GLOBAL_PROPOSAL | TYPE_APP_SHARD_PROPOSAL |
        TYPE_QUORUM_CERTIFICATE | TYPE_TIMEOUT_STATE |
        TYPE_TIMEOUT_CERTIFICATE | TYPE_PROPOSAL_VOTE
    ) {
        return Ok(MessageRoute::Consensus);
    }

    // Global prover ops
    if matches!(tp,
        TYPE_PROVER_JOIN | TYPE_PROVER_LEAVE | TYPE_PROVER_PAUSE |
        TYPE_PROVER_RESUME | TYPE_PROVER_CONFIRM | TYPE_PROVER_REJECT |
        TYPE_PROVER_KICK | TYPE_PROVER_UPDATE | TYPE_SENIORITY_MERGE
    ) {
        return Ok(MessageRoute::GlobalProverOp);
    }

    // Shard management
    if matches!(tp, TYPE_FRAME_HEADER | TYPE_SHARD_SPLIT | TYPE_SHARD_MERGE) {
        return Ok(MessageRoute::ShardManagement);
    }

    // Hypergraph ops
    if is_hypergraph_type_prefix(tp) {
        return Ok(MessageRoute::HypergraphOp);
    }

    // Token/compute ops (0x05xx, 0x06xx ranges)
    if (tp >> 8) == 0x05 || (tp >> 8) == 0x06 {
        return Ok(MessageRoute::AppShardOp);
    }

    Ok(MessageRoute::Unknown)
}

/// Classify a consensus-specific message type prefix.
pub fn classify_consensus_message(tp: u32) -> Option<ConsensusMessageKind> {
    match tp {
        TYPE_GLOBAL_PROPOSAL => Some(ConsensusMessageKind::GlobalProposal),
        TYPE_APP_SHARD_PROPOSAL => Some(ConsensusMessageKind::AppShardProposal),
        TYPE_QUORUM_CERTIFICATE => Some(ConsensusMessageKind::QuorumCertificate),
        TYPE_TIMEOUT_STATE => Some(ConsensusMessageKind::TimeoutState),
        TYPE_TIMEOUT_CERTIFICATE => Some(ConsensusMessageKind::TimeoutCertificate),
        TYPE_PROPOSAL_VOTE => Some(ConsensusMessageKind::ProposalVote),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_prover_join() {
        let bytes = TYPE_PROVER_JOIN.to_be_bytes();
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::GlobalProverOp);
    }

    #[test]
    fn classify_global_proposal() {
        let bytes = TYPE_GLOBAL_PROPOSAL.to_be_bytes();
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::Consensus);
    }

    #[test]
    fn classify_qc() {
        let bytes = TYPE_QUORUM_CERTIFICATE.to_be_bytes();
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::Consensus);
    }

    #[test]
    fn classify_frame_header() {
        let bytes = TYPE_FRAME_HEADER.to_be_bytes();
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::ShardManagement);
    }

    #[test]
    fn classify_vertex_add() {
        let bytes = 0x0404u32.to_be_bytes(); // TYPE_VERTEX_ADD
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::HypergraphOp);
    }

    #[test]
    fn classify_token_transaction() {
        let bytes = 0x0509u32.to_be_bytes(); // TYPE_TRANSACTION
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::AppShardOp);
    }

    #[test]
    fn classify_compute_code_execute() {
        let bytes = 0x060Cu32.to_be_bytes(); // TYPE_CODE_EXECUTE
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::AppShardOp);
    }

    #[test]
    fn classify_bundle() {
        let bytes = 0x0312u32.to_be_bytes(); // TYPE_MESSAGE_BUNDLE
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::Bundle);
    }

    #[test]
    fn classify_unknown() {
        let bytes = 0xDEADu32.to_be_bytes();
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::Unknown);
    }

    #[test]
    fn classify_short_rejects() {
        assert!(classify_message(&[0, 0]).is_err());
    }

    #[test]
    fn consensus_message_kinds_all_distinct() {
        let qc = classify_consensus_message(TYPE_QUORUM_CERTIFICATE);
        let tc = classify_consensus_message(TYPE_TIMEOUT_CERTIFICATE);
        let ts = classify_consensus_message(TYPE_TIMEOUT_STATE);
        assert_ne!(qc, tc);
        assert_ne!(tc, ts);
    }
}
