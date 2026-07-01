//! Decode consensus gossip messages into the rank/frame/sender signal the
//! proxy event loop drives partitions from.
//!
//! Messages on the global-consensus bitmask are Quilibrium canonical bytes
//! prefixed with a 4-byte big-endian type tag. We reuse `quil-engine`'s wire
//! decoders for `GlobalProposal` / `ProposalVote` / `TimeoutState` rather than
//! reimplementing the format. Mirrors the Go proxy's `extractConsensusMessage`.

use anyhow::{bail, Result};
use prost::Message;
use quil_engine::bitmasks;
use quil_engine::consensus_wire::{
    GlobalProposal, ProposalVote, TimeoutState, GLOBAL_PROPOSAL_TYPE, PROPOSAL_VOTE_TYPE,
    TIMEOUT_STATE_TYPE,
};
use quil_types::proto::global::SubmitGlobalConsensusRequest;

/// Information extracted from a gossip consensus message. `sender_address` holds
/// the prover address of the node that originated the message: the proposer for
/// a `GlobalProposal`, the voter for a `ProposalVote`, and the timed-out node
/// for a `TimeoutState`. For `TimeoutState` messages carrying a sender,
/// `is_timeout` is true (used to count unique timed-out nodes); proposals and
/// votes are always `is_timeout: false`. The address may be empty if the
/// underlying vote was unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusEvent {
    pub rank: u64,
    pub frame_number: u64,
    pub is_timeout: bool,
    /// Prover address of the originator (proposer/voter/timed-out node). Empty
    /// when the source vote carried no address.
    pub sender_address: Vec<u8>,
}

/// Peek at the 4-byte type prefix and decode the consensus message to extract
/// its rank and frame number (and, for timeouts, the sender's prover address).
/// Returns `None` for non-consensus or undecodable messages.
pub fn extract_consensus_event(data: &[u8]) -> Option<ConsensusEvent> {
    if data.len() < 4 {
        return None;
    }
    let type_prefix = u32::from_be_bytes(data[..4].try_into().ok()?);
    match type_prefix {
        GLOBAL_PROPOSAL_TYPE => {
            let p = GlobalProposal::from_canonical_bytes(data).ok()?;
            // The embedded vote is the proposer's self-signed vote, so its
            // address identifies the proposer.
            Some(ConsensusEvent {
                rank: p.vote.rank,
                frame_number: p.vote.frame_number,
                is_timeout: false,
                sender_address: p.vote.address.clone(),
            })
        }
        PROPOSAL_VOTE_TYPE => {
            let v = ProposalVote::from_canonical_bytes(data).ok()?;
            // A standalone vote's address identifies the voter.
            Some(ConsensusEvent {
                rank: v.rank,
                frame_number: v.frame_number,
                is_timeout: false,
                sender_address: v.address.clone(),
            })
        }
        TIMEOUT_STATE_TYPE => {
            let t = TimeoutState::from_canonical_bytes(data).ok()?;
            let sender_address = t.vote.address.clone();
            // Match Go: a timeout is only counted when it carries a sender
            // address (the BLS-signed prover filter). Unsigned timeouts are
            // treated as non-timeout signals.
            let is_timeout = !sender_address.is_empty();
            Some(ConsensusEvent {
                rank: t.vote.rank,
                frame_number: t.vote.frame_number,
                is_timeout,
                sender_address,
            })
        }
        _ => None,
    }
}

/// Snoop a `SubmitGlobalConsensus` gRPC request frame and extract the same
/// [`ConsensusEvent`] the gossip snoop produces. Since v2.1.0.25, global
/// consensus proposals/votes/timeouts travel point-to-point over
/// `GlobalService.SubmitGlobalConsensus` instead of gossip, so the proxy taps
/// them off the gRPC path it already relays.
///
/// `frame` is one gRPC length-prefixed message:
/// `[1 compression flag][4-byte big-endian length][protobuf message]`. The
/// protobuf is a `SubmitGlobalConsensusRequest { bitmask, data }` whose `data`
/// is byte-identical to what used to be gossiped, so we hand it straight to
/// [`extract_consensus_event`].
///
/// Returns `Err` for a **compressed** frame — tonic clients send uncompressed,
/// so a compressed frame means the snoop's assumption is broken and would
/// silently miss consensus (the exact failure this code fixes); the caller
/// surfaces it loudly rather than degrading quietly. Returns `Ok(None)` for a
/// truncated/undecodable frame, a submission on the wrong bitmask, or a payload
/// that isn't a recognized consensus message.
///
/// Only `GLOBAL_CONSENSUS` submissions (votes + timeouts) are accepted, mirroring
/// the archive's consensus topic: those carry every signal the proxy needs (rank,
/// frame, timeout, voter). A caller cannot drive rank / stop-frame detection by
/// sending consensus bytes under a mismatched bitmask (e.g. `GLOBAL_FRAME`, which
/// the backend routes elsewhere).
pub fn extract_from_grpc_message(frame: &[u8]) -> Result<Option<ConsensusEvent>> {
    // gRPC framing: leading compression flag, then a big-endian u32 length.
    if frame.len() < 5 {
        return Ok(None);
    }
    if frame[0] != 0 {
        bail!("compressed SubmitGlobalConsensus frame — the snoop cannot decode it (tonic clients send uncompressed)");
    }
    let len = u32::from_be_bytes(frame[1..5].try_into().expect("checked len >= 5")) as usize;
    let Some(msg) = frame.get(5..5 + len) else {
        return Ok(None);
    };
    let Ok(req) = SubmitGlobalConsensusRequest::decode(msg) else {
        return Ok(None);
    };
    // Mirror the archive's accepted consensus topic. Votes/timeouts ride
    // GLOBAL_CONSENSUS; anything else (e.g. proposals on GLOBAL_FRAME) is routed
    // elsewhere by the backend and must not advance our rank / stop-frame state.
    if req.bitmask.as_slice() != bitmasks::GLOBAL_CONSENSUS {
        return Ok(None);
    }
    Ok(extract_consensus_event(&req.data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_engine::consensus_wire::{AggregateSignature, QuorumCertificate};

    fn vote(rank: u64, frame: u64, address: Vec<u8>) -> ProposalVote {
        ProposalVote {
            filter: vec![0u8; 32],
            rank,
            frame_number: frame,
            selector: vec![0u8; 32],
            timestamp: 0,
            signature: if address.is_empty() {
                Vec::new()
            } else {
                vec![1u8; 74]
            },
            address,
            openings: Vec::new(),
        }
    }

    fn qc() -> QuorumCertificate {
        QuorumCertificate {
            filter: vec![0u8; 32],
            rank: 0,
            frame_number: 0,
            selector: vec![0u8; 32],
            timestamp: 0,
            aggregate_signature: AggregateSignature::empty(),
        }
    }

    #[test]
    fn too_short_returns_none() {
        assert!(extract_consensus_event(&[0x00, 0x01]).is_none());
    }

    #[test]
    fn unknown_prefix_returns_none() {
        // Valid length, but not a consensus type prefix.
        assert!(extract_consensus_event(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00]).is_none());
    }

    #[test]
    fn decodes_proposal_vote() {
        // A signed vote carries the voter's address as the sender.
        let addr = vec![0x11u8; 32];
        let bytes = vote(7, 42, addr.clone()).to_canonical_bytes().unwrap();
        let ev = extract_consensus_event(&bytes).expect("decode vote");
        assert_eq!(
            ev,
            ConsensusEvent {
                rank: 7,
                frame_number: 42,
                is_timeout: false,
                sender_address: addr
            }
        );
    }

    #[test]
    fn decodes_global_proposal() {
        // The embedded vote's address identifies the proposer.
        let addr = vec![0x22u8; 32];
        let proposal = GlobalProposal {
            state: vec![0xAB; 8],
            parent_quorum_certificate: qc(),
            prior_rank_timeout_certificate: None,
            vote: vote(3, 100, addr.clone()),
        };
        let bytes = proposal.to_canonical_bytes().unwrap();
        let ev = extract_consensus_event(&bytes).expect("decode proposal");
        assert_eq!(ev.rank, 3);
        assert_eq!(ev.frame_number, 100);
        assert!(!ev.is_timeout);
        assert_eq!(ev.sender_address, addr);
    }

    #[test]
    fn decodes_timeout_with_sender() {
        let addr = vec![0x42u8; 32];
        let timeout = TimeoutState {
            latest_quorum_certificate: qc(),
            prior_rank_timeout_certificate: None,
            vote: vote(5, 9, addr.clone()),
            timeout_tick: 1,
            timestamp: 0,
        };
        let bytes = timeout.to_canonical_bytes().unwrap();
        let ev = extract_consensus_event(&bytes).expect("decode timeout");
        assert_eq!(ev.rank, 5);
        assert_eq!(ev.frame_number, 9);
        assert!(ev.is_timeout);
        assert_eq!(ev.sender_address, addr);
    }

    #[test]
    fn timeout_without_sender_is_not_counted() {
        let timeout = TimeoutState {
            latest_quorum_certificate: qc(),
            prior_rank_timeout_certificate: None,
            vote: vote(5, 9, Vec::new()),
            timeout_tick: 1,
            timestamp: 0,
        };
        let bytes = timeout.to_canonical_bytes().unwrap();
        let ev = extract_consensus_event(&bytes).expect("decode timeout");
        assert!(!ev.is_timeout, "unsigned timeout must not count");
        assert!(ev.sender_address.is_empty());
    }

    /// Wrap `data` in a `SubmitGlobalConsensusRequest` on `bitmask` and a gRPC
    /// length-prefixed frame, exactly as tonic would send it (uncompressed).
    fn grpc_frame_with(bitmask: &[u8], data: Vec<u8>) -> Vec<u8> {
        let req = SubmitGlobalConsensusRequest {
            bitmask: bitmask.to_vec(),
            data,
        };
        let msg = req.encode_to_vec();
        let mut frame = vec![0u8]; // compression flag: uncompressed
        frame.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        frame.extend_from_slice(&msg);
        frame
    }

    /// A frame on the GLOBAL_CONSENSUS topic (votes/timeouts) the proxy snoops.
    fn grpc_frame(data: Vec<u8>) -> Vec<u8> {
        grpc_frame_with(bitmasks::GLOBAL_CONSENSUS, data)
    }

    #[test]
    fn extracts_vote_from_grpc_frame() {
        let addr = vec![0x33u8; 32];
        let data = vote(7, 42, addr.clone()).to_canonical_bytes().unwrap();
        let ev = extract_from_grpc_message(&grpc_frame(data))
            .unwrap()
            .expect("snoop vote");
        assert_eq!(
            ev,
            ConsensusEvent {
                rank: 7,
                frame_number: 42,
                is_timeout: false,
                sender_address: addr
            }
        );
    }

    #[test]
    fn extracts_timeout_from_grpc_frame() {
        let addr = vec![0x55u8; 32];
        let timeout = TimeoutState {
            latest_quorum_certificate: qc(),
            prior_rank_timeout_certificate: None,
            vote: vote(5, 9, addr.clone()),
            timeout_tick: 1,
            timestamp: 0,
        };
        let data = timeout.to_canonical_bytes().unwrap();
        let ev = extract_from_grpc_message(&grpc_frame(data))
            .unwrap()
            .expect("snoop timeout");
        assert_eq!(ev.rank, 5);
        assert!(ev.is_timeout);
        assert_eq!(ev.sender_address, addr);
    }

    #[test]
    fn wrong_bitmask_is_ignored() {
        // Valid consensus bytes, but submitted on GLOBAL_FRAME (the proposal
        // topic) rather than GLOBAL_CONSENSUS — the backend routes it elsewhere,
        // so it must not drive our rank / stop-frame detection.
        let data = vote(7, 42, vec![0x33u8; 32]).to_canonical_bytes().unwrap();
        let frame = grpc_frame_with(bitmasks::GLOBAL_FRAME, data);
        assert!(extract_from_grpc_message(&frame).unwrap().is_none());
    }

    #[test]
    fn compressed_frame_is_error() {
        let data = vote(1, 1, vec![0x01u8; 32]).to_canonical_bytes().unwrap();
        let mut frame = grpc_frame(data);
        frame[0] = 1; // mark compressed — we can't decode it, so surface an error
        assert!(extract_from_grpc_message(&frame).is_err());
    }

    #[test]
    fn short_or_empty_frame_is_none() {
        assert!(extract_from_grpc_message(&[]).unwrap().is_none());
        assert!(extract_from_grpc_message(&[0x00, 0x00, 0x00])
            .unwrap()
            .is_none());
    }

    #[test]
    fn non_consensus_payload_is_none() {
        // Right bitmask + well-formed frame, but `data` isn't a consensus message.
        let ev =
            extract_from_grpc_message(&grpc_frame(vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00])).unwrap();
        assert!(ev.is_none());
    }
}
