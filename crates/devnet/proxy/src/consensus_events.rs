//! Decode consensus messages into the view/frame/sender/participation signal the
//! proxy runs on: the gRPC snoop drives the partition schedule
//! ([`crate::view_schedule`]) from the view, and the event loop tracks frame
//! progress and consensus participation from the rest.
//!
//! Global consensus runs on commonware-simplex, split across four `:8340`
//! channels: the leader pushes frame bytes on the block channel, and members
//! exchange simplex votes/certificates on the others. Both carry a view — the
//! block channel as `GlobalFrameHeader.rank`, which *is* the simplex view the
//! frame was proposed in, and the vote/cert channels in their own wire prefix
//! (see [`crate::simplex_view`]).
//!
//! Reading both matters because they fail differently. A nullified view produces
//! no block, so a schedule keyed off the block channel alone goes blind exactly
//! when a partition is stalling consensus — which is when it has work to do. The
//! vote channels keep reporting through a stall, because simplex broadcasts
//! every `Nullify` to all peers.
//!
//! Frames are still only ever read off the block channel, since that is the only
//! payload that states one.

use std::sync::{Mutex, Once};

use anyhow::{bail, Result};
use prost::Message;
use quil_engine::bitmasks;
use quil_engine::consensus_wire::decode_global_frame;
use quil_types::proto::global::SubmitGlobalConsensusRequest;

use crate::simplex_view::{decode_view, VoteKind, CW_BLOCK_CHANNEL, CW_VOTE_CHANNEL};

/// The epoch global consensus runs in. The node constructs the global engine
/// with `epoch: 0` hardcoded, so anything else on these channels is not global
/// consensus and must not drive the partition schedule.
const GLOBAL_EPOCH: u64 = 0;

/// Which message produced this observation, and so what it can attest to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSource {
    /// A proposed frame on the block channel. The only payload that states its
    /// own frame number, so the only one whose `(view, frame_number)` is a fact
    /// rather than an attribution. Proposing is also active participation.
    Block,
    /// A simplex `Notarize` or `Finalize` — the sender's own attestation that it
    /// is driving this view forward.
    ActiveVote,
    /// A `Nullify` (this view produced nothing), or a certificate (aggregated
    /// votes rebroadcast by whoever assembled them). Neither is evidence that
    /// the sender voted for a frame. Nothing is lost by excluding them: every
    /// participating archive broadcasts its own `Notarize`/`Finalize` to all
    /// peers.
    Passive,
}

impl EventSource {
    /// Whether this is evidence that the sender voted in this event's view.
    ///
    /// The rejoin check asks whether each archive rejoined consensus rather than
    /// passively syncing frames, so it may only count messages that attest to
    /// the sender's own participation.
    pub fn is_active(self) -> bool {
        !matches!(self, Self::Passive)
    }

    /// Whether this event's `(view, frame_number)` is authoritative — i.e. the
    /// frame is the one this very message carries, not one inherited from the
    /// newest block seen so far.
    ///
    /// Only such an event may be used to learn which view produced a given
    /// frame. A vote names its own view but inherits its frame, so pairing the
    /// two would tie a frame to whatever view happened to be running when the
    /// vote was snooped.
    pub fn states_own_frame(self) -> bool {
        matches!(self, Self::Block)
    }
}

/// One observation of consensus progress.
///
/// `view` is the simplex view the message belongs to — the ordinal the partition
/// schedule keys on. `sender_address` is the prover address of the node that
/// originated the message, taken from the authenticated transport rather than
/// from anything the payload claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusEvent {
    pub view: u64,
    /// The frame this message belongs to, or `None` when no block has
    /// established one yet. Views advance before (and without) frames, so a
    /// view-only observation is normal rather than an error.
    pub frame_number: Option<u64>,
    /// Prover address of the originator. Empty when the caller had no mapped
    /// prover address.
    pub sender_address: Vec<u8>,
    /// What produced this observation, and so what it may be used to conclude.
    pub source: EventSource,
}

/// Snoop a `SubmitGlobalConsensus` gRPC request frame and extract the
/// [`ConsensusEvent`] it implies. Since v2.1.0.25 global consensus travels
/// point-to-point over `GlobalService.SubmitGlobalConsensus` rather than gossip,
/// so the proxy taps it off the gRPC path it already relays.
///
/// `frame` is one gRPC length-prefixed message:
/// `[1 compression flag][4-byte big-endian length][protobuf message]`. The
/// protobuf is a `SubmitGlobalConsensusRequest { bitmask, data }`.
///
/// Returns `Err` for a **compressed** frame — tonic clients send uncompressed,
/// so a compressed frame means the snoop's assumption is broken and would
/// silently miss consensus; the caller surfaces it loudly rather than degrading
/// quietly. Returns `Ok(None)` for a truncated/undecodable frame, a submission
/// on a non-CW bitmask (e.g. `GLOBAL_FRAME`, which the backend routes
/// elsewhere), or a payload that isn't a recognized consensus message — so a
/// caller cannot drive view / stop-frame detection by sending consensus bytes
/// under a mismatched bitmask.
///
/// `caller_address` is the prover address of the node that opened this
/// connection. The proxy re-originates every call under the true caller's
/// identity, so this attribution comes from the transport.
pub fn extract_from_grpc_message(
    frame: &[u8],
    caller_address: &[u8],
    cursor: &CwConsensusCursor,
) -> Result<Option<ConsensusEvent>> {
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

    Ok(cursor.observe(&req.bitmask, &req.data, caller_address))
}

/// Tracks the newest global frame seen on the CW **block** channel, so simplex
/// vote traffic — which references a view and a payload digest but never a frame
/// number — can be attributed to the frame consensus is working on.
///
/// The frame a vote is stamped with is therefore the frame consensus is
/// currently on rather than one parsed out of that vote. For a liveness harness
/// that distinction does not change the outcome, and participation is still
/// attested by the caller's authenticated identity rather than a self-reported
/// field.
#[derive(Debug)]
pub struct CwConsensusCursor {
    newest_frame: Mutex<Option<u64>>,
    /// Guards the foreign-epoch warning so a persistent mismatch logs once
    /// rather than once per message.
    foreign_epoch_warned: Once,
}

impl Default for CwConsensusCursor {
    fn default() -> Self {
        Self {
            newest_frame: Mutex::new(None),
            foreign_epoch_warned: Once::new(),
        }
    }
}

impl CwConsensusCursor {
    /// Fold one CW-channel submission into the cursor, returning the event it
    /// implies (if any). Non-CW bitmasks yield `None`.
    fn observe(
        &self,
        bitmask: &[u8],
        data: &[u8],
        caller_address: &[u8],
    ) -> Option<ConsensusEvent> {
        let channel = bitmasks::global_cw_channel_of(bitmask)?;
        let (view, frame_number, source) = if channel == CW_BLOCK_CHANNEL {
            // The frame itself — the only CW payload that states its own frame
            // number. Its header rank is the view it was proposed in.
            let frame = decode_global_frame(data).ok()?;
            let header = frame.header.as_ref()?;
            let mut newest = self.newest_frame.lock().expect("cursor mutex poisoned");
            // Frames can arrive out of order across backends; keep the highest.
            if newest.is_none_or(|f| header.frame_number >= f) {
                *newest = Some(header.frame_number);
            }
            // Proposing the frame is the strongest evidence of participation,
            // and this is the one message that ties a frame to its view.
            (header.rank, Some(header.frame_number), EventSource::Block)
        } else {
            // A simplex vote or certificate. Nullifications land here too, which
            // is what keeps the view advancing while a partition stalls block
            // production.
            let decoded = decode_view(channel, data)?;
            if decoded.epoch != GLOBAL_EPOCH {
                self.foreign_epoch_warned.call_once(|| {
                    tracing::warn!(
                        epoch = decoded.epoch,
                        expected = GLOBAL_EPOCH,
                        "ignoring CW consensus message from a foreign epoch; the partition \
                         schedule only follows global consensus"
                    );
                });
                return None;
            }
            // Logged because "the snoop stopped understanding the wire format"
            // otherwise presents only as a run that times out with no partition
            // ever applied. Seeing votes decode here is the positive signal.
            tracing::debug!(
                view = decoded.view,
                kind = ?decoded.kind,
                channel,
                "decoded simplex vote"
            );
            let source = match (channel, decoded.kind) {
                (CW_VOTE_CHANNEL, VoteKind::Notarize | VoteKind::Finalize) => {
                    EventSource::ActiveVote
                }
                _ => EventSource::Passive,
            };
            // The frame here is an attribution, not a fact: this message names
            // only a view, so it is stamped with the frame consensus is working
            // on. `EventSource::states_own_frame` is what keeps that
            // approximation from being mistaken for the real pairing.
            let newest = *self.newest_frame.lock().expect("cursor mutex poisoned");
            (decoded.view, newest, source)
        };

        Some(ConsensusEvent {
            view,
            frame_number,
            sender_address: caller_address.to_vec(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex_view::CW_VOTE_CHANNEL;
    use commonware_codec::varint::UInt;
    use commonware_codec::Encode;

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

    /// Canonical bytes for a global frame carrying `(frame_number, rank)`.
    fn cw_block(frame_number: u64, rank: u64) -> Vec<u8> {
        let header = quil_types::proto::global::GlobalFrameHeader {
            frame_number,
            rank,
            ..Default::default()
        };
        let frame = quil_types::proto::global::GlobalFrame {
            header: Some(header),
            ..Default::default()
        };
        quil_engine::consensus_wire::encode_global_frame(&frame).unwrap()
    }

    /// A simplex vote payload: `tag || epoch || view`, then attestation filler.
    fn cw_vote(tag: u8, epoch: u64, view: u64) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&UInt(epoch).encode());
        out.extend_from_slice(&UInt(view).encode());
        out.extend_from_slice(&[0xAB; 666]);
        out
    }

    fn snoop(
        bitmask: &[u8],
        data: Vec<u8>,
        caller: &[u8],
        cursor: &CwConsensusCursor,
    ) -> Option<ConsensusEvent> {
        extract_from_grpc_message(&grpc_frame_with(bitmask, data), caller, cursor).unwrap()
    }

    #[test]
    fn block_yields_view_and_frame_attributed_to_caller() {
        let caller = vec![0x77u8; 32];
        let cursor = CwConsensusCursor::default();
        let ev = snoop(bitmasks::GLOBAL_CW_BLOCK, cw_block(42, 7), &caller, &cursor)
            .expect("snoop cw block");
        assert_eq!(
            ev,
            ConsensusEvent {
                view: 7,
                frame_number: Some(42),
                sender_address: caller,
                source: EventSource::Block,
            }
        );
    }

    /// The reason this change exists: a nullified view advances the view while
    /// producing no block, so it must still yield an event — with no frame,
    /// because none has been established.
    #[test]
    fn nullify_before_any_block_reports_a_view_with_no_frame() {
        let cursor = CwConsensusCursor::default();
        let voter = vec![0x22u8; 32];
        let ev = snoop(bitmasks::GLOBAL_CW_VOTE, cw_vote(1, 0, 4), &voter, &cursor)
            .expect("a nullify must be observable before any block");
        assert_eq!(
            ev,
            ConsensusEvent {
                view: 4,
                frame_number: None,
                sender_address: voter,
                // A nullification is not evidence of voting for a frame.
                source: EventSource::Passive,
            }
        );
    }

    /// A vote carries no frame number, so it is attributed to the frame the
    /// newest block established — and to the caller that sent it. This is what
    /// lets the rejoin check see every archive participating, not just the
    /// leader that pushed the block.
    #[test]
    fn vote_inherits_frame_from_latest_block_and_reports_its_own_view() {
        let cursor = CwConsensusCursor::default();
        let leader = vec![0x11u8; 32];
        let voter = vec![0x22u8; 32];

        snoop(bitmasks::GLOBAL_CW_BLOCK, cw_block(9, 3), &leader, &cursor)
            .expect("block establishes the frame");

        // The view has moved past the block's, as it does when a view nullifies.
        let ev = snoop(bitmasks::GLOBAL_CW_VOTE, cw_vote(0, 0, 5), &voter, &cursor)
            .expect("snoop cw vote");
        assert_eq!(
            ev,
            ConsensusEvent {
                view: 5,
                frame_number: Some(9),
                sender_address: voter,
                source: EventSource::ActiveVote,
            }
        );
    }

    /// The rejoin check counts only messages that attest to the sender's own
    /// participation. Getting this table wrong is what let an archive that
    /// merely nullified pass the rejoin gate.
    #[test]
    fn participation_is_classified_per_channel_and_kind() {
        let cases = [
            (bitmasks::GLOBAL_CW_VOTE, 0u8, EventSource::ActiveVote), // Notarize
            (bitmasks::GLOBAL_CW_VOTE, 1, EventSource::Passive),      // Nullify
            (bitmasks::GLOBAL_CW_VOTE, 2, EventSource::ActiveVote),   // Finalize
            // Certificates are aggregated votes rebroadcast by the assembler.
            (bitmasks::GLOBAL_CW_CERT, 0, EventSource::Passive),
            (bitmasks::GLOBAL_CW_CERT, 1, EventSource::Passive),
            (bitmasks::GLOBAL_CW_CERT, 2, EventSource::Passive),
        ];
        let cursor = CwConsensusCursor::default();
        for (bitmask, tag, expected) in cases {
            let ev = snoop(bitmask, cw_vote(tag, 0, 5), &[0x11u8; 32], &cursor).expect("decode");
            assert_eq!(ev.source, expected, "bitmask {bitmask:?} tag {tag}");
            // However a vote is classified, its frame is inherited, so it may
            // never be used to learn which view produced that frame.
            assert!(
                !ev.source.states_own_frame(),
                "a vote must not be treated as authoritative for its frame"
            );
        }
    }

    /// Proposing the frame is the strongest evidence of participation.
    #[test]
    fn a_proposed_block_is_active_participation() {
        let cursor = CwConsensusCursor::default();
        let ev = snoop(
            bitmasks::GLOBAL_CW_BLOCK,
            cw_block(9, 3),
            &[0x11u8; 32],
            &cursor,
        )
        .expect("decode");
        assert_eq!(ev.source, EventSource::Block);
        assert!(ev.source.is_active());
        assert!(ev.source.states_own_frame());
    }

    /// A vote is stamped with the frame consensus is working on, so its
    /// `(view, frame_number)` pair is not a real pairing — here view 5 with
    /// frame 9, a frame produced by view 3. Only the block's own pair may be
    /// used to learn which view produced a frame.
    #[test]
    fn a_votes_view_and_inherited_frame_are_not_a_real_pairing() {
        let cursor = CwConsensusCursor::default();
        let block = snoop(
            bitmasks::GLOBAL_CW_BLOCK,
            cw_block(9, 3),
            &[0x11u8; 32],
            &cursor,
        )
        .expect("block");
        assert_eq!((block.view, block.frame_number), (3, Some(9)));

        let vote = snoop(
            bitmasks::GLOBAL_CW_VOTE,
            cw_vote(0, 0, 5),
            &[0x22u8; 32],
            &cursor,
        )
        .expect("vote");
        assert_eq!((vote.view, vote.frame_number), (5, Some(9)));
        assert!(
            !vote.source.states_own_frame(),
            "frame 9 was produced by view 3, not view 5"
        );
    }

    #[test]
    fn certificates_are_observed_too() {
        let cursor = CwConsensusCursor::default();
        let ev = snoop(
            bitmasks::GLOBAL_CW_CERT,
            cw_vote(1, 0, 11),
            &[0x33u8; 32],
            &cursor,
        )
        .expect("snoop cw cert");
        assert_eq!(ev.view, 11);
    }

    #[test]
    fn foreign_epoch_is_ignored() {
        let cursor = CwConsensusCursor::default();
        assert!(snoop(
            bitmasks::GLOBAL_CW_VOTE,
            cw_vote(0, 1, 5),
            &[0x22u8; 32],
            &cursor
        )
        .is_none());
    }

    #[test]
    fn resolver_channel_is_ignored() {
        // Backfiller requests have a different shape and no meaningful view.
        let cursor = CwConsensusCursor::default();
        assert!(snoop(
            bitmasks::GLOBAL_CW_RESOLVER,
            vec![0x00, 0x00, 0x05],
            &[0x22u8; 32],
            &cursor
        )
        .is_none());
    }

    /// Blocks fan out to every backend listener and can arrive out of order, so
    /// the cursor must hold the highest frame rather than the most recent one.
    #[test]
    fn cursor_keeps_highest_frame() {
        let cursor = CwConsensusCursor::default();
        let caller = vec![0x11u8; 32];
        for (frame_number, rank) in [(9u64, 3u64), (4, 1)] {
            snoop(
                bitmasks::GLOBAL_CW_BLOCK,
                cw_block(frame_number, rank),
                &caller,
                &cursor,
            );
        }
        let ev = snoop(bitmasks::GLOBAL_CW_VOTE, cw_vote(0, 0, 3), &caller, &cursor)
            .expect("snoop cw vote");
        assert_eq!(ev.frame_number, Some(9));
    }

    #[test]
    fn non_cw_bitmask_is_ignored() {
        // Well-formed frame on a bitmask the backend routes elsewhere: it must
        // not drive view / stop-frame detection.
        let cursor = CwConsensusCursor::default();
        assert!(snoop(bitmasks::GLOBAL_FRAME, cw_block(42, 7), &[], &cursor).is_none());
        assert!(snoop(bitmasks::GLOBAL_CONSENSUS, cw_vote(0, 0, 5), &[], &cursor).is_none());
    }

    #[test]
    fn compressed_frame_is_error() {
        let mut frame = grpc_frame_with(bitmasks::GLOBAL_CW_VOTE, cw_vote(0, 0, 5));
        frame[0] = 1; // mark compressed — we can't decode it, so surface an error
        assert!(extract_from_grpc_message(&frame, &[], &CwConsensusCursor::default()).is_err());
    }

    #[test]
    fn short_or_empty_frame_is_none() {
        let cursor = CwConsensusCursor::default();
        assert!(extract_from_grpc_message(&[], &[], &cursor)
            .unwrap()
            .is_none());
        assert!(extract_from_grpc_message(&[0x00, 0x00, 0x00], &[], &cursor)
            .unwrap()
            .is_none());
    }

    #[test]
    fn non_consensus_payload_is_none() {
        // Right bitmask + well-formed frame, but `data` isn't a simplex message.
        let cursor = CwConsensusCursor::default();
        assert!(snoop(bitmasks::GLOBAL_CW_VOTE, vec![0xFF, 0xFF], &[], &cursor).is_none());
        assert!(snoop(bitmasks::GLOBAL_CW_BLOCK, vec![0xFF, 0xFF], &[], &cursor).is_none());
    }

    /// The vote channel constant must agree with the bitmask table, or the
    /// decoder would silently reject every vote.
    #[test]
    fn vote_channel_constant_matches_bitmask_table() {
        assert_eq!(
            bitmasks::global_cw_channel_of(bitmasks::GLOBAL_CW_VOTE),
            Some(CW_VOTE_CHANNEL)
        );
        assert_eq!(
            bitmasks::global_cw_channel_of(bitmasks::GLOBAL_CW_BLOCK),
            Some(CW_BLOCK_CHANNEL)
        );
    }
}
