//! Admission of GLOBAL_FRAME gossip, and what it remembers between frames.
//!
//! A GLOBAL frame is authenticated by its header (committee finalization
//! certificate and VDF) and bound to its body by the header's requests root.
//! Any peer can republish a finalized header with another body, and each copy
//! has a new message id, so without memory of what was already checked every
//! copy costs every node the certificate, VDF and requests-root work and is
//! forwarded through the whole mesh. [`GlobalFrameGate`] remembers:
//!
//! * the frame numbers this node accepted from gossip within the last
//!   [`STALE_WINDOW`] frames: later copies, and copies further below the
//!   newest accepted frame, are dropped before decoding and not forwarded;
//! * the headers whose certificate and VDF verified, so a repeated header
//!   skips both checks (its body is still checked against the root);
//! * the global committee's peer ids: a frame the committee signed is rate
//!   limited per author, every other one per forwarding peer, so a peer that
//!   relays someone else's flood cannot get the committee's frames dropped.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use libp2p::PeerId;

use crate::ValidationResult;

/// Frames this far below the newest frame accepted from gossip are dropped
/// unverified. Gossip carries the chain head, so an honest copy is never this
/// late (about 10 to 25 minutes of frames); the archive poller fills gaps.
pub const STALE_WINDOW: u64 = 64;

/// Bound on remembered verified headers (one per frame in practice).
const VERIFIED_HEADER_CAP: usize = 256;

/// Canonical type prefix of a GLOBAL frame header (`consensus_wire`).
const GLOBAL_FRAME_HEADER_TYPE: u32 = 0x0309;

/// Most frames one key (committee author, or forwarding peer otherwise) may
/// deliver in a one-second window. Honest gossip is about one frame per 10 s.
const MAX_FRAMES_PER_SEC: u32 = 8;

/// Bound on the rate-limit map; past it the map is cleared wholesale.
const RATE_MAP_CAP: usize = 4096;

/// How the gate classifies a frame number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameStatus {
    /// Not accepted yet and within the window: check it.
    New,
    /// Already accepted from gossip.
    Accepted,
    /// More than [`STALE_WINDOW`] frames below the newest accepted frame.
    Stale,
}

/// State shared by the GLOBAL_FRAME gossip validator (swarm task) and the
/// receive loop that verifies and stores frames.
#[derive(Debug, Default)]
pub struct GlobalFrameGate {
    state: Mutex<GateState>,
}

#[derive(Debug, Default)]
struct GateState {
    newest_accepted: Option<u64>,
    accepted: BTreeSet<u64>,
    verified_headers: HashMap<[u8; 32], u64>,
    committee: HashSet<PeerId>,
}

impl GlobalFrameGate {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, GateState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Classify a frame number against the frames accepted so far.
    pub fn status(&self, frame_number: u64) -> FrameStatus {
        let state = self.state();
        if state.accepted.contains(&frame_number) {
            return FrameStatus::Accepted;
        }
        match state.newest_accepted {
            Some(newest) if frame_number.saturating_add(STALE_WINDOW) < newest => {
                FrameStatus::Stale
            }
            _ => FrameStatus::New,
        }
    }

    /// Record a frame that passed every check and was stored.
    pub fn mark_accepted(&self, frame_number: u64) {
        let mut state = self.state();
        let newest = state
            .newest_accepted
            .map_or(frame_number, |newest| newest.max(frame_number));
        state.newest_accepted = Some(newest);
        state.accepted.insert(frame_number);
        let floor = newest.saturating_sub(STALE_WINDOW);
        let kept = state.accepted.split_off(&floor);
        state.accepted = kept;
        state.verified_headers.retain(|_, frame| *frame >= floor);
    }

    /// Whether a header with this digest already passed the certificate and
    /// VDF checks.
    pub fn header_verified(&self, digest: &[u8; 32]) -> bool {
        self.state().verified_headers.contains_key(digest)
    }

    /// Record a header that passed the certificate and VDF checks. Evicts the
    /// lowest frame when full.
    pub fn mark_header_verified(&self, digest: [u8; 32], frame_number: u64) {
        let mut state = self.state();
        if !state.verified_headers.contains_key(&digest)
            && state.verified_headers.len() >= VERIFIED_HEADER_CAP
        {
            let oldest = state
                .verified_headers
                .iter()
                .min_by_key(|(_, frame)| **frame)
                .map(|(digest, _)| *digest);
            if let Some(oldest) = oldest {
                state.verified_headers.remove(&oldest);
            }
        }
        state.verified_headers.insert(digest, frame_number);
    }

    /// Set the peer ids of the global committee, the authors of GLOBAL frames.
    pub fn set_committee(&self, peers: impl IntoIterator<Item = PeerId>) {
        self.state().committee = peers.into_iter().collect();
    }

    fn is_committee(&self, peer: &PeerId) -> bool {
        self.state().committee.contains(peer)
    }
}

/// Frame number of a canonical GLOBAL frame, read without decoding it:
/// `[frame type u32][header length u32][header type u32][frame number u64]`.
pub fn peek_frame_number(data: &[u8]) -> Option<u64> {
    let header_len = u32::from_be_bytes(data.get(4..8)?.try_into().ok()?);
    if header_len < 12 {
        return None;
    }
    let header_type = u32::from_be_bytes(data.get(8..12)?.try_into().ok()?);
    if header_type != GLOBAL_FRAME_HEADER_TYPE {
        return None;
    }
    Some(u64::from_be_bytes(data.get(12..20)?.try_into().ok()?))
}

/// The GLOBAL_FRAME gossip validator. It runs on the swarm task before a
/// message is delivered or forwarded, so it stays O(1): it never decodes a
/// frame (up to ~15 MiB) or verifies its certificate.
pub struct GlobalFrameAdmission {
    frame_type: u32,
    gate: Arc<GlobalFrameGate>,
    counters: Mutex<HashMap<(bool, PeerId), (u64, u32)>>,
}

impl GlobalFrameAdmission {
    pub fn new(frame_type: u32, gate: Arc<GlobalFrameGate>) -> Self {
        Self {
            frame_type,
            gate,
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Verdict on a message from `forwarder`, signed by `author`, at
    /// `now_secs` (Unix seconds).
    ///
    /// * A wrong type prefix is `Reject`ed: every build rejects it, so an
    ///   honest peer never forwards one.
    /// * A frame already accepted, or stale, is `Ignore`d: no further work and
    ///   no forwarding, without penalty, as an honest relay may still forward
    ///   a copy it has not finished checking.
    /// * Past the rate limit, `Ignore`. A frame the committee signed counts
    ///   against its author, anything else against the forwarding peer.
    pub fn admit(
        &self,
        forwarder: &PeerId,
        author: Option<&PeerId>,
        data: &[u8],
        now_secs: u64,
    ) -> ValidationResult {
        if data.len() < 4
            || u32::from_be_bytes(data[..4].try_into().unwrap_or([0; 4])) != self.frame_type
        {
            return ValidationResult::Reject;
        }
        if let Some(frame_number) = peek_frame_number(data) {
            if self.gate.status(frame_number) != FrameStatus::New {
                return ValidationResult::Ignore;
            }
        }
        let key = match author {
            Some(author) if self.gate.is_committee(author) => (true, *author),
            _ => (false, *forwarder),
        };
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if counters.len() > RATE_MAP_CAP {
            counters.clear();
        }
        let entry = counters.entry(key).or_insert((now_secs, 0));
        if entry.0 == now_secs {
            entry.1 = entry.1.saturating_add(1);
        } else {
            *entry = (now_secs, 1);
        }
        if entry.1 > MAX_FRAMES_PER_SEC {
            return ValidationResult::Ignore;
        }
        ValidationResult::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME_TYPE: u32 = 0x030E;

    fn frame(number: u64, body: &[u8]) -> Vec<u8> {
        let mut header = GLOBAL_FRAME_HEADER_TYPE.to_be_bytes().to_vec();
        header.extend_from_slice(&number.to_be_bytes());
        header.extend_from_slice(b"rest of header");
        let mut data = FRAME_TYPE.to_be_bytes().to_vec();
        data.extend_from_slice(&(header.len() as u32).to_be_bytes());
        data.extend_from_slice(&header);
        data.extend_from_slice(body);
        data
    }

    #[test]
    fn peeks_the_frame_number_of_canonical_bytes_only() {
        assert_eq!(peek_frame_number(&frame(907_920, b"body")), Some(907_920));
        assert_eq!(peek_frame_number(&frame(7, b"")[..19]), None);
        let mut other_header = frame(7, b"");
        other_header[11] ^= 1;
        assert_eq!(peek_frame_number(&other_header), None);
    }

    #[test]
    fn accepted_and_stale_frames_are_known() {
        let gate = GlobalFrameGate::new();
        assert_eq!(gate.status(1_000), FrameStatus::New);
        gate.mark_accepted(1_000);
        assert_eq!(gate.status(1_000), FrameStatus::Accepted);
        assert_eq!(gate.status(1_001), FrameStatus::New);
        assert_eq!(gate.status(1_000 - STALE_WINDOW), FrameStatus::New);
        assert_eq!(gate.status(999 - STALE_WINDOW), FrameStatus::Stale);
        gate.mark_accepted(1_000 + STALE_WINDOW + 1);
        assert_eq!(gate.status(1_000), FrameStatus::Stale);
        assert_eq!(gate.state().accepted.len(), 1);
    }

    #[test]
    fn verified_headers_are_bounded_and_follow_the_window() {
        let gate = GlobalFrameGate::new();
        for frame in 0..(VERIFIED_HEADER_CAP as u64 + 10) {
            let mut digest = [0u8; 32];
            digest[..8].copy_from_slice(&frame.to_be_bytes());
            gate.mark_header_verified(digest, frame);
        }
        assert_eq!(gate.state().verified_headers.len(), VERIFIED_HEADER_CAP);
        assert!(!gate.header_verified(&[0u8; 32]));
        let mut newest = [0u8; 32];
        newest[..8].copy_from_slice(&(VERIFIED_HEADER_CAP as u64 + 9).to_be_bytes());
        assert!(gate.header_verified(&newest));
        gate.mark_accepted(10_000);
        assert!(gate.state().verified_headers.is_empty());
    }

    /// A republished copy of an accepted frame, whatever its body, is dropped
    /// unforwarded and costs no further checks.
    #[test]
    fn copies_of_accepted_and_stale_frames_are_ignored() {
        let gate = Arc::new(GlobalFrameGate::new());
        let admission = GlobalFrameAdmission::new(FRAME_TYPE, gate.clone());
        let relay = PeerId::random();
        assert_eq!(
            admission.admit(&relay, None, &frame(500, b"genuine"), 1),
            ValidationResult::Accept
        );
        gate.mark_accepted(500);
        for body in [&b"other"[..], b"bodies", b"each"] {
            assert_eq!(
                admission.admit(&relay, None, &frame(500, body), 1),
                ValidationResult::Ignore
            );
        }
        gate.mark_accepted(500 + STALE_WINDOW + 1);
        assert_eq!(
            admission.admit(&relay, None, &frame(499, b"old"), 2),
            ValidationResult::Ignore
        );
        assert_eq!(
            admission.admit(&relay, None, b"\0\0\0\x01junk", 2),
            ValidationResult::Reject
        );
    }

    /// A relay that forwards a flood still delivers the committee's frame, and
    /// the flood is dropped without penalising the relay.
    #[test]
    fn a_relayed_flood_does_not_drop_the_committee_frame() {
        let gate = Arc::new(GlobalFrameGate::new());
        let committee = PeerId::random();
        gate.set_committee([committee]);
        let admission = GlobalFrameAdmission::new(FRAME_TYPE, gate);
        let relay = PeerId::random();
        let flooder = PeerId::random();
        let verdicts: Vec<_> = (0..MAX_FRAMES_PER_SEC as u8 + 4)
            .map(|i| admission.admit(&relay, Some(&flooder), &frame(600, &[i]), 5))
            .collect();
        assert!(verdicts[..MAX_FRAMES_PER_SEC as usize]
            .iter()
            .all(|v| *v == ValidationResult::Accept));
        assert!(verdicts[MAX_FRAMES_PER_SEC as usize..]
            .iter()
            .all(|v| *v == ValidationResult::Ignore));
        assert_eq!(
            admission.admit(&relay, Some(&committee), &frame(600, b"genuine"), 5),
            ValidationResult::Accept
        );
        assert_eq!(
            admission.admit(&relay, Some(&flooder), &frame(600, b"more"), 6),
            ValidationResult::Accept
        );
    }
}
