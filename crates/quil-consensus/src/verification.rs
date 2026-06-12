//! Message construction helpers for consensus signatures. Mirror of
//! `consensus/verification/common.go` — the format-level plumbing that
//! specifies which bytes are signed by votes and timeouts.
//!
//! Keeping these in `quil-consensus` (rather than a crypto adapter
//! crate) preserves wire compatibility with the Go implementation
//! regardless of which signature scheme is wired underneath.

use crate::models::Identity;

/// Construct the byte buffer that a vote signs. Mirror of
/// `verification.MakeVoteMessage`.
///
/// Layout (big-endian, byte-concatenated):
///
/// ```text
///     filter || stateID || rank:u64(BE)
/// ```
///
/// The filter disambiguates different consensus instances (shards);
/// the stateID + rank disambiguates individual proposals. The redundant
/// `rank` field allows signature verification without access to the
/// full state object.
pub fn make_vote_message(filter: &[u8], rank: u64, state_id: &Identity) -> Vec<u8> {
    let mut out = Vec::with_capacity(filter.len() + state_id.len() + 8);
    out.extend_from_slice(filter);
    out.extend_from_slice(state_id);
    out.extend_from_slice(&rank.to_be_bytes());
    out
}

/// Construct the byte buffer that a timeout signs. Mirror of
/// `verification.MakeTimeoutMessage`.
///
/// Layout:
///
/// ```text
///     filter || rank:u64(BE) || newestQCRank:u64(BE)
/// ```
///
/// The `(rank, newestQCRank)` pair is per-signer: each replica
/// contributes its own `newestQCRank`, so the resulting aggregate
/// signature is over potentially-different messages per signer.
pub fn make_timeout_message(filter: &[u8], rank: u64, newest_qc_rank: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(filter.len() + 16);
    out.extend_from_slice(filter);
    out.extend_from_slice(&rank.to_be_bytes());
    out.extend_from_slice(&newest_qc_rank.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vote_message_layout() {
        let filter = b"filter";
        let state_id: Identity = b"s1".to_vec();
        let msg = make_vote_message(filter, 0x0102030405060708, &state_id);
        // filter(6) + "s1"(2) + 8 bytes big-endian rank = 16 bytes
        assert_eq!(msg.len(), 16);
        assert_eq!(&msg[..6], b"filter");
        assert_eq!(&msg[6..8], b"s1");
        assert_eq!(
            &msg[8..16],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn timeout_message_layout() {
        let filter = b"f";
        let msg = make_timeout_message(filter, 5, 4);
        assert_eq!(msg.len(), 17); // 1 + 8 + 8
        assert_eq!(&msg[..1], b"f");
        assert_eq!(
            &msg[1..9],
            &[0, 0, 0, 0, 0, 0, 0, 5]
        );
        assert_eq!(
            &msg[9..17],
            &[0, 0, 0, 0, 0, 0, 0, 4]
        );
    }

    #[test]
    fn empty_filter_is_fine() {
        let empty: Vec<u8> = Vec::new();
        let vote = make_vote_message(&empty, 7, &b"state".to_vec());
        // "state" (5) + 8-byte rank = 13
        assert_eq!(vote.len(), 13);
        let to = make_timeout_message(&empty, 7, 3);
        assert_eq!(to.len(), 16);
    }

    #[test]
    fn different_ranks_produce_different_messages() {
        let filter = b"f";
        let state_id = b"s".to_vec();
        let a = make_vote_message(filter, 1, &state_id);
        let b = make_vote_message(filter, 2, &state_id);
        assert_ne!(a, b);
    }
}
