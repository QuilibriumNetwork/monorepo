//! Frame chain continuity checker. Port of Go's
//! `node/consensus/global/frame_chain_checker.go::CanProcessSequentialChain`.
//!
//! Given a proposal and the locally finalized state, walks the
//! `parent_selector` chain backwards and returns `true` if it links to
//! either a sealed clock-frame in the store, a candidate frame with a
//! matching identity, or the finalized state. Frame `Identity()` is
//! `Poseidon(output).FillBytes(32)` — see `protobufs/global.go:142-149`.
//!
//! The legacy "walk forward and check parent_selector == SHA-256(output)"
//! algorithm in this file's prior shape used the wrong hash and the
//! wrong direction; it is replaced here entirely.

use tracing::debug;

use quil_consensus::models::Identity;
use quil_types::error::QuilError;
use quil_types::proto::global::{GlobalProposal, GlobalFrame};
use quil_types::store::ClockStore;

/// Compute the canonical identity of a `GlobalFrame`. Mirror of Go's
/// `GlobalFrame.Identity()` — `poseidon.HashBytes(output).FillBytes(32)`.
fn global_frame_identity(frame: &GlobalFrame) -> Vec<u8> {
    let header = match frame.header.as_ref() {
        Some(h) => h,
        None => return Vec::new(),
    };
    quil_crypto::poseidon::hash_bytes_to_32(&header.output)
        .map(|h| h.to_vec())
        .unwrap_or_default()
}

/// Walk the proposal's parent chain backwards and decide whether it
/// links to known sealed/candidate/finalized state.
///
/// Mirrors `FrameChainChecker.CanProcessSequentialChain` at
/// `frame_chain_checker.go:44-135`. Returns `false` for any of:
/// - proposal has no header / no parent_selector
/// - the proposal claims frame number 0 (genesis is never a child)
/// - we hit a frame number the store can't resolve and which doesn't
///   match the finalized state
/// - a candidate has a mismatched `frame_number`
///
/// `finalized_state` mirrors Go's `*models.State[*GlobalFrame]` —
/// pass `Some((finalized_frame_number, finalized_identity))` if the
/// caller has a locally finalized frame, otherwise `None`.
pub fn can_process_sequential_chain_proposal(
    store: &dyn ClockStore,
    proposal: &GlobalProposal,
    finalized_state: Option<(u64, &Identity)>,
) -> bool {
    let Some(state) = proposal.state.as_ref() else {
        return false;
    };
    let Some(header) = state.header.as_ref() else {
        return false;
    };

    let mut parent_selector: Vec<u8> = header.parent_selector.clone();
    if parent_selector.is_empty() {
        return false;
    }

    let mut frame_number = header.frame_number;
    if frame_number == 0 {
        return false;
    }

    while frame_number > 0 && !parent_selector.is_empty() {
        frame_number -= 1;

        // 1. Sealed frame match — sealed.Identity() == parent_selector
        match store.get_global_clock_frame(frame_number) {
            Ok(sealed) => {
                let identity = global_frame_identity(&sealed);
                if identity == parent_selector {
                    debug!(
                        sealed_frame_number = frame_number,
                        "frame chain linked to sealed frame",
                    );
                    return true;
                }
            }
            Err(e) => {
                if !matches!(e, QuilError::NotFound(_)) {
                    debug!(
                        frame_number,
                        error = %e,
                        "failed to read sealed frame during chain validation",
                    );
                    return false;
                }
                // NotFound — fall through to candidate / finalized.
            }
        }

        // 2. Candidate frame at the same selector
        match store.get_global_clock_frame_candidate(frame_number, &parent_selector) {
            Ok(candidate) => {
                let candidate_header = match candidate.header.as_ref() {
                    Some(h) => h,
                    None => {
                        debug!(
                            frame_number,
                            "candidate frame had no header",
                        );
                        return false;
                    }
                };
                if candidate_header.frame_number != frame_number {
                    debug!(
                        frame_number,
                        candidate_frame_number = candidate_header.frame_number,
                        "candidate frame had mismatched header",
                    );
                    return false;
                }
                debug!(
                    candidate_frame_number = frame_number,
                    "frame chain matched candidate",
                );
                parent_selector = candidate_header.parent_selector.clone();
                continue;
            }
            Err(e) => {
                if !matches!(e, QuilError::NotFound(_)) {
                    debug!(
                        frame_number,
                        error = %e,
                        "failed to read candidate frame during chain validation",
                    );
                    return false;
                }
                // NotFound — fall through to finalized.
            }
        }

        // 3. Finalized state match
        if let Some((finalized_frame, finalized_identifier)) = finalized_state {
            if frame_number == finalized_frame
                && finalized_identifier.as_slice() == parent_selector.as_slice()
            {
                debug!(
                    finalized_frame_number = frame_number,
                    "frame chain linked to finalized frame",
                );
                return true;
            }
        }

        debug!(
            missing_frame_number = frame_number,
            expected_parent_selector = %hex::encode(&parent_selector),
            "missing ancestor frame while validating chain",
        );
        return false;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::global::{
        GlobalFrame, GlobalFrameHeader, GlobalProposal, MessageBundle,
    };

    /// Minimal in-memory ClockStore stub providing the two methods the
    /// checker actually calls (`get_global_clock_frame`,
    /// `get_global_clock_frame_candidate`). Other methods return NotFound.
    struct InMemoryGlobalStore {
        sealed: std::collections::HashMap<u64, GlobalFrame>,
        candidates: std::collections::HashMap<(u64, Vec<u8>), GlobalFrame>,
    }

    impl InMemoryGlobalStore {
        fn new() -> Self {
            Self {
                sealed: std::collections::HashMap::new(),
                candidates: std::collections::HashMap::new(),
            }
        }

        fn add_sealed(&mut self, frame: GlobalFrame) {
            let n = frame.header.as_ref().unwrap().frame_number;
            self.sealed.insert(n, frame);
        }

        fn add_candidate(&mut self, frame: GlobalFrame) {
            let header = frame.header.as_ref().unwrap();
            let key = (header.frame_number, global_frame_identity(&frame));
            self.candidates.insert(key, frame);
        }
    }

    fn make_frame(frame_number: u64, output: Vec<u8>, parent_selector: Vec<u8>) -> GlobalFrame {
        GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number,
                rank: 0,
                timestamp: 0,
                difficulty: 0,
                output,
                parent_selector,
                global_commitments: Vec::new(),
                prover_tree_commitment: Vec::new(),
                requests_root: Vec::new(),
                prover: Vec::new(),
                public_key_signature_bls48581: None,
            }),
            requests: Vec::<MessageBundle>::new(),
        }
    }

    fn make_proposal(header: GlobalFrameHeader) -> GlobalProposal {
        GlobalProposal {
            state: Some(GlobalFrame {
                header: Some(header),
                requests: Vec::<MessageBundle>::new(),
            }),
            parent_quorum_certificate: None,
            prior_rank_timeout_certificate: None,
            vote: None,
        }
    }

    impl ClockStore for InMemoryGlobalStore {
        fn new_transaction(&self, _: bool) -> quil_types::error::Result<Box<dyn quil_types::store::Transaction>> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_latest_global_clock_frame(&self) -> quil_types::error::Result<GlobalFrame> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_earliest_global_clock_frame(&self) -> quil_types::error::Result<GlobalFrame> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_global_clock_frame(&self, n: u64) -> quil_types::error::Result<GlobalFrame> {
            self.sealed
                .get(&n)
                .cloned()
                .ok_or_else(|| QuilError::NotFound(format!("sealed {}", n)))
        }
        fn put_global_clock_frame(&self, _: &GlobalFrame, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn put_global_clock_frame_candidate(&self, _: &GlobalFrame, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn get_global_clock_frame_candidate(&self, n: u64, sel: &[u8]) -> quil_types::error::Result<GlobalFrame> {
            self.candidates
                .get(&(n, sel.to_vec()))
                .cloned()
                .ok_or_else(|| QuilError::NotFound(format!("candidate {}", n)))
        }
        fn delete_global_clock_frame_range(&self, _: u64, _: u64) -> quil_types::error::Result<()> { Ok(()) }
        fn reset_global_clock_frames(&self) -> quil_types::error::Result<()> { Ok(()) }
        fn get_latest_certified_global_state(&self) -> quil_types::error::Result<GlobalProposal> { Err(QuilError::NotFound("stub".into())) }
        fn get_earliest_certified_global_state(&self) -> quil_types::error::Result<GlobalProposal> { Err(QuilError::NotFound("stub".into())) }
        fn get_certified_global_state(&self, _: u64) -> quil_types::error::Result<GlobalProposal> { Err(QuilError::NotFound("stub".into())) }
        fn put_certified_global_state(&self, _: &GlobalProposal, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn get_latest_quorum_certificate(&self, _: &[u8]) -> quil_types::error::Result<quil_types::proto::global::QuorumCertificate> { Err(QuilError::NotFound("stub".into())) }
        fn get_quorum_certificate(&self, _: &[u8], _: u64) -> quil_types::error::Result<quil_types::proto::global::QuorumCertificate> { Err(QuilError::NotFound("stub".into())) }
        fn put_quorum_certificate(&self, _: &quil_types::proto::global::QuorumCertificate, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn get_latest_timeout_certificate(&self, _: &[u8]) -> quil_types::error::Result<quil_types::proto::global::TimeoutCertificate> { Err(QuilError::NotFound("stub".into())) }
        fn get_timeout_certificate(&self, _: &[u8], _: u64) -> quil_types::error::Result<quil_types::proto::global::TimeoutCertificate> { Err(QuilError::NotFound("stub".into())) }
        fn put_timeout_certificate(&self, _: &quil_types::proto::global::TimeoutCertificate, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn get_latest_shard_clock_frame(&self, _: &[u8]) -> quil_types::error::Result<quil_types::proto::global::AppShardFrame> { Err(QuilError::NotFound("stub".into())) }
        fn get_shard_clock_frame(&self, _: &[u8], _: u64, _: bool) -> quil_types::error::Result<quil_types::proto::global::AppShardFrame> { Err(QuilError::NotFound("stub".into())) }
        fn commit_shard_clock_frame(&self, _: &[u8], _: u64, _: &[u8], _: &dyn quil_types::store::Transaction, _: bool) -> quil_types::error::Result<()> { Ok(()) }
        fn stage_shard_clock_frame(&self, _: &[u8], _: &quil_types::proto::global::AppShardFrame, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn get_staged_shard_clock_frame(&self, _: &[u8], _: u64, _: &[u8], _: bool) -> quil_types::error::Result<quil_types::proto::global::AppShardFrame> { Err(QuilError::NotFound("stub".into())) }
        fn set_latest_shard_clock_frame_number(&self, _: &[u8], _: u64) -> quil_types::error::Result<()> { Ok(()) }
        fn delete_shard_clock_frame_range(&self, _: &[u8], _: u64, _: u64) -> quil_types::error::Result<()> { Ok(()) }
        fn reset_shard_clock_frames(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
        fn get_latest_certified_app_shard_state(&self, _: &[u8]) -> quil_types::error::Result<quil_types::proto::global::AppShardProposal> { Err(QuilError::NotFound("stub".into())) }
        fn put_certified_app_shard_state(&self, _: &quil_types::proto::global::AppShardProposal, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn put_proposal_vote(&self, _: &dyn quil_types::store::Transaction, _: &quil_types::proto::global::ProposalVote) -> quil_types::error::Result<()> { Ok(()) }
        fn get_proposal_vote(&self, _: &[u8], _: u64, _: &[u8]) -> quil_types::error::Result<quil_types::proto::global::ProposalVote> { Err(QuilError::NotFound("stub".into())) }
        fn get_proposal_votes(&self, _: &[u8], _: u64) -> quil_types::error::Result<Vec<quil_types::proto::global::ProposalVote>> { Ok(vec![]) }
        fn put_timeout_vote(&self, _: &dyn quil_types::store::Transaction, _: &quil_types::proto::global::TimeoutState) -> quil_types::error::Result<()> { Ok(()) }
        fn get_timeout_vote(&self, _: &[u8], _: u64, _: &[u8]) -> quil_types::error::Result<quil_types::proto::global::TimeoutState> { Err(QuilError::NotFound("stub".into())) }
        fn get_timeout_votes(&self, _: &[u8], _: u64) -> quil_types::error::Result<Vec<quil_types::proto::global::TimeoutState>> { Ok(vec![]) }
        fn get_total_distance(&self, _: &[u8], _: u64, _: &[u8]) -> quil_types::error::Result<num_bigint::BigInt> { Err(QuilError::NotFound("stub".into())) }
        fn set_total_distance(&self, _: &[u8], _: u64, _: &[u8], _: &num_bigint::BigInt) -> quil_types::error::Result<()> { Ok(()) }
        fn get_peer_seniority_map(&self, _: &[u8]) -> quil_types::error::Result<std::collections::HashMap<String, u64>> { Ok(std::collections::HashMap::new()) }
        fn put_peer_seniority_map(&self, _: &dyn quil_types::store::Transaction, _: &[u8], _: &std::collections::HashMap<String, u64>) -> quil_types::error::Result<()> { Ok(()) }
        fn compact_data(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
    }

    fn output_for_n(n: u64) -> Vec<u8> {
        // 516-byte VDF output stub; only the bytes feed Poseidon so any
        // distinct content suffices.
        let mut v = vec![0u8; 516];
        v[..8].copy_from_slice(&n.to_be_bytes());
        v
    }

    #[test]
    fn proposal_with_no_state_returns_false() {
        let store = InMemoryGlobalStore::new();
        let prop = GlobalProposal { state: None, parent_quorum_certificate: None, prior_rank_timeout_certificate: None, vote: None };
        assert!(!can_process_sequential_chain_proposal(&store, &prop, None));
    }

    #[test]
    fn proposal_for_genesis_frame_returns_false() {
        let store = InMemoryGlobalStore::new();
        let mut h = GlobalFrameHeader::default();
        h.frame_number = 0;
        h.parent_selector = vec![0xAAu8; 32];
        let prop = make_proposal(h);
        assert!(!can_process_sequential_chain_proposal(&store, &prop, None));
    }

    #[test]
    fn empty_parent_selector_returns_false() {
        let store = InMemoryGlobalStore::new();
        let mut h = GlobalFrameHeader::default();
        h.frame_number = 5;
        h.parent_selector = Vec::new();
        let prop = make_proposal(h);
        assert!(!can_process_sequential_chain_proposal(&store, &prop, None));
    }

    #[test]
    fn proposal_links_to_sealed_frame() {
        let mut store = InMemoryGlobalStore::new();
        let parent = make_frame(10, output_for_n(10), vec![0u8; 32]);
        let parent_id = global_frame_identity(&parent);
        store.add_sealed(parent);

        let mut h = GlobalFrameHeader::default();
        h.frame_number = 11;
        h.parent_selector = parent_id;
        let prop = make_proposal(h);

        assert!(can_process_sequential_chain_proposal(&store, &prop, None));
    }

    #[test]
    fn proposal_walks_through_candidate_to_sealed() {
        let mut store = InMemoryGlobalStore::new();
        // Sealed frame at 9.
        let frame_9 = make_frame(9, output_for_n(9), vec![0u8; 32]);
        let id_9 = global_frame_identity(&frame_9);
        store.add_sealed(frame_9);
        // Candidate at 10 whose parent_selector points at frame_9's identity.
        let cand_10 = make_frame(10, output_for_n(10), id_9);
        let id_10 = global_frame_identity(&cand_10);
        store.add_candidate(cand_10);

        // Proposal at 11 whose parent points at the candidate.
        let mut h = GlobalFrameHeader::default();
        h.frame_number = 11;
        h.parent_selector = id_10;
        let prop = make_proposal(h);

        assert!(can_process_sequential_chain_proposal(&store, &prop, None));
    }

    #[test]
    fn proposal_links_to_finalized_state() {
        let store = InMemoryGlobalStore::new();
        let finalized_id: Identity = vec![0xAAu8; 32];

        let mut h = GlobalFrameHeader::default();
        h.frame_number = 5;
        h.parent_selector = finalized_id.clone();
        let prop = make_proposal(h);

        assert!(can_process_sequential_chain_proposal(
            &store,
            &prop,
            Some((4, &finalized_id)),
        ));
    }

    #[test]
    fn unresolvable_parent_returns_false() {
        let store = InMemoryGlobalStore::new();
        let mut h = GlobalFrameHeader::default();
        h.frame_number = 5;
        h.parent_selector = vec![0xFFu8; 32];
        let prop = make_proposal(h);
        assert!(!can_process_sequential_chain_proposal(&store, &prop, None));
    }
}
