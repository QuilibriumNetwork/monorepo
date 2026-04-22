//! Frame chain continuity checker.
//!
//! Verifies that a sequence of shard frames in the clock store forms a
//! valid chain: each frame's `parent_selector` must match the SHA-256
//! hash of the previous frame's `output`.

use sha2::{Digest, Sha256};
use tracing::debug;

use quil_types::store::ClockStore;

/// Check whether frames `from_frame..=to_frame` exist in the store and
/// form a valid sequential chain for the given shard filter.
///
/// A chain is valid when every frame N+1's `parent_selector` equals
/// `SHA-256(frame_N.output)`. Returns `false` if any frame is missing,
/// has no header, or breaks the chain.
pub fn can_process_sequential_chain(
    store: &dyn ClockStore,
    filter: &[u8],
    from_frame: u64,
    to_frame: u64,
) -> bool {
    if from_frame > to_frame {
        return false;
    }

    let mut prev_output: Option<Vec<u8>> = None;

    for frame_number in from_frame..=to_frame {
        let frame = match store.get_shard_clock_frame(filter, frame_number, false) {
            Ok(f) => f,
            Err(_) => {
                debug!(
                    frame_number,
                    "chain check failed: frame missing from store"
                );
                return false;
            }
        };

        let header = match frame.header.as_ref() {
            Some(h) => h,
            None => {
                debug!(
                    frame_number,
                    "chain check failed: frame has no header"
                );
                return false;
            }
        };

        if let Some(ref prev) = prev_output {
            let expected_selector = Sha256::digest(prev);
            if header.parent_selector != expected_selector.as_slice() {
                debug!(
                    frame_number,
                    expected = hex::encode(&expected_selector),
                    actual = hex::encode(&header.parent_selector),
                    "chain check failed: parent_selector mismatch"
                );
                return false;
            }
        }

        prev_output = Some(header.output.clone());
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::error::Result;

    #[test]
    fn test_empty_range() {
        // from > to should return false
        assert!(!can_process_sequential_chain(
            &StubStore,
            &[0x01],
            10,
            5,
        ));
    }

    /// A minimal stub that always returns NotFound — enough to verify
    /// that the checker correctly reports a broken chain.
    struct StubStore;

    impl ClockStore for StubStore {
        fn new_transaction(
            &self,
            _indexed: bool,
        ) -> Result<Box<dyn quil_types::store::Transaction>> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_latest_global_clock_frame(
            &self,
        ) -> Result<quil_types::proto::global::GlobalFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_earliest_global_clock_frame(
            &self,
        ) -> Result<quil_types::proto::global::GlobalFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_global_clock_frame(
            &self,
            _: u64,
        ) -> Result<quil_types::proto::global::GlobalFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn put_global_clock_frame(
            &self,
            _: &quil_types::proto::global::GlobalFrame,
            _: &dyn quil_types::store::Transaction,
        ) -> Result<()> {
            Ok(())
        }
        fn put_global_clock_frame_candidate(
            &self,
            _: &quil_types::proto::global::GlobalFrame,
            _: &dyn quil_types::store::Transaction,
        ) -> Result<()> {
            Ok(())
        }
        fn get_global_clock_frame_candidate(
            &self,
            _: u64,
            _: &[u8],
        ) -> Result<quil_types::proto::global::GlobalFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn delete_global_clock_frame_range(&self, _: u64, _: u64) -> Result<()> {
            Ok(())
        }
        fn reset_global_clock_frames(&self) -> Result<()> {
            Ok(())
        }
        fn get_latest_certified_global_state(
            &self,
        ) -> Result<quil_types::proto::global::GlobalProposal> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_earliest_certified_global_state(
            &self,
        ) -> Result<quil_types::proto::global::GlobalProposal> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_certified_global_state(
            &self,
            _: u64,
        ) -> Result<quil_types::proto::global::GlobalProposal> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn put_certified_global_state(
            &self,
            _: &quil_types::proto::global::GlobalProposal,
            _: &dyn quil_types::store::Transaction,
        ) -> Result<()> {
            Ok(())
        }
        fn get_latest_quorum_certificate(
            &self,
            _: &[u8],
        ) -> Result<quil_types::proto::global::QuorumCertificate> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_quorum_certificate(
            &self,
            _: &[u8],
            _: u64,
        ) -> Result<quil_types::proto::global::QuorumCertificate> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn put_quorum_certificate(
            &self,
            _: &quil_types::proto::global::QuorumCertificate,
            _: &dyn quil_types::store::Transaction,
        ) -> Result<()> {
            Ok(())
        }
        fn get_latest_timeout_certificate(
            &self,
            _: &[u8],
        ) -> Result<quil_types::proto::global::TimeoutCertificate> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_timeout_certificate(
            &self,
            _: &[u8],
            _: u64,
        ) -> Result<quil_types::proto::global::TimeoutCertificate> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn put_timeout_certificate(
            &self,
            _: &quil_types::proto::global::TimeoutCertificate,
            _: &dyn quil_types::store::Transaction,
        ) -> Result<()> {
            Ok(())
        }
        fn get_latest_shard_clock_frame(
            &self,
            _: &[u8],
        ) -> Result<quil_types::proto::global::AppShardFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_shard_clock_frame(
            &self,
            _: &[u8],
            _: u64,
            _: bool,
        ) -> Result<quil_types::proto::global::AppShardFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn commit_shard_clock_frame(
            &self,
            _: &[u8],
            _: u64,
            _: &[u8],
            _: &dyn quil_types::store::Transaction,
            _: bool,
        ) -> Result<()> {
            Ok(())
        }
        fn stage_shard_clock_frame(
            &self,
            _: &[u8],
            _: &quil_types::proto::global::AppShardFrame,
            _: &dyn quil_types::store::Transaction,
        ) -> Result<()> {
            Ok(())
        }
        fn get_staged_shard_clock_frame(
            &self,
            _: &[u8],
            _: u64,
            _: &[u8],
            _: bool,
        ) -> Result<quil_types::proto::global::AppShardFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn set_latest_shard_clock_frame_number(
            &self,
            _: &[u8],
            _: u64,
        ) -> Result<()> {
            Ok(())
        }
        fn delete_shard_clock_frame_range(&self, _: &[u8], _: u64, _: u64) -> Result<()> {
            Ok(())
        }
        fn reset_shard_clock_frames(&self, _: &[u8]) -> Result<()> {
            Ok(())
        }
        fn get_latest_certified_app_shard_state(
            &self,
            _: &[u8],
        ) -> Result<quil_types::proto::global::AppShardProposal> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn put_certified_app_shard_state(
            &self,
            _: &quil_types::proto::global::AppShardProposal,
            _: &dyn quil_types::store::Transaction,
        ) -> Result<()> {
            Ok(())
        }
        fn put_proposal_vote(
            &self,
            _: &dyn quil_types::store::Transaction,
            _: &quil_types::proto::global::ProposalVote,
        ) -> Result<()> {
            Ok(())
        }
        fn get_proposal_vote(
            &self,
            _: &[u8],
            _: u64,
            _: &[u8],
        ) -> Result<quil_types::proto::global::ProposalVote> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_proposal_votes(
            &self,
            _: &[u8],
            _: u64,
        ) -> Result<Vec<quil_types::proto::global::ProposalVote>> {
            Ok(vec![])
        }
        fn put_timeout_vote(
            &self,
            _: &dyn quil_types::store::Transaction,
            _: &quil_types::proto::global::TimeoutState,
        ) -> Result<()> {
            Ok(())
        }
        fn get_timeout_vote(
            &self,
            _: &[u8],
            _: u64,
            _: &[u8],
        ) -> Result<quil_types::proto::global::TimeoutState> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_timeout_votes(
            &self,
            _: &[u8],
            _: u64,
        ) -> Result<Vec<quil_types::proto::global::TimeoutState>> {
            Ok(vec![])
        }
        fn get_total_distance(
            &self,
            _: &[u8],
            _: u64,
            _: &[u8],
        ) -> Result<num_bigint::BigInt> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn set_total_distance(
            &self,
            _: &[u8],
            _: u64,
            _: &[u8],
            _: &num_bigint::BigInt,
        ) -> Result<()> {
            Ok(())
        }
        fn get_peer_seniority_map(
            &self,
            _: &[u8],
        ) -> Result<std::collections::HashMap<String, u64>> {
            Ok(std::collections::HashMap::new())
        }
        fn put_peer_seniority_map(
            &self,
            _: &dyn quil_types::store::Transaction,
            _: &[u8],
            _: &std::collections::HashMap<String, u64>,
        ) -> Result<()> {
            Ok(())
        }
        fn compact_data(&self, _: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_missing_frame_returns_false() {
        assert!(!can_process_sequential_chain(&StubStore, &[0x01], 1, 3));
    }

    /// A mock store that can hold shard frames in memory for chain tests.
    struct InMemoryChainStore {
        frames: std::sync::Mutex<
            std::collections::HashMap<(Vec<u8>, u64), quil_types::proto::global::AppShardFrame>,
        >,
    }

    impl InMemoryChainStore {
        fn new() -> Self {
            Self {
                frames: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn add_frame(&self, filter: &[u8], frame_number: u64, output: Vec<u8>, parent_selector: Vec<u8>) {
            let frame = quil_types::proto::global::AppShardFrame {
                header: Some(quil_types::proto::global::FrameHeader {
                    frame_number,
                    output,
                    parent_selector,
                    address: filter.to_vec(),
                    ..Default::default()
                }),
                requests: Vec::new(),
            };
            self.frames
                .lock()
                .unwrap()
                .insert((filter.to_vec(), frame_number), frame);
        }
    }

    impl ClockStore for InMemoryChainStore {
        fn new_transaction(&self, _: bool) -> Result<Box<dyn quil_types::store::Transaction>> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_latest_global_clock_frame(&self) -> Result<quil_types::proto::global::GlobalFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_earliest_global_clock_frame(&self) -> Result<quil_types::proto::global::GlobalFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_global_clock_frame(&self, _: u64) -> Result<quil_types::proto::global::GlobalFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn put_global_clock_frame(&self, _: &quil_types::proto::global::GlobalFrame, _: &dyn quil_types::store::Transaction) -> Result<()> { Ok(()) }
        fn put_global_clock_frame_candidate(&self, _: &quil_types::proto::global::GlobalFrame, _: &dyn quil_types::store::Transaction) -> Result<()> { Ok(()) }
        fn get_global_clock_frame_candidate(&self, _: u64, _: &[u8]) -> Result<quil_types::proto::global::GlobalFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn delete_global_clock_frame_range(&self, _: u64, _: u64) -> Result<()> { Ok(()) }
        fn reset_global_clock_frames(&self) -> Result<()> { Ok(()) }
        fn get_latest_certified_global_state(&self) -> Result<quil_types::proto::global::GlobalProposal> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_earliest_certified_global_state(&self) -> Result<quil_types::proto::global::GlobalProposal> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_certified_global_state(&self, _: u64) -> Result<quil_types::proto::global::GlobalProposal> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn put_certified_global_state(&self, _: &quil_types::proto::global::GlobalProposal, _: &dyn quil_types::store::Transaction) -> Result<()> { Ok(()) }
        fn get_latest_quorum_certificate(&self, _: &[u8]) -> Result<quil_types::proto::global::QuorumCertificate> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_quorum_certificate(&self, _: &[u8], _: u64) -> Result<quil_types::proto::global::QuorumCertificate> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn put_quorum_certificate(&self, _: &quil_types::proto::global::QuorumCertificate, _: &dyn quil_types::store::Transaction) -> Result<()> { Ok(()) }
        fn get_latest_timeout_certificate(&self, _: &[u8]) -> Result<quil_types::proto::global::TimeoutCertificate> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_timeout_certificate(&self, _: &[u8], _: u64) -> Result<quil_types::proto::global::TimeoutCertificate> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn put_timeout_certificate(&self, _: &quil_types::proto::global::TimeoutCertificate, _: &dyn quil_types::store::Transaction) -> Result<()> { Ok(()) }
        fn get_latest_shard_clock_frame(&self, _: &[u8]) -> Result<quil_types::proto::global::AppShardFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_shard_clock_frame(&self, filter: &[u8], frame_number: u64, _truncate: bool) -> Result<quil_types::proto::global::AppShardFrame> {
            let guard = self.frames.lock().unwrap();
            guard
                .get(&(filter.to_vec(), frame_number))
                .cloned()
                .ok_or_else(|| quil_types::error::QuilError::NotFound("frame not found".into()))
        }
        fn commit_shard_clock_frame(&self, _: &[u8], _: u64, _: &[u8], _: &dyn quil_types::store::Transaction, _: bool) -> Result<()> { Ok(()) }
        fn stage_shard_clock_frame(&self, _: &[u8], _: &quil_types::proto::global::AppShardFrame, _: &dyn quil_types::store::Transaction) -> Result<()> { Ok(()) }
        fn get_staged_shard_clock_frame(&self, _: &[u8], _: u64, _: &[u8], _: bool) -> Result<quil_types::proto::global::AppShardFrame> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn set_latest_shard_clock_frame_number(&self, _: &[u8], _: u64) -> Result<()> { Ok(()) }
        fn delete_shard_clock_frame_range(&self, _: &[u8], _: u64, _: u64) -> Result<()> { Ok(()) }
        fn reset_shard_clock_frames(&self, _: &[u8]) -> Result<()> { Ok(()) }
        fn get_latest_certified_app_shard_state(&self, _: &[u8]) -> Result<quil_types::proto::global::AppShardProposal> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn put_certified_app_shard_state(&self, _: &quil_types::proto::global::AppShardProposal, _: &dyn quil_types::store::Transaction) -> Result<()> { Ok(()) }
        fn put_proposal_vote(&self, _: &dyn quil_types::store::Transaction, _: &quil_types::proto::global::ProposalVote) -> Result<()> { Ok(()) }
        fn get_proposal_vote(&self, _: &[u8], _: u64, _: &[u8]) -> Result<quil_types::proto::global::ProposalVote> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_proposal_votes(&self, _: &[u8], _: u64) -> Result<Vec<quil_types::proto::global::ProposalVote>> { Ok(vec![]) }
        fn put_timeout_vote(&self, _: &dyn quil_types::store::Transaction, _: &quil_types::proto::global::TimeoutState) -> Result<()> { Ok(()) }
        fn get_timeout_vote(&self, _: &[u8], _: u64, _: &[u8]) -> Result<quil_types::proto::global::TimeoutState> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn get_timeout_votes(&self, _: &[u8], _: u64) -> Result<Vec<quil_types::proto::global::TimeoutState>> { Ok(vec![]) }
        fn get_total_distance(&self, _: &[u8], _: u64, _: &[u8]) -> Result<num_bigint::BigInt> {
            Err(quil_types::error::QuilError::NotFound("stub".into()))
        }
        fn set_total_distance(&self, _: &[u8], _: u64, _: &[u8], _: &num_bigint::BigInt) -> Result<()> { Ok(()) }
        fn get_peer_seniority_map(&self, _: &[u8]) -> Result<std::collections::HashMap<String, u64>> {
            Ok(std::collections::HashMap::new())
        }
        fn put_peer_seniority_map(&self, _: &dyn quil_types::store::Transaction, _: &[u8], _: &std::collections::HashMap<String, u64>) -> Result<()> { Ok(()) }
        fn compact_data(&self, _: &[u8]) -> Result<()> { Ok(()) }
    }

    #[test]
    fn test_valid_sequential_chain() {
        let store = InMemoryChainStore::new();
        let filter = vec![0x01];

        // Build a 3-frame chain: frame 10 -> 11 -> 12
        let output_10 = vec![10u8; 32];
        let selector_11 = Sha256::digest(&output_10).to_vec();
        let output_11 = vec![11u8; 32];
        let selector_12 = Sha256::digest(&output_11).to_vec();
        let output_12 = vec![12u8; 32];

        store.add_frame(&filter, 10, output_10, vec![]); // genesis (no parent)
        store.add_frame(&filter, 11, output_11, selector_11);
        store.add_frame(&filter, 12, output_12, selector_12);

        assert!(can_process_sequential_chain(&store, &filter, 10, 12));
    }

    #[test]
    fn test_broken_chain_bad_parent_selector() {
        let store = InMemoryChainStore::new();
        let filter = vec![0x01];

        let output_10 = vec![10u8; 32];
        let output_11 = vec![11u8; 32];

        store.add_frame(&filter, 10, output_10, vec![]);
        // Frame 11 has wrong parent_selector (not SHA-256 of frame 10's output)
        store.add_frame(&filter, 11, output_11, vec![0xFF; 32]);

        assert!(!can_process_sequential_chain(&store, &filter, 10, 11));
    }

    #[test]
    fn test_single_frame_always_valid() {
        let store = InMemoryChainStore::new();
        let filter = vec![0x01];
        store.add_frame(&filter, 5, vec![5u8; 32], vec![]);

        // A single-frame range (from == to) should always be valid
        assert!(can_process_sequential_chain(&store, &filter, 5, 5));
    }

    #[test]
    fn test_missing_middle_frame() {
        let store = InMemoryChainStore::new();
        let filter = vec![0x01];

        // Add frame 10 and 12, but NOT 11
        let output_10 = vec![10u8; 32];
        let output_12 = vec![12u8; 32];
        store.add_frame(&filter, 10, output_10, vec![]);
        store.add_frame(&filter, 12, output_12, vec![0xAA; 32]);

        // Should fail because frame 11 is missing
        assert!(!can_process_sequential_chain(&store, &filter, 10, 12));
    }
}
