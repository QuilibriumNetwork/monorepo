//! Concrete consensus state type for app shard chains.
//!
//! - `AppShardState` — wraps an AppShardFrameHeader, implements `Unique`.
//!
//! The legacy HotStuff vote/QC/TC types and genesis-bootstrap helpers have
//! been removed in favour of the commonware-simplex ("CW") path.

use std::fmt;

use quil_consensus::models::{Identity, Unique};

// =====================================================================
// AppShardState — unique identity for a shard frame
// =====================================================================

/// App shard chain state = an app shard frame header. The "unique
/// identity" is hex(SHA3-256(output)), matching Go's `getIdentifier`
/// on `AppShardFrame`.
#[derive(Clone)]
pub struct AppShardState {
    pub filter: Vec<u8>,
    pub frame_number: u64,
    pub rank: u64,
    pub timestamp: i64,
    pub difficulty: u32,
    pub output: Vec<u8>,
    pub parent_selector: Vec<u8>,
    pub prover: Vec<u8>,
    pub requests_root: Vec<u8>,
    pub state_roots: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
    pub fee_multiplier: u64,
    /// Committee digest over the per-member proof-of-storage openings (header
    /// field 13). Carried so the proto header round-trips losslessly and the
    /// re-derived VDF challenge matches the signed one.
    pub storage_attestation_root: Vec<u8>,
    /// The global frame whose VDF output anchors the storage beacon (field 14).
    pub global_frame_number: u64,
    /// Cached identity (sha3-256 of output, raw bytes).
    identity_cache: Identity,
}

impl AppShardState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        filter: Vec<u8>,
        frame_number: u64,
        rank: u64,
        timestamp: i64,
        difficulty: u32,
        output: Vec<u8>,
        parent_selector: Vec<u8>,
        prover: Vec<u8>,
        requests_root: Vec<u8>,
        state_roots: Vec<Vec<u8>>,
        signature: Vec<u8>,
        fee_multiplier: u64,
        storage_attestation_root: Vec<u8>,
        global_frame_number: u64,
    ) -> Self {
        let identity_cache = compute_output_identity(&output);
        Self {
            filter,
            frame_number,
            rank,
            timestamp,
            difficulty,
            output,
            parent_selector,
            prover,
            requests_root,
            state_roots,
            signature,
            fee_multiplier,
            storage_attestation_root,
            global_frame_number,
            identity_cache,
        }
    }

    /// Create from a proto FrameHeader (used by both global and app shard frames).
    pub fn from_header(
        header: &quil_types::proto::global::FrameHeader,
        filter: &[u8],
    ) -> Self {
        let identity_cache = compute_output_identity(&header.output);
        Self {
            filter: filter.to_vec(),
            frame_number: header.frame_number,
            rank: header.rank,
            timestamp: header.timestamp,
            difficulty: header.difficulty,
            output: header.output.clone(),
            parent_selector: header.parent_selector.clone(),
            prover: header.prover.clone(),
            requests_root: header.requests_root.clone(),
            state_roots: header.state_roots.clone(),
            signature: header
                .public_key_signature_bls48581
                .as_ref()
                .map(|s| s.signature.clone())
                .unwrap_or_default(),
            fee_multiplier: header.fee_multiplier_vote,
            storage_attestation_root: header.storage_attestation_root.clone(),
            global_frame_number: header.global_frame_number,
            identity_cache,
        }
    }
}

/// 32-byte Poseidon hash of a frame's `output` field — the
/// canonical identity used by `AppShardFrame` / `GlobalFrame`.
fn compute_output_identity(output: &[u8]) -> Identity {
    quil_crypto::poseidon::hash_bytes_to_32(output)
        .expect("poseidon hash of shard frame output must succeed")
        .to_vec()
}

impl fmt::Debug for AppShardState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppShardState")
            .field("filter", &hex::encode(&self.filter))
            .field("frame", &self.frame_number)
            .field("rank", &self.rank)
            .finish()
    }
}

impl Unique for AppShardState {
    fn identity(&self) -> &Identity {
        &self.identity_cache
    }

    fn rank(&self) -> u64 {
        self.rank
    }

    fn source(&self) -> &Identity {
        // The prover bytes ARE the source identity.
        &self.prover
    }

    fn timestamp(&self) -> u64 {
        self.timestamp as u64
    }

    fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_shard_state_identity_is_deterministic() {
        let s1 = AppShardState::new(
            vec![1], 10, 0, 1000, 50000,
            vec![0xAAu8; 64], vec![], vec![], vec![], vec![], vec![], 0,
            vec![], 0,
        );
        let s2 = AppShardState::new(
            vec![1], 10, 0, 1000, 50000,
            vec![0xAAu8; 64], vec![], vec![], vec![], vec![], vec![], 0,
            vec![], 0,
        );
        assert_eq!(s1.identity(), s2.identity());
        assert!(!s1.identity().is_empty());
    }

    #[test]
    fn app_shard_state_unique_trait() {
        let s = AppShardState::new(
            vec![1, 2], 42, 5, 1000, 100000,
            vec![0xBBu8; 64], vec![], vec![0xCCu8; 585], vec![], vec![],
            vec![0xDDu8; 74], 100,
            vec![], 0,
        );
        assert_eq!(s.rank(), 5);
        assert_eq!(s.timestamp(), 1000);
        assert_eq!(s.signature(), &[0xDDu8; 74][..]);
    }
}
