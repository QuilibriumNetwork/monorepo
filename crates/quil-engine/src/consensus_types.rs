//! Concrete consensus type instantiations for the global chain.
//!
//! The generic consensus protocol in quil-consensus uses
//! `<S: Unique, V: Unique>` type parameters. This module provides
//! the concrete implementations:
//!
//! - `GlobalState` — wraps `GlobalFrameHeader` proto, implements `Unique`
//! - `GlobalVote` — a BLS signature over a proposal hash
//!
//! These types allow instantiating `EventLoop<GlobalState, GlobalVote>`
//! for the global consensus engine.

use std::fmt;

use quil_consensus::models::{Identity, Unique};

/// Global chain state = a frame header. The "unique identity" is the
/// hex-encoded SHA3-256 of the output field, matching Go's
/// `getIdentifier` on `GlobalFrame`.
#[derive(Clone)]
pub struct GlobalState {
    pub frame_number: u64,
    pub rank: u64,
    pub timestamp: i64,
    pub difficulty: u32,
    pub output: Vec<u8>,
    pub parent_selector: Vec<u8>,
    pub prover: Vec<u8>,
    pub prover_tree_commitment: Vec<u8>,
    pub requests_root: Vec<u8>,
    pub signature: Vec<u8>,
    /// Cached identity (hex of SHA-256 of output). Avoids re-hashing on every call.
    identity_cache: String,
    /// Cached source (hex-encoded prover address). Avoids re-encoding on every call.
    source_cache: String,
}

impl GlobalState {
    /// Construct a new `GlobalState`, computing the identity and source caches.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        frame_number: u64,
        rank: u64,
        timestamp: i64,
        difficulty: u32,
        output: Vec<u8>,
        parent_selector: Vec<u8>,
        prover: Vec<u8>,
        prover_tree_commitment: Vec<u8>,
        requests_root: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        let identity_cache = compute_output_identity(&output);
        let source_cache = hex::encode(&prover);
        Self {
            frame_number,
            rank,
            timestamp,
            difficulty,
            output,
            parent_selector,
            prover,
            prover_tree_commitment,
            requests_root,
            signature,
            identity_cache,
            source_cache,
        }
    }

    /// Create from a prost GlobalFrameHeader.
    pub fn from_header(h: &quil_types::proto::global::GlobalFrameHeader) -> Self {
        let identity_cache = compute_output_identity(&h.output);
        let source_cache = hex::encode(&h.prover);
        Self {
            frame_number: h.frame_number,
            rank: h.rank,
            timestamp: h.timestamp,
            difficulty: h.difficulty,
            output: h.output.clone(),
            parent_selector: h.parent_selector.clone(),
            prover: h.prover.clone(),
            prover_tree_commitment: h.prover_tree_commitment.clone(),
            requests_root: h.requests_root.clone(),
            signature: h
                .public_key_signature_bls48581
                .as_ref()
                .map(|s| s.signature.clone())
                .unwrap_or_default(),
            identity_cache,
            source_cache,
        }
    }

    pub fn compute_identity(&self) -> Identity {
        compute_output_identity(&self.output)
    }
}

fn compute_output_identity(output: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(output))
}

impl fmt::Debug for GlobalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GlobalState")
            .field("frame", &self.frame_number)
            .field("rank", &self.rank)
            .finish()
    }
}

impl Unique for GlobalState {
    fn identity(&self) -> &Identity {
        &self.identity_cache
    }

    fn rank(&self) -> u64 {
        self.rank
    }

    fn source(&self) -> &Identity {
        &self.source_cache
    }

    fn timestamp(&self) -> u64 {
        self.timestamp as u64
    }

    fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Global chain vote = a BLS48-581 aggregate signature over a proposal.
#[derive(Clone)]
pub struct GlobalVote {
    identity: Identity,
    rank: u64,
    source: Identity,
    timestamp: u64,
    pub signature_bytes: Vec<u8>,
    pub bitmask: Vec<u8>,
}

impl GlobalVote {
    pub fn new(
        proposal_identity: Identity,
        rank: u64,
        voter_identity: Identity,
        timestamp: u64,
        signature: Vec<u8>,
        bitmask: Vec<u8>,
    ) -> Self {
        Self {
            identity: proposal_identity,
            rank,
            source: voter_identity,
            timestamp,
            signature_bytes: signature,
            bitmask,
        }
    }
}

impl fmt::Debug for GlobalVote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GlobalVote")
            .field("rank", &self.rank)
            .field("source", &self.source)
            .finish()
    }
}

impl Unique for GlobalVote {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn rank(&self) -> u64 {
        self.rank
    }

    fn source(&self) -> &Identity {
        &self.source
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }

    fn signature(&self) -> &[u8] {
        &self.signature_bytes
    }
}

/// Type alias for the global consensus event loop handle.
pub type GlobalEventLoopHandle =
    quil_consensus::event_loop::EventLoopHandle<GlobalState, GlobalVote>;

/// Bridge an inbound wire `GlobalProposal` into the typed `SignedProposal`
/// the consensus event loop accepts.
///
/// Port of the decode half of `global_consensus_engine.go:handleGlobalProposal`.
/// Splits the wire record's embedded QC/TC out (they should be submitted
/// separately via `handle.submit_quorum_certificate` /
/// `handle.submit_timeout_certificate`).
pub fn wire_proposal_to_signed(
    wire: crate::consensus_wire::GlobalProposal,
) -> quil_types::error::Result<(
    quil_consensus::models::SignedProposal<GlobalState, GlobalVote>,
    std::sync::Arc<dyn quil_consensus::models::QuorumCertificate>,
    Option<std::sync::Arc<dyn quil_consensus::models::TimeoutCertificate>>,
)> {
    // 1. Decode the embedded frame bytes → GlobalFrameHeader proto
    let frame = crate::consensus_wire::decode_global_frame(&wire.state)?;
    let header = frame.header.ok_or_else(|| {
        quil_types::error::QuilError::InvalidArgument(
            "GlobalProposal: embedded frame missing header".into(),
        )
    })?;

    // 2. Build GlobalState (identity = SHA-256(output), source = hex(prover))
    let state = GlobalState::from_header(&header);
    let identifier = state.compute_identity();

    // 3. Convert the wire QC to a trait object — the event loop accepts it
    //    both as the proposal's parent QC and (separately) via submit_qc().
    let parent_qc: std::sync::Arc<dyn quil_consensus::models::QuorumCertificate> =
        wire.parent_quorum_certificate.clone().into_trait_object();
    let parent_qc_identity = parent_qc.identity().clone();
    let parent_qc_rank = parent_qc.rank();

    // 4. Optional prior-rank TC
    let prior_tc: Option<std::sync::Arc<dyn quil_consensus::models::TimeoutCertificate>> =
        wire.prior_rank_timeout_certificate.clone().map(|tc| tc.into_trait_object());

    // 5. Build the State<GlobalState>
    let consensus_state = quil_consensus::models::State {
        rank: wire.vote.rank,
        identifier: identifier.clone(),
        proposer_id: hex::encode(&wire.vote.address),
        parent_qc_identity,
        parent_qc_rank,
        timestamp: wire.vote.timestamp,
        state,
    };

    // 6. Build the proposer's self-vote — signature bytes from ProposalVote
    let vote = GlobalVote::new(
        identifier,
        wire.vote.rank,
        hex::encode(&wire.vote.address),
        wire.vote.timestamp,
        wire.vote.signature,
        Vec::new(),
    );

    let proposal = quil_consensus::models::Proposal {
        state: consensus_state,
        previous_rank_timeout_certificate: prior_tc.clone(),
    };
    let signed = quil_consensus::models::SignedProposal { proposal, vote };

    Ok((signed, parent_qc, prior_tc))
}

/// Build a genesis `CertifiedState` for bootstrapping the consensus event loop.
/// Takes the latest stored frame and produces the trusted root state.
pub fn build_genesis_certified_state(
    frame: &quil_types::proto::global::GlobalFrame,
) -> quil_consensus::models::CertifiedState<GlobalState> {
    let header = frame.header.as_ref().expect("frame must have header");
    let state = GlobalState::from_header(header);
    let identity = state.compute_identity();

    // Genesis QC identity = Poseidon(output)
    let qc_identity = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
        .map(|h| hex::encode(h))
        .unwrap_or_default();

    quil_consensus::models::CertifiedState {
        state: quil_consensus::models::State {
            rank: header.rank,
            identifier: identity,
            proposer_id: hex::encode(&header.prover),
            parent_qc_identity: qc_identity.clone(),
            parent_qc_rank: header.rank.saturating_sub(1),
            timestamp: header.timestamp as u64,
            state,
        },
        certifying_qc_identity: qc_identity,
        certifying_qc_rank: header.rank,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_state_from_header() {
        let h = quil_types::proto::global::GlobalFrameHeader {
            frame_number: 100,
            rank: 0,
            timestamp: 1234567890,
            difficulty: 50000,
            output: vec![0xAAu8; 516],
            parent_selector: vec![0xBBu8; 32],
            prover: vec![0xCCu8; 585],
            prover_tree_commitment: vec![0xDDu8; 64],
            requests_root: vec![0xEEu8; 64],
            ..Default::default()
        };
        let state = GlobalState::from_header(&h);
        assert_eq!(state.frame_number, 100);
        assert_eq!(state.rank, 0);
        assert_eq!(state.difficulty, 50000);
    }

    #[test]
    fn global_state_unique_trait() {
        let state = GlobalState::new(
            42, 5, 1000, 100000,
            vec![0xAAu8; 64],
            vec![],
            vec![0xBBu8; 585],
            vec![],
            vec![],
            vec![0xCCu8; 74],
        );
        assert_eq!(state.rank(), 5);
        assert_eq!(state.timestamp(), 1000);
        assert_eq!(state.signature(), &[0xCCu8; 74][..]);
        assert!(!state.identity().is_empty());
    }

    #[test]
    fn global_state_identity_is_deterministic() {
        let state = GlobalState::new(
            1, 0, 0, 0,
            vec![1, 2, 3],
            vec![], vec![], vec![], vec![], vec![],
        );
        let id1 = state.compute_identity();
        let id2 = state.compute_identity();
        assert_eq!(id1, id2);
    }

    #[test]
    fn global_vote_unique_trait() {
        let vote = GlobalVote::new(
            "proposal-hash".into(),
            3,
            "voter-id".into(),
            5000,
            vec![0xAAu8; 74],
            vec![0x01],
        );
        assert_eq!(vote.identity(), "proposal-hash");
        assert_eq!(vote.rank(), 3);
        assert_eq!(vote.source(), "voter-id");
        assert_eq!(vote.timestamp(), 5000);
        assert_eq!(vote.signature(), &[0xAAu8; 74][..]);
    }
}
