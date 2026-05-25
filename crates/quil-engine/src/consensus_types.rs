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
/// 32-byte big-endian Poseidon hash of the `output` field, matching
/// Go's `GlobalFrame.Identity()` at `protobufs/global.go:142-149`
/// (`poseidon.HashBytes(g.Header.Output).FillBytes(make([]byte, 32))`).
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
    /// Inbound message bundles attached to this proposal, decoded
    /// into the prost proto type used by the materializer. Populated
    /// by the leader at `prove_next_state` (canonical bytes from
    /// `MessageCollector` → `decode_message_bundle`), carried through
    /// the consensus state, embedded into the wire `GlobalFrame.requests`
    /// field by `on_own_proposal`, and reconstituted on the receiver
    /// via `wire_proposal_to_signed`. The `on_finalized_state` hook
    /// re-attaches them to the persisted frame so the materializer
    /// iterates them on finalization to apply transactions
    /// (ProverJoin/Confirm/Leave, token, compute, hypergraph).
    /// Without this, requests_root is hashed from collected messages
    /// but the wire frame ships an empty requests Vec — receivers'
    /// materializers see no work to do and the registry never
    /// updates.
    pub messages: Vec<quil_types::proto::global::MessageBundle>,
    /// Cached identity (raw 32-byte Poseidon of `output`).
    identity_cache: Vec<u8>,
    /// Cached source (raw prover bytes).
    source_cache: Vec<u8>,
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
        let source_cache = prover.clone();
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
            messages: Vec::new(),
            identity_cache,
            source_cache,
        }
    }

    /// Attach the leader's collected message bundles to this state.
    /// Called in `prove_next_state` after `MessageCollector::collect_for_rank`
    /// so the wire-encode path in `on_own_proposal` can populate
    /// `GlobalFrame.requests`.
    pub fn with_messages(
        mut self,
        messages: Vec<quil_types::proto::global::MessageBundle>,
    ) -> Self {
        self.messages = messages;
        self
    }

    /// Create from a prost GlobalFrameHeader.
    pub fn from_header(h: &quil_types::proto::global::GlobalFrameHeader) -> Self {
        let identity_cache = compute_output_identity(&h.output);
        let source_cache = h.prover.clone();
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
            messages: Vec::new(),
            identity_cache,
            source_cache,
        }
    }

    pub fn compute_identity(&self) -> Identity {
        compute_output_identity(&self.output)
    }
}

/// Compute the 32-byte big-endian Poseidon hash of a frame's `output`
/// field. Mirrors Go's `GlobalFrame.Identity()` at
/// `protobufs/global.go:142-149`. Panics on poseidon failure (an
/// empty `output` is an unrecoverable consensus invariant violation
/// that Go would also fail on).
fn compute_output_identity(output: &[u8]) -> Vec<u8> {
    quil_crypto::poseidon::hash_bytes_to_32(output)
        .expect("poseidon hash of frame output must succeed")
        .to_vec()
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
///
/// Semantics mirror Go's `protobufs/global.go::ProposalVote`:
/// - `identity` = signer/voter id (the address that produced the vote)
/// - `source` = the proposal id this vote points to (what's being voted for)
///
/// The cache and vote-collector code in `quil-consensus` keys by signer
/// (i.e. `vote.identity()`) and asserts `vote.source() == state.identifier`.
/// Swapping the two would cause the votes cache to flag every distinct
/// voter for the same proposal as a double-vote and prevent QC formation.
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
        // Match Go: identity = voter, source = proposal id.
        Self {
            identity: voter_identity,
            rank,
            source: proposal_identity,
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
    let frame_requests = frame.requests;

    // 2. Build GlobalState (identity = SHA-256(output), source = hex(prover))
    //    plus the inbound message bundles so the materializer sees
    //    them when this state is finalized.
    let state = GlobalState::from_header(&header).with_messages(frame_requests);
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
    //
    // `parent_quorum_certificate` is the QC the wire proposal carried
    // in `wire.latest_quorum_certificate`; the same Arc is cloned into
    // both the State and the wrapping Proposal so consumers reading
    // the QC off the state see the same aggregated signature the
    // proposer signed against. Mirrors Go's
    // `models.State.ParentQuorumCertificate`.
    let consensus_state = quil_consensus::models::State {
        rank: wire.vote.rank,
        identifier: identifier.clone(),
        proposer_id: wire.vote.address.clone(),
        parent_qc_identity,
        parent_qc_rank,
        parent_quorum_certificate: Some(std::sync::Arc::clone(&parent_qc)),
        timestamp: wire.vote.timestamp,
        state,
    };

    // 6. Build the proposer's self-vote — signature bytes from ProposalVote
    let vote = GlobalVote::new(
        identifier,
        wire.vote.rank,
        wire.vote.address.clone(),
        wire.vote.timestamp,
        wire.vote.signature,
        Vec::new(),
    );

    let proposal = quil_consensus::models::Proposal {
        state: consensus_state,
        parent_quorum_certificate: std::sync::Arc::clone(&parent_qc),
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
        .map(|h| h.to_vec())
        .unwrap_or_default();

    quil_consensus::models::CertifiedState {
        state: quil_consensus::models::State {
            rank: header.rank,
            identifier: identity,
            proposer_id: header.prover.clone(),
            parent_qc_identity: qc_identity.clone(),
            parent_qc_rank: header.rank.saturating_sub(1),
            // Genesis trusted-root: no parent QC trait object
            // available (the seeded genesis QC is constructed separately
            // and threaded through `genesis_qc_override`).
            parent_quorum_certificate: None,
            timestamp: header.timestamp as u64,
            state,
        },
        certifying_qc_identity: qc_identity,
        certifying_qc_rank: header.rank,
        certifying_quorum_certificate: None,
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
            prover: vec![0xCCu8; 32],
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
            b"proposal-hash".to_vec(),
            3,
            b"voter-id".to_vec(),
            5000,
            vec![0xAAu8; 74],
            vec![0x01],
        );
        // `identity` = voter, `source` = proposal id — matches Go.
        assert_eq!(vote.identity().as_slice(), b"voter-id");
        assert_eq!(vote.rank(), 3);
        assert_eq!(vote.source().as_slice(), b"proposal-hash");
        assert_eq!(vote.timestamp(), 5000);
        assert_eq!(vote.signature(), &[0xAAu8; 74][..]);
    }
}
