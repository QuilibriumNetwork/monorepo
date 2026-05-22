//! Concrete consensus type instantiations for app shard chains.
//!
//! Mirrors `consensus_types.rs` (GlobalState/GlobalVote) but for the
//! per-shard HotStuff consensus. Each app shard runs its own
//! `EventLoop<AppShardState, AppShardVote>`.
//!
//! - `AppShardState` — wraps an AppShardFrameHeader, implements `Unique`
//! - `AppShardVote` — a BLS signature over a shard proposal hash

use std::fmt;
use std::sync::Arc;

use quil_consensus::models::{
    AggregatedSignature, CertifiedState, Identity, QuorumCertificate,
    State, TimeoutCertificate, Unique,
};
use quil_consensus::signature_aggregator::TimeoutSignerInfo;
use quil_types::error::Result;

use crate::voting_provider::VotingProviderFactory;

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
    /// Cached identity (sha3-256 of output, raw bytes).
    identity_cache: Identity,
}

impl AppShardState {
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

// =====================================================================
// AppShardVote — BLS signature over a shard proposal
// =====================================================================

/// App shard vote = a BLS48-581 signature over a shard proposal hash.
/// Mirrors ProposalVote on the wire but typed for the consensus layer.
#[derive(Clone)]
pub struct AppShardVote {
    /// Identity of the state being voted on.
    identity: Identity,
    rank: u64,
    /// Voter's identity (hex-encoded prover address).
    source: Identity,
    timestamp: u64,
    pub signature_bytes: Vec<u8>,
    pub bitmask: Vec<u8>,
    /// Filter of the shard this vote belongs to.
    pub filter: Vec<u8>,
    /// 516-byte per-voter VDF multi-proof contribution (PoMW). Empty
    /// for the single-participant aggregate path. The aggregator
    /// collects these from each vote in committee order and packs
    /// them past the BLS aggregate signature in the final wire blob:
    /// `bls_agg(74) || u32(count) || concat(multi_proofs)`. Verifiers
    /// re-derive the challenge as `sha3(parent_selector)` and check
    /// each multi-proof via `verify_multi_proof`.
    pub multi_proof: Vec<u8>,
}

impl AppShardVote {
    pub fn new(
        proposal_identity: Identity,
        rank: u64,
        voter_identity: Identity,
        timestamp: u64,
        signature: Vec<u8>,
        bitmask: Vec<u8>,
        filter: Vec<u8>,
    ) -> Self {
        // `identity` = voter, `source` = proposal id —
        // `VoteCollector::process_cached_votes` filters cached
        // entries by `source() == state.identifier`, so swapping
        // these would drop every leader self-vote.
        Self {
            identity: voter_identity,
            rank,
            source: proposal_identity,
            timestamp,
            signature_bytes: signature,
            bitmask,
            filter,
            multi_proof: Vec::new(),
        }
    }

    /// Attach a 516-byte VDF multi-proof contribution. Used by the
    /// voter to include their per-voter PoMW share alongside the BLS
    /// vote signature, which the aggregator concatenates into the
    /// final FrameHeader signature blob.
    pub fn with_multi_proof(mut self, multi_proof: Vec<u8>) -> Self {
        self.multi_proof = multi_proof;
        self
    }
}

impl fmt::Debug for AppShardVote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppShardVote")
            .field("rank", &self.rank)
            .field("source", &self.source)
            .finish()
    }
}

impl Unique for AppShardVote {
    fn identity(&self) -> &Identity { &self.identity }
    fn rank(&self) -> u64 { self.rank }
    fn source(&self) -> &Identity { &self.source }
    fn timestamp(&self) -> u64 { self.timestamp }
    fn signature(&self) -> &[u8] { &self.signature_bytes }
    fn aux(&self) -> &[u8] { &self.multi_proof }
}

// =====================================================================
// Type aliases
// =====================================================================

/// Type alias for the app shard consensus event loop handle.
pub type AppEventLoopHandle =
    quil_consensus::event_loop::EventLoopHandle<AppShardState, AppShardVote>;

// =====================================================================
// AppShardVoteFactory — builds votes, QCs, TCs for app shards
// =====================================================================

/// Factory for building concrete app shard consensus artifacts.
pub struct AppShardVoteFactory {
    pub filter: Vec<u8>,
}

impl VotingProviderFactory<AppShardState, AppShardVote> for AppShardVoteFactory {
    fn make_vote(
        &self,
        state_rank: u64,
        state_id: &Identity,
        signature: Vec<u8>,
        voter_address: &[u8],
    ) -> Result<AppShardVote> {
        Ok(AppShardVote::new(
            state_id.clone(),
            state_rank,
            voter_address.to_vec(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            signature,
            Vec::new(),
            self.filter.clone(),
        ))
    }

    fn make_vote_with_aux(
        &self,
        state_rank: u64,
        state_id: &Identity,
        signature: Vec<u8>,
        voter_address: &[u8],
        aux: Vec<u8>,
    ) -> Result<AppShardVote> {
        let vote = self.make_vote(state_rank, state_id, signature, voter_address)?;
        Ok(if aux.is_empty() { vote } else { vote.with_multi_proof(aux) })
    }

    fn make_timeout_vote(
        &self,
        rank: u64,
        newest_qc_rank: u64,
        signature: Vec<u8>,
        voter_address: &[u8],
    ) -> Result<AppShardVote> {
        Ok(AppShardVote::new(
            format!("timeout-{}-{}", rank, newest_qc_rank).into_bytes(),
            rank,
            voter_address.to_vec(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            signature,
            Vec::new(),
            self.filter.clone(),
        ))
    }

    fn make_quorum_certificate(
        &self,
        state: &State<AppShardState>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn QuorumCertificate>> {
        Ok(Arc::new(AppShardQC {
            filter: self.filter.clone(),
            rank: state.rank,
            frame_number: state.state.frame_number,
            identity: state.identifier.clone(),
            timestamp: state.timestamp,
            agg_sig: aggregated_sig,
        }))
    }

    fn make_timeout_certificate(
        &self,
        rank: u64,
        newest_qc: Arc<dyn QuorumCertificate>,
        signers: Vec<TimeoutSignerInfo>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn TimeoutCertificate>> {
        let latest_ranks: Vec<u64> = signers.iter().map(|s| s.newest_qc_rank).collect();
        Ok(Arc::new(AppShardTC {
            filter: self.filter.clone(),
            rank,
            latest_ranks,
            latest_qc: newest_qc,
            agg_sig: aggregated_sig,
        }))
    }
}

// =====================================================================
// Concrete QC / TC types for app shards
// =====================================================================

#[derive(Debug)]
struct AppShardQC {
    filter: Vec<u8>,
    rank: u64,
    frame_number: u64,
    identity: Identity,
    timestamp: u64,
    agg_sig: Arc<dyn AggregatedSignature>,
}

impl QuorumCertificate for AppShardQC {
    fn filter(&self) -> &[u8] { &self.filter }
    fn rank(&self) -> u64 { self.rank }
    fn frame_number(&self) -> u64 { self.frame_number }
    fn identity(&self) -> &Identity { &self.identity }
    fn timestamp(&self) -> u64 { self.timestamp }
    fn aggregated_signature(&self) -> &dyn AggregatedSignature { self.agg_sig.as_ref() }
    fn equals(&self, other: &dyn QuorumCertificate) -> bool {
        self.rank == other.rank() && self.identity == *other.identity()
    }
}

#[derive(Debug)]
struct AppShardTC {
    filter: Vec<u8>,
    rank: u64,
    latest_ranks: Vec<u64>,
    latest_qc: Arc<dyn QuorumCertificate>,
    agg_sig: Arc<dyn AggregatedSignature>,
}

impl TimeoutCertificate for AppShardTC {
    fn filter(&self) -> &[u8] { &self.filter }
    fn rank(&self) -> u64 { self.rank }
    fn latest_ranks(&self) -> &[u64] { &self.latest_ranks }
    fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { self.latest_qc.as_ref() }
    fn aggregated_signature(&self) -> &dyn AggregatedSignature { self.agg_sig.as_ref() }
    fn equals(&self, other: &dyn TimeoutCertificate) -> bool {
        self.rank == other.rank()
    }
}

// =====================================================================
// Genesis certified state builder for app shards
// =====================================================================

/// Build a genesis `CertifiedState<AppShardState>` for bootstrapping
/// a shard's consensus event loop. `rank` is the rank of the QC
/// certifying this state — 0 for a fresh shard, otherwise the rank
/// of the latest finalized shard frame on resume.
pub fn build_app_genesis_certified_state(
    filter: &[u8],
    frame_number: u64,
    output: &[u8],
    rank: u64,
) -> CertifiedState<AppShardState> {
    let state = AppShardState::new(
        filter.to_vec(),
        frame_number,
        rank,
        0,       // timestamp
        50000,   // default difficulty
        output.to_vec(),
        vec![0u8; 32],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        0,
    );
    let identity = state.identity_cache.clone();

    CertifiedState {
        state: State {
            rank,
            identifier: identity.clone(),
            proposer_id: Vec::new(),
            parent_qc_identity: identity.clone(),
            parent_qc_rank: rank,
            // Genesis has no parent QC.
            parent_quorum_certificate: None,
            timestamp: 0,
            state,
        },
        certifying_qc_identity: identity,
        certifying_qc_rank: rank,
        // Genesis CertifiedState — bootstrap trusted-root pattern.
        // No real aggregated signature; populated by `genesis_qc_override`
        // path when callers want a real QC trait object.
        certifying_quorum_certificate: None,
    }
}

// =====================================================================
// Genesis QC for app shards (needed by ConsensusStore bootstrap)
// =====================================================================

/// A minimal genesis QC for app shard consensus bootstrapping.
///
/// The QC's `identity` MUST equal the genesis `AppShardState`'s
/// identity (`compute_output_identity(state.output)` =
/// `Sha256(output)`). Otherwise the event handler's parent-state
/// lookup at `event_handler.rs:469` (`forks.get_state(qc.identity())`)
/// returns `None`, the leader silently skips proposing, and the shard
/// just times out forever at rank 1.
#[derive(Debug)]
pub struct AppGenesisQC {
    pub filter: Vec<u8>,
    pub identity: Identity,
    pub rank: u64,
}

impl AppGenesisQC {
    /// Build a genesis QC whose identity matches the genesis
    /// `AppShardState` produced from the given output bytes. Pass the
    /// same `output` you handed to `build_app_genesis_certified_state`.
    /// For a fresh shard this is rank 0; on resume this is the rank
    /// of the trusted root (the latest finalized shard frame), so the
    /// event handler's `current_rank == qc.rank + 1` happy path is
    /// satisfied without demanding a `prior_rank_tc` to bridge a gap.
    pub fn for_output(filter: Vec<u8>, output: &[u8], rank: u64) -> Self {
        Self {
            filter,
            identity: compute_output_identity(output),
            rank,
        }
    }
}

impl QuorumCertificate for AppGenesisQC {
    fn filter(&self) -> &[u8] { &self.filter }
    fn rank(&self) -> u64 { self.rank }
    fn frame_number(&self) -> u64 { 0 }
    fn identity(&self) -> &Identity { &self.identity }
    fn timestamp(&self) -> u64 { 0 }
    fn aggregated_signature(&self) -> &dyn AggregatedSignature { &EmptyAggSig }
    fn equals(&self, o: &dyn QuorumCertificate) -> bool {
        o.rank() == self.rank && o.identity() == &self.identity
    }
}

#[derive(Debug)]
struct EmptyAggSig;
impl AggregatedSignature for EmptyAggSig {
    fn signature(&self) -> &[u8] { &[] }
    fn public_key(&self) -> &[u8] { &[] }
    fn bitmask(&self) -> &[u8] { &[] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_shard_state_identity_is_deterministic() {
        let s1 = AppShardState::new(
            vec![1], 10, 0, 1000, 50000,
            vec![0xAAu8; 64], vec![], vec![], vec![], vec![], vec![], 0,
        );
        let s2 = AppShardState::new(
            vec![1], 10, 0, 1000, 50000,
            vec![0xAAu8; 64], vec![], vec![], vec![], vec![], vec![], 0,
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
        );
        assert_eq!(s.rank(), 5);
        assert_eq!(s.timestamp(), 1000);
        assert_eq!(s.signature(), &[0xDDu8; 74][..]);
    }

    #[test]
    fn app_shard_vote_unique_trait() {
        let v = AppShardVote::new(
            b"proposal-abc".to_vec(), 7, b"voter-xyz".to_vec(),
            5000, vec![0xEEu8; 74], vec![0x01], vec![1, 2],
        );
        // `identity` = voter, `source` = proposal id (see
        // `AppShardVote::new` comment: VoteCollector filters cached
        // entries by `source() == state.identifier`).
        assert_eq!(v.identity().as_slice(), b"voter-xyz");
        assert_eq!(v.rank(), 7);
        assert_eq!(v.source().as_slice(), b"proposal-abc");
        assert_eq!(v.timestamp(), 5000);
        assert_eq!(v.signature(), &[0xEEu8; 74][..]);
    }

    #[test]
    fn genesis_certified_state_rank_zero() {
        let cs = build_app_genesis_certified_state(&[1, 2, 3], 0, &[0xAAu8; 32], 0);
        assert_eq!(cs.state.rank, 0);
        assert_eq!(cs.certifying_qc_rank, 0);
        assert_eq!(cs.state.state.filter, vec![1, 2, 3]);
    }

    #[test]
    fn certified_state_at_nonzero_rank() {
        // Restart scenario: latest finalized shard frame is at rank 17293.
        // The trusted root must be at that rank so the resumed
        // `LivenessState.current_rank=17294` leader's parent-state
        // lookup finds it in the forks tree.
        let cs = build_app_genesis_certified_state(&[1, 2, 3], 5764, &[0xAAu8; 32], 17293);
        assert_eq!(cs.state.rank, 17293);
        assert_eq!(cs.certifying_qc_rank, 17293);
        assert_eq!(cs.state.state.frame_number, 5764);
    }

    #[test]
    fn vote_factory_make_vote() {
        let f = AppShardVoteFactory { filter: vec![1, 2] };
        let vote = f.make_vote(5, &"state-5".into(), vec![0xAAu8; 74], &[0xBBu8; 32]).unwrap();
        assert_eq!(vote.rank(), 5);
        assert_eq!(vote.filter, vec![1, 2]);
        assert!(!vote.signature_bytes.is_empty());
    }
}
