use std::fmt::Debug;
use std::sync::Arc;

/// Identity is the raw byte sequence identifying a consensus object —
/// for `GlobalFrame` it's the 32-byte big-endian Poseidon hash of the
/// frame output, for QCs it's the `Selector` field, etc. Mirrors Go's
/// `models.Identity = string` (Go strings are arbitrary byte
/// sequences); we use `Vec<u8>` so we can hold the raw bytes without
/// UTF-8 lossiness.
pub type Identity = Vec<u8>;

/// All consensus objects must implement Unique for identification and ordering.
pub trait Unique: Send + Sync + Clone + Debug + 'static {
    fn identity(&self) -> &Identity;
    fn rank(&self) -> u64;
    fn source(&self) -> &Identity;
    fn timestamp(&self) -> u64;
    fn signature(&self) -> &[u8];

    /// Optional per-vote auxiliary payload. App shard votes use this
    /// to carry a 516-byte VDF multi-proof contribution (PoMW). The
    /// signature aggregator concatenates these in committee-index
    /// order past the BLS aggregate to form the wire-level frame
    /// signature blob: `bls_agg(74) || u32(count) || concat(aux)`.
    /// Vote types that don't carry aux data (global votes) return
    /// the default empty slice.
    fn aux(&self) -> &[u8] {
        &[]
    }
}

/// Aggregated BLS signature with bitmask.
pub trait AggregatedSignature: Send + Sync + Debug {
    fn signature(&self) -> &[u8];
    fn public_key(&self) -> &[u8];
    fn bitmask(&self) -> &[u8];
}

/// Quorum Certificate — proves supermajority agreement on a state.
pub trait QuorumCertificate: Send + Sync + Debug {
    fn filter(&self) -> &[u8];
    fn rank(&self) -> u64;
    fn frame_number(&self) -> u64;
    fn identity(&self) -> &Identity;
    fn timestamp(&self) -> u64;
    fn aggregated_signature(&self) -> &dyn AggregatedSignature;
    fn equals(&self, other: &dyn QuorumCertificate) -> bool;
}

/// Timeout Certificate — proves supermajority timeout for a rank.
pub trait TimeoutCertificate: Send + Sync + Debug {
    fn filter(&self) -> &[u8];
    fn rank(&self) -> u64;
    fn latest_ranks(&self) -> &[u64];
    fn latest_quorum_cert(&self) -> &dyn QuorumCertificate;
    fn aggregated_signature(&self) -> &dyn AggregatedSignature;
    fn equals(&self, other: &dyn TimeoutCertificate) -> bool;
}

/// A weighted participant in the consensus committee.
pub trait WeightedIdentity: Send + Sync + Debug {
    fn public_key(&self) -> &[u8];
    fn identity(&self) -> &Identity;
    fn weight(&self) -> u64;
}

/// A consensus state (block), parameterized over the application state type.
///
/// `parent_quorum_certificate` mirrors Go's `models.State.ParentQuorumCertificate` —
/// the QC at the parent's rank that certified the parent. `None` only for
/// genesis (no parent). The `parent_qc_identity` / `parent_qc_rank` fields
/// are kept as a redundant shortcut for callers that only need the
/// reference without paying for QC trait-object dispatch / serialization.
#[derive(Debug, Clone)]
pub struct State<S: Unique> {
    pub rank: u64,
    pub identifier: Identity,
    pub proposer_id: Identity,
    pub parent_qc_identity: Identity,
    pub parent_qc_rank: u64,
    pub parent_quorum_certificate: Option<Arc<dyn QuorumCertificate>>,
    pub timestamp: u64,
    pub state: S,
}

/// A proposal with an optional timeout certificate from the previous rank.
/// The TC is held behind an `Arc` so the proposal can be cloned cheaply while
/// the trait object stays shared. `None` means the proposer entered the
/// current rank via the happy-path QC rather than a recovery-path TC.
///
/// `parent_quorum_certificate` is the QC the proposed state builds on top
/// of (the QC for `parent_qc_identity` at `parent_qc_rank`). The wire
/// `GlobalProposal` carries this verbatim so receivers can verify the
/// proposal lineage; the in-memory shape carries the trait object so the
/// outbound publisher can serialize it without re-fetching from the QC
/// store.
#[derive(Debug, Clone)]
pub struct Proposal<S: Unique> {
    pub state: State<S>,
    pub parent_quorum_certificate: Arc<dyn QuorumCertificate>,
    pub previous_rank_timeout_certificate: Option<Arc<dyn TimeoutCertificate>>,
}

/// A signed proposal includes the proposer's own vote.
#[derive(Debug, Clone)]
pub struct SignedProposal<S: Unique, V: Unique> {
    pub proposal: Proposal<S>,
    pub vote: V,
}

/// A certified state: state + the QC that certifies it.
///
/// `certifying_quorum_certificate` mirrors Go's
/// `models.CertifiedState.CertifyingQuorumCertificate` — the QC at this
/// state's rank that aggregated the supermajority votes proving the
/// state. `None` is allowed for genesis / legacy paths that construct
/// CertifiedStates without the QC trait object; production paths
/// populate it so consumers (e.g. `AppFollower` for coverage emission)
/// can read the aggregated signature directly.
#[derive(Debug, Clone)]
pub struct CertifiedState<S: Unique> {
    pub state: State<S>,
    pub certifying_qc_identity: Identity,
    pub certifying_qc_rank: u64,
    pub certifying_quorum_certificate: Option<Arc<dyn QuorumCertificate>>,
}

/// Timeout state broadcast by a node when its local timer fires.
/// Mirror of Go's `models.TimeoutState`.
#[derive(Debug, Clone)]
pub struct TimeoutState<V: Unique> {
    pub rank: u64,
    pub latest_quorum_certificate: Arc<dyn QuorumCertificate>,
    pub prior_rank_timeout_certificate: Option<Arc<dyn TimeoutCertificate>>,
    pub vote: V,
    /// Re-broadcast counter (prevents de-duplication in the network layer).
    pub timeout_tick: u64,
}

/// Finality proof: a state is finalized when a certified child exists at rank+1.
#[derive(Debug, Clone)]
pub struct FinalityProof<S: Unique> {
    pub state: State<S>,
    pub certified_child: CertifiedState<S>,
}

/// Persisted consensus state for crash recovery.
#[derive(Debug, Clone)]
pub struct ConsensusState<V: Unique> {
    pub filter: Vec<u8>,
    pub finalized_rank: u64,
    pub latest_acknowledged_rank: u64,
    pub latest_timeout: Option<TimeoutState<V>>,
}

/// Persisted liveness state for crash recovery.
#[derive(Debug, Clone)]
pub struct LivenessState {
    pub filter: Vec<u8>,
    pub current_rank: u64,
    pub latest_quorum_certificate: Arc<dyn QuorumCertificate>,
    pub prior_rank_timeout_certificate: Option<Arc<dyn TimeoutCertificate>>,
}
