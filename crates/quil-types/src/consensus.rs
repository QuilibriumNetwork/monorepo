use crate::error::Result;
use crate::proto;
use crate::store;
use num_bigint::BigInt;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Engine state
// ---------------------------------------------------------------------------

/// Consensus engine states (matches Go's EngineState enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EngineState {
    Stopped = 0,
    Starting = 1,
    Loading = 2,
    Collecting = 3,
    LivenessCheck = 4,
    Proving = 5,
    Publishing = 6,
    Voting = 7,
    Finalizing = 8,
    Verifying = 9,
    Stopping = 10,
}

impl EngineState {
    /// Return the lowercase string name.
    pub fn as_str(&self) -> &'static str {
        match self {
            EngineState::Stopped => "stopped",
            EngineState::Starting => "starting",
            EngineState::Loading => "loading",
            EngineState::Collecting => "collecting",
            EngineState::LivenessCheck => "liveness_check",
            EngineState::Proving => "proving",
            EngineState::Publishing => "publishing",
            EngineState::Voting => "voting",
            EngineState::Finalizing => "finalizing",
            EngineState::Verifying => "verifying",
            EngineState::Stopping => "stopping",
        }
    }
}

impl std::fmt::Display for EngineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Event system
// ---------------------------------------------------------------------------

/// Control event types distributed across consensus components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlEventType {
    Start = 0,
    Stop = 1,
    Halt = 2,
    Resume = 3,
    GlobalNewHead = 4,
    GlobalFork = 5,
    GlobalEquivocation = 6,
    AppNewHead = 7,
    AppFork = 8,
    AppEquivocation = 9,
    CoverageHalt = 10,
    CoverageWarn = 11,
    CoverageResume = 12,
    ShardMergeEligible = 13,
    ShardSplitEligible = 14,
}

/// A control event carrying typed data.
#[derive(Debug, Clone)]
pub struct ControlEvent {
    pub event_type: ControlEventType,
    pub data: ControlEventData,
}

/// Typed event data payloads.
#[derive(Debug, Clone)]
pub enum ControlEventData {
    None,
    NewFrame {
        frame_number: u64,
        selector: Vec<u8>,
    },
    StateChange {
        old_state: EngineState,
        new_state: EngineState,
    },
    Error {
        message: String,
    },
    Coverage {
        filter: Vec<u8>,
        duration: u64,
    },
    ShardMerge {
        filters: Vec<Vec<u8>>,
        parent: Vec<u8>,
    },
    ShardSplit {
        filter: Vec<u8>,
        proposed: Vec<Vec<u8>>,
    },
    Alert {
        message: String,
    },
}

/// Distributes control events to subscribers.
pub trait EventDistributor: Send + Sync {
    fn subscribe(&self, id: &str) -> tokio::sync::mpsc::Receiver<ControlEvent>;
    fn publish(&self, event: ControlEvent);
    fn unsubscribe(&self, id: &str);
}

// ---------------------------------------------------------------------------
// Prover registry
// ---------------------------------------------------------------------------

/// Prover status in the registry. Matches Go's
/// `types/consensus/prover_registry.go::ProverStatus` 1:1 by name.
///
/// IMPORTANT: `Leaving` means **in flight, awaiting Confirm/Reject**
/// (trie byte 3) — it is NOT a terminal state. The terminal
/// "leave-confirmed" / evicted state is `Kicked` (trie byte 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProverStatus {
    Unknown = 0,
    Joining = 1,
    Active = 2,
    Paused = 3,
    Leaving = 4,
    Rejected = 5,
    Kicked = 6,
}

/// Allocation info for a prover on a specific shard. Mirrors
/// `types/consensus/prover_registry.go::ProverAllocationInfo`.
#[derive(Debug, Clone)]
pub struct ProverAllocationInfo {
    pub status: ProverStatus,
    pub confirmation_filter: Vec<u8>,
    pub rejection_filter: Vec<u8>,
    pub join_frame_number: u64,
    pub leave_frame_number: u64,
    pub pause_frame_number: u64,
    pub resume_frame_number: u64,
    pub kick_frame_number: u64,
    pub join_confirm_frame_number: u64,
    pub join_reject_frame_number: u64,
    pub leave_confirm_frame_number: u64,
    pub leave_reject_frame_number: u64,
    pub last_active_frame_number: u64,
    /// The storage epoch this allocation was last confirmed for. A data-shard
    /// (non-empty filter) Active allocation whose `epoch` is older than the
    /// current epoch is read as [`EffectiveStatus::ExpiredEpoch`]. `0` is the
    /// genesis/grandfather sentinel.
    pub epoch: u64,
    /// The 32-byte vertex address (last 32 bytes of the 64-byte
    /// hypergraph key).
    pub vertex_address: Vec<u8>,
}

/// Number of frames an allocation has to be Confirmed or Rejected
/// before the protocol implicitly treats it as expired. Joining
/// allocations past `join_frame_number + GRACE` are effectively
/// rejected; Leaving allocations past `leave_frame_number + GRACE`
/// are effectively left. Mirrors Go's
/// `worker_allocator.go::PENDING_FILTER_GRACE_FRAMES`.
pub const ALLOCATION_GRACE_FRAMES: u64 = 720;

/// Frames per storage epoch. At each epoch boundary a data-shard prover must
/// re-encode its replicas and re-confirm its allocation (carrying fresh leaf
/// roots). An Active data-shard allocation whose recorded `epoch` is older than
/// the current epoch stops counting for coverage/reward (read-side expiry, hard
/// boundary). Aligned with the 360..720 confirm window and the 720-frame grace.
pub const EPOCH_LENGTH_FRAMES: u64 = 720;

/// Test/testnet override for the epoch length. `0` = use the
/// `EPOCH_LENGTH_FRAMES` mainnet default. Mirrors the
/// `set_confirm_window_frames` testnet pattern — production never sets it, so
/// all mainnet nodes agree on 720. Lets e2e/integration harnesses exercise the
/// full epoch-aligned join→confirm→activate pipeline in a handful of frames
/// instead of 720+.
static EPOCH_LENGTH_OVERRIDE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Override the epoch length (frames per storage epoch) for tests/testnet.
/// `0` restores the mainnet `EPOCH_LENGTH_FRAMES` default. CONSENSUS PARAMETER —
/// only call this in test/testnet bootstrap, never on mainnet.
pub fn set_epoch_length_frames(frames: u64) {
    EPOCH_LENGTH_OVERRIDE.store(frames, std::sync::atomic::Ordering::Relaxed);
}

/// The effective epoch length (override if set, else the mainnet default).
#[inline]
pub fn epoch_length_frames() -> u64 {
    let o = EPOCH_LENGTH_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
    if o == 0 { EPOCH_LENGTH_FRAMES } else { o }
}

/// Epoch length for testnet/devnet (`network != 0`): a short epoch so the
/// epoch-aligned join→confirm(E+1)→activate(E+2) lifecycle plays out in
/// minutes instead of hours. The whole pipeline (`epoch_for_frame`,
/// `validate_confirm_timing`, lifecycle confirm/leave emission, materialize,
/// `effective_status`) reads `epoch_length_frames()`, so setting this once at
/// startup auto-scales every timing rule consistently.
pub const TESTNET_EPOCH_LENGTH_FRAMES: u64 = 60;

/// Pin the process-global epoch length from the network id at node startup.
/// Mainnet (`network == 0`) keeps the 720-frame default; every other network
/// uses the short testnet epoch. CONSENSUS PARAMETER — all nodes on a network
/// share the network id, so they all derive the SAME epoch length (fork-proof).
/// Must be called by BOTH the master and each worker process before any frame
/// is evaluated.
pub fn init_epoch_length_for_network(network: u8) {
    if network == 0 {
        set_epoch_length_frames(0); // mainnet default 720
    } else {
        set_epoch_length_frames(TESTNET_EPOCH_LENGTH_FRAMES);
    }
}

/// The storage epoch a frame belongs to.
#[inline]
pub fn epoch_for_frame(frame_number: u64) -> u64 {
    frame_number / epoch_length_frames()
}

/// PoRep block polynomial size (KZG evaluation-domain size per replica block).
/// Measured most efficient at 64 in testing; a power-of-two ≤ the ceremony
/// domain cap (`quil_crypto::sdr::BLOCK_POLY_SIZE = 256`). Consensus parameter —
/// the producer encodes and the verifier opens against this exact domain, so it
/// is a pinned consensus constant. The `SdrParams` (DRSample degree 6,
/// expander 8, 11 layers, 32-byte nodes) come from `SdrParams::default()`.
pub const STORAGE_BLOCK_POLY_SIZE: u64 = 64;

/// Per-frame storage-audit sample SIZE (absolute count, not a rate). The global
/// frame audits ≈ this many openings each frame, drawn unpredictably from the
/// beacon ρ_N: the caller sets the `is_audited` threshold to
/// `STORAGE_AUDIT_SAMPLE / T` where `T` is the frame's total auditable
/// population, so the expected audited count stays ≈ this constant regardless of
/// scale (cost ≈ 1024 · 0.56 ms ≈ 0.57 s/frame — independent of M·N). A fixed
/// RATE would instead grow with T and defeat the cost-decoupling. A junk-replica
/// cheater is caught within ≈ `T / STORAGE_AUDIT_SAMPLE` frames; the rate is the
/// security knob (seniority-only penalty ⇒ it must beat extract-before-catch).
/// 1024 is the low-safe end of the design's 1–2k range; raise toward 2048 at the
/// fork for more aggressive auditing.
pub const STORAGE_AUDIT_SAMPLE: u64 = 1024;

/// Number of independent ρ_N-derived block challenges a member opens per covered
/// leaf, per frame. Each query samples a distinct (block, point), so per-leaf
/// retrievability is ≈ `1 − (1−ε)^q`. 2 balances payload (each opening is
/// ~48 B proof + ~32 B value) against retrievability; a consensus parameter
/// pinned at the storage fork. Producer and verifier derive the same indices
/// from ρ_N, so this only affects how many openings are carried + audited.
pub const STORAGE_QUERIES_PER_LEAF: u32 = 2;

/// The effective state of an allocation at a given frame, with the
/// 720-frame grace window applied. Prefer this over reading
/// `alloc.status` directly anywhere the protocol's implicit
/// expiry semantics matter (TUI panels, server `is_allocated`
/// flags, halt-risk classification, lifecycle decisions). Open-
/// coding the grace check at each call site is a known regression
/// source — `EffectiveStatus` is the single source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveStatus {
    /// Status byte = Joining, still within the 720-frame grace.
    Joining,
    Active,
    Paused,
    /// Status byte = Leaving, still within the 720-frame grace.
    Leaving,
    /// Status byte = Joining but past `join_frame + 720`. Treated
    /// as implicitly rejected by the protocol.
    ExpiredJoining,
    /// Status byte = Leaving but past `leave_frame + 720`. Treated
    /// as implicitly left.
    ExpiredLeaving,
    /// Status byte = Active on a data shard, but the allocation's recorded
    /// `epoch` is older than the current epoch — the prover failed to re-confirm
    /// (re-register its leaf roots) for this epoch, so it no longer counts.
    ExpiredEpoch,
    Rejected,
    Kicked,
    Unknown,
}

impl EffectiveStatus {
    /// True when the prover currently OWNS this allocation slot —
    /// the user can't Join the same filter again because they
    /// already have an alloc. Used by TUI Available-panel filtering.
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Joining | Self::Active | Self::Paused | Self::Leaving
        )
    }

    /// True when the allocation should count toward "currently
    /// working on this shard" for IsAllocated flags and ring
    /// computation. Excludes Paused and Leaving (the user owns the
    /// slot but isn't producing).
    pub fn is_allocated(self) -> bool {
        matches!(self, Self::Joining | Self::Active)
    }

    /// True for allocations the protocol implicitly treats as expired without
    /// an on-chain status change: Joining/Leaving past their grace window, or an
    /// Active data-shard allocation that wasn't re-confirmed this epoch.
    pub fn is_expired(self) -> bool {
        matches!(
            self,
            Self::ExpiredJoining | Self::ExpiredLeaving | Self::ExpiredEpoch
        )
    }

    /// True for terminal end-states the registry will never
    /// transition out of.
    ///
    /// NOTE: `ExpiredEpoch` is deliberately NOT terminal — a stale-epoch
    /// allocation becomes live again the moment the prover re-confirms it for
    /// the current epoch (the raw status byte is still Active on chain).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Rejected | Self::Kicked | Self::ExpiredJoining | Self::ExpiredLeaving
        )
    }
}

impl ProverAllocationInfo {
    /// Resolve `status` + frame-number fields into the protocol's
    /// effective state at `current_frame`. Applies the 720-frame
    /// grace window for Joining/Leaving.
    pub fn effective_status(&self, current_frame: u64) -> EffectiveStatus {
        let current_epoch = epoch_for_frame(current_frame);
        match self.status {
            ProverStatus::Joining => {
                // Epoch-aligned: a join proposed in epoch E must be confirmed in
                // EXACTLY epoch E+1 (the chain rejects confirms outside that
                // slot). The raw `Joining` byte means "proposed, not yet
                // confirmed" — once confirmed the byte flips to Active and the
                // deferred-activation logic below takes over. So a Joining byte
                // that has slipped past its confirm epoch (current_epoch >
                // join_epoch + 1) is implicitly rejected. `join_frame_number==0`
                // is the genesis/test sentinel (no expiry).
                if self.join_frame_number > 0
                    && current_epoch > epoch_for_frame(self.join_frame_number) + 1
                {
                    EffectiveStatus::ExpiredJoining
                } else {
                    EffectiveStatus::Joining
                }
            }
            ProverStatus::Active => {
                // The global/empty filter stores no shard data and is exempt
                // from epoch obligations entirely.
                if self.confirmation_filter.is_empty() {
                    return EffectiveStatus::Active;
                }
                // Deferred activation (epoch-aligned lifecycle): a fresh join
                // confirmed in epoch E+1 flips its byte to Active but does NOT
                // join the committee until the next epoch boundary E+2, so the
                // committee stays FROZEN for the duration of E+1. Until then the
                // allocation reads as `Joining` (Pending folded into Joining).
                // `ActivationEpoch = epoch_for_frame(JoinConfirmFrameNumber)+1`.
                // The `join_confirm > 0` guard keeps genesis / legacy / test
                // fixtures (which leave it zero) on the always-active path — they
                // have no deferred activation.
                if self.join_confirm_frame_number > 0 {
                    let activation_epoch =
                        epoch_for_frame(self.join_confirm_frame_number) + 1;
                    if current_epoch < activation_epoch {
                        return EffectiveStatus::Joining;
                    }
                }
                // Epoch re-confirm obligation. `epoch` records the HIGHEST epoch
                // this allocation has registered leaf roots for (the `next`
                // slot of the two-slot registration). An Active prover re-confirms
                // each epoch X for X+1, so a current member always satisfies
                // `epoch >= current_epoch`. A stale recorded epoch means the
                // prover missed its re-confirm and stops counting until it renews
                // (recoverable, not terminal).
                if self.epoch >= current_epoch {
                    EffectiveStatus::Active
                } else {
                    EffectiveStatus::ExpiredEpoch
                }
            }
            ProverStatus::Paused => EffectiveStatus::Paused,
            ProverStatus::Leaving => {
                // Epoch-aligned departure. A leave proposed in epoch E is
                // confirmed in EXACTLY E+1; the prover keeps SERVING NOTICE
                // (still proving, still counted for coverage as `Leaving`)
                // through the rest of that epoch and departs at the E+2 boundary
                // — `DeactivationEpoch = epoch_for_frame(LeaveConfirmFrameNumber)+1`.
                // This keeps the committee frozen: a departing member stays in
                // it until the boundary. A leave that never confirmed in its E+1
                // slot is implicitly departed (ExpiredLeaving).
                if self.leave_confirm_frame_number > 0 {
                    let deactivation_epoch =
                        epoch_for_frame(self.leave_confirm_frame_number) + 1;
                    if current_epoch < deactivation_epoch {
                        EffectiveStatus::Leaving
                    } else {
                        EffectiveStatus::ExpiredLeaving
                    }
                } else if self.leave_frame_number > 0
                    && current_epoch > epoch_for_frame(self.leave_frame_number) + 1
                {
                    EffectiveStatus::ExpiredLeaving
                } else {
                    EffectiveStatus::Leaving
                }
            }
            ProverStatus::Rejected => EffectiveStatus::Rejected,
            ProverStatus::Kicked => EffectiveStatus::Kicked,
            ProverStatus::Unknown => EffectiveStatus::Unknown,
        }
    }

    /// Shorthand: is this allocation in any "live" state (owned by
    /// the prover) at `current_frame`?
    pub fn is_live(&self, current_frame: u64) -> bool {
        self.effective_status(current_frame).is_live()
    }

    /// Shorthand: should this allocation flip `IsAllocated=true`
    /// in `GetShardInfo` responses at `current_frame`? True only
    /// for Active and non-expired Joining.
    pub fn is_allocated(&self, current_frame: u64) -> bool {
        self.effective_status(current_frame).is_allocated()
    }
}

/// Complete prover information.
#[derive(Debug, Clone)]
pub struct ProverInfo {
    pub public_key: Vec<u8>,
    pub address: Vec<u8>,
    pub status: ProverStatus,
    pub kick_frame_number: u64,
    pub allocations: Vec<ProverAllocationInfo>,
    pub available_storage: u64,
    pub seniority: u64,
    pub delegate_address: Vec<u8>,
}

/// Prover allocation for reward calculation. Mirror of
/// `types/consensus/issuance.go::ProverAllocation`. Note this is a
/// SEPARATE type from `ProverAllocationInfo` — Go uses two different
/// structs named ProverAllocation in `types/consensus`: one for the
/// reward issuer (this one), one for the registry (that's
/// `ProverAllocationInfo`).
#[derive(Debug, Clone, Copy)]
pub struct ProverAllocation {
    /// 2^(ring+1) is the shard's allocated divisor.
    pub ring: u8,
    /// Total number of shards the prover is allocated to.
    pub shards: u64,
    /// Prover's contribution to world state, in bytes.
    pub state_size: u64,
}

/// Summary of provers per shard.
#[derive(Debug, Clone)]
pub struct ProverShardSummary {
    pub filter: Vec<u8>,
    pub status_counts: HashMap<ProverStatus, u32>,
    /// Approximate state size in bytes for this shard (for reward scoring).
    /// If unknown, defaults to 0 — the proposer treats 0-size shards as
    /// equal weight.
    pub total_size: u64,
}

/// Frame at which the eviction inactivity/grace clock starts ticking.
/// The network is not considered "available for participation" before
/// this frame, so a prover accrues NO inactivity prior to it: effective
/// inactivity is measured from `max(last_active_frame_number,
/// EVICTION_INACTIVITY_START_FRAME)`. This keeps anyone from being
/// counted (or surfaced as eviction-pending) for downtime that predates
/// the network being live for eviction purposes. Shared by the consensus
/// eviction path (`find_eviction_candidates`) and the explorer
/// eviction-risk display so they agree exactly.
pub const EVICTION_INACTIVITY_START_FRAME: u64 = 674_000;

/// Manages the prover trie: state transitions, lookups, eviction.
pub trait ProverRegistry: Send + Sync {
    fn get_prover_info(&self, address: &[u8]) -> Result<Option<ProverInfo>>;
    /// A member's registered storage leaf root for `leaf_id`, as
    /// `(leaf_root, num_blocks, epoch)`, or `None` if not registered. `leaf_id`
    /// is the opening's `shard_id`. Default `None` (registries that don't track
    /// storage attestation); the real registry overrides it.
    fn get_leaf_root(
        &self,
        _member: &[u8],
        _leaf_id: &[u8],
    ) -> Result<Option<(Vec<u8>, u64, u64)>> {
        Ok(None)
    }
    fn get_next_prover(&self, input: &[u8; 32], filter: &[u8]) -> Result<Vec<u8>>;
    fn get_ordered_provers(&self, input: &[u8; 32], filter: &[u8]) -> Result<Vec<Vec<u8>>>;
    fn get_active_provers(&self, filter: &[u8]) -> Result<Vec<ProverInfo>>;
    fn get_prover_count(&self, filter: &[u8]) -> Result<usize>;
    fn get_provers(&self, filter: &[u8]) -> Result<Vec<ProverInfo>>;
    fn get_provers_by_status(
        &self,
        filter: &[u8],
        status: ProverStatus,
    ) -> Result<Vec<ProverInfo>>;
    /// Touch the prover's last-active-frame counter under `filter`.
    /// Default: no-op (test stubs don't care; only the persistent
    /// registry overrides). Production maintains an in-memory cache
    /// of allocation activity that drives eviction.
    fn update_prover_activity(
        &self,
        _address: &[u8],
        _filter: &[u8],
        _frame_number: u64,
    ) -> Result<()> {
        Ok(())
    }
    /// Repopulate the registry's in-memory cache from the persistent
    /// store. Default: no-op (test stubs hold their state directly).
    fn refresh(&self) -> Result<()> {
        Ok(())
    }
    /// All Active provers across every non-empty filter. Default
    /// implementation falls back to `get_active_provers(&[])` so
    /// test stubs don't need to special-case "any filter" semantics.
    /// Production overrides to walk the per-prover cache directly.
    fn get_all_active_app_shard_provers(&self) -> Result<Vec<ProverInfo>> {
        self.get_active_provers(&[])
    }
    /// Per-filter prover count grouped by allocation status, with the
    /// 720-frame grace check applied so expired Joining/Leaving
    /// allocations don't inflate `status_counts`. Halt-risk
    /// classification reads `Joining` count from these summaries —
    /// without the expiry filter, a shard whose pending joins all
    /// timed out still looks "halt-risk-safe" (lots of pending
    /// provers) and the auto-allocator skips it.
    ///
    /// `frame_number` is the latest received frame (NOT the
    /// registry's internal `current_frame` — that one only advances
    /// when the materializer runs, so it lags on observer-only
    /// nodes).
    fn get_prover_shard_summaries(
        &self,
        frame_number: u64,
    ) -> Result<Vec<ProverShardSummary>>;
    /// Drop stale Joining vertices that never confirmed.
    /// Default: no-op (test stubs don't track orphan lifecycle).
    /// Production walks the prover cache and removes entries past
    /// the 720-frame grace.
    fn prune_orphan_joins(&self, _frame_number: u64) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Signer registry
// ---------------------------------------------------------------------------

/// Manages key registration and validation.
pub trait SignerRegistry: Send + Sync {
    fn get_key_registry(&self, identity_key_address: &[u8]) -> Result<proto::keys::KeyRegistry>;
    fn get_key_registry_by_prover(
        &self,
        prover_key_address: &[u8],
    ) -> Result<proto::keys::KeyRegistry>;
    fn validate_identity_key(&self, key: &proto::keys::Ed448PublicKey) -> Result<()>;
    fn validate_proving_key(
        &self,
        key: &proto::keys::Bls48581SignatureWithProofOfPossession,
    ) -> Result<()>;
    fn put_identity_key(
        &self,
        txn: &dyn store::Transaction,
        address: &[u8],
        key: &proto::keys::Ed448PublicKey,
    ) -> Result<()>;
    fn put_proving_key(
        &self,
        txn: &dyn store::Transaction,
        address: &[u8],
        key: &proto::keys::Bls48581SignatureWithProofOfPossession,
    ) -> Result<()>;
    fn put_cross_signature(
        &self,
        txn: &dyn store::Transaction,
        identity_key_address: &[u8],
        proving_key_address: &[u8],
        identity_sig: &[u8],
        proving_sig: &[u8],
    ) -> Result<()>;
    fn get_identity_key(&self, address: &[u8]) -> Result<proto::keys::Ed448PublicKey>;
    fn get_proving_key(
        &self,
        address: &[u8],
    ) -> Result<proto::keys::Bls48581SignatureWithProofOfPossession>;
}

// ---------------------------------------------------------------------------
// Consensus sub-components
// ---------------------------------------------------------------------------

/// ASERT-style difficulty adjustment.
pub trait DifficultyAdjuster: Send + Sync {
    fn get_next_difficulty(&self, current_frame_number: u64, current_time: i64) -> u64;
}

/// Dynamic fee multiplier management.
pub trait DynamicFeeManager: Send + Sync {
    fn add_frame_fee_vote(
        &self,
        filter: &[u8],
        frame_number: u64,
        fee_multiplier_vote: u64,
    ) -> Result<()>;
    fn get_next_fee_multiplier(&self, filter: &[u8]) -> Result<u64>;
    fn get_vote_history(&self, filter: &[u8]) -> Result<Vec<u64>>;
    fn get_average_window_size(&self, filter: &[u8]) -> Result<usize>;
    fn prune_old_data(&self, max_age: u64) -> Result<()>;
    fn rewind_to_frame(&self, filter: &[u8], frame_number: u64) -> Result<usize>;
}

/// Reward calculation.
pub trait RewardIssuance: Send + Sync {
    fn calculate(
        &self,
        difficulty: u64,
        world_state_bytes: u64,
        units: u64,
        provers: &[HashMap<String, ProverAllocation>],
    ) -> Result<Vec<BigInt>>;
}

/// Shard detail for info queries.
#[derive(Debug, Clone)]
pub struct ShardDetail {
    pub filter: Vec<u8>,
    pub shard_size: BigInt,
    pub active_provers: u32,
    pub ring: u32,
    pub estimated_reward: BigInt,
    pub is_allocated: bool,
    pub data_shards: u64,
}

/// Provides shard-level info.
pub trait ShardInfoProvider: Send + Sync {
    fn get_shard_info(
        &self,
        include_all: bool,
    ) -> Result<(Vec<ShardDetail>, u64, BigInt, u64)>;
}

// ---------------------------------------------------------------------------
// Frame validators
// ---------------------------------------------------------------------------

pub trait GlobalFrameValidator: Send + Sync {
    fn validate(&self, frame: &proto::global::GlobalFrame) -> Result<bool>;
}

pub trait AppFrameValidator: Send + Sync {
    fn validate(&self, frame: &proto::global::AppShardFrame) -> Result<bool>;
}

#[cfg(test)]
mod epoch_tests {
    use super::*;

    fn active_alloc(filter: Vec<u8>, epoch: u64) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status: ProverStatus::Active,
            confirmation_filter: filter,
            rejection_filter: Vec::new(),
            join_frame_number: 0,
            leave_frame_number: 0,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: 0,
            epoch,
            vertex_address: Vec::new(),
        }
    }

    // A frame in epoch `e` (storage attestation is always-on, so any epoch works).
    fn frame_in_epoch(e: u64) -> u64 {
        e * EPOCH_LENGTH_FRAMES + 1
    }

    #[test]
    fn stale_epoch_data_shard_is_expired_always_on() {
        // No activation gate: a stale-epoch data shard is ExpiredEpoch the moment
        // the current frame crosses into a later epoch than the one it recorded.
        let a = active_alloc(vec![0xAB; 32], 0); // epoch 0 < epoch_for_frame(1000)=1
        assert_eq!(a.effective_status(1000), EffectiveStatus::ExpiredEpoch);
        // ...but within epoch 0 (frame < 720) it's still Active — the epoch check
        // itself is the natural gate, no fork-height needed.
        assert_eq!(a.effective_status(700), EffectiveStatus::Active);
    }

    #[test]
    fn data_shard_active_with_current_epoch_stays_active() {
        let e = epoch_for_frame(frame_in_epoch(3));
        let a = active_alloc(vec![0xAB; 32], e);
        assert_eq!(a.effective_status(frame_in_epoch(3)), EffectiveStatus::Active);
    }

    #[test]
    fn data_shard_active_with_stale_epoch_is_expired() {
        let cur = frame_in_epoch(5);
        let stale = epoch_for_frame(cur) - 1;
        let a = active_alloc(vec![0xAB; 32], stale);
        assert_eq!(a.effective_status(cur), EffectiveStatus::ExpiredEpoch);
        assert!(a.effective_status(cur).is_expired());
        // ExpiredEpoch is recoverable, not terminal.
        assert!(!a.effective_status(cur).is_terminal());
        // And it no longer counts as allocated/live.
        assert!(!a.effective_status(cur).is_allocated());
    }

    #[test]
    fn global_empty_filter_is_exempt_from_epoch_expiry() {
        let cur = frame_in_epoch(9);
        // Empty filter (global prover), stale epoch 0 — still Active.
        let a = active_alloc(Vec::new(), 0);
        assert_eq!(a.effective_status(cur), EffectiveStatus::Active);
    }

    #[test]
    fn epoch_expiry_inert_within_genesis_epoch() {
        // Within epoch 0 (frame < EPOCH_LENGTH_FRAMES) a stale-epoch data-shard
        // allocation is NOT expired — there is no later epoch to be stale
        // against yet, so the always-on check naturally holds off until the
        // first epoch boundary.
        let a = active_alloc(vec![0xAB; 32], 0);
        let pre = EPOCH_LENGTH_FRAMES - 1;
        assert_eq!(a.effective_status(pre), EffectiveStatus::Active);
    }

    // Build a confirmed-join allocation: byte Active, with the confirm frame
    // and the registered (next-slot) epoch set explicitly.
    fn confirmed_alloc(
        filter: Vec<u8>,
        join_confirm_frame_number: u64,
        epoch: u64,
    ) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status: ProverStatus::Active,
            confirmation_filter: filter,
            join_confirm_frame_number,
            epoch,
            ..active_alloc(Vec::new(), 0)
        }
    }

    #[test]
    fn fresh_join_is_pending_until_activation_epoch() {
        // Join proposed in epoch 2 (frame 2*720+10), confirmed in EXACTLY epoch 3
        // (frame 3*720+5), registers for its first active epoch 4.
        let join_confirm = 3 * EPOCH_LENGTH_FRAMES + 5; // epoch 3
        let a = confirmed_alloc(vec![0xAB; 32], join_confirm, 4);
        // During the confirm epoch (E+1 = 3) the byte is Active but the prover
        // is NOT yet in the committee — reads as Joining (deferred activation).
        assert_eq!(a.effective_status(frame_in_epoch(3)), EffectiveStatus::Joining);
        // It owns the slot (is_live) but is not yet a committee member — the
        // lifecycle `active` bucket (which excludes Joining), not is_allocated,
        // is what gates committee/coverage counting.
        assert!(a.effective_status(frame_in_epoch(3)).is_live());
        // At the activation boundary E+2 = 4, it becomes Active.
        assert_eq!(a.effective_status(frame_in_epoch(4)), EffectiveStatus::Active);
        // If it then fails to re-confirm, epoch 5 reads ExpiredEpoch.
        assert_eq!(a.effective_status(frame_in_epoch(5)), EffectiveStatus::ExpiredEpoch);
    }

    #[test]
    fn leave_confirmed_serves_notice_then_departs() {
        // Leave confirmed in epoch 3 → departs at the E+2 = 4 boundary.
        let mut a = active_alloc(vec![0xAB; 32], 4);
        a.status = ProverStatus::Leaving;
        a.leave_confirm_frame_number = 3 * EPOCH_LENGTH_FRAMES + 5; // epoch 3
        // Serving notice through the rest of epoch 3 — still counted as Leaving
        // (live coverage), keeps the committee frozen.
        assert_eq!(a.effective_status(frame_in_epoch(3)), EffectiveStatus::Leaving);
        assert!(a.effective_status(frame_in_epoch(3)).is_live());
        // Departs at epoch 4.
        assert_eq!(a.effective_status(frame_in_epoch(4)), EffectiveStatus::ExpiredLeaving);
        assert!(a.effective_status(frame_in_epoch(4)).is_terminal());
    }

    #[test]
    fn join_not_confirmed_in_next_epoch_expires() {
        // Joining byte, proposed epoch 2, never confirmed. By epoch 4 (past the
        // E+1=3 confirm slot) it is implicitly rejected.
        let mut a = active_alloc(vec![0xAB; 32], 0);
        a.status = ProverStatus::Joining;
        a.join_frame_number = 2 * EPOCH_LENGTH_FRAMES + 10; // epoch 2
        // Still valid through its confirm epoch (3).
        assert_eq!(a.effective_status(frame_in_epoch(3)), EffectiveStatus::Joining);
        // Past it → ExpiredJoining.
        assert_eq!(a.effective_status(frame_in_epoch(4)), EffectiveStatus::ExpiredJoining);
    }

    #[test]
    fn reconfirm_ahead_does_not_demote_active_member() {
        // An established member re-confirms in epoch 5 for epoch 6 (registers
        // ahead, epoch field = 6). It must stay Active for the rest of epoch 5,
        // NOT demote to Joining — this is what the two-slot {current,next}
        // registration buys. join_confirm is old (activation in the past).
        let a = confirmed_alloc(vec![0xCD; 32], EPOCH_LENGTH_FRAMES + 1 /* epoch 1 */, 6);
        assert_eq!(a.effective_status(frame_in_epoch(5)), EffectiveStatus::Active);
        assert_eq!(a.effective_status(frame_in_epoch(6)), EffectiveStatus::Active);
    }

    #[test]
    fn reconfirm_restores_active() {
        let cur = frame_in_epoch(7);
        let cur_epoch = epoch_for_frame(cur);
        // Stale → expired.
        assert_eq!(
            active_alloc(vec![1, 2, 3], cur_epoch - 1).effective_status(cur),
            EffectiveStatus::ExpiredEpoch
        );
        // Re-confirmed for the current epoch → Active again.
        assert_eq!(
            active_alloc(vec![1, 2, 3], cur_epoch).effective_status(cur),
            EffectiveStatus::Active
        );
    }

    // ---- Gap coverage (audit 2026-06-28) -------------------------------

    /// Leave PROPOSED but never confirmed: the `leave_confirm == 0` implicit-
    /// expiry branch (symmetric to `join_not_confirmed_in_next_epoch_expires`).
    /// Serves notice through its E+1 slot, then departs as ExpiredLeaving.
    #[test]
    fn leave_proposed_never_confirmed_expires_after_e_plus_1() {
        let leaving = |leave_frame: u64| ProverAllocationInfo {
            status: ProverStatus::Leaving,
            leave_frame_number: leave_frame,
            leave_confirm_frame_number: 0, // never confirmed
            ..active_alloc(vec![0xAB; 32], 0)
        };
        // Leave proposed in epoch 2.
        let a = leaving(frame_in_epoch(2));
        // Epoch 2 (proposal epoch) and epoch 3 (the E+1 notice slot) → still Leaving.
        assert_eq!(a.effective_status(frame_in_epoch(2)), EffectiveStatus::Leaving);
        assert_eq!(a.effective_status(frame_in_epoch(3)), EffectiveStatus::Leaving);
        assert!(a.is_live(frame_in_epoch(3)));
        // Epoch 4 (past E+1) → ExpiredLeaving + terminal, no longer live.
        assert_eq!(
            a.effective_status(frame_in_epoch(4)),
            EffectiveStatus::ExpiredLeaving
        );
        assert!(a.effective_status(frame_in_epoch(4)).is_terminal());
        assert!(!a.is_live(frame_in_epoch(4)));
    }

    /// Activation/expiry transitions land EXACTLY on the epoch boundary frame
    /// (`N * EPOCH_LENGTH_FRAMES`), not one frame early or late. Guards the
    /// `frame / epoch_length` division at the boundary.
    #[test]
    fn effective_status_flips_exactly_at_epoch_boundary() {
        // A confirmed join: byte Active, confirmed in epoch 2 → ActivationEpoch 3.
        // `epoch` set high so the re-confirm check never expires it.
        let a = ProverAllocationInfo {
            join_confirm_frame_number: frame_in_epoch(2),
            ..active_alloc(vec![0xCD; 32], 100)
        };
        let boundary = 3 * EPOCH_LENGTH_FRAMES; // first frame of epoch 3
        // One frame BEFORE the boundary (last frame of epoch 2) → still deferred.
        assert_eq!(
            a.effective_status(boundary - 1),
            EffectiveStatus::Joining,
            "last frame of epoch 2 is pre-activation"
        );
        // Exactly ON the boundary → Active.
        assert_eq!(
            a.effective_status(boundary),
            EffectiveStatus::Active,
            "activation lands on the epoch-3 boundary frame"
        );
    }

    /// `join_frame_number == 0` is the genesis/test sentinel: a Joining byte
    /// never expires regardless of how far the chain advances.
    #[test]
    fn joining_zero_frame_sentinel_never_expires() {
        let a = ProverAllocationInfo {
            status: ProverStatus::Joining,
            join_frame_number: 0,
            ..active_alloc(vec![0x11; 32], 0)
        };
        assert_eq!(a.effective_status(frame_in_epoch(50)), EffectiveStatus::Joining);
    }

    /// `join_confirm_frame_number == 0` (genesis/legacy) means NO deferred
    /// activation — the allocation is governed purely by the epoch re-confirm
    /// check, not read as a pending Joining.
    #[test]
    fn active_with_zero_join_confirm_is_not_deferred() {
        // Stale recorded epoch → ExpiredEpoch (NOT deferred Joining).
        assert_eq!(
            active_alloc(vec![0x22; 32], 1).effective_status(frame_in_epoch(5)),
            EffectiveStatus::ExpiredEpoch
        );
        // Current recorded epoch → Active.
        assert_eq!(
            active_alloc(vec![0x22; 32], 5).effective_status(frame_in_epoch(5)),
            EffectiveStatus::Active
        );
    }

    /// Direct assertions on the `EffectiveStatus` helper predicates for the
    /// three Expired* variants (previously only inferred via bucketing).
    #[test]
    fn expired_variant_helper_predicates() {
        // ExpiredJoining: terminal, expired, not allocated/live.
        let ej = EffectiveStatus::ExpiredJoining;
        assert!(ej.is_terminal() && ej.is_expired() && !ej.is_allocated() && !ej.is_live());
        // ExpiredLeaving: terminal, expired.
        let el = EffectiveStatus::ExpiredLeaving;
        assert!(el.is_terminal() && el.is_expired() && !el.is_allocated() && !el.is_live());
        // ExpiredEpoch: expired + recoverable (NOT terminal), not counting now.
        let ee = EffectiveStatus::ExpiredEpoch;
        assert!(ee.is_expired() && !ee.is_terminal() && !ee.is_allocated() && !ee.is_live());
    }

    /// Epoch-length override recomputes boundaries and round-trips back to the
    /// 720 default. Serialized via a process-global mutex so it never races the
    /// other unit tests reading the default.
    #[test]
    fn epoch_length_override_recomputes_and_restores() {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap();
        set_epoch_length_frames(16);
        assert_eq!(epoch_length_frames(), 16);
        assert_eq!(epoch_for_frame(16), 1);
        assert_eq!(epoch_for_frame(15), 0);
        // A data-shard alloc recorded for epoch 0 is stale at frame 16 (epoch 1).
        assert_eq!(
            active_alloc(vec![0x33; 32], 0).effective_status(16),
            EffectiveStatus::ExpiredEpoch
        );
        // Restore default.
        set_epoch_length_frames(0);
        assert_eq!(epoch_length_frames(), EPOCH_LENGTH_FRAMES);
        assert_eq!(epoch_for_frame(720), 1);
    }
}
