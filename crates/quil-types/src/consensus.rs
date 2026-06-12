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

    /// True for Joining/Leaving allocations whose grace window has
    /// elapsed without a Confirm/Reject landing on chain.
    pub fn is_expired(self) -> bool {
        matches!(self, Self::ExpiredJoining | Self::ExpiredLeaving)
    }

    /// True for terminal end-states the registry will never
    /// transition out of.
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
        match self.status {
            ProverStatus::Joining => {
                if self.join_frame_number > 0
                    && current_frame > self.join_frame_number + ALLOCATION_GRACE_FRAMES
                {
                    EffectiveStatus::ExpiredJoining
                } else {
                    EffectiveStatus::Joining
                }
            }
            ProverStatus::Active => EffectiveStatus::Active,
            ProverStatus::Paused => EffectiveStatus::Paused,
            ProverStatus::Leaving => {
                if self.leave_frame_number > 0
                    && current_frame > self.leave_frame_number + ALLOCATION_GRACE_FRAMES
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

/// Manages the prover trie: state transitions, lookups, eviction.
pub trait ProverRegistry: Send + Sync {
    fn get_prover_info(&self, address: &[u8]) -> Result<Option<ProverInfo>>;
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
