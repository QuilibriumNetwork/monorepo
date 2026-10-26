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
    /// Superseded by a reassignment — the prover was moved OFF this filter onto
    /// another shard, but the allocation slot is retained (not deleted) so it can
    /// be flipped back to Active if the shard is ever re-formed (split→lose
    /// coverage→merge back). A hard delete tombstones the `allocation_address`
    /// permanently (see `HypergraphCrdt::get_vertex_data` — the removes-phase
    /// tombstone gates the read and no `add_vertex` clears it), making the slot
    /// unrepresentable forever; `Historic` is the reversible representation of
    /// "not on this shard right now." Excluded from committees; NOT terminal.
    /// Allocation trie byte 6 (bytes 4=Rejected, 5=Kicked already taken).
    Historic = 7,
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
    /// The last GLOBAL frame that included an app frame this allocation
    /// signed. Unlike `last_active_frame_number`, confirms do not advance it.
    /// `0` when never recorded, including every frame before
    /// [`SIGNED_FRAME_ACTIVATION_FRAME`].
    pub last_signed_frame_number: u64,
    /// The storage epoch this allocation was last confirmed for. A data-shard
    /// (non-empty filter) Active allocation whose `epoch` is older than the
    /// current epoch is read as [`EffectiveStatus::ExpiredEpoch`]. `0` is the
    /// genesis/grandfather sentinel.
    pub epoch: u64,
    /// The reward-ring index this allocation is LOCKED into, computed at
    /// confirmation (and recomputed only on a membership change — a higher prover
    /// leaving/evicting shifts survivors up). Read during materialization instead
    /// of re-sorting by live seniority, which is what keeps the prover-tree root
    /// deterministic across nodes.
    pub ring: u8,
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

/// Network policy for globally authorized app-committee sessions (committee
/// handoff). `None` keeps the legacy registry-derived committees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeHandoffPolicy {
    /// First global frame whose maintenance pass authorizes sessions.
    pub activation_frame: u64,
    /// Bound into every session ID, and through it every signing namespace.
    pub chain_id: [u8; 32],
    /// How shards with legacy-certified history enter sessions.
    pub legacy_history: LegacyHistory,
    /// From this GLOBAL frame, a session's membership successor is scheduled
    /// only at an epoch boundary (the first session pass of an epoch): the
    /// eligible set changes mid-epoch (late re-confirms, leave rejects) wait
    /// for the next boundary, as the epoch-aligned lifecycle intends.
    pub membership_boundary_frame: u64,
    /// From this GLOBAL frame a shard's FIRST session is also authorized only
    /// at the first session pass of an epoch, so a mid-epoch pass decides
    /// nothing and skips its prover scan.
    pub first_session_boundary_frame: u64,
}

/// What a network with legacy app history does with it at activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyHistory {
    /// Generation zero: GLOBAL records legacy tips from `LEGACY_TIP_LEAD`
    /// frames before activation, and each legacy committee seals its shard
    /// into its first session in place.
    Migrate,
    /// Flag day: at activation every node discards the legacy app frame
    /// chains (members and archives alike) and keeps the application state;
    /// every shard's first session starts at frame 0 over that state. No tips
    /// are recorded and no legacy frame is accepted from activation on.
    Discard,
}

/// Mainnet's committee-handoff activation: the GLOBAL frame whose maintenance
/// pass authorizes the first sessions, an epoch boundary (1197 × 720).
/// Decided 2026-10-05: a flag day that discards legacy app history.
pub const MAINNET_COMMITTEE_HANDOFF_FRAME: u64 = 861_840;

/// Mainnet's first frame of epoch-boundary membership successors (epoch
/// 1198). Decided 2026-10-06: after activation, every eligible-set
/// change re-sealed every shard its prover sat on, every 8 frames, so no
/// first session produced a frame.
pub const MAINNET_MEMBERSHIP_BOUNDARY_FRAME: u64 = 862_560;

/// Mainnet's first frame of epoch-boundary first sessions (epoch 1200).
/// Decided 2026-10-06: with membership frozen mid-epoch, a pass still
/// scanned the whole prover shard every 8 frames only to learn whether a
/// shard without a session had gained members.
pub const MAINNET_FIRST_SESSION_BOUNDARY_FRAME: u64 = 864_000;

static COMMITTEE_HANDOFF_POLICY: std::sync::RwLock<Option<CommitteeHandoffPolicy>> =
    std::sync::RwLock::new(None);

/// CONSENSUS PARAMETER — every node materializing global frames must install
/// the same value before evaluating any frame. Tests and network bootstrap only.
pub fn set_committee_handoff_policy(policy: Option<CommitteeHandoffPolicy>) {
    *COMMITTEE_HANDOFF_POLICY.write().unwrap_or_else(|e| e.into_inner()) = policy;
}

pub fn committee_handoff_policy() -> Option<CommitteeHandoffPolicy> {
    *COMMITTEE_HANDOFF_POLICY.read().unwrap_or_else(|e| e.into_inner())
}

/// Whether committee sessions govern GLOBAL frame `frame`: a policy is
/// installed and `frame` is at or past its activation. Before activation a
/// network with a policy still runs its legacy committees.
pub fn committee_handoff_active(frame: u64) -> bool {
    committee_handoff_policy().is_some_and(|policy| frame >= policy.activation_frame)
}

/// Chain identifier sessions bind on `network`: a fixed label and the network id.
pub fn committee_handoff_chain_id(network: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    let label = b"quil/app-handoff/chain/v1";
    id[..label.len()].copy_from_slice(label);
    id[31] = network;
    id
}

/// Pin the committee-handoff policy from the network id at node startup, like
/// [`init_epoch_length_for_network`]. Mainnet (`network == 0`) activates at
/// [`MAINNET_COMMITTEE_HANDOFF_FRAME`] and discards its legacy app history
/// there; the environment cannot change either. Other networks opt in with
/// `QUIL_COMMITTEE_HANDOFF_FRAME` (the activation frame, `0` for a network
/// started from an empty genesis), env-gated like
/// `QUIL_UNIFIED_TREE_CUTOVER_FRAME`: every node of that network must set the
/// same value. A network with legacy app history migrates it in place through
/// generation zero, and must set a frame at least `LEGACY_TIP_LEAD` after its
/// nodes adopt this release, so every live shard has a recorded tip first;
/// `QUIL_COMMITTEE_HANDOFF_DISCARD_LEGACY=1` selects mainnet's flag day
/// instead.
pub fn init_committee_handoff_for_network(network: u8) {
    set_committee_handoff_policy(committee_handoff_policy_for_network(network, |name| std::env::var(name).ok()));
}

fn committee_handoff_policy_for_network(
    network: u8,
    env: impl Fn(&str) -> Option<String>,
) -> Option<CommitteeHandoffPolicy> {
    if network == 0 {
        return Some(CommitteeHandoffPolicy {
            activation_frame: MAINNET_COMMITTEE_HANDOFF_FRAME,
            chain_id: committee_handoff_chain_id(network),
            legacy_history: LegacyHistory::Discard,
            membership_boundary_frame: MAINNET_MEMBERSHIP_BOUNDARY_FRAME,
            first_session_boundary_frame: MAINNET_FIRST_SESSION_BOUNDARY_FRAME,
        });
    }
    let activation_frame = env("QUIL_COMMITTEE_HANDOFF_FRAME")?.parse::<u64>().ok()?;
    let discard = env("QUIL_COMMITTEE_HANDOFF_DISCARD_LEGACY").is_some_and(|value| value == "1");
    let membership_boundary_frame = env("QUIL_COMMITTEE_MEMBERSHIP_BOUNDARY_FRAME")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(activation_frame);
    let first_session_boundary_frame = env("QUIL_COMMITTEE_FIRST_SESSION_BOUNDARY_FRAME")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    Some(CommitteeHandoffPolicy {
        activation_frame,
        chain_id: committee_handoff_chain_id(network),
        legacy_history: if discard { LegacyHistory::Discard } else { LegacyHistory::Migrate },
        membership_boundary_frame,
        first_session_boundary_frame,
    })
}

/// The storage epoch a frame belongs to.
#[inline]
pub fn epoch_for_frame(frame_number: u64) -> u64 {
    frame_number / epoch_length_frames()
}

/// The epoch from which a `ProverSeniorityMerge` follows the seniority
/// succession rules: an Ed448 node key whose spent markers name another,
/// idle prover can move that prover's seniority to the prover submitting
/// the merge, a merge must raise the submitter's seniority, a merge may
/// name targets the submitter itself consumed, and a rejoin keeps the
/// prover's `LastSeniorityFrameNumber`. Consensus-affecting: every archive
/// and prover must run a build with it before then. Mainnet: the epoch the
/// hash storage proofs begin ([`MAINNET_HASH_STORAGE_PROOF_EPOCH`], decided
/// 2026-10-25), so both rule changes land at one boundary.
/// `QUIL_SENIORITY_SUCCESSION_EPOCH` elsewhere, never by default.
pub const MAINNET_SENIORITY_SUCCESSION_EPOCH: Option<u64> = MAINNET_HASH_STORAGE_PROOF_EPOCH;

/// Frames a predecessor must stay without any recorded activity before a
/// succession can move its seniority, on mainnet: two epochs. After one
/// epoch every allocation missed a re-confirm and reads as `ExpiredEpoch`;
/// the second lets `ALLOCATION_GRACE_FRAMES` lapse for a joining or leaving
/// allocation, and gives whoever holds the predecessor's prover key a full
/// epoch to contest the move by participating, which moves its last
/// activity. A proposal.
pub const SENIORITY_SUCCESSION_QUIET_FRAMES: u64 = 2 * EPOCH_LENGTH_FRAMES;

/// The quiet period in frames on this network: two epochs of its length
/// ([`SENIORITY_SUCCESSION_QUIET_FRAMES`] on mainnet).
pub fn seniority_succession_quiet_frames() -> u64 {
    2 * epoch_length_frames()
}

static SENIORITY_SUCCESSION_EPOCH: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

thread_local! {
    static SENIORITY_SUCCESSION_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

fn seniority_succession_epoch_for(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_SENIORITY_SUCCESSION_EPOCH.unwrap_or(u64::MAX);
    }
    setting.and_then(|value| value.parse().ok()).unwrap_or(u64::MAX)
}

/// Fix this process's seniority succession epoch from its network, and
/// return it. Called at startup before any frame is processed; the first
/// call decides.
pub fn init_seniority_succession_epoch(network: u8) -> u64 {
    *SENIORITY_SUCCESSION_EPOCH.get_or_init(|| {
        seniority_succession_epoch_for(
            network,
            std::env::var("QUIL_SENIORITY_SUCCESSION_EPOCH").ok().as_deref(),
        )
    })
}

/// The epoch fixed by [`init_seniority_succession_epoch`]; the mainnet epoch
/// in a process that never called it, so the setting cannot reach mainnet.
/// `u64::MAX` when the network has none.
pub fn seniority_succession_epoch() -> u64 {
    if let Some(epoch) = SENIORITY_SUCCESSION_OVERRIDE.with(|cell| cell.get()) {
        return epoch;
    }
    *SENIORITY_SUCCESSION_EPOCH.get_or_init(|| seniority_succession_epoch_for(0, None))
}

/// Whether GLOBAL frame `frame` applies the seniority succession rules.
pub fn seniority_succession_active(frame: u64) -> bool {
    epoch_for_frame(frame) >= seniority_succession_epoch()
}

/// Set the seniority succession epoch for the calling thread only (tests).
/// `Some(u64::MAX)` disables it; `None` restores the process setting.
pub fn set_seniority_succession_epoch_for_thread(epoch: Option<u64>) {
    SENIORITY_SUCCESSION_OVERRIDE.with(|cell| cell.set(epoch));
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

/// One epoch of a member's storage seat on a shard, as GLOBAL recorded it
/// (hash storage proofs; `quil_execution::global_intrinsic::storage_seat`):
/// the leaves it registered, whether its epoch proof sealed them, and the
/// roots its proposals committed ([`ProverRegistry::get_storage_seat_slot`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageSeatSlot {
    pub epoch: u64,
    /// Sorted: the order a commitment opens them in.
    pub leaves: Vec<Vec<u32>>,
    /// The GLOBAL frame that recorded the registration (the frame after it
    /// is the seal's beacon).
    pub registered_at: u64,
    pub sealed_at: Option<u64>,
    /// Roots committed, and their chain.
    pub frames: u64,
    pub accumulator: [u8; 32],
    /// The app frames chained, ascending, each with the GLOBAL frame it
    /// anchors to: what the member's epoch proof lists. GLOBAL never executes
    /// a header that missed its GLOBAL frame, so these can be fewer than the
    /// member's finalized frames. Empty once the epoch is closed.
    pub chained: Vec<(u64, u64)>,
    /// No epoch proof settled the epoch and its window has not closed.
    pub open: bool,
}

/// The certified state a shard's storage registrations for `epoch` commit to
/// (hash storage proofs; `quil_execution::global_intrinsic::storage_snapshot`):
/// the state roots of the first header of the shard GLOBAL executed at or
/// after [`storage_snapshot_frame`]`(epoch)`, one per phase, with that header's
/// app frame and anchor ([`ProverRegistry::get_storage_snapshot`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageSnapshotRoots {
    pub epoch: u64,
    pub frame: u64,
    pub anchor: u64,
    pub roots: [[u8; 32]; 4],
}

/// Challenges a seal proof answers (hash storage proofs): each opens one
/// node's labels on every layer and those of its parents, so a replica that
/// is not the member's encoding on a fraction ε of its nodes escapes with
/// probability (1−ε)^64 — about 4% at ε = 5% and 0.1% at ε = 10%. Decided
/// 2026-10-20.
pub const STORAGE_SEAL_CHALLENGES: usize = 64;

/// Serialized storage epoch proofs a GLOBAL proposal carries at most. GLOBAL
/// verifies every one (decided 2026-10-20); they cluster once the epoch's
/// registrations land, and one is about 0.5–0.75 MB.
pub const STORAGE_SEAL_BYTES_PER_FRAME: usize = 4 << 20;

/// The epoch whose registrations, openings and audits use the hash storage
/// proofs (`quil_crypto::storage_proof`: SHA3-256 Merkle commitments and seal
/// proofs) instead of KZG over BLS48-581, which is not post-quantum. Members
/// register for an epoch during the one before it, so the first hash
/// registrations land in the epoch before this one. Consensus-affecting:
/// every archive and prover must run a build with it before then.
pub const MAINNET_HASH_STORAGE_PROOF_EPOCH: Option<u64> = Some(1311);

static HASH_STORAGE_PROOF_EPOCH: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

thread_local! {
    static HASH_STORAGE_PROOF_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

fn hash_storage_proof_epoch_for(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_HASH_STORAGE_PROOF_EPOCH.unwrap_or(u64::MAX);
    }
    setting.and_then(|value| value.parse().ok()).unwrap_or(u64::MAX)
}

/// Fix this process's hash storage proof epoch from its network, and return
/// it. Called at startup before any frame is processed; the first call decides.
pub fn init_hash_storage_proof_epoch(network: u8) -> u64 {
    *HASH_STORAGE_PROOF_EPOCH.get_or_init(|| {
        hash_storage_proof_epoch_for(network, std::env::var("QUIL_HASH_STORAGE_PROOF_EPOCH").ok().as_deref())
    })
}

/// The epoch fixed by [`init_hash_storage_proof_epoch`]; the mainnet epoch in
/// a process that never called it, so the setting cannot reach mainnet.
pub fn hash_storage_proof_epoch() -> u64 {
    if let Some(epoch) = HASH_STORAGE_PROOF_OVERRIDE.with(|cell| cell.get()) {
        return epoch;
    }
    *HASH_STORAGE_PROOF_EPOCH.get_or_init(|| hash_storage_proof_epoch_for(0, None))
}

/// Whether `epoch`'s storage registrations, openings and audits are hash-based.
pub fn hash_storage_proofs_at(epoch: u64) -> bool {
    epoch >= hash_storage_proof_epoch()
}

/// GLOBAL frames into an epoch at which leaf data is snapshotted for the next
/// epoch's hash registrations: after the epoch's first session pass (frames
/// 0–7 of an epoch hand committees over), well before renewals are needed.
pub const STORAGE_SNAPSHOT_OFFSET: u64 = 16;

/// The GLOBAL frame whose crossing snapshots leaf data for `target_epoch`'s
/// registrations (made during the epoch before it).
pub fn storage_snapshot_frame(target_epoch: u64) -> u64 {
    target_epoch.saturating_sub(1).saturating_mul(epoch_length_frames()) + STORAGE_SNAPSHOT_OFFSET
}

/// The epoch whose registrations snapshot their leaf data at an app frame
/// anchored at `anchor` whose predecessor was anchored at `previous_anchor`:
/// the shard's state just before its first frame anchored at or after
/// [`storage_snapshot_frame`]. Every member and archive executes the same
/// certified chain, so all of them snapshot the same state. `None` when this
/// frame crosses no snapshot of a hash-proof epoch.
pub fn storage_snapshot_crossed(previous_anchor: u64, anchor: u64) -> Option<u64> {
    let target = epoch_for_frame(anchor) + 1;
    let at = storage_snapshot_frame(target);
    (hash_storage_proofs_at(target) && previous_anchor < at && at <= anchor).then_some(target)
}

/// Set the hash storage proof epoch for the calling thread only (tests).
pub fn set_hash_storage_proof_epoch_for_thread(epoch: Option<u64>) {
    HASH_STORAGE_PROOF_OVERRIDE.with(|cell| cell.set(epoch));
}

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
    /// Superseded by a reassignment (see [`ProverStatus::Historic`]). Excluded
    /// from committees, but NOT terminal — reversible back to Active if the shard
    /// is re-formed.
    Historic,
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
            // Superseded by a reassignment — no grace/epoch semantics; the byte
            // maps straight through. Reversible (a later reassignment flips it
            // back to Active), so it is intentionally NOT in `is_terminal`.
            ProverStatus::Historic => EffectiveStatus::Historic,
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

/// Where an allocation stands at a frame, by effective status, with a
/// confirmed join or leave told apart from an undecided one: a confirmed join
/// is activating until the next boundary, a confirmed leave departing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationPhase {
    Joining,
    Activating,
    Active,
    Paused,
    Leaving,
    Departing,
}

impl ProverAllocationInfo {
    /// The allocation's [`AllocationPhase`] at `frame`; `None` when it is
    /// expired, rejected, kicked, historic or unknown.
    pub fn phase(&self, frame: u64) -> Option<AllocationPhase> {
        Some(match self.effective_status(frame) {
            EffectiveStatus::Joining if self.join_confirm_frame_number > 0 => AllocationPhase::Activating,
            EffectiveStatus::Joining => AllocationPhase::Joining,
            EffectiveStatus::Active => AllocationPhase::Active,
            EffectiveStatus::Paused => AllocationPhase::Paused,
            EffectiveStatus::Leaving if self.leave_confirm_frame_number > 0 => AllocationPhase::Departing,
            EffectiveStatus::Leaving => AllocationPhase::Leaving,
            _ => return None,
        })
    }
}

/// The first frame of `epoch`.
pub fn epoch_start_frame(epoch: u64) -> u64 {
    epoch.saturating_mul(epoch_length_frames())
}

/// What a join of this prover waits for before its allocation joins the
/// committee: a join proposed in epoch E must be confirmed in epoch E+1 and
/// activates at the boundary after its confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinWait {
    /// Not confirmed yet: the confirm is due in `epoch`, which also sets the
    /// earliest activation.
    Confirmation { epoch: u64 },
    /// Confirmed: the allocation joins its committee at frame `frame`.
    Activation { frame: u64 },
}

impl JoinWait {
    /// The first frame the allocation can serve at: the activation frame
    /// once confirmed, else the boundary after the confirm epoch.
    pub fn activation_frame(self) -> u64 {
        match self {
            JoinWait::Confirmation { epoch } => epoch_start_frame(epoch + 1),
            JoinWait::Activation { frame } => frame,
        }
    }
}

impl ProverAllocationInfo {
    /// What the allocation's join waits for at `frame`, by its
    /// [`AllocationPhase`]; `None` unless it is joining or activating
    /// (or a genesis/test allocation without a join frame).
    pub fn join_wait(&self, frame: u64) -> Option<JoinWait> {
        match self.phase(frame)? {
            AllocationPhase::Joining if self.join_frame_number > 0 =>
                Some(JoinWait::Confirmation { epoch: epoch_for_frame(self.join_frame_number) + 1 }),
            AllocationPhase::Activating =>
                Some(JoinWait::Activation { frame: epoch_start_frame(epoch_for_frame(self.join_confirm_frame_number) + 1) }),
            _ => None,
        }
    }
}

/// A shard's provers counted by [`AllocationPhase`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhaseCounts {
    pub joining: u32,
    pub activating: u32,
    pub active: u32,
    pub paused: u32,
    pub leaving: u32,
    pub departing: u32,
}

impl PhaseCounts {
    pub fn add(&mut self, phase: AllocationPhase) {
        let count = match phase {
            AllocationPhase::Joining => &mut self.joining,
            AllocationPhase::Activating => &mut self.activating,
            AllocationPhase::Active => &mut self.active,
            AllocationPhase::Paused => &mut self.paused,
            AllocationPhase::Leaving => &mut self.leaving,
            AllocationPhase::Departing => &mut self.departing,
        };
        *count += 1;
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

/// First mainnet GLOBAL frame finalized by the successor GLOBAL committee:
/// the four genesis archives still running after QmQfp3 was decommissioned
/// (2026-10-20), in consensus epoch 1, with a quorum of 3 of 4. Every earlier
/// frame is finalized by all five genesis archives (4 of 5) in epoch 0, and is
/// verified against them for good. The first frame of epoch 1,261; decided
/// 2026-10-20.
pub const MAINNET_GLOBAL_COMMITTEE_SUCCESSION_FRAME: u64 = 907_920;

static GLOBAL_COMMITTEE_SUCCESSION_FRAME: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);

/// Pin the GLOBAL committee succession from the network id at node startup,
/// like [`init_committee_handoff_for_network`]. Only mainnet has one, and its
/// frame cannot be changed.
pub fn init_global_committee_succession_for_network(network: u8) {
    set_global_committee_succession_frame(if network == 0 {
        MAINNET_GLOBAL_COMMITTEE_SUCCESSION_FRAME
    } else {
        u64::MAX
    });
}

/// Set the succession frame directly (tests). `u64::MAX`: no succession.
pub fn set_global_committee_succession_frame(frame: u64) {
    GLOBAL_COMMITTEE_SUCCESSION_FRAME.store(frame, std::sync::atomic::Ordering::Relaxed);
}

/// The first GLOBAL frame the successor committee finalizes; `u64::MAX` when
/// this network has none.
pub fn global_committee_succession_frame() -> u64 {
    GLOBAL_COMMITTEE_SUCCESSION_FRAME.load(std::sync::atomic::Ordering::Relaxed)
}

/// The GLOBAL consensus epoch, and so the committee, that finalizes GLOBAL
/// frame `frame`: 0 below the succession frame, 1 from it on.
pub fn global_committee_epoch(frame: u64) -> u64 {
    u64::from(frame >= global_committee_succession_frame())
}

/// First GLOBAL frame whose included app frames record each signer's
/// `LastSignedFrameNumber` on its allocation. One inactivity threshold later,
/// when every member has had a full window to sign, the eviction stall census
/// counts an allocation as fresh by that field instead of
/// `LastActiveFrameNumber`, which confirms also advance. Recording the field
/// changes committed allocation trees, so every archive must start at the same
/// frame. `u64::MAX` disables both: no frame records the field and the census
/// keeps reading `LastActiveFrameNumber`.
pub const SIGNED_FRAME_ACTIVATION_FRAME: u64 = u64::MAX;

/// Minimum number of effectively-active provers a shard needs to run its
/// app-shard consensus (form a committee and reach quorum). A shard with
/// FEWER than this many active provers is under a coverage halt and cannot
/// produce a shard frame at all, so its provers physically CANNOT submit a
/// shard proof — they must NOT be evicted for inactivity. Evicting them is a
/// death spiral (too few provers → no frames → everyone evicted → zero
/// provers) and punishes provers for a shortfall that isn't their fault.
///
/// This mirrors the coverage monitor's `halt_threshold` (a shard with
/// `active_count <= 3` is halt-risk), but is a FIXED consensus constant, not
/// the per-node coverage config: eviction is consensus-state-mutating, so
/// every archive must apply the identical exemption or their prover roots
/// diverge. The eviction path derives each shard's active-prover census from
/// committed registry state (not the live coverage monitor) so the exemption
/// is deterministic across the fleet.
pub const MIN_SHARD_CONSENSUS_PROVERS: u64 = 4;

/// Registry inputs for one lifecycle evaluation. Membership lists use the
/// same raw allocation statuses as `get_provers_by_status`; this is planning
/// information, not committee authorization or storage-proof eligibility.
#[derive(Debug, Clone)]
pub struct ProverLifecycleView {
    pub prover: Option<ProverInfo>,
    pub summaries: Vec<ProverShardSummary>,
    pub members: HashMap<Vec<u8>, LifecycleMembers>,
    pub reward_rings: HashMap<Vec<u8>, crate::reward_ring::RewardRingEstimate>,
}

/// A shard's provers as the lifecycle counts them at one frame: who is a
/// member after the next epoch boundary, and whose leave is still undecided.
/// By effective status, not the raw status byte: a confirmed join's byte is
/// already Active but it becomes a member only at the boundary, a confirmed
/// leave keeps its Leaving byte while it departs regardless, and a departed or
/// stale-epoch allocation keeps its byte for good.
#[derive(Debug, Clone, Default)]
pub struct LifecycleMembers {
    /// Effective Active members.
    pub active: Vec<Vec<u8>>,
    /// Confirmed joins that become members at the next boundary.
    pub activating: Vec<Vec<u8>>,
    /// Members whose leave is proposed but not yet confirmed.
    pub leaving: Vec<Vec<u8>>,
}

impl LifecycleMembers {
    /// Count `address`, whose allocation on this shard is `alloc`, by its
    /// effective status at `frame`; confirmed leaves, paused, expired and
    /// terminal allocations are not counted.
    pub fn add(&mut self, address: Vec<u8>, alloc: &ProverAllocationInfo, frame: u64) {
        match alloc.effective_status(frame) {
            EffectiveStatus::Active => self.active.push(address),
            EffectiveStatus::Joining if alloc.join_confirm_frame_number > 0 => self.activating.push(address),
            EffectiveStatus::Leaving if alloc.leave_confirm_frame_number == 0 => self.leaving.push(address),
            _ => {}
        }
    }

    /// How many provers remain members after the boundary if no undecided
    /// leave departs.
    pub fn staying(&self) -> usize {
        self.active.len() + self.activating.len()
    }

    /// Sort each list, so every node orders members the same way.
    pub fn sort(&mut self) {
        self.active.sort();
        self.activating.sort();
        self.leaving.sort();
    }
}

/// Manages the prover trie: state transitions, lookups, eviction.
pub trait ProverRegistry: Send + Sync {
    /// Identify a supported registry implementation before reconstructing an
    /// isolated execution context. Custom registries must opt in explicitly.
    fn as_any(&self) -> Option<&dyn std::any::Any> { None }
    fn get_prover_info(&self, address: &[u8]) -> Result<Option<ProverInfo>>;
    /// Whether the registry holds the store's contents yet. A node loads its
    /// canonical registry in the background at startup and reads it empty
    /// until then; a reader whose decision outlasts the read (releasing
    /// workers, say) checks this first. Registries filled when built are
    /// loaded from the start.
    fn initial_load_complete(&self) -> bool {
        true
    }
    /// Capture the inputs used by lifecycle planning. Concurrent production
    /// registries must override this to capture all fields under one read lock.
    /// The compatibility implementation retains sequential getter semantics
    /// for immutable/test registries; it does not promise atomicity.
    fn get_lifecycle_view(&self, address: &[u8], frame: u64) -> Result<ProverLifecycleView> {
        let prover = self.get_prover_info(address)?;
        let summaries = self.get_prover_shard_summaries(frame)?;
        let filters: std::collections::BTreeSet<_> = prover.iter()
            .flat_map(|p| p.allocations.iter())
            .map(|a| a.confirmation_filter.clone())
            .chain(summaries.iter().map(|s| s.filter.clone()))
            .filter(|f| !f.is_empty()).collect();
        let mut members = HashMap::new();
        let mut reward_rings = HashMap::new();
        for filter in filters {
            if let Some(estimate) = self.get_reward_ring_estimate(address, &filter, frame)? {
                reward_rings.insert(filter.clone(), estimate);
            }
            let mut shard = LifecycleMembers::default();
            for status in [ProverStatus::Active, ProverStatus::Leaving] {
                for p in self.get_provers_by_status(&filter, status)? {
                    if let Some(alloc) = p.allocations.iter().find(|a| a.confirmation_filter == filter && a.status == status) {
                        shard.add(p.address.clone(), alloc, frame);
                    }
                }
            }
            shard.sort();
            members.insert(filter, shard);
        }
        Ok(ProverLifecycleView { prover, summaries, members, reward_rings })
    }
    /// A current or explicitly projected reward position. Concurrent
    /// registries override this to read committee and allocations atomically.
    fn get_reward_ring_estimate(&self, address: &[u8], filter: &[u8], frame: u64)
        -> Result<Option<crate::reward_ring::RewardRingEstimate>> {
        let committee = self.get_active_provers(filter, frame)?;
        let all = self.get_provers(filter)?;
        Ok(crate::reward_ring::estimate_reward_ring(
            &committee.iter().collect::<Vec<_>>(), &all.iter().collect::<Vec<_>>(),
            address, filter, frame))
    }
    /// A member's registered storage leaf root for `leaf_id`, as
    /// `(leaf_root, num_blocks, epoch)`, or `None` if not registered. `leaf_id`
    /// is the opening's `shard_id`. Default `None` (registries that don't track
    /// storage attestation); the real registry overrides it.
    fn get_leaf_root(
        &self,
        _member: &[u8],
        _leaf_id: &[u8],
        _epoch: u64,
    ) -> Result<Option<(Vec<u8>, u64, u64)>> {
        Ok(None)
    }
    /// `member`'s storage seat on `filter` for `epoch`, or `None`.
    fn get_storage_seat_slot(
        &self,
        _member: &[u8],
        _filter: &[u8],
        _epoch: u64,
    ) -> Result<Option<StorageSeatSlot>> {
        Ok(None)
    }
    /// The snapshot `filter`'s registrations for `epoch` commit to, once
    /// GLOBAL has recorded it, or `None`.
    fn get_storage_snapshot(&self, _filter: &[u8], _epoch: u64) -> Result<Option<StorageSnapshotRoots>> {
        Ok(None)
    }
    fn get_next_prover(&self, input: &[u8; 32], filter: &[u8], frame_number: u64) -> Result<Vec<u8>>;
    fn get_ordered_provers(
        &self,
        input: &[u8; 32],
        filter: &[u8],
        frame_number: u64,
    ) -> Result<Vec<Vec<u8>>>;
    /// The epoch-aligned committee under `filter` as of `frame_number` — the
    /// same `effective_status` view the rest of the node uses. Includes `Active`
    /// and `Leaving`-within-grace (a departing member stays in the frozen
    /// committee until the E+2 boundary; from the leaver currency frame only
    /// one that was current when it left); excludes `Joining` (incl.
    /// deferred-activation — a just-confirmed prover that is pre-E+2 and not yet
    /// running its consensus loop), `ExpiredEpoch` (storage-stale), `Leaving`
    /// past grace, and terminal allocations. An empty-committee floor re-admits
    /// demoted-but-raw-`Active` allocations (deferred / stale-epoch) if the
    /// strict set would leave a non-empty filter with no members (see
    /// `committee_eligible`). The empty/global filter is exempt from the epoch
    /// checks, so GLOBAL consensus is unaffected. `frame_number` is the frame
    /// whose committee is being evaluated (produced/validated), so all nodes
    /// agree by construction.
    fn get_active_provers(&self, filter: &[u8], frame_number: u64) -> Result<Vec<ProverInfo>>;
    fn get_prover_count(&self, filter: &[u8]) -> Result<usize>;
    fn get_provers(&self, filter: &[u8]) -> Result<Vec<ProverInfo>>;
    /// The provers of [`Self::get_provers`] over all of `filters` (the empty
    /// filter is the global committee), each once. The default asks
    /// `get_provers` per filter, cloning a prover once per filter it holds;
    /// the persistent registry clones each prover once.
    fn get_provers_on_filters(&self, filters: &[Vec<u8>]) -> Result<Vec<ProverInfo>> {
        let mut by_address: std::collections::HashMap<Vec<u8>, ProverInfo> =
            std::collections::HashMap::new();
        for filter in filters {
            for prover in self.get_provers(filter)? {
                by_address.entry(prover.address.clone()).or_insert(prover);
            }
        }
        Ok(by_address.into_values().collect())
    }
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
        // Test-stub fallback only (production overrides this to walk the
        // per-prover rollup). Stubs ignore the frame arg, so the value is
        // immaterial here.
        self.get_active_provers(&[], 0)
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
    /// Recorded local proposal intent; absent when historical intent is unavailable.
    pub allocation_reason: Option<String>,
    /// Whether the reward position is established or explicitly projected.
    pub ring_known: bool,
    pub filter: Vec<u8>,
    pub shard_size: BigInt,
    pub active_provers: u32,
    pub ring: u32,
    pub estimated_reward: BigInt,
    pub is_allocated: bool,
    pub data_shards: u64,
    pub materialized_frame: u64,
    pub latest_frame: u64,
    /// The shard's provers by lifecycle phase; `None` when not computed.
    pub prover_counts: Option<PhaseCounts>,
}

/// Provides shard-level info.
pub trait ShardInfoProvider: Send + Sync {
    /// Local lifecycle scoring strategy, unavailable on older providers.
    fn allocation_scoring_strategy(&self) -> &'static str { "" }

    /// One committed GLOBAL cursor per filter, from a single snapshot.
    /// Missing coverage/session data stays unavailable; zero is a real cursor.
    fn get_global_app_heads(&self, filters: &[Vec<u8>]) -> Result<Vec<Option<proto::node::GlobalAppFrameHead>>> {
        Ok(vec![None; filters.len()])
    }

    fn get_shard_info(
        &self,
        include_all: bool,
    ) -> Result<(Vec<ShardDetail>, u64, BigInt, u64, BigInt)>;
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
pub(crate) mod epoch_tests {
    use super::*;

    /// The epoch length is process-global, and one test overrides it. Every
    /// test that reads it — which is every test computing a frame from
    /// `EPOCH_LENGTH_FRAMES` — takes this first, so the override is never in
    /// force while another test assumes the default.
    static EPOCH_LENGTH: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(crate) fn epoch_length_guard() -> std::sync::MutexGuard<'static, ()> {
        EPOCH_LENGTH.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Each live allocation has one phase, a confirmed join or leave its own,
    /// and expired allocations none; counts add them up per shard.
    #[test]
    fn allocations_count_by_phase() {
        let _guard = epoch_length_guard();
        let e = EPOCH_LENGTH_FRAMES;
        let frame = 10 * e + 5;
        let with = |status, f: &dyn Fn(&mut ProverAllocationInfo)| {
            let mut a = active_alloc(vec![7], 10);
            a.status = status;
            f(&mut a);
            a
        };
        let allocations = [
            with(ProverStatus::Joining, &|a| a.join_frame_number = 10 * e),
            with(ProverStatus::Active, &|a| a.join_confirm_frame_number = 10 * e + 1),
            with(ProverStatus::Active, &|_| {}),
            with(ProverStatus::Active, &|_| {}),
            with(ProverStatus::Paused, &|_| {}),
            with(ProverStatus::Leaving, &|a| a.leave_frame_number = 10 * e),
            with(ProverStatus::Leaving, &|a| { a.leave_frame_number = 9 * e; a.leave_confirm_frame_number = 10 * e + 2; }),
            with(ProverStatus::Joining, &|a| a.join_frame_number = 2 * e),
            with(ProverStatus::Active, &|a| a.epoch = 8),
        ];
        let mut counts = PhaseCounts::default();
        for a in &allocations {
            if let Some(phase) = a.phase(frame) {
                counts.add(phase);
            }
        }
        assert_eq!(counts, PhaseCounts { joining: 1, activating: 1, active: 2, paused: 1, leaving: 1, departing: 1 });
    }

    /// A join waits for its confirmation in the epoch after the join, then,
    /// once confirmed, for the boundary after the confirmation; an active
    /// allocation waits for neither.
    #[test]
    fn a_join_waits_for_its_confirm_epoch_then_its_activation_boundary() {
        let _guard = epoch_length_guard();
        let e = EPOCH_LENGTH_FRAMES;
        let mut a = active_alloc(vec![7], 0);
        a.status = ProverStatus::Joining;
        a.join_frame_number = 1275 * e + 7;
        let wait = a.join_wait(1275 * e + 29);
        assert_eq!(wait, Some(JoinWait::Confirmation { epoch: 1276 }));
        assert_eq!(wait.map(JoinWait::activation_frame), Some(1277 * e));
        a.status = ProverStatus::Active;
        a.join_confirm_frame_number = 1276 * e + 8;
        a.epoch = 1277;
        assert_eq!(a.join_wait(1276 * e + 9), Some(JoinWait::Activation { frame: 1277 * e }));
        assert_eq!(a.join_wait(1277 * e), None, "active from the boundary");
        a.join_frame_number = 0;
        a.join_confirm_frame_number = 0;
        a.status = ProverStatus::Joining;
        assert_eq!(a.join_wait(5), None, "a genesis join has no confirm epoch");
    }

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
            last_signed_frame_number: 0,
            epoch,
            ring: 0,
            vertex_address: Vec::new(),
        }
    }

    // A frame in epoch `e` (storage attestation is always-on, so any epoch works).
    fn frame_in_epoch(e: u64) -> u64 {
        e * EPOCH_LENGTH_FRAMES + 1
    }

    #[test]
    fn stale_epoch_data_shard_is_expired_always_on() {
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
        let e = epoch_for_frame(frame_in_epoch(3));
        let a = active_alloc(vec![0xAB; 32], e);
        assert_eq!(a.effective_status(frame_in_epoch(3)), EffectiveStatus::Active);
    }

    #[test]
    fn data_shard_active_with_stale_epoch_is_expired() {
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
        let cur = frame_in_epoch(9);
        // Empty filter (global prover), stale epoch 0 — still Active.
        let a = active_alloc(Vec::new(), 0);
        assert_eq!(a.effective_status(cur), EffectiveStatus::Active);
    }

    #[test]
    fn epoch_expiry_inert_within_genesis_epoch() {
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
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

    // ---- Additional lifecycle coverage --------------------------------

    /// Leave PROPOSED but never confirmed: the `leave_confirm == 0` implicit-
    /// expiry branch (symmetric to `join_not_confirmed_in_next_epoch_expires`).
    /// Serves notice through its E+1 slot, then departs as ExpiredLeaving.
    #[test]
    fn leave_proposed_never_confirmed_expires_after_e_plus_1() {
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
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
        let _guard = epoch_length_guard();
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

    /// Members are counted by effective status: a confirmed join is
    /// activating, a confirmed leave and every expired, stale-epoch or paused
    /// allocation is not counted, and only an undecided leave is leaving.
    #[test]
    fn lifecycle_members_count_by_effective_status() {
        let _guard = epoch_length_guard();
        let e = EPOCH_LENGTH_FRAMES;
        let frame = 10 * e + 5;
        let with = |status, f: &dyn Fn(&mut ProverAllocationInfo)| {
            let mut a = active_alloc(vec![7], 10);
            a.status = status;
            f(&mut a);
            a
        };
        let cases = [
            (1u8, with(ProverStatus::Active, &|_| {})),
            (2, with(ProverStatus::Active, &|a| a.join_confirm_frame_number = 10 * e + 1)),
            (3, with(ProverStatus::Active, &|a| a.epoch = 8)),
            (4, with(ProverStatus::Leaving, &|a| { a.leave_frame_number = 9 * e; a.leave_confirm_frame_number = 10 * e + 2; })),
            (5, with(ProverStatus::Leaving, &|a| a.leave_frame_number = 2 * e)),
            (6, with(ProverStatus::Leaving, &|a| a.leave_frame_number = 9 * e + 3)),
            (7, with(ProverStatus::Paused, &|_| {})),
        ];
        let mut members = LifecycleMembers::default();
        for (id, a) in &cases {
            members.add(vec![*id], a, frame);
        }
        assert_eq!(members.active, vec![vec![1]]);
        assert_eq!(members.activating, vec![vec![2]]);
        assert_eq!(members.leaving, vec![vec![6]]);
        assert_eq!(members.staying(), 2);
    }
}

#[cfg(test)]
mod hash_storage_proof_epoch_tests {
    #[test]
    fn only_a_test_network_reads_the_hash_storage_proof_setting() {
        for setting in [None, Some("4"), Some("0"), Some("bad")] {
            assert_eq!(super::hash_storage_proof_epoch_for(0, setting),
                super::MAINNET_HASH_STORAGE_PROOF_EPOCH.unwrap_or(u64::MAX));
        }
        assert_eq!(super::hash_storage_proof_epoch_for(1, Some("4")), 4);
        assert_eq!(super::hash_storage_proof_epoch_for(1, Some("bad")), u64::MAX);
        assert_eq!(super::hash_storage_proof_epoch_for(1, None), u64::MAX);
    }

    /// Mainnet's first hash-proof epoch begins at GLOBAL frame 943,920, and
    /// its snapshot and registrations come in the epoch before.
    #[test]
    fn mainnet_hash_storage_proofs_begin_at_frame_943920() {
        let epoch = super::MAINNET_HASH_STORAGE_PROOF_EPOCH.unwrap();
        assert_eq!(epoch * super::EPOCH_LENGTH_FRAMES, 943_920);
        assert_eq!((epoch - 1) * super::EPOCH_LENGTH_FRAMES, 943_200);
        assert_eq!((epoch - 1) * super::EPOCH_LENGTH_FRAMES + super::STORAGE_SNAPSHOT_OFFSET, 943_216);
    }
}

#[cfg(test)]
mod global_committee_succession_tests {
    use super::*;

    // The only test in this crate that sets the succession frame.
    #[test]
    fn only_mainnet_hands_global_consensus_to_the_successor_committee_at_its_frame() {
        init_global_committee_succession_for_network(1);
        assert_eq!(global_committee_epoch(u64::MAX - 1), 0);
        init_global_committee_succession_for_network(0);
        assert_eq!(global_committee_succession_frame(), 907_920);
        assert_eq!(global_committee_epoch(907_919), 0);
        assert_eq!(global_committee_epoch(907_920), 1);
        assert_eq!(global_committee_epoch(907_921), 1);
        set_global_committee_succession_frame(u64::MAX);
        assert_eq!(global_committee_epoch(907_920), 0);
    }
}

#[cfg(test)]
mod committee_handoff_policy_tests {
    use super::*;

    #[test]
    fn mainnet_activates_its_flag_day_whatever_the_environment_says() {
        let env = |name: &str| match name {
            "QUIL_COMMITTEE_HANDOFF_FRAME" => Some("5".to_string()),
            "QUIL_COMMITTEE_HANDOFF_DISCARD_LEGACY" => Some("0".to_string()),
            _ => None,
        };
        let mainnet = committee_handoff_policy_for_network(0, env).unwrap();
        assert_eq!(mainnet.activation_frame, 861_840);
        assert_eq!(mainnet.activation_frame % 720, 0, "an epoch boundary");
        assert_eq!(mainnet.legacy_history, LegacyHistory::Discard);
        assert_eq!(mainnet.membership_boundary_frame, 862_560);
        assert_eq!(mainnet.membership_boundary_frame % 720, 0, "an epoch boundary");
        assert_eq!(mainnet.first_session_boundary_frame, 864_000);
        assert_eq!(mainnet.first_session_boundary_frame % 720, 0, "an epoch boundary");
        assert_eq!(mainnet.chain_id, committee_handoff_chain_id(0));

        assert_eq!(committee_handoff_policy_for_network(1, |_| None), None, "other networks opt in");
        let testnet = committee_handoff_policy_for_network(1, env).unwrap();
        assert_eq!((testnet.activation_frame, testnet.legacy_history), (5, LegacyHistory::Migrate));
        assert_eq!(testnet.membership_boundary_frame, 5, "on from activation unless set");
        let drill = committee_handoff_policy_for_network(1, |name| match name {
            "QUIL_COMMITTEE_HANDOFF_FRAME" => Some("9".to_string()),
            "QUIL_COMMITTEE_HANDOFF_DISCARD_LEGACY" => Some("1".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!((drill.activation_frame, drill.legacy_history), (9, LegacyHistory::Discard));
        assert_ne!(drill.chain_id, mainnet.chain_id);
    }
}

#[cfg(test)]
mod seniority_succession_epoch_tests {
    #[test]
    fn only_a_test_network_reads_the_seniority_succession_setting() {
        for setting in [None, Some("4"), Some("0"), Some("bad")] {
            assert_eq!(super::seniority_succession_epoch_for(0, setting),
                super::MAINNET_SENIORITY_SUCCESSION_EPOCH.unwrap_or(u64::MAX));
        }
        assert_eq!(super::seniority_succession_epoch_for(1, Some("4")), 4);
        assert_eq!(super::seniority_succession_epoch_for(1, Some("bad")), u64::MAX);
        assert_eq!(super::seniority_succession_epoch_for(1, None), u64::MAX);
    }

    /// Mode selection hangs on this: inert while unset, from the first frame
    /// of the activation epoch once set.
    #[test]
    fn succession_is_active_from_the_first_frame_of_its_epoch() {
        super::set_seniority_succession_epoch_for_thread(Some(u64::MAX));
        assert!(!super::seniority_succession_active(u64::MAX - 1), "inert while unset");
        super::set_seniority_succession_epoch_for_thread(Some(10));
        let first = 10 * super::epoch_length_frames();
        assert!(!super::seniority_succession_active(first - 1));
        assert!(super::seniority_succession_active(first));
        super::set_seniority_succession_epoch_for_thread(None);
        assert_eq!(super::seniority_succession_epoch(),
            super::MAINNET_SENIORITY_SUCCESSION_EPOCH.unwrap_or(u64::MAX));
    }

    #[test]
    fn the_quiet_period_is_two_epochs() {
        assert_eq!(super::SENIORITY_SUCCESSION_QUIET_FRAMES, 1_440);
        assert_eq!(super::seniority_succession_quiet_frames(), 2 * super::epoch_length_frames());
    }
}
