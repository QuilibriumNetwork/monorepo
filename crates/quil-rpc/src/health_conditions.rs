//! The health conditions this node detects, served in its health report.
//!
//! The node owns each condition: it detects it from its own observations,
//! gives it a severity, a scope (this node, a peer, the network), its
//! evidence and the operator's next check, logs it when it starts, at most
//! every [`REPEAT_INTERVAL_MS`] while it lasts and when it ends, and serves
//! the current ones in [`HealthConditions`]. Clients only render them, and
//! every condition served has its start and end line.
//!
//! A condition is served only while its last evaluation found it: one clear
//! is not served. It ends after [`CLEAR_HOLD_MS`] clear; one recurring
//! sooner is served again under its first start, without a line, and its
//! lasting and end lines count those clear spells and the seconds they
//! lasted, so the log can be matched against what a client showed.
//!
//! Missing or old observations establish no condition: a shard's clock
//! restarts after a gap of [`OBSERVATION_GAP_MS`], an unchanged span counts
//! only up to the latest observation, and a kind without fresh
//! observations reports nothing and ends what it reported.
//!
//! Evidence is safe to serve to an allowlisted peer: public shard filters,
//! worker core numbers, frames, counts, times and store read and fsync times,
//! never addresses, keys, paths or peer IDs. A kind whose evidence reveals more
//! than that (amounts, this node's addresses) is [`local_only`]: the report
//! drops it for peers.

use std::collections::{BTreeMap, HashMap, VecDeque};

use num_bigint::{BigInt, Sign};
use quil_engine::global_stall::GlobalReach;
use quil_forest::store_io::{health_cause, SlowCause};
use quil_types::consensus::{EffectiveStatus, SILENT_RENEWAL_BLOCKER};
use quil_types::proto::diagnostics::{
    AffectedShard, ConditionAction, ConditionKind, ConditionScope, ConditionSeverity,
    ConditionSource, ExpectedWait, GlobalProgress, HealthCondition, HealthConditions,
    StoreIoHealth, StoreIoVerdict,
};
use quil_types::proto::node::{
    CertificateShare, FrameCadence, FrameWindow, GlobalAppFrameHead, NodeReachability,
    ShardRewardInfo,
};
use tracing::{error, info, warn};

use crate::reachability::{self, Ipv6Note, Verdict};

/// The shortest window a stall is judged by.
pub const BASE_WINDOW_MS: u64 = 60_000;
/// A slower shard's window spans this many of its mean frame intervals, so
/// a healthy shard is not reported between two of its frames.
pub const CADENCE_INTERVALS: u64 = 3;
/// A committed head trailing the shard's app head by more frames is behind.
pub const GLOBAL_APP_LAG_FRAMES: u64 = 100;
/// A gap between two observations longer than this restarts a shard's
/// clock, and a shard not observed for this long is no longer tracked.
pub const OBSERVATION_GAP_MS: u64 = 150_000;
/// A worker observation older than this is stale (the worker view's
/// threshold).
pub const WORKER_STALE_MS: u64 = 30_000;
/// Affected shards a condition lists; the rest are counted.
pub const MAX_AFFECTED: usize = 64;
/// How often a lasting condition is logged again.
pub const REPEAT_INTERVAL_MS: u64 = 10 * 60_000;
/// A condition clear this long ends; one that recurs sooner continues.
pub const CLEAR_HOLD_MS: u64 = 60_000;
/// A cadence sampled longer ago than this is not fresh.
const CADENCE_FRESH_SECS: u64 = 90;
/// How long a GLOBAL state sync leaves committed GLOBAL state unreadable at
/// most when all is well (its installs take about 80 s); longer is a
/// warning.
pub const GLOBAL_SYNC_EXPECTED_MS: u64 = 10 * 60_000;
/// Frames a prover op takes to land at most: every node refuses one older.
pub const PROVER_OP_MARGIN_FRAMES: u64 =
    quil_execution::global_intrinsic::verify::PROVER_OP_FRESHNESS_WINDOW;
/// How long prover ops wait for the next epoch at most while GLOBAL
/// advances: the margin's frames many times over. Longer means GLOBAL is not
/// advancing, or this node is not following it.
pub const EPOCH_WAIT_EXPECTED_MS: u64 = 10 * 60_000;
/// GLOBAL's head unchanged this long is a stall: four leader timeouts and at
/// least this, so a few skipped leader turns and a frame are not one; a
/// GLOBAL prover's longer leader timeout widens it ([`GlobalReach`]).
pub const GLOBAL_STALL_MS: u64 = quil_engine::global_stall::MIN_STALL_AFTER.as_millis() as u64;
/// GLOBAL advancing fewer frames an hour is slow (10 s frames make 360).
pub const GLOBAL_MIN_FRAMES_PER_HOUR: u64 = 330;
/// GLOBAL's rate is judged over at most this window, once its samples span
/// [`GLOBAL_RATE_MIN_SPAN_MS`].
pub const GLOBAL_RATE_WINDOW_MS: u64 = 3_600_000;
pub const GLOBAL_RATE_MIN_SPAN_MS: u64 = 600_000;
/// Frames a materializing worker normally trails the head peers report: a
/// worker within them has caught up.
pub const RECOVERY_TRAIL_FRAMES: u64 = 2;
/// Base units per QUIL.
pub const UNITS_PER_QUIL: u64 = 0x1_DCD6_5000;
/// The 60m and 24h windows a shard's forecast needs counted before its
/// reward can establish a drop.
const REWARD_HOUR_COVERAGE_SECS: u64 = 1800;
const REWARD_DAY_COVERAGE_SECS: u64 = 7200;

/// Every kind this build judges.
pub const KINDS: [ConditionKind; 27] = [
    ConditionKind::LocalAppFramesUnchanged,
    ConditionKind::PeerAppFramesUnchanged,
    ConditionKind::GlobalAppFramesUnchanged,
    ConditionKind::GlobalAppFramesBehind,
    ConditionKind::GlobalHeadUnchanged,
    ConditionKind::GlobalFramesSlow,
    ConditionKind::AllocationsWithoutWorker,
    ConditionKind::LocalExecutionStopped,
    ConditionKind::AllocationEpochStale,
    ConditionKind::RenewalWithheld,
    ConditionKind::RecoveryFailing,
    ConditionKind::AllocationsRejected,
    ConditionKind::AllocationsPaused,
    ConditionKind::WorkersBoundWithoutAllocation,
    ConditionKind::LocalAppFramesNoneMaterialized,
    ConditionKind::WorkerObservationsStale,
    ConditionKind::CertificateShareLow,
    ConditionKind::ShardHaltRisk,
    ConditionKind::PeerMaterializationLag,
    ConditionKind::RewardDrop,
    ConditionKind::StoreIoSlow,
    ConditionKind::MasterStoreWriteFailed,
    ConditionKind::PeersCannotDial,
    ConditionKind::Ipv6NotPublished,
    ConditionKind::GlobalStateSyncInstalling,
    ConditionKind::ProverOpsWaitForEpoch,
    ConditionKind::ShieldsNotAdmitted,
];

/// The expected waits: each names the event that ends it, and only a wait
/// past its expected time repeats in the log.
pub const WAIT_KINDS: [ConditionKind; 3] = [
    ConditionKind::GlobalStateSyncInstalling,
    ConditionKind::ProverOpsWaitForEpoch,
    ConditionKind::ShieldsNotAdmitted,
];

/// The frames left in the epoch when a prover op signed at `head` may land
/// after it, where every node refuses it: at most
/// [`PROVER_OP_MARGIN_FRAMES`], and at most half an epoch, so a short devnet
/// epoch keeps a time to sign. `None` with an unknown head or epoch length.
pub fn epoch_end_frames_left(head: u64, epoch_length: u64) -> Option<u64> {
    if head == 0 || epoch_length == 0 {
        return None;
    }
    let left = epoch_length - head % epoch_length;
    (left <= PROVER_OP_MARGIN_FRAMES.min(epoch_length / 2)).then_some(left)
}

/// This node's GLOBAL position and settings, as the expected waits judge
/// them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GlobalObservation {
    /// The GLOBAL head this node serves (`last_global_head_frame`); 0
    /// before it knows one.
    pub head_frame: u64,
    pub epoch_length: u64,
    /// The GLOBAL frames from which admission takes shields of legacy coins
    /// (`token shield`, `token shield-all`); `None` when this build admits
    /// none, `u64::MAX` when the network sets no frame.
    pub shields_from: Option<(u64, u64)>,
    /// Whether a GLOBAL state sync has installed some of its chunks but not
    /// the last; `None` when that could not be read.
    pub sync_installing: Option<bool>,
}

/// A seat's signers per frame: the `N3f1` quorum, `n - (n - 1) / 3`, and a
/// frame credits only those signers.
pub fn quorum_signers(n: u32) -> u32 {
    n - n.saturating_sub(1) / 3
}

/// A shard's frame committee: its active provers and seated leavers
/// (`get_active_provers`); joining and paused provers do not sign. Servers
/// without phase counts give only the live count, which includes them.
pub fn committee_size(shard: &ShardRewardInfo) -> u32 {
    shard
        .prover_counts
        .as_ref()
        .map_or(shard.active_provers, |c| c.active + c.leaving + c.departing)
}

/// A cadence window with enough coverage to read. The node withholds a cadence
/// once its latest sample is over 90s old, so freshness on arrival is the node's
/// call on its own clock; the client's clock takes no part.
pub fn observed_window(cadence: &FrameCadence, day: bool) -> Option<&FrameWindow> {
    let w = if day {
        cadence.day.as_ref()?
    } else {
        cadence.hour.as_ref()?
    };
    (w.observed_seconds >= 60 && w.observed_seconds <= w.window_seconds).then_some(w)
}

/// The share of a shard's frames that pay a seat: `paid` of `frames`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningShare {
    pub paid: u64,
    pub frames: u64,
    /// The seat's own certificate share, as the node counted it; else the
    /// share a member voting in time signs, quorum of committee.
    pub measured: bool,
}

/// [`SigningShare`] of a seat in the 60m or 24h window. GLOBAL credits each
/// signer of a frame's certificate the same per-signer reward, so a seat
/// earns the frames it signs: its own share once the node counted a frame
/// in the window, else [`quorum_signers`] of `committee`. A committee of 0
/// or 1 pays every frame.
pub fn signing_share(share: Option<&CertificateShare>, day: bool, committee: u32) -> SigningShare {
    let own = share.and_then(|s| if day { s.day.as_ref() } else { s.hour.as_ref() });
    if let Some(w) = own.filter(|w| w.frames > 0) {
        return SigningShare {
            paid: w.signed_frames.min(w.frames),
            frames: w.frames,
            measured: true,
        };
    }
    let n = committee.max(1);
    SigningShare {
        paid: u64::from(quorum_signers(n)),
        frames: u64::from(n),
        measured: false,
    }
}

/// Observed QUIL/day of a seat on a shard: the shard's observed frame rate
/// times the [`signing_share`] of its frames that pay the seat.
pub fn observed_quil_daily(
    per_frame: &BigInt,
    cadence: &FrameCadence,
    day: bool,
    committee: u32,
    share: Option<&CertificateShare>,
) -> Option<BigInt> {
    let w = observed_window(cadence, day)?;
    let s = signing_share(share, day, committee);
    Some(
        per_frame * BigInt::from(w.advanced_frames) * BigInt::from(86400) * BigInt::from(s.paid)
            / (BigInt::from(w.observed_seconds) * BigInt::from(s.frames)),
    )
}

/// A forecast in base units per day as `~1.2` QUIL.
pub fn format_quil_daily_units(v: &BigInt) -> String {
    let negative = v.sign() == Sign::Minus;
    let magnitude = if negative { -v } else { v.clone() };
    let tenths =
        (&magnitude + BigInt::from(UNITS_PER_QUIL / 20)) / BigInt::from(UNITS_PER_QUIL / 10);
    let text = if magnitude > BigInt::from(0) && tenths == BigInt::from(0) {
        "<0.1".into()
    } else {
        format!("{}.{}", &tenths / 10, &tenths % 10)
    };
    format!("~{}{text}", if negative { "-" } else { "" })
}

/// A latency in microseconds, to two significant figures or so.
fn io_ms(us: u64) -> String {
    match us {
        0..=9_999 => format!("{:.1}ms", us as f64 / 1000.0),
        10_000..=9_999_999 => format!("{}ms", us / 1000),
        _ => format!("{}s", us / 1_000_000),
    }
}

/// The figures of a store I/O interval that it has: the canary reads'
/// p99 and count, a read still pending, the disk's read and write await.
pub fn store_io_figures(io: &StoreIoHealth) -> String {
    let mut parts = Vec::new();
    if io.canary_reads > 0 {
        parts.push(format!(
            "canary p99 {} of {} reads in {}s",
            io_ms(io.canary_p99_us),
            io.canary_reads,
            io.interval_secs
        ));
    }
    if io.canary_pending_us > 0 {
        parts.push(format!("a read pending {}", io_ms(io.canary_pending_us)));
    }
    match (io.disk_read_await_us, io.disk_write_await_us) {
        (Some(read), Some(write)) => parts.push(format!(
            "disk read {}/op, write {}/op",
            io_ms(read),
            io_ms(write)
        )),
        (Some(read), None) => parts.push(format!("disk read {}/op", io_ms(read))),
        (None, Some(write)) => parts.push(format!("disk write {}/op", io_ms(write))),
        (None, None) => {}
    }
    parts.join(", ")
}

/// The store's 4 KiB write and fsync against its bound, both in ms.
fn store_fsync_figure(ms: u64, bound_ms: u64) -> String {
    format!(
        "4 KiB write and fsync {} (bound {})",
        io_ms(ms.saturating_mul(1000)),
        io_ms(bound_ms.saturating_mul(1000))
    )
}

/// The label of the store-slow notice: the cause the figures support
/// (the same rule as the node's warning line).
pub fn store_io_scope(io: &StoreIoHealth) -> &'static str {
    match health_cause(io) {
        SlowCause::Disk => "this node's disk",
        SlowCause::Load => "disk normal, this node's load",
        SlowCause::Unknown => "disk not ruled out",
    }
}

/// A master store that refuses writes, as its condition's notice says it.
pub const MASTER_STORE_WRITE_FAILED: &str =
    "Master store stopped writing (a failed write, or free space below the \
    floor): this node cannot follow GLOBAL until the store is reopened.";

/// A shard's stall window: [`BASE_WINDOW_MS`], widened to
/// [`CADENCE_INTERVALS`] of its mean frame interval on slower shards. The
/// shorter of the fresh 60m and 24h means counts, so an ongoing stall cannot
/// widen its own window past the 24h mean; without a fresh cadence the base
/// window applies.
pub fn stall_window_ms(cadence: Option<&FrameCadence>, now_secs: u64) -> u64 {
    let Some(cadence) = cadence else {
        return BASE_WINDOW_MS;
    };
    if now_secs < cadence.last_observed_unix_seconds
        || now_secs - cadence.last_observed_unix_seconds > CADENCE_FRESH_SECS
    {
        return BASE_WINDOW_MS;
    }
    let fresh = |w: &&FrameWindow| {
        w.observed_seconds >= 60 && w.observed_seconds <= w.window_seconds && w.advanced_frames > 0
    };
    [cadence.hour.as_ref(), cadence.day.as_ref()]
        .into_iter()
        .flatten()
        .filter(fresh)
        .map(|w| {
            w.observed_seconds
                .saturating_mul(CADENCE_INTERVALS)
                .saturating_mul(1000)
                / w.advanced_frames
        })
        .min()
        .map_or(BASE_WINDOW_MS, |ms| ms.max(BASE_WINDOW_MS))
}

/// One worker as the master's worker view and prover registry show it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkerObservation {
    pub core_id: u32,
    pub filter: Vec<u8>,
    /// Its allocation is active or leaving in this node's prover registry.
    pub earning: bool,
    pub state: String,
    pub blocker: String,
    pub observed_unix_ms: u64,
    pub materialized_frame: Option<u64>,
    /// When the materialized frame last advanced; 0 when it has not since
    /// the engine started.
    pub last_advance_unix_ms: u64,
    /// When its latest archive recovery attempt failed, and when one last
    /// finished; 0 when none has.
    pub recovery_error_unix_ms: u64,
    pub recovery_outcome_unix_ms: u64,
}

impl WorkerObservation {
    fn fresh(&self, now_ms: u64) -> bool {
        self.observed_unix_ms != 0
            && now_ms.saturating_sub(self.observed_unix_ms) <= WORKER_STALE_MS
    }

    /// The handoff wait, which older workers classified as a blocker.
    fn handoff(&self) -> bool {
        self.state == "blocked" && self.blocker == "awaiting successor"
    }

    /// A fresh observation of an earning worker in a phase that advances
    /// frames: sync, close, handoff, activation and other waits are
    /// expected lifecycle waits, not stalls.
    fn earning_and_advancing(&self, now_ms: u64) -> bool {
        self.fresh(now_ms)
            && self.earning
            && !self.filter.is_empty()
            && !self.handoff()
            && matches!(
                self.state.as_str(),
                "starting" | "running" | "serving" | "blocked" | "stopped"
            )
    }

    /// An earning, advancing worker that reports its materialized frame.
    fn judged(&self, now_ms: u64) -> bool {
        self.earning_and_advancing(now_ms) && self.materialized_frame.is_some()
    }
}

/// One of this prover's allocations in this node's prover registry at the
/// current frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationObservation {
    pub filter: Vec<u8>,
    pub status: EffectiveStatus,
    /// For a rejected or kicked allocation, or a join that missed its
    /// confirm window: the epoch it was lost in; `None` otherwise or
    /// unknown.
    pub lost_epoch: Option<u64>,
}

impl AllocationObservation {
    /// A row the operator sees: live, or active with a stale epoch.
    fn shown(&self) -> bool {
        self.status.is_live() || self.status == EffectiveStatus::ExpiredEpoch
    }
}

/// One shard row of served shard info: the head peers report for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerObservation {
    pub filter: Vec<u8>,
    pub latest_frame: u64,
    pub materialized_frame: u64,
    pub active_provers: u32,
    /// The generation of the shard's committed session, if known.
    pub generation: Option<u64>,
}

/// One shard row of served shard info, as the shard conditions judge it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShardObservation {
    pub filter: Vec<u8>,
    pub materialized_frame: u64,
    pub latest_frame: u64,
    /// The provers serving after the next epoch boundary, active ones and
    /// confirmed joins; `None` when unreported.
    pub serving_provers: Option<u32>,
    /// The shard holds data, so losing its quorum halts something.
    pub holds_data: bool,
    /// A seat's forecast on this shard in base units per day over the last
    /// 60m and 24h, with both windows covered and its reward known.
    pub forecast: Option<(u64, u64)>,
}

impl ShardObservation {
    pub fn of(info: &ShardRewardInfo) -> Self {
        let per_frame = BigInt::from_bytes_be(Sign::Plus, &info.estimated_reward);
        let committee = committee_size(info);
        let forecast = info
            .frame_cadence
            .as_ref()
            .filter(|_| info.ring_known != Some(false))
            .filter(|cadence| {
                let covered = |w: Option<&FrameWindow>, seconds: u64| {
                    w.is_some_and(|w| w.observed_seconds >= seconds)
                };
                covered(cadence.hour.as_ref(), REWARD_HOUR_COVERAGE_SECS)
                    && covered(cadence.day.as_ref(), REWARD_DAY_COVERAGE_SECS)
            })
            .and_then(|cadence| {
                let daily = |day| {
                    observed_quil_daily(
                        &per_frame,
                        cadence,
                        day,
                        committee,
                        info.certificate_share.as_ref(),
                    )
                    .map(|v| u64::try_from(&v).unwrap_or(u64::MAX))
                };
                Some((daily(false)?, daily(true)?))
            });
        Self {
            filter: info.filter.clone(),
            materialized_frame: info.materialized_frame,
            latest_frame: info.latest_frame,
            serving_provers: info
                .prover_counts
                .as_ref()
                .map(|c| c.active.saturating_add(c.activating)),
            holds_data: info.shard_size.iter().any(|byte| *byte != 0),
            forecast,
        }
    }
}

/// A seat of this node reporting a certificate share.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeatShare {
    pub filter: Vec<u8>,
    /// It is in a low-share episode, as the node's seat tracker judges it.
    pub low: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ReachabilityVerdict {
    cannot_dial: bool,
    ipv6_not_published: bool,
}

#[derive(Debug, Clone)]
struct PeerTrack {
    frame: u64,
    generation: Option<u64>,
    since_ms: u64,
    seen_ms: u64,
}

#[derive(Debug, Clone)]
struct CommittedTrack {
    frame: u64,
    generation: u64,
    /// The GLOBAL frame and the app head when the committed head last
    /// changed (the app head: when first known since).
    global_frame_at_change: u64,
    head_at_change: u64,
    global_frame: u64,
    since_ms: u64,
    seen_ms: u64,
}

/// The GLOBAL head this node knows, as the health task samples it.
#[derive(Debug, Clone, Default)]
struct GlobalTrack {
    head: u64,
    since_ms: u64,
    seen_ms: u64,
    /// `(time, head)` over the rate window.
    samples: VecDeque<(u64, u64)>,
    reach: Option<GlobalReach>,
}

#[derive(Debug, Clone)]
struct Current {
    since_ms: u64,
    last_logged_ms: u64,
    clear_since_ms: Option<u64>,
    /// The clear spells it recurred from, and their total length.
    clear_spells: u32,
    unserved_ms: u64,
    /// An expected wait that lasted past its expected time.
    overran: bool,
    condition: HealthCondition,
    log_evidence: Option<String>,
}

/// A change of a condition, to be logged.
#[derive(Debug, Clone, PartialEq)]
pub enum Transition {
    Started {
        condition: HealthCondition,
        /// Evidence for this node's log that is not served, such as the
        /// labels of unreachable GLOBAL provers.
        log_evidence: Option<String>,
    },
    Lasting {
        condition: HealthCondition,
        duration_ms: u64,
        /// The clear spells it recurred from so far, and their total
        /// length, during which it was not served.
        clear_spells: u32,
        unserved_ms: u64,
        log_evidence: Option<String>,
    },
    /// An expected wait lasted past its expected time: from now on a
    /// warning.
    Overran {
        condition: HealthCondition,
        duration_ms: u64,
    },
    Ended {
        kind: ConditionKind,
        /// From its start to this end.
        duration_ms: u64,
        /// How long it was clear, and so not served, before it ended.
        clear_ms: u64,
        /// Its clear spells from start to end, this last one included, and
        /// their total length, during which it was not served.
        clear_spells: u32,
        unserved_ms: u64,
        /// Its inputs went stale rather than the progress resuming.
        unobserved: bool,
    },
}

/// The node's conditions, fed by its observations and judged on a timer.
#[derive(Debug, Default)]
pub struct HealthRegistry {
    peers: HashMap<Vec<u8>, PeerTrack>,
    committed: HashMap<Vec<u8>, CommittedTrack>,
    workers: Vec<WorkerObservation>,
    workers_seen_ms: u64,
    peers_seen_ms: u64,
    committed_seen_ms: u64,
    global: GlobalObservation,
    global_seen_ms: u64,
    global_head: Option<GlobalTrack>,
    allocations: Vec<AllocationObservation>,
    allocations_seen_ms: u64,
    /// The epoch of the frame the allocations were read at.
    epoch: u64,
    /// When each kind's (worker core, shard) was first judged in the state
    /// that kind holds over the base window.
    held_since: HashMap<(i32, u32, Vec<u8>), u64>,
    shards: Vec<ShardObservation>,
    shards_seen_ms: u64,
    seats: Vec<SeatShare>,
    seats_seen_ms: u64,
    store_io: Option<StoreIoHealth>,
    store_io_seen_ms: u64,
    /// The store's latest write and fsync and its bound, in ms.
    store_fsync: Option<(u64, u64)>,
    store_fsync_seen_ms: u64,
    master_store_write_failed: bool,
    master_store_seen_ms: u64,
    reachability: ReachabilityVerdict,
    reachability_seen_ms: u64,
    /// When each judged worker without an advance was first judged.
    worker_first_seen: HashMap<(u32, Vec<u8>), u64>,
    current: BTreeMap<i32, Current>,
    sources: Vec<ConditionSource>,
}

/// A kind's severity; an expected wait past its expected time is a
/// warning.
fn severity_of(kind: ConditionKind, overran: bool) -> ConditionSeverity {
    if WAIT_KINDS.contains(&kind) && !overran {
        return ConditionSeverity::Info;
    }
    match kind {
        // GLOBAL stopped stalls every shard's inclusion; a seat that does no
        // work, or lost its place, earns nothing.
        ConditionKind::GlobalHeadUnchanged
        | ConditionKind::AllocationsWithoutWorker
        | ConditionKind::LocalExecutionStopped
        | ConditionKind::AllocationsRejected
        | ConditionKind::MasterStoreWriteFailed => ConditionSeverity::Error,
        // A closing session usually keeps its worker until it seals, and a
        // stale observation says only that the state is unknown.
        ConditionKind::WorkersBoundWithoutAllocation | ConditionKind::WorkerObservationsStale => {
            ConditionSeverity::Info
        }
        // A one-frame gap is routine, and the note changes no duty.
        ConditionKind::PeerMaterializationLag | ConditionKind::Ipv6NotPublished => {
            ConditionSeverity::Info
        }
        _ => ConditionSeverity::Warning,
    }
}

fn scope_of(kind: ConditionKind) -> ConditionScope {
    match kind {
        ConditionKind::PeerAppFramesUnchanged | ConditionKind::PeerMaterializationLag => {
            ConditionScope::Peer
        }
        ConditionKind::GlobalAppFramesUnchanged
        | ConditionKind::GlobalAppFramesBehind
        | ConditionKind::GlobalHeadUnchanged
        | ConditionKind::GlobalFramesSlow
        | ConditionKind::ShardHaltRisk
        | ConditionKind::ProverOpsWaitForEpoch
        | ConditionKind::ShieldsNotAdmitted => ConditionScope::Network,
        _ => ConditionScope::ThisNode,
    }
}

fn action_of(kind: ConditionKind) -> ConditionAction {
    match kind {
        ConditionKind::LocalAppFramesUnchanged | ConditionKind::LocalAppFramesNoneMaterialized => {
            ConditionAction::CheckWorkerLogs
        }
        ConditionKind::PeerAppFramesUnchanged | ConditionKind::PeerMaterializationLag => {
            ConditionAction::ComparePeerWithExplorer
        }
        ConditionKind::CertificateShareLow => ConditionAction::CheckSeatWorker,
        ConditionKind::ShardHaltRisk => ConditionAction::CheckShardProvers,
        ConditionKind::RewardDrop => ConditionAction::CheckSeatsAndFrames,
        ConditionKind::StoreIoSlow => ConditionAction::CheckDiskAndLoad,
        ConditionKind::MasterStoreWriteFailed => ConditionAction::ReopenMasterStore,
        ConditionKind::PeersCannotDial | ConditionKind::Ipv6NotPublished => {
            ConditionAction::RunNodeDoctor
        }
        ConditionKind::GlobalStateSyncInstalling => ConditionAction::WaitForGlobalSync,
        ConditionKind::ProverOpsWaitForEpoch => ConditionAction::WaitForNextEpoch,
        ConditionKind::ShieldsNotAdmitted => ConditionAction::WaitForShieldAdmission,
        ConditionKind::GlobalHeadUnchanged => ConditionAction::CheckGlobalHead,
        ConditionKind::GlobalFramesSlow => ConditionAction::CheckGlobalRate,
        ConditionKind::AllocationsWithoutWorker => ConditionAction::BindWorkers,
        ConditionKind::LocalExecutionStopped => ConditionAction::CheckBlockers,
        ConditionKind::AllocationEpochStale => ConditionAction::CheckProverConfirmations,
        ConditionKind::RenewalWithheld => ConditionAction::CheckSilentWorkers,
        ConditionKind::RecoveryFailing => ConditionAction::CheckArchiveRecovery,
        ConditionKind::AllocationsRejected => ConditionAction::CheckAllocations,
        ConditionKind::AllocationsPaused => ConditionAction::ResumeOrLeave,
        ConditionKind::WorkersBoundWithoutAllocation => ConditionAction::CheckWorkerBindings,
        ConditionKind::WorkerObservationsStale => ConditionAction::CheckWorkerProcesses,
        _ => ConditionAction::CheckGlobalInclusion,
    }
}

/// How long an expected wait lasts at most when all is well; `None` for a
/// wait only its frame bounds, and for the other kinds.
fn expected_ms(kind: ConditionKind) -> Option<u64> {
    match kind {
        ConditionKind::GlobalStateSyncInstalling => Some(GLOBAL_SYNC_EXPECTED_MS),
        ConditionKind::ProverOpsWaitForEpoch => Some(EPOCH_WAIT_EXPECTED_MS),
        _ => None,
    }
}

/// Whether `frames` over `span_ms` reach [`GLOBAL_MIN_FRAMES_PER_HOUR`].
fn global_rate_ok(frames: u64, span_ms: u64) -> bool {
    u128::from(frames) * 3_600_000 >= u128::from(GLOBAL_MIN_FRAMES_PER_HOUR) * u128::from(span_ms)
}

/// `seen` while it is fresh at `now_ms`; 0 otherwise.
fn fresh_at(seen: u64, now_ms: u64) -> u64 {
    if seen != 0 && now_ms.saturating_sub(seen) <= OBSERVATION_GAP_MS {
        seen
    } else {
        0
    }
}

/// Whether a kind's evidence reveals more than a peer may get: amounts, or
/// what this node binds and whether peers can dial it. Served to this node
/// only.
pub fn local_only(kind: i32) -> bool {
    matches!(
        ConditionKind::try_from(kind),
        Ok(ConditionKind::RewardDrop
            | ConditionKind::PeersCannotDial
            | ConditionKind::Ipv6NotPublished)
    )
}

/// `health` as a peer may get it: without [`local_only`] kinds, whose sources
/// go too, so a peer cannot tell they exist.
pub fn for_peer(mut health: HealthConditions) -> HealthConditions {
    health.conditions.retain(|c| !local_only(c.kind));
    health.sources.retain(|s| !local_only(s.kind));
    health
}

/// The shards a kind lists, and how many it tracks.
type ShardJudgement = (Vec<AffectedShard>, u32);

/// One kind's judgement in an evaluation.
#[derive(Default)]
struct Judged {
    kind: ConditionKind,
    shards: Vec<AffectedShard>,
    /// Affected beyond the shards listed, for kinds that list none.
    affected: u32,
    tracked: u32,
    observed_unix_ms: u64,
    threshold: u64,
    /// For an expected wait: what ends it, when it is current.
    wait: Option<ExpectedWait>,
    global: Option<GlobalProgress>,
    log_evidence: Option<String>,
    store_io: Option<StoreIoHealth>,
    store_fsync_ms: Option<u64>,
    reward_hour_units: u64,
    reward_day_units: u64,
}

/// GLOBAL's progress judged at one evaluation.
#[derive(Default)]
struct GlobalJudged {
    unchanged: Option<(AffectedShard, GlobalProgress)>,
    slow: Option<(AffectedShard, GlobalProgress)>,
    tracked: u32,
    window_ms: u64,
    unreachable: Option<String>,
}

impl HealthRegistry {
    /// Record the heads peers report, from one served shard info.
    pub fn observe_peers(&mut self, rows: &[PeerObservation], now_ms: u64) {
        for row in rows {
            // Empty or unknown peer metadata and unstaffed shards cannot
            // establish a stall.
            if row.active_provers == 0 || (row.latest_frame == 0 && row.materialized_frame == 0) {
                continue;
            }
            let fresh = PeerTrack {
                frame: row.latest_frame,
                generation: row.generation,
                since_ms: now_ms,
                seen_ms: now_ms,
            };
            let track = self
                .peers
                .entry(row.filter.clone())
                .or_insert_with(|| fresh.clone());
            if track.frame != row.latest_frame
                || track.generation != row.generation
                || now_ms.saturating_sub(track.seen_ms) > OBSERVATION_GAP_MS
            {
                *track = fresh;
            }
            track.seen_ms = now_ms;
        }
        self.peers_seen_ms = now_ms;
    }

    /// The app head of `filter`: the highest of its fresh peer-reported
    /// head and this node's workers' materialized frames on it; 0 unknown.
    fn app_head(&self, filter: &[u8], now_ms: u64) -> u64 {
        let peer = self
            .peers
            .get(filter)
            .filter(|t| now_ms.saturating_sub(t.seen_ms) <= OBSERVATION_GAP_MS)
            .map_or(0, |t| t.frame);
        let local = self
            .workers
            .iter()
            .filter(|w| w.filter == filter && w.fresh(now_ms))
            .filter_map(|w| w.materialized_frame)
            .max()
            .unwrap_or(0);
        peer.max(local)
    }

    /// Record shards' heads in this node's committed GLOBAL state.
    pub fn observe_committed(&mut self, heads: &[(Vec<u8>, GlobalAppFrameHead)], now_ms: u64) {
        for (filter, committed) in heads {
            let head = self.app_head(filter, now_ms);
            let fresh = CommittedTrack {
                frame: committed.frame,
                generation: committed.generation,
                global_frame_at_change: committed.global_frame,
                head_at_change: head,
                global_frame: committed.global_frame,
                since_ms: now_ms,
                seen_ms: now_ms,
            };
            let track = self
                .committed
                .entry(filter.clone())
                .or_insert_with(|| fresh.clone());
            if track.frame != committed.frame
                || track.generation != committed.generation
                || now_ms.saturating_sub(track.seen_ms) > OBSERVATION_GAP_MS
            {
                *track = fresh;
            }
            if track.head_at_change == 0 {
                track.head_at_change = head;
            }
            track.global_frame = track.global_frame.max(committed.global_frame);
            track.seen_ms = now_ms;
        }
        self.committed_seen_ms = now_ms;
    }

    /// Record this node's GLOBAL position and settings.
    pub fn observe_global(&mut self, global: GlobalObservation, now_ms: u64) {
        self.global = global;
        self.global_seen_ms = now_ms;
    }

    /// The expected waits as of the latest GLOBAL observation: each current
    /// one with what ends it. Without a fresh observation, or the inputs a
    /// kind needs, it tracks nothing and reports nothing.
    fn judge_waits(&self, now_ms: u64) -> [Judged; 3] {
        let fresh = self.global_seen_ms != 0
            && now_ms.saturating_sub(self.global_seen_ms) <= OBSERVATION_GAP_MS;
        let g = self.global;
        let observed = |known: bool| {
            if fresh && known {
                self.global_seen_ms
            } else {
                0
            }
        };
        let wait = |until_frame, batch_from_frame, kind| ExpectedWait {
            head_frame: g.head_frame,
            until_frame,
            batch_from_frame,
            expected_secs: expected_ms(kind).unwrap_or(0) / 1000,
        };
        let judged =
            |kind, observed_unix_ms: u64, tracked: bool, threshold, wait: Option<_>| Judged {
                kind,
                shards: Vec::new(),
                tracked: u32::from(observed_unix_ms != 0 && tracked),
                observed_unix_ms,
                threshold,
                wait: wait.filter(|_| observed_unix_ms != 0 && tracked),
                ..Default::default()
            };

        let kind = ConditionKind::GlobalStateSyncInstalling;
        let installing = g.sync_installing == Some(true);
        let sync = judged(
            kind,
            observed(g.sync_installing.is_some()),
            true,
            0,
            installing.then(|| wait(0, 0, kind)),
        );

        let kind = ConditionKind::ProverOpsWaitForEpoch;
        let left = epoch_end_frames_left(g.head_frame, g.epoch_length);
        let epoch = judged(
            kind,
            observed(g.head_frame != 0 && g.epoch_length != 0),
            true,
            PROVER_OP_MARGIN_FRAMES.min(g.epoch_length / 2),
            left.map(|left| wait(g.head_frame + left, 0, kind)),
        );

        // A network that sets no admission frame has no wait to track.
        let kind = ConditionKind::ShieldsNotAdmitted;
        let frames = g
            .shields_from
            .filter(|(single, batch)| *single != u64::MAX && *batch != u64::MAX);
        let shields = judged(
            kind,
            observed(g.head_frame != 0),
            frames.is_some(),
            0,
            frames
                .filter(|(single, batch)| g.head_frame < (*single).max(*batch))
                .map(|(single, batch)| wait(single, single.max(batch), kind)),
        );
        [sync, epoch, shields]
    }

    /// Judge the expected waits at once on `global`, as a report is served:
    /// a client deciding when to sign reads the head it signs at. The
    /// transitions to log.
    pub fn refresh_waits(&mut self, global: GlobalObservation, now_ms: u64) -> Vec<Transition> {
        self.observe_global(global, now_ms);
        self.sources
            .retain(|s| !WAIT_KINDS.iter().any(|k| *k as i32 == s.kind));
        let mut transitions = Vec::new();
        for judged in self.judge_waits(now_ms) {
            self.sources.push(ConditionSource {
                kind: judged.kind as i32,
                observed_unix_ms: judged.observed_unix_ms,
                tracked: judged.tracked,
            });
            if let Some(t) = self.update(judged, now_ms) {
                transitions.push(t);
            }
        }
        transitions
    }

    /// Record the GLOBAL head this node knows (0: unknown) and, on a GLOBAL
    /// prover, the GLOBAL provers it hears.
    pub fn observe_global_head(&mut self, head: u64, reach: Option<GlobalReach>, now_ms: u64) {
        if head == 0 {
            return;
        }
        let mut track = match self.global_head.take() {
            Some(t) if now_ms.saturating_sub(t.seen_ms) <= OBSERVATION_GAP_MS => t,
            _ => GlobalTrack {
                head,
                since_ms: now_ms,
                ..Default::default()
            },
        };
        if track.head != head {
            track.head = head;
            track.since_ms = now_ms;
        }
        track.seen_ms = now_ms;
        track.samples.push_back((now_ms, head));
        while track
            .samples
            .front()
            .is_some_and(|(t, _)| t + GLOBAL_RATE_WINDOW_MS < now_ms)
        {
            track.samples.pop_front();
        }
        track.reach = reach;
        self.global_head = Some(track);
    }

    /// Record the worker view.
    pub fn observe_workers(&mut self, workers: Vec<WorkerObservation>, now_ms: u64) {
        self.workers = workers;
        self.workers_seen_ms = now_ms;
    }

    /// Record this prover's allocations, read at a frame of `epoch`.
    pub fn observe_allocations(
        &mut self,
        allocations: Vec<AllocationObservation>,
        epoch: u64,
        now_ms: u64,
    ) {
        self.allocations = allocations;
        self.epoch = epoch;
        self.allocations_seen_ms = now_ms;
    }

    /// The conditions of this node's allocations and their workers. Each
    /// needs fresh observations of what it compares: without them it tracks
    /// nothing. States that pass at a restart or a rebind (no worker yet, a
    /// blocked start, nothing materialized yet, a worker bound before its
    /// allocation shows, a stale epoch or a missed join read ahead of the
    /// prover registry) count once they held for the base window.
    fn judge_seats(&mut self, now_ms: u64) -> Vec<Judged> {
        let workers_seen = fresh_at(self.workers_seen_ms, now_ms);
        let allocations_seen = fresh_at(self.allocations_seen_ms, now_ms);
        let both_seen = if workers_seen != 0 && allocations_seen != 0 {
            workers_seen.min(allocations_seen)
        } else {
            0
        };
        let workers: &[WorkerObservation] = if workers_seen != 0 {
            &self.workers
        } else {
            &[]
        };
        let allocations: &[AllocationObservation] = if allocations_seen != 0 {
            &self.allocations
        } else {
            &[]
        };
        let (workers_and_allocations, allocations_and_workers) = if both_seen != 0 {
            (workers, allocations)
        } else {
            (&[][..], &[][..])
        };
        let mut held = HashMap::new();
        let mut over_window = |kind: ConditionKind, core_id: u32, filter: &[u8], frame: u64| {
            let key = (kind as i32, core_id, filter.to_vec());
            let since = self.held_since.get(&key).copied().unwrap_or(now_ms);
            held.insert(key, since);
            (now_ms.saturating_sub(since) >= BASE_WINDOW_MS).then(|| AffectedShard {
                filter: filter.to_vec(),
                core_id,
                frame,
                unchanged_since_unix_ms: since,
                window_secs: BASE_WINDOW_MS / 1000,
                lag_frames: 0,
            })
        };
        let allocation = |a: &AllocationObservation| AffectedShard {
            filter: a.filter.clone(),
            ..Default::default()
        };
        let worker = |w: &WorkerObservation| AffectedShard {
            filter: w.filter.clone(),
            core_id: w.core_id,
            frame: w.materialized_frame.unwrap_or(0),
            ..Default::default()
        };
        let shown =
            |list: &[AllocationObservation]| list.iter().filter(|a| a.shown()).count() as u32;

        let due: Vec<_> = allocations_and_workers
            .iter()
            .filter(|a| {
                matches!(
                    a.status,
                    EffectiveStatus::Active
                        | EffectiveStatus::Leaving
                        | EffectiveStatus::ExpiredEpoch
                )
            })
            .collect();
        let workerless = due
            .iter()
            .filter(|a| !workers_and_allocations.iter().any(|w| w.filter == a.filter))
            .filter_map(|a| over_window(ConditionKind::AllocationsWithoutWorker, 0, &a.filter, 0))
            .collect();

        let staffed: Vec<_> = workers
            .iter()
            .filter(|w| w.earning_and_advancing(now_ms))
            .collect();
        let stopped = staffed
            .iter()
            .filter(|w| matches!(w.state.as_str(), "blocked" | "stopped"))
            .filter_map(|w| {
                over_window(
                    ConditionKind::LocalExecutionStopped,
                    w.core_id,
                    &w.filter,
                    w.materialized_frame.unwrap_or(0),
                )
            })
            .collect();

        let reporting: Vec<_> = workers.iter().filter(|w| w.fresh(now_ms)).collect();
        let withheld = reporting
            .iter()
            .filter(|w| both_seen != 0 && w.blocker == SILENT_RENEWAL_BLOCKER)
            .map(|w| worker(w))
            .collect();
        let recovering = reporting
            .iter()
            .filter(|w| w.recovery_error_unix_ms > w.recovery_outcome_unix_ms)
            .filter(|w| {
                // Without both heights nothing is known, so nothing counts
                // as caught up.
                let head = self
                    .peers
                    .get(&w.filter)
                    .filter(|t| now_ms.saturating_sub(t.seen_ms) <= OBSERVATION_GAP_MS)
                    .map_or(0, |t| t.frame);
                let caught_up = head > 0
                    && w.materialized_frame
                        .is_some_and(|h| h > 0 && h + RECOVERY_TRAIL_FRAMES >= head);
                !caught_up
            })
            .map(|w| worker(w))
            .collect();

        let running: Vec<_> = reporting
            .iter()
            .filter(|w| !w.filter.is_empty() && matches!(w.state.as_str(), "running" | "serving"))
            .collect();
        let unmaterialized = running
            .iter()
            .filter(|w| w.materialized_frame == Some(0))
            .filter_map(|w| {
                over_window(
                    ConditionKind::LocalAppFramesNoneMaterialized,
                    w.core_id,
                    &w.filter,
                    0,
                )
            })
            .collect();

        // A worker with no execution report says nothing; one whose report
        // stopped arriving is stale.
        let reported: Vec<_> = workers
            .iter()
            .filter(|w| !w.state.is_empty() || w.observed_unix_ms != 0)
            .collect();
        let stale = reported
            .iter()
            .filter(|w| !w.fresh(now_ms))
            .map(|w| AffectedShard {
                unchanged_since_unix_ms: w.observed_unix_ms,
                ..worker(w)
            })
            .collect();

        // A stale epoch and a missed join are read at this node's freshest
        // frame, which runs ahead of its prover registry while it catches
        // up, as after a restart: they count after the base window. A
        // rejection or a kick is recorded in the registry and counts at once.
        let epoch_stale = allocations
            .iter()
            .filter(|a| a.status == EffectiveStatus::ExpiredEpoch)
            .filter_map(|a| over_window(ConditionKind::AllocationEpochStale, 0, &a.filter, 0))
            .collect();
        let epoch = self.epoch;
        let rejected = allocations
            .iter()
            .filter(|a| {
                matches!(
                    a.status,
                    EffectiveStatus::Rejected
                        | EffectiveStatus::Kicked
                        | EffectiveStatus::ExpiredJoining
                )
            })
            .filter(|a| {
                a.lost_epoch
                    .is_some_and(|lost| lost.saturating_add(1) >= epoch)
            })
            .filter_map(|a| {
                if a.status != EffectiveStatus::ExpiredJoining {
                    return Some(allocation(a));
                }
                over_window(ConditionKind::AllocationsRejected, 0, &a.filter, 0)
            })
            .collect();
        let with_status = |status: EffectiveStatus| {
            allocations
                .iter()
                .filter(|a| a.status == status)
                .map(allocation)
                .collect::<Vec<_>>()
        };
        let live: Vec<&[u8]> = allocations_and_workers
            .iter()
            .filter(|a| a.shown())
            .map(|a| a.filter.as_slice())
            .collect();
        // A restart or a rebind reports its workers' filters before their
        // allocations show, so a bound worker counts after the base window.
        let bound = workers_and_allocations
            .iter()
            .filter(|w| !w.filter.is_empty() && !live.contains(&w.filter.as_slice()))
            .filter_map(|w| {
                over_window(
                    ConditionKind::WorkersBoundWithoutAllocation,
                    w.core_id,
                    &w.filter,
                    w.materialized_frame.unwrap_or(0),
                )
            })
            .collect();

        let base_secs = BASE_WINDOW_MS / 1000;
        let judged = vec![
            Judged {
                kind: ConditionKind::AllocationsWithoutWorker,
                shards: workerless,
                tracked: due.len() as u32,
                observed_unix_ms: both_seen,
                threshold: base_secs,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::LocalExecutionStopped,
                shards: stopped,
                tracked: staffed.len() as u32,
                observed_unix_ms: workers_seen,
                threshold: base_secs,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::AllocationEpochStale,
                shards: epoch_stale,
                tracked: shown(allocations),
                observed_unix_ms: allocations_seen,
                threshold: base_secs,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::RenewalWithheld,
                shards: withheld,
                tracked: shown(allocations_and_workers),
                observed_unix_ms: both_seen,
                threshold: 0,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::RecoveryFailing,
                shards: recovering,
                tracked: reporting.len() as u32,
                observed_unix_ms: workers_seen,
                threshold: RECOVERY_TRAIL_FRAMES,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::AllocationsRejected,
                shards: rejected,
                tracked: allocations.len() as u32,
                observed_unix_ms: allocations_seen,
                threshold: 0,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::AllocationsPaused,
                shards: with_status(EffectiveStatus::Paused),
                tracked: shown(allocations),
                observed_unix_ms: allocations_seen,
                threshold: 0,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::WorkersBoundWithoutAllocation,
                shards: bound,
                tracked: workers_and_allocations.len() as u32,
                observed_unix_ms: both_seen,
                threshold: base_secs,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::LocalAppFramesNoneMaterialized,
                shards: unmaterialized,
                tracked: running.len() as u32,
                observed_unix_ms: workers_seen,
                threshold: base_secs,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::WorkerObservationsStale,
                shards: stale,
                tracked: reported.len() as u32,
                observed_unix_ms: workers_seen,
                threshold: WORKER_STALE_MS / 1000,
                ..Default::default()
            },
        ];
        self.held_since = held;
        judged
    }

    /// Record one served shard info's rows.
    pub fn observe_shards(&mut self, rows: Vec<ShardObservation>, now_ms: u64) {
        self.shards = rows;
        self.shards_seen_ms = now_ms;
    }

    /// Record this node's seats reporting a certificate share.
    pub fn observe_seats(&mut self, seats: Vec<SeatShare>, now_ms: u64) {
        self.seats = seats;
        self.seats_seen_ms = now_ms;
    }

    /// Record the master store's latest I/O interval; `None` before the first
    /// one closes, which establishes nothing.
    pub fn observe_store_io(&mut self, io: Option<StoreIoHealth>, now_ms: u64) {
        if io.is_some() {
            self.store_io = io;
            self.store_io_seen_ms = now_ms;
        }
    }

    /// Record the store's latest 4 KiB write and fsync, which returned at
    /// `sampled_ms`, and the bound from which it delays this node's votes.
    /// A probe that stops returning goes stale like any observation.
    pub fn observe_store_fsync(&mut self, fsync_ms: u64, bound_ms: u64, sampled_ms: u64) {
        self.store_fsync = Some((fsync_ms, bound_ms));
        self.store_fsync_seen_ms = sampled_ms;
    }

    /// Record whether the master store stopped writing.
    pub fn observe_master_store(&mut self, write_failed: bool, now_ms: u64) {
        self.master_store_write_failed = write_failed;
        self.master_store_seen_ms = now_ms;
    }

    /// Record this node's view of its reachability.
    pub fn observe_reachability(&mut self, report: &NodeReachability, now_ms: u64) {
        let assessment = reachability::assess(report);
        self.reachability = ReachabilityVerdict {
            cannot_dial: assessment.verdict == Verdict::NotReachable,
            ipv6_not_published: matches!(assessment.ipv6_note, Some(Ipv6Note::NotPublished { .. })),
        };
        self.reachability_seen_ms = now_ms;
    }

    /// Low seats, of those reporting a share.
    fn judge_certificate_shares(&self, now_ms: u64) -> (Vec<AffectedShard>, u32) {
        if now_ms.saturating_sub(self.seats_seen_ms) > OBSERVATION_GAP_MS {
            return (Vec::new(), 0);
        }
        let low = self
            .seats
            .iter()
            .filter(|seat| seat.low)
            .map(|seat| AffectedShard {
                filter: seat.filter.clone(),
                ..Default::default()
            })
            .collect();
        (low, self.seats.len() as u32)
    }

    /// Shards at halt risk of those whose provers are reported, and shards
    /// whose materialization trails of those with a known head. Unreported
    /// counts and an unknown head establish nothing.
    fn judge_shards(&self, now_ms: u64) -> (ShardJudgement, ShardJudgement) {
        if now_ms.saturating_sub(self.shards_seen_ms) > OBSERVATION_GAP_MS {
            return Default::default();
        }
        let (mut halt, mut halt_tracked, mut lag, mut lag_tracked) = (Vec::new(), 0, Vec::new(), 0);
        for shard in &self.shards {
            if let Some(serving) = shard.serving_provers {
                halt_tracked += 1;
                if shard.holds_data
                    && u64::from(serving) <= quil_engine::provers::proposer::HALT_RISK_PROVER_COUNT
                {
                    halt.push(AffectedShard {
                        filter: shard.filter.clone(),
                        ..Default::default()
                    });
                }
            }
            if shard.latest_frame > 0 {
                lag_tracked += 1;
                if shard.materialized_frame < shard.latest_frame {
                    lag.push(AffectedShard {
                        filter: shard.filter.clone(),
                        frame: shard.materialized_frame,
                        lag_frames: shard.latest_frame - shard.materialized_frame,
                        ..Default::default()
                    });
                }
            }
        }
        ((halt, halt_tracked), (lag, lag_tracked))
    }

    /// The earning seats' forecasts over the last 60m and 24h: `hour` and
    /// `day` in base units per day, and the seats counted. Both windows use
    /// the current per-frame reward, so a drop is in frames, not pricing.
    fn seat_forecasts(&self, now_ms: u64) -> (u128, u128, u32) {
        let (mut hour, mut day, mut seats) = (0u128, 0u128, 0);
        if now_ms.saturating_sub(self.shards_seen_ms) > OBSERVATION_GAP_MS
            || now_ms.saturating_sub(self.workers_seen_ms) > OBSERVATION_GAP_MS
        {
            return (hour, day, seats);
        }
        for worker in self.workers.iter().filter(|w| w.earning) {
            let row = self.shards.iter().find(|s| s.filter == worker.filter);
            if let Some((h, d)) = row.and_then(|s| s.forecast) {
                hour += u128::from(h);
                day += u128::from(d);
                seats += 1;
            }
        }
        (hour, day, seats)
    }

    fn judge_local(
        &mut self,
        now_ms: u64,
        window: &dyn Fn(&[u8]) -> u64,
    ) -> (Vec<AffectedShard>, u32) {
        let mut affected = Vec::new();
        let mut tracked = 0;
        let mut judged_keys = Vec::new();
        let stale = now_ms.saturating_sub(self.workers_seen_ms) > OBSERVATION_GAP_MS;
        for w in self.workers.iter().filter(|w| !stale && w.judged(now_ms)) {
            tracked += 1;
            let key = (w.core_id, w.filter.clone());
            let since = if w.last_advance_unix_ms != 0 {
                w.last_advance_unix_ms
            } else {
                *self.worker_first_seen.entry(key.clone()).or_insert(now_ms)
            };
            judged_keys.push(key);
            let window_ms = window(&w.filter);
            if now_ms.saturating_sub(since) >= window_ms {
                affected.push(AffectedShard {
                    filter: w.filter.clone(),
                    core_id: w.core_id,
                    frame: w.materialized_frame.unwrap_or(0),
                    unchanged_since_unix_ms: since,
                    window_secs: window_ms / 1000,
                    lag_frames: 0,
                });
            }
        }
        self.worker_first_seen
            .retain(|key, _| judged_keys.contains(key));
        (affected, tracked)
    }

    fn judge_peers(
        &mut self,
        now_ms: u64,
        window: &dyn Fn(&[u8]) -> u64,
    ) -> (Vec<AffectedShard>, u32) {
        self.peers
            .retain(|_, t| now_ms.saturating_sub(t.seen_ms) <= OBSERVATION_GAP_MS);
        let mut affected = Vec::new();
        for (filter, t) in &self.peers {
            let window_ms = window(filter);
            // Unchanged only as far as it was observed.
            if t.seen_ms.saturating_sub(t.since_ms) >= window_ms {
                affected.push(AffectedShard {
                    filter: filter.clone(),
                    frame: t.frame,
                    unchanged_since_unix_ms: t.since_ms,
                    window_secs: window_ms / 1000,
                    ..Default::default()
                });
            }
        }
        (affected, self.peers.len() as u32)
    }

    fn judge_committed(
        &mut self,
        now_ms: u64,
        window: &dyn Fn(&[u8]) -> u64,
    ) -> (Vec<AffectedShard>, Vec<AffectedShard>, u32) {
        self.committed
            .retain(|_, t| now_ms.saturating_sub(t.seen_ms) <= OBSERVATION_GAP_MS);
        let (mut unchanged, mut behind, mut tracked) = (Vec::new(), Vec::new(), 0);
        for (filter, t) in &self.committed {
            // A shard without a known app head cannot establish a stall or
            // a lag.
            let head = self.app_head(filter, now_ms);
            if head == 0 {
                continue;
            }
            tracked += 1;
            let window_ms = window(filter);
            if t.seen_ms.saturating_sub(t.since_ms) >= window_ms
                && t.global_frame > t.global_frame_at_change
                && t.head_at_change != 0
                && head > t.head_at_change
            {
                unchanged.push(AffectedShard {
                    filter: filter.clone(),
                    frame: t.frame,
                    unchanged_since_unix_ms: t.since_ms,
                    window_secs: window_ms / 1000,
                    ..Default::default()
                });
            }
            let lag = head.saturating_sub(t.frame);
            if lag > GLOBAL_APP_LAG_FRAMES {
                behind.push(AffectedShard {
                    filter: filter.clone(),
                    frame: t.frame,
                    lag_frames: lag,
                    ..Default::default()
                });
            }
        }
        (unchanged, behind, tracked)
    }

    /// GLOBAL's head unchanged for its window, else its rate below
    /// [`GLOBAL_MIN_FRAMES_PER_HOUR`] once the samples span
    /// [`GLOBAL_RATE_MIN_SPAN_MS`]: a stall is one condition while it lasts
    /// and shows in the rate after it, until the hour has made it up, so a
    /// stall shorter than a reader's gap between reads still shows.
    /// Nothing without a fresh observation.
    fn judge_global(&mut self, now_ms: u64) -> GlobalJudged {
        if self
            .global_head
            .as_ref()
            .is_some_and(|t| now_ms.saturating_sub(t.seen_ms) > OBSERVATION_GAP_MS)
        {
            self.global_head = None;
        }
        let Some(t) = self.global_head.as_ref() else {
            return GlobalJudged {
                window_ms: GLOBAL_STALL_MS,
                ..Default::default()
            };
        };
        let window_ms = global_window_ms(t.reach.as_ref());
        let progress = |advanced_frames, span_ms: u64| {
            let (provers, reachable, quorum) = t
                .reach
                .as_ref()
                .map_or((0, 0, 0), |r| (r.provers, r.reachable, r.quorum));
            GlobalProgress {
                head: t.head,
                advanced_frames,
                span_secs: span_ms / 1000,
                provers: provers as u32,
                reachable: reachable as u32,
                quorum: quorum as u32,
            }
        };
        let mut judged = GlobalJudged {
            tracked: 1,
            window_ms,
            unreachable: t
                .reach
                .as_ref()
                .filter(|r| !r.unreachable.is_empty())
                .map(|r| r.unreachable.join(", ")),
            ..Default::default()
        };
        // Unchanged only as far as it was observed.
        let unchanged_ms = t.seen_ms.saturating_sub(t.since_ms);
        if unchanged_ms >= window_ms {
            let row = AffectedShard {
                frame: t.head,
                unchanged_since_unix_ms: t.since_ms,
                window_secs: window_ms / 1000,
                ..Default::default()
            };
            judged.unchanged = Some((row, progress(0, unchanged_ms)));
        } else if let Some(&(first_ms, first_head)) = t.samples.front() {
            let span_ms = t.seen_ms.saturating_sub(first_ms);
            let frames = t.head.saturating_sub(first_head);
            if span_ms >= GLOBAL_RATE_MIN_SPAN_MS && !global_rate_ok(frames, span_ms) {
                let row = AffectedShard {
                    frame: t.head,
                    window_secs: span_ms / 1000,
                    ..Default::default()
                };
                judged.slow = Some((row, progress(frames, span_ms)));
            }
        }
        judged
    }

    /// Judge every kind at `now_ms`, each shard by its window from
    /// `cadence`; the transitions to log.
    pub fn evaluate(
        &mut self,
        now_ms: u64,
        cadence: &dyn Fn(&[u8]) -> Option<FrameCadence>,
    ) -> Vec<Transition> {
        let now_secs = now_ms / 1000;
        let window = |filter: &[u8]| stall_window_ms(cadence(filter).as_ref(), now_secs);
        let (local, local_tracked) = self.judge_local(now_ms, &window);
        let (peer, peer_tracked) = self.judge_peers(now_ms, &window);
        let (unchanged, behind, committed_tracked) = self.judge_committed(now_ms, &window);
        let global = self.judge_global(now_ms);
        let global_seen = self.global_head.as_ref().map_or(0, |t| t.seen_ms);
        let seats = self.judge_seats(now_ms);
        let fresh = |seen: u64| fresh_at(seen, now_ms);
        let base_secs = BASE_WINDOW_MS / 1000;
        let (seats_low, seats_tracked) = self.judge_certificate_shares(now_ms);
        let ((halt, halt_tracked), (lag, lag_tracked)) = self.judge_shards(now_ms);
        let (reward_hour, reward_day, reward_seats) = self.seat_forecasts(now_ms);
        let reward_dropped = reward_seats > 0 && reward_day > 0 && 2 * reward_hour < reward_day;
        // A verdict of no shard: one thing tracked while it is observed.
        let verdict = |kind, seen: u64, holds: bool| {
            let observed_unix_ms = fresh(seen);
            Judged {
                kind,
                affected: u32::from(holds && observed_unix_ms != 0),
                tracked: u32::from(observed_unix_ms != 0),
                observed_unix_ms,
                ..Default::default()
            }
        };
        // Reads and fsync are judged apart, each while fresh; either holds
        // the one condition of the store.
        let (reads_seen, fsync_seen) = (
            fresh(self.store_io_seen_ms),
            fresh(self.store_fsync_seen_ms),
        );
        let store_io = self
            .store_io
            .filter(|io| reads_seen != 0 && io.verdict() == StoreIoVerdict::Slow);
        let fsync_bound_ms = self.store_fsync.map_or(0, |(_, bound)| bound);
        let store_fsync_ms = self
            .store_fsync
            .filter(|&(ms, bound)| fsync_seen != 0 && ms >= bound)
            .map(|(ms, _)| ms);
        let judged = [
            Judged {
                kind: ConditionKind::LocalAppFramesUnchanged,
                shards: local,
                tracked: local_tracked,
                observed_unix_ms: fresh(self.workers_seen_ms),
                threshold: base_secs,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::PeerAppFramesUnchanged,
                shards: peer,
                tracked: peer_tracked,
                observed_unix_ms: fresh(self.peers_seen_ms),
                threshold: base_secs,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::GlobalAppFramesUnchanged,
                shards: unchanged,
                tracked: committed_tracked,
                observed_unix_ms: fresh(self.committed_seen_ms),
                threshold: base_secs,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::GlobalAppFramesBehind,
                shards: behind,
                tracked: committed_tracked,
                observed_unix_ms: fresh(self.committed_seen_ms),
                threshold: GLOBAL_APP_LAG_FRAMES,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::GlobalHeadUnchanged,
                shards: global
                    .unchanged
                    .iter()
                    .map(|(row, _)| row.clone())
                    .collect(),
                tracked: global.tracked,
                observed_unix_ms: fresh(global_seen),
                threshold: global.window_ms / 1000,
                global: global.unchanged.map(|(_, progress)| progress),
                log_evidence: global.unreachable,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::GlobalFramesSlow,
                shards: global.slow.iter().map(|(row, _)| row.clone()).collect(),
                tracked: global.tracked,
                observed_unix_ms: fresh(global_seen),
                threshold: GLOBAL_MIN_FRAMES_PER_HOUR,
                global: global.slow.map(|(_, progress)| progress),
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::CertificateShareLow,
                shards: seats_low,
                tracked: seats_tracked,
                observed_unix_ms: fresh(self.seats_seen_ms),
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::ShardHaltRisk,
                shards: halt,
                tracked: halt_tracked,
                observed_unix_ms: fresh(self.shards_seen_ms),
                threshold: quil_engine::provers::proposer::HALT_RISK_PROVER_COUNT,
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::PeerMaterializationLag,
                shards: lag,
                tracked: lag_tracked,
                observed_unix_ms: fresh(self.shards_seen_ms),
                ..Default::default()
            },
            Judged {
                kind: ConditionKind::RewardDrop,
                affected: if reward_dropped { reward_seats } else { 0 },
                tracked: reward_seats,
                observed_unix_ms: fresh(self.shards_seen_ms.min(self.workers_seen_ms)),
                reward_hour_units: u64::try_from(reward_hour).unwrap_or(u64::MAX),
                reward_day_units: u64::try_from(reward_day).unwrap_or(u64::MAX),
                ..Default::default()
            },
            Judged {
                store_io,
                store_fsync_ms,
                threshold: fsync_bound_ms,
                ..verdict(
                    ConditionKind::StoreIoSlow,
                    reads_seen.max(fsync_seen),
                    store_io.is_some() || store_fsync_ms.is_some(),
                )
            },
            verdict(
                ConditionKind::MasterStoreWriteFailed,
                self.master_store_seen_ms,
                self.master_store_write_failed,
            ),
            verdict(
                ConditionKind::PeersCannotDial,
                self.reachability_seen_ms,
                self.reachability.cannot_dial,
            ),
            verdict(
                ConditionKind::Ipv6NotPublished,
                self.reachability_seen_ms,
                self.reachability.ipv6_not_published,
            ),
        ];
        self.sources.clear();
        let mut transitions = Vec::new();
        let waits = self.judge_waits(now_ms);
        for mut judged in judged.into_iter().chain(seats).chain(waits) {
            self.sources.push(ConditionSource {
                kind: judged.kind as i32,
                observed_unix_ms: judged.observed_unix_ms,
                tracked: judged.tracked,
            });
            judged
                .shards
                .sort_by(|a, b| a.filter.cmp(&b.filter).then(a.core_id.cmp(&b.core_id)));
            if let Some(t) = self.update(judged, now_ms) {
                transitions.push(t);
            }
        }
        transitions
    }

    fn update(&mut self, judged: Judged, now_ms: u64) -> Option<Transition> {
        let Judged {
            kind,
            mut shards,
            affected,
            tracked,
            threshold,
            wait,
            global,
            log_evidence,
            store_io,
            store_fsync_ms,
            reward_hour_units,
            reward_day_units,
            ..
        } = judged;
        let key = kind as i32;
        // A current wait is one condition of this node; the others count
        // their shards and what they affect beyond them.
        let affected = if wait.is_some() {
            1
        } else {
            affected + shards.len() as u32
        };
        if affected == 0 {
            let current = self.current.get_mut(&key)?;
            let clear_since = *current.clear_since_ms.get_or_insert(now_ms);
            // Without fresh observations nothing holds it open.
            if tracked > 0 && now_ms.saturating_sub(clear_since) < CLEAR_HOLD_MS {
                return None;
            }
            let current = self.current.remove(&key)?;
            let clear_ms = now_ms.saturating_sub(clear_since);
            return Some(Transition::Ended {
                kind,
                duration_ms: now_ms.saturating_sub(current.since_ms),
                clear_ms,
                clear_spells: current.clear_spells + u32::from(clear_ms > 0),
                unserved_ms: current.unserved_ms + clear_ms,
                unobserved: tracked == 0,
            });
        }
        let omitted_shards = shards.len().saturating_sub(MAX_AFFECTED) as u32;
        shards.truncate(MAX_AFFECTED);
        let condition = |since_unix_ms, overran| HealthCondition {
            kind: key,
            severity: severity_of(kind, overran) as i32,
            scope: scope_of(kind) as i32,
            // A drive slow to sync is checked as such, whatever its reads.
            action: if store_fsync_ms.is_some() {
                ConditionAction::CheckStoreFsync
            } else {
                action_of(kind)
            } as i32,
            since_unix_ms,
            affected,
            tracked,
            threshold,
            shards,
            omitted_shards,
            wait,
            global,
            store_io,
            store_fsync_ms,
            reward_hour_units,
            reward_day_units,
        };
        if let Some(current) = self.current.get_mut(&key) {
            // It recurred within its clear hold: count the spell.
            if let Some(clear_since) = current.clear_since_ms.take() {
                current.clear_spells += 1;
                current.unserved_ms += now_ms.saturating_sub(clear_since);
            }
            let duration_ms = now_ms.saturating_sub(current.since_ms);
            let overran = expected_ms(kind).is_some_and(|expected| duration_ms >= expected);
            current.condition = condition(current.since_ms, overran);
            current.log_evidence = log_evidence;
            if overran && !current.overran {
                // An anomaly now: a warning from here on.
                current.overran = true;
                current.last_logged_ms = now_ms;
                return Some(Transition::Overran {
                    condition: current.condition.clone(),
                    duration_ms,
                });
            }
            // An expected wait repeats only once it overran.
            let repeats = !WAIT_KINDS.contains(&kind) || current.overran;
            if repeats && now_ms.saturating_sub(current.last_logged_ms) >= REPEAT_INTERVAL_MS {
                current.last_logged_ms = now_ms;
                return Some(Transition::Lasting {
                    condition: current.condition.clone(),
                    duration_ms: now_ms.saturating_sub(current.since_ms),
                    clear_spells: current.clear_spells,
                    unserved_ms: current.unserved_ms,
                    log_evidence: current.log_evidence.clone(),
                });
            }
            return None;
        }
        let current = Current {
            since_ms: now_ms,
            last_logged_ms: now_ms,
            clear_since_ms: None,
            clear_spells: 0,
            unserved_ms: 0,
            overran: false,
            condition: condition(now_ms, false),
            log_evidence: log_evidence.clone(),
        };
        let started = current.condition.clone();
        self.current.insert(key, current);
        Some(Transition::Started {
            condition: started,
            log_evidence,
        })
    }

    /// The conditions found at the last evaluation, worst first (a clear
    /// one is not served), and every kind's source.
    pub fn snapshot(&self) -> HealthConditions {
        let mut conditions: Vec<HealthCondition> = self
            .current
            .values()
            .filter(|c| c.clear_since_ms.is_none())
            .map(|c| c.condition.clone())
            .collect();
        conditions.sort_by_key(|c| (std::cmp::Reverse(c.severity), c.kind));
        HealthConditions {
            conditions,
            sources: self.sources.clone(),
        }
    }
}

/// The stall window GLOBAL's head is judged by.
fn global_window_ms(reach: Option<&GlobalReach>) -> u64 {
    reach.map_or(GLOBAL_STALL_MS, |r| {
        (r.stall_after.as_millis() as u64).max(GLOBAL_STALL_MS)
    })
}

/// The condition's notice, as the node logs it and clients show it.
pub fn notice_text(c: &HealthCondition) -> String {
    let (affected, tracked, threshold) = (c.affected, c.tracked, c.threshold);
    match ConditionKind::try_from(c.kind).unwrap_or(ConditionKind::Unspecified) {
        ConditionKind::LocalAppFramesUnchanged => {
            format!("Local app frames unchanged >{threshold}s: {affected}/{tracked} allocations.")
        }
        ConditionKind::PeerAppFramesUnchanged => {
            format!("Peer app frames unchanged >{threshold}s: {affected}/{tracked} tracked shards.")
        }
        ConditionKind::GlobalAppFramesUnchanged => format!(
            "Global app frames unchanged >{threshold}s: {affected}/{tracked} tracked shards."
        ),
        ConditionKind::GlobalAppFramesBehind => format!(
            "Global app frames >{threshold} behind app heads: {affected}/{tracked} tracked shards."
        ),
        ConditionKind::GlobalStateSyncInstalling => {
            let expected = c.wait.as_ref().map_or(0, |w| w.expected_secs / 60);
            if c.severity == ConditionSeverity::Warning as i32 {
                format!(
                    "GLOBAL state sync installing >{expected}m: committed GLOBAL state stays \
                     unreadable until its last chunk is in."
                )
            } else {
                "GLOBAL state sync installing: committed shard heads show again once its last \
                 chunk is in."
                    .into()
            }
        }
        ConditionKind::ProverOpsWaitForEpoch => {
            let w = c.wait.unwrap_or_default();
            if c.severity == ConditionSeverity::Warning as i32 {
                format!(
                    "Prover ops waited >{}m for the next epoch at frame {}; the GLOBAL head \
                     stays at {}.",
                    w.expected_secs / 60,
                    w.until_frame,
                    w.head_frame
                )
            } else {
                format!(
                    "Prover ops wait for the next epoch: it starts at frame {} ({} frames).",
                    w.until_frame,
                    w.until_frame.saturating_sub(w.head_frame)
                )
            }
        }
        ConditionKind::ShieldsNotAdmitted => {
            let w = c.wait.unwrap_or_default();
            let to_go = w.batch_from_frame.saturating_sub(w.head_frame);
            if w.until_frame == w.batch_from_frame {
                format!(
                    "Legacy coin shields admitted from GLOBAL frame {}: {to_go} frames to go.",
                    w.until_frame
                )
            } else {
                format!(
                    "Legacy coin shields admitted from GLOBAL frame {}, batches from {}: \
                     {to_go} frames to go.",
                    w.until_frame, w.batch_from_frame
                )
            }
        }
        ConditionKind::GlobalHeadUnchanged => {
            let reach = c.global.as_ref().filter(|g| g.provers > 0);
            match reach {
                Some(g) if g.reachable < g.quorum => format!(
                    "Global head unchanged >{threshold}s: {} of {} GLOBAL provers reachable, {} \
                     needed.",
                    g.reachable, g.provers, g.quorum
                ),
                Some(g) => format!(
                    "Global head unchanged >{threshold}s although {} of {} GLOBAL provers are \
                     reachable ({} needed).",
                    g.reachable, g.provers, g.quorum
                ),
                None => format!("Global head unchanged >{threshold}s."),
            }
        }
        // Each number once: over the full hour (to within a sample) the
        // count is the hourly rate, and a rate equal to the count adds none.
        ConditionKind::GlobalFramesSlow => {
            let g = c.global.unwrap_or_default();
            let frames = g.advanced_frames;
            if g.span_secs + 60 >= GLOBAL_RATE_WINDOW_MS / 1000 {
                format!("Global frames slow: {frames} in the last hour, below {threshold}.")
            } else {
                let minutes = g.span_secs / 60;
                match (frames * 3_600).checked_div(g.span_secs) {
                    Some(rate) if rate != frames => format!(
                        "Global frames slow: {frames} in {minutes} min (~{rate}/h, below \
                         {threshold}/h)."
                    ),
                    _ => format!(
                        "Global frames slow: {frames} in {minutes} min, below {threshold}/h."
                    ),
                }
            }
        }
        ConditionKind::AllocationsWithoutWorker => {
            format!("Allocations without a worker: {affected}/{tracked}.")
        }
        ConditionKind::LocalExecutionStopped => {
            format!("Local execution blocked or stopped: {affected}/{tracked} allocations.")
        }
        ConditionKind::AllocationEpochStale => {
            format!("Allocation epoch stale (re-confirm!): {affected}/{tracked} allocations.")
        }
        ConditionKind::RenewalWithheld => {
            format!("Renewal withheld, no vote sent: {affected}/{tracked} allocations.")
        }
        ConditionKind::RecoveryFailing => {
            format!("Last recovery attempt failed: {affected}/{tracked} workers.")
        }
        ConditionKind::AllocationsRejected => {
            format!("Allocations rejected or kicked: {affected}/{tracked}.")
        }
        ConditionKind::AllocationsPaused => format!("Allocations paused: {affected}/{tracked}."),
        ConditionKind::WorkersBoundWithoutAllocation => {
            format!("Workers bound without an allocation: {affected}/{tracked} workers.")
        }
        ConditionKind::LocalAppFramesNoneMaterialized => {
            format!("Local app frames: none materialized on {affected}/{tracked} allocations.")
        }
        ConditionKind::WorkerObservationsStale => {
            format!("Worker observations stale >{threshold}s: {affected}/{tracked} workers.")
        }
        ConditionKind::CertificateShareLow => {
            format!("Low certificate share (60m): {affected}/{tracked} allocations.")
        }
        ConditionKind::ShardHaltRisk => format!(
            "Shards at halt risk (<={threshold} provers): {affected}/{tracked} tracked shards."
        ),
        ConditionKind::PeerMaterializationLag => {
            format!("Peer materialization trails its head: {affected}/{tracked} tracked shards.")
        }
        ConditionKind::RewardDrop => format!(
            "Reward now 60m {} vs 24h {} Q/d.",
            format_quil_daily_units(&BigInt::from(c.reward_hour_units)),
            format_quil_daily_units(&BigInt::from(c.reward_day_units))
        ),
        // The fsync probe times the disk itself: past its bound, the disk is
        // the cause.
        ConditionKind::StoreIoSlow => match (c.store_fsync_ms, c.store_io) {
            (Some(ms), Some(io)) => format!(
                "Store reads and fsync slow (this node's disk): {}, {}.",
                store_io_figures(&io),
                store_fsync_figure(ms, threshold)
            ),
            (Some(ms), None) => format!(
                "Store fsync slow (this node's disk): {}.",
                store_fsync_figure(ms, threshold)
            ),
            (None, io) => {
                let io = io.unwrap_or_default();
                let figures = store_io_figures(&io);
                let cause = store_io_scope(&io);
                if figures.is_empty() {
                    format!("Store reads slow ({cause}).")
                } else {
                    format!("Store reads slow ({cause}): {figures}.")
                }
            }
        },
        ConditionKind::MasterStoreWriteFailed => MASTER_STORE_WRITE_FAILED.to_string(),
        ConditionKind::PeersCannotDial => {
            "Reachability: peers cannot dial this node; run qclient node doctor.".to_string()
        }
        ConditionKind::Ipv6NotPublished => {
            "IPv6: this node binds an address but publishes none; peers do not learn it."
                .to_string()
        }
        // A kind added after this build: the node is newer than this client.
        ConditionKind::Unspecified => format!(
            "Health condition {} ({}, {}) unknown to this qclient, older than the node: update \
             or restart qclient (the node's log names it).",
            c.kind,
            severity_label(c.severity),
            scope_label(c.scope)
        ),
    }
}

/// The notice of the worst current GLOBAL progress condition, if any, as a
/// clause without its final stop: what a paced shield pauses for.
pub fn global_progress_notice(health: &HealthConditions) -> Option<String> {
    health
        .conditions
        .iter()
        .find(|c| {
            matches!(
                ConditionKind::try_from(c.kind),
                Ok(ConditionKind::GlobalHeadUnchanged | ConditionKind::GlobalFramesSlow)
            )
        })
        .map(|c| notice_text(c).trim_end_matches('.').to_string())
}

/// What the operator checks next.
pub fn action_text(action: i32) -> &'static str {
    match ConditionAction::try_from(action).unwrap_or(ConditionAction::Unspecified) {
        ConditionAction::CheckWorkerLogs => {
            "check the affected workers' logs: sync, close, handoff and activation waits are \
             excluded, so a stop there is an engine or consensus failure"
        }
        ConditionAction::ComparePeerWithExplorer => {
            "compare the shards on the explorer: advancing there means the reporting peer \
             trails, stopped there means the shard halted"
        }
        ConditionAction::CheckGlobalInclusion => {
            "check GLOBAL's inclusion of the shards on the explorer: advancing there means \
             this node's GLOBAL view trails, else GLOBAL is not including them"
        }
        ConditionAction::WaitForGlobalSync => {
            "nothing: committed GLOBAL state reads again once the sync's last chunk is in; past \
             10 min, check the node's `sync phase` and prover tree sync lines"
        }
        ConditionAction::WaitForNextEpoch => {
            "nothing: prover ops are signed once the next epoch starts; past 10 min, check that \
             this node follows GLOBAL"
        }
        ConditionAction::WaitForShieldAdmission => {
            "nothing: shield once GLOBAL reaches the admission frame"
        }
        ConditionAction::CheckGlobalHead => {
            "compare GLOBAL's head on the explorer: stopped there means GLOBAL halted \
             network-wide (a GLOBAL prover's log names the unreachable provers to bring back; \
             with a quorum reachable, look for provers on builds with other activation \
             constants), advancing there means this node stopped following GLOBAL: check its \
             peers and sync"
        }
        ConditionAction::CheckGlobalRate => {
            "compare GLOBAL's frame rate on the explorer: slow there means GLOBAL provers vote \
             late or skip leader turns (their logs count skipped turns), normal there means \
             this node receives GLOBAL frames late: check its peers"
        }
        ConditionAction::BindWorkers => {
            "check the worker allocator's log lines and the free workers: an allocation \
             without a worker does no work and earns nothing until one is bound"
        }
        ConditionAction::CheckBlockers => {
            "read each affected row's blocker and its worker's log: the blocker names what \
             stopped it"
        }
        ConditionAction::CheckProverConfirmations => {
            "check the node's prover confirmation log lines: the node reconfirms each \
             allocation during every epoch, so this epoch's reconfirm has not been recorded"
        }
        ConditionAction::CheckSilentWorkers => {
            "check the workers and restart one that stays silent: a seat renews once its \
             worker votes or restarts, or at the latest four epochs on"
        }
        ConditionAction::CheckArchiveRecovery => {
            "read the recovery's error and failure streak: the worker retries and keeps the \
             leaves it installed; it ends once the worker catches up"
        }
        ConditionAction::CheckAllocations => {
            "check the allocations on the explorer and the node's join and confirmation log \
             lines: a rejected or kicked seat earns nothing until a new join is confirmed"
        }
        ConditionAction::ResumeOrLeave => {
            "resume the paused allocations or leave them: a paused seat earns nothing"
        }
        ConditionAction::CheckWorkerBindings => {
            "expected while a closing session the worker belongs to seals; a binding that \
             outlasts it does work no seat pays for"
        }
        ConditionAction::CheckWorkerProcesses => {
            "check that the workers run and answer: their state is unknown until a report \
             arrives"
        }
        ConditionAction::CheckSeatWorker => {
            "check the seats' workers: blocked or behind their shard, silent, or voting late \
             from CPU load or slow peer connections; frames a seat does not sign earn it nothing"
        }
        ConditionAction::CheckShardProvers => {
            "a join adds coverage to the shards, and a leave from them risks their quorum; \
             compare their provers on the explorer"
        }
        ConditionAction::CheckSeatsAndFrames => {
            "check the allocations' certificate share and their shards' frame intervals: \
             both windows price frames alike, so the drop is in frames credited"
        }
        ConditionAction::CheckDiskAndLoad => {
            "check TRIM, the disk's health and other I/O load, then this node's load (CPU, \
             memory pressure, compaction)"
        }
        ConditionAction::CheckStoreFsync => {
            "the store's drive syncs writes too slowly, which delays this node's votes: check \
             it with iostat -x and what else writes to it, storage label writes included; a \
             DRAM-less drive under load is a common cause: move the store to a drive with a \
             DRAM cache, or run fewer seats"
        }
        ConditionAction::ReopenMasterStore => {
            "free disk space or fix the failed write, then restart the node to reopen the store"
        }
        ConditionAction::RunNodeDoctor => {
            "run qclient node doctor: it gives the verdict per address family and what to change"
        }
        ConditionAction::Unspecified => {
            "update or restart qclient, which does not know this action"
        }
    }
}

pub fn severity_label(severity: i32) -> &'static str {
    match ConditionSeverity::try_from(severity).unwrap_or(ConditionSeverity::Unspecified) {
        ConditionSeverity::Error => "error",
        ConditionSeverity::Warning => "warning",
        ConditionSeverity::Info => "info",
        ConditionSeverity::Unspecified => "unknown severity",
    }
}

pub fn scope_label(scope: i32) -> &'static str {
    match ConditionScope::try_from(scope).unwrap_or(ConditionScope::Unspecified) {
        ConditionScope::ThisNode => "this node",
        ConditionScope::Peer => "peer reports",
        ConditionScope::Network => "the network",
        ConditionScope::Unspecified => "unknown scope",
    }
}

/// The kind's name in log lines.
pub fn kind_label(kind: i32) -> &'static str {
    match ConditionKind::try_from(kind).unwrap_or(ConditionKind::Unspecified) {
        ConditionKind::LocalAppFramesUnchanged => "local_app_frames_unchanged",
        ConditionKind::PeerAppFramesUnchanged => "peer_app_frames_unchanged",
        ConditionKind::GlobalAppFramesUnchanged => "global_app_frames_unchanged",
        ConditionKind::GlobalAppFramesBehind => "global_app_frames_behind",
        ConditionKind::GlobalStateSyncInstalling => "global_state_sync_installing",
        ConditionKind::ProverOpsWaitForEpoch => "prover_ops_wait_for_epoch",
        ConditionKind::ShieldsNotAdmitted => "shields_not_admitted",
        ConditionKind::GlobalHeadUnchanged => "global_head_unchanged",
        ConditionKind::GlobalFramesSlow => "global_frames_slow",
        ConditionKind::AllocationsWithoutWorker => "allocations_without_worker",
        ConditionKind::LocalExecutionStopped => "local_execution_stopped",
        ConditionKind::AllocationEpochStale => "allocation_epoch_stale",
        ConditionKind::RenewalWithheld => "renewal_withheld",
        ConditionKind::RecoveryFailing => "recovery_failing",
        ConditionKind::AllocationsRejected => "allocations_rejected",
        ConditionKind::AllocationsPaused => "allocations_paused",
        ConditionKind::WorkersBoundWithoutAllocation => "workers_bound_without_allocation",
        ConditionKind::LocalAppFramesNoneMaterialized => "local_app_frames_none_materialized",
        ConditionKind::WorkerObservationsStale => "worker_observations_stale",
        ConditionKind::CertificateShareLow => "certificate_share_low",
        ConditionKind::ShardHaltRisk => "shard_halt_risk",
        ConditionKind::PeerMaterializationLag => "peer_materialization_lag",
        ConditionKind::RewardDrop => "reward_drop",
        ConditionKind::StoreIoSlow => "store_io_slow",
        ConditionKind::MasterStoreWriteFailed => "master_store_write_failed",
        ConditionKind::PeersCannotDial => "peers_cannot_dial",
        ConditionKind::Ipv6NotPublished => "ipv6_not_published",
        ConditionKind::Unspecified => "unknown",
    }
}

/// The first affected shards' filter ends, for a log line: filters on one
/// app share their leading bytes, so only the end tells shards apart.
fn shard_names(c: &HealthCondition) -> String {
    let mut text = c
        .shards
        .iter()
        .take(3)
        .map(|s| match s.filter.as_slice() {
            [] => "global".to_string(),
            filter => hex::encode(&filter[filter.len().saturating_sub(6)..]),
        })
        .collect::<Vec<_>>()
        .join(",");
    let more = c.affected.saturating_sub(3);
    if more > 0 {
        text += &format!(",+{more}");
    }
    text
}

/// The longest window the affected shards were judged by.
fn widest_window(c: &HealthCondition) -> u64 {
    c.shards.iter().map(|s| s.window_secs).max().unwrap_or(0)
}

/// The condition's text for a log line. Peers may be given this node's log,
/// which removes reward balances by key: a forecast's amounts stay out of it.
fn log_text(c: &HealthCondition) -> String {
    if c.kind == ConditionKind::RewardDrop as i32 {
        return "Reward forecast over 60m is below half its 24h value.".to_string();
    }
    notice_text(c)
}

/// Why a condition of `kind` ended while its observations stayed fresh.
fn ended_reason(kind: ConditionKind) -> &'static str {
    match kind {
        ConditionKind::GlobalStateSyncInstalling => "GLOBAL state installed",
        ConditionKind::ProverOpsWaitForEpoch => "next epoch started",
        ConditionKind::ShieldsNotAdmitted => "admission frame reached",
        ConditionKind::LocalAppFramesUnchanged
        | ConditionKind::PeerAppFramesUnchanged
        | ConditionKind::GlobalAppFramesUnchanged
        | ConditionKind::GlobalAppFramesBehind
        | ConditionKind::GlobalHeadUnchanged
        | ConditionKind::GlobalFramesSlow => "progress resumed",
        _ => "condition cleared",
    }
}

/// Emit `$($line)*` at the level of `$severity`.
macro_rules! at_severity {
    ($severity:expr, $($line:tt)*) => {
        match ConditionSeverity::try_from($severity) {
            Ok(ConditionSeverity::Error) => error!($($line)*),
            Ok(ConditionSeverity::Info) => info!($($line)*),
            _ => warn!($($line)*),
        }
    };
}

/// Log one transition as one structured line, at the condition's severity:
/// an expected wait starts as info, and warns once it overruns.
pub fn log_transition(transition: &Transition) {
    match transition {
        Transition::Started {
            condition: c,
            log_evidence,
        } => {
            at_severity!(c.severity, condition = kind_label(c.kind), scope = scope_label(c.scope),
                affected = c.affected, tracked = c.tracked, shards = %shard_names(c),
                widest_window_secs = widest_window(c), evidence = log_evidence.as_deref(),
                action = action_text(c.action),
                text = %log_text(c), "health condition started");
        }
        Transition::Lasting {
            condition: c,
            duration_ms,
            clear_spells,
            unserved_ms,
            log_evidence,
        } => {
            at_severity!(c.severity, condition = kind_label(c.kind), scope = scope_label(c.scope),
                affected = c.affected, tracked = c.tracked, shards = %shard_names(c),
                widest_window_secs = widest_window(c), duration_secs = duration_ms / 1000,
                clear_spells, unserved_secs = unserved_ms / 1000,
                evidence = log_evidence.as_deref(),
                action = action_text(c.action), text = %log_text(c),
                "health condition lasting");
        }
        Transition::Overran {
            condition: c,
            duration_ms,
        } => {
            warn!(condition = kind_label(c.kind), scope = scope_label(c.scope),
                duration_secs = duration_ms / 1000,
                expected_secs = c.wait.as_ref().map_or(0, |w| w.expected_secs),
                action = action_text(c.action), text = %log_text(c),
                "health condition overran its expected wait");
        }
        Transition::Ended {
            kind,
            duration_ms,
            clear_ms,
            clear_spells,
            unserved_ms,
            unobserved,
        } => {
            info!(
                condition = kind_label(*kind as i32),
                duration_secs = duration_ms / 1000,
                clear_secs = clear_ms / 1000,
                clear_spells,
                unserved_secs = unserved_ms / 1000,
                reason = if *unobserved {
                    "no fresh observations"
                } else {
                    ended_reason(*kind)
                },
                "health condition ended"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_800_000_000_000;

    fn cadence(now_ms: u64, hour: Option<(u64, u64)>, day: Option<(u64, u64)>) -> FrameCadence {
        let window = |seconds, (observed_seconds, advanced_frames)| FrameWindow {
            window_seconds: seconds,
            observed_seconds,
            advanced_frames,
        };
        FrameCadence {
            last_observed_unix_seconds: now_ms / 1000,
            hour: hour.map(|h| window(3600, h)),
            day: day.map(|d| window(86_400, d)),
        }
    }

    fn peer(filter: u8, frame: u64) -> PeerObservation {
        PeerObservation {
            filter: vec![filter],
            latest_frame: frame,
            active_provers: 3,
            generation: Some(1),
            ..Default::default()
        }
    }

    fn worker(core_id: u32, filter: u8, now_ms: u64, last_advance: u64) -> WorkerObservation {
        WorkerObservation {
            core_id,
            filter: vec![filter],
            earning: true,
            state: "serving".into(),
            observed_unix_ms: now_ms,
            materialized_frame: Some(500),
            last_advance_unix_ms: last_advance,
            ..Default::default()
        }
    }

    fn affected(reg: &HealthRegistry, kind: ConditionKind) -> Option<(u32, u32)> {
        reg.snapshot()
            .conditions
            .iter()
            .find(|c| c.kind == kind as i32)
            .map(|c| (c.affected, c.tracked))
    }

    /// Three of the shard's mean frame intervals, never under the base
    /// window; without a fresh cadence the base window.
    #[test]
    fn stall_window_scales_with_the_shard_cadence() {
        let now = T0 / 1000;
        // 150 s mean: 450 s.
        let slow = cadence(T0, Some((3000, 20)), None);
        assert_eq!(stall_window_ms(Some(&slow), now), 450_000);
        // 10 s mean: the base window.
        let fast = cadence(T0, Some((600, 60)), None);
        assert_eq!(stall_window_ms(Some(&fast), now), BASE_WINDOW_MS);
        assert_eq!(stall_window_ms(None, now), BASE_WINDOW_MS);
        // Sampled over 90 s ago: not fresh.
        assert_eq!(stall_window_ms(Some(&slow), now + 91), BASE_WINDOW_MS);
        // No advance in the hour: the day's mean alone.
        let halted = cadence(T0, Some((3600, 0)), Some((86_400, 576)));
        assert_eq!(stall_window_ms(Some(&halted), now), 450_000);
    }

    /// The shorter fresh mean counts, so a stall that inflates the 60m mean
    /// is bounded by the 24h one.
    #[test]
    fn stall_window_uses_the_shorter_fresh_mean() {
        let now = T0 / 1000;
        // 60m: 600 s mean (1800 s window); 24h: 150 s mean (450 s window).
        let c = cadence(T0, Some((3600, 6)), Some((86_400, 576)));
        assert_eq!(stall_window_ms(Some(&c), now), 450_000);
    }

    /// A 150 s shard is not stalled between frames; a fast shard and one
    /// without a cadence are after 60 s.
    #[test]
    fn peer_stall_is_judged_by_each_shard_window() {
        let mut reg = HealthRegistry::default();
        let slow = cadence(T0, Some((3000, 20)), None);
        let cad = move |f: &[u8]| (f == [1]).then_some(slow);
        let rows = [peer(1, 10), peer(2, 20)];
        for secs in (0..=100).step_by(20) {
            let now = T0 + secs * 1000;
            reg.observe_peers(&rows, now);
            // The test's cadence is pinned to T0: keep it fresh.
            let c = cad;
            let cadence = move |f: &[u8]| {
                c(f).map(|mut x| {
                    x.last_observed_unix_seconds = now / 1000;
                    x
                })
            };
            reg.evaluate(now, &cadence);
        }
        assert_eq!(
            affected(&reg, ConditionKind::PeerAppFramesUnchanged),
            Some((1, 2))
        );
        let c = reg.snapshot();
        let peer_condition = c
            .conditions
            .iter()
            .find(|c| c.kind == ConditionKind::PeerAppFramesUnchanged as i32)
            .unwrap();
        assert_eq!(peer_condition.shards[0].filter, vec![2]);
        assert_eq!(peer_condition.shards[0].window_secs, 60);
        for secs in (120..=480).step_by(20) {
            let now = T0 + secs * 1000;
            reg.observe_peers(&rows, now);
            let c = cad;
            let cadence = move |f: &[u8]| {
                c(f).map(|mut x| {
                    x.last_observed_unix_seconds = now / 1000;
                    x
                })
            };
            reg.evaluate(now, &cadence);
            let slow_flagged =
                affected(&reg, ConditionKind::PeerAppFramesUnchanged) == Some((2, 2));
            assert_eq!(slow_flagged, secs >= 460, "at {secs}s");
        }
    }

    /// A gap longer than the observation gap restarts the clock, and an
    /// unchanged span counts only to the latest observation.
    #[test]
    fn peer_stall_needs_continuous_observations() {
        let mut reg = HealthRegistry::default();
        let none = |_: &[u8]| None;
        reg.observe_peers(&[peer(1, 10)], T0);
        reg.evaluate(T0 + 59_000, &none);
        assert_eq!(affected(&reg, ConditionKind::PeerAppFramesUnchanged), None);
        reg.observe_peers(&[peer(1, 10)], T0 + 59_000);
        // Observed 59 s unchanged, judged at 100 s: not yet.
        reg.evaluate(T0 + 100_000, &none);
        assert_eq!(affected(&reg, ConditionKind::PeerAppFramesUnchanged), None);
        // After a 160 s gap the clock restarts.
        reg.observe_peers(&[peer(1, 10)], T0 + 219_000);
        reg.evaluate(T0 + 219_000, &none);
        assert_eq!(affected(&reg, ConditionKind::PeerAppFramesUnchanged), None);
        reg.observe_peers(&[peer(1, 10)], T0 + 279_000);
        reg.evaluate(T0 + 279_000, &none);
        assert_eq!(
            affected(&reg, ConditionKind::PeerAppFramesUnchanged),
            Some((1, 1))
        );
    }

    /// Only fresh, earning workers in frame-advancing phases count; each
    /// is judged by its shard's window.
    #[test]
    fn local_stall_judges_earning_workers_by_their_shard_window() {
        let mut reg = HealthRegistry::default();
        let now = T0 + 300_000;
        let slow = cadence(now, Some((3000, 20)), None);
        let cad = move |f: &[u8]| (f == [1]).then_some(slow);
        let mut syncing = worker(3, 3, now, T0);
        syncing.state = "syncing".into();
        let mut idle = worker(4, 4, now, T0);
        idle.earning = false;
        let stale = worker(5, 5, now - 31_000, T0);
        let mut handoff = worker(6, 6, now, T0);
        handoff.state = "blocked".into();
        handoff.blocker = "awaiting successor".into();
        reg.observe_workers(
            vec![
                // 300 s without an advance on a 450 s shard: not stalled.
                worker(1, 1, now, T0),
                // 300 s on a shard without a cadence: stalled.
                worker(2, 2, now, T0),
                syncing,
                idle,
                stale,
                handoff,
            ],
            now,
        );
        reg.evaluate(now, &cad);
        assert_eq!(
            affected(&reg, ConditionKind::LocalAppFramesUnchanged),
            Some((1, 2))
        );
        let snapshot = reg.snapshot();
        let c = &snapshot.conditions[0];
        assert_eq!(c.shards[0].core_id, 2);
        assert_eq!(c.scope, ConditionScope::ThisNode as i32);
        assert_eq!(
            notice_text(c),
            "Local app frames unchanged >60s: 1/2 allocations."
        );
    }

    /// A worker that never advanced is judged from when it was first seen.
    #[test]
    fn local_stall_without_an_advance_counts_from_the_first_sighting() {
        let mut reg = HealthRegistry::default();
        let none = |_: &[u8]| None;
        reg.observe_workers(vec![worker(1, 1, T0, 0)], T0);
        reg.evaluate(T0, &none);
        reg.observe_workers(vec![worker(1, 1, T0 + 59_000, 0)], T0 + 59_000);
        reg.evaluate(T0 + 59_000, &none);
        assert_eq!(affected(&reg, ConditionKind::LocalAppFramesUnchanged), None);
        reg.observe_workers(vec![worker(1, 1, T0 + 60_000, 0)], T0 + 60_000);
        reg.evaluate(T0 + 60_000, &none);
        assert_eq!(
            affected(&reg, ConditionKind::LocalAppFramesUnchanged),
            Some((1, 1))
        );
    }

    fn committed(frame: u64, global_frame: u64) -> GlobalAppFrameHead {
        GlobalAppFrameHead {
            frame,
            global_frame,
            generation: 1,
        }
    }

    /// The committed head is unchanged only while GLOBAL and the shard's
    /// app frames both advance; a halted shard is not GLOBAL's lag.
    #[test]
    fn global_stall_needs_global_and_app_progress() {
        let none = |_: &[u8]| None;
        // App frames advance, GLOBAL advances, committed head stays.
        let mut reg = HealthRegistry::default();
        for (i, secs) in [0u64, 30, 60].into_iter().enumerate() {
            let now = T0 + secs * 1000;
            reg.observe_peers(&[peer(1, 100 + i as u64)], now);
            reg.observe_committed(&[(vec![1], committed(90, 1000 + i as u64))], now);
            reg.evaluate(now, &none);
        }
        assert_eq!(
            affected(&reg, ConditionKind::GlobalAppFramesUnchanged),
            Some((1, 1))
        );
        // The shard's app head stays too: no GLOBAL claim.
        let mut halted = HealthRegistry::default();
        for (i, secs) in [0u64, 30, 60].into_iter().enumerate() {
            let now = T0 + secs * 1000;
            halted.observe_peers(&[peer(1, 100)], now);
            halted.observe_committed(&[(vec![1], committed(90, 1000 + i as u64))], now);
            halted.evaluate(now, &none);
        }
        assert_eq!(
            affected(&halted, ConditionKind::GlobalAppFramesUnchanged),
            None
        );
        // GLOBAL stays: no inclusion claim.
        let mut stopped = HealthRegistry::default();
        for (i, secs) in [0u64, 30, 60].into_iter().enumerate() {
            let now = T0 + secs * 1000;
            stopped.observe_peers(&[peer(1, 100 + i as u64)], now);
            stopped.observe_committed(&[(vec![1], committed(90, 1000))], now);
            stopped.evaluate(now, &none);
        }
        assert_eq!(
            affected(&stopped, ConditionKind::GlobalAppFramesUnchanged),
            None
        );
    }

    /// Behind: the committed head trails the app head by over 100 frames.
    #[test]
    fn global_behind_counts_lag_over_the_threshold() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        reg.observe_peers(&[peer(1, 200), peer(2, 201)], T0);
        reg.observe_committed(
            &[
                (vec![1], committed(100, 1000)),
                (vec![2], committed(100, 1000)),
            ],
            T0,
        );
        reg.evaluate(T0, &none);
        let snapshot = reg.snapshot();
        let c = snapshot
            .conditions
            .iter()
            .find(|c| c.kind == ConditionKind::GlobalAppFramesBehind as i32)
            .unwrap();
        assert_eq!((c.affected, c.tracked), (1, 2));
        assert_eq!(c.shards[0].lag_frames, 101);
        assert_eq!(
            notice_text(c),
            "Global app frames >100 behind app heads: 1/2 tracked shards."
        );
    }

    /// A condition logs its start once, lasts through a short clear spell
    /// with its first start time, repeats at most every 10 minutes and ends
    /// after a clear minute; a restart is logged however soon it comes;
    /// stale inputs end it at once.
    #[test]
    fn conditions_start_last_and_end_with_bounded_lines() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        let step = |reg: &mut HealthRegistry, secs: u64, frame: u64| {
            let now = T0 + secs * 1000;
            reg.observe_peers(&[peer(1, frame)], now);
            reg.evaluate(now, &none)
        };
        assert!(step(&mut reg, 0, 10).is_empty());
        let started = step(&mut reg, 60, 10);
        assert!(matches!(started.as_slice(), [Transition::Started { .. }]));
        let since = reg.snapshot().conditions[0].since_unix_ms;
        // It advances once, then stalls again within the clear hold.
        assert!(step(&mut reg, 75, 11).is_empty());
        assert!(
            reg.snapshot().conditions.is_empty(),
            "clear while it advances"
        );
        assert!(step(&mut reg, 135, 11).is_empty());
        assert_eq!(reg.snapshot().conditions[0].since_unix_ms, since);
        // Lasting lines at most every 10 minutes.
        let mut lasting = 0;
        for secs in (150..=1300).step_by(15) {
            for t in step(&mut reg, secs, 11) {
                assert!(matches!(t, Transition::Lasting { .. }), "{t:?}");
                lasting += 1;
            }
        }
        assert_eq!(lasting, 2);
        // Progress resumes: it ends after a clear minute.
        assert!(step(&mut reg, 1315, 12).is_empty());
        assert!(step(&mut reg, 1330, 13).is_empty());
        let ended = step(&mut reg, 1375, 14);
        assert!(
            matches!(
                ended.as_slice(),
                [Transition::Ended {
                    unobserved: false,
                    ..
                }]
            ),
            "{ended:?}"
        );
        // A start: logged.
        let again = step(&mut reg, 1500, 14);
        assert!(
            matches!(again.as_slice(), [Transition::Started { .. }]),
            "{again:?}"
        );
        assert!(step(&mut reg, 1515, 15).is_empty());
        let ended = step(&mut reg, 1575, 16);
        assert!(
            matches!(ended.as_slice(), [Transition::Ended { .. }]),
            "{ended:?}"
        );
        // A restart within 10 minutes of the last start line: logged too.
        let restart = step(&mut reg, 1650, 16);
        assert!(
            matches!(restart.as_slice(), [Transition::Started { .. }]),
            "a restart is logged: {restart:?}"
        );
        // Inputs go stale: it ends at once, unobserved, never clear first.
        let stale = reg.evaluate(T0 + 1850 * 1000, &none);
        assert!(
            matches!(
                stale.as_slice(),
                [Transition::Ended {
                    unobserved: true,
                    clear_ms: 0,
                    ..
                }]
            ),
            "{stale:?}"
        );
        assert!(reg.snapshot().conditions.is_empty());
        let source = reg
            .snapshot()
            .sources
            .into_iter()
            .find(|s| s.kind == ConditionKind::PeerAppFramesUnchanged as i32)
            .unwrap();
        assert_eq!((source.observed_unix_ms, source.tracked), (0, 0));
    }

    /// Every condition served has its start and end line, however soon it
    /// recurs, so a client shows only what the log records. A manager that
    /// polls 90 s of every 5 min feeds the peer heads: each poll window
    /// starts a condition and each gap ends it.
    #[test]
    fn every_served_condition_has_a_start_and_an_end_line() {
        let none = |_: &[u8]| None;
        let kind = ConditionKind::PeerAppFramesUnchanged;
        let mut reg = HealthRegistry::default();
        let (mut open, mut starts, mut ends) = (false, 0, 0);
        for secs in (0..3600u64).step_by(15) {
            let now = T0 + secs * 1000;
            if secs % 300 < 90 {
                reg.observe_peers(&[peer(1, 10)], now);
            }
            for t in reg.evaluate(now, &none) {
                match t {
                    Transition::Started { condition, .. } if condition.kind == kind as i32 => {
                        assert!(!open, "a second start line at {secs}s");
                        open = true;
                        starts += 1;
                    }
                    Transition::Ended { kind: k, .. } if k == kind => {
                        assert!(open, "an end line without a start at {secs}s");
                        open = false;
                        ends += 1;
                    }
                    _ => {}
                }
            }
            let served = affected(&reg, kind).is_some();
            assert!(!served || open, "served without a start line at {secs}s");
        }
        assert_eq!(
            (starts, ends),
            (12, 12),
            "one start and end per poll window"
        );
    }

    /// An end line's duration runs from its start line to it, and it names
    /// how long the condition was clear, and so not served, before it ended.
    #[test]
    fn an_end_line_spans_from_its_start_and_names_its_clear_spell() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        let mut lines = Vec::new();
        for secs in (0..=165u64).step_by(15) {
            let now = T0 + secs * 1000;
            // Unchanged to 75 s (a start at 60 s), then advancing from 90 s.
            let frame = if secs < 90 { 10 } else { secs };
            reg.observe_peers(&[peer(1, frame)], now);
            lines.extend(reg.evaluate(now, &none));
        }
        let ended: Vec<_> = lines
            .iter()
            .filter_map(|t| match t {
                Transition::Ended {
                    duration_ms,
                    clear_ms,
                    ..
                } => Some((*duration_ms, *clear_ms)),
                _ => None,
            })
            .collect();
        // Started at 60 s, clear from 90 s, ended at 150 s.
        assert_eq!(
            ended,
            vec![(90_000, 60_000)],
            "the end line's duration from its start and its clear spell"
        );
    }

    /// A condition is not served while clear. One that recurs within its
    /// clear hold continues under its first start without a line, and its
    /// lasting and end lines count those clear spells and their length, so
    /// the log accounts for each time a client showed nothing.
    #[test]
    fn an_end_line_counts_the_clear_spells_a_condition_was_not_served() {
        let none = |_: &[u8]| None;
        let kind = ConditionKind::LocalAppFramesUnchanged;
        let mut reg = HealthRegistry::default();
        let mut step = |secs: u64, advanced: u64| {
            let now = T0 + secs * 1000;
            reg.observe_workers(vec![worker(1, 1, now, T0 + advanced * 1000)], now);
            let lines = reg.evaluate(now, &none);
            (lines, reg.snapshot())
        };
        let served = |s: &HealthConditions| {
            s.conditions
                .iter()
                .find(|c| c.kind == kind as i32)
                .map(|c| c.since_unix_ms)
        };
        let (lines, _) = step(45, 0);
        assert!(lines.is_empty(), "{lines:?}");
        let (lines, s) = step(60, 0);
        assert!(matches!(lines.as_slice(), [Transition::Started { .. }]));
        let since = served(&s).unwrap();
        // An advance at 30 s, first reported at 75 s: clear for 15 s.
        let (lines, s) = step(75, 30);
        assert!(lines.is_empty(), "{lines:?}");
        assert_eq!(served(&s), None, "not served while clear at 75s");
        // Unchanged 60 s at 90 s: served again under its first start.
        let (lines, s) = step(90, 30);
        assert!(lines.is_empty(), "a recurrence adds no line: {lines:?}");
        assert_eq!(served(&s), Some(since), "served under its first start");
        let mut lasting = Vec::new();
        for secs in (105..=690).step_by(15) {
            let (lines, s) = step(secs, 30);
            assert_eq!(served(&s), Some(since), "served at {secs}s");
            lasting.extend(lines.into_iter().filter_map(|t| match t {
                Transition::Lasting {
                    clear_spells,
                    unserved_ms,
                    ..
                } => Some((clear_spells, unserved_ms)),
                _ => None,
            }));
        }
        assert_eq!(
            lasting,
            vec![(1, 15_000)],
            "the lasting line counts the unserved spell so far"
        );
        // Progress resumes at 705 s: clear, and ended after 60 s clear.
        for secs in (705..=750).step_by(15) {
            let (lines, s) = step(secs, secs);
            assert!(lines.is_empty(), "{lines:?}");
            assert_eq!(served(&s), None, "not served while clear at {secs}s");
        }
        let (lines, s) = step(765, 765);
        assert_eq!(served(&s), None);
        let ended: Vec<_> = lines
            .iter()
            .filter_map(|t| match t {
                Transition::Ended {
                    duration_ms,
                    clear_ms,
                    clear_spells,
                    unserved_ms,
                    ..
                } => Some((*duration_ms, *clear_ms, *clear_spells, *unserved_ms)),
                _ => None,
            })
            .collect();
        // Started at 60 s, clear 75-90 s and 705-765 s, ended at 765 s.
        assert_eq!(
            ended,
            vec![(705_000, 60_000, 2, 75_000)],
            "the end line counts each unserved clear spell and their length"
        );
    }

    /// Every kind reports its source, observed or not, and a condition
    /// lists at most 64 shards.
    #[test]
    fn snapshot_reports_every_source_and_bounds_shards() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        let rows: Vec<_> = (0..100u8).map(|f| peer(f, 10)).collect();
        reg.observe_peers(&rows, T0);
        reg.observe_peers(&rows, T0 + 60_000);
        reg.evaluate(T0 + 60_000, &none);
        let snapshot = reg.snapshot();
        assert_eq!(snapshot.sources.len(), KINDS.len());
        let c = &snapshot.conditions[0];
        assert_eq!((c.affected, c.tracked), (100, 100));
        assert_eq!((c.shards.len(), c.omitted_shards), (64, 36));
    }

    /// Filters on one app differ only at their end, so a log line naming
    /// shards by their first bytes would name every shard alike.
    #[test]
    fn a_log_line_tells_shards_of_one_app_apart() {
        let filter = |end: u8| {
            let mut f = vec![0x11; 32];
            f.extend([0x90, end]);
            f
        };
        let condition = HealthCondition {
            affected: 4,
            shards: [0x01, 0x02, 0x03, 0x04]
                .iter()
                .map(|end| AffectedShard {
                    filter: filter(*end),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            shard_names(&condition),
            "111111119001,111111119002,111111119003,+1"
        );
    }

    /// A node on a 720-frame epoch at `head`: no shields, its sync state
    /// unread.
    fn at_head(head: u64) -> GlobalObservation {
        GlobalObservation {
            head_frame: head,
            epoch_length: 720,
            shields_from: None,
            sync_installing: None,
        }
    }

    /// `kind`'s current condition.
    fn current(reg: &HealthRegistry, kind: ConditionKind) -> Option<HealthCondition> {
        reg.snapshot()
            .conditions
            .into_iter()
            .find(|c| c.kind == kind as i32)
    }

    /// `kind`'s source: when it was observed and what it tracks.
    fn source_of(reg: &HealthRegistry, kind: ConditionKind) -> (u64, u32) {
        let s = reg
            .snapshot()
            .sources
            .into_iter()
            .find(|s| s.kind == kind as i32)
            .expect("every kind reports its source");
        (s.observed_unix_ms, s.tracked)
    }

    /// Only an epoch's last frames hold prover ops, where one may land in
    /// the next epoch: the freshness window on a mainnet epoch, half of a
    /// short devnet one; nothing without a head or an epoch length.
    #[test]
    fn only_the_end_of_an_epoch_holds_prover_ops() {
        assert_eq!(PROVER_OP_MARGIN_FRAMES, 10);
        assert_eq!(epoch_end_frames_left(720 - 11, 720), None);
        assert_eq!(epoch_end_frames_left(720 - 10, 720), Some(10));
        assert_eq!(epoch_end_frames_left(719, 720), Some(1));
        assert_eq!(epoch_end_frames_left(720, 720), None);
        assert_eq!(epoch_end_frames_left(89, 30), Some(1));
        assert_eq!(epoch_end_frames_left(79, 30), None);
        assert_eq!(epoch_end_frames_left(80, 30), Some(10));
        assert_eq!(epoch_end_frames_left(4, 10), None);
        assert_eq!(epoch_end_frames_left(5, 10), Some(5));
        assert_eq!(epoch_end_frames_left(0, 720), None);
        assert_eq!(epoch_end_frames_left(719, 0), None);
    }

    /// The epoch-end wait is an info condition naming the frame that ends
    /// it, judged on the head as a report is served, and it ends with the
    /// epoch; a frame-bound wait within its expected time never repeats.
    #[test]
    fn prover_ops_wait_for_the_next_epoch_as_an_expected_wait() {
        let kind = ConditionKind::ProverOpsWaitForEpoch;
        let mut reg = HealthRegistry::default();
        assert!(reg.refresh_waits(at_head(709), T0).is_empty());
        assert!(current(&reg, kind).is_none());
        assert_eq!(source_of(&reg, kind), (T0, 1));
        let started = reg.refresh_waits(at_head(712), T0 + 1_000);
        assert!(
            matches!(started.as_slice(), [Transition::Started { .. }]),
            "{started:?}"
        );
        let c = current(&reg, kind).expect("ops wait");
        assert_eq!(
            c.severity,
            ConditionSeverity::Info as i32,
            "an expected wait is info"
        );
        assert_eq!(c.scope, ConditionScope::Network as i32);
        assert_eq!(c.action, ConditionAction::WaitForNextEpoch as i32);
        assert_eq!((c.affected, c.tracked, c.threshold), (1, 1, 10));
        assert_eq!(
            c.wait,
            Some(ExpectedWait {
                head_frame: 712,
                until_frame: 720,
                batch_from_frame: 0,
                expected_secs: 600,
            })
        );
        assert_eq!(
            notice_text(&c),
            "Prover ops wait for the next epoch: it starts at frame 720 (8 frames)."
        );
        // Judged on the tick too, with no lines while it lasts as expected.
        for secs in [15, 30, 45, 60, 75] {
            let now = T0 + secs * 1000;
            reg.observe_global(at_head(712 + secs / 15), now);
            assert!(reg.evaluate(now, &|_: &[u8]| None).is_empty());
        }
        // The next epoch: gone from the report at once, ended after the
        // clear hold with its reason.
        assert!(reg.refresh_waits(at_head(720), T0 + 90_000).is_empty());
        assert!(current(&reg, kind).is_none());
        let ended = reg.refresh_waits(at_head(726), T0 + 150_000);
        assert!(
            matches!(
                ended.as_slice(),
                [Transition::Ended {
                    unobserved: false,
                    ..
                }]
            ),
            "{ended:?}"
        );
        assert_eq!(ended_reason(kind), "next epoch started");
        // Without a head nothing is judged.
        let mut unknown = HealthRegistry::default();
        unknown.refresh_waits(at_head(0), T0);
        assert_eq!(source_of(&unknown, kind), (0, 0));
    }

    /// Observe a GLOBAL state sync `installing` at `secs` and judge; the
    /// transitions to log.
    fn sync_at(reg: &mut HealthRegistry, secs: u64, installing: bool) -> Vec<Transition> {
        let now = T0 + secs * 1000;
        reg.observe_global(
            GlobalObservation {
                sync_installing: Some(installing),
                ..at_head(700)
            },
            now,
        );
        reg.evaluate(now, &|_: &[u8]| None)
    }

    /// A GLOBAL state sync's install is an info condition of this node that
    /// names the event ending it, and ends after the clear hold once the
    /// last chunk is in. An unreadable sync state establishes nothing.
    #[test]
    fn a_global_state_sync_install_is_an_expected_wait() {
        let kind = ConditionKind::GlobalStateSyncInstalling;
        let mut reg = HealthRegistry::default();
        assert!(sync_at(&mut reg, 0, false).is_empty());
        assert_eq!(source_of(&reg, kind), (T0, 1));
        let started = sync_at(&mut reg, 15, true);
        assert!(
            matches!(started.as_slice(), [Transition::Started { .. }]),
            "{started:?}"
        );
        let c = current(&reg, kind).expect("installing");
        assert_eq!(c.severity, ConditionSeverity::Info as i32);
        assert_eq!(c.scope, ConditionScope::ThisNode as i32);
        assert_eq!(c.action, ConditionAction::WaitForGlobalSync as i32);
        assert_eq!(c.wait.map(|w| w.expected_secs), Some(600));
        assert_eq!(
            notice_text(&c),
            "GLOBAL state sync installing: committed shard heads show again once its last \
             chunk is in."
        );
        for secs in [30, 45, 60, 75, 90] {
            assert!(sync_at(&mut reg, secs, true).is_empty());
        }
        // The last chunk is in: gone from the report, ended after the hold.
        assert!(sync_at(&mut reg, 105, false).is_empty());
        assert!(current(&reg, kind).is_none());
        let mut ended = Vec::new();
        for secs in [120, 135, 150, 165] {
            ended.extend(sync_at(&mut reg, secs, false));
        }
        assert!(
            matches!(
                ended.as_slice(),
                [Transition::Ended {
                    unobserved: false,
                    ..
                }]
            ),
            "{ended:?}"
        );
        assert_eq!(ended_reason(kind), "GLOBAL state installed");
        let mut unread = HealthRegistry::default();
        unread.refresh_waits(at_head(700), T0);
        assert!(current(&unread, kind).is_none());
        assert_eq!(source_of(&unread, kind), (0, 0));
    }

    /// An expected wait lasting past its expected time warns once, then
    /// repeats every 10 minutes; before that it logs nothing while it
    /// lasts.
    #[test]
    fn an_expected_wait_warns_once_it_overruns() {
        let mut reg = HealthRegistry::default();
        let mut shape = Vec::new();
        for secs in (0..=1800).step_by(15) {
            for t in sync_at(&mut reg, secs, true) {
                let name = match t {
                    Transition::Started { .. } => "started",
                    Transition::Overran { .. } => "overran",
                    Transition::Lasting { .. } => "lasting",
                    Transition::Ended { .. } => "ended",
                };
                shape.push((secs, name));
            }
        }
        assert_eq!(
            shape,
            [
                (0, "started"),
                (600, "overran"),
                (1200, "lasting"),
                (1800, "lasting")
            ]
        );
        let c = current(&reg, ConditionKind::GlobalStateSyncInstalling).unwrap();
        assert_eq!(c.since_unix_ms, T0);
    }

    /// A wait past its expected time is a warning and says so; it started
    /// as info.
    #[test]
    fn an_overrun_wait_is_a_warning() {
        let kind = ConditionKind::GlobalStateSyncInstalling;
        let mut reg = HealthRegistry::default();
        sync_at(&mut reg, 0, true);
        assert_eq!(
            current(&reg, kind).map(|c| c.severity),
            Some(ConditionSeverity::Info as i32)
        );
        for secs in (15..=1500).step_by(15) {
            sync_at(&mut reg, secs, true);
        }
        let c = current(&reg, kind).expect("still installing");
        assert_eq!(c.severity, ConditionSeverity::Warning as i32);
        assert_eq!(
            notice_text(&c),
            "GLOBAL state sync installing >10m: committed GLOBAL state stays unreadable until \
             its last chunk is in."
        );
    }

    /// Shields wait for their admission frame, batches for the later one,
    /// with no overrun and no repeat however long; stale inputs end it at
    /// once.
    #[test]
    fn shields_wait_for_their_admission_frame() {
        let kind = ConditionKind::ShieldsNotAdmitted;
        let shields = |head, from| GlobalObservation {
            shields_from: from,
            ..at_head(head)
        };
        let mut reg = HealthRegistry::default();
        let started = reg.refresh_waits(shields(950, Some((900, 1000))), T0);
        assert!(matches!(started.as_slice(), [Transition::Started { .. }]));
        let c = current(&reg, kind).expect("not admitted");
        assert_eq!(c.severity, ConditionSeverity::Info as i32);
        assert_eq!(c.scope, ConditionScope::Network as i32);
        assert_eq!(c.action, ConditionAction::WaitForShieldAdmission as i32);
        assert_eq!(
            c.wait,
            Some(ExpectedWait {
                head_frame: 950,
                until_frame: 900,
                batch_from_frame: 1000,
                expected_secs: 0,
            })
        );
        assert_eq!(
            notice_text(&c),
            "Legacy coin shields admitted from GLOBAL frame 900, batches from 1000: 50 frames to \
             go."
        );
        for hour in 1..=24 {
            let lines = reg.refresh_waits(shields(990, Some((900, 1000))), T0 + hour * 3_600_000);
            assert!(lines.is_empty(), "{lines:?}");
        }
        assert_eq!(
            current(&reg, kind).map(|c| c.severity),
            Some(ConditionSeverity::Info as i32)
        );
        let now = T0 + 25 * 3_600_000;
        reg.refresh_waits(shields(1000, Some((900, 1000))), now);
        assert!(current(&reg, kind).is_none(), "admitted at the batch frame");
        let mut one = HealthRegistry::default();
        one.refresh_waits(shields(10, Some((50, 50))), T0);
        assert_eq!(
            current(&one, kind).map(|c| notice_text(&c)).as_deref(),
            Some("Legacy coin shields admitted from GLOBAL frame 50: 40 frames to go.")
        );
        let ended = one.evaluate(T0 + OBSERVATION_GAP_MS + 1, &|_: &[u8]| None);
        assert!(
            matches!(
                ended.as_slice(),
                [Transition::Ended {
                    unobserved: true,
                    ..
                }]
            ),
            "{ended:?}"
        );
    }

    /// A network that sets no admission frame for either shield, or a
    /// build that admits none, has no wait to track.
    #[test]
    fn shields_track_nothing_without_admission_frames() {
        let kind = ConditionKind::ShieldsNotAdmitted;
        for from in [None, Some((u64::MAX, u64::MAX)), Some((50, u64::MAX))] {
            let mut reg = HealthRegistry::default();
            reg.refresh_waits(
                GlobalObservation {
                    shields_from: from,
                    ..at_head(10)
                },
                T0,
            );
            assert!(current(&reg, kind).is_none(), "{from:?}");
            assert_eq!(source_of(&reg, kind), (T0, 0), "{from:?}");
        }
    }

    fn reach(reachable: usize, stall_secs: u64) -> GlobalReach {
        GlobalReach {
            provers: 4,
            reachable,
            quorum: 3,
            unreachable: (reachable..4).map(|m| format!("…member{m}")).collect(),
            stall_after: std::time::Duration::from_secs(stall_secs),
        }
    }

    /// GLOBAL's head unchanged for 120 s, as far as it was observed, is an
    /// error of the network; an advance clears it.
    #[test]
    fn global_head_unchanged_starts_after_its_window() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        for secs in (0..=105).step_by(15) {
            let now = T0 + secs * 1000;
            reg.observe_global_head(5_000, None, now);
            assert!(reg.evaluate(now, &none).is_empty(), "at {secs}s");
        }
        let now = T0 + 120_000;
        reg.observe_global_head(5_000, None, now);
        let started = reg.evaluate(now, &none);
        assert!(
            matches!(
                started.as_slice(),
                [Transition::Started {
                    log_evidence: None,
                    ..
                }]
            ),
            "{started:?}"
        );
        let snapshot = reg.snapshot();
        let c = &snapshot.conditions[0];
        assert_eq!(
            (c.kind, c.severity, c.scope, c.action, c.threshold),
            (
                ConditionKind::GlobalHeadUnchanged as i32,
                ConditionSeverity::Error as i32,
                ConditionScope::Network as i32,
                ConditionAction::CheckGlobalHead as i32,
                120
            ),
            "GLOBAL head unchanged: an error of the network"
        );
        assert_eq!(c.shards[0].unchanged_since_unix_ms, T0);
        assert_eq!(
            c.global.as_ref().map(|g| (g.head, g.span_secs, g.provers)),
            Some((5_000, 120, 0))
        );
        assert_eq!(notice_text(c), "Global head unchanged >120s.");
        assert_eq!(shard_names(c), "global");
        reg.observe_global_head(5_001, None, now + 15_000);
        reg.evaluate(now + 15_000, &none);
        assert!(reg.snapshot().conditions.is_empty());
    }

    /// On a GLOBAL prover the window is four of its leader timeouts, the
    /// notice counts the provers it hears against the quorum, and only the
    /// log names the silent ones.
    #[test]
    fn a_global_prover_judges_by_its_leader_timeout_and_counts_the_provers_heard() {
        let none = |_: &[u8]| None;
        let run = |reachable: usize| {
            let mut reg = HealthRegistry::default();
            let mut transitions = Vec::new();
            for secs in (0..=255).step_by(15) {
                let now = T0 + secs * 1000;
                reg.observe_global_head(5_000, Some(reach(reachable, 240)), now);
                let changes = reg.evaluate(now, &none);
                assert!(secs >= 240 || changes.is_empty(), "at {secs}s: {changes:?}");
                transitions.extend(changes);
            }
            (reg.snapshot().conditions, transitions)
        };
        let (conditions, transitions) = run(2);
        assert_eq!(
            notice_text(&conditions[0]),
            "Global head unchanged >240s: 2 of 4 GLOBAL provers reachable, 3 needed."
        );
        assert!(
            matches!(
                transitions.as_slice(),
                [Transition::Started { log_evidence: Some(names), .. }]
                    if names == "…member2, …member3"
            ),
            "{transitions:?}"
        );
        let (conditions, _) = run(3);
        assert_eq!(
            notice_text(&conditions[0]),
            "Global head unchanged >240s although 3 of 4 GLOBAL provers are reachable (3 needed)."
        );
    }

    /// Under 330 frames an hour is slow once 10 minutes are observed; 330
    /// is not.
    #[test]
    fn global_frames_slow_needs_ten_minutes_under_330_an_hour() {
        let none = |_: &[u8]| None;
        // `frames` every 120 s: 11 make 330 an hour, 10 make 300.
        let run = |frames: u64, until: u64| {
            let mut reg = HealthRegistry::default();
            for step in 0..=until / 120 {
                let now = T0 + step * 120_000;
                reg.observe_global_head(1_000 + step * frames, None, now);
                reg.evaluate(now, &none);
            }
            reg.snapshot().conditions
        };
        assert!(run(10, 480).is_empty(), "judged before 10 minutes");
        assert!(run(11, 3_600).is_empty(), "330 an hour is not slow");
        let slow = run(10, 600);
        assert_eq!(slow.len(), 1);
        assert_eq!(
            (slow[0].kind, slow[0].severity, slow[0].threshold),
            (
                ConditionKind::GlobalFramesSlow as i32,
                ConditionSeverity::Warning as i32,
                GLOBAL_MIN_FRAMES_PER_HOUR
            )
        );
        assert_eq!(
            notice_text(&slow[0]),
            "Global frames slow: 50 in 10 min (~300/h, below 330/h)."
        );
    }

    /// A stall is one condition while it lasts; after it the hour's rate
    /// shows it, so a stall between two of a reader's reads still shows.
    #[test]
    fn a_global_stall_then_shows_in_the_hourly_rate() {
        let none = |_: &[u8]| None;
        // One frame per 10 s for 20 min, standing still for 5 min, then on.
        let head = |secs: u64| {
            1_000
                + match secs {
                    s if s < 1_200 => s / 10,
                    s if s < 1_500 => 120,
                    s => 120 + (s - 1_500) / 10,
                }
        };
        let mut reg = HealthRegistry::default();
        let mut kinds = HashMap::new();
        for secs in (0..=1_530).step_by(15) {
            let now = T0 + secs * 1000;
            reg.observe_global_head(head(secs), None, now);
            reg.evaluate(now, &none);
            let current: Vec<i32> = reg.snapshot().conditions.iter().map(|c| c.kind).collect();
            kinds.insert(secs, current);
        }
        assert_eq!(kinds[&1_185], Vec::<i32>::new());
        assert_eq!(kinds[&1_485], [ConditionKind::GlobalHeadUnchanged as i32]);
        assert_eq!(kinds[&1_515], [ConditionKind::GlobalFramesSlow as i32]);
    }

    /// A paced shield pauses for the worst GLOBAL progress condition and for
    /// no other kind.
    #[test]
    fn the_global_progress_notice_is_the_worst_global_condition() {
        let condition = |kind: ConditionKind, severity: ConditionSeverity| HealthCondition {
            kind: kind as i32,
            severity: severity as i32,
            threshold: 120,
            global: Some(GlobalProgress {
                advanced_frames: 50,
                span_secs: 600,
                ..Default::default()
            }),
            ..Default::default()
        };
        let local = condition(
            ConditionKind::LocalAppFramesUnchanged,
            ConditionSeverity::Warning,
        );
        let mut health = HealthConditions {
            conditions: vec![
                condition(ConditionKind::GlobalHeadUnchanged, ConditionSeverity::Error),
                local.clone(),
                condition(ConditionKind::GlobalFramesSlow, ConditionSeverity::Warning),
            ],
            sources: Vec::new(),
        };
        assert_eq!(
            global_progress_notice(&health).as_deref(),
            Some("Global head unchanged >120s")
        );
        health.conditions = vec![local];
        assert_eq!(global_progress_notice(&health), None);
    }

    /// Without a fresh GLOBAL observation the GLOBAL kinds end, unobserved.
    #[test]
    fn global_conditions_end_without_fresh_observations() {
        let none = |_: &[u8]| None;
        let mut reg = HealthRegistry::default();
        for secs in (0..=135).step_by(15) {
            let now = T0 + secs * 1000;
            reg.observe_global_head(5_000, None, now);
            reg.evaluate(now, &none);
        }
        assert!(affected(&reg, ConditionKind::GlobalHeadUnchanged).is_some());
        let ended = reg.evaluate(T0 + 295_000, &none);
        assert!(
            matches!(
                ended.as_slice(),
                [Transition::Ended {
                    unobserved: true,
                    ..
                }]
            ),
            "{ended:?}"
        );
        let source = reg
            .snapshot()
            .sources
            .into_iter()
            .find(|s| s.kind == ConditionKind::GlobalHeadUnchanged as i32)
            .unwrap();
        assert_eq!((source.observed_unix_ms, source.tracked), (0, 0));
    }

    /// A newer node serves kinds and actions this client lacks: the text
    /// says this client is older and how to fix that, not to read the log.
    #[test]
    fn an_unknown_kind_names_an_older_qclient() {
        let c = HealthCondition {
            kind: 999,
            severity: ConditionSeverity::Warning as i32,
            scope: ConditionScope::Network as i32,
            action: 999,
            affected: 1,
            tracked: 1,
            ..Default::default()
        };
        assert_eq!(
            notice_text(&c),
            "Health condition 999 (warning, the network) unknown to this qclient, older than the \
             node: update or restart qclient (the node's log names it).",
            "the notice of a kind this client lacks"
        );
        assert_eq!(
            action_text(c.action),
            "update or restart qclient, which does not know this action"
        );
    }

    /// Every notice states each number once: a figure restated, or a
    /// derived value equal to a shown one, is noise in a one-row notice.
    #[test]
    fn every_notice_states_each_number_once() {
        let numbers = |text: &str| -> Vec<String> {
            text.split(|ch: char| !ch.is_ascii_digit())
                .filter(|token| !token.is_empty())
                .map(str::to_owned)
                .collect()
        };
        let global = |advanced_frames, span_secs, reachable| GlobalProgress {
            head: 9_000,
            advanced_frames,
            span_secs,
            provers: 7,
            reachable,
            quorum: 5,
        };
        let wait = |batch_from_frame| ExpectedWait {
            head_frame: 1_000,
            until_frame: 1_250,
            batch_from_frame,
            expected_secs: 600,
        };
        let kinds: Vec<i32> = (0..64)
            .filter(|kind| ConditionKind::try_from(*kind).is_ok())
            .chain([999])
            .collect();
        let mut rendered = Vec::new();
        for kind in kinds {
            let threshold = match ConditionKind::try_from(kind) {
                Ok(ConditionKind::GlobalFramesSlow) => GLOBAL_MIN_FRAMES_PER_HOUR,
                Ok(ConditionKind::GlobalAppFramesBehind) => 100,
                _ => 120,
            };
            let globals = [
                None,
                // The usual span: the full hour, one sample short of it.
                Some(global(217, 3_600, 3)),
                Some(global(217, 3_585, 3)),
                Some(global(160, 1_800, 6)),
                // A rate that rounds down to the count.
                Some(global(3, 3_480, 3)),
            ];
            for severity in [ConditionSeverity::Info, ConditionSeverity::Warning] {
                for global in &globals {
                    // A slow condition always carries its progress.
                    if global.is_none() && kind == ConditionKind::GlobalFramesSlow as i32 {
                        continue;
                    }
                    for wait in [wait(1_250), wait(1_300)] {
                        rendered.push(notice_text(&HealthCondition {
                            kind,
                            severity: severity as i32,
                            scope: ConditionScope::Network as i32,
                            affected: 3,
                            tracked: 7,
                            threshold,
                            global: *global,
                            wait: Some(wait),
                            // A drop: the last hour below the day, in figures apart.
                            reward_hour_units: 12 * UNITS_PER_QUIL / 10,
                            reward_day_units: 34 * UNITS_PER_QUIL / 10,
                            ..Default::default()
                        }));
                    }
                }
            }
        }
        let offenders: Vec<&String> = rendered
            .iter()
            .filter(|text| {
                let tokens = numbers(text);
                let unique: std::collections::HashSet<&String> = tokens.iter().collect();
                unique.len() != tokens.len()
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "a notice states a number twice: {offenders:?}"
        );
        assert!(rendered
            .iter()
            .any(|text| text.contains("in the last hour")));
    }

    fn seat(filter: u8, status: EffectiveStatus) -> AllocationObservation {
        AllocationObservation {
            filter: vec![filter],
            status,
            lost_epoch: None,
        }
    }

    /// `kind`'s current condition.
    fn condition(reg: &HealthRegistry, kind: ConditionKind) -> Option<HealthCondition> {
        reg.snapshot()
            .conditions
            .into_iter()
            .find(|c| c.kind == kind as i32)
    }

    /// Each listed row's filter byte and worker core.
    fn listed(c: &HealthCondition) -> Vec<(u8, u32)> {
        c.shards.iter().map(|s| (s.filter[0], s.core_id)).collect()
    }

    /// Observe `workers` and `seats` at `now` in epoch 10 and judge.
    fn judge_seats_at(
        reg: &mut HealthRegistry,
        workers: &[WorkerObservation],
        seats: &[AllocationObservation],
        now: u64,
    ) -> Vec<Transition> {
        reg.observe_workers(workers.to_vec(), now);
        reg.observe_allocations(seats.to_vec(), 10, now);
        reg.evaluate(now, &|_: &[u8]| None)
    }

    /// Active, leaving and epoch-stale allocations need a worker on their
    /// shard; one without counts once it lacked one for the base window,
    /// and a bound worker ends it.
    #[test]
    fn allocations_without_a_worker_count_after_the_base_window() {
        let seats = [
            seat(1, EffectiveStatus::Active),
            seat(2, EffectiveStatus::Leaving),
            seat(3, EffectiveStatus::ExpiredEpoch),
            seat(4, EffectiveStatus::Joining),
            seat(5, EffectiveStatus::Paused),
        ];
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &[worker(7, 1, T0, T0)], &seats, T0);
        let kind = ConditionKind::AllocationsWithoutWorker;
        assert!(condition(&reg, kind).is_none(), "not yet for the window");
        let now = T0 + BASE_WINDOW_MS;
        judge_seats_at(&mut reg, &[worker(7, 1, now, T0)], &seats, now);
        let c = condition(&reg, kind).expect("workerless");
        assert_eq!(listed(&c), [(2, 0), (3, 0)]);
        assert_eq!((c.affected, c.tracked), (2, 3));
        assert_eq!(c.severity, ConditionSeverity::Error as i32);
        assert_eq!(c.scope, ConditionScope::ThisNode as i32);
        assert_eq!(notice_text(&c), "Allocations without a worker: 2/3.");
        let bound = [
            worker(7, 1, now, T0),
            worker(8, 2, now, T0),
            worker(9, 3, now, T0),
        ];
        judge_seats_at(&mut reg, &bound, &seats, now + 15_000);
        assert!(condition(&reg, kind).is_none(), "a bound worker ends it");
    }

    /// An earning worker blocked or stopped for the base window counts, of
    /// the earning workers in frame-advancing phases; the handoff wait and
    /// workers that do not earn take no part.
    #[test]
    fn local_execution_stopped_counts_earning_workers_after_the_base_window() {
        let at = |now: u64| {
            let state = |core, state: &str| {
                let mut w = worker(core, core as u8, now, T0);
                w.state = state.into();
                w
            };
            let mut handoff = state(3, "blocked");
            handoff.blocker = "awaiting successor".into();
            let mut idle = state(4, "blocked");
            idle.earning = false;
            vec![
                state(1, "blocked"),
                state(2, "stopped"),
                handoff,
                idle,
                state(5, "serving"),
                state(6, "syncing"),
            ]
        };
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &at(T0), &[], T0);
        let kind = ConditionKind::LocalExecutionStopped;
        assert!(condition(&reg, kind).is_none(), "not yet for the window");
        let now = T0 + BASE_WINDOW_MS;
        judge_seats_at(&mut reg, &at(now), &[], now);
        let c = condition(&reg, kind).expect("stopped");
        assert_eq!(listed(&c), [(1, 1), (2, 2)]);
        assert_eq!((c.affected, c.tracked), (2, 3));
        assert_eq!(c.severity, ConditionSeverity::Error as i32);
        assert_eq!(c.shards[0].window_secs, 60);
        assert_eq!(
            notice_text(&c),
            "Local execution blocked or stopped: 2/3 allocations."
        );
    }

    /// Active allocations whose recorded epoch is stale, of the allocations
    /// the operator sees (expired and lost ones are not).
    #[test]
    fn epoch_stale_allocations_are_counted_of_those_shown() {
        let seats = [
            seat(1, EffectiveStatus::Active),
            seat(2, EffectiveStatus::ExpiredEpoch),
            seat(3, EffectiveStatus::Paused),
            seat(4, EffectiveStatus::Joining),
            seat(5, EffectiveStatus::ExpiredLeaving),
            seat(6, EffectiveStatus::Rejected),
        ];
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &[], &seats, T0);
        judge_seats_at(&mut reg, &[], &seats, T0 + BASE_WINDOW_MS);
        let c = condition(&reg, ConditionKind::AllocationEpochStale).expect("stale epoch");
        assert_eq!(listed(&c), [(2, 0)]);
        assert_eq!((c.affected, c.tracked), (1, 4));
        assert_eq!(c.severity, ConditionSeverity::Warning as i32);
        assert_eq!(
            notice_text(&c),
            "Allocation epoch stale (re-confirm!): 1/4 allocations."
        );
    }

    /// A stale epoch and a missed join are read at the node's freshest
    /// frame, ahead of its prover registry while it catches up, as after a
    /// restart: they count once they held for the base window, and a
    /// registry that catches up within it starts nothing. A rejection
    /// counts at once.
    #[test]
    fn stale_epochs_and_missed_joins_count_after_the_base_window() {
        let missed = AllocationObservation {
            lost_epoch: Some(10),
            ..seat(3, EffectiveStatus::ExpiredJoining)
        };
        let rejected = AllocationObservation {
            lost_epoch: Some(10),
            ..seat(4, EffectiveStatus::Rejected)
        };
        let behind = [
            seat(1, EffectiveStatus::ExpiredEpoch),
            seat(2, EffectiveStatus::ExpiredEpoch),
            missed.clone(),
            rejected.clone(),
        ];
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &[], &behind, T0);
        assert!(
            condition(&reg, ConditionKind::AllocationEpochStale).is_none(),
            "a stale epoch read ahead stays unlisted before the base window"
        );
        let lost = condition(&reg, ConditionKind::AllocationsRejected).expect("rejected");
        assert_eq!(
            listed(&lost),
            [(4, 0)],
            "a missed join read ahead stays unlisted before the base window"
        );
        let caught_up = [
            seat(1, EffectiveStatus::Active),
            seat(2, EffectiveStatus::ExpiredEpoch),
            seat(3, EffectiveStatus::Active),
            rejected,
        ];
        judge_seats_at(&mut reg, &[], &caught_up, T0 + 15_000);
        let now = T0 + BASE_WINDOW_MS;
        judge_seats_at(&mut reg, &[], &caught_up, now);
        let c = condition(&reg, ConditionKind::AllocationEpochStale).expect("still stale");
        assert_eq!(listed(&c), [(2, 0)]);
        assert_eq!(c.shards[0].unchanged_since_unix_ms, T0);
        assert_eq!(
            listed(&condition(&reg, ConditionKind::AllocationsRejected).expect("rejected")),
            [(4, 0)]
        );
        let still_missed = [missed, seat(4, EffectiveStatus::Active)];
        judge_seats_at(&mut reg, &[], &still_missed, now);
        judge_seats_at(&mut reg, &[], &still_missed, now + BASE_WINDOW_MS);
        assert_eq!(
            listed(&condition(&reg, ConditionKind::AllocationsRejected).expect("missed")),
            [(3, 0)]
        );
    }

    /// Paused allocations are listed of those shown.
    #[test]
    fn paused_allocations_are_listed() {
        let seats = [
            seat(1, EffectiveStatus::Active),
            seat(3, EffectiveStatus::Paused),
            seat(4, EffectiveStatus::Joining),
        ];
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &[], &seats, T0);
        let c = condition(&reg, ConditionKind::AllocationsPaused).expect("paused");
        assert_eq!(listed(&c), [(3, 0)]);
        assert_eq!(c.severity, ConditionSeverity::Warning as i32);
        assert_eq!(notice_text(&c), "Allocations paused: 1/3.");
    }

    /// Workers whose renewal the node withholds are listed by their fresh
    /// blocker, of the allocations shown.
    #[test]
    fn renewal_withheld_lists_workers_with_the_silent_blocker() {
        let mut silent = worker(1, 1, T0, T0);
        silent.blocker = SILENT_RENEWAL_BLOCKER.into();
        let mut old = worker(3, 3, T0 - WORKER_STALE_MS - 1, T0);
        old.blocker = SILENT_RENEWAL_BLOCKER.into();
        let seats = [
            seat(1, EffectiveStatus::Active),
            seat(2, EffectiveStatus::Active),
            seat(3, EffectiveStatus::Active),
        ];
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &[silent, worker(2, 2, T0, T0), old], &seats, T0);
        let c = condition(&reg, ConditionKind::RenewalWithheld).expect("withheld");
        assert_eq!(listed(&c), [(1, 1)]);
        assert_eq!((c.affected, c.tracked), (1, 3));
        assert_eq!(
            notice_text(&c),
            "Renewal withheld, no vote sent: 1/3 allocations."
        );
    }

    /// A failed latest recovery attempt counts while the worker trails the
    /// head peers report by more than the normal trail, or the head is
    /// unknown; one older than the last outcome does not.
    #[test]
    fn recovery_failing_ends_once_the_worker_is_within_the_normal_trail() {
        let failing = |core, filter, materialized| {
            let mut w = worker(core, filter, T0, T0);
            w.materialized_frame = Some(materialized);
            w.recovery_error_unix_ms = T0 - 1000;
            w.recovery_outcome_unix_ms = T0 - 5000;
            w
        };
        let judge = |workers: &[WorkerObservation]| {
            let mut reg = HealthRegistry::default();
            reg.observe_peers(&[peer(1, 800)], T0);
            judge_seats_at(&mut reg, workers, &[], T0);
            condition(&reg, ConditionKind::RecoveryFailing).map(|c| listed(&c))
        };
        assert_eq!(judge(&[failing(1, 1, 700)]), Some(vec![(1, 1)]));
        assert_eq!(judge(&[failing(1, 1, 799)]), None, "the normal trail");
        assert_eq!(judge(&[failing(1, 1, 797)]), Some(vec![(1, 1)]));
        assert_eq!(judge(&[failing(2, 2, 900)]), Some(vec![(2, 2)]), "no head");
        let mut recovered = failing(1, 1, 700);
        recovered.recovery_outcome_unix_ms = T0;
        assert_eq!(judge(&[recovered]), None);
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &[failing(1, 1, 700)], &[], T0);
        let c = condition(&reg, ConditionKind::RecoveryFailing).expect("failing");
        assert_eq!(
            notice_text(&c),
            "Last recovery attempt failed: 1/1 workers."
        );
    }

    /// A rejected or kicked allocation, or a join that missed its confirm
    /// window, counts in the epoch it was lost and the next; one lost at an
    /// unknown time establishes nothing.
    #[test]
    fn rejections_and_kicks_count_in_their_epoch_and_the_next() {
        let lost = |filter, status, epoch| AllocationObservation {
            lost_epoch: epoch,
            ..seat(filter, status)
        };
        let seats = vec![
            lost(1, EffectiveStatus::Rejected, Some(10)),
            lost(2, EffectiveStatus::Kicked, Some(9)),
            lost(3, EffectiveStatus::ExpiredJoining, Some(8)),
            lost(4, EffectiveStatus::Rejected, None),
            seat(5, EffectiveStatus::Active),
        ];
        let mut reg = HealthRegistry::default();
        reg.observe_allocations(seats.clone(), 10, T0);
        reg.evaluate(T0, &|_: &[u8]| None);
        let c = condition(&reg, ConditionKind::AllocationsRejected).expect("lost seats");
        assert_eq!(listed(&c), [(1, 0), (2, 0)]);
        assert_eq!((c.affected, c.tracked), (2, 5));
        assert_eq!(c.severity, ConditionSeverity::Error as i32);
        assert_eq!(notice_text(&c), "Allocations rejected or kicked: 2/5.");
        reg.observe_allocations(seats, 11, T0 + 15_000);
        reg.evaluate(T0 + 15_000, &|_: &[u8]| None);
        let c = condition(&reg, ConditionKind::AllocationsRejected).expect("lost seats");
        assert_eq!(listed(&c), [(1, 0)]);
    }

    /// A worker bound for the base window to a shard where this prover
    /// holds no live allocation is listed, of the bound workers; an
    /// informational wait.
    #[test]
    fn workers_bound_without_a_live_allocation_are_listed() {
        let seats = [
            seat(1, EffectiveStatus::Active),
            seat(2, EffectiveStatus::ExpiredLeaving),
            seat(3, EffectiveStatus::Rejected),
        ];
        let at = |now: u64| {
            vec![
                worker(1, 1, now, T0),
                worker(2, 2, now, T0),
                worker(3, 3, now, T0),
                worker(4, 9, now, T0),
            ]
        };
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &at(T0), &seats, T0);
        let now = T0 + BASE_WINDOW_MS;
        judge_seats_at(&mut reg, &at(now), &seats, now);
        let c = condition(&reg, ConditionKind::WorkersBoundWithoutAllocation).expect("bound");
        assert_eq!(listed(&c), [(2, 2), (3, 3), (9, 4)]);
        assert_eq!((c.affected, c.tracked), (3, 4));
        assert_eq!(c.severity, ConditionSeverity::Info as i32);
        assert_eq!(
            (c.threshold, c.shards[0].window_secs),
            (60, 60),
            "bound rows carry the base-window threshold"
        );
        assert_eq!(
            notice_text(&c),
            "Workers bound without an allocation: 3/4 workers."
        );
    }

    /// After a restart the workers report their filters before the
    /// allocations show: a worker bound without a live allocation counts
    /// only once that held for the base window, so allocations shown
    /// within it start nothing, and a worker that stays unallocated is
    /// listed at the window.
    #[test]
    fn workers_bound_without_a_live_allocation_count_after_the_base_window() {
        let kind = ConditionKind::WorkersBoundWithoutAllocation;
        let at = |now: u64| vec![worker(1, 1, now, T0), worker(2, 2, now, T0)];
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &at(T0), &[], T0);
        assert!(
            condition(&reg, kind).is_none(),
            "bound workers stay unlisted before the base window"
        );
        let shown = [
            seat(1, EffectiveStatus::Active),
            seat(2, EffectiveStatus::ExpiredLeaving),
        ];
        let later = T0 + 15_000;
        judge_seats_at(&mut reg, &at(later), &shown, later);
        assert!(condition(&reg, kind).is_none(), "not yet for the window");
        let now = T0 + BASE_WINDOW_MS;
        judge_seats_at(&mut reg, &at(now), &shown, now);
        let c = condition(&reg, kind).expect("still bound after the window");
        assert_eq!(listed(&c), [(2, 2)]);
        assert_eq!(c.shards[0].unchanged_since_unix_ms, T0);
        assert_eq!((c.affected, c.tracked), (1, 2));
    }

    /// A running or serving worker that has materialized no frame counts
    /// once it held for the base window; other phases take no part.
    #[test]
    fn running_workers_without_a_materialized_frame_count_after_the_base_window() {
        let at = |now: u64| {
            let state = |core, state: &str, frame| {
                let mut w = worker(core, core as u8, now, T0);
                w.state = state.into();
                w.materialized_frame = Some(frame);
                w
            };
            let mut idle = state(2, "running", 0);
            idle.earning = false;
            vec![
                state(1, "serving", 0),
                idle,
                state(3, "syncing", 0),
                state(4, "serving", 500),
            ]
        };
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &at(T0), &[], T0);
        let kind = ConditionKind::LocalAppFramesNoneMaterialized;
        assert!(condition(&reg, kind).is_none(), "not yet for the window");
        let now = T0 + BASE_WINDOW_MS;
        judge_seats_at(&mut reg, &at(now), &[], now);
        let c = condition(&reg, kind).expect("none materialized");
        assert_eq!(listed(&c), [(1, 1), (2, 2)]);
        assert_eq!((c.affected, c.tracked), (2, 3));
        assert_eq!(c.severity, ConditionSeverity::Warning as i32);
        assert_eq!(
            notice_text(&c),
            "Local app frames: none materialized on 2/3 allocations."
        );
    }

    /// A worker observation older than the stale threshold on this node's
    /// clock, or one never observed, is stale; a worker without a report
    /// says nothing.
    #[test]
    fn stale_worker_observations_are_judged_by_the_node_clock() {
        let old = T0 - WORKER_STALE_MS - 1;
        let mut unreported = worker(4, 4, 0, T0);
        unreported.state.clear();
        let workers = [
            worker(1, 1, T0, T0),
            worker(2, 2, old, T0),
            worker(3, 3, 0, T0),
            unreported,
        ];
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &workers, &[], T0);
        let c = condition(&reg, ConditionKind::WorkerObservationsStale).expect("stale");
        assert_eq!(listed(&c), [(2, 2), (3, 3)]);
        assert_eq!((c.affected, c.tracked), (2, 3));
        assert_eq!(c.shards[0].unchanged_since_unix_ms, old);
        assert_eq!(c.severity, ConditionSeverity::Info as i32);
        assert_eq!(
            notice_text(&c),
            "Worker observations stale >30s: 2/3 workers."
        );
    }

    /// The allocation conditions rest on the prover registry's view: when
    /// it is not read again they end, unobserved, rather than last forever.
    #[test]
    fn seat_conditions_end_without_fresh_allocations() {
        let mut reg = HealthRegistry::default();
        judge_seats_at(&mut reg, &[], &[seat(1, EffectiveStatus::Paused)], T0);
        assert!(condition(&reg, ConditionKind::AllocationsPaused).is_some());
        let later = T0 + OBSERVATION_GAP_MS + 1;
        reg.observe_workers(Vec::new(), later);
        let transitions = reg.evaluate(later, &|_: &[u8]| None);
        assert!(
            transitions.iter().any(|t| matches!(
                t,
                Transition::Ended {
                    kind: ConditionKind::AllocationsPaused,
                    unobserved: true,
                    ..
                }
            )),
            "{transitions:?}"
        );
        assert!(condition(&reg, ConditionKind::AllocationsPaused).is_none());
    }

    fn no_cadence(_: &[u8]) -> Option<FrameCadence> {
        None
    }

    fn shard(filter: u8, serving: Option<u32>, holds_data: bool) -> ShardObservation {
        ShardObservation {
            filter: vec![filter],
            serving_provers: serving,
            holds_data,
            ..Default::default()
        }
    }

    /// At most 3 provers serving after the boundary on a shard with data is
    /// halt risk: confirmed joins count, unconfirmed ones do not, a shard
    /// without data cannot halt and unreported counts establish nothing.
    #[test]
    fn halt_risk_counts_the_serving_provers_of_shards_with_data() {
        use quil_types::proto::node::ShardProverCounts;
        let row = |filter: u8, active, activating, joining, size: Vec<u8>| {
            ShardObservation::of(&ShardRewardInfo {
                filter: vec![filter],
                shard_size: size,
                prover_counts: Some(ShardProverCounts {
                    active,
                    activating,
                    joining,
                    ..Default::default()
                }),
                ..Default::default()
            })
        };
        let mut reg = HealthRegistry::default();
        let rows = vec![
            row(1, 2, 1, 9, vec![1]),
            row(2, 0, 0, 0, vec![1]),
            row(3, 3, 1, 0, vec![1]),
            row(4, 4, 0, 0, vec![1]),
            row(5, 0, 0, 0, vec![0]),
            ShardObservation::of(&ShardRewardInfo {
                filter: vec![6],
                shard_size: vec![1],
                ..Default::default()
            }),
        ];
        reg.observe_shards(rows, T0);
        reg.evaluate(T0, &no_cadence);
        let c = current(&reg, ConditionKind::ShardHaltRisk).expect("at risk");
        let filters: Vec<&[u8]> = c.shards.iter().map(|s| s.filter.as_slice()).collect();
        assert_eq!(filters, [&[1u8][..], &[2u8][..]]);
        assert_eq!((c.affected, c.tracked, c.threshold), (2, 5, 3));
        assert_eq!(c.severity, ConditionSeverity::Warning as i32);
        assert_eq!(c.scope, ConditionScope::Network as i32);
        assert_eq!(
            notice_text(&c),
            "Shards at halt risk (<=3 provers): 2/5 tracked shards."
        );
    }

    /// A materialized frame behind the head, or none materialized, is listed
    /// with its lag; a current shard is not, and an unknown head establishes
    /// nothing.
    #[test]
    fn peer_materialization_lag_lists_each_trailing_shard() {
        let row = |filter: u8, materialized_frame, latest_frame| ShardObservation {
            filter: vec![filter],
            materialized_frame,
            latest_frame,
            ..Default::default()
        };
        let mut reg = HealthRegistry::default();
        let rows = vec![
            row(1, 15, 20),
            row(2, 0, 20),
            row(3, 20, 20),
            row(4, 30, 20),
            row(5, 7, 0),
        ];
        reg.observe_shards(rows, T0);
        reg.evaluate(T0, &no_cadence);
        let c = current(&reg, ConditionKind::PeerMaterializationLag).expect("trailing");
        let listed: Vec<(u8, u64, u64)> = c
            .shards
            .iter()
            .map(|s| (s.filter[0], s.frame, s.lag_frames))
            .collect();
        assert_eq!(listed, [(1, 15, 5), (2, 0, 20)]);
        assert_eq!((c.affected, c.tracked), (2, 4));
        // A routine gap informs; it is no warning.
        assert_eq!(c.severity, ConditionSeverity::Info as i32);
        assert_eq!(c.scope, ConditionScope::Peer as i32);
        assert_eq!(
            notice_text(&c),
            "Peer materialization trails its head: 2/4 tracked shards."
        );
    }

    /// Shard conditions rest on served shard info: when none is served they
    /// report nothing and say they are not judged, rather than last forever
    /// or read as healthy.
    #[test]
    fn shard_conditions_end_without_fresh_shard_info() {
        let mut reg = HealthRegistry::default();
        reg.observe_shards(vec![shard(1, Some(1), true)], T0);
        reg.evaluate(T0, &no_cadence);
        assert!(current(&reg, ConditionKind::ShardHaltRisk).is_some());
        let later = T0 + OBSERVATION_GAP_MS + 1;
        let transitions = reg.evaluate(later, &no_cadence);
        assert!(
            transitions.iter().any(|t| matches!(
                t,
                Transition::Ended {
                    kind: ConditionKind::ShardHaltRisk,
                    unobserved: true,
                    ..
                }
            )),
            "{transitions:?}"
        );
        assert!(current(&reg, ConditionKind::ShardHaltRisk).is_none());
        let source = reg
            .snapshot()
            .sources
            .into_iter()
            .find(|s| s.kind == ConditionKind::ShardHaltRisk as i32)
            .unwrap();
        assert_eq!((source.observed_unix_ms, source.tracked), (0, 0));
    }

    fn reward_row(filter: u8, hour: (u64, u64), day: (u64, u64)) -> ShardRewardInfo {
        ShardRewardInfo {
            filter: vec![filter],
            estimated_reward: 5_000_000u64.to_be_bytes().to_vec(),
            frame_cadence: Some(cadence(T0, Some(hour), Some(day))),
            ..Default::default()
        }
    }

    fn earning(filter: u8) -> WorkerObservation {
        worker(1, filter, T0, T0)
    }

    fn judge_reward(
        row: ShardRewardInfo,
        workers: Vec<WorkerObservation>,
    ) -> Option<HealthCondition> {
        let mut reg = HealthRegistry::default();
        reg.observe_workers(workers, T0);
        reg.observe_shards(vec![ShardObservation::of(&row)], T0);
        reg.evaluate(T0, &no_cadence);
        current(&reg, ConditionKind::RewardDrop)
    }

    /// The earning seats' 60m forecast under half their 24h one is a drop;
    /// half or more is not.
    #[test]
    fn reward_drop_compares_the_earning_seats_forecasts() {
        let judge = judge_reward;
        let day = (86_400, 4800);
        let c = judge(reward_row(1, (3600, 20), day), vec![earning(1)]).expect("a drop");
        assert_eq!(notice_text(&c), "Reward now 60m ~0.3 vs 24h ~3.0 Q/d.");
        assert_eq!((c.affected, c.tracked), (1, 1));
        assert_eq!(c.scope, ConditionScope::ThisNode as i32);
        // Half of the 24h rate or more is not a drop.
        assert!(judge(reward_row(1, (3600, 100), day), vec![earning(1)]).is_none());
    }

    /// Short coverage establishes no drop, an unknown reward prices nothing,
    /// and seats that do not earn take no part.
    #[test]
    fn reward_drop_needs_covered_windows_and_earning_seats() {
        let judge = judge_reward;
        let day = (86_400, 4800);
        // Short coverage of either window cannot establish one.
        assert!(judge(reward_row(1, (600, 0), day), vec![earning(1)]).is_none());
        assert!(judge(reward_row(1, (3600, 20), (3600, 200)), vec![earning(1)]).is_none());
        // Seats that do not earn, and shards without a seat, take no part.
        let mut idle = earning(1);
        idle.earning = false;
        assert!(judge(reward_row(1, (3600, 20), day), vec![idle]).is_none());
        assert!(judge(reward_row(2, (3600, 20), day), vec![earning(1)]).is_none());
        // An unknown reward ring prices nothing.
        let mut unknown = reward_row(1, (3600, 20), day);
        unknown.ring_known = Some(false);
        assert!(judge(unknown, vec![earning(1)]).is_none());
    }

    /// The node prices a seat as the manager's forecast does, by its own
    /// certificate share once one is counted: at an unchanged frame rate, a
    /// seat that signed fewer of its shard's frames over the last hour is a
    /// drop.
    #[test]
    fn reward_drop_prices_the_seats_own_certificate_share() {
        use quil_types::proto::node::CertificateWindow;
        let window = |window_seconds, frames, signed_frames| CertificateWindow {
            window_seconds,
            observed_seconds: window_seconds,
            frames,
            signed_frames,
        };
        let mut row = reward_row(1, (3600, 200), (86_400, 4800));
        assert!(judge_reward(row.clone(), vec![earning(1)]).is_none());
        row.certificate_share = Some(CertificateShare {
            hour: Some(window(3600, 200, 20)),
            day: Some(window(86_400, 4800, 4320)),
            committee: 4,
            quorum: 3,
        });
        let c = judge_reward(row, vec![earning(1)]).expect("a drop in the seat's own share");
        assert!(c.reward_hour_units * 2 < c.reward_day_units, "{c:?}");
    }

    /// A reward drop's log text carries no amounts, unlike its notice.
    #[test]
    fn a_reward_drop_logs_no_amounts() {
        let c = HealthCondition {
            kind: ConditionKind::RewardDrop as i32,
            reward_hour_units: 2_400_000_000,
            reward_day_units: 24_000_000_000,
            ..Default::default()
        };
        assert!(notice_text(&c).contains("~0.3"));
        let logged = log_text(&c);
        assert!(
            !logged.contains("0.3") && !logged.contains("3.0"),
            "{logged}"
        );
    }

    /// Low seats count over those reporting a share, and each is listed.
    #[test]
    fn certificate_share_low_counts_over_the_seats_reporting_one() {
        let seat = |filter: u8, low| SeatShare {
            filter: vec![filter],
            low,
        };
        let mut reg = HealthRegistry::default();
        reg.observe_seats(vec![seat(1, false), seat(2, true)], T0);
        reg.evaluate(T0, &no_cadence);
        let c = current(&reg, ConditionKind::CertificateShareLow).expect("low");
        assert_eq!(c.shards[0].filter, vec![2]);
        assert_eq!(
            notice_text(&c),
            "Low certificate share (60m): 1/2 allocations."
        );
        assert_eq!(c.action, ConditionAction::CheckSeatWorker as i32);
        // Recovered: it ends once clear for the hold.
        reg.observe_seats(vec![seat(1, false), seat(2, false)], T0 + 15_000);
        reg.evaluate(T0 + 15_000, &no_cadence);
        assert!(current(&reg, ConditionKind::CertificateShareLow).is_none());
    }

    fn slow_io() -> StoreIoHealth {
        let mut io = StoreIoHealth {
            interval_secs: 60,
            canary_reads: 58,
            canary_p99_us: 412_000,
            disk_reads: Some(40),
            disk_writes: Some(10),
            disk_read_await_us: Some(25_400),
            disk_write_await_us: Some(3_100),
            ..Default::default()
        };
        io.set_verdict(StoreIoVerdict::Slow);
        io
    }

    /// The node's slow verdict is a condition carrying its interval, and the
    /// notice's label follows the cause the figures support. An unmeasured
    /// store establishes nothing and says it is not judged.
    #[test]
    fn store_io_slow_follows_the_node_verdict_and_names_its_cause() {
        let mut reg = HealthRegistry::default();
        reg.observe_store_io(None, T0);
        reg.evaluate(T0, &no_cadence);
        assert!(current(&reg, ConditionKind::StoreIoSlow).is_none());
        let source = reg
            .snapshot()
            .sources
            .into_iter()
            .find(|s| s.kind == ConditionKind::StoreIoSlow as i32)
            .unwrap();
        assert_eq!(source.observed_unix_ms, 0);

        reg.observe_store_io(Some(slow_io()), T0);
        reg.evaluate(T0, &no_cadence);
        let c = current(&reg, ConditionKind::StoreIoSlow).expect("slow");
        assert_eq!((c.affected, c.tracked), (1, 1));
        assert_eq!(
            notice_text(&c),
            "Store reads slow (this node's disk): canary p99 412ms of 58 reads in 60s, \
             disk read 25ms/op, write 3.1ms/op."
        );
        let text = |io: StoreIoHealth| {
            notice_text(&HealthCondition {
                kind: ConditionKind::StoreIoSlow as i32,
                store_io: Some(io),
                ..Default::default()
            })
        };
        let mut normal = slow_io();
        normal.disk_read_await_us = Some(1_500);
        assert_eq!(
            text(normal),
            "Store reads slow (disk normal, this node's load): canary p99 412ms of 58 \
             reads in 60s, disk read 1.5ms/op, write 3.1ms/op."
        );
        let mut unknown = slow_io();
        unknown.disk_reads = None;
        unknown.disk_writes = None;
        unknown.disk_read_await_us = None;
        unknown.disk_write_await_us = None;
        assert_eq!(
            text(unknown),
            "Store reads slow (disk not ruled out): canary p99 412ms of 58 reads in 60s."
        );

        let mut ok = slow_io();
        ok.set_verdict(StoreIoVerdict::Ok);
        reg.observe_store_io(Some(ok), T0 + 15_000);
        reg.evaluate(T0 + 15_000, &no_cadence);
        assert!(current(&reg, ConditionKind::StoreIoSlow).is_none());
    }

    /// The store's fsync at or past its bound is the store condition, with
    /// its figure and the drive's check; one under the bound clears it, and
    /// it ends after the clear hold. A probe that stops returning ends it as
    /// unobserved once stale.
    #[test]
    fn a_store_fsync_at_its_bound_is_a_store_condition_until_one_under_it() {
        const BOUND: u64 = 100;
        let at = |secs: u64| T0 + secs * 1000;
        let step = |reg: &mut HealthRegistry, secs: u64, fsync: Option<u64>| {
            if let Some(ms) = fsync {
                reg.observe_store_fsync(ms, BOUND, at(secs));
            }
            reg.evaluate(at(secs), &no_cadence)
        };
        let fsync_of = |reg: &HealthRegistry| {
            current(reg, ConditionKind::StoreIoSlow).and_then(|c| c.store_fsync_ms)
        };
        let mut reg = HealthRegistry::default();
        assert!(
            step(&mut reg, 0, Some(BOUND - 1)).is_empty(),
            "FSYNC-HEALTH fsync_below_bound_raised"
        );
        assert!(
            current(&reg, ConditionKind::StoreIoSlow).is_none(),
            "FSYNC-HEALTH fsync_below_bound_raised"
        );
        let source = reg
            .snapshot()
            .sources
            .into_iter()
            .find(|s| s.kind == ConditionKind::StoreIoSlow as i32)
            .unwrap();
        assert_eq!(
            (source.observed_unix_ms, source.tracked),
            (at(0), 1),
            "FSYNC-HEALTH fsync_not_observed"
        );

        let started = step(&mut reg, 60, Some(BOUND));
        assert!(
            matches!(started.as_slice(), [Transition::Started { .. }]),
            "FSYNC-HEALTH fsync_at_bound_not_raised: {started:?}"
        );
        let c = current(&reg, ConditionKind::StoreIoSlow).unwrap();
        assert_eq!(
            (c.affected, c.tracked, c.threshold, c.store_fsync_ms),
            (1, 1, BOUND, Some(BOUND))
        );
        assert_eq!(c.severity, ConditionSeverity::Warning as i32);
        assert_eq!(
            c.action,
            ConditionAction::CheckStoreFsync as i32,
            "FSYNC-HEALTH fsync_action_not_named"
        );
        assert_eq!(
            notice_text(&c),
            "Store fsync slow (this node's disk): 4 KiB write and fsync 100ms (bound 100ms).",
            "FSYNC-HEALTH fsync_notice_missing"
        );
        assert!(action_text(c.action).contains("DRAM cache"));
        // Between probes it holds on the last; a slower one updates the
        // figure without a line.
        assert!(step(&mut reg, 105, None).is_empty());
        assert_eq!(fsync_of(&reg), Some(BOUND));
        assert!(step(&mut reg, 120, Some(1_002)).is_empty());
        assert_eq!(fsync_of(&reg), Some(1_002));
        // One under the bound: no longer served, ended after the hold.
        assert!(
            step(&mut reg, 180, Some(BOUND - 1)).is_empty(),
            "FSYNC-HEALTH fsync_ended_within_hold"
        );
        assert!(
            current(&reg, ConditionKind::StoreIoSlow).is_none(),
            "FSYNC-HEALTH fsync_below_bound_raised"
        );
        assert!(
            step(&mut reg, 225, None).is_empty(),
            "FSYNC-HEALTH fsync_ended_within_hold"
        );
        let ended = step(&mut reg, 240, Some(BOUND - 1));
        assert!(
            matches!(
                ended.as_slice(),
                [Transition::Ended {
                    kind: ConditionKind::StoreIoSlow,
                    unobserved: false,
                    ..
                }]
            ),
            "FSYNC-HEALTH fsync_not_ended_after_hold: {ended:?}"
        );
        // A probe that stops returning (30 s is its timeout).
        let started = step(&mut reg, 300, Some(30_000));
        assert!(matches!(started.as_slice(), [Transition::Started { .. }]));
        assert!(step(&mut reg, 300 + OBSERVATION_GAP_MS / 1000, None).is_empty());
        let stale = step(&mut reg, 301 + OBSERVATION_GAP_MS / 1000, None);
        assert!(
            matches!(
                stale.as_slice(),
                [Transition::Ended {
                    unobserved: true,
                    ..
                }]
            ),
            "FSYNC-HEALTH stale_fsync_kept: {stale:?}"
        );
    }

    /// Reads and fsync slow together are one notice naming both, with the
    /// drive's check; slow reads beside a quick fsync keep their own.
    #[test]
    fn slow_reads_and_fsync_are_one_store_condition() {
        let mut reg = HealthRegistry::default();
        reg.observe_store_io(Some(slow_io()), T0);
        reg.observe_store_fsync(1_002, 100, T0);
        reg.evaluate(T0, &no_cadence);
        let c = current(&reg, ConditionKind::StoreIoSlow).unwrap();
        assert_eq!(
            notice_text(&c),
            "Store reads and fsync slow (this node's disk): canary p99 412ms of 58 reads in \
             60s, disk read 25ms/op, write 3.1ms/op, 4 KiB write and fsync 1002ms (bound 100ms).",
            "FSYNC-HEALTH fsync_notice_missing"
        );
        assert_eq!(c.action, ConditionAction::CheckStoreFsync as i32);
        reg.observe_store_fsync(4, 100, T0 + 15_000);
        reg.evaluate(T0 + 15_000, &no_cadence);
        let c = current(&reg, ConditionKind::StoreIoSlow).unwrap();
        assert_eq!(c.store_fsync_ms, None);
        assert_eq!(c.action, ConditionAction::CheckDiskAndLoad as i32);
        assert!(notice_text(&c).starts_with("Store reads slow (this node's disk): "));
    }

    /// A master store that stopped writing is this node's error.
    #[test]
    fn a_master_store_write_failure_is_an_error_of_this_node() {
        let mut reg = HealthRegistry::default();
        reg.observe_master_store(false, T0);
        reg.evaluate(T0, &no_cadence);
        assert!(current(&reg, ConditionKind::MasterStoreWriteFailed).is_none());
        reg.observe_master_store(true, T0 + 15_000);
        reg.evaluate(T0 + 15_000, &no_cadence);
        let c = current(&reg, ConditionKind::MasterStoreWriteFailed).expect("failed");
        assert_eq!(
            c.severity,
            ConditionSeverity::Error as i32,
            "store write failure severity"
        );
        assert_eq!(c.scope, ConditionScope::ThisNode as i32);
        assert_eq!(notice_text(&c), MASTER_STORE_WRITE_FAILED);
    }

    fn reachability_report(
        listen: &[&str],
        announced: &[&str],
        unreachable: bool,
    ) -> NodeReachability {
        NodeReachability {
            listen_multiaddrs: listen.iter().map(ToString::to_string).collect(),
            nat_status: "unknown".to_string(),
            probe_failure: Some(quil_types::proto::node::AutonatProbeFailure {
                class: "dial_error".to_string(),
                probes: 14,
                failing_secs: 1_920,
                unreachable,
            }),
            announced: true,
            announced_pubsub_multiaddrs: announced.iter().map(ToString::to_string).collect(),
            ..Default::default()
        }
    }

    /// Peers cannot dial this node once AutoNAT settles it; a confirmed
    /// address, or probes that do not settle it, are no claim. A bound IPv6
    /// address that is not published is its own note.
    #[test]
    fn reachability_conditions_follow_the_nodes_assessment() {
        let judge = |report: &NodeReachability| {
            let mut reg = HealthRegistry::default();
            reg.observe_reachability(report, T0);
            reg.evaluate(T0, &no_cadence);
            (
                current(&reg, ConditionKind::PeersCannotDial),
                current(&reg, ConditionKind::Ipv6NotPublished),
            )
        };
        let v4 = "/ip4/192.168.1.20/tcp/8336";
        let (dial, ipv6) = judge(&reachability_report(&[v4], &[v4], true));
        let dial = dial.expect("settled");
        assert_eq!(
            notice_text(&dial),
            "Reachability: peers cannot dial this node; run qclient node doctor."
        );
        assert_eq!(dial.action, ConditionAction::RunNodeDoctor as i32);
        assert!(ipv6.is_none());
        // Not settled yet.
        assert!(judge(&reachability_report(&[v4], &[v4], false)).0.is_none());
        // Confirmed.
        let mut confirmed = reachability_report(&[v4], &[v4], true);
        confirmed.confirmed_multiaddrs = vec!["/ip4/203.0.113.7/tcp/8336".to_string()];
        assert!(judge(&confirmed).0.is_none());
        // Binds IPv6, publishes only IPv4.
        let v6 = "/ip6/2001:db8::7/tcp/8336";
        let (_, ipv6) = judge(&reachability_report(&[v4, v6], &[v4], false));
        let ipv6 = ipv6.expect("not published");
        assert_eq!(ipv6.severity, ConditionSeverity::Info as i32);
        assert!(
            !notice_text(&ipv6).contains("2001:db8"),
            "no address in a condition's text: {}",
            notice_text(&ipv6)
        );
        assert!(judge(&reachability_report(&[v4, v6], &[v4, v6], false))
            .1
            .is_none());
    }

    /// Every kind has its own text, label, action and scope, and an unknown
    /// value still reads as something to look up; only reward and
    /// reachability evidence stays on this node.
    #[test]
    fn every_kind_has_text_and_only_reward_and_reachability_stay_local() {
        let mut labels = std::collections::HashSet::new();
        for kind in KINDS {
            let c = HealthCondition {
                kind: kind as i32,
                ..Default::default()
            };
            assert!(!notice_text(&c).contains("see this node's log"), "{kind:?}");
            assert_ne!(kind_label(kind as i32), "unknown");
            assert!(labels.insert(kind_label(kind as i32)), "{kind:?}");
            assert_ne!(action_of(kind), ConditionAction::Unspecified);
            assert_ne!(action_text(action_of(kind) as i32), "see this node's log");
            assert_eq!(
                local_only(kind as i32),
                matches!(
                    kind,
                    ConditionKind::RewardDrop
                        | ConditionKind::PeersCannotDial
                        | ConditionKind::Ipv6NotPublished
                ),
                "{kind:?}"
            );
        }
        let health = HealthConditions {
            conditions: KINDS
                .iter()
                .map(|kind| HealthCondition {
                    kind: *kind as i32,
                    ..Default::default()
                })
                .collect(),
            sources: KINDS
                .iter()
                .map(|kind| ConditionSource {
                    kind: *kind as i32,
                    ..Default::default()
                })
                .collect(),
        };
        let peer = for_peer(health);
        assert_eq!(peer.conditions.len(), KINDS.len() - 3);
        assert_eq!(peer.sources.len(), KINDS.len() - 3);
        assert!(peer.conditions.iter().all(|c| !local_only(c.kind)));
        assert!(peer.sources.iter().all(|s| !local_only(s.kind)));
    }
}
