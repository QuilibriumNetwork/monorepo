//! State model for the `prover manage` TUI. Port of the bubbletea
//! `manageModel` (`client/cmd/node/prover/manage_model.go`) — the state
//! struct, data-refresh processing, and the filter/sort derivations.

use super::super::local_execution::{execution_label, local_execution_state, state_at};
use std::collections::{HashMap, HashSet};

use num_bigint::{BigInt, Sign};

use quil_types::proto::node::{
    GetShardInfoResponse, NodeInfoResponse, ShardAllocationInfo, ShardProverCounts,
    WorkerInfoResponse,
};

use super::super::epoch::{
    action_hints, compute_effective_status, confirmed_phase, epoch_len, ActionHint,
    AllocationTiming, ConfirmWindow, EffectiveStatus, ThresholdClock, ThresholdUnit, WindowState,
};

// ── Column metadata (shared between rendering and filtering) ─────────────

pub const ALLOC_COL_NAMES: [&str; 18] = [
    "Select",
    "Filter",
    "Provers",
    "Ring",
    "Size [GB]",
    "Shards",
    "LocalMat",
    "PeerHead",
    "GlobalHead",
    "Execution",
    "Reward [~Q/d]",
    "Worker",
    "Status",
    "Mode",
    "NextAction",
    "DefaultAction",
    "Interval [s]",
    "ProverPhases",
];
pub const AVAIL_COL_NAMES: [&str; 13] = [
    "Select",
    "Filter",
    "Provers",
    "Ring",
    "Size [GB]",
    "Shards",
    "PeerMat",
    "PeerHead",
    "GlobalHead",
    "PeerState",
    "Reward [~Q/d]",
    "Interval [s]",
    "ProverPhases",
];

// Keep the new measurement beside its committed source without renumbering action columns,
// and ProverPhases beside the Provers count it breaks down.
pub const ALLOC_DISPLAY_COLS: &[usize] =
    &[0, 1, 2, 17, 3, 4, 5, 6, 7, 8, 16, 9, 10, 11, 12, 13, 14, 15];
pub const AVAIL_DISPLAY_COLS: &[usize] = &[0, 1, 2, 12, 3, 4, 5, 6, 7, 8, 11, 9, 10];

/// The optional ProverPhases column in each panel; one visibility setting,
/// keyed by the allocations index, covers both. Hidden until the picker
/// enables it.
pub const ALLOC_PROVER_PHASES_COL: usize = 17;
pub const AVAIL_PROVER_PHASES_COL: usize = 12;

/// Provers-per-shard ceiling at or under which a shard holding data is at
/// halt risk: losing one prover risks its quorum. Mirrors quil-engine's
/// `provers::proposer::HALT_RISK_PROVER_COUNT`, which the client cannot
/// import.
pub const HALT_RISK_PROVER_COUNT: u32 = 3;

pub const INTERVAL_WINDOW_NAMES: &[&str] = &["  60m window", "  24h window"];
/// The Global KPI's fields, in printed order; picker names, and the expanded
/// labels the KPI prints.
pub const GLOBAL_FIELD_NAMES: &[&str] = &["  frame", "  epoch", "  next boundary"];
pub const REWARD_ESTIMATE_NAMES: &[&str] = &["60m window", "24h window", "Theory (T): 10s/frame"];

pub const TOP_KPI_NAMES: &[&str] = &[
    "Peer ID",
    "Strategy",
    "Seniority",
    "Global",
    "Global interval",
    "World size",
    "RPC",
];
pub const ALLOC_KPI_NAMES: &[&str] = &[
    "Workers",
    "Status",
    "Claimable",
    "Reward",
    "Allocation GLOBAL snapshot",
    "Shown allocations",
    "Selected allocations",
];
pub const NOTICE_KPI_NAMES: &[&str] = &["Notification level", "Notification position"];
pub const AVAIL_KPI_NAMES: &[&str] = &[
    "Available count",
    "Available GLOBAL snapshot",
    "Selected shards",
];

pub const ALLOC_FILTERABLE_COLS: [usize; 14] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16];
pub const AVAIL_FILTERABLE_COLS: [usize; 11] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterColKind {
    Text,
    Numeric,
    Select,
}

/// Filter kind per absolute column index (allocations panel).
pub fn alloc_filter_col_kind(col: usize) -> FilterColKind {
    match col {
        1 => FilterColKind::Text,
        9 | 12 | 13 => FilterColKind::Select,
        _ => FilterColKind::Numeric,
    }
}

/// Filter kind per absolute column index (available panel).
pub fn avail_filter_col_kind(col: usize) -> FilterColKind {
    match col {
        1 | 9 => FilterColKind::Text,
        _ => FilterColKind::Numeric,
    }
}

/// How the two tables size their columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColumnSizing {
    /// Measure every column against the rows on screen: a column is as wide
    /// as its own content needs and no wider.
    #[default]
    Dynamic,
    /// The historical layout — a fixed width per column, sized for that
    /// column's worst case rather than for what the table is showing.
    Fixed,
}

// ── Column widths (`ColumnSizing::Fixed`) ────────────────────────────────
//
// Mirrors the Go consts. Shards and the reward columns are minimums rather
// than fixed widths: their content has no upper bound and `{:>w$}` doesn't
// clip, so an over-wide cell would shift every column after it.

pub const SELECT_WIDTH: usize = 6;
pub const FILTER_WIDTH: usize = 70;
pub const PROVERS_WIDTH: usize = 7;
pub const RING_WIDTH: usize = 5;
pub const SIZE_WIDTH: usize = 10;
pub const SHARDS_WIDTH: usize = 7;
pub const MAT_WIDTH: usize = 9;
pub const HEAD_WIDTH: usize = 8;
pub const GLOBAL_HEAD_WIDTH: usize = 10;
pub const STATE_WIDTH: usize = 9;
// Header width in both panels; the values are whole QUIL/day.
pub const REWARD_WIDTH: usize = 12;
pub const ALLOC_REWARD_WIDTH: usize = 12;
pub const WORKER_WIDTH: usize = 7;
pub const STATUS_WIDTH: usize = 12;
pub const MODE_WIDTH: usize = 4;
// Widest absolute values: `(reject|confirm)@f<8 digits>` and `activate@f<8 digits>`;
// the fixed layout grows them for expanded relative estimates.
pub const NEXT_ACTION_WIDTH: usize = 26;
pub const DEFAULT_ACTION_WIDTH: usize = 18;

// 16 spaces between 17 columns, 2 external borders, 1-char sort arrow;
// the optional ProverPhases column adds its own width when shown.
pub const ALLOC_FIXED_WIDTH: usize = SELECT_WIDTH
    + PROVERS_WIDTH
    + RING_WIDTH
    + SIZE_WIDTH
    + SHARDS_WIDTH
    + MAT_WIDTH
    + HEAD_WIDTH
    + GLOBAL_HEAD_WIDTH
    + STATE_WIDTH
    + ALLOC_REWARD_WIDTH
    + WORKER_WIDTH
    + STATUS_WIDTH
    + MODE_WIDTH
    + NEXT_ACTION_WIDTH
    + DEFAULT_ACTION_WIDTH
    + 16
    + 12
    + 2
    + 1;
// 11 spaces between 12 columns, 2 external borders, 1-char sort arrow;
// ProverPhases likewise.
pub const AVAIL_FIXED_WIDTH: usize = SELECT_WIDTH
    + PROVERS_WIDTH
    + RING_WIDTH
    + SIZE_WIDTH
    + SHARDS_WIDTH
    + MAT_WIDTH
    + HEAD_WIDTH
    + GLOBAL_HEAD_WIDTH
    + STATE_WIDTH
    + REWARD_WIDTH
    + 11
    + 12
    + 2
    + 1;

/// Floor for the Filter column in either layout. Filter is what gives way
/// when the pane cannot hold the table, being the only column whose content
/// is already truncated for display.
pub const MIN_FILTER_WIDTH: usize = 12;

// ── Rows ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AllocationRow {
    pub global_head: Option<quil_types::proto::node::GlobalAppFrameHead>,
    pub execution: Option<quil_types::proto::node::WorkerExecution>,
    /// A shard-info row was actually returned for this allocation.
    pub shard_info_known: bool,
    pub allocation_reason: Option<String>,
    pub filter: Vec<u8>,
    pub filter_key: String,
    pub filter_hex: String,
    pub status: u32,
    pub status_name: String,
    pub ring: u32,
    pub active_provers: u32,
    /// The shard's provers by lifecycle phase; `None` when the node did not
    /// report them (older server, or no shard-info row).
    pub prover_counts: Option<ShardProverCounts>,
    pub shard_size: BigInt,
    pub data_shards: u64,
    pub materialized_frame: u64,
    pub latest_frame: u64,
    pub estimated_reward: BigInt,
    pub join_frame: u64,
    pub leave_frame: u64,
    pub worker_id: i64, // core_id, -1 if no worker assigned
    pub next_action: ActionHint,
    pub default_action: ActionHint,
    pub manually_managed: bool,
    // Carried for struct parity with the Go `allocationRow`; not displayed.
    #[allow(dead_code)]
    pub confirm_frame: u64,
    #[allow(dead_code)]
    pub leave_confirm_frame: u64,
    #[allow(dead_code)]
    pub epoch: u64,
    #[allow(dead_code)]
    pub last_active_frame: u64,
}

impl AllocationRow {
    /// Classify staffed live rows for current, paused and planned rewards.
    /// Orphan estimates remain visible in their rows but do not enter totals.
    pub fn reward_status(&self, frame: u64, epoch_length: u64) -> Option<EffectiveStatus> {
        if self.worker_id < 0 || self.status == 0 {
            return None;
        }
        let status = compute_effective_status(
            &AllocationTiming {
                raw_status: self.status,
                filter: &self.filter,
                join_frame: self.join_frame,
                join_confirm_frame: self.confirm_frame,
                leave_frame: self.leave_frame,
                leave_confirm_frame: self.leave_confirm_frame,
                epoch: self.epoch,
            },
            frame,
            epoch_length,
        );
        matches!(
            status,
            EffectiveStatus::Active
                | EffectiveStatus::Joining
                | EffectiveStatus::Paused
                | EffectiveStatus::Leaving
        )
        .then_some(status)
    }

    /// The Mode cell — `m` when the row's worker is managed by hand, `a` when
    /// the node assigns it. Cell values are lower-case; headers carry the
    /// capital.
    pub fn mode(&self) -> &'static str {
        if self.manually_managed {
            "m"
        } else {
            "a"
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShardRow {
    pub global_head: Option<quil_types::proto::node::GlobalAppFrameHead>,
    pub filter: Vec<u8>,
    pub filter_key: String,
    pub filter_hex: String,
    pub active_provers: u32,
    /// As [`AllocationRow::prover_counts`].
    pub prover_counts: Option<ShardProverCounts>,
    pub ring: u32,
    pub shard_size: BigInt,
    pub data_shards: u64,
    pub materialized_frame: u64,
    pub latest_frame: u64,
    pub estimated_reward: BigInt,
}

// ── Column filter state ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ColumnFilter {
    pub text: String,            // substring match (Filter column)
    pub values: HashSet<String>, // selected values (empty = all = no filter)
    pub expr: String,            // numeric expression like "> 47" or "1,5,7"
}

impl ColumnFilter {
    pub fn is_active(&self) -> bool {
        !self.text.is_empty() || !self.values.is_empty() || !self.expr.is_empty()
    }
}

// ── Pending batch action ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PendingAction {
    pub action: String,
    /// The filters one op of the queue carries: one per op for a batch of
    /// single-filter actions, up to the decoders' limit for a split
    /// multi-filter action.
    pub filters: Vec<Vec<u8>>,
    pub status: u32,
}

/// Per-filter await tracking during a post-broadcast confirm loop.
#[derive(Debug, Clone)]
pub struct AwaitFilterEntry {
    pub filter: Vec<u8>,
    pub original_status: u32,
    pub settled: bool,
    pub outcome: String,
}

/// One resolved per-filter outcome from a status poll.
#[derive(Debug, Clone)]
pub struct FilterOutcome {
    pub filter: Vec<u8>,
    pub outcome: String,
    pub settled: bool,
}

/// Progress inferred only from newly returned peer-head snapshots.
#[derive(Debug, Clone)]
pub struct ReportedAppProgress {
    pub frame: u64,
    pub generation: Option<u64>,
    pub last_change: std::time::Instant,
    pub last_seen: std::time::Instant,
    pub observations: u32,
    pub stalled: bool,
}

/// A committed app head (GlobalHead) trailing the shard's app head by more
/// than this many frames is reported as behind.
pub const GLOBAL_APP_LAG_FRAMES: u64 = 100;

/// Progress of GLOBAL's committed app head of one shard, inferred only from
/// newly returned shard snapshots, against the shard's app head: the higher
/// of the peer-reported head and this node's materialized frame.
#[derive(Debug, Clone)]
pub struct CommittedAppProgress {
    pub frame: u64,
    pub generation: u64,
    /// The GLOBAL frame and app head when `frame` last changed.
    pub global_frame: u64,
    pub head: u64,
    pub last_change: std::time::Instant,
    pub last_seen: std::time::Instant,
    pub observations: u32,
    /// Unchanged while GLOBAL and the app head both advanced.
    pub stalled: bool,
    /// More than [`GLOBAL_APP_LAG_FRAMES`] behind the app head.
    pub behind: bool,
}

// ── Model ────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct Model {
    // Header data.
    pub peer_id: String,
    pub seniority: String,
    pub running_workers: u32,
    pub allocated_workers: u32,
    /// The node's configured worker count; 0 from a node that predates it.
    pub worker_capacity: u32,
    pub last_global_head: u64,
    pub reachable: bool,
    pub frame_number: u64,
    pub epoch_length: u64,
    pub current_epoch: u64,
    pub last_received_frame: u64,
    /// Automatic polling cadence, changed by the refresh toggle.
    pub refresh_seconds: u64,
    pub compact_actions: bool,
    pub compact_units: bool,
    pub refresh_changed_at: Option<std::time::Instant>,
    /// Monotonic observation of the received GLOBAL head, independent of RPC success.
    pub global_observed_head: u64,
    pub node_global_cadence: Option<quil_types::proto::node::FrameCadence>,
    pub node_app_cadence: HashMap<Vec<u8>, quil_types::proto::node::FrameCadence>,
    pub reward_windows: u8,
    pub interval_windows: u8,
    pub global_interval_windows: u8,
    /// Bit mask of the shown [`GLOBAL_FIELD_NAMES`].
    pub global_fields: u8,
    pub global_last_advance: Option<std::time::Instant>,
    /// Disruptive command and exact selected allocation identities/statuses.
    pub operation_confirmation: Option<(char, Vec<(String, u32, i64, bool)>)>,
    pub difficulty: u64,

    // Verified GLOBAL reward witness, refreshed independently of shard queries.
    pub claimable_reward: Option<(u128, u64)>,
    pub reward_loaded: bool,
    pub reward_last_success: Option<std::time::Instant>,

    // Panel data.
    pub allocations: Vec<AllocationRow>,
    pub available: Vec<ShardRow>,
    pub alloc_cursor: usize,
    pub avail_cursor: usize,
    pub focus: PanelFocus,
    pub panel_boundary_offsets: [i16; 2],
    pub panel_content_heights: [u16; 3],
    pub horizontal_offsets: [u16; 2],
    pub horizontal_limits: [u16; 2],
    pub alloc_offset: usize,
    pub avail_offset: usize,

    // Multiselect state (filter_key present == selected).
    pub alloc_selected: HashSet<String>,
    pub avail_selected: HashSet<String>,

    // Batch action queue.
    pub action_queue: Vec<PendingAction>,
    pub action_total: usize,
    pub action_index: usize,

    // Free workers (no filter assigned).
    pub free_workers: Vec<u32>,

    // Join worker picker.
    pub join_picker_active: bool,
    pub join_picker_cursor: usize,
    pub join_picker_offset: usize,
    pub join_picker_workers: Vec<u32>,
    pub join_picker_selected: HashSet<u32>,
    pub join_picker_filters: Vec<Vec<u8>>,

    // Await state.
    pub await_action: String,
    pub await_filters: Vec<AwaitFilterEntry>,
    pub await_send_frame: u64,
    pub await_retries: u32,
    /// Wall-clock deadline as elapsed-seconds budget from await start.
    pub await_deadline_secs: u64,
    pub await_start: Option<std::time::Instant>,

    // Sort state per panel (-1 == no explicit sort, stored as i32).
    pub alloc_sort_col: i32,
    pub alloc_sort_asc: bool,
    pub avail_sort_col: i32,
    pub avail_sort_asc: bool,

    // Sort selection mode.
    pub sort_mode: bool,
    pub sort_order_mode: bool,
    pub sort_highlight_col: usize,

    // Per-column filters (keyed by absolute column index).
    pub alloc_col_filters: HashMap<usize, ColumnFilter>,
    pub avail_col_filters: HashMap<usize, ColumnFilter>,

    // Filter navigation mode per panel.
    pub alloc_filter_mode: bool,
    pub alloc_filter_highlight_idx: usize,
    pub avail_filter_mode: bool,
    pub avail_filter_highlight_idx: usize,

    // Filter column edit state.
    pub filter_edit_active: bool,
    pub filter_edit_col_idx: usize,
    pub filter_edit_input: String,
    pub filter_edit_select_cursor: usize,
    pub filter_edit_select_items: Vec<String>,
    pub filter_edit_select_state: HashMap<String, bool>,

    // UI.
    pub width: u16,
    pub height: u16,
    pub notice_minimum: NoticeSeverity,
    pub notice_offset: usize,
    pub notice_lines: usize,
    pub notice_visible: usize,
    pub app_progress_observed_since: Option<std::time::Instant>,
    pub global_alarm_time: Option<std::time::SystemTime>,
    pub app_stall_time: Option<std::time::SystemTime>,
    pub reported_app_progress: HashMap<Vec<u8>, ReportedAppProgress>,
    pub reported_app_stall_time: Option<std::time::SystemTime>,
    pub committed_app_progress: HashMap<Vec<u8>, CommittedAppProgress>,
    /// Allocations (filter keys) whose local materialized frame is unchanged
    /// for 60s, and the staffed earning allocations with fresh observations.
    pub local_stalled_rows: HashSet<String>,
    pub local_stalled_count: usize,
    pub local_app_rows: usize,
    /// When each current condition notice was first observed, by its key.
    pub notice_since: HashMap<&'static str, std::time::SystemTime>,
    pub status_msg: String,
    pub status_message_key: String,
    pub status_message_seen: Option<std::time::Instant>,
    pub status_message_time: Option<std::time::SystemTime>,
    pub status_is_error: bool,
    pub status_sticky: bool,
    pub action_in_flight: bool,
    pub show_help: bool,
    /// First help line drawn under the pinned title. The help outgrew a
    /// terminal once it documented every key and every column, and a screen
    /// that silently loses its bottom half is worse than a short one.
    pub help_offset: usize,
    /// Help lines the last frame produced, so scrolling can stop at the end
    /// without the key handler having to know how the screen is built.
    pub help_lines: usize,
    pub help_visible: usize,
    pub color_coding: bool,
    pub column_sizing: ColumnSizing,
    pub alloc_column_order: Vec<usize>,
    pub avail_column_order: Vec<usize>,
    pub hidden_columns: HashSet<usize>,
    pub hidden_header_kpis: HashSet<String>,
    /// Columns, top header, Allocations, Available and Notifications headers.
    pub visibility_section: usize,
    pub column_picker_active: bool,
    pub column_picker_cursor: usize,
    pub column_picker_offset: usize,
    pub threshold_unit: ThresholdUnit,
    pub spinner_frame: usize,

    // Load / staleness tracking.
    pub data_loaded: bool,
    pub last_fetch_success: Option<std::time::Instant>,
    pub consecutive_failures: u32,

    // Aux-response cache (stabilizes panels across transient RPC blips).
    pub cached_node_info: Option<NodeInfoResponse>,
    pub shard_loading: bool,
    pub shard_message_time: Option<std::time::SystemTime>,
    pub shard_fetch_started: Option<std::time::Instant>,
    pub shard_last_success: Option<std::time::Instant>,
    pub shard_last_duration: Option<std::time::Duration>,
    pub shard_error: Option<String>,
    pub cached_shard_info: Option<GetShardInfoResponse>,
    /// Receipt clock of the last successful worker snapshot; cache reuse cannot reset it.
    pub worker_snapshot_received: Option<(std::time::Instant, u64)>,
    pub cached_worker_info: Option<WorkerInfoResponse>,

    // Broadcast accumulator for the await loop.
    pub broadcasted_filters: Vec<Vec<u8>>,
    pub broadcasted_statuses: Vec<u32>,
    /// Messages of the current action that failed, the filters they
    /// carried, and the first failure's error.
    pub failed_messages: usize,
    pub failed_filters: usize,
    pub first_failure: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum NoticeSeverity {
    Info,
    #[default]
    Warning,
    Error,
}

impl NoticeSeverity {
    pub fn next(self) -> Self {
        match self {
            Self::Info => Self::Warning,
            Self::Warning => Self::Error,
            Self::Error => Self::Info,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "all",
            Self::Warning => "warnings+",
            Self::Error => "errors",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PanelFocus {
    #[default]
    Allocations,
    Available,
    Notifications,
}

impl PanelFocus {
    pub fn index(self) -> usize {
        match self {
            Self::Allocations => 0,
            Self::Available => 1,
            Self::Notifications => 2,
        }
    }
    pub fn next(self) -> Self {
        match self {
            Self::Allocations => Self::Available,
            Self::Available => Self::Notifications,
            Self::Notifications => Self::Allocations,
        }
    }
    pub fn previous(self) -> Self {
        match self {
            Self::Allocations => Self::Notifications,
            Self::Available => Self::Allocations,
            Self::Notifications => Self::Available,
        }
    }
    pub fn is_alloc(self) -> bool {
        matches!(self, PanelFocus::Allocations)
    }
}

impl Model {
    pub fn new() -> Self {
        Model {
            color_coding: true,
            compact_actions: true,
            alloc_column_order: ALLOC_DISPLAY_COLS.to_vec(),
            avail_column_order: AVAIL_DISPLAY_COLS.to_vec(),
            hidden_columns: [ALLOC_PROVER_PHASES_COL].into_iter().collect(),
            reward_windows: 7,
            interval_windows: 3,
            global_interval_windows: 3,
            global_fields: 7,
            compact_units: true,
            refresh_seconds: 15,
            alloc_sort_col: 11, // Worker column
            alloc_sort_asc: true,
            avail_sort_col: 10, // Reward column
            avail_sort_asc: false,
            reachable: false,
            ..Default::default()
        }
    }

    /// Joining allocations have no execution requirement before admission.
    /// Retain observed states and unknown telemetry for admitted allocations.
    pub fn allocation_execution_state<'a>(&self, row: &'a AllocationRow) -> &'a str {
        if row.execution.is_none() && matches!(row.status_name.as_str(), "joining" | "activating") {
            "-"
        } else {
            execution_label(self.execution_state(row.execution.as_ref()))
        }
    }

    /// Classify node observation age at receipt, separately from client cache age.
    pub fn execution_state<'a>(
        &self,
        execution: Option<&'a quil_types::proto::node::WorkerExecution>,
    ) -> &'a str {
        self.execution_state_at(execution, std::time::Instant::now())
    }

    fn execution_state_at<'a>(
        &self,
        execution: Option<&'a quil_types::proto::node::WorkerExecution>,
        now: std::time::Instant,
    ) -> &'a str {
        if execution.is_none() {
            return "unknown";
        }
        let Some((received, wall_ms)) = self.worker_snapshot_received else {
            return local_execution_state(execution);
        };
        if now.saturating_duration_since(received).as_secs() > self.refresh_seconds * 2 + 30 {
            return "cached";
        }
        state_at(execution, wall_ms)
    }

    /// `epochFrame` — frame the client uses for epoch-aligned lifecycle math.
    pub fn epoch_frame(&self) -> u64 {
        if self.last_received_frame > 0 {
            self.last_received_frame
        } else {
            self.frame_number
        }
    }

    pub fn cadence_window<'a>(
        &self,
        cadence: &'a quil_types::proto::node::FrameCadence,
        day: bool,
    ) -> Option<&'a quil_types::proto::node::FrameWindow> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        if now < cadence.last_observed_unix_seconds || now - cadence.last_observed_unix_seconds > 90
        {
            return None;
        }
        let w = if day {
            cadence.day.as_ref()?
        } else {
            cadence.hour.as_ref()?
        };
        (w.observed_seconds >= 60 && w.observed_seconds <= w.window_seconds).then_some(w)
    }
    pub fn interval_mask(&self) -> u8 {
        let mask = self.interval_windows & 3;
        if mask == 0 {
            1
        } else {
            mask
        }
    }
    pub fn global_interval_mask(&self) -> u8 {
        let mask = self.global_interval_windows & 3;
        if mask == 0 {
            1
        } else {
            mask
        }
    }
    pub fn global_field_mask(&self) -> u8 {
        let mask = self.global_fields & 7;
        if mask == 0 {
            1
        } else {
            mask
        }
    }
    /// Measured mean seconds per received GLOBAL frame: the 60m window when it
    /// has advances, else the 24h one; `None` without a fresh measurement.
    pub fn global_seconds_per_frame(&self) -> Option<f64> {
        let cadence = self.node_global_cadence.as_ref()?;
        [false, true].into_iter().find_map(|day| {
            self.cadence_window(cadence, day)
                .filter(|w| w.advanced_frames > 0)
                .map(|w| w.observed_seconds as f64 / w.advanced_frames as f64)
        })
    }
    /// What Next/Default Action thresholds count from; expanded mode adds the
    /// `~` time estimate.
    pub fn threshold_clock(&self) -> ThresholdClock {
        ThresholdClock {
            frame: self.epoch_frame(),
            seconds_per_frame: if self.compact_actions {
                None
            } else {
                self.global_seconds_per_frame()
            },
        }
    }
    pub fn global_interval_labels(&self) -> String {
        ["60m", "24h"]
            .iter()
            .enumerate()
            .filter(|(i, _)| self.global_interval_mask() & (1 << i) != 0)
            .map(|(_, label)| *label)
            .collect::<Vec<_>>()
            .join("/")
    }
    pub fn interval_labels(&self) -> String {
        ["60m", "24h"]
            .iter()
            .enumerate()
            .filter(|(i, _)| self.interval_mask() & (1 << i) != 0)
            .map(|(_, label)| *label)
            .collect::<Vec<_>>()
            .join("/")
    }
    pub fn reward_mask(&self) -> u8 {
        if self.reward_windows == 0 {
            4
        } else {
            self.reward_windows & 7
        }
    }
    pub fn reward_labels(&self) -> String {
        [
            "60m",
            "24h",
            if self.compact_units { "T" } else { "theory" },
        ]
        .iter()
        .enumerate()
        .filter(|(i, _)| self.reward_mask() & (1 << i) != 0)
        .map(|(_, s)| *s)
        .collect::<Vec<_>>()
        .join("/")
    }
    pub fn daily_reward(&self, per_frame: &BigInt, filter: &[u8], index: usize) -> Option<BigInt> {
        if index == 2 {
            return Some(per_frame * BigInt::from(8640));
        }
        if self.shard_error.is_some() {
            return None;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        super::super::observed_quil_daily(
            per_frame,
            self.node_app_cadence.get(filter)?,
            index == 1,
            now,
        )
    }
    pub fn app_interval(&self, filter: &[u8]) -> Option<f64> {
        self.cadence_window(
            self.node_app_cadence.get(filter)?,
            self.interval_mask() == 2,
        )
        .and_then(|w| {
            (w.advanced_frames > 0).then(|| w.observed_seconds as f64 / w.advanced_frames as f64)
        })
    }
    /// RPC values are node-owned; cached refreshes never invent observations.
    pub fn observe_app_intervals(
        &mut self,
        shards: &GetShardInfoResponse,
        _now: std::time::Instant,
    ) {
        self.node_app_cadence = shards
            .shards
            .iter()
            .filter_map(|s| s.frame_cadence.clone().map(|c| (s.filter.clone(), c)))
            .collect();
    }

    /// Track only fresh node responses; shard-cache refreshes cannot reset this clock.
    pub fn observe_global_head(&mut self, head: u64, now: std::time::Instant) {
        if self.global_last_advance.is_none() || head > self.global_observed_head {
            self.global_observed_head = head;
            self.global_last_advance = Some(now);
            self.global_alarm_time = None;
        }
    }

    /// Record peer-head progress once per fresh shard RPC, never on cache reuse.
    pub fn observe_reported_app_heads(
        &mut self,
        shards: &GetShardInfoResponse,
        now: std::time::Instant,
    ) {
        let budget = std::time::Duration::from_secs(self.refresh_seconds * 2 + 30);
        let window = std::time::Duration::from_secs(60.max(self.refresh_seconds * 3));
        let mut known = HashSet::new();
        for shard in &shards.shards {
            // Empty/unknown peer metadata and unstaffed shards cannot establish a stall.
            if shard.active_provers == 0
                || (shard.latest_frame == 0 && shard.materialized_frame == 0)
            {
                continue;
            }
            if !known.insert(shard.filter.clone()) {
                continue;
            }
            let generation = shard.global_head.as_ref().map(|h| h.generation);
            let progress = self
                .reported_app_progress
                .entry(shard.filter.clone())
                .or_insert(ReportedAppProgress {
                    frame: shard.latest_frame,
                    generation,
                    last_change: now,
                    last_seen: now,
                    observations: 0,
                    stalled: false,
                });
            if progress.frame != shard.latest_frame
                || progress.generation != generation
                || now.saturating_duration_since(progress.last_seen) > budget
            {
                *progress = ReportedAppProgress {
                    frame: shard.latest_frame,
                    generation,
                    last_change: now,
                    last_seen: now,
                    observations: 0,
                    stalled: false,
                };
            }
            progress.last_seen = now;
            progress.observations = progress.observations.saturating_add(1);
            if progress.observations >= 3
                && now.saturating_duration_since(progress.last_change) >= window
            {
                progress.stalled = true;
            }
        }
        self.reported_app_progress
            .retain(|filter, _| known.contains(filter));
    }

    pub fn reported_app_stalled(&self, filter: &[u8]) -> bool {
        if self.shard_error.is_some() {
            return false;
        }
        self.reported_app_progress.get(filter).is_some_and(|p| {
            p.stalled && p.last_seen.elapsed().as_secs() <= self.refresh_seconds * 2 + 30
        })
    }

    pub fn reported_app_stall_counts(&self, now: std::time::Instant) -> Option<(usize, usize)> {
        if self.shard_error.is_some() {
            return None;
        }
        let budget = std::time::Duration::from_secs(self.refresh_seconds * 2 + 30);
        let known: Vec<_> = self
            .reported_app_progress
            .values()
            .filter(|p| now.saturating_duration_since(p.last_seen) <= budget)
            .collect();
        let stalled = known.iter().filter(|p| p.stalled).count();
        (stalled > 0).then_some((stalled, known.len()))
    }

    /// Record GLOBAL's committed app heads once per fresh shard RPC, never on
    /// cache reuse. Unstaffed shards and shards without a committed head or
    /// an app head cannot establish a stall or a lag.
    pub fn observe_committed_app_heads(
        &mut self,
        shards: &GetShardInfoResponse,
        now: std::time::Instant,
    ) {
        let budget = std::time::Duration::from_secs(self.refresh_seconds * 2 + 30);
        let window = std::time::Duration::from_secs(60.max(self.refresh_seconds * 3));
        let mut local: HashMap<Vec<u8>, u64> = HashMap::new();
        for a in &self.allocations {
            if let Some(frame) = a.execution.as_ref().and_then(|e| e.materialized_frame) {
                let entry = local.entry(a.filter.clone()).or_default();
                *entry = (*entry).max(frame);
            }
        }
        let mut known = HashSet::new();
        for shard in &shards.shards {
            let Some(committed) = shard.global_head.as_ref() else {
                continue;
            };
            let head = shard
                .latest_frame
                .max(local.get(&shard.filter).copied().unwrap_or(0));
            if shard.active_provers == 0 || head == 0 || !known.insert(shard.filter.clone()) {
                continue;
            }
            let fresh = CommittedAppProgress {
                frame: committed.frame,
                generation: committed.generation,
                global_frame: committed.global_frame,
                head,
                last_change: now,
                last_seen: now,
                observations: 0,
                stalled: false,
                behind: false,
            };
            let progress = self
                .committed_app_progress
                .entry(shard.filter.clone())
                .or_insert_with(|| fresh.clone());
            if progress.frame != committed.frame
                || progress.generation != committed.generation
                || now.saturating_duration_since(progress.last_seen) > budget
            {
                *progress = fresh;
            }
            progress.last_seen = now;
            progress.observations = progress.observations.saturating_add(1);
            progress.behind = head.saturating_sub(committed.frame) > GLOBAL_APP_LAG_FRAMES;
            if progress.observations >= 3
                && now.saturating_duration_since(progress.last_change) >= window
                && committed.global_frame > progress.global_frame
                && head > progress.head
            {
                progress.stalled = true;
            }
        }
        self.committed_app_progress
            .retain(|filter, _| known.contains(filter));
    }

    /// The shard's GlobalHead is stalled or behind in a fresh snapshot.
    pub fn committed_app_flagged(&self, filter: &[u8]) -> bool {
        if self.shard_error.is_some() {
            return false;
        }
        self.committed_app_progress.get(filter).is_some_and(|p| {
            (p.stalled || p.behind)
                && p.last_seen.elapsed().as_secs() <= self.refresh_seconds * 2 + 30
        })
    }

    /// Stalled and behind shards, and the tracked shards with fresh snapshots.
    pub fn committed_app_counts(&self, now: std::time::Instant) -> Option<(usize, usize, usize)> {
        if self.shard_error.is_some() {
            return None;
        }
        let budget = std::time::Duration::from_secs(self.refresh_seconds * 2 + 30);
        let known: Vec<_> = self
            .committed_app_progress
            .values()
            .filter(|p| now.saturating_duration_since(p.last_seen) <= budget)
            .collect();
        let stalled = known.iter().filter(|p| p.stalled).count();
        let behind = known.iter().filter(|p| p.behind).count();
        (stalled + behind > 0).then_some((stalled, behind, known.len()))
    }

    // ── Data refresh ─────────────────────────────────────────────────────

    /// `processRefreshData` — merge NodeInfo + ShardInfo + WorkerInfo into
    /// model state, building the two panels' rows.
    pub fn process_refresh_data(
        &mut self,
        node_info: Option<NodeInfoResponse>,
        shard_info: Option<GetShardInfoResponse>,
        worker_info: Option<WorkerInfoResponse>,
    ) {
        let Some(node_info) = node_info else {
            return;
        };

        self.cached_node_info = Some(node_info.clone());

        // Aux cache: prefer fresh, fall back to cached.
        let shard_info = match shard_info {
            Some(s) => {
                self.cached_shard_info = Some(s.clone());
                Some(s)
            }
            None => self.cached_shard_info.clone(),
        };
        let worker_info = match worker_info {
            Some(w) => {
                self.worker_snapshot_received = Some((
                    std::time::Instant::now(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                ));
                self.cached_worker_info = Some(w.clone());
                Some(w)
            }
            None => self.cached_worker_info.clone(),
        };

        // Header.
        self.node_global_cadence = node_info.frame_cadence.clone();
        if let Some(shards) = &shard_info {
            self.node_app_cadence = shards
                .shards
                .iter()
                .filter_map(|s| s.frame_cadence.clone().map(|c| (s.filter.clone(), c)))
                .collect();
        }
        self.peer_id = node_info.peer_id.clone();
        if !node_info.peer_seniority.is_empty() {
            self.seniority =
                BigInt::from_bytes_be(Sign::Plus, &node_info.peer_seniority).to_string();
        }
        self.running_workers = node_info.running_workers;
        self.allocated_workers = node_info.allocated_workers;
        self.worker_capacity = node_info.worker_capacity;
        self.last_global_head = node_info.last_global_head_frame;
        self.reachable = node_info.reachable;
        self.epoch_length = node_info.epoch_length_frames;
        self.current_epoch = node_info.current_epoch;
        self.last_received_frame = node_info.last_received_frame;

        if let Some(si) = &shard_info {
            self.frame_number = si.frame_number;
            self.difficulty = si.difficulty;
        }

        // Worker maps: core_id + manually_managed by filter hex.
        let mut workers: HashMap<String, (u32, bool)> = HashMap::new();
        if let Some(wi) = &worker_info {
            for w in &wi.worker_info {
                workers.insert(hex::encode(&w.filter), (w.core_id, w.manually_managed));
            }
        }

        // Free workers (empty filter).
        let mut free_workers: Vec<u32> = Vec::new();
        if let Some(wi) = &worker_info {
            for w in &wi.worker_info {
                if w.filter.is_empty() {
                    free_workers.push(w.core_id);
                }
            }
        }
        free_workers.sort_unstable();
        self.free_workers = free_workers;

        // Shard reward info by filter for enrichment.
        let mut reward_by_filter: HashMap<String, &_> = HashMap::new();
        if let Some(si) = &shard_info {
            for s in &si.shards {
                reward_by_filter.insert(hex::encode(&s.filter), s);
            }
        }

        let mut allocated_filters: HashSet<String> = HashSet::new();
        let ef = self.epoch_frame();
        let el = self.epoch_length;
        let next_boundary = (self.current_epoch + 1) * epoch_len(el);

        let mut allocs: Vec<AllocationRow> = Vec::with_capacity(node_info.shard_allocations.len());
        for a in &node_info.shard_allocations {
            let s = a.status;
            if s != 1 && s != 2 && s != 3 && s != 4 {
                continue;
            }
            let t = timing(a);
            let eff = compute_effective_status(&t, ef, el);
            if eff == EffectiveStatus::ExpiredJoining || eff == EffectiveStatus::ExpiredLeaving {
                continue;
            }

            let filter_hex = hex::encode(&a.filter);
            allocated_filters.insert(filter_hex.clone());
            let status_name = confirmed_phase(&t, eff, el)
                .map_or(eff.label(), |(name, _)| name)
                .to_string();

            let (next_action, default_action) = action_hints(&t, eff, el, ef, next_boundary);

            let (wid, mm) = workers
                .get(&filter_hex)
                .map(|(id, m)| (*id as i64, *m))
                .unwrap_or((-1, false));

            let execution = worker_info
                .as_ref()
                .and_then(|wi| {
                    wi.worker_info
                        .iter()
                        .find(|w| w.core_id as i64 == wid && w.filter == a.filter)
                })
                .and_then(|w| w.execution.clone());
            let mut row = AllocationRow {
                global_head: None,
                execution,
                shard_info_known: false,
                allocation_reason: None,
                filter: a.filter.clone(),
                filter_key: filter_hex.clone(),
                filter_hex: filter_hex.clone(),
                status: a.status,
                status_name,
                ring: UNKNOWN_REWARD_RING,
                active_provers: 0,
                prover_counts: None,
                shard_size: BigInt::from(0),
                data_shards: 0,
                materialized_frame: 0,
                latest_frame: 0,
                estimated_reward: BigInt::from(0),
                join_frame: a.join_frame_number,
                confirm_frame: a.join_confirm_frame_number,
                leave_frame: a.leave_frame_number,
                leave_confirm_frame: a.leave_confirm_frame_number,
                epoch: a.epoch,
                last_active_frame: a.last_active_frame_number,
                worker_id: wid,
                next_action,
                default_action,
                manually_managed: mm,
            };
            if let Some(info) = reward_by_filter.get(&filter_hex) {
                row.global_head = info.global_head.clone();
                row.shard_info_known = true;
                row.allocation_reason = info.allocation_reason.clone();
                row.ring = reward_ring(info);
                row.allocation_reason = info.allocation_reason.clone();
                row.active_provers = info.active_provers;
                row.prover_counts = info.prover_counts.clone();
                row.shard_size = BigInt::from_bytes_be(Sign::Plus, &info.shard_size);
                row.data_shards = info.data_shards;
                row.materialized_frame = info.materialized_frame;
                row.latest_frame = info.latest_frame;
                row.estimated_reward = BigInt::from_bytes_be(Sign::Plus, &info.estimated_reward);
            }
            allocs.push(row);
        }

        // Every reported worker stays visible, including a nonempty binding
        // whose allocation was retired or omitted from this registry snapshot.
        // Such a worker is bound, not idle, and has no allocation reward totals.
        let represented_workers: HashSet<i64> = allocs
            .iter()
            .filter(|a| a.worker_id >= 0)
            .map(|a| a.worker_id)
            .collect();
        if let Some(wi) = &worker_info {
            for w in &wi.worker_info {
                if !represented_workers.contains(&(w.core_id as i64)) {
                    let idle = w.filter.is_empty();
                    let filter_hex = hex::encode(&w.filter);
                    allocs.push(AllocationRow {
                        global_head: reward_by_filter
                            .get(&filter_hex)
                            .and_then(|info| info.global_head.clone()),
                        execution: w.execution.clone(),
                        shard_info_known: false,
                        allocation_reason: None,
                        filter: w.filter.clone(),
                        filter_key: format!("worker:{}", w.core_id),
                        filter_hex,
                        status: 0,
                        status_name: if idle { "idle" } else { "bound" }.to_string(),
                        ring: UNKNOWN_REWARD_RING,
                        active_provers: 0,
                        prover_counts: None,
                        shard_size: BigInt::from(0),
                        data_shards: 0,
                        materialized_frame: 0,
                        latest_frame: 0,
                        estimated_reward: BigInt::from(0),
                        join_frame: 0,
                        confirm_frame: 0,
                        leave_frame: 0,
                        leave_confirm_frame: 0,
                        epoch: 0,
                        last_active_frame: 0,
                        worker_id: w.core_id as i64,
                        next_action: ActionHint::none(),
                        default_action: ActionHint::none(),
                        manually_managed: w.manually_managed,
                    });
                }
            }
        }
        self.allocations = allocs;

        // Available shards: from ShardInfo where not allocated.
        let mut avail: Vec<ShardRow> = Vec::new();
        if let Some(si) = &shard_info {
            for s in &si.shards {
                let filter_hex = hex::encode(&s.filter);
                if s.is_allocated || allocated_filters.contains(&filter_hex) {
                    continue;
                }
                avail.push(ShardRow {
                    global_head: s.global_head.clone(),
                    filter: s.filter.clone(),
                    filter_key: filter_hex.clone(),
                    filter_hex,
                    active_provers: s.active_provers,
                    prover_counts: s.prover_counts.clone(),
                    ring: reward_ring(s),
                    shard_size: BigInt::from_bytes_be(Sign::Plus, &s.shard_size),
                    data_shards: s.data_shards,
                    materialized_frame: s.materialized_frame,
                    latest_frame: s.latest_frame,
                    estimated_reward: BigInt::from_bytes_be(Sign::Plus, &s.estimated_reward),
                });
            }
        }
        self.available = avail;

        self.clamp_cursors();
    }

    // ── Filtering + sorting ──────────────────────────────────────────────

    pub fn filtered_allocations(&self) -> Vec<AllocationRow> {
        if self.alloc_col_filters.is_empty() {
            return self.allocations.clone();
        }
        self.allocations
            .iter()
            .filter(|r| self.alloc_row_matches(r))
            .cloned()
            .collect()
    }

    fn alloc_row_matches(&self, row: &AllocationRow) -> bool {
        for (&col, cf) in &self.alloc_col_filters {
            if !cf.is_active() {
                continue;
            }
            match alloc_filter_col_kind(col) {
                FilterColKind::Text => {
                    if !row.filter_hex.contains(&cf.text) {
                        return false;
                    }
                }
                FilterColKind::Numeric => {
                    if !super::filter::matches_numeric_expr(
                        alloc_row_numeric_val(self, row, col),
                        &cf.expr,
                    ) {
                        return false;
                    }
                }
                FilterColKind::Select => {
                    if !cf.values.is_empty()
                        && !cf.values.contains(&alloc_row_text_val(self, row, col))
                    {
                        return false;
                    }
                }
            }
        }
        true
    }

    pub fn filtered_available(&self) -> Vec<ShardRow> {
        if self.avail_col_filters.is_empty() {
            return self.available.clone();
        }
        self.available
            .iter()
            .filter(|r| self.avail_row_matches(r))
            .cloned()
            .collect()
    }

    fn avail_row_matches(&self, row: &ShardRow) -> bool {
        for (&col, cf) in &self.avail_col_filters {
            if !cf.is_active() {
                continue;
            }
            match avail_filter_col_kind(col) {
                FilterColKind::Text => {
                    if !row.filter_hex.contains(&cf.text) {
                        return false;
                    }
                }
                FilterColKind::Numeric => {
                    if !super::filter::matches_numeric_expr(
                        avail_row_numeric_val(self, row, col),
                        &cf.expr,
                    ) {
                        return false;
                    }
                }
                FilterColKind::Select => {}
            }
        }
        true
    }

    pub fn sorted_allocations(&self) -> Vec<AllocationRow> {
        let mut rows = self.filtered_allocations();
        let col = self.alloc_sort_col;
        if col < 0 {
            return rows;
        }
        let asc = self.alloc_sort_asc;
        let sel = &self.alloc_selected;
        // Thresholds sort by verb, then frame, whichever way they are displayed.
        let hint_order = |a: &ActionHint, b: &ActionHint| {
            a.label.cmp(&b.label).then(a.at_frame.cmp(&b.at_frame))
        };
        rows.sort_by(|a, b| {
            let ord = match col {
                0 => sel
                    .contains(&a.filter_key)
                    .cmp(&sel.contains(&b.filter_key)),
                1 => a.filter_hex.cmp(&b.filter_hex),
                2 => a.active_provers.cmp(&b.active_provers),
                3 => a.ring.cmp(&b.ring),
                4 => a.shard_size.cmp(&b.shard_size),
                5 => a.data_shards.cmp(&b.data_shards),
                6 => a
                    .execution
                    .as_ref()
                    .and_then(|s| s.materialized_frame)
                    .cmp(&b.execution.as_ref().and_then(|s| s.materialized_frame)),
                7 => a.latest_frame.cmp(&b.latest_frame),
                8 => a
                    .global_head
                    .as_ref()
                    .map(|h| h.frame)
                    .cmp(&b.global_head.as_ref().map(|h| h.frame)),
                9 => self
                    .allocation_execution_state(a)
                    .cmp(self.allocation_execution_state(b)),
                10 => self
                    .daily_reward(
                        &a.estimated_reward,
                        &a.filter,
                        self.reward_mask().trailing_zeros() as usize,
                    )
                    .cmp(&self.daily_reward(
                        &b.estimated_reward,
                        &b.filter,
                        self.reward_mask().trailing_zeros() as usize,
                    )),
                16 => self
                    .app_interval(&a.filter)
                    .partial_cmp(&self.app_interval(&b.filter))
                    .unwrap_or(std::cmp::Ordering::Equal),
                // ALLOC_PROVER_PHASES_COL; the sort column is an i32.
                17 => prover_phase_order(a.prover_counts.as_ref())
                    .cmp(&prover_phase_order(b.prover_counts.as_ref())),
                11 => a.worker_id.cmp(&b.worker_id),
                12 => a.status.cmp(&b.status),
                13 => a.manually_managed.cmp(&b.manually_managed),
                14 => hint_order(&a.next_action, &b.next_action),
                15 => hint_order(&a.default_action, &b.default_action),
                _ => std::cmp::Ordering::Equal,
            };
            if asc {
                ord
            } else {
                ord.reverse()
            }
        });
        rows
    }

    pub fn sorted_available(&self) -> Vec<ShardRow> {
        let mut rows = self.filtered_available();
        let col = self.avail_sort_col;
        if col < 0 {
            return rows;
        }
        let asc = self.avail_sort_asc;
        let sel = &self.avail_selected;
        rows.sort_by(|a, b| {
            let ord = match col {
                0 => sel
                    .contains(&a.filter_key)
                    .cmp(&sel.contains(&b.filter_key)),
                1 => a.filter_hex.cmp(&b.filter_hex),
                2 => a.active_provers.cmp(&b.active_provers),
                3 => a.ring.cmp(&b.ring),
                4 => a.shard_size.cmp(&b.shard_size),
                5 => a.data_shards.cmp(&b.data_shards),
                6 => a.materialized_frame.cmp(&b.materialized_frame),
                7 => a.latest_frame.cmp(&b.latest_frame),
                8 => a
                    .global_head
                    .as_ref()
                    .map(|h| h.frame)
                    .cmp(&b.global_head.as_ref().map(|h| h.frame)),
                9 => materialization_state(a.materialized_frame, a.latest_frame)
                    .cmp(materialization_state(b.materialized_frame, b.latest_frame)),
                10 => self
                    .daily_reward(
                        &a.estimated_reward,
                        &a.filter,
                        self.reward_mask().trailing_zeros() as usize,
                    )
                    .cmp(&self.daily_reward(
                        &b.estimated_reward,
                        &b.filter,
                        self.reward_mask().trailing_zeros() as usize,
                    )),
                11 => self
                    .app_interval(&a.filter)
                    .partial_cmp(&self.app_interval(&b.filter))
                    .unwrap_or(std::cmp::Ordering::Equal),
                // AVAIL_PROVER_PHASES_COL; the sort column is an i32.
                12 => prover_phase_order(a.prover_counts.as_ref())
                    .cmp(&prover_phase_order(b.prover_counts.as_ref())),
                _ => std::cmp::Ordering::Equal,
            };
            if asc {
                ord
            } else {
                ord.reverse()
            }
        });
        rows
    }

    pub fn clamp_cursors(&mut self) {
        let na = self.sorted_allocations().len();
        if self.alloc_cursor >= na {
            self.alloc_cursor = na.saturating_sub(1);
        }
        let nv = self.sorted_available().len();
        if self.avail_cursor >= nv {
            self.avail_cursor = nv.saturating_sub(1);
        }
    }

    // ── Selection helpers ────────────────────────────────────────────────

    /// `selectedAllocRows` — selected rows in display order, or the cursor row.
    pub fn selected_alloc_rows(&self) -> Vec<AllocationRow> {
        let sorted = self.sorted_allocations();
        if sorted.is_empty() {
            return Vec::new();
        }
        let selected: Vec<AllocationRow> = sorted
            .iter()
            .filter(|r| self.alloc_selected.contains(&r.filter_key))
            .cloned()
            .collect();
        if !selected.is_empty() {
            return selected;
        }
        sorted.get(self.alloc_cursor).cloned().into_iter().collect()
    }

    pub fn selected_avail_rows(&self) -> Vec<ShardRow> {
        let sorted = self.sorted_available();
        if sorted.is_empty() {
            return Vec::new();
        }
        let selected: Vec<ShardRow> = sorted
            .iter()
            .filter(|r| self.avail_selected.contains(&r.filter_key))
            .cloned()
            .collect();
        if !selected.is_empty() {
            return selected;
        }
        sorted.get(self.avail_cursor).cloned().into_iter().collect()
    }

    // ── Applicable actions (for help highlighting + labels) ──────────────

    /// Free workers already managed manually, eligible for operator joins.
    pub fn manual_free_workers(&self) -> Vec<u32> {
        self.free_workers
            .iter()
            .copied()
            .filter(|id| {
                self.allocations
                    .iter()
                    .any(|r| r.worker_id == i64::from(*id) && r.status == 0 && r.manually_managed)
            })
            .collect()
    }

    /// `applicableAllocActions` — action names valid for the current
    /// allocation selection (intersection across all selected rows).
    pub fn applicable_alloc_actions(&self) -> HashSet<String> {
        if self.action_in_flight {
            return HashSet::new();
        }
        let rows = self.selected_alloc_rows();
        if rows.is_empty() {
            return HashSet::new();
        }
        let ef = self.epoch_frame();
        let el = self.epoch_length;
        let actions_for_row = |row: &AllocationRow| -> HashSet<String> {
            let window_gated = |propose_frame: u64| -> HashSet<String> {
                let mut a = HashSet::new();
                if propose_frame == 0 {
                    a.insert("Reject".to_string());
                    a.insert("Confirm".to_string());
                    return a;
                }
                let w = ConfirmWindow::for_frame(propose_frame, el);
                if w.state(ef, el) == WindowState::Open {
                    a.insert("Confirm".to_string());
                    a.insert("Reject".to_string());
                }
                a
            };
            if !row.manually_managed {
                return match row.status {
                    2 => ["Pause".to_string()].into_iter().collect(),
                    3 => ["Resume".to_string()].into_iter().collect(),
                    _ => HashSet::new(),
                };
            }
            match row.status {
                1 => window_gated(row.join_frame),
                4 => window_gated(row.leave_frame),
                2 => ["Leave", "Pause"].iter().map(|s| s.to_string()).collect(),
                3 => ["Leave", "Resume"].iter().map(|s| s.to_string()).collect(),
                _ => HashSet::new(),
            }
        };
        let mut result = actions_for_row(&rows[0]);
        for row in &rows[1..] {
            let row_actions = actions_for_row(row);
            result.retain(|a| row_actions.contains(a));
        }
        result
    }

    /// `applicableActionsLabel` — human-readable list for status messages.
    pub fn applicable_actions_label(&self) -> String {
        if self.focus == PanelFocus::Available {
            if !self.manual_free_workers().is_empty() {
                return "Join".to_string();
            }
            return "none (no free manual workers)".to_string();
        }
        let actions = self.applicable_alloc_actions();
        if actions.is_empty() {
            return "none".to_string();
        }
        let mut names = Vec::new();
        for a in ["Confirm", "Reject", "Leave", "Pause", "Resume"] {
            if actions.contains(a) {
                names.push(a);
            }
        }
        names.join(", ")
    }

    // ── Filter mode helpers ──────────────────────────────────────────────

    pub fn active_panel_filter_cols(&self) -> Vec<usize> {
        let cols: &[usize] = if self.focus.is_alloc() {
            &ALLOC_FILTERABLE_COLS
        } else {
            &AVAIL_FILTERABLE_COLS
        };
        self.display_columns()
            .iter()
            .copied()
            .filter(|col| cols.contains(col) && self.column_visible(*col))
            .collect()
    }

    pub fn column_visibility_key(&self, col: usize) -> usize {
        if self.focus.is_alloc() {
            col
        } else {
            avail_visibility_key(col)
        }
    }

    pub fn alloc_column_visible(&self, col: usize) -> bool {
        col < 2 || !self.hidden_columns.contains(&col)
    }

    pub fn avail_column_visible(&self, col: usize) -> bool {
        col < 2 || !self.hidden_columns.contains(&avail_visibility_key(col))
    }

    pub fn column_visible(&self, col: usize) -> bool {
        if self.focus.is_alloc() {
            self.alloc_column_visible(col)
        } else {
            self.avail_column_visible(col)
        }
    }

    pub fn alloc_display_columns(&self) -> &[usize] {
        if self.alloc_column_order.is_empty() {
            ALLOC_DISPLAY_COLS
        } else {
            &self.alloc_column_order
        }
    }
    pub fn avail_display_columns(&self) -> &[usize] {
        if self.avail_column_order.is_empty() {
            AVAIL_DISPLAY_COLS
        } else {
            &self.avail_column_order
        }
    }
    pub fn display_columns(&self) -> &[usize] {
        if self.focus.is_alloc() {
            self.alloc_display_columns()
        } else {
            self.avail_display_columns()
        }
    }
    fn column_children(&self, col: usize) -> usize {
        if col == 10 {
            3
        } else if col == if self.focus.is_alloc() { 16 } else { 11 } {
            2
        } else {
            0
        }
    }
    fn picker_column(&self, index: usize) -> Option<(usize, usize)> {
        let mut row = 0;
        for &col in self.display_columns() {
            let count = 1 + self.column_children(col);
            if index < row + count {
                return Some((col, index - row));
            }
            row += count;
        }
        None
    }
    pub fn visibility_column_index(&self, index: usize) -> Option<usize> {
        self.picker_column(index)
            .filter(|(_, child)| *child == 0)
            .map(|(col, _)| col)
    }
    /// The top-header picker row `index` as its KPI and child number; child 0
    /// is the KPI itself.
    pub fn top_picker_item(index: usize) -> Option<(&'static str, usize)> {
        let mut row = 0;
        for &name in TOP_KPI_NAMES {
            let children = top_kpi_children(name).len();
            if index <= row + children {
                return Some((name, index - row));
            }
            row += children + 1;
        }
        None
    }
    /// The Global KPI field at top-header picker row `index`.
    pub fn visibility_global_field(&self, section: usize, index: usize) -> Option<usize> {
        match Self::top_picker_item(index) {
            Some(("Global", child)) if section == 1 && child > 0 => Some(child - 1),
            _ => None,
        }
    }
    pub fn visibility_interval_window(
        &self,
        section: usize,
        index: usize,
    ) -> Option<(bool, usize)> {
        if section == 1 {
            return match Self::top_picker_item(index) {
                Some(("Global interval", child)) if child > 0 => Some((true, child - 1)),
                _ => None,
            };
        }
        if section == 0 {
            let (col, child) = self.picker_column(index)?;
            if col == (if self.focus.is_alloc() { 16 } else { 11 }) && child > 0 {
                return Some((false, child - 1));
            }
        }
        None
    }
    pub fn visibility_reward_window(&self, section: usize, index: usize) -> Option<usize> {
        if section == 0 {
            let (col, child) = self.picker_column(index)?;
            if col == 10 && child > 0 {
                return Some(child - 1);
            }
        } else if section == 2 && (4..7).contains(&index) {
            return Some(index - 4);
        }
        None
    }
    pub fn move_picker_column(&mut self, up: bool) {
        let Some((col, child)) = self.picker_column(self.column_picker_cursor) else {
            return;
        };
        let mut order = self.display_columns().to_vec();
        let Some(pos) = order.iter().position(|&c| c == col) else {
            return;
        };
        let next = if up { pos.saturating_sub(1) } else { pos + 1 };
        if pos < 2 || next < 2 || next >= order.len() {
            return;
        }
        order.swap(pos, next);
        self.column_picker_cursor = order[..next]
            .iter()
            .map(|&c| 1 + self.column_children(c))
            .sum::<usize>()
            + child;
        if self.focus.is_alloc() {
            self.alloc_column_order = order;
        } else {
            self.avail_column_order = order;
        }
        self.column_picker_offset = 0;
        self.horizontal_offsets[usize::from(!self.focus.is_alloc())] = 0;
    }
    pub fn reset_picker_column_order(&mut self) {
        if self.focus.is_alloc() {
            self.alloc_column_order = ALLOC_DISPLAY_COLS.to_vec();
        } else {
            self.avail_column_order = AVAIL_DISPLAY_COLS.to_vec();
        }
        self.column_picker_cursor = 2;
        self.column_picker_offset = 0;
        self.horizontal_offsets[usize::from(!self.focus.is_alloc())] = 0;
    }

    pub fn active_visible_columns(&self) -> Vec<usize> {
        self.display_columns()
            .iter()
            .copied()
            .filter(|&col| self.column_visible(col))
            .collect()
    }

    pub fn is_filter_mode_active(&self) -> bool {
        if self.focus.is_alloc() {
            self.alloc_filter_mode
        } else {
            self.avail_filter_mode
        }
    }

    pub fn filter_highlight_idx(&self) -> usize {
        if self.focus.is_alloc() {
            self.alloc_filter_highlight_idx
        } else {
            self.avail_filter_highlight_idx
        }
    }

    /// Absolute column index highlighted in filter mode (-1 == none).
    pub fn active_filter_col_idx(&self) -> i32 {
        let cols = self.active_panel_filter_cols();
        let idx = self.filter_highlight_idx();
        if idx < cols.len() {
            cols[idx] as i32
        } else {
            -1
        }
    }

    pub fn active_filter_col_kind(&self, col: usize) -> FilterColKind {
        if self.focus.is_alloc() {
            alloc_filter_col_kind(col)
        } else {
            avail_filter_col_kind(col)
        }
    }

    pub fn active_filter_col(&self, col: usize) -> ColumnFilter {
        let map = if self.focus.is_alloc() {
            &self.alloc_col_filters
        } else {
            &self.avail_col_filters
        };
        map.get(&col).cloned().unwrap_or_default()
    }

    pub fn set_active_filter_col(&mut self, col: usize, cf: ColumnFilter) {
        let map = if self.focus.is_alloc() {
            &mut self.alloc_col_filters
        } else {
            &mut self.avail_col_filters
        };
        if cf.is_active() {
            map.insert(col, cf);
        } else {
            map.remove(&col);
        }
    }

    pub fn has_active_filters(&self) -> bool {
        let map = if self.focus.is_alloc() {
            &self.alloc_col_filters
        } else {
            &self.avail_col_filters
        };
        map.values().any(|cf| cf.is_active())
    }

    /// Unique text values for a select-kind column (allocations only).
    pub fn filter_select_values(&self, col: usize) -> Vec<String> {
        let mut seen: HashSet<String> = HashSet::new();
        if self.focus.is_alloc() {
            for row in &self.allocations {
                let v = alloc_row_text_val(self, row, col);
                if !v.is_empty() {
                    seen.insert(v);
                }
            }
        }
        let mut vals: Vec<String> = seen.into_iter().collect();
        vals.sort();
        vals
    }

    pub fn visibility_names(&self) -> Vec<&'static str> {
        self.visibility_names_for(self.visibility_section)
    }
    pub fn visibility_names_for(&self, section: usize) -> Vec<&'static str> {
        match section {
            4 => NOTICE_KPI_NAMES.to_vec(),
            3 => AVAIL_KPI_NAMES.to_vec(),
            1 => TOP_KPI_NAMES
                .iter()
                .flat_map(|&name| {
                    std::iter::once(name).chain(top_kpi_children(name).iter().copied())
                })
                .collect(),
            2 => ALLOC_KPI_NAMES
                .iter()
                .flat_map(|&name| {
                    if name == "Reward" {
                        std::iter::once(name)
                            .chain(REWARD_ESTIMATE_NAMES.iter().copied())
                            .collect::<Vec<_>>()
                    } else {
                        vec![name]
                    }
                })
                .collect(),
            _ => {
                let names = if self.focus.is_alloc() {
                    &ALLOC_COL_NAMES[..]
                } else {
                    &AVAIL_COL_NAMES[..]
                };
                let interval = if self.focus.is_alloc() { 16 } else { 11 };
                self.display_columns()
                    .iter()
                    .flat_map(|&col| {
                        if col == interval {
                            vec![
                                names[col],
                                INTERVAL_WINDOW_NAMES[0],
                                INTERVAL_WINDOW_NAMES[1],
                            ]
                        } else if col == 10 {
                            std::iter::once(names[col])
                                .chain(REWARD_ESTIMATE_NAMES.iter().copied())
                                .collect()
                        } else {
                            vec![names[col]]
                        }
                    })
                    .collect()
            }
        }
    }

    pub fn header_kpi_visible(&self, name: &str) -> bool {
        !self.hidden_header_kpis.contains(name)
    }

    pub fn visibility_item_visible_in(&self, section: usize, index: usize) -> bool {
        if let Some((global, window)) = self.visibility_interval_window(section, index) {
            (if global {
                self.global_interval_mask()
            } else {
                self.interval_mask()
            }) & (1 << window)
                != 0
        } else if let Some(field) = self.visibility_global_field(section, index) {
            self.global_field_mask() & (1 << field) != 0
        } else if let Some(window) = self.visibility_reward_window(section, index) {
            self.reward_mask() & (1 << window) != 0
        } else if section == 0 {
            self.visibility_column_index(index)
                .is_some_and(|col| self.column_visible(col))
        } else {
            self.visibility_names_for(section)
                .get(index)
                .is_some_and(|name| self.header_kpi_visible(name))
        }
    }
}

/// The picker sub-items nested beneath a top-header KPI.
fn top_kpi_children(name: &str) -> &'static [&'static str] {
    match name {
        "Global" => GLOBAL_FIELD_NAMES,
        "Global interval" => INTERVAL_WINDOW_NAMES,
        _ => &[],
    }
}

// ── Row value accessors (for filtering + sorting) ────────────────────────

pub fn alloc_row_numeric_val(m: &Model, row: &AllocationRow, col: usize) -> f64 {
    if !row.shard_info_known && matches!(col, 2..=5 | 7 | 10) {
        return f64::NAN;
    }
    match col {
        2 => row.active_provers as f64,
        3 => {
            if row.ring == UNKNOWN_REWARD_RING {
                f64::NAN
            } else {
                row.ring as f64
            }
        }
        4 => bigint_to_f64(&row.shard_size) / 1_000_000_000.0,
        5 => row.data_shards as f64,
        6 => row
            .execution
            .as_ref()
            .and_then(|s| s.materialized_frame)
            .map_or(f64::NAN, |h| h as f64),
        7 => {
            if row.materialized_frame == 0 && row.latest_frame == 0 {
                f64::NAN
            } else {
                row.latest_frame as f64
            }
        }
        8 => row
            .global_head
            .as_ref()
            .map_or(f64::NAN, |h| h.frame as f64),
        10 => {
            if row.ring == UNKNOWN_REWARD_RING {
                f64::NAN
            } else {
                m.daily_reward(
                    &row.estimated_reward,
                    &row.filter,
                    m.reward_mask().trailing_zeros() as usize,
                )
                .map_or(f64::NAN, |v| {
                    bigint_to_f64(&v) / crate::util::UNITS_PER_QUIL as f64
                })
            }
        }
        11 => row.worker_id as f64,
        16 => m.app_interval(&row.filter).unwrap_or(f64::NAN),
        _ => 0.0,
    }
}

pub fn alloc_row_text_val(m: &Model, row: &AllocationRow, col: usize) -> String {
    match col {
        1 => row.filter_hex.clone(),
        9 => m.allocation_execution_state(row).to_string(),
        12 => super::view::allocation_status_text(m, row),
        13 => row.mode().to_string(),
        _ => String::new(),
    }
}

pub fn avail_row_numeric_val(m: &Model, row: &ShardRow, col: usize) -> f64 {
    match col {
        2 => row.active_provers as f64,
        3 => {
            if row.ring == UNKNOWN_REWARD_RING {
                f64::NAN
            } else {
                row.ring as f64
            }
        }
        4 => bigint_to_f64(&row.shard_size) / 1_000_000_000.0,
        5 => row.data_shards as f64,
        6 => {
            if row.materialized_frame == 0 && row.latest_frame == 0 {
                f64::NAN
            } else {
                row.materialized_frame as f64
            }
        }
        7 => {
            if row.materialized_frame == 0 && row.latest_frame == 0 {
                f64::NAN
            } else {
                row.latest_frame as f64
            }
        }
        8 => row
            .global_head
            .as_ref()
            .map_or(f64::NAN, |h| h.frame as f64),
        10 => {
            if row.ring == UNKNOWN_REWARD_RING {
                f64::NAN
            } else {
                m.daily_reward(
                    &row.estimated_reward,
                    &row.filter,
                    m.reward_mask().trailing_zeros() as usize,
                )
                .map_or(f64::NAN, |v| {
                    bigint_to_f64(&v) / crate::util::UNITS_PER_QUIL as f64
                })
            }
        }
        11 => m.app_interval(&row.filter).unwrap_or(f64::NAN),
        _ => 0.0,
    }
}

/// Internal display sentinel; it never leaves the client on the wire.
pub const UNKNOWN_REWARD_RING: u32 = u32::MAX;

pub fn reward_ring(info: &quil_types::proto::node::ShardRewardInfo) -> u32 {
    if info.ring_known == Some(false) {
        UNKNOWN_REWARD_RING
    } else {
        info.ring
    }
}

pub fn materialization_state(materialized: u64, latest: u64) -> &'static str {
    match (materialized, latest) {
        (_, 0) => "unknown",
        (0, _) => "unmat",
        (mat, head) if mat >= head => "current",
        _ => "lag",
    }
}

/// An available-panel column's visibility key: the allocations index of
/// the same field, so both panels share one setting.
fn avail_visibility_key(col: usize) -> usize {
    match col {
        11 => 16,
        AVAIL_PROVER_PHASES_COL => ALLOC_PROVER_PHASES_COL,
        _ => col,
    }
}

/// Provers that serve the shard after the next epoch boundary: active ones
/// and confirmed joins. Departing provers are counted apart and leave at it.
pub fn serving_after_boundary(counts: &ShardProverCounts) -> u32 {
    counts.active.saturating_add(counts.activating)
}

/// Halt risk by count: the shard holds data and at most
/// [`HALT_RISK_PROVER_COUNT`] of its provers are active or activating.
/// Unreported counts establish nothing.
pub fn prover_halt_risk(counts: Option<&ShardProverCounts>, size: &BigInt) -> bool {
    counts.is_some_and(|c| {
        size.sign() == Sign::Plus && serving_after_boundary(c) <= HALT_RISK_PROVER_COUNT
    })
}

/// ProverPhases sorts by the provers serving after the next boundary, then
/// by active ones; unreported counts sort first ascending.
fn prover_phase_order(counts: Option<&ShardProverCounts>) -> Option<(u32, u32)> {
    counts.map(|c| (serving_after_boundary(c), c.active))
}

#[cfg(test)]
mod readability_tests {
    use super::*;
    use crate::commands::node::prover::epoch::raw_status;

    const EL: u64 = 720;

    fn alloc(status: u32) -> ShardAllocationInfo {
        ShardAllocationInfo {
            filter: vec![0xFF],
            status,
            ..Default::default()
        }
    }

    fn hints_in(
        a: &ShardAllocationInfo,
        current_frame: u64,
        unit: ThresholdUnit,
    ) -> (String, String) {
        let t = timing(a);
        let eff = compute_effective_status(&t, current_frame, EL);
        let next_boundary = (current_frame / EL + 1) * EL;
        let (n, d) = action_hints(&t, eff, EL, current_frame, next_boundary);
        let clock = ThresholdClock {
            frame: current_frame,
            seconds_per_frame: None,
        };
        (n.render(unit, clock), d.render(unit, clock))
    }

    fn hints(a: &ShardAllocationInfo, current_frame: u64) -> (String, String) {
        hints_in(a, current_frame, ThresholdUnit::Absolute)
    }

    #[test]
    fn a_pending_join_groups_both_verbs_under_one_threshold() {
        let mut a = alloc(raw_status::JOINING);
        a.join_frame_number = 1117 * EL + 10; // window is epoch 1118
                                              // Still in epoch 1117: neither verb is available yet.
        assert_eq!(
            hints(&a, 1117 * EL + 100),
            (
                "(reject|confirm)@f804960".to_string(),
                "expire@f805680".to_string()
            )
        );
        // Inside epoch 1118: both are available, so the threshold drops.
        assert_eq!(
            hints(&a, 1118 * EL + 100),
            ("(reject|confirm)".to_string(), "expire@f805680".to_string())
        );
    }

    #[test]
    fn every_threshold_reads_in_the_selected_unit() {
        let mut a = alloc(raw_status::JOINING);
        a.join_frame_number = 1117 * EL + 10;
        assert_eq!(
            hints_in(&a, 1117 * EL + 100, ThresholdUnit::Relative),
            (
                "(reject|confirm) in 620f".to_string(),
                "expire in 1340f".to_string()
            )
        );
        // An unbounded hint is unit-independent.
        let free = ActionHint::text("(pause|leave)");
        let clock = ThresholdClock {
            frame: 1117 * EL,
            seconds_per_frame: Some(10.0),
        };
        assert_eq!(free.render(ThresholdUnit::Relative, clock), "(pause|leave)");
        assert_eq!(free.render(ThresholdUnit::Absolute, clock), "(pause|leave)");
    }

    #[test]
    fn an_active_allocation_renews_at_the_next_epoch_boundary() {
        let mut a = alloc(raw_status::ACTIVE);
        a.epoch = 1118;
        assert_eq!(
            hints(&a, 1118 * EL + 100),
            ("(pause|leave)".to_string(), "renew@f805680".to_string())
        );
    }

    #[test]
    fn a_stale_epoch_keeps_the_same_renewal_default() {
        let mut a = alloc(raw_status::ACTIVE);
        a.epoch = 1117; // missed epoch 1118
        let t = timing(&a);
        assert_eq!(
            compute_effective_status(&t, 1118 * EL + 100, EL),
            EffectiveStatus::ExpiredEpoch
        );
        assert_eq!(
            hints(&a, 1118 * EL + 100),
            ("(pause|leave)".to_string(), "renew@f805680".to_string())
        );
    }

    #[test]
    fn a_confirmed_join_activates_at_the_boundary_after_confirmation() {
        let mut a = alloc(raw_status::ACTIVE);
        a.epoch = 1118;
        a.join_confirm_frame_number = 1118 * EL + 5; // activates in epoch 1119
        assert_eq!(
            hints(&a, 1118 * EL + 100),
            ("(pause|leave)".to_string(), "activate@f805680".to_string())
        );
    }

    #[test]
    fn a_confirmed_leave_departs_and_offers_nothing_to_do() {
        let mut a = alloc(raw_status::LEAVING);
        a.leave_frame_number = 1117 * EL + 10;
        a.leave_confirm_frame_number = 1118 * EL + 5; // departs in epoch 1119
        assert_eq!(
            hints(&a, 1118 * EL + 100),
            (String::new(), "depart@f805680".to_string())
        );
    }

    #[test]
    fn a_paused_allocation_has_no_default_transition() {
        let a = alloc(raw_status::PAUSED);
        assert_eq!(
            hints(&a, 1118 * EL + 100),
            ("(resume|leave)".to_string(), String::new())
        );
    }

    #[test]
    fn defaults_sort_allocations_by_worker_and_available_by_reward() {
        let m = Model::new();
        assert_eq!(ALLOC_COL_NAMES[m.alloc_sort_col as usize], "Worker");
        assert!(m.alloc_sort_asc);
        assert_eq!(AVAIL_COL_NAMES[m.avail_sort_col as usize], "Reward [~Q/d]");
        assert!(!m.avail_sort_asc);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

pub fn bigint_to_f64(v: &BigInt) -> f64 {
    v.to_string().parse::<f64>().unwrap_or(0.0)
}

/// BigInt (assumed < 2^64) → u64, for the display formatters.
// Retained display conversion; current fields use other precision formats.
#[allow(dead_code)]
pub fn bigint_to_u64(v: &BigInt) -> u64 {
    let (_, digits) = v.to_u64_digits();
    digits.first().copied().unwrap_or(0)
}

fn timing(a: &ShardAllocationInfo) -> AllocationTiming<'_> {
    AllocationTiming {
        raw_status: a.status,
        filter: &a.filter,
        join_frame: a.join_frame_number,
        join_confirm_frame: a.join_confirm_frame_number,
        leave_frame: a.leave_frame_number,
        leave_confirm_frame: a.leave_confirm_frame_number,
        epoch: a.epoch,
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn reported_heads_track_individual_shards_and_ignore_unknown_or_unstaffed_rows() {
        use quil_types::proto::node::ShardRewardInfo;
        use std::time::{Duration, Instant};
        let start = Instant::now();
        let mut m = Model::new();
        let mut shards = GetShardInfoResponse {
            shards: vec![
                ShardRewardInfo {
                    filter: vec![1],
                    active_provers: 1,
                    latest_frame: 10,
                    ..Default::default()
                },
                ShardRewardInfo {
                    filter: vec![2],
                    active_provers: 1,
                    latest_frame: 20,
                    ..Default::default()
                },
                ShardRewardInfo {
                    filter: vec![3],
                    active_provers: 1,
                    ..Default::default()
                },
                ShardRewardInfo {
                    filter: vec![4],
                    latest_frame: 30,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        for secs in [0, 30, 60] {
            shards.shards[1].latest_frame += 1;
            m.observe_reported_app_heads(&shards, start + Duration::from_secs(secs));
        }
        assert_eq!(m.reported_app_progress.len(), 2);
        assert_eq!(
            m.reported_app_stall_counts(start + Duration::from_secs(60)),
            Some((1, 2))
        );
        // Row filtering and cache-backed local-status refreshes do not affect tracking.
        m.allocations.clear();
        m.available.clear();
        m.process_refresh_data(Some(NodeInfoResponse::default()), None, None);
        assert_eq!(m.reported_app_progress[&vec![1]].observations, 3);
        m.refresh_seconds = 60;
        m.observe_reported_app_heads(&shards, start + Duration::from_secs(61));
        assert_eq!(
            m.reported_app_stall_counts(start + Duration::from_secs(61)),
            Some((1, 2))
        );
        shards.shards[0].latest_frame += 1;
        m.observe_reported_app_heads(&shards, start + Duration::from_secs(62));
        assert_eq!(
            m.reported_app_stall_counts(start + Duration::from_secs(62)),
            None
        );
    }

    #[test]
    fn reported_heads_require_fresh_confirmations_and_reset_on_missing_data_or_generation() {
        use quil_types::proto::node::{GlobalAppFrameHead, ShardRewardInfo};
        use std::time::{Duration, Instant};
        let start = Instant::now();
        let mut m = Model::new();
        let mut shards = GetShardInfoResponse {
            shards: vec![ShardRewardInfo {
                filter: vec![1],
                active_provers: 1,
                latest_frame: 10,
                global_head: Some(GlobalAppFrameHead {
                    generation: 1,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        m.observe_reported_app_heads(&shards, start);
        m.observe_reported_app_heads(&shards, start + Duration::from_secs(60));
        assert_eq!(
            m.reported_app_stall_counts(start + Duration::from_secs(60)),
            None
        );
        m.observe_reported_app_heads(&shards, start + Duration::from_secs(61));
        assert_eq!(
            m.reported_app_stall_counts(start + Duration::from_secs(61)),
            Some((1, 1))
        );
        m.shard_error = Some("fetch failed".into());
        assert_eq!(
            m.reported_app_stall_counts(start + Duration::from_secs(61)),
            None
        );
        m.shard_error = None;
        assert_eq!(
            m.reported_app_stall_counts(start + Duration::from_secs(122)),
            None
        );
        m.observe_reported_app_heads(&shards, start + Duration::from_secs(122));
        assert_eq!(m.reported_app_progress[&vec![1]].observations, 1);
        assert!(!m.reported_app_progress[&vec![1]].stalled);
        shards.shards[0].global_head.as_mut().unwrap().generation = 2;
        m.observe_reported_app_heads(&shards, start + Duration::from_secs(123));
        assert_eq!(m.reported_app_progress[&vec![1]].observations, 1);
        shards.shards[0].latest_frame = 9;
        m.observe_reported_app_heads(&shards, start + Duration::from_secs(124));
        assert_eq!(m.reported_app_progress[&vec![1]].observations, 1);
        m.observe_reported_app_heads(
            &GetShardInfoResponse::default(),
            start + Duration::from_secs(125),
        );
        assert!(m.reported_app_progress.is_empty());
    }
    use super::*;

    fn allocation(filter: Vec<u8>, epoch: u64) -> ShardAllocationInfo {
        ShardAllocationInfo {
            filter,
            status: super::super::super::epoch::raw_status::ACTIVE,
            epoch,
            ..Default::default()
        }
    }

    fn shard_info(filter: Vec<u8>, reward: u8) -> GetShardInfoResponse {
        use quil_types::proto::node::ShardRewardInfo;

        GetShardInfoResponse {
            shards: vec![ShardRewardInfo {
                ring_known: Some(true),
                filter,
                estimated_reward: vec![reward],
                ..Default::default()
            }],
            frame_number: 2_160,
            ..Default::default()
        }
    }

    fn node_info(allocation: ShardAllocationInfo) -> NodeInfoResponse {
        NodeInfoResponse {
            shard_allocations: vec![allocation],
            current_epoch: 3,
            epoch_length_frames: 720,
            last_received_frame: 2_160,
            ..Default::default()
        }
    }

    #[test]
    fn prover_phase_counts_reach_allocation_and_available_rows() {
        use quil_types::proto::node::{ShardProverCounts, ShardRewardInfo};
        let counts = ShardProverCounts {
            joining: 3,
            activating: 1,
            active: 12,
            paused: 0,
            leaving: 2,
            departing: 1,
        };
        let mut shards = shard_info(vec![0xab], 1);
        shards.shards[0].prover_counts = Some(counts.clone());
        shards.shards.push(ShardRewardInfo {
            ring_known: Some(true),
            filter: vec![0xcd],
            prover_counts: Some(counts.clone()),
            ..Default::default()
        });
        // An older server leaves the counts absent.
        shards.shards.push(ShardRewardInfo {
            ring_known: Some(true),
            filter: vec![0xef],
            active_provers: 4,
            ..Default::default()
        });
        let mut model = Model::new();
        model.process_refresh_data(
            Some(node_info(allocation(vec![0xab], 3))),
            Some(shards),
            None,
        );
        assert_eq!(model.allocations.len(), 1);
        assert_eq!(model.allocations[0].prover_counts, Some(counts.clone()));
        let available = |filter: u8| {
            model
                .available
                .iter()
                .find(|row| row.filter == vec![filter])
                .unwrap()
                .prover_counts
                .clone()
        };
        assert_eq!(available(0xcd), Some(counts));
        assert_eq!(available(0xef), None, "absent counts are not zero counts");
        // An allocation without a shard-info row has none either.
        let mut model = Model::new();
        model.process_refresh_data(
            Some(node_info(allocation(vec![0x01], 3))),
            Some(GetShardInfoResponse::default()),
            None,
        );
        assert_eq!(model.allocations[0].prover_counts, None);
    }

    #[test]
    fn absent_shard_metadata_does_not_match_measured_zero_filters() {
        let filter = vec![0xab];
        let mut model = Model::new();
        model.process_refresh_data(
            Some(node_info(allocation(filter.clone(), 3))),
            Some(GetShardInfoResponse::default()),
            None,
        );
        assert!(!model.allocations[0].shard_info_known);
        for col in [2, 3, 4, 5, 6, 7, 10] {
            assert!(!super::super::filter::matches_numeric_expr(
                alloc_row_numeric_val(
                    &Model {
                        reward_windows: 4,
                        ..Model::new()
                    },
                    &model.allocations[0],
                    col
                ),
                "=0"
            ));
        }
        model.process_refresh_data(
            Some(node_info(allocation(filter.clone(), 3))),
            Some(shard_info(filter, 0)),
            None,
        );
        assert!(model.allocations[0].shard_info_known);
        for col in [2, 3, 4, 5, 10] {
            assert_eq!(
                alloc_row_numeric_val(
                    &Model {
                        reward_windows: 4,
                        ..Model::new()
                    },
                    &model.allocations[0],
                    col
                ),
                0.0
            );
        }
    }

    #[test]
    fn refresh_distinguishes_unknown_ring_from_real_zero() {
        let filter = vec![0xab];
        let mut model = Model::new();
        let mut info = shard_info(filter.clone(), 0);
        info.shards[0].ring_known = Some(false);
        model.process_refresh_data(
            Some(node_info(allocation(filter.clone(), 3))),
            Some(info.clone()),
            None,
        );
        assert_eq!(model.allocations[0].ring, UNKNOWN_REWARD_RING);
        for col in [3, 6, 7, 10] {
            assert!(!super::super::filter::matches_numeric_expr(
                alloc_row_numeric_val(
                    &Model {
                        reward_windows: 4,
                        ..Model::new()
                    },
                    &model.allocations[0],
                    col
                ),
                "=0"
            ));
        }
        info.shards[0].ring_known = Some(true);
        info.shards[0].latest_frame = 20;
        model.process_refresh_data(
            Some(node_info(allocation(filter.clone(), 3))),
            Some(info.clone()),
            None,
        );
        assert_eq!(model.allocations[0].ring, 0);
        assert_eq!(
            alloc_row_numeric_val(
                &Model {
                    reward_windows: 4,
                    ..Model::new()
                },
                &model.allocations[0],
                3
            ),
            0.0
        );
        assert_eq!(
            alloc_row_numeric_val(
                &Model {
                    reward_windows: 4,
                    ..Model::new()
                },
                &model.allocations[0],
                10
            ),
            0.0
        );
        assert_eq!(materialization_state(0, 20), "unmat");
        info.shards[0].ring_known = None;
        info.shards[0].ring = 2;
        model.process_refresh_data(
            Some(node_info(allocation(filter.clone(), 3))),
            Some(info),
            None,
        );
        assert_eq!(
            model.allocations[0].ring, 2,
            "older servers remain compatible"
        );
        assert_eq!(materialization_state(10, 0), "unknown");
    }

    #[test]
    fn refresh_keeps_bound_workers_without_live_allocations_visible() {
        use quil_types::proto::node::{WorkerExecution, WorkerInfo};
        let parent = vec![0xaa];
        let child = vec![0xbb];
        let unassigned = vec![0xcc];
        let mut retired = allocation(parent.clone(), 3);
        retired.status = 7;
        let mut node = node_info(allocation(child.clone(), 3));
        node.running_workers = 3;
        node.allocated_workers = 2;
        node.shard_allocations
            .extend([allocation(unassigned.clone(), 3), retired]);
        let mut workers = WorkerInfoResponse {
            worker_info: vec![
                WorkerInfo {
                    core_id: 6,
                    filter: parent.clone(),
                    manually_managed: true,
                    execution: Some(WorkerExecution {
                        state: "blocked".into(),
                        blocker: "closing session".into(),
                        materialized_frame: Some(12),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                WorkerInfo {
                    core_id: 7,
                    filter: child.clone(),
                    ..Default::default()
                },
                WorkerInfo {
                    core_id: 8,
                    ..Default::default()
                },
            ],
        };
        let mut model = Model::new();
        model.process_refresh_data(
            Some(node.clone()),
            Some(shard_info(parent.clone(), 42)),
            Some(workers.clone()),
        );
        assert_eq!(
            model.allocations.len(),
            4,
            "three workers and one unassigned live allocation"
        );
        for id in [6, 7, 8] {
            assert_eq!(
                model
                    .allocations
                    .iter()
                    .filter(|a| a.worker_id == id)
                    .count(),
                1
            );
        }
        let bound = model.allocations.iter().find(|a| a.worker_id == 6).unwrap();
        assert_eq!(bound.status_name, "bound");
        assert_eq!(
            bound.status, 0,
            "worker rows cannot submit allocation actions"
        );
        assert_eq!(bound.filter, parent);
        assert!(bound.manually_managed);
        assert_eq!(
            bound.execution.as_ref().unwrap().materialized_frame,
            Some(12)
        );
        assert_eq!(bound.execution.as_ref().unwrap().blocker, "closing session");
        assert!(
            !bound.shard_info_known,
            "a retired filter estimate is not a live worker reward"
        );
        assert_eq!(bound.reward_status(2160, 720), None);
        assert_eq!(
            model
                .allocations
                .iter()
                .find(|a| a.worker_id == 8)
                .unwrap()
                .status_name,
            "idle"
        );
        assert_eq!(
            model
                .allocations
                .iter()
                .find(|a| a.filter == unassigned)
                .unwrap()
                .worker_id,
            -1
        );
        // Once reconciliation binds the workers, their synthetic rows disappear.
        workers.worker_info[0].filter = child;
        workers.worker_info[1].filter = unassigned;
        model.process_refresh_data(Some(node), None, Some(workers));
        assert_eq!(model.allocations.len(), 3);
        assert!(model.allocations.iter().all(|a| a.status_name != "bound"));
    }

    #[test]
    fn row_estimates_survive_without_total_eligibility() {
        use quil_types::proto::node::WorkerInfo;

        let filter = vec![0xab];
        let workers = WorkerInfoResponse {
            worker_info: vec![WorkerInfo {
                core_id: 4,
                filter: filter.clone(),
                ..Default::default()
            }],
        };

        let mut active = Model::new();
        active.process_refresh_data(
            Some(node_info(allocation(filter.clone(), 3))),
            Some(shard_info(filter.clone(), 42)),
            Some(workers),
        );
        assert_eq!(active.allocations[0].estimated_reward, BigInt::from(42));

        let mut expired_epoch = Model::new();
        expired_epoch.process_refresh_data(
            Some(node_info(allocation(filter.clone(), 2))),
            Some(shard_info(filter.clone(), 42)),
            None,
        );
        assert_eq!(expired_epoch.allocations[0].status_name, "re-confirm!");
        assert_eq!(expired_epoch.allocations[0].worker_id, -1);
        assert_eq!(
            expired_epoch.allocations[0].estimated_reward,
            BigInt::from(42)
        );

        let mut unassigned = Model::new();
        unassigned.process_refresh_data(
            Some(node_info(allocation(filter.clone(), 3))),
            Some(shard_info(filter, 42)),
            None,
        );
        assert_eq!(unassigned.allocations[0].status_name, "active");
        assert_eq!(unassigned.allocations[0].worker_id, -1);
        assert_eq!(unassigned.allocations[0].estimated_reward, BigInt::from(42));
        assert_eq!(unassigned.allocations[0].reward_status(2160, 720), None);
        assert_eq!(expired_epoch.allocations[0].reward_status(2160, 720), None);
        assert_eq!(
            active.allocations[0].reward_status(2160, 720),
            Some(EffectiveStatus::Active)
        );
    }

    #[test]
    fn joining_allocations_show_projected_rewards_before_worker_assignment() {
        use super::super::super::epoch::raw_status;
        use quil_types::proto::node::WorkerInfo;

        let filter = vec![0xab];
        for (status, confirm_frame, label) in [
            (raw_status::JOINING, 0, "joining"),
            (raw_status::ACTIVE, 2_160, "activating"),
        ] {
            for assigned in [false, true] {
                let mut alloc = allocation(filter.clone(), 3);
                alloc.status = status;
                alloc.join_confirm_frame_number = confirm_frame;
                let workers = assigned.then(|| WorkerInfoResponse {
                    worker_info: vec![WorkerInfo {
                        core_id: 0,
                        filter: filter.clone(),
                        ..Default::default()
                    }],
                });
                let mut model = Model::new();
                model.process_refresh_data(
                    Some(node_info(alloc)),
                    Some(shard_info(filter.clone(), 42)),
                    workers,
                );
                assert_eq!(model.allocations[0].status_name, label);
                assert_eq!(model.allocations[0].estimated_reward, BigInt::from(42));
                assert_eq!(
                    model.allocations[0].reward_status(2160, 720),
                    assigned.then_some(EffectiveStatus::Joining)
                );
                // Expired joins lose their forecast, but their bound worker stays visible.
                model.process_refresh_data(
                    Some(node_info({
                        let mut expired = allocation(filter.clone(), 1);
                        expired.status = raw_status::JOINING;
                        expired.join_frame_number = 720;
                        expired
                    })),
                    None,
                    None,
                );
                assert_eq!(model.allocations.len(), usize::from(assigned));
                if assigned {
                    let worker = &model.allocations[0];
                    assert_eq!(worker.status_name, "bound");
                    assert_eq!(worker.worker_id, 0);
                    assert_eq!(worker.estimated_reward, BigInt::from(0));
                    assert_eq!(worker.reward_status(2160, 720), None);
                }
            }
        }
    }

    #[test]
    fn assigned_allocations_keep_estimates_and_classify_live_rewards() {
        use super::super::super::epoch::raw_status;
        use quil_types::proto::node::WorkerInfo;

        let filter = vec![0xab];
        for (status, epoch, join_confirm_frame, label) in [
            (raw_status::ACTIVE, 2, 0, "re-confirm!"),
            (raw_status::PAUSED, 3, 0, "paused"),
            (raw_status::LEAVING, 3, 0, "leaving"),
        ] {
            let mut alloc = allocation(filter.clone(), epoch);
            alloc.status = status;
            alloc.join_confirm_frame_number = join_confirm_frame;
            let mut info = shard_info(filter.clone(), 42);
            info.shards[0].ring = 7;
            info.shards[0].active_provers = 9;
            info.shards[0].shard_size = vec![64];
            info.shards[0].data_shards = 3;
            info.shards[0].materialized_frame = 2_100;
            info.shards[0].latest_frame = 2_160;
            let mut model = Model::new();
            model.process_refresh_data(
                Some(node_info(alloc)),
                Some(info),
                Some(WorkerInfoResponse {
                    worker_info: vec![WorkerInfo {
                        core_id: 0,
                        filter: filter.clone(),
                        ..Default::default()
                    }],
                }),
            );
            let row = &model.allocations[0];
            assert_eq!(row.status_name, label);
            assert_eq!(row.worker_id, 0);
            assert_eq!(row.estimated_reward, BigInt::from(42), "{label}");
            assert_eq!(
                row.reward_status(2160, 720),
                match status {
                    raw_status::PAUSED => Some(EffectiveStatus::Paused),
                    raw_status::LEAVING => Some(EffectiveStatus::Leaving),
                    _ => None,
                },
                "{label}"
            );
            assert_eq!(row.ring, 7);
            assert_eq!(row.active_provers, 9);
            assert_eq!(row.shard_size, BigInt::from(64));
            assert_eq!(row.data_shards, 3);
            assert_eq!(row.materialized_frame, 2_100);
            assert_eq!(row.latest_frame, 2_160);
        }
    }

    #[test]
    fn refresh_keeps_estimates_but_updates_total_eligibility() {
        use quil_types::proto::node::WorkerInfo;

        let filter = vec![0xab];
        let workers = WorkerInfoResponse {
            worker_info: vec![WorkerInfo {
                core_id: 0,
                filter: filter.clone(),
                ..Default::default()
            }],
        };
        let mut model = Model::new();
        model.process_refresh_data(
            Some(node_info(allocation(filter.clone(), 3))),
            Some(shard_info(filter.clone(), 42)),
            Some(workers.clone()),
        );
        assert_eq!(model.allocations[0].estimated_reward, BigInt::from(42));

        // A successful empty worker response replaces cached assignments.
        model.process_refresh_data(
            Some(node_info(allocation(filter.clone(), 3))),
            None,
            Some(WorkerInfoResponse {
                worker_info: vec![],
            }),
        );
        assert_eq!(model.allocations[0].worker_id, -1);
        assert_eq!(model.allocations[0].estimated_reward, BigInt::from(42));
        assert_eq!(model.allocations[0].reward_status(2160, 720), None);

        model.process_refresh_data(
            Some(node_info(allocation(filter.clone(), 3))),
            None,
            Some(workers),
        );
        assert_eq!(model.allocations[0].estimated_reward, BigInt::from(42));

        // Cached row estimates must not contribute after expiry.
        model.process_refresh_data(Some(node_info(allocation(filter, 2))), None, None);
        assert_eq!(model.allocations[0].status_name, "re-confirm!");
        assert_eq!(model.allocations[0].estimated_reward, BigInt::from(42));
        assert_eq!(model.allocations[0].reward_status(2160, 720), None);
    }
}

#[cfg(test)]
mod execution_freshness_tests {
    use super::*;
    use quil_types::proto::node::WorkerExecution;
    use std::time::{Duration, Instant};

    #[test]
    fn all_poll_options_preserve_fresh_received_state_and_bound_cached_data() {
        let received = Instant::now();
        let fresh = WorkerExecution {
            state: "blocked".into(),
            observed_unix_ms: 99_000,
            ..Default::default()
        };
        let old = WorkerExecution {
            state: "running".into(),
            observed_unix_ms: 69_999,
            ..Default::default()
        };
        for seconds in [5, 15, 30, 60] {
            let mut m = Model::new();
            m.refresh_seconds = seconds;
            m.worker_snapshot_received = Some((received, 100_000));
            assert_eq!(
                m.execution_state_at(Some(&fresh), received + Duration::from_secs(seconds + 15)),
                "blocked"
            );
            assert_eq!(
                m.execution_state_at(
                    Some(&fresh),
                    received + Duration::from_secs(seconds * 2 + 30)
                ),
                "blocked"
            );
            assert_eq!(
                m.execution_state_at(
                    Some(&fresh),
                    received + Duration::from_secs(seconds * 2 + 31)
                ),
                "cached"
            );
            assert_eq!(m.execution_state_at(Some(&old), received), "stale");
            assert_eq!(
                m.execution_state_at(Some(&WorkerExecution::default()), received),
                "stale"
            );
            assert_eq!(
                m.execution_state_at(None, received + Duration::from_secs(500)),
                "unknown"
            );
        }
    }

    #[test]
    fn cache_reuse_does_not_renew_worker_receipt_clock() {
        let mut m = Model::new();
        m.process_refresh_data(
            Some(NodeInfoResponse::default()),
            None,
            Some(WorkerInfoResponse::default()),
        );
        let clock = m.worker_snapshot_received.unwrap();
        m.process_refresh_data(Some(NodeInfoResponse::default()), None, None);
        assert_eq!(m.worker_snapshot_received, Some(clock));
        m.process_refresh_data(None, None, None);
        assert_eq!(m.worker_snapshot_received, Some(clock));
    }
}

#[cfg(test)]
mod frame_interval_tests {
    use super::*;
    use quil_types::proto::node::{FrameCadence, FrameWindow, ShardRewardInfo};
    #[test]
    fn server_windows_ignore_peer_heads_and_client_start_time() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut m = Model::new();
        let mut shards = GetShardInfoResponse {
            shards: vec![ShardRewardInfo {
                filter: vec![1],
                latest_frame: 1000,
                frame_cadence: Some(FrameCadence {
                    last_observed_unix_seconds: now,
                    hour: Some(FrameWindow {
                        window_seconds: 3600,
                        observed_seconds: 600,
                        advanced_frames: 30,
                    }),
                    day: None,
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        m.observe_app_intervals(&shards, std::time::Instant::now());
        assert_eq!(m.app_interval(&[1]), Some(20.0));
        shards.shards[0].latest_frame = 2000;
        m.observe_app_intervals(&shards, std::time::Instant::now());
        assert_eq!(m.app_interval(&[1]), Some(20.0));
        shards.shards[0].frame_cadence = None;
        m.observe_app_intervals(&shards, std::time::Instant::now());
        assert_eq!(m.app_interval(&[1]), None);
    }
    #[test]
    fn a_received_head_alone_cannot_create_a_node_cadence_measurement() {
        let mut m = Model::new();
        let shards = GetShardInfoResponse {
            shards: vec![ShardRewardInfo {
                filter: vec![1],
                global_head: Some(quil_types::proto::node::GlobalAppFrameHead {
                    frame: 2456,
                    generation: 5,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        m.observe_app_intervals(&shards, std::time::Instant::now());
        assert_eq!(m.app_interval(&[1]), None);
    }
}
