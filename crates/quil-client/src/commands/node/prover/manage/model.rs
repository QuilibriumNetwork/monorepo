//! State model for the `prover manage` TUI. Port of the bubbletea
//! `manageModel` (`client/cmd/node/prover/manage_model.go`) — the state
//! struct, data-refresh processing, and the filter/sort derivations.

use std::collections::{HashMap, HashSet};

use num_bigint::{BigInt, Sign};

use quil_types::proto::node::{
    GetShardInfoResponse, NodeInfoResponse, ShardAllocationInfo, WorkerInfoResponse,
};

use super::super::epoch::{
    alloc_confirm_window, compute_effective_status, epoch_for_frame, epoch_len, AllocationTiming,
    ConfirmWindow, EffectiveStatus, WindowState,
};

// ── Column metadata (shared between rendering and filtering) ─────────────

pub const ALLOC_COL_NAMES: [&str; 15] = [
    "Select", "Filter", "Provers", "Ring", "Size [MB]", "Shards", "Mat", "Lag", "State",
    "Reward [Q/f]", "Worker", "Status", "Mode", "Next Action", "Default Action",
];
pub const AVAIL_COL_NAMES: [&str; 10] =
    ["Select", "Filter", "Provers", "Ring", "Size [MB]", "Shards", "Mat", "Lag", "State", "Reward [Q/f]"];

pub const ALLOC_FILTERABLE_COLS: [usize; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
pub const AVAIL_FILTERABLE_COLS: [usize; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];

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
        8 | 11 | 12 => FilterColKind::Select,
        _ => FilterColKind::Numeric,
    }
}

/// Filter kind per absolute column index (available panel).
pub fn avail_filter_col_kind(col: usize) -> FilterColKind {
    match col {
        1 | 8 => FilterColKind::Text,
        _ => FilterColKind::Numeric,
    }
}

/// How the two tables size their columns. Toggled at runtime with `w`.
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
/// Available panel: cells carry a ` Q/f` suffix, so they need the extra room.
pub const MAT_WIDTH: usize = 9;
pub const LAG_WIDTH: usize = 6;
pub const STATE_WIDTH: usize = 8;
pub const REWARD_WIDTH: usize = 20;
/// Allocations panel: bare `~<value>` cells.
pub const ALLOC_REWARD_WIDTH: usize = 14;
pub const WORKER_WIDTH: usize = 7;
pub const STATUS_WIDTH: usize = 12;
pub const MODE_WIDTH: usize = 4;
pub const NEXT_ACTION_WIDTH: usize = 30;
pub const DEFAULT_ACTION_WIDTH: usize = 16;

// 11 spaces between 12 columns, 2 external borders, 2-char sort indicator.
pub const ALLOC_FIXED_WIDTH: usize = SELECT_WIDTH
    + PROVERS_WIDTH
    + RING_WIDTH
    + SIZE_WIDTH
    + SHARDS_WIDTH
    + MAT_WIDTH + LAG_WIDTH + STATE_WIDTH + ALLOC_REWARD_WIDTH
    + WORKER_WIDTH
    + STATUS_WIDTH
    + MODE_WIDTH
    + NEXT_ACTION_WIDTH
    + DEFAULT_ACTION_WIDTH
    + 14
    + 2
    + 2;
// 6 spaces between 7 columns, 2 external borders, 2-char sort indicator.
pub const AVAIL_FIXED_WIDTH: usize =
    SELECT_WIDTH + PROVERS_WIDTH + RING_WIDTH + SIZE_WIDTH + SHARDS_WIDTH + MAT_WIDTH + LAG_WIDTH + STATE_WIDTH + REWARD_WIDTH + 9 + 2 + 2;

/// Floor for the Filter column in either layout. Filter is what gives way
/// when the pane cannot hold the table, being the only column whose content
/// is already truncated for display.
pub const MIN_FILTER_WIDTH: usize = 12;

pub const ACTION_FRAME_DELAY: u64 = 360;

// ── Rows ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AllocationRow {
    pub filter: Vec<u8>,
    pub filter_key: String,
    pub filter_hex: String,
    pub status: u32,
    pub status_name: String,
    pub ring: u32,
    pub active_provers: u32,
    pub shard_size: BigInt,
    pub data_shards: u64,
    pub materialized_frame: u64,
    pub latest_frame: u64,
    pub estimated_reward: BigInt,
    pub join_frame: u64,
    pub leave_frame: u64,
    pub worker_id: i64, // core_id, -1 if no worker assigned
    pub next_action: String,
    pub default_action: String,
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
    pub filter: Vec<u8>,
    pub filter_key: String,
    pub filter_hex: String,
    pub active_provers: u32,
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
    pub text: String,               // substring match (Filter column)
    pub values: HashSet<String>,    // selected values (empty = all = no filter)
    pub expr: String,               // numeric expression like "> 47" or "1,5,7"
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
    pub filter: Vec<u8>,
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

// ── Model ────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct Model {
    // Header data.
    pub peer_id: String,
    pub seniority: String,
    pub running_workers: u32,
    pub allocated_workers: u32,
    pub last_global_head: u64,
    pub reachable: bool,
    pub frame_number: u64,
    pub epoch_length: u64,
    pub current_epoch: u64,
    pub last_received_frame: u64,
    pub difficulty: u64,
    pub auto_managed: bool,

    // Panel data.
    pub allocations: Vec<AllocationRow>,
    pub available: Vec<ShardRow>,
    pub alloc_cursor: usize,
    pub avail_cursor: usize,
    pub focus: PanelFocus,
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
    pub status_msg: String,
    pub status_is_error: bool,
    pub status_sticky: bool,
    pub action_in_flight: bool,
    pub show_help: bool,
    pub color_coding: bool,
    pub column_sizing: ColumnSizing,
    pub spinner_frame: usize,

    // Load / staleness tracking.
    pub data_loaded: bool,
    pub last_fetch_success: Option<std::time::Instant>,
    pub consecutive_failures: u32,

    // Aux-response cache (stabilizes panels across transient RPC blips).
    pub cached_shard_info: Option<GetShardInfoResponse>,
    pub cached_worker_info: Option<WorkerInfoResponse>,

    // Broadcast accumulator for the await loop.
    pub broadcasted_filters: Vec<Vec<u8>>,
    pub broadcasted_statuses: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PanelFocus {
    #[default]
    Allocations,
    Available,
}

impl PanelFocus {
    pub fn is_alloc(self) -> bool {
        matches!(self, PanelFocus::Allocations)
    }
}

impl Model {
    pub fn new() -> Self {
        Model {
            auto_managed: true,
            color_coding: true,
            alloc_sort_col: 10, // Worker column
            alloc_sort_asc: true,
            avail_sort_col: 9, // Reward column
            avail_sort_asc: false,
            reachable: false,
            ..Default::default()
        }
    }

    /// `epochFrame` — frame the client uses for epoch-aligned lifecycle math.
    pub fn epoch_frame(&self) -> u64 {
        if self.last_received_frame > 0 {
            self.last_received_frame
        } else {
            self.frame_number
        }
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
                self.cached_worker_info = Some(w.clone());
                Some(w)
            }
            None => self.cached_worker_info.clone(),
        };

        // Header.
        self.peer_id = node_info.peer_id.clone();
        if !node_info.peer_seniority.is_empty() {
            self.seniority =
                BigInt::from_bytes_be(Sign::Plus, &node_info.peer_seniority).to_string();
        }
        self.running_workers = node_info.running_workers;
        self.allocated_workers = node_info.allocated_workers;
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
        let mut any_manual = false;
        if let Some(wi) = &worker_info {
            for w in &wi.worker_info {
                workers.insert(hex::encode(&w.filter), (w.core_id, w.manually_managed));
                if w.manually_managed {
                    any_manual = true;
                }
            }
        }
        self.auto_managed = !any_manual;

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
            let status_name = eff.label().to_string();

            let (next_action, default_action) =
                action_hints(a, &t, eff, el, ef, next_boundary);

            let (wid, mm) = workers
                .get(&filter_hex)
                .map(|(id, m)| (*id as i64, *m))
                .unwrap_or((-1, false));

            let mut row = AllocationRow {
                filter: a.filter.clone(),
                filter_key: filter_hex.clone(),
                filter_hex: filter_hex.clone(),
                status: a.status,
                status_name,
                ring: 0,
                active_provers: 0,
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
                row.ring = info.ring;
                row.active_provers = info.active_provers;
                row.shard_size = BigInt::from_bytes_be(Sign::Plus, &info.shard_size);
                row.data_shards = info.data_shards;
                row.materialized_frame = info.materialized_frame;
                row.latest_frame = info.latest_frame;
                row.estimated_reward = BigInt::from_bytes_be(Sign::Plus, &info.estimated_reward);
            }
            allocs.push(row);
        }

        // Idle workers (empty filter) as Idle rows.
        if let Some(wi) = &worker_info {
            for w in &wi.worker_info {
                if w.filter.is_empty() {
                    allocs.push(AllocationRow {
                        filter: Vec::new(),
                        filter_key: format!("worker:{}", w.core_id),
                        filter_hex: String::new(),
                        status: 0,
                        status_name: "idle".to_string(),
                        ring: 0,
                        active_provers: 0,
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
                        next_action: String::new(),
                        default_action: String::new(),
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
                    filter: s.filter.clone(),
                    filter_key: filter_hex.clone(),
                    filter_hex,
                    active_provers: s.active_provers,
                    ring: s.ring,
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
                        alloc_row_numeric_val(row, col),
                        &cf.expr,
                    ) {
                        return false;
                    }
                }
                FilterColKind::Select => {
                    if !cf.values.is_empty()
                        && !cf.values.contains(&alloc_row_text_val(row, col))
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
                        avail_row_numeric_val(row, col),
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
        rows.sort_by(|a, b| {
            let ord = match col {
                0 => sel.contains(&a.filter_key).cmp(&sel.contains(&b.filter_key)),
                1 => a.filter_hex.cmp(&b.filter_hex),
                2 => a.active_provers.cmp(&b.active_provers),
                3 => a.ring.cmp(&b.ring),
                4 => a.shard_size.cmp(&b.shard_size),
                5 => a.data_shards.cmp(&b.data_shards),
                6 => a.materialized_frame.cmp(&b.materialized_frame),
                7 => materialization_lag(a.materialized_frame, a.latest_frame).cmp(&materialization_lag(b.materialized_frame, b.latest_frame)),
                8 => materialization_state(a.materialized_frame, a.latest_frame).cmp(materialization_state(b.materialized_frame, b.latest_frame)),
                9 => a.estimated_reward.cmp(&b.estimated_reward),
                10 => a.worker_id.cmp(&b.worker_id), 11 => a.status.cmp(&b.status),
                12 => a.manually_managed.cmp(&b.manually_managed), 13 => a.next_action.cmp(&b.next_action),
                14 => a.default_action.cmp(&b.default_action),
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
                0 => sel.contains(&a.filter_key).cmp(&sel.contains(&b.filter_key)),
                1 => a.filter_hex.cmp(&b.filter_hex),
                2 => a.active_provers.cmp(&b.active_provers),
                3 => a.ring.cmp(&b.ring),
                4 => a.shard_size.cmp(&b.shard_size),
                5 => a.data_shards.cmp(&b.data_shards),
                6 => a.materialized_frame.cmp(&b.materialized_frame),
                7 => materialization_lag(a.materialized_frame, a.latest_frame).cmp(&materialization_lag(b.materialized_frame, b.latest_frame)),
                8 => materialization_state(a.materialized_frame, a.latest_frame).cmp(materialization_state(b.materialized_frame, b.latest_frame)),
                9 => a.estimated_reward.cmp(&b.estimated_reward),
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
            if !self.free_workers.is_empty() {
                return "Join".to_string();
            }
            return "none (no free workers)".to_string();
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

    pub fn active_panel_filter_cols(&self) -> &'static [usize] {
        if self.focus.is_alloc() {
            &ALLOC_FILTERABLE_COLS
        } else {
            &AVAIL_FILTERABLE_COLS
        }
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
                let v = alloc_row_text_val(row, col);
                if !v.is_empty() {
                    seen.insert(v);
                }
            }
        }
        let mut vals: Vec<String> = seen.into_iter().collect();
        vals.sort();
        vals
    }

    pub fn active_panel_col_count(&self) -> usize {
        if self.focus.is_alloc() {
            14
        } else {
            10
        }
    }
}

// ── Row value accessors (for filtering + sorting) ────────────────────────

pub fn alloc_row_numeric_val(row: &AllocationRow, col: usize) -> f64 {
    match col {
        2 => row.active_provers as f64,
        3 => row.ring as f64,
        4 => bigint_to_f64(&row.shard_size) / (1024.0 * 1024.0),
        5 => row.data_shards as f64,
        6 => row.materialized_frame as f64,
        7 => materialization_lag(row.materialized_frame, row.latest_frame).unwrap_or(0) as f64,
        9 => {
            if row.estimated_reward.sign() == Sign::NoSign {
                0.0
            } else {
                bigint_to_f64(&row.estimated_reward) / 1e8
            }
        }
        10 => row.worker_id as f64,
        _ => 0.0,
    }
}

pub fn alloc_row_text_val(row: &AllocationRow, col: usize) -> String {
    match col {
        1 => row.filter_hex.clone(),
        8 => materialization_state(row.materialized_frame, row.latest_frame).to_string(),
        11 => row.status_name.clone(),
        12 => row.mode().to_string(),
        _ => String::new(),
    }
}

pub fn avail_row_numeric_val(row: &ShardRow, col: usize) -> f64 {
    match col {
        2 => row.active_provers as f64,
        3 => row.ring as f64,
        4 => bigint_to_f64(&row.shard_size) / (1024.0 * 1024.0),
        5 => row.data_shards as f64,
        6 => row.materialized_frame as f64,
        7 => materialization_lag(row.materialized_frame, row.latest_frame).unwrap_or(0) as f64,
        9 => {
            if row.estimated_reward.sign() == Sign::NoSign {
                0.0
            } else {
                bigint_to_f64(&row.estimated_reward) / 1e8
            }
        }
        _ => 0.0,
    }
}

pub fn materialization_lag(materialized: u64, latest: u64) -> Option<u64> {
    (latest > 0).then(|| latest.saturating_sub(materialized))
}

pub fn materialization_state(materialized: u64, latest: u64) -> &'static str {
    match (materialized, latest) {
        (0, 0) => "Unknown", (0, _) => "Unmat", (mat, head) if mat >= head => "Current", _ => "Lag",
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

pub fn bigint_to_f64(v: &BigInt) -> f64 {
    v.to_string().parse::<f64>().unwrap_or(0.0)
}

/// BigInt (assumed < 2^64) → u64, for the display formatters.
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

/// The `nextAction` / `defaultAction` hint pair for an allocation row
/// (mirrors the switch in `processRefreshData`).
fn action_hints(
    a: &ShardAllocationInfo,
    t: &AllocationTiming,
    eff: EffectiveStatus,
    el: u64,
    ef: u64,
    next_boundary: u64,
) -> (String, String) {
    if let Some(w) = alloc_confirm_window(t, el) {
        return match w.state(ef, el) {
            WindowState::Open => (
                "reject | confirm now".to_string(),
                format!("thru f{}", w.end_frame),
            ),
            WindowState::Pending => (
                format!("reject | confirm@f{}", w.start_frame),
                format!("epoch {}", w.confirm_epoch),
            ),
            WindowState::Missed => ("window missed".to_string(), "expired".to_string()),
        };
    }
    match eff {
        EffectiveStatus::Active => {
            let default = if !a.filter.is_empty() {
                format!("renew<f{}", next_boundary)
            } else {
                String::new()
            };
            ("pause | leave".to_string(), default)
        }
        EffectiveStatus::Paused => ("resume | leave".to_string(), String::new()),
        EffectiveStatus::Joining => {
            if a.join_confirm_frame_number > 0 {
                let act_e = epoch_for_frame(a.join_confirm_frame_number, el) + 1;
                ("confirmed".to_string(), format!("active@e{}", act_e))
            } else {
                (String::new(), String::new())
            }
        }
        EffectiveStatus::Leaving => {
            if a.leave_confirm_frame_number > 0 {
                let deact_e = epoch_for_frame(a.leave_confirm_frame_number, el) + 1;
                ("leaving".to_string(), format!("departs@e{}", deact_e))
            } else {
                (String::new(), String::new())
            }
        }
        EffectiveStatus::ExpiredEpoch => {
            ("confirm now (renew)".to_string(), "re-confirm!".to_string())
        }
        _ => (String::new(), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_sort_allocations_by_worker_and_available_by_reward() {
        let m = Model::new();
        assert_eq!(ALLOC_COL_NAMES[m.alloc_sort_col as usize], "Worker");
        assert!(m.alloc_sort_asc);
        assert_eq!(AVAIL_COL_NAMES[m.avail_sort_col as usize], "Reward [Q/f]");
        assert!(!m.avail_sort_asc);
    }
}
