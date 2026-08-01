//! Event/message handling for the `prover manage` TUI. Port of the
//! bubbletea `Update` + `handleKey` (and all sub-mode handlers).

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::model::{
    AwaitFilterEntry, ColumnFilter, FilterColKind, Model, PanelFocus, PendingAction,
    ACTION_FRAME_DELAY,
};
use super::msg::Msg;
use super::super::epoch::epoch_len;

const MAX_AWAIT_RETRIES: u32 = 3;

/// A side-effect the event loop performs after an update (the `tea.Cmd`
/// equivalent). The loop spawns the matching async task or timer.
pub enum Cmd {
    Fetch,
    Join(Vec<Vec<u8>>),
    Lifecycle {
        action: String,
        filters: Vec<Vec<u8>>,
        original_status: u32,
    },
    ToggleManual {
        core_id: u32,
        manual: bool,
    },
    MarkManual(Vec<u32>),
    CheckAllocation {
        action: String,
        entries: Vec<AwaitFilterEntry>,
    },
    ScheduleAwaitCheck(Duration),
    Quit,
}

// ── Message application ──────────────────────────────────────────────────

pub fn apply_msg(m: &mut Model, msg: Msg) -> Vec<Cmd> {
    match msg {
        Msg::DataRefresh {
            node_info,
            shard_info,
            worker_info,
            err,
        } => {
            if let Some(e) = err {
                m.consecutive_failures += 1;
                m.status_msg = format!("Refresh failed: {e}");
                m.status_is_error = true;
                m.status_sticky = true;
                return vec![];
            }
            m.last_fetch_success = Some(Instant::now());
            m.consecutive_failures = 0;
            m.data_loaded = true;
            m.process_refresh_data(node_info, shard_info, worker_info);
            if !m.action_in_flight && !m.status_sticky {
                m.status_msg.clear();
                m.status_is_error = false;
            }
            vec![]
        }

        Msg::ActionResult {
            action,
            filter,
            filters_raw,
            err,
        } => {
            if let Some(e) = err {
                return handle_action_failure(m, &format!("{action} failed"), &e, Some(Cmd::Fetch));
            }
            if !filters_raw.is_empty() {
                begin_await(m, &action, &filters_raw, 0);
                m.status_msg = format!("{action} sent for {filter}. Awaiting registry...");
                m.status_is_error = false;
                return vec![Cmd::ScheduleAwaitCheck(Duration::from_secs(3))];
            }
            m.status_msg = format!("{action} sent for {filter}");
            m.status_is_error = false;
            m.status_sticky = true;
            if let Some(cmd) = advance_queue(m) {
                return vec![cmd];
            }
            m.action_in_flight = false;
            vec![Cmd::Fetch]
        }

        Msg::ActionBroadcast {
            action,
            filters_raw,
            send_frame,
            original_status,
            err,
            ..
        } => {
            if let Some(e) = err {
                return handle_action_failure(
                    m,
                    &format!("{action} broadcast failed"),
                    &e,
                    Some(Cmd::Fetch),
                );
            }
            for f in &filters_raw {
                m.broadcasted_filters.push(f.clone());
                m.broadcasted_statuses.push(original_status);
            }
            if send_frame > m.await_send_frame {
                m.await_send_frame = send_frame;
            }
            if !m.action_queue.is_empty() {
                m.status_msg = format!("{action} broadcast ({}/{})", m.action_index, m.action_total);
                if let Some(cmd) = advance_queue(m) {
                    return vec![cmd];
                }
                return vec![];
            }
            // Final broadcast — convert accumulated filters into await entries.
            let entries: Vec<AwaitFilterEntry> = m
                .broadcasted_filters
                .iter()
                .zip(m.broadcasted_statuses.iter())
                .map(|(f, s)| AwaitFilterEntry {
                    filter: f.clone(),
                    original_status: *s,
                    settled: false,
                    outcome: String::new(),
                })
                .collect();
            begin_await(m, &action, &[], 0);
            m.await_filters = entries;
            let n = m.await_filters.len();
            if m.action_total > 1 {
                m.status_msg = format!(
                    "{} {}(s) broadcast (frame {}). Awaiting inclusion for {} filter(s)...",
                    m.action_total, action, m.await_send_frame, n
                );
            } else {
                m.status_msg = format!(
                    "{} broadcast (frame {}). Awaiting inclusion for {} filter(s)...",
                    action, m.await_send_frame, n
                );
            }
            vec![Cmd::ScheduleAwaitCheck(Duration::from_secs(3))]
        }

        Msg::AwaitCheck => {
            if !m.action_in_flight || m.await_action.is_empty() {
                return vec![];
            }
            vec![Cmd::CheckAllocation {
                action: m.await_action.clone(),
                entries: m.await_filters.clone(),
            }]
        }

        Msg::AwaitResult {
            action,
            frame,
            err,
            per_filter,
        } => {
            if !m.action_in_flight || m.await_action.is_empty() {
                return vec![];
            }
            let elapsed = m.await_start.map(|s| s.elapsed().as_secs()).unwrap_or(0);
            let past_deadline = elapsed > m.await_deadline_secs;

            if let Some(e) = err {
                m.await_retries += 1;
                if m.await_retries < MAX_AWAIT_RETRIES && !past_deadline {
                    m.status_msg = format!(
                        "{action} check transient error ({}/{}): {e}",
                        m.await_retries, MAX_AWAIT_RETRIES
                    );
                    m.status_is_error = false;
                    let backoff = Duration::from_secs(3 * m.await_retries as u64);
                    return vec![Cmd::ScheduleAwaitCheck(backoff)];
                }
                finish_await(m);
                m.status_msg =
                    format!("{action} check failed after {} retries: {e}", m.await_retries);
                m.status_is_error = true;
                m.status_sticky = true;
                return vec![Cmd::Fetch];
            }

            m.await_retries = 0;
            for o in &per_filter {
                for e in m.await_filters.iter_mut() {
                    if e.filter == o.filter && !e.settled {
                        e.settled = o.settled;
                        e.outcome = o.outcome.clone();
                    }
                }
            }
            let all_settled = m.await_filters.iter().all(|e| e.settled);
            if all_settled || past_deadline {
                return finish_confirmed(m, frame);
            }
            let settled_total = m.await_filters.iter().filter(|e| e.settled).count();
            m.status_msg = format!(
                "{} awaiting {}/{} filter(s)... ({}s elapsed, frame {})",
                m.await_action,
                m.await_filters.len() - settled_total,
                m.await_filters.len(),
                elapsed,
                m.await_send_frame,
            );
            m.status_is_error = false;
            vec![Cmd::ScheduleAwaitCheck(Duration::from_secs(3))]
        }

        Msg::ToggleManual {
            core_id,
            new_state,
            err,
        } => {
            if let Some(e) = err {
                m.status_msg = format!("Worker {core_id} toggle failed: {e}");
                m.status_is_error = true;
                m.status_sticky = true;
            } else {
                let state = if new_state { "Manual" } else { "Auto" };
                m.status_msg = format!("Worker {core_id} set to {state} mode");
                m.status_is_error = false;
            }
            vec![Cmd::Fetch]
        }

        Msg::MarkManual {
            worker_ids,
            failed_ids,
            err,
        } => {
            if !failed_ids.is_empty() {
                m.status_msg = format!(
                    "manual-tag: {}/{} worker(s) failed to mark manual (e.g. {}): {}",
                    failed_ids.len(),
                    worker_ids.len(),
                    failed_ids[0],
                    err.unwrap_or_default()
                );
                m.status_is_error = true;
                m.status_sticky = true;
                return vec![Cmd::Fetch];
            }
            vec![]
        }
    }
}

// ── Await lifecycle ──────────────────────────────────────────────────────

fn begin_await(m: &mut Model, action: &str, filters_raw: &[Vec<u8>], original_status: u32) {
    m.await_action = action.to_string();
    m.await_start = Some(Instant::now());
    // Deadline = one epoch of wall time (10s/frame) + slack.
    const FRAME_WALL_SECONDS: u64 = 10;
    const SLACK_SECONDS: u64 = 30;
    m.await_deadline_secs = epoch_len(m.epoch_length) * FRAME_WALL_SECONDS + SLACK_SECONDS;
    m.await_retries = 0;
    if !filters_raw.is_empty() {
        m.await_filters = filters_raw
            .iter()
            .map(|f| AwaitFilterEntry {
                filter: f.clone(),
                original_status,
                settled: false,
                outcome: String::new(),
            })
            .collect();
    }
}

fn finish_await(m: &mut Model) {
    m.action_in_flight = false;
    m.await_action.clear();
    m.await_filters.clear();
    m.await_send_frame = 0;
    m.await_deadline_secs = 0;
    m.await_start = None;
    m.await_retries = 0;
    m.action_queue.clear();
    m.action_total = 0;
    m.action_index = 0;
    m.broadcasted_filters.clear();
    m.broadcasted_statuses.clear();
}

/// `buildConfirmed` + the `actionConfirmedMsg` handler, collapsed: build
/// the per-filter summary, finish the await, and refresh.
fn finish_confirmed(m: &mut Model, frame: u64) -> Vec<Cmd> {
    let confirmed = m.await_filters.iter().filter(|e| e.settled).count();
    let unchanged = m.await_filters.len() - confirmed;
    let first_unchanged = m
        .await_filters
        .iter()
        .find(|e| !e.settled)
        .map(|e| super::util::trunc_hex(&hex::encode(&e.filter)))
        .unwrap_or_else(|| "n/a".to_string());
    let total = m.await_filters.len();
    let action = m.await_action.clone();
    let send_frame = m.await_send_frame;

    if unchanged == 0 {
        m.status_msg = format!("{action} confirmed at frame {frame} ({confirmed} filter(s))");
        m.status_is_error = false;
    } else if confirmed == 0 {
        m.status_msg = format!(
            "{action} broadcast at frame {send_frame} but {unchanged}/{total} filter(s) did not change (e.g. {first_unchanged})"
        );
        m.status_is_error = true;
    } else {
        m.status_msg = format!(
            "{action} partial: {confirmed}/{total} confirmed, {unchanged} unchanged (e.g. {first_unchanged})"
        );
        m.status_is_error = confirmed == 0;
    }
    m.status_sticky = true;
    finish_await(m);
    vec![Cmd::Fetch]
}

fn handle_action_failure(
    m: &mut Model,
    prefix: &str,
    err: &str,
    fallback: Option<Cmd>,
) -> Vec<Cmd> {
    m.status_msg = format!("{prefix}: {err}");
    m.status_is_error = true;
    m.status_sticky = true;
    if let Some(cmd) = advance_queue(m) {
        return vec![cmd];
    }
    m.action_in_flight = false;
    fallback.into_iter().collect()
}

/// `advanceQueue` — start the next queued (single-filter) action.
fn advance_queue(m: &mut Model) -> Option<Cmd> {
    if m.action_queue.is_empty() {
        return None;
    }
    let next = m.action_queue.remove(0);
    m.action_index += 1;
    m.action_in_flight = true;
    m.status_is_error = false;
    m.status_msg = format!(
        "Creating {} message ({}/{})...",
        next.action, m.action_index, m.action_total
    );
    Some(Cmd::Lifecycle {
        action: next.action,
        filters: vec![next.filter],
        original_status: next.status,
    })
}

// ── Key handling ─────────────────────────────────────────────────────────

/// Char produced by the key (already case-folded by the terminal).
fn ch(ev: &KeyEvent) -> Option<char> {
    match ev.code {
        KeyCode::Char(c) => Some(c),
        _ => None,
    }
}

fn is_quit(ev: &KeyEvent) -> bool {
    matches!(ev.code, KeyCode::Char('q'))
        || (ev.code == KeyCode::Char('c') && ev.modifiers.contains(KeyModifiers::CONTROL))
}

pub fn handle_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    if m.join_picker_active {
        return handle_join_picker_key(m, ev);
    }
    if m.filter_edit_active {
        return handle_filter_edit_key(m, ev);
    }
    if m.is_filter_mode_active() {
        return handle_filter_mode_key(m, ev);
    }
    if m.sort_mode && m.sort_order_mode {
        return handle_sort_order_key(m, ev);
    }
    if m.sort_mode {
        return handle_sort_mode_key(m, ev);
    }
    handle_normal_key(m, ev)
}

fn handle_normal_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    if is_quit(&ev) {
        return vec![Cmd::Quit];
    }
    let c = ch(&ev);
    match ev.code {
        KeyCode::Char('h') => {
            m.show_help = !m.show_help;
            return vec![];
        }
        KeyCode::Char('C') => {
            m.color_coding = !m.color_coding;
            return vec![];
        }
        KeyCode::Tab => {
            m.focus = if m.focus.is_alloc() {
                PanelFocus::Available
            } else {
                PanelFocus::Allocations
            };
            m.filter_edit_active = false;
            return vec![];
        }
        KeyCode::Char(' ') => {
            toggle_select(m);
            return vec![];
        }
        KeyCode::Char('a') => {
            select_all(m);
            return vec![];
        }
        KeyCode::Up | KeyCode::Char('k') => {
            cursor_up(m);
            return vec![];
        }
        KeyCode::Down | KeyCode::Char('j') => {
            cursor_down(m);
            return vec![];
        }
        KeyCode::Char('R') => return vec![Cmd::Fetch],
        _ => {}
    }
    match c {
        Some('J') => action_join(m),
        Some('l') => action_leave(m),
        Some('c') => action_confirm(m),
        Some('r') => action_reject(m),
        Some('p') => action_pause(m),
        Some('u') => action_resume(m),
        Some('M') => action_toggle_manual(m),
        Some('s') => {
            m.sort_mode = true;
            m.sort_order_mode = false;
            m.sort_highlight_col = 0;
            vec![]
        }
        Some('f') => {
            if m.focus.is_alloc() {
                m.alloc_filter_mode = true;
                m.alloc_filter_highlight_idx = 0;
            } else {
                m.avail_filter_mode = true;
                m.avail_filter_highlight_idx = 0;
            }
            m.filter_edit_active = false;
            vec![]
        }
        _ => vec![],
    }
}

fn toggle_select(m: &mut Model) {
    if m.focus.is_alloc() {
        let sorted = m.sorted_allocations();
        if let Some(row) = sorted.get(m.alloc_cursor) {
            let k = row.filter_key.clone();
            if !m.alloc_selected.remove(&k) {
                m.alloc_selected.insert(k);
            }
            if m.alloc_cursor < sorted.len().saturating_sub(1) {
                m.alloc_cursor += 1;
            }
        }
    } else {
        let sorted = m.sorted_available();
        if let Some(row) = sorted.get(m.avail_cursor) {
            let k = row.filter_key.clone();
            if !m.avail_selected.remove(&k) {
                m.avail_selected.insert(k);
            }
            if m.avail_cursor < sorted.len().saturating_sub(1) {
                m.avail_cursor += 1;
            }
        }
    }
}

fn select_all(m: &mut Model) {
    if m.focus.is_alloc() {
        let sorted = m.sorted_allocations();
        let all = m.alloc_selected.len() == sorted.len() && !sorted.is_empty();
        m.alloc_selected.clear();
        if !all {
            for row in &sorted {
                m.alloc_selected.insert(row.filter_key.clone());
            }
        }
    } else {
        let sorted = m.sorted_available();
        let all = m.avail_selected.len() == sorted.len() && !sorted.is_empty();
        m.avail_selected.clear();
        if !all {
            for row in &sorted {
                m.avail_selected.insert(row.filter_key.clone());
            }
        }
    }
}

fn cursor_up(m: &mut Model) {
    if m.focus.is_alloc() {
        m.alloc_cursor = m.alloc_cursor.saturating_sub(1);
    } else {
        m.avail_cursor = m.avail_cursor.saturating_sub(1);
    }
}

fn cursor_down(m: &mut Model) {
    if m.focus.is_alloc() {
        let n = m.sorted_allocations().len();
        if m.alloc_cursor + 1 < n {
            m.alloc_cursor += 1;
        }
    } else {
        let n = m.sorted_available().len();
        if m.avail_cursor + 1 < n {
            m.avail_cursor += 1;
        }
    }
}

// ── Action dispatch (normal mode) ────────────────────────────────────────

fn wrong_panel(m: &mut Model, verb: &str) -> Vec<Cmd> {
    m.status_msg = format!(
        "{verb} is only available in the {} panel (Tab to switch). Current panel supports: {}",
        if verb == "Join" {
            "Available Shards"
        } else {
            "Allocations"
        },
        m.applicable_actions_label()
    );
    m.status_is_error = true;
    vec![]
}

fn action_join(m: &mut Model) -> Vec<Cmd> {
    if m.action_in_flight {
        return vec![];
    }
    if m.focus != PanelFocus::Available {
        m.status_msg = "Join is only available in the Available Shards panel (Tab to switch)".into();
        m.status_is_error = true;
        return vec![];
    }
    if m.free_workers.is_empty() {
        m.status_msg = "Join requires at least one free worker".into();
        m.status_is_error = true;
        return vec![];
    }
    let rows = m.selected_avail_rows();
    if rows.is_empty() {
        return vec![];
    }
    m.join_picker_active = true;
    m.join_picker_cursor = 0;
    m.join_picker_offset = 0;
    m.join_picker_workers = m.free_workers.clone();
    m.join_picker_selected.clear();
    m.join_picker_filters = rows.iter().map(|r| r.filter.clone()).collect();
    vec![]
}

fn action_leave(m: &mut Model) -> Vec<Cmd> {
    if m.action_in_flight {
        return vec![];
    }
    if !m.focus.is_alloc() {
        return wrong_panel(m, "Leave");
    }
    let rows = m.selected_alloc_rows();
    start_multi_filter_action(m, "Leave", rows, |s| s == 2)
}

fn action_confirm(m: &mut Model) -> Vec<Cmd> {
    if m.action_in_flight {
        return vec![];
    }
    if !m.focus.is_alloc() {
        return wrong_panel(m, "Confirm");
    }
    // Pre-filter to rows whose confirm window is currently open.
    let mut confirm_rows = Vec::new();
    let mut earliest: u64 = 0;
    for row in m.selected_alloc_rows() {
        let mut action_frame = 0u64;
        match row.status {
            1 => {
                if row.join_frame > 0 {
                    action_frame = row.join_frame + ACTION_FRAME_DELAY;
                    if m.frame_number >= action_frame
                        && m.frame_number < row.join_frame + ACTION_FRAME_DELAY * 2
                    {
                        confirm_rows.push(row.clone());
                    }
                }
            }
            4 => {
                if row.leave_frame > 0 {
                    action_frame = row.leave_frame + ACTION_FRAME_DELAY;
                    if m.frame_number >= action_frame
                        && m.frame_number < row.leave_frame + ACTION_FRAME_DELAY * 2
                    {
                        confirm_rows.push(row.clone());
                    }
                }
            }
            _ => {}
        }
        if action_frame > m.frame_number && (earliest == 0 || action_frame < earliest) {
            earliest = action_frame;
        }
    }
    if confirm_rows.is_empty() && earliest > 0 {
        m.status_msg = format!(
            "Confirm not yet available (current frame: {}, opens at: {}). Applicable action(s): Reject",
            m.frame_number, earliest
        );
        m.status_is_error = true;
        return vec![];
    }
    start_multi_filter_action(m, "Confirm", confirm_rows, |s| s == 1 || s == 4)
}

fn action_reject(m: &mut Model) -> Vec<Cmd> {
    if m.action_in_flight {
        return vec![];
    }
    if !m.focus.is_alloc() {
        return wrong_panel(m, "Reject");
    }
    let rows = m.selected_alloc_rows();
    start_multi_filter_action(m, "Reject", rows, |s| s == 1 || s == 4)
}

fn action_pause(m: &mut Model) -> Vec<Cmd> {
    if m.action_in_flight {
        return vec![];
    }
    if !m.focus.is_alloc() {
        return wrong_panel(m, "Pause");
    }
    let rows = m.selected_alloc_rows();
    start_batch_action(m, "Pause", rows, |s| s == 2)
}

fn action_resume(m: &mut Model) -> Vec<Cmd> {
    if m.action_in_flight {
        return vec![];
    }
    if !m.focus.is_alloc() {
        return wrong_panel(m, "Resume");
    }
    let rows = m.selected_alloc_rows();
    start_batch_action(m, "Resume", rows, |s| s == 3)
}

fn action_toggle_manual(m: &mut Model) -> Vec<Cmd> {
    if m.action_in_flight {
        return vec![];
    }
    if !m.focus.is_alloc() {
        return wrong_panel(m, "Mode toggle");
    }
    let sorted = m.sorted_allocations();
    let Some(row) = sorted.get(m.alloc_cursor) else {
        return vec![];
    };
    if row.worker_id < 0 {
        m.status_msg = "No worker assigned to this allocation".into();
        m.status_is_error = true;
        return vec![];
    }
    let new_state = !row.manually_managed;
    let core_id = row.worker_id as u32;
    vec![Cmd::ToggleManual {
        core_id,
        manual: new_state,
    }]
}

fn start_multi_filter_action(
    m: &mut Model,
    action: &str,
    rows: Vec<super::model::AllocationRow>,
    valid: impl Fn(u32) -> bool,
) -> Vec<Cmd> {
    let mut filters = Vec::new();
    let mut status = 0u32;
    let mut worker_ids = Vec::new();
    for row in &rows {
        if valid(row.status) {
            filters.push(row.filter.clone());
            status = row.status;
            if row.worker_id >= 0 {
                worker_ids.push(row.worker_id as u32);
            }
        }
    }
    if filters.is_empty() {
        m.status_msg = format!(
            "No selected allocations are valid for {action}. Applicable action(s): {}",
            m.applicable_actions_label()
        );
        m.status_is_error = true;
        return vec![];
    }
    m.action_in_flight = true;
    m.status_is_error = false;
    m.alloc_selected.clear();
    m.status_msg = format!("Creating {action} message for {} allocation(s)...", filters.len());
    let mut cmds = vec![Cmd::Lifecycle {
        action: action.to_string(),
        filters,
        original_status: status,
    }];
    if !worker_ids.is_empty() {
        cmds.push(Cmd::MarkManual(worker_ids));
    }
    cmds
}

fn start_batch_action(
    m: &mut Model,
    action: &str,
    rows: Vec<super::model::AllocationRow>,
    valid: impl Fn(u32) -> bool,
) -> Vec<Cmd> {
    let mut queue: Vec<PendingAction> = Vec::new();
    for row in &rows {
        if valid(row.status) {
            queue.push(PendingAction {
                action: action.to_string(),
                filter: row.filter.clone(),
                status: row.status,
            });
        }
    }
    if queue.is_empty() {
        m.status_msg = format!(
            "No selected allocations are valid for {action}. Applicable action(s): {}",
            m.applicable_actions_label()
        );
        m.status_is_error = true;
        return vec![];
    }
    let first = queue.remove(0);
    m.action_queue = queue;
    m.action_total = m.action_queue.len() + 1;
    m.action_index = 1;
    m.action_in_flight = true;
    m.status_is_error = false;
    m.alloc_selected.clear();
    m.status_msg = format!("Creating {action} message (1/{})...", m.action_total);
    vec![Cmd::Lifecycle {
        action: action.to_string(),
        filters: vec![first.filter],
        original_status: first.status,
    }]
}

// ── Sort mode ────────────────────────────────────────────────────────────

fn handle_sort_mode_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    let num_cols = m.active_panel_col_count();
    match ev.code {
        KeyCode::Right => {
            m.sort_highlight_col = (m.sort_highlight_col + 1) % num_cols;
        }
        KeyCode::Left => {
            m.sort_highlight_col = (m.sort_highlight_col + num_cols - 1) % num_cols;
        }
        KeyCode::Enter => {
            m.sort_order_mode = true;
        }
        KeyCode::Esc => {
            m.sort_mode = false;
            m.sort_order_mode = false;
            m.sort_highlight_col = 0;
        }
        _ if is_quit(&ev) => {
            m.sort_mode = false;
            m.sort_order_mode = false;
            m.sort_highlight_col = 0;
        }
        _ => {}
    }
    vec![]
}

fn handle_sort_order_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    match ev.code {
        KeyCode::Enter | KeyCode::Char('a') | KeyCode::Char('A') => {
            apply_sort(m, true);
            m.sort_mode = false;
            m.sort_order_mode = false;
        }
        KeyCode::Char('d') | KeyCode::Char('D') => {
            apply_sort(m, false);
            m.sort_mode = false;
            m.sort_order_mode = false;
        }
        KeyCode::Esc => {
            m.sort_mode = false;
            m.sort_order_mode = false;
            m.sort_highlight_col = 0;
        }
        _ if is_quit(&ev) => {
            m.sort_mode = false;
            m.sort_order_mode = false;
            m.sort_highlight_col = 0;
        }
        _ => {}
    }
    vec![]
}

fn apply_sort(m: &mut Model, asc: bool) {
    if m.focus.is_alloc() {
        m.alloc_sort_col = m.sort_highlight_col as i32;
        m.alloc_sort_asc = asc;
    } else {
        m.avail_sort_col = m.sort_highlight_col as i32;
        m.avail_sort_asc = asc;
    }
}

// ── Filter mode ──────────────────────────────────────────────────────────

fn handle_filter_mode_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    let cols = m.active_panel_filter_cols();
    let num_cols = cols.len();
    let hi = m.filter_highlight_idx();

    let set_hi = |m: &mut Model, idx: usize| {
        if m.focus.is_alloc() {
            m.alloc_filter_highlight_idx = idx;
        } else {
            m.avail_filter_highlight_idx = idx;
        }
    };
    let close = |m: &mut Model| {
        if m.focus.is_alloc() {
            m.alloc_filter_mode = false;
        } else {
            m.avail_filter_mode = false;
        }
    };

    match ev.code {
        KeyCode::Right => set_hi(m, (hi + 1) % num_cols),
        KeyCode::Left => set_hi(m, (hi + num_cols - 1) % num_cols),
        KeyCode::Enter => {
            if hi < num_cols {
                let col = cols[hi];
                let kind = m.active_filter_col_kind(col);
                m.filter_edit_col_idx = col;
                m.filter_edit_active = true;
                match kind {
                    FilterColKind::Text => m.filter_edit_input = m.active_filter_col(col).text,
                    FilterColKind::Numeric => m.filter_edit_input = m.active_filter_col(col).expr,
                    FilterColKind::Select => {
                        m.filter_edit_select_items = m.filter_select_values(col);
                        let existing = m.active_filter_col(col);
                        m.filter_edit_select_state.clear();
                        if !existing.values.is_empty() {
                            for v in &existing.values {
                                m.filter_edit_select_state.insert(v.clone(), true);
                            }
                        } else {
                            for v in &m.filter_edit_select_items {
                                m.filter_edit_select_state.insert(v.clone(), true);
                            }
                        }
                        m.filter_edit_select_cursor = 0;
                    }
                }
            }
        }
        KeyCode::Delete | KeyCode::Backspace => {
            if hi < num_cols {
                let col = cols[hi];
                m.set_active_filter_col(col, ColumnFilter::default());
                m.clamp_cursors();
            }
        }
        KeyCode::Char('x') => {
            close(m);
            m.filter_edit_active = false;
            if m.focus.is_alloc() {
                m.alloc_col_filters.clear();
            } else {
                m.avail_col_filters.clear();
            }
            m.clamp_cursors();
        }
        KeyCode::Esc => {
            close(m);
            m.filter_edit_active = false;
        }
        _ if is_quit(&ev) => return vec![Cmd::Quit],
        _ => {}
    }
    vec![]
}

fn handle_filter_edit_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    let kind = m.active_filter_col_kind(m.filter_edit_col_idx);
    if kind == FilterColKind::Select {
        handle_filter_select_key(m, ev)
    } else {
        handle_filter_text_key(m, ev)
    }
}

fn handle_filter_text_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    match ev.code {
        KeyCode::Enter => {
            let kind = m.active_filter_col_kind(m.filter_edit_col_idx);
            let mut cf = ColumnFilter::default();
            match kind {
                FilterColKind::Text => cf.text = m.filter_edit_input.clone(),
                FilterColKind::Numeric => cf.expr = m.filter_edit_input.clone(),
                FilterColKind::Select => {}
            }
            let col = m.filter_edit_col_idx;
            m.set_active_filter_col(col, cf);
            m.filter_edit_active = false;
            m.filter_edit_input.clear();
            m.clamp_cursors();
        }
        KeyCode::Esc => {
            m.filter_edit_active = false;
            m.filter_edit_input.clear();
        }
        KeyCode::Backspace => {
            m.filter_edit_input.pop();
        }
        KeyCode::Char(c) => {
            // Ctrl+H maps to backspace in Go; treat control chars as no text.
            if !ev.modifiers.contains(KeyModifiers::CONTROL) {
                m.filter_edit_input.push(c);
            } else if c == 'h' {
                m.filter_edit_input.pop();
            }
        }
        _ => {}
    }
    vec![]
}

fn handle_filter_select_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    let n = m.filter_edit_select_items.len();
    match ev.code {
        KeyCode::Right => {
            if n > 0 {
                m.filter_edit_select_cursor = (m.filter_edit_select_cursor + 1) % n;
            }
        }
        KeyCode::Left => {
            if n > 0 {
                m.filter_edit_select_cursor = (m.filter_edit_select_cursor + n - 1) % n;
            }
        }
        KeyCode::Char(' ') => {
            if let Some(v) = m.filter_edit_select_items.get(m.filter_edit_select_cursor).cloned() {
                let e = m.filter_edit_select_state.entry(v).or_insert(false);
                *e = !*e;
            }
        }
        KeyCode::Char('a') | KeyCode::Char('A') => {
            let all = m
                .filter_edit_select_items
                .iter()
                .all(|v| *m.filter_edit_select_state.get(v).unwrap_or(&false));
            for v in m.filter_edit_select_items.clone() {
                m.filter_edit_select_state.insert(v, !all);
            }
        }
        KeyCode::Enter => {
            let mut values = std::collections::HashSet::new();
            let mut all = true;
            for v in &m.filter_edit_select_items {
                if *m.filter_edit_select_state.get(v).unwrap_or(&false) {
                    values.insert(v.clone());
                } else {
                    all = false;
                }
            }
            let mut cf = ColumnFilter::default();
            if !all && !values.is_empty() {
                cf.values = values;
            }
            let col = m.filter_edit_col_idx;
            m.set_active_filter_col(col, cf);
            m.filter_edit_active = false;
            m.filter_edit_select_state.clear();
            m.clamp_cursors();
        }
        KeyCode::Esc => {
            m.filter_edit_active = false;
            m.filter_edit_select_state.clear();
        }
        _ => {}
    }
    vec![]
}

// ── Join worker picker ───────────────────────────────────────────────────

fn handle_join_picker_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    match ev.code {
        KeyCode::Up | KeyCode::Char('k') => {
            m.join_picker_cursor = m.join_picker_cursor.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if m.join_picker_cursor + 1 < m.join_picker_workers.len() {
                m.join_picker_cursor += 1;
            }
        }
        KeyCode::Char(' ') => {
            if let Some(&wid) = m.join_picker_workers.get(m.join_picker_cursor) {
                if !m.join_picker_selected.remove(&wid) {
                    m.join_picker_selected.insert(wid);
                }
            }
        }
        KeyCode::Enter | KeyCode::Char('J') => {
            let worker_ids: Vec<u32> = m.join_picker_selected.iter().copied().collect();
            m.join_picker_active = false;
            m.action_in_flight = true;
            m.status_msg = format!(
                "Joining {} shard(s) (VDF may take a while)...",
                m.join_picker_filters.len()
            );
            m.status_is_error = false;
            m.avail_selected.clear();
            let mut cmds = vec![Cmd::Join(m.join_picker_filters.clone())];
            if !worker_ids.is_empty() {
                cmds.push(Cmd::MarkManual(worker_ids));
            }
            return cmds;
        }
        KeyCode::Esc => {
            m.join_picker_active = false;
            m.status_msg = "Join cancelled".into();
            m.status_is_error = false;
        }
        _ if is_quit(&ev) => {
            m.join_picker_active = false;
            m.status_msg = "Join cancelled".into();
            m.status_is_error = false;
        }
        _ => {}
    }
    vec![]
}
