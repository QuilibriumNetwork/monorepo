//! Event/message handling for the `prover manage` TUI. Port of the
//! bubbletea `Update` + `handleKey` (and all sub-mode handlers).

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::super::epoch::{epoch_len, ConfirmWindow, WindowState};
use super::super::sign;
use super::coins;
use super::mint;
use super::model::{
    AwaitFilterEntry, ColumnFilter, FilterColKind, Model, PanelFocus, PendingAction, Tab,
};
use super::msg::Msg;
use super::settings;
use super::shield;
use super::transfer;

const MAX_AWAIT_RETRIES: u32 = 3;

/// A side-effect the event loop performs after an update (the `tea.Cmd`
/// equivalent). The loop spawns the matching async task or timer.
pub enum Cmd {
    Fetch,
    /// Read this node's legacy coins for the Coins tab.
    FetchLegacy,
    /// Read and quote `token shield-all`'s batches for its confirmation.
    ShieldPrepare,
    /// Prove and submit the confirmed batches.
    ShieldRun(super::shield::Preview),
    /// Read the reward and quote the fee for a mint confirmation.
    MintPrepare,
    /// Read the saved authorization's GLOBAL witness for a claim.
    ClaimPrepare(std::path::PathBuf, u64),
    /// Prove and submit the confirmed mint, or submit the claim.
    MintRun(super::mint::Preview),
    /// Read this wallet's shielded coins and the pending transfers it can
    /// act on.
    FetchShielded,
    /// Check and quote a transfer action for its confirmation.
    TransferPrepare(super::transfer::Kind),
    /// Run the confirmed transfer action.
    TransferRun(super::transfer::Preview),
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
        Msg::LegacyRefresh {
            answer,
            took,
            mints,
        } => {
            m.coins.mint.saved = mints;
            m.coins.mint.cursor = m
                .coins
                .mint
                .cursor
                .min(m.coins.mint.saved.len().saturating_sub(1));
            coins::apply_legacy(m, answer, took);
            vec![]
        }
        Msg::MintPreview(preview) => {
            mint::apply_preview(m, preview);
            vec![]
        }
        Msg::Mint(progress) => {
            mint::apply_progress(m, progress);
            vec![]
        }
        Msg::Shielded(read) => {
            transfer::apply_read(m, read);
            vec![]
        }
        Msg::TransferPreview(preview) => {
            transfer::apply_preview(m, preview);
            vec![]
        }
        Msg::Transfer(progress) => {
            transfer::apply_progress(m, progress);
            vec![]
        }
        Msg::ShieldPreview(preview) => {
            shield::apply_preview(m, preview);
            vec![]
        }
        Msg::Shield(progress) => {
            shield::apply_progress(m, progress);
            vec![]
        }
        Msg::RewardRefresh(result) => {
            m.reward_loaded = true;
            m.reward_error = result.as_ref().err().cloned();
            m.claimable_reward = result.ok().flatten();
            m.reward_last_success = m.claimable_reward.map(|_| Instant::now());
            vec![]
        }
        Msg::ShardLoading => {
            m.shard_loading = true;
            m.shard_message_time = Some(std::time::SystemTime::now());
            m.shard_fetch_started = Some(Instant::now());
            vec![]
        }
        Msg::ShardRefresh(result) => {
            m.shard_loading = false;
            m.shard_message_time = Some(std::time::SystemTime::now());
            let elapsed = m
                .shard_fetch_started
                .take()
                .map(|started| started.elapsed());
            match result {
                Ok(shards) => {
                    m.observe_app_intervals(&shards, Instant::now());
                    m.observe_reported_app_heads(&shards, Instant::now());
                    m.observe_committed_app_heads(&shards, Instant::now());
                    m.shard_error = None;
                    m.shard_last_success = Some(Instant::now());
                    m.shard_last_duration = elapsed;
                    // Node status can arrive after shard data on initial load.
                    m.cached_shard_info = Some(shards.clone());
                    m.process_refresh_data(m.cached_node_info.clone(), Some(shards), None);
                }
                Err(error) => m.shard_error = Some(error),
            }
            vec![]
        }

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
            if let Some(node) = &node_info {
                m.node_global_cadence = node.frame_cadence.clone();
                m.observe_global_head(node.last_received_frame, Instant::now());
            }
            if let Some(shards) = &shard_info {
                m.observe_app_intervals(shards, Instant::now());
                m.observe_reported_app_heads(shards, Instant::now());
                m.observe_committed_app_heads(shards, Instant::now());
            }
            m.last_fetch_success = Some(Instant::now());
            if m.consecutive_failures > 0 && m.status_msg.starts_with("Refresh failed: ") {
                m.status_msg.clear();
                m.status_sticky = false;
            }
            m.consecutive_failures = 0;
            m.data_loaded = true;
            m.process_refresh_data(node_info, shard_info, worker_info);
            if !m.action_in_flight && !m.status_sticky && m.operation_confirmation.is_none() {
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
                let prefix = format!("{action} failed");
                return handle_action_failure(m, &action, &prefix, &e, filters_raw.len());
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
                let prefix = format!("{action} broadcast failed");
                return handle_action_failure(m, &action, &prefix, &e, filters_raw.len());
            }
            for f in &filters_raw {
                m.broadcasted_filters.push(f.clone());
                m.broadcasted_statuses.push(original_status);
            }
            if send_frame > m.await_send_frame {
                m.await_send_frame = send_frame;
            }
            if let Some(cmd) = advance_queue(m) {
                return vec![cmd];
            }
            await_broadcast(m, &action)
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
                    let suffix = failed_suffix(m);
                    m.status_msg.push_str(&suffix);
                    m.status_is_error = m.failed_messages > 0;
                    let backoff = Duration::from_secs(3 * m.await_retries as u64);
                    return vec![Cmd::ScheduleAwaitCheck(backoff)];
                }
                let failed = failed_suffix(m);
                m.status_msg = format!(
                    "{action} check failed after {} retries: {e}{failed}",
                    m.await_retries
                );
                finish_await(m);
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
            let suffix = failed_suffix(m);
            m.status_msg.push_str(&suffix);
            m.status_is_error = m.failed_messages > 0;
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
    m.failed_messages = 0;
    m.failed_filters = 0;
    m.first_failure.clear();
}

/// Clear the previous action's queue, broadcast and failure state as a new
/// action starts, so none of it leaks into this action's counts.
fn reset_action(m: &mut Model) {
    finish_await(m);
    m.action_total = 1;
    m.action_index = 1;
}

/// The messages of a split or batched action that failed, appended to its
/// status lines: `; 1/3 messages failed (100 filter(s)): <first error>`.
fn failed_suffix(m: &Model) -> String {
    if m.failed_messages == 0 {
        return String::new();
    }
    format!(
        "; {}/{} messages failed ({} filter(s)): {}",
        m.failed_messages, m.action_total, m.failed_filters, m.first_failure
    )
}

/// Every message of the action went out or failed: await the filters the
/// broadcast messages carried, and keep the failed ones in view.
fn await_broadcast(m: &mut Model, action: &str) -> Vec<Cmd> {
    let total = m.action_total;
    let sent = total.saturating_sub(m.failed_messages);
    let failed = failed_suffix(m);
    if m.broadcasted_filters.is_empty() {
        m.status_msg = format!("0/{total} {action} messages broadcast{failed}");
        m.status_is_error = true;
        m.status_sticky = true;
        finish_await(m);
        return vec![Cmd::Fetch];
    }
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
    begin_await(m, action, &[], 0);
    m.await_filters = entries;
    let n = m.await_filters.len();
    let frame = m.await_send_frame;
    m.status_msg = if total > 1 {
        format!("{sent}/{total} {action} messages broadcast (frame {frame}). Awaiting inclusion for {n} filter(s)")
    } else {
        format!("{action} broadcast (frame {frame}). Awaiting inclusion for {n} filter(s)")
    };
    if failed.is_empty() {
        m.status_msg.push_str("...");
        m.status_is_error = false;
    } else {
        m.status_msg.push_str(&failed);
        m.status_is_error = true;
        m.status_sticky = true;
    }
    vec![Cmd::ScheduleAwaitCheck(Duration::from_secs(3))]
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
    let failed = failed_suffix(m);

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
    if !failed.is_empty() {
        m.status_msg.push_str(&failed);
        m.status_is_error = true;
    }
    m.status_sticky = true;
    finish_await(m);
    vec![Cmd::Fetch]
}

/// A message of the action failed. A single message reports its error; a
/// message of a split or batched action is counted, the rest still go out,
/// and the filters of those that went out are awaited.
fn handle_action_failure(
    m: &mut Model,
    action: &str,
    prefix: &str,
    err: &str,
    filters: usize,
) -> Vec<Cmd> {
    if m.action_total <= 1 {
        m.status_msg = format!("{prefix}: {err}");
        m.status_is_error = true;
        m.status_sticky = true;
        finish_await(m);
        return vec![Cmd::Fetch];
    }
    m.failed_messages += 1;
    m.failed_filters += filters;
    if m.first_failure.is_empty() {
        m.first_failure = err.to_string();
    }
    if let Some(cmd) = advance_queue(m) {
        return vec![cmd];
    }
    await_broadcast(m, action)
}

/// `advanceQueue` — start the next queued action: one filter of a batch, or
/// the next message of a split multi-filter action.
fn advance_queue(m: &mut Model) -> Option<Cmd> {
    if m.action_queue.is_empty() {
        return None;
    }
    let next = m.action_queue.remove(0);
    m.action_index += 1;
    m.action_in_flight = true;
    m.status_msg = format!(
        "Creating {} message ({}/{})...",
        next.action, m.action_index, m.action_total
    );
    let suffix = failed_suffix(m);
    m.status_msg.push_str(&suffix);
    m.status_is_error = m.failed_messages > 0;
    Some(Cmd::Lifecycle {
        action: next.action,
        filters: next.filters,
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
    if ev.kind != KeyEventKind::Press {
        return vec![];
    }
    if let Some(cmds) = shield::quit_guard(m, &ev, is_quit(&ev)) {
        return cmds;
    }
    if m.column_picker_active {
        return handle_column_picker_key(m, ev);
    }
    if m.operation_confirmation.is_some() {
        if is_quit(&ev) {
            return vec![Cmd::Quit];
        }
        if ev.code == KeyCode::Esc {
            m.operation_confirmation = None;
            m.join_choice = None;
            m.status_msg.clear();
        } else if ev.code == KeyCode::Enter {
            let (command, targets) = m.operation_confirmation.take().unwrap();
            if targets != operation_targets(m, command) {
                m.join_choice = None;
                m.status_msg =
                    "Allocation selection or state changed; request the action again.".into();
                m.status_is_error = true;
                m.status_sticky = true;
                return vec![];
            }
            m.status_msg.clear();
            if command == 'g' {
                return join_submit(m);
            }
            return dispatch_operation(m, command);
        }
        return vec![];
    }
    if m.tab == Tab::Coins {
        if matches!(m.coins.shield.dialog, Some(shield::Dialog::Confirm(_))) {
            return shield::dialog_key(m, ev);
        }
        if matches!(m.coins.mint.dialog, Some(mint::Dialog::Confirm(_))) {
            return mint::dialog_key(m, ev);
        }
        // A form takes every key as text but Ctrl+C, which quits.
        if matches!(m.coins.transfer.dialog, Some(transfer::Dialog::Form(_))) {
            if ev.code == KeyCode::Char('c') && ev.modifiers.contains(KeyModifiers::CONTROL) {
                return vec![Cmd::Quit];
            }
            return transfer::form_key(m, ev);
        }
        if matches!(m.coins.transfer.dialog, Some(transfer::Dialog::Confirm(_))) {
            return transfer::dialog_key(m, ev);
        }
        if m.show_help {
            return handle_help_key(m, ev);
        }
        return match ev.code {
            _ if is_quit(&ev) => vec![Cmd::Quit],
            KeyCode::Char(_) if ev.modifiers.contains(KeyModifiers::CONTROL) => vec![],
            KeyCode::Char(_) if shared_view_key(m, &ev) => vec![],
            _ => coins::handle_key(m, ev),
        };
    }
    if m.filter_edit_active
        && ev.code == KeyCode::Char('h')
        && ev.modifiers == KeyModifiers::CONTROL
    {
        return handle_filter_edit_key(m, KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
    }
    // Modifier chords never fall through into ordinary navigation or text input.
    if ev.modifiers.contains(KeyModifiers::CONTROL) && !is_quit(&ev) {
        if ev.modifiers != KeyModifiers::CONTROL
            || m.join_picker_active
            || m.show_help
            || m.filter_edit_active
            || m.is_filter_mode_active()
            || m.sort_mode
        {
            return vec![];
        }
        if let KeyCode::Char(command @ ('g' | 'l' | 'y' | 'r' | 'p' | 'u' | 'o')) = ev.code {
            // An action that does not apply, hidden or dimmed in the
            // Workers row, does nothing but say why.
            if let Some(why) = worker_action_refusal(m, command) {
                m.key_reply = Some(why.clone());
                m.status_msg = why;
                m.status_is_error = false;
                return vec![];
            }
            if matches!(command, 'l' | 'y' | 'r') && !manual_actions_allowed(m) {
                return vec![];
            }
            // Every action that signs or sends something waits for Enter;
            // Ctrl+G only opens the worker picker, whose choice asks too.
            if matches!(command, 'l' | 'y' | 'r' | 'p' | 'u' | 'o') {
                if !m.focus.is_alloc() {
                    return wrong_panel(m, "Allocation action");
                }
                let targets = operation_targets(m, command);
                if targets.is_empty() {
                    // Confirm explains when its window opens.
                    return if command == 'y' {
                        action_confirm(m)
                    } else {
                        vec![]
                    };
                }
                m.status_msg = confirmation_text(command, &targets);
                m.status_is_error = false;
                m.operation_confirmation = Some((command, targets));
                return vec![];
            }
            return dispatch_operation(m, command);
        }
        return vec![];
    }
    if m.join_picker_active {
        return handle_join_picker_key(m, ev);
    }
    if m.show_help {
        return handle_help_key(m, ev);
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

/// Help is a full screen of its own, so while it is up the cursor keys page
/// through it rather than moving a table nobody can see.
fn handle_help_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    if is_quit(&ev) {
        return vec![Cmd::Quit];
    }
    // Title and command footer stay fixed; page only the visible help body.
    let page = m.help_visible.max(1);
    let max = m.help_lines.saturating_sub(page);
    match ev.code {
        KeyCode::Char('h') | KeyCode::Esc => {
            m.show_help = false;
            m.help_offset = 0;
        }
        KeyCode::Char('d') => {
            settings::restore_defaults(m);
            m.status_msg = "View settings restored to their defaults.".into();
            m.status_is_error = false;
        }
        KeyCode::Up | KeyCode::Char('k') => m.help_offset = m.help_offset.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => m.help_offset = (m.help_offset + 1).min(max),
        KeyCode::PageUp => m.help_offset = m.help_offset.saturating_sub(page),
        KeyCode::PageDown => m.help_offset = (m.help_offset + page).min(max),
        KeyCode::Home => m.help_offset = 0,
        KeyCode::End => m.help_offset = max,
        _ => {}
    }
    vec![]
}

/// Move exactly one shared boundary; outer edges stay fixed.
fn move_panel_boundary(m: &mut Model, upper: bool, down: bool) {
    let focused = m.focus.index();
    let boundary = if upper {
        focused.checked_sub(1)
    } else if focused < 2 {
        Some(focused)
    } else {
        None
    };
    let Some(i) = boundary else { return };
    let minimum = [3, 2, 1];
    let donor = if down { i + 1 } else { i };
    if m.panel_content_heights[donor] <= minimum[donor] {
        return;
    }
    let movement = if down { 1 } else { -1 };
    m.panel_boundary_offsets[i] = m.panel_boundary_offsets[i].saturating_add(movement);
    m.panel_content_heights[i] =
        (i32::from(m.panel_content_heights[i]) + i32::from(movement)) as u16;
    m.panel_content_heights[i + 1] =
        (i32::from(m.panel_content_heights[i + 1]) - i32::from(movement)) as u16;
}

/// Why a Workers action does nothing on the current panel and selection,
/// as the one line pressing it shows; `None` when it applies. The Workers
/// row hides (compact) or dims (expanded) exactly these keys.
fn worker_action_refusal(m: &Model, command: char) -> Option<String> {
    let (tag, verb) = match command {
        'g' => ("Join", "Join"),
        'l' => ("Leave", "Leave"),
        'y' => ("Confirm", "Confirm"),
        'r' => ("Reject", "Reject"),
        'p' => ("Pause", "Pause"),
        'u' => ("Resume", "Resume"),
        'o' => ("ToggleManual", "Mode"),
        _ => return None,
    };
    if super::view::applicable_worker_actions(m).contains(tag) {
        return None;
    }
    let key = command.to_ascii_uppercase();
    let table_name = if command == 'g' {
        "Available Shards"
    } else {
        "Allocations"
    };
    let why = if m.action_in_flight {
        "an action is in progress; one action at a time.".to_string()
    } else if (command == 'g') != (m.focus == PanelFocus::Available)
        || (command != 'g' && !m.focus.is_alloc())
    {
        format!(
            "‹Ctrl+{key}› {} acts on the {table_name} table; ‹tab› selects it.",
            verb.to_lowercase()
        )
    } else if command == 'g' {
        "no free manual worker to join with.".to_string()
    } else if command == 'o' {
        "the row under the cursor has no worker.".to_string()
    } else if m.selected_alloc_rows().is_empty() {
        "no allocation selected.".to_string()
    } else if matches!(command, 'l' | 'y' | 'r')
        && m.selected_alloc_rows().iter().any(|r| !r.manually_managed)
    {
        "join/leave/confirm/reject require manual mode; AUTO allows pause/resume and mode \
         changes."
            .to_string()
    } else if let (true, (_, Some(opens))) = (command == 'y', confirmable_rows(m)) {
        format!(
            "Confirm is not yet available (current frame: {}, opens at: {opens}).",
            m.epoch_frame()
        )
    } else {
        format!(
            "{verb} does not apply to every selected allocation; they support: {}.",
            m.applicable_actions_label()
        )
    };
    Some(format!("Workers: {why}"))
}

/// Keys both tabs share: display, refresh, notice level, help and the key
/// rows. Returns whether `ev` was one.
fn shared_view_key(m: &mut Model, ev: &KeyEvent) -> bool {
    match ev.code {
        KeyCode::Char('n') => {
            m.compact_actions = !m.compact_actions;
            m.compact_units = m.compact_actions;
        }
        KeyCode::Char('t') => {
            m.refresh_seconds = match m.refresh_seconds {
                5 => 15,
                15 => 30,
                30 => 60,
                _ => 5,
            };
            m.refresh_changed_at = Some(Instant::now());
        }
        KeyCode::Char('v') => {
            m.notice_minimum = m.notice_minimum.next();
            m.notice_offset = 0;
        }
        KeyCode::Char('h') => super::view::open_help(m),
        KeyCode::Char('c') => m.color_coding = !m.color_coding,
        KeyCode::Char('?') => m.show_key_rows = !m.show_key_rows,
        _ => return false,
    }
    true
}

fn handle_normal_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    if is_quit(&ev) {
        return vec![Cmd::Quit];
    }
    if shared_view_key(m, &ev) {
        return vec![];
    }
    let c = ch(&ev);
    let hint = match ev.code {
        KeyCode::Up | KeyCode::Char('k') => Some("↑/k"),
        KeyCode::Down | KeyCode::Char('j') => Some("↓/j"),
        KeyCode::Left | KeyCode::Right => Some("←/→"),
        KeyCode::Char('b') => Some("b"),
        KeyCode::Char('s') => Some("s"),
        KeyCode::Char('f') => Some("f"),
        KeyCode::Char(' ') => Some("space"),
        KeyCode::Char('a') => Some("a"),
        _ => None,
    };
    // A key that does not apply, hidden or dimmed in the UI row, does
    // nothing but say why.
    if let Some(why) = hint.and_then(|key| super::view::ui_key_refusal(m, key)) {
        m.key_reply = Some(why.clone());
        m.status_msg = why;
        m.status_is_error = false;
        return vec![];
    }
    match ev.code {
        KeyCode::Char('1') => return vec![],
        KeyCode::Char('2') => return coins::open(m),
        KeyCode::Char('b') => {
            if m.focus == PanelFocus::Notifications {
                return vec![];
            }
            m.column_picker_active = true;
            m.visibility_section = 0;
            m.column_picker_cursor = 2;
            m.column_picker_offset = 0;
            return vec![];
        }
        KeyCode::PageUp => {
            m.notice_offset = m.notice_offset.saturating_sub(m.notice_visible.max(1));
            return vec![];
        }
        KeyCode::PageDown => {
            m.notice_offset = (m.notice_offset + m.notice_visible.max(1))
                .min(m.notice_lines.saturating_sub(m.notice_visible));
            return vec![];
        }
        KeyCode::Home => {
            m.notice_offset = 0;
            return vec![];
        }
        KeyCode::End => {
            m.notice_offset = m.notice_lines.saturating_sub(m.notice_visible);
            return vec![];
        }
        KeyCode::Char('e') => {
            m.threshold_unit = m.threshold_unit.toggled();
            return vec![];
        }
        KeyCode::Tab => {
            m.focus = m.focus.next();
            m.filter_edit_active = false;
            return vec![];
        }
        KeyCode::BackTab => {
            m.focus = m.focus.previous();
            return vec![];
        }
        KeyCode::Left | KeyCode::Right => {
            let i = m.focus.index();
            if i < 2 {
                m.horizontal_offsets[i] = if ev.code == KeyCode::Left {
                    m.horizontal_offsets[i].saturating_sub(8)
                } else {
                    m.horizontal_offsets[i]
                        .saturating_add(8)
                        .min(m.horizontal_limits[i])
                };
            }
            return vec![];
        }
        KeyCode::Char('[') => {
            move_panel_boundary(m, true, false);
            return vec![];
        }
        KeyCode::Char(']') => {
            move_panel_boundary(m, true, true);
            return vec![];
        }
        KeyCode::Char('{') => {
            move_panel_boundary(m, false, false);
            return vec![];
        }
        KeyCode::Char('}') => {
            move_panel_boundary(m, false, true);
            return vec![];
        }
        KeyCode::Char(' ') => {
            if m.focus == PanelFocus::Notifications {
                return vec![];
            }
            toggle_select(m);
            return vec![];
        }
        KeyCode::Char('a') => {
            if m.focus == PanelFocus::Notifications {
                return vec![];
            }
            select_all(m);
            return vec![];
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if m.focus == PanelFocus::Notifications {
                m.notice_offset = m.notice_offset.saturating_sub(1);
            } else {
                cursor_up(m);
            }
            return vec![];
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if m.focus == PanelFocus::Notifications {
                m.notice_offset =
                    (m.notice_offset + 1).min(m.notice_lines.saturating_sub(m.notice_visible));
            } else {
                cursor_down(m);
            }
            return vec![];
        }
        _ => {}
    }
    if m.focus == PanelFocus::Notifications {
        return vec![];
    }
    match c {
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

fn handle_column_picker_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    if is_quit(&ev) {
        return vec![Cmd::Quit];
    }
    if ev
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return vec![];
    }
    match ev.code {
        KeyCode::Up if ev.modifiers.contains(KeyModifiers::SHIFT) && m.visibility_section == 0 => {
            m.move_picker_column(true)
        }
        KeyCode::Down
            if ev.modifiers.contains(KeyModifiers::SHIFT) && m.visibility_section == 0 =>
        {
            m.move_picker_column(false)
        }
        KeyCode::Char('r') if m.visibility_section == 0 => m.reset_picker_column_order(),
        KeyCode::Up | KeyCode::Char('k') => {
            m.column_picker_cursor = m.column_picker_cursor.saturating_sub(1)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            m.column_picker_cursor =
                (m.column_picker_cursor + 1).min(m.visibility_names().len() - 1)
        }
        KeyCode::Tab | KeyCode::BackTab => {
            m.visibility_section =
                (m.visibility_section + if ev.code == KeyCode::BackTab { 4 } else { 1 }) % 5;
            m.column_picker_cursor = if m.visibility_section == 0 { 2 } else { 0 };
            m.column_picker_offset = 0;
        }
        KeyCode::Char(' ') => {
            if let Some((global, window)) =
                m.visibility_interval_window(m.visibility_section, m.column_picker_cursor)
            {
                let next = (if global {
                    m.global_interval_mask()
                } else {
                    m.interval_mask()
                }) ^ (1 << window);
                if next != 0 {
                    if global {
                        m.global_interval_windows = next;
                    } else {
                        m.interval_windows = next;
                    }
                }
            } else if let Some(window) =
                m.visibility_reward_window(m.visibility_section, m.column_picker_cursor)
            {
                let next = m.reward_mask() ^ (1 << window);
                if next != 0 {
                    m.reward_windows = next;
                }
            } else if let Some(field) =
                m.visibility_global_field(m.visibility_section, m.column_picker_cursor)
            {
                let next = m.global_field_mask() ^ (1 << field);
                if next != 0 {
                    m.global_fields = next;
                }
            } else if m.visibility_section == 0 {
                let col = m.visibility_column_index(m.column_picker_cursor).unwrap();
                let key = m.column_visibility_key(col);
                if col >= 2 && !m.hidden_columns.remove(&key) {
                    m.hidden_columns.insert(key);
                }
            } else {
                let name = m.visibility_names()[m.column_picker_cursor];
                if !m.hidden_header_kpis.remove(name) {
                    m.hidden_header_kpis.insert(name.into());
                }
            }
        }
        KeyCode::Char('c') if m.visibility_section == 0 => m.hidden_columns.extend([2, 4, 5]),
        KeyCode::Char('a') => {
            if m.visibility_section == 0 {
                m.hidden_columns.clear();
                m.interval_windows = 3;
                m.reward_windows = 7;
            } else {
                for name in m.visibility_names() {
                    m.hidden_header_kpis.remove(name);
                }
                if m.visibility_section == 1 {
                    m.global_interval_windows = 3;
                    m.global_fields = 7;
                }
                if m.visibility_section == 2 {
                    m.reward_windows = 7;
                }
            }
        }
        KeyCode::Enter | KeyCode::Esc | KeyCode::Char('b') => m.column_picker_active = false,
        _ => {}
    }
    vec![]
}

fn operation_targets(m: &Model, command: char) -> Vec<(String, u32, i64, bool)> {
    if command == 'g' {
        // The chosen shards, and the chosen workers that are still free.
        let Some((filters, workers)) = &m.join_choice else {
            return vec![];
        };
        let free = m.manual_free_workers();
        let mut targets: Vec<_> = filters
            .iter()
            .map(|filter| (hex::encode(filter), 0, -1, true))
            .chain(
                workers
                    .iter()
                    .filter(|id| free.contains(id))
                    .map(|id| (format!("worker:{id}"), 0, i64::from(*id), true)),
            )
            .collect();
        targets.sort();
        return targets;
    }
    if command == 'y' {
        let mut targets: Vec<_> = confirmable_rows(m)
            .0
            .into_iter()
            .map(|row| {
                (
                    row.filter_key,
                    row.status,
                    row.worker_id,
                    row.manually_managed,
                )
            })
            .collect();
        targets.sort();
        return targets;
    }
    let rows = if command == 'o' {
        m.sorted_allocations()
            .get(m.alloc_cursor)
            .cloned()
            .into_iter()
            .collect()
    } else {
        m.selected_alloc_rows()
    };
    let mut targets: Vec<_> = rows
        .into_iter()
        .filter(|row| match command {
            'l' | 'p' => row.status == 2,
            'u' => row.status == 3,
            'r' => row.status == 1 || row.status == 4,
            'o' => row.worker_id >= 0,
            _ => false,
        })
        .map(|row| {
            (
                row.filter_key,
                row.status,
                row.worker_id,
                row.manually_managed,
            )
        })
        .collect();
    targets.sort();
    targets
}

fn manual_actions_allowed(m: &mut Model) -> bool {
    if m.focus.is_alloc() && m.selected_alloc_rows().iter().any(|r| !r.manually_managed) {
        m.status_msg = "Join/leave/confirm/reject require manual mode; AUTO allows pause/resume and mode changes.".into();
        m.status_is_error = true;
        m.status_sticky = true;
        return false;
    }
    true
}

fn dispatch_operation(m: &mut Model, command: char) -> Vec<Cmd> {
    if matches!(command, 'l' | 'y' | 'r') && !manual_actions_allowed(m) {
        return vec![];
    }
    match command {
        'g' => action_join(m),
        'l' => action_leave(m),
        'y' => action_confirm(m),
        'r' => action_reject(m),
        'p' => action_pause(m),
        'u' => action_resume(m),
        'o' => action_toggle_manual(m),
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

/// The confirmed join: request it and set the chosen workers to manual.
fn join_submit(m: &mut Model) -> Vec<Cmd> {
    let Some((filters, workers)) = m.join_choice.take() else {
        return vec![];
    };
    reset_action(m);
    m.action_in_flight = true;
    m.status_msg = format!(
        "Joining {} shard(s) (VDF may take a while)...",
        filters.len()
    );
    m.status_is_error = false;
    m.avail_selected.clear();
    let mut cmds = vec![Cmd::Join(filters)];
    if !workers.is_empty() {
        cmds.push(Cmd::MarkManual(workers));
    }
    cmds
}

fn action_join(m: &mut Model) -> Vec<Cmd> {
    if m.action_in_flight {
        return vec![];
    }
    if m.focus != PanelFocus::Available {
        m.status_msg =
            "Join is only available in the Available Shards panel (Tab to switch)".into();
        m.status_is_error = true;
        return vec![];
    }
    if m.manual_free_workers().is_empty() {
        m.status_msg =
            "Join requires at least one free manual worker; switch an idle worker with Ctrl+O"
                .into();
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
    m.join_picker_workers = m.manual_free_workers();
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
    let current_frame = m.epoch_frame();
    let (confirm_rows, earliest) = confirmable_rows(m);
    if confirm_rows.is_empty() {
        if let Some(earliest) = earliest {
            m.status_msg = format!(
                "Confirm not yet available (current frame: {}, opens at: {}). Applicable action(s): Reject",
                current_frame, earliest
            );
            m.status_is_error = true;
            return vec![];
        }
    }
    start_multi_filter_action(m, "Confirm", confirm_rows, |s| s == 1 || s == 4)
}

/// The selected allocations whose join or leave Confirm can act on now
/// (its window is open), and the earliest frame a pending window opens.
fn confirmable_rows(m: &Model) -> (Vec<super::model::AllocationRow>, Option<u64>) {
    // Use the same epoch-aligned window and current frame as the hints.
    let current_frame = m.epoch_frame();
    let mut confirm_rows = Vec::new();
    let mut earliest: Option<u64> = None;
    for row in m.selected_alloc_rows() {
        let proposal_frame = match row.status {
            1 if row.confirm_frame == 0 => row.join_frame,
            4 if row.leave_confirm_frame == 0 => row.leave_frame,
            _ => continue,
        };
        if proposal_frame == 0 {
            continue;
        }
        let window = ConfirmWindow::for_frame(proposal_frame, m.epoch_length);
        match window.state(current_frame, m.epoch_length) {
            WindowState::Open => confirm_rows.push(row),
            WindowState::Pending => {
                earliest = Some(earliest.map_or(window.start_frame, |f| f.min(window.start_frame)));
            }
            WindowState::Missed => {}
        }
    }
    (confirm_rows, earliest)
}

/// A shard filter key as the tables shorten it.
fn short_target(key: &str) -> String {
    match key.strip_prefix("worker:") {
        Some(id) => format!("worker {id}"),
        None if key.len() > 9 => format!("…{}", &key[key.len() - 9..]),
        None => key.to_string(),
    }
}

/// Up to three targets by name, then how many more.
fn target_list(names: Vec<String>) -> String {
    let more = names.len().saturating_sub(3);
    let mut text = names.into_iter().take(3).collect::<Vec<_>>().join(", ");
    if more > 0 {
        text.push_str(&format!(" and {more} more"));
    }
    text
}

/// The question an operation's confirmation asks, naming its targets.
pub(super) fn confirmation_text(command: char, targets: &[(String, u32, i64, bool)]) -> String {
    const ASK: &str = "Enter confirms; Esc cancels.";
    match command {
        'g' => {
            let shards: Vec<String> = targets
                .iter()
                .filter(|t| t.2 < 0)
                .map(|t| short_target(&t.0))
                .collect();
            let workers: Vec<String> = targets
                .iter()
                .filter(|t| t.2 >= 0)
                .map(|t| t.2.to_string())
                .collect();
            format!(
                "Join for {} shard(s): {}, with worker(s) {} set to manual? {ASK}",
                shards.len(),
                target_list(shards),
                workers.join(", ")
            )
        }
        'o' => match targets.first() {
            Some((key, _, worker, manual)) => format!(
                "Change worker mode for 1 allocation(s): worker {worker} on {} to {}? {ASK}",
                short_target(key),
                if *manual { "auto" } else { "manual" }
            ),
            None => String::new(),
        },
        _ => {
            let label = match command {
                'l' => "Leave",
                'y' => "Confirm",
                'r' => "Reject",
                'p' => "Pause",
                'u' => "Resume",
                _ => "Allocation action",
            };
            format!(
                "{label} for {} allocation(s): {}? {ASK}",
                targets.len(),
                target_list(targets.iter().map(|t| short_target(&t.0)).collect())
            )
        }
    }
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
    reset_action(m);
    m.action_in_flight = true;
    m.status_is_error = false;
    m.alloc_selected.clear();
    // One op carries at most the filters every node decodes: a longer
    // selection goes out as several messages, sent in turn like a batch.
    let mut chunks: Vec<Vec<Vec<u8>>> =
        sign::op_chunks(&filters).map(<[Vec<u8>]>::to_vec).collect();
    let first = chunks.remove(0);
    if chunks.is_empty() {
        m.status_msg = format!(
            "Creating {action} message for {} allocation(s)...",
            filters.len()
        );
    } else {
        m.action_queue = chunks
            .into_iter()
            .map(|filters| PendingAction {
                action: action.to_string(),
                filters,
                status,
            })
            .collect();
        m.action_total = m.action_queue.len() + 1;
        m.action_index = 1;
        m.status_msg = format!(
            "Creating {action} message (1/{}) for {} allocation(s)...",
            m.action_total,
            filters.len()
        );
    }
    let mut cmds = vec![Cmd::Lifecycle {
        action: action.to_string(),
        filters: first,
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
                filters: vec![row.filter.clone()],
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
    reset_action(m);
    m.action_queue = queue;
    m.action_total = m.action_queue.len() + 1;
    m.action_index = 1;
    m.action_in_flight = true;
    m.status_is_error = false;
    m.alloc_selected.clear();
    m.status_msg = format!("Creating {action} message (1/{})...", m.action_total);
    vec![Cmd::Lifecycle {
        action: action.to_string(),
        filters: first.filters,
        original_status: first.status,
    }]
}

// ── Sort mode ────────────────────────────────────────────────────────────

fn handle_sort_mode_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    let cols = m.active_visible_columns();
    let index = cols
        .iter()
        .position(|&col| col == m.sort_highlight_col)
        .unwrap_or(0);
    let num_cols = cols.len();
    match ev.code {
        KeyCode::Right => {
            m.sort_highlight_col = cols[(index + 1) % num_cols];
        }
        KeyCode::Left => {
            m.sort_highlight_col = cols[(index + num_cols - 1) % num_cols];
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
            if let Some(v) = m
                .filter_edit_select_items
                .get(m.filter_edit_select_cursor)
                .cloned()
            {
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
        KeyCode::Enter => {
            let worker_ids: Vec<u32> = m.join_picker_selected.iter().copied().collect();
            let free = m.manual_free_workers();
            if worker_ids.is_empty() || worker_ids.iter().any(|id| !free.contains(id)) {
                m.status_msg =
                    "Select a free manual worker; worker state may have changed. Esc cancels."
                        .into();
                m.status_is_error = true;
                return vec![];
            }
            m.join_picker_active = false;
            let mut workers = worker_ids;
            workers.sort_unstable();
            m.join_choice = Some((m.join_picker_filters.clone(), workers));
            let targets = operation_targets(m, 'g');
            m.status_msg = confirmation_text('g', &targets);
            m.status_is_error = false;
            m.operation_confirmation = Some(('g', targets));
            return vec![];
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

#[cfg(test)]
mod tests {
    use super::super::model::FilterOutcome;
    use super::*;
    use quil_types::proto::node::{NodeInfoResponse, ShardAllocationInfo};

    fn operational_model(status: u32) -> Model {
        let mut m = Model::new();
        m.process_refresh_data(
            Some(NodeInfoResponse {
                shard_allocations: vec![ShardAllocationInfo {
                    filter: vec![1],
                    status,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            None,
            None,
        );
        m.allocations[0].manually_managed = true;
        m
    }

    /// A multi-filter action over more allocations than one op carries goes
    /// out as several messages, sent in turn; the await covers them all.
    #[test]
    fn a_long_multi_filter_action_is_sent_as_several_messages() {
        let mut m = Model::new();
        let filter = |n: u16| [n.to_be_bytes().as_slice(), &[0xC0; 30]].concat();
        m.process_refresh_data(
            Some(NodeInfoResponse {
                shard_allocations: (0..250)
                    .map(|n| ShardAllocationInfo {
                        filter: filter(n),
                        status: 2,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }),
            None,
            None,
        );
        let rows = m.allocations.clone();
        let sent = |cmds: &[Cmd]| match cmds.first() {
            Some(Cmd::Lifecycle {
                action, filters, ..
            }) if action == "Leave" => filters.clone(),
            _ => panic!("a Leave message"),
        };
        let mut filters = sent(&start_multi_filter_action(&mut m, "Leave", rows, |s| {
            s == 2
        }));
        assert_eq!(filters.len(), 100);
        assert_eq!(
            m.status_msg,
            "Creating Leave message (1/3) for 250 allocation(s)..."
        );
        let broadcast = |filters: Vec<Vec<u8>>| Msg::ActionBroadcast {
            action: "Leave".into(),
            filters_raw: filters,
            send_frame: 9,
            original_status: 2,
            err: None,
        };
        for expected in [100, 50] {
            let next = sent(&apply_msg(&mut m, broadcast(filters.clone())));
            assert_eq!(next.len(), expected);
            filters = next;
        }
        assert!(matches!(
            apply_msg(&mut m, broadcast(filters)).as_slice(),
            [Cmd::ScheduleAwaitCheck(_)]
        ));
        assert_eq!(m.await_filters.len(), 250);
        assert_eq!(
            m.status_msg,
            "3/3 Leave messages broadcast (frame 9). Awaiting inclusion for 250 filter(s)..."
        );
    }

    /// A model with 250 operational allocations whose Leave was started:
    /// three messages of 100, 100 and 50 filters.
    fn leaving_250(m: &mut Model) -> Vec<Vec<u8>> {
        let filter = |n: u16| [n.to_be_bytes().as_slice(), &[0xC0; 30]].concat();
        m.process_refresh_data(
            Some(NodeInfoResponse {
                shard_allocations: (0..250)
                    .map(|n| ShardAllocationInfo {
                        filter: filter(n),
                        status: 2,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }),
            None,
            None,
        );
        let rows = m.allocations.clone();
        lifecycle_filters(&start_multi_filter_action(m, "Leave", rows, |s| s == 2))
    }

    fn lifecycle_filters(cmds: &[Cmd]) -> Vec<Vec<u8>> {
        match cmds.first() {
            Some(Cmd::Lifecycle {
                action, filters, ..
            }) if action == "Leave" => filters.clone(),
            _ => panic!("a Leave message"),
        }
    }

    fn leave_broadcast(filters: Vec<Vec<u8>>, err: Option<&str>) -> Msg {
        Msg::ActionBroadcast {
            action: "Leave".into(),
            filters_raw: filters,
            send_frame: if err.is_some() { 0 } else { 9 },
            original_status: 2,
            err: err.map(str::to_string),
        }
    }

    /// A failed message of a split action stays in view through the await
    /// and its result, and only the filters that went out are awaited.
    #[test]
    fn a_failed_message_of_a_split_action_is_reported_with_its_filters() {
        let mut m = Model::new();
        let first = leaving_250(&mut m);
        let second = lifecycle_filters(&apply_msg(&mut m, leave_broadcast(first.clone(), None)));
        let third = lifecycle_filters(&apply_msg(&mut m, leave_broadcast(second, Some("boom"))));
        assert_eq!(third.len(), 50);
        assert_eq!(
            m.status_msg,
            "Creating Leave message (3/3)...; 1/3 messages failed (100 filter(s)): boom"
        );
        assert!(m.status_is_error);
        assert!(matches!(
            apply_msg(&mut m, leave_broadcast(third.clone(), None)).as_slice(),
            [Cmd::ScheduleAwaitCheck(_)]
        ));
        assert_eq!(m.await_filters.len(), 150);
        assert_eq!(
            m.status_msg,
            "2/3 Leave messages broadcast (frame 9). Awaiting inclusion for 150 filter(s); 1/3 messages failed (100 filter(s)): boom"
        );
        assert!(m.status_is_error);
        apply_msg(
            &mut m,
            Msg::AwaitResult {
                action: "Leave".into(),
                frame: 10,
                err: Some("rpc".into()),
                per_filter: Vec::new(),
            },
        );
        assert_eq!(
            m.status_msg,
            "Leave check transient error (1/3): rpc; 1/3 messages failed (100 filter(s)): boom"
        );
        assert!(m.status_is_error);
        let per_filter = first
            .iter()
            .chain(&third)
            .map(|f| FilterOutcome {
                filter: f.clone(),
                outcome: "left".into(),
                settled: true,
            })
            .collect();
        apply_msg(
            &mut m,
            Msg::AwaitResult {
                action: "Leave".into(),
                frame: 12,
                err: None,
                per_filter,
            },
        );
        assert_eq!(m.status_msg, "Leave confirmed at frame 12 (150 filter(s)); 1/3 messages failed (100 filter(s)): boom");
        assert!(m.status_is_error && !m.action_in_flight);
        assert_eq!(
            (m.broadcasted_filters.len(), m.action_total),
            (0, 0),
            "nothing carries over"
        );
    }

    /// When the last message fails, the filters of the earlier ones are
    /// still awaited; when every message fails, none is.
    #[test]
    fn a_failed_last_message_still_awaits_the_sent_filters() {
        let mut m = Model::new();
        let first = leaving_250(&mut m);
        let second = lifecycle_filters(&apply_msg(&mut m, leave_broadcast(first, None)));
        let third = lifecycle_filters(&apply_msg(&mut m, leave_broadcast(second, None)));
        assert!(matches!(
            apply_msg(&mut m, leave_broadcast(third, Some("boom"))).as_slice(),
            [Cmd::ScheduleAwaitCheck(_)]
        ));
        assert!(m.action_in_flight);
        assert_eq!(m.await_filters.len(), 200);
        assert_eq!(
            m.status_msg,
            "2/3 Leave messages broadcast (frame 9). Awaiting inclusion for 200 filter(s); 1/3 messages failed (50 filter(s)): boom"
        );

        let mut m = Model::new();
        let mut filters = leaving_250(&mut m);
        for _ in 0..2 {
            filters = lifecycle_filters(&apply_msg(&mut m, leave_broadcast(filters, Some("boom"))));
        }
        assert!(matches!(
            apply_msg(&mut m, leave_broadcast(filters, Some("late"))).as_slice(),
            [Cmd::Fetch]
        ));
        assert_eq!(
            m.status_msg,
            "0/3 Leave messages broadcast; 3/3 messages failed (250 filter(s)): boom"
        );
        assert!(m.status_is_error && !m.action_in_flight && m.await_filters.is_empty());
    }

    /// A new action starts from clean counts: nothing a previous action
    /// broadcast, queued or failed leaks into its messages or its await.
    #[test]
    fn a_new_action_does_not_inherit_the_previous_actions_counts() {
        let mut m = Model::new();
        let filter = |n: u8| vec![n; 32];
        m.process_refresh_data(
            Some(NodeInfoResponse {
                shard_allocations: (0..2)
                    .map(|n| ShardAllocationInfo {
                        filter: filter(n),
                        status: 2,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }),
            None,
            None,
        );
        m.action_total = 3;
        m.action_index = 3;
        m.broadcasted_filters = vec![filter(7); 100];
        m.broadcasted_statuses = vec![2; 100];
        let rows = m.allocations.clone();
        let filters = lifecycle_filters(&start_multi_filter_action(&mut m, "Leave", rows, |s| {
            s == 2
        }));
        assert_eq!(
            m.status_msg,
            "Creating Leave message for 2 allocation(s)..."
        );
        apply_msg(&mut m, leave_broadcast(filters, None));
        assert_eq!(m.await_filters.len(), 2);
        assert_eq!(
            m.status_msg,
            "Leave broadcast (frame 9). Awaiting inclusion for 2 filter(s)..."
        );
        assert!(!m.status_is_error);
    }

    #[test]
    fn visibility_picker_separates_columns_top_and_panel_kpis() {
        let mut m = Model::new();
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        handle_key(&mut m, key(KeyCode::Char('b')));
        handle_key(&mut m, key(KeyCode::Tab));
        assert_eq!(m.visibility_section, 1);
        handle_key(&mut m, key(KeyCode::Char(' ')));
        assert!(!m.header_kpi_visible("Peer ID"));
        assert!(m.column_visible(1));
        handle_key(&mut m, key(KeyCode::Tab));
        assert_eq!(m.visibility_section, 2);
        handle_key(&mut m, key(KeyCode::Char(' ')));
        assert!(!m.header_kpi_visible("Workers"));
        assert!(!m.header_kpi_visible("Peer ID"));
        handle_key(&mut m, key(KeyCode::Char('a')));
        assert!(m.header_kpi_visible("Workers"));
        assert!(!m.header_kpi_visible("Peer ID"));
        handle_key(&mut m, key(KeyCode::BackTab));
        handle_key(&mut m, key(KeyCode::Char('a')));
        assert!(m.header_kpi_visible("Peer ID"));
    }

    #[test]
    fn column_picker_hides_shared_fields_and_preserves_required_identity_columns() {
        let mut m = Model::new();
        let key = |c| KeyEvent::new(c, KeyModifiers::NONE);
        assert!(handle_key(&mut m, key(KeyCode::Char('b'))).is_empty());
        assert!(m.column_picker_active);
        handle_key(&mut m, key(KeyCode::Char('c')));
        for col in [2, 4, 5] {
            assert!(!m.column_visible(col));
        }
        m.column_picker_cursor = 1;
        handle_key(&mut m, key(KeyCode::Char(' ')));
        assert!(m.column_visible(0) && m.column_visible(1));
        handle_key(&mut m, key(KeyCode::Esc));
        handle_key(&mut m, key(KeyCode::Char('s')));
        handle_key(&mut m, key(KeyCode::Right));
        assert_eq!(m.sort_highlight_col, 1);
        handle_key(&mut m, key(KeyCode::Right));
        assert_eq!(m.sort_highlight_col, 3);
        handle_key(&mut m, key(KeyCode::Esc));
        assert!(!m.active_panel_filter_cols().contains(&2));
        m.focus = PanelFocus::Available;
        assert!(!m.active_panel_filter_cols().contains(&4));
        handle_key(&mut m, key(KeyCode::Char('b')));
        handle_key(&mut m, key(KeyCode::Char('a')));
        assert!(m.hidden_columns.is_empty());
        assert!(!m.action_in_flight);
    }

    #[test]
    fn auto_workers_reject_manual_only_commands_and_allow_mode_changes() {
        for (status, keys) in [
            (1, vec!['y', 'r']),
            (2, vec!['l']),
            (3, vec!['l']),
            (4, vec!['y', 'r']),
        ] {
            let mut m = operational_model(status);
            m.allocations[0].manually_managed = false;
            m.allocations[0].worker_id = 1;
            for c in keys {
                assert!(handle_key(
                    &mut m,
                    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
                )
                .is_empty());
                assert!(!m.action_in_flight && m.operation_confirmation.is_none());
                assert!(!m.applicable_alloc_actions().contains(match c {
                    'l' => "Leave",
                    'y' => "Confirm",
                    _ => "Reject",
                }));
            }
            handle_key(
                &mut m,
                KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL),
            );
            assert!(m.operation_confirmation.is_some());
            assert!(matches!(
                handle_key(&mut m, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)).as_slice(),
                [Cmd::ToggleManual { manual: true, .. }]
            ));
        }
        let mut m = operational_model(2);
        let mut auto = m.allocations[0].clone();
        auto.filter_key = "auto".into();
        auto.manually_managed = false;
        m.allocations.push(auto);
        m.alloc_selected
            .extend([m.allocations[0].filter_key.clone(), "auto".into()]);
        assert!(dispatch_operation(&mut m, 'l').is_empty());
        assert!(!m.action_in_flight);
    }

    #[test]
    fn auto_pause_and_resume_use_status_checks_and_preserve_worker_mode() {
        let key = |code| KeyEvent::new(code, KeyModifiers::CONTROL);
        let mut m = operational_model(2);
        m.allocations[0].manually_managed = false;
        assert_eq!(
            m.applicable_alloc_actions(),
            ["Pause".to_string()].into_iter().collect()
        );
        assert!(handle_key(&mut m, key(KeyCode::Char('p'))).is_empty());
        assert!(m.operation_confirmation.is_some() && !m.action_in_flight);
        let commands = handle_key(&mut m, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            matches!(commands.as_slice(), [Cmd::Lifecycle { action, filters, .. }] if action == "Pause" && filters == &vec![vec![1]])
        );
        assert!(!m.allocations[0].manually_managed);
        let mut m = operational_model(3);
        m.allocations[0].manually_managed = false;
        assert_eq!(
            m.applicable_alloc_actions(),
            ["Resume".to_string()].into_iter().collect()
        );
        // Ctrl+U alone only asks, naming the allocation; Enter sends.
        assert!(handle_key(&mut m, key(KeyCode::Char('u'))).is_empty());
        assert_eq!(
            m.status_msg,
            "Resume for 1 allocation(s): 01? Enter confirms; Esc cancels."
        );
        assert!(
            matches!(handle_key(&mut m, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)).as_slice(), [Cmd::Lifecycle { action, .. }] if action == "Resume")
        );
        assert!(!m.allocations[0].manually_managed);
        let mut m = operational_model(2);
        let mut auto = m.allocations[0].clone();
        auto.filter_key = "auto".into();
        auto.filter = vec![2];
        auto.manually_managed = false;
        m.allocations.push(auto);
        m.alloc_selected
            .extend([m.allocations[0].filter_key.clone(), "auto".into()]);
        assert_eq!(
            m.applicable_alloc_actions(),
            ["Pause".to_string()].into_iter().collect()
        );
        assert!(
            matches!(dispatch_operation(&mut m, 'p').as_slice(), [Cmd::Lifecycle { action, filters, .. }] if action == "Pause" && filters.len() == 1)
        );
        assert_eq!(m.action_total, 2);
        assert_eq!(m.action_queue.len(), 1);
    }

    #[test]
    fn lowercase_color_toggle_is_distinct_from_ctrl_c_quit() {
        let mut m = Model::new();
        assert!(handle_key(
            &mut m,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE)
        )
        .is_empty());
        assert!(!m.color_coding && !m.action_in_flight);
        assert!(matches!(
            handle_key(
                &mut m,
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
            )
            .as_slice(),
            [Cmd::Quit]
        ));
    }

    #[test]
    fn joining_requires_free_manual_workers_and_rechecks_mode() {
        let mut m = operational_model(2);
        m.allocations[0].status = 0;
        m.allocations[0].worker_id = 2;
        m.free_workers = vec![2];
        assert_eq!(m.manual_free_workers(), vec![2]);
        m.join_picker_active = true;
        m.join_picker_selected.insert(2);
        m.allocations[0].manually_managed = false;
        assert!(
            handle_join_picker_key(&mut m, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .is_empty()
        );
        assert!(!m.action_in_flight && m.join_picker_active);
        assert!(m.manual_free_workers().is_empty());
    }

    /// The worker picker's choice is a question, not a join: Enter in the
    /// picker names the shards and workers; only Enter again sends, and
    /// only while the chosen workers are still free.
    #[test]
    fn the_join_pickers_choice_waits_for_enter_and_names_its_targets() {
        let enter = || KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let choose = |m: &mut Model| {
            m.join_picker_active = true;
            m.join_picker_filters = vec![vec![0xab; 3]];
            m.join_picker_selected.insert(2);
            handle_join_picker_key(m, enter())
        };
        let mut m = operational_model(2);
        m.allocations[0].status = 0;
        m.allocations[0].worker_id = 2;
        m.free_workers = vec![2];
        assert!(choose(&mut m).is_empty());
        assert!(!m.join_picker_active && !m.action_in_flight);
        assert_eq!(
            m.status_msg,
            "Join for 1 shard(s): ababab, with worker(s) 2 set to manual? Enter confirms; Esc cancels."
        );
        // Esc cancels: nothing sent, nothing kept.
        assert!(handle_key(&mut m, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)).is_empty());
        assert!(m.operation_confirmation.is_none() && m.join_choice.is_none());
        // Enter sends the join and the mode change.
        choose(&mut m);
        assert!(matches!(
            handle_key(&mut m, enter()).as_slice(),
            [Cmd::Join(filters), Cmd::MarkManual(workers)]
                if *filters == vec![vec![0xab; 3]] && *workers == vec![2]
        ));
        assert!(m.action_in_flight);
        // A worker taken meanwhile voids the question.
        let mut m = operational_model(2);
        m.allocations[0].status = 0;
        m.allocations[0].worker_id = 2;
        m.free_workers = vec![2];
        choose(&mut m);
        m.free_workers.clear();
        assert!(handle_key(&mut m, enter()).is_empty());
        assert!(m.status_msg.contains("changed; request the action again"));
    }

    #[test]
    fn refresh_toggle_cycles_without_operational_side_effects() {
        let mut m = Model::new();
        assert_eq!(m.refresh_seconds, 15);
        for expected in [30, 60, 5, 15] {
            assert!(handle_key(
                &mut m,
                KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE)
            )
            .is_empty());
            assert_eq!(m.refresh_seconds, expected);
            assert!(!m.action_in_flight);
            assert!(m.refresh_changed_at.is_some());
        }
    }

    #[test]
    fn operational_keys_require_control_and_disruptive_actions_require_confirmation() {
        let mut m = operational_model(2);
        for command in ['J', 'l', 'c', 'r', 'p', 'u', 'M'] {
            assert!(handle_key(
                &mut m,
                KeyEvent::new(KeyCode::Char(command), KeyModifiers::NONE)
            )
            .is_empty());
            assert!(!m.action_in_flight && m.operation_confirmation.is_none());
        }
        let ctrl_pause = KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL);
        assert!(handle_key(&mut m, ctrl_pause).is_empty());
        assert!(m.operation_confirmation.is_some());
        assert!(handle_key(
            &mut m,
            KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE)
        )
        .is_empty());
        assert_eq!(m.alloc_cursor, 0);
        handle_key(&mut m, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(m.operation_confirmation.is_none() && !m.action_in_flight);
        handle_key(&mut m, ctrl_pause);
        let cmds = handle_key(&mut m, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(cmds.iter().any(|c| matches!(c, Cmd::Lifecycle { action, filters, .. } if action == "Pause" && filters == &vec![vec![1]])));
    }

    #[test]
    fn confirmation_rejects_changed_targets_and_repeated_keys() {
        let mut m = operational_model(2);
        let mut ev = KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL);
        ev.kind = KeyEventKind::Repeat;
        assert!(handle_key(&mut m, ev).is_empty());
        assert!(m.operation_confirmation.is_none());
        ev.kind = KeyEventKind::Press;
        handle_key(&mut m, ev);
        m.allocations[0].filter_key = "changed".into();
        assert!(handle_key(&mut m, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)).is_empty());
        assert!(m.status_is_error && !m.action_in_flight);
    }

    #[test]
    fn control_shortcuts_do_not_leak_into_navigation_or_editors() {
        let mut m = operational_model(2);
        m.filter_edit_active = true;
        for c in ['g', 'l', 'y', 'r', 'p', 'u', 'o'] {
            assert!(handle_key(
                &mut m,
                KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
            )
            .is_empty());
        }
        assert!(m.filter_edit_input.is_empty() && m.operation_confirmation.is_none());
        m.filter_edit_active = false;
        handle_key(
            &mut m,
            KeyEvent::new(KeyCode::Char('h'), KeyModifiers::CONTROL),
        );
        assert!(!m.show_help);
        assert!(matches!(
            handle_key(
                &mut m,
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
            )
            .as_slice(),
            [Cmd::Quit]
        ));
    }

    #[test]
    fn global_age_tracks_fresh_advances_not_shard_cache_or_rpc_success() {
        let mut m = Model::new();
        let before = Instant::now() - Duration::from_secs(65);
        m.observe_global_head(10, before);
        m.observe_global_head(10, Instant::now());
        m.observe_global_head(9, Instant::now());
        assert_eq!(m.global_last_advance, Some(before));
        m.process_refresh_data(
            Some(NodeInfoResponse {
                last_received_frame: 10,
                ..Default::default()
            }),
            None,
            None,
        );
        assert_eq!(m.global_last_advance, Some(before));
        let now = Instant::now();
        m.observe_global_head(11, now);
        assert_eq!(m.global_last_advance, Some(now));
    }

    #[test]
    fn tab_cycles_three_panels_and_notifications_only_scroll() {
        let mut m = Model::new();
        m.notice_lines = 10;
        m.notice_visible = 3;
        let key = |c| KeyEvent::new(c, KeyModifiers::NONE);
        for focus in [PanelFocus::Available, PanelFocus::Notifications] {
            assert!(handle_key(&mut m, key(KeyCode::Tab)).is_empty());
            assert_eq!(m.focus, focus);
        }
        handle_key(&mut m, key(KeyCode::Down));
        assert_eq!(m.notice_offset, 1);
        handle_key(&mut m, key(KeyCode::Up));
        assert_eq!(m.notice_offset, 0);
        for c in [' ', 'a', 'J', 'l', 's', 'f'] {
            assert!(handle_key(&mut m, key(KeyCode::Char(c))).is_empty());
        }
        assert!(!m.sort_mode);
        assert!(!m.avail_filter_mode);
        assert!(!m.join_picker_active);
        assert!(m.avail_selected.is_empty());
        handle_key(&mut m, key(KeyCode::Tab));
        assert_eq!(m.focus, PanelFocus::Allocations);
        handle_key(&mut m, key(KeyCode::BackTab));
        assert_eq!(m.focus, PanelFocus::Notifications);
    }

    #[test]
    fn horizontal_navigation_is_bounded_and_notification_actions_stay_inert() {
        let mut m = Model::new();
        m.horizontal_limits = [12, 20];
        let key = |c| KeyEvent::new(c, KeyModifiers::NONE);
        handle_key(&mut m, key(KeyCode::Right));
        assert_eq!(m.horizontal_offsets, [8, 0]);
        handle_key(&mut m, key(KeyCode::Right));
        assert_eq!(m.horizontal_offsets, [12, 0]);
        handle_key(&mut m, key(KeyCode::Left));
        assert_eq!(m.horizontal_offsets, [4, 0]);
        m.focus = PanelFocus::Notifications;
        handle_key(&mut m, key(KeyCode::Right));
        assert_eq!(m.horizontal_offsets, [4, 0]);
    }

    #[test]
    fn boundary_keys_move_only_neighboring_panels_and_preserve_outer_edges() {
        let mut m = Model::new();
        m.panel_content_heights = [10, 10, 3];
        let key = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
        handle_key(&mut m, key('['));
        assert_eq!(m.panel_boundary_offsets, [0, 0]);
        handle_key(&mut m, key('}'));
        assert_eq!(m.panel_content_heights, [11, 9, 3]);
        assert_eq!(m.panel_boundary_offsets, [1, 0]);
        m.focus = PanelFocus::Available;
        handle_key(&mut m, key('['));
        assert_eq!(m.panel_content_heights, [10, 10, 3]);
        handle_key(&mut m, key('}'));
        assert_eq!(m.panel_content_heights, [10, 11, 2]);
        m.focus = PanelFocus::Notifications;
        handle_key(&mut m, key('}'));
        assert_eq!(m.panel_content_heights, [10, 11, 2]);
        handle_key(&mut m, key(']'));
        assert_eq!(m.panel_content_heights, [10, 12, 1]);
        handle_key(&mut m, key(']'));
        assert_eq!(m.panel_content_heights, [10, 12, 1]);
        assert_eq!(m.panel_content_heights.iter().sum::<u16>(), 23);
    }

    #[test]
    fn notification_controls_cycle_severity_and_bound_scrolling() {
        use super::super::model::NoticeSeverity;
        let mut m = Model::new();
        m.notice_lines = 10;
        m.notice_visible = 3;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        apply_msg(&mut m, Msg::ShardLoading);
        handle_key(&mut m, key(KeyCode::PageDown));
        assert_eq!(m.notice_offset, 3);
        handle_key(&mut m, key(KeyCode::End));
        assert_eq!(m.notice_offset, 7);
        handle_key(&mut m, key(KeyCode::PageDown));
        assert_eq!(m.notice_offset, 7);
        handle_key(&mut m, key(KeyCode::PageUp));
        assert_eq!(m.notice_offset, 4);
        handle_key(&mut m, key(KeyCode::Home));
        assert_eq!(m.notice_offset, 0);
        for minimum in [
            NoticeSeverity::Error,
            NoticeSeverity::Info,
            NoticeSeverity::Warning,
        ] {
            m.notice_offset = 7;
            handle_key(&mut m, key(KeyCode::Char('v')));
            assert_eq!(m.notice_minimum, minimum);
            assert_eq!(m.notice_offset, 0);
        }
    }

    #[test]
    fn shard_refresh_can_complete_before_node_status_and_survive_failures() {
        use quil_types::proto::node::{GetShardInfoResponse, ShardRewardInfo};
        let mut model = Model::new();
        let shards = GetShardInfoResponse {
            shards: vec![ShardRewardInfo {
                ring_known: Some(true),
                filter: vec![0xab],
                ..Default::default()
            }],
            ..Default::default()
        };
        apply_msg(&mut model, Msg::ShardLoading);
        assert!(model.shard_loading);
        apply_msg(&mut model, Msg::ShardRefresh(Ok(shards)));
        assert!(!model.shard_loading);
        apply_msg(
            &mut model,
            Msg::DataRefresh {
                node_info: Some(NodeInfoResponse {
                    last_received_frame: 720,
                    ..Default::default()
                }),
                shard_info: None,
                worker_info: None,
                err: None,
            },
        );
        assert_eq!(model.available.len(), 1);
        apply_msg(&mut model, Msg::ShardRefresh(Err("timed out".into())));
        assert_eq!(model.available.len(), 1, "retain usable cached rows");
        assert_eq!(model.shard_error.as_deref(), Some("timed out"));
        apply_msg(
            &mut model,
            Msg::DataRefresh {
                node_info: Some(NodeInfoResponse {
                    last_received_frame: 721,
                    ..Default::default()
                }),
                shard_info: None,
                worker_info: None,
                err: None,
            },
        );
        assert_eq!(model.last_received_frame, 721);
        assert_eq!(model.shard_error.as_deref(), Some("timed out"));
        apply_msg(
            &mut model,
            Msg::ShardRefresh(Ok(GetShardInfoResponse::default())),
        );
        assert!(model.shard_error.is_none());
        assert!(model.available.is_empty());
    }

    #[test]
    fn confirm_key_uses_the_same_epoch_window_as_the_hint() {
        // Proposals need not be at the start of an epoch. Test mainnet,
        // shorter testnet epochs, and the RPC's zero-length fallback.
        for epoch_length in [720, 60, 0] {
            let el = epoch_len(epoch_length);
            for status in [1, 4] {
                for (frame, expected) in [
                    (el + el / 2, false),
                    (2 * el, true),
                    (3 * el - 1, true),
                    (3 * el, false),
                ] {
                    let filter = vec![0xab];
                    let mut alloc = ShardAllocationInfo {
                        filter: filter.clone(),
                        status,
                        epoch: frame / el,
                        ..Default::default()
                    };
                    if status == 1 {
                        alloc.join_frame_number = el + el / 4;
                    } else {
                        alloc.leave_frame_number = el + el / 4;
                    }
                    let mut model = Model::new();
                    model.process_refresh_data(
                        Some(NodeInfoResponse {
                            shard_allocations: vec![alloc],
                            current_epoch: frame / el,
                            epoch_length_frames: epoch_length,
                            last_received_frame: frame,
                            ..Default::default()
                        }),
                        None,
                        None,
                    );
                    // ShardInfo may lag; lifecycle decisions use NodeInfo's frame.
                    assert_eq!(model.frame_number, 0);
                    if expected {
                        assert_eq!(model.allocations[0].next_action.label, "(reject|confirm)");
                        assert_eq!(model.allocations[0].next_action.at_frame, None);
                    }
                    for row in &mut model.allocations {
                        row.manually_managed = true;
                    }
                    // Ctrl+Y alone only asks; Enter sends.
                    let cmds = handle_key(
                        &mut model,
                        KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL),
                    );
                    assert!(cmds.is_empty(), "Ctrl+Y sent before Enter");
                    assert_eq!(model.operation_confirmation.is_some(), expected);
                    if expected {
                        assert_eq!(
                            model.status_msg,
                            "Confirm for 1 allocation(s): ab? Enter confirms; Esc cancels."
                        );
                    }
                    let cmds = handle_key(
                        &mut model,
                        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                    );
                    let sent = cmds.iter().any(|cmd| matches!(cmd,
                        Cmd::Lifecycle { action, filters, .. } if action == "Confirm" && filters == &vec![filter.clone()]
                    ));
                    assert_eq!(
                        sent, expected,
                        "epoch length {epoch_length}, status {status}, frame {frame}"
                    );
                    if frame < 2 * el {
                        assert!(model.status_msg.contains(&format!("opens at: {}", 2 * el)));
                    }
                }
            }
        }
    }
    #[test]
    fn nested_intervals_have_independent_masks_and_preserve_parent_visibility() {
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        for focus in [PanelFocus::Allocations, PanelFocus::Available] {
            let mut m = Model::new();
            m.focus = focus;
            m.column_picker_active = true;
            let interval = if focus.is_alloc() { 16 } else { 11 };
            let parent = m
                .display_columns()
                .iter()
                .position(|&col| col == interval)
                .unwrap();
            m.column_picker_cursor = parent + 1;
            handle_key(&mut m, key(KeyCode::Char(' ')));
            assert_eq!(m.interval_mask(), 2);
            m.column_picker_cursor += 1;
            handle_key(&mut m, key(KeyCode::Char(' ')));
            assert_eq!(m.interval_mask(), 2);
            assert_eq!(m.global_interval_mask(), 3);
            assert!(m.column_visible(interval));
            m.column_picker_cursor = parent;
            handle_key(&mut m, key(KeyCode::Char(' ')));
            assert!(!m.column_visible(interval));
            assert_eq!(m.interval_mask(), 2);
            handle_key(&mut m, key(KeyCode::Tab));
            assert_eq!(m.visibility_section, 1);
            // Top header rows: Global 3, its fields 4-6, Global interval 7, its windows 8-9.
            m.column_picker_cursor = 9;
            handle_key(&mut m, key(KeyCode::Char(' ')));
            assert_eq!(m.global_interval_mask(), 1);
            m.column_picker_cursor = 8;
            handle_key(&mut m, key(KeyCode::Char(' ')));
            assert_eq!(m.global_interval_mask(), 1);
            assert_eq!(m.interval_mask(), 2);
            assert!(m.header_kpi_visible("Global interval"));
            m.column_picker_cursor = 7;
            handle_key(&mut m, key(KeyCode::Char(' ')));
            assert!(!m.header_kpi_visible("Global interval"));
            m.column_picker_cursor = 5;
            handle_key(&mut m, key(KeyCode::Char(' ')));
            assert_eq!(m.global_field_mask(), 5);
            assert_eq!(m.global_interval_mask(), 1);
            assert!(m.header_kpi_visible("Global"));
            handle_key(&mut m, key(KeyCode::Char('a')));
            assert_eq!(m.global_interval_mask(), 3);
            assert!(m.header_kpi_visible("Global interval"));
            assert_eq!(m.global_field_mask(), 7);
            assert_eq!(m.interval_mask(), 2);
            assert_eq!(m.reward_mask(), 7);
            handle_key(&mut m, key(KeyCode::BackTab));
            handle_key(&mut m, key(KeyCode::Char('a')));
            assert_eq!(m.interval_mask(), 3);
        }
    }
    /// The Global KPI's frame/epoch/next fields nest beneath it in the Top
    /// header group; the last field cannot be deselected, and the KPI itself
    /// still hides as a whole.
    #[test]
    fn global_fields_toggle_in_the_top_header_picker() {
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let mut m = Model::new();
        m.column_picker_active = true;
        handle_key(&mut m, key(KeyCode::Tab));
        assert_eq!(m.visibility_section, 1);
        let names = m.visibility_names();
        assert_eq!(
            &names[3..10],
            &[
                "Global",
                "  frame",
                "  epoch",
                "  next boundary",
                "Global interval",
                "  60m window",
                "  24h window"
            ]
        );
        assert_eq!(
            (4..7)
                .map(|i| m.visibility_global_field(1, i))
                .collect::<Vec<_>>(),
            vec![Some(0), Some(1), Some(2)]
        );
        assert_eq!(m.visibility_global_field(1, 3), None);
        assert_eq!(m.visibility_global_field(1, 7), None);
        assert_eq!(m.visibility_global_field(0, 4), None);
        assert_eq!(m.visibility_interval_window(1, 8), Some((true, 0)));
        assert_eq!(m.visibility_interval_window(1, 6), None);
        assert_eq!(m.global_field_mask(), 7);
        for (cursor, mask) in [(4, 6), (6, 2)] {
            m.column_picker_cursor = cursor;
            handle_key(&mut m, key(KeyCode::Char(' ')));
            assert_eq!(m.global_field_mask(), mask);
            assert!(!m.visibility_item_visible_in(1, cursor));
        }
        m.column_picker_cursor = 5;
        handle_key(&mut m, key(KeyCode::Char(' ')));
        assert_eq!(m.global_field_mask(), 2, "one field stays");
        assert!(m.visibility_item_visible_in(1, 5));
        m.column_picker_cursor = 3;
        handle_key(&mut m, key(KeyCode::Char(' ')));
        assert!(!m.header_kpi_visible("Global"));
        assert_eq!(m.global_field_mask(), 2);
        assert_eq!(m.global_interval_mask(), 3);
        handle_key(&mut m, key(KeyCode::Char('a')));
        assert!(m.header_kpi_visible("Global"));
        assert_eq!(m.global_field_mask(), 7);
    }

    /// ‹e› switches thresholds between relative and absolute and leaves the
    /// Global KPI alone.
    #[test]
    fn e_toggles_thresholds_between_relative_and_absolute() {
        use super::super::super::epoch::ThresholdUnit;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let mut m = Model::new();
        assert_eq!(m.threshold_unit, ThresholdUnit::Relative);
        assert!(handle_key(&mut m, key(KeyCode::Char('e'))).is_empty());
        assert_eq!(m.threshold_unit, ThresholdUnit::Absolute);
        assert!(handle_key(&mut m, key(KeyCode::Char('e'))).is_empty());
        assert_eq!(m.threshold_unit, ThresholdUnit::Relative);
        assert_eq!(m.global_field_mask(), 7);
    }

    #[test]
    fn shifted_arrows_move_columns_with_children_and_preserve_identity_and_other_panel() {
        use super::super::model::{ALLOC_DISPLAY_COLS, AVAIL_DISPLAY_COLS};
        let mut m = Model::new();
        m.column_picker_active = true;
        let shifted = |code| KeyEvent::new(code, KeyModifiers::SHIFT);
        m.column_picker_cursor = 11;
        handle_key(&mut m, shifted(KeyCode::Down));
        assert_eq!(m.alloc_display_columns()[11], 16);
        assert_eq!(m.column_picker_cursor, 12);
        assert_eq!(m.visibility_interval_window(0, 12), Some((false, 0)));
        assert_eq!(m.avail_display_columns(), AVAIL_DISPLAY_COLS);
        m.column_picker_cursor = 13;
        handle_key(
            &mut m,
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        );
        assert_eq!(m.interval_mask(), 1);
        m.column_picker_cursor = 0;
        handle_key(&mut m, shifted(KeyCode::Down));
        assert_eq!(&m.alloc_display_columns()[..2], &[0, 1]);
        m.column_picker_cursor = 2;
        handle_key(&mut m, shifted(KeyCode::Up));
        assert_eq!(&m.alloc_display_columns()[..2], &[0, 1]);
        handle_key(
            &mut m,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
        );
        assert_eq!(m.alloc_display_columns(), ALLOC_DISPLAY_COLS);
        assert_eq!(m.interval_mask(), 1);
        m.focus = PanelFocus::Available;
        m.column_picker_cursor = 10;
        handle_key(&mut m, shifted(KeyCode::Up));
        assert_eq!(m.avail_display_columns()[9], 11);
        assert_eq!(m.alloc_display_columns(), ALLOC_DISPLAY_COLS);
        assert_eq!(m.active_visible_columns()[8], 11);
        m.focus = PanelFocus::Notifications;
        m.column_picker_cursor = 2;
        m.horizontal_offsets = [1, 12];
        handle_key(&mut m, shifted(KeyCode::Down));
        assert_eq!(m.horizontal_offsets, [1, 0]);
    }
    #[test]
    fn reward_visibility_selects_any_nonempty_subset_for_both_panels() {
        let mut m = Model::new();
        m.column_picker_active = true;
        m.visibility_section = 2;
        m.column_picker_cursor = 6;
        let space = KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE);
        handle_key(&mut m, space);
        assert_eq!(m.reward_mask(), 3);
        m.column_picker_cursor = 4;
        handle_key(&mut m, space);
        assert_eq!(m.reward_mask(), 2);
        m.column_picker_cursor = 5;
        handle_key(&mut m, space);
        assert_eq!(m.reward_mask(), 2);
        handle_key(
            &mut m,
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
        );
        assert_eq!(m.reward_mask(), 7);
    }

    #[test]
    fn reward_children_follow_reordered_columns_and_share_the_header_selection() {
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let mut m = Model::new();
        m.column_picker_active = true;
        for focus in [PanelFocus::Allocations, PanelFocus::Available] {
            m.focus = focus;
            m.visibility_section = 0;
            m.reward_windows = 7;
            m.column_picker_cursor = m
                .visibility_names()
                .iter()
                .position(|&name| name == "Reward [~Q/d]")
                .unwrap()
                + 1;
            handle_key(&mut m, KeyEvent::new(KeyCode::Up, KeyModifiers::SHIFT));
            assert_eq!(
                m.visibility_reward_window(0, m.column_picker_cursor),
                Some(0)
            );
            handle_key(&mut m, key(KeyCode::Char(' ')));
            assert_eq!(m.reward_mask(), 6);
            m.visibility_section = 2;
            assert!(!m.visibility_item_visible_in(2, 4));
            m.column_picker_cursor = 6;
            handle_key(&mut m, key(KeyCode::Char(' ')));
            assert_eq!(m.reward_mask(), 2);
            m.column_picker_cursor = 3;
            handle_key(&mut m, key(KeyCode::Char(' ')));
            assert!(!m.header_kpi_visible("Reward"));
            assert!(m.column_visible(10));
            assert_eq!(m.reward_mask(), 2);
            handle_key(&mut m, key(KeyCode::Char('a')));
            assert_eq!(m.reward_mask(), 7);
        }
        m.focus = PanelFocus::Notifications;
        assert_eq!(m.visibility_names_for(2)[0], "Workers");
        assert_eq!(m.visibility_names_for(3)[0], "Available count");
        m.visibility_section = 4;
        m.column_picker_cursor = 0;
        handle_key(&mut m, key(KeyCode::Char(' ')));
        assert!(!m.header_kpi_visible("Notification level"));
        assert!(m.header_kpi_visible("Notification position"));
    }
}
