//! Rendering for the `prover manage` TUI. Port of the bubbletea `View`
//! and its panel/help/join-picker renderers, expressed with ratatui.

use num_bigint::BigInt;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

use super::super::{format_quil_daily, format_quil_reward};
use super::model::*;
use super::util::{center_trunc, clamp_offset};

// ── Colors (mirror lipgloss constants) ───────────────────────────────────

const PRIMARY: Color = Color::Rgb(0xff, 0x00, 0x70);
const DIM: Color = Color::Rgb(0x55, 0x55, 0x55);
const TEXT: Color = Color::Rgb(0xff, 0xff, 0xff);
const SUCCESS: Color = Color::Rgb(0x00, 0xff, 0x00);
const ERROR: Color = Color::Rgb(0xff, 0x00, 0x00);
const HELP: Color = Color::Rgb(0x88, 0x88, 0x88);
const FILTER: Color = Color::Rgb(0xff, 0xaa, 0x00);

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn ring_color(ring: u32) -> Color {
    match ring {
        0 => Color::Rgb(0x00, 0xff, 0x00),
        1 => Color::Rgb(0x88, 0xff, 0x00),
        2 => Color::Rgb(0xff, 0xff, 0x00),
        3 => Color::Rgb(0xff, 0x88, 0x00),
        _ => Color::Rgb(0xff, 0x00, 0x00),
    }
}

fn status_color(name: &str) -> Color {
    match name.to_lowercase().as_str() {
        "active" => Color::Rgb(0x00, 0xff, 0x00),
        "joining" => Color::Rgb(0x88, 0xff, 0x88),
        "leaving" => Color::Rgb(0xff, 0x88, 0x00),
        _ => Color::Rgb(0xff, 0x44, 0x44),
    }
}
fn materialization_state_color(state: &str) -> Color {
    match state { "Current" => SUCCESS, "Lag" | "Unmat" => ERROR, _ => HELP }
}

fn mode_color(mode: &str) -> Color {
    if mode == "m" {
        Color::Rgb(0xff, 0x88, 0x00)
    } else {
        Color::Rgb(0x00, 0xff, 0x00)
    }
}

fn spinner(m: &Model) -> &'static str {
    SPINNER[m.spinner_frame % SPINNER.len()]
}

/// `~` + QUIL reward (8dp), for the reward cell.
fn fmt_reward(v: &BigInt) -> String {
    format!("~{}", format_quil_reward(v))
}

fn fmt_mb(v: &BigInt) -> String {
    super::super::format_mb(v)
}

/// A column header as printed: sort indicator, name, active-filter marker.
/// Sizing and rendering share it, so a column is never measured against a
/// different string than it draws.
///
/// `compact` underscores the spaces inside a name. Measured columns sit one
/// space apart, which leaves `Next Action Default Action` with no way to see
/// where one header ends; `Next_Action Default_Action` reads unambiguously.
/// The fixed layout has slack between columns and keeps the spaces.
fn header_text(
    name: &str,
    idx: usize,
    sort_col: i32,
    asc: bool,
    filtered: bool,
    compact: bool,
) -> String {
    let mut s = if compact {
        name.replace(' ', "_")
    } else {
        name.to_string()
    };
    if filtered {
        s.push('*');
    }
    if sort_col == idx as i32 {
        s.insert_str(0, if asc { "^|" } else { "v|" });
    }
    s
}

/// Width a `ColumnSizing::Fixed` column needs: its constant, which doubles as
/// the minimum, widened to the longest cell. `{:>w$}` doesn't clip, so a cell
/// wider than its column shifts every column after it to the right; columns
/// whose content has no fixed upper bound have to be measured even here.
fn fit(base: usize, cells: impl Iterator<Item = usize>) -> usize {
    cells.max().unwrap_or(0).max(base)
}

/// Width of one column: its printed header, widened to its widest cell.
///
/// Every column is measured, in both directions. `{:>w$}` doesn't clip, so a
/// cell wider than its column shifts every column after it out of alignment;
/// a column wider than its content spends the difference on blanks and pushes
/// the columns to its right off the pane. Measuring is the fix for both.
fn col_width(header: &str, cells: impl Iterator<Item = usize>) -> usize {
    cells.max().unwrap_or(0).max(header.len())
}

/// A column header as printed: sort indicator, name, active-filter marker.
/// Sizing and rendering share it, so a column is never measured against a
/// different string than it draws.
///
/// `compact` underscores the spaces inside a name. Measured columns sit one
/// space apart, which leaves `Next Action Default Action` with no way to see
/// where one header ends; `Next_Action Default_Action` reads unambiguously.
/// The fixed layout has slack between columns and keeps the spaces.
fn header_text(
    name: &str,
    idx: usize,
    sort_col: i32,
    asc: bool,
    filtered: bool,
    compact: bool,
) -> String {
    let mut s = if compact {
        name.replace(' ', "_")
    } else {
        name.to_string()
    };
    if filtered {
        s.push('*');
    }
    if sort_col == idx as i32 {
        s.insert_str(0, if asc { "^|" } else { "v|" });
    }
    s
}

/// Width a `ColumnSizing::Fixed` column needs: its constant, which doubles as
/// the minimum, widened to the longest cell. `{:>w$}` doesn't clip, so a cell
/// wider than its column shifts every column after it to the right; columns
/// whose content has no fixed upper bound have to be measured even here.
fn fit(base: usize, cells: impl Iterator<Item = usize>) -> usize {
    cells.max().unwrap_or(0).max(base)
}

/// Width of one column: its printed header, widened to its widest cell.
///
/// Every column is measured, in both directions. `{:>w$}` doesn't clip, so a
/// cell wider than its column shifts every column after it out of alignment;
/// a column wider than its content spends the difference on blanks and pushes
/// the columns to its right off the pane. Measuring is the fix for both.
fn col_width(header: &str, cells: impl Iterator<Item = usize>) -> usize {
    cells.max().unwrap_or(0).max(header.len())
}

// ── Entry ────────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, m: &mut Model) {
    let area = f.area();
    m.width = area.width;
    m.height = area.height;

    if area.width < 40 || area.height < 10 {
        let p = Paragraph::new("Terminal too small. Please resize.");
        f.render_widget(p, area);
        return;
    }
    if m.join_picker_active {
        render_join_picker(f, m, area);
        return;
    }
    if m.show_help {
        render_help_screen(f, m, area);
        return;
    }
    render_main(f, m, area);
}

fn render_main(f: &mut Frame, m: &mut Model, area: Rect) {
    // Vertical budget split (mirrors the Go layout math).
    let panel_budget = (area.height as i32 - 10).max(4) as u16;
    let alloc_h = panel_budget / 2;
    let avail_h = panel_budget - alloc_h;

    let chunks = Layout::vertical([
        Constraint::Length(1),           // header
        Constraint::Length(1),           // alloc title
        Constraint::Length(alloc_h + 2), // alloc panel (+ border)
        Constraint::Length(1),           // avail title
        Constraint::Length(avail_h + 2), // avail panel (+ border)
        Constraint::Length(1),           // actions
        Constraint::Length(1),           // status
    ])
    .split(area);

    // Header.
    f.render_widget(
        Paragraph::new(header_line(m)).style(Style::new().fg(TEXT).bg(PRIMARY)),
        chunks[0],
    );

    // Allocations title + panel.
    let sorted_allocs = m.sorted_allocations();
    f.render_widget(
        Paragraph::new(alloc_title(m, &sorted_allocs))
            .style(Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD)),
        chunks[1],
    );
    let alloc_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if m.focus.is_alloc() { PRIMARY } else { DIM }));
    let alloc_inner = alloc_block.inner(chunks[2]);
    f.render_widget(alloc_block, chunks[2]);
    let alloc_lines = render_alloc_panel(m, &sorted_allocs, alloc_inner);
    f.render_widget(Paragraph::new(alloc_lines), alloc_inner);

    // Available title + panel.
    let sorted_avail = m.sorted_available();
    f.render_widget(
        Paragraph::new(avail_title(m, &sorted_avail))
            .style(Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD)),
        chunks[3],
    );
    let avail_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if !m.focus.is_alloc() { PRIMARY } else { DIM }));
    let avail_inner = avail_block.inner(chunks[4]);
    f.render_widget(avail_block, chunks[4]);
    let avail_lines = render_avail_panel(m, &sorted_avail, avail_inner);
    f.render_widget(Paragraph::new(avail_lines), avail_inner);

    // Actions + status lines.
    let (actions, status) = footer_lines(m);
    f.render_widget(Paragraph::new(actions).style(Style::new().fg(HELP)), chunks[5]);
    f.render_widget(Paragraph::new(status).style(Style::new().fg(HELP)), chunks[6]);
}

// ── Header ───────────────────────────────────────────────────────────────

fn header_line(m: &Model) -> Line<'static> {
    if !m.data_loaded {
        return Line::from(format!(" {} Connecting to node…", spinner(m)));
    }
    let reach = if m.reachable { "OK" } else { "UNREACHABLE" };
    let worker_mode = if m.auto_managed { "Auto" } else { "Manual" };
    let mut s = format!(
        " Peer ID: {}  Seniority: {}  Workers: {}/{} ({})  Frame: {}  Epoch: {}  [{}]",
        m.peer_id,
        m.seniority,
        m.allocated_workers,
        m.running_workers,
        worker_mode,
        m.frame_number,
        super::super::epoch::epoch_for_frame(m.frame_number, m.epoch_length),
        reach,
    );
    if m.consecutive_failures > 0 {
        if let Some(t) = m.last_fetch_success {
            s += &format!(
                "  (stale: last update {}s ago, {} retries failed)",
                t.elapsed().as_secs(),
                m.consecutive_failures
            );
        }
    }
    Line::from(s)
}

fn alloc_title(m: &Model, sorted: &[AllocationRow]) -> Line<'static> {
    let mut joining = BigInt::from(0);
    let mut active = BigInt::from(0);
    let mut paused = BigInt::from(0);
    let mut leaving = BigInt::from(0);
    for a in sorted {
        match a.status {
            1 => joining += &a.estimated_reward,
            2 => active += &a.estimated_reward,
            3 => paused += &a.estimated_reward,
            4 => leaving += &a.estimated_reward,
            _ => {}
        }
    }
    let total = &joining + &active + &paused + &leaving;
    let mut s = format!(
        "Allocations ({}) Rewards: Total ~{} QUIL/day = Joining ~{} QUIL/day + Active ~{} QUIL/day + Paused ~{} QUIL/day + Leaving ~{} QUIL/day",
        sorted.len(),
        format_quil_daily(&total),
        format_quil_daily(&joining),
        format_quil_daily(&active),
        format_quil_daily(&paused),
        format_quil_daily(&leaving),
    );
    if !m.alloc_selected.is_empty() {
        s += &format!(" [{} selected]", m.alloc_selected.len());
    }
    Line::from(s)
}

fn avail_title(m: &Model, sorted: &[ShardRow]) -> Line<'static> {
    let mut s = format!(" Available Shards ({})", sorted.len());
    if !m.avail_selected.is_empty() {
        s += &format!(" [{} selected]", m.avail_selected.len());
    }
    Line::from(s)
}

// ── Allocations panel ────────────────────────────────────────────────────

/// The printed text of one allocations cell. Sizing and rendering both go
/// through here. `fw` is the Filter column's width, which is a budget rather
/// than a measurement — pass 0 when measuring the other columns.
fn alloc_cell(m: &Model, a: &AllocationRow, col: usize, fw: usize) -> String {
    match col {
        0 => alloc_marker(m, a).to_string(),
        1 => center_trunc(&a.filter_hex, fw),
        2 => a.active_provers.to_string(),
        3 => a.ring.to_string(),
        4 => fmt_mb(&a.shard_size),
        5 => a.data_shards.to_string(),
        6 => a.materialized_frame.to_string(),
        7 => materialization_lag(a.materialized_frame, a.latest_frame).map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
        8 => materialization_state(a.materialized_frame, a.latest_frame).to_string(),
        9 => fmt_reward(&a.estimated_reward),
        10 => a.worker_id.to_string(),
        11 => a.status_name.clone(),
        12 => a.mode().to_string(),
        13 => a.next_action.clone(),
        _ => a.default_action.clone(),
    }
}

fn alloc_marker(m: &Model, a: &AllocationRow) -> &'static str {
    if m.alloc_selected.contains(&a.filter_key) {
        "[x]"
    } else {
        "[ ]"
    }
}

fn alloc_header(m: &Model, idx: usize) -> String {
    header_text(
        ALLOC_COL_NAMES[idx],
        idx,
        m.alloc_sort_col,
        m.alloc_sort_asc,
        m.alloc_col_filters
            .get(&idx)
            .is_some_and(|cf| cf.is_active()),
        m.column_sizing == ColumnSizing::Dynamic,
    )
}

fn alloc_col_widths(
    m: &Model,
    content_width: usize,
    sorted: &[AllocationRow],
) -> (Vec<usize>, usize) {
    match m.column_sizing {
        ColumnSizing::Dynamic => alloc_widths_measured(m, content_width, sorted),
        ColumnSizing::Fixed => alloc_widths_fixed(m, content_width, sorted),
    }
}

/// Every column takes its header or its widest cell, whichever is longer, one
/// space apart — nothing reserves room for a value it isn't showing.
/// Remeasured each frame, so the layout tracks the data.
///
/// Filter is sized last, from whatever the pane has left: it is the only
/// column already truncated for display, so it is both the one that can grow
/// usefully and the one that can give way without losing a value outright.
fn alloc_widths_measured(
    m: &Model,
    content_width: usize,
    sorted: &[AllocationRow],
) -> (Vec<usize>, usize) {
    let n = ALLOC_COL_NAMES.len();
    let mut widths: Vec<usize> = (0..n)
        .map(|c| {
            col_width(
                &alloc_header(m, c),
                sorted.iter().map(|a| alloc_cell(m, a, c, 0).len()),
            )
        })
        .collect();

    let cap = filter_cap(
        &alloc_header(m, 1),
        sorted.iter().map(|a| a.filter_hex.len()),
    );
    let fw = filter_width(content_width, &widths, n, cap);
    widths[1] = fw;
    (widths, fw)
}

/// The historical layout: a constant per column, with Shards and Reward grown
/// to their content so an over-wide cell can't shift the row.
fn alloc_widths_fixed(
    m: &Model,
    content_width: usize,
    sorted: &[AllocationRow],
) -> (Vec<usize>, usize) {
    let shards_w = fit(
        SHARDS_WIDTH,
        sorted.iter().map(|a| alloc_cell(m, a, 5, 0).len()),
    );
    let reward_w = fit(
        ALLOC_REWARD_WIDTH,
        sorted.iter().map(|a| alloc_cell(m, a, 6, 0).len()),
    );
    // Whatever the wide columns took comes out of the flexible Filter column.
    let grown = (shards_w - SHARDS_WIDTH) + (reward_w - ALLOC_REWARD_WIDTH);
    let mut fw = content_width.saturating_sub(ALLOC_FIXED_WIDTH + grown);
    for &col in &ALLOC_FILTERABLE_COLS {
        if col == 1 {
            continue;
        }
        if m.alloc_col_filters.get(&col).is_some_and(|cf| cf.is_active()) {
            fw = fw.saturating_sub(1);
        }
    }
    fw = fw.clamp(MIN_FILTER_WIDTH, FILTER_WIDTH);

    let mut widths = vec![
        SELECT_WIDTH,
        fw,
        PROVERS_WIDTH,
        RING_WIDTH,
        SIZE_WIDTH,
        shards_w, MAT_WIDTH, LAG_WIDTH, STATE_WIDTH, reward_w,
        WORKER_WIDTH,
        STATUS_WIDTH,
        MODE_WIDTH,
        NEXT_ACTION_WIDTH,
        DEFAULT_ACTION_WIDTH,
    ];
    for &col in &ALLOC_FILTERABLE_COLS {
        if col == 1 {
            continue;
        }
        if m.alloc_col_filters.get(&col).is_some_and(|cf| cf.is_active()) {
            widths[col] += 1;
        }
    }
    if m.alloc_sort_col >= 0 && (m.alloc_sort_col as usize) < widths.len() {
        widths[m.alloc_sort_col as usize] += 2;
    }
    (widths, fw)
}

/// How wide the Filter column can usefully get: the longest hex in the table,
/// past which the extra columns would be padding. Its header is the floor, so
/// the column is legible even when every row's filter is empty.
fn filter_cap(header: &str, hexes: impl Iterator<Item = usize>) -> usize {
    col_width(header, hexes).max(MIN_FILTER_WIDTH)
}

/// Filter takes what the pane has left after the other columns, the `n - 1`
/// separators and the 2 borders, bounded by `cap` and `MIN_FILTER_WIDTH`.
/// Below the floor the row is clipped rather than shrunk further — 12 columns
/// is the least that leaves a recognisable hex.
fn filter_width(content_width: usize, widths: &[usize], n: usize, cap: usize) -> usize {
    let others: usize = widths
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, w)| *w)
        .sum();
    content_width
        .saturating_sub(others + (n - 1) + 2)
        .clamp(MIN_FILTER_WIDTH, cap)
}

fn render_alloc_panel(m: &mut Model, sorted: &[AllocationRow], area: Rect) -> Vec<Line<'static>> {
    let content_width = area.width as usize;
    let height = area.height as usize;
    if sorted.is_empty() {
        if !m.data_loaded {
            return vec![Line::from(format!("  {} Loading allocations…", spinner(m)))];
        }
        return vec![Line::from("  No allocations")];
    }
    let (widths, fw) = alloc_col_widths(m, content_width, sorted);
    let filter_hi = m.active_filter_col_idx();

    // Header row.
    let mut hdr_spans: Vec<Span> = Vec::new();
    for i in 0..ALLOC_COL_NAMES.len() {
        let cell = format!("{:>w$}", alloc_header(m, i), w = widths[i]);
        let style = if m.sort_mode && m.focus.is_alloc() && m.sort_highlight_col == i {
            Style::new().bg(PRIMARY).fg(TEXT).add_modifier(Modifier::BOLD)
        } else if m.alloc_filter_mode
            && !m.filter_edit_active
            && m.focus.is_alloc()
            && filter_hi == i as i32
        {
            Style::new().bg(FILTER).fg(TEXT).add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::BOLD)
        };
        if i > 0 {
            hdr_spans.push(Span::raw(" "));
        }
        hdr_spans.push(Span::styled(cell, style));
    }
    let mut lines = vec![Line::from(hdr_spans)];

    let visible = height.saturating_sub(1).max(1);
    m.alloc_offset = clamp_offset(m.alloc_offset, m.alloc_cursor, visible, sorted.len());
    let end = (m.alloc_offset + visible).min(sorted.len());

    for i in m.alloc_offset..end {
        let a = &sorted[i];
        let selected = i == m.alloc_cursor && m.focus.is_alloc();

        let cells: Vec<String> = (0..widths.len())
            .map(|c| format!("{:>w$}", alloc_cell(m, a, c, fw), w = widths[c]))
            .collect();

        if selected {
            let joined = cells.join(" ");
            let padded = format!("{:<width$}", joined, width = content_width);
            lines.push(Line::from(Span::styled(
                padded,
                Style::new().fg(TEXT).bg(PRIMARY),
            )));
        } else {
            let mut spans: Vec<Span> = Vec::new();
            for (ci, cell) in cells.iter().enumerate() {
                if ci > 0 {
                    spans.push(Span::raw(" "));
                }
                let span = match ci {
                    3 if m.color_coding => Span::styled(cell.clone(), Style::new().fg(ring_color(a.ring))),
                    8 if m.color_coding => Span::styled(cell.clone(), Style::new().fg(materialization_state_color(materialization_state(a.materialized_frame, a.latest_frame)))),
                    11 if m.color_coding => {
                        Span::styled(cell.clone(), Style::new().fg(status_color(&a.status_name)))
                    }
                    12 if m.color_coding => {
                        Span::styled(cell.clone(), Style::new().fg(mode_color(a.mode())))
                    }
                    _ => Span::raw(cell.clone()),
                };
                spans.push(span);
            }
            lines.push(Line::from(spans));
        }
    }
    lines
}

// ── Available panel ──────────────────────────────────────────────────────

/// The printed text of one available-shards cell.
///
/// Every row prints the same way. The cursor row used to render size and
/// reward differently from the rest — megabytes against an adaptive unit, a
/// bare reward against one suffixed ` Q/f` — so moving the cursor changed the
/// value under it, and the unsuffixed variants disagreed with the `Size [MB]`
/// and `Reward [Q/f]` headers that were already stating those units. One
/// rendering per cell settles both, and drops the widest reward cell from 15
/// columns to 12.
fn avail_cell(m: &Model, s: &ShardRow, col: usize, fw: usize) -> String {
    match col {
        0 => avail_marker(m, s).to_string(),
        1 => center_trunc(&s.filter_hex, fw),
        2 => s.active_provers.to_string(),
        3 => s.ring.to_string(),
        4 => fmt_mb(&s.shard_size),
        5 => s.data_shards.to_string(),
        6 => s.materialized_frame.to_string(),
        7 => materialization_lag(s.materialized_frame, s.latest_frame).map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
        8 => materialization_state(s.materialized_frame, s.latest_frame).to_string(),
        _ => fmt_reward(&s.estimated_reward),
    }
}

fn avail_marker(m: &Model, s: &ShardRow) -> &'static str {
    if m.avail_selected.contains(&s.filter_key) {
        "[x]"
    } else {
        "[ ]"
    }
}

fn avail_header(m: &Model, idx: usize) -> String {
    header_text(
        AVAIL_COL_NAMES[idx],
        idx,
        m.avail_sort_col,
        m.avail_sort_asc,
        m.avail_col_filters
            .get(&idx)
            .is_some_and(|cf| cf.is_active()),
        m.column_sizing == ColumnSizing::Dynamic,
    )
}

fn avail_col_widths(m: &Model, content_width: usize, sorted: &[ShardRow]) -> (Vec<usize>, usize) {
    match m.column_sizing {
        ColumnSizing::Dynamic => avail_widths_measured(m, content_width, sorted),
        ColumnSizing::Fixed => avail_widths_fixed(m, content_width, sorted),
    }
}

/// Same rule as the allocations panel.
fn avail_widths_measured(
    m: &Model,
    content_width: usize,
    sorted: &[ShardRow],
) -> (Vec<usize>, usize) {
    let n = AVAIL_COL_NAMES.len();
    let mut widths: Vec<usize> = (0..n)
        .map(|c| {
            col_width(
                &avail_header(m, c),
                sorted.iter().map(|s| avail_cell(m, s, c, 0).len()),
            )
        })
        .collect();

    let cap = filter_cap(
        &avail_header(m, 1),
        sorted.iter().map(|s| s.filter_hex.len()),
    );
    let fw = filter_width(content_width, &widths, n, cap);
    widths[1] = fw;
    (widths, fw)
}

fn avail_widths_fixed(m: &Model, content_width: usize, sorted: &[ShardRow]) -> (Vec<usize>, usize) {
    let shards_w = fit(
        SHARDS_WIDTH,
        sorted.iter().map(|s| avail_cell(m, s, 5, 0).len()),
    );
    let reward_w = fit(
        REWARD_WIDTH,
        sorted.iter().map(|s| avail_cell(m, s, 9, 0).len()),
    );
    let grown = (shards_w - SHARDS_WIDTH) + (reward_w - REWARD_WIDTH);
    let mut fw = content_width.saturating_sub(AVAIL_FIXED_WIDTH + grown);
    for &col in &AVAIL_FILTERABLE_COLS {
        if col == 1 {
            continue;
        }
        if m.avail_col_filters.get(&col).is_some_and(|cf| cf.is_active()) {
            fw = fw.saturating_sub(1);
        }
    }
    fw = fw.clamp(MIN_FILTER_WIDTH, FILTER_WIDTH);

    let mut widths = vec![
        SELECT_WIDTH,
        fw,
        PROVERS_WIDTH,
        RING_WIDTH,
        SIZE_WIDTH,
        shards_w, MAT_WIDTH, LAG_WIDTH, STATE_WIDTH, reward_w,
    ];
    for &col in &AVAIL_FILTERABLE_COLS {
        if col == 1 {
            continue;
        }
        if m.avail_col_filters.get(&col).is_some_and(|cf| cf.is_active()) {
            widths[col] += 1;
        }
    }
    if m.avail_sort_col >= 0 && (m.avail_sort_col as usize) < widths.len() {
        widths[m.avail_sort_col as usize] += 2;
    }
    (widths, fw)
}

fn render_avail_panel(m: &mut Model, sorted: &[ShardRow], area: Rect) -> Vec<Line<'static>> {
    let content_width = area.width as usize;
    let height = area.height as usize;
    if sorted.is_empty() {
        if !m.data_loaded {
            return vec![Line::from(format!("  {} Loading available shards…", spinner(m)))];
        }
        return vec![Line::from("  No available shards")];
    }
    let (widths, fw) = avail_col_widths(m, content_width, sorted);
    let filter_hi = m.active_filter_col_idx();

    let mut hdr_spans: Vec<Span> = Vec::new();
    for i in 0..AVAIL_COL_NAMES.len() {
        let cell = format!("{:>w$}", avail_header(m, i), w = widths[i]);
        let style = if m.sort_mode && !m.focus.is_alloc() && m.sort_highlight_col == i {
            Style::new().bg(PRIMARY).fg(TEXT).add_modifier(Modifier::BOLD)
        } else if m.avail_filter_mode
            && !m.filter_edit_active
            && !m.focus.is_alloc()
            && filter_hi == i as i32
        {
            Style::new().bg(FILTER).fg(TEXT).add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::BOLD)
        };
        if i > 0 {
            hdr_spans.push(Span::raw(" "));
        }
        hdr_spans.push(Span::styled(cell, style));
    }
    let mut lines = vec![Line::from(hdr_spans)];

    let visible = height.saturating_sub(1).max(1);
    m.avail_offset = clamp_offset(m.avail_offset, m.avail_cursor, visible, sorted.len());
    let end = (m.avail_offset + visible).min(sorted.len());

    for i in m.avail_offset..end {
        let s = &sorted[i];
        let selected = i == m.avail_cursor && !m.focus.is_alloc();

        if selected {
            let cells: Vec<String> = (0..widths.len())
                .map(|c| format!("{:>w$}", avail_cell(m, s, c, fw), w = widths[c]))
                .collect();
            let padded = format!("{:<width$}", cells.join(" "), width = content_width);
            lines.push(Line::from(Span::styled(
                padded,
                Style::new().fg(TEXT).bg(PRIMARY),
            )));
        } else {
            // Non-selected: size uses human-readable storage; ring colored.
            let mut spans: Vec<Span> = Vec::new();
            for c in 0..widths.len() {
                if c > 0 {
                    spans.push(Span::raw(" "));
                }
                let cell = format!("{:>w$}", avail_cell(m, s, c, fw), w = widths[c]);
                spans.push(match c {
                    3 if m.color_coding => Span::styled(cell, Style::new().fg(ring_color(s.ring))),
                    8 if m.color_coding => Span::styled(cell, Style::new().fg(materialization_state_color(materialization_state(s.materialized_frame, s.latest_frame)))),
                    _ => Span::raw(cell),
                });
            }
            lines.push(Line::from(spans));
        }
    }
    lines
}

// ── Footer (actions + status) ────────────────────────────────────────────

fn footer_lines(m: &Model) -> (Line<'static>, Line<'static>) {
    if m.filter_edit_active {
        return render_filter_edit_lines(m);
    }
    if m.is_filter_mode_active() {
        let col = m.active_filter_col_idx();
        let col_name = if m.focus.is_alloc() {
            (col >= 0)
                .then(|| ALLOC_COL_NAMES.get(col as usize).copied())
                .flatten()
                .unwrap_or("")
        } else {
            (col >= 0)
                .then(|| AVAIL_COL_NAMES.get(col as usize).copied())
                .flatten()
                .unwrap_or("")
        };
        let actions = Line::from(Span::styled(
            format!(
                "Filter [{col_name}]: [←/→] column  [enter] edit  [del] clear  [x] disable all  [esc] close"
            ),
            Style::new().fg(FILTER).add_modifier(Modifier::BOLD),
        ));
        return (actions, status_line(m));
    }
    if m.sort_mode && m.sort_order_mode {
        return (
            Line::from(Span::styled(
                "Sort order: [enter/a] ascending (default)  [d] descending  [esc] cancel",
                Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        );
    }
    if m.sort_mode {
        return (
            Line::from(Span::styled(
                "Sort: [←/→] Move column  [enter] apply  [esc] cancel",
                Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        );
    }
    (help_line(m), status_line(m))
}

fn status_line(m: &Model) -> Line<'static> {
    if m.action_in_flight {
        return Line::from(format!("{} {}", spinner(m), m.status_msg));
    }
    if m.status_msg.is_empty() {
        return Line::from("");
    }
    let color = if m.status_is_error { ERROR } else { SUCCESS };
    Line::from(Span::styled(m.status_msg.clone(), Style::new().fg(color)))
}

/// `renderHelpLine` — key hints with applicable actions highlighted.
fn help_line(m: &Model) -> Line<'static> {
    let mut applicable: std::collections::HashSet<String> = std::collections::HashSet::new();
    if !m.action_in_flight {
        if m.focus.is_alloc() {
            for a in m.applicable_alloc_actions() {
                applicable.insert(a);
            }
            let sorted = m.sorted_allocations();
            if sorted.get(m.alloc_cursor).is_some_and(|r| r.worker_id >= 0) {
                applicable.insert("ToggleManual".to_string());
            }
        } else if !m.free_workers.is_empty() {
            applicable.insert("Join".to_string());
        }
    }
    let filters_active = m.has_active_filters();

    // (key, desc, action-tag)
    let entries: [(&str, &str, &str); 19] = [
        ("tab", "switch", ""),
        ("↑/k", "up", ""),
        ("↓/j", "down", ""),
        ("space", "toggle", ""),
        ("a", "all/none", ""),
        ("J", "join", "Join"),
        ("l", "leave", "Leave"),
        ("c", "confirm", "Confirm"),
        ("r", "reject", "Reject"),
        ("p", "pause", "Pause"),
        ("u", "resume", "Resume"),
        ("M", "mode", "ToggleManual"),
        ("R", "refresh", ""),
        ("s", "sort", ""),
        ("f", "filter", "Filter"),
        ("C", "colors", "ColorCoding"),
        ("w", "widths", "ColumnSizing"),
        ("h", "help", ""),
        ("q", "quit", ""),
    ];
    let mut spans: Vec<Span> = Vec::new();
    for (i, (key, desc, tag)) in entries.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        let text = format!("[{key}] {desc}");
        let style = match *tag {
            "Filter" => {
                if filters_active {
                    Style::new().fg(FILTER).add_modifier(Modifier::BOLD)
                } else {
                    Style::new().fg(HELP)
                }
            }
            "ColorCoding" => {
                if m.color_coding {
                    Style::new().fg(SUCCESS)
                } else {
                    Style::new().fg(HELP)
                }
            }
            "ColumnSizing" => {
                if m.column_sizing == ColumnSizing::Dynamic {
                    Style::new().fg(SUCCESS)
                } else {
                    Style::new().fg(HELP)
                }
            }
            "" => Style::new().fg(HELP),
            t if applicable.contains(t) => Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
            _ => Style::new().fg(DIM),
        };
        spans.push(Span::styled(text, style));
    }
    Line::from(spans)
}

fn render_filter_edit_lines(m: &Model) -> (Line<'static>, Line<'static>) {
    let col_name = if m.focus.is_alloc() {
        ALLOC_COL_NAMES.get(m.filter_edit_col_idx).copied().unwrap_or("")
    } else {
        AVAIL_COL_NAMES.get(m.filter_edit_col_idx).copied().unwrap_or("")
    };
    let kind = m.active_filter_col_kind(m.filter_edit_col_idx);

    if kind == FilterColKind::Select {
        let mut spans: Vec<Span> = vec![Span::raw(format!("Filter [{col_name}]: "))];
        for (i, v) in m.filter_edit_select_items.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw("  "));
            }
            let checked = if *m.filter_edit_select_state.get(v).unwrap_or(&false) {
                "[x]"
            } else {
                "[ ]"
            };
            if i == m.filter_edit_select_cursor {
                spans.push(Span::styled(
                    format!("▶{checked} {v}"),
                    Style::new().fg(FILTER).add_modifier(Modifier::BOLD),
                ));
            } else {
                spans.push(Span::styled(format!("  {checked} {v}"), Style::new().fg(HELP)));
            }
        }
        let status = Line::from(Span::styled(
            "[←/→] column  [space] toggle  [a] all/none  [enter] apply  [esc] cancel",
            Style::new().fg(HELP),
        ));
        return (Line::from(spans), status);
    }

    let actions = Line::from(Span::styled(
        format!("Filter [{col_name}]: {}_", m.filter_edit_input),
        Style::new().fg(FILTER).add_modifier(Modifier::BOLD),
    ));
    let hint = if kind == FilterColKind::Numeric {
        "Numeric: >N  >=N  <N  <=N  =N  or  N1,N2,...    [enter] apply  [esc] cancel"
    } else {
        "[enter] apply  [esc] cancel"
    };
    (actions, Line::from(Span::styled(hint, Style::new().fg(HELP))))
}

// ── Help screen ──────────────────────────────────────────────────────────

fn render_help_screen(f: &mut Frame, m: &Model, area: Rect) {
    let sec = |s: &str| Line::from(Span::styled(s.to_string(), Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD)));
    let kv = |k: &str, v: &str| {
        Line::from(vec![
            Span::styled(format!("  {:<14}", k), Style::new().fg(TEXT).add_modifier(Modifier::BOLD)),
            Span::styled(v.to_string(), Style::new().fg(HELP)),
        ])
    };
    let note = |s: &str| Line::from(Span::styled(format!("  {s}"), Style::new().fg(FILTER)));

    let mut lines = vec![
        Line::from(Span::styled(
            " Shard Manager — Help",
            Style::new().fg(TEXT).bg(PRIMARY).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        sec("Navigation"),
        kv("↑ / k", "Move cursor up"),
        kv("↓ / j", "Move cursor down"),
        kv("Tab", "Switch between Allocations and Available Shards panels"),
        kv("Space", "Toggle selection on cursor row (advances cursor)"),
        kv("a", "Select all / deselect all rows in current panel"),
        Line::from(""),
        sec("Actions — Allocations panel"),
        kv("l", "Leave  — request to leave an Active allocation (status 2)"),
        kv("c", "Confirm — confirm a pending Join/Leave once the window opens"),
        kv("r", "Reject  — reject a pending Join/Leave"),
        kv("p", "Pause   — pause an Active allocation (status 2)"),
        kv("u", "Resume  — resume a Paused allocation (status 3)"),
        kv("M", "Toggle manual / auto worker management on cursor row"),
        note("Multi-select with Space or 'a' to batch Leave/Confirm/Reject/Pause/Resume."),
        Line::from(""),
        sec("Actions — Available Shards panel"),
        kv("J", "Join    — open worker picker for selected shard(s)"),
        note("At least one free (unassigned) worker must exist to join."),
        Line::from(""),
        sec("Sort mode  (press s)"),
        kv("← / →", "Move highlight to previous / next column"),
        kv("enter", "Confirm column, then choose sort order"),
        kv("a", "Ascending order"),
        kv("d", "Descending order"),
        kv("esc", "Cancel sort mode"),
        Line::from(""),
        sec("Filter mode  (press f)"),
        kv("← / →", "Move highlight to previous / next filterable column"),
        kv("enter", "Open filter editor for highlighted column"),
        kv("del", "Clear filter on highlighted column"),
        kv("x", "Disable all filters in current panel"),
        kv("esc", "Close filter mode"),
        note("Filter editor: text columns accept a substring; numeric columns accept"),
        note("an expression like \"> 47\", \"< 100\", or a comma list \"1,5,7\";"),
        note("select columns toggle values with Space, confirm with Enter."),
        Line::from(""),
        sec("General"),
        kv("R", "Force data refresh"),
        kv("C", "Toggle color-coding of Ring, Status and Mode columns"),
        kv("w", "Column widths: sized to content (default) or fixed"),
        kv("h", "Toggle this help screen"),
        kv("q / Ctrl+C", "Quit"),
        Line::from(""),
        Line::from(Span::styled("Press h to return", Style::new().fg(HELP))),
    ];
    // Header title fills width.
    if let Some(first) = lines.first_mut() {
        *first = Line::from(Span::styled(
            format!("{:<width$}", " Shard Manager — Help", width = area.width as usize),
            Style::new().fg(TEXT).bg(PRIMARY).add_modifier(Modifier::BOLD),
        ));
    }
    let _ = m;
    f.render_widget(Paragraph::new(lines), area);
}

// ── Join worker picker ───────────────────────────────────────────────────

fn render_join_picker(f: &mut Frame, m: &mut Model, area: Rect) {
    let mut lines = vec![
        Line::from(Span::styled(
            format!("{:<width$}", " Select workers to mark as manually managed", width = area.width as usize),
            Style::new().fg(TEXT).bg(PRIMARY).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "  Joining {} shard(s). Select which free workers to set to Manual mode:",
            m.join_picker_filters.len()
        )),
        Line::from(""),
    ];

    let visible = (area.height as usize).saturating_sub(6).max(1);
    m.join_picker_offset = clamp_offset(
        m.join_picker_offset,
        m.join_picker_cursor,
        visible,
        m.join_picker_workers.len(),
    );
    let end = (m.join_picker_offset + visible).min(m.join_picker_workers.len());
    for i in m.join_picker_offset..end {
        let wid = m.join_picker_workers[i];
        let marker = if m.join_picker_selected.contains(&wid) {
            "[x]"
        } else {
            "[ ]"
        };
        let cursor = if i == m.join_picker_cursor { "> " } else { "  " };
        let text = format!("{cursor}{marker} Worker {wid}");
        if i == m.join_picker_cursor {
            lines.push(Line::from(Span::styled(text, Style::new().fg(TEXT).bg(PRIMARY))));
        } else {
            lines.push(Line::from(text));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  space: toggle  J/enter: confirm join  esc: cancel",
        Style::new().fg(HELP),
    )));
    f.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One allocations row. Only the fields that reach a cell are meaningful.
    fn row(
        hex: &str,
        provers: u32,
        shards: u64,
        worker: i64,
        next: &str,
        dflt: &str,
    ) -> AllocationRow {
        AllocationRow {
            filter: Vec::new(),
            filter_key: hex.to_string(),
            filter_hex: hex.to_string(),
            status: 1,
            status_name: "joining".to_string(),
            ring: 5,
            active_provers: provers,
            shard_size: BigInt::from(0),
            data_shards: shards,
            estimated_reward: BigInt::from(0),
            join_frame: 0,
            leave_frame: 0,
            worker_id: worker,
            next_action: next.to_string(),
            default_action: dflt.to_string(),
            manually_managed: false,
            confirm_frame: 0,
            leave_confirm_frame: 0,
            epoch: 0,
            last_active_frame: 0,
        }
    }

    fn shard(hex: &str, size: u64, reward: u64) -> ShardRow {
        ShardRow {
            filter: Vec::new(),
            filter_key: hex.to_string(),
            filter_hex: hex.to_string(),
            active_provers: 42,
            ring: 1,
            shard_size: BigInt::from(size),
            data_shards: 2,
            estimated_reward: BigInt::from(reward),
        }
    }

    /// The cursor row is the same row. It used to print size in an adaptive
    /// unit and suffix the reward with ` Q/f`, so moving the cursor rewrote
    /// two cells of whichever row it landed on.
    #[test]
    fn the_cursor_does_not_change_what_a_row_says() {
        let m = Model::new();
        let rows = [
            shard(&format!("{:064x}", 1), 0, 0),
            shard(&format!("{:064x}", 2), 12_396, 4_498),
            shard(&format!("{:064x}", 3), 6_688_000_000, 768_047),
        ];
        for s in &rows {
            for c in 0..AVAIL_COL_NAMES.len() {
                // Rendering is now independent of the cursor by construction;
                // this pins the reward cell to the header's unit.
                let cell = avail_cell(&m, s, c, 64);
                assert!(!cell.contains("Q/f"), "column {c} repeats the header unit: {cell}");
            }
        }
        // Reward stops carrying its unit, so the column fits its header.
        let (w, _) = avail_col_widths(&m, 154, &rows);
        assert_eq!(w[6], avail_header(&m, 6).len());
    }

    /// The table as reported: 15 joining allocations, sorted ascending on
    /// Worker, none of them in a confirm window.
    fn joining_table() -> Vec<AllocationRow> {
        (1..=15)
            .map(|i| {
                row(
                    &format!("{:064x}", i),
                    57,
                    10_076_371,
                    i as i64,
                    "confirmed",
                    "active@e972",
                )
            })
            .collect()
    }

    fn fixed() -> Model {
        Model {
            column_sizing: ColumnSizing::Fixed,
            ..Model::new()
        }
    }

    #[test]
    fn header_text_decorates_and_underscores() {
        assert_eq!(header_text("Worker", 7, 7, true, false, false), "^|Worker");
        assert_eq!(header_text("Worker", 7, 7, false, false, false), "v|Worker");
        assert_eq!(header_text("Ring", 3, 7, true, true, false), "Ring*");
        assert_eq!(header_text("Ring", 3, 3, true, true, false), "^|Ring*");
        // Measured columns sit one space apart, so the spaces inside a name
        // become underscores to keep the pairs readable.
        assert_eq!(
            header_text("Default Action", 11, 7, true, false, true),
            "Default_Action"
        );
        assert_eq!(
            header_text("Default Action", 11, 7, true, false, false),
            "Default Action"
        );
    }

    #[test]
    fn every_column_is_sized_to_its_own_content() {
        let m = Model::new(); // Dynamic, sorted ascending on Worker
        let rows = joining_table();
        let (w, fw) = alloc_col_widths(&m, 154, &rows);

        assert_eq!(
            w,
            vec![
                6,  // "Select"
                51, // Filter — what the pane has left
                7,  // "Provers"
                4,  // "Ring"
                9,  // "Size_[MB]"
                8,  // "10076371", wider than "Shards"
                12, // "Reward_[Q/f]"
                8,  // "^|Worker"
                7,  // "joining", wider than "Status"
                4,  // "Mode"
                11, // "Next_Action", wider than "confirmed"
                14, // "Default_Action", wider than "active@e972"
            ]
        );
        assert_eq!(fw, 51);
        // 12 columns + 11 separators + 2 borders fill the pane exactly.
        assert_eq!(w.iter().sum::<usize>() + 11 + 2, 154);
    }

    #[test]
    fn fixed_sizing_reproduces_the_historical_layout() {
        let (w, fw) = alloc_col_widths(&fixed(), 154, &joining_table());
        assert_eq!(w, vec![6, 20, 7, 5, 10, 8, 14, 9, 12, 4, 30, 16]);
        assert_eq!(fw, 20);
        assert_eq!(w.iter().sum::<usize>() + 11, 152);
        // 30 columns of Next Action for a 9-column value, in a row 152 wide.
        assert_eq!(w[10], NEXT_ACTION_WIDTH);
    }

    #[test]
    fn no_cell_overflows_its_column() {
        for m in [Model::new(), fixed()] {
            let rows = joining_table();
            let (w, fw) = alloc_col_widths(&m, 154, &rows);
            for (c, width) in w.iter().enumerate() {
                for a in &rows {
                    let cell = alloc_cell(&m, a, c, fw);
                    assert!(
                        cell.len() <= *width,
                        "column {c} is {width} wide but a cell needs {}",
                        cell.len()
                    );
                }
            }
        }
    }

    #[test]
    fn next_action_widens_when_a_confirm_window_opens() {
        let m = Model::new();
        let mut rows = joining_table();
        let (before, before_fw) = alloc_col_widths(&m, 154, &rows);
        rows[3].next_action = "reject | confirm now".to_string();
        let (after, after_fw) = alloc_col_widths(&m, 154, &rows);

        assert_eq!(before[10], 11);
        assert_eq!(after[10], 20);
        // Filter gives back exactly what Next Action took; the row still fits.
        assert_eq!(before_fw - after_fw, 9);
        assert_eq!(after.iter().sum::<usize>() + 11 + 2, 154);
    }

    #[test]
    fn filter_takes_the_slack_and_gives_it_back_first() {
        let m = Model::new();
        let rows = joining_table();
        // Wide pane: Filter stops at the longest hex rather than padding on.
        assert_eq!(alloc_col_widths(&m, 300, &rows).1, 64);
        assert_eq!(alloc_col_widths(&m, 167, &rows).1, 64);
        // Narrower: Filter absorbs the shortfall…
        assert_eq!(alloc_col_widths(&m, 154, &rows).1, 51);
        assert_eq!(alloc_col_widths(&m, 118, &rows).1, 15);
        // …down to the floor, past which the row is clipped rather than shrunk.
        assert_eq!(alloc_col_widths(&m, 115, &rows).1, MIN_FILTER_WIDTH);
        assert_eq!(alloc_col_widths(&m, 40, &rows).1, MIN_FILTER_WIDTH);
    }
}
