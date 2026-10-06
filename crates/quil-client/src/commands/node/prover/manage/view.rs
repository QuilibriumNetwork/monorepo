//! Rendering for the `prover manage` TUI. Port of the bubbletea `View`
//! and its panel/help/join-picker renderers, expressed with ratatui.

use super::super::local_execution::{local_execution_state, age};

use num_bigint::BigInt;
use super::super::epoch::EffectiveStatus;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

use super::super::epoch::ThresholdUnit;
use super::super::format_quil_daily_round;
use super::model::*;
use super::util::{center_trunc, filter_label, shared_filter_address, clamp_offset};

// ── Colors (mirror lipgloss constants) ───────────────────────────────────

const PRIMARY: Color = Color::Rgb(0xff, 0x00, 0x70);
const CURSOR_BG: Color = Color::Rgb(0x28, 0x28, 0x28);
const INACTIVE_CURSOR_BG: Color = Color::Rgb(0x18, 0x18, 0x18);
const DIM: Color = Color::Rgb(0x55, 0x55, 0x55);
const TEXT: Color = Color::Rgb(0xff, 0xff, 0xff);
const SUCCESS: Color = Color::Rgb(0x00, 0xff, 0x00);
const ERROR: Color = Color::Rgb(0xff, 0x00, 0x00);
const HELP: Color = Color::Rgb(0x88, 0x88, 0x88);
const FILTER: Color = Color::Rgb(0xff, 0xaa, 0x00);
/// The sort-direction arrow, so the sorted column is findable at a glance.
/// Distinct from every status palette above: it marks the layout, not a value.
const SORT: Color = Color::Rgb(0x55, 0xaa, 0xff);

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn ring_color(ring: u32) -> Color {
    match ring {
        UNKNOWN_REWARD_RING => HELP,
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
    match state {
        "current" => SUCCESS,
        "lag" | "unmat" => ERROR,
        _ => HELP,
    }
}

/// A worker id is only worth colouring when it says the allocation is not
/// being proved: `-1` is "no worker bound", which is the one value in the
/// column that asks the operator to do something. Assigned ids are left plain
/// rather than coloured green, so twelve bound rows stay quiet.
fn worker_color(worker_id: i64) -> Option<Color> {
    (worker_id < 0).then_some(ERROR)
}

fn mode_color(mode: &str) -> Color {
    if mode == "m" {
        Color::Rgb(0xff, 0x88, 0x00)
    } else {
        Color::Rgb(0x00, 0xff, 0x00)
    }
}

/// Sort-direction arrow prefixed to the sorted column's header.
fn sort_arrow(ascending: bool) -> &'static str {
    if ascending {
        "↑"
    } else {
        "↓"
    }
}

fn spinner(m: &Model) -> &'static str {
    SPINNER[m.spinner_frame % SPINNER.len()]
}

/// Estimated reward for the reward cell: whole QUIL/day, matching the
/// `Reward [Q/d]` header and the panel-title totals.
fn fmt_reward(v: &BigInt) -> String {
    format_quil_daily_round(v)
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
        s.insert_str(0, sort_arrow(asc));
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
    cells.max().unwrap_or(0).max(printed_width(header))
}

/// Columns are laid out in terminal cells and `{:>w$}` pads by `char`, so a
/// width has to be counted the same way. The sort arrow is one character and
/// three bytes: measuring `len()` would reserve two blanks it never fills.
fn printed_width(s: &str) -> usize {
    s.chars().count()
}

/// Next Action is laid out flush left; every other column stays right.
///
/// Right-justifying aligns a column on its tail, which is what you want when
/// the tail is the part being compared. Default Action always carries a
/// threshold, so its `@f804960`s line up and the eye reads straight down
/// them. Next Action does not: `(pause|leave)` has no threshold at all, and
/// aligned on the tail it lands under the middle of `(reject|confirm)@f804960`
/// — the column stops looking like one column. Left is the only edge its
/// values share. Filters likewise align on their prefix.
fn alloc_left_aligned(col: usize) -> bool {
    col == 1 || col == 14
}

/// One cell padded to its column width, on the side its column aligns to.
fn pad_cell(text: &str, width: usize, left: bool) -> String {
    if left {
        format!("{text:<width$}")
    } else {
        format!("{text:>width$}")
    }
}

/// One header cell, as spans.
///
/// The sorted column is underlined — an indicator that survives a monochrome
/// terminal, unlike the arrow's colour — and when colour is on and the cell
/// isn't already carrying a sort/filter background, the arrow itself is
/// tinted. Padding is emitted as its own span under the same style so a
/// highlight background stays contiguous across the whole cell.
fn header_spans(
    text: &str,
    width: usize,
    base: Style,
    sorted: bool,
    tint: bool,
    left: bool,
) -> Vec<Span<'static>> {
    let style = if sorted {
        base.add_modifier(Modifier::UNDERLINED)
    } else {
        base
    };
    let blanks = " ".repeat(width.saturating_sub(printed_width(text)));
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(4);
    if !left && !blanks.is_empty() {
        spans.push(Span::styled(blanks.clone(), style));
    }
    let mut name = text;
    if tint {
        if let Some(arrow) = text.chars().next() {
            spans.push(Span::styled(arrow.to_string(), style.fg(SORT)));
            name = &text[arrow.len_utf8()..];
        }
    }
    spans.push(Span::styled(name.to_string(), style));
    if left && !blanks.is_empty() {
        spans.push(Span::styled(blanks, style));
    }
    spans
}

// ── Entry ────────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, m: &mut Model) {
    let area = f.area();
    m.width = area.width;
    m.height = area.height;
    update_message_lifetime(m);

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

fn table_horizontal_offset(m: &mut Model, panel: usize, lines: &[Line<'_>], visible: u16) -> u16 {
    let width = lines.iter().map(Line::width).max().unwrap_or(0);
    m.horizontal_limits[panel] = width.saturating_sub(usize::from(visible)).min(usize::from(u16::MAX)) as u16;
    m.horizontal_offsets[panel] = m.horizontal_offsets[panel].min(m.horizontal_limits[panel]);
    m.horizontal_offsets[panel]
}

fn scroll_hint(offset: usize, total: usize, visible: usize, horizontal: u16, horizontal_limit: u16) -> String {
    let above = offset;
    let below = total.saturating_sub(offset + visible);
    let right = horizontal_limit.saturating_sub(horizontal);
    if above + below + usize::from(horizontal) + usize::from(right) == 0 { return String::new(); }
    format!(" ↑{above} ↓{below} | ←{horizontal} →{right} ")
}

fn render_scroll_hint(f: &mut Frame, area: Rect, offset: usize, total: usize, visible: usize, horizontal: u16, horizontal_limit: u16) {
    let hint = scroll_hint(offset, total, visible, horizontal, horizontal_limit);
    if area.height >= 2 && area.width >= 4 && !hint.is_empty() {
        f.render_widget(Paragraph::new(hint).style(Style::new().fg(HELP)), Rect::new(area.x + 1, area.y + area.height - 1, area.width - 2, 1));
    }
}

fn base_panel_heights(total: u16) -> [u16; 3] {
    if total < 6 { return [total / 3 + total % 3, total / 3, total / 3]; }
    let notice = total.saturating_sub(5).min(3);
    let alloc = ((total - notice) / 2).max(3);
    [alloc, total - notice - alloc, notice]
}

fn panel_heights(m: &Model, total: u16) -> [u16; 3] {
    let mut heights = base_panel_heights(total);
    if total < 6 { return heights; }
    let minimum = [3i32, 2, 1];
    for i in 0..2 {
        let movement = i32::from(m.panel_boundary_offsets[i]).clamp(minimum[i] - i32::from(heights[i]), i32::from(heights[i + 1]) - minimum[i + 1]);
        heights[i] = (i32::from(heights[i]) + movement) as u16;
        heights[i + 1] = (i32::from(heights[i + 1]) - movement) as u16;
    }
    heights
}

/// Normalize clipped offsets after a terminal resize so the next key moves
/// the visible boundary immediately, rather than walking an obsolete offset.
fn sync_panel_heights(m: &mut Model, total: u16) -> [u16; 3] {
    let base = base_panel_heights(total);
    let heights = panel_heights(m, total);
    m.panel_content_heights = heights;
    m.panel_boundary_offsets = [
        (i32::from(heights[0]) - i32::from(base[0])) as i16,
        (i32::from(base[2]) - i32::from(heights[2])) as i16,
    ];
    heights
}

fn render_main(f: &mut Frame, m: &mut Model, area: Rect) {
    let (actions, status) = footer_lines(m);
    let mut actions = wrap_actions(actions, area.width);
    let max_actions = usize::from(area.height.saturating_sub(15).max(1));
    if actions.len() > max_actions {
        actions.truncate(max_actions);
        actions[max_actions - 1] = Line::from("[h] all keys  [q] quit");
    }
    let actions_h = actions.len() as u16;
    // Content height depends only on terminal geometry and explicit resize keys.
    let [alloc_h, avail_h, notice_h] = sync_panel_heights(m, area.height.saturating_sub(7 + actions_h));
    let status_h = notice_h + 2;

    let chunks = Layout::vertical([
        Constraint::Length(1),           // header
        Constraint::Length(alloc_h + 2), // alloc panel (+ border)
        Constraint::Length(avail_h + 2), // avail panel (+ border)
        Constraint::Length(status_h),    // notifications
        Constraint::Length(actions_h),   // commands at the bottom
    ])
    .split(area);

    // Header.
    f.render_widget(
        Paragraph::new(header_line(m)).style(Style::new().fg(TEXT).bg(PRIMARY)),
        chunks[0],
    );

    // Titles share the top borders, leaving two more rows for table data.
    let sorted_allocs = m.sorted_allocations();
    let sorted_avail = m.sorted_available();
    let (alloc_widths, avail_widths) = shared_col_widths(m, area.width.saturating_sub(2) as usize, &sorted_allocs, &sorted_avail);
    update_app_progress_warning(m);
    let alloc_block = Block::default()
        .title(alloc_title(m, &sorted_allocs))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if m.focus.is_alloc() { PRIMARY } else { DIM }));
    let alloc_inner = alloc_block.inner(chunks[1]);
    f.render_widget(alloc_block, chunks[1]);
    let alloc_lines = render_alloc_panel(m, &sorted_allocs, alloc_inner, Some(&alloc_widths));
    let mut alloc_lines = alloc_lines;
    let detail = if !sorted_allocs.is_empty() && alloc_inner.height >= 3 { alloc_lines.pop() } else { None };
    let horizontal = table_horizontal_offset(m, 0, &alloc_lines, alloc_inner.width);
    f.render_widget(Paragraph::new(alloc_lines).scroll((0, horizontal)), alloc_inner);
    if let Some(detail) = detail { f.render_widget(Paragraph::new(detail), Rect::new(alloc_inner.x, alloc_inner.y + alloc_inner.height - 1, alloc_inner.width, 1)); }
    render_scroll_hint(f, chunks[1], m.alloc_offset, sorted_allocs.len(), usize::from(alloc_inner.height.saturating_sub(2)), horizontal, m.horizontal_limits[0]);

    let avail_block = Block::default()
        .title(avail_title(m, &sorted_avail))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if m.focus == PanelFocus::Available { PRIMARY } else { DIM }));
    let avail_inner = avail_block.inner(chunks[2]);
    f.render_widget(avail_block, chunks[2]);
    let avail_lines = render_avail_panel(m, &sorted_avail, avail_inner, Some(&avail_widths));
    let mut avail_lines = avail_lines;
    let detail = if !sorted_avail.is_empty() && avail_inner.height >= 3 { avail_lines.pop() } else { None };
    let detail_rows = u16::from(detail.is_some());
    let horizontal = table_horizontal_offset(m, 1, &avail_lines, avail_inner.width);
    f.render_widget(Paragraph::new(avail_lines).scroll((0, horizontal)), avail_inner);
    if let Some(detail) = detail { f.render_widget(Paragraph::new(detail), Rect::new(avail_inner.x, avail_inner.y + avail_inner.height - 1, avail_inner.width, 1)); }
    render_scroll_hint(f, chunks[2], m.avail_offset, sorted_avail.len(), usize::from(avail_inner.height.saturating_sub(1 + detail_rows + u16::from(m.shard_error.is_some()))), horizontal, m.horizontal_limits[1]);

    render_notifications(f, m, status, chunks[3]);
    f.render_widget(
        Paragraph::new(actions).style(Style::new().fg(HELP)),
        chunks[4],
    );
}

fn render_notifications(f: &mut Frame, m: &mut Model, primary: Line<'static>, area: Rect) {
    let mut lines = message_lines(m, primary, area.width.saturating_sub(2));
    if lines.len() == 1 && lines[0].width() == 0 {
        lines[0] = Line::from(Span::styled(
            match m.notice_minimum {
                NoticeSeverity::Info => "No notifications",
                NoticeSeverity::Warning => "No warnings or errors",
                NoticeSeverity::Error => "No errors",
            }, Style::new().fg(HELP),
        ));
    }
    m.notice_lines = lines.len();
    m.notice_visible = usize::from(area.height.saturating_sub(2));
    m.notice_offset = m.notice_offset.min(m.notice_lines.saturating_sub(m.notice_visible));
    let title = if m.notice_lines > m.notice_visible {
        format!(" Notifications: {} {}/{} ", m.notice_minimum.label(), m.notice_offset + 1, m.notice_lines)
    } else { format!(" Notifications: {} ", m.notice_minimum.label()) };
    let block = Block::default().title(panel_title(title)).borders(Borders::ALL)
        .border_type(BorderType::Rounded).border_style(Style::new().fg(if m.focus == PanelFocus::Notifications { PRIMARY } else { DIM }));
    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(Paragraph::new(lines.into_iter().skip(m.notice_offset)
        .take(m.notice_visible).collect::<Vec<_>>()), inner);
    render_scroll_hint(f, area, m.notice_offset, m.notice_lines, m.notice_visible, 0, 0);
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

fn panel_title(text: String) -> Line<'static> {
    Line::from(format!(" {} ", text.trim()))
        .style(Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD))
}

/// Display signed changes without rounding a nonzero loss/gain to zero.
fn fmt_reward_change(v: &BigInt) -> String {
    match v.sign() {
        num_bigint::Sign::Minus => format!("-{}", fmt_reward(&(-v))),
        num_bigint::Sign::Plus => format!("+{}", fmt_reward(v)),
        num_bigint::Sign::NoSign => "0".to_string(),
    }
}

/// Round to five decimals with integer arithmetic; preserve tiny positive amounts.
fn fmt_claimable(value: u128) -> String {
    const UNITS_PER_QUIL: u128 = 8_000_000_000;
    const UNITS_PER_DECIMAL: u128 = UNITS_PER_QUIL / 100_000;
    if value == 0 { return "0".into(); }
    if value < UNITS_PER_DECIMAL { return "<0.00001".into(); }
    let mut whole = value / UNITS_PER_QUIL;
    let mut fraction = (value % UNITS_PER_QUIL + UNITS_PER_DECIMAL / 2) / UNITS_PER_DECIMAL;
    if fraction == 100_000 { whole += 1; fraction = 0; }
    if fraction == 0 { whole.to_string() }
    else { format!("{whole}.{:05}", fraction).trim_end_matches('0').to_string() }
}

fn claimable_title(m: &Model) -> String {
    match m.claimable_reward {
        Some((value, frame)) => format!("Claimable [Q]: {} @f{}{}",
            fmt_claimable(value),
            frame,
            if m.reward_last_success.is_some_and(|t| t.elapsed().as_secs() >= 30) { " (stale)" } else { "" }),
        None if m.reward_loaded => "Claimable [Q]: unavailable".into(),
        None => "Claimable [Q]: loading".into(),
    }
}

fn alloc_title(m: &Model, sorted: &[AllocationRow]) -> Line<'static> {
    let mut joining = BigInt::from(0);
    let mut active = BigInt::from(0);
    let mut paused = BigInt::from(0);
    let mut leaving = BigInt::from(0);
    let (mut current_unknown, mut paused_unknown, mut change_unknown) = (false, false, false);
    let mut current_known = false;
    for a in sorted {
        if a.ring == UNKNOWN_REWARD_RING {
            match a.reward_status(m.epoch_frame(), m.epoch_length) {
                Some(EffectiveStatus::Active) => current_unknown = true,
                Some(EffectiveStatus::Leaving) => { current_unknown = true; change_unknown = true; },
                Some(EffectiveStatus::Paused) => paused_unknown = true,
                Some(EffectiveStatus::Joining) => change_unknown = true,
                _ => {}
            }
            continue;
        }
        match a.reward_status(m.epoch_frame(), m.epoch_length) {
            Some(EffectiveStatus::Joining) => joining += &a.estimated_reward,
            Some(EffectiveStatus::Active) => { current_known = true; active += &a.estimated_reward; },
            Some(EffectiveStatus::Paused) => paused += &a.estimated_reward,
            Some(EffectiveStatus::Leaving) => { current_known = true; leaving += &a.estimated_reward; },
            _ => {}
        }
    }
    let current = &active + &leaving;
    let change = &joining - &leaving;
    let mut s = format!(
        "Allocations: {}  {}  Rewards [Q/d]: Current {} | Paused {} | Planned change {}",
        sorted.len(),
        claimable_title(m),
        if current_unknown && !current_known { "?".into() }
        else { format!("{}{}", fmt_reward(&current), if current_unknown { "+" } else { "" }) },
        if paused_unknown { "?".into() } else { fmt_reward(&paused) },
        if change_unknown { "?".into() } else { fmt_reward_change(&change) },
    );
    if !m.alloc_selected.is_empty() {
        s += &format!(" [{} selected]", m.alloc_selected.len());
    }
    panel_title(s)
}

fn avail_title(m: &Model, sorted: &[ShardRow]) -> Line<'static> {
    let mut s = format!(" Available Shards: {}", sorted.len());
    if !m.avail_selected.is_empty() {
        s += &format!(" [{} selected]", m.avail_selected.len());
    }
    panel_title(s)
}

// ── Allocations panel ────────────────────────────────────────────────────

fn fmt_ring(ring: u32) -> String {
    if ring == UNKNOWN_REWARD_RING { "-".into() } else { ring.to_string() }
}

fn fmt_materialized(materialized: u64, latest: u64) -> String {
    if materialized == 0 && latest == 0 { "-".into() } else { materialized.to_string() }
}

/// The printed text of one allocations cell. Sizing and rendering both go
/// through here. `fw` is the Filter column's width, which is a budget rather
/// than a measurement — pass 0 when measuring the other columns.
fn alloc_cell(m: &Model, a: &AllocationRow, col: usize, fw: usize) -> String {
    if !a.shard_info_known && matches!(col, 2..=5 | 7 | 10) { return "-".into(); }
    match col {
        0 => alloc_marker(m, a).to_string(),
        1 => center_trunc(&a.filter_hex, fw),
        2 => a.active_provers.to_string(),
        3 => fmt_ring(a.ring),
        4 => fmt_mb(&a.shard_size),
        5 => a.data_shards.to_string(),
        6 => if local_warning(a) { "0!".into() }
            else { a.execution.as_ref().and_then(|s| s.materialized_frame).map(|h| h.to_string()).unwrap_or_else(|| "-".into()) },
        7 => if a.materialized_frame == 0 && a.latest_frame == 0 { "-".into() } else { a.latest_frame.to_string() },
        8 => a.global_head.as_ref().map(|h| h.frame.to_string()).unwrap_or_else(|| "-".into()),
        9 => local_execution_state(a.execution.as_ref()).into(),
        10 => if a.ring == UNKNOWN_REWARD_RING { "-".into() } else { fmt_reward(&a.estimated_reward) },
        11 => a.worker_id.to_string(),
        12 => a.status_name.clone(),
        13 => a.mode().to_string(),
        14 => a.next_action.render(m.threshold_unit, m.epoch_length),
        _ => a.default_action.render(m.threshold_unit, m.epoch_length),
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

/// Align shared columns through Reward; local and peer context use their own labels.
fn shared_col_widths(m: &Model, content_width: usize, allocations: &[AllocationRow], available: &[ShardRow]) -> (Vec<usize>, Vec<usize>) {
    let (mut alloc, _) = alloc_col_widths(m, content_width, allocations);
    let (mut avail, _) = avail_col_widths(m, content_width, available);
    for i in 0..AVAIL_COL_NAMES.len() {
        if i != 1 { alloc[i] = alloc[i].max(avail[i]); }
    }
    let cap = alloc[1].max(avail[1]);
    alloc[1] = filter_width(content_width, &alloc, alloc.len(), cap);
    avail.copy_from_slice(&alloc[..AVAIL_COL_NAMES.len()]);
    (alloc, avail)
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
                sorted
                    .iter()
                    .map(|a| printed_width(&alloc_cell(m, a, c, 0))),
            )
        })
        .collect();

    let cap = filter_cap(
        &alloc_header(m, 1),
        sorted.iter().map(|a| printed_width(&a.filter_hex)),
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
        sorted
            .iter()
            .map(|a| printed_width(&alloc_cell(m, a, 5, 0))),
    );
    let reward_w = fit(
        ALLOC_REWARD_WIDTH,
        sorted
            .iter()
            .map(|a| printed_width(&alloc_cell(m, a, 10, 0))),
    );
    let global_head_w = fit(GLOBAL_HEAD_WIDTH, sorted.iter().map(|row| printed_width(&alloc_cell(m, row, 8, 0))));
    // Whatever the wide columns took comes out of the flexible Filter column.
    let grown = (global_head_w - GLOBAL_HEAD_WIDTH) + (shards_w - SHARDS_WIDTH) + (reward_w - ALLOC_REWARD_WIDTH);
    let mut fw = content_width.saturating_sub(ALLOC_FIXED_WIDTH + grown);
    for &col in &ALLOC_FILTERABLE_COLS {
        if col == 1 {
            continue;
        }
        if m.alloc_col_filters
            .get(&col)
            .is_some_and(|cf| cf.is_active())
        {
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
        shards_w,
        MAT_WIDTH,
        HEAD_WIDTH,
        global_head_w,
        STATE_WIDTH,
        reward_w,
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
        if m.alloc_col_filters
            .get(&col)
            .is_some_and(|cf| cf.is_active())
        {
            widths[col] += 1;
        }
    }
    if m.alloc_sort_col >= 0 && (m.alloc_sort_col as usize) < widths.len() {
        widths[m.alloc_sort_col as usize] += 1;
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

fn local_warning(a: &AllocationRow) -> bool {
    local_execution_state(a.execution.as_ref()) == "running"
        && a.execution.as_ref().and_then(|s| s.materialized_frame) == Some(0)
}

fn local_color(a: &AllocationRow) -> Color {
    match local_execution_state(a.execution.as_ref()) {
        "blocked" | "stopped" => ERROR,
        "running" if local_warning(a) => Color::Yellow,
        "running" => SUCCESS,
        _ => HELP,
    }
}

fn global_head_detail(head: Option<&quil_types::proto::node::GlobalAppFrameHead>) -> String {
    match head {
        Some(head) => format!("GLOBAL @f{} (gen {})", head.global_frame, head.generation),
        None => "GLOBAL app head: unavailable".into(),
    }
}

fn allocation_detail(a: &AllocationRow) -> Line<'static> {
    let Some(execution) = a.execution.as_ref() else {
        return Line::from(Span::styled(format!("{} | Local execution details unavailable", global_head_detail(a.global_head.as_ref())), Style::new().fg(HELP)));
    };
    let mut text = format!("{} | Last advance: {}", global_head_detail(a.global_head.as_ref()), if execution.last_advance_unix_ms == 0 {
        "not observed since start".into()
    } else { format!("{} ago", age(execution.last_advance_unix_ms)) });
    if !execution.blocker.is_empty() { text += &format!(" | Blocker: {}", execution.blocker); }
    if local_warning(a) { text += " | Warning: no materialized frames"; }
    let warning = !execution.blocker.is_empty() || local_warning(a) || matches!(local_execution_state(Some(execution)), "blocked" | "stopped");
    Line::from(Span::styled(text, Style::new().fg(if warning { Color::Yellow } else { HELP })))
}

fn render_alloc_panel(m: &mut Model, sorted: &[AllocationRow], area: Rect, aligned: Option<&[usize]>) -> Vec<Line<'static>> {
    let content_width = area.width as usize;
    let height = area.height as usize;
    if sorted.is_empty() {
        if !m.data_loaded {
            return vec![Line::from(format!("  {} Loading allocations…", spinner(m)))];
        }
        return vec![Line::from("  No allocations")];
    }
    let (widths, fw) = aligned.map(|w| (w.to_vec(), w[1])).unwrap_or_else(|| alloc_col_widths(m, content_width, sorted));
    let filter_hi = m.active_filter_col_idx();

    // Header row.
    let mut hdr_spans: Vec<Span> = Vec::new();
    for i in 0..ALLOC_COL_NAMES.len() {
        let hi_sort = m.sort_mode && m.focus.is_alloc() && m.sort_highlight_col == i;
        let hi_filter = m.alloc_filter_mode
            && !m.filter_edit_active
            && m.focus.is_alloc()
            && filter_hi == i as i32;
        let style = if hi_sort {
            Style::new()
                .bg(PRIMARY)
                .fg(TEXT)
                .add_modifier(Modifier::BOLD)
        } else if hi_filter {
            Style::new()
                .bg(FILTER)
                .fg(TEXT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::BOLD)
        };
        let sorted = m.alloc_sort_col == i as i32;
        if i > 0 {
            hdr_spans.push(Span::raw(" "));
        }
        hdr_spans.extend(header_spans(
            &alloc_header(m, i),
            widths[i],
            style,
            sorted,
            sorted && m.color_coding && !hi_sort && !hi_filter,
            alloc_left_aligned(i),
        ));
    }
    let mut lines = vec![Line::from(hdr_spans)];

    let detail_rows = usize::from(height >= 3);
    let visible = height.saturating_sub(1 + detail_rows).max(1);
    m.alloc_offset = clamp_offset(m.alloc_offset, m.alloc_cursor, visible, sorted.len());
    let end = (m.alloc_offset + visible).min(sorted.len());

    let shared_address = shared_filter_address(sorted.iter().map(|a| a.filter_hex.as_str()));
    let longest_suffix = sorted.iter().map(|a| a.filter_hex.len().saturating_sub(64)).max().unwrap_or(0);
    for i in m.alloc_offset..end {
        let a = &sorted[i];
        let selected = i == m.alloc_cursor;

        let cells: Vec<String> = (0..widths.len())
            .map(|c| {
                let cell = if c == 1 && shared_address { filter_label(&a.filter_hex, fw, longest_suffix) }
                    else { alloc_cell(m, a, c, fw) };
                pad_cell(&cell, widths[c], alloc_left_aligned(c))
            })
            .collect();

        if selected {
            let mut spans = Vec::new();
            for (ci, cell) in cells.iter().enumerate() {
                if ci > 0 { spans.push(Span::raw(" ")); }
                let color = if m.color_coding && matches!(ci, 6 | 9) { local_color(a) }
                    else if ci == 10 && m.color_coding && a.worker_id < 0 { ERROR } else { TEXT };
                spans.push(Span::styled(cell.clone(), Style::new().fg(color)));
            }
            let used = cells.iter().map(String::len).sum::<usize>() + cells.len().saturating_sub(1);
            spans.push(Span::raw(" ".repeat(content_width.saturating_sub(used))));
            lines.push(Line::from(spans).style(Style::new().fg(TEXT).bg(if m.focus.is_alloc() { CURSOR_BG } else { INACTIVE_CURSOR_BG })));
        } else {
            let mut spans: Vec<Span> = Vec::new();
            for (ci, cell) in cells.iter().enumerate() {
                if ci > 0 {
                    spans.push(Span::raw(" "));
                }
                let span = match ci {
                    3 if m.color_coding => {
                        Span::styled(cell.clone(), Style::new().fg(ring_color(a.ring)))
                    }
                    // Local engine health and the provider gap are separate observations.
                    6 | 9 if m.color_coding => {
                        Span::styled(cell.clone(), Style::new().fg(local_color(a)))
                    }
                    7 | 8 if m.color_coding => Span::styled(cell.clone(), Style::new().fg(HELP)),
                    11 if m.color_coding => match worker_color(a.worker_id) {
                        Some(color) => Span::styled(cell.clone(), Style::new().fg(color)),
                        None => Span::raw(cell.clone()),
                    },
                    10 if m.color_coding && a.worker_id < 0 => {
                        Span::styled(cell.clone(), Style::new().fg(ERROR))
                    }
                    12 if m.color_coding => {
                        Span::styled(cell.clone(), Style::new().fg(status_color(&a.status_name)))
                    }
                    13 if m.color_coding => {
                        Span::styled(cell.clone(), Style::new().fg(mode_color(a.mode())))
                    }
                    _ => Span::raw(cell.clone()),
                };
                spans.push(span);
            }
            lines.push(Line::from(spans));
        }
    }
    if detail_rows > 0 {
        while lines.len() < height - 1 { lines.push(Line::default()); }
        if let Some(a) = sorted.get(m.alloc_cursor) { lines.push(allocation_detail(a)); }
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
/// and `Reward [Q/d]` headers that were already stating those units. One
/// rendering per cell settles both, and drops the widest reward cell from 15
/// columns to 12.
fn avail_cell(m: &Model, s: &ShardRow, col: usize, fw: usize) -> String {
    match col {
        0 => avail_marker(m, s).to_string(),
        1 => center_trunc(&s.filter_hex, fw),
        2 => s.active_provers.to_string(),
        3 => fmt_ring(s.ring),
        4 => fmt_mb(&s.shard_size),
        5 => s.data_shards.to_string(),
        6 => fmt_materialized(s.materialized_frame, s.latest_frame),
        7 => if s.materialized_frame == 0 && s.latest_frame == 0 { "-".into() } else { s.latest_frame.to_string() },
        8 => s.global_head.as_ref().map(|h| h.frame.to_string()).unwrap_or_else(|| "-".into()),
        9 => { let state = materialization_state(s.materialized_frame, s.latest_frame); if matches!(state, "lag" | "unmat") { format!("{state}!") } else { state.to_string() } },
        _ => if s.ring == UNKNOWN_REWARD_RING { "-".into() } else { fmt_reward(&s.estimated_reward) },
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
                sorted
                    .iter()
                    .map(|s| printed_width(&avail_cell(m, s, c, 0))),
            )
        })
        .collect();

    let cap = filter_cap(
        &avail_header(m, 1),
        sorted.iter().map(|s| printed_width(&s.filter_hex)),
    );
    let fw = filter_width(content_width, &widths, n, cap);
    widths[1] = fw;
    (widths, fw)
}

fn avail_widths_fixed(m: &Model, content_width: usize, sorted: &[ShardRow]) -> (Vec<usize>, usize) {
    let shards_w = fit(
        SHARDS_WIDTH,
        sorted
            .iter()
            .map(|s| printed_width(&avail_cell(m, s, 5, 0))),
    );
    let reward_w = fit(
        REWARD_WIDTH,
        sorted
            .iter()
            .map(|s| printed_width(&avail_cell(m, s, 10, 0))),
    );
    let global_head_w = fit(GLOBAL_HEAD_WIDTH, sorted.iter().map(|row| printed_width(&avail_cell(m, row, 8, 0))));
    let grown = (global_head_w - GLOBAL_HEAD_WIDTH) + (shards_w - SHARDS_WIDTH) + (reward_w - REWARD_WIDTH);
    let mut fw = content_width.saturating_sub(AVAIL_FIXED_WIDTH + grown);
    for &col in &AVAIL_FILTERABLE_COLS {
        if col == 1 {
            continue;
        }
        if m.avail_col_filters
            .get(&col)
            .is_some_and(|cf| cf.is_active())
        {
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
        shards_w,
        MAT_WIDTH,
        HEAD_WIDTH,
        global_head_w,
        STATE_WIDTH,
        reward_w,
    ];
    for &col in &AVAIL_FILTERABLE_COLS {
        if col == 1 {
            continue;
        }
        if m.avail_col_filters
            .get(&col)
            .is_some_and(|cf| cf.is_active())
        {
            widths[col] += 1;
        }
    }
    if m.avail_sort_col >= 0 && (m.avail_sort_col as usize) < widths.len() {
        widths[m.avail_sort_col as usize] += 1;
    }
    (widths, fw)
}

fn available_detail(s: &ShardRow) -> Line<'static> {
    let (message, color) = match materialization_state(s.materialized_frame, s.latest_frame) {
        "unmat" => ("Warning: provider has not materialized any app frames".into(), Color::Yellow),
        "lag" => (format!("Warning: provider materialization trails its head by {} frames", s.latest_frame.saturating_sub(s.materialized_frame)), Color::Yellow),
        "current" => ("Provider materialization is current".into(), HELP),
        _ => ("Provider shard heights unavailable; health unknown".into(), HELP),
    };
    Line::from(Span::styled(format!("{} | {message}", global_head_detail(s.global_head.as_ref())), Style::new().fg(color)))
}

fn render_avail_panel(m: &mut Model, sorted: &[ShardRow], area: Rect, aligned: Option<&[usize]>) -> Vec<Line<'static>> {
    let content_width = area.width as usize;
    let height = area.height as usize;
    if sorted.is_empty() {
        if let Some(error) = &m.shard_error {
            return vec![Line::from(format!("  {error}"))];
        }
        if m.shard_loading || m.cached_shard_info.is_none() {
            return vec![Line::from(format!(
                "  {} Loading available shards…",
                spinner(m)
            ))];
        }
        return vec![Line::from("  No available shards")];
    }
    let (widths, fw) = aligned.map(|w| (w.to_vec(), w[1])).unwrap_or_else(|| avail_col_widths(m, content_width, sorted));
    let filter_hi = m.active_filter_col_idx();

    let mut hdr_spans: Vec<Span> = Vec::new();
    for i in 0..AVAIL_COL_NAMES.len() {
        let hi_sort = m.sort_mode && m.focus == PanelFocus::Available && m.sort_highlight_col == i;
        let hi_filter = m.avail_filter_mode
            && !m.filter_edit_active
            && m.focus == PanelFocus::Available
            && filter_hi == i as i32;
        let style = if hi_sort {
            Style::new()
                .bg(CURSOR_BG)
                .fg(TEXT)
                .add_modifier(Modifier::BOLD)
        } else if hi_filter {
            Style::new()
                .bg(FILTER)
                .fg(TEXT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::BOLD)
        };
        let sorted = m.avail_sort_col == i as i32;
        if i > 0 {
            hdr_spans.push(Span::raw(" "));
        }
        // Filters align on their prefix; numeric columns align on their tail.
        hdr_spans.extend(header_spans(
            &avail_header(m, i),
            widths[i],
            style,
            sorted,
            sorted && m.color_coding && !hi_sort && !hi_filter,
            i == 1,
        ));
    }
    let mut lines = Vec::new();
    if let Some(error) = &m.shard_error {
        lines.push(Line::from(Span::styled(
            format!("{error} (showing cached shards)"), Style::new().fg(Color::Yellow),
        )));
    }
    lines.push(Line::from(hdr_spans));

    let detail_rows = usize::from(height >= 3);
    let visible = height.saturating_sub(lines.len() + detail_rows).max(1);
    m.avail_offset = clamp_offset(m.avail_offset, m.avail_cursor, visible, sorted.len());
    let end = (m.avail_offset + visible).min(sorted.len());

    let shared_address = shared_filter_address(sorted.iter().map(|s| s.filter_hex.as_str()));
    let longest_suffix = sorted.iter().map(|s| s.filter_hex.len().saturating_sub(64)).max().unwrap_or(0);
    for i in m.avail_offset..end {
        let s = &sorted[i];
        let selected = i == m.avail_cursor;

        if selected {
            let cells: Vec<String> = (0..widths.len())
                .map(|c| {
                    let cell = if c == 1 && shared_address { filter_label(&s.filter_hex, fw, longest_suffix) }
                        else { avail_cell(m, s, c, fw) };
                    pad_cell(&cell, widths[c], c == 1)
                })
                .collect();
            let mut spans = Vec::new();
            for (c, cell) in cells.iter().enumerate() {
                if c > 0 { spans.push(Span::raw(" ")); }
                let color = if m.color_coding && matches!(c, 6 | 7 | 9) { materialization_state_color(materialization_state(s.materialized_frame, s.latest_frame)) } else { TEXT };
                spans.push(Span::styled(cell.clone(), Style::new().fg(color)));
            }
            let used = cells.iter().map(|cell| printed_width(cell)).sum::<usize>() + cells.len().saturating_sub(1);
            spans.push(Span::raw(" ".repeat(content_width.saturating_sub(used))));
            lines.push(Line::from(spans).style(Style::new().fg(TEXT).bg(if m.focus == PanelFocus::Available { CURSOR_BG } else { INACTIVE_CURSOR_BG })));
        } else {
            // Non-selected: size uses human-readable storage; ring colored.

            let mut spans: Vec<Span> = Vec::new();
            for c in 0..widths.len() {
                if c > 0 {
                    spans.push(Span::raw(" "));
                }
                let cell = if c == 1 && shared_address { filter_label(&s.filter_hex, fw, longest_suffix) }
                    else { avail_cell(m, s, c, fw) };
                let cell = pad_cell(&cell, widths[c], c == 1);
                spans.push(match c {
                    3 if m.color_coding => Span::styled(cell, Style::new().fg(ring_color(s.ring))),
                    6 | 7 | 9 if m.color_coding => {
                        let color = materialization_state_color(materialization_state(
                            s.materialized_frame,
                            s.latest_frame,
                        ));
                        Span::styled(cell, Style::new().fg(color))
                    }
                    _ => Span::raw(cell),
                });
            }
            lines.push(Line::from(spans));
        }
    }
    if detail_rows > 0 {
        while lines.len() < height - 1 { lines.push(Line::default()); }
        if let Some(s) = sorted.get(m.avail_cursor) { lines.push(available_detail(s)); }
    }
    lines
}

// ── Footer (actions + status) ────────────────────────────────────────────

/// Wrap between command hints, keeping each shortcut and label together.
/// The resulting lines also give the layout its exact footer height.
fn wrap_actions(actions: Line<'static>, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut line = Line::default();
    for span in actions.spans {
        // Double spaces separate hints, including in the single-span mode bars.
        // Preserve single spaces inside labels (and checkbox markers).
        for hint in span.content.split("  ").map(str::trim).filter(|hint| !hint.is_empty()) {
            let hint = Span::styled(hint.to_owned(), span.style);
            if !line.spans.is_empty() && line.width() + 2 + hint.width() > usize::from(width) {
                lines.push(line);
                line = Line::default();
            }
            if !line.spans.is_empty() {
                line.spans.push(Span::raw("  "));
            }
            line.spans.push(hint);
        }
    }
    lines.push(line);
    lines
}

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

const MESSAGE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

fn message_timestamp(time: Option<std::time::SystemTime>) -> String {
    let seconds = time.unwrap_or_else(std::time::SystemTime::now)
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("[{:02}:{:02}:{:02} UTC] ", seconds / 3600 % 24, seconds / 60 % 60, seconds % 60)
}

/// Expire completed action notices, while retaining an operation in progress
/// or a refresh failure that is still unresolved. No extra timer task needed.
fn update_message_lifetime(m: &mut Model) {
    if m.status_message_key != m.status_msg {
        m.status_message_key = m.status_msg.clone();
        m.status_message_seen = Some(std::time::Instant::now());
        m.status_message_time = Some(std::time::SystemTime::now());
    }
    if !m.action_in_flight && m.consecutive_failures == 0
        && m.status_message_seen.is_some_and(|t| t.elapsed() >= MESSAGE_TTL)
    {
        m.status_msg.clear();
        m.status_message_key.clear();
        m.status_sticky = false;
        m.status_message_seen = None;
        m.status_message_time = None;
    }
}

fn shard_severity(m: &Model) -> NoticeSeverity {
    if m.shard_error.is_some() {
        if m.cached_shard_info.is_some() { NoticeSeverity::Warning } else { NoticeSeverity::Error }
    } else if m.shard_loading && m.shard_fetch_started.is_some_and(|t| t.elapsed().as_secs() >= 15) {
        NoticeSeverity::Warning
    } else { NoticeSeverity::Info }
}

/// One short notice per current state; repeated polls do not create a feed.
fn shard_message(m: &Model) -> Option<Line<'static>> {
    let elapsed = m.shard_fetch_started.map(|t| t.elapsed().as_secs()).unwrap_or(0);
    let message = if let Some(error) = &m.shard_error {
        let reason = if error.contains("timed out") { "Shard query timed out".to_owned() }
            else { let mut text: String = error.chars().take(90).collect();
                if error.chars().count() > 90 { text.push('…'); } text };
        format!("{reason}; retrying.{}", if m.cached_shard_info.is_some() { " Cached rows retained." } else { "" })
    } else if m.shard_loading {
        if elapsed >= 15 { format!("Shard query slow ({elapsed}s); still waiting.") }
        else { format!("Fetching shard data ({elapsed}s).") }
    } else if let Some(shards) = &m.cached_shard_info {
        if m.shard_last_success.is_some_and(|t| t.elapsed() >= MESSAGE_TTL) { return None; }
        let elapsed = m.shard_last_duration.map(|d| d.as_secs()).unwrap_or(0);
        format!("Shard data updated ({} shards, {elapsed}s).", shards.shards.len())
    } else { return None; };
    let color = match shard_severity(m) { NoticeSeverity::Info => HELP,
        NoticeSeverity::Warning => Color::Yellow, NoticeSeverity::Error => ERROR };
    Some(Line::from(Span::styled(format!("{}{message}", message_timestamp(m.shard_message_time)), Style::new().fg(color))))
}

/// Wrap message words independently of the indivisible command hints above.
fn wrap_message(message: Line<'static>, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut line = Line::default();
    for span in message.spans {
        for word in span.content.split_whitespace() {
            // Long RPC tokens must also fit a narrow terminal. Split only when
            // a single word cannot fit; ordinary words wrap as whole units.
            let mut part = String::new();
            for ch in word.chars() {
                if printed_width(&part) + printed_width(&ch.to_string()) > usize::from(width) {
                    if !line.spans.is_empty() { lines.push(line); line = Line::default(); }
                    lines.push(Line::from(Span::styled(std::mem::take(&mut part), span.style)));
                }
                part.push(ch);
            }
            if !line.spans.is_empty() && line.width() + 1 + printed_width(&part) > usize::from(width) {
                lines.push(line); line = Line::default();
            }
            if !line.spans.is_empty() { line.spans.push(Span::raw(" ")); }
            line.spans.push(Span::styled(part, span.style));
        }
    }
    if !line.spans.is_empty() { lines.push(line); }
    lines
}

/// Require fresh observations for every staffed earning allocation: missing data
/// must not be reported as a demonstrated stall. Peer metadata is independent.
fn update_app_progress_warning(m: &mut Model) {
    let rows: Vec<_> = m.allocations.iter().filter(|a| matches!(a.reward_status(m.epoch_frame(), m.epoch_length), Some(EffectiveStatus::Active | EffectiveStatus::Leaving))).collect();
    let known = m.reachable && !rows.is_empty() && rows.iter().all(|a| {
        a.execution.as_ref().is_some_and(|e| e.materialized_frame.is_some() && matches!(local_execution_state(Some(e)), "starting" | "running" | "blocked" | "stopped"))
    });
    if !known { m.app_progress_observed_since = None; m.app_stall_time = None; return; }
    let observed = m.app_progress_observed_since.get_or_insert_with(std::time::Instant::now);
    let last = rows.iter().filter_map(|a| a.execution.as_ref()).map(|e| e.last_advance_unix_ms).max().unwrap_or(0);
    let now = std::time::SystemTime::now();
    let now_ms = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    let stalled = if last == 0 { observed.elapsed().as_secs() >= 60 } else { now_ms.saturating_sub(last) >= 60_000 };
    if stalled { m.app_stall_time.get_or_insert(now); } else { m.app_stall_time = None; }
}

fn message_lines(m: &Model, primary: Line<'static>, width: u16) -> Vec<Line<'static>> {
    let primary_severity = if m.status_is_error { NoticeSeverity::Error } else { NoticeSeverity::Info };
    // Filter-editor prompts are controls rather than notifications.
    let primary = if m.filter_edit_active || primary_severity >= m.notice_minimum {
        wrap_message(primary, width)
    } else { Vec::new() };
    let shard_severity = shard_severity(m);
    let shards = if shard_severity >= m.notice_minimum {
        shard_message(m).map(|line| wrap_message(line, width)).unwrap_or_default()
    } else { Vec::new() };
    let mut lines = Vec::new();
    if m.notice_minimum <= NoticeSeverity::Warning {
        if let Some(time) = m.app_stall_time {
            lines.extend(wrap_message(Line::from(Span::styled(format!("{}No local app worker has advanced for at least 60s; check allocation blockers.", message_timestamp(Some(time))), Style::new().fg(Color::Yellow))), width));
        }
    }
    if shard_severity > primary_severity { lines.extend(shards); lines.extend(primary); }
    else { lines.extend(primary); lines.extend(shards); }
    if lines.is_empty() { lines.push(Line::default()); }
    lines
}

fn status_line(m: &Model) -> Line<'static> {
    if m.action_in_flight {
        return Line::from(format!("{}{} {}", message_timestamp(m.status_message_time), spinner(m), m.status_msg));
    }
    if m.status_msg.is_empty() {
        return Line::from("");
    }
    let color = if m.status_is_error { ERROR } else { SUCCESS };
    Line::from(Span::styled(format!("{}{}", message_timestamp(m.status_message_time), m.status_msg), Style::new().fg(color)))
}

/// `renderHelpLine` — key hints with applicable actions highlighted.
fn command_hint(key: &str, description: &str, style: Style) -> Span<'static> {
    Span::styled(format!("[{key}] {description}"), style)
}

fn help_commands() -> Line<'static> {
    let mut spans = Vec::new();
    for (key, description) in [("↑/k", "up"), ("↓/j", "down"), ("Pg↑/↓", "page"), ("Home/End", "first/last"), ("h/esc", "close"), ("q", "quit")] {
        if !spans.is_empty() { spans.push(Span::raw("  ")); }
        spans.push(command_hint(key, description, Style::new().fg(HELP)));
    }
    Line::from(spans)
}

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
        } else if m.focus == PanelFocus::Available && !m.free_workers.is_empty() {
            applicable.insert("Join".to_string());
        }
    }
    let filters_active = m.has_active_filters();

    // (key, desc, action-tag)
    let entries: [(&str, &str, &str); 23] = [
        ("tab", "switch", ""),
        ("↑/k", "up", ""),
        ("↓/j", "down", ""),
        ("←/→", "columns", ""),
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
        ("e", "frames/epochs", "ThresholdUnit"),
        ("v", "notice level", ""),
        ("[/] {/}", "upper/lower edge", ""),
        ("h", "help", ""),
        ("q", "quit", ""),
    ];
    let mut spans: Vec<Span> = Vec::new();
    for (i, (key, desc, tag)) in entries.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
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
            "ThresholdUnit" => {
                if m.threshold_unit == ThresholdUnit::Epochs {
                    Style::new().fg(SUCCESS)
                } else {
                    Style::new().fg(HELP)
                }
            }
            "" => Style::new().fg(HELP),
            t if applicable.contains(t) => Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
            _ => Style::new().fg(DIM),
        };
        spans.push(command_hint(key, desc, style));
    }
    Line::from(spans)
}

fn render_filter_edit_lines(m: &Model) -> (Line<'static>, Line<'static>) {
    let col_name = if m.focus.is_alloc() {
        ALLOC_COL_NAMES
            .get(m.filter_edit_col_idx)
            .copied()
            .unwrap_or("")
    } else {
        AVAIL_COL_NAMES
            .get(m.filter_edit_col_idx)
            .copied()
            .unwrap_or("")
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
                spans.push(Span::styled(
                    format!("  {checked} {v}"),
                    Style::new().fg(HELP),
                ));
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
    (
        actions,
        Line::from(Span::styled(hint, Style::new().fg(HELP))),
    )
}

// ── Help screen ──────────────────────────────────────────────────────────

fn render_help_screen(f: &mut Frame, m: &mut Model, area: Rect) {
    let body = help_body();
    m.help_lines = body.len();
    let mut commands = wrap_actions(help_commands(), area.width);
    let footer_height = commands.len().min(usize::from(area.height.saturating_sub(3).max(1)));
    if commands.len() > footer_height {
        commands.truncate(footer_height);
        commands[footer_height - 1] = Line::from("[h/esc] close  [q] quit");
    }
    let body_height = usize::from(area.height).saturating_sub(2 + footer_height);
    m.help_visible = body_height;
    let max_offset = body.len().saturating_sub(body_height);
    m.help_offset = m.help_offset.min(max_offset);
    let title = format!(" Shard Manager — Help  ({}–{} of {})", m.help_offset + 1, (m.help_offset + body_height).min(body.len()), body.len());
    f.render_widget(Paragraph::new(Line::from(title)).style(Style::new().fg(TEXT).bg(PRIMARY).add_modifier(Modifier::BOLD)), Rect::new(area.x, area.y, area.width, area.height.min(1)));
    f.render_widget(Paragraph::new(body.into_iter().skip(m.help_offset).take(body_height).collect::<Vec<_>>()), Rect::new(area.x, area.y + area.height.min(1), area.width, body_height as u16));
    let separator_y = area.y + area.height.saturating_sub(footer_height as u16 + 1);
    f.render_widget(Paragraph::new("─".repeat(usize::from(area.width))).style(Style::new().fg(HELP)), Rect::new(area.x, separator_y, area.width, 1));
    f.render_widget(Paragraph::new(commands).style(Style::new().fg(HELP)), Rect::new(area.x, area.y + area.height.saturating_sub(footer_height as u16), area.width, footer_height as u16));
}

/// Everything under the pinned title, in one place so a test can read it.
/// A column or a key that never appears here is undocumented, and the help
/// is the only surface that says what `Lag` or `re-confirm!` mean.
fn help_body() -> Vec<Line<'static>> {
    let sec = |s: &str| {
        Line::from(Span::styled(
            s.to_string(),
            Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
        ))
    };
    let kv = |k: &str, v: &str| {
        Line::from(vec![
            Span::styled(
                format!("  {:<16}", k),
                Style::new().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(v.to_string(), Style::new().fg(HELP)),
        ])
    };
    let note = |s: &str| Line::from(Span::styled(format!("  {s}"), Style::new().fg(FILTER)));

    vec![
        Line::from(""),
        sec("Worker progress"),
        kv("LocalMat", "Local height; - unknown; 0! warns a running host has no materialized frames"),
        kv("Execution", "Host state; running with zero LocalMat is warned, not healthy progress"),
        kv("GlobalHead", "App head committed in GLOBAL; - unavailable, 0 is a known genesis head"),
        kv("PeerHead", "Provider shard head; remote metadata, not the local worker cursor"),
        kv("Details", "Selected allocation footer shows blocker and last advance; no observation timer"),

        kv("", "Selected allocation shows blocker and last advance; PeerHead is provider metadata"),
        kv("", "Observations older than 30s are stale; startup restoration is not an advance"),
        sec("Navigation"),
        kv("↑ / k", "Move cursor up"),
        kv("↓ / j", "Move cursor down"),
        kv("← / →", "Scroll table horizontally by eight columns"),
        kv("Scroll hints", "Bottom border counts hidden rows ↑/↓ and columns ←/→"),
        kv(
            "Tab",
            "Cycle Allocations, Available Shards and Notifications; Shift+Tab reverses",
        ),
        kv("Space", "Toggle selection on cursor row (advances cursor)"),
        kv("a", "Select all / deselect all rows in current table"),
        kv("Boundaries", "Top of Allocations and bottom of Notifications remain fixed"),
        Line::from(""),
        sec("Notifications"),
        kv("v", "Cycle minimum severity: warnings/errors (default), errors only, all"),
        kv("PgUp / PgDn", "When Notifications is focused, ↑/↓ scroll; Home/End jump to first/last line"),
        kv("", "[ / ] moves upper boundary up/down; { / } moves lower boundary up/down"),
        sec("Actions — Allocations panel"),
        kv(
            "l",
            "Leave  — request to leave an Active allocation (status 2)",
        ),
        kv(
            "c",
            "Confirm — confirm a pending Join/Leave once the window opens",
        ),
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
        sec("Worker picker  (opens on J)"),
        kv("↑ / k, ↓ / j", "Move cursor between free workers"),
        kv("Space", "Toggle a worker into the manual-management set"),
        kv("enter / J", "Join the shard(s); selected workers are set to Manual"),
        kv("esc", "Cancel the join"),
        Line::from(""),
        sec("Sort mode  (press s)"),
        kv("s", "Enter sort mode"),
        kv("← / →", "Move highlight to previous / next column"),
        kv("enter", "Confirm column, then choose sort order"),
        kv("a", "Ascending order"),
        kv("d", "Descending order"),
        kv("esc", "Cancel sort mode"),
        note("The sorted column's header is underlined, with ↑ or ↓ for the order."),
        Line::from(""),
        sec("Filter mode  (press f)"),
        kv("f", "Enter filter mode"),
        kv(
            "← / →",
            "Move highlight to previous / next filterable column",
        ),
        kv("enter", "Open filter editor for highlighted column"),
        kv("del / backspace", "Clear filter on highlighted column"),
        kv("x", "Disable all filters in current panel"),
        kv("esc", "Close filter mode"),
        note("An active filter marks its column header with *."),
        Line::from(""),
        sec("Filter editor  (enter, from filter mode)"),
        kv("type", "Text columns take a substring; numeric columns take an"),
        kv("", "expression like \"> 47\", \"< 100\", or a comma list \"1,5,7\""),
        kv("backspace", "Delete the last character (Ctrl+H does the same)"),
        kv("← / →", "Select columns: move between the available values"),
        kv("Space", "Select columns: toggle the value under the cursor"),
        kv("a", "Select columns: select all / deselect all values"),
        kv("enter", "Apply the filter"),
        kv("esc", "Cancel without changing the filter"),
        Line::from(""),
        sec("Columns"),
        kv("Select", "[x] marks the row for a batch action (Space, or `a` for all)"),
        kv("Filter", "Shard filter, in hex; shortened from the middle when narrow"),
        kv("Provers", "Provers currently active on the shard"),
        kv("Ring", "Prover ring the shard sits in; colour runs 0 green to 4+ red"),
        kv("Size [MB]", "Shard size, in megabytes"),
        kv("Shards", "Data shards the filter covers"),
        kv("PeerMat", "Materialized height reported by the shard metadata provider"),
        kv("GlobalHead", "App head committed in GLOBAL; - unavailable, 0 is a known genesis head"),
        kv("PeerHead", "Provider shard head; remote metadata"),
        kv("PeerState", "Reading of PeerMat and PeerHead; lag!/unmat! flag provider warnings"),
        kv("Cursor", "Inactive cursor stays visible to bind the detail below to its row"),
        kv("GLOBAL citation", "Selected-row detail: committed GLOBAL frame and session generation"),
        kv("", "Independent of LocalMat and peer metadata; absent on older servers"),
        kv("", "lag: behind it; unmat: nothing materialized; unknown: no head"),
        kv(
            "Reward [Q/d]",
            "Estimated whole QUIL per day; `<1` is a trickle, not nothing",
        ),
        kv("Current", "Staffed active + leaving reward estimates, not measured income"),
        kv("Paused", "Staffed paused estimates available upon resume"),
        kv("Unknown", "- fields are unavailable; Current sums known rewards with + for unknown rows"),
        kv("Planned change", "Staffed joining minus leaving; activation epochs may differ"),
        note("Reward totals follow displayed rows; unassigned rows are excluded."),
        kv("Worker", "Core the allocation is bound to; -1 means none is bound"),
        kv("Status", "joining, active, paused, leaving, rejected, kicked;"),
        kv("", "expiredJoin / expiredLeave: confirm window missed;"),
        kv("", "re-confirm!: the allocation's epoch is stale but recoverable"),
        kv("Mode", "Worker management — a: automatic, m: manual (toggle with M)"),
        kv("Next Action", "What you can do now, and the threshold it applies from"),
        kv(
            "Default Action",
            "What the network does if you do nothing, and when",
        ),
        note("Thresholds read f<frame> or e<epoch>; press e to switch. Q/d is whole"),
        note("QUIL per day, MB is megabytes. Available Shards shows the same columns,"),
        note("minus the ones that only exist once a shard is allocated to you."),
        Line::from(""),
        sec("General"),
        kv("R", "Force data refresh"),
        kv(
            "C",
            "Toggle color-coding of Ring, Mat/Lag/State, Worker, Status and Mode",
        ),
        kv("w", "Column widths: sized to content (default) or fixed"),
        kv(
            "e",
            "Show Next/Default Action thresholds as frames (f…) or epochs (e…)",
        ),
        kv("h", "Open this help screen (↑/↓ or PgUp/PgDn scroll; h or esc closes)"),
        kv("q / Ctrl+C", "Quit"),
        Line::from(""),
    ]
}

// ── Join worker picker ───────────────────────────────────────────────────

fn render_join_picker(f: &mut Frame, m: &mut Model, area: Rect) {
    let mut lines = vec![
        Line::from(Span::styled(
            format!(
                "{:<width$}",
                " Select workers to mark as manually managed",
                width = area.width as usize
            ),
            Style::new()
                .fg(TEXT)
                .bg(PRIMARY)
                .add_modifier(Modifier::BOLD),
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
        let cursor = if i == m.join_picker_cursor {
            "> "
        } else {
            "  "
        };
        let text = format!("{cursor}{marker} Worker {wid}");
        if i == m.join_picker_cursor {
            lines.push(Line::from(Span::styled(
                text,
                Style::new().fg(TEXT).bg(PRIMARY),
            )));
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
    use crate::commands::node::prover::epoch::ActionHint;

    #[test]
    fn scroll_indicators_track_hidden_rows_and_columns() {
        assert_eq!(scroll_hint(0, 3, 3, 0, 0), "");
        assert_eq!(scroll_hint(2, 10, 3, 8, 20), " ↑2 ↓5 | ←8 →12 ");
        assert_eq!(scroll_hint(7, 10, 3, 20, 20), " ↑7 ↓0 | ←20 →0 ");
        let mut m = Model::new(); m.horizontal_offsets[0] = 20;
        assert_eq!(table_horizontal_offset(&mut m, 0, &[Line::from("x".repeat(50))], 30), 20);
        assert_eq!(table_horizontal_offset(&mut m, 0, &[Line::from("x")], 30), 0);
        assert_eq!(m.horizontal_limits[0], 0);
    }

    #[test]
    fn a_boundary_moves_immediately_after_terminal_resize_clips_its_offset() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut m = Model::new(); m.panel_boundary_offsets = [100, -100];
        let before = sync_panel_heights(&mut m, 13);
        super::super::update::handle_key(&mut m, KeyEvent::new(KeyCode::Char('{'), KeyModifiers::NONE));
        let after = sync_panel_heights(&mut m, 13);
        assert_eq!(after, [before[0] - 1, before[1] + 1, before[2]]);
    }

    #[test]
    fn resized_panels_preserve_terminal_budget_and_minimum_rows() {
        let mut m = Model::new();
        for offsets in [[0, 0], [8, -2], [-100, 100], [100, -100]] {
            m.panel_boundary_offsets = offsets;
            for total in [6, 12, 25, 60] {
                let h = panel_heights(&m, total);
                assert_eq!(h.iter().sum::<u16>(), total);
                assert!(h[0] >= 3 && h[1] >= 2 && h[2] >= 1, "{offsets:?}: {h:?}");
            }
        }
    }

    #[test]
    fn shared_columns_align_with_different_data_and_filter_markers() {
        let mut m = Model::new();
        let allocations = [row("aabb0123456789", 1, 1, 7, "", "")];
        let mut peer = shard("ccdd0123456789", 12345, 10000);
        peer.latest_frame = 987654321;
        let available = [peer];
        for sizing in [ColumnSizing::Dynamic, ColumnSizing::Fixed] {
            m.column_sizing = sizing;
            let (a, v) = shared_col_widths(&m, 240, &allocations, &available);
            assert_eq!(&a[..v.len()], v.as_slice());
            assert!(a.iter().sum::<usize>() + a.len() - 1 <= 240);
            let alloc = render_alloc_panel(&mut m, &allocations, Rect::new(0, 0, 240, 5), Some(&a))[0].to_string();
            let avail = render_avail_panel(&mut m, &available, Rect::new(0, 0, 240, 5), Some(&v))[0].to_string();
            for label in ["Filter", "Provers", "Ring", "Size", "Shards", "PeerHead", "GlobalHead", "Reward"] {
                assert_eq!(printed_width(&alloc[..alloc.find(label).unwrap()]), printed_width(&avail[..avail.find(label).unwrap()]), "{label}: {alloc} / {avail}");
            }
            assert!(!avail.contains("LocalMat"));
            assert!(!avail.contains("Execution"));
            assert_eq!(avail_cell(&m, &available[0], 7, v[1]), "987654321");
        }
    }

    #[test]
    fn app_stall_warning_respects_severity_and_clears_on_progress_or_missing_data() {
        use quil_types::proto::node::WorkerExecution;
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut m = Model::new(); m.frame_number = 2160; m.epoch_length = 720; m.reachable = true;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let mut worker = row("aa", 1, 1, 7, "", ""); worker.status = 2; worker.epoch = 3;
        worker.execution = Some(WorkerExecution { state: "blocked".into(), materialized_frame: Some(744), observed_unix_ms: now, last_advance_unix_ms: now - 120_000, ..Default::default() });
        m.allocations = vec![worker.clone(), worker];
        update_app_progress_warning(&mut m);
        let timestamp = m.app_stall_time.expect("known stalled workers warn");
        update_app_progress_warning(&mut m); assert_eq!(m.app_stall_time, Some(timestamp));
        m.notice_minimum = NoticeSeverity::Warning;
        assert!(message_lines(&m, Line::default(), 240).iter().any(|l| l.to_string().contains("No local app worker")));
        m.notice_minimum = NoticeSeverity::Error;
        assert!(!message_lines(&m, Line::default(), 240).iter().any(|l| l.to_string().contains("No local app worker")));
        m.allocations[1].execution.as_mut().unwrap().last_advance_unix_ms = now;
        update_app_progress_warning(&mut m); assert!(m.app_stall_time.is_none());
        m.allocations[1].execution = None;
        update_app_progress_warning(&mut m); assert!(m.app_stall_time.is_none());
        assert!(m.app_progress_observed_since.is_none());
    }

    #[test]
    fn worker_context_stays_in_allocation_panel_and_zero_frames_warns() {
        use quil_types::proto::node::WorkerExecution;
        let mut m = Model::new();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let mut worker = row("01", 2, 1, 7, "", "");
        worker.execution = Some(WorkerExecution { state: "running".into(), observed_unix_ms: now,
            materialized_frame: Some(124), last_advance_unix_ms: now - 22_000, ..Default::default() });
        worker.latest_frame = 125;
        assert!(!local_warning(&worker));
        assert_eq!(alloc_cell(&m, &worker, 7, 12), "125");
        assert!(allocation_detail(&worker).to_string().contains("Last advance: 22s ago"));
        worker.execution.as_mut().unwrap().materialized_frame = Some(0);
        assert!(local_warning(&worker));
        assert_eq!(alloc_cell(&m, &worker, 6, 12), "0!");
        assert_eq!(local_color(&worker), Color::Yellow);
        assert!(allocation_detail(&worker).to_string().contains("Warning: no materialized frames"));
        worker.execution.as_mut().unwrap().state = "blocked".into();
        worker.execution.as_mut().unwrap().blocker = "awaiting successor".into();
        m.allocations.push(worker);
        for minimum in [NoticeSeverity::Info, NoticeSeverity::Warning, NoticeSeverity::Error] {
            m.notice_minimum = minimum;
            let notices = message_lines(&m, Line::default(), 150).iter().map(Line::to_string).collect::<String>();
            assert!(!notices.contains("Worker") && !notices.contains("awaiting successor"));
        }
        let rows = m.allocations.clone();
        let panel = render_alloc_panel(&mut m, &rows, Rect::new(0, 0, 154, 7), None);
        let details = panel.last().unwrap().to_string();
        assert!(details.contains("Blocker: awaiting successor"));
        assert!(!details.contains("observation") && !details.contains("Worker 7"));
    }

    #[test]
    fn current_reward_total_retains_known_subtotal_when_other_rows_are_unknown() {
        let mut m = Model::new(); m.frame_number = 2160; m.epoch_length = 720;
        let mut known = row("aa", 1, 1, 7, "", "");
        known.status = 2; known.epoch = 3; known.estimated_reward = BigInt::from(10000);
        let mut unknown = known.clone(); unknown.ring = UNKNOWN_REWARD_RING;
        let title = alloc_title(&m, &[known.clone(), unknown.clone()]).to_string();
        assert!(title.contains(&format!("Current {}+ |", fmt_reward(&known.estimated_reward))), "{title}");
        assert!(alloc_title(&m, &[unknown]).to_string().contains("Current ? |"));
        known.estimated_reward = BigInt::from(0);
        let mut unknown = known.clone(); unknown.ring = UNKNOWN_REWARD_RING;
        assert!(alloc_title(&m, &[known, unknown]).to_string().contains("Current 0+ |"));
    }

    #[test]
    fn all_actual_notices_have_utc_timestamps() {
        let mut m = Model::new(); m.status_msg = "Action failed".into(); m.status_is_error = true;
        let action = status_line(&m).to_string();
        assert!(action.starts_with('[') && action.contains(" UTC] Action failed"));
        m.shard_error = Some("timed out".into());
        assert!(shard_message(&m).unwrap().to_string().contains(" UTC] Shard query timed out"));
    }

    #[test]
    fn claimable_five_decimals_preserve_zero_tiny_values_and_rounding_carry() {
        for (units, expected) in [(0, "0"), (1, "<0.00001"), (79_999, "<0.00001"), (80_000, "0.00001"), (119_999, "0.00001"), (120_000, "0.00002"), (474_867, "0.00006"), (40_000_000_000, "5"), (7_999_999_999, "1")] {
            assert_eq!(fmt_claimable(units), expected);
        }
        assert!(fmt_claimable(u128::MAX).split('.').nth(1).is_none_or(|fraction| fraction.len() <= 5));
    }

    #[test]
    fn global_app_cursor_stays_distinct_from_peer_and_local_heights() {
        let mut allocation = row("aa", 1, 1, 7, "", "");
        allocation.latest_frame = 744;
        allocation.global_head = Some(quil_types::proto::node::GlobalAppFrameHead { frame: 742, global_frame: 1000, generation: 2 });
        allocation.execution = Some(quil_types::proto::node::WorkerExecution { materialized_frame: Some(744), ..Default::default() });
        assert!(allocation_detail(&allocation).to_string().contains("GLOBAL @f1000 (gen 2)"));
        let m = Model::new();
        assert_eq!(alloc_cell(&m, &allocation, 8, 0), "742");
        assert_eq!(alloc_cell(&m, &allocation, 7, 0), "744");
        let mut peer = shard("bb", 1, 1); peer.latest_frame = 900;
        peer.global_head = allocation.global_head.clone();
        assert!(available_detail(&peer).to_string().contains("GLOBAL @f1000"));
        assert_eq!(avail_cell(&m, &peer, 8, 0), "742");
        assert_eq!(avail_cell(&m, &peer, 7, 0), "900");
        peer.global_head = None;
        assert_eq!(avail_cell(&m, &peer, 8, 0), "-");
        assert!(avail_row_numeric_val(&peer, 8).is_nan());
        peer.global_head = Some(Default::default());
        assert_eq!(avail_cell(&m, &peer, 8, 0), "0");
        assert_eq!(avail_row_numeric_val(&peer, 8), 0.0);
        assert_eq!(global_head_detail(None), "GLOBAL app head: unavailable");
        assert!(global_head_detail(Some(&quil_types::proto::node::GlobalAppFrameHead::default())).contains("GLOBAL @f0"));
    }

    #[test]
    fn panel_detail_warnings_use_the_same_color() {
        let mut allocation = row("aa", 1, 1, 7, "", "");
        allocation.execution = Some(quil_types::proto::node::WorkerExecution {
            state: "blocked".into(), blocker: "awaiting successor".into(), ..Default::default()
        });
        let mut peer = shard("bb", 1, 1);
        peer.materialized_frame = 18; peer.latest_frame = 22;
        assert!(allocation_detail(&allocation).spans.iter().all(|s| s.style.fg == Some(Color::Yellow)));
        assert!(available_detail(&peer).spans.iter().all(|s| s.style.fg == Some(Color::Yellow)));
    }

    #[test]
    fn global_head_columns_sort_and_filter_without_confusing_unknown_and_zero() {
        let mut m = Model::new();
        for (id, head) in [("a", Some(742)), ("b", None), ("c", Some(0))] {
            let mut a = row(id, 1, 1, 7, "", "");
            a.global_head = head.map(|frame| quil_types::proto::node::GlobalAppFrameHead { frame, global_frame: 1000, generation: 2 });
            let mut s = shard(id, 1, 1); s.global_head = a.global_head.clone();
            m.allocations.push(a); m.available.push(s);
        }
        m.alloc_sort_col = 8; m.alloc_sort_asc = true;
        m.avail_sort_col = 8; m.avail_sort_asc = true;
        assert_eq!(m.sorted_allocations().iter().map(|r| r.filter_key.as_str()).collect::<Vec<_>>(), vec!["b", "c", "a"]);
        assert_eq!(m.sorted_available().iter().map(|r| r.filter_key.as_str()).collect::<Vec<_>>(), vec!["b", "c", "a"]);
        let filter = ColumnFilter { expr: "=0".into(), ..Default::default() };
        m.alloc_col_filters.insert(8, filter.clone()); m.avail_col_filters.insert(8, filter);
        assert_eq!(m.filtered_allocations()[0].filter_key, "c");
        assert_eq!(m.filtered_allocations().len(), 1);
        assert_eq!(m.filtered_available()[0].filter_key, "c");
        assert_eq!(m.filtered_available().len(), 1);
    }

    #[test]
    fn inactive_cursors_bind_both_panel_details_and_keep_peer_warnings_visible() {
        let mut m = Model::new(); m.focus = PanelFocus::Notifications;
        let mut allocation = row("aa", 1, 1, 7, "", "");
        allocation.execution = Some(quil_types::proto::node::WorkerExecution { state: "blocked".into(), blocker: "awaiting successor".into(), ..Default::default() });
        let allocations = render_alloc_panel(&mut m, &[allocation], Rect::new(0, 0, 240, 5), None);
        assert_eq!(allocations[1].style.bg, Some(INACTIVE_CURSOR_BG));
        assert!(allocations.last().unwrap().to_string().contains("awaiting successor"));
        let mut peer = shard("bb", 1, 1); peer.latest_frame = 20;
        let peers = render_avail_panel(&mut m, &[peer.clone()], Rect::new(0, 0, 240, 5), None);
        assert_eq!(peers[1].style.bg, Some(INACTIVE_CURSOR_BG));
        assert!(peers[1].to_string().contains("unmat!"));
        assert!(peers.last().unwrap().to_string().contains("Warning: provider has not materialized"));
        peer.materialized_frame = 15;
        assert!(available_detail(&peer).to_string().contains("by 5 frames"));
        peer.materialized_frame = 20;
        assert!(!available_detail(&peer).to_string().contains("Warning"));
        peer.latest_frame = 0; peer.materialized_frame = 0;
        assert!(available_detail(&peer).to_string().contains("health unknown"));
    }

    #[test]
    fn claimable_header_distinguishes_loading_missing_verified_and_stale() {
        let mut m = Model::new();
        assert_eq!(claimable_title(&m), "Claimable [Q]: loading");
        super::super::update::apply_msg(&mut m, super::super::msg::Msg::RewardRefresh(Ok(Some((474867, 862280)))));
        assert_eq!(claimable_title(&m), "Claimable [Q]: 0.00006 @f862280");
        assert!(alloc_title(&m, &[]).to_string().contains("Claimable [Q]:"));
        m.reward_last_success = Some(std::time::Instant::now() - std::time::Duration::from_secs(31));
        assert!(claimable_title(&m).ends_with("(stale)"));
        super::super::update::apply_msg(&mut m, super::super::msg::Msg::RewardRefresh(Err("timeout".into())));
        assert_eq!(claimable_title(&m), "Claimable [Q]: unavailable");
        super::super::update::apply_msg(&mut m, super::super::msg::Msg::RewardRefresh(Ok(None)));
        assert_eq!(claimable_title(&m), "Claimable [Q]: unavailable");
    }

    #[test]
    fn severity_filter_hides_routine_updates_and_preserves_errors() {
        use std::time::{Duration, Instant};
        let mut m = Model::new();
        m.shard_loading = true;
        m.shard_fetch_started = Some(Instant::now());
        let text = |m: &Model| message_lines(m, status_line(m), 80).iter().map(ToString::to_string).collect::<String>();
        assert!(text(&m).is_empty(), "default warnings filter hides routine fetches");
        m.shard_fetch_started = Some(Instant::now() - Duration::from_secs(16));
        assert!(text(&m).contains("slow (16s)"));
        m.notice_minimum = NoticeSeverity::Error;
        assert!(text(&m).is_empty());
        m.shard_error = Some("Shard query timed out".into());
        assert!(text(&m).contains("timed out"), "missing data is an error");
        m.cached_shard_info = Some(Default::default());
        assert!(text(&m).is_empty(), "cache-preserving failures are warnings");
        m.notice_minimum = NoticeSeverity::Warning;
        assert!(text(&m).contains("Cached rows retained"));
        m.status_is_error = true;
        m.status_msg = "Action failed".into();
        m.notice_minimum = NoticeSeverity::Error;
        assert!(text(&m).contains("Action failed"));
        assert!(!text(&m).contains("Cached rows"));
    }

    #[test]
    fn notification_panel_geometry_stays_fixed_and_commands_stay_at_bottom() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut m = Model::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        let mut notification_rows = Vec::new();
        let mut available_rows = Vec::new();
        for message in ["", "Short warning", "A long error notification ".repeat(20).as_str()] {
            m.status_msg = message.to_owned();
            m.status_is_error = true;
            terminal.draw(|f| draw(f, &mut m)).unwrap();
            let buffer = terminal.backend().buffer();
            let rows = (0..30).map(|y| (0..80).map(|x| buffer[(x,y)].symbol()).collect::<String>()).collect::<Vec<_>>();
            notification_rows.push(rows.iter().position(|row| row.contains("Notifications:")).unwrap());
            available_rows.push(rows.iter().position(|row| row.contains("Available Shards:")).unwrap());
            for title in ["Allocations:", "Available Shards:", "Notifications:"] {
                let row = rows.iter().find(|row| row.contains(title)).unwrap();
                assert!(row.starts_with('╭') && row.ends_with('╮'), "title must share its panel border: {row}");
                let y = rows.iter().position(|candidate| candidate == row).unwrap() as u16;
                let cell = &buffer[(2, y)];
                assert_eq!(cell.fg, PRIMARY, "panel titles share the primary color");
                assert!(cell.modifier.contains(Modifier::BOLD), "panel titles share bold weight");
            }
            assert_eq!(rows.iter().position(|row| row.contains("Allocations:")), Some(1));
            assert_eq!(m.notice_visible, 3);
            assert!(rows[29].contains("[q]"));
        }
        assert!(notification_rows.iter().all(|y| *y == notification_rows[0]));
        assert!(available_rows.iter().all(|y| *y == available_rows[0]));
    }

    #[test]
    fn completed_notices_expire_but_unresolved_warnings_stay_visible() {
        use std::time::{Duration, Instant, UNIX_EPOCH};
        assert_eq!(message_timestamp(Some(UNIX_EPOCH + Duration::from_secs(3723))), "[01:02:03 UTC] ");
        let mut m = Model::new();
        m.status_msg = "Confirm completed".into();
        m.status_sticky = true;
        update_message_lifetime(&mut m);
        assert!(m.status_message_time.is_some());
        m.status_message_seen = Some(Instant::now() - Duration::from_secs(31));
        update_message_lifetime(&mut m);
        assert!(m.status_msg.is_empty());
        assert!(!m.status_sticky);
        m.cached_shard_info = Some(Default::default());
        m.shard_last_success = Some(Instant::now() - Duration::from_secs(31));
        assert!(shard_message(&m).is_none());
        m.shard_error = Some("Query failed".into());
        assert!(shard_message(&m).unwrap().to_string().contains("Query failed"));
        m.status_msg = "Refresh failed: disconnected".into();
        update_message_lifetime(&mut m);
        m.consecutive_failures = 1;
        m.status_message_seen = Some(Instant::now() - Duration::from_secs(31));
        update_message_lifetime(&mut m);
        assert!(m.status_msg.contains("disconnected"));
    }

    #[test]
    fn refresh_messages_preserve_action_status_and_explain_wait_retry_and_recovery() {
        use std::time::Instant;
        let mut m = Model::new();
        m.status_msg = "Confirm sent. Awaiting registry...".into();
        m.action_in_flight = true;
        m.notice_minimum = NoticeSeverity::Info;
        m.shard_loading = true;
        m.shard_fetch_started = Some(Instant::now());
        let text = |lines: Vec<Line<'static>>| lines.into_iter().map(|l| l.to_string()).collect::<Vec<_>>().join(" ");
        let waiting = text(message_lines(&m, status_line(&m), 60));
        assert!(waiting.contains("Confirm sent"));
        assert!(waiting.contains("Fetching shard data"));
        assert!(!waiting.contains("archive peers"));
        m.shard_error = Some("Shard query timed out".into());
        let retry = text(message_lines(&m, status_line(&m), 60));
        assert!(retry.contains("retrying"));
        assert!(retry.contains("timed out"));
        m.shard_loading = false;
        assert!(text(message_lines(&m, status_line(&m), 60)).contains("retrying"));
        m.shard_error = None;
        m.cached_shard_info = Some(Default::default());
        m.shard_last_duration = Some(std::time::Duration::from_secs(22));
        let recovered = text(message_lines(&m, status_line(&m), 60));
        assert!(recovered.contains("0 shards, 22s"));
        assert!(!recovered.contains("timed out"));
    }

    #[test]
    fn message_footer_wraps_words_and_long_rpc_tokens_without_losing_text() {
        use ratatui::{backend::TestBackend, Terminal};
        let message = "Shard query timed out; retrying automatically while showing cached rows.";
        let style = Style::new().fg(Color::Yellow);
        let lines = wrap_message(Line::from(Span::styled(message, style)), 40);
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|line| line.width() <= 40));
        assert_eq!(lines.iter().map(ToString::to_string).collect::<Vec<_>>().join(" "), message);
        let token = "x".repeat(105);
        let lines = wrap_message(Line::from(token.clone()), 40);
        assert!(lines.iter().all(|line| line.width() <= 40));
        assert_eq!(lines.iter().map(ToString::to_string).collect::<String>(), token);
        let mut m = Model::new();
        m.status_msg = message.into();
        m.status_is_error = true;
        let mut terminal = Terminal::new(TestBackend::new(40, 24)).unwrap();
        terminal.draw(|f| draw(f, &mut m)).unwrap();
        let buffer = terminal.backend().buffer();
        let rows = (0..24).map(|y| (0..40).map(|x| buffer[(x, y)].symbol()).collect::<String>()).collect::<Vec<_>>();
        let screen = rows.iter().map(|line| line.trim().trim_matches('│').trim()).collect::<Vec<_>>().join(" ");
        assert!(screen.contains(message));
        assert!(screen.contains("Notifications"));
        assert!(screen.contains("[q]"));
    }

    #[test]
    fn missing_shard_data_is_loading_or_failed_instead_of_empty() {
        let mut m = Model::new();
        m.data_loaded = true;
        let text = |lines: Vec<Line<'static>>| lines[0].spans.iter()
            .map(|span| span.content.as_ref()).collect::<String>();
        assert!(text(render_avail_panel(&mut m, &[], Rect::new(0, 0, 100, 5), None))
            .contains("Loading available shards"));
        m.shard_error = Some("Shard data timed out after 60s; retrying".into());
        assert!(text(render_avail_panel(&mut m, &[], Rect::new(0, 0, 100, 5), None))
            .contains("timed out"));
        m.shard_error = None;
        m.cached_shard_info = Some(Default::default());
        assert!(text(render_avail_panel(&mut m, &[], Rect::new(0, 0, 100, 5), None))
            .contains("No available shards"));
    }

    #[test]
    fn local_worker_state_is_independent_of_remote_shard_cursor() {
        let m = Model::new();
        let mut a = row("01", 1, 1, 4, "", "");
        a.materialized_frame = 91;
        a.latest_frame = 93;
        a.execution = Some(quil_types::proto::node::WorkerExecution {
            state: "blocked".into(), blocker: "checkpoint mismatch".into(),
            materialized_frame: Some(93),
            observed_unix_ms: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
            ..Default::default()
        });
        assert_eq!(alloc_cell(&m, &a, 6, 12), "93");
        assert_eq!(alloc_cell(&m, &a, 7, 12), "93");
        assert_eq!(alloc_cell(&m, &a, 9, 12), "blocked");
        a.materialized_frame = 93;
        assert_eq!(alloc_cell(&m, &a, 9, 12), "blocked");
        a.execution = None;
        assert_eq!(alloc_cell(&m, &a, 6, 12), "-");
        assert_eq!(alloc_cell(&m, &a, 9, 12), "unknown");
    }

    #[test]
    fn state_cells_use_lowercase_and_keep_their_colors() {
        let m = Model::new();
        for (mat, head, label, color) in [
            (0, 0, "unknown", HELP),
            (0, 10, "unmat", ERROR),
            (5, 10, "lag", ERROR),
            (10, 10, "current", SUCCESS),
            (11, 10, "current", SUCCESS),
        ] {
            let mut a = row("01", 1, 1, 1, "", "");
            a.materialized_frame = mat;
            a.latest_frame = head;
            let mut s = shard("01", 0, 0);
            s.materialized_frame = mat;
            s.latest_frame = head;
            assert_eq!(alloc_cell(&m, &a, 9, 12), "unknown");
            assert_eq!(avail_cell(&m, &s, 9, 12), if matches!(label, "lag" | "unmat") { format!("{label}!") } else { label.to_string() });
            assert_eq!(materialization_state_color(label), color);
        }
    }

    #[test]
    fn command_footer_wraps_and_leaves_status_visible() {
        use ratatui::{backend::TestBackend, Terminal};
        for width in [40, 80, 100, 160, 320] {
            let mut m = Model::new();
            m.status_msg = "status is visible".to_owned();
            m.notice_minimum = NoticeSeverity::Info;
            let lines = wrap_actions(help_line(&m), width);
            for hint in help_line(&m).spans.into_iter().filter(|span| !span.content.trim().is_empty()) {
                assert!(lines.iter().any(|line| line.spans.iter().any(|span| span == &hint)),
                    "split command hint at width {width}: {}", hint.content);
            }
            assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
            if width == 40 {
                assert!(lines.len() > 1);
            }
            let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
            terminal.draw(|f| draw(f, &mut m)).unwrap();
            let buffer = terminal.backend().buffer();
            let footer_start = 24 - lines.len() as u16;
            let footer = (footer_start..24).map(|y| {
                (0..width).map(|x| buffer[(x, y)].symbol()).collect::<String>()
            }).collect::<Vec<_>>().join(" ");
            for key in ["[tab]", "[J]", "[C]", "[e]", "[h]", "[q]"] {
                assert!(footer.contains(key), "missing {key} at width {width}: {footer}");
            }
            let status = (0..width).map(|x| buffer[(x, 23)].symbol()).collect::<String>();
            let screen = (0..24).map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect::<String>()).collect::<Vec<_>>().join(" ");
            assert!(screen.contains("status is visible"));
            assert!(status.contains("[q]"));
        }
    }

    #[test]
    fn mode_footer_keeps_multiword_labels_and_styles_together() {
        let style = Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD);
        let lines = wrap_actions(Line::from(Span::styled(
            "Sort: [←/→] Move column  [enter] apply  [esc] cancel", style,
        )), 25);
        assert_eq!(lines.len(), 3);
        for (line, expected) in lines.iter().zip([
            "Sort: [←/→] Move column", "[enter] apply", "[esc] cancel",
        ]) {
            assert_eq!(line.spans, vec![Span::styled(expected, style)]);
        }
    }

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
            global_head: None,
            execution: None,
            shard_info_known: true,
            filter: Vec::new(),
            filter_key: hex.to_string(),
            filter_hex: hex.to_string(),
            status: 1,
            status_name: "joining".to_string(),
            ring: 5,
            active_provers: provers,
            shard_size: BigInt::from(0),
            data_shards: shards,
            materialized_frame: 0,
            latest_frame: 0,
            estimated_reward: BigInt::from(0),
            join_frame: 0,
            leave_frame: 0,
            worker_id: worker,
            next_action: ActionHint::text(next),
            default_action: ActionHint::text(dflt),
            manually_managed: false,
            confirm_frame: 0,
            leave_confirm_frame: 0,
            epoch: 0,
            last_active_frame: 0,
        }
    }

    #[test]
    fn filter_prefixes_align_in_both_panels_with_selected_rows() {
        let mut m = Model::new();
        let allocations = [row("aabb01", 1, 1, 0, "", ""), row("aabb012345", 1, 1, 1, "", "")];
        let available = [shard("aabb01", 1, 1), shard("aabb012345", 1, 1)];
        for focus in [PanelFocus::Allocations, PanelFocus::Available] {
            m.focus = focus;
            for cursor in [0, 1] {
                m.alloc_cursor = cursor;
                m.avail_cursor = cursor;
                for lines in [
                    render_alloc_panel(&mut m, &allocations, Rect::new(0, 0, 240, 5), None),
                    render_avail_panel(&mut m, &available, Rect::new(0, 0, 240, 5), None),
                ] {
                    let text: Vec<String> = lines.iter().map(|line| line.spans.iter().map(|span| span.content.as_ref()).collect()).collect();
                    assert_eq!(text[1].find("aabb"), text[2].find("aabb"));
                    assert!(text[1].contains("aabb01"));
                    assert!(text[2].contains("aabb012345"));
                }
            }
        }
    }

    #[test]
    fn missing_shard_rows_display_unknown_but_measured_zero_rows_remain_numeric() {
        let model = Model::new();
        let mut allocation = row("aa", 0, 0, 1, "", "");
        allocation.shard_info_known = false;
        for col in [2, 3, 4, 5, 6, 7, 10] {
            assert_eq!(alloc_cell(&model, &allocation, col, 12), "-");
        }
        assert_eq!(alloc_cell(&model, &allocation, 9, 12), "unknown");
        allocation.shard_info_known = true;
        for col in [2, 5] { assert_eq!(alloc_cell(&model, &allocation, col, 12), "0"); }
        assert_eq!(alloc_cell(&model, &allocation, 4, 12), fmt_mb(&BigInt::from(0)));
    }

    #[test]
    fn unavailable_values_are_not_rendered_as_zero_rewards_or_heights() {
        let mut model = Model::new();
        model.frame_number = 2160;
        model.epoch_length = 720;
        let mut allocation = row("aa", 1, 1, 0, "", "");
        allocation.filter = vec![0xaa];
        allocation.status = 2;
        allocation.epoch = 3;
        allocation.ring = UNKNOWN_REWARD_RING;
        for col in [3, 6, 7, 10] { assert_eq!(alloc_cell(&model, &allocation, col, 12), "-"); }
        assert_eq!(alloc_cell(&model, &allocation, 9, 12), "unknown");
        assert_eq!(ring_color(UNKNOWN_REWARD_RING), HELP);
        let mut available = shard("bb", 1, 1);
        available.ring = UNKNOWN_REWARD_RING;
        for col in [3, 6, 7, 10] { assert_eq!(avail_cell(&model, &available, col, 12), "-"); }
        let title = alloc_title(&model, &[allocation.clone()]);
        let text: String = title.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("Current ? | Paused 0 | Planned change 0"), "{text}");
        allocation.ring = 0;
        allocation.latest_frame = 20;
        assert_eq!(alloc_cell(&model, &allocation, 3, 12), "0");
        assert_eq!(alloc_cell(&model, &allocation, 6, 12), "-");
        // A remote head does not establish the local worker's cursor.
        allocation.execution = Some(quil_types::proto::node::WorkerExecution {
            materialized_frame: Some(0), ..Default::default()
        });
        assert_eq!(alloc_cell(&model, &allocation, 6, 12), "0");
        assert_eq!(alloc_cell(&model, &allocation, 7, 12), "20");
        assert_eq!(alloc_cell(&model, &allocation, 9, 12), "stale");
        assert_eq!(alloc_cell(&model, &allocation, 10, 12), "0");
    }

    #[test]
    fn reward_totals_separate_current_paused_and_planned_changes() {
        let mut m = Model::new();
        m.frame_number = 2160;
        m.epoch_length = 720;
        let mut active = row("aa", 1, 1, 0, "", "");
        active.filter = vec![0xaa];
        active.status = 2;
        active.epoch = 3;
        active.estimated_reward = BigInt::from(10000);
        let mut joining = active.clone();
        // Raw Active does not earn yet when confirmation defers activation.
        joining.confirm_frame = 2160;
        joining.estimated_reward = BigInt::from(20000);
        let mut unstaffed = joining.clone();
        unstaffed.worker_id = -1;
        unstaffed.estimated_reward = BigInt::from(900000);
        let mut expired = active.clone();
        expired.epoch = 2;
        expired.estimated_reward = BigInt::from(800000);
        let mut paused = active.clone();
        paused.status = 3;
        paused.estimated_reward = BigInt::from(40000);
        let mut leaving = active.clone();
        leaving.status = 4;
        leaving.leave_frame = 2100;
        leaving.leave_confirm_frame = 2160;
        leaving.estimated_reward = BigInt::from(50000);
        let mut unstaffed_leave = leaving.clone();
        unstaffed_leave.worker_id = -1;
        let mut ended = leaving.clone();
        ended.leave_confirm_frame = 1400;
        let title = alloc_title(&m, &[active, joining, unstaffed, expired, paused, leaving, unstaffed_leave, ended]);
        let text: String = title.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains(&format!("Current {} | Paused {} | Planned change -{}",
            fmt_reward(&BigInt::from(60000)), fmt_reward(&BigInt::from(40000)),
            fmt_reward(&BigInt::from(30000)))), "{text}");
    }

    #[test]
    fn planned_reward_change_preserves_sign_and_small_amounts() {
        assert_eq!(fmt_reward_change(&BigInt::from(0)), "0");
        assert_eq!(fmt_reward_change(&BigInt::from(1)), "+<1");
        assert_eq!(fmt_reward_change(&BigInt::from(-1)), "-<1");
        assert_eq!(fmt_reward_change(&BigInt::from(3_124_022)), "+270");
        assert_eq!(fmt_reward_change(&BigInt::from(-3_124_022)), "-270");
    }

    #[test]
    fn unassigned_reward_is_red_even_on_the_selected_row() {
        for selected in [false, true] {
            let mut m = Model::new();
            m.color_coding = true;
            m.alloc_cursor = if selected { 0 } else { 1 };
            let mut allocation = row("aa", 1, 1, -1, "", "");
            allocation.estimated_reward = BigInt::from(123456);
            let reward = fmt_reward(&allocation.estimated_reward);
            let lines = render_alloc_panel(&mut m, &[allocation], Rect::new(0, 0, 240, 5), None);
            let span = lines[1].spans.iter().find(|s| s.content.trim() == reward).expect("reward cell");
            assert_eq!(span.style.fg, Some(ERROR));
            if selected { assert_eq!(lines[1].style.bg, Some(CURSOR_BG)); }
        }
    }

    fn shard(hex: &str, size: u64, reward: u64) -> ShardRow {
        ShardRow {
            global_head: None,
            filter: Vec::new(),
            filter_key: hex.to_string(),
            filter_hex: hex.to_string(),
            active_provers: 42,
            ring: 1,
            shard_size: BigInt::from(size),
            data_shards: 2,
            materialized_frame: 0,
            latest_frame: 0,
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
                assert!(
                    !cell.contains("Q/f"),
                    "column {c} repeats the header unit: {cell}"
                );
            }
        }
        // Reward stops carrying its unit, so the column fits its header.
        let (w, _) = avail_col_widths(&m, 154, &rows);
        assert_eq!(w[10], printed_width(&avail_header(&m, 10)));
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
                    "(pause|leave)",
                    "activate@f699840",
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
        assert_eq!(header_text("Worker", 7, 7, true, false, false), "↑Worker");
        assert_eq!(header_text("Worker", 7, 7, false, false, false), "↓Worker");
        assert_eq!(header_text("Ring", 3, 7, true, true, false), "Ring*");
        assert_eq!(header_text("Ring", 3, 3, true, true, false), "↑Ring*");
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
        let (w, fw) = alloc_col_widths(&m, 165, &rows);

        assert_eq!(
            w,
            vec![
                6,  // "Select"
                20, // Filter — what the pane has left
                7,  // "Provers"
                4,  // "Ring"
                9,  // "Size_[MB]"
                8,  // "10076371", wider than "Shards"
                8,  // "LocalMat"
                8,  // "PeerHead"
                10, // "GlobalHead"
                9,  // "Execution"
                12, // "Reward_[Q/d]"
                7,  // "↑Worker", including the active sort arrow
                7,  // "joining", wider than "Status"
                4,  // "Mode"
                13, // "(pause|leave)", wider than "Next_Action"
                16, // "activate@f699840", wider than "Default_Action"
            ]
        );
        assert_eq!(fw, 20);
        // 16 columns + 15 separators + 2 borders fill the pane exactly.
        assert_eq!(w.iter().sum::<usize>() + 15 + 2, 165);
    }

    #[test]
    fn fixed_sizing_reserves_the_local_and_peer_column_labels() {
        let (w, fw) = alloc_col_widths(&fixed(), 165, &joining_table());
        assert_eq!(w, vec![6, 12, 7, 5, 10, 8, 9, 8, 10, 9, 12, 8, 12, 4, 26, 18]);
        assert_eq!(fw, 12);
        assert_eq!(w.iter().sum::<usize>() + 15, 179);
        // 26 columns of Next Action for a 13-column value in the fixed layout.
        assert_eq!(w[14], NEXT_ACTION_WIDTH);
    }

    #[test]
    fn no_cell_overflows_its_column() {
        for m in [Model::new(), fixed()] {
            let rows = joining_table();
            let (w, fw) = alloc_col_widths(&m, 165, &rows);
            for (c, width) in w.iter().enumerate() {
                for a in &rows {
                    let cell = alloc_cell(&m, a, c, fw);
                    assert!(
                        printed_width(&cell) <= *width,
                        "column {c} is {width} wide but a cell needs {}",
                        printed_width(&cell)
                    );
                }
            }
        }
    }

    #[test]
    fn next_action_widens_when_a_confirm_window_opens() {
        let m = Model::new();
        let mut rows = joining_table();
        let (before, before_fw) = alloc_col_widths(&m, 165, &rows);
        rows[3].next_action = ActionHint::text("(reject|confirm)");
        let (after, after_fw) = alloc_col_widths(&m, 165, &rows);

        assert_eq!(before[14], 13);
        assert_eq!(after[14], 16);
        // Filter gives back exactly what Next Action took; the row still fits.
        assert_eq!(before_fw - after_fw, 3);
        assert_eq!(after.iter().sum::<usize>() + 15 + 2, 165);
    }

    #[test]
    fn filter_takes_the_slack_and_gives_it_back_first() {
        let m = Model::new();
        let rows = joining_table();
        // Wide pane: Filter stops at the longest hex rather than padding on.
        assert_eq!(alloc_col_widths(&m, 300, &rows).1, 64);
        assert_eq!(alloc_col_widths(&m, 178, &rows).1, 33);
        // Narrower: Filter absorbs the shortfall…
        assert_eq!(alloc_col_widths(&m, 165, &rows).1, 20);
        assert_eq!(alloc_col_widths(&m, 121, &rows).1, 12);
        // …down to the floor, past which the row is clipped rather than shrunk.
        assert_eq!(alloc_col_widths(&m, 118, &rows).1, MIN_FILTER_WIDTH);
        assert_eq!(alloc_col_widths(&m, 40, &rows).1, MIN_FILTER_WIDTH);
    }

    fn joined(spans: &[Span<'static>]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    /// The arrow already said which column sorts, but only to someone reading
    /// the header row character by character. The underline is the part that
    /// works without colour and without reading.
    #[test]
    fn the_sorted_column_is_marked_without_colour() {
        let base = Style::new().add_modifier(Modifier::BOLD);
        let spans = header_spans("↑Worker", 9, base, true, false, false);
        assert_eq!(joined(&spans), "  ↑Worker");
        assert!(spans
            .iter()
            .all(|s| s.style.add_modifier.contains(Modifier::UNDERLINED)));
        assert!(spans.iter().all(|s| s.style.fg.is_none()));
        // An unsorted column is left exactly as it was.
        let plain = header_spans("Worker", 9, base, false, false, false);
        assert_eq!(joined(&plain), "   Worker");
        assert!(plain
            .iter()
            .all(|s| !s.style.add_modifier.contains(Modifier::UNDERLINED)));
    }

    /// Tinting the whole header would compete with the column's values; only
    /// the one character that carries the sort direction takes the colour.
    #[test]
    fn only_the_arrow_carries_the_sort_colour() {
        let spans = header_spans(
            "↓Reward [Q/d]",
            14,
            Style::new().add_modifier(Modifier::BOLD),
            true,
            true,
            false,
        );
        assert_eq!(joined(&spans), " ↓Reward [Q/d]");
        let tinted: Vec<&Span<'static>> =
            spans.iter().filter(|s| s.style.fg == Some(SORT)).collect();
        assert_eq!(tinted.len(), 1);
        assert_eq!(tinted[0].content.as_ref(), "↓");
    }

    /// The cell is drawn as several spans, so the padding has to keep the
    /// style; a bare `Span::raw` pad would punch a hole in the sort-mode
    /// highlight, on the side the column aligns away from.
    #[test]
    fn padding_shares_the_highlight_style() {
        let base = Style::new()
            .bg(PRIMARY)
            .fg(TEXT)
            .add_modifier(Modifier::BOLD);
        for left in [false, true] {
            let spans = header_spans("Mode", 8, base, true, false, left);
            assert!(spans.iter().all(|s| s.style.bg == Some(PRIMARY)));
            assert_eq!(joined(&spans).trim(), "Mode");
        }
    }

    /// Filters and Next Action share a meaningful starting edge. Default
    /// Action stays right: its thresholds are the point of the column, and
    /// they only read as a list when they line up.
    #[test]
    fn filters_and_next_action_align_left() {
        assert!(alloc_left_aligned(14));
        assert!(alloc_left_aligned(1));
        for c in (0..ALLOC_COL_NAMES.len()).filter(|c| *c != 14 && *c != 1) {
            assert!(
                !alloc_left_aligned(c),
                "column {c} should stay right-aligned"
            );
        }
        assert_eq!(
            pad_cell("(pause|leave)", 22, true),
            "(pause|leave)         "
        );
        assert_eq!(pad_cell("renew@f804960", 16, false), "   renew@f804960");
        assert_eq!(pad_cell("expire@f805680", 16, false), "  expire@f805680");
    }

    /// Colouring every bound worker green would tint most of the table and
    /// leave the one row that needs attention no louder than the rest.
    #[test]
    fn an_unbound_worker_is_the_only_id_worth_colouring() {
        assert_eq!(worker_color(-1), Some(ERROR));
        assert_eq!(worker_color(0), None);
        assert_eq!(worker_color(57), None);
    }

    fn help_text() -> String {
        help_body()
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|sp| sp.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The help is the only place that says what `Lag`, `Mode` or
    /// `re-confirm!` mean. A column added without a line here ships
    /// undocumented, and nothing else would catch it.
    #[test]
    fn every_column_has_a_help_entry() {
        let text = help_text();
        for name in ALLOC_COL_NAMES.iter().chain(AVAIL_COL_NAMES.iter()) {
            assert!(text.contains(*name), "column `{name}` has no help entry");
        }
    }

    /// The documented keys: the left-hand column of every `kv` line. Matching
    /// on the whole text would pass on any single letter appearing anywhere in
    /// a sentence, which is how `d` and `x` went undocumented while a naive
    /// `contains` said otherwise.
    fn documented_keys() -> Vec<String> {
        help_body()
            .iter()
            .filter(|l| l.spans.len() == 2)
            .map(|l| l.spans[0].content.trim().to_string())
            .collect()
    }

    /// Listed by hand against `handle_normal_key` and its mode handlers: a
    /// binding that exists and is undocumented is exactly what this should
    /// force someone to reconcile.
    #[test]
    fn every_key_has_a_help_entry() {
        let keys = documented_keys();
        for key in [
            "l", "c", "r", "p", "u", "M", "J", "s", "f", "R", "C", "w", "e", "h", "a", "x", "d",
            "Tab", "Space", "enter", "esc", "q / Ctrl+C",
        ] {
            assert!(
                keys.iter().any(|k| k == key),
                "key `{key}` has no help entry"
            );
        }
    }

    /// The help outgrew a terminal the moment it documented everything, so
    /// it scrolls; the title is pinned and never counted as body.
    #[test]
    fn the_help_is_longer_than_a_terminal_and_so_it_scrolls() {
        assert!(
            help_body().len() > 50,
            "help fits on one screen; the scroll path is now untested"
        );
    }

    #[test]
    fn fixed_reward_width_tracks_the_reward_in_both_panels() {
        let m = fixed();
        let mut allocation = joining_table().remove(0);
        allocation.estimated_reward = BigInt::from(10u64).pow(30);
        let (widths, _) = alloc_col_widths(&m, 300, &[allocation.clone()]);
        assert!(widths[10] >= printed_width(&alloc_cell(&m, &allocation, 10, 0)));
        let mut available = shard("ab", 0, 0);
        available.estimated_reward = allocation.estimated_reward;
        let (widths, _) = avail_col_widths(&m, 300, &[available.clone()]);
        assert!(widths[10] >= printed_width(&avail_cell(&m, &available, 10, 0)));
    }

    #[test]
    fn reward_filters_use_daily_units_without_rounding_the_sort() {
        let mut m = Model::new();
        m.available = vec![shard("low", 0, 10_000), shard("high", 0, 11_000)];
        // Both display 1 Q/d, but sorting retains the underlying precision.
        assert_eq!(fmt_reward(&m.available[0].estimated_reward), "1");
        assert_eq!(fmt_reward(&m.available[1].estimated_reward), "1");
        let sorted = m.sorted_available();
        assert_eq!(sorted[0].filter_key, "high");
        m.avail_col_filters.insert(10, ColumnFilter {
            expr: ">0.9".into(),
            ..Default::default()
        });
        let filtered = m.filtered_available();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].filter_key, "high");
        let mut allocation = joining_table().remove(0);
        allocation.estimated_reward = BigInt::from(11_000);
        assert!((alloc_row_numeric_val(&allocation, 10) - 0.9504).abs() < 1e-10);
    }

    #[test]
    fn help_close_commands_stay_at_bottom_before_and_after_scrolling() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        use ratatui::{backend::TestBackend, Terminal};
        let mut m = Model::new(); m.show_help = true;
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|f| draw(f, &mut m)).unwrap();
        let bottom = |buffer: &ratatui::buffer::Buffer| (0..100).map(|x| buffer[(x, 23)].symbol()).collect::<String>();
        let before = bottom(terminal.backend().buffer());
        let separator = |buffer: &ratatui::buffer::Buffer| (0..100).map(|x| buffer[(x, 22)].symbol()).collect::<String>();
        assert_eq!(separator(terminal.backend().buffer()), "─".repeat(100));
        assert_eq!(m.help_visible, 21);
        assert!(before.contains("[h/esc] close"));
        super::super::update::handle_key(&mut m, KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        terminal.draw(|f| draw(f, &mut m)).unwrap();
        assert_eq!(bottom(terminal.backend().buffer()), before);
        assert_eq!(separator(terminal.backend().buffer()), "─".repeat(100));
        assert_eq!(m.help_offset + m.help_visible, m.help_lines);
    }

    #[test]
    fn threshold_toggle_and_help_scroll_work_through_the_ui() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        use ratatui::{backend::TestBackend, Terminal};
        use super::super::update::handle_key;

        let mut m = Model::new();
        m.epoch_length = 720;
        m.allocations = joining_table();
        m.allocations[0].next_action = ActionHint::at("(reject|confirm)", 2_160);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(handle_key(&mut m, key(KeyCode::Char('e'))).is_empty());
        assert_eq!(alloc_cell(&m, &m.allocations[0], 14, 0), "(reject|confirm)@e3");
        assert!(handle_key(&mut m, key(KeyCode::Char('e'))).is_empty());
        assert_eq!(alloc_cell(&m, &m.allocations[0], 14, 0), "(reject|confirm)@f2160");

        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        assert!(handle_key(&mut m, key(KeyCode::Char('h'))).is_empty());
        terminal.draw(|f| draw(f, &mut m)).unwrap();
        assert!(m.help_lines > m.height as usize);
        let text = |buffer: &ratatui::buffer::Buffer| {
            buffer.content().iter().map(|cell| cell.symbol()).collect::<String>()
        };
        let before = text(terminal.backend().buffer());
        assert!(handle_key(&mut m, key(KeyCode::End)).is_empty());
        terminal.draw(|f| draw(f, &mut m)).unwrap();
        let after = text(terminal.backend().buffer());
        assert!(m.help_offset > 0);
        assert_ne!(before, after);
        assert!(before.starts_with(" Shard Manager — Help"));
        assert!(after.starts_with(" Shard Manager — Help"));
        assert!(handle_key(&mut m, key(KeyCode::Esc)).is_empty());
        assert!(!m.show_help);
        assert_eq!(m.help_offset, 0);
    }

}
