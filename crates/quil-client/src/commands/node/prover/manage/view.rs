//! Rendering for the `prover manage` TUI. Port of the bubbletea `View`
//! and its panel/help/join-picker renderers, expressed with ratatui.

use super::super::local_execution::{
    advance_age, execution_label, recovery, recovery_summary, seal_summary, sealed,
};

use super::super::epoch::EffectiveStatus;
use num_bigint::BigInt;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

#[cfg(test)]
use super::super::format_quil_daily_round;
use super::model::*;
use super::util::{center_trunc, clamp_offset, filter_label, shared_filter_address};

// ── Colors: red is reserved for execution failures and errors ───────────────────────────────────

const PRIMARY: Color = Color::Rgb(0x80, 0xb8, 0xd8);
const HEADER_BG: Color = Color::Rgb(0x24, 0x36, 0x48);
const CURSOR_BG: Color = Color::Rgb(0x28, 0x28, 0x28);
const INACTIVE_CURSOR_BG: Color = Color::Rgb(0x18, 0x18, 0x18);
const DIM: Color = Color::Rgb(0x55, 0x55, 0x55);
const TEXT: Color = Color::Rgb(0xff, 0xff, 0xff);
const SUCCESS: Color = Color::Rgb(0x85, 0xc7, 0x94);
const ERROR: Color = Color::Rgb(0xf0, 0x80, 0x80);
const WARNING: Color = Color::Yellow;
const HELP: Color = Color::Rgb(0x88, 0x88, 0x88);
const FILTER: Color = Color::Rgb(0xff, 0xaa, 0x00);
/// The sort-direction arrow, so the sorted column is findable at a glance.
/// Distinct from every status palette above: it marks the layout, not a value.
const SORT: Color = Color::Rgb(0x55, 0xaa, 0xff);

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn ring_color(ring: u32) -> Color {
    // Rank is an economic position, never an execution-health alarm.
    match ring {
        UNKNOWN_REWARD_RING => HELP,
        0 => SUCCESS,
        1 => Color::Rgb(0x80, 0xc8, 0xc0),
        2 => PRIMARY,
        3 => Color::Rgb(0xa0, 0xa8, 0xd8),
        _ => Color::Rgb(0xb8, 0xa0, 0xc8),
    }
}

fn status_color(name: &str) -> Color {
    match name.to_lowercase().as_str() {
        "active" => SUCCESS,
        "joining" | "activating" => PRIMARY,
        "bound" | "leaving" | "departing" | "paused" | "re-confirm!" | "expiredjoin"
        | "expiredleave" => WARNING,
        "rejected" | "kicked" => ERROR,
        _ => HELP,
    }
}
fn materialization_state_color(state: &str) -> Color {
    match state {
        "current" => SUCCESS,
        "lag" | "unmat" => WARNING,
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
    // Both worker-management modes are normal operator choices.
    if mode == "m" {
        PRIMARY
    } else {
        HELP
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

/// Estimated reward for the reward cell: QUIL/day to one decimal, matching the
/// `Reward [~Q/d]` header and the panel-title totals.
#[cfg(test)]
fn fmt_reward(v: &BigInt) -> String {
    format_quil_daily_round(v)
}

fn fmt_forecast(value: &BigInt) -> String {
    super::super::format_quil_daily_units(value)
        .trim_start_matches('~')
        .to_string()
}
fn reward_cell(m: &Model, v: &BigInt, filter: &[u8]) -> String {
    (0..3)
        .filter(|i| m.reward_mask() & (1 << i) != 0)
        .map(|i| {
            m.daily_reward(v, filter, i)
                .map_or_else(|| "-".into(), |v| fmt_forecast(&v))
        })
        .collect::<Vec<_>>()
        .join("/")
}
fn reward_total(m: &Model, rows: &[AllocationRow], kind: usize) -> String {
    (0..3)
        .filter(|i| m.reward_mask() & (1 << i) != 0)
        .map(|i| {
            let mut total = BigInt::from(0);
            let mut unknown = false;
            let mut known = false;
            for row in rows {
                let sign = match (kind, row.reward_status(m.epoch_frame(), m.epoch_length)) {
                    (0, Some(EffectiveStatus::Active | EffectiveStatus::Leaving))
                    | (1, Some(EffectiveStatus::Paused))
                    | (2, Some(EffectiveStatus::Joining)) => 1,
                    (2, Some(EffectiveStatus::Leaving)) => -1,
                    _ => continue,
                };
                let value = if row.ring == UNKNOWN_REWARD_RING {
                    None
                } else {
                    m.daily_reward(&row.estimated_reward, &row.filter, i)
                };
                if let Some(v) = value {
                    total += v * sign;
                    known = true;
                } else {
                    unknown = true;
                }
            }
            if unknown && !known {
                "-".into()
            } else {
                format!(
                    "{}{}",
                    if kind == 2 && total.sign() == num_bigint::Sign::Plus {
                        format!("+{}", fmt_forecast(&total))
                    } else {
                        fmt_forecast(&total)
                    },
                    if unknown { "+" } else { "" }
                )
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}
fn cadence_coverage(m: &Model, filter: &[u8]) -> Option<String> {
    let c = m.node_app_cadence.get(filter)?;
    let values = [false, true]
        .iter()
        .map(|day| {
            m.cadence_window(c, *day)
                .map_or_else(|| "-".into(), |w| format!("{}m", w.observed_seconds / 60))
        })
        .collect::<Vec<_>>();
    Some(format!("Coverage 60m/24h: {}", values.join("/")))
}
fn interval_values(
    m: &Model,
    cadence: Option<&quil_types::proto::node::FrameCadence>,
    mask: u8,
) -> String {
    [false, true]
        .iter()
        .enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0)
        .map(|(_, day)| {
            fmt_interval(
                cadence
                    .and_then(|c| m.cadence_window(c, *day))
                    .and_then(|w| {
                        (w.advanced_frames > 0)
                            .then(|| w.observed_seconds as f64 / w.advanced_frames as f64)
                    }),
            )
            .trim_end_matches('s')
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("/")
}
fn fmt_gb(v: &BigInt) -> String {
    super::super::format_gb(v)
}

/// A column header as printed: sort indicator, name, active-filter marker.
/// Sizing and rendering share it, so a column is never measured against a
/// different string than it draws.
///
/// Column names use the same casing and unit labels in both sizing modes.
fn header_text(
    name: &str,
    idx: usize,
    sort_col: i32,
    asc: bool,
    filtered: bool,
    compact: bool,
) -> String {
    let mut s = if compact && name.starts_with("Reward [~Q/d ") {
        name.replacen("Reward ", "", 1)
    } else if compact && name.starts_with("Interval [s ") {
        name.replacen("Interval ", "", 1)
    } else {
        (if compact {
            match name {
                "Size [GB]" => "[GB]",
                "Reward [~Q/d]" => "[~Q/d]",
                "Interval [s]" => "[s]",
                _ => name,
            }
        } else {
            name
        })
        .to_string()
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
/// threshold, so its `in 512f`s (or `@f804960`s) line up and the eye reads
/// straight down them. Next Action does not: `(pause|leave)` has no threshold
/// at all, and aligned on the tail it lands under the middle of
/// `(reject|confirm)@f804960`
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
    if m.column_picker_active {
        render_column_picker(f, m, area);
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
    m.horizontal_limits[panel] = width
        .saturating_sub(usize::from(visible))
        .min(usize::from(u16::MAX)) as u16;
    m.horizontal_offsets[panel] = m.horizontal_offsets[panel].min(m.horizontal_limits[panel]);
    m.horizontal_offsets[panel]
}

fn scroll_hint(
    offset: usize,
    total: usize,
    visible: usize,
    horizontal: u16,
    horizontal_limit: u16,
) -> String {
    let above = offset;
    let below = total.saturating_sub(offset + visible);
    let right = horizontal_limit.saturating_sub(horizontal);
    if above + below + usize::from(horizontal) + usize::from(right) == 0 {
        return String::new();
    }
    format!(" ↑{above} ↓{below} | ←{horizontal} →{right} ")
}

fn render_scroll_hint(
    f: &mut Frame,
    area: Rect,
    offset: usize,
    total: usize,
    visible: usize,
    horizontal: u16,
    horizontal_limit: u16,
) {
    let hint = scroll_hint(offset, total, visible, horizontal, horizontal_limit);
    if area.height >= 2 && area.width >= 4 && !hint.is_empty() {
        f.render_widget(
            Paragraph::new(hint)
                .alignment(Alignment::Right)
                .style(Style::new().fg(HELP)),
            Rect::new(area.x + 1, area.y + area.height - 1, area.width - 2, 1),
        );
    }
}

fn base_panel_heights(total: u16) -> [u16; 3] {
    if total < 6 {
        return [total / 3 + total % 3, total / 3, total / 3];
    }
    let notice = total.saturating_sub(5).min(3);
    let alloc = ((total - notice) / 2).max(3);
    [alloc, total - notice - alloc, notice]
}

fn panel_heights(m: &Model, total: u16) -> [u16; 3] {
    let mut heights = base_panel_heights(total);
    if total < 6 {
        return heights;
    }
    let minimum = [3i32, 2, 1];
    for i in 0..2 {
        let movement = i32::from(m.panel_boundary_offsets[i]).clamp(
            minimum[i] - i32::from(heights[i]),
            i32::from(heights[i + 1]) - minimum[i + 1],
        );
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
    if !m.filter_edit_active
        && !m.is_filter_mode_active()
        && !m.sort_mode
        && m.operation_confirmation.is_none()
    {
        actions.extend(wrap_actions(worker_commands_line(m), area.width));
    }
    let max_actions = usize::from(area.height.saturating_sub(15).max(1));
    if actions.len() > max_actions {
        actions.truncate(max_actions);
        actions[max_actions - 1] = Line::from("‹h› all keys  ‹q› quit");
    }
    let actions_h = actions.len() as u16;
    let header = header_lines(m, area.width);
    let header_height = header.len() as u16;
    // Content height depends only on terminal geometry and explicit resize keys.
    let [alloc_h, avail_h, notice_h] =
        sync_panel_heights(m, area.height.saturating_sub(6 + header_height + actions_h));
    let status_h = notice_h + 2;

    let chunks = Layout::vertical([
        Constraint::Length(header_height), // identity and worker counts
        Constraint::Length(alloc_h + 2),   // alloc panel (+ border)
        Constraint::Length(avail_h + 2),   // avail panel (+ border)
        Constraint::Length(status_h),      // notifications
        Constraint::Length(actions_h),     // commands at the bottom
    ])
    .split(area);

    // Header.
    f.render_widget(
        Paragraph::new(header).style(Style::new().fg(TEXT).bg(HEADER_BG)),
        chunks[0],
    );

    // First heading line shares the border; continuation KPIs stay above the table.
    let sorted_allocs = m.sorted_allocations();
    let sorted_avail = m.sorted_available();
    let (alloc_widths, avail_widths) = shared_col_widths(
        m,
        area.width.saturating_sub(2) as usize,
        &sorted_allocs,
        &sorted_avail,
    );
    update_app_progress_warning(m);
    let alloc_heading = alloc_heading_lines(m, &sorted_allocs, chunks[1].width.saturating_sub(4));
    let alloc_block = Block::default()
        .title(panel_title(alloc_heading[0].to_string()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if m.focus.is_alloc() { PRIMARY } else { DIM }));
    let alloc_inner = alloc_block.inner(chunks[1]);
    f.render_widget(alloc_block, chunks[1]);
    // Keep room for the table header and a data row on small panels.
    let heading_count = alloc_heading.len();
    let continuation_h = heading_count
        .saturating_sub(1)
        .min(usize::from(alloc_inner.height.saturating_sub(2))) as u16;
    if continuation_h > 0 {
        let mut continuation = alloc_heading
            .into_iter()
            .skip(1)
            .take(usize::from(continuation_h))
            .collect::<Vec<_>>();
        if heading_count > usize::from(continuation_h) + 1 {
            continuation[usize::from(continuation_h) - 1] =
                Line::from("… enlarge panel for remaining KPIs");
        }
        f.render_widget(
            Paragraph::new(continuation)
                .style(Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD)),
            Rect::new(
                alloc_inner.x,
                alloc_inner.y,
                alloc_inner.width,
                continuation_h,
            ),
        );
    }
    let alloc_inner = Rect::new(
        alloc_inner.x,
        alloc_inner.y + continuation_h,
        alloc_inner.width,
        alloc_inner.height.saturating_sub(continuation_h),
    );
    let detail_lines = allocation_detail_lines(m, &sorted_allocs, alloc_inner);
    // The table renderer already reserves one footer row; reserve additional
    // wrapped lines here without allowing detail to displace every data row.
    let table_area = Rect {
        height: alloc_inner
            .height
            .saturating_sub(detail_lines.len().saturating_sub(1) as u16),
        ..alloc_inner
    };
    let alloc_lines = render_alloc_panel(m, &sorted_allocs, table_area, Some(&alloc_widths));
    let mut alloc_lines = alloc_lines;
    if !detail_lines.is_empty() {
        alloc_lines.pop();
    }
    let horizontal = table_horizontal_offset(m, 0, &alloc_lines, alloc_inner.width);
    f.render_widget(
        Paragraph::new(alloc_lines).scroll((0, horizontal)),
        alloc_inner,
    );
    if !detail_lines.is_empty() {
        let detail_h = detail_lines.len() as u16;
        f.render_widget(
            Paragraph::new(detail_lines),
            Rect::new(
                alloc_inner.x,
                alloc_inner.y + alloc_inner.height - detail_h,
                alloc_inner.width,
                detail_h,
            ),
        );
    }
    render_scroll_hint(
        f,
        chunks[1],
        m.alloc_offset,
        sorted_allocs.len(),
        usize::from(
            table_area
                .height
                .saturating_sub(1 + u16::from(table_area.height >= 3)),
        ),
        horizontal,
        m.horizontal_limits[0],
    );

    let avail_block = Block::default()
        .title(avail_title(m, &sorted_avail))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if m.focus == PanelFocus::Available {
            PRIMARY
        } else {
            DIM
        }));
    let avail_inner = avail_block.inner(chunks[2]);
    f.render_widget(avail_block, chunks[2]);
    let avail_lines = render_avail_panel(m, &sorted_avail, avail_inner, Some(&avail_widths));
    let mut avail_lines = avail_lines;
    let detail = if !sorted_avail.is_empty() && avail_inner.height >= 3 {
        avail_lines.pop()
    } else {
        None
    };
    let detail_rows = u16::from(detail.is_some());
    let horizontal = table_horizontal_offset(m, 1, &avail_lines, avail_inner.width);
    f.render_widget(
        Paragraph::new(avail_lines).scroll((0, horizontal)),
        avail_inner,
    );
    if let Some(detail) = detail {
        f.render_widget(
            Paragraph::new(detail),
            Rect::new(
                avail_inner.x,
                avail_inner.y + avail_inner.height - 1,
                avail_inner.width,
                1,
            ),
        );
    }
    render_scroll_hint(
        f,
        chunks[2],
        m.avail_offset,
        sorted_avail.len(),
        usize::from(
            avail_inner
                .height
                .saturating_sub(1 + detail_rows + u16::from(m.shard_error.is_some())),
        ),
        horizontal,
        m.horizontal_limits[1],
    );

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
            },
            Style::new().fg(HELP),
        ));
    }
    m.notice_lines = lines.len();
    m.notice_visible = usize::from(area.height.saturating_sub(2));
    m.notice_offset = m
        .notice_offset
        .min(m.notice_lines.saturating_sub(m.notice_visible));
    let mut title = "Notifications".to_string();
    if m.header_kpi_visible("Notification level") {
        title += &format!(" · Level: {}", m.notice_minimum.label());
    }
    if m.notice_lines > m.notice_visible && m.header_kpi_visible("Notification position") {
        title += &format!(" · Line {}/{}", m.notice_offset + 1, m.notice_lines);
    }
    let block = Block::default()
        .title(panel_title(title))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if m.focus == PanelFocus::Notifications {
            PRIMARY
        } else {
            DIM
        }));
    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(m.notice_offset)
                .take(m.notice_visible)
                .collect::<Vec<_>>(),
        ),
        inner,
    );
    render_scroll_hint(
        f,
        area,
        m.notice_offset,
        m.notice_lines,
        m.notice_visible,
        0,
        0,
    );
}

// ── Header ───────────────────────────────────────────────────────────────

/// Pack complete KPI blocks, never splitting their internal pipe-separated fields.
fn header_lines(m: &Model, width: u16) -> Vec<Line<'static>> {
    let blocks = header_kpis(m);
    if blocks.is_empty() {
        return vec![];
    }
    pack_kpis(blocks, width)
        .into_iter()
        .flat_map(|line| {
            if line.width() > usize::from(width) {
                wrap_message(line, width)
            } else {
                vec![line]
            }
        })
        .collect()
}

fn pack_kpis(blocks: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut line = Line::default();
    for block in blocks {
        if !line.spans.is_empty() && line.width() + 3 + block.width() > usize::from(width) {
            lines.push(line);
            line = Line::default();
        }
        if !line.spans.is_empty() {
            line.spans.push(Span::raw(" · "));
        }
        line.spans.extend(block.spans);
    }
    lines.push(line);
    lines
}

fn header_kpis(m: &Model) -> Vec<Line<'static>> {
    if !m.data_loaded {
        return vec![Line::from(format!("{} Connecting to node…", spinner(m)))];
    }
    let rpc = if m.consecutive_failures > 0 {
        "retrying"
    } else if m.last_fetch_success.is_none() {
        "unknown"
    } else if rpc_status_is_fresh(m) {
        "connected"
    } else {
        "stale"
    };
    let compact = m.compact_actions;
    let strategy = match m
        .cached_shard_info
        .as_ref()
        .map(|s| s.allocation_scoring_strategy.as_str())
    {
        Some("reward-greedy") => {
            if compact {
                "Strategy: H → $"
            } else {
                "Strategy: Halt risk, then reward"
            }
        }
        Some("data-greedy") => {
            if compact {
                "Strategy: H → D"
            } else {
                "Strategy: Halt risk, then data"
            }
        }
        _ => "Strategy: ?",
    };
    let peer = if compact {
        let suffix: String = m
            .peer_id
            .chars()
            .rev()
            .take(8)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        format!("Peer: …{suffix}")
    } else {
        format!("Peer ID: {}", m.peer_id)
    };
    let rpc_text = if compact && rpc == "connected" {
        "RPC: ✓".into()
    } else {
        format!("RPC: {rpc}")
    };
    let world = m
        .cached_shard_info
        .as_ref()
        .filter(|info| !info.world_state_bytes.is_empty())
        .map(|info| BigInt::from_signed_bytes_be(&info.world_state_bytes))
        .filter(|bytes| bytes.sign() != num_bigint::Sign::Minus)
        .map(|bytes| fmt_gb(&bytes))
        .unwrap_or_else(|| "-".into());
    let candidates = [
        ("Peer ID", peer),
        ("Strategy", strategy.into()),
        ("Seniority", format!("Seniority: {}", m.seniority)),
        ("Global", global_kpi(m)),
        (
            "Global interval",
            format!(
                "{} [s {}]: {}",
                if compact { "Global" } else { "Global interval" },
                m.global_interval_labels(),
                interval_values(m, m.node_global_cadence.as_ref(), m.global_interval_mask())
            ),
        ),
        (
            "World size",
            format!(
                "{} [GB]: {world}",
                if compact { "World" } else { "World size" }
            ),
        ),
        ("RPC", rpc_text),
    ];
    let mut blocks: Vec<_> = candidates
        .into_iter()
        .filter(|(name, _)| m.header_kpi_visible(name))
        .map(|(_, text)| Line::from(text))
        .collect();
    // Retry evidence stays visible even when the operator hides the ordinary RPC KPI.
    if m.consecutive_failures > 0 {
        if let Some(t) = m.last_fetch_success {
            blocks.push(Line::from(format!(
                "RPC retrying | status age {} | failed retries {}",
                if t.elapsed().as_secs() >= 60 {
                    ">60s"
                } else {
                    "<60s"
                },
                m.consecutive_failures
            )));
        }
    }
    blocks
}

fn global_kpi(m: &Model) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    global_kpi_at(m, now)
}

/// The Global KPI at wall-clock `now` (UNIX seconds): the received GLOBAL
/// head, its epoch and the frames to the next epoch boundary, the selected
/// fields joined by ` | `. The time to the boundary is a `~` estimate from the
/// measured GLOBAL interval, absent without one; expanded mode adds the UTC
/// clock time it falls at.
fn global_kpi_at(m: &Model, now: u64) -> String {
    use super::super::epoch::{epoch_for_frame, fmt_estimate, next_epoch_boundary};
    let frame = m.last_received_frame;
    if frame == 0 {
        return "Global: -".into();
    }
    let compact = m.compact_actions;
    let epoch = epoch_for_frame(frame, m.epoch_length);
    let left = next_epoch_boundary(frame, m.epoch_length) - frame;
    let fields = [
        if compact {
            format!("f{frame}")
        } else {
            format!("frame {frame}")
        },
        if compact {
            format!("e{epoch}")
        } else {
            format!("epoch {epoch}")
        },
        match (compact, m.global_seconds_per_frame()) {
            (true, None) => format!("next {left}f"),
            (true, Some(spf)) => format!("next {left}f ~{}", fmt_estimate(left as f64 * spf)),
            (false, None) => format!("next boundary in {left} frames"),
            (false, Some(spf)) => {
                let seconds = left as f64 * spf;
                // The clock time of the rounded estimate, so the two agree.
                let at = now + (seconds.max(0.0) / 60.0).round() as u64 * 60;
                format!(
                    "next boundary in {left} frames, ~{} (~{:02}:{:02} UTC)",
                    fmt_estimate(seconds),
                    at / 3600 % 24,
                    at / 60 % 60
                )
            }
        },
    ];
    let mask = m.global_field_mask();
    let shown: Vec<_> = fields
        .into_iter()
        .enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0)
        .map(|(_, f)| f)
        .collect();
    format!("Global: {}", shown.join(" | "))
}

/// Only operator actions have shortcuts; automatic defaults keep their names.
fn next_action_text(m: &Model, hint: &super::super::epoch::ActionHint) -> String {
    let mut hint = hint.clone();
    if m.compact_actions {
        for (name, key) in [
            ("reject", "R"),
            ("confirm", "Y"),
            ("pause", "P"),
            ("resume", "U"),
            ("leave", "L"),
        ] {
            hint.label = hint.label.replace(name, key);
        }
    }
    hint.render(m.threshold_unit, m.threshold_clock())
}

#[cfg(test)]
fn header_line(m: &Model) -> Line<'static> {
    header_lines(m, u16::MAX).remove(0)
}

// Require three polls before establishing a new stall notice, with a 60s floor.
// This measures lack of observed head advancement, not the frame's timestamp.
const GLOBAL_ALARM_SECS: u64 = 60;

fn rpc_status_is_fresh(m: &Model) -> bool {
    m.consecutive_failures == 0
        && m.last_fetch_success
            .is_some_and(|t| t.elapsed().as_secs() < m.refresh_seconds * 2 + 30)
}

fn global_alarm_active(m: &Model) -> bool {
    let Some(last) = m.global_last_advance else {
        return false;
    };
    if !rpc_status_is_fresh(m) {
        return false;
    }
    // A cadence change cannot retract an already established stall.
    // Head advancement clears this latch in observe_global_head.
    if m.global_alarm_time.is_some() {
        return true;
    }
    let secs = last.elapsed().as_secs();
    // A changed cadence must first observe enough of its own polling window.
    let window = m
        .refresh_changed_at
        .map_or(secs, |t| secs.min(t.elapsed().as_secs()));
    window >= GLOBAL_ALARM_SECS.max(m.refresh_seconds * 3)
}

fn worker_counts_line(m: &Model) -> Line<'static> {
    let (automatic, manual, draining) = match m.cached_worker_info.as_ref() {
        Some(info) => {
            let workers: std::collections::HashMap<_, _> = info
                .worker_info
                .iter()
                .map(|w| (w.core_id, (w.manually_managed, w.draining)))
                .collect();
            let manual = workers.values().filter(|(manual, _)| *manual).count();
            let draining = workers.values().filter(|(_, draining)| *draining).count();
            (
                (workers.len() - manual).to_string(),
                manual.to_string(),
                draining,
            )
        }
        None => ("?".into(), "?".into(), 0),
    };
    // Against the configured count, which a node that predates it reports as 0.
    let configured = match (m.worker_capacity, m.compact_actions) {
        (0, _) => String::new(),
        (count, true) => format!(" of {count}"),
        (count, false) => format!(" of {count} configured"),
    };
    let draining = match (draining, m.compact_actions) {
        (0, _) => String::new(),
        (count, true) => format!(" | drain {count}"),
        (count, false) => format!(" | draining {count}"),
    };
    if m.compact_actions {
        Line::from(format!(
            "Workers: run {}{configured}{draining} | assigned {}{}",
            m.running_workers,
            m.allocated_workers,
            if manual == "0" {
                String::new()
            } else {
                format!(" | manual {manual}")
            }
        ))
    } else {
        Line::from(format!(
            "Workers: running {}{configured}{draining} | assigned {} | auto {} | manual {}",
            m.running_workers, m.allocated_workers, automatic, manual
        ))
    }
}

/// Row status, then its compact and expanded label in the `Status` KPI.
const STATUS_KPI_LABELS: [(&str, &str, &str); 14] = [
    ("active", "active", "active"),
    ("paused", "paused", "paused"),
    ("joining", "join", "joining"),
    ("activating", "activ", "activating"),
    ("leaving", "leave", "leaving"),
    ("departing", "depart", "departing"),
    ("bound", "bound", "bound"),
    ("idle", "idle", "idle"),
    ("expiredJoin", "join expired", "expired joining"),
    ("expiredLeave", "leave expired", "expired leaving"),
    ("re-confirm!", "reconfirm", "reconfirm"),
    ("rejected", "rejected", "rejected"),
    ("kicked", "kicked", "kicked"),
    ("unknown", "unknown", "unknown"),
];

fn allocation_status_kpi(m: &Model) -> String {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for a in &m.allocations {
        let label = if matches!(a.status_name.as_str(), "bound" | "idle") {
            a.status_name.clone()
        } else {
            super::super::epoch::compute_effective_status(
                &super::super::epoch::AllocationTiming {
                    raw_status: a.status,
                    filter: &a.filter,
                    join_frame: a.join_frame,
                    join_confirm_frame: a.confirm_frame,
                    leave_frame: a.leave_frame,
                    leave_confirm_frame: a.leave_confirm_frame,
                    epoch: a.epoch,
                },
                m.epoch_frame(),
                m.epoch_length,
            )
            .label()
            .into()
        };
        *counts.entry(label).or_default() += 1;
    }
    let mut fields = Vec::new();
    for (key, compact, expanded) in STATUS_KPI_LABELS {
        let count = counts.get(key).copied().unwrap_or(0);
        if count != 0 || !m.compact_actions {
            fields.push(format!(
                "{} {count}",
                if m.compact_actions { compact } else { expanded }
            ));
        }
    }
    if fields.is_empty() {
        "Status: none".into()
    } else {
        format!("Status: {}", fields.join(" | "))
    }
}

/// Frame offsets always refer to the top-level GLOBAL head, even in epoch mode.
fn frame_citation(m: &Model, frame: u64) -> String {
    if !m.compact_actions {
        return format!(" @f{frame}");
    }
    match frame.cmp(&m.last_received_frame) {
        std::cmp::Ordering::Less => format!(" @-{}f", m.last_received_frame - frame),
        std::cmp::Ordering::Greater => format!(" @+{}f", frame - m.last_received_frame),
        std::cmp::Ordering::Equal => String::new(),
    }
}

fn panel_title(text: String) -> Line<'static> {
    Line::from(format!(" {} ", text.trim()))
        .style(Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD))
}

/// Display signed changes without rounding a nonzero loss/gain to zero.
#[cfg(test)]
fn fmt_reward_change(v: &BigInt) -> String {
    match v.sign() {
        num_bigint::Sign::Minus => format!("-{}", fmt_reward(&(-v))),
        num_bigint::Sign::Plus => format!("+{}", fmt_reward(v)),
        num_bigint::Sign::NoSign => "0.0".to_string(),
    }
}

/// Round to five decimals with integer arithmetic; preserve tiny positive amounts.
fn fmt_claimable(value: u128) -> String {
    const UNITS_PER_QUIL: u128 = crate::util::UNITS_PER_QUIL as u128;
    const UNITS_PER_DECIMAL: u128 = UNITS_PER_QUIL / 100_000;
    if value == 0 {
        return "0".into();
    }
    if value < UNITS_PER_DECIMAL {
        return "<0.00001".into();
    }
    let mut whole = value / UNITS_PER_QUIL;
    let mut fraction = (value % UNITS_PER_QUIL + UNITS_PER_DECIMAL / 2) / UNITS_PER_DECIMAL;
    if fraction == 100_000 {
        whole += 1;
        fraction = 0;
    }
    if fraction == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{:05}", fraction)
            .trim_end_matches('0')
            .to_string()
    }
}

fn claimable_title(m: &Model) -> String {
    match m.claimable_reward {
        Some((value, frame)) => format!(
            "Claimable [Q]: {}{}{}",
            fmt_claimable(value),
            frame_citation(m, frame),
            if m.reward_last_success
                .is_some_and(|t| t.elapsed().as_secs() >= m.refresh_seconds * 2 + 30)
            {
                " (stale)"
            } else {
                ""
            }
        ),
        None if m.reward_loaded => "Claimable [Q]: unavailable".into(),
        None => "Claimable [Q]: loading".into(),
    }
}

fn alloc_kpis(m: &Model, sorted: &[AllocationRow]) -> Vec<String> {
    let mut joining = BigInt::from(0);
    let mut paused = BigInt::from(0);
    let mut leaving = BigInt::from(0);
    let (mut paused_unknown, mut change_unknown) = (false, false);
    for a in sorted {
        if a.ring == UNKNOWN_REWARD_RING {
            match a.reward_status(m.epoch_frame(), m.epoch_length) {
                Some(EffectiveStatus::Leaving) => change_unknown = true,
                Some(EffectiveStatus::Paused) => paused_unknown = true,
                Some(EffectiveStatus::Joining) => change_unknown = true,
                _ => {}
            }
            continue;
        }
        match a.reward_status(m.epoch_frame(), m.epoch_length) {
            Some(EffectiveStatus::Joining) => joining += &a.estimated_reward,
            Some(EffectiveStatus::Paused) => paused += &a.estimated_reward,
            Some(EffectiveStatus::Leaving) => leaving += &a.estimated_reward,
            _ => {}
        }
    }
    let change = &joining - &leaving;
    let now = reward_total(m, sorted, 0);
    let paused_text = reward_total(m, sorted, 1);
    let change_text = reward_total(m, sorted, 2);
    let reward = if m.compact_actions {
        let breakdown = paused_unknown
            || change_unknown
            || paused != BigInt::from(0)
            || change != BigInt::from(0);
        let mut text = format!(
            "[~Q/d {}] {}{now}",
            m.reward_labels(),
            if breakdown { "now " } else { "" }
        );
        if paused_unknown || paused != BigInt::from(0) {
            text += &format!(" | paused {paused_text}");
        }
        if change_unknown || change != BigInt::from(0) {
            text += &format!(" | Δ {change_text}");
        }
        text
    } else {
        format!(
            "Reward [~Q/d {}]: now {now} | paused {paused_text} | delta {change_text}",
            m.reward_labels()
        )
    };
    let mut blocks = vec!["Allocations".to_string()];
    for (name, text) in [
        ("Workers", worker_counts_line(m).to_string()),
        ("Status", allocation_status_kpi(m)),
        (
            "Claimable",
            if m.compact_actions {
                claimable_title(m).replacen("Claimable [Q]:", "[Q]", 1)
            } else {
                claimable_title(m)
            },
        ),
        ("Reward", reward),
        (
            "Allocation GLOBAL snapshot",
            global_snapshot_label(m, sorted.iter().map(|a| a.global_head.as_ref())),
        ),
    ] {
        if m.header_kpi_visible(name)
            && !(name == "Allocation GLOBAL snapshot" && m.compact_actions)
        {
            blocks.push(text);
        }
    }
    if sorted.len() != m.allocations.len() && m.header_kpi_visible("Shown allocations") {
        blocks.push(format!("Shown {}/{}", sorted.len(), m.allocations.len()));
    }
    if !m.alloc_selected.is_empty() && m.header_kpi_visible("Selected allocations") {
        blocks.push(format!("Selected {}", m.alloc_selected.len()));
    }
    blocks
}

#[cfg(test)]
fn alloc_title(m: &Model, sorted: &[AllocationRow]) -> Line<'static> {
    panel_title(alloc_kpis(m, sorted).join(" · "))
}

fn alloc_heading_lines(m: &Model, sorted: &[AllocationRow], width: u16) -> Vec<Line<'static>> {
    pack_kpis(
        alloc_kpis(m, sorted).into_iter().map(Line::from).collect(),
        width,
    )
    .into_iter()
    .flat_map(|line| {
        if line.width() > usize::from(width) {
            wrap_message(line, width)
        } else {
            vec![line]
        }
    })
    .collect()
}

fn avail_title(m: &Model, sorted: &[ShardRow]) -> Line<'static> {
    let mut blocks = vec!["Available Shards".to_string()];
    if m.header_kpi_visible("Available count") {
        blocks.push(format!("Count {}", sorted.len()));
    }
    if !m.compact_actions && m.header_kpi_visible("Available GLOBAL snapshot") {
        let snapshot = global_snapshot_label(m, sorted.iter().map(|s| s.global_head.as_ref()));
        if snapshot != "Snapshot" {
            blocks.push(snapshot);
        }
    }
    if !m.avail_selected.is_empty() && m.header_kpi_visible("Selected shards") {
        blocks.push(format!("Selected {}", m.avail_selected.len()));
    }
    panel_title(blocks.join(" · "))
}

// ── Allocations panel ────────────────────────────────────────────────────

fn fmt_interval(interval: Option<f64>) -> String {
    interval
        .map(|seconds| {
            if seconds < 0.05 {
                "<0.1s".into()
            } else {
                format!("{seconds:.1}s")
            }
        })
        .unwrap_or_else(|| "-".into())
}

fn fmt_ring(ring: u32) -> String {
    if ring == UNKNOWN_REWARD_RING {
        "-".into()
    } else {
        ring.to_string()
    }
}

fn fmt_materialized(materialized: u64, latest: u64) -> String {
    if materialized == 0 && latest == 0 {
        "-".into()
    } else {
        materialized.to_string()
    }
}

/// The ProverPhases cell: the shard's provers by lifecycle phase, symbols in
/// compact mode and names in expanded mode. Zero fields are omitted except
/// active, so an empty shard reads `a0`; unreported counts read `-`. A
/// trailing `!` marks halt risk for `warning_slot`.
fn prover_phases_cell(
    m: &Model,
    counts: Option<&quil_types::proto::node::ShardProverCounts>,
    size: &BigInt,
) -> String {
    let Some(c) = counts else {
        return "-".into();
    };
    let fields = [
        (c.active, "a", "active"),
        (c.joining, "j", "joining"),
        (c.activating, "+", "activating"),
        (c.leaving, "l", "leaving"),
        (c.departing, "-", "departing"),
        (c.paused, "p", "paused"),
    ];
    let shown = fields
        .iter()
        .enumerate()
        .filter(|(i, (count, ..))| *i == 0 || *count > 0)
        .map(|(_, field)| field);
    let text = if m.compact_actions {
        shown
            .map(|(count, symbol, _)| format!("{symbol}{count}"))
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        shown
            .map(|(count, _, name)| format!("{count} {name}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    if prover_halt_risk(counts, size) {
        text + "!"
    } else {
        text
    }
}

/// The printed text of one allocations cell. Sizing and rendering both go
/// through here. `fw` is the Filter column's width, which is a budget rather
/// than a measurement — pass 0 when measuring the other columns.
fn alloc_cell(m: &Model, a: &AllocationRow, col: usize, fw: usize) -> String {
    if !a.shard_info_known && matches!(col, 2..=5 | 7 | 10) {
        return "-".into();
    }
    match col {
        0 => alloc_marker(m, a).to_string(),
        1 => center_trunc(&a.filter_hex, fw),
        2 => a.active_provers.to_string(),
        3 => fmt_ring(a.ring),
        4 => fmt_gb(&a.shard_size),
        5 => a.data_shards.to_string(),
        6 => {
            if local_warning(m, a) {
                "0!".into()
            } else {
                let height = a
                    .execution
                    .as_ref()
                    .and_then(|s| s.materialized_frame)
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "-".into());
                if m.local_stalled_rows.contains(&a.filter_key) {
                    height + "!"
                } else {
                    height
                }
            }
        }
        7 => {
            if a.materialized_frame == 0 && a.latest_frame == 0 {
                "-".into()
            } else {
                format!(
                    "{}{}",
                    a.latest_frame,
                    if m.reported_app_stalled(&a.filter) {
                        "!"
                    } else {
                        ""
                    }
                )
            }
        }
        8 => committed_head_cell(m, a.global_head.as_ref(), &a.filter),
        9 => m.allocation_execution_state(a).into(),
        10 => {
            if a.ring == UNKNOWN_REWARD_RING {
                "-".into()
            } else {
                reward_cell(m, &a.estimated_reward, &a.filter)
            }
        }
        11 => a.worker_id.to_string(),
        12 => allocation_status_text(m, a),
        13 => a.mode().to_string(),
        14 => next_action_text(m, &a.next_action),
        16 => interval_values(m, m.node_app_cadence.get(&a.filter), m.interval_mask()),
        ALLOC_PROVER_PHASES_COL => prover_phases_cell(m, a.prover_counts.as_ref(), &a.shard_size),
        _ => a
            .default_action
            .render(m.threshold_unit, m.threshold_clock()),
    }
}

/// Keep a marker position even when warning colors replace the exclamation mark.
fn warning_slot(text: &str, color_coding: bool) -> String {
    match text.strip_suffix('!') {
        Some(value) => format!("{value}{}", if color_coding { ' ' } else { '!' }),
        None => format!("{text} "),
    }
}

pub(super) fn allocation_status_text(m: &Model, a: &AllocationRow) -> String {
    if !matches!(
        a.status_name.as_str(),
        "joining" | "activating" | "leaving" | "departing"
    ) {
        return a.status_name.clone();
    }
    let (symbol, name) = match a.allocation_reason.as_deref() {
        Some("$") => ("$", "reward"),
        Some("H") => ("H", "halt risk"),
        Some("S") => ("S", "split"),
        Some("G") => ("G", "merge"),
        Some("T") => ("T", "retired"),
        Some("E") => ("E", "empty"),
        Some("C") => ("C", "capacity"),
        Some("O") => ("O", "orphan"),
        Some("M") => ("M", "manual"),
        Some("D") => ("D", "data"),
        Some("W") => ("W", "worker shortage"),
        _ => ("?", "unknown"),
    };
    format!(
        "{}({})",
        a.status_name,
        if m.compact_actions { symbol } else { name }
    )
}

fn alloc_display_cell(m: &Model, a: &AllocationRow, col: usize, fw: usize) -> String {
    let text = alloc_cell(m, a, col, fw);
    if matches!(col, 6 | 7 | 8 | 12 | ALLOC_PROVER_PHASES_COL) {
        warning_slot(&text, m.color_coding)
    } else {
        text
    }
}

fn avail_display_cell(m: &Model, s: &ShardRow, col: usize, fw: usize) -> String {
    let text = avail_cell(m, s, col, fw);
    if matches!(col, 8 | 9 | AVAIL_PROVER_PHASES_COL) {
        warning_slot(&text, m.color_coding)
    } else {
        text
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
    let reward_header = format!("Reward [~Q/d {}]", m.reward_labels());
    let interval_header = format!("Interval [s {}]", m.interval_labels());
    let mut text = header_text(
        if idx == 10 {
            &reward_header
        } else if idx == 16 {
            &interval_header
        } else if idx == 8 && m.compact_actions {
            "Global"
        } else {
            ALLOC_COL_NAMES[idx]
        },
        idx,
        m.alloc_sort_col,
        m.alloc_sort_asc,
        m.alloc_col_filters
            .get(&idx)
            .is_some_and(|cf| cf.is_active()),
        m.compact_units,
    );
    if idx == 8 && m.compact_actions && m.header_kpi_visible("Allocation GLOBAL snapshot") {
        text +=
            snapshot_suffix(m, m.allocations.iter().map(|a| a.global_head.as_ref())).trim_start();
    }
    if matches!(idx, 6 | 12 | ALLOC_PROVER_PHASES_COL) {
        warning_slot(&text, true)
    } else {
        text
    }
}

/// Align shared columns through Reward; local and peer context use their own labels.
fn shared_col_widths(
    m: &Model,
    content_width: usize,
    allocations: &[AllocationRow],
    available: &[ShardRow],
) -> (Vec<usize>, Vec<usize>) {
    let (mut alloc, _) = alloc_col_widths(m, content_width, allocations);
    let (mut avail, _) = avail_col_widths(m, content_width, available);
    for i in 0..11 {
        if i != 1 {
            alloc[i] = alloc[i].max(avail[i]);
        }
    }
    let cap = alloc[1].max(avail[1]);
    let interval_width = alloc[16].max(avail[11]);
    alloc[16] = interval_width;
    alloc[1] = filter_width(
        content_width,
        &alloc,
        alloc.iter().filter(|&&w| w > 0).count(),
        cap,
    );
    avail[..11].copy_from_slice(&alloc[..11]);
    avail[11] = interval_width;
    (alloc, avail)
}

fn alloc_col_widths(
    m: &Model,
    content_width: usize,
    sorted: &[AllocationRow],
) -> (Vec<usize>, usize) {
    let (mut widths, fw) = match m.column_sizing {
        ColumnSizing::Dynamic => alloc_widths_measured(m, content_width, sorted),
        ColumnSizing::Fixed => alloc_widths_fixed(m, content_width, sorted),
    };
    // The sizers already leave a hidden ProverPhases out.
    if (0..widths.len()).all(|col| m.alloc_column_visible(col) || col == ALLOC_PROVER_PHASES_COL) {
        return (widths, fw);
    }
    for (col, width) in widths.iter_mut().enumerate() {
        if !m.alloc_column_visible(col) {
            *width = 0;
        }
    }
    let cap = if m.column_sizing == ColumnSizing::Fixed {
        FILTER_WIDTH
    } else {
        filter_cap(
            &alloc_header(m, 1),
            sorted.iter().map(|a| printed_width(&a.filter_hex)),
        )
    };
    widths[1] = filter_width(
        content_width,
        &widths,
        widths.iter().filter(|&&w| w > 0).count(),
        cap,
    );
    let fw = widths[1];
    (widths, fw)
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
            if c == ALLOC_PROVER_PHASES_COL && !m.alloc_column_visible(c) {
                return 0;
            }
            col_width(
                &alloc_header(m, c),
                sorted
                    .iter()
                    .map(|a| printed_width(&alloc_display_cell(m, a, c, 0))),
            )
        })
        .collect();

    let cap = filter_cap(
        &alloc_header(m, 1),
        sorted.iter().map(|a| printed_width(&a.filter_hex)),
    );
    let fw = filter_width(
        content_width,
        &widths,
        n - usize::from(widths[ALLOC_PROVER_PHASES_COL] == 0),
        cap,
    );
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
            .map(|a| printed_width(&alloc_display_cell(m, a, 5, 0))),
    );
    let reward_w = fit(
        ALLOC_REWARD_WIDTH.max(printed_width(&alloc_header(m, 10))),
        sorted
            .iter()
            .map(|a| printed_width(&alloc_display_cell(m, a, 10, 0))),
    );
    let global_head_w = fit(
        GLOBAL_HEAD_WIDTH.max(printed_width(&alloc_header(m, 8))),
        sorted
            .iter()
            .map(|row| printed_width(&alloc_display_cell(m, row, 8, 0))),
    );
    let status_w = fit(
        STATUS_WIDTH,
        sorted
            .iter()
            .map(|row| printed_width(&alloc_display_cell(m, row, 12, 0))),
    );
    // Expanded relative thresholds append a time estimate past the fixed widths.
    let next_w = fit(
        NEXT_ACTION_WIDTH,
        sorted
            .iter()
            .map(|row| printed_width(&alloc_display_cell(m, row, 14, 0))),
    );
    let default_w = fit(
        DEFAULT_ACTION_WIDTH,
        sorted
            .iter()
            .map(|row| printed_width(&alloc_display_cell(m, row, 15, 0))),
    );
    // The optional column has no fixed width: measured when shown, else absent.
    let phases_w = if m.alloc_column_visible(ALLOC_PROVER_PHASES_COL) {
        col_width(
            &alloc_header(m, ALLOC_PROVER_PHASES_COL),
            sorted
                .iter()
                .map(|row| printed_width(&alloc_display_cell(m, row, ALLOC_PROVER_PHASES_COL, 0))),
        )
    } else {
        0
    };
    // Whatever the wide columns took comes out of the flexible Filter column.
    let grown = (status_w - STATUS_WIDTH)
        + (global_head_w - GLOBAL_HEAD_WIDTH)
        + (shards_w - SHARDS_WIDTH)
        + (reward_w - ALLOC_REWARD_WIDTH)
        + (next_w - NEXT_ACTION_WIDTH)
        + (default_w - DEFAULT_ACTION_WIDTH)
        + phases_w
        + usize::from(phases_w > 0);
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
        status_w,
        MODE_WIDTH,
        next_w,
        default_w,
        col_width(
            &alloc_header(m, 16),
            sorted
                .iter()
                .map(|a| printed_width(&alloc_display_cell(m, a, 16, 0))),
        ),
        phases_w,
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
    // A hidden column stays absent, even when it is the sort column.
    if m.alloc_sort_col >= 0
        && (m.alloc_sort_col as usize) < widths.len()
        && widths[m.alloc_sort_col as usize] > 0
    {
        widths[m.alloc_sort_col as usize] += 1;
    }
    if m.compact_units {
        for col in [4, 10] {
            widths[col] = col_width(
                &alloc_header(m, col),
                sorted
                    .iter()
                    .map(|a| printed_width(&alloc_display_cell(m, a, col, 0))),
            );
        }
        fw = filter_width(
            content_width,
            &widths,
            widths.len() - usize::from(phases_w == 0),
            FILTER_WIDTH,
        );
        widths[1] = fw;
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

fn local_warning(m: &Model, a: &AllocationRow) -> bool {
    matches!(
        m.execution_state(a.execution.as_ref()),
        "running" | "serving"
    ) && a.execution.as_ref().and_then(|s| s.materialized_frame) == Some(0)
}

fn local_color(m: &Model, a: &AllocationRow) -> Color {
    let state = m.execution_state(a.execution.as_ref());
    if matches!(state, "running" | "serving")
        && (local_warning(m, a) || m.local_stalled_rows.contains(&a.filter_key))
    {
        Color::Yellow
    } else {
        execution_color(state)
    }
}

fn execution_color(state: &str) -> Color {
    match state {
        "blocked" | "stopped" => ERROR,
        "running" | "serving" => SUCCESS,
        _ => HELP,
    }
}

/// Every execution state an allocation row can show.
const EXECUTION_STATES: [&str; 12] = [
    "starting", "syncing", "serving", "running", "closing", "handoff", "waiting", "blocked",
    "stopped", "stale", "cached", "unknown",
];

fn fmt_global_head(head: Option<&quil_types::proto::node::GlobalAppFrameHead>) -> String {
    head.map(|h| format!("{}@g{}", h.frame, h.generation))
        .unwrap_or_else(|| "-".into())
}

/// The GlobalHead cell; a trailing `!` marks a stalled or trailing committed
/// head for `warning_slot`.
fn committed_head_cell(
    m: &Model,
    head: Option<&quil_types::proto::node::GlobalAppFrameHead>,
    filter: &[u8],
) -> String {
    let text = fmt_global_head(head);
    if head.is_some() && m.committed_app_flagged(filter) {
        text + "!"
    } else {
        text
    }
}

fn snapshot_suffix<'a>(
    m: &Model,
    heads: impl Iterator<Item = Option<&'a quil_types::proto::node::GlobalAppFrameHead>>,
) -> String {
    let heads: Vec<_> = heads.collect();
    if heads.is_empty() || heads.iter().all(|h| h.is_none()) {
        return " @?".into();
    }
    if heads.iter().any(|h| h.is_none()) {
        return " @partial".into();
    }
    let frame = heads[0].unwrap().global_frame;
    if heads.iter().all(|h| h.unwrap().global_frame == frame) {
        frame_citation(m, frame)
    } else {
        " @mixed".into()
    }
}

fn global_snapshot_label<'a>(
    m: &Model,
    heads: impl Iterator<Item = Option<&'a quil_types::proto::node::GlobalAppFrameHead>>,
) -> String {
    let mut frames = heads.flatten().map(|h| h.global_frame);
    let Some(frame) = frames.next() else {
        return "Snapshot: unavailable".into();
    };
    if frames.all(|f| f == frame) {
        if m.compact_actions {
            format!("Snapshot{}", frame_citation(m, frame))
        } else {
            format!("Snapshot: @f{frame}")
        }
    } else {
        "Snapshot: mixed".into()
    }
}

fn allocation_detail(m: &Model, a: &AllocationRow) -> Line<'static> {
    let binding_detail = if a.status_name == "bound" {
        "Worker bound; no live allocation reported. "
    } else {
        ""
    };
    let Some(execution) = a.execution.as_ref() else {
        if matches!(a.status_name.as_str(), "joining" | "activating") {
            return peer_materialization_detail(a.materialized_frame, a.latest_frame);
        }
        return Line::from(Span::styled(
            format!("{binding_detail}Local execution details unavailable"),
            Style::new().fg(if binding_detail.is_empty() {
                HELP
            } else {
                WARNING
            }),
        ));
    };
    let mut text = format!(
        "{binding_detail}Last advance: {}",
        if execution.last_advance_unix_ms == 0 {
            "not observed since start"
        } else {
            advance_age(execution.last_advance_unix_ms)
        }
    );
    let state = m.execution_state(Some(execution));
    if !execution.blocker.is_empty() {
        let label = if matches!(execution.state.as_str(), "blocked" | "stopped")
            && execution.blocker != "awaiting successor"
        {
            "Blocker"
        } else {
            "Reason"
        };
        text += &format!(" | {label}: {}", execution.blocker);
    }
    if let Some(coverage) = cadence_coverage(m, &a.filter) {
        text += &format!(" | {coverage}");
    }
    if local_warning(m, a) {
        text += " | Local app frames: none materialized.";
    }
    if let Some(r) = execution.recovery.as_ref() {
        text += &format!(
            " | {}",
            if m.compact_actions {
                recovery_summary(r)
            } else {
                recovery(r)
            }
        );
    }
    if let Some(seal) = execution.seal.as_ref() {
        text += &format!(
            " | {}",
            if m.compact_actions {
                seal_summary(seal)
            } else {
                sealed(seal)
            }
        );
    }
    if matches!(state, "cached" | "stale") {
        text += &format!(" | Observation: {state}");
    }
    let color = if matches!(state, "cached" | "stale") {
        HELP
    } else if matches!(state, "blocked" | "stopped") {
        ERROR
    } else if local_warning(m, a) {
        WARNING
    } else {
        HELP
    };
    Line::from(Span::styled(text, Style::new().fg(color)))
}

fn allocation_detail_lines(m: &Model, sorted: &[AllocationRow], area: Rect) -> Vec<Line<'static>> {
    if area.height < 3 || area.width == 0 {
        return vec![];
    }
    let Some(row) = sorted.get(m.alloc_cursor) else {
        return vec![];
    };
    let mut lines = wrap_message(allocation_detail(m, row), area.width);
    let limit = usize::from(area.height.saturating_sub(2))
        .min(usize::from(area.height / 2))
        .max(1);
    if lines.len() > limit {
        lines.truncate(limit);
        lines[limit - 1] = Line::from(Span::styled(
            "… enlarge panel for details",
            Style::new().fg(HELP),
        ));
        lines[limit - 1] = wrap_message(lines[limit - 1].clone(), area.width)
            .into_iter()
            .next()
            .unwrap_or_default();
    }
    lines
}

fn render_alloc_panel(
    m: &mut Model,
    sorted: &[AllocationRow],
    area: Rect,
    aligned: Option<&[usize]>,
) -> Vec<Line<'static>> {
    let content_width = area.width as usize;
    let height = area.height as usize;
    if sorted.is_empty() {
        if !m.data_loaded {
            return vec![Line::from(format!("  {} Loading allocations…", spinner(m)))];
        }
        return vec![Line::from("  No allocations")];
    }
    let (widths, fw) = aligned
        .map(|w| (w.to_vec(), w[1]))
        .unwrap_or_else(|| alloc_col_widths(m, content_width, sorted));
    let filter_hi = m.active_filter_col_idx();

    // Header row.
    let mut hdr_spans: Vec<Span> = Vec::new();
    for &i in m.alloc_display_columns() {
        if !m.alloc_column_visible(i) {
            continue;
        }
        let hi_sort = m.sort_mode && m.focus.is_alloc() && m.sort_highlight_col == i;
        let hi_filter = m.alloc_filter_mode
            && !m.filter_edit_active
            && m.focus.is_alloc()
            && filter_hi == i as i32;
        let style = if hi_sort {
            Style::new()
                .bg(HEADER_BG)
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
    let longest_suffix = sorted
        .iter()
        .map(|a| a.filter_hex.len().saturating_sub(64))
        .max()
        .unwrap_or(0);
    for i in m.alloc_offset..end {
        let a = &sorted[i];
        let selected = i == m.alloc_cursor;

        let cells: Vec<String> = (0..widths.len())
            .map(|c| {
                let cell = if c == 1 && shared_address {
                    filter_label(&a.filter_hex, fw, longest_suffix)
                } else {
                    alloc_display_cell(m, a, c, fw)
                };
                pad_cell(&cell, widths[c], alloc_left_aligned(c))
            })
            .collect();

        if selected {
            let mut spans = Vec::new();
            for &ci in m.alloc_display_columns() {
                let cell = &cells[ci];
                if !m.alloc_column_visible(ci) {
                    continue;
                }
                if ci > 0 {
                    spans.push(Span::raw(" "));
                }
                let color = if m.color_coding && matches!(ci, 6 | 9) {
                    local_color(m, a)
                } else if ci == 7 && m.color_coding && m.reported_app_stalled(&a.filter) {
                    WARNING
                } else if ci == 8 && m.color_coding && m.committed_app_flagged(&a.filter) {
                    WARNING
                } else if ci == ALLOC_PROVER_PHASES_COL
                    && m.color_coding
                    && prover_halt_risk(a.prover_counts.as_ref(), &a.shard_size)
                {
                    WARNING
                } else if ci == 10 && m.color_coding && a.worker_id < 0 {
                    ERROR
                } else if ci == 12 && m.color_coding {
                    status_color(&a.status_name)
                } else {
                    TEXT
                };
                spans.push(Span::styled(cell.clone(), Style::new().fg(color)));
            }
            let used = cells
                .iter()
                .enumerate()
                .filter(|(col, _)| m.alloc_column_visible(*col))
                .map(|(_, cell)| printed_width(cell))
                .sum::<usize>()
                + widths.iter().filter(|&&w| w > 0).count().saturating_sub(1);
            spans.push(Span::raw(" ".repeat(content_width.saturating_sub(used))));
            lines.push(
                Line::from(spans).style(Style::new().fg(TEXT).bg(if m.focus.is_alloc() {
                    CURSOR_BG
                } else {
                    INACTIVE_CURSOR_BG
                })),
            );
        } else {
            let mut spans: Vec<Span> = Vec::new();
            for &ci in m.alloc_display_columns() {
                let cell = &cells[ci];
                if !m.alloc_column_visible(ci) {
                    continue;
                }
                if ci > 0 {
                    spans.push(Span::raw(" "));
                }
                let span = match ci {
                    3 if m.color_coding => {
                        Span::styled(cell.clone(), Style::new().fg(ring_color(a.ring)))
                    }
                    // Local engine health and the peer gap are separate observations.
                    6 | 9 if m.color_coding => {
                        Span::styled(cell.clone(), Style::new().fg(local_color(m, a)))
                    }
                    7 if m.color_coding && m.reported_app_stalled(&a.filter) => {
                        Span::styled(cell.clone(), Style::new().fg(WARNING))
                    }
                    8 if m.color_coding && m.committed_app_flagged(&a.filter) => {
                        Span::styled(cell.clone(), Style::new().fg(WARNING))
                    }
                    7 | 8 if m.color_coding => Span::styled(cell.clone(), Style::new().fg(HELP)),
                    ALLOC_PROVER_PHASES_COL
                        if m.color_coding
                            && prover_halt_risk(a.prover_counts.as_ref(), &a.shard_size) =>
                    {
                        Span::styled(cell.clone(), Style::new().fg(WARNING))
                    }
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
        while lines.len() < height - 1 {
            lines.push(Line::default());
        }
        if let Some(a) = sorted.get(m.alloc_cursor) {
            lines.push(allocation_detail(m, a));
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
/// value under it, and the unsuffixed variants disagreed with the `Size [GB]`
/// and `Reward [~Q/d]` headers that were already stating those units. One
/// rendering per cell settles both, and drops the widest reward cell from 15
/// columns to 12.
fn avail_cell(m: &Model, s: &ShardRow, col: usize, fw: usize) -> String {
    match col {
        0 => avail_marker(m, s).to_string(),
        1 => center_trunc(&s.filter_hex, fw),
        2 => s.active_provers.to_string(),
        3 => fmt_ring(s.ring),
        4 => fmt_gb(&s.shard_size),
        5 => s.data_shards.to_string(),
        6 => fmt_materialized(s.materialized_frame, s.latest_frame),
        7 => {
            if s.materialized_frame == 0 && s.latest_frame == 0 {
                "-".into()
            } else {
                s.latest_frame.to_string()
            }
        }
        8 => committed_head_cell(m, s.global_head.as_ref(), &s.filter),
        9 if m.reported_app_stalled(&s.filter) => "stalled!".into(),
        9 => {
            let state = materialization_state(s.materialized_frame, s.latest_frame);
            if matches!(state, "lag" | "unmat") {
                format!("{state}!")
            } else {
                state.to_string()
            }
        }
        11 => interval_values(m, m.node_app_cadence.get(&s.filter), m.interval_mask()),
        AVAIL_PROVER_PHASES_COL => prover_phases_cell(m, s.prover_counts.as_ref(), &s.shard_size),
        _ => {
            if s.ring == UNKNOWN_REWARD_RING {
                "-".into()
            } else {
                reward_cell(m, &s.estimated_reward, &s.filter)
            }
        }
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
    let reward_header = format!("Reward [~Q/d {}]", m.reward_labels());
    let interval_header = format!("Interval [s {}]", m.interval_labels());
    let mut text = header_text(
        if idx == 10 {
            &reward_header
        } else if idx == 11 {
            &interval_header
        } else if idx == 8 && m.compact_actions {
            "Global"
        } else {
            AVAIL_COL_NAMES[idx]
        },
        idx,
        m.avail_sort_col,
        m.avail_sort_asc,
        m.avail_col_filters
            .get(&idx)
            .is_some_and(|cf| cf.is_active()),
        m.compact_units,
    );
    if idx == 8 && m.compact_actions && m.header_kpi_visible("Available GLOBAL snapshot") {
        text += snapshot_suffix(m, m.available.iter().map(|s| s.global_head.as_ref())).trim_start();
    }
    if matches!(idx, 9 | AVAIL_PROVER_PHASES_COL) {
        warning_slot(&text, true)
    } else {
        text
    }
}

fn avail_col_widths(m: &Model, content_width: usize, sorted: &[ShardRow]) -> (Vec<usize>, usize) {
    let (mut widths, fw) = match m.column_sizing {
        ColumnSizing::Dynamic => avail_widths_measured(m, content_width, sorted),
        ColumnSizing::Fixed => avail_widths_fixed(m, content_width, sorted),
    };
    if (0..widths.len()).all(|col| m.avail_column_visible(col) || col == AVAIL_PROVER_PHASES_COL) {
        return (widths, fw);
    }
    for (col, width) in widths.iter_mut().enumerate() {
        if !m.avail_column_visible(col) {
            *width = 0;
        }
    }
    let cap = if m.column_sizing == ColumnSizing::Fixed {
        FILTER_WIDTH
    } else {
        filter_cap(
            &avail_header(m, 1),
            sorted.iter().map(|a| printed_width(&a.filter_hex)),
        )
    };
    widths[1] = filter_width(
        content_width,
        &widths,
        widths.iter().filter(|&&w| w > 0).count(),
        cap,
    );
    let fw = widths[1];
    (widths, fw)
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
            if c == AVAIL_PROVER_PHASES_COL && !m.avail_column_visible(c) {
                return 0;
            }
            col_width(
                &avail_header(m, c),
                sorted
                    .iter()
                    .map(|s| printed_width(&avail_display_cell(m, s, c, 0))),
            )
        })
        .collect();

    let cap = filter_cap(
        &avail_header(m, 1),
        sorted.iter().map(|s| printed_width(&s.filter_hex)),
    );
    let fw = filter_width(
        content_width,
        &widths,
        n - usize::from(widths[AVAIL_PROVER_PHASES_COL] == 0),
        cap,
    );
    widths[1] = fw;
    (widths, fw)
}

fn avail_widths_fixed(m: &Model, content_width: usize, sorted: &[ShardRow]) -> (Vec<usize>, usize) {
    let shards_w = fit(
        SHARDS_WIDTH,
        sorted
            .iter()
            .map(|s| printed_width(&avail_display_cell(m, s, 5, 0))),
    );
    let reward_w = fit(
        REWARD_WIDTH.max(printed_width(&avail_header(m, 10))),
        sorted
            .iter()
            .map(|s| printed_width(&avail_display_cell(m, s, 10, 0))),
    );
    let global_head_w = fit(
        GLOBAL_HEAD_WIDTH.max(printed_width(&avail_header(m, 8))),
        sorted
            .iter()
            .map(|row| printed_width(&avail_display_cell(m, row, 8, 0))),
    );
    let state_w = STATE_WIDTH.max(printed_width(&avail_header(m, 9)));
    let phases_w = if m.avail_column_visible(AVAIL_PROVER_PHASES_COL) {
        col_width(
            &avail_header(m, AVAIL_PROVER_PHASES_COL),
            sorted
                .iter()
                .map(|row| printed_width(&avail_display_cell(m, row, AVAIL_PROVER_PHASES_COL, 0))),
        )
    } else {
        0
    };
    let grown = (state_w - STATE_WIDTH)
        + (global_head_w - GLOBAL_HEAD_WIDTH)
        + (shards_w - SHARDS_WIDTH)
        + (reward_w - REWARD_WIDTH)
        + phases_w
        + usize::from(phases_w > 0);
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
        state_w,
        reward_w,
        col_width(
            &avail_header(m, 11),
            sorted
                .iter()
                .map(|row| printed_width(&avail_display_cell(m, row, 11, 0))),
        ),
        phases_w,
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
    if m.avail_sort_col >= 0
        && (m.avail_sort_col as usize) < widths.len()
        && widths[m.avail_sort_col as usize] > 0
    {
        widths[m.avail_sort_col as usize] += 1;
    }
    if m.compact_units {
        for col in [4, 10] {
            widths[col] = col_width(
                &avail_header(m, col),
                sorted
                    .iter()
                    .map(|s| printed_width(&avail_display_cell(m, s, col, 0))),
            );
        }
        fw = filter_width(
            content_width,
            &widths,
            widths.len() - usize::from(phases_w == 0),
            FILTER_WIDTH,
        );
        widths[1] = fw;
    }
    (widths, fw)
}

fn available_detail(m: &Model, s: &ShardRow) -> Line<'static> {
    let mut line = peer_materialization_detail(s.materialized_frame, s.latest_frame);
    if let Some(coverage) = cadence_coverage(m, &s.filter) {
        line.spans.push(Span::styled(
            format!(" | {coverage}"),
            Style::new().fg(HELP),
        ));
    }
    line
}

fn peer_materialization_detail(materialized: u64, latest: u64) -> Line<'static> {
    let (message, color) = match materialization_state(materialized, latest) {
        "unmat" => ("Peer app frames: none materialized.".into(), Color::Yellow),
        "lag" => (
            format!(
                "Peer materialization trails its head by {} frame{}.",
                latest.saturating_sub(materialized),
                if latest.saturating_sub(materialized) == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            Color::Yellow,
        ),
        "current" => ("Peer materialization is current.".into(), HELP),
        _ => ("Peer app frame heights unavailable.".into(), HELP),
    };
    Line::from(Span::styled(message, Style::new().fg(color)))
}

fn render_avail_panel(
    m: &mut Model,
    sorted: &[ShardRow],
    area: Rect,
    aligned: Option<&[usize]>,
) -> Vec<Line<'static>> {
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
    let (widths, fw) = aligned
        .map(|w| (w.to_vec(), w[1]))
        .unwrap_or_else(|| avail_col_widths(m, content_width, sorted));
    let filter_hi = m.active_filter_col_idx();

    let mut hdr_spans: Vec<Span> = Vec::new();
    for &i in m.avail_display_columns() {
        if !m.avail_column_visible(i) {
            continue;
        }
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
            format!("{error} (showing cached shards)"),
            Style::new().fg(Color::Yellow),
        )));
    }
    lines.push(Line::from(hdr_spans));

    let detail_rows = usize::from(height >= 3);
    let visible = height.saturating_sub(lines.len() + detail_rows).max(1);
    m.avail_offset = clamp_offset(m.avail_offset, m.avail_cursor, visible, sorted.len());
    let end = (m.avail_offset + visible).min(sorted.len());

    let shared_address = shared_filter_address(sorted.iter().map(|s| s.filter_hex.as_str()));
    let longest_suffix = sorted
        .iter()
        .map(|s| s.filter_hex.len().saturating_sub(64))
        .max()
        .unwrap_or(0);
    for i in m.avail_offset..end {
        let s = &sorted[i];
        let selected = i == m.avail_cursor;

        if selected {
            let cells: Vec<String> = (0..widths.len())
                .map(|c| {
                    let cell = if c == 1 && shared_address {
                        filter_label(&s.filter_hex, fw, longest_suffix)
                    } else {
                        avail_display_cell(m, s, c, fw)
                    };
                    pad_cell(&cell, widths[c], c == 1)
                })
                .collect();
            let mut spans = Vec::new();
            for &c in m.avail_display_columns() {
                let cell = &cells[c];
                if !m.avail_column_visible(c) {
                    continue;
                }
                if c > 0 {
                    spans.push(Span::raw(" "));
                }
                let color =
                    if m.color_coding && matches!(c, 7 | 9) && m.reported_app_stalled(&s.filter) {
                        WARNING
                    } else if m.color_coding && c == 8 && m.committed_app_flagged(&s.filter) {
                        WARNING
                    } else if m.color_coding && matches!(c, 6 | 9) {
                        materialization_state_color(materialization_state(
                            s.materialized_frame,
                            s.latest_frame,
                        ))
                    } else if m.color_coding
                        && c == AVAIL_PROVER_PHASES_COL
                        && prover_halt_risk(s.prover_counts.as_ref(), &s.shard_size)
                    {
                        WARNING
                    } else {
                        TEXT
                    };
                spans.push(Span::styled(cell.clone(), Style::new().fg(color)));
            }
            let used = cells
                .iter()
                .enumerate()
                .filter(|(col, _)| m.avail_column_visible(*col))
                .map(|(_, cell)| printed_width(cell))
                .sum::<usize>()
                + widths.iter().filter(|&&w| w > 0).count().saturating_sub(1);
            spans.push(Span::raw(" ".repeat(content_width.saturating_sub(used))));
            lines.push(
                Line::from(spans).style(Style::new().fg(TEXT).bg(
                    if m.focus == PanelFocus::Available {
                        CURSOR_BG
                    } else {
                        INACTIVE_CURSOR_BG
                    },
                )),
            );
        } else {
            // Non-selected: size uses human-readable storage; ring colored.

            let mut spans: Vec<Span> = Vec::new();
            for &c in m.avail_display_columns() {
                if !m.avail_column_visible(c) {
                    continue;
                }
                if c > 0 {
                    spans.push(Span::raw(" "));
                }
                let cell = if c == 1 && shared_address {
                    filter_label(&s.filter_hex, fw, longest_suffix)
                } else {
                    avail_display_cell(m, s, c, fw)
                };
                let cell = pad_cell(&cell, widths[c], c == 1);
                spans.push(match c {
                    3 if m.color_coding => Span::styled(cell, Style::new().fg(ring_color(s.ring))),
                    7 | 9 if m.color_coding && m.reported_app_stalled(&s.filter) => {
                        Span::styled(cell, Style::new().fg(WARNING))
                    }
                    8 if m.color_coding && m.committed_app_flagged(&s.filter) => {
                        Span::styled(cell, Style::new().fg(WARNING))
                    }
                    7 | 8 if m.color_coding => Span::styled(cell, Style::new().fg(HELP)),
                    AVAIL_PROVER_PHASES_COL
                        if m.color_coding
                            && prover_halt_risk(s.prover_counts.as_ref(), &s.shard_size) =>
                    {
                        Span::styled(cell, Style::new().fg(WARNING))
                    }
                    6 | 9 if m.color_coding => {
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
        while lines.len() < height - 1 {
            lines.push(Line::default());
        }
        if let Some(s) = sorted.get(m.avail_cursor) {
            lines.push(available_detail(m, s));
        }
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
        for hint in span
            .content
            .split("  ")
            .map(str::trim)
            .filter(|hint| !hint.is_empty())
        {
            let hint = Span::styled(hint.to_owned(), span.style);
            if !line.spans.is_empty() && line.width() + 1 + hint.width() > usize::from(width) {
                lines.push(line);
                line = Line::default();
            }
            if !line.spans.is_empty() {
                line.spans.push(Span::raw(" "));
            }
            line.spans.push(hint);
        }
    }
    if !line.spans.is_empty() {
        lines.push(line);
    }
    lines
}

fn footer_lines(m: &Model) -> (Line<'static>, Line<'static>) {
    if m.operation_confirmation.is_some() {
        return (
            Line::from(Span::styled(
                "Confirm: ‹enter› confirm  ‹esc› cancel  ‹q› quit",
                Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
            )),
            status_line(m),
        );
    }
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
                "Filter [{col_name}]: ‹←/→› column  ‹enter› edit  ‹del› clear  ‹x› disable all  ‹esc› close"
            ),
            Style::new().fg(FILTER).add_modifier(Modifier::BOLD),
        ));
        return (actions, status_line(m));
    }
    if m.sort_mode && m.sort_order_mode {
        return (
            Line::from(Span::styled(
                "Sort order: ‹enter/a› ascending (default)  ‹d› descending  ‹esc› cancel",
                Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        );
    }
    if m.sort_mode {
        return (
            Line::from(Span::styled(
                "Sort: ‹←/→› Move column  ‹enter› apply  ‹esc› cancel",
                Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        );
    }
    (help_line(m), status_line(m))
}

const MESSAGE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

fn message_timestamp(time: Option<std::time::SystemTime>) -> String {
    let seconds = time
        .unwrap_or_else(std::time::SystemTime::now)
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!(
        "[{:02}:{:02}:{:02} UTC] ",
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// Expire completed action notices, while retaining an operation in progress
/// or a refresh failure that is still unresolved. No extra timer task needed.
fn update_message_lifetime(m: &mut Model) {
    if global_alarm_active(m) {
        m.global_alarm_time
            .get_or_insert_with(std::time::SystemTime::now);
    } else {
        m.global_alarm_time = None;
    }
    if rpc_status_is_fresh(m)
        && m.reported_app_stall_counts(std::time::Instant::now())
            .is_some()
    {
        m.reported_app_stall_time
            .get_or_insert_with(std::time::SystemTime::now);
    } else {
        m.reported_app_stall_time = None;
    }
    let active: Vec<&'static str> = condition_notices(m)
        .into_iter()
        .map(|(key, ..)| key)
        .collect();
    m.notice_since.retain(|key, _| active.contains(key));
    for key in active {
        m.notice_since
            .entry(key)
            .or_insert_with(std::time::SystemTime::now);
    }
    if m.status_message_key != m.status_msg {
        m.status_message_key = m.status_msg.clone();
        m.status_message_seen = Some(std::time::Instant::now());
        m.status_message_time = Some(std::time::SystemTime::now());
    }
    if !m.action_in_flight
        && m.consecutive_failures == 0
        && m.status_message_seen
            .is_some_and(|t| t.elapsed() >= MESSAGE_TTL)
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
        if m.cached_shard_info.is_some() {
            NoticeSeverity::Warning
        } else {
            NoticeSeverity::Error
        }
    } else if m.shard_loading
        && m.shard_fetch_started
            .is_some_and(|t| t.elapsed().as_secs() >= 15)
    {
        NoticeSeverity::Warning
    } else {
        NoticeSeverity::Info
    }
}

/// One short notice per current state; repeated polls do not create a feed.
fn shard_message(m: &Model) -> Option<Line<'static>> {
    let elapsed = m
        .shard_fetch_started
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);
    let message = if let Some(error) = &m.shard_error {
        let reason = if error.contains("timed out") {
            "Shard fetch timed out".to_owned()
        } else {
            let mut text: String = error.chars().take(90).collect();
            if error.chars().count() > 90 {
                text.push('…');
            }
            text
        };
        format!(
            "{reason}; retrying{}.",
            if m.cached_shard_info.is_some() {
                " (cached rows)"
            } else {
                ""
            }
        )
    } else if m.shard_loading {
        if elapsed >= 15 {
            format!("Shard fetch slow ({elapsed}s).")
        } else {
            format!("Fetching shards ({elapsed}s).")
        }
    } else if let Some(shards) = &m.cached_shard_info {
        if m.shard_last_success
            .is_some_and(|t| t.elapsed() >= MESSAGE_TTL)
        {
            return None;
        }
        let elapsed = m.shard_last_duration.map(|d| d.as_secs()).unwrap_or(0);
        format!("Shards updated: {} ({elapsed}s).", shards.shards.len())
    } else {
        return None;
    };
    let color = match shard_severity(m) {
        NoticeSeverity::Info => HELP,
        NoticeSeverity::Warning => Color::Yellow,
        NoticeSeverity::Error => ERROR,
    };
    Some(Line::from(Span::styled(
        format!("{}{message}", message_timestamp(m.shard_message_time)),
        Style::new().fg(color),
    )))
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
                    if !line.spans.is_empty() {
                        lines.push(line);
                        line = Line::default();
                    }
                    lines.push(Line::from(Span::styled(
                        std::mem::take(&mut part),
                        span.style,
                    )));
                }
                part.push(ch);
            }
            if !line.spans.is_empty()
                && line.width() + 1 + printed_width(&part) > usize::from(width)
            {
                lines.push(line);
                line = Line::default();
            }
            if !line.spans.is_empty() {
                line.spans.push(Span::raw(" "));
            }
            line.spans.push(Span::styled(part, span.style));
        }
    }
    if !line.spans.is_empty() {
        lines.push(line);
    }
    lines
}

/// Staffed earning allocations past their activation waits; local progress
/// and execution notices judge only these.
fn earning_allocations(m: &Model) -> Vec<&AllocationRow> {
    m.allocations
        .iter()
        .filter(|a| {
            matches!(
                a.reward_status(m.epoch_frame(), m.epoch_length),
                Some(EffectiveStatus::Active | EffectiveStatus::Leaving)
            )
        })
        .filter(|a| {
            !matches!(
                m.execution_state(a.execution.as_ref()),
                "waiting" | "syncing" | "closing" | "handoff"
            )
        })
        .collect()
}

/// Judge each staffed earning allocation with a fresh observation on its own:
/// missing or old data is excluded rather than reported as a stall, and one
/// advancing allocation does not hide another that stopped.
fn update_app_progress_warning(m: &mut Model) {
    let rows: Vec<(String, u64)> = if m.reachable {
        earning_allocations(m)
            .into_iter()
            .filter_map(|a| {
                let e = a.execution.as_ref()?;
                (e.materialized_frame.is_some()
                    && matches!(
                        m.execution_state(Some(e)),
                        "starting" | "running" | "serving" | "blocked" | "stopped"
                    ))
                .then(|| (a.filter_key.clone(), e.last_advance_unix_ms))
            })
            .collect()
    } else {
        Vec::new()
    };
    if rows.is_empty() {
        m.app_progress_observed_since = None;
        m.app_stall_time = None;
        m.local_stalled_rows.clear();
        m.local_stalled_count = 0;
        m.local_app_rows = 0;
        return;
    }
    let observed = *m
        .app_progress_observed_since
        .get_or_insert_with(std::time::Instant::now);
    let now = std::time::SystemTime::now();
    let now_ms = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    m.local_app_rows = rows.len();
    let stalled: Vec<String> = rows
        .into_iter()
        .filter(|(_, last)| {
            if *last == 0 {
                observed.elapsed().as_secs() >= 60
            } else {
                now_ms.saturating_sub(*last) >= 60_000
            }
        })
        .map(|(key, _)| key)
        .collect();
    m.local_stalled_count = stalled.len();
    m.local_stalled_rows = stalled.into_iter().collect();
    if m.local_stalled_count == 0 {
        m.app_stall_time = None;
    } else {
        m.app_stall_time.get_or_insert(now);
    }
}

/// Current active + leaving forecasts in the 60m and 24h windows when the
/// 60m one is below half the 24h one. Only rows whose shard has 30 min of
/// 60m and 2h of 24h coverage count; both windows price frames alike.
fn reward_drop(m: &Model) -> Option<(BigInt, BigInt)> {
    let (mut hour, mut day, mut rows) = (BigInt::from(0), BigInt::from(0), 0);
    for a in &m.allocations {
        if a.ring == UNKNOWN_REWARD_RING
            || !matches!(
                a.reward_status(m.epoch_frame(), m.epoch_length),
                Some(EffectiveStatus::Active | EffectiveStatus::Leaving)
            )
        {
            continue;
        }
        let Some(cadence) = m.node_app_cadence.get(&a.filter) else {
            continue;
        };
        let covered = |w: Option<&quil_types::proto::node::FrameWindow>, seconds: u64| {
            w.is_some_and(|w| w.observed_seconds >= seconds)
        };
        if !covered(cadence.hour.as_ref(), 1800) || !covered(cadence.day.as_ref(), 7200) {
            continue;
        }
        let (Some(h), Some(d)) = (
            m.daily_reward(&a.estimated_reward, &a.filter, 0),
            m.daily_reward(&a.estimated_reward, &a.filter, 1),
        ) else {
            continue;
        };
        hour += h;
        day += d;
        rows += 1;
    }
    (rows > 0 && day.sign() == num_bigint::Sign::Plus && BigInt::from(2) * &hour < day)
        .then_some((hour, day))
}

/// Conditions that need attention besides the progress stalls: key, severity
/// and text without its timestamp. Each needs fresh node status; missing or
/// old data establishes none. Definitions belong in help.
fn condition_notices(m: &Model) -> Vec<(&'static str, NoticeSeverity, String)> {
    let mut notices = Vec::new();
    if !rpc_status_is_fresh(m) {
        return notices;
    }
    if let Some((stalled, behind, known)) = m.committed_app_counts(std::time::Instant::now()) {
        if stalled > 0 {
            notices.push((
                "global-app-unchanged",
                NoticeSeverity::Warning,
                format!(
                    "{}: {stalled}/{known} tracked shards.",
                    progress_stall_text("Global app frames", 60.max(m.refresh_seconds * 3))
                ),
            ));
        }
        if behind > 0 {
            notices.push((
                "global-app-behind",
                NoticeSeverity::Warning,
                format!(
                    "Global app frames >{GLOBAL_APP_LAG_FRAMES} behind app heads: \
                     {behind}/{known} tracked shards."
                ),
            ));
        }
    }
    if let Some((hour, day)) = reward_drop(m) {
        notices.push((
            "reward-drop",
            NoticeSeverity::Warning,
            format!(
                "Reward now 60m {} vs 24h {} Q/d.",
                super::super::format_quil_daily_units(&hour),
                super::super::format_quil_daily_units(&day)
            ),
        ));
    }
    let worker_fresh = m
        .worker_snapshot_received
        .is_some_and(|(t, _)| t.elapsed().as_secs() <= m.refresh_seconds * 2 + 30);
    let allocations: Vec<_> = m.allocations.iter().filter(|a| a.status != 0).collect();
    let due: Vec<_> = allocations
        .iter()
        .filter(|a| {
            matches!(
                a.status_name.as_str(),
                "active" | "leaving" | "departing" | "re-confirm!"
            )
        })
        .collect();
    let workerless = due.iter().filter(|a| a.worker_id < 0).count();
    if worker_fresh && workerless > 0 {
        notices.push((
            "allocation-workerless",
            NoticeSeverity::Error,
            format!("Allocations without a worker: {workerless}/{}.", due.len()),
        ));
    }
    let observed: Vec<_> = earning_allocations(m)
        .into_iter()
        .filter(|a| {
            matches!(
                m.execution_state(a.execution.as_ref()),
                "starting" | "running" | "serving" | "blocked" | "stopped"
            )
        })
        .collect();
    let failed = observed
        .iter()
        .filter(|a| {
            matches!(
                m.execution_state(a.execution.as_ref()),
                "blocked" | "stopped"
            )
        })
        .count();
    if failed > 0 {
        notices.push((
            "local-execution-failed",
            NoticeSeverity::Error,
            format!(
                "Local execution blocked or stopped: {failed}/{} allocations.",
                observed.len()
            ),
        ));
    }
    let stale = allocations
        .iter()
        .filter(|a| a.status_name == "re-confirm!")
        .count();
    if stale > 0 {
        notices.push((
            "allocation-epoch-stale",
            NoticeSeverity::Warning,
            format!(
                "Allocation epoch stale (re-confirm!): {stale}/{} allocations.",
                allocations.len()
            ),
        ));
    }
    let workers: Vec<_> = m
        .allocations
        .iter()
        .filter(|a| {
            !matches!(
                m.execution_state(a.execution.as_ref()),
                "unknown" | "stale" | "cached"
            )
        })
        .collect();
    let recovery_failed = workers
        .iter()
        .filter(|a| {
            a.execution
                .as_ref()
                .and_then(|e| e.recovery.as_ref())
                .is_some_and(|r| r.last_error_unix_ms > r.last_outcome_unix_ms)
        })
        .count();
    if recovery_failed > 0 {
        notices.push((
            "recovery-failed",
            NoticeSeverity::Warning,
            format!(
                "Last recovery attempt failed: {recovery_failed}/{} workers.",
                workers.len()
            ),
        ));
    }
    notices
}

/// Shared progress-notice convention; tracker definitions belong in help.
fn progress_stall_text(signal: &str, seconds: u64) -> String {
    format!("{signal} unchanged >{seconds}s")
}

fn message_lines(m: &Model, primary: Line<'static>, width: u16) -> Vec<Line<'static>> {
    let primary_severity = if m.status_is_error {
        NoticeSeverity::Error
    } else {
        NoticeSeverity::Info
    };
    // Filter-editor prompts are controls rather than notifications.
    let primary = if m.filter_edit_active
        || m.operation_confirmation.is_some()
        || primary_severity >= m.notice_minimum
    {
        wrap_message(primary, width)
    } else {
        Vec::new()
    };
    let shard_severity = shard_severity(m);
    let shards = if shard_severity >= m.notice_minimum {
        shard_message(m)
            .map(|line| wrap_message(line, width))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut lines = Vec::new();
    if global_alarm_active(m) {
        lines.extend(wrap_message(
            Line::from(Span::styled(
                format!(
                    "{}{}.",
                    message_timestamp(m.global_alarm_time),
                    progress_stall_text("Global head", 60)
                ),
                Style::new().fg(ERROR),
            )),
            width,
        ));
    }
    if m.notice_minimum <= NoticeSeverity::Warning {
        if rpc_status_is_fresh(m) {
            if let Some((stalled, known)) = m.reported_app_stall_counts(std::time::Instant::now()) {
                lines.extend(wrap_message(
                    Line::from(Span::styled(
                        format!(
                            "{}{}: {stalled}/{known} tracked shards.",
                            message_timestamp(m.reported_app_stall_time),
                            progress_stall_text("Peer app frames", 60.max(m.refresh_seconds * 3))
                        ),
                        Style::new().fg(Color::Yellow),
                    )),
                    width,
                ));
            }
        }
        if let Some(time) = m.app_stall_time {
            lines.extend(wrap_message(
                Line::from(Span::styled(
                    format!(
                        "{}{}: {}/{} allocations.",
                        message_timestamp(Some(time)),
                        progress_stall_text("Local app frames", 60),
                        m.local_stalled_count,
                        m.local_app_rows
                    ),
                    Style::new().fg(Color::Yellow),
                )),
                width,
            ));
        }
    }
    for (key, severity, text) in condition_notices(m) {
        if severity >= m.notice_minimum {
            lines.extend(wrap_message(
                Line::from(Span::styled(
                    format!(
                        "{}{text}",
                        message_timestamp(m.notice_since.get(key).copied())
                    ),
                    Style::new().fg(if severity == NoticeSeverity::Error {
                        ERROR
                    } else {
                        WARNING
                    }),
                )),
                width,
            ));
        }
    }
    if shard_severity > primary_severity {
        lines.extend(shards);
        lines.extend(primary);
    } else {
        lines.extend(primary);
        lines.extend(shards);
    }
    if lines.is_empty() {
        lines.push(Line::default());
    }
    lines
}

fn status_line(m: &Model) -> Line<'static> {
    if let Some((command, targets)) = &m.operation_confirmation {
        let label = match command {
            'l' => "Leave",
            'r' => "Reject",
            'p' => "Pause",
            _ => "Change worker mode",
        };
        return Line::from(Span::styled(
            format!(
                "{label} for {} allocation(s)? Enter confirms; Esc cancels.",
                targets.len()
            ),
            Style::new().fg(WARNING),
        ));
    }
    if m.action_in_flight {
        return Line::from(format!(
            "{}{} {}",
            message_timestamp(m.status_message_time),
            spinner(m),
            m.status_msg
        ));
    }
    if m.status_msg.is_empty() {
        return Line::from("");
    }
    let color = if m.operation_confirmation.is_some() {
        WARNING
    } else if m.status_is_error {
        ERROR
    } else {
        SUCCESS
    };
    Line::from(Span::styled(
        format!(
            "{}{}",
            message_timestamp(m.status_message_time),
            m.status_msg
        ),
        Style::new().fg(color),
    ))
}

/// `renderHelpLine` — key hints with applicable actions highlighted.
fn command_hint(key: &str, description: &str, style: Style) -> Span<'static> {
    Span::styled(format!("‹{key}› {description}"), style)
}

fn help_commands() -> Line<'static> {
    let mut spans = Vec::new();
    for (key, description) in [
        ("↑/k", "up"),
        ("↓/j", "down"),
        ("Pg↑/↓", "page"),
        ("Home/End", "first/last"),
        ("h/esc", "close"),
        ("q", "quit"),
    ] {
        if !spans.is_empty() {
            spans.push(Span::raw(" "));
        }
        spans.push(command_hint(key, description, Style::new().fg(HELP)));
    }
    Line::from(spans)
}

fn help_line(m: &Model) -> Line<'static> {
    legend_line(m, false)
}
fn worker_commands_line(m: &Model) -> Line<'static> {
    legend_line(m, true)
}

/// Whether a normal-mode shortcut can act on the current panel/selection.
fn ui_command_available(m: &Model, key: &str) -> bool {
    let table = m.focus != PanelFocus::Notifications;
    let (cursor, count) = if m.focus.is_alloc() {
        (m.alloc_cursor, m.sorted_allocations().len())
    } else if m.focus == PanelFocus::Available {
        (m.avail_cursor, m.sorted_available().len())
    } else {
        (
            m.notice_offset,
            m.notice_lines.saturating_sub(m.notice_visible) + 1,
        )
    };
    match key {
        "↑/k" => cursor > 0,
        "↓/j" => cursor + 1 < count,
        "←/→" => {
            table
                && (m.horizontal_limits[m.focus.index()] > 0
                    || m.horizontal_offsets[m.focus.index()] > 0)
        }
        "b" | "s" | "f" => table,
        "space" => table && count > 0,
        "a" => {
            table
                && (count > 0
                    || if m.focus.is_alloc() {
                        !m.alloc_selected.is_empty()
                    } else {
                        !m.avail_selected.is_empty()
                    })
        }
        // Every panel has an adjustable shared edge. Limits constrain movement,
        // not availability; don't change the legend after its first layout.
        "[/] {/}" => true,
        _ => true,
    }
}

fn legend_line(m: &Model, workers: bool) -> Line<'static> {
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
        } else if m.focus == PanelFocus::Available && !m.manual_free_workers().is_empty() {
            applicable.insert("Join".to_string());
        }
    }
    let filters_active = m.has_active_filters();

    let actions_label = if m.compact_actions {
        "expand"
    } else {
        "compact"
    };
    let refresh_label = format!("refresh {}s", m.refresh_seconds);
    let colors_label = if m.color_coding {
        "colors on"
    } else {
        "colors off"
    };
    let units_label = format!("thresholds {}", m.threshold_unit.label());
    // (key, desc, action-tag)
    let entries: [(&str, &str, &str); 24] = [
        ("tab", "switch", ""),
        ("↑/k", "up", ""),
        ("↓/j", "down", ""),
        ("←/→", "pan", ""),
        ("b", "visibility", ""),
        ("n", actions_label, ""),
        ("space", "toggle", ""),
        ("a", "all/none", ""),
        ("Ctrl+G", "join", "Join"),
        ("Ctrl+L", "leave", "Leave"),
        ("Ctrl+Y", "confirm", "Confirm"),
        ("Ctrl+R", "reject", "Reject"),
        ("Ctrl+P", "pause", "Pause"),
        ("Ctrl+U", "resume", "Resume"),
        ("Ctrl+O", "mode", "ToggleManual"),
        ("s", "sort", ""),
        (
            "f",
            if filters_active { "filter*" } else { "filter" },
            "Filter",
        ),
        ("c", colors_label, "ColorCoding"),
        ("e", units_label.as_str(), "ThresholdUnit"),
        ("v", "notice level", ""),
        ("t", refresh_label.as_str(), ""),
        ("[/] {/}", "upper/lower edge", ""),
        ("h", "help", ""),
        ("q", "quit", ""),
    ];
    let mut spans = Vec::new();
    for (key, desc, tag) in &entries {
        if key.starts_with("Ctrl+") != workers {
            continue;
        }
        let usable = if workers {
            applicable.contains(*tag)
        } else {
            ui_command_available(m, key)
        };
        if m.compact_actions && !usable {
            continue;
        }
        if spans.is_empty() {
            spans.push(Span::styled(
                if workers { "Workers (Ctrl+):" } else { "UI:" },
                Style::new().fg(HELP).add_modifier(Modifier::BOLD),
            ));
        }
        spans.push(Span::raw(" "));
        let style = Style::new().fg(if usable { PRIMARY } else { DIM });
        let style = if usable {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        };
        spans.push(command_hint(
            key.strip_prefix("Ctrl+").unwrap_or(key),
            desc,
            style,
        ));
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
            "‹←/→› column  ‹space› toggle  ‹a› all/none  ‹enter› apply  ‹esc› cancel",
            Style::new().fg(HELP),
        ));
        return (Line::from(spans), status);
    }

    let actions = Line::from(Span::styled(
        format!("Filter [{col_name}]: {}_", m.filter_edit_input),
        Style::new().fg(FILTER).add_modifier(Modifier::BOLD),
    ));
    let hint = if kind == FilterColKind::Numeric {
        "Numeric: >N  >=N  <N  <=N  =N  or  N1,N2,...    ‹enter› apply  ‹esc› cancel"
    } else {
        "‹enter› apply  ‹esc› cancel"
    };
    (
        actions,
        Line::from(Span::styled(hint, Style::new().fg(HELP))),
    )
}

// ── Help screen ──────────────────────────────────────────────────────────

fn render_help_screen(f: &mut Frame, m: &mut Model, area: Rect) {
    let body = help_lines(area.width, m.color_coding);
    m.help_lines = body.len();
    let mut commands = wrap_actions(help_commands(), area.width);
    let footer_height = commands
        .len()
        .min(usize::from(area.height.saturating_sub(3).max(1)));
    if commands.len() > footer_height {
        commands.truncate(footer_height);
        commands[footer_height - 1] = Line::from("‹h/esc› close  ‹q› quit");
    }
    let body_height = usize::from(area.height).saturating_sub(2 + footer_height);
    m.help_visible = body_height;
    let max_offset = body.len().saturating_sub(body_height);
    m.help_offset = m.help_offset.min(max_offset);
    let title = format!(
        " Shard Manager — Help  ({}–{} of {})",
        m.help_offset + 1,
        (m.help_offset + body_height).min(body.len()),
        body.len()
    );
    f.render_widget(
        Paragraph::new(Line::from(title)).style(
            Style::new()
                .fg(TEXT)
                .bg(HEADER_BG)
                .add_modifier(Modifier::BOLD),
        ),
        Rect::new(area.x, area.y, area.width, area.height.min(1)),
    );
    f.render_widget(
        Paragraph::new(
            body.into_iter()
                .skip(m.help_offset)
                .take(body_height)
                .collect::<Vec<_>>(),
        ),
        Rect::new(
            area.x,
            area.y + area.height.min(1),
            area.width,
            body_height as u16,
        ),
    );
    let separator_y = area.y + area.height.saturating_sub(footer_height as u16 + 1);
    f.render_widget(
        Paragraph::new("─".repeat(usize::from(area.width))).style(Style::new().fg(HELP)),
        Rect::new(area.x, separator_y, area.width, 1),
    );
    f.render_widget(
        Paragraph::new(commands).style(Style::new().fg(HELP)),
        Rect::new(
            area.x,
            area.y + area.height.saturating_sub(footer_height as u16),
            area.width,
            footer_height as u16,
        ),
    );
}

/// One help entry; `help_lines` lays it out for a terminal width.
#[derive(Clone, Copy)]
enum HelpItem {
    Blank,
    Section(&'static str),
    Entry(&'static str, &'static str),
    /// One value of the entry above it, as a bulleted line in its text column.
    Item(&'static str),
    Note(&'static str),
}

const HELP_KEY_WIDTH: usize = 16;
/// Two spaces, the key column and one space.
const HELP_TEXT_COLUMN: usize = HELP_KEY_WIDTH + 3;
/// Narrowest text column kept beside the keys; below it, text goes under
/// its key so that long slash-joined words still fit whole.
const HELP_TEXT_MIN: usize = 30;
const HELP_BULLET: &str = "• ";

impl HelpItem {
    fn section_style() -> Style {
        Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD)
    }
    fn key_style() -> Style {
        Style::new().fg(TEXT).add_modifier(Modifier::BOLD)
    }

    /// Help text as spans. `backticked` values the TUI prints take the key
    /// style, so they stand out from the description, and the color the
    /// main view gives them under `entry` while colors are on; the
    /// backticks never reach the screen. `‹keys›` keep their brackets, as
    /// in the command legends, and take the key style.
    fn spans(text: &str, style: Style, entry: &str, colors: bool) -> Vec<Span<'static>> {
        let mut spans = Vec::new();
        for (i, part) in text
            .split('`')
            .enumerate()
            .filter(|(_, part)| !part.is_empty())
        {
            if i % 2 == 1 {
                spans.push(Span::styled(
                    part.to_string(),
                    Self::value_style(entry, part, colors),
                ));
                continue;
            }
            let mut rest = part;
            while let Some(open) = rest.find('‹') {
                let Some(close) = rest[open..].find('›').map(|c| open + c + '›'.len_utf8())
                else {
                    break;
                };
                if open > 0 {
                    spans.push(Span::styled(rest[..open].to_string(), style));
                }
                spans.push(Span::styled(
                    rest[open..close].to_string(),
                    Self::key_style(),
                ));
                rest = &rest[close..];
            }
            if !rest.is_empty() {
                spans.push(Span::styled(rest.to_string(), style));
            }
        }
        spans
    }

    fn value_style(entry: &str, value: &str, colors: bool) -> Style {
        match help_value_color(entry, value).filter(|_| colors) {
            Some(color) => Self::key_style().fg(color),
            None => Self::key_style(),
        }
    }

    /// The key column: keys and names in the key style, a value in its color.
    fn key_spans(k: &str, entry: &str, colors: bool) -> Vec<Span<'static>> {
        Self::spans(k, Self::key_style(), entry, colors)
    }

    /// The entry on one line, however wide.
    #[cfg(test)]
    fn line(self, entry: &str, colors: bool) -> Line<'static> {
        let pad = |spans: Vec<Span<'static>>| {
            let used: usize = spans.iter().map(|s| printed_width(&s.content)).sum();
            [
                vec![Span::raw("  ")],
                spans,
                vec![Span::raw(
                    " ".repeat(HELP_KEY_WIDTH.saturating_sub(used) + 1),
                )],
            ]
            .concat()
        };
        match self {
            HelpItem::Blank => Line::from(""),
            HelpItem::Section(s) => {
                Line::from(Self::spans(s, Self::section_style(), entry, colors))
            }
            HelpItem::Entry(k, v) => Line::from(
                [
                    pad(Self::key_spans(k, entry, colors)),
                    Self::spans(v, Style::new().fg(HELP), entry, colors),
                ]
                .concat(),
            ),
            HelpItem::Item(v) => Line::from(
                [
                    pad(vec![]),
                    vec![Span::styled(HELP_BULLET, Style::new().fg(HELP))],
                    Self::spans(v, Style::new().fg(HELP), entry, colors),
                ]
                .concat(),
            ),
            HelpItem::Note(s) => Line::from(
                [
                    vec![Span::raw("  ")],
                    Self::spans(s, Style::new().fg(FILTER), entry, colors),
                ]
                .concat(),
            ),
        }
    }

    /// The entry wrapped to `width`. Text continues under its own column; a
    /// key wider than the key column, or a terminal too narrow for both
    /// columns, puts the text on the lines below the key. An item hangs
    /// under its bullet.
    fn wrapped(self, width: usize, entry: &str, colors: bool) -> Vec<Line<'static>> {
        let indented =
            |spans: Vec<Span<'static>>, first: usize, rest: usize| -> Vec<Line<'static>> {
                help_wrap(spans, width.saturating_sub(rest))
                    .into_iter()
                    .enumerate()
                    .map(|(i, mut line)| {
                        line.spans
                            .insert(0, Span::raw(" ".repeat(if i == 0 { first } else { rest })));
                        line
                    })
                    .collect()
            };
        let two_columns = width >= HELP_TEXT_COLUMN + HELP_TEXT_MIN;
        let column = if two_columns { HELP_TEXT_COLUMN } else { 4 };
        let text = |v: &str| Self::spans(v, Style::new().fg(HELP), entry, colors);
        match self {
            HelpItem::Blank => vec![Line::from("")],
            HelpItem::Section(s) => {
                indented(Self::spans(s, Self::section_style(), entry, colors), 0, 0)
            }
            HelpItem::Note(s) => {
                indented(Self::spans(s, Style::new().fg(FILTER), entry, colors), 2, 2)
            }
            HelpItem::Item(v) => {
                let bullet = printed_width(HELP_BULLET);
                let mut lines = indented(text(v), column + bullet, column + bullet);
                if let Some(first) = lines.first_mut() {
                    first.spans[0] = Span::raw(" ".repeat(column));
                    first
                        .spans
                        .insert(1, Span::styled(HELP_BULLET, Style::new().fg(HELP)));
                }
                lines
            }
            HelpItem::Entry(k, v) => {
                if k.is_empty() {
                    return indented(text(v), column, column);
                }
                let key = Self::key_spans(k, entry, colors);
                if !two_columns || printed_width(k) > HELP_KEY_WIDTH {
                    let mut lines = indented(key, 2, 2);
                    lines.extend(indented(text(v), column, column));
                    return lines;
                }
                let mut lines = indented(text(v), HELP_TEXT_COLUMN, HELP_TEXT_COLUMN);
                let used: usize = key.iter().map(|s| printed_width(&s.content)).sum();
                let mut head = vec![Span::raw("  ")];
                head.extend(key);
                head.push(Span::raw(" ".repeat(HELP_KEY_WIDTH - used + 1)));
                match lines.first_mut() {
                    Some(first) => drop(first.spans.splice(0..1, head)),
                    None => lines.push(Line::from(head)),
                }
                lines
            }
        }
    }
}

/// Lay out `spans` as words no wider than `room`. Words break on whitespace
/// only, so a highlighted value and the punctuation after it stay together;
/// a word wider than `room` breaks at the edge.
fn help_wrap(spans: Vec<Span<'static>>, room: usize) -> Vec<Line<'static>> {
    let room = room.max(1);
    let mut words: Vec<Vec<Span<'static>>> = Vec::new();
    let mut word = Vec::new();
    for span in spans {
        let mut part = String::new();
        for ch in span.content.chars() {
            if ch.is_whitespace() {
                if !part.is_empty() {
                    word.push(Span::styled(std::mem::take(&mut part), span.style));
                }
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            } else {
                part.push(ch);
            }
        }
        if !part.is_empty() {
            word.push(Span::styled(part, span.style));
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    let mut lines = Vec::new();
    let mut line: Vec<Span<'static>> = Vec::new();
    let mut used = 0;
    for word in words {
        let len: usize = word.iter().map(|span| printed_width(&span.content)).sum();
        if used > 0 && used + 1 + len > room {
            lines.push(Line::from(std::mem::take(&mut line)));
            used = 0;
        }
        if len > room {
            for piece in word {
                for ch in piece.content.chars() {
                    if used == room {
                        lines.push(Line::from(std::mem::take(&mut line)));
                        used = 0;
                    }
                    line.push(Span::styled(ch.to_string(), piece.style));
                    used += 1;
                }
            }
            continue;
        }
        if used > 0 {
            line.push(Span::raw(" "));
            used += 1;
        }
        used += len;
        line.extend(word);
    }
    if !line.is_empty() {
        lines.push(Line::from(line));
    }
    lines
}

/// Every help entry on one line each, as a test reads them.
#[cfg(test)]
fn help_body() -> Vec<Line<'static>> {
    help_entries()
        .into_iter()
        .map(|(item, entry)| item.line(entry, true))
        .collect()
}

/// One frame of the TUI drawn at `width` × `height`, as plain text with
/// trailing spaces trimmed: what `manage --render` prints.
pub(super) fn render_text(m: &mut Model, width: u16, height: u16) -> String {
    use ratatui::{backend::TestBackend, Terminal};
    let mut terminal =
        Terminal::new(TestBackend::new(width, height)).expect("an in-memory terminal");
    terminal.draw(|f| draw(f, m)).expect("drawing into memory");
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .trim_end()
                .to_string()
                + "\n"
        })
        .collect()
}

/// The help screen at `width`, as plain text without colors.
pub(super) fn help_text(width: u16) -> String {
    help_lines(width, false)
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
                .trim_end()
                .to_string()
                + "\n"
        })
        .collect()
}

/// The help laid out for a terminal `width` columns wide; `colors` follows
/// the main view's color-coding toggle.
fn help_lines(width: u16, colors: bool) -> Vec<Line<'static>> {
    help_entries()
        .into_iter()
        .flat_map(|(item, entry)| item.wrapped(usize::from(width), entry, colors))
        .collect()
}

/// Each item with the entry it describes: a continuation without a key
/// belongs to the entry above it, and a section starts afresh. Header KPI
/// sections describe no colored values.
fn help_entries() -> Vec<(HelpItem, &'static str)> {
    let (mut section, mut entry) = ("", "");
    help_items()
        .into_iter()
        .map(|item| {
            match item {
                HelpItem::Entry(k, _) if !k.is_empty() => entry = k,
                HelpItem::Section(s) => {
                    section = s;
                    entry = "";
                }
                // A note speaks for its section, not for the entry above it.
                HelpItem::Note(_) => return (item, ""),
                _ => {}
            }
            // Header KPIs print their fields uncolored, so the help does too.
            (item, if section.ends_with("KPIs") { "" } else { entry })
        })
        .collect()
}

/// The main-view color of a value the help quotes under `entry`, so the
/// help reads like the table; `None` keeps the plain key style. Header
/// KPI labels are uncolored in the main view and stay so here.
fn help_value_color(entry: &str, value: &str) -> Option<Color> {
    match (entry, value) {
        (_, "green") => Some(SUCCESS),
        (_, "blue") => Some(PRIMARY),
        (_, "purple") => Some(ring_color(4)),
        (_, "yellow") => Some(WARNING),
        (_, "red") => Some(ERROR),
        ("Status" | "bound" | "idle", status)
            if STATUS_KPI_LABELS.iter().any(|(row, ..)| *row == status) =>
        {
            Some(status_color(status))
        }
        ("Execution", label) => EXECUTION_STATES
            .iter()
            .find(|state| execution_label(state) == label)
            .map(|state| execution_color(state)),
        ("PeerState", state @ ("current" | "lag" | "unmat" | "unknown")) => {
            Some(materialization_state_color(state))
        }
        ("Worker", "-1") => worker_color(-1),
        ("Mode", mode @ ("a" | "m")) => Some(mode_color(mode)),
        _ => None,
    }
}

/// Everything under the pinned title, in one place so a test can read it.
/// A column or a key that never appears here is undocumented, and the help
/// is the only surface that says what `Lag` or `re-confirm!` mean. Each
/// KPI and column is named once, in the area of the screen that prints it,
/// with the values it prints listed beneath it.
fn help_items() -> Vec<HelpItem> {
    let sec = HelpItem::Section;
    let kv = HelpItem::Entry;
    let item = HelpItem::Item;
    let note = HelpItem::Note;

    vec![
        HelpItem::Blank,
        sec("Top header KPIs"),
        kv("Peer ID", "This node's identity; compact `Peer: …` shows the last 8 characters, ‹n› expands it"),
        kv("Strategy", "Allocation scoring strategy the node reports; expanded mode spells out the priorities:"),
        item("`H → $`: halt-risk shards first, then reward"),
        item("`H → D`: halt-risk shards first, then data"),
        item("`?`: not reported by this node"),
        kv("Seniority", "Committed prover seniority; committee rings rank members by it (see Ring)"),
        kv("Global", "The received GLOBAL head, its epoch and the next epoch boundary; ‹b› → Top header selects the fields. `-` until a frame is received. Compact / expanded labels:"),
        item("`f<frame>` / `frame`: the received GLOBAL head"),
        item("`e<epoch>` / `epoch`: the epoch that frame falls in"),
        item("`next Nf` / `next boundary`: frames to the next epoch boundary, where activations, departures, renewals and the epoch reconfirm take effect. `~` estimates the time from the measured GLOBAL interval (`60m`, else `24h`); expanded mode adds the `~HH:MM UTC` it falls at. No measurement, no time"),
        kv("Global interval", "Mean seconds per received GLOBAL frame in the selected `60m`/`24h` windows (compact label `Global [s …]`); see Frame intervals"),
        kv("World size", "Node-reported total world state in GB from the shard-info snapshot, not this table subtotal or local disk use; compact label `World`, `-` unreported. Toggle under ‹b› → Top header"),
        kv("RPC", "Local status responses; they do not establish peer or shard health:"),
        item("`✓` (expanded: `connected`): fresh responses"),
        item("`retrying`: refreshes are failing; `RPC retrying | status age | failed retries` stays visible even with the RPC KPI hidden"),
        item("`stale`: no status for 2 polling intervals + 30s; cached data cannot establish a stall"),
        item("`unknown`: no response yet"),
        sec("Panel header KPIs"),
        kv("KPI separators", "Middle dot `·` separates KPIs; pipe `|` separates the lowercase fields within a KPI"),
        kv("Workers", "This node's workers:"),
        item("`run` (expanded: `running`): reported workers; `of N` (expanded: `of N configured`): the configured worker count, which caps the allocations the node holds"),
        item("`drain` (expanded: `draining`): workers above the configured count, shown when any. They take no new seat; their seats leave through the surplus leave, lowest reward first, and each stops once it holds none. A seat on a shard at the halt-risk count stays until the shard gains provers (expected wait)"),
        item("`assigned`: workers marked allocated; a binding may outlive its live allocation"),
        item("`auto` / `manual`: workers in each management mode, idle ones included; compact shows only a nonzero `manual`"),
        kv("Status", "Allocations rows by effective protocol status, including unassigned, bound and idle rows; ignores filters. Compact shows nonzero counts only. Compact / expanded labels:"),
        item("`active`, `paused`, `rejected`, `kicked`: rows with that status; `active` does not prove execution progress"),
        item("`join` / `joining`, `leave` / `leaving`: pending joins and leaves"),
        item("`activ` / `activating`, `depart` / `departing`: confirmed joins and leaves until the next epoch boundary"),
        item("`join expired` / `expired joining`, `leave expired` / `expired leaving`: confirm window missed (`expiredJoin`, `expiredLeave`)"),
        item("`reconfirm`: stale but recoverable epoch (`re-confirm!`)"),
        item("`bound`, `idle`: worker rows (see the Status column)"),
        item("`unknown`: a raw allocation status this client cannot classify"),
        kv("Claimable", "Authenticated claimable QUIL at the cited frame; compact label `[Q]`"),
        kv("Reward", "Forecast QUIL/day of the displayed staffed rows in the selected `60m`/`24h`/`T` order; compact label `[~Q/d …]`, which omits zero fields. Estimates, not measured earnings; unassigned rows are excluded:"),
        item("`now`: active + leaving estimates; compact names it only beside other fields"),
        item("`paused`: paused estimates, available upon resume"),
        item("`delta` (compact `Δ`): joining minus leaving; activation epochs may differ"),
        item("`-`: unavailable; `+` after a value: known subtotal with unknown rows"),
        kv("Snapshot", "GLOBAL frame the panel's GlobalHead values cite, in expanded headers; compact mode cites it in the GlobalHead column header (see Global citation)"),
        kv("Shown", "Allocations rows that pass the active column filters / all rows; shown only while filters hide rows"),
        kv("Selected", "Rows marked for a batch action in that panel (‹space›, or ‹a› for all)"),
        kv("Count", "Available Shards rows that pass the active column filters"),
        kv("Level", "Notifications shown at or above this severity; ‹v› cycles it"),
        kv("Line", "Notifications scroll position, shown when lines exceed the panel"),
        sec("Columns"),
        kv("Select", "`[x]` marks the row for a batch action (‹space›, or ‹a› for all)"),
        kv("Filter", "Shard filter, in hex; shortened from the middle when narrow"),
        kv("Provers", "Live allocations: active, joining, paused and leaving; not peer availability. ProverPhases splits them by phase"),
        kv("ProverPhases", "The shard's provers by lifecycle phase, as this node reports them at its frame; counts are provers of this shard, not of this node. Hidden by default: ‹b› → Columns, select it, ‹space›. Zero counts are omitted except active, so an empty shard shows `a0`; compact symbol / expanded name:"),
        item("`a` / `active`: active provers"),
        item("`j` / `joining`: joins not yet confirmed"),
        item("`+` / `activating`: join confirmed; it joins its committee at the next epoch boundary"),
        item("`l` / `leaving`: leaves not yet confirmed"),
        item("`-` before a count / `departing`: leave confirmed; it keeps serving until the next epoch boundary"),
        item("`p` / `paused`: paused provers"),
        item("`-` alone: unavailable from this node (older server or no shard info)"),
        item("`yellow` (or `!` with colors off): halt risk by count; the shard holds data and at most 3 of its provers are active or activating, so losing one risks its quorum"),
        kv("Ring", "Committed rank; `~` marks a join forecast with one ring of competing admissions"),
        kv("Size [GB]", "Shard size in decimal gigabytes, one decimal; `<0.1` preserves small nonzero sizes"),
        kv("Shards", "Data shards the filter covers"),
        kv("LocalMat", "Local materialized height:"),
        item("`-`: unknown"),
        item("`0!`: no materialized frames, with colors off; colors show a `yellow` `0`"),
        item("`yellow` (or `!` with colors off): unchanged for 60s; see Local app notice"),
        kv("PeerMat", "Peer-reported materialized height; compared with PeerHead"),
        kv("PeerHead", "Peer-reported shard head; remote metadata, not the local cursor. `yellow` (or `!` with colors off) marks unchanged fresh reports for max(60s, 3 polls)"),
        kv("GlobalHead", "Committed app head@generation, independent of LocalMat and peer metadata; absent on older servers:"),
        item("`-`: unavailable"),
        item("`0@gN`: a known genesis head"),
        item("`yellow` (or `!` with colors off): unchanged or trailing; see Global app notice"),
        kv("Execution", "Local phase of the allocation's worker, not proof of frame progress or quorum; local progress notices exclude sync, close, handoff and activation waits:"),
        item("`start`: host starting"),
        item("`sync`: staging shard data"),
        item("`serve`: ready host"),
        item("`close`: awaiting closing certificate"),
        item("`handoff`: sealed, awaiting successor"),
        item("`wait`: awaiting allocation activation"),
        item("`blocked`: preparation/admission failure"),
        item("`stopped`: engine exited"),
        item("`running`: an older node reports host startup only"),
        item("`stale` / `cached`: old observation (see Freshness)"),
        item("`-`: joining without observations"),
        item("`unknown`: phase unavailable"),
        kv("PeerState", "Peer-reported materialization relative to its head; no local worker phase or peer lifecycle inference. `!` marks a warning with colors off:"),
        item("`current`: materialized to its head"),
        item("`lag`: behind its head"),
        item("`unmat`: nothing materialized"),
        item("`unknown`: no head"),
        kv("Reward [~Q/d]", "Forecast QUIL/day to one decimal, in selected `60m`/`24h`/`T` order (`T` = theoretical 10s/frame; expanded: `theory`). `~` before `Q/d` marks estimates; `<0.1` is a trickle; current per-frame pricing/ring applied to observed cadence, not historical credited income"),
        kv("Worker", "Core the allocation is bound to; `-1` means none is bound"),
        kv("Status", "Effective protocol status of the row:"),
        item("`joining`, `active`, `paused`, `leaving`, `rejected`, `kicked`: protocol status"),
        item("`activating`: join confirmed; it joins its committee at the next epoch boundary"),
        item("`departing`: leave confirmed; it keeps serving until the next epoch boundary"),
        item("`expiredJoin` / `expiredLeave`: confirm window missed"),
        item("`re-confirm!`: the allocation's epoch is stale but recoverable"),
        item("`bound`: a worker bound to a filter with no live allocation row, usually because a closing session it still belongs to keeps it until that session seals or GLOBAL fences it; it is then released for a waiting allocation. Shown with its local execution, excluded from rewards"),
        item("`idle`: a worker with no filter; every reported worker remains visible alongside unassigned allocations"),
        item("`unknown`: a raw allocation status this client cannot classify"),
        item("`joining(…)` / `activating(…)` / `leaving(…)` / `departing(…)`: the recorded local reason, a symbol in compact mode and a name in expanded: `$` reward, `H` halt risk, `S` split, `G` merge, `T` retired, `E` empty, `C` capacity, `O` orphan, `M` manual, `D` data, `?` unavailable history. `W` worker shortage is not history: the node infers it from its current seat and worker counts (more seats than configured workers) for a leave it holds no local record of, e.g. after a store reset; other current counts never establish history"),
        kv("Mode", "Worker management; ‹Ctrl+O› toggles:"),
        item("`a`: automatic"),
        item("`m`: manual"),
        kv("NextAction", "What you can do now, and the threshold it applies from"),
        kv("DefaultAction", "What the network does if you do nothing, and when"),
        kv("Interval [s]", "Node-observed mean seconds per committed app frame. ‹b› exposes `60m`/`24h` sub-items under Interval [s] in Columns and Global interval in Top header; these selections are independent. Sort/filter uses the first visible interval. Coverage needs 60s; gaps/downtime excluded; includes pauses/catch-up. `-` unavailable or no advances"),
        note("Thresholds read `in Nf` (frames from the received GLOBAL frame; `now` once reached) or `@f<frame>`; ‹e› switches. Expanded relative thresholds add a `~` time estimate from the measured GLOBAL interval; `~` marks estimates. Q/d is whole QUIL per day, GB is decimal gigabytes. Available Shards shows the same columns, minus the ones that only exist once a shard is allocated to you."),
        sec("Footers and notifications"),
        kv("Details", "Selected allocation footer shows reason/blocker, last advance as `<60s` / `>60s`, and Local app frames warnings; no ticking timers. PeerHead is peer-reported metadata"),
        kv("Recovery footer", "Compact shows phase and fixed age buckets; expand for archive, attempt, leaf and outcome details. `unobserved` means no timestamp; `<60s` / `>60s` are fixed age buckets. Detail wraps within the panel; enlarge it for omitted lines"),
        kv("Freshness", "Age of the worker state shown; poll delays do not age the received state, and startup restoration is not an advance:"),
        item("`stale`: node observation already >30s old at receipt"),
        item("`cached`: no worker result for >2 polls +30s; not proof of ongoing execution"),
        kv("Local app notice", "`Local app frames unchanged >60s`: staffed earning allocations whose LocalMat has not advanced for 60s, of those with fresh observations; sync, close, handoff and activation waits are excluded. Their LocalMat cells are `yellow`, or marked `!` with colors off"),
        kv("Reported app heads", "No peer-reported app frames advanced on the stated subset of tracked shards. Counts include allocated and unallocated shards. Affected PeerHead / PeerState cells are `yellow`, or marked `!` with colors off. Requires 3+ fresh snapshots over max(60s, 3 polls); missing/unstaffed rows are excluded. Does not prove a network halt"),
        kv("Global notice", "After max(60s, 3 polls) without received-head advance; timestamp survives refresh changes. Clears on advance or stale RPC"),
        kv("Global app notice", "Committed GLOBAL state: each tracked shard's GlobalHead against its app head, the higher of PeerHead and LocalMat. Counts include allocated and unallocated shards with provers, a GlobalHead and an app head. Affected GlobalHead cells are `yellow`, or marked `!` with colors off:"),
        item("`Global app frames unchanged >Ns`: GlobalHead kept its frame over 3+ fresh snapshots spanning max(60s, 3 polls) while the GLOBAL snapshot and the app head both advanced"),
        item("`Global app frames >100 behind app heads`: GlobalHead trails the app head by more than 100 frames"),
        item("Either way GLOBAL has not applied the newer shard frames, so their shard state and rewards are not credited yet. On most tracked shards it is network-wide: GLOBAL frames are not carrying shard frames; report it with the GLOBAL frame and shard filters. On a few shards, check those shards' committees"),
        kv("Reward notice", "`Reward now 60m … vs 24h … Q/d`: the active + leaving forecast over the last 60m is below half its 24h value. Counts rows whose shard has 30 min of 60m and 2h of 24h coverage. Both windows apply the current per-frame reward, so the drop is in committed app frames, not in pricing; see Global app notice"),
        kv("Allocation notices", "Allocations or workers with a condition, out of those it applies to:"),
        item("`Allocations without a worker`: active, leaving, departing or `re-confirm!` allocations with Worker `-1`; they do no work and earn nothing until a worker is bound"),
        item("`Local execution blocked or stopped`: staffed earning allocations whose Execution is `blocked` or `stopped`, of those with fresh observations; the row footer names the blocker"),
        item("`Allocation epoch stale (re-confirm!)`: allocations whose epoch is older than the current one. The node reconfirms each allocation during every epoch, so its reconfirm has not been recorded; check the node's prover confirmation log lines"),
        item("`Last recovery attempt failed`: workers whose latest archive recovery attempt failed, of workers with fresh observations; the Recovery footer gives the error and the failure streak"),
        kv("Command legends", "Compact mode shows applicable UI/worker commands only; expanded mode also shows disabled commands. Usable commands share one highlight; labels show colors on/off and relative/absolute thresholds. `filter*` means a column filter is active"),
        kv("Scroll hints", "Bottom border counts hidden rows `↑`/`↓` and columns `←`/`→`"),
        kv("Colors", "What the main view's colors mean:"),
        item("`green`: current"),
        item("`blue` / `purple`: rank or normal mode"),
        item("`yellow`: delay"),
        item("`red`: blocked/error"),
        sec("Measurements and forecasts"),
        kv("Frame windows", "Node samples once/minute; `60m`/`24h` windows survive updates. Downtime/missing reads excluded; selected row shows coverage. Generation changes cannot count inherited heights as produced frames"),
        kv("Frame intervals", "GLOBAL measures received head; app measures committed GlobalHead. Node history survives updates, retains at most 24h, samples once/minute. Freshness 90s; coverage in RPC. Forecasts use current per-frame reward and observed frame rate; 10s is theoretical, none proves earned credits"),
        kv("Reward estimates", "`60m`/`24h` are observation windows; `T` (`theory` in expanded mode) assumes 10s/frame. Forecasts in heading order; ‹b› exposes shared `60m`/`24h`/`T` sub-items under the Reward column and Allocations header Reward KPI. `~` before `Q/d` marks estimates. Observed zero progress estimates zero; actual credits separate; reward sort/filter uses the first visible window"),
        kv("Global citation", "Compact Global heading / expanded Snapshot cite the GLOBAL frame behind GlobalHead cells. Compact `@-Nf` / `@+Nf` offsets refer to the top Global head; equal-frame citations are omitted. Claimable uses its authenticated balance frame. Expanded shows absolute frames"),
        sec("Display"),
        kv("‹n›", "Toggle compact / expanded display (n: names; default compact): identity, KPIs, action/reason names, threshold estimates, units and recovery/seal detail; default actions remain named"),
        kv("‹b›", "Visibility picker (b: blocks): ‹tab› moves focus between Columns, Top header and every panel header group; ‹↑/↓› selects, ‹space› toggles, ‹a› restores the focused group, ‹enter›/‹esc› closes. Interval, reward and Global field options nest beneath their KPI. Panel names and identity columns stay visible"),
        kv("Columns group", "In the picker, visibility shared by both panels; ‹Shift+↑/↓› reorders focused table columns with their sub-items, ‹r› restores order, ‹c› hides Provers/Size/Shards and ‹a› restores all columns. Select/Filter stay pinned; settings last for the TUI session"),
        kv("‹t›", "Cycle refresh (t: timer) 5/15/30/60s (default 15); startup and post-action fetches are immediate"),
        kv("‹c›", "Toggle color-coding of Ring, Mat/Lag/State, GlobalHead, ProverPhases, Worker, Status and Mode; values quoted in this help follow it"),
        kv("‹e›", "Show Next/Default Action thresholds relative to the received GLOBAL frame (`in Nf`, default) or as absolute frames (`@f…`)"),
        kv("‹h›", "Open this help (‹↑/↓› or ‹Pg↑/↓› scroll; ‹h› or ‹esc› closes)"),
        kv("‹q› / ‹Ctrl+C›", "Quit"),
        sec("Navigation"),
        kv("‹↑/k›", "Move cursor up; scrolls Notifications when it is focused"),
        kv("‹↓/j›", "Move cursor down; scrolls Notifications when it is focused"),
        kv("‹←/→›", "Scroll table horizontally by eight columns"),
        kv("‹tab›", "Cycle Allocations, Available Shards and Notifications; ‹Shift+tab› reverses"),
        kv("‹space›", "Toggle selection on cursor row (advances cursor)"),
        kv("‹a›", "Select all / deselect all rows in current table"),
        kv("Cursor", "Inactive cursor stays visible to bind the detail below to its row"),
        kv("Boundaries", "Top of Allocations and bottom of Notifications remain fixed"),
        sec("Notifications"),
        kv("‹v›", "Cycle minimum severity (v: verbosity): warnings/errors (default), errors only, all"),
        kv("‹Pg↑/↓›", "Page through Notifications; ‹Home/End› jump to its first/last line"),
        kv("‹[/]› / ‹{/}›", "Move the upper boundary up/down / the lower boundary up/down"),
        sec("Actions — Allocations panel"),
        note("Operational commands require Ctrl. Leave/Reject/Pause/Mode ask ‹enter› or ‹esc›."),
        note("‹Ctrl+C› quits; ‹Ctrl+J›/‹Ctrl+M› alias ‹enter›; ‹Ctrl+S›/‹Ctrl+Q› may be terminal flow control. Terminals also send ‹Ctrl+I› as ‹tab› and ‹Ctrl+H› as backspace, which is why some actions take a less obvious letter."),
        note("Pause/resume and mode changes are available in `AUTO`. Join/leave/confirm/reject require manual mode; Join also needs a free manual worker."),
        kv("‹Ctrl+L›", "Leave — request to leave an Active allocation (status 2)"),
        kv("‹Ctrl+Y›", "Confirm (Y: yes) — confirm a pending Join/Leave once the window opens"),
        kv("‹Ctrl+R›", "Reject — reject a pending Join/Leave"),
        kv("‹Ctrl+P›", "Pause — pause an Active allocation (status 2)"),
        kv("‹Ctrl+U›", "Resume (U: unpause) — resume a Paused allocation (status 3)"),
        kv("‹Ctrl+O›", "Mode (O: own) — toggle manual / auto worker management on cursor row"),
        note("Multi-select with ‹space› or ‹a› to batch Leave/Confirm/Reject/Pause/Resume."),
        HelpItem::Blank,
        sec("Actions — Available Shards panel"),
        kv("‹Ctrl+G›", "Join (G: go) — open worker picker for selected shard(s)"),
        note("At least one free (unassigned) worker must exist to join."),
        HelpItem::Blank,
        sec("Worker picker  (opens on ‹Ctrl+G›)"),
        kv("‹↑/k› / ‹↓/j›", "Move cursor between free workers"),
        kv("‹space›", "Toggle a worker into the manual-management set"),
        kv("‹enter›", "Join the shard(s); selected workers are set to Manual"),
        kv("‹esc›", "Cancel the join"),
        HelpItem::Blank,
        sec("Sort mode  (press ‹s›)"),
        kv("‹s›", "Enter sort mode"),
        kv("‹←/→›", "Move highlight to previous / next column"),
        kv("‹enter›", "Confirm column, then choose sort order"),
        kv("‹a›", "Ascending order"),
        kv("‹d›", "Descending order"),
        kv("‹esc›", "Cancel sort mode"),
        note("The sorted column's header is underlined, with `↑` or `↓` for the order."),
        HelpItem::Blank,
        sec("Filter mode  (press ‹f›)"),
        kv("‹f›", "Enter filter mode"),
        kv("‹←/→›", "Move highlight to previous / next filterable column"),
        kv("‹enter›", "Open filter editor for highlighted column"),
        kv("‹del› / ‹backspace›", "Clear filter on highlighted column"),
        kv("‹x›", "Disable all filters in current panel (x: clear)"),
        kv("‹esc›", "Close filter mode"),
        note("An active filter marks its column header with `*`."),
        HelpItem::Blank,
        sec("Filter editor  (‹enter›, from filter mode)"),
        kv("Typing", "Text columns take a substring; numeric columns take an expression like `> 47`, `< 100`, or a comma list `1,5,7`"),
        kv("‹backspace›", "Delete the last character (‹Ctrl+H› does the same)"),
        kv("‹←/→›", "Select columns: move between the available values"),
        kv("‹space›", "Select columns: toggle the value under the cursor"),
        kv("‹a›", "Select columns: select all / deselect all values"),
        kv("‹enter›", "Apply the filter"),
        kv("‹esc›", "Cancel without changing the filter"),
        HelpItem::Blank,
    ]
}

/// All settings groups stay on screen; Tab moves focus rather than replacing content.
fn render_column_picker(f: &mut Frame, m: &mut Model, area: Rect) {
    let commands = wrap_actions(
        Line::from(if area.width < 70 {
            "Tab group  ↑↓ item  Shift+↑↓ move  r reset order  Space toggle  a show all  Enter/Esc close"
        } else {
            "‹Tab/Shift+Tab› group  ‹↑/↓› item  ‹Space› toggle  ‹Shift+↑/↓› move column  ‹r› reset order  ‹c› compact columns  ‹a› show all  ‹Enter/Esc› close"
        }),
        area.width,
    );
    let footer_height = commands
        .len()
        .min(usize::from(area.height.saturating_sub(1))) as u16;
    let body = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1 + footer_height),
    );
    let left_width = body.width / 2;
    let columns = Rect::new(body.x, body.y, left_width, body.height);
    let right = Rect::new(
        body.x + left_width,
        body.y,
        body.width - left_width,
        body.height,
    );
    let mut heights = [
        m.visibility_names_for(1).len() as u16 + 1,
        m.visibility_names_for(2).len() as u16 + 1,
        m.visibility_names_for(3).len() as u16 + 1,
        m.visibility_names_for(4).len() as u16 + 1,
    ];
    // Reserve every group heading and at least one item in small terminals.
    while heights.iter().sum::<u16>() > right.height {
        let Some(index) = (0..4)
            .filter(|&i| heights[i] > if m.visibility_section == i + 1 { 2 } else { 1 })
            .max_by_key(|&i| heights[i])
        else {
            break;
        };
        heights[index] -= 1;
    }
    f.render_widget(
        Paragraph::new("Visibility — Tab moves focus").style(Style::new().fg(TEXT).bg(HEADER_BG)),
        Rect::new(area.x, area.y, area.width, 1),
    );
    render_visibility_group(f, m, 0, "Columns", columns);
    let mut y = right.y;
    for (i, title) in [
        "Top header",
        "Allocations header",
        "Available header",
        "Notifications header",
    ]
    .iter()
    .enumerate()
    {
        render_visibility_group(
            f,
            m,
            i + 1,
            title,
            Rect::new(right.x, y, right.width, heights[i]),
        );
        y += heights[i];
    }
    f.render_widget(
        Paragraph::new(commands).style(Style::new().fg(HELP)),
        Rect::new(
            area.x,
            area.y + area.height - footer_height,
            area.width,
            footer_height,
        ),
    );
}

fn render_visibility_group(f: &mut Frame, m: &mut Model, section: usize, title: &str, area: Rect) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    let names = m.visibility_names_for(section);
    let active = m.visibility_section == section;
    let visible = usize::from(area.height.saturating_sub(1));
    let offset = if active {
        m.column_picker_offset = clamp_offset(
            m.column_picker_offset,
            m.column_picker_cursor,
            visible.max(1),
            names.len(),
        );
        m.column_picker_offset
    } else {
        0
    };
    let heading = format!(
        "{} {}",
        if active { "▶" } else { " " },
        center_trunc(title, usize::from(area.width.saturating_sub(2)))
    );
    let style = Style::new()
        .fg(if active { TEXT } else { PRIMARY })
        .bg(HEADER_BG)
        .add_modifier(Modifier::BOLD);
    f.render_widget(
        Paragraph::new(heading).style(style),
        Rect::new(area.x, area.y, area.width, 1),
    );
    let mut lines = Vec::new();
    for (index, name) in names.iter().enumerate().skip(offset).take(visible) {
        let selected = active && index == m.column_picker_cursor;
        let required = section == 0 && index < 2;
        let child = m.visibility_interval_window(section, index).is_some()
            || m.visibility_reward_window(section, index).is_some()
            || m.visibility_global_field(section, index).is_some();
        let indent = if child { "  " } else { "" };
        let label = format!(
            "{}{}",
            name.trim_start(),
            if required { " (required)" } else { "" }
        );
        let text = format!(
            "{} {}{} {}",
            if selected { "▶" } else { " " },
            indent,
            if m.visibility_item_visible_in(section, index) {
                "[x]"
            } else {
                "[ ]"
            },
            center_trunc(
                &label,
                usize::from(area.width.saturating_sub(6 + indent.len() as u16))
            )
        );
        lines.push(Line::from(Span::styled(
            text,
            if selected {
                Style::new().fg(TEXT).bg(CURSOR_BG)
            } else {
                Style::new().fg(HELP)
            },
        )));
    }
    f.render_widget(
        Paragraph::new(lines),
        Rect::new(
            area.x,
            area.y + 1,
            area.width,
            area.height.saturating_sub(1),
        ),
    );
}

// ── Join worker picker ───────────────────────────────────────────────────

fn render_join_picker(f: &mut Frame, m: &mut Model, area: Rect) {
    let mut lines = vec![
        Line::from(Span::styled(
            format!(
                "{:<width$}",
                " Select free manual workers",
                width = area.width as usize
            ),
            Style::new()
                .fg(TEXT)
                .bg(HEADER_BG)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "  Joining {} shard(s). Select at least one free manual worker:",
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
                Style::new().fg(TEXT).bg(HEADER_BG),
            )));
        } else {
            lines.push(Line::from(text));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  space: toggle  enter: confirm join  esc: cancel",
        Style::new().fg(HELP),
    )));
    f.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::node::prover::epoch::ActionHint;

    #[test]
    fn hidden_shared_columns_disappear_from_both_panels_and_reclaim_width() {
        let mut m = Model::new();
        let mut a = row("aabb", 123456, 5, 7, "", "");
        a.shard_size = BigInt::from(987_654_321u64) * 1024 * 1024;
        let mut peer = shard("ccdd", 123456, 5);
        peer.shard_size = a.shard_size.clone();
        for sizing in [ColumnSizing::Dynamic, ColumnSizing::Fixed] {
            m.column_sizing = sizing;
            m.hidden_columns.clear();
            let before = alloc_col_widths(&m, 180, &[a.clone()]).0;
            let shown = render_alloc_panel(&mut m, &[a.clone()], Rect::new(0, 0, 500, 5), None);
            assert!(shown[1].to_string().contains(&fmt_gb(&a.shard_size)));
            m.hidden_columns.extend([2, 4, 5]);
            let (aw, bw) = shared_col_widths(&m, 180, &[a.clone()], &[peer.clone()]);
            for col in [2, 4, 5] {
                assert_eq!(aw[col], 0);
                assert_eq!(bw[col], 0);
            }
            assert!(aw[1] >= before[1]);
            for cursor in [0, 1] {
                m.alloc_cursor = cursor;
                m.avail_cursor = cursor;
                let alloc = render_alloc_panel(
                    &mut m,
                    &[a.clone(), a.clone()],
                    Rect::new(0, 0, 500, 5),
                    Some(&aw),
                );
                let avail = render_avail_panel(
                    &mut m,
                    &[peer.clone(), peer.clone()],
                    Rect::new(0, 0, 500, 5),
                    Some(&bw),
                );
                for header in [&alloc[0], &avail[0]] {
                    let text = header.to_string();
                    assert!(
                        !text.contains("Provers")
                            && !text.contains("Size")
                            && !text.contains("Shards")
                    );
                    assert!(text.contains("Filter") && text.contains("Ring"));
                }
                for line in alloc.iter().chain(avail.iter()).skip(1) {
                    assert!(!line.to_string().contains(&fmt_gb(&a.shard_size)));
                }
            }
        }
    }

    #[test]
    fn allocation_heading_wraps_complete_kpis_and_keeps_citations() {
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        m.running_workers = 15;
        m.allocated_workers = 15;
        m.claimable_reward = Some((8_000_000_000, 123456));
        let blocks = alloc_kpis(&m, &[]);
        for width in [40, 80, 120, 300] {
            let lines = alloc_heading_lines(&m, &[], width);
            assert!(lines.iter().all(|l| l.width() <= usize::from(width)));
            for block in &blocks {
                let joined = lines
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                assert!(joined.contains(block), "missing KPI {block} at {width}");
            }
        }
        assert_eq!(alloc_heading_lines(&m, &[], 1000).len(), 1);
        assert!(alloc_heading_lines(&m, &[], 80).len() > 1);
        assert!(alloc_title(&m, &[])
            .to_string()
            .contains("Claimable [Q]: 1 @f123456"));
    }

    /// A render is the drawn frame as text: one line per row, no trailing
    /// spaces, with the same content an interactive draw shows.
    #[test]
    fn a_render_prints_the_drawn_frame_as_text() {
        let mut m = Model::new();
        m.compact_actions = false;
        m.data_loaded = true;
        m.allocations = joining_table();
        let text = render_text(&mut m, 100, 40);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 40);
        assert!(lines.iter().all(|l| !l.ends_with(' ')));
        assert!(lines.iter().any(|l| l.contains("Select Filter")), "{text}");
        assert!(!text.contains('\u{1b}'), "no escape sequences");
    }

    /// The help as text keeps every section heading and has no styling.
    #[test]
    fn help_text_lists_the_help_sections() {
        let text = super::help_text(100);
        // Wrapping folds a heading's runs of spaces into one.
        let flat = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let words = flat(&text);
        for item in help_items() {
            if let HelpItem::Section(section) = item {
                assert!(words.contains(&flat(section)), "missing section {section}");
            }
        }
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn wrapped_allocation_heading_stays_visible_when_table_pans() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        m.data_loaded = true;
        m.claimable_reward = Some((8_000_000_000, 123456));
        m.allocations = joining_table();
        let mut terminal = Terminal::new(TestBackend::new(80, 42)).unwrap();
        let render = |terminal: &mut Terminal<TestBackend>, m: &mut Model| {
            terminal.draw(|f| draw(f, m)).unwrap();
            let b = terminal.backend().buffer();
            (0..42)
                .map(|y| (0..80).map(|x| b[(x, y)].symbol()).collect::<String>())
                .collect::<Vec<_>>()
        };
        let before = render(&mut terminal, &mut m);
        let table = before
            .iter()
            .position(|l| l.contains("Select Filter"))
            .unwrap();
        assert!(before[..table]
            .iter()
            .any(|l| l.contains("Reward [~Q/d 60m/24h/theory]: now")));
        m.horizontal_offsets[0] = 30;
        let after = render(&mut terminal, &mut m);
        assert_eq!(&before[..table], &after[..table]);
        assert_ne!(before[table], after[table]);
        assert!(after[..table]
            .iter()
            .any(|l| l.contains("Claimable [Q]: 1 @f123456")));
    }

    #[test]
    fn all_header_kpis_wrap_as_complete_blocks() {
        let mut m = Model::new();
        m.data_loaded = true;
        m.peer_id = "p".repeat(52);
        m.running_workers = 15;
        let blocks = header_kpis(&m);
        for width in [40, 80, 120, 300] {
            let lines = header_lines(&m, width);
            for block in &blocks {
                assert!(
                    lines
                        .iter()
                        .any(|line| line.to_string().contains(&block.to_string())),
                    "split block at width {width}: {block}"
                );
            }
        }
    }

    #[test]
    fn header_exposes_configured_strategy_without_guessing_on_older_servers() {
        let mut m = Model::new();
        m.data_loaded = true;
        assert!(header_line(&m).to_string().contains("Strategy: ?"));
        for (strategy, expected) in [
            ("reward-greedy", "Strategy: H → $"),
            ("data-greedy", "Strategy: H → D"),
        ] {
            m.cached_shard_info = Some(quil_types::proto::node::GetShardInfoResponse {
                allocation_scoring_strategy: strategy.into(),
                ..Default::default()
            });
            let text = header_line(&m).to_string();
            assert!(text.contains(expected));
            assert!(!text.contains("greedy"));
        }
    }

    #[test]
    fn header_identifies_rpc_connection_independently_of_reported_reachability() {
        use std::time::{Duration, Instant};
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        m.data_loaded = true;
        m.reachable = false;
        m.last_fetch_success = Some(Instant::now());
        assert!(header_line(&m).to_string().contains("RPC: connected"));
        m.consecutive_failures = 1;
        m.reachable = true;
        assert!(header_line(&m).to_string().contains("RPC: retrying"));
        m.consecutive_failures = 0;
        m.last_fetch_success = Some(Instant::now() - Duration::from_secs(60));
        assert!(header_line(&m).to_string().contains("RPC: stale"));
    }

    #[test]
    fn panel_headers_separate_kpis_from_fields_with_distinct_delimiters() {
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        let title = alloc_title(&m, &[]).to_string();
        assert!(title.contains(" · Status:") && title.contains(" · Claimable"));
        assert!(title.contains(" · Reward [~Q/d 60m/24h/theory]:") && title.contains("| paused"));
        assert!(title.contains(" · Snapshot:"));
        assert!(!title.contains("  "));
        assert!(avail_title(&m, &[]).to_string().contains(" · Snapshot:"));
    }

    #[test]
    fn worker_counts_belong_to_allocations_and_not_the_top_header() {
        let mut m = Model::new();
        m.compact_actions = false;
        m.data_loaded = true;
        m.running_workers = 15;
        assert!(!header_line(&m).to_string().contains("Workers:"));
        assert!(alloc_title(&m, &[])
            .to_string()
            .contains("Workers: running 15"));
        m.data_loaded = false;
        assert_eq!(header_lines(&m, 40).len(), 1);
    }

    #[test]
    fn legends_separate_ui_from_worker_commands_and_share_one_modifier_prefix() {
        let mut m = Model::new();
        m.compact_actions = false;
        let ui = help_line(&m).to_string();
        let workers = worker_commands_line(&m).to_string();
        assert!(ui.starts_with("UI:"));
        assert!(ui.contains("‹t› refresh 15s") && ui.contains("‹[/] {/}›"));
        assert!(!ui.contains("Ctrl+"));
        assert!(workers.starts_with("Workers (Ctrl+):"));
        assert_eq!(workers.matches("Ctrl+").count(), 1);
        assert!(workers.contains("‹G› join") && workers.contains("‹O› mode"));
        assert!(!workers.contains("refresh"));
        assert!(!ui.contains("  ") && !workers.contains("  "));
    }

    #[test]
    fn auto_worker_legend_highlights_only_the_valid_pause_or_resume_and_mode() {
        let mut m = Model::new();
        m.compact_actions = false;
        let mut a = row("01", 1, 1, 1, "", "");
        a.status = 2;
        a.manually_managed = false;
        m.allocations = vec![a];
        for (status, enabled, disabled) in [
            (2, "‹P› pause", "‹U› resume"),
            (3, "‹U› resume", "‹P› pause"),
        ] {
            m.allocations[0].status = status;
            let legend = worker_commands_line(&m);
            for label in [enabled, "‹O› mode"] {
                assert!(legend
                    .spans
                    .iter()
                    .any(|s| s.content == label && s.style.fg == Some(PRIMARY)));
            }
            for label in [disabled, "‹L› leave", "‹Y› confirm", "‹R› reject"] {
                assert!(legend
                    .spans
                    .iter()
                    .any(|s| s.content == label && s.style.fg == Some(DIM)));
            }
        }
    }

    #[test]
    fn compact_legends_hide_unusable_commands_and_ui_styles_match_panel_capabilities() {
        let mut m = Model::new();
        let mut a = row("01", 1, 1, 1, "", "");
        a.status = 2;
        a.manually_managed = false;
        m.allocations = vec![a];
        assert_eq!(
            worker_commands_line(&m).to_string(),
            "Workers (Ctrl+): ‹P› pause ‹O› mode"
        );
        m.allocations[0].status = 3;
        assert_eq!(
            worker_commands_line(&m).to_string(),
            "Workers (Ctrl+): ‹U› resume ‹O› mode"
        );
        m.focus = PanelFocus::Notifications;
        assert!(worker_commands_line(&m).spans.is_empty());
        assert!(wrap_actions(worker_commands_line(&m), 80).is_empty());
        let ui = help_line(&m);
        for key in ["‹b›", "‹s›", "‹f›", "‹space›", "‹a›", "‹←/→›"] {
            assert!(!ui.to_string().contains(key));
        }
        for label in ["‹n› expand", "‹t› refresh 15s", "‹h› help", "‹q› quit"] {
            assert!(ui
                .spans
                .iter()
                .any(|s| s.content == label && s.style.fg == Some(PRIMARY)));
        }
        assert!(ui
            .spans
            .iter()
            .any(|s| s.content == "‹c› colors on" && s.style.fg == Some(PRIMARY)));
        m.compact_actions = false;
        assert!(help_line(&m)
            .spans
            .iter()
            .any(|s| s.content == "‹b› visibility" && s.style.fg == Some(DIM)));
        m.focus = PanelFocus::Allocations;
        assert!(help_line(&m)
            .spans
            .iter()
            .any(|s| s.content == "‹b› visibility" && s.style.fg == Some(PRIMARY)));
    }

    #[test]
    fn global_alarm_requires_fresh_rpc_and_survives_notice_filters_and_monochrome() {
        use std::time::{Duration, Instant};
        let mut m = Model::new();
        m.data_loaded = true;
        m.last_fetch_success = Some(Instant::now());
        for secs in [0, 29, 30, 59, 60] {
            m.global_last_advance = Some(Instant::now() - Duration::from_secs(secs));
            assert_eq!(global_alarm_active(&m), secs >= 60);
        }
        m.notice_minimum = NoticeSeverity::Error;
        m.color_coding = false;
        assert!(!header_line(&m).to_string().contains("ALARM"));
        assert!(!header_line(&m).to_string().contains("GLOBAL"));
        assert!(!header_line(&m).to_string().contains("Poll"));
        update_message_lifetime(&mut m);
        let stamp = m.global_alarm_time.unwrap();
        update_message_lifetime(&mut m);
        assert_eq!(m.global_alarm_time, Some(stamp));
        assert!(message_lines(&m, Line::default(), 300)
            .iter()
            .any(|l| l.to_string().starts_with(&format!(
                "{}Global head unchanged",
                message_timestamp(Some(stamp))
            ))));
        assert!(message_lines(&m, Line::default(), 40)
            .iter()
            .any(|l| l.to_string().contains("Global head unchanged")));
        m.consecutive_failures = 1;
        assert!(!global_alarm_active(&m));
        update_message_lifetime(&mut m);
        assert!(m.global_alarm_time.is_none());
        m.consecutive_failures = 0;
        m.last_fetch_success = Some(Instant::now() - Duration::from_secs(60));
        assert!(!global_alarm_active(&m));
        m.last_fetch_success = Some(Instant::now());
        m.observe_global_head(1, Instant::now());
        assert!(!global_alarm_active(&m));
    }

    #[test]
    fn established_global_notice_survives_refresh_changes_until_recovery() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        use std::time::{Duration, Instant};
        let mut m = Model::new();
        m.last_fetch_success = Some(Instant::now());
        m.global_observed_head = 100;
        m.global_last_advance = Some(Instant::now() - Duration::from_secs(75));
        m.notice_minimum = NoticeSeverity::Info;
        m.status_msg = "Action completed".into();
        m.shard_error = Some("Shard fetch timed out".into());
        update_message_lifetime(&mut m);
        let stamp = m.global_alarm_time.unwrap();
        for interval in [30, 60, 5, 15] {
            super::super::update::handle_key(
                &mut m,
                KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE),
            );
            assert_eq!(m.refresh_seconds, interval);
            update_message_lifetime(&mut m);
            assert_eq!(m.global_alarm_time, Some(stamp));
            let notices = message_lines(&m, status_line(&m), 300)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            assert!(notices.contains(&format!(
                "{}Global head unchanged",
                message_timestamp(Some(stamp))
            )));
            assert!(!notices.contains("ALARM:"));
            assert!(notices.contains("Global head unchanged >60s."));
            assert!(
                notices.contains("Action completed") && notices.contains("Shard fetch timed out")
            );
        }
        m.observe_global_head(100, Instant::now());
        assert_eq!(m.global_alarm_time, Some(stamp));
        m.observe_global_head(101, Instant::now());
        assert!(m.global_alarm_time.is_none() && !global_alarm_active(&m));
        m.global_alarm_time = Some(stamp);
        m.consecutive_failures = 1;
        update_message_lifetime(&mut m);
        assert!(m.global_alarm_time.is_none());
        assert!(!message_lines(&m, Line::default(), 300)
            .iter()
            .any(|l| l.to_string().contains("Global head unchanged")));
    }

    #[test]
    fn slow_polling_allows_multiple_observations_before_global_alarm() {
        use std::time::{Duration, Instant};
        let mut m = Model::new();
        m.refresh_seconds = 60;
        m.last_fetch_success = Some(Instant::now());
        m.global_last_advance = Some(Instant::now() - Duration::from_secs(60));
        assert!(!global_alarm_active(&m));

        m.global_last_advance = Some(Instant::now() - Duration::from_secs(120));
        assert!(!global_alarm_active(&m));
        m.global_last_advance = Some(Instant::now() - Duration::from_secs(180));
        assert!(global_alarm_active(&m));
        m.refresh_seconds = 5;
        m.refresh_changed_at = Some(Instant::now());
        assert!(!global_alarm_active(&m));
    }

    #[test]
    fn ordinary_ranks_modes_and_peer_delays_are_distinct_from_blocked_execution() {
        for ring in [0, 1, 2, 3, 4, 100, UNKNOWN_REWARD_RING] {
            assert_ne!(ring_color(ring), ERROR);
        }
        for status in [
            "active",
            "joining",
            "activating",
            "leaving",
            "departing",
            "paused",
            "re-confirm!",
        ] {
            assert_ne!(status_color(status), ERROR);
        }
        assert_ne!(mode_color("m"), ERROR);
        assert_ne!(mode_color("a"), ERROR);
        assert_eq!(materialization_state_color("lag"), WARNING);
        let mut a = row("a", 1, 1, 1, "", "");
        a.execution = Some(quil_types::proto::node::WorkerExecution {
            state: "blocked".into(),
            observed_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            ..Default::default()
        });
        assert_eq!(local_color(&Model::new(), &a), ERROR);
    }

    #[test]
    fn confirmation_is_visible_even_with_errors_only_notifications() {
        let mut m = Model::new();
        m.notice_minimum = NoticeSeverity::Error;
        m.operation_confirmation = Some(('p', vec![]));
        let text = message_lines(&m, Line::from("Enter confirms; Esc cancels"), 80);
        assert!(text
            .iter()
            .any(|l| l.to_string().contains("Enter confirms")));
    }

    #[test]
    fn scroll_indicators_track_hidden_rows_and_columns() {
        assert_eq!(scroll_hint(0, 3, 3, 0, 0), "");
        assert_eq!(scroll_hint(2, 10, 3, 8, 20), " ↑2 ↓5 | ←8 →12 ");
        assert_eq!(scroll_hint(7, 10, 3, 20, 20), " ↑7 ↓0 | ←20 →0 ");
        let mut m = Model::new();
        m.horizontal_offsets[0] = 20;
        assert_eq!(
            table_horizontal_offset(&mut m, 0, &[Line::from("x".repeat(50))], 30),
            20
        );
        assert_eq!(
            table_horizontal_offset(&mut m, 0, &[Line::from("x")], 30),
            0
        );
        assert_eq!(m.horizontal_limits[0], 0);
    }

    #[test]
    fn a_boundary_moves_immediately_after_terminal_resize_clips_its_offset() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut m = Model::new();
        m.panel_boundary_offsets = [100, -100];
        let before = sync_panel_heights(&mut m, 13);
        super::super::update::handle_key(
            &mut m,
            KeyEvent::new(KeyCode::Char('{'), KeyModifiers::NONE),
        );
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
        m.compact_actions = false;
        m.compact_units = false;
        let allocations = [row("aabb0123456789", 1, 1, 7, "", "")];
        let mut peer = shard("ccdd0123456789", 12345, 10000);
        peer.latest_frame = 987654321;
        let available = [peer];
        for sizing in [ColumnSizing::Dynamic, ColumnSizing::Fixed] {
            m.column_sizing = sizing;
            let (a, v) = shared_col_widths(&m, 240, &allocations, &available);
            assert_eq!(&a[..11], &v[..11]);
            assert_eq!(a[16], v[11]);
            assert!(a.iter().sum::<usize>() + a.len() - 1 <= 240);
            let alloc = render_alloc_panel(&mut m, &allocations, Rect::new(0, 0, 240, 5), Some(&a))
                [0]
            .to_string();
            let avail = render_avail_panel(&mut m, &available, Rect::new(0, 0, 240, 5), Some(&v))
                [0]
            .to_string();
            for label in [
                "Filter",
                "Provers",
                "Ring",
                "Size",
                "Shards",
                "PeerHead",
                "GlobalHead",
                "Reward",
            ] {
                assert_eq!(
                    printed_width(&alloc[..alloc.find(label).unwrap()]),
                    printed_width(&avail[..avail.find(label).unwrap()]),
                    "{label}: {alloc} / {avail}"
                );
            }
            assert!(!avail.contains("LocalMat"));
            assert!(!avail.contains("Execution"));
            assert_eq!(avail_cell(&m, &available[0], 7, v[1]), "987654321");
        }
    }

    #[test]
    fn reported_app_notice_has_independent_scope_timestamp_and_freshness() {
        use quil_types::proto::node::ShardRewardInfo;
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let mut m = Model::new();
        m.last_fetch_success = Some(now);
        let shards = quil_types::proto::node::GetShardInfoResponse {
            shards: vec![ShardRewardInfo {
                filter: vec![1],
                active_provers: 1,
                latest_frame: 10,
                ..Default::default()
            }],
            ..Default::default()
        };
        for ago in [60, 30, 0] {
            m.observe_reported_app_heads(&shards, now - Duration::from_secs(ago));
        }
        update_message_lifetime(&mut m);
        let timestamp = m
            .reported_app_stall_time
            .expect("known shard stalls independently of local allocations");
        let text = message_lines(&m, Line::default(), 300)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains(&format!(
            "{}Peer app frames unchanged >60s: 1/1 tracked shards.",
            message_timestamp(Some(timestamp))
        )));
        assert!(
            text.chars().count() <= 80,
            "keep routine notices short; explain tracking in help"
        );
        assert!(!text.contains("Local app frames unchanged"));
        for interval in [30, 60, 5, 15] {
            m.refresh_seconds = interval;
            update_message_lifetime(&mut m);
            assert_eq!(m.reported_app_stall_time, Some(timestamp));
        }
        let mut allocation = row("01", 1, 1, 9, "", "");
        allocation.filter = vec![1];
        allocation.latest_frame = 10;
        let mut available = shard("01", 1, 1);
        available.filter = vec![1];
        available.latest_frame = 10;
        assert_eq!(alloc_cell(&m, &allocation, 7, 0), "10!");
        assert_eq!(avail_cell(&m, &available, 9, 0), "stalled!");
        m.color_coding = true;
        assert!(!alloc_display_cell(&m, &allocation, 7, 0).contains('!'));
        assert!(!avail_display_cell(&m, &available, 9, 0).contains('!'));
        let lines =
            render_alloc_panel(&mut m, &[allocation.clone()], Rect::new(0, 0, 300, 3), None);
        assert!(lines
            .iter()
            .flat_map(|line| &line.spans)
            .any(|span| span.content.trim() == "10" && span.style.fg == Some(WARNING)));
        m.color_coding = false;
        assert!(alloc_display_cell(&m, &allocation, 7, 0).contains('!'));
        assert!(avail_display_cell(&m, &available, 9, 0).contains('!'));
        m.notice_minimum = NoticeSeverity::Error;
        assert!(!message_lines(&m, Line::default(), 300)
            .iter()
            .any(|l| l.to_string().contains("Peer app frames unchanged")));
        m.shard_error = Some("fetch failed".into());
        update_message_lifetime(&mut m);
        assert!(m.reported_app_stall_time.is_none());
        assert_eq!(alloc_cell(&m, &allocation, 7, 0), "10");
        assert_ne!(avail_cell(&m, &available, 9, 0), "stalled!");
    }

    #[test]
    fn app_stall_warning_counts_each_allocation_and_clears_on_progress_or_missing_data() {
        use quil_types::proto::node::WorkerExecution;
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut m = Model::new();
        m.frame_number = 2160;
        m.epoch_length = 720;
        m.reachable = true;
        m.color_coding = false;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut worker = row("aa", 1, 1, 7, "", "");
        worker.status = 2;
        worker.epoch = 3;
        worker.execution = Some(WorkerExecution {
            state: "serving".into(),
            materialized_frame: Some(744),
            observed_unix_ms: now,
            last_advance_unix_ms: now - 120_000,
            ..Default::default()
        });
        let mut other = worker.clone();
        other.filter_key = "bb".into();
        other.filter_hex = "bb".into();
        other.worker_id = 8;
        m.allocations = vec![worker, other];
        update_app_progress_warning(&mut m);
        let timestamp = m.app_stall_time.expect("known stalled workers warn");
        update_app_progress_warning(&mut m);
        assert_eq!(m.app_stall_time, Some(timestamp));
        let notices = |m: &Model| {
            message_lines(m, Line::default(), 240)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        };
        m.notice_minimum = NoticeSeverity::Warning;
        assert!(notices(&m).contains(&format!(
            "{}Local app frames unchanged >60s: 2/2 allocations.",
            message_timestamp(Some(timestamp))
        )));
        m.notice_minimum = NoticeSeverity::Error;
        assert!(!notices(&m).contains("Local app frames unchanged"));
        m.notice_minimum = NoticeSeverity::Warning;
        // One advancing allocation no longer hides another that stopped.
        m.allocations[1]
            .execution
            .as_mut()
            .unwrap()
            .last_advance_unix_ms = now;
        update_app_progress_warning(&mut m);
        assert_eq!(m.app_stall_time, Some(timestamp));
        assert!(notices(&m).contains("Local app frames unchanged >60s: 1/2 allocations."));
        assert_eq!(alloc_display_cell(&m, &m.allocations[0], 6, 0), "744!");
        assert_eq!(alloc_display_cell(&m, &m.allocations[1], 6, 0), "744 ");
        assert_eq!(local_color(&m, &m.allocations[0]), Color::Yellow);
        assert_eq!(local_color(&m, &m.allocations[1]), SUCCESS);
        // Missing data leaves the count rather than counting as a stall.
        m.allocations[0].execution = None;
        update_app_progress_warning(&mut m);
        assert!(m.app_stall_time.is_none());
        assert!(!notices(&m).contains("Local app frames unchanged"));
        m.allocations[1].execution = None;
        update_app_progress_warning(&mut m);
        assert!(m.app_stall_time.is_none());
        assert!(m.app_progress_observed_since.is_none());
    }

    #[test]
    fn global_app_notice_reports_unchanged_and_trailing_committed_heads() {
        use quil_types::proto::node::{GetShardInfoResponse, GlobalAppFrameHead, ShardRewardInfo};
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let mut m = Model::new();
        m.last_fetch_success = Some(now);
        let shard_info =
            |filter: u8, provers: u32, latest: u64, head: Option<(u64, u64)>| ShardRewardInfo {
                filter: vec![filter],
                active_provers: provers,
                latest_frame: latest,
                global_head: head.map(|(frame, global_frame)| GlobalAppFrameHead {
                    frame,
                    global_frame,
                    generation: 1,
                }),
                ..Default::default()
            };
        for step in 0..3u64 {
            let snapshot = GetShardInfoResponse {
                shards: vec![
                    // GLOBAL and the shard advance; the committed head does not.
                    shard_info(1, 4, 1000 + step * 6, Some((995, 500 + step * 3))),
                    // The committed head advances but trails by more than the bound.
                    shard_info(2, 4, 1300 + step, Some((1000 + step, 500 + step * 3))),
                    // Healthy: the committed head follows the shard.
                    shard_info(
                        3,
                        4,
                        1000 + step * 6,
                        Some((995 + step * 6, 500 + step * 3)),
                    ),
                    // GLOBAL did not advance: the Global head notice covers it.
                    shard_info(4, 4, 1000 + step * 6, Some((995, 500))),
                    // The shard produced nothing new for GLOBAL to commit.
                    shard_info(5, 4, 1000, Some((995, 500 + step * 3))),
                    // Unstaffed, or without a committed head: not tracked.
                    shard_info(6, 0, 1000 + step * 6, Some((995, 500 + step * 3))),
                    shard_info(7, 4, 1000 + step * 6, None),
                ],
                ..Default::default()
            };
            m.observe_committed_app_heads(&snapshot, now - Duration::from_secs(60 - step * 30));
        }
        assert_eq!(m.committed_app_counts(now), Some((1, 1, 5)));
        update_message_lifetime(&mut m);
        let unchanged = m.notice_since["global-app-unchanged"];
        let behind = m.notice_since["global-app-behind"];
        let text = message_lines(&m, Line::default(), 300)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        for notice in [
            format!(
                "{}Global app frames unchanged >60s: 1/5 tracked shards.",
                message_timestamp(Some(unchanged))
            ),
            format!(
                "{}Global app frames >100 behind app heads: 1/5 tracked shards.",
                message_timestamp(Some(behind))
            ),
        ] {
            assert!(text.contains(&notice), "{notice} missing from {text:?}");
            assert!(notice.chars().count() <= 80, "routine notices fit one row");
        }
        let committed = |filter: u8, frame: u64| {
            let mut s = shard("01", 1, 1);
            s.filter = vec![filter];
            s.global_head = Some(GlobalAppFrameHead {
                frame,
                global_frame: 506,
                generation: 1,
            });
            s
        };
        let (stalled, trailing, healthy) =
            (committed(1, 995), committed(2, 1002), committed(3, 1007));
        assert_eq!(avail_cell(&m, &stalled, 8, 0), "995@g1!");
        assert_eq!(avail_cell(&m, &trailing, 8, 0), "1002@g1!");
        assert_eq!(avail_cell(&m, &healthy, 8, 0), "1007@g1");
        let mut allocation = row("02", 1, 1, 7, "", "");
        allocation.filter = vec![2];
        allocation.global_head = trailing.global_head.clone();
        assert_eq!(alloc_cell(&m, &allocation, 8, 0), "1002@g1!");
        assert_eq!(alloc_display_cell(&m, &allocation, 8, 0), "1002@g1 ");
        let lines = render_avail_panel(
            &mut m,
            &[healthy.clone(), stalled.clone()],
            Rect::new(0, 0, 300, 4),
            None,
        );
        let fg = |content: &str| {
            lines
                .iter()
                .flat_map(|line| &line.spans)
                .find(|span| span.content.trim() == content)
                .and_then(|span| span.style.fg)
        };
        assert_eq!(fg("995@g1"), Some(WARNING));
        assert_ne!(fg("1007@g1"), Some(WARNING));
        m.color_coding = false;
        assert_eq!(avail_display_cell(&m, &stalled, 8, 0), "995@g1!");
        assert_eq!(avail_display_cell(&m, &healthy, 8, 0), "1007@g1 ");
        m.notice_minimum = NoticeSeverity::Error;
        assert!(!message_lines(&m, Line::default(), 300)
            .iter()
            .any(|l| l.to_string().contains("Global app frames")));
        m.notice_minimum = NoticeSeverity::Warning;
        // Stale status cannot keep a claim alive, nor can a failed shard fetch.
        m.last_fetch_success = Some(now - Duration::from_secs(60));
        assert!(!message_lines(&m, Line::default(), 300)
            .iter()
            .any(|l| l.to_string().contains("Global app frames")));
        m.last_fetch_success = Some(now);
        m.shard_error = Some("fetch failed".into());
        update_message_lifetime(&mut m);
        assert!(m.committed_app_counts(now).is_none());
        assert!(!m.committed_app_flagged(&[1]));
        assert!(m.notice_since.is_empty());
        assert_eq!(avail_cell(&m, &stalled, 8, 0), "995@g1");
    }

    #[test]
    fn global_app_lag_needs_one_snapshot_and_uses_the_higher_local_or_peer_head() {
        use quil_types::proto::node::{
            GetShardInfoResponse, GlobalAppFrameHead, ShardRewardInfo, WorkerExecution,
        };
        let now = std::time::Instant::now();
        let mut m = Model::new();
        m.last_fetch_success = Some(now);
        let mut allocation = row("09", 1, 1, 3, "", "");
        allocation.filter = vec![9];
        allocation.execution = Some(WorkerExecution {
            materialized_frame: Some(1151),
            ..Default::default()
        });
        m.allocations = vec![allocation];
        let snapshot = |committed| GetShardInfoResponse {
            shards: vec![ShardRewardInfo {
                filter: vec![9],
                active_provers: 4,
                latest_frame: 1000,
                global_head: Some(GlobalAppFrameHead {
                    frame: committed,
                    global_frame: 500,
                    generation: 2,
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        m.observe_committed_app_heads(&snapshot(1051), now);
        assert_eq!(
            m.committed_app_counts(now),
            None,
            "the bound itself is not behind"
        );
        m.observe_committed_app_heads(&snapshot(1050), now);
        assert_eq!(m.committed_app_counts(now), Some((0, 1, 1)));
        assert!(m.committed_app_flagged(&[9]));
        m.allocations.clear();
        m.observe_committed_app_heads(&snapshot(1050), now);
        assert_eq!(
            m.committed_app_counts(now),
            None,
            "the peer head alone is within the bound"
        );
    }

    #[test]
    fn reward_notice_compares_the_60m_forecast_with_its_24h_window() {
        use quil_types::proto::node::{FrameCadence, FrameWindow};
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        let mut m = Model::new();
        m.frame_number = 2160;
        m.epoch_length = 720;
        m.last_fetch_success = Some(Instant::now());
        let mut allocation = row("aa", 1, 1, 7, "", "");
        allocation.filter = vec![0xaa];
        allocation.status = 2;
        allocation.epoch = 3;
        allocation.estimated_reward = BigInt::from(5_000_000);
        m.allocations = vec![allocation];
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cadence = |hour_seconds, hour_frames| FrameCadence {
            last_observed_unix_seconds: seconds,
            hour: Some(FrameWindow {
                window_seconds: 3600,
                observed_seconds: hour_seconds,
                advanced_frames: hour_frames,
            }),
            day: Some(FrameWindow {
                window_seconds: 86_400,
                observed_seconds: 86_400,
                advanced_frames: 4800,
            }),
        };
        let notices = |m: &Model| {
            message_lines(m, Line::default(), 300)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        };
        m.node_app_cadence.insert(vec![0xaa], cadence(3600, 20));
        update_message_lifetime(&mut m);
        let since = m.notice_since["reward-drop"];
        assert!(notices(&m).contains(&format!(
            "{}Reward now 60m ~0.3 vs 24h ~3.0 Q/d.",
            message_timestamp(Some(since))
        )));
        // The notice quotes the same forecasts as the Reward KPI.
        assert!(reward_total(&m, &m.allocations, 0).starts_with("0.3/3.0/"));
        m.notice_minimum = NoticeSeverity::Error;
        assert!(!notices(&m).contains("Reward now"));
        m.notice_minimum = NoticeSeverity::Warning;
        m.last_fetch_success = Some(Instant::now() - Duration::from_secs(60));
        assert!(!notices(&m).contains("Reward now"));
        m.last_fetch_success = Some(Instant::now());
        // Half of the 24h rate or more is not a drop.
        m.node_app_cadence.insert(vec![0xaa], cadence(3600, 100));
        update_message_lifetime(&mut m);
        assert!(!m.notice_since.contains_key("reward-drop"));
        // Short 60m coverage cannot establish a drop.
        m.node_app_cadence.insert(vec![0xaa], cadence(600, 0));
        update_message_lifetime(&mut m);
        assert!(!m.notice_since.contains_key("reward-drop"));
        // Unassigned allocations take no part.
        m.node_app_cadence.insert(vec![0xaa], cadence(3600, 20));
        m.allocations[0].worker_id = -1;
        assert!(reward_drop(&m).is_none());
    }

    #[test]
    fn allocation_notices_count_workerless_failed_stale_and_recovering_rows() {
        use quil_types::proto::node::{ShardRecovery, WorkerExecution};
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        let mut m = Model::new();
        m.frame_number = 2160;
        m.epoch_length = 720;
        m.reachable = true;
        m.last_fetch_success = Some(Instant::now());
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        m.worker_snapshot_received = Some((Instant::now(), now_ms));
        let execution = |state: &str| {
            Some(WorkerExecution {
                state: state.into(),
                materialized_frame: Some(744),
                observed_unix_ms: now_ms,
                last_advance_unix_ms: now_ms,
                ..Default::default()
            })
        };
        let allocation =
            |filter: u8, worker: i64, epoch: u64, status: &str, state: Option<&str>| {
                let mut a = row(&format!("{filter:02x}"), 1, 1, worker, "", "");
                a.filter = vec![filter];
                a.status = 2;
                a.epoch = epoch;
                a.status_name = status.into();
                a.execution = state.and_then(|state| execution(state));
                a
            };
        m.allocations = vec![
            allocation(1, 3, 3, "active", Some("serving")),
            allocation(2, -1, 3, "active", None),
            allocation(3, 4, 1, "re-confirm!", Some("serving")),
            allocation(4, 5, 3, "active", Some("blocked")),
        ];
        m.allocations[0].execution.as_mut().unwrap().recovery = Some(ShardRecovery {
            last_error_unix_ms: now_ms,
            last_outcome_unix_ms: now_ms - 1000,
            consecutive_failures: 1,
            ..Default::default()
        });
        // A bound worker's stopped engine is a lifecycle wait, not an allocation's failure.
        let mut bound = row("w9", 1, 1, 9, "", "");
        bound.status = 0;
        bound.status_name = "bound".into();
        bound.execution = execution("stopped");
        m.allocations.push(bound);
        update_message_lifetime(&mut m);
        let lines = message_lines(&m, Line::default(), 300);
        let find = |text: &str| {
            lines
                .iter()
                .find(|l| l.to_string().contains(text))
                .unwrap_or_else(|| panic!("`{text}` missing"))
        };
        for (key, text, color) in [
            (
                "allocation-workerless",
                "Allocations without a worker: 1/4.",
                ERROR,
            ),
            (
                "local-execution-failed",
                "Local execution blocked or stopped: 1/2 allocations.",
                ERROR,
            ),
            (
                "allocation-epoch-stale",
                "Allocation epoch stale (re-confirm!): 1/4 allocations.",
                WARNING,
            ),
            (
                "recovery-failed",
                "Last recovery attempt failed: 1/4 workers.",
                WARNING,
            ),
        ] {
            let line = find(text);
            assert!(line
                .to_string()
                .starts_with(&message_timestamp(Some(m.notice_since[key]))));
            assert_eq!(line.spans[0].style.fg, Some(color), "{text}");
            assert!(line.to_string().chars().count() <= 80, "{text}");
        }
        m.notice_minimum = NoticeSeverity::Error;
        let errors = message_lines(&m, Line::default(), 300)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(errors.contains("Allocations without a worker"));
        assert!(!errors.contains("Last recovery attempt failed"));
        // Old worker data cannot establish a worker, execution or recovery claim.
        m.worker_snapshot_received = Some((Instant::now() - Duration::from_secs(120), now_ms));
        update_message_lifetime(&mut m);
        assert_eq!(
            m.notice_since.keys().copied().collect::<Vec<_>>(),
            vec!["allocation-epoch-stale"]
        );
        m.worker_snapshot_received = Some((Instant::now(), now_ms));
        m.allocations[0].execution.as_mut().unwrap().recovery = Some(ShardRecovery {
            last_error_unix_ms: now_ms - 1000,
            last_outcome_unix_ms: now_ms,
            ..Default::default()
        });
        m.allocations[1].worker_id = 6;
        m.allocations[1].execution = execution("serving");
        m.allocations[2].epoch = 3;
        m.allocations[2].status_name = "active".into();
        m.allocations[3].execution = execution("serving");
        assert!(condition_notices(&m).is_empty());
        update_message_lifetime(&mut m);
        assert!(m.notice_since.is_empty());
    }

    #[test]
    fn worker_context_stays_in_allocation_panel_and_zero_frames_warns() {
        use quil_types::proto::node::WorkerExecution;
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut worker = row("01", 2, 1, 7, "", "");
        worker.execution = Some(WorkerExecution {
            state: "running".into(),
            observed_unix_ms: now,
            materialized_frame: Some(124),
            last_advance_unix_ms: now - 22_000,
            ..Default::default()
        });
        worker.latest_frame = 125;
        assert!(!local_warning(&m, &worker));
        assert_eq!(alloc_cell(&m, &worker, 7, 12), "125");
        assert!(allocation_detail(&m, &worker)
            .to_string()
            .contains("Last advance: <60s"));
        for elapsed in [120_000, 240_000] {
            worker.execution.as_mut().unwrap().last_advance_unix_ms = now - elapsed;
            assert_eq!(
                allocation_detail(&m, &worker).to_string(),
                "Last advance: >60s"
            );
        }
        worker.execution.as_mut().unwrap().last_advance_unix_ms = 0;
        assert!(allocation_detail(&m, &worker)
            .to_string()
            .contains("not observed since start"));
        worker.execution.as_mut().unwrap().materialized_frame = Some(0);
        assert!(local_warning(&m, &worker));
        assert_eq!(alloc_cell(&m, &worker, 6, 12), "0!");
        assert_eq!(local_color(&m, &worker), Color::Yellow);
        assert!(allocation_detail(&m, &worker)
            .to_string()
            .contains("Local app frames: none materialized."));
        worker.execution.as_mut().unwrap().recovery =
            Some(quil_types::proto::node::ShardRecovery {
                phase: "installing_leaves".into(),
                phase_since_unix_ms: now - 5_000,
                installed_leaves: 131_072,
                planned_leaves: 2_517_449,
                leaves_observed_unix_ms: now,
                ..Default::default()
            });
        let detail = allocation_detail(&m, &worker).to_string();
        assert!(
            detail.contains("Local app frames: none materialized.")
                && detail.contains("Recovery: installing_leaves")
        );
        assert!(detail.contains("131072/2517449"));
        worker.execution.as_mut().unwrap().state = "blocked".into();
        worker.execution.as_mut().unwrap().blocker = "awaiting successor".into();
        m.allocations.push(worker);
        for minimum in [
            NoticeSeverity::Info,
            NoticeSeverity::Warning,
            NoticeSeverity::Error,
        ] {
            m.notice_minimum = minimum;
            let notices = message_lines(&m, Line::default(), 150)
                .iter()
                .map(Line::to_string)
                .collect::<String>();
            assert!(!notices.contains("Worker") && !notices.contains("awaiting successor"));
        }
        let rows = m.allocations.clone();
        let panel = render_alloc_panel(&mut m, &rows, Rect::new(0, 0, 154, 7), None);
        let details = panel.last().unwrap().to_string();
        assert!(details.contains("Reason: awaiting successor"));
        assert!(!details.contains("observation") && !details.contains("Worker 7"));
    }

    #[test]
    fn current_reward_total_retains_known_subtotal_when_other_rows_are_unknown() {
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        m.frame_number = 2160;
        m.epoch_length = 720;
        let mut known = row("aa", 1, 1, 7, "", "");
        known.status = 2;
        known.epoch = 3;
        known.estimated_reward = BigInt::from(10000);
        let mut unknown = known.clone();
        unknown.ring = UNKNOWN_REWARD_RING;
        let title = alloc_title(&m, &[known.clone(), unknown.clone()]).to_string();
        assert!(
            title.contains(&format!(
                "now -/-/{}+ |",
                fmt_reward(&known.estimated_reward)
            )),
            "{title}"
        );
        assert!(alloc_title(&m, &[unknown])
            .to_string()
            .contains("now -/-/- |"));
        known.estimated_reward = BigInt::from(0);
        let mut unknown = known.clone();
        unknown.ring = UNKNOWN_REWARD_RING;
        assert!(alloc_title(&m, &[known, unknown])
            .to_string()
            .contains("now -/-/0.0+ |"));
    }

    #[test]
    fn all_actual_notices_have_utc_timestamps() {
        let mut m = Model::new();
        m.status_msg = "Action failed".into();
        m.status_is_error = true;
        let action = status_line(&m).to_string();
        assert!(action.starts_with('[') && action.contains(" UTC] Action failed"));
        m.shard_error = Some("timed out".into());
        assert!(shard_message(&m)
            .unwrap()
            .to_string()
            .contains(" UTC] Shard fetch timed out"));
    }

    #[test]
    fn claimable_five_decimals_preserve_zero_tiny_values_and_rounding_carry() {
        for (units, expected) in [
            (0, "0"),
            (1, "<0.00001"),
            (79_999, "<0.00001"),
            (80_000, "0.00001"),
            (119_999, "0.00001"),
            (120_000, "0.00002"),
            (474_867, "0.00006"),
            (40_000_000_000, "5"),
            (7_999_999_999, "1"),
        ] {
            assert_eq!(fmt_claimable(units), expected);
        }
        assert!(fmt_claimable(u128::MAX)
            .split('.')
            .nth(1)
            .is_none_or(|fraction| fraction.len() <= 5));
    }

    #[test]
    fn global_app_cursor_stays_distinct_from_peer_and_local_heights() {
        let mut allocation = row("aa", 1, 1, 7, "", "");
        allocation.latest_frame = 744;
        allocation.global_head = Some(quil_types::proto::node::GlobalAppFrameHead {
            frame: 742,
            global_frame: 1000,
            generation: 2,
        });
        allocation.execution = Some(quil_types::proto::node::WorkerExecution {
            materialized_frame: Some(744),
            ..Default::default()
        });
        assert!(!allocation_detail(&Model::new(), &allocation)
            .to_string()
            .contains("Global"));
        let mut m = Model::new();
        assert_eq!(alloc_cell(&m, &allocation, 8, 0), "742@g2");
        assert_eq!(alloc_cell(&m, &allocation, 7, 0), "744");
        let mut peer = shard("bb", 1, 1);
        peer.latest_frame = 900;
        peer.global_head = allocation.global_head.clone();
        assert!(!available_detail(&m, &peer).to_string().contains("Global"));
        assert_eq!(avail_cell(&m, &peer, 8, 0), "742@g2");
        assert_eq!(avail_cell(&m, &peer, 7, 0), "900");
        peer.global_head = None;
        assert_eq!(avail_cell(&m, &peer, 8, 0), "-");
        assert!(avail_row_numeric_val(&Model::new(), &peer, 8).is_nan());
        peer.global_head = Some(Default::default());
        assert_eq!(avail_cell(&m, &peer, 8, 0), "0@g0");
        assert_eq!(avail_row_numeric_val(&Model::new(), &peer, 8), 0.0);
        m.compact_actions = false;
        assert_eq!(
            global_snapshot_label(&m, [allocation.global_head.as_ref()].into_iter()),
            "Snapshot: @f1000"
        );
        assert_eq!(
            global_snapshot_label(&m, [None].into_iter()),
            "Snapshot: unavailable"
        );
        assert_eq!(
            global_snapshot_label(
                &m,
                [allocation.global_head.as_ref(), peer.global_head.as_ref()].into_iter()
            ),
            "Snapshot: mixed"
        );
        assert!(alloc_title(&m, &[allocation])
            .to_string()
            .contains("Snapshot: @f1000"));
        assert!(avail_title(&m, &[peer])
            .to_string()
            .contains("Snapshot: @f0"));
    }

    #[test]
    fn panel_details_distinguish_successor_wait_from_peer_delay() {
        let mut allocation = row("aa", 1, 1, 7, "", "");
        allocation.execution = Some(quil_types::proto::node::WorkerExecution {
            state: "blocked".into(),
            blocker: "awaiting successor".into(),
            observed_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            ..Default::default()
        });
        let mut peer = shard("bb", 1, 1);
        peer.materialized_frame = 18;
        peer.latest_frame = 22;
        assert_eq!(
            Model::new().allocation_execution_state(&allocation),
            "handoff"
        );
        assert!(allocation_detail(&Model::new(), &allocation)
            .spans
            .iter()
            .all(|s| s.style.fg == Some(HELP)));
        assert!(available_detail(&Model::new(), &peer)
            .spans
            .iter()
            .all(|s| s.style.fg == Some(Color::Yellow)));
    }

    #[test]
    fn execution_phases_fit_the_column_and_expected_waits_do_not_warn() {
        use quil_types::proto::node::WorkerExecution;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut m = Model::new();
        m.reachable = true;
        m.frame_number = 2160;
        m.epoch_length = 720;
        for (state, label, reason) in [
            ("syncing", "sync", "staging shard data"),
            ("closing", "close", "awaiting closing certificate"),
            ("handoff", "handoff", "awaiting successor"),
            ("waiting", "wait", "awaiting allocation activation"),
        ] {
            let mut allocation = row("aa", 1, 1, 7, "", "");
            allocation.status = 2;
            allocation.epoch = 3;
            allocation.status_name = "active".into();
            allocation.execution = Some(WorkerExecution {
                state: state.into(),
                blocker: reason.into(),
                materialized_frame: Some(0),
                last_advance_unix_ms: now - 120_000,
                observed_unix_ms: now,
                ..Default::default()
            });
            assert_eq!(alloc_cell(&m, &allocation, 9, STATE_WIDTH), label);
            assert_eq!(alloc_cell(&m, &allocation, 6, MAT_WIDTH), "0");
            assert_eq!(local_color(&m, &allocation), HELP);
            assert!(allocation_detail(&m, &allocation)
                .to_string()
                .contains(&format!("Reason: {reason}")));
            m.allocations = vec![allocation];
            m.app_progress_observed_since =
                Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
            update_app_progress_warning(&mut m);
            assert!(m.app_stall_time.is_none());
            assert!(m.app_progress_observed_since.is_none());
        }
        m.allocations[0].execution.as_mut().unwrap().state = "serving".into();
        assert_eq!(alloc_cell(&m, &m.allocations[0], 9, STATE_WIDTH), "serve");
        assert!(local_warning(&m, &m.allocations[0]));
        update_app_progress_warning(&mut m);
        assert!(
            m.app_stall_time.is_some(),
            "serving still has independent progress warnings"
        );
    }

    #[test]
    fn global_head_columns_sort_and_filter_without_confusing_unknown_and_zero() {
        let mut m = Model::new();
        for (id, head) in [("a", Some(742)), ("b", None), ("c", Some(0))] {
            let mut a = row(id, 1, 1, 7, "", "");
            a.global_head = head.map(|frame| quil_types::proto::node::GlobalAppFrameHead {
                frame,
                global_frame: 1000,
                generation: 2,
            });
            let mut s = shard(id, 1, 1);
            s.global_head = a.global_head.clone();
            m.allocations.push(a);
            m.available.push(s);
        }
        m.alloc_sort_col = 8;
        m.alloc_sort_asc = true;
        m.avail_sort_col = 8;
        m.avail_sort_asc = true;
        assert_eq!(
            m.sorted_allocations()
                .iter()
                .map(|r| r.filter_key.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "c", "a"]
        );
        assert_eq!(
            m.sorted_available()
                .iter()
                .map(|r| r.filter_key.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "c", "a"]
        );
        let filter = ColumnFilter {
            expr: "=0".into(),
            ..Default::default()
        };
        m.alloc_col_filters.insert(8, filter.clone());
        m.avail_col_filters.insert(8, filter);
        assert_eq!(m.filtered_allocations()[0].filter_key, "c");
        assert_eq!(m.filtered_allocations().len(), 1);
        assert_eq!(m.filtered_available()[0].filter_key, "c");
        assert_eq!(m.filtered_available().len(), 1);
    }

    #[test]
    fn inactive_cursors_bind_both_panel_details_and_keep_peer_warnings_visible() {
        let mut m = Model::new();
        m.focus = PanelFocus::Notifications;
        let mut allocation = row("aa", 1, 1, 7, "", "");
        allocation.execution = Some(quil_types::proto::node::WorkerExecution {
            state: "blocked".into(),
            blocker: "awaiting successor".into(),
            ..Default::default()
        });
        let allocations = render_alloc_panel(&mut m, &[allocation], Rect::new(0, 0, 240, 5), None);
        assert_eq!(allocations[1].style.bg, Some(INACTIVE_CURSOR_BG));
        assert!(allocations
            .last()
            .unwrap()
            .to_string()
            .contains("awaiting successor"));
        let mut peer = shard("bb", 1, 1);
        peer.latest_frame = 20;
        let peers = render_avail_panel(&mut m, &[peer.clone()], Rect::new(0, 0, 240, 5), None);
        assert_eq!(peers[1].style.bg, Some(INACTIVE_CURSOR_BG));
        assert!(peers[1].to_string().contains("unmat"));
        assert!(!peers[1].to_string().contains("unmat!"));
        assert_eq!(peers[1].spans[20].style.fg, Some(WARNING));
        assert!(peers
            .last()
            .unwrap()
            .to_string()
            .contains("Peer app frames: none materialized."));
        peer.materialized_frame = 15;
        assert!(available_detail(&m, &peer)
            .to_string()
            .contains("by 5 frames"));
        peer.materialized_frame = 20;
        assert!(!available_detail(&m, &peer).to_string().contains("Warning"));
        peer.latest_frame = 0;
        peer.materialized_frame = 0;
        assert!(available_detail(&m, &peer)
            .to_string()
            .contains("Peer app frame heights unavailable."));
    }

    #[test]
    fn claimable_header_distinguishes_loading_missing_verified_and_stale() {
        let mut m = Model::new();
        m.compact_actions = false;
        assert_eq!(claimable_title(&m), "Claimable [Q]: loading");
        super::super::update::apply_msg(
            &mut m,
            super::super::msg::Msg::RewardRefresh(Ok(Some((474867, 862280)))),
        );
        assert_eq!(claimable_title(&m), "Claimable [Q]: 0.00006 @f862280");
        assert!(alloc_title(&m, &[]).to_string().contains("[Q]"));
        m.reward_last_success = Some(
            std::time::Instant::now() - std::time::Duration::from_secs(m.refresh_seconds * 2 + 31),
        );
        assert!(claimable_title(&m).ends_with("(stale)"));
        super::super::update::apply_msg(
            &mut m,
            super::super::msg::Msg::RewardRefresh(Err("timeout".into())),
        );
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
        let text = |m: &Model| {
            message_lines(m, status_line(m), 80)
                .iter()
                .map(ToString::to_string)
                .collect::<String>()
        };
        assert!(
            text(&m).is_empty(),
            "default warnings filter hides routine fetches"
        );
        m.shard_fetch_started = Some(Instant::now() - Duration::from_secs(16));
        assert!(text(&m).contains("slow (16s)"));
        m.notice_minimum = NoticeSeverity::Error;
        assert!(text(&m).is_empty());
        m.shard_error = Some("Shard query timed out".into());
        assert!(text(&m).contains("timed out"), "missing data is an error");
        m.cached_shard_info = Some(Default::default());
        assert!(
            text(&m).is_empty(),
            "cache-preserving failures are warnings"
        );
        m.notice_minimum = NoticeSeverity::Warning;
        assert!(text(&m).contains("cached rows"));
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
        for message in [
            "",
            "Short warning",
            "A long error notification ".repeat(20).as_str(),
        ] {
            m.status_msg = message.to_owned();
            m.status_is_error = true;
            terminal.draw(|f| draw(f, &mut m)).unwrap();
            let buffer = terminal.backend().buffer();
            let rows = (0..30)
                .map(|y| (0..80).map(|x| buffer[(x, y)].symbol()).collect::<String>())
                .collect::<Vec<_>>();
            notification_rows.push(
                rows.iter()
                    .position(|row| row.contains("Notifications · Level:"))
                    .unwrap(),
            );
            available_rows.push(
                rows.iter()
                    .position(|row| row.contains("Available Shards"))
                    .unwrap(),
            );
            for title in ["Allocations", "Available Shards", "Notifications · Level:"] {
                let row = rows.iter().find(|row| row.contains(title)).unwrap();
                assert!(
                    row.starts_with('╭') && row.ends_with('╮'),
                    "title must share its panel border: {row}"
                );
                let y = rows.iter().position(|candidate| candidate == row).unwrap() as u16;
                let cell = &buffer[(2, y)];
                assert_eq!(cell.fg, PRIMARY, "panel titles share the primary color");
                assert!(
                    cell.modifier.contains(Modifier::BOLD),
                    "panel titles share bold weight"
                );
            }
            assert_eq!(
                rows.iter().position(|row| row.contains("Allocations")),
                Some(1)
            );
            assert_eq!(m.notice_visible, 3);
            assert!(rows.iter().any(|row| row.contains("‹q›")));
        }
        assert!(notification_rows.iter().all(|y| *y == notification_rows[0]));
        assert!(available_rows.iter().all(|y| *y == available_rows[0]));
    }

    #[test]
    fn completed_notices_expire_but_unresolved_warnings_stay_visible() {
        use std::time::{Duration, Instant, UNIX_EPOCH};
        assert_eq!(
            message_timestamp(Some(UNIX_EPOCH + Duration::from_secs(3723))),
            "[01:02:03 UTC] "
        );
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
        assert!(shard_message(&m)
            .unwrap()
            .to_string()
            .contains("Query failed"));
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
        let text = |lines: Vec<Line<'static>>| {
            lines
                .into_iter()
                .map(|l| l.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        };
        let waiting = text(message_lines(&m, status_line(&m), 60));
        assert!(waiting.contains("Confirm sent"));
        assert!(waiting.contains("Fetching shards"));
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
        assert!(recovered.contains("Shards updated: 0 (22s)"));
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
        assert_eq!(
            lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" "),
            message
        );
        let token = "x".repeat(105);
        let lines = wrap_message(Line::from(token.clone()), 40);
        assert!(lines.iter().all(|line| line.width() <= 40));
        assert_eq!(
            lines.iter().map(ToString::to_string).collect::<String>(),
            token
        );
        let mut m = Model::new();
        m.status_msg = message.into();
        m.status_is_error = true;
        let mut terminal = Terminal::new(TestBackend::new(40, 24)).unwrap();
        terminal.draw(|f| draw(f, &mut m)).unwrap();
        let buffer = terminal.backend().buffer();
        let rows = (0..24)
            .map(|y| (0..40).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>();
        let screen = rows
            .iter()
            .map(|line| line.trim().trim_matches('│').trim())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(screen.contains(message));
        assert!(screen.contains("Notifications"));
        assert!(screen.contains("‹q›"));
    }

    #[test]
    fn missing_shard_data_is_loading_or_failed_instead_of_empty() {
        let mut m = Model::new();
        m.data_loaded = true;
        let text = |lines: Vec<Line<'static>>| {
            lines[0]
                .spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        };
        assert!(text(render_avail_panel(
            &mut m,
            &[],
            Rect::new(0, 0, 100, 5),
            None
        ))
        .contains("Loading available shards"));
        m.shard_error = Some("Shard data timed out after 60s; retrying".into());
        assert!(text(render_avail_panel(
            &mut m,
            &[],
            Rect::new(0, 0, 100, 5),
            None
        ))
        .contains("timed out"));
        m.shard_error = None;
        m.cached_shard_info = Some(Default::default());
        assert!(text(render_avail_panel(
            &mut m,
            &[],
            Rect::new(0, 0, 100, 5),
            None
        ))
        .contains("No available shards"));
    }

    #[test]
    fn local_worker_state_is_independent_of_remote_shard_cursor() {
        let m = Model::new();
        let mut a = row("01", 1, 1, 4, "", "");
        a.status_name = "active".into();
        a.materialized_frame = 91;
        a.latest_frame = 93;
        a.execution = Some(quil_types::proto::node::WorkerExecution {
            state: "blocked".into(),
            blocker: "checkpoint mismatch".into(),
            materialized_frame: Some(93),
            observed_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
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
            (0, 10, "unmat", WARNING),
            (5, 10, "lag", WARNING),
            (10, 10, "current", SUCCESS),
            (11, 10, "current", SUCCESS),
        ] {
            let mut a = row("01", 1, 1, 1, "", "");
            a.status_name = "active".into();
            a.materialized_frame = mat;
            a.latest_frame = head;
            let mut s = shard("01", 0, 0);
            s.materialized_frame = mat;
            s.latest_frame = head;
            assert_eq!(alloc_cell(&m, &a, 9, 12), "unknown");
            assert_eq!(
                avail_cell(&m, &s, 9, 12),
                if matches!(label, "lag" | "unmat") {
                    format!("{label}!")
                } else {
                    label.to_string()
                }
            );
            assert_eq!(materialization_state_color(label), color);
        }
    }

    #[test]
    fn command_footer_wraps_and_leaves_status_visible() {
        use ratatui::{backend::TestBackend, Terminal};
        for width in [40, 80, 100, 160, 320] {
            let mut m = Model::new();
            m.compact_actions = false;
            m.status_msg = "status is visible".to_owned();
            m.notice_minimum = NoticeSeverity::Info;
            let mut lines = wrap_actions(help_line(&m), width);
            lines.extend(wrap_actions(worker_commands_line(&m), width));
            let legends = [help_line(&m), worker_commands_line(&m)];
            for hint in legends
                .into_iter()
                .flat_map(|line| line.spans)
                .filter(|span| !span.content.trim().is_empty())
            {
                assert!(
                    lines
                        .iter()
                        .any(|line| line.spans.iter().any(|span| span == &hint)),
                    "split command hint at width {width}: {}",
                    hint.content
                );
            }
            assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
            if width == 40 {
                assert!(lines.len() > 1);
            }
            let mut terminal = Terminal::new(TestBackend::new(width, 42)).unwrap();
            terminal.draw(|f| draw(f, &mut m)).unwrap();
            let buffer = terminal.backend().buffer();
            let footer_start = 42 - lines.len() as u16;
            let footer = (footer_start..42)
                .map(|y| {
                    (0..width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join(" ");
            for key in ["‹tab›", "‹G›", "‹c›", "‹e›", "‹h›", "‹q›"] {
                assert!(
                    footer.contains(key),
                    "missing {key} at width {width}: {footer}"
                );
            }
            let screen = (0..42)
                .map(|y| {
                    (0..width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join(" ");
            assert!(screen.contains("status is visible"));
            assert!(screen.contains("‹q›"));
        }
    }

    #[test]
    fn mode_footer_keeps_multiword_labels_and_styles_together() {
        let style = Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD);
        let lines = wrap_actions(
            Line::from(Span::styled(
                "Sort: ‹←/→› Move column  ‹enter› apply  ‹esc› cancel",
                style,
            )),
            25,
        );
        assert_eq!(lines.len(), 3);
        for (line, expected) in
            lines
                .iter()
                .zip(["Sort: ‹←/→› Move column", "‹enter› apply", "‹esc› cancel"])
        {
            assert_eq!(line.spans, vec![Span::styled(expected, style)]);
        }
    }

    /// One allocations row. Only the fields that reach a cell are meaningful.
    pub(super) fn row(
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
            allocation_reason: None,
            shard_info_known: true,
            filter: Vec::new(),
            filter_key: hex.to_string(),
            filter_hex: hex.to_string(),
            status: 1,
            status_name: "joining".to_string(),
            ring: 5,
            active_provers: provers,
            prover_counts: None,
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
        let allocations = [
            row("aabb01", 1, 1, 0, "", ""),
            row("aabb012345", 1, 1, 1, "", ""),
        ];
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
                    let text: Vec<String> = lines
                        .iter()
                        .map(|line| {
                            line.spans
                                .iter()
                                .map(|span| span.content.as_ref())
                                .collect()
                        })
                        .collect();
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
        allocation.status_name = "active".into();
        allocation.shard_info_known = false;
        for col in [2, 3, 4, 5, 6, 7, 10] {
            assert_eq!(alloc_cell(&model, &allocation, col, 12), "-");
        }
        assert_eq!(alloc_cell(&model, &allocation, 9, 12), "unknown");
        allocation.shard_info_known = true;
        for col in [2, 5] {
            assert_eq!(alloc_cell(&model, &allocation, col, 12), "0");
        }
        assert_eq!(
            alloc_cell(&model, &allocation, 4, 12),
            fmt_gb(&BigInt::from(0))
        );
    }

    #[test]
    fn unavailable_values_are_not_rendered_as_zero_rewards_or_heights() {
        let mut model = Model::new();
        model.frame_number = 2160;
        model.epoch_length = 720;
        let mut allocation = row("aa", 1, 1, 0, "", "");
        allocation.status_name = "active".into();
        allocation.filter = vec![0xaa];
        allocation.status = 2;
        allocation.epoch = 3;
        allocation.ring = UNKNOWN_REWARD_RING;
        for col in [3, 6, 7, 10] {
            assert_eq!(alloc_cell(&model, &allocation, col, 12), "-");
        }
        assert_eq!(alloc_cell(&model, &allocation, 9, 12), "unknown");
        assert_eq!(ring_color(UNKNOWN_REWARD_RING), HELP);
        let mut available = shard("bb", 1, 1);
        available.ring = UNKNOWN_REWARD_RING;
        for col in [3, 6, 7, 10] {
            assert_eq!(avail_cell(&model, &available, col, 12), "-");
        }
        let title = alloc_title(&model, &[allocation.clone()]);
        let text: String = title.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("[~Q/d 60m/24h/T] -/-/-"), "{text}");
        allocation.ring = 0;
        allocation.latest_frame = 20;
        assert_eq!(alloc_cell(&model, &allocation, 3, 12), "0");
        assert_eq!(alloc_cell(&model, &allocation, 6, 12), "-");
        // A remote head does not establish the local worker's cursor.
        allocation.execution = Some(quil_types::proto::node::WorkerExecution {
            materialized_frame: Some(0),
            ..Default::default()
        });
        assert_eq!(alloc_cell(&model, &allocation, 6, 12), "0");
        assert_eq!(alloc_cell(&model, &allocation, 7, 12), "20");
        assert_eq!(alloc_cell(&model, &allocation, 9, 12), "stale");
        assert_eq!(alloc_cell(&model, &allocation, 10, 12), "-/-/0.0");
    }

    #[test]
    fn reward_totals_separate_current_paused_and_planned_changes() {
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
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
        let title = alloc_title(
            &m,
            &[
                active,
                joining,
                unstaffed,
                expired,
                paused,
                leaving,
                unstaffed_leave,
                ended,
            ],
        );
        let text: String = title.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains(&format!(
                "now -/-/{} | paused -/-/{} | delta -/-/-{}",
                fmt_reward(&BigInt::from(60000)),
                fmt_reward(&BigInt::from(40000)),
                fmt_reward(&BigInt::from(30000))
            )),
            "{text}"
        );
    }

    #[test]
    fn planned_reward_change_preserves_sign_and_small_amounts() {
        assert_eq!(fmt_reward_change(&BigInt::from(0)), "0.0");
        assert_eq!(fmt_reward_change(&BigInt::from(1)), "+<0.1");
        assert_eq!(fmt_reward_change(&BigInt::from(-1)), "-<0.1");
        assert_eq!(fmt_reward_change(&BigInt::from(249_921_760)), "+269.9");
        assert_eq!(fmt_reward_change(&BigInt::from(-249_921_760)), "-269.9");
    }

    #[test]
    fn unassigned_reward_is_red_even_on_the_selected_row() {
        for selected in [false, true] {
            let mut m = Model::new();
            m.color_coding = true;
            m.alloc_cursor = if selected { 0 } else { 1 };
            let mut allocation = row("aa", 1, 1, -1, "", "");
            allocation.estimated_reward = BigInt::from(123456);
            let reward = reward_cell(&m, &allocation.estimated_reward, &allocation.filter);
            let lines = render_alloc_panel(&mut m, &[allocation], Rect::new(0, 0, 240, 5), None);
            let span = lines[1]
                .spans
                .iter()
                .find(|s| s.content.trim() == reward)
                .expect("reward cell");
            assert_eq!(span.style.fg, Some(ERROR));
            if selected {
                assert_eq!(lines[1].style.bg, Some(CURSOR_BG));
            }
        }
    }

    pub(super) fn shard(hex: &str, size: u64, reward: u64) -> ShardRow {
        ShardRow {
            global_head: None,
            filter: Vec::new(),
            filter_key: hex.to_string(),
            filter_hex: hex.to_string(),
            active_provers: 42,
            prover_counts: None,
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

    #[test]
    fn frame_interval_cells_and_header_share_the_window_in_both_layouts() {
        use quil_types::proto::node::{FrameCadence, FrameWindow};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut m = Model::new();
        m.data_loaded = true;
        let a = row("aa", 3, 1, 1, "", "");
        let peer = shard("aa", 1, 1);
        let c = FrameCadence {
            last_observed_unix_seconds: now,
            hour: Some(FrameWindow {
                window_seconds: 3600,
                observed_seconds: 60,
                advanced_frames: 4,
            }),
            day: Some(FrameWindow {
                window_seconds: 86400,
                observed_seconds: 120,
                advanced_frames: 4,
            }),
        };
        m.node_global_cadence = Some(c.clone());
        m.node_app_cadence.insert(a.filter.clone(), c);
        assert_eq!(alloc_cell(&m, &a, 16, 20), "15.0/30.0");
        assert_eq!(avail_cell(&m, &peer, 11, 20), "15.0/30.0");
        assert!(header_kpis(&m)
            .iter()
            .any(|line| line.to_string().contains("Global [s 60m/24h]: 15.0/30.0")));
        for mode in [ColumnSizing::Fixed, ColumnSizing::Dynamic] {
            m.column_sizing = mode;
            let (alloc, avail) = shared_col_widths(&m, 260, &[a.clone()], &[peer.clone()]);
            assert_eq!(alloc.len(), 18);
            assert_eq!(avail.len(), 13);
            assert_eq!(alloc[16], avail[11]);
            assert!(alloc[16] >= "15.0".len());
        }
        m.compact_actions = false;
        m.compact_units = false;
        let alloc_header =
            render_alloc_panel(&mut m, &[a.clone()], Rect::new(0, 0, 300, 5), None)[0].to_string();
        let avail_header =
            render_avail_panel(&mut m, &[peer.clone()], Rect::new(0, 0, 300, 5), None)[0]
                .to_string();
        assert!(alloc_header.find("GlobalHead").unwrap() < alloc_header.find("Interval").unwrap());
        assert!(alloc_header.find("Interval").unwrap() < alloc_header.find("Execution").unwrap());
        assert!(avail_header.find("GlobalHead").unwrap() < avail_header.find("Interval").unwrap());
        assert!(avail_header.find("Interval").unwrap() < avail_header.find("PeerState").unwrap());
        m.hidden_header_kpis.insert("Global interval".into());
        assert!(!header_kpis(&m)
            .iter()
            .any(|line| line.to_string().contains("Global interval")));
        m.hidden_columns.insert(16);
        m.focus = PanelFocus::Available;
        assert!(!m.column_visible(11));
        assert_eq!(m.column_visibility_key(11), 16);
        assert!(
            m.alloc_column_visible(11),
            "hiding interval must not hide Worker"
        );
        for mode in [ColumnSizing::Fixed, ColumnSizing::Dynamic] {
            m.column_sizing = mode;
            let (alloc, avail) = shared_col_widths(&m, 260, &[a.clone()], &[peer.clone()]);
            assert_eq!(alloc[16], 0);
            assert_eq!(avail[11], 0);
            assert!(alloc[11] > 0);
        }
        m.hidden_columns.remove(&16);
        m.hidden_columns.insert(11);
        assert!(
            m.avail_column_visible(11),
            "hiding Worker must not hide interval"
        );
        m.node_app_cadence.clear();
        assert_eq!(alloc_cell(&m, &a, 16, 20), "-/-");
        assert_eq!(avail_cell(&m, &peer, 11, 20), "-/-");
    }

    fn fixed() -> Model {
        Model {
            column_sizing: ColumnSizing::Fixed,
            compact_units: false,
            ..Model::new()
        }
    }

    #[test]
    fn active_count_uses_node_frame_while_shard_info_is_loading() {
        let mut m = Model::new();
        m.last_received_frame = 2160;
        m.epoch_length = 720;
        m.cached_worker_info = Some(Default::default());
        let mut active = row("01", 1, 1, 7, "", "");
        active.filter = vec![1];
        active.status = 2;
        active.epoch = 3;
        active.confirm_frame = 1;
        let mut joining = active.clone();
        joining.worker_id = 8;
        joining.confirm_frame = 2160;
        let mut orphan = active.clone();
        orphan.worker_id = -1;
        m.allocations = vec![active, joining, orphan];
        assert_eq!(m.frame_number, 0, "no shard-info snapshot yet");
        assert!(allocation_status_kpi(&m).contains("active 2"));
        m.frame_number = 720;
        assert!(
            allocation_status_kpi(&m).contains("active 2"),
            "cached shard frame does not classify current workers"
        );
    }

    #[test]
    fn bound_worker_row_explains_its_binding_and_excludes_rewards() {
        use quil_types::proto::node::WorkerExecution;
        let mut m = Model::new();
        m.cached_worker_info = Some(Default::default());
        m.allocated_workers = 1;
        m.running_workers = 1;
        let mut bound = row("aa", 1, 1, 6, "", "");
        bound.status = 0;
        bound.status_name = "bound".into();
        bound.shard_info_known = false;
        bound.estimated_reward = BigInt::from(1_000_000);
        bound.execution = Some(WorkerExecution {
            state: "blocked".into(),
            blocker: "closing session".into(),
            materialized_frame: Some(12),
            ..Default::default()
        });
        m.allocations = vec![bound.clone()];
        assert_eq!(alloc_cell(&m, &bound, 6, 12), "12");
        assert_eq!(alloc_cell(&m, &bound, 10, 12), "-");
        assert_eq!(alloc_cell(&m, &bound, 12, 12), "bound");
        assert_eq!(status_color("bound"), WARNING);
        let detail = allocation_detail(&m, &bound).to_string();
        assert!(detail.contains("Worker bound; no live allocation reported."));
        assert!(detail.contains("Blocker: closing session"));
        let title = alloc_title(&m, &m.allocations).to_string();
        assert!(title.contains("Status: bound 1"));
        assert!(
            !title.contains("86.4"),
            "worker-only estimates do not enter reward totals"
        );
        bound.execution = None;
        assert!(allocation_detail(&m, &bound)
            .to_string()
            .contains("no live allocation reported"));
        let help = help_body()
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(help.contains("run (expanded: running): reported workers"));
        assert!(help.contains("assigned: workers marked allocated"));
        assert!(help.contains("a binding may outlive its live allocation"));
        assert!(help.contains("excluded from rewards"));
    }

    /// A leave the node holds no record of (after a store reset) reads as a
    /// worker shortage while it holds more seats than configured workers.
    #[test]
    fn a_leave_inferred_from_a_worker_shortage_renders_as_w() {
        let mut m = Model::new();
        m.data_loaded = true;
        m.running_workers = 6;
        m.allocated_workers = 6;
        m.worker_capacity = 6;
        m.allocations = (1..=9u8)
            .map(|i| {
                let mut a = row(
                    &format!("{:064x}", 0x9000800 + u32::from(i)),
                    10,
                    1_000_000,
                    if i <= 6 { i64::from(i) } else { -1 },
                    "",
                    "",
                );
                if i <= 6 {
                    a.status = 2;
                    a.status_name = "active".into();
                } else {
                    a.status = 4;
                    a.status_name = "leaving".into();
                    a.allocation_reason = Some("W".into());
                }
                a
            })
            .collect();
        let compact = render_text(&mut m, 160, 24);
        assert_eq!(compact.matches("leaving(W)").count(), 3, "{compact}");
        m.compact_actions = false;
        let leaving = m.allocations[8].clone();
        assert_eq!(
            allocation_status_text(&m, &leaving),
            "leaving(worker shortage)"
        );
        let expanded = render_text(&mut m, 200, 24);
        assert!(expanded.contains("leaving(worker shortage)"), "{expanded}");
    }

    /// A node running more workers than configured shows the configured
    /// count and, while any drain, the draining workers; a node that predates
    /// the configured count keeps the old line.
    #[test]
    fn worker_header_names_the_configured_count_and_draining_workers() {
        use quil_types::proto::node::{WorkerInfo, WorkerInfoResponse};
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        m.data_loaded = true;
        m.running_workers = 9;
        m.allocated_workers = 9;
        m.worker_capacity = 6;
        let workers = |running: u32, configured: u32| WorkerInfoResponse {
            worker_info: (1..=running)
                .map(|core_id| WorkerInfo {
                    core_id,
                    filter: vec![core_id as u8; 32],
                    draining: core_id > configured,
                    ..Default::default()
                })
                .collect(),
        };
        m.cached_worker_info = Some(workers(9, 6));
        assert_eq!(
            worker_counts_line(&m).to_string(),
            "Workers: running 9 of 6 configured | draining 3 | assigned 9 | auto 9 | manual 0"
        );
        let expanded = render_text(&mut m, 160, 12);
        assert!(
            expanded.contains("Workers: running 9 of 6 configured | draining 3 | assigned 9"),
            "{expanded}"
        );
        m.compact_actions = true;
        assert_eq!(
            worker_counts_line(&m).to_string(),
            "Workers: run 9 of 6 | drain 3 | assigned 9"
        );
        let compact = render_text(&mut m, 100, 12);
        assert!(
            compact.contains("Workers: run 9 of 6 | drain 3 | assigned 9"),
            "{compact}"
        );
        m.running_workers = 6;
        m.allocated_workers = 6;
        m.cached_worker_info = Some(workers(6, 6));
        assert_eq!(
            worker_counts_line(&m).to_string(),
            "Workers: run 6 of 6 | assigned 6"
        );
        m.worker_capacity = 0;
        assert_eq!(
            worker_counts_line(&m).to_string(),
            "Workers: run 6 | assigned 6"
        );
        let help = help_body()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            help.contains("drain (expanded: draining): workers above the configured count"),
            "{help}"
        );
        assert!(help.contains("stays until the shard gains provers (expected wait)"));
    }

    #[test]
    fn worker_header_separates_assignment_activity_and_individual_modes() {
        use quil_types::proto::node::{WorkerInfo, WorkerInfoResponse};
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        m.data_loaded = true;
        m.running_workers = 3;
        m.allocated_workers = 2;
        let mut active = row("01", 1, 1, 7, "", "");
        active.status = 2;
        let mut paused = active.clone();
        paused.worker_id = 8;
        paused.status = 3;
        let mut orphan = active.clone();
        orphan.worker_id = -1;
        m.allocations = vec![active.clone(), active, paused, orphan];
        m.cached_worker_info = Some(WorkerInfoResponse {
            worker_info: vec![
                WorkerInfo {
                    core_id: 7,
                    ..Default::default()
                },
                WorkerInfo {
                    core_id: 8,
                    manually_managed: true,
                    ..Default::default()
                },
                WorkerInfo {
                    core_id: 9,
                    ..Default::default()
                },
                WorkerInfo {
                    core_id: 7,
                    ..Default::default()
                },
            ],
        });
        assert_eq!(
            worker_counts_line(&m).to_string(),
            "Workers: running 3 | assigned 2 | auto 2 | manual 1"
        );
        assert!(alloc_title(&m, &m.allocations)
            .to_string()
            .contains("Status: active 3 | paused 1"));
        m.alloc_col_filters.insert(
            1,
            ColumnFilter {
                text: "no matching allocation".into(),
                ..Default::default()
            },
        );
        assert!(m.filtered_allocations().is_empty());
        assert!(worker_counts_line(&m)
            .to_string()
            .contains("auto 2 | manual 1"));
        assert!(alloc_title(&m, &m.filtered_allocations())
            .to_string()
            .contains("Status: active 3 | paused 1"));
        assert!(alloc_title(&m, &m.filtered_allocations())
            .to_string()
            .contains("Shown 0/4"));
        m.cached_worker_info = None;
        assert!(worker_counts_line(&m)
            .to_string()
            .contains("auto ? | manual ?"));
        assert!(alloc_title(&m, &[])
            .to_string()
            .contains("Status: active 3 | paused 1"));
    }

    /// Nodes report lifecycle phases; older nodes report `running`. Both
    /// show as themselves, and only a host with no frames warns.
    #[test]
    fn lifecycle_phases_show_and_color_like_running() {
        use quil_types::proto::node::WorkerExecution;
        let m = Model::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let worker = |state: &str, frame: u64| {
            let mut a = row("01", 2, 1, 7, "", "");
            a.execution = Some(WorkerExecution {
                state: state.into(),
                observed_unix_ms: now,
                materialized_frame: Some(frame),
                ..Default::default()
            });
            a
        };
        for (state, label, color) in [
            ("running", "running", SUCCESS),
            ("serving", "serve", SUCCESS),
            ("syncing", "sync", HELP),
            ("closing", "close", HELP),
            ("handoff", "handoff", HELP),
            ("waiting", "wait", HELP),
            ("starting", "start", HELP),
            ("blocked", "blocked", ERROR),
            ("stopped", "stopped", ERROR),
        ] {
            let a = worker(state, 124);
            assert_eq!(alloc_cell(&m, &a, 9, 12), label);
            assert_eq!(local_color(&m, &a), color, "{state}");
            assert!(!local_warning(&m, &a), "{state}");
        }
        for state in ["running", "serving"] {
            let a = worker(state, 0);
            assert!(local_warning(&m, &a), "{state}");
            assert_eq!(local_color(&m, &a), Color::Yellow, "{state}");
        }
        for state in ["syncing", "closing", "handoff", "waiting"] {
            assert!(!local_warning(&m, &worker(state, 0)), "{state}");
        }
    }

    #[test]
    fn warning_markers_keep_rendered_values_aligned_when_colors_toggle() {
        use quil_types::proto::node::WorkerExecution;
        let mut m = Model::new();
        let mut a = row("01", 2, 1, 7, "", "");
        a.execution = Some(WorkerExecution {
            state: "running".into(),
            materialized_frame: Some(0),
            observed_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            ..Default::default()
        });
        a.status_name = "re-confirm!".into();
        let mut normal = a.clone();
        normal.worker_id = 8;
        normal.execution.as_mut().unwrap().state = "blocked".into();
        let allocations = vec![a, normal];
        let mut peer = shard("02", 1, 1);
        peer.materialized_frame = 44;
        peer.latest_frame = 47;
        let available = vec![peer.clone(), peer];
        let cell = |line: &Line<'_>, widths: &[usize], col: usize| -> String {
            let order = if widths.len() == ALLOC_COL_NAMES.len() {
                ALLOC_DISPLAY_COLS
            } else {
                AVAIL_DISPLAY_COLS
            };
            let position = order.iter().position(|&index| index == col).unwrap();
            let before = order[..position]
                .iter()
                .map(|&index| widths[index])
                .sum::<usize>()
                + position;
            line.to_string()
                .chars()
                .skip(before)
                .take(widths[col])
                .collect()
        };
        m.color_coding = false;
        let (aw, _) = alloc_col_widths(&m, 300, &allocations);
        let (vw, _) = avail_col_widths(&m, 300, &available);
        let plain_a = render_alloc_panel(&mut m, &allocations, Rect::new(0, 0, 300, 8), None);
        let plain_v = render_avail_panel(&mut m, &available, Rect::new(0, 0, 300, 8), None);
        assert_eq!(cell(&plain_a[1], &aw, 6).trim(), "0!");
        assert_eq!(cell(&plain_a[2], &aw, 6).trim(), "0");
        assert_eq!(
            cell(&plain_a[1], &aw, 6).find('0'),
            cell(&plain_a[2], &aw, 6).find('0')
        );
        m.color_coding = true;
        assert_eq!(alloc_col_widths(&m, 300, &allocations).0, aw);
        assert_eq!(avail_col_widths(&m, 300, &available).0, vw);
        let colored_a = render_alloc_panel(&mut m, &allocations, Rect::new(0, 0, 300, 8), None);
        let colored_v = render_avail_panel(&mut m, &available, Rect::new(0, 0, 300, 8), None);
        for row in 1..=2 {
            for col in [6, 12] {
                assert_eq!(
                    cell(&plain_a[row], &aw, col).replace('!', " "),
                    cell(&colored_a[row], &aw, col)
                );
            }
            assert_eq!(cell(&plain_v[row], &vw, 9).trim(), "lag!");
            assert_eq!(
                cell(&plain_v[row], &vw, 9).replace('!', " "),
                cell(&colored_v[row], &vw, 9)
            );
        }
        assert_eq!(
            colored_a[1].spans[26].style.fg,
            Some(status_color("re-confirm!"))
        );
        for row in 1..=2 {
            assert_eq!(
                colored_a[row].spans[14].style.fg,
                colored_v[row].spans[14].style.fg
            );
            assert_ne!(
                colored_v[row].spans[12].style.fg,
                colored_v[row].spans[14].style.fg
            );
        }
    }

    #[test]
    fn header_text_decorates_consistently_across_sizing_modes() {
        assert_eq!(header_text("Worker", 7, 7, true, false, false), "↑Worker");
        assert_eq!(header_text("Worker", 7, 7, false, false, false), "↓Worker");
        assert_eq!(header_text("Ring", 3, 7, true, true, false), "Ring*");
        assert_eq!(header_text("Ring", 3, 3, true, true, false), "↑Ring*");
        assert_eq!(header_text("Size [GB]", 4, 4, true, true, true), "↑[GB]*");
        assert_eq!(
            header_text("Reward [~Q/d]", 10, 7, true, false, true),
            "[~Q/d]"
        );
        // Other labels are independent of the unit-name toggle.
        assert_eq!(
            header_text("DefaultAction", 11, 7, true, false, true),
            "DefaultAction"
        );
        assert_eq!(
            header_text("DefaultAction", 11, 7, true, false, false),
            "DefaultAction"
        );
    }

    #[test]
    fn every_column_is_sized_to_its_own_content() {
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false; // Dynamic, sorted ascending on Worker
        let rows = joining_table();
        let (w, fw) = alloc_col_widths(&m, 208, &rows);

        assert_eq!(
            w,
            vec![
                6,  // "Select"
                15, // Filter — what the pane has left
                7,  // "Provers"
                4,  // "Ring"
                9,  // "Size [GB]"
                8,  // "10076371", wider than "Shards"
                9,  // "LocalMat" plus marker position
                8,  // "PeerHead"
                10, // "GlobalHead"
                9,  // "Execution"
                28, // "Reward [~Q/d 60m/24h/theory]"
                7,  // "↑Worker", including the active sort arrow
                17, // "joining(unknown)" plus marker position, wider than "Status"
                4,  // "Mode"
                13, // "(pause|leave)", wider than "NextAction"
                16, // "activate@f699840", wider than "DefaultAction"
                20, // "Interval [s 60m/24h]"
                0,  // "ProverPhases", hidden by default
            ]
        );
        assert_eq!(fw, 15);
        // 17 columns + 16 separators + 2 borders fill the pane exactly.
        assert_eq!(w.iter().sum::<usize>() + 16 + 2, 208);
    }

    #[test]
    fn fixed_sizing_reserves_the_local_and_peer_column_labels() {
        let (w, fw) = alloc_col_widths(&fixed(), 165, &joining_table());
        assert_eq!(
            w,
            vec![6, 12, 7, 5, 10, 8, 9, 8, 10, 9, 28, 8, 12, 4, 26, 18, 20, 0]
        );
        assert_eq!(fw, 12);
        assert_eq!(w.iter().sum::<usize>() + 16, 216);
        // 26 columns of Next Action for a 13-column value in the fixed layout.
        assert_eq!(w[14], NEXT_ACTION_WIDTH);
    }

    #[test]
    fn no_cell_overflows_its_column() {
        let mut expanded = fixed();
        expanded.compact_actions = false;
        expanded.compact_units = false;
        for m in [Model::new(), fixed(), expanded] {
            let rows = joining_table();
            let (w, fw) = alloc_col_widths(&m, 165, &rows);
            // A hidden column takes no width and prints no cell.
            for (c, width) in w
                .iter()
                .enumerate()
                .filter(|(c, _)| m.alloc_column_visible(*c))
            {
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
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        let mut rows = joining_table();
        let (before, before_fw) = alloc_col_widths(&m, 208, &rows);
        rows[3].next_action = ActionHint::text("(reject|confirm)");
        let (after, after_fw) = alloc_col_widths(&m, 208, &rows);

        assert_eq!(before[14], 13);
        assert_eq!(after[14], 16);
        // Filter gives back exactly what Next Action took; the row still fits.
        assert_eq!(before_fw - after_fw, 3);
        assert_eq!(after.iter().sum::<usize>() + 16 + 2, 208);
    }

    #[test]
    fn filter_takes_the_slack_and_gives_it_back_first() {
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        let rows = joining_table();
        // Wide pane: Filter stops at the longest hex rather than padding on.
        assert_eq!(alloc_col_widths(&m, 300, &rows).1, 64);
        assert_eq!(alloc_col_widths(&m, 221, &rows).1, 28);
        // Narrower: Filter absorbs the shortfall…
        assert_eq!(alloc_col_widths(&m, 208, &rows).1, 15);
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
            "↓Reward [~Q/d]",
            15,
            Style::new().add_modifier(Modifier::BOLD),
            true,
            true,
            false,
        );
        assert_eq!(joined(&spans), " ↓Reward [~Q/d]");
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
            .bg(HEADER_BG)
            .fg(TEXT)
            .add_modifier(Modifier::BOLD);
        for left in [false, true] {
            let spans = header_spans("Mode", 8, base, true, false, left);
            assert!(spans.iter().all(|s| s.style.bg == Some(HEADER_BG)));
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

    #[test]
    fn prover_phase_cells_omit_zero_fields_except_active_in_both_modes() {
        use quil_types::proto::node::ShardProverCounts;
        let mut m = Model::new();
        let sample = ShardProverCounts {
            joining: 3,
            activating: 1,
            active: 12,
            paused: 0,
            leaving: 2,
            departing: 1,
        };
        let mut a = row("aa", 19, 1, 1, "", "");
        a.shard_size = BigInt::from(1_000_000u64);
        a.prover_counts = Some(sample.clone());
        let mut s = shard("bb", 1_000_000, 0);
        s.prover_counts = Some(sample);
        assert_eq!(
            alloc_cell(&m, &a, ALLOC_PROVER_PHASES_COL, 0),
            "a12 j3 +1 l2 -1"
        );
        assert_eq!(
            avail_cell(&m, &s, AVAIL_PROVER_PHASES_COL, 0),
            "a12 j3 +1 l2 -1"
        );
        m.compact_actions = false;
        let expanded = "12 active, 3 joining, 1 activating, 2 leaving, 1 departing";
        assert_eq!(alloc_cell(&m, &a, ALLOC_PROVER_PHASES_COL, 0), expanded);
        assert_eq!(avail_cell(&m, &s, AVAIL_PROVER_PHASES_COL, 0), expanded);
        a.prover_counts = Some(ShardProverCounts {
            active: 5,
            paused: 2,
            ..Default::default()
        });
        assert_eq!(
            alloc_cell(&m, &a, ALLOC_PROVER_PHASES_COL, 0),
            "5 active, 2 paused"
        );
        m.compact_actions = true;
        assert_eq!(alloc_cell(&m, &a, ALLOC_PROVER_PHASES_COL, 0), "a5 p2");
        // An empty shard keeps its active field; without data it is no halt risk.
        s.shard_size = BigInt::from(0);
        s.prover_counts = Some(ShardProverCounts::default());
        assert_eq!(avail_cell(&m, &s, AVAIL_PROVER_PHASES_COL, 0), "a0");
        m.compact_actions = false;
        assert_eq!(avail_cell(&m, &s, AVAIL_PROVER_PHASES_COL, 0), "0 active");
        // Unreported counts are unavailable, not zero.
        a.prover_counts = None;
        s.prover_counts = None;
        assert_eq!(alloc_cell(&m, &a, ALLOC_PROVER_PHASES_COL, 0), "-");
        assert_eq!(avail_cell(&m, &s, AVAIL_PROVER_PHASES_COL, 0), "-");
    }

    #[test]
    fn prover_phases_warn_of_halt_risk_by_active_and_activating_count() {
        use quil_types::proto::node::ShardProverCounts;
        let counts = |active, activating, joining| {
            Some(ShardProverCounts {
                active,
                activating,
                joining,
                ..Default::default()
            })
        };
        let size = BigInt::from(1u64);
        assert!(
            prover_halt_risk(counts(2, 1, 9).as_ref(), &size),
            "unconfirmed joins are no coverage"
        );
        assert!(prover_halt_risk(counts(0, 0, 0).as_ref(), &size));
        assert!(
            !prover_halt_risk(counts(3, 1, 0).as_ref(), &size),
            "a confirmed join is coverage"
        );
        assert!(!prover_halt_risk(counts(4, 0, 0).as_ref(), &size));
        assert!(
            !prover_halt_risk(counts(0, 0, 0).as_ref(), &BigInt::from(0)),
            "a shard without data cannot halt"
        );
        assert!(
            !prover_halt_risk(None, &size),
            "unreported counts establish nothing"
        );

        let mut m = Model::new();
        m.hidden_columns.remove(&ALLOC_PROVER_PHASES_COL);
        let mut risky = row("aa", 3, 1, 1, "", "");
        risky.shard_size = size.clone();
        risky.prover_counts = counts(2, 1, 0);
        let mut healthy = row("bb", 4, 1, 2, "", "");
        healthy.shard_size = size.clone();
        healthy.prover_counts = counts(4, 0, 0);
        let mut risky_shard = shard("cc", 1, 0);
        risky_shard.prover_counts = risky.prover_counts.clone();
        let mut healthy_shard = shard("dd", 1, 0);
        healthy_shard.prover_counts = healthy.prover_counts.clone();
        // Colors off: `!` marks the warning; colors on keep its slot blank.
        m.color_coding = false;
        assert_eq!(
            alloc_display_cell(&m, &risky, ALLOC_PROVER_PHASES_COL, 0),
            "a2 +1!"
        );
        assert_eq!(
            alloc_display_cell(&m, &healthy, ALLOC_PROVER_PHASES_COL, 0),
            "a4 "
        );
        assert_eq!(
            avail_display_cell(&m, &risky_shard, AVAIL_PROVER_PHASES_COL, 0),
            "a2 +1!"
        );
        m.color_coding = true;
        assert_eq!(
            alloc_display_cell(&m, &risky, ALLOC_PROVER_PHASES_COL, 0),
            "a2 +1 "
        );
        let fg = |lines: &[Line<'static>], line: usize, text: &str| {
            lines[line]
                .spans
                .iter()
                .find(|span| span.content.trim() == text)
                .unwrap_or_else(|| panic!("no `{text}` cell: {}", lines[line]))
                .style
                .fg
        };
        // Both row renderings: the cursor row and the others.
        for allocations in [
            [risky.clone(), healthy.clone()],
            [healthy.clone(), risky.clone()],
        ] {
            let lines = render_alloc_panel(&mut m, &allocations, Rect::new(0, 0, 300, 6), None);
            let (r, h) = if allocations[0].filter_hex == "aa" {
                (1, 2)
            } else {
                (2, 1)
            };
            assert_eq!(fg(&lines, r, "a2 +1"), Some(WARNING));
            assert_ne!(fg(&lines, h, "a4"), Some(WARNING));
        }
        for available in [
            [risky_shard.clone(), healthy_shard.clone()],
            [healthy_shard.clone(), risky_shard.clone()],
        ] {
            let lines = render_avail_panel(&mut m, &available, Rect::new(0, 0, 300, 6), None);
            let (r, h) = if available[0].filter_hex == "cc" {
                (1, 2)
            } else {
                (2, 1)
            };
            assert_eq!(fg(&lines, r, "a2 +1"), Some(WARNING));
            assert_ne!(fg(&lines, h, "a4"), Some(WARNING));
        }
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
        let sections = help_sections();
        for name in ALLOC_COL_NAMES.iter().chain(AVAIL_COL_NAMES.iter()) {
            let count = sections
                .iter()
                .filter(|(section, key, _)| *section == "Columns" && key == name)
                .count();
            assert_eq!(
                count, 1,
                "column `{name}` needs exactly one entry under Columns"
            );
        }
    }

    /// Each entry with the section it sits in, its key and the values its
    /// items list, so a test can ask where a name and its values appear.
    fn help_sections() -> Vec<(&'static str, String, Vec<String>)> {
        let mut section = "";
        let mut entries: Vec<(&'static str, String, Vec<String>)> = Vec::new();
        for item in help_items() {
            match item {
                HelpItem::Section(s) => section = s,
                HelpItem::Entry(k, _) if !k.is_empty() => {
                    entries.push((section, k.to_string(), vec![]))
                }
                HelpItem::Item(text) => {
                    let values = text.split('`').skip(1).step_by(2).map(str::to_string);
                    entries
                        .last_mut()
                        .expect("an item follows its entry")
                        .2
                        .extend(values);
                }
                _ => {}
            }
        }
        entries
    }

    /// A value is documented under the KPI or column that prints it, never
    /// as an entry of its own: the key column holds keys, KPI and column
    /// names, and a fixed set of topics.
    #[test]
    fn every_value_is_listed_under_the_name_that_prints_it() {
        let sections = help_sections();
        let values = |section: &str, key: &str| {
            sections
                .iter()
                .find(|(s, k, _)| *s == section && k == key)
                .unwrap_or_else(|| panic!("no `{key}` entry under {section}"))
                .2
                .clone()
        };
        let column = values("Columns", "Status");
        for (row, ..) in STATUS_KPI_LABELS {
            assert!(
                column.iter().any(|v| v == row),
                "status `{row}` is not listed under the Status column"
            );
        }
        let kpi = values("Panel header KPIs", "Status");
        for (_, compact, expanded) in STATUS_KPI_LABELS {
            for label in [compact, expanded] {
                assert!(
                    kpi.iter().any(|v| v == label),
                    "Status KPI label `{label}` is not listed under the Status KPI"
                );
            }
        }
        let execution = values("Columns", "Execution");
        for state in EXECUTION_STATES {
            let label = execution_label(state);
            assert!(
                execution
                    .iter()
                    .any(|v| v.split(" / ").any(|v| v == label) || v == label),
                "execution `{label}` is not listed under Execution"
            );
        }
        let peer = values("Columns", "PeerState");
        for state in ["current", "lag", "unmat", "unknown"] {
            assert!(
                peer.iter().any(|v| v == state),
                "peer state `{state}` is not listed under PeerState"
            );
        }
        for value in ["a", "m"] {
            assert!(
                values("Columns", "Mode").iter().any(|v| v == value),
                "mode `{value}` is not listed under Mode"
            );
        }
        let global = values("Top header KPIs", "Global");
        for label in GLOBAL_FIELD_NAMES
            .iter()
            .map(|name| name.trim())
            .chain(["f<frame>", "e<epoch>", "next Nf"])
        {
            assert!(
                global.iter().any(|v| v == label),
                "Global field `{label}` is not listed under the Global KPI"
            );
        }
        let kpis = [
            "Peer ID",
            "Strategy",
            "Seniority",
            "Global",
            "Global interval",
            "World size",
            "RPC",
            "Workers",
            "Status",
            "Claimable",
            "Reward",
            "Snapshot",
            "Shown",
            "Selected",
            "Count",
            "Level",
            "Line",
        ];
        let topics = [
            "KPI separators",
            "Details",
            "Recovery footer",
            "Freshness",
            "Local app notice",
            "Reported app heads",
            "Global notice",
            "Global app notice",
            "Reward notice",
            "Allocation notices",
            "Command legends",
            "Scroll hints",
            "Colors",
            "Frame windows",
            "Frame intervals",
            "Reward estimates",
            "Global citation",
            "Columns group",
            "Cursor",
            "Boundaries",
            "Typing",
        ];
        for (section, key, _) in &sections {
            let named = key.starts_with('‹')
                || kpis.contains(&key.as_str())
                || topics.contains(&key.as_str())
                || ALLOC_COL_NAMES.contains(&key.as_str())
                || AVAIL_COL_NAMES.contains(&key.as_str());
            assert!(
                named,
                "`{key}` under {section} is neither a key, a KPI, a column nor a known topic"
            );
        }
    }

    /// The documented keys: the left-hand column of every `kv` line. Matching
    /// on the whole text would pass on any single letter appearing anywhere in
    /// a sentence, which is how `d` and `x` went undocumented while a naive
    /// `contains` said otherwise.
    fn documented_keys() -> Vec<String> {
        help_items()
            .into_iter()
            .filter_map(|item| match item {
                HelpItem::Entry(key, _) => Some(key),
                _ => None,
            })
            .flat_map(|key| {
                let keys: Vec<String> = key
                    .split('‹')
                    .skip(1)
                    .filter_map(|k| k.split_once('›'))
                    .map(|(k, _)| k.to_string())
                    .collect();
                if keys.is_empty() {
                    vec![key.trim().to_string()]
                } else {
                    keys
                }
            })
            .collect()
    }

    /// Listed by hand against `handle_normal_key` and its mode handlers: a
    /// binding that exists and is undocumented is exactly what this should
    /// force someone to reconcile.
    #[test]
    fn every_key_has_a_help_entry() {
        let keys = documented_keys();
        for key in [
            "Ctrl+L",
            "Ctrl+Y",
            "Ctrl+R",
            "Ctrl+P",
            "Ctrl+U",
            "Ctrl+O",
            "Ctrl+G",
            "s",
            "f",
            "c",
            "e",
            "h",
            "a",
            "x",
            "d",
            "tab",
            "space",
            "enter",
            "esc",
            "q",
            "Ctrl+C",
            "t",
            "b",
            "n",
            "v",
            "↑/k",
            "↓/j",
            "←/→",
            "[/]",
            "{/}",
            "Pg↑/↓",
        ] {
            assert!(
                keys.iter().any(|k| k == key),
                "key `{key}` has no help entry"
            );
        }
    }

    /// Header KPIs print labels of their own (`Shown 3/9`, `Level: …`,
    /// `Status: join 1`); each needs an entry, not just its picker name.
    #[test]
    fn every_header_kpi_value_has_a_help_entry() {
        let keys = documented_keys();
        for key in [
            "Peer ID",
            "Strategy",
            "Seniority",
            "Global",
            "Global interval",
            "World size",
            "RPC",
            "Workers",
            "Status",
            "Claimable",
            "Reward",
            "Shown",
            "Selected",
            "Count",
            "Snapshot",
            "Level",
            "Line",
        ] {
            assert!(
                keys.iter().any(|k| k == key),
                "KPI `{key}` has no help entry"
            );
        }
        let text = help_text();
        for (_, compact, expanded) in STATUS_KPI_LABELS {
            for label in [compact, expanded] {
                assert!(
                    text.contains(label),
                    "Status label `{label}` has no help description"
                );
            }
        }
    }

    /// Every word of the help must reach a narrow terminal: lines wrap under
    /// their own column instead of running past the right edge.
    #[test]
    fn help_wraps_to_narrow_terminals_without_losing_text() {
        use ratatui::{backend::TestBackend, Terminal};
        let words = |text: &str| {
            text.split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        let expected = words(&help_text());
        for width in [40u16, 60, 80, 120] {
            let mut m = Model::new();
            m.show_help = true;
            // Tall enough for the whole help; ratatui caps an area at u16::MAX cells.
            let mut terminal = Terminal::new(TestBackend::new(width, u16::MAX / width)).unwrap();
            terminal.draw(|f| draw(f, &mut m)).unwrap();
            let buffer = terminal.backend().buffer();
            let screen = (1..1 + m.help_visible as u16)
                .map(|y| {
                    (0..width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(words(&screen), expected, "help text lost at width {width}");
            assert!(
                !screen.contains('`'),
                "value markers reached the screen at width {width}"
            );
        }
    }

    /// Values the TUI prints stand out from their description, with or
    /// without colors.
    #[test]
    fn help_values_take_the_key_style() {
        let line = HelpItem::Entry("LocalMat", "Local height; `-` unknown; `0!` warns")
            .line("LocalMat", true);
        let styled: Vec<_> = line
            .spans
            .iter()
            .map(|span| (span.content.as_ref(), span.style))
            .collect();
        assert_eq!(styled[1], ("LocalMat", HelpItem::key_style()));
        assert_eq!(styled[4], ("-", HelpItem::key_style()));
        assert_eq!(styled[6], ("0!", HelpItem::key_style()));
        assert_eq!(styled[5], (" unknown; ", Style::new().fg(HELP)));
        let keys = HelpItem::Entry("‹b›", "‹space› toggles").line("‹b›", true);
        let styled: Vec<_> = keys
            .spans
            .iter()
            .map(|span| (span.content.as_ref(), span.style))
            .collect();
        assert_eq!(
            styled[1],
            ("‹b›", HelpItem::key_style()),
            "keys keep their legend brackets"
        );
        assert_eq!(styled[3], ("‹space›", HelpItem::key_style()));
        assert_eq!(styled[4], (" toggles", Style::new().fg(HELP)));
        assert!(HelpItem::key_style().add_modifier.contains(Modifier::BOLD));
    }

    /// A value the help quotes takes the color the main view gives it, and
    /// only while colors are on; header labels and keys stay plain.
    #[test]
    fn help_values_keep_their_main_view_colors() {
        let spans = |colors: bool| {
            help_entries()
                .into_iter()
                .flat_map(|(item, entry)| {
                    item.line(entry, colors)
                        .spans
                        .into_iter()
                        .map(move |span| (entry, span.content.trim().to_string(), span.style.fg))
                })
                .collect::<Vec<_>>()
        };
        let cases = [
            ("Status", "re-confirm!", status_color("re-confirm!")),
            ("", "active", TEXT),
            ("Status", "bound", WARNING),
            ("Execution", "serve", SUCCESS),
            ("Execution", "blocked", ERROR),
            ("Execution", "sync", HELP),
            ("PeerState", "lag", WARNING),
            ("Worker", "-1", ERROR),
            ("Mode", "m", PRIMARY),
            ("Mode", "‹Ctrl+O›", TEXT),
            ("Colors", "green", SUCCESS),
            ("Colors", "red", ERROR),
            ("‹b›", "‹a›", TEXT),
        ];
        for colors in [true, false] {
            let spans = spans(colors);
            for (entry, value, color) in cases {
                let found = spans
                    .iter()
                    .find(|(e, v, _)| *e == entry && v == value)
                    .unwrap_or_else(|| panic!("`{value}` is not quoted under {entry}"));
                assert_eq!(
                    found.2,
                    Some(if colors { color } else { TEXT }),
                    "`{value}` under {entry}, colors {colors}"
                );
            }
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
        m.reward_windows = 4;
        m.available = vec![shard("low", 0, 800_000), shard("high", 0, 880_000)];
        // Rounded display preserves tenths, but sorting retains the underlying precision.
        assert_eq!(fmt_reward(&m.available[0].estimated_reward), "0.9");
        assert_eq!(fmt_reward(&m.available[1].estimated_reward), "1.0");
        let sorted = m.sorted_available();
        assert_eq!(sorted[0].filter_key, "high");
        m.avail_col_filters.insert(
            10,
            ColumnFilter {
                expr: ">0.9".into(),
                ..Default::default()
            },
        );
        let filtered = m.filtered_available();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].filter_key, "high");
        let mut allocation = joining_table().remove(0);
        allocation.estimated_reward = BigInt::from(880_000);
        assert!((alloc_row_numeric_val(&m, &allocation, 10) - 0.9504).abs() < 1e-10);
    }

    #[test]
    fn help_close_commands_stay_at_bottom_before_and_after_scrolling() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        use ratatui::{backend::TestBackend, Terminal};
        let mut m = Model::new();
        m.show_help = true;
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|f| draw(f, &mut m)).unwrap();
        let bottom = |buffer: &ratatui::buffer::Buffer| {
            (0..100)
                .map(|x| buffer[(x, 23)].symbol())
                .collect::<String>()
        };
        let before = bottom(terminal.backend().buffer());
        let separator = |buffer: &ratatui::buffer::Buffer| {
            (0..100)
                .map(|x| buffer[(x, 22)].symbol())
                .collect::<String>()
        };
        assert_eq!(separator(terminal.backend().buffer()), "─".repeat(100));
        assert_eq!(m.help_visible, 21);
        assert!(before.contains("‹h/esc› close"));
        super::super::update::handle_key(&mut m, KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        terminal.draw(|f| draw(f, &mut m)).unwrap();
        assert_eq!(bottom(terminal.backend().buffer()), before);
        assert_eq!(separator(terminal.backend().buffer()), "─".repeat(100));
        assert_eq!(m.help_offset + m.help_visible, m.help_lines);
    }

    #[test]
    fn threshold_toggle_and_help_scroll_work_through_the_ui() {
        use super::super::update::handle_key;
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        use ratatui::{backend::TestBackend, Terminal};

        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        m.epoch_length = 720;
        m.allocations = joining_table();
        m.allocations[0].next_action = ActionHint::at("(reject|confirm)", 2_160);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        m.last_received_frame = 1_500;
        assert_eq!(
            alloc_cell(&m, &m.allocations[0], 14, 0),
            "(reject|confirm) in 660f"
        );
        assert!(help_line(&m).to_string().contains("thresholds relative"));
        assert!(handle_key(&mut m, key(KeyCode::Char('e'))).is_empty());
        assert_eq!(
            alloc_cell(&m, &m.allocations[0], 14, 0),
            "(reject|confirm)@f2160"
        );
        assert!(help_line(&m).to_string().contains("thresholds absolute"));
        assert!(handle_key(&mut m, key(KeyCode::Char('e'))).is_empty());
        assert_eq!(
            alloc_cell(&m, &m.allocations[0], 14, 0),
            "(reject|confirm) in 660f"
        );

        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        assert!(handle_key(&mut m, key(KeyCode::Char('h'))).is_empty());
        terminal.draw(|f| draw(f, &mut m)).unwrap();
        assert!(m.help_lines > m.height as usize);
        let text = |buffer: &ratatui::buffer::Buffer| {
            buffer
                .content()
                .iter()
                .map(|cell| cell.symbol())
                .collect::<String>()
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

#[cfg(test)]
mod compact_action_tests {
    use super::super::super::epoch::{ActionHint, ThresholdUnit};
    use super::*;
    #[test]
    fn display_toggle_preserves_visibility_and_expands_identity_and_strategy() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut m = Model::new();
        m.data_loaded = true;
        m.peer_id = "abcdefgh12345678".into();
        m.last_fetch_success = Some(std::time::Instant::now());
        m.cached_shard_info = Some(quil_types::proto::node::GetShardInfoResponse {
            allocation_scoring_strategy: "reward-greedy".into(),
            ..Default::default()
        });
        let compact = header_line(&m).to_string();
        assert!(compact.contains("Peer: …12345678") && compact.contains("RPC: ✓"));
        assert!(!compact.contains("abcdefgh"));
        m.hidden_header_kpis.insert("Seniority".into());
        super::super::update::handle_key(
            &mut m,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        );
        let expanded = header_line(&m).to_string();
        assert!(
            expanded.contains("Peer ID: abcdefgh12345678") && expanded.contains("RPC: connected")
        );
        assert!(expanded.contains("Strategy: Halt risk, then reward"));
        assert!(!expanded.contains("Seniority:") && !m.compact_units);
        for name in ALLOC_KPI_NAMES {
            m.hidden_header_kpis.insert((*name).into());
        }
        for name in AVAIL_KPI_NAMES {
            m.hidden_header_kpis.insert((*name).into());
        }
        assert_eq!(alloc_title(&m, &[]).to_string().trim(), "Allocations");
        assert_eq!(avail_title(&m, &[]).to_string().trim(), "Available Shards");
    }

    #[test]
    fn expanded_identity_wraps_without_losing_characters_and_hidden_header_reclaims_space() {
        let mut m = Model::new();
        m.data_loaded = true;
        m.compact_actions = false;
        m.peer_id = "1234567890".repeat(6);
        let lines = header_lines(&m, 40);
        assert!(lines.iter().all(|line| line.width() <= 40));
        let text = lines.iter().map(ToString::to_string).collect::<String>();
        assert!(text.contains(&m.peer_id));
        for name in TOP_KPI_NAMES {
            m.hidden_header_kpis.insert((*name).into());
        }
        assert!(header_lines(&m, 40).is_empty());
    }

    #[test]
    fn compact_snapshot_heading_preserves_offsets_and_missing_evidence() {
        let mut m = Model::new();
        m.last_received_frame = 1002;
        let head = quil_types::proto::node::GlobalAppFrameHead {
            global_frame: 1000,
            frame: 50,
            generation: 3,
        };
        let mut a = super::tests::row("01", 1, 1, 7, "", "");
        a.global_head = Some(head.clone());
        m.allocations = vec![a.clone()];
        assert_eq!(alloc_header(&m, 8), "Global@-2f");
        m.last_received_frame = 1000;
        assert_eq!(alloc_header(&m, 8), "Global");
        m.last_received_frame = 1002;
        assert!(!alloc_title(&m, &m.allocations)
            .to_string()
            .contains("Snapshot"));
        assert_eq!(
            snapshot_suffix(&m, [Some(&head), None].into_iter()),
            " @partial"
        );
        let newer = quil_types::proto::node::GlobalAppFrameHead {
            global_frame: 1001,
            ..head.clone()
        };
        assert_eq!(
            snapshot_suffix(&m, [Some(&head), Some(&newer)].into_iter()),
            " @mixed"
        );
        let (widths, _) = alloc_col_widths(&m, 180, &m.allocations);
        assert!(widths[8] >= printed_width(&alloc_header(&m, 8)));
        m.hidden_header_kpis
            .insert("Allocation GLOBAL snapshot".into());
        assert!(!alloc_header(&m, 8).contains('@'));
    }

    #[test]
    fn compact_global_units_and_frame_offsets_keep_distinct_citations() {
        let mut m = Model::new();
        m.data_loaded = true;
        m.last_received_frame = 1442;
        m.epoch_length = 720;
        assert!(header_line(&m)
            .to_string()
            .contains("Global: f1442 | e2 | next 718f ·"));
        m.threshold_unit = ThresholdUnit::Absolute;
        assert!(
            header_line(&m)
                .to_string()
                .contains("Global: f1442 | e2 | next 718f ·"),
            "‹e› leaves the Global KPI alone"
        );
        assert_eq!(frame_citation(&m, 1440), " @-2f");
        assert_eq!(frame_citation(&m, 1442), "");
        assert_eq!(frame_citation(&m, 1443), " @+1f");
        m.claimable_reward = Some((8_000_000_000, 1440));
        assert!(alloc_title(&m, &[]).to_string().contains("[Q] 1 @-2f"));
        m.compact_actions = false;
        assert!(header_line(&m)
            .to_string()
            .contains("Global: frame 1442 | epoch 2 | next boundary in 718 frames ·"));
        assert_eq!(frame_citation(&m, 1440), " @f1440");
        for line in [help_line(&m), worker_commands_line(&m)] {
            assert!(line.spans[0].style.add_modifier.contains(Modifier::BOLD));
        }
    }

    #[test]
    fn compact_kpis_omit_zero_breakdown_but_keep_unknown_and_nonzero_values() {
        use quil_types::proto::node::{WorkerInfo, WorkerInfoResponse};
        let mut m = Model::new();
        m.running_workers = 1;
        m.cached_worker_info = Some(WorkerInfoResponse {
            worker_info: vec![WorkerInfo::default()],
        });
        assert_eq!(
            worker_counts_line(&m).to_string(),
            "Workers: run 1 | assigned 0"
        );
        m.cached_worker_info = None;
        assert!(worker_counts_line(&m)
            .to_string()
            .contains("assigned 0 | manual ?"));
        let mut a = super::tests::row("01", 1, 1, 1, "", "");
        a.status = 2;
        a.estimated_reward = BigInt::from(8_000_000_000u64);
        let title = alloc_title(&m, &[a.clone()]).to_string();
        assert!(title.contains("[Q] loading") && title.contains("[~Q/d 60m/24h/T]"));
        assert!(!title.contains("Claimable") && !title.contains("Reward"));
        assert!(!title.contains("paused") && !title.contains("Δ") && !title.contains("] now "));
        a.status = 3;
        let paused = alloc_title(&m, &[a.clone()]).to_string();
        assert!(paused.contains("] now 0.0/0.0/0.0 | paused ") && !paused.contains("Δ"));
        a.ring = UNKNOWN_REWARD_RING;
        assert!(alloc_title(&m, &[a])
            .to_string()
            .contains("now 0.0/0.0/0.0 | paused -/-/-"));
        m.compact_actions = false;
        m.compact_units = false;
        assert!(alloc_title(&m, &[])
            .to_string()
            .contains("paused 0.0/0.0/0.0 | delta 0.0/0.0/0.0"));
    }

    #[test]
    fn recovery_footer_wraps_and_keeps_room_for_table_rows() {
        let mut m = Model::new();
        let mut a = super::tests::row("01", 1, 1, 1, "", "");
        a.execution = Some(quil_types::proto::node::WorkerExecution {
            blocker: "waiting for archive recovery".into(),
            recovery: Some(quil_types::proto::node::ShardRecovery {
                phase: "installing_leaves".into(),
                source: "192.0.2.1:8340".into(),
                planned_leaves: 100,
                installed_leaves: 20,
                ..Default::default()
            }),
            ..Default::default()
        });
        let compact = allocation_detail(&m, &a).to_string();
        assert!(compact.contains("Recovery: installing_leaves (unobserved)"));
        assert!(!compact.contains("192.0.2.1") && !compact.contains("leaves 20/100"));
        for height in [3, 6, 20] {
            let lines = allocation_detail_lines(&m, &[a.clone()], Rect::new(0, 0, 40, height));
            assert!(lines.len() <= usize::from(height - 2));
            assert!(lines.iter().all(|l| l.width() <= 40));
            if height == 20 {
                assert!(lines.len() > 1);
            }
        }
        m.compact_actions = false;
        m.compact_units = false;
        let expanded = allocation_detail(&m, &a).to_string();
        assert!(expanded.contains("192.0.2.1:8340") && expanded.contains("leaves 20/100"));
    }
    #[test]
    fn unit_only_headers_reclaim_width_in_both_panels_and_sizing_modes() {
        let allocations = [super::tests::row("01", 1, 1, 1, "", "")];
        let available = [super::tests::shard("01", 1, 1)];
        let mut m = Model::new();
        for sizing in [ColumnSizing::Dynamic, ColumnSizing::Fixed] {
            m.column_sizing = sizing;
            m.compact_units = false;
            let (alloc_before, _) = alloc_col_widths(&m, 100, &allocations);
            let (avail_before, _) = avail_col_widths(&m, 100, &available);
            m.compact_units = true;
            let (alloc_after, _) = alloc_col_widths(&m, 100, &allocations);
            let (avail_after, _) = avail_col_widths(&m, 100, &available);
            for col in [4, 10] {
                assert!(alloc_after[col] < alloc_before[col]);
                assert!(avail_after[col] < avail_before[col]);
            }
        }
    }

    #[test]
    fn reasons_actions_and_units_share_one_display_toggle() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut m = Model::new();
        let mut a = super::tests::row("aa", 1, 1, 7, "", "");
        let key = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
        for status in ["joining", "leaving"] {
            a.status_name = status.into();
            for (symbol, name) in [
                ("$", "reward"),
                ("H", "halt risk"),
                ("S", "split"),
                ("G", "merge"),
                ("T", "retired"),
                ("E", "empty"),
                ("C", "capacity"),
                ("O", "orphan"),
                ("M", "manual"),
                ("D", "data"),
                ("W", "worker shortage"),
            ] {
                a.allocation_reason = Some(symbol.into());
                assert_eq!(
                    allocation_status_text(&m, &a),
                    format!("{status}({symbol})")
                );
                super::super::update::handle_key(&mut m, key('n'));
                assert_eq!(allocation_status_text(&m, &a), format!("{status}({name})"));
                super::super::update::handle_key(&mut m, key('n'));
            }
        }
        a.allocation_reason = None;
        assert_eq!(allocation_status_text(&m, &a), "leaving(?)");
        assert!(m.compact_units && m.compact_actions);
        super::super::update::handle_key(&mut m, key('n'));
        assert!(!m.compact_units && !m.compact_actions);
        assert_eq!(allocation_status_text(&m, &a), "leaving(unknown)");
        a.status_name = "active".into();
        assert_eq!(allocation_status_text(&m, &a), "active");
        super::super::update::handle_key(&mut m, key('n'));
        assert!(m.compact_units && m.compact_actions);
        assert_eq!(
            header_text("Size [GB]", 4, 7, true, false, m.compact_units),
            "[GB]"
        );
    }

    #[test]
    fn shortcut_labels_preserve_thresholds_and_automatic_actions() {
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        m.threshold_unit = ThresholdUnit::Absolute;
        let hint = ActionHint::at("(reject|confirm)", 123);
        assert_eq!(next_action_text(&m, &hint), "(reject|confirm)@f123");
        m.compact_actions = true;
        assert_eq!(next_action_text(&m, &hint), "(R|Y)@f123");
        assert_eq!(
            next_action_text(&m, &ActionHint::text("(pause|leave)")),
            "(P|L)"
        );
        assert_eq!(
            next_action_text(&m, &ActionHint::at("renew", 123)),
            "renew@f123"
        );
        assert_eq!(hint.label, "(reject|confirm)");
    }

    /// A fresh GLOBAL cadence whose 60m window measures 3600s over 191 frames
    /// (~18.8s/frame), so 512 frames estimate ~2h41m.
    fn global_cadence(
        hour: Option<(u64, u64)>,
        day: Option<(u64, u64)>,
        age: u64,
    ) -> quil_types::proto::node::FrameCadence {
        use quil_types::proto::node::{FrameCadence, FrameWindow};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let window = |seconds, (observed_seconds, advanced_frames)| FrameWindow {
            window_seconds: seconds,
            observed_seconds,
            advanced_frames,
        };
        FrameCadence {
            last_observed_unix_seconds: now - age,
            hour: hour.map(|w| window(3600, w)),
            day: day.map(|w| window(86400, w)),
        }
    }

    /// 21:11 UTC on the second UNIX day; 2h41m later is 23:52.
    const CLOCK: u64 = 86_400 + 21 * 3600 + 11 * 60;

    #[test]
    fn global_kpi_reads_frame_epoch_and_next_boundary() {
        let mut m = Model::new();
        m.data_loaded = true;
        m.epoch_length = 720;
        assert_eq!(global_kpi_at(&m, CLOCK), "Global: -");
        m.last_received_frame = 896_608; // epoch 1245 spans 896400..897120
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: f896608 | e1245 | next 512f"
        );
        m.compact_actions = false;
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: frame 896608 | epoch 1245 | next boundary in 512 frames"
        );
        m.node_global_cadence = Some(global_cadence(Some((3600, 191)), Some((86_400, 8_640)), 0));
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: frame 896608 | epoch 1245 | next boundary in 512 frames, ~2h41m (~23:52 UTC)"
        );
        m.compact_actions = true;
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: f896608 | e1245 | next 512f ~2h41m"
        );
        assert!(header_line(&m)
            .to_string()
            .contains("Global: f896608 | e1245 | next 512f ~2h41m ·"));
        // Without 60m advances the 24h window (10s/frame) estimates instead.
        m.node_global_cadence = Some(global_cadence(Some((3600, 0)), Some((7_200, 720)), 0));
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: f896608 | e1245 | next 512f ~1h25m"
        );
        // A stale or missing measurement shows frames only, never a guessed time.
        m.node_global_cadence = Some(global_cadence(
            Some((3600, 191)),
            Some((86_400, 8_640)),
            600,
        ));
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: f896608 | e1245 | next 512f"
        );
        m.node_global_cadence = None;
        m.compact_actions = false;
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: frame 896608 | epoch 1245 | next boundary in 512 frames"
        );
    }

    /// From an epoch's first frame a whole epoch remains; from its last, one
    /// frame.
    #[test]
    fn global_kpi_next_boundary_at_an_epochs_first_and_last_frame() {
        let mut m = Model::new();
        m.data_loaded = true;
        m.epoch_length = 720;
        m.node_global_cadence = Some(global_cadence(Some((3600, 360)), None, 0)); // 10s/frame
        m.last_received_frame = 896_400;
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: f896400 | e1245 | next 720f ~2h00m"
        );
        m.last_received_frame = 897_119;
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: f897119 | e1245 | next 1f ~<1m"
        );
        m.last_received_frame = 897_120;
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: f897120 | e1246 | next 720f ~2h00m"
        );
    }

    /// Fields deselected under ‹b› → Top header drop out of the KPI; the
    /// remaining ones keep their order and separators.
    #[test]
    fn global_kpi_fields_follow_the_picker() {
        use super::super::update::handle_key;
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let mut m = Model::new();
        m.data_loaded = true;
        m.epoch_length = 720;
        m.last_received_frame = 896_608;
        m.node_global_cadence = Some(global_cadence(Some((3600, 191)), None, 0));
        handle_key(&mut m, key(KeyCode::Char('b')));
        assert!(m.column_picker_active);
        handle_key(&mut m, key(KeyCode::Tab));
        assert_eq!(m.visibility_section, 1);
        let row = |name: &str| {
            m.visibility_names()
                .iter()
                .position(|n| n.trim() == name)
                .unwrap()
        };
        let (frame, epoch, next) = (row("frame"), row("epoch"), row("next boundary"));
        m.column_picker_cursor = frame;
        handle_key(&mut m, key(KeyCode::Char(' ')));
        assert_eq!(global_kpi_at(&m, CLOCK), "Global: e1245 | next 512f ~2h41m");
        m.column_picker_cursor = next;
        handle_key(&mut m, key(KeyCode::Char(' ')));
        assert_eq!(global_kpi_at(&m, CLOCK), "Global: e1245");
        m.column_picker_cursor = epoch;
        handle_key(&mut m, key(KeyCode::Char(' ')));
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: e1245",
            "the last field stays"
        );
        m.column_picker_cursor = next;
        handle_key(&mut m, key(KeyCode::Char(' ')));
        m.column_picker_cursor = epoch;
        handle_key(&mut m, key(KeyCode::Char(' ')));
        m.compact_actions = false;
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: next boundary in 512 frames, ~2h41m (~23:52 UTC)"
        );
        handle_key(&mut m, key(KeyCode::Char('a')));
        assert_eq!(
            global_kpi_at(&m, CLOCK),
            "Global: frame 896608 | epoch 1245 | next boundary in 512 frames, ~2h41m (~23:52 UTC)"
        );
    }

    /// Relative thresholds count down from the received frame; expanded mode
    /// adds the estimate from the measured GLOBAL interval.
    #[test]
    fn expanded_relative_thresholds_add_the_global_estimate() {
        let mut m = Model::new();
        m.epoch_length = 720;
        m.last_received_frame = 896_608;
        let mut a = super::tests::row("aabb", 1, 1, 1, "", "");
        a.next_action = ActionHint::at("(reject|confirm)", 897_120);
        a.default_action = ActionHint::at("expire", 897_840);
        assert_eq!(alloc_cell(&m, &a, 14, 0), "(R|Y) in 512f");
        assert_eq!(alloc_cell(&m, &a, 15, 0), "expire in 1232f");
        m.node_global_cadence = Some(global_cadence(Some((3600, 191)), None, 0));
        assert_eq!(
            alloc_cell(&m, &a, 14, 0),
            "(R|Y) in 512f",
            "compact mode shows frames only"
        );
        m.compact_actions = false;
        m.compact_units = false;
        assert_eq!(
            alloc_cell(&m, &a, 14, 0),
            "(reject|confirm) in 512f (~2h41m)"
        );
        assert_eq!(alloc_cell(&m, &a, 15, 0), "expire in 1232f (~6h27m)");
        m.threshold_unit = ThresholdUnit::Absolute;
        assert_eq!(alloc_cell(&m, &a, 15, 0), "expire@f897840");
        m.threshold_unit = ThresholdUnit::Relative;
        m.node_global_cadence = None;
        assert_eq!(alloc_cell(&m, &a, 15, 0), "expire in 1232f");
        m.last_received_frame = 897_120;
        assert_eq!(alloc_cell(&m, &a, 14, 0), "(reject|confirm) now");
        // The fixed layout grows the action columns to the estimate.
        m.last_received_frame = 896_608;
        m.column_sizing = ColumnSizing::Fixed;
        m.node_global_cadence = Some(global_cadence(Some((3600, 191)), None, 0));
        let (w, _) = alloc_col_widths(&m, 260, &[a.clone()]);
        assert!(
            w[14] >= printed_width(&alloc_cell(&m, &a, 14, 0))
                && w[15] >= printed_width(&alloc_cell(&m, &a, 15, 0))
        );
    }
    #[test]
    fn reward_windows_share_order_and_sum_each_allocations_own_cadence() {
        use quil_types::proto::node::{FrameCadence, FrameWindow};
        let mut m = Model::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut a = super::tests::row("aabb", 100, 5, 7, "", "");
        a.status = 2;
        a.epoch = m.current_epoch;
        a.estimated_reward = BigInt::from(8_000_000_000u64);
        let c = FrameCadence {
            last_observed_unix_seconds: now,
            hour: Some(FrameWindow {
                window_seconds: 3600,
                observed_seconds: 120,
                advanced_frames: 6,
            }),
            day: Some(FrameWindow {
                window_seconds: 86400,
                observed_seconds: 120,
                advanced_frames: 3,
            }),
        };
        m.node_app_cadence.insert(a.filter.clone(), c);
        assert_eq!(
            reward_cell(&m, &a.estimated_reward, &a.filter),
            "4320.0/2160.0/8640.0"
        );
        assert_eq!(reward_total(&m, &[a.clone()], 0), "4320.0/2160.0/8640.0");
        let mut b = a.clone();
        b.filter = vec![2];
        b.estimated_reward *= 2;
        let mut other = m.node_app_cadence[&a.filter].clone();
        other.hour.as_mut().unwrap().advanced_frames = 3;
        other.day.as_mut().unwrap().advanced_frames = 0;
        m.node_app_cadence.insert(b.filter.clone(), other);
        assert_eq!(
            reward_total(&m, &[a.clone(), b.clone()], 0),
            "8640.0/2160.0/25920.0"
        );
        b.worker_id = -1;
        assert_eq!(reward_total(&m, &[a.clone(), b], 0), "4320.0/2160.0/8640.0");
        m.reward_windows = 3;
        assert_eq!(m.reward_labels(), "60m/24h");
        assert_eq!(
            reward_cell(&m, &a.estimated_reward, &a.filter),
            "4320.0/2160.0"
        );
        m.reward_windows = 2;
        assert_eq!(reward_cell(&m, &a.estimated_reward, &a.filter), "2160.0");
        m.node_app_cadence.clear();
        assert_eq!(reward_cell(&m, &a.estimated_reward, &a.filter), "-");
    }
}

#[cfg(test)]
mod visibility_grid_tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{backend::TestBackend, Terminal};
    fn screen(
        terminal: &mut Terminal<TestBackend>,
        m: &mut Model,
        width: u16,
        height: u16,
    ) -> String {
        terminal.draw(|f| draw(f, m)).unwrap();
        let b = terminal.backend().buffer();
        (0..height)
            .map(|y| (0..width).map(|x| b[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }
    #[test]
    fn all_visibility_groups_and_settings_remain_visible_when_tab_changes_focus() {
        let mut m = Model::new();
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        super::super::update::handle_key(&mut m, key(KeyCode::Char('b')));
        let mut terminal = Terminal::new(TestBackend::new(100, 44)).unwrap();
        for section in 0..5 {
            assert_eq!(m.visibility_section, section);
            let text = screen(&mut terminal, &mut m, 100, 44);
            for title in [
                "Columns",
                "Top header",
                "Allocations header",
                "Available header",
                "Notifications header",
            ] {
                assert!(text.contains(title), "missing {title}: {text}");
            }
            for group in 0..5 {
                for name in m.visibility_names_for(group) {
                    assert!(text.contains(name.trim_start()), "missing {name}: {text}");
                }
            }
            let mask = m.reward_mask();
            super::super::update::handle_key(&mut m, key(KeyCode::Tab));
            assert_eq!(m.reward_mask(), mask);
        }
        assert_eq!(m.visibility_section, 0);
        super::super::update::handle_key(&mut m, key(KeyCode::BackTab));
        assert_eq!(m.visibility_section, 4);
    }
    #[test]
    fn compact_headers_carry_units_and_the_forecast_marker_without_value_noise() {
        let mut m = Model::new();
        m.reward_windows = 4;
        let mut row = super::tests::row("01", 1, 1, 1, "", "");
        row.status = 2;
        row.estimated_reward = BigInt::from(8_000_000_000u64);
        assert_eq!(alloc_header(&m, 16), "[s 60m/24h]");
        assert_eq!(alloc_header(&m, 10), "[~Q/d T]");
        m.compact_units = false;
        assert_eq!(alloc_header(&m, 10), "Reward [~Q/d theory]");
        m.compact_units = true;
        assert_eq!(
            reward_cell(&m, &row.estimated_reward, &row.filter),
            "8640.0"
        );
        let title = alloc_title(&m, &[row]).to_string();
        assert!(title.contains("[~Q/d T] 8640.0"), "{title}");
        assert!(!title.contains("~8640"));
        assert_eq!(fmt_forecast(&BigInt::from(1)), "<0.1");
        assert_eq!(fmt_forecast(&BigInt::from(-8_000_000_000i64)), "-1.0");
    }
    #[test]
    fn interval_visibility_controls_global_and_shard_headers_cells_and_numeric_values() {
        use super::super::model::{alloc_row_numeric_val, avail_row_numeric_val};
        use quil_types::proto::node::{FrameCadence, FrameWindow};
        let mut m = Model::new();
        m.data_loaded = true;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cadence = FrameCadence {
            last_observed_unix_seconds: now,
            hour: Some(FrameWindow {
                window_seconds: 3600,
                observed_seconds: 600,
                advanced_frames: 30,
            }),
            day: Some(FrameWindow {
                window_seconds: 86400,
                observed_seconds: 1200,
                advanced_frames: 30,
            }),
        };
        m.node_global_cadence = Some(cadence.clone());
        m.node_app_cadence.insert(vec![1], cadence.clone());
        let mut row = super::tests::row("01", 1, 1, 1, "", "");
        row.filter = vec![1];
        let mut available = super::tests::shard("01", 1, 0);
        available.filter = vec![1];
        for (mask, label, value, first) in [
            (3, "60m/24h", "20.0/40.0", 20.0),
            (1, "60m", "20.0", 20.0),
            (2, "24h", "40.0", 40.0),
        ] {
            m.interval_windows = mask;
            m.global_interval_windows = mask;
            assert!(alloc_header(&m, 16).contains(label));
            assert!(avail_header(&m, 11).contains(label));
            assert_eq!(alloc_cell(&m, &row, 16, 24), value);
            assert_eq!(avail_cell(&m, &available, 11, 24), value);
            assert_eq!(alloc_row_numeric_val(&m, &row, 16), first);
            assert_eq!(avail_row_numeric_val(&m, &available, 11), first);
            for compact in [true, false] {
                m.compact_actions = compact;
                let label = if compact {
                    format!("Global [s {label}]: {value}")
                } else {
                    format!("Global interval [s {label}]: {value}")
                };
                assert!(
                    header_kpis(&m)
                        .iter()
                        .any(|line| line.to_string().contains(&label)),
                    "{label}"
                );
            }
            assert_eq!(m.reward_mask(), 7);
        }
    }
    #[test]
    fn world_header_uses_node_total_and_distinguishes_unreported_from_zero() {
        use quil_types::proto::node::{GetShardInfoResponse, ShardRewardInfo};
        let mut m = Model::new();
        m.data_loaded = true;
        let text = |m: &Model| {
            header_kpis(m)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert!(text(&m).contains("World [GB]: -"));
        m.cached_shard_info = Some(GetShardInfoResponse {
            world_state_bytes: BigInt::from(75_400_000_000u64).to_signed_bytes_be(),
            shards: vec![ShardRewardInfo {
                shard_size: BigInt::from(1_000_000_000u64).to_signed_bytes_be(),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert!(text(&m).contains("World [GB]: 75.4"));
        m.compact_actions = false;
        assert!(text(&m).contains("World size [GB]: 75.4"));
        m.hidden_header_kpis.insert("World size".into());
        assert!(!text(&m).contains("World size"));
        m.hidden_header_kpis.clear();
        m.cached_shard_info.as_mut().unwrap().world_state_bytes = vec![0];
        assert!(text(&m).contains("World size [GB]: 0.0"));
        m.cached_shard_info
            .as_mut()
            .unwrap()
            .world_state_bytes
            .clear();
        assert!(text(&m).contains("World size [GB]: -"));
    }
    #[test]
    fn picker_order_tracks_rendered_columns_and_nested_choices_after_reorder() {
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        for focus in [PanelFocus::Allocations, PanelFocus::Available] {
            m.focus = focus;
            let parent = m
                .display_columns()
                .iter()
                .position(|&col| col == if focus.is_alloc() { 16 } else { 11 })
                .unwrap();
            m.column_picker_cursor = parent;
            m.move_picker_column(false);
            let picker_cols = (0..m.visibility_names().len())
                .filter_map(|i| m.visibility_column_index(i))
                .collect::<Vec<_>>();
            assert_eq!(picker_cols, m.display_columns());
            let names = m.visibility_names();
            let interval = names
                .iter()
                .position(|&name| name == "Interval [s]")
                .unwrap();
            assert_eq!(&names[interval + 1..interval + 3], INTERVAL_WINDOW_NAMES);
            let header = if focus.is_alloc() {
                render_alloc_panel(
                    &mut m,
                    &[super::tests::row("01", 1, 1, 1, "", "")],
                    Rect::new(0, 0, 300, 5),
                    None,
                )[0]
                .to_string()
            } else {
                render_avail_panel(
                    &mut m,
                    &[super::tests::shard("01", 1, 0)],
                    Rect::new(0, 0, 300, 5),
                    None,
                )[0]
                .to_string()
            };
            let neighbor = if focus.is_alloc() {
                "Execution"
            } else {
                "PeerState"
            };
            assert!(
                header.find(neighbor).unwrap() < header.find("Interval").unwrap(),
                "{header}"
            );
            let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
            m.column_picker_active = true;
            let text = screen(&mut terminal, &mut m, 80, 30);
            assert!(text.contains("    [x] 60m window"));
        }
    }
    #[test]
    fn tiny_picker_keeps_all_group_headings_and_scrolls_the_focused_item() {
        let mut m = Model::new();
        m.column_picker_active = true;
        let mut terminal = Terminal::new(TestBackend::new(50, 12)).unwrap();
        for section in 0..5 {
            m.visibility_section = section;
            m.column_picker_cursor = m.visibility_names().len() - 1;
            m.column_picker_offset = 0;
            let text = screen(&mut terminal, &mut m, 50, 12);
            for title in [
                "Columns",
                "Top header",
                "Allocations header",
                "Available header",
                "Notifications header",
            ] {
                assert!(text.contains(title), "missing {title}: {text}");
            }
            assert!(
                m.column_picker_offset > 0,
                "focused last item must scroll into view"
            );
            assert!(
                text.contains("▶ [x]") || text.contains("▶   [x]"),
                "selected item missing: {text}"
            );
        }
    }
    #[test]
    fn prover_phases_column_is_hidden_until_the_picker_enables_it_for_both_panels() {
        use super::super::update::handle_key;
        use quil_types::proto::node::ShardProverCounts;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let mut m = Model::new();
        m.compact_actions = false;
        m.compact_units = false;
        m.data_loaded = true;
        let mut a = super::tests::row("aa", 7, 1, 1, "", "");
        a.prover_counts = Some(ShardProverCounts {
            active: 7,
            ..Default::default()
        });
        let mut s = super::tests::shard("bb", 0, 0);
        s.prover_counts = Some(ShardProverCounts {
            active: 5,
            joining: 1,
            ..Default::default()
        });
        let tables = |m: &mut Model| {
            (
                render_alloc_panel(m, &[a.clone()], Rect::new(0, 0, 300, 5), None),
                render_avail_panel(m, &[s.clone()], Rect::new(0, 0, 300, 5), None),
            )
        };
        let (alloc, avail) = tables(&mut m);
        assert!(
            !alloc[0].to_string().contains("ProverPhases")
                && !avail[0].to_string().contains("ProverPhases")
        );
        assert!(
            !alloc[1].to_string().contains("7 active")
                && !avail[1].to_string().contains("5 active")
        );
        // ‹b›, move to the item, ‹space›: the picker shows it unchecked, then checked.
        let mut terminal = Terminal::new(TestBackend::new(100, 44)).unwrap();
        handle_key(&mut m, key(KeyCode::Char('b')));
        assert!(m.column_picker_active);
        let item = m
            .visibility_names()
            .iter()
            .position(|&name| name == "ProverPhases")
            .unwrap();
        assert!(m.column_picker_cursor < item);
        while m.column_picker_cursor < item {
            handle_key(&mut m, key(KeyCode::Down));
        }
        assert!(screen(&mut terminal, &mut m, 100, 44).contains("[ ] ProverPhases"));
        handle_key(&mut m, key(KeyCode::Char(' ')));
        assert!(screen(&mut terminal, &mut m, 100, 44).contains("[x] ProverPhases"));
        handle_key(&mut m, key(KeyCode::Enter));
        assert!(!m.column_picker_active);
        let (alloc, avail) = tables(&mut m);
        assert!(
            alloc[0].to_string().contains("ProverPhases")
                && avail[0].to_string().contains("ProverPhases")
        );
        assert!(alloc[1].to_string().contains("7 active"), "{}", alloc[1]);
        assert!(
            avail[1].to_string().contains("5 active, 1 joining"),
            "{}",
            avail[1]
        );
        // The Available panel's picker toggles the same shared setting.
        m.focus = PanelFocus::Available;
        handle_key(&mut m, key(KeyCode::Char('b')));
        let item = m
            .visibility_names()
            .iter()
            .position(|&name| name == "ProverPhases")
            .unwrap();
        while m.column_picker_cursor < item {
            handle_key(&mut m, key(KeyCode::Down));
        }
        handle_key(&mut m, key(KeyCode::Char(' ')));
        handle_key(&mut m, key(KeyCode::Esc));
        let (alloc, avail) = tables(&mut m);
        assert!(
            !alloc[0].to_string().contains("ProverPhases")
                && !avail[0].to_string().contains("ProverPhases")
        );
    }
}
