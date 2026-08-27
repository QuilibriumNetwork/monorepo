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

use super::super::{format_quil_daily, format_quil_reward, format_storage};
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

fn mode_color(mode: &str) -> Color {
    if mode == "M" {
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

fn alloc_col_widths(m: &Model, content_width: usize) -> (Vec<usize>, usize) {
    let mut fw = content_width.saturating_sub(ALLOC_FIXED_WIDTH);
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
        SHARDS_WIDTH,
        REWARD_WIDTH,
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

fn render_alloc_panel(m: &mut Model, sorted: &[AllocationRow], area: Rect) -> Vec<Line<'static>> {
    let content_width = area.width as usize;
    let height = area.height as usize;
    if sorted.is_empty() {
        if !m.data_loaded {
            return vec![Line::from(format!("  {} Loading allocations…", spinner(m)))];
        }
        return vec![Line::from("  No allocations")];
    }
    let (widths, fw) = alloc_col_widths(m, content_width);
    let filter_hi = m.active_filter_col_idx();

    // Header row.
    let mut hdr_spans: Vec<Span> = Vec::new();
    for (i, name) in ALLOC_COL_NAMES.iter().enumerate() {
        let w = widths[i];
        let mut disp = name.to_string();
        if m.alloc_col_filters.get(&i).is_some_and(|cf| cf.is_active()) {
            disp.push('*');
        }
        if m.alloc_sort_col == i as i32 {
            let ind = if m.alloc_sort_asc { "^|" } else { "v|" };
            disp = format!("{ind}{disp}");
        }
        let cell = format!("{:>w$}", disp, w = w);
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
        let mode_str = if a.manually_managed { "M" } else { "A" };
        let marker = if m.alloc_selected.contains(&a.filter_key) {
            "[x]"
        } else {
            "[ ]"
        };
        let worker_str = a.worker_id.to_string();
        let selected = i == m.alloc_cursor && m.focus.is_alloc();

        let cells = [
            format!("{:>w$}", marker, w = widths[0]),
            format!("{:>w$}", center_trunc(&a.filter_hex, fw), w = widths[1]),
            format!("{:>w$}", a.active_provers, w = widths[2]),
            format!("{:>w$}", a.ring, w = widths[3]),
            format!("{:>w$}", fmt_mb(&a.shard_size), w = widths[4]),
            format!("{:>w$}", a.data_shards, w = widths[5]),
            format!("{:>w$}", fmt_reward(&a.estimated_reward), w = widths[6]),
            format!("{:>w$}", worker_str, w = widths[7]),
            format!("{:>w$}", a.status_name, w = widths[8]),
            format!("{:>w$}", mode_str, w = widths[9]),
            format!("{:>w$}", a.next_action, w = widths[10]),
            format!("{:>w$}", a.default_action, w = widths[11]),
        ];

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
                    8 if m.color_coding => {
                        Span::styled(cell.clone(), Style::new().fg(status_color(&a.status_name)))
                    }
                    9 if m.color_coding => {
                        Span::styled(cell.clone(), Style::new().fg(mode_color(mode_str)))
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

fn avail_col_widths(m: &Model, content_width: usize) -> (Vec<usize>, usize) {
    let mut fw = content_width.saturating_sub(AVAIL_FIXED_WIDTH);
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
        SHARDS_WIDTH,
        REWARD_WIDTH,
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
    let (widths, fw) = avail_col_widths(m, content_width);
    let filter_hi = m.active_filter_col_idx();

    let mut hdr_spans: Vec<Span> = Vec::new();
    for (i, name) in AVAIL_COL_NAMES.iter().enumerate() {
        let w = widths[i];
        let mut disp = name.to_string();
        if m.avail_col_filters.get(&i).is_some_and(|cf| cf.is_active()) {
            disp.push('*');
        }
        if m.avail_sort_col == i as i32 {
            let ind = if m.avail_sort_asc { "^|" } else { "v|" };
            disp = format!("{ind}{disp}");
        }
        let cell = format!("{:>w$}", disp, w = w);
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
        let marker = if m.avail_selected.contains(&s.filter_key) {
            "[x]"
        } else {
            "[ ]"
        };
        let selected = i == m.avail_cursor && !m.focus.is_alloc();

        if selected {
            let cells = [
                format!("{:>w$}", marker, w = widths[0]),
                format!("{:>w$}", center_trunc(&s.filter_hex, fw), w = widths[1]),
                format!("{:>w$}", s.active_provers, w = widths[2]),
                format!("{:>w$}", s.ring, w = widths[3]),
                format!("{:>w$}", fmt_mb(&s.shard_size), w = widths[4]),
                format!("{:>w$}", s.data_shards, w = widths[5]),
                format!("{:>w$}", fmt_reward(&s.estimated_reward), w = widths[6]),
            ];
            let padded = format!("{:<width$}", cells.join(" "), width = content_width);
            lines.push(Line::from(Span::styled(
                padded,
                Style::new().fg(TEXT).bg(PRIMARY),
            )));
        } else {
            // Non-selected: size uses human-readable storage; ring colored.
            let cells = [
                (format!("{:>w$}", marker, w = widths[0]), None),
                (format!("{:>w$}", center_trunc(&s.filter_hex, fw), w = widths[1]), None),
                (format!("{:>w$}", s.active_provers, w = widths[2]), None),
                (
                    format!("{:>w$}", s.ring, w = widths[3]),
                    m.color_coding.then(|| ring_color(s.ring)),
                ),
                (
                    format!("{:>w$}", format_storage(bigint_to_u64(&s.shard_size)), w = widths[4]),
                    None,
                ),
                (format!("{:>w$}", s.data_shards, w = widths[5]), None),
                (
                    format!("{:>w$}", format!("{} Q/f", fmt_reward(&s.estimated_reward)), w = widths[6]),
                    None,
                ),
            ];
            let mut spans: Vec<Span> = Vec::new();
            for (ci, (cell, color)) in cells.into_iter().enumerate() {
                if ci > 0 {
                    spans.push(Span::raw(" "));
                }
                spans.push(match color {
                    Some(c) => Span::styled(cell, Style::new().fg(c)),
                    None => Span::raw(cell),
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
    let entries: [(&str, &str, &str); 18] = [
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
