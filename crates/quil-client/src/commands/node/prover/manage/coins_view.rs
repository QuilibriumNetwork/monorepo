//! Drawing of the Coins tab ([`super::coins`]): the shared top header,
//! the Balances panel, the shared notifications panel and the key rows.

use std::time::{Instant, SystemTime};

use super::super::shield::{Dialog, Preview};
use super::coins::{self, CoinsFocus, ATTENTION};
use super::*;

const COLUMNS: [&str; 5] = ["Kind", "Coins", "Amount [Q]", "State", "As of"];

/// A cell's text and color; `None` keeps the table's text color.
type Cell = (String, Option<Color>);

fn plain(text: impl Into<String>) -> Cell {
    (text.into(), None)
}

/// `unavailable`, in the warning color or marked `!` with colors off.
fn unavailable(m: &Model) -> Cell {
    if m.color_coding {
        ("unavailable".into(), Some(WARNING))
    } else {
        ("unavailable!".into(), None)
    }
}

fn attention(text: &str) -> Cell {
    (format!("{ATTENTION} {text}"), Some(PRIMARY))
}

fn claimable_row(m: &Model) -> [Cell; 5] {
    let state = match (&m.claimable_reward, &m.reward_error) {
        (_, _) if !m.reward_loaded => plain("loading"),
        (Some((units, _)), _) if *units > 0 => attention("claimable"),
        (None, Some(_)) => unavailable(m),
        _ => plain("none"),
    };
    [
        plain("claimable"),
        plain("-"),
        plain(
            m.claimable_reward
                .map_or("-".into(), |(units, _)| fmt_claimable(units)),
        ),
        state,
        plain(
            m.claimable_reward
                .map_or("-".into(), |(_, frame)| format!("f{frame}")),
        ),
    ]
}

fn legacy_row(m: &Model) -> [Cell; 5] {
    let legacy = &m.coins.legacy;
    let reading = legacy
        .reading
        .map(|_| format!(" {}", spinner(m)))
        .unwrap_or_default();
    let Some((snapshot, at, _)) = &legacy.answer else {
        let state = if legacy.error.is_some() {
            unavailable(m)
        } else {
            plain("loading")
        };
        let as_of: String = if reading.is_empty() {
            "-".into()
        } else {
            reading.trim().into()
        };
        return [plain("legacy"), plain("-"), plain("-"), state, plain(as_of)];
    };
    // A failing refresh leaves older figures on screen: mark their age.
    let as_of = format!("{}{reading}", coins::utc_hm(*at));
    let as_of = match (&legacy.error, m.color_coding) {
        (None, _) => plain(as_of),
        (Some(_), true) => (as_of, Some(WARNING)),
        (Some(_), false) => plain(format!("{as_of}!")),
    };
    let Some(snapshot) = snapshot else {
        return [
            plain("legacy"),
            plain("-"),
            plain("-"),
            plain("no key"),
            as_of,
        ];
    };
    let tally = snapshot.tally;
    let total = tally.unshielded + tally.shielded;
    let state = if tally.unshielded > 0 {
        if coins::shields_open_at(snapshot).is_some() {
            plain("unshielded")
        } else {
            attention("unshielded")
        }
    } else if total > 0 {
        ("shielded".into(), Some(SUCCESS))
    } else {
        plain("none")
    };
    [
        plain("legacy"),
        plain(if total > 0 {
            format!("{} of {total}", tally.unshielded)
        } else {
            "0".into()
        }),
        plain(fmt_claimable(tally.units)),
        state,
        as_of,
    ]
}

/// The cursor row's detail.
fn detail(m: &Model) -> String {
    if m.coins.cursor == 0 {
        return match m.claimable_reward {
            Some((_, frame)) => format!(
                "Claimable: reward balance at f{frame}, from the GLOBAL reward witness; read with \
                 each Provers refresh ({}s).",
                m.refresh_seconds
            ),
            None => match &m.reward_error {
                Some(error) => format!("Claimable: read failed ({error})."),
                None => "Claimable: read with each Provers refresh.".into(),
            },
        };
    }
    let legacy = &m.coins.legacy;
    let mut parts = Vec::new();
    if let Some((Some(snapshot), _, took)) = &legacy.answer {
        parts.push(format!("{} shielded", snapshot.tally.shielded));
        if let Some(plan) = snapshot.plan {
            let mut text = format!(
                "plan {}{} {} of ≤{} coins",
                if plan.exact { "" } else { "≥" },
                plan.batches,
                if plan.batches == 1 {
                    "batch"
                } else {
                    "batches"
                },
                snapshot.batch_max.unwrap_or(0)
            );
            if plan.outside > 0 {
                text.push_str(&format!(", {} on no live shard", plan.outside));
            }
            parts.push(text);
        }
        if let Some((frame, left)) = coins::shields_open_at(snapshot) {
            parts.push(format!("shields open at f{frame} (in {left} frames)"));
        }
        parts.push(format!(
            "read {} pages in {:.1}s",
            snapshot.pages,
            took.as_secs_f64()
        ));
    }
    if legacy.reading.is_some() {
        parts.push("reading now".into());
    } else if let Some(start) = legacy.last_start {
        let next = SystemTime::now()
            + (start + coins::LEGACY_REFRESH).saturating_duration_since(Instant::now());
        parts.push(format!("next read ~{}; ‹r› reads now", coins::utc_hm(next)));
    }
    format!("Legacy coins: {}.", parts.join("; "))
}

/// The Balances table, its rows padded to shared column widths.
fn table_lines(m: &Model) -> Vec<Line<'static>> {
    let rows = [claimable_row(m), legacy_row(m)];
    let mut widths = COLUMNS.map(|name| name.chars().count());
    for row in &rows {
        for (width, (text, _)) in widths.iter_mut().zip(row) {
            *width = (*width).max(text.chars().count());
        }
    }
    // Counts and amounts align right, words left.
    let pad = |column: usize, text: &str, width: usize| match column {
        1 | 2 => format!("{text:>width$}  "),
        _ => format!("{text:<width$}  "),
    };
    let mut lines = vec![Line::from(
        COLUMNS
            .iter()
            .zip(widths)
            .enumerate()
            .map(|(column, (name, width))| {
                Span::styled(
                    pad(column, name, width),
                    Style::new().fg(TEXT).add_modifier(Modifier::BOLD),
                )
            })
            .collect::<Vec<_>>(),
    )];
    let focused = m.coins.focus == CoinsFocus::Balances;
    for (i, row) in rows.into_iter().enumerate() {
        let background = (i == m.coins.cursor).then_some(if focused {
            CURSOR_BG
        } else {
            INACTIVE_CURSOR_BG
        });
        let spans = row
            .into_iter()
            .zip(widths)
            .enumerate()
            .map(|(column, ((text, color), width))| {
                let mut style = Style::new().fg(color.unwrap_or(TEXT));
                if let Some(bg) = background {
                    style = style.bg(bg);
                }
                Span::styled(pad(column, &text, width), style)
            })
            .collect::<Vec<_>>();
        lines.push(Line::from(spans));
    }
    lines
}

fn notice_lines(m: &mut Model, width: u16) -> Vec<Line<'static>> {
    let now = SystemTime::now();
    let notices = coins::notices(m, fmt_claimable);
    m.coins
        .notice_since
        .retain(|key, _| notices.iter().any(|notice| notice.key == *key));
    for notice in &notices {
        m.coins.notice_since.entry(notice.key).or_insert(now);
    }
    let mut lines = Vec::new();
    let primary = status_line(m);
    let primary_severity = if m.status_is_error {
        NoticeSeverity::Error
    } else {
        NoticeSeverity::Info
    };
    // Replies to this tab's keys (a refused or cancelled shield) show from
    // the default level, as its progress does.
    if primary.width() > 0 && primary_severity.max(NoticeSeverity::Warning) >= m.notice_minimum {
        lines.extend(wrap_message(primary, width));
    }
    for notice in notices
        .into_iter()
        .filter(|notice| notice.rank() >= m.notice_minimum)
    {
        let marker = if notice.attention {
            format!("{ATTENTION} ")
        } else {
            String::new()
        };
        lines.extend(wrap_message(
            Line::from(Span::styled(
                format!(
                    "{}{marker}{}",
                    message_timestamp(m.coins.notice_since.get(notice.key).copied()),
                    notice.text
                ),
                Style::new().fg(if notice.success {
                    SUCCESS
                } else {
                    severity_color(notice.severity)
                }),
            )),
            width,
        ));
    }
    lines
}

/// Whether `S` can start: legacy coins to shield, shields open, no run.
fn shield_usable(m: &Model) -> bool {
    !super::super::shield::running(m)
        && matches!(&m.coins.legacy.answer, Some((Some(snapshot), _, _))
            if snapshot.tally.unshielded > snapshot.pending
                && coins::shields_open_at(snapshot).is_none())
}

/// The recipient of a shield: this node's own wallet. Its confidential
/// address runs to thousands of characters, so the dialog names it by its
/// ends and length; `qclient token confidential-address` prints it whole.
fn recipient_text(address: &str) -> String {
    let hex = address.strip_prefix("0x").unwrap_or(address);
    if hex.len() <= 40 {
        return format!("this node's wallet, {address}");
    }
    format!(
        "this node's wallet, 0x{}…{} ({} bytes; `qclient token confidential-address` prints it \
         in full)",
        &hex[..12],
        &hex[hex.len() - 12..],
        hex.len() / 2
    )
}

/// The amount with five decimals, so a column of amounts aligns.
fn fixed_amount(units: u128) -> String {
    let text = fmt_claimable(units);
    if text.starts_with('<') {
        return text;
    }
    match text.split_once('.') {
        Some((whole, fraction)) => format!("{whole}.{fraction:0<5}"),
        None => format!("{text}.00000"),
    }
}

/// The confirmation: the action and its exact inputs.
fn confirm_lines(preview: &Preview, width: u16) -> Vec<Line<'static>> {
    let row = |label: &str, text: String| {
        Line::from(vec![
            Span::styled(
                format!("{label}: "),
                Style::new().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(text, Style::new().fg(TEXT)),
        ])
    };
    // Every listed coin outside the batches, with its reason: nothing
    // goes unshielded without the confirmation saying so.
    let mut left = Vec::new();
    if preview.shielded > 0 {
        left.push(format!("{} already shielded", preview.shielded));
    }
    if preview.uncovered > 0 {
        left.push(format!(
            "{} on no live shard, for a later run",
            preview.uncovered
        ));
    }
    if preview.pending > 0 {
        left.push(format!(
            "{} submitted <1h ago, awaiting their batch",
            preview.pending
        ));
    }
    if preview.duplicates > 0 {
        left.push(format!("{} listed twice", preview.duplicates));
    }
    let mut lines = vec![
        Line::from(Span::styled(
            "Shield legacy coins into this wallet, as `qclient token shield-all` does:",
            Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
        )),
        row(
            "Coins",
            format!(
                "{} of {} listed legacy coins, in {} {} of up to {} coins, one shard each",
                preview.coins,
                preview.listed,
                preview.batches,
                if preview.batches == 1 {
                    "batch"
                } else {
                    "batches"
                },
                super::super::shield::BATCH_COINS
            ),
        ),
        row(
            "Amount",
            format!("{} Q, less the fees", fmt_claimable(preview.units)),
        ),
        row(
            "Fee",
            format!(
                "{} base units ({} Q) in total as quoted now, up to {} per batch; each batch \
                 is quoted again before it is proved",
                preview.fee,
                fmt_claimable(preview.fee),
                preview.fee_max
            ),
        ),
        row(
            "Cap",
            format!(
                "{} Q per batch (--max-fee); a higher quote stops the run",
                fmt_claimable(preview.max_fee)
            ),
        ),
    ];
    if !left.is_empty() {
        lines.push(row("Left out", left.join("; ")));
    }
    lines.push(row("Recipient", recipient_text(&preview.recipient)));
    lines.push(Line::from(Span::styled(
        "Batches are proved here one at a time and submitted to this node; the coins are \
         spent once a batch is included.",
        Style::new().fg(HELP),
    )));
    lines
        .into_iter()
        .flat_map(|line| wrap_message(line, width))
        .collect()
}

/// The Shield plan panel's title and lines: the confirmation while it is
/// open, else one row per `token shield-all` batch and its footer.
/// Rows the panel scrolls: first shown, total and shown.
type Scroll = Option<(usize, usize, usize)>;

fn plan_lines(m: &mut Model, width: u16, height: u16) -> (String, Vec<Line<'static>>, Scroll) {
    match &m.coins.shield.dialog {
        Some(Dialog::Confirm(preview)) => {
            return ("Confirm shield".into(), confirm_lines(preview, width), None);
        }
        Some(Dialog::Preparing(_)) => {
            return (
                "Shield plan".into(),
                vec![Line::from(Span::styled(
                    format!("{} Reading coins and quoting fees…", spinner(m)),
                    Style::new().fg(PRIMARY),
                ))],
                None,
            );
        }
        None => {}
    }
    let help = Style::new().fg(HELP);
    let Some((Some(snapshot), _, _)) = &m.coins.legacy.answer else {
        let text = match &m.coins.legacy.answer {
            Some((None, _, _)) => "No Ed448 key in the node config: no legacy coins.",
            _ => "Legacy coins are not read yet.",
        };
        return (
            "Shield plan".into(),
            vec![Line::from(Span::styled(text, help))],
            None,
        );
    };
    let mut footer = Vec::new();
    if let Some((frame, left)) = coins::shields_open_at(snapshot) {
        footer.push(Line::from(Span::styled(
            format!("Shields open at f{frame} (in {left} frames)."),
            Style::new().fg(PRIMARY),
        )));
    }
    let max = snapshot.batch_max.unwrap_or(0);
    let mut summary = match snapshot.plan {
        None if snapshot.tally.unshielded == 0 => "Nothing to shield.".to_string(),
        None => "Nothing to shield now.".to_string(),
        Some(plan) if plan.exact => format!(
            "Batches: {} of ≤{max} coins; {} coins on no live shard",
            plan.batches, plan.outside
        ),
        Some(plan) => format!(
            "Batches: ≥{}; the shard list is unavailable, so no rows",
            plan.batches
        ),
    };
    if snapshot.pending > 0 {
        summary.push_str(&format!("; {} submitted <1h ago hidden", snapshot.pending));
    }
    footer.push(Line::from(Span::styled(summary, help)));
    let rows = &snapshot.batches;
    let count = rows.len();
    let visible = usize::from(height).saturating_sub(1 + footer.len()).max(1);
    m.coins.plan_cursor = m.coins.plan_cursor.min(count.saturating_sub(1));
    m.coins.plan_offset = clamp_offset(m.coins.plan_offset, m.coins.plan_cursor, visible, count);
    let mut lines = Vec::new();
    if count > 0 {
        let longest = rows
            .iter()
            .map(|row| (row.filter.len() * 2).saturating_sub(64))
            .max()
            .unwrap_or(0);
        let shard_width = (3 + longest + 6).clamp(12, 24);
        let label_width = format!("{count}/{count}").len().max(5);
        let amounts: Vec<String> = rows.iter().map(|row| fixed_amount(row.units)).collect();
        let amount_width = amounts.iter().map(String::len).max().unwrap_or(0).max(10);
        let bold = Style::new().fg(TEXT).add_modifier(Modifier::BOLD);
        lines.push(Line::from(Span::styled(
            format!(
                "{:<label_width$}  {:<shard_width$}  {:>5}  {:>amount_width$}",
                "Batch", "Shard", "Coins", "Amount [Q]"
            ),
            bold,
        )));
        let focused = m.coins.focus == CoinsFocus::ShieldPlan;
        for (i, row) in rows
            .iter()
            .enumerate()
            .skip(m.coins.plan_offset)
            .take(visible)
        {
            let mut style = Style::new().fg(TEXT);
            if i == m.coins.plan_cursor {
                style = style.bg(if focused {
                    CURSOR_BG
                } else {
                    INACTIVE_CURSOR_BG
                });
            }
            lines.push(Line::from(Span::styled(
                format!(
                    "{:<label_width$}  {:<shard_width$}  {:>5}  {:>amount_width$}",
                    format!("{}/{count}", i + 1),
                    filter_label(&hex::encode(&row.filter), shard_width, longest),
                    row.coins,
                    amounts[i]
                ),
                style,
            )));
        }
    }
    lines.extend(footer);
    let scroll = (count > visible).then_some((m.coins.plan_offset, count, visible));
    ("Shield plan".into(), lines, scroll)
}

/// The UI key row of the Coins tab, or the collapsed row.
fn key_rows(m: &Model, width: u16) -> Vec<Line<'static>> {
    if matches!(m.coins.shield.dialog, Some(Dialog::Confirm(_))) {
        return vec![Line::from(Span::styled(
            "Confirm: ‹y› shield  any other key cancels",
            Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
        ))];
    }
    if !m.show_key_rows {
        return vec![collapsed_keys_line()];
    }
    let compact = if m.compact_actions {
        "expand"
    } else {
        "compact"
    };
    let colors = if m.color_coding {
        "colors on"
    } else {
        "colors off"
    };
    let refresh = format!("refresh {}s", m.refresh_seconds);
    let reading = m.coins.legacy.reading.is_some();
    let (up, down) = match m.coins.focus {
        CoinsFocus::Balances => (m.coins.cursor > 0, m.coins.cursor + 1 < coins::BALANCE_ROWS),
        CoinsFocus::ShieldPlan => {
            let rows = match &m.coins.legacy.answer {
                Some((Some(snapshot), _, _)) => snapshot.batches.len(),
                _ => 0,
            };
            (m.coins.plan_cursor > 0, m.coins.plan_cursor + 1 < rows)
        }
        CoinsFocus::Notifications => (
            m.notice_offset > 0,
            m.notice_offset + m.notice_visible < m.notice_lines,
        ),
    };
    let entries = [
        ("tab", "switch", true),
        ("↑/k", "up", up),
        ("↓/j", "down", down),
        ("r", "read legacy", !reading),
        ("S", "shield", shield_usable(m)),
        ("n", compact, true),
        ("c", colors, true),
        ("v", "notice level", true),
        ("t", refresh.as_str(), true),
        ("?", "hide keys", true),
        ("h", "help", true),
        ("q", "quit", true),
    ];
    let mut spans = vec![Span::styled(
        "UI:",
        Style::new().fg(HELP).add_modifier(Modifier::BOLD),
    )];
    for (key, description, usable) in entries {
        if m.compact_actions && !usable {
            continue;
        }
        spans.push(Span::raw(" "));
        let style = if usable {
            Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(DIM)
        };
        spans.push(command_hint(key, description, style));
    }
    wrap_actions(Line::from(spans), width)
}

pub(super) fn render(f: &mut Frame, m: &mut Model, area: Rect) {
    let header = header_lines(m, area.width);
    let actions = key_rows(m, area.width);
    let inner_width = area.width.saturating_sub(2);
    let mut balances = table_lines(m);
    balances.extend(wrap_message(
        Line::from(Span::styled(detail(m), Style::new().fg(HELP))),
        inner_width,
    ));
    let notices = notice_lines(m, inner_width);
    let fixed = header.len() as u16 + actions.len() as u16;
    let rest = area.height.saturating_sub(fixed);
    // Shield plan keeps four lines, Notifications one, inside borders.
    let balances_h = (balances.len() as u16 + 2).min(rest.saturating_sub(9));
    let notice_h = (notices.len().clamp(1, 6) as u16 + 2)
        .min(rest.saturating_sub(balances_h + 6))
        .max(3);
    let chunks = Layout::vertical([
        Constraint::Length(header.len() as u16),
        Constraint::Length(balances_h),
        Constraint::Min(3),
        Constraint::Length(notice_h),
        Constraint::Length(actions.len() as u16),
    ])
    .split(area);
    f.render_widget(
        Paragraph::new(header).style(Style::new().fg(TEXT).bg(HEADER_BG)),
        chunks[0],
    );
    let bordered = |title: String, focused: bool| {
        Block::default()
            .title(panel_title(title))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(if focused { PRIMARY } else { DIM }))
    };
    let block = bordered("Balances".into(), m.coins.focus == CoinsFocus::Balances);
    let inner = block.inner(chunks[1]);
    f.render_widget(block, chunks[1]);
    f.render_widget(Paragraph::new(balances), inner);
    let plan_area = chunks[2];
    let (title, lines, scroll) = plan_lines(
        m,
        plan_area.width.saturating_sub(2),
        plan_area.height.saturating_sub(2),
    );
    let dialog = matches!(m.coins.shield.dialog, Some(Dialog::Confirm(_)));
    let block = bordered(title, dialog || m.coins.focus == CoinsFocus::ShieldPlan);
    let inner = block.inner(plan_area);
    f.render_widget(block, plan_area);
    f.render_widget(Paragraph::new(lines), inner);
    if let Some((offset, total, visible)) = scroll {
        render_scroll_hint(f, plan_area, offset, total, visible, 0, 0);
    }
    let focused = m.coins.focus == CoinsFocus::Notifications;
    render_notifications(f, m, notices, focused, chunks[3]);
    f.render_widget(
        Paragraph::new(actions).style(Style::new().fg(HELP)),
        chunks[4],
    );
}

#[cfg(test)]
mod coins_render_tests {
    use super::*;
    use crate::commands::token::legacy::{ShieldPlan, ShieldRule, Snapshot, Tally};
    use std::time::Duration;

    fn loaded() -> Model {
        let mut m = Model::new();
        m.data_loaded = true;
        m.reward_loaded = true;
        m.claimable_reward = Some((2_500_000_000_000_000, 1200));
        coins::open(&mut m);
        coins::apply_legacy(
            &mut m,
            Ok(Some(Snapshot {
                tally: Tally {
                    units: 8_000_000_000_000,
                    unshielded: 4,
                    shielded: 6,
                },
                plan: Some(ShieldPlan {
                    batches: 2,
                    exact: true,
                    outside: 1,
                }),
                batch_max: Some(96),
                head: Ok(2000),
                rule: Some(ShieldRule {
                    shield_from: 900,
                    shield_all_from: 1000,
                }),
                pages: 8,
                batches: Vec::new(),
                pending: 0,
                shielded: Default::default(),
            })),
            Duration::from_millis(6200),
        );
        m
    }

    #[test]
    fn coins_tab_shows_balances_attention_and_its_keys() {
        let mut m = loaded();
        m.color_coding = false;
        let text = render_text(&mut m, 120, 24);
        let row = |kind: &str| {
            text.lines()
                .find(|line| line.trim_start_matches('│').trim_start().starts_with(kind))
                .unwrap_or_else(|| panic!("no {kind} row in\n{text}"))
                .to_string()
        };
        assert!(
            text.contains("‹1› Provers") && text.contains("‹2› Coins"),
            "{text}"
        );
        assert!(text.contains("Balances"));
        assert!(row("claimable").contains("◆ claimable"), "{text}");
        let legacy = row("legacy");
        assert!(legacy.contains("4 of 10"), "{legacy}");
        assert!(legacy.contains("◆ unshielded"), "{legacy}");
        assert!(
            text.contains("◆ Legacy coins: 4 of 10 unshielded in 2 batches"),
            "{text}"
        );
        assert!(text.contains("‹r› read legacy"), "{text}");
        assert!(
            text.contains("‹↓/j› down") && !text.contains("‹↑/k› up"),
            "{text}"
        );
        assert!(!text.contains("Allocations"), "{text}");
        assert!(!text.contains("Workers (Ctrl+)"), "{text}");
        // Down: the legacy row's detail.
        coins::handle_key(
            &mut m,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Down),
        );
        let text = render_text(&mut m, 200, 24);
        assert!(
            text.contains("Legacy coins: 6 shielded; plan 2 batches of ≤96 coins, 1 on no live shard; read 8 pages in 6.2s"),
            "{text}"
        );
    }

    #[test]
    fn a_failing_read_marks_old_figures_and_the_other_tab_counts_notices() {
        let mut m = loaded();
        m.color_coding = false;
        coins::apply_legacy(
            &mut m,
            Err("node unreachable".into()),
            Duration::from_secs(1),
        );
        let text = render_text(&mut m, 140, 24);
        assert!(
            text.contains("Legacy coins: read failed 1 time since"),
            "{text}"
        );
        assert!(text.contains(" UTC!"), "{text}");
        m.tab = Tab::Provers;
        // Claimable, unshielded and the failed read show at the default level.
        assert!(header_line(&m)
            .to_string()
            .starts_with("‹1› Provers  ‹2› Coins 3!"));
        m.color_coding = true;
        assert!(header_line(&m)
            .to_string()
            .starts_with("‹1› Provers  ‹2› Coins 3 "));
    }

    #[test]
    fn question_mark_collapses_the_key_rows_on_both_tabs() {
        for tab in [Tab::Provers, Tab::Coins] {
            let mut m = loaded();
            m.tab = tab;
            let full = render_text(&mut m, 120, 30);
            assert!(full.contains("‹?› hide keys"), "{full}");
            super::super::super::update::handle_key(
                &mut m,
                crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('?')),
            );
            let collapsed = render_text(&mut m, 120, 30);
            let last = collapsed.lines().last().unwrap();
            assert_eq!(last, "‹?› keys ‹h› help ‹q› quit", "{collapsed}");
            assert!(!collapsed.contains("UI:"), "{collapsed}");
        }
    }

    /// The confirmation and a run's states as they draw; with
    /// `QCLIENT_RENDER_DIR` set, each frame is also written there.
    #[test]
    fn shield_confirmation_and_progress_draw() {
        use super::super::super::shield::{self, Preview, Progress};
        let dump = |name: &str, text: &str| {
            if let Ok(dir) = std::env::var("QCLIENT_RENDER_DIR") {
                std::fs::write(format!("{dir}/{name}.txt"), text).unwrap();
            }
        };
        let mut m = loaded();
        m.color_coding = false;
        if let Some((Some(snapshot), _, _)) = m.coins.legacy.answer.as_mut() {
            snapshot.batches = vec![
                crate::commands::token::legacy::PlanBatch {
                    filter: [vec![0x11; 32], vec![0x90, 0x00, 0x91]].concat(),
                    coins: 3,
                    units: 6_000_000_000_000,
                },
                crate::commands::token::legacy::PlanBatch {
                    filter: [vec![0x11; 32], vec![0x90, 0x00, 0x92]].concat(),
                    coins: 1,
                    units: 2_000_000_000_000,
                },
            ];
        }
        let text = render_text(&mut m, 120, 30);
        dump("offline-shield-plan-120x30", &text);
        assert!(text.contains("Shield plan"), "{text}");
        assert!(text.contains("1/2    ...111111900091"), "{text}");
        assert!(
            text.contains("Batches: 2 of ≤96 coins; 1 coins on no live shard"),
            "{text}"
        );
        assert!(text.contains("‹S› shield"), "{text}");
        let recipient = format!("0x{}", "ab".repeat(40));
        m.coins.shield.dialog = Some(shield::Dialog::Confirm(Preview {
            batches: 2,
            coins: 4,
            units: 8_000_000_000_000,
            fee: 16_000,
            fee_max: 9_000,
            max_fee: 800_000_000,
            recipient: recipient.clone(),
            listed: 8,
            shielded: 2,
            uncovered: 1,
            pending: 1,
            duplicates: 0,
        }));
        let text = render_text(&mut m, 120, 30);
        dump("offline-shield-confirm-120x30", &text);
        for line in [
            "Confirm shield",
            "Coins: 4 of 8 listed legacy coins, in 2 batches of up to 96 coins, one shard each",
            "Amount: 1000 Q, less the fees",
            "Recipient: this node's wallet, 0xabababababab…abababababab (40 bytes;",
            "Fee: 16000 base units (<0.00001 Q) in total as quoted now, up to 9000 per batch",
            "Cap: 0.1 Q per batch (--max-fee); a higher quote stops the run",
            "Left out: 2 already shielded; 1 on no live shard, for a later run; 1 submitted <1h",
            "Confirm: ‹y› shield  any other key cancels",
        ] {
            assert!(text.contains(line), "{line}\n{text}");
        }
        // Any key but `y` cancels, and says so at the default level.
        let mut cancelled = loaded();
        cancelled.coins.shield.dialog = m.coins.shield.dialog.take();
        m.coins.shield.dialog = Some(shield::Dialog::Confirm(Preview {
            batches: 2,
            coins: 4,
            units: 8_000_000_000_000,
            fee: 16_000,
            fee_max: 9_000,
            max_fee: 800_000_000,
            recipient,
            listed: 8,
            shielded: 2,
            uncovered: 1,
            pending: 1,
            duplicates: 0,
        }));
        super::super::super::update::handle_key(
            &mut cancelled,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('n')),
        );
        let text = render_text(&mut cancelled, 120, 30);
        assert!(
            text.contains("Shield: cancelled; nothing was submitted."),
            "{text}"
        );
        assert!(cancelled.coins.shield.run.is_none());
        super::super::super::update::handle_key(
            &mut m,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('y')),
        );
        for progress in [
            Progress::Proving {
                index: 1,
                count: 2,
                coins: 3,
            },
            Progress::Note("Estimated fee: 9000 base units".into()),
        ] {
            shield::apply_progress(&mut m, progress);
        }
        let text = render_text(&mut m, 120, 30);
        dump("offline-shield-proving-120x30", &text);
        assert!(
            text.contains("Shield batch 1/2: proving 3 coins <60s."),
            "{text}"
        );
        assert!(!text.contains("‹S› shields them"), "{text}");
        shield::apply_progress(
            &mut m,
            Progress::Submitted {
                index: 1,
                count: 2,
                addresses: vec![[1; 32]; 3],
                shielded: 5_999_999_991_000,
            },
        );
        shield::apply_progress(&mut m, Progress::Done(Err("fee changed".into())));
        let text = render_text(&mut m, 120, 30);
        dump("offline-shield-failed-120x30", &text);
        assert!(
            text.contains("Shield: 1 batch of 2 submitted (3 coins); inclusion not yet confirmed."),
            "{text}"
        );
        assert!(
            text.contains("Shield batch 2/2 failed")
                || text.contains("Shield: failed before any batch"),
            "{text}"
        );
    }
}
