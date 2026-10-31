//! Drawing of the Coins tab ([`super::coins`]): the shared top header,
//! the Balances panel, the shared notifications panel and the key rows.

use std::time::{Instant, SystemTime};

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
    if primary.width() > 0 && primary_severity >= m.notice_minimum {
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
                Style::new().fg(severity_color(notice.severity)),
            )),
            width,
        ));
    }
    lines
}

/// The UI key row of the Coins tab.
fn key_rows(m: &Model, width: u16) -> Vec<Line<'static>> {
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
        ("n", compact, true),
        ("c", colors, true),
        ("v", "notice level", true),
        ("t", refresh.as_str(), true),
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
    let mut balances = table_lines(m);
    balances.extend(wrap_message(
        Line::from(Span::styled(detail(m), Style::new().fg(HELP))),
        area.width.saturating_sub(2),
    ));
    let fixed = header.len() as u16 + actions.len() as u16;
    // Notifications keep at least one line inside their border.
    let balances_h = (balances.len() as u16 + 2).min(area.height.saturating_sub(fixed + 3));
    let chunks = Layout::vertical([
        Constraint::Length(header.len() as u16),
        Constraint::Length(balances_h),
        Constraint::Min(3),
        Constraint::Length(actions.len() as u16),
    ])
    .split(area);
    f.render_widget(
        Paragraph::new(header).style(Style::new().fg(TEXT).bg(HEADER_BG)),
        chunks[0],
    );
    let block = Block::default()
        .title(panel_title("Balances".into()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if m.coins.focus == CoinsFocus::Balances {
            PRIMARY
        } else {
            DIM
        }));
    let inner = block.inner(chunks[1]);
    f.render_widget(block, chunks[1]);
    f.render_widget(Paragraph::new(balances), inner);
    let lines = notice_lines(m, chunks[2].width.saturating_sub(2));
    let focused = m.coins.focus == CoinsFocus::Notifications;
    render_notifications(f, m, lines, focused, chunks[2]);
    f.render_widget(
        Paragraph::new(actions).style(Style::new().fg(HELP)),
        chunks[3],
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
}
