//! Drawing of the Coins tab ([`super::coins`]): the shared top header,
//! the Balances panel, the middle panel of the selected Balances row, the
//! shared notifications panel and the key rows.

use std::time::{Instant, SystemTime};

use super::super::mint::{
    Dialog as MintDialog, Preview as MintPreview, Stage as MintStage, Status as MintStatus,
};
use super::super::shield::{Dialog, Preview};
use super::coins::{self, CoinsFocus, Middle, ATTENTION};
use super::*;

const COLUMNS: [&str; 5] = ["Kind", "Coins", "Amount [Q]", "State", "As of"];

/// Lines the Balances panel reserves under its rows for the cursor row's
/// detail; a longer detail ends in the enlarge marker until an edge key
/// gives the panel more.
const BALANCE_DETAIL: u16 = 2;

/// Lines the Notifications panel takes inside its borders on a tall
/// terminal before an edge key moves it: the most it took when it grew
/// with its notices.
const NOTICE_LINES: u16 = 6;

/// Lines the middle panel keeps inside its borders before Notifications
/// takes more than one: the Claim status at 80 columns.
const MIDDLE_LINES: u16 = 5;

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
    // A run under way shows on the row, whichever panel is on screen.
    let state = if let Some(state) = super::super::shield::row_state(m) {
        (state, Some(PRIMARY))
    } else if tally.unshielded > 0 {
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
        // Unshielded of all listed; the detail splits them by kind.
        plain(if tally.unshielded > 0 {
            format!("{}/{total}", tally.unshielded)
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
        // The cells carry the amount and its frame, Notifications a failure.
        return format!(
            "Claimable: the reward balance of the GLOBAL reward witness, read with each Provers \
             refresh ({}s).",
            m.refresh_seconds
        );
    }
    let legacy = &m.coins.legacy;
    let mut parts = Vec::new();
    if let Some((Some(snapshot), _, took)) = &legacy.answer {
        // The row's U/T leaves out the shielded count; the plan and when
        // shields open are the Shield plan's, on screen with this row.
        if snapshot.tally.shielded > 0 {
            parts.push(format!("{} shielded", snapshot.tally.shielded));
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

/// The Balances table, its rows padded to shared column widths, for a
/// panel `inner` columns wide.
fn table_lines(m: &Model, inner: u16) -> Vec<Line<'static>> {
    let rows = [claimable_row(m), legacy_row(m)];
    let mut widths = COLUMNS.map(|name| name.chars().count());
    for row in &rows {
        for (width, (text, _)) in widths.iter_mut().zip(row) {
            *width = (*width).max(text.chars().count());
        }
    }
    // Two spaces between columns, one where two would not fit.
    let gap = if widths.iter().sum::<usize>() + 2 * (widths.len() - 1) > usize::from(inner) {
        " "
    } else {
        "  "
    };
    // Counts and amounts align right, words left.
    let pad = |column: usize, text: &str, width: usize| match column {
        1 | 2 => format!("{text:>width$}{gap}"),
        _ => format!("{text:<width$}{gap}"),
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

/// An amount in Q to the base unit, as `qclient token` prints one: a
/// confirmation shows what it spends and pays without rounding.
fn exact_amount(units: u128) -> String {
    #[cfg(feature = "confidential-tokens")]
    return crate::commands::token::balance::quil_amount(units);
    #[cfg(not(feature = "confidential-tokens"))]
    return fmt_claimable(units);
}

/// What a masked field shows in a render without `--reveal`.
const MASKED: &str = "hidden in this render (--reveal shows it)";

/// The confirmation: the action and its exact inputs; `mask` hides the
/// amount and the recipient's address. In a panel of `height` lines too
/// short for them all, the Recipient row's first line, which names the
/// wallet and its address, stays in view before the marker.
fn confirm_lines(preview: &Preview, width: u16, height: u16, mask: bool) -> Vec<Line<'static>> {
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
            "{} submitted <2h ago, awaiting their batch",
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
            if mask {
                MASKED.to_string()
            } else {
                format!("{} Q, less the fees", exact_amount(preview.units))
            },
        ),
        row(
            "Fee",
            format!(
                "{} base units ({} Q) in total as quoted now, up to {} per batch; each batch \
                 is quoted again before it is proved",
                preview.fee,
                exact_amount(preview.fee),
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
    let recipient = lines.len();
    lines.push(row(
        "Recipient",
        if mask {
            format!("this node's wallet, its address {MASKED}")
        } else {
            recipient_text(&preview.recipient)
        },
    ));
    lines.push(Line::from(Span::styled(
        "Batches are proved here one at a time and submitted to this node; the coins are \
         spent once a batch is included.",
        Style::new().fg(HELP),
    )));
    let mut wrapped = Vec::new();
    let mut kept = 0..0;
    for (i, line) in lines.into_iter().enumerate() {
        let start = wrapped.len();
        wrapped.extend(wrap_message(line, width));
        if i == recipient {
            kept = start..(start + 1).min(wrapped.len());
        }
    }
    keep_in_view(wrapped, kept, width, height)
}

/// `lines` in `height` lines as [`fit_lines`] cuts them, except that the
/// `kept` lines stay in view: the lines between them and the marker give
/// way first. A panel too short for them and the marker shows as many as
/// leave the marker its line, at least one.
fn keep_in_view(
    lines: Vec<Line<'static>>,
    kept: std::ops::Range<usize>,
    width: u16,
    height: u16,
) -> Vec<Line<'static>> {
    let height = usize::from(height);
    if height == 0 || lines.len() <= height || kept.end < height {
        return lines;
    }
    let mut out: Vec<Line<'static>> = lines[kept.clone()].to_vec();
    if out.len() >= height {
        out.truncate(height.saturating_sub(1).max(1));
        if out.len() < height {
            out.push(enlarge_marker(width));
        }
        return out;
    }
    let room = height - 1 - out.len();
    out.splice(0..0, lines.into_iter().take(room.min(kept.start)));
    out.push(enlarge_marker(width));
    out
}

/// Rows the panel scrolls: first shown, total and shown.
type Scroll = Option<(usize, usize, usize)>;

/// The Claim status panel in `height` rows: the claimable reward at its
/// frame, its mint, and the authorizations saved for a claim.
fn claim_lines(m: &Model, width: u16, height: u16) -> Vec<Line<'static>> {
    let row = |label: &str, text: String| {
        Line::from(vec![
            Span::styled(
                format!("{label}: "),
                Style::new().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(text, Style::new().fg(TEXT)),
        ])
    };
    // The claimable amount and its frame are the Balances row's; this
    // panel adds what to do with them.
    let authorization = if super::super::mint::running(m) {
        "a mint or claim is under way; Notifications follow it"
    } else if !m.reward_loaded {
        "waits for the first Provers refresh to read the reward"
    } else {
        match (&m.claimable_reward, &m.reward_error) {
            (Some((units, _)), _) if *units > 0 => {
                "‹M› authorizes a mint of the claimable reward, as `qclient token mint` does"
            }
            (None, Some(_)) => "waits for a reward read to succeed",
            _ => "nothing to authorize",
        }
    };
    let mut lines: Vec<Line<'static>> =
        wrap_message(row("Authorization", authorization.into()), width);
    let rest = usize::from(height).saturating_sub(lines.len());
    lines.extend(saved_lines(m, width, rest));
    lines
}

/// The authorizations `token mint` saved, newest first, one row each with
/// the Claim status cursor, in `rows` lines.
fn saved_lines(m: &Model, width: u16, rows: usize) -> Vec<Line<'static>> {
    let help = Style::new().fg(HELP);
    let saved = &m.coins.mint.saved;
    if saved.is_empty() {
        return wrap_message(
            Line::from(Span::styled(
                "Saved authorizations: none; a mint saves one as mint-<frame>.bin for its claim.",
                help,
            )),
            width,
        );
    }
    let cell = |amount: Option<u128>| amount.map_or("-".to_string(), fixed_amount);
    let cells: Vec<[String; 4]> = saved
        .iter()
        .map(|saved| {
            [
                format!("f{}", saved.cited_frame),
                cell(
                    saved
                        .amounts
                        .map(|(reward, fee)| reward.saturating_sub(fee)),
                ),
                cell(saved.amounts.map(|(_, fee)| fee)),
                match super::super::mint::status(saved) {
                    MintStatus::Unavailable => "unavailable".to_string(),
                },
            ]
        })
        .collect();
    let headers = ["Cited", "Amount [Q]", "Fee [Q]", "State"];
    let mut widths = headers.map(str::len);
    for row in &cells {
        for (width, text) in widths.iter_mut().zip(row) {
            *width = (*width).max(text.chars().count());
        }
    }
    let line = |cells: [&str; 4]| {
        format!(
            "{:<w0$}  {:>w1$}  {:>w2$}  {:<w3$}",
            cells[0],
            cells[1],
            cells[2],
            cells[3],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3]
        )
    };
    let mut lines = vec![Line::from(Span::styled(
        line(headers),
        Style::new().fg(TEXT).add_modifier(Modifier::BOLD),
    ))];
    let height = u16::try_from(rows).unwrap_or(u16::MAX);
    let note = fit_detail(
        wrap_message(
            Line::from(Span::styled(
                "State: this node reports no authorization status; ‹C› checks for the finalized \
                 witness before it claims.",
                help,
            )),
            width,
        ),
        width,
        height,
        2,
    );
    let visible = rows.saturating_sub(1 + note.len()).max(1);
    let focused = m.coins.focus == CoinsFocus::Middle;
    let first = m.coins.mint.cursor.saturating_sub(visible - 1);
    for (i, row) in cells.iter().enumerate().skip(first).take(visible) {
        let mut style = Style::new().fg(TEXT);
        if i == m.coins.mint.cursor {
            style = style.bg(if focused {
                CURSOR_BG
            } else {
                INACTIVE_CURSOR_BG
            });
        }
        lines.push(Line::from(Span::styled(
            line([&row[0], &row[1], &row[2], &row[3]]),
            style,
        )));
    }
    pin_detail(lines, note, height)
}

/// The middle panel's title and lines: a confirmation while one is open;
/// else the selected Balances row's panel ([`Middle`]).
fn middle_lines(m: &mut Model, width: u16, height: u16) -> (String, Vec<Line<'static>>, Scroll) {
    match &m.coins.mint.dialog {
        Some(MintDialog::Confirm(preview)) => {
            let title = match preview.stage {
                MintStage::Authorize => "Confirm mint",
                MintStage::Claim { .. } => "Confirm claim",
            };
            let lines = mint_confirm_lines(preview, width, m.mask_private);
            return (title.into(), lines, None);
        }
        Some(MintDialog::Preparing(_, claim)) => {
            let text = if *claim {
                "Reading the authorization's GLOBAL witness…"
            } else {
                "Reading the reward and quoting the fee…"
            };
            return (
                Middle::Claim.title().into(),
                vec![Line::from(Span::styled(
                    format!("{} {text}", spinner(m)),
                    Style::new().fg(PRIMARY),
                ))],
                None,
            );
        }
        None => {}
    }
    if coins::middle(m) == Middle::Claim {
        let lines = claim_lines(m, width, height);
        return (Middle::Claim.title().into(), lines, None);
    }
    plan_lines(m, width, height)
}

/// The Shield plan panel's title and lines: the confirmation while it is
/// open, else one row per `token shield-all` batch and its footer.
fn plan_lines(m: &mut Model, width: u16, height: u16) -> (String, Vec<Line<'static>>, Scroll) {
    match &m.coins.shield.dialog {
        Some(Dialog::Confirm(preview)) => {
            return (
                "Confirm shield".into(),
                confirm_lines(preview, width, height, m.mask_private),
                None,
            );
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
        Some(plan) => format!("Batches: ≥{}; no rows", plan.batches),
    };
    if snapshot.pending > 0 {
        summary.push_str(&format!("; {} submitted <2h ago hidden", snapshot.pending));
    }
    footer.push(Line::from(Span::styled(summary, help)));
    let rows = &snapshot.batches;
    let count = rows.len();
    // Under batch rows the footer keeps to the panel's bottom; without
    // rows it is the panel's content.
    if count > 0 {
        footer = fit_detail(footer, width, height, 2);
    }
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
        let focused = m.coins.focus == CoinsFocus::Middle;
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
    let lines = if count > 0 {
        pin_detail(lines, footer, height)
    } else {
        footer
    };
    let scroll = (count > visible).then_some((m.coins.plan_offset, count, visible));
    ("Shield plan".into(), lines, scroll)
}

/// The mint confirmation: the stage and its exact inputs; `mask` hides the
/// amounts and the recipient's address.
fn mint_confirm_lines(preview: &MintPreview, width: u16, mask: bool) -> Vec<Line<'static>> {
    let row = |label: &str, text: String| {
        Line::from(vec![
            Span::styled(
                format!("{label}: "),
                Style::new().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(text, Style::new().fg(TEXT)),
        ])
    };
    let title = |text: &str| {
        Line::from(Span::styled(
            text.to_string(),
            Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
        ))
    };
    // To the base unit, as `token mint` prints it: a fee far below
    // 0.00001 Q must not round the minted amount up to the reward.
    let amount = row(
        "Amount",
        if mask {
            MASKED.to_string()
        } else {
            format!(
                "{} Q (reward {} Q less fee {} Q)",
                exact_amount(preview.minted()),
                exact_amount(preview.reward),
                exact_amount(preview.fee)
            )
        },
    );
    let lines = match &preview.stage {
        MintStage::Authorize => vec![
            title("Authorize a reward mint, as `qclient token mint` does:"),
            row(
                "Reward",
                if mask {
                    format!(
                        "{MASKED}; claimable at f{}, from the GLOBAL reward witness",
                        preview.cited_frame
                    )
                } else {
                    format!(
                        "{} Q claimable at f{}, from the GLOBAL reward witness",
                        exact_amount(preview.reward),
                        preview.cited_frame
                    )
                },
            ),
            amount,
            row(
                "Fee",
                format!(
                    "{} base units ({} Q) as quoted now, paid from the reward",
                    preview.fee,
                    exact_amount(preview.fee)
                ),
            ),
            row(
                "Cap",
                format!(
                    "{} Q (--max-fee); a higher quote is refused",
                    fmt_claimable(preview.max_fee)
                ),
            ),
            row(
                "Recipient",
                if mask {
                    format!("this node's wallet, its address {MASKED}")
                } else {
                    recipient_text(&preview.recipient)
                },
            ),
            row(
                "Saved as",
                "mint-<frame>.bin in the node config directory, for the claim; <frame> is the \
                 GLOBAL frame the proof cites"
                    .into(),
            ),
            Line::from(Span::styled(
                "The authorization is proved here and submitted to this node. The run reads the \
                 reward and quotes the fee again at the frame then current: a reward that grew \
                 is minted in full to this wallet, and the outcome names both amounts; a changed \
                 fee reopens this confirmation with it; a reward that fell stops the run. ‹C› \
                 claims it once GLOBAL finalizes it.",
                Style::new().fg(HELP),
            )),
        ],
        MintStage::Claim { path, witness } => vec![
            title("Claim a reward mint, as `qclient token mint --claim` does:"),
            row(
                "Authorization",
                format!(
                    "{}, citing f{}; finalized, its GLOBAL witness cites f{witness}",
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    preview.cited_frame
                ),
            ),
            amount,
            row(
                "Recipient",
                "as the authorization names it (this node's wallet unless `token mint` was \
                 given another)"
                    .into(),
            ),
            Line::from(Span::styled(
                "The claim is built here and submitted to this node; it creates the coins.",
                Style::new().fg(HELP),
            )),
        ],
    };
    lines
        .into_iter()
        .flat_map(|line| wrap_message(line, width))
        .collect()
}

/// The UI key row of the Coins tab, or the collapsed row.
fn key_rows(m: &Model, width: u16) -> Vec<Line<'static>> {
    if let Some(MintDialog::Confirm(preview)) = &m.coins.mint.dialog {
        return vec![Line::from(Span::styled(
            match preview.stage {
                MintStage::Authorize => "Confirm: ‹y› authorize the mint  any other key cancels",
                MintStage::Claim { .. } => "Confirm: ‹y› claim  any other key cancels",
            },
            Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
        ))];
    }
    if matches!(m.coins.shield.dialog, Some(Dialog::Confirm(_))) {
        return vec![Line::from(Span::styled(
            "Confirm: ‹y› shield  any other key cancels",
            Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
        ))];
    }
    if m.coins.shield.stop_pending {
        return vec![Line::from(Span::styled(
            "Stop shield: ‹y› stop before the next submission  any other key keeps it running",
            Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
        ))];
    }
    if !m.show_key_rows {
        return vec![collapsed_keys_line()];
    }
    ui_key_rows(m, width)
}

/// The UI key rows of the Coins tab, as they show while no question
/// replaces them.
fn ui_key_rows(m: &Model, width: u16) -> Vec<Line<'static>> {
    ui_key_rows_esc(m, width, None)
}

/// Every description of the esc hint, which a question renames; "cancel
/// transfer" is the transfer dialog's, so the rows fit it too.
const ESC_LABELS: [&str; 4] = [
    "stop shield",
    "cancel mint",
    "cancel shield",
    "cancel transfer",
];

/// The lines the UI key rows take whichever esc description shows, so a
/// question that renames the hint never moves the panels above.
fn ui_key_rows_reserved(m: &Model, width: u16) -> usize {
    ESC_LABELS
        .iter()
        .map(|esc| ui_key_rows_esc(m, width, Some(esc)).len())
        .max()
        .unwrap_or(0)
}

/// [`ui_key_rows`], with the esc hint described as `esc` when given.
fn ui_key_rows_esc(m: &Model, width: u16, esc: Option<&str>) -> Vec<Line<'static>> {
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
    let entries = [
        ("tab", "switch"),
        ("↑/k", "up"),
        ("↓/j", "down"),
        ("r", "read legacy"),
        ("S", "shield"),
        ("M", "mint"),
        ("C", "claim"),
        (
            "esc",
            if m.coins.mint.dialog.is_some() {
                "cancel mint"
            } else if m.coins.shield.dialog.is_some() {
                "cancel shield"
            } else {
                "stop shield"
            },
        ),
        ("n", compact),
        ("c", colors),
        ("v", "notice level"),
        ("t", refresh.as_str()),
        ("[/] {/}", "upper/lower edge"),
        ("?", "hide keys"),
        ("h", "help"),
        ("q", "quit"),
    ];
    let mut spans = vec![Span::styled(
        "UI:",
        Style::new().fg(HELP).add_modifier(Modifier::BOLD),
    )];
    // A key that does not apply to the selection: left out when compact,
    // dimmed when expanded; pressing it says why.
    for (key, description) in entries {
        let description = match esc {
            Some(esc) if key == "esc" => esc,
            _ => description,
        };
        let usable = coins::key_refusal(m, key).is_none();
        push_key_hint(&mut spans, m, key, description, usable);
    }
    wrap_actions(Line::from(spans), width)
}

pub(super) fn render(f: &mut Frame, m: &mut Model, area: Rect) {
    let header = header_lines(m, area.width);
    let actions = key_rows(m, area.width);
    let reserved = key_rows_height(m, |m| ui_key_rows_reserved(m, area.width));
    let actions = pad_key_rows(actions, reserved);
    let inner_width = area.width.saturating_sub(2);
    let balances = table_lines(m, inner_width);
    let balance_detail = wrap_message(
        Line::from(Span::styled(detail(m), Style::new().fg(HELP))),
        inner_width,
    );
    let notices = notice_lines(m, inner_width);
    let fixed = header.len() as u16 + actions.len() as u16;
    let rest = area.height.saturating_sub(fixed);
    // Heights follow the terminal and the edge keys, never the cursor
    // row's detail or the notices shown. Balances reserves its rows and
    // BALANCE_DETAIL lines, then its edge moves; of the lines it leaves
    // as drawn, the middle panel takes MIDDLE_LINES first, then
    // Notifications up to NOTICE_LINES, the middle panel the rest: inside
    // borders, Notifications' lines are clamp(left - MIDDLE_LINES - 4, 1,
    // NOTICE_LINES), 4 for the two panels' borders. A short terminal or a
    // taller Balances so takes the notices' spare lines before the
    // content's; Balances leaves at least nine by default, so the middle
    // panel keeps four lines and Notifications one.
    let balances_h = (balances.len() as u16 + BALANCE_DETAIL + 2).min(rest.saturating_sub(9));
    let [balances_h, plan_h, notice_h] = coins::place_panels(m, rest, balances_h, |left| {
        left.saturating_sub(MIDDLE_LINES + 4).clamp(1, NOTICE_LINES) + 2
    });
    let chunks = Layout::vertical([
        Constraint::Length(header.len() as u16),
        Constraint::Length(balances_h),
        Constraint::Length(plan_h),
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
    // The cursor row's detail keeps to the panel's bottom, as in
    // Allocations; the rows do not scroll, so it never displaces one.
    let keep = balances.len() as u16;
    let balance_detail = fit_detail(balance_detail, inner.width, inner.height, keep);
    let balances = fit_lines(balances, inner.width, inner.height);
    f.render_widget(
        Paragraph::new(pin_detail(balances, balance_detail, inner.height)),
        inner,
    );
    let plan_area = chunks[2];
    let (title, lines, scroll) = middle_lines(
        m,
        plan_area.width.saturating_sub(2),
        plan_area.height.saturating_sub(2),
    );
    let dialog = matches!(m.coins.shield.dialog, Some(Dialog::Confirm(_)))
        || matches!(m.coins.mint.dialog, Some(MintDialog::Confirm(_)));
    let block = bordered(title, dialog || m.coins.focus == CoinsFocus::Middle);
    let inner = block.inner(plan_area);
    f.render_widget(block, plan_area);
    f.render_widget(
        Paragraph::new(fit_lines(lines, inner.width, inner.height)),
        inner,
    );
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
        assert!(legacy.contains("4/10"), "{legacy}");
        assert!(!legacy.contains("shielded ·"), "{legacy}");
        assert!(legacy.contains("◆ unshielded"), "{legacy}");
        assert!(
            text.contains("◆ Legacy coins unshielded: ‹S› shields them."),
            "{text}"
        );
        // The claimable row is selected: the legacy keys are left out.
        assert!(!text.contains("read legacy"), "{text}");
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
            text.contains("Legacy coins: 6 shielded; read 8 pages in 6.2s"),
            "{text}"
        );
        assert!(
            text.contains("‹r› read legacy") && text.contains("‹S› shield"),
            "{text}"
        );
    }

    /// The middle panel follows the Balances selection and its title names
    /// it; a running shield stays on the legacy row and in Notifications
    /// with the claimable reward selected.
    /// The legacy row counts the unshielded of all listed coins, `0`
    /// once none is (its state says which), at every width.
    #[test]
    fn the_legacy_row_counts_unshielded_of_all_listed_coins() {
        let mut m = loaded();
        m.color_coding = false;
        m.coins.cursor = 1;
        for (unshielded, shielded, coins, state) in [
            (4, 6, "4/10", "◆ unshielded"),
            (0, 6, "0", "shielded"),
            (0, 0, "0", "none"),
        ] {
            if let Some((Some(snapshot), _, _)) = m.coins.legacy.answer.as_mut() {
                snapshot.tally.unshielded = unshielded;
                snapshot.tally.shielded = shielded;
            }
            for width in [80, 120, 200] {
                let text = render_text(&mut m, width, 40);
                let row = text
                    .lines()
                    .find(|line| {
                        line.trim_start_matches('│')
                            .trim_start()
                            .starts_with("legacy")
                    })
                    .unwrap_or_else(|| panic!("no legacy row in\n{text}"));
                let cells: Vec<&str> = row
                    .trim_matches('│')
                    .split("  ")
                    .map(str::trim)
                    .filter(|cell| !cell.is_empty())
                    .collect();
                assert_eq!(cells[1], coins, "{width}\n{text}");
                assert!(cells.contains(&state), "{width}\n{text}");
            }
        }
    }

    /// The legacy row's detail adds the shielded count the row's U/T
    /// leaves out, and repeats neither the unshielded count nor the
    /// Shield plan's figures.
    #[test]
    fn the_legacy_detail_adds_the_shielded_count() {
        let mut m = loaded();
        m.coins.cursor = 1;
        for (unshielded, shielded) in [(4, 6), (0, 6), (0, 0)] {
            if let Some((Some(snapshot), _, _)) = m.coins.legacy.answer.as_mut() {
                snapshot.tally.unshielded = unshielded;
                snapshot.tally.shielded = shielded;
            }
            let text = detail(&m);
            assert!(
                !text.contains("unshielded") && !text.contains("batch"),
                "{text}"
            );
            if shielded > 0 {
                let split = format!("Legacy coins: {shielded} shielded; read 8 pages");
                assert!(text.starts_with(&split), "{text}");
            } else {
                assert!(text.starts_with("Legacy coins: read 8 pages"), "{text}");
            }
        }
    }

    #[test]
    fn the_middle_panel_follows_the_selection_and_a_run_stays_visible() {
        use super::super::super::shield::{self, Progress};
        let mut m = loaded();
        m.color_coding = false;
        for width in [80, 160] {
            m.coins.cursor = 0;
            let text = render_text(&mut m, width, 40);
            assert!(text.contains("╭ Claim status"), "{width}\n{text}");
            assert!(!text.contains("Shield plan"), "{width}\n{text}");
            // The amount is the Balances row's alone.
            assert!(!text.contains("312500.000000000000"), "{text}");
            assert_eq!(text.matches("312500").count(), 1, "{text}");
            assert!(
                text.contains("Authorization: ‹M› authorizes a mint of the claimable reward"),
                "{text}"
            );
            m.coins.cursor = 1;
            let text = render_text(&mut m, width, 40);
            assert!(text.contains("╭ Shield plan"), "{width}\n{text}");
            assert!(!text.contains("Claim status"), "{width}\n{text}");
        }
        let request = shield::request(&mut m);
        assert!(matches!(
            request.as_slice(),
            [super::super::super::update::Cmd::ShieldPrepare]
        ));
        shield::apply_preview(&mut m, Ok(shield::shield_tests::preview()));
        super::super::super::update::handle_key(
            &mut m,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('y')),
        );
        shield::apply_progress(
            &mut m,
            Progress::Proving {
                index: 1,
                count: 2,
                coins: 96,
            },
        );
        m.coins.cursor = 0;
        for width in [80, 160] {
            let text = render_text(&mut m, width, 40);
            let legacy = text
                .lines()
                .find(|line| line.trim_start_matches('│').starts_with("legacy"))
                .unwrap();
            assert!(legacy.contains("shielding 1/2"), "{width}\n{text}");
            assert!(text.contains("╭ Claim status"), "{width}\n{text}");
            assert!(
                text.contains("Shield batch 1/2: proving 96 coins <60s."),
                "{width}\n{text}"
            );
        }
    }

    /// A paced run renders its waits as notices: a held batch while GLOBAL
    /// is degraded (a warning), the included batches with the projected
    /// end, and ‹esc›'s stop question as the key row; a render still hides
    /// the shielded amount without --reveal.
    #[test]
    fn a_paced_run_renders_its_waits_and_its_stop_question() {
        use super::super::super::shield::{self, Progress};
        use crossterm::event::{KeyCode, KeyEvent};
        let mut m = loaded();
        m.color_coding = false;
        m.mask_private = true;
        m.coins.cursor = 1;
        shield::request(&mut m);
        shield::apply_preview(&mut m, Ok(shield::shield_tests::preview()));
        super::super::super::update::handle_key(&mut m, KeyEvent::from(KeyCode::Char('y')));
        let end = std::time::SystemTime::now() + Duration::from_secs(1_800);
        let end = end.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        for progress in [
            Progress::Proving {
                index: 1,
                count: 2,
                coins: 96,
            },
            Progress::Proved { index: 1, count: 2 },
            Progress::Submitted {
                index: 1,
                count: 2,
                addresses: vec![[1; 32]; 96],
                shielded: 7_000_000_000_000,
            },
            Progress::Included { index: 1, count: 2 },
            Progress::Projected { end },
            Progress::Proving {
                index: 2,
                count: 2,
                coins: 4,
            },
            Progress::Proved { index: 2, count: 2 },
            Progress::Paused {
                reason: "GLOBAL head 2000 has not advanced for 75 s".into(),
            },
        ] {
            shield::apply_progress(&mut m, progress);
        }
        for (width, height) in [(80, 40), (160, 40)] {
            let text = render_text(&mut m, width, height);
            println!("--- {width}x{height} ---\n{text}");
            let flat = text
                .lines()
                .map(|line| line.trim_matches(|c| c == '│' || c == ' '))
                .collect::<Vec<_>>()
                .join(" ");
            for part in [
                "Shield batch 2/2: proved and held; paused since ",
                "GLOBAL head 2000 has not advanced for 75 s; it submits after 10 min of healthy",
                "Shield: 1 batch of 2 included: 96 coins shielded; projected end ~",
            ] {
                assert!(flat.contains(part), "{width}: {part}\n{text}");
            }
            assert!(text.contains("shielding 2/2"), "{width}\n{text}");
            assert!(!text.contains("7000"), "{width}\n{text}");
        }
        super::super::super::update::handle_key(&mut m, KeyEvent::from(KeyCode::Esc));
        let text = render_text(&mut m, 120, 30);
        println!("--- 120x30 after esc ---\n{text}");
        assert!(
            text.contains(
                "Stop shield: ‹y› stop before the next submission  any other key keeps it running"
            ),
            "{text}"
        );
    }

    /// Without --reveal a render hides the confirmation's amount and the
    /// recipient's address, and the shielded amount of included batches.
    #[test]
    fn a_render_masks_private_wallet_fields_unless_revealed() {
        use super::super::super::shield::{self, Progress};
        let recipient = format!("0x{}{}", "5143".repeat(10), "cf00".repeat(10));
        let confirm = |mask: bool| {
            let mut m = loaded();
            m.color_coding = false;
            m.mask_private = mask;
            m.coins.cursor = 1;
            m.coins.shield.dialog = Some(shield::Dialog::Confirm(Preview {
                recipient: recipient.clone(),
                units: 8_000_000_000_000,
                ..shield::shield_tests::preview()
            }));
            let text = render_text(&mut m, 160, 40);
            super::super::super::update::handle_key(
                &mut m,
                crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('y')),
            );
            shield::apply_progress(
                &mut m,
                Progress::Submitted {
                    index: 1,
                    count: 2,
                    addresses: vec![[1; 32]],
                    shielded: 7_000_000_000_000,
                },
            );
            if let Some(run) = m.coins.shield.run.as_mut() {
                run.submitted[0].included = true;
            }
            (text, render_text(&mut m, 160, 40))
        };
        let (masked, masked_after) = confirm(true);
        for line in [
            "Amount: hidden in this render (--reveal shows it)",
            "Recipient: this node's wallet, its address hidden in this render (--reveal shows it)",
        ] {
            assert!(masked.contains(line), "{line}\n{masked}");
        }
        assert!(
            masked_after.contains("Shield: 1 batch of 2 included: 1 coins shielded."),
            "{masked_after}"
        );
        let (revealed, revealed_after) = confirm(false);
        for text in [&masked, &masked_after] {
            for private in ["1000.000000000000", "51435143", "cf00cf00", " 875 Q"] {
                assert!(!text.contains(private), "{private}\n{text}");
            }
        }
        assert!(
            revealed.contains("Amount: 1000.000000000000 Q, less the fees"),
            "{revealed}"
        );
        assert!(
            revealed.contains("Recipient: this node's wallet, 0x514351435143…cf00cf00cf00"),
            "{revealed}"
        );
        assert!(
            revealed_after.contains("included: 1 coins, 875 Q shielded."),
            "{revealed_after}"
        );
    }

    /// The Balances and middle panels' text of a render, Notifications
    /// left out.
    fn upper_panels(text: &str) -> String {
        text.lines()
            .take_while(|line| !line.starts_with("╭ Notifications"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The claimable amount shows once on the tab, in its Balances row;
    /// the Claim status adds the action, not the amount.
    #[test]
    fn the_claimable_amount_shows_in_its_row_only() {
        let mut m = loaded();
        m.color_coding = false;
        m.coins.cursor = 0;
        for width in [80, 120, 200] {
            let text = render_text(&mut m, width, 40);
            let panels = upper_panels(&text);
            assert_eq!(panels.matches("312500").count(), 1, "{text}");
            assert!(text.contains("╭ Claim status"), "{text}");
            assert!(
                text.contains("Authorization: ‹M› authorizes a mint of the claimable reward"),
                "{text}"
            );
        }
    }

    /// The claimable frame shows once, in the row's `As of`; its detail
    /// says where the figure comes from.
    #[test]
    fn the_claimable_frame_shows_in_its_row_only() {
        let mut m = loaded();
        m.color_coding = false;
        m.coins.cursor = 0;
        for width in [80, 120, 200] {
            let text = render_text(&mut m, width, 40);
            assert_eq!(upper_panels(&text).matches("f1200").count(), 1, "{text}");
            assert!(
                detail(&m).starts_with("Claimable: the reward balance"),
                "{text}"
            );
        }
    }

    /// Coins notices name a condition and its key, never a figure their
    /// rows or panels show: amount, frame, counts or batches.
    #[test]
    fn coins_notices_name_conditions_not_figures() {
        let mut m = loaded();
        m.notice_minimum = NoticeSeverity::Info;
        let texts: Vec<String> = coins::notices(&m, fmt_claimable)
            .into_iter()
            .map(|notice| notice.text)
            .collect();
        assert!(
            texts.contains(&"Reward claimable: ‹M› authorizes a mint.".to_string()),
            "{texts:?}"
        );
        for text in &texts {
            for figure in [
                "312500",
                "f1200",
                "4 unshielded",
                "6 shielded",
                "2 batches",
                "1 on",
            ] {
                assert!(!text.contains(figure), "{figure} in {text}");
            }
        }
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

    /// A Coins key that does not apply to the selection: left out when
    /// compact, dimmed when expanded (`(k)` with colors off, the color alone
    /// with them on). Every hint shows whole at 80, 120 and 200 columns.
    #[test]
    fn coins_keys_hide_when_compact_and_dim_when_expanded() {
        let mut m = loaded();
        m.color_coding = false;
        m.show_key_rows = true;
        // The key rows: from `UI:` to the end.
        let keys = |m: &mut Model, width| {
            let text = render_text(m, width, 40);
            text[text.rfind("UI:").unwrap()..].to_string()
        };
        for width in [80, 120, 200] {
            m.coins.focus = CoinsFocus::Balances;
            m.coins.cursor = 0;
            m.compact_actions = true;
            let text = keys(&mut m, width);
            for hint in ["‹↓/j› down", "‹h› help", "‹t› refresh"] {
                assert!(text.contains(hint), "{hint} at {width}\n{text}");
            }
            for key in [
                "‹S› shield",
                "(S) shield",
                "read legacy",
                "‹↑/k› up",
                "(↑/k) up",
            ] {
                assert!(!text.contains(key), "{key} at {width}\n{text}");
            }
            m.compact_actions = false;
            let text = keys(&mut m, width);
            for hint in ["(S) shield", "(r) read legacy", "(↑/k) up", "‹↓/j› down"] {
                assert!(text.contains(hint), "{hint} at {width}\n{text}");
            }
            m.coins.cursor = 1;
            for compact in [true, false] {
                m.compact_actions = compact;
                let text = keys(&mut m, width);
                for hint in ["‹S› shield", "‹r› read legacy", "‹↑/k› up"] {
                    assert!(text.contains(hint), "{hint} at {width}\n{text}");
                }
            }
        }
        // `M` on the claimable row and in its Claim status; `C` in the Claim
        // status only, with a saved authorization under its cursor.
        m.coins.cursor = 0;
        m.compact_actions = true;
        let text = keys(&mut m, 120);
        assert!(
            text.contains("‹M› mint") && !text.contains("claim"),
            "{text}"
        );
        m.compact_actions = false;
        let text = keys(&mut m, 120);
        assert!(
            text.contains("‹M› mint") && text.contains("(C) claim"),
            "{text}"
        );
        m.coins.cursor = 1;
        let text = keys(&mut m, 120);
        assert!(text.contains("(M) mint"), "{text}");
        m.coins.cursor = 0;
        m.coins.focus = CoinsFocus::Middle;
        let text = keys(&mut m, 120);
        assert!(
            text.contains("‹M› mint") && text.contains("(C) claim"),
            "no saved authorization to claim\n{text}"
        );
        m.coins.mint.saved = vec![super::super::super::mint::Saved {
            path: "/x/mint-1200.bin".into(),
            cited_frame: 1200,
            amounts: Some((900, 9)),
        }];
        let text = keys(&mut m, 120);
        assert!(
            text.contains("‹M› mint") && text.contains("‹C› claim"),
            "{text}"
        );
        m.coins.focus = CoinsFocus::Balances;
        m.coins.mint.saved.clear();
        m.coins.cursor = 0;
        m.color_coding = true;
        let text = keys(&mut m, 120);
        assert!(
            text.contains("‹S› shield") && !text.contains("(S)"),
            "{text}"
        );
    }

    /// A moved edge draws at 80 and 160 columns, and the edge keys show,
    /// compact or not, while an edge of the focused panel can move.
    #[test]
    fn a_moved_coins_edge_draws_at_both_widths() {
        let mut m = loaded();
        m.color_coding = false;
        m.show_key_rows = true;
        // Each panel's drawn height, from the rows its top borders are on.
        let drawn = |text: &str| {
            let top = |title: &str| {
                text.lines()
                    .position(|line| line.starts_with(&format!("╭ {title}")))
                    .unwrap()
            };
            let tops = [top("Balances"), top("Claim status"), top("Notifications")];
            [tops[1] - tops[0], tops[2] - tops[1]]
        };
        for width in [80, 160] {
            m.coins.edges = [0, 0];
            let base = drawn(&render_text(&mut m, width, 40));
            m.coins.edges = [2, -1];
            let text = render_text(&mut m, width, 40);
            assert_eq!(drawn(&text), [base[0] + 2, base[1] - 3], "{text}");
            assert_eq!(m.coins.edges, [2, -1]);
            for compact in [true, false] {
                m.compact_actions = compact;
                let text = render_text(&mut m, width, 40);
                assert!(text.contains("‹[/] {/}› upper/lower edge"), "{text}");
            }
        }
    }

    /// The Claim status lists the saved authorizations, and both mint
    /// confirmations draw there, masked unless revealed; with
    /// `QCLIENT_RENDER_DIR` set, each frame is also written there.
    #[test]
    fn claim_status_lists_authorizations_and_mint_confirmations_draw() {
        use super::super::super::mint::{self, Saved, Stage};
        let dump = |name: &str, text: &str| {
            if let Ok(dir) = std::env::var("QCLIENT_RENDER_DIR") {
                std::fs::write(format!("{dir}/{name}.txt"), text).unwrap();
            }
        };
        let mut m = loaded();
        m.color_coding = false;
        m.coins.mint.saved = vec![Saved {
            path: "/cfg/mint-1200.bin".into(),
            cited_frame: 1200,
            amounts: Some((80_000_000_000, 8_000_000)),
        }];
        for width in [80, 120] {
            let text = render_text(&mut m, width, 40);
            dump(&format!("offline-claim-status-{width}x40"), &text);
            assert!(text.contains("╭ Claim status"), "{text}");
            assert!(text.contains("Cited  Amount [Q]  Fee [Q]  State"), "{text}");
            assert!(
                text.contains("f1200     9.99900  0.00100  unavailable"),
                "{text}"
            );
            // The claimable row is selected: `M` acts, `C` waits for the
            // Claim status.
            assert!(
                text.contains("‹M› mint") && !text.contains("‹C› claim"),
                "{text}"
            );
        }
        let preview = |stage| mint::Preview {
            stage,
            cited_frame: 1200,
            reward: 80_000_000_000,
            fee: 8_000_000,
            max_fee: 800_000_000,
            recipient: format!("0x{}", "cd".repeat(40)),
        };
        // A confirmation shows in the Claim status whichever row is
        // selected.
        m.coins.cursor = 1;
        m.coins.mint.dialog = Some(mint::Dialog::Confirm(preview(Stage::Authorize)));
        let text = render_text(&mut m, 120, 40);
        dump("offline-mint-confirm-120x40", &text);
        for line in [
            "Confirm mint",
            "Reward: 10.000000000000 Q claimable at f1200, from the GLOBAL reward witness",
            "Amount: 9.999000000000 Q (reward 10.000000000000 Q less fee 0.001000000000 Q)",
            "Fee: 8000000 base units (0.001000000000 Q) as quoted now, paid from the reward",
            "Cap: 0.1 Q (--max-fee); a higher quote is refused",
            "Recipient: this node's wallet, 0xcdcdcdcdcdcd",
            "Saved as: mint-<frame>.bin in the node config directory, for the claim",
            "Confirm: ‹y› authorize the mint  any other key cancels",
        ] {
            assert!(text.contains(line), "{line}\n{text}");
        }
        // The run's re-read, unwrapped: a grown reward is minted, a
        // changed fee reopens it.
        let help: String = mint_confirm_lines(&preview(Stage::Authorize), 400, false)
            .iter()
            .flat_map(|line| line.spans.iter().map(|span| span.content.to_string()))
            .collect();
        assert!(
            help.contains(
                "The run reads the reward and quotes the fee again at the frame then current: a \
                 reward that grew is minted in full to this wallet, and the outcome names both \
                 amounts; a changed fee reopens this confirmation with it; a reward that fell \
                 stops the run."
            ),
            "{help}"
        );
        m.mask_private = true;
        let text = render_text(&mut m, 120, 40);
        dump("offline-mint-confirm-masked-120x40", &text);
        for line in [
            "Reward: hidden in this render (--reveal shows it); claimable at f1200",
            "Amount: hidden in this render (--reveal shows it)",
            "Recipient: this node's wallet, its address hidden in this render",
        ] {
            assert!(text.contains(line), "{line}\n{text}");
        }
        for private in ["10.000000000000", "9.999000000000", "cdcdcd"] {
            assert!(!text.contains(private), "{private}\n{text}");
        }
        m.mask_private = false;
        // A run that found the reward grown at the confirmed fee mints it
        // and names both amounts and the frame its authorization cites.
        mint::dialog_key(
            &mut m,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('y')),
        );
        mint::apply_progress(
            &mut m,
            mint::Progress::Submitted {
                cited_frame: 1204,
                reward: 84_000_000_000,
                saved: "/cfg/mint-1204.bin".into(),
            },
        );
        mint::apply_progress(&mut m, mint::Progress::Done(Ok(())));
        for width in [80, 200] {
            let text = render_text(&mut m, width, 40);
            dump(&format!("offline-mint-grown-{width}x40"), &text);
            if width == 200 {
                assert!(
                    text.contains(
                        "Mint f1204: authorization of 10.499 Q submitted (confirmed 9.999 Q; \
                         the reward grew); inclusion not yet confirmed; ‹C› claims it once \
                         GLOBAL finalizes it."
                    ),
                    "{text}"
                );
            }
            assert!(!text.contains("Confirm mint"), "{text}");
        }
        // One that found the fee quoted otherwise opens the confirmation
        // again with it.
        m.coins.mint.run = None;
        m.coins.mint.dialog = Some(mint::Dialog::Confirm(preview(Stage::Authorize)));
        mint::dialog_key(
            &mut m,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('y')),
        );
        mint::apply_progress(
            &mut m,
            mint::Progress::Requoted(mint::Preview {
                cited_frame: 1205,
                fee: 8_800_000,
                ..preview(Stage::Authorize)
            }),
        );
        let text = render_text(&mut m, 120, 40);
        dump("offline-mint-fee-requoted-120x40", &text);
        for line in [
            "Mint: the fee quote changed from 8000000 to 8800000 base units; confirm again.",
            "Fee: 8800000 base units (0.001100000000 Q) as quoted now, paid from the reward",
        ] {
            assert!(text.contains(line), "{line}\n{text}");
        }
        m.coins.mint.requoted = None;
        m.coins.mint.dialog = Some(mint::Dialog::Confirm(preview(Stage::Claim {
            path: "/cfg/mint-1200.bin".into(),
            witness: 1250,
        })));
        let text = render_text(&mut m, 120, 40);
        dump("offline-mint-claim-confirm-120x40", &text);
        assert!(
            text.contains("Authorization: mint-1200.bin, citing f1200; finalized, its GLOBAL witness cites f1250"),
            "{text}"
        );
        assert!(
            text.contains("Confirm: ‹y› claim  any other key cancels"),
            "{text}"
        );
        assert!(!text.contains("/cfg/"), "{text}");
    }

    /// The Provers rows follow the same rule, and pressing a key that does
    /// not apply, shown or not, only says why.
    #[test]
    fn provers_keys_hide_when_compact_dim_when_expanded_and_say_why() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut m = loaded();
        m.tab = Tab::Provers;
        m.color_coding = false;
        m.show_key_rows = true;
        m.focus = PanelFocus::Notifications;
        for width in [80, 160] {
            m.compact_actions = true;
            let text = render_text(&mut m, width, 40);
            assert!(
                !text.contains("toggle") && !text.contains("sort"),
                "{width}\n{text}"
            );
            m.compact_actions = false;
            let text = render_text(&mut m, width, 40);
            for hint in [
                "(space) toggle",
                "(s) sort",
                "(L) leave",
                "‹v› notice level",
            ] {
                assert!(text.contains(hint), "{hint} at {width}\n{text}");
            }
        }
        for compact in [true, false] {
            m.compact_actions = compact;
            m.focus = PanelFocus::Notifications;
            m.status_msg.clear();
            let space = KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE);
            assert!(super::super::super::update::handle_key(&mut m, space).is_empty());
            assert_eq!(
                m.status_msg,
                "Notifications: ‹space› applies to the Allocations and Available Shards tables; \
                 ‹tab› selects one."
            );
            // It shows at the default notice level.
            let text = render_text(&mut m, 160, 40);
            assert!(
                text.contains("Notifications: ‹space› applies to the Allocations and Available"),
                "{text}"
            );
            let leave = KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL);
            assert!(super::super::super::update::handle_key(&mut m, leave).is_empty());
            assert_eq!(
                m.status_msg,
                "Workers: ‹Ctrl+L› leave acts on the Allocations table; ‹tab› selects it."
            );
            m.focus = PanelFocus::Allocations;
            assert!(super::super::super::update::handle_key(&mut m, leave).is_empty());
            assert_eq!(m.status_msg, "Workers: no allocation selected.");
            assert!(m.operation_confirmation.is_none() && !m.sort_mode);
        }
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
    /// While a mint or a shield is prepared, ‹esc› names what it cancels.
    #[test]
    fn esc_names_the_preparation_it_cancels() {
        let mut m = loaded();
        m.coins.mint.dialog = Some(MintDialog::Preparing(std::time::Instant::now(), false));
        let text = render_text(&mut m, 200, 40);
        assert!(text.contains("cancel mint"), "{text}");
        m.coins.mint.dialog = None;
        m.coins.shield.dialog = Some(Dialog::Preparing(std::time::Instant::now()));
        let text = render_text(&mut m, 200, 40);
        assert!(text.contains("cancel shield"), "{text}");
    }

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
        m.coins.cursor = 1;
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
        // At 32 lines the rows read below stay in view beside a taller
        // Balances panel; a shorter terminal ends the question in the marker.
        let text = render_text(&mut m, 120, 32);
        dump("offline-shield-confirm-120x32", &text);
        for line in [
            "Confirm shield",
            "Coins: 4 of 8 listed legacy coins, in 2 batches of up to 96 coins, one shard each",
            "Amount: 1000.000000000000 Q, less the fees",
            "Recipient: this node's wallet, 0xabababababab…abababababab (40 bytes;",
            "Fee: 16000 base units (0.000002000000 Q) in total as quoted now, up to 9000 per batch",
            "Cap: 0.1 Q per batch (--max-fee); a higher quote stops the run",
            "Left out: 2 already shielded; 1 on no live shard, for a later run; 1 submitted <2h",
            "Confirm: ‹y› shield  any other key cancels",
        ] {
            assert!(text.contains(line), "{line}\n{text}");
        }
        // Any key but `y` cancels, and says so at the default level.
        let mut cancelled = loaded();
        cancelled.coins.cursor = 1;
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
        assert!(!text.contains("‹S› shields the rest"), "{text}");
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
        // The run failed between batches: no batch was being proved or
        // held, and one stays submitted.
        assert!(
            text.contains("Shield: the run stopped after 1 batch of 2 submitted: fee changed"),
            "{text}"
        );
        assert!(!text.contains("nothing was submitted"), "{text}");
    }

    /// The render rows of the panels' top and bottom borders.
    fn borders(text: &str) -> Vec<usize> {
        text.lines()
            .enumerate()
            .filter(|(_, line)| line.starts_with('╭') || line.starts_with('╰'))
            .map(|(i, _)| i)
            .collect()
    }

    /// The Balances panel keeps its height while the cursor moves between
    /// rows whose details differ in length; expanded keys, which show
    /// every key, keep the key rows out of it.
    #[test]
    fn balances_height_ignores_the_cursor_rows_detail() {
        let mut m = loaded();
        m.color_coding = false;
        m.compact_actions = false;
        m.claimable_reward = None;
        // Here the claimable detail takes one line at 80 columns and the
        // legacy detail two.
        let width = 80;
        for height in [24, 40] {
            m.coins.cursor = 0;
            let text = render_text(&mut m, width, height);
            m.coins.cursor = 1;
            let moved = render_text(&mut m, width, height);
            assert_eq!(borders(&moved), borders(&text), "{text}\n{moved}");
        }
    }

    /// The key rows keep their height across cursor and focus moves and a
    /// confirmation, though compact mode leaves out the keys that do not
    /// apply and a confirmation shows one row: Notifications' bottom
    /// border, right above them, stays put.
    #[test]
    fn coins_key_rows_keep_their_height_across_moves_and_questions() {
        let mut m = loaded();
        m.color_coding = false;
        m.compact_actions = true;
        for (width, height) in [(80, 24), (100, 30), (120, 40), (160, 40), (200, 60)] {
            m.coins.shield.dialog = None;
            m.coins.focus = CoinsFocus::Balances;
            m.coins.cursor = 0;
            let text = render_text(&mut m, width, height);
            let bottom = *borders(&text).last().unwrap();
            for (focus, cursor) in [
                (CoinsFocus::Balances, 1),
                (CoinsFocus::Middle, 1),
                (CoinsFocus::Notifications, 1),
                (CoinsFocus::Middle, 0),
            ] {
                m.coins.focus = focus;
                m.coins.cursor = cursor;
                let moved = render_text(&mut m, width, height);
                assert_eq!(
                    *borders(&moved).last().unwrap(),
                    bottom,
                    "{width}x{height} {focus:?} row {cursor}\n{text}\n{moved}"
                );
            }
            m.coins.shield.dialog = Some(super::super::super::shield::Dialog::Confirm(
                super::super::super::shield::shield_tests::preview(),
            ));
            let asked = render_text(&mut m, width, height);
            assert!(asked.contains("Confirm: ‹y› shield"), "{asked}");
            assert_eq!(
                *borders(&asked).last().unwrap(),
                bottom,
                "{width}x{height} confirm\n{text}\n{asked}"
            );
        }
    }

    /// Notifications keeps its height however many notices it shows.
    #[test]
    fn coins_panel_borders_ignore_the_notices_shown() {
        let mut m = loaded();
        m.color_coding = false;
        m.compact_actions = false;
        for (width, height) in [(80, 24), (120, 40)] {
            m.status_msg.clear();
            let text = render_text(&mut m, width, height);
            m.status_msg = "Shield: a long reply to a key ".repeat(12);
            m.status_is_error = true;
            m.status_message_time = Some(SystemTime::now());
            let busy = render_text(&mut m, width, height);
            assert!(busy.contains("a long reply"), "{busy}");
            assert_eq!(borders(&busy), borders(&text), "{text}\n{busy}");
        }
    }

    /// A panel's inner lines, borders and edge spaces trimmed, from the
    /// render row under its `title` to the one above its bottom border.
    fn panel_inner(text: &str, title: &str) -> Vec<String> {
        let lines: Vec<&str> = text.lines().collect();
        let top = lines
            .iter()
            .position(|line| line.starts_with(&format!("╭ {title}")))
            .unwrap_or_else(|| panic!("no {title} panel in\n{text}"));
        let height = lines[top + 1..]
            .iter()
            .position(|line| line.starts_with('╰'))
            .unwrap();
        lines[top + 1..top + 1 + height]
            .iter()
            .map(|line| line.trim_matches('│').trim().to_string())
            .collect()
    }

    /// `detail` fills the panel's last inner lines, after a blank line
    /// that parts it from the `rows` lines of content above it.
    fn assert_pinned(inner: &[String], rows: usize, detail: &[String], text: &str) {
        assert!(inner.len() > rows + detail.len(), "panel too short\n{text}");
        assert_eq!(&inner[inner.len() - detail.len()..], detail, "{text}");
        assert!(
            inner[rows].is_empty(),
            "detail right under the rows\n{text}"
        );
    }

    /// The text of `text` wrapped to `width`, each line trimmed.
    fn wrapped(text: &str, width: u16) -> Vec<String> {
        wrap_message(Line::from(text.to_string()), width)
            .iter()
            .map(|line| line.to_string().trim().to_string())
            .collect()
    }

    /// A model whose Claim status lists a saved authorization and whose
    /// Shield plan lists two batches.
    fn with_rows() -> Model {
        let mut m = loaded();
        m.color_coding = false;
        m.coins.mint.saved = vec![super::super::super::mint::Saved {
            path: "/cfg/mint-1200.bin".into(),
            cited_frame: 1200,
            amounts: Some((80_000_000_000, 8_000_000)),
        }];
        if let Some((Some(snapshot), _, _)) = m.coins.legacy.answer.as_mut() {
            snapshot.batches = vec![
                crate::commands::token::legacy::PlanBatch {
                    filter: [vec![0x11; 32], vec![0x90, 0x00, 0x91]].concat(),
                    coins: 3,
                    units: 6_000_000_000_000,
                };
                2
            ];
        }
        m
    }

    /// In a Balances panel taller than its content the cursor row's
    /// detail fills its last lines, as Allocations does, the rows at the
    /// top.
    #[test]
    fn the_balances_detail_keeps_to_the_panel_bottom() {
        let mut m = with_rows();
        for (width, height) in [(100, 70), (200, 60)] {
            m.coins.edges = [6, 0];
            m.coins.cursor = 0;
            let text = render_text(&mut m, width, height);
            let balances = panel_inner(&text, "Balances");
            let rows = table_lines(&m, width - 2).len();
            assert_pinned(&balances, rows, &wrapped(&detail(&m), width - 2), &text);
        }
    }

    /// A shield confirmation keeps its Recipient in view in a short
    /// panel: the other rows give way to the enlarge marker. Moving the
    /// Balances edge down stands in for more balance rows.
    #[test]
    fn a_short_shield_confirmation_keeps_its_recipient() {
        let mut m = loaded();
        m.color_coding = false;
        let mut preview = super::super::super::shield::shield_tests::preview();
        preview.recipient = format!("0x{}", "ab".repeat(40));
        let full = |width: u16| confirm_lines(&preview, width - 2, u16::MAX, false).len();
        let full = [full(80), full(120)];
        m.coins.shield.dialog = Some(super::super::super::shield::Dialog::Confirm(preview));
        for ((width, height), full) in [(80, 24), (120, 30)].into_iter().zip(full) {
            for edge in [0, 1, 2] {
                m.coins.edges = [edge, 0];
                let text = render_text(&mut m, width, height);
                let inner = panel_inner(&text, "Confirm shield");
                assert!(
                    inner
                        .iter()
                        .any(|line| line.starts_with("Recipient: this node's wallet")),
                    "{width}x{height} edge {edge}: no Recipient\n{text}"
                );
                if inner.len() < full {
                    assert_eq!(
                        inner.last().map(String::as_str),
                        Some("… enlarge panel for details"),
                        "{width}x{height} edge {edge}\n{text}"
                    );
                }
            }
        }
    }

    /// The Claim status keeps its State note on its last lines, under the
    /// saved authorizations.
    #[test]
    fn the_claim_status_note_keeps_to_the_panel_bottom() {
        let mut m = with_rows();
        for (width, height) in [(100, 70), (200, 60)] {
            m.coins.cursor = 0;
            let text = render_text(&mut m, width, height);
            let claim = panel_inner(&text, "Claim status");
            let note = wrapped(
                "State: this node reports no authorization status; ‹C› checks for the finalized \
                 witness before it claims.",
                width - 2,
            );
            let saved = claim
                .iter()
                .position(|line| line.starts_with("f1200"))
                .unwrap();
            assert_pinned(&claim, saved + 1, &note, &text);
        }
    }

    /// The Shield plan keeps its footer on its last line, under the
    /// batch rows.
    #[test]
    fn the_shield_plan_footer_keeps_to_the_panel_bottom() {
        let mut m = with_rows();
        for (width, height) in [(100, 70), (200, 60)] {
            m.coins.cursor = 1;
            let text = render_text(&mut m, width, height);
            let plan = panel_inner(&text, "Shield plan");
            assert_pinned(
                &plan,
                3,
                &["Batches: 2 of ≤96 coins; 1 coins on no live shard".to_string()],
                &text,
            );
        }
    }

    /// A Balances panel too short for its detail keeps every row: with no
    /// line beyond the rows it shows none, with one it shows the marker.
    #[test]
    fn a_short_balances_panel_keeps_its_rows_before_the_detail() {
        let mut m = loaded();
        m.color_coding = false;
        m.coins.cursor = 0;
        let width = 80;
        assert!(wrap_message(Line::from(detail(&m)), width - 2).len() > 1);
        for (edge, last) in [(-2, None), (-1, Some("… enlarge panel for details"))] {
            m.coins.edges = [edge, 0];
            let text = render_text(&mut m, width, 40);
            let inner = panel_inner(&text, "Balances");
            let rows = table_lines(&m, width - 2).len();
            assert!(inner[0].starts_with("Kind"), "{text}");
            assert!(inner[1].starts_with("claimable"), "{text}");
            assert!(inner[2].starts_with("legacy"), "{text}");
            match last {
                None => assert_eq!(inner.len(), rows, "{text}"),
                Some(marker) => assert_eq!(inner[rows..], [marker.to_string()], "{text}"),
            }
        }
    }

    /// A Shield plan of two lines keeps its header and a row and drops
    /// the footer; of three, the footer takes the last.
    #[test]
    fn a_short_shield_plan_keeps_a_row_before_its_footer() {
        let mut m = loaded();
        if let Some((Some(snapshot), _, _)) = m.coins.legacy.answer.as_mut() {
            snapshot.batches = vec![
                crate::commands::token::legacy::PlanBatch {
                    filter: vec![0x11; 32],
                    coins: 3,
                    units: 6_000_000_000_000,
                };
                4
            ];
        }
        for height in [2u16, 3] {
            let (_, lines, _) = plan_lines(&mut m, 100, height);
            let lines: Vec<String> = lines.iter().map(Line::to_string).collect();
            assert_eq!(lines.len(), usize::from(height), "{lines:?}");
            assert!(lines[0].starts_with("Batch"), "{lines:?}");
            assert!(lines[1].starts_with("1/4"), "{lines:?}");
            assert_eq!(
                lines.last().unwrap().starts_with("Batches:"),
                height > 2,
                "{lines:?}"
            );
        }
    }

    /// The Claim status lines at `width` columns, each trimmed.
    fn claim_text(m: &Model, width: u16) -> Vec<String> {
        claim_lines(m, width - 2, u16::MAX)
            .iter()
            .map(|line| line.to_string().trim().to_string())
            .collect()
    }

    /// On an 80x24 terminal the Claim status keeps every line, with the
    /// key rows as `?` leaves them; with the expanded rows it keeps them
    /// or ends in the enlarge marker, never dropping one unmarked.
    #[test]
    fn an_80x24_claim_status_keeps_its_lines() {
        let mut m = loaded();
        m.color_coding = false;
        m.coins.cursor = 0;
        let want = claim_text(&m, 80);
        assert!(
            want.iter()
                .any(|line| line.starts_with("Saved authorizations")),
            "{want:?}"
        );
        for show in [false, true] {
            m.show_key_rows = show;
            let text = render_text(&mut m, 80, 24);
            let claim = panel_inner(&text, "Claim status");
            if !show || claim.len() >= want.len() {
                assert!(claim.len() >= want.len(), "{text}");
                assert_eq!(claim[..want.len()], want[..], "{text}");
            } else {
                let shown = claim.len() - 1;
                assert_eq!(claim[..shown], want[..shown], "{text}");
                assert_eq!(claim[shown], "… enlarge panel for details", "{text}");
            }
        }
    }

    /// Notifications takes its height from the terminal, the same with no
    /// notice, one line and six or more: one line until the middle panel
    /// has MIDDLE_LINES, NOTICE_LINES on a tall terminal.
    #[test]
    fn coins_notifications_follow_the_terminal_not_the_notices() {
        let mut m = loaded();
        m.color_coding = false;
        m.notice_minimum = NoticeSeverity::Error;
        for show in [false, true] {
            m.show_key_rows = show;
            for (width, height) in [(80, 24), (100, 30), (120, 40), (200, 60)] {
                let mut drawn = Vec::new();
                let long = "Shield: a long reply ".repeat(80);
                for reply in ["", "Shield: a refused key", long.as_str()] {
                    m.status_msg = reply.to_string();
                    m.status_is_error = true;
                    m.status_message_time = Some(SystemTime::now());
                    let text = render_text(&mut m, width, height);
                    let notices = panel_inner(&text, "Notifications");
                    let lines = notices.iter().filter(|line| !line.is_empty()).count();
                    let all = notice_lines(&mut m, width - 2).len().max(1);
                    assert_eq!(lines, all.min(notices.len()), "{text}");
                    drawn.push((borders(&text), text));
                }
                let (edges, text) = &drawn[0];
                for (moved, busy) in &drawn[1..] {
                    assert_eq!(moved, edges, "{width}x{height}\n{text}\n{busy}");
                }
                let [_, _, middle_top, middle_bottom, notice_top, notice_bottom] = edges[..] else {
                    panic!("not three panels\n{text}");
                };
                let middle = middle_bottom - middle_top - 1;
                let notices = notice_bottom - notice_top - 1;
                assert!(
                    notices == 1 || middle >= usize::from(MIDDLE_LINES),
                    "{width}x{height}: {notices} notice lines, {middle} middle\n{text}"
                );
                if height >= 40 {
                    assert_eq!(notices, usize::from(NOTICE_LINES), "{text}");
                }
            }
        }
    }

    /// A Claim status shorter than its lines, its lower edge moved up,
    /// ends in the enlarge marker.
    #[test]
    fn a_short_claim_status_ends_in_the_marker() {
        let mut m = loaded();
        m.color_coding = false;
        m.show_key_rows = false;
        m.coins.cursor = 0;
        let want = claim_text(&m, 80);
        m.coins.edges = [0, -3];
        let text = render_text(&mut m, 80, 24);
        let claim = panel_inner(&text, "Claim status");
        assert!(claim.len() < want.len(), "{text}");
        let shown = claim.len() - 1;
        assert_eq!(claim[..shown], want[..shown], "{text}");
        assert_eq!(claim[shown], "… enlarge panel for details", "{text}");
    }

    /// Balances' moved lower edge takes Notifications' spare lines before
    /// the middle panel's: at 80x24 with the edges [1, 0] (a live
    /// `coinsPanelEdges`) the Claim status keeps every line, and while
    /// Notifications has more than one line the middle panel keeps
    /// MIDDLE_LINES.
    #[test]
    fn a_moved_balances_edge_takes_the_spare_notice_lines_first() {
        let mut m = loaded();
        m.color_coding = false;
        m.show_key_rows = false;
        m.coins.cursor = 0;
        let want = claim_text(&m, 80);
        let base = borders(&render_text(&mut m, 80, 24));
        for upper in 0..=4i16 {
            m.coins.edges = [upper, 0];
            let text = render_text(&mut m, 80, 24);
            assert_eq!(m.coins.edges, [upper, 0], "{text}");
            let drawn = borders(&text);
            let [top, bottom, middle_top, middle_bottom, notice_top, notice_bottom] = drawn[..]
            else {
                panic!("not three panels\n{text}");
            };
            assert_eq!(top, base[0], "{text}");
            assert_eq!(bottom, base[1] + upper as usize, "{text}");
            let middle = middle_bottom - middle_top - 1;
            let notices = notice_bottom - notice_top - 1;
            assert!(
                notices == 1 || middle >= usize::from(MIDDLE_LINES),
                "edges [{upper}, 0]: {notices} notice lines, {middle} middle\n{text}"
            );
            // The live case, and any split that leaves the middle panel
            // the Claim status's lines.
            if upper <= 1 || middle >= want.len() {
                let claim = panel_inner(&text, "Claim status");
                assert!(claim.len() >= want.len(), "edges [{upper}, 0]\n{text}");
                assert_eq!(claim[..want.len()], want[..], "{text}");
            }
        }
    }
}
