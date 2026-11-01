//! Drawing of the Coins tab ([`super::coins`]): the shared top header,
//! the Balances panel, the middle panel of the selected Balances row, the
//! shared notifications panel and the key rows.

use std::time::{Instant, SystemTime};

use super::super::mint::{
    Dialog as MintDialog, Preview as MintPreview, Stage as MintStage, Status as MintStatus,
};
use super::super::shield::{Dialog, Preview};
use super::super::transfer::{
    Dialog as TransferDialog, Form as TransferForm, Kind as TransferKind,
    Preview as TransferPreview,
};
use super::coins::{self, CoinsFocus, Middle, ATTENTION};
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
        plain(if total > 0 {
            format!(
                "{} unshielded · {} shielded",
                tally.unshielded, tally.shielded
            )
        } else {
            "0".into()
        }),
        plain(fmt_claimable(tally.units)),
        state,
        as_of,
    ]
}

/// This wallet's confidential coins, from the last `E` read; their amount
/// is masked in a render.
fn shielded_row(m: &Model) -> [Cell; 5] {
    let transfers = &m.coins.transfer;
    let reading = transfers.reading.map(|_| spinner(m).to_string());
    let Some(Ok((read, at))) = &transfers.read else {
        let state = match &transfers.read {
            Some(Err(_)) => unavailable(m),
            _ if reading.is_some() => plain("reading"),
            _ => plain("not read"),
        };
        return [
            plain("shielded"),
            plain("-"),
            plain("-"),
            state,
            plain(reading.unwrap_or_else(|| "-".into())),
        ];
    };
    let as_of = match &reading {
        Some(spin) => format!("{} {spin}", coins::utc_hm(*at)),
        None => coins::utc_hm(*at),
    };
    let incoming = read.escrows.iter().any(|e| !e.outgoing);
    let refundable = read
        .escrows
        .iter()
        .any(|e| e.outgoing && m.last_global_head >= e.refund_after);
    let state = if super::super::transfer::running(m) {
        ("in progress".into(), Some(PRIMARY))
    } else if incoming {
        attention("incoming")
    } else if refundable {
        attention("refundable")
    } else if read.coins.is_some_and(|(count, _)| count > 0) {
        plain("held")
    } else {
        plain("none")
    };
    let (count, total) = read.coins.unwrap_or((0, 0));
    let amount = if m.mask_private {
        plain("hidden")
    } else {
        plain(fmt_claimable(total))
    };
    [
        plain("shielded"),
        plain(count.to_string()),
        amount,
        state,
        plain(as_of),
    ]
}

/// The shielded row's detail.
fn shielded_detail(m: &Model) -> String {
    let transfers = &m.coins.transfer;
    if transfers.reading.is_some() {
        return "Shielded coins: reading the coins and pending transfers now (full scans matched \
                on this machine, about a minute)."
            .into();
    }
    match &transfers.read {
        None => "Shielded coins: not read yet; ‹E› reads them with full scans of the coins and \
                 pending transfers, matched on this machine (about a minute)."
            .into(),
        Some(Err(error)) => format!("Shielded coins: read failed ({error}); ‹E› reads them again."),
        Some(Ok((read, at))) => {
            let incoming = read.escrows.iter().filter(|e| !e.outgoing).count();
            format!(
                "Shielded coins: {} unspent; pending transfers {incoming} incoming, {} outgoing; \
                 read {} with full scans matched on this machine; ‹E› reads again.",
                read.coins.map_or(0, |(count, _)| count),
                read.escrows.len() - incoming,
                coins::utc_hm(*at)
            )
        }
    }
}

/// The cursor row's detail.
fn detail(m: &Model) -> String {
    if m.coins.cursor == 2 {
        return shielded_detail(m);
    }
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

/// The Balances table, its rows padded to shared column widths, for a
/// panel `inner` columns wide.
fn table_lines(m: &Model, inner: u16) -> Vec<Line<'static>> {
    let rows = [claimable_row(m), legacy_row(m), shielded_row(m)];
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
/// amount and the recipient's address.
fn confirm_lines(preview: &Preview, width: u16, mask: bool) -> Vec<Line<'static>> {
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
    lines
        .into_iter()
        .flat_map(|line| wrap_message(line, width))
        .collect()
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
    let claimable = match (&m.claimable_reward, &m.reward_error) {
        _ if !m.reward_loaded => "not read yet; it comes with the first Provers refresh".into(),
        (Some((units, frame)), _) if *units > 0 => format!(
            "{} Q at f{frame}, the reward balance of the GLOBAL reward witness",
            exact_amount(*units)
        ),
        (Some((_, frame)), _) => format!("none at f{frame}"),
        (None, Some(error)) => format!("read failed ({error})"),
        (None, None) => "none".into(),
    };
    let authorization = if super::super::mint::running(m) {
        "a mint or claim is under way; Notifications follow it"
    } else {
        match m.claimable_reward {
            Some((units, _)) if units > 0 => {
                "‹M› authorizes a mint of it, as `qclient token mint` does"
            }
            _ => "nothing to authorize",
        }
    };
    let mut lines: Vec<Line<'static>> = [
        row("Claimable", claimable),
        row("Authorization", authorization.into()),
    ]
    .into_iter()
    .flat_map(|line| wrap_message(line, width))
    .collect();
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
    let visible = rows.saturating_sub(2).max(1);
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
    lines.extend(wrap_message(
        Line::from(Span::styled(
            "State: this node reports no authorization status; ‹C› checks for the finalized \
             witness before it claims.",
            help,
        )),
        width,
    ));
    lines
}

/// The middle panel's title and lines: a confirmation while one is open;
/// else the selected Balances row's panel ([`Middle`]).
fn middle_lines(m: &mut Model, width: u16, height: u16) -> (String, Vec<Line<'static>>, Scroll) {
    match &m.coins.transfer.dialog {
        Some(TransferDialog::Form(form)) => {
            let title = if form.pending {
                "Pending transfer"
            } else {
                "Transfer"
            };
            return (title.into(), form_lines(form, width, m.mask_private), None);
        }
        Some(TransferDialog::Confirm(preview)) => {
            let title = format!("Confirm {}", preview.kind.name().to_lowercase());
            let lines = transfer_confirm_lines(preview, width, m.mask_private);
            return (title, lines, None);
        }
        Some(TransferDialog::Preparing(_)) => {
            return (
                Middle::Transfers.title().into(),
                vec![Line::from(Span::styled(
                    format!("{} Checking the inputs and quoting the fee…", spinner(m)),
                    Style::new().fg(PRIMARY),
                ))],
                None,
            );
        }
        None => {}
    }
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
    match coins::middle(m) {
        Middle::Claim => {
            let lines = claim_lines(m, width, height);
            (Middle::Claim.title().into(), lines, None)
        }
        Middle::Transfers => {
            let lines = transfer_lines(m, width, height);
            (Middle::Transfers.title().into(), lines, None)
        }
        Middle::ShieldPlan => plan_lines(m, width, height),
    }
}

/// An escrow address in the panel: `…` and its last six characters, or in
/// full in expanded mode (‹n›); hidden in a render.
fn escrow_label(m: &Model, address: &[u8; 32]) -> String {
    let hex = hex::encode(address);
    if m.mask_private {
        "hidden".into()
    } else if m.compact_actions {
        format!("…{}", &hex[hex.len() - 6..])
    } else {
        format!("0x{hex}")
    }
}

/// The Transfers panel: one row per pending transfer this wallet can act
/// on, under the panel's cursor, in `height` rows.
fn transfer_lines(m: &Model, width: u16, height: u16) -> Vec<Line<'static>> {
    let help = Style::new().fg(HELP);
    let transfers = &m.coins.transfer;
    let note =
        |text: String, style: Style| wrap_message(Line::from(Span::styled(text, style)), width);
    let actions = "‹T› transfers, ‹P› makes a pending transfer, ‹J› merges coins.";
    let rows = match &transfers.read {
        None if transfers.reading.is_some() => {
            return note(
                format!(
                    "{} Reading the shielded coins and pending transfers (full scans, about a \
                     minute)…",
                    spinner(m)
                ),
                Style::new().fg(PRIMARY),
            );
        }
        None => {
            return note(
                format!(
                    "Pending transfers are not read yet; ‹E› reads them with the shielded coins \
                     (full scans matched on this machine, about a minute). {actions}"
                ),
                help,
            );
        }
        Some(Err(error)) => {
            return note(
                format!("Shielded coins: read failed ({error}); ‹E› reads them again."),
                Style::new().fg(WARNING),
            );
        }
        Some(Ok((read, _))) if read.escrows.is_empty() => {
            return note(format!("No pending transfers to act on. {actions}"), help);
        }
        Some(Ok((read, _))) => &read.escrows,
    };
    let cells: Vec<[String; 4]> = rows
        .iter()
        .map(|escrow| {
            [
                escrow_label(m, &escrow.address),
                if escrow.outgoing { "out" } else { "in" }.to_string(),
                if m.mask_private {
                    "hidden".into()
                } else {
                    fixed_amount(escrow.amount)
                },
                if !escrow.outgoing {
                    "-".to_string()
                } else if m.last_global_head >= escrow.refund_after {
                    format!("f{} (open)", escrow.refund_after)
                } else {
                    format!("f{}", escrow.refund_after)
                },
            ]
        })
        .collect();
    let headers = ["Escrow", "Direction", "Amount [Q]", "Refund after"];
    let mut widths = headers.map(str::len);
    for row in &cells {
        for (width, text) in widths.iter_mut().zip(row) {
            *width = (*width).max(text.chars().count());
        }
    }
    let line = |c: [&str; 4]| {
        format!(
            "{:<w0$}  {:<w1$}  {:>w2$}  {:<w3$}",
            c[0],
            c[1],
            c[2],
            c[3],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3]
        )
    };
    let as_of = match &transfers.read {
        Some(Ok((_, at))) => coins::utc_hm(*at),
        _ => String::new(),
    };
    let footer = note(
        format!(
            "As of {as_of}. ‹A› accepts an incoming one; ‹R› refunds an outgoing one once its \
             refund frame passes; ‹E› reads again."
        ),
        help,
    );
    let mut lines = vec![Line::from(Span::styled(
        line(headers),
        Style::new().fg(TEXT).add_modifier(Modifier::BOLD),
    ))];
    let visible = usize::from(height).saturating_sub(1 + footer.len()).max(1);
    let focused = m.coins.focus == CoinsFocus::Middle;
    let first = transfers.cursor.saturating_sub(visible - 1);
    for (i, row) in cells.iter().enumerate().skip(first).take(visible) {
        let mut style = Style::new().fg(TEXT);
        if i == transfers.cursor {
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
    lines.extend(footer);
    lines
}

/// A long address by its ends and length; the form and confirmation keep
/// it whole for the action.
fn address_text(address: &str) -> String {
    let hex = address.strip_prefix("0x").unwrap_or(address);
    if hex.len() <= 40 {
        return address.to_string();
    }
    format!(
        "0x{}…{} ({} bytes)",
        &hex[..12],
        &hex[hex.len() - 12..],
        hex.len() / 2
    )
}

/// The transfer form: one line per field, the cursor field marked; `mask`
/// hides what was typed.
fn form_lines(form: &TransferForm, width: u16, mask: bool) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        if form.pending {
            "Pending transfer, as `qclient token pending-transfer` makes one:"
        } else {
            "Transfer, as `qclient token transfer` makes one:"
        },
        Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
    ))];
    for (i, label) in form.labels().iter().enumerate() {
        let value = &form.fields[i];
        let marker = if i == form.field { "▶ " } else { "  " };
        let shown = match (i, value.is_empty()) {
            (0, true) => "paste the address".to_string(),
            (2, true) => "empty: the GLOBAL head plus about a day".to_string(),
            (0 | 1, false) if mask => MASKED.to_string(),
            (0, false) => address_text(value),
            _ => value.clone(),
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{marker}{label}: "),
                Style::new().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                shown,
                Style::new().fg(if value.is_empty() { HELP } else { TEXT }),
            ),
        ]));
    }
    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(
            format!("Not ready: {error}."),
            Style::new().fg(WARNING),
        )));
    }
    lines.push(Line::from(Span::styled(
        "Amounts are in Q (1 Q = 8000000000 base units). ‹tab› moves between fields, \
         ‹enter› checks them and quotes the fee, ‹esc› cancels.",
        Style::new().fg(HELP),
    )));
    lines
        .into_iter()
        .flat_map(|line| wrap_message(line, width))
        .collect()
}

/// A transfer action's confirmation: what it does and its exact inputs;
/// `mask` hides the amounts, the escrow and the recipient.
fn transfer_confirm_lines(preview: &TransferPreview, width: u16, mask: bool) -> Vec<Line<'static>> {
    let row = |label: &str, text: String| {
        Line::from(vec![
            Span::styled(
                format!("{label}: "),
                Style::new().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(text, Style::new().fg(TEXT)),
        ])
    };
    let amount = |units: u128| {
        if mask {
            MASKED.to_string()
        } else {
            format!("{} Q ({units} base units)", exact_amount(units))
        }
    };
    let escrow = |address: &[u8; 32]| {
        if mask {
            MASKED.to_string()
        } else {
            format!("0x{}", hex::encode(address))
        }
    };
    let mut lines = vec![Line::from(Span::styled(
        match &preview.kind {
            TransferKind::Transfer { .. } => "Transfer, as `qclient token transfer` does:",
            TransferKind::Pending { .. } => {
                "Pending transfer, as `qclient token pending-transfer` does:"
            }
            TransferKind::Accept { .. } => {
                "Accept a pending transfer, as `qclient token accept` does:"
            }
            TransferKind::Refund { .. } => {
                "Refund a pending transfer, as `qclient token reject` does:"
            }
            TransferKind::Merge => "Merge coins, as `qclient token merge all` does:",
        },
        Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
    ))];
    match &preview.kind {
        TransferKind::Transfer { amount: units, .. } => {
            lines.push(row("Amount", amount(*units)));
        }
        TransferKind::Pending {
            amount: units,
            refund_after,
            ..
        } => {
            lines.push(row("Amount", amount(*units)));
            lines.push(row(
                "Refund after",
                match refund_after {
                    Some(frame) => format!("f{frame}: from then you may take it back if unclaimed"),
                    None => "the GLOBAL head plus about a day".into(),
                },
            ));
        }
        TransferKind::Accept {
            escrow: address,
            amount: units,
        } => {
            lines.push(row("Escrow", escrow(address)));
            lines.push(row("Amount", amount(*units)));
        }
        TransferKind::Refund {
            escrow: address,
            amount: units,
        } => {
            lines.push(row("Escrow", escrow(address)));
            lines.push(row(
                "Amount",
                if mask {
                    MASKED.to_string()
                } else {
                    format!("{} back to this wallet", amount(*units))
                },
            ));
        }
        TransferKind::Merge => {
            if let Some((coins, total)) = preview.merge {
                lines.push(row(
                    "Coins",
                    if mask {
                        format!("{coins}, into one coin of this wallet; their total {MASKED}")
                    } else {
                        format!(
                            "{coins}, together {}, into one coin of this wallet",
                            amount(total)
                        )
                    },
                ));
            }
        }
    }
    lines.push(row(
        "Fee",
        format!(
            "{} base units ({} Q) as quoted now{}",
            preview.fee,
            exact_amount(preview.fee),
            if matches!(preview.kind, TransferKind::Transfer { .. }) {
                "; quoted again before submission"
            } else {
                ""
            }
        ),
    ));
    lines.push(row(
        "Cap",
        format!(
            "{} Q (--max-fee); a higher quote is refused",
            fmt_claimable(preview.max_fee)
        ),
    ));
    lines.push(Line::from(Span::styled(
        "It is proved here and submitted to this node; it cannot be undone once included.",
        Style::new().fg(HELP),
    )));
    // The recipient in full, last: a confidential address runs to
    // thousands of characters.
    if let TransferKind::Transfer { recipient, .. } | TransferKind::Pending { recipient, .. } =
        &preview.kind
    {
        let bytes = recipient.trim_start_matches("0x").len() / 2;
        lines.push(row(
            "Recipient",
            if mask {
                format!("{bytes} bytes, {MASKED}")
            } else {
                format!("{bytes} bytes, in full: {recipient}")
            },
        ));
    }
    lines
        .into_iter()
        .flat_map(|line| wrap_message(line, width))
        .collect()
}

/// The Shield plan panel's title and lines: the confirmation while it is
/// open, else one row per `token shield-all` batch and its footer.
fn plan_lines(m: &mut Model, width: u16, height: u16) -> (String, Vec<Line<'static>>, Scroll) {
    match &m.coins.shield.dialog {
        Some(Dialog::Confirm(preview)) => {
            return (
                "Confirm shield".into(),
                confirm_lines(preview, width, m.mask_private),
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
    lines.extend(footer);
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
    match &m.coins.transfer.dialog {
        Some(TransferDialog::Confirm(preview)) => {
            return vec![Line::from(Span::styled(
                format!(
                    "Confirm: ‹y› {}  any other key cancels",
                    preview.kind.name().to_lowercase()
                ),
                Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
            ))];
        }
        Some(TransferDialog::Form(_)) => {
            return vec![Line::from(Span::styled(
                "Form: ‹tab› next field  ‹enter› check and quote  ‹esc› cancel  ‹Ctrl+C› quit",
                Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
            ))];
        }
        _ => {}
    }
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
    let entries = [
        ("tab", "switch"),
        ("↑/k", "up"),
        ("↓/j", "down"),
        ("r", "read legacy"),
        ("S", "shield"),
        ("M", "mint"),
        ("C", "claim"),
        ("E", "read shielded"),
        ("T", "transfer"),
        ("P", "pending transfer"),
        ("A", "accept"),
        ("R", "refund"),
        ("J", "merge"),
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
        let usable = coins::key_refusal(m, key).is_none();
        push_key_hint(&mut spans, m, key, description, usable);
    }
    wrap_actions(Line::from(spans), width)
}

pub(super) fn render(f: &mut Frame, m: &mut Model, area: Rect) {
    let header = header_lines(m, area.width);
    let actions = key_rows(m, area.width);
    let inner_width = area.width.saturating_sub(2);
    let mut balances = table_lines(m, inner_width);
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
    let plan_h = rest.saturating_sub(balances_h + notice_h);
    let [balances_h, plan_h, notice_h] = coins::place_edges(m, [balances_h, plan_h, notice_h]);
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
    f.render_widget(Paragraph::new(balances), inner);
    let plan_area = chunks[2];
    let (title, lines, scroll) = middle_lines(
        m,
        plan_area.width.saturating_sub(2),
        plan_area.height.saturating_sub(2),
    );
    let dialog = matches!(m.coins.shield.dialog, Some(Dialog::Confirm(_)))
        || matches!(m.coins.mint.dialog, Some(MintDialog::Confirm(_)))
        || matches!(
            m.coins.transfer.dialog,
            Some(TransferDialog::Confirm(_) | TransferDialog::Form(_))
        );
    let block = bordered(title, dialog || m.coins.focus == CoinsFocus::Middle);
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
        assert!(legacy.contains("4 unshielded · 6 shielded"), "{legacy}");
        assert!(legacy.contains("◆ unshielded"), "{legacy}");
        let shielded = row("shielded");
        assert!(shielded.contains("not read"), "{shielded}");
        assert!(
            text.contains("◆ Legacy coins: 4 unshielded, 6 shielded; 2 batches; ‹S› shields the"),
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
            text.contains("Legacy coins: plan 2 batches of ≤96 coins, 1 on no live shard; read 8 pages in 6.2s"),
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
            assert!(
                text.contains("Claimable: 312500.000000000000 Q at f1200"),
                "{text}"
            );
            assert!(
                text.contains(
                    "Authorization: ‹M› authorizes a mint of it, as `qclient token mint`"
                ),
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
        // The transfer keys with the shielded row or the Transfers panel;
        // `A` and `R` in the panel, on a row they apply to.
        let transfer_keys = [
            "read shielded",
            "‹T› transfer",
            "pending transfer",
            "‹J› merge",
        ];
        m.coins.cursor = 0;
        m.compact_actions = true;
        let text = keys(&mut m, 120);
        assert!(transfer_keys.iter().all(|k| !text.contains(k)), "{text}");
        m.compact_actions = false;
        let text = keys(&mut m, 120);
        assert!(
            text.contains("(T) transfer") && text.contains("(E) read shielded"),
            "{text}"
        );
        m.coins.cursor = 2;
        for compact in [true, false] {
            m.compact_actions = compact;
            let text = keys(&mut m, 120);
            assert!(transfer_keys.iter().all(|k| text.contains(k)), "{text}");
            assert!(!text.contains("‹A› accept"), "{text}");
        }
        super::super::super::transfer::apply_read(
            &mut m,
            Ok(super::super::super::transfer::Read {
                coins: Some((1, 5)),
                escrows: vec![super::super::super::transfer::Escrow {
                    address: [1; 32],
                    amount: 5,
                    outgoing: false,
                    refund_after: 0,
                }],
            }),
        );
        m.coins.focus = CoinsFocus::Middle;
        let text = keys(&mut m, 120);
        assert!(
            text.contains("‹A› accept") && text.contains("(R) refund"),
            "{text}"
        );
        m.coins.focus = CoinsFocus::Balances;
        m.coins.transfer.read = None;
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

    /// The shielded row and the Transfers panel, a form and a confirmation
    /// as they draw, and what a render hides of them; with
    /// `QCLIENT_RENDER_DIR` set, each frame is also written there.
    #[test]
    fn shielded_coins_transfers_form_and_confirmation_draw() {
        use super::super::super::transfer::{self, Dialog, Escrow, Kind, Preview, Read};
        let dump = |name: &str, text: &str| {
            if let Ok(dir) = std::env::var("QCLIENT_RENDER_DIR") {
                std::fs::write(format!("{dir}/{name}.txt"), text).unwrap();
            }
        };
        // A drawn row's cells, from the first row starting with `first`.
        let cells = |text: &str, first: &str| -> Vec<String> {
            text.lines()
                .map(|line| line.trim_matches('│').trim())
                .find(|line| line.starts_with(first))
                .unwrap_or_else(|| panic!("no {first} row in\n{text}"))
                .split_whitespace()
                .map(String::from)
                .collect()
        };
        let mut m = loaded();
        m.color_coding = false;
        m.last_global_head = 2000;
        m.coins.cursor = 2;
        let text = render_text(&mut m, 120, 40);
        assert!(text.contains("╭ Transfers"), "{text}");
        assert!(
            text.contains("Pending transfers are not read yet; ‹E› reads them"),
            "{text}"
        );
        transfer::apply_read(
            &mut m,
            Ok(Read {
                coins: Some((4, 24_000_000_000)),
                escrows: vec![
                    Escrow {
                        address: [0xab; 32],
                        amount: 16_000_000_000,
                        outgoing: false,
                        refund_after: 3000,
                    },
                    Escrow {
                        address: [0xcd; 32],
                        amount: 8_000_000_000,
                        outgoing: true,
                        refund_after: 1900,
                    },
                ],
            }),
        );
        for width in [80, 120] {
            let text = render_text(&mut m, width, 40);
            dump(&format!("offline-transfers-panel-{width}x40"), &text);
            assert_eq!(
                cells(&text, "shielded")[..5],
                ["shielded", "4", "3", "◆", "incoming"],
                "{text}"
            );
            assert!(
                text.contains(
                    "Shielded coins: 4 unspent; pending transfers 1 incoming, 1 outgoing"
                ),
                "{text}"
            );
            assert!(
                text.contains("Escrow   Direction  Amount [Q]  Refund after"),
                "{text}"
            );
            assert!(text.contains("…ababab  in            2.00000  -"), "{text}");
            assert!(
                text.contains("…cdcdcd  out           1.00000  f1900 (open)"),
                "{text}"
            );
            assert!(
                text.contains("◆ Pending transfers: 1 incoming (2 Q)"),
                "{text}"
            );
        }
        // A render hides the amounts and the escrows.
        m.mask_private = true;
        let text = render_text(&mut m, 120, 40);
        dump("offline-transfers-panel-masked-120x40", &text);
        assert_eq!(cells(&text, "hidden"), ["hidden", "in", "hidden", "-"]);
        assert_eq!(
            cells(&text, "shielded")[..5],
            ["shielded", "4", "hidden", "◆", "incoming"]
        );
        assert!(
            text.contains("◆ Pending transfers: 1 incoming; ‹A›"),
            "{text}"
        );
        for private in ["ababab", "cdcdcd", "2.00000", "1.00000", "(2 Q)"] {
            assert!(!text.contains(private), "{private}\n{text}");
        }
        m.mask_private = false;
        transfer::request_form(&mut m, false);
        let text = render_text(&mut m, 120, 40);
        dump("offline-transfer-form-120x40", &text);
        assert!(
            text.contains("▶ Recipient address: paste the address"),
            "{text}"
        );
        assert!(text.contains("Form: ‹tab› next field"), "{text}");
        assert!(
            text.contains("Amounts are in Q (1 Q = 8000000000 base units)."),
            "{text}"
        );
        let recipient = format!("0x{}", "ef".repeat(60));
        let confirm = |kind| {
            Some(Dialog::Confirm(Preview {
                kind,
                fee: 4_000,
                max_fee: 800_000_000,
                merge: None,
            }))
        };
        m.coins.cursor = 0;
        m.coins.transfer.dialog = confirm(Kind::Transfer {
            recipient: recipient.clone(),
            amount: 12_000_000_000,
        });
        let text = render_text(&mut m, 120, 40);
        dump("offline-transfer-confirm-120x40", &text);
        for line in [
            "Confirm transfer",
            "Amount: 1.500000000000 Q (12000000000 base units)",
            "Fee: 4000 base units (0.000000500000 Q) as quoted now; quoted again before submission",
            "Cap: 0.1 Q (--max-fee); a higher quote is refused",
            "Recipient: 60 bytes, in full:",
            "0xefefefefefefefef",
            "Confirm: ‹y› transfer  any other key cancels",
        ] {
            assert!(text.contains(line), "{line}\n{text}");
        }
        m.mask_private = true;
        let text = render_text(&mut m, 120, 40);
        dump("offline-transfer-confirm-masked-120x40", &text);
        for line in [
            "Amount: hidden in this render (--reveal shows it)",
            "Recipient: 60 bytes, hidden in this render (--reveal shows it)",
            "Fee: 4000 base units",
        ] {
            assert!(text.contains(line), "{line}\n{text}");
        }
        for private in ["efefef", "1.500000000000", "12000000000"] {
            assert!(!text.contains(private), "{private}\n{text}");
        }
        m.coins.transfer.dialog = confirm(Kind::Accept {
            escrow: [0xab; 32],
            amount: 16_000_000_000,
        });
        let text = render_text(&mut m, 120, 40);
        assert!(
            text.contains("Escrow: hidden in this render (--reveal shows it)"),
            "{text}"
        );
        assert!(
            !text.contains("abab") && !text.contains("2.000000000000"),
            "{text}"
        );
        // A typed recipient and amount are hidden too.
        m.coins.transfer.dialog = None;
        transfer::request_form(&mut m, true);
        if let Some(Dialog::Form(form)) = m.coins.transfer.dialog.as_mut() {
            form.fields = vec![recipient.clone(), "7.125".into(), String::new()];
        }
        let text = render_text(&mut m, 120, 40);
        assert!(
            text.contains("▶ Recipient escrow address: hidden in this render"),
            "{text}"
        );
        assert!(text.contains("Amount [Q]: hidden in this render"), "{text}");
        assert!(
            !text.contains("efefef") && !text.contains("7.125"),
            "{text}"
        );
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
        let text = render_text(&mut m, 120, 30);
        dump("offline-shield-confirm-120x30", &text);
        for line in [
            "Confirm shield",
            "Coins: 4 of 8 listed legacy coins, in 2 batches of up to 96 coins, one shard each",
            "Amount: 1000.000000000000 Q, less the fees",
            "Recipient: this node's wallet, 0xabababababab…abababababab (40 bytes;",
            "Fee: 16000 base units (0.000002000000 Q) in total as quoted now, up to 9000 per batch",
            "Cap: 0.1 Q per batch (--max-fee); a higher quote stops the run",
            "Left out: 2 already shielded; 1 on no live shard, for a later run; 1 submitted <1h",
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
        assert!(
            text.contains("Shield batch 2/2 failed")
                || text.contains("Shield: failed before any batch"),
            "{text}"
        );
    }
}
