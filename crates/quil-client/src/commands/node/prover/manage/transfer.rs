//! The Coins tab's transfers: the shielded row of Balances shows this
//! wallet's confidential coins, and the Transfers panel under it the
//! pending transfers (escrows) it can act on. One read on `E` fills both:
//! full scans of the coins and of the escrows, matched on this machine,
//! never on a timer, and never a coin or escrow looked up by its address
//! anywhere but this node. `T` transfers, `P` makes a pending transfer,
//! `A` accepts an incoming one, `R` refunds an outgoing one once its refund
//! frame passes and `J` merges coins, each behind a confirmation and run
//! through `qclient token`'s own functions. One action at a time, shields
//! and mints included; `--render` reads and quotes but never runs.
//!
//! An action logs one operator line when it starts and one with its
//! outcome (target [`LOG_TARGET`]): the action, frames, the duration and an
//! error class; never amounts, recipients, escrow or coin addresses. The
//! private action log ([`crate::commands::token::action_log`]) keeps the
//! details.

use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::coins::Notice;
use super::model::{Model, NoticeSeverity};
use super::shield::{error_class, LOG_TARGET};
use super::update::Cmd;

/// Base units per Q.
const UNITS_PER_Q: u128 = crate::util::UNITS_PER_QUIL as u128;

/// A pending transfer this wallet can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escrow {
    pub address: [u8; 32],
    pub amount: u128,
    /// This wallet funded it (refund branch); otherwise it is incoming.
    pub outgoing: bool,
    pub refund_after: u64,
}

/// One read of this wallet's shielded side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// Unspent confidential coins and their total; `None` while the
    /// application holds no confidential coin at all.
    pub coins: Option<(usize, u128)>,
    pub escrows: Vec<Escrow>,
}

/// What an action does, with its exact inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Transfer {
        recipient: String,
        amount: u128,
    },
    Pending {
        recipient: String,
        amount: u128,
        /// `None`: the node's GLOBAL head plus about a day.
        refund_after: Option<u64>,
    },
    Accept {
        escrow: [u8; 32],
        amount: u128,
    },
    Refund {
        escrow: [u8; 32],
        amount: u128,
    },
    Merge,
}

impl Kind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Transfer { .. } => "Transfer",
            Self::Pending { .. } => "Pending transfer",
            Self::Accept { .. } => "Accept",
            Self::Refund { .. } => "Refund",
            Self::Merge => "Merge",
        }
    }

    /// The operator log's name of the action.
    pub fn log_name(&self) -> &'static str {
        match self {
            Self::Transfer { .. } => "transfer",
            Self::Pending { .. } => "pending_transfer",
            Self::Accept { .. } => "accept",
            Self::Refund { .. } => "refund",
            Self::Merge => "merge",
        }
    }
}

/// The confirmation: the action, its quoted fee and, for a merge, the
/// coins a scan selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    pub kind: Kind,
    pub fee: u128,
    pub max_fee: u128,
    /// Merge: coins and their total.
    pub merge: Option<(usize, u128)>,
}

/// A transfer or pending-transfer form being filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    pub pending: bool,
    /// Recipient, amount in Q and (pending) refund frame.
    pub fields: Vec<String>,
    pub field: usize,
    pub error: Option<String>,
}

impl Form {
    pub fn labels(&self) -> &'static [&'static str] {
        if self.pending {
            &[
                "Recipient escrow address",
                "Amount [Q]",
                "Refund after frame",
            ]
        } else {
            &["Recipient address", "Amount [Q]"]
        }
    }
}

#[derive(Debug)]
pub enum Dialog {
    Form(Form),
    Preparing(Instant),
    Confirm(Preview),
}

/// What a running action reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// A line the CLI would print.
    Note(String),
    /// The private action log could not be written: why.
    LogFailed(String),
    Done(Result<(), String>),
}

#[derive(Debug)]
pub struct Run {
    pub preview: Preview,
    pub started: Instant,
    /// The GLOBAL head the manager last received when the run started.
    pub start_frame: u64,
    /// The CLI's last progress line.
    pub note: Option<String>,
    pub done: Option<Result<(), String>>,
}

#[derive(Debug, Default)]
pub struct Transfers {
    /// The last read: what it found and when, or why it failed.
    pub read: Option<Result<(Read, SystemTime), String>>,
    pub reading: Option<Instant>,
    /// The Transfers row under the cursor.
    pub cursor: usize,
    pub dialog: Option<Dialog>,
    pub run: Option<Run>,
    pub refused: Option<(String, SystemTime)>,
    /// The last run's private action log could not be written: why.
    pub log_failed: Option<String>,
}

/// The pending transfers of the last read.
pub fn escrows(m: &Model) -> &[Escrow] {
    match &m.coins.transfer.read {
        Some(Ok((read, _))) => &read.escrows,
        _ => &[],
    }
}

/// The operator log's start line.
fn log_start(run: &Run) {
    tracing::info!(
        target: LOG_TARGET,
        kind = run.preview.kind.log_name(),
        phase = "start",
        coins = run.preview.merge.map_or(0, |(coins, _)| coins),
        frame = run.start_frame,
        "transfer action started"
    );
}

/// The operator log's outcome line, at GLOBAL `frame`.
fn log_outcome(run: &Run, frame: u64) {
    let Some(done) = &run.done else {
        return;
    };
    let (outcome, (class, reason)) = match done {
        Ok(()) => ("ok", ("none", "")),
        Err(error) => ("failed", error_class(error)),
    };
    tracing::info!(
        target: LOG_TARGET,
        kind = run.preview.kind.log_name(),
        phase = "outcome",
        outcome,
        error_class = class,
        reason,
        fee_cap_hit = class == "fee_cap",
        duration_s = run.started.elapsed().as_secs(),
        start_frame = run.start_frame,
        frame,
        "transfer action finished"
    );
}

/// A transfer action is proving or submitting.
pub fn running(m: &Model) -> bool {
    m.coins
        .transfer
        .run
        .as_ref()
        .is_some_and(|run| run.done.is_none())
}

/// Some action is under way or awaiting its confirmation.
pub fn busy(m: &Model) -> bool {
    running(m)
        || super::shield::running(m)
        || super::mint::running(m)
        || m.coins.transfer.dialog.is_some()
        || m.coins.mint.dialog.is_some()
        || m.coins.shield.dialog.is_some()
}

/// Why `key` (`E`, `T`, `P`, `A`, `R` or `J`) cannot start now, as the
/// line pressing it shows; `None` when it can. Which panel it needs is the
/// Coins tab's check.
pub fn refusal(m: &Model, key: char) -> Option<String> {
    let why = match key {
        'E' if m.coins.transfer.reading.is_some() => "a read is already in progress.".to_string(),
        'E' => return None,
        _ if busy(m) => "another action is in progress; one action at a time.".to_string(),
        'A' | 'R' => match selected(m) {
            None => "no pending transfer selected; ‹E› reads them.".to_string(),
            Some(escrow) => match (key, escrow.outgoing) {
                ('A', false) => return None,
                ('R', true) if m.last_global_head >= escrow.refund_after => return None,
                ('R', true) => format!(
                    "its refund opens at f{}, in {} frames.",
                    escrow.refund_after,
                    escrow.refund_after - m.last_global_head
                ),
                ('A', true) => "an outgoing transfer is not accepted; ‹R› refunds it.".to_string(),
                _ => "an incoming transfer is accepted with ‹A›.".to_string(),
            },
        },
        _ => return None,
    };
    Some(format!("Transfers: {why}"))
}

/// Show `refusal`'s line for `key`; whether there was one.
fn refused(m: &mut Model, key: char) -> bool {
    match refusal(m, key) {
        Some(why) => {
            m.status_msg = why;
            m.status_is_error = false;
            true
        }
        None => false,
    }
}

/// The escrow under the cursor.
fn selected(m: &Model) -> Option<Escrow> {
    escrows(m).get(m.coins.transfer.cursor).cloned()
}

/// `E`: read the shielded coins and the pending transfers.
pub fn request_read(m: &mut Model) -> Vec<Cmd> {
    if refused(m, 'E') {
        return vec![];
    }
    m.coins.transfer.reading = Some(Instant::now());
    vec![Cmd::FetchShielded]
}

/// A finished read. A failed one leaves no figures: the row and the panel
/// say it failed rather than show older ones as current.
pub fn apply_read(m: &mut Model, read: Result<Read, String>) {
    let transfers = &mut m.coins.transfer;
    transfers.reading = None;
    transfers.read = Some(read.map(|read| (read, SystemTime::now())));
    let rows = escrows(m).len();
    m.coins.transfer.cursor = m.coins.transfer.cursor.min(rows.saturating_sub(1));
}

/// `T` / `P`: open the form.
pub fn request_form(m: &mut Model, pending: bool) -> Vec<Cmd> {
    if refused(m, if pending { 'P' } else { 'T' }) {
        return vec![];
    }
    m.coins.transfer.refused = None;
    m.coins.transfer.dialog = Some(Dialog::Form(Form {
        pending,
        fields: vec![String::new(); if pending { 3 } else { 2 }],
        field: 0,
        error: None,
    }));
    vec![]
}

/// `A` / `R` / `J`: prepare a confirmation.
pub fn request(m: &mut Model, key: char) -> Vec<Cmd> {
    if refused(m, key) {
        return vec![];
    }
    let kind = match (key, selected(m)) {
        ('J', _) => Kind::Merge,
        ('A', Some(escrow)) => Kind::Accept {
            escrow: escrow.address,
            amount: escrow.amount,
        },
        ('R', Some(escrow)) => Kind::Refund {
            escrow: escrow.address,
            amount: escrow.amount,
        },
        _ => return vec![],
    };
    m.coins.transfer.refused = None;
    m.coins.transfer.dialog = Some(Dialog::Preparing(Instant::now()));
    vec![Cmd::TransferPrepare(kind)]
}

/// `1.5` Q as base units, exactly; at most the precision a base unit has.
pub fn parse_q(text: &str) -> Result<u128, String> {
    let text = text.trim();
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |part: &str| part.chars().all(|c| c.is_ascii_digit());
    if whole.is_empty() && fraction.is_empty() || !digits(whole) || !digits(fraction) {
        return Err(format!("amount {text:?} is not a number of Q"));
    }
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| format!("amount {text:?} is too large"))?
    };
    let scale = 10u128
        .checked_pow(fraction.len() as u32)
        .ok_or_else(|| format!("amount {text:?} has too many decimals"))?;
    let fraction: u128 = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse()
            .map_err(|_| format!("amount {text:?} has too many decimals"))?
    };
    let scaled = fraction
        .checked_mul(UNITS_PER_Q)
        .ok_or_else(|| format!("amount {text:?} has too many decimals"))?;
    if scaled % scale != 0 {
        return Err(format!(
            "amount {text:?} is not a whole number of base units (1 Q is {UNITS_PER_Q})"
        ));
    }
    let units = whole
        .checked_mul(UNITS_PER_Q)
        .and_then(|units| units.checked_add(scaled / scale))
        .ok_or_else(|| format!("amount {text:?} is too large"))?;
    if units == 0 {
        return Err("the amount must be positive".into());
    }
    Ok(units)
}

/// A key while the form is open: text goes to the field, ‹tab› moves,
/// ‹enter› checks and prepares the confirmation, ‹esc› cancels.
pub fn form_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    let Some(Dialog::Form(form)) = m.coins.transfer.dialog.as_mut() else {
        return vec![];
    };
    match ev.code {
        KeyCode::Esc => {
            m.coins.transfer.dialog = None;
            m.status_msg = "Transfers: cancelled; nothing was submitted.".into();
            m.status_is_error = false;
            return vec![];
        }
        KeyCode::Tab | KeyCode::Down => form.field = (form.field + 1) % form.fields.len(),
        KeyCode::BackTab | KeyCode::Up => {
            form.field = (form.field + form.fields.len() - 1) % form.fields.len();
        }
        KeyCode::Backspace => {
            form.fields[form.field].pop();
        }
        KeyCode::Char(c) if !ev.modifiers.contains(KeyModifiers::CONTROL) && !c.is_whitespace() => {
            form.fields[form.field].push(c);
            form.error = None;
        }
        KeyCode::Enter => {
            let recipient = form.fields[0].trim().to_string();
            if recipient.is_empty() {
                form.error = Some("the recipient is missing".into());
                return vec![];
            }
            let amount = match parse_q(&form.fields[1]) {
                Ok(amount) => amount,
                Err(error) => {
                    form.error = Some(error);
                    return vec![];
                }
            };
            let kind = if form.pending {
                let refund = form.fields[2].trim().trim_start_matches('f');
                let refund_after = if refund.is_empty() {
                    None
                } else {
                    match refund.parse() {
                        Ok(frame) => Some(frame),
                        Err(_) => {
                            form.error = Some(format!("refund frame {refund:?} is not a frame"));
                            return vec![];
                        }
                    }
                };
                Kind::Pending {
                    recipient,
                    amount,
                    refund_after,
                }
            } else {
                Kind::Transfer { recipient, amount }
            };
            m.coins.transfer.dialog = Some(Dialog::Preparing(Instant::now()));
            return vec![Cmd::TransferPrepare(kind)];
        }
        _ => {}
    }
    vec![]
}

/// The preparation's answer: a confirmation, or why there is none.
pub fn apply_preview(m: &mut Model, preview: Result<Preview, String>) {
    if !matches!(m.coins.transfer.dialog, Some(Dialog::Preparing(_))) {
        return;
    }
    match preview {
        Ok(preview) => m.coins.transfer.dialog = Some(Dialog::Confirm(preview)),
        Err(error) => {
            m.coins.transfer.dialog = None;
            m.coins.transfer.refused = Some((error, SystemTime::now()));
        }
    }
}

/// A key while the confirmation is open: `y` starts; any other cancels.
pub fn dialog_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    let confirmed = ev.code == KeyCode::Char('y') && ev.modifiers.is_empty();
    match m.coins.transfer.dialog.take() {
        Some(Dialog::Confirm(preview)) if confirmed => {
            let run = Run {
                preview: preview.clone(),
                started: Instant::now(),
                start_frame: m.last_global_head,
                note: None,
                done: None,
            };
            log_start(&run);
            m.coins.transfer.run = Some(run);
            m.coins.transfer.log_failed = None;
            m.status_msg.clear();
            vec![Cmd::TransferRun(preview)]
        }
        _ => {
            m.status_msg = "Transfers: cancelled; nothing was submitted.".into();
            m.status_is_error = false;
            vec![]
        }
    }
}

/// A running action's report.
pub fn apply_progress(m: &mut Model, progress: Progress) {
    let Some(run) = m.coins.transfer.run.as_mut() else {
        return;
    };
    match progress {
        Progress::Note(note) => run.note = Some(note),
        Progress::LogFailed(why) => m.coins.transfer.log_failed = Some(why),
        Progress::Done(done) => {
            run.done = Some(done);
            log_outcome(run, m.last_global_head);
        }
    }
}

fn bucket(since: Instant) -> &'static str {
    if since.elapsed() < Duration::from_secs(60) {
        "<60s"
    } else {
        ">60s"
    }
}

/// The transfers' notices, in display order.
pub fn notices(m: &Model, fmt_amount: &dyn Fn(u128) -> String) -> Vec<Notice> {
    let mut out = Vec::new();
    let mut push = |key, severity, attention, progress, text: String| {
        out.push(Notice {
            key,
            severity,
            attention,
            progress,
            success: false,
            text,
        })
    };
    let transfers = &m.coins.transfer;
    if let Some(since) = transfers.reading {
        push(
            "transfers-reading",
            NoticeSeverity::Info,
            false,
            true,
            format!(
                "Shielded coins: reading the coins and pending transfers {}.",
                bucket(since)
            ),
        );
    }
    if let Some(Dialog::Preparing(since)) = &transfers.dialog {
        push(
            "transfers-preparing",
            NoticeSeverity::Info,
            false,
            true,
            format!("Transfers: reading and quoting the fee {}.", bucket(*since)),
        );
    }
    if let Some((error, _)) = &transfers.refused {
        push(
            "transfers-refused",
            NoticeSeverity::Error,
            false,
            false,
            format!("Transfers: not started ({error}); nothing was submitted."),
        );
    }
    if let Some(run) = &transfers.run {
        let what = run.preview.kind.name();
        match &run.done {
            None => push(
                "transfers-running",
                NoticeSeverity::Info,
                false,
                true,
                format!("{what}: proving and submitting {}.", bucket(run.started)),
            ),
            Some(Ok(())) => push(
                "transfers-submitted",
                NoticeSeverity::Info,
                false,
                true,
                format!(
                    "{what}: submitted; finalized inclusion is not yet confirmed; ‹E› reads the \
                     shielded coins again."
                ),
            ),
            Some(Err(error)) => push(
                "transfers-failed",
                NoticeSeverity::Error,
                false,
                false,
                format!("{what} failed: {error}."),
            ),
        }
    }
    if let Some(why) = &transfers.log_failed {
        let what = transfers
            .run
            .as_ref()
            .map_or("action", |run| run.preview.kind.log_name());
        push(
            "transfers-log-failed",
            NoticeSeverity::Warning,
            false,
            false,
            format!(
                "Action log: not written ({why}); the {} is unaffected.",
                what.replace('_', " ")
            ),
        );
    }
    match &transfers.read {
        Some(Err(error)) => push(
            "transfers-read-failed",
            NoticeSeverity::Warning,
            false,
            false,
            format!("Shielded coins: read failed ({error}); ‹E› reads them again."),
        ),
        Some(Ok((read, _))) => {
            let rows = &read.escrows;
            let incoming: Vec<&Escrow> = rows.iter().filter(|e| !e.outgoing).collect();
            if !incoming.is_empty() {
                // A render shows no pending amount without --reveal.
                let amount = if m.mask_private {
                    String::new()
                } else {
                    format!(
                        " ({} Q)",
                        fmt_amount(incoming.iter().map(|e| e.amount).sum())
                    )
                };
                push(
                    "transfers-incoming",
                    NoticeSeverity::Info,
                    true,
                    false,
                    format!(
                        "Pending transfers: {} incoming{amount}; ‹A› accepts the one under the \
                         Transfers cursor.",
                        incoming.len(),
                    ),
                );
            }
            let refundable = rows
                .iter()
                .filter(|e| e.outgoing && m.last_global_head >= e.refund_after)
                .count();
            if refundable > 0 {
                push(
                    "transfers-refundable",
                    NoticeSeverity::Info,
                    true,
                    false,
                    format!(
                        "Pending transfers: {refundable} of yours unclaimed past their refund \
                         frame; ‹R› refunds the one under the cursor."
                    ),
                );
            }
        }
        None => {}
    }
    out
}

#[cfg(test)]
mod transfer_tests {
    use super::super::coins::CoinsFocus;
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_text(m: &mut Model, text: &str) {
        for c in text.chars() {
            form_key(m, key(KeyCode::Char(c)));
        }
    }

    #[test]
    fn amounts_in_q_convert_to_base_units_exactly() {
        assert_eq!(parse_q("1"), Ok(UNITS_PER_Q));
        assert_eq!(parse_q("1.5"), Ok(UNITS_PER_Q * 3 / 2));
        assert_eq!(parse_q("0.000000000125"), Ok(1));
        assert_eq!(parse_q(".000000125"), Ok(1000));
        assert!(parse_q("0.0000000001").is_err(), "below one base unit");
        assert!(
            parse_q("1.0000000001").is_err(),
            "not a whole number of base units"
        );
        assert!(parse_q("0").is_err());
        assert!(parse_q("1,5").is_err());
        assert!(parse_q("").is_err());
    }

    #[test]
    fn the_form_takes_text_and_prepares_on_enter() {
        let mut m = Model::new();
        request_form(&mut m, true);
        // Letters that are keys elsewhere are text here.
        type_text(&mut m, "0xabq");
        form_key(&mut m, key(KeyCode::Backspace));
        form_key(&mut m, key(KeyCode::Tab));
        type_text(&mut m, "2.5");
        form_key(&mut m, key(KeyCode::Tab));
        type_text(&mut m, "f1200");
        let cmds = form_key(&mut m, key(KeyCode::Enter));
        assert!(matches!(
            cmds.as_slice(),
            [Cmd::TransferPrepare(Kind::Pending { recipient, amount, refund_after: Some(1200) })]
                if recipient == "0xab" && *amount == UNITS_PER_Q * 5 / 2
        ));
        // A bad amount stays in the form with the reason.
        request_form(&mut m, false);
        m.coins.transfer.dialog = None;
        request_form(&mut m, false);
        type_text(&mut m, "0xcd");
        form_key(&mut m, key(KeyCode::Tab));
        type_text(&mut m, "x");
        assert!(form_key(&mut m, key(KeyCode::Enter)).is_empty());
        assert!(matches!(&m.coins.transfer.dialog, Some(Dialog::Form(f)) if f.error.is_some()));
    }

    #[test]
    fn accept_and_refund_act_on_the_selected_escrow_only_when_they_can() {
        let mut m = Model::new();
        m.last_global_head = 1000;
        assert!(request(&mut m, 'A').is_empty());
        let read = |escrows| Read {
            coins: Some((2, 300)),
            escrows,
        };
        apply_read(
            &mut m,
            Ok(read(vec![
                Escrow {
                    address: [1; 32],
                    amount: 50,
                    outgoing: false,
                    refund_after: 2000,
                },
                Escrow {
                    address: [2; 32],
                    amount: 70,
                    outgoing: true,
                    refund_after: 1500,
                },
            ])),
        );
        m.coins.focus = CoinsFocus::Middle;
        m.coins.cursor = 2;
        assert!(matches!(
            request(&mut m, 'A').as_slice(),
            [Cmd::TransferPrepare(Kind::Accept {
                escrow: [1, ..],
                amount: 50
            })]
        ));
        m.coins.transfer.dialog = None;
        m.coins.transfer.cursor = 1;
        assert!(request(&mut m, 'R').is_empty());
        assert!(m
            .status_msg
            .contains("refund opens at f1500, in 500 frames"));
        m.last_global_head = 1500;
        assert!(matches!(
            request(&mut m, 'R').as_slice(),
            [Cmd::TransferPrepare(Kind::Refund { amount: 70, .. })]
        ));
        let texts: Vec<String> = notices(&m, &|u| u.to_string())
            .into_iter()
            .map(|n| n.text)
            .collect();
        assert!(texts.contains(
            &"Pending transfers: 1 incoming (50 Q); ‹A› accepts the one under the Transfers \
              cursor."
                .to_string()
        ));
        // A render hides the pending amount; a failed read leaves no rows.
        m.mask_private = true;
        let texts: Vec<String> = notices(&m, &|u| u.to_string())
            .into_iter()
            .map(|n| n.text)
            .collect();
        assert!(texts.contains(
            &"Pending transfers: 1 incoming; ‹A› accepts the one under the Transfers cursor."
                .to_string()
        ));
        apply_read(&mut m, Err("unavailable".into()));
        assert!(escrows(&m).is_empty() && m.coins.transfer.cursor == 0);
        assert!(request(&mut m, 'R').is_empty());
    }

    #[test]
    fn y_runs_one_action_at_a_time() {
        let mut m = Model::new();
        m.coins.transfer.dialog = Some(Dialog::Preparing(Instant::now()));
        let preview = Preview {
            kind: Kind::Merge,
            fee: 9,
            max_fee: 10,
            merge: Some((3, 300)),
        };
        apply_preview(&mut m, Ok(preview.clone()));
        // Any other key cancels and sends nothing.
        assert!(dialog_key(&mut m, key(KeyCode::Char('n'))).is_empty());
        assert!(m.coins.transfer.dialog.is_none() && !running(&m));
        assert!(m.status_msg.contains("cancelled; nothing was submitted"));
        m.coins.transfer.dialog = Some(Dialog::Preparing(Instant::now()));
        apply_preview(&mut m, Ok(preview.clone()));
        assert!(matches!(
            dialog_key(&mut m, key(KeyCode::Char('y'))).as_slice(),
            [Cmd::TransferRun(p)] if *p == preview
        ));
        assert!(running(&m));
        assert!(request(&mut m, 'J').is_empty());
        assert!(super::super::shield::request(&mut m).is_empty());
        m.claimable_reward = Some((5, 1));
        assert!(super::super::mint::request_mint(&mut m).is_empty());
        // A refused action-log write is a warning; the merge goes on.
        apply_progress(&mut m, Progress::LogFailed("wallet has mode 755".into()));
        assert!(running(&m));
        let notice = notices(&m, &|u| u.to_string())
            .into_iter()
            .find(|n| n.key == "transfers-log-failed")
            .unwrap();
        assert_eq!(notice.severity, NoticeSeverity::Warning);
        assert_eq!(
            notice.text,
            "Action log: not written (wallet has mode 755); the merge is unaffected."
        );
        apply_progress(&mut m, Progress::Done(Err("fee changed".into())));
        assert!(!running(&m));
    }

    /// Every action logs one operator line at the start and one at the
    /// outcome, with frames and an error class; no amount, recipient,
    /// escrow, node address or path reaches it, though the error carries
    /// some of them.
    #[test]
    fn operator_log_lines_carry_the_action_and_no_private_field() {
        let recipient = format!("0x{}", "c3".repeat(60));
        let kinds = [
            Kind::Transfer {
                recipient: recipient.clone(),
                amount: 123_456_789,
            },
            Kind::Pending {
                recipient: recipient.clone(),
                amount: 123_456_789,
                refund_after: Some(4321),
            },
            Kind::Accept {
                escrow: [0xab; 32],
                amount: 123_456_789,
            },
            Kind::Refund {
                escrow: [0xab; 32],
                amount: 123_456_789,
            },
            Kind::Merge,
        ];
        for kind in kinds {
            let name = kind.log_name();
            let mut m = Model::new();
            m.last_global_head = 777;
            m.coins.transfer.dialog = Some(Dialog::Confirm(Preview {
                kind,
                fee: 98_765,
                max_fee: 43_210,
                merge: (name == "merge").then_some((3, 123_456_789)),
            }));
            let text = super::super::shield::shield_tests::operator_log(|| {
                dialog_key(&mut m, key(KeyCode::Char('y')));
                apply_progress(
                    &mut m,
                    Progress::Note(format!("escrow 0x{} funded", "ab".repeat(32))),
                );
                m.last_global_head = 790;
                apply_progress(
                    &mut m,
                    Progress::Done(Err(format!(
                        "the estimated fee of 98765 base units exceeds the automatic fee limit \
                         of 43210 base units for {recipient} at 10.1.2.3:8337 \
                         (/home/operator/.config); raise --max-fee"
                    ))),
                );
            });
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.len(), 2, "{name}: {text}");
            let kind = format!("kind=\"{name}\"");
            let coins = if name == "merge" {
                "coins=3"
            } else {
                "coins=0"
            };
            for part in [
                "qclient::action",
                &kind,
                r#"phase="start""#,
                coins,
                "frame=777",
            ] {
                assert!(lines[0].contains(part), "{part}: {}", lines[0]);
            }
            for part in [
                &kind,
                r#"phase="outcome""#,
                r#"outcome="failed""#,
                r#"error_class="fee_cap""#,
                "fee_cap_hit=true",
                "start_frame=777",
                "frame=790",
                "duration_s=",
            ] {
                assert!(lines[1].contains(part), "{part}: {}", lines[1]);
            }
            for private in [
                "c3c3",
                "abab",
                "123456789",
                "98765",
                "43210",
                "4321",
                "10.1.2.3",
                "/home/",
            ] {
                assert!(
                    !text.contains(private),
                    "{name}: {private} reached the log:\n{text}"
                );
            }
        }
    }
}
