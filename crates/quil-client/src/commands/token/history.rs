//! Wallet history: the private action log ([`super::action_log`]) read
//! back as one row per action, newest first. `qclient token history` prints
//! it; the node manager's Coins tab draws it in its History panel.
//!
//! The records carry no action id: an action is the run of records of one
//! kind and source from its `start` to its `outcome`. A run with no
//! `start` (cut off by the size bound, or a shield refused before it
//! started) or no `outcome` (killed, or still running) stays its own row.
//! Only what this client ran while the log was on is there: coins received,
//! other wallets' actions and commands that record nothing are not.

use std::fmt::Write as _;
use std::path::Path;

/// What an action ended with, as its `outcome` record says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Ok,
    Failed,
    /// A mint whose fee quote changed: nothing was proved.
    Requoted,
    /// An outcome this reader does not know, as recorded.
    Other(String),
    /// No outcome record: the run was killed, or it is still running.
    Unrecorded,
}

impl Outcome {
    /// The outcome's word.
    pub(crate) fn word(&self) -> &str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Requoted => "requoted",
            Self::Other(word) => word,
            Self::Unrecorded => "no outcome",
        }
    }
}

/// Who an action paid or claimed from, as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Party {
    /// A recipient address as given.
    Recipient(String),
    /// A pending transfer's escrow address, in hex.
    Escrow(String),
}

/// One wallet action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Action {
    /// As recorded: `shield`, `mint`, `mint_claim`, `transfer`, ...
    pub kind: String,
    /// `cli` or `manager`, when recorded.
    pub source: Option<String>,
    /// The time of its first record, Unix seconds.
    pub at: u64,
    /// Whether its `start` record is in the log.
    pub started: bool,
    pub outcome: Outcome,
    /// The amount it moved, in base units: a shield's submitted batches,
    /// a mint's minted amount, a transfer action's amount.
    pub amount: Option<u128>,
    /// The fee it paid or was quoted, in base units: a shield's submitted
    /// batches' fees.
    pub fee: Option<u128>,
    pub party: Option<Party>,
    /// A shield's batches submitted, and planned when its start is there.
    pub batches: Option<(u64, Option<u64>)>,
    /// The run's duration, from its outcome.
    pub duration_s: Option<u64>,
    /// The error its outcome records.
    pub error: Option<String>,
    /// Its place in the log: ties of `at` keep the later record first.
    order: usize,
}

impl Action {
    /// The action's name: `claim` for a mint's claim, else its kind in
    /// words.
    pub(crate) fn name(&self) -> String {
        match self.kind.as_str() {
            "mint_claim" => "claim".into(),
            kind => kind.replace('_', " "),
        }
    }

    /// Whether this is a shield, whose amount and fee sum its batches.
    fn shield(&self) -> bool {
        self.kind == "shield"
    }

    fn new(kind: &str, source: Option<&str>, at: u64, order: usize) -> Self {
        Self {
            kind: kind.into(),
            source: source.map(Into::into),
            at,
            started: false,
            outcome: Outcome::Unrecorded,
            amount: None,
            fee: None,
            party: None,
            batches: None,
            duration_s: None,
            error: None,
            order,
        }
    }

    /// Take in one of its records.
    fn add(&mut self, phase: &str, record: &serde_json::Map<String, serde_json::Value>) {
        let amount = |name: &str| record.get(name).and_then(units);
        let count = |name: &str| record.get(name).and_then(serde_json::Value::as_u64);
        match phase {
            "start" => {
                self.started = true;
                if let (true, Some(planned)) = (self.shield(), count("batches")) {
                    self.batches = Some((0, Some(planned)));
                }
            }
            "outcome" => {
                self.outcome = match record.get("outcome").and_then(|o| o.as_str()) {
                    Some("ok") => Outcome::Ok,
                    Some("failed") => Outcome::Failed,
                    Some("requoted") => Outcome::Requoted,
                    Some(other) => Outcome::Other(other.into()),
                    None => Outcome::Other("unknown".into()),
                };
                self.duration_s = count("duration_s");
                self.error = record.get("error").and_then(|e| e.as_str()).map(Into::into);
            }
            _ => {}
        }
        if self.shield() {
            // Each submitted batch adds its amount and fee; the plan's
            // `units` is what it meant to shield, not what it did.
            if phase == "submitted" {
                let add = |sum: Option<u128>, part: Option<u128>| match (sum, part) {
                    (Some(sum), Some(part)) => Some(sum.saturating_add(part)),
                    (sum, part) => sum.or(part),
                };
                self.amount = add(self.amount, amount("shielded"));
                self.fee = add(self.fee, amount("fee"));
                let (submitted, planned) = self.batches.unwrap_or((0, None));
                self.batches = Some((submitted + 1, planned.or(count("of"))));
            }
        } else if phase != "outcome" || self.outcome != Outcome::Requoted {
            // A requote's figures are the new confirmation's, never run.
            if let Some(moved) = amount("minted").or_else(|| amount("amount")) {
                self.amount = Some(moved);
            }
            if let Some(fee) = amount("fee") {
                self.fee = Some(fee);
            }
        }
        if let Some(recipient) = record.get("recipient").and_then(|r| r.as_str()) {
            self.party = Some(Party::Recipient(recipient.into()));
        }
        if let Some(escrow) = record.get("escrow").and_then(|e| e.as_str()) {
            self.party = Some(Party::Escrow(escrow.into()));
        }
    }
}

/// A base-unit amount, recorded as a string of digits or a number.
fn units(value: &serde_json::Value) -> Option<u128> {
    match value {
        serde_json::Value::String(text) => text.parse().ok(),
        serde_json::Value::Number(number) => number.as_u64().map(u128::from),
        _ => None,
    }
}

/// The log's actions, newest first, and the lines that were no record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct History {
    pub actions: Vec<Action>,
    pub unreadable: usize,
}

/// Group the log's `text` into actions, newest first.
pub(crate) fn parse(text: &str) -> History {
    let mut done: Vec<Action> = Vec::new();
    // The action each kind and source has open.
    let mut open: Vec<Action> = Vec::new();
    let mut unreadable = 0;
    for (order, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record = match serde_json::from_str::<serde_json::Value>(line) {
            Ok(serde_json::Value::Object(record)) => record,
            _ => {
                unreadable += 1;
                continue;
            }
        };
        let field = |name: &str| record.get(name).and_then(|v| v.as_str());
        let (Some(ts), Some(kind), Some(phase)) = (
            record.get("ts").and_then(serde_json::Value::as_u64),
            field("kind"),
            field("phase"),
        ) else {
            unreadable += 1;
            continue;
        };
        let source = field("source");
        let at = open
            .iter()
            .position(|a| a.kind == kind && a.source.as_deref() == source);
        // A new start ends the run before it: that one recorded no outcome.
        let at = match at {
            Some(at) if phase == "start" => {
                done.push(open.remove(at));
                None
            }
            at => at,
        };
        let mut action = match at {
            Some(at) => open.remove(at),
            None => Action::new(kind, source, ts, order),
        };
        action.add(phase, &record);
        if phase == "outcome" {
            done.push(action);
        } else {
            open.push(action);
        }
    }
    done.extend(open);
    done.sort_by_key(|action| std::cmp::Reverse((action.at, action.order)));
    History {
        actions: done,
        unreadable,
    }
}

/// `YYYY-MM-DD HH:MM` in UTC of Unix seconds `ts`.
pub(crate) fn utc_minute(ts: u64) -> String {
    let (date, time) = utc(ts);
    format!("{date} {}", &time[..5])
}

/// `YYYY-MM-DD` and `HH:MM:SS` in UTC of Unix seconds `ts`.
pub(crate) fn utc(ts: u64) -> (String, String) {
    let days = (ts / 86_400) as i64;
    let seconds = ts % 86_400;
    // Days since 1970-01-01 to the civil date (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        format!("{year:04}-{month:02}-{day:02}"),
        format!(
            "{:02}:{:02}:{:02}",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60
        ),
    )
}

/// `units` in QUIL, exact, trailing zeros dropped.
pub(crate) fn quil(units: u128) -> String {
    let text = crate::util::float_string_12(
        &num_bigint::BigInt::from(units),
        &crate::util::conversion_factor(),
    );
    if text.contains('.') {
        text.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        text
    }
}

/// The table `qclient token history` prints: the newest `limit` actions
/// (0: all), with each failed one's recorded error under it when `verbose`.
pub(crate) fn table(history: &History, limit: usize, verbose: bool) -> String {
    let mut out = String::new();
    let total = history.actions.len();
    let shown = if limit == 0 { total } else { limit.min(total) };
    let cell = |amount: Option<u128>| amount.map_or("-".to_string(), quil);
    let rows: Vec<[String; 6]> = history.actions[..shown]
        .iter()
        .map(|action| {
            [
                utc_minute(action.at),
                action.name(),
                action.source.clone().unwrap_or_else(|| "-".into()),
                cell(action.amount),
                cell(action.fee),
                match (&action.outcome, &action.error) {
                    (Outcome::Failed, Some(error)) => {
                        format!("failed: {}", super::action_log::error_class(error).1)
                    }
                    (outcome, _) => outcome.word().to_string(),
                },
            ]
        })
        .collect();
    let headers = [
        "When (UTC)",
        "Action",
        "Via",
        "Amount [Q]",
        "Fee [Q]",
        "Outcome",
    ];
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (width, text) in widths.iter_mut().zip(row) {
            *width = (*width).max(text.chars().count());
        }
    }
    let line = |out: &mut String, c: [&str; 6]| {
        let _ = writeln!(
            out,
            "{:<w0$}  {:<w1$}  {:<w2$}  {:>w3$}  {:>w4$}  {}",
            c[0],
            c[1],
            c[2],
            c[3],
            c[4],
            c[5],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
            w4 = widths[4],
        );
    };
    if total == 0 {
        out.push_str("No wallet actions recorded in wallet/actions.jsonl.\n");
    } else {
        line(&mut out, headers);
        for (row, action) in rows.iter().zip(&history.actions) {
            line(
                &mut out,
                [&row[0], &row[1], &row[2], &row[3], &row[4], &row[5]],
            );
            if let (true, Some(error)) = (verbose, &action.error) {
                let _ = writeln!(out, "    error: {error}");
            }
        }
        if shown < total {
            let _ = writeln!(
                out,
                "Showing {shown} of {total} actions, newest first; --limit 0 shows all."
            );
        }
    }
    if history.unreadable > 0 {
        let _ = writeln!(
            out,
            "{}",
            match history.unreadable {
                1 => "1 line of the action log was unreadable and skipped.".to_string(),
                n => format!("{n} lines of the action log were unreadable and skipped."),
            }
        );
    }
    out
}

/// `qclient token history`: the action log under `config_dir`.
pub(crate) fn run(config_dir: &Path, limit: usize) -> anyhow::Result<()> {
    let log = super::action_log::ActionLog::new(config_dir);
    let history = parse(&log.read()?.unwrap_or_default());
    print!("{}", table(&history, limit, crate::verbosity::on()));
    if crate::config::action_log_off() {
        println!("Recording is off: noActionLog is set in the qclient config.");
    }
    Ok(())
}

/// One action log line of `kind` and `phase` at `ts` from `source`, with
/// `fields` (a JSON object), as [`super::action_log::ActionLog::append`]
/// writes it.
#[cfg(test)]
pub(crate) fn record_line(ts: u64, kind: &str, phase: &str, source: &str, fields: &str) -> String {
    let mut line = serde_json::json!({ "ts": ts, "kind": kind, "phase": phase, "source": source });
    let fields: serde_json::Value = serde_json::from_str(fields).unwrap();
    if let (Some(line), serde_json::Value::Object(fields)) = (line.as_object_mut(), fields) {
        line.extend(fields);
    }
    line.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::record_line as rec;

    const T: u64 = 1_763_000_000;

    fn log(lines: &[String]) -> String {
        lines.join("\n") + "\n"
    }

    /// Each action's records make one row, newest first by its first
    /// record's time, whatever order the actions ended in.
    #[test]
    fn actions_are_grouped_and_newest_first() {
        let text = log(&[
            rec(
                T,
                "transfer",
                "start",
                "cli",
                r#"{"recipient":"QCT3abc","amount":"1500","fee":"7"}"#,
            ),
            rec(
                T + 5,
                "mint",
                "start",
                "manager",
                r#"{"minted":"900","fee":"3","recipient":"QCT3self"}"#,
            ),
            rec(T + 9, "mint", "outcome", "manager", r#"{"outcome":"ok"}"#),
            rec(
                T + 20,
                "transfer",
                "outcome",
                "cli",
                r#"{"outcome":"ok","duration_s":20}"#,
            ),
        ]);
        let history = parse(&text);
        assert_eq!(history.unreadable, 0);
        let kinds: Vec<&str> = history.actions.iter().map(|a| a.kind.as_str()).collect();
        assert_eq!(kinds, ["mint", "transfer"]);
        let transfer = &history.actions[1];
        assert_eq!(transfer.at, T);
        assert_eq!(transfer.source.as_deref(), Some("cli"));
        assert_eq!((transfer.amount, transfer.fee), (Some(1500), Some(7)));
        assert_eq!(transfer.party, Some(Party::Recipient("QCT3abc".into())));
        assert_eq!(transfer.outcome, Outcome::Ok);
        assert_eq!(transfer.duration_s, Some(20));
        let mint = &history.actions[0];
        assert_eq!((mint.amount, mint.fee), (Some(900), Some(3)));
    }

    /// A start with no outcome before the next start of its kind and
    /// source stays its own row with no outcome; an outcome with no start
    /// is a row too; a run still open at the end has no outcome.
    #[test]
    fn a_run_without_its_start_or_outcome_stays_its_own_row() {
        let escrow = "ab".repeat(32);
        let text = log(&[
            rec(T, "merge", "start", "cli", r#"{"fee":"2"}"#),
            rec(T + 60, "merge", "start", "cli", r#"{"fee":"4"}"#),
            rec(
                T + 70,
                "merge",
                "outcome",
                "cli",
                r#"{"outcome":"failed","error":"plan changed"}"#,
            ),
            rec(
                T + 80,
                "shield",
                "outcome",
                "manager",
                r#"{"outcome":"failed","error":"connect refused"}"#,
            ),
            rec(
                T + 90,
                "accept",
                "start",
                "manager",
                &format!(r#"{{"escrow":"{escrow}","amount":"5"}}"#),
            ),
        ]);
        let history = parse(&text);
        let rows: Vec<(&str, u64, bool, &Outcome)> = history
            .actions
            .iter()
            .map(|a| (a.kind.as_str(), a.at, a.started, &a.outcome))
            .collect();
        assert_eq!(
            rows,
            [
                ("accept", T + 90, true, &Outcome::Unrecorded),
                ("shield", T + 80, false, &Outcome::Failed),
                ("merge", T + 60, true, &Outcome::Failed),
                ("merge", T, true, &Outcome::Unrecorded),
            ]
        );
        assert_eq!(history.actions[2].fee, Some(4));
        assert_eq!(history.actions[3].fee, Some(2));
        assert_eq!(history.actions[0].party, Some(Party::Escrow(escrow)));
    }

    /// A shield's amount and fee are its submitted batches' sums, its
    /// batches the submitted of the planned; a skipped batch adds nothing.
    #[test]
    fn a_shield_sums_its_submitted_batches() {
        let text = log(&[
            rec(
                T,
                "shield",
                "start",
                "cli",
                r#"{"batches":3,"coins":200,"units":"999999"}"#,
            ),
            rec(
                T + 1,
                "shield",
                "submitted",
                "cli",
                r#"{"batch":1,"of":3,"shielded":"100","fee":"10"}"#,
            ),
            rec(
                T + 2,
                "shield",
                "skipped",
                "cli",
                r#"{"batch":2,"of":3,"units":"50","fee":"99"}"#,
            ),
            rec(
                T + 3,
                "shield",
                "submitted",
                "cli",
                r#"{"batch":3,"of":3,"shielded":"250","fee":"20"}"#,
            ),
            rec(T + 4, "shield", "outcome", "cli", r#"{"outcome":"ok"}"#),
        ]);
        let shield = &parse(&text).actions[0];
        assert_eq!((shield.amount, shield.fee), (Some(350), Some(30)));
        assert_eq!(shield.batches, Some((2, Some(3))));
        assert_eq!(shield.name(), "shield");
    }

    /// A requoted mint keeps the figures it ran with; a claim is named
    /// so; lines that are no record are counted and skipped.
    #[test]
    fn a_requote_keeps_its_figures_and_bad_lines_are_counted() {
        let text = log(&[
            "not json".to_string(),
            rec(
                T,
                "mint",
                "start",
                "manager",
                r#"{"minted":"900","fee":"3"}"#,
            ),
            r#"{"ts":"soon","kind":"mint"}"#.to_string(),
            rec(
                T + 1,
                "mint",
                "outcome",
                "manager",
                r#"{"outcome":"requoted","reward":"990","fee":"5"}"#,
            ),
            rec(
                T + 2,
                "mint_claim",
                "start",
                "cli",
                r#"{"file":"mint-1.bin"}"#,
            ),
            "[1,2]".to_string(),
        ]);
        let history = parse(&text);
        assert_eq!(history.unreadable, 3);
        let mint = &history.actions[1];
        assert_eq!(mint.outcome, Outcome::Requoted);
        assert_eq!((mint.amount, mint.fee), (Some(900), Some(3)));
        assert_eq!(history.actions[0].name(), "claim");
        assert_eq!(history.actions[0].amount, None);
    }

    /// UTC dates across a leap day and a year end.
    #[test]
    fn utc_dates_are_civil() {
        assert_eq!(utc(0), ("1970-01-01".into(), "00:00:00".into()));
        assert_eq!(utc_minute(951_782_400), "2000-02-29 00:00");
        assert_eq!(utc_minute(1_767_225_599), "2025-12-31 23:59");
        assert_eq!(utc(1_763_056_997), ("2025-11-13".into(), "18:03:17".into()));
    }

    /// The CLI table: newest first, the newest `limit` with a footer, a
    /// failure by its fixed reason (its text only under -v), amounts in
    /// QUIL, `-` where none was recorded; empty and skipped-line notes.
    #[test]
    fn the_cli_table_pages_newest_first() {
        let quil = u128::from(crate::util::UNITS_PER_QUIL);
        let amount = format!(r#"{{"amount":"{}"}}"#, quil * 3 / 2);
        let mut lines = Vec::new();
        for i in 0..5u64 {
            lines.push(rec(T + i * 60, "transfer", "start", "cli", &amount));
            let ok = r#"{"outcome":"ok"}"#;
            lines.push(rec(T + i * 60 + 1, "transfer", "outcome", "cli", ok));
        }
        lines.push(rec(
            T + 600,
            "merge",
            "start",
            "manager",
            r#"{"fee":"8000"}"#,
        ));
        lines.push(rec(
            T + 601,
            "merge",
            "outcome",
            "manager",
            r#"{"outcome":"failed","error":"fee of 9 exceeds --max-fee at 10.1.2.3"}"#,
        ));
        lines.push("garbage".into());
        let history = parse(&log(&lines));
        let text = table(&history, 3, false);
        let rows: Vec<&str> = text.lines().collect();
        assert_eq!(rows.len(), 6, "{text}");
        assert!(rows[0].starts_with("When (UTC)"), "{text}");
        assert!(rows[1].starts_with(&utc_minute(T + 600)), "{text}");
        assert!(rows[1].contains("merge     manager"), "{text}");
        assert!(
            rows[1].ends_with("failed: a fee quote exceeds --max-fee"),
            "{text}"
        );
        assert!(!text.contains("10.1.2.3"), "{text}");
        assert!(
            rows[2].contains("transfer") && rows[2].contains("1.5"),
            "{text}"
        );
        assert!(rows[2].starts_with(&utc_minute(T + 240)), "{text}");
        assert_eq!(
            rows[4],
            "Showing 3 of 6 actions, newest first; --limit 0 shows all."
        );
        assert_eq!(
            rows[5],
            "1 line of the action log was unreadable and skipped."
        );
        let all = table(&history, 0, true);
        assert_eq!(all.lines().filter(|l| l.contains("transfer")).count(), 5);
        assert!(all.contains("    error: fee of 9"), "{all}");
        assert!(!all.contains("Showing"), "{all}");
        assert_eq!(
            table(&History::default(), 20, false),
            "No wallet actions recorded in wallet/actions.jsonl.\n"
        );
    }
}
