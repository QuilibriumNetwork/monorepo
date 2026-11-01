//! The Coins tab's shield action: `S` reads and quotes `token shield-all`'s
//! batches, a confirmation names them, `y` runs them in the background
//! through the CLI's own functions. One run at a time; quitting during one
//! asks first. `--render` reads and quotes but never runs.
//!
//! A run logs two kinds of lines. The operator log (target
//! [`LOG_TARGET`], at info, on stderr like qclient's other logs) gets one
//! line when a run starts and one with its outcome: counts, frames, the
//! duration and an error class; never amounts, the recipient, coin
//! addresses or hashes, so the lines can be shared. The private action
//! log ([`crate::commands::token::action_log`]) keeps the details.

use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{KeyCode, KeyEvent};

use super::coins::{self, Notice};
use super::model::{Model, NoticeSeverity};
use super::update::Cmd;

/// Coins per batch, as `token shield-all` cuts them by default.
pub const BATCH_COINS: usize = 96;

/// How soon after a submission the next legacy read looks for inclusion.
pub const INCLUSION_CHECK: Duration = Duration::from_secs(120);

/// How long after a run's start inclusion is still looked for.
const INCLUSION_WINDOW: Duration = Duration::from_secs(3600);

/// What the confirmation shows, read and quoted just before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    pub batches: usize,
    pub coins: usize,
    /// Base units of all batches' coins.
    pub units: u128,
    /// Sum of the batches' quoted fees, and the largest one.
    pub fee: u128,
    pub fee_max: u128,
    /// `--max-fee`: a larger quote stops the run.
    pub max_fee: u128,
    /// The wallet address the coins are shielded into, in full.
    pub recipient: String,
    /// Every listed legacy coin, and those not in the batches: already
    /// shielded, on no live shard, submitted within the hour, or listed
    /// twice. The five counts add up to `listed`.
    pub listed: usize,
    pub shielded: usize,
    pub uncovered: usize,
    pub pending: usize,
    pub duplicates: usize,
}

/// What a running shield reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    Proving {
        index: usize,
        count: usize,
        coins: usize,
    },
    Skipped {
        index: usize,
        count: usize,
    },
    Submitted {
        index: usize,
        count: usize,
        addresses: Vec<[u8; 32]>,
        shielded: u128,
    },
    /// A line the CLI would print (a fee estimate).
    Note(String),
    /// The private action log could not be written: why.
    LogFailed(String),
    Done(Result<(), String>),
}

#[derive(Debug)]
pub enum Dialog {
    /// Reading coins and quoting fees since this time.
    Preparing(Instant),
    Confirm(Preview),
}

#[derive(Debug, Clone)]
pub struct Submitted {
    pub addresses: Vec<[u8; 32]>,
    pub shielded: u128,
    pub included: bool,
}

#[derive(Debug)]
pub struct Run {
    pub preview: Preview,
    pub started: Instant,
    /// The GLOBAL head the manager last received when the run started.
    pub start_frame: u64,
    /// The batch being proved and submitted: index, coins, since when.
    pub proving: Option<(usize, usize, Instant)>,
    pub submitted: Vec<Submitted>,
    pub skipped: usize,
    pub note: Option<String>,
    /// The outcome, and the batch it failed at.
    pub done: Option<Result<(), String>>,
    pub failed_at: Option<usize>,
}

/// The shield action's state on the Coins tab.
#[derive(Debug, Default)]
pub struct Shield {
    pub dialog: Option<Dialog>,
    pub run: Option<Run>,
    /// Why the last request did not open a confirmation, and when.
    pub refused: Option<(String, SystemTime)>,
    /// `q` was pressed during a run; `y` quits.
    pub quit_pending: bool,
    /// The last run's private action log could not be written: why.
    pub log_failed: Option<String>,
}

/// The operator log's target and error classes, shared with the CLI's
/// wallet commands.
pub(crate) use crate::commands::token::action_log::{error_class, LOG_TARGET};

/// The operator log's start line.
fn log_start(run: &Run) {
    tracing::info!(
        target: LOG_TARGET,
        kind = "shield",
        phase = "start",
        batches = run.preview.batches,
        coins = run.preview.coins,
        frame = run.start_frame,
        "shield run started"
    );
}

/// The operator log's outcome line, at GLOBAL `frame`.
fn log_outcome(run: &Run, frame: u64) {
    let Some(done) = &run.done else {
        return;
    };
    let (outcome, (class, reason)) = match done {
        Ok(()) => ("ok", ("none", "")),
        Err(error) if !run.submitted.is_empty() => ("partial", error_class(error)),
        Err(error) => ("failed", error_class(error)),
    };
    let fee_cap_hit = class == "fee_cap";
    let coins_submitted: usize = run.submitted.iter().map(|b| b.addresses.len()).sum();
    tracing::info!(
        target: LOG_TARGET,
        kind = "shield",
        phase = "outcome",
        outcome,
        error_class = class,
        reason,
        failed_batch = run.failed_at.unwrap_or(0),
        fee_cap_hit,
        duration_s = run.started.elapsed().as_secs(),
        start_frame = run.start_frame,
        frame,
        batches = run.preview.batches,
        submitted = run.submitted.len(),
        skipped = run.skipped,
        coins_submitted,
        "shield run finished"
    );
}

/// The legacy row's state while a run proves and submits: the batch under
/// way of all, e.g. `shielding 3/106`.
pub fn row_state(m: &Model) -> Option<String> {
    let run = m.coins.shield.run.as_ref().filter(|_| running(m))?;
    let count = run.preview.batches;
    let current = match run.proving {
        Some((index, ..)) => index,
        None => (run.submitted.len() + run.skipped + 1).min(count),
    };
    Some(format!("shielding {current}/{count}"))
}

/// A run is proving or submitting.
pub fn running(m: &Model) -> bool {
    m.coins
        .shield
        .run
        .as_ref()
        .is_some_and(|run| run.done.is_none())
}

/// Why `S` cannot start now, as the line pressing it shows; `None` when
/// there is something to shield and nothing else runs.
pub fn refusal(m: &Model) -> Option<String> {
    let why = if running(m)
        || super::mint::running(m)
        || super::transfer::running(m)
        || m.coins.mint.dialog.is_some()
        || m.coins.transfer.dialog.is_some()
    {
        "another action is in progress; one action at a time.".to_string()
    } else if m.coins.shield.dialog.is_some() {
        "the shield is being prepared; ‹esc› cancels it.".to_string()
    } else {
        match &m.coins.legacy.answer {
            Some((Some(snapshot), _, _)) => {
                if let Some((frame, left)) = coins::shields_open_at(snapshot) {
                    format!("shields open at f{frame}, in {left} frames.")
                } else if snapshot.tally.unshielded <= snapshot.pending {
                    "no unshielded legacy coins to shield.".to_string()
                } else {
                    return None;
                }
            }
            Some((None, _, _)) => {
                "this node config has no Ed448 key, so it owns no legacy coins.".to_string()
            }
            None => "legacy coins are not read yet; ‹r› reads them.".to_string(),
        }
    };
    Some(format!("Shield: {why}"))
}

/// `S`: read and quote the batches for a confirmation, when there is
/// something to shield and nothing else runs.
pub fn request(m: &mut Model) -> Vec<Cmd> {
    if let Some(why) = refusal(m) {
        m.status_msg = why;
        m.status_is_error = false;
        return vec![];
    }
    m.coins.shield.refused = None;
    m.coins.shield.dialog = Some(Dialog::Preparing(Instant::now()));
    vec![Cmd::ShieldPrepare]
}

/// The preparation's answer: a confirmation, or why there is none.
pub fn apply_preview(m: &mut Model, preview: Result<Preview, String>) {
    // Cancelled meanwhile: the answer is stale.
    if !matches!(m.coins.shield.dialog, Some(Dialog::Preparing(_))) {
        return;
    }
    match preview {
        Ok(preview) => m.coins.shield.dialog = Some(Dialog::Confirm(preview)),
        Err(error) => {
            m.coins.shield.dialog = None;
            m.coins.shield.refused = Some((error, SystemTime::now()));
        }
    }
}

/// A key while the dialog is open: `y` on a confirmation starts the run;
/// any other key cancels.
pub fn dialog_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    let confirmed = ev.code == KeyCode::Char('y') && ev.modifiers.is_empty();
    match m.coins.shield.dialog.take() {
        Some(Dialog::Confirm(preview)) if confirmed => {
            let run = Run {
                preview: preview.clone(),
                started: Instant::now(),
                start_frame: m.last_global_head,
                proving: None,
                submitted: Vec::new(),
                skipped: 0,
                note: None,
                done: None,
                failed_at: None,
            };
            log_start(&run);
            m.coins.shield.run = Some(run);
            m.coins.shield.log_failed = None;
            m.status_msg.clear();
            vec![Cmd::ShieldRun(preview)]
        }
        _ => {
            m.status_msg = "Shield: cancelled; nothing was submitted.".into();
            m.status_is_error = false;
            vec![]
        }
    }
}

/// Keys on any tab while a run is in progress: quitting asks first.
/// Returns the commands when the key was taken.
pub fn quit_guard(m: &mut Model, ev: &KeyEvent, quit: bool) -> Option<Vec<Cmd>> {
    if m.coins.shield.quit_pending {
        m.coins.shield.quit_pending = false;
        if ev.code == KeyCode::Char('y') {
            return Some(vec![Cmd::Quit]);
        }
        m.status_msg = "Shield: the run continues.".into();
        m.status_is_error = false;
        return Some(vec![]);
    }
    if quit && (running(m) || super::mint::running(m) || super::transfer::running(m)) {
        m.coins.shield.quit_pending = true;
        m.status_msg = "A submission is in progress: ‹y› quits and abandons what is being \
                        proved; any other key keeps it running."
            .into();
        m.status_is_error = true;
        return Some(vec![]);
    }
    None
}

/// A running shield's report.
pub fn apply_progress(m: &mut Model, progress: Progress) {
    let now = Instant::now();
    let Some(run) = m.coins.shield.run.as_mut() else {
        return;
    };
    match progress {
        Progress::Proving { index, coins, .. } => run.proving = Some((index, coins, now)),
        Progress::Skipped { .. } => run.skipped += 1,
        Progress::Submitted {
            addresses,
            shielded,
            ..
        } => {
            run.proving = None;
            run.submitted.push(Submitted {
                addresses,
                shielded,
                included: false,
            });
            m.coins.legacy.refresh_at = Some(now + INCLUSION_CHECK);
        }
        Progress::Note(line) => run.note = Some(line),
        Progress::LogFailed(why) => m.coins.shield.log_failed = Some(why),
        Progress::Done(result) => {
            if result.is_err() {
                run.failed_at = run.proving.map(|(index, ..)| index);
            }
            run.proving = None;
            run.done = Some(result);
            log_outcome(run, m.last_global_head);
        }
    }
}

/// After a legacy read: batches whose coins GLOBAL now records as shielded
/// are included; the next read follows while some are not.
pub fn observe_inclusion(m: &mut Model) {
    let Some((Some(snapshot), _, _)) = &m.coins.legacy.answer else {
        return;
    };
    let Some(run) = m.coins.shield.run.as_mut() else {
        return;
    };
    for batch in &mut run.submitted {
        batch.included = batch.included
            || batch
                .addresses
                .iter()
                .all(|address| snapshot.shielded.contains(address));
    }
    let waiting = run.submitted.iter().any(|batch| !batch.included);
    if waiting && run.started.elapsed() < INCLUSION_WINDOW {
        m.coins.legacy.refresh_at = Some(Instant::now() + INCLUSION_CHECK);
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// `<60s` / `>60s`, the fixed progress buckets.
fn bucket(since: Instant) -> &'static str {
    if since.elapsed() < Duration::from_secs(60) {
        "<60s"
    } else {
        ">60s"
    }
}

/// The shield's notices, in display order.
pub fn notices(m: &Model, fmt_amount: &dyn Fn(u128) -> String) -> Vec<Notice> {
    let mut out = Vec::new();
    let mut push = |key, severity, progress, success, text: String| {
        out.push(Notice {
            key,
            severity,
            attention: false,
            progress,
            success,
            text,
        })
    };
    let shield = &m.coins.shield;
    if let Some(Dialog::Preparing(since)) = &shield.dialog {
        push(
            "shield-preparing",
            NoticeSeverity::Info,
            true,
            false,
            format!("Shield: reading coins and quoting fees {}.", bucket(*since)),
        );
    }
    if let Some((error, _)) = &shield.refused {
        push(
            "shield-refused",
            NoticeSeverity::Error,
            false,
            false,
            format!("Shield: not started ({error}); nothing was submitted."),
        );
    }
    if let Some((Some(snapshot), _, _)) = &m.coins.legacy.answer {
        if snapshot.pending > 0 {
            push(
                "shield-pending",
                NoticeSeverity::Info,
                false,
                false,
                format!(
                    "Shield: {} submitted <1h ago are hidden from the plan.",
                    plural(snapshot.pending, "coin", "coins")
                ),
            );
        }
    }
    let Some(run) = &shield.run else {
        return out;
    };
    let count = run.preview.batches;
    if let Some((index, coins, since)) = run.proving {
        push(
            "shield-proving",
            NoticeSeverity::Info,
            true,
            false,
            format!(
                "Shield batch {index}/{count}: proving {} coins {}.",
                coins,
                bucket(since)
            ),
        );
    }
    let submitted = run.submitted.len();
    let included: Vec<&Submitted> = run.submitted.iter().filter(|b| b.included).collect();
    if submitted > included.len() {
        push(
            "shield-submitted",
            NoticeSeverity::Info,
            true,
            false,
            format!(
                "Shield: {} of {count} submitted ({} coins); inclusion not yet confirmed.",
                plural(submitted - included.len(), "batch", "batches"),
                run.submitted
                    .iter()
                    .filter(|b| !b.included)
                    .map(|b| b.addresses.len())
                    .sum::<usize>()
            ),
        );
    }
    if !included.is_empty() {
        let coins = included.iter().map(|b| b.addresses.len()).sum::<usize>();
        // A render shows no shielded amount without --reveal.
        let amount = if m.mask_private {
            String::new()
        } else {
            format!(
                ", {} Q",
                fmt_amount(included.iter().map(|b| b.shielded).sum())
            )
        };
        push(
            "shield-included",
            NoticeSeverity::Info,
            true,
            true,
            format!(
                "Shield: {} of {count} included: {coins} coins{amount} shielded.",
                plural(included.len(), "batch", "batches"),
            ),
        );
    }
    if let Some(why) = &shield.log_failed {
        push(
            "shield-log-failed",
            NoticeSeverity::Warning,
            false,
            false,
            format!("Action log: not written ({why}); the shield is unaffected."),
        );
    }
    if run.skipped > 0 {
        push(
            "shield-skipped",
            NoticeSeverity::Info,
            false,
            false,
            format!(
                "Shield: {} skipped; their coins do not cover the fee.",
                plural(run.skipped, "batch", "batches")
            ),
        );
    }
    if let Some(Err(error)) = &run.done {
        push(
            "shield-failed",
            NoticeSeverity::Error,
            false,
            false,
            match run.failed_at {
                Some(index) => format!(
                    "Shield batch {index}/{count} failed: {error}; it was not submitted, \
                     the run stopped."
                ),
                None => {
                    format!("Shield: failed before any batch ({error}); nothing was submitted.")
                }
            },
        );
    }
    out
}

#[cfg(test)]
pub(crate) mod shield_tests {
    use super::*;
    use crate::commands::token::legacy::{ShieldPlan, ShieldRule, Snapshot, Tally};
    use crossterm::event::KeyModifiers;

    pub(crate) fn preview() -> Preview {
        Preview {
            batches: 2,
            coins: 100,
            units: 50_000,
            fee: 300,
            fee_max: 200,
            max_fee: 800_000_000,
            recipient: "0xabc".into(),
            listed: 100,
            shielded: 0,
            uncovered: 0,
            pending: 0,
            duplicates: 0,
        }
    }

    fn with_coins(head: u64) -> Model {
        let mut m = Model::new();
        coins::open(&mut m);
        coins::apply_legacy(
            &mut m,
            Ok(Some(Snapshot {
                tally: Tally {
                    units: 50_000,
                    unshielded: 100,
                    shielded: 0,
                },
                plan: Some(ShieldPlan {
                    batches: 2,
                    exact: true,
                    outside: 0,
                }),
                batch_max: Some(96),
                head: Ok(head),
                rule: Some(ShieldRule {
                    shield_from: 900,
                    shield_all_from: 1000,
                }),
                pages: 2,
                batches: Vec::new(),
                pending: 0,
                shielded: Default::default(),
            })),
            Duration::from_secs(1),
        );
        m
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    #[test]
    fn s_asks_y_runs_and_any_other_key_cancels() {
        // Before the gate: refused, no read or quote.
        let mut m = with_coins(990);
        assert!(request(&mut m).is_empty());
        assert!(m.status_msg.contains("shields open at f1000, in 10 frames"));
        let mut m = with_coins(2000);
        assert!(matches!(request(&mut m).as_slice(), [Cmd::ShieldPrepare]));
        apply_preview(&mut m, Ok(preview()));
        assert!(dialog_key(&mut m, key('n')).is_empty());
        assert!(m.coins.shield.dialog.is_none() && m.coins.shield.run.is_none());
        assert!(m.status_msg.contains("cancelled; nothing was submitted"));
        request(&mut m);
        apply_preview(&mut m, Ok(preview()));
        assert!(matches!(
            dialog_key(&mut m, key('y')).as_slice(),
            [Cmd::ShieldRun(p)] if *p == preview()
        ));
        assert!(running(&m));
        // One action at a time.
        assert!(request(&mut m).is_empty());
        assert!(m.status_msg.contains("one action at a time"));
        // Nor a mint beside it.
        m.claimable_reward = Some((5, 1));
        assert!(super::super::mint::request_mint(&mut m).is_empty());
    }

    /// A sink for the operator log's formatted lines.
    #[derive(Clone, Default)]
    pub(crate) struct Capture(pub(crate) std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The operator log's lines `work` writes, formatted as on stderr.
    pub(crate) fn operator_log(work: impl FnOnce()) -> String {
        let capture = Capture::default();
        let sink = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .without_time()
            .with_writer(move || sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, work);
        let bytes = capture.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    /// The operator log gets one line at the start and one at the outcome,
    /// with counts, frames and an error class; no amount, recipient, coin
    /// address, node address or path reaches it, though the error carries
    /// some of them.
    #[test]
    fn operator_log_lines_carry_counts_and_no_private_field() {
        let capture = Capture::default();
        let sink = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .without_time()
            .with_writer(move || sink.clone())
            .finish();
        let recipient = format!("0x{}", "c3".repeat(40));
        let mut m = with_coins(2000);
        m.last_global_head = 777;
        tracing::subscriber::with_default(subscriber, || {
            request(&mut m);
            apply_preview(
                &mut m,
                Ok(Preview {
                    units: 123_456_789,
                    fee: 98_765,
                    fee_max: 43_210,
                    recipient: recipient.clone(),
                    ..preview()
                }),
            );
            dialog_key(&mut m, key('y'));
            apply_progress(
                &mut m,
                Progress::Submitted {
                    index: 1,
                    count: 2,
                    addresses: vec![[0xab; 32], [0xcd; 32]],
                    shielded: 55_555_551,
                },
            );
            m.last_global_head = 790;
            apply_progress(
                &mut m,
                Progress::Done(Err(format!(
                    "the node at 10.1.2.3:8337 is peer …a1b2c3, but submissions would be \
                     signed by /home/operator/.config (peer …d4e5f6), and a node accepts only \
                     submissions signed with its own peer key; amount 123456789 to {recipient}"
                ))),
            );
        });
        let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        for part in [
            "qclient::action",
            r#"kind="shield""#,
            r#"phase="start""#,
            "batches=2",
            "coins=100",
            "frame=777",
        ] {
            assert!(lines[0].contains(part), "{part}: {}", lines[0]);
        }
        for part in [
            r#"phase="outcome""#,
            r#"outcome="partial""#,
            r#"error_class="identity""#,
            r#"reason="the signing config is not the node's""#,
            "fee_cap_hit=false",
            "start_frame=777",
            "frame=790",
            "submitted=1",
            "skipped=0",
            "coins_submitted=2",
            "duration_s=",
        ] {
            assert!(lines[1].contains(part), "{part}: {}", lines[1]);
        }
        for private in [
            "c3c3",
            "abab",
            "cdcd",
            "123456789",
            "98765",
            "43210",
            "55555551",
            "10.1.2.3",
            "/home/",
            "a1b2c3",
            "d4e5f6",
        ] {
            assert!(
                !text.contains(private),
                "{private} reached the log:\n{text}"
            );
        }
    }

    #[test]
    fn errors_fall_into_fixed_classes() {
        for (error, class) in [
            (
                "the estimated fee of 9 base units exceeds the automatic fee limit of 8 base \
                 units; ... --max-fee or QUILIBRIUM_MAX_FEE",
                "fee_cap",
            ),
            (
                "the plan changed since it was confirmed (3 batches of 9 coins now)",
                "plan_changed",
            ),
            ("transport error", "rpc"),
            (
                "the reward changed since it was confirmed (f43, 1001 base units now); \
                 press ‹M› again",
                "reward_changed",
            ),
            (
                "the authorization citing f42 is not finalized: GLOBAL holds no witness for \
                 it yet",
                "not_finalized",
            ),
            ("something new", "other"),
        ] {
            assert_eq!(error_class(error).0, class, "{error}");
        }
    }

    /// While a run proves and submits, the legacy row names the batch under
    /// way; it ends with the run.
    #[test]
    fn the_legacy_row_follows_a_running_shield() {
        let mut m = with_coins(2000);
        assert_eq!(row_state(&m), None);
        request(&mut m);
        apply_preview(&mut m, Ok(preview()));
        dialog_key(&mut m, key('y'));
        assert_eq!(row_state(&m).as_deref(), Some("shielding 1/2"));
        apply_progress(
            &mut m,
            Progress::Submitted {
                index: 1,
                count: 2,
                addresses: vec![[1; 32]],
                shielded: 9,
            },
        );
        assert_eq!(row_state(&m).as_deref(), Some("shielding 2/2"));
        apply_progress(&mut m, Progress::Done(Ok(())));
        assert_eq!(row_state(&m), None);
    }

    /// A refused action-log write is a warning; the run goes on.
    #[test]
    fn a_failed_action_log_write_is_a_warning() {
        let fmt = |units: u128| units.to_string();
        let mut m = with_coins(2000);
        request(&mut m);
        apply_preview(&mut m, Ok(preview()));
        dialog_key(&mut m, key('y'));
        apply_progress(
            &mut m,
            Progress::LogFailed(
                "wallet has mode 755; the action log needs 700 (owner only)".into(),
            ),
        );
        assert!(running(&m));
        let notice = notices(&m, &fmt)
            .into_iter()
            .find(|n| n.key == "shield-log-failed")
            .unwrap();
        assert_eq!(notice.severity, NoticeSeverity::Warning);
        assert_eq!(
            notice.text,
            "Action log: not written (wallet has mode 755; the action log needs 700 (owner \
             only)); the shield is unaffected."
        );
        // The next run starts without it.
        apply_progress(&mut m, Progress::Done(Ok(())));
        request(&mut m);
        apply_preview(&mut m, Ok(preview()));
        dialog_key(&mut m, key('y'));
        assert!(notices(&m, &fmt)
            .iter()
            .all(|n| n.key != "shield-log-failed"));
    }

    #[test]
    fn quitting_during_a_run_asks_first() {
        let mut m = with_coins(2000);
        assert!(quit_guard(&mut m, &key('q'), true).is_none());
        request(&mut m);
        apply_preview(&mut m, Ok(preview()));
        dialog_key(&mut m, key('y'));
        assert_eq!(
            quit_guard(&mut m, &key('q'), true).map(|c| c.len()),
            Some(0)
        );
        assert!(m.coins.shield.quit_pending);
        assert!(quit_guard(&mut m, &key('x'), false).unwrap().is_empty());
        assert!(running(&m));
        quit_guard(&mut m, &key('q'), true);
        assert!(matches!(
            quit_guard(&mut m, &key('y'), false).as_deref(),
            Some([Cmd::Quit])
        ));
    }

    #[test]
    fn progress_submission_inclusion_and_failure_read_as_notices() {
        let fmt = |units: u128| units.to_string();
        let mut m = with_coins(2000);
        request(&mut m);
        apply_preview(&mut m, Ok(preview()));
        dialog_key(&mut m, key('y'));
        apply_progress(
            &mut m,
            Progress::Proving {
                index: 1,
                count: 2,
                coins: 96,
            },
        );
        let texts =
            |m: &Model| -> Vec<String> { notices(m, &fmt).into_iter().map(|n| n.text).collect() };
        assert_eq!(texts(&m), ["Shield batch 1/2: proving 96 coins <60s."]);
        apply_progress(
            &mut m,
            Progress::Submitted {
                index: 1,
                count: 2,
                addresses: vec![[1; 32], [2; 32]],
                shielded: 900,
            },
        );
        assert!(m.coins.legacy.refresh_at.is_some());
        assert_eq!(
            texts(&m),
            ["Shield: 1 batch of 2 submitted (2 coins); inclusion not yet confirmed."]
        );
        // The next read shows the coins shielded.
        if let Some((Some(snapshot), _, _)) = m.coins.legacy.answer.as_mut() {
            snapshot.shielded.extend([[1; 32], [2; 32]]);
        }
        observe_inclusion(&mut m);
        apply_progress(
            &mut m,
            Progress::Proving {
                index: 2,
                count: 2,
                coins: 4,
            },
        );
        apply_progress(&mut m, Progress::Done(Err("proving: budget".into())));
        assert!(!running(&m));
        assert_eq!(
            texts(&m),
            [
                "Shield: 1 batch of 2 included: 2 coins, 900 Q shielded.",
                "Shield batch 2/2 failed: proving: budget; it was not submitted, the run stopped."
            ]
        );
        let failed = notices(&m, &fmt).pop().unwrap();
        assert_eq!(failed.severity, NoticeSeverity::Error);
    }
}
