//! The Coins tab's shield action: `S` reads and quotes `token shield-all`'s
//! batches, a confirmation names them, `y` runs them in the background
//! through the CLI's own functions. One run at a time; quitting during one
//! asks first. `--render` reads and quotes but never runs.

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
}

/// A run is proving or submitting.
pub fn running(m: &Model) -> bool {
    m.coins
        .shield
        .run
        .as_ref()
        .is_some_and(|run| run.done.is_none())
}

fn refuse(m: &mut Model, why: String) -> Vec<Cmd> {
    m.status_msg = format!("Shield: {why}");
    m.status_is_error = false;
    vec![]
}

/// `S`: read and quote the batches for a confirmation, when there is
/// something to shield and nothing else runs.
pub fn request(m: &mut Model) -> Vec<Cmd> {
    if running(m) {
        return refuse(m, "a run is in progress; one action at a time.".into());
    }
    if m.coins.shield.dialog.is_some() {
        return vec![];
    }
    let Some((Some(snapshot), _, _)) = &m.coins.legacy.answer else {
        return refuse(m, "legacy coins are not read yet; ‹r› reads them.".into());
    };
    if let Some((frame, left)) = coins::shields_open_at(snapshot) {
        return refuse(m, format!("shields open at f{frame}, in {left} frames."));
    }
    if snapshot.tally.unshielded <= snapshot.pending {
        return refuse(m, "no unshielded legacy coins to shield.".into());
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
            m.coins.shield.run = Some(Run {
                preview: preview.clone(),
                started: Instant::now(),
                proving: None,
                submitted: Vec::new(),
                skipped: 0,
                note: None,
                done: None,
                failed_at: None,
            });
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
    if quit && running(m) {
        m.coins.shield.quit_pending = true;
        m.status_msg = "A shield submission is in progress: ‹y› quits and abandons the batch \
                        being proved; any other key keeps it running."
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
        Progress::Done(result) => {
            if result.is_err() {
                run.failed_at = run.proving.map(|(index, ..)| index);
            }
            run.proving = None;
            run.done = Some(result);
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
        push(
            "shield-included",
            NoticeSeverity::Info,
            true,
            true,
            format!(
                "Shield: {} of {count} included: {} coins, {} Q shielded.",
                plural(included.len(), "batch", "batches"),
                included.iter().map(|b| b.addresses.len()).sum::<usize>(),
                fmt_amount(included.iter().map(|b| b.shielded).sum())
            ),
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
mod shield_tests {
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
