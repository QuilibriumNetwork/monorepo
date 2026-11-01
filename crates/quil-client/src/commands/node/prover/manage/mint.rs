//! The Coins tab's reward mint: `M` reads the claimable reward and quotes
//! the fee, a confirmation names the mint, `y` proves and submits its
//! authorization through `qclient token mint`'s own functions, which save
//! it as `mint-<frame>.bin`. The Claim status panel lists those files; `C`
//! claims the one under its cursor once GLOBAL has finalized it. One
//! action at a time, shields included; `--render` reads and quotes but
//! never runs.
//!
//! A mint or claim logs one operator line when it starts and one with its
//! outcome (target [`LOG_TARGET`]): the stage, frames, the duration and an
//! error class; never amounts, the recipient, the file or hashes. The
//! private action log ([`crate::commands::token::action_log`]) keeps the
//! details.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{KeyCode, KeyEvent};

use super::coins::Notice;
use super::model::{Model, NoticeSeverity};
use super::shield::{error_class, LOG_TARGET};
use super::update::Cmd;

/// A saved authorization, as the Claim status lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub path: PathBuf,
    pub cited_frame: u64,
    /// Reward and fee in base units; `None` when the file does not decode.
    pub amounts: Option<(u128, u128)>,
}

/// The saved authorization's state. `GetMintAuthorizationStatus` (#1062)
/// answers it once nodes serve it; until then every row is `Unavailable`
/// and `C` asks for the finalized witness the claim needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Unavailable,
}

/// The state of `saved` on this node.
pub fn status(_saved: &Saved) -> Status {
    // #1062: GetMintAuthorizationStatus goes here (claimable, awaiting
    // root, not included, no citable root, no retained root).
    Status::Unavailable
}

/// Which stage a confirmation is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    Authorize,
    /// Claim the authorization saved at `path`, whose GLOBAL witness cites
    /// `witness`.
    Claim {
        path: PathBuf,
        witness: u64,
    },
}

/// What a mint confirmation shows, read and quoted just before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    pub stage: Stage,
    /// The GLOBAL frame the reward (or the authorization) cites.
    pub cited_frame: u64,
    pub reward: u128,
    pub fee: u128,
    /// `--max-fee`; the authorization's fee is quoted under it.
    pub max_fee: u128,
    /// This wallet's address, in full.
    pub recipient: String,
}

impl Preview {
    pub fn minted(&self) -> u128 {
        self.reward.saturating_sub(self.fee)
    }
}

/// What a running mint or claim reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    Proving,
    /// The authorization was submitted and saved; the GLOBAL frame it
    /// cites, which may be later than the confirmed one, and the reward it
    /// mints, which may be larger.
    Submitted {
        cited_frame: u64,
        reward: u128,
        saved: PathBuf,
    },
    Claimed,
    Note(String),
    /// The private action log could not be written: why.
    LogFailed(String),
    /// The fee quote changed since the confirmation: a confirmation of the
    /// amount and fee read now, and its frame. Nothing was proved.
    Requoted(Preview),
    Done(Result<(), String>),
}

#[derive(Debug)]
pub enum Dialog {
    Preparing(Instant, bool),
    Confirm(Preview),
}

#[derive(Debug)]
pub struct Run {
    pub preview: Preview,
    pub started: Instant,
    /// The GLOBAL head the manager last received when the run started.
    pub start_frame: u64,
    pub proving: Option<Instant>,
    pub submitted: Option<PathBuf>,
    /// The reward the submitted authorization mints: the confirmed one or,
    /// when it grew before the run read it, more.
    pub submitted_reward: Option<u128>,
    pub claimed: bool,
    pub note: Option<String>,
    pub done: Option<Result<(), String>>,
}

#[derive(Debug, Default)]
pub struct Mint {
    pub dialog: Option<Dialog>,
    pub run: Option<Run>,
    pub refused: Option<(String, SystemTime)>,
    /// The saved authorizations, newest first, read with each legacy read.
    pub saved: Vec<Saved>,
    /// The Claim status row under the cursor.
    pub cursor: usize,
    /// The last run's private action log could not be written: why.
    pub log_failed: Option<String>,
    /// The fee a run found quoted otherwise, from and to in base units,
    /// while its new confirmation is open.
    pub requoted: Option<(u128, u128)>,
}

/// The operator log's name of a stage.
fn kind(stage: &Stage) -> &'static str {
    match stage {
        Stage::Authorize => "mint",
        Stage::Claim { .. } => "mint_claim",
    }
}

/// The operator log's start line.
fn log_start(run: &Run) {
    tracing::info!(
        target: LOG_TARGET,
        kind = kind(&run.preview.stage),
        phase = "start",
        frame = run.start_frame,
        "mint started"
    );
}

/// Whether the run minted more than its confirmation showed.
fn reward_grew(run: &Run) -> bool {
    run.submitted_reward
        .is_some_and(|reward| reward > run.preview.reward)
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
        kind = kind(&run.preview.stage),
        phase = "outcome",
        outcome,
        error_class = class,
        reason,
        fee_cap_hit = class == "fee_cap",
        submitted = run.submitted.is_some() || run.claimed,
        reward_grew = reward_grew(run),
        duration_s = run.started.elapsed().as_secs(),
        start_frame = run.start_frame,
        frame,
        "mint finished"
    );
}

/// The operator log's outcome line of a run that found the fee quoted
/// otherwise and asks for a new confirmation, at GLOBAL `frame`.
fn log_requoted(run: &Run, frame: u64) {
    tracing::info!(
        target: LOG_TARGET,
        kind = kind(&run.preview.stage),
        phase = "outcome",
        outcome = "requoted",
        error_class = "fee_changed",
        reason = "the fee quote changed since the confirmation",
        fee_cap_hit = false,
        submitted = false,
        reward_grew = false,
        duration_s = run.started.elapsed().as_secs(),
        start_frame = run.start_frame,
        frame,
        "mint finished"
    );
}

/// A mint or claim is proving or submitting.
pub fn running(m: &Model) -> bool {
    m.coins
        .mint
        .run
        .as_ref()
        .is_some_and(|run| run.done.is_none())
}

/// Some action (a shield, a mint or a claim) is under way or awaiting its
/// confirmation.
fn busy(m: &Model) -> bool {
    running(m)
        || super::shield::running(m)
        || super::transfer::running(m)
        || m.coins.transfer.dialog.is_some()
        || m.coins.mint.dialog.is_some()
        || m.coins.shield.dialog.is_some()
}

/// Why `M` cannot start now, as the line pressing it shows; `None` when
/// there is a reward to mint and nothing else runs.
pub fn mint_refusal(m: &Model) -> Option<String> {
    let why = if busy(m) {
        "another action is in progress; one action at a time."
    } else if !m.claimable_reward.is_some_and(|(units, _)| units > 0) {
        "no claimable reward to mint."
    } else {
        return None;
    };
    Some(format!("Mint: {why}"))
}

/// Why `C` cannot start now; `None` when an authorization is under the
/// Mint cursor and nothing else runs.
pub fn claim_refusal(m: &Model) -> Option<String> {
    let why = if busy(m) {
        "another action is in progress; one action at a time."
    } else if m.coins.mint.saved.get(m.coins.mint.cursor).is_none() {
        "no saved authorization to claim; ‹M› authorizes a mint."
    } else {
        return None;
    };
    Some(format!("Mint: {why}"))
}

/// `M`: read the reward and quote the fee for a confirmation.
pub fn request_mint(m: &mut Model) -> Vec<Cmd> {
    if let Some(why) = mint_refusal(m) {
        m.status_msg = why;
        m.status_is_error = false;
        return vec![];
    }
    m.coins.mint.refused = None;
    m.coins.mint.requoted = None;
    m.coins.mint.dialog = Some(Dialog::Preparing(Instant::now(), false));
    vec![Cmd::MintPrepare]
}

/// `C`: check the saved authorization under the cursor for its finalized
/// witness, for a confirmation.
pub fn request_claim(m: &mut Model) -> Vec<Cmd> {
    if let Some(why) = claim_refusal(m) {
        m.status_msg = why;
        m.status_is_error = false;
        return vec![];
    }
    let saved = m.coins.mint.saved[m.coins.mint.cursor].clone();
    m.coins.mint.refused = None;
    m.coins.mint.dialog = Some(Dialog::Preparing(Instant::now(), true));
    vec![Cmd::ClaimPrepare(saved.path, saved.cited_frame)]
}

/// The preparation's answer: a confirmation, or why there is none.
pub fn apply_preview(m: &mut Model, preview: Result<Preview, String>) {
    if !matches!(m.coins.mint.dialog, Some(Dialog::Preparing(..))) {
        return;
    }
    match preview {
        Ok(preview) => m.coins.mint.dialog = Some(Dialog::Confirm(preview)),
        Err(error) => {
            m.coins.mint.dialog = None;
            m.coins.mint.refused = Some((error, SystemTime::now()));
        }
    }
}

/// A key while the confirmation is open: `y` starts; any other cancels.
pub fn dialog_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    let confirmed = ev.code == KeyCode::Char('y') && ev.modifiers.is_empty();
    m.coins.mint.requoted = None;
    match m.coins.mint.dialog.take() {
        Some(Dialog::Confirm(preview)) if confirmed => {
            let run = Run {
                preview: preview.clone(),
                started: Instant::now(),
                start_frame: m.last_global_head,
                proving: None,
                submitted: None,
                submitted_reward: None,
                claimed: false,
                note: None,
                done: None,
            };
            log_start(&run);
            m.coins.mint.run = Some(run);
            m.coins.mint.log_failed = None;
            m.status_msg.clear();
            vec![Cmd::MintRun(preview)]
        }
        _ => {
            m.status_msg = "Mint: cancelled; nothing was submitted.".into();
            m.status_is_error = false;
            vec![]
        }
    }
}

/// A running mint's or claim's report.
pub fn apply_progress(m: &mut Model, progress: Progress) {
    if let Progress::Requoted(preview) = progress {
        // The run ends; its confirmation opens again with the fee quoted
        // now.
        let Some(run) = m.coins.mint.run.take() else {
            return;
        };
        log_requoted(&run, m.last_global_head);
        m.coins.mint.requoted = Some((run.preview.fee, preview.fee));
        m.coins.mint.dialog = Some(Dialog::Confirm(preview));
        return;
    }
    let Some(run) = m.coins.mint.run.as_mut() else {
        return;
    };
    match progress {
        Progress::Requoted(_) => {}
        Progress::Proving => run.proving = Some(Instant::now()),
        Progress::Submitted {
            cited_frame,
            reward,
            saved,
        } => {
            run.proving = None;
            run.preview.cited_frame = cited_frame;
            run.submitted = Some(saved);
            run.submitted_reward = Some(reward);
            // The new file shows with the next read.
            m.coins.legacy.refresh_at = Some(Instant::now());
        }
        Progress::Claimed => run.claimed = true,
        Progress::Note(line) => run.note = Some(line),
        Progress::LogFailed(why) => m.coins.mint.log_failed = Some(why),
        Progress::Done(result) => {
            run.proving = None;
            run.done = Some(result);
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

/// The mint's notices, in display order.
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
    let mint = &m.coins.mint;
    if let Some(Dialog::Preparing(since, claim)) = &mint.dialog {
        push(
            "mint-preparing",
            NoticeSeverity::Info,
            true,
            false,
            if *claim {
                format!("Mint claim: reading its GLOBAL witness {}.", bucket(*since))
            } else {
                format!(
                    "Mint: reading the reward and quoting the fee {}.",
                    bucket(*since)
                )
            },
        );
    }
    if let (Some((from, to)), Some(Dialog::Confirm(_))) = (mint.requoted, &mint.dialog) {
        // In base units, as the confirmation's Fee row: a fee rounds to 0
        // Q. A render shows them too, as it shows that row.
        push(
            "mint-requoted",
            NoticeSeverity::Info,
            true,
            false,
            format!("Mint: the fee quote changed from {from} to {to} base units; confirm again."),
        );
    }
    if let Some((error, _)) = &mint.refused {
        push(
            "mint-refused",
            NoticeSeverity::Error,
            false,
            false,
            format!("Mint: not started ({error}); nothing was submitted."),
        );
    }
    if let Some(run) = &mint.run {
        let frame = run.preview.cited_frame;
        let claim = matches!(run.preview.stage, Stage::Claim { .. });
        let what = if claim { "Mint claim" } else { "Mint" };
        if let Some(since) = run.proving {
            push(
                "mint-proving",
                NoticeSeverity::Info,
                true,
                false,
                format!(
                    "Mint f{frame}: proving the authorization {}.",
                    bucket(since)
                ),
            );
        }
        if run.submitted.is_some() {
            let confirmed = run.preview.minted();
            let minted = run
                .submitted_reward
                .map_or(confirmed, |reward| reward.saturating_sub(run.preview.fee));
            // The reward grew before the run read it: the larger amount was
            // minted, to this wallet, and the line says so.
            let grew = if reward_grew(run) {
                format!(" (confirmed {} Q; the reward grew)", fmt_amount(confirmed))
            } else {
                String::new()
            };
            push(
                "mint-submitted",
                NoticeSeverity::Info,
                true,
                false,
                format!(
                    "Mint f{frame}: authorization of {} Q submitted{grew}; inclusion not yet \
                     confirmed; ‹C› claims it once GLOBAL finalizes it.",
                    fmt_amount(minted)
                ),
            );
        }
        if run.claimed {
            push(
                "mint-claimed",
                NoticeSeverity::Info,
                true,
                false,
                format!(
                    "Mint claim f{frame}: {} Q submitted; finalized inclusion is not yet \
                     confirmed.",
                    fmt_amount(run.preview.minted())
                ),
            );
        }
        if let Some(Err(error)) = &run.done {
            push(
                "mint-failed",
                NoticeSeverity::Error,
                false,
                false,
                format!("{what} f{frame} failed: {error}."),
            );
        }
    }
    if let Some(why) = &mint.log_failed {
        push(
            "mint-log-failed",
            NoticeSeverity::Warning,
            false,
            false,
            format!("Action log: not written ({why}); the mint is unaffected."),
        );
    }
    if !mint.saved.is_empty() {
        push(
            "mint-saved",
            NoticeSeverity::Info,
            false,
            false,
            format!(
                "Mint: {} saved; this node reports no authorization status, so ‹C› checks \
                 for the finalized witness before claiming.",
                if mint.saved.len() == 1 {
                    "1 authorization".to_string()
                } else {
                    format!("{} authorizations", mint.saved.len())
                }
            ),
        );
    }
    out
}

#[cfg(test)]
mod mint_tests {
    use super::super::coins::CoinsFocus;
    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    pub(crate) fn preview(stage: Stage) -> Preview {
        Preview {
            stage,
            cited_frame: 1200,
            reward: 10_000,
            fee: 100,
            max_fee: 800_000_000,
            recipient: "0xabc".into(),
        }
    }

    #[test]
    fn m_asks_y_runs_and_one_action_runs_at_a_time() {
        let mut m = Model::new();
        assert!(request_mint(&mut m).is_empty());
        assert!(m.status_msg.contains("no claimable reward"));
        m.claimable_reward = Some((10_000, 1200));
        assert!(matches!(
            request_mint(&mut m).as_slice(),
            [Cmd::MintPrepare]
        ));
        apply_preview(&mut m, Ok(preview(Stage::Authorize)));
        assert!(dialog_key(&mut m, key('x')).is_empty());
        assert!(m.status_msg.contains("cancelled; nothing was submitted"));
        request_mint(&mut m);
        apply_preview(&mut m, Ok(preview(Stage::Authorize)));
        assert!(matches!(
            dialog_key(&mut m, key('y')).as_slice(),
            [Cmd::MintRun(p)] if *p == preview(Stage::Authorize)
        ));
        assert!(running(&m));
        // No second action, and the shield's guard covers a mint too.
        assert!(request_mint(&mut m).is_empty());
        assert!(super::super::shield::request(&mut m).is_empty());
        assert!(super::super::shield::quit_guard(&mut m, &key('q'), true).is_some());
    }

    #[test]
    fn c_claims_the_saved_authorization_under_the_cursor() {
        let mut m = Model::new();
        assert!(request_claim(&mut m).is_empty());
        assert!(m.status_msg.contains("no saved authorization"));
        m.coins.mint.saved = vec![
            Saved {
                path: "/x/mint-1300.bin".into(),
                cited_frame: 1300,
                amounts: Some((900, 9)),
            },
            Saved {
                path: "/x/mint-1200.bin".into(),
                cited_frame: 1200,
                amounts: None,
            },
        ];
        m.coins.focus = CoinsFocus::Middle;
        m.coins.mint.cursor = 1;
        assert!(matches!(
            request_claim(&mut m).as_slice(),
            [Cmd::ClaimPrepare(path, 1200)] if path.ends_with("mint-1200.bin")
        ));
        // Not finalized: refused with the reason, nothing runs.
        apply_preview(&mut m, Err("no GLOBAL witness yet".into()));
        assert!(m.coins.mint.dialog.is_none() && !running(&m));
        let texts: Vec<String> = notices(&m, &|u| u.to_string())
            .into_iter()
            .map(|n| n.text)
            .collect();
        assert_eq!(
            texts,
            [
                "Mint: not started (no GLOBAL witness yet); nothing was submitted.",
                "Mint: 2 authorizations saved; this node reports no authorization status, so \
                 ‹C› checks for the finalized witness before claiming."
            ]
        );
        assert_eq!(status(&m.coins.mint.saved[0]), Status::Unavailable);
    }

    #[test]
    fn a_mint_reads_as_proving_submitted_then_failed() {
        let mut m = Model::new();
        m.claimable_reward = Some((10_000, 1200));
        request_mint(&mut m);
        apply_preview(&mut m, Ok(preview(Stage::Authorize)));
        dialog_key(&mut m, key('y'));
        apply_progress(&mut m, Progress::Proving);
        let texts = |m: &Model| -> Vec<String> {
            notices(m, &|u| u.to_string())
                .into_iter()
                .map(|n| n.text)
                .collect()
        };
        assert_eq!(texts(&m), ["Mint f1200: proving the authorization <60s."]);
        // Read again at a later frame, the authorization cites it.
        apply_progress(
            &mut m,
            Progress::Submitted {
                cited_frame: 1203,
                reward: 10_000,
                saved: "/x/mint-1203.bin".into(),
            },
        );
        assert!(m.coins.legacy.refresh_at.is_some());
        apply_progress(&mut m, Progress::Done(Ok(())));
        assert!(!running(&m));
        assert_eq!(
            texts(&m),
            [
                "Mint f1203: authorization of 9900 Q submitted; inclusion not yet confirmed; \
              ‹C› claims it once GLOBAL finalizes it."
            ]
        );
        // A refused action-log write is a warning; the mint goes on.
        apply_progress(&mut m, Progress::LogFailed("wallet has mode 755".into()));
        let notice = notices(&m, &|u| u.to_string())
            .into_iter()
            .find(|n| n.key == "mint-log-failed")
            .unwrap();
        assert_eq!(notice.severity, NoticeSeverity::Warning);
        assert_eq!(
            notice.text,
            "Action log: not written (wallet has mode 755); the mint is unaffected."
        );
    }

    /// A run that finds the fee quoted otherwise ends without proving and
    /// opens the confirmation again with the amount and fee read now,
    /// saying so in base units, as the confirmation's Fee row shows the
    /// fee in a render too; `y` runs the new one. Its operator line says
    /// requoted, without the amounts.
    #[test]
    fn a_changed_fee_opens_the_confirmation_again() {
        let mut m = Model::new();
        m.claimable_reward = Some((10_000, 1200));
        m.last_global_head = 777;
        request_mint(&mut m);
        apply_preview(&mut m, Ok(preview(Stage::Authorize)));
        let requoted = Preview {
            cited_frame: 1207,
            reward: 12_345,
            fee: 101,
            ..preview(Stage::Authorize)
        };
        let text = super::super::shield::shield_tests::operator_log(|| {
            dialog_key(&mut m, key('y'));
            apply_progress(&mut m, Progress::Requoted(requoted.clone()));
        });
        assert!(!running(&m) && m.coins.mint.run.is_none());
        assert!(matches!(&m.coins.mint.dialog, Some(Dialog::Confirm(p)) if *p == requoted));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        for part in [
            r#"outcome="requoted""#,
            r#"error_class="fee_changed""#,
            "submitted=false",
            "reward_grew=false",
        ] {
            assert!(lines[1].contains(part), "{part}: {}", lines[1]);
        }
        for private in ["10000", "12345", "1207", "101"] {
            assert!(!text.contains(private), "{private}: {text}");
        }
        let texts = |m: &Model| -> Vec<String> {
            notices(m, &|u| u.to_string())
                .into_iter()
                .map(|n| n.text)
                .collect()
        };
        let changed = ["Mint: the fee quote changed from 100 to 101 base units; confirm again."];
        assert_eq!(texts(&m), changed);
        m.mask_private = true;
        assert_eq!(texts(&m), changed);
        m.mask_private = false;
        assert!(matches!(
            dialog_key(&mut m, key('y')).as_slice(),
            [Cmd::MintRun(p)] if *p == requoted
        ));
        assert!(running(&m) && texts(&m).iter().all(|t| !t.contains("confirm again")));
    }

    /// A reward that grew before the run read it, at the confirmed fee, is
    /// minted in full without a new confirmation: the submitted line names
    /// the amount minted and the one confirmed, both in Q, and the frame
    /// the authorization cites. The operator line says the reward grew,
    /// without either amount.
    #[test]
    fn a_grown_reward_is_minted_and_named_beside_the_confirmed_one() {
        let mut m = Model::new();
        m.claimable_reward = Some((10_000, 1200));
        m.last_global_head = 777;
        request_mint(&mut m);
        apply_preview(&mut m, Ok(preview(Stage::Authorize)));
        let text = super::super::shield::shield_tests::operator_log(|| {
            dialog_key(&mut m, key('y'));
            apply_progress(&mut m, Progress::Proving);
            apply_progress(
                &mut m,
                Progress::Submitted {
                    cited_frame: 1207,
                    reward: 12_345,
                    saved: "/x/mint-1207.bin".into(),
                },
            );
            apply_progress(&mut m, Progress::Done(Ok(())));
        });
        assert!(!running(&m) && m.coins.mint.dialog.is_none());
        let texts: Vec<String> = notices(&m, &|u| u.to_string())
            .into_iter()
            .map(|n| n.text)
            .collect();
        assert_eq!(
            texts,
            [
                "Mint f1207: authorization of 12245 Q submitted (confirmed 9900 Q; the reward \
                 grew); inclusion not yet confirmed; ‹C› claims it once GLOBAL finalizes it."
            ]
        );
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        for part in [r#"outcome="ok""#, "submitted=true", "reward_grew=true"] {
            assert!(lines[1].contains(part), "{part}: {}", lines[1]);
        }
        for private in ["10000", "12345", "12245", "9900", "1207"] {
            assert!(!text.contains(private), "{private}: {text}");
        }
    }

    /// Each stage logs one operator line at the start and one at the
    /// outcome, with frames and an error class; no amount, recipient, file,
    /// node address or path reaches it, though the error carries some.
    #[test]
    fn operator_log_lines_carry_the_stage_and_no_private_field() {
        let recipient = format!("0x{}", "c3".repeat(40));
        let stages = [
            ("mint", Stage::Authorize),
            (
                "mint_claim",
                Stage::Claim {
                    path: "/home/operator/.config/mint-1200.bin".into(),
                    witness: 1250,
                },
            ),
        ];
        for (name, stage) in stages {
            let mut m = Model::new();
            m.claimable_reward = Some((123_456_789, 1200));
            m.last_global_head = 777;
            m.coins.mint.dialog = Some(Dialog::Confirm(Preview {
                stage,
                cited_frame: 1200,
                reward: 123_456_789,
                fee: 98_765,
                max_fee: 43_210,
                recipient: recipient.clone(),
            }));
            let text = super::super::shield::shield_tests::operator_log(|| {
                dialog_key(&mut m, key('y'));
                apply_progress(
                    &mut m,
                    Progress::Submitted {
                        cited_frame: 1201,
                        reward: 123_456_789,
                        saved: "/home/operator/.config/mint-1201.bin".into(),
                    },
                );
                m.last_global_head = 790;
                apply_progress(
                    &mut m,
                    Progress::Done(Err(format!(
                        "the node at 10.1.2.3:8337 is peer …a1b2c3, but submissions would be \
                         signed by /home/operator/.config (peer …d4e5f6), and a node accepts \
                         only submissions signed with its own peer key; amount 123456789 to \
                         {recipient}"
                    ))),
                );
            });
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.len(), 2, "{text}");
            let kind = format!("kind=\"{name}\"");
            for part in ["qclient::action", &kind, r#"phase="start""#, "frame=777"] {
                assert!(lines[0].contains(part), "{part}: {}", lines[0]);
            }
            for part in [
                &kind,
                r#"phase="outcome""#,
                r#"outcome="failed""#,
                r#"error_class="identity""#,
                "fee_cap_hit=false",
                "submitted=true",
                "reward_grew=false",
                "start_frame=777",
                "frame=790",
                "duration_s=",
            ] {
                assert!(lines[1].contains(part), "{part}: {}", lines[1]);
            }
            for private in [
                "c3c3",
                "123456789",
                "98765",
                "43210",
                "mint-12",
                "1200",
                "1201",
                "1250",
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
    }
}
