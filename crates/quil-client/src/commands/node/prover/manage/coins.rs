//! The Coins tab: this node's claimable rewards and legacy coins, read
//! only. Claimable rewards come with each Provers refresh; legacy coins
//! are read in the background once when the manager starts, so the tab
//! bar counts their conditions from either tab, then every
//! [`LEGACY_REFRESH`] while the Coins tab is open, and on `r`. A read
//! lists both owner forms through `token legacy`'s own functions, so the
//! figures match `qclient token legacy`.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::commands::token::legacy::Snapshot;

use super::model::{Model, NoticeSeverity, Tab};
use super::update::Cmd;

/// How often an open Coins tab reads legacy coins again (6–9 s per read on
/// a regular node).
pub const LEGACY_REFRESH: Duration = Duration::from_secs(600);

/// Rows of the Balances panel, top to bottom.
pub const BALANCE_ROWS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoinsFocus {
    #[default]
    Balances,
    Notifications,
}

/// One legacy read's answer: `None` when the node config has no Ed448
/// key, which owns no legacy coins.
pub type LegacyAnswer = Result<Option<Snapshot>, String>;

#[derive(Debug, Default)]
pub struct Legacy {
    /// A read is in flight, started at this time.
    pub reading: Option<Instant>,
    /// When the last read started; the next one is due [`LEGACY_REFRESH`]
    /// later.
    pub last_start: Option<Instant>,
    /// The last successful answer, when it arrived and how long it took.
    pub answer: Option<(Option<Snapshot>, SystemTime, Duration)>,
    /// The last read failed with this reason.
    pub error: Option<String>,
    /// Consecutive failed reads, and when the first of them failed.
    pub failures: u32,
    pub failing_since: Option<SystemTime>,
}

#[derive(Debug, Default)]
pub struct Coins {
    pub focus: CoinsFocus,
    /// The Balances row under the cursor: 0 claimable, 1 legacy.
    pub cursor: usize,
    pub legacy: Legacy,
    /// When each current notice was first shown, by its key.
    pub notice_since: HashMap<&'static str, SystemTime>,
}

/// Start a legacy read unless one is in flight.
fn start_legacy(m: &mut Model, now: Instant) -> Vec<Cmd> {
    if m.coins.legacy.reading.is_some() {
        return vec![];
    }
    m.coins.legacy.reading = Some(now);
    m.coins.legacy.last_start = Some(now);
    vec![Cmd::FetchLegacy]
}

/// The legacy read that is due: the first one at start on either tab,
/// then one every [`LEGACY_REFRESH`] while the Coins tab is open.
pub fn due(m: &mut Model, now: Instant) -> Vec<Cmd> {
    let last = m.coins.legacy.last_start;
    let stale = last.is_none_or(|start| now.saturating_duration_since(start) >= LEGACY_REFRESH);
    if last.is_none() || (m.tab == Tab::Coins && stale) {
        start_legacy(m, now)
    } else {
        vec![]
    }
}

/// Show the Coins tab, with its read when one is due.
pub fn open(m: &mut Model) -> Vec<Cmd> {
    m.tab = Tab::Coins;
    m.notice_offset = 0;
    due(m, Instant::now())
}

/// A finished legacy read.
pub fn apply_legacy(m: &mut Model, answer: LegacyAnswer, took: Duration) {
    let legacy = &mut m.coins.legacy;
    legacy.reading = None;
    match answer {
        Ok(snapshot) => {
            legacy.answer = Some((snapshot, SystemTime::now(), took));
            legacy.error = None;
            legacy.failures = 0;
            legacy.failing_since = None;
        }
        Err(error) => {
            legacy.error = Some(error);
            legacy.failures += 1;
            legacy.failing_since.get_or_insert_with(SystemTime::now);
        }
    }
}

/// Keys while the Coins tab is on screen. Allocation actions and the
/// Provers panels' keys do nothing here.
pub fn handle_key(m: &mut Model, ev: KeyEvent) -> Vec<Cmd> {
    if ev.modifiers.contains(KeyModifiers::CONTROL) {
        return vec![];
    }
    let notices = m.coins.focus == CoinsFocus::Notifications;
    match ev.code {
        KeyCode::Char('1') => {
            m.tab = Tab::Provers;
            m.notice_offset = 0;
        }
        KeyCode::Char('r') => {
            if m.coins.legacy.reading.is_some() {
                m.status_msg = "Legacy coins: a read is already in progress.".into();
                m.status_is_error = false;
                return vec![];
            }
            return start_legacy(m, Instant::now());
        }
        KeyCode::Tab | KeyCode::BackTab => {
            m.coins.focus = if notices {
                CoinsFocus::Balances
            } else {
                CoinsFocus::Notifications
            };
        }
        KeyCode::Up | KeyCode::Char('k') if notices => {
            m.notice_offset = m.notice_offset.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') if notices => {
            m.notice_offset =
                (m.notice_offset + 1).min(m.notice_lines.saturating_sub(m.notice_visible));
        }
        KeyCode::Up | KeyCode::Char('k') => m.coins.cursor = m.coins.cursor.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => {
            m.coins.cursor = (m.coins.cursor + 1).min(BALANCE_ROWS - 1);
        }
        KeyCode::PageUp => {
            m.notice_offset = m.notice_offset.saturating_sub(m.notice_visible.max(1));
        }
        KeyCode::PageDown => {
            m.notice_offset = (m.notice_offset + m.notice_visible.max(1))
                .min(m.notice_lines.saturating_sub(m.notice_visible));
        }
        KeyCode::Home => m.notice_offset = 0,
        KeyCode::End => m.notice_offset = m.notice_lines.saturating_sub(m.notice_visible),
        _ => {}
    }
    vec![]
}

/// `HH:MM UTC` of a wall-clock time.
pub fn utc_hm(time: SystemTime) -> String {
    let seconds = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{:02}:{:02} UTC", seconds / 3600 % 24, seconds / 60 % 60)
}

/// A Coins notice. `attention` marks an item waiting for the user's
/// action: it is drawn in the info color with the `◆` marker, and shows
/// from the default (warnings+) level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub key: &'static str,
    pub severity: NoticeSeverity,
    pub attention: bool,
    pub text: String,
}

impl Notice {
    /// The level from which the notice shows.
    pub fn rank(&self) -> NoticeSeverity {
        if self.attention {
            NoticeSeverity::Warning
        } else {
            self.severity
        }
    }
}

/// The attention marker, so meaning never rests on color alone.
pub const ATTENTION: &str = "◆";

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// Shields of legacy coins open at this GLOBAL frame, and the frames
/// left, while the received head is before it.
pub fn shields_open_at(snapshot: &Snapshot) -> Option<(u64, u64)> {
    let rule = snapshot.rule?;
    let head = *snapshot.head.as_ref().ok()?;
    (head < rule.shield_all_from).then(|| (rule.shield_all_from, rule.shield_all_from - head))
}

/// Every current Coins condition, in display order.
pub fn notices(m: &Model, fmt_amount: impl Fn(u128) -> String) -> Vec<Notice> {
    let mut out = Vec::new();
    let mut push = |key, severity, attention, text: String| {
        out.push(Notice {
            key,
            severity,
            attention,
            text,
        })
    };
    match (&m.claimable_reward, &m.reward_error) {
        (Some((units, frame)), _) if *units > 0 => push(
            "coins-claimable",
            NoticeSeverity::Info,
            true,
            format!(
                "Claimable: {} Q at f{frame}; `qclient token mint` authorizes a mint.",
                fmt_amount(*units)
            ),
        ),
        (None, Some(error)) => push(
            "coins-claimable-failed",
            NoticeSeverity::Warning,
            false,
            format!("Claimable: read failed ({error})."),
        ),
        _ => {}
    }
    let legacy = &m.coins.legacy;
    if let (Some(error), Some(since)) = (&legacy.error, legacy.failing_since) {
        let figures = match &legacy.answer {
            Some((_, at, _)) => format!("; figures as of {}", utc_hm(*at)),
            None => String::new(),
        };
        push(
            "coins-legacy-failed",
            NoticeSeverity::Warning,
            false,
            format!(
                "Legacy coins: read failed {} since {} ({error}){figures}.",
                plural(legacy.failures as usize, "time", "times"),
                utc_hm(since)
            ),
        );
    }
    let Some((Some(snapshot), _, _)) = &legacy.answer else {
        return out;
    };
    let unshielded = snapshot.tally.unshielded;
    if unshielded == 0 {
        return out;
    }
    let total = unshielded + snapshot.tally.shielded;
    match (shields_open_at(snapshot), snapshot.plan) {
        (Some((frame, left)), _) => push(
            "coins-shield-gate",
            NoticeSeverity::Info,
            false,
            format!(
                "Shields open at f{frame}, in {}.",
                plural(left as usize, "frame", "frames")
            ),
        ),
        (None, Some(plan)) => push(
            "coins-unshielded",
            NoticeSeverity::Info,
            true,
            format!(
                "Legacy coins: {unshielded} of {total} unshielded in {}{}; \
                 `qclient token shield-all` shields them.",
                if plan.exact { "" } else { "≥" },
                plural(plan.batches, "batch", "batches")
            ),
        ),
        (None, None) => push(
            "coins-unshielded",
            NoticeSeverity::Info,
            true,
            format!("Legacy coins: {unshielded} of {total} unshielded."),
        ),
    }
    if let Some(plan) = snapshot.plan {
        if plan.outside > 0 {
            push(
                "coins-outside",
                NoticeSeverity::Info,
                false,
                format!(
                    "Legacy coins: {} on no live shard; a later run covers them.",
                    plan.outside
                ),
            );
        }
        if !plan.exact {
            push(
                "coins-plan-inexact",
                NoticeSeverity::Warning,
                false,
                format!(
                    "Shield plan: shard list unavailable; batches may exceed {}.",
                    plan.batches
                ),
            );
        }
    }
    out
}

/// The notices that show at the current level.
pub fn shown_notices(m: &Model, fmt_amount: impl Fn(u128) -> String) -> Vec<Notice> {
    notices(m, fmt_amount)
        .into_iter()
        .filter(|notice| notice.rank() >= m.notice_minimum)
        .collect()
}

#[cfg(test)]
mod coins_tests {
    use super::*;
    use crate::commands::token::legacy::{ShieldPlan, ShieldRule, Tally};

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn snapshot(unshielded: usize, head: u64, outside: usize, exact: bool) -> Snapshot {
        Snapshot {
            tally: Tally {
                units: 5 * unshielded as u128,
                unshielded,
                shielded: 2,
            },
            plan: (unshielded > 0).then_some(ShieldPlan {
                batches: 3,
                exact,
                outside,
            }),
            batch_max: Some(96),
            head: Ok(head),
            rule: Some(ShieldRule {
                shield_from: 900,
                shield_all_from: 1000,
            }),
            pages: 4,
        }
    }

    #[test]
    fn legacy_reads_on_open_every_ten_minutes_and_on_r() {
        let mut m = Model::new();
        let now = Instant::now();
        // At start, on Provers: one read; later, Provers reads no more.
        assert!(matches!(due(&mut m, now).as_slice(), [Cmd::FetchLegacy]));
        apply_legacy(&mut m, Ok(None), Duration::from_secs(6));
        assert!(due(&mut m, now + LEGACY_REFRESH * 2).is_empty());
        // Opening Coins within 10 minutes of the last read reuses it.
        assert!(open(&mut m).is_empty());
        assert!(matches!(
            due(&mut m, now + LEGACY_REFRESH).as_slice(),
            [Cmd::FetchLegacy]
        ));
        // In flight: neither the cadence nor `r` starts another.
        assert!(due(&mut m, now + LEGACY_REFRESH * 2).is_empty());
        assert!(handle_key(&mut m, key('r')).is_empty());
        assert!(m.status_msg.contains("already in progress"));
        apply_legacy(&mut m, Ok(None), Duration::from_secs(6));
        let start = m.coins.legacy.last_start.unwrap();
        assert!(due(&mut m, start + LEGACY_REFRESH - Duration::from_secs(1)).is_empty());
        assert!(matches!(
            due(&mut m, start + LEGACY_REFRESH).as_slice(),
            [Cmd::FetchLegacy]
        ));
        apply_legacy(&mut m, Err("x".into()), Duration::from_secs(1));
        assert!(matches!(
            handle_key(&mut m, key('r')).as_slice(),
            [Cmd::FetchLegacy]
        ));
        // Back on Provers the cadence stops.
        apply_legacy(&mut m, Ok(None), Duration::from_secs(1));
        handle_key(&mut m, key('1'));
        assert_eq!(m.tab, Tab::Provers);
        assert!(due(&mut m, Instant::now() + LEGACY_REFRESH * 3).is_empty());
    }

    #[test]
    fn allocation_actions_do_nothing_on_coins() {
        let mut m = Model::new();
        open(&mut m);
        apply_legacy(&mut m, Ok(None), Duration::from_secs(6));
        for c in ['g', 'l', 'y', 'r', 'p', 'u', 'o'] {
            let chord = KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
            // Neither the Coins keys nor the manager's dispatch act on it.
            assert!(handle_key(&mut m, chord).is_empty(), "Ctrl+{c}");
            assert!(
                super::super::update::handle_key(&mut m, chord).is_empty(),
                "Ctrl+{c}"
            );
        }
        assert!(m.coins.legacy.reading.is_none());
        assert_eq!(m.tab, Tab::Coins);
    }

    #[test]
    fn attention_items_are_marked_and_show_by_default() {
        let fmt = |units: u128| units.to_string();
        let mut m = Model::new();
        m.claimable_reward = Some((7, 120));
        apply_legacy(
            &mut m,
            Ok(Some(snapshot(4, 1200, 1, true))),
            Duration::from_secs(6),
        );
        let shown = shown_notices(&m, fmt);
        let texts: Vec<&str> = shown.iter().map(|n| n.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "Claimable: 7 Q at f120; `qclient token mint` authorizes a mint.",
                "Legacy coins: 4 of 6 unshielded in 3 batches; `qclient token shield-all` shields them.",
            ],
            "the outside-shard note is info and hides at the default level"
        );
        assert!(shown
            .iter()
            .all(|n| n.attention && n.severity == NoticeSeverity::Info));
        m.notice_minimum = NoticeSeverity::Info;
        assert_eq!(shown_notices(&m, fmt).len(), 3);
        // Before the gate: an expected wait, no attention item.
        apply_legacy(
            &mut m,
            Ok(Some(snapshot(4, 990, 0, false))),
            Duration::from_secs(6),
        );
        let texts: Vec<String> = notices(&m, fmt)
            .into_iter()
            .filter(|n| n.key != "coins-claimable")
            .map(|n| n.text)
            .collect();
        assert_eq!(
            texts,
            [
                "Shields open at f1000, in 10 frames.",
                "Shield plan: shard list unavailable; batches may exceed 3.",
            ]
        );
        // A failing read keeps the last figures and says how old they are.
        apply_legacy(&mut m, Err("unavailable".into()), Duration::from_secs(1));
        apply_legacy(&mut m, Err("unavailable".into()), Duration::from_secs(1));
        let failed = notices(&m, fmt)
            .into_iter()
            .find(|n| n.key == "coins-legacy-failed")
            .unwrap();
        assert_eq!(failed.severity, NoticeSeverity::Warning);
        assert!(failed.text.contains("read failed 2 times since "));
        assert!(failed.text.contains("; figures as of "));
    }
}
