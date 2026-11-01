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

/// Panels of the tab, top to bottom: Balances, the panel of the Balances
/// row under the cursor ([`Middle`]), Notifications. `[`/`]` and `{`/`}`
/// move the focused panel's upper and lower edge.
pub const PANELS: usize = 3;
/// The edges between the panels; edge `i` lies under panel `i`.
pub const EDGES: usize = PANELS - 1;
/// The fewest rows a panel keeps when an edge moves: borders and a line.
pub const PANEL_MIN: u16 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoinsFocus {
    #[default]
    Balances,
    /// The middle panel, whichever [`Middle`] it shows.
    Middle,
    Notifications,
}

/// What the middle panel shows: it follows the Balances row under the
/// cursor, and a shield's or a mint's preparation or confirmation while it
/// is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Middle {
    /// The claimable reward: its amount, frame and mint, and the
    /// authorizations saved for a claim.
    Claim,
    /// `token shield-all`'s batches of the legacy coins.
    ShieldPlan,
}

impl Middle {
    /// The panel's title, naming what it shows.
    pub fn title(self) -> &'static str {
        match self {
            Self::Claim => "Claim status",
            Self::ShieldPlan => "Shield plan",
        }
    }
}

/// The middle panel's mode.
pub fn middle(m: &Model) -> Middle {
    if m.coins.shield.dialog.is_some() {
        return Middle::ShieldPlan;
    }
    if m.coins.mint.dialog.is_some() {
        return Middle::Claim;
    }
    match m.coins.cursor {
        0 => Middle::Claim,
        _ => Middle::ShieldPlan,
    }
}

/// What the Coins tab's cursor is on. An action key acts only on the
/// selection it applies to; for any other its hint is dimmed and pressing
/// it shows why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// The claimable-reward row of Balances.
    Claimable,
    /// The legacy-coins row of Balances.
    Legacy,
    /// A batch of the Shield plan: legacy coins too.
    Plan,
    /// The Claim status panel: the claimable reward and the saved
    /// authorizations.
    Claim,
    Notifications,
}

/// The current [`Selection`].
pub fn selection(m: &Model) -> Selection {
    match m.coins.focus {
        CoinsFocus::Balances if m.coins.cursor == 0 => Selection::Claimable,
        CoinsFocus::Balances => Selection::Legacy,
        CoinsFocus::Middle => match middle(m) {
            Middle::Claim => Selection::Claim,
            Middle::ShieldPlan => Selection::Plan,
        },
        CoinsFocus::Notifications => Selection::Notifications,
    }
}

/// The focused panel's place, top to bottom.
fn panel_index(m: &Model) -> usize {
    match m.coins.focus {
        CoinsFocus::Balances => 0,
        CoinsFocus::Middle => 1,
        CoinsFocus::Notifications => PANELS - 1,
    }
}

/// The edge `key` (`[`, `]`, `{` or `}`) moves and by how much, or why it
/// cannot: the focused panel has no such edge, or the panel it would shrink
/// keeps only [`PANEL_MIN`] rows.
fn edge_move(m: &Model, key: char) -> Result<(usize, i16), String> {
    let panel = panel_index(m);
    let name = cursor_rows(m).2;
    let upper = matches!(key, '[' | ']');
    let down = matches!(key, ']' | '}');
    let edge = if upper {
        panel.checked_sub(1)
    } else {
        (panel < EDGES).then_some(panel)
    };
    let side = if upper { "upper" } else { "lower" };
    let Some(edge) = edge else {
        return Err(format!("{name}: it has no {side} edge to move."));
    };
    let donor = if down { edge + 1 } else { edge };
    if m.coins.heights[donor] <= PANEL_MIN {
        return Err(format!(
            "{name}: its {side} edge is at its limit; every panel keeps {PANEL_MIN} rows."
        ));
    }
    Ok((edge, if down { 1 } else { -1 }))
}

/// Move an edge, or say why it cannot move.
fn move_edge(m: &mut Model, key: char) {
    match edge_move(m, key) {
        Ok((edge, step)) => {
            m.coins.edges[edge] = (m.coins.edges[edge] + step).clamp(-500, 500);
            // Bound repeated keys before the next draw.
            m.coins.heights[edge] = m.coins.heights[edge].saturating_add_signed(step);
            m.coins.heights[edge + 1] = m.coins.heights[edge + 1].saturating_add_signed(-step);
        }
        Err(why) => {
            m.status_msg = why;
            m.status_is_error = false;
        }
    }
}

/// Apply the moved edges to the panels' default `heights`, each kept to
/// [`PANEL_MIN`], and store the result and the edges as drawn, so the next
/// key moves the visible edge.
pub fn place_edges(m: &mut Model, mut heights: [u16; PANELS]) -> [u16; PANELS] {
    let base = heights;
    if heights.iter().all(|&h| h >= PANEL_MIN) {
        let min = i32::from(PANEL_MIN);
        for i in 0..EDGES {
            let step = i32::from(m.coins.edges[i])
                .clamp(min - i32::from(heights[i]), i32::from(heights[i + 1]) - min);
            heights[i] = (i32::from(heights[i]) + step) as u16;
            heights[i + 1] = (i32::from(heights[i + 1]) - step) as u16;
        }
        let mut moved = 0i32;
        for i in 0..EDGES {
            moved += i32::from(heights[i]) - i32::from(base[i]);
            m.coins.edges[i] = moved as i16;
        }
    }
    m.coins.heights = heights;
    heights
}

/// The focused panel's cursor and row count, and its name.
fn cursor_rows(m: &Model) -> (usize, usize, &'static str) {
    match m.coins.focus {
        CoinsFocus::Balances => (m.coins.cursor, BALANCE_ROWS, "Balances"),
        CoinsFocus::Middle => match middle(m) {
            Middle::Claim => (
                m.coins.mint.cursor,
                m.coins.mint.saved.len().max(1),
                Middle::Claim.title(),
            ),
            Middle::ShieldPlan => (m.coins.plan_cursor, plan_rows(m), "Shield plan"),
        },
        CoinsFocus::Notifications => (
            m.notice_offset,
            m.notice_lines.saturating_sub(m.notice_visible) + 1,
            "Notifications",
        ),
    }
}

/// Rows of the Shield plan: one per batch.
fn plan_rows(m: &Model) -> usize {
    match &m.coins.legacy.answer {
        Some((Some(snapshot), _, _)) => snapshot.batches.len(),
        _ => 0,
    }
}

/// Why the key its hint names (`S`, `↑/k`, …) does nothing for the
/// current selection, as the one line pressing it shows; `None` when it
/// acts. The key row dims exactly these keys; view keys always act.
pub fn key_refusal(m: &Model, key: &str) -> Option<String> {
    let legacy = matches!(selection(m), Selection::Legacy | Selection::Plan);
    match key {
        "↑/k" | "↓/j" => {
            let (at, rows, panel) = cursor_rows(m);
            let up = key == "↑/k";
            let moves = if up { at > 0 } else { at + 1 < rows };
            (!moves).then(|| {
                format!(
                    "{panel}: already at the {} row.",
                    if up { "first" } else { "last" }
                )
            })
        }
        "r" if !legacy => Some(
            "Legacy coins: ‹r› reads legacy coins; select the legacy row or the Shield plan."
                .into(),
        ),
        "r" => m
            .coins
            .legacy
            .reading
            .is_some()
            .then(|| "Legacy coins: a read is already in progress.".into()),
        "S" if !legacy => Some(
            "Shield: ‹S› shields legacy coins; select the legacy row or the Shield plan.".into(),
        ),
        "S" => super::shield::refusal(m),
        "M" if !matches!(selection(m), Selection::Claimable | Selection::Claim) => Some(
            "Mint: ‹M› mints the claimable reward; select the claimable row or its Claim status."
                .into(),
        ),
        "M" => super::mint::mint_refusal(m),
        "C" if selection(m) != Selection::Claim => {
            Some("Mint: ‹C› claims a saved authorization; select it in the Claim status.".into())
        }
        "C" => super::mint::claim_refusal(m),
        "[/] {/}" => ['[', ']', '{', '}']
            .iter()
            .all(|&key| edge_move(m, key).is_err())
            .then(|| format!("{}: its edges are at their limits.", cursor_rows(m).2)),
        _ => None,
    }
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
    /// A read due at this time on either tab: one looking for a submitted
    /// shield's inclusion.
    pub refresh_at: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct Coins {
    pub focus: CoinsFocus,
    /// The Balances row under the cursor: 0 claimable, 1 legacy.
    pub cursor: usize,
    pub legacy: Legacy,
    /// The Shield plan row under the cursor, and its first row on screen.
    pub plan_cursor: usize,
    pub plan_offset: usize,
    /// The shield action.
    pub shield: super::shield::Shield,
    /// The reward mint and its saved authorizations.
    pub mint: super::mint::Mint,
    /// When each current notice was first shown, by its key.
    pub notice_since: HashMap<&'static str, SystemTime>,
    /// How far each edge is moved from its default, in rows (kept between
    /// runs apart from the Provers tab's), and each panel's height as last
    /// drawn, which bounds the next move.
    pub edges: [i16; EDGES],
    pub heights: [u16; PANELS],
}

/// Start a legacy read unless one is in flight.
fn start_legacy(m: &mut Model, now: Instant) -> Vec<Cmd> {
    if m.coins.legacy.reading.is_some() {
        return vec![];
    }
    m.coins.legacy.reading = Some(now);
    m.coins.legacy.last_start = Some(now);
    m.coins.legacy.refresh_at = None;
    vec![Cmd::FetchLegacy]
}

/// The legacy read that is due: the first one at start on either tab,
/// then one every [`LEGACY_REFRESH`] while the Coins tab is open.
pub fn due(m: &mut Model, now: Instant) -> Vec<Cmd> {
    let last = m.coins.legacy.last_start;
    let stale = last.is_none_or(|start| now.saturating_duration_since(start) >= LEGACY_REFRESH);
    let asked = m.coins.legacy.refresh_at.is_some_and(|at| now >= at);
    if last.is_none() || asked || (m.tab == Tab::Coins && stale) {
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
            super::shield::observe_inclusion(m);
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
    let plan = selection(m) == Selection::Plan;
    let claim = selection(m) == Selection::Claim;
    let plan_rows = plan_rows(m);
    let hint = match ev.code {
        KeyCode::Up | KeyCode::Char('k') => Some("↑/k"),
        KeyCode::Down | KeyCode::Char('j') => Some("↓/j"),
        KeyCode::Char('r') => Some("r"),
        KeyCode::Char('S') => Some("S"),
        KeyCode::Char('M') => Some("M"),
        KeyCode::Char('C') => Some("C"),
        _ => None,
    };
    if let Some(why) = hint.and_then(|key| key_refusal(m, key)) {
        m.status_msg = why;
        m.status_is_error = false;
        return vec![];
    }
    match ev.code {
        KeyCode::Char(key @ ('[' | ']' | '{' | '}')) => move_edge(m, key),
        KeyCode::Char('1') => {
            m.tab = Tab::Provers;
            m.notice_offset = 0;
            m.coins.shield.dialog = None;
            m.coins.mint.dialog = None;
        }
        KeyCode::Char('S') => return super::shield::request(m),
        KeyCode::Char('M') => return super::mint::request_mint(m),
        KeyCode::Char('C') => return super::mint::request_claim(m),
        KeyCode::Esc if m.coins.mint.dialog.is_some() => {
            m.coins.mint.dialog = None;
            m.status_msg = "Mint: cancelled; nothing was submitted.".into();
            m.status_is_error = false;
        }
        KeyCode::Esc if m.coins.shield.dialog.is_some() => {
            m.coins.shield.dialog = None;
            m.status_msg = "Shield: cancelled; nothing was submitted.".into();
            m.status_is_error = false;
        }
        KeyCode::Char('r') => return start_legacy(m, Instant::now()),
        KeyCode::Tab => {
            m.coins.focus = match m.coins.focus {
                CoinsFocus::Balances => CoinsFocus::Middle,
                CoinsFocus::Middle => CoinsFocus::Notifications,
                CoinsFocus::Notifications => CoinsFocus::Balances,
            };
        }
        KeyCode::BackTab => {
            m.coins.focus = match m.coins.focus {
                CoinsFocus::Balances => CoinsFocus::Notifications,
                CoinsFocus::Middle => CoinsFocus::Balances,
                CoinsFocus::Notifications => CoinsFocus::Middle,
            };
        }
        KeyCode::Up | KeyCode::Char('k') if claim => {
            m.coins.mint.cursor = m.coins.mint.cursor.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') if claim => {
            m.coins.mint.cursor =
                (m.coins.mint.cursor + 1).min(m.coins.mint.saved.len().saturating_sub(1));
        }
        KeyCode::Up | KeyCode::Char('k') if plan => {
            m.coins.plan_cursor = m.coins.plan_cursor.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') if plan => {
            m.coins.plan_cursor = (m.coins.plan_cursor + 1).min(plan_rows.saturating_sub(1));
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
/// `progress` marks an action under way, which also shows from the
/// default level, without the marker; `success` draws it green.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub key: &'static str,
    pub severity: NoticeSeverity,
    pub attention: bool,
    pub progress: bool,
    pub success: bool,
    pub text: String,
}

impl Notice {
    /// The level from which the notice shows.
    pub fn rank(&self) -> NoticeSeverity {
        if self.attention || self.progress {
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
    let mut out = super::shield::notices(m, &fmt_amount);
    out.extend(super::mint::notices(m, &fmt_amount));
    let busy = m.coins.shield.dialog.is_some() || super::shield::running(m);
    let mut push = |key, severity, attention, text: String| {
        out.push(Notice {
            key,
            severity,
            attention,
            progress: false,
            success: false,
            text,
        })
    };
    match (&m.claimable_reward, &m.reward_error) {
        (Some((units, frame)), _) if *units > 0 => push(
            "coins-claimable",
            NoticeSeverity::Info,
            true,
            format!(
                "Claimable: {} Q at f{frame}; ‹M› authorizes a mint.",
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
    let counts = format!(
        "{unshielded} unshielded, {} shielded",
        snapshot.tally.shielded
    );
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
        (None, Some(plan)) if !busy => push(
            "coins-unshielded",
            NoticeSeverity::Info,
            true,
            format!(
                "Legacy coins: {counts}; {}{}; ‹S› shields the rest.",
                if plan.exact { "" } else { "≥" },
                plural(plan.batches, "batch", "batches")
            ),
        ),
        (None, Some(_)) => {}
        (None, None) => push(
            "coins-unshielded",
            NoticeSeverity::Info,
            true,
            format!("Legacy coins: {counts}."),
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
            batches: Vec::new(),
            pending: 0,
            shielded: Default::default(),
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
        m.coins.cursor = 1;
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

    /// `S` and `r` act on legacy coins only, the legacy row or the Shield
    /// plan; with the claimable reward, its Claim status or Notifications
    /// selected they do nothing but say why.
    #[test]
    fn s_and_r_act_only_with_legacy_coins_selected() {
        let mut m = Model::new();
        open(&mut m);
        let coins = || Ok(Some(snapshot(3, 2000, 0, true)));
        apply_legacy(&mut m, coins(), Duration::from_secs(6));
        for focus in [
            CoinsFocus::Balances,
            CoinsFocus::Middle,
            CoinsFocus::Notifications,
        ] {
            m.coins.focus = focus;
            m.coins.cursor = 0;
            for c in ['S', 'r'] {
                m.status_msg.clear();
                assert!(handle_key(&mut m, key(c)).is_empty(), "{c}");
                assert!(
                    m.status_msg
                        .contains("; select the legacy row or the Shield plan."),
                    "{c}: {}",
                    m.status_msg
                );
            }
            assert!(m.coins.shield.dialog.is_none());
            assert!(m.coins.legacy.reading.is_none());
        }
        assert_eq!(
            key_refusal(&m, "S").unwrap(),
            "Shield: ‹S› shields legacy coins; select the legacy row or the Shield plan."
        );
        for focus in [CoinsFocus::Balances, CoinsFocus::Middle] {
            m.coins.focus = focus;
            m.coins.cursor = 1;
            assert!(matches!(
                handle_key(&mut m, key('S')).as_slice(),
                [Cmd::ShieldPrepare]
            ));
            m.coins.shield.dialog = None;
            assert!(matches!(
                handle_key(&mut m, key('r')).as_slice(),
                [Cmd::FetchLegacy]
            ));
            apply_legacy(&mut m, coins(), Duration::from_secs(6));
        }
        // Legacy coins selected but none left to shield: the reason.
        apply_legacy(
            &mut m,
            Ok(Some(snapshot(0, 2000, 0, true))),
            Duration::from_secs(6),
        );
        m.coins.focus = CoinsFocus::Balances;
        m.coins.cursor = 1;
        assert!(handle_key(&mut m, key('S')).is_empty());
        assert_eq!(
            m.status_msg,
            "Shield: no unshielded legacy coins to shield."
        );
    }

    /// The middle panel follows the Balances row under the cursor: the
    /// claimable reward's Claim status, the legacy coins' Shield plan, and
    /// the Shield plan while a shield is prepared. Its cursor keys act on
    /// the panel it shows.
    #[test]
    fn the_middle_panel_follows_the_balances_selection() {
        let mut m = Model::new();
        open(&mut m);
        apply_legacy(
            &mut m,
            Ok(Some(snapshot(3, 2000, 0, true))),
            Duration::from_secs(6),
        );
        if let Some((Some(snapshot), _, _)) = m.coins.legacy.answer.as_mut() {
            let batch = crate::commands::token::legacy::PlanBatch {
                filter: vec![1; 35],
                coins: 1,
                units: 5,
            };
            snapshot.batches = vec![batch; 3];
        }
        assert_eq!(
            (middle(&m), selection(&m)),
            (Middle::Claim, Selection::Claimable)
        );
        handle_key(&mut m, KeyEvent::from(KeyCode::Tab));
        assert_eq!(
            (middle(&m), selection(&m)),
            (Middle::Claim, Selection::Claim)
        );
        assert!(handle_key(&mut m, key('j')).is_empty());
        assert_eq!(m.status_msg, "Claim status: already at the last row.");
        assert_eq!((m.coins.cursor, m.coins.plan_cursor), (0, 0));
        handle_key(&mut m, KeyEvent::from(KeyCode::BackTab));
        handle_key(&mut m, key('j'));
        assert_eq!(
            (middle(&m), selection(&m)),
            (Middle::ShieldPlan, Selection::Legacy)
        );
        handle_key(&mut m, KeyEvent::from(KeyCode::Tab));
        assert_eq!(selection(&m), Selection::Plan);
        handle_key(&mut m, key('j'));
        assert_eq!((m.coins.cursor, m.coins.plan_cursor), (1, 1));
        // A shield being prepared keeps the Shield plan on screen.
        m.coins.focus = CoinsFocus::Balances;
        m.coins.shield.dialog = Some(super::super::shield::Dialog::Preparing(Instant::now()));
        handle_key(&mut m, key('k'));
        assert_eq!((m.coins.cursor, middle(&m)), (0, Middle::ShieldPlan));
        m.coins.shield.dialog = None;
        assert_eq!(middle(&m), Middle::Claim);
        // A mint being prepared keeps its Claim status on screen.
        m.coins.mint.dialog = Some(super::super::mint::Dialog::Preparing(Instant::now(), false));
        handle_key(&mut m, key('j'));
        assert_eq!((m.coins.cursor, middle(&m)), (1, Middle::Claim));
        m.coins.mint.dialog = None;
        assert_eq!(middle(&m), Middle::ShieldPlan);
    }

    /// `M` acts with the claimable row or its Claim status selected, `C` in
    /// the Claim status only, on the saved authorization under its cursor;
    /// elsewhere both do nothing but say why.
    #[test]
    fn m_and_c_act_only_on_the_claimable_reward() {
        let mut m = Model::new();
        open(&mut m);
        apply_legacy(
            &mut m,
            Ok(Some(snapshot(3, 2000, 0, true))),
            Duration::from_secs(6),
        );
        m.claimable_reward = Some((5_000, 1200));
        m.coins.mint.saved = [1300, 1200]
            .map(|frame| super::super::mint::Saved {
                path: format!("/x/mint-{frame}.bin").into(),
                cited_frame: frame,
                amounts: Some((900, 9)),
            })
            .to_vec();
        for (focus, cursor) in [
            (CoinsFocus::Balances, 1),
            (CoinsFocus::Middle, 1),
            (CoinsFocus::Notifications, 0),
        ] {
            m.coins.focus = focus;
            m.coins.cursor = cursor;
            assert!(handle_key(&mut m, key('M')).is_empty());
            assert_eq!(
                m.status_msg,
                "Mint: ‹M› mints the claimable reward; select the claimable row or its Claim \
                 status."
            );
            assert!(handle_key(&mut m, key('C')).is_empty());
            assert_eq!(
                m.status_msg,
                "Mint: ‹C› claims a saved authorization; select it in the Claim status."
            );
            assert!(m.coins.mint.dialog.is_none());
        }
        m.coins.focus = CoinsFocus::Balances;
        m.coins.cursor = 0;
        assert!(handle_key(&mut m, key('C')).is_empty());
        assert!(m.status_msg.contains("select it in the Claim status"));
        assert!(matches!(
            handle_key(&mut m, key('M')).as_slice(),
            [Cmd::MintPrepare]
        ));
        m.coins.mint.dialog = None;
        m.coins.focus = CoinsFocus::Middle;
        assert_eq!(selection(&m), Selection::Claim);
        assert!(matches!(
            handle_key(&mut m, key('M')).as_slice(),
            [Cmd::MintPrepare]
        ));
        m.coins.mint.dialog = None;
        // The Claim status cursor moves over the saved authorizations.
        handle_key(&mut m, key('j'));
        assert_eq!((m.coins.cursor, m.coins.mint.cursor), (0, 1));
        assert!(handle_key(&mut m, key('j')).is_empty());
        assert_eq!(m.status_msg, "Claim status: already at the last row.");
        assert!(matches!(
            handle_key(&mut m, key('C')).as_slice(),
            [Cmd::ClaimPrepare(_, 1200)]
        ));
        // ‹esc› cancels the preparation, and the Claim status stays.
        handle_key(&mut m, KeyEvent::from(KeyCode::Esc));
        assert!(m.coins.mint.dialog.is_none());
        assert_eq!(m.status_msg, "Mint: cancelled; nothing was submitted.");
    }

    /// `[`/`]` and `{`/`}` move the focused panel's upper and lower edge
    /// one row at a time until the panel they shrink keeps three rows; an
    /// edge that cannot move says why.
    #[test]
    fn panel_edges_move_within_their_bounds() {
        let mut m = Model::new();
        open(&mut m);
        m.coins.heights = [5, 10, 5];
        assert_eq!(key_refusal(&m, "[/] {/}"), None);
        assert!(handle_key(&mut m, key('[')).is_empty());
        assert_eq!(m.status_msg, "Balances: it has no upper edge to move.");
        handle_key(&mut m, key('}'));
        assert_eq!((m.coins.edges, m.coins.heights), ([1, 0], [6, 9, 5]));
        for _ in 0..4 {
            handle_key(&mut m, key('{'));
        }
        assert_eq!((m.coins.edges, m.coins.heights), ([-2, 0], [3, 12, 5]));
        assert_eq!(
            m.status_msg,
            "Balances: its lower edge is at its limit; every panel keeps 3 rows."
        );
        m.coins.focus = CoinsFocus::Notifications;
        handle_key(&mut m, key('}'));
        assert_eq!(m.status_msg, "Notifications: it has no lower edge to move.");
        handle_key(&mut m, key('['));
        assert_eq!((m.coins.edges, m.coins.heights), ([-2, -1], [3, 11, 6]));
        // No edge of a panel can move: the key hint goes.
        m.coins.heights = [3, 3, 3];
        assert_eq!(
            key_refusal(&m, "[/] {/}").unwrap(),
            "Notifications: its edges are at their limits."
        );
    }

    /// Drawing clamps moved edges to the terminal and keeps what it drew, so
    /// the next key moves the edge on screen.
    #[test]
    fn drawing_clamps_the_edges_and_keeps_them() {
        let mut m = Model::new();
        m.coins.edges = [2, -1];
        assert_eq!(place_edges(&mut m, [5, 10, 5]), [7, 7, 6]);
        assert_eq!(m.coins.edges, [2, -1]);
        m.coins.edges = [100, 0];
        assert_eq!(place_edges(&mut m, [5, 10, 5]), [12, 3, 5]);
        assert_eq!(m.coins.edges, [7, 0]);
        // Too small for every panel's three rows: left as laid out.
        m.coins.edges = [1, 1];
        assert_eq!(place_edges(&mut m, [2, 2, 2]), [2, 2, 2]);
    }

    /// At a panel's first or last row the cursor keys say so.
    #[test]
    fn cursor_keys_at_a_panel_edge_say_so() {
        let mut m = Model::new();
        open(&mut m);
        assert!(handle_key(&mut m, key('k')).is_empty());
        assert_eq!(m.status_msg, "Balances: already at the first row.");
        handle_key(&mut m, key('j'));
        assert_eq!(m.coins.cursor, 1);
        handle_key(&mut m, key('j'));
        assert_eq!(m.coins.cursor, 1);
        assert_eq!(m.status_msg, "Balances: already at the last row.");
    }

    #[test]
    fn allocation_actions_do_nothing_on_coins() {
        let mut m = Model::new();
        open(&mut m);
        apply_legacy(&mut m, Ok(None), Duration::from_secs(6));
        // On the legacy row, where a plain `r` would read.
        m.coins.cursor = 1;
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
                "Claimable: 7 Q at f120; ‹M› authorizes a mint.",
                "Legacy coins: 4 unshielded, 2 shielded; 3 batches; ‹S› shields the rest.",
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
