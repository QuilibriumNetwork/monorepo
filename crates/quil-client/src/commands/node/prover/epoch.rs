//! Client-side mirror of the node's epoch-aligned prover lifecycle, used
//! to display and interpret join/leave/confirm/reject windows.
//!
//! Direct port of `client/cmd/node/prover/epoch.go`, which is itself a
//! mirror of `quil_types::consensus` (`epoch_for_frame`,
//! `effective_status`). Ported verbatim (parameterized by the
//! RPC-reported `epoch_length_frames`) so the display matches the Go
//! client byte-for-byte, including on testnets with a 60-frame epoch.

/// Mainnet epoch length; fallback when the node reports 0
/// (`defaultEpochLengthFrames`).
pub const DEFAULT_EPOCH_LENGTH_FRAMES: u64 = 720;

/// Raw `ProverStatus` discriminants as sent over the RPC.
pub mod raw_status {
    pub const JOINING: u32 = 1;
    pub const ACTIVE: u32 = 2;
    pub const PAUSED: u32 = 3;
    pub const LEAVING: u32 = 4;
    pub const REJECTED: u32 = 5;
    pub const KICKED: u32 = 6;
}

/// Client-side mirror of the node's `EffectiveStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveStatus {
    Unknown,
    Joining,
    Active,
    Paused,
    Leaving,
    ExpiredJoining,
    ExpiredLeaving,
    ExpiredEpoch,
    Rejected,
    Kicked,
}

impl EffectiveStatus {
    /// Display label (`effectiveStatus.String()`).
    pub fn label(self) -> &'static str {
        match self {
            EffectiveStatus::Joining => "joining",
            EffectiveStatus::Active => "active",
            EffectiveStatus::Paused => "paused",
            EffectiveStatus::Leaving => "leaving",
            EffectiveStatus::ExpiredJoining => "expiredJoin",
            EffectiveStatus::ExpiredLeaving => "expiredLeave",
            EffectiveStatus::ExpiredEpoch => "re-confirm!",
            EffectiveStatus::Rejected => "rejected",
            EffectiveStatus::Kicked => "kicked",
            EffectiveStatus::Unknown => "unknown",
        }
    }

    /// `EffectiveStatus::is_live` — Joining|Active|Paused|Leaving.
    pub fn is_live(self) -> bool {
        matches!(
            self,
            EffectiveStatus::Joining
                | EffectiveStatus::Active
                | EffectiveStatus::Paused
                | EffectiveStatus::Leaving
        )
    }
}

/// Safe epoch length (`epochLen`).
pub fn epoch_len(epoch_length: u64) -> u64 {
    if epoch_length == 0 {
        DEFAULT_EPOCH_LENGTH_FRAMES
    } else {
        epoch_length
    }
}

/// `epoch_for_frame` — `frame / epoch_len`.
pub fn epoch_for_frame(frame: u64, epoch_length: u64) -> u64 {
    frame / epoch_len(epoch_length)
}

/// First frame of the given epoch (`epochStartFrame`).
pub fn epoch_start_frame(epoch: u64, epoch_length: u64) -> u64 {
    epoch * epoch_len(epoch_length)
}

/// The name and boundary frame of a confirmed join or leave that has not
/// reached its epoch boundary: `activating` joins its committee at the
/// boundary, `departing` keeps serving until it. Both read as joining or
/// leaving in [`EffectiveStatus`]; `None` for anything else.
pub fn confirmed_phase(
    t: &AllocationTiming,
    eff: EffectiveStatus,
    epoch_length: u64,
) -> Option<(&'static str, u64)> {
    let boundary =
        |confirm: u64| epoch_start_frame(epoch_for_frame(confirm, epoch_length) + 1, epoch_length);
    match eff {
        EffectiveStatus::Joining if t.join_confirm_frame > 0 => {
            Some(("activating", boundary(t.join_confirm_frame)))
        }
        EffectiveStatus::Leaving if t.leave_confirm_frame > 0 => {
            Some(("departing", boundary(t.leave_confirm_frame)))
        }
        _ => None,
    }
}

/// Fields of a shard allocation relevant to lifecycle timing.
#[derive(Debug, Clone, Copy)]
pub struct AllocationTiming<'a> {
    pub raw_status: u32,
    pub filter: &'a [u8],
    pub join_frame: u64,
    pub join_confirm_frame: u64,
    pub leave_frame: u64,
    pub leave_confirm_frame: u64,
    pub epoch: u64,
}

/// `computeEffectiveStatus` — map raw status + timing + current frame to
/// the effective lifecycle state.
pub fn compute_effective_status(
    a: &AllocationTiming,
    current_frame: u64,
    epoch_length: u64,
) -> EffectiveStatus {
    let el = epoch_len(epoch_length);
    let current_epoch = current_frame / el;

    match a.raw_status {
        raw_status::JOINING => {
            if a.join_frame > 0 && current_epoch > a.join_frame / el + 1 {
                EffectiveStatus::ExpiredJoining
            } else {
                EffectiveStatus::Joining
            }
        }
        raw_status::ACTIVE => {
            if a.filter.is_empty() {
                return EffectiveStatus::Active;
            }
            if a.join_confirm_frame > 0 {
                let activation_epoch = a.join_confirm_frame / el + 1;
                if current_epoch < activation_epoch {
                    return EffectiveStatus::Joining;
                }
            }
            if a.epoch >= current_epoch {
                EffectiveStatus::Active
            } else {
                EffectiveStatus::ExpiredEpoch
            }
        }
        raw_status::PAUSED => EffectiveStatus::Paused,
        raw_status::LEAVING => {
            if a.leave_confirm_frame > 0 {
                let deactivation_epoch = a.leave_confirm_frame / el + 1;
                if current_epoch < deactivation_epoch {
                    return EffectiveStatus::Leaving;
                }
                return EffectiveStatus::ExpiredLeaving;
            }
            if a.leave_frame > 0 && current_epoch > a.leave_frame / el + 1 {
                EffectiveStatus::ExpiredLeaving
            } else {
                EffectiveStatus::Leaving
            }
        }
        raw_status::REJECTED => EffectiveStatus::Rejected,
        raw_status::KICKED => EffectiveStatus::Kicked,
        _ => EffectiveStatus::Unknown,
    }
}

/// The single epoch slot in which a pending join/leave may be confirmed
/// or rejected (`confirmWindow`).
#[derive(Debug, Clone, Copy)]
pub struct ConfirmWindow {
    pub confirm_epoch: u64,
    pub start_frame: u64,
    pub end_frame: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowState {
    Pending,
    Open,
    Missed,
}

impl ConfirmWindow {
    pub fn for_frame(propose_frame: u64, epoch_length: u64) -> Self {
        let el = epoch_len(epoch_length);
        let ce = propose_frame / el + 1;
        ConfirmWindow {
            confirm_epoch: ce,
            start_frame: ce * el,
            end_frame: (ce + 1) * el,
        }
    }

    pub fn state(&self, current_frame: u64, epoch_length: u64) -> WindowState {
        let ce = current_frame / epoch_len(epoch_length);
        if ce < self.confirm_epoch {
            WindowState::Pending
        } else if ce == self.confirm_epoch {
            WindowState::Open
        } else {
            WindowState::Missed
        }
    }
}

/// `allocConfirmWindow` — window for a pending Joining/Leaving allocation.
pub fn alloc_confirm_window(a: &AllocationTiming, epoch_length: u64) -> Option<ConfirmWindow> {
    match a.raw_status {
        raw_status::JOINING if a.join_frame > 0 => {
            Some(ConfirmWindow::for_frame(a.join_frame, epoch_length))
        }
        raw_status::LEAVING if a.leave_frame > 0 => {
            Some(ConfirmWindow::for_frame(a.leave_frame, epoch_length))
        }
        _ => None,
    }
}

/// The first frame of the epoch after the one `frame` falls in — the
/// boundary at which an epoch-aligned lifecycle transition takes effect.
pub fn next_epoch_boundary(frame: u64, epoch_length: u64) -> u64 {
    epoch_start_frame(epoch_for_frame(frame, epoch_length) + 1, epoch_length)
}

/// How the Next/Default Action thresholds are displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThresholdUnit {
    /// Frames left from the received GLOBAL frame: `in 512f`, `now` once
    /// reached.
    #[default]
    Relative,
    /// The threshold frame itself: `@f897120`.
    Absolute,
}

impl ThresholdUnit {
    pub fn toggled(self) -> Self {
        match self {
            ThresholdUnit::Relative => ThresholdUnit::Absolute,
            ThresholdUnit::Absolute => ThresholdUnit::Relative,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ThresholdUnit::Relative => "relative",
            ThresholdUnit::Absolute => "absolute",
        }
    }
}

/// What a relative threshold counts from: the received GLOBAL frame, and the
/// measured mean seconds per GLOBAL frame that turns the frames left into a
/// `~` time estimate. `None` shows frames only, never a guessed time.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ThresholdClock {
    pub frame: u64,
    pub seconds_per_frame: Option<f64>,
}

/// A forecast duration rounded to whole minutes: `<1m`, `45m`, `2h41m`.
pub fn fmt_estimate(seconds: f64) -> String {
    let minutes = (seconds.max(0.0) / 60.0).round() as u64;
    match minutes {
        0 => "<1m".into(),
        1..=59 => format!("{minutes}m"),
        _ => format!("{}h{:02}m", minutes / 60, minutes % 60),
    }
}

/// One lifecycle hint: a verb, and — when it is bounded — the frame it falls
/// due at. Every threshold shown is an epoch boundary, so a single stored
/// frame renders either relative to the received frame or absolute. An empty
/// label means "nothing to show".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionHint {
    pub label: String,
    pub at_frame: Option<u64>,
}

impl ActionHint {
    pub fn none() -> Self {
        ActionHint::default()
    }

    pub fn text(label: impl Into<String>) -> Self {
        ActionHint {
            label: label.into(),
            at_frame: None,
        }
    }

    pub fn at(label: impl Into<String>, frame: u64) -> Self {
        ActionHint {
            label: label.into(),
            at_frame: Some(frame),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.label.is_empty()
    }

    /// `verb in <N>f` (with ` (~<time>)` when the clock carries an interval)
    /// or `verb now` once reached, relative to the clock's frame; `verb@f<frame>`
    /// when absolute. The bare verb when unbounded, which for a Next Action
    /// reads as "available now".
    pub fn render(&self, unit: ThresholdUnit, clock: ThresholdClock) -> String {
        let Some(f) = self.at_frame else {
            return self.label.clone();
        };
        if unit == ThresholdUnit::Absolute {
            return format!("{}@f{}", self.label, f);
        }
        if f <= clock.frame {
            return format!("{} now", self.label);
        }
        let left = f - clock.frame;
        match clock.seconds_per_frame {
            Some(spf) => format!(
                "{} in {left}f (~{})",
                self.label,
                fmt_estimate(left as f64 * spf)
            ),
            None => format!("{} in {left}f", self.label),
        }
    }
}

/// The Next Action / Default Action hint pair for an allocation.
///
/// Next Action lists the key-bound verbs the operator may use (`reject`,
/// `confirm`, `pause`, `resume`, `leave`), with a threshold when they are not
/// yet available. Default Action is the single verb the network applies on
/// its own if the operator does nothing, at the boundary it takes effect.
/// Both are shared with `qclient node prover status` so the two surfaces
/// speak the same vocabulary.
pub fn action_hints(
    t: &AllocationTiming,
    eff: EffectiveStatus,
    epoch_length: u64,
    current_frame: u64,
    next_boundary: u64,
) -> (ActionHint, ActionHint) {
    match eff {
        // A proposed join, or a leave nobody has answered yet: confirm or
        // reject it inside its one-epoch window.
        EffectiveStatus::Joining if t.raw_status == raw_status::JOINING => {
            confirm_hints(t, epoch_length, current_frame)
        }
        EffectiveStatus::Leaving if t.leave_confirm_frame == 0 => {
            confirm_hints(t, epoch_length, current_frame)
        }
        // A confirmed leave is out of the operator's hands; it departs at the
        // boundary after the confirmation.
        EffectiveStatus::Leaving => (
            ActionHint::none(),
            ActionHint::at(
                "depart",
                next_epoch_boundary(t.leave_confirm_frame, epoch_length),
            ),
        ),
        // A confirmed join short of its activation boundary is already an
        // ordinary allocation to pause or leave.
        EffectiveStatus::Joining => (
            ActionHint::text("(pause|leave)"),
            ActionHint::at(
                "activate",
                next_epoch_boundary(t.join_confirm_frame, epoch_length),
            ),
        ),
        // A stale epoch is recoverable, so its default is the same renewal an
        // Active allocation gets; the Status column carries the alarm.
        EffectiveStatus::Active | EffectiveStatus::ExpiredEpoch => {
            let default = if t.filter.is_empty() {
                ActionHint::none() // the global filter is exempt from epoch checks
            } else {
                ActionHint::at("renew", next_boundary)
            };
            (ActionHint::text("(pause|leave)"), default)
        }
        EffectiveStatus::Paused => (ActionHint::text("(resume|leave)"), ActionHint::none()),
        _ => (ActionHint::none(), ActionHint::none()),
    }
}

/// Hints for a pending join/leave: both verbs share one window, so they are
/// grouped under a single threshold, and letting the window close is what
/// happens by default.
fn confirm_hints(
    t: &AllocationTiming,
    epoch_length: u64,
    current_frame: u64,
) -> (ActionHint, ActionHint) {
    let Some(w) = alloc_confirm_window(t, epoch_length) else {
        // No proposal frame recorded: nothing gates the answer.
        return (ActionHint::text("(reject|confirm)"), ActionHint::none());
    };
    let expire = ActionHint::at("expire", w.end_frame);
    match w.state(current_frame, epoch_length) {
        WindowState::Open => (ActionHint::text("(reject|confirm)"), expire),
        WindowState::Pending => (ActionHint::at("(reject|confirm)", w.start_frame), expire),
        WindowState::Missed => (ActionHint::none(), expire),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A join or leave reads as activating or departing from its confirm until
    /// the next epoch boundary, and the boundary is the first frame after it.
    #[test]
    fn confirmed_joins_activate_and_confirmed_leaves_depart_at_the_boundary() {
        let timing = |raw_status, join_confirm_frame, leave_confirm_frame| AllocationTiming {
            raw_status,
            filter: &[0xab],
            join_frame: 1_500,
            join_confirm_frame,
            leave_frame: 1_500,
            leave_confirm_frame,
            epoch: 3,
        };
        let phase = |t: AllocationTiming, frame| {
            confirmed_phase(&t, compute_effective_status(&t, frame, 720), 720)
        };
        assert_eq!(phase(timing(raw_status::JOINING, 0, 0), 1_600), None);
        assert_eq!(
            phase(timing(raw_status::ACTIVE, 2_165, 0), 2_200),
            Some(("activating", 2_880))
        );
        assert_eq!(phase(timing(raw_status::ACTIVE, 2_165, 0), 2_880), None);
        assert_eq!(phase(timing(raw_status::LEAVING, 0, 0), 1_600), None);
        assert_eq!(
            phase(timing(raw_status::LEAVING, 0, 2_165), 2_200),
            Some(("departing", 2_880))
        );
        assert_eq!(phase(timing(raw_status::LEAVING, 0, 2_165), 2_880), None);
    }

    fn timing(status: u32) -> AllocationTiming<'static> {
        AllocationTiming {
            raw_status: status,
            filter: &[0xFF],
            join_frame: 0,
            join_confirm_frame: 0,
            leave_frame: 0,
            leave_confirm_frame: 0,
            epoch: 0,
        }
    }

    #[test]
    fn active_global_filter_is_always_active() {
        let mut t = timing(raw_status::ACTIVE);
        t.filter = &[];
        assert_eq!(
            compute_effective_status(&t, 100_000, 720),
            EffectiveStatus::Active
        );
    }

    #[test]
    fn active_data_shard_expires_when_epoch_stale() {
        let mut t = timing(raw_status::ACTIVE);
        t.epoch = 1; // registered for epoch 1
                     // current frame in epoch 3 -> stale
        assert_eq!(
            compute_effective_status(&t, 3 * 720, 720),
            EffectiveStatus::ExpiredEpoch
        );
    }

    #[test]
    fn joining_expires_past_confirm_epoch() {
        let mut t = timing(raw_status::JOINING);
        t.join_frame = 720; // epoch 1 -> must confirm epoch 2
                            // current epoch 3 -> expired
        assert_eq!(
            compute_effective_status(&t, 3 * 720, 720),
            EffectiveStatus::ExpiredJoining
        );
    }

    /// Relative thresholds count down from the received frame, read `now` once
    /// reached, and add a `~` estimate only when an interval is measured;
    /// absolute ones print the frame.
    #[test]
    fn thresholds_render_relative_absolute_and_now() {
        let renew = ActionHint::at("renew", 897_120);
        let clock = |frame, seconds_per_frame| ThresholdClock {
            frame,
            seconds_per_frame,
        };
        assert_eq!(
            renew.render(ThresholdUnit::Relative, clock(896_608, None)),
            "renew in 512f"
        );
        assert_eq!(
            renew.render(ThresholdUnit::Relative, clock(896_608, Some(18.87))),
            "renew in 512f (~2h41m)"
        );
        assert_eq!(
            renew.render(ThresholdUnit::Relative, clock(897_119, Some(10.0))),
            "renew in 1f (~<1m)"
        );
        assert_eq!(
            renew.render(ThresholdUnit::Relative, clock(897_120, Some(10.0))),
            "renew now"
        );
        assert_eq!(
            renew.render(ThresholdUnit::Relative, clock(897_200, None)),
            "renew now"
        );
        assert_eq!(
            renew.render(ThresholdUnit::Absolute, clock(896_608, Some(18.87))),
            "renew@f897120"
        );
        let free = ActionHint::text("(pause|leave)");
        for unit in [ThresholdUnit::Relative, ThresholdUnit::Absolute] {
            assert_eq!(
                free.render(unit, clock(896_608, Some(10.0))),
                "(pause|leave)"
            );
        }
        assert_eq!(ThresholdUnit::default(), ThresholdUnit::Relative);
        assert_eq!(ThresholdUnit::Relative.toggled(), ThresholdUnit::Absolute);
        assert_eq!(ThresholdUnit::Absolute.toggled(), ThresholdUnit::Relative);
    }

    #[test]
    fn estimates_round_to_whole_minutes() {
        assert_eq!(fmt_estimate(0.0), "<1m");
        assert_eq!(fmt_estimate(29.0), "<1m");
        assert_eq!(fmt_estimate(30.0), "1m");
        assert_eq!(fmt_estimate(45.0 * 60.0), "45m");
        assert_eq!(fmt_estimate(59.0 * 60.0 + 29.0), "59m");
        assert_eq!(fmt_estimate(60.0 * 60.0), "1h00m");
        assert_eq!(fmt_estimate(2.0 * 3600.0 + 41.0 * 60.0 + 10.0), "2h41m");
        assert_eq!(fmt_estimate(26.0 * 3600.0 + 5.0 * 60.0), "26h05m");
    }

    /// The next boundary is the first frame of the following epoch, from an
    /// epoch's first frame through its last.
    #[test]
    fn next_boundary_from_an_epochs_first_and_last_frame() {
        assert_eq!(next_epoch_boundary(1_440, 720), 2_160);
        assert_eq!(next_epoch_boundary(2_159, 720), 2_160);
        assert_eq!(next_epoch_boundary(2_160, 720), 2_880);
        assert_eq!(next_epoch_boundary(0, 0), DEFAULT_EPOCH_LENGTH_FRAMES);
        assert_eq!(next_epoch_boundary(119, 60), 120);
    }

    #[test]
    fn confirm_window_open_now() {
        let t = {
            let mut t = timing(raw_status::JOINING);
            t.join_frame = 720; // epoch 1 -> confirm epoch 2 [1440,2160)
            t
        };
        let w = alloc_confirm_window(&t, 720).unwrap();
        assert_eq!(w.confirm_epoch, 2);
        assert_eq!(w.state(1500, 720), WindowState::Open);
        assert_eq!(w.state(700, 720), WindowState::Pending);
        assert_eq!(w.state(3000, 720), WindowState::Missed);
    }
}
