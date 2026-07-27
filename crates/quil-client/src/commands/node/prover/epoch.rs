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
            EffectiveStatus::Joining => "Joining",
            EffectiveStatus::Active => "Active",
            EffectiveStatus::Paused => "Paused",
            EffectiveStatus::Leaving => "Leaving",
            EffectiveStatus::ExpiredJoining => "ExpiredJoin",
            EffectiveStatus::ExpiredLeaving => "ExpiredLeave",
            EffectiveStatus::ExpiredEpoch => "Re-confirm!",
            EffectiveStatus::Rejected => "Rejected",
            EffectiveStatus::Kicked => "Kicked",
            EffectiveStatus::Unknown => "Unknown",
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
pub fn compute_effective_status(a: &AllocationTiming, current_frame: u64, epoch_length: u64) -> EffectiveStatus {
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
    fn for_frame(propose_frame: u64, epoch_length: u64) -> Self {
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

    /// `confirmWindow.label` — compact human hint.
    pub fn label(&self, verb: &str, current_frame: u64, epoch_length: u64) -> String {
        match self.state(current_frame, epoch_length) {
            WindowState::Open => format!(
                "{verb} now (epoch {}, until frame {})",
                self.confirm_epoch, self.end_frame
            ),
            WindowState::Pending => format!(
                "{verb} @epoch {} (frame {})",
                self.confirm_epoch, self.start_frame
            ),
            WindowState::Missed => {
                format!("{verb} window missed (was epoch {})", self.confirm_epoch)
            }
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

#[cfg(test)]
mod tests {
    use super::*;

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
