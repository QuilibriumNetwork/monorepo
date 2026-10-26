//! Operator-visible transitions of cells that stay unset until GLOBAL/CW
//! consensus activates on a consensus-participant archive.
//!
//! Until activation, readers of `global_finalization` and `cw_router` fall
//! back to the legacy path (canonical clock write, legacy message dispatch).
//! That fallback is expected, but it was silent: an archive that never
//! activates looked the same as one that has not yet reached the activation.
//! Each cell logs two lines per run of unset reads: when it starts falling
//! back and when it becomes set. Never per read.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use tracing::info;

/// Tracks one cell's unset-to-set transition.
pub(crate) struct ActivationWatch {
    cell: &'static str,
    fallback: &'static str,
    /// False on regular nodes and archives without a CW committee, which never
    /// activate the cell: nothing to report there.
    enabled: bool,
    waiting: AtomicBool,
    since: Mutex<Option<Instant>>,
}

impl ActivationWatch {
    fn new(cell: &'static str, fallback: &'static str, enabled: bool) -> Self {
        Self { cell, fallback, enabled, waiting: AtomicBool::new(false), since: Mutex::new(None) }
    }

    /// Records one read of the cell: `is_set` is whether it held a value.
    /// `frame` is the GLOBAL frame the reader was handling, when it knows it.
    pub(crate) fn observe(&self, is_set: bool, frame: Option<u64>) {
        if !self.enabled || self.waiting.load(Ordering::Relaxed) == !is_set {
            return;
        }
        if !is_set {
            if self.waiting.swap(true, Ordering::AcqRel) {
                return;
            }
            *self.since.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
            info!(
                cell = self.cell, frame = frame.unwrap_or(0), fallback = self.fallback,
                "archive is waiting for GLOBAL consensus activation; using the legacy path until the cell is set \
                 (expected wait, no action needed)",
            );
        } else if self.waiting.swap(false, Ordering::AcqRel) {
            let waited = self.since.lock().unwrap_or_else(|e| e.into_inner()).take()
                .map_or(0, |since| since.elapsed().as_secs());
            info!(
                cell = self.cell, frame = frame.unwrap_or(0), waited_secs = waited,
                "GLOBAL consensus activated on this archive; the cell is set and the legacy path is no longer used",
            );
        }
    }

    #[cfg(test)]
    fn waiting(&self) -> bool {
        self.waiting.load(Ordering::Relaxed)
    }
}

/// The watches for the two activation cells.
pub(crate) struct ActivationWaits {
    pub(crate) cw_router: ActivationWatch,
    pub(crate) global_finalization: ActivationWatch,
}

impl ActivationWaits {
    /// `enabled`: this node is an archive with a CW consensus committee.
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            cw_router: ActivationWatch::new("cw_router", "legacy gossip dispatch", enabled),
            global_finalization: ActivationWatch::new("global_finalization", "canonical clock write first", enabled),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waiting_flag_follows_the_cell_once_per_transition() {
        let waits = ActivationWaits::new(true);
        let watch = &waits.cw_router;
        assert!(!watch.waiting());
        watch.observe(true, None);
        assert!(!watch.waiting(), "a set cell was never waited on");
        watch.observe(false, Some(7));
        assert!(watch.waiting());
        watch.observe(false, Some(8));
        assert!(watch.waiting());
        watch.observe(true, Some(9));
        assert!(!watch.waiting());
    }

    #[test]
    fn disabled_watch_never_waits() {
        let waits = ActivationWaits::new(false);
        waits.global_finalization.observe(false, Some(1));
        assert!(!waits.global_finalization.waiting());
    }
}
