//! Who holds the execution engines and CRDT metadata locks a canonical
//! publication needs. A refused capture names the lock, not its reader, so
//! an archive that falls back to the legacy materializer could not say whether
//! gossip validation, message processing or an RPC cost query held it.
//!
//! Callers that read those locks for a while take a [`Held`] guard of their
//! kind; a busy error appends [`report`]. The registry's own mutex is held
//! for a few instructions and never across a call out.
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Instant;

/// The readers that keep the execution engines locked.
#[derive(Clone, Copy, Debug)]
pub enum Holder {
    /// Gossip validation and mempool arrival checks.
    Validation = 0,
    /// Executing or locking a message.
    Processing = 1,
    /// An RPC cost query.
    CostQuery = 2,
}

const NAMES: [&str; 3] = ["gossip validation", "message processing", "cost query"];

#[derive(Clone, Copy)]
struct Slot {
    active: u32,
    /// Milliseconds since the clock origin of the latest entry.
    entered_ms: u64,
    /// Longest hold ended since the previous report, in milliseconds.
    longest_ms: u64,
}

const EMPTY: Slot = Slot {
    active: 0,
    entered_ms: 0,
    longest_ms: 0,
};

static SLOTS: Mutex<[Slot; 3]> = Mutex::new([EMPTY; 3]);

fn slots() -> std::sync::MutexGuard<'static, [Slot; 3]> {
    SLOTS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn now_ms() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    u64::try_from(ORIGIN.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// A reader of one kind is inside the locks until this drops.
#[must_use]
pub struct Held {
    index: usize,
    entered_ms: u64,
}

pub fn hold(holder: Holder) -> Held {
    let index = holder as usize;
    let entered_ms = now_ms();
    let mut slots = slots();
    slots[index].active += 1;
    slots[index].entered_ms = entered_ms;
    Held { index, entered_ms }
}

impl Drop for Held {
    fn drop(&mut self) {
        let held = now_ms().saturating_sub(self.entered_ms);
        let mut slots = slots();
        let slot = &mut slots[self.index];
        slot.active = slot.active.saturating_sub(1);
        slot.longest_ms = slot.longest_ms.max(held);
    }
}

/// The holders now and since the previous report, as `kind: N active, held
/// up to M ms` (an active holder counts its time since the latest entry).
/// Without any tagged holder the reader is untagged, such as a forest reader.
pub fn report() -> String {
    let now = now_ms();
    let mut slots = slots();
    let parts: Vec<String> = slots
        .iter_mut()
        .zip(NAMES)
        .filter_map(|(slot, name)| {
            let mut longest = std::mem::take(&mut slot.longest_ms);
            if slot.active > 0 {
                longest = longest.max(now.saturating_sub(slot.entered_ms));
            }
            (slot.active > 0 || longest > 0)
                .then(|| format!("{name}: {} active, held up to {longest} ms", slot.active))
        })
        .collect();
    if parts.is_empty() {
        "no tagged holder: a forest reader or an untagged caller".to_string()
    } else {
        parts.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // One test: the registry is process-wide.
    #[test]
    fn the_report_names_the_kind_holding_and_how_long() {
        report();
        assert!(report().starts_with("no tagged holder"));
        let held = hold(Holder::CostQuery);
        std::thread::sleep(Duration::from_millis(20));
        let live = report();
        assert!(live.contains("cost query: 1 active, held up to "), "{live}");
        assert!(!live.contains("gossip validation"), "{live}");
        drop(held);
        let ended = report();
        assert!(
            ended.contains("cost query: 0 active, held up to "),
            "{ended}"
        );
        assert!(!ended.contains("held up to 0 ms"), "{ended}");
        assert!(report().starts_with("no tagged holder"), "a report resets");
        let _a = hold(Holder::Validation);
        let _b = hold(Holder::Validation);
        assert!(report().contains("gossip validation: 2 active"));
    }
}
