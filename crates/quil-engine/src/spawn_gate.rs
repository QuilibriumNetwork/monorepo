//! A cap on tasks that remote input can spawn: a permit is taken without
//! waiting, and work over the cap is dropped, counted and reported at most
//! once a minute.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Semaphore, SemaphorePermit};

const WARN_EVERY_MS: u64 = 60_000;

pub struct SpawnGate {
    name: &'static str,
    permits: Semaphore,
    cap: usize,
    dropped: AtomicU64,
    reported: AtomicU64,
    last_warn_ms: AtomicU64,
}

impl SpawnGate {
    pub const fn new(name: &'static str, cap: usize) -> Self {
        Self {
            name,
            permits: Semaphore::const_new(cap),
            cap,
            dropped: AtomicU64::new(0),
            reported: AtomicU64::new(0),
            last_warn_ms: AtomicU64::new(0),
        }
    }

    /// Tasks refused since start.
    pub fn dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// A permit, or `None` when `cap` tasks are in flight; the refusal is
    /// counted and logged (first drop at once, then once a minute).
    pub fn try_enter(&'static self) -> Option<SemaphorePermit<'static>> {
        if let Ok(permit) = self.permits.try_acquire() {
            return Some(permit);
        }
        self.refuse();
        None
    }

    /// A permit, waiting up to `wait` for a slot: for a caller that can be
    /// held back (an RPC), so a burst is delayed rather than refused.
    pub async fn enter_within(&'static self, wait: Duration) -> Option<SemaphorePermit<'static>> {
        if let Ok(Ok(permit)) = tokio::time::timeout(wait, self.permits.acquire()).await {
            return Some(permit);
        }
        self.refuse();
        None
    }

    fn refuse(&self) {
        let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
        let last = self.last_warn_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= WARN_EVERY_MS
            && self.last_warn_ms.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
        {
            let since = total - self.reported.swap(total, Ordering::Relaxed);
            tracing::warn!(
                gate = self.name, cap = self.cap, dropped_since_last_line = since, dropped_total = total,
                scope = "this node: work arriving from peers faster than it is processed",
                action = "excess work was dropped and is retried by its sender; a steady count means \
                    this node's blocking pool or storage is saturated: report it with this line",
                "task cap reached",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SpawnGate;

    #[test]
    fn refuses_and_counts_over_the_cap_and_frees_a_slot_on_drop() {
        static GATE: SpawnGate = SpawnGate::new("test-gate", 2);
        let first = GATE.try_enter().expect("first slot");
        let second = GATE.try_enter().expect("second slot");
        assert_eq!(GATE.dropped_total(), 0, "nothing is refused below the cap");
        assert!(GATE.try_enter().is_none(), "the cap is reached");
        assert!(GATE.try_enter().is_none());
        assert_eq!(GATE.dropped_total(), 2, "each refusal is counted");
        drop(first);
        let third = GATE.try_enter().expect("a dropped permit frees its slot");
        assert!(GATE.try_enter().is_none(), "the freed slot is taken again");
        assert_eq!(GATE.dropped_total(), 3);
        drop((second, third));
        assert!(GATE.try_enter().is_some() && GATE.try_enter().is_some());
        assert_eq!(GATE.dropped_total(), 3, "no refusal below the cap");
    }

    #[tokio::test]
    async fn a_held_back_caller_gets_a_slot_freed_within_its_wait() {
        static GATE: SpawnGate = SpawnGate::new("test-wait-gate", 1);
        let held = GATE.try_enter().expect("the only slot");
        let wait = std::time::Duration::from_millis(50);
        assert!(GATE.enter_within(wait).await.is_none(), "no slot frees within the wait");
        assert_eq!(GATE.dropped_total(), 1);
        let release = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            drop(held);
        });
        assert!(GATE.enter_within(std::time::Duration::from_secs(5)).await.is_some(), "the freed slot is handed over");
        release.await.unwrap();
        assert_eq!(GATE.dropped_total(), 1, "a caller served within its wait is not counted");
    }
}
