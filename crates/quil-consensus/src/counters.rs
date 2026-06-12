//! Strict monotonic counter. Mirror of
//! `consensus/counters/strict_monotonic_counter.go`.
//!
//! The event loop and aggregator façades use this to track "highest
//! rank ever observed" values without pulling in a full lock.

use std::sync::atomic::{AtomicU64, Ordering};

/// Strict monotonic counter backed by an atomic u64. `set(new)` only
/// succeeds when `new > current`.
#[derive(Debug)]
pub struct StrictMonotonicCounter {
    value: AtomicU64,
}

impl StrictMonotonicCounter {
    pub fn new(initial: u64) -> Self {
        Self {
            value: AtomicU64::new(initial),
        }
    }

    /// Atomically read the current value.
    pub fn value(&self) -> u64 {
        self.value.load(Ordering::Acquire)
    }

    /// Attempt to install `new_value`. Returns `true` iff the install
    /// happened (`new_value > current`).
    pub fn set(&self, new_value: u64) -> bool {
        loop {
            let old = self.value.load(Ordering::Acquire);
            if new_value <= old {
                return false;
            }
            match self
                .value
                .compare_exchange(old, new_value, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    /// Atomically increment and return the new value.
    pub fn increment(&self) -> u64 {
        self.value.fetch_add(1, Ordering::AcqRel) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_read() {
        let c = StrictMonotonicCounter::new(5);
        assert_eq!(c.value(), 5);
    }

    #[test]
    fn set_installs_strictly_greater() {
        let c = StrictMonotonicCounter::new(5);
        assert!(c.set(10));
        assert_eq!(c.value(), 10);
    }

    #[test]
    fn set_rejects_equal_or_lower() {
        let c = StrictMonotonicCounter::new(5);
        assert!(!c.set(5));
        assert!(!c.set(3));
        assert_eq!(c.value(), 5);
    }

    #[test]
    fn increment_bumps_by_one() {
        let c = StrictMonotonicCounter::new(10);
        assert_eq!(c.increment(), 11);
        assert_eq!(c.increment(), 12);
        assert_eq!(c.value(), 12);
    }

    #[test]
    fn concurrent_set_preserves_monotonicity() {
        use std::sync::Arc;
        use std::thread;
        let c = Arc::new(StrictMonotonicCounter::new(0));
        let mut handles = vec![];
        for i in 1..=20 {
            let c = Arc::clone(&c);
            handles.push(thread::spawn(move || c.set(i)));
        }
        for h in handles {
            let _ = h.join();
        }
        // After any interleaving, value == 20 (the highest set).
        assert_eq!(c.value(), 20);
    }
}
