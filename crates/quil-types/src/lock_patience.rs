//! Bounded waits for the locks a canonical publication takes. Readers hold
//! them briefly but often on a busy archive; giving up on the first conflict
//! threw away a whole executed frame (three times per frame, then in-place
//! execution, on one archive that never caught up).
//!
//! A wait never deadlocks: whatever holds a lock is never waited on past the
//! deadline, after which the caller fails exactly as an immediate try would.
use std::sync::{Mutex, MutexGuard, RwLock, RwLockWriteGuard, TryLockError};
use std::time::{Duration, Instant};

/// How long one publication step keeps trying the locks it needs.
pub const LOCK_PATIENCE: Duration = Duration::from_millis(500);

/// One deadline shared by every lock a step takes, so waits cannot add up.
pub struct Patience {
    deadline: Instant,
}

impl Patience {
    pub fn new() -> Self {
        Self::for_duration(LOCK_PATIENCE)
    }

    pub fn for_duration(patience: Duration) -> Self {
        Self { deadline: Instant::now() + patience }
    }

    /// `None` when poisoned, or still held when the deadline passes.
    pub fn write<'a, T>(&self, lock: &'a RwLock<T>) -> Option<RwLockWriteGuard<'a, T>> {
        self.retry(|| lock.try_write())
    }

    /// `None` when poisoned, or still held when the deadline passes.
    pub fn lock<'a, T>(&self, lock: &'a Mutex<T>) -> Option<MutexGuard<'a, T>> {
        self.retry(|| lock.try_lock())
    }

    fn retry<G>(&self, mut attempt: impl FnMut() -> Result<G, TryLockError<G>>) -> Option<G> {
        let mut pause = Duration::from_micros(100);
        loop {
            match attempt() {
                Ok(guard) => return Some(guard),
                Err(TryLockError::Poisoned(_)) => return None,
                Err(TryLockError::WouldBlock) => {
                    let now = Instant::now();
                    if now >= self.deadline {
                        return None;
                    }
                    std::thread::sleep(pause.min(self.deadline - now));
                    pause = (pause * 2).min(Duration::from_millis(10));
                }
            }
        }
    }
}

impl Default for Patience {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_lock_released_in_time_is_taken_and_one_held_past_the_deadline_is_not() {
        let lock = Arc::new(RwLock::new(0));
        let held = lock.clone();
        let (taken_tx, taken_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _guard = held.read().unwrap();
            taken_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });
        taken_rx.recv().unwrap();
        assert!(Patience::new().write(&lock).is_some(), "a brief reader is waited out");
        reader.join().unwrap();

        let _guard = lock.read().unwrap();
        let started = Instant::now();
        assert!(Patience::for_duration(Duration::from_millis(30)).write(&lock).is_none());
        assert!(started.elapsed() >= Duration::from_millis(30));
    }

    #[test]
    fn a_poisoned_lock_fails_at_once() {
        let lock = Arc::new(Mutex::new(0));
        let poisoner = lock.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison");
        })
        .join();
        let started = Instant::now();
        assert!(Patience::new().lock(&lock).is_none());
        assert!(started.elapsed() < LOCK_PATIENCE);
    }
}
