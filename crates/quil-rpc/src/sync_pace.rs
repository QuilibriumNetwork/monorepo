//! The pace of one tree sync from one archive: the remote reads of its tree
//! walks and the leaves of its blob fetches, against the time the sync spent
//! waiting on that archive. A watchdog judges the rate over a window of that
//! time ([`PaceWindow`]) and may give up on the archive
//! ([`PeerPace::give_up`]): every archive read of the sync, in flight or
//! next, then fails at once, and the caller tries another archive.
//!
//! Only time spent waiting on the archive counts, so a sync stalled by local
//! work (a busy store, a rebase) is never blamed on its archive.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Why an archive read of a sync fails once its archive was given up on.
pub const PACE_GIVEN_UP: &str = "sync from this archive given up: it served below the minimum rate";

/// What one archive call of a sync waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// A tree walk's node, value or leaf-listing read.
    Walk,
    /// The blobs of one chunk of changed leaves.
    Fetch,
}

/// Counters of one sync from one archive. Shared by the walk's reader (on a
/// blocking thread), the blob fetches and the watchdog.
pub struct PeerPace {
    origin: tokio::time::Instant,
    reads: AtomicU64,
    leaves: AtomicU64,
    bytes: AtomicU64,
    chunks: AtomicU64,
    walk_ms: AtomicU64,
    fetch_ms: AtomicU64,
    chunk_max_ms: AtomicU64,
    /// Milliseconds after `origin`, plus one, at which the archive call in
    /// flight began; 0 when none is.
    waiting_since: AtomicU64,
    given_up: CancellationToken,
}

/// One reading of a [`PeerPace`] for its watchdog.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PaceSample {
    /// Time spent waiting on the archive, the call in flight included.
    pub waited_ms: u64,
    pub reads: u64,
    pub leaves: u64,
    pub bytes: u64,
}

/// A sync's totals, for its summary line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PaceSummary {
    pub reads: u64,
    pub walk_ms: u64,
    pub leaves: u64,
    pub bytes: u64,
    pub chunks: u64,
    pub fetch_ms: u64,
    pub chunk_max_ms: u64,
}

impl PaceSummary {
    /// Walk reads per second of waiting on the archive.
    pub fn reads_per_s(&self) -> u64 {
        per_second(self.reads, self.walk_ms)
    }
    /// Fetched leaves per second of waiting on the archive.
    pub fn leaves_per_s(&self) -> u64 {
        per_second(self.leaves, self.fetch_ms)
    }
    /// Fetched blob bytes per second of waiting on the archive.
    pub fn bytes_per_s(&self) -> u64 {
        per_second(self.bytes, self.fetch_ms)
    }
    /// Mean wait for one chunk's blobs.
    pub fn chunk_mean_ms(&self) -> u64 {
        self.fetch_ms.checked_div(self.chunks).unwrap_or(0)
    }
}

fn per_second(count: u64, ms: u64) -> u64 {
    count.saturating_mul(1000).checked_div(ms).unwrap_or(0)
}

impl Default for PeerPace {
    fn default() -> Self {
        Self {
            origin: tokio::time::Instant::now(),
            reads: AtomicU64::new(0),
            leaves: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            chunks: AtomicU64::new(0),
            walk_ms: AtomicU64::new(0),
            fetch_ms: AtomicU64::new(0),
            chunk_max_ms: AtomicU64::new(0),
            waiting_since: AtomicU64::new(0),
            given_up: CancellationToken::new(),
        }
    }
}

impl PeerPace {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    /// Count walk reads (nodes, values or listed leaves).
    pub fn add_reads(&self, n: u64) {
        self.reads.fetch_add(n, Ordering::Relaxed);
    }

    /// Await `call`, an archive call of kind `wait`, counting its time as
    /// time waited on the archive. `None` once the archive was given up on,
    /// before or during the call.
    pub async fn remote<T>(&self, wait: Wait, call: impl Future<Output = T>) -> Option<T> {
        if self.given_up() {
            return None;
        }
        let began = self.now_ms();
        // The outermost call of a nested pair keeps the mark.
        let marked = self
            .waiting_since
            .compare_exchange(0, began + 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok();
        let answer = tokio::select! {
            biased;
            _ = self.given_up.cancelled() => None,
            answer = call => Some(answer),
        };
        let took = self.now_ms().saturating_sub(began);
        if marked {
            let total = match wait {
                Wait::Walk => &self.walk_ms,
                Wait::Fetch => &self.fetch_ms,
            };
            total.fetch_add(took, Ordering::Relaxed);
            self.waiting_since.store(0, Ordering::Release);
        }
        if wait == Wait::Fetch && answer.is_some() {
            self.chunks.fetch_add(1, Ordering::Relaxed);
            self.chunk_max_ms.fetch_max(took, Ordering::Relaxed);
        }
        answer
    }

    /// Count `leaves` leaves, with `bytes` of blobs, a chunk fetch
    /// delivered.
    pub fn add_leaves(&self, leaves: u64, bytes: u64) {
        self.leaves.fetch_add(leaves, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Give up on the archive: every archive read of this sync fails.
    pub fn give_up(&self) {
        self.given_up.cancel();
    }

    pub fn given_up(&self) -> bool {
        self.given_up.is_cancelled()
    }

    pub fn sample(&self) -> PaceSample {
        let since = self.waiting_since.load(Ordering::Acquire);
        let in_flight = match since {
            0 => 0,
            since => self.now_ms().saturating_sub(since - 1),
        };
        PaceSample {
            waited_ms: self.walk_ms.load(Ordering::Relaxed)
                + self.fetch_ms.load(Ordering::Relaxed)
                + in_flight,
            reads: self.reads.load(Ordering::Relaxed),
            leaves: self.leaves.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }

    pub fn summary(&self) -> PaceSummary {
        PaceSummary {
            reads: self.reads.load(Ordering::Relaxed),
            walk_ms: self.walk_ms.load(Ordering::Relaxed),
            leaves: self.leaves.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            chunks: self.chunks.load(Ordering::Relaxed),
            fetch_ms: self.fetch_ms.load(Ordering::Relaxed),
            chunk_max_ms: self.chunk_max_ms.load(Ordering::Relaxed),
        }
    }
}

/// The least an archive must serve over a window of time waited on it.
/// Measured on a regular node's GLOBAL prover tree syncs (Nov 2026):
/// healthy archives walked and installed 3.3-3.8k changed leaves in 15-45 s
/// (one long walk: 32,936 reads in 34 s; installs at 600+ leaves per
/// second); a slow one walked at 12-41 reads per second and installed about
/// 3 leaves per second, holding a sync for 28 minutes. Large blobs pass on
/// bytes: a chunk of few large leaves is not slow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaceFloor {
    pub window: Duration,
    pub reads_per_s: u64,
    pub leaves_per_s: u64,
    pub bytes_per_s: u64,
}

pub const SYNC_PACE_FLOOR: PaceFloor = PaceFloor {
    window: Duration::from_secs(60),
    reads_per_s: 100,
    leaves_per_s: 50,
    bytes_per_s: 512 * 1024,
};

/// An archive's rates over a window it ran below its [`PaceFloor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlowPace {
    pub window_secs: u64,
    pub reads_per_s: u64,
    pub leaves_per_s: u64,
    pub bytes_per_s: u64,
}

/// Judges a [`PeerPace`]'s samples. A window passes when its walk reads
/// and its fetches (leaves or bytes, whichever is more), each as a share of
/// what the floor asks over the window, add up to at least one: a window
/// spanning the end of a walk and the start of its install is judged on
/// both.
pub struct PaceWindow {
    floor: PaceFloor,
    samples: VecDeque<PaceSample>,
}

impl PaceWindow {
    pub fn new(floor: PaceFloor) -> Self {
        Self {
            floor,
            samples: VecDeque::new(),
        }
    }

    /// Add `sample`; `Some` when the last full window of waiting ran below
    /// the floor.
    pub fn observe(&mut self, sample: PaceSample) -> Option<SlowPace> {
        let window_ms = self.floor.window.as_millis() as u64;
        self.samples.push_back(sample);
        // Keep the latest sample at least a window of waiting back.
        while self
            .samples
            .get(1)
            .is_some_and(|next| next.waited_ms + window_ms <= sample.waited_ms)
        {
            self.samples.pop_front();
        }
        let first = *self.samples.front()?;
        let waited = sample.waited_ms.saturating_sub(first.waited_ms);
        if waited < window_ms || waited == 0 {
            return None;
        }
        let reads = sample.reads.saturating_sub(first.reads);
        let leaves = sample.leaves.saturating_sub(first.leaves);
        let bytes = sample.bytes.saturating_sub(first.bytes);
        let secs = waited as f64 / 1000.0;
        let share = |count: u64, floor: u64| count as f64 / (floor.max(1) as f64 * secs);
        let served = share(reads, self.floor.reads_per_s)
            + share(leaves, self.floor.leaves_per_s).max(share(bytes, self.floor.bytes_per_s));
        if served >= 1.0 {
            return None;
        }
        Some(SlowPace {
            window_secs: waited / 1000,
            reads_per_s: per_second(reads, waited),
            leaves_per_s: per_second(leaves, waited),
            bytes_per_s: per_second(bytes, waited),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOOR: PaceFloor = PaceFloor {
        window: Duration::from_secs(60),
        reads_per_s: 100,
        leaves_per_s: 50,
        bytes_per_s: 1000,
    };

    fn at(waited_s: u64, reads: u64, leaves: u64) -> PaceSample {
        PaceSample {
            waited_ms: waited_s * 1000,
            reads,
            leaves,
            bytes: 0,
        }
    }

    fn slow(reads_per_s: u64, leaves_per_s: u64) -> Option<SlowPace> {
        Some(SlowPace {
            window_secs: 60,
            reads_per_s,
            leaves_per_s,
            bytes_per_s: 0,
        })
    }

    #[test]
    fn a_window_below_the_floor_is_slow_and_one_at_it_is_not() {
        let mut window = PaceWindow::new(FLOOR);
        assert_eq!(window.observe(at(0, 0, 0)), None);
        // Under a full window: never judged, however slow.
        assert_eq!(window.observe(at(59, 10, 0)), None);
        assert_eq!(window.observe(at(60, 30 * 60, 0)), slow(30, 0));
        let mut window = PaceWindow::new(FLOOR);
        window.observe(at(0, 0, 0));
        assert_eq!(window.observe(at(60, 100 * 60, 0)), None);
    }

    #[test]
    fn a_window_spanning_walk_and_install_counts_both() {
        let mut window = PaceWindow::new(FLOOR);
        window.observe(at(0, 0, 0));
        // Half the reads the floor asks and half its leaves.
        assert_eq!(window.observe(at(60, 50 * 60, 25 * 60)), None);
        let mut window = PaceWindow::new(FLOOR);
        window.observe(at(0, 0, 0));
        assert_eq!(window.observe(at(60, 50 * 60, 24 * 60)), slow(50, 24));
    }

    #[test]
    fn few_large_blobs_pass_on_bytes() {
        let mut window = PaceWindow::new(FLOOR);
        window.observe(at(0, 0, 0));
        let mut large = at(60, 0, 60);
        large.bytes = 1000 * 60;
        assert_eq!(window.observe(large), None, "large blobs judged slow");
    }

    #[test]
    fn only_the_last_window_is_judged() {
        let mut window = PaceWindow::new(FLOOR);
        // A fast start does not cover a stall after it.
        window.observe(at(0, 0, 0));
        assert_eq!(window.observe(at(30, 100_000, 0)), None);
        assert_eq!(window.observe(at(60, 100_000, 0)), None);
        assert_eq!(
            window.observe(at(90, 100_000, 0)),
            slow(0, 0),
            "a stall after a fast start was not judged"
        );
    }
}
