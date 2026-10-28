//! Gossiped application frames an archive ingests, handed off the message
//! loop. GLOBAL execution holds the archive's ingest while it materializes
//! the application frames a GLOBAL frame sequences, and the loop used to take
//! it for every gossiped frame and every retry pass: at GLOBAL frame 945,000
//! (2026-10-28) that held every consensus message behind one execution for
//! hours, on every archive at once. A worker thread takes it now. The loop
//! only queues, and drops what does not fit; the gap fetch asks for a dropped
//! frame again when a GLOBAL frame needs it.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quil_types::thread_probe::{self as probe, Section, ThreadProbe};
use tracing::error;

/// Frames queued at most.
pub(crate) const QUEUE_FRAMES: usize = 4096;
/// Bytes queued at most: a full queue of the largest frames would not fit
/// in memory.
pub(crate) const QUEUE_BYTES: usize = 256 << 20;
/// How often the ingest's retry pass runs: the message loop's status tick,
/// where it ran before.
pub(crate) const RETRY_EVERY: Duration = Duration::from_secs(30);

/// Whether a message on `bitmask` may carry a shard frame. A shard's frame
/// topic is its 32-byte application filter; its consensus, dispatch, prover
/// and consensus-engine topics prefix that filter, and an archive, which runs
/// no shard engine, ingests nothing from them.
pub(crate) fn may_carry_shard_frame(bitmask: &[u8]) -> bool {
    bitmask.len() == quil_engine::bitmasks::shard_frame_bitmask(&[0; 32]).len()
}

/// The loop's end of the queue.
pub(crate) struct ArchiveIngestQueue {
    frames: SyncSender<Vec<u8>>,
    queued_bytes: Arc<AtomicUsize>,
    max_bytes: usize,
    dropped: AtomicU64,
    dropped_bytes: AtomicU64,
}

impl ArchiveIngestQueue {
    /// Start the worker thread: it hands each queued frame to `ingest`, and
    /// calls `retry` at least every `retry_every`, marking both on `watched`.
    pub(crate) fn spawn(
        max_frames: usize,
        max_bytes: usize,
        retry_every: Duration,
        watched: Option<Arc<ThreadProbe>>,
        ingest: impl FnMut(&[u8]) + Send + 'static,
        retry: impl FnMut() + Send + 'static,
    ) -> Self {
        let (frames, queue) = sync_channel(max_frames);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let held = queued_bytes.clone();
        let started = std::thread::Builder::new()
            .name("archive-ingest".into())
            .spawn(move || {
                let _installed = watched.map(probe::install);
                run(queue, &held, retry_every, ingest, retry);
            });
        if let Err(error) = started {
            error!(%error, "archive ingest worker did not start: gossiped application frames are not ingested");
        }
        Self {
            frames,
            queued_bytes,
            max_bytes,
            dropped: AtomicU64::new(0),
            dropped_bytes: AtomicU64::new(0),
        }
    }

    /// Queue `data` for the worker without waiting. False, and counted, when
    /// the queue is full.
    pub(crate) fn offer(&self, data: Vec<u8>) -> bool {
        let len = data.len();
        let before = self.queued_bytes.fetch_add(len, Ordering::AcqRel);
        let queued =
            before.saturating_add(len) <= self.max_bytes && self.frames.try_send(data).is_ok();
        if !queued {
            self.queued_bytes.fetch_sub(len, Ordering::AcqRel);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            self.dropped_bytes.fetch_add(len as u64, Ordering::Relaxed);
        }
        queued
    }

    /// Frames, and their bytes, dropped since the last call.
    pub(crate) fn take_dropped(&self) -> (u64, u64) {
        (
            self.dropped.swap(0, Ordering::Relaxed),
            self.dropped_bytes.swap(0, Ordering::Relaxed),
        )
    }
}

fn run(
    queue: Receiver<Vec<u8>>,
    queued_bytes: &AtomicUsize,
    retry_every: Duration,
    mut ingest: impl FnMut(&[u8]),
    mut retry: impl FnMut(),
) {
    let mut next_retry = Instant::now() + retry_every;
    loop {
        probe::idle();
        let received = queue.recv_timeout(next_retry.saturating_duration_since(Instant::now()));
        probe::beat();
        match received {
            Ok(data) => {
                queued_bytes.fetch_sub(data.len(), Ordering::AcqRel);
                probe::step(Section::IngestFrame);
                if catch_unwind(AssertUnwindSafe(|| ingest(&data))).is_err() {
                    error!("archive ingest of a gossiped application frame panicked; the worker continues");
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        if Instant::now() >= next_retry {
            probe::step(Section::IngestRetry);
            if catch_unwind(AssertUnwindSafe(&mut retry)).is_err() {
                error!("archive ingest retry pass panicked; the worker continues");
            }
            next_retry = Instant::now() + retry_every;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn wait_until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// While the ingest is held elsewhere the loop's offers return at once:
    /// what fits waits in order, the rest is dropped and counted, and the
    /// queued frames are ingested once the ingest is free.
    #[test]
    fn offers_never_wait_for_a_held_ingest() {
        let ingest_lock = Arc::new(Mutex::new(()));
        let ingested = Arc::new(Mutex::new(Vec::new()));
        let held = ingest_lock.lock().unwrap();
        let queue = {
            let (lock, ingested) = (ingest_lock.clone(), ingested.clone());
            ArchiveIngestQueue::spawn(
                2,
                1 << 20,
                Duration::from_secs(3600),
                None,
                move |data| {
                    let _ingest = lock.lock().unwrap();
                    ingested.lock().unwrap().push(data.to_vec());
                },
                || {},
            )
        };
        let started = Instant::now();
        let mut accepted = 0;
        for frame in 0..50u8 {
            accepted += usize::from(queue.offer(vec![frame; 10]));
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        // The worker holds one frame while it waits, and two more queue.
        assert!((2..=3).contains(&accepted), "{accepted} accepted");
        let (dropped, dropped_bytes) = queue.take_dropped();
        assert_eq!(dropped as usize, 50 - accepted);
        assert_eq!(dropped_bytes, dropped * 10);
        assert_eq!(queue.take_dropped(), (0, 0));

        drop(held);
        wait_until("the queued frames", || {
            ingested.lock().unwrap().len() == accepted
        });
        let ingested = ingested.lock().unwrap();
        assert!(ingested.windows(2).all(|pair| pair[0][0] < pair[1][0]));
        assert_eq!(ingested[0], vec![0; 10]);
    }

    /// A frame that would take the queue past its byte bound is dropped.
    #[test]
    fn the_queue_is_bounded_in_bytes() {
        let queue = ArchiveIngestQueue::spawn(
            16,
            100,
            Duration::from_secs(3600),
            None,
            |_| std::thread::sleep(Duration::from_secs(3600)),
            || {},
        );
        assert!(queue.offer(vec![0; 60]));
        wait_until("the first frame to be taken", || {
            queue.queued_bytes.load(Ordering::Acquire) == 0
        });
        assert!(queue.offer(vec![1; 60]));
        assert!(!queue.offer(vec![2; 60]));
        assert!(queue.offer(vec![3; 40]));
        assert_eq!(queue.take_dropped(), (1, 60));
    }

    /// Retry passes run on their own timer with no frame arriving, and a
    /// panicking ingest leaves the worker running.
    #[test]
    fn retries_run_on_a_timer_and_a_panic_does_not_stop_the_worker() {
        let retries = Arc::new(AtomicUsize::new(0));
        let ingested = Arc::new(AtomicUsize::new(0));
        let queue = {
            let (retries, ingested) = (retries.clone(), ingested.clone());
            ArchiveIngestQueue::spawn(
                16,
                1 << 20,
                Duration::from_millis(20),
                None,
                move |data| {
                    assert_ne!(data, b"panic");
                    ingested.fetch_add(1, Ordering::AcqRel);
                },
                move || {
                    retries.fetch_add(1, Ordering::AcqRel);
                },
            )
        };
        wait_until("two retry passes", || retries.load(Ordering::Acquire) >= 2);
        assert!(queue.offer(b"panic".to_vec()));
        assert!(queue.offer(b"frame".to_vec()));
        wait_until("the frame after the panic", || {
            ingested.load(Ordering::Acquire) == 1
        });
    }

    /// A worker that waits for the ingest is named by the watchdog, with the
    /// frame it holds; one waiting for frames is not blocked.
    #[test]
    fn a_worker_waiting_for_the_ingest_is_reported() {
        use super::super::stall_watch::{
            StallReport, StallWatch, ARCHIVE_INGEST_IMPACT, ARCHIVE_INGEST_STALL_AFTER,
        };
        let watched = ThreadProbe::new();
        let mut watch = StallWatch::new(Duration::from_secs(60));
        watch.add(
            Section::ArchiveIngest,
            ARCHIVE_INGEST_IMPACT,
            ARCHIVE_INGEST_STALL_AFTER,
            &watched,
        );
        let ingest_lock = Arc::new(Mutex::new(()));
        let entered = Arc::new(AtomicUsize::new(0));
        let held = ingest_lock.lock().unwrap();
        let queue = {
            let (lock, entered) = (ingest_lock.clone(), entered.clone());
            ArchiveIngestQueue::spawn(
                4,
                1 << 20,
                Duration::from_secs(3600),
                Some(watched.clone()),
                move |_| {
                    entered.fetch_add(1, Ordering::AcqRel);
                    let _ingest = lock.lock().unwrap();
                },
                || {},
            )
        };
        wait_until("the worker to wait for frames", || {
            watched.snapshot().idle()
        });
        let stall_ms = ARCHIVE_INGEST_STALL_AFTER.as_millis() as u64;
        assert_eq!(watch.poll(probe::now_ms() + stall_ms + 1_000), Vec::new());

        assert!(queue.offer(vec![1; 4]));
        wait_until("the worker to take the frame", || {
            entered.load(Ordering::Acquire) == 1
        });
        let reports = watch.poll(probe::now_ms() + stall_ms + 1_000);
        let [StallReport::Blocked { task, place, .. }] = reports.as_slice() else {
            panic!("{reports:?}");
        };
        assert_eq!(*task, Section::ArchiveIngest);
        assert_eq!(place.describe(), "gossiped application frame");
        drop(held);
    }

    #[test]
    fn only_frame_topics_carry_shard_frames() {
        let filter = [7u8; 32];
        assert!(may_carry_shard_frame(
            &quil_engine::bitmasks::shard_frame_bitmask(&filter)
        ));
        for other in [
            quil_engine::bitmasks::shard_consensus_bitmask(&filter),
            quil_engine::bitmasks::shard_dispatch_bitmask(&filter),
            quil_engine::bitmasks::shard_prover_bitmask(&filter),
            quil_engine::bitmasks::shard_cw_bitmask(&filter),
        ] {
            assert!(!may_carry_shard_frame(&other));
        }
    }
}
