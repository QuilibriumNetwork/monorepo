//! Gossiped application frames an archive ingests, handed off the message
//! loop. GLOBAL execution holds the archive's ingest while it materializes
//! the application frames a GLOBAL frame sequences, and the loop used to take
//! it for every gossiped frame and every retry pass: at GLOBAL frame 945,000
//! (2026-10-28) that held every consensus message behind one execution for
//! hours, on every archive at once. A worker thread takes it now. The loop
//! only queues, and drops what does not fit; the gap fetch asks for a dropped
//! frame again when a GLOBAL frame needs it.

use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quil_types::thread_probe::{self as probe, Section, ThreadProbe};
use tracing::{error, info, warn};

/// Frames queued at most.
pub(crate) const QUEUE_FRAMES: usize = 4096;
/// Bytes queued at most: a full queue of the largest frames would not fit
/// in memory.
pub(crate) const QUEUE_BYTES: usize = 256 << 20;
/// How often the ingest's retry pass runs: the message loop's status tick,
/// where it ran before.
pub(crate) const RETRY_EVERY: Duration = Duration::from_secs(30);
/// A backlog of more than this many frames logs when it has drained.
pub(crate) const BACKLOG_FRAMES: usize = 256;
/// A retry pass that runs longer than this logs its duration.
pub(crate) const SLOW_RETRY: Duration = Duration::from_secs(5);

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
    /// When each queued frame was queued, oldest first: the worker takes
    /// frames in this order.
    queued_at: Arc<Mutex<VecDeque<Instant>>>,
    /// False once the worker failed to start or stopped.
    worker_running: Arc<AtomicBool>,
    max_bytes: usize,
    dropped: AtomicU64,
    dropped_bytes: AtomicU64,
}

/// Clears the running flag when the worker thread ends, however it ends.
struct Running(Arc<AtomicBool>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
        if std::thread::panicking() {
            error!(
                scope = "this archive",
                action = "restart the node and report this line",
                "archive ingest worker stopped: gossiped application frames are not ingested"
            );
        }
    }
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
        Self::start(
            max_frames,
            max_bytes,
            retry_every,
            watched,
            ingest,
            retry,
            |worker| {
                std::thread::Builder::new()
                    .name("archive-ingest".into())
                    .spawn(worker)
                    .map(drop)
            },
        )
    }

    /// [`Self::spawn`] with the thread started by `start_thread`.
    fn start(
        max_frames: usize,
        max_bytes: usize,
        retry_every: Duration,
        watched: Option<Arc<ThreadProbe>>,
        ingest: impl FnMut(&[u8]) + Send + 'static,
        retry: impl FnMut() + Send + 'static,
        start_thread: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
    ) -> Self {
        let (frames, queue) = sync_channel(max_frames);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let queued_at = Arc::new(Mutex::new(VecDeque::new()));
        let worker_running = Arc::new(AtomicBool::new(true));
        let worker = {
            let (bytes, at, running) = (
                queued_bytes.clone(),
                queued_at.clone(),
                worker_running.clone(),
            );
            // The worker logs where its spawner does.
            let dispatch = tracing::dispatcher::get_default(|dispatch| dispatch.clone());
            move || {
                let _running = Running(running);
                let _installed = watched.map(probe::install);
                tracing::dispatcher::with_default(&dispatch, || {
                    run(queue, &bytes, &at, retry_every, ingest, retry)
                });
            }
        };
        if let Err(error) = start_thread(Box::new(worker)) {
            worker_running.store(false, Ordering::Release);
            error!(
                %error,
                scope = "this archive",
                action = "restart the node; if it repeats, check the host's thread and memory \
                          limits and report this line",
                "archive ingest worker did not start: gossiped application frames are not ingested"
            );
        }
        Self {
            frames,
            queued_bytes,
            queued_at,
            worker_running,
            max_bytes,
            dropped: AtomicU64::new(0),
            dropped_bytes: AtomicU64::new(0),
        }
    }

    /// Queue `data` for the worker without waiting. False, and counted, when
    /// the queue is full or its worker is not running.
    pub(crate) fn offer(&self, data: Vec<u8>) -> bool {
        let len = data.len();
        let before = self.queued_bytes.fetch_add(len, Ordering::AcqRel);
        let queued = before.saturating_add(len) <= self.max_bytes && {
            // Stamped before the worker can take it: it takes the stamp under
            // this lock.
            let mut queued_at = self.queued_at.lock().unwrap_or_else(|p| p.into_inner());
            queued_at.push_back(Instant::now());
            let sent = self.frames.try_send(data).is_ok();
            if !sent {
                queued_at.pop_back();
            }
            sent
        };
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

    /// Log the frames dropped since the last call, if any, with what is
    /// queued. Called every `interval_secs`.
    pub(crate) fn report_dropped(&self, interval_secs: u64) {
        let (frames, bytes) = self.take_dropped();
        if frames == 0 {
            return;
        }
        if !self.worker_running.load(Ordering::Acquire) {
            error!(
                frames,
                bytes,
                interval_secs,
                scope = "this archive",
                action = "restart the node and report the 'archive ingest worker' error logged \
                          before this; until then only the gap fetch recovers frames a GLOBAL \
                          frame needs",
                "archive dropped gossiped application frames: its ingest worker is not running"
            );
            return;
        }
        let (queued, oldest_age_s) = {
            let queued_at = self.queued_at.lock().unwrap_or_else(|p| p.into_inner());
            (
                queued_at.len(),
                queued_at.front().map_or(0, |at| at.elapsed().as_secs()),
            )
        };
        warn!(
            frames,
            bytes,
            queued,
            queued_bytes = self.queued_bytes.load(Ordering::Acquire),
            oldest_age_s,
            interval_secs,
            scope = "this archive",
            action = "none if it passes: the application frame ingest is held, usually by GLOBAL \
                      execution sequencing application frames, and the gap fetch asks for a dropped \
                      frame again when a GLOBAL frame needs it; if it repeats, look for 'master task \
                      blocked' lines naming the GLOBAL frame materializer",
            "archive dropped gossiped application frames: its ingest queue was full"
        );
    }
}

/// A backlog the worker is draining.
struct Drain {
    started: Instant,
    /// How long the frame that started it had waited.
    waited: Duration,
    peak: usize,
    frames: u64,
}

impl Drain {
    /// The backlog when the worker takes a frame `waited` old with `queued`
    /// more behind it, if it is one.
    fn starts(queued: usize, waited: Duration) -> Option<Self> {
        (queued + 1 > BACKLOG_FRAMES).then(|| Self {
            started: Instant::now(),
            waited,
            peak: queued + 1,
            frames: 0,
        })
    }

    fn drained(&self) {
        info!(
            frames = self.frames,
            peak = self.peak,
            waited_s = self.waited.as_secs(),
            duration_ms = self.started.elapsed().as_millis() as u64,
            scope = "this archive",
            "archive ingest queue drained a backlog of gossiped application frames"
        );
    }
}

/// Log a retry pass that ran longer than [`SLOW_RETRY`]; true when it did.
fn note_retry_pass(elapsed: Duration) -> bool {
    if elapsed <= SLOW_RETRY {
        return false;
    }
    info!(
        duration_ms = elapsed.as_millis() as u64,
        scope = "this archive",
        "archive ingest retry pass was slow: it materializes held application frames and \
         waits for the ingest while GLOBAL execution holds it; gossiped frames queue meanwhile"
    );
    true
}

fn run(
    queue: Receiver<Vec<u8>>,
    queued_bytes: &AtomicUsize,
    queued_at: &Mutex<VecDeque<Instant>>,
    retry_every: Duration,
    mut ingest: impl FnMut(&[u8]),
    mut retry: impl FnMut(),
) {
    let mut next_retry = Instant::now() + retry_every;
    let mut drain: Option<Drain> = None;
    loop {
        probe::idle();
        let received = queue.recv_timeout(next_retry.saturating_duration_since(Instant::now()));
        probe::beat();
        match received {
            Ok(data) => {
                queued_bytes.fetch_sub(data.len(), Ordering::AcqRel);
                let (waited, queued) = {
                    let mut queued_at = queued_at.lock().unwrap_or_else(|p| p.into_inner());
                    let waited = queued_at
                        .pop_front()
                        .map_or(Duration::ZERO, |at| at.elapsed());
                    (waited, queued_at.len())
                };
                if drain.is_none() {
                    drain = Drain::starts(queued, waited);
                }
                if let Some(drain) = drain.as_mut() {
                    drain.peak = drain.peak.max(queued + 1);
                }
                probe::step(Section::IngestFrame);
                if catch_unwind(AssertUnwindSafe(|| ingest(&data))).is_err() {
                    error!("archive ingest of a gossiped application frame panicked; the worker continues");
                }
                if let Some(current) = drain.as_mut() {
                    current.frames += 1;
                    let empty = queued_at
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .is_empty();
                    if empty {
                        current.drained();
                        drain = None;
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        if Instant::now() >= next_retry {
            probe::step(Section::IngestRetry);
            let started = Instant::now();
            if catch_unwind(AssertUnwindSafe(&mut retry)).is_err() {
                error!("archive ingest retry pass panicked; the worker continues");
            }
            note_retry_pass(started.elapsed());
            next_retry = Instant::now() + retry_every;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Records `LEVEL message field=value ...` of every event, from any
    /// thread that logs to it.
    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<String>>>);

    impl tracing::Subscriber for Recorder {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Fields(String);
            impl tracing::field::Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!(" {}={:?}", field.name(), value));
                }
            }
            let mut fields = Fields(event.metadata().level().to_string());
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    impl Recorder {
        fn install(&self) -> tracing::subscriber::DefaultGuard {
            tracing::subscriber::set_default(self.clone())
        }

        fn lines_with(&self, text: &str) -> Vec<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|line| line.contains(text))
                .cloned()
                .collect()
        }
    }

    /// Queue `backlog` frames behind one the worker holds while the ingest
    /// is held, release it, and return the drain lines once all are ingested.
    fn drain_lines(backlog: usize) -> Vec<String> {
        let logs = Recorder::default();
        let _logging = logs.install();
        let ingest_lock = Arc::new(Mutex::new(()));
        let ingested = Arc::new(AtomicUsize::new(0));
        let held = ingest_lock.lock().unwrap();
        let queue = {
            let (lock, ingested) = (ingest_lock.clone(), ingested.clone());
            ArchiveIngestQueue::spawn(
                1024,
                1 << 20,
                Duration::from_secs(3600),
                None,
                move |_| {
                    ingested.fetch_add(1, Ordering::AcqRel);
                    let _ingest = lock.lock().unwrap();
                },
                || {},
            )
        };
        assert!(queue.offer(vec![0; 4]));
        wait_until("the worker to hold the first frame", || {
            ingested.load(Ordering::Acquire) == 1
        });
        for frame in 0..backlog {
            assert!(queue.offer(vec![frame as u8; 4]));
        }
        drop(held);
        wait_until("the backlog", || {
            ingested.load(Ordering::Acquire) == backlog + 1
        });
        // The line follows the last frame's ingest.
        if backlog > BACKLOG_FRAMES {
            wait_until("the drain line", || {
                !logs.lines_with("drained a backlog").is_empty()
            });
        } else {
            std::thread::sleep(Duration::from_millis(200));
        }
        logs.lines_with("drained a backlog")
    }

    /// A backlog of more than [`BACKLOG_FRAMES`] logs one line once it has
    /// drained, with its frames; one at the bound logs none.
    #[test]
    fn a_drained_backlog_logs_once_above_its_bound() {
        let lines = drain_lines(BACKLOG_FRAMES + 1);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("INFO"), "{}", lines[0]);
        assert!(
            lines[0].contains(&format!(" frames={}", BACKLOG_FRAMES + 1)),
            "{}",
            lines[0]
        );
        assert!(
            lines[0].contains(&format!(" peak={}", BACKLOG_FRAMES + 1)),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains(" waited_s="), "{}", lines[0]);
        assert!(lines[0].contains(" duration_ms="), "{}", lines[0]);
        assert_eq!(drain_lines(BACKLOG_FRAMES), Vec::<String>::new());
    }

    /// A retry pass longer than [`SLOW_RETRY`] logs its duration.
    #[test]
    fn a_slow_retry_pass_logs_its_duration() {
        let logs = Recorder::default();
        let _logging = logs.install();
        assert!(!note_retry_pass(SLOW_RETRY));
        assert_eq!(logs.lines_with("retry pass"), Vec::<String>::new());
        assert!(note_retry_pass(SLOW_RETRY + Duration::from_millis(1)));
        let lines = logs.lines_with("archive ingest retry pass was slow");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("INFO"), "{}", lines[0]);
        assert!(lines[0].contains(" duration_ms=5001"), "{}", lines[0]);
    }

    /// Frames dropped while the ingest is held are reported with what is
    /// queued; an interval without drops is silent.
    #[test]
    fn dropped_frames_are_reported_with_the_queue() {
        let logs = Recorder::default();
        let _logging = logs.install();
        let ingest_lock = Arc::new(Mutex::new(()));
        let held = ingest_lock.lock().unwrap();
        let queue = {
            let lock = ingest_lock.clone();
            ArchiveIngestQueue::spawn(
                2,
                1 << 20,
                Duration::from_secs(3600),
                None,
                move |_| {
                    let _ingest = lock.lock().unwrap();
                },
                || {},
            )
        };
        queue.report_dropped(30);
        let mut accepted = 0;
        for frame in 0..10u8 {
            accepted += usize::from(queue.offer(vec![frame; 10]));
        }
        queue.report_dropped(30);
        let lines = logs.lines_with("archive dropped gossiped application frames");
        assert_eq!(lines.len(), 1, "{lines:?}");
        let line = &lines[0];
        assert!(line.starts_with("WARN"), "{line}");
        assert!(line.contains("its ingest queue was full"), "{line}");
        assert!(
            line.contains(&format!(" frames={}", 10 - accepted)),
            "{line}"
        );
        assert!(line.contains(" queued="), "{line}");
        assert!(line.contains(" queued_bytes="), "{line}");
        assert!(line.contains(" oldest_age_s=0"), "{line}");
        queue.report_dropped(30);
        assert_eq!(logs.lines_with("archive dropped").len(), 1);
        drop(held);
    }

    /// A worker that never started says so at the start, and every frame it
    /// drops is reported as a stopped worker, never as a held ingest.
    #[test]
    fn a_worker_that_did_not_start_is_reported_as_such() {
        let logs = Recorder::default();
        let _logging = logs.install();
        let queue = ArchiveIngestQueue::start(
            16,
            1 << 20,
            Duration::from_secs(3600),
            None,
            |_| {},
            || {},
            |_| Err(std::io::Error::other("no threads left")),
        );
        let started = logs.lines_with("archive ingest worker did not start");
        assert_eq!(started.len(), 1, "{started:?}");
        assert!(started[0].starts_with("ERROR"), "{}", started[0]);
        assert!(started[0].contains("no threads left"), "{}", started[0]);
        assert!(!queue.offer(vec![1; 4]));
        assert!(!queue.offer(vec![2; 4]));
        queue.report_dropped(30);
        let lines = logs.lines_with("archive dropped gossiped application frames");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("ERROR"), "{}", lines[0]);
        assert!(
            lines[0].contains("its ingest worker is not running"),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains(" frames=2 bytes=8"), "{}", lines[0]);
        assert!(!lines[0].contains("held"), "{}", lines[0]);
    }
}
