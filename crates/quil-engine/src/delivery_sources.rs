//! The certified frames a shard's pending deliveries read their bytes from,
//! fetched off the engine's select loop.
//!
//! A split application's outputs are delivered by the shard owning their
//! block, which is rarely the shard that executed them, so a member fetches
//! the executing shard's frame from an archive before it can propose those
//! deliveries. Finding the pending deliveries reads the shard's state from
//! the store, which can take tens of seconds (after a payload eviction, a
//! read seeks across deleted records that a snapshot still pins); a fetch
//! dials an archive and can take tens of seconds too; and a frame no archive
//! returns stays missing. Run on the engine's select loop every ten seconds,
//! such reads and fetches held off votes and finalized frames for as long as
//! they took. Here the loop only starts a sweep and takes in what earlier
//! sweeps read: at most one sweep runs at a time, in its own task; its store
//! reads and writes run on a blocking thread; each fetch has a deadline; and
//! a frame that could not be obtained is asked for again only after a
//! backoff that doubles up to [`MAX_RETRY`]. A delivery that keeps waiting,
//! and a read that keeps being slow, are each reported as an [`Outage`].

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use quil_types::{proto::global::AppShardFrame, store::ClockStore};
use tokio::{sync::mpsc, time::Instant};
use tracing::{debug, info, warn};

use crate::{
    app_engine::DeliveryFrameSource,
    outage::{Outage, OutageEvent},
};

/// How long one fetch may take before it counts as failed.
const FETCH_DEADLINE: Duration = Duration::from_secs(30);
/// The wait before a source frame that could not be obtained is asked for
/// again; it doubles with each further failure.
const FIRST_RETRY: Duration = Duration::from_secs(20);
/// The longest wait between two requests for one source frame.
const MAX_RETRY: Duration = Duration::from_secs(300);
/// Consecutive engine ticks (ten seconds apart) at which the latest read
/// shows a delivery waiting on a source frame that could not be obtained
/// before the wait is reported: about a minute.
const REPORT_AFTER_SWEEPS: u64 = 6;
/// A read of the pending deliveries that takes this long or longer is slow:
/// it outlasts the engine tick that starts the sweeps.
const SLOW_READ: Duration = Duration::from_secs(10);

/// A source frame: the executing shard's filter and its frame number.
type Source = (Vec<u8>, u64);

/// Reads, from the store, the source frames of the shard's pending
/// deliveries that this node does not hold, in delivery order. It blocks, so
/// a sweep runs it on a blocking thread; it does not log, since a worker's
/// log lines are routed by the thread that writes them.
pub(crate) type Collect = Box<dyn FnOnce() -> Result<Vec<Source>, String> + Send>;

/// What one sweep's read found, sent back to the select loop.
struct Collected {
    /// The missing source frames, or why they could not be read.
    missing: Result<Vec<Source>, String>,
    /// How long the read took.
    read: Duration,
}

/// A source frame whose fetch failed.
struct Waiting {
    since: Instant,
    failures: u32,
    retry_at: Instant,
}

type Unobtained = Arc<Mutex<HashMap<Source, Waiting>>>;

/// Why a fetched frame was not stored.
enum Unstored {
    /// The frame is another than the one asked for.
    NotRequested,
    /// The store failed.
    Failed,
}

/// One engine's delivery source fetches; see the module docs.
pub(crate) struct DeliverySources {
    unobtained: Unobtained,
    sweep: Option<tokio::task::JoinHandle<()>>,
    /// The sweeps' reads, on their way to the select loop.
    collected_tx: mpsc::UnboundedSender<Collected>,
    collected_rx: mpsc::UnboundedReceiver<Collected>,
    /// What the latest read found missing; none before the first read.
    missing: Option<Vec<Source>>,
    outage: Outage,
    slow_reads: Outage,
}

impl Default for DeliverySources {
    fn default() -> Self {
        let (collected_tx, collected_rx) = mpsc::unbounded_channel();
        Self {
            unobtained: Unobtained::default(),
            sweep: None,
            collected_tx,
            collected_rx,
            missing: None,
            outage: Outage::begin_after(REPORT_AFTER_SWEEPS),
            slow_reads: Outage::default(),
        }
    }
}

impl Drop for DeliverySources {
    fn drop(&mut self) {
        if let Some(sweep) = self.sweep.take() {
            sweep.abort();
        }
    }
}

impl DeliverySources {
    /// Report what earlier sweeps read for the shard `filter`, then start a
    /// sweep: `collect` reads the source frames of the shard's pending
    /// deliveries that this node lacks, and the due ones are fetched into
    /// `clock_store`. Waits for neither the store nor the network; nothing
    /// starts while an earlier sweep still runs.
    pub(crate) fn sweep(
        &mut self,
        filter: &[u8],
        collect: Collect,
        fetch: DeliveryFrameSource,
        clock_store: Arc<dyn ClockStore>,
    ) {
        let now = Instant::now();
        while let Ok(collected) = self.collected_rx.try_recv() {
            observe_read(&mut self.slow_reads, filter, collected.read, now);
            match collected.missing {
                Ok(missing) => self.missing = Some(missing),
                Err(error) => debug!(filter = hex::encode(filter), %error, "delivery sources unavailable"),
            }
        }
        if let Some(missing) = self.missing.as_ref() {
            let unobtained = self.unobtained.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            report(&mut self.outage, filter, missing, &unobtained, now);
        }
        if self.sweep.as_ref().is_some_and(|sweep| !sweep.is_finished()) {
            return;
        }
        self.sweep = Some(tokio::spawn(run_sweep(
            collect,
            fetch,
            clock_store,
            self.unobtained.clone(),
            self.collected_tx.clone(),
        )));
    }
}

/// Log the start, bounded repeats and end of a wait for a source frame that
/// could not be obtained. The first such frame in delivery order holds up
/// every later delivery of the shard, so the line names it.
fn report(outage: &mut Outage, filter: &[u8], missing: &[Source], unobtained: &HashMap<Source, Waiting>, now: Instant) {
    let first = missing.iter().find_map(|source| unobtained.get(source).map(|waiting| (source, waiting)));
    let event = outage.observe(now.into_std(), first.is_none());
    let filter = hex::encode(filter);
    match (event, first) {
        (Some(OutageEvent::Began), Some(((source_filter, source_frame), waiting))) => warn!(
            filter = %filter, source_filter = %hex::encode(source_filter), source_frame,
            waiting_sources = unobtained.len(), failures = waiting.failures,
            waited_secs = now.duration_since(waiting.since).as_secs(), scope = "network", action = "report",
            "this shard's deliveries wait for another shard's frame that no archive returned; the outputs \
             executed in it, and every later delivery of this shard, are not proposed until an archive \
             serves it; report this line if it persists"),
        (Some(OutageEvent::Continues { secs, .. }), Some(((source_filter, source_frame), waiting))) => warn!(
            filter = %filter, source_filter = %hex::encode(source_filter), source_frame,
            waiting_sources = unobtained.len(), failures = waiting.failures, secs,
            scope = "network", action = "report",
            "this shard's deliveries still wait for another shard's frame that no archive returned"),
        (Some(OutageEvent::Ended { secs, .. }), _) => info!(filter = %filter, secs,
            "this shard's deliveries no longer wait for another shard's frame"),
        _ => {}
    }
}

/// Log the start, bounded repeats and end of slow reads of the shard
/// `filter`'s pending deliveries; `read` is how long the latest one took.
fn observe_read(slow_reads: &mut Outage, filter: &[u8], read: Duration, now: Instant) {
    let read_secs = read.as_secs();
    match slow_reads.observe(now.into_std(), read < SLOW_READ) {
        Some(OutageEvent::Began) => warn!(
            filter = %hex::encode(filter), read_secs, scope = "local", action = "report",
            "reading this shard's pending deliveries from the store is slow; the engine goes on, but \
             fetching their source frames waits for the read; report this line if it persists"),
        Some(OutageEvent::Continues { secs, failures }) => warn!(
            filter = %hex::encode(filter), read_secs, secs, slow_reads = failures, scope = "local",
            action = "report", "reading this shard's pending deliveries from the store is still slow"),
        Some(OutageEvent::Ended { secs, failures }) => info!(
            filter = %hex::encode(filter), read_ms = read.as_millis() as u64, secs, slow_reads = failures,
            "reading this shard's pending deliveries from the store is fast again"),
        None => {}
    }
}

/// One sweep: `collect` on a blocking thread, its outcome to the select loop
/// over `collected`, then the fetch of the due frames.
async fn run_sweep(
    collect: Collect,
    fetch: DeliveryFrameSource,
    clock_store: Arc<dyn ClockStore>,
    unobtained: Unobtained,
    collected: mpsc::UnboundedSender<Collected>,
) {
    let started = Instant::now();
    let missing = tokio::task::spawn_blocking(collect)
        .await
        .unwrap_or_else(|error| Err(format!("the read did not finish: {error}")));
    let read = started.elapsed();
    let due: Vec<Source> = match &missing {
        Ok(missing) => {
            let now = Instant::now();
            let mut unobtained = unobtained.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            // A source no longer missing was delivered or obtained.
            unobtained.retain(|source, _| missing.contains(source));
            missing
                .iter()
                .filter(|source| unobtained.get(*source).is_none_or(|waiting| waiting.retry_at <= now))
                .cloned()
                .collect()
        }
        Err(_) => Vec::new(),
    };
    let _ = collected.send(Collected { missing, read });
    fetch_due(due, fetch, clock_store, unobtained).await;
}

/// Fetch `due` in order, each within [`FETCH_DEADLINE`], storing what
/// arrives (on a blocking thread) and scheduling the retry of what does not.
async fn fetch_due(due: Vec<Source>, fetch: DeliveryFrameSource, clock_store: Arc<dyn ClockStore>, unobtained: Unobtained) {
    for (filter, frame_number) in due {
        let fetched = tokio::time::timeout(FETCH_DEADLINE, fetch(filter.clone(), frame_number)).await.ok().flatten();
        let stored = match fetched {
            Some(frame) => {
                let (clock_store, source_filter) = (clock_store.clone(), filter.clone());
                let stored = tokio::task::spawn_blocking(move || store(clock_store.as_ref(), &source_filter, frame_number, &frame))
                    .await
                    .unwrap_or(Err(Unstored::Failed));
                match stored {
                    Ok(()) => true,
                    Err(Unstored::NotRequested) => {
                        warn!(filter = hex::encode(&filter), frame = frame_number, "delivery source frame is not the one requested");
                        false
                    }
                    Err(Unstored::Failed) => {
                        warn!(filter = hex::encode(&filter), frame = frame_number, "storing a delivery's source frame failed");
                        false
                    }
                }
            }
            None => {
                debug!(filter = hex::encode(&filter), frame = frame_number, "delivery source frame not available yet");
                false
            }
        };
        let now = Instant::now();
        let mut unobtained = unobtained.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let source = (filter, frame_number);
        if stored {
            let earlier = unobtained.remove(&source);
            info!(filter = hex::encode(&source.0), frame = frame_number,
                failures = earlier.as_ref().map_or(0, |waiting| waiting.failures),
                waited_secs = earlier.map_or(0, |waiting| now.duration_since(waiting.since).as_secs()),
                "fetched a delivery's source frame");
        } else {
            let waiting = unobtained.entry(source).or_insert(Waiting { since: now, failures: 0, retry_at: now });
            waiting.failures += 1;
            waiting.retry_at = now + retry_after(waiting.failures);
        }
    }
}

/// The wait after the `failures`-th failed fetch of one source frame.
fn retry_after(failures: u32) -> Duration {
    FIRST_RETRY.saturating_mul(1 << failures.saturating_sub(1).min(16)).min(MAX_RETRY)
}

/// Store `frame`, fetched as frame `frame_number` of `filter`, unless it is
/// another frame or the store fails. Blocks; does not log.
fn store(clock_store: &dyn ClockStore, filter: &[u8], frame_number: u64, frame: &AppShardFrame) -> Result<(), Unstored> {
    let Some(header) = frame.header.as_ref() else { return Err(Unstored::NotRequested) };
    if header.address != filter || header.frame_number != frame_number {
        return Err(Unstored::NotRequested);
    }
    let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
        .map(|hash| hash.to_vec())
        .unwrap_or_default();
    clock_store
        .new_transaction(false)
        .ok()
        .and_then(|txn| {
            clock_store.stage_shard_clock_frame(&selector, frame, txn.as_ref()).ok()?;
            txn.commit().ok()?;
            let txn = clock_store.new_transaction(false).ok()?;
            clock_store.commit_shard_clock_frame(filter, frame_number, &selector, txn.as_ref(), true).ok()?;
            txn.commit().ok()
        })
        .ok_or(Unstored::Failed)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use quil_types::proto::global::FrameHeader;

    use super::*;
    use crate::outage::test_logs::CapturedLogs;

    const FILTER: [u8; 35] = [0x11; 35];
    const SOURCE: [u8; 35] = [0x22; 35];
    const TICK: Duration = Duration::from_secs(10);

    struct Directory(std::path::PathBuf);

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn clock() -> (Directory, quil_store::RocksDb, Arc<dyn ClockStore>) {
        let path = std::env::temp_dir().join(format!(
            "quil-delivery-sources-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        let directory = Directory(path);
        let db = quil_store::RocksDb::open(&directory.0).unwrap();
        let clock: Arc<dyn ClockStore> = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        (directory, db, clock)
    }

    fn frame(filter: &[u8], frame_number: u64) -> AppShardFrame {
        AppShardFrame {
            header: Some(FrameHeader {
                address: filter.to_vec(),
                frame_number,
                output: vec![5; 64],
                ..Default::default()
            }),
            requests: Vec::new(),
            storage_attestation: None,
        }
    }

    /// A source answering `answer`, counting requests.
    fn source(calls: Arc<AtomicUsize>, answer: Option<AppShardFrame>) -> DeliveryFrameSource {
        Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            let answer = answer.clone();
            Box::pin(async move { answer })
        })
    }

    /// A source that never answers, counting requests.
    fn hung(calls: Arc<AtomicUsize>) -> DeliveryFrameSource {
        Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending::<Option<AppShardFrame>>())
        })
    }

    /// One engine tick: a sweep whose read finds `missing`, then the wait
    /// for the next tick.
    async fn tick(
        sources: &mut DeliverySources,
        missing: &[Source],
        fetch: &DeliveryFrameSource,
        clock: &Arc<dyn ClockStore>,
    ) {
        let missing = missing.to_vec();
        sources.sweep(&FILTER, Box::new(move || Ok(missing)), fetch.clone(), clock.clone());
        tokio::time::sleep(TICK).await;
    }

    /// A slow store read in a sweep must not hold the engine's select loop:
    /// the loop goes on handling its other messages while the read runs.
    #[tokio::test]
    async fn the_loop_handles_messages_while_a_sweep_reads_the_store() {
        let (_directory, _db, clock) = clock();
        let fetch = source(Arc::new(AtomicUsize::new(0)), None);
        let mut sources = DeliverySources::default();
        // The read blocks its thread until the loop has handled a message,
        // or at the latest for five seconds, so a loop held by the read
        // fails the test instead of hanging it.
        let (release, gate) = std::sync::mpsc::channel::<()>();
        let reading = Arc::new(AtomicBool::new(false));
        let collect: Collect = {
            let reading = reading.clone();
            Box::new(move || {
                reading.store(true, Ordering::SeqCst);
                let _ = gate.recv_timeout(Duration::from_secs(5));
                reading.store(false, Ordering::SeqCst);
                Ok(vec![(SOURCE.to_vec(), 7)])
            })
        };
        // Another message for the loop, sent once the read has begun.
        let (messages_tx, mut messages) = tokio::sync::mpsc::unbounded_channel::<()>();
        let sender = {
            let reading = reading.clone();
            std::thread::spawn(move || {
                let started = std::time::Instant::now();
                while !reading.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(5) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                let _ = messages_tx.send(());
            })
        };
        let mut collect = Some(collect);
        let mut timer = tokio::time::interval(TICK);
        let handled_while_reading = loop {
            tokio::select! {
                _ = timer.tick() => {
                    if let Some(collect) = collect.take() {
                        sources.sweep(&FILTER, collect, fetch.clone(), clock.clone());
                    }
                }
                Some(()) = messages.recv() => break reading.load(Ordering::SeqCst),
            }
        };
        let _ = release.send(());
        sender.join().unwrap();
        assert!(handled_while_reading, "the select loop waited for the sweep's store read");
    }

    /// A sweep still running is not started again: one fetch at a time.
    #[tokio::test(start_paused = true)]
    async fn a_running_sweep_is_not_started_again() {
        let (_directory, _db, clock) = clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = hung(calls.clone());
        let missing = vec![(SOURCE.to_vec(), 7)];
        let mut sources = DeliverySources::default();
        tick(&mut sources, &missing, &fetch, &clock).await;
        tick(&mut sources, &missing, &fetch, &clock).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a second fetch started beside the running one");
    }

    /// A fetch that never answers is abandoned at its deadline, and the frame
    /// is asked for again after the first backoff.
    #[tokio::test(start_paused = true)]
    async fn a_hung_fetch_is_abandoned_at_its_deadline() {
        let (_directory, _db, clock) = clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = hung(calls.clone());
        let missing = vec![(SOURCE.to_vec(), 7)];
        let mut sources = DeliverySources::default();
        // Ticks at 0..=60 s: the fetch from 0 s fails at 30 s, so the next
        // is due at 50 s.
        for _ in 0..7 {
            tick(&mut sources, &missing, &fetch, &clock).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A frame no archive returns is asked for again with a doubling
    /// backoff, not on every tick.
    #[tokio::test(start_paused = true)]
    async fn an_unavailable_source_is_asked_for_with_backoff() {
        let (_directory, _db, clock) = clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = source(calls.clone(), None);
        let missing = vec![(SOURCE.to_vec(), 7)];
        let mut sources = DeliverySources::default();
        // Ten minutes of ticks: asked at 0, 20, 60, 140 and 300 s.
        for _ in 0..60 {
            tick(&mut sources, &missing, &fetch, &clock).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    /// A fetched frame lands in the clock store under its own filter.
    #[tokio::test(start_paused = true)]
    async fn a_fetched_source_frame_is_stored() {
        let (_directory, _db, clock) = clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = source(calls.clone(), Some(frame(&SOURCE, 7)));
        let mut sources = DeliverySources::default();
        tick(&mut sources, &[(SOURCE.to_vec(), 7)], &fetch, &clock).await;
        let stored = clock.get_shard_clock_frame(&SOURCE, 7, false).expect("the fetched frame is stored");
        assert_eq!(stored.header.map(|header| header.frame_number), Some(7));
        // Another frame than the one asked for is not stored.
        tick(&mut sources, &[(SOURCE.to_vec(), 8)], &fetch, &clock).await;
        assert!(clock.get_shard_clock_frame(&SOURCE, 8, false).is_err());
    }

    /// A delivery that keeps waiting for a frame no archive returns is
    /// reported once, naming the frame, and its end is logged.
    #[tokio::test(start_paused = true)]
    async fn a_delivery_waiting_on_an_unobtainable_frame_is_reported() {
        let logs = CapturedLogs::default();
        let _logging = logs.install();
        let (_directory, _db, clock) = clock();
        let fetch = source(Arc::new(AtomicUsize::new(0)), None);
        let missing = vec![(SOURCE.to_vec(), 7)];
        let mut sources = DeliverySources::default();
        for _ in 0..8 {
            tick(&mut sources, &missing, &fetch, &clock).await;
        }
        let reported = logs.lines_with("no archive returned");
        assert_eq!(reported.len(), 1, "{reported:?}");
        assert!(reported[0].contains(&format!("source_filter={}", hex::encode(SOURCE))), "{}", reported[0]);
        assert!(reported[0].contains("source_frame=7"), "{}", reported[0]);
        assert!(reported[0].contains(&format!("filter={}", hex::encode(FILTER))), "{}", reported[0]);
        // The delivery no longer needs it: the next read finds that, and the
        // tick after it logs the end.
        tick(&mut sources, &[], &fetch, &clock).await;
        tick(&mut sources, &[], &fetch, &clock).await;
        assert_eq!(logs.lines_with("no longer wait").len(), 1);
    }

    /// A slow read of the pending deliveries is reported once, with its
    /// duration, and the end of the slow reads is logged.
    #[test]
    fn slow_reads_are_reported() {
        let logs = CapturedLogs::default();
        let _logging = logs.install();
        let mut slow_reads = Outage::default();
        let start = Instant::now();
        observe_read(&mut slow_reads, &FILTER, Duration::from_millis(30), start);
        observe_read(&mut slow_reads, &FILTER, Duration::from_secs(41), start + TICK);
        observe_read(&mut slow_reads, &FILTER, Duration::from_secs(38), start + 2 * TICK);
        let slow = logs.lines_with("is slow");
        assert_eq!(slow.len(), 1, "{slow:?}");
        assert!(slow[0].contains("read_secs=41"), "{}", slow[0]);
        assert!(slow[0].contains(&format!("filter={}", hex::encode(FILTER))), "{}", slow[0]);
        assert!(logs.lines_with("still slow").is_empty());
        observe_read(&mut slow_reads, &FILTER, Duration::from_millis(40), start + 3 * TICK);
        assert_eq!(logs.lines_with("fast again").len(), 1);
    }
}
