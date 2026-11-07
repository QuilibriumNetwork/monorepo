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
//! backoff that doubles up to [`MAX_RETRY`]. A source frame this node holds
//! without the operation a delivery needs is asked for again too, and a
//! fetched frame without it is not stored. A delivery that keeps waiting,
//! a read that keeps being slow or failing, are each reported as an
//! [`Outage`], and the backlog itself is logged when its shape changes.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use quil_execution::manager::DeliveryCensus;
use quil_types::{proto::global::AppShardFrame, store::ClockStore};
use tokio::{sync::mpsc, time::Instant};
use tracing::{info, warn};

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
/// A slow-read outage ends only when a read takes less than this: reads
/// hovering at [`SLOW_READ`] would otherwise end and restart it each time.
const FAST_AGAIN: Duration = Duration::from_secs(5);
/// The backlog line is logged at most this often while what waits changes.
const BACKLOG_CHANGE_EVERY: Duration = Duration::from_secs(60);
/// ... and this often while something is pending and only its count moves.
const BACKLOG_REPEAT_EVERY: Duration = Duration::from_secs(600);

/// A source frame: the executing shard's filter and its frame number.
type Source = (Vec<u8>, u64);

/// A source frame to fetch, and the operations a copy must hold to be of use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Wanted {
    pub(crate) source: Source,
    pub(crate) operations: Vec<[u8; 32]>,
}

/// Why a block's next delivery cannot be proposed yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wait {
    /// This node does not hold the source frame.
    NotHeld,
    /// This node holds a frame at the source's height without the operation.
    HeldWithoutOperation,
    /// This node's GLOBAL view lacks the committed delivery record.
    MissingRecord,
}

impl Wait {
    fn reason(self) -> &'static str {
        match self {
            Wait::NotHeld => "source frame not held",
            Wait::HeldWithoutOperation => "held source frame lacks the operation",
            Wait::MissingRecord => "delivery record missing from this node's GLOBAL view",
        }
    }

    fn ends_when(self) -> &'static str {
        match self {
            Wait::NotHeld => "an archive serves the source frame to this node",
            Wait::HeldWithoutOperation => {
                "an archive serves a copy of the source frame that holds the operation"
            }
            Wait::MissingRecord => "this node's GLOBAL sync brings the record",
        }
    }
}

/// The first block in delivery order whose next delivery waits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    pub(crate) block: u64,
    pub(crate) seq: u64,
    pub(crate) source: Option<Source>,
    pub(crate) wait: Wait,
}

/// What a [`Collect`] read: the shard's undelivered backlog, and the source
/// frames to fetch for it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Backlog {
    /// The source frames to fetch, in delivery order.
    pub(crate) wanted: Vec<Wanted>,
    /// Committed outputs and escrows not taken yet.
    pub(crate) pending: u64,
    /// Owned blocks read.
    pub(crate) blocks: usize,
    /// Blocks with something pending.
    pub(crate) blocks_pending: usize,
    /// Items listed this read.
    pub(crate) listed: usize,
    /// Whether the per-frame cap left items unlisted.
    pub(crate) capped: bool,
    /// Blocks whose next delivery waits.
    pub(crate) waiting: usize,
    /// Committed items whose delivery record this GLOBAL view lacks.
    pub(crate) missing_records: usize,
    pub(crate) head: Option<Head>,
}

/// A backlog line's shape: anything pending, waiting count, capped,
/// missing records and the head's (block, seq, wait).
type BacklogShape = (bool, usize, bool, usize, Option<(u64, u64, Wait)>);

impl Backlog {
    /// The backlog `census` shows, given what this node holds: `held(filter,
    /// frame number)` is the canonical frame this node stores there. `own` is
    /// the shard's filter: its own frames are never asked for again.
    pub(crate) fn of(
        own: &[u8],
        census: &DeliveryCensus,
        held: impl Fn(&[u8], u64) -> Option<AppShardFrame>,
    ) -> Self {
        let mut backlog = Backlog {
            pending: census.pending,
            blocks: census.blocks,
            blocks_pending: census.blocks_pending,
            listed: census.items.len(),
            capped: census.capped,
            missing_records: census.missing_records.len(),
            ..Backlog::default()
        };
        // The operation ids of each source frame this node holds.
        let mut frames: HashMap<Source, Option<HashSet<[u8; 32]>>> = HashMap::new();
        let mut waiting = BTreeSet::new();
        for item in &census.items {
            let operations = frames.entry(item.source.clone()).or_insert_with(|| {
                held(&item.source.0, item.source.1).map(|frame| operation_ids(&frame))
            });
            let wait = match operations {
                None => Wait::NotHeld,
                Some(ids) if !ids.contains(&item.tx_id) => Wait::HeldWithoutOperation,
                Some(_) => continue,
            };
            if waiting.insert((item.escrow, item.block)) && backlog.head.is_none() {
                backlog.head = Some(Head {
                    block: item.block,
                    seq: item.seq,
                    source: Some(item.source.clone()),
                    wait,
                });
            }
            // A frame of this shard's own chain is never replaced.
            if wait == Wait::HeldWithoutOperation && item.source.0 == own {
                continue;
            }
            match backlog
                .wanted
                .iter_mut()
                .find(|wanted| wanted.source == item.source)
            {
                Some(wanted) => wanted.operations.push(item.tx_id),
                None => backlog.wanted.push(Wanted {
                    source: item.source.clone(),
                    operations: vec![item.tx_id],
                }),
            }
        }
        if backlog.head.is_none() {
            if let Some((block, seq)) = census.missing_records.first() {
                backlog.head = Some(Head {
                    block: *block,
                    seq: *seq,
                    source: None,
                    wait: Wait::MissingRecord,
                });
            }
        }
        backlog.waiting = waiting.len() + census.missing_records.len();
        backlog
    }

    fn sources(&self) -> Vec<Source> {
        self.wanted
            .iter()
            .map(|wanted| wanted.source.clone())
            .collect()
    }

    /// What the backlog line reports, without the counts that move with
    /// every delivery.
    fn shape(&self) -> BacklogShape {
        (
            self.pending > 0,
            self.waiting,
            self.capped,
            self.missing_records,
            self.head
                .as_ref()
                .map(|head| (head.block, head.seq, head.wait)),
        )
    }
}

/// The ids of the token operations `frame` holds.
fn operation_ids(frame: &AppShardFrame) -> HashSet<[u8; 32]> {
    frame
        .requests
        .iter()
        .flat_map(|bundle| bundle.requests.iter())
        .filter_map(|request| match request.request.as_ref()? {
            quil_types::proto::global::message_request::Request::TokenOperation(op)
                if op.canonical_bytes.len() >= 4 =>
            {
                Some(quil_execution::token_intrinsic::global_commit_tx_id(
                    &op.canonical_bytes,
                ))
            }
            _ => None,
        })
        .collect()
}

/// The token operation `tx_id` in `frame`: its type prefix and bytes.
pub(crate) fn frame_operation(frame: &AppShardFrame, tx_id: &[u8; 32]) -> Option<(u32, Vec<u8>)> {
    frame
        .requests
        .iter()
        .flat_map(|bundle| bundle.requests.iter())
        .find_map(|request| match request.request.as_ref()? {
            quil_types::proto::global::message_request::Request::TokenOperation(op)
                if op.canonical_bytes.len() >= 4
                    && quil_execution::token_intrinsic::global_commit_tx_id(
                        &op.canonical_bytes,
                    ) == *tx_id =>
            {
                Some((
                    u32::from_be_bytes(op.canonical_bytes[..4].try_into().ok()?),
                    op.canonical_bytes.clone(),
                ))
            }
            _ => None,
        })
}

/// Reads, from the store, the shard's pending deliveries and the source
/// frames they need that this node does not hold. It blocks, so a sweep runs
/// it on a blocking thread; it does not log, since a worker's log lines are
/// routed by the thread that writes them.
pub(crate) type Collect = Box<dyn FnOnce() -> Result<Backlog, String> + Send>;

/// What one sweep's read found, sent back to the select loop.
struct Collected {
    /// The backlog, or why it could not be read.
    backlog: Result<Backlog, String>,
    read: Read,
}

/// How long one read took, and what for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Read {
    /// From the sweep's start to the end of the read.
    total: Duration,
    /// Waiting for a blocking thread to run it.
    queued: Duration,
    /// Waiting for a store commit lock (the worker's or the GLOBAL view's
    /// the read also reads) while another local task
    /// (a commit, a sync, retention pruning) held it.
    lock_wait: Duration,
    pending: usize,
    blocks: usize,
}

impl Read {
    /// Whether the read mostly waited for the store's commit lock.
    fn lock_bound(&self) -> bool {
        self.lock_wait * 2 >= self.total
    }
}

/// A source frame whose fetch failed.
struct Waiting {
    since: Instant,
    failures: u32,
    retry_at: Instant,
    /// Why the latest fetch failed.
    failure: &'static str,
}

type Unobtained = Arc<Mutex<HashMap<Source, Waiting>>>;

/// Why a fetched frame was not stored.
enum Unstored {
    /// The frame is another than the one asked for.
    NotRequested,
    /// The frame lacks an operation it was fetched for.
    LacksOperation,
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
    failed_reads: Outage,
    /// The latest backlog line's shape and time.
    logged: Option<(BacklogShape, Instant)>,
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
            failed_reads: Outage::begin_after(REPORT_AFTER_SWEEPS),
            logged: None,
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
    /// sweep: `collect` reads the shard's pending deliveries and the source
    /// frames this node lacks, and the due ones are fetched into
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
            observe_read(&mut self.slow_reads, filter, &collected.read, now);
            observe_failed_read(
                &mut self.failed_reads,
                filter,
                collected.backlog.as_ref().err(),
                now,
            );
            if let Ok(backlog) = collected.backlog {
                self.log_backlog(filter, &backlog, now);
                self.missing = Some(backlog.sources());
            }
        }
        if let Some(missing) = self.missing.as_ref() {
            let unobtained = self
                .unobtained
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            report(&mut self.outage, filter, missing, &unobtained, now);
        }
        if self
            .sweep
            .as_ref()
            .is_some_and(|sweep| !sweep.is_finished())
        {
            return;
        }
        self.sweep = Some(tokio::spawn(quil_types::thread_probe::probed(
            quil_types::thread_probe::Section::DeliverySweep,
            run_sweep(
                collect,
                fetch,
                clock_store,
                self.unobtained.clone(),
                self.collected_tx.clone(),
            ),
        )));
    }

    /// Log the shard's delivery backlog: when what waits changes (at most
    /// every [`BACKLOG_CHANGE_EVERY`]), every [`BACKLOG_REPEAT_EVERY`] while
    /// anything is pending, and once when nothing is.
    fn log_backlog(&mut self, filter: &[u8], backlog: &Backlog, now: Instant) {
        let shape = backlog.shape();
        let due = match &self.logged {
            None => backlog.pending > 0,
            Some((logged, at)) => {
                let since = now.duration_since(*at);
                if backlog.pending == 0 {
                    logged.0
                } else if *logged != shape {
                    since >= BACKLOG_CHANGE_EVERY
                } else {
                    since >= BACKLOG_REPEAT_EVERY
                }
            }
        };
        if !due {
            return;
        }
        self.logged = Some((shape, now));
        let filter = hex::encode(filter);
        if backlog.pending == 0 {
            info!(filter = %filter, "this shard has no committed outputs left to deliver");
            return;
        }
        let (head_block, head_seq, head_source_filter, head_source_frame, wait, ends_when) =
            match &backlog.head {
                Some(head) => (
                    head.block,
                    head.seq,
                    head.source
                        .as_ref()
                        .map(|source| hex::encode(&source.0))
                        .unwrap_or_default(),
                    head.source.as_ref().map_or(0, |source| source.1),
                    head.wait.reason(),
                    head.wait.ends_when(),
                ),
                None => (
                    0,
                    0,
                    String::new(),
                    0,
                    "none",
                    "the shard's leaders propose them in the next frames",
                ),
            };
        info!(
            filter = %filter, pending = backlog.pending, blocks_pending = backlog.blocks_pending,
            listed = backlog.listed, capped = backlog.capped, waiting_blocks = backlog.waiting,
            missing_records = backlog.missing_records, fetching = backlog.wanted.len(), head_block,
            head_seq, head_source_filter = %head_source_filter, head_source_frame, wait, ends_when,
            "this shard has committed outputs to deliver"
        );
    }
}

/// Log the start, bounded repeats and end of a wait for a source frame that
/// could not be obtained. The first such frame in delivery order holds up
/// the later deliveries of its block, so the line names it.
fn report(
    outage: &mut Outage,
    filter: &[u8],
    missing: &[Source],
    unobtained: &HashMap<Source, Waiting>,
    now: Instant,
) {
    let first = missing
        .iter()
        .find_map(|source| unobtained.get(source).map(|waiting| (source, waiting)));
    let event = outage.observe(now.into_std(), first.is_none());
    let filter = hex::encode(filter);
    match (event, first) {
        (Some(OutageEvent::Began), Some(((source_filter, source_frame), waiting))) => warn!(
            filter = %filter, source_filter = %hex::encode(source_filter), source_frame,
            waiting_sources = unobtained.len(), failures = waiting.failures, last_failure = waiting.failure,
            waited_secs = now.duration_since(waiting.since).as_secs(), scope = "network", action = "report",
            "this shard's deliveries wait for another shard's frame that no archive returned; the outputs \
             executed in it, and the later deliveries of their blocks, are not proposed until an archive \
             serves it; report this line if it persists"),
        (
            Some(OutageEvent::Continues { secs, .. }),
            Some(((source_filter, source_frame), waiting)),
        ) => warn!(
            filter = %filter, source_filter = %hex::encode(source_filter), source_frame,
            waiting_sources = unobtained.len(), failures = waiting.failures,
            last_failure = waiting.failure, secs, scope = "network", action = "report",
            "this shard's deliveries still wait for another shard's frame that no archive returned"),
        (Some(OutageEvent::Ended { secs, .. }), _) => info!(filter = %filter, secs,
            "this shard's deliveries no longer wait for another shard's frame"),
        _ => {}
    }
}

/// Log the start, bounded repeats and end of slow reads of the shard
/// `filter`'s pending deliveries; `read` is the latest one. A read that
/// mostly waited for a store commit lock names that, since
/// another local task held it; one that did not is the store's.
fn observe_read(slow_reads: &mut Outage, filter: &[u8], read: &Read, now: Instant) {
    let read_secs = read.total.as_secs();
    let lock_wait_ms = read.lock_wait.as_millis() as u64;
    let queued_ms = read.queued.as_millis() as u64;
    let (pending, blocks_scanned) = (read.pending, read.blocks);
    let (waited_on, action) = if read.lock_bound() {
        ("commit_lock", "check")
    } else {
        ("store", "report")
    };
    // Hysteresis: a read under SLOW_READ is fast again only once the outage
    // has ended below FAST_AGAIN; between the two it stays slow.
    let fast = read.total
        < if slow_reads.is_active() {
            FAST_AGAIN
        } else {
            SLOW_READ
        };
    match (slow_reads.observe(now.into_std(), fast), read.lock_bound()) {
        (Some(OutageEvent::Began), true) => warn!(
            filter = %hex::encode(filter), read_secs, lock_wait_ms, queued_ms, pending, blocks_scanned,
            waited_on, scope = "local", action,
            "reading this shard's pending deliveries is slow: it waited for a store commit lock (this worker's \
             or the GLOBAL view's), which another local task held (a commit, a sync or retention pruning); the \
             engine goes on, but \
             fetching their source frames waits for the read; if it persists, check this node's logs for \
             a retained-version pruning lock-hold warning at the same time"),
        (Some(OutageEvent::Began), false) => warn!(
            filter = %hex::encode(filter), read_secs, lock_wait_ms, queued_ms, pending, blocks_scanned,
            waited_on, scope = "local", action,
            "reading this shard's pending deliveries from the store is slow; the engine goes on, but \
             fetching their source frames waits for the read; report this line if it persists"),
        (Some(OutageEvent::Continues { secs, failures }), _) => warn!(
            filter = %hex::encode(filter), read_secs, lock_wait_ms, queued_ms, pending, blocks_scanned, secs,
            slow_reads = failures, waited_on, scope = "local", action,
            "reading this shard's pending deliveries is still slow"),
        (Some(OutageEvent::Ended { secs, failures }), _) => info!(
            filter = %hex::encode(filter), read_ms = read.total.as_millis() as u64, lock_wait_ms, pending,
            blocks_scanned, secs, slow_reads = failures,
            "reading this shard's pending deliveries from the store is fast again"),
        (None, _) => {}
    }
}

/// Log the start, bounded repeats and end of failing reads of the shard
/// `filter`'s pending deliveries: while they fail, nothing is fetched for
/// them; `error` is the latest read's failure, if it failed.
fn observe_failed_read(failed: &mut Outage, filter: &[u8], error: Option<&String>, now: Instant) {
    match failed.observe(now.into_std(), error.is_none()) {
        Some(OutageEvent::Began) => warn!(
            filter = %hex::encode(filter), error = error.map(String::as_str).unwrap_or_default(),
            scope = "local", action = "report",
            "reading this shard's pending deliveries fails; their source frames are not fetched and \
             the outputs committed to this shard wait; report this line if it persists"),
        Some(OutageEvent::Continues { secs, failures }) => warn!(
            filter = %hex::encode(filter), error = error.map(String::as_str).unwrap_or_default(),
            secs, failed_reads = failures, scope = "local", action = "report",
            "reading this shard's pending deliveries still fails"),
        Some(OutageEvent::Ended { secs, failures }) => info!(
            filter = %hex::encode(filter), secs, failed_reads = failures,
            "reading this shard's pending deliveries works again"),
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
    let (backlog, began, lock_wait) = tokio::task::spawn_blocking(move || {
        let began = std::time::Instant::now();
        let waited = quil_hypergraph::commit_lock_wait_on_this_thread();
        let backlog = collect();
        let lock_wait = quil_hypergraph::commit_lock_wait_on_this_thread().saturating_sub(waited);
        (backlog, Some(began), lock_wait)
    })
    .await
    .unwrap_or_else(|error| {
        (
            Err(format!("the read did not finish: {error}")),
            None,
            Duration::ZERO,
        )
    });
    let (pending, blocks) = backlog
        .as_ref()
        .map_or((0, 0), |backlog| (backlog.listed, backlog.blocks));
    let read = Read {
        total: started.elapsed(),
        queued: began.map_or(Duration::ZERO, |began| {
            began.saturating_duration_since(started.into_std())
        }),
        lock_wait,
        pending,
        blocks,
    };
    let due: Vec<Wanted> = match &backlog {
        Ok(backlog) => {
            let now = Instant::now();
            let mut unobtained = unobtained
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // A source no longer missing was delivered or obtained.
            unobtained
                .retain(|source, _| backlog.wanted.iter().any(|wanted| wanted.source == *source));
            backlog
                .wanted
                .iter()
                .filter(|wanted| {
                    unobtained
                        .get(&wanted.source)
                        .is_none_or(|waiting| waiting.retry_at <= now)
                })
                .cloned()
                .collect()
        }
        Err(_) => Vec::new(),
    };
    let _ = collected.send(Collected { backlog, read });
    fetch_due(due, fetch, clock_store, unobtained).await;
}

/// Fetch `due` in order, each within [`FETCH_DEADLINE`], storing what
/// arrives holding the operations it was fetched for (on a blocking thread)
/// and scheduling the retry of what does not.
async fn fetch_due(
    due: Vec<Wanted>,
    fetch: DeliveryFrameSource,
    clock_store: Arc<dyn ClockStore>,
    unobtained: Unobtained,
) {
    for Wanted {
        source: (filter, frame_number),
        operations,
    } in due
    {
        let fetched = tokio::time::timeout(FETCH_DEADLINE, fetch(filter.clone(), frame_number))
            .await
            .ok()
            .flatten();
        let outcome = match fetched {
            Some(frame) => {
                let (clock_store, source_filter) = (clock_store.clone(), filter.clone());
                let stored = tokio::task::spawn_blocking(move || {
                    store(
                        clock_store.as_ref(),
                        &source_filter,
                        frame_number,
                        &operations,
                        &frame,
                    )
                })
                .await
                .unwrap_or(Err(Unstored::Failed));
                match stored {
                    Ok(()) => Ok(()),
                    Err(Unstored::NotRequested) => {
                        warn!(
                            filter = hex::encode(&filter),
                            frame = frame_number,
                            "delivery source frame is not the one requested"
                        );
                        Err("an archive returned another frame")
                    }
                    Err(Unstored::LacksOperation) => {
                        Err("an archive returned the frame without the operation")
                    }
                    Err(Unstored::Failed) => {
                        warn!(
                            filter = hex::encode(&filter),
                            frame = frame_number,
                            "storing a delivery's source frame failed"
                        );
                        Err("storing it failed")
                    }
                }
            }
            None => Err("no archive returned it in time"),
        };
        let now = Instant::now();
        let mut unobtained = unobtained
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let source = (filter, frame_number);
        match outcome {
            Ok(()) => {
                let earlier = unobtained.remove(&source);
                info!(
                    filter = hex::encode(&source.0),
                    frame = frame_number,
                    failures = earlier.as_ref().map_or(0, |waiting| waiting.failures),
                    waited_secs =
                        earlier.map_or(0, |waiting| now.duration_since(waiting.since).as_secs()),
                    "fetched a delivery's source frame"
                );
            }
            Err(failure) => {
                let waiting = unobtained.entry(source).or_insert(Waiting {
                    since: now,
                    failures: 0,
                    retry_at: now,
                    failure,
                });
                waiting.failures += 1;
                waiting.failure = failure;
                waiting.retry_at = now + retry_after(waiting.failures);
            }
        }
    }
}

/// The wait after the `failures`-th failed fetch of one source frame.
fn retry_after(failures: u32) -> Duration {
    FIRST_RETRY
        .saturating_mul(1 << failures.saturating_sub(1).min(16))
        .min(MAX_RETRY)
}

/// Store `frame`, fetched as frame `frame_number` of `filter` for
/// `operations`, unless it is another frame, lacks one of them, or the store
/// fails. Blocks; does not log.
fn store(
    clock_store: &dyn ClockStore,
    filter: &[u8],
    frame_number: u64,
    operations: &[[u8; 32]],
    frame: &AppShardFrame,
) -> Result<(), Unstored> {
    let Some(header) = frame.header.as_ref() else {
        return Err(Unstored::NotRequested);
    };
    if header.address != filter || header.frame_number != frame_number {
        return Err(Unstored::NotRequested);
    }
    let held = operation_ids(frame);
    if !operations.iter().all(|operation| held.contains(operation)) {
        return Err(Unstored::LacksOperation);
    }
    let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
        .map(|hash| hash.to_vec())
        .unwrap_or_default();
    clock_store
        .new_transaction(false)
        .ok()
        .and_then(|txn| {
            clock_store
                .stage_shard_clock_frame(&selector, frame, txn.as_ref())
                .ok()?;
            txn.commit().ok()?;
            let txn = clock_store.new_transaction(false).ok()?;
            clock_store
                .commit_shard_clock_frame(filter, frame_number, &selector, txn.as_ref(), true)
                .ok()?;
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

    /// A backlog wanting `missing`, for frames holding any operations.
    fn wanting(missing: Vec<Source>) -> Backlog {
        Backlog {
            wanted: missing
                .into_iter()
                .map(|source| Wanted {
                    source,
                    operations: Vec::new(),
                })
                .collect(),
            ..Backlog::default()
        }
    }

    /// `frame(filter, frame_number)` holding the token operations `operations`.
    fn frame_with(filter: &[u8], frame_number: u64, operations: &[&[u8]]) -> AppShardFrame {
        use quil_types::proto::global::{message_request::Request, MessageBundle, MessageRequest};
        AppShardFrame {
            requests: operations
                .iter()
                .map(|bytes| MessageBundle {
                    requests: vec![MessageRequest {
                        timestamp: 0,
                        request: Some(Request::TokenOperation(
                            quil_types::proto::token::TokenOperation {
                                canonical_bytes: bytes.to_vec(),
                            },
                        )),
                    }],
                    timestamp: 0,
                })
                .collect(),
            ..frame(filter, frame_number)
        }
    }

    const OPERATION: &[u8] = &[0, 0, 5, 18, 1, 2, 3];
    const OTHER_OPERATION: &[u8] = &[0, 0, 5, 18, 9, 9, 9];

    fn item(source: Source, block: u64, seq: u64, operation: &[u8]) -> DeliveryItem {
        DeliveryItem {
            source,
            tx_id: quil_execution::token_intrinsic::global_commit_tx_id(operation),
            block,
            seq,
            escrow: false,
        }
    }

    use quil_execution::manager::DeliveryItem;

    /// A source frame this node holds without the operation a delivery needs
    /// (before this fix its block's outputs waited for good, and nothing was
    /// fetched or logged) is asked for again, and names the block's wait; a
    /// held frame with it needs nothing; one of the shard's own chain is never
    /// replaced.
    #[test]
    fn a_held_frame_without_the_operation_is_fetched_again() {
        let census = DeliveryCensus {
            items: vec![
                item((SOURCE.to_vec(), 7), 300, 4, OPERATION),
                item((SOURCE.to_vec(), 8), 301, 0, OPERATION),
                item((FILTER.to_vec(), 9), 302, 0, OPERATION),
            ],
            pending: 3,
            blocks_pending: 3,
            ..DeliveryCensus::default()
        };
        let held = |filter: &[u8], number: u64| match number {
            7 => Some(frame_with(filter, number, &[OTHER_OPERATION])),
            8 => Some(frame_with(filter, number, &[OPERATION])),
            9 => Some(frame_with(filter, number, &[])),
            _ => None,
        };
        let backlog = Backlog::of(&FILTER, &census, held);
        assert_eq!(
            backlog.wanted,
            vec![Wanted {
                source: (SOURCE.to_vec(), 7),
                operations: vec![quil_execution::token_intrinsic::global_commit_tx_id(
                    OPERATION
                )],
            }],
            "the held copy without the operation is not fetched again: block 300's outputs stay \
             stranded"
        );
        assert_eq!(backlog.waiting, 2, "{backlog:?}");
        assert_eq!(
            backlog.head,
            Some(Head {
                block: 300,
                seq: 4,
                source: Some((SOURCE.to_vec(), 7)),
                wait: Wait::HeldWithoutOperation,
            })
        );
        // A frame not held is wanted, as before.
        let backlog = Backlog::of(&FILTER, &census, |_: &[u8], _| None);
        assert_eq!(backlog.wanted.len(), 3, "{backlog:?}");
        assert_eq!(backlog.head.map(|head| head.wait), Some(Wait::NotHeld));
    }

    /// A fetched copy without the operation it was fetched for is not stored,
    /// and is asked for again after the backoff; a copy with it is stored.
    #[tokio::test(start_paused = true)]
    async fn a_fetched_frame_without_the_operation_is_not_stored() {
        let (_directory, _db, clock) = clock();
        let wanted = Backlog {
            wanted: vec![Wanted {
                source: (SOURCE.to_vec(), 7),
                operations: vec![quil_execution::token_intrinsic::global_commit_tx_id(
                    OPERATION,
                )],
            }],
            ..Backlog::default()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let bodiless = source(calls.clone(), Some(frame(&SOURCE, 7)));
        let mut sources = DeliverySources::default();
        for _ in 0..3 {
            let wanted = wanted.clone();
            sources.sweep(
                &FILTER,
                Box::new(move || Ok(wanted)),
                bodiless.clone(),
                clock.clone(),
            );
            tokio::time::sleep(TICK).await;
        }
        assert!(
            clock.get_shard_clock_frame(&SOURCE, 7, false).is_err(),
            "a copy without the operation was stored as the source frame"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "asked again after 20 s");
        let full = source(
            Arc::new(AtomicUsize::new(0)),
            Some(frame_with(&SOURCE, 7, &[OPERATION])),
        );
        let mut sources = DeliverySources::default();
        for _ in 0..3 {
            let wanted = wanted.clone();
            sources.sweep(
                &FILTER,
                Box::new(move || Ok(wanted)),
                full.clone(),
                clock.clone(),
            );
            tokio::time::sleep(TICK).await;
        }
        let stored = clock.get_shard_clock_frame(&SOURCE, 7, false).unwrap();
        assert_eq!(operation_ids(&stored).len(), 1);
    }

    /// The backlog is logged at info when it appears, not again while only
    /// its count moves, when what waits changes (at most once a minute), every
    /// ten minutes while it persists, and once when it clears.
    #[test]
    fn the_backlog_is_logged_on_changes_and_bounded() {
        let logs = CapturedLogs::default();
        let _logging = logs.install();
        let mut sources = DeliverySources::default();
        let start = Instant::now();
        let waiting_on = |block: u64, pending: u64| Backlog {
            pending,
            blocks_pending: 2,
            listed: 2,
            waiting: 1,
            head: Some(Head {
                block,
                seq: 4,
                source: Some((SOURCE.to_vec(), 7)),
                wait: Wait::NotHeld,
            }),
            ..Backlog::default()
        };
        sources.log_backlog(&FILTER, &Backlog::default(), start);
        assert!(logs.lines_with("committed outputs").is_empty());
        sources.log_backlog(&FILTER, &waiting_on(300, 5), start + TICK);
        let lines = logs.lines_with("committed outputs to deliver");
        assert_eq!(lines.len(), 1, "{lines:?}");
        for field in [
            "pending=5",
            "head_block=300",
            "head_seq=4",
            "head_source_frame=7",
            &format!("head_source_filter={}", hex::encode(SOURCE)),
            "wait=\"source frame not held\"",
            "ends_when=",
        ] {
            assert!(lines[0].contains(field), "{field}: {}", lines[0]);
        }
        // Each tick for ten minutes, the count moving, then another block.
        for tick in 2..62 {
            sources.log_backlog(
                &FILTER,
                &waiting_on(300, u64::from(tick % 4 + 1)),
                start + TICK * tick,
            );
        }
        assert_eq!(logs.lines_with("committed outputs to deliver").len(), 2);
        // Logged at 610 s; another block waits 10 s later: held back for a
        // minute, then logged; a third change 10 s after that is held back.
        sources.log_backlog(&FILTER, &waiting_on(301, 3), start + TICK * 62);
        assert_eq!(logs.lines_with("committed outputs to deliver").len(), 2);
        sources.log_backlog(
            &FILTER,
            &waiting_on(301, 3),
            start + TICK * 61 + BACKLOG_CHANGE_EVERY,
        );
        sources.log_backlog(
            &FILTER,
            &waiting_on(302, 3),
            start + TICK * 62 + BACKLOG_CHANGE_EVERY,
        );
        let lines = logs.lines_with("committed outputs to deliver");
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[2].contains("head_block=301"), "{}", lines[2]);
        sources.log_backlog(&FILTER, &Backlog::default(), start + TICK * 80);
        sources.log_backlog(&FILTER, &Backlog::default(), start + TICK * 81);
        assert_eq!(logs.lines_with("no committed outputs left").len(), 1);
    }

    /// Failing reads of the pending deliveries, which stop every fetch for
    /// the shard, are reported after about a minute, with the error, and their
    /// end is logged.
    #[test]
    fn failing_reads_are_reported() {
        let logs = CapturedLogs::default();
        let _logging = logs.install();
        let mut failed = Outage::begin_after(REPORT_AFTER_SWEEPS);
        let start = Instant::now();
        let error = "coin root: invalid history record".to_string();
        for tick in 0..7 {
            observe_failed_read(&mut failed, &FILTER, Some(&error), start + TICK * tick);
        }
        let lines = logs.lines_with("pending deliveries fails");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("invalid history record"), "{}", lines[0]);
        observe_failed_read(&mut failed, &FILTER, None, start + TICK * 8);
        assert_eq!(logs.lines_with("works again").len(), 1);
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
        sources.sweep(
            &FILTER,
            Box::new(move || Ok(wanting(missing))),
            fetch.clone(),
            clock.clone(),
        );
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
                Ok(wanting(vec![(SOURCE.to_vec(), 7)]))
            })
        };
        // Another message for the loop, sent once the read has begun.
        let (messages_tx, mut messages) = tokio::sync::mpsc::unbounded_channel::<()>();
        let sender = {
            let reading = reading.clone();
            std::thread::spawn(move || {
                let started = std::time::Instant::now();
                while !reading.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(5)
                {
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
        assert!(
            handled_while_reading,
            "the select loop waited for the sweep's store read"
        );
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
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a second fetch started beside the running one"
        );
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
        let stored = clock
            .get_shard_clock_frame(&SOURCE, 7, false)
            .expect("the fetched frame is stored");
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
        assert!(
            reported[0].contains(&format!("source_filter={}", hex::encode(SOURCE))),
            "{}",
            reported[0]
        );
        assert!(reported[0].contains("source_frame=7"), "{}", reported[0]);
        assert!(
            reported[0].contains(&format!("filter={}", hex::encode(FILTER))),
            "{}",
            reported[0]
        );
        // The delivery no longer needs it: the next read finds that, and the
        // tick after it logs the end.
        tick(&mut sources, &[], &fetch, &clock).await;
        tick(&mut sources, &[], &fetch, &clock).await;
        assert_eq!(logs.lines_with("no longer wait").len(), 1);
    }

    fn took(total: Duration) -> Read {
        Read {
            total,
            ..Read::default()
        }
    }

    /// A slow read of the pending deliveries is reported once, with its
    /// duration, and the end of the slow reads is logged.
    #[test]
    fn slow_reads_are_reported() {
        let logs = CapturedLogs::default();
        let _logging = logs.install();
        let mut slow_reads = Outage::default();
        let start = Instant::now();
        observe_read(
            &mut slow_reads,
            &FILTER,
            &took(Duration::from_millis(30)),
            start,
        );
        observe_read(
            &mut slow_reads,
            &FILTER,
            &took(Duration::from_secs(41)),
            start + TICK,
        );
        observe_read(
            &mut slow_reads,
            &FILTER,
            &took(Duration::from_secs(38)),
            start + 2 * TICK,
        );
        let slow = logs.lines_with("is slow");
        assert_eq!(slow.len(), 1, "{slow:?}");
        assert!(slow[0].contains("read_secs=41"), "{}", slow[0]);
        assert!(slow[0].contains("waited_on=\"store\""), "{}", slow[0]);
        assert!(slow[0].contains("report this line"), "{}", slow[0]);
        assert!(
            slow[0].contains(&format!("filter={}", hex::encode(FILTER))),
            "{}",
            slow[0]
        );
        assert!(logs.lines_with("still slow").is_empty());
        observe_read(
            &mut slow_reads,
            &FILTER,
            &took(Duration::from_millis(40)),
            start + 3 * TICK,
        );
        assert_eq!(logs.lines_with("fast again").len(), 1);
    }

    /// Reads hovering at the threshold (9.6 s and 10.4 s alternately) are one
    /// outage: it starts once, and ends only on a read under half the
    /// threshold.
    #[test]
    fn reads_hovering_at_the_threshold_log_one_start() {
        let logs = CapturedLogs::default();
        let _logging = logs.install();
        let mut slow_reads = Outage::default();
        let start = Instant::now();
        for i in 0..10u32 {
            let ms = if i % 2 == 0 { 10_400 } else { 9_600 };
            observe_read(
                &mut slow_reads,
                &FILTER,
                &took(Duration::from_millis(ms)),
                start + i * TICK,
            );
        }
        assert_eq!(logs.lines_with("is slow").len(), 1);
        assert!(logs.lines_with("fast again").is_empty());
        observe_read(
            &mut slow_reads,
            &FILTER,
            &took(Duration::from_millis(4_900)),
            start + 10 * TICK,
        );
        assert_eq!(logs.lines_with("fast again").len(), 1);
        observe_read(
            &mut slow_reads,
            &FILTER,
            &took(Duration::from_millis(10_400)),
            start + 11 * TICK,
        );
        assert_eq!(logs.lines_with("is slow").len(), 2);
    }

    /// A slow read that mostly waited for the store's commit lock says so,
    /// with the wait and the read's scale, and asks for no report: another
    /// local task held the lock.
    #[test]
    fn a_slow_read_waiting_on_the_commit_lock_names_the_lock() {
        let logs = CapturedLogs::default();
        let _logging = logs.install();
        let mut slow_reads = Outage::default();
        let start = Instant::now();
        let read = Read {
            total: Duration::from_secs(12),
            queued: Duration::from_millis(3),
            lock_wait: Duration::from_millis(11_400),
            pending: 17,
            blocks: 64,
        };
        observe_read(&mut slow_reads, &FILTER, &read, start);
        let slow = logs.lines_with("is slow");
        assert_eq!(slow.len(), 1, "{slow:?}");
        for field in [
            "lock_wait_ms=11400",
            "queued_ms=3",
            "pending=17",
            "blocks_scanned=64",
            "waited_on=\"commit_lock\"",
            "commit lock",
        ] {
            assert!(slow[0].contains(field), "{field}: {}", slow[0]);
        }
        assert!(!slow[0].contains("report this line"), "{}", slow[0]);
        assert!(slow[0].contains("action=\"check\""), "{}", slow[0]);
        observe_read(&mut slow_reads, &FILTER, &read, start + 61 * TICK);
        let still = logs.lines_with("still slow");
        assert_eq!(still.len(), 1, "{still:?}");
        assert!(still[0].contains("action=\"check\""), "{}", still[0]);
    }
}
