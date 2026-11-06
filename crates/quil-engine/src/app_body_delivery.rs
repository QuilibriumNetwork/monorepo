//! What an operator needs to tell why finalized app frames wait on a worker.
//!
//! A frame body goes out once by gossip. A worker that misses it holds back
//! later finalizations until the body arrives or archive replay passes the
//! frame, and its seat signs little meanwhile. One such wait is ordinary: this
//! module counts them, per shard, into one bounded summary line that separates
//! a thin mesh, loss on the link and one silent sender, and warns only when
//! they take a real share of the worker's time.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

/// One summary line per shard per this interval: at most 12 per shard per hour.
const SUMMARY_EVERY: Duration = Duration::from_secs(300);
/// How often the running engine's mesh size is read from the p2p layer.
const MESH_SAMPLE_EVERY: Duration = Duration::from_secs(60);
/// The window of [`BodyDelivery::share_signal`].
const SHARE_WINDOW: Duration = Duration::from_secs(3600);
/// 1% of [`SHARE_WINDOW`].
const SHARE_WARN: Duration = Duration::from_secs(36);
/// How often the warning repeats while the share stays high.
const SHARE_REPEAT: Duration = Duration::from_secs(1800);
/// A stall starting this soon after a consensus host starts is its catch-up,
/// which brings most stalls on a healthy node: it takes no part in the share.
const HOST_START_GRACE: Duration = Duration::from_secs(1800);

const LINK_ACTION: &str = "frame bodies are not reaching this worker: check that this node's line \
    can carry its shard traffic and that its p2p port is forwarded, or run fewer workers; \
    'app shard body delivery summary' lines tell a thin mesh (mesh_peers under 3) from loss on \
    the link (mesh_peers 6 or more with body_never high) and from one sender (top_leader_missing \
    dominant)";
const DISK_ACTION: &str = "this worker refuses proposals mostly for other reasons than a missing \
    body, so it applies frames late: check this node's disk (fsync latency, free space) and CPU; \
    'refused' in 'this worker refused some proposals' lines names the reasons";

#[derive(Default)]
struct Inner {
    since: Option<Instant>,
    finalized: u64,
    body_late: u64,
    body_never: u64,
    block_bytes_in: u64,
    missing_by_leader: BTreeMap<u32, u64>,
    host_started: Option<Instant>,
    /// The noted stall still open, by when it began.
    open: Option<Instant>,
    /// Noted stalls ended within [`SHARE_WINDOW`], oldest first.
    closed: VecDeque<(Instant, Instant)>,
    warned: Option<Instant>,
}

impl Inner {
    /// Stalled time within the window ending `now`, and how many stalls.
    fn stalled(&mut self, now: Instant) -> (Duration, usize) {
        let start = now.checked_sub(SHARE_WINDOW);
        while self
            .closed
            .front()
            .is_some_and(|(_, end)| start.is_some_and(|start| *end <= start))
        {
            self.closed.pop_front();
        }
        let within = |from: Instant, to: Instant| {
            let from = start.map_or(from, |start| from.max(start));
            to.saturating_duration_since(from)
        };
        let mut stalled = self
            .closed
            .iter()
            .map(|(from, to)| within(*from, *to))
            .sum::<Duration>();
        if let Some(open) = self.open {
            stalled += within(open, now);
        }
        (
            stalled,
            self.closed.len() + usize::from(self.open.is_some()),
        )
    }
}

/// One shard interval's counts; see [`log_summary`].
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct BodySummary {
    pub secs: u64,
    pub finalized: u64,
    pub body_late: u64,
    pub body_never: u64,
    pub top_leader: Option<(u32, u64)>,
    pub block_bytes_in: u64,
}

impl BodySummary {
    fn is_quiet(&self) -> bool {
        self.finalized == 0 && self.block_bytes_in == 0 && self.body_never == 0
    }
}

/// What [`BodyDelivery::share_signal`] tells the operator.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ShareSignal {
    /// Stalled time reached the share.
    High { stalled: Duration, stalls: usize },
    /// A warned share fell back below it.
    Ended { stalled: Duration },
}

/// A worker's body delivery counts. Consensus hosts come and go with their
/// sessions; this stays with the engine, so the hour spans them.
#[derive(Default)]
pub struct BodyDelivery(Mutex<Inner>);

impl BodyDelivery {
    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A consensus host starts: a stall its predecessor left open ended.
    pub(crate) fn host_started(&self, now: Instant) {
        self.stall_ended(now);
        self.inner().host_started = Some(now);
    }

    pub(crate) fn finalized(&self) {
        self.inner().finalized += 1;
    }

    /// A finalized frame's body is not held; `leader` proposed it, if known.
    pub(crate) fn body_missing(&self, leader: Option<u32>) {
        if let Some(leader) = leader {
            *self.inner().missing_by_leader.entry(leader).or_default() += 1;
        }
    }

    /// A body missing at its finalization arrived later.
    pub(crate) fn body_late(&self) {
        self.inner().body_late += 1;
    }

    /// Finalizations dropped as materialized: their bodies never came.
    pub(crate) fn body_never(&self, dropped: u64) {
        self.inner().body_never += dropped;
    }

    pub(crate) fn block_in(&self, bytes: usize) {
        self.inner().block_bytes_in += bytes as u64;
    }

    /// A stall that began at `since` lasted long enough to be logged.
    pub(crate) fn stall_noted(&self, since: Instant) {
        let mut inner = self.inner();
        let catching_up = inner
            .host_started
            .is_some_and(|started| since.saturating_duration_since(started) < HOST_START_GRACE);
        if !catching_up {
            inner.open = Some(since);
        }
    }

    pub(crate) fn stall_ended(&self, now: Instant) {
        let mut inner = self.inner();
        if let Some(since) = inner.open.take() {
            inner.closed.push_back((since, now));
        }
    }

    /// This interval's counts once [`SUMMARY_EVERY`] has passed, restarting
    /// the interval. The first call starts the first interval.
    pub(crate) fn take_summary(&self, now: Instant) -> Option<BodySummary> {
        let mut inner = self.inner();
        let since = *inner.since.get_or_insert(now);
        let secs = now.saturating_duration_since(since);
        if secs < SUMMARY_EVERY {
            return None;
        }
        inner.since = Some(now);
        let top_leader = std::mem::take(&mut inner.missing_by_leader)
            .into_iter()
            .max_by_key(|(leader, missing)| (*missing, std::cmp::Reverse(*leader)));
        Some(BodySummary {
            secs: secs.as_secs(),
            finalized: std::mem::take(&mut inner.finalized),
            body_late: std::mem::take(&mut inner.body_late),
            body_never: std::mem::take(&mut inner.body_never),
            top_leader,
            block_bytes_in: std::mem::take(&mut inner.block_bytes_in),
        })
    }

    /// Say when stalled time reaches [`SHARE_WARN`] of the last hour, again
    /// every [`SHARE_REPEAT`], and when it falls back below it.
    pub(crate) fn share_signal(&self, now: Instant) -> Option<ShareSignal> {
        let mut inner = self.inner();
        let (stalled, stalls) = inner.stalled(now);
        if stalled < SHARE_WARN {
            return inner.warned.take().map(|_| ShareSignal::Ended { stalled });
        }
        if inner
            .warned
            .is_some_and(|warned| now.saturating_duration_since(warned) < SHARE_REPEAT)
        {
            return None;
        }
        inner.warned = Some(now);
        Some(ShareSignal::High { stalled, stalls })
    }
}

/// What a consensus host reports through, kept by its owner across hosts.
#[derive(Default)]
pub struct HostReporting {
    pub delivery: Arc<BodyDelivery>,
    /// Tags the host's threads, so their lines carry the worker's `coreId`.
    pub thread_tag: Option<quil_cw_consensus::engine_host::ThreadTag>,
}

/// The running engine's mesh size on its consensus topic, as last sampled.
#[derive(Default)]
pub(crate) struct MeshPeers(Arc<AtomicUsize>);

impl MeshPeers {
    /// For the sampler; it stops once the engine is gone.
    pub(crate) fn sampler(&self) -> MeshPeerSampler {
        MeshPeerSampler(Arc::downgrade(&self.0))
    }

    /// What the summary line shows: never sampled reads `unknown`.
    pub(crate) fn shown(&self) -> String {
        match self.0.load(Ordering::Relaxed) {
            0 => "unknown".to_string(),
            sampled => (sampled - 1).to_string(),
        }
    }
}

/// Keeps an engine's [`MeshPeers`] current from wherever its p2p handle is.
#[derive(Clone, Debug, Default)]
pub struct MeshPeerSampler(Weak<AtomicUsize>);

impl MeshPeerSampler {
    /// Sample `count` until the engine is gone or the p2p layer stops.
    pub async fn run<C, F>(self, mut count: C)
    where
        C: FnMut() -> F,
        F: std::future::Future<Output = quil_types::error::Result<usize>>,
    {
        while self.0.strong_count() > 0 {
            let Ok(peers) = count().await else { return };
            if let Some(cell) = self.0.upgrade() {
                cell.store(peers.saturating_add(1), Ordering::Relaxed);
            }
            tokio::time::sleep(MESH_SAMPLE_EVERY).await;
        }
    }
}

/// One shard's interval, bounded by [`SUMMARY_EVERY`]. `mesh_peers` under 3 is
/// a thin mesh; 6 or more with `body_never` high is loss on the link or a
/// queue; `top_leader_missing` dominant is one sender. A quiet shard logs
/// nothing.
pub(crate) fn log_summary(
    filter: &[u8],
    summary: &BodySummary,
    mesh_peers: &str,
    refused_block_not_delivered: u64,
) {
    if summary.is_quiet() && refused_block_not_delivered == 0 {
        return;
    }
    let (top_leader, top_leader_missing) = summary
        .top_leader
        .map_or_else(|| ("none".to_string(), 0), |(l, n)| (l.to_string(), n));
    tracing::info!(filter = %hex::encode(filter), secs = summary.secs, mesh_peers = %mesh_peers,
        finalized = summary.finalized, body_late = summary.body_late,
        body_never = summary.body_never, refused_block_not_delivered, top_leader = %top_leader,
        top_leader_missing, block_bytes_in = summary.block_bytes_in,
        "app shard body delivery summary");
}

/// Which of this node's parts to check, by what this worker refused:
/// `block_not_delivered` refusals against every other reason.
pub(crate) fn share_action(block_not_delivered: u64, other_refusals: u64) -> &'static str {
    if other_refusals > block_not_delivered {
        DISK_ACTION
    } else {
        LINK_ACTION
    }
}

pub(crate) fn log_share(
    filter: &[u8],
    signal: &ShareSignal,
    block_not_delivered: u64,
    other_refusals: u64,
) {
    match signal {
        ShareSignal::High { stalled, stalls } => tracing::warn!(
            filter = %hex::encode(filter), stalled_secs = stalled.as_secs(),
            window_secs = SHARE_WINDOW.as_secs(), stalls,
            refused_block_not_delivered = block_not_delivered, refused_other = other_refusals,
            scope = "this node",
            action = share_action(block_not_delivered, other_refusals),
            "finalized app frames stalled on this worker for over 1% of the last hour; \
             its seat signs little during a stall"
        ),
        ShareSignal::Ended { stalled } => tracing::info!(
            filter = %hex::encode(filter), stalled_secs = stalled.as_secs(),
            window_secs = SHARE_WINDOW.as_secs(),
            "finalized app frames stalled on this worker for under 1% of the last hour again"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outage::test_logs::CapturedLogs;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn stall(delivery: &BodyDelivery, from: Instant, for_secs: u64) {
        delivery.stall_noted(from);
        delivery.stall_ended(from + secs(for_secs));
    }

    /// At most 12 lines per shard per hour however busy the shard, each
    /// reporting only its own interval.
    #[test]
    fn the_summary_is_bounded_per_shard_interval_and_reports_each_interval_once() {
        let delivery = BodyDelivery::default();
        let start = Instant::now();
        assert_eq!(delivery.take_summary(start), None);
        let mut lines = 0;
        for tick in 1..=3600 {
            delivery.finalized();
            delivery.block_in(1000);
            if let Some(summary) = delivery.take_summary(start + secs(tick)) {
                lines += 1;
                assert_eq!(summary.finalized, 300, "{tick}");
                assert_eq!(summary.block_bytes_in, 300_000, "{tick}");
                assert_eq!(summary.secs, 300);
            }
        }
        assert_eq!(lines, 12, "lines per shard per hour");
    }

    #[test]
    fn the_summary_names_the_leader_with_the_most_missing_bodies() {
        let delivery = BodyDelivery::default();
        let start = Instant::now();
        delivery.take_summary(start);
        for leader in [Some(3), Some(5), Some(5), None] {
            delivery.body_missing(leader);
        }
        delivery.body_late();
        delivery.body_never(2);
        let summary = delivery.take_summary(start + SUMMARY_EVERY).unwrap();
        assert_eq!(summary.top_leader, Some((5, 2)));
        assert_eq!((summary.body_late, summary.body_never), (1, 2));
        let next = delivery.take_summary(start + SUMMARY_EVERY * 2).unwrap();
        assert_eq!(next.top_leader, None, "an interval starts empty");
        assert_eq!((next.body_late, next.body_never), (0, 0));
    }

    #[test]
    fn the_summary_line_carries_every_field_and_a_quiet_shard_logs_none() {
        let logs = CapturedLogs::default();
        let _guard = logs.install();
        log_summary(&[0xab], &BodySummary::default(), "7", 0);
        assert!(logs.lines_with("body delivery summary").is_empty());
        let summary = BodySummary {
            secs: 300,
            finalized: 30,
            body_late: 2,
            body_never: 1,
            top_leader: Some((4, 3)),
            block_bytes_in: 9000,
        };
        log_summary(&[0xab], &summary, "7", 5);
        let line = logs.lines_with("app shard body delivery summary");
        assert_eq!(line.len(), 1, "{line:?}");
        for field in [
            "INFO",
            "filter=ab",
            "secs=300",
            "mesh_peers=7",
            "finalized=30",
            "body_late=2",
            "body_never=1",
            "refused_block_not_delivered=5",
            "top_leader=4",
            "top_leader_missing=3",
            "block_bytes_in=9000",
        ] {
            assert!(line[0].contains(field), "{field}: {}", line[0]);
        }
    }

    /// 1% of the hour warns, a little less does not, and it ends as time
    /// passes: an anomaly's start, bounded repeats and its end.
    #[test]
    fn the_share_warns_at_one_percent_of_the_hour_repeats_bounded_and_ends() {
        let delivery = BodyDelivery::default();
        let start = Instant::now();
        let at = |s| start + secs(s);
        stall(&delivery, at(10), 35);
        assert_eq!(delivery.share_signal(at(100)), None, "35 s is under 1%");
        stall(&delivery, at(200), 1);
        assert_eq!(
            delivery.share_signal(at(300)),
            Some(ShareSignal::High {
                stalled: secs(36),
                stalls: 2
            })
        );
        assert_eq!(delivery.share_signal(at(301)), None);
        stall(&delivery, at(1000), 40);
        assert_eq!(delivery.share_signal(at(1800)), None, "within the repeat");
        assert_eq!(
            delivery.share_signal(at(2100)),
            Some(ShareSignal::High {
                stalled: secs(76),
                stalls: 3
            })
        );
        // The first stall has left the hour; the rest are still over 1%.
        assert_eq!(delivery.share_signal(at(3800)), None);
        assert_eq!(
            delivery.share_signal(at(4700)),
            Some(ShareSignal::Ended { stalled: secs(0) })
        );
        assert_eq!(delivery.share_signal(at(4701)), None);
    }

    #[test]
    fn a_stall_still_open_counts_and_one_leaving_the_hour_counts_in_part() {
        let delivery = BodyDelivery::default();
        let start = Instant::now();
        delivery.stall_noted(start + secs(10));
        assert_eq!(delivery.share_signal(start + secs(30)), None);
        assert!(matches!(
            delivery.share_signal(start + secs(46)),
            Some(ShareSignal::High { .. })
        ));
        delivery.stall_ended(start + secs(70));
        // 60 s long; 25 s of it is left in the hour ending at 3645 s.
        let (stalled, stalls) = delivery.inner().stalled(start + secs(3645));
        assert_eq!((stalled, stalls), (secs(25), 1));
    }

    /// Restarts and session starts bring most stalls on healthy nodes: they
    /// do not count, and a stall the old host left open ends with it.
    #[test]
    fn a_stall_in_a_hosts_catch_up_takes_no_share() {
        let delivery = BodyDelivery::default();
        let start = Instant::now();
        delivery.host_started(start);
        stall(&delivery, start + secs(60), 400);
        assert_eq!(delivery.share_signal(start + secs(500)), None);
        stall(&delivery, start + HOST_START_GRACE, 40);
        assert!(delivery
            .share_signal(start + HOST_START_GRACE + secs(50))
            .is_some());

        let delivery = BodyDelivery::default();
        delivery.stall_noted(start);
        delivery.host_started(start + secs(40));
        assert_eq!(
            delivery.inner().stalled(start + secs(100)),
            (secs(40), 1),
            "closed when the host stopped"
        );
    }

    #[test]
    fn the_share_warning_names_the_link_or_the_disk_by_the_refusal_mix() {
        assert_eq!(
            share_action(0, 0),
            LINK_ACTION,
            "bodies are what is missing"
        );
        assert_eq!(share_action(9, 3), LINK_ACTION);
        assert_eq!(share_action(3, 3), LINK_ACTION);
        assert_eq!(share_action(3, 9), DISK_ACTION);
        let logs = CapturedLogs::default();
        let _guard = logs.install();
        let high = ShareSignal::High {
            stalled: secs(40),
            stalls: 2,
        };
        log_share(&[1], &high, 3, 9);
        let warned = logs.lines_with("over 1% of the last hour");
        assert_eq!(warned.len(), 1);
        assert!(warned[0].contains("WARN"), "{}", warned[0]);
        assert!(warned[0].contains("disk"), "{}", warned[0]);
        assert!(warned[0].contains("stalled_secs=40"), "{}", warned[0]);
        log_share(&[1], &high, 9, 3);
        assert!(logs.lines_with("over 1% of the last hour")[1].contains("p2p port"));
        log_share(&[1], &ShareSignal::Ended { stalled: secs(1) }, 0, 0);
        assert!(logs.lines_with("under 1% of the last hour")[0].contains("INFO"));
    }

    #[tokio::test(start_paused = true)]
    async fn the_mesh_sampler_keeps_the_count_and_stops_with_the_engine() {
        let mesh = MeshPeers::default();
        assert_eq!(mesh.shown(), "unknown");
        let calls = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(mesh.sampler().run({
            let calls = calls.clone();
            move || {
                let calls = calls.clone();
                async move { Ok(calls.fetch_add(1, Ordering::SeqCst)) }
            }
        }));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(mesh.shown(), "0", "a sampled empty mesh is not unknown");
        tokio::time::sleep(MESH_SAMPLE_EVERY).await;
        assert_eq!(mesh.shown(), "1");
        drop(mesh);
        tokio::time::sleep(MESH_SAMPLE_EVERY * 2).await;
        task.await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the engine's end stops the sampling"
        );

        let failing = MeshPeers::default();
        failing
            .sampler()
            .run(|| async { Err::<usize, _>(quil_types::error::QuilError::P2p("stopped".into())) })
            .await;
        assert_eq!(failing.shown(), "unknown", "a stopped p2p layer ends it");
    }
}
