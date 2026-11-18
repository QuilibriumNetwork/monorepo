//! Archive failover for the GLOBAL prover tree pulls. Each pull from an
//! archive runs under a watchdog judging the archive's pace
//! ([`quil_rpc::sync_pace`]); an archive serving below the floor for a
//! window is given up on while another archive is left to try, at most
//! [`MAX_SLOW_FAILOVERS`] times a pass. Chunks it installed stay: the next
//! archive's walk diffs against them. An archive given up on is tried again,
//! unwatched, after every other archive of the pass failed, so a pass never
//! ends with less than it used to.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;

use quil_rpc::sync_pace::{PaceWindow, PeerPace, SYNC_PACE_FLOOR};
use quil_types::error::Result;
use tracing::{info, warn};

/// Archives a pass gives up on for their pace before it lets one finish.
pub(crate) const MAX_SLOW_FAILOVERS: usize = 2;
/// How often the watchdog reads an archive's pace.
const PACE_TICK: std::time::Duration = std::time::Duration::from_secs(5);

/// One pull from one archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub addr: String,
    /// Whether an archive below the floor is given up on; else only warned
    /// of.
    pub enforce: bool,
    /// The archive the pass tries next if this one is given up on.
    pub replacement: Option<String>,
}

/// The archives of one pass, in the order tried.
pub(crate) struct PacedArchives {
    queue: VecDeque<String>,
    given_up: VecDeque<String>,
    failovers: usize,
}

impl PacedArchives {
    pub(crate) fn new(archives: Vec<String>, max_failovers: usize) -> Self {
        Self {
            queue: archives.into(),
            given_up: VecDeque::new(),
            failovers: max_failovers,
        }
    }

    /// The next archive to pull from: each in order, then each given up on,
    /// unwatched. Only an archive with another after it is watched.
    pub(crate) fn next_archive(&mut self) -> Option<Attempt> {
        if let Some(addr) = self.queue.pop_front() {
            let enforce = self.failovers > 0 && !self.queue.is_empty();
            let replacement = self.queue.front().cloned().filter(|_| enforce);
            return Some(Attempt {
                addr,
                enforce,
                replacement,
            });
        }
        self.given_up.pop_front().map(|addr| Attempt {
            addr,
            enforce: false,
            replacement: None,
        })
    }

    /// Pull with `sync` from `attempt`'s archive under its watchdog, and log
    /// one line of its pace. `None` when the archive was given up on (it is
    /// tried again once the others failed); else what `sync` returned.
    pub(crate) async fn pull<F, Fut>(
        &mut self,
        attempt: &Attempt,
        sync: F,
    ) -> Option<Result<Option<u64>>>
    where
        F: FnOnce(Arc<PeerPace>) -> Fut,
        Fut: Future<Output = Result<Option<u64>>>,
    {
        let pace = Arc::new(PeerPace::default());
        let started = tokio::time::Instant::now();
        let synced = watched(attempt, &pace, sync(pace.clone())).await;
        let given_up = pace.given_up() && synced.is_err();
        let outcome = match &synced {
            _ if given_up => "given up: below the minimum rate",
            Ok(Some(_)) => "pulled the pinned root",
            Ok(None) => "cannot serve the pinned root",
            Err(_) => "failed",
        };
        let pace_now = pace.summary();
        info!(peer = %attempt.addr, outcome, watched = attempt.enforce,
            reads = pace_now.reads, reads_per_s = pace_now.reads_per_s(),
            walk_wait_secs = pace_now.walk_ms / 1000,
            leaves = pace_now.leaves, leaves_per_s = pace_now.leaves_per_s(),
            kib_per_s = pace_now.bytes_per_s() / 1024,
            chunks = pace_now.chunks, chunk_mean_ms = pace_now.chunk_mean_ms(),
            chunk_max_ms = pace_now.chunk_max_ms,
            elapsed_secs = started.elapsed().as_secs(),
            "prover tree sync: archive pace");
        if !given_up {
            return Some(synced);
        }
        self.failovers = self.failovers.saturating_sub(1);
        self.given_up.push_back(attempt.addr.clone());
        crate::prover_tree_syncer_prod::source_slow(&attempt.addr);
        None
    }
}

/// Run `sync` from `attempt`'s archive, reading `pace` every
/// [`PACE_TICK`]. The first window below [`SYNC_PACE_FLOOR`] is warned of
/// once and, when the attempt is enforced, gives up on the archive: its
/// reads fail and `sync` returns its error.
async fn watched<F: Future>(attempt: &Attempt, pace: &PeerPace, sync: F) -> F::Output {
    let mut window = PaceWindow::new(SYNC_PACE_FLOOR);
    let mut tick = tokio::time::interval(PACE_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut warned = false;
    tokio::pin!(sync);
    loop {
        tokio::select! {
            synced = &mut sync => return synced,
            _ = tick.tick(), if !warned => {
                let Some(slow) = window.observe(pace.sample()) else { continue };
                warned = true;
                let floor = SYNC_PACE_FLOOR;
                if attempt.enforce {
                    warn!(peer = %attempt.addr, window_secs = slow.window_secs,
                        reads_per_s = slow.reads_per_s, leaves_per_s = slow.leaves_per_s,
                        kib_per_s = slow.bytes_per_s / 1024,
                        floor_reads_per_s = floor.reads_per_s, floor_leaves_per_s = floor.leaves_per_s,
                        floor_kib_per_s = floor.bytes_per_s / 1024,
                        replacement = attempt.replacement.as_deref().unwrap_or(""),
                        "prover tree sync: archive below the minimum rate; giving up on it and \
                         pulling from the replacement (installed chunks are kept)");
                    pace.give_up();
                } else {
                    warn!(peer = %attempt.addr, window_secs = slow.window_secs,
                        reads_per_s = slow.reads_per_s, leaves_per_s = slow.leaves_per_s,
                        kib_per_s = slow.bytes_per_s / 1024,
                        floor_reads_per_s = floor.reads_per_s, floor_leaves_per_s = floor.leaves_per_s,
                        floor_kib_per_s = floor.bytes_per_s / 1024,
                        "prover tree sync: archive below the minimum rate, but no other archive is \
                         left to try this pass; the committed GLOBAL view waits for this pull");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_rpc::sync_pace::Wait;
    use quil_types::error::QuilError;
    use std::time::Duration;

    fn archives(names: &[&str]) -> PacedArchives {
        PacedArchives::new(
            names.iter().map(|n| n.to_string()).collect(),
            MAX_SLOW_FAILOVERS,
        )
    }

    /// A pull that serves `reads` walk reads, `per_s` a second, then
    /// verifies the root.
    async fn serve(pace: Arc<PeerPace>, reads: u64, per_s: u64) -> Result<Option<u64>> {
        if per_s == 0 {
            return Err(QuilError::Internal("archive connect: refused".into()));
        }
        for _ in 0..reads / per_s {
            pace.remote(Wait::Walk, tokio::time::sleep(Duration::from_secs(1)))
                .await
                .ok_or_else(|| {
                    QuilError::ExecutionUnavailable(quil_rpc::sync_pace::PACE_GIVEN_UP.into())
                })?;
            pace.add_reads(per_s);
        }
        Ok(Some(7))
    }

    /// Run a pass the way the prover tree sync does; the archive the root
    /// was pulled from and every attempt made.
    async fn pass(
        mut order: PacedArchives,
        speed: impl Fn(&str) -> u64,
    ) -> (Option<String>, Vec<Attempt>) {
        let mut tried = Vec::new();
        while let Some(attempt) = order.next_archive() {
            tried.push(attempt.clone());
            let per_s = speed(&attempt.addr);
            let Some(synced) = order
                .pull(&attempt, |pace| serve(pace, 30_000, per_s))
                .await
            else {
                continue;
            };
            if let Ok(Some(_)) = synced {
                return (Some(attempt.addr), tried);
            }
        }
        (None, tried)
    }

    fn speed_of(name: &str) -> u64 {
        if name.starts_with("slow") {
            20
        } else {
            1000
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_archive_is_given_up_for_the_next() {
        let (from, tried) = pass(archives(&["slow", "fast"]), speed_of).await;
        assert_eq!(
            from.as_deref(),
            Some("fast"),
            "the pull waited on the slow archive: {tried:?}"
        );
        assert_eq!(
            tried[0],
            Attempt {
                addr: "slow".into(),
                enforce: true,
                replacement: Some("fast".into())
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_last_archive_and_failovers_past_the_bound_are_not_given_up() {
        let started = tokio::time::Instant::now();
        let (from, tried) = pass(archives(&["slow1", "slow2", "slow3", "slow4"]), speed_of).await;
        // Two given up, the third finishes however slow.
        assert_eq!(
            from.as_deref(),
            Some("slow3"),
            "failed over past the bound: {tried:?}"
        );
        assert_eq!(
            tried.iter().map(|a| a.enforce).collect::<Vec<_>>(),
            vec![true, true, false]
        );
        assert!(started.elapsed() >= Duration::from_secs(30_000 / 20));
        let (from, tried) = pass(archives(&["slow"]), speed_of).await;
        assert_eq!(from.as_deref(), Some("slow"));
        assert!(!tried[0].enforce, "the last archive was given up on");
    }

    #[tokio::test(start_paused = true)]
    async fn an_archive_given_up_is_tried_again_when_the_others_fail() {
        // "dead" serves nothing and fails: the slow one is pulled from after all.
        let speed = |name: &str| if name == "dead" { 0 } else { speed_of(name) };
        let (from, tried) = pass(archives(&["slow", "dead"]), speed).await;
        assert_eq!(
            from.as_deref(),
            Some("slow"),
            "the archive given up on was not tried again: {tried:?}"
        );
        assert_eq!(
            tried
                .iter()
                .map(|a| (a.addr.as_str(), a.enforce))
                .collect::<Vec<_>>(),
            vec![("slow", true), ("dead", false), ("slow", false)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn only_time_waiting_on_the_archive_counts() {
        let pace = PeerPace::default();
        // Local work between calls is not waiting.
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert_eq!(
            pace.sample().waited_ms,
            0,
            "local work counted as waiting on the archive"
        );
        pace.remote(Wait::Walk, tokio::time::sleep(Duration::from_secs(2)))
            .await
            .unwrap();
        pace.remote(Wait::Fetch, tokio::time::sleep(Duration::from_secs(3)))
            .await
            .unwrap();
        pace.add_leaves(30, 3000);
        let summary = pace.summary();
        assert_eq!((summary.walk_ms, summary.fetch_ms), (2000, 3000));
        assert_eq!((summary.chunks, summary.chunk_max_ms), (1, 3000));
        assert_eq!((summary.leaves_per_s(), summary.bytes_per_s()), (10, 1000));
        assert_eq!(pace.sample().waited_ms, 5000);
    }

    #[tokio::test(start_paused = true)]
    async fn a_call_in_flight_counts_and_ends_when_given_up() {
        let pace = Arc::new(PeerPace::default());
        let call = {
            let pace = pace.clone();
            tokio::spawn(async move { pace.remote(Wait::Walk, std::future::pending::<()>()).await })
        };
        tokio::time::sleep(Duration::from_secs(90)).await;
        assert_eq!(pace.sample().waited_ms, 90_000);
        pace.give_up();
        // Bounded: a call that ignored the give-up would wait forever.
        let ended = tokio::time::timeout(Duration::from_secs(1), call).await;
        assert!(
            matches!(ended, Ok(Ok(None))),
            "the call in flight went on after its archive was given up: {ended:?}"
        );
        assert_eq!(pace.remote(Wait::Fetch, async { 1 }).await, None);
    }
}
