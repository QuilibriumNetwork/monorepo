//! A shard's commonware consensus message on its gossip topic, retried while
//! the topic has no subscribed peers. Such a spell is an episode per shard,
//! logged as it starts, summarized every five minutes and logged as it ends:
//! a line at every retry of every message made about ten warnings a second
//! while a node was offline for 65 minutes (2026-11-13).

use std::collections::HashMap;
use std::time::Duration;

use quil_types::error::Result;
use tokio::time::Instant;
use tracing::{info, warn};

/// How often a shard's spell without subscribed peers is summarized.
const SUMMARY_EVERY: Duration = Duration::from_secs(300);

/// The gossip side of a shard CW publish.
#[async_trait::async_trait]
pub(crate) trait CwGossip: Send + Sync {
    async fn publish(&self, topic: Vec<u8>, payload: Vec<u8>) -> Result<()>;
    /// Peers this node is connected to.
    fn peer_count(&self) -> usize;
}

#[async_trait::async_trait]
impl CwGossip for quil_p2p::node::P2PHandle {
    async fn publish(&self, topic: Vec<u8>, payload: Vec<u8>) -> Result<()> {
        quil_p2p::node::P2PHandle::publish(self, topic, payload).await
    }

    fn peer_count(&self) -> usize {
        quil_p2p::node::P2PHandle::peer_count(self)
    }
}

/// Publish `payload` on shard `filter`'s CW topic, retried with a doubling
/// delay while the topic has no subscribed peers, up to eight sends. While
/// this node has no peer at all a retry cannot reach anyone: the message is
/// sent once.
pub(crate) async fn publish_shard_cw(
    gossip: &dyn CwGossip,
    core_id: u32,
    filter: &[u8],
    topic: Vec<u8>,
    payload: Vec<u8>,
) {
    for attempt in 1..=8u32 {
        let error = match gossip.publish(topic.clone(), payload.clone()).await {
            Ok(()) => {
                note(core_id, filter, Outcome::Delivered, 0, "");
                return;
            }
            Err(e) => e.to_string(),
        };
        let peers = gossip.peer_count();
        if super::worker_manager::retryable_cw_publish_failure(&error, attempt) {
            if peers == 0 {
                note(core_id, filter, Outcome::Offline, peers, &error);
                return;
            }
            note(core_id, filter, Outcome::Retried, peers, &error);
            let delay = Duration::from_millis(250u64.saturating_mul(1u64 << (attempt - 1)));
            tokio::time::sleep(delay).await;
            continue;
        }
        if no_subscribed_peers(&error) {
            note(core_id, filter, Outcome::Failed, peers, &error);
        } else {
            warn!(core_id, filter = %hex::encode(filter), attempt, %error, "shard cw publish failed");
        }
        return;
    }
}

/// The topic had no subscribed peer.
fn no_subscribed_peers(error: &str) -> bool {
    error.contains("NoPeersSubscribedToTopic")
}

/// What became of one send.
#[derive(Clone, Copy)]
enum Outcome {
    /// The topic took it.
    Delivered,
    /// No subscribed peer; sent again after a delay.
    Retried,
    /// No subscribed peer at its last send: given up.
    Failed,
    /// No subscribed peer and this node has no peer: given up.
    Offline,
}

/// Sends of one shard's spell without subscribed peers.
#[derive(Clone, Copy, Default)]
struct Counts {
    retries: u64,
    failed: u64,
    offline: u64,
}

impl Counts {
    fn add(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Delivered => {}
            Outcome::Retried => self.retries += 1,
            Outcome::Failed => self.failed += 1,
            Outcome::Offline => self.offline += 1,
        }
    }
}

/// One shard topic's spell without subscribed peers.
struct Episode {
    started: Instant,
    summarized: Instant,
    total: Counts,
    /// Since the last summary.
    recent: Counts,
}

/// Each shard's open spell, by filter.
fn episodes() -> &'static parking_lot::Mutex<HashMap<Vec<u8>, Episode>> {
    static EPISODES: std::sync::OnceLock<parking_lot::Mutex<HashMap<Vec<u8>, Episode>>> =
        std::sync::OnceLock::new();
    EPISODES.get_or_init(Default::default)
}

/// Count one send of shard `filter`'s CW message, `peers` connected: its
/// first failure starts the shard's spell, a summary follows every five
/// minutes, and the first send the topic takes ends it.
fn note(core_id: u32, filter: &[u8], outcome: Outcome, peers: usize, error: &str) {
    let now = Instant::now();
    let mut episodes = episodes().lock();
    if let Outcome::Delivered = outcome {
        let Some(episode) = episodes.remove(filter) else {
            return;
        };
        drop(episodes);
        let total = episode.total;
        info!(core_id, filter = %hex::encode(filter),
            secs = now.duration_since(episode.started).as_secs(), retries = total.retries,
            failed = total.failed, offline = total.offline,
            "shard CW topic publishes again: its spell without subscribed peers ended (retries: sends \
             retried; failed: messages given up after eight sends; offline: messages sent once while \
             this node had no peer)");
        return;
    }
    let started = !episodes.contains_key(filter);
    let episode = episodes.entry(filter.to_vec()).or_insert(Episode {
        started: now,
        summarized: now,
        total: Counts::default(),
        recent: Counts::default(),
    });
    episode.total.add(outcome);
    episode.recent.add(outcome);
    let summary =
        (!started && now.duration_since(episode.summarized) >= SUMMARY_EVERY).then(|| {
            episode.summarized = now;
            (
                std::mem::take(&mut episode.recent),
                now.duration_since(episode.started),
            )
        });
    drop(episodes);
    if started {
        let action = if peers == 0 {
            "this node has no peer: check its network connection; each message is sent once until a peer connects"
        } else {
            "expected for a moment after a shard starts; lasting, its committee's members are not reachable from this node"
        };
        warn!(core_id, filter = %hex::encode(filter), peers, %error, action,
            "shard CW publish found no subscribed peers: retrying each message up to eight times (one line per \
             shard; a summary every five minutes and a line when the topic takes a message again)");
    }
    if let Some((recent, lasted)) = summary {
        warn!(core_id, filter = %hex::encode(filter), secs = lasted.as_secs(), peers,
            retries = recent.retries, failed = recent.failed, offline = recent.offline,
            "shard CW topic still has no subscribed peers (counts since the last summary)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Gossip with `peers` peers connected whose topic has no subscribed
    /// peer for its first `failing` publishes.
    struct Gossip {
        peers: usize,
        failing: usize,
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl CwGossip for Gossip {
        async fn publish(&self, _topic: Vec<u8>, _payload: Vec<u8>) -> Result<()> {
            if self.calls.fetch_add(1, Ordering::SeqCst) < self.failing {
                return Err(quil_types::error::QuilError::P2p(
                    "blossomsub publish failed: NoPeersSubscribedToTopic".into(),
                ));
            }
            Ok(())
        }

        fn peer_count(&self) -> usize {
            self.peers
        }
    }

    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            std::io::Write::write(&mut *self.0.lock().unwrap(), bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Lines {
        /// The lines naming `filter`.
        fn of(&self, filter: &[u8]) -> Vec<String> {
            let filter = hex::encode(filter);
            String::from_utf8_lossy(&self.0.lock().unwrap())
                .lines()
                .filter(|line| line.contains(&filter))
                .map(str::to_string)
                .collect()
        }
    }

    fn capture() -> (Lines, tracing::subscriber::DefaultGuard) {
        let lines = Lines::default();
        let writer = lines.clone();
        let guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish(),
        );
        (lines, guard)
    }

    fn with<'a>(lines: &'a [String], text: &str) -> Vec<&'a String> {
        lines.iter().filter(|line| line.contains(text)).collect()
    }

    /// A shard topic without subscribed peers is logged as it starts, in a
    /// summary every five minutes and as it ends, not at every retry of
    /// every message: so logged, a node offline for 65 minutes wrote about
    /// ten warnings a second (2026-11-13).
    #[tokio::test(start_paused = true)]
    async fn a_shard_cw_publish_outage_logs_its_start_summaries_and_end_not_each_retry() {
        let filter = [0xc1u8; 32];
        let (lines, _guard) = capture();
        let messages = 12;
        let gossip = Gossip {
            peers: 5,
            failing: messages * 8,
            calls: AtomicUsize::new(0),
        };
        for _ in 0..=messages {
            publish_shard_cw(&gossip, 3, &filter, vec![1], vec![2]).await;
        }
        assert_eq!(
            gossip.calls.load(Ordering::SeqCst),
            messages * 8 + 1,
            "each message is tried eight times while peers are connected"
        );
        let lines = lines.of(&filter);
        let warns = with(&lines, "WARN");
        assert!(
            warns.len() <= 3,
            "retry_warn_flood: {} warn lines for {messages} messages",
            warns.len()
        );
        let started = with(&lines, "found no subscribed peers");
        assert_eq!(started.len(), 1, "episode_start_unlogged: {lines:?}");
        assert!(started[0].contains("peers=5"), "{}", started[0]);
        let summaries = with(&lines, "still has no subscribed peers");
        assert_eq!(summaries.len(), 1, "episode_summary_unlogged: {lines:?}");
        assert!(summaries[0].contains("retries="), "{}", summaries[0]);
        let ended = with(&lines, "publishes again");
        assert_eq!(ended.len(), 1, "episode_end_unlogged: {lines:?}");
        assert!(
            ended[0].contains("retries=84") && ended[0].contains("failed=12"),
            "episode_end_unlogged: {}",
            ended[0]
        );
    }

    /// A node without peers sends each shard CW message once: no retry can
    /// reach a subscriber until a peer connects, and each message's retries
    /// took half a minute (2026-11-13).
    #[tokio::test(start_paused = true)]
    async fn a_node_without_peers_does_not_retry_shard_cw_messages() {
        let filter = [0xc2u8; 32];
        let (lines, _guard) = capture();
        let gossip = Gossip {
            peers: 0,
            failing: usize::MAX,
            calls: AtomicUsize::new(0),
        };
        for _ in 0..3 {
            publish_shard_cw(&gossip, 3, &filter, vec![1], vec![2]).await;
        }
        assert_eq!(
            gossip.calls.load(Ordering::SeqCst),
            3,
            "offline_retries: messages retried without a peer"
        );
        let lines = lines.of(&filter);
        let warns = with(&lines, "WARN");
        assert_eq!(warns.len(), 1, "offline_warn_flood: {lines:?}");
        assert!(warns[0].contains("peers=0"), "{}", warns[0]);
    }
}
