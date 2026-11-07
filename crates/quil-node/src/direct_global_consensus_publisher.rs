//! Direct point-to-point publisher for GLOBAL consensus messages.
//!
//! Global consensus is a tiny committee (~6 genesis archives, wired as
//! direct peers). A full-coverage global proposal (thousands of shard
//! FrameHeader proofs) is far larger than the BlossomSub gossip
//! message-size ceiling (~1 MiB soft / ~16-20 MiB hard), so proposals
//! and votes/timeouts are delivered **point-to-point** over the existing
//! `:8340` Ed448-mTLS `GlobalService.SubmitGlobalConsensus` RPC instead
//! of gossip. The proposer's own message is delivered via the local
//! loopback (same as before). Prover-admin messages (GLOBAL_PROVER) stay
//! on gossip — unchanged. App-shard consensus is a completely separate
//! publisher (per-shard gossip topics) and is untouched.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// Minimum interval between two lines about one peer's failed sends.
const SEND_FAILURE_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// What became of one message sent to one peer.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Delivery {
    /// Delivered on the first try.
    Sent,
    /// The send failed; delivered by the resend after a reconnect.
    Resent { error: String },
    /// The send failed and so did the resend after a reconnect: dropped.
    ResendFailed { error: String },
    /// The send failed and the reconnect failed: dropped.
    ReconnectFailed { error: String },
    /// No cached connection and the connect failed: dropped.
    ConnectFailed { error: String },
}

/// Failed sends to one peer, by outcome.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FailureCounts {
    /// First sends that failed (each reconnected and resent once).
    send_failed: u64,
    /// Of those, resends that failed after a reconnect.
    resend_failed: u64,
    /// Of those, reconnects that failed.
    reconnect_failed: u64,
    /// Of those, resends that got through.
    resent: u64,
    /// Messages dropped because no connection could be made at all.
    connect_failed: u64,
}

impl FailureCounts {
    fn add(&mut self, delivery: &Delivery) {
        match delivery {
            Delivery::Sent => {}
            Delivery::Resent { .. } => {
                self.send_failed += 1;
                self.resent += 1;
            }
            Delivery::ResendFailed { .. } => {
                self.send_failed += 1;
                self.resend_failed += 1;
            }
            Delivery::ReconnectFailed { .. } => {
                self.send_failed += 1;
                self.reconnect_failed += 1;
            }
            Delivery::ConnectFailed { .. } => self.connect_failed += 1,
        }
    }

    /// Messages lost for their rank.
    fn dropped(&self) -> u64 {
        self.resend_failed + self.reconnect_failed + self.connect_failed
    }
}

/// One peer's failed sends since its last success.
#[derive(Debug, Default)]
struct PeerFailures {
    /// When the current run of failures began.
    failing_since: Option<Instant>,
    /// Whether the current run has been logged.
    announced: bool,
    /// When the last line about this peer was logged.
    last_line: Option<Instant>,
    /// Failures since the last line about this peer.
    pending: FailureCounts,
    /// Failures in the current run.
    run: FailureCounts,
    latest_error: String,
}

/// A line to log about one peer's sends.
#[derive(Debug, PartialEq, Eq)]
enum SendFailureLine {
    /// A run of failures began.
    Started {
        counts: FailureCounts,
        since_last_line: Option<Duration>,
        error: String,
    },
    /// Failures continue.
    Continuing {
        counts: FailureCounts,
        since_last_line: Duration,
        failing: Duration,
        error: String,
    },
    /// A send succeeded after a logged run of failures.
    Recovered {
        run: FailureCounts,
        failing: Duration,
    },
}

/// Failed direct consensus sends, per peer address. A peer that fails
/// every message (an unreachable archive, or one whose message loop is
/// blocked) is logged when it starts failing, then at most once per
/// [`SEND_FAILURE_LOG_INTERVAL`] with counts, and once when a send
/// succeeds again. A run's first line also waits for that interval since
/// the peer's previous line, so a peer that alternates between failing
/// and succeeding logs at most one warning and one info line per
/// interval; failures of a run that ends before its first line are
/// counted in the peer's next line.
#[derive(Debug, Default)]
struct SendFailures {
    peers: HashMap<String, PeerFailures>,
}

impl SendFailures {
    fn record(&mut self, addr: &str, delivery: &Delivery, now: Instant) -> Option<SendFailureLine> {
        let error = match delivery {
            Delivery::Sent => {
                let peer = self.peers.get_mut(addr)?;
                let failing_since = peer.failing_since.take()?;
                let run = std::mem::take(&mut peer.run);
                if !std::mem::take(&mut peer.announced) {
                    return None;
                }
                peer.pending = FailureCounts::default();
                peer.last_line = Some(now);
                return Some(SendFailureLine::Recovered {
                    run,
                    failing: now.saturating_duration_since(failing_since),
                });
            }
            Delivery::Resent { error }
            | Delivery::ResendFailed { error }
            | Delivery::ReconnectFailed { error }
            | Delivery::ConnectFailed { error } => error,
        };
        let peer = self.peers.entry(addr.to_string()).or_default();
        peer.pending.add(delivery);
        peer.run.add(delivery);
        peer.latest_error.clone_from(error);
        let failing_since = *peer.failing_since.get_or_insert(now);
        let since_last_line = peer
            .last_line
            .map(|last| now.saturating_duration_since(last));
        if since_last_line.is_some_and(|elapsed| elapsed < SEND_FAILURE_LOG_INTERVAL) {
            return None;
        }
        peer.last_line = Some(now);
        let counts = std::mem::take(&mut peer.pending);
        let error = peer.latest_error.clone();
        if std::mem::replace(&mut peer.announced, true) {
            Some(SendFailureLine::Continuing {
                counts,
                since_last_line: since_last_line.unwrap_or_default(),
                failing: now.saturating_duration_since(failing_since),
                error,
            })
        } else {
            Some(SendFailureLine::Started {
                counts,
                since_last_line,
                error,
            })
        }
    }

    /// Record what became of one message to `addr` and log a line about
    /// the peer when one is due.
    fn report(&mut self, addr: &str, delivery: Delivery, now: Instant) {
        if let Some(line) = self.record(addr, &delivery, now) {
            line.log(addr);
        }
    }
}

impl SendFailureLine {
    fn log(&self, addr: &str) {
        match self {
            SendFailureLine::Started {
                counts,
                since_last_line,
                error,
            } => {
                let window = match since_last_line {
                    Some(elapsed) => format!("the last {}s", elapsed.as_secs()),
                    None => "startup".to_string(),
                };
                tracing::warn!(
                    scope = "peer",
                    addr = %addr,
                    send_failed = counts.send_failed,
                    resend_failed = counts.resend_failed,
                    reconnect_failed = counts.reconnect_failed,
                    resent = counts.resent,
                    connect_failed = counts.connect_failed,
                    dropped = counts.dropped(),
                    error = %error,
                    "direct consensus: sends to a GLOBAL peer started failing (counts since {window}): \
                     this node's GLOBAL consensus messages to it fail until it accepts them again; \
                     each failed send is reconnected and resent once, a dropped message is lost for \
                     its rank; check the peer's reachability from this node; if most GLOBAL peers \
                     fail, GLOBAL cannot form a quorum (see the `GLOBAL halted network-wide` line); \
                     repeated at most every 60s until a send to it succeeds"
                );
            }
            SendFailureLine::Continuing {
                counts,
                since_last_line,
                failing,
                error,
            } => {
                tracing::warn!(
                    scope = "peer",
                    addr = %addr,
                    failing_secs = failing.as_secs(),
                    send_failed = counts.send_failed,
                    resend_failed = counts.resend_failed,
                    reconnect_failed = counts.reconnect_failed,
                    resent = counts.resent,
                    connect_failed = counts.connect_failed,
                    dropped = counts.dropped(),
                    error = %error,
                    "direct consensus: sends to a GLOBAL peer still failing after {}s (counts for \
                     the last {}s, latest error)",
                    failing.as_secs(),
                    since_last_line.as_secs()
                );
            }
            SendFailureLine::Recovered { run, failing } => {
                tracing::info!(
                    scope = "peer",
                    addr = %addr,
                    failing_secs = failing.as_secs(),
                    send_failed = run.send_failed,
                    resend_failed = run.resend_failed,
                    reconnect_failed = run.reconnect_failed,
                    resent = run.resent,
                    connect_failed = run.connect_failed,
                    dropped = run.dropped(),
                    "direct consensus: sends to a GLOBAL peer succeed again after {}s of failures \
                     (counts for the whole run)",
                    failing.as_secs()
                );
            }
        }
    }
}

pub(crate) struct DirectGlobalConsensusPublisher {
    /// Target archives (their `:8340` mTLS endpoints) — the global
    /// consensus committee. Sourced from the archive endpoint pool /
    /// genesis direct-peer set.
    pool: Arc<quil_rpc::ArchiveEndpointPool>,
    /// Our Ed448 seed, used as the mTLS client identity for outbound
    /// `connect_mtls` to peer archives.
    falcon_signing_key: Vec<u8>,
    /// Self-loopback so our own `vote_aggregator` / event loop sees our
    /// own votes/timeouts (we don't deliver to ourselves over gRPC).
    loopback_tx: tokio::sync::mpsc::Sender<quil_p2p::node::ReceivedMessage>,
    self_peer_id: Vec<u8>,
    spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
    /// Cached mTLS connections per archive address, reused across
    /// messages — a fresh handshake per consensus message would add
    /// ~300 ms of latency to every round. Evicted + reconnected on a
    /// send failure. `ArchiveClient` clones share one multiplexed h2
    /// channel, so concurrent sends are cheap.
    clients: Arc<Mutex<HashMap<String, quil_rpc::ArchiveClient>>>,
    /// Failed sends per archive address, logged as one bounded summary
    /// per peer rather than one warning per message.
    failures: Arc<std::sync::Mutex<SendFailures>>,
}

impl DirectGlobalConsensusPublisher {
    pub(crate) fn new(
        pool: Arc<quil_rpc::ArchiveEndpointPool>,
        falcon_signing_key: Vec<u8>,
        loopback_tx: tokio::sync::mpsc::Sender<quil_p2p::node::ReceivedMessage>,
        self_peer_id: Vec<u8>,
        spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
    ) -> Self {
        Self {
            pool,
            falcon_signing_key,
            loopback_tx,
            self_peer_id,
            spawner,
            clients: Arc::new(Mutex::new(HashMap::new())),
            failures: Arc::new(std::sync::Mutex::new(SendFailures::default())),
        }
    }

    /// Deliver `data` (tagged with the original gossip `bitmask`) to every
    /// committee archive over `SubmitGlobalConsensus`, plus optionally to
    /// ourselves via loopback. Non-blocking: the consensus task returns
    /// immediately; delivery happens on detached tasks, one per archive so
    /// a slow/unreachable peer can't delay the others.
    fn fan_out(&self, bitmask: Vec<u8>, data: Vec<u8>, loopback: bool) {
        if loopback {
            let lb = self.loopback_tx.clone();
            let self_id = self.self_peer_id.clone();
            let bm = bitmask.clone();
            let d = data.clone();
            self.spawner
                .detach("direct-consensus-loopback", async move {
                    let _ = lb
                        .send(quil_p2p::node::ReceivedMessage {
                            bitmask: bm,
                            data: d,
                            from: self_id,
                            direct: false,
                        })
                        .await;
                    Ok(())
                });
        }

        let pool = self.pool.clone();
        let seed = self.falcon_signing_key.clone();
        let clients = self.clients.clone();
        let failures = self.failures.clone();
        self.spawner.detach("direct-consensus-fanout", async move {
            let addrs = pool.get_all().await;
            for addr in addrs {
                let bitmask = bitmask.clone();
                let data = data.clone();
                let clients = clients.clone();
                let seed = seed.clone();
                let failures = failures.clone();
                // Per-archive concurrent send: one peer being slow or down
                // must not delay delivery to the rest.
                tokio::spawn(async move {
                    // Reuse a cached connection if we have one; the lock is
                    // held only for the map get/insert, never across the
                    // (slow) handshake.
                    let cached = { clients.lock().await.get(&addr).cloned() };
                    let mut client = match cached {
                        Some(c) => c,
                        None => match quil_rpc::ArchiveClient::connect_mtls(&addr, &seed).await {
                            Ok(c) => {
                                clients.lock().await.insert(addr.clone(), c.clone());
                                c
                            }
                            Err(e) => {
                                let delivery = Delivery::ConnectFailed {
                                    error: e.to_string(),
                                };
                                failures
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .report(&addr, delivery, Instant::now());
                                return;
                            }
                        },
                    };
                    // Attempt delivery; on failure, reconnect once and resend.
                    //
                    // Consensus liveness DEPENDS on this: unlike timeouts
                    // (which `on_own_timeout` rebroadcasts every tick), a
                    // vote/proposal is produced and sent exactly ONCE per
                    // rank. A single dropped send — most commonly a stale
                    // cached h2 connection whose first write fails, or a
                    // transient inbound accept hiccup on the peer while it
                    // serves hypersync — silently loses that rank's vote,
                    // and the round degrades to a timeout. With no resend,
                    // any nonzero per-send failure rate collapses the
                    // committee into timeout-only mode (TCs form from
                    // rebroadcast timeouts, but QCs rarely do, so Jolteon's
                    // 2-chain never completes and finalization stalls).
                    // Reconnecting and resending gives votes/proposals the
                    // same self-healing the timeout path already has.
                    let submit_start = std::time::Instant::now();
                    let submit_res = client
                        .submit_global_consensus(bitmask.clone(), data.clone())
                        .await;
                    quil_engine::metrics::record_archive_submit_duration(
                        submit_start.elapsed().as_secs_f64(),
                    );
                    let delivery = match submit_res {
                        Ok(()) => Delivery::Sent,
                        Err(e) => {
                            // Drop the (possibly dead) connection.
                            clients.lock().await.remove(&addr);
                            // Reconnect on a fresh mTLS channel and retry the
                            // send exactly once. A stale/half-open cached
                            // connection recovers here instead of losing the
                            // message for this rank.
                            match quil_rpc::ArchiveClient::connect_mtls(&addr, &seed).await {
                                Ok(mut fresh) => {
                                    match fresh.submit_global_consensus(bitmask, data).await {
                                        Err(e2) => Delivery::ResendFailed {
                                            error: format!("send: {e}; resend: {e2}"),
                                        },
                                        Ok(()) => {
                                            // Resend succeeded — cache the fresh
                                            // connection for subsequent messages.
                                            clients.lock().await.insert(addr.clone(), fresh);
                                            Delivery::Resent {
                                                error: e.to_string(),
                                            }
                                        }
                                    }
                                }
                                Err(e2) => Delivery::ReconnectFailed {
                                    error: format!("send: {e}; reconnect: {e2}"),
                                },
                            }
                        }
                    };
                    failures
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .report(&addr, delivery, Instant::now());
                });
            }
            Ok(())
        });
    }

    /// Deliver a commonware-simplex consensus message on `channel` (0=vote,
    /// 1=certificate, 2=resolver) to the whole committee over `:8340`, tagging
    /// the channel in the bitmask so peers demux it back. No self-loopback —
    /// simplex processes our own messages internally. Used by the simplex
    /// cutover's `GlobalConsensusTransport`.
    pub(crate) fn submit_cw_channel(&self, channel: u64, data: Vec<u8>) {
        let bitmask = quil_engine::bitmasks::global_cw_channel_bitmask(channel).to_vec();
        self.fan_out(bitmask, data, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER_A: &str = "archive-a:8340";
    const PEER_B: &str = "archive-b:8340";

    fn failure(n: u64) -> Delivery {
        let error = format!("error {n}");
        match n % 10 {
            0 => Delivery::ReconnectFailed { error },
            1 => Delivery::ConnectFailed { error },
            2 => Delivery::Resent { error },
            _ => Delivery::ResendFailed { error },
        }
    }

    /// Everything logged at info and above while `run` runs.
    fn captured(run: impl FnOnce()) -> String {
        use std::io;

        #[derive(Clone, Default)]
        struct Buffer(Arc<std::sync::Mutex<Vec<u8>>>);
        impl io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, run);
        let out = buffer.0.lock().unwrap().clone();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_failing_peer_logs_its_start_bounded_summaries_and_its_end() {
        let start = Instant::now();
        let at = |millis: u64| start + Duration::from_millis(millis);
        let mut failures = SendFailures::default();
        let out = captured(|| {
            failures.report(PEER_A, Delivery::Sent, at(0));
            // 1,000 failed messages to one peer over 150 s, as a blocked
            // archive's message loop produces them.
            for n in 0..1_000u64 {
                failures.report(PEER_A, failure(n), at(n * 150));
                if n == 100 {
                    // Another peer fails once and recovers on its own.
                    failures.report(PEER_B, failure(5), at(n * 150));
                    failures.report(PEER_B, Delivery::Sent, at(n * 150 + 1));
                }
            }
            failures.report(PEER_A, Delivery::Sent, at(150_000));
            failures.report(PEER_A, Delivery::Sent, at(150_001));
        });
        let lines: Vec<&str> = out.lines().collect();
        let count = |text: &str| lines.iter().filter(|line| line.contains(text)).count();
        assert_eq!(lines.len(), 6, "{out}");
        assert_eq!(count("started failing"), 2, "{out}");
        assert_eq!(count("still failing"), 2, "{out}");
        assert_eq!(count("succeed again"), 2, "{out}");
        assert_eq!(count(" WARN "), 4, "{out}");
        assert_eq!(count(PEER_A), 4, "{out}");
        assert_eq!(count(PEER_B), 2, "{out}");
        let recovered = lines
            .iter()
            .find(|line| line.contains("succeed again") && line.contains(PEER_A))
            .unwrap();
        for field in [
            "failing_secs=150",
            "send_failed=900",
            "resend_failed=700",
            "reconnect_failed=100",
            "resent=100",
            "connect_failed=100",
            "dropped=900",
        ] {
            assert!(recovered.contains(field), "{field} missing: {recovered}");
        }
        let continuing = lines
            .iter()
            .filter(|line| line.contains("still failing"))
            .collect::<Vec<_>>();
        assert!(continuing[0].contains("failing_secs=60"), "{out}");
        assert!(continuing[0].contains("error=error 400"), "{out}");
        assert!(continuing[1].contains("failing_secs=120"), "{out}");
    }

    #[test]
    fn summaries_count_each_window_and_a_flapping_peer_stays_bounded() {
        let start = Instant::now();
        let at = |millis: u64| start + Duration::from_millis(millis);
        let mut failures = SendFailures::default();
        let started = failures.record(PEER_A, &failure(3), at(0)).unwrap();
        assert_eq!(
            started,
            SendFailureLine::Started {
                counts: FailureCounts {
                    send_failed: 1,
                    resend_failed: 1,
                    ..FailureCounts::default()
                },
                since_last_line: None,
                error: "error 3".into(),
            }
        );
        assert!(matches!(
            failures.record(PEER_A, &Delivery::Sent, at(10)),
            Some(SendFailureLine::Recovered { .. })
        ));
        // Alternating failures and successes within the interval log
        // nothing more; their failures are counted in the next line.
        for n in 1..=500u64 {
            assert_eq!(failures.record(PEER_A, &failure(1), at(10 + n * 100)), None);
            assert_eq!(
                failures.record(PEER_A, &Delivery::Sent, at(60 + n * 100)),
                None
            );
        }
        let next = failures.record(PEER_A, &failure(2), at(60_010)).unwrap();
        assert_eq!(
            next,
            SendFailureLine::Started {
                counts: FailureCounts {
                    send_failed: 1,
                    resent: 1,
                    connect_failed: 500,
                    ..FailureCounts::default()
                },
                since_last_line: Some(Duration::from_secs(60)),
                error: "error 2".into(),
            }
        );
        assert_eq!(failures.record(PEER_A, &failure(1), at(70_000)), None);
        let continuing = failures.record(PEER_A, &failure(0), at(120_010)).unwrap();
        assert_eq!(
            continuing,
            SendFailureLine::Continuing {
                counts: FailureCounts {
                    send_failed: 1,
                    reconnect_failed: 1,
                    connect_failed: 1,
                    ..FailureCounts::default()
                },
                since_last_line: Duration::from_secs(60),
                failing: Duration::from_secs(60),
                error: "error 0".into(),
            }
        );
        let recovered = failures
            .record(PEER_A, &Delivery::Sent, at(121_010))
            .unwrap();
        assert_eq!(
            recovered,
            SendFailureLine::Recovered {
                run: FailureCounts {
                    send_failed: 2,
                    resent: 1,
                    reconnect_failed: 1,
                    connect_failed: 1,
                    ..FailureCounts::default()
                },
                failing: Duration::from_secs(61),
            }
        );
    }
}
