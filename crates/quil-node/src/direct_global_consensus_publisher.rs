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

use tokio::sync::Mutex;

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
            self.spawner.detach("direct-consensus-loopback", async move {
                let _ = lb
                    .send(quil_p2p::node::ReceivedMessage {
                        bitmask: bm,
                        data: d,
                        from: self_id,
                    })
                    .await;
                Ok(())
            });
        }

        let pool = self.pool.clone();
        let seed = self.falcon_signing_key.clone();
        let clients = self.clients.clone();
        self.spawner.detach("direct-consensus-fanout", async move {
            let addrs = pool.get_all().await;
            for addr in addrs {
                let bitmask = bitmask.clone();
                let data = data.clone();
                let clients = clients.clone();
                let seed = seed.clone();
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
                                tracing::warn!(addr = %addr, error = %e, "direct consensus: connect failed");
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
                    let submit_res = client.submit_global_consensus(bitmask.clone(), data.clone()).await;
                    quil_engine::metrics::record_archive_submit_duration(
                        submit_start.elapsed().as_secs_f64(),
                    );
                    if let Err(e) = submit_res {
                        tracing::warn!(addr = %addr, error = %e, "direct consensus: send failed, reconnecting and resending");
                        // Drop the (possibly dead) connection.
                        clients.lock().await.remove(&addr);
                        // Reconnect on a fresh mTLS channel and retry the
                        // send exactly once. A stale/half-open cached
                        // connection recovers here instead of losing the
                        // message for this rank.
                        match quil_rpc::ArchiveClient::connect_mtls(&addr, &seed).await {
                            Ok(mut fresh) => {
                                if let Err(e2) =
                                    fresh.submit_global_consensus(bitmask, data).await
                                {
                                    tracing::warn!(addr = %addr, error = %e2, "direct consensus: resend failed after reconnect");
                                } else {
                                    // Resend succeeded — cache the fresh
                                    // connection for subsequent messages.
                                    clients.lock().await.insert(addr.clone(), fresh);
                                }
                            }
                            Err(e2) => {
                                tracing::warn!(addr = %addr, error = %e2, "direct consensus: reconnect failed, message dropped for this rank");
                            }
                        }
                    }
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
