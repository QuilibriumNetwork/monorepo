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
    ed448_seed: [u8; 57],
    /// Self-loopback so our own `vote_aggregator` / event loop sees our
    /// own votes/timeouts (we don't deliver to ourselves over gRPC).
    loopback_tx: tokio::sync::mpsc::Sender<quil_p2p::node::ReceivedMessage>,
    self_peer_id: Vec<u8>,
    /// Retained only for prover-admin messages, which stay on gossip.
    p2p_handle: quil_p2p::node::P2PHandle,
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
        ed448_seed: [u8; 57],
        loopback_tx: tokio::sync::mpsc::Sender<quil_p2p::node::ReceivedMessage>,
        self_peer_id: Vec<u8>,
        p2p_handle: quil_p2p::node::P2PHandle,
        spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
    ) -> Self {
        Self {
            pool,
            ed448_seed,
            loopback_tx,
            self_peer_id,
            p2p_handle,
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
        let seed = self.ed448_seed;
        let clients = self.clients.clone();
        self.spawner.detach("direct-consensus-fanout", async move {
            let addrs = pool.get_all().await;
            for addr in addrs {
                let bitmask = bitmask.clone();
                let data = data.clone();
                let clients = clients.clone();
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
                                tracing::debug!(addr = %addr, error = %e, "direct consensus: connect failed");
                                return;
                            }
                        },
                    };
                    if let Err(e) = client.submit_global_consensus(bitmask, data).await {
                        tracing::debug!(addr = %addr, error = %e, "direct consensus: send failed, evicting connection");
                        // Drop the (possibly dead) connection so the next
                        // message reconnects.
                        clients.lock().await.remove(&addr);
                    }
                });
            }
            Ok(())
        });
    }
}

impl quil_engine::consensus_glue::ConsensusPublisher for DirectGlobalConsensusPublisher {
    fn publish_frame(&self, data: Vec<u8>) {
        // Proposals/frames → committee, no self-loopback (the proposer's
        // own event loop already holds its proposal). Mirrors the old
        // BlossomSub publisher's `publish_frame`.
        self.fan_out(quil_engine::bitmasks::GLOBAL_FRAME.to_vec(), data, false);
    }

    fn publish_consensus(&self, data: Vec<u8>) {
        // Votes/timeouts → committee + self-loopback so our own aggregator
        // counts our own vote. Mirrors the old `publish_consensus`.
        self.fan_out(quil_engine::bitmasks::GLOBAL_CONSENSUS.to_vec(), data, true);
    }

    fn publish_prover_message(&self, data: Vec<u8>) {
        // Prover-admin messages (e.g. ProverKick) stay on GLOBAL_PROVER
        // gossip — unchanged from the BlossomSub publisher.
        let handle = self.p2p_handle.clone();
        let bitmask = quil_engine::bitmasks::GLOBAL_PROVER.to_vec();
        self.spawner.detach("direct-publish-prover", async move {
            let req = match quil_execution::message_envelope::CanonicalMessageRequest::from_canonical_bytes(&data) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "publish_prover_message: bad MessageRequest envelope");
                    return Ok(());
                }
            };
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let bundle = quil_execution::message_envelope::CanonicalMessageBundle {
                requests: vec![Some(req)],
                timestamp,
            };
            match bundle.to_canonical_bytes() {
                Ok(bytes) => {
                    if let Err(e) = handle.publish(bitmask, bytes).await {
                        tracing::warn!(error = %e, "publish_prover_message failed");
                    }
                }
                Err(e) => tracing::error!(error = %e, "publish_prover_message: bundle encode failed"),
            }
            Ok(())
        });
    }
}
