//! BlossomSub side of the proxy: a libp2p host that meshes with every node,
//! relays gossip, and applies bipartite network partitions via the per-(src,dst)
//! forward filter. It also decodes consensus messages off the global-consensus
//! bitmask and forwards them to the event loop.
//!
//! Built on `quil-p2p`'s `P2PNode`/`P2PHandle` (reusing the production
//! BlossomSub) plus the `set_forward_filter` hook added for devnet. Mirrors the
//! Go proxy's `BlossomSubProxy`.

use std::sync::Arc;

use anyhow::Context;
use quil_config::P2PConfig;
use quil_engine::bitmasks;
use quil_lifecycle::Supervisor;
use quil_p2p::node::P2PNode;
use quil_p2p::P2PHandle;
use tokio::sync::mpsc;

use crate::consensus_events::{extract_consensus_event, ConsensusEvent};
use crate::partitioner::NetworkPartitioner;

/// Default QUIC listen address when the config doesn't specify one.
const DEFAULT_LISTEN: &str = "/ip4/0.0.0.0/udp/8336/quic-v1";

/// The proxy's gossip layer. Owns the libp2p handle and the shared partitioner.
pub struct BlossomSubProxy {
    /// Retained to keep the swarm alive — dropping the last `P2PHandle` makes
    /// the swarm command loop see `None` and shut down. The proxy only relays
    /// (via the forward filter) and never publishes, so the handle is otherwise
    /// unused.
    #[allow(dead_code)]
    handle: P2PHandle,
    partitioner: Arc<NetworkPartitioner>,
}

impl BlossomSubProxy {
    /// Build the host, install the partition forward filter, subscribe to the
    /// four global bitmasks, and spawn the consensus-decode loop. The swarm and
    /// consumer tasks are registered on `sup`. Consensus events decoded off the
    /// global-consensus bitmask are sent to `consensus_tx`.
    pub async fn start(
        sup: &mut Supervisor<anyhow::Error>,
        p2p_config: &P2PConfig,
        partitioner: Arc<NetworkPartitioner>,
        consensus_tx: mpsc::Sender<ConsensusEvent>,
    ) -> anyhow::Result<Self> {
        let node = P2PNode::new(p2p_config).context("construct P2PNode")?;
        let listen_addr = if p2p_config.listen_multiaddr.is_empty() {
            DEFAULT_LISTEN.to_string()
        } else {
            p2p_config.listen_multiaddr.clone()
        };
        let (handle, mut msg_rx) = node
            .start(sup, &listen_addr)
            .await
            .context("start P2P swarm")?;

        // Install the partition forward filter. The closure captures the shared
        // partitioner, so later `apply_partition` calls take effect live without
        // reinstalling the filter.
        {
            let p = Arc::clone(&partitioner);
            handle
                .set_forward_filter(move |src, dst| p.forward_filter(src, dst))
                .await;
        }

        // Subscribe before relaying — BlossomSub only forwards on subscribed
        // bitmasks, and rejects publishes to unsubscribed ones.
        handle.subscribe(bitmasks::GLOBAL_CONSENSUS.to_vec()).await;
        handle.subscribe(bitmasks::GLOBAL_PROVER.to_vec()).await;
        handle.subscribe(bitmasks::GLOBAL_PEER_INFO.to_vec()).await;
        handle.subscribe(bitmasks::GLOBAL_ALERT.to_vec()).await;
        tracing::info!("proxy subscribed to all global bitmasks");

        // Consensus-decode loop: surface rank/frame/timeout signals to the
        // event loop. Dropped on shutdown via the supervisor token.
        sup.run_until_cancelled("blossomsub-consumer", move |_token| async move {
            while let Some(msg) = msg_rx.recv().await {
                if msg.bitmask.as_slice() == bitmasks::GLOBAL_CONSENSUS {
                    if let Some(event) = extract_consensus_event(&msg.data) {
                        tracing::debug!(
                            rank = event.rank,
                            frame_number = event.frame_number,
                            is_timeout = event.is_timeout,
                            "decoded global consensus message"
                        );
                        if consensus_tx.send(event).await.is_err() {
                            break; // event loop gone
                        }
                    }
                }
            }
            Ok(())
        });

        Ok(Self {
            handle,
            partitioner,
        })
    }

    /// Replace the partition state: clear all partitions and block every
    /// `group1 × group2` peer pair. Each element is a base58 peer ID.
    pub fn apply_partition(&self, group1: &[String], group2: &[String]) {
        self.partitioner.apply_partition(group1, group2);
    }

    /// Remove all network partitions.
    pub fn clear_partitions(&self) {
        self.partitioner.clear_partitions();
    }
}
