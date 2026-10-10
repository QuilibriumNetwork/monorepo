//! BlossomSub side of the proxy: a libp2p host that meshes with every node,
//! relays gossip, and applies bipartite network partitions via the per-(src,dst)
//! forward filter.
//!
//! Gossip carries no consensus signal any more — global consensus moved to
//! point-to-point gRPC on `:8340` in v2.1.0.25, and the node now counts and
//! drops anything arriving on the `GLOBAL_CONSENSUS` topic. The proxy snoops
//! consensus off the gRPC path instead (see `crate::consensus_events`), so this
//! side only relays and partitions.
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

use crate::partitioner::NetworkPartitioner;

/// Default QUIC listen address when the config doesn't specify one.
const DEFAULT_LISTEN: &str = "/ip4/0.0.0.0/udp/8336/quic-v1";

/// The proxy's gossip layer.
///
/// Holding this value is what keeps the swarm alive — dropping the last
/// `P2PHandle` makes the swarm command loop see `None` and shut down. The proxy
/// only relays (via the forward filter) and never publishes, so there is nothing
/// to call on it; partitions are driven through the shared
/// [`NetworkPartitioner`] the forward filter closes over.
pub struct BlossomSubProxy {
    #[allow(dead_code)]
    handle: P2PHandle,
}

impl BlossomSubProxy {
    /// Build the host, install the partition forward filter, and subscribe to
    /// the four global bitmasks. The swarm task is registered on `sup`.
    pub async fn start(
        sup: &mut Supervisor<anyhow::Error>,
        p2p_config: &P2PConfig,
        partitioner: Arc<NetworkPartitioner>,
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

        // Drain received gossip. The proxy consumes nothing from it — relaying
        // happens inside the swarm, behind the forward filter — but the receiver
        // must keep being emptied or the swarm backs up behind a full channel.
        sup.run_until_cancelled("blossomsub-consumer", move |_token| async move {
            while msg_rx.recv().await.is_some() {}
            Ok(())
        });

        Ok(Self { handle })
    }
}
