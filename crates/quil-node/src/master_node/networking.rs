use tracing::{info, warn};

use quil_lifecycle::Supervisor;

pub(crate) struct P2pHandles {
    pub p2p_handle: quil_p2p::node::P2PHandle,
    pub msg_rx: tokio::sync::mpsc::Receiver<quil_p2p::node::ReceivedMessage>,
    pub peer_id: quil_p2p::PeerId,
    pub consensus_loopback_tx: tokio::sync::mpsc::Sender<quil_p2p::node::ReceivedMessage>,
    pub consensus_loopback_rx: tokio::sync::mpsc::Receiver<quil_p2p::node::ReceivedMessage>,
    pub listen_addr: String,
}

pub(crate) async fn init(
    sup: &mut Supervisor<anyhow::Error>,
    config: &quil_config::Config,
    config_dir: &std::path::Path,
    network: u8,
    archive_mode: bool,
) -> anyhow::Result<P2pHandles> {
    // ---------------------------------------------------------------
    // 5. Start P2P networking
    // ---------------------------------------------------------------
    let listen_addr = if config.p2p.listen_multiaddr.is_empty() {
        "/ip4/0.0.0.0/udp/8336/quic-v1".to_string()
    } else {
        config.p2p.listen_multiaddr.clone()
    };

    // CLI `--network` is the source of truth — override the YAML's
    // `p2p.network` so a single config file can be reused across
    // networks without the BlossomSub protocol id falling back to
    // the mainnet variant on testnet runs.
    let mut p2p_config = config.p2p.clone();
    p2p_config.network = network;
    let p2p_node = quil_p2p::node::P2PNode::new(&p2p_config)?;
    let peer_id = p2p_node.peer_id;
    info!(
        key_type = if config.p2p.peer_priv_key.is_empty() { "generated Ed448" } else { "loaded from config" },
        %peer_id,
        "P2P identity ready"
    );

    // Persist newly generated Ed448 key to config
    if let Some(key_hex) = &p2p_node.generated_key_hex {
        let mut updated_config = config.clone();
        updated_config.p2p.peer_priv_key = key_hex.clone();
        if let Err(e) = quil_config::save_config(config_dir, &updated_config) {
            warn!(error = %e, "failed to save generated peer key to config");
        } else {
            info!("saved new Ed448 peer key to config (peer ID is now stable)");
        }
    }

    info!(%peer_id, "starting P2P networking");

    let (p2p_handle, msg_rx) = p2p_node.start(sup, &listen_addr).await?;
    info!(listen = %listen_addr, "P2P swarm started");

    // Self-loopback channel for consensus messages — used by
    // `BlossomsubConsensusPublisher::publish_consensus` to feed the
    // local node's own outbound proposal/vote back into the dispatcher
    // (BlossomSub does not echo self-published messages, so without
    // this the proposer's own state never reaches its own
    // `vote_aggregator` / event_loop).
    let (consensus_loopback_tx, consensus_loopback_rx) =
        tokio::sync::mpsc::channel::<quil_p2p::node::ReceivedMessage>(256);

    // GLOBAL_FRAME subscription is archive-only — non-archive nodes
    // get the chain head via the archive poller and don't need the
    // gossip firehose (matches Go's behavior). Subscribing on a
    // In Go, all global-bitmask subscriptions except GLOBAL_PEER_INFO
    // are gated on `isConsensusParticipant()` which is `ArchiveMode ||
    // Network == 99`. Non-archive nodes receive frames from the
    // archive poller, submit prover messages via direct gRPC, and
    // participate in per-shard consensus only (subscribed dynamically
    // by the AppConsensusEngine). Subscribing to GLOBAL_CONSENSUS on
    // a non-archive causes every global-frame vote/proposal from every
    // archive to be relayed through the non-archive — massive
    // bandwidth and processing overhead with zero benefit.
    //
    // Archives also do a bulk subscribe to `[0xFF; 32]` (catches all
    // shard traffic via bloom overlap) for the app-frames queue.
    if archive_mode {
        p2p_handle.subscribe(quil_engine::bitmasks::GLOBAL_FRAME.to_vec()).await;
        p2p_handle.subscribe(quil_engine::bitmasks::GLOBAL_CONSENSUS.to_vec()).await;
        p2p_handle.subscribe(quil_engine::bitmasks::GLOBAL_PROVER.to_vec()).await;
        // Bulk shard subscription — mirrors Go's `bytes.Repeat([]byte{0xff}, 32)`
        // inside `subscribeToGlobalConsensus`. Catches all per-shard frame/
        // consensus/prover traffic via bloom-filter overlap.
        p2p_handle.subscribe(vec![0xFFu8; 32]).await;
    }
    p2p_handle.subscribe(quil_engine::bitmasks::GLOBAL_PEER_INFO.to_vec()).await;
    p2p_handle.subscribe(quil_engine::bitmasks::GLOBAL_ALERT.to_vec()).await;
    if archive_mode {
        info!("subscribed to all global + bulk shard bitmasks (archive mode)");
    } else {
        info!("subscribed to GLOBAL_PEER_INFO + GLOBAL_ALERT (non-archive)");
    }

    // Apply engine blacklist — deny connections from blacklisted peers.
    // Blacklist entries are peer ID strings (Qm... multihash format).
    for peer_str in &config.engine.blacklist {
        if let Ok(peer_id) = peer_str.parse::<quil_p2p::PeerId>() {
            p2p_handle.blacklist_peer(peer_id).await;
            info!(peer = %peer_id, "blacklisted peer from config");
        }
    }

    Ok(P2pHandles {
        p2p_handle,
        msg_rx,
        peer_id,
        consensus_loopback_tx,
        consensus_loopback_rx,
        listen_addr,
    })
}
