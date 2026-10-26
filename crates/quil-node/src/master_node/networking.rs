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
    // Raw 1281-byte Falcon-512 signing key (the q-prover-key) — the libp2p
    // NETWORK identity under the Rust-only flag day.
    falcon_signing_key: &[u8],
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

    // Ensure the Ed448 SENIORITY-ROOT key exists (persisted in
    // config.p2p.peer_priv_key). It is NO LONGER the network identity — that is
    // the Falcon q-prover-key below — but seniority is anchored to it, so a
    // fresh node must still have one.
    if p2p_config.peer_priv_key.is_empty() {
        let id = quil_p2p::Ed448Identity::generate()?;
        let key_hex = id.to_config_hex();
        p2p_config.peer_priv_key = key_hex.clone();
        let mut updated_config = config.clone();
        updated_config.p2p.peer_priv_key = key_hex;
        if let Err(e) = quil_config::save_config(config_dir, &updated_config) {
            warn!(error = %e, "failed to save generated Ed448 seniority-root key to config");
        } else {
            info!("generated Ed448 seniority-root key (saved to config)");
        }
    }

    // Network identity = the Falcon q-prover-key. The Ed448 key above is kept
    // only as the seniority root and never derives the peer-id.
    let p2p_node =
        quil_p2p::node::P2PNode::new_with_falcon_identity(&p2p_config, falcon_signing_key)?;
    let peer_id = p2p_node.peer_id;
    info!(%peer_id, "P2P identity ready (Falcon network identity)");

    info!(%peer_id, "starting P2P networking");

    let (p2p_handle, msg_rx) = p2p_node.start(sup, &listen_addr).await?;
    info!(listen = %listen_addr, "P2P swarm started");

    // Self-loopback channel for consensus messages — used by
    // `DirectGlobalConsensusPublisher::fan_out` to feed the local node's
    // own outbound message back into the dispatcher when loopback is
    // requested (the :8340 fan-out does not deliver to self).
    // Capacity sized to absorb bursts of peer proposals/votes without
    // dropping. The delivery handler drops a peer's consensus message when
    // this fills (grpc.rs), and dropped peer votes directly threaten the
    // 2f+1 quorum, so give the drain task ample headroom over the small
    // global committee's per-rank message volume.
    let (consensus_loopback_tx, consensus_loopback_rx) =
        tokio::sync::mpsc::channel::<quil_p2p::node::ReceivedMessage>(4096);

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
    // GLOBAL_FRAME is now subscribed by ALL nodes: the CW committee gossip-
    // publishes each finalized global frame (see `GlobalSeamFinalizer`), so
    // regular/non-committee nodes receive the chain head over gossip instead of
    // RPC-polling archives (the archive poller stays as gap-fill / catch-up).
    // GLOBAL_CONSENSUS/GLOBAL_PROVER + the bulk-shard subscribes remain archive-
    // only — their bandwidth rationale (vote firehose, all-shard coverage) still
    // holds and non-archives don't need them.
    p2p_handle
        .subscribe(quil_engine::bitmasks::GLOBAL_FRAME.to_vec())
        .await;
    // Mesh-level gate on GLOBAL_FRAME: shed wrong-type garbage and rate-limit
    // per peer BEFORE delivery/forward, so a peer flooding the topic (the CPU-DoS
    // vector — each frame otherwise forces a downstream VDF verify) is penalised
    // by gossip scoring and its floods stop propagating. The authoritative
    // genesis-prover + committee-cert + VDF checks still run in the recv loop.
    p2p_handle
        .register_global_frame_validator(
            quil_engine::bitmasks::GLOBAL_FRAME.to_vec(),
            quil_engine::consensus_wire::GLOBAL_FRAME_TYPE,
        )
        .await;
    if archive_mode {
        p2p_handle
            .subscribe(quil_engine::bitmasks::GLOBAL_CONSENSUS.to_vec())
            .await;
        p2p_handle
            .subscribe(quil_engine::bitmasks::GLOBAL_PROVER.to_vec())
            .await;
        // Bulk shard subscription — an all-ones bitmask bit-COVERS every
        // specific per-shard bloom, so coverage classification meshes the
        // archive with the provers. The four per-shard channels are different
        // LENGTHS due to their prefix bytes: frame=`filter` (32),
        // consensus=`0x00‖filter` (33), dispatch=`0x00 0x00‖filter` (34),
        // prover=`0x00 0x00 0x00‖filter` (35). `bitmask_covers` requires equal
        // length, so we subscribe at EACH length — otherwise the archive relays
        // proposals (frame) but not votes (consensus) and app-shard consensus
        // stalls with no QC.
        for len in [32usize, 33, 34, 35] {
            p2p_handle.subscribe(vec![0xFFu8; len]).await;
        }
        // Mesh-level checks on the archive-only global topics: a prover
        // message must be a prover operation, bundle or request (the receive
        // loop's own check), and GLOBAL_CONSENSUS carries nothing any release
        // reads.
        // Refused messages are ignored, not rejected: releases before these
        // checks forward them, and penalising those relays would cut them off
        // the mesh.
        let prover_check = quil_engine::message_router::validator_global_prover();
        p2p_handle
            .register_gossip_validator(
                quil_engine::bitmasks::GLOBAL_PROVER.to_vec(),
                Box::new(move |_peer: &quil_p2p::PeerId, data: &[u8]| {
                    if prover_check(data).is_accept() {
                        quil_p2p::ValidationResult::Accept
                    } else {
                        quil_p2p::ValidationResult::Ignore
                    }
                }),
            )
            .await;
        p2p_handle
            .register_gossip_validator(
                quil_engine::bitmasks::GLOBAL_CONSENSUS.to_vec(),
                Box::new(|_peer: &quil_p2p::PeerId, _data: &[u8]| {
                    quil_p2p::ValidationResult::Ignore
                }),
            )
            .await;
    }
    p2p_handle
        .subscribe(quil_engine::bitmasks::GLOBAL_PEER_INFO.to_vec())
        .await;
    // Drop stale or invalid PeerInfo/KeyRegistry at the MESH (before forward),
    // not just at the app router. Both ride the GLOBAL_PEER_INFO bitmask; without this the
    // composite broker re-gossips millions of already-stale PeerInfo/KeyRegistry
    // per hour (`*_ts_too_old`), self-amplifying the flood and bloating the
    // gossip dedup caches. The app router still fully validates the fresh ones.
    p2p_handle
        .register_peer_info_staleness_validator(quil_engine::bitmasks::GLOBAL_PEER_INFO.to_vec())
        .await;
    p2p_handle
        .subscribe(quil_engine::bitmasks::GLOBAL_ALERT.to_vec())
        .await;
    // Forward only alerts the receive loop can verify.
    p2p_handle
        .register_global_alert_validator(quil_engine::bitmasks::GLOBAL_ALERT.to_vec())
        .await;
    // Topics without a validator of their own: the shard topics, subscribed as
    // shards come and go.
    p2p_handle
        .register_fallback_validator(Box::new(
            |_peer: &quil_p2p::PeerId, bitmask: &[u8], data: &[u8]| {
                shard_gossip_verdict(bitmask, data)
            },
        ))
        .await;
    if archive_mode {
        info!("subscribed to all global + bulk shard bitmasks (archive mode)");
    } else {
        info!("subscribed to GLOBAL_FRAME + GLOBAL_PEER_INFO + GLOBAL_ALERT (non-archive)");
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

/// The mesh verdict on a message of a topic without a validator of its own.
/// On a shard CW topic (`0x01 ‖ appFilter`) a transmission must split into one
/// of the CW channels with a payload
/// ([`quil_engine::bitmasks::shard_cw_split_payload`]): the receive loop drops
/// anything else unread, so it is not forwarded either. It is ignored, not
/// rejected: releases before this check forward such messages. Messages of
/// other topics are accepted, as before.
pub(crate) fn shard_gossip_verdict(bitmask: &[u8], data: &[u8]) -> quil_p2p::ValidationResult {
    let shard_cw_topic = bitmask.len() == 33 && bitmask[0] == 0x01;
    if !shard_cw_topic {
        return quil_p2p::ValidationResult::Accept;
    }
    match quil_engine::bitmasks::shard_cw_split_payload(data) {
        Some((channel, cw_bytes))
            if channel <= quil_engine::cw_app_seams::CW_APP_BLOCK_CHANNEL
                && !cw_bytes.is_empty() =>
        {
            quil_p2p::ValidationResult::Accept
        }
        _ => quil_p2p::ValidationResult::Ignore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_p2p::ValidationResult::{Accept, Ignore};

    /// Shard CW transmissions of every framing a release sends are forwarded;
    /// malformed ones and unknown channels are dropped without penalty, and
    /// other topics are unaffected.
    #[test]
    fn shard_cw_transmissions_are_checked_at_the_mesh() {
        let filter = [7u8; 32];
        let topic = quil_engine::bitmasks::shard_cw_bitmask(&filter);
        let vote = b"vote bytes";
        for channel in 0..=quil_engine::cw_app_seams::CW_APP_BLOCK_CHANNEL {
            let framed = quil_engine::bitmasks::shard_cw_frame_payload(channel, vote);
            assert_eq!(shard_gossip_verdict(&topic, &framed), Accept);
            let addressed =
                quil_engine::bitmasks::shard_cw_frame_for(channel, vote, &[vec![1; 897]]);
            assert_eq!(shard_gossip_verdict(&topic, &addressed), Accept);
            let mut legacy = vec![channel as u8];
            legacy.extend_from_slice(vote);
            assert_eq!(shard_gossip_verdict(&topic, &legacy), Accept);
        }
        let unknown = quil_engine::bitmasks::shard_cw_frame_payload(4, vote);
        assert_eq!(shard_gossip_verdict(&topic, &unknown), Ignore);
        assert_eq!(shard_gossip_verdict(&topic, &[]), Ignore);
        assert_eq!(shard_gossip_verdict(&topic, &[0x80, 1, 2]), Ignore);
        assert_eq!(shard_gossip_verdict(&topic, &[0]), Ignore);
        let frame_topic = quil_engine::bitmasks::shard_frame_bitmask(&filter);
        assert_eq!(shard_gossip_verdict(&frame_topic, &[]), Accept);
        assert_eq!(shard_gossip_verdict(&[0x01; 33], b"anything"), Ignore);
    }
}
