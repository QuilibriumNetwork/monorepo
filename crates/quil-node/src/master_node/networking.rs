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
    let role = if archive_mode {
        MeshRole::Archive
    } else {
        MeshRole::Master
    };
    join_global_topics(&p2p_handle, role).await;
    if archive_mode {
        // Bulk shard subscription — an all-ones bitmask bit-COVERS every
        // specific per-shard bloom, so coverage classification meshes the
        // archive with the provers. The four per-shard channels are different
        // LENGTHS due to their prefix bytes: frame=`filter` (32),
        // consensus=`0x00‖filter` (33), dispatch=`0x00 0x00‖filter` (34),
        // prover=`0x00 0x00 0x00‖filter` (35). `bitmask_covers` requires equal
        // length, so we subscribe at EACH length — otherwise the archive relays
        // proposals (frame) but not votes (consensus) and app-shard consensus
        // stalls with no QC.
        for len in ARCHIVE_BULK_LENGTHS {
            p2p_handle.subscribe(vec![0xFFu8; len]).await;
        }
    }
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

/// Bitmask lengths of an archive's bulk shard subscriptions, `[0xFF; len]`
/// (see `init`).
pub(crate) const ARCHIVE_BULK_LENGTHS: [usize; 4] = [32, 33, 34, 35];

/// The p2p whose global topics and mesh checks [`join_global_topics`] sets up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MeshRole {
    /// A master that is not an archive.
    Master,
    /// An archive master.
    Archive,
    /// A standalone worker's own p2p (`engine.enableMasterProxy` off).
    Worker,
}

/// The mesh check of a global topic (see [`register_mesh_checks`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GlobalCheck {
    /// GLOBAL_FRAME's gate: type prefix and per-author rate.
    Frame,
    /// GLOBAL_CONSENSUS: nothing any release reads.
    Consensus,
    /// GLOBAL_PROVER: a prover operation, bundle or request.
    Prover,
    /// GLOBAL_PEER_INFO: freshness, size and signatures.
    PeerInfo,
    /// GLOBAL_ALERT: the canonical layout.
    Alert,
}

/// The global topics a node of `role` subscribes, each with its mesh check.
/// Every master subscribes GLOBAL_FRAME (the committee gossips each
/// finalized global frame), GLOBAL_PEER_INFO and GLOBAL_ALERT; archives also
/// GLOBAL_CONSENSUS and GLOBAL_PROVER. A standalone worker's own p2p
/// subscribes GLOBAL_PEER_INFO (peer discovery) and GLOBAL_ALERT only: it gets
/// frames over the master's stream, submits prover messages over gRPC, and
/// serves per-shard consensus only, subscribed as its shard starts.
pub(crate) fn global_topics(role: MeshRole) -> Vec<(&'static [u8], GlobalCheck)> {
    use quil_engine::bitmasks::{
        GLOBAL_ALERT, GLOBAL_CONSENSUS, GLOBAL_FRAME, GLOBAL_PEER_INFO, GLOBAL_PROVER,
    };
    let mut topics = Vec::new();
    if role != MeshRole::Worker {
        topics.push((GLOBAL_FRAME, GlobalCheck::Frame));
    }
    if role == MeshRole::Archive {
        topics.push((GLOBAL_CONSENSUS, GlobalCheck::Consensus));
        topics.push((GLOBAL_PROVER, GlobalCheck::Prover));
    }
    topics.push((GLOBAL_PEER_INFO, GlobalCheck::PeerInfo));
    topics.push((GLOBAL_ALERT, GlobalCheck::Alert));
    topics
}

/// Registers the mesh checks of a node of `role`, then subscribes its
/// global topics ([`global_topics`]), so that nothing a topic carries is
/// delivered or forwarded unchecked. A standalone worker's p2p gets the
/// master's checks: without them it forwarded what masters refuse, an
/// invalid PeerInfo among it, and their scores of it fell.
pub(crate) async fn join_global_topics(p2p: &quil_p2p::node::P2PHandle, role: MeshRole) {
    register_mesh_checks(p2p, role).await;
    for (topic, _) in global_topics(role) {
        p2p.subscribe(topic.to_vec()).await;
    }
}

/// Registers the mesh check of each global topic of `role` and the fallback
/// of every other topic ([`shard_gossip_verdict`]). They run in the gossip
/// poll thread before a message is delivered or forwarded, so they stay
/// cheap; the receive loop still runs the authoritative checks.
pub(crate) async fn register_mesh_checks(p2p: &quil_p2p::node::P2PHandle, role: MeshRole) {
    for (topic, check) in global_topics(role) {
        match check {
            // Shed wrong-type garbage and rate-limit per peer BEFORE
            // delivery/forward, so a peer flooding the topic (the CPU-DoS
            // vector — each frame otherwise forces a downstream VDF verify) is
            // penalised by gossip scoring and its floods stop propagating. The
            // authoritative genesis-prover + committee-cert + VDF checks still
            // run in the recv loop.
            GlobalCheck::Frame => {
                p2p.register_global_frame_validator(
                    topic.to_vec(),
                    quil_engine::consensus_wire::GLOBAL_FRAME_TYPE,
                )
                .await;
            }
            // The archive-only global topics: a prover message must be a
            // prover operation, bundle or request (the receive loop's own
            // check), and GLOBAL_CONSENSUS carries nothing any release reads.
            // Refused messages are ignored, not rejected: releases before
            // these checks forward them, and penalising those relays would cut
            // them off the mesh.
            GlobalCheck::Prover => {
                let prover_check = quil_engine::message_router::validator_global_prover();
                p2p.register_gossip_validator(
                    topic.to_vec(),
                    Box::new(move |_peer: &quil_p2p::PeerId, data: &[u8]| {
                        if prover_check(data).is_accept() {
                            quil_p2p::ValidationResult::Accept
                        } else {
                            quil_p2p::ValidationResult::Ignore
                        }
                    }),
                )
                .await;
            }
            GlobalCheck::Consensus => {
                p2p.register_gossip_validator(
                    topic.to_vec(),
                    Box::new(|_peer: &quil_p2p::PeerId, _data: &[u8]| {
                        quil_p2p::ValidationResult::Ignore
                    }),
                )
                .await;
            }
            // Drop stale or invalid PeerInfo/KeyRegistry at the MESH (before
            // forward), not just at the app router. Both ride the
            // GLOBAL_PEER_INFO bitmask; without this the composite broker
            // re-gossips millions of already-stale PeerInfo/KeyRegistry per
            // hour (`*_ts_too_old`), self-amplifying the flood and bloating the
            // gossip dedup caches. The app router still fully validates the
            // fresh ones.
            GlobalCheck::PeerInfo => {
                p2p.register_peer_info_staleness_validator(topic.to_vec())
                    .await;
            }
            // Forward only alerts the receive loop can verify.
            GlobalCheck::Alert => {
                p2p.register_global_alert_validator(topic.to_vec()).await;
            }
        }
    }
    // Topics without a validator of their own: the shard topics, subscribed as
    // shards come and go.
    p2p.register_fallback_validator(Box::new(
        |_peer: &quil_p2p::PeerId, bitmask: &[u8], data: &[u8]| shard_gossip_verdict(bitmask, data),
    ))
    .await;
}

/// The kinds of shard topic a node subscribes, by bitmask (`appFilter` is a
/// shard's 32-byte bloom, [`quil_engine::bitmasks::shard_app_filter`]), and
/// what the mesh makes of their messages ([`shard_gossip_verdict`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShardTopic {
    /// `appFilter`: finalized frames, accepted. A frame's check is its full
    /// verification, left to its reader.
    Frame,
    /// `0x00 ‖ appFilter`: the legacy consensus topic, ignored. Engines drop
    /// its messages unread, and no release publishes there.
    Consensus,
    /// `0x00 0x00 ‖ appFilter`: dispatch, accepted when it is a message
    /// bundle a leader can propose ([`shard_submission_well_formed`]); its
    /// operations are left to the shard's engine.
    Dispatch,
    /// `0x00 0x00 0x00 ‖ appFilter`: prover messages and an application's
    /// submissions, checked as dispatch is.
    Prover,
    /// `0x01 ‖ appFilter`: consensus transmissions, accepted when they frame
    /// one of the CW channels.
    Cw,
    /// `[0xFF; len]` ([`ARCHIVE_BULK_LENGTHS`]): an archive's bulk
    /// subscriptions, accepted.
    ArchiveBulk,
}

/// The kind of shard topic `bitmask` is, if it is one.
pub(crate) fn shard_topic(bitmask: &[u8]) -> Option<ShardTopic> {
    const FILTER: usize = 32;
    if ARCHIVE_BULK_LENGTHS.contains(&bitmask.len()) && bitmask.iter().all(|byte| *byte == 0xFF) {
        return Some(ShardTopic::ArchiveBulk);
    }
    match bitmask {
        filter if filter.len() == FILTER => Some(ShardTopic::Frame),
        [0x00, filter @ ..] if filter.len() == FILTER => Some(ShardTopic::Consensus),
        [0x01, filter @ ..] if filter.len() == FILTER => Some(ShardTopic::Cw),
        [0x00, 0x00, filter @ ..] if filter.len() == FILTER => Some(ShardTopic::Dispatch),
        [0x00, 0x00, 0x00, filter @ ..] if filter.len() == FILTER => Some(ShardTopic::Prover),
        _ => None,
    }
}

/// The mesh verdict on a message of a topic without a validator of its own.
/// On a shard CW topic a transmission must split into one of the CW channels
/// with a payload ([`quil_engine::bitmasks::shard_cw_split_payload`]): the
/// receive loop drops anything else unread, so it is not forwarded either.
/// Nothing on the legacy shard consensus topic is forwarded: no release reads
/// it. Both are ignored, not rejected: releases before these checks forward
/// such messages. On a shard dispatch or submission topic a message must be a
/// bundle a leader can propose ([`shard_submission_well_formed`]); anything
/// else is ignored before the strict shard gossip epoch
/// ([`quil_p2p::strict_shard_gossip`]) and rejected from it. Messages of
/// other topics are accepted, as before.
pub(crate) fn shard_gossip_verdict(bitmask: &[u8], data: &[u8]) -> quil_p2p::ValidationResult {
    shard_gossip_verdict_when(bitmask, data, quil_p2p::strict_shard_gossip())
}

/// Whether a message on a shard's dispatch or submission topic is one a
/// leader can propose: a message bundle that decodes as an application
/// shard's (`decode_app_message_bundle`), the leader's own check. A leader
/// drops anything else unread, so the mesh need not forward it. Its size is
/// bounded by the transport (`quil_p2p::protocol::MAX_MESSAGE_SIZE`, before
/// any check), the bound a frame carrying it must meet too; its operations
/// are left to the shard's engine.
pub(crate) fn shard_submission_well_formed(data: &[u8]) -> bool {
    quil_engine::consensus_wire::decode_app_message_bundle(data).is_ok()
}

/// [`shard_gossip_verdict`] with strict shard gossip `strict`.
pub(crate) fn shard_gossip_verdict_when(
    bitmask: &[u8],
    data: &[u8],
    strict: bool,
) -> quil_p2p::ValidationResult {
    match shard_topic(bitmask) {
        Some(ShardTopic::Cw) => match quil_engine::bitmasks::shard_cw_split_payload(data) {
            Some((channel, cw_bytes))
                if channel <= quil_engine::cw_app_seams::CW_APP_BLOCK_CHANNEL
                    && !cw_bytes.is_empty() =>
            {
                quil_p2p::ValidationResult::Accept
            }
            _ => quil_p2p::ValidationResult::Ignore,
        },
        Some(ShardTopic::Consensus) => quil_p2p::ValidationResult::Ignore,
        Some(ShardTopic::Dispatch | ShardTopic::Prover) => {
            if shard_submission_well_formed(data) {
                quil_p2p::ValidationResult::Accept
            } else if strict {
                quil_p2p::ValidationResult::Reject
            } else {
                quil_p2p::ValidationResult::Ignore
            }
        }
        _ => quil_p2p::ValidationResult::Accept,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_p2p::ValidationResult::{Accept, Ignore, Reject};
    use std::time::Duration;

    /// A message bundle of one operation, distinct for each `n`, as a wallet's
    /// node publishes it on an application's submission topic. Its operation
    /// is junk: the mesh checks the bundle, the engine its operations.
    fn submission(n: u32) -> Vec<u8> {
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let mut operation = 0x0512u32.to_be_bytes().to_vec();
        operation.extend_from_slice(&n.to_be_bytes());
        CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest::wrap(operation).unwrap())],
            timestamp: i64::from(n),
        }
        .to_canonical_bytes()
        .unwrap()
    }

    /// Messages on a shard dispatch or submission topic that no leader can
    /// propose, distinct for each `n` but the empty one: none is a bundle
    /// `decode_app_message_bundle` takes (junk, a truncated bundle, a bare
    /// request, a bundle carrying a retired token operation).
    fn undecodable_submissions(n: u32) -> Vec<Vec<u8>> {
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let mut junk = vec![0xEE; 64];
        junk.extend_from_slice(&n.to_be_bytes());
        let bundle = submission(n);
        let mut operation = 0x0512u32.to_be_bytes().to_vec();
        operation.extend_from_slice(&n.to_be_bytes());
        let request = CanonicalMessageRequest::wrap(operation)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        let retired = CanonicalMessageBundle {
            requests: vec![Some(
                CanonicalMessageRequest::wrap(0x0509u32.to_be_bytes().to_vec()).unwrap(),
            )],
            timestamp: i64::from(n),
        }
        .to_canonical_bytes()
        .unwrap();
        vec![
            Vec::new(),
            junk,
            bundle[..bundle.len() - 1].to_vec(),
            request,
            retired,
        ]
    }

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

    /// The legacy shard consensus topic is dropped at the mesh without
    /// penalty, whatever it carries; the other shard topics are unaffected.
    #[test]
    fn legacy_shard_consensus_gossip_is_ignored_at_the_mesh() {
        let filter = [7u8; 32];
        let consensus = quil_engine::bitmasks::shard_consensus_bitmask(&filter);
        assert_eq!(shard_topic(&consensus), Some(ShardTopic::Consensus));
        for data in [&b""[..], &b"vote"[..], &[0x80u8; 64][..]] {
            assert_eq!(shard_gossip_verdict(&consensus, data), Ignore);
        }
        let frame_topic = quil_engine::bitmasks::shard_frame_bitmask(&filter);
        assert_eq!(shard_gossip_verdict(&frame_topic, b"vote"), Accept);
        for topic in [
            quil_engine::bitmasks::shard_dispatch_bitmask(&filter),
            quil_engine::bitmasks::app_prover_bitmask(&filter),
        ] {
            assert_eq!(shard_gossip_verdict(&topic, &submission(1)), Accept);
        }
    }

    /// On a shard dispatch or submission topic the mesh forwards a message
    /// bundle a leader can propose, and drops anything else: without penalty
    /// before the strict shard gossip epoch, rejected from it. The other shard
    /// topics are unaffected.
    #[test]
    fn shard_submissions_are_checked_at_the_mesh() {
        let filter = [7u8; 32];
        for topic in [
            quil_engine::bitmasks::shard_dispatch_bitmask(&filter),
            quil_engine::bitmasks::app_prover_bitmask(&filter),
        ] {
            for strict in [false, true] {
                assert_eq!(
                    shard_gossip_verdict_when(&topic, &submission(1), strict),
                    Accept
                );
                for junk in undecodable_submissions(1) {
                    assert_eq!(
                        shard_gossip_verdict_when(&topic, &junk, strict),
                        if strict { Reject } else { Ignore },
                        "{} on {}",
                        hex::encode(&junk),
                        hex::encode(&topic)
                    );
                }
            }
        }
        let frame_topic = quil_engine::bitmasks::shard_frame_bitmask(&filter);
        assert_eq!(shard_gossip_verdict_when(&frame_topic, &[], true), Accept);
        let consensus = quil_engine::bitmasks::shard_consensus_bitmask(&filter);
        assert_eq!(
            shard_gossip_verdict_when(&consensus, &submission(1), true),
            Ignore
        );
    }

    /// Class guard: every topic a node subscribes has a mesh check. Each
    /// global topic gets its own ([`global_topics`], registered by
    /// [`register_mesh_checks`]). Every shard topic a master, an archive or a
    /// standalone worker subscribes is of a kind [`shard_topic`] names, for the
    /// fallback, and junk on it is forwarded only for the kinds whose check is
    /// left to their reader: a shard frame (its full verification) and an
    /// archive's bulk subscriptions. A topic of a new kind fails here until it
    /// gets a check.
    #[test]
    fn every_subscribed_topic_has_a_mesh_check() {
        let filter = [7u8; 32];
        let master: Vec<Vec<u8>> = super::super::worker_manager::shard_topics(&filter)
            .into_iter()
            .chain([quil_engine::bitmasks::shard_cw_bitmask(&filter)])
            .collect();
        let archive: Vec<Vec<u8>> = ARCHIVE_BULK_LENGTHS
            .iter()
            .map(|len| vec![0xFFu8; *len])
            .chain([quil_engine::bitmasks::shard_frame_bitmask(&filter)])
            .collect();
        let worker = quil_engine::worker_node::shard_bitmasks(&filter);
        for (role, subscribed) in [
            (MeshRole::Master, master),
            (MeshRole::Archive, archive),
            (MeshRole::Worker, worker),
        ] {
            for (topic, _) in global_topics(role) {
                assert_eq!(
                    shard_topic(topic),
                    None,
                    "{role:?}: the global topic {} is taken for a shard topic",
                    hex::encode(topic)
                );
            }
            for topic in &subscribed {
                let Some(kind) = shard_topic(topic) else {
                    panic!(
                        "{role:?} subscribes {} without a mesh check",
                        hex::encode(topic)
                    );
                };
                let forwarded = [&b""[..], &[0xEEu8; 64][..]]
                    .into_iter()
                    .any(|junk| shard_gossip_verdict(topic, junk) == Accept);
                assert!(
                    !forwarded || matches!(kind, ShardTopic::Frame | ShardTopic::ArchiveBulk),
                    "{role:?}: junk on {} ({kind:?}) is forwarded unchecked",
                    hex::encode(topic)
                );
            }
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    type Inbound = tokio::sync::mpsc::Receiver<quil_p2p::node::ReceivedMessage>;

    /// Three nodes on loopback subscribed to the same topics. The source and
    /// the sink connect only to the relay (loopback addresses are not
    /// routable, so neither learns of the other): what the sink receives from
    /// the source, the relay forwarded.
    struct Chain {
        _sup: quil_lifecycle::Supervisor<anyhow::Error>,
        source: quil_p2p::node::P2PHandle,
        source_id: quil_p2p::PeerId,
        relay: quil_p2p::node::P2PHandle,
        relay_id: quil_p2p::PeerId,
        relay_port: u16,
        sink: quil_p2p::node::P2PHandle,
        sink_rx: Inbound,
        _inbound: Vec<Inbound>,
    }

    async fn start_node(
        sup: &mut quil_lifecycle::Supervisor<anyhow::Error>,
        relay: Option<(u16, quil_p2p::PeerId)>,
    ) -> (quil_p2p::node::P2PHandle, quil_p2p::PeerId, u16, Inbound) {
        let config = quil_config::P2PConfig {
            network: 99,
            bootstrap_peers: relay
                .map(|(port, id)| vec![format!("/ip4/127.0.0.1/tcp/{port}/p2p/{id}")])
                .unwrap_or_default(),
            direct_peers: Vec::new(),
            ..Default::default()
        };
        let node = quil_p2p::node::P2PNode::new_with_options(&config, true, None).unwrap();
        let id = node.peer_id;
        let port = free_port();
        let (handle, inbound) = node
            .start(sup, &format!("/ip4/127.0.0.1/tcp/{port}"))
            .await
            .unwrap();
        (handle, id, port, inbound)
    }

    /// The chain, with the relay and the sink set up as nodes of their roles
    /// ([`join`]) and every node also subscribed to `topics`.
    async fn chain(
        topics: &[&[u8]],
        relay_role: Option<MeshRole>,
        sink_role: Option<MeshRole>,
    ) -> Chain {
        let mut sup = quil_lifecycle::Supervisor::<anyhow::Error>::new();
        let (relay, relay_id, relay_port, relay_rx) = start_node(&mut sup, None).await;
        let (source, source_id, _, source_rx) =
            start_node(&mut sup, Some((relay_port, relay_id))).await;
        let (sink, _, _, sink_rx) = start_node(&mut sup, Some((relay_port, relay_id))).await;
        join(&relay, relay_role).await;
        join(&sink, sink_role).await;
        for p2p in [&relay, &source, &sink] {
            for topic in topics {
                p2p.subscribe(topic.to_vec()).await;
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        for topic in topics {
            loop {
                let peers = relay
                    .subscribed_peer_count(topic.to_vec())
                    .await
                    .unwrap_or(0);
                if peers >= 2 {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the chain never formed: the relay sees {peers} of 2 peers on {}",
                    hex::encode(topic)
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        Chain {
            _sup: sup,
            source,
            source_id,
            relay,
            relay_id,
            relay_port,
            sink,
            sink_rx,
            _inbound: vec![relay_rx, source_rx],
        }
    }

    /// A GLOBAL_ALERT of the canonical layout, distinct for each `n`. Its
    /// signature is checked by the receive loop, not at the mesh, so every
    /// node forwards it.
    fn control_alert(n: u32) -> Vec<u8> {
        let message = format!("relay check {n}");
        let mut alert = 0x0911u32.to_be_bytes().to_vec();
        alert.extend_from_slice(&(message.len() as u32).to_be_bytes());
        alert.extend_from_slice(message.as_bytes());
        alert.extend_from_slice(&114u32.to_be_bytes());
        alert.extend_from_slice(&[7; 114]);
        alert
    }

    impl Chain {
        /// Publishes control alerts from the source until the sink receives
        /// one through the relay, then lets a few heartbeats graft the meshes
        /// of the other topics.
        async fn wait_for_meshes(&mut self) {
            let alert = quil_engine::bitmasks::GLOBAL_ALERT.to_vec();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            let mut n = 0;
            'publish: loop {
                let _ = self.source.publish(alert.clone(), control_alert(n)).await;
                n += 1;
                let turn = tokio::time::Instant::now() + Duration::from_secs(1);
                while let Ok(Some(message)) =
                    tokio::time::timeout_at(turn, self.sink_rx.recv()).await
                {
                    if message.bitmask == alert {
                        break 'publish;
                    }
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the relay never forwarded a control alert to the sink"
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Sets up `p2p` as a node of `role` does ([`join_global_topics`]), or
    /// leaves it without mesh checks.
    async fn join(p2p: &quil_p2p::node::P2PHandle, role: Option<MeshRole>) {
        if let Some(role) = role {
            join_global_topics(p2p, role).await;
        }
    }

    /// A standalone worker's own p2p must check what it forwards as a master
    /// does. Unchecked, it forwarded an invalid PeerInfo anyone may send, and
    /// the masters it relays to rejected it under strict validation and
    /// lowered the worker's score as an attacker's (repeats graylist it, its
    /// consensus messages with it). Each test runs in its own process under
    /// nextest, so the strict switch stays within this one.
    #[tokio::test]
    async fn reproduces_worker_relay_penalised_for_unchecked_gossip() {
        quil_p2p::set_strict_peer_info_validation(true);
        let peer_info = quil_engine::bitmasks::GLOBAL_PEER_INFO;
        let alert = quil_engine::bitmasks::GLOBAL_ALERT;
        let mut chain = chain(
            &[peer_info, alert],
            Some(MeshRole::Worker),
            Some(MeshRole::Master),
        )
        .await;
        chain.wait_for_meshes().await;

        // Fresh, with junk keys and signatures.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let invalid = quil_p2p::encode_canonical_peer_info(
            &quil_p2p::CanonicalPeerInfo {
                peer_id: vec![1; 38],
                timestamp: now_ms,
                ..Default::default()
            },
            &[2; 897],
            &[3; 666],
        );
        assert_eq!(
            quil_p2p::peer_info::peer_info_gossip_verdict(&invalid, now_ms),
            quil_p2p::peer_info::PeerInfoVerdict::Invalid
        );
        chain
            .source
            .publish(peer_info.to_vec(), invalid)
            .await
            .expect("publish the invalid PeerInfo");
        let last = control_alert(u32::MAX);
        chain
            .source
            .publish(alert.to_vec(), last.clone())
            .await
            .expect("publish the last control alert");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut arrived = false;
        while !arrived {
            let score = chain.sink.get_peer_score(chain.relay_id).await;
            assert!(
                score >= 0.0,
                "VULNERABLE: the worker's p2p forwarded an invalid PeerInfo it never checked, \
                 and the master it relays to scored it {score}"
            );
            if let Ok(Some(message)) =
                tokio::time::timeout(Duration::from_millis(100), chain.sink_rx.recv()).await
            {
                arrived = message.data == last;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the relay never forwarded the last control alert"
            );
        }
        let score = chain.sink.get_peer_score(chain.relay_id).await;
        assert!(
            score >= 0.0,
            "VULNERABLE: the worker's p2p forwarded an invalid PeerInfo it never checked, \
             and the master it relays to scored it {score}"
        );
        let sender = chain.relay.get_peer_score(chain.source_id).await;
        assert!(
            sender < 0.0,
            "the worker's p2p did not reject the invalid PeerInfo (its sender scores {sender})"
        );
    }

    /// Whether a PeerInfo is stale depends on the receiver's clock, so a
    /// master must drop a stale one without lowering its forwarder's score:
    /// rejecting it graylisted, on every topic, relays and originators whose
    /// clocks run a few minutes slow and releases that forward unchecked.
    #[tokio::test]
    async fn reproduces_stale_peer_info_penalising_its_forwarder() {
        let peer_info = quil_engine::bitmasks::GLOBAL_PEER_INFO;
        let alert = quil_engine::bitmasks::GLOBAL_ALERT;
        let mut chain = chain(&[peer_info, alert], Some(MeshRole::Master), None).await;
        chain.wait_for_meshes().await;

        // Six minutes old, with junk keys and signatures: dropped for its age
        // before anything else is checked.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let stale = quil_p2p::encode_canonical_peer_info(
            &quil_p2p::CanonicalPeerInfo {
                peer_id: vec![1; 38],
                timestamp: now_ms - 360_000,
                ..Default::default()
            },
            &[2; 897],
            &[3; 666],
        );
        assert_eq!(
            quil_p2p::peer_info::peer_info_gossip_verdict(&stale, now_ms),
            quil_p2p::peer_info::PeerInfoVerdict::Stale
        );
        chain
            .source
            .publish(peer_info.to_vec(), stale.clone())
            .await
            .expect("publish the stale PeerInfo");
        let last = control_alert(u32::MAX);
        chain
            .source
            .publish(alert.to_vec(), last.clone())
            .await
            .expect("publish the last control alert");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut received: Vec<quil_p2p::node::ReceivedMessage> = Vec::new();
        while !received.iter().any(|message| message.data == last) {
            match tokio::time::timeout_at(deadline, chain.sink_rx.recv()).await {
                Ok(Some(message)) => received.push(message),
                Ok(None) => panic!("the sink stopped"),
                Err(_) => panic!("the relay never forwarded the last control alert"),
            }
        }
        let score = chain.relay.get_peer_score(chain.source_id).await;
        assert!(
            score >= 0.0,
            "VULNERABLE: a master rejected a stale PeerInfo, which depends on its own \
             clock, and scored its forwarder {score}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        while let Ok(message) = chain.sink_rx.try_recv() {
            received.push(message);
        }
        assert!(
            !received.iter().any(|message| message.data == stale),
            "the master forwarded the stale PeerInfo"
        );
    }

    /// The legacy shard consensus topic (`0x00 ‖ appFilter`), subscribed for
    /// every shard a node serves, carries nothing any release reads, so a
    /// master must not forward what anyone publishes there: it reached every
    /// mesh peer and their engines' queues, beside the shard's votes.
    #[tokio::test]
    async fn reproduces_legacy_shard_consensus_gossip_relayed() {
        let consensus = quil_engine::bitmasks::shard_consensus_bitmask(&[7u8; 32]);
        let alert = quil_engine::bitmasks::GLOBAL_ALERT;
        let mut chain = chain(&[consensus.as_slice(), alert], Some(MeshRole::Master), None).await;
        chain.wait_for_meshes().await;

        chain
            .source
            .publish(consensus.clone(), b"read by no release".to_vec())
            .await
            .expect("publish on the legacy shard consensus topic");
        let last = control_alert(u32::MAX);
        chain
            .source
            .publish(alert.to_vec(), last.clone())
            .await
            .expect("publish the last control alert");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut received: Vec<quil_p2p::node::ReceivedMessage> = Vec::new();
        while !received.iter().any(|message| message.data == last) {
            match tokio::time::timeout_at(deadline, chain.sink_rx.recv()).await {
                Ok(Some(message)) => received.push(message),
                Ok(None) => panic!("the sink stopped"),
                Err(_) => panic!("the relay never forwarded the last control alert"),
            }
        }
        // Anything the relay forwarded before the last alert has arrived.
        tokio::time::sleep(Duration::from_millis(500)).await;
        while let Ok(message) = chain.sink_rx.try_recv() {
            received.push(message);
        }
        let relayed = received
            .iter()
            .filter(|message| message.bitmask == consensus)
            .count();
        assert_eq!(
            relayed, 0,
            "VULNERABLE: a master forwarded {relayed} message(s) published on the legacy \
             shard consensus topic, which no release reads"
        );
    }

    /// A CW vote names its signer only within its committee, and the receive
    /// loop attributes a shard CW message to its gossip author. With the
    /// content id alone, a copy of a member's vote that another peer
    /// re-published reached a master first, and the master dropped the
    /// member's own copy as its duplicate: the vote was lost, attributed to a
    /// stranger. Here the attacker re-publishes the member's vote before the
    /// member does (the member joins the topic only as it publishes, so it has
    /// not seen the copy, as when the copy reaches the master first), and the
    /// sink must still receive the member's copy, from the member, through the
    /// master. Each test runs in its own process under nextest, so the strict
    /// switch stays within this one.
    #[tokio::test]
    async fn reproduces_re_authored_cw_vote_dropping_the_genuine_copy() {
        quil_p2p::set_strict_shard_gossip(true);
        let cw = quil_engine::bitmasks::shard_cw_bitmask(&[7u8; 32]);
        let alert = quil_engine::bitmasks::GLOBAL_ALERT;
        let mut chain = chain(&[cw.as_slice(), alert], Some(MeshRole::Master), None).await;
        chain.wait_for_meshes().await;
        // The member: connected to the master only, and on the alert topic
        // only until it publishes its vote.
        let (member, member_id, _, member_rx) =
            start_node(&mut chain._sup, Some((chain.relay_port, chain.relay_id))).await;
        chain._inbound.push(member_rx);
        member.subscribe(alert.to_vec()).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while chain
            .relay
            .subscribed_peer_count(alert.to_vec())
            .await
            .unwrap_or(0)
            < 3
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the member never joined the master's alert topic"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let vote = quil_engine::bitmasks::shard_cw_frame_payload(0, b"the member's vote");
        assert_eq!(shard_gossip_verdict(&cw, &vote), Accept);
        chain
            .source
            .publish(cw.clone(), vote.clone())
            .await
            .expect("publish the re-authored copy");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            match tokio::time::timeout_at(deadline, chain.sink_rx.recv()).await {
                Ok(Some(message)) if message.data == vote => {
                    assert_eq!(message.from, chain.source_id.to_bytes());
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) => panic!("the sink stopped"),
                Err(_) => panic!("the master never forwarded the re-authored copy"),
            }
        }

        // The member's own copy, published to the master, which has seen the
        // re-authored one. The member joins the topic just before (publishing
        // needs a subscription), so the copy has not reached it.
        member.subscribe(cw.clone()).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let published = loop {
            match member.publish(cw.clone(), vote.clone()).await {
                Ok(()) => break Ok(()),
                Err(error)
                    if error.to_string().contains("InsufficientPeers")
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(error) => break Err(error.to_string()),
            }
        };
        published.expect("the member publishes its vote");
        let last = control_alert(u32::MAX);
        member
            .publish(alert.to_vec(), last.clone())
            .await
            .expect("publish the last control alert");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut received: Vec<quil_p2p::node::ReceivedMessage> = Vec::new();
        while !received.iter().any(|message| message.data == last) {
            match tokio::time::timeout_at(deadline, chain.sink_rx.recv()).await {
                Ok(Some(message)) => received.push(message),
                Ok(None) => panic!("the sink stopped"),
                Err(_) => panic!("the master never forwarded the member's last control alert"),
            }
        }
        // Anything the master forwarded before the last alert has arrived.
        tokio::time::sleep(Duration::from_millis(500)).await;
        while let Ok(message) = chain.sink_rx.try_recv() {
            received.push(message);
        }
        let genuine = received
            .iter()
            .filter(|message| message.data == vote && message.from == member_id.to_bytes())
            .count();
        assert_eq!(
            genuine, 1,
            "VULNERABLE: a master dropped a member's CW vote as the duplicate of a copy \
             another peer re-published first, so the vote reached its committee only \
             attributed to that peer"
        );
    }

    /// A shard's dispatch topic (`0x00 0x00 ‖ appFilter`) and an application's
    /// submission topic (`0x00 0x00 0x00 ‖ appFilter`) carry message bundles,
    /// and a leader drops anything else unread, so a master must not forward
    /// what no leader can propose: unchecked, junk anyone publishes there
    /// reached every mesh peer and their engines' queues, and its sender kept
    /// its score. A well-formed bundle published first shows the path works.
    #[tokio::test]
    async fn reproduces_undecodable_dispatch_gossip_relayed() {
        let filter = [7u8; 32];
        let dispatch = quil_engine::bitmasks::shard_dispatch_bitmask(&filter);
        let submissions = quil_engine::bitmasks::app_prover_bitmask(&filter);
        let alert = quil_engine::bitmasks::GLOBAL_ALERT;
        let mut chain = chain(
            &[dispatch.as_slice(), submissions.as_slice(), alert],
            Some(MeshRole::Master),
            None,
        )
        .await;
        chain.wait_for_meshes().await;

        let bundle = submission(1);
        chain
            .source
            .publish(dispatch.clone(), bundle.clone())
            .await
            .expect("publish a bundle on the dispatch topic");
        // Distinct for each topic: a copy of a message already seen is never
        // forwarded again, whatever the mesh makes of it.
        for (n, topic) in [(2, &dispatch), (3, &submissions)] {
            for data in undecodable_submissions(n) {
                if data.is_empty() {
                    continue;
                }
                chain
                    .source
                    .publish(topic.clone(), data)
                    .await
                    .expect("publish junk on a shard dispatch or submission topic");
            }
        }
        let last = control_alert(u32::MAX);
        chain
            .source
            .publish(alert.to_vec(), last.clone())
            .await
            .expect("publish the last control alert");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut received: Vec<quil_p2p::node::ReceivedMessage> = Vec::new();
        while !received.iter().any(|message| message.data == last) {
            match tokio::time::timeout_at(deadline, chain.sink_rx.recv()).await {
                Ok(Some(message)) => received.push(message),
                Ok(None) => panic!("the sink stopped"),
                Err(_) => panic!("the relay never forwarded the last control alert"),
            }
        }
        // Anything the relay forwarded before the last alert has arrived.
        tokio::time::sleep(Duration::from_millis(500)).await;
        while let Ok(message) = chain.sink_rx.try_recv() {
            received.push(message);
        }
        assert!(
            received
                .iter()
                .any(|message| message.bitmask == dispatch && message.data == bundle),
            "the relay never forwarded the well-formed bundle"
        );
        let relayed = received
            .iter()
            .filter(|message| {
                (message.bitmask == dispatch || message.bitmask == submissions)
                    && message.data != bundle
            })
            .count();
        assert_eq!(
            relayed, 0,
            "VULNERABLE: a master forwarded {relayed} undecodable message(s) published on \
             a shard dispatch or submission topic, which no leader can propose"
        );
        let score = chain.relay.get_peer_score(chain.source_id).await;
        assert!(
            score >= 0.0,
            "a master penalised junk on a shard dispatch topic before the strict epoch \
             (its sender scores {score})"
        );
    }
}
