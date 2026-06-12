use std::sync::Arc;

use tracing::{debug, info, warn};

use quil_lifecycle::Supervisor;

pub(crate) struct MessageLoopArgs {
    pub clock_store: Arc<quil_store::RocksClockStore>,
    pub exec_manager: Arc<quil_execution::ExecutionEngineManager>,
    pub msg_rx: tokio::sync::mpsc::Receiver<quil_p2p::node::ReceivedMessage>,
    pub consensus_loopback_rx: tokio::sync::mpsc::Receiver<quil_p2p::node::ReceivedMessage>,
    pub global_msg_tx: tokio::sync::broadcast::Sender<
        quil_types::proto::global::StreamGlobalMessagesResponse,
    >,
    pub archive_pool: Arc<quil_rpc::ArchiveEndpointPool>,
    pub mtls_seed: Option<[u8; 57]>,
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
    pub frame_validator: quil_engine::frame_validator::GlobalFrameVerifier,
    pub message_collector: Arc<quil_engine::message_collector::MessageCollector>,
    pub coverage_monitor: Arc<quil_engine::coverage::CoverageMonitor>,
    pub worker_allocator: Arc<quil_engine::worker_allocator::WorkerAllocator>,
    pub prover_pipeline: Arc<quil_engine::prover_pipeline::ProverPipeline>,
    pub consensus_handle:
        Arc<std::sync::OnceLock<quil_engine::consensus_types::GlobalEventLoopHandle>>,
    pub vote_aggregator:
        Arc<std::sync::OnceLock<Arc<quil_engine::vote_aggregation::VoteAggregation>>>,
    pub timeout_aggregator:
        Arc<std::sync::OnceLock<Arc<quil_engine::timeout_aggregation::TimeoutAggregation>>>,
    pub peer_info_cache: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>,
    >>,
    pub shard_engines: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_engine::app_engine::AppEngineHandle>,
    >>,
    pub signer_registry: Arc<quil_p2p::SignerRegistry>,
    pub current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
    pub last_global_head_frame: Arc<std::sync::atomic::AtomicU64>,
    pub genesis_archive_peer_ids: std::collections::HashSet<Vec<u8>>,
    pub genesis_prover_addrs: std::collections::HashSet<Vec<u8>>,
    pub alert_pubkey: Vec<u8>,
    pub network: u8,
    pub archive_mode: bool,
    pub prover_lifecycle: Arc<quil_engine::provers::lifecycle::ProverLifecycle>,
    pub prover_registry: Arc<quil_execution::SharedProverRegistry>,
    pub worker_manager: Arc<dyn quil_engine::worker::WorkerManager>,
    pub prover_address: [u8; 32],
    pub p2p_handle: quil_p2p::node::P2PHandle,
    pub time_reel: Option<Arc<quil_engine::time_reel::GlobalTimeReel>>,
    pub spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
}

pub(crate) fn spawn(sup: &mut Supervisor<anyhow::Error>, args: MessageLoopArgs) {
    let MessageLoopArgs {
        clock_store: clock_store_recv,
        exec_manager: exec_mgr_for_recv,
        mut msg_rx,
        mut consensus_loopback_rx,
        global_msg_tx: gmtx_for_recv,
        archive_pool: pool_for_recv,
        mtls_seed: mtls_seed_for_recv,
        hg_store: hg_store_for_recv,
        frame_validator: frame_validator_for_recv,
        message_collector: mc_for_recv,
        coverage_monitor: coverage_for_recv,
        worker_allocator: wa_for_recv,
        prover_pipeline: pp_for_recv,
        consensus_handle: ch_for_recv,
        vote_aggregator: va_for_recv,
        timeout_aggregator: ta_for_recv,
        peer_info_cache: pic_for_recv,
        shard_engines: shard_engines_for_recv,
        signer_registry: sr_for_recv,
        current_frame: cf_for_recv,
        last_global_head_frame: lhf_for_recv,
        genesis_archive_peer_ids: genesis_archive_peer_ids_for_recv,
        genesis_prover_addrs: genesis_prover_addrs_for_recv,
        alert_pubkey: alert_pubkey_for_recv,
        network: network_for_recv,
        archive_mode: archive_mode_recv,
        prover_lifecycle: pl_for_recv,
        prover_registry: pr_for_recv,
        worker_manager: wm_for_recv,
        prover_address: pa_for_recv,
        p2p_handle: p2p_for_recv,
        time_reel: time_reel_for_recv,
        spawner,
    } = args;

    // Global bitmasks for BlossomSub topic subscriptions.
    const GLOBAL_CONSENSUS: &[u8] = &[0x00];
    const GLOBAL_FRAME: &[u8] = &[0x00, 0x00];
    const GLOBAL_PROVER: &[u8] = &[0x00, 0x00, 0x00];
    const GLOBAL_PEER_INFO: &[u8] = &[0x00, 0x00, 0x00, 0x00];
    const GLOBAL_ALERT: &[u8] = &[0u8; 16];

    // Per-bitmask validator gate. Malformed bytes are dropped here so
    // the dispatch loop below stays cheap. Topics without a registered
    // validator fall through unchanged.
    let message_router = Arc::new(quil_engine::message_router::MessageRouter::new());
    message_router.register_validator(
        GLOBAL_PEER_INFO.to_vec(),
        quil_engine::message_router::validator_global_peer_info(),
    );
    message_router.register_validator(
        GLOBAL_PROVER.to_vec(),
        quil_engine::message_router::validator_global_prover(),
    );
    message_router.register_validator(
        GLOBAL_FRAME.to_vec(),
        quil_engine::message_router::validator_global_frame(),
    );
    message_router.register_validator(
        GLOBAL_CONSENSUS.to_vec(),
        quil_engine::message_router::validator_global_consensus(),
    );
    let router_for_recv = message_router.clone();

    let reward_issuer: Arc<quil_engine::OptRewardIssuance> = Arc::new(quil_engine::OptRewardIssuance);
    let archive_mode_for_recv: bool = archive_mode_recv;

    // Bundle every cache/map we want to size-report in the 30s
    // status tick. Cheap clone (all Arc inside) so it can move into
    // the recv-loop closure alongside everything else.
    let mem_sources = crate::mem_stats::StructuralSources {
        peer_info_cache: pic_for_recv.clone(),
        shard_engines: shard_engines_for_recv.clone(),
        signer_registry: sr_for_recv.clone(),
        prover_registry: pr_for_recv.clone(),
        time_reel: time_reel_for_recv.clone(),
    };

    sup.spawn("message-loop", move |recv_token| async move {
        let mut time_reel_rx = time_reel_for_recv
            .as_ref()
            .and_then(|tr| tr.take_event_rx());
        let mut frames_received: u64 = 0;
        let mut peer_infos_received: u64 = 0;
        let mut peer_info_digest_cache: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut archive_peers_seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut consensus_msgs_received: u64 = 0;
        let mut prover_msgs_received: u64 = 0;
        let mut router_drops: u64 = 0;
        // Per-topic drop counters so we can tell which validator is
        // doing the rejecting. Without these, all four global
        // validators' drops are lumped into `router_drops` and we
        // can't distinguish a peer-info flood from a frame flood
        // from per-shard noise.
        let mut router_drops_peer_info: u64 = 0;
        let mut router_drops_prover: u64 = 0;
        let mut router_drops_frame: u64 = 0;
        let mut router_drops_consensus: u64 = 0;
        let mut router_drops_alert: u64 = 0;
        let mut router_drops_other: u64 = 0;
        // Per-reason aggregation (validator reject string -> count).
        // Bounded by the static set of `&'static str` reasons the
        // validators emit; size <= ~20 keys in practice.
        let mut router_drops_by_reason: std::collections::HashMap<&'static str, u64> =
            std::collections::HashMap::new();
        let mut status_timer = tokio::time::interval(std::time::Duration::from_secs(30));
        status_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Track the highest frame number we've fully executed (through
        // the execution manager + lifecycle). New frames arriving via
        // gossip can be wildly out of order; only execute consecutive
        // frames starting from `last_executed + 1` so prover-state
        // dependent ops (ProverConfirm/Resume against a prover the
        // previous frame registered) don't fail spuriously. Seeded
        // from the latest frame already in the clock store so a
        // restart picks up where it left off.
        let mut last_executed_frame: u64 = clock_store_recv
            .get_latest_global_frame()
            .ok()
            .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
            .unwrap_or(0);
        loop {
            tokio::select! {
                _ = status_timer.tick() => {
                    // Periodic allocation status snapshot.
                    let peer_count = p2p_for_recv.peer_count();
                    let latest_frame = clock_store_recv.get_latest_global_frame()
                        .ok()
                        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
                        .unwrap_or(0);
                    let (active, pending, total_allocs) = {
                        use quil_types::consensus::{EffectiveStatus, ProverRegistry};
                        match pr_for_recv.get_prover_info(&pa_for_recv) {
                            Ok(Some(info)) => {
                                let mut a = 0usize;
                                let mut p = 0usize;
                                let mut total = 0usize;
                                for alloc in &info.allocations {
                                    match alloc.effective_status(latest_frame) {
                                        EffectiveStatus::Active => {
                                            a += 1;
                                            total += 1;
                                        }
                                        EffectiveStatus::Joining => {
                                            p += 1;
                                            total += 1;
                                        }
                                        EffectiveStatus::Paused | EffectiveStatus::Leaving => {
                                            total += 1;
                                        }
                                        _ => {}
                                    }
                                }
                                (a, p, total)
                            }
                            _ => (0, 0, 0),
                        }
                    };
                    info!(
                        peers = peer_count,
                        frame = latest_frame,
                        frames_received,
                        active_shards = active,
                        pending_joins = pending,
                        total_allocations = total_allocs,
                        peer_infos = peer_infos_received,
                        archive_peers = archive_peers_seen.len(),
                        consensus_msgs = consensus_msgs_received,
                        prover_msgs = prover_msgs_received,
                        router_drops,
                        rdrop_peer_info = router_drops_peer_info,
                        rdrop_prover = router_drops_prover,
                        rdrop_frame = router_drops_frame,
                        rdrop_consensus = router_drops_consensus,
                        rdrop_alert = router_drops_alert,
                        rdrop_other = router_drops_other,
                        rdrop_reasons = %{
                            // Render as `reason1=N,reason2=M,...` sorted
                            // descending by count so the most-common
                            // cause is first. Bounded to top 8 to keep
                            // the log line under control.
                            let mut entries: Vec<(&&str, &u64)> =
                                router_drops_by_reason.iter().collect();
                            entries.sort_by(|a, b| b.1.cmp(a.1));
                            entries.into_iter().take(8)
                                .map(|(k, v)| format!("{}={}", k, v))
                                .collect::<Vec<_>>()
                                .join(",")
                        },
                        "node status"
                    );
                    // Memory snapshot. Logged separately so the size
                    // fields don't crowd `node status`; growth between
                    // ticks is the diagnosis signal.
                    let sizes = mem_sources.snapshot(
                        archive_peers_seen.len(),
                        peer_info_digest_cache.len(),
                    );
                    let proc_mem = crate::mem_stats::process_memory();
                    info!(
                        rss_mb = proc_mem
                            .map(|m| crate::mem_stats::fmt_mb(m.rss_bytes))
                            .unwrap_or_else(|| "?".to_string()),
                        vsize_mb = proc_mem
                            .map(|m| crate::mem_stats::fmt_mb(m.vsize_bytes))
                            .unwrap_or_else(|| "?".to_string()),
                        peer_info_cache = sizes.peer_info_cache,
                        shard_engines = sizes.shard_engines,
                        signer_registry = sizes.signer_registry,
                        archive_peers_seen = sizes.archive_peers_seen,
                        peer_info_digest_cache = sizes.peer_info_digest_cache,
                        prover_registry_addresses = sizes.prover_registry_addresses,
                        prover_registry_filters = sizes.prover_registry_filters,
                        time_reel_nodes = sizes.time_reel_nodes,
                        time_reel_pending = sizes.time_reel_pending,
                        time_reel_equivocators = sizes.time_reel_equivocators,
                        app_engine_frame_store = sizes.app_engine_frame_store,
                        app_engine_message_spillover = sizes.app_engine_message_spillover,
                        app_engine_proposal_cache = sizes.app_engine_proposal_cache,
                        app_engine_pending_certified_parents = sizes.app_engine_pending_certified_parents,
                        "memory snapshot"
                    );
                }
                msg = async {
                    // Merge the network receive channel and the
                    // self-loopback channel — both produce
                    // `ReceivedMessage`s that go through the same
                    // dispatch logic. This is how the proposer's own
                    // proposal reaches its own `vote_aggregator` and
                    // event_loop without relying on BlossomSub
                    // self-echo (which doesn't happen).
                    tokio::select! {
                        biased;
                        m = consensus_loopback_rx.recv() => m,
                        m = msg_rx.recv() => m,
                    }
                } => {
                    match msg {
                        Some(received) => {
                            // Forward to connected StreamGlobalMessages
                            // subscribers (workers) — ONLY peer-info.
                            //
                            // In Go, `broadcastGlobalMessage` is called
                            // from GLOBAL_FRAME, GLOBAL_PROVER, and
                            // GLOBAL_PEER_INFO handlers. But on a
                            // non-archive master those handlers don't
                            // fire (not subscribed). The only messages
                            // arriving here are GLOBAL_PEER_INFO (from
                            // the mesh) and GLOBAL_CONSENSUS (from the
                            // self-loopback when the master produces
                            // its own proposals/votes). Workers don't
                            // need either — they get global frames
                            // from the archive poller, prover messages
                            // via direct gRPC, and per-shard consensus
                            // from their own mesh subscriptions.
                            // Forwarding the loopback's
                            // GLOBAL_CONSENSUS was the source of QC
                            // verification failures (all-zero sig/pk,
                            // 0xFF bitmask from genesis QC data) and
                            // OOM (on archive masters, the [0xFF;32]
                            // catch-all subscription fed every shard's
                            // traffic into the broadcast channel).
                            //
                            // The only bitmask workers still need from
                            // the master stream is GLOBAL_PEER_INFO
                            // (peer discovery for their own mesh).
                            if received.bitmask.as_slice() == GLOBAL_PEER_INFO {
                                let _ = gmtx_for_recv.send(
                                    quil_types::proto::global::StreamGlobalMessagesResponse {
                                        data: received.data.clone(),
                                        bitmask: received.bitmask.clone(),
                                    },
                                );
                            }

                            // Per-topic validator gate. Malformed bytes are
                            // dropped before they reach a queue.
                            // Unregistered topics fall through.
                            let route_outcome = router_for_recv
                                .route(&received.bitmask, &received.data);
                            if !route_outcome.should_dispatch() {
                                router_drops += 1;
                                if let Some(reason) = route_outcome.reject_reason() {
                                    *router_drops_by_reason.entry(reason).or_insert(0) += 1;
                                }
                                // Categorize for operator visibility.
                                let topic = match received.bitmask.as_slice() {
                                    GLOBAL_PEER_INFO => {
                                        router_drops_peer_info += 1;
                                        "peer_info"
                                    }
                                    GLOBAL_PROVER => {
                                        router_drops_prover += 1;
                                        "prover"
                                    }
                                    GLOBAL_FRAME => {
                                        router_drops_frame += 1;
                                        "frame"
                                    }
                                    GLOBAL_CONSENSUS => {
                                        router_drops_consensus += 1;
                                        "consensus"
                                    }
                                    GLOBAL_ALERT => {
                                        router_drops_alert += 1;
                                        "alert"
                                    }
                                    _ => {
                                        router_drops_other += 1;
                                        "shard/unknown"
                                    }
                                };
                                let type_prefix = if received.data.len() >= 4 {
                                    format!("0x{:08x}", u32::from_be_bytes(
                                        received.data[..4].try_into().unwrap_or([0;4])
                                    ))
                                } else {
                                    format!("short({}B)", received.data.len())
                                };
                                debug!(
                                    topic,
                                    type_prefix,
                                    len = received.data.len(),
                                    total_dropped = router_drops,
                                    "router validator dropped message",
                                );
                                continue;
                            }

                            match received.bitmask.as_slice() {
                            GLOBAL_PEER_INFO => {
                                match quil_p2p::classify_peer_info_message(&received.data) {
                                    Ok(quil_p2p::PeerInfoMessage::PeerInfo(info)) => {
                                        peer_infos_received += 1;
                                        // Dedup: hash PeerInfo with timestamp zeroed
                                        // (mirrors Go's hashPeerInfo). Skip if seen.
                                        let mut dedup_info = info.clone();
                                        dedup_info.timestamp = 0;
                                        let dedup_payload = quil_p2p::encode_canonical_peer_info(
                                            &dedup_info,
                                            &dedup_info.public_key,
                                            &dedup_info.signature,
                                        );
                                        use sha2::Digest as _;
                                        let digest: [u8; 32] = sha2::Sha256::digest(&dedup_payload).into();
                                        if !peer_info_digest_cache.insert(digest) {
                                            continue;
                                        }
                                        if peer_info_digest_cache.len() > 10_000 {
                                            peer_info_digest_cache.clear();
                                        }
                                        if !info.peer_id.is_empty() {
                                            let mut cache = pic_for_recv.write();
                                            cache.insert(info.peer_id.clone(), info.clone());
                                        }
                                        // Only ARCHIVE-capable peers go into the
                                        // poll pool. Plain peers reject every
                                        // GetGlobalFrame call with "not currently
                                        // syncable".
                                        if info.is_archive() {
                                            // Validate against genesis archive peers.
                                            // The peer_id in PeerInfo is raw bytes;
                                            // genesis has base58 peer IDs. Convert
                                            // PeerInfo peer_id to hex for comparison
                                            // against genesis BLS pubkey hashes.
                                            let peer_hex = bs58::encode(&info.peer_id).into_string();
                                            // On testnet/devnet (network != 0) the genesis
                                            // archive list isn't ours, so we accept any
                                            // archive-claiming peer. Mainnet keeps the
                                            // strict allowlist check below.
                                            let is_genesis_archive = network_for_recv != 0
                                                || genesis_archive_peer_ids_for_recv
                                                    .contains(&info.peer_id);
                                            if !is_genesis_archive {
                                                warn!(
                                                    peer = peer_hex,
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "FAKE ARCHIVE — peer claims archive capability but is not a genesis archive peer"
                                                );
                                                continue;
                                            }
                                            let is_new = archive_peers_seen.insert(info.peer_id.clone());
                                            if is_new {
                                                info!(
                                                    peer = peer_hex,
                                                    head_frame = info.last_global_head_frame,
                                                    total = archive_peers_seen.len(),
                                                    "verified genesis archive peer"
                                                );
                                            }
                                            let mut first_addr: Option<String> = None;
                                            for reach in &info.reachability {
                                                for ma in &reach.stream_multiaddrs {
                                                    if let Some(addr) = crate::util::multiaddr::multiaddr_to_host_port_with_network(ma, network_for_recv) {
                                                        if first_addr.is_none() {
                                                            first_addr = Some(addr.clone());
                                                        }
                                                        pool_for_recv.add(addr).await;
                                                    }
                                                }
                                            }
                                            info!(
                                                peer = bs58::encode(&info.peer_id).into_string(),
                                                head_frame = info.last_global_head_frame,
                                                total_archives = archive_peers_seen.len(),
                                                "discovered archive peer"
                                            );
                                            // First archive: sync all four
                                            // CRDT phases of the global
                                            // prover tree sequentially. Each
                                            // ensure_prover_tree call either
                                            // loads the cached blob from
                                            // RocksDB or pulls + verifies +
                                            // persists from this archive.
                                            // Skip in archive mode — archives
                                            // have full history locally and
                                            // the legacy whole-tree blob
                                            // sync path isn't populated by
                                            // migrated stores (per-vertex
                                            // data at `0x30` is, but blob
                                            // cache at `0x2F` is not), so
                                            // calling this against another
                                            // archive that's also fresh
                                            // from migration just trades
                                            // "no tree data available"
                                            // errors back and forth.
                                            if is_new && archive_peers_seen.len() == 1
                                                && !archive_mode_for_recv {
                                                if let (Some(seed), Some(addr)) =
                                                    (mtls_seed_for_recv, first_addr)
                                                {
                                                    let store = hg_store_for_recv.clone();
                                                    let cs = clock_store_recv.clone();
                                                    spawner.detach("prover-tree-bootstrap", async move {
                                                        use quil_types::proto::application::HypergraphPhaseSet::*;
                                                        // Pin sync against the most-recent verified
                                                        // frame's prover_tree_commitment (when
                                                        // available). Empty during bootstrap before
                                                        // any frame is stored.
                                                        let expected_root = cs
                                                            .get_latest_global_frame()
                                                            .ok()
                                                            .and_then(|f| f.header.map(|h| h.prover_tree_commitment))
                                                            .unwrap_or_default();
                                                        for phase in [VertexAdds, VertexRemoves, HyperedgeAdds, HyperedgeRemoves] {
                                                            match quil_rpc::ensure_prover_tree(
                                                                &addr,
                                                                &seed,
                                                                phase,
                                                                store.clone(),
                                                                &expected_root,
                                                            ).await {
                                                                Ok(stats) => {
                                                                    info!(
                                                                        addr = %addr,
                                                                        ?phase,
                                                                        matched = stats.commitments_match,
                                                                        leaves = stats.leaves_pulled,
                                                                        "phase sync complete"
                                                                    );
                                                                }
                                                                Err(e) => {
                                                                    warn!(addr = %addr, ?phase, error = %e, "ensure_prover_tree failed");
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                        info!("all 4 phases synced");

                                                        // Build the in-memory ProverRegistry
                                                        // from the persisted vertex store.
                                                        let mut registry =
                                                            quil_execution::InMemoryProverRegistry::new();
                                                        registry.refresh(&store);
                                                        info!(
                                                            provers_visited = registry.provers_visited(),
                                                            allocations_visited = registry.allocations_visited(),
                                                            rewards_visited = registry.rewards_visited(),
                                                            distinct_provers = registry.distinct_provers(),
                                                            distinct_filters = registry.distinct_filters(),
                                                            "prover registry refreshed"
                                                        );

                                                        // Sample a few active provers.
                                                        let all_active =
                                                            registry.get_all_active_app_shard_provers();
                                                        info!(
                                                            active_count = all_active.len(),
                                                            "active prover count from registry"
                                                        );
                                                        for prover in all_active.iter().take(3) {
                                                            info!(
                                                                address = %hex::encode(&prover.address),
                                                                seniority = prover.seniority,
                                                                available_storage = prover.available_storage,
                                                                allocations = prover.allocations.len(),
                                                                "  active prover"
                                                            );
                                                        }
                                                        Ok(())
                                                    });
                                                }
                                            }
                                        } else if peer_infos_received <= 5
                                            || peer_infos_received % 100 == 0
                                        {
                                            info!(
                                                total_peer_infos = peer_infos_received,
                                                total_archives = archive_peers_seen.len(),
                                                "PeerInfo discovery progress"
                                            );
                                        }
                                    }
                                    Ok(quil_p2p::PeerInfoMessage::KeyRegistry) => {
                                        // Decode and stash in the signer registry so
                                        // consensus-message BLS signatures from the
                                        // announcing peer can later be verified using
                                        // the prover key bound to its Ed448 identity.
                                        // Older-timestamp replays are ignored inside
                                        // `SignerRegistry::update`.
                                        match quil_p2p::decode_canonical_key_registry(&received.data) {
                                            Ok(reg) => {
                                                let identity_len = reg.ed448_pubkey.len();
                                                let prover_len = reg.bls_pubkey.len();
                                                sr_for_recv.update(reg);
                                                debug!(
                                                    identity_len,
                                                    prover_len,
                                                    total_entries = sr_for_recv.len(),
                                                    "ingested KeyRegistry"
                                                );
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "failed to decode KeyRegistry");
                                            }
                                        }
                                    }
                                    Ok(quil_p2p::PeerInfoMessage::Unknown(prefix)) => {
                                        warn!(prefix = format!("0x{:04x}", prefix),
                                            "unknown PEER_INFO bitmask message type");
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "failed to decode PeerInfo");
                                    }
                                }
                            }
                            GLOBAL_FRAME => {
                                // Try canonical bytes first (the wire format),
                                // fall back to proto decode (archive poller uses proto).
                                let frame_result: std::result::Result<quil_types::proto::global::GlobalFrame, _> =
                                    quil_engine::consensus_wire::decode_global_frame(&received.data)
                                        .or_else(|canonical_err| {
                                            warn!(error = %canonical_err, "canonical decode failed, trying proto");
                                            prost::Message::decode(received.data.as_slice())
                                                .map_err(|e| quil_types::error::QuilError::InvalidArgument(
                                                    format!("failed to decode Protobuf message: {} (canonical: {})", e, canonical_err)
                                                ))
                                        });
                                match frame_result {
                                    Ok(frame) => {
                                        let frame_num = frame.header.as_ref()
                                            .map(|h| h.frame_number).unwrap_or(0);

                                        // Validate prover is a genesis prover
                                        if let Some(h) = frame.header.as_ref() {
                                            if !genesis_prover_addrs_for_recv.contains(&h.prover) {
                                                warn!(
                                                    frame = frame_num,
                                                    prover = hex::encode(&h.prover),
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "INVALID PROVER — not a genesis prover, possible attacker"
                                                );
                                                continue;
                                            }
                                        }

                                        // Verify VDF proof before storing.
                                        // Wrap in catch_unwind — the classgroup can panic
                                        // on malformed VDF output from canonical decode bugs.
                                        let validate_result = std::panic::catch_unwind(
                                            std::panic::AssertUnwindSafe(|| frame_validator_for_recv.validate(&frame))
                                        );
                                        match validate_result {
                                            Ok(Ok(true)) => {}
                                            Ok(Ok(false)) => {
                                                // Validator returned false — either VDF or BLS
                                                // signature check rejected it. The specific
                                                // reason is logged by `GlobalFrameVerifier::validate`.
                                                warn!(frame = frame_num, "frame rejected by validator — dropping");
                                                continue;
                                            }
                                            Ok(Err(e)) => {
                                                warn!(frame = frame_num, error = %e, "VDF validation error — dropping frame");
                                                continue;
                                            }
                                            Err(_) => {
                                                warn!(
                                                    frame = frame_num,
                                                    output_len = frame.header.as_ref().map(|h| h.output.len()).unwrap_or(0),
                                                    "VDF validation PANIC — frame output likely corrupted, dropping"
                                                );
                                                continue;
                                            }
                                        }

                                        match clock_store_recv.put_global_frame(&frame, None) {
                                            Ok(()) => {
                                                frames_received += 1;
                                                // `observe` / `fetch_max` never
                                                // regress these counters below
                                                // an already-seen value (e.g.
                                                // if a stale duplicate frame
                                                // arrives out-of-order via
                                                // BlossomSub).
                                                cf_for_recv.observe(frame_num);
                                                lhf_for_recv.fetch_max(frame_num, std::sync::atomic::Ordering::Relaxed);

                                                // Frame execution dispatches on node mode:
                                                //
                                                //   * Archive nodes need contiguous frame
                                                //     history (clients sync from us; gaps
                                                //     break their replay). We drain the
                                                //     clock store in order from
                                                //     `last_executed + 1` forward and
                                                //     wait for missing predecessors.
                                                //
                                                //   * Non-archive nodes only need to
                                                //     follow the chain head. BlossomSub
                                                //     gossip is unordered; stale / backfill
                                                //     frames are noise. We skip any frame
                                                //     whose number is not strictly newer
                                                //     than what we've already executed,
                                                //     and never wait for missing
                                                //     predecessors — they're already past.
                                                let frames_to_execute: Vec<(u64, quil_types::proto::global::GlobalFrame)> =
                                                if archive_mode_recv {
                                                    let mut out = Vec::new();
                                                    loop {
                                                        let next_num = last_executed_frame.saturating_add(1);
                                                        match clock_store_recv.get_global_frame(next_num) {
                                                            Ok(f) => out.push((next_num, f)),
                                                            Err(_) => break,
                                                        }
                                                        last_executed_frame = next_num;
                                                    }
                                                    if frame_num > last_executed_frame {
                                                        debug!(
                                                            frame = frame_num,
                                                            awaiting = last_executed_frame + 1,
                                                            "archive: stored out-of-order frame, awaiting predecessor"
                                                        );
                                                    }
                                                    out
                                                } else if let Some(ref reel) = time_reel_for_recv {
                                                    if let Err(e) = reel.insert(Arc::new(frame.clone())) {
                                                        debug!(
                                                            frame = frame_num,
                                                            error = %e,
                                                            "time reel rejected frame",
                                                        );
                                                    }
                                                    // Drain events — execute frames the reel promotes to head.
                                                    let mut out = Vec::new();
                                                    if let Some(ref mut rx) = time_reel_rx {
                                                        while let Ok(event) = rx.try_recv() {
                                                            match event.event_type {
                                                                quil_engine::time_reel::TimeReelEventType::NewHead |
                                                                quil_engine::time_reel::TimeReelEventType::ForkDetected => {
                                                                    let head_num = event.frame.header.as_ref()
                                                                        .map(|h| h.frame_number).unwrap_or(0);
                                                                    if head_num > last_executed_frame {
                                                                        last_executed_frame = head_num;
                                                                        let f: quil_types::proto::global::GlobalFrame =
                                                                            (*event.frame).clone();
                                                                        out.push((head_num, f));
                                                                    }
                                                                    if event.event_type == quil_engine::time_reel::TimeReelEventType::ForkDetected {
                                                                        info!(
                                                                            new_head = head_num,
                                                                            "time reel: fork detected, switching to new head"
                                                                        );
                                                                    }
                                                                }
                                                                quil_engine::time_reel::TimeReelEventType::EquivocationDetected => {
                                                                    warn!(
                                                                        msg = %event.message,
                                                                        "time reel: equivocation detected"
                                                                    );
                                                                }
                                                            }
                                                        }
                                                    }
                                                    out
                                                } else if frame_num > last_executed_frame {
                                                    last_executed_frame = frame_num;
                                                    vec![(frame_num, frame.clone())]
                                                } else {
                                                    debug!(
                                                        frame = frame_num,
                                                        last_executed = last_executed_frame,
                                                        "non-archive: skipping stale/backfill frame",
                                                    );
                                                    Vec::new()
                                                };

                                                for (exec_num, exec_frame) in frames_to_execute {
                                                    match quil_engine::frame_processor::process_global_frame_with_rewards(
                                                        &exec_mgr_for_recv,
                                                        &exec_frame,
                                                        &num_bigint::BigInt::from(1),
                                                        Some(reward_issuer.as_ref() as &dyn quil_types::consensus::RewardIssuance),
                                                        Some(pr_for_recv.as_ref() as &dyn quil_types::consensus::ProverRegistry),
                                                    ) {
                                                        Ok((applied, skipped)) => {
                                                            info!(
                                                                frame = exec_num,
                                                                total = frames_received,
                                                                applied,
                                                                skipped,
                                                                "received + processed GlobalFrame"
                                                            );
                                                            coverage_for_recv.check(exec_num);
                                                            if !archive_mode_recv {
                                                                if let Err(e) = wa_for_recv.on_new_frame(exec_num) {
                                                                    warn!(error = %e, "worker allocation failed");
                                                                }
                                                            }
                                                            let frame_difficulty = exec_frame.header.as_ref()
                                                                .map(|h| h.difficulty)
                                                                .unwrap_or(0);
                                                            pl_for_recv.set_prover_root_verified_frame(exec_num);
                                                            if !archive_mode_recv {
                                                                match pl_for_recv.evaluate(
                                                                    exec_num,
                                                                    frame_difficulty as u64,
                                                                    pr_for_recv.as_ref(),
                                                                    wm_for_recv.as_ref(),
                                                                ) {
                                                                    Ok(actions) => {
                                                                        for action in actions {
                                                                            info!(frame = exec_num, ?action, "prover lifecycle action");
                                                                            pp_for_recv.dispatch(action);
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        debug!(error = %e, "prover lifecycle evaluation skipped");
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            info!(
                                                                frame = exec_num,
                                                                total = frames_received,
                                                                error = %e,
                                                                "received GlobalFrame (processing failed)"
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "failed to store frame");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let prefix = if received.data.len() >= 8 {
                                            hex::encode(&received.data[..8])
                                        } else {
                                            hex::encode(&received.data)
                                        };
                                        warn!(
                                            error = %e,
                                            bytes = received.data.len(),
                                            prefix = %prefix,
                                            "GLOBAL_FRAME decode failed"
                                        );
                                    }
                                }
                            }
                            GLOBAL_CONSENSUS => {
                                consensus_msgs_received += 1;
                                let current_rank = frames_received;
                                mc_for_recv.add_message(current_rank, received.data.clone());
                                // Route inbound consensus messages to the event
                                // loop handle (populated once activation completes).
                                if let Some(handle) = ch_for_recv.get() {
                                    if let Some(tp) = quil_engine::consensus_wire::peek_consensus_type(&received.data) {
                                        match tp {
                                            quil_engine::consensus_wire::GLOBAL_PROPOSAL_TYPE => {
                                                match quil_engine::consensus_wire::GlobalProposal::from_canonical_bytes(&received.data) {
                                                    Ok(wire) => {
                                                        match quil_engine::consensus_types::wire_proposal_to_signed(wire) {
                                                            Ok((sp, qc, _tc)) => {
                                                                handle.submit_quorum_certificate(qc);
                                                                // Skip pre-submitting the
                                                                // proposal's
                                                                // `previous_rank_timeout_certificate`.
                                                                // Same hazard as the TimeoutState
                                                                // path below: an unvalidated TC
                                                                // would land in the pacemaker's
                                                                // newest-TC tracker and be
                                                                // embedded into our own next
                                                                // outgoing timeout. Validation
                                                                // happens later in
                                                                // `validate_proposal` →
                                                                // `validate_timeout_certificate`,
                                                                // and a real TC will surface via
                                                                // the local timeout aggregator's
                                                                // `on_tc_created` callback once
                                                                // enough peer timeouts arrive.
                                                                // Feed into the rank's vote collector
                                                                // so the proposer's self-vote counts
                                                                // toward quorum and subsequent
                                                                // standalone votes get verified.
                                                                if let Some(agg) = va_for_recv.get() {
                                                                    agg.handle_proposal(&sp);
                                                                }
                                                                let h = handle.clone();
                                                                spawner.detach("global-proposal-submit", async move {
                                                                    h.submit_proposal(sp).await;
                                                                    Ok(())
                                                                });
                                                            }
                                                            Err(e) => warn!(error = %e, "GlobalProposal bridge failed"),
                                                        }
                                                    }
                                                    Err(e) => warn!(error = %e, "GlobalProposal decode failed"),
                                                }
                                            }
                                            quil_engine::consensus_wire::PROPOSAL_VOTE_TYPE => {
                                                // Route standalone votes into the per-rank aggregator.
                                                // On reaching quorum, the aggregator's
                                                // OnQuorumCertificateCreated callback fires
                                                // `handle.submit_quorum_certificate`.
                                                match quil_engine::consensus_wire::ProposalVote::from_canonical_bytes(&received.data) {
                                                    Ok(wire) => {
                                                        if let Some(agg) = va_for_recv.get() {
                                                            let gv = quil_engine::vote_aggregation::wire_vote_to_global_vote(wire);
                                                            agg.handle_vote(gv);
                                                        }
                                                    }
                                                    Err(e) => warn!(error = %e, "ProposalVote decode failed"),
                                                }
                                            }
                                            quil_engine::consensus_wire::TIMEOUT_STATE_TYPE => {
                                                match quil_engine::consensus_wire::TimeoutState::from_canonical_bytes(&received.data) {
                                                    Ok(ts) => {
                                                        // Fast-forward the newest-QC tracker.
                                                        // Safe: bad QCs fail later validation.
                                                        let qc_for_handle = ts.latest_quorum_certificate.clone().into_trait_object();
                                                        handle.submit_quorum_certificate(qc_for_handle);
                                                        // DO NOT auto-submit the embedded
                                                        // `prior_rank_timeout_certificate` —
                                                        // a malformed TC would land in our
                                                        // pacemaker's newest-TC tracker and
                                                        // get embedded into our next timeout,
                                                        // which peers then reject. Outgoing
                                                        // TCs source from clock store
                                                        // (previously validated). Local
                                                        // aggregation forms a valid TC once
                                                        // peer timeouts arrive.
                                                        if let Some(agg) = ta_for_recv.get() {
                                                            let typed = quil_engine::timeout_aggregation::wire_timeout_to_typed(ts);
                                                            agg.handle_timeout(typed);
                                                        }
                                                    }
                                                    Err(e) => warn!(error = %e, "TimeoutState decode failed"),
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            GLOBAL_PROVER => {
                                prover_msgs_received += 1;
                                let current_rank = frames_received;
                                mc_for_recv.add_message(current_rank, received.data.clone());
                            }
                            GLOBAL_ALERT => {
                                // Mirrors Go's alert validation at
                                // `message_validation.go:641-657` +
                                // `handleAlertMessage` at
                                // `message_processors.go:810`. The
                                // alert's Ed448 signature must verify
                                // against the configured `alertKey`
                                // with domain `"GLOBAL_ALERT" || message`.
                                // Canonical format:
                                //   [u32 type=0x0911][u32 msg_len][msg][u32 sig_len][sig]
                                if alert_pubkey_for_recv.is_empty() || alert_pubkey_for_recv.len() != 57 {
                                    debug!("GLOBAL_ALERT received but no valid alertKey configured — dropping");
                                } else if received.data.len() >= 12 {
                                    let d = &received.data;
                                    let mut c = 4usize; // skip type prefix
                                    let msg_len = u32::from_be_bytes(d[c..c+4].try_into().unwrap_or([0;4])) as usize;
                                    c += 4;
                                    if msg_len <= 1000 && c + msg_len + 4 <= d.len() {
                                        let msg = &d[c..c+msg_len];
                                        c += msg_len;
                                        let sig_len = u32::from_be_bytes(d[c..c+4].try_into().unwrap_or([0;4])) as usize;
                                        c += 4;
                                        if sig_len == 114 && c + sig_len <= d.len() {
                                            let sig = &d[c..c+sig_len];
                                            let mut signed = Vec::with_capacity(b"GLOBAL_ALERT".len() + msg_len);
                                            signed.extend_from_slice(b"GLOBAL_ALERT");
                                            signed.extend_from_slice(msg);
                                            if quil_crypto::ed448_verify(&alert_pubkey_for_recv, &signed, sig) {
                                                let msg_str = String::from_utf8_lossy(msg);
                                                warn!(message = %msg_str, "GLOBAL ALERT (verified)");
                                                coverage_for_recv.emit_alert(&msg_str);
                                            } else {
                                                debug!("GLOBAL ALERT rejected — signature invalid");
                                            }
                                        } else {
                                            debug!(sig_len, "GLOBAL ALERT rejected — bad signature length");
                                        }
                                    } else {
                                        debug!(msg_len, "GLOBAL ALERT rejected — bad message length");
                                    }
                                }
                            }
                            _ => {
                                // Per-shard routing: if the bitmask matches one
                                // of the four bitmasks for an active shard
                                // engine on this node, forward the bytes to
                                // the engine via its `AppEngineHandle`. The
                                // worker thread loops own messages back via
                                // `app_handle.send(...)`, so we must not also
                                // route self-published messages here — the
                                // BlossomSub mesh already drops self-echoes.
                                let bm = received.bitmask.as_slice();
                                // Snapshot the active filter set under the read
                                // lock, then drop it before doing per-handle
                                // sends (the channel is bounded; sends are
                                // try_send).
                                let entries: Vec<(Vec<u8>, quil_engine::app_engine::AppEngineHandle)> = {
                                    let map = shard_engines_for_recv.read();
                                    map.iter()
                                        .map(|(f, h)| (f.clone(), h.clone()))
                                        .collect()
                                };
                                let mut routed = false;
                                for (filter, handle) in &entries {
                                    if bm == quil_engine::bitmasks::shard_consensus_bitmask(filter).as_slice() {
                                        handle.send(quil_engine::app_engine::AppEngineMessage::Consensus(received.data.clone()));
                                        routed = true;
                                        break;
                                    }
                                    if bm == quil_engine::bitmasks::shard_frame_bitmask(filter).as_slice() {
                                        handle.send(quil_engine::app_engine::AppEngineMessage::Frame(received.data.clone()));
                                        routed = true;
                                        break;
                                    }
                                    if bm == quil_engine::bitmasks::shard_prover_bitmask(filter).as_slice() {
                                        handle.send(quil_engine::app_engine::AppEngineMessage::Prover(received.data.clone()));
                                        routed = true;
                                        break;
                                    }
                                    if bm == quil_engine::bitmasks::shard_dispatch_bitmask(filter).as_slice() {
                                        handle.send(quil_engine::app_engine::AppEngineMessage::Dispatch(received.data.clone()));
                                        routed = true;
                                        break;
                                    }
                                }
                                if !routed {
                                    // Non-shard traffic (e.g. mesh relay) — no local handler.
                                }
                            }
                            }
                        }
                        None => {
                            info!("message channel closed");
                            break;
                        }
                    }
                }
                _ = recv_token.cancelled() => {
                    break;
                }
            }
        }
        info!(
            frames = frames_received,
            peer_infos = peer_infos_received,
            "message receiver stopped"
        );
        Ok(())
    });
}
