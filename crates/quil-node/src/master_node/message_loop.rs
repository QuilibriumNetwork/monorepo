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
    /// The FALCON network-identity signing key (`q-prover-key`) for outbound
    /// :8340 PQNoise dials — the prover-tree bootstrap sync uses this, NOT the
    /// legacy Ed448 `mtls_seed` (which the migrated transport can no longer
    /// decode). Present iff we have a transport identity.
    pub prover_falcon_key: Option<Vec<u8>>,
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
    pub frame_validator: quil_engine::frame_validator::GlobalFrameVerifier,
    pub message_collector: Arc<quil_engine::message_collector::MessageCollector>,
    pub coverage_monitor: Arc<quil_engine::coverage::CoverageMonitor>,
    pub worker_allocator: Arc<quil_engine::worker_allocator::WorkerAllocator>,
    pub prover_pipeline: Arc<quil_engine::prover_pipeline::ProverPipeline>,
    /// Commonware-simplex inbound router (P2c cutover), set post-spawn at the
    /// activation site when `config.engine.consensus_committee` is non-empty.
    /// Unset (the default) → the simplex path is off and this adds no overhead.
    pub cw_router:
        Arc<std::sync::OnceLock<Arc<crate::cw_consensus_bridge::CwInboundRouter>>>,
    pub peer_info_cache: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>,
    >>,
    pub shard_engines: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_engine::app_engine::AppEngineHandle>,
    >>,
    pub signer_registry: Arc<quil_p2p::SignerRegistry>,
    pub current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
    pub last_global_head_frame: Arc<std::sync::atomic::AtomicU64>,
    /// Stamped on every gossip-delivered `GLOBAL_FRAME` so the RPC poller can
    /// back off while the mesh is carrying the head.
    pub gossip_freshness: Arc<quil_rpc::GossipFreshness>,
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
    /// Archive-only: ingests full app-shard frames received on the bulk
    /// shard subscription and materializes them into the archive's CRDT.
    /// `None` on non-archive nodes.
    pub archive_app_shard_ingest:
        Option<quil_engine::archive_ingest::ArchiveAppShardIngest>,
    /// Explorer recent-message ring. `Some` only when the explorer service
    /// is enabled; every inbound gossip message is recorded for the
    /// `GET /messages` endpoint. `None` (the default) means no overhead.
    pub recent_messages: Option<Arc<quil_explorer::RecentMessageRing>>,
}

pub(crate) fn spawn(sup: &mut Supervisor<anyhow::Error>, args: MessageLoopArgs) {
    let MessageLoopArgs {
        clock_store: clock_store_recv,
        exec_manager: exec_mgr_for_recv,
        mut msg_rx,
        mut consensus_loopback_rx,
        global_msg_tx: gmtx_for_recv,
        archive_pool: pool_for_recv,
        mtls_seed: _mtls_seed_for_recv,
        prover_falcon_key: prover_falcon_for_recv,
        hg_store: hg_store_for_recv,
        frame_validator: frame_validator_for_recv,
        message_collector: mc_for_recv,
        coverage_monitor: coverage_for_recv,
        worker_allocator: wa_for_recv,
        prover_pipeline: pp_for_recv,
        peer_info_cache: pic_for_recv,
        shard_engines: shard_engines_for_recv,
        signer_registry: sr_for_recv,
        current_frame: cf_for_recv,
        last_global_head_frame: lhf_for_recv,
        gossip_freshness: gossip_freshness_for_recv,
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
        archive_app_shard_ingest,
        recent_messages: recent_messages_for_recv,
        cw_router: cw_router_for_recv,
    } = args;
    let mut archive_ingest_for_recv = archive_app_shard_ingest;

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
        // Per-SOURCE aggregation (propagation peer -> dropped-message count).
        // Distinguishes a targeted flood (drops concentrated on one/few peers →
        // blacklist candidate) from systemic backlog aging (drops spread across
        // every mesh peer → this node is overloaded, not attacked). Keyed by the
        // authenticated `from` peer, so it is bounded by the live connection set.
        let mut router_drops_by_source: std::collections::HashMap<Vec<u8>, u64> =
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
        // Epoch of the last frame whose crossing triggered a registry refresh.
        // Prover ALLOCATIONS only take effect at epoch boundaries
        // (`effective_status` is epoch-quantized: activation/departure/expiry all
        // flip on `epoch_for_frame` boundaries), so the shared prover-registry
        // cache — which drives every worker's app-shard COMMITTEE and this loop's
        // `on_new_frame` reconcile — only needs to be refreshed once per epoch.
        // Refreshing per-frame is both wasteful (a full O(N) store scan) and, on
        // the recv path, was simply ABSENT: `on_new_frame` reconciled against a
        // never-refreshed cache on non-archive nodes. Track the epoch and refresh
        // exactly on a boundary crossing.
        let mut last_committee_epoch: u64 =
            quil_types::consensus::epoch_for_frame(last_executed_frame);
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
                        // Top drop sources: `peer(short-hex)=count`, most first.
                        // A single peer dominating ⇒ targeted flood; even spread
                        // ⇒ this node is backlog-aging (overloaded), not attacked.
                        drop_sources = %{
                            let mut entries: Vec<(&Vec<u8>, &u64)> =
                                router_drops_by_source.iter().collect();
                            entries.sort_by(|a, b| b.1.cmp(a.1));
                            entries.into_iter().take(8)
                                .map(|(k, v)| {
                                    let h = hex::encode(k);
                                    let short = if h.len() > 12 { &h[..12] } else { &h };
                                    format!("{}={}", short, v)
                                })
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
                    // jemalloc allocator stats — PROCESS-GLOBAL, so this single
                    // line captures the master, every worker thread, AND the
                    // C++ RocksDB allocations. The decisive OOM signal:
                    //   allocated rising → true live-heap leak
                    //   allocated flat, resident hi → fragmentation, not a leak
                    // Compare `allocated_mb` across ticks to tell them apart.
                    if let Some(j) = crate::mem_stats::jemalloc_stats() {
                        info!(
                            allocated_mb = %crate::mem_stats::fmt_mb(j.allocated),
                            active_mb = %crate::mem_stats::fmt_mb(j.active),
                            resident_mb = %crate::mem_stats::fmt_mb(j.resident),
                            retained_mb = %crate::mem_stats::fmt_mb(j.retained),
                            mapped_mb = %crate::mem_stats::fmt_mb(j.mapped),
                            "jemalloc stats"
                        );
                        // Localize the leak BY ALLOCATION SIZE: the dominant
                        // size class says small-objects-leak vs big-buffers-leak
                        // and the exact byte size to cross-reference. Sampled
                        // here (cheap mallctl reads), so the next status tick on
                        // an affected node pins where the 40 GB lives.
                        let br = crate::mem_stats::jemalloc_size_classes();
                        info!(
                            breakdown = %crate::mem_stats::fmt_breakdown(&br),
                            "jemalloc size classes"
                        );
                    }
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
                            // Explorer tap: record every inbound gossip
                            // message for the `GET /messages` endpoint.
                            // Only present when the explorer is enabled,
                            // so this is a no-op otherwise.
                            if let Some(ring) = &recent_messages_for_recv {
                                ring.push_received(
                                    &received.from,
                                    &received.bitmask,
                                    &received.data,
                                );
                            }

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
                                // Attribute the drop to the peer that forwarded
                                // it (bounded by the live connection set).
                                if !received.from.is_empty() {
                                    *router_drops_by_source
                                        .entry(received.from.clone())
                                        .or_insert(0) += 1;
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

                            // Commonware-simplex cutover (P2c): when the simplex
                            // router is wired (committee configured), a message on
                            // one of its channel bitmasks is fed to the engine and
                            // the legacy dispatch below is skipped. Off by default
                            // (router unset) → zero overhead.
                            if let Some(router) = cw_router_for_recv.get() {
                                if router.route(
                                    &received.bitmask,
                                    &received.from,
                                    received.data.clone(),
                                ) {
                                    continue;
                                }
                            }

                            match received.bitmask.as_slice() {
                            GLOBAL_PEER_INFO => {
                                match quil_p2p::classify_peer_info_message(&received.data) {
                                    Ok(quil_p2p::PeerInfoMessage::PeerInfo(info)) => {
                                        peer_infos_received += 1;
                                        // Signature validation MOVED here from the
                                        // route validator (which now does timestamp
                                        // only — Falcon verify inline on the recv
                                        // loop was starving it and overflowing the
                                        // per-peer send queue). Runs AFTER retrieval,
                                        // BEFORE the entry is cached/trusted, so an
                                        // unverified/spoofed PeerInfo never reaches
                                        // the peer_info_cache or the archive
                                        // admission gate below.
                                        //   1. Falcon key/sig lengths (897 / 666).
                                        //   2. peer_id ↔ signing-pubkey binding —
                                        //      without it an attacker signs with
                                        //      their OWN key but sets peer_id to a
                                        //      genesis archive's, impersonating it to
                                        //      the admission gate.
                                        //   3. Falcon verify (empty domain, matching
                                        //      `Signer::sign` = sign_with_domain(m,&[])).
                                        if info.peer_id.is_empty()
                                            || info.public_key.len() != 897
                                            || info.signature.len() != 666
                                        {
                                            continue;
                                        }
                                        if info.peer_id
                                            != quil_p2p::peer_id_from_falcon_pubkey(&info.public_key)
                                        {
                                            continue;
                                        }
                                        let signing_payload = quil_p2p::encode_canonical_peer_info(
                                            &info,
                                            &info.public_key,
                                            &[],
                                        );
                                        if !quil_crypto::falcon_verify(
                                            &info.public_key,
                                            &info.signature,
                                            &signing_payload,
                                            &[],
                                        ) {
                                            continue;
                                        }
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
                                                debug!(
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
                                            // Authenticated network-head hint for the poller's
                                            // reconcile: this PeerInfo is signed and genesis-archive
                                            // verified, so its advertised head lets the poller decide
                                            // "am I behind?" without an RPC head-fetch.
                                            gossip_freshness_for_recv
                                                .note_network_head(info.last_global_head_frame);
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
                                                    (prover_falcon_for_recv.clone(), first_addr)
                                                {
                                                    let store = hg_store_for_recv.clone();
                                                    let cs = clock_store_recv.clone();
                                                    let crdt_for_bootstrap = exec_mgr_for_recv.crdt();
                                                    spawner.detach("prover-tree-bootstrap", async move {
                                                        // Pin sync against the most-recent verified
                                                        // frame's prover_tree_commitment (when
                                                        // available). Empty during bootstrap before
                                                        // any frame is stored.
                                                        let expected_root = cs
                                                            .get_latest_global_frame()
                                                            .ok()
                                                            .and_then(|f| f.header.map(|h| h.prover_tree_commitment))
                                                            .unwrap_or_default();
                                                        // Onboarding: swap the ephemeral in-memory
                                                        // forest for the persistent RocksDB one (+ QUIL
                                                        // partition) BEFORE syncing, so synced state is
                                                        // durable and produced roots are network-consistent.
                                                        // No-op once persistent.
                                                        if quil_forest_migrate::install_forest_for_sync(
                                                            crdt_for_bootstrap.as_ref(), store.as_ref(),
                                                            network_for_recv == 0,
                                                        ) {
                                                            info!("prover-tree-bootstrap: installed persistent forest for onboarding sync");
                                                        }
                                                        // Forest sync of the global prover shard
                                                        // (single-shard, all 4 phases + blobs).
                                                        match crate::forest_sync::sync_single_shard_verified(
                                                            &addr, &seed, crdt_for_bootstrap, &[0xffu8; 32], &expected_root,
                                                        ).await {
                                                            Ok(converged) => {
                                                                info!(addr = %addr, match_ok = converged, "prover tree bootstrap synced");
                                                            }
                                                            Err(e) => {
                                                                warn!(addr = %addr, error = %e, "prover tree bootstrap sync failed");
                                                            }
                                                        }

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
                                                // Finding B: `update` verifies the
                                                // identity↔prover cross-signatures and
                                                // rejects (returns false) any binding
                                                // whose sigs don't validate, so a peer
                                                // can't inject an arbitrary Ed448→BLS
                                                // pairing.
                                                if sr_for_recv.update(reg) {
                                                    debug!(
                                                        identity_len,
                                                        prover_len,
                                                        total_entries = sr_for_recv.len(),
                                                        "ingested KeyRegistry"
                                                    );
                                                } else {
                                                    debug!(
                                                        identity_len,
                                                        prover_len,
                                                        "rejected KeyRegistry: invalid cross-signature, empty key, or stale replay"
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                debug!(error = %e, "failed to decode KeyRegistry");
                                            }
                                        }
                                    }
                                    Ok(quil_p2p::PeerInfoMessage::Unknown(prefix)) => {
                                        debug!(prefix = format!("0x{:04x}", prefix),
                                            "unknown PEER_INFO bitmask message type");
                                    }
                                    Err(e) => {
                                        debug!(error = %e, "failed to decode PeerInfo");
                                    }
                                }
                            }
                            GLOBAL_FRAME => {
                                // Try canonical bytes first (the wire format),
                                // fall back to proto decode (archive poller uses proto).
                                let frame_result: std::result::Result<quil_types::proto::global::GlobalFrame, _> =
                                    quil_engine::consensus_wire::decode_global_frame(&received.data)
                                        .or_else(|canonical_err| {
                                            debug!(error = %canonical_err, "canonical decode failed, trying proto");
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
                                                debug!(
                                                    frame = frame_num,
                                                    prover = hex::encode(&h.prover),
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "INVALID PROVER — not a genesis prover, possible attacker"
                                                );
                                                continue;
                                            }
                                        }

                                        // Frame-number sanity (cheap, pre-cert). Gossip is
                                        // head-only, so a legit frame sits at ~the network head;
                                        // one implausibly far beyond our head can only be a forged
                                        // number aimed at poisoning the head atomic / gossip-head
                                        // target. Shed it before the (Falcon) cert verify below. The
                                        // margin is deliberately huge (~1M frames ≈ months) so a
                                        // genuinely behind node still follows the real head; a node
                                        // that far behind uses the state-jump path, not gossip.
                                        {
                                            const MAX_HEAD_LEAD: u64 = 1_000_000;
                                            let head_now = lhf_for_recv
                                                .load(std::sync::atomic::Ordering::Relaxed);
                                            if frame_num > head_now.saturating_add(MAX_HEAD_LEAD) {
                                                debug!(
                                                    frame = frame_num,
                                                    head = head_now,
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "gossip global frame implausibly far ahead — dropping",
                                                );
                                                continue;
                                            }
                                        }

                                        // UNTRUSTED SOURCE GATE. This frame came off the open
                                        // GLOBAL_FRAME gossip mesh (any peer can publish), not the
                                        // mTLS-authenticated archive poller. The VDF proof below is
                                        // PUBLICLY COMPUTABLE — it authenticates nothing — and the
                                        // genesis-prover check above is a public-address allowlist.
                                        // So require a committee FINALIZATION cert (CWCT) that
                                        // verifies against the fixed global committee: this proves
                                        // the committee actually finalized the frame. Fails closed
                                        // (no committee / no cert / bad cert ⇒ drop) and runs BEFORE
                                        // the expensive VDF verify so forged frames are cheap to shed.
                                        // Legit gossip + archive frames both carry this cert.
                                        match frame.header.as_ref() {
                                            Some(h) if frame_validator_for_recv
                                                .verify_global_finalization_cert(h) => {}
                                            _ => {
                                                debug!(
                                                    frame = frame_num,
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "gossip global frame missing/invalid committee finalization cert — dropping",
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
                                                debug!(frame = frame_num, "frame rejected by validator — dropping");
                                                continue;
                                            }
                                            Ok(Err(e)) => {
                                                debug!(frame = frame_num, error = %e, "VDF validation error — dropping frame");
                                                continue;
                                            }
                                            Err(_) => {
                                                debug!(
                                                    frame = frame_num,
                                                    output_len = frame.header.as_ref().map(|h| h.output.len()).unwrap_or(0),
                                                    "VDF validation PANIC — frame output likely corrupted, dropping"
                                                );
                                                continue;
                                            }
                                        }

                                        // BIND THE BODY TO THE AUTHENTICATED HEADER. The cert + VDF
                                        // above authenticate the header (incl. `requests_root`), but
                                        // `frame.requests` is a separate field. An attacker could keep
                                        // a real frame's valid header+cert+VDF and swap in a different
                                        // request set — each request is still intrinsic-validated on
                                        // execution, but a receiver would compute a DIVERGENT state for
                                        // this frame. Recompute the requests root from the carried body
                                        // and require it to equal the authenticated `requests_root`.
                                        // (The mTLS poller path trusts its source; this gate is for the
                                        // untrusted gossip mesh.)
                                        // Bound the work an attacker can force. Recomputing the
                                        // requests root builds a commitment tree over every bundle and
                                        // converts every request. A real header+cert can be REPLAYED
                                        // with a maximally-large tampered body (a 16 MiB frame packs
                                        // millions of minimal bundles) to burn seconds of CPU before
                                        // the root mismatch is detected — the check is inherently
                                        // build-then-compare. Shed oversized bodies here, cheaply
                                        // (O(bundles) length reads, no tree work), before the recompute.
                                        // Typical global frames are far under these caps; a rare genuinely
                                        // huge frame simply isn't followed over gossip and is instead
                                        // fetched by the RPC poller (which has no such cap and trusts its
                                        // mTLS source), so correctness is preserved.
                                        {
                                            const MAX_GOSSIP_GLOBAL_BUNDLES: usize = 65_536;
                                            const MAX_GOSSIP_GLOBAL_REQUESTS: usize = 65_536;
                                            let total_requests: usize =
                                                frame.requests.iter().map(|b| b.requests.len()).sum();
                                            if frame.requests.len() > MAX_GOSSIP_GLOBAL_BUNDLES
                                                || total_requests > MAX_GOSSIP_GLOBAL_REQUESTS
                                            {
                                                debug!(
                                                    frame = frame_num,
                                                    bundles = frame.requests.len(),
                                                    requests = total_requests,
                                                    from = bs58::encode(&received.from).into_string(),
                                                    "gossip global frame body oversized — dropping (poller fetches if real)",
                                                );
                                                continue;
                                            }
                                        }

                                        // Recompute runs on the ATTACKER-CONTROLLED body (before the
                                        // match rejects a forgery), so contain any panic in the
                                        // canonical-encoding / tree path exactly like the VDF verify
                                        // above — a panic ⇒ treat as invalid ⇒ drop, never crash the
                                        // recv loop.
                                        let requests_root_ok = std::panic::catch_unwind(
                                            std::panic::AssertUnwindSafe(|| match frame.header.as_ref() {
                                                Some(h) => frame_validator_for_recv
                                                    .verify_global_requests_root(h, &frame.requests),
                                                None => false,
                                            }),
                                        )
                                        .unwrap_or(false);
                                        if !requests_root_ok {
                                            debug!(
                                                frame = frame_num,
                                                from = bs58::encode(&received.from).into_string(),
                                                "gossip global frame body does not match authenticated requests_root — dropping",
                                            );
                                            continue;
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
                                                // Signal the RPC poller that gossip is delivering the
                                                // head, so it backs off its redundant per-second fetch.
                                                gossip_freshness_for_recv.stamp(frame_num);

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
                                                    // Archives apply GLOBAL frame state ONLY through the
                                                    // dedicated in-order materializer (frame_materializer +
                                                    // the archive_sync consumer), which owns the durable
                                                    // cursor and the frozen-era no-op gate. This gossip-
                                                    // driven `process_global_frame_with_rewards` path is a
                                                    // SECOND, ungated state applier: it double-applies
                                                    // rewards/prover ops and — during the flag-day recovery —
                                                    // executes frozen-era frames the materializer is
                                                    // no-op'ing (the "invoke_step: prover/allocation not
                                                    // found" storm). Never run it on archives.
                                                    Vec::new()
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
                                                            // Epoch-boundary registry refresh: repopulate the
                                                            // shared prover-registry cache from the just-
                                                            // materialized store when we cross into a new epoch,
                                                            // so the committee + `on_new_frame` reconcile read
                                                            // the new epoch's allocations. Allocations are
                                                            // epoch-stable, so one refresh per boundary is
                                                            // sufficient (and avoids a per-frame full scan). This
                                                            // is the previously-missing recv-path refresh.
                                                            let exec_epoch =
                                                                quil_types::consensus::epoch_for_frame(exec_num);
                                                            if exec_epoch != last_committee_epoch {
                                                                pr_for_recv.refresh_from_store(&hg_store_for_recv);
                                                                last_committee_epoch = exec_epoch;
                                                                debug!(
                                                                    frame = exec_num,
                                                                    epoch = exec_epoch,
                                                                    "epoch boundary — refreshed prover registry"
                                                                );
                                                            }
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
                                        debug!(
                                            error = %e,
                                            bytes = received.data.len(),
                                            prefix = %prefix,
                                            "GLOBAL_FRAME decode failed"
                                        );
                                    }
                                }
                            }
                            GLOBAL_CONSENSUS => {
                                // Legacy Jolteon (in-house quil-consensus)
                                // gossip topic. The commonware-simplex GLOBAL
                                // consensus path delivers proposals/votes/certs
                                // point-to-point over :8340 and routes them
                                // through `cw_router`, so these gossip messages
                                // are no longer decoded/aggregated here — count
                                // and drop.
                                consensus_msgs_received += 1;
                            }
                            GLOBAL_PROVER => {
                                prover_msgs_received += 1;
                                // Tag with the CONSENSUS RANK (matches the
                                // gRPC submit path and the leader's
                                // `collect_for_rank`). `frames_received` is a
                                // session-local counter in the wrong space, so
                                // relayed prover messages were never collected.
                                let current_rank = cf_for_recv.effective_rank();
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
                                    // (P3) Commonware-simplex shard traffic. Split the
                                    // channel out of the payload byte, and resolve the
                                    // gossip sender's peer id → its committee Falcon key
                                    // via PeerInfo (`CanonicalPeerInfo.public_key` is the
                                    // prover key = the committee member key). The Falcon
                                    // attestation self-attributes via its embedded signer
                                    // index, so `from` is advisory for verification — but
                                    // it must be a valid committee key or the engine drops
                                    // it; an empty `from` (peer not yet in PeerInfo) is a
                                    // benign startup transient until the peer's PeerInfo
                                    // propagates.
                                    if bm == quil_engine::bitmasks::shard_cw_bitmask(filter).as_slice() {
                                        if let Some((channel, cw_bytes)) =
                                            quil_engine::bitmasks::shard_cw_split_payload(&received.data)
                                        {
                                            let from_key = pic_for_recv
                                                .read()
                                                .get(&received.from)
                                                .map(|pi| pi.public_key.clone())
                                                .unwrap_or_default();
                                            handle.send(quil_engine::app_engine::AppEngineMessage::CwIn {
                                                channel,
                                                from: from_key,
                                                data: cw_bytes.to_vec(),
                                            });
                                        }
                                        routed = true;
                                        break;
                                    }
                                }
                                if !routed {
                                    // Non-shard traffic (e.g. mesh relay) — no local
                                    // handler. On an archive (no local shard engines),
                                    // un-routed shard-frame traffic lands here: feed it to
                                    // the app-shard ingest, which decodes/verifies it as a
                                    // full AppShardFrame (non-frame messages fail decode and
                                    // are ignored) and materializes the shard's state.
                                    if let Some(ingest) = archive_ingest_for_recv.as_mut() {
                                        ingest.ingest(&received.data);
                                    }
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
