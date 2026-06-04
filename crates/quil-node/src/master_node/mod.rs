use std::sync::Arc;

use tracing::{debug, info, warn};

use quil_lifecycle::{ShutdownReason, Supervisor};

pub(crate) mod allocator_and_lifecycle;
pub(crate) mod archive_sync;
pub(crate) mod engines;
pub(crate) mod frame_pipeline;
pub(crate) mod grpc;
pub(crate) mod keys;
pub(crate) mod message_loop;
pub(crate) mod networking;
pub(crate) mod peer_info_publisher;
pub(crate) mod runtime_state;
pub(crate) mod storage;
pub(crate) mod worker_manager;

pub(crate) async fn start(
    mut sup: Supervisor<anyhow::Error>,
    config: &quil_config::Config,
    config_dir: &std::path::Path,
    archive_mode: bool,
    network: u8,
    metrics_handle: Option<metrics_exporter_prometheus::PrometheusHandle>,
) -> anyhow::Result<ShutdownReason<anyhow::Error>> {
    // Cloneable spawner for fire-and-forget tasks that can't await
    // inline (sync trait impls, gRPC handlers, drain loops). Tasks
    // submitted via this handle surface panics/errors to the
    // supervisor instead of being silently swallowed by bare
    // `tokio::spawn`.
    let detached_spawner = sup.detached_spawner();

    let storage = storage::init(config, archive_mode)?;
    let db_arc = storage.db_arc.clone();
    let clock_store = storage.clock_store.clone();
    let token_store = storage.token_store.clone();
    let key_store = storage.key_store.clone();
    let shards_store = storage.shards_store.clone();
    let hg_store = storage.hg_store.clone();

    let keys = keys::init(config, config_dir)?;
    let file_key_manager = keys.file_key_manager.clone();
    let bls_pubkey = keys.bls_pubkey.clone();
    let prover_address = keys.prover_address;

    let engines = engines::init_engines(&storage);
    let inclusion_prover = engines.inclusion_prover.clone();
    let crdt = engines.crdt.clone();
    let exec_manager = engines.exec_manager.clone();
    engines::bootstrap_genesis(network, config, &storage, &engines, &bls_pubkey)?;


    let frame_pipeline::FramePipeline {
        frame_prover,
        frame_validator,
        fee_manager,
    } = frame_pipeline::init();

    let networking::P2pHandles {
        p2p_handle,
        msg_rx,
        peer_id,
        consensus_loopback_tx,
        consensus_loopback_rx,
        listen_addr,
    } = networking::init(&mut sup, config, config_dir, network, archive_mode).await?;

    // Frame tracking — single source of truth for "what frame is
    // this node on right now." Updated by the BlossomSub receive
    // loop (`observe`), archive poller (`observe`), and frame
    // materializer (`materialize`). Read by RPC handlers,
    // shard-info, peer-info publisher, lifecycle, eviction, and
    // every other site that previously took `max(clock_store, lrf)`.
    let current_frame = quil_engine::current_frame::CurrentFrame::new();
    // Seed from any frame already persisted to the clock store so
    // RPC consumers can read a sensible current frame *immediately*
    // at startup — before the first BlossomSub frame arrives. The
    // `observe` call is monotonic, so a later live frame can still
    // advance it.
    if let Ok(frame) = clock_store.get_latest_global_frame() {
        if let Some(h) = frame.header.as_ref() {
            current_frame.observe(h.frame_number);
        }
    }
    // PeerInfo cache populated by the GLOBAL_PEER_INFO recv path.
    // Read by NodeService::get_peer_info so CLI tools can enumerate
    // the peers this node has observed on the network. Keyed by the
    // raw peer_id bytes; last-write-wins.
    // parking_lot::RwLock instead of std::sync::RwLock: smaller +
    // faster, no poisoning (so `.read()` / `.write()` return guards
    // directly without `.unwrap()`), and better fairness under
    // contention. This is a strict ergonomics + perf upgrade, NOT
    // an async-fix — parking_lot's lock is still blocking from
    // tokio's view. Switch to `tokio::sync::RwLock` if reads need
    // to yield instead of block.
    let peer_info_cache: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>,
    >> = Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
    // filter → AppEngineHandle registry. Populated by the worker→master
    // drain task on `WorkerToMaster::ShardActivated` and cleared on
    // `ShardDeactivated`. Read by the inbound BlossomSub recv loop to
    // route per-shard frame / consensus / prover / dispatch messages
    // to the right engine in multi-prover deployments.
    let shard_engines: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_engine::app_engine::AppEngineHandle>,
    >> = Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
    // SignerRegistry — populated from inbound KeyRegistry broadcasts
    // on GLOBAL_PEER_INFO. Consumed by consensus message verification
    // (BLS signatures from peers whose identity↔prover binding we've
    // observed).
    let signer_registry: Arc<quil_p2p::SignerRegistry> =
        Arc::new(quil_p2p::SignerRegistry::new());
    // Seed from the local clock store so PeerInfo broadcasts our
    // real head on the first publish. Without this, restart leaves
    // the atomic at 0 until a new frame arrives over the network —
    // peers then see `head_frame=0` in our PeerInfo, can't form a
    // quorum on rank N+1 because they assume we have no state, and
    // consensus stalls. Loading the local latest from RocksDB
    // (which the migration already populated to e.g. 414) closes
    // the gap immediately.
    let initial_head_frame: u64 = clock_store
        .get_latest_global_frame()
        .ok()
        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
        .unwrap_or(0);
    if initial_head_frame > 0 {
        info!(
            head_frame = initial_head_frame,
            "seeded last_global_head_frame from local clock store",
        );
    }
    let last_global_head_frame = Arc::new(std::sync::atomic::AtomicU64::new(initial_head_frame));

    // Deferred worker-manager handle for per-worker reachability
    // advertisements. The PeerInfo broadcaster spawns here (before
    // `worker_manager` exists). Once `worker_manager` is constructed
    // ~250 lines below, it's published into this OnceLock. The next
    // PeerInfo tick picks it up. First tick (immediate at startup)
    // may publish without per-worker entries; subsequent ticks
    // include them.
    let pi_worker_manager: Arc<std::sync::OnceLock<
        Arc<dyn quil_engine::worker::WorkerManager>,
    >> = Arc::new(std::sync::OnceLock::new());
    peer_info_publisher::spawn(&mut sup, peer_info_publisher::PeerInfoPublisherArgs {
        p2p_handle: p2p_handle.clone(),
        peer_id,
        peer_priv_key_hex: config.p2p.peer_priv_key.clone(),
        announce_listen_multiaddr: config.p2p.announce_listen_multiaddr.clone(),
        announce_stream_listen_multiaddr: config.p2p.announce_stream_listen_multiaddr.clone(),
        stream_listen_multiaddr: config.p2p.stream_listen_multiaddr.clone(),
        listen_fallback: listen_addr.clone(),
        current_frame: current_frame.clone(),
        last_global_head_frame: last_global_head_frame.clone(),
        worker_p2p_multiaddrs: config.engine.data_worker_p2p_multiaddrs.clone(),
        worker_stream_multiaddrs: config.engine.data_worker_stream_multiaddrs.clone(),
        worker_announce_p2p: config.engine.data_worker_announce_p2p_multiaddrs.clone(),
        worker_announce_stream: config.engine.data_worker_announce_stream_multiaddrs.clone(),
        worker_manager_cell: pi_worker_manager.clone(),
        bls_pubkey: bls_pubkey.clone(),
        key_manager: file_key_manager.clone(),
        exec_manager: exec_manager.clone(),
        archive_mode,
    });

    let runtime_state::RuntimeState {
        message_collector,
        prover_registry,
        prover_only_flag: _prover_only_flag,
        global_event_distributor,
        coverage_monitor,
        halt_state,
        remote_worker_manager_for_halt,
    } = runtime_state::init(&mut sup, hg_store.clone(), shard_engines.clone());

    // Lazy cell holding the prover-message transport. The transport
    // itself is constructed later (it depends on the archive pool and
    // mtls seed which are resolved further down), but worker_manager
    // needs a stable handle now to wire up its publish paths.
    // `set()` is called once the real transport is built.
    let prover_message_transport_cell: Arc<
        std::sync::OnceLock<
            Arc<dyn quil_engine::prover_message_transport::ProverMessageTransport>,
        >,
    > = Arc::new(std::sync::OnceLock::new());

    let worker_manager: Arc<dyn quil_engine::worker::WorkerManager> = worker_manager::init(
        &mut sup,
        worker_manager::WorkerManagerArgs {
            config: config.clone(),
            archive_mode,
            p2p_handle: p2p_handle.clone(),
            db_arc: db_arc.clone(),
            clock_store: clock_store.clone(),
            crdt: crdt.clone(),
            exec_manager: exec_manager.clone(),
            inclusion_prover: inclusion_prover.clone(),
            frame_prover: frame_prover.clone(),
            message_collector: message_collector.clone(),
            fee_manager: fee_manager.clone(),
            prover_registry: prover_registry.clone(),
            halt_state: halt_state.clone(),
            file_key_manager: file_key_manager.clone(),
            prover_address,
            bls_pubkey: bls_pubkey.clone(),
            shard_engines: shard_engines.clone(),
            remote_worker_manager_for_halt: remote_worker_manager_for_halt.clone(),
            pi_worker_manager: pi_worker_manager.clone(),
            prover_message_transport: prover_message_transport_cell.clone(),
            spawner: detached_spawner.clone(),
        },
    );

    let allocator_and_lifecycle::LifecycleHandles {
        worker_allocator,
        consensus_handle,
        vote_aggregator,
        timeout_aggregator,
        prover_lifecycle,
        frame_materializer,
    } = allocator_and_lifecycle::init(&mut sup, allocator_and_lifecycle::LifecycleInitArgs {
        config: config.clone(),
        network,
        archive_mode,
        worker_manager: worker_manager.clone(),
        prover_registry: prover_registry.clone(),
        prover_address,
        halt_state: halt_state.clone(),
        current_frame: current_frame.clone(),
        last_global_head_frame: last_global_head_frame.clone(),
        shards_store: shards_store.clone(),
        exec_manager: exec_manager.clone(),
        frame_prover: frame_prover.clone(),
        inclusion_prover: inclusion_prover.clone(),
        clock_store: clock_store.clone(),
        crdt: crdt.clone(),
        hg_store: hg_store.clone(),
    });

    // ---------------------------------------------------------------
    // 6. Message receive loop
    // ---------------------------------------------------------------
    info!(archive = archive_mode, "master node initialized — waiting for frames");


    // Resolve our Ed448 seed (57 bytes) for the mTLS cert. The peer key in
    // config is either 57 bytes (raw seed) or 114 bytes (seed + pubkey).
    let mtls_seed: Option<[u8; 57]> = (|| {
        let bytes = hex::decode(&config.p2p.peer_priv_key).ok()?;
        if bytes.len() < 57 {
            return None;
        }
        let mut seed = [0u8; 57];
        seed.copy_from_slice(&bytes[..57]);
        Some(seed)
    })();

    // Log Ed448 identity if available
    if let Some(ref seed) = mtls_seed {
        let ed448_pubkey = quil_p2p::ed448_identity::derive_public_key(seed);
        let ed448_peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&ed448_pubkey);
        info!(
            ed448_peer_id = hex::encode(&ed448_peer_id),
            ed448_pubkey_len = ed448_pubkey.len(),
            "Ed448 identity ready (Go-compatible peer ID)"
        );
    }

    // Pool of *archive-capable* endpoints, populated by the BlossomSub
    // PeerInfo handler whenever it sees a peer advertising
    // ARCHIVE_SERVICE_CAPABILITY_ID. The poller spawned below picks one as
    // its source and forward-polls the chain head.
    let archive_pool = std::sync::Arc::new(quil_rpc::ArchiveEndpointPool::new());

    // Pre-seed the archive pool. Precedence matches the Go node
    // (`node/main.go:737-741`):
    //   1. If `engine.archiveEndpoints` is non-empty, use those.
    //   2. Else, on mainnet (network == 0), fall back to the hardcoded
    //      genesis-archive static IPs.
    //   3. Else, nothing — PeerInfo gossip will populate the pool once
    //      the libp2p mesh converges.
    // The pool needs at least one reachable endpoint before the mesh
    // converges so the shard-info remote fallback (and any other
    // archive-pool consumer) has somewhere to dial. mTLS gRPC
    // convention is TCP/8340.
    if !config.engine.archive_endpoints.is_empty() {
        for raw in &config.engine.archive_endpoints {
            match crate::util::multiaddr::archive_multiaddr_to_host_port(raw, network) {
                Some(endpoint) => {
                    archive_pool.add(endpoint.clone()).await;
                    tracing::debug!(
                        multiaddr = %raw,
                        endpoint = %endpoint,
                        "seeded archive pool from engine.archiveEndpoints"
                    );
                }
                None => {
                    tracing::warn!(
                        multiaddr = %raw,
                        "skipping invalid engine.archiveEndpoints entry (expected /ip4|ip6|dns4|dns6|dns/.../tcp/PORT)"
                    );
                }
            }
        }
    } else if network == 0 {
        let pool = archive_pool.clone();
        let static_ips = quil_engine::genesis::genesis_archive_static_ips();
        for (peer_id, ip) in static_ips {
            let endpoint = format!("{}:8340", ip);
            pool.add(endpoint.clone()).await;
            tracing::debug!(
                peer = %peer_id,
                endpoint = %endpoint,
                "seeded archive pool with static genesis-archive mTLS endpoint"
            );
        }
    }

    // Load genesis archive peer IDs for validation (5 archives + beacon)
    let genesis_archive_peer_ids: std::collections::HashSet<Vec<u8>> = {
        let mut ids: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        // 5 archive peers
        if let Ok(peers) = quil_engine::genesis::genesis_archive_peers() {
            for (pid, _) in peers {
                if let Ok(decoded) = bs58::decode(&pid).into_vec() {
                    ids.insert(decoded);
                }
            }
        }
        // Beacon peer — derive peer ID from Ed448 key
        if let Ok(data) = quil_engine::genesis::get_mainnet_genesis_data() {
            if let Ok(ed448_key) = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &data.beacon_ed448_key,
            ) {
                // Ed448 peer ID = multihash(identity, protobuf(KeyType=4, key=ed448_bytes))
                // Protobuf: field 1 (varint) = 4, field 2 (bytes) = key
                let mut proto = vec![0x08, 0x04, 0x12, ed448_key.len() as u8];
                proto.extend_from_slice(&ed448_key);
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(&proto);
                // Multihash: 0x12 (SHA2-256) + 0x20 (32 bytes) + hash
                let mut mh = vec![0x12u8, 0x20];
                mh.extend_from_slice(&hash);
                ids.insert(mh);
            }
        }
        ids
    };
    // Valid genesis prover ADDRESSES (Poseidon(BLS pubkey)). The frame
    // header's `prover` field is the 32-byte address, not the raw key.
    // Mainnet uses embedded genesis (5 archive peers + beacon);
    // testnet/devnet uses `config.engine.genesis_seed`.
    let genesis_prover_addrs: std::collections::HashSet<Vec<u8>> = {
        let mut addrs = std::collections::HashSet::new();
        if network == 0 {
            if let Ok(data) = quil_engine::genesis::get_mainnet_genesis_data() {
                if let Ok(beacon_key) = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &data.beacon_bls48581_key,
                ) {
                    if let Ok(addr) = quil_crypto::poseidon::hash_bytes_to_32(&beacon_key) {
                        addrs.insert(addr.to_vec());
                    }
                }
                for (_pid, pubkey_hex) in &data.archive_peers {
                    if let Ok(key) = hex::decode(pubkey_hex) {
                        if let Ok(addr) = quil_crypto::poseidon::hash_bytes_to_32(&key) {
                            addrs.insert(addr.to_vec());
                        }
                    }
                }
            }
        } else {
            match quil_engine::genesis::resolve_testnet_prover_keys(
                network,
                &config.engine.genesis_seed,
                &bls_pubkey,
            ) {
                Ok(keys) => {
                    for key in &keys {
                        if let Ok(addr) = quil_crypto::poseidon::hash_bytes_to_32(key) {
                            addrs.insert(addr.to_vec());
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, network = network, "could not resolve testnet genesis provers");
                }
            }
        }
        addrs
    };
    info!(
        genesis_archives = genesis_archive_peer_ids.len(),
        genesis_provers = genesis_prover_addrs.len(),
        "loaded genesis peer data for validation"
    );

    // Assemble the multisig Ed448 seed set for seniority merge helpers.
    // Always includes our local peer-private key seed; extra seeds are
    // loaded from `config.engine.multisig_prover_enrollment_paths`. The
    // pipeline signs the local BLS prover pubkey once per seed under
    // the `PROVER_SENIORITY_MERGE` domain.
    let mut multisig_ed448_seeds: Vec<[u8; 57]> = Vec::new();
    {
        let bytes = hex::decode(&config.p2p.peer_priv_key).unwrap_or_default();
        if bytes.len() >= 57 {
            let mut seed = [0u8; 57];
            seed.copy_from_slice(&bytes[..57]);
            multisig_ed448_seeds.push(seed);
        }
        for extra_path in &config.engine.multisig_prover_enrollment_paths {
            let path = std::path::PathBuf::from(extra_path);
            if let Ok(extra_cfg) = quil_config::load_config(&path) {
                if let Ok(extra_bytes) = hex::decode(&extra_cfg.p2p.peer_priv_key) {
                    if extra_bytes.len() >= 57 {
                        let mut seed = [0u8; 57];
                        seed.copy_from_slice(&extra_bytes[..57]);
                        multisig_ed448_seeds.push(seed);
                    }
                }
            }
        }
    }

    // Build the prover submission pipeline. Owned as an Arc so both the
    // poller on_frame callback and the BlossomSub message-receive loop
    // can dispatch lifecycle actions.
    // Hex-decode the configured delegate address (empty string =
    // empty Vec). A misconfigured delegate is downgraded to a warning
    // + default empty rather than aborting, so a typo doesn't take
    // the node down — emit an empty-delegate join (semantically
    // equivalent) instead of refusing to join.
    let delegate_address: Vec<u8> = {
        let raw = config.engine.delegate_address.trim();
        if raw.is_empty() {
            Vec::new()
        } else {
            match hex::decode(raw) {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(
                        delegate_address = raw,
                        %e,
                        "config.engine.delegate_address is not valid hex; \
                         defaulting to empty"
                    );
                    Vec::new()
                }
            }
        }
    };

    // Production transport: gRPC fan-out to archives. Archive nodes
    // also publish on BlossomSub for maximum dissemination; non-archive
    // nodes skip the gossip publish (they don't subscribe to
    // GLOBAL_PROVER so publishing into it is wasteful and unreliable).
    let prover_message_transport: Arc<dyn quil_engine::prover_message_transport::ProverMessageTransport> =
        Arc::new(crate::prover_message_transport_prod::ProdProverMessageTransport {
            archive_pool: archive_pool.clone(),
            clock_store: clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
            p2p_handle: p2p_handle.clone(),
            ed448_seed: mtls_seed,
            publish_to_blossomsub: archive_mode,
        });

    // Hand the freshly-built transport to the worker_manager so its
    // coverage_publish closure and shard-finalize drain can route
    // reward proofs through the gRPC archive fan-out instead of a
    // direct BlossomSub publish on GLOBAL_PROVER (which fails on
    // non-archive nodes — they don't subscribe to that bitmask).
    let _ = prover_message_transport_cell.set(prover_message_transport.clone());

    let prover_pipeline = Arc::new(quil_engine::prover_pipeline::ProverPipeline {
        lifecycle: prover_lifecycle.clone(),
        worker_manager: worker_manager.clone(),
        frame_prover: frame_prover.clone(),
        key_manager: file_key_manager.clone() as Arc<dyn quil_keys::KeyManager + Send + Sync>,
        bls_pubkey: bls_pubkey.clone(),
        prover_address,
        multisig_ed448_seeds,
        delegate_address,
        transport: prover_message_transport,
    });

    // Shard orchestration subscriber: watches for ShardSplitEligible /
    // ShardMergeEligible events and submits signed canonical messages
    // via the prover pipeline (the coverage-monitor → shard-orchestrator
    // handoff).
    {
        let mut rx = global_event_distributor.subscribe("shard-orchestrator");
        let pp = prover_pipeline.clone();
        let cf_for_orch = current_frame.clone();
        let detached_spawner = detached_spawner.clone();
        sup.spawn("shard-orchestration-subscriber", move |cancel| async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    maybe_event = rx.recv() => {
                        let Some(event) = maybe_event else { break };
                        let frame = cf_for_orch.effective();
                        if frame == 0 {
                            debug!("shard event received before any frame — ignoring");
                            continue;
                        }
                        match (event.event_type, &event.data) {
                            (
                                quil_types::consensus::ControlEventType::ShardSplitEligible,
                                quil_types::consensus::ControlEventData::ShardSplit { filter, proposed },
                            ) => {
                                let pp2 = pp.clone();
                                let shard = filter.clone();
                                let proposed = proposed.clone();
                                detached_spawner.detach("shard-split-submit", async move {
                                    if let Err(e) = pp2.submit_shard_split(shard, proposed, frame).await {
                                        warn!(%e, "ShardSplit submission failed");
                                    }
                                    Ok(())
                                });
                            }
                            (
                                quil_types::consensus::ControlEventType::ShardMergeEligible,
                                quil_types::consensus::ControlEventData::ShardMerge { filters, parent },
                            ) => {
                                let pp2 = pp.clone();
                                let shards = filters.clone();
                                let parent = parent.clone();
                                detached_spawner.detach("shard-merge-submit", async move {
                                    if let Err(e) = pp2.submit_shard_merge(shards, parent, frame).await {
                                        warn!(%e, "ShardMerge submission failed");
                                    }
                                    Ok(())
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(())
        });
        info!("shard orchestration subscriber spawned");
    }

    archive_sync::spawn_all(&mut sup, archive_sync::ArchiveSyncArgs {
        mtls_seed,
        network,
        archive_mode,
        archive_pool: archive_pool.clone(),
        clock_store: clock_store.clone(),
        hg_store: hg_store.clone(),
        crdt: crdt.clone(),
        shards_store: shards_store.clone(),
        exec_manager: exec_manager.clone(),
        worker_allocator: worker_allocator.clone(),
        prover_lifecycle: prover_lifecycle.clone(),
        prover_registry: prover_registry.clone(),
        worker_manager: worker_manager.clone(),
        coverage_monitor: coverage_monitor.clone(),
        current_frame: current_frame.clone(),
        last_global_head_frame: last_global_head_frame.clone(),
        prover_pipeline: prover_pipeline.clone(),
        file_key_manager: file_key_manager.clone(),
        frame_prover: frame_prover.clone(),
        message_collector: message_collector.clone(),
        bls_pubkey: bls_pubkey.clone(),
        prover_address,
        p2p_handle: p2p_handle.clone(),
        consensus_handle: consensus_handle.clone(),
        vote_aggregator: vote_aggregator.clone(),
        timeout_aggregator: timeout_aggregator.clone(),
        db_arc: db_arc.clone(),
        frame_materializer: frame_materializer.clone(),
        consensus_loopback_tx: consensus_loopback_tx.clone(),
        peer_id,
        spawner: detached_spawner.clone(),
    });


    // Broadcast channel for GlobalService::StreamGlobalMessages.
    // Construction here (before recv loop) so the recv loop can
    // feed it; the gRPC server takes a clone later.
    let global_msg_tx: tokio::sync::broadcast::Sender<
        quil_types::proto::global::StreamGlobalMessagesResponse,
    > = tokio::sync::broadcast::channel(
        quil_rpc::global_service::GLOBAL_MESSAGE_BROADCAST_CAPACITY,
    )
    .0;
    message_loop::spawn(&mut sup, message_loop::MessageLoopArgs {
        clock_store: clock_store.clone(),
        exec_manager: exec_manager.clone(),
        msg_rx,
        consensus_loopback_rx,
        global_msg_tx: global_msg_tx.clone(),
        archive_pool: archive_pool.clone(),
        mtls_seed,
        hg_store: hg_store.clone(),
        frame_validator,
        message_collector: message_collector.clone(),
        coverage_monitor: coverage_monitor.clone(),
        worker_allocator: worker_allocator.clone(),
        prover_pipeline: prover_pipeline.clone(),
        consensus_handle: consensus_handle.clone(),
        vote_aggregator: vote_aggregator.clone(),
        timeout_aggregator: timeout_aggregator.clone(),
        peer_info_cache: peer_info_cache.clone(),
        shard_engines: shard_engines.clone(),
        signer_registry: signer_registry.clone(),
        current_frame: current_frame.clone(),
        last_global_head_frame: last_global_head_frame.clone(),
        genesis_archive_peer_ids: genesis_archive_peer_ids.clone(),
        genesis_prover_addrs: genesis_prover_addrs.clone(),
        alert_pubkey: hex::decode(&config.engine.alert_key).unwrap_or_default(),
        network,
        archive_mode,
        prover_lifecycle: prover_lifecycle.clone(),
        prover_registry: prover_registry.clone(),
        worker_manager: worker_manager.clone(),
        prover_address,
        p2p_handle: p2p_handle.clone(),
        time_reel: if !archive_mode {
            Some(Arc::new(quil_engine::time_reel::GlobalTimeReel::new(network)))
        } else {
            None
        },
        spawner: detached_spawner.clone(),
    });

    // ---------------------------------------------------------------
    // 7. gRPC service
    // ---------------------------------------------------------------
    grpc::spawn_all(&mut sup, grpc::GrpcArgs {
        config: config.clone(),
        network,
        archive_mode,
        db_arc: db_arc.clone(),
        clock_store: clock_store.clone(),
        hg_store: hg_store.clone(),
        message_collector: message_collector.clone(),
        current_frame: current_frame.clone(),
        last_global_head_frame: last_global_head_frame.clone(),
        prover_address,
        token_store: token_store.clone(),
        prover_registry: prover_registry.clone(),
        prover_pipeline: prover_pipeline.clone(),
        worker_manager: worker_manager.clone(),
        inclusion_prover: inclusion_prover.clone(),
        peer_id,
        p2p_handle: p2p_handle.clone(),
        file_key_manager: file_key_manager.clone(),
        mtls_seed,
        crdt: crdt.clone(),
        peer_info_cache: peer_info_cache.clone(),
        key_store: key_store.clone(),
        metrics_handle: metrics_handle.clone(),
        global_msg_tx: global_msg_tx.clone(),
        archive_pool: archive_pool.clone(),
        spawner: detached_spawner.clone(),
    })?;


    // ---------------------------------------------------------------
    // 8. Wait for shutdown
    // ---------------------------------------------------------------
    let reason = sup.run().await;
    info!("master node shutting down");

    Ok(reason)
}

