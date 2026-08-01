use std::path::PathBuf;
use std::sync::Arc;

use tracing::{info, warn};

// Import KeyManager trait for get_public_key/get_signer methods
use quil_keys::KeyManager as _;

use quil_lifecycle::{ShutdownReason, Supervisor};

pub(crate) async fn start(
    mut sup: Supervisor<anyhow::Error>,
    config: &quil_config::Config,
    core_id: u32,
    parent_process: u32,
) -> anyhow::Result<ShutdownReason<anyhow::Error>> {
    info!(core_id, parent_process, "worker node starting");

    // Match the master's epoch length (network-derived). Workers are separate
    // processes with their own copy of the epoch-length atomic; without this a
    // testnet worker would evaluate frames at the 720-frame default and diverge
    // from the master's short-epoch lifecycle timing.
    quil_types::consensus::init_epoch_length_for_network(config.p2p.network);

    // Resolve the per-worker store path. Worker processes can NOT
    // share the master's RocksDB directory: RocksDB takes an exclusive
    // file lock per `LOCK` file, so a second `open` against the same
    // path fails. Each worker must own its own store.
    //
    // Resolution order:
    //   1. `db.worker_paths[core_id - 1]` (core 0 is master).
    //   2. `db.worker_path_prefix` with `%d` → core id.
    //   3. `<db.path or .config/store>/worker-<core_id>`.
    let db_path: std::path::PathBuf = {
        let idx = core_id.saturating_sub(1) as usize;
        if let Some(p) = config.db.worker_paths.get(idx).filter(|s| !s.is_empty()) {
            std::path::PathBuf::from(p)
        } else if !config.db.worker_path_prefix.is_empty() {
            std::path::PathBuf::from(
                config.db.worker_path_prefix.replace("%d", &core_id.to_string()),
            )
        } else {
            let base = if config.db.path.is_empty() {
                std::path::PathBuf::from(".config/store")
            } else {
                std::path::PathBuf::from(&config.db.path)
            };
            base.join(format!("worker-{}", core_id))
        }
    };
    info!(core_id, db_path = %db_path.display(), "worker store path resolved");
    std::fs::create_dir_all(&db_path)?;
    let db = quil_store::RocksDb::open(&db_path)?;
    let db_arc = Arc::new(db);
    let clock_store: Arc<dyn quil_types::store::ClockStore> =
        Arc::new(quil_store::RocksClockStore::new(db_arc.inner()));
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db_arc.inner()));

    // Per-worker crypto + CRDT + execution engines. Each worker
    // process owns its own RocksDB store (per `worker_path_prefix`)
    // and therefore its own crdt + execution manager.
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
        Arc::new(quil_tries::ShaInclusionProver);
    let key_manager: Arc<dyn quil_types::crypto::KeyManager> =
        Arc::new(quil_crypto::DefaultKeyManager::new());
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover.clone(),
    ));
    // Phase-3: commit state into the JMT forest. Install the persistent forest on
    // a migrated OR brand-new/fresh worker store (a fresh worker builds on the
    // persistent forest from the start rather than the ephemeral in-memory
    // default). A store with un-migrated legacy state is skipped (must
    // `--migrate-db`).
    let store_is_fresh = clock_store
        .get_latest_global_clock_frame()
        .ok()
        .and_then(|f| f.header.map(|h| h.frame_number))
        .map(|n| n == 0)
        .unwrap_or(true);
    if quil_forest_migrate::install_forest_boot(crdt.as_ref(), hg_store.as_ref(), store_is_fresh) {
        tracing::info!("Phase-3 JMT forest installed — committing state to the forest");
    }
    // Same crypto setup as the master node — bulletproof is real;
    // Decaf / circuit compiler are still noop stubs pending production
    // impls. See the master block earlier in this file for rationale.
    let circuit_compiler_worker: Arc<dyn quil_types::execution::CircuitCompiler> =
        Arc::new(quil_execution::testing::NoopCircuitCompiler);
    let clock_store_for_exec_worker: Arc<dyn quil_types::store::ClockStore> =
        clock_store.clone();
    let hypergraph_resolver_worker: Arc<dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver> =
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
    let exec_manager = Arc::new(quil_execution::ExecutionEngineManager::new(
        inclusion_prover.clone(),
        key_manager.clone(),
        crdt.clone(),
        circuit_compiler_worker,
        clock_store_for_exec_worker,
        hypergraph_resolver_worker,
        true,
    ));

    // Key management — same keys as master
    let bls_ctor = quil_crypto::FalconKeyConstructor;
    let keys_path = config.key.key_store_file.path.clone();
    let proving_key_id = if config.engine.proving_key_id.is_empty() {
        "q-prover-key".to_string()
    } else {
        config.engine.proving_key_id.clone()
    };
    let file_key_manager = Arc::new(quil_keys::FileKeyManager::new(
        PathBuf::from(&keys_path),
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(bls_ctor),
    )?);
    file_key_manager.set_peer_priv_key_hex(&config.p2p.peer_priv_key);
    let bls_pubkey = file_key_manager.get_public_key(quil_types::crypto::KeyType::Falcon512)?;
    let prover_address = quil_crypto::poseidon::hash_bytes_to_32(&bls_pubkey)?;

    // Shared prover registry (syncs from store)
    let prover_registry = Arc::new(quil_execution::SharedProverRegistry::new());

    // Frame prover
    let frame_prover: Arc<dyn quil_types::crypto::FrameProver> =
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048));
    let message_collector = Arc::new(quil_engine::message_collector::MessageCollector::new());
    let fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager> =
        Arc::new(quil_engine::InMemoryDynamicFeeManager::new(360));

    // BLS signer factory
    let fkm = file_key_manager.clone();
    let signer_factory: Arc<dyn Fn() -> Box<dyn quil_types::crypto::Signer> + Send + Sync> =
        Arc::new(move || {
            fkm.get_signer(quil_types::crypto::KeyType::Falcon512)
                .expect("BLS signer should be available")
        });

    // Compute worker listen address from config
    let listen_addr = quil_engine::worker_node::worker_listen_addr(
        core_id,
        &config.engine.data_worker_base_listen_multiaddr,
        config.engine.data_worker_base_stream_port,
        &config.engine.data_worker_stream_multiaddrs,
    );

    // Master endpoint — derived from p2p.stream_listen_multiaddr.
    // In a cluster, the worker's config has that field pointed at the
    // master's stream listener; on single-machine setups it's the
    // local `/ip4/0.0.0.0/tcp/8340` and gets rewritten to localhost.
    let master_endpoint = quil_engine::worker_node::master_grpc_endpoint(&config);
    // Clone for the syncer (master_endpoint gets moved into WorkerNodeConfig).
    let master_endpoint_for_syncer = master_endpoint.clone();

    // Worker's Ed448 seed for mTLS to the master. The master's
    // GlobalService listener requires mTLS; without a seed configured
    // here the worker would dial plaintext and the master's TLS
    // acceptor would immediately close the connection (surfaces as
    // "h2 protocol error" in the worker logs).
    let worker_mtls_seed: Option<[u8; 57]> = {
        let bytes = hex::decode(&config.p2p.peer_priv_key).unwrap_or_default();
        if bytes.len() >= 57 {
            let mut seed = [0u8; 57];
            seed.copy_from_slice(&bytes[..57]);
            Some(seed)
        } else {
            None
        }
    };
    if worker_mtls_seed.is_none() {
        warn!(
            "worker has no Ed448 seed configured (p2p.peerPrivKey empty or short); \
             will dial master in plaintext — only works against a plaintext-allowing \
             master (single-machine dev only)",
        );
    }
    let factory_endpoint = master_endpoint.clone();
    // Worker dials the master's :8340 with the node's FALCON identity, so the
    // handshake peer-id == the node's peer-id (the master's self-identity gate).
    let worker_dialer_falcon_sk: Option<Vec<u8>> = file_key_manager
        .get_private_key(quil_types::crypto::KeyType::Falcon512)
        .ok();
    let channel_factory: quil_engine::worker_node::MasterChannelFactory = Arc::new(move || {
        let endpoint_str = factory_endpoint.clone();
        let seed = worker_dialer_falcon_sk.clone();
        Box::pin(async move {
            use tonic::transport::Endpoint;
            let endpoint = Endpoint::from_shared(endpoint_str)
                .map_err(|e| Box::new(std::io::Error::other(format!("endpoint: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>)?
                .connect_timeout(std::time::Duration::from_secs(10))
                .keep_alive_while_idle(true);
            match seed {
                Some(seed) => {
                    // sntrup761 PQNoise (post-quantum), matching the master's
                    // pqnoise-only :8340 acceptor. The worker dials with the
                    // node's OWN Ed448 seed, so the handshake authenticates its
                    // peer_id == the node's peer_id — which the master's
                    // self-identity gate on worker-privileged RPCs enforces.
                    // (Was Ed448/X.509 mTLS via QuilTlsConnector — a transport
                    // mismatch against the pqnoise server + not post-quantum.)
                    let connector = quil_rpc::QuilPqNoiseConnector::new(seed);
                    let channel = endpoint.connect_with_connector(connector).await
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
                    Ok(channel)
                }
                None => {
                    let channel = endpoint.connect().await
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
                    Ok(channel)
                }
            }
        })
    });

    let worker_config = quil_engine::worker_node::WorkerNodeConfig {
        core_id,
        master_endpoint,
        listen_addr,
        parent_pid: if parent_process > 0 { Some(parent_process) } else { None },
        channel_factory: Some(channel_factory),
        app_consensus_cw: config.engine.app_consensus_cw,
        // Persist the app-shard CW journal under the worker's resolved data dir
        // (else the ephemeral temp journal panics on prune once a real committee
        // starts producing views).
        data_dir: Some(db_path.clone()),
    };

    let reward_greedy = config.engine.reward_strategy == "reward-greedy";
    // Mainnet (`p2p.network == 0`) uses 3 — matches the protocol's
    // halt-risk floor so a single prover can't drive consensus alone.
    // Testnets use 1 so a single-prover test cluster still progresses.
    let min_active_provers_for_propose: u64 =
        if config.p2p.network == 0 { 3 } else { 1 };

    // Concrete registry + store for the post-sync refresh hook (the trait
    // `refresh()` is a no-op; a cluster worker must `refresh_from_store` to
    // repopulate its registry after syncing the prover tree, else its committee
    // build fails and the shard engine stays passive).
    let registry_refresh: Arc<dyn Fn() + Send + Sync> = {
        let r = prover_registry.clone();
        let s = hg_store.clone();
        Arc::new(move || r.refresh_from_store(&s))
    };
    let mut worker_node = quil_engine::worker_node::WorkerOnlyNode::new(
        worker_config,
        clock_store,
        prover_registry as Arc<dyn quil_types::consensus::ProverRegistry>,
        frame_prover,
        message_collector,
        fee_manager,
        prover_address.to_vec(),
        bls_pubkey,
        signer_factory,
        reward_greedy,
        min_active_provers_for_propose,
    )
    .with_state_engines(crdt.clone(), exec_manager, inclusion_prover)
    .with_registry_refresh(registry_refresh);

    // Wire the prover-tree syncer so the worker can sync the global
    // prover tree from the master at startup and before materializing
    // frames with a prover-root mismatch. In Go, workers call
    // `HyperSyncSelf` which dials the master's
    // HypergraphComparisonService. We reuse the master_endpoint (the
    // same one the gRPC message stream connects to — port 8340).
    if worker_mtls_seed.is_some() {
        // Extract `host:port` from the master endpoint URL
        // (`http://host:port`) for the syncer. Dials with the Falcon network
        // identity (the same one the master's :8340 acceptor expects).
        let stream_addr = master_endpoint_for_syncer
            .strip_prefix("http://")
            .unwrap_or(&master_endpoint_for_syncer)
            .to_string();
        if let Ok(falcon_sk) =
            file_key_manager.get_private_key(quil_types::crypto::KeyType::Falcon512)
        {
            let syncer: Arc<dyn quil_engine::prover_tree_syncer::ProverTreeSyncer> =
                Arc::new(crate::prover_tree_syncer_prod::ProdProverTreeSyncer {
                    master_stream_addr: stream_addr,
                    hg_store: hg_store.clone(),
                    falcon_signing_key: falcon_sk,
                    crdt: crdt.clone(),
                });
            worker_node = worker_node.with_prover_tree_syncer(syncer);
        }
    } else {
        warn!("worker has no mTLS seed — prover-tree sync will be unavailable");
    }

    // Outbound pubsub. Two mutually exclusive modes:
    //   * `engine.enable_master_proxy = true` → dial the master's
    //     PubSubProxy on the peer mTLS listener and route all pubsub
    //     through it. Used when one machine should be the only mesh
    //     participant (homogenous LAN layouts, gateway-style setups).
    //   * `engine.enable_master_proxy = false` → the worker spins up
    //     its own libp2p instance with a synthetic peer key (per
    //     `node/p2p/blossomsub.go:473-496`) and joins the mesh
    //     directly. Pubsub messages are signed with the REAL prover
    //     key so peers attribute them to the prover, not the worker
    //     host. Required for multi-machine clusters where workers and
    //     master live on different hosts.
    if config.engine.enable_master_proxy {
        let master_addr = quil_engine::worker_node::master_grpc_endpoint(&config);
        // `master_addr` is already `http://host:port`.
        match quil_rpc::proxy_pubsub::ProxyPubSub::connect(master_addr.clone(), None).await {
            Ok(proxy) => {
                let proxy = Arc::new(proxy);
                info!(master = %master_addr, "worker connected to master PubSubProxy");
                let proxy_for_publish = proxy.clone();
                let publish_fn: quil_engine::worker_node::PublishFn =
                    Arc::new(move |bitmask, data| {
                        let p = proxy_for_publish.clone();
                        Box::pin(async move {
                            if let Err(e) = p.publish(bitmask, data).await {
                                warn!(error = %e, "proxy publish failed");
                            }
                        })
                    });
                worker_node = worker_node.with_publish_fn(publish_fn);
            }
            Err(e) => {
                warn!(error = ?e, master = %master_addr,
                    "worker proxy connect failed — running receive-only");
            }
        }
    }

    // Worker-owned p2p when proxy is off. Carry the receiver out of
    // this scope so we can spawn the routing task after the worker is
    // wrapped in an Arc.
    let worker_owned_p2p: Option<(
        Arc<quil_p2p::P2PHandle>,
        tokio::sync::mpsc::Receiver<quil_p2p::ReceivedMessage>,
    )> = if !config.engine.enable_master_proxy {
        // Falcon q-prover-key = the node's real network identity; the worker
        // signs pubsub as it (msg.from = real Falcon peer-id) while keeping a
        // synthetic Ed448 host identity.
        let worker_falcon_sk = file_key_manager
            .get_private_key(quil_types::crypto::KeyType::Falcon512)
            .map_err(|e| anyhow::anyhow!("worker load Falcon identity key: {}", e))?;
        let p2p_node =
            quil_p2p::P2PNode::new_for_worker(&config.p2p, core_id, Some(&worker_falcon_sk))
                .map_err(|e| anyhow::anyhow!("worker p2p node init: {}", e))?;
        let worker_listen = quil_p2p::P2PNode::worker_listen_multiaddr(
            &config.engine,
            core_id,
        )
        .map_err(|e| anyhow::anyhow!("worker p2p listen addr: {}", e))?;
        info!(core_id, listen = %worker_listen, "starting worker-owned p2p");
        let (handle, rx) = p2p_node
            .start(&mut sup, &worker_listen)
            .await
            .map_err(|e| anyhow::anyhow!("worker p2p start: {}", e))?;
        let handle = Arc::new(handle);
        // Workers subscribe to GLOBAL_PEER_INFO only (peer discovery).
        // GLOBAL_FRAME, GLOBAL_PROVER, and GLOBAL_CONSENSUS are
        // deliberately omitted:
        //   - GLOBAL_FRAME: received via master gRPC stream
        //   - GLOBAL_PROVER: submitted via direct gRPC to archives
        //   - GLOBAL_CONSENSUS: workers participate in PER-SHARD
        //     consensus only (subscribed dynamically on Respawn via
        //     `subscribe_to_shard_bitmasks`). Subscribing to GLOBAL
        //     causes every worker to relay every shard's votes/
        //     proposals — massive amplification with zero benefit.
        handle.subscribe(quil_engine::bitmasks::GLOBAL_PEER_INFO.to_vec()).await;
        handle.subscribe(quil_engine::bitmasks::GLOBAL_ALERT.to_vec()).await;
        // Wire publish_fn → worker's own p2p.
        let p2p_for_publish = handle.clone();
        let publish_fn: quil_engine::worker_node::PublishFn =
            Arc::new(move |bitmask, data| {
                let h = p2p_for_publish.clone();
                Box::pin(async move {
                    if let Err(e) = h.publish(bitmask, data).await {
                        warn!(error = %e, "worker p2p publish failed");
                    }
                })
            });
        worker_node = worker_node
            .with_publish_fn(publish_fn)
            .with_p2p_handle(handle.clone());
        Some((handle, rx))
    } else {
        None
    };

    let worker = Arc::new(worker_node);

    // Route incoming pubsub messages from the worker's own p2p into
    // the active engine. The worker's `route_message` dispatches by
    // bitmask pattern; if no engine is active yet, the message is
    // silently dropped.
    if let Some((_handle, mut rx)) = worker_owned_p2p {
        let route_worker = worker.clone();
        sup.run_until_cancelled(
            "worker-p2p-router",
            move |_token| async move {
                loop {
                    match rx.recv().await {
                        // `msg.from` is the gossip sender's PeerId — needed to
                        // resolve the committee key for inbound app-shard CW.
                        Some(msg) => route_worker.route_message(&msg.data, &msg.bitmask, &msg.from),
                        None => break,
                    }
                }
                info!("worker p2p routing task stopped");
                Ok(())
            },
        );
    }

    info!(core_id, "worker node initialized, starting event loop");

    // Memory telemetry for THIS worker process. In cluster mode each worker
    // is a SEPARATE OS process with its own jemalloc heap + RocksDB, invisible
    // to the master's status tick — so without this a cluster worker's memory
    // (the most likely OOM contributor on a node running many workers) is
    // completely unmonitored. Mirrors the master's `"jemalloc stats"` and the
    // thread-worker's `"worker rocksdb memory"` lines. Every 60s.
    {
        let db_for_mem = db_arc.clone();
        sup.run_until_cancelled("worker-mem-telemetry", move |token| async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tick.tick() => {
                        let rss = crate::mem_stats::process_memory()
                            .map(|m| crate::mem_stats::fmt_mb(m.rss_bytes))
                            .unwrap_or_else(|| "?".to_string());
                        let dbm = db_for_mem.memory_usage();
                        if let Some(j) = crate::mem_stats::jemalloc_stats() {
                            info!(
                                core_id,
                                rss_mb = %rss,
                                allocated_mb = %crate::mem_stats::fmt_mb(j.allocated),
                                resident_mb = %crate::mem_stats::fmt_mb(j.resident),
                                retained_mb = %crate::mem_stats::fmt_mb(j.retained),
                                rocksdb_mb = %crate::mem_stats::fmt_mb(dbm.total()),
                                "worker process memory",
                            );
                            let br = crate::mem_stats::jemalloc_size_classes();
                            info!(
                                core_id,
                                breakdown = %crate::mem_stats::fmt_breakdown(&br),
                                "worker jemalloc size classes",
                            );
                        } else {
                            info!(
                                core_id,
                                rss_mb = %rss,
                                rocksdb_mb = %crate::mem_stats::fmt_mb(dbm.total()),
                                "worker process memory",
                            );
                        }
                    }
                }
            }
            Ok(())
        });
    }

    // Run the worker — uses plain `sup.spawn` (not `run_until_cancelled`)
    // because the cancel branch must call `worker.stop()`; drop-on-cancel
    // can't invoke a method.
    let worker_run = worker.clone();
    let worker_stop = worker.clone();
    sup.spawn("worker-engine", move |token| async move {
        tokio::select! {
            result = worker_run.run() => result.map_err(anyhow::Error::from),
            _ = token.cancelled() => {
                worker_stop.stop();
                Ok(())
            }
        }
    });

    let reason = sup.run().await;
    info!(core_id, "worker node shut down");
    Ok(reason)
}
