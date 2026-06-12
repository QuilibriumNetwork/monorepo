use std::sync::Arc;

use tracing::{debug, info, warn};

// Import KeyManager trait for get_signer
use quil_keys::KeyManager as _;

use quil_lifecycle::Supervisor;

pub(crate) struct WorkerManagerArgs {
    pub config: quil_config::Config,
    pub archive_mode: bool,
    pub p2p_handle: quil_p2p::node::P2PHandle,
    pub db_arc: Arc<quil_store::RocksDb>,
    pub clock_store: Arc<quil_store::RocksClockStore>,
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub exec_manager: Arc<quil_execution::ExecutionEngineManager>,
    pub inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    pub frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    pub message_collector: Arc<quil_engine::message_collector::MessageCollector>,
    pub fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager>,
    pub prover_registry: Arc<quil_execution::SharedProverRegistry>,
    pub halt_state: Arc<quil_engine::halt_state::HaltState>,
    pub file_key_manager: Arc<quil_keys::FileKeyManager>,
    pub prover_address: [u8; 32],
    pub bls_pubkey: Vec<u8>,
    pub shard_engines: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_engine::app_engine::AppEngineHandle>,
    >>,
    pub remote_worker_manager_for_halt:
        Arc<std::sync::OnceLock<Arc<quil_engine::remote_worker::RemoteWorkerManager>>>,
    pub pi_worker_manager: Arc<std::sync::OnceLock<Arc<dyn quil_engine::worker::WorkerManager>>>,
    /// Prover-message transport. Populated by master_node init after
    /// worker_manager comes up (transport depends on archive_pool +
    /// mtls_seed which are constructed later in the boot sequence).
    /// Used to publish reward-proof finalizations and coverage updates;
    /// on non-archive nodes a direct BlossomSub publish to
    /// `GLOBAL_PROVER` fails ("not subscribed to bitmask") because the
    /// node deliberately skips that subscription — Rust's BlossomSub
    /// has no fanout path like Go's. The transport's gRPC archive
    /// fan-out is the substitute delivery channel.
    pub prover_message_transport: Arc<
        std::sync::OnceLock<
            Arc<dyn quil_engine::prover_message_transport::ProverMessageTransport>,
        >,
    >,
    pub spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
}

pub(crate) fn init(
    sup: &mut Supervisor<anyhow::Error>,
    args: WorkerManagerArgs,
) -> Arc<dyn quil_engine::worker::WorkerManager> {
    let WorkerManagerArgs {
        config,
        archive_mode,
        p2p_handle,
        db_arc,
        clock_store,
        crdt,
        exec_manager,
        inclusion_prover,
        frame_prover,
        message_collector,
        fee_manager,
        prover_registry,
        halt_state,
        file_key_manager,
        prover_address,
        bls_pubkey,
        shard_engines,
        remote_worker_manager_for_halt,
        pi_worker_manager,
        prover_message_transport,
        spawner,
    } = args;

    // Worker manager — either local threads or remote gRPC workers.
    // If data_worker_stream_multiaddrs has entries, use remote mode
    // (cluster of machines). Otherwise, use local threads.
    let reward_greedy = config.engine.reward_strategy == "reward-greedy";
    // Minimum Active provers a shard needs before its leader starts
    // producing frames. Mainnet (`p2p.network == 0`) uses 3 — matches
    // the protocol's halt-risk floor so a single prover can't drive
    // consensus alone and burn CPU on rounds that never form a quorum.
    // Testnets use 1 because a single-prover test cluster is a valid
    // setup. Plumbed into `WorkerConsensusDeps` →
    // `AppEngineDeps::min_active_provers_for_propose` →
    // `AppLeaderProvider::prove_next_state`'s gate.
    let min_active_provers_for_propose: u64 = if config.p2p.network == 0 { 3 } else { 1 };
    let fkm_for_factory = file_key_manager.clone();

    let worker_manager: Arc<dyn quil_engine::worker::WorkerManager> =
        if !config.engine.data_worker_stream_multiaddrs.is_empty() {
            // CLUSTER MODE: remote workers via gRPC
            // Master listens on the stream port from P2P config
            let master_port = if config.p2p.stream_listen_multiaddr.is_empty() {
                8340u16
            } else {
                // Extract port from /ip4/X/tcp/PORT
                config.p2p.stream_listen_multiaddr
                    .split('/')
                    .collect::<Vec<_>>()
                    .windows(2)
                    .find(|w| w[0] == "tcp")
                    .and_then(|w| w[1].parse::<u16>().ok())
                    .unwrap_or(8340)
            };
            let master_ep = format!("http://0.0.0.0:{}", master_port);
            let remote_mgr = Arc::new(quil_engine::remote_worker::RemoteWorkerManager::from_config(
                &config.engine.data_worker_stream_multiaddrs,
                master_ep,
            ));
            info!(
                remote_workers = config.engine.data_worker_stream_multiaddrs.len(),
                "remote worker manager ready (cluster mode)"
            );
            // Publish to the halt broadcaster spawned above so it can
            // SetHalted across standalone workers when coverage halts.
            let _ = remote_worker_manager_for_halt.set(remote_mgr.clone());
            remote_mgr as Arc<dyn quil_engine::worker::WorkerManager>
        } else {
            // LOCAL MODE: core-pinned threads
            let thread_mgr = Arc::new(quil_engine::thread_worker::ThreadWorkerManager::new());
            // Persistent worker registry — survives restarts so the
            // operator's `manually_managed` flag and the
            // worker→filter binding don't reset every reboot.
            let worker_store: Arc<dyn quil_types::store::WorkerStore> =
                Arc::new(quil_store::RocksWorkerStore::new(db_arc.inner()));
            thread_mgr.set_worker_store(worker_store);
            // Closure invoked by AppFollower from inside the consensus
            // event loop: wraps a finalized FrameHeader (canonical
            // bytes) in a `MessageBundle{Shard: header}` and ships it
            // out through the prover-message transport (gRPC archive
            // fan-out, plus BlossomSub publish on archive nodes that
            // subscribe to `GLOBAL_PROVER`). Spawning the work keeps
            // the call non-blocking from the consensus side.
            let coverage_spawner = spawner.clone();
            let coverage_transport_cell = prover_message_transport.clone();
            let coverage_halt = halt_state.clone();
            let coverage_publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> =
                Arc::new(move |header_canonical_bytes: Vec<u8>| {
                    // Belt-and-suspenders halt gate: the engine's
                    // `handle_consensus_event::Finalized` arm already
                    // skips the ShardFrameFinalized emission during
                    // halt, but `coverage_publish` fires earlier
                    // (inside the follower's `report_committed`) on a
                    // separate path, before that gate runs. Drop the
                    // publish here too so no reward proof escapes
                    // for shard work that shouldn't have produced
                    // anything during the halt window.
                    if coverage_halt.any_halted() {
                        debug!("suppressing coverage publish — coverage halt active");
                        return;
                    }
                    let req = match quil_execution::message_envelope::CanonicalMessageRequest::wrap(
                        header_canonical_bytes,
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(error = %e, "coverage publish: bad FrameHeader bytes");
                            return;
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
                            let cell = coverage_transport_cell.clone();
                            coverage_spawner.detach("coverage-publish", async move {
                                match cell.get() {
                                    Some(transport) => {
                                        if let Err(e) = transport
                                            .publish_prover_bundle(bytes)
                                            .await
                                        {
                                            warn!(error = %e,
                                                "coverage publish: transport submission failed");
                                        }
                                    }
                                    None => {
                                        warn!(
                                            "coverage publish: transport not yet wired — dropping"
                                        );
                                    }
                                }
                                Ok(())
                            });
                        }
                        Err(e) => warn!(error = %e, "coverage publish: bundle encode failed"),
                    }
                });
            // Per-worker state builder: each thread-mode worker opens
            // its own RocksDB (resolved from db.worker_paths /
            // worker_path_prefix / fallback) and builds its own
            // clock_store, hypergraph CRDT, and execution engine on
            // top. Master keeps its own global stores untouched.
            let worker_db_base = config.db.path.clone();
            let worker_paths_cfg = config.db.worker_paths.clone();
            let worker_path_prefix_cfg = config.db.worker_path_prefix.clone();
            let worker_state_builder: Arc<
                dyn Fn(u32) -> std::result::Result<
                    quil_engine::thread_worker::WorkerOwnedDeps,
                    String,
                > + Send
                    + Sync,
            > = Arc::new(move |core_id: u32| {
                let path: std::path::PathBuf = {
                    let idx = core_id.saturating_sub(1) as usize;
                    if let Some(p) = worker_paths_cfg.get(idx).filter(|s| !s.is_empty()) {
                        std::path::PathBuf::from(p)
                    } else if !worker_path_prefix_cfg.is_empty() {
                        std::path::PathBuf::from(
                            worker_path_prefix_cfg.replace("%d", &core_id.to_string()),
                        )
                    } else {
                        let base = if worker_db_base.is_empty() {
                            std::path::PathBuf::from(".config/store")
                        } else {
                            std::path::PathBuf::from(&worker_db_base)
                        };
                        base.join(format!("worker-{}", core_id))
                    }
                };
                std::fs::create_dir_all(&path).map_err(|e| {
                    format!("worker {} mkdir {}: {e}", core_id, path.display())
                })?;
                let db = quil_store::RocksDb::open(&path).map_err(|e| {
                    format!("worker {} open db {}: {e}", core_id, path.display())
                })?;
                let db_arc = Arc::new(db);
                let clock_store: Arc<dyn quil_types::store::ClockStore> = Arc::new(
                    quil_store::RocksClockStore::new(db_arc.inner()),
                );
                let hg_store: Arc<dyn quil_types::store::HypergraphStore> = Arc::new(
                    quil_store::RocksHypergraphStore::new(db_arc.inner()),
                );
                let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
                    Arc::new(quil_crypto::KzgInclusionProver);
                let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                    hg_store,
                    inclusion_prover.clone(),
                ));
                // Workers don't sign or verify identities — a default
                // key manager satisfies the execution engine's
                // `KeyManager` requirement for state materialization.
                let bls_constructor: Arc<dyn quil_types::crypto::BlsConstructor> =
                    Arc::new(quil_crypto::Bls48581KeyConstructor);
                let worker_key_manager: Arc<dyn quil_types::crypto::KeyManager> =
                    Arc::new(quil_crypto::DefaultKeyManager::new(bls_constructor));
                // Bulletproof prover is real; Decaf448 / circuit
                // compiler still use the noop stubs (no production
                // impl yet). See the analogous block in the master
                // setup above for the rationale.
                let bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver> =
                    Arc::new(quil_crypto::Decaf448BulletproofProver);
                let decaf_constructor: Arc<dyn quil_types::crypto::DecafConstructor> =
                    Arc::new(quil_execution::testing::NoopDecafConstructor);
                let circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler> =
                    Arc::new(quil_execution::testing::NoopCircuitCompiler);
                let clock_store_for_exec: Arc<dyn quil_types::store::ClockStore> =
                    clock_store.clone();
                let hypergraph_resolver: Arc<dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver> =
                    Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
                let exec_manager = Arc::new(
                    quil_execution::ExecutionEngineManager::new(
                        inclusion_prover.clone(),
                        worker_key_manager,
                        crdt.clone(),
                        bulletproof_prover,
                        decaf_constructor,
                        circuit_compiler,
                        clock_store_for_exec,
                        hypergraph_resolver,
                        true,
                    ),
                );
                tracing::info!(
                    core_id,
                    path = %path.display(),
                    "worker state initialized"
                );
                Ok(quil_engine::thread_worker::WorkerOwnedDeps {
                    clock_store,
                    hypergraph: crdt,
                    execution_engine: exec_manager,
                    inclusion_prover,
                    // Each worker writes consensus + liveness state
                    // into its own RocksDB. Mirrors the per-worker
                    // clock/hypergraph stores above.
                    kv_db: Some(db_arc.clone() as Arc<dyn quil_types::store::KvDb>),
                })
            });

            thread_mgr.set_consensus_deps(quil_engine::thread_worker::WorkerConsensusDeps {
                prover_registry: prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
                frame_prover: frame_prover.clone(),
                message_collector: message_collector.clone(),
                clock_store: clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
                fee_manager: fee_manager.clone(),
                local_prover_address: prover_address.to_vec(),
                local_bls_pubkey: bls_pubkey.clone(),
                bls_signer_factory: Arc::new(move || {
                    fkm_for_factory.get_signer(quil_types::crypto::KeyType::Bls48581G1)
                        .expect("BLS signer should be available")
                }),
                reward_greedy,
                min_active_provers_for_propose,
                coverage_publish: Some(coverage_publish),
                // Master's global state, used as fallback when the
                // per-worker builder fails or isn't wired.
                hypergraph: Some(crdt.clone()),
                execution_engine: Some(exec_manager.clone()),
                inclusion_prover: Some(inclusion_prover.clone()),
                worker_init: Some(Arc::new(|core_id: u32| {
                    crate::logging::set_worker_core_id(core_id);
                    crate::logging::register_worker_log_file(core_id);
                })),
                worker_state_builder: Some(worker_state_builder),
                // Master's RocksDB doubles as the persistent backing
                // for app-shard `ConsensusState` / `LivenessState` —
                // workers writing through the master path (no
                // per-worker DB) land here. Per-worker builds can
                // override via `WorkerOwnedDeps::kv_db`.
                kv_db: Some(db_arc.clone() as Arc<dyn quil_types::store::KvDb>),
            });
            info!(
                worker_cores = thread_mgr.num_worker_cores(),
                "thread worker manager ready (local mode)"
            );
            // Drain `WorkerToMaster` events from in-process worker
            // threads and forward to the master's BlossomSub publish
            // path. `ShardFrameFinalized` becomes a
            // `MessageBundle{Shard: header}` on `GLOBAL_PROVER`.
            // Per-shard bitmask subscriptions are wired on
            // `ShardActivated`; inbound routing dispatches by filter
            // through `shard_engines` in the recv loop below.
            if let Some(mut master_rx) = thread_mgr.take_master_rx() {
                let drain_p2p = p2p_handle.clone();
                let drain_shard_engines = shard_engines.clone();
                let drain_halt = halt_state.clone();
                let drain_spawner = spawner.clone();
                let drain_transport_cell = prover_message_transport.clone();
                sup.run_until_cancelled("worker-master-drain", move |_token| async move {
                    loop {
                        let Some(event) = master_rx.recv().await else { break };
                        use quil_engine::thread_worker::WorkerToMaster;
                                // Each publish is dispatched as a fire-and-forget
                                // task: the swarm's `publish().await` can block on
                                // an internal mesh send, and back-pressure here
                                // would propagate all the way to the per-shard
                                // consensus event handler (engine→master event_tx
                                // is bounded), stalling QC processing and
                                // finalization.
                                match event {
                                    WorkerToMaster::ShardFrameFinalized {
                                        core_id,
                                        filter,
                                        header_canonical_bytes,
                                    } => {
                                        // Drop reward-proof submissions during a coverage
                                        // halt. The engine's per-message halt gates stop
                                        // new consensus from advancing, but a finalize
                                        // event already in-flight when the halt arrived
                                        // can still race through and emit here. Suppress
                                        // the publish so we don't credit shard work that
                                        // shouldn't have happened during the halt window.
                                        if drain_halt.any_halted() {
                                            debug!(
                                                core_id,
                                                filter = %hex::encode(&filter),
                                                "suppressing GLOBAL_PROVER publish — coverage halt active"
                                            );
                                            continue;
                                        }
                                        // Decode for a positive log line so the operator
                                        // can see each rewardable proof going out. The
                                        // bytes are consumed by `wrap` below; decode a
                                        // borrowed view first.
                                        if let Ok(h) =
                                            quil_execution::global_intrinsic::frame_header::FrameHeader::from_canonical_bytes(
                                                &header_canonical_bytes,
                                            )
                                        {
                                            info!(
                                                core_id,
                                                filter = %hex::encode(&filter),
                                                frame = h.frame_number,
                                                rank = h.rank,
                                                prover = %hex::encode(&h.prover),
                                                "submitting reward proof to GLOBAL_PROVER"
                                            );
                                        }
                                        let req = match quil_execution::message_envelope::CanonicalMessageRequest::wrap(
                                            header_canonical_bytes,
                                        ) {
                                            Ok(r) => r,
                                            Err(e) => {
                                                warn!(core_id, filter = %hex::encode(&filter), error = %e,
                                                    "shard finalize: bad FrameHeader bytes — dropping coverage publish");
                                                continue;
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
                                                let cell = drain_transport_cell.clone();
                                                let filter_owned = filter.clone();
                                                drain_spawner.detach("shard-finalize-publish", async move {
                                                    match cell.get() {
                                                        Some(transport) => {
                                                            if let Err(e) = transport
                                                                .publish_prover_bundle(bytes)
                                                                .await
                                                            {
                                                                warn!(core_id,
                                                                    filter = %hex::encode(&filter_owned),
                                                                    error = %e,
                                                                    "shard finalize: transport submission failed");
                                                            }
                                                        }
                                                        None => {
                                                            warn!(core_id,
                                                                filter = %hex::encode(&filter_owned),
                                                                "shard finalize: transport not yet wired — dropping");
                                                        }
                                                    }
                                                    Ok(())
                                                });
                                            }
                                            Err(e) => warn!(core_id, error = %e,
                                                "shard finalize: bundle encode failed"),
                                        }
                                    }
                                    WorkerToMaster::FrameProduced { core_id, filter, frame_data, .. } => {
                                        // Per-shard frame bitmask = filter itself.
                                        // Self-loopback is handled in thread_worker
                                        // before we get here.
                                        if drain_halt.any_halted() {
                                            debug!(core_id, filter = %hex::encode(&filter),
                                                "suppressing shard frame publish — coverage halt active");
                                            continue;
                                        }
                                        let p2p = drain_p2p.clone();
                                        drain_spawner.detach("shard-frame-publish", async move {
                                            if let Err(e) = p2p
                                                .publish(
                                                    quil_engine::bitmasks::shard_frame_bitmask(&filter),
                                                    frame_data,
                                                )
                                                .await
                                            {
                                                warn!(core_id, filter = %hex::encode(&filter),
                                                    error = %e, "shard frame publish failed");
                                            }
                                            Ok(())
                                        });
                                    }
                                    WorkerToMaster::VoteProduced { core_id, filter, vote_data } => {
                                        // Per-shard consensus bitmask = `0x00 || filter`.
                                        if drain_halt.any_halted() {
                                            debug!(core_id, filter = %hex::encode(&filter),
                                                "suppressing shard vote publish — coverage halt active");
                                            continue;
                                        }
                                        let p2p = drain_p2p.clone();
                                        drain_spawner.detach("shard-vote-publish", async move {
                                            if let Err(e) = p2p
                                                .publish(
                                                    quil_engine::bitmasks::shard_consensus_bitmask(&filter),
                                                    vote_data,
                                                )
                                                .await
                                            {
                                                warn!(core_id, filter = %hex::encode(&filter),
                                                    error = %e, "shard vote publish failed");
                                            }
                                            Ok(())
                                        });
                                    }
                                    WorkerToMaster::TimeoutProduced { core_id, filter, timeout_data } => {
                                        if drain_halt.any_halted() {
                                            debug!(core_id, filter = %hex::encode(&filter),
                                                "suppressing shard timeout publish — coverage halt active");
                                            continue;
                                        }
                                        let p2p = drain_p2p.clone();
                                        drain_spawner.detach("shard-timeout-publish", async move {
                                            if let Err(e) = p2p
                                                .publish(
                                                    quil_engine::bitmasks::shard_consensus_bitmask(&filter),
                                                    timeout_data,
                                                )
                                                .await
                                            {
                                                warn!(core_id, filter = %hex::encode(&filter),
                                                    error = %e, "shard timeout publish failed");
                                            }
                                            Ok(())
                                        });
                                    }
                                    WorkerToMaster::ShardActivated { core_id, filter, handle } => {
                                        // Push the current halt state to the
                                        // freshly-activated engine before
                                        // registering it. Without this the
                                        // engine boots with halted=false and
                                        // happily proposes frames during a
                                        // network-wide halt window until the
                                        // next halt-state transition arrives.
                                        handle.set_halted(drain_halt.any_halted());
                                        // Register the engine handle so the
                                        // recv loop can dispatch peer
                                        // messages to it.
                                        {
                                            let mut map = drain_shard_engines.write();
                                            map.insert(filter.clone(), handle);
                                        }
                                        // Subscribe BlossomSub to the four
                                        // per-shard bitmasks. Without these
                                        // subscriptions our mesh peers won't
                                        // forward shard traffic to us, so
                                        // peer votes / proposals / frames /
                                        // dispatches never reach the engine.
                                        let p2p = drain_p2p.clone();
                                        let filter_for_sub = filter.clone();
                                        drain_spawner.detach("shard-subscribe", async move {
                                            p2p.subscribe(quil_engine::bitmasks::shard_frame_bitmask(&filter_for_sub)).await;
                                            p2p.subscribe(quil_engine::bitmasks::shard_consensus_bitmask(&filter_for_sub)).await;
                                            p2p.subscribe(quil_engine::bitmasks::shard_prover_bitmask(&filter_for_sub)).await;
                                            p2p.subscribe(quil_engine::bitmasks::shard_dispatch_bitmask(&filter_for_sub)).await;
                                            Ok(())
                                        });
                                        info!(
                                            core_id,
                                            filter = %hex::encode(&filter),
                                            "registered shard engine + subscribed per-shard bitmasks"
                                        );
                                    }
                                    WorkerToMaster::ShardDeactivated { core_id, filter } => {
                                        {
                                            let mut map = drain_shard_engines.write();
                                            map.remove(&filter);
                                        }
                                        let p2p = drain_p2p.clone();
                                        let filter_for_sub = filter.clone();
                                        drain_spawner.detach("shard-unsubscribe", async move {
                                            p2p.unsubscribe(quil_engine::bitmasks::shard_frame_bitmask(&filter_for_sub)).await;
                                            p2p.unsubscribe(quil_engine::bitmasks::shard_consensus_bitmask(&filter_for_sub)).await;
                                            p2p.unsubscribe(quil_engine::bitmasks::shard_prover_bitmask(&filter_for_sub)).await;
                                            p2p.unsubscribe(quil_engine::bitmasks::shard_dispatch_bitmask(&filter_for_sub)).await;
                                            Ok(())
                                        });
                                        info!(
                                            core_id,
                                            filter = %hex::encode(&filter),
                                            "deregistered shard engine + unsubscribed per-shard bitmasks"
                                        );
                                    }
                                    WorkerToMaster::Ready { .. }
                                    | WorkerToMaster::ShardHeartbeat { .. } => {
                                        // No-op — informational only.
                                    }
                                }
                    }
                    info!("worker→master drain task stopped");
                    Ok(())
                });
            }
            // Restore persisted worker state (manually_managed flag +
            // assigned filter) before any pre-allocation runs, so the
            // operator's intent sticks across restarts.
            //
            // Archive mode skips the restore — `set_worker_filter`
            // would otherwise spawn worker threads, and archives don't
            // run app-shard workers. A subsequent return to non-archive
            // will pick
            // them up again because we don't delete them here.
            let persisted = if archive_mode {
                if !thread_mgr.load_all_persisted().is_empty() {
                    info!("archive mode: skipping persisted worker restore");
                }
                Vec::new()
            } else {
                thread_mgr.load_all_persisted()
            };
            if !persisted.is_empty() {
                info!(
                    count = persisted.len(),
                    "restoring persisted worker state from store"
                );
                for entry in persisted {
                    // Resurrect the binding (filter pinned, no
                    // consensus engine yet — `worker_allocator` will
                    // re-attach the engine when the registry alloc
                    // for this filter is observed Active).
                    if !entry.filter.is_empty() {
                        if let Err(e) = quil_engine::worker::WorkerManager::set_worker_filter(
                            thread_mgr.as_ref(),
                            entry.core_id,
                            &entry.filter,
                            false,
                        ) {
                            warn!(
                                core_id = entry.core_id,
                                error = %e,
                                "failed to restore worker filter from store"
                            );
                        }
                    }
                    if entry.manually_managed {
                        if let Err(e) = quil_engine::worker::WorkerManager::set_manually_managed(
                            thread_mgr.as_ref(),
                            entry.core_id,
                            true,
                        ) {
                            warn!(
                                core_id = entry.core_id,
                                error = %e,
                                "failed to restore manually_managed flag"
                            );
                        }
                    }
                    if entry.pending_filter_frame > 0 {
                        let _ = quil_engine::worker::WorkerManager::set_pending_filter_frame(
                            thread_mgr.as_ref(),
                            entry.core_id,
                            entry.pending_filter_frame,
                        );
                    }
                }
            }
            thread_mgr as Arc<dyn quil_engine::worker::WorkerManager>
        };

    // Pre-allocate idle workers for each available core so they're
    // online from startup. Workers start idle (empty filter) and get
    // assigned shards by the lifecycle when join proposals are accepted.
    //
    // Archive mode skips this entirely. Per the architecture
    // (re-stated at the `frame_materializer` block below): archives
    // materialize global frames; workers materialize app-shard frames
    // — a separate role. An archive node spawning app-shard workers
    // would be every-role-at-once, which is wrong: an archive's job
    // is to retain global history and serve sync, not to compete
    // for shard rewards. The other gates (lifecycle.evaluate,
    // worker_allocator.on_new_frame) are also archive-skipped in
    // their respective call sites below.
    if !archive_mode {
        let num_cores = match worker_manager.check_workers_connected() {
            Ok(ids) => ids.len() as u32,
            Err(_) => 0,
        };
        // If no workers exist yet, create them for cores 1..N
        if num_cores == 0 {
            let total = std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(4);
            let worker_count = total.saturating_sub(1).max(1); // reserve core 0 for master
            for core_id in 1..=worker_count {
                if let Err(e) = worker_manager.allocate_worker(core_id, &[]) {
                    warn!(core_id, error = %e, "failed to pre-allocate idle worker");
                }
            }
            info!(workers = worker_count, "pre-allocated idle workers");
        }
    } else {
        info!("archive mode: skipping worker pre-allocation (archives don't run app-shard workers)");
    }

    // Apply `engine.data_worker_filters` from YAML config. Runs AFTER
    // persisted-restore and idle pre-allocation:
    //   * fresh node pins config filters with manually_managed=true;
    //   * restart with prior persisted/gRPC assignment keeps it
    //     (persisted wins).
    // Skipped in archive mode for the same reason as pre-allocation.
    if !archive_mode {
        let cfg_filters = &config.engine.data_worker_filters;
        let stats = quil_engine::worker_allocator::apply_config_worker_filters(
            worker_manager.as_ref(),
            cfg_filters,
        );
        if !cfg_filters.is_empty() {
            info!(
                declared = cfg_filters.len(),
                applied = stats.applied,
                skipped_existing = stats.skipped_existing,
                skipped_missing_core = stats.skipped_missing_core,
                skipped_empty = stats.skipped_empty,
                invalid = stats.invalid,
                "applied engine.data_worker_filters"
            );
        }
    } else if !config.engine.data_worker_filters.is_empty() {
        info!(
            declared = config.engine.data_worker_filters.len(),
            "archive mode: ignoring engine.data_worker_filters (archives don't run app-shard workers)"
        );
    }

    // Publish the worker_manager handle to the PeerInfo broadcaster.
    // From this point on, every PeerInfo tick advertises a
    // per-worker reachability for each running worker with a
    // non-empty filter. Thread-mode workers (the default) share the
    // master's addresses; process-mode workers (when
    // `engine.data_worker_p2p_multiaddrs` or
    // `engine.data_worker_stream_multiaddrs` is configured) advertise
    // their own ports. See
    // `quil_p2p::peer_info::build_worker_reachability` for the
    // selection rules.
    let _ = pi_worker_manager.set(worker_manager.clone());

    worker_manager
}
