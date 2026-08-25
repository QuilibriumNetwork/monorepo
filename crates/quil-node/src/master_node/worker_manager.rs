use std::collections::HashSet;
use std::sync::Arc;

use tracing::{debug, info, warn};

// Import KeyManager trait for get_signer
use quil_keys::KeyManager as _;
// ClockStore trait — mirror worker-finalized app-shard frames into the master store.
use quil_types::store::ClockStore as _;

use quil_lifecycle::Supervisor;

/// Restore persisted local workers and recreate any configured core that is
/// absent from the in-memory pool.
///
/// An empty filter is an idle worker slot, not an absent worker. Restoring only
/// filtered records followed by all-or-nothing preallocation loses those idle
/// slots after the first restart.
fn restore_and_fill_worker_pool(
    worker_manager: &dyn quil_engine::worker::WorkerManager,
    persisted: &[quil_types::store::PersistedWorkerInfo],
    expected_worker_count: u32,
) -> quil_types::error::Result<(usize, usize)> {
    let mut restored = 0;
    for entry in persisted {
        // This deliberately also spawns records with an empty filter: they are
        // idle workers which must remain available for later allocations.
        worker_manager.set_worker_filter(entry.core_id, &entry.filter, false)?;
        if entry.manually_managed {
            worker_manager.set_manually_managed(entry.core_id, true)?;
        }
        if entry.pending_filter_frame > 0 {
            worker_manager.set_pending_filter_frame(entry.core_id, entry.pending_filter_frame)?;
        }
        restored += 1;
    }

    let connected: HashSet<u32> = worker_manager.check_workers_connected()?.into_iter().collect();
    let mut created = 0;
    for core_id in 1..=expected_worker_count {
        if !connected.contains(&core_id) {
            worker_manager.allocate_worker(core_id, &[])?;
            created += 1;
        }
    }
    Ok((restored, created))
}

/// Mirror a finalized `AppShardFrame` (canonical `frame_data`) into the master
/// clock store so the store-backed `AppShardService::get_app_shard_frame` serves
/// it. Workers commit into their OWN per-worker store (a REMOTE process in
/// cluster mode), which the master-store-backed service otherwise can't see.
/// Stages by selector = `poseidon(header.output)` (so `get_latest_shard_clock_frame`
/// resolves via the latest index), then commits the latest-index head. Best-
/// effort + idempotent/monotonic (clock.rs:1152), so safe to re-run.
///
/// Used by BOTH paths: the in-process thread-worker drain (`WorkerToMaster::
/// FullFrameProduced`) AND the master's recv loop on `shard_frame_bitmask`
/// gossip — the latter is the ONLY way a cluster master (whose shards are on
/// remote workers) ever populates its own store for those filters.
pub(crate) fn mirror_shard_frame_to_clock_store(
    clock_store: &dyn quil_types::store::ClockStore,
    filter: &[u8],
    frame_data: &[u8],
) {
    let frame = match <quil_types::proto::global::AppShardFrame as prost::Message>::decode(frame_data)
    {
        Ok(f) => f,
        Err(_) => return, // non-frame traffic on this bitmask — ignore
    };
    let Some(header) = frame.header.as_ref() else { return };
    let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
        .map(|h| h.to_vec())
        .unwrap_or_default();
    let frame_number = header.frame_number;
    if let Ok(txn) = clock_store.new_transaction(false) {
        match clock_store.stage_shard_clock_frame(&selector, &frame, txn.as_ref()) {
            Ok(()) => {
                let _ = txn.commit();
            }
            Err(e) => warn!(
                filter = %hex::encode(filter),
                error = %e,
                "mirror app-shard frame to master store failed"
            ),
        }
    }
    // Commit the latest-index pointer too — staging alone writes only the staged
    // key, so `get_latest_shard_clock_frame` (which reads the canonical key via
    // the latest index) would NOT resolve to this frame.
    if let Ok(txn) = clock_store.new_transaction(false) {
        if let Err(e) =
            clock_store.commit_shard_clock_frame(filter, frame_number, &selector, txn.as_ref(), false)
        {
            warn!(
                filter = %hex::encode(filter),
                error = %e,
                "commit mirrored app-shard frame head failed"
            );
        } else {
            let _ = txn.commit();
        }
    }
}

/// Build the hypergraph CRDT owned by one in-process (thread) worker, with a
/// PERSISTENT (namespaced Rocks) forest installed.
///
/// Thread workers use a dedicated RocksDB, just like standalone workers. A
/// brand-new worker must install the Rocks forest before its first
/// materialization: leaving the CRDT's default IN-MEMORY forest in place
/// persists the vertex blobs + materialized cursor but LOSES the commitment
/// nodes on restart (they lived only in memory) — so on restart the worker has
/// state but can't reproduce its roots. The prior `install_forest_if_migrated`
/// only installed on an already-migrated DB, missing the fresh-worker case;
/// `install_forest_boot(store_is_fresh=…)` installs for a fresh DB too. "Fresh"
/// means NO durable materialized state — `RocksDb::open`'s schema marker and any
/// Simplex liveness/consensus metadata written before the first app write don't
/// count.
pub(crate) fn build_thread_worker_hypergraph(
    db: &Arc<quil_store::RocksDb>,
    inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    mainnet_quil_grid: bool,
) -> Arc<quil_hypergraph::HypergraphCrdt> {
    let raw_db = db.inner();
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(raw_db.clone()));
    let store_has_no_materialized_state = {
        let has_prefix = |prefix: &[u8]| {
            let mut it = raw_db.raw_iterator();
            it.seek(prefix);
            it.valid() && it.key().map(|k| k.starts_with(prefix)).unwrap_or(false)
        };
        let has_hypergraph_state = has_prefix(&[quil_store::encoding::HYPERGRAPH_SHARD]);
        let has_app_cursor = has_prefix(&[
            quil_store::encoding::CONSENSUS,
            quil_store::encoding::CONSENSUS_MATERIALIZED_CURSOR,
        ]);
        let has_global_cursor = has_prefix(&[
            quil_store::encoding::CONSENSUS,
            quil_store::encoding::CONSENSUS_GLOBAL_MATERIALIZED_CURSOR,
        ]);
        !(has_hypergraph_state || has_app_cursor || has_global_cursor)
    };
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover,
    ));
    if quil_forest_migrate::install_forest_boot(
        crdt.as_ref(),
        hg_store.as_ref(),
        store_has_no_materialized_state,
        mainnet_quil_grid,
    ) {
        tracing::info!(
            "Phase-3 JMT forest installed on thread-worker CRDT — state commitments are persistent"
        );
    }
    crdt
}

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
    /// Shared archive endpoint pool. Thread-mode workers build a per-worker
    /// step-4 app-shard catch-up syncer that resolves a live archive from this
    /// pool per attempt (see `worker_state_builder`).
    pub archive_pool: Arc<quil_rpc::ArchiveEndpointPool>,
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
        archive_pool,
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
            // Derive the master↔worker mTLS materials from the node's Falcon key
            // (workers derive the identical cert from the same key). Cluster mode
            // without this would be a plaintext, unauthenticated control channel.
            let channel_tls_pem = file_key_manager
                .get_private_key(quil_types::crypto::KeyType::Falcon512)
                .ok()
                .and_then(|sk| quil_rpc::quil_tls::build_worker_channel_cert(&sk).ok())
                .map(|t| (t.ca_cert_pem, t.leaf_cert_pem, t.leaf_key_pem));
            if channel_tls_pem.is_none() {
                warn!("cluster mode: could not build worker-channel mTLS cert — worker channel will be UNAUTHENTICATED plaintext");
            }
            let remote_mgr = Arc::new(quil_engine::remote_worker::RemoteWorkerManager::from_config(
                &config.engine.data_worker_stream_multiaddrs,
                master_ep,
                channel_tls_pem,
            ));
            info!(
                remote_workers = config.engine.data_worker_stream_multiaddrs.len(),
                "remote worker manager ready (cluster mode)"
            );
            // Publish to the halt broadcaster spawned above so it can
            // SetHalted across standalone workers when coverage halts.
            let _ = remote_worker_manager_for_halt.set(remote_mgr.clone());
            // Establish (and maintain) the gRPC channels to the remote workers.
            // `connect_all` was previously never called — cluster workers
            // registered but the master never connected, so the Respawn stayed
            // deferred forever and app-shard consensus never started. Poll so a
            // worker that boots after the master (or restarts) gets connected and
            // its owed Respawn re-issued (see RemoteWorkerManager::connect_all).
            {
                let cm = remote_mgr.clone();
                spawner.detach("remote-worker-connect", async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
                    loop {
                        tick.tick().await;
                        cm.connect_all().await;
                    }
                });
            }
            remote_mgr as Arc<dyn quil_engine::worker::WorkerManager>
        } else {
            // LOCAL MODE: core-pinned threads
            // Honor an explicit `dataWorkerCount` in local thread mode (0/unset
            // → auto-size to cpu-1). Without this the config field was ignored
            // and every node ran cpu-1 workers regardless of what was requested.
            let thread_mgr = Arc::new(quil_engine::thread_worker::ThreadWorkerManager::new_with_count(
                config.engine.data_worker_count,
            ));
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
            // For the per-worker step-4 app-shard catch-up syncer: the shared
            // archive pool + this node's Falcon key (the :8340 mTLS identity).
            let archive_pool_for_builder = archive_pool.clone();
            let falcon_sk_for_builder = file_key_manager
                .get_private_key(quil_types::crypto::KeyType::Falcon512)
                .ok();
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
                let hg_store_concrete =
                    Arc::new(quil_store::RocksHypergraphStore::new(db_arc.inner()));
                let hg_store: Arc<dyn quil_types::store::HypergraphStore> =
                    hg_store_concrete.clone();
                let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
                    Arc::new(quil_tries::ShaInclusionProver);
                // Build the worker CRDT with a PERSISTENT forest — a fresh worker
                // DB must install the Rocks forest or it loses its commitment nodes
                // on restart (the prior `install_forest_if_migrated` no-op'd on a
                // fresh DB). `hg_store`/`hg_store_concrete` above stay for the
                // syncer/hooks/exec below; the helper installs the forest over the
                // same DB.
                let _ = hg_store; // superseded by the helper's own store handle
                let mainnet_quil_grid = config.p2p.network == 0;
                let crdt =
                    build_thread_worker_hypergraph(&db_arc, inclusion_prover.clone(), mainnet_quil_grid);
                // Workers don't sign or verify identities — a default
                // key manager satisfies the execution engine's
                // `KeyManager` requirement for state materialization.
                let worker_key_manager: Arc<dyn quil_types::crypto::KeyManager> =
                    Arc::new(quil_crypto::DefaultKeyManager::new());
                // decaf448 bulletproof/decaf providers are retired (the
                // confidential-value path is now lattice-CT); the circuit
                // compiler still uses a noop stub (no production impl yet).
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
                        circuit_compiler,
                        clock_store_for_exec,
                        hypergraph_resolver,
                        true,
                    ),
                );
                // Step-4 app-shard catch-up syncer bound to THIS worker's CRDT +
                // store, dialing a live archive from the shared pool per attempt.
                // Only when the Falcon key resolved (the mTLS identity); otherwise
                // the worker skips the event (shared-state / keyless test paths).
                let shard_syncer: Option<
                    Arc<dyn quil_engine::prover_tree_syncer::ProverTreeSyncer>,
                > = falcon_sk_for_builder.clone().map(|sk| {
                    Arc::new(crate::prover_tree_syncer_prod::ProdProverTreeSyncer {
                        // Unused when the pool resolves an endpoint; kept as the
                        // fallback (empty ⇒ connect fails, logged, retried next gap).
                        master_stream_addr: String::new(),
                        hg_store: hg_store_concrete.clone(),
                        falcon_signing_key: sk,
                        crdt: crdt.clone(),
                        archive_pool: Some(archive_pool_for_builder.clone()),
                    })
                        as Arc<dyn quil_engine::prover_tree_syncer::ProverTreeSyncer>
                });
                // (B) Unified-cutover consolidation hook bound to THIS worker's
                // store: fold the covered app's pre-cutover per-sub-shard trees
                // into its single app.l2 tree (`convert_app`, empty prefix = whole
                // app rebuilt from raw vertices) so the first unified subtree
                // `state_root` (A) reflects pre-cutover data. A no-op at genesis
                // (empty app). `filter[..32]` = the covered app.
                let hg_for_hook = hg_store_concrete.clone();
                let unified_cutover_hook: Option<
                    Arc<dyn Fn(&[u8], u64) -> bool + Send + Sync>,
                > = Some(Arc::new(move |filter: &[u8], _gfn: u64| -> bool {
                    if filter.len() < 32 {
                        return false;
                    }
                    let mut app = [0u8; 32];
                    app.copy_from_slice(&filter[..32]);
                    let shard_key = quil_types::store::ShardKey {
                        l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3),
                        l2: app,
                    };
                    let forest = quil_forest::Forest::with_namespace(
                        hg_for_hook.raw_db(),
                        quil_store::FOREST_NAMESPACE.to_vec(),
                    );
                    match quil_forest_migrate::convert_app(
                        hg_for_hook.as_ref(),
                        &forest,
                        &shard_key,
                        0,
                        &[Vec::new()],
                    ) {
                        Ok(_) => true,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                app = %hex::encode(app),
                                "worker unified-cutover consolidation (convert_app) failed"
                            );
                            false
                        }
                    }
                }));
                tracing::info!(
                    core_id,
                    path = %path.display(),
                    has_shard_syncer = shard_syncer.is_some(),
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
                    shard_syncer,
                    unified_cutover_hook,
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
                    fkm_for_factory.get_signer(quil_types::crypto::KeyType::Falcon512)
                        .expect("BLS signer should be available")
                }),
                reward_greedy,
                min_active_provers_for_propose,
                app_consensus_cw: config.engine.app_consensus_cw,
                // Persistent per-shard simplex-journal base (Go parity): master
                // core 0 → db.path, worker core N → worker path. Threaded so
                // app-shard consensus resumes across restarts.
                db_config: config.db.clone(),
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
                // Master clock store — worker-finalized app-shard frames are mirrored
                // here so `AppShardService` (and any master-side reader) can serve
                // them. Workers commit into their OWN per-worker store, which the
                // master-store-backed service otherwise can't see.
                let drain_clock_store = clock_store.clone();
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
                                        // `FrameProduced` carries the proposal-time
                                        // `AppShardProposal` (0x0318), NOT a finalized frame.
                                        // It MUST go on the per-shard CONSENSUS bitmask so peers
                                        // route it through `handle_consensus_message` →
                                        // `handle_app_shard_proposal`, which submits the proposal's
                                        // parent QC + the proposal to their event loop so they
                                        // VOTE and ADVANCE. Publishing it on the frame bitmask
                                        // sent it to `handle_frame_message` (finalized-frame
                                        // materialization only), which can't decode 0x0318 and
                                        // drops it — so followers never voted, the chain wedged at
                                        // rank 1, no 2-chain, no finalization, no reward. Mirrors
                                        // Go publishing proposals on `getConsensusMessageBitmask`.
                                        // (`FullFrameProduced` below stays on the frame bitmask.)
                                        if drain_halt.any_halted() {
                                            debug!(core_id, filter = %hex::encode(&filter),
                                                "suppressing shard proposal publish — coverage halt active");
                                            continue;
                                        }
                                        let p2p = drain_p2p.clone();
                                        drain_spawner.detach("shard-proposal-publish", async move {
                                            if let Err(e) = p2p
                                                .publish(
                                                    quil_engine::bitmasks::shard_consensus_bitmask(&filter),
                                                    frame_data,
                                                )
                                                .await
                                            {
                                                warn!(core_id, filter = %hex::encode(&filter),
                                                    error = %e, "shard proposal publish failed");
                                            }
                                            Ok(())
                                        });
                                    }
                                    WorkerToMaster::FullFrameProduced { core_id, filter, frame_data, .. } => {
                                        // Full AppShardFrame (header+requests) — publish on
                                        // the per-shard frame bitmask for state distribution
                                        // to followers/archives.
                                        if drain_halt.any_halted() {
                                            continue;
                                        }
                                        // Mirror the finalized frame into the MASTER clock store so
                                        // the store-backed `AppShardService` serves it (the worker
                                        // committed it only into its OWN store). Best-effort; never
                                        // blocks the publish below.
                                        mirror_shard_frame_to_clock_store(
                                            drain_clock_store.as_ref(),
                                            &filter,
                                            &frame_data,
                                        );
                                        let p2p = drain_p2p.clone();
                                        drain_spawner.detach("shard-full-frame-publish", async move {
                                            if let Err(e) = p2p
                                                .publish(
                                                    quil_engine::bitmasks::shard_frame_bitmask(&filter),
                                                    frame_data,
                                                )
                                                .await
                                            {
                                                warn!(core_id, filter = %hex::encode(&filter),
                                                    error = %e, "full shard frame publish failed");
                                            }
                                            Ok(())
                                        });
                                    }
                                    WorkerToMaster::CwConsensus { core_id, filter, channel, bytes } => {
                                        // (P3) commonware-simplex message → one shard CW
                                        // gossip topic; channel tagged into the payload.
                                        if drain_halt.any_halted() {
                                            continue;
                                        }
                                        let p2p = drain_p2p.clone();
                                        drain_spawner.detach("shard-cw-publish", async move {
                                            if let Err(e) = p2p
                                                .publish(
                                                    quil_engine::bitmasks::shard_cw_bitmask(&filter),
                                                    quil_engine::bitmasks::shard_cw_frame_payload(channel, &bytes),
                                                )
                                                .await
                                            {
                                                warn!(core_id, filter = %hex::encode(&filter),
                                                    error = %e, "shard cw publish failed");
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
                                            // (P3) Subscribe the shard's commonware-simplex topic so
                                            // committee peers' votes/certs/blocks reach this engine.
                                            p2p.subscribe(quil_engine::bitmasks::shard_cw_bitmask(&filter_for_sub)).await;
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
            if !archive_mode {
                let worker_count = if config.engine.data_worker_count > 0 {
                    config.engine.data_worker_count as u32
                } else {
                    std::thread::available_parallelism()
                        .map(|n| n.get() as u32)
                        .unwrap_or(4)
                        .saturating_sub(1)
                        .max(1)
                };
                match restore_and_fill_worker_pool(thread_mgr.as_ref(), &persisted, worker_count) {
                    Ok((restored, created)) => info!(
                        workers = worker_count,
                        restored,
                        created,
                        "restored and filled local worker pool"
                    ),
                    Err(e) => warn!(error = %e, "failed to restore and fill local worker pool"),
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
        // If no workers exist yet, create them for cores 1..N. Honor an explicit
        // `dataWorkerCount` (>0); otherwise auto-size to `available_parallelism-1`
        // (reserve core 0 for the master). Without honoring the config here, this
        // loop would spawn cpu-1 worker threads even when the operator asked for
        // a specific count (e.g. a single-worker localnet).
        if num_cores == 0 {
            let worker_count = if config.engine.data_worker_count > 0 {
                config.engine.data_worker_count as u32
            } else {
                std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(4)
                    .saturating_sub(1)
                    .max(1) // reserve core 0 for master
            };
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

#[cfg(test)]
mod tests {
    use super::*;
    use quil_engine::test_support::TestWorkerManager;
    use quil_engine::worker::WorkerManager as _;

    #[test]
    fn restart_restores_idle_worker_slot_and_fills_missing_cores() {
        // After the initial post-wipe run, core 2 is allocated and core 3 is
        // idle. Both are persisted; restarting must retain the idle core.
        let manager = TestWorkerManager::new();
        let persisted = vec![
            quil_types::store::PersistedWorkerInfo {
                core_id: 2,
                filter: vec![0xaa],
                manually_managed: false,
                allocated: true,
                pending_filter_frame: 0,
            },
            quil_types::store::PersistedWorkerInfo {
                core_id: 3,
                filter: Vec::new(),
                manually_managed: false,
                allocated: false,
                pending_filter_frame: 0,
            },
        ];

        assert_eq!(
            restore_and_fill_worker_pool(&manager, &persisted, 3).unwrap(),
            (2, 1)
        );
        let workers = manager.range_workers().unwrap();
        assert_eq!(workers.iter().map(|w| w.core_id).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert!(workers.iter().find(|w| w.core_id == 3).unwrap().filter.is_empty());
    }

    /// #595 regression: a fresh thread worker must install a PERSISTENT (Rocks)
    /// forest, not the CRDT's default in-memory one — otherwise the commitment
    /// nodes are lost on restart even though the vertex blobs + cursor persist,
    /// so the restarted worker can't reproduce (or extend) its own state root.
    #[test]
    fn fresh_thread_worker_forest_survives_restart_and_extends_prior_root() {
        let dir = tempfile::tempdir().unwrap();
        let first_location = quil_hypergraph::Location {
            app_address: [0x2a; 32],
            data_address: [0x07; 32],
        };
        let shard_key = quil_hypergraph::shard_key_for_location(&first_location);

        let first_root = {
            let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
            // RocksDb::open's schema marker + any Simplex/consensus metadata
            // written before the first materialized frame must NOT disqualify a
            // fresh worker from installing its persistent forest.
            db.inner()
                .put(
                    [
                        quil_store::encoding::CONSENSUS,
                        quil_store::encoding::CONSENSUS_STATE,
                        0x42,
                    ],
                    b"pre-materialization metadata",
                )
                .unwrap();
            let crdt = build_thread_worker_hypergraph(
                &db,
                Arc::new(quil_tries::ShaInclusionProver),
                false,
            );
            assert!(
                crdt.forest_is_persistent(),
                "fresh worker must not use Forest::in_memory"
            );

            crdt.add_vertex(&first_location, b"persisted worker state").unwrap();
            let roots = crdt.commit(1).unwrap();
            let root = roots[&shard_key][0].clone();
            assert!(root.iter().any(|byte| *byte != 0));
            root
        };

        // Drop every handle above, then REOPEN the exact worker DB. The
        // commitment root must come from RocksDB, not process memory.
        let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
        let crdt =
            build_thread_worker_hypergraph(&db, Arc::new(quil_tries::ShaInclusionProver), false);
        assert!(crdt.forest_is_persistent());
        assert_eq!(
            crdt.compute_shard_root("vertex", "adds", &shard_key),
            first_root,
            "restarted worker must recover the previously advertised state root"
        );

        // Extending after restart must build on the RESTORED tree, not an empty
        // forest that merely happens to be persistent now.
        crdt.add_vertex(
            &quil_hypergraph::Location {
                app_address: first_location.app_address,
                data_address: [0x08; 32],
            },
            b"state added after restart",
        )
        .unwrap();
        let second_root = crdt.commit(2).unwrap()[&shard_key][0].clone();
        assert_ne!(second_root, first_root);
    }
}
