use std::collections::{HashMap, HashSet};
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

/// `NoPeersSubscribedToTopic` is transient during gossip mesh startup; other
/// publish errors require a different recovery path and must not be retried by
/// the CW outbox.
fn retryable_cw_publish_failure(error: &str, attempt: u32) -> bool {
    error.contains("NoPeersSubscribedToTopic") && attempt < 8
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
    // Committee-handoff flag day: from activation the master's copy of the
    // legacy chains is discarded before the first session frame is mirrored
    // (under one lock, so no session frame is mirrored into a store about to
    // be discarded), and legacy frames are not mirrored any more.
    static FLAG_DAY: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _flag_day = match quil_types::consensus::committee_handoff_policy()
        .filter(|policy| policy.legacy_history == quil_types::consensus::LegacyHistory::Discard)
    {
        Some(policy) => {
            let global = clock_store.get_latest_global_clock_frame().ok()
                .and_then(|frame| frame.header).map_or(0, |header| header.frame_number);
            if global < policy.activation_frame {
                None
            } else {
                if header.global_frame_number < policy.activation_frame {
                    return;
                }
                let guard = FLAG_DAY.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if matches!(clock_store.app_frame_history_discarded(), Ok(None)) {
                    match clock_store.discard_app_frame_history(global) {
                        Ok(()) => tracing::info!(global, "committee-handoff flag day: master discarded its mirrored legacy app frames"),
                        Err(error) => {
                            warn!(%error, "mirrored legacy app frames could not be discarded; not mirroring");
                            return;
                        }
                    }
                }
                Some(guard)
            }
        }
        None => None,
    };
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

/// Store key recording that `application`'s tree in this worker store is the
/// unified tree ([`unified_cutover_conversion`]).
fn unified_cutover_marker_key(application: &[u8; 32]) -> Vec<u8> {
    let mut key = b"\x00__quil_worker_unified_cutover__".to_vec();
    key.extend_from_slice(application);
    key
}

/// Fold the application `filter` names into its single unified app tree
/// (empty prefix = the whole app rebuilt from its vertices), once per worker
/// store. A no-op at genesis (empty app).
///
/// The engine's unified flag lives in memory, so it asks for this again on
/// every restart past the cutover. Rebuilding then committed the tree at
/// version zero, and the commits after it continued from there while the
/// store still held each vertex's blobs at the higher versions written before
/// the restart. Reads take the greatest version, so every record updated after
/// a restart read back its old value (live: a delivery wrote its coin, but the
/// block's count, root and summary reverted, and every later delivery to that
/// block failed). An app tree that already exists is therefore never rebuilt,
/// and a first conversion commits each phase above the blobs it already holds.
pub(crate) fn unified_cutover_conversion(
    hg: &quil_store::RocksHypergraphStore,
    filter: &[u8],
) -> bool {
    let Some(app) = filter.get(..32).and_then(|app| <[u8; 32]>::try_from(app).ok()) else {
        return false;
    };
    let marker = unified_cutover_marker_key(&app);
    if hg.raw_db().get(&marker).ok().flatten().is_some() {
        return true;
    }
    let shard_key = quil_types::store::ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3),
        l2: app,
    };
    let forest = quil_forest::Forest::with_namespace(
        hg.raw_db(),
        quil_store::FOREST_NAMESPACE.to_vec(),
    );
    let converted = (|| -> anyhow::Result<()> {
        let mut heads = [None; 4];
        let mut blobs = [None; 4];
        for (index, (set, phase, tree)) in UNIFIED_PHASES.into_iter().enumerate() {
            heads[index] = forest.read_head_version(&app, tree)?;
            blobs[index] = hg.max_vertex_v2_version(set, phase, &shard_key)?;
        }
        if heads.iter().any(Option::is_some) {
            // Committed as one tree already: a single-shard app before the
            // cutover, or a store an earlier conversion rebuilt. A store whose
            // blobs lie above its tree already reads stale values.
            if heads.iter().zip(&blobs).any(|(head, blob)| blob > &Some(head.unwrap_or(0))) {
                warn!(app = %hex::encode(app),
                    "worker store holds vertex blobs above its app tree version; \
                     updated records read stale values until this shard is resynced");
            }
            return Ok(());
        }
        let versions = blobs.map(|blob| blob.map_or(0, |version| version + 1));
        quil_forest_migrate::convert_app_at_versions(hg, &forest, &shard_key, versions, &[Vec::new()])?;
        Ok(())
    })();
    match converted {
        Ok(()) => {
            if let Err(error) = hg.raw_db().put(&marker, [1u8]) {
                warn!(%error, app = %hex::encode(app),
                    "worker unified-cutover marker write failed; the next restart checks again");
            }
            true
        }
        Err(error) => {
            warn!(%error, app = %hex::encode(app),
                "worker unified-cutover consolidation (convert_app) failed");
            false
        }
    }
}

/// The four phase keyspaces and trees, in [`quil_forest::Phase`] order.
const UNIFIED_PHASES: [(&str, &str, quil_forest::Phase); 4] = [
    ("vertex", "adds", quil_forest::Phase::VertexAdds),
    ("vertex", "removes", quil_forest::Phase::VertexRemoves),
    ("hyperedge", "adds", quil_forest::Phase::HyperedgeAdds),
    ("hyperedge", "removes", quil_forest::Phase::HyperedgeRemoves),
];

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
/// Mark a worker CRDT's persisted size buckets as its initialized size
/// accounting, without a forest scan. A worker's buckets are local: its frames
/// commit only their phase roots, so nothing members agree on reads them. But
/// an uninitialized CRDT refuses every execution fork ("execution capture
/// requires initialized size accounting"), so the private-parent executor
/// never ran on a worker: a selected parent that was notarized but not
/// finalized then made every member abstain, and the shard wedged. The master
/// warms its own CRDT at boot with its committed apps.
/// The gossip topics a registered shard engine subscribes.
fn shard_topics(filter: &[u8]) -> [Vec<u8>; 4] {
    [
        quil_engine::bitmasks::shard_frame_bitmask(filter),
        quil_engine::bitmasks::shard_consensus_bitmask(filter),
        quil_engine::bitmasks::app_prover_bitmask(filter),
        quil_engine::bitmasks::shard_dispatch_bitmask(filter),
    ]
}

/// The topics a deactivated shard's engine can release: those no registered
/// engine still subscribes. The wallet submission topic is keyed by the
/// application, so every shard of an application shares it; releasing it
/// with one shard left the others unreachable (a live width run's transfers
/// failed with `NoPeersSubscribedToTopic`).
fn releasable_shard_topics<'a>(filter: &[u8], registered: impl IntoIterator<Item = &'a Vec<u8>>) -> Vec<Vec<u8>> {
    let needed: std::collections::HashSet<Vec<u8>> =
        registered.into_iter().flat_map(|other| shard_topics(other)).collect();
    shard_topics(filter).into_iter().filter(|topic| !needed.contains(topic)).collect()
}

pub(crate) fn initialize_worker_size_accounting(crdt: &quil_hypergraph::HypergraphCrdt, label: &str) {
    if let Err(error) = crdt.warm_sizes(&[]) {
        tracing::warn!(store = label, %error,
            "worker size accounting not initialized; selected parents cannot be executed privately");
    }
}

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
    initialize_worker_size_accounting(&crdt, &db.inner().path().display().to_string());
    if let (true, Some(policy)) = (crdt.forest_is_persistent(), quil_hypergraph::RetentionPolicy::from_env()) {
        quil_hypergraph::spawn_retention_pruner(&crdt, policy, db.inner().path().display().to_string());
    }
    let label = db.inner().path().display().to_string();
    crate::clock_retention::apply_snapshot_pin_limit(&crdt, &label);
    crate::clock_retention::spawn_staged_cleanup(Arc::new(quil_store::RocksClockStore::new(db.inner())), label);
    crdt
}

/// Stores owned by one in-process (thread) worker. A worker opens its own
/// RocksDB, so the application state it materializes is not in the master's
/// stores; the node's RPC reads an application's wallet state from here.
#[derive(Clone)]
pub(crate) struct WorkerAppState {
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub db: Arc<quil_store::RocksDb>,
    pub hg_store: Arc<dyn quil_types::store::HypergraphStore>,
}

/// Shard filter → stores of the thread worker covering it. Filled on shard
/// activation from the per-core stores the worker builder registers.
pub(crate) type WorkerAppStates =
    Arc<parking_lot::RwLock<std::collections::HashMap<Vec<u8>, WorkerAppState>>>;

pub(crate) struct WorkerManagerArgs {
    /// Rebuilds legacy committees from GLOBAL state; set once the archive
    /// sync has its frame verifier.
    pub historical_committees: Arc<std::sync::OnceLock<Arc<super::historical_committees::HistoricalCommittees>>>,
    /// Peer id → PeerInfo; maps a committee key to the peer a resolver
    /// message can be delivered to directly ([`CommitteePeers`]).
    pub peer_info_cache: Arc<parking_lot::RwLock<HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>>,
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
    /// Filter → covering thread worker's stores (see [`WorkerAppState`]).
    pub worker_app_states: WorkerAppStates,
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
    /// Clone of the node-wide token proof verifier client; installed on
    /// every thread worker's execution manager so they share one admission slot.
    #[cfg(feature = "native-proof")]
    pub proof_worker: Option<quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier>,
}

pub(crate) fn init(
    sup: &mut Supervisor<anyhow::Error>,
    args: WorkerManagerArgs,
) -> Arc<dyn quil_engine::worker::WorkerManager> {
    let WorkerManagerArgs {
        historical_committees,
        peer_info_cache,
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
        worker_app_states,
        remote_worker_manager_for_halt,
        pi_worker_manager,
        prover_message_transport,
        archive_pool,
        spawner,
        #[cfg(feature = "native-proof")]
        proof_worker,
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
    let min_active_provers_for_propose: u64 =
        quil_execution::token_intrinsic::constants::min_active_provers_for_shard_frames(config.p2p.network);
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
            let historical_committees_for_builder = historical_committees.clone();
            let falcon_sk_for_builder = file_key_manager
                .get_private_key(quil_types::crypto::KeyType::Falcon512)
                .ok();
            #[cfg(feature = "native-proof")]
            let proof_worker_for_builder = proof_worker.clone();
            let network_for_builder = config.p2p.network;
            // Per-core stores, mapped to shard filters on activation.
            let worker_stores_by_core: Arc<parking_lot::RwLock<std::collections::HashMap<u32, WorkerAppState>>> =
                Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
            let worker_stores_for_builder = worker_stores_by_core.clone();
            // Global frames live in the master's store; a worker's own store
            // holds only its app-shard chain.
            let master_clock_for_builder: Arc<dyn quil_types::store::ClockStore> =
                clock_store.clone();
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
                    Arc::new(quil_execution::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(crdt.clone()));
                let exec_manager = quil_execution::ExecutionEngineManager::new(
                    inclusion_prover.clone(),
                    worker_key_manager,
                    crdt.clone(),
                    circuit_compiler,
                    clock_store_for_exec,
                    hypergraph_resolver,
                    true,
                )
                .with_pricing_network(network_for_builder)
                .with_application_venue()
                .and_then(|manager| manager.with_global_clock_store(master_clock_for_builder.clone()))
                .map_err(|e| format!("worker {core_id}: {e}"))?;
                // Same token policy and shared verifier slot as the master.
                #[cfg(feature = "native-proof")]
                let exec_manager = crate::proof_worker::install_token_worker(
                    exec_manager,
                    network_for_builder,
                    proof_worker_for_builder.as_ref(),
                )
                .map_err(|e| format!("worker {core_id}: {e}"))?;
                #[cfg(not(feature = "native-proof"))]
                let _ = network_for_builder;
                let exec_manager = Arc::new(exec_manager);
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
                        discover_archives_from_master: false,
                    })
                        as Arc<dyn quil_engine::prover_tree_syncer::ProverTreeSyncer>
                });
                // (B) Unified-cutover consolidation hook bound to THIS worker's
                // store: fold the covered app's pre-cutover per-sub-shard trees
                // into its single app.l2 tree so the first unified subtree
                // `state_root` (A) reflects pre-cutover data.
                let hg_for_hook = hg_store_concrete.clone();
                let unified_cutover_hook: Option<
                    Arc<dyn Fn(&[u8], u64) -> bool + Send + Sync>,
                > = Some(Arc::new(move |filter: &[u8], _gfn: u64| -> bool {
                    unified_cutover_conversion(hg_for_hook.as_ref(), filter)
                }));
                tracing::info!(
                    core_id,
                    path = %path.display(),
                    has_shard_syncer = shard_syncer.is_some(),
                    "worker state initialized"
                );
                worker_stores_for_builder.write().insert(core_id, WorkerAppState {
                    crdt: crdt.clone(),
                    db: db_arc.clone(),
                    hg_store: hg_store_concrete.clone() as Arc<dyn quil_types::store::HypergraphStore>,
                });
                // Outputs committed to this worker's shard were often executed
                // on another: their bytes live in that shard's certified frame,
                // which only an archive holds. Pull them on the engine's own
                // timer so a proposal reads them locally.
                let delivery_pool = archive_pool_for_builder.clone();
                let delivery_frame_source: Option<quil_engine::app_engine::DeliveryFrameSource> =
                    falcon_sk_for_builder.clone().map(|key| {
                        Arc::new(move |filter: Vec<u8>, frame_number: u64| {
                            let pool = delivery_pool.clone();
                            let key = key.clone();
                            Box::pin(async move {
                                let endpoint = pool.next().await?;
                                let mut client = quil_rpc::ArchiveClient::connect_mtls(&endpoint, &key).await.ok()?;
                                client.get_app_shard_frame(filter, frame_number).await.ok().flatten()
                            }) as std::pin::Pin<Box<dyn std::future::Future<Output = Option<quil_types::proto::global::AppShardFrame>> + Send>>
                        }) as quil_engine::app_engine::DeliveryFrameSource
                    });
                Ok(quil_engine::thread_worker::WorkerOwnedDeps {
                    delivery_frame_source,
                    storage_history_source: falcon_sk_for_builder.clone().map(|key|
                        crate::storage_history::from_pool(archive_pool_for_builder.clone(), key)),
                    outgoing_history_source: falcon_sk_for_builder.clone().map(|key|
                        crate::storage_history::outgoing_history_from_pool(archive_pool_for_builder.clone(), key)),
                    historical_committee_source: Some(historical_committee_source(historical_committees_for_builder.clone())),
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
                // The master's grid and pending changes: a shard a recorded
                // split or merge retires drains before its flip.
                topology: Some(Arc::new(quil_store::RocksShardsStore::new(db_arc.inner()))
                    as Arc<dyn quil_types::store::ShardsStore>),
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
                let drain_committee_peers = super::direct_delivery::CommitteePeers::new(peer_info_cache.clone());
                let drain_registry = prover_registry.clone();
                let drain_pubkey = bls_pubkey.clone();
                let drain_clock = clock_store.clone();
                let drain_shard_engines = shard_engines.clone();
                let drain_worker_app_states = worker_app_states.clone();
                let drain_worker_stores = worker_stores_by_core.clone();
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
                                        // A positive log line so the operator can see
                                        // each rewardable proof going out (standalone
                                        // workers' log the same through the master).
                                        super::reward_proofs::log_reward_proof(core_id, "thread", &header_canonical_bytes);
                                        match super::reward_proofs::prover_bundle(header_canonical_bytes) {
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
                                    WorkerToMaster::CwConsensus { core_id, filter, channel, bytes, recipients } => {
                                        // Commonware-simplex message → one shard CW
                                        // gossip topic; channel tagged into the payload.
                                        if drain_halt.any_halted() {
                                            // Dropping consensus traffic is invisible from the
                                            // shard's side: its members simply never certify.
                                            debug!(core_id, filter = %hex::encode(&filter), channel,
                                                "suppressing shard CW publish — coverage halt active");
                                            continue;
                                        }
                                        debug!(core_id, filter = %hex::encode(&filter), channel, bytes = bytes.len(),
                                            "publishing shard CW message");
                                        // A committee of one has nobody to send to: every
                                        // publish would fail and retry for half a minute, and a
                                        // lone Simplex host turns views quickly. A live run logged
                                        // about 230,000 such warnings in seventeen minutes.
                                        {
                                            use quil_types::consensus::ProverRegistry as _;
                                            use quil_types::store::ClockStore as _;
                                            let frame = drain_clock.get_latest_global_clock_frame().ok()
                                                .and_then(|f| f.header.map(|h| h.frame_number)).unwrap_or(0);
                                            // Exactly one member, and it is this node. An empty
                                            // answer (a registry still loading) is NOT a committee
                                            // of one: dropping a real committee's votes on it would
                                            // be far worse than a few wasted retries.
                                            if drain_registry.get_active_provers(&filter, frame)
                                                .is_ok_and(|members| members.len() == 1 && members[0].public_key == drain_pubkey)
                                            {
                                                continue;
                                            }
                                        }
                                        let p2p = drain_p2p.clone();
                                        let committee_peers = drain_committee_peers.clone();
                                        drain_spawner.detach("shard-cw-publish", async move {
                                            let topic = quil_engine::bitmasks::shard_cw_bitmask(&filter);
                                            // A message for one member names it, so a copy the
                                            // topic carries is dropped unread by the others.
                                            let payload = quil_engine::bitmasks::shard_cw_frame_for(channel, &bytes, &recipients);
                                            if !recipients.is_empty() {
                                                if super::direct_delivery::deliver_direct(&p2p, &committee_peers, &recipients, &topic, &payload).await {
                                                    return Ok(());
                                                }
                                                p2p.note_direct_fallback();
                                            }
                                            for attempt in 1..=8u32 {
                                                match p2p.publish(topic.clone(), payload.clone()).await {
                                                    Ok(()) => break,
                                                    Err(e) if retryable_cw_publish_failure(&e.to_string(), attempt) => {
                                                        let delay = std::time::Duration::from_millis(250u64.saturating_mul(1u64 << (attempt - 1)));
                                                        warn!(core_id, filter = %hex::encode(&filter), attempt, ?delay, error = %e,
                                                            "shard CW publish has no subscribed peers — retrying");
                                                        tokio::time::sleep(delay).await;
                                                    }
                                                    Err(e) => {
                                                        warn!(core_id, filter = %hex::encode(&filter), attempt, error = %e, "shard cw publish failed");
                                                        break;
                                                    }
                                                }
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
                                        // Keep a second handle for the asynchronous CW transport
                                        // readiness barrier below; the routing registry owns the
                                        // original handle.
                                        let ready_handle = handle.clone();
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
                                        if let Some(stores) = drain_worker_stores.read().get(&core_id).cloned() {
                                            drain_worker_app_states.write().insert(filter.clone(), stores);
                                        }
                                        // Subscribe BlossomSub to the four
                                        // per-shard bitmasks. Without these
                                        // subscriptions our mesh peers won't
                                        // forward shard traffic to us, so
                                        // peer votes / proposals / frames /
                                        // dispatches never reach the engine.
                                        let p2p = drain_p2p.clone();
                                        let filter_for_sub = filter.clone();
                                        let registry_for_sub = drain_registry.clone();
                                        let pubkey_for_sub = drain_pubkey.clone();
                                        let clock_for_sub = drain_clock.clone();
                                        drain_spawner.detach("shard-subscribe", async move {
                                            for topic in shard_topics(&filter_for_sub) {
                                                if let Err(e) = p2p.subscribe_confirmed(topic).await {
                                                    warn!(core_id, filter = %hex::encode(&filter_for_sub), error = %e,
                                                        "failed to install shard topic subscription");
                                                    return Ok(());
                                                }
                                            }
                                            // Subscribe the shard's commonware-simplex topic so
                                            // committee peers' votes/certs/blocks reach this engine.
                                            let cw_topic = quil_engine::bitmasks::shard_cw_bitmask(&filter_for_sub);
                                            if let Err(e) = p2p.subscribe_confirmed(cw_topic.clone()).await {
                                                warn!(core_id, filter = %hex::encode(&filter_for_sub), error = %e,
                                                    "failed to install shard CW topic subscription");
                                                return Ok(());
                                            }
                                            // This engine runs here: its committee may send it
                                            // resolver messages directly.
                                            p2p.allow_direct(cw_topic.clone()).await;
                                            let mut wait_logged = false;
                                            loop {
                                                match p2p.subscribed_peer_count(cw_topic.clone()).await {
                                                    Ok(peers) if peers > 0 => {
                                                        info!(core_id, filter = %hex::encode(&filter_for_sub), peers,
                                                            "shard CW transport ready; starting consensus engine");
                                                        ready_handle.set_cw_transport_ready();
                                                        break;
                                                    }
                                                    // A committee of one has no peer to wait for:
                                                    // it proposes and finalizes alone. Without this a
                                                    // shard's first, sole prover never started (a live
                                                    // run stranded a committed coin behind it).
                                                    Ok(_) if {
                                                        use quil_types::consensus::ProverRegistry as _;
                                                        use quil_types::store::ClockStore as _;
                                                        let frame = clock_for_sub.get_latest_global_clock_frame().ok()
                                                            .and_then(|f| f.header.map(|h| h.frame_number)).unwrap_or(0);
                                                        registry_for_sub.get_active_provers(&filter_for_sub, frame)
                                                            .is_ok_and(|members| members.len() == 1 && members[0].public_key == pubkey_for_sub)
                                                    } => {
                                                        info!(core_id, filter = %hex::encode(&filter_for_sub),
                                                            "sole committee member; starting consensus without a CW peer");
                                                        ready_handle.set_cw_transport_ready();
                                                        break;
                                                    }
                                                    Ok(_) if !wait_logged => {
                                                        wait_logged = true;
                                                        info!(core_id, filter = %hex::encode(&filter_for_sub),
                                                            "waiting for a subscribed CW peer before starting consensus");
                                                    }
                                                    Ok(_) => {}
                                                    Err(e) => warn!(core_id, filter = %hex::encode(&filter_for_sub), error = %e,
                                                        "CW transport readiness check failed"),
                                                }
                                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                            }
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
                                        drain_worker_app_states.write().remove(&filter);
                                        let p2p = drain_p2p.clone();
                                        let filter_for_sub = filter.clone();
                                        let engines = drain_shard_engines.clone();
                                        drain_spawner.detach("shard-unsubscribe", async move {
                                            if !engines.read().contains_key(&filter_for_sub) {
                                                p2p.revoke_direct(quil_engine::bitmasks::shard_cw_bitmask(&filter_for_sub)).await;
                                            }
                                            // Decided when this runs, not when the engine
                                            // left: a sibling or the same filter may have
                                            // registered since. A registration racing the
                                            // unsubscribe is caught by the second look.
                                            let releasable = |topic: &Vec<u8>| {
                                                releasable_shard_topics(&filter_for_sub, engines.read().keys()).contains(topic)
                                            };
                                            for topic in shard_topics(&filter_for_sub) {
                                                if !releasable(&topic) {
                                                    continue;
                                                }
                                                p2p.unsubscribe(topic.clone()).await;
                                                if !releasable(&topic) {
                                                    let _ = p2p.subscribe_confirmed(topic).await;
                                                }
                                            }
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


    /// Reopen a worker store a test just dropped. The one-shot staged-frame
    /// cleanup the builder starts holds its own handle until it finishes, so
    /// under load the store can still be locked for a moment.
    fn reopen(path: &std::path::Path) -> Arc<quil_store::RocksDb> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match quil_store::RocksDb::open(path) {
                Ok(db) => return Arc::new(db),
                Err(error) if std::time::Instant::now() < deadline && error.to_string().contains("lock") => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) => panic!("reopen worker store: {error}"),
            }
        }
    }

    #[test]
    fn a_shard_leaving_keeps_the_topics_other_registered_shards_need() {
        let app = [0x11u8; 32];
        let root = app.to_vec();
        let left = quil_forest::encode_shard_bit_path(&app, &[false]);
        let right = quil_forest::encode_shard_bit_path(&app, &[true]);
        let submission = quil_engine::bitmasks::app_prover_bitmask(&root);
        assert_eq!(submission, quil_engine::bitmasks::app_prover_bitmask(&left), "one submission topic per application");

        // The split-away root leaves while a child still runs: the child's
        // submission topic stays, the root's own topics go.
        let released = releasable_shard_topics(&root, [&left]);
        assert!(!released.contains(&submission));
        assert_eq!(released.len(), 3);
        // The application's last shard releases everything.
        assert_eq!(releasable_shard_topics(&right, std::iter::empty()).len(), 4);
        // A filter registered again before the release runs keeps all of it.
        assert!(releasable_shard_topics(&left, [&left, &right]).is_empty());
    }

    /// A thread worker's CRDT can be forked for private execution, before and
    /// after a restart: its size accounting is initialized when it is built.
    /// Without that, every fork was refused and a shard whose selected parent
    /// was notarized but not finalized wedged.
    #[test]
    fn a_thread_worker_crdt_can_be_forked_for_private_execution() {
        let dir = tempfile::tempdir().unwrap();
        let limits = quil_hypergraph::ExecutionForkLimits {
            overlay: quil_forest::OverlayLimits {
                max_delta_bytes: 1 << 20,
                max_delta_entries: 10_000,
                max_record_bytes: 1 << 20,
                max_read_bytes: 1 << 24,
                max_read_operations: 100_000,
                max_cursors: 16,
            },
            max_metadata_entries: 10_000,
            max_metadata_bytes: 1 << 20,
        };
        let fork = |crdt: &quil_hypergraph::HypergraphCrdt| {
            crdt.lock_execution_capture().unwrap().fork(limits, |overlay| {
                Ok(Arc::new(quil_store::OverlayHypergraphStore::new(overlay)) as Arc<dyn quil_types::store::HypergraphStore>)
            }).map(|fork| fork.overlay.close())
        };
        let app = quil_execution::domains::QUIL_TOKEN;
        {
            let db = reopen(dir.path());
            let crdt = build_thread_worker_hypergraph(&db, Arc::new(quil_tries::ShaInclusionProver), false);
            fork(&crdt).expect("a fresh worker CRDT forks");
            crdt.add_vertex(&quil_hypergraph::Location { app_address: app, data_address: [1; 32] }, &[7; 64]).unwrap();
            crdt.commit(1).unwrap();
            fork(&crdt).expect("a worker CRDT with committed state forks");
        }
        let db = reopen(dir.path());
        let crdt = build_thread_worker_hypergraph(&db, Arc::new(quil_tries::ShaInclusionProver), false);
        fork(&crdt).expect("a restarted worker CRDT forks");
    }

    #[test]
    fn cw_publish_retry_is_limited_to_missing_topic_peers() {
        assert!(retryable_cw_publish_failure("blossomsub publish failed: NoPeersSubscribedToTopic", 1));
        assert!(retryable_cw_publish_failure("NoPeersSubscribedToTopic", 7));
        assert!(!retryable_cw_publish_failure("NoPeersSubscribedToTopic", 8));
        assert!(!retryable_cw_publish_failure("p2p command channel closed", 1));
    }

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
            let db = reopen(dir.path());
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
        let db = reopen(dir.path());
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

    /// A restart past the unified cutover asks for the conversion again. It
    /// must not rebuild the tree: the rebuild committed at version zero, below
    /// the blobs the store already held, and reads take the greatest version,
    /// so every record updated afterwards read back its pre-restart value.
    #[test]
    fn a_restarted_worker_keeps_reading_what_it_writes_after_the_cutover() {
        let dir = tempfile::tempdir().unwrap();
        let record = quil_hypergraph::Location { app_address: [0x2a; 32], data_address: [0x07; 32] };
        let filter = record.app_address.to_vec();
        let open = || {
            let db = reopen(dir.path());
            let crdt = build_thread_worker_hypergraph(&db, Arc::new(quil_tries::ShaInclusionProver), false);
            let hg = quil_store::RocksHypergraphStore::new(db.inner());
            (db, crdt, hg)
        };
        let head = |hg: &quil_store::RocksHypergraphStore| {
            quil_forest::Forest::with_namespace(hg.raw_db(), quil_store::FOREST_NAMESPACE.to_vec())
                .read_head_version(&record.app_address, quil_forest::Phase::VertexAdds)
                .unwrap()
        };
        {
            let (_db, crdt, hg) = open();
            assert!(unified_cutover_conversion(&hg, &filter));
            crdt.set_unified_tree(true);
            for (frame, value) in [b"count 1", b"count 2", b"count 3", b"count 4"].into_iter().enumerate() {
                crdt.add_vertex(&record, value).unwrap();
                crdt.commit(frame as u64 + 1).unwrap();
            }
        }
        for (restart, value) in [b"count 5", b"count 6"].into_iter().enumerate() {
            let (db, crdt, hg) = open();
            let before = head(&hg);
            // The second restart also covers a store an earlier build converted:
            // its tree exists, but no marker records it.
            if restart == 1 {
                db.inner().delete(unified_cutover_marker_key(&record.app_address)).unwrap();
            }
            assert!(unified_cutover_conversion(&hg, &filter));
            assert_eq!(head(&hg), before, "restart {restart} rebuilt the unified tree");
            crdt.set_unified_tree(true);
            crdt.add_vertex(&record, value).unwrap();
            crdt.commit(10 + restart as u64).unwrap();
            assert_eq!(
                crdt.get_vertex_data_checked(&record).unwrap().as_deref(),
                Some(&value[..]),
                "restart {restart}: an update after the restart must be read back"
            );
        }
    }

    /// A first conversion over versioned blobs written before it (no app tree
    /// yet) commits above them, so the vertex's next write is the one read.
    #[test]
    fn a_first_conversion_commits_above_existing_blob_versions() {
        let dir = tempfile::tempdir().unwrap();
        let record = quil_hypergraph::Location { app_address: [0x2b; 32], data_address: [0x07; 32] };
        let db = reopen(dir.path());
        let crdt = build_thread_worker_hypergraph(&db, Arc::new(quil_tries::ShaInclusionProver), false);
        let hg = quil_store::RocksHypergraphStore::new(db.inner());
        let shard_key = quil_types::store::ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(&record.app_address, 256, 3),
            l2: record.app_address,
        };
        let txn = quil_types::store::HypergraphStore::new_transaction(&hg, false).unwrap();
        quil_types::store::HypergraphStore::save_vertex_underlying_versioned(
            &hg, txn.as_ref(), "vertex", "adds", &shard_key, &record.to_id(), b"before the cutover", 9,
        ).unwrap();
        txn.commit().unwrap();

        assert!(unified_cutover_conversion(&hg, &record.app_address));
        crdt.set_unified_tree(true);
        crdt.add_vertex(&record, b"after the cutover").unwrap();
        crdt.commit(1).unwrap();
        assert_eq!(
            crdt.get_vertex_data_checked(&record).unwrap().as_deref(),
            Some(&b"after the cutover"[..]),
        );
    }
}

/// A historical-committee source for engines that resolves the node's
/// service when it is called: engines start before the archive sync has
/// built it.
pub(crate) fn historical_committee_source(
    cell: Arc<std::sync::OnceLock<Arc<super::historical_committees::HistoricalCommittees>>>,
) -> quil_engine::historical_committee::HistoricalCommitteeSource {
    Arc::new(move |filter: Vec<u8>, anchor: u64| {
        let service = cell.get().cloned();
        Box::pin(async move {
            match service {
                Some(service) => service.committees(&filter, anchor).await,
                None => Err(quil_types::error::QuilError::ExecutionUnavailable(
                    "historical committees not ready".into(),
                )),
            }
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = quil_types::error::Result<Vec<Vec<Vec<u8>>>>> + Send>>
    })
}
