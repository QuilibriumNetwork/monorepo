//! Worker-only node — runs on a separate machine and connects back
//! to the master via gRPC for shard consensus.
//!
//! Usage: `quil-node --core=N --config /path/to/config`
//!
//! The worker:
//! 1. Starts a gRPC server (DataIPCService) for master commands
//! 2. Connects to master's gRPC endpoint for message streaming
//! 3. Runs AppConsensusEngine when assigned a shard via Respawn
//! 4. Monitors parent process and exits if master dies

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tracing::{error, info, warn};

use quil_types::consensus::ProverRegistry;
use quil_types::crypto::FrameProver;
use quil_types::error::{QuilError, Result};
use quil_types::store::ClockStore;

use crate::app_engine::{AppConsensusEngine, AppEngineDeps, AppEngineHandle, AppEngineMessage};
use crate::message_collector::MessageCollector;

/// Async factory for the gRPC channel that the worker uses to stream
/// from the master. The worker spawns a reconnect loop and calls this
/// each time it needs a fresh channel. main.rs supplies an
/// implementation that wires up Quilibrium's mTLS scheme (Ed448
/// client cert + self-signed acceptor) since the master's listener
/// requires mTLS; a plaintext fallback is available for single-machine
/// dev setups.
pub type MasterChannelFactory = Arc<
    dyn Fn() -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = std::result::Result<
                            tonic::transport::Channel,
                            Box<dyn std::error::Error + Send + Sync>,
                        >,
                    > + Send,
            >,
        > + Send
        + Sync,
>;

/// Configuration for a worker-only node.
pub struct WorkerNodeConfig {
    /// This worker's core ID (1, 2, 3, ...).
    pub core_id: u32,
    /// Master's gRPC endpoint for message streaming (informational —
    /// used for log lines; the actual channel is built by
    /// `channel_factory`).
    pub master_endpoint: String,
    /// This worker's gRPC listen address (for Respawn commands).
    pub listen_addr: String,
    /// Parent process ID (for monitoring).
    pub parent_pid: Option<u32>,
    /// Builds a fresh gRPC channel to the master. main.rs wires this
    /// to a closure that uses quil-rpc's `build_quil_client_config` +
    /// `QuilTlsConnector` so the worker presents the same Ed448 cert
    /// shape the master's peer-gRPC listener requires. `None`
    /// disables the worker→master stream (worker still serves
    /// DataIPC; used in tests and during master-less bring-up).
    pub channel_factory: Option<MasterChannelFactory>,
}

/// Publish-side hook for the standalone worker's outbound traffic.
/// Today this is wired to the master's PubSubProxy; once each worker
/// runs its own libp2p instance with a synthetic peer key (per
/// `node/p2p/blossomsub.go` lines ~452-496), this will dispatch to
/// the worker's own p2p handle instead.
pub type PublishFn = Arc<
    dyn Fn(Vec<u8>, Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// A worker-only node that runs on a separate machine.
pub struct WorkerOnlyNode {
    config: WorkerNodeConfig,
    cancel: CancellationToken,
    /// Dependencies shared across engine respawns.
    clock_store: Arc<dyn ClockStore>,
    prover_registry: Arc<dyn ProverRegistry>,
    frame_prover: Arc<dyn FrameProver>,
    message_collector: Arc<MessageCollector>,
    fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager>,
    local_prover_address: Vec<u8>,
    local_bls_pubkey: Vec<u8>,
    bls_signer_factory: Arc<dyn Fn() -> Box<dyn quil_types::crypto::Signer> + Send + Sync>,
    reward_greedy: bool,
    /// Minimum Active prover count required before this worker's
    /// `AppLeaderProvider` will produce frames. Mainnet=3, testnet=1.
    /// See `AppLeaderProvider::min_active_provers_for_propose`.
    min_active_provers_for_propose: u64,
    /// Per-worker hypergraph CRDT — required for state_roots.
    hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// Per-worker execution manager — required for requests_root.
    execution_engine: Option<Arc<quil_execution::ExecutionEngineManager>>,
    /// Per-worker inclusion prover — required for requests_root tree
    /// commit.
    inclusion_prover: Option<Arc<dyn quil_types::crypto::InclusionProver>>,
    /// Current engine handle (set after Respawn).
    engine_handle: std::sync::Mutex<Option<AppEngineHandle>>,
    /// Channel for engine events back to the master stream.
    engine_event_tx: mpsc::UnboundedSender<crate::app_engine::AppEngineEvent>,
    /// Optional receiver for engine events — consumed by the
    /// publish pump when proxy mode is enabled. When `None`, the
    /// worker runs receive-only (legacy behavior).
    engine_event_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<crate::app_engine::AppEngineEvent>>>,
    /// Optional publish path (via master's PubSubProxy). When set,
    /// engine-produced messages are forwarded to the master for
    /// broadcast.
    publish_fn: Option<PublishFn>,
    /// Worker-owned libp2p handle. Present when running in
    /// standalone mode WITHOUT `engine.enable_master_proxy` — the
    /// worker joins the mesh directly with a synthetic peer ID, and
    /// `respawn` toggles per-shard bitmask subscriptions on it
    /// without needing the master.
    worker_p2p: Option<Arc<quil_p2p::P2PHandle>>,
    /// Currently-subscribed shard bitmasks on the worker-owned p2p.
    /// Tracked so a Respawn that swaps filters drops the old
    /// subscriptions before adding new ones.
    active_shard_subscriptions: std::sync::Mutex<Vec<Vec<u8>>>,
    /// Worker-local mirror of the master's coverage-halt verdict
    /// (set via the `SetHalted` IPC RPC). The publish pump consults
    /// this to drop in-flight FrameProduced / VoteProduced /
    /// TimeoutProduced events that the engine emitted just before
    /// receiving its own `set_halted(true)`.
    local_halted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Syncer for the global prover tree. Used before materializing
    /// frames whose `ProverTreeCommitment` mismatches the worker's
    /// local root. Without this, remote workers start with an empty
    /// CRDT and can't resolve leader rotation or verify FrameHeaders.
    prover_tree_syncer: Option<Arc<dyn crate::prover_tree_syncer::ProverTreeSyncer>>,
    /// Cooldown frame to avoid sync-storms: after a sync attempt,
    /// skip further attempts until frame_number >= cooldown_until.
    sync_cooldown_until: std::sync::atomic::AtomicU64,
}

impl WorkerOnlyNode {
    pub fn new(
        config: WorkerNodeConfig,
        clock_store: Arc<dyn ClockStore>,
        prover_registry: Arc<dyn ProverRegistry>,
        frame_prover: Arc<dyn FrameProver>,
        message_collector: Arc<MessageCollector>,
        fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager>,
        local_prover_address: Vec<u8>,
        local_bls_pubkey: Vec<u8>,
        bls_signer_factory: Arc<dyn Fn() -> Box<dyn quil_types::crypto::Signer> + Send + Sync>,
        reward_greedy: bool,
        min_active_provers_for_propose: u64,
    ) -> Self {
        let (engine_event_tx, engine_event_rx) = mpsc::unbounded_channel();
        Self {
            config,
            cancel: CancellationToken::new(),
            clock_store,
            prover_registry,
            frame_prover,
            message_collector,
            fee_manager,
            local_prover_address,
            local_bls_pubkey,
            bls_signer_factory,
            reward_greedy,
            min_active_provers_for_propose,
            hypergraph: None,
            execution_engine: None,
            inclusion_prover: None,
            engine_handle: std::sync::Mutex::new(None),
            engine_event_tx,
            engine_event_rx: std::sync::Mutex::new(Some(engine_event_rx)),
            publish_fn: None,
            worker_p2p: None,
            active_shard_subscriptions: std::sync::Mutex::new(Vec::new()),
            local_halted: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            prover_tree_syncer: None,
            sync_cooldown_until: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Attach the per-worker hypergraph CRDT, execution manager, and
    /// inclusion prover. These are required for byte-for-byte
    /// header parity (state_roots + requests_root) with Go peers.
    pub fn with_state_engines(
        mut self,
        hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
        execution_engine: Arc<quil_execution::ExecutionEngineManager>,
        inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    ) -> Self {
        self.hypergraph = Some(hypergraph);
        self.execution_engine = Some(execution_engine);
        self.inclusion_prover = Some(inclusion_prover);
        self
    }

    /// Attach a prover-tree syncer. Remote workers MUST have this
    /// wired — without it the CRDT starts empty and the worker can't
    /// resolve leader rotation or verify FrameHeaders.
    pub fn with_prover_tree_syncer(
        mut self,
        syncer: Arc<dyn crate::prover_tree_syncer::ProverTreeSyncer>,
    ) -> Self {
        self.prover_tree_syncer = Some(syncer);
        self
    }

    /// Supply a publish path (typically backed by a `ProxyPubSub`
    /// today, the worker's own libp2p once that port lands).
    /// Enables the worker to forward engine-produced messages
    /// upstream. Must be called before `run()`.
    pub fn with_publish_fn(mut self, publish: PublishFn) -> Self {
        self.publish_fn = Some(publish);
        self
    }

    /// Supply the worker's own libp2p handle (standalone, non-proxy
    /// mode). [`Self::respawn`] uses it to subscribe to per-shard
    /// bitmasks when the engine activates and to unsubscribe on
    /// teardown.
    pub fn with_p2p_handle(mut self, handle: Arc<quil_p2p::P2PHandle>) -> Self {
        self.worker_p2p = Some(handle);
        self
    }

    /// Run the worker node. Blocks until cancelled or parent dies.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let core_id = self.config.core_id;
        info!(
            core_id,
            master = %self.config.master_endpoint,
            listen = %self.config.listen_addr,
            "worker node starting"
        );

        // 0. Initial prover-tree sync from archive. Remote workers
        // start with an empty CRDT; without this sync the prover
        // registry is empty and the worker can't resolve leader
        // rotation or verify FrameHeaders. Mirrors Go's startup-time
        // `HyperSyncSelf` in `AppConsensusEngine.Start`.
        if let Some(syncer) = self.prover_tree_syncer.as_ref() {
            info!("performing initial prover-tree sync from archive");
            match syncer.sync_prover_tree(&[]).await {
                Ok(_converged) => {
                    if let Err(e) = self.prover_registry.refresh() {
                        warn!(error = %e, "prover registry refresh after initial sync failed");
                    }
                    info!("initial prover-tree sync complete");
                }
                Err(e) => {
                    warn!(error = %e, "initial prover-tree sync failed — worker may have stale/empty prover state");
                }
            }
        } else {
            warn!("no prover-tree syncer wired — worker will run with stale/empty prover state");
        }

        // 1. Start parent process monitor (if parent PID given)
        if let Some(parent_pid) = self.config.parent_pid {
            let cancel = self.cancel.clone();
            // TODO https://github.com/QuilibriumNetwork/monorepo/issues/563
            tokio::spawn(async move {
                monitor_parent_process(parent_pid, cancel).await;
            });
        }

        // 2. Start gRPC server for DataIPCService
        let ipc_service = DataIpcServiceImpl {
            worker: self.clone(),
        };
        let listen_addr = self.config.listen_addr.parse()
            .map_err(|e| QuilError::Internal(format!("bad listen addr: {}", e)))?;

        let server_cancel = self.cancel.clone();
        // TODO https://github.com/QuilibriumNetwork/monorepo/issues/563
        let server_handle = tokio::spawn(async move {
            info!("DataIPC gRPC server starting on {}", listen_addr);
            if let Err(e) = Server::builder()
                .add_service(
                    quil_types::proto::node::data_ipc_service_server::DataIpcServiceServer::new(
                        ipc_service,
                    ),
                )
                .serve_with_shutdown(listen_addr, server_cancel.cancelled())
                .await
            {
                error!(error = %e, "DataIPC gRPC server failed");
            }
        });

        // 3. Connect to master for message streaming. Skipped when no
        // factory is supplied (single-process tests, etc.).
        if let Some(factory) = self.config.channel_factory.clone() {
            let master_endpoint = self.config.master_endpoint.clone();
            let worker_ref = self.clone();
            let stream_cancel = self.cancel.clone();
            // TODO https://github.com/QuilibriumNetwork/monorepo/issues/563
            tokio::spawn(async move {
                stream_global_messages_from_master(
                    &master_endpoint,
                    factory,
                    worker_ref,
                    stream_cancel,
                ).await;
            });
        } else {
            info!("no channel factory — worker will not stream from master");
        }

        // 3b. Spawn the publish pump — if a PublishFn was supplied
        // (proxy mode), drain engine events and forward them to the
        // master's PubSubProxy on the appropriate bitmask.
        if let Some(publish) = self.publish_fn.clone() {
            let rx_opt = self.engine_event_rx.lock().unwrap().take();
            if let Some(mut rx) = rx_opt {
                let pump_cancel = self.cancel.clone();
                let halt_flag = self.local_halted.clone();
                // TODO https://github.com/QuilibriumNetwork/monorepo/issues/563
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = pump_cancel.cancelled() => break,
                            ev = rx.recv() => {
                                let Some(ev) = ev else { break; };
                                use crate::app_engine::AppEngineEvent::*;
                                // Suppress network publishes while the master
                                // reports a coverage halt. The engine's own
                                // halt gate handles new consensus, but an
                                // event already in flight can still hit this
                                // pump.
                                let halted = halt_flag.load(std::sync::atomic::Ordering::Relaxed);
                                match ev {
                                    FrameProduced { filter, frame_data, .. } => {
                                        if halted {
                                            tracing::debug!(filter = %hex::encode(&filter),
                                                "suppressing standalone shard frame publish — halt active");
                                            continue;
                                        }
                                        // Go publishes ONLY on the per-shard frame
                                        // bitmask (`appFilter`), NOT on GLOBAL_FRAME.
                                        // Publishing on GLOBAL_FRAME would broadcast
                                        // shard-specific frames to every mesh peer
                                        // (massive amplification for no benefit).
                                        publish(crate::bitmasks::shard_frame_bitmask(&filter), frame_data).await;
                                    }
                                    VoteProduced { filter, vote_data, .. } => {
                                        if halted {
                                            tracing::debug!(filter = %hex::encode(&filter),
                                                "suppressing standalone shard vote publish — halt active");
                                            continue;
                                        }
                                        // Per-shard only — Go uses
                                        // `[0x00] || appFilter`, NOT
                                        // `GLOBAL_CONSENSUS = [0x00]`.
                                        publish(crate::bitmasks::shard_consensus_bitmask(&filter), vote_data).await;
                                    }
                                    TimeoutProduced { filter, timeout_data, .. } => {
                                        if halted {
                                            tracing::debug!(filter = %hex::encode(&filter),
                                                "suppressing standalone shard timeout publish — halt active");
                                            continue;
                                        }
                                        publish(crate::bitmasks::shard_consensus_bitmask(&filter), timeout_data).await;
                                    }
                                    // Internal signals — no network publish.
                                    EquivocationDetected { .. }
                                    | Halted { .. }
                                    | AncestorSyncRequested { .. }
                                    | ParentSealed { .. }
                                    | ShardFrameFinalized { .. } => {
                                        // Proxy mode: master handles
                                        // GLOBAL_PROVER publish via its
                                        // own drain task; workers
                                        // forwarding through PubSubProxy
                                        // would double-publish.
                                    }
                                }
                            }
                        }
                    }
                    tracing::info!("worker publish pump stopped");
                });
            }
        }

        // 4. Wait for shutdown
        self.cancel.cancelled().await;
        info!(core_id, "worker node shutting down");
        server_handle.abort();
        Ok(())
    }

    /// Handle a Respawn command: tear down existing engine, start new
    /// one with the given filter.
    pub async fn respawn(&self, filter: Vec<u8>) -> Result<()> {
        let core_id = self.config.core_id;

        // Stop existing engine and drop subscriptions for the
        // outgoing filter.
        {
            let mut handle = self.engine_handle.lock().unwrap();
            *handle = None;
        }
        self.unsubscribe_active_shards().await;

        if filter.is_empty() {
            info!(core_id, "worker set to idle (no filter)");
            return Ok(());
        }

        info!(
            core_id,
            filter = hex::encode(&filter),
            "worker respawning with new filter"
        );

        // Create new AppConsensusEngine
        let deps = AppEngineDeps {
            clock_store: self.clock_store.clone(),
            prover_registry: self.prover_registry.clone(),
            frame_prover: self.frame_prover.clone(),
            message_collector: self.message_collector.clone(),
            fee_manager: self.fee_manager.clone(),
            local_prover_address: self.local_prover_address.clone(),
            local_bls_pubkey: self.local_bls_pubkey.clone(),
            bls_signer: (self.bls_signer_factory)(),
            reward_greedy: self.reward_greedy,
            min_active_provers_for_propose: self.min_active_provers_for_propose,
            // Cluster-mode worker: master mediates GLOBAL_PROVER via
            // gRPC. App shard finalize → master path needs separate
            // wiring; leave None until that's ported.
            coverage_publish: None,
            // Per-worker CRDT + execution manager + inclusion prover
            // for byte-for-byte header parity with Go: state_roots from
            // the worker's own hypergraph commit, requests_root from
            // the worker's own execution-manager Lock loop. Each
            // worker owns its own RocksDB store (per
            // `db.worker_path_prefix`) and therefore its own
            // CRDT/exec-mgr instance, mirroring Go's cluster mode.
            hypergraph: self.hypergraph.clone(),
            execution_engine: self.execution_engine.clone(),
            inclusion_prover: self.inclusion_prover.clone(),
            // Cluster mode: worker process owns its own DB and can
            // back this with a real KV handle once the wiring is in
            // place. Until then, fall through to the in-memory store.
            kv_db: None,
        };

        let (engine, handle) = AppConsensusEngine::new(
            core_id,
            filter.clone(),
            deps,
            self.engine_event_tx.clone(),
        );

        // Store handle for message routing
        {
            let mut h = self.engine_handle.lock().unwrap();
            *h = Some(handle);
        }

        // Run engine in background
        let bls_signer = (self.bls_signer_factory)();
        // TODO https://github.com/QuilibriumNetwork/monorepo/issues/563
        tokio::spawn(async move {
            engine.run(bls_signer).await;
        });

        // Subscribe to per-shard bitmasks on the worker's own p2p so
        // peer-published shard traffic flows in. No-op when running in
        // proxy mode (worker_p2p is None there).
        self.subscribe_to_shard_bitmasks(&filter).await;

        Ok(())
    }

    /// Subscribe to all four per-shard bitmasks for `filter` on the
    /// worker-owned p2p handle. Tracks the subscriptions so the next
    /// respawn can unsubscribe them.
    async fn subscribe_to_shard_bitmasks(&self, filter: &[u8]) {
        let Some(p2p) = self.worker_p2p.clone() else { return };
        let bitmasks = vec![
            crate::bitmasks::shard_frame_bitmask(filter),
            crate::bitmasks::shard_consensus_bitmask(filter),
            crate::bitmasks::shard_prover_bitmask(filter),
            crate::bitmasks::shard_dispatch_bitmask(filter),
        ];
        for bm in &bitmasks {
            p2p.subscribe(bm.clone()).await;
        }
        let mut tracked = self.active_shard_subscriptions.lock().unwrap();
        *tracked = bitmasks;
    }

    /// Inverse of [`Self::subscribe_to_shard_bitmasks`]. Idempotent —
    /// safe to call when nothing was previously subscribed.
    async fn unsubscribe_active_shards(&self) {
        let Some(p2p) = self.worker_p2p.clone() else { return };
        let previous: Vec<Vec<u8>> = {
            let mut tracked = self.active_shard_subscriptions.lock().unwrap();
            std::mem::take(&mut *tracked)
        };
        for bm in previous {
            p2p.unsubscribe(bm).await;
        }
    }

    /// Check whether the incoming global frame's
    /// `prover_tree_commitment` matches the worker's local CRDT root.
    /// On mismatch, fires the blocking sync. Called from the master
    /// stream receive loop BEFORE routing the message to the engine.
    async fn maybe_sync_before_global_frame(&self, data: &[u8]) {
        // Minimal decode: just need `prover_tree_commitment` from the
        // GlobalFrame header. Use proto decode — the master stream
        // sends proto-encoded frames.
        let frame: quil_types::proto::global::GlobalFrame = match prost::Message::decode(data) {
            Ok(f) => f,
            Err(_) => {
                // Also try canonical decode in case master sends that format.
                match crate::consensus_wire::decode_global_frame(data) {
                    Ok(f) => f,
                    Err(_) => return, // can't decode → skip check, route anyway
                }
            }
        };
        let Some(header) = frame.header.as_ref() else { return };
        let expected = &header.prover_tree_commitment;
        if expected.is_empty() {
            return;
        }
        // Compute local root from CRDT.
        let local_root = match self.hypergraph.as_ref() {
            Some(hg) => {
                use quil_types::store::ShardKey;
                let shard = ShardKey {
                    l1: [0u8; 3],
                    l2: [0xFFu8; 32], // GLOBAL_INTRINSIC_ADDRESS
                };
                hg.compute_shard_root("vertex", "adds", &shard)
            }
            None => Vec::new(),
        };
        if local_root.is_empty() || local_root == expected.as_slice() {
            return;
        }
        // Root mismatch — sync.
        self.perform_blocking_prover_sync(header.frame_number, expected).await;
    }

    /// Blocking prover-tree sync. Mirrors Go's
    /// `AppConsensusEngine.performBlockingGlobalHypersync`: calls the
    /// syncer up to 3 times with 500ms delay, checks convergence,
    /// refreshes the prover registry after each attempt. The 5-frame
    /// cooldown (`sync_cooldown_until`) prevents sync-storms.
    async fn perform_blocking_prover_sync(
        &self,
        frame_number: u64,
        expected_root: &[u8],
    ) {
        const MAX_ATTEMPTS: usize = 3;
        const RETRY_DELAY: Duration = Duration::from_millis(500);
        const COOLDOWN_FRAMES: u64 = 5;

        let cooldown = self.sync_cooldown_until.load(std::sync::atomic::Ordering::Relaxed);
        if frame_number < cooldown {
            tracing::debug!(
                frame = frame_number,
                cooldown_until = cooldown,
                "prover tree sync: cooldown active, skipping"
            );
            return;
        }

        let Some(syncer) = self.prover_tree_syncer.as_ref() else {
            warn!("prover tree sync: no syncer wired — worker will run with stale/empty prover tree");
            return;
        };

        info!(
            frame = frame_number,
            expected = hex::encode(expected_root),
            "performing blocking prover tree sync before materialization"
        );

        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(RETRY_DELAY).await;
                info!(
                    attempt = attempt + 1,
                    "retrying prover tree sync"
                );
            }
            match syncer.sync_prover_tree(expected_root).await {
                Ok(true) => {
                    info!(
                        attempt = attempt + 1,
                        "prover tree sync converged"
                    );
                    // Refresh the prover registry from the just-synced store.
                    if let Err(e) = self.prover_registry.refresh() {
                        warn!(error = %e, "prover registry refresh after sync failed");
                    }
                    self.sync_cooldown_until.store(
                        frame_number.saturating_add(COOLDOWN_FRAMES),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    return;
                }
                Ok(false) => {
                    warn!(
                        attempt = attempt + 1,
                        "prover tree sync completed but roots still diverge"
                    );
                }
                Err(e) => {
                    warn!(
                        attempt = attempt + 1,
                        error = %e,
                        "prover tree sync failed"
                    );
                }
            }
        }
        // All attempts exhausted. Set cooldown and move on — the next
        // frame will retry after the cooldown window.
        self.sync_cooldown_until.store(
            frame_number.saturating_add(COOLDOWN_FRAMES),
            std::sync::atomic::Ordering::Relaxed,
        );
        warn!(
            frame = frame_number,
            "prover tree sync did not converge after {MAX_ATTEMPTS} attempts"
        );
    }

    /// Route an incoming message from the master to the active engine.
    /// Bitmask dispatch:
    ///   - `[0x00, 0x00, 0x00, 0x00]` → global peer info
    ///   - `[0x00, 0x00, 0x00]`       → global prover
    ///   - `[0x00, 0x00]`             → global frame
    ///   - `[0x00]`                   → global consensus
    ///   - `shard_frame_bitmask(f)`     → Frame
    ///   - `shard_consensus_bitmask(f)` → Consensus
    ///   - `shard_prover_bitmask(f)`    → Prover
    ///   - `shard_dispatch_bitmask(f)`  → Dispatch
    pub fn route_message(&self, data: &[u8], bitmask: &[u8]) {
        let handle = {
            let guard = self.engine_handle.lock().unwrap();
            guard.clone()
        };
        let Some(h) = handle else { return };
        // Globals are detected by their fixed prefix-of-zeros shape.
        match bitmask {
            crate::bitmasks::GLOBAL_PEER_INFO => {
                h.send(AppEngineMessage::PeerInfo(data.to_vec()));
                return;
            }
            crate::bitmasks::GLOBAL_PROVER => {
                h.send(AppEngineMessage::Prover(data.to_vec()));
                return;
            }
            crate::bitmasks::GLOBAL_FRAME => {
                h.send(AppEngineMessage::GlobalFrame(data.to_vec()));
                return;
            }
            crate::bitmasks::GLOBAL_CONSENSUS => {
                h.send(AppEngineMessage::Consensus(data.to_vec()));
                return;
            }
            _ => {}
        }
        // Per-shard bitmask routing. Compare against the engine's
        // own filter — a message tagged with another shard's filter
        // would still be delivered to this engine but the engine's
        // app-address gate (`handle_app_shard_proposal` et al.)
        // drops it.
        let filter = &h.filter;
        if bitmask == crate::bitmasks::shard_frame_bitmask(filter).as_slice() {
            h.send(AppEngineMessage::Frame(data.to_vec()));
        } else if bitmask == crate::bitmasks::shard_consensus_bitmask(filter).as_slice() {
            h.send(AppEngineMessage::Consensus(data.to_vec()));
        } else if bitmask == crate::bitmasks::shard_prover_bitmask(filter).as_slice() {
            h.send(AppEngineMessage::Prover(data.to_vec()));
        } else if bitmask == crate::bitmasks::shard_dispatch_bitmask(filter).as_slice() {
            h.send(AppEngineMessage::Dispatch(data.to_vec()));
        }
        // Unknown bitmask shape — silently drop. Logging every drop
        // is noisy because the master fans out all peer pubsub to
        // every standalone worker; the worker only cares about its
        // own filter's bitmasks.
    }

    /// Stop the worker node.
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

// =====================================================================
// DataIPCService — gRPC server on the worker for master commands
// =====================================================================

struct DataIpcServiceImpl {
    worker: Arc<WorkerOnlyNode>,
}

#[tonic::async_trait]
impl quil_types::proto::node::data_ipc_service_server::DataIpcService
    for DataIpcServiceImpl
{
    async fn respawn(
        &self,
        request: tonic::Request<quil_types::proto::node::RespawnRequest>,
    ) -> std::result::Result<
        tonic::Response<quil_types::proto::node::RespawnResponse>,
        tonic::Status,
    > {
        let filter = request.into_inner().filter;
        match self.worker.respawn(filter).await {
            Ok(()) => Ok(tonic::Response::new(
                quil_types::proto::node::RespawnResponse {},
            )),
            Err(e) => Err(tonic::Status::internal(format!("respawn failed: {}", e))),
        }
    }

    async fn create_join_proof(
        &self,
        request: tonic::Request<quil_types::proto::node::CreateJoinProofRequest>,
    ) -> std::result::Result<
        tonic::Response<quil_types::proto::node::CreateJoinProofResponse>,
        tonic::Status,
    > {
        let req = request.into_inner();
        // Compute VDF proof on this worker's core
        let proof = vdf::wesolowski_solve_multi(
            2048,
            &req.challenge.try_into().unwrap_or([0u8; 32]),
            req.difficulty,
            &req.ids,
            req.prover_index,
        );
        Ok(tonic::Response::new(
            quil_types::proto::node::CreateJoinProofResponse { response: proof },
        ))
    }

    async fn set_halted(
        &self,
        request: tonic::Request<quil_types::proto::node::SetHaltedRequest>,
    ) -> std::result::Result<
        tonic::Response<quil_types::proto::node::SetHaltedResponse>,
        tonic::Status,
    > {
        let halted = request.into_inner().halted;
        // Forward to the local engine if one is running. A standalone
        // worker without an active engine has nothing to gate; the call
        // becomes a no-op until the next Respawn boots the engine.
        let handle = self.worker.engine_handle.lock().unwrap().clone();
        if let Some(h) = handle {
            h.set_halted(halted);
        }
        // Mirror the flag onto the worker's local view so any
        // local publish path (publish_fn pump) can also gate on it.
        self.worker
            .local_halted
            .store(halted, std::sync::atomic::Ordering::Relaxed);
        Ok(tonic::Response::new(
            quil_types::proto::node::SetHaltedResponse {},
        ))
    }
}

// =====================================================================
// Master message streaming — worker connects to master
// =====================================================================

async fn stream_global_messages_from_master(
    master_endpoint: &str,
    channel_factory: MasterChannelFactory,
    worker: Arc<WorkerOnlyNode>,
    cancel: CancellationToken,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);

    loop {
        if cancel.is_cancelled() {
            return;
        }

        info!(endpoint = master_endpoint, "connecting to master for message stream");

        match channel_factory().await {
            Ok(channel) => {
                info!("connected to master, starting message stream");
                backoff = Duration::from_secs(1); // reset backoff

                let mut client = quil_types::proto::global::global_service_client::GlobalServiceClient::new(channel);
                let request = tonic::Request::new(
                    quil_types::proto::global::StreamGlobalMessagesRequest {},
                );

                match client.stream_global_messages(request).await {
                    Ok(response) => {
                        let mut stream = response.into_inner();
                        loop {
                            tokio::select! {
                                msg = stream.message() => {
                                    match msg {
                                        Ok(Some(resp)) => {
                                            // For GLOBAL_FRAME messages, check the
                                            // prover-tree root before routing. If
                                            // mismatched, do a blocking sync so the
                                            // worker's CRDT is current before the
                                            // engine materializes.
                                            if resp.bitmask.as_slice() == crate::bitmasks::GLOBAL_FRAME {
                                                worker.maybe_sync_before_global_frame(&resp.data).await;
                                            }
                                            worker.route_message(&resp.data, &resp.bitmask);
                                        }
                                        Ok(None) => {
                                            info!("master stream ended");
                                            break;
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "master stream error");
                                            break;
                                        }
                                    }
                                }
                                _ = cancel.cancelled() => return,
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to start message stream");
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to connect to master");
            }
        }

        // Reconnect with backoff
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = cancel.cancelled() => return,
        }
        backoff = (backoff * 2).min(max_backoff);
    }
}

// =====================================================================
// Parent process monitor — exit if master dies
// =====================================================================

async fn monitor_parent_process(parent_pid: u32, cancel: CancellationToken) {
    let check_interval = Duration::from_secs(5);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(check_interval) => {
                if !is_process_alive(parent_pid) {
                    error!(
                        parent_pid,
                        "parent process died, shutting down worker"
                    );
                    cancel.cancel();
                    // Give a moment for cleanup, then force exit
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    std::process::exit(1);
                }
            }
            _ = cancel.cancelled() => return,
        }
    }
}

/// Check if a process is still alive.
#[cfg(unix)]
fn is_process_alive(pid: u32) -> bool {
    // kill(pid, 0) checks if process exists without sending a signal
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[cfg(not(unix))]
fn is_process_alive(_pid: u32) -> bool {
    true // Can't check on non-Unix
}

// =====================================================================
// Helper: compute worker listen address from config
// =====================================================================

/// Compute the gRPC listen address for a worker from config. Always
/// returns a parseable `host:port` socket address — never a libp2p
/// multiaddr — so callers can `.parse::<SocketAddr>()` without
/// preprocessing.
///
/// Resolution order (decreasing preference):
///   1. `data_worker_stream_multiaddrs[core_id - 1]` if set. Accepts
///      either `host:port` directly or a libp2p multiaddr
///      `/ip4/HOST/tcp/PORT` (extracted into `HOST:PORT`).
///   2. `data_worker_base_listen_multiaddr` template with `%d` →
///      `data_worker_base_stream_port + (core_id - 1)`. Core 1 gets
///      `base_stream_port` itself.
///   3. Same as (2) but with the serde defaults for those two fields
///      (which is what you get when the config doesn't set them).
pub fn worker_listen_addr(
    core_id: u32,
    base_listen: &str,
    base_stream_port: u16,
    stream_multiaddrs: &[String],
) -> String {
    // Tier 1: explicit per-worker stream multiaddr.
    let idx = core_id.saturating_sub(1) as usize;
    if let Some(addr) = stream_multiaddrs.get(idx) {
        if !addr.is_empty() {
            if let Some(socket) = multiaddr_to_socket_addr(addr) {
                return socket;
            }
            return addr.clone();
        }
    }
    // Tier 2 / 3: construct from template. Core 1 → base_stream_port,
    // core 2 → base_stream_port + 1, etc. Use the template's `%d`
    // replacement so the host portion matches what the operator configured.
    let port = base_stream_port
        .saturating_add(core_id.saturating_sub(1).min(u16::MAX as u32) as u16);
    if base_listen.contains("%d") {
        // Template has `%d` — build a multiaddr, then extract `host:port`
        // so the return value is always a socket address (the caller
        // `.parse::<SocketAddr>()`s it).
        let ma = base_listen.replace("%d", &port.to_string());
        if let Some(socket) = multiaddr_to_socket_addr(&ma) {
            return socket;
        }
    }
    format!("0.0.0.0:{}", port)
}

/// Pull a `host:port` socket address out of a libp2p multiaddr like
/// `/ip4/10.0.0.1/tcp/32501` or `/ip6/::1/tcp/32501`. Returns `None`
/// for shapes we don't understand; callers fall back to using the
/// input verbatim.
pub fn multiaddr_to_socket_addr(ma: &str) -> Option<String> {
    if !ma.starts_with('/') {
        return None;
    }
    let parts: Vec<&str> = ma.trim_start_matches('/').split('/').collect();
    // Need at least: ipX, addr, tcp, port.
    if parts.len() < 4 {
        return None;
    }
    let host = match parts[0] {
        "ip4" => parts[1].to_string(),
        "ip6" => format!("[{}]", parts[1]),
        _ => return None,
    };
    if parts[2] != "tcp" && parts[2] != "udp" {
        return None;
    }
    let port = parts[3];
    Some(format!("{}:{}", host, port))
}

/// Compute the master's gRPC endpoint from config.
///
/// Uses `p2p.stream_listen_multiaddr` — on the worker's config in a
/// cluster setup, this points at the master's gRPC stream listener.
/// A host of `0.0.0.0` is rewritten to `127.0.0.1` so single-machine
/// (master+worker on the same host) layouts keep working unchanged.
///
/// Returns an `http://host:port` URL ready to pass to `tonic`.
pub fn master_grpc_endpoint(config: &quil_config::Config) -> String {
    // p2p.stream_listen_multiaddr defaults to /ip4/0.0.0.0/tcp/8340.
    let ma = config.p2p.stream_listen_multiaddr.trim();
    let default_port: u16 = 8340;
    if let Some(endpoint) = multiaddr_to_http_endpoint(ma, default_port) {
        return endpoint;
    }
    tracing::warn!(
        stream_listen = %ma,
        "p2p.stream_listen_multiaddr does not parse — falling back to localhost",
    );
    format!("http://127.0.0.1:{}", default_port)
}

/// Parse a multiaddr like `/ip4/10.0.0.5/tcp/32500` into
/// `http://10.0.0.5:32500`. Returns `None` if the address can't be
/// extracted. `0.0.0.0` is rewritten to `127.0.0.1` so single-machine
/// layouts (master listens on all interfaces) still resolve to a
/// dialable host. `default_port` is used only when the multiaddr is
/// missing a tcp/udp port component.
fn multiaddr_to_http_endpoint(ma: &str, default_port: u16) -> Option<String> {
    let parts: Vec<&str> = ma.split('/').filter(|s| !s.is_empty()).collect();
    let mut host: Option<String> = None;
    let mut port: Option<String> = None;
    let mut i = 0;
    while i + 1 < parts.len() {
        match parts[i] {
            "ip4" => host = Some(parts[i + 1].to_string()),
            "ip6" => host = Some(format!("[{}]", parts[i + 1])),
            "dns" | "dns4" | "dns6" => host = Some(parts[i + 1].to_string()),
            "tcp" | "udp" => port = Some(parts[i + 1].to_string()),
            _ => {}
        }
        i += 2;
    }
    let mut h = host?;
    if h == "0.0.0.0" {
        h = "127.0.0.1".to_string();
    } else if h == "[::]" {
        h = "[::1]".to_string();
    }
    let p = port.unwrap_or_else(|| default_port.to_string());
    Some(format!("http://{}:{}", h, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_listen_addr_from_explicit_multiaddr_extracts_socket() {
        // Multiaddr inputs are flattened to `host:port` so the caller
        // can `.parse::<SocketAddr>()` directly. Returning the raw
        // multiaddr (the previous behaviour) crashed workers at
        // startup with "invalid socket address syntax".
        let addrs = vec![
            "/ip4/10.0.0.1/tcp/32501".to_string(),
            "/ip4/10.0.0.2/tcp/32502".to_string(),
        ];
        assert_eq!(
            worker_listen_addr(1, "/ip4/0.0.0.0/tcp/%d", 32500, &addrs),
            "10.0.0.1:32501"
        );
        assert_eq!(
            worker_listen_addr(2, "/ip4/0.0.0.0/tcp/%d", 32500, &addrs),
            "10.0.0.2:32502"
        );
    }

    #[test]
    fn worker_listen_addr_passes_through_socket_form_unchanged() {
        let addrs = vec!["10.0.0.1:32501".to_string()];
        assert_eq!(
            worker_listen_addr(1, "/ip4/0.0.0.0/tcp/%d", 32500, &addrs),
            "10.0.0.1:32501"
        );
    }

    #[test]
    fn worker_listen_addr_handles_ipv6_multiaddr() {
        let addrs = vec!["/ip6/::1/tcp/32501".to_string()];
        assert_eq!(
            worker_listen_addr(1, "/ip4/0.0.0.0/tcp/%d", 32500, &addrs),
            "[::1]:32501"
        );
    }

    #[test]
    fn worker_listen_addr_from_base_port() {
        // core_id=1 gets base_stream_port itself; core_id=N gets
        // base_stream_port + (N-1).
        let addrs: Vec<String> = vec![];
        assert_eq!(
            worker_listen_addr(1, "/ip4/0.0.0.0/tcp/%d", 32500, &addrs),
            "0.0.0.0:32500"
        );
        assert_eq!(
            worker_listen_addr(3, "/ip4/0.0.0.0/tcp/%d", 32500, &addrs),
            "0.0.0.0:32502"
        );
    }

    #[test]
    fn worker_listen_addr_high_core_id_does_not_panic() {
        let addrs: Vec<String> = vec![];
        // core_id=168 → base + 167 = 32667
        let result = worker_listen_addr(168, "/ip4/0.0.0.0/tcp/%d", 32500, &addrs);
        assert_eq!(result, "0.0.0.0:32667");
        // Saturate near the top of u16.
        let result = worker_listen_addr(1000, "/ip4/0.0.0.0/tcp/%d", 65000, &addrs);
        assert_eq!(result, "0.0.0.0:65535");
    }

    fn config_with_stream(ma: &str) -> quil_config::Config {
        let mut c = quil_config::Config::default();
        c.p2p.stream_listen_multiaddr = ma.to_string();
        c
    }

    #[test]
    fn master_endpoint_rewrites_unspecified_v4_to_localhost() {
        // Single-machine: master listens on 0.0.0.0; the worker's
        // dial target must be 127.0.0.1.
        let c = config_with_stream("/ip4/0.0.0.0/tcp/8340");
        assert_eq!(master_grpc_endpoint(&c), "http://127.0.0.1:8340");
    }

    #[test]
    fn master_endpoint_cluster_uses_remote_master_ip() {
        // Cluster: worker's config has stream_listen_multiaddr pointed
        // at the master on a different machine.
        let c = config_with_stream("/ip4/10.0.0.5/tcp/8340");
        assert_eq!(master_grpc_endpoint(&c), "http://10.0.0.5:8340");
    }

    #[test]
    fn master_endpoint_honors_non_default_port() {
        let c = config_with_stream("/ip4/10.0.0.5/tcp/40000");
        assert_eq!(master_grpc_endpoint(&c), "http://10.0.0.5:40000");
    }

    #[test]
    fn master_endpoint_ipv6() {
        let c = config_with_stream("/ip6/::1/tcp/8340");
        assert_eq!(master_grpc_endpoint(&c), "http://[::1]:8340");
    }

    #[test]
    fn master_endpoint_ipv6_unspecified_rewritten_to_loopback() {
        // Multiaddrs encode IPv6 without brackets — the wire form is
        // /ip6/::/tcp/8340. The parser brackets it for the URL, and
        // the "all interfaces" sentinel `[::]` gets rewritten to the
        // loopback `[::1]` so single-machine layouts work.
        let c = config_with_stream("/ip6/::/tcp/8340");
        assert_eq!(master_grpc_endpoint(&c), "http://[::1]:8340");
    }

    #[test]
    fn master_endpoint_dns() {
        let c = config_with_stream("/dns4/master.local/tcp/8340");
        assert_eq!(master_grpc_endpoint(&c), "http://master.local:8340");
    }

    #[test]
    fn master_endpoint_falls_back_when_unparseable() {
        // Garbage falls back to localhost with a warn log rather than
        // panicking — the worker still starts and the operator sees
        // the misconfig in logs.
        let c = config_with_stream("not-a-multiaddr");
        assert_eq!(master_grpc_endpoint(&c), "http://127.0.0.1:8340");
    }
}
