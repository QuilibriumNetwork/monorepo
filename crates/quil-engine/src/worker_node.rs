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

/// Configuration for a worker-only node.
pub struct WorkerNodeConfig {
    /// This worker's core ID (1, 2, 3, ...).
    pub core_id: u32,
    /// Master's gRPC endpoint for message streaming.
    pub master_endpoint: String,
    /// This worker's gRPC listen address (for Respawn commands).
    pub listen_addr: String,
    /// Parent process ID (for monitoring).
    pub parent_pid: Option<u32>,
}

/// Handle to the master's PubSubProxy — used by a standalone worker
/// to publish engine-produced events (FrameProduced, VoteProduced,
/// TimeoutProduced) back into the p2p network. Wrapped in an
/// abstraction so this crate doesn't depend on `quil-rpc`.
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
    /// Current engine handle (set after Respawn).
    engine_handle: std::sync::Mutex<Option<AppEngineHandle>>,
    /// Channel for engine events back to the master stream.
    engine_event_tx: mpsc::Sender<crate::app_engine::AppEngineEvent>,
    /// Optional receiver for engine events — consumed by the
    /// publish pump when proxy mode is enabled. When `None`, the
    /// worker runs receive-only (legacy behavior).
    engine_event_rx: std::sync::Mutex<Option<mpsc::Receiver<crate::app_engine::AppEngineEvent>>>,
    /// Optional publish path (via master's PubSubProxy). When set,
    /// engine-produced messages are forwarded to the master for
    /// broadcast.
    publish_fn: Option<PublishFn>,
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
    ) -> Self {
        let (engine_event_tx, engine_event_rx) = mpsc::channel(256);
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
            engine_handle: std::sync::Mutex::new(None),
            engine_event_tx,
            engine_event_rx: std::sync::Mutex::new(Some(engine_event_rx)),
            publish_fn: None,
        }
    }

    /// Supply a publish path (typically backed by a `ProxyPubSub`).
    /// Enables the worker to forward engine-produced messages
    /// upstream. Must be called before `run()`.
    pub fn with_publish_fn(mut self, publish: PublishFn) -> Self {
        self.publish_fn = Some(publish);
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

        // 1. Start parent process monitor (if parent PID given)
        if let Some(parent_pid) = self.config.parent_pid {
            let cancel = self.cancel.clone();
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

        // 3. Connect to master for message streaming
        let master_endpoint = self.config.master_endpoint.clone();
        let worker_ref = self.clone();
        let stream_cancel = self.cancel.clone();
        tokio::spawn(async move {
            stream_global_messages_from_master(
                &master_endpoint,
                worker_ref,
                stream_cancel,
            ).await;
        });

        // 3b. Spawn the publish pump — if a PublishFn was supplied
        // (proxy mode), drain engine events and forward them to the
        // master's PubSubProxy on the appropriate bitmask.
        if let Some(publish) = self.publish_fn.clone() {
            let rx_opt = self.engine_event_rx.lock().unwrap().take();
            if let Some(mut rx) = rx_opt {
                let pump_cancel = self.cancel.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = pump_cancel.cancelled() => break,
                            ev = rx.recv() => {
                                let Some(ev) = ev else { break; };
                                use crate::app_engine::AppEngineEvent::*;
                                match ev {
                                    FrameProduced { frame_data, .. } => {
                                        publish(crate::bitmasks::GLOBAL_FRAME.to_vec(), frame_data).await;
                                    }
                                    VoteProduced { vote_data, .. } => {
                                        publish(crate::bitmasks::GLOBAL_CONSENSUS.to_vec(), vote_data).await;
                                    }
                                    TimeoutProduced { timeout_data, .. } => {
                                        publish(crate::bitmasks::GLOBAL_CONSENSUS.to_vec(), timeout_data).await;
                                    }
                                    // Internal signals — no network publish.
                                    EquivocationDetected { .. }
                                    | Halted { .. }
                                    | AncestorSyncRequested { .. }
                                    | ParentSealed { .. } => {}
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

        // Stop existing engine
        {
            let mut handle = self.engine_handle.lock().unwrap();
            *handle = None; // Drop the old handle
        }

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
        };

        let (engine, handle) = AppConsensusEngine::new(
            core_id,
            filter,
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
        tokio::spawn(async move {
            engine.run(bls_signer).await;
        });

        Ok(())
    }

    /// Route an incoming message from the master to the active engine.
    pub fn route_message(&self, data: &[u8], bitmask: &[u8]) {
        let handle = self.engine_handle.lock().unwrap();
        if let Some(ref h) = *handle {
            // Route based on bitmask type
            if bitmask.len() <= 1 {
                h.send(AppEngineMessage::GlobalFrame(data.to_vec()));
            } else if bitmask.len() <= 2 {
                h.send(AppEngineMessage::Frame(data.to_vec()));
            } else if bitmask.len() <= 3 {
                h.send(AppEngineMessage::Prover(data.to_vec()));
            } else if bitmask.len() <= 4 {
                h.send(AppEngineMessage::PeerInfo(data.to_vec()));
            } else {
                h.send(AppEngineMessage::Consensus(data.to_vec()));
            }
        }
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
}

// =====================================================================
// Master message streaming — worker connects to master
// =====================================================================

async fn stream_global_messages_from_master(
    master_endpoint: &str,
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

        match tonic::transport::Channel::from_shared(master_endpoint.to_string()) {
            Ok(channel_builder) => {
                match channel_builder.connect().await {
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
            }
            Err(e) => {
                warn!(error = %e, "invalid master endpoint");
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

/// Compute the gRPC listen address for a worker from config.
///
/// Uses `data_worker_stream_multiaddrs[core_id - 1]` if available,
/// otherwise computes from base: `base_port + core_id`.
pub fn worker_listen_addr(
    core_id: u32,
    _base_listen: &str,
    base_stream_port: u16,
    stream_multiaddrs: &[String],
) -> String {
    if let Some(addr) = stream_multiaddrs.get((core_id - 1) as usize) {
        return addr.clone();
    }
    // Compute from base
    let port = base_stream_port + core_id as u16;
    format!("0.0.0.0:{}", port)
}

/// Compute the master's gRPC endpoint from config.
///
/// Uses `data_worker_base_stream_port` as the master's gRPC port,
/// with the master address derived from the base listen multiaddr.
/// If the base multiaddr is `/ip4/0.0.0.0/tcp/%d`, the master
/// is on localhost. For remote clusters, the master address should
/// be explicitly configured.
pub fn master_grpc_endpoint(config: &quil_config::EngineConfig) -> String {
    // Extract host from data_worker_base_listen_multiaddr
    let host = config.data_worker_base_listen_multiaddr
        .split('/')
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "ip4" || w[0] == "ip6")
        .map(|w| w[1].to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    // Master's stream port (same as the base — workers offset from this)
    let port = config.data_worker_base_stream_port;

    // If host is 0.0.0.0, use localhost (workers connect to master)
    let resolved_host = if host == "0.0.0.0" { "127.0.0.1" } else { &host };
    format!("http://{}:{}", resolved_host, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_listen_addr_from_explicit_config() {
        let addrs = vec![
            "/ip4/10.0.0.1/tcp/32501".to_string(),
            "/ip4/10.0.0.2/tcp/32502".to_string(),
        ];
        assert_eq!(
            worker_listen_addr(1, "/ip4/0.0.0.0/tcp/%d", 32500, &addrs),
            "/ip4/10.0.0.1/tcp/32501"
        );
        assert_eq!(
            worker_listen_addr(2, "/ip4/0.0.0.0/tcp/%d", 32500, &addrs),
            "/ip4/10.0.0.2/tcp/32502"
        );
    }

    #[test]
    fn worker_listen_addr_from_base_port() {
        let addrs: Vec<String> = vec![];
        assert_eq!(
            worker_listen_addr(1, "/ip4/0.0.0.0/tcp/%d", 32500, &addrs),
            "0.0.0.0:32501"
        );
        assert_eq!(
            worker_listen_addr(3, "/ip4/0.0.0.0/tcp/%d", 32500, &addrs),
            "0.0.0.0:32503"
        );
    }
}
