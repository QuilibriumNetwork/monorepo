//! Remote worker manager — manages workers running on separate machines
//! via gRPC. Port of Go's `node/worker/manager.go` cluster mode.
//!
//! When `DataWorkerStreamMultiaddrs` is configured, the master uses
//! this instead of `ThreadWorkerManager` to manage remote workers.
//! Each remote worker runs as a separate `quil-node --core=N` process.
//!
//! Communication:
//! - Master → Worker: `Respawn(filter)` RPC to assign shards
//! - Worker → Master: `StreamGlobalMessages` to receive PubSub messages
//! - Worker → Master: `SubmitGlobalMessage` to publish messages

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::mpsc;
use tonic::transport::Channel;
use tracing::{info, warn};

use quil_types::error::{QuilError, Result};

use crate::worker::{WorkerInfo, WorkerManager};

/// gRPC endpoint for a remote worker.
#[derive(Debug, Clone)]
struct RemoteWorkerState {
    core_id: u32,
    /// gRPC endpoint address (e.g., "http://192.168.1.10:32501").
    endpoint: String,
    /// Currently assigned filter.
    filter: Vec<u8>,
    /// Last filter acknowledged by the worker's Respawn service. Public frame
    /// reads resolve against actual state, not allocator intent.
    active_filter: Vec<u8>,
    /// Frame number when a join proposal was submitted for this worker.
    pending_filter_frame: u64,
    /// Operator-set: skip this worker during auto-allocation.
    manually_managed: bool,
    /// Whether the worker's filter is fully active in the registry
    /// (allocation Status=Active or Paused). Mirrors Go's
    /// `WorkerInfo.Allocated` field.
    allocated: bool,
    /// gRPC channel (lazily connected).
    channel: Option<Channel>,
    /// Whether the worker is reachable.
    connected: bool,
    /// Monotonic assignment version used to discard superseded Respawn work.
    assignment_generation: u64,
    /// A Respawn (including an empty-filter deallocation) still needs an ack.
    respawn_pending: bool,
    /// Command payload is separate from desired assignment: a Joining worker is
    /// assigned a filter in manager state but commanded idle until activation.
    respawn_filter: Vec<u8>,
    /// Serializes Respawn RPCs for this core so A -> B cannot land as B -> A.
    respawn_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}
/// Manages workers running on remote machines via gRPC.
///
/// Implements the `WorkerManager` trait so it can be used as a
/// drop-in replacement for `ThreadWorkerManager`.
/// TLS domain name for the worker-channel leaf cert. MUST match
/// `quil_rpc::quil_tls::WORKER_CHANNEL_SAN` (duplicated to avoid a crate cycle —
/// quil-engine cannot depend on quil-rpc).
const WORKER_CHANNEL_SAN: &str = "quil-worker";

pub struct RemoteWorkerManager {
    /// Shared so background tasks spawned from `set_worker_filter`
    /// (which only has `&self`) can re-acquire the channel to issue
    /// the Respawn RPC after this method returns.
    workers: std::sync::Arc<Mutex<HashMap<u32, RemoteWorkerState>>>,
    /// Master's stream endpoint for workers to connect back.
    master_endpoint: String,
    /// Channel for receiving events from remote workers.
    event_tx: mpsc::Sender<RemoteWorkerEvent>,
    event_rx: Mutex<Option<mpsc::Receiver<RemoteWorkerEvent>>>,
    /// mTLS config for dialing workers, derived from the node's Falcon key
    /// (`quil_rpc::quil_tls::build_worker_channel_cert`). When set (cluster
    /// mode), the master presents the node leaf cert and verifies the worker's
    /// server cert against the node CA — so only node-key holders interoperate.
    /// `None` = plaintext (back-compat / tests).
    client_tls: Option<tonic::transport::ClientTlsConfig>,
}

/// Events from remote workers to the master.
#[derive(Debug)]
pub enum RemoteWorkerEvent {
    /// Worker produced a frame.
    FrameProduced {
        core_id: u32,
        filter: Vec<u8>,
        frame_number: u64,
        frame_data: Vec<u8>,
    },
    /// Worker connected.
    Connected { core_id: u32 },
    /// Worker disconnected.
    Disconnected { core_id: u32 },
    /// Worker submitted a message for global publishing.
    MessageSubmitted { data: Vec<u8>, bitmask: Vec<u8> },
}

impl RemoteWorkerManager {
    /// `worker_endpoints` maps core_id → gRPC endpoint string.
    /// These come from `config.engine.data_worker_stream_multiaddrs`.
    pub fn new(
        worker_endpoints: Vec<(u32, String)>,
        master_endpoint: String,
        channel_tls_pem: Option<(String, String, String)>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(256);
        // Build the client mTLS config from (ca, leaf, key) PEM once.
        let client_tls = channel_tls_pem.map(|(ca, leaf, key)| {
            tonic::transport::ClientTlsConfig::new()
                .ca_certificate(tonic::transport::Certificate::from_pem(ca))
                .identity(tonic::transport::Identity::from_pem(leaf, key))
                .domain_name(WORKER_CHANNEL_SAN)
        });
        let mut workers = HashMap::new();

        for (core_id, endpoint) in worker_endpoints {
            info!(
                core_id,
                endpoint = %endpoint,
                "registered remote worker"
            );
            workers.insert(core_id, RemoteWorkerState {
                core_id,
                endpoint,
                filter: Vec::new(),
                active_filter: Vec::new(),
                pending_filter_frame: 0,
                manually_managed: false,
                allocated: false,
                channel: None,
                connected: false,
                assignment_generation: 0,
                respawn_pending: false,
                respawn_filter: Vec::new(),
                respawn_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            });
        }

        Self {
            workers: std::sync::Arc::new(Mutex::new(workers)),
            master_endpoint,
            event_tx,
            event_rx: Mutex::new(Some(event_rx)),
            client_tls,
        }
    }

    /// Build from config. Parses `data_worker_stream_multiaddrs` into
    /// (core_id, endpoint) pairs. Core IDs start at 1.
    pub fn from_config(
        stream_multiaddrs: &[String],
        master_endpoint: String,
        channel_tls_pem: Option<(String, String, String)>,
    ) -> Self {
        let endpoints: Vec<(u32, String)> = stream_multiaddrs
            .iter()
            .enumerate()
            .map(|(i, addr)| {
                let core_id = (i + 1) as u32;
                // Convert multiaddr to gRPC endpoint.
                // Go uses /ip4/HOST/tcp/PORT format; we need http://HOST:PORT.
                let endpoint = multiaddr_to_http(addr);
                (core_id, endpoint)
            })
            .collect();
        Self::new(endpoints, master_endpoint, channel_tls_pem)
    }

    /// Take the event receiver (call once at startup).
    pub fn take_event_rx(&self) -> Option<mpsc::Receiver<RemoteWorkerEvent>> {
        self.event_rx.lock().unwrap().take()
    }

    /// Connect to any registered workers that are NOT already connected. Safe to
    /// poll on an interval: workers with a live channel are skipped (no redundant
    /// reconnect / duplicate deferred-Respawn), so it only acts on the initial
    /// connect or after a disconnect clears the channel.
    pub async fn connect_all(&self) {
        let (endpoints, pending_connected): (Vec<(u32, String)>, Vec<(u32, u64)>) = {
            let workers = self.workers.lock().unwrap();
            let endpoints = workers
                .values()
                .filter(|w| w.channel.is_none())
                .map(|w| (w.core_id, w.endpoint.clone()))
                .collect();
            let pending = workers
                .values()
                .filter(|w| w.channel.is_some() && w.respawn_pending)
                .map(|w| (w.core_id, w.assignment_generation))
                .collect();
            (endpoints, pending)
        };

        for (core_id, endpoint) in endpoints {
            match connect_to_worker(&endpoint, self.client_tls.as_ref()).await {
                Ok(channel) => {
                    let pending_generation = {
                        let mut workers = self.workers.lock().unwrap();
                        if let Some(w) = workers.get_mut(&core_id) {
                            w.channel = Some(channel.clone());
                            w.connected = true;
                            if w.respawn_pending {
                                Some(w.assignment_generation)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };
                    info!(core_id, endpoint = %endpoint, "connected to remote worker");
                    let _ = self
                        .event_tx
                        .send(RemoteWorkerEvent::Connected { core_id })
                        .await;
                    if let Some(generation) = pending_generation {
                        Self::apply_pending_respawn(self.workers.clone(), core_id, generation)
                            .await;
                    }
                }
                Err(e) => {
                    warn!(
                        core_id,
                        endpoint = %endpoint,
                        error = %e,
                        "failed to connect to remote worker"
                    );
                }
            }
        }

        // A server-side failure need not tear down the tonic channel. Retry the
        // latest pending generation on the manager's regular connect poll.
        for (core_id, generation) in pending_connected {
            Self::apply_pending_respawn(self.workers.clone(), core_id, generation).await;
        }
    }

    /// Apply one assignment version after taking the per-core command lock.
    /// The generation check coalesces queued assignments, while the lock makes
    /// an already-in-flight A assignment finish before the newer B assignment.
    async fn apply_pending_respawn(
        workers: std::sync::Arc<Mutex<HashMap<u32, RemoteWorkerState>>>,
        core_id: u32,
        generation: u64,
    ) {
        let command_lock = {
            let workers = workers.lock().unwrap();
            workers
                .get(&core_id)
                .map(|worker| worker.respawn_lock.clone())
        };
        let Some(command_lock) = command_lock else {
            return;
        };
        let _command_guard = command_lock.lock().await;

        let command = {
            let workers = workers.lock().unwrap();
            workers.get(&core_id).and_then(|worker| {
                (worker.assignment_generation == generation && worker.respawn_pending)
                    .then(|| (worker.respawn_filter.clone(), worker.channel.clone()))
            })
        };
        let Some((filter, Some(channel))) = command else {
            return;
        };

        let mut client =
            quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(channel);
        let request = tonic::Request::new(quil_types::proto::node::RespawnRequest {
            filter: filter.clone(),
        });
        match tokio::time::timeout(std::time::Duration::from_secs(10), client.respawn(request))
            .await
        {
            Ok(Ok(_)) => {
                let mut workers = workers.lock().unwrap();
                if let Some(worker) = workers.get_mut(&core_id) {
                    // Even a superseded command changed the worker's actual
                    // state. A queued newer generation will update this again
                    // after its own acknowledgement.
                    worker.active_filter = filter.clone();
                    if worker.assignment_generation == generation {
                        worker.respawn_pending = false;
                    }
                }
                info!(
                    core_id,
                    filter = hex::encode(&filter),
                    generation,
                    "remote worker Respawn acknowledged"
                );
            }
            Ok(Err(error)) => warn!(
                core_id,
                filter = hex::encode(&filter),
                generation,
                %error,
                "remote worker Respawn RPC failed"
            ),
            Err(_) => warn!(
                core_id,
                filter = hex::encode(&filter),
                generation,
                "remote worker Respawn RPC timed out"
            ),
        }
    }

    /// Send a SetHalted command to every connected remote worker.
    /// Fire-and-forget per-worker — a failure on one doesn't abort
    /// the others. Mirrors the in-process broadcaster's behavior of
    /// pushing the flag to every active engine regardless of
    /// reachability.
    pub async fn broadcast_set_halted(&self, halted: bool) {
        let channels: Vec<(u32, Channel)> = {
            let workers = self.workers.lock().unwrap();
            workers
                .iter()
                .filter_map(|(&core_id, w)| w.channel.clone().map(|c| (core_id, c)))
                .collect()
        };
        for (core_id, channel) in channels {
            let mut client = quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(channel);
            let request = tonic::Request::new(
                quil_types::proto::node::SetHaltedRequest { halted },
            );
            match client.set_halted(request).await {
                Ok(_) => {
                    info!(core_id, halted, "remote worker SetHalted ack");
                }
                Err(e) => {
                    warn!(core_id, error = %e, halted, "remote worker SetHalted failed");
                }
            }
        }
    }

    /// Send a Respawn command to a remote worker via gRPC.
    pub async fn send_respawn(&self, core_id: u32, filter: &[u8]) -> Result<()> {
        let generation = {
            let mut workers = self.workers.lock().unwrap();
            let worker = workers.get_mut(&core_id).ok_or_else(|| {
                QuilError::InvalidArgument(format!("no remote worker with core_id {core_id}"))
            })?;
            if worker.channel.is_none() {
                return Err(QuilError::Internal(format!(
                    "worker {core_id} not connected"
                )));
            }
            worker.filter = filter.to_vec();
            worker.assignment_generation = worker.assignment_generation.wrapping_add(1);
            worker.respawn_pending = true;
            worker.respawn_filter = filter.to_vec();
            worker.assignment_generation
        };
        Self::apply_pending_respawn(self.workers.clone(), core_id, generation).await;
        let still_pending = self
            .workers
            .lock()
            .unwrap()
            .get(&core_id)
            .is_some_and(|worker| {
                worker.assignment_generation == generation && worker.respawn_pending
            });
        if still_pending {
            Err(QuilError::Internal(format!(
                "worker {core_id} Respawn was not acknowledged"
            )))
        } else {
            Ok(())
        }
    }

    /// Proxy an app-shard frame read to the connected worker assigned to
    /// `filter`. The worker validates its actual active filter, so desired
    /// manager state cannot expose an old shard during a failed/racing Respawn.
    pub async fn get_app_shard_frame(
        &self,
        filter: &[u8],
        frame_number: u64,
    ) -> std::result::Result<Option<quil_types::proto::global::AppShardFrame>, tonic::Status> {
        enum Route {
            Active(u32, Option<Channel>),
            Pending(u32),
            Missing,
        }
        let route = {
            let workers = self.workers.lock().unwrap();
            match workers.values().find(|worker| worker.filter == filter) {
                Some(worker) if worker.active_filter == filter && !worker.respawn_pending => {
                    Route::Active(worker.core_id, worker.channel.clone())
                }
                Some(worker) if worker.respawn_pending && worker.respawn_filter == filter => {
                    Route::Pending(worker.core_id)
                }
                _ => Route::Missing,
            }
        };
        let (core_id, channel) = match route {
            Route::Active(core_id, channel) => (core_id, channel),
            Route::Pending(core_id) => {
                return Err(tonic::Status::unavailable(format!(
                    "worker {core_id} shard assignment is pending"
                )))
            }
            Route::Missing => return Ok(None),
        };
        let Some(channel) = channel else {
            return Err(tonic::Status::unavailable(format!(
                "worker {core_id} assigned to shard is not connected"
            )));
        };

        let mut client =
            quil_types::proto::global::app_shard_service_client::AppShardServiceClient::new(
                channel,
            )
            .max_decoding_message_size(64 * 1024 * 1024)
            .max_encoding_message_size(64 * 1024 * 1024);
        let request = tonic::Request::new(quil_types::proto::global::GetAppShardFrameRequest {
            filter: filter.to_vec(),
            frame_number,
        });
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.get_app_shard_frame(request),
        )
        .await
        {
            Ok(Ok(response)) => Ok(response.into_inner().frame),
            Ok(Err(status)) if status.code() == tonic::Code::NotFound => Ok(None),
            Ok(Err(status)) => Err(tonic::Status::new(
                status.code(),
                format!(
                    "worker {core_id} app-shard read failed: {}",
                    status.message()
                ),
            )),
            Err(_) => Err(tonic::Status::deadline_exceeded(format!(
                "worker {core_id} app-shard read timed out"
            ))),
        }
    }

    /// Number of registered workers.
    pub fn worker_count(&self) -> usize {
        self.workers.lock().unwrap().len()
    }

    /// Master endpoint that workers connect to.
    pub fn master_endpoint(&self) -> &str {
        &self.master_endpoint
    }
}

impl WorkerManager for RemoteWorkerManager {
    fn set_worker_filter(&self, core_id: u32, filter: &[u8], start_consensus: bool) -> Result<()> {
        let (connected, generation) = {
            let mut workers = self.workers.lock().unwrap();
            if let Some(w) = workers.get_mut(&core_id) {
                w.filter = filter.to_vec();
                w.assignment_generation = w.assignment_generation.wrapping_add(1);
                // Every assignment transition is a real command. Joining keeps
                // the desired filter but commands the worker idle, guaranteeing
                // an outgoing engine cannot survive until the new allocation is
                // activated.
                w.respawn_pending = true;
                w.respawn_filter = if start_consensus {
                    filter.to_vec()
                } else {
                    Vec::new()
                };
                (w.channel.is_some(), w.assignment_generation)
            } else {
                return Err(QuilError::InvalidArgument(format!(
                    "no remote worker with core_id {}",
                    core_id
                )));
            }
        };

        if !connected {
            // Worker hasn't connected yet. The next `connect_all` /
            // reconnect cycle is responsible for re-issuing the
            // Respawn once the channel comes up.
            info!(
                core_id,
                filter = hex::encode(filter),
                "remote worker not yet connected — Respawn deferred"
            );
            return Ok(());
        }

        // Fire the Respawn RPC. set_worker_filter is sync but invoked
        // from async contexts; spawn the call so this returns
        // immediately and the lifecycle loop doesn't block on a
        // potentially slow worker.
        let workers = self.workers.clone();
        tokio::spawn(async move {
            Self::apply_pending_respawn(workers, core_id, generation).await;
        });
        Ok(())
    }

    fn deallocate_worker(&self, core_id: u32) -> Result<()> {
        self.set_worker_filter(core_id, &[], false)?;
        info!(core_id, "remote worker deallocated and idle Respawn queued");
        Ok(())
    }

    fn check_workers_connected(&self) -> Result<Vec<u32>> {
        let workers = self.workers.lock().unwrap();
        Ok(workers.values()
            .filter(|w| w.connected)
            .map(|w| w.core_id)
            .collect())
    }

    fn range_workers(&self) -> Result<Vec<WorkerInfo>> {
        let workers = self.workers.lock().unwrap();
        Ok(workers.values()
            .map(|w| WorkerInfo {
                core_id: w.core_id,
                filter: w.filter.clone(),
                available_storage: 0,
                total_storage: 0,
                manually_managed: w.manually_managed,
                pending_filter_frame: w.pending_filter_frame,
                allocated: w.allocated,
            })
            .collect())
    }

    fn respawn_worker(&self, core_id: u32, filter: &[u8]) -> Result<()> {
        self.allocate_worker(core_id, filter)
    }

    fn set_pending_filter_frame(&self, core_id: u32, frame: u64) -> Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if let Some(w) = workers.get_mut(&core_id) {
            w.pending_filter_frame = frame;
        }
        Ok(())
    }

    fn set_manually_managed(&self, core_id: u32, manually_managed: bool) -> Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if let Some(w) = workers.get_mut(&core_id) {
            w.manually_managed = manually_managed;
        }
        Ok(())
    }

    fn set_allocated(&self, core_id: u32, allocated: bool) -> Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if let Some(w) = workers.get_mut(&core_id) {
            w.allocated = allocated;
        }
        Ok(())
    }
}

/// Convert a libp2p multiaddr string to an HTTP endpoint.
/// `/ip4/192.168.1.10/tcp/32501` → `http://192.168.1.10:32501`
fn multiaddr_to_http(multiaddr: &str) -> String {
    let parts: Vec<&str> = multiaddr.split('/').collect();
    let mut host = "127.0.0.1";
    let mut port = "32500";

    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "ip4" | "ip6" => {
                if i + 1 < parts.len() {
                    host = parts[i + 1];
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "tcp" | "udp" => {
                if i + 1 < parts.len() {
                    port = parts[i + 1];
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    format!("http://{}:{}", host, port)
}

/// Connect to a remote worker's gRPC endpoint with retry. When `tls` is set the
/// dial is mTLS (https): the master presents the node leaf cert and verifies the
/// worker's cert against the node CA — only node-key holders interoperate.
async fn connect_to_worker(
    endpoint: &str,
    tls: Option<&tonic::transport::ClientTlsConfig>,
) -> Result<Channel> {
    let mut backoff = std::time::Duration::from_millis(50);
    let max_backoff = std::time::Duration::from_secs(5);
    let max_attempts = 10;

    // tonic uses TLS based on the URI scheme + tls_config; switch http→https.
    let uri = if tls.is_some() {
        endpoint.replacen("http://", "https://", 1)
    } else {
        endpoint.to_string()
    };

    for attempt in 1..=max_attempts {
        let mut ep = match Channel::from_shared(uri.clone())
            .map_err(|e| QuilError::Internal(format!("invalid endpoint: {}", e)))
        {
            Ok(ep) => ep,
            Err(e) => return Err(e),
        };
        if let Some(cfg) = tls {
            ep = ep
                .tls_config(cfg.clone())
                .map_err(|e| QuilError::Internal(format!("worker channel TLS: {}", e)))?;
        }
        match ep.connect().await {
            Ok(channel) => return Ok(channel),
            Err(e) => {
                if attempt == max_attempts {
                    return Err(QuilError::Internal(format!(
                        "failed to connect after {} attempts: {}", max_attempts, e
                    )));
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }

    Err(QuilError::Internal("unreachable".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAppShardService {
        calls: std::sync::Arc<std::sync::Mutex<Vec<(Vec<u8>, u64)>>>,
    }

    struct TestDataIpcService {
        completed: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        first_started: std::sync::Arc<tokio::sync::Semaphore>,
        release_first: std::sync::Arc<tokio::sync::Semaphore>,
    }

    #[tonic::async_trait]
    impl quil_types::proto::node::data_ipc_service_server::DataIpcService for TestDataIpcService {
        async fn respawn(
            &self,
            request: tonic::Request<quil_types::proto::node::RespawnRequest>,
        ) -> std::result::Result<
            tonic::Response<quil_types::proto::node::RespawnResponse>,
            tonic::Status,
        > {
            let filter = request.into_inner().filter;
            if filter == b"shard-a" {
                self.first_started.add_permits(1);
                self.release_first.acquire().await.unwrap().forget();
            }
            self.completed.lock().unwrap().push(filter);
            Ok(tonic::Response::new(
                quil_types::proto::node::RespawnResponse {},
            ))
        }

        async fn create_join_proof(
            &self,
            _request: tonic::Request<quil_types::proto::node::CreateJoinProofRequest>,
        ) -> std::result::Result<
            tonic::Response<quil_types::proto::node::CreateJoinProofResponse>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(
                quil_types::proto::node::CreateJoinProofResponse {
                    response: Vec::new(),
                },
            ))
        }

        async fn set_halted(
            &self,
            _request: tonic::Request<quil_types::proto::node::SetHaltedRequest>,
        ) -> std::result::Result<
            tonic::Response<quil_types::proto::node::SetHaltedResponse>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(
                quil_types::proto::node::SetHaltedResponse {},
            ))
        }
    }

    #[tonic::async_trait]
    impl quil_types::proto::global::app_shard_service_server::AppShardService for TestAppShardService {
        async fn get_app_shard_frame(
            &self,
            request: tonic::Request<quil_types::proto::global::GetAppShardFrameRequest>,
        ) -> std::result::Result<
            tonic::Response<quil_types::proto::global::AppShardFrameResponse>,
            tonic::Status,
        > {
            let req = request.into_inner();
            self.calls
                .lock()
                .unwrap()
                .push((req.filter.clone(), req.frame_number));
            let mut header = quil_types::proto::global::FrameHeader::default();
            header.address = req.filter;
            header.frame_number = req.frame_number;
            header.output = vec![9; 5 * 1024 * 1024];
            Ok(tonic::Response::new(
                quil_types::proto::global::AppShardFrameResponse {
                    frame: Some(quil_types::proto::global::AppShardFrame {
                        header: Some(header),
                        requests: Vec::new(),
                        ..Default::default()
                    }),
                    proof: Vec::new(),
                },
            ))
        }

        async fn get_app_shard_proposal(
            &self,
            _request: tonic::Request<quil_types::proto::global::GetAppShardProposalRequest>,
        ) -> std::result::Result<
            tonic::Response<quil_types::proto::global::AppShardProposalResponse>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(
                quil_types::proto::global::AppShardProposalResponse { proposal: None },
            ))
        }
    }

    #[test]
    fn multiaddr_to_http_ipv4() {
        assert_eq!(
            multiaddr_to_http("/ip4/192.168.1.10/tcp/32501"),
            "http://192.168.1.10:32501"
        );
    }

    #[test]
    fn multiaddr_to_http_localhost() {
        assert_eq!(
            multiaddr_to_http("/ip4/127.0.0.1/tcp/8340"),
            "http://127.0.0.1:8340"
        );
    }

    #[test]
    fn from_config_assigns_core_ids() {
        let addrs = vec![
            "/ip4/10.0.0.1/tcp/32501".to_string(),
            "/ip4/10.0.0.2/tcp/32502".to_string(),
        ];
        let mgr = RemoteWorkerManager::from_config(&addrs, "http://master:8340".into(), None);
        assert_eq!(mgr.worker_count(), 2);
        let workers = mgr.range_workers().unwrap();
        let ids: Vec<u32> = workers.iter().map(|w| w.core_id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
    }

    #[test]
    fn allocate_unknown_core_errors() {
        let mgr = RemoteWorkerManager::new(vec![], "http://master:8340".into(), None);
        assert!(mgr.allocate_worker(99, &[0x01]).is_err());
    }

    #[test]
    fn deallocate_clears_filter() {
        let mgr = RemoteWorkerManager::new(
            vec![(1, "http://10.0.0.1:32501".into())],
            "http://master:8340".into(),
            None,
        );
        mgr.allocate_worker(1, &[0xAA; 32]).unwrap();
        mgr.deallocate_worker(1).unwrap();
        let workers = mgr.range_workers().unwrap();
        assert!(workers[0].filter.is_empty());
    }

    #[tokio::test]
    async fn proxies_frame_reads_to_assigned_worker_with_large_messages() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let service = TestAppShardService {
            calls: calls.clone(),
        };
        let data_service = TestDataIpcService {
            completed: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            first_started: std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
            release_first: std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::global::app_shard_service_server::AppShardServiceServer::new(
                        service,
                    )
                    .max_decoding_message_size(64 * 1024 * 1024)
                    .max_encoding_message_size(64 * 1024 * 1024),
                )
                .add_service(
                    quil_types::proto::node::data_ipc_service_server::DataIpcServiceServer::new(
                        data_service,
                    ),
                )
                .serve_with_shutdown(addr, async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let manager = RemoteWorkerManager::new(
            vec![(1, format!("http://{addr}"))],
            "http://master:8340".into(),
            None,
        );
        manager.connect_all().await;
        manager.send_respawn(1, b"assigned-shard").await.unwrap();

        let frame = manager
            .get_app_shard_frame(b"assigned-shard", 44)
            .await
            .unwrap()
            .unwrap();
        let header = frame.header.unwrap();
        assert_eq!(header.frame_number, 44);
        assert_eq!(header.output.len(), 5 * 1024 * 1024);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![(b"assigned-shard".to_vec(), 44)]
        );
        assert!(manager
            .get_app_shard_frame(b"unassigned-shard", 44)
            .await
            .unwrap()
            .is_none());

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn app_shard_read_reports_an_assigned_disconnected_worker() {
        let manager = RemoteWorkerManager::new(
            vec![(1, "http://127.0.0.1:1".into())],
            "http://master:8340".into(),
            None,
        );
        manager
            .set_worker_filter(1, b"assigned-shard", false)
            .unwrap();
        {
            let mut workers = manager.workers.lock().unwrap();
            let worker = workers.get_mut(&1).unwrap();
            worker.active_filter = b"assigned-shard".to_vec();
            worker.respawn_pending = false;
        }

        let status = manager
            .get_app_shard_frame(b"assigned-shard", 0)
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn serializes_reassignment_and_sends_idle_on_deallocation() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let completed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let first_started = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let release_first = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let service = TestDataIpcService {
            completed: completed.clone(),
            first_started: first_started.clone(),
            release_first: release_first.clone(),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::node::data_ipc_service_server::DataIpcServiceServer::new(
                        service,
                    ),
                )
                .serve_with_shutdown(addr, async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let manager = RemoteWorkerManager::new(
            vec![(1, format!("http://{addr}"))],
            "http://master:8340".into(),
            None,
        );
        manager.connect_all().await;
        manager.set_worker_filter(1, b"shard-a", true).unwrap();
        first_started.acquire().await.unwrap().forget();
        manager.set_worker_filter(1, b"shard-b", true).unwrap();
        let pending = manager
            .get_app_shard_frame(b"shard-b", 0)
            .await
            .unwrap_err();
        assert_eq!(pending.code(), tonic::Code::Unavailable);
        assert!(manager
            .get_app_shard_frame(b"shard-a", 0)
            .await
            .unwrap()
            .is_none());
        release_first.add_permits(1);

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let active = manager
                    .workers
                    .lock()
                    .unwrap()
                    .get(&1)
                    .unwrap()
                    .active_filter
                    .clone();
                if completed.lock().unwrap().len() == 2 && active == b"shard-b" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            *completed.lock().unwrap(),
            vec![b"shard-a".to_vec(), b"shard-b".to_vec()]
        );
        assert_eq!(
            manager
                .workers
                .lock()
                .unwrap()
                .get(&1)
                .unwrap()
                .active_filter,
            b"shard-b"
        );

        manager.deallocate_worker(1).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let active_is_empty = manager
                    .workers
                    .lock()
                    .unwrap()
                    .get(&1)
                    .unwrap()
                    .active_filter
                    .is_empty();
                if completed.lock().unwrap().len() == 3 && active_is_empty {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(completed.lock().unwrap()[2].is_empty());
        assert!(manager
            .workers
            .lock()
            .unwrap()
            .get(&1)
            .unwrap()
            .active_filter
            .is_empty());
        let _ = shutdown_tx.send(());
    }
}
