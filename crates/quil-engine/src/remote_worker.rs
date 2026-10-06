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
use tracing::{debug, error, info, warn};

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
    /// Identity of this quote binding. Replaced on rebinding/reconnect, so an
    /// A→B→A change cannot make an old in-flight response appear current.
    quote_binding: std::sync::Arc<()>,
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
    /// Whether a `start_consensus=true` Respawn is owed to this worker. Set when
    /// the allocator asks to start consensus while the worker's channel is down
    /// (a cluster worker that connects AFTER its alloc went Active). `connect_all`
    /// re-issues the Respawn once the channel comes up. Without this the deferred
    /// Respawn (remote_worker.rs "consensus not yet started"/"deferred") was lost
    /// and the worker never activated.
    wants_consensus: bool,
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

/// What became of a shard consensus message handed to a standalone worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteDelivery {
    Accepted,
    /// The worker no longer runs that shard's engine.
    Refused,
    /// The worker's build lacks `DeliverShardConsensus`.
    Unsupported,
    Failed,
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
            // Show the effective scheme (https under mTLS), matching the actual
            // dial in `connect_to_worker`, not the raw `http://` endpoint.
            let display_endpoint = if client_tls.is_some() {
                endpoint.replacen("http://", "https://", 1)
            } else {
                endpoint.clone()
            };
            info!(
                core_id,
                endpoint = %display_endpoint,
                "registered remote worker"
            );
            workers.insert(core_id, RemoteWorkerState {
                core_id,
                endpoint,
                filter: Vec::new(),
                quote_binding: std::sync::Arc::new(()),
                pending_filter_frame: 0,
                manually_managed: false,
                allocated: false,
                channel: None,
                connected: false,
                wants_consensus: false,
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
        let endpoints: Vec<(u32, String)> = {
            let workers = self.workers.lock().unwrap();
            workers.values()
                .filter(|w| w.channel.is_none())
                .map(|w| (w.core_id, w.endpoint.clone()))
                .collect()
        };
        if endpoints.is_empty() {
            return;
        }

        for (core_id, endpoint) in endpoints {
            // Log the EFFECTIVE scheme: `connect_to_worker` dials https (mTLS)
            // when `client_tls` is set, swapping the endpoint's `http://` →
            // `https://`. Mirror that here so the log matches the real dial
            // instead of showing the raw `http://` (a cosmetic artifact that
            // looked like plaintext even under mTLS).
            let display_endpoint = if self.client_tls.is_some() {
                endpoint.replacen("http://", "https://", 1)
            } else {
                endpoint.clone()
            };
            match connect_to_worker(&endpoint, self.client_tls.as_ref()).await {
                Ok(channel) => {
                    let (owed_filter, chan) = {
                        let mut workers = self.workers.lock().unwrap();
                        if let Some(w) = workers.get_mut(&core_id) {
                            w.quote_binding = std::sync::Arc::new(());
                            w.channel = Some(channel.clone());
                            w.connected = true;
                            // If a start_consensus Respawn was deferred while the
                            // channel was down, it's owed now.
                            let owed = if w.wants_consensus && !w.filter.is_empty() {
                                Some(w.filter.clone())
                            } else {
                                None
                            };
                            (owed, channel)
                        } else {
                            (None, channel)
                        }
                    };
                    info!(core_id, endpoint = %display_endpoint, "connected to remote worker");
                    let _ = self.event_tx.send(RemoteWorkerEvent::Connected { core_id }).await;
                    // Re-issue the deferred Respawn now that the worker is up.
                    if let Some(filter) = owed_filter {
                        info!(core_id, filter = hex::encode(&filter), "re-issuing deferred Respawn on connect");
                        let mut client =
                            quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(chan);
                        let req = tonic::Request::new(quil_types::proto::node::RespawnRequest {
                            filter,
                        });
                        if let Err(e) = client.respawn(req).await {
                            warn!(core_id, error = %e, "deferred Respawn failed");
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        core_id,
                        endpoint = %display_endpoint,
                        error = %e,
                        "failed to connect to remote worker"
                    );
                }
            }
        }
    }

    /// Read one bound worker's actual materialized pricing inputs. No fanout,
    /// archive-derived fallback, or connection is created by this operation.
    pub async fn app_fee_snapshot(&self, application: [u8; 32]) -> Result<quil_execution::pricing::AppFeeSnapshot> {
        let unavailable = || quil_types::error::QuilError::ExecutionUnavailable("application fee worker unavailable".into());
        let (core, binding, channel) = {
            let workers = self.workers.lock().map_err(|_| unavailable())?;
            workers.iter().filter(|(_, w)| w.filter.as_slice() == application.as_slice())
                .filter_map(|(core, w)| w.channel.clone().map(|c| (*core, w.quote_binding.clone(), c)))
                .min_by_key(|(core, _, _)| *core).ok_or_else(unavailable)?
        };
        let mut client = quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(channel)
            .max_decoding_message_size(1024).max_encoding_message_size(1024);
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), client.get_app_fee_snapshot(
            quil_types::proto::node::GetAppFeeSnapshotRequest { application: application.to_vec() },
        )).await.map_err(|_| unavailable())?.map_err(|_| unavailable())?.into_inner();
        let workers = self.workers.lock().map_err(|_| unavailable())?;
        if response.application.as_slice() != application.as_slice()
            || !workers.get(&core).is_some_and(|w| w.filter.as_slice() == application.as_slice()
                && std::sync::Arc::ptr_eq(&w.quote_binding, &binding)) {
            return Err(unavailable());
        }
        Ok(quil_execution::pricing::AppFeeSnapshot {
            application, frame_number: response.frame_number, global_frame_number: response.global_frame_number,
            difficulty: response.difficulty, world_state_bytes: response.world_state_bytes,
            fee_multiplier_vote: response.fee_multiplier_vote,
        })
    }

    /// Whether a standalone worker is running consensus for `filter`. A
    /// Joining allocation is assigned to a worker whose engine starts only
    /// when it becomes active, so the worker holds nothing to prepare from yet.
    pub fn serves_filter(&self, filter: &[u8]) -> bool {
        self.workers
            .lock()
            .map(|workers| workers.values().any(|w| Self::runs(w, filter)))
            .unwrap_or(false)
    }

    fn runs(worker: &RemoteWorkerState, filter: &[u8]) -> bool {
        !filter.is_empty() && worker.wants_consensus && worker.filter.as_slice() == filter
    }

    /// Filters a standalone worker is running consensus for.
    pub fn served_filters(&self) -> Vec<Vec<u8>> {
        self.workers
            .lock()
            .map(|workers| {
                workers.values().filter(|w| Self::runs(w, &w.filter)).map(|w| w.filter.clone()).collect()
            })
            .unwrap_or_default()
    }

    /// Hand the standalone worker running `filter` a shard consensus message
    /// a committee member (`from`, its committee key) sent this node
    /// directly.
    pub async fn deliver_shard_consensus(
        &self,
        filter: &[u8],
        channel: u64,
        data: Vec<u8>,
        from: Vec<u8>,
    ) -> RemoteDelivery {
        let connection = self.workers.lock().ok().and_then(|workers| {
            workers.values().find(|w| Self::runs(w, filter)).and_then(|w| w.channel.clone())
        });
        let Some(connection) = connection else { return RemoteDelivery::Failed };
        let mut client = quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(connection)
            .max_decoding_message_size(16 << 20)
            .max_encoding_message_size(16 << 20);
        let request = quil_types::proto::node::DeliverShardConsensusRequest {
            filter: filter.to_vec(),
            channel,
            data,
            from,
        };
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.deliver_shard_consensus(request)).await {
            Ok(Ok(response)) if response.get_ref().accepted => RemoteDelivery::Accepted,
            Ok(Ok(_)) => RemoteDelivery::Refused,
            Ok(Err(status)) if status.code() == tonic::Code::Unimplemented => RemoteDelivery::Unsupported,
            _ => RemoteDelivery::Failed,
        }
    }

    /// Leaf roots for `filter`'s next-epoch replicas, encoded by the standalone
    /// worker running it, from its own store. `Ok(None)`: no standalone worker
    /// runs this filter (including a Joining allocation, whose engine has not
    /// started); the caller encodes from its own store as before. Encoding a
    /// large shard is slow; the caller bounds concurrency, this bounds the wait.
    pub async fn prepare_storage_confirm(
        &self,
        filter: &[u8],
        targets: &[Vec<u8>],
        frame_number: u64,
    ) -> Result<Option<Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>>> {
        let channel = {
            let workers = self.workers.lock().map_err(|_| QuilError::Internal("worker table poisoned".into()))?;
            let Some(worker) = workers.values().find(|w| Self::runs(w, filter)) else {
                return Ok(None);
            };
            worker.channel.clone().ok_or_else(|| {
                QuilError::ExecutionUnavailable("worker serving this filter is not connected".into())
            })?
        };
        let mut client = quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(channel)
            .max_decoding_message_size(16 << 20);
        let response = match tokio::time::timeout(
            std::time::Duration::from_secs(600),
            client.prepare_storage_confirm(quil_types::proto::node::PrepareStorageConfirmRequest {
                filter: filter.to_vec(),
                frame_number,
                targets: targets.to_vec(),
            }),
        )
        .await
        .map_err(|_| QuilError::ExecutionUnavailable("worker storage confirm timed out".into()))?
        {
            Ok(response) => response.into_inner(),
            // The worker has not bound or synced this shard yet: the caller
            // encodes from its own store, as for a Joining allocation.
            Err(status) if status.code() == tonic::Code::FailedPrecondition => {
                debug!(filter = hex::encode(filter), message = status.message(), "worker cannot prepare storage confirm yet");
                return Ok(None);
            }
            Err(status) => {
                return Err(QuilError::ExecutionUnavailable(format!("worker storage confirm: {}", status.message())));
            }
        };
        let roots: Vec<_> = response
            .leaf_roots
            .iter()
            .map(quil_execution::global_intrinsic::conversions::confirm_leaf_roots_from_proto)
            .collect();
        if roots.iter().any(|group| group.filter != filter) {
            return Err(QuilError::ExecutionUnavailable("worker returned leaf roots for another filter".into()));
        }
        Ok(Some(roots))
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
        let channel = {
            let mut workers = self.workers.lock().unwrap();
            workers.get_mut(&core_id)
                .and_then(|w| { w.quote_binding = std::sync::Arc::new(()); w.channel.clone() })
                .ok_or_else(|| QuilError::Internal(
                    format!("worker {} not connected", core_id)
                ))?
        };

        // Call the DataIPC Respawn RPC
        let mut client = quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(channel);
        let request = tonic::Request::new(quil_types::proto::node::RespawnRequest {
            filter: filter.to_vec(),
        });

        match client.respawn(request).await {
            Ok(_) => {
                info!(core_id, filter = hex::encode(filter), "remote worker respawned");
                Ok(())
            }
            Err(e) => {
                error!(core_id, error = %e, "remote worker respawn failed");
                Err(QuilError::Internal(format!("respawn failed: {}", e)))
            }
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
    fn set_worker_filter(
        &self,
        core_id: u32,
        filter: &[u8],
        start_consensus: bool,
    ) -> Result<()> {
        let connected = {
            let mut workers = self.workers.lock().unwrap();
            if let Some(w) = workers.get_mut(&core_id) {
                w.quote_binding = std::sync::Arc::new(());
                w.filter = filter.to_vec();
                // Remember whether consensus is owed, so `connect_all` can
                // re-issue the Respawn if the worker connects later. A
                // non-empty filter with start_consensus=false (Joining) clears
                // it; an empty filter (idle) clears it too.
                w.wants_consensus = start_consensus && !filter.is_empty();
                // A worker owed consensus is allocated; otherwise the
                // allocator's next pass re-issues the Respawn (see the thread
                // manager).
                w.allocated = w.wants_consensus;
                w.channel.is_some()
            } else {
                return Err(QuilError::InvalidArgument(
                    format!("no remote worker with core_id {}", core_id)
                ));
            }
        };

        // Empty filter = idle slot reservation (e.g. startup
        // pre-allocation at main.rs that creates `cores - 1` empty
        // slots before any shard work is assigned). There is no
        // consensus engine to (re)spawn for an empty filter; just
        // record the binding. Falls through `start_consensus` and
        // `connected` checks because both are irrelevant here.
        if filter.is_empty() {
            debug!(core_id, "remote worker idle slot recorded (no filter)");
            return Ok(());
        }

        // `start_consensus=false` (Joining alloc, no Active prover yet)
        // intentionally skips the Respawn — the worker stays idle until
        // the allocation transitions to Active.
        if !start_consensus {
            info!(
                core_id,
                filter = hex::encode(filter),
                "remote worker filter recorded (consensus not yet started)"
            );
            return Ok(());
        }
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
        let filter_owned = filter.to_vec();
        tokio::spawn(async move {
            let channel = {
                let guard = workers.lock().unwrap();
                guard.get(&core_id).and_then(|w| w.channel.clone())
            };
            let Some(channel) = channel else {
                warn!(core_id, "remote worker channel disappeared before Respawn");
                return;
            };
            let mut client = quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(channel);
            let request = tonic::Request::new(quil_types::proto::node::RespawnRequest {
                filter: filter_owned.clone(),
            });
            match client.respawn(request).await {
                Ok(_) => info!(
                    core_id,
                    filter = hex::encode(&filter_owned),
                    "remote worker respawned"
                ),
                Err(e) => warn!(
                    core_id,
                    filter = hex::encode(&filter_owned),
                    error = %e,
                    "remote worker Respawn RPC failed"
                ),
            }
        });
        Ok(())
    }

    fn deallocate_worker(&self, core_id: u32) -> Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if let Some(w) = workers.get_mut(&core_id) {
            w.quote_binding = std::sync::Arc::new(());
            w.filter.clear();
            info!(core_id, "remote worker deallocated");
        }
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
        assert!(mgr.range_workers().unwrap()[0].allocated, "a worker owed consensus is allocated");
        mgr.deallocate_worker(1).unwrap();
        let workers = mgr.range_workers().unwrap();
        assert!(workers[0].filter.is_empty());
        mgr.set_worker_filter(1, &[0xBB; 32], false).unwrap();
        assert!(!mgr.range_workers().unwrap()[0].allocated);
    }
}

#[cfg(test)]
mod fee_relay_tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicU8, Ordering}};
    use quil_types::proto::node;

    struct Incoming(tokio::net::TcpListener);
    impl tonic::codegen::tokio_stream::Stream for Incoming {
        type Item = std::io::Result<tokio::net::TcpStream>;
        fn poll_next(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>)
            -> std::task::Poll<Option<Self::Item>> {
            self.0.poll_accept(cx).map(|result| Some(result.map(|(stream, _)| stream)))
        }
    }

    struct SnapshotServer {
        mode: Arc<AtomicU8>, entered: Arc<tokio::sync::Notify>, release: Arc<tokio::sync::Notify>,
    }
    #[tonic::async_trait]
    impl node::data_ipc_service_server::DataIpcService for SnapshotServer {
        async fn deliver_shard_consensus(&self, _: tonic::Request<node::DeliverShardConsensusRequest>)
            -> std::result::Result<tonic::Response<node::DeliverShardConsensusResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("test server"))
        }
        async fn get_app_fee_snapshot(&self, request: tonic::Request<node::GetAppFeeSnapshotRequest>)
            -> std::result::Result<tonic::Response<node::GetAppFeeSnapshotResponse>, tonic::Status> {
            let mode = self.mode.load(Ordering::SeqCst);
            if mode == 1 { self.entered.notify_one(); self.release.notified().await; }
            if mode == 4 { std::future::pending::<()>().await; }
            let application = match mode { 2 => vec![9; 32], 3 => vec![7; 2048], _ => request.into_inner().application };
            Ok(tonic::Response::new(node::GetAppFeeSnapshotResponse { application,
                frame_number: 42, global_frame_number: 100, difficulty: 50_000,
                world_state_bytes: 1234, fee_multiplier_vote: 7 }))
        }
        async fn respawn(&self, _: tonic::Request<node::RespawnRequest>) -> std::result::Result<tonic::Response<node::RespawnResponse>, tonic::Status> {
            Ok(tonic::Response::new(node::RespawnResponse {}))
        }
        async fn create_join_proof(&self, _: tonic::Request<node::CreateJoinProofRequest>) -> std::result::Result<tonic::Response<node::CreateJoinProofResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("not used by fee relay"))
        }
        async fn set_halted(&self, _: tonic::Request<node::SetHaltedRequest>) -> std::result::Result<tonic::Response<node::SetHaltedResponse>, tonic::Status> {
            Ok(tonic::Response::new(node::SetHaltedResponse {}))
        }
        async fn prepare_storage_confirm(&self, _: tonic::Request<node::PrepareStorageConfirmRequest>) -> std::result::Result<tonic::Response<node::PrepareStorageConfirmResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("not used by fee relay"))
        }
    }

    /// A shard a worker runs consensus for is served, and a direct message
    /// for it reaches that worker; a worker build without the delivery RPC is
    /// told apart, so the master stops taking direct messages for it.
    #[tokio::test]
    async fn direct_shard_consensus_goes_to_the_worker_running_the_shard() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = SnapshotServer {
            mode: Arc::new(AtomicU8::new(0)),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(node::data_ipc_service_server::DataIpcServiceServer::new(server))
                .serve_with_incoming_shutdown(Incoming(listener), async { let _ = stopped.await; }).await.unwrap();
        });
        let manager = RemoteWorkerManager::new(vec![(1, endpoint)], String::new(), None);
        manager.connect_all().await;
        manager.set_worker_filter(1, &[7; 32], false).unwrap();
        assert!(manager.served_filters().is_empty(), "a Joining allocation runs no consensus yet");
        manager.set_worker_filter(1, &[7; 32], true).unwrap();
        assert_eq!(manager.served_filters(), vec![vec![7; 32]]);
        assert_eq!(
            manager.deliver_shard_consensus(&[7; 32], 2, b"x".to_vec(), vec![5; 897]).await,
            RemoteDelivery::Unsupported,
            "this test worker lacks the RPC, like an older build"
        );
        assert_eq!(
            manager.deliver_shard_consensus(&[8; 32], 2, b"x".to_vec(), vec![5; 897]).await,
            RemoteDelivery::Failed,
            "no worker runs that shard"
        );
        stop.send(()).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), serving).await;
    }

    #[tokio::test]
    async fn app_fee_relay_transport_bounds_and_binding_races() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(0));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let server = SnapshotServer { mode: mode.clone(), entered: entered.clone(), release: release.clone() };
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let mut serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(node::data_ipc_service_server::DataIpcServiceServer::new(server))
                .serve_with_incoming_shutdown(Incoming(listener), async { let _ = stopped.await; }).await.unwrap();
        });
        let manager = Arc::new(RemoteWorkerManager::new(vec![(1, endpoint)], String::new(), None));
        manager.connect_all().await;
        manager.set_worker_filter(1, &[7; 32], false).unwrap();
        let snapshot = manager.app_fee_snapshot([7; 32]).await.unwrap();
        assert_eq!((snapshot.application, snapshot.frame_number, snapshot.global_frame_number,
            snapshot.difficulty, snapshot.world_state_bytes, snapshot.fee_multiplier_vote),
            ([7; 32], 42, 100, 50_000, 1234, 7));
        for bad_mode in [2, 3] {
            mode.store(bad_mode, Ordering::SeqCst);
            assert!(manager.app_fee_snapshot([7; 32]).await.unwrap_err().is_execution_unavailable());
        }
        mode.store(1, Ordering::SeqCst);
        let in_flight = { let manager = manager.clone(); tokio::spawn(async move { manager.app_fee_snapshot([7; 32]).await }) };
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified()).await.unwrap();
        manager.set_worker_filter(1, &[8; 32], false).unwrap();
        manager.set_worker_filter(1, &[7; 32], false).unwrap();
        release.notify_one();
        assert!(in_flight.await.unwrap().is_err(), "rebinding away and back must invalidate the old response");
        mode.store(4, Ordering::SeqCst);
        assert!(tokio::time::timeout(std::time::Duration::from_secs(7), manager.app_fee_snapshot([7; 32]))
            .await.unwrap().unwrap_err().is_execution_unavailable());
        mode.store(0, Ordering::SeqCst);
        manager.deallocate_worker(1).unwrap();
        assert!(manager.app_fee_snapshot([7; 32]).await.is_err());
        stop.send(()).unwrap();
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut serving).await.is_err() {
            serving.abort();
            let _ = serving.await;
        }
    }
}
