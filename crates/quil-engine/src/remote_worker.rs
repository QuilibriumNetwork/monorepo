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
}

/// Manages workers running on remote machines via gRPC.
///
/// Implements the `WorkerManager` trait so it can be used as a
/// drop-in replacement for `ThreadWorkerManager`.
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
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(256);
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
                pending_filter_frame: 0,
                manually_managed: false,
                allocated: false,
                channel: None,
                connected: false,
            });
        }

        Self {
            workers: std::sync::Arc::new(Mutex::new(workers)),
            master_endpoint,
            event_tx,
            event_rx: Mutex::new(Some(event_rx)),
        }
    }

    /// Build from config. Parses `data_worker_stream_multiaddrs` into
    /// (core_id, endpoint) pairs. Core IDs start at 1.
    pub fn from_config(
        stream_multiaddrs: &[String],
        master_endpoint: String,
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
        Self::new(endpoints, master_endpoint)
    }

    /// Take the event receiver (call once at startup).
    pub fn take_event_rx(&self) -> Option<mpsc::Receiver<RemoteWorkerEvent>> {
        self.event_rx.lock().unwrap().take()
    }

    /// Connect to all registered workers. Called during startup.
    pub async fn connect_all(&self) {
        let endpoints: Vec<(u32, String)> = {
            let workers = self.workers.lock().unwrap();
            workers.values()
                .map(|w| (w.core_id, w.endpoint.clone()))
                .collect()
        };

        for (core_id, endpoint) in endpoints {
            match connect_to_worker(&endpoint).await {
                Ok(channel) => {
                    let mut workers = self.workers.lock().unwrap();
                    if let Some(w) = workers.get_mut(&core_id) {
                        w.channel = Some(channel);
                        w.connected = true;
                    }
                    info!(core_id, endpoint = %endpoint, "connected to remote worker");
                    let _ = self.event_tx.send(RemoteWorkerEvent::Connected { core_id }).await;
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
            let workers = self.workers.lock().unwrap();
            workers.get(&core_id)
                .and_then(|w| w.channel.clone())
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
                w.filter = filter.to_vec();
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

/// Connect to a remote worker's gRPC endpoint with retry.
async fn connect_to_worker(endpoint: &str) -> Result<Channel> {
    let mut backoff = std::time::Duration::from_millis(50);
    let max_backoff = std::time::Duration::from_secs(5);
    let max_attempts = 10;

    for attempt in 1..=max_attempts {
        match Channel::from_shared(endpoint.to_string())
            .map_err(|e| QuilError::Internal(format!("invalid endpoint: {}", e)))?
            .connect()
            .await
        {
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
        let mgr = RemoteWorkerManager::from_config(&addrs, "http://master:8340".into());
        assert_eq!(mgr.worker_count(), 2);
        let workers = mgr.range_workers().unwrap();
        let ids: Vec<u32> = workers.iter().map(|w| w.core_id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
    }

    #[test]
    fn allocate_unknown_core_errors() {
        let mgr = RemoteWorkerManager::new(vec![], "http://master:8340".into());
        assert!(mgr.allocate_worker(99, &[0x01]).is_err());
    }

    #[test]
    fn deallocate_clears_filter() {
        let mgr = RemoteWorkerManager::new(
            vec![(1, "http://10.0.0.1:32501".into())],
            "http://master:8340".into(),
        );
        mgr.allocate_worker(1, &[0xAA; 32]).unwrap();
        mgr.deallocate_worker(1).unwrap();
        let workers = mgr.range_workers().unwrap();
        assert!(workers[0].filter.is_empty());
    }
}
