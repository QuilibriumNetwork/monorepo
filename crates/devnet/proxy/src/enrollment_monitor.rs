//! Verifies that every client's prover registration landed in the archives'
//! registry (and, optionally, that the client locally observed its allocation).
//!
//! Mirrors the Go `EnrollmentMonitor`. Connections are plaintext: the Rust
//! node's `NodeService` listens in the clear at `listen_grpc_multiaddr`
//! (qclient-facing convention). An archive poll succeeds when EVERY client's
//! prover-vertex returns at least one entry; overall success needs at least
//! `min_archives` archives confirming, plus every client with a node address
//! reporting a bound worker.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use quil_types::proto::node::node_service_client::NodeServiceClient;
use quil_types::proto::node::{GetVertexDataRequest, GetWorkerInfoRequest};
use tonic::transport::Channel;

/// 32-byte global-intrinsic application address (all 0xFF). A prover registry
/// vertex's 64-byte address is this prefix followed by the 32-byte
/// Poseidon(BLS pubkey) prover address.
const GLOBAL_INTRINSIC_ADDRESS: [u8; 32] = [0xFF; 32];

/// An archive whose registry should be polled.
#[derive(Debug, Clone)]
pub struct ArchiveTarget {
    pub name: String,
    pub address: String,
}

/// A client whose prover registration should be confirmed.
#[derive(Debug, Clone)]
pub struct EnrollmentTarget {
    pub name: String,
    /// 32-byte Poseidon(BLS pubkey) prover address.
    pub prover_address: Vec<u8>,
    /// `host:port` of the client's NodeService gRPC; empty disables the
    /// client-side worker check.
    pub node_address: String,
    /// When > 0, require exactly this many bound workers; otherwise ≥ 1.
    pub expected_cores: i32,
}

#[derive(Default)]
struct ArchiveStatus {
    client: Option<NodeServiceClient<Channel>>,
    all_confirmed: bool,
}

struct ClientStatus {
    client: Option<NodeServiceClient<Channel>>,
    confirmed: bool,
    skipped: bool,
    expected_cores: i32,
}

pub struct EnrollmentMonitor {
    archives: Vec<ArchiveTarget>,
    clients: Vec<EnrollmentTarget>,
    poll_interval: Duration,
    timeout: Duration,
    min_archives: usize,
    archive_status: HashMap<String, ArchiveStatus>,
    client_status: HashMap<String, ClientStatus>,
}

impl EnrollmentMonitor {
    pub fn new(
        archives: Vec<ArchiveTarget>,
        clients: Vec<EnrollmentTarget>,
        poll_interval: Duration,
        min_archives: usize,
        timeout: Duration,
    ) -> Self {
        let archive_status = archives
            .iter()
            .map(|a| (a.name.clone(), ArchiveStatus::default()))
            .collect();
        let client_status = clients
            .iter()
            .map(|c| {
                (
                    c.name.clone(),
                    ClientStatus {
                        client: None,
                        confirmed: false,
                        skipped: c.node_address.is_empty(),
                        expected_cores: c.expected_cores,
                    },
                )
            })
            .collect();
        Self {
            archives,
            clients,
            poll_interval,
            timeout,
            min_archives,
            archive_status,
            client_status,
        }
    }

    /// Lazily connect a plaintext NodeService channel.
    async fn connect(address: &str) -> Option<NodeServiceClient<Channel>> {
        let url = format!("http://{address}");
        match Channel::from_shared(url).ok()?.connect().await {
            Ok(ch) => Some(NodeServiceClient::new(ch)),
            Err(e) => {
                tracing::debug!(address, error = %e, "enrollment monitor: connect failed");
                None
            }
        }
    }

    /// Poll one archive: confirm every client's prover-vertex has ≥1 entry.
    async fn poll_archive(&mut self, name: &str, address: &str) {
        if self
            .archive_status
            .get(name)
            .and_then(|s| s.client.as_ref())
            .is_none()
        {
            let c = Self::connect(address).await;
            self.archive_status.get_mut(name).unwrap().client = c;
        }
        let Some(mut client) = self.archive_status.get_mut(name).unwrap().client.clone() else {
            self.archive_status.get_mut(name).unwrap().all_confirmed = false;
            return;
        };

        let mut all_found = true;
        for c in &self.clients {
            let mut addr = GLOBAL_INTRINSIC_ADDRESS.to_vec();
            addr.extend_from_slice(&c.prover_address);
            let req = GetVertexDataRequest {
                address: addr,
                full_data: false,
            };
            match tokio::time::timeout(Duration::from_secs(5), client.get_vertex_data(req)).await {
                Ok(Ok(resp)) => {
                    if resp.into_inner().entries.is_empty() {
                        all_found = false;
                    }
                }
                _ => {
                    all_found = false;
                    self.archive_status.get_mut(name).unwrap().client = None; // reconnect next poll
                }
            }
        }
        self.archive_status.get_mut(name).unwrap().all_confirmed = all_found;
    }

    /// Poll one client's GetWorkerInfo: confirmed when a worker is bound to a
    /// non-empty filter (or exactly `expected_cores` are, when set).
    async fn poll_client(&mut self, target: &EnrollmentTarget) {
        let st = self.client_status.get(&target.name).unwrap();
        if st.skipped {
            return;
        }
        if st.client.is_none() {
            let c = Self::connect(&target.node_address).await;
            self.client_status.get_mut(&target.name).unwrap().client = c;
        }
        let Some(mut client) = self.client_status.get(&target.name).unwrap().client.clone() else {
            self.client_status.get_mut(&target.name).unwrap().confirmed = false;
            return;
        };

        match tokio::time::timeout(
            Duration::from_secs(5),
            client.get_worker_info(GetWorkerInfoRequest {}),
        )
        .await
        {
            Ok(Ok(resp)) => {
                let bound = resp
                    .into_inner()
                    .worker_info
                    .iter()
                    .filter(|w| !w.filter.is_empty())
                    .count() as i32;
                let st = self.client_status.get_mut(&target.name).unwrap();
                st.confirmed = if st.expected_cores > 0 {
                    bound == st.expected_cores
                } else {
                    bound > 0
                };
            }
            _ => {
                let st = self.client_status.get_mut(&target.name).unwrap();
                st.confirmed = false;
                st.client = None;
            }
        }
    }

    async fn poll_all(&mut self) {
        let archives: Vec<(String, String)> = self
            .archives
            .iter()
            .map(|a| (a.name.clone(), a.address.clone()))
            .collect();
        for (name, address) in &archives {
            self.poll_archive(name, address).await;
        }
        let clients = self.clients.clone();
        for c in &clients {
            if !c.node_address.is_empty() {
                self.poll_client(c).await;
            }
        }
    }

    /// Quorum: at least `min_archives` archives confirmed every client vertex,
    /// AND every non-skipped client reports a bound worker.
    fn quorum_reached(&self) -> bool {
        let confirmed_archives = self
            .archive_status
            .values()
            .filter(|s| s.all_confirmed)
            .count();
        if confirmed_archives < self.min_archives {
            return false;
        }
        self.client_status
            .values()
            .all(|s| s.skipped || s.confirmed)
    }

    /// Poll until quorum is reached, the timeout elapses, or cancellation.
    /// Returns `Ok(())` on success (including when there are no clients).
    pub async fn wait_for_enrollment(
        &mut self,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<(), String> {
        if self.clients.is_empty() {
            tracing::info!("enrollment monitor: no clients to verify, skipping");
            return Ok(());
        }
        if self.min_archives == 0 || self.min_archives > self.archives.len() {
            return Err(format!(
                "enrollment monitor: min_archives={} out of range (archives={})",
                self.min_archives,
                self.archives.len()
            ));
        }

        tracing::info!(
            archives = self.archives.len(),
            clients = self.clients.len(),
            min_archives = self.min_archives,
            "enrollment monitor: starting"
        );

        let deadline = Instant::now() + self.timeout;
        self.poll_all().await;
        if self.quorum_reached() {
            return Ok(());
        }

        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Err("enrollment monitor: cancelled".to_string()),
                _ = ticker.tick() => {
                    self.poll_all().await;
                    if self.quorum_reached() {
                        return Ok(());
                    }
                    if Instant::now() > deadline {
                        return Err(self.timeout_error());
                    }
                }
            }
        }
    }

    fn timeout_error(&self) -> String {
        let confirmed = self
            .archive_status
            .values()
            .filter(|s| s.all_confirmed)
            .count();
        let unconfirmed_clients: Vec<&str> = self
            .client_status
            .iter()
            .filter(|(_, s)| !s.skipped && !s.confirmed)
            .map(|(n, _)| n.as_str())
            .collect();
        format!(
            "enrollment monitor: timed out — {confirmed}/{} archives confirmed (need {}), unconfirmed clients: {:?}",
            self.archives.len(),
            self.min_archives,
            unconfirmed_clients
        )
    }
}
