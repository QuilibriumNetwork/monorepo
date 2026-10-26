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
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

use quil_types::error::{QuilError, Result};

use crate::outage::{Outage, OutageEvent};
use crate::worker::{WorkerInfo, WorkerManager};

/// How long a dial to a worker may take; the 5 s connect tick is the retry.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a Respawn RPC may take before it counts as failed.
const RESPAWN_TIMEOUT: Duration = Duration::from_secs(30);
/// First and longest wait before re-sending an owed Respawn.
const RESPAWN_RETRY_FIRST: Duration = Duration::from_secs(5);
const RESPAWN_RETRY_MAX: Duration = Duration::from_secs(300);
/// Answers of a worker still in its initial prover-tree sync before its
/// wait warns: 120 asks 5 s apart, ten minutes, beyond a normal start.
const STARTING_WARN_AFTER: u64 = 120;
/// What the operator can check when a worker cannot be reached or does not
/// take its Respawn.
const WORKER_REMEDY: &str = "check the worker process on that host and its 'DataIPC gRPC server' line";

/// A Respawn a worker is owed: its RPC failed, or the worker reported
/// running another filter or none while its allocation is active. The
/// connect tick re-sends it with backoff (`reconcile_respawns`).
#[derive(Debug)]
struct OwedRespawn {
    filter: Vec<u8>,
    backoff: Duration,
    next_at: Instant,
    outage: Outage,
    /// The worker's answers that it is still starting, as an expected wait
    /// that warns only past `STARTING_WARN_AFTER`.
    starting: Outage,
}

impl OwedRespawn {
    fn new(filter: &[u8], next_at: Instant) -> Self {
        Self {
            filter: filter.to_vec(),
            backoff: RESPAWN_RETRY_FIRST,
            next_at,
            outage: Outage::default(),
            starting: Outage::begin_after(STARTING_WARN_AFTER),
        }
    }

    /// Log the end of a starting wait that warned, at `now`.
    fn started(&mut self, core_id: u32, now: Instant) {
        if let Some(OutageEvent::Ended { secs, .. }) = self.starting.observe(now, true) {
            info!(core_id, secs, "remote worker finished starting after {}s", secs);
        }
    }
}

/// How long a worker's report must show an engine running its filter
/// before an engine that kept exiting counts as up again.
const ENGINE_UP_FOR: Duration = Duration::from_secs(60);

/// A worker's engine that was reported lost after its Respawn: the
/// Respawn is owed again with backoff, so an engine that exits right
/// after each start is not restarted at the refresh cadence. The backoff
/// is kept until reports show the engine running for `ENGINE_UP_FOR`.
#[derive(Debug)]
struct LostEngine {
    filter: Vec<u8>,
    /// The wait before the next re-sent Respawn.
    backoff: Duration,
    /// The engine's exits; the second begins the outage.
    exits: Outage,
    /// The first report since the last loss showing the engine running.
    running_since: Option<Instant>,
}

/// One Respawn RPC in flight to a worker. Settling it releases the worker
/// (`settle_respawn`); a task that panics or is dropped first releases it
/// on drop, so the count cannot stick and stop re-sends for good.
struct RespawnInFlight {
    workers: std::sync::Arc<Mutex<HashMap<u32, RemoteWorkerState>>>,
    core_id: u32,
    settled: bool,
}

impl RespawnInFlight {
    /// Count a Respawn in flight to `worker`; called with the table locked.
    fn begin(workers: &std::sync::Arc<Mutex<HashMap<u32, RemoteWorkerState>>>, worker: &mut RemoteWorkerState) -> Self {
        worker.respawns_in_flight += 1;
        Self { workers: workers.clone(), core_id: worker.core_id, settled: false }
    }
}

impl Drop for RespawnInFlight {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Ok(mut workers) = self.workers.lock() {
            if let Some(w) = workers.get_mut(&self.core_id) {
                w.respawns_in_flight = w.respawns_in_flight.saturating_sub(1);
            }
        }
    }
}

/// Why a Respawn did not reach a worker's engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RespawnError {
    /// The worker is still in its initial prover-tree sync: an expected wait.
    Starting,
    Unreachable,
    TimedOut,
    /// The worker answered with an error of its own.
    Refused,
    Other,
}

impl RespawnError {
    fn of(status: &tonic::Status) -> Self {
        match status.code() {
            tonic::Code::Unavailable if status.message() == crate::worker_node::WORKER_STARTING => Self::Starting,
            tonic::Code::Unavailable => Self::Unreachable,
            tonic::Code::DeadlineExceeded => Self::TimedOut,
            tonic::Code::Internal | tonic::Code::FailedPrecondition => Self::Refused,
            _ => Self::Other,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "worker starting",
            Self::Unreachable => "unreachable",
            Self::TimedOut => "timed out",
            Self::Refused => "worker error",
            Self::Other => "rpc error",
        }
    }
}

/// How one Respawn attempt ended.
#[derive(Debug)]
enum RespawnOutcome {
    Delivered,
    /// The worker is starting: it took the Respawn and applies it once
    /// its initial prover-tree sync completes.
    Deferred,
    /// The worker already ran the filter: nothing was sent, or the worker
    /// kept its engine.
    AlreadyRuns,
    /// The worker's assignment changed before the Respawn was sent.
    Superseded,
    Failed(RespawnError, String),
}

/// gRPC endpoint for a remote worker.
#[derive(Debug)]
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
    /// The Respawn this worker is owed, if any (`reconcile_respawns`).
    owed: Option<OwedRespawn>,
    /// Respawn RPCs to this worker in flight. While one is, a report of
    /// another filter comes from before it and owes nothing.
    respawns_in_flight: u32,
    /// Failing dials, logged as one outage.
    connect_outage: Outage,
    /// When a Respawn to this worker last succeeded: a report asked for
    /// before then shows the engine it replaced.
    respawned_at: Option<Instant>,
    /// The engine this worker lost after its Respawn, while it keeps
    /// exiting (`owe_reported_respawn`).
    lost: Option<LostEngine>,
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
    /// Each standalone worker's latest execution report, as the filter its
    /// engine runs and the report on this node's clock
    /// (`refresh_executions`).
    executions: Mutex<HashMap<u32, (Vec<u8>, quil_types::proto::node::WorkerExecution)>>,
    /// Each standalone worker running consensus that did not answer the
    /// latest report request, as its filter and the reason
    /// (`refresh_executions`).
    unanswered: Mutex<HashMap<u32, (Vec<u8>, &'static str)>>,
    /// Standalone workers whose build lacks `EvictPayload`, each logged once
    /// until it answers the call.
    evict_unsupported: std::sync::Arc<Mutex<std::collections::HashSet<u32>>>,
}

/// How long a payload eviction request may take: the worker answers before
/// it runs the removal.
const EVICT_PAYLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Why a standalone worker running consensus gave no report.
const NO_ANSWER: &str = "worker does not answer";
const NOT_CONNECTED: &str = "worker not connected";
const STARTING: &str = "worker starting (initial prover-tree sync)";

/// What a standalone worker gave for its execution report.
enum Answer {
    Report(quil_types::proto::node::WorkerExecution),
    /// It answered without a usable report: without a record, or from a
    /// build without the call.
    Nothing,
    /// It answered that its engine runs another filter, or none (empty).
    Other(Vec<u8>),
    /// It did not answer in time, or the node holds no connection to it.
    Unanswered(&'static str),
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
                owed: None,
                respawns_in_flight: 0,
                // A worker restarting with the master is refused for a few
                // ticks; three failed dials in a row (15 s) are an outage.
                connect_outage: Outage::begin_after(3),
                respawned_at: None,
                lost: None,
            });
        }

        Self {
            workers: std::sync::Arc::new(Mutex::new(workers)),
            master_endpoint,
            event_tx,
            event_rx: Mutex::new(Some(event_rx)),
            client_tls,
            executions: Mutex::new(HashMap::new()),
            unanswered: Mutex::new(HashMap::new()),
            evict_unsupported: Default::default(),
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
    /// connect or after a disconnect clears the channel. Each pending worker is
    /// dialled once, all at the same time and each within `CONNECT_TIMEOUT`,
    /// so a pass ends within seconds however many workers refuse; the next
    /// tick dials again. A worker reached with an active assignment is owed
    /// its Respawn, sent only if it does not already run the filter, so a
    /// master restart leaves running engines alone.
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

        let mut dials = tokio::task::JoinSet::new();
        for (core_id, endpoint) in endpoints {
            let tls = self.client_tls.clone();
            dials.spawn(async move {
                let dialled = connect_to_worker(&endpoint, tls.as_ref()).await;
                (core_id, endpoint, dialled)
            });
        }
        let mut owed_on_connect = false;
        while let Some(dial) = dials.join_next().await {
            let Ok((core_id, endpoint, dialled)) = dial else { continue };
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
            let now = Instant::now();
            match dialled {
                Ok(channel) => {
                    let (owed_filter, outage) = {
                        let mut workers = self.workers.lock().unwrap();
                        if let Some(w) = workers.get_mut(&core_id) {
                            w.quote_binding = std::sync::Arc::new(());
                            w.channel = Some(channel);
                            w.connected = true;
                            // If a start_consensus Respawn was deferred while the
                            // channel was down, it's owed now.
                            let filter = w.filter.clone();
                            let owed = if Self::owes_consensus(w, &filter) {
                                if w.owed.is_none() {
                                    w.owed = Some(OwedRespawn::new(&filter, now));
                                }
                                Some(filter)
                            } else {
                                None
                            };
                            (owed, w.connect_outage.observe(now, true))
                        } else {
                            (None, None)
                        }
                    };
                    match outage {
                        Some(OutageEvent::Ended { secs, failures }) => info!(core_id, endpoint = %display_endpoint,
                            secs, failures, "connected to remote worker after {} failed dials over {}s", failures, secs),
                        _ => info!(core_id, endpoint = %display_endpoint, "connected to remote worker"),
                    }
                    let _ = self.event_tx.send(RemoteWorkerEvent::Connected { core_id }).await;
                    // Re-issue the deferred Respawn now that the worker is up,
                    // unless it already runs the filter.
                    if let Some(filter) = owed_filter {
                        info!(core_id, filter = hex::encode(&filter), "re-issuing deferred Respawn on connect");
                        owed_on_connect = true;
                    }
                }
                Err(e) => {
                    let outage = match self.workers.lock() {
                        Ok(mut workers) => workers.get_mut(&core_id).and_then(|w| w.connect_outage.observe(now, false)),
                        Err(_) => None,
                    };
                    match outage {
                        Some(OutageEvent::Began) => warn!(core_id, endpoint = %display_endpoint, error = %e,
                            scope = "local", action = "check",
                            "failed to connect to remote worker; it gets no assignment until it is reached; {}", WORKER_REMEDY),
                        Some(OutageEvent::Continues { secs, failures }) => warn!(core_id, endpoint = %display_endpoint,
                            error = %e, secs, failures, scope = "local", action = "check",
                            "still cannot connect to remote worker"),
                        _ => debug!(core_id, endpoint = %display_endpoint, error = %e, "remote worker dial failed"),
                    }
                }
            }
        }
        if owed_on_connect {
            self.reconcile_respawns().await;
        }
    }

    /// Fetch the execution report of every standalone worker running
    /// consensus: its engine's phase, which the lifecycle reads to renew only
    /// seats whose worker hosts its committee session. A worker that answers
    /// for another filter, or whose build lacks the call, has no report. One
    /// that does not answer in time, or that the node holds no connection
    /// to, hosts nothing: it is listed as unanswered.
    pub async fn refresh_executions(&self) {
        self.refresh_executions_at(Instant::now()).await
    }

    async fn refresh_executions_at(&self, asked: Instant) {
        let targets: Vec<(u32, Vec<u8>, Option<Channel>)> = match self.workers.lock() {
            Ok(workers) => workers
                .values()
                .filter(|w| Self::runs(w, &w.filter))
                .map(|w| (w.core_id, w.filter.clone(), w.channel.clone()))
                .collect(),
            Err(_) => return,
        };
        let mut fetches = tokio::task::JoinSet::new();
        for (core_id, filter, channel) in targets {
            fetches.spawn(async move {
                let Some(channel) = channel else { return (core_id, filter, Answer::Unanswered(NOT_CONNECTED)) };
                let mut client = quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(channel)
                    .max_decoding_message_size(64 << 10);
                let answer = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    client.get_worker_execution(quil_types::proto::node::GetWorkerExecutionRequest {}),
                )
                .await;
                let answer = match answer {
                    Ok(Ok(response)) => {
                        let response = response.into_inner();
                        if response.filter != filter {
                            Answer::Other(response.filter)
                        } else {
                            response.execution.map_or(Answer::Nothing, |execution| Answer::Report(
                                on_local_clock(execution, response.now_unix_ms, crate::worker_execution::now_ms())))
                        }
                    }
                    Ok(Err(status)) if status.code() == tonic::Code::Unavailable
                        && status.message() == crate::worker_node::WORKER_STARTING => Answer::Unanswered(STARTING),
                    Ok(Err(status)) if matches!(status.code(), tonic::Code::Unavailable | tonic::Code::DeadlineExceeded) =>
                        Answer::Unanswered(NO_ANSWER),
                    Ok(Err(_)) => Answer::Nothing,
                    Err(_) => Answer::Unanswered(NO_ANSWER),
                };
                (core_id, filter, answer)
            });
        }
        let mut fetched = Vec::new();
        while let Some(result) = fetches.join_next().await {
            if let Ok(entry) = result {
                fetched.push(entry);
            }
        }
        let mut lost = Vec::new();
        let mut running = Vec::new();
        {
            let (Ok(mut executions), Ok(mut unanswered)) = (self.executions.lock(), self.unanswered.lock()) else { return };
            executions.clear();
            unanswered.clear();
            for (core_id, filter, answer) in fetched {
                match answer {
                    Answer::Report(report) => {
                        running.push((core_id, filter.clone()));
                        executions.insert(core_id, (filter, report));
                    }
                    Answer::Unanswered(reason) => {
                        unanswered.insert(core_id, (filter, reason));
                    }
                    Answer::Other(running) => lost.push((core_id, filter, running)),
                    Answer::Nothing => {}
                }
            }
        }
        for (core_id, filter) in running {
            self.note_engine_running(core_id, &filter, asked);
        }
        for (core_id, filter, running) in lost {
            self.owe_reported_respawn(core_id, &filter, &running, asked);
        }
    }

    /// A report sent at `asked` showed worker `core_id` running `filter`:
    /// once reports show it running for `ENGINE_UP_FOR`, an engine that
    /// kept exiting counts as up again and its backoff is reset.
    fn note_engine_running(&self, core_id: u32, filter: &[u8], asked: Instant) {
        let Ok(mut workers) = self.workers.lock() else { return };
        let Some(w) = workers.get_mut(&core_id) else { return };
        let Some(lost) = w.lost.as_mut().filter(|lost| lost.filter == filter) else { return };
        let since = *lost.running_since.get_or_insert(asked);
        if asked.saturating_duration_since(since) < ENGINE_UP_FOR {
            return;
        }
        if let Some(OutageEvent::Ended { secs, failures }) = lost.exits.observe(asked, true) {
            info!(core_id, endpoint = %w.endpoint, filter = hex::encode(filter), secs, failures,
                "remote worker's engine stays up again after {} exits over {}s", failures, secs);
        }
        w.lost = None;
    }

    /// A worker whose allocation is active reported running `running`
    /// instead of `filter` (it restarted, its engine exited, or its Respawn
    /// was lost) in answer to a request sent at `asked`: it owes a Respawn,
    /// which `reconcile_respawns` sends after confirming. An answer that
    /// predates a Respawn in flight or since delivered shows the engine it
    /// replaced.
    fn owe_reported_respawn(&self, core_id: u32, filter: &[u8], running: &[u8], asked: Instant) {
        let Ok(mut workers) = self.workers.lock() else { return };
        let Some(w) = workers.get_mut(&core_id) else { return };
        if !Self::owes_consensus(w, filter)
            || w.respawns_in_flight > 0
            || w.owed.is_some()
            || w.respawned_at.is_some_and(|at| at >= asked)
        {
            return;
        }
        // A repeated loss of the same filter waits out the backoff, so an
        // engine that exits right after each start is not restarted at the
        // refresh cadence.
        let repeated = w.lost.as_ref().is_some_and(|lost| lost.filter == filter);
        if !repeated {
            w.lost = Some(LostEngine {
                filter: filter.to_vec(),
                backoff: RESPAWN_RETRY_FIRST,
                exits: Outage::begin_after(2),
                running_since: None,
            });
        }
        let Some(lost) = w.lost.as_mut() else { return };
        lost.running_since = None;
        let event = lost.exits.observe(asked, false);
        let retry = if repeated { lost.backoff } else { Duration::ZERO };
        if repeated {
            lost.backoff = (lost.backoff * 2).min(RESPAWN_RETRY_MAX);
        }
        w.owed = Some(OwedRespawn::new(filter, asked + retry));
        let filter_hex = hex::encode(filter);
        match event {
            Some(OutageEvent::Began) => warn!(core_id, endpoint = %w.endpoint, filter = %filter_hex,
                exits = 2, retry_secs = retry.as_secs(), scope = "local", action = "check",
                "remote worker's engine exited again after its Respawn; re-sending with backoff until it stays up; \
                 check the worker's lines before its 'app consensus engine exited' warning"),
            Some(OutageEvent::Continues { secs, failures }) => warn!(core_id, endpoint = %w.endpoint,
                filter = %filter_hex, exits = failures, secs, retry_secs = retry.as_secs(),
                scope = "local", action = "check", "remote worker's engine still keeps exiting after its Respawn"),
            _ if repeated => debug!(core_id, filter = %filter_hex, retry_secs = retry.as_secs(),
                "remote worker's engine exited again; Respawn re-sent after its backoff"),
            _ => {
                let running = if running.is_empty() { "none".to_string() } else { hex::encode(running) };
                warn!(core_id, endpoint = %w.endpoint, filter = %filter_hex, running = %running,
                    scope = "local", action = "check",
                    "remote worker runs another filter or none while its allocation is active (it restarted, or its \
                     engine exited); re-sending its Respawn");
            }
        }
    }

    /// Whether `worker` should run consensus for `filter` now: its assigned
    /// filter, with consensus started and the allocation active.
    fn owes_consensus(worker: &RemoteWorkerState, filter: &[u8]) -> bool {
        Self::runs(worker, filter) && worker.allocated
    }

    /// Owe `worker` a Respawn of its current assignment, if it has one and
    /// is not owed one already.
    fn owe_current(worker: &mut RemoteWorkerState, now: Instant) {
        let filter = worker.filter.clone();
        if worker.owed.is_none() && Self::owes_consensus(worker, &filter) {
            worker.owed = Some(OwedRespawn::new(&filter, now));
        }
    }

    /// Re-send each owed Respawn that is due, to every connected worker at
    /// once: first ask the worker what it runs, and send only when it does
    /// not run its filter, so a running engine is never restarted. A failure
    /// waits from `RESPAWN_RETRY_FIRST`, doubling to `RESPAWN_RETRY_MAX`; a
    /// worker still starting is asked again at the first interval.
    pub async fn reconcile_respawns(&self) {
        self.reconcile_respawns_at(Instant::now()).await
    }

    async fn reconcile_respawns_at(&self, now: Instant) {
        let due: Vec<(RespawnInFlight, Vec<u8>, Channel)> = {
            let Ok(mut workers) = self.workers.lock() else { return };
            let mut due = Vec::new();
            for w in workers.values_mut() {
                // An assignment changed or released since the Respawn was
                // owed owes nothing.
                if w.owed.as_ref().is_some_and(|owed| !Self::owes_consensus(w, &owed.filter)) {
                    w.owed = None;
                }
                let Some(owed) = w.owed.as_ref() else { continue };
                // Not connected: `connect_all` re-issues it on connect.
                let Some(channel) = w.channel.clone() else { continue };
                if owed.next_at > now || w.respawns_in_flight > 0 {
                    continue;
                }
                let filter = owed.filter.clone();
                due.push((RespawnInFlight::begin(&self.workers, w), filter, channel));
            }
            due
        };
        let mut attempts = tokio::task::JoinSet::new();
        for (in_flight, filter, channel) in due {
            let started = Instant::now();
            attempts.spawn(async move {
                let outcome = resend_respawn(&in_flight.workers, in_flight.core_id, channel, &filter).await;
                // Back off from the attempt's end, so a Respawn that ran
                // into its timeout does not use up the wait.
                Self::settle_respawn(in_flight, &filter, outcome, now + started.elapsed());
            });
        }
        while attempts.join_next().await.is_some() {}
    }

    /// Record how a Respawn of `filter` ended: clear or record the Respawn
    /// its worker is owed, and log the start, bounded repeats and end of a
    /// failing one.
    fn settle_respawn(mut in_flight: RespawnInFlight, filter: &[u8], outcome: RespawnOutcome, now: Instant) {
        let table = in_flight.workers.clone();
        let Ok(mut workers) = table.lock() else { return };
        in_flight.settled = true;
        let core_id = in_flight.core_id;
        let Some(w) = workers.get_mut(&core_id) else { return };
        w.respawns_in_flight = w.respawns_in_flight.saturating_sub(1);
        let filter_hex = hex::encode(filter);
        if !Self::owes_consensus(w, filter) {
            // The assignment changed or was released meanwhile; the current
            // one, if any, is what the worker is owed.
            debug!(core_id, filter = %filter_hex, outcome = ?outcome, "superseded remote worker Respawn settled");
            Self::owe_current(w, now);
            return;
        }
        let (error, message) = match outcome {
            RespawnOutcome::Superseded => {
                Self::owe_current(w, now);
                return;
            }
            RespawnOutcome::Failed(error, message) => (error, message),
            taken => {
                w.respawned_at = Some(Instant::now());
                let ended = match w.owed.take_if(|owed| owed.filter == filter) {
                    Some(mut owed) => {
                        owed.started(core_id, now);
                        owed.outage.observe(now, true)
                    }
                    None => None,
                };
                let recovered = match ended {
                    Some(OutageEvent::Ended { secs, failures }) => Some((secs, failures)),
                    _ => None,
                };
                match (taken, recovered) {
                    (RespawnOutcome::Delivered, Some((secs, failures))) => info!(core_id, filter = %filter_hex,
                        secs, failures, "remote worker respawned after {} failures over {}s", failures, secs),
                    (RespawnOutcome::Delivered, None) => info!(core_id, filter = %filter_hex, "remote worker respawned"),
                    (RespawnOutcome::Deferred, Some((secs, failures))) => info!(core_id, filter = %filter_hex,
                        secs, failures, "remote worker took its Respawn after {} failures over {}s; it is still starting \
                         and applies it once its initial prover-tree sync completes", failures, secs),
                    (RespawnOutcome::Deferred, None) => info!(core_id, filter = %filter_hex,
                        "remote worker took its Respawn while starting; it applies it once its initial prover-tree \
                         sync completes"),
                    (_, Some((secs, failures))) => info!(core_id, filter = %filter_hex,
                        secs, failures, "remote worker runs its filter again after {} failures over {}s", failures, secs),
                    (_, None) => info!(core_id, filter = %filter_hex,
                        "remote worker already runs its filter; its engine is kept"),
                }
                return;
            }
        };
        let endpoint = w.endpoint.clone();
        let owed = w.owed.get_or_insert_with(|| OwedRespawn::new(filter, now));
        if error == RespawnError::Starting {
            // An expected wait: ask again at the first interval, and warn
            // only when it lasts beyond a normal start.
            owed.next_at = now + RESPAWN_RETRY_FIRST;
            match owed.starting.observe(now, false) {
                Some(OutageEvent::Began) => warn!(core_id, endpoint = %endpoint, filter = %filter_hex,
                    scope = "local", action = "check",
                    "remote worker still in its initial prover-tree sync; its Respawn waits until it is ready; \
                     check the worker's 'initial prover-tree sync' lines"),
                Some(OutageEvent::Continues { secs, .. }) => warn!(core_id, endpoint = %endpoint,
                    filter = %filter_hex, secs, scope = "local", action = "check",
                    "remote worker still in its initial prover-tree sync"),
                _ => debug!(core_id, filter = %filter_hex, "remote worker starting; its Respawn waits"),
            }
            return;
        }
        owed.started(core_id, now);
        let retry = owed.backoff;
        owed.next_at = now + retry;
        owed.backoff = (owed.backoff * 2).min(RESPAWN_RETRY_MAX);
        match owed.outage.observe(now, false) {
            Some(OutageEvent::Began) => warn!(core_id, endpoint = %endpoint, filter = %filter_hex,
                error_class = error.as_str(), error = %message, retry_secs = retry.as_secs(),
                scope = "local", action = "check",
                "remote worker Respawn RPC failed; the worker stays idle while its allocation counts as served; \
                 retrying with backoff; {}", WORKER_REMEDY),
            Some(OutageEvent::Continues { secs, failures }) => warn!(core_id, endpoint = %endpoint,
                filter = %filter_hex, error_class = error.as_str(), error = %message, secs, failures,
                retry_secs = retry.as_secs(), scope = "local", action = "check",
                "remote worker still has not taken its Respawn"),
            _ => debug!(core_id, error_class = error.as_str(), error = %message, "remote worker Respawn retry failed"),
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

    /// Whether a standalone worker prepares `filter`'s storage confirm: the
    /// one running it, or, when `snapshots` names the shard's recorded
    /// snapshot (hash storage proofs), the one assigned it before it runs it
    /// (a joining seat). That worker encodes from the snapshot, synced from an
    /// archive, so the replicas it later proves land in its own store.
    pub fn prepares_storage_confirm(&self, filter: &[u8], snapshots: &[crate::prover_pipeline::SnapshotSources]) -> bool {
        self.workers
            .lock()
            .map(|workers| workers.values().any(|w| Self::prepares(w, filter, snapshots)))
            .unwrap_or(false)
    }

    fn prepares(worker: &RemoteWorkerState, filter: &[u8], snapshots: &[crate::prover_pipeline::SnapshotSources]) -> bool {
        Self::runs(worker, filter)
            || (!filter.is_empty() && worker.filter.as_slice() == filter
                && snapshots.iter().any(|(shard, _)| shard.as_slice() == filter))
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
    /// large shard is slow; the caller bounds concurrency and, by `timeout`,
    /// the wait.
    pub async fn prepare_storage_confirm(
        &self,
        filter: &[u8],
        targets: &[Vec<u8>],
        frame_number: u64,
        timeout: std::time::Duration,
        snapshots: &[crate::prover_pipeline::SnapshotSources],
    ) -> Result<Option<Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>>> {
        let channel = {
            let workers = self.workers.lock().map_err(|_| QuilError::Internal("worker table poisoned".into()))?;
            let Some(worker) = workers.values().find(|w| Self::runs(w, filter))
                .or_else(|| workers.values().find(|w| Self::prepares(w, filter, snapshots)))
            else {
                return Ok(None);
            };
            worker.channel.clone().ok_or_else(|| {
                QuilError::ExecutionUnavailable("worker serving this filter is not connected".into())
            })?
        };
        let mut client = quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(channel)
            .max_decoding_message_size(16 << 20);
        let response = match tokio::time::timeout(
            timeout,
            client.prepare_storage_confirm(quil_types::proto::node::PrepareStorageConfirmRequest {
                filter: filter.to_vec(),
                frame_number,
                targets: targets.to_vec(),
                snapshot_sources: quil_execution::global_intrinsic::storage_snapshot::encode_plan(snapshots),
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
        // The worker encodes its shard and the shards a pending split or
        // merge creates from it (`targets`); any other group is not its own.
        if roots.iter().any(|group| group.filter != filter && !targets.contains(&group.filter)) {
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
            Ok(response) => {
                let response = response.into_inner();
                if response.deferred {
                    info!(core_id, filter = hex::encode(filter),
                        "remote worker took its Respawn while starting; it applies it once its initial prover-tree sync completes");
                } else if response.kept {
                    info!(core_id, filter = hex::encode(filter), "remote worker already runs its filter; its engine is kept");
                } else {
                    info!(core_id, filter = hex::encode(filter), "remote worker respawned");
                }
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
    /// Hand the request to the standalone worker over `EvictPayload` without
    /// waiting: the allocator calls this under its locks and repeats it at
    /// its interval, so a worker that is not connected, fails or times out
    /// is asked again then.
    fn evict_payload(&self, core_id: u32, keep: Vec<Vec<u8>>) -> Result<()> {
        let channel = {
            let workers = self.workers.lock().map_err(|_| QuilError::Internal("worker table poisoned".into()))?;
            let worker = workers
                .get(&core_id)
                .ok_or_else(|| QuilError::InvalidArgument("eviction worker missing".into()))?;
            worker.channel.clone()
        };
        let Some(channel) = channel else {
            debug!(core_id, "remote worker not connected; payload eviction waits for the next interval");
            return Ok(());
        };
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| QuilError::ExecutionUnavailable("payload eviction needs a runtime".into()))?;
        let unsupported = self.evict_unsupported.clone();
        runtime.spawn(async move {
            let mut client = quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(channel)
                .max_decoding_message_size(64 << 10);
            let request = quil_types::proto::node::EvictPayloadRequest { keep };
            match tokio::time::timeout(EVICT_PAYLOAD_TIMEOUT, client.evict_payload(request)).await {
                Ok(Ok(response)) => {
                    if let Ok(mut unsupported) = unsupported.lock() {
                        unsupported.remove(&core_id);
                    }
                    let response = response.into_inner();
                    debug!(core_id, started = response.started, deferred = %response.deferred, "remote worker answered payload eviction");
                }
                Ok(Err(status)) if status.code() == tonic::Code::Unimplemented => {
                    if unsupported.lock().is_ok_and(|mut unsupported| unsupported.insert(core_id)) {
                        info!(core_id, "remote worker keeps the payload of shards it left until it is upgraded");
                    }
                }
                Ok(Err(status)) if status.code() == tonic::Code::Unavailable
                    && status.message() == crate::worker_node::WORKER_STARTING =>
                    debug!(core_id, "remote worker starting; payload eviction asked again next interval"),
                Ok(Err(status)) => warn!(core_id, code = ?status.code(), message = status.message(),
                    "remote worker payload eviction request failed; asking again next interval"),
                Err(_) => warn!(core_id, timeout_s = EVICT_PAYLOAD_TIMEOUT.as_secs(),
                    "remote worker payload eviction request timed out; asking again next interval"),
            }
        });
        Ok(())
    }

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
                if w.owed.as_ref().is_some_and(|owed| !(w.wants_consensus && owed.filter == filter)) {
                    w.owed = None;
                }
                if w.lost.as_ref().is_some_and(|lost| lost.filter != filter) {
                    w.lost = None;
                }
                match w.channel.clone() {
                    // Another Respawn is in flight: this one goes after it,
                    // asking first (`reconcile_respawns`), so the older one
                    // cannot land last.
                    Some(_) if w.wants_consensus && w.respawns_in_flight > 0 => {
                        if w.owed.is_none() {
                            w.owed = Some(OwedRespawn::new(filter, Instant::now()));
                        }
                        Some(None)
                    }
                    // The Respawn below is in flight from here, so a report
                    // of the old engine does not count as a lost assignment.
                    Some(channel) if w.wants_consensus => Some(Some((RespawnInFlight::begin(&self.workers, w), channel))),
                    Some(_) => Some(None),
                    None => None,
                }
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
        let Some(send) = connected else {
            // Worker hasn't connected yet. The next `connect_all` /
            // reconnect cycle is responsible for re-issuing the
            // Respawn once the channel comes up.
            info!(
                core_id,
                filter = hex::encode(filter),
                "remote worker not yet connected — Respawn deferred"
            );
            return Ok(());
        };
        let Some((in_flight, channel)) = send else {
            info!(core_id, filter = hex::encode(filter), "remote worker Respawn queued behind the one in flight");
            return Ok(());
        };

        // Fire the Respawn RPC. set_worker_filter is sync but invoked
        // from async contexts; spawn the call so this returns
        // immediately and the lifecycle loop doesn't block on a
        // potentially slow worker. A failure leaves the Respawn owed;
        // the connect tick re-sends it (`reconcile_respawns`).
        let filter_owned = filter.to_vec();
        tokio::spawn(async move {
            let outcome = respawn_rpc(channel, &filter_owned).await;
            Self::settle_respawn(in_flight, &filter_owned, outcome, Instant::now());
        });
        Ok(())
    }

    fn deallocate_worker(&self, core_id: u32) -> Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if let Some(w) = workers.get_mut(&core_id) {
            w.quote_binding = std::sync::Arc::new(());
            w.filter.clear();
            w.owed = None;
            w.lost = None;
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

    /// The reports `refresh_executions` fetched, for workers still running
    /// the filter they were fetched for.
    fn worker_execution(&self) -> Vec<(u32, Vec<u8>, quil_types::proto::node::WorkerExecution)> {
        let (Ok(workers), Ok(executions)) = (self.workers.lock(), self.executions.lock()) else {
            return Vec::new();
        };
        executions
            .iter()
            .filter(|(core_id, (filter, _))| workers.get(core_id).is_some_and(|w| Self::runs(w, filter)))
            .map(|(core_id, (filter, execution))| (*core_id, filter.clone(), execution.clone()))
            .collect()
    }

    /// The workers `refresh_executions` found unanswered, still running the
    /// filter they were asked for.
    fn unanswered_workers(&self) -> Vec<(u32, Vec<u8>, &'static str)> {
        let (Ok(workers), Ok(unanswered)) = (self.workers.lock(), self.unanswered.lock()) else {
            return Vec::new();
        };
        unanswered
            .iter()
            .filter(|(core_id, (filter, _))| workers.get(core_id).is_some_and(|w| Self::runs(w, filter)))
            .map(|(core_id, (filter, reason))| (*core_id, filter.clone(), *reason))
            .collect()
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
        let changed = {
            let mut workers = self.workers.lock().unwrap();
            workers.get_mut(&core_id).is_some_and(|w| {
                let changed = w.manually_managed != manually_managed;
                w.manually_managed = manually_managed;
                changed
            })
        };
        // As the local manager logs it. This manager keeps no worker store,
        // so the mode lasts until the node restarts; `data_worker_filters`
        // is what pins a remote worker across restarts.
        if changed {
            info!(
                core_id,
                mode = if manually_managed { "manual" } else { "auto" },
                persisted = false,
                "worker management mode changed"
            );
        }
        Ok(())
    }

    fn set_allocated(&self, core_id: u32, allocated: bool) -> Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if let Some(w) = workers.get_mut(&core_id) {
            w.allocated = allocated;
            // A released allocation is owed no Respawn.
            if !allocated {
                w.owed = None;
            }
        }
        Ok(())
    }
}

/// Convert a libp2p multiaddr string to an HTTP endpoint.
/// `/ip4/192.168.1.10/tcp/32501` → `http://192.168.1.10:32501`
/// A worker's `execution` report with its timestamps moved from the
/// worker's clock (`worker_now_ms` when it answered) onto this node's
/// (`local_now_ms`), so its age reads the same on both machines.
fn on_local_clock(
    mut execution: quil_types::proto::node::WorkerExecution,
    worker_now_ms: u64,
    local_now_ms: u64,
) -> quil_types::proto::node::WorkerExecution {
    if worker_now_ms == 0 {
        return execution;
    }
    let rebase = |at: u64| if at == 0 { 0 } else { local_now_ms.saturating_sub(worker_now_ms.saturating_sub(at)) };
    execution.observed_unix_ms = rebase(execution.observed_unix_ms);
    execution.last_advance_unix_ms = rebase(execution.last_advance_unix_ms);
    execution.last_peer_vote_unix_ms = rebase(execution.last_peer_vote_unix_ms);
    // `host_started_unix_ms` and `engine_started_unix_ms` name the host and
    // engine; moved, they would differ between reports by the request's
    // latency, so they stay on the worker's clock.
    execution
}

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

/// Dial a remote worker's gRPC endpoint once, within `CONNECT_TIMEOUT`;
/// `connect_all`'s tick is the retry. When `tls` is set the dial is mTLS
/// (https): the master presents the node leaf cert and verifies the worker's
/// cert against the node CA — only node-key holders interoperate.
async fn connect_to_worker(
    endpoint: &str,
    tls: Option<&tonic::transport::ClientTlsConfig>,
) -> Result<Channel> {
    // tonic uses TLS based on the URI scheme + tls_config; switch http→https.
    let uri = if tls.is_some() {
        endpoint.replacen("http://", "https://", 1)
    } else {
        endpoint.to_string()
    };
    let mut ep = Channel::from_shared(uri)
        .map_err(|e| QuilError::Internal(format!("invalid endpoint: {}", e)))?
        .connect_timeout(CONNECT_TIMEOUT);
    if let Some(cfg) = tls {
        ep = ep
            .tls_config(cfg.clone())
            .map_err(|e| QuilError::Internal(format!("worker channel TLS: {}", e)))?;
    }
    ep.connect().await
        .map_err(|e| QuilError::Internal(format!("failed to connect: {}", crate::worker_node::error_chain(&e))))
}

/// A failed call's code and message, for the log.
fn status_text(status: &tonic::Status) -> String {
    format!("{:?}: {}", status.code(), status.message())
}

/// Send a Respawn of `filter`, bounded by `RESPAWN_TIMEOUT`. A worker build
/// without the answer's fields reads as respawned.
async fn respawn_rpc(channel: Channel, filter: &[u8]) -> RespawnOutcome {
    let mut client = quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(channel);
    let request = quil_types::proto::node::RespawnRequest { filter: filter.to_vec() };
    match tokio::time::timeout(RESPAWN_TIMEOUT, client.respawn(request)).await {
        Ok(Ok(response)) if response.get_ref().deferred => RespawnOutcome::Deferred,
        Ok(Ok(response)) if response.get_ref().kept => RespawnOutcome::AlreadyRuns,
        Ok(Ok(_)) => RespawnOutcome::Delivered,
        Ok(Err(status)) => RespawnOutcome::Failed(RespawnError::of(&status), status_text(&status)),
        Err(_) => RespawnOutcome::Failed(RespawnError::TimedOut, format!("no answer in {}s", RESPAWN_TIMEOUT.as_secs())),
    }
}

/// Re-send an owed Respawn of `filter` to worker `core_id`. Ask the worker
/// what it runs first (a failed RPC may have reached it) and send nothing
/// when it already runs `filter`, so a running engine is not restarted; a
/// build without the call cannot say, and is sent the Respawn it was owed.
/// Just before sending, check that `filter` is still its assignment.
async fn resend_respawn(
    workers: &Mutex<HashMap<u32, RemoteWorkerState>>,
    core_id: u32,
    channel: Channel,
    filter: &[u8],
) -> RespawnOutcome {
    let mut client = quil_types::proto::node::data_ipc_service_client::DataIpcServiceClient::new(channel.clone())
        .max_decoding_message_size(64 << 10);
    let answer = tokio::time::timeout(
        Duration::from_secs(3),
        client.get_worker_execution(quil_types::proto::node::GetWorkerExecutionRequest {}),
    )
    .await;
    match answer {
        Ok(Ok(response)) if response.get_ref().filter == filter => return RespawnOutcome::AlreadyRuns,
        Ok(Ok(_)) => {}
        Ok(Err(status)) if status.code() == tonic::Code::Unimplemented => {}
        Ok(Err(status)) => return RespawnOutcome::Failed(RespawnError::of(&status), status_text(&status)),
        Err(_) => return RespawnOutcome::Failed(RespawnError::TimedOut, "no answer to the execution request in 3s".into()),
    }
    let current = workers.lock().ok().is_some_and(|workers| {
        workers.get(&core_id).is_some_and(|w| RemoteWorkerManager::owes_consensus(w, filter))
    });
    if !current {
        return RespawnOutcome::Superseded;
    }
    respawn_rpc(channel, filter).await
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

    /// A joining seat's storage confirm goes to the worker assigned it once
    /// the shard's recorded snapshot is named (hash storage proofs): its
    /// replicas must land in that worker's store. Without one, only the
    /// worker running the shard prepares it.
    #[test]
    fn a_joining_seat_is_prepared_by_its_worker_from_the_recorded_snapshot() {
        let mgr = RemoteWorkerManager::new(vec![(1, "http://10.0.0.1:32501".into())], String::new(), None);
        let (joining, other) = (vec![0xBB; 32], vec![0xCC; 32]);
        mgr.set_worker_filter(1, &joining, false).unwrap();
        let snapshot = |shard: &[u8]| -> Vec<crate::prover_pipeline::SnapshotSources> { vec![(shard.to_vec(), Vec::new())] };
        assert!(!mgr.serves_filter(&joining));
        assert!(!mgr.prepares_storage_confirm(&joining, &[]), "no snapshot: not before it runs the shard");
        assert!(mgr.prepares_storage_confirm(&joining, &snapshot(&joining)));
        assert!(!mgr.prepares_storage_confirm(&other, &snapshot(&other)), "a shard it was not assigned");
        assert!(!mgr.prepares_storage_confirm(&joining, &snapshot(&other)), "another shard's snapshot");
        mgr.set_worker_filter(1, &joining, true).unwrap();
        assert!(mgr.prepares_storage_confirm(&joining, &[]), "the worker running it");
    }

    /// A mode toggle on a remote worker is logged on change, as the local
    /// manager logs it, and says it is not persisted.
    #[test]
    fn a_mode_toggle_is_logged_on_change_only() {
        #[derive(Clone, Default)]
        struct Lines(std::sync::Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Lines {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> { self.0.lock().unwrap().write(bytes) }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let mgr = RemoteWorkerManager::new(vec![(1, "http://10.0.0.1:32501".into())], String::new(), None);
        let lines = Lines::default();
        let writer = lines.clone();
        let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
        tracing::subscriber::with_default(subscriber, || {
            mgr.set_manually_managed(1, true).unwrap();
            mgr.set_manually_managed(1, true).unwrap();
            mgr.set_manually_managed(1, false).unwrap();
            mgr.set_manually_managed(99, true).unwrap();
        });
        let logged = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
        assert_eq!(logged.matches("worker management mode changed").count(), 2, "{logged}");
        assert!(logged.contains("mode=\"manual\"") || logged.contains("mode=manual"), "{logged}");
        assert!(logged.contains("persisted=false"), "{logged}");
        assert!(!mgr.range_workers().unwrap()[0].manually_managed);
    }
}


#[cfg(test)]
impl RemoteWorkerManager {
    /// Whether `core_id` is owed a Respawn, and how many are in flight.
    fn respawn_state(&self, core_id: u32) -> (bool, u32) {
        let workers = self.workers.lock().unwrap();
        workers.get(&core_id).map_or((false, 0), |w| (w.owed.is_some(), w.respawns_in_flight))
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
        /// The keep sets of eviction requests received.
        keeps: Arc<std::sync::Mutex<Vec<Vec<Vec<u8>>>>>,
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
            Ok(tonic::Response::new(node::RespawnResponse::default()))
        }
        async fn create_join_proof(&self, _: tonic::Request<node::CreateJoinProofRequest>) -> std::result::Result<tonic::Response<node::CreateJoinProofResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("not used by fee relay"))
        }
        async fn set_halted(&self, _: tonic::Request<node::SetHaltedRequest>) -> std::result::Result<tonic::Response<node::SetHaltedResponse>, tonic::Status> {
            Ok(tonic::Response::new(node::SetHaltedResponse {}))
        }
        /// Mode 8 answers for the requested shard and its targets, as a
        /// worker does; mode 9 adds a group for a shard it was not asked for.
        async fn prepare_storage_confirm(&self, request: tonic::Request<node::PrepareStorageConfirmRequest>) -> std::result::Result<tonic::Response<node::PrepareStorageConfirmResponse>, tonic::Status> {
            let mode = self.mode.load(Ordering::SeqCst);
            if !matches!(mode, 8 | 9) {
                return Err(tonic::Status::unimplemented("not used by fee relay"));
            }
            let request = request.into_inner();
            let mut groups: Vec<Vec<u8>> = std::iter::once(request.filter).chain(request.targets).collect();
            if mode == 9 {
                groups.push(vec![0xEE; 32]);
            }
            Ok(tonic::Response::new(node::PrepareStorageConfirmResponse {
                leaf_roots: groups
                    .into_iter()
                    .map(|filter| quil_execution::global_intrinsic::conversions::confirm_leaf_roots_to_proto(
                        &quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots { filter, entries: Vec::new() },
                    ))
                    .collect(),
            }))
        }
        /// Mode 5 is an older build without the call.
        async fn evict_payload(&self, request: tonic::Request<node::EvictPayloadRequest>)
            -> std::result::Result<tonic::Response<node::EvictPayloadResponse>, tonic::Status> {
            if self.mode.load(Ordering::SeqCst) == 5 {
                return Err(tonic::Status::unimplemented("older worker"));
            }
            self.keeps.lock().unwrap().push(request.into_inner().keep);
            Ok(tonic::Response::new(node::EvictPayloadResponse { started: true, deferred: String::new() }))
        }
        /// Mode 5 is an older build without the call, mode 6 never answers
        /// and mode 7 answers unavailable; otherwise the engine runs
        /// `[7; 32]`, blocked, observed a minute before the answer, on a
        /// clock an hour ahead of the master's.
        async fn get_worker_execution(&self, _: tonic::Request<node::GetWorkerExecutionRequest>)
            -> std::result::Result<tonic::Response<node::GetWorkerExecutionResponse>, tonic::Status> {
            match self.mode.load(Ordering::SeqCst) {
                5 => return Err(tonic::Status::unimplemented("older worker")),
                6 => std::future::pending::<()>().await,
                7 => return Err(tonic::Status::unavailable("worker going down")),
                _ => {}
            }
            let now = crate::worker_execution::now_ms() + 3_600_000;
            Ok(tonic::Response::new(node::GetWorkerExecutionResponse {
                filter: vec![7; 32],
                execution: Some(node::WorkerExecution { state: "blocked".into(), observed_unix_ms: now - 60_000, ..Default::default() }),
                now_unix_ms: now,
            }))
        }
    }

    /// Every time of a worker's report, the last vote it received from
    /// another member included, is read on this node's clock; none stays
    /// none, and the start times naming its host and engine stay as the
    /// worker reported them.
    #[test]
    fn a_report_is_moved_onto_the_local_clock() {
        let report = node::WorkerExecution { observed_unix_ms: 9_000, last_advance_unix_ms: 8_000,
            last_peer_vote_unix_ms: 7_000, own_votes: Some(0), host_started_unix_ms: 6_000,
            engine_started_unix_ms: 5_000, silent_ms: 4_000, ..Default::default() };
        let moved = on_local_clock(report, 10_000, 50_000);
        assert_eq!((moved.observed_unix_ms, moved.last_advance_unix_ms, moved.last_peer_vote_unix_ms),
            (49_000, 48_000, 47_000));
        assert_eq!((moved.own_votes, moved.host_started_unix_ms, moved.engine_started_unix_ms, moved.silent_ms),
            (Some(0), 6_000, 5_000, 4_000));
        assert_eq!(on_local_clock(node::WorkerExecution::default(), 10_000, 50_000).last_peer_vote_unix_ms, 0);
    }

    /// A standalone worker's execution report reaches the master on the
    /// master's clock, only while the worker runs the filter it reports;
    /// a build without the call leaves no report.
    #[tokio::test]
    async fn worker_execution_reports_come_from_the_worker_running_the_filter() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(0));
        let server = SnapshotServer {
            mode: mode.clone(),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            keeps: Default::default(),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(node::data_ipc_service_server::DataIpcServiceServer::new(server))
                .serve_with_incoming_shutdown(Incoming(listener), async { let _ = stopped.await; }).await.unwrap();
        });
        let manager = RemoteWorkerManager::new(vec![(1, endpoint)], String::new(), None);
        manager.connect_all().await;
        manager.set_worker_filter(1, &[8; 32], true).unwrap();
        manager.refresh_executions().await;
        assert!(manager.worker_execution().is_empty(), "a report for another filter is no report");

        manager.set_worker_filter(1, &[7; 32], true).unwrap();
        manager.refresh_executions().await;
        let reports = manager.worker_execution();
        assert_eq!(reports.len(), 1);
        let (core_id, filter, execution) = &reports[0];
        assert_eq!((*core_id, filter.as_slice(), execution.state.as_str()), (1, &[7u8; 32][..], "blocked"));
        let age = crate::worker_execution::now_ms().saturating_sub(execution.observed_unix_ms);
        assert!((59_000..=65_000).contains(&age), "a minute old on the master's clock: {age}");

        manager.set_worker_filter(1, &[7; 32], false).unwrap();
        assert!(manager.worker_execution().is_empty(), "a worker no longer running consensus reports nothing");

        manager.set_worker_filter(1, &[7; 32], true).unwrap();
        mode.store(5, Ordering::SeqCst);
        manager.refresh_executions().await;
        assert!(manager.worker_execution().is_empty(), "an older build leaves no report");
        stop.send(()).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), serving).await;
    }

    /// A standalone worker running consensus that stops answering its
    /// report request (no answer in time, or unavailable), or that the
    /// master never reached, is listed unanswered; one that answers, even
    /// from a build without the call, is not, nor is one no longer running
    /// consensus.
    #[tokio::test]
    async fn a_worker_that_does_not_answer_is_listed_unanswered() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(5));
        let server = SnapshotServer {
            mode: mode.clone(),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            keeps: Default::default(),
        };
        let serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(node::data_ipc_service_server::DataIpcServiceServer::new(server))
                .serve_with_incoming(Incoming(listener)).await.unwrap();
        });
        // Core 2's endpoint cannot be dialled (a reachable one that refuses
        // would be retried for seconds), so the master never connects to it.
        let manager = RemoteWorkerManager::new(vec![(1, endpoint), (2, "http://no such host".into())], String::new(), None);
        manager.connect_all().await;
        manager.set_worker_filter(1, &[7; 32], true).unwrap();
        manager.set_worker_filter(2, &[9; 32], true).unwrap();
        let listed = || {
            let mut listed = manager.unanswered_workers();
            listed.sort();
            listed
        };
        manager.refresh_executions().await;
        assert!(manager.worker_execution().is_empty());
        assert_eq!(listed(), vec![(2, vec![9; 32], NOT_CONNECTED)], "an older build answers");

        mode.store(0, Ordering::SeqCst);
        manager.refresh_executions().await;
        assert_eq!(manager.worker_execution().len(), 1);
        assert_eq!(listed(), vec![(2, vec![9; 32], NOT_CONNECTED)]);

        for silent in [6, 7] {
            mode.store(silent, Ordering::SeqCst);
            manager.refresh_executions().await;
            assert!(manager.worker_execution().is_empty(), "mode {silent}");
            assert_eq!(listed(), vec![(1, vec![7; 32], NO_ANSWER), (2, vec![9; 32], NOT_CONNECTED)], "mode {silent}");
        }

        manager.set_worker_filter(1, &[7; 32], false).unwrap();
        assert_eq!(listed(), vec![(2, vec![9; 32], NOT_CONNECTED)], "a worker no longer running consensus is not listed");
        serving.abort();
    }

    /// An eviction request reaches the standalone worker with its keep set
    /// and returns at once; a build without the call is noted once and asked
    /// again, and an unknown worker is an error.
    #[tokio::test]
    async fn payload_eviction_reaches_the_standalone_worker() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(0));
        let keeps: Arc<std::sync::Mutex<Vec<Vec<Vec<u8>>>>> = Default::default();
        let server = SnapshotServer {
            mode: mode.clone(),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            keeps: keeps.clone(),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(node::data_ipc_service_server::DataIpcServiceServer::new(server))
                .serve_with_incoming_shutdown(Incoming(listener), async { let _ = stopped.await; }).await.unwrap();
        });
        let manager = RemoteWorkerManager::new(vec![(1, endpoint), (2, "http://no such host".into())], String::new(), None);
        manager.connect_all().await;
        manager.set_worker_filter(1, &[7; 32], true).unwrap();
        async fn until(done: impl Fn() -> bool) {
            let started = std::time::Instant::now();
            while !done() && started.elapsed() < std::time::Duration::from_secs(5) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        let keep = vec![vec![7; 32], vec![7; 33]];
        manager.evict_payload(1, keep.clone()).unwrap();
        until(|| !keeps.lock().unwrap().is_empty()).await;
        assert_eq!(*keeps.lock().unwrap(), vec![keep.clone()], "the worker receives the keep set");

        mode.store(5, Ordering::SeqCst);
        manager.evict_payload(1, keep.clone()).unwrap();
        until(|| manager.evict_unsupported.lock().unwrap().contains(&1)).await;
        assert!(manager.evict_unsupported.lock().unwrap().contains(&1), "an older build is noted");
        mode.store(0, Ordering::SeqCst);
        manager.evict_payload(1, keep.clone()).unwrap();
        until(|| !manager.evict_unsupported.lock().unwrap().contains(&1)).await;
        assert!(!manager.evict_unsupported.lock().unwrap().contains(&1), "an upgraded worker is asked again");
        assert_eq!(keeps.lock().unwrap().len(), 2);

        manager.evict_payload(2, keep.clone()).unwrap();
        assert!(manager.evict_payload(9, keep).is_err(), "an unknown worker");
        stop.send(()).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), serving).await;
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
            keeps: Default::default(),
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

    /// A worker's leaf roots for the shards a pending change creates from its
    /// shard are accepted with its own; a group for any other shard is not.
    #[tokio::test]
    async fn a_worker_s_leaf_roots_for_its_pre_registration_targets_are_accepted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(8));
        let server = SnapshotServer {
            mode: mode.clone(),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            keeps: Default::default(),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(node::data_ipc_service_server::DataIpcServiceServer::new(server))
                .serve_with_incoming_shutdown(Incoming(listener), async { let _ = stopped.await; }).await.unwrap();
        });
        let manager = RemoteWorkerManager::new(vec![(1, endpoint)], String::new(), None);
        manager.connect_all().await;
        manager.set_worker_filter(1, &[7; 32], true).unwrap();
        let targets = vec![vec![10; 32], vec![11; 32]];
        let roots = manager
            .prepare_storage_confirm(&[7; 32], &targets, 720, std::time::Duration::from_secs(10), &[])
            .await
            .unwrap()
            .expect("the worker runs the shard");
        assert_eq!(
            roots.iter().map(|group| group.filter.clone()).collect::<Vec<_>>(),
            vec![vec![7; 32], vec![10; 32], vec![11; 32]],
            "its shard and the shards a split creates from it"
        );
        mode.store(9, Ordering::SeqCst);
        assert!(manager
            .prepare_storage_confirm(&[7; 32], &targets, 720, std::time::Duration::from_secs(10), &[])
            .await
            .unwrap_err()
            .is_execution_unavailable(), "a group for a shard it was not asked for");
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
        let server = SnapshotServer { mode: mode.clone(), entered: entered.clone(), release: release.clone(), keeps: Default::default() };
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

    /// A standalone worker that records the Respawns it is sent and
    /// reports the filter its engine runs (none until a Respawn). While
    /// `hold` is set, its report waits for `release`, after `entered`;
    /// while `starting` is set, it takes a Respawn for its ready point;
    /// while `exits` is set, its engine exits right after each Respawn.
    #[derive(Clone, Default)]
    struct AssignedWorker {
        runs: Arc<std::sync::Mutex<Vec<u8>>>,
        respawns: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        starting: Arc<std::sync::atomic::AtomicBool>,
        exits: Arc<std::sync::atomic::AtomicBool>,
        hold: Arc<std::sync::atomic::AtomicBool>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }
    #[tonic::async_trait]
    impl node::data_ipc_service_server::DataIpcService for AssignedWorker {
        async fn deliver_shard_consensus(&self, _: tonic::Request<node::DeliverShardConsensusRequest>)
            -> std::result::Result<tonic::Response<node::DeliverShardConsensusResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("test server"))
        }
        async fn get_app_fee_snapshot(&self, _: tonic::Request<node::GetAppFeeSnapshotRequest>)
            -> std::result::Result<tonic::Response<node::GetAppFeeSnapshotResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("test server"))
        }
        async fn evict_payload(&self, _: tonic::Request<node::EvictPayloadRequest>)
            -> std::result::Result<tonic::Response<node::EvictPayloadResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("test server"))
        }
        async fn respawn(&self, request: tonic::Request<node::RespawnRequest>) -> std::result::Result<tonic::Response<node::RespawnResponse>, tonic::Status> {
            let filter = request.into_inner().filter;
            self.respawns.lock().unwrap().push(filter.clone());
            let deferred = self.starting.load(Ordering::SeqCst);
            if !deferred && !self.exits.load(Ordering::SeqCst) {
                *self.runs.lock().unwrap() = filter;
            }
            Ok(tonic::Response::new(node::RespawnResponse { deferred, kept: false }))
        }
        async fn create_join_proof(&self, _: tonic::Request<node::CreateJoinProofRequest>) -> std::result::Result<tonic::Response<node::CreateJoinProofResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("test server"))
        }
        async fn set_halted(&self, _: tonic::Request<node::SetHaltedRequest>) -> std::result::Result<tonic::Response<node::SetHaltedResponse>, tonic::Status> {
            Ok(tonic::Response::new(node::SetHaltedResponse {}))
        }
        async fn prepare_storage_confirm(&self, _: tonic::Request<node::PrepareStorageConfirmRequest>) -> std::result::Result<tonic::Response<node::PrepareStorageConfirmResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("test server"))
        }
        async fn get_worker_execution(&self, _: tonic::Request<node::GetWorkerExecutionRequest>)
            -> std::result::Result<tonic::Response<node::GetWorkerExecutionResponse>, tonic::Status> {
            if self.hold.load(Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            let filter = self.runs.lock().unwrap().clone();
            let now = crate::worker_execution::now_ms();
            let execution = (!filter.is_empty())
                .then(|| node::WorkerExecution { state: "running".into(), observed_unix_ms: now, ..Default::default() });
            Ok(tonic::Response::new(node::GetWorkerExecutionResponse { filter, execution, now_unix_ms: now }))
        }
    }

    fn serve_assigned(listener: tokio::net::TcpListener, worker: AssignedWorker)
        -> (tokio::sync::oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(node::data_ipc_service_server::DataIpcServiceServer::new(worker))
                .serve_with_incoming_shutdown(Incoming(listener), async { let _ = stopped.await; }).await.unwrap();
        });
        (stop, serving)
    }

    async fn stop_serving(stop: tokio::sync::oneshot::Sender<()>, mut serving: tokio::task::JoinHandle<()>) {
        let _ = stop.send(());
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut serving).await.is_err() {
            serving.abort();
            let _ = serving.await;
        }
    }

    /// Wait up to five seconds for `done`.
    async fn eventually(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..250 {
            if done() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        done()
    }

    /// A connected worker assigned and started, its Respawn delivered.
    async fn assigned(worker: &AssignedWorker) -> (RemoteWorkerManager, tokio::sync::oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (stop, serving) = serve_assigned(listener, worker.clone());
        let manager = RemoteWorkerManager::new(vec![(1, endpoint)], String::new(), None);
        manager.connect_all().await;
        manager.set_worker_filter(1, &[7; 32], true).unwrap();
        assert!(eventually(|| worker.respawns.lock().unwrap().len() == 1 && manager.respawn_state(1).1 == 0).await);
        (manager, stop, serving)
    }

    /// A Respawn that fails while the worker is down is owed, and sent once
    /// the worker is back, after its backoff: the worker is not left idle
    /// while its allocation counts as served.
    #[tokio::test]
    async fn a_respawn_lost_while_the_worker_was_down_is_sent_again() {
        let logs = crate::outage::test_logs::CapturedLogs::default();
        let _guard = logs.install();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let worker = AssignedWorker::default();
        let (stop, serving) = serve_assigned(listener, worker.clone());
        let manager = RemoteWorkerManager::new(vec![(1, format!("http://{address}"))], String::new(), None);
        manager.connect_all().await;
        assert_eq!(manager.check_workers_connected().unwrap(), vec![1]);
        stop_serving(stop, serving).await;

        manager.set_worker_filter(1, &[7; 32], true).unwrap();
        assert!(eventually(|| manager.respawn_state(1) == (true, 0)).await, "the failed Respawn is owed");
        assert!(worker.respawns.lock().unwrap().is_empty());

        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        let (stop, serving) = serve_assigned(listener, worker.clone());
        manager.reconcile_respawns_at(std::time::Instant::now()).await;
        assert!(worker.respawns.lock().unwrap().is_empty(), "not before its backoff");
        let mut later = std::time::Instant::now();
        for _ in 0..5 {
            later += std::time::Duration::from_secs(600);
            manager.reconcile_respawns_at(later).await;
            if !manager.respawn_state(1).0 {
                break;
            }
        }
        assert_eq!(*worker.respawns.lock().unwrap(), vec![vec![7u8; 32]]);
        assert_eq!(manager.respawn_state(1), (false, 0));

        manager.refresh_executions().await;
        manager.reconcile_respawns_at(later + std::time::Duration::from_secs(600)).await;
        assert_eq!(worker.respawns.lock().unwrap().len(), 1, "a worker running its filter is not respawned again");
        let failed = logs.lines_with("remote worker Respawn RPC failed");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert!(failed[0].contains("core_id=1") && failed[0].contains(&address.to_string()), "{}", failed[0]);
        assert_eq!(logs.lines_with("remote worker respawned after").len(), 1);
        stop_serving(stop, serving).await;
    }

    /// A worker that reports running no filter while its allocation is
    /// active (it restarted) is sent its Respawn again.
    #[tokio::test]
    async fn a_restarted_worker_running_nothing_is_sent_its_filter_again() {
        let worker = AssignedWorker::default();
        let (manager, stop, serving) = assigned(&worker).await;
        worker.runs.lock().unwrap().clear();
        manager.refresh_executions().await;
        assert_eq!(manager.respawn_state(1), (true, 0), "a lost assignment is owed");
        manager.reconcile_respawns_at(std::time::Instant::now()).await;
        assert_eq!(*worker.respawns.lock().unwrap(), vec![vec![7u8; 32]; 2]);
        assert_eq!(manager.respawn_state(1), (false, 0));
        stop_serving(stop, serving).await;
    }

    /// A worker that reports running its filter is never respawned.
    #[tokio::test]
    async fn a_worker_running_its_filter_is_not_respawned() {
        let worker = AssignedWorker::default();
        let (manager, stop, serving) = assigned(&worker).await;
        manager.refresh_executions().await;
        assert_eq!(manager.respawn_state(1), (false, 0));
        manager.reconcile_respawns_at(std::time::Instant::now() + std::time::Duration::from_secs(600)).await;
        assert_eq!(worker.respawns.lock().unwrap().len(), 1);
        stop_serving(stop, serving).await;
    }

    /// A worker the master reaches with an active assignment it already
    /// runs (the master restarted) keeps its engine: no Respawn is sent.
    #[tokio::test]
    async fn a_worker_reached_running_its_filter_keeps_its_engine() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let worker = AssignedWorker::default();
        *worker.runs.lock().unwrap() = vec![7; 32];
        let (stop, serving) = serve_assigned(listener, worker.clone());
        let manager = RemoteWorkerManager::new(vec![(1, endpoint)], String::new(), None);
        manager.set_worker_filter(1, &[7; 32], true).unwrap();
        manager.connect_all().await;
        assert!(worker.respawns.lock().unwrap().is_empty(), "a running engine is not restarted");
        assert_eq!(manager.respawn_state(1), (false, 0));

        // One that runs nothing is sent its Respawn.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let idle = AssignedWorker::default();
        let (stop_idle, serving_idle) = serve_assigned(listener, idle.clone());
        let manager = RemoteWorkerManager::new(vec![(1, endpoint)], String::new(), None);
        manager.set_worker_filter(1, &[7; 32], true).unwrap();
        manager.connect_all().await;
        assert_eq!(*idle.respawns.lock().unwrap(), vec![vec![7u8; 32]]);
        stop_serving(stop, serving).await;
        stop_serving(stop_idle, serving_idle).await;
    }

    /// A Respawn a starting worker takes for its ready point is logged as
    /// taken, not as applied, and is no longer owed.
    #[tokio::test]
    async fn a_respawn_taken_while_starting_is_not_logged_as_applied() {
        let logs = crate::outage::test_logs::CapturedLogs::default();
        let _guard = logs.install();
        let worker = AssignedWorker::default();
        worker.starting.store(true, Ordering::SeqCst);
        let (manager, stop, serving) = assigned(&worker).await;
        let taken = logs.lines_with("remote worker took its Respawn while starting");
        assert_eq!(taken.len(), 1, "{taken:?}");
        assert!(logs.lines_with("remote worker respawned").is_empty(), "nothing was applied yet");
        assert_eq!(manager.respawn_state(1), (false, 0));
        stop_serving(stop, serving).await;
    }

    /// A worker whose engine exits right after each Respawn is sent it again
    /// at growing intervals, not at every 5 s refresh, with one warning for
    /// the loop; once its engine stays up for a minute the loop ends.
    #[tokio::test]
    async fn an_engine_that_keeps_exiting_is_respawned_with_backoff() {
        let logs = crate::outage::test_logs::CapturedLogs::default();
        let _guard = logs.install();
        let worker = AssignedWorker::default();
        worker.exits.store(true, Ordering::SeqCst);
        let (manager, stop, serving) = assigned(&worker).await;
        // Ahead of the real clock, so every report postdates the Respawns.
        let start = std::time::Instant::now() + std::time::Duration::from_secs(3600);
        let mut sent_at = Vec::new();
        for tick in 1..=120u64 {
            let now = start + std::time::Duration::from_secs(5 * tick);
            manager.refresh_executions_at(now).await;
            let before = worker.respawns.lock().unwrap().len();
            manager.reconcile_respawns_at(now).await;
            if worker.respawns.lock().unwrap().len() > before {
                sent_at.push(5 * tick);
            }
        }
        assert!((4..=10).contains(&sent_at.len()), "re-sent with backoff, not at the refresh cadence: {sent_at:?}");
        let gaps: Vec<u64> = sent_at.windows(2).map(|pair| pair[1] - pair[0]).collect();
        assert!(gaps.windows(2).all(|pair| pair[1] >= pair[0]), "intervals grow: {sent_at:?}");
        assert_eq!(logs.lines_with("engine exited again after its Respawn").len(), 1);
        assert_eq!(logs.lines_with("runs another filter or none").len(), 1, "the first loss only");

        worker.exits.store(false, Ordering::SeqCst);
        let mut tick = 120u64;
        while logs.lines_with("engine stays up again").is_empty() && tick < 400 {
            tick += 1;
            let now = start + std::time::Duration::from_secs(5 * tick);
            manager.refresh_executions_at(now).await;
            manager.reconcile_respawns_at(now).await;
        }
        assert_eq!(logs.lines_with("engine stays up again").len(), 1, "the loop ends once the engine stays up");
        stop_serving(stop, serving).await;
    }

    /// An owed Respawn follows the assignment: after a reassignment only the
    /// current filter is sent; after a deallocation or a released
    /// allocation, nothing.
    #[tokio::test]
    async fn an_owed_respawn_follows_the_assignment() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let worker = AssignedWorker::default();
        let (stop, serving) = serve_assigned(listener, worker.clone());
        let manager = RemoteWorkerManager::new(vec![(1, format!("http://{address}"))], String::new(), None);
        manager.connect_all().await;
        stop_serving(stop, serving).await;

        manager.set_worker_filter(1, &[7; 32], true).unwrap();
        assert!(eventually(|| manager.respawn_state(1) == (true, 0)).await, "the failed Respawn is owed");
        manager.set_worker_filter(1, &[8; 32], true).unwrap();
        assert!(eventually(|| manager.respawn_state(1) == (true, 0)).await, "the reassignment's failed Respawn is owed");
        let mut later = std::time::Instant::now();
        let restart = {
            let worker = worker.clone();
            move || {
                let worker = worker.clone();
                async move { serve_assigned(tokio::net::TcpListener::bind(address).await.unwrap(), worker) }
            }
        };
        let (stop, serving) = restart().await;
        for _ in 0..5 {
            later += std::time::Duration::from_secs(600);
            manager.reconcile_respawns_at(later).await;
            if !manager.respawn_state(1).0 {
                break;
            }
        }
        assert_eq!(*worker.respawns.lock().unwrap(), vec![vec![8u8; 32]], "only the current filter");
        stop_serving(stop, serving).await;

        manager.set_worker_filter(1, &[9; 32], true).unwrap();
        assert!(eventually(|| manager.respawn_state(1) == (true, 0)).await);
        manager.deallocate_worker(1).unwrap();
        let (stop, serving) = restart().await;
        for _ in 0..3 {
            later += std::time::Duration::from_secs(600);
            manager.reconcile_respawns_at(later).await;
        }
        assert_eq!(*worker.respawns.lock().unwrap(), vec![vec![8u8; 32]], "nothing after a deallocation");
        stop_serving(stop, serving).await;

        manager.set_worker_filter(1, &[10; 32], true).unwrap();
        assert!(eventually(|| manager.respawn_state(1) == (true, 0)).await);
        manager.set_allocated(1, false).unwrap();
        let (stop, serving) = restart().await;
        for _ in 0..3 {
            later += std::time::Duration::from_secs(600);
            manager.reconcile_respawns_at(later).await;
        }
        assert_eq!(*worker.respawns.lock().unwrap(), vec![vec![8u8; 32]], "nothing for a released allocation");
        assert_eq!(manager.respawn_state(1), (false, 0));
        stop_serving(stop, serving).await;
    }

    /// A reassignment while an owed Respawn is being asked about is sent
    /// after it, and the old filter is not sent over the new one.
    #[tokio::test]
    async fn a_reassignment_during_a_resend_is_not_overtaken() {
        let worker = AssignedWorker::default();
        let (manager, stop, serving) = assigned(&worker).await;
        let manager = Arc::new(manager);
        worker.runs.lock().unwrap().clear();
        manager.refresh_executions().await;
        assert_eq!(manager.respawn_state(1), (true, 0));
        worker.hold.store(true, Ordering::SeqCst);
        let reconciling = {
            let manager = manager.clone();
            tokio::spawn(async move { manager.reconcile_respawns_at(std::time::Instant::now()).await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), worker.entered.notified()).await.unwrap();
        manager.set_worker_filter(1, &[8; 32], true).unwrap();
        worker.hold.store(false, Ordering::SeqCst);
        worker.release.notify_one();
        reconciling.await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(*worker.respawns.lock().unwrap(), vec![vec![7u8; 32]], "the old filter is not sent");
        manager.reconcile_respawns_at(std::time::Instant::now() + std::time::Duration::from_secs(600)).await;
        assert_eq!(*worker.respawns.lock().unwrap(), vec![vec![7u8; 32], vec![8u8; 32]]);
        assert_eq!(manager.respawn_state(1), (false, 0));
        stop_serving(stop, serving).await;
    }
}
