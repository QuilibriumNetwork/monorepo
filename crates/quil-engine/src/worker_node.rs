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

/// Resolver replies being relayed to a shard's members at once.
static RESOLVER_RELAY_TASKS: crate::spawn_gate::SpawnGate =
    crate::spawn_gate::SpawnGate::new("resolver-relay", 64);

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
    /// mTLS materials for the master↔worker (DataIpc) channel, derived from the
    /// node's Falcon key (`quil_rpc::quil_tls::build_worker_channel_cert`) and
    /// threaded in by the node layer. When all three are `Some`, the DataIpc
    /// server REQUIRES a client cert chaining to `channel_tls_ca_pem` — so only a
    /// master holding the node's key can connect. `None` (e.g. tests) = plaintext.
    pub channel_tls_ca_pem: Option<String>,
    pub channel_tls_leaf_pem: Option<String>,
    pub channel_tls_key_pem: Option<String>,
    /// Parent process ID (for monitoring).
    pub parent_pid: Option<u32>,
    /// Whether app-shard consensus runs on commonware-simplex (CW) rather than
    /// the legacy path — mirrors thread mode's `config.engine.app_consensus_cw`.
    /// Threaded here so a cluster (separate-process) worker's `AppConsensusEngine`
    /// activates the same CW path the in-process thread worker does, instead of
    /// the previously hardcoded `false` (which pinned cluster workers to legacy).
    pub app_consensus_cw: bool,
    /// This worker's on-disk data directory. Used as the base for the app-shard
    /// commonware-simplex journal (`<data_dir>/cw-app-consensus/app-<addr>`) so a
    /// cluster worker's CW journal is PERSISTENT — matching thread mode. With no
    /// dir the runtime falls back to a random temp journal, whose prune path
    /// panics with `BlobMissing` (the ephemeral journal was never exercised
    /// before cluster CW reached a real 2-member committee). `None` keeps the old
    /// ephemeral behavior (tests / master-less bring-up).
    pub data_dir: Option<std::path::PathBuf>,
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

/// Answers the master's `ExportLogs` with this worker's own log lines, as
/// a stream of messages. The node layer, which owns the log files and
/// their reader, supplies it.
pub type LogExportSource = Arc<
    dyn Fn(
            quil_types::proto::node::ExportWorkerLogsRequest,
        ) -> mpsc::Receiver<
            std::result::Result<quil_types::proto::node::ExportWorkerLogsChunk, tonic::Status>,
        > + Send
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
    /// The tag naming this member as a shard CW transmission's addressee.
    local_cw_tag: [u8; crate::bitmasks::SHARD_CW_ADDRESSEE_LEN],
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
    /// Per-worker replica-store KV handle (the worker's own RocksDB). Required
    /// for storage-attestation generation: the attestation block seals + attests
    /// from a `ReplicaStore` backed by this. `None` (the old cluster default)
    /// meant the whole attestation block was skipped — the worker NEVER attested,
    /// so its shard reward was silently zeroed by the global proof-of-storage gate.
    kv_db: Option<Arc<dyn quil_types::store::KvDb>>,
    /// The replica epoch below which this worker's confirms have evicted
    /// `kv_db` (see `encode_worker_storage_confirm`).
    replicas_retired_below: Arc<std::sync::atomic::AtomicU64>,
    /// Current engine handle (set after Respawn).
    engine_handle: Arc<std::sync::Mutex<Option<AppEngineHandle>>>,
    /// Stop the old engine and its transport wait before rebinding this worker.
    engine_cancel: std::sync::Mutex<Option<CancellationToken>>,
    respawn_lock: tokio::sync::Mutex<()>,
    /// When the engine generation last changed: a payload eviction waits
    /// for the previous engine's detached tasks to finish with its scope.
    bound_since: std::sync::Mutex<std::time::Instant>,
    /// Set while this worker's payload eviction passes run.
    evicting: Arc<std::sync::atomic::AtomicBool>,
    /// The master's Respawn requests, and whether the worker has finished
    /// starting (its initial prover-tree sync). The listener binds before
    /// the sync; until then the calls that depend on its state answer
    /// `Unavailable` with [`WORKER_STARTING`], and a Respawn is kept for
    /// the ready point.
    respawns: Arc<RespawnQueue>,
    /// Channel for engine events back to the master stream.
    engine_event_tx: mpsc::UnboundedSender<crate::app_engine::AppEngineEvent>,
    /// Optional receiver for engine events — consumed by the
    /// publish pump when proxy mode is enabled. When `None`, the
    /// worker runs receive-only (legacy behavior).
    engine_event_rx:
        std::sync::Mutex<Option<mpsc::UnboundedReceiver<crate::app_engine::AppEngineEvent>>>,
    /// Optional publish path (via master's PubSubProxy). When set,
    /// engine-produced messages are forwarded to the master for
    /// broadcast.
    publish_fn: Option<PublishFn>,
    /// This worker's log lines for the master's diagnostics log bundles.
    log_export: Option<LogExportSource>,
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
    /// Peer-id → committee Falcon public-key, learned from inbound
    /// `GLOBAL_PEER_INFO`. Mirrors the master's PeerInfo cache: inbound app-shard
    /// CW messages (`shard_cw_bitmask`) carry only the gossip sender's PeerId,
    /// but the engine's `CwIn` handler needs the raw committee key
    /// (`FalconPublicKey::from_bytes`) and DROPS any message whose `from` doesn't
    /// resolve. Without this a cluster worker would receive CW votes and silently
    /// drop every one → its simplex engine never reaches quorum. Only a key the
    /// peer ID is derived from is learned ([`learn_peer_key`]); the flag marks
    /// keys a CW message used since the map was last pruned.
    peer_key_by_id: std::sync::Mutex<std::collections::HashMap<Vec<u8>, (Vec<u8>, bool)>>,
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
    /// Repopulate the prover-registry cache from the just-synced store. The
    /// trait `ProverRegistry::refresh()` is a deliberate no-op (avoids O(N)
    /// rescans on the shared registry), so a cluster worker — which owns its
    /// registry and must reload it after a prover-tree sync — needs a real
    /// `refresh_from_store` hook. Without it the worker's registry stays empty
    /// and `build_app_committee` fails ("this node's key not in the active
    /// set"), leaving the shard engine in passive mode.
    registry_refresh: Option<Arc<dyn Fn() -> Result<()> + Send + Sync>>,
    storage_history_source: Option<crate::storage_history::GlobalVertexProofSource>,
    global_anchor_source: Option<crate::global_anchor::GlobalAnchorSource>,
    delivery_frame_source: Option<crate::app_engine::DeliveryFrameSource>,
    outgoing_history_source: Option<crate::app_handoff::OutgoingHistorySource>,
    /// Cooldown frame to avoid sync-storms: after a sync attempt,
    /// skip further attempts until frame_number >= cooldown_until.
    sync_cooldown_until: std::sync::atomic::AtomicU64,
    /// The prover-tree roots (phase 0 = `prover_tree_commitment`, phases
    /// 1/2/3 = `prover_tree_aux_roots`) from the most recent global frame
    /// header the worker has seen on the master stream. The periodic
    /// background sync uses these as its anchor so it verifies the peer's
    /// served tree against a consensus-certified root instead of blindly
    /// trusting the peer. Empty until the first global frame
    /// arrives — the periodic sync falls back to trust-the-peer only for
    /// that initial window.
    latest_prover_tree_anchor: std::sync::Mutex<Vec<Vec<u8>>>,
    /// The master's calls that act as the node: resolver messages it
    /// delivers directly, and GLOBAL submissions it sends on.
    master_relay: Arc<MasterRelay>,
}

/// How long a master without the relay is not asked again.
const MASTER_RELAY_RETRY_AFTER: Duration = Duration::from_secs(600);
/// How long a relayed send may take: the master's own direct send times out
/// after five seconds.
const MASTER_RELAY_TIMEOUT: Duration = Duration::from_secs(8);

type MasterClient = quil_types::proto::global::global_service_client::GlobalServiceClient<
    tonic::transport::Channel,
>;

/// A standalone worker's channel to its master's `GlobalService` calls that
/// act as the node. The worker connects under a synthetic identity: members
/// cannot attribute its connections to its committee key, and it has no
/// archive transport of its own; its master holds both. Reconnected after a
/// failure.
pub(crate) struct MasterRelay {
    factory: Option<MasterChannelFactory>,
    client: tokio::sync::Mutex<Option<MasterClient>>,
    /// When the master last answered that it lacks the direct relay (an older
    /// build): resolver messages go to the topic for a while.
    direct_unsupported: std::sync::Mutex<Option<std::time::Instant>>,
    /// When the master last answered that it cannot take GLOBAL submissions.
    submit_unsupported: std::sync::Mutex<Option<std::time::Instant>>,
    /// When a reward proof was last lost, for a warning at most once a minute.
    proof_lost_warned: std::sync::Mutex<Option<std::time::Instant>>,
}

/// What became of a GLOBAL submission handed to the master.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MasterSubmission {
    /// Queued for the archives.
    Queued,
    /// Held back by the master's coverage halt.
    Held,
    /// The master refused it as not a worker submission.
    Refused,
    /// Not delivered: no master channel, a master without the call, or a
    /// failure.
    Unavailable,
}

impl MasterRelay {
    pub(crate) fn new(factory: Option<MasterChannelFactory>) -> Self {
        Self {
            factory,
            client: tokio::sync::Mutex::new(None),
            direct_unsupported: std::sync::Mutex::new(None),
            submit_unsupported: std::sync::Mutex::new(None),
            proof_lost_warned: std::sync::Mutex::new(None),
        }
    }

    fn recently(marker: &std::sync::Mutex<Option<std::time::Instant>>) -> bool {
        marker
            .lock()
            .unwrap()
            .is_some_and(|since| since.elapsed() < MASTER_RELAY_RETRY_AFTER)
    }

    async fn client(&self) -> Option<MasterClient> {
        let factory = self.factory.clone()?;
        let mut client = self.client.lock().await;
        if client.is_none() {
            let Ok(Ok(channel)) = tokio::time::timeout(MASTER_RELAY_TIMEOUT, factory()).await
            else {
                return None;
            };
            *client = Some(MasterClient::new(channel));
        }
        client.clone()
    }

    async fn reconnect(&self) {
        *self.client.lock().await = None;
    }

    /// Have the master deliver a resolver message directly to the committee
    /// members it names. False: send it to the topic (no master channel, a
    /// master without the relay, a failure, or a recipient the master could
    /// not reach).
    async fn relay_direct(
        &self,
        filter: Vec<u8>,
        channel: u64,
        data: Vec<u8>,
        recipients: Vec<Vec<u8>>,
    ) -> bool {
        if Self::recently(&self.direct_unsupported) {
            return false;
        }
        let Some(mut client) = self.client().await else {
            return false;
        };
        let request = quil_types::proto::global::SendShardConsensusDirectRequest {
            filter,
            channel,
            data,
            recipients,
        };
        match tokio::time::timeout(
            MASTER_RELAY_TIMEOUT,
            client.send_shard_consensus_direct(request),
        )
        .await
        {
            Ok(Ok(response)) => response.into_inner().delivered,
            Ok(Err(status)) if status.code() == tonic::Code::Unimplemented => {
                *self.direct_unsupported.lock().unwrap() = Some(std::time::Instant::now());
                false
            }
            _ => {
                self.reconnect().await;
                false
            }
        }
    }

    /// Hand one canonical GLOBAL request (a certified shard frame header or a
    /// committee-handoff submission) to the master to send on.
    pub(crate) async fn submit(&self, core_id: u32, request: Vec<u8>) -> MasterSubmission {
        if Self::recently(&self.submit_unsupported) {
            return MasterSubmission::Unavailable;
        }
        let Some(mut client) = self.client().await else {
            return MasterSubmission::Unavailable;
        };
        let request =
            quil_types::proto::global::SubmitWorkerProverMessageRequest { core_id, request };
        match tokio::time::timeout(
            MASTER_RELAY_TIMEOUT,
            client.submit_worker_prover_message(request),
        )
        .await
        {
            Ok(Ok(response)) if response.get_ref().accepted => MasterSubmission::Queued,
            Ok(Ok(_)) => MasterSubmission::Held,
            Ok(Err(status)) if status.code() == tonic::Code::InvalidArgument => {
                MasterSubmission::Refused
            }
            Ok(Err(status)) if status.code() == tonic::Code::Unimplemented => {
                *self.submit_unsupported.lock().unwrap() = Some(std::time::Instant::now());
                MasterSubmission::Unavailable
            }
            _ => {
                self.reconnect().await;
                MasterSubmission::Unavailable
            }
        }
    }

    /// Historical legacy committees, rebuilt by the master (which holds the
    /// GLOBAL verifier and archive access).
    pub(crate) fn historical_committee_source(
        self: &Arc<Self>,
    ) -> crate::historical_committee::HistoricalCommitteeSource {
        let relay = self.clone();
        Arc::new(move |filter: Vec<u8>, anchor: u64| {
            let relay = relay.clone();
            Box::pin(async move {
                let unavailable =
                    |reason: String| quil_types::error::QuilError::ExecutionUnavailable(reason);
                let mut client = relay
                    .client()
                    .await
                    .ok_or_else(|| unavailable("no master channel".into()))?;
                let request =
                    quil_types::proto::global::GetHistoricalCommitteesRequest { filter, anchor };
                let response = tokio::time::timeout(
                    crate::historical_committee::HISTORICAL_COMMITTEE_TIMEOUT,
                    client.get_historical_committees(request),
                )
                .await
                .map_err(|_| unavailable("master historical committees timed out".into()))?
                .map_err(|status| unavailable(format!("master historical committees: {status}")))?;
                Ok(response
                    .into_inner()
                    .committees
                    .into_iter()
                    .map(|c| c.members)
                    .collect())
            })
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                                Output = quil_types::error::Result<Vec<Vec<Vec<u8>>>>,
                            > + Send,
                    >,
                >
        })
    }

    /// Whether to warn now about a lost reward proof (at most once a minute).
    fn warn_proof_lost(&self) -> bool {
        let mut last = self.proof_lost_warned.lock().unwrap();
        if last.is_some_and(|at| at.elapsed() < Duration::from_secs(60)) {
            return false;
        }
        *last = Some(std::time::Instant::now());
        true
    }
}

/// The engine's GLOBAL submission hook for a standalone worker: every
/// request goes to the master, which sends it through its archive transport
/// as it does its thread workers'. A finalized frame's header is the reward
/// proof GLOBAL credits the shard's provers from; without this, a shard
/// staffed only by standalone workers was never credited. Only a
/// committee-handoff submission falls back to GLOBAL_PROVER gossip when the
/// master cannot take it (its earlier path).
fn worker_global_submissions(
    relay: Arc<MasterRelay>,
    publish: Option<PublishFn>,
    core_id: u32,
    halted: Arc<std::sync::atomic::AtomicBool>,
) -> Arc<dyn Fn(Vec<u8>) + Send + Sync> {
    let handoff_prefix =
        quil_execution::global_intrinsic::handoff::TYPE_COMMITTEE_HANDOFF.to_be_bytes();
    let presence_prefix =
        quil_execution::global_intrinsic::handoff::TYPE_PRESENCE_REPORT.to_be_bytes();
    // Storage epoch proof parts are handed over from a storage job's thread,
    // outside the runtime.
    let runtime = tokio::runtime::Handle::try_current().ok();
    Arc::new(move |canonical: Vec<u8>| {
        if halted.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::debug!(
                core_id,
                "holding back GLOBAL submission — coverage halt active"
            );
            crate::presence_reports::publication_failed(&canonical);
            return;
        }
        let (relay, publish) = (relay.clone(), publish.clone());
        let spawn = |task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>| {
            match &runtime {
                Some(runtime) => drop(runtime.spawn(task)),
                None => drop(tokio::spawn(task)),
            }
        };
        spawn(Box::pin(async move {
            let handoff = canonical.starts_with(&handoff_prefix);
            let outcome = relay.submit(core_id, canonical.clone()).await;
            // A presence report goes only through the master, which answers
            // once it is published; one not taken gives its budget back.
            if canonical.starts_with(&presence_prefix) {
                if outcome != MasterSubmission::Queued {
                    crate::presence_reports::publication_failed(&canonical);
                    let filter = quil_execution::global_intrinsic::handoff::presence::PresenceReport::from_canonical_bytes(&canonical)
                        .map(|report| hex::encode(report.filter))
                        .unwrap_or_default();
                    warn!(core_id, kind = "presence_report", filter = %filter, outcome = ?outcome,
                        "presence report not published: the master held, refused or did not take it; \
                         the next look may build it again");
                }
                return;
            }
            if outcome != MasterSubmission::Unavailable {
                if outcome == MasterSubmission::Refused {
                    warn!(
                        core_id,
                        handoff, "master refused this worker's GLOBAL submission"
                    );
                }
                return;
            }
            if crate::storage_epoch_batch::is_seat_message(&canonical) {
                // Only the node proves a member's seats; the part is sent
                // again when the worker next retries.
                warn!(core_id, "storage epoch proof part not taken: the master is unreachable or an older build");
                return;
            }
            if !handoff {
                if relay.warn_proof_lost() {
                    warn!(core_id,
                        "reward proof not submitted: the master did not take it (unreachable, or an older build without SubmitWorkerProverMessage)");
                }
                return;
            }
            let Some(publish) = publish else { return };
            let bundle = quil_execution::message_envelope::CanonicalMessageRequest::wrap(canonical)
                .and_then(|request| {
                    quil_execution::message_envelope::CanonicalMessageBundle {
                        requests: vec![Some(request)],
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as i64,
                    }
                    .to_canonical_bytes()
                });
            match bundle {
                Ok(bytes) => publish(crate::bitmasks::GLOBAL_PROVER.to_vec(), bytes).await,
                Err(error) => warn!(%error, "committee handoff submission could not be encoded"),
            }
        }));
    })
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
        let channel_factory = config.channel_factory.clone();
        Self {
            config,
            cancel: CancellationToken::new(),
            clock_store,
            prover_registry,
            frame_prover,
            message_collector,
            fee_manager,
            local_prover_address,
            local_cw_tag: crate::bitmasks::shard_cw_addressee_tag(&local_bls_pubkey),
            local_bls_pubkey,
            bls_signer_factory,
            reward_greedy,
            min_active_provers_for_propose,
            hypergraph: None,
            execution_engine: None,
            inclusion_prover: None,
            kv_db: None,
            replicas_retired_below: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            engine_handle: Arc::new(std::sync::Mutex::new(None)),
            engine_cancel: std::sync::Mutex::new(None),
            respawn_lock: tokio::sync::Mutex::new(()),
            bound_since: std::sync::Mutex::new(std::time::Instant::now()),
            evicting: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            respawns: Arc::new(RespawnQueue::default()),
            engine_event_tx,
            engine_event_rx: std::sync::Mutex::new(Some(engine_event_rx)),
            publish_fn: None,
            log_export: None,
            worker_p2p: None,
            active_shard_subscriptions: std::sync::Mutex::new(Vec::new()),
            peer_key_by_id: std::sync::Mutex::new(std::collections::HashMap::new()),
            local_halted: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            prover_tree_syncer: None,
            registry_refresh: None,
            storage_history_source: None,
            global_anchor_source: None,
            delivery_frame_source: None,
            outgoing_history_source: None,
            sync_cooldown_until: std::sync::atomic::AtomicU64::new(0),
            latest_prover_tree_anchor: std::sync::Mutex::new(Vec::new()),
            master_relay: Arc::new(MasterRelay::new(channel_factory)),
        }
    }

    /// Have the master deliver a resolver message directly to the committee
    /// members it names (see [`MasterRelay::relay_direct`]).
    async fn relay_direct(
        &self,
        filter: Vec<u8>,
        channel: u64,
        data: Vec<u8>,
        recipients: Vec<Vec<u8>>,
    ) -> bool {
        self.master_relay
            .relay_direct(filter, channel, data, recipients)
            .await
    }

    /// Recover bounded historical registration proofs through the master.
    pub fn with_storage_history_source(
        mut self,
        source: crate::storage_history::GlobalVertexProofSource,
    ) -> Self {
        self.storage_history_source = Some(source);
        self
    }

    pub fn with_global_anchor_source(
        mut self,
        source: crate::global_anchor::GlobalAnchorSource,
    ) -> Self {
        self.global_anchor_source = Some(source);
        self
    }

    pub fn with_outgoing_history_source(
        mut self,
        source: crate::app_handoff::OutgoingHistorySource,
    ) -> Self {
        self.outgoing_history_source = Some(source);
        self
    }

    pub fn with_delivery_frame_source(
        mut self,
        source: crate::app_engine::DeliveryFrameSource,
    ) -> Self {
        self.delivery_frame_source = Some(source);
        self
    }

    /// Attach the per-worker CRDT, execution manager and inclusion prover.
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

    /// Attach the worker's own KV handle (its RocksDB) to back the
    /// storage-attestation `ReplicaStore`. Without this a cluster worker cannot
    /// seal replicas or emit a storage attestation, so its shard reward is
    /// silently withheld by the global proof-of-storage gate. The replica store
    /// uses a disjoint keyspace from the hypergraph store, so sharing the one DB
    /// is safe (mirrors the master/thread-worker single-DB layout).
    pub fn with_kv_db(mut self, kv_db: Arc<dyn quil_types::store::KvDb>) -> Self {
        self.kv_db = Some(kv_db);
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

    /// Supply a real prover-registry refresh (`refresh_from_store`) to run after
    /// a prover-tree sync. See `registry_refresh`.
    pub fn with_registry_refresh(mut self, f: Arc<dyn Fn() -> Result<()> + Send + Sync>) -> Self {
        self.registry_refresh = Some(f);
        self
    }

    /// Reload the prover registry from the synced store (real hook when wired,
    /// else the trait no-op).
    fn refresh_registry(&self) -> Result<()> {
        if let Some(f) = self.registry_refresh.as_ref() {
            f()
        } else {
            self.prover_registry.refresh()
        }
    }

    /// Supply the export of this worker's own log lines, which the master
    /// collects into its diagnostics log bundles (`ExportLogs`).
    pub fn with_log_export(mut self, export: LogExportSource) -> Self {
        self.log_export = Some(export);
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

        // The DataIPC listener binds first, so a bind failure shows at once
        // and the master's channel comes up while the sync below runs; the
        // calls that need the synced state answer `Unavailable` until the
        // worker is ready, and a Respawn waits for it (see `respawns`).
        let listen_addr: std::net::SocketAddr = self
            .config
            .listen_addr
            .parse()
            .map_err(|e| QuilError::Internal(format!("bad listen addr: {}", e)))?;
        // mTLS the master↔worker (DataIpc) channel when the node layer supplied
        // cert materials (cluster mode). The server then REQUIRES a client cert
        // chaining to our CA — only a master holding the node's Falcon key can
        // connect. `None` (tests / not wired) keeps the old plaintext behavior.
        let channel_tls: Option<tonic::transport::ServerTlsConfig> = match (
            self.config.channel_tls_ca_pem.clone(),
            self.config.channel_tls_leaf_pem.clone(),
            self.config.channel_tls_key_pem.clone(),
        ) {
            (Some(ca), Some(leaf), Some(key)) => Some(
                tonic::transport::ServerTlsConfig::new()
                    .identity(tonic::transport::Identity::from_pem(leaf, key))
                    .client_ca_root(tonic::transport::Certificate::from_pem(ca)),
            ),
            _ => None,
        };
        let server_handle = tokio::spawn(serve_data_ipc(
            self.clone(),
            listen_addr,
            channel_tls,
            self.cancel.clone(),
        ));

        // 0. Initial prover-tree sync from archive. Remote workers
        // start with an empty CRDT; without this sync the prover
        // registry is empty and the worker can't resolve leader
        // rotation or verify FrameHeaders. Mirrors Go's startup-time
        // `HyperSyncSelf` in `AppConsensusEngine.Start`.
        if let Some(syncer) = self.prover_tree_syncer.as_ref() {
            info!("performing initial prover-tree sync from archive");
            match syncer.sync_prover_tree(&[]).await {
                Ok(_converged) => match self.refresh_registry() {
                    Ok(()) => info!("initial prover-tree sync complete"),
                    Err(error) => {
                        warn!(%error, "initial prover registry refresh failed; will retry")
                    }
                },
                Err(e) => {
                    warn!(error = %e, "initial prover-tree sync failed — worker may have stale/empty prover state");
                }
            }
        } else {
            warn!("no prover-tree syncer wired — worker will run with stale/empty prover state");
        }

        // 0b. Periodic background prover-tree sync. The initial sync above runs
        // BEFORE the shard's provers have joined/activated, so the worker's
        // registry starts empty and its committee build fails. The
        // materialize-gated `maybe_sync_before_global_frame` path can't recover
        // it (it treats an empty local root as "matched" and skips), so a passive
        // worker would never re-sync — a deadlock. This loop pulls the latest
        // prover tree from an archive and refreshes the registry every 10-12 s,
        // so the registry becomes current and the engine's CW retry can
        // build the committee. Trust-the-peer sync (empty expected root).
        if let Some(syncer) = self.prover_tree_syncer.clone() {
            let this = self.clone();
            tokio::spawn(periodic_prover_tree_syncs(
                self.cancel.clone(),
                self.config.core_id,
                move || {
                    let (this, syncer) = (this.clone(), syncer.clone());
                    async move {
                        // Anchor against the last-seen global frame header's
                        // certified prover-tree roots. Empty
                        // only before the first global frame arrives, in which
                        // case we fall back to trust-the-peer for that window.
                        let anchor = { this.latest_prover_tree_anchor.lock().unwrap().clone() };
                        match syncer.sync_prover_tree(&anchor).await {
                            Ok(_) => {
                                if let Err(error) = this.refresh_registry() {
                                    tracing::warn!(%error, "periodic prover registry refresh failed");
                                }
                                None
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "periodic prover-tree sync failed");
                                Some(e.to_string())
                            }
                        }
                    }
                },
            ));
        }

        // Resolver traffic of this worker's shard, every 30 s.
        {
            let cancel = self.cancel.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                tick.tick().await;
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tick.tick() => crate::resolver_traffic::ResolverTraffic::process().log(),
                    }
                }
            });
        }

        // 1. Start parent process monitor (if parent PID given)
        if let Some(parent_pid) = self.config.parent_pid {
            let cancel = self.cancel.clone();
            // TODO
            tokio::spawn(async move {
                monitor_parent_process(parent_pid, cancel).await;
            });
        }

        // 2. Serve the DataIPC calls that need the synced state, and apply
        // a Respawn received while starting; the listener has been up since
        // the start of `run`.
        info!(core_id, listen = %listen_addr, "worker ready for DataIPC commands");
        self.respawns
            .set_ready(respawn_apply(self.clone()), core_id);

        // 3. Connect to master for message streaming. Skipped when no
        // factory is supplied (single-process tests, etc.).
        if let Some(factory) = self.config.channel_factory.clone() {
            let master_endpoint = self.config.master_endpoint.clone();
            let worker_ref = self.clone();
            let stream_cancel = self.cancel.clone();
            // TODO
            tokio::spawn(async move {
                stream_global_messages_from_master(
                    &master_endpoint,
                    factory,
                    worker_ref,
                    stream_cancel,
                )
                .await;
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
                // Captured so the pump can trigger a shard catch-up sync
                // on `AncestorSyncRequested`.
                let sync_for_pump = self.prover_tree_syncer.clone();
                let clock_for_pump = self.clock_store.clone();
                // Capture the requesting engine for each recovery task. A
                // respawn cancels that task instead of retargeting a new actor.
                let worker_for_pump = self.clone();
                // In-flight shard syncs keyed by filter. Gap detection
                // re-fires `AncestorSyncRequested` on every subsequent
                // frame until the cursor catches up, so without this the
                // pump would spawn an unbounded pile of concurrent syncs
                // against the archive. Shared with each spawned sync task
                // so it clears its own slot on completion.
                let syncing_filters: Arc<std::sync::Mutex<std::collections::HashSet<Vec<u8>>>> =
                    Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
                // TODO
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
                                    FullFrameProduced { filter, frame_data, .. } => {
                                        if halted {
                                            continue;
                                        }
                                        // Full AppShardFrame (header+requests) for
                                        // state distribution to followers/archives.
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
                                    // Commonware-simplex message → one shard CW
                                    // gossip topic, channel tagged in the payload.
                                    CwOut { filter, channel, bytes, recipients } => {
                                        if halted {
                                            continue;
                                        }
                                        if recipients.is_empty() {
                                            publish(
                                                crate::bitmasks::shard_cw_bitmask(&filter),
                                                crate::bitmasks::shard_cw_frame_payload(channel, &bytes),
                                            )
                                            .await;
                                            continue;
                                        }
                                        // A resolver message: through the master to just
                                        // its recipients, else the topic. Off the pump,
                                        // which also carries votes, since a relayed send
                                        // can wait out the master's timeout.
                                        // Either way it names its recipient, so other
                                        // members drop it unread.
                                        let worker = worker_for_pump.clone();
                                        let publish = publish.clone();
                                        // A peer's resolver requests drive these; each can wait
                                        // out the master's timeout. A dropped reply is re-asked.
                                        let Some(permit) = RESOLVER_RELAY_TASKS.try_enter() else { continue };
                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            let payload = crate::bitmasks::shard_cw_frame_for(channel, &bytes, &recipients);
                                            if !worker.relay_direct(filter.clone(), channel, bytes, recipients).await {
                                                publish(crate::bitmasks::shard_cw_bitmask(&filter), payload).await;
                                            }
                                        });
                                    }
                                    // Recover existing lineage through bounded
                                    // replay, or authenticate a headless worker's
                                    // archive checkpoint before fetching its trees.
                                    AncestorSyncRequested { filter, .. }
                                    | ShardDataBootstrapRequested { filter } => {
                                        if let Some(syncer) = sync_for_pump.clone() {
                                            // Dedup: skip if a sync for this
                                            // filter is already running.
                                            {
                                                let mut g = syncing_filters.lock().unwrap();
                                                if !g.insert(filter.clone()) {
                                                    continue;
                                                }
                                            }
                                            // Capture the requesting actor, not whichever
                                            // same-filter actor happens to exist at completion.
                                            let target = worker_for_pump.engine_handle.lock().unwrap().clone()
                                                .filter(|handle| handle.filter == filter);
                                            let cancel = worker_for_pump.engine_cancel.lock().unwrap().clone();
                                            let (Some(target), Some(cancel)) = (target, cancel) else {
                                                syncing_filters.lock().unwrap().remove(&filter);
                                                continue;
                                            };
                                            let local = match clock_for_pump.get_latest_shard_clock_frame(&filter) {
                                                Ok(frame) => Some(frame),
                                                Err(QuilError::NotFound(_)) => None,
                                                Err(error) => {
                                                    warn!(%error, "cannot read cluster shard lineage for recovery");
                                                    syncing_filters.lock().unwrap().remove(&filter);
                                                    continue;
                                                }
                                            };
                                            struct ReleaseSync {
                                                filters: Arc<std::sync::Mutex<std::collections::HashSet<Vec<u8>>>>,
                                                filter: Vec<u8>,
                                            }
                                            impl Drop for ReleaseSync {
                                                fn drop(&mut self) { self.filters.lock().unwrap().remove(&self.filter); }
                                            }
                                            let release = ReleaseSync { filters: syncing_filters.clone(), filter: filter.clone() };
                                            tokio::spawn(async move {
                                                let _release = release;
                                                // Attempts that keep stopping at a shard
                                                // frame no archive serves back off.
                                                if crate::prover_tree_syncer::archive_gap_held(
                                                    target.execution_record(), &filter, &target,
                                                ).await {
                                                    return;
                                                }
                                                tokio::select! {
                                                    biased;
                                                    _ = cancel.cancelled() => {},
                                                    _ = target.execution_record().recovering(&filter, crate::prover_tree_syncer::recover_shard_from_latest(
                                                        syncer.as_ref(), &filter, local, &target, &[], None,
                                                    )) => {}
                                                }
                                            });
                                        }
                                    }
                                    // Internal signals — no network publish.
                                    // A finalized frame's reward proof goes
                                    // to the master through the engine's
                                    // GLOBAL submission hook
                                    // (`worker_global_submissions`).
                                    EquivocationDetected { .. }
                                    | Halted { .. }
                                    | ParentSealed { .. }
                                    | ShardFrameFinalized { .. } => {}
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
    /// one with the given filter. An engine that already runs `filter`
    /// is kept, so a master that restarts or sends the same assignment
    /// again does not restart it.
    pub async fn respawn(&self, filter: Vec<u8>) -> Result<Respawned> {
        let _respawn = self.respawn_lock.lock().await;
        let core_id = self.config.core_id;
        if !filter.is_empty()
            && self
                .running_engine()
                .is_some_and(|handle| handle.filter == filter)
        {
            info!(
                core_id,
                filter = hex::encode(&filter),
                "worker already runs this filter; Respawn keeps its engine"
            );
            return Ok(Respawned::Kept);
        }
        *self.bound_since.lock().unwrap() = std::time::Instant::now();

        // Stop existing engine and drop subscriptions for the
        // outgoing filter.
        if let Some(cancel) = self.engine_cancel.lock().unwrap().take() {
            cancel.cancel();
        }
        {
            let mut handle = self.engine_handle.lock().unwrap();
            *handle = None;
        }
        self.unsubscribe_active_shards().await;

        if filter.is_empty() {
            info!(core_id, "worker set to idle (no filter)");
            return Ok(Respawned::Applied);
        }

        info!(
            core_id,
            filter = hex::encode(&filter),
            "worker respawning with new filter"
        );

        // Create new AppConsensusEngine
        let deps = AppEngineDeps {
            // A worker node covers one shard; cross-shard delivery sources
            // are fetched by the node that wires an archive pool.
            delivery_frame_source: self.delivery_frame_source.clone(),
            clock_store: self.clock_store.clone(),
            // The worker persists the master's GLOBAL stream in clock_store.
            // Historical anchors missed before joining are backfilled on demand
            // from the same identity-pinned master before frame validation.
            global_anchor_store: None,
            // On a network with committee sessions, this worker's own store is
            // its authenticated GLOBAL state: the prover shard (which holds the
            // authorization records) is synced here against each global header's
            // `prover_tree_commitment`, and `maybe_sync_before_global_frame`
            // checkpoints the global cursor only at a verified root. Legacy
            // networks keep `None`: their validators must not require a cursor.
            global_hypergraph: quil_types::consensus::committee_handoff_policy()
                .and(self.hypergraph.clone()),
            prover_registry: self.prover_registry.clone(),
            frame_prover: self.frame_prover.clone(),
            message_collector: self.message_collector.clone(),
            fee_manager: self.fee_manager.clone(),
            local_prover_address: self.local_prover_address.clone(),
            local_bls_pubkey: self.local_bls_pubkey.clone(),
            bls_signer: (self.bls_signer_factory)(),
            reward_greedy: self.reward_greedy,
            min_active_provers_for_propose: self.min_active_provers_for_propose,
            // Finalized frame headers (reward proofs) and closing seals go
            // to the master, which sends them on through its archive
            // transport (see `worker_global_submissions`).
            coverage_publish: Some(worker_global_submissions(
                self.master_relay.clone(),
                self.publish_fn.clone(),
                core_id as u32,
                self.local_halted.clone(),
            )),
            // Per-worker CRDT + execution manager + inclusion prover
            // for byte-for-byte header parity with Go: state_roots from
            // the worker's own hypergraph commit, requests_root from
            // the worker's own execution-manager Lock loop. Each
            // worker owns its own RocksDB store (per
            // `db.worker_path_prefix`) and therefore its own
            // CRDT/exec-mgr instance, mirroring Go's cluster mode.
            hypergraph: self.hypergraph.clone(),
            // Cluster-mode worker: the shard's committed data lives in the
            // worker's OWN hypergraph (forest-synced + self-materialized), so the
            // storage source IS that same crdt — the SDR seal reads it directly.
            // (The intra-crdt sync step is then a no-op; sealing from own_crdt is
            // what populates the replica store for `build_vote_openings`.)
            storage_source_hypergraph: self.hypergraph.clone(),
            topology: None,
            execution_engine: self.execution_engine.clone(),
            inclusion_prover: self.inclusion_prover.clone(),
            // Cluster mode: back the replica store with the worker's OWN RocksDB
            // (wired via `with_kv_db`). REQUIRED for storage-attestation
            // generation — with `None` the whole attestation block (app_engine.rs,
            // gated on `Some(kv)`) was skipped, so the worker NEVER attested and
            // its shard reward was silently zeroed by the global gate.
            kv_db: self.kv_db.clone(),
            // Cluster-mode app-shard CW: mirror thread mode by honoring the
            // configured flag. The worker's own p2p subscribes to
            // `shard_cw_bitmask` and routes inbound CW to the engine (see
            // `route_message` / `subscribe_to_shard_bitmasks`).
            app_consensus_cw: self.config.app_consensus_cw,
            // App-shard CW journal path for THIS cluster worker. A cluster worker
            // is its OWN process with a UNIQUE on-disk data dir, and is ALWAYS
            // core_id 1. `DbConfig::default().worker_path_prefix` is the RELATIVE
            // "worker-store/%d" → "worker-store/1" for EVERY node's worker; since
            // all worker processes share a cwd, they would all resolve the SAME
            // app-CW journal dir. Two simplex Manager instances (separate
            // processes) on one partition delete each other's section files →
            // commonware's `journal.prune` panics with `BlobMissing`, killing the
            // voter before consensus can finalize. Seed `db.path` from the
            // worker's own (unique) data dir AND clear the prefix/paths so
            // `cw_app_storage_base` resolves to that unique `db.path`
            // (`<data_dir>/cw-app-consensus/app-<addr>`), never the shared prefix.
            db_config: self.consensus_db_config(),
            // Multi-process worker: consolidation hook not wired here yet (the
            // thread-mode path is the mainnet path); the flip still occurs.
            unified_cutover_hook: None,
        };

        let (engine, handle) =
            AppConsensusEngine::new(core_id, filter.clone(), deps, self.engine_event_tx.clone());
        let engine = engine
            .with_storage_history_source(self.storage_history_source.clone())
            .with_outgoing_history_source(self.outgoing_history_source.clone())
            .with_global_anchor_source(self.global_anchor_source.clone())
            .with_historical_committee_source(
                self.config
                    .channel_factory
                    .is_some()
                    .then(|| self.master_relay.historical_committee_source()),
            );

        let transport_handle = handle.clone();
        let engine_cancel = self.cancel.child_token();
        *self.engine_cancel.lock().unwrap() = Some(engine_cancel.clone());

        // Store handle for message routing
        {
            let mut h = self.engine_handle.lock().unwrap();
            *h = Some(handle);
        }

        // Run engine in background. Pass the signer FACTORY so the engine can
        // retry starting CW (obtaining a fresh signer each attempt) until its
        // committee is buildable.
        let signer_factory = self.bls_signer_factory.clone();
        let run_cancel = engine_cancel.clone();
        let engine_slot = self.engine_handle.clone();
        let filter_hex = hex::encode(&filter);
        tokio::spawn(async move {
            tokio::select! {
                _ = run_cancel.cancelled() => {},
                _ = engine.run(signer_factory) => {
                    // The engine ended on its own: drop its handle, so the
                    // worker reports running no filter and its master sends
                    // the Respawn again.
                    if let Ok(mut handle) = engine_slot.lock() {
                        if handle.as_ref().is_some_and(|handle| !handle.is_running()) {
                            *handle = None;
                        }
                    }
                    if !run_cancel.is_cancelled() {
                        warn!(core_id, filter = %filter_hex, scope = "local", action = "report",
                            "app consensus engine exited on its own; the worker runs no filter until its master \
                             sends the Respawn again; the lines before this one say why");
                    }
                },
            }
            run_cancel.cancel();
        });

        // Subscribe to per-shard bitmasks on the worker's own p2p so
        // peer-published shard traffic flows in. No-op when running in
        // proxy mode (worker_p2p is None there).
        self.subscribe_to_shard_bitmasks(&filter, transport_handle, engine_cancel)
            .await;

        Ok(Respawned::Applied)
    }

    /// The handle of the engine this worker runs: `None` when it runs
    /// none, or its engine was stopped or has exited.
    fn running_engine(&self) -> Option<AppEngineHandle> {
        let stopped = self
            .engine_cancel
            .lock()
            .ok()?
            .as_ref()
            .is_none_or(|cancel| cancel.is_cancelled());
        if stopped {
            return None;
        }
        self.engine_handle
            .lock()
            .ok()?
            .clone()
            .filter(|handle| handle.is_running())
    }

    /// The DB config whose `cw_app_storage_base` is this worker's own data
    /// dir (see `respawn`).
    fn consensus_db_config(&self) -> quil_config::DbConfig {
        let mut d = quil_config::DbConfig::default();
        if let Some(dir) = self.config.data_dir.as_ref() {
            d.path = dir.to_string_lossy().into_owned();
        }
        d.worker_path_prefix = String::new();
        d.worker_paths = Vec::new();
        d
    }

    /// Subscribe to all per-shard bitmasks for `filter` on the
    /// worker-owned p2p handle. Tracks the subscriptions so the next
    /// respawn can unsubscribe them.
    async fn subscribe_to_shard_bitmasks(
        &self,
        filter: &[u8],
        ready_handle: AppEngineHandle,
        cancel: CancellationToken,
    ) {
        let Some(p2p) = self.worker_p2p.clone() else {
            return;
        };
        let bitmasks = vec![
            crate::bitmasks::shard_frame_bitmask(filter),
            crate::bitmasks::shard_consensus_bitmask(filter),
            crate::bitmasks::app_prover_bitmask(filter),
            crate::bitmasks::shard_dispatch_bitmask(filter),
            // App-shard CW consensus rides its own per-shard topic. The app
            // engine ALWAYS starts commonware-simplex (`app_engine::run` →
            // `start_consensus_cw`, ungated — Jolteon is gone), so this
            // subscription must be unconditional too: without it the worker
            // publishes CW out (`CwOut` → `shard_cw_bitmask`) to a topic it
            // never joined ("not subscribed to bitmask") AND never receives
            // peers' votes/certs/blocks → its simplex engine can't reach
            // quorum. Gating this on `config.app_consensus_cw` (default false,
            // a vestige of the removed legacy path) was the bug.
            crate::bitmasks::shard_cw_bitmask(filter),
        ];
        for bm in &bitmasks {
            p2p.subscribe(bm.clone()).await;
        }
        let mut tracked = self.active_shard_subscriptions.lock().unwrap();
        *tracked = bitmasks;
        drop(tracked);

        let topic = crate::bitmasks::shard_cw_bitmask(filter);
        let count_topic = topic.clone();
        let subscribe_p2p = p2p.clone();
        let filter = filter.to_vec();
        let registry = self.prover_registry.clone();
        let clock = self.clock_store.clone();
        let global = self.hypergraph.clone();
        let public_key = self.local_bls_pubkey.clone();
        let core_id = self.config.core_id;
        tokio::spawn(async move {
            let sole_member = || {
                let frame = clock
                    .get_latest_global_clock_frame()
                    .ok()
                    .and_then(|frame| frame.header.map(|h| h.frame_number))
                    .unwrap_or(0);
                if let Some(global) = global.as_ref() {
                    match crate::app_handoff::resolve(global, &filter, frame) {
                        Ok(crate::app_handoff::SessionChoice::Session(session)) => {
                            return session.members.len() == 1 && session.members[0] == public_key;
                        }
                        Ok(crate::app_handoff::SessionChoice::Legacy) => {}
                        _ => return false,
                    }
                } else if quil_types::consensus::committee_handoff_policy().is_some() {
                    return false;
                }
                registry
                    .get_active_provers(&filter, frame)
                    .is_ok_and(|members| members.len() == 1 && members[0].public_key == public_key)
            };
            let readiness = wait_for_cw_transport(
                subscribe_p2p.subscribe_confirmed(topic),
                || p2p.subscribed_peer_count(count_topic.clone()),
                sole_member,
                &cancel,
            )
            .await;
            match readiness {
                Ok(true) => {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {},
                        sent = ready_handle.send_cw_transport_ready() => {
                            if sent {
                                info!(core_id, filter = hex::encode(&filter),
                                    "cluster CW transport ready; releasing consensus startup barrier");
                            }
                        }
                    }
                }
                Ok(false) => {}
                Err(error) => warn!(core_id, %error, "cluster CW transport readiness failed"),
            }
        });
    }

    /// Inverse of [`Self::subscribe_to_shard_bitmasks`]. Idempotent —
    /// safe to call when nothing was previously subscribed.
    async fn unsubscribe_active_shards(&self) {
        let Some(p2p) = self.worker_p2p.clone() else {
            return;
        };
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
        let Some(header) = frame.header.as_ref() else {
            return;
        };
        let expected = &header.prover_tree_commitment;
        if expected.is_empty() {
            return;
        }
        // Cache the certified prover-tree roots so the periodic background sync
        // can anchor against them instead of trusting the peer.
        {
            let mut anchor = self.latest_prover_tree_anchor.lock().unwrap();
            anchor.clear();
            anchor.push(header.prover_tree_commitment.clone());
            anchor.extend(header.prover_tree_aux_roots.iter().cloned());
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
        let matched = local_root.is_empty() || local_root == expected.as_slice();
        crate::metrics::record_root_verification(matched);
        if matched {
            if !local_root.is_empty() {
                self.checkpoint_authenticated_global_state(header.frame_number);
            }
            return;
        }
        // Root mismatch — sync. Pin ALL FOUR phases: phase 0 =
        // prover_tree_commitment, phases 1/2/3 = prover_tree_aux_roots.
        let mut expected_roots = Vec::with_capacity(4);
        expected_roots.push(header.prover_tree_commitment.clone());
        expected_roots.extend(header.prover_tree_aux_roots.iter().cloned());
        self.perform_blocking_prover_sync(header.frame_number, &expected_roots)
            .await;
    }

    /// Record that the local prover shard equals the root committed by global
    /// header `frame_number` (which binds the state BEFORE that frame). Committee
    /// session reads require this cursor; it is written only at a verified root
    /// and only on networks that enable sessions.
    fn checkpoint_authenticated_global_state(&self, frame_number: u64) {
        if quil_types::consensus::committee_handoff_policy().is_none() {
            return;
        }
        let Some(hg) = self.hypergraph.as_ref() else {
            return;
        };
        if let Err(error) = hg.checkpoint_frame_cursor(
            frame_number.saturating_sub(1),
            &quil_store::encoding::global_materialized_cursor_key(),
        ) {
            warn!(frame = frame_number, %error, "could not checkpoint authenticated GLOBAL state");
        }
    }

    /// Blocking prover-tree sync. Mirrors Go's
    /// `AppConsensusEngine.performBlockingGlobalHypersync`: calls the
    /// syncer up to 3 times, after a jittered delay, checks convergence,
    /// refreshes the prover registry after each attempt. The 5-frame
    /// cooldown (`sync_cooldown_until`) prevents sync-storms.
    async fn perform_blocking_prover_sync(&self, frame_number: u64, expected_roots: &[Vec<u8>]) {
        const MAX_ATTEMPTS: usize = 3;
        const COOLDOWN_FRAMES: u64 = 5;

        let cooldown = self
            .sync_cooldown_until
            .load(std::sync::atomic::Ordering::Relaxed);
        if frame_number < cooldown {
            tracing::debug!(
                frame = frame_number,
                cooldown_until = cooldown,
                "prover tree sync: cooldown active, skipping"
            );
            return;
        }

        let Some(syncer) = self.prover_tree_syncer.as_ref() else {
            warn!(
                "prover tree sync: no syncer wired — worker will run with stale/empty prover tree"
            );
            return;
        };

        info!(
            frame = frame_number,
            expected = expected_roots.first().map(hex::encode).unwrap_or_default(),
            phases = expected_roots.len(),
            "performing blocking prover tree sync before materialization"
        );

        for attempt in 0..MAX_ATTEMPTS {
            tokio::time::sleep(blocking_prover_sync_delay(attempt)).await;
            if attempt > 0 {
                info!(attempt = attempt + 1, "retrying prover tree sync");
            }
            match syncer.sync_prover_tree(expected_roots).await {
                Ok(true) => {
                    info!(attempt = attempt + 1, "prover tree sync converged");
                    self.checkpoint_authenticated_global_state(frame_number);
                    // Refresh the prover registry from the just-synced store.
                    if let Err(error) = self.refresh_registry() {
                        warn!(%error, "synced prover registry refresh failed; retrying before cooldown");
                        continue;
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
    /// - `[0x00, 0x00, 0x00, 0x00]` → global peer info
    ///   - `[0x00, 0x00, 0x00]` → global prover
    ///   - `[0x00, 0x00]` → global frame
    ///   - `[0x00]` → global consensus
    ///   - `shard_frame_bitmask(f)` → Frame
    /// - `shard_consensus_bitmask(f)` → Consensus
    ///   - `shard_prover_bitmask(f)` → Prover
    ///   - `shard_dispatch_bitmask(f)` → Dispatch
    pub fn route_message(&self, data: &[u8], bitmask: &[u8], from: &[u8]) {
        // Learn peer-id → committee key from PeerInfo regardless of engine state,
        // so the mapping is warm before this shard's CW traffic arrives. The
        // peer_id + public_key live INSIDE the PeerInfo payload (not the transport
        // `from`), so this works whether the message came via the worker's own
        // p2p or the master stream.
        if bitmask == crate::bitmasks::GLOBAL_PEER_INFO {
            if let Ok(info) = quil_p2p::decode_canonical_peer_info(data) {
                learn_peer_key(
                    &mut self.peer_key_by_id.lock().unwrap(),
                    info.peer_id,
                    info.public_key,
                );
            }
        }
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
        } else if bitmask == crate::bitmasks::app_prover_bitmask(filter).as_slice() {
            h.send(AppEngineMessage::Prover(data.to_vec()));
        } else if bitmask == crate::bitmasks::shard_dispatch_bitmask(filter).as_slice() {
            h.send(AppEngineMessage::Dispatch(data.to_vec()));
        } else if bitmask == crate::bitmasks::shard_cw_bitmask(filter).as_slice() {
            // App-shard commonware-simplex traffic: unpack the channel tag, then
            // resolve the gossip sender's PeerId → its committee Falcon key so
            // the engine's `CwIn` can attribute (and not drop) it. The BLOCK
            // channel needs no key (self-describing), so an unresolved sender is
            // only fatal for votes/certs — a benign transient until the peer's
            // PeerInfo propagates. Mirrors the master's inbound CW routing.
            if let Some((channel, cw_bytes)) =
                crate::bitmasks::shard_cw_admit(filter, data, &self.local_cw_tag)
            {
                let from_key = self
                    .peer_key_by_id
                    .lock()
                    .unwrap()
                    .get_mut(from)
                    .map(|(key, used)| {
                        *used = true;
                        key.clone()
                    })
                    .unwrap_or_default();
                h.send(AppEngineMessage::CwIn {
                    channel,
                    from: from_key,
                    data: cw_bytes.to_vec(),
                });
            }
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

/// Most peer keys a worker keeps. A mainnet node knew about 105 peers
/// (2026-10-26).
const MAX_PEER_KEYS: usize = 4096;

/// Learn `peer_id`'s committee key from a PeerInfo when the ID is derived
/// from the key: a PeerInfo is unauthenticated on the worker's own mesh,
/// and an ID names one key only, so no record can attribute a peer's
/// messages to another key. When full, the keys no CW message used since
/// the last pruning are dropped (a committee member's are used), and the
/// rest are marked unused; if every key was used, all are dropped. Returns
/// whether the key is known now.
fn learn_peer_key(
    keys: &mut std::collections::HashMap<Vec<u8>, (Vec<u8>, bool)>,
    peer_id: Vec<u8>,
    public_key: Vec<u8>,
) -> bool {
    if peer_id.is_empty()
        || public_key.len() != quil_crypto::FALCON_PUBLIC_KEY_LEN
        || quil_p2p::peer_id_from_falcon_pubkey(&public_key) != peer_id
    {
        return false;
    }
    if keys.contains_key(&peer_id) {
        return true;
    }
    if keys.len() >= MAX_PEER_KEYS {
        keys.retain(|_, held| std::mem::take(&mut held.1));
        if keys.len() >= MAX_PEER_KEYS {
            keys.clear();
        }
    }
    keys.insert(peer_id, (public_key, false));
    true
}

/// Subscription installation must finish before a remote peer (or an
/// authorized singleton) can release consensus startup. Cancellation also
/// interrupts outstanding transport requests when the worker changes shards.
async fn wait_for_cw_transport<S, P, F, O>(
    subscribe: S,
    mut peers: P,
    sole_member: O,
    cancel: &CancellationToken,
) -> Result<bool>
where
    S: std::future::Future<Output = Result<()>>,
    P: FnMut() -> F,
    F: std::future::Future<Output = Result<usize>>,
    O: Fn() -> bool,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Ok(false),
        ready = async {
            subscribe.await?;
            loop {
                if peers().await? > 0 || sole_member() {
                    return Ok(true);
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        } => ready,
    }
}

/// What a starting worker answers the DataIPC calls that need its synced
/// state; the master waits for it instead of counting it as a failure.
pub(crate) const WORKER_STARTING: &str = "worker starting: initial prover-tree sync in progress";

/// What a Respawn did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Respawned {
    /// The engine for the filter was started, or the worker set idle.
    Applied,
    /// The worker already ran the filter and kept its engine.
    Kept,
    /// The worker is starting: it applies the Respawn once its initial
    /// prover-tree sync completes.
    AtReady,
}

/// Applies one Respawn: the worker's `respawn`, or a test's stand-in.
type RespawnApply = Arc<
    dyn Fn(
            Vec<u8>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::result::Result<Respawned, String>> + Send>,
        > + Send
        + Sync,
>;

/// A call waiting for a Respawn's outcome.
type RespawnWaiter = tokio::sync::oneshot::Sender<std::result::Result<Respawned, String>>;

/// The worker's `respawn` as a [`RespawnApply`].
fn respawn_apply(worker: Arc<WorkerOnlyNode>) -> RespawnApply {
    Arc::new(move |filter| {
        let worker = worker.clone();
        Box::pin(async move { worker.respawn(filter).await.map_err(|e| e.to_string()) })
    })
}

/// What a Respawn that a newer one replaced before it ran answers.
const RESPAWN_SUPERSEDED: &str = "superseded by a newer Respawn";

/// The master's Respawn requests, applied one at a time in a task of their
/// own, so a master that stops waiting (its call timed out, or the
/// connection reset) cannot cancel a respawn half-way, leaving an engine
/// that reads as running but never started consensus. A request that
/// arrives while one runs waits for it; a newer one replaces a waiting one,
/// and one for the filter being applied waits for that application instead
/// of repeating it. Until a request is applied, the worker reports its
/// filter as the one it runs, so its master does not send it again
/// meanwhile. While the worker starts, the latest request is accepted and
/// kept (an empty filter clears it) and applied once the worker is ready,
/// so a master's single Respawn is not lost.
#[derive(Default)]
struct RespawnQueue {
    state: std::sync::Mutex<RespawnQueueState>,
}

#[derive(Default)]
struct RespawnQueueState {
    ready: bool,
    /// A task is applying requests.
    running: bool,
    queued: Option<QueuedRespawn>,
    /// The request being applied.
    applying: Option<QueuedRespawn>,
}

struct QueuedRespawn {
    filter: Vec<u8>,
    /// The calls waiting for this request's outcome.
    waiters: Vec<RespawnWaiter>,
}

/// Clears `running` if the task applying requests unwinds, so the next
/// request starts another.
struct RespawnDrain(Arc<RespawnQueue>);

impl Drop for RespawnDrain {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Ok(mut state) = self.0.state.lock() {
                state.running = false;
                state.applying = None;
            }
        }
    }
}

impl RespawnQueue {
    fn is_ready(&self) -> bool {
        self.state.lock().map(|state| state.ready).unwrap_or(false)
    }

    /// Respawn on `filter`. Answers once it is applied (or replaced by a
    /// newer request before it ran); while the worker starts, at once,
    /// with [`Respawned::AtReady`].
    async fn respawn(
        self: &Arc<Self>,
        filter: Vec<u8>,
        apply: RespawnApply,
        core_id: u32,
    ) -> std::result::Result<Respawned, tonic::Status> {
        let Some(outcome) = self.enqueue(filter, apply, core_id)? else {
            return Ok(Respawned::AtReady);
        };
        match outcome.await {
            Ok(Ok(respawned)) => Ok(respawned),
            Ok(Err(error)) if error == RESPAWN_SUPERSEDED => Err(tonic::Status::aborted(error)),
            Ok(Err(error)) => Err(tonic::Status::internal(format!(
                "respawn failed: {}",
                error
            ))),
            Err(_) => Err(tonic::Status::internal("respawn ended without an outcome")),
        }
    }

    /// Queue a Respawn on `filter` and start applying requests; `None` when
    /// the worker is starting and keeps it for the ready point.
    fn enqueue(
        self: &Arc<Self>,
        filter: Vec<u8>,
        apply: RespawnApply,
        core_id: u32,
    ) -> std::result::Result<
        Option<tokio::sync::oneshot::Receiver<std::result::Result<Respawned, String>>>,
        tonic::Status,
    > {
        let mut state = self
            .state
            .lock()
            .map_err(|_| tonic::Status::internal("respawn queue poisoned"))?;
        let state = &mut *state;
        if !state.ready {
            info!(core_id, filter = hex::encode(&filter),
                "Respawn received while starting; applied once the initial prover-tree sync completes");
            state.queued = (!filter.is_empty()).then(|| QueuedRespawn {
                filter,
                waiters: Vec::new(),
            });
            return Ok(None);
        }
        let (answer, outcome) = tokio::sync::oneshot::channel();
        if let Some(applying) = state
            .applying
            .as_mut()
            .filter(|applying| applying.filter == filter)
        {
            // Being applied already: answer with that outcome rather than
            // apply it twice, and drop an older request still waiting.
            info!(
                core_id,
                filter = hex::encode(&filter),
                "Respawn received for the filter being applied; answered when it completes"
            );
            applying.waiters.push(answer);
            for waiter in state
                .queued
                .take()
                .into_iter()
                .flat_map(|queued| queued.waiters)
            {
                let _ = waiter.send(Err(RESPAWN_SUPERSEDED.to_string()));
            }
            return Ok(Some(outcome));
        }
        match state.queued.take() {
            Some(mut queued) if queued.filter == filter => {
                queued.waiters.push(answer);
                state.queued = Some(queued);
            }
            replaced => {
                for waiter in replaced.into_iter().flat_map(|queued| queued.waiters) {
                    let _ = waiter.send(Err(RESPAWN_SUPERSEDED.to_string()));
                }
                state.queued = Some(QueuedRespawn {
                    filter,
                    waiters: vec![answer],
                });
            }
        }
        if !state.running {
            state.running = true;
            tokio::spawn(self.clone().drain(apply));
        }
        Ok(Some(outcome))
    }

    /// Mark the worker ready, and apply the Respawn it accepted while
    /// starting, if any.
    fn set_ready(self: &Arc<Self>, apply: RespawnApply, core_id: u32) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.ready = true;
        if let Some(queued) = state.queued.as_ref() {
            info!(
                core_id,
                filter = hex::encode(&queued.filter),
                "applying the Respawn received while starting"
            );
            if !state.running {
                state.running = true;
                tokio::spawn(self.clone().drain(apply));
            }
        }
    }

    /// Apply queued requests, one at a time, until none is left.
    async fn drain(self: Arc<Self>, apply: RespawnApply) {
        let _drain = RespawnDrain(self.clone());
        while let Some(filter) = self.next_queued() {
            let outcome = apply(filter).await;
            for waiter in self.applied() {
                let _ = waiter.send(outcome.clone());
            }
        }
    }

    /// Mark the next request as being applied and return its filter;
    /// `None` ends the applying task.
    fn next_queued(&self) -> Option<Vec<u8>> {
        let mut state = self.state.lock().ok()?;
        let next = state.queued.take();
        if next.is_none() {
            state.running = false;
        }
        let filter = next.as_ref().map(|next| next.filter.clone());
        state.applying = next;
        filter
    }

    /// The calls waiting for the request just applied.
    fn applied(&self) -> Vec<RespawnWaiter> {
        self.state
            .lock()
            .ok()
            .and_then(|mut state| state.applying.take())
            .map(|applied| applied.waiters)
            .unwrap_or_default()
    }

    /// The filter of the latest Respawn waiting or being applied, if any.
    fn pending(&self) -> Option<Vec<u8>> {
        let state = self.state.lock().ok()?;
        state
            .queued
            .as_ref()
            .or(state.applying.as_ref())
            .map(|request| request.filter.clone())
    }
}

/// First and longest wait between attempts to bind the DataIPC listener.
const DATA_IPC_BIND_RETRY_FIRST: Duration = Duration::from_secs(1);
const DATA_IPC_BIND_RETRY_MAX: Duration = Duration::from_secs(30);

/// `error` with its chain of sources, as one line.
pub(crate) fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut line = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        line.push_str(": ");
        line.push_str(&cause.to_string());
        source = cause.source();
    }
    line
}

/// Serve the DataIPC service on `listen_addr` until `cancel`. A listener
/// that cannot bind, or a server that stops on an error, is bound again
/// with backoff rather than leaving the worker unreachable for good.
async fn serve_data_ipc(
    worker: Arc<WorkerOnlyNode>,
    listen_addr: std::net::SocketAddr,
    tls: Option<tonic::transport::ServerTlsConfig>,
    cancel: CancellationToken,
) {
    let core_id = worker.config.core_id;
    let mut pause = DATA_IPC_BIND_RETRY_FIRST;
    loop {
        let Some(incoming) = bind_data_ipc(core_id, listen_addr, &cancel).await else {
            return;
        };
        let started = std::time::Instant::now();
        info!(
            "DataIPC gRPC server starting on {} (mtls={})",
            listen_addr,
            tls.is_some()
        );
        let mut builder = Server::builder()
            // Reap dead master connections (h2 PING) so a master that
            // dies without FIN doesn't leave the stream fd behind. TCP
            // keepalive is set on the bound listener.
            .http2_keepalive_interval(Some(std::time::Duration::from_secs(20)))
            .http2_keepalive_timeout(Some(std::time::Duration::from_secs(10)));
        if let Some(tls) = tls.clone() {
            match builder.tls_config(tls) {
                Ok(b) => builder = b,
                Err(e) => {
                    error!(error = %e, "DataIPC gRPC TLS config invalid — server not started");
                    return;
                }
            }
        }
        let served = builder
            .add_service(
                quil_types::proto::node::data_ipc_service_server::DataIpcServiceServer::new(
                    DataIpcServiceImpl {
                        worker: worker.clone(),
                    },
                ),
            )
            .serve_with_incoming_shutdown(incoming, cancel.cancelled())
            .await;
        let Err(e) = served else { return };
        // A server that keeps failing at once is bound again at most twice
        // a minute; one that served for a while starts over from a second.
        if started.elapsed() >= 2 * DATA_IPC_BIND_RETRY_MAX {
            pause = DATA_IPC_BIND_RETRY_FIRST;
        }
        error!(core_id, listen = %listen_addr, error = %error_chain(&e), retry_secs = pause.as_secs(),
            "DataIPC gRPC server failed; binding its listener again");
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(pause) => {}
        }
        pause = (pause * 2).min(DATA_IPC_BIND_RETRY_MAX);
    }
}

/// Bind the DataIPC listener on `listen_addr`, retrying from
/// [`DATA_IPC_BIND_RETRY_FIRST`], doubling to [`DATA_IPC_BIND_RETRY_MAX`],
/// until it binds; `None` once `cancel` fires. A failing bind warns when it
/// begins and at a bounded interval, and logs its end.
async fn bind_data_ipc(
    core_id: u32,
    listen_addr: std::net::SocketAddr,
    cancel: &CancellationToken,
) -> Option<tonic::transport::server::TcpIncoming> {
    use crate::outage::OutageEvent;
    let mut outage = crate::outage::Outage::default();
    let mut backoff = DATA_IPC_BIND_RETRY_FIRST;
    loop {
        let bound = tonic::transport::server::TcpIncoming::new(
            listen_addr,
            true,
            Some(Duration::from_secs(60)),
        );
        let now = std::time::Instant::now();
        match bound {
            Ok(incoming) => {
                if let Some(OutageEvent::Ended { secs, failures }) = outage.observe(now, true) {
                    info!(core_id, listen = %listen_addr, secs, failures,
                        "DataIPC listener bound after {} failed attempts over {}s", failures, secs);
                }
                return Some(incoming);
            }
            Err(error) => {
                let error = error_chain(&*error);
                match outage.observe(now, false) {
                    Some(OutageEvent::Began) => {
                        warn!(core_id, listen = %listen_addr, error = %error,
                        scope = "local", action = "check",
                        "DataIPC listener cannot bind; the master cannot reach this worker until it does; \
                         check that the address belongs to this host and that no old worker process holds the port")
                    }
                    Some(OutageEvent::Continues { secs, failures }) => {
                        warn!(core_id, listen = %listen_addr,
                        error = %error, secs, failures, scope = "local", action = "check",
                        "DataIPC listener still cannot bind")
                    }
                    _ => {}
                }
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => return None,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(DATA_IPC_BIND_RETRY_MAX);
    }
}

// =====================================================================
// DataIPCService — gRPC server on the worker for master commands
// =====================================================================

struct DataIpcServiceImpl {
    worker: Arc<WorkerOnlyNode>,
}

impl DataIpcServiceImpl {
    /// Refuse a call that needs the synced state while the worker starts.
    fn ready(&self) -> std::result::Result<(), tonic::Status> {
        if self.worker.respawns.is_ready() {
            Ok(())
        } else {
            Err(tonic::Status::unavailable(WORKER_STARTING))
        }
    }
}

/// Hand a directly received shard consensus message to `handle` when it is
/// the engine for that shard. False: this worker does not run it.
fn deliver_to_engine(
    handle: Option<crate::app_engine::AppEngineHandle>,
    request: quil_types::proto::node::DeliverShardConsensusRequest,
) -> bool {
    let Some(handle) = handle.filter(|handle| handle.filter == request.filter) else {
        return false;
    };
    if request.channel == crate::cw_app_seams::CW_APP_RESOLVER_CHANNEL {
        crate::resolver_traffic::ResolverTraffic::process().note_received(
            &request.filter,
            &request.data,
            crate::resolver_traffic::Addressed::Here,
        );
    }
    handle.send(crate::app_engine::AppEngineMessage::CwIn {
        channel: request.channel,
        from: request.from,
        data: request.data,
    });
    true
}

/// Start the eviction passes for `keep` unless the binding of `handle`
/// defers them or a run is in progress. Returns why they did not start.
fn start_payload_eviction<R>(
    core_id: u32,
    handle: Option<&AppEngineHandle>,
    bound_for: Duration,
    evicting: &Arc<std::sync::atomic::AtomicBool>,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    keep: Vec<Vec<u8>>,
    storage: Option<(std::path::PathBuf, R)>,
) -> Option<&'static str>
where
    R: Fn(&[u8]) -> bool + Send + 'static,
{
    let bound = handle
        .map(|handle| handle.filter.clone())
        .unwrap_or_default();
    let serving = handle.is_some_and(|handle| handle.is_running());
    if let Some(reason) =
        crate::worker_payload_eviction::deferral(&bound, &keep, serving, bound_for)
    {
        info!(core_id, reason, "worker payload eviction deferred");
        return Some(reason);
    }
    if evicting.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Some("an eviction is running");
    }
    let flag = evicting.clone();
    // A rebind stops the engine the passes start for.
    let engine = handle.cloned();
    let serving: Arc<dyn Fn() -> bool + Send + Sync> =
        Arc::new(move || engine.as_ref().is_some_and(|h| h.is_running()));
    tokio::spawn(async move {
        crate::worker_payload_eviction::run_passes(
            core_id,
            hex::encode(&bound),
            crdt,
            keep,
            storage,
            serving,
        )
        .await;
        flag.store(false, std::sync::atomic::Ordering::SeqCst);
    });
    None
}

#[tonic::async_trait]
impl quil_types::proto::node::data_ipc_service_server::DataIpcService for DataIpcServiceImpl {
    type ExportLogsStream = tonic::codegen::tokio_stream::wrappers::ReceiverStream<
        std::result::Result<quil_types::proto::node::ExportWorkerLogsChunk, tonic::Status>,
    >;

    /// This worker's own log lines of a window, for the master's
    /// diagnostics log bundle. Answered while the worker starts too: a
    /// start that does not end is among what its lines explain.
    async fn export_logs(
        &self,
        request: tonic::Request<quil_types::proto::node::ExportWorkerLogsRequest>,
    ) -> std::result::Result<tonic::Response<Self::ExportLogsStream>, tonic::Status> {
        let Some(export) = self.worker.log_export.as_ref() else {
            return Err(tonic::Status::failed_precondition(
                "this worker process exports no log lines",
            ));
        };
        let lines = export(request.into_inner());
        Ok(tonic::Response::new(
            tonic::codegen::tokio_stream::wrappers::ReceiverStream::new(lines),
        ))
    }

    /// A committee member's message the master received directly, for this
    /// worker's shard. Handed to the engine exactly as the topic copy would
    /// be; the engine checks `from` against the committee.
    async fn deliver_shard_consensus(
        &self,
        request: tonic::Request<quil_types::proto::node::DeliverShardConsensusRequest>,
    ) -> std::result::Result<
        tonic::Response<quil_types::proto::node::DeliverShardConsensusResponse>,
        tonic::Status,
    > {
        self.ready()?;
        let handle = self
            .worker
            .engine_handle
            .lock()
            .map_err(|_| tonic::Status::unavailable("worker handle unavailable"))?
            .clone();
        let accepted = deliver_to_engine(handle, request.into_inner());
        Ok(tonic::Response::new(
            quil_types::proto::node::DeliverShardConsensusResponse { accepted },
        ))
    }

    /// The engine this worker runs and its latest execution report, for the
    /// master's renewal decisions and operator views. An engine that was
    /// stopped or has exited runs nothing; a Respawn waiting or being
    /// applied counts as run, so the master does not send it again.
    async fn get_worker_execution(
        &self,
        _request: tonic::Request<quil_types::proto::node::GetWorkerExecutionRequest>,
    ) -> std::result::Result<
        tonic::Response<quil_types::proto::node::GetWorkerExecutionResponse>,
        tonic::Status,
    > {
        self.ready()?;
        let handle = self.worker.running_engine();
        let (filter, execution) = match (self.worker.respawns.pending(), handle) {
            (Some(pending), handle) => {
                let execution = handle
                    .filter(|handle| handle.filter == pending)
                    .map(|handle| handle.execution());
                (pending, execution)
            }
            (None, Some(handle)) => (handle.filter.clone(), Some(handle.execution())),
            (None, None) => (Vec::new(), None),
        };
        // A standalone worker runs its own swarm: its gossip traffic is not
        // in the master's.
        let execution = execution.map(|mut execution| {
            execution.gossip_traffic = self
                .worker
                .worker_p2p
                .as_ref()
                .map(|p2p| p2p.gossip_traffic().to_proto());
            execution
        });
        Ok(tonic::Response::new(
            quil_types::proto::node::GetWorkerExecutionResponse {
                filter,
                // A store that refuses writes reads as blocked by it, to the
                // master's lifecycle and health report alike.
                execution: crate::worker_execution::with_store_state(
                    self.worker.config.core_id,
                    execution,
                ),
                now_unix_ms: crate::worker_execution::now_ms(),
            },
        ))
    }

    async fn get_app_fee_snapshot(
        &self,
        request: tonic::Request<quil_types::proto::node::GetAppFeeSnapshotRequest>,
    ) -> std::result::Result<
        tonic::Response<quil_types::proto::node::GetAppFeeSnapshotResponse>,
        tonic::Status,
    > {
        let application: [u8; 32] = request
            .into_inner()
            .application
            .as_slice()
            .try_into()
            .map_err(|_| tonic::Status::invalid_argument("application must be 32 bytes"))?;
        let handle = self
            .worker
            .engine_handle
            .lock()
            .map_err(|_| tonic::Status::unavailable("worker handle unavailable"))?
            .clone()
            .ok_or_else(|| tonic::Status::unavailable("worker has no active engine"))?;
        if handle.filter.as_slice() != application.as_slice() {
            return Err(tonic::Status::unavailable(
                "worker does not execute this full application",
            ));
        }
        let s = handle
            .fee_snapshot()
            .filter(|s| s.application == application)
            .ok_or_else(|| {
                tonic::Status::unavailable("materialized pricing snapshot unavailable")
            })?;
        Ok(tonic::Response::new(
            quil_types::proto::node::GetAppFeeSnapshotResponse {
                application: s.application.to_vec(),
                frame_number: s.frame_number,
                global_frame_number: s.global_frame_number,
                difficulty: s.difficulty,
                world_state_bytes: s.world_state_bytes,
                fee_multiplier_vote: s.fee_multiplier_vote,
            },
        ))
    }

    async fn respawn(
        &self,
        request: tonic::Request<quil_types::proto::node::RespawnRequest>,
    ) -> std::result::Result<tonic::Response<quil_types::proto::node::RespawnResponse>, tonic::Status>
    {
        // Accepted while starting too: an older master sends its Respawn
        // only once. The respawn itself runs in a task of its own, so a
        // master that stops waiting cannot cancel it half-way.
        let filter = request.into_inner().filter;
        let core_id = self.worker.config.core_id;
        let respawned = self
            .worker
            .respawns
            .respawn(filter, respawn_apply(self.worker.clone()), core_id)
            .await?;
        Ok(tonic::Response::new(
            quil_types::proto::node::RespawnResponse {
                deferred: respawned == Respawned::AtReady,
                kept: respawned == Respawned::Kept,
            },
        ))
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

    /// The master's request to remove what this worker's store keeps
    /// outside `keep`, computed as for its thread workers. The worker runs
    /// the thread workers' passes once its own binding is protected, served
    /// and settled; they continue after the answer. While the worker starts
    /// it answers `Unavailable`, and the allocator's repeat asks again.
    async fn evict_payload(
        &self,
        request: tonic::Request<quil_types::proto::node::EvictPayloadRequest>,
    ) -> std::result::Result<
        tonic::Response<quil_types::proto::node::EvictPayloadResponse>,
        tonic::Status,
    > {
        self.ready()?;
        let keep = request.into_inner().keep;
        let worker = &self.worker;
        let Some(crdt) = worker.hypergraph.clone() else {
            return Err(tonic::Status::unavailable("worker has no shard storage"));
        };
        let handle = worker
            .engine_handle
            .lock()
            .map_err(|_| tonic::Status::unavailable("worker handle unavailable"))?
            .clone();
        let bound_for = worker
            .bound_since
            .lock()
            .map_err(|_| tonic::Status::unavailable("worker binding unavailable"))?
            .elapsed();
        // As in `respawn`: on a network with committee sessions this
        // worker's own store holds the authorization records.
        let storage = crate::app_engine::cw_app_storage_base(
            &worker.consensus_db_config(),
            worker.config.core_id,
        )
        .map(|base| {
            let global =
                quil_types::consensus::committee_handoff_policy().and(worker.hypergraph.clone());
            let member = worker.local_bls_pubkey.clone();
            (base, move |shard: &[u8]| {
                global
                    .as_ref()
                    .is_none_or(|global| crate::app_handoff::retains_worker(global, shard, &member))
            })
        });
        let deferred = start_payload_eviction(
            worker.config.core_id,
            handle.as_ref(),
            bound_for,
            &worker.evicting,
            crdt,
            keep,
            storage,
        );
        Ok(tonic::Response::new(
            quil_types::proto::node::EvictPayloadResponse {
                started: deferred.is_none(),
                deferred: deferred.unwrap_or_default().to_string(),
            },
        ))
    }

    async fn prepare_storage_confirm(
        &self,
        request: tonic::Request<quil_types::proto::node::PrepareStorageConfirmRequest>,
    ) -> std::result::Result<
        tonic::Response<quil_types::proto::node::PrepareStorageConfirmResponse>,
        tonic::Status,
    > {
        self.ready()?;
        let req = request.into_inner();
        let snapshots =
            quil_execution::global_intrinsic::storage_snapshot::decode_plan(&req.snapshot_sources)
                .ok_or_else(|| {
                    tonic::Status::invalid_argument("undecodable storage snapshot sources")
                })?;
        // Only the worker executing this shard holds its data. The master's
        // own store does not, so its confirm registered leaves this worker
        // could never prove, and every frame it attested was rejected. With
        // the shard's recorded snapshot (hash storage proofs) the worker
        // assigned a joining seat encodes before it runs the shard: the
        // snapshot is synced from an archive, and the replicas it proves
        // later land here.
        let bound = self
            .worker
            .engine_handle
            .lock()
            .map_err(|_| tonic::Status::unavailable("worker handle unavailable"))?
            .as_ref()
            .is_some_and(|handle| handle.filter == req.filter);
        let from_snapshot = snapshots.iter().any(|(shard, _)| *shard == req.filter);
        if !(bound || from_snapshot) || req.filter.is_empty() {
            return Err(tonic::Status::failed_precondition(
                "worker is not bound to this filter",
            ));
        }
        let (Some(crdt), Some(kv)) = (self.worker.hypergraph.clone(), self.worker.kv_db.clone())
        else {
            return Err(tonic::Status::unavailable("worker has no shard storage"));
        };
        let member = self.worker.local_prover_address.clone();
        let retired_below = self.worker.replicas_retired_below.clone();
        // A confirm in epoch E registers, and encodes, the leaves for E + 1.
        let epoch = quil_types::consensus::epoch_for_frame(req.frame_number) + 1;
        let frame_number = req.frame_number;
        let filter = req.filter;
        // The bound shard first, then the shards a recorded change creates
        // from it, all from this worker's store.
        let mut filters = vec![filter.clone()];
        filters.extend(
            req.targets
                .into_iter()
                .filter(|target| !target.is_empty() && *target != filter),
        );
        let roots = tokio::task::spawn_blocking(move || {
            encode_worker_storage_confirm(
                &crdt,
                &quil_store::replica_store::ReplicaStore::new(kv),
                &retired_below,
                &filters,
                &member,
                frame_number,
                &snapshots,
            )
        })
        .await
        .map_err(|e| tonic::Status::internal(format!("storage confirm task: {e}")))?
        .map_err(|e| {
            tonic::Status::unavailable(format!("storage confirm preparation failed: {e}"))
        })?;
        // Before its data sync completes the worker has nothing to encode; an
        // empty registration would leave it unattested for the next epoch.
        // In a hash-proof epoch the renewal registers what the epoch's leaf
        // snapshot encoded, and past its grace renews without one on purpose.
        if !quil_types::consensus::hash_storage_proofs_at(epoch)
            && roots
                .iter()
                .filter(|group| group.filter == filter)
                .all(|group| group.entries.is_empty())
        {
            return Err(tonic::Status::failed_precondition(
                "worker holds no data for this filter yet",
            ));
        }
        Ok(tonic::Response::new(
            quil_types::proto::node::PrepareStorageConfirmResponse {
                leaf_roots: roots
                    .iter()
                    .map(quil_execution::global_intrinsic::conversions::confirm_leaf_roots_to_proto)
                    .collect(),
            },
        ))
    }
}

/// A confirm at `frame_number`, in epoch E, registers and encodes the leaves
/// for E + 1. First evict the replicas no frame can still challenge, with the
/// window the master's reconfirmation applies to the stores it encodes
/// (#734): nothing else evicts a standalone worker's store.
fn encode_worker_storage_confirm(
    crdt: &std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
    replicas: &quil_store::replica_store::ReplicaStore,
    retired_below: &std::sync::atomic::AtomicU64,
    filters: &[Vec<u8>],
    member: &[u8],
    frame_number: u64,
    snapshots: &[crate::prover_pipeline::SnapshotSources],
) -> Result<Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>> {
    let current_epoch = quil_types::consensus::epoch_for_frame(frame_number);
    crate::app_shard_metadata::retire_unchallengeable_replicas(
        replicas,
        retired_below,
        current_epoch,
        filters.first().map_or(&[][..], Vec::as_slice),
        frame_number,
    );
    crate::app_shard_metadata::compute_storage_confirm(
        crdt,
        replicas,
        filters,
        member,
        current_epoch + 1,
        quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
        &quil_crypto::sdr::SdrParams::default(),
        frame_number,
        snapshots,
    )
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

        info!(
            endpoint = master_endpoint,
            "connecting to master for message stream"
        );

        match channel_factory().await {
            Ok(channel) => {
                info!("connected to master, starting message stream");
                backoff = Duration::from_secs(1); // reset backoff

                let mut client =
                    quil_types::proto::global::global_service_client::GlobalServiceClient::new(
                        channel,
                    );
                let request =
                    tonic::Request::new(quil_types::proto::global::StreamGlobalMessagesRequest {});

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
                                            // Master stream carries no sender id;
                                            // it fans out GLOBAL_* traffic only, so
                                            // shard-CW (which needs `from`) never
                                            // arrives here — an empty sender is fine.
                                            worker.route_message(&resp.data, &resp.bitmask, &[]);
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
                    // Give a moment for cleanup, then force exit, skipping
                    // the teardown that aborts under a storage job still
                    // using a store (`storage_jobs::exit_now`).
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    crate::storage_jobs::exit_now(1);
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
/// 1. `data_worker_stream_multiaddrs[core_id - 1]` if set. Accepts
/// either `host:port` directly or a libp2p multiaddr
/// `/ip4/HOST/tcp/PORT` (extracted into `HOST:PORT`).
/// 2. `data_worker_base_listen_multiaddr` template with `%d` →
/// `data_worker_base_stream_port + (core_id - 1)`. Core 1 gets
/// `base_stream_port` itself.
/// 3. Same as (2) but with the serde defaults for those two fields
/// (which is what you get when the config doesn't set them).
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
    let port =
        base_stream_port.saturating_add(core_id.saturating_sub(1).min(u16::MAX as u32) as u16);
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

    /// Confirms in epochs E..E+3 encode E+1..E+4; by the last, the replicas
    /// of every epoch below E+2 are gone, the backlog an older build left
    /// included, and the previous, current and next epochs remain.
    #[test]
    fn worker_confirms_evict_replicas_no_frame_can_challenge() {
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use quil_hypergraph::Location;
        quil_crypto::init();
        let crdt = quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_hypergraph::testing::StubProver),
        );
        let app = 0x44u8;
        let filter = vec![app; 32];
        for d in 0u8..3 {
            crdt.add_vertex(
                &Location {
                    app_address: [app; 32],
                    data_address: [d; 32],
                },
                &vec![d.wrapping_add(1); 256],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let crdt = Arc::new(crdt);
        let replicas = quil_store::replica_store::ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_in_memory().unwrap(),
        ));
        let retired_below = std::sync::atomic::AtomicU64::new(0);
        let member = vec![0xC2u8; 32];
        let first = 10u64;
        replicas.put(first - 3, b"backlog", b"old").unwrap();
        let mut leaves = Vec::new();
        for epoch in first..=first + 3 {
            let frame = epoch * quil_types::consensus::epoch_length_frames() + 1;
            let roots = encode_worker_storage_confirm(
                &crdt,
                &replicas,
                &retired_below,
                std::slice::from_ref(&filter),
                &member,
                frame,
                &[],
            )
            .expect("worker confirm");
            leaves = roots[0]
                .entries
                .iter()
                .map(|e| leaf_id_bytes(&filter, &e.prefix))
                .collect();
            assert!(!leaves.is_empty(), "the shard's data is encoded");
        }
        assert!(
            replicas.get(first - 3, b"backlog").unwrap().is_none(),
            "the backlog is evicted"
        );
        for leaf in &leaves {
            assert!(
                replicas.get(first + 1, leaf).unwrap().is_none(),
                "epoch E+1 is evicted"
            );
            for epoch in first + 2..=first + 4 {
                assert!(
                    replicas.get(epoch, leaf).unwrap().is_some(),
                    "epoch {epoch} is kept"
                );
            }
        }
    }

    /// Without a master to take them, a reward proof is not gossiped (regular
    /// nodes hold no GLOBAL_PROVER subscription to publish on) while a closing
    /// seal keeps its earlier gossip path; during a coverage halt nothing
    /// leaves at all.
    #[tokio::test]
    async fn global_submissions_without_a_master_keep_only_the_seal_gossip() {
        let published: Arc<std::sync::Mutex<Vec<(Vec<u8>, Vec<u8>)>>> = Default::default();
        let publish: PublishFn = {
            let published = published.clone();
            Arc::new(move |bitmask, data| {
                published.lock().unwrap().push((bitmask, data));
                Box::pin(async {})
            })
        };
        let relay = Arc::new(MasterRelay::new(None));
        let halted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let submit = worker_global_submissions(relay.clone(), Some(publish), 4, halted.clone());
        let header = quil_execution::global_intrinsic::frame_header::FrameHeader {
            address: vec![9; 32],
            frame_number: 12,
            ..Default::default()
        }
        .to_canonical_bytes()
        .unwrap();
        let mut seal = quil_execution::global_intrinsic::handoff::TYPE_COMMITTEE_HANDOFF
            .to_be_bytes()
            .to_vec();
        seal.extend_from_slice(b"closing seal");
        assert_eq!(
            relay.submit(4, header.clone()).await,
            MasterSubmission::Unavailable
        );

        let settle = || async {
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
        };
        halted.store(true, std::sync::atomic::Ordering::Relaxed);
        submit(header.clone());
        submit(seal.clone());
        settle().await;
        assert!(
            published.lock().unwrap().is_empty(),
            "nothing leaves during a halt"
        );

        halted.store(false, std::sync::atomic::Ordering::Relaxed);
        submit(header);
        submit(seal.clone());
        settle().await;
        let published = published.lock().unwrap();
        assert_eq!(published.len(), 1, "only the seal is gossiped");
        assert_eq!(published[0].0, crate::bitmasks::GLOBAL_PROVER.to_vec());
        let bundle =
            quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(
                &published[0].1,
            )
            .unwrap();
        let requests: Vec<_> = bundle.requests.into_iter().flatten().collect();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].inner_bytes, seal);
    }

    /// The master's direct delivery reaches the engine only for the shard
    /// this worker runs, carrying the sender's committee key.
    #[test]
    fn a_directly_delivered_message_reaches_only_this_shards_engine() {
        let request = |filter: Vec<u8>| quil_types::proto::node::DeliverShardConsensusRequest {
            filter,
            channel: 2,
            data: b"certificate".to_vec(),
            from: vec![5; 897],
        };
        let (handle, mut engine) = crate::app_engine::AppEngineHandle::for_test(vec![1; 32]);
        assert!(!deliver_to_engine(None, request(vec![1; 32])), "no engine");
        assert!(
            !deliver_to_engine(Some(handle.clone()), request(vec![2; 32])),
            "another shard"
        );
        assert!(engine.try_recv().is_err());
        assert!(deliver_to_engine(Some(handle), request(vec![1; 32])));
        match engine.try_recv().unwrap() {
            crate::app_engine::AppEngineMessage::CwIn {
                channel,
                from,
                data,
            } => {
                assert_eq!(
                    (channel, from, data),
                    (2, vec![5; 897], b"certificate".to_vec())
                );
            }
            _ => panic!("expected CwIn"),
        }
    }

    #[tokio::test]
    async fn cluster_consensus_waits_for_subscription_and_peer() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let peers = Arc::new(AtomicUsize::new(0));
        let (installed, installation) = tokio::sync::oneshot::channel();
        let (queried, mut queries) = mpsc::unbounded_channel();
        let count = peers.clone();
        let task = tokio::spawn(async move {
            wait_for_cw_transport(
                async {
                    installation.await.unwrap();
                    Ok(())
                },
                || {
                    let count = count.load(Ordering::SeqCst);
                    queried.send(()).unwrap();
                    std::future::ready(Ok(count))
                },
                || false,
                &CancellationToken::new(),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(
            queries.try_recv().is_err(),
            "peer checks must follow subscription acknowledgement"
        );
        installed.send(()).unwrap();
        queries.recv().await.unwrap();
        assert!(
            !task.is_finished(),
            "a subscribed worker without a peer must still wait"
        );
        peers.store(1, Ordering::SeqCst);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn cluster_singleton_still_requires_successful_subscription() {
        let cancel = CancellationToken::new();
        assert!(wait_for_cw_transport(
            async { Ok(()) },
            || std::future::ready(Ok(0)),
            || true,
            &cancel
        )
        .await
        .unwrap());
        let denied = wait_for_cw_transport(
            async { Err(QuilError::P2p("subscription failed".into())) },
            || std::future::ready(Ok(0)),
            || true,
            &cancel,
        )
        .await;
        assert!(
            denied.is_err(),
            "singleton status cannot bypass a failed subscription"
        );
    }

    #[tokio::test]
    async fn cluster_transport_wait_cancels_during_subscription_or_peer_query() {
        for installed in [false, true] {
            let cancel = CancellationToken::new();
            let child_cancel = cancel.clone();
            let (entered, receive) = tokio::sync::oneshot::channel();
            let mut entered = Some(entered);
            let task = tokio::spawn(async move {
                let subscription = async {
                    if !installed {
                        std::future::pending::<()>().await;
                    }
                    Ok(())
                };
                wait_for_cw_transport(
                    subscription,
                    || {
                        if let Some(entered) = entered.take() {
                            entered.send(()).unwrap();
                        }
                        std::future::pending::<Result<usize>>()
                    },
                    || false,
                    &child_cancel,
                )
                .await
            });
            if installed {
                receive.await.unwrap();
            } else {
                tokio::task::yield_now().await;
            }
            cancel.cancel();
            assert!(
                !tokio::time::timeout(std::time::Duration::from_secs(1), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
            );
        }
    }

    /// A standalone worker starts the passes only for a protected, served
    /// and settled binding, one run at a time, and clears the run when
    /// they finish.
    #[tokio::test]
    async fn a_standalone_worker_starts_eviction_only_for_a_settled_protected_binding() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        let bound = vec![7u8; 32];
        let (handle, _receiver) = AppEngineHandle::for_test(bound.clone());
        let settled = crate::worker_allocator::PAYLOAD_EVICTION_SETTLE;
        let evicting = Arc::new(AtomicBool::new(false));
        let start = |handle: Option<&AppEngineHandle>, bound_for: Duration, keep: Vec<Vec<u8>>| {
            let no_storage: Option<(std::path::PathBuf, fn(&[u8]) -> bool)> = None;
            start_payload_eviction(
                1,
                handle,
                bound_for,
                &evicting,
                crdt.clone(),
                keep,
                no_storage,
            )
        };
        assert_eq!(
            start(None, settled, vec![bound.clone()]),
            Some("binding is not protected")
        );
        assert_eq!(
            start(Some(&handle), settled, vec![vec![8; 32]]),
            Some("binding is not protected")
        );
        assert_eq!(
            start(Some(&handle), Duration::from_secs(1), vec![bound.clone()]),
            Some("binding has not settled")
        );
        evicting.store(true, Ordering::SeqCst);
        assert_eq!(
            start(Some(&handle), settled, vec![bound.clone()]),
            Some("an eviction is running")
        );
        evicting.store(false, Ordering::SeqCst);
        assert_eq!(start(Some(&handle), settled, vec![bound.clone()]), None);
        for _ in 0..200 {
            if !evicting.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !evicting.load(Ordering::SeqCst),
            "the finished run is cleared"
        );
    }

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

#[cfg(test)]
mod data_ipc_bind_tests {
    use super::*;
    use crate::outage::test_logs::CapturedLogs;

    /// A DataIPC port another process holds is bound once it is released,
    /// with one warning naming the worker, its address and the error, and
    /// one line for the recovery.
    #[tokio::test]
    async fn a_held_data_ipc_port_is_bound_once_released() {
        let logs = CapturedLogs::default();
        let _guard = logs.install();
        let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = holder.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let binding = tokio::spawn({
            let cancel = cancel.clone();
            async move { bind_data_ipc(3, listen_addr, &cancel).await }
        });
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(!binding.is_finished(), "the port is held");
        drop(holder);
        let bound = tokio::time::timeout(Duration::from_secs(5), binding)
            .await
            .expect("bound after release")
            .unwrap();
        assert!(bound.is_some());
        let warns = logs.lines_with("DataIPC listener cannot bind");
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("core_id=3") && warns[0].contains(&listen_addr.to_string()),
            "{}",
            warns[0]
        );
        assert!(warns[0].contains("in use"), "names the error: {}", warns[0]);
        let bound_lines = logs.lines_with("DataIPC listener bound after");
        assert_eq!(bound_lines.len(), 1, "{bound_lines:?}");
        assert!(bound_lines[0].contains("failures="), "{}", bound_lines[0]);
        cancel.cancel();
    }
}

#[cfg(test)]
mod respawn_queue_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Records each filter it applies; the first waits for `release` when
    /// set, after `entered`.
    #[derive(Clone, Default)]
    struct Recorder {
        applied: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        done: Arc<AtomicBool>,
        hold_first: Arc<AtomicBool>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    impl Recorder {
        fn apply(&self) -> RespawnApply {
            let recorder = self.clone();
            Arc::new(move |filter| {
                let recorder = recorder.clone();
                Box::pin(async move {
                    recorder.applied.lock().unwrap().push(filter);
                    if recorder.hold_first.swap(false, Ordering::SeqCst) {
                        recorder.entered.notify_one();
                        recorder.release.notified().await;
                    }
                    recorder.done.store(true, Ordering::SeqCst);
                    Ok(Respawned::Applied)
                })
            })
        }

        fn applied(&self) -> Vec<Vec<u8>> {
            self.applied.lock().unwrap().clone()
        }
    }

    async fn eventually(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..200 {
            if done() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        done()
    }

    /// A Respawn received while the worker starts is accepted and applied
    /// once it is ready, the latest one winning; an empty one clears it.
    #[tokio::test]
    async fn a_respawn_received_while_starting_is_applied_once_ready() {
        let recorder = Recorder::default();
        let queue = Arc::new(RespawnQueue::default());
        assert!(
            queue
                .respawn(vec![1; 32], recorder.apply(), 1)
                .await
                .is_ok(),
            "accepted while starting"
        );
        assert!(queue
            .respawn(vec![2; 32], recorder.apply(), 1)
            .await
            .is_ok());
        tokio::task::yield_now().await;
        assert!(
            recorder.applied().is_empty(),
            "nothing is applied before the worker is ready"
        );
        queue.set_ready(recorder.apply(), 1);
        assert!(eventually(|| recorder.applied().len() == 1).await);
        assert_eq!(
            recorder.applied(),
            vec![vec![2u8; 32]],
            "the latest request wins"
        );

        let cleared = Recorder::default();
        let queue = Arc::new(RespawnQueue::default());
        assert!(queue.respawn(vec![1; 32], cleared.apply(), 1).await.is_ok());
        assert!(queue.respawn(Vec::new(), cleared.apply(), 1).await.is_ok());
        queue.set_ready(cleared.apply(), 1);
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert!(
            cleared.applied().is_empty(),
            "an empty filter clears the request"
        );
    }

    /// A respawn runs to its end when the master stops waiting for it.
    #[tokio::test]
    async fn a_respawn_completes_when_its_caller_stops_waiting() {
        let recorder = Recorder::default();
        recorder.hold_first.store(true, Ordering::SeqCst);
        let queue = Arc::new(RespawnQueue::default());
        queue.set_ready(recorder.apply(), 1);
        let call = {
            let (queue, apply) = (queue.clone(), recorder.apply());
            tokio::spawn(async move { queue.respawn(vec![1; 32], apply, 1).await })
        };
        tokio::time::timeout(Duration::from_secs(2), recorder.entered.notified())
            .await
            .unwrap();
        call.abort();
        let _ = call.await;
        recorder.release.notify_one();
        assert!(
            eventually(|| recorder.done.load(Ordering::SeqCst)).await,
            "the respawn ran to its end"
        );
    }

    /// Requests run one at a time; a newer one replaces one still waiting.
    #[tokio::test]
    async fn a_newer_respawn_replaces_a_waiting_one() {
        let recorder = Recorder::default();
        recorder.hold_first.store(true, Ordering::SeqCst);
        let queue = Arc::new(RespawnQueue::default());
        queue.set_ready(recorder.apply(), 1);
        let call = |filter: Vec<u8>| {
            let (queue, apply) = (queue.clone(), recorder.apply());
            tokio::spawn(async move { queue.respawn(filter, apply, 1).await })
        };
        let first = call(vec![1; 32]);
        tokio::time::timeout(Duration::from_secs(2), recorder.entered.notified())
            .await
            .unwrap();
        let second = call(vec![2; 32]);
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        let third = call(vec![3; 32]);
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert_eq!(recorder.applied(), vec![vec![1u8; 32]], "one at a time");
        recorder.release.notify_one();
        assert!(first.await.unwrap().is_ok());
        assert_eq!(
            second.await.unwrap().unwrap_err().code(),
            tonic::Code::Aborted
        );
        assert!(third.await.unwrap().is_ok());
        assert_eq!(recorder.applied(), vec![vec![1u8; 32], vec![3u8; 32]]);
    }

    /// A Respawn for the filter being applied waits for that application
    /// instead of repeating it; meanwhile the filter is reported as run.
    #[tokio::test]
    async fn a_respawn_for_the_filter_being_applied_runs_once() {
        let recorder = Recorder::default();
        recorder.hold_first.store(true, Ordering::SeqCst);
        let queue = Arc::new(RespawnQueue::default());
        queue.set_ready(recorder.apply(), 1);
        let call = |filter: Vec<u8>| {
            let (queue, apply) = (queue.clone(), recorder.apply());
            tokio::spawn(async move { queue.respawn(filter, apply, 1).await })
        };
        let first = call(vec![1; 32]);
        tokio::time::timeout(Duration::from_secs(2), recorder.entered.notified())
            .await
            .unwrap();
        assert_eq!(
            queue.pending(),
            Some(vec![1u8; 32]),
            "the filter being applied is reported"
        );
        let second = call(vec![1; 32]);
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        recorder.release.notify_one();
        assert_eq!(first.await.unwrap().unwrap(), Respawned::Applied);
        assert_eq!(
            second.await.unwrap().unwrap(),
            Respawned::Applied,
            "answered by the same application"
        );
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert_eq!(recorder.applied(), vec![vec![1u8; 32]], "applied once");
        assert_eq!(queue.pending(), None);
    }

    /// A worker with no master, store or engine.
    fn idle_worker() -> Arc<WorkerOnlyNode> {
        Arc::new(idle_node())
    }

    fn idle_node() -> WorkerOnlyNode {
        let config = WorkerNodeConfig {
            core_id: 1,
            master_endpoint: String::new(),
            listen_addr: "127.0.0.1:0".into(),
            channel_tls_ca_pem: None,
            channel_tls_leaf_pem: None,
            channel_tls_key_pem: None,
            parent_pid: None,
            app_consensus_cw: false,
            data_dir: None,
            channel_factory: None,
        };
        let signer: Arc<dyn Fn() -> Box<dyn quil_types::crypto::Signer> + Send + Sync> =
            Arc::new(|| -> Box<dyn quil_types::crypto::Signer> {
                unreachable!("no engine starts in this test")
            });
        WorkerOnlyNode::new(
            config,
            Arc::new(quil_store::testing::InMemoryClockStore::new()),
            Arc::new(crate::test_support::TestProverRegistry::new()),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            Arc::new(MessageCollector::new()),
            Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
            vec![1; 32],
            vec![2; 32],
            signer,
            false,
            1,
        )
    }

    /// A/B reproducer (M3): a PeerInfo naming another peer's ID with the
    /// sender's own key, unsigned, must not teach the worker that key for
    /// the ID (cluster workers attribute CW votes by it).
    #[tokio::test]
    async fn reproduces_worker_learns_unbound_peer_key() {
        use quil_types::crypto::Signer as _;
        let worker = idle_worker();
        let victim = quil_crypto::FalconSigner::generate();
        let victim_peer = quil_p2p::peer_id_from_falcon_pubkey(victim.public_key());
        let attacker = quil_crypto::FalconSigner::generate();
        let forged = quil_p2p::CanonicalPeerInfo {
            peer_id: victim_peer.clone(),
            timestamp: 1,
            ..Default::default()
        };
        let wire = quil_p2p::encode_canonical_peer_info(&forged, attacker.public_key(), &[]);
        worker.route_message(&wire, crate::bitmasks::GLOBAL_PEER_INFO, &[]);
        assert!(
            !worker
                .peer_key_by_id
                .lock()
                .unwrap()
                .contains_key(&victim_peer),
            "the worker attributes the victim's peer ID to the attacker's key from an unauthenticated PeerInfo"
        );
    }

    /// The filter `service`'s worker reports running.
    async fn reported_filter(service: &DataIpcServiceImpl) -> Vec<u8> {
        use quil_types::proto::node::data_ipc_service_server::DataIpcService as _;
        let request = tonic::Request::new(quil_types::proto::node::GetWorkerExecutionRequest {});
        service
            .get_worker_execution(request)
            .await
            .unwrap()
            .into_inner()
            .filter
    }

    /// A Respawn of the filter the running engine runs keeps that engine:
    /// it is neither stopped nor replaced.
    #[tokio::test]
    async fn a_respawn_of_the_running_filter_keeps_the_engine() {
        let worker = idle_worker();
        let (handle, _engine) = AppEngineHandle::for_test(vec![7; 32]);
        let cancel = CancellationToken::new();
        *worker.engine_handle.lock().unwrap() = Some(handle);
        *worker.engine_cancel.lock().unwrap() = Some(cancel.clone());
        let respawned =
            tokio::time::timeout(Duration::from_secs(5), worker.respawn(vec![7; 32])).await;
        assert!(
            matches!(respawned, Ok(Ok(Respawned::Kept))),
            "a running engine is kept"
        );
        assert!(!cancel.is_cancelled(), "the engine is not stopped");
        assert!(worker
            .running_engine()
            .is_some_and(|handle| handle.filter == vec![7u8; 32]));
    }

    /// An engine that has exited runs nothing, so the worker reports no
    /// filter and its master sends the Respawn again; a Respawn being
    /// applied while no engine runs is reported as run.
    #[tokio::test]
    async fn an_exited_engine_reports_no_filter() {
        let worker = idle_worker();
        worker.respawns.state.lock().unwrap().ready = true;
        let service = DataIpcServiceImpl {
            worker: worker.clone(),
        };
        let (handle, engine) = AppEngineHandle::for_test(vec![7; 32]);
        *worker.engine_handle.lock().unwrap() = Some(handle);
        *worker.engine_cancel.lock().unwrap() = Some(CancellationToken::new());
        assert_eq!(
            reported_filter(&service).await,
            vec![7u8; 32],
            "a running engine is reported"
        );
        drop(engine);
        assert!(
            reported_filter(&service).await.is_empty(),
            "an exited engine runs nothing"
        );
        assert!(worker.running_engine().is_none());
        worker.respawns.state.lock().unwrap().applying = Some(QueuedRespawn {
            filter: vec![8; 32],
            waiters: Vec::new(),
        });
        assert_eq!(
            reported_filter(&service).await,
            vec![8u8; 32],
            "a Respawn being applied is reported"
        );
    }

    /// While the worker starts, a payload eviction is refused as starting,
    /// and the master asks again at its next interval.
    #[tokio::test]
    async fn a_payload_eviction_while_starting_answers_starting() {
        use quil_types::proto::node::data_ipc_service_server::DataIpcService as _;
        let service = DataIpcServiceImpl {
            worker: idle_worker(),
        };
        let request =
            tonic::Request::new(quil_types::proto::node::EvictPayloadRequest { keep: Vec::new() });
        let status = service.evict_payload(request).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(status.message(), WORKER_STARTING);
    }

    /// The master's log export is answered from the export the node layer
    /// supplies, while the worker starts too; a worker process without one
    /// refuses it as a precondition, which the master records as failed.
    #[tokio::test]
    async fn log_exports_are_streamed_from_the_supplied_export() {
        use quil_types::proto::node::data_ipc_service_server::DataIpcService as _;
        use quil_types::proto::node::{ExportWorkerLogsChunk, ExportWorkerLogsRequest};
        let request = || {
            tonic::Request::new(ExportWorkerLogsRequest {
                since_unix: 1,
                until_unix: 2,
                ..Default::default()
            })
        };
        let unwired = DataIpcServiceImpl {
            worker: idle_worker(),
        };
        let status = unwired.export_logs(request()).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);

        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let export: LogExportSource = {
            let asked = asked.clone();
            Arc::new(move |request: ExportWorkerLogsRequest| {
                asked.lock().unwrap().push(request.until_unix);
                let (tx, rx) = mpsc::channel(2);
                tx.try_send(Ok(ExportWorkerLogsChunk {
                    summary: Some(Default::default()),
                    lines: b"line\n".to_vec(),
                }))
                .unwrap();
                rx
            })
        };
        let wired = DataIpcServiceImpl {
            worker: Arc::new(idle_node().with_log_export(export)),
        };
        assert!(!wired.worker.respawns.is_ready(), "the worker is starting");
        let mut stream = wired.export_logs(request()).await.unwrap().into_inner();
        let first = std::future::poll_fn(|cx| {
            tonic::codegen::tokio_stream::Stream::poll_next(std::pin::Pin::new(&mut stream), cx)
        })
        .await
        .unwrap()
        .unwrap();
        assert!(first.summary.is_some());
        assert_eq!(first.lines, b"line\n");
        assert_eq!(*asked.lock().unwrap(), vec![2]);
    }
}

/// Pause between the end of a periodic prover-tree sync and the start of the
/// next, before its jitter.
const PROVER_TREE_SYNC_PERIOD: Duration = Duration::from_secs(10);

/// Most random delay added to a periodic pause. Workers that started
/// together, as after a release, would otherwise sync in lockstep; the
/// added 0-2 s (1 s on average) only lengthens the period, so it adds no
/// archive reads.
const PROVER_TREE_SYNC_JITTER: Duration = Duration::from_secs(2);

/// Most random delay before the first attempt of a blocking prover-tree
/// sync. Every worker of every node receives a GLOBAL frame within moments
/// of the others, and a root change sends all of them to the archives at
/// once. GLOBAL frames come about 10 s apart and the sync holds this
/// worker's GLOBAL stream for its own connection and diff anyway, so a
/// second more still leaves the registry current well before the next frame.
const BLOCKING_PROVER_SYNC_JITTER: Duration = Duration::from_secs(1);

/// Pause before a blocking sync's retry, before its jitter of up to as much
/// again: retries of workers that failed together then spread out too.
const BLOCKING_PROVER_SYNC_RETRY: Duration = Duration::from_millis(500);

/// The wait before the next periodic prover-tree sync.
fn periodic_prover_tree_sync_pause() -> Duration {
    PROVER_TREE_SYNC_PERIOD + crate::prover_tree_syncer::sync_jitter(PROVER_TREE_SYNC_JITTER)
}

/// The wait before attempt `attempt` (from 0) of a blocking prover-tree sync.
fn blocking_prover_sync_delay(attempt: usize) -> Duration {
    if attempt == 0 {
        crate::prover_tree_syncer::sync_jitter(BLOCKING_PROVER_SYNC_JITTER)
    } else {
        BLOCKING_PROVER_SYNC_RETRY
            + crate::prover_tree_syncer::sync_jitter(BLOCKING_PROVER_SYNC_RETRY)
    }
}

/// Run `sync` until `cancel`, each run a jittered pause after the previous
/// one ended. A fixed-rate timer would instead fire the ticks a slow sync
/// (an archive timing out) missed back to back, at the archive that is
/// already slow. `sync` returns its error, if any.
async fn periodic_prover_tree_syncs<F, Fut>(cancel: CancellationToken, core_id: u32, mut sync: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    // A failing sync leaves the worker's GLOBAL view, and with it its
    // committee sessions, behind; three failures in a row (about 30 s) make
    // it an outage.
    let mut outage = crate::outage::Outage::begin_after(3);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(periodic_prover_tree_sync_pause()) => {
                let error = sync().await;
                log_prover_tree_sync(&mut outage, core_id, std::time::Instant::now(), error);
            }
        }
    }
}

/// Log the outage transitions of a worker's periodic prover-tree sync;
/// `error` is the attempt's failure, `None` when it succeeded.
fn log_prover_tree_sync(
    outage: &mut crate::outage::Outage,
    core_id: u32,
    now: std::time::Instant,
    error: Option<String>,
) {
    use crate::outage::OutageEvent;
    let failed = error.is_some();
    let error = error.unwrap_or_default();
    match outage.observe(now, !failed) {
        Some(OutageEvent::Began) => {
            tracing::warn!(core_id, error = %error, scope = "local", action = "check",
            "periodic prover-tree sync failing; this worker's GLOBAL view stops advancing; \
             check its connection to the master and the master's GLOBAL sync")
        }
        Some(OutageEvent::Continues { secs, failures }) => tracing::warn!(core_id, secs, failures,
            error = %error, scope = "local", action = "check", "periodic prover-tree sync still failing"),
        Some(OutageEvent::Ended { secs, failures }) => tracing::info!(
            core_id,
            secs,
            failures,
            "periodic prover-tree sync recovered"
        ),
        None => {}
    }
}

#[cfg(test)]
mod prover_tree_sync_log_tests {
    use super::*;
    use crate::outage::test_logs::CapturedLogs;

    /// A sync failing three times in a row warns once, naming the worker and
    /// the error; a success then logs the recovery with its duration.
    #[test]
    fn a_failing_prover_tree_sync_warns_once_then_logs_its_recovery() {
        let logs = CapturedLogs::default();
        let _guard = logs.install();
        let start = std::time::Instant::now();
        let at = |secs: u64| start + std::time::Duration::from_secs(secs);
        let mut outage = crate::outage::Outage::begin_after(3);
        for secs in [0, 10, 20, 30] {
            log_prover_tree_sync(&mut outage, 7, at(secs), Some("master unreachable".into()));
        }
        let warns = logs.lines_with("prover-tree sync failing");
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("core_id=7") && warns[0].contains("master unreachable"),
            "{}",
            warns[0]
        );
        assert!(
            warns[0].contains("scope") && warns[0].contains("check"),
            "{}",
            warns[0]
        );
        log_prover_tree_sync(&mut outage, 7, at(40), None);
        let recovered = logs.lines_with("prover-tree sync recovered");
        assert_eq!(recovered.len(), 1);
        assert!(
            recovered[0].contains("secs=40") && recovered[0].contains("failures=4"),
            "{}",
            recovered[0]
        );
    }

    /// A sync slowed by a timing-out archive is followed by a full pause, not
    /// by the syncs its timer missed meanwhile.
    #[tokio::test(start_paused = true)]
    async fn a_slow_periodic_prover_tree_sync_is_not_followed_by_catch_up_syncs() {
        type Runs = Arc<std::sync::Mutex<Vec<(tokio::time::Instant, tokio::time::Instant)>>>;
        let runs: Runs = Default::default();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(periodic_prover_tree_syncs(cancel.clone(), 7, {
            let runs = runs.clone();
            move || {
                let runs = runs.clone();
                async move {
                    let start = tokio::time::Instant::now();
                    let first = runs.lock().unwrap().is_empty();
                    if first {
                        tokio::time::sleep(Duration::from_secs(35)).await;
                    }
                    runs.lock()
                        .unwrap()
                        .push((start, tokio::time::Instant::now()));
                    None
                }
            }
        }));
        tokio::time::sleep(Duration::from_secs(120)).await;
        cancel.cancel();
        task.await.unwrap();
        let runs = runs.lock().unwrap();
        assert!(runs.len() >= 5, "{} syncs", runs.len());
        for pair in runs.windows(2) {
            let pause = pair[1].0 - pair[0].1;
            assert!(
                (PROVER_TREE_SYNC_PERIOD..=PROVER_TREE_SYNC_PERIOD + PROVER_TREE_SYNC_JITTER)
                    .contains(&pause),
                "pause {pause:?} after a sync"
            );
        }
    }

    /// Periodic pauses and blocking-sync delays vary within their bounds, so
    /// workers that start together drift apart.
    #[test]
    fn prover_tree_sync_delays_are_jittered_within_their_bounds() {
        let distinct = |delays: Vec<Duration>, low: Duration, high: Duration| {
            assert!(
                delays.iter().all(|delay| (low..=high).contains(delay)),
                "{delays:?}"
            );
            delays
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
        };
        let periodic = (0..64).map(|_| periodic_prover_tree_sync_pause()).collect();
        assert!(
            distinct(
                periodic,
                PROVER_TREE_SYNC_PERIOD,
                PROVER_TREE_SYNC_PERIOD + PROVER_TREE_SYNC_JITTER
            ) > 1
        );
        let first = (0..64).map(|_| blocking_prover_sync_delay(0)).collect();
        assert!(distinct(first, Duration::ZERO, BLOCKING_PROVER_SYNC_JITTER) > 1);
        let retry = (0..64).map(|_| blocking_prover_sync_delay(1)).collect();
        assert!(
            distinct(
                retry,
                BLOCKING_PROVER_SYNC_RETRY,
                BLOCKING_PROVER_SYNC_RETRY * 2
            ) > 1
        );
    }

    /// A key whose hash is not the peer ID is never learned; a full map
    /// keeps the keys CW messages used.
    #[test]
    fn learned_peer_keys_are_bound_to_their_ids_and_bounded() {
        let key = |i: u32| {
            let mut key = vec![0u8; quil_crypto::FALCON_PUBLIC_KEY_LEN];
            key[..4].copy_from_slice(&i.to_be_bytes());
            key
        };
        let id = |i: u32| quil_p2p::peer_id_from_falcon_pubkey(&key(i));
        let mut keys = std::collections::HashMap::new();
        assert!(!learn_peer_key(&mut keys, id(1), key(2)), "another key");
        assert!(!learn_peer_key(&mut keys, id(1), vec![1; 32]), "not a key");
        assert!(!learn_peer_key(&mut keys, Vec::new(), key(1)));
        assert!(keys.is_empty());
        assert!(learn_peer_key(&mut keys, id(0), key(0)));
        keys.get_mut(&id(0)).unwrap().1 = true;
        for i in 1..=MAX_PEER_KEYS as u32 {
            assert!(learn_peer_key(&mut keys, id(i), key(i)));
        }
        assert!(keys.len() <= MAX_PEER_KEYS);
        assert!(keys.contains_key(&id(0)), "a used key survives pruning");
        assert!(keys.contains_key(&id(MAX_PEER_KEYS as u32)));
    }
}
