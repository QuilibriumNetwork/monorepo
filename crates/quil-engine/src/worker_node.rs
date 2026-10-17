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
    /// Current engine handle (set after Respawn).
    engine_handle: std::sync::Mutex<Option<AppEngineHandle>>,
    /// Stop the old engine and its transport wait before rebinding this worker.
    engine_cancel: std::sync::Mutex<Option<CancellationToken>>,
    respawn_lock: tokio::sync::Mutex<()>,
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
    /// Peer-id → committee Falcon public-key, learned from inbound
    /// `GLOBAL_PEER_INFO`. Mirrors the master's PeerInfo cache: inbound app-shard
    /// CW messages (`shard_cw_bitmask`) carry only the gossip sender's PeerId,
    /// but the engine's `CwIn` handler needs the raw committee key
    /// (`FalconPublicKey::from_bytes`) and DROPS any message whose `from` doesn't
    /// resolve. Without this a cluster worker would receive CW votes and silently
    /// drop every one → its simplex engine never reaches quorum.
    peer_key_by_id: std::sync::Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
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

type MasterClient =
    quil_types::proto::global::global_service_client::GlobalServiceClient<tonic::transport::Channel>;

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
        marker.lock().unwrap().is_some_and(|since| since.elapsed() < MASTER_RELAY_RETRY_AFTER)
    }

    async fn client(&self) -> Option<MasterClient> {
        let factory = self.factory.clone()?;
        let mut client = self.client.lock().await;
        if client.is_none() {
            let Ok(Ok(channel)) = tokio::time::timeout(MASTER_RELAY_TIMEOUT, factory()).await else {
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
    async fn relay_direct(&self, filter: Vec<u8>, channel: u64, data: Vec<u8>, recipients: Vec<Vec<u8>>) -> bool {
        if Self::recently(&self.direct_unsupported) {
            return false;
        }
        let Some(mut client) = self.client().await else { return false };
        let request = quil_types::proto::global::SendShardConsensusDirectRequest { filter, channel, data, recipients };
        match tokio::time::timeout(MASTER_RELAY_TIMEOUT, client.send_shard_consensus_direct(request)).await {
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
        let Some(mut client) = self.client().await else { return MasterSubmission::Unavailable };
        let request = quil_types::proto::global::SubmitWorkerProverMessageRequest { core_id, request };
        match tokio::time::timeout(MASTER_RELAY_TIMEOUT, client.submit_worker_prover_message(request)).await {
            Ok(Ok(response)) if response.get_ref().accepted => MasterSubmission::Queued,
            Ok(Ok(_)) => MasterSubmission::Held,
            Ok(Err(status)) if status.code() == tonic::Code::InvalidArgument => MasterSubmission::Refused,
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
    pub(crate) fn historical_committee_source(self: &Arc<Self>) -> crate::historical_committee::HistoricalCommitteeSource {
        let relay = self.clone();
        Arc::new(move |filter: Vec<u8>, anchor: u64| {
            let relay = relay.clone();
            Box::pin(async move {
                let unavailable = |reason: String| quil_types::error::QuilError::ExecutionUnavailable(reason);
                let mut client = relay.client().await.ok_or_else(|| unavailable("no master channel".into()))?;
                let request = quil_types::proto::global::GetHistoricalCommitteesRequest { filter, anchor };
                let response = tokio::time::timeout(
                    crate::historical_committee::HISTORICAL_COMMITTEE_TIMEOUT,
                    client.get_historical_committees(request),
                )
                .await
                .map_err(|_| unavailable("master historical committees timed out".into()))?
                .map_err(|status| unavailable(format!("master historical committees: {status}")))?;
                Ok(response.into_inner().committees.into_iter().map(|c| c.members).collect())
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = quil_types::error::Result<Vec<Vec<Vec<u8>>>>> + Send>>
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
    let handoff_prefix = quil_execution::global_intrinsic::handoff::TYPE_COMMITTEE_HANDOFF.to_be_bytes();
    Arc::new(move |canonical: Vec<u8>| {
        if halted.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::debug!(core_id, "holding back GLOBAL submission — coverage halt active");
            return;
        }
        let (relay, publish) = (relay.clone(), publish.clone());
        tokio::spawn(async move {
            let handoff = canonical.starts_with(&handoff_prefix);
            let outcome = relay.submit(core_id, canonical.clone()).await;
            if outcome != MasterSubmission::Unavailable {
                if outcome == MasterSubmission::Refused {
                    warn!(core_id, handoff, "master refused this worker's GLOBAL submission");
                }
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
                .and_then(|request| quil_execution::message_envelope::CanonicalMessageBundle {
                    requests: vec![Some(request)],
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64,
                }.to_canonical_bytes());
            match bundle {
                Ok(bytes) => publish(crate::bitmasks::GLOBAL_PROVER.to_vec(), bytes).await,
                Err(error) => warn!(%error, "committee handoff submission could not be encoded"),
            }
        });
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
            engine_handle: std::sync::Mutex::new(None),
            engine_cancel: std::sync::Mutex::new(None),
            respawn_lock: tokio::sync::Mutex::new(()),
            engine_event_tx,
            engine_event_rx: std::sync::Mutex::new(Some(engine_event_rx)),
            publish_fn: None,
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
    async fn relay_direct(&self, filter: Vec<u8>, channel: u64, data: Vec<u8>, recipients: Vec<Vec<u8>>) -> bool {
        self.master_relay.relay_direct(filter, channel, data, recipients).await
    }

    /// Recover bounded historical registration proofs through the master.
    pub fn with_storage_history_source(mut self, source: crate::storage_history::GlobalVertexProofSource) -> Self {
        self.storage_history_source = Some(source);
        self
    }

    pub fn with_global_anchor_source(mut self, source: crate::global_anchor::GlobalAnchorSource) -> Self {
        self.global_anchor_source = Some(source);
        self
    }

    pub fn with_outgoing_history_source(mut self, source: crate::app_handoff::OutgoingHistorySource) -> Self {
        self.outgoing_history_source = Some(source);
        self
    }

    pub fn with_delivery_frame_source(mut self, source: crate::app_engine::DeliveryFrameSource) -> Self {
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
                    match self.refresh_registry() {
                        Ok(()) => info!("initial prover-tree sync complete"),
                        Err(error) => warn!(%error, "initial prover registry refresh failed; will retry"),
                    }
                }
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
        // prover tree from the master and refreshes the registry on a fixed
        // cadence, so the registry becomes current and the engine's CW retry can
        // build the committee. Trust-the-peer sync (empty expected root).
        if self.prover_tree_syncer.is_some() {
            let this = self.clone();
            let cancel = self.cancel.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tick.tick() => {
                            if let Some(syncer) = this.prover_tree_syncer.as_ref() {
                                // Anchor against the last-seen global frame header's
                                // certified prover-tree roots. Empty
                                // only before the first global frame arrives, in which
                                // case we fall back to trust-the-peer for that window.
                                let anchor = {
                                    this.latest_prover_tree_anchor.lock().unwrap().clone()
                                };
                                match syncer.sync_prover_tree(&anchor).await {
                                    Ok(_) => {
                                        if let Err(error) = this.refresh_registry() {
                                            tracing::warn!(%error, "periodic prover registry refresh failed");
                                        }
                                    }
                                    Err(e) => tracing::debug!(error = %e, "periodic prover-tree sync failed"),
                                }
                            }
                        }
                    }
                }
            });
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

        // 2. Start gRPC server for DataIPCService
        let ipc_service = DataIpcServiceImpl {
            worker: self.clone(),
        };
        let listen_addr = self.config.listen_addr.parse()
            .map_err(|e| QuilError::Internal(format!("bad listen addr: {}", e)))?;

        let server_cancel = self.cancel.clone();
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
        let server_handle = tokio::spawn(async move {
            info!("DataIPC gRPC server starting on {} (mtls={})", listen_addr, channel_tls.is_some());
            let mut builder = Server::builder()
                // Reap dead master connections (h2 PING) so a master that
                // dies without FIN doesn't leave the stream fd behind.
                .http2_keepalive_interval(Some(std::time::Duration::from_secs(20)))
                .http2_keepalive_timeout(Some(std::time::Duration::from_secs(10)))
                .tcp_keepalive(Some(std::time::Duration::from_secs(60)));
            if let Some(tls) = channel_tls {
                match builder.tls_config(tls) {
                    Ok(b) => builder = b,
                    Err(e) => {
                        error!(error = %e, "DataIPC gRPC TLS config invalid — server not started");
                        return;
                    }
                }
            }
            if let Err(e) = builder
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
            // TODO
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
                                        tokio::spawn(async move {
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
                                                tokio::select! {
                                                    biased;
                                                    _ = cancel.cancelled() => {},
                                                    _ = target.execution_record().recovering(&filter, crate::prover_tree_syncer::recover_shard_from_latest(
                                                        syncer.as_ref(), &filter, local, &target,
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
    /// one with the given filter.
    pub async fn respawn(&self, filter: Vec<u8>) -> Result<()> {
        let _respawn = self.respawn_lock.lock().await;
        let core_id = self.config.core_id;

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
            return Ok(());
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
            db_config: {
                let mut d = quil_config::DbConfig::default();
                if let Some(dir) = self.config.data_dir.as_ref() {
                    d.path = dir.to_string_lossy().into_owned();
                }
                d.worker_path_prefix = String::new();
                d.worker_paths = Vec::new();
                d
            },
            // Multi-process worker: consolidation hook not wired here yet (the
            // thread-mode path is the mainnet path); the flip still occurs.
            unified_cutover_hook: None,
        };

        let (engine, handle) = AppConsensusEngine::new(
            core_id,
            filter.clone(),
            deps,
            self.engine_event_tx.clone(),
        );
        let engine = engine.with_storage_history_source(self.storage_history_source.clone())
            .with_outgoing_history_source(self.outgoing_history_source.clone())
            .with_global_anchor_source(self.global_anchor_source.clone())
            .with_historical_committee_source(
                self.config.channel_factory.is_some().then(|| self.master_relay.historical_committee_source()),
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
        tokio::spawn(async move {
            tokio::select! {
                _ = run_cancel.cancelled() => {},
                _ = engine.run(signer_factory) => {},
            }
            run_cancel.cancel();
        });

        // Subscribe to per-shard bitmasks on the worker's own p2p so
        // peer-published shard traffic flows in. No-op when running in
        // proxy mode (worker_p2p is None there).
        self.subscribe_to_shard_bitmasks(&filter, transport_handle, engine_cancel).await;

        Ok(())
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
        let Some(p2p) = self.worker_p2p.clone() else { return };
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
                let frame = clock.get_latest_global_clock_frame().ok()
                    .and_then(|frame| frame.header.map(|h| h.frame_number)).unwrap_or(0);
                if let Some(global) = global.as_ref() {
                    match crate::app_handoff::resolve(global, &filter, frame) {
                        Ok(crate::app_handoff::SessionChoice::Session(session)) => {
                            return session.members.len() == 1 && session.members[0] == public_key;
                        }
                        Ok(crate::app_handoff::SessionChoice::Legacy) => {},
                        _ => return false,
                    }
                } else if quil_types::consensus::committee_handoff_policy().is_some() {
                    return false;
                }
                registry.get_active_provers(&filter, frame)
                    .is_ok_and(|members| members.len() == 1 && members[0].public_key == public_key)
            };
            let readiness = wait_for_cw_transport(
                subscribe_p2p.subscribe_confirmed(topic),
                || p2p.subscribed_peer_count(count_topic.clone()),
                sole_member,
                &cancel,
            ).await;
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
                Ok(false) => {},
                Err(error) => warn!(core_id, %error, "cluster CW transport readiness failed"),
            }
        });
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
        let Some(hg) = self.hypergraph.as_ref() else { return };
        if let Err(error) = hg.checkpoint_frame_cursor(
            frame_number.saturating_sub(1),
            &quil_store::encoding::global_materialized_cursor_key(),
        ) {
            warn!(frame = frame_number, %error, "could not checkpoint authenticated GLOBAL state");
        }
    }

    /// Blocking prover-tree sync. Mirrors Go's
    /// `AppConsensusEngine.performBlockingGlobalHypersync`: calls the
    /// syncer up to 3 times with 500ms delay, checks convergence,
    /// refreshes the prover registry after each attempt. The 5-frame
    /// cooldown (`sync_cooldown_until`) prevents sync-storms.
    async fn perform_blocking_prover_sync(
        &self,
        frame_number: u64,
        expected_roots: &[Vec<u8>],
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
            expected = expected_roots.first().map(hex::encode).unwrap_or_default(),
            phases = expected_roots.len(),
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
            match syncer.sync_prover_tree(expected_roots).await {
                Ok(true) => {
                    info!(
                        attempt = attempt + 1,
                        "prover tree sync converged"
                    );
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
                if !info.peer_id.is_empty() && !info.public_key.is_empty() {
                    self.peer_key_by_id
                        .lock()
                        .unwrap()
                        .insert(info.peer_id, info.public_key);
                }
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
            if let Some((channel, cw_bytes)) = crate::bitmasks::shard_cw_admit(filter, data, &self.local_cw_tag) {
                let from_key = self
                    .peer_key_by_id
                    .lock()
                    .unwrap()
                    .get(from)
                    .cloned()
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

// =====================================================================
// DataIPCService — gRPC server on the worker for master commands
// =====================================================================

struct DataIpcServiceImpl {
    worker: Arc<WorkerOnlyNode>,
}

/// Hand a directly received shard consensus message to `handle` when it is
/// the engine for that shard. False: this worker does not run it.
fn deliver_to_engine(
    handle: Option<crate::app_engine::AppEngineHandle>,
    request: quil_types::proto::node::DeliverShardConsensusRequest,
) -> bool {
    let Some(handle) = handle.filter(|handle| handle.filter == request.filter) else { return false };
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

#[tonic::async_trait]
impl quil_types::proto::node::data_ipc_service_server::DataIpcService
    for DataIpcServiceImpl
{
    /// A committee member's message the master received directly, for this
    /// worker's shard. Handed to the engine exactly as the topic copy would
    /// be; the engine checks `from` against the committee.
    async fn deliver_shard_consensus(
        &self,
        request: tonic::Request<quil_types::proto::node::DeliverShardConsensusRequest>,
    ) -> std::result::Result<tonic::Response<quil_types::proto::node::DeliverShardConsensusResponse>, tonic::Status> {
        let handle = self
            .worker
            .engine_handle
            .lock()
            .map_err(|_| tonic::Status::unavailable("worker handle unavailable"))?
            .clone();
        let accepted = deliver_to_engine(handle, request.into_inner());
        Ok(tonic::Response::new(quil_types::proto::node::DeliverShardConsensusResponse { accepted }))
    }

    async fn get_app_fee_snapshot(
        &self, request: tonic::Request<quil_types::proto::node::GetAppFeeSnapshotRequest>,
    ) -> std::result::Result<tonic::Response<quil_types::proto::node::GetAppFeeSnapshotResponse>, tonic::Status> {
        let application: [u8; 32] = request.into_inner().application.as_slice().try_into()
            .map_err(|_| tonic::Status::invalid_argument("application must be 32 bytes"))?;
        let handle = self.worker.engine_handle.lock().map_err(|_| tonic::Status::unavailable("worker handle unavailable"))?.clone()
            .ok_or_else(|| tonic::Status::unavailable("worker has no active engine"))?;
        if handle.filter.as_slice() != application.as_slice() {
            return Err(tonic::Status::unavailable("worker does not execute this full application"));
        }
        let s = handle.fee_snapshot().filter(|s| s.application == application)
            .ok_or_else(|| tonic::Status::unavailable("materialized pricing snapshot unavailable"))?;
        Ok(tonic::Response::new(quil_types::proto::node::GetAppFeeSnapshotResponse {
            application: s.application.to_vec(), frame_number: s.frame_number,
            global_frame_number: s.global_frame_number, difficulty: s.difficulty,
            world_state_bytes: s.world_state_bytes, fee_multiplier_vote: s.fee_multiplier_vote,
        }))
    }

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

    async fn prepare_storage_confirm(
        &self,
        request: tonic::Request<quil_types::proto::node::PrepareStorageConfirmRequest>,
    ) -> std::result::Result<
        tonic::Response<quil_types::proto::node::PrepareStorageConfirmResponse>,
        tonic::Status,
    > {
        let req = request.into_inner();
        // Only the worker executing this shard holds its data. The master's
        // own store does not, so its confirm registered leaves this worker
        // could never prove, and every frame it attested was rejected.
        let bound = self
            .worker
            .engine_handle
            .lock()
            .map_err(|_| tonic::Status::unavailable("worker handle unavailable"))?
            .as_ref()
            .is_some_and(|handle| handle.filter == req.filter);
        if !bound || req.filter.is_empty() {
            return Err(tonic::Status::failed_precondition("worker is not bound to this filter"));
        }
        let (Some(crdt), Some(kv)) = (self.worker.hypergraph.clone(), self.worker.kv_db.clone()) else {
            return Err(tonic::Status::unavailable("worker has no shard storage"));
        };
        let member = self.worker.local_prover_address.clone();
        // A confirm in epoch E registers, and encodes, the leaves for E + 1.
        let epoch = quil_types::consensus::epoch_for_frame(req.frame_number) + 1;
        let filter = req.filter;
        // The bound shard first, then the shards a recorded change creates
        // from it, all from this worker's store.
        let mut filters = vec![filter.clone()];
        filters.extend(req.targets.into_iter().filter(|target| !target.is_empty() && *target != filter));
        let roots = tokio::task::spawn_blocking(move || {
            crate::app_shard_metadata::compute_storage_confirm(
                &crdt,
                &quil_store::replica_store::ReplicaStore::new(kv),
                &filters,
                &member,
                epoch,
                quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
                &quil_crypto::sdr::SdrParams::default(),
            )
        })
        .await
        .map_err(|e| tonic::Status::internal(format!("storage confirm task: {e}")))?
        .map_err(|e| tonic::Status::unavailable(format!("storage confirm preparation failed: {e}")))?;
        // Before its data sync completes the worker has nothing to encode; an
        // empty registration would leave it unattested for the next epoch.
        if roots.iter().filter(|group| group.filter == filter).all(|group| group.entries.is_empty()) {
            return Err(tonic::Status::failed_precondition("worker holds no data for this filter yet"));
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
        let mut seal = quil_execution::global_intrinsic::handoff::TYPE_COMMITTEE_HANDOFF.to_be_bytes().to_vec();
        seal.extend_from_slice(b"closing seal");
        assert_eq!(relay.submit(4, header.clone()).await, MasterSubmission::Unavailable);

        let settle = || async {
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
        };
        halted.store(true, std::sync::atomic::Ordering::Relaxed);
        submit(header.clone());
        submit(seal.clone());
        settle().await;
        assert!(published.lock().unwrap().is_empty(), "nothing leaves during a halt");

        halted.store(false, std::sync::atomic::Ordering::Relaxed);
        submit(header);
        submit(seal.clone());
        settle().await;
        let published = published.lock().unwrap();
        assert_eq!(published.len(), 1, "only the seal is gossiped");
        assert_eq!(published[0].0, crate::bitmasks::GLOBAL_PROVER.to_vec());
        let bundle = quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(&published[0].1).unwrap();
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
        assert!(!deliver_to_engine(Some(handle.clone()), request(vec![2; 32])), "another shard");
        assert!(engine.try_recv().is_err());
        assert!(deliver_to_engine(Some(handle), request(vec![1; 32])));
        match engine.try_recv().unwrap() {
            crate::app_engine::AppEngineMessage::CwIn { channel, from, data } => {
                assert_eq!((channel, from, data), (2, vec![5; 897], b"certificate".to_vec()));
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
                async { installation.await.unwrap(); Ok(()) },
                || {
                    let count = count.load(Ordering::SeqCst);
                    queried.send(()).unwrap();
                    std::future::ready(Ok(count))
                },
                || false,
                &CancellationToken::new(),
            ).await
        });
        tokio::task::yield_now().await;
        assert!(queries.try_recv().is_err(), "peer checks must follow subscription acknowledgement");
        installed.send(()).unwrap();
        queries.recv().await.unwrap();
        assert!(!task.is_finished(), "a subscribed worker without a peer must still wait");
        peers.store(1, Ordering::SeqCst);
        assert!(tokio::time::timeout(std::time::Duration::from_secs(3), task).await.unwrap().unwrap().unwrap());
    }

    #[tokio::test]
    async fn cluster_singleton_still_requires_successful_subscription() {
        let cancel = CancellationToken::new();
        assert!(wait_for_cw_transport(async { Ok(()) }, || std::future::ready(Ok(0)), || true, &cancel).await.unwrap());
        let denied = wait_for_cw_transport(async { Err(QuilError::P2p("subscription failed".into())) },
            || std::future::ready(Ok(0)), || true, &cancel).await;
        assert!(denied.is_err(), "singleton status cannot bypass a failed subscription");
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
                wait_for_cw_transport(subscription, || {
                    if let Some(entered) = entered.take() { entered.send(()).unwrap(); }
                    std::future::pending::<Result<usize>>()
                }, || false, &child_cancel).await
            });
            if installed { receive.await.unwrap(); } else { tokio::task::yield_now().await; }
            cancel.cancel();
            assert!(!tokio::time::timeout(std::time::Duration::from_secs(1), task).await.unwrap().unwrap().unwrap());
        }
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
