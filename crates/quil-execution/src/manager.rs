#[cfg(all(test, feature = "confidential-tokens"))]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use num_bigint::BigInt;
use quil_types::crypto::InclusionProver;
use quil_types::error::{QuilError, Result};
use quil_types::execution::{ProcessMessageResult, ShardExecutionEngine};
use quil_types::proto::node;

use crate::domains;
use crate::engines::*;

#[path = "execution_branch.rs"]
mod execution_branch;
pub use execution_branch::{
    busy_unavailable, lock_unavailable, source_busy, ExecutionBranch, ExecutionBranchLimits,
    ExecutionPublicationGuard,
};

/// State-dependent providers for a separate execution manager. The caller must
/// construct them over the same committed checkpoint and serialize capture
/// against frame materialization/sync. This is engine construction, not a
/// database snapshot, selected-parent check, or finalization operation.
pub struct ExecutionForkContext {
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    /// The frame store used by the global intrinsic.
    pub clock_store: Arc<dyn quil_types::store::ClockStore>,
    /// GLOBAL anchors for token, compute and hypergraph claims. App workers may
    /// keep these in a different store from their own frame chain.
    pub global_clock_store: Arc<dyn quil_types::store::ClockStore>,
    pub shards_store: Option<Arc<dyn quil_types::store::ShardsStore>>,
    pub prover_registry: Arc<dyn quil_types::consensus::ProverRegistry>,
}

/// Manages multiple execution engines and routes messages to the
/// appropriate engine based on domain address.
pub struct ExecutionEngineManager {
    engines: RwLock<HashMap<String, Box<dyn ShardExecutionEngine>>>,
    /// Shared CRDT used by the global/token/hypergraph engines. Held
    /// here so callers can trigger a frame-keyed `commit` after
    /// processing all bundles — this is what flushes the in-memory
    /// phase trees to the on-disk hypergraph store, making new
    /// vertices visible to `prover_registry::refresh_from_store` and
    /// to peer HyperSync.
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    /// The shard grid store (`None` for app-shard-only managers). Held so
    /// [`Self::refresh_shard_prefixes`] can re-read the grid after a split/merge
    /// flip and re-attribute the CRDT's per-app prefix sets + size buckets.
    shards_store: Option<Arc<dyn quil_types::store::ShardsStore>>,
    global_quil_fee: RwLock<Option<crate::pricing::GlobalQuilFeeSnapshot>>,
    /// Pricing inputs of the last committed GLOBAL frame, published every
    /// frame: the venue reward mints (and later settlements) execute in.
    global_venue_fee: RwLock<Option<crate::pricing::GlobalQuilFeeSnapshot>>,
    /// Network selector every venue on this node prices growth for
    /// (`pricing::fee_multiplier_for_cost`). Mainnet unless configured.
    pricing_network: u8,
    /// Applications whose local block summary must be rebuilt from block records
    /// before the next report (see [`Self::rebuild_block_summary_before_report`]).
    summary_rebuilds: RwLock<std::collections::HashSet<[u8; 32]>>,
}

/// The filter of the shard that executed an operation: a shard holding the
/// whole application is named by the bare application address, which is the
/// filter its frames are stored under — `encode_shard_bit_path` would give the
/// empty path its own encoding, which names no stored frame.
#[cfg(feature = "native-proof")]
fn executing_filter(application: &[u8; 32], shard: &[bool]) -> Vec<u8> {
    if shard.is_empty() {
        return application.to_vec();
    }
    quil_forest::encode_shard_bit_path(application, shard)
}

/// The deliveries `build` makes of `pending`, in order, at most `cap`. A block
/// whose next item `build` cannot make yet (`None`) is left there, since its
/// later items would be out of sequence; the other blocks' items still are.
#[cfg(feature = "native-proof")]
fn take_deliverable(
    pending: Vec<crate::token_intrinsic::delivery::PendingDelivery>,
    cap: usize,
    mut build: impl FnMut(&crate::token_intrinsic::delivery::PendingDelivery) -> Result<Option<Vec<u8>>>,
) -> Result<Vec<Vec<u8>>> {
    let mut deliveries = Vec::new();
    let mut stalled = std::collections::BTreeSet::new();
    for item in pending {
        if deliveries.len() >= cap {
            break;
        }
        if stalled.contains(&(item.escrow, item.block)) {
            continue;
        }
        match build(&item)? {
            Some(bytes) => deliveries.push(bytes),
            None => {
                stalled.insert((item.escrow, item.block));
            }
        }
    }
    Ok(deliveries)
}

/// One output or escrow committed to a shard that it has not taken yet
/// ([`ExecutionEngineManager::pending_delivery_census`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryItem {
    /// `(executing filter, frame number)`: the certified frame holding the
    /// operation's bytes.
    pub source: (Vec<u8>, u64),
    /// The operation's id.
    pub tx_id: [u8; 32],
    pub block: u64,
    pub seq: u64,
    pub escrow: bool,
}

/// What a read of the outputs and escrows committed to a shard that it has
/// not taken yet found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeliveryCensus {
    /// The listed items: each block's in delivery order, the blocks in turn.
    pub items: Vec<DeliveryItem>,
    /// Owned blocks read.
    pub blocks: usize,
    /// Committed outputs and escrows not taken yet, over every owned block.
    pub pending: u64,
    /// Blocks with something pending, coins and escrows counted apart.
    pub blocks_pending: usize,
    /// Whether the per-frame cap left pending items unlisted.
    pub capped: bool,
    /// `(block, seq)` committed whose delivery record this GLOBAL view
    /// lacks: its block lists nothing from there on.
    pub missing_records: Vec<(u64, u64)>,
}

impl DeliveryCensus {
    /// The listed items' source frames, in delivery order, without repeats.
    pub fn sources(&self) -> Vec<(Vec<u8>, u64)> {
        let mut sources: Vec<(Vec<u8>, u64)> = Vec::new();
        for item in &self.items {
            if !sources.contains(&item.source) {
                sources.push(item.source.clone());
            }
        }
        sources
    }
}

/// What a read of a shard's pending deliveries found
/// ([`ExecutionEngineManager::pending_delivery_sources`]): their source
/// frames, without repeats, and the scale of the read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeliverySourceScan {
    /// `(executing filter, frame number)` of each source frame.
    pub sources: Vec<(Vec<u8>, u64)>,
    /// Pending deliveries read.
    pub pending: usize,
    /// Owned blocks read.
    pub blocks: usize,
}

/// What a proof pre-verification pass ([`ExecutionEngineManager::preverify_bundles`])
/// found: confidential operations, and of them how many had a cached verdict,
/// were verified (and cached), found no worker slot, or failed in the worker.
/// Operations without a worker proof count in `operations` only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreverifyCounts {
    pub operations: usize,
    pub cached: usize,
    pub verified: usize,
    /// Of `verified`, those another caller in this process was verifying
    /// already (a background pre-verification, say): this pass waited for
    /// that verification instead of running its own.
    pub joined: usize,
    pub busy: usize,
    pub unavailable: usize,
}

/// Why an arriving submission's confidential proofs are not verified on
/// arrival ([`ExecutionEngineManager::arrival_operations`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArrivalRefusal {
    /// The bundle or one of its confidential operations does not decode or
    /// fails dispatch's checks before native work.
    Malformed,
    /// The global commit already decided one of its operations.
    Decided,
    /// One of its operations can only be rejected, whatever GLOBAL frame
    /// decides it: it spends a marker the global commit already holds as
    /// consumed (a coin shielded, a key image spent), claims an escrow
    /// already claimed or under another binding, or shields a coin its key
    /// does not own or did not sign for.
    Rejected,
    /// One of its operations names what this node's GLOBAL view does not
    /// hold yet (a root, an escrow), or a legacy source or mint policy its
    /// store does not hold: it is held unverified until the view does.
    Pending,
}

/// What a shield its owner key signed claims on its shard, per legacy source
/// ([`ExecutionEngineManager::shield_claims`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShieldClaim {
    /// The coin under that key: the application, the source and the key.
    pub coin: [u8; 32],
    /// The statement the key signed. The signature does not cover the
    /// proof, so copies of a shield with other proof bytes make the same
    /// statement.
    pub statement: [u8; 32],
}

/// Which bundles failed their proof verification on this node
/// ([`ExecutionEngineManager::proof_failures`]).
#[derive(Clone)]
pub struct ProofFailures {
    #[cfg(feature = "native-proof")]
    policy: crate::token_intrinsic::dispatch::TokenPolicy,
    #[cfg(feature = "native-proof")]
    application: Vec<u8>,
}

impl ProofFailures {
    /// Whether a confidential operation of canonical bundle `bundle_bytes`
    /// failed its proof verification on this node (its verdict is cached as
    /// rejected), with the statements of the shields among them whose own
    /// proof failed. A verdict is a pure function of the operation and the
    /// network policy, and a bundle executes whole or not at all, so no
    /// frame executes the bundle on any node of that policy. A cache lookup
    /// per operation, no proof work. `None` when none failed.
    pub fn of(&self, bundle_bytes: &[u8]) -> Option<Vec<[u8; 32]>> {
        #[cfg(feature = "native-proof")]
        {
            let bundle =
                crate::message_envelope::CanonicalMessageBundle::from_canonical_bytes(bundle_bytes)
                    .ok()?;
            let mut failed = None::<Vec<[u8; 32]>>;
            for request in bundle.requests.iter().flatten() {
                let tp = request.inner_type_prefix;
                if crate::token_intrinsic::dispatch::is_confidential_type(tp)
                    && self
                        .policy
                        .verdict_rejected(&self.application, &request.inner_bytes, tp)
                {
                    let statements = failed.get_or_insert_with(Vec::new);
                    for claim in ExecutionEngineManager::request_claims(request) {
                        if !statements.contains(&claim.statement) {
                            statements.push(claim.statement);
                        }
                    }
                }
            }
            failed
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = bundle_bytes;
            None
        }
    }
}

/// What the global commit can make of a canonical bundle, read ahead of it
/// from this node's GLOBAL view and shard store
/// ([`ExecutionEngineManager::commit_outlook`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitOutlook {
    /// Nothing this node holds refuses it.
    Open,
    /// Decided, or an operation can only be rejected (see
    /// [`ArrivalRefusal::Rejected`]): no shard needs to verify or propose it.
    Settled,
    /// An operation names what this node does not hold yet (see
    /// [`ArrivalRefusal::Pending`]): verifying or proposing it waits until
    /// this node holds it; a later GLOBAL frame may settle it either way.
    Pending,
}

impl PreverifyCounts {
    pub fn add(&mut self, other: PreverifyCounts) {
        self.operations += other.operations;
        self.cached += other.cached;
        self.verified += other.verified;
        self.joined += other.joined;
        self.busy += other.busy;
        self.unavailable += other.unavailable;
    }
}

/// One confidential operation as its verification estimate sees it: its
/// bytes, and the least time its verification takes by its structure (a
/// shield's sources), which no measurement lowers.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct OperationEstimate {
    pub bytes: usize,
    pub floor_secs: f64,
}

/// How a pre-verification pass runs: at most `parallelism` operations at once
/// (default: the worker's slots), each finished one counted into `done`, none
/// started while `pause` returns true, as `background` work (no finalized
/// frame waits on it) leaving the first node-wide worker slot free, and
/// ahead of `executing` (default: a frame not known yet).
#[derive(Default)]
pub struct PreverifyPacing<'a> {
    pub parallelism: Option<usize>,
    pub done: Option<&'a std::sync::atomic::AtomicUsize>,
    pub pause: Option<&'a (dyn Fn() -> bool + Sync)>,
    pub background: bool,
    pub executing: ExecutingFrame,
}

/// The frame that executes an operation judged ahead of it, as far as the
/// judging caller knows it. A caller holding the frame's header passes its
/// anchor: a frame anchored before a gate executes what the gate refuses
/// there, however far past the gate this node saw GLOBAL since.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecutingFrame {
    /// One not known yet: a frame a later proposal carries.
    #[default]
    Later,
    /// An app-shard frame anchored at this GLOBAL frame (`None`: without an
    /// anchor).
    App(Option<u64>),
    /// GLOBAL frame N in the global venue, anchored at N - 1.
    Global(u64),
}

/// How far behind the latest GLOBAL frame this process saw a frame not known
/// yet may be anchored: an app-shard frame anchors
/// `GLOBAL_ANCHOR_SAFETY_MARGIN` behind its proposer's latest GLOBAL frame,
/// and its proposer may be as far again behind this node (the slack a mint
/// claim's citation keeps). A later GLOBAL frame is anchored past every
/// frame seen.
#[cfg(feature = "native-proof")]
const LATER_ANCHOR_LAG: u64 = crate::token_intrinsic::constants::MINT_CLAIM_CITATION_LAG;

#[cfg(feature = "native-proof")]
impl ExecutingFrame {
    /// The lowest GLOBAL anchor a frame executing the operation can have,
    /// `head` being the latest GLOBAL frame this process saw: its own where
    /// it is known (the global venue's N - 1), and for a frame not known yet
    /// `LATER_ANCHOR_LAG` behind `head` (none before `head` reaches it). A
    /// gate that opens once and is active there is active at every frame
    /// that can still carry the operation.
    fn anchor_floor(self, head: u64) -> Option<u64> {
        match self {
            Self::Later => head.checked_sub(LATER_ANCHOR_LAG),
            Self::App(anchor) => anchor,
            Self::Global(frame) => frame.checked_sub(1),
        }
    }

    /// [`Self::anchor_floor`] at the latest GLOBAL frame this process saw.
    fn anchor_floor_now(self) -> Option<u64> {
        self.anchor_floor(quil_types::consensus::frame_time_head())
    }

    /// The GLOBAL frame whose commit the global venue makes inline.
    fn commit_frame(self) -> Option<u64> {
        match self {
            Self::Global(frame) => Some(frame),
            Self::Later | Self::App(_) => None,
        }
    }
}

impl ExecutionEngineManager {
    /// Reconstruct all engines against the supplied state, preserving configured
    /// modes, cryptographic providers, worker admission and pricing policy.
    /// Message changesets and resolver caches are new, and no source engine is
    /// reused. The caller must hold its whole-frame capture barrier while
    /// constructing this context and calling this method.
    pub fn fork_with_context(&self, context: ExecutionForkContext) -> Result<Self> {
        if Arc::ptr_eq(&self.crdt, &context.crdt) {
            return Err(QuilError::InvalidArgument(
                "execution fork requires a separate CRDT".into(),
            ));
        }
        let source = self.engines.write().map_err(|_| {
            QuilError::ExecutionUnavailable("execution manager lock poisoned".into())
        })?;
        self.fork_with_locked_engines(context, &source, None)
    }

    fn fork_with_locked_engines(
        &self,
        context: ExecutionForkContext,
        source: &HashMap<String, Box<dyn ShardExecutionEngine>>,
        max_summary_rebuilds: Option<usize>,
    ) -> Result<Self> {
        let summary_rebuilds = {
            let source = self.summary_rebuilds.read().map_err(|_| {
                QuilError::ExecutionUnavailable("summary rebuild lock poisoned".into())
            })?;
            if max_summary_rebuilds.is_some_and(|limit| source.len() > limit) {
                return Err(QuilError::ExecutionUnavailable(
                    "execution branch summary metadata limit".into(),
                ));
            }
            source.iter().copied().collect()
        };
        for name in ["token", "compute", "hypergraph"] {
            if !source.contains_key(name) {
                return Err(QuilError::ExecutionUnavailable(format!(
                    "execution fork requires {name} engine"
                )));
            }
        }
        let shards_store = if self.shards_store.is_some() {
            Some(context.shards_store.clone().ok_or_else(|| {
                QuilError::ExecutionUnavailable(
                    "execution fork requires shard metadata store".into(),
                )
            })?)
        } else {
            None
        };
        let mut engines: HashMap<String, Box<dyn ShardExecutionEngine>> = HashMap::new();
        for (name, engine) in source.iter() {
            let any = engine.as_any().ok_or_else(|| {
                QuilError::ExecutionUnavailable(format!(
                    "execution fork cannot reconstruct engine {name}"
                ))
            })?;
            let fork: Box<dyn ShardExecutionEngine> = match name.as_str() {
                "global" => Box::new(
                    any.downcast_ref::<GlobalExecutionEngine>()
                        .ok_or_else(|| {
                            QuilError::ExecutionUnavailable("unexpected global engine type".into())
                        })?
                        .fork_with_context(&context)?,
                ),
                "token" => Box::new(
                    any.downcast_ref::<TokenExecutionEngine>()
                        .ok_or_else(|| {
                            QuilError::ExecutionUnavailable("unexpected token engine type".into())
                        })?
                        .fork_with_context(&context)?,
                ),
                "compute" => Box::new(
                    any.downcast_ref::<ComputeExecutionEngine>()
                        .ok_or_else(|| {
                            QuilError::ExecutionUnavailable("unexpected compute engine type".into())
                        })?
                        .fork_with_context(&context)?,
                ),
                "hypergraph" => Box::new(
                    any.downcast_ref::<HypergraphExecutionEngine>()
                        .ok_or_else(|| {
                            QuilError::ExecutionUnavailable(
                                "unexpected hypergraph engine type".into(),
                            )
                        })?
                        .fork_with_context(&context)?,
                ),
                _ => {
                    return Err(QuilError::ExecutionUnavailable(format!(
                        "unsupported execution fork engine {name}"
                    )))
                }
            };
            engines.insert(name.clone(), fork);
        }
        Ok(Self {
            engines: RwLock::new(engines),
            crdt: context.crdt,
            shards_store,
            global_quil_fee: RwLock::new(*self.global_quil_fee.read().map_err(|_| {
                QuilError::ExecutionUnavailable("fee snapshot lock poisoned".into())
            })?),
            global_venue_fee: RwLock::new(*self.global_venue_fee.read().map_err(|_| {
                QuilError::ExecutionUnavailable("fee snapshot lock poisoned".into())
            })?),
            pricing_network: self.pricing_network,
            summary_rebuilds: RwLock::new(summary_rebuilds),
        })
    }

    /// Configure the token suite before sharing this manager.
    /// Global and application managers must receive clones of the same worker
    /// client to share its admission slot. No worker is created per shard here.
    /// This consumes the manager so configuration cannot race frame execution.
    #[cfg(feature = "native-proof")]
    pub fn with_token_worker(
        mut self,
        policy: crate::token_intrinsic::dispatch::TokenPolicy,
        worker: quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier,
    ) -> Result<Self> {
        let engines = self.engines.get_mut().map_err(|_| {
            QuilError::ExecutionUnavailable("execution manager lock poisoned".into())
        })?;
        let token = engines
            .get_mut("token")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<TokenExecutionEngine>())
            .ok_or_else(|| {
                QuilError::InvalidArgument("manager requires a concrete token engine".into())
            })?;
        token.configure_token_worker(policy, worker)?;
        Ok(self)
    }

    /// Execute app-shard frames: the token engine runs in the application
    /// venue even when the global engine is also installed. A worker's frame
    /// numbers are app-shard numbers, so the global venue's "finalized global
    /// frame = execution frame − 1" bound would judge claims against the wrong
    /// frame; the application venue uses the frame's certified global anchor.
    pub fn with_application_venue(mut self) -> Result<Self> {
        let engines = self.engines.get_mut().map_err(|_| {
            QuilError::ExecutionUnavailable("execution manager lock poisoned".into())
        })?;
        let token = engines
            .get_mut("token")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<TokenExecutionEngine>())
            .ok_or_else(|| {
                QuilError::InvalidArgument("manager requires a concrete token engine".into())
            })?;
        token.set_mode(crate::engines::ExecutionMode::Application);
        Ok(self)
    }

    /// Give the token engine the store that holds canonical global frames.
    /// Required for managers whose own clock store holds only an app-shard
    /// chain (thread workers): a claim citing a global frame the store lacks
    /// is an infrastructure failure that holds the shard frame for retry.
    pub fn with_global_clock_store(
        mut self,
        store: Arc<dyn quil_types::store::ClockStore>,
    ) -> Result<Self> {
        let engines = self.engines.get_mut().map_err(|_| {
            QuilError::ExecutionUnavailable("execution manager lock poisoned".into())
        })?;
        let token = engines
            .get_mut("token")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<TokenExecutionEngine>())
            .ok_or_else(|| {
                QuilError::InvalidArgument("manager requires a concrete token engine".into())
            })?;
        token.set_global_clock_store(store.clone());
        if let Some(compute) = engines
            .get_mut("compute")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<ComputeExecutionEngine>())
        {
            compute.set_global_clock_store(store.clone());
        }
        if let Some(hypergraph) = engines
            .get_mut("hypergraph")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<HypergraphExecutionEngine>())
        {
            hypergraph.set_global_clock_store(store);
        }
        Ok(self)
    }

    /// Set the network this node prices state growth for, which is also the
    /// network whose first citable global frame bounds the settlement claims
    /// the compute and hypergraph engines admit, and the token engine admits
    /// without a token policy. Every node of a network must use the same value
    /// (it is the network's own selector).
    pub fn with_pricing_network(mut self, network: u8) -> Self {
        self.pricing_network = network;
        let engines = self
            .engines
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(feature = "native-proof")]
        if let Some(token) = engines
            .get_mut("token")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<TokenExecutionEngine>())
        {
            token.set_network(network);
        }
        if let Some(compute) = engines
            .get_mut("compute")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<ComputeExecutionEngine>())
        {
            compute.set_network(network);
        }
        if let Some(hypergraph) = engines
            .get_mut("hypergraph")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<HypergraphExecutionEngine>())
        {
            hypergraph.set_network(network);
        }
        self
    }

    /// The network selector for fee pricing.
    pub fn pricing_network(&self) -> u8 {
        self.pricing_network
    }

    /// Pre-verify confidential token operations of the given `(address,
    /// canonical bundle bytes)` pairs concurrently, filling the verdict cache.
    /// Bundles routed to other engines are ignored. Never fails.
    pub fn preverify_bundles(&self, bundles: &[(Vec<u8>, Vec<u8>)]) -> PreverifyCounts {
        self.preverify_bundles_paced(bundles, &PreverifyPacing::default())
    }

    /// [`Self::preverify_bundles`] paced by `pacing`. The engines are read
    /// only to take the token policy and worker client: a verification runs
    /// for minutes, and a held read guard would keep every engine writer,
    /// and the readers queued behind it, waiting that long. Operations
    /// execution against this node's store refuses before their proof (a
    /// shield of a coin its key does not own, or did not sign; a source the
    /// store does not hold; an unauthorized custom mint) are not verified:
    /// no frame carrying them verifies them either, here or on an archive.
    pub fn preverify_bundles_paced(
        &self,
        bundles: &[(Vec<u8>, Vec<u8>)],
        pacing: &PreverifyPacing<'_>,
    ) -> PreverifyCounts {
        self.preverify_routed(bundles, pacing)
    }

    /// [`Self::preverify_bundles`] ahead of the global venue's execution of
    /// GLOBAL frame `frame`: what that frame's commit refuses from GLOBAL
    /// state alone (a root GLOBAL does not hold, a consumed marker, a
    /// claimed escrow, ...) is not verified either, as the venue refuses it
    /// before the proof. One an earlier operation of the frame lifts (it
    /// publishes the root) is verified when it executes.
    pub fn preverify_global_bundles(
        &self,
        frame: u64,
        bundles: &[(Vec<u8>, Vec<u8>)],
    ) -> PreverifyCounts {
        self.preverify_routed(
            bundles,
            &PreverifyPacing {
                executing: ExecutingFrame::Global(frame),
                ..Default::default()
            },
        )
    }

    /// [`Self::preverify_bundles`] ahead of executing an app-shard frame
    /// anchored at GLOBAL frame `anchor` (`None`: without an anchor): what
    /// execution refuses before the proof from that anchor on (an owner
    /// that is not a canonical identity) is not verified, and what it
    /// admits there is, whatever GLOBAL frame this node saw since.
    pub fn preverify_app_frame_bundles(
        &self,
        anchor: Option<u64>,
        bundles: &[(Vec<u8>, Vec<u8>)],
    ) -> PreverifyCounts {
        self.preverify_routed(
            bundles,
            &PreverifyPacing {
                executing: ExecutingFrame::App(anchor),
                ..Default::default()
            },
        )
    }

    fn preverify_routed(
        &self,
        bundles: &[(Vec<u8>, Vec<u8>)],
        pacing: &PreverifyPacing<'_>,
    ) -> PreverifyCounts {
        #[cfg(feature = "native-proof")]
        {
            let routed: Vec<(Vec<u8>, Vec<u8>)> = bundles
                .iter()
                .filter(|(address, _)| {
                    self.select_engine(address)
                        .map(|name| name == "token")
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            if routed.is_empty() {
                return PreverifyCounts::default();
            }
            let verifier = match self.engines.read() {
                Ok(engines) => engines
                    .get("token")
                    .and_then(|e| e.as_any())
                    .and_then(|e| e.downcast_ref::<TokenExecutionEngine>())
                    .and_then(TokenExecutionEngine::token_verifier),
                Err(_) => None,
            };
            match verifier {
                Some((policy, worker)) => {
                    let network = policy.network;
                    let frame = pacing.executing;
                    let refused = |address: &[u8], bytes: &[u8], tp: u32| {
                        self.proof_refused(&network, address, bytes, tp, frame)
                    };
                    TokenExecutionEngine::preverify_with(policy, &worker, &routed, pacing, &refused)
                }
                None => PreverifyCounts::default(),
            }
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (bundles, pacing);
            PreverifyCounts::default()
        }
    }

    /// The confidential token operations in `bundles` whose verdicts are not
    /// cached yet, as their verification is estimated: what materializing
    /// them in a frame not known yet would still verify (not those
    /// execution refuses before their proof, which
    /// [`Self::preverify_bundles_paced`] leaves unverified). Empty when
    /// every proof is verified, and without a worker.
    pub fn unverified_confidential_operations(
        &self,
        bundles: &[(Vec<u8>, Vec<u8>)],
    ) -> Vec<OperationEstimate> {
        self.unverified_confidential_operations_for(ExecutingFrame::Later, bundles)
    }

    /// [`Self::unverified_confidential_operations`] of `bundles` executed by
    /// `frame`: a frame anchored before a gate still verifies what the gate
    /// refuses.
    pub fn unverified_confidential_operations_for(
        &self,
        frame: ExecutingFrame,
        bundles: &[(Vec<u8>, Vec<u8>)],
    ) -> Vec<OperationEstimate> {
        #[cfg(feature = "native-proof")]
        {
            let routed: Vec<(Vec<u8>, Vec<u8>)> = bundles
                .iter()
                .filter(|(address, _)| {
                    self.select_engine(address)
                        .map(|name| name == "token")
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            if routed.is_empty() {
                return Vec::new();
            }
            let policy = match self.engines.read() {
                Ok(engines) => engines
                    .get("token")
                    .and_then(|e| e.as_any())
                    .and_then(|e| e.downcast_ref::<TokenExecutionEngine>())
                    .and_then(TokenExecutionEngine::token_verifier)
                    .map(|(policy, _)| policy),
                Err(_) => None,
            };
            match policy {
                Some(policy) => {
                    let refused = |address: &[u8], bytes: &[u8], tp: u32| {
                        self.proof_refused(&policy.network, address, bytes, tp, frame)
                    };
                    TokenExecutionEngine::unverified_operation_estimates(&policy, &routed, &refused)
                }
                None => Vec::new(),
            }
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (frame, bundles);
            Vec::new()
        }
    }

    /// The per-frame proof-verification budget in worker-seconds; `None`
    /// (unbounded) without a worker.
    pub fn token_verification_budget(&self) -> Option<f64> {
        #[cfg(feature = "native-proof")]
        {
            let engines = self.engines.read().ok()?;
            return engines
                .get("token")
                .and_then(|e| e.as_any())
                .and_then(|e| e.downcast_ref::<TokenExecutionEngine>())
                .and_then(|token| token.verification_budget());
        }
        #[cfg(not(feature = "native-proof"))]
        None
    }

    /// Whether verifying one confidential operation of `operation_bytes`
    /// bytes is known to take at most `budget_secs` on this node: its size
    /// class was measured and fits. Always without the native prover.
    pub fn verification_known_to_fit(operation_bytes: usize, budget_secs: f64) -> bool {
        #[cfg(feature = "native-proof")]
        {
            return crate::token_intrinsic::dispatch::verification_known_to_fit(
                operation_bytes,
                budget_secs,
            );
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (operation_bytes, budget_secs);
            true
        }
    }

    /// Whether verifying confidential operation `operation` is known to take
    /// at most `budget_secs` on this node: it is below the size verified in
    /// the background whatever was measured, its structure's floor fits, and
    /// its size class was measured from accepted verdicts and fits. Always
    /// without the native prover.
    pub fn operation_known_to_fit(operation: &OperationEstimate, budget_secs: f64) -> bool {
        #[cfg(feature = "native-proof")]
        {
            return crate::token_intrinsic::dispatch::operation_known_to_fit(
                operation.bytes,
                operation.floor_secs,
                budget_secs,
            );
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (operation, budget_secs);
            true
        }
    }

    /// Estimated wall time of verifying confidential operation `operation`
    /// on this node: its size class's measured mean, at least its
    /// structure's floor.
    pub fn estimated_operation_secs(operation: &OperationEstimate) -> f64 {
        #[cfg(feature = "native-proof")]
        {
            return crate::token_intrinsic::dispatch::estimated_operation_secs(
                operation.bytes,
                operation.floor_secs,
            );
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = operation;
            0.0
        }
    }

    /// Estimated wall time of verifying one confidential operation of
    /// `operation_bytes` bytes on this node (measured per size class).
    pub fn estimated_verify_secs(operation_bytes: usize) -> f64 {
        #[cfg(feature = "native-proof")]
        {
            return crate::token_intrinsic::dispatch::estimated_verify_secs(operation_bytes);
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = operation_bytes;
            0.0
        }
    }

    /// Number of confidential token operations in a canonical bundle
    /// (always zero without the native proof feature).
    pub fn confidential_operation_count(address: &[u8], bundle_bytes: &[u8]) -> usize {
        #[cfg(feature = "native-proof")]
        {
            return TokenExecutionEngine::confidential_operations(&[(
                address.to_vec(),
                bundle_bytes.to_vec(),
            )])
            .len();
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (address, bundle_bytes);
            0
        }
    }

    /// Byte sizes of the confidential token operations in `(address,
    /// canonical bundle bytes)` pairs, each as a pre-verification pass would
    /// verify it (none without the native proof feature).
    pub fn confidential_operation_sizes(bundles: &[(Vec<u8>, Vec<u8>)]) -> Vec<usize> {
        #[cfg(feature = "native-proof")]
        {
            return TokenExecutionEngine::confidential_operations(bundles)
                .into_iter()
                .map(|(_, bytes, _)| bytes.len())
                .collect();
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = bundles;
            Vec::new()
        }
    }

    /// Proof-verification seconds a frame may spend per verifier slot (the
    /// per-frame verification budget; 0 without the native prover).
    pub fn frame_verification_budget_secs() -> f64 {
        #[cfg(feature = "native-proof")]
        {
            return crate::token_intrinsic::dispatch::verification_budget_secs();
        }
        #[cfg(not(feature = "native-proof"))]
        0.0
    }

    /// Verifier slots of this node's proof worker: confidential operations it
    /// verifies at once; 1 without a worker.
    pub fn proof_verifier_slots(&self) -> usize {
        #[cfg(feature = "native-proof")]
        {
            let worker = self.engines.read().ok().and_then(|engines| {
                engines
                    .get("token")
                    .and_then(|e| e.as_any())
                    .and_then(|e| e.downcast_ref::<TokenExecutionEngine>())
                    .and_then(TokenExecutionEngine::token_verifier)
                    .map(|(_, worker)| worker.concurrency())
            });
            if let Some(slots) = worker {
                return slots.max(1);
            }
        }
        1
    }

    /// Whether a canonical bundle holds an operation dispatch refuses before
    /// any native work ([`TokenPolicy::preflight`]: encoding, context,
    /// dimensions): a pure check of its bytes and this network's limits, run
    /// first when a frame executes it, so the bundle can never take effect
    /// and waiting cannot change that. False without a token policy, and for
    /// operations that do not commit through the global frame, which other
    /// paths execute.
    pub fn refused_before_native_work(&self, address: &[u8], bundle_bytes: &[u8]) -> bool {
        #[cfg(feature = "native-proof")]
        {
            use crate::token_intrinsic::{dispatch::is_confidential_type, spend_entries};
            let Some(Ok(application)) = address.get(..32).map(<[u8; 32]>::try_from) else {
                return false;
            };
            if !self
                .select_engine(&application)
                .is_ok_and(|name| name == "token")
            {
                return false;
            }
            let Ok(bundle) =
                crate::message_envelope::CanonicalMessageBundle::from_canonical_bytes(bundle_bytes)
            else {
                return false;
            };
            let policy = match self.engines.read() {
                Ok(engines) => engines
                    .get("token")
                    .and_then(|e| e.as_any())
                    .and_then(|e| e.downcast_ref::<TokenExecutionEngine>())
                    .and_then(TokenExecutionEngine::token_verifier)
                    .map(|(policy, _)| policy),
                Err(_) => None,
            };
            let Some(policy) = policy else {
                return false;
            };
            bundle.requests.iter().flatten().any(|request| {
                let tp = request.inner_type_prefix;
                is_confidential_type(tp)
                    && spend_entries::commits_globally(&application, tp)
                    && policy
                        .preflight(&application, &request.inner_bytes, tp)
                        .is_err()
            })
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (address, bundle_bytes);
            false
        }
    }

    /// The legacy coin the first shield of a canonical bundle consumes. Only
    /// the shard holding that coin can verify the shield (its source check
    /// reads the shard's own store), so the bundle is routed there.
    pub fn shield_source(bundle_bytes: &[u8]) -> Option<[u8; 32]> {
        #[cfg(feature = "native-proof")]
        {
            let bundle =
                crate::message_envelope::CanonicalMessageBundle::from_canonical_bytes(bundle_bytes)
                    .ok()?;
            return bundle
                .requests
                .into_iter()
                .flatten()
                .filter(|request| {
                    request.inner_type_prefix == crate::token_engine::TYPE_LATTICE_SHIELD
                })
                .find_map(|request| {
                    quil_lattice_ct::confidential::shield::source_address(&request.inner_bytes)
                });
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = bundle_bytes;
            None
        }
    }

    /// What each shield of a canonical bundle that its owner key signed
    /// claims on its shard: one coin per legacy source it consumes, of its
    /// application, the source and that key, with the digest of the
    /// statement the key signed. Decoding and one signature check per
    /// shield, no proof and no state. A shield whose signature does not
    /// verify claims nothing, so no key can claim a source for another.
    /// Empty without the native prover.
    pub fn shield_claims(bundle_bytes: &[u8]) -> Vec<ShieldClaim> {
        #[cfg(feature = "native-proof")]
        {
            let Ok(bundle) =
                crate::message_envelope::CanonicalMessageBundle::from_canonical_bytes(bundle_bytes)
            else {
                return Vec::new();
            };
            bundle
                .requests
                .iter()
                .flatten()
                .flat_map(Self::request_claims)
                .collect()
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = bundle_bytes;
            Vec::new()
        }
    }

    /// [`Self::shield_claims`] of one request.
    #[cfg(feature = "native-proof")]
    fn request_claims(
        request: &crate::message_envelope::CanonicalMessageRequest,
    ) -> Vec<ShieldClaim> {
        use sha3::Digest;
        if request.inner_type_prefix != crate::token_engine::TYPE_LATTICE_SHIELD {
            return Vec::new();
        }
        let bytes = &request.inner_bytes;
        let context = |range: std::ops::Range<usize>| {
            bytes
                .get(range)
                .and_then(|field| <[u8; 32]>::try_from(field).ok())
        };
        let (Some(network), Some(application)) = (context(12..44), context(44..76)) else {
            return Vec::new();
        };
        let Ok(shield) =
            quil_lattice_ct::confidential::shield::AnyShield::decode(bytes, &network, &application)
        else {
            return Vec::new();
        };
        if crate::token_intrinsic::shield::check_authorization(&shield).is_err() {
            return Vec::new();
        }
        let Ok(signed) = shield.context_bytes() else {
            return Vec::new();
        };
        let mut statement = sha3::Sha3_256::new();
        statement.update(b"quil/shield-statement/v1\0");
        statement.update(&signed);
        let statement: [u8; 32] = statement.finalize().into();
        shield
            .sources()
            .iter()
            .map(|source| {
                let mut hash = sha3::Sha3_256::new();
                hash.update(b"quil/shield-claim/v1\0");
                hash.update(application);
                hash.update(source.address);
                hash.update(shield.owner_public_key());
                ShieldClaim {
                    coin: hash.finalize().into(),
                    statement,
                }
            })
            .collect()
    }

    /// The token policy, if a token worker is configured.
    #[cfg(feature = "native-proof")]
    fn token_policy(&self) -> Option<crate::token_intrinsic::dispatch::TokenPolicy> {
        match self.engines.read() {
            Ok(engines) => engines
                .get("token")
                .and_then(|e| e.as_any())
                .and_then(|e| e.downcast_ref::<TokenExecutionEngine>())
                .and_then(TokenExecutionEngine::token_verifier)
                .map(|(policy, _)| policy),
            Err(_) => None,
        }
    }

    /// What tells which bundles of `address` (an application, or a shard
    /// filter under it) failed their proof verification on this node
    /// ([`ProofFailures::of`]), with the token policy read now: it reads
    /// only the verdict cache, never the engines' lock, so a caller may hold
    /// its own locks while it judges. `None` without a token policy and
    /// without the native prover.
    pub fn proof_failures(&self, address: &[u8]) -> Option<ProofFailures> {
        #[cfg(feature = "native-proof")]
        {
            Some(ProofFailures {
                policy: self.token_policy()?,
                application: address[..address.len().min(32)].to_vec(),
            })
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = address;
            None
        }
    }

    /// What stops a confidential operation of `application` from committing,
    /// read before any proof work: the global commit's state checks
    /// ([`global_commit::precheck`]: consumed markers, a root or an escrow
    /// GLOBAL holds, an escrow's binding and claim) against `global`, GLOBAL
    /// state as this node holds it; and, with `shard` (this node's store and
    /// its token policy's network), what execution refuses before the proof
    /// (a shield's legacy sources and signature, a custom mint's authority)
    /// and a custom mint's policy-bound markers. A record that cannot be read
    /// refuses nothing. A lasting refusal (one no later GLOBAL frame lifts)
    /// comes first. Every lasting refusal here only grows as GLOBAL advances
    /// (a consumed marker, a claimed escrow, an escrow's binding, a legacy
    /// coin, a signature), so a view behind GLOBAL refuses less, never more;
    /// what it does not hold yet is pending, never refused.
    ///
    /// [`global_commit::precheck`]: crate::token_intrinsic::global_commit::precheck
    #[cfg(feature = "native-proof")]
    fn request_standing(
        global: &crate::hypergraph_state::HypergraphState,
        shard: Option<(&crate::hypergraph_state::HypergraphState, &[u8; 32])>,
        application: &[u8; 32],
        request: &crate::message_envelope::CanonicalMessageRequest,
    ) -> Option<crate::token_intrinsic::global_commit::Standing> {
        use crate::token_engine::TYPE_LATTICE_MINT;
        use crate::token_intrinsic::{
            custom_mint,
            global_commit::{self, Standing},
            spend_entries,
        };
        let (tp, bytes) = (request.inner_type_prefix, request.inner_bytes.as_slice());
        let mut needs = spend_entries::commit_needs(application, tp, bytes)?;
        let mut held = None;
        if let Some((shard, network)) = shard {
            let anchor = ExecutingFrame::Later.anchor_floor_now();
            match Self::execution_standing(shard, network, application, tp, bytes, anchor) {
                Some(lasting @ Standing::Lasting(_)) => return Some(lasting),
                pending => held = pending,
            }
            if tp == TYPE_LATTICE_MINT && application != &crate::domains::QUIL_TOKEN {
                if let Ok(markers) =
                    custom_mint::commit_consumptions(shard, bytes, network, application)
                {
                    needs.consumptions = markers;
                }
            }
        }
        match global_commit::precheck(global, application, &needs) {
            Ok(Some(lasting @ Standing::Lasting(_))) => Some(lasting),
            Ok(pending) => held.or(pending),
            Err(_) => held,
        }
    }

    /// What execution against `shard` (a store holding the operation's
    /// shard, of a node on `network`) refuses before verifying the proof of
    /// operation `bytes` of type `tp`: a shield's legacy sources and
    /// signature (lasting when a source is another key's coin or the key
    /// did not sign, pending when the store does not hold a source), a
    /// pending claim its branch's authority did not sign and a settlement
    /// whose terms execution refuses (lasting: both are read from the bytes
    /// alone, by execution's own checks), a custom mint the policy held here
    /// does not authorize (pending), and an owner that is not a canonical
    /// identity once that check is active at GLOBAL frame `anchor`, the
    /// lowest anchor of a frame that can still execute it
    /// ([`ExecutingFrame::anchor_floor`]; lasting). `None` for every other
    /// operation and when it cannot say. When a refund falls due, a batch
    /// shield's activation and a source outside the executing shard are
    /// judged by the executing frame only: no frame is known ahead of it.
    #[cfg(feature = "native-proof")]
    fn execution_standing(
        shard: &crate::hypergraph_state::HypergraphState,
        network: &[u8; 32],
        application: &[u8; 32],
        tp: u32,
        bytes: &[u8],
        anchor: Option<u64>,
    ) -> Option<crate::token_intrinsic::global_commit::Standing> {
        use crate::token_engine::{
            TYPE_LATTICE_MINT, TYPE_LATTICE_PENDING_CLAIM, TYPE_LATTICE_SETTLEMENT,
            TYPE_LATTICE_SHIELD,
        };
        use crate::token_intrinsic::{
            commit_verify, custom_mint,
            global_commit::{self, Standing},
            shield::{self, SourceStanding},
            spend_entries,
        };
        // Execution refuses an operation naming an owner that is not a
        // canonical identity before its proof once that check is active at
        // the executing frame's anchor (`dispatch_for_commit`,
        // `dispatch_global_mint`). The check reads the bytes alone and its
        // gate opens once, so active at `anchor` it is active at every frame
        // that can still carry the operation.
        if global_commit::canonical_owners_active(anchor)
            && spend_entries::names_noncanonical_owner(network, application, tp, bytes)
        {
            return Some(Standing::Lasting("an owner is not a canonical identity"));
        }
        if tp == TYPE_LATTICE_PENDING_CLAIM {
            let claim = quil_lattice_ct::confidential::pending_claim::PendingClaim::decode(
                bytes,
                network,
                application,
            )
            .ok()?;
            return commit_verify::claim_signature_refused(&claim, network, application)
                .then_some(Standing::Lasting("invalid selected authority signature"));
        }
        if tp == TYPE_LATTICE_SETTLEMENT {
            let tx = quil_lattice_ct::confidential::settlement::Settlement::decode(
                bytes,
                network,
                application,
            )
            .ok()?;
            return commit_verify::settlement_terms(&tx)
                .is_err()
                .then_some(Standing::Lasting("settlement terms refused"));
        }
        if tp == TYPE_LATTICE_SHIELD {
            let tx = quil_lattice_ct::confidential::shield::AnyShield::decode(
                bytes,
                network,
                application,
            )
            .ok()?;
            return match shield::source_standing(shard, application, &tx)? {
                SourceStanding::Unowned => {
                    Some(Standing::Lasting("shield source is not its key's coin"))
                }
                SourceStanding::Unsigned => Some(Standing::Lasting("invalid source authorization")),
                SourceStanding::Missing => Some(Standing::Pending("shield source not held here")),
                SourceStanding::Owned => None,
            };
        }
        if tp == TYPE_LATTICE_MINT
            && application != &crate::domains::QUIL_TOKEN
            && custom_mint::refused_before_proof(shard, network, application, bytes) == Some(true)
        {
            return Some(Standing::Pending(
                "custom mint not authorized by the policy held here",
            ));
        }
        None
    }

    /// Whether the proof of confidential operation `bytes` (type `tp`) of
    /// `address` needs no verification here: execution against this node's
    /// store refuses it before its proof ([`Self::execution_standing`]), so
    /// no frame that carries it verifies it, here or on any node holding
    /// that state, as `frame` executes it; and, when `frame` is GLOBAL frame
    /// N, in the global venue that commits it at N, the commit refuses it
    /// from GLOBAL state alone (`commit_apply::refused_before_proof`), as
    /// the venue does before the proof. A frame reading a store that gains
    /// what refused it (a source still syncing, a root an earlier operation
    /// of the frame publishes) verifies it when it executes, as before.
    #[cfg(feature = "native-proof")]
    fn proof_refused(
        &self,
        network: &[u8; 32],
        address: &[u8],
        bytes: &[u8],
        tp: u32,
        frame: ExecutingFrame,
    ) -> bool {
        let Some(Ok(application)) = address.get(..32).map(<[u8; 32]>::try_from) else {
            return false;
        };
        let store = crate::hypergraph_state::HypergraphState::new(self.crdt());
        let anchor = frame.anchor_floor_now();
        let standing = Self::execution_standing(&store, network, &application, tp, bytes, anchor);
        if standing.is_some() {
            return true;
        }
        frame.commit_frame().is_some_and(|frame| {
            crate::token_intrinsic::spend_entries::commits_globally(&application, tp)
                && crate::token_intrinsic::commit_apply::refused_before_proof(
                    &store,
                    frame,
                    network,
                    &application,
                    tp,
                    bytes,
                )
                .is_some()
        })
    }

    /// Whether the global commit has decided every request of `bundle`.
    #[cfg(feature = "native-proof")]
    fn all_decided(
        state: &crate::hypergraph_state::HypergraphState,
        application: &[u8; 32],
        bundle: &crate::message_envelope::CanonicalMessageBundle,
    ) -> bool {
        use crate::token_intrinsic::global_commit;
        bundle.requests.iter().all(|request| {
            request.as_ref().is_some_and(|request| {
                global_commit::is_decided(
                    state,
                    application,
                    &global_commit::tx_id(&request.inner_bytes),
                )
                .unwrap_or(false)
            })
        })
    }

    /// What the global commit can make of a canonical bundle, read before
    /// any proof work from `global` (GLOBAL state as this node holds it) and
    /// this node's store: settled when it decided every request or one can
    /// only be rejected; pending when one names what this node does not hold
    /// yet (`request_standing`). `address` is the application, or a shard
    /// filter under it (its first 32 bytes). Open when it cannot say, and
    /// without the native prover. Without a token policy only GLOBAL state is
    /// read.
    pub fn commit_outlook(
        &self,
        global: &Arc<quil_hypergraph::HypergraphCrdt>,
        address: &[u8],
        bundle_bytes: &[u8],
    ) -> CommitOutlook {
        #[cfg(feature = "native-proof")]
        {
            use crate::token_intrinsic::global_commit::Standing;
            let Some(Ok(application)) = address.get(..32).map(<[u8; 32]>::try_from) else {
                return CommitOutlook::Open;
            };
            let Ok(bundle) =
                crate::message_envelope::CanonicalMessageBundle::from_canonical_bytes(bundle_bytes)
            else {
                return CommitOutlook::Open;
            };
            if bundle.requests.is_empty() {
                return CommitOutlook::Open;
            }
            let state = crate::hypergraph_state::HypergraphState::new(global.clone());
            let store = crate::hypergraph_state::HypergraphState::new(self.crdt());
            let network = self.token_policy().map(|policy| policy.network);
            let shard = network.as_ref().map(|network| (&store, network));
            let mut pending = false;
            for request in bundle.requests.iter().flatten() {
                match Self::request_standing(&state, shard, &application, request) {
                    Some(Standing::Lasting(_)) => return CommitOutlook::Settled,
                    Some(Standing::Pending(_)) => pending = true,
                    None => {}
                }
            }
            if Self::all_decided(&state, &application, &bundle) {
                return CommitOutlook::Settled;
            }
            if pending {
                CommitOutlook::Pending
            } else {
                CommitOutlook::Open
            }
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (global, address, bundle_bytes);
            CommitOutlook::Open
        }
    }

    /// Whether no shard needs to execute a canonical bundle again: the global
    /// commit has decided every request, or GLOBAL state alone shows it can
    /// only reject one (a re-shield of a shielded coin, a re-spend of a spent
    /// key image, a claim of a claimed escrow). Only globally committed
    /// operations are ever decided, so a bundle holding anything else is
    /// not, unless one of its operations can only be rejected. `global`
    /// holds GLOBAL state; false when it cannot say. `address` is the
    /// application, or a shard filter under it (its first 32 bytes).
    /// [`Self::commit_outlook`] also reads this node's store.
    pub fn decided_globally(
        global: Arc<quil_hypergraph::HypergraphCrdt>,
        address: &[u8],
        bundle_bytes: &[u8],
    ) -> bool {
        #[cfg(feature = "native-proof")]
        {
            use crate::token_intrinsic::global_commit;
            let Some(Ok(application)) = address.get(..32).map(<[u8; 32]>::try_from) else {
                return false;
            };
            let Ok(bundle) =
                crate::message_envelope::CanonicalMessageBundle::from_canonical_bytes(bundle_bytes)
            else {
                return false;
            };
            if bundle.requests.is_empty() {
                return false;
            }
            let state = crate::hypergraph_state::HypergraphState::new(global);
            if bundle.requests.iter().flatten().any(|request| {
                matches!(
                    Self::request_standing(&state, None, &application, request),
                    Some(global_commit::Standing::Lasting(_))
                )
            }) {
                return true;
            }
            Self::all_decided(&state, &application, &bundle)
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (global, address, bundle_bytes);
            false
        }
    }

    /// Byte sizes of the confidential token operations of an arriving
    /// canonical bundle that verifying it would send to the proof worker,
    /// or why it needs no verification on arrival. Cheap: decoding and
    /// record reads, no proof. Operations whose verdict is cached, or that
    /// dispatch refuses before native work (encoding, context, dimensions,
    /// fee: they fail execution without a proof), are left out. Refused
    /// when the bundle does not decode, when the global commit already
    /// decided one of its operations (executing it again changes nothing,
    /// and the collector keeps it from proposals once a finalized frame
    /// carried it), when one can only be rejected, and while one names what
    /// this node does not hold yet ([`Self::commit_outlook`]); `global` holds
    /// GLOBAL state, and a record it cannot read refuses nothing. `address`
    /// is the application, or a shard filter under it. Empty without the
    /// native prover, and for bundles routed to other engines.
    pub fn arrival_operations(
        &self,
        global: &Arc<quil_hypergraph::HypergraphCrdt>,
        address: &[u8],
        bundle_bytes: &[u8],
    ) -> std::result::Result<Vec<usize>, ArrivalRefusal> {
        #[cfg(feature = "native-proof")]
        {
            use crate::token_intrinsic::{
                dispatch::is_confidential_type,
                global_commit::{self, Standing},
            };
            let Some(Ok(application)) = address.get(..32).map(<[u8; 32]>::try_from) else {
                return Ok(Vec::new());
            };
            if !self
                .select_engine(&application)
                .is_ok_and(|name| name == "token")
            {
                return Ok(Vec::new());
            }
            let bundle =
                crate::message_envelope::CanonicalMessageBundle::from_canonical_bytes(bundle_bytes)
                    .map_err(|_| ArrivalRefusal::Malformed)?;
            let policy = self.token_policy();
            let state = crate::hypergraph_state::HypergraphState::new(global.clone());
            let store = crate::hypergraph_state::HypergraphState::new(self.crdt());
            let shard = policy.as_ref().map(|policy| (&store, &policy.network));
            let mut sizes = Vec::new();
            let mut pending = false;
            for request in bundle.requests.iter().flatten() {
                if !is_confidential_type(request.inner_type_prefix) {
                    continue;
                }
                let tx_id = global_commit::tx_id(&request.inner_bytes);
                if global_commit::is_decided(&state, &application, &tx_id).unwrap_or(false) {
                    return Err(ArrivalRefusal::Decided);
                }
                match Self::request_standing(&state, shard, &application, request) {
                    Some(Standing::Lasting(_)) => return Err(ArrivalRefusal::Rejected),
                    Some(Standing::Pending(_)) => pending = true,
                    None => {}
                }
                if let Some(policy) = policy.as_ref() {
                    if policy
                        .preflight(
                            &application,
                            &request.inner_bytes,
                            request.inner_type_prefix,
                        )
                        .is_err()
                    {
                        return Err(ArrivalRefusal::Malformed);
                    }
                    if policy.verdict_known(
                        &application,
                        &request.inner_bytes,
                        request.inner_type_prefix,
                    ) {
                        continue;
                    }
                }
                sizes.push(request.inner_bytes.len());
            }
            if pending {
                return Err(ArrivalRefusal::Pending);
            }
            Ok(sizes)
        }
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (global, address, bundle_bytes);
            Ok(Vec::new())
        }
    }

    /// Build a manager with all engines initialized. Every engine is
    /// constructed with mandatory crypto + store providers — no silent
    /// crypto-less fallback. Production callers MUST supply real
    /// implementations; tests can wire noop stubs from
    /// `crate::testing::NoopExecutionCrypto`.
    ///
    /// `include_global = false` also starts every engine in the application
    /// venue, as [`Self::with_application_venue`] sets the token engine: the
    /// store is then taken to hold only the shard it executes, and a missing
    /// coin summary is rebuilt from that shard's blocks
    /// ([`TokenExecutionEngine::shard_store`]).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inclusion_prover: Arc<dyn InclusionProver>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler>,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
        hypergraph_config_resolver: Arc<dyn crate::hypergraph_intrinsic::HypergraphConfigResolver>,
        include_global: bool,
    ) -> Self {
        Self::new_with_shards(
            inclusion_prover,
            key_manager,
            crdt,
            circuit_compiler,
            clock_store,
            hypergraph_config_resolver,
            include_global,
            None,
            None,
        )
    }

    /// Like [`Self::new`], but wires the global intrinsic's shard stores so
    /// shard split/merge topology changes actually record (`PendingShardChange`)
    /// and apply at the E+2 boundary. The GLOBAL materialization path
    /// (master/archive, `include_global = true`) MUST use this — otherwise
    /// proposed splits validate + "succeed" but never take effect. App-shard-only
    /// managers (workers) can keep using [`Self::new`] (they never process the
    /// global-intrinsic split/merge ops).
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_shards(
        inclusion_prover: Arc<dyn InclusionProver>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler>,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
        hypergraph_config_resolver: Arc<dyn crate::hypergraph_intrinsic::HypergraphConfigResolver>,
        include_global: bool,
        shards_store: Option<Arc<dyn quil_types::store::ShardsStore>>,
        shards_db: Option<Arc<dyn quil_types::store::KvDb>>,
    ) -> Self {
        // Keep a handle for `refresh_shard_prefixes` before the store is moved into
        // the global engine below.
        let shards_store_for_manager = shards_store.clone();
        let mut engines: HashMap<String, Box<dyn ShardExecutionEngine>> = HashMap::new();

        if include_global {
            engines.insert(
                "global".into(),
                Box::new(GlobalExecutionEngine::new_with_intrinsic(
                    inclusion_prover.clone(),
                    key_manager.clone(),
                    crdt.clone(),
                    clock_store.clone(),
                    shards_store,
                    shards_db,
                )),
            );
        }

        let mode = if include_global {
            ExecutionMode::Global
        } else {
            ExecutionMode::Application
        };

        engines.insert(
            "token".into(),
            Box::new(TokenExecutionEngine::new_with_state(
                mode,
                inclusion_prover.clone(),
                crdt.clone(),
                key_manager.clone(),
                clock_store.clone(),
            )),
        );
        let mut compute = ComputeExecutionEngine::new_with_state(
            mode,
            crdt.clone(),
            key_manager.clone(),
            circuit_compiler,
        );
        compute.set_global_clock_store(clock_store.clone());
        engines.insert("compute".into(), Box::new(compute));
        engines.insert(
            "hypergraph".into(),
            Box::new({
                let mut hypergraph = HypergraphExecutionEngine::new_with_state(
                    mode,
                    crdt.clone(),
                    hypergraph_config_resolver,
                )
                .with_key_manager(key_manager);
                hypergraph.set_global_clock_store(clock_store.clone());
                hypergraph
            }),
        );

        Self {
            engines: RwLock::new(engines),
            crdt,
            shards_store: shards_store_for_manager,
            global_quil_fee: RwLock::new(None),
            global_venue_fee: RwLock::new(None),
            pricing_network: crate::pricing::MAINNET_NETWORK,
            summary_rebuilds: RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Re-attribute the CRDT's per-app shard prefixes + size buckets to the
    /// CURRENT grid in the shards store. MUST be called after a split/merge flips
    /// the grid (`apply_global_due_shard_changes`) — otherwise the CRDT keeps the
    /// PRE-split partition, so `sub_meta_for` (GetAppShards size / the reward
    /// basis) can't resolve the new deep-split sub-shards and reports size 0 for
    /// them (the parent bucket lingers on a now-merged shallow prefix). Mirrors the
    /// node's `refresh_crdt_shard_prefixes`: a changed shard set rebuilds its
    /// size buckets from committed state under the CRDT commit barrier. Failed
    /// rebuilds retain the old layout and remain eligible for retry. Unchanged
    /// sets need no rebuild. Returns the number of successfully changed apps.
    pub fn refresh_shard_prefixes(&self) -> usize {
        let Some(store) = self.shards_store.as_ref() else {
            return 0;
        };
        let rows = match store.range_app_shards() {
            Ok(r) => r,
            Err(_) => return 0,
        };
        let mut by_app: HashMap<[u8; 32], Vec<Vec<u32>>> = HashMap::new();
        for row in rows {
            if row.shard_key.len() >= 35 {
                let mut l2 = [0u8; 32];
                l2.copy_from_slice(&row.shard_key[3..35]);
                by_app.entry(l2).or_default().push(row.prefix);
            }
        }
        let mut changed = 0usize;
        for (app, prefixes) in by_app {
            match self.crdt.refresh_app_shard_prefixes(app, prefixes) {
                Ok(true) => changed += 1,
                Ok(false) => {}
                Err(e) => tracing::warn!(app = %hex::encode(app), error = %e,
                    "refresh_shard_prefixes: layout unchanged after rebuild failure; will retry"),
            }
        }
        changed
    }

    /// Checked refresh for tentative execution. A failure may follow earlier
    /// in-memory layout changes, so the owner must discard the whole branch.
    pub fn try_refresh_shard_prefixes(&self) -> Result<usize> {
        let Some(store) = &self.shards_store else {
            return Ok(0);
        };
        let mut by_app = std::collections::BTreeMap::<[u8; 32], Vec<Vec<u32>>>::new();
        for row in store.range_app_shards()? {
            if row.shard_key.len() != 35 {
                return Err(QuilError::ExecutionUnavailable(
                    "invalid captured shard metadata key".into(),
                ));
            }
            by_app
                .entry(row.shard_key[3..].try_into().unwrap())
                .or_default()
                .push(row.prefix);
        }
        let mut changed = 0;
        for (app, prefixes) in by_app {
            changed += usize::from(self.crdt.refresh_app_shard_prefixes(app, prefixes)?);
        }
        Ok(changed)
    }

    /// Publish only after global state/cursor commit. None invalidates quotes
    /// when QUIL no longer uses this venue. This cache is not persisted.
    pub fn publish_global_quil_fee_snapshot(
        &self,
        snapshot: Option<crate::pricing::GlobalQuilFeeSnapshot>,
    ) {
        *self
            .global_quil_fee
            .write()
            .unwrap_or_else(|e| e.into_inner()) = snapshot;
    }

    /// Publish the global venue's pricing inputs after the global state and
    /// cursor commit (every frame, independent of QUIL routing).
    pub fn publish_global_venue_fee_snapshot(
        &self,
        snapshot: crate::pricing::GlobalQuilFeeSnapshot,
    ) {
        *self
            .global_venue_fee
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(snapshot);
    }

    /// The global venue snapshot, only while it is the current materialized frame's.
    pub fn global_venue_fee_snapshot(
        &self,
        materialized_frame: u64,
    ) -> Result<Option<crate::pricing::GlobalQuilFeeSnapshot>> {
        self.global_venue_fee
            .read()
            .map(|snapshot| snapshot.filter(|s| s.frame_number == materialized_frame))
            .map_err(|_| QuilError::ExecutionUnavailable("fee snapshot lock poisoned".into()))
    }

    pub fn global_quil_fee_snapshot(
        &self,
        materialized_frame: u64,
    ) -> Result<Option<crate::pricing::GlobalQuilFeeSnapshot>> {
        self.global_quil_fee
            .read()
            .map(|snapshot| snapshot.filter(|s| s.frame_number == materialized_frame))
            .map_err(|_| QuilError::ExecutionUnavailable("fee snapshot lock poisoned".into()))
    }

    /// The hypergraph CRDT these engines commit to — used by the forest sync,
    /// which applies pulled state into this same CRDT (coordinated versions).
    pub fn crdt(&self) -> Arc<quil_hypergraph::HypergraphCrdt> {
        self.crdt.clone()
    }

    /// Reads the engines until the returned guard drops, as a gossip
    /// validation or an RPC cost query does.
    #[cfg(any(test, feature = "testing-stubs"))]
    pub fn hold_engines_for_test(&self) -> impl Sized + '_ {
        self.engines.read().unwrap()
    }

    /// Poisons the engine lock: a thread panics while it writes them.
    #[cfg(any(test, feature = "testing-stubs"))]
    pub fn poison_engines_for_test(&self) {
        std::thread::scope(|scope| {
            let panicked = scope
                .spawn(|| {
                    let _engines = self.engines.write().unwrap();
                    panic!("a test panics while it writes the execution engines");
                })
                .join();
            assert!(panicked.is_err());
        });
        assert!(self.engines.is_poisoned());
    }

    /// Shard metadata bound to this manager's execution state.
    pub fn shards_store(&self) -> Option<Arc<dyn quil_types::store::ShardsStore>> {
        self.shards_store.clone()
    }

    /// Persist the in-memory hypergraph phase trees for the given
    /// frame to the underlying store. Mirrors Go's
    /// `frame_materializer.go:316` `hg.Commit(frame)` after the
    /// per-bundle `state.Commit()` calls. Without this flush, the
    /// `RocksHypergraphStore::load_tree_blob` reads the previous
    /// frame's trees, so new vertices stay invisible to the prover
    /// registry refresh and to peer HyperSync.
    pub fn commit_frame(&self, frame_number: u64) -> Result<()> {
        // The CRDT commit is the tree-flush hot path (per-branch KZG multiexp
        // across four shard trees) — the suspected #1 cost center. Timed under
        // engine_type="crdt", op="commit".
        let start = std::time::Instant::now();
        let res = self.crdt.commit(frame_number);
        crate::metrics::observe_execution_duration("crdt", "commit", start.elapsed().as_secs_f64());
        res?;
        Ok(())
    }

    /// Like [`commit_frame`] but ALSO stages the durable GLOBAL
    /// materialization cursor (`= frame_number`) into the CRDT commit's own
    /// batch, so the cursor is persisted atomically with this frame's reward /
    /// prover / shard writes (one `db.write`).
    ///
    /// GLOBAL-ONLY: this must be called only by the global frame materializer.
    /// Application materialization uses its own full-filter cursor key and
    /// never writes this global cursor. Reward minting is additive with no per-frame
    /// idempotency, so the cursor MUST equal the CRDT frontier exactly — the
    /// atomic co-write here is what guarantees the crash-gap re-materialize
    /// only re-runs un-committed frames and never double-mints.
    pub fn commit_frame_with_global_cursor(&self, frame_number: u64) -> Result<()> {
        let cursor_key = quil_store::encoding::global_materialized_cursor_key();
        let start = std::time::Instant::now();
        let res = self
            .crdt
            .commit_with_global_cursor(frame_number, &cursor_key);
        crate::metrics::observe_execution_duration("crdt", "commit", start.elapsed().as_secs_f64());
        res?;
        Ok(())
    }

    /// Call before GLOBAL frame `frame_number` executes. From the exact
    /// state-size epoch sizes count every committed leaf exactly: the first
    /// such frame rebuilds them once from the committed state trees
    /// ([`quil_hypergraph::HypergraphCrdt::activate_exact_sizes`]), so every
    /// node counts the world size and the reward basis alike whatever its
    /// restart or sync history. A no-op before the epoch and once active.
    pub fn prepare_exact_state_sizes(&self, frame_number: u64) -> Result<()> {
        if self.crdt.exact_sizes() || !quil_types::consensus::exact_state_size_active(frame_number)
        {
            return Ok(());
        }
        let mut apps: Vec<[u8; 32]> = Vec::new();
        if let Some(shards) = &self.shards_store {
            apps.extend(
                shards
                    .range_app_shards()?
                    .iter()
                    .filter(|shard| shard.shard_key.len() == 35)
                    .filter_map(|shard| <[u8; 32]>::try_from(&shard.shard_key[3..]).ok()),
            );
        }
        if let Some(rebuild) = self.crdt.activate_exact_sizes(&apps)? {
            tracing::info!(
                frame = frame_number,
                apps = rebuild.apps,
                shards = rebuild.shards,
                staged_leaves = rebuild.staged_leaves,
                ms = rebuild.elapsed.as_millis() as u64,
                "exact state sizes: rebuilt every application's sizes from the committed leaf sizes; world size and reward basis follow them from this frame"
            );
        }
        Ok(())
    }

    /// Atomically publish application state and its full-filter cursor.
    pub fn commit_frame_with_app_cursor(&self, frame_number: u64, filter: &[u8]) -> Result<()> {
        let key = quil_store::encoding::consensus_materialized_cursor_key(filter);
        let start = std::time::Instant::now();
        let result = self.crdt.commit_with_frame_cursor(frame_number, &key);
        crate::metrics::observe_execution_duration("crdt", "commit", start.elapsed().as_secs_f64());
        result?;
        Ok(())
    }

    /// Commit an application's state, cursor and outgoing history together.
    /// Production clock and hypergraph stores share a DB; later headers read
    /// these clock records even after the manager's memory has been discarded.
    /// Report construction and history encoding must succeed before any write.
    pub fn commit_frame_with_app_history(
        &self,
        frame_number: u64,
        filter: &[u8],
        fee_total: u128,
        settlements: &[crate::token_intrinsic::settlement_record::SettlementEntry],
        spends: &[Vec<u8>],
        anchor: u64,
    ) -> Result<Vec<u8>> {
        use crate::token_intrinsic::{accumulator_header, settlement_record, spend_relay};
        use quil_store::encoding;

        let settlements = settlement_record::encode_entries(settlements)?;
        let spends = spend_relay::encode_frame_entries(spends)?;
        self.fold_placed_coins(frame_number, filter)?;
        // HypergraphState includes this frame's staged blobs. Computing after
        // commit would leave a cursor with no report if construction failed.
        let report = self.shard_accumulator_report(filter, anchor)?;
        let digest = accumulator_header::report_digest(&report);
        let mut records = vec![
            (
                encoding::clock_shard_frame_fee_total_key(filter, frame_number),
                fee_total.to_be_bytes().to_vec(),
            ),
            (
                encoding::clock_shard_frame_settlements_key(filter, frame_number),
                settlements,
            ),
            (
                encoding::clock_shard_frame_spends_key(filter, frame_number),
                spends,
            ),
            (
                encoding::clock_shard_frame_accumulator_key(filter, frame_number),
                digest.clone(),
            ),
        ];
        if !digest.is_empty() {
            records.push((
                encoding::clock_shard_accumulator_report_key(filter, &digest),
                report.clone(),
            ));
        }
        let cursor = encoding::consensus_materialized_cursor_key(filter);
        let start = std::time::Instant::now();
        let result =
            self.crdt
                .commit_with_frame_cursor_and_records(frame_number, &cursor, &records);
        crate::metrics::observe_execution_duration("crdt", "commit", start.elapsed().as_secs_f64());
        result?;
        Ok(report)
    }

    /// Fold the coins this application frame's deliveries placed into their
    /// blocks and the root, once, before its report reads them. Refreshing the
    /// root for each delivery redid the summary and root history per coin.
    fn fold_placed_coins(&self, frame_number: u64, filter: &[u8]) -> Result<()> {
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (frame_number, filter);
            Ok(())
        }
        #[cfg(feature = "native-proof")]
        {
            use crate::token_intrinsic::{dispatch::TokenPolicy, roots};
            // A filter naming no shard is refused by the report.
            let Some(application) = quil_forest::decode_shard_filter_or_root(filter, 32)
                .and_then(|(application, _)| <[u8; 32]>::try_from(application.as_slice()).ok())
            else {
                return Ok(());
            };
            let network =
                quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
            let limits = TokenPolicy::for_network(self.pricing_network()).snapshots;
            let state = crate::hypergraph_state::HypergraphState::new(self.crdt());
            if roots::fold_placed(&state, frame_number, &network, &application, limits)?.is_some() {
                state.commit()?;
            }
            Ok(())
        }
    }

    /// Checkpoint completed shard sync without flushing unrelated pending state.
    pub fn checkpoint_app_materialized_cursor(
        &self,
        frame_number: u64,
        filter: &[u8],
    ) -> Result<()> {
        self.crdt.checkpoint_frame_cursor(
            frame_number,
            &quil_store::encoding::consensus_materialized_cursor_key(filter),
        )
    }

    pub fn read_app_materialized_cursor(&self, filter: &[u8]) -> Result<u64> {
        self.crdt
            .read_frame_cursor(&quil_store::encoding::consensus_materialized_cursor_key(
                filter,
            ))
    }

    /// Apply epoch-aligned shard topology changes (split/merge) due at this GLOBAL
    /// frame, once per frame — decoupled from `invoke_frame_header` so a staged
    /// `PendingShardChange` flips at its E+2 boundary regardless of whether an
    /// app-shard `FrameHeader` is materialized in the frame. GLOBAL-ONLY; a no-op
    /// on app-shard-only managers (no "global" engine). MUST be called after the
    /// frame's messages are processed and BEFORE `commit_frame_with_global_cursor`,
    /// so the reassignment writes ride the same commit batch.
    pub fn apply_global_due_shard_changes(&self, frame_number: u64) -> Result<()> {
        // Confirm whether the per-frame ~5s materialize cost is the WAIT to acquire
        // this write lock (contention with another engines-lock holder — e.g. a
        // concurrent materializer or a background task) vs actual apply work.
        let engines_lock_start = std::time::Instant::now();
        let mut engines = self.engines.write().unwrap();
        let engines_lock_ms = engines_lock_start.elapsed().as_millis() as u64;
        if engines_lock_ms > 500 {
            tracing::warn!(
                frame = frame_number,
                ms = engines_lock_ms,
                "apply_global_due_shard_changes: waited >500ms for the engines WRITE lock (contention, not apply work)"
            );
        }
        let Some(engine) = engines.get_mut("global") else {
            return Ok(());
        };
        let Some(any) = engine.as_any_mut() else {
            return Ok(());
        };
        let Some(global) = any.downcast_mut::<GlobalExecutionEngine>() else {
            return Ok(());
        };
        global.apply_due_shard_changes(frame_number)
    }

    /// Pay the token fees materialized by a GLOBAL frame to the frame's
    /// prover (see `GlobalExecutionEngine::credit_global_frame_fees`).
    pub fn credit_global_frame_fees(
        &self,
        frame_number: u64,
        prover_public_key: &[u8],
        fee_total: u128,
    ) -> Result<bool> {
        if fee_total == 0 {
            return Ok(false);
        }
        let mut engines = self.engines.write().unwrap();
        let Some(engine) = engines.get_mut("global") else {
            return Ok(false);
        };
        let Some(any) = engine.as_any_mut() else {
            return Ok(false);
        };
        let Some(global) = any.downcast_mut::<GlobalExecutionEngine>() else {
            return Ok(false);
        };
        global.credit_global_frame_fees(frame_number, prover_public_key, fee_total)
    }

    /// Get an engine by name.
    pub fn get_engine(&self, name: &str) -> Option<String> {
        let engines = self.engines.read().unwrap();
        if engines.contains_key(name) {
            Some(name.to_string())
        } else {
            None
        }
    }

    /// Install frame-header deps onto the global engine's intrinsic.
    /// Must be called for the materializer to apply shard-coverage
    /// proofs (LastActiveFrameNumber advance + reward distribution).
    /// Without this, `invoke_frame_header` is a silent no-op.
    pub fn install_global_frame_header_deps(
        &self,
        prover_registry: Arc<dyn quil_types::consensus::ProverRegistry>,
        reward_issuance: Arc<dyn quil_types::consensus::RewardIssuance>,
        bls_constructor: Arc<dyn quil_types::crypto::BlsConstructor>,
        inclusion_prover: Arc<dyn InclusionProver>,
        frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    ) -> Result<()> {
        let mut engines = self.engines.write().unwrap();
        let engine = engines
            .get_mut("global")
            .ok_or_else(|| QuilError::NotFound("engine 'global' not found".into()))?;
        let any = engine.as_any_mut().ok_or_else(|| {
            QuilError::Internal("global engine does not support as_any_mut downcast".into())
        })?;
        let global = any.downcast_mut::<GlobalExecutionEngine>().ok_or_else(|| {
            QuilError::Internal("global engine is not a GlobalExecutionEngine".into())
        })?;
        global.install_frame_header_deps(
            prover_registry,
            reward_issuance,
            bls_constructor,
            inclusion_prover,
            frame_prover,
        );
        Ok(())
    }

    /// Install only the `frame_prover` onto the global engine's
    /// intrinsic. Required on every node that drives global-frame
    /// validation — including non-archive masters, whose archive-poller
    /// callback invokes `process_global_frame` → `validate_message` →
    /// the intrinsic's `TYPE_PROVER_JOIN` arm. Without this, ProverJoin
    /// validation fails closed with "frame_prover not installed". The
    /// broader `install_global_frame_header_deps` is archive-only
    /// because it also wires materializer-side registry / issuance /
    /// kick deps that non-archive masters don't need.
    pub fn install_global_frame_prover(
        &self,
        frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    ) -> Result<()> {
        let mut engines = self.engines.write().unwrap();
        let engine = engines
            .get_mut("global")
            .ok_or_else(|| QuilError::NotFound("engine 'global' not found".into()))?;
        let any = engine.as_any_mut().ok_or_else(|| {
            QuilError::Internal("global engine does not support as_any_mut downcast".into())
        })?;
        let global = any.downcast_mut::<GlobalExecutionEngine>().ok_or_else(|| {
            QuilError::Internal("global engine is not a GlobalExecutionEngine".into())
        })?;
        global.install_frame_prover(frame_prover);
        Ok(())
    }

    /// Install the split-reset config (archive KEEP-set + network QUIL genesis
    /// prefix set) on the global engine's intrinsic, used by the unified-tree
    /// split reset at the flag day. GLOBAL-ONLY; a no-op without a "global" engine.
    pub fn install_global_split_reset_config(
        &self,
        archive_prover_addresses: Arc<std::collections::HashSet<Vec<u8>>>,
        reset_genesis_prefixes: Arc<Vec<Vec<u32>>>,
    ) -> Result<()> {
        let mut engines = self.engines.write().unwrap();
        let Some(engine) = engines.get_mut("global") else {
            return Ok(());
        };
        let Some(any) = engine.as_any_mut() else {
            return Ok(());
        };
        let Some(global) = any.downcast_mut::<GlobalExecutionEngine>() else {
            return Ok(());
        };
        global.install_split_reset_config(archive_prover_addresses, reset_genesis_prefixes);
        Ok(())
    }

    /// Get all supported capabilities across all engines.
    pub fn get_supported_capabilities(&self) -> Vec<node::Capability> {
        let engines = self.engines.read().unwrap();
        engines
            .values()
            .flat_map(|e| e.get_capabilities())
            .collect()
    }

    /// Route a message to the appropriate engine and validate it.
    pub fn validate_message(
        &self,
        frame_number: u64,
        address: &[u8],
        message: &[u8],
    ) -> Result<()> {
        let engine_name = self.select_engine(address)?;
        let label = crate::metrics::engine_label(&engine_name);
        crate::metrics::inc_execution_requests(label, "validate");
        let start = std::time::Instant::now();
        let _held = quil_types::lock_holders::hold(quil_types::lock_holders::Holder::Validation);
        let engines = self.engines.read().unwrap();
        let res = if let Some(engine) = engines.get(&engine_name) {
            engine.validate_message(frame_number, address, message)
        } else {
            Err(QuilError::NotFound(format!(
                "engine '{}' not found",
                engine_name
            )))
        };
        crate::metrics::observe_execution_duration(
            label,
            "validate",
            start.elapsed().as_secs_f64(),
        );
        if res.is_err() {
            crate::metrics::inc_execution_errors(label, "validate");
        }
        res
    }

    /// Route a message to the appropriate engine and process it.
    pub fn process_message(
        &self,
        frame_number: u64,
        fee_multiplier: &BigInt,
        address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        self.process_message_with_context(
            quil_types::execution::FrameExecutionContext {
                frame_number,
                finalized_global_frame: None,
                venue: None,
                shard: quil_types::execution::ShardPath::WHOLE,
            },
            fee_multiplier,
            address,
            message,
        )
    }

    pub fn process_message_with_context(
        &self,
        context: quil_types::execution::FrameExecutionContext,
        fee_multiplier: &BigInt,
        address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        let engine_name = self.select_engine(address)?;
        let label = crate::metrics::engine_label(&engine_name);
        crate::metrics::inc_execution_requests(label, "process");
        let start = std::time::Instant::now();
        let _held = quil_types::lock_holders::hold(quil_types::lock_holders::Holder::Processing);
        let engines = self.engines.read().unwrap();
        let res = if let Some(engine) = engines.get(&engine_name) {
            engine.process_message_with_context(context, fee_multiplier, address, message)
        } else {
            Err(QuilError::NotFound(format!(
                "engine '{}' not found",
                engine_name
            )))
        };
        crate::metrics::observe_execution_duration(label, "process", start.elapsed().as_secs_f64());
        if res.is_err() {
            crate::metrics::inc_execution_errors(label, "process");
        }
        res
    }

    /// Acquire address locks for a message by routing to the
    /// appropriate engine. Used by app shard frame production to build
    /// the per-message `tx_map` that feeds `requests_root`.
    pub fn lock(&self, frame_number: u64, address: &[u8], message: &[u8]) -> Result<Vec<Vec<u8>>> {
        let engine_name = self.select_engine(address)?;
        let _held = quil_types::lock_holders::hold(quil_types::lock_holders::Holder::Processing);
        let engines = self.engines.read().unwrap();
        if let Some(engine) = engines.get(&engine_name) {
            engine.lock(frame_number, address, message)
        } else {
            Err(QuilError::NotFound(format!(
                "engine '{}' not found",
                engine_name
            )))
        }
    }

    /// Release any address locks held by every registered engine.
    /// Mirrors Go's `executionManager.Unlock()` post-loop call: at
    /// frame production time we call this once after the per-message
    /// `lock` loop completes so no engine holds stale locks across
    /// frames.
    pub fn unlock(&self) -> Result<()> {
        let engines = self.engines.read().unwrap();
        for engine in engines.values() {
            engine.unlock()?;
        }
        Ok(())
    }

    /// Get the cost of a message by routing to the appropriate engine.
    ///
    /// Token requests contribute their cost even inside mixed bundles.
    /// Other operation types retain their current pricing policy; their presence
    /// cannot erase a token operation's cost contribution.
    pub fn get_cost(&self, message: &[u8]) -> Result<BigInt> {
        let _held = quil_types::lock_holders::hold(quil_types::lock_holders::Holder::CostQuery);
        let engines = self.engines.read().unwrap();
        // World-state growth of hypergraph and compute writes (and of a
        // settlement claim's consumption marker), paid by the settlement the
        // bundle consumes.
        #[cfg(feature = "confidential-tokens")]
        let consumer = BigInt::from(crate::token_intrinsic::settlement_claim::message_cost(
            message,
        )?);
        #[cfg(not(feature = "confidential-tokens"))]
        let consumer = BigInt::from(0);
        if let Some(token) = engines.get("token") {
            if let Some(cost) = token_message_cost(token.as_ref(), message)? {
                return Ok(cost + consumer);
            }
        }
        if let Some(engine) = engines.get("global") {
            return Ok(engine.get_cost(message)? + consumer);
        }
        Ok(consumer)
    }

    /// QUIL fees a successfully executed request or bundle paid to the venue
    /// that executed it at `address`, which the venue's provers are credited.
    ///
    /// Only what the executing engine admitted counts, never fees merely
    /// present in the bytes: on the QUIL application the proof-bound fees of
    /// the QUIL operations it verified (a mint claim's fee was already paid by
    /// its global authorization and is excluded); on any other application the
    /// settlement its claim consumed (its engine verifies the claim before any
    /// write, and token operations there carry no QUIL fee). The global
    /// intrinsic executes no fee-bearing operation, so bundles it processes
    /// (including application operations published to the global topic for a
    /// covered application, which it skips) credit nothing.
    /// The accumulator report of the shard `filter` names, including staged
    /// state: encoded [`ShardReport`] bytes, or empty when it holds no coins.
    ///
    /// [`ShardReport`]: crate::token_intrinsic::shard_accumulator::ShardReport
    /// The block summary (`BLOCK_SUMMARY_ADDRESS`) and published root are
    /// records outside every sub-shard's prefix: each shard keeps a private
    /// copy describing the blocks it appended, and the report folds from it.
    /// A member that inherited a merged range holds the copy of the source it
    /// came from, so the two halves of a merged committee reported different
    /// roots over identical state (live: no frame after the first could
    /// finalize). Sync and restart can likewise leave this private record
    /// absent or stale. Rebuild it from the covered block roots/frontiers,
    /// inside the next report's commit, without enumerating every coin.
    pub fn rebuild_block_summary_before_report(&self, filter: &[u8]) {
        if let Some((application, _)) = quil_forest::decode_shard_filter_or_root(filter, 32) {
            if let Ok(application) = <[u8; 32]>::try_from(application.as_slice()) {
                self.summary_rebuilds.write().unwrap().insert(application);
            }
        }
    }

    /// Read-only report for history recovery from a captured committed state.
    /// `anchor`: the GLOBAL frame the reported frame cites.
    pub fn snapshot_accumulator_report(
        &self,
        snapshot: &dyn quil_types::store::SnapshotReadable,
        filter: &[u8],
        anchor: u64,
    ) -> Result<Vec<u8>> {
        #[cfg(not(feature = "confidential-tokens"))]
        {
            let _ = (snapshot, filter, anchor);
            Ok(Vec::new())
        }
        #[cfg(feature = "confidential-tokens")]
        {
            let (application, shard) = quil_forest::decode_shard_filter_or_root(filter, 32)
                .ok_or_else(|| {
                    QuilError::InvalidArgument("snapshot report: invalid filter".into())
                })?;
            let application: [u8; 32] = application.try_into().map_err(|_| {
                QuilError::InvalidArgument("snapshot report: invalid application".into())
            })?;
            let network =
                quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
            let attest =
                anchor >= crate::token_intrinsic::global_commit::orphan_replacement_frame();
            crate::token_intrinsic::shard_accumulator::snapshot_report(
                snapshot,
                &network,
                &application,
                &shard,
                attest,
            )?
            .map(|report| report.encode())
            .transpose()
            .map(Option::unwrap_or_default)
        }
    }

    /// `anchor`: the GLOBAL frame the reported frame cites; from the orphan
    /// re-placement frame the report also attests held blocks.
    pub fn shard_accumulator_report(&self, filter: &[u8], anchor: u64) -> Result<Vec<u8>> {
        #[cfg(not(feature = "confidential-tokens"))]
        {
            let _ = (filter, anchor);
            Ok(Vec::new())
        }
        #[cfg(feature = "confidential-tokens")]
        {
            use crate::token_intrinsic::roots;
            let (application, shard) = quil_forest::decode_shard_filter_or_root(filter, 32)
                .ok_or_else(|| {
                    QuilError::InvalidArgument("accumulator report: filter names no shard".into())
                })?;
            let application: [u8; 32] = application.as_slice().try_into().map_err(|_| {
                QuilError::InvalidArgument("accumulator report: malformed application".into())
            })?;
            let network =
                quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
            let state = crate::hypergraph_state::HypergraphState::new(self.crdt());
            if self.summary_rebuilds.read().unwrap().contains(&application) {
                roots::rebuild_block_summary(&state, &network, &application, &shard)?;
                state.commit()?;
                self.summary_rebuilds.write().unwrap().remove(&application);
                tracing::info!(
                    filter = hex::encode(filter),
                    "rebuilt the local block summary from covered block records"
                );
            }
            let attest =
                anchor >= crate::token_intrinsic::global_commit::orphan_replacement_frame();
            match crate::token_intrinsic::shard_accumulator::shard_report(
                &state,
                &network,
                &application,
                &shard,
                attest,
            )? {
                Some(report) => report.encode(),
                None => Ok(Vec::new()),
            }
        }
    }

    /// Encoded spend entries of a message's operations that commit through the
    /// global frame, executed at `source_frame` of a shard of `address`'s
    /// application. Built from the operation bytes, plus the deployed mint
    /// policy for custom mints; nothing is verified here. Empty for messages
    /// with none. See `token_intrinsic::spend_entries`.
    /// Whether EVERY operation in this message commits through the global
    /// frame, so the frame carrying it must price it at the global venue's fee
    /// vote of one.
    ///
    /// A relayed operation is charged where it commits. The global frame prices
    /// at vote 1 (`frame_materializer`, `frame_processor`) and that is the quote
    /// a wallet is handed for it: `GetTokenFeeQuote` answers QUIL from the
    /// global snapshot and refuses any global-venue quote whose vote is not 1.
    /// An app shard's own frame carries a different, generally much larger vote
    /// (`compute_fee_multiplier_vote`), so pricing the relay at that vote
    /// rejects operations the global frame would accept, at a price no wallet
    /// was ever quoted — every spend would be skipped as
    /// `QUIL fee below operation's dynamic cost`.
    ///
    /// Conservative on a mixed message: if anything in it executes in the app
    /// venue, the whole message keeps the app vote (the higher price).
    pub fn message_commits_globally(&self, address: &[u8], message: &[u8]) -> bool {
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (address, message);
            false
        }
        #[cfg(feature = "native-proof")]
        {
            use crate::message_envelope::{
                CanonicalMessageBundle, CanonicalMessageRequest, TYPE_MESSAGE_BUNDLE,
                TYPE_MESSAGE_REQUEST,
            };
            let Some(application) = address.get(..32).and_then(|a| <[u8; 32]>::try_from(a).ok())
            else {
                return false;
            };
            if message.len() < 4 {
                return false;
            }
            let requests = match u32::from_be_bytes(message[..4].try_into().unwrap()) {
                TYPE_MESSAGE_REQUEST => {
                    match CanonicalMessageRequest::from_canonical_bytes(message) {
                        Ok(request) => vec![request],
                        Err(_) => return false,
                    }
                }
                TYPE_MESSAGE_BUNDLE => {
                    match CanonicalMessageBundle::from_canonical_bytes(message) {
                        Ok(bundle) => bundle.requests.into_iter().flatten().collect(),
                        Err(_) => return false,
                    }
                }
                _ => return false,
            };
            !requests.is_empty()
                && requests.iter().all(|request| {
                    crate::token_intrinsic::spend_entries::commits_globally(
                        &application,
                        request.inner_type_prefix,
                    )
                })
        }
    }

    pub fn message_spend_entries(
        &self,
        address: &[u8],
        message: &[u8],
        source_frame: u64,
    ) -> Result<Vec<Vec<u8>>> {
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (address, message, source_frame);
            Ok(Vec::new())
        }
        #[cfg(feature = "native-proof")]
        {
            use crate::message_envelope::{
                CanonicalMessageBundle, CanonicalMessageRequest, TYPE_MESSAGE_BUNDLE,
                TYPE_MESSAGE_REQUEST,
            };
            let Some(application) = address.get(..32).and_then(|a| <[u8; 32]>::try_from(a).ok())
            else {
                return Ok(Vec::new());
            };
            if message.len() < 4 {
                return Ok(Vec::new());
            }
            let requests = match u32::from_be_bytes(message[..4].try_into().unwrap()) {
                TYPE_MESSAGE_REQUEST => {
                    vec![CanonicalMessageRequest::from_canonical_bytes(message)?]
                }
                TYPE_MESSAGE_BUNDLE => CanonicalMessageBundle::from_canonical_bytes(message)?
                    .requests
                    .into_iter()
                    .flatten()
                    .collect(),
                _ => return Ok(Vec::new()),
            };
            let network =
                quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
            let state = crate::hypergraph_state::HypergraphState::new(self.crdt());
            let mut entries = Vec::new();
            for request in requests {
                if !crate::token_intrinsic::spend_entries::commits_globally(
                    &application,
                    request.inner_type_prefix,
                ) {
                    continue;
                }
                // A custom mint's consumptions depend on the deployed policy.
                let entry = crate::token_intrinsic::spend_entries::commit_entry(
                    &state,
                    &network,
                    &application,
                    request.inner_type_prefix,
                    &request.inner_bytes,
                    source_frame,
                )?;
                entries.push(entry.encode()?);
            }
            Ok(entries)
        }
    }

    /// The certified frames holding the bytes of everything committed to the
    /// shard `filter` that it has not delivered yet: `(executing filter, frame
    /// number)`, without repeats. On a whole-application shard these are its
    /// own frames; on a split one they are mostly other shards', which a node
    /// must fetch before it can propose those deliveries.
    pub fn pending_delivery_sources(
        &self,
        global: Arc<quil_hypergraph::HypergraphCrdt>,
        filter: &[u8],
    ) -> Result<DeliverySourceScan> {
        self.pending_delivery_census(global, filter)
            .map(|census| DeliverySourceScan {
                sources: census.sources(),
                pending: census.items.len(),
                blocks: census.blocks,
            })
    }

    /// What is committed to the shard `filter` that it has not delivered
    /// yet: the next items of every block, in turns, up to
    /// [`MAX_DELIVERIES_PER_FRAME`] beyond those, and the backlog's scale.
    ///
    /// [`MAX_DELIVERIES_PER_FRAME`]: crate::token_intrinsic::delivery::MAX_DELIVERIES_PER_FRAME
    pub fn pending_delivery_census(
        &self,
        global: Arc<quil_hypergraph::HypergraphCrdt>,
        filter: &[u8],
    ) -> Result<DeliveryCensus> {
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (global, filter);
            Ok(DeliveryCensus::default())
        }
        #[cfg(feature = "native-proof")]
        {
            let Some((application, _)) = quil_forest::decode_shard_filter_or_root(filter, 32)
            else {
                return Ok(DeliveryCensus::default());
            };
            let Ok(application) = <[u8; 32]>::try_from(application.as_slice()) else {
                return Ok(DeliveryCensus::default());
            };
            let census = self.pending_census(global, filter)?;
            Ok(DeliveryCensus {
                items: census
                    .items
                    .iter()
                    .filter_map(|item| {
                        let bits = item.source_shard.bits()?;
                        Some(DeliveryItem {
                            source: (executing_filter(&application, &bits), item.source_frame),
                            tx_id: item.tx_id,
                            block: item.block,
                            seq: item.seq,
                            escrow: item.escrow,
                        })
                    })
                    .collect(),
                blocks: census.blocks,
                pending: census.pending,
                blocks_pending: census.blocks_pending,
                capped: census.capped,
                missing_records: census
                    .missing_records
                    .iter()
                    .map(|(_, block, seq)| (*block, *seq))
                    .collect(),
            })
        }
    }

    #[cfg(feature = "native-proof")]
    fn pending_census(
        &self,
        global: Arc<quil_hypergraph::HypergraphCrdt>,
        filter: &[u8],
    ) -> Result<crate::token_intrinsic::delivery::PendingCensus> {
        use crate::token_intrinsic::{delivery, dispatch::TokenPolicy};
        let Some((application, shard)) = quil_forest::decode_shard_filter_or_root(filter, 32)
        else {
            return Ok(Default::default());
        };
        let Ok(application) = <[u8; 32]>::try_from(application.as_slice()) else {
            return Ok(Default::default());
        };
        let network =
            quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
        let limits = TokenPolicy::for_network(self.pricing_network()).snapshots;
        let global = crate::hypergraph_state::HypergraphState::new(global);
        let local = crate::hypergraph_state::HypergraphState::new(self.crdt());
        delivery::pending_census(
            &global,
            &local,
            &network,
            &application,
            &shard,
            limits,
            delivery::MAX_DELIVERIES_PER_FRAME,
        )
    }

    /// Deliveries (`0x051A` operation bytes) of committed outputs the shard
    /// `filter` owns and has not yet taken, at most
    /// [`MAX_DELIVERIES_PER_FRAME`]. `global` holds GLOBAL state and `clock`
    /// canonical global frames; each record is proven at the newest global
    /// root retained at or before `anchor`. `operation(executing filter,
    /// source frame, tx id)` supplies the bytes of the committed operation,
    /// from the certified frame of the shard that executed it — the owner's
    /// own frames on a whole-application shard, and another shard's on a
    /// split one. A block whose next output cannot be delivered yet is left
    /// there, since its later outputs would be out of sequence; the other
    /// blocks' outputs are still delivered.
    ///
    /// [`MAX_DELIVERIES_PER_FRAME`]: crate::token_intrinsic::delivery::MAX_DELIVERIES_PER_FRAME
    pub fn coin_deliveries(
        &self,
        global: Arc<quil_hypergraph::HypergraphCrdt>,
        clock: &dyn quil_types::store::ClockStore,
        filter: &[u8],
        anchor: u64,
        operation: &dyn Fn(&[u8], u64, &[u8; 32]) -> Option<(u32, Vec<u8>)>,
    ) -> Result<Vec<Vec<u8>>> {
        #[cfg(not(feature = "native-proof"))]
        {
            let _ = (global, clock, filter, anchor, operation);
            Ok(Vec::new())
        }
        #[cfg(feature = "native-proof")]
        {
            use crate::token_intrinsic::delivery;
            let Some((application, _)) = quil_forest::decode_shard_filter_or_root(filter, 32)
            else {
                return Ok(Vec::new());
            };
            let Ok(application) = <[u8; 32]>::try_from(application.as_slice()) else {
                return Ok(Vec::new());
            };
            let network =
                quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
            let pending = self.pending_census(global.clone(), filter)?.items;
            let global = crate::hypergraph_state::HypergraphState::new(global);
            take_deliverable(pending, delivery::MAX_DELIVERIES_PER_FRAME, |item| {
                // Where it ran is where its bytes are: the commit recorded it.
                let Some(source) = item.source_shard.bits() else {
                    return Ok(None);
                };
                let source_filter = executing_filter(&application, &source);
                let delivered = operation(&source_filter, item.source_frame, &item.tx_id).and_then(
                    |(tp, bytes)| {
                        delivery::find_delivered(&network, &application, tp, &bytes, item)
                            .ok()
                            .flatten()
                    },
                );
                match delivered {
                    Some(delivered) => delivery::build_delivery(
                        &global,
                        clock,
                        &network,
                        &application,
                        anchor,
                        item,
                        delivered,
                    ),
                    None => Ok(None),
                }
            })
        }
    }

    /// Poseidon digest of the application root this node's own accumulator
    /// published for `filter`'s application, if any — for comparing, in logs,
    /// against the canonical root the global materializer folds from reports.
    pub fn local_application_root_digest(&self, filter: &[u8]) -> Result<Option<[u8; 32]>> {
        #[cfg(not(feature = "confidential-tokens"))]
        {
            let _ = filter;
            Ok(None)
        }
        #[cfg(feature = "confidential-tokens")]
        {
            let Some(application) = filter.get(..32).and_then(|a| <[u8; 32]>::try_from(a).ok())
            else {
                return Ok(None);
            };
            let network =
                quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
            let state = crate::hypergraph_state::HypergraphState::new(self.crdt());
            crate::token_intrinsic::roots::read_current(&state, &network, &application)?
                .map(|record| quil_crypto::poseidon::hash_bytes_to_32(&record.root.to_bytes()))
                .transpose()
        }
    }

    pub fn message_token_fees(&self, address: &[u8], message: &[u8]) -> Result<u128> {
        #[cfg(not(feature = "confidential-tokens"))]
        {
            let _ = (address, message);
            Ok(0)
        }
        #[cfg(feature = "confidential-tokens")]
        {
            use crate::message_envelope::{
                CanonicalMessageBundle, CanonicalMessageRequest, TYPE_MESSAGE_BUNDLE,
                TYPE_MESSAGE_REQUEST,
            };
            if message.len() < 4 || address.len() < 32 || address[..32] == domains::GLOBAL {
                return Ok(0);
            }
            if address[..32] != domains::QUIL_TOKEN {
                return Ok(
                    crate::token_intrinsic::settlement_claim::message_settlement_amount(message),
                );
            }
            // Operations that commit through the global frame are credited
            // there, and only if they commit (`global_commit::materialize_relay`).
            let fee_of = |tp: u32, bytes: &[u8]| -> u128 {
                let self_paid = (0x0512..=0x0518).contains(&tp)
                    && tp != crate::token_engine::TYPE_LATTICE_MINT_CLAIM
                    && !crate::token_intrinsic::spend_entries_relayed(tp);
                if self_paid
                    && crate::token_intrinsic::wire::domain(bytes).ok() == Some(domains::QUIL_TOKEN)
                {
                    crate::token_intrinsic::wire::fee(bytes).unwrap_or(0)
                } else {
                    0
                }
            };
            Ok(match u32::from_be_bytes(message[..4].try_into().unwrap()) {
                TYPE_MESSAGE_REQUEST => {
                    let request = CanonicalMessageRequest::from_canonical_bytes(message)?;
                    fee_of(request.inner_type_prefix, &request.inner_bytes)
                }
                TYPE_MESSAGE_BUNDLE => {
                    let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                    bundle.requests.iter().flatten().fold(0u128, |sum, r| {
                        sum.saturating_add(fee_of(r.inner_type_prefix, &r.inner_bytes))
                    })
                }
                _ => 0,
            })
        }
    }

    /// GLOBAL frames whose prover roots the reward citations of a request or
    /// bundle to `address` name (mint claims, settlement claims and coin
    /// deliveries that decode), limited to the ones execution reads: from the
    /// network's first citable frame to `anchor`, the executing frame's GLOBAL
    /// anchor. Ascending, each once. A shard worker fetches those it lacks
    /// before executing the frame; execution still decides every operation,
    /// so a citation missed here only goes unfetched.
    pub fn message_cited_global_frames(
        &self,
        address: &[u8],
        message: &[u8],
        anchor: u64,
    ) -> Vec<u64> {
        #[cfg(not(feature = "confidential-tokens"))]
        {
            let _ = (address, message, anchor);
            Vec::new()
        }
        #[cfg(feature = "confidential-tokens")]
        {
            use crate::message_envelope::{
                CanonicalMessageBundle, CanonicalMessageRequest, TYPE_MESSAGE_BUNDLE,
                TYPE_MESSAGE_REQUEST,
            };
            use crate::token_intrinsic::{constants, settlement_claim};
            let Some(application) = address.get(..32).and_then(|a| <[u8; 32]>::try_from(a).ok())
            else {
                return Vec::new();
            };
            let requests: Vec<CanonicalMessageRequest> = match message
                .get(..4)
                .map(|prefix| u32::from_be_bytes(prefix.try_into().unwrap()))
            {
                Some(TYPE_MESSAGE_REQUEST) => {
                    CanonicalMessageRequest::from_canonical_bytes(message)
                        .map(|request| vec![request])
                        .unwrap_or_default()
                }
                Some(TYPE_MESSAGE_BUNDLE) => CanonicalMessageBundle::from_canonical_bytes(message)
                    .map(|bundle| bundle.requests.into_iter().flatten().collect())
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            let network = crate::token_intrinsic::state::network_identifier(self.pricing_network());
            let first =
                crate::token_intrinsic::mint_authorization::first_citable_global_frame(&network);
            let mut cited = std::collections::BTreeSet::new();
            for request in &requests {
                let bytes = request.inner_bytes.as_slice();
                let frame = match request.inner_type_prefix {
                    // Execution refuses a mint claim of any other application
                    // before reading its citation (`mint_claim::verify_from_clock`).
                    constants::TYPE_LATTICE_MINT_CLAIM
                        if application == crate::domains::QUIL_TOKEN =>
                    {
                        quil_lattice_ct::confidential::mint_claim::MintClaim::decode(
                            bytes,
                            &network,
                            &application,
                        )
                        .ok()
                        .map(|claim| claim.cited_global_frame)
                    }
                    settlement_claim::TYPE_SETTLEMENT_CLAIM => {
                        settlement_claim::SettlementClaim::decode(bytes)
                            .ok()
                            .map(|claim| claim.cited_global_frame)
                    }
                    #[cfg(feature = "native-proof")]
                    constants::TYPE_COIN_DELIVERY => {
                        crate::token_intrinsic::delivery::CoinDelivery::decode(
                            bytes,
                            &network,
                            &application,
                        )
                        .ok()
                        .map(|delivery| delivery.cited_global_frame)
                    }
                    _ => None,
                };
                cited.extend(frame.filter(|frame| (first..=anchor).contains(frame)));
            }
            cited.into_iter().collect()
        }
    }

    /// Relay entries of the cross-domain settlements (`0x0518`) carried by a
    /// request or bundle, in request order (empty for anything else). The app
    /// materializer records them for an admitted bundle; the next shard frame
    /// headers relay them to the global materializer.
    pub fn message_settlements(
        &self,
        message: &[u8],
    ) -> Result<Vec<crate::token_intrinsic::settlement_record::SettlementEntry>> {
        #[cfg(not(feature = "confidential-tokens"))]
        {
            let _ = message;
            Ok(Vec::new())
        }
        #[cfg(feature = "confidential-tokens")]
        {
            use crate::message_envelope::{
                CanonicalMessageBundle, CanonicalMessageRequest, TYPE_MESSAGE_BUNDLE,
                TYPE_MESSAGE_REQUEST,
            };
            use crate::token_intrinsic::settlement_record::operation_entry;
            // Settlements commit through the global frame, which records them
            // only if their spend commits; nothing is relayed separately.
            if message.len() < 4 || crate::token_intrinsic::spend_entries_relayed(0x0518) {
                return Ok(Vec::new());
            }
            let mut entries = Vec::new();
            match u32::from_be_bytes(message[..4].try_into().unwrap()) {
                TYPE_MESSAGE_REQUEST => {
                    let request = CanonicalMessageRequest::from_canonical_bytes(message)?;
                    if request.inner_type_prefix == 0x0518 {
                        entries.extend(operation_entry(&request.inner_bytes)?);
                    }
                }
                TYPE_MESSAGE_BUNDLE => {
                    let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                    for request in bundle
                        .requests
                        .iter()
                        .flatten()
                        .filter(|r| r.inner_type_prefix == 0x0518)
                    {
                        entries.extend(operation_entry(&request.inner_bytes)?);
                    }
                }
                _ => {}
            }
            Ok(entries)
        }
    }

    /// Select the engine for a given domain address. Port of Go
    /// `ExecutionEngineManager.ProcessMessage`'s routing
    /// (execution_manager.go:357-549):
    /// - `0xff*32` (GLOBAL) → global engine.
    /// - a base domain (COMPUTE / HYPERGRAPH_BASE / TOKEN_BASE /
    /// QUIL_TOKEN) → that engine directly.
    /// - any other address is a DEPLOYED app: read its base type-domain
    /// from the metadata vertex at `(addr, 0xff*32)`, key `0xff*32`
    /// (written at deploy by `init_metadata_vertex`), and route by it.
    /// - no metadata / unknown type-domain → error (Go errors "no
    /// execution engine found"; we do NOT silently default to
    /// hypergraph — that was the prior bug that mis-routed everything).
    fn select_engine(&self, address: &[u8]) -> Result<String> {
        if address.len() < 32 {
            return Err(QuilError::InvalidArgument("address too short".into()));
        }

        let mut addr = [0u8; 32];
        addr.copy_from_slice(&address[..32]);

        if addr == domains::GLOBAL {
            return Ok("global".into());
        }

        let token_base = crate::token_intrinsic::constants::token_base_domain();
        let hg_base = crate::hypergraph_intrinsic::hypergraph_base_domain();

        // Base domains route directly; anything else resolves via the
        // deployed app's recorded type-domain.
        let route: [u8; 32] = if addr == domains::COMPUTE
            || addr == hg_base
            || addr == token_base
            || addr == domains::QUIL_TOKEN
        {
            addr
        } else {
            let loc = quil_hypergraph::addressing::Location {
                app_address: addr,
                data_address: [0xFFu8; 32],
            };
            let blob = self.crdt.get_vertex_data(&loc).ok_or_else(|| {
                QuilError::NotFound(format!(
                    "no execution engine found for address: {} (no metadata vertex)",
                    hex::encode(addr)
                ))
            })?;
            let root = quil_tries::deserialize_go_tree(&blob).map_err(|e| {
                QuilError::Internal(format!("select_engine: metadata tree deserialize: {e}"))
            })?;
            let tree = quil_tries::VectorCommitmentTree { root };
            let type_domain = tree.get(&[0xFFu8; 32]).ok_or_else(|| {
                QuilError::NotFound(format!(
                    "no type-domain in metadata for address: {}",
                    hex::encode(addr)
                ))
            })?;
            if type_domain.len() < 32 {
                return Err(QuilError::Internal(
                    "select_engine: type-domain shorter than 32 bytes".into(),
                ));
            }
            let mut td = [0u8; 32];
            td.copy_from_slice(&type_domain[..32]);
            td
        };

        engine_for_route(&route).map(String::from).ok_or_else(|| {
            QuilError::NotFound(format!(
                "no execution engine found for address: {}",
                hex::encode(addr)
            ))
        })
    }
}

/// The engine executing an application whose type domain is `route` (a base
/// domain routes as itself), or `None` for no engine.
pub fn engine_for_route(route: &[u8; 32]) -> Option<&'static str> {
    if *route == domains::COMPUTE {
        Some("compute")
    } else if *route == crate::hypergraph_intrinsic::hypergraph_base_domain() {
        Some("hypergraph")
    } else if *route == crate::token_intrinsic::constants::token_base_domain()
        || *route == domains::QUIL_TOKEN
    {
        Some("token")
    } else {
        None
    }
}

/// Price token-only requests and bundles through the token engine. Returns
/// `None` for anything else (including malformed or mixed bundles) so the
/// caller keeps its historical routing for those messages.
fn token_message_cost(
    token: &dyn quil_types::execution::ShardExecutionEngine,
    message: &[u8],
) -> Result<Option<BigInt>> {
    use crate::message_envelope::{
        CanonicalMessageBundle, CanonicalMessageRequest, TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST,
    };
    if message.len() < 4 {
        return Ok(None);
    }
    match u32::from_be_bytes(message[..4].try_into().unwrap()) {
        TYPE_MESSAGE_REQUEST => {
            let request = CanonicalMessageRequest::from_canonical_bytes(message)?;
            if !crate::token_engine::is_token_type_prefix(request.inner_type_prefix) {
                return Ok(None);
            }
            token.get_cost(message).map(Some)
        }
        TYPE_MESSAGE_BUNDLE => {
            let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
            let mut total = BigInt::from(0);
            let mut priced = false;
            for request in bundle.requests.iter().flatten() {
                if !crate::token_engine::is_token_type_prefix(request.inner_type_prefix) {
                    continue;
                }
                total += token.get_cost(&request.to_canonical_bytes()?)?;
                priced = true;
            }
            Ok(priced.then_some(total))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
#[path = "manager_fork_tests.rs"]
mod fork_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use quil_hypergraph::testing::MemStore;
    use quil_types::crypto::NoopInclusionProver;

    #[test]
    fn global_quil_fee_snapshot_requires_current_materialized_frame_and_explicit_publication() {
        let manager = build_manager(true);
        assert_eq!(manager.global_quil_fee_snapshot(42).unwrap(), None);
        let snapshot = crate::pricing::GlobalQuilFeeSnapshot {
            frame_number: 42,
            difficulty: 50_000,
            world_state_bytes: 123_456,
        };
        manager.publish_global_quil_fee_snapshot(Some(snapshot));
        assert_eq!(
            manager.global_quil_fee_snapshot(42).unwrap(),
            Some(snapshot)
        );
        assert_eq!(manager.global_quil_fee_snapshot(41).unwrap(), None);
        assert_eq!(manager.global_quil_fee_snapshot(43).unwrap(), None);
        manager.publish_global_quil_fee_snapshot(None);
        assert_eq!(manager.global_quil_fee_snapshot(42).unwrap(), None);
        // The global venue snapshot is independent of QUIL routing.
        assert_eq!(manager.global_venue_fee_snapshot(42).unwrap(), None);
        manager.publish_global_venue_fee_snapshot(snapshot);
        assert_eq!(
            manager.global_venue_fee_snapshot(42).unwrap(),
            Some(snapshot)
        );
        assert_eq!(manager.global_venue_fee_snapshot(43).unwrap(), None);
        assert_eq!(manager.global_quil_fee_snapshot(42).unwrap(), None);
    }

    #[test]
    fn application_venue_switches_the_token_engine_only() {
        let mut manager = build_manager(true).with_application_venue().unwrap();
        let engines = manager.engines.get_mut().unwrap();
        assert!(
            engines.contains_key("global"),
            "the global engine stays installed"
        );
        let token = engines
            .get_mut("token")
            .unwrap()
            .as_any_mut()
            .unwrap()
            .downcast_mut::<TokenExecutionEngine>()
            .unwrap();
        assert_eq!(token.mode(), crate::engines::ExecutionMode::Application);
        let mut global = build_manager(true);
        let token = global
            .engines
            .get_mut()
            .unwrap()
            .get_mut("token")
            .unwrap()
            .as_any_mut()
            .unwrap()
            .downcast_mut::<TokenExecutionEngine>()
            .unwrap();
        assert_eq!(token.mode(), crate::engines::ExecutionMode::Global);
    }

    /// An arriving bundle sends to the proof worker only its operations that
    /// pass dispatch's checks before native work; one that does not decode,
    /// holds an operation failing those checks, or holds an operation the
    /// global commit decided sends none. Without a token policy every
    /// confidential operation counts.
    #[cfg(feature = "native-proof")]
    #[test]
    fn arrival_operations_leave_out_decided_and_malformed_submissions() {
        use super::prework_tests::{key_address, legacy_coin};
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use crate::token_intrinsic::{dispatch::TokenPolicy, global_commit, state::SnapshotLimits};
        use quil_lattice_ct::confidential::{
            relation::backend::{native::NativeBudget, worker_client::WorkerVerifier},
            transfer::CompileLimits,
        };
        let network = [1; 32];
        let application = domains::QUIL_TOKEN;
        // A shield of a legacy coin its key owns (the coin is written into
        // the node's store below), signed by that key; no valid native proof.
        let source = legacy_coin(&super::prework_tests::global_view(), key_address(4), 12, 1);
        let shield =
            CanonicalMessageRequest::wrap(super::prework_tests::shield(4, source, 2, true))
                .unwrap();
        let mut truncated = shield.inner_bytes.clone();
        truncated.pop();
        let malformed = CanonicalMessageRequest::wrap(truncated).unwrap();
        let bundle = |requests: Vec<Option<CanonicalMessageRequest>>| {
            CanonicalMessageBundle {
                requests,
                timestamp: 1,
            }
            .to_canonical_bytes()
            .unwrap()
        };
        let policy = TokenPolicy {
            network,
            limits: CompileLimits {
                max_inputs: 2,
                max_outputs: 2,
                max_depth: 3,
            },
            snapshots: SnapshotLimits {
                max_coins: 8,
                max_depth: 3,
                max_nodes: 24,
            },
            native_budget: NativeBudget {
                max_native_bytes: 0,
            },
        };
        let directory = tempfile::tempdir().unwrap();
        let worker = WorkerVerifier::new(
            directory.path().join("absent-worker"),
            1,
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let bare = build_manager(false);
        let manager = build_manager(false)
            .with_token_worker(policy, worker)
            .unwrap();
        legacy_coin(&manager.crdt(), key_address(4), 12, 1);
        let fresh = bundle(vec![Some(shield.clone())]);
        assert_eq!(
            manager.arrival_operations(&global, &application, &fresh),
            Ok(vec![shield.inner_bytes.len()])
        );
        // A shard filter under the application reads the same.
        let shard_filter = quil_forest::encode_shard_bit_path(&application, &[true, false]);
        assert_eq!(
            manager.arrival_operations(&global, &shard_filter, &fresh),
            Ok(vec![shield.inner_bytes.len()])
        );
        assert_eq!(
            manager.arrival_operations(
                &global,
                &application,
                &bundle(vec![Some(shield.clone()), Some(malformed.clone())])
            ),
            Err(ArrivalRefusal::Malformed)
        );
        assert_eq!(
            manager.arrival_operations(&global, &application, b"\x00\x00\x00\x01junk"),
            Err(ArrivalRefusal::Malformed)
        );
        // Without a policy nothing is checked before the worker.
        assert_eq!(
            bare.arrival_operations(
                &global,
                &application,
                &bundle(vec![Some(malformed.clone())])
            ),
            Ok(vec![malformed.inner_bytes.len()])
        );
        // Once the global commit decided it, executing it changes nothing.
        let entry = global_commit::SpendEntry {
            kind: 0x0512,
            tx_id: global_commit::tx_id(&shield.inner_bytes),
            source_frame: 40,
            context: [8; 32],
            root_digest: None,
            consumptions: vec![[20; 32]],
            outputs: vec![[20; 32]],
            escrow_create: None,
            escrow_claim: None,
            fee: 5,
            settlement: None,
        };
        let state = crate::hypergraph_state::HypergraphState::new(global.clone());
        global_commit::commit_entry(
            &state,
            100,
            &application,
            &entry,
            quil_types::execution::ShardPath::WHOLE,
        )
        .unwrap();
        state.commit().unwrap();
        assert_eq!(
            manager.arrival_operations(&global, &application, &fresh),
            Err(ArrivalRefusal::Decided)
        );
        assert_eq!(
            bare.arrival_operations(&global, &application, &fresh),
            Err(ArrivalRefusal::Decided)
        );
        // Other engines' bundles send nothing.
        assert_eq!(
            manager.arrival_operations(&global, &crate::domains::GLOBAL, &fresh),
            Ok(Vec::new())
        );
    }

    /// A legacy coin is shielded once: the global commit marks its source
    /// consumed. Another shield of the same coin (new outputs, so a new
    /// operation id) can then only be rejected by the global commit, which
    /// credits no fee for it. It is refused before any proof work: on
    /// arrival, and by the filter a shard proposal drops settled bundles
    /// with. Otherwise each such shield is verified by the shard and by
    /// every archive (minutes of CPU each) before the global commit rejects
    /// it, free of charge.
    #[cfg(feature = "native-proof")]
    #[test]
    fn a_reshield_of_a_consumed_source_is_refused_before_any_proof_work() {
        use super::prework_tests::{key_address, legacy_coin};
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use crate::token_engine::TYPE_LATTICE_SHIELD;
        use crate::token_intrinsic::{
            dispatch::TokenPolicy, global_commit, spend_entries, spend_relay,
            spent_check::key_image_spent_address, state::SnapshotLimits,
        };
        use quil_lattice_ct::confidential::{
            relation::backend::{native::NativeBudget, worker_client::WorkerVerifier},
            transfer::CompileLimits,
        };
        let network = [1; 32];
        let application = domains::QUIL_TOKEN;
        // Two shields of one legacy coin by its owner (the coin is written
        // into the node's store below), told apart by their outputs only:
        // signed, no valid native proof, which nothing before the proof
        // worker checks.
        let source = legacy_coin(&super::prework_tests::global_view(), key_address(4), 12, 1);
        let shield = |seed: u8| {
            CanonicalMessageRequest::wrap(super::prework_tests::shield(4, source, seed, true))
                .unwrap()
        };
        let (first, second) = (shield(5), shield(7));
        assert_ne!(
            global_commit::tx_id(&first.inner_bytes),
            global_commit::tx_id(&second.inner_bytes)
        );
        let bundle = |request: &CanonicalMessageRequest| {
            CanonicalMessageBundle {
                requests: vec![Some(request.clone())],
                timestamp: 1,
            }
            .to_canonical_bytes()
            .unwrap()
        };
        let policy = TokenPolicy {
            network,
            limits: CompileLimits {
                max_inputs: 2,
                max_outputs: 2,
                max_depth: 3,
            },
            snapshots: SnapshotLimits {
                max_coins: 8,
                max_depth: 3,
                max_nodes: 24,
            },
            native_budget: NativeBudget {
                max_native_bytes: 0,
            },
        };
        let directory = tempfile::tempdir().unwrap();
        let worker = WorkerVerifier::new(
            directory.path().join("absent-worker"),
            1,
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        let manager = build_manager(false)
            .with_token_worker(policy, worker)
            .unwrap();
        let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let state = crate::hypergraph_state::HypergraphState::new(global.clone());
        legacy_coin(&manager.crdt(), key_address(4), 12, 1);
        // Shard frame 40 executed the operation and relayed its spend entry;
        // header 41 carries it into GLOBAL frame `frame`. The fees credited,
        // and the decision recorded.
        let commit = |request: &CanonicalMessageRequest, frame: u64| {
            let entry = spend_entries::spend_entry(
                &network,
                &application,
                TYPE_LATTICE_SHIELD,
                &request.inner_bytes,
                40,
            )
            .unwrap();
            let relay = spend_relay::encode_relay(&[(40, vec![entry.encode().unwrap()])]).unwrap();
            let fees =
                global_commit::materialize_relay(&state, frame, &application, 41, &relay).unwrap();
            state.commit().unwrap();
            state.abort();
            let decision = state
                .get(
                    &crate::global_schema::GLOBAL_INTRINSIC_ADDRESS,
                    &global_commit::decision_address(&application, &entry.tx_id).unwrap(),
                    &crate::hypergraph_state::vertex_adds_discriminator().unwrap(),
                )
                .unwrap()
                .map(|blob| global_commit::decode_decision(&blob).unwrap());
            (fees, decision)
        };
        // New to the network, either shield passes arrival.
        assert!(manager
            .arrival_operations(&global, &application, &bundle(&second))
            .is_ok());
        let (fees, decision) = commit(&first, 100);
        assert_eq!(fees, 2, "the first shield commits and pays its fee");
        assert!(matches!(
            decision,
            Some(Some(global_commit::Decision::Committed { .. }))
        ));
        let marker = key_image_spent_address(&source).unwrap();
        assert!(global_commit::is_consumed(&state, &application, &marker).unwrap());

        // The second shield arrives once the first has committed.
        let arrival = manager.arrival_operations(&global, &application, &bundle(&second));
        let proposal_drops = ExecutionEngineManager::decided_globally(
            global.clone(),
            &application,
            &bundle(&second),
        );
        // What the global commit makes of it once it was verified.
        let (fees, decision) = commit(&second, 101);
        assert_eq!(fees, 0, "a rejected shield credits no fee");
        assert!(
            arrival.is_err() && proposal_drops,
            "VULNERABLE: re-shield of a consumed source passed arrival (arrival_operations: \
             {arrival:?}; dropped by the shard proposal filter: {proposal_drops}); only the \
             global commit refused it, after its proof was verified, crediting fees {fees} \
             ({decision:?})"
        );
    }

    /// A transfer spending a key image the global commit already holds as
    /// spent can only be rejected there: refused on arrival as consumed, and
    /// dropped by the shard proposal filter, before any proof work.
    #[cfg(feature = "native-proof")]
    #[test]
    fn a_respend_of_a_spent_key_image_is_refused_before_any_proof_work() {
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use crate::token_intrinsic::{
            dispatch::TokenPolicy, global_commit, spent, state::SnapshotLimits,
        };
        use quil_lattice_ct::confidential::{
            relation::{
                backend::{native::NativeBudget, worker_client::WorkerVerifier},
                membership::{Node, NODE_BYTES},
            },
            transfer::{
                parameter_context, CompileLimits, Output, Transfer, TransferStatement, MEMO_BYTES,
            },
            AmountOpening, CommitmentKey,
        };
        let network = [1; 32];
        let application = domains::QUIL_TOKEN;
        let context = parameter_context(&network, &application);
        let image = [4; IDENTITY_BYTES];
        let transfer = Transfer {
            statement: TransferStatement {
                network,
                application,
                depth: 1,
                root: Node::from_bytes(&[3; NODE_BYTES]).unwrap(),
                images: vec![image],
                outputs: vec![Output {
                    commitment: CommitmentKey::derive(&context)
                        .commit(10, &AmountOpening::from_seed(&context, &[5; 32])),
                    owner: [5; IDENTITY_BYTES],
                    memo: [6; MEMO_BYTES],
                }],
                fee: 2,
            },
            proof: {
                let mut proof = vec![0; 40];
                proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
                proof
            },
        }
        .encode()
        .unwrap();
        let bundle = CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest::wrap(transfer).unwrap())],
            timestamp: 1,
        }
        .to_canonical_bytes()
        .unwrap();
        let policy = TokenPolicy {
            network,
            limits: CompileLimits {
                max_inputs: 2,
                max_outputs: 2,
                max_depth: 3,
            },
            snapshots: SnapshotLimits {
                max_coins: 8,
                max_depth: 3,
                max_nodes: 24,
            },
            native_budget: NativeBudget {
                max_native_bytes: 0,
            },
        };
        let directory = tempfile::tempdir().unwrap();
        let worker = WorkerVerifier::new(
            directory.path().join("absent-worker"),
            1,
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        let manager = build_manager(false)
            .with_token_worker(policy, worker)
            .unwrap();
        let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        assert!(manager
            .arrival_operations(&global, &application, &bundle)
            .is_ok());
        assert!(!ExecutionEngineManager::decided_globally(
            global.clone(),
            &application,
            &bundle
        ));
        // Another operation spent the image.
        let state = crate::hypergraph_state::HypergraphState::new(global.clone());
        let entry = global_commit::SpendEntry {
            kind: crate::token_engine::TYPE_LATTICE_TRANSACTION,
            tx_id: [7; 32],
            source_frame: 40,
            context,
            root_digest: None,
            consumptions: vec![spent::marker_address(&network, &application, &image).unwrap()],
            outputs: vec![[8; 32]],
            escrow_create: None,
            escrow_claim: None,
            fee: 2,
            settlement: None,
        };
        assert!(matches!(
            global_commit::commit_entry(
                &state,
                100,
                &application,
                &entry,
                quil_types::execution::ShardPath::WHOLE,
            )
            .unwrap(),
            global_commit::Outcome::Committed { .. }
        ));
        state.commit().unwrap();
        assert_eq!(
            manager.arrival_operations(&global, &application, &bundle),
            Err(ArrivalRefusal::Rejected),
            "a re-spend of a spent key image passed arrival"
        );
        assert!(
            ExecutionEngineManager::decided_globally(global.clone(), &application, &bundle),
            "a re-spend of a spent key image passed the shard proposal filter"
        );
    }

    /// As a shard's members fetch: the pending
    /// deliveries were listed block by block up to the per-frame cap, so one
    /// block's backlog, undeliverable while its source frame was missing,
    /// filled the list, and the source frame of an output committed to a later
    /// block was never fetched. Its output stayed undelivered, and nothing
    /// said so.
    #[cfg(feature = "native-proof")]
    #[test]
    fn a_backlogged_block_does_not_hide_a_later_blocks_source_frame() {
        use crate::token_intrinsic::{delivery::MAX_DELIVERIES_PER_FRAME, global_commit};
        let manager = build_manager(true);
        let application = [2u8; 32];
        let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let state = crate::hypergraph_state::HypergraphState::new(global.clone());
        let commit = |n: u32, first_byte: u8, source: &[bool], frame: u64| {
            let mut output = [0u8; 32];
            output[0] = first_byte;
            output[28..].copy_from_slice(&n.to_be_bytes());
            let mut tx_id = [0u8; 32];
            tx_id[..4].copy_from_slice(&n.to_be_bytes());
            let mut marker = tx_id;
            marker[31] = 1;
            let outcome = global_commit::commit_entry(
                &state,
                100,
                &application,
                &global_commit::SpendEntry {
                    kind: 0x0512,
                    tx_id,
                    source_frame: frame,
                    context: [8; 32],
                    root_digest: None,
                    consumptions: vec![marker],
                    outputs: vec![output],
                    escrow_create: None,
                    escrow_claim: None,
                    fee: 0,
                    settlement: None,
                },
                quil_types::execution::ShardPath::from_bits(source),
            )
            .unwrap();
            assert!(
                matches!(outcome, global_commit::Outcome::Committed { .. }),
                "{outcome:?}"
            );
        };
        // One block's backlog, executed on one eight-bit shard...
        for n in 0..MAX_DELIVERIES_PER_FRAME as u32 + 6 {
            commit(n, 0, &[false; 8], 40 + u64::from(n));
        }
        // ...and one output of a later block, executed on another.
        let later_shard = [false, false, false, false, false, false, true, false];
        commit(1000, 2, &later_shard, 900);
        state.commit().unwrap();
        let filter = quil_forest::encode_shard_bit_path(&application, &[false; 6]);
        let sources = manager
            .pending_delivery_sources(global, &filter)
            .unwrap()
            .sources;
        let later = (
            quil_forest::encode_shard_bit_path(&application, &later_shard),
            900,
        );
        assert!(
            sources.contains(&later),
            "the source frame of the output committed to a later block is never fetched, so the \
             output is stranded: the {} frames listed are all one block's backlog",
            sources.len()
        );
    }

    /// Deliveries are taken in order up to the cap; a block whose next item
    /// cannot be built yet is left there, and the other blocks' items still
    /// are.
    #[cfg(feature = "native-proof")]
    #[test]
    fn deliveries_skip_a_waiting_block_and_stop_at_the_cap() {
        use crate::token_intrinsic::delivery::PendingDelivery;
        let item = |block: u64, seq: u64| PendingDelivery {
            escrow: false,
            block,
            seq,
            address: [0; 32],
            source_frame: 0,
            tx_id: [0; 32],
            source_shard: quil_types::execution::ShardPath::from_bits(&[false; 8]),
        };
        let pending = vec![item(1, 0), item(2, 0), item(1, 1), item(2, 1), item(3, 0)];
        let mut built = Vec::new();
        let deliveries = take_deliverable(pending, 2, |item| {
            built.push((item.block, item.seq));
            Ok((item.block != 1).then(|| vec![item.block as u8, item.seq as u8]))
        })
        .unwrap();
        assert_eq!(deliveries, vec![vec![2, 0], vec![2, 1]]);
        assert_eq!(
            built,
            vec![(1, 0), (2, 0), (2, 1)],
            "block 1's later item was tried out of sequence, or the cap was passed"
        );
    }

    /// A bundle is done once the global commit has decided each of its
    /// operations, whichever shard relayed them; one holding anything else is
    /// never treated as done.
    #[cfg(feature = "native-proof")]
    #[test]
    fn a_bundle_is_done_once_every_operation_is_decided_globally() {
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use crate::token_intrinsic::global_commit;
        let app = crate::domains::QUIL_TOKEN;
        let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let op = |tp: u32, tag: u8| CanonicalMessageRequest {
            inner_type_prefix: tp,
            inner_bytes: [tp.to_be_bytes().as_slice(), &[tag; 40]].concat(),
        };
        let bundle = |requests: Vec<Option<CanonicalMessageRequest>>| {
            CanonicalMessageBundle {
                requests,
                timestamp: 1,
            }
            .to_canonical_bytes()
            .unwrap()
        };
        let (first, second) = (op(0x0512, 1), op(0x0512, 2));
        let both = bundle(vec![Some(first.clone()), Some(second.clone())]);
        let decide = |request: &CanonicalMessageRequest, marker: u8| {
            let entry = global_commit::SpendEntry {
                kind: request.inner_type_prefix,
                tx_id: global_commit::tx_id(&request.inner_bytes),
                source_frame: 40,
                context: [8; 32],
                root_digest: None,
                consumptions: vec![[marker; 32]],
                outputs: vec![[marker; 32]],
                escrow_create: None,
                escrow_claim: None,
                fee: 5,
                settlement: None,
            };
            let state = crate::hypergraph_state::HypergraphState::new(global.clone());
            global_commit::commit_entry(
                &state,
                100,
                &app,
                &entry,
                quil_types::execution::ShardPath::WHOLE,
            )
            .unwrap();
            state.commit().unwrap();
        };
        assert!(!ExecutionEngineManager::decided_globally(
            global.clone(),
            &app,
            &both
        ));
        decide(&first, 20);
        assert!(
            !ExecutionEngineManager::decided_globally(global.clone(), &app, &both),
            "one still undecided"
        );
        assert!(ExecutionEngineManager::decided_globally(
            global.clone(),
            &app,
            &bundle(vec![Some(first.clone())])
        ));
        decide(&second, 21);
        assert!(ExecutionEngineManager::decided_globally(
            global.clone(),
            &app,
            &both
        ));
        // Anything the global commit does not decide keeps the bundle pending.
        let mixed = bundle(vec![Some(first.clone()), Some(op(0x0404, 3))]);
        assert!(!ExecutionEngineManager::decided_globally(
            global.clone(),
            &app,
            &mixed
        ));
        assert!(!ExecutionEngineManager::decided_globally(
            global.clone(),
            &app,
            &bundle(vec![Some(first), None])
        ));
        assert!(!ExecutionEngineManager::decided_globally(
            global.clone(),
            &app,
            &bundle(Vec::new())
        ));
        assert!(
            !ExecutionEngineManager::decided_globally(global.clone(), &[7; 32], &both),
            "decisions are per application"
        );
        // A shard engine passes its filter, the application plus its bit path.
        let shard_filter = quil_forest::encode_shard_bit_path(&app, &[true, false, true]);
        assert!(
            ExecutionEngineManager::decided_globally(global.clone(), &shard_filter, &both),
            "a shard filter names its application"
        );
        assert!(!ExecutionEngineManager::decided_globally(
            global.clone(),
            &app[..31],
            &both
        ));
        assert!(!ExecutionEngineManager::decided_globally(
            global,
            &app,
            b"not a bundle"
        ));
    }

    fn build_manager(include_global: bool) -> ExecutionEngineManager {
        let inclusion_prover: Arc<dyn InclusionProver> = Arc::new(NoopInclusionProver);
        let mem_store: Arc<dyn quil_types::store::HypergraphStore> = Arc::new(MemStore::new());
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            mem_store,
            inclusion_prover.clone(),
        ));
        let stubs = crate::testing::NoopExecutionCrypto::new();
        let hg_resolver: Arc<dyn crate::hypergraph_intrinsic::HypergraphConfigResolver> =
            Arc::new(crate::testing::NoopHypergraphConfigResolver);
        ExecutionEngineManager::new(
            inclusion_prover,
            stubs.key_manager.clone(),
            crdt,
            stubs.circuit_compiler,
            stubs.clock_store,
            hg_resolver,
            include_global,
        )
    }

    /// GLOBAL execution switches to exact state sizes before the first frame
    /// of their epoch, rebuilding the sizes once: an overwrite counted in
    /// full before it is corrected, a frame below it keeps the legacy rule,
    /// and later overwrites count only their size change.
    #[test]
    fn exact_state_sizes_rebuild_before_the_first_frame_of_their_epoch() {
        quil_types::consensus::set_exact_state_size_epoch_for_thread(Some(2));
        let first = 2 * quil_types::consensus::epoch_length_frames();
        let manager = build_manager(true);
        let crdt = manager.crdt();
        let vertex = quil_hypergraph::Location {
            app_address: [0x42; 32],
            data_address: [0x07; 32],
        };
        crdt.add_vertex(&vertex, b"original").unwrap();
        crdt.add_vertex(&vertex, b"replaced").unwrap();
        manager.commit_frame(first - 2).unwrap();
        manager.prepare_exact_state_sizes(first - 1).unwrap();
        assert!(!crdt.exact_sizes(), "below the epoch");
        assert_eq!(crdt.total_size(), BigInt::from(16), "legacy rule");
        manager.prepare_exact_state_sizes(first).unwrap();
        assert!(crdt.exact_sizes());
        assert_eq!(crdt.total_size(), BigInt::from(8), "rebuilt from the leaf");
        crdt.add_vertex(&vertex, b"twelve bytes").unwrap();
        assert_eq!(crdt.total_size(), BigInt::from(12));
        manager.prepare_exact_state_sizes(first + 1).unwrap();
        assert_eq!(crdt.total_size(), BigInt::from(12), "rebuilds once");
        quil_types::consensus::set_exact_state_size_epoch_for_thread(None);
    }

    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn app_history_commits_staged_accumulator_and_reopens_after_failed_write_retry() {
        use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        use crate::token_intrinsic::{accumulator_header, roots, settlement_record, spend_relay};
        use quil_lattice_ct::confidential::{
            transfer::{network_identifier, parameter_context, Output},
            AmountOpening, CommitmentKey,
        };
        use quil_types::store::ClockStore;

        let directory = tempfile::tempdir().unwrap();
        let application = domains::QUIL_TOKEN;
        let network = network_identifier(crate::pricing::MAINNET_NETWORK);
        let context = parameter_context(&network, &application);
        let settlements = vec![settlement_record::SettlementEntry {
            receipt: [1; 32],
            parameter_context: context,
            destination: [2; 32],
            context: [3; 32],
            settlement: 41,
            payment_address: [0; 32],
            payment: 0,
            claimant: [0; 32],
        }];
        // Spend framing is opaque at this persistence boundary.
        let spends = vec![vec![4; 24]];
        let expected_report;
        {
            let db = quil_store::RocksDb::open(directory.path()).unwrap();
            let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
            let prover = Arc::new(NoopInclusionProver);
            let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                store.clone(),
                prover.clone(),
            ));
            crdt.set_forest(quil_forest::Forest::with_namespace(
                db.inner(),
                quil_store::FOREST_NAMESPACE,
            ));
            let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
            let stubs = crate::testing::NoopExecutionCrypto::new();
            let manager = ExecutionEngineManager::new(
                prover,
                stubs.key_manager,
                crdt.clone(),
                stubs.circuit_compiler,
                clock.clone(),
                Arc::new(crate::testing::NoopHypergraphConfigResolver),
                false,
            );
            let state = HypergraphState::new(crdt.clone());
            let empty_snapshot = crdt.capture_committed_shard(&application).unwrap();
            assert!(manager
                .snapshot_accumulator_report(empty_snapshot.records.as_ref(), &application, 0)
                .unwrap()
                .is_empty());
            assert!(
                manager
                    .snapshot_accumulator_report(store.as_ref(), &application, 0)
                    .is_err(),
                "a live-store adapter cannot supply isolated recovery reads"
            );
            let output = Output {
                owner: [7; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context)
                    .commit(7, &AmountOpening::from_seed(&context, &[8; 32])),
                memo: [0; 1115],
            };
            let limits = crate::token_intrinsic::state::SnapshotLimits {
                max_coins: 8,
                max_depth: 32,
                max_nodes: 1 << 12,
            };
            let (address, tree) = roots::stage_coin(
                &state,
                &network,
                &application,
                &context,
                1,
                &output,
                &mut Default::default(),
                limits,
            )
            .unwrap();
            state
                .set(
                    &application,
                    &address,
                    &vertex_adds_discriminator().unwrap(),
                    1,
                    quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
                )
                .unwrap();
            roots::refresh_root(&state, &network, &application, limits).unwrap();
            state.commit().unwrap();
            state.abort();
            expected_report = manager.shard_accumulator_report(&application, 0).unwrap();
            assert!(
                !expected_report.is_empty(),
                "the report must include uncommitted coin state"
            );
            assert!(
                manager
                    .snapshot_accumulator_report(empty_snapshot.records.as_ref(), &application, 0)
                    .unwrap()
                    .is_empty(),
                "snapshot reports must not include staged coins or the private summary"
            );

            // Malformed history cannot commit the already-staged state/cursor.
            assert!(manager
                .commit_frame_with_app_history(1, &application, 123, &settlements, &[vec![]], 0)
                .is_err());
            assert_eq!(
                manager.read_app_materialized_cursor(&application).unwrap(),
                0
            );
            store.fail_commit_for_test(true);
            assert!(manager
                .commit_frame_with_app_history(1, &application, 123, &settlements, &spends, 0)
                .is_err());
            assert_eq!(
                manager.read_app_materialized_cursor(&application).unwrap(),
                0
            );
            assert!(clock
                .get_shard_frame_fee_total(&application, 1)
                .unwrap()
                .is_none());
            assert!(clock
                .get_shard_frame_settlements(&application, 1)
                .unwrap()
                .is_none());
            assert!(clock
                .get_shard_frame_spends(&application, 1)
                .unwrap()
                .is_none());
            assert!(clock
                .get_shard_frame_accumulator(&application, 1)
                .unwrap()
                .is_none());
            assert!(clock
                .get_shard_accumulator_report(
                    &application,
                    &accumulator_header::report_digest(&expected_report)
                )
                .unwrap()
                .is_none());
            store.fail_commit_for_test(false);
            assert_eq!(
                manager
                    .commit_frame_with_app_history(1, &application, 123, &settlements, &spends, 0)
                    .unwrap(),
                expected_report
            );
            assert_eq!(
                manager.shard_accumulator_report(&application, 0).unwrap(),
                expected_report,
                "the report calculated before commit must match committed state"
            );
            let committed = crdt.capture_committed_shard(&application).unwrap();
            assert_eq!(
                manager
                    .snapshot_accumulator_report(committed.records.as_ref(), &application, 0)
                    .unwrap(),
                expected_report
            );
            assert!(
                manager
                    .snapshot_accumulator_report(empty_snapshot.records.as_ref(), &application, 0)
                    .unwrap()
                    .is_empty(),
                "an earlier snapshot stays empty after the live commit"
            );
            state
                .set(
                    &application,
                    &crate::token_intrinsic::state::BLOCK_SUMMARY_ADDRESS,
                    &vertex_adds_discriminator().unwrap(),
                    2,
                    b"broken private summary".to_vec(),
                )
                .unwrap();
            state.commit().unwrap();
            state.abort();
            assert!(manager.shard_accumulator_report(&application, 0).is_err());
            assert_eq!(
                manager
                    .snapshot_accumulator_report(committed.records.as_ref(), &application, 0)
                    .unwrap(),
                expected_report,
                "recovery reads block records and ignores live private-summary corruption"
            );
        }
        // Every previous handle is dropped: reopen the real database, with no
        // outflow cache, and recover both the state and all future-header inputs.
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = quil_hypergraph::HypergraphCrdt::new(store, Arc::new(NoopInclusionProver));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        assert_eq!(
            crdt.read_frame_cursor(&quil_store::encoding::consensus_materialized_cursor_key(
                &application
            ))
            .unwrap(),
            1
        );
        let clock = quil_store::RocksClockStore::new(db.inner());
        assert_eq!(
            clock.get_shard_frame_fee_total(&application, 1).unwrap(),
            Some(123)
        );
        assert_eq!(
            settlement_record::decode_entries(
                &clock
                    .get_shard_frame_settlements(&application, 1)
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            settlements
        );
        assert_eq!(
            spend_relay::decode_frame_entries(
                &clock
                    .get_shard_frame_spends(&application, 1)
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            spends
        );
        let digest = clock
            .get_shard_frame_accumulator(&application, 1)
            .unwrap()
            .unwrap();
        assert_eq!(digest, accumulator_header::report_digest(&expected_report));
        assert_eq!(
            clock
                .get_shard_accumulator_report(&application, &digest)
                .unwrap(),
            Some(expected_report.clone())
        );
        let state = HypergraphState::new(Arc::new(crdt));
        assert_eq!(
            crate::token_intrinsic::shard_accumulator::shard_report(
                &state,
                &network,
                &application,
                &[],
                false
            )
            .unwrap()
            .unwrap()
            .encode()
            .unwrap(),
            expected_report
        );
    }

    // =================================================================
    // Engine registry
    // =================================================================

    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn synced_shard_rebuilds_missing_and_stale_summaries_from_block_records() {
        use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        use crate::token_intrinsic::{coin_blocks, roots, state};
        use quil_lattice_ct::confidential::{
            coin_tree::Frontier,
            transfer::{network_identifier, parameter_context},
            AmountOpening, CommitmentKey,
        };
        let source = build_manager(false);
        let recovered = build_manager(false);
        let application = domains::QUIL_TOKEN;
        let network = network_identifier(crate::pricing::MAINNET_NETWORK);
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let disc = vertex_adds_discriminator().unwrap();
        let shard = [false, false, false];
        let filter = quil_forest::encode_shard_bit_path(&application, &shard);
        let before = HypergraphState::new(source.crdt());
        let imported = HypergraphState::new(recovered.crdt());
        let mut summary = roots::BlockSummary::default();
        let mut saved = Vec::new();
        // Include a layer newer than the private (default width-six) setting,
        // and stale data outside this shard, as after reassignment or a split.
        for (seed, width, path) in [(1u8, 6, 0), (2, 8, 1), (3, 8, 128)] {
            let block = coin_blocks::block_id(width, path).unwrap();
            let mut frontier =
                Frontier::new(&context, usize::from(coin_blocks::SUBTREE_BITS)).unwrap();
            let commitment = key.commit(
                u128::from(seed),
                &AmountOpening::from_seed(&context, &[seed; 32]),
            );
            frontier
                .append(&[seed; IDENTITY_BYTES], &commitment)
                .unwrap();
            let root = frontier
                .root_at_depth(usize::from(coin_blocks::SUBTREE_BITS))
                .unwrap()
                .root;
            summary.put(block, frontier.count(), root.clone()).unwrap();
            for (tag, bytes) in [
                (state::BLOCK_FRONTIER_TAG, frontier.encode()),
                (state::BLOCK_ROOT_TAG, root.to_bytes().to_vec()),
            ] {
                let address = state::block_record_address(tag, block);
                before
                    .set(&application, &address, &disc, 0, bytes.clone())
                    .unwrap();
                imported
                    .set(&application, &address, &disc, 0, bytes.clone())
                    .unwrap();
                saved.push((address, bytes));
            }
        }
        before
            .set(
                &application,
                &state::BLOCK_SUMMARY_ADDRESS,
                &disc,
                0,
                summary.encode(),
            )
            .unwrap();
        before.commit().unwrap();
        imported.commit().unwrap();
        imported.abort();
        let expected = source.shard_accumulator_report(&filter, 0).unwrap();
        assert!(!expected.is_empty());
        assert!(
            recovered
                .shard_accumulator_report(&filter, 0)
                .unwrap()
                .is_empty(),
            "imported block data alone did not populate the private summary"
        );
        recovered.rebuild_block_summary_before_report(&filter);
        assert_eq!(
            recovered
                .commit_frame_with_app_history(76, &filter, 0, &[], &[], 0)
                .unwrap(),
            expected,
            "the first replay after sync must record the inherited coins"
        );
        assert_eq!(
            roots::block_summary(&imported, &application)
                .unwrap()
                .blocks
                .len(),
            2,
            "the rebuilt private summary excludes stale data outside the covered range"
        );

        // A nonempty summary from the old allocation must be rebuilt as well.
        summary
            .blocks
            .retain(|(block, _, _)| !coin_blocks::shard_owns_block(&shard, *block));
        imported
            .set(
                &application,
                &state::BLOCK_SUMMARY_ADDRESS,
                &disc,
                0,
                summary.encode(),
            )
            .unwrap();
        imported.commit().unwrap();
        imported.abort();
        assert!(recovered
            .shard_accumulator_report(&filter, 0)
            .unwrap()
            .is_empty());
        recovered.rebuild_block_summary_before_report(&filter);
        assert_eq!(
            recovered.shard_accumulator_report(&filter, 0).unwrap(),
            expected
        );

        // A damaged import must fail before replacing the summary. Retrying
        // after its block is repaired needs no second invalidation signal.
        let (address, bytes) = saved
            .iter()
            .find(|(address, _)| {
                *address
                    == state::block_record_address(
                        state::BLOCK_ROOT_TAG,
                        coin_blocks::block_id(6, 0).unwrap(),
                    )
            })
            .unwrap();
        let previous = roots::block_summary(&imported, &application)
            .unwrap()
            .encode();
        imported
            .set(
                &application,
                address,
                &disc,
                0,
                quil_lattice_ct::confidential::relation::membership::Node::zero()
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap();
        imported.commit().unwrap();
        imported.abort();
        recovered.rebuild_block_summary_before_report(&filter);
        assert!(recovered.shard_accumulator_report(&filter, 0).is_err());
        assert_eq!(
            roots::block_summary(&imported, &application)
                .unwrap()
                .encode(),
            previous
        );
        imported
            .set(&application, address, &disc, 0, bytes.clone())
            .unwrap();
        imported.commit().unwrap();
        imported.abort();
        assert_eq!(
            recovered.shard_accumulator_report(&filter, 0).unwrap(),
            expected
        );
    }

    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn rebuilding_a_shard_without_coin_blocks_does_not_create_token_metadata() {
        use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        use crate::token_intrinsic::state::{BLOCK_SUMMARY_ADDRESS, ROOT_ADDRESS};
        let manager = build_manager(false);
        let application = [99; 32];
        let filter = quil_forest::encode_shard_bit_path(&application, &[true, false, true]);
        manager.rebuild_block_summary_before_report(&filter);
        assert!(manager
            .shard_accumulator_report(&filter, 0)
            .unwrap()
            .is_empty());
        let state = HypergraphState::new(manager.crdt());
        let disc = vertex_adds_discriminator().unwrap();
        assert!(state
            .get(&application, &BLOCK_SUMMARY_ADDRESS, &disc)
            .unwrap()
            .is_none());
        assert!(state
            .get(&application, &ROOT_ADDRESS, &disc)
            .unwrap()
            .is_none());
    }

    /// The frames of a shard holding the whole application are stored under
    /// the bare application address, so that is the filter a delivery looks
    /// its operation up by — not the empty path's own encoding, which names
    /// no stored frame and would stall every delivery.
    #[cfg(feature = "native-proof")]
    #[test]
    fn the_executing_filter_of_a_whole_application_is_its_address() {
        let application = [3u8; 32];
        assert_eq!(
            super::executing_filter(&application, &[]),
            application.to_vec()
        );
        for shard in [vec![false], vec![true, false, true]] {
            let filter = super::executing_filter(&application, &shard);
            assert_eq!(
                quil_forest::decode_shard_filter_or_root(&filter, 32),
                Some((application.to_vec(), shard.clone())),
            );
        }
        // Both forms decode to the same application, and only the bare one is
        // what a whole-application shard files its frames under.
        assert_ne!(
            super::executing_filter(&application, &[]),
            quil_forest::encode_shard_bit_path(&application, &[])
        );
    }

    /// A bundle whose operations all commit through the global frame must be
    /// priced at the global venue's vote of one — the price the wallet was
    /// quoted. A bundle carrying anything that executes in the app venue keeps
    /// the app vote, the higher price.
    #[cfg(feature = "native-proof")]
    #[test]
    fn a_bundle_that_commits_globally_is_recognised_for_global_pricing() {
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use quil_lattice_ct::confidential::{
            relation::membership::{Node, NODE_BYTES},
            transfer::{parameter_context, Output, Transfer, TransferStatement, MEMO_BYTES},
            AmountOpening, CommitmentKey,
        };
        let network = [1; 32];
        let application = domains::QUIL_TOKEN;
        let context = parameter_context(&network, &application);
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let transfer = Transfer {
            statement: TransferStatement {
                network,
                application,
                depth: 1,
                root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(),
                images: vec![[5; IDENTITY_BYTES]],
                fee: 7,
                outputs: vec![Output {
                    commitment: CommitmentKey::derive(&context)
                        .commit(10, &AmountOpening::from_seed(&context, &[2; 32])),
                    owner: [3; IDENTITY_BYTES],
                    memo: [4; MEMO_BYTES],
                }],
            },
            proof,
        }
        .encode()
        .unwrap();
        // Something that is not relayed: an app-venue operation of another kind.
        let mut app_venue = vec![0u8; 16];
        app_venue[..4].copy_from_slice(&0x0999u32.to_be_bytes());
        assert!(!crate::token_intrinsic::spend_entries::commits_globally(
            &application,
            0x0999
        ));
        let bundle = |requests: Vec<Vec<u8>>| {
            CanonicalMessageBundle {
                requests: requests
                    .into_iter()
                    .map(|r| Some(CanonicalMessageRequest::wrap(r).unwrap()))
                    .collect(),
                timestamp: 0,
            }
            .to_canonical_bytes()
            .unwrap()
        };
        let manager = build_manager(true);

        assert!(manager.message_commits_globally(&application, &bundle(vec![transfer.clone()])));
        // A single request, not wrapped in a bundle, is the wallet's own shape.
        let single = CanonicalMessageRequest::wrap(transfer.clone())
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        assert!(manager.message_commits_globally(&application, &single));
        // Mixed, empty and malformed stay on the app vote.
        assert!(!manager.message_commits_globally(
            &application,
            &bundle(vec![transfer.clone(), app_venue.clone()])
        ));
        assert!(!manager.message_commits_globally(&application, &bundle(vec![])));
        assert!(!manager.message_commits_globally(&application, &[0, 1]));
    }

    /// Fees are credited only for what the executing venue admitted: QUIL
    /// operations on the QUIL application, a consumed settlement claim on any
    /// other application, and nothing for bundles the global intrinsic skips.
    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn fee_credit_counts_only_what_the_executing_venue_admits() {
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use crate::token_intrinsic::settlement_claim::SettlementClaim;
        use quil_lattice_ct::confidential::{
            relation::membership::{Node, NODE_BYTES},
            transfer::{parameter_context, Output, Transfer, TransferStatement, MEMO_BYTES},
            AmountOpening, CommitmentKey,
        };
        let network = [1; 32];
        let context = parameter_context(&network, &domains::QUIL_TOKEN);
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let transfer = Transfer {
            statement: TransferStatement {
                network,
                application: domains::QUIL_TOKEN,
                depth: 1,
                root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(),
                images: vec![[5; IDENTITY_BYTES]],
                fee: 7,
                outputs: vec![Output {
                    commitment: CommitmentKey::derive(&context)
                        .commit(10, &AmountOpening::from_seed(&context, &[2; 32])),
                    owner: [3; IDENTITY_BYTES],
                    memo: [4; MEMO_BYTES],
                }],
            },
            proof,
        }
        .encode()
        .unwrap();
        let app = [0x44; 32];
        let claim = SettlementClaim {
            network,
            application: app,
            cited_global_frame: 1,
            global_root: [0; 32],
            receipt: [9; 32],
            settlement: 500,
            context: [8; 32],
            payment_address: [0; 32],
            payment: 0,
            forest_proof: vec![1; 8],
            claimant_key_type: 0,
            claimant_public_key: Vec::new(),
            claimant_signature: Vec::new(),
        }
        .encode()
        .unwrap();
        let bundle = |requests: Vec<Vec<u8>>| {
            CanonicalMessageBundle {
                requests: requests
                    .into_iter()
                    .map(|r| Some(CanonicalMessageRequest::wrap(r).unwrap()))
                    .collect(),
                timestamp: 0,
            }
            .to_canonical_bytes()
            .unwrap()
        };
        let manager = build_manager(true);
        let mixed = bundle(vec![claim.clone(), transfer.clone()]);
        // Native-proof builds relay the transfer and credit its fee only at
        // global commit. Without native proofs nothing is relayed, so the
        // QUIL venue's fee helper counts the transfer's fee locally.
        #[cfg(feature = "native-proof")]
        let expected_transfer_fee = 0;
        #[cfg(not(feature = "native-proof"))]
        let expected_transfer_fee = 7;
        assert_eq!(
            manager
                .message_token_fees(&domains::QUIL_TOKEN, &mixed)
                .unwrap(),
            expected_transfer_fee
        );
        // An unverified settlement claim never contributes QUIL-venue fees.
        assert_eq!(
            manager
                .message_token_fees(&domains::QUIL_TOKEN, &bundle(vec![claim.clone()]))
                .unwrap(),
            0
        );
        // Exercise single-request framing as well as a mixed bundle.
        let single = CanonicalMessageRequest::wrap(transfer.clone())
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        assert_eq!(
            manager
                .message_token_fees(&domains::QUIL_TOKEN, &single)
                .unwrap(),
            expected_transfer_fee
        );
        // Another application: only the claim it verified, never QUIL fees it skipped.
        assert_eq!(manager.message_token_fees(&app, &mixed).unwrap(), 500);
        assert_eq!(
            manager
                .message_token_fees(&app, &bundle(vec![transfer.clone()]))
                .unwrap(),
            0
        );
        // The global intrinsic credits nothing for application operations it skips.
        assert_eq!(
            manager
                .message_token_fees(&domains::GLOBAL, &mixed)
                .unwrap(),
            0
        );
    }

    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn manager_preserves_token_cost_in_mixed_bundles() {
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use quil_lattice_ct::confidential::{
            relation::membership::{Node, NODE_BYTES},
            transfer::{parameter_context, Output, Transfer, TransferStatement, MEMO_BYTES},
            AmountOpening, CommitmentKey,
        };
        let network = [1; 32];
        let application = domains::QUIL_TOKEN;
        let context = parameter_context(&network, &application);
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        // Structural fixture: framing only, no valid proof.
        let inner = Transfer {
            statement: TransferStatement {
                network,
                application,
                depth: 1,
                root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(),
                images: vec![[5; IDENTITY_BYTES]],
                fee: 7,
                outputs: vec![Output {
                    commitment: CommitmentKey::derive(&context)
                        .commit(10, &AmountOpening::from_seed(&context, &[2; 32])),
                    owner: [3; IDENTITY_BYTES],
                    memo: [4; MEMO_BYTES],
                }],
            },
            proof,
        }
        .encode()
        .unwrap();
        let request = CanonicalMessageRequest::wrap(inner.clone()).unwrap();
        let other =
            CanonicalMessageRequest::wrap(vec![0x00, 0x04, 0x04, 0x00, 1, 2, 3, 4]).unwrap();
        let bundle = |requests: Vec<CanonicalMessageRequest>| {
            CanonicalMessageBundle {
                requests: requests.into_iter().map(Some).collect(),
                timestamp: 0,
            }
            .to_canonical_bytes()
            .unwrap()
        };
        for include_global in [true, false] {
            let manager = build_manager(include_global);
            // Token cost is the staged state growth, not the payload length.
            let expected =
                BigInt::from(crate::token_intrinsic::cost::state_growth(&inner).unwrap());
            assert!(expected > BigInt::from(0));
            assert_eq!(
                manager
                    .get_cost(&request.to_canonical_bytes().unwrap())
                    .unwrap(),
                expected
            );
            assert_eq!(
                manager
                    .get_cost(&bundle(vec![request.clone(), request.clone()]))
                    .unwrap(),
                &expected * 2u8
            );
            // Non-token requests retain their current cost, in either order.
            assert_eq!(
                manager
                    .get_cost(&other.to_canonical_bytes().unwrap())
                    .unwrap(),
                BigInt::from(0)
            );
            assert_eq!(
                manager
                    .get_cost(&bundle(vec![request.clone(), other.clone()]))
                    .unwrap(),
                expected
            );
            assert_eq!(
                manager
                    .get_cost(&bundle(vec![other.clone(), request.clone()]))
                    .unwrap(),
                expected
            );
            assert_eq!(
                manager
                    .get_cost(&bundle(vec![
                        request.clone(),
                        other.clone(),
                        request.clone()
                    ]))
                    .unwrap(),
                &expected * 2u8
            );
            let with_empty_slots = CanonicalMessageBundle {
                requests: vec![None, Some(other.clone()), Some(request.clone()), None],
                timestamp: 0,
            }
            .to_canonical_bytes()
            .unwrap();
            assert_eq!(manager.get_cost(&with_empty_slots).unwrap(), expected);
            let mut malformed = bundle(vec![request.clone()]);
            malformed.pop();
            assert!(manager.get_cost(&malformed).is_err());
            assert_eq!(
                manager.get_cost(&bundle(Vec::new())).unwrap(),
                BigInt::from(0)
            );
            assert_eq!(manager.get_cost(b"\x00\x00").unwrap(), BigInt::from(0));
        }
    }

    #[cfg(feature = "native-proof")]
    /// What arrival refuses, a frame refuses the same way, for every type the
    /// gate reads: dispatch's first step is the same pure check, which takes
    /// no state, clock or frame.
    #[test]
    fn what_arrival_refuses_a_frame_refuses_the_same_way() {
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use crate::token_engine::{
            TYPE_LATTICE_MINT, TYPE_LATTICE_MINT_CLAIM, TYPE_LATTICE_PENDING,
            TYPE_LATTICE_PENDING_CLAIM, TYPE_LATTICE_SETTLEMENT, TYPE_LATTICE_SHIELD,
            TYPE_LATTICE_TRANSACTION,
        };
        use crate::token_intrinsic::{dispatch::TokenPolicy, spend_entries};
        use quil_lattice_ct::confidential::{
            relation::backend::worker_client::WorkerVerifier,
            shield::{Shield, ShieldStatement},
            transfer::{parameter_context, Output, MEMO_BYTES},
            AmountOpening, CommitmentKey,
        };
        use quil_types::execution::{FrameExecutionContext, ShardPath, Venue};
        let policy = TokenPolicy::for_network(0);
        let directory = tempfile::tempdir().unwrap();
        let worker = WorkerVerifier::new(
            directory.path().join("absent-worker"),
            1,
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        let manager = build_manager(false)
            .with_token_worker(policy, worker)
            .unwrap();
        let bundle = |requests: &[&[u8]]| {
            let requests = requests
                .iter()
                .map(|inner| {
                    Some(CanonicalMessageRequest {
                        inner_type_prefix: u32::from_be_bytes(inner[..4].try_into().unwrap()),
                        inner_bytes: inner.to_vec(),
                    })
                })
                .collect();
            CanonicalMessageBundle {
                requests,
                timestamp: 1,
            }
            .to_canonical_bytes()
            .unwrap()
        };
        let state = crate::hypergraph_state::HypergraphState::new(manager.crdt());
        let clock = crate::testing::NoopExecutionCrypto::new().clock_store;
        let context = FrameExecutionContext {
            frame_number: 7,
            finalized_global_frame: Some(913),
            shard: ShardPath::WHOLE,
            venue: Some(Venue::Application),
        };
        // Refused by the check, by a frame's dispatch with the same error, and
        // on the QUIL token by the whole execution path.
        let refused = |application: &[u8; 32], operation: &[u8], tp: u32, name: &str| {
            assert!(spend_entries::commits_globally(application, tp), "{name}");
            let check = policy
                .preflight(application, operation, tp)
                .unwrap_err()
                .to_string();
            let frame = policy
                .dispatch_for_commit(
                    &state,
                    context,
                    clock.as_ref(),
                    application,
                    operation,
                    tp,
                    None,
                    None,
                )
                .unwrap_err()
                .to_string();
            assert_eq!(frame, check, "{name}");
            if application == &domains::QUIL_TOKEN {
                let data = bundle(&[operation]);
                assert!(
                    manager.refused_before_native_work(application, &data),
                    "{name}"
                );
                assert!(
                    manager
                        .process_message_with_context(context, &BigInt::from(0), application, &data)
                        .is_err(),
                    "{name}"
                );
            }
        };
        let quil = domains::QUIL_TOKEN;
        let custom = [7; 32];
        let types = [
            ("transfer", quil, TYPE_LATTICE_TRANSACTION),
            ("pending", quil, TYPE_LATTICE_PENDING),
            ("pending claim", quil, TYPE_LATTICE_PENDING_CLAIM),
            ("shield", quil, TYPE_LATTICE_SHIELD),
            ("mint claim", quil, TYPE_LATTICE_MINT_CLAIM),
            ("settlement", quil, TYPE_LATTICE_SETTLEMENT),
            ("custom mint", custom, TYPE_LATTICE_MINT),
        ];
        for (name, application, tp) in types {
            let mut junk = tp.to_be_bytes().to_vec();
            refused(&application, &junk, tp, name);
            junk.resize(4096, 0x44);
            refused(&application, &junk, tp, name);
        }
        // The QUIL mint executes elsewhere, so the gate does not read it.
        let mint = TYPE_LATTICE_MINT.to_be_bytes().to_vec();
        assert!(!spend_entries::commits_globally(&quil, TYPE_LATTICE_MINT));
        assert!(!manager.refused_before_native_work(&quil, &bundle(&[&mint])));
        // Every way a shield can fail the check, and one that passes it.
        let context_bytes = parameter_context(&policy.network, &quil);
        let key = CommitmentKey::derive(&context_bytes);
        let opening = AmountOpening::from_seed(&context_bytes, &[2; 32]);
        let output = Output {
            commitment: key.commit(10, &opening),
            owner: [5; IDENTITY_BYTES],
            memo: [6; MEMO_BYTES],
        };
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let formed = Shield {
            statement: ShieldStatement {
                network: policy.network,
                application: quil,
                transparent_address: [3; 32],
                owner_public_key: [4; 57],
                amount: 12,
                fee: 2,
                outputs: vec![output.clone()],
            },
            signature: [0; 114],
            proof,
        };
        let good = formed.encode().unwrap();
        policy.preflight(&quil, &good, TYPE_LATTICE_SHIELD).unwrap();
        assert!(!manager.refused_before_native_work(&quil, &bundle(&[&good])));
        let shield = TYPE_LATTICE_SHIELD;
        refused(&quil, &good[..good.len() - 1], shield, "truncated shield");
        let mut other = formed.clone();
        other.statement.network = [9; 32];
        refused(&quil, &other.encode().unwrap(), shield, "other network");
        let mut version = good.clone();
        version[11] ^= 0xff;
        refused(&quil, &version, shield, "unknown version");
        let mut wide = formed.clone();
        wide.statement.outputs = vec![output; policy.limits.max_outputs + 1];
        refused(&quil, &wide.encode().unwrap(), shield, "too many outputs");
        // One operation that fails it sinks the bundle, in either place.
        let junk = shield.to_be_bytes().to_vec();
        let mixed = bundle(&[&junk, &good]);
        assert!(manager.refused_before_native_work(&quil, &mixed));
        assert!(manager.refused_before_native_work(&quil, &bundle(&[&good, &junk])));
        let execute = |data: &[u8]| {
            manager
                .process_message_with_context(context, &BigInt::from(0), &quil, data)
                .unwrap_err()
                .to_string()
        };
        assert_eq!(execute(&mixed), execute(&bundle(&[&junk])));
    }

    #[test]
    fn manager_token_worker_configures_both_venues_and_rejects_missing_engine() {
        use crate::token_intrinsic::{dispatch::TokenPolicy, state::SnapshotLimits};
        use quil_lattice_ct::confidential::{
            relation::backend::{native::NativeBudget, worker_client::WorkerVerifier},
            shield::{Shield, ShieldStatement},
            transfer::{parameter_context, CompileLimits, Output, MEMO_BYTES},
            AmountOpening, CommitmentKey,
        };
        let network = [1; 32];
        let application = domains::QUIL_TOKEN;
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[2; 32]);
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        // Structural validation only: no valid signature or native proof.
        let tx = Shield {
            statement: ShieldStatement {
                network,
                application,
                transparent_address: [3; 32],
                owner_public_key: [4; 57],
                amount: 12,
                fee: 2,
                outputs: vec![Output {
                    commitment: key.commit(10, &opening),
                    owner: [5; IDENTITY_BYTES],
                    memo: [6; MEMO_BYTES],
                }],
            },
            signature: [0; 114],
            proof,
        };
        let wrap = |bytes| {
            crate::message_envelope::CanonicalMessageRequest::wrap(bytes)
                .unwrap()
                .to_canonical_bytes()
                .unwrap()
        };
        let bytes = wrap(tx.encode().unwrap());
        let policy = TokenPolicy {
            network,
            limits: CompileLimits {
                max_inputs: 2,
                max_outputs: 2,
                max_depth: 3,
            },
            snapshots: SnapshotLimits {
                max_coins: 8,
                max_depth: 3,
                max_nodes: 24,
            },
            native_budget: NativeBudget {
                max_native_bytes: 0,
            },
        };
        let directory = tempfile::tempdir().unwrap();
        let worker = WorkerVerifier::new(
            directory.path().join("absent-worker"),
            1,
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        for global in [false, true] {
            let manager = build_manager(global);
            assert!(manager.validate_message(2, &application, &bytes).is_err());
            let manager = manager.with_token_worker(policy, worker.clone()).unwrap();
            manager.validate_message(2, &application, &bytes).unwrap();
            // A structurally encoded transaction from a different network fails.
            let mut other = tx.clone();
            other.statement.network = [9; 32];
            let wrong_context = wrap(other.encode().unwrap());
            assert!(manager
                .validate_message(2, &application, &wrong_context)
                .is_err());
            // Configuration must preserve the original execution venue.
            let mut mint = tx.encode().unwrap();
            mint[..4].copy_from_slice(&crate::token_engine::TYPE_LATTICE_MINT.to_be_bytes());
            let error = manager
                .validate_message(2, &application, &wrap(mint))
                .unwrap_err()
                .to_string();
            assert_eq!(
                error.contains("requires serialized global execution"),
                !global
            );
        }
        let mut missing = build_manager(true);
        missing.engines.get_mut().unwrap().remove("token");
        assert!(missing.with_token_worker(policy, worker.clone()).is_err());
        let mut wrong = build_manager(true);
        let compute = wrong.engines.get_mut().unwrap().remove("compute").unwrap();
        wrong
            .engines
            .get_mut()
            .unwrap()
            .insert("token".into(), compute);
        assert!(wrong.with_token_worker(policy, worker).is_err());
    }

    #[test]
    fn manager_with_global_registers_four_engines() {
        let m = build_manager(true);
        assert!(m.get_engine("global").is_some());
        assert!(m.get_engine("token").is_some());
        assert!(m.get_engine("compute").is_some());
        assert!(m.get_engine("hypergraph").is_some());
    }

    #[test]
    fn manager_without_global_registers_three_engines() {
        let m = build_manager(false);
        assert!(m.get_engine("global").is_none());
        assert!(m.get_engine("token").is_some());
        assert!(m.get_engine("compute").is_some());
        assert!(m.get_engine("hypergraph").is_some());
    }

    #[test]
    fn manager_get_engine_unknown_returns_none() {
        let m = build_manager(true);
        assert!(m.get_engine("nonexistent").is_none());
        assert!(m.get_engine("").is_none());
        // Case-sensitive lookup.
        assert!(m.get_engine("GLOBAL").is_none());
    }

    // =================================================================
    // Capabilities aggregation
    // =================================================================

    #[test]
    fn manager_with_global_advertises_all_engine_protocol_ids() {
        // Each engine now advertises multiple capabilities (including
        // common ones like Double/Triple Ratchet and Onion Routing).
        // The manager concatenates all of them.
        let m = build_manager(true);
        let caps = m.get_supported_capabilities();
        // global(4) + token(4) + compute(12) + hypergraph(4) = 24
        assert_eq!(caps.len(), 24);
        let ids: Vec<u32> = caps.iter().map(|c| c.protocol_identifier).collect();
        assert!(ids.contains(&crate::capabilities::GLOBAL_PROTOCOL_V1));
        assert!(ids.contains(&crate::capabilities::TOKEN_PROTOCOL_V1));
        assert!(ids.contains(&crate::capabilities::COMPUTE_PROTOCOL_V1));
    }

    #[test]
    fn manager_without_global_advertises_engine_protocol_ids() {
        let m = build_manager(false);
        let caps = m.get_supported_capabilities();
        // token(4) + compute(12) + hypergraph(4) = 20
        assert_eq!(caps.len(), 20);
        let ids: Vec<u32> = caps.iter().map(|c| c.protocol_identifier).collect();
        assert!(!ids.contains(&crate::capabilities::GLOBAL_PROTOCOL_V1));
        assert!(ids.contains(&crate::capabilities::TOKEN_PROTOCOL_V1));
        assert!(ids.contains(&crate::capabilities::COMPUTE_PROTOCOL_V1));
    }

    // =================================================================
    // select_engine domain routing
    // =================================================================

    #[test]
    fn select_engine_routes_global_domain() {
        let m = build_manager(true);
        assert_eq!(m.select_engine(&domains::GLOBAL).unwrap(), "global");
    }

    #[test]
    fn select_engine_routes_compute_domain() {
        let m = build_manager(true);
        assert_eq!(m.select_engine(&domains::COMPUTE).unwrap(), "compute");
    }

    #[test]
    fn select_engine_routes_quil_token_domain() {
        let m = build_manager(true);
        assert_eq!(m.select_engine(&domains::QUIL_TOKEN).unwrap(), "token");
    }

    #[test]
    fn select_engine_rejects_unknown_domain_without_metadata() {
        // Go parity (execution_manager.go): an address that is neither a
        // base domain nor a deployed app with a recorded type-domain has
        // no engine — it errors, rather than silently defaulting to the
        // hypergraph engine (the prior bug that mis-routed everything).
        let m = build_manager(true);
        let random = [0x42u8; 32];
        let err = m.select_engine(&random).unwrap_err();
        assert!(matches!(err, QuilError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn select_engine_routes_base_domains() {
        let m = build_manager(true);
        assert_eq!(m.select_engine(&domains::GLOBAL).unwrap(), "global");
        assert_eq!(m.select_engine(&domains::COMPUTE).unwrap(), "compute");
        assert_eq!(m.select_engine(&domains::QUIL_TOKEN).unwrap(), "token");
        assert_eq!(
            m.select_engine(&crate::token_intrinsic::constants::token_base_domain())
                .unwrap(),
            "token"
        );
        assert_eq!(
            m.select_engine(&crate::hypergraph_intrinsic::hypergraph_base_domain())
                .unwrap(),
            "hypergraph"
        );
    }

    #[test]
    fn select_engine_resolves_deployed_app_via_metadata() {
        // Write a metadata vertex for a deployed app whose type-domain is
        // TOKEN_BASE_DOMAIN, then confirm select_engine reads it back and
        // routes to the token engine. Exercises init_metadata_vertex →
        // select_engine round-trip (the deploy → routing contract).
        use crate::hypergraph_state::HypergraphState;
        let inclusion_prover: Arc<dyn InclusionProver> = Arc::new(NoopInclusionProver);
        let mem_store: Arc<dyn quil_types::store::HypergraphStore> = Arc::new(MemStore::new());
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            mem_store,
            inclusion_prover.clone(),
        ));

        // Deploy: write the type-domain metadata into the shared crdt.
        let deployed = [0x42u8; 32];
        let state = HypergraphState::new(crdt.clone());
        let mut consensus = quil_tries::VectorCommitmentTree::new();
        let mut sumcheck = quil_tries::VectorCommitmentTree::new();
        let mut config = quil_tries::VectorCommitmentTree::new();
        config
            .insert(&[0x40u8], b"cfg", &[], &num_bigint::BigInt::from(3))
            .unwrap();
        let mut additional: Vec<Option<quil_tries::VectorCommitmentTree>> =
            (0..14).map(|_| None).collect();
        additional[13] = Some(config);
        state
            .init_metadata_vertex(
                &deployed,
                &mut consensus,
                &mut sumcheck,
                "schema",
                &mut additional,
                &crate::token_intrinsic::constants::token_base_domain(),
                1,
                inclusion_prover.as_ref(),
            )
            .unwrap();
        state.commit().unwrap();

        let stubs = crate::testing::NoopExecutionCrypto::new();
        let hg_resolver: Arc<dyn crate::hypergraph_intrinsic::HypergraphConfigResolver> =
            Arc::new(crate::testing::NoopHypergraphConfigResolver);
        let m = ExecutionEngineManager::new(
            inclusion_prover,
            stubs.key_manager.clone(),
            crdt,
            stubs.circuit_compiler,
            stubs.clock_store,
            hg_resolver,
            true,
        );

        assert_eq!(m.select_engine(&deployed).unwrap(), "token");
    }

    #[test]
    fn select_engine_resolves_each_intrinsic_type_domain() {
        // A deployed app's metadata vertex records its base type-domain
        // at 0xff*32; select_engine must route each to the right engine.
        // Covers token/compute/hypergraph deployed-app routing.
        use crate::hypergraph_state::HypergraphState;
        let cases: [([u8; 32], &str); 3] = [
            (
                crate::token_intrinsic::constants::token_base_domain(),
                "token",
            ),
            (crate::domains::COMPUTE, "compute"),
            (
                crate::hypergraph_intrinsic::hypergraph_base_domain(),
                "hypergraph",
            ),
        ];
        for (i, (type_domain, expected_engine)) in cases.iter().enumerate() {
            let inclusion_prover: Arc<dyn InclusionProver> = Arc::new(NoopInclusionProver);
            let mem_store: Arc<dyn quil_types::store::HypergraphStore> = Arc::new(MemStore::new());
            let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                mem_store,
                inclusion_prover.clone(),
            ));
            let deployed = [0x50u8 + i as u8; 32];
            let state = HypergraphState::new(crdt.clone());
            let mut consensus = quil_tries::VectorCommitmentTree::new();
            let mut sumcheck = quil_tries::VectorCommitmentTree::new();
            let mut config = quil_tries::VectorCommitmentTree::new();
            config
                .insert(&[0x40u8], b"cfg", &[], &num_bigint::BigInt::from(3))
                .unwrap();
            let mut additional: Vec<Option<quil_tries::VectorCommitmentTree>> =
                (0..14).map(|_| None).collect();
            additional[13] = Some(config);
            state
                .init_metadata_vertex(
                    &deployed,
                    &mut consensus,
                    &mut sumcheck,
                    "schema",
                    &mut additional,
                    type_domain,
                    1,
                    inclusion_prover.as_ref(),
                )
                .unwrap();
            state.commit().unwrap();

            let stubs = crate::testing::NoopExecutionCrypto::new();
            let hg_resolver: Arc<dyn crate::hypergraph_intrinsic::HypergraphConfigResolver> =
                Arc::new(crate::testing::NoopHypergraphConfigResolver);
            let m = ExecutionEngineManager::new(
                inclusion_prover,
                stubs.key_manager.clone(),
                crdt,
                stubs.circuit_compiler,
                stubs.clock_store,
                hg_resolver,
                true,
            );
            assert_eq!(
                m.select_engine(&deployed).unwrap(),
                *expected_engine,
                "type-domain case {i}"
            );
        }
    }

    #[test]
    fn select_engine_rejects_short_address() {
        let m = build_manager(true);
        let err = m.select_engine(&[0xFFu8; 16]).unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    #[test]
    fn select_engine_rejects_empty_address() {
        let m = build_manager(true);
        let err = m.select_engine(&[]).unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    #[test]
    fn select_engine_accepts_address_longer_than_32_bytes() {
        let m = build_manager(true);
        let mut long = [0u8; 64];
        long[..32].copy_from_slice(&domains::GLOBAL);
        long[32..].copy_from_slice(&[0xDE; 32]);
        assert_eq!(m.select_engine(&long).unwrap(), "global");
    }

    #[test]
    fn select_engine_is_deterministic() {
        let m = build_manager(true);
        let a = m.select_engine(&domains::QUIL_TOKEN).unwrap();
        let b = m.select_engine(&domains::QUIL_TOKEN).unwrap();
        assert_eq!(a, b);
    }

    // =================================================================
    // validate_message / process_message routing
    // =================================================================

    #[test]
    fn validate_message_routes_global_domain_to_global_engine() {
        let m = build_manager(true);
        assert!(m.validate_message(0, &domains::GLOBAL, b"").is_ok());
    }

    #[test]
    fn validate_message_routes_token_domain_to_token_engine() {
        let m = build_manager(true);
        assert!(m.validate_message(0, &domains::QUIL_TOKEN, b"").is_ok());
    }

    #[test]
    fn validate_message_routes_unknown_to_hypergraph() {
        let m = build_manager(true);
        let random = [0x99u8; 32];
        // The hypergraph engine now validates the message (peeks at the
        // type prefix). An empty message is too short → rejected.
        assert!(m.validate_message(0, &random, b"").is_err());
    }

    #[test]
    fn validate_message_rejects_short_address() {
        let m = build_manager(true);
        let err = m.validate_message(0, &[0xFF; 8], b"").unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    #[test]
    fn process_message_preserves_distinct_global_context_through_routing() {
        use quil_types::execution::FrameExecutionContext;
        struct Recorder {
            inner: Box<dyn ShardExecutionEngine>,
            seen: Arc<std::sync::Mutex<Vec<FrameExecutionContext>>>,
        }
        impl ShardExecutionEngine for Recorder {
            fn get_name(&self) -> &str {
                self.inner.get_name()
            }
            fn validate_message(&self, f: u64, a: &[u8], m: &[u8]) -> Result<()> {
                self.inner.validate_message(f, a, m)
            }
            fn process_message(
                &self,
                _: u64,
                _: &BigInt,
                _: &[u8],
                _: &[u8],
            ) -> Result<ProcessMessageResult> {
                panic!("manager must forward explicit execution context")
            }
            fn process_message_with_context(
                &self,
                c: FrameExecutionContext,
                fee: &BigInt,
                a: &[u8],
                m: &[u8],
            ) -> Result<ProcessMessageResult> {
                self.seen.lock().unwrap().push(c);
                self.inner.process_message_with_context(c, fee, a, m)
            }
            fn prove(
                &self,
                a: &[u8],
                f: u64,
                m: &[u8],
            ) -> Result<quil_types::proto::global::MessageRequest> {
                self.inner.prove(a, f, m)
            }
            fn lock(&self, f: u64, a: &[u8], m: &[u8]) -> Result<Vec<Vec<u8>>> {
                self.inner.lock(f, a, m)
            }
            fn unlock(&self) -> Result<()> {
                self.inner.unlock()
            }
            fn get_cost(&self, m: &[u8]) -> Result<BigInt> {
                self.inner.get_cost(m)
            }
            fn get_capabilities(&self) -> Vec<node::Capability> {
                self.inner.get_capabilities()
            }
        }
        let m = build_manager(false);
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        {
            let mut engines = m.engines.write().unwrap();
            let inner = engines.remove("token").unwrap();
            engines.insert(
                "token".into(),
                Box::new(Recorder {
                    inner,
                    seen: seen.clone(),
                }),
            );
        }
        let context = FrameExecutionContext {
            frame_number: 7,
            finalized_global_frame: Some(913),
            venue: None,
            shard: quil_types::execution::ShardPath::WHOLE,
        };
        m.process_message_with_context(context, &BigInt::from(0), &domains::QUIL_TOKEN, b"")
            .unwrap();
        m.process_message(8, &BigInt::from(0), &domains::QUIL_TOKEN, b"")
            .unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                context,
                FrameExecutionContext {
                    frame_number: 8,
                    finalized_global_frame: None,
                    venue: None,
                    shard: quil_types::execution::ShardPath::WHOLE
                }
            ]
        );
    }

    #[test]
    fn process_message_routes_global_and_returns_empty_result() {
        let m = build_manager(true);
        let r = m
            .process_message(0, &BigInt::from(1), &domains::GLOBAL, b"")
            .unwrap();
        assert!(r.messages.is_empty());
        assert!(r.state.is_empty());
    }

    #[test]
    fn process_message_routes_token_domain() {
        let m = build_manager(true);
        let r = m
            .process_message(0, &BigInt::from(1), &domains::QUIL_TOKEN, b"")
            .unwrap();
        assert!(r.messages.is_empty());
    }

    #[test]
    fn token_deploy_through_manager_creates_routable_shard() {
        // End-to-end: a TokenDeploy fed to the manager at the token BASE
        // domain — the exact address the global frame materializer routes
        // deploy bundles to — dispatches through the token engine's
        // deploy arm, derives the new shard's domain from the config,
        // writes its metadata vertex into the shared CRDT, and makes the
        // shard routable. This proves a brand-new shard comes into existence
        // purely via the execution manager (the chain Go relies on: manager
        // → intrinsic engine → deploy), with no pre-existing target shard.
        use crate::hypergraph_state::HypergraphState;

        // Use the REAL KZG prover: the new shard's domain is derived from the
        // config COMMITMENT, so a trivial (constant) commitment would collide
        // with the token base domain. This also exercises the real KZG path.
        quil_crypto::init(); // load the SRS (idempotent)
        let prover: Arc<dyn InclusionProver> = Arc::new(quil_tries::ShaInclusionProver);
        let cfg = crate::token_intrinsic::config::TokenConfiguration {
            behavior: (crate::token_intrinsic::constants::DIVISIBLE
                | crate::token_intrinsic::constants::ACCEPTABLE
                | crate::token_intrinsic::constants::EXPIRABLE) as u32,
            owner_public_key: vec![0x01u8; 32],
            ..Default::default()
        };

        // The derived domain depends only on (config, prover), not the CRDT,
        // so compute it on a throwaway state to know which shard to query.
        let throwaway_store: Arc<dyn quil_types::store::HypergraphStore> =
            Arc::new(MemStore::new());
        let throwaway = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            throwaway_store,
            prover.clone(),
        ));
        let derived = crate::token_intrinsic::materialize::materialize_token_deploy_init(
            &HypergraphState::new(throwaway),
            &cfg,
            0,
            prover.as_ref(),
        )
        .unwrap();
        // The derived shard is distinct from the token base domain.
        assert_ne!(
            derived,
            crate::token_intrinsic::constants::token_base_domain()
        );

        // Build a Global-mode manager (all four engines share one CRDT) over
        // the real KZG prover.
        let mem_store: Arc<dyn quil_types::store::HypergraphStore> = Arc::new(MemStore::new());
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            mem_store,
            prover.clone(),
        ));
        let stubs = crate::testing::NoopExecutionCrypto::new();
        let hg_resolver: Arc<dyn crate::hypergraph_intrinsic::HypergraphConfigResolver> =
            Arc::new(crate::testing::NoopHypergraphConfigResolver);
        let m = ExecutionEngineManager::new(
            prover.clone(),
            stubs.key_manager.clone(),
            crdt,
            stubs.circuit_compiler,
            stubs.clock_store,
            hg_resolver,
            true,
        );

        // Before the deploy, the derived shard has no metadata → not routable.
        assert!(m.select_engine(&derived).is_err());

        // Encode the TokenDeploy as a canonical MessageBundle.
        let deploy = crate::token_intrinsic::TokenDeploy {
            config: cfg.to_canonical_bytes().unwrap(),
            rdf_schema: Vec::new(),
        };
        let inner = deploy.to_canonical_bytes().unwrap();
        let bundle = crate::message_envelope::CanonicalMessageBundle {
            requests: vec![Some(
                crate::message_envelope::CanonicalMessageRequest::wrap(inner).unwrap(),
            )],
            timestamp: 0,
        };
        let bundle_bytes = bundle.to_canonical_bytes().unwrap();

        // Route it at the token base domain (as the global frame materializer
        // does for a deploy), at a zero price: what this test checks is
        // routing, and at a nonzero price every node refuses a deploy that
        // carries no settlement claim (engines' settlement parity tests).
        let token_base = crate::token_intrinsic::constants::token_base_domain();
        m.process_message(0, &BigInt::from(0), &token_base, &bundle_bytes)
            .unwrap();
        m.commit_frame(0).unwrap();

        // The brand-new shard now routes to the token engine.
        assert_eq!(m.select_engine(&derived).unwrap(), "token");
    }

    #[test]
    fn process_message_missing_global_errors_with_not_found() {
        // Without the global engine registered, process_message for
        // the GLOBAL domain routes to "global" and then fails to look
        // it up, returning NotFound.
        let m = build_manager(false);
        let err = m
            .process_message(0, &BigInt::from(1), &domains::GLOBAL, b"")
            .unwrap_err();
        assert!(matches!(err, QuilError::NotFound(_)));
    }
}

#[cfg(all(test, feature = "native-proof"))]
#[path = "manager_prework_tests.rs"]
mod prework_tests;
