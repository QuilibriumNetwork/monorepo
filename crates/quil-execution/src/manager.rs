use std::collections::HashMap;
#[cfg(all(test, feature = "confidential-tokens"))]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
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
pub use execution_branch::{ExecutionBranch, ExecutionBranchLimits, ExecutionPublicationGuard};

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

impl ExecutionEngineManager {
    /// Reconstruct all engines against the supplied state, preserving configured
    /// modes, cryptographic providers, worker admission and pricing policy.
    /// Message changesets and resolver caches are new, and no source engine is
    /// reused. The caller must hold its whole-frame capture barrier while
    /// constructing this context and calling this method.
    pub fn fork_with_context(&self, context: ExecutionForkContext) -> Result<Self> {
        if Arc::ptr_eq(&self.crdt, &context.crdt) {
            return Err(QuilError::InvalidArgument("execution fork requires a separate CRDT".into()));
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
                return Err(QuilError::ExecutionUnavailable("execution branch summary metadata limit".into()));
            }
            source.iter().copied().collect()
        };
        for name in ["token", "compute", "hypergraph"] {
            if !source.contains_key(name) {
                return Err(QuilError::ExecutionUnavailable(format!("execution fork requires {name} engine")));
            }
        }
        let shards_store = if self.shards_store.is_some() {
            Some(context.shards_store.clone().ok_or_else(|| {
                QuilError::ExecutionUnavailable("execution fork requires shard metadata store".into())
            })?)
        } else { None };
        let mut engines: HashMap<String, Box<dyn ShardExecutionEngine>> = HashMap::new();
        for (name, engine) in source.iter() {
            let any = engine.as_any().ok_or_else(|| {
                QuilError::ExecutionUnavailable(format!("execution fork cannot reconstruct engine {name}"))
            })?;
            let fork: Box<dyn ShardExecutionEngine> = match name.as_str() {
                "global" => Box::new(any.downcast_ref::<GlobalExecutionEngine>()
                    .ok_or_else(|| QuilError::ExecutionUnavailable("unexpected global engine type".into()))?
                    .fork_with_context(&context)?),
                "token" => Box::new(any.downcast_ref::<TokenExecutionEngine>()
                    .ok_or_else(|| QuilError::ExecutionUnavailable("unexpected token engine type".into()))?
                    .fork_with_context(&context)?),
                "compute" => Box::new(any.downcast_ref::<ComputeExecutionEngine>()
                    .ok_or_else(|| QuilError::ExecutionUnavailable("unexpected compute engine type".into()))?
                    .fork_with_context(&context)?),
                "hypergraph" => Box::new(any.downcast_ref::<HypergraphExecutionEngine>()
                    .ok_or_else(|| QuilError::ExecutionUnavailable("unexpected hypergraph engine type".into()))?
                    .fork_with_context(&context)?),
                _ => return Err(QuilError::ExecutionUnavailable(format!("unsupported execution fork engine {name}"))),
            };
            engines.insert(name.clone(), fork);
        }
        Ok(Self {
            engines: RwLock::new(engines), crdt: context.crdt, shards_store,
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
        let token = engines.get_mut("token")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<TokenExecutionEngine>())
            .ok_or_else(|| QuilError::InvalidArgument("manager requires a concrete token engine".into()))?;
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
        let token = engines.get_mut("token")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<TokenExecutionEngine>())
            .ok_or_else(|| QuilError::InvalidArgument("manager requires a concrete token engine".into()))?;
        token.set_mode(crate::engines::ExecutionMode::Application);
        Ok(self)
    }

    /// Give the token engine the store that holds canonical global frames.
    /// Required for managers whose own clock store holds only an app-shard
    /// chain (thread workers): a claim citing a global frame the store lacks
    /// is an infrastructure failure that holds the shard frame for retry.
    pub fn with_global_clock_store(mut self, store: Arc<dyn quil_types::store::ClockStore>) -> Result<Self> {
        let engines = self.engines.get_mut().map_err(|_| {
            QuilError::ExecutionUnavailable("execution manager lock poisoned".into())
        })?;
        let token = engines.get_mut("token")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<TokenExecutionEngine>())
            .ok_or_else(|| QuilError::InvalidArgument("manager requires a concrete token engine".into()))?;
        token.set_global_clock_store(store.clone());
        if let Some(compute) = engines.get_mut("compute")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<ComputeExecutionEngine>())
        {
            compute.set_global_clock_store(store.clone());
        }
        if let Some(hypergraph) = engines.get_mut("hypergraph")
            .and_then(|engine| engine.as_any_mut())
            .and_then(|engine| engine.downcast_mut::<HypergraphExecutionEngine>())
        {
            hypergraph.set_global_clock_store(store);
        }
        Ok(self)
    }

    /// Set the network this node prices state growth for. Every node of a
    /// network must use the same value (it is the network's own selector).
    pub fn with_pricing_network(mut self, network: u8) -> Self {
        self.pricing_network = network;
        self
    }

    /// The network selector for fee pricing.
    pub fn pricing_network(&self) -> u8 {
        self.pricing_network
    }

    /// Pre-verify confidential token operations of the given `(address,
    /// canonical bundle bytes)` pairs concurrently, filling the verdict cache.
    /// Bundles routed to other engines are ignored. Never fails.
    pub fn preverify_bundles(&self, bundles: &[(Vec<u8>, Vec<u8>)]) {
        #[cfg(feature = "native-proof")]
        {
            let routed: Vec<(Vec<u8>, Vec<u8>)> = bundles
                .iter()
                .filter(|(address, _)| self.select_engine(address).map(|name| name == "token").unwrap_or(false))
                .cloned()
                .collect();
            if routed.is_empty() { return; }
            let engines = match self.engines.read() { Ok(engines) => engines, Err(_) => return };
            if let Some(token) = engines.get("token").and_then(|e| e.as_any()).and_then(|e| e.downcast_ref::<TokenExecutionEngine>()) {
                token.preverify_bundles(&routed);
            }
        }
        #[cfg(not(feature = "native-proof"))]
        let _ = bundles;
    }

    /// Confidential operations a proposal may schedule per frame under the
    /// configured verification budget (unbounded without a worker).
    pub fn token_verification_capacity(&self) -> usize {
        #[cfg(feature = "native-proof")]
        {
            let engines = match self.engines.read() { Ok(engines) => engines, Err(_) => return usize::MAX };
            return engines.get("token").and_then(|e| e.as_any()).and_then(|e| e.downcast_ref::<TokenExecutionEngine>())
                .map(|token| token.verification_capacity()).unwrap_or(usize::MAX);
        }
        #[cfg(not(feature = "native-proof"))]
        usize::MAX
    }

    /// Number of confidential token operations in a canonical bundle
    /// (always zero without the native proof feature).
    pub fn confidential_operation_count(address: &[u8], bundle_bytes: &[u8]) -> usize {
        #[cfg(feature = "native-proof")]
        {
            return TokenExecutionEngine::confidential_operations(&[(address.to_vec(), bundle_bytes.to_vec())]).len();
        }
        #[cfg(not(feature = "native-proof"))]
        { let _ = (address, bundle_bytes); 0 }
    }

    /// Whether the global commit has decided every request of a canonical
    /// bundle, so no shard needs to execute it again. Only globally committed
    /// operations are ever decided, so a bundle holding anything else never
    /// is. `global` holds GLOBAL state; false when it cannot say. `address`
    /// is the application, or a shard filter under it (its first 32 bytes).
    pub fn decided_globally(global: Arc<quil_hypergraph::HypergraphCrdt>, address: &[u8], bundle_bytes: &[u8]) -> bool {
        #[cfg(feature = "native-proof")]
        {
            use crate::token_intrinsic::global_commit;
            let Some(Ok(application)) = address.get(..32).map(<[u8; 32]>::try_from) else { return false };
            let Ok(bundle) = crate::message_envelope::CanonicalMessageBundle::from_canonical_bytes(bundle_bytes) else { return false };
            if bundle.requests.is_empty() {
                return false;
            }
            let state = crate::hypergraph_state::HypergraphState::new(global);
            return bundle.requests.iter().all(|request| {
                request.as_ref().is_some_and(|request| {
                    global_commit::is_decided(&state, &application, &global_commit::tx_id(&request.inner_bytes)).unwrap_or(false)
                })
            });
        }
        #[cfg(not(feature = "native-proof"))]
        { let _ = (global, address, bundle_bytes); false }
    }

    /// Build a manager with all engines initialized. Every engine is
    /// constructed with mandatory crypto + store providers — no silent
    /// crypto-less fallback. Production callers MUST supply real
    /// implementations; tests can wire noop stubs from
    /// `crate::testing::NoopExecutionCrypto`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inclusion_prover: Arc<dyn InclusionProver>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler>,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
        hypergraph_config_resolver: Arc<
            dyn crate::hypergraph_intrinsic::HypergraphConfigResolver,
        >,
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
        hypergraph_config_resolver: Arc<
            dyn crate::hypergraph_intrinsic::HypergraphConfigResolver,
        >,
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
            Box::new(
                {
                    let mut hypergraph = HypergraphExecutionEngine::new_with_state(
                        mode,
                        crdt.clone(),
                        hypergraph_config_resolver,
                    )
                    .with_key_manager(key_manager);
                    hypergraph.set_global_clock_store(clock_store.clone());
                    hypergraph
                },
            ),
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
                Ok(false) => {},
                Err(e) => tracing::warn!(app = %hex::encode(app), error = %e,
                    "refresh_shard_prefixes: layout unchanged after rebuild failure; will retry"),
            }
        }
        changed
    }

    /// Checked refresh for tentative execution. A failure may follow earlier
    /// in-memory layout changes, so the owner must discard the whole branch.
    pub fn try_refresh_shard_prefixes(&self) -> Result<usize> {
        let Some(store) = &self.shards_store else { return Ok(0); };
        let mut by_app = std::collections::BTreeMap::<[u8; 32], Vec<Vec<u32>>>::new();
        for row in store.range_app_shards()? {
            if row.shard_key.len() != 35 {
                return Err(QuilError::ExecutionUnavailable("invalid captured shard metadata key".into()));
            }
            by_app.entry(row.shard_key[3..].try_into().unwrap()).or_default().push(row.prefix);
        }
        let mut changed = 0;
        for (app, prefixes) in by_app {
            changed += usize::from(self.crdt.refresh_app_shard_prefixes(app, prefixes)?);
        }
        Ok(changed)
    }

    /// Publish only after global state/cursor commit. None invalidates quotes
    /// when QUIL no longer uses this venue. This cache is not persisted.
    pub fn publish_global_quil_fee_snapshot(&self, snapshot: Option<crate::pricing::GlobalQuilFeeSnapshot>) {
        *self.global_quil_fee.write().unwrap_or_else(|e| e.into_inner()) = snapshot;
    }

    /// Publish the global venue's pricing inputs after the global state and
    /// cursor commit (every frame, independent of QUIL routing).
    pub fn publish_global_venue_fee_snapshot(&self, snapshot: crate::pricing::GlobalQuilFeeSnapshot) {
        *self.global_venue_fee.write().unwrap_or_else(|e| e.into_inner()) = Some(snapshot);
    }

    /// The global venue snapshot, only while it is the current materialized frame's.
    pub fn global_venue_fee_snapshot(&self, materialized_frame: u64) -> Result<Option<crate::pricing::GlobalQuilFeeSnapshot>> {
        self.global_venue_fee.read().map(|snapshot| snapshot.filter(|s| s.frame_number == materialized_frame))
            .map_err(|_| QuilError::ExecutionUnavailable("fee snapshot lock poisoned".into()))
    }

    pub fn global_quil_fee_snapshot(&self, materialized_frame: u64) -> Result<Option<crate::pricing::GlobalQuilFeeSnapshot>> {
        self.global_quil_fee.read().map(|snapshot| snapshot.filter(|s| s.frame_number == materialized_frame))
            .map_err(|_| QuilError::ExecutionUnavailable("fee snapshot lock poisoned".into()))
    }

    /// The hypergraph CRDT these engines commit to — used by the forest sync,
    /// which applies pulled state into this same CRDT (coordinated versions).
    pub fn crdt(&self) -> Arc<quil_hypergraph::HypergraphCrdt> {
        self.crdt.clone()
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
        let res = self.crdt.commit_with_global_cursor(frame_number, &cursor_key);
        crate::metrics::observe_execution_duration("crdt", "commit", start.elapsed().as_secs_f64());
        res?;
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
        // HypergraphState includes this frame's staged blobs. Computing after
        // commit would leave a cursor with no report if construction failed.
        let report = self.shard_accumulator_report(filter, anchor)?;
        let digest = accumulator_header::report_digest(&report);
        let mut records = vec![
            (encoding::clock_shard_frame_fee_total_key(filter, frame_number), fee_total.to_be_bytes().to_vec()),
            (encoding::clock_shard_frame_settlements_key(filter, frame_number), settlements),
            (encoding::clock_shard_frame_spends_key(filter, frame_number), spends),
            (encoding::clock_shard_frame_accumulator_key(filter, frame_number), digest.clone()),
        ];
        if !digest.is_empty() {
            records.push((encoding::clock_shard_accumulator_report_key(filter, &digest), report.clone()));
        }
        let cursor = encoding::consensus_materialized_cursor_key(filter);
        let start = std::time::Instant::now();
        let result = self.crdt.commit_with_frame_cursor_and_records(frame_number, &cursor, &records);
        crate::metrics::observe_execution_duration("crdt", "commit", start.elapsed().as_secs_f64());
        result?;
        Ok(report)
    }

    /// Checkpoint completed shard sync without flushing unrelated pending state.
    pub fn checkpoint_app_materialized_cursor(&self, frame_number: u64, filter: &[u8]) -> Result<()> {
        self.crdt.checkpoint_frame_cursor(frame_number,
            &quil_store::encoding::consensus_materialized_cursor_key(filter))
    }

    pub fn read_app_materialized_cursor(&self, filter: &[u8]) -> Result<u64> {
        self.crdt.read_frame_cursor(&quil_store::encoding::consensus_materialized_cursor_key(filter))
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
            QuilError::Internal(
                "global engine does not support as_any_mut downcast".into(),
            )
        })?;
        let global = any.downcast_mut::<GlobalExecutionEngine>().ok_or_else(|| {
            QuilError::Internal(
                "global engine is not a GlobalExecutionEngine".into(),
            )
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
            QuilError::Internal(
                "global engine does not support as_any_mut downcast".into(),
            )
        })?;
        let global = any.downcast_mut::<GlobalExecutionEngine>().ok_or_else(|| {
            QuilError::Internal(
                "global engine is not a GlobalExecutionEngine".into(),
            )
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
        let engines = self.engines.read().unwrap();
        let res = if let Some(engine) = engines.get(&engine_name) {
            engine.validate_message(frame_number, address, message)
        } else {
            Err(QuilError::NotFound(format!(
                "engine '{}' not found",
                engine_name
            )))
        };
        crate::metrics::observe_execution_duration(label, "validate", start.elapsed().as_secs_f64());
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
            quil_types::execution::FrameExecutionContext { frame_number, finalized_global_frame: None, venue: None, shard: quil_types::execution::ShardPath::WHOLE },
            fee_multiplier, address, message,
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
    pub fn lock(
        &self,
        frame_number: u64,
        address: &[u8],
        message: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        let engine_name = self.select_engine(address)?;
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
        let engines = self.engines.read().unwrap();
        // World-state growth of hypergraph and compute writes (and of a
        // settlement claim's consumption marker), paid by the settlement the
        // bundle consumes.
        #[cfg(feature = "confidential-tokens")]
        let consumer = BigInt::from(crate::token_intrinsic::settlement_claim::message_cost(message)?);
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
        { let _ = (snapshot, filter, anchor); Ok(Vec::new()) }
        #[cfg(feature = "confidential-tokens")]
        {
            let (application, shard) = quil_forest::decode_shard_filter_or_root(filter, 32)
                .ok_or_else(|| QuilError::InvalidArgument("snapshot report: invalid filter".into()))?;
            let application: [u8; 32] = application.try_into()
                .map_err(|_| QuilError::InvalidArgument("snapshot report: invalid application".into()))?;
            let network = quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
            let attest = anchor >= crate::token_intrinsic::global_commit::orphan_replacement_frame();
            crate::token_intrinsic::shard_accumulator::snapshot_report(snapshot, &network, &application, &shard, attest)?
                .map(|report| report.encode()).transpose().map(Option::unwrap_or_default)
        }
    }

    /// `anchor`: the GLOBAL frame the reported frame cites; from the orphan
    /// re-placement frame the report also attests held blocks.
    pub fn shard_accumulator_report(&self, filter: &[u8], anchor: u64) -> Result<Vec<u8>> {
        #[cfg(not(feature = "confidential-tokens"))]
        { let _ = (filter, anchor); Ok(Vec::new()) }
        #[cfg(feature = "confidential-tokens")]
        {
            use crate::token_intrinsic::roots;
            let (application, shard) = quil_forest::decode_shard_filter_or_root(filter, 32)
                .ok_or_else(|| QuilError::InvalidArgument("accumulator report: filter names no shard".into()))?;
            let application: [u8; 32] = application.as_slice().try_into()
                .map_err(|_| QuilError::InvalidArgument("accumulator report: malformed application".into()))?;
            let network = quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
            let state = crate::hypergraph_state::HypergraphState::new(self.crdt());
            if self.summary_rebuilds.read().unwrap().contains(&application) {
                roots::rebuild_block_summary(&state, &network, &application, &shard)?;
                state.commit()?;
                self.summary_rebuilds.write().unwrap().remove(&application);
                tracing::info!(filter = hex::encode(filter), "rebuilt the local block summary from covered block records");
            }
            let attest = anchor >= crate::token_intrinsic::global_commit::orphan_replacement_frame();
            match crate::token_intrinsic::shard_accumulator::shard_report(&state, &network, &application, &shard, attest)? {
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
        { let _ = (address, message); false }
        #[cfg(feature = "native-proof")]
        {
            use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest, TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST};
            let Some(application) = address.get(..32).and_then(|a| <[u8; 32]>::try_from(a).ok()) else { return false };
            if message.len() < 4 {
                return false;
            }
            let requests = match u32::from_be_bytes(message[..4].try_into().unwrap()) {
                TYPE_MESSAGE_REQUEST => match CanonicalMessageRequest::from_canonical_bytes(message) {
                    Ok(request) => vec![request],
                    Err(_) => return false,
                },
                TYPE_MESSAGE_BUNDLE => match CanonicalMessageBundle::from_canonical_bytes(message) {
                    Ok(bundle) => bundle.requests.into_iter().flatten().collect(),
                    Err(_) => return false,
                },
                _ => return false,
            };
            !requests.is_empty() && requests.iter().all(|request|
                crate::token_intrinsic::spend_entries::commits_globally(&application, request.inner_type_prefix))
        }
    }

    pub fn message_spend_entries(&self, address: &[u8], message: &[u8], source_frame: u64) -> Result<Vec<Vec<u8>>> {
        #[cfg(not(feature = "native-proof"))]
        { let _ = (address, message, source_frame); Ok(Vec::new()) }
        #[cfg(feature = "native-proof")]
        {
            use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest, TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST};
            let Some(application) = address.get(..32).and_then(|a| <[u8; 32]>::try_from(a).ok()) else { return Ok(Vec::new()) };
            if message.len() < 4 {
                return Ok(Vec::new());
            }
            let requests = match u32::from_be_bytes(message[..4].try_into().unwrap()) {
                TYPE_MESSAGE_REQUEST => vec![CanonicalMessageRequest::from_canonical_bytes(message)?],
                TYPE_MESSAGE_BUNDLE => CanonicalMessageBundle::from_canonical_bytes(message)?.requests.into_iter().flatten().collect(),
                _ => return Ok(Vec::new()),
            };
            let network = quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
            let state = crate::hypergraph_state::HypergraphState::new(self.crdt());
            let mut entries = Vec::new();
            for request in requests {
                if !crate::token_intrinsic::spend_entries::commits_globally(&application, request.inner_type_prefix) {
                    continue;
                }
                // A custom mint's consumptions depend on the deployed policy.
                let entry = crate::token_intrinsic::spend_entries::commit_entry(
                    &state, &network, &application, request.inner_type_prefix, &request.inner_bytes, source_frame,
                )?;
                entries.push(entry.encode()?);
            }
            Ok(entries)
        }
    }

    /// Deliveries (`0x051A` operation bytes) of committed outputs the shard
    /// `filter` owns and has not yet taken, in delivery order, at most
    /// [`MAX_DELIVERIES_PER_FRAME`]. `global` holds GLOBAL state and `clock`
    /// canonical global frames; each record is proven at the newest global
    /// root retained at or before `anchor`. `operation(source frame, tx id)`
    /// returns the committed operation's `(type prefix, bytes)` from that
    /// certified shard frame. Stops at the first output it cannot deliver yet,
    /// since later outputs of the block would be out of sequence.
    ///
    /// [`MAX_DELIVERIES_PER_FRAME`]: crate::token_intrinsic::delivery::MAX_DELIVERIES_PER_FRAME
    /// The certified frames holding the bytes of everything committed to the
    /// shard `filter` that it has not delivered yet: `(executing filter, frame
    /// number)`, without repeats. On a whole-application shard these are its
    /// own frames; on a split one they are mostly other shards', which a node
    /// must fetch before it can propose those deliveries.
    pub fn pending_delivery_sources(
        &self,
        global: Arc<quil_hypergraph::HypergraphCrdt>,
        filter: &[u8],
    ) -> Result<Vec<(Vec<u8>, u64)>> {
        #[cfg(not(feature = "native-proof"))]
        { let _ = (global, filter); Ok(Vec::new()) }
        #[cfg(feature = "native-proof")]
        {
            let Some((application, _)) = quil_forest::decode_shard_filter_or_root(filter, 32) else { return Ok(Vec::new()) };
            let Ok(application) = <[u8; 32]>::try_from(application.as_slice()) else { return Ok(Vec::new()) };
            let mut sources: Vec<(Vec<u8>, u64)> = Vec::new();
            for item in self.pending_deliveries(global, filter)? {
                let Some(bits) = item.source_shard.bits() else { continue };
                let source = (executing_filter(&application, &bits), item.source_frame);
                if !sources.contains(&source) {
                    sources.push(source);
                }
            }
            Ok(sources)
        }
    }

    #[cfg(feature = "native-proof")]
    fn pending_deliveries(
        &self,
        global: Arc<quil_hypergraph::HypergraphCrdt>,
        filter: &[u8],
    ) -> Result<Vec<crate::token_intrinsic::delivery::PendingDelivery>> {
        use crate::token_intrinsic::{delivery, dispatch::TokenPolicy};
        let Some((application, shard)) = quil_forest::decode_shard_filter_or_root(filter, 32) else { return Ok(Vec::new()) };
        let Ok(application) = <[u8; 32]>::try_from(application.as_slice()) else { return Ok(Vec::new()) };
        let network = quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
        let limits = TokenPolicy::for_network(self.pricing_network()).snapshots;
        let global = crate::hypergraph_state::HypergraphState::new(global);
        let local = crate::hypergraph_state::HypergraphState::new(self.crdt());
        delivery::pending_deliveries(
            &global, &local, &network, &application, &shard, limits, delivery::MAX_DELIVERIES_PER_FRAME,
        )
    }

    /// `operation(executing filter, source frame, tx id)` supplies the bytes of
    /// the committed operation, from the certified frame of the shard that
    /// executed it — the owner's own frames on a whole-application shard, and
    /// another shard's on a split one.
    pub fn coin_deliveries(
        &self,
        global: Arc<quil_hypergraph::HypergraphCrdt>,
        clock: &dyn quil_types::store::ClockStore,
        filter: &[u8],
        anchor: u64,
        operation: &dyn Fn(&[u8], u64, &[u8; 32]) -> Option<(u32, Vec<u8>)>,
    ) -> Result<Vec<Vec<u8>>> {
        #[cfg(not(feature = "native-proof"))]
        { let _ = (global, clock, filter, anchor, operation); Ok(Vec::new()) }
        #[cfg(feature = "native-proof")]
        {
            use crate::token_intrinsic::delivery;
            let Some((application, _)) = quil_forest::decode_shard_filter_or_root(filter, 32) else { return Ok(Vec::new()) };
            let Ok(application) = <[u8; 32]>::try_from(application.as_slice()) else { return Ok(Vec::new()) };
            let network = quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
            let pending = self.pending_deliveries(global.clone(), filter)?;
            let global = crate::hypergraph_state::HypergraphState::new(global);
            let mut deliveries = Vec::with_capacity(pending.len());
            let mut stalled = std::collections::BTreeSet::new();
            for item in pending {
                if stalled.contains(&(item.escrow, item.block)) {
                    continue;
                }
                // Where it ran is where its bytes are: the commit recorded it.
                let Some(source) = item.source_shard.bits() else { continue };
                let source_filter = executing_filter(&application, &source);
                let delivered = operation(&source_filter, item.source_frame, &item.tx_id).and_then(|(tp, bytes)| {
                    delivery::find_delivered(&network, &application, tp, &bytes, &item).ok().flatten()
                });
                let built = match delivered {
                    Some(delivered) => delivery::build_delivery(&global, clock, &network, &application, anchor, &item, delivered)?,
                    None => None,
                };
                match built {
                    Some(bytes) => deliveries.push(bytes),
                    None => { stalled.insert((item.escrow, item.block)); }
                }
            }
            Ok(deliveries)
        }
    }

    /// Poseidon digest of the application root this node's own accumulator
    /// published for `filter`'s application, if any — for comparing, in logs,
    /// against the canonical root the global materializer folds from reports.
    pub fn local_application_root_digest(&self, filter: &[u8]) -> Result<Option<[u8; 32]>> {
        #[cfg(not(feature = "confidential-tokens"))]
        { let _ = filter; Ok(None) }
        #[cfg(feature = "confidential-tokens")]
        {
            let Some(application) = filter.get(..32).and_then(|a| <[u8; 32]>::try_from(a).ok()) else { return Ok(None) };
            let network = quil_lattice_ct::confidential::transfer::network_identifier(self.pricing_network());
            let state = crate::hypergraph_state::HypergraphState::new(self.crdt());
            crate::token_intrinsic::roots::read_current(&state, &network, &application)?
                .map(|record| quil_crypto::poseidon::hash_bytes_to_32(&record.root.to_bytes()))
                .transpose()
        }
    }

    pub fn message_token_fees(&self, address: &[u8], message: &[u8]) -> Result<u128> {
        #[cfg(not(feature = "confidential-tokens"))]
        { let _ = (address, message); Ok(0) }
        #[cfg(feature = "confidential-tokens")]
        {
            use crate::message_envelope::{
                CanonicalMessageBundle, CanonicalMessageRequest, TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST,
            };
            if message.len() < 4 || address.len() < 32 || address[..32] == domains::GLOBAL {
                return Ok(0);
            }
            if address[..32] != domains::QUIL_TOKEN {
                return Ok(crate::token_intrinsic::settlement_claim::message_settlement_amount(message));
            }
            // Operations that commit through the global frame are credited
            // there, and only if they commit (`global_commit::materialize_relay`).
            let fee_of = |tp: u32, bytes: &[u8]| -> u128 {
                let self_paid = (0x0512..=0x0518).contains(&tp)
                    && tp != crate::token_engine::TYPE_LATTICE_MINT_CLAIM
                    && !crate::token_intrinsic::spend_entries_relayed(tp);
                if self_paid && crate::token_intrinsic::wire::domain(bytes).ok() == Some(domains::QUIL_TOKEN) {
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
                    bundle.requests.iter().flatten()
                        .fold(0u128, |sum, r| sum.saturating_add(fee_of(r.inner_type_prefix, &r.inner_bytes)))
                }
                _ => 0,
            })
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
        { let _ = message; Ok(Vec::new()) }
        #[cfg(feature = "confidential-tokens")]
        {
            use crate::message_envelope::{
                CanonicalMessageBundle, CanonicalMessageRequest, TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST,
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
                    for request in bundle.requests.iter().flatten().filter(|r| r.inner_type_prefix == 0x0518) {
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

        if route == domains::COMPUTE {
            Ok("compute".into())
        } else if route == hg_base {
            Ok("hypergraph".into())
        } else if route == token_base || route == domains::QUIL_TOKEN {
            Ok("token".into())
        } else {
            Err(QuilError::NotFound(format!(
                "no execution engine found for address: {}",
                hex::encode(addr)
            )))
        }
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
            frame_number: 42, difficulty: 50_000, world_state_bytes: 123_456,
        };
        manager.publish_global_quil_fee_snapshot(Some(snapshot));
        assert_eq!(manager.global_quil_fee_snapshot(42).unwrap(), Some(snapshot));
        assert_eq!(manager.global_quil_fee_snapshot(41).unwrap(), None);
        assert_eq!(manager.global_quil_fee_snapshot(43).unwrap(), None);
        manager.publish_global_quil_fee_snapshot(None);
        assert_eq!(manager.global_quil_fee_snapshot(42).unwrap(), None);
        // The global venue snapshot is independent of QUIL routing.
        assert_eq!(manager.global_venue_fee_snapshot(42).unwrap(), None);
        manager.publish_global_venue_fee_snapshot(snapshot);
        assert_eq!(manager.global_venue_fee_snapshot(42).unwrap(), Some(snapshot));
        assert_eq!(manager.global_venue_fee_snapshot(43).unwrap(), None);
        assert_eq!(manager.global_quil_fee_snapshot(42).unwrap(), None);
    }

    #[test]
    fn application_venue_switches_the_token_engine_only() {
        let mut manager = build_manager(true).with_application_venue().unwrap();
        let engines = manager.engines.get_mut().unwrap();
        assert!(engines.contains_key("global"), "the global engine stays installed");
        let token = engines.get_mut("token").unwrap().as_any_mut().unwrap()
            .downcast_mut::<TokenExecutionEngine>().unwrap();
        assert_eq!(token.mode(), crate::engines::ExecutionMode::Application);
        let mut global = build_manager(true);
        let token = global.engines.get_mut().unwrap().get_mut("token").unwrap().as_any_mut().unwrap()
            .downcast_mut::<TokenExecutionEngine>().unwrap();
        assert_eq!(token.mode(), crate::engines::ExecutionMode::Global);
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
        let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(Arc::new(MemStore::new()), Arc::new(NoopInclusionProver)));
        let op = |tp: u32, tag: u8| CanonicalMessageRequest {
            inner_type_prefix: tp,
            inner_bytes: [tp.to_be_bytes().as_slice(), &[tag; 40]].concat(),
        };
        let bundle = |requests: Vec<Option<CanonicalMessageRequest>>| {
            CanonicalMessageBundle { requests, timestamp: 1 }.to_canonical_bytes().unwrap()
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
            global_commit::commit_entry(&state, 100, &app, &entry, quil_types::execution::ShardPath::WHOLE).unwrap();
            state.commit().unwrap();
        };
        assert!(!ExecutionEngineManager::decided_globally(global.clone(), &app, &both));
        decide(&first, 20);
        assert!(!ExecutionEngineManager::decided_globally(global.clone(), &app, &both), "one still undecided");
        assert!(ExecutionEngineManager::decided_globally(global.clone(), &app, &bundle(vec![Some(first.clone())])));
        decide(&second, 21);
        assert!(ExecutionEngineManager::decided_globally(global.clone(), &app, &both));
        // Anything the global commit does not decide keeps the bundle pending.
        let mixed = bundle(vec![Some(first.clone()), Some(op(0x0404, 3))]);
        assert!(!ExecutionEngineManager::decided_globally(global.clone(), &app, &mixed));
        assert!(!ExecutionEngineManager::decided_globally(global.clone(), &app, &bundle(vec![Some(first), None])));
        assert!(!ExecutionEngineManager::decided_globally(global.clone(), &app, &bundle(Vec::new())));
        assert!(!ExecutionEngineManager::decided_globally(global.clone(), &[7; 32], &both), "decisions are per application");
        // A shard engine passes its filter, the application plus its bit path.
        let shard_filter = quil_forest::encode_shard_bit_path(&app, &[true, false, true]);
        assert!(ExecutionEngineManager::decided_globally(global.clone(), &shard_filter, &both), "a shard filter names its application");
        assert!(!ExecutionEngineManager::decided_globally(global.clone(), &app[..31], &both));
        assert!(!ExecutionEngineManager::decided_globally(global, &app, b"not a bundle"));
    }

    fn build_manager(include_global: bool) -> ExecutionEngineManager {
        let inclusion_prover: Arc<dyn InclusionProver> = Arc::new(NoopInclusionProver);
        let mem_store: Arc<dyn quil_types::store::HypergraphStore> =
            Arc::new(MemStore::new());
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

    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn app_history_commits_staged_accumulator_and_reopens_after_failed_write_retry() {
        use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        use crate::token_intrinsic::{accumulator_header, roots, settlement_record, spend_relay};
        use quil_lattice_ct::confidential::{
            AmountOpening, CommitmentKey,
            transfer::{network_identifier, parameter_context, Output},
        };
        use quil_types::store::ClockStore;

        let directory = tempfile::tempdir().unwrap();
        let application = domains::QUIL_TOKEN;
        let network = network_identifier(crate::pricing::MAINNET_NETWORK);
        let context = parameter_context(&network, &application);
        let settlements = vec![settlement_record::SettlementEntry {
            receipt: [1; 32], parameter_context: context, destination: [2; 32],
            context: [3; 32], settlement: 41, payment_address: [0; 32], payment: 0, claimant: [0; 32],
        }];
        // Spend framing is opaque at this persistence boundary.
        let spends = vec![vec![4; 24]];
        let expected_report;
        {
            let db = quil_store::RocksDb::open(directory.path()).unwrap();
            let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
            let prover = Arc::new(NoopInclusionProver);
            let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store.clone(), prover.clone()));
            crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
            let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
            let stubs = crate::testing::NoopExecutionCrypto::new();
            let manager = ExecutionEngineManager::new(
                prover, stubs.key_manager, crdt.clone(), stubs.circuit_compiler,
                clock.clone(), Arc::new(crate::testing::NoopHypergraphConfigResolver), false,
            );
            let state = HypergraphState::new(crdt.clone());
            let empty_snapshot = crdt.capture_committed_shard(&application).unwrap();
            assert!(manager.snapshot_accumulator_report(empty_snapshot.records.as_ref(), &application, 0).unwrap().is_empty());
            assert!(manager.snapshot_accumulator_report(store.as_ref(), &application, 0).is_err(),
                "a live-store adapter cannot supply isolated recovery reads");
            let output = Output {
                owner: [7; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context).commit(7, &AmountOpening::from_seed(&context, &[8; 32])),
                memo: [0; 1115],
            };
            let limits = crate::token_intrinsic::state::SnapshotLimits { max_coins: 8, max_depth: 32, max_nodes: 1 << 12 };
            let (address, tree) = roots::stage_coin(
                &state, &network, &application, &context, 1, &output, &mut Default::default(), limits,
            ).unwrap();
            state.set(&application, &address, &vertex_adds_discriminator().unwrap(), 1,
                quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
            roots::refresh_root(&state, &network, &application, limits).unwrap();
            state.commit().unwrap();
            state.abort();
            expected_report = manager.shard_accumulator_report(&application, 0).unwrap();
            assert!(!expected_report.is_empty(), "the report must include uncommitted coin state");
            assert!(manager.snapshot_accumulator_report(empty_snapshot.records.as_ref(), &application, 0).unwrap().is_empty(),
                "snapshot reports must not include staged coins or the private summary");

            // Malformed history cannot commit the already-staged state/cursor.
            assert!(manager.commit_frame_with_app_history(1, &application, 123, &settlements, &[vec![]], 0).is_err());
            assert_eq!(manager.read_app_materialized_cursor(&application).unwrap(), 0);
            store.fail_commit_for_test(true);
            assert!(manager.commit_frame_with_app_history(1, &application, 123, &settlements, &spends, 0).is_err());
            assert_eq!(manager.read_app_materialized_cursor(&application).unwrap(), 0);
            assert!(clock.get_shard_frame_fee_total(&application, 1).unwrap().is_none());
            assert!(clock.get_shard_frame_settlements(&application, 1).unwrap().is_none());
            assert!(clock.get_shard_frame_spends(&application, 1).unwrap().is_none());
            assert!(clock.get_shard_frame_accumulator(&application, 1).unwrap().is_none());
            assert!(clock.get_shard_accumulator_report(&application, &accumulator_header::report_digest(&expected_report)).unwrap().is_none());
            store.fail_commit_for_test(false);
            assert_eq!(manager.commit_frame_with_app_history(1, &application, 123, &settlements, &spends, 0).unwrap(), expected_report);
            assert_eq!(manager.shard_accumulator_report(&application, 0).unwrap(), expected_report,
                "the report calculated before commit must match committed state");
            let committed = crdt.capture_committed_shard(&application).unwrap();
            assert_eq!(manager.snapshot_accumulator_report(committed.records.as_ref(), &application, 0).unwrap(), expected_report);
            assert!(manager.snapshot_accumulator_report(empty_snapshot.records.as_ref(), &application, 0).unwrap().is_empty(),
                "an earlier snapshot stays empty after the live commit");
            state.set(&application, &crate::token_intrinsic::state::BLOCK_SUMMARY_ADDRESS,
                &vertex_adds_discriminator().unwrap(), 2, b"broken private summary".to_vec()).unwrap();
            state.commit().unwrap();
            state.abort();
            assert!(manager.shard_accumulator_report(&application, 0).is_err());
            assert_eq!(manager.snapshot_accumulator_report(committed.records.as_ref(), &application, 0).unwrap(), expected_report,
                "recovery reads block records and ignores live private-summary corruption");
        }
        // Every previous handle is dropped: reopen the real database, with no
        // outflow cache, and recover both the state and all future-header inputs.
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = quil_hypergraph::HypergraphCrdt::new(store, Arc::new(NoopInclusionProver));
        crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
        assert_eq!(crdt.read_frame_cursor(&quil_store::encoding::consensus_materialized_cursor_key(&application)).unwrap(), 1);
        let clock = quil_store::RocksClockStore::new(db.inner());
        assert_eq!(clock.get_shard_frame_fee_total(&application, 1).unwrap(), Some(123));
        assert_eq!(settlement_record::decode_entries(&clock.get_shard_frame_settlements(&application, 1).unwrap().unwrap()).unwrap(), settlements);
        assert_eq!(spend_relay::decode_frame_entries(&clock.get_shard_frame_spends(&application, 1).unwrap().unwrap()).unwrap(), spends);
        let digest = clock.get_shard_frame_accumulator(&application, 1).unwrap().unwrap();
        assert_eq!(digest, accumulator_header::report_digest(&expected_report));
        assert_eq!(clock.get_shard_accumulator_report(&application, &digest).unwrap(), Some(expected_report.clone()));
        let state = HypergraphState::new(Arc::new(crdt));
        assert_eq!(crate::token_intrinsic::shard_accumulator::shard_report(&state, &network, &application, &[], false)
            .unwrap().unwrap().encode().unwrap(), expected_report);
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
            coin_tree::Frontier, AmountOpening, CommitmentKey,
            transfer::{network_identifier, parameter_context},
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
            let mut frontier = Frontier::new(&context, usize::from(coin_blocks::SUBTREE_BITS)).unwrap();
            let commitment = key.commit(u128::from(seed), &AmountOpening::from_seed(&context, &[seed; 32]));
            frontier.append(&[seed; IDENTITY_BYTES], &commitment).unwrap();
            let root = frontier.root_at_depth(usize::from(coin_blocks::SUBTREE_BITS)).unwrap().root;
            summary.put(block, frontier.count(), root.clone()).unwrap();
            for (tag, bytes) in [(state::BLOCK_FRONTIER_TAG, frontier.encode()),
                                 (state::BLOCK_ROOT_TAG, root.to_bytes().to_vec())] {
                let address = state::block_record_address(tag, block);
                before.set(&application, &address, &disc, 0, bytes.clone()).unwrap();
                imported.set(&application, &address, &disc, 0, bytes.clone()).unwrap();
                saved.push((address, bytes));
            }
        }
        before.set(&application, &state::BLOCK_SUMMARY_ADDRESS, &disc, 0, summary.encode()).unwrap();
        before.commit().unwrap();
        imported.commit().unwrap();
        imported.abort();
        let expected = source.shard_accumulator_report(&filter, 0).unwrap();
        assert!(!expected.is_empty());
        assert!(recovered.shard_accumulator_report(&filter, 0).unwrap().is_empty(),
            "imported block data alone did not populate the private summary");
        recovered.rebuild_block_summary_before_report(&filter);
        assert_eq!(recovered.commit_frame_with_app_history(76, &filter, 0, &[], &[], 0).unwrap(), expected,
            "the first replay after sync must record the inherited coins");
        assert_eq!(roots::block_summary(&imported, &application).unwrap().blocks.len(), 2,
            "the rebuilt private summary excludes stale data outside the covered range");

        // A nonempty summary from the old allocation must be rebuilt as well.
        summary.blocks.retain(|(block, _, _)| !coin_blocks::shard_owns_block(&shard, *block));
        imported.set(&application, &state::BLOCK_SUMMARY_ADDRESS, &disc, 0, summary.encode()).unwrap();
        imported.commit().unwrap();
        imported.abort();
        assert!(recovered.shard_accumulator_report(&filter, 0).unwrap().is_empty());
        recovered.rebuild_block_summary_before_report(&filter);
        assert_eq!(recovered.shard_accumulator_report(&filter, 0).unwrap(), expected);

        // A damaged import must fail before replacing the summary. Retrying
        // after its block is repaired needs no second invalidation signal.
        let (address, bytes) = saved.iter().find(|(address, _)| *address ==
            state::block_record_address(state::BLOCK_ROOT_TAG, coin_blocks::block_id(6, 0).unwrap())).unwrap();
        let previous = roots::block_summary(&imported, &application).unwrap().encode();
        imported.set(&application, address, &disc, 0,
            quil_lattice_ct::confidential::relation::membership::Node::zero().to_bytes().to_vec()).unwrap();
        imported.commit().unwrap();
        imported.abort();
        recovered.rebuild_block_summary_before_report(&filter);
        assert!(recovered.shard_accumulator_report(&filter, 0).is_err());
        assert_eq!(roots::block_summary(&imported, &application).unwrap().encode(), previous);
        imported.set(&application, address, &disc, 0, bytes.clone()).unwrap();
        imported.commit().unwrap();
        imported.abort();
        assert_eq!(recovered.shard_accumulator_report(&filter, 0).unwrap(), expected);
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
        assert!(manager.shard_accumulator_report(&filter, 0).unwrap().is_empty());
        let state = HypergraphState::new(manager.crdt());
        let disc = vertex_adds_discriminator().unwrap();
        assert!(state.get(&application, &BLOCK_SUMMARY_ADDRESS, &disc).unwrap().is_none());
        assert!(state.get(&application, &ROOT_ADDRESS, &disc).unwrap().is_none());
    }

    /// The frames of a shard holding the whole application are stored under
    /// the bare application address, so that is the filter a delivery looks
    /// its operation up by — not the empty path's own encoding, which names
    /// no stored frame and would stall every delivery.
    #[cfg(feature = "native-proof")]
    #[test]
    fn the_executing_filter_of_a_whole_application_is_its_address() {
        let application = [3u8; 32];
        assert_eq!(super::executing_filter(&application, &[]), application.to_vec());
        for shard in [vec![false], vec![true, false, true]] {
            let filter = super::executing_filter(&application, &shard);
            assert_eq!(
                quil_forest::decode_shard_filter_or_root(&filter, 32),
                Some((application.to_vec(), shard.clone())),
            );
        }
        // Both forms decode to the same application, and only the bare one is
        // what a whole-application shard files its frames under.
        assert_ne!(super::executing_filter(&application, &[]), quil_forest::encode_shard_bit_path(&application, &[]));
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
        let transfer = Transfer { statement: TransferStatement { network, application, depth: 1,
            root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(), images: vec![[5; IDENTITY_BYTES]], fee: 7,
            outputs: vec![Output { commitment: CommitmentKey::derive(&context).commit(10, &AmountOpening::from_seed(&context, &[2; 32])),
                owner: [3; IDENTITY_BYTES], memo: [4; MEMO_BYTES] }] }, proof }.encode().unwrap();
        // Something that is not relayed: an app-venue operation of another kind.
        let mut app_venue = vec![0u8; 16];
        app_venue[..4].copy_from_slice(&0x0999u32.to_be_bytes());
        assert!(!crate::token_intrinsic::spend_entries::commits_globally(&application, 0x0999));
        let bundle = |requests: Vec<Vec<u8>>| CanonicalMessageBundle {
            requests: requests.into_iter().map(|r| Some(CanonicalMessageRequest::wrap(r).unwrap())).collect(), timestamp: 0,
        }.to_canonical_bytes().unwrap();
        let manager = build_manager(true);

        assert!(manager.message_commits_globally(&application, &bundle(vec![transfer.clone()])));
        // A single request, not wrapped in a bundle, is the wallet's own shape.
        let single = CanonicalMessageRequest::wrap(transfer.clone()).unwrap().to_canonical_bytes().unwrap();
        assert!(manager.message_commits_globally(&application, &single));
        // Mixed, empty and malformed stay on the app vote.
        assert!(!manager.message_commits_globally(&application, &bundle(vec![transfer.clone(), app_venue.clone()])));
        assert!(!manager.message_commits_globally(&application, &bundle(vec![])));
        assert!(!manager.message_commits_globally(&application, &[0, 1]));
    }

    #[cfg(feature = "confidential-tokens")]
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
        let transfer = Transfer { statement: TransferStatement { network, application: domains::QUIL_TOKEN, depth: 1,
            root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(), images: vec![[5; IDENTITY_BYTES]], fee: 7,
            outputs: vec![Output { commitment: CommitmentKey::derive(&context).commit(10, &AmountOpening::from_seed(&context, &[2; 32])),
                owner: [3; IDENTITY_BYTES], memo: [4; MEMO_BYTES] }] }, proof }.encode().unwrap();
        let app = [0x44; 32];
        let claim = SettlementClaim { network, application: app, cited_global_frame: 1, global_root: [0; 32], receipt: [9; 32],
            settlement: 500, context: [8; 32], payment_address: [0; 32], payment: 0, forest_proof: vec![1; 8],
            claimant_key_type: 0, claimant_public_key: Vec::new(), claimant_signature: Vec::new() }.encode().unwrap();
        let bundle = |requests: Vec<Vec<u8>>| CanonicalMessageBundle {
            requests: requests.into_iter().map(|r| Some(CanonicalMessageRequest::wrap(r).unwrap())).collect(), timestamp: 0,
        }.to_canonical_bytes().unwrap();
        let manager = build_manager(true);
        let mixed = bundle(vec![claim.clone(), transfer.clone()]);
        // QUIL: neither the transfer's fee — it commits through the global
        // frame and is credited there, only if it commits — nor an
        // (unverified there) claim.
        assert_eq!(manager.message_token_fees(&domains::QUIL_TOKEN, &mixed).unwrap(), 0);
        // Another application: only the claim it verified, never QUIL fees it skipped.
        assert_eq!(manager.message_token_fees(&app, &mixed).unwrap(), 500);
        assert_eq!(manager.message_token_fees(&app, &bundle(vec![transfer.clone()])).unwrap(), 0);
        // The global intrinsic credits nothing for application operations it skips.
        assert_eq!(manager.message_token_fees(&domains::GLOBAL, &mixed).unwrap(), 0);
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
        let inner = Transfer { statement: TransferStatement { network, application, depth: 1,
            root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(), images: vec![[5; IDENTITY_BYTES]], fee: 7,
            outputs: vec![Output { commitment: CommitmentKey::derive(&context).commit(10, &AmountOpening::from_seed(&context, &[2; 32])),
                owner: [3; IDENTITY_BYTES], memo: [4; MEMO_BYTES] }] }, proof }.encode().unwrap();
        let request = CanonicalMessageRequest::wrap(inner.clone()).unwrap();
        let other = CanonicalMessageRequest::wrap(vec![0x00, 0x04, 0x04, 0x00, 1, 2, 3, 4]).unwrap();
        let bundle = |requests: Vec<CanonicalMessageRequest>| CanonicalMessageBundle {
            requests: requests.into_iter().map(Some).collect(), timestamp: 0,
        }.to_canonical_bytes().unwrap();
        for include_global in [true, false] {
            let manager = build_manager(include_global);
            // Token cost is the staged state growth, not the payload length.
            let expected = BigInt::from(crate::token_intrinsic::cost::state_growth(&inner).unwrap());
            assert!(expected > BigInt::from(0));
            assert_eq!(manager.get_cost(&request.to_canonical_bytes().unwrap()).unwrap(), expected);
            assert_eq!(manager.get_cost(&bundle(vec![request.clone(), request.clone()])).unwrap(), &expected * 2u8);
            // Non-token requests retain their current cost, in either order.
            assert_eq!(manager.get_cost(&other.to_canonical_bytes().unwrap()).unwrap(), BigInt::from(0));
            assert_eq!(manager.get_cost(&bundle(vec![request.clone(), other.clone()])).unwrap(), expected);
            assert_eq!(manager.get_cost(&bundle(vec![other.clone(), request.clone()])).unwrap(), expected);
            assert_eq!(manager.get_cost(&bundle(vec![request.clone(), other.clone(), request.clone()])).unwrap(), &expected * 2u8);
            let with_empty_slots = CanonicalMessageBundle { requests: vec![None, Some(other.clone()), Some(request.clone()), None], timestamp: 0 }.to_canonical_bytes().unwrap();
            assert_eq!(manager.get_cost(&with_empty_slots).unwrap(), expected);
            let mut malformed = bundle(vec![request.clone()]); malformed.pop();
            assert!(manager.get_cost(&malformed).is_err());
            assert_eq!(manager.get_cost(&bundle(Vec::new())).unwrap(), BigInt::from(0));
            assert_eq!(manager.get_cost(b"\x00\x00").unwrap(), BigInt::from(0));
        }
    }

    #[cfg(feature = "native-proof")]
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
                network, application, transparent_address: [3; 32],
                owner_public_key: [4; 57], amount: 12, fee: 2,
                outputs: vec![Output { commitment: key.commit(10, &opening),
                    owner: [5; IDENTITY_BYTES], memo: [6; MEMO_BYTES] }],
            },
            signature: [0; 114], proof,
        };
        let wrap = |bytes| crate::message_envelope::CanonicalMessageRequest::wrap(bytes)
            .unwrap().to_canonical_bytes().unwrap();
        let bytes = wrap(tx.encode().unwrap());
        let policy = TokenPolicy {
            network, limits: CompileLimits { max_inputs: 2, max_outputs: 2, max_depth: 3 },
            snapshots: SnapshotLimits { max_coins: 8, max_depth: 3, max_nodes: 24 },
            native_budget: NativeBudget { max_native_bytes: 0 },
        };
        let directory = tempfile::tempdir().unwrap();
        let worker = WorkerVerifier::new(directory.path().join("absent-worker"), 1,
            std::time::Duration::from_secs(2)).unwrap();
        for global in [false, true] {
            let manager = build_manager(global);
            assert!(manager.validate_message(2, &application, &bytes).is_err());
            let manager = manager.with_token_worker(policy, worker.clone()).unwrap();
            manager.validate_message(2, &application, &bytes).unwrap();
            // A structurally encoded transaction from a different network fails.
            let mut other = tx.clone();
            other.statement.network = [9; 32];
            let wrong_context = wrap(other.encode().unwrap());
            assert!(manager.validate_message(2, &application, &wrong_context).is_err());
            // Configuration must preserve the original execution venue.
            let mut mint = tx.encode().unwrap();
            mint[..4].copy_from_slice(&crate::token_engine::TYPE_LATTICE_MINT.to_be_bytes());
            let error = manager.validate_message(2, &application, &wrap(mint)).unwrap_err().to_string();
            assert_eq!(error.contains("requires serialized global execution"), !global);
        }
        let mut missing = build_manager(true);
        missing.engines.get_mut().unwrap().remove("token");
        assert!(missing.with_token_worker(policy, worker.clone()).is_err());
        let mut wrong = build_manager(true);
        let compute = wrong.engines.get_mut().unwrap().remove("compute").unwrap();
        wrong.engines.get_mut().unwrap().insert("token".into(), compute);
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
        let cases: [( [u8; 32], &str); 3] = [
            (crate::token_intrinsic::constants::token_base_domain(), "token"),
            (crate::domains::COMPUTE, "compute"),
            (crate::hypergraph_intrinsic::hypergraph_base_domain(), "hypergraph"),
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
            fn get_name(&self) -> &str { self.inner.get_name() }
            fn validate_message(&self,f:u64,a:&[u8],m:&[u8])->Result<()> { self.inner.validate_message(f,a,m) }
            fn process_message(&self,_:u64,_:&BigInt,_:&[u8],_:&[u8])->Result<ProcessMessageResult> {
                panic!("manager must forward explicit execution context")
            }
            fn process_message_with_context(&self,c:FrameExecutionContext,fee:&BigInt,a:&[u8],m:&[u8])->Result<ProcessMessageResult> {
                self.seen.lock().unwrap().push(c);
                self.inner.process_message_with_context(c,fee,a,m)
            }
            fn prove(&self,a:&[u8],f:u64,m:&[u8])->Result<quil_types::proto::global::MessageRequest> { self.inner.prove(a,f,m) }
            fn lock(&self,f:u64,a:&[u8],m:&[u8])->Result<Vec<Vec<u8>>> { self.inner.lock(f,a,m) }
            fn unlock(&self)->Result<()> { self.inner.unlock() }
            fn get_cost(&self,m:&[u8])->Result<BigInt> { self.inner.get_cost(m) }
            fn get_capabilities(&self)->Vec<node::Capability> { self.inner.get_capabilities() }
        }
        let m=build_manager(false);
        let seen=Arc::new(std::sync::Mutex::new(Vec::new()));
        {
            let mut engines=m.engines.write().unwrap();
            let inner=engines.remove("token").unwrap();
            engines.insert("token".into(),Box::new(Recorder { inner,seen:seen.clone() }));
        }
        let context=FrameExecutionContext { frame_number:7,finalized_global_frame:Some(913), venue: None, shard: quil_types::execution::ShardPath::WHOLE };
        m.process_message_with_context(context,&BigInt::from(0),&domains::QUIL_TOKEN,b"").unwrap();
        m.process_message(8,&BigInt::from(0),&domains::QUIL_TOKEN,b"").unwrap();
        assert_eq!(*seen.lock().unwrap(),vec![context,FrameExecutionContext { frame_number:8,finalized_global_frame:None, venue: None, shard: quil_types::execution::ShardPath::WHOLE }]);
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
                | crate::token_intrinsic::constants::EXPIRABLE)
                as u32,
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
        // does for a deploy).
        let token_base = crate::token_intrinsic::constants::token_base_domain();
        m.process_message(0, &BigInt::from(1), &token_base, &bundle_bytes)
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
