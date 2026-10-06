//! Own a complete same-store execution context over one captured generation.
//! This is not consensus-parent authentication or canonical publication.
use super::*;
use crate::prover_registry::{RegistryLimits, RegistryUsage, SharedProverRegistry};
use quil_hypergraph::{ExecutionForkLimits, ExecutionMetadataUsage};
use quil_store::{OverlayClockStore, OverlayHypergraphStore, OverlayShardsStore};
use quil_types::store::{ClockStore, HypergraphStore, ShardsStore};
use std::sync::RwLockWriteGuard;

#[cfg(test)]
#[path = "execution_branch_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug)]
pub struct ExecutionBranchLimits {
    pub state: ExecutionForkLimits,
    pub registry: RegistryLimits,
    /// Pending application summary rebuilds copied from the source manager.
    /// Each entry contains a fixed 32-byte address plus set overhead.
    pub max_summary_rebuilds: usize,
}

struct OwnedOverlay(Arc<quil_forest::ExecutionOverlay>);
impl Drop for OwnedOverlay {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// The branch owns its captured storage lifetime. Dropping it closes storage
/// even when a consumer retained a manager/store handle. Descendant branches
/// retain their own independent captured generation and remain usable.
///
/// Execution and maintenance must be serialized by the owner. All retained
/// engines, clocks, shard metadata and registry belong to this branch, but
/// cached reads alone do not attest that a branch is open or consensus-valid.
pub struct ExecutionBranch {
    storage: OwnedOverlay,
    manager: Arc<ExecutionEngineManager>,
    store: Arc<OverlayHypergraphStore>,
    clock: Arc<OverlayClockStore>,
    shards: Option<Arc<OverlayShardsStore>>,
    registry: SharedProverRegistry,
    metadata: ExecutionMetadataUsage,
}

/// Retains the source mutation barriers through private execution and adoption.
/// Constructed together with the branch it protects. Do not reenter source
/// engines, CRDT mutation, fee publication or summary maintenance while held.
pub struct ExecutionPublicationGuard<'a> {
    source: &'a ExecutionEngineManager,
    capture: quil_hypergraph::ExecutionCapture<'a>,
    engines: RwLockWriteGuard<'a, HashMap<String, Box<dyn ShardExecutionEngine>>>,
    global_quil_fee: RwLockWriteGuard<'a, Option<crate::pricing::GlobalQuilFeeSnapshot>>,
    global_venue_fee: RwLockWriteGuard<'a, Option<crate::pricing::GlobalQuilFeeSnapshot>>,
    summary_rebuilds: RwLockWriteGuard<'a, std::collections::HashSet<[u8; 32]>>,
    overlay: quil_types::store::BackingStoreIdentity,
    limits: ExecutionBranchLimits,
}

impl ExecutionBranch {
    pub fn manager(&self) -> &Arc<ExecutionEngineManager> {
        &self.manager
    }
    pub fn hypergraph_store(&self) -> &Arc<OverlayHypergraphStore> {
        &self.store
    }
    pub fn clock_store(&self) -> &Arc<OverlayClockStore> {
        &self.clock
    }
    pub fn shards_store(&self) -> Option<&Arc<OverlayShardsStore>> {
        self.shards.as_ref()
    }
    pub fn registry(&self) -> &SharedProverRegistry {
        &self.registry
    }
    pub fn overlay(&self) -> &Arc<quil_forest::ExecutionOverlay> {
        &self.storage.0
    }
    pub fn metadata_usage(&self) -> ExecutionMetadataUsage {
        self.metadata
    }
    pub fn registry_usage(&self) -> RegistryUsage {
        self.registry.read(|r| r.resource_usage())
    }
}

impl ExecutionEngineManager {
    /// Capture CRDT metadata, record state and all same-database providers,
    /// then reconstruct the configured engines and an independent registry.
    /// Uses a pinned read view; it never copies or writes the primary store.
    ///
    /// The caller must hold its whole-frame materialization/sync barrier,
    /// including direct-store/reset/cutover hooks and fee publication. The
    /// internal CRDT barrier alone does not cover those external operations.
    /// Do not call with the source CRDT capture/forest lock already held.
    /// Active engine users cause a retryable error instead of lock inversion.
    ///
    /// Providers backed by a separate GLOBAL database are rejected: those
    /// require an explicitly captured and authenticated external anchor view.
    /// Per-branch limits do not replace aggregate, lifetime or disk policy.
    pub fn capture_execution_branch(
        &self,
        limits: ExecutionBranchLimits,
    ) -> Result<ExecutionBranch> {
        let (branch, _guard) = self.capture_execution_branch_guarded(limits)?;
        Ok(branch)
    }

    /// [`Self::capture_execution_branch`], copying `registry` into the branch
    /// when its last scan is provably the captured rows (see
    /// [`SharedProverRegistry::for_execution_capture`]) instead of reading
    /// every prover vertex through the branch again.
    pub fn capture_execution_branch_seeded(
        &self,
        limits: ExecutionBranchLimits,
        registry: &SharedProverRegistry,
    ) -> Result<ExecutionBranch> {
        let (branch, _guard) = self.capture_execution_branch_inner(limits, None, Some(registry))?;
        Ok(branch)
    }

    /// Keep the canonical source unchanged until the returned guard is dropped.
    /// Direct database writers remain possible and are checked by the atomic
    /// storage publication's sequence barrier. The caller also holds its frame
    /// lock, and must authenticate the input independently of this capture.
    pub fn capture_execution_branch_guarded(
        &self,
        limits: ExecutionBranchLimits,
    ) -> Result<(ExecutionBranch, ExecutionPublicationGuard<'_>)> {
        self.capture_execution_branch_inner(limits, None, None)
    }

    /// [`Self::capture_execution_branch_guarded`] with a registry seed, as in
    /// [`Self::capture_execution_branch_seeded`].
    pub fn capture_execution_branch_guarded_seeded(
        &self,
        limits: ExecutionBranchLimits,
        registry: &SharedProverRegistry,
    ) -> Result<(ExecutionBranch, ExecutionPublicationGuard<'_>)> {
        self.capture_execution_branch_inner(limits, None, Some(registry))
    }

    /// Private execution for a worker whose engines read GLOBAL frames from a
    /// separate store (a thread worker's master clock). Engine GLOBAL reads go
    /// through a read-only view bounded to `max_global_frame`, which the caller
    /// has authenticated as the input's anchor. The branch can never publish:
    /// no publication guard is returned and its GLOBAL provider has no identity.
    pub fn capture_anchored_execution_branch(
        &self,
        limits: ExecutionBranchLimits,
        anchor: Arc<dyn ClockStore>,
        max_global_frame: u64,
    ) -> Result<ExecutionBranch> {
        let identity = anchor.backing_store_identity().ok_or_else(|| {
            QuilError::ExecutionUnavailable("GLOBAL anchor store requires an identity".into())
        })?;
        let view = crate::global_anchor_view::GlobalAnchorView::new(anchor, max_global_frame);
        let (branch, _guard) =
            self.capture_execution_branch_inner(limits, Some((identity, Arc::new(view))), None)?;
        Ok(branch)
    }

    fn capture_execution_branch_inner(
        &self,
        limits: ExecutionBranchLimits,
        anchor: Option<(
            quil_types::store::BackingStoreIdentity,
            Arc<crate::global_anchor_view::GlobalAnchorView>,
        )>,
        seed: Option<&SharedProverRegistry>,
    ) -> Result<(ExecutionBranch, ExecutionPublicationGuard<'_>)> {
        let anchor_identity = anchor.as_ref().map(|(identity, _)| identity);
        let identity = self.crdt.backing_store_identity().ok_or_else(|| {
            QuilError::ExecutionUnavailable("execution branch requires identifiable storage".into())
        })?;
        let capture = self.crdt.lock_execution_capture()?;
        // An executor may hold this lock while acquiring the CRDT commit lock.
        // Never wait on it with the capture barrier held.
        let engines = self.engines.try_write().map_err(|_| {
            QuilError::ExecutionUnavailable("execution branch engines are busy or poisoned".into())
        })?;
        for required in ["token", "compute", "hypergraph"] {
            if !engines.contains_key(required) {
                return Err(QuilError::ExecutionUnavailable(format!(
                    "capture requires {required} engine"
                )));
            }
        }
        if self
            .shards_store
            .as_ref()
            .is_some_and(|s| s.backing_store_identity().as_ref() != Some(&identity))
        {
            return Err(QuilError::ExecutionUnavailable(
                "execution branch shard store mismatch".into(),
            ));
        }
        for (name, engine) in engines.iter() {
            let any = engine.as_any().ok_or_else(|| unavailable_engine(name))?;
            match name.as_str() {
                "global" => any
                    .downcast_ref::<GlobalExecutionEngine>()
                    .ok_or_else(|| unavailable_engine(name))?
                    .check_execution_capture(&self.crdt, &identity)?,
                "token" => any
                    .downcast_ref::<TokenExecutionEngine>()
                    .ok_or_else(|| unavailable_engine(name))?
                    .check_execution_capture(&self.crdt, &identity, anchor_identity)?,
                "compute" => any
                    .downcast_ref::<ComputeExecutionEngine>()
                    .ok_or_else(|| unavailable_engine(name))?
                    .check_execution_capture(&self.crdt, &identity, anchor_identity)?,
                "hypergraph" => any
                    .downcast_ref::<HypergraphExecutionEngine>()
                    .ok_or_else(|| unavailable_engine(name))?
                    .check_execution_capture(&self.crdt, &identity, anchor_identity)?,
                _ => return Err(unavailable_engine(name)),
            }
        }
        let mut store = None;
        let captured = capture.fork(limits.state, |overlay| {
            let result = Arc::new(OverlayHypergraphStore::new(overlay));
            store = Some(result.clone());
            Ok(result as Arc<dyn HypergraphStore>)
        })?;
        // Establish cleanup before any later fallible operation.
        let storage = OwnedOverlay(captured.overlay);
        let store = store.ok_or_else(|| {
            QuilError::ExecutionUnavailable("capture omitted record store".into())
        })?;
        let clock = Arc::new(OverlayClockStore::new(storage.0.clone()));
        let shards = self
            .shards_store
            .as_ref()
            .map(|_| Arc::new(OverlayShardsStore::new(storage.0.clone())));
        let registry = SharedProverRegistry::for_execution_capture(
            store.as_ref(),
            limits.registry,
            seed,
            storage.0.capture_point(),
        )?;
        let global_clock_store: Arc<dyn ClockStore> = match &anchor {
            Some((_, view)) => view.clone(),
            None => clock.clone(),
        };
        let context = ExecutionForkContext {
            crdt: captured.crdt,
            clock_store: clock.clone(),
            global_clock_store,
            shards_store: shards.as_ref().map(|s| s.clone() as Arc<dyn ShardsStore>),
            prover_registry: Arc::new(registry.clone()),
        };
        let manager = Arc::new(self.fork_with_locked_engines(
            context,
            &engines,
            Some(limits.max_summary_rebuilds),
        )?);
        if !storage.0.execution_healthy() {
            return Err(QuilError::ExecutionUnavailable(
                "captured execution storage has a prior failure".into(),
            ));
        }
        let branch = ExecutionBranch {
            storage,
            manager,
            store,
            clock,
            shards,
            registry,
            metadata: captured.metadata,
        };
        // These publishers need not take the engine lock. Acquire them without
        // waiting under the CRDT barrier, and reject a change during capture.
        let global_quil_fee = self.global_quil_fee.try_write().map_err(|_| {
            QuilError::ExecutionUnavailable(
                "execution source fee snapshot is busy or poisoned".into(),
            )
        })?;
        let global_venue_fee = self.global_venue_fee.try_write().map_err(|_| {
            QuilError::ExecutionUnavailable(
                "execution source venue fee snapshot is busy or poisoned".into(),
            )
        })?;
        let summary_rebuilds = self.summary_rebuilds.try_write().map_err(|_| {
            QuilError::ExecutionUnavailable(
                "execution source summary metadata is busy or poisoned".into(),
            )
        })?;
        if *global_quil_fee
            != *branch
                .manager
                .global_quil_fee
                .read()
                .map_err(|_| unavailable_engine("fee"))?
            || *global_venue_fee
                != *branch
                    .manager
                    .global_venue_fee
                    .read()
                    .map_err(|_| unavailable_engine("venue fee"))?
            || *summary_rebuilds
                != *branch
                    .manager
                    .summary_rebuilds
                    .read()
                    .map_err(|_| unavailable_engine("summary"))?
        {
            return Err(QuilError::ExecutionUnavailable(
                "execution source metadata changed during capture".into(),
            ));
        }
        let overlay = quil_types::store::BackingStoreIdentity::of(branch.overlay());
        Ok((
            branch,
            ExecutionPublicationGuard {
                source: self,
                capture,
                engines,
                global_quil_fee,
                global_venue_fee,
                summary_rebuilds,
                overlay,
                limits,
            },
        ))
    }
}

impl ExecutionPublicationGuard<'_> {
    /// Atomically publish this guard's branch and adopt its complete execution
    /// provider state. The caller authenticates finality and owns the frame
    /// lock. `adopt_frame` only moves already-prepared metadata under the retained
    /// database barrier; it must not lock, perform I/O or call public observers.
    /// Public progress/callbacks run after this guard is released.
    pub fn publish(
        &mut self,
        branch: &mut ExecutionBranch,
        context: ExecutionForkContext,
        registry: &SharedProverRegistry,
        adopt_frame: impl FnOnce(Arc<dyn quil_types::store::SnapshotReadable>),
    ) -> Result<()> {
        let _close = OwnedOverlay(branch.overlay().clone());
        if quil_types::store::BackingStoreIdentity::of(branch.overlay()) != self.overlay
            || !branch.overlay().execution_healthy()
            || branch.overlay().stats().closed
        {
            return Err(QuilError::ExecutionUnavailable(
                "publication does not own this healthy branch".into(),
            ));
        }
        let db = self.capture.database()?;
        let identity = db.backing_store_identity();
        if !Arc::ptr_eq(&context.crdt, &self.source.crdt)
            || context.clock_store.backing_store_identity().as_ref() != Some(&identity)
            || context.global_clock_store.backing_store_identity().as_ref() != Some(&identity)
            || context.shards_store.is_some() != self.source.shards_store.is_some()
            || context
                .shards_store
                .as_ref()
                .is_some_and(|s| s.backing_store_identity().as_ref() != Some(&identity))
            || !context
                .prover_registry
                .as_any()
                .and_then(|r| r.downcast_ref::<SharedProverRegistry>())
                .is_some_and(|r| r.shares_cache_with(registry))
        {
            return Err(QuilError::ExecutionUnavailable(
                "canonical publication provider mismatch".into(),
            ));
        }
        let mut timing = PublicationSteps::start();
        // A newly accepted registration must be visible after this frame, even
        // if the branch's once-per-epoch maintenance refresh preceded it. Only
        // the records the branch's registry rows feed are re-read.
        let refreshed = branch.overlay().delta_generation();
        branch.registry.update_written_rows(branch.store.as_ref(), branch.overlay())?;
        timing.mark("update registry");
        let branch_engines = branch.manager.engines.try_read().map_err(|_| {
            QuilError::ExecutionUnavailable("private execution engines are busy or poisoned".into())
        })?;
        if branch_engines.len() != self.engines.len()
            || !branch_engines
                .keys()
                .all(|name| self.engines.contains_key(name))
        {
            return Err(QuilError::ExecutionUnavailable(
                "private execution engine set changed".into(),
            ));
        }
        let clock = context.clock_store.clone();
        let global_clock = context.global_clock_store.clone();
        let prepared = branch.manager.fork_with_locked_engines(
            context,
            &branch_engines,
            Some(self.limits.max_summary_rebuilds),
        )?;
        drop(branch_engines);
        timing.mark("fork engines");
        // Resolve every fallible lock and allocation before the durable batch.
        let engines = prepared
            .engines
            .into_inner()
            .map_err(|_| unavailable_engine("prepared engines"))?;
        let fee = prepared
            .global_quil_fee
            .into_inner()
            .map_err(|_| unavailable_engine("prepared fee"))?;
        let venue_fee = prepared
            .global_venue_fee
            .into_inner()
            .map_err(|_| unavailable_engine("prepared venue fee"))?;
        let summaries = prepared
            .summary_rebuilds
            .into_inner()
            .map_err(|_| unavailable_engine("prepared summary"))?;
        let mut registry = registry.prepare_adoption(&branch.registry, &self.overlay)?;
        let mut clock_cache = clock.prepare_execution_publication()?;
        let mut global_clock_cache = if Arc::ptr_eq(&clock, &global_clock) {
            None
        } else {
            Some(global_clock.prepare_execution_publication()?)
        };
        let mut crdt = self.capture.prepare_adoption(
            &branch.manager.crdt,
            branch.overlay(),
            self.limits.state,
            |overlay| Ok(Arc::new(OverlayHypergraphStore::new(overlay))),
        )?;
        let plan = branch.overlay().prepare_commit().map_err(|e| {
            QuilError::ExecutionUnavailable(format!("prepare canonical execution: {e}"))
        })?;
        timing.mark("prepare adoption");
        let mut write = db.lock_writes().map_err(|e| {
            QuilError::ExecutionUnavailable(format!("canonical write barrier: {e}"))
        })?;
        timing.mark("wait for write barrier");
        // The refreshed registry holds the published rows exactly when it read
        // the delta this plan commits and nothing else wrote them since capture.
        let registry_rows_published = plan.delta_generation() == refreshed
            && write
                .watched_write_sequence()
                .is_some_and(|watched| watched <= plan.base_sequence());
        plan.commit_locked(&mut write).map_err(|e| {
            QuilError::ExecutionUnavailable(format!("canonical execution commit: {e}"))
        })?;
        timing.mark("synced commit");
        let published = db.latest_sequence_number();
        let snapshot = Arc::new(quil_store::RocksHypergraphSnapshot::from_database(
            db.clone(),
        ));
        crdt.adopt();
        *self.engines = engines;
        *self.global_quil_fee = fee;
        *self.global_venue_fee = venue_fee;
        *self.summary_rebuilds = summaries;
        registry.adopt();
        if registry_rows_published {
            registry.published_at(quil_types::store::ScanPoint {
                database: db.instance(),
                from: published,
                to: published,
            });
        }
        clock_cache.adopt();
        if let Some(cache) = global_clock_cache.as_mut() {
            cache.adopt();
        }
        adopt_frame(snapshot);
        timing.mark("adopt");
        Ok(())
    }
}

/// One publication's steps, logged together when it took a second or more:
/// its caller holds the node's frame lock and GLOBAL execution lease.
struct PublicationSteps {
    started: std::time::Instant,
    last: std::time::Instant,
    steps: Vec<(&'static str, u128)>,
}

impl PublicationSteps {
    fn start() -> Self {
        let now = std::time::Instant::now();
        Self { started: now, last: now, steps: Vec::new() }
    }

    fn mark(&mut self, step: &'static str) {
        let now = std::time::Instant::now();
        self.steps.push((step, now.duration_since(self.last).as_millis()));
        self.last = now;
    }
}

impl Drop for PublicationSteps {
    fn drop(&mut self) {
        let total = self.started.elapsed();
        if total >= std::time::Duration::from_secs(1) {
            tracing::warn!(
                total_ms = total.as_millis() as u64,
                steps = ?self.steps,
                after_last_step_ms = self.last.elapsed().as_millis() as u64,
                "slow execution publication"
            );
        }
    }
}

fn unavailable_engine(name: &str) -> QuilError {
    QuilError::ExecutionUnavailable(format!("unsupported execution capture engine {name}"))
}
