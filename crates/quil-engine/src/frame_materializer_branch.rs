//! Own an isolated GLOBAL materializer and its captured execution providers.
//! This checkpoint check is not selected-consensus-parent authentication.
use super::*;

#[path = "frame_materializer_live_publication.rs"]
mod publication;
pub use publication::CanonicalAttempt;
use quil_execution::{ExecutionBranch, ExecutionBranchLimits};

#[cfg(test)]
#[path = "frame_materializer_branch_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug)]
pub struct MaterializerBranchLimits {
    pub execution: ExecutionBranchLimits,
    pub max_metadata_entries: usize,
    pub max_metadata_bytes: usize,
    /// Protobuf encoded size, checked before canonical encoding/preverification.
    /// This bounds accepted input, not allocator/RSS or proof-worker memory.
    pub max_frame_bytes: usize,
    /// Bundles plus their request slots, including empty bundles/absent slots.
    pub max_frame_items: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaterializerMetadataUsage {
    pub entries: usize,
    pub bytes: usize,
}

/// Execution evidence only. Consumed bundles may leave the public mempool only
/// after an authenticated finalization publishes this frame canonically.
#[derive(Debug)]
pub struct TentativeFrameResult {
    pub frame_number: u64,
    pub processed: usize,
    pub skipped: usize,
    pub prover_root: [u8; 32],
    pub consumed_bundles: Vec<Vec<u8>>,
    pub checkpoint: GlobalExecutionCheckpoint,
}

/// No primary-store, notification or writable materializer handles are exposed.
/// Dropping this owner invalidates retained storage, including on construction
/// failure. A failed or unwound frame attempt permanently closes this branch;
/// independently captured descendants keep their own generations.
pub struct MaterializerBranch {
    execution: ExecutionBranch,
    materializer: FrameMaterializer,
    metadata: MaterializerMetadataUsage,
    limits: MaterializerBranchLimits,
}

fn unavailable(message: &str) -> QuilError {
    QuilError::ExecutionUnavailable(message.into())
}

struct FrameAttempt {
    overlay: Arc<quil_forest::ExecutionOverlay>,
    succeeded: bool,
}
impl Drop for FrameAttempt {
    fn drop(&mut self) {
        if !self.succeeded {
            self.overlay.close();
        }
    }
}

impl MaterializerBranch {
    pub(super) fn execution(&self) -> &ExecutionBranch {
        &self.execution
    }

    fn check_open(&self) -> Result<()> {
        if self.execution.overlay().stats().closed {
            return Err(unavailable("materializer branch is closed"));
        }
        if !self.execution.overlay().execution_healthy() {
            self.execution.overlay().close();
            return Err(unavailable(
                "materializer branch has a prior storage failure",
            ));
        }
        Ok(())
    }

    pub fn cursor(&self) -> Result<u64> {
        self.check_open()?;
        Ok(self.materializer.last_materialized_frame())
    }

    pub fn prover_root(&self) -> Result<[u8; 32]> {
        self.check_open()?;
        self.materializer
            .hypergraph
            .current_forest_phase_root(&[0xff; 32], 0)
    }

    pub fn storage_usage(&self) -> quil_forest::OverlayStats {
        self.execution.overlay().stats()
    }

    pub fn metadata_usage(&self) -> MaterializerMetadataUsage {
        self.metadata
    }

    /// Local execution provenance only; absence is a legacy/unbound checkpoint
    /// and must never be replaced by guessing an identity from the clock head.
    pub fn completed_checkpoint(&self) -> Result<Option<GlobalExecutionCheckpoint>> {
        self.check_open()?;
        let checkpoint = execution_checkpoint::read_completed(
            self.execution.hypergraph_store().as_ref(),
            &self.materializer.hypergraph,
            self.cursor()?,
        )?;
        self.check_open()?;
        Ok(checkpoint)
    }

    pub fn capture_child(&self, limits: MaterializerBranchLimits) -> Result<Self> {
        self.check_open()?;
        self.materializer.capture_execution_branch(limits)
    }

    /// Execute exactly the next frame. Parent selection and certificates must
    /// be authenticated by the eventual runtime owner before using this result.
    /// Neither a stored clock head nor a matching state root does that binding.
    pub fn materialize(
        &mut self,
        frame: &quil_types::proto::global::GlobalFrame,
    ) -> Result<TentativeFrameResult> {
        self.check_open()?;
        let mut attempt = FrameAttempt {
            overlay: self.execution.overlay().clone(),
            succeeded: false,
        };
        let items = frame
            .requests
            .iter()
            .try_fold(frame.requests.len(), |count, bundle| {
                count
                    .checked_add(bundle.requests.len())
                    .filter(|next| *next <= self.limits.max_frame_items)
            })
            .filter(|count| *count <= self.limits.max_frame_items);
        if items.is_none() || prost::Message::encoded_len(frame) > self.limits.max_frame_bytes {
            return Err(unavailable("tentative frame input budget exceeded"));
        }
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| unavailable("tentative frame has no header"))?;
        let number = header.frame_number;
        if self.materializer.last_materialized_frame().checked_add(1) != Some(number)
            || number.checked_add(1).is_none()
        {
            return Err(unavailable(
                "tentative frame must immediately follow its captured cursor",
            ));
        }
        let result = self.materializer.materialize(frame)?;
        self.check_open()?;
        let root: [u8; 32] = result
            .local_prover_root
            .as_slice()
            .try_into()
            .map_err(|_| unavailable("tentative frame omitted its prover root"))?;
        if !result.prover_root_matched
            || self.materializer.last_materialized_frame() != number
            || read_cursor(self.execution.hypergraph_store().as_ref())? != number
        {
            return Err(unavailable("tentative frame checkpoint did not complete"));
        }
        self.check_open()?;
        let checkpoint = self
            .completed_checkpoint()?
            .ok_or_else(|| unavailable("tentative frame has no execution checkpoint"))?;
        if !checkpoint.matches_frame(frame)? {
            return Err(unavailable("tentative completion belongs to another input"));
        }
        attempt.succeeded = true;
        Ok(TentativeFrameResult {
            frame_number: number,
            processed: result.processed,
            skipped: result.skipped,
            prover_root: root,
            consumed_bundles: result.finalized_bundles,
            checkpoint,
        })
    }
}

fn read_cursor(store: &dyn HypergraphStore) -> Result<u64> {
    let txn = store.new_transaction(false)?;
    let bytes = txn.get(&quil_store::encoding::global_materialized_cursor_key())?;
    txn.abort()?;
    match bytes {
        None => Ok(0),
        Some(bytes) => {
            Ok(u64::from_be_bytes(bytes.as_slice().try_into().map_err(
                |_| unavailable("invalid captured materializer cursor"),
            )?))
        }
    }
}

impl FrameMaterializer {
    /// Capture a complete materializer over one same-store checkpoint. The
    /// frame mutex excludes materialize/frozen-skip; CRDT/engine capture excludes
    /// commits and in-flight engine mutations. Cursor comparison rejects a
    /// concurrent seeding/sync transition instead of treating clock head as the
    /// execution frontier. Strict execution checks the actual captured parent
    /// root before any maintenance, including while records are ahead of state.
    ///
    /// Public progress/admission/catch-up hooks are absent. Node coverage and
    /// mismatch diagnostics are private; immutable maintenance and crypto
    /// services may be shared. Aggregate admission, lifetime, disk policy and
    /// canonical promotion are still the runtime owner's responsibility.
    pub fn capture_execution_branch(
        &self,
        limits: MaterializerBranchLimits,
    ) -> Result<MaterializerBranch> {
        let _frame = self
            .frame_execution
            .try_lock()
            .map_err(|_| unavailable("materializer is busy or poisoned"))?;
        self.capture_execution_branch_with(limits, || {
            self.execution_manager
                .capture_execution_branch(limits.execution)
                .map(|branch| (branch, ()))
        })
        .map(|(branch, ())| branch)
    }

    /// The caller already holds the source frame lock. The factory may retain
    /// the execution barriers through publication without reacquiring them.
    fn capture_execution_branch_with<T>(
        &self,
        limits: MaterializerBranchLimits,
        capture: impl FnOnce() -> Result<(ExecutionBranch, T)>,
    ) -> Result<(MaterializerBranch, T)> {
        if self.prover_sync_in_progress.load(Ordering::SeqCst) {
            return Err(unavailable("materializer prover sync is active"));
        }
        if self.unified_cutover_consolidate.is_some() || self.prover_tree_reset.is_some() {
            return Err(unavailable(
                "opaque materializer maintenance cannot be captured",
            ));
        }
        let registry = self
            .prover_registry
            .as_any()
            .and_then(|r| r.downcast_ref::<ConcreteProverRegistry>())
            .ok_or_else(|| unavailable("unsupported materializer registry"))?;
        if self
            .eviction_registry
            .as_ref()
            .is_some_and(|r| !r.shares_cache_with(registry))
        {
            return Err(unavailable(
                "materializer eviction registry differs from execution registry",
            ));
        }
        if !Arc::ptr_eq(&self.hypergraph, &self.execution_manager.crdt()) {
            return Err(unavailable("materializer execution CRDT mismatch"));
        }
        let identity = self
            .hypergraph
            .backing_store_identity()
            .ok_or_else(|| unavailable("materializer requires identifiable storage"))?;
        if self.hypergraph_store.backing_store_identity().as_ref() != Some(&identity)
            || self.clock_store.backing_store_identity().as_ref() != Some(&identity)
        {
            return Err(unavailable("materializer provider store mismatch"));
        }
        let halt_guard = self
            .coverage_halt_durations
            .lock()
            .map_err(|_| unavailable("materializer coverage metadata poisoned"))?;
        let entries = halt_guard
            .len()
            .checked_add(2)
            .ok_or_else(|| unavailable("materializer metadata entry overflow"))?;
        let bytes = halt_guard
            .keys()
            .fold(
                4096usize.checked_add(self._prover_address.len()),
                |total, key| {
                    total
                        .and_then(|v| v.checked_add(128))
                        .and_then(|v| v.checked_add(key.len()))
                },
            )
            .ok_or_else(|| unavailable("materializer metadata byte overflow"))?;
        if entries > limits.max_metadata_entries || bytes > limits.max_metadata_bytes {
            return Err(unavailable("materializer metadata budget exceeded"));
        }
        let halt = halt_guard.clone();
        drop(halt_guard);
        let cursor = self.last_materialized_frame.load(Ordering::SeqCst);
        let epoch = self.last_eviction_pass_epoch.load(Ordering::SeqCst);
        let (execution, retained) = capture()?;
        if read_cursor(execution.hypergraph_store().as_ref())? != cursor {
            return Err(unavailable(
                "captured durable cursor differs from materializer cursor",
            ));
        }
        let crdt = execution.manager().crdt();
        let root = crdt.current_forest_phase_root(&[0xff; 32], 0)?;
        match crdt.prover_root_at(cursor) {
            Some(recorded) if recorded.as_slice() != root => {
                return Err(unavailable(
                    "captured prover root differs from completed frame",
                ))
            }
            None if cursor != 0 => {
                return Err(unavailable("captured frame has no completed prover root"))
            }
            _ => {}
        }
        let registry = Arc::new(execution.registry().clone());
        let mut materializer = FrameMaterializer::new(
            execution.manager().clone(),
            registry.clone(),
            execution.clock_store().clone(),
            crdt,
            execution.hypergraph_store().clone(),
            self._reward_issuance.clone(),
            self._prover_address.clone(),
            self.archive_mode,
        );
        materializer.tentative_execution = true;
        materializer.global_maintenance = self.global_maintenance.clone();
        materializer.eviction_grace_frames = self.eviction_grace_frames;
        materializer.evictions_enabled = self.evictions_enabled;
        materializer.eviction_registry = self.eviction_registry.as_ref().map(|_| registry);
        materializer.frozen_era_recovery_enabled = self.frozen_era_recovery_enabled;
        materializer.frame_prover = self.frame_prover.clone();
        materializer.bls = self.bls.clone();
        *materializer.coverage_halt_durations.lock().unwrap() = halt;
        materializer
            .last_materialized_frame
            .store(cursor, Ordering::SeqCst);
        materializer
            .last_eviction_pass_epoch
            .store(epoch, Ordering::SeqCst);
        let branch = MaterializerBranch {
            execution,
            materializer,
            limits,
            metadata: MaterializerMetadataUsage { entries, bytes },
        };
        branch.check_open()?;
        Ok((branch, retained))
    }
}
