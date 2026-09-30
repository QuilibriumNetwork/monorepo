//! Commit one fresh, authenticated frame and adopt its live execution state.
use super::*;

/// One attempt to execute an already-canonical GLOBAL frame atomically.
#[derive(Debug)]
pub enum CanonicalAttempt {
    /// State, receipt and cursor published in one batch.
    Published(TentativeFrameResult),
    /// The cursor already covers this exact frame.
    Replayed,
    /// Not published; nothing changed. The caller may use the in-place path.
    Unavailable(QuilError),
}

impl FrameMaterializer {
    /// Execute the canonical record at the next height the way a consensus
    /// finalization is published: privately, then state, receipt and cursor in
    /// one batch. The record is already canonical (stored by sync or by the
    /// finalization fallback) and is not rewritten.
    ///
    /// The in-place path writes execution effects progressively. A crash
    /// there leaves an unfinished-execution marker that refuses every
    /// execution until a restart resolves it
    /// ([`FrameMaterializer::recover_unfinished_execution`]), so this path
    /// runs first whenever it can.
    /// Unavailable covers inputs over the branch budget, a local prover root
    /// that differs from the header (the in-place path records that
    /// divergence for reconcile), storage without branch support and a busy
    /// or conflicting capture.
    pub fn materialize_canonical_atomically(
        &self,
        frame: &quil_types::proto::global::GlobalFrame,
        limits: MaterializerBranchLimits,
    ) -> CanonicalAttempt {
        let Some(number) = frame.header.as_ref().map(|h| h.frame_number) else {
            return CanonicalAttempt::Unavailable(unavailable("canonical frame has no header"));
        };
        let attempt = self.publish_atomically(frame, limits, false, |branch| {
            let cursor = branch.cursor()?;
            let clock = branch.execution.clock_store();
            if clock.get_global_clock_frame(number)? != *frame {
                return Err(unavailable("frame is not the canonical record at its height"));
            }
            if number == cursor {
                return match branch.completed_checkpoint()? {
                    Some(receipt) if receipt.matches_frame(frame)? => Ok(false),
                    _ => Err(unavailable("canonical frame at the cursor has no matching receipt")),
                };
            }
            if cursor.checked_add(1) != Some(number) {
                return Err(unavailable("canonical frame is not the next height"));
            }
            // A receipt must describe the canonical base; a store without
            // one keeps the in-place path's semantics for its base.
            if let Some(receipt) = branch.completed_checkpoint()? {
                if !receipt.matches_frame(&clock.get_global_clock_frame(cursor)?)? {
                    return Err(unavailable("canonical base differs from its execution receipt"));
                }
            }
            Ok(true)
        });
        match attempt {
            Ok(Some(result)) => CanonicalAttempt::Published(result),
            Ok(None) => CanonicalAttempt::Replayed,
            Err(error) => CanonicalAttempt::Unavailable(error),
        }
    }

    /// The consensus owner must validate finality, ancestry and pre-state in
    /// `authenticate`, against this fresh capture. Tentative proposal leases
    /// are never promoted into the canonical store.
    pub(in crate::frame_materializer) fn materialize_atomically(
        &self,
        frame: &quil_types::proto::global::GlobalFrame,
        limits: MaterializerBranchLimits,
        authenticate: impl FnOnce(&MaterializerBranch) -> Result<bool>,
    ) -> Result<Option<TentativeFrameResult>> {
        self.publish_atomically(frame, limits, true, authenticate)
    }

    /// `write_clock`: publish the frame's clock record in the same batch.
    /// False only for a record that is already canonical.
    fn publish_atomically(
        &self,
        frame: &quil_types::proto::global::GlobalFrame,
        limits: MaterializerBranchLimits,
        write_clock: bool,
        authenticate: impl FnOnce(&MaterializerBranch) -> Result<bool>,
    ) -> Result<Option<TentativeFrameResult>> {
        let number = frame
            .header
            .as_ref()
            .ok_or_else(|| unavailable("finalized frame has no header"))?
            .frame_number;
        let result = self.materialize_atomically_inner(frame, limits, write_clock, authenticate)?;
        // All execution barriers were released before these callbacks, including
        // on an authenticated replay after a previous commit or restart.
        if let Some(refresh) = &self.shard_admission_refresh {
            if let Err(error) = refresh() {
                warn!(frame = number, %error, "committed shard admission refresh failed; will retry next frame");
            }
        }
        if let Some(current) = &self.current_frame {
            current.materialize(number);
        }
        Ok(result)
    }

    fn materialize_atomically_inner(
        &self,
        frame: &quil_types::proto::global::GlobalFrame,
        limits: MaterializerBranchLimits,
        write_clock: bool,
        // False is allowed only for an exact, authenticated completed replay.
        authenticate: impl FnOnce(&MaterializerBranch) -> Result<bool>,
    ) -> Result<Option<TentativeFrameResult>> {
        let frame_guard = self
            .frame_execution
            .try_lock()
            .map_err(|_| unavailable("canonical materializer is busy or poisoned"))?;
        let (mut branch, mut publication) = self.capture_execution_branch_with(limits, |registry| {
            self.execution_manager
                .capture_execution_branch_guarded_seeded(limits.execution, registry)
        })?;
        // Node-local coverage and diagnostic writers must not be overwritten by
        // metadata captured before their update. Keep their locks through adoption.
        let mut coverage = self
            .coverage_halt_durations
            .try_lock()
            .map_err(|_| unavailable("canonical coverage metadata is busy or poisoned"))?;
        if *coverage
            != *branch
                .materializer
                .coverage_halt_durations
                .lock()
                .map_err(|_| unavailable("private coverage metadata poisoned"))?
        {
            return Err(unavailable("canonical coverage changed during capture"));
        }
        let status = self
            .prover_status
            .try_lock()
            .map_err(|_| unavailable("canonical prover status is busy or poisoned"))?;
        if !authenticate(&branch)? {
            return Ok(None);
        }
        if write_clock {
            let clock = branch.execution.clock_store();
            let txn = clock.new_transaction(false)?;
            clock.put_global_clock_frame(frame, txn.as_ref())?;
            txn.commit()?;
        }
        let result = branch.materialize(frame)?;
        let number = result.frame_number;
        let epoch = branch
            .materializer
            .last_eviction_pass_epoch
            .load(Ordering::SeqCst);
        let private_coverage = std::mem::take(
            &mut *branch
                .materializer
                .coverage_halt_durations
                .lock()
                .map_err(|_| unavailable("private coverage metadata poisoned"))?,
        );
        let synced = branch
            .materializer
            .prover_root_synced
            .load(Ordering::Relaxed);
        let mismatch = branch
            .materializer
            .prover_root_mismatch
            .load(Ordering::Relaxed);
        let verified = branch
            .materializer
            .prover_root_verified_frame
            .load(Ordering::Relaxed);
        let mut fork_target = self
            .fork_target_root
            .try_write()
            .map_err(|_| unavailable("canonical fork diagnostics are busy or poisoned"))?;
        let mut snapshot = self.hypergraph.prepare_snapshot_publication(
            result.prover_root.to_vec(),
            // Forest versions represent the pre-state of the following frame.
            number
                .checked_add(1)
                .ok_or_else(|| unavailable("publication frame overflow"))?,
        )?;
        let registry = self
            .prover_registry
            .as_any()
            .and_then(|r| r.downcast_ref::<ConcreteProverRegistry>())
            .ok_or_else(|| unavailable("unsupported canonical registry"))?;
        let context = quil_execution::ExecutionForkContext {
            crdt: self.hypergraph.clone(),
            clock_store: self.clock_store.clone(),
            global_clock_store: self.clock_store.clone(),
            shards_store: self.execution_manager.shards_store(),
            prover_registry: self.prover_registry.clone(),
        };
        publication.publish(&mut branch.execution, context, registry, |read_view| {
            *coverage = private_coverage;
            *fork_target = None;
            self.last_eviction_pass_epoch.store(epoch, Ordering::SeqCst);
            self.prover_root_synced.store(synced, Ordering::Relaxed);
            self.prover_root_mismatch.store(mismatch, Ordering::Relaxed);
            self.prover_root_verified_frame
                .store(verified, Ordering::Relaxed);
            self.last_materialized_frame.store(number, Ordering::SeqCst);
            snapshot.adopt(read_view);
        })?;
        // Observer callbacks may read engines, roots, clocks and the cursor.
        // Release every internal barrier before invoking them.
        drop(snapshot);
        drop(fork_target);
        drop(status);
        drop(coverage);
        drop(publication);
        drop(frame_guard);
        Ok(Some(result))
    }
}
