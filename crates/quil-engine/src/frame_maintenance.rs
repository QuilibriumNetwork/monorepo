//! Immutable maintenance policy. Storage is supplied by each materializer;
//! cloning this policy cannot carry a primary database into a tentative branch.
use quil_hypergraph::{ForestWriteGuard, HypergraphCrdt};
use quil_types::{
    error::{QuilError, Result},
    store::{HypergraphStore, ShardsStore},
};
use std::sync::Arc;

#[cfg(test)]
#[path = "frame_maintenance_tests.rs"]
mod tests;

pub const BOOT_RESET_MARKER_KEY: &[u8] = b"\x00__quil_boot_cutover_reset_v1__";
// The boot marker covers grid reset and consolidation too. A runtime prover
// reset alone must never certify those operations, including across a crash.
const FRAME_PROVER_RESET_V1_MARKER_KEY: &[u8] = b"\x00__quil_frame_prover_reset_v1__";
pub const GRID_RESET_V2_MARKER_KEY: &[u8] = b"\x00__quil_grid_reset_v2__";
pub const PROVER_RESET_V3_MARKER_KEY: &[u8] = b"\x00__quil_prover_reset_v3__";
pub const PROVER_RESET_V4_MARKER_KEY: &[u8] = b"\x00__quil_prover_reset_v4__";
pub const PROVER_RESET_V5_MARKER_KEY: &[u8] = b"\x00__quil_prover_reset_v5__";

#[derive(Clone)]
pub struct GlobalMaintenance {
    network: u8,
    genesis_seed: Arc<str>,
    local_prover_pubkey: Arc<[u8]>,
}

impl GlobalMaintenance {
    pub fn new(network: u8, genesis_seed: String, local_prover_pubkey: Vec<u8>) -> Self {
        Self {
            network,
            genesis_seed: genesis_seed.into(),
            local_prover_pubkey: local_prover_pubkey.into(),
        }
    }

    pub(crate) fn consolidate(
        &self,
        crdt: &HypergraphCrdt,
        store: &dyn HypergraphStore,
        shards: &dyn ShardsStore,
        guard: &ForestWriteGuard<'_>,
        frame: u64,
    ) -> Result<()> {
        crdt.maintain_forest(guard, |forest| {
            quil_forest_migrate::run_unified_consolidation(store, forest, shards, frame, 256)
                .map(|_| ())
                .map_err(|error| {
                    QuilError::ExecutionUnavailable(format!("frame consolidation: {error}"))
                })
        })
    }

    pub(crate) fn reset(
        &self,
        crdt: &Arc<HypergraphCrdt>,
        store: &dyn HypergraphStore,
        guard: &ForestWriteGuard<'_>,
        frame: u64,
    ) -> Result<()> {
        crdt.check_forest_guard(guard)?;
        let identity = crdt.backing_store_identity().ok_or_else(|| {
            QuilError::ExecutionUnavailable("reset requires identifiable state".into())
        })?;
        if store.backing_store_identity().as_ref() != Some(&identity) {
            return Err(QuilError::ExecutionUnavailable(
                "reset marker store mismatch".into(),
            ));
        }
        let key = reset_marker(frame);
        if crdt.read_execution_record(key)?.is_some()
            || (key == FRAME_PROVER_RESET_V1_MARKER_KEY
                && crdt.read_execution_record(BOOT_RESET_MARKER_KEY)?.is_some())
        {
            return Ok(());
        }
        crate::genesis::reset_prover_tree_to_genesis_with_guard(
            crdt,
            store,
            guard,
            frame,
            self.network,
            &self.genesis_seed,
            &self.local_prover_pubkey,
        )?;
        let txn = store.new_transaction(false)?;
        txn.set(key, &[1])?;
        txn.commit()
    }
}

fn reset_marker(frame: u64) -> &'static [u8] {
    use quil_execution::global_intrinsic::materialize as m;
    if frame == m::quil_prover_reset_v5_frame() {
        PROVER_RESET_V5_MARKER_KEY
    } else if frame == m::quil_prover_reset_v4_frame() {
        PROVER_RESET_V4_MARKER_KEY
    } else if frame == m::quil_prover_reset_v3_frame() {
        PROVER_RESET_V3_MARKER_KEY
    } else if frame == m::quil_grid_reset_v2_frame() {
        GRID_RESET_V2_MARKER_KEY
    } else {
        FRAME_PROVER_RESET_V1_MARKER_KEY
    }
}
