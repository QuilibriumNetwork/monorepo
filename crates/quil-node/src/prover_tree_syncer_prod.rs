//! Production [`ProverTreeSyncer`] impl.
//!
//! Syncs the global prover tree from the master's
//! HypergraphComparisonService via mTLS. In Go, workers call
//! `HyperSyncSelf` which dials the master — the master hosts the
//! snapshot of the prover tree. This Rust port does the same: it
//! connects to the master's stream port (the same one that serves
//! `GlobalService`) and uses `ensure_prover_tree_incremental` to pull
//! the vertex-adds tree for the global shard.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{info, warn};

use quil_engine::prover_tree_syncer::ProverTreeSyncer;
use quil_types::error::{QuilError, Result};

/// Syncs from a fixed endpoint (typically the master's stream port).
pub struct ProdProverTreeSyncer {
    /// `host:port` of the master's peer gRPC listener.
    pub master_stream_addr: String,
    /// Worker's HypergraphStore — synced tree data is persisted here.
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
    /// Ed448 seed for mTLS to the master.
    pub ed448_seed: [u8; 57],
}

#[async_trait]
impl ProverTreeSyncer for ProdProverTreeSyncer {
    async fn sync_prover_tree(&self, expected_root: &[u8]) -> Result<bool> {
        info!(addr = %self.master_stream_addr, "syncing prover tree from master");
        let stats = quil_rpc::ensure_prover_tree_incremental(
            &self.master_stream_addr,
            &self.ed448_seed,
            quil_types::proto::application::HypergraphPhaseSet::VertexAdds,
            self.hg_store.clone(),
            expected_root,
        )
        .await
        .map_err(|e| QuilError::Internal(format!("prover tree sync failed: {}", e)))?;
        if stats.leaves_pulled > 0 {
            info!(
                leaves = stats.leaves_pulled,
                matched = stats.commitments_match,
                "prover tree sync complete"
            );
        }
        Ok(stats.commitments_match)
    }

    async fn sync_shard_tree(&self, filter: &[u8], expected_root: &[u8]) -> Result<bool> {
        use quil_types::proto::application::HypergraphPhaseSet;
        // Derive the shard key from the filter (same as the prove path:
        // l1 = bloom indices, l2 = filter[..32]).
        let n = filter.len().min(32);
        let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&filter[..n], 256, 3);
        let mut l2 = [0u8; 32];
        l2[..n].copy_from_slice(&filter[..n]);
        let shard = quil_types::store::ShardKey { l1, l2 };
        info!(
            addr = %self.master_stream_addr,
            filter = %hex::encode(&filter[..n]),
            "syncing app-shard tree from archive (all phase sets)"
        );
        // Sync ALL FOUR phase sets, mirroring Go's HyperSync
        // (sync_provider.go:411-414 `phaseSyncs`): app-shard state lives
        // across vertex adds/removes AND hyperedge adds/removes (token
        // spends move coins into the remove set; spent-markers + outputs
        // into adds). Syncing only VertexAdds would leave the other phase
        // trees stale. Every phase is pinned to the SAME `expected_root`
        // — the frame's `state_roots[0]` (vertex-adds root), which the
        // server uses as the snapshot-generation anchor; each phase pulls
        // its own tree from that one consistent generation.
        let phases = [
            HypergraphPhaseSet::VertexAdds,
            HypergraphPhaseSet::VertexRemoves,
            HypergraphPhaseSet::HyperedgeAdds,
            HypergraphPhaseSet::HyperedgeRemoves,
        ];
        let mut adds_converged = false;
        for phase in phases {
            match quil_rpc::ensure_shard_tree_fresh(
                &shard,
                &self.master_stream_addr,
                &self.ed448_seed,
                phase,
                self.hg_store.clone(),
                expected_root,
            )
            .await
            {
                Ok(stats) => {
                    // The vertex-adds phase root IS the generation anchor,
                    // so its convergence confirms we caught the tree up to
                    // the pinned frame; the engine keys its cursor
                    // fast-forward on this.
                    if matches!(phase, HypergraphPhaseSet::VertexAdds) {
                        adds_converged = stats.commitments_match;
                    }
                }
                Err(e) => {
                    warn!(?phase, error = %e, "app-shard phase sync failed");
                    // A vertex-adds failure means we didn't reach the
                    // generation at all — surface it; the others are
                    // best-effort (an empty phase is a no-op).
                    if matches!(phase, HypergraphPhaseSet::VertexAdds) {
                        return Err(QuilError::Internal(format!(
                            "shard vertex-adds sync failed: {}",
                            e
                        )));
                    }
                }
            }
        }
        Ok(adds_converged)
    }
}
