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
}
