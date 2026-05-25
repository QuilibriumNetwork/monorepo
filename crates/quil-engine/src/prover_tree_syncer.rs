//! Trait for syncing the global prover tree from archives.
//!
//! Workers need to sync the prover tree to resolve leader rotation,
//! verify FrameHeaders, and attribute shard work. In Go this is
//! `AppConsensusEngine.performBlockingGlobalHypersync` which calls
//! `HyperSyncSelf` against the master/archive. The Rust port can't
//! call `quil-rpc` from `quil-engine` (circular dep), so the trait
//! lives here and the implementation lives in `quil-node`.

use async_trait::async_trait;
use quil_types::error::Result;

/// Syncs the global prover tree (vertex-adds set for the global
/// intrinsic address) from an archive. Returns `true` if the
/// locally-recomputed root matches `expected_root` after sync.
///
/// Implementations should:
///   1. Connect to an archive endpoint (mTLS)
///   2. Pull the prover tree via `ensure_prover_tree_incremental`
///      with `expected_root` pinned
///   3. Return whether the final root matches
#[async_trait]
pub trait ProverTreeSyncer: Send + Sync {
    /// Sync the global prover tree, pinning to `expected_root`.
    /// Returns `Ok(true)` if post-sync root matches, `Ok(false)` if
    /// the sync completed but roots still diverge, `Err` on failure.
    async fn sync_prover_tree(&self, expected_root: &[u8]) -> Result<bool>;
}
