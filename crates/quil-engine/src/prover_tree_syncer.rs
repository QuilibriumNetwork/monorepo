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

    /// Sync a specific app-shard's vertex-adds subtree from an archive,
    /// pinning to `expected_root`. Used to catch a shard's CRDT up after
    /// a frame gap / restart / late-join (step 4). `filter` is the
    /// shard filter; the impl derives the `ShardKey`. Default is a no-op
    /// (returns `Ok(false)`) for syncers that don't support shard sync.
    async fn sync_shard_tree(&self, _filter: &[u8], _expected_root: &[u8]) -> Result<bool> {
        Ok(false)
    }
}
