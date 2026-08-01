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
/// 1. Connect to an archive endpoint (mTLS)
/// 2. Pull the prover tree via `ensure_prover_tree_incremental`
/// with `expected_root` pinned
/// 3. Return whether the final root matches
#[async_trait]
pub trait ProverTreeSyncer: Send + Sync {
    /// Sync the global prover tree, pinning EACH phase to `expected_roots[phase]`
    /// — `[prover_tree_commitment (phase 0), prover_tree_aux_roots (1,2,3)]` from
    /// the global header (audit #5: all four phases anchored). Empty slice ⇒
    /// trust the peer (bootstrap). Returns `Ok(true)` if post-sync roots match,
    /// `Ok(false)` if the sync completed but roots still diverge, `Err` on failure.
    async fn sync_prover_tree(&self, expected_roots: &[Vec<u8>]) -> Result<bool>;

    /// Sync a specific app-shard's subtrees from an archive, pinning EACH of
    /// the four phases to `expected_roots[phase]` — the finalized header's
    /// `state_roots` (audit #5: all four phases anchored, not just vertex-adds).
    /// Used to catch a shard's CRDT up after a frame gap / restart / late-join
    /// (step 4). `filter` is the shard filter; the impl derives the `ShardKey`.
    /// An empty entry (or empty slice) trusts the peer for that phase
    /// (bootstrap). Default is a no-op (`Ok(false)`) for syncers without shard
    /// sync.
    async fn sync_shard_tree(&self, _filter: &[u8], _expected_roots: &[Vec<u8>]) -> Result<bool> {
        Ok(false)
    }
}
