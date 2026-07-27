//! Production [`ProverTreeSyncer`] impl — efficient forest Merkle-diff sync.
//!
//! A behind worker catches its shard/phase trees up to a peer archive by
//! walking the peer's JMT top-down and pulling only the nodes whose hash
//! differs from its own ([`quil_forest::diff_leaves`], via a gRPC-backed
//! [`RemoteTreeReader`]). The diff is self-authenticating against the trusted
//! header root, and the pulled leaves are applied into the live CRDT's forest at
//! a COORDINATED version (so they never collide with `commit_inner`).
//!
//! Replaces the legacy KZG `ensure_prover_tree_incremental` /
//! `ensure_shard_tree_fresh` node-by-node walk (which rebuilt a
//! `VectorCommitmentTree`); that path is retired with the forest cutover.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{info, warn};

use quil_engine::prover_tree_syncer::ProverTreeSyncer;
use quil_rpc::ArchiveClient;
use quil_types::error::{QuilError, Result};

/// Syncs from a fixed endpoint (typically the master's stream port).
pub struct ProdProverTreeSyncer {
    /// `host:port` of the master's peer gRPC listener.
    pub master_stream_addr: String,
    /// Worker's HypergraphStore (the forest shares its RocksDB).
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
    /// Falcon q-prover-key signing key (1281B) — the `:8340` network identity
    /// used for the PQNoise handshake to the master.
    pub falcon_signing_key: Vec<u8>,
    /// The live CRDT — sync applies into ITS forest at coordinated versions.
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
}

impl ProdProverTreeSyncer {
    /// Sync one SINGLE-shard tree (its `shard_id` is the app address) via the
    /// efficient Merkle diff. For each of the four phases: discover the peer's
    /// `(version, root)`, verify the vertex-adds root (phase 0) against
    /// `expected_va_root` (the header root the caller pinned), then diff + apply
    /// into the CRDT forest. Returns whether phase 0 converged to that root.
    /// Phases 1–3 pin to the same generation but have no separately-advertised
    /// header root, so they are pulled best-effort behind the phase-0 anchor.
    async fn sync_single_shard(&self, shard_id: Vec<u8>, expected_va_root: &[u8]) -> Result<bool> {
        let mut client = ArchiveClient::connect_mtls(&self.master_stream_addr, &self.falcon_signing_key)
            .await
            .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
        let handle = tokio::runtime::Handle::current();
        let mut va_converged = false;
        for phase in 0u32..4 {
            let head = client
                .get_forest_head(shard_id.clone(), phase)
                .await
                .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))?;
            let Some((v_s, root_s)) = head else {
                continue; // peer has no tree for this phase (empty) — nothing to pull
            };
            if phase == 0 && root_s.as_slice() != expected_va_root {
                warn!(
                    peer = %hex::encode(&root_s),
                    expected = %hex::encode(expected_va_root),
                    "peer vertex-adds root != expected — not syncing this shard"
                );
                return Ok(false);
            }
            let got = crate::forest_sync::sync_one_phase(
                &mut client, &handle, &self.crdt, &shard_id, phase, v_s,
            )
            .await?;
            if phase == 0 {
                va_converged = got.as_slice() == expected_va_root;
                if !va_converged {
                    warn!("post-sync vertex-adds root still differs from expected");
                }
            }
        }
        Ok(va_converged)
    }

    /// Sync a SPLIT app (QUIL: 64 sub-shards). For each phase: fetch every
    /// sub-shard's `(version, root)`; on phase 0, verify the whole set aggregates
    /// to the header app root (`expected_va_root`) — one binding that
    /// authenticates all 64 sub-shard roots at once (model B) — then diff + apply
    /// each present sub-shard. Absent sub-shards contribute the empty root, so
    /// the aggregate matches `commit_inner`. Returns whether phase 0 converged.
    async fn sync_split_shard(&self, app: [u8; 32], expected_va_root: &[u8]) -> Result<bool> {
        let mut client = ArchiveClient::connect_mtls(&self.master_stream_addr, &self.falcon_signing_key)
            .await
            .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
        let handle = tokio::runtime::Handle::current();
        let sub_shards = self.crdt.app_sub_shards(&app);
        let mut va_converged = false;
        for phase in 0u32..4 {
            // Fetch every sub-shard's head for this phase.
            let mut heads: Vec<(Vec<u8>, Vec<bool>, Option<(u64, [u8; 32])>)> =
                Vec::with_capacity(sub_shards.len());
            for (shard_id, bits) in &sub_shards {
                let h = client
                    .get_forest_head(shard_id.clone(), phase)
                    .await
                    .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))?;
                let h32 = h.and_then(|(v, r)| {
                    <[u8; 32]>::try_from(r.as_slice()).ok().map(|a| (v, a))
                });
                heads.push((shard_id.clone(), bits.clone(), h32));
            }
            // Phase 0: the aggregate of all sub-shard roots must equal the trusted
            // header app root, which authenticates every root before we pull it.
            if phase == 0 {
                let sub_roots: Vec<(Vec<bool>, [u8; 32])> = heads
                    .iter()
                    .map(|(_, bits, h)| (bits.clone(), h.map(|(_, r)| r).unwrap_or([0u8; 32])))
                    .collect();
                if !self.crdt.app_root_matches(&sub_roots, expected_va_root) {
                    warn!("QUIL sub-shard roots do not aggregate to the expected app root — not syncing");
                    return Ok(false);
                }
            }
            // Diff + apply each present sub-shard (identical ones transfer nothing).
            for (shard_id, _, head) in &heads {
                let Some((v_s, root_s)) = *head else { continue };
                let got = crate::forest_sync::sync_one_phase(
                    &mut client, &handle, &self.crdt, shard_id, phase, v_s,
                )
                .await?;
                if got != root_s {
                    warn!(phase, "QUIL sub-shard post-sync root mismatch");
                    if phase == 0 {
                        return Ok(false);
                    }
                }
            }
            if phase == 0 {
                va_converged = true;
            }
        }
        Ok(va_converged)
    }
}

#[async_trait]
impl ProverTreeSyncer for ProdProverTreeSyncer {
    async fn sync_prover_tree(&self, expected_root: &[u8]) -> Result<bool> {
        // The global prover shard is a single-shard app: L2 = [0xff; 32].
        info!(addr = %self.master_stream_addr, "syncing global prover tree (forest diff)");
        self.sync_single_shard(vec![0xffu8; 32], expected_root).await
    }

    async fn sync_shard_tree(&self, filter: &[u8], expected_root: &[u8]) -> Result<bool> {
        let n = filter.len().min(32);
        let mut l2 = [0u8; 32];
        l2[..n].copy_from_slice(&filter[..n]);
        // QUIL splits 64-way: its state lives in sub-shard trees (app‖prefix),
        // verified as a set via the aggregation binding.
        if l2 == quil_execution::domains::QUIL_TOKEN {
            info!(addr = %self.master_stream_addr, "syncing QUIL app (forest diff, 64 sub-shards)");
            return self.sync_split_shard(l2, expected_root).await;
        }
        info!(
            addr = %self.master_stream_addr,
            filter = %hex::encode(&filter[..n]),
            "syncing app-shard tree (forest diff, single-shard)"
        );
        self.sync_single_shard(l2.to_vec(), expected_root).await
    }
}
