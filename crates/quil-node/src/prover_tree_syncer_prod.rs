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
    /// `host:port` of the master's peer gRPC listener. Used when `archive_pool`
    /// is absent or empty (the multi-process worker path, which dials its master).
    pub master_stream_addr: String,
    /// Worker's HypergraphStore (the forest shares its RocksDB).
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
    /// Falcon q-prover-key signing key (1281B) — the `:8340` network identity
    /// used for the PQNoise handshake to the master.
    pub falcon_signing_key: Vec<u8>,
    /// The live CRDT — sync applies into ITS forest at coordinated versions.
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    /// When set, resolve a live ARCHIVE endpoint per sync attempt (round-robin,
    /// failure-blacklisting) instead of the fixed `master_stream_addr`. Used by
    /// thread-mode workers doing the step-4 app-shard catch-up: they dial an
    /// archive directly (the master only serves the global tree, not app-shard
    /// leaves), and the pool tolerates an empty-at-build / dead-archive state.
    pub archive_pool: Option<Arc<quil_rpc::ArchiveEndpointPool>>,
}

impl ProdProverTreeSyncer {
    /// The endpoint to dial for the next sync: a live archive from the pool when
    /// wired (falling back to `master_stream_addr` if the pool is empty), else
    /// the fixed `master_stream_addr`.
    async fn resolve_addr(&self) -> String {
        if let Some(pool) = self.archive_pool.as_ref() {
            if let Some(ep) = pool.next().await {
                return ep;
            }
        }
        self.master_stream_addr.clone()
    }

    /// Sync one SINGLE-shard tree (its `shard_id` is the app address) via the
    /// efficient Merkle diff. `expected_roots` is the finalized header's
    /// `state_roots` (audit #5): index `p` is the committed root of phase `p`
    /// (0=vertex.adds, 1=vertex.removes, 2=hyperedge.adds, 3=hyperedge.removes).
    /// For EACH phase we authenticate the peer's advertised root against that
    /// committed root BEFORE pulling — an absent peer tree is the zero root, so
    /// it must match a zero header root. Any divergence aborts the whole sync
    /// (no partial, unauthenticated state is applied). Empty `expected_roots`
    /// (or a missing entry) ⇒ TRUST the peer for that phase (bootstrap / initial
    /// sync). Now that `state_roots` is deterministic + validated at consensus
    /// (audit #3), phases 1–3 have real header anchors — previously they were
    /// pulled best-effort behind phase 0, which let a peer serve divergent
    /// removes/hyperedge state. Returns whether the sync converged.
    async fn sync_single_shard(&self, shard_id: Vec<u8>, expected_roots: &[Vec<u8>]) -> Result<bool> {
        let mut client = ArchiveClient::connect_mtls(&self.resolve_addr().await, &self.falcon_signing_key)
            .await
            .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
        let handle = tokio::runtime::Handle::current();
        for phase in 0u32..4 {
            // Header-committed root for this phase (empty ⇒ no anchor / trust).
            let expected = expected_roots.get(phase as usize).cloned().unwrap_or_default();
            let head = client
                .get_forest_head(shard_id.clone(), phase)
                .await
                .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))?;
            // PRE-pull anchor (audit #5): the peer's root for THIS phase must
            // equal the header-committed root. An absent tree == the zero root.
            if !expected.is_empty() {
                let peer_root = head
                    .as_ref()
                    .map(|(_, r)| r.clone())
                    .unwrap_or_else(|| vec![0u8; expected.len()]);
                if peer_root.as_slice() != expected.as_slice() {
                    warn!(
                        phase,
                        peer = %hex::encode(&peer_root),
                        expected = %hex::encode(&expected),
                        "peer phase root != header-committed root — not syncing this shard",
                    );
                    return Ok(false);
                }
            }
            let Some((v_s, root_s)) = head else {
                // Peer has no tree for this phase (matched the zero anchor). Verify
                // our LOCAL tree is ALSO empty (audit residual #4): otherwise stale
                // local data the header says shouldn't exist would survive the sync
                // (the pull is skipped, so nothing overwrites it).
                if !expected.is_empty() {
                    if let Some(sk) = crate::forest_sync::app_shard_key(&shard_id) {
                        let (s, p) = crate::forest_sync::phase_strs(phase);
                        let mut local = self.crdt.compute_shard_root(s, p, &sk);
                        if local.is_empty() {
                            local = vec![0u8; expected.len()];
                        }
                        if local.as_slice() != expected.as_slice() {
                            warn!(
                                phase,
                                "peer absent but LOCAL phase root != header-committed zero root \
                                 (stale local data) — not syncing this shard",
                            );
                            return Ok(false);
                        }
                    }
                }
                continue;
            };
            let rr = <[u8; 32]>::try_from(root_s.as_slice()).ok();
            let got = crate::forest_sync::sync_one_phase(
                &mut client, &handle, &self.crdt, &shard_id, phase, v_s, rr,
            )
            .await?;
            // POST-pull: the applied root must equal the anchor (belt-and-suspenders
            // — the diff should land exactly on the pre-verified peer root).
            if !expected.is_empty() && got.as_slice() != expected.as_slice() {
                warn!(phase, "post-sync phase root still differs from the header-committed root");
                return Ok(false);
            }
        }
        // Every phase either had no anchor (trusted bootstrap) or matched.
        Ok(true)
    }

    /// Sync a SPLIT app (QUIL: 64 sub-shards). `expected_roots` is the header's
    /// `state_roots` (audit #5): index `p` is the AGGREGATE root of phase `p`
    /// across the sub-shards. For EVERY phase we verify the fetched sub-shard set
    /// aggregates to `expected_roots[p]` — one binding that authenticates all 64
    /// sub-shard roots at once — BEFORE diffing + applying. Absent sub-shards
    /// contribute the zero root, so the aggregate matches `commit_inner`. Any
    /// phase whose aggregate or post-apply root diverges aborts the sync.
    /// Previously only phase 0 was bound; phases 1–3 could be served divergent.
    async fn sync_split_shard(&self, app: [u8; 32], expected_roots: &[Vec<u8>]) -> Result<bool> {
        let mut client = ArchiveClient::connect_mtls(&self.resolve_addr().await, &self.falcon_signing_key)
            .await
            .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
        let handle = tokio::runtime::Handle::current();
        let sub_shards = self.crdt.app_sub_shards(&app);
        for phase in 0u32..4 {
            let expected = expected_roots.get(phase as usize).cloned().unwrap_or_default();
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
            // Anchor (audit #5): the aggregate of all sub-shard roots for THIS
            // phase must equal the header-committed aggregate, authenticating
            // every sub-shard root before we pull it. Empty ⇒ trust (bootstrap).
            if !expected.is_empty() {
                let sub_roots: Vec<(Vec<bool>, [u8; 32])> = heads
                    .iter()
                    .map(|(_, bits, h)| (bits.clone(), h.map(|(_, r)| r).unwrap_or([0u8; 32])))
                    .collect();
                if !self.crdt.app_root_matches(&sub_roots, &expected) {
                    warn!(phase, "QUIL sub-shard roots do not aggregate to the header root — not syncing");
                    return Ok(false);
                }
            }
            // Diff + apply each present sub-shard (identical ones transfer nothing).
            for (shard_id, _, head) in &heads {
                let Some((v_s, root_s)) = *head else { continue };
                let got = crate::forest_sync::sync_one_phase(
                    &mut client, &handle, &self.crdt, shard_id, phase, v_s, Some(root_s),
                )
                .await?;
                if got != root_s {
                    warn!(phase, "QUIL sub-shard post-sync root mismatch — not syncing");
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// UNIFIED shard-prover subtree-range sync: catch up ONLY the covered shard's
    /// subtree of the app tree — never the whole app. `prefix_bytes` are the
    /// shard's `ShardInfo.prefix` bytes (`filter[32..]`); `expected_roots[phase]`
    /// is the header's app-phase root, which we pin the peer's app tree to and
    /// authenticate the pulled subtree against (the descent co-path). Each phase's
    /// pulled leaves reconstruct a local subtree whose root the CRDT verifies
    /// equals the authenticated source subtree root.
    async fn sync_shard_subtree(
        &self,
        app: [u8; 32],
        prefix_bytes: &[u8],
        expected_roots: &[Vec<u8>],
    ) -> Result<bool> {
        let prefix: Vec<u32> = prefix_bytes.iter().map(|b| *b as u32).collect();
        let bits = self.crdt.canonical_bits_for_prefix(&app, &prefix);
        let mut client = ArchiveClient::connect_mtls(&self.resolve_addr().await, &self.falcon_signing_key)
            .await
            .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
        let handle = tokio::runtime::Handle::current();
        for phase in 0u32..4 {
            let expected = expected_roots.get(phase as usize).cloned().unwrap_or_default();
            let head = client
                .get_forest_head(app.to_vec(), phase)
                .await
                .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))?;
            let Some((v_s, root_s)) = head else {
                // Peer has no app tree for this phase → must match the zero anchor.
                if !expected.is_empty() && expected.iter().any(|b| *b != 0) {
                    warn!(phase, "peer absent but header app root non-empty — not syncing subtree");
                    return Ok(false);
                }
                continue;
            };
            // Pin: the peer's advertised APP root must equal the header app root
            // for this phase (audit #5). Empty ⇒ trust (bootstrap).
            if !expected.is_empty() && root_s.as_slice() != expected.as_slice() {
                warn!(phase, "peer app root != header-committed root — not syncing subtree");
                return Ok(false);
            }
            let pinned = if expected.is_empty() {
                None
            } else {
                <[u8; 32]>::try_from(expected.as_slice()).ok()
            };
            // Pull ONLY this shard's subtree, authenticated against the app root.
            crate::forest_sync::sync_subtree_one_phase(
                &mut client, &handle, &self.crdt, &app, phase, v_s, bits.clone(), pinned,
            )
            .await?;
        }
        Ok(true)
    }

    /// (#3) True when every phase's LOCAL root already equals the header anchor's
    /// — the node is caught up and a sync would pull nothing, so the whole cycle
    /// (gRPC connect + per-phase head round-trips + diff) can be skipped. Requires
    /// a FULL 4-phase anchor with no empty entry; a bootstrap / partial anchor
    /// returns false so the sync proceeds and trusts the peer. `compute_shard_root`
    /// is a plain forest read and aggregates sub-shards, so this works for both a
    /// single-shard app and a QUIL split.
    fn caught_up_to_anchor(&self, l2: &[u8; 32], expected_roots: &[Vec<u8>]) -> bool {
        if expected_roots.len() < 4 || expected_roots.iter().any(|r| r.is_empty()) {
            return false;
        }
        let Some(sk) = crate::forest_sync::app_shard_key(l2) else { return false };
        for phase in 0u32..4 {
            let (s, p) = crate::forest_sync::phase_strs(phase);
            let mut local = self.crdt.compute_shard_root(s, p, &sk);
            if local.is_empty() {
                // An empty local tree is the zero root of the anchor's width.
                local = vec![0u8; expected_roots[phase as usize].len()];
            }
            if local.as_slice() != expected_roots[phase as usize].as_slice() {
                return false;
            }
        }
        true
    }
}

#[async_trait]
impl ProverTreeSyncer for ProdProverTreeSyncer {
    async fn sync_prover_tree(&self, expected_roots: &[Vec<u8>]) -> Result<bool> {
        // The global prover shard is a single-shard app: L2 = [0xff; 32]. The
        // global header now commits ALL FOUR prover-shard phase roots (audit #5
        // flag-day): `expected_roots` = [prover_tree_commitment (phase 0),
        // prover_tree_aux_roots (phases 1,2,3)], so every phase is authenticated.
        // (#3) Skip the whole sync when already caught up to the committed anchor
        // — the periodic cadence would otherwise re-diff the entire prover tree
        // every tick on a node that keeps it current via its own materializer.
        if self.caught_up_to_anchor(&[0xffu8; 32], expected_roots) {
            return Ok(true);
        }
        info!(addr = %self.master_stream_addr, "syncing global prover tree (forest diff)");
        self.sync_single_shard(vec![0xffu8; 32], expected_roots).await
    }

    async fn sync_shard_tree(&self, filter: &[u8], expected_roots: &[Vec<u8>]) -> Result<bool> {
        let n = filter.len().min(32);
        let mut l2 = [0u8; 32];
        l2[..n].copy_from_slice(&filter[..n]);
        // (#3) Skip when already caught up (works for single-shard and QUIL split).
        if self.caught_up_to_anchor(&l2, expected_roots) {
            return Ok(true);
        }
        // UNIFIED mode: EVERY app is ONE L3 tree keyed by `l2`, and its four phase
        // roots ARE the header `state_roots`. A shard prover covering a specific
        // prefix (`filter = app ‖ prefix`) pulls ONLY its subtree — authenticated
        // against the header app root via the descent co-path — so it never stores
        // the whole app. A whole-app sync (no prefix, e.g. an archive) diffs the
        // one tree directly.
        if self.crdt.unified_tree() {
            let prefix_bytes: Vec<u8> = if filter.len() > 32 { filter[32..].to_vec() } else { Vec::new() };
            if prefix_bytes.is_empty() {
                info!(
                    addr = %self.master_stream_addr,
                    filter = %hex::encode(&filter[..n]),
                    "syncing app tree (unified, whole tree)"
                );
                return self.sync_single_shard(l2.to_vec(), expected_roots).await;
            }
            info!(
                addr = %self.master_stream_addr,
                filter = %hex::encode(&filter[..n]),
                "syncing shard subtree (unified, range diff — only this prefix)"
            );
            return self.sync_shard_subtree(l2, &prefix_bytes, expected_roots).await;
        }
        // QUIL splits 64-way: its state lives in sub-shard trees (app‖prefix),
        // verified as a set via the aggregation binding (all 4 phases).
        if l2 == quil_execution::domains::QUIL_TOKEN {
            info!(addr = %self.master_stream_addr, "syncing QUIL app (forest diff, 64 sub-shards)");
            return self.sync_split_shard(l2, expected_roots).await;
        }
        info!(
            addr = %self.master_stream_addr,
            filter = %hex::encode(&filter[..n]),
            "syncing app-shard tree (forest diff, single-shard)"
        );
        self.sync_single_shard(l2.to_vec(), expected_roots).await
    }
}
