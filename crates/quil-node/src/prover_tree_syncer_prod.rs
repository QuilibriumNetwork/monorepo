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

/// Syncs authenticated trees from an archive, with optional master discovery.
pub struct ProdProverTreeSyncer {
    /// Master's directory endpoint for a separate worker, or an explicitly
    /// configured source when archive discovery is disabled.
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
    /// Separate workers discover the master's verified archive endpoints.
    /// They then read application trees directly from those archives.
    pub discover_archives_from_master: bool,
}

use crate::forest_sync::{is_empty_phase_root, phase_anchor};

impl ProdProverTreeSyncer {
    /// Predecessor outgoing history from this syncer's archive, as the engine
    /// source for a cluster worker (whose archives are discovered through its
    /// master). Unverified: the engine checks it against the sealed root.
    pub fn outgoing_history_source(self: &Arc<Self>) -> quil_engine::app_handoff::OutgoingHistorySource {
        let syncer = self.clone();
        Arc::new(move |filter, from, through| {
            let syncer = syncer.clone();
            Box::pin(async move {
                let addr = syncer.resolve_addr().await?;
                crate::storage_history::outgoing_page_from(&addr, &syncer.falcon_signing_key, filter, from, through).await
            })
        })
    }

    /// Resolve a verified archive. Separate workers must discover one through
    /// their master first: the regular master's tree is not an app-state source.
    async fn resolve_addr(&self) -> Result<String> {
        if let Some(pool) = self.archive_pool.as_ref() {
            if let Some(ep) = pool.next().await {
                return Ok(ep);
            }
            if self.discover_archives_from_master {
                let endpoints = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    let mut client = ArchiveClient::connect_own_master(&self.master_stream_addr, &self.falcon_signing_key).await?;
                    client.get_archive_endpoints().await
                }).await.map_err(|_| QuilError::ExecutionUnavailable("archive discovery timed out".into()))?
                    .map_err(|e| QuilError::ExecutionUnavailable(format!("archive discovery: {e}")))?;
                for endpoint in endpoints { pool.add(endpoint).await; }
                return pool.next().await.ok_or_else(|| QuilError::ExecutionUnavailable("master has not discovered an archive yet".into()));
            }
        }
        Ok(self.master_stream_addr.clone())
    }

    /// Resolve each committed phase at its retained version, then install its
    /// authenticated leaves and data. The peer may have advanced since the
    /// header was finalized; live-head equality is not required.
    async fn sync_single_shard(&self, shard_id: Vec<u8>, expected_roots: &[Vec<u8>]) -> Result<bool> {
        let expected = std::array::from_fn(|phase| {
            expected_roots.get(phase).map_or(&[][..], Vec::as_slice)
        });
        Ok(crate::forest_sync::sync_shard_phases_verified(
            &self.resolve_addr().await?,
            &self.falcon_signing_key,
            self.crdt.clone(),
            &shard_id,
            expected,
        ).await?.is_some())
    }

    /// Sync a SPLIT app (QUIL: 64 sub-shards). `expected_roots` is the header's
    /// `state_roots`: index `p` is the AGGREGATE root of phase `p`
    /// across the sub-shards. For EVERY phase we verify the fetched sub-shard set
    /// aggregates to `expected_roots[p]` — one binding that authenticates all 64
    /// sub-shard roots at once — BEFORE diffing + applying. Absent sub-shards
    /// contribute the zero root, so the aggregate matches `commit_inner`. Any
    /// phase whose aggregate or post-apply root diverges aborts the sync.
    /// Previously only phase 0 was bound; phases 1–3 could be served divergent.
    async fn sync_split_shard(&self, app: [u8; 32], expected_roots: &[Vec<u8>]) -> Result<bool> {
        let mut client = ArchiveClient::connect_mtls(&self.resolve_addr().await?, &self.falcon_signing_key)
            .await
            .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
        let handle = tokio::runtime::Handle::current();
        let sub_shards = self.crdt.app_sub_shards(&app);
        for phase in 0u32..4 {
            let expected = expected_roots.get(phase as usize).cloned().unwrap_or_default();
            phase_anchor(&expected)?;
            if is_empty_phase_root(&expected) {
                for (id, _) in &sub_shards {
                    if !is_empty_phase_root(&self.crdt.current_forest_phase_root(id, phase as usize)?) {
                        warn!(phase, "committed empty split phase still has local data");
                        return Ok(false);
                    }
                }
                continue;
            }
            // Fetch every sub-shard's head for this phase.
            let mut heads: Vec<(Vec<u8>, Vec<bool>, Option<(u64, [u8; 32])>)> =
                Vec::with_capacity(sub_shards.len());
            for (shard_id, bits) in &sub_shards {
                let h = client
                    .get_forest_head(shard_id.clone(), phase)
                    .await
                    .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))?;
                let h32 = h.map(|(v, r)| {
                    let root = phase_anchor(&r)?.ok_or_else(|| {
                        QuilError::InvalidArgument("peer forest head has no root".into())
                    })?;
                    Ok::<_, QuilError>((v, root))
                }).transpose()?;
                if h32.is_none()
                    && !is_empty_phase_root(&self.crdt.current_forest_phase_root(shard_id, phase as usize)?) {
                    warn!(phase, "absent split phase still has local data");
                    return Ok(false);
                }
                heads.push((shard_id.clone(), bits.clone(), h32));
            }
            // Anchor: the aggregate of all sub-shard roots for THIS
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

    /// Pull the covered subtree against the commitment in a unified shard
    /// header. The archive can hold other shards at unrelated heights; its
    /// whole-app root is neither the header commitment nor a required anchor.
    async fn sync_shard_subtree(
        &self,
        filter: &[u8],
        expected_roots: &[Vec<u8>],
    ) -> Result<bool> {
        let bits = self.crdt.canonical_bits_for_filter(filter).ok_or_else(|| {
            QuilError::InvalidArgument("invalid shard filter for subtree sync".into())
        })?;
        let app = &filter[..32];
        let addr = self.resolve_addr().await?;
        let mut client = ArchiveClient::connect_mtls(&addr, &self.falcon_signing_key)
            .await
            .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
        let handle = tokio::runtime::Handle::current();
        for phase in 0u32..4 {
            let pinned = phase_anchor(expected_roots.get(phase as usize).map_or(&[][..], Vec::as_slice))?;
            if pinned.as_ref().is_some_and(|root| is_empty_phase_root(root)) {
                let (set, phase_name) = crate::forest_sync::phase_strs(phase);
                let local = self.crdt.sub_shard_commitment_for_filter(set, phase_name, filter);
                if !is_empty_phase_root(&local) {
                    warn!(phase, "committed empty shard phase has stale or unreadable local state");
                    return Ok(false);
                }
                continue;
            }
            let source_version = if let Some(root) = pinned {
                match client.resolve_root(filter.to_vec(), phase, root.to_vec()).await {
                    Ok(Some((version, _))) => version,
                    Ok(None) => {
                        warn!(phase, peer = %addr, filter = %hex::encode(filter),
                            root = %hex::encode(root), "peer does not retain the committed shard subtree");
                        return Ok(false);
                    }
                    Err(e) => return Err(QuilError::Internal(format!("resolve shard subtree: {e}"))),
                }
            } else {
                // No header exists for a brand-new child shard. Bootstrap must
                // actually pull its inherited subtree; no anchor is not empty state.
                match client.get_forest_head(app.to_vec(), phase).await
                    .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))? {
                    Some((version, _)) => version,
                    None => {
                        let (set, phase_name) = crate::forest_sync::phase_strs(phase);
                        let local = self.crdt.sub_shard_commitment_for_filter(set, phase_name, filter);
                        if !is_empty_phase_root(&local) {
                            return Ok(false);
                        }
                        continue;
                    }
                }
            };
            let got = crate::forest_sync::sync_subtree_one_phase(
                &mut client, &handle, &self.crdt, app, phase, source_version, bits.clone(), pinned,
            ).await?;
            if pinned.is_some_and(|expected| got != expected) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// True when every phase's LOCAL root already equals the header anchor's
    /// — the node is caught up and a sync would pull nothing, so the whole cycle
    /// (gRPC connect + per-phase head round-trips + diff) can be skipped. Requires
    /// a FULL 4-phase anchor with no empty entry; a bootstrap / partial anchor
    /// returns false so the sync proceeds and trusts the peer. `compute_shard_root`
    /// is a plain forest read and aggregates sub-shards, so this works for both a
    /// single-shard app and a QUIL split.
    fn caught_up_to_anchor(&self, filter: &[u8], expected_roots: &[Vec<u8>]) -> bool {
        if expected_roots.len() != 4 || expected_roots.iter().any(|r| r.len() != 32) {
            return false;
        }
        let Some(sk) = crate::forest_sync::app_shard_key(filter) else { return false };
        let scopes = if self.crdt.unified_tree() {
            let Some(bits) = self.crdt.canonical_bits_for_filter(filter) else { return false };
            vec![(sk.l2.to_vec(), bits)]
        } else {
            self.crdt.app_sub_shards(&sk.l2).into_iter().map(|(id, _)| (id, Vec::new())).collect()
        };
        for phase in 0u32..4 {
            let (s, p) = crate::forest_sync::phase_strs(phase);
            let local = if self.crdt.unified_tree() {
                self.crdt.sub_shard_commitment_for_filter(s, p, filter)
            } else {
                self.crdt.compute_shard_root(s, p, &sk)
            };
            if local.is_empty() {
                // Unreadable/malformed state is not an authenticated empty tree.
                return false;
            }
            if local.as_slice() != expected_roots[phase as usize].as_slice() {
                return false;
            }
            if !is_empty_phase_root(&local) && scopes.iter().any(|(id, bits)| {
                !self.crdt.sync_data_ready(id, phase as usize, bits).unwrap_or(false)
            }) {
                // Old sync code could reach this root before its data arrived.
                // Repair/audit it once before enabling the root-only shortcut.
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
        // global header commits ALL FOUR prover-shard phase roots (a flag-day
        // change): `expected_roots` = [prover_tree_commitment (phase 0),
        // prover_tree_aux_roots (phases 1,2,3)], so every phase is authenticated.
        // Skip the whole sync when already caught up to the committed anchor
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
        // Skip when already caught up (works for single-shard and QUIL split).
        if self.caught_up_to_anchor(filter, expected_roots) {
            return Ok(true);
        }
        // UNIFIED mode: EVERY app is ONE L3 tree keyed by `l2`, and its four phase
        // roots ARE the header `state_roots`. A shard prover covering a specific
        // prefix (`filter = app ‖ prefix`) pulls ONLY its subtree — authenticated
        // against the header subtree root — so it never stores
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
            return self.sync_shard_subtree(filter, expected_roots).await;
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

    async fn get_app_shard_frame(
        &self,
        filter: &[u8],
        frame_number: u64,
    ) -> Result<Option<quil_types::proto::global::AppShardFrame>> {
        let addr = self.resolve_addr().await?;
        let mut client = ArchiveClient::connect_mtls(&addr, &self.falcon_signing_key)
            .await
            .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
        client
            .get_app_shard_frame(filter.to_vec(), frame_number)
            .await
            .map_err(|e| QuilError::Internal(format!("get app-shard frame: {e}")))
    }
}

#[cfg(test)]
mod archive_routing_tests {
    use super::*;

    #[tokio::test]
    async fn worker_tree_recovery_uses_archives_and_never_falls_back_to_master_state() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(std::time::Duration::ZERO));
        let mut syncer = ProdProverTreeSyncer {
            master_stream_addr: String::new(), hg_store, crdt,
            falcon_signing_key: vec![], archive_pool: Some(pool.clone()),
            discover_archives_from_master: true,
        };
        // Discovery failure is retryable; an empty archive pool must not turn
        // into a read of the regular master's incomplete application forest.
        assert!(syncer.resolve_addr().await.is_err());
        pool.add("127.0.0.1:8340".into()).await;
        pool.add("127.0.0.1:8350".into()).await;
        assert_eq!(syncer.resolve_addr().await.unwrap(), "127.0.0.1:8340");
        assert_eq!(syncer.resolve_addr().await.unwrap(), "127.0.0.1:8350");
        // Explicit fixed-source tools retain their existing source selection.
        syncer.archive_pool = None;
        syncer.discover_archives_from_master = false;
        syncer.master_stream_addr = "127.0.0.1:8340".into();
        assert_eq!(syncer.resolve_addr().await.unwrap(), "127.0.0.1:8340");
    }
}
