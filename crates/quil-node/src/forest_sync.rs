//! Reusable forest Merkle-diff sync helpers (shared by the worker
//! [`ProverTreeSyncer`](crate::prover_tree_syncer_prod) and the archive
//! state-jump).
//!
//! Each pull authenticates an efficient Merkle diff of the COMMITMENT
//! (forest JMT) via [`quil_forest::diff_leaves`] through a gRPC-backed
//! [`RemoteTreeReader`](quil_rpc::RemoteTreeReader), then downloads the readable DATA:
//! each changed leaf names a vertex whose blob is verified and committed in
//! the same bounded transaction as that leaf, in the blob keyspace — where `get_vertex_data` / the prover registry read
//! (they do NOT read the forest). A failed or interrupted download cannot
//! leave a new tree head whose data is missing.

use std::sync::Arc;

use quil_hypergraph::addressing::get_bloom_filter_indices;
use quil_rpc::{ArchiveClient, RemoteTreeReader};
use quil_types::error::{QuilError, Result};
use quil_types::store::ShardKey;
use tracing::{info, warn};

pub(crate) const EMPTY_PHASE_ROOT: [u8; 32] = *b"SPARSE_MERKLE_PLACEHOLDER_HASH__";

pub(crate) fn is_empty_phase_root(root: &[u8]) -> bool {
    root == [0u8; 32] || root == EMPTY_PHASE_ROOT
}

pub(crate) fn phase_anchor(root: &[u8]) -> Result<Option<[u8; 32]>> {
    if root.is_empty() { return Ok(None); }
    root.try_into().map(Some).map_err(|_| {
        QuilError::InvalidArgument("phase anchor must contain exactly 32 bytes".into())
    })
}

#[async_trait::async_trait]
trait PhaseSourceLookup {
    async fn head(&mut self, shard: &[u8], phase: u32) -> Result<Option<(u64, Vec<u8>)>>;
    async fn resolve(&mut self, shard: &[u8], phase: u32, root: &[u8; 32])
        -> Result<Option<(u64, u64)>>;
}

#[async_trait::async_trait]
impl PhaseSourceLookup for ArchiveClient {
    async fn head(&mut self, shard: &[u8], phase: u32) -> Result<Option<(u64, Vec<u8>)>> {
        self.get_forest_head(shard.to_vec(), phase).await
            .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))
    }

    async fn resolve(&mut self, shard: &[u8], phase: u32, root: &[u8; 32])
        -> Result<Option<(u64, u64)>> {
        self.resolve_root(shard.to_vec(), phase, root.to_vec()).await
            .map_err(|e| QuilError::Internal(format!("resolve_root: {e}")))
    }
}

#[derive(Debug, PartialEq)]
enum PhaseSource {
    Empty,
    Tree { version: u64, root: [u8; 32], global_frame: u64 },
}

/// Resolve a committed root independently of the peer's advancing live head.
/// Empty source state is successful only when the local physical tree is empty
/// too; sync cannot delete stale state just by skipping a missing peer phase.
async fn resolve_phase_source(
    source: &mut impl PhaseSourceLookup,
    crdt: &quil_hypergraph::HypergraphCrdt,
    shard: &[u8],
    phase: u32,
    expected: &[u8],
) -> Result<Option<PhaseSource>> {
    let empty_local = || -> Result<Option<PhaseSource>> {
        Ok(is_empty_phase_root(&crdt.current_forest_phase_root(shard, phase as usize)?)
            .then_some(PhaseSource::Empty))
    };
    if let Some(anchor) = phase_anchor(expected)? {
        if is_empty_phase_root(&anchor) { return empty_local(); }
        if let Some((version, global_frame)) = source.resolve(shard, phase, &anchor).await? {
            return Ok(Some(PhaseSource::Tree { version, root: anchor, global_frame }));
        }
        // Phase 0 also supplies the frame cursor, so a root match without a
        // retained root-to-frame mapping is insufficient for that phase.
        if phase != 0 {
            if let Some((version, root)) = source.head(shard, phase).await? {
                if root.as_slice() == anchor {
                    return Ok(Some(PhaseSource::Tree { version, root: anchor, global_frame: 0 }));
                }
            }
        }
        return Ok(None);
    }
    match source.head(shard, phase).await? {
        None => empty_local(),
        Some((version, root)) => {
            let root = phase_anchor(&root)?.ok_or_else(|| {
                QuilError::InvalidArgument("peer forest head has no root".into())
            })?;
            Ok(Some(PhaseSource::Tree { version, root, global_frame: 0 }))
        }
    }
}

/// `(set, phase)` string pair — the blob keyspace keying, matching the CRDT.
pub(crate) fn phase_strs(phase: u32) -> (&'static str, &'static str) {
    match phase {
        0 => ("vertex", "adds"),
        1 => ("vertex", "removes"),
        2 => ("hyperedge", "adds"),
        _ => ("hyperedge", "removes"),
    }
}

/// The app ShardKey (blob-keyspace key) for a forest `shard_id` — its first 32
/// bytes are the app address `l2` (whether it is the app itself for a
/// single-shard app, or `app‖prefix` for a QUIL sub-shard).
pub(crate) fn app_shard_key(shard_id: &[u8]) -> Option<ShardKey> {
    if shard_id.len() < 32 {
        return None;
    }
    let mut l2 = [0u8; 32];
    l2.copy_from_slice(&shard_id[..32]);
    Some(ShardKey { l1: get_bloom_filter_indices(&l2, 256, 3), l2 })
}

/// Download readable data before installing the corresponding tree leaves.
/// Empty tombstones are reconstructed directly from their authenticated leaves.
async fn fetch_sync_blob(
    client: &mut ArchiveClient,
    crdt: &quil_hypergraph::HypergraphCrdt,
    shard_id: &[u8],
    phase: u32,
    source_version: u64,
    key: &[u8; 32],
    leaf: &[u8],
) -> Result<Vec<u8>> {
    use quil_hypergraph::crdt::sync_blob_matches;
    if sync_blob_matches(phase as usize, leaf, &[])? { return Ok(Vec::new()); }
    let shard = app_shard_key(shard_id)
        .ok_or_else(|| QuilError::InvalidArgument("invalid sync shard".into()))?;
    let mut vertex_id = shard.l2.to_vec();
    vertex_id.extend_from_slice(key);
    if let Some(blob) = crdt.peek_synced_blob(&shard, phase as usize, &vertex_id) {
        if sync_blob_matches(phase as usize, leaf, &blob)? { return Ok(blob); }
    }
    let shard_bytes = shard.l1.iter().copied().chain(shard.l2).collect();
    let blob = client.get_vertex_blob_at(shard_bytes, phase, vertex_id.clone(), source_version)
        .await.map_err(|e| QuilError::Internal(format!("get_vertex_blob: {e}")))?
        .ok_or_else(|| QuilError::ExecutionUnavailable(format!(
            "peer did not serve blob {} at phase {phase}, version {source_version}", hex::encode(&vertex_id),
        )))?;
    if !sync_blob_matches(phase as usize, leaf, &blob)? {
        return Err(QuilError::InvalidArgument("peer served a blob not bound to its authenticated leaf".into()));
    }
    Ok(blob)
}

/// The tree head never advances without the data needed to read its new
/// leaves. Each bounded transaction is a resumable intermediate tree; only
/// the complete, current target root is reported as a successful sync.
#[allow(clippy::too_many_arguments)]
async fn sync_phase_data(
    client: &mut ArchiveClient,
    handle: &tokio::runtime::Handle,
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
    phase: u32,
    source_version: u64,
    bit_path: Vec<bool>,
    anchor: Option<quil_forest::SubtreeSyncAnchor>,
) -> Result<[u8; 32]> {
    use quil_hypergraph::crdt::{sync_blob_matches, MAX_SYNC_CHUNK_BYTES, MAX_SYNC_CHUNK_LEAVES};
    let remote = RemoteTreeReader::new(client.clone(), handle.clone(), shard_id.to_vec(), phase);
    let c = crdt.clone();
    let sid = shard_id.to_vec();
    let mut plan = tokio::task::spawn_blocking(move || {
        c.prepare_phase_sync(&remote, source_version, &sid, phase as usize, &bit_path, anchor)
    }).await.map_err(|e| QuilError::Internal(format!("sync preparation task: {e}")))??;
    let planned = plan.remaining().len();
    if planned > 0 {
        info!(shard = %hex::encode(&shard_id[..shard_id.len().min(8)]), phase, leaves = planned, "sync phase: installing changed leaves");
    }
    let mut next_report = 1024usize;
    while !plan.remaining().is_empty() {
        let installed = planned - plan.remaining().len();
        if installed >= next_report {
            info!(shard = %hex::encode(&shard_id[..shard_id.len().min(8)]), phase, installed, planned, "sync phase: installing");
            next_report *= 2;
        }
        let mut blobs = Vec::new();
        let mut bytes = 0usize;
        for (key, leaf) in plan.remaining().iter().take(MAX_SYNC_CHUNK_LEAVES) {
            let Some(leaf) = leaf else {
                // The prepared, root-checked GLOBAL diff proves absence. No
                // readable blob is fetched for a removed local-only record.
                blobs.push(Vec::new());
                continue;
            };
            // Size is authenticated in the leaf. Flush before fetching the
            // next blob, so collecting a cold sync never retains all blobs.
            let size = if sync_blob_matches(phase as usize, leaf, &[])? { 0 } else {
                let (_, size) = quil_tries::split_vertex_leaf(leaf)
                    .ok_or_else(|| QuilError::InvalidArgument("malformed synced vertex leaf".into()))?;
                usize::try_from(size).map_err(|_| QuilError::InvalidArgument("synced blob too large".into()))?
            };
            if size > MAX_SYNC_CHUNK_BYTES {
                return Err(QuilError::ExecutionUnavailable("synced blob exceeds the transfer limit".into()));
            }
            if !blobs.is_empty() && bytes + size > MAX_SYNC_CHUNK_BYTES { break; }
            let blob = fetch_sync_blob(client, crdt, shard_id, phase, source_version, key, leaf).await?;
            bytes += blob.len();
            blobs.push(blob);
        }
        let c = crdt.clone();
        plan = tokio::task::spawn_blocking(move || {
            c.apply_sync_chunk(&mut plan, &blobs)?;
            Ok::<_, QuilError>(plan)
        }).await.map_err(|e| QuilError::Internal(format!("sync installation task: {e}")))??;
    }
    let c = crdt.clone();
    tokio::task::spawn_blocking(move || c.finish_phase_sync(&plan))
        .await.map_err(|e| QuilError::Internal(format!("sync completion task: {e}")))?
}

/// Sync one complete phase, authenticating the remote root and installing
/// changed leaves with their readable blobs in bounded atomic transactions.
pub async fn sync_one_phase(
    client: &mut ArchiveClient,
    handle: &tokio::runtime::Handle,
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
    phase: u32,
    source_version: u64,
    remote_root: Option<[u8; 32]>,
) -> Result<[u8; 32]> {
    sync_phase_data(client, handle, crdt, shard_id, phase, source_version, Vec::new(),
        remote_root.map(quil_forest::SubtreeSyncAnchor::AppRoot)).await
}

/// Pull only the covered subtree from a unified application, pinned to the
/// subtree commitment carried in the trusted shard header.
#[allow(clippy::too_many_arguments)]
pub async fn sync_subtree_one_phase(
    client: &mut ArchiveClient,
    handle: &tokio::runtime::Handle,
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    app: &[u8],
    phase: u32,
    source_version: u64,
    bit_path: Vec<bool>,
    pinned_subtree_root: Option<[u8; 32]>,
) -> Result<[u8; 32]> {
    sync_phase_data(client, handle, crdt, app, phase, source_version, bit_path,
        pinned_subtree_root.map(quil_forest::SubtreeSyncAnchor::SubtreeRoot)).await
}

/// Sync a SINGLE-shard forest tree (all four phases + blobs) from `addr`,
/// anchoring ONLY phase 0 to `expected_va_root` (empty ⇒ trust the peer's latest
/// snapshot). A thin wrapper over [`sync_shard_phases_verified`] — correct for
/// the global prover tree (`[0xff; 32]`), whose phases 1-3 never change
/// (allocations use delete-free `Historic` reassignment, not removes), so pinning
/// only phase 0 keeps the whole tree consistent. Returns `Some(global_frame)`
/// (the frame the verified state is at, for cursor pinning) or `None` (retry).
pub async fn sync_single_shard_verified(
    addr: &str,
    falcon_signing_key: &[u8],
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
    expected_va_root: &[u8],
) -> Result<Option<u64>> {
    sync_shard_phases_verified(
        addr,
        falcon_signing_key,
        crdt,
        shard_id,
        [expected_va_root, &[], &[], &[]],
    )
    .await
}

/// Sync a single-shard forest tree (all four phases + blobs), ROOT-ADDRESSING
/// each phase whose `expected[i]` is non-empty. Returns `Some(global_frame)` from
/// phase 0's `resolve_root` (the frame the verified state corresponds to, for
/// cursor pinning; `0` when phase 0 is unanchored) or `None` (caller retries
/// another peer). `shard_id` is a single tree id — `[0xff; 32]` for the prover
/// tree, or a bare app L2 for a unified app tree.
///
/// ROOT-ADDRESSED anchoring (fixes a state-jump off-by-one): a frame commitment —
/// the global `prover_tree_commitment`, and equally an app-shard frame's
/// `state_roots[i]` — binds the PRE-application root (`root_at(N-1)`), while a
/// peer's live forest head is POST-application. Comparing the head directly
/// against the anchor is an off-by-one that stops matching the moment the tree
/// mutates every frame, so a fresh node can never anchor. Instead `resolve_root`
/// maps each anchor to the peer's `(version, global_frame)` and we sync that EXACT
/// version (retained — `resolve_root` found it within the prune window), so the
/// pulled tree hashes to the anchor by construction.
///
/// Phase 0 is crucial and frame-anchored: a `resolve_root` miss ⇒ the peer
/// pruned/never-had it ⇒ retry another peer. An auxiliary phase (1-3) whose anchor
/// is not in the version index but EQUALS the peer's current head is an
/// empty/unchanged tree (its root was never separately committed) — sync the head;
/// any other miss fails.
pub async fn sync_shard_phases_verified(
    addr: &str,
    falcon_signing_key: &[u8],
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
    expected: [&[u8]; 4],
) -> Result<Option<u64>> {
    for root in expected { phase_anchor(root)?; }
    let mut client = ArchiveClient::connect_mtls(addr, falcon_signing_key)
        .await
        .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
    let handle = tokio::runtime::Handle::current();
    // The global frame the verified phase-0 tree corresponds to (from
    // `resolve_root`); 0 when phase 0 is unanchored (bootstrap/trust sync).
    let mut pinned_frame: u64 = 0;
    for phase in 0u32..4 {
        let exp = expected[phase as usize];
        let Some(source) = resolve_phase_source(&mut client, &crdt, shard_id, phase, exp).await? else {
            warn!(phase, anchor = %hex::encode(exp),
                "phase cannot reach its anchor: source unavailable or empty source with stale local data");
            return Ok(None);
        };
        let PhaseSource::Tree { version: source_version, root: remote_root, global_frame } = source else {
            continue;
        };
        if phase == 0 { pinned_frame = global_frame; }
        let got =
            sync_one_phase(&mut client, &handle, &crdt, shard_id, phase, source_version, Some(remote_root))
                .await?;
        if !exp.is_empty() {
            if got.as_slice() != exp {
                warn!(
                    phase,
                    got = %hex::encode(got),
                    expected = %hex::encode(exp),
                    "phase root != anchor after root-addressed pull — not committing",
                );
                return Ok(None);
            }
            // Index the just-synced anchor into this node's root→version map so it
            // can later SERVE `resolve_root` for it. The sync install path does not
            // touch the index `commit_inner` maintains, so without this a node that
            // obtained its tree via sync/reconcile (e.g. an archive that reconciled
            // its prover tree rather than materializing it) misses on `resolve_root`
            // for its CURRENT roots and cannot bootstrap peers. `pinned_frame` is
            // phase 0's resolved global frame (the same header frame for phases 1-3);
            // 0 ⇒ unanchored/bootstrap ⇒ nothing to index against a frame.
            if pinned_frame != 0 {
                crdt.index_synced_root(shard_id, phase as usize, exp, pinned_frame)?;
            }
        }
    }
    Ok(Some(pinned_frame))
}

/// Pull ONE forest tree (all four phases + blobs) from `addr` into the CRDT,
/// TRUSTING the peer's head — used by the state-jump, which pins to a peer's
/// generation rather than a header root. Returns the number of phases that
/// carried data. `shard_id` is `addr_path_shard_id(app, prefix)`.
// Retained unpinned sync adapter; current callers use pinned or cancellable variants.
#[allow(dead_code)]
pub async fn pull_shard_from_peer(
    addr: &str,
    falcon_signing_key: &[u8],
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
) -> Result<usize> {
    let mut client = ArchiveClient::connect_mtls(addr, falcon_signing_key)
        .await
        .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
    let handle = tokio::runtime::Handle::current();
    let mut synced = 0usize;
    for phase in 0u32..4 {
        let head = client
            .get_forest_head(shard_id.to_vec(), phase)
            .await
            .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))?;
        let Some((v_s, root_s)) = head else { continue };
        let rr = <[u8; 32]>::try_from(root_s.as_slice()).ok();
        match sync_one_phase(&mut client, &handle, &crdt, shard_id, phase, v_s, rr).await {
            Ok(_) => synced += 1,
            Err(e) => {
                if phase == 0 {
                    return Err(e);
                }
                warn!(phase, error = %e, "forest sync: non-anchor phase failed (best-effort)");
            }
        }
    }
    Ok(synced)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Peer {
        head: Option<(u64, Vec<u8>)>,
        resolved: Option<(u64, u64)>,
        head_calls: usize,
        resolve_calls: usize,
    }

    #[async_trait::async_trait]
    impl PhaseSourceLookup for Peer {
        async fn head(&mut self, _: &[u8], _: u32) -> Result<Option<(u64, Vec<u8>)>> {
            self.head_calls += 1;
            Ok(self.head.clone())
        }
        async fn resolve(&mut self, _: &[u8], _: u32, _: &[u8; 32]) -> Result<Option<(u64, u64)>> {
            self.resolve_calls += 1;
            Ok(self.resolved)
        }
    }

    fn fixture() -> (tempfile::TempDir, Arc<quil_hypergraph::HypergraphCrdt>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
        let crdt = crate::master_node::worker_manager::build_thread_worker_hypergraph(
            &db, Arc::new(quil_tries::ShaInclusionProver), false,
        );
        (dir, crdt)
    }

    #[tokio::test]
    async fn committed_phase_resolves_history_even_when_peer_head_has_advanced() {
        let (_dir, crdt) = fixture();
        let mut peer = Peer { head: Some((40, vec![9; 32])), resolved: Some((12, 81)), head_calls: 0, resolve_calls: 0 };
        assert_eq!(resolve_phase_source(&mut peer, &crdt, &[4; 32], 0, &[7; 32]).await.unwrap(),
            Some(PhaseSource::Tree { version: 12, root: [7; 32], global_frame: 81 }));
        assert_eq!((peer.resolve_calls, peer.head_calls), (1, 0));

        // A matching live root alone cannot fabricate the phase-0 frame cursor.
        peer.resolved = None;
        peer.head = Some((40, vec![7; 32]));
        assert_eq!(resolve_phase_source(&mut peer, &crdt, &[4; 32], 0, &[7; 32]).await.unwrap(), None);
        // An unchanged auxiliary root needs no separate frame cursor.
        assert_eq!(resolve_phase_source(&mut peer, &crdt, &[4; 32], 2, &[7; 32]).await.unwrap(),
            Some(PhaseSource::Tree { version: 40, root: [7; 32], global_frame: 0 }));
        peer.head = Some((40, vec![9; 32]));
        assert_eq!(resolve_phase_source(&mut peer, &crdt, &[4; 32], 2, &[7; 32]).await.unwrap(), None);
    }

    #[tokio::test]
    async fn empty_or_absent_source_cannot_hide_stale_local_phase_data() {
        let (_dir, crdt) = fixture();
        let app = [5; 32];
        let mut peer = Peer { head: None, resolved: None, head_calls: 0, resolve_calls: 0 };
        for root in [[0; 32], EMPTY_PHASE_ROOT] {
            assert_eq!(resolve_phase_source(&mut peer, &crdt, &app, 0, &root).await.unwrap(), Some(PhaseSource::Empty));
        }
        assert_eq!((peer.head_calls, peer.resolve_calls), (0, 0));
        assert_eq!(resolve_phase_source(&mut peer, &crdt, &app, 0, &[]).await.unwrap(), Some(PhaseSource::Empty));

        crdt.add_vertex(&quil_hypergraph::Location { app_address: app, data_address: [1; 32] }, b"stale").unwrap();
        crdt.commit(1).unwrap();
        let before = crdt.current_forest_phase_root(&app, 0).unwrap();
        for root in [Vec::new(), vec![0; 32], EMPTY_PHASE_ROOT.to_vec()] {
            assert_eq!(resolve_phase_source(&mut peer, &crdt, &app, 0, &root).await.unwrap(), None);
            assert_eq!(crdt.current_forest_phase_root(&app, 0).unwrap(), before);
        }
    }

    #[tokio::test]
    async fn bootstrap_is_distinct_from_empty_or_malformed_commitments() {
        let (_dir, crdt) = fixture();
        let mut peer = Peer { head: Some((0, vec![8; 32])), resolved: None, head_calls: 0, resolve_calls: 0 };
        assert_eq!(phase_anchor(&[]).unwrap(), None);
        assert!(!is_empty_phase_root(&[]));
        assert_eq!(resolve_phase_source(&mut peer, &crdt, &[3; 32], 0, &[]).await.unwrap(),
            Some(PhaseSource::Tree { version: 0, root: [8; 32], global_frame: 0 }));
        for size in [1, 16, 31, 33, 64] {
            assert!(resolve_phase_source(&mut peer, &crdt, &[3; 32], 0, &vec![0; size]).await.is_err());
        }
        assert_eq!(peer.resolve_calls, 0);
        assert_eq!(peer.head_calls, 1);
        for root in [vec![], vec![0; 31]] {
            peer.head = Some((0, root));
            assert!(resolve_phase_source(&mut peer, &crdt, &[3; 32], 0, &[]).await.is_err());
        }
        let mut forged = EMPTY_PHASE_ROOT;
        forged[31] ^= 1;
        assert!(!is_empty_phase_root(&forged));
    }
}
