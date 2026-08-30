//! Reusable forest Merkle-diff sync helpers (shared by the worker
//! [`ProverTreeSyncer`](crate::prover_tree_syncer_prod) and the archive
//! state-jump).
//!
//! Each pull does two things: (1) the efficient Merkle diff of the COMMITMENT
//! (forest JMT) via [`quil_forest::diff_leaves`] through a gRPC-backed
//! [`RemoteTreeReader`](quil_rpc::RemoteTreeReader), and (2) the readable DATA:
//! the diff's changed leaves are mapped to their vertices (via the peer's
//! key-hash → raw-key preimages) and those vertices' blobs are pulled and stored
//! in the blob keyspace — where `get_vertex_data` / the prover registry read
//! (they do NOT read the forest). Without (2) a synced node would have correct
//! roots but no readable state.

use std::sync::Arc;

use quil_hypergraph::addressing::get_bloom_filter_indices;
use quil_rpc::{ArchiveClient, RemoteTreeReader};
use quil_types::error::{QuilError, Result};
use quil_types::store::ShardKey;
use tracing::warn;

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

/// Given the CHANGED key-hashes of a synced shard/phase, fetch the raw-key
/// preimage of each (→ the vertex id), dedup, then pull and store each changed
/// vertex's blob (the readable data) into the CRDT's blob keyspace.
async fn fetch_changed_blobs(
    client: &mut ArchiveClient,
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
    phase: u32,
    // Version to REQUEST from the peer (the peer's tree version the diff
    // addressed — MVCC-pins the served blob so it matches the committed leaf).
    source_version: u64,
    // Version to SAVE at locally (the version our forest tree was applied at in
    // `sync_shard_phase_from`) — keeps the blob keyspace consistent with the tree.
    apply_version: u64,
    changed: Vec<([u8; 32], Vec<u8>)>,
) -> Result<()> {
    let Some(shard) = app_shard_key(shard_id) else { return Ok(()) };
    let shard_key_bytes: Vec<u8> = shard.l1.iter().copied().chain(shard.l2).collect();
    for (kh, leaf_value) in changed {
        // Per-vertex-subtree raw-key model: the changed `key_hash` IS the
        // vertex's 32-byte DATA address (no preimage round-trip), so the vertex
        // id is `app(32) ‖ key_hash(32)` — the app address is this shard's `l2`.
        let mut vertex_id = shard.l2.to_vec();
        vertex_id.extend_from_slice(&kh);
        // A vertex the client already holds needs no re-fetch — but ONLY if the
        // blob we hold is the CORRECT one, i.e. it hashes to the committed
        // `leaf_value` (commitment‖size) the diff just applied. The old
        // `is_some()` check skipped on ANY existing blob, including an EMPTY
        // add-side placeholder (staged by `remove_vertex` for a
        // removed-but-never-added id) or a STALE prior-version blob. That left
        // the real vertex data un-fetched: `read_blob` then returns the empty /
        // stale blob and callers see nothing (e.g. a synced prover's reward
        // balance reads 0 forever). Re-fetch unless we already hold the exact
        // committed blob.
        let have_correct = crdt
            .peek_synced_blob(&shard, phase as usize, &vertex_id)
            .filter(|b| !b.is_empty())
            .and_then(|b| quil_tries::vertex_leaf_value(&b).ok())
            .map(|recomputed| recomputed == leaf_value)
            .unwrap_or(false);
        if have_correct {
            continue;
        }
        let Some(blob) = client
            .get_vertex_blob(shard_key_bytes.clone(), phase, vertex_id.clone(), source_version)
            .await
            .map_err(|e| QuilError::Internal(format!("get_vertex_blob: {e}")))?
        else {
            // FAIL, don't skip (audit residual #4): this leaf is in the diff the
            // peer committed to in its authenticated root, so its blob MUST exist.
            // Skipping left the tree with a correct root but MISSING data (later
            // reads of this vertex return nothing). Abort so the caller retries /
            // picks another peer rather than completing an incomplete sync.
            return Err(QuilError::Internal(format!(
                "peer did not serve blob for changed vertex {} (phase {}, ver {}) — \
                 incomplete sync, aborting",
                hex::encode(&vertex_id),
                phase,
                source_version
            )));
        };
        // SECURITY: the served blob MUST hash to the committed leaf value
        // (`commitment ‖ size`), else a peer could serve data not bound to the
        // authenticated shard root we just synced.
        let recomputed = quil_tries::vertex_leaf_value(&blob)
            .map_err(|e| QuilError::Internal(format!("vertex_leaf_value: {e}")))?;
        if recomputed != leaf_value {
            return Err(QuilError::Internal(format!(
                "synced blob for {} does not match its committed commitment‖size \
                 (peer served unbound data)",
                hex::encode(&vertex_id)
            )));
        }
        crdt.save_synced_blob(&shard, phase as usize, &vertex_id, &blob, apply_version)
            .map_err(|e| QuilError::Internal(format!("save_synced_blob: {e}")))?;
    }
    Ok(())
}

/// Sync ONE forest tree's phase from a peer: diff + apply the commitment, then
/// pull the changed vertices' blobs. Returns the new root (for the caller to
/// verify, if it has an expected root).
pub async fn sync_one_phase(
    client: &mut ArchiveClient,
    handle: &tokio::runtime::Handle,
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
    phase: u32,
    source_version: u64,
    // The peer's advertised root for this shard/phase (from `get_forest_head`).
    // When it already equals our LOCAL root the trees are identical — the diff
    // would return no changed leaves and fetch no blobs — so we skip the whole
    // O(tree) diff walk (the caught-up steady state, which otherwise burns a
    // full-tree diff every sync tick and, before this, held the forest lock while
    // doing it). `None` (peer root unknown) always diffs.
    remote_root: Option<[u8; 32]>,
) -> Result<[u8; 32]> {
    // (#1) Cheap root-check short-circuit. `compute_shard_root` is a plain
    // forest read (no recompute); when it matches the peer root there is nothing
    // to sync — return it without touching the diff or the forest lock.
    if let Some(rr) = remote_root {
        if let Some(sk) = app_shard_key(shard_id) {
            let (s, p) = phase_strs(phase);
            if crdt.compute_shard_root(s, p, &sk).as_slice() == rr.as_slice() {
                return Ok(rr);
            }
        }
    }
    let remote = RemoteTreeReader::new(client.clone(), handle.clone(), shard_id.to_vec(), phase);
    let c = crdt.clone();
    let sid = shard_id.to_vec();
    // The forest-write lock is taken INSIDE `sync_shard_phase_from`, around the
    // apply only — the diff runs lock-free so it can't starve the materializer.
    let (root, apply_version, changed) = tokio::task::spawn_blocking(move || {
        c.sync_shard_phase_from(&remote, source_version, &sid, phase as usize)
    })
    .await
    .map_err(|e| QuilError::Internal(format!("sync task join: {e}")))?
    .map_err(|e| QuilError::Internal(format!("sync apply: {e}")))?;
    fetch_changed_blobs(client, crdt, shard_id, phase, source_version, apply_version, changed)
        .await?;
    Ok(root)
}

/// UNIFIED shard-prover subtree-range sync of ONE phase: pull only the leaves
/// under `bit_path` (this prover's shard prefix) from the peer's APP tree
/// (`shard_id = app`), authenticated against `pinned_app_root` (the trusted
/// header app root), and apply to the local app tree. Returns the local subtree
/// root (shard commitment). This is the per-shard counterpart of
/// [`sync_one_phase`] — a shard prover NEVER pulls the whole app.
#[allow(clippy::too_many_arguments)]
pub async fn sync_subtree_one_phase(
    client: &mut ArchiveClient,
    handle: &tokio::runtime::Handle,
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    app: &[u8],
    phase: u32,
    source_version: u64,
    bit_path: Vec<bool>,
    pinned_app_root: Option<[u8; 32]>,
) -> Result<[u8; 32]> {
    let remote = RemoteTreeReader::new(client.clone(), handle.clone(), app.to_vec(), phase);
    let c = crdt.clone();
    let app_v = app.to_vec();
    let (root, apply_version, changed) = tokio::task::spawn_blocking(move || {
        c.sync_shard_subtree_phase_from(
            &remote,
            source_version,
            &app_v,
            phase as usize,
            &bit_path,
            pinned_app_root,
        )
    })
    .await
    .map_err(|e| QuilError::Internal(format!("subtree sync task join: {e}")))?
    .map_err(|e| QuilError::Internal(format!("subtree sync apply: {e}")))?;
    fetch_changed_blobs(client, crdt, app, phase, source_version, apply_version, changed).await?;
    Ok(root)
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
    let mut client = ArchiveClient::connect_mtls(addr, falcon_signing_key)
        .await
        .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
    let handle = tokio::runtime::Handle::current();
    // The global frame the verified phase-0 tree corresponds to (from
    // `resolve_root`); 0 when phase 0 is unanchored (bootstrap/trust sync).
    let mut pinned_frame: u64 = 0;
    for phase in 0u32..4 {
        let exp = expected[phase as usize];
        let (source_version, remote_root) = if exp.is_empty() {
            let head = client
                .get_forest_head(shard_id.to_vec(), phase)
                .await
                .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))?;
            let Some((v_s, root_s)) = head else { continue };
            (v_s, <[u8; 32]>::try_from(root_s.as_slice()).ok())
        } else {
            let Ok(anchor) = <[u8; 32]>::try_from(exp) else {
                return Ok(None);
            };
            match client
                .resolve_root(shard_id.to_vec(), phase, anchor.to_vec())
                .await
                .map_err(|e| QuilError::Internal(format!("resolve_root: {e}")))?
            {
                Some((v, g)) => {
                    if phase == 0 {
                        pinned_frame = g;
                    }
                    (v, Some(anchor))
                }
                None => {
                    if phase == 0 {
                        warn!(
                            anchor = %hex::encode(exp),
                            "peer has no version for the authenticated phase-0 anchor (behind/pruned) — trying another peer",
                        );
                        return Ok(None);
                    }
                    // Auxiliary phase: accept ONLY if the anchor is the peer's
                    // current head (empty/unchanged tree — root never separately
                    // versioned); else the peer can't serve the anchored version.
                    let head = client
                        .get_forest_head(shard_id.to_vec(), phase)
                        .await
                        .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))?;
                    match head {
                        Some((v_s, root_s)) if root_s.as_slice() == exp => (v_s, Some(anchor)),
                        _ => {
                            warn!(
                                phase,
                                anchor = %hex::encode(exp),
                                "peer cannot serve the anchored phase version — trying another peer",
                            );
                            return Ok(None);
                        }
                    }
                }
            }
        };
        let got =
            sync_one_phase(&mut client, &handle, &crdt, shard_id, phase, source_version, remote_root)
                .await?;
        if !exp.is_empty() && got.as_slice() != exp {
            warn!(
                phase,
                got = %hex::encode(got),
                expected = %hex::encode(exp),
                "phase root != anchor after root-addressed pull — not committing",
            );
            return Ok(None);
        }
    }
    Ok(Some(pinned_frame))
}

/// Pull ONE forest tree (all four phases + blobs) from `addr` into the CRDT,
/// TRUSTING the peer's head — used by the state-jump, which pins to a peer's
/// generation rather than a header root. Returns the number of phases that
/// carried data. `shard_id` is `addr_path_shard_id(app, prefix)`.
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
