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

/// The GLOBAL prover tree. The prover-tree resets wiped all four of its
/// phases on the archives and reseeded phase 0 only.
const PROVER_SHARD: [u8; 32] = [0xff; 32];

/// One whole-tree sync per tree at a time. The initial, periodic and
/// gossip-bootstrap prover-tree syncs (and a state-jump) each walked the same
/// tree from the same archives at once; a sync that waits here finds the
/// tree already current and transfers little.
async fn tree_sync_turn(
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
) -> tokio::sync::OwnedMutexGuard<()> {
    type Turns = std::collections::HashMap<(usize, Vec<u8>), Arc<tokio::sync::Mutex<()>>>;
    static TURNS: std::sync::LazyLock<std::sync::Mutex<Turns>> =
        std::sync::LazyLock::new(Default::default);
    // Keyed by store as well: a scratch tree (historical committees) never
    // waits on the node's own.
    let key = (Arc::as_ptr(crdt) as usize, shard_id.to_vec());
    let turn = TURNS.lock().unwrap().entry(key).or_default().clone();
    match turn.clone().try_lock_owned() {
        Ok(guard) => guard,
        Err(_) => {
            info!(shard = %hex::encode(shard_id),
                "tree sync: another sync of this tree is running; waiting for it");
            turn.lock_owned().await
        }
    }
}

pub(crate) fn is_empty_phase_root(root: &[u8]) -> bool {
    root == [0u8; 32] || root == EMPTY_PHASE_ROOT
}

pub(crate) fn phase_anchor(root: &[u8]) -> Result<Option<[u8; 32]>> {
    if root.is_empty() {
        return Ok(None);
    }
    root.try_into().map(Some).map_err(|_| {
        QuilError::InvalidArgument("phase anchor must contain exactly 32 bytes".into())
    })
}

#[async_trait::async_trait]
trait PhaseSourceLookup {
    async fn head(&mut self, shard: &[u8], phase: u32) -> Result<Option<(u64, Vec<u8>)>>;
    async fn resolve(
        &mut self,
        shard: &[u8],
        phase: u32,
        root: &[u8; 32],
    ) -> Result<Option<(u64, u64)>>;
}

#[async_trait::async_trait]
impl PhaseSourceLookup for ArchiveClient {
    async fn head(&mut self, shard: &[u8], phase: u32) -> Result<Option<(u64, Vec<u8>)>> {
        quil_rpc::forest_sync_reader::forest_head(self, shard.to_vec(), phase)
            .await
            .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))
    }

    async fn resolve(
        &mut self,
        shard: &[u8],
        phase: u32,
        root: &[u8; 32],
    ) -> Result<Option<(u64, u64)>> {
        quil_rpc::forest_sync_reader::resolve_forest_root(
            self,
            shard.to_vec(),
            phase,
            root.to_vec(),
        )
        .await
        .map_err(|e| QuilError::Internal(format!("resolve_root: {e}")))
    }
}

#[derive(Debug, PartialEq)]
enum PhaseSource {
    Empty,
    Tree {
        version: u64,
        root: [u8; 32],
        global_frame: u64,
    },
}

/// Resolve a committed root independently of the peer's advancing live head.
/// Empty source state is successful only when the local physical tree is empty
/// too (see [`empty_source`]); sync cannot delete stale state just by skipping
/// a missing peer phase.
async fn resolve_phase_source(
    source: &mut impl PhaseSourceLookup,
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    shard: &[u8],
    phase: u32,
    expected: &[u8],
) -> Result<Option<PhaseSource>> {
    if let Some(anchor) = phase_anchor(expected)? {
        if is_empty_phase_root(&anchor) {
            return empty_source(
                crdt,
                shard,
                phase,
                "the committed root of this phase is empty",
            )
            .await;
        }
        if let Some((version, global_frame)) = source.resolve(shard, phase, &anchor).await? {
            return Ok(Some(PhaseSource::Tree {
                version,
                root: anchor,
                global_frame,
            }));
        }
        // Phase 0 also supplies the frame cursor, so a root match without a
        // retained root-to-frame mapping is insufficient for that phase.
        if phase != 0 {
            if let Some((version, root)) = source.head(shard, phase).await? {
                if root.as_slice() == anchor {
                    return Ok(Some(PhaseSource::Tree {
                        version,
                        root: anchor,
                        global_frame: 0,
                    }));
                }
            }
        }
        return Ok(None);
    }
    match source.head(shard, phase).await? {
        None => empty_source(crdt, shard, phase, "the archive holds no such phase").await,
        Some((version, root)) => {
            let root = phase_anchor(&root)?
                .ok_or_else(|| QuilError::InvalidArgument("peer forest head has no root".into()))?;
            Ok(Some(PhaseSource::Tree {
                version,
                root,
                global_frame: 0,
            }))
        }
    }
}

/// The source holds nothing in `phase`: in step when the local tree is empty
/// too, otherwise refused, except for an auxiliary phase (removes or
/// hyperedges) of the GLOBAL prover tree. A store that synced that tree before
/// the prover-tree resets keeps the phases they emptied, which no sync would
/// ever remove, and its tombstones hide re-created allocations; such a phase
/// is emptied here. Phase 0 and application shards stay refused.
async fn empty_source(
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    shard: &[u8],
    phase: u32,
    reason: &'static str,
) -> Result<Option<PhaseSource>> {
    let local = crdt.current_forest_phase_root(shard, phase as usize)?;
    if is_empty_phase_root(&local) {
        return Ok(Some(PhaseSource::Empty));
    }
    if shard != PROVER_SHARD.as_slice() || phase == 0 {
        return Ok(None);
    }
    let (c, sid) = (crdt.clone(), shard.to_vec());
    let leaves =
        tokio::task::spawn_blocking(move || c.wipe_shard_phase(&sid, phase as usize, local))
            .await
            .map_err(|e| QuilError::Internal(format!("phase wipe task: {e}")))??;
    info!(shard = %hex::encode(shard), phase, leaves, reason,
        "prover tree sync: emptied a local phase that predates the prover-tree reset");
    Ok(Some(PhaseSource::Empty))
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
    Some(ShardKey {
        l1: get_bloom_filter_indices(&l2, 256, 3),
        l2,
    })
}

/// Fetch the readable blobs for `leaves` (`None`: a removal, which needs
/// none). Tombstones are rebuilt from their leaves and local copies are
/// reused; the rest come from the archive in batched requests (one key per
/// request from an archive without them). Each blob is checked against its
/// authenticated leaf.
async fn fetch_sync_blobs(
    client: &mut ArchiveClient,
    crdt: &quil_hypergraph::HypergraphCrdt,
    shard_id: &[u8],
    phase: u32,
    source_version: u64,
    leaves: &[([u8; 32], Option<Vec<u8>>)],
) -> Result<Vec<Vec<u8>>> {
    use quil_hypergraph::crdt::sync_blob_matches;
    let shard = app_shard_key(shard_id)
        .ok_or_else(|| QuilError::InvalidArgument("invalid sync shard".into()))?;
    let mut blobs: Vec<Option<Vec<u8>>> = Vec::with_capacity(leaves.len());
    let mut wanted: Vec<(usize, Vec<u8>)> = Vec::new();
    for (i, (key, leaf)) in leaves.iter().enumerate() {
        let Some(leaf) = leaf else {
            // The prepared, root-checked GLOBAL diff proves absence. No
            // readable blob is fetched for a removed local-only record.
            blobs.push(Some(Vec::new()));
            continue;
        };
        if sync_blob_matches(phase as usize, leaf, &[])? {
            blobs.push(Some(Vec::new()));
            continue;
        }
        let mut vertex_id = shard.l2.to_vec();
        vertex_id.extend_from_slice(key);
        match crdt.peek_synced_blob(&shard, phase as usize, &vertex_id) {
            Some(blob) if sync_blob_matches(phase as usize, leaf, &blob)? => blobs.push(Some(blob)),
            _ => {
                blobs.push(None);
                wanted.push((i, vertex_id));
            }
        }
    }
    if !wanted.is_empty() {
        let shard_bytes: Vec<u8> = shard.l1.iter().copied().chain(shard.l2).collect();
        let fetched =
            fetch_remote_blobs(client, &shard_bytes, phase, source_version, &wanted).await?;
        for ((i, vertex_id), blob) in wanted.into_iter().zip(fetched) {
            let blob = blob.ok_or_else(|| {
                QuilError::ExecutionUnavailable(format!(
                    "peer did not serve blob {} at phase {phase}, version {source_version}",
                    hex::encode(&vertex_id),
                ))
            })?;
            let leaf = leaves[i]
                .1
                .as_deref()
                .expect("only leaves with values are fetched");
            if !sync_blob_matches(phase as usize, leaf, &blob)? {
                return Err(QuilError::InvalidArgument(
                    "peer served a blob not bound to its authenticated leaf".into(),
                ));
            }
            blobs[i] = Some(blob);
        }
    }
    Ok(blobs
        .into_iter()
        .map(|blob| blob.expect("every blob resolved"))
        .collect())
}

async fn fetch_remote_blobs(
    client: &mut ArchiveClient,
    shard_bytes: &[u8],
    phase: u32,
    source_version: u64,
    wanted: &[(usize, Vec<u8>)],
) -> Result<Vec<Option<Vec<u8>>>> {
    use quil_rpc::forest_sync_reader::{fetch_in_batches, retry_forest_read};
    let keys: Vec<(Vec<u8>, u64)> = wanted
        .iter()
        .map(|(_, id)| (id.clone(), source_version))
        .collect();
    let batched = fetch_in_batches(keys.clone(), |chunk: Vec<(Vec<u8>, u64)>| {
        let (mut client, shard_bytes) = (client.clone(), shard_bytes.to_vec());
        async move { client.get_vertex_blobs(shard_bytes, phase, chunk).await }
    })
    .await;
    match batched {
        Ok(blobs) => Ok(blobs),
        Err(e) if e.is_unimplemented() => {
            let mut blobs = Vec::with_capacity(keys.len());
            for (id, version) in keys {
                let blob = retry_forest_read(|| {
                    let (mut client, shard_bytes, id) =
                        (client.clone(), shard_bytes.to_vec(), id.clone());
                    async move {
                        client
                            .get_vertex_blob_at(shard_bytes, phase, id, version)
                            .await
                    }
                })
                .await
                .map_err(|e| QuilError::Internal(format!("get_vertex_blob: {e}")))?;
                blobs.push(blob);
            }
            Ok(blobs)
        }
        Err(e) => Err(QuilError::Internal(format!("get_vertex_blobs: {e}"))),
    }
}

/// How many times a sync rebases onto local commits before giving up.
const MAX_SYNC_REBASES: usize = 16;
/// How long a chunk waits out local writes staged but not yet committed.
const STAGED_WRITES_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
/// How often a long install logs its progress between doublings.
const SYNC_PROGRESS_REPEAT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// The tree head never advances without the data needed to read its new
/// leaves. Each bounded transaction is a resumable intermediate tree; only
/// the complete, current target root is reported as a successful sync.
/// A local commit landing mid-download rebases the plan (see
/// [`quil_hypergraph::HypergraphCrdt::rebase_phase_sync`]) rather than
/// discarding the download. `filter` names the shard in logs.
#[allow(clippy::too_many_arguments)]
async fn sync_phase_data(
    client: &mut ArchiveClient,
    handle: &tokio::runtime::Handle,
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
    filter: &[u8],
    phase: u32,
    source_version: u64,
    bit_path: Vec<bool>,
    anchor: Option<quil_forest::SubtreeSyncAnchor>,
) -> Result<[u8; 32]> {
    let remote = RemoteTreeReader::new(client.clone(), handle.clone(), shard_id.to_vec(), phase)
        .labelled(filter.to_vec());
    let (client, store, shard) = (client.clone(), crdt.clone(), shard_id.to_vec());
    let fetch = move |leaves: Vec<([u8; 32], Option<Vec<u8>>)>| {
        let (mut client, store, shard) = (client.clone(), store.clone(), shard.clone());
        async move {
            fetch_sync_blobs(&mut client, &store, &shard, phase, source_version, &leaves).await
        }
    };
    install_phase(
        crdt,
        shard_id,
        filter,
        phase,
        source_version,
        bit_path,
        anchor,
        remote,
        fetch,
    )
    .await
}

/// [`sync_phase_data`] from `source`, whose blobs `fetch` supplies for the
/// leaves of each chunk.
///
/// A worker's recovery past its turn's hold limit hands the turn back after
/// a chunk with more of the phase to come
/// ([`quil_engine::worker_execution::recovery_turn_spent`]), never at a phase
/// boundary: the chunk leaves its scope marked incomplete
/// (`HypergraphCrdt::sync_incomplete`), so the shard's partial data never
/// counts as staged between turns, while a phase it completed leaves no
/// marker for the phases after it. Its installed chunks stay, and its next
/// sync diffs against them.
#[allow(clippy::too_many_arguments)]
async fn install_phase<R, F, Fut>(
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
    filter: &[u8],
    phase: u32,
    source_version: u64,
    bit_path: Vec<bool>,
    anchor: Option<quil_forest::SubtreeSyncAnchor>,
    source: R,
    mut fetch: F,
) -> Result<[u8; 32]>
where
    R: quil_forest::BatchTreeReader + Send + 'static,
    F: FnMut(Vec<([u8; 32], Option<Vec<u8>>)>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<Vec<u8>>>>,
{
    use quil_engine::worker_execution::{recovery_turn_spent, turn_spent_error};
    use quil_hypergraph::crdt::{
        sync_blob_matches, sync_phase_advanced, sync_staged_writes, MAX_SYNC_CHUNK_BYTES,
        MAX_SYNC_CHUNK_LEAVES,
    };
    let c = crdt.clone();
    let sid = shard_id.to_vec();
    let started = std::time::Instant::now();
    let mut plan = tokio::task::spawn_blocking(move || {
        c.prepare_phase_sync(
            &source,
            source_version,
            &sid,
            phase as usize,
            &bit_path,
            anchor,
        )
    })
    .await
    .map_err(|e| QuilError::Internal(format!("sync preparation task: {e}")))??;
    let filter = hex::encode(filter);
    let mut planned = plan.remaining().len();
    // A worker's recovery reports its progress; other syncs report nothing.
    let progress = |installed: usize, planned: usize| {
        quil_engine::worker_execution::recovery_leaves(phase, installed as u64, planned as u64);
    };
    progress(0, planned);
    if planned > 0 {
        info!(%filter, phase, leaves = planned, walk_secs = started.elapsed().as_secs(),
            "sync phase: installing changed leaves");
    }
    let mut next_report = 1024usize;
    // When a progress line was last logged; an install that logged one
    // also logs its end.
    let mut reported: Option<std::time::Instant> = None;
    let mut rebases = 0usize;
    let mut staged_since: Option<std::time::Instant> = None;
    loop {
        while !plan.remaining().is_empty() {
            let installed = planned.saturating_sub(plan.remaining().len());
            progress(installed, planned);
            if installed >= next_report
                || (installed > 0 && reported.unwrap_or(started).elapsed() >= SYNC_PROGRESS_REPEAT)
            {
                info!(%filter, phase, installed, planned, rebases,
                    elapsed_secs = started.elapsed().as_secs(), "sync phase: installing");
                while next_report <= installed {
                    next_report *= 2;
                }
                reported = Some(std::time::Instant::now());
            }
            // Take leaves up to the chunk's leaf and byte limits; sizes are
            // authenticated in the leaves, so no blob is held beyond a chunk.
            let mut take = 0usize;
            let mut bytes = 0usize;
            for (_, leaf) in plan.remaining().iter().take(MAX_SYNC_CHUNK_LEAVES) {
                let size = match leaf {
                    None => 0,
                    Some(leaf) if sync_blob_matches(phase as usize, leaf, &[])? => 0,
                    Some(leaf) => {
                        let (_, size) = quil_tries::split_vertex_leaf(leaf).ok_or_else(|| {
                            QuilError::InvalidArgument("malformed synced vertex leaf".into())
                        })?;
                        usize::try_from(size).map_err(|_| {
                            QuilError::InvalidArgument("synced blob too large".into())
                        })?
                    }
                };
                if size > MAX_SYNC_CHUNK_BYTES {
                    return Err(QuilError::ExecutionUnavailable(
                        "synced blob exceeds the transfer limit".into(),
                    ));
                }
                if take > 0 && bytes + size > MAX_SYNC_CHUNK_BYTES {
                    break;
                }
                bytes += size;
                take += 1;
            }
            let leaves = plan.remaining()[..take].to_vec();
            let blobs = fetch(leaves).await?;
            let c = crdt.clone();
            let (returned, applied) = tokio::task::spawn_blocking(move || {
                let applied = c.apply_sync_chunk(&mut plan, &blobs);
                (plan, applied)
            })
            .await
            .map_err(|e| QuilError::Internal(format!("sync installation task: {e}")))?;
            plan = returned;
            match applied {
                Ok(()) => {
                    staged_since = None;
                    quil_engine::worker_execution::recovery_installed(take as u64);
                    // Only with more of the phase to come, so the scope
                    // stays marked incomplete. A repair of legacy state
                    // restarts its audit when prepared again, so it keeps
                    // its turn until done.
                    if !plan.remaining().is_empty() && plan.resumable() && recovery_turn_spent() {
                        return Err(turn_spent_error());
                    }
                }
                Err(e) if sync_staged_writes(&e) => {
                    let since = *staged_since.get_or_insert_with(std::time::Instant::now);
                    if since.elapsed() >= STAGED_WRITES_WAIT {
                        return Err(e);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                Err(e) if sync_phase_advanced(&e) && rebases < MAX_SYNC_REBASES => {
                    rebases += 1;
                    plan = rebase(crdt, plan).await?;
                    planned = plan.remaining().len();
                    info!(%filter, phase, rebases, leaves = planned,
                        "sync phase: local tree advanced; rebased onto it");
                }
                Err(e) => return Err(e),
            }
        }
        progress(planned, planned);
        let c = crdt.clone();
        let (returned, finished) = tokio::task::spawn_blocking(move || {
            let finished = c.finish_phase_sync(&plan);
            (plan, finished)
        })
        .await
        .map_err(|e| QuilError::Internal(format!("sync completion task: {e}")))?;
        plan = returned;
        match finished {
            Err(e) if sync_phase_advanced(&e) && rebases < MAX_SYNC_REBASES => {
                rebases += 1;
                plan = rebase(crdt, plan).await?;
                planned = plan.remaining().len();
            }
            other => {
                if reported.is_some() {
                    info!(%filter, phase, leaves = planned, rebases,
                        elapsed_secs = started.elapsed().as_secs(),
                        outcome = if other.is_ok() { "installed" } else { "failed" },
                        "sync phase: installing changed leaves finished");
                }
                return other;
            }
        }
    }
}

async fn rebase(
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    mut plan: quil_hypergraph::crdt::ForestSyncPlan,
) -> Result<quil_hypergraph::crdt::ForestSyncPlan> {
    let c = crdt.clone();
    tokio::task::spawn_blocking(move || {
        c.rebase_phase_sync(&mut plan)?;
        Ok::<_, QuilError>(plan)
    })
    .await
    .map_err(|e| QuilError::Internal(format!("sync rebase task: {e}")))?
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
    sync_phase_data(
        client,
        handle,
        crdt,
        shard_id,
        shard_id,
        phase,
        source_version,
        Vec::new(),
        remote_root.map(quil_forest::SubtreeSyncAnchor::AppRoot),
    )
    .await
}

/// Pull only the covered subtree of shard `filter` from a unified
/// application, pinned to the subtree commitment carried in the trusted
/// shard header.
#[allow(clippy::too_many_arguments)]
pub async fn sync_subtree_one_phase(
    client: &mut ArchiveClient,
    handle: &tokio::runtime::Handle,
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    app: &[u8],
    filter: &[u8],
    phase: u32,
    source_version: u64,
    bit_path: Vec<bool>,
    pinned_subtree_root: Option<[u8; 32]>,
) -> Result<[u8; 32]> {
    sync_phase_data(
        client,
        handle,
        crdt,
        app,
        filter,
        phase,
        source_version,
        bit_path,
        pinned_subtree_root.map(quil_forest::SubtreeSyncAnchor::SubtreeRoot),
    )
    .await
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
    sync_shard_phases(addr, falcon_signing_key, crdt, shard_id, expected, false).await
}

async fn sync_shard_phases(
    addr: &str,
    falcon_signing_key: &[u8],
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
    expected: [&[u8]; 4],
    pinned_only: bool,
) -> Result<Option<u64>> {
    for root in expected {
        phase_anchor(root)?;
    }
    let mut client = ArchiveClient::connect_mtls(addr, falcon_signing_key)
        .await
        .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
    sync_shard_phases_on(&mut client, crdt, shard_id, expected, pinned_only).await
}

/// [`sync_shard_phases_verified`] over an already connected archive client;
/// with `pinned_only`, only the phases `expected` pins are synced, and an
/// unpinned phase is left as it is rather than taken from the peer's head.
pub(crate) async fn sync_shard_phases_on(
    client: &mut ArchiveClient,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    shard_id: &[u8],
    expected: [&[u8]; 4],
    pinned_only: bool,
) -> Result<Option<u64>> {
    for root in expected {
        phase_anchor(root)?;
    }
    let _turn = tree_sync_turn(&crdt, shard_id).await;
    let mut client = client.clone();
    let handle = tokio::runtime::Handle::current();
    // The global frame the verified phase-0 tree corresponds to (from
    // `resolve_root`); 0 when phase 0 is unanchored (bootstrap/trust sync).
    let mut pinned_frame: u64 = 0;
    for phase in 0u32..4 {
        let exp = expected[phase as usize];
        if pinned_only && exp.is_empty() {
            continue;
        }
        let Some(source) = resolve_phase_source(&mut client, &crdt, shard_id, phase, exp).await?
        else {
            warn!(phase, shard = %hex::encode(shard_id), anchor = %hex::encode(exp),
                "phase cannot reach its anchor: source unavailable or empty source with stale local data");
            return Ok(None);
        };
        let PhaseSource::Tree {
            version: source_version,
            root: remote_root,
            global_frame,
        } = source
        else {
            continue;
        };
        if phase == 0 {
            pinned_frame = global_frame;
        }
        let got = sync_one_phase(
            &mut client,
            &handle,
            &crdt,
            shard_id,
            phase,
            source_version,
            Some(remote_root),
        )
        .await?;
        if !exp.is_empty() {
            if got.as_slice() != exp {
                warn!(
                    phase,
                    shard = %hex::encode(shard_id),
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
    let _turn = tree_sync_turn(&crdt, shard_id).await;
    let mut client = ArchiveClient::connect_mtls(addr, falcon_signing_key)
        .await
        .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
    let handle = tokio::runtime::Handle::current();
    let mut synced = 0usize;
    for phase in 0u32..4 {
        let head = quil_rpc::forest_sync_reader::forest_head(&client, shard_id.to_vec(), phase)
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

    /// An in-memory tree.
    fn memory_crdt() -> Arc<quil_hypergraph::HypergraphCrdt> {
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        crdt.set_unified_tree(true);
        crdt
    }

    /// The blob of the vertex at `address` in [`source_of`]'s trees.
    fn blob_of(address: &[u8; 32]) -> Vec<u8> {
        address[..8].repeat(5)
    }

    /// A tree of `app` holding `count` vertices, committed: its phase-0
    /// version and root.
    fn source_of(
        app: [u8; 32],
        count: u16,
    ) -> (Arc<quil_hypergraph::HypergraphCrdt>, u64, [u8; 32]) {
        let source = memory_crdt();
        for i in 0..count {
            let mut address = [0x5a; 32];
            address[..2].copy_from_slice(&i.to_be_bytes());
            source
                .add_vertex(
                    &quil_hypergraph::Location {
                        app_address: app,
                        data_address: address,
                    },
                    &blob_of(&address),
                )
                .unwrap();
        }
        source.commit(1).unwrap();
        let (version, root) = source.serve_forest_head(&app, 0).unwrap();
        (source, version, root)
    }

    /// Install phase 0 of `app` from `source` into `target`, counting the
    /// leaves whose blobs it fetched.
    async fn install_from(
        source: &Arc<quil_hypergraph::HypergraphCrdt>,
        target: &Arc<quil_hypergraph::HypergraphCrdt>,
        app: [u8; 32],
        version: u64,
        root: [u8; 32],
        fetched: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> Result<[u8; 32]> {
        let reader = quil_hypergraph::testing::CrdtTreeReader {
            source: source.clone(),
            shard_id: app.to_vec(),
            phase: 0,
        };
        let fetched = fetched.clone();
        let fetch = move |leaves: Vec<([u8; 32], Option<Vec<u8>>)>| {
            fetched.fetch_add(leaves.len(), std::sync::atomic::Ordering::SeqCst);
            async move { Ok::<_, QuilError>(leaves.iter().map(|(key, _)| blob_of(key)).collect()) }
        };
        install_phase(
            target,
            &app,
            &app,
            0,
            version,
            Vec::new(),
            Some(quil_forest::SubtreeSyncAnchor::AppRoot(root)),
            reader,
            fetch,
        )
        .await
    }

    /// A recovery whose turn is spent hands it back only inside a phase,
    /// after a chunk, with the scope marked incomplete, so the shard's data
    /// does not count as staged between turns; at the start of a phase it
    /// goes on, and a phase of one chunk completes. The next sync resumes
    /// from the installed chunks.
    #[tokio::test]
    async fn a_spent_turn_is_handed_back_inside_a_phase_with_its_scope_incomplete() {
        use quil_engine::worker_execution::{
            recovery_installed, turn_spent, with_recovery_turn, SharedWorkerExecution,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        let spent = std::time::Duration::from_secs(3600);
        let execution = SharedWorkerExecution::default();

        // A phase of one chunk, started with the turn spent by an earlier
        // phase's leaves, completes.
        let small = [0x74; 32];
        let (source, version, root) = source_of(small, 10);
        let target = memory_crdt();
        let fetched = Arc::new(AtomicUsize::new(0));
        let installed = with_recovery_turn(&execution, spent, async {
            recovery_installed(1);
            install_from(&source, &target, small, version, root, &fetched).await
        })
        .await;
        assert_eq!(installed.unwrap(), root, "a phase boundary is no hand-back");
        assert!(!target.sync_incomplete(&small, &[]).unwrap());

        // A phase of two chunks hands the turn back after its first.
        let large = [0x73; 32];
        let (source, version, root) = source_of(large, 1_100);
        let target = memory_crdt();
        let fetched = Arc::new(AtomicUsize::new(0));
        let handed_back = with_recovery_turn(&execution, spent, async {
            recovery_installed(1);
            install_from(&source, &target, large, version, root, &fetched).await
        })
        .await;
        assert!(
            handed_back.as_ref().is_err_and(turn_spent),
            "{handed_back:?}"
        );
        assert_eq!(
            fetched.load(Ordering::SeqCst),
            1_024,
            "a chunk of the phase is installed first"
        );
        assert!(
            target.sync_incomplete(&large, &[]).unwrap(),
            "the partial scope stays marked incomplete"
        );

        // The next sync plans only the rest and completes the scope.
        assert_eq!(
            install_from(&source, &target, large, version, root, &fetched)
                .await
                .unwrap(),
            root
        );
        assert_eq!(
            fetched.load(Ordering::SeqCst),
            1_100,
            "no leaf fetched twice"
        );
        assert!(!target.sync_incomplete(&large, &[]).unwrap());
    }

    fn fixture() -> (tempfile::TempDir, Arc<quil_hypergraph::HypergraphCrdt>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
        let crdt = crate::master_node::worker_manager::build_thread_worker_hypergraph(
            &db,
            Arc::new(quil_tries::ShaInclusionProver),
            false,
        );
        (dir, crdt)
    }

    /// A root-index entry naming a version whose tree does not have that root
    /// (left by a reset that cleared the tree but not the index) resolves as
    /// unavailable, so a syncing peer is told so instead of being sent to a
    /// version it cannot read (issue #672). Entries that hold still resolve.
    #[test]
    fn a_root_indexed_to_a_version_without_it_resolves_as_unavailable() {
        use quil_types::store::HypergraphStore as _;
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
        let crdt = crate::master_node::worker_manager::build_thread_worker_hypergraph(
            &db,
            Arc::new(quil_tries::ShaInclusionProver),
            false,
        );
        let app = [0xffu8; 32];
        for byte in [1u8, 2, 3] {
            crdt.add_vertex(
                &quil_hypergraph::Location {
                    app_address: app,
                    data_address: [byte; 32],
                },
                &[byte; 48],
            )
            .unwrap();
        }
        crdt.commit(9).unwrap();
        let (version, root) = crdt.serve_forest_head(&app, 0).unwrap();
        let store = quil_store::RocksHypergraphStore::new(db.inner());
        let index = |root: &[u8; 32]| {
            let txn = store.new_transaction(false).unwrap();
            store
                .put_root_version(txn.as_ref(), "vertex", "adds", &app, root, version, 77)
                .unwrap();
            txn.commit().unwrap();
        };
        let stale = [0x5a; 32];
        index(&stale);
        assert_eq!(crdt.resolve_root(&app, 0, stale), None);
        assert!(!crdt.global_root_available(&stale).unwrap());
        index(&root);
        assert_eq!(crdt.resolve_root(&app, 0, root), Some((version, 77)));
        assert!(crdt.global_root_available(&root).unwrap());
    }

    #[tokio::test]
    async fn committed_phase_resolves_history_even_when_peer_head_has_advanced() {
        let (_dir, crdt) = fixture();
        let mut peer = Peer {
            head: Some((40, vec![9; 32])),
            resolved: Some((12, 81)),
            head_calls: 0,
            resolve_calls: 0,
        };
        assert_eq!(
            resolve_phase_source(&mut peer, &crdt, &[4; 32], 0, &[7; 32])
                .await
                .unwrap(),
            Some(PhaseSource::Tree {
                version: 12,
                root: [7; 32],
                global_frame: 81
            })
        );
        assert_eq!((peer.resolve_calls, peer.head_calls), (1, 0));

        // A matching live root alone cannot fabricate the phase-0 frame cursor.
        peer.resolved = None;
        peer.head = Some((40, vec![7; 32]));
        assert_eq!(
            resolve_phase_source(&mut peer, &crdt, &[4; 32], 0, &[7; 32])
                .await
                .unwrap(),
            None
        );
        // An unchanged auxiliary root needs no separate frame cursor.
        assert_eq!(
            resolve_phase_source(&mut peer, &crdt, &[4; 32], 2, &[7; 32])
                .await
                .unwrap(),
            Some(PhaseSource::Tree {
                version: 40,
                root: [7; 32],
                global_frame: 0
            })
        );
        peer.head = Some((40, vec![9; 32]));
        assert_eq!(
            resolve_phase_source(&mut peer, &crdt, &[4; 32], 2, &[7; 32])
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn empty_or_absent_source_cannot_hide_stale_local_phase_data() {
        let (_dir, crdt) = fixture();
        let app = [5; 32];
        let mut peer = Peer {
            head: None,
            resolved: None,
            head_calls: 0,
            resolve_calls: 0,
        };
        for root in [[0; 32], EMPTY_PHASE_ROOT] {
            assert_eq!(
                resolve_phase_source(&mut peer, &crdt, &app, 0, &root)
                    .await
                    .unwrap(),
                Some(PhaseSource::Empty)
            );
        }
        assert_eq!((peer.head_calls, peer.resolve_calls), (0, 0));
        assert_eq!(
            resolve_phase_source(&mut peer, &crdt, &app, 0, &[])
                .await
                .unwrap(),
            Some(PhaseSource::Empty)
        );

        crdt.add_vertex(
            &quil_hypergraph::Location {
                app_address: app,
                data_address: [1; 32],
            },
            b"stale",
        )
        .unwrap();
        crdt.commit(1).unwrap();
        let before = crdt.current_forest_phase_root(&app, 0).unwrap();
        for root in [Vec::new(), vec![0; 32], EMPTY_PHASE_ROOT.to_vec()] {
            assert_eq!(
                resolve_phase_source(&mut peer, &crdt, &app, 0, &root)
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(crdt.current_forest_phase_root(&app, 0).unwrap(), before);
        }
    }

    /// The GLOBAL prover tree's auxiliary phases hold nothing on an archive
    /// since the prover-tree resets. A store that synced removes before them
    /// empties such a phase, unanchored or against an empty committed root,
    /// so its sync converges and the vertices it removed read again. Phase 0
    /// and application shards keep refusing stale local data.
    #[tokio::test]
    async fn absent_prover_aux_phase_empties_stale_local_data() {
        let (_dir, crdt) = fixture();
        let at = |app: [u8; 32], byte: u8| quil_hypergraph::Location {
            app_address: app,
            data_address: [byte; 32],
        };
        for app in [PROVER_SHARD, [5; 32]] {
            crdt.add_vertex(&at(app, 1), b"allocation").unwrap();
            crdt.remove_vertex(&at(app, 1)).unwrap();
        }
        crdt.commit(1).unwrap();
        let mut peer = Peer {
            head: None,
            resolved: None,
            head_calls: 0,
            resolve_calls: 0,
        };
        for (app, phase) in [([5; 32], 1), (PROVER_SHARD, 0)] {
            let before = crdt
                .current_forest_phase_root(&app, phase as usize)
                .unwrap();
            assert!(!is_empty_phase_root(&before));
            assert_eq!(
                resolve_phase_source(&mut peer, &crdt, &app, phase, &[])
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(
                crdt.current_forest_phase_root(&app, phase as usize)
                    .unwrap(),
                before
            );
        }
        assert_eq!(crdt.get_vertex_data(&at(PROVER_SHARD, 1)), None);

        assert_eq!(
            resolve_phase_source(&mut peer, &crdt, &PROVER_SHARD, 1, &[])
                .await
                .unwrap(),
            Some(PhaseSource::Empty)
        );
        assert!(is_empty_phase_root(
            &crdt.current_forest_phase_root(&PROVER_SHARD, 1).unwrap()
        ));
        assert_eq!(
            crdt.get_vertex_data(&at(PROVER_SHARD, 1)).as_deref(),
            Some(&b"allocation"[..])
        );
        assert_eq!(crdt.get_vertex_data(&at([5; 32], 1)), None);

        crdt.add_vertex(&at(PROVER_SHARD, 2), b"allocation")
            .unwrap();
        crdt.remove_vertex(&at(PROVER_SHARD, 2)).unwrap();
        crdt.commit(2).unwrap();
        assert!(!is_empty_phase_root(
            &crdt.current_forest_phase_root(&PROVER_SHARD, 1).unwrap()
        ));
        assert_eq!(
            resolve_phase_source(&mut peer, &crdt, &PROVER_SHARD, 1, &[0; 32])
                .await
                .unwrap(),
            Some(PhaseSource::Empty)
        );
        assert!(is_empty_phase_root(
            &crdt.current_forest_phase_root(&PROVER_SHARD, 1).unwrap()
        ));
        assert_eq!(
            crdt.get_vertex_data(&at(PROVER_SHARD, 2)).as_deref(),
            Some(&b"allocation"[..])
        );
    }

    #[tokio::test]
    async fn bootstrap_is_distinct_from_empty_or_malformed_commitments() {
        let (_dir, crdt) = fixture();
        let mut peer = Peer {
            head: Some((0, vec![8; 32])),
            resolved: None,
            head_calls: 0,
            resolve_calls: 0,
        };
        assert_eq!(phase_anchor(&[]).unwrap(), None);
        assert!(!is_empty_phase_root(&[]));
        assert_eq!(
            resolve_phase_source(&mut peer, &crdt, &[3; 32], 0, &[])
                .await
                .unwrap(),
            Some(PhaseSource::Tree {
                version: 0,
                root: [8; 32],
                global_frame: 0
            })
        );
        for size in [1, 16, 31, 33, 64] {
            assert!(
                resolve_phase_source(&mut peer, &crdt, &[3; 32], 0, &vec![0; size])
                    .await
                    .is_err()
            );
        }
        assert_eq!(peer.resolve_calls, 0);
        assert_eq!(peer.head_calls, 1);
        for root in [vec![], vec![0; 31]] {
            peer.head = Some((0, root));
            assert!(resolve_phase_source(&mut peer, &crdt, &[3; 32], 0, &[])
                .await
                .is_err());
        }
        let mut forged = EMPTY_PHASE_ROOT;
        forged[31] ^= 1;
        assert!(!is_empty_phase_root(&forged));
    }
}
