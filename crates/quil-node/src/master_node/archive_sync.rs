use std::sync::Arc;

use tracing::{debug, info, warn};

// Import KeyManager trait for get_signer
use quil_keys::KeyManager as _;

use quil_lifecycle::Supervisor;

/// Genesis-prover allowlist + VDF/BLS gate for an archive-sourced global
/// frame. This is the SAME check the gossip `GLOBAL_FRAME` handler runs
/// (`message_loop.rs`): the frame's `prover` must be a known genesis prover
/// AND the VDF proof + BLS signature must verify. Returns `true` to accept,
/// `false` to drop. VDF verification is panic-contained because the
/// classgroup code can panic on malformed output.
fn archive_frame_is_valid(
    frame: &quil_types::proto::global::GlobalFrame,
    genesis_prover_addrs: &std::collections::HashSet<Vec<u8>>,
    frame_validator: &quil_engine::frame_validator::GlobalFrameVerifier,
) -> bool {
    let Some(h) = frame.header.as_ref() else {
        warn!("archive frame validation: frame has no header — dropping");
        return false;
    };
    let frame_num = h.frame_number;
    // 1. Genesis-prover allowlist (frame header `prover` is the 32-byte address).
    // Common + benign on startup: the frame poller backfills over LEGACY
    // pre-migration frames whose producer isn't a genesis archive. Log at debug
    // so it isn't noisy; the gossip path (`message_loop.rs`) keeps `warn` since
    // an unsolicited non-genesis frame there is a possible attacker.
    if !genesis_prover_addrs.contains(&h.prover) {
        debug!(
            frame = frame_num,
            prover = %hex::encode(&h.prover),
            "archive frame: non-genesis prover, dropping (expected for legacy pre-migration frames)"
        );
        return false;
    }
    // 2. VDF proof + BLS signature (panic-contained like the gossip path).
    let validate_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        frame_validator.validate(frame)
    }));
    match validate_result {
        Ok(Ok(true)) => true,
        Ok(Ok(false)) => {
            warn!(frame = frame_num, "archive frame rejected by validator — dropping");
            false
        }
        Ok(Err(e)) => {
            warn!(frame = frame_num, error = %e, "archive frame VDF validation error — dropping");
            false
        }
        Err(_) => {
            warn!(frame = frame_num, "archive frame VDF validation PANIC — dropping");
            false
        }
    }
}

/// Reconstruct a `GlobalProposal` for frame `n` from the LOCAL clock store,
/// mirroring `ClockStoreFrameLookup::get_global_proposal` (grpc.rs): state +
/// parent QC (from the parent frame's cert) + prior-rank TC + proposer vote,
/// all best-effort from what's persisted. `Err` when the frame isn't present.
/// Load the frame at `n`, falling back to an uncommitted candidate — the TIP or
/// ANY intermediate frame between the committed head and the newest QC — when
/// there is no committed frame at `n`.
///
/// This is the crux of surviving a coordinated halt AND a restart during one.
/// When the committee stalls, the frames above the committed head are
/// *uncommitted candidates*: produced (into `clock_global_frame_candidate_key(n,
/// selector)`) and CERTIFIED (a QC formed) but never finalized. Jolteon holds
/// those certified states only in the in-memory forks tree — a restart loses
/// them, re-seeding the forks tree at the committed head. To rebuild the chain,
/// every uncommitted frame `[committed_head+1 .. newest_qc]` must be loadable,
/// not just the tip. Both the serve path (`get_global_proposal`) and the local
/// replay path read only the committed index, so without this a restart-during-
/// halt permanently wedges: the leader's newest-QC parent state is gone, it
/// skips forever, and no manual-free recovery exists.
///
/// `on_qc_observed` persists EVERY observed QC per-rank, so each uncommitted
/// frame's `(frame_number, selector)` is recoverable from the stored QC chain.
/// We scan ranks `[committed_head_rank+1 .. newest_qc.rank]` for the QC naming
/// frame `n` and load that candidate. The gap is tiny (a handful of ranks), so
/// the scan is cheap. The candidate is finalized normally later by the real
/// 2-chain built on top of it — never blessed as final on its own QC.
pub(crate) fn load_committed_or_tip_candidate(
    clock_store: &dyn quil_types::store::ClockStore,
    n: u64,
) -> Result<quil_types::proto::global::GlobalFrame, String> {
    use quil_types::store::ClockStore;
    if let Ok(f) = clock_store.get_global_clock_frame(n) {
        return Ok(f);
    }
    // Not committed — resolve the uncommitted candidate via the stored QC chain.
    let newest = clock_store
        .get_latest_quorum_certificate(&[])
        .map_err(|e| format!("no committed frame at {n} and no latest QC: {e}"))?;
    if n > newest.frame_number {
        return Err(format!(
            "frame {n} is above the newest QC frame {} — nothing to load",
            newest.frame_number
        ));
    }
    // Fast path: the tip candidate is named directly by the latest QC.
    if newest.frame_number == n {
        return clock_store
            .get_global_clock_frame_candidate(n, &newest.selector)
            .map_err(|e| e.to_string());
    }
    // Intermediate candidate: scan the per-rank QC chain from the committed
    // head up to the newest QC for the one certifying frame `n`.
    let committed_rank = clock_store
        .get_latest_global_clock_frame()
        .ok()
        .and_then(|f| f.header.as_ref().map(|h| h.rank))
        .unwrap_or(0);
    for rank in (committed_rank.saturating_add(1))..=newest.rank {
        if let Ok(qc) = clock_store.get_quorum_certificate(&[], rank) {
            if qc.frame_number == n {
                return clock_store
                    .get_global_clock_frame_candidate(n, &qc.selector)
                    .map_err(|e| e.to_string());
            }
        }
    }
    Err(format!(
        "no committed frame at {n} and no certified candidate found in the QC chain \
         (committed_rank={committed_rank}, newest_qc_rank={}, newest_qc_frame={})",
        newest.rank, newest.frame_number
    ))
}

pub(crate) fn reconstruct_local_proposal(
    clock_store: &dyn quil_types::store::ClockStore,
    n: u64,
) -> Result<quil_types::proto::global::GlobalProposal, String> {
    use quil_types::store::ClockStore;
    let frame = load_committed_or_tip_candidate(clock_store, n)?;
    if n == 0 {
        return Ok(quil_types::proto::global::GlobalProposal {
            state: Some(frame),
            parent_quorum_certificate: None,
            prior_rank_timeout_certificate: None,
            vote: None,
        });
    }
    let header = frame.header.as_ref().ok_or("frame missing header")?;
    let rank = header.rank;
    let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
        .map(|h| h.to_vec())
        .map_err(|e| format!("frame identity: {e}"))?;
    let vote = clock_store.get_proposal_vote(&[], rank, &selector).ok();
    let prior_rank_timeout_certificate = clock_store
        .get_timeout_certificate(&[], rank.saturating_sub(1))
        .ok();
    let parent = clock_store.get_global_clock_frame(n - 1).map_err(|e| e.to_string())?;
    let parent_rank = parent.header.as_ref().map(|h| h.rank).unwrap_or(0);
    let parent_quorum_certificate = clock_store.get_quorum_certificate(&[], parent_rank).ok();
    Ok(quil_types::proto::global::GlobalProposal {
        state: Some(frame),
        parent_quorum_certificate,
        prior_rank_timeout_certificate,
        vote,
    })
}

/// Record-only frame backfill for the restart "hole" `[lo, hi]`.
///
/// On restart the forks tree re-seeds at the latest-QC frame N and
/// finalizes *forward* from there — it never re-finalizes ranks below N.
/// If finalization had lagged the persisted canonical head H before the
/// restart, frame RECORDS `[H+1, N-1]` are absent from the clock store,
/// and the archive poller can't recover them: it forward-fills from the
/// MAX stored frame (which consensus pushes up to ~N), so the sub-max gap
/// is never scanned. This task fills exactly that gap.
///
/// "Record-only" is load-bearing: we fetch each missing frame from a peer
/// archive and write ONLY the clock-store record (`put_global_frame`). We
/// deliberately do NOT run the frame through `on_frame` /
/// `process_global_frame` — that path re-applies the frame's message
/// bundles to the execution engines, double-spending/-crediting state that
/// was already materialized before the restart. This restores the archive's
/// ability to SERVE those heights; CRDT state convergence is a separate
/// concern (handled by materialization on the consensus path / hypersync),
/// not this task.
///
/// Best-effort and bounded: a frame that no peer can serve is genuinely
/// absent (uncommitted / TC-orphaned and correctly not part of the
/// canonical chain), so after trying the known endpoints we give up on the
/// remainder and log it rather than wedging.
#[allow(clippy::too_many_arguments)]
async fn run_record_only_backfill(
    pool: Arc<quil_rpc::ArchiveEndpointPool>,
    clock_store: Arc<quil_store::RocksClockStore>,
    frame_validate: quil_rpc::frame_sync::FrameValidator,
    anchor: Option<quil_types::proto::global::GlobalFrame>,
    seed: Vec<u8>,
    lo: u64,
    hi: u64,
    cancel: tokio_util::sync::CancellationToken,
) {
    if lo > hi {
        return;
    }
    info!(lo, hi, "record-only frame-record backfill started");

    // FIRST resort — promote LOCAL candidate frames along the ancestor chain.
    // The hole [lo, hi] is exactly the ancestor chain of the re-seed frame
    // (`anchor`, frame hi+1). Every frame on that chain is an ancestor of a
    // frame the node re-seeds from and finalizes forward, so it is committed
    // and safe to write as a canonical record. Consensus persisted these as
    // candidates via `on_incorporated` (keyed by (frame_number,
    // Poseidon(output))), and each frame's `parent_selector` IS its parent's
    // candidate identity — so we can walk the chain locally with no peer.
    //
    // This is the case that peer-fetch cannot handle: when archives restart
    // together they share the same record hole, so NO peer can serve it — but
    // each one holds the missing frames locally as candidates. Walk first, then
    // fall back to peers only for whatever isn't present locally.
    if let Some(mut cur) = anchor {
        let mut promoted_local = 0u64;
        while !cancel.is_cancelled() {
            let Some(h) = cur.header.as_ref() else { break };
            let fnum = h.frame_number;
            // Stop once we reach the bottom of the hole; `lo-1` (== canonical
            // head) is already present, so there is nothing below to promote.
            if fnum == 0 || fnum <= lo {
                break;
            }
            let parent_num = fnum - 1;
            let parent_sel = h.parent_selector.clone();
            if parent_sel.is_empty() {
                break;
            }
            // Candidate keyed by (frame_number, identity == Poseidon(output));
            // `parent_selector` is exactly that identity for the parent. Falls
            // back to the canonical record if the candidate key is absent.
            let parent = match quil_types::store::ClockStore::get_global_clock_frame_candidate(
                clock_store.as_ref(),
                parent_num,
                &parent_sel,
            ) {
                Ok(f) => f,
                // Chain broken locally (neither candidate nor record present);
                // we can't derive deeper parents without it — let the peer loop
                // below recover the remaining heights.
                Err(_) => break,
            };
            if parent_num >= lo
                && parent_num <= hi
                && clock_store.get_global_frame(parent_num).is_err()
            {
                if !frame_validate(&parent) {
                    warn!(
                        frame = parent_num,
                        "record-only backfill: local candidate failed validation — skipping",
                    );
                } else if let Err(e) = clock_store.put_global_frame(&parent, None) {
                    warn!(
                        error = %e,
                        frame = parent_num,
                        "record-only backfill: local candidate promote store failed",
                    );
                } else {
                    promoted_local += 1;
                }
            }
            cur = parent;
        }
        if promoted_local > 0 {
            info!(
                promoted_local,
                lo, hi, "record-only backfill: promoted local candidate frames (ancestor chain)",
            );
        }
    }
    // Which heights are actually missing? (Consensus may have already
    // persisted some of the range forward.) Uses the inherent
    // `get_global_frame` point lookup on the concrete clock store.
    let mut remaining: Vec<u64> = (lo..=hi)
        .filter(|&n| clock_store.get_global_frame(n).is_err())
        .collect();
    if remaining.is_empty() {
        info!(lo, hi, "record-only backfill: no holes, nothing to do");
        return;
    }
    let initial = remaining.len();
    info!(holes = initial, lo, hi, "record-only backfill: filling missing frame records");

    let endpoints = pool.get_all().await;
    if endpoints.is_empty() {
        warn!(holes = initial, "record-only backfill: no archive endpoints known yet — skipping");
        return;
    }
    // One pass per known endpoint, plus a little slack; we rotate through
    // `endpoints` so each round prefers a different archive.
    let max_rounds = endpoints.len() + 2;
    let mut filled = 0u64;
    for round in 0..max_rounds {
        if remaining.is_empty() || cancel.is_cancelled() {
            break;
        }
        let addr = endpoints[round % endpoints.len()].clone();
        let mut client = match quil_rpc::ArchiveClient::connect_mtls(&addr, &seed).await {
            Ok(c) => c,
            Err(e) => {
                debug!(%addr, error = %e, "record-only backfill: connect failed, rotating");
                continue;
            }
        };
        let mut still: Vec<u64> = Vec::new();
        for n in std::mem::take(&mut remaining) {
            if cancel.is_cancelled() {
                still.push(n);
                continue;
            }
            match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                client.get_global_frame(n),
            )
            .await
            {
                Ok(Ok(frame)) => {
                    // Gate BEFORE persist — genesis-prover allowlist + VDF/BLS,
                    // the SAME check the gossip GLOBAL_FRAME handler runs. A
                    // frame failing validation is a forged/corrupt record; skip
                    // it (never store). Execution side effects are already
                    // skipped by design (record-only). Re-queue so another
                    // endpoint may still serve the honest record for `n`.
                    if !frame_validate(&frame) {
                        warn!(%addr, frame = n, "record-only backfill: frame failed validation — skipping");
                        still.push(n);
                        continue;
                    }
                    // RECORD-ONLY: store the clock-store record, never the
                    // execution side effects.
                    if let Err(e) = clock_store.put_global_frame(&frame, None) {
                        warn!(error = %e, frame = n, "record-only backfill: store failed");
                        still.push(n);
                    } else {
                        filled += 1;
                    }
                }
                Ok(Err(e)) => {
                    // This endpoint lacks it; retry on another next round.
                    debug!(%addr, frame = n, error = %e, "record-only backfill: frame unavailable");
                    still.push(n);
                }
                Err(_) => {
                    debug!(%addr, frame = n, "record-only backfill: fetch timeout");
                    still.push(n);
                }
            }
        }
        remaining = still;
    }
    if remaining.is_empty() {
        info!(filled, attempted = initial, "record-only frame-record backfill complete");
    } else {
        warn!(
            filled,
            attempted = initial,
            unrecoverable = remaining.len(),
            "record-only backfill finished with frames no peer could serve — \
             these heights are likely uncommitted/orphaned (correctly not canonical)"
        );
    }
}

/// Scan the ENTIRE persisted frame-record range for internal gaps left by
/// prior restarts and backfill each one. The reseed-anchored backfill
/// (`run_record_only_backfill` called from bootstrap) only covers the single
/// open range ABOVE the head (`[canonical_head+1, reseed-1]`); it does not see
/// the many small 2-3 frame holes scattered BELOW the head that accumulate
/// across repeated restart rounds. This driver finds every such hole (a cheap
/// key-only keyspace scan) and reuses `run_record_only_backfill` per hole —
/// which promotes the locally-stashed candidate frames FIRST (the common case:
/// the frames are present as candidates on this very node) and only falls back
/// to peers for anything genuinely absent locally.
async fn run_all_gap_backfill(
    pool: Arc<quil_rpc::ArchiveEndpointPool>,
    clock_store: Arc<quil_store::RocksClockStore>,
    frame_validate: quil_rpc::frame_sync::FrameValidator,
    seed: Vec<u8>,
    cancel: tokio_util::sync::CancellationToken,
) {
    // The gap scan walks the whole frame keyspace (key-only, no decode) — run
    // it on a blocking thread so it never stalls the async runtime.
    let scan_cs = clock_store.clone();
    let gaps = match tokio::task::spawn_blocking(move || {
        scan_cs.find_global_frame_record_gaps()
    })
    .await
    {
        Ok(g) => g,
        Err(e) => {
            warn!(error = %e, "restart gap scan: scan task failed");
            return;
        }
    };
    if gaps.is_empty() {
        info!("restart gap scan: no internal frame-record gaps");
        return;
    }
    let total: u64 = gaps.iter().map(|(lo, hi)| hi - lo + 1).sum();
    info!(
        gap_count = gaps.len(),
        missing_frames = total,
        "restart gap scan: found internal frame-record holes — backfilling \
         (local candidates first, peers as fallback)",
    );
    for (lo, hi) in gaps {
        if cancel.is_cancelled() {
            break;
        }
        // Anchor at the present record immediately above the hole; its
        // `parent_selector` chain walks down through [lo, hi]. The record at
        // hi+1 is guaranteed present (gaps are strictly BETWEEN stored frames).
        let anchor = clock_store.get_global_frame(hi + 1).ok();
        run_record_only_backfill(
            pool.clone(),
            clock_store.clone(),
            frame_validate.clone(),
            anchor,
            seed.clone(),
            lo,
            hi,
            cancel.clone(),
        )
        .await;
    }
    info!("restart gap scan: backfill pass complete");
}

/// The state-jump is a blind-trust recovery for archives stranded far below the
/// network head: it syncs a peer's full state snapshot wholesale (no per-frame
/// verification). It is confined to the migration-recovery window BELOW this
/// frame — a node at/past it must catch up only via the verified poller/
/// consensus, never by trusting a peer's current-era state. (Network is at
/// ~671.7k; the whole mechanism self-disables at this boundary.)
const STATE_JUMP_MAX_FRAME: u64 = 672_000;
/// Only state-jump when replaying the gap would be impractical; below this the
/// frame poller catches up fine and a blind full-state sync isn't warranted.
const STATE_JUMP_MIN_GAP: u64 = 1_000;

/// Full-state "state jump" for a far-behind archive (below
/// [`STATE_JUMP_MAX_FRAME`]): hypersync the prover tree + EVERY app-shard tree
/// (all four phases) to a peer's snapshot at frame N — every pull pinned to N's
/// snapshot generation so the captured state is cross-tree CONSISTENT — then
/// store the frame-N record (advancing the clock head) and advance the durable
/// materialized cursor to N, so the poller/materializer resume near head
/// instead of replaying (and re-materializing) tens of thousands of frames.
///
/// Consistency is why all pulls pin to ONE generation (prover tree →
/// `prover_tree_commitment`, shards → `state_roots[0]`, both from frame N): the
/// serving archive retains ≥128 generations ([`SNAPSHOT_MAX_GENERATIONS`]) so N
/// survives the sequential multi-minute jump; a mid-jump eviction (`failed to
/// acquire snapshot`) aborts this peer and retries a fresh N on the next.
///
/// Returns the synced frame on success. Best-effort: on any failure it returns
/// `None` and the node falls back to the normal poller.
async fn run_state_jump(
    pool: Arc<quil_rpc::ArchiveEndpointPool>,
    seed: Vec<u8>,
    clock_store: Arc<quil_store::RocksClockStore>,
    hg_store: Arc<quil_store::RocksHypergraphStore>,
    shards_store: Arc<dyn quil_types::store::ShardsStore>,
    frame_validate: quil_rpc::frame_sync::FrameValidator,
    prover_registry: Arc<quil_execution::SharedProverRegistry>,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    // Archives pull EVERY app-shard so they can serve full state. A regular
    // (non-archive) passes `false`: it pulls only the global prover tree +
    // advances the cursor — enough to STOP replaying ancient pre-migration
    // history — and syncs its own assigned shards via the worker path.
    sync_all_shards: bool,
    cancel: tokio_util::sync::CancellationToken,
) -> Option<u64> {
    let local_head = clock_store.get_latest_frame_number().unwrap_or(0);
    if local_head >= STATE_JUMP_MAX_FRAME {
        return None; // recovery window closed — never blind-trust current-era state
    }
    let endpoints = pool.get_all().await;
    if endpoints.is_empty() {
        return None;
    }
    for addr in endpoints {
        if cancel.is_cancelled() {
            return None;
        }
        let mut client = match quil_rpc::ArchiveClient::connect_mtls(&addr, &seed).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        let head = match client.get_global_frame(0).await {
            Ok(f) => f,
            Err(_) => continue,
        };
        let hdr = match head.header.as_ref() {
            Some(h) => h.clone(),
            None => continue,
        };
        let target = hdr.frame_number;
        // Gate: strictly below the cap, and far enough behind to justify a jump.
        if target == 0 || target >= STATE_JUMP_MAX_FRAME {
            continue;
        }
        if target <= local_head.saturating_add(STATE_JUMP_MIN_GAP) {
            return None; // small gap — the poller handles it; don't blind-trust
        }
        if !frame_validate(&head) {
            warn!(%addr, target, "state-jump: peer head failed validation — trying another peer");
            continue;
        }
        // Single generation anchor for ALL pulls. `GlobalFrameHeader` commits
        // the whole generation via `prover_tree_commitment`; the hypersync
        // server's snapshot registry retains "(global + active app shards) per
        // generation", so passing this one root as `expected_root` selects
        // generation N and serves every tree (prover + each app-shard) from it
        // → cross-tree consistent. (App-shard `state_roots` live on the
        // app-shard `FrameHeader`, not here — the global header does not carry
        // per-shard roots, so the generation anchor is the pin we use.)
        let anchor = hdr.prover_tree_commitment.clone();
        if anchor.is_empty() {
            warn!(%addr, target, "state-jump: peer head has no prover_tree_commitment anchor — skipping");
            continue;
        }
        let prover_root = anchor.clone();
        info!(%addr, local_head, target, "state-jump: syncing FULL state pinned to frame N");

        // Onboarding: a fresh node boots on the ephemeral in-memory forest, so
        // `sync_shard_phase_from` below would write into memory (never persisted)
        // and the node would produce with the wrong (un-QUIL-split) root. Swap in
        // the persistent RocksDB forest + declare the QUIL partition BEFORE the
        // pulls so synced + produced state lands on disk consistently. No-op once
        // persistent (migrated node / prior jump).
        if quil_forest_migrate::install_forest_for_sync(crdt.as_ref(), hg_store.as_ref()) {
            info!("state-jump: installed persistent forest for onboarding sync");
        }

        // Prover tree — the global prover shard is a single-shard forest app
        // (L2 = [0xff; 32]). Pull it (all phases) from the peer via the efficient
        // Merkle diff. (`prover_root` / `anchor` are the peer's generation pin;
        // the diff authenticates against the peer's own tree root.)
        let _ = &prover_root;
        if let Err(e) =
            crate::forest_sync::pull_shard_from_peer(&addr, &seed, crdt.clone(), &[0xffu8; 32]).await
        {
            warn!(%addr, error = %e, "state-jump: prover tree sync failed — trying another peer");
            continue;
        }

        // Every app-shard forest tree. `range_app_shards` yields one `ShardInfo`
        // per sub-shard (a QUIL app has 64, each with its own `prefix`), which
        // maps directly to the forest sub-shard id `addr_path_shard_id(l2,
        // prefix)`. Dedup by that id (QUIL sub-shards share an l1‖l2 shard_key
        // but differ in prefix, so we must NOT dedup on shard_key).
        let _ = &anchor;
        // Regulars skip the ALL-shards pull (see `sync_all_shards`): prover tree
        // + cursor advance is enough to stop them replaying ancient history.
        let mut shard_count = 0usize;
        if sync_all_shards {
            let shard_rows = shards_store.range_app_shards().unwrap_or_default();
            let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
            let mut aborted = false;
            for row in &shard_rows {
                if cancel.is_cancelled() {
                    return None;
                }
                if row.shard_key.len() < 35 {
                    continue;
                }
                let mut l2 = [0u8; 32];
                l2.copy_from_slice(&row.shard_key[3..35]);
                let shard_id = quil_forest::Forest::addr_path_shard_id(&l2, &row.prefix);
                if !seen.insert(shard_id.clone()) {
                    continue;
                }
                if let Err(e) =
                    crate::forest_sync::pull_shard_from_peer(&addr, &seed, crdt.clone(), &shard_id).await
                {
                    // A vertex-adds (anchor) failure means we didn't reach the peer's
                    // generation for this shard — abort and retry a fresh N on another
                    // peer (a partial jump must NOT be committed).
                    warn!(
                        %addr, error = %e,
                        "state-jump: shard sync failed — aborting, retrying another peer",
                    );
                    aborted = true;
                    break;
                }
                shard_count += 1;
            }
            if aborted {
                continue;
            }
        }

        // Commit the jump: store the head frame record (clock head → target),
        // then advance the durable materialized cursor so the startup
        // re-materialize does NOT replay/re-apply [local_head+1..=target].
        if let Err(e) = clock_store.put_global_frame(&head, None) {
            warn!(error = %e, target, "state-jump: store head frame failed — aborting");
            return None;
        }
        if let Err(e) = clock_store.put_global_materialized_cursor(target) {
            warn!(error = %e, "state-jump: cursor advance failed");
        }
        // Refresh the prover registry from the freshly-synced prover tree.
        let pr = prover_registry.clone();
        let hs = hg_store.clone();
        let _ = tokio::task::spawn_blocking(move || pr.refresh_from_store(&hs)).await;
        info!(
            target,
            shards = shard_count,
            "state-jump complete — resuming near head (poller/consensus take over)"
        );
        return Some(target);
    }
    None
}

pub(crate) struct ArchiveSyncArgs {
    pub mtls_seed: Option<[u8; 57]>,
    pub network: u8,
    pub archive_mode: bool,
    pub archive_pool: Arc<quil_rpc::ArchiveEndpointPool>,
    pub clock_store: Arc<quil_store::RocksClockStore>,
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub shards_store: Arc<dyn quil_types::store::ShardsStore>,
    pub exec_manager: Arc<quil_execution::ExecutionEngineManager>,
    pub worker_allocator: Arc<quil_engine::worker_allocator::WorkerAllocator>,
    pub prover_lifecycle: Arc<quil_engine::provers::lifecycle::ProverLifecycle>,
    pub prover_registry: Arc<quil_execution::SharedProverRegistry>,
    pub worker_manager: Arc<dyn quil_engine::worker::WorkerManager>,
    pub coverage_monitor: Arc<quil_engine::coverage::CoverageMonitor>,
    pub current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
    pub last_global_head_frame: Arc<std::sync::atomic::AtomicU64>,
    pub prover_pipeline: Arc<quil_engine::prover_pipeline::ProverPipeline>,
    pub file_key_manager: Arc<quil_keys::FileKeyManager>,
    pub frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    pub message_collector: Arc<quil_engine::message_collector::MessageCollector>,
    pub bls_pubkey: Vec<u8>,
    pub prover_address: [u8; 32],
    /// Genesis prover addresses (Poseidon(BLS pubkey)) — the allowlist the
    /// gossip GLOBAL_FRAME handler checks. Used to gate every archive-sourced
    /// frame BEFORE it is persisted, mirroring that path.
    pub genesis_prover_addrs: std::collections::HashSet<Vec<u8>>,
    pub frame_materializer: Option<Arc<quil_engine::frame_materializer::FrameMaterializer>>,
    pub consensus_loopback_tx: tokio::sync::mpsc::Sender<quil_p2p::node::ReceivedMessage>,
    pub peer_id: quil_p2p::PeerId,
    pub spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
    /// commonware-simplex committee (`q-consensus-key` pubkeys, hex). Empty ⇒
    /// legacy quil-consensus path; non-empty ⇒ simplex + Falcon global consensus.
    pub consensus_committee: Vec<String>,
    /// Parallel to `consensus_committee`: each member's libp2p peer id (base58),
    /// so inbound `:8340` messages resolve to the sender's committee key.
    pub consensus_committee_peer_ids: Vec<String>,
    /// simplex leader timeout (seconds); 0 = engine default (30s).
    pub consensus_leader_timeout_secs: u64,
    /// Shared cell the simplex inbound router is published into once activated;
    /// the receive loop routes CW-channel `:8340` messages through it.
    pub cw_router:
        Arc<std::sync::OnceLock<Arc<crate::cw_consensus_bridge::CwInboundRouter>>>,
    /// Persistent directory for the simplex consensus journal (a stable subdir
    /// of the node's data dir). Without a fixed path the CW runtime defaults to
    /// a random temp dir and every restart replays consensus from the migration
    /// head instead of resuming.
    pub cw_storage_dir: std::path::PathBuf,
}

pub(crate) fn spawn_all(sup: &mut Supervisor<anyhow::Error>, args: ArchiveSyncArgs) {
    let ArchiveSyncArgs {
        mtls_seed,
        network,
        archive_mode,
        archive_pool,
        clock_store,
        hg_store,
        crdt,
        shards_store,
        exec_manager,
        worker_allocator,
        prover_lifecycle,
        prover_registry,
        worker_manager,
        coverage_monitor,
        current_frame,
        last_global_head_frame,
        prover_pipeline,
        file_key_manager,
        frame_prover,
        message_collector,
        bls_pubkey,
        prover_address,
        genesis_prover_addrs,
        frame_materializer,
        consensus_loopback_tx,
        peer_id,
        spawner,
        consensus_committee,
        consensus_committee_peer_ids,
        consensus_leader_timeout_secs,
        cw_router,
        cw_storage_dir,
    } = args;

    // The archive-sync transport identity is the FALCON network key (all
    // outbound :8340 dials below use it). `mtls_seed` (Ed448) presence still
    // gates whether we have any transport identity at all.
    let mtls_falcon: Option<Vec<u8>> = if mtls_seed.is_some() {
        use quil_keys::KeyManager as _;
        file_key_manager
            .get_private_key(quil_types::crypto::KeyType::Falcon512)
            .ok()
    } else {
        None
    };
    if let Some(seed) = mtls_falcon {
        // `consensus_finalized` tracks the engine's finalized frame (updated by
        // the finalized hook — distinct from the poller-written store head).
        // Seeded from the persisted finalized head; consumed by the incremental
        // hypersync task below. Only canonical (2-chain finalized) frames are
        // persisted via `get_latest_global_frame`, so this is the correct
        // finalized watermark.
        let consensus_finalized = Arc::new(std::sync::atomic::AtomicU64::new(
            clock_store
                .get_latest_global_frame()
                .ok()
                .and_then(|f| f.header.map(|h| h.frame_number))
                .unwrap_or(0),
        ));
        // Shared frame verifier (VDF + BLS) — the SAME check the gossip
        // GLOBAL_FRAME / GLOBAL_CONSENSUS handlers run. Built from the frame
        // prover already in scope + a fresh BLS constructor (mirrors
        // `frame_pipeline::init`). Used to gate every archive-sourced frame
        // and proposal BEFORE it is persisted / submitted into consensus.
        let frame_verifier: Arc<quil_engine::frame_validator::GlobalFrameVerifier> =
            Arc::new(quil_engine::frame_validator::GlobalFrameVerifier::with_bls(
                frame_prover.clone(),
                Arc::new(quil_crypto::FalconKeyConstructor)
                    as Arc<dyn quil_types::crypto::BlsConstructor>,
            ));
        // Genesis-prover-allowlist + VDF/BLS gate packaged as a closure so the
        // (quil-rpc) poller and the record-only backfill can apply the exact
        // same drop-before-store check the gossip GLOBAL_FRAME handler applies.
        let frame_validate: quil_rpc::frame_sync::FrameValidator = {
            let addrs = genesis_prover_addrs.clone();
            let verifier = frame_verifier.clone();
            Arc::new(move |frame: &quil_types::proto::global::GlobalFrame| {
                archive_frame_is_valid(frame, &addrs, &verifier)
            })
        };

        // Far-behind recovery: spawn a one-shot state jump pinned to a single
        // peer frame N. It fires for ANY node stranded far below the
        // migration-recovery boundary (`STATE_JUMP_MAX_FRAME`) — NOT just
        // archives — so a regular that has been offline since the flag day
        // doesn't try to replay ancient (pre-migration, now-invalid) history
        // from the poller. For a healthy or only-slightly-behind node the jump
        // returns immediately (gate check) and is a no-op.
        //
        // `sync_all_shards = archive_mode`: archives pull the prover tree AND
        // every app-shard (they must serve full state); a regular pulls only
        // the prover tree + advances the cursor, and syncs its own assigned
        // shards via the worker path. The poller waits on
        // `poller_startup_barrier` before reading its cursor, so it always sees
        // the POST-jump head and never replays (re-materializes) below the
        // synced frame. The barrier lifts whether the jump did work or no-op'd.
        let poller_startup_barrier: Option<tokio::sync::oneshot::Receiver<()>> = {
            let (sj_tx, sj_rx) = tokio::sync::oneshot::channel::<()>();
            let sj_pool = archive_pool.clone();
            let sj_cs = clock_store.clone();
            let sj_hg = hg_store.clone();
            let sj_ss: Arc<dyn quil_types::store::ShardsStore> =
                shards_store.clone() as Arc<dyn quil_types::store::ShardsStore>;
            let sj_fv = frame_validate.clone();
            let sj_pr = prover_registry.clone();
            let sj_crdt = crdt.clone();
            let sj_all_shards = archive_mode;
            // DETACH (fire-and-forget) — NOT `sup.spawn`. The state-jump is a
            // one-shot task that RETURNS when done (jump complete or no-op); a
            // supervised task that exits is treated as a fatal
            // "exited unexpectedly" and shuts the node down. Detached tasks may
            // complete freely.
            spawner.detach("state-jump", {
                let seed = seed.clone();
                async move {
                if let Some(n) = run_state_jump(
                    sj_pool,
                    seed.clone(),
                    sj_cs,
                    sj_hg,
                    sj_ss,
                    sj_fv,
                    sj_pr,
                    sj_crdt,
                    sj_all_shards,
                    tokio_util::sync::CancellationToken::new(),
                )
                .await
                {
                    info!(target = n, "state-jump: fast-forwarded to peer head");
                }
                // Lift the barrier regardless of outcome so the poller proceeds.
                let _ = sj_tx.send(());
                Ok(())
                }
            });
            Some(sj_rx)
        };

        let exec_mgr_for_poller = exec_manager.clone();
        let wa_for_poller = worker_allocator.clone();
        let pl_for_poller = prover_lifecycle.clone();
        let pr_for_poller = prover_registry.clone();
        let wm_for_poller = worker_manager.clone();
        let cov_for_poller = coverage_monitor.clone();
        let cf_for_poller = current_frame.clone();
        let lhf_for_poller = last_global_head_frame.clone();
        let pp_for_poller = prover_pipeline.clone();
        let hg_for_poller = hg_store.clone();
        let crdt_for_poller = crdt.clone();
        let shards_store_for_poller: Arc<dyn quil_types::store::ShardsStore> =
            shards_store.clone() as Arc<dyn quil_types::store::ShardsStore>;
        let archive_mode_poller = archive_mode;
        let poller_config = quil_rpc::ArchivePollerConfig {
            on_frame: Some(Arc::new(move |frame: &quil_types::proto::global::GlobalFrame| {
                let frame_num = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
                let frame_difficulty = frame.header.as_ref().map(|h| h.difficulty).unwrap_or(0);
                // Skip bogus frames (no header or frame_number=0):
                // `current_frame.observe(0)` is a no-op, and the
                // lifecycle's evaluate guards against 0 anyway.
                if frame_num == 0 {
                    tracing::debug!(
                        "archive poller: dropping frame with frame_number=0"
                    );
                    return;
                }
                cf_for_poller.observe(frame_num);
                lhf_for_poller.fetch_max(frame_num, std::sync::atomic::Ordering::Relaxed);

                // Process frame messages through execution pipeline
                match quil_engine::frame_processor::process_global_frame(
                    &exec_mgr_for_poller,
                    frame,
                    &num_bigint::BigInt::from(1),
                ) {
                    Ok((applied, skipped)) => {
                        if applied > 0 || skipped > 0 {
                            info!(
                                frame = frame_num,
                                applied,
                                skipped,
                                "processed frame messages"
                            );
                        }
                        // After per-bundle materialize calls flushed
                        // their changesets to the in-memory CRDT (via
                        // each engine's `state.commit`), persist the
                        // resulting phase trees to the on-disk
                        // hypergraph store. Without this commit, the
                        // store still serves the previous frame's
                        // trees and the registry refresh below sees
                        // no new ProverJoin/Confirm/Leave writes.
                        if applied > 0 {
                            if let Err(e) = exec_mgr_for_poller.commit_frame(frame_num) {
                                warn!(error = %e, frame = frame_num, "hypergraph commit failed");
                            }
                            pr_for_poller.refresh_from_store(&hg_for_poller);
                            // Keep the CRDT's per-app shard sets in sync with the
                            // shards store so a split applied this frame (at an
                            // epoch boundary) is reflected in the NEXT frame's app
                            // root — deterministically on every node. Cheap: reuses
                            // the store the poller already reads.
                            super::engines::refresh_crdt_shard_prefixes(
                                crdt_for_poller.as_ref(),
                                shards_store_for_poller.as_ref(),
                            );
                        }
                    }
                    Err(e) => {
                        warn!(frame = frame_num, error = %e, "frame processing failed");
                    }
                }

                // Trigger worker allocation reconciliation. Skip in
                // archive mode — archives don't run app-shard workers,
                // so the reconciler has nothing to do and calling it
                // would resurface the no-workers-spawned-yet pathways
                // that produced phantom worker allocations on prior
                // versions.
                cov_for_poller.check(frame_num);
                if !archive_mode_poller {
                    if let Err(e) = wa_for_poller.on_new_frame(frame_num) {
                        tracing::warn!(error = %e, "worker allocation failed");
                    }
                }

                // Advance the lifecycle's "verified frame" marker. The
                // initial prover-tree sync already proved our root
                // matches the network (`commitments_match==true` —
                // see the spawn at the bottom of `main.rs`). From
                // that point on, every successfully-processed frame
                // either applies new prover messages (and our tree
                // moves with it) or is a no-op for prover state.
                // Either way we stay in sync; drift is caught by the
                // 5-minute periodic incremental sync.
                //
                // The earlier strict per-frame commitment check
                // required `crdt.commit(frame_num)` to have run AND
                // matched the frame's `prover_tree_commitment`, which
                // only happened on the rare frames where we applied
                // prover messages — leaving the lifecycle gate held
                // perpetually for non-archive nodes.
                pl_for_poller.set_prover_root_verified_frame(frame_num);

                // Refresh the lifecycle's per-filter byte-size map
                // before evaluating. Without this the proposer falls
                // back to `summary.total_size` which is a prover-
                // count proxy (sum of status_counts), not bytes —
                // joins fire on shards with no actual data, and
                // halt-risk priority can't tell apart "0 bytes
                // because empty" from "real bytes." We walk the
                // local hypergraph the same way the
                // GetShardInfo RPC does (`local_app_shard_get_sizes`).
                {
                    use std::collections::HashMap;
                    let get_sizes = quil_engine::shard_info::local_app_shard_get_sizes(
                        crdt_for_poller.clone(),
                        shards_store_for_poller.clone(),
                    );
                    let mut sizes_by_filter: HashMap<Vec<u8>, u64> = HashMap::new();
                    if let Ok(shards) = shards_store_for_poller.range_app_shards() {
                        // Dedupe to one entry per parent shard_key
                        // (range_app_shards returns one row per
                        // sub-shard).
                        let mut seen: std::collections::HashSet<Vec<u8>> =
                            std::collections::HashSet::new();
                        for s in shards {
                            if !seen.insert(s.shard_key.clone()) {
                                continue;
                            }
                            if let Ok(sub_sizes) = get_sizes(&s.shard_key, &s) {
                                for entry in sub_sizes {
                                    // `entry.size` is a big-endian
                                    // byte representation of the
                                    // shard's byte count. Saturate
                                    // at u64::MAX for absurdly large
                                    // shards rather than wrap.
                                    let mut bytes: u64 = 0;
                                    for &b in entry.size.iter() {
                                        bytes = bytes
                                            .saturating_mul(256)
                                            .saturating_add(b as u64);
                                    }
                                    if bytes == 0 {
                                        continue;
                                    }
                                    // Reconstruct the `bp` filter the
                                    // proposer keys on: L2[32] +
                                    // prefix bytes.
                                    let l2 = if s.shard_key.len() >= 35 {
                                        &s.shard_key[3..35]
                                    } else if s.shard_key.len() > 3 {
                                        &s.shard_key[3..]
                                    } else {
                                        &s.shard_key[..]
                                    };
                                    let mut bp = l2.to_vec();
                                    for &p in &entry.prefix {
                                        bp.push(p as u8);
                                    }
                                    sizes_by_filter.insert(bp, bytes);
                                }
                            }
                        }
                    }
                    pl_for_poller.set_local_shard_sizes(sizes_by_filter);
                }

                // Skip lifecycle evaluation on archives — they don't
                // propose joins/leaves, don't dispatch through the
                // prover pipeline, and the evaluate() output would
                // be ignored anyway since there are no workers to
                // bind allocations to.
                if !archive_mode_poller {
                    match pl_for_poller.evaluate(
                        frame_num,
                        frame_difficulty as u64,
                        pr_for_poller.as_ref() as &dyn quil_types::consensus::ProverRegistry,
                        wm_for_poller.as_ref(),
                    ) {
                        Ok(actions) => {
                            for action in actions {
                                tracing::info!(frame = frame_num, ?action, "prover lifecycle action");
                                pp_for_poller.dispatch(action);
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "prover lifecycle evaluation skipped");
                        }
                    }
                }
            })),
            frame_validator: Some(frame_validate.clone()),
            // Forward-fill EVERY global frame (not just the head), on regulars too
            // — NOT only archives. A regular runs app-shard workers whose storage
            // attestation anchors ρ_N to a recent global frame (`latest − K`) and
            // requires that exact frame to be present in the local clock store; a
            // peer validator likewise needs the proposer's anchored frame. With
            // head-jumping (the old `archive_mode`-gated behavior) the regular's
            // store had HOLES, so anchors landed in gaps → "anchored global frame
            // unavailable for ρ_N" → the multi-member app shard never finalized.
            // The state-jump barrier still bounds the initial backfill.
            forward_fill: true,
            startup_barrier: poller_startup_barrier,
            ..Default::default()
        };
        {
            let pool = archive_pool.clone();
            let cs = clock_store.clone();
            sup.run_until_cancelled("archive-poller", {
                let seed = seed.clone();
                move |cancel| async move {
                    quil_rpc::run_archive_poller(pool, cs, seed, poller_config, cancel).await;
                    Ok(())
                }
            });
        }
        info!("archive frame poller spawned (with execution pipeline)");

        // Periodic incremental HyperSync — refreshes prover registry every ~5 minutes.
        // After initial full sync, subsequent syncs use commitment comparison
        // and only fetch changed branches (seconds instead of 9 minutes).
        {
            let sync_pool = archive_pool.clone();
            let sync_hg = hg_store.clone();
            let sync_pr = prover_registry.clone();
            let sync_pl = prover_lifecycle.clone();
            let sync_km = file_key_manager.clone();
            let sync_cs = clock_store.clone();
            let sync_fp = frame_prover.clone();
            let (anchor_frame, anchor_time, anchor_diff) = if network == 0 {
                (244_200u64, 1_762_862_400_000i64, 80_000u32)
            } else {
                (0, 1_762_862_400_000, 80_000)
            };
            let sync_da = Arc::new(quil_engine::AsertDifficultyAdjuster::new(
                anchor_frame, anchor_time, anchor_diff,
            ));
            let sync_mc = message_collector.clone();
            let sync_em = exec_manager.clone();
            let sync_bls_pub = bls_pubkey.clone();
            let sync_pa = prover_address;
            let sync_crdt = crdt.clone();
            let sync_shards_store = shards_store.clone();
            let sync_cov = coverage_monitor.clone();
            let sync_cf = current_frame.clone();
            let sync_lhf = last_global_head_frame.clone();
            let sync_consensus_finalized = consensus_finalized.clone();
            let sync_archive_mode = archive_mode;
            // Committee endpoints for the direct global-consensus publisher.
            let sync_archive_pool = archive_pool.clone();
            // Frame gate for the record-only backfill spawned inside this task.
            let sync_frame_validate = frame_validate.clone();
            // commonware-simplex committee + inbound router (moved into the task).
            let sync_consensus_committee = consensus_committee.clone();
            let sync_consensus_committee_peer_ids = consensus_committee_peer_ids.clone();
            let sync_consensus_leader_timeout_secs = consensus_leader_timeout_secs;
            let sync_cw_router = cw_router.clone();
            let sync_cw_storage_dir = cw_storage_dir.clone();
            let seed = std::sync::Arc::new(seed.clone());
            sup.spawn("archive-prover-tree-sync", move |sync_token| async move {
                // Archive nodes ARE the source of truth — they don't wait
                // for some other archive to be discovered before activating
                // consensus. Without this bypass, a fresh testnet bootstrap
                // (every node `--archive` and starting from genesis at
                // frame 0) deadlocks: each node waits for an archive to
                // appear in the pool, but the pool only fills when peers
                // exchange PeerInfo with `archive_mode=true`, and PeerInfo
                // exchange happens after consensus is up. Skip the wait +
                // remote-sync entirely; the local store already holds
                // genesis from `establish_testnet_genesis_provers`.
                if !sync_archive_mode {
                    // Wait for initial archive discovery before starting
                    loop {
                        if sync_token.is_cancelled() { return Ok(()); }
                        if sync_pool.len().await > 0 { break; }
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }

                // Initial full sync — skipped when we're an archive
                // since the local genesis path already populated the
                // hypergraph store with the prover tree.
                let mut initial_sync_data_ok = sync_archive_mode;
                if !sync_archive_mode {
                    if let Some(addr) = sync_pool.get_all().await.first() {
                        info!("starting initial prover tree sync");
                        // Initial bootstrap sync — no verified frame
                        // yet to pin against. Empty expected_root
                        // means "trust the archive's latest snapshot".
                        // Subsequent periodic syncs DO pin against the
                        // most-recent verified frame's
                        // prover_tree_commitment.
                        // Forest sync of the global prover shard (single-shard,
                        // L2 = [0xff; 32]). Empty expected root ⇒ trust the
                        // archive's latest snapshot (bootstrap; no verified frame
                        // yet). Pulls the commitment diff + the changed vertices'
                        // blobs.
                        match crate::forest_sync::sync_single_shard_verified(
                            addr, &seed[..], sync_crdt.clone(), &[0xffu8; 32], &[],
                        ).await {
                            Ok(_) => {
                                initial_sync_data_ok = true;
                            }
                            Err(e) => {
                                warn!(error = %e, "initial prover tree sync failed; lifecycle gate stays held");
                            }
                        }
                    // Refresh prover registry from synced data
                    let pr = sync_pr.clone();
                    let hs2 = sync_hg.clone();
                    if let Err(e) = tokio::task::spawn_blocking(move || {
                        pr.refresh_from_store(&hs2);
                    }).await {
                        warn!(error = %e, "prover registry refresh failed");
                    }
                    // Reconstruct coverage streaks from synced prover
                    // data once at startup, before any frame-driven check.
                    // Without this, the first eviction pass after a
                    // restart would interpret all previously-stale
                    // allocations as freshly inactive and kick them
                    // immediately.
                    {
                        let pr_for_streak = sync_pr.clone();
                        let cov = sync_cov.clone();
                        let cur_frame = sync_lhf.load(std::sync::atomic::Ordering::Relaxed);
                        let _ = tokio::task::spawn_blocking(move || {
                            match (pr_for_streak.as_ref() as &dyn quil_types::consensus::ProverRegistry)
                                .get_all_active_app_shard_provers()
                            {
                                Ok(provers) => {
                                    cov.reconstruct_streaks(&provers, cur_frame);
                                    info!(
                                        provers = provers.len(),
                                        current_frame = cur_frame,
                                        "reconstructed coverage streaks"
                                    );
                                }
                                Err(e) => warn!(
                                    error = %e,
                                    "could not reconstruct coverage streaks"
                                ),
                            }
                        }).await;
                    }
                    } // end of `if let Some(addr) { ... }`
                } // end of `if !sync_archive_mode { ... }`
                // Only flip the lifecycle gate when we actually have
                // prover-tree data to evaluate against. On a fresh
                // wipe with no reachable archive (or sync error), the
                // local registry is empty — toggling sync_complete
                // here would let the lifecycle propose joins for
                // every shard before we know what we already own.
                if initial_sync_data_ok {
                    sync_pl.set_sync_complete();
                    info!("initial prover tree sync complete, lifecycle enabled");
                } else {
                    warn!(
                        "no prover-tree data available; lifecycle gate held — \
                         will retry via the periodic sync task"
                    );
                }

                // HIGH-2: seed the materializer from the durable GLOBAL
                // cursor and re-materialize the CRDT gap `[cursor+1..=head]`
                // BEFORE the live finalized feed is wired.
                //
                // The clock head (txn-A) commits synchronously on the
                // consensus loop; the CRDT + reward writes (txn-B) commit
                // later on the materializer worker, with the durable cursor
                // riding txn-B's own batch. So after any crash the durable
                // cursor M equals the CRDT frontier EXACTLY, while the
                // canonical clock head H may lead it. On restart the
                // in-memory `last_materialized_frame` is lost (→0); without
                // this seed+replay the live feed (which resumes at the
                // consensus re-seed frame ≥ H) would leave `[M+1..H]`
                // permanently un-materialized → prover-root divergence.
                //
                // Re-materializing `[M+1..=H]` reads the pre-M reward
                // balances and adds each frame's share exactly once (the
                // frames' CRDT mutations are NOT yet committed), so balances
                // land at the single-pass value — never doubled. The gate
                // `frame_number <= last_materialized` guarantees no frame
                // at/below M is re-run.
                //
                // Archive-only: the live materializer worker (and thus the
                // atomic cursor) exists only on archives; non-archive masters
                // pull already-materialized state from archives via the
                // poller (`process_global_frame` + plain `commit_frame`, no
                // cursor) and must NOT re-materialize. Target is the
                // canonical head H, never the forks re-seed frame N (frames
                // `(H,N]` aren't canonical-committed and get re-finalized
                // forward by consensus). Distinct from the record-only
                // backfill, which fills clock-record holes `[H+1,N-1]`
                // WITHOUT re-materializing.
                if sync_archive_mode {
                    if let Some(m) = frame_materializer.clone() {
                        let cs = sync_cs.clone();
                        let cov = sync_cov.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            let durable_cursor =
                                cs.get_global_materialized_cursor().unwrap_or(0);
                            let canonical_head = cs
                                .get_latest_global_frame()
                                .ok()
                                .and_then(|f| f.header.map(|h| h.frame_number))
                                .unwrap_or(0);
                            m.seed_cursor(durable_cursor);
                            if canonical_head > durable_cursor {
                                info!(
                                    from = durable_cursor + 1,
                                    to = canonical_head,
                                    gap = canonical_head - durable_cursor,
                                    "startup: re-materializing CRDT gap [cursor+1..=head] \
                                     (crash between clock-head and CRDT commit)"
                                );
                                for n in (durable_cursor + 1)..=canonical_head {
                                    let frame = match cs.get_global_frame(n) {
                                        Ok(f) => f,
                                        Err(e) => {
                                            warn!(
                                                frame = n,
                                                error = %e,
                                                "startup re-materialize: missing clock \
                                                 frame record — stopping (restart to resume)"
                                            );
                                            break;
                                        }
                                    };
                                    // Mirror the live worker: refresh halt
                                    // durations before each materialize so the
                                    // eviction step is gated identically.
                                    m.set_coverage_halt_durations(cov.check(n));
                                    if let Err(e) = m.materialize(&frame) {
                                        tracing::error!(
                                            frame = n,
                                            error = %e,
                                            "startup re-materialize failed — stopping to \
                                             avoid a permanent state hole (restart resumes \
                                             from the durable cursor)"
                                        );
                                        break;
                                    }
                                }
                                info!(
                                    cursor = m.last_materialized_frame(),
                                    "startup: CRDT gap re-materialize complete"
                                );
                            } else {
                                info!(
                                    cursor = durable_cursor,
                                    head = canonical_head,
                                    "startup: durable cursor at/after canonical head — \
                                     no CRDT gap to re-materialize"
                                );
                            }
                        })
                        .await;
                    }
                }

                    // Check if we're an active prover and build genesis QC.
                    // Try the latest QC's candidate frame first (an
                    // unfinalized rank-N candidate that the network
                    // never committed but a QC was already formed on
                    // — typical at the head of a chain mid-round).
                    // Falling back to the latest *committed* global
                    // frame would seed the forks tree at rank N-1,
                    // leaving the leader at rank N+1 unable to find
                    // the parent state and consensus stuck timing out.
                    let genesis_frame_result = {
                        use quil_types::store::ClockStore;
                        let cs_trait: &dyn ClockStore = sync_cs.as_ref();
                        // Canonical committed head — the frame all honest nodes
                        // share (their fork-ladders match). The forks forest must
                        // anchor here, not above it.
                        let committed_head_fn = cs_trait
                            .get_latest_global_clock_frame()
                            .ok()
                            .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
                            .unwrap_or(0);
                        let latest_qc = cs_trait.get_latest_quorum_certificate(&[]);
                        match &latest_qc {
                            Ok(qc) => info!(
                                rank = qc.rank,
                                frame_number = qc.frame_number,
                                committed_head = committed_head_fn,
                                selector = %hex::encode(&qc.selector),
                                "bootstrap: latest QC in store",
                            ),
                            Err(e) => warn!(
                                error = %e,
                                "bootstrap: no latest QC in store",
                            ),
                        }
                        let candidate = latest_qc.ok().and_then(|qc| {
                            // A latest-QC candidate ABOVE the committed head is an
                            // uncommitted but QC-CERTIFIED frame — normal at the head
                            // of a chain mid-round. Anchor the forks forest there when
                            // we actually hold the frame locally (persisted by
                            // `on_incorporated`), because:
                            //
                            //  - A post-grandfather (rank >= 587000) QC is a real
                            //    4-of-5 certificate, so >=4 nodes incorporated + kept
                            //    the frame and will anchor at the SAME candidate ->
                            //    the committee converges. Anchoring at the committed
                            //    head instead strands the leader: its newest-QC parent
                            //    isn't in the forest so it skips forever, and the
                            //    intermediate chain can't be rebuilt from local data
                            //    (frame_number is the chain HEIGHT, with multiple
                            //    competing fork candidates per height, and the
                            //    intermediate per-rank QCs aren't all stored).
                            //
                            //  - The ONLY unsafe case is a PRE-587000 single-signer
                            //    candidate (the degenerate/grandfathered era's
                            //    self-certified "latest QC", e.g. 2e5e08ad): it may
                            //    exist on just ONE node, so anchoring there forks that
                            //    node off alone. For those, fall back to the shared
                            //    committed head.
                            //
                            //  - If the frame isn't on disk at all (genuinely
                            //    dangling), the load below fails and we also fall back.
                            const GRANDFATHER_CUTOFF_RANK: u64 = 587_000;
                            if qc.frame_number > committed_head_fn
                                && qc.rank < GRANDFATHER_CUTOFF_RANK
                            {
                                warn!(
                                    qc_frame = qc.frame_number,
                                    qc_rank = qc.rank,
                                    committed_head = committed_head_fn,
                                    selector = %hex::encode(&qc.selector),
                                    "bootstrap: PRE-cutoff uncommitted latest-QC candidate — \
                                     anchoring on the shared committed head (single-signer-era \
                                     safety; such a candidate may be held by only one node)",
                                );
                                return None;
                            }
                            match cs_trait
                                .get_global_clock_frame_candidate(qc.frame_number, &qc.selector)
                            {
                                Ok(frame) => {
                                    if qc.frame_number > committed_head_fn {
                                        info!(
                                            qc_frame = qc.frame_number,
                                            qc_rank = qc.rank,
                                            committed_head = committed_head_fn,
                                            selector = %hex::encode(&qc.selector),
                                            "bootstrap: anchoring forks forest at the PERSISTED \
                                             newest-QC candidate above the committed head \
                                             (post-cutoff 4-of-5 QC — peers hold it too and \
                                             converge here; no chain rebuild needed)",
                                        );
                                    }
                                    Some(frame)
                                }
                                Err(e) => {
                                    warn!(
                                        error = %e,
                                        rank = qc.rank,
                                        frame_number = qc.frame_number,
                                        selector = %hex::encode(&qc.selector),
                                        "bootstrap: candidate frame lookup failed — falling back to committed",
                                    );
                                    None
                                }
                            }
                        });
                        match candidate {
                            Some(frame) => {
                                info!(
                                    rank = frame.header.as_ref().map(|h| h.rank).unwrap_or(0),
                                    frame_number = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0),
                                    "bootstrapping from latest QC candidate frame",
                                );
                                Ok(frame)
                            }
                            None => sync_cs.get_latest_global_frame()
                                .or_else(|_| {
                                    info!("no global frame in store, loading embedded mainnet genesis");
                                    quil_engine::genesis::load_mainnet_genesis()
                                }),
                        }
                    };

                    // #2 visibility: detect a canonical frame-record hole.
                    // On restart the forks tree re-seeds from the latest QC
                    // candidate (frame N), and finalization resumes from
                    // there — it does NOT re-finalize ranks below N. If
                    // finalization was lagging before the restart (heavy
                    // timeouts → chain advancing on TCs), the canonical
                    // clock store's head H can sit well below N, leaving
                    // frame RECORDS [H+1, N-1] absent even though their CRDT
                    // state was materialized (durably) before the restart.
                    // Those frames can't be served to catching-up peers
                    // until backfilled. We surface the gap here; the
                    // partial-progress-safe archive poller backfills forward
                    // from the canonical head via peers.
                    //
                    // We deliberately do NOT reprocess these frames through
                    // the execution pipeline on restart: that path
                    // re-applies already-materialized messages (double
                    // spend/credit). The safe recovery is a record-only
                    // backfill (fetch frame, store record, skip on_frame),
                    // tracked separately.
                    {
                        let canonical_head = sync_cs
                            .get_latest_global_frame()
                            .ok()
                            .and_then(|f| f.header.map(|h| h.frame_number))
                            .unwrap_or(0);
                        if let Ok(gf) = genesis_frame_result.as_ref() {
                            let reseed_frame =
                                gf.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
                            if reseed_frame > canonical_head.saturating_add(1) {
                                warn!(
                                    canonical_head,
                                    reseed_frame,
                                    gap = reseed_frame
                                        .saturating_sub(canonical_head)
                                        .saturating_sub(1),
                                    "restart: canonical frame records lag the consensus \
                                     re-seed point — backfilling the gap (record-only) from peers",
                                );
                                // Archives serve frame ranges to the network;
                                // fill the sub-max hole the poller can't reach.
                                // Record-only — no re-materialization (see
                                // run_record_only_backfill). Non-archive nodes
                                // don't serve ranges, so skip.
                                if sync_archive_mode {
                                    let bf_pool = sync_archive_pool.clone();
                                    let bf_cs = sync_cs.clone();
                                    let bf_validate = sync_frame_validate.clone();
                                    let bf_cancel = sync_token.clone();
                                    let lo = canonical_head.saturating_add(1);
                                    let hi = reseed_frame.saturating_sub(1);
                                    // The re-seed frame (frame hi+1) anchors the
                                    // local ancestor-chain walk; its parent
                                    // chain IS the [lo, hi] hole.
                                    let bf_anchor = Some(gf.clone());
                                    let seed = seed.clone();
                                    spawner.detach("record-only-backfill", async move {
                                        run_record_only_backfill(
                                            bf_pool, bf_cs, bf_validate, bf_anchor, (*seed).clone(), lo, hi,
                                            bf_cancel,
                                        )
                                        .await;
                                        Ok(())
                                    });
                                }
                            } else {
                                info!(
                                    canonical_head,
                                    reseed_frame,
                                    "restart: canonical frame records contiguous to re-seed point",
                                );
                            }
                        }
                    }

                    // Beyond the single reseed-anchored gap above, an archive
                    // restarted many times accumulates many small internal
                    // frame-record holes scattered BELOW the head (each round's
                    // finalization-lag gap). Scan the whole keyspace for all of
                    // them and backfill from local candidates (peers as
                    // fallback). Archive-only (non-archives don't serve ranges);
                    // detached + best-effort so it never blocks bringup.
                    if sync_archive_mode {
                        let gap_pool = sync_archive_pool.clone();
                        let gap_cs = sync_cs.clone();
                        let gap_validate = sync_frame_validate.clone();
                        let gap_cancel = sync_token.clone();
                        let seed = seed.clone();
                        spawner.detach("restart-gap-backfill", async move {
                            run_all_gap_backfill(gap_pool, gap_cs, gap_validate, (*seed).clone(), gap_cancel)
                                .await;
                            Ok(())
                        });
                    }

                    // Only nodes registered as global provers (i.e. with
                    // an allocation on the empty filter) should run the
                    // global consensus event loop. A non-global prover
                    // joining mid-stream subscribes to GLOBAL_CONSENSUS
                    // for awareness, but feeding inbound proposals into
                    // a local HotStuff loop crashes on "missing parent
                    // state at rank N" because we never saw ranks 1..N-1.
                    // Mainnet genesis-frame provers and testnet seed
                    // provers both qualify; config6-style joining nodes
                    // do not until ConfirmJoins flips their allocation
                    // to Active (at which point a future activation
                    // path can spin up the loop).
                    let is_global_prover: bool = {
                        use quil_types::consensus::ProverRegistry;
                        match sync_pr.get_prover_info(&sync_pa) {
                            Ok(Some(info)) => info
                                .allocations
                                .iter()
                                .any(|a| a.confirmation_filter.is_empty()),
                            _ => false,
                        }
                    };
                    // Global consensus (HotStuff over the global frame
                    // chain) is archive-only. In Go this is gated on
                    // `isConsensusParticipant() = ArchiveMode || Network == 99`.
                    // Non-archive provers participate in per-shard consensus
                    // (via AppConsensusEngine) but NOT in global consensus —
                    // they receive finalized global frames from the archive
                    // poller. Running the global event loop on a non-archive
                    // produces proposals/votes on GLOBAL_CONSENSUS that
                    // (a) flood the mesh, (b) get looped back to the receive
                    // dispatch and forwarded to workers, (c) cause QC
                    // verification failures with genesis-shaped all-zero
                    // signatures.
                    let is_consensus_participant = sync_archive_mode || network == 99;
                    if !is_consensus_participant {
                        info!(
                            "non-archive, non-devnet — skipping global consensus event loop activation \
                             (global frames arrive via the archive poller)",
                        );
                    } else if !is_global_prover {
                        info!(
                            "archive/devnet but not a global prover — skipping global consensus activation",
                        );
                    } else if genesis_frame_result.is_ok() {
                        if let Ok(genesis_frame) = genesis_frame_result {
                            if let Ok(bls_signer) = sync_km.get_signer(quil_types::crypto::KeyType::Falcon512) {
                                // Global consensus is delivered point-to-point over
                                // the :8340 mTLS channel to the committee archives
                                // (a full-coverage proposal exceeds the gossip
                                // message-size cap); app consensus stays on gossip.
                                // Falls back to the BlossomSub publisher only if we
                                // lack an mTLS identity (not a global prover archive).
                                // Keep the CONCRETE `DirectGlobalConsensusPublisher`
                                // Arc (when we have an mTLS identity) so the simplex
                                // cutover's `Cw8340Transport` can call its crate-private
                                // `submit_cw_channel`; the old path uses it as the
                                // `dyn ConsensusPublisher` below.
                                let direct_publisher: Option<Arc<crate::direct_global_consensus_publisher::DirectGlobalConsensusPublisher>> = {
                                    use quil_keys::KeyManager as _;
                                    file_key_manager
                                        .get_private_key(quil_types::crypto::KeyType::Falcon512)
                                        .ok()
                                        .map(|falcon_sk| {
                                            Arc::new(
                                                crate::direct_global_consensus_publisher::DirectGlobalConsensusPublisher::new(
                                                    sync_archive_pool.clone(),
                                                    falcon_sk,
                                                    consensus_loopback_tx.clone(),
                                                    peer_id.to_bytes(),
                                                    spawner.clone(),
                                                ),
                                            )
                                        })
                                };
                                // Build an on-finalized hook that prunes per-rank
                                // aggregator state below the finalized watermark.
                                // Captures the OnceLocks so the callback stays valid
                                // even though the aggregators are populated later
                                // in this same activation (finalization can't fire
                                // before the event loop runs).
                                // Dedicated materialization worker (archive nodes only).
                                // Frame materialization — up to ~100 BLS aggregate
                                // signature verifications plus the CRDT/KZG commit per
                                // frame — MUST NOT run on the consensus event loop:
                                // `on_finalized_state` is called synchronously from the
                                // forks finalizer on that loop, so an inline materialize
                                // blocks proposals/votes/timeouts for its whole duration
                                // (the network-wide stall once frames filled with
                                // shard-frame proofs). Offload to an ordered single-
                                // consumer channel; each materialize runs on the blocking
                                // pool and is awaited in turn, preserving finalize order
                                // and the materializer's `last_materialized_frame`
                                // idempotency guard. The consensus loop only does a
                                // non-blocking `send`.
                                let mat_job_tx: Option<
                                    tokio::sync::mpsc::UnboundedSender<(quil_types::proto::global::GlobalFrame, u64)>,
                                > = if let Some(m) = frame_materializer.clone() {
                                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(
                                        quil_types::proto::global::GlobalFrame,
                                        u64,
                                    )>();
                                    let cov_for_worker = sync_cov.clone();
                                    let mc_for_worker = sync_mc.clone();
                                    let pa_for_worker = sync_pa.to_vec();
                                    // Handles for the leader-gated merge trigger's shard-inventory
                                    // assembly (filters + committed sizes + active counts). Use the
                                    // closure-local `sync_*` clones so the outer originals stay
                                    // available to later spawns.
                                    let crdt_for_merge = sync_crdt.clone();
                                    let shards_store_for_merge = sync_shards_store.clone();
                                    let registry_for_merge = sync_pr.clone();
                                    spawner.detach("global-materializer", async move {
                                        while let Some((frame, frame_number)) = rx.recv().await {
                                            let m = m.clone();
                                            let cov = cov_for_worker.clone();
                                            let mc = mc_for_worker.clone();
                                            let pa = pa_for_worker.clone();
                                            let crdt_for_merge = crdt_for_merge.clone();
                                            let shards_store_for_merge = shards_store_for_merge.clone();
                                            let registry_for_merge = registry_for_merge.clone();
                                            let outcome = tokio::task::spawn_blocking(move || {
                                                // Refresh halt durations right before
                                                // materialize so the eviction step inside
                                                // skips halted shards correctly.
                                                let halts = cov.check(frame_number);
                                                m.set_coverage_halt_durations(halts);
                                                let res = match m.materialize(&frame) {
                                                    Ok(result) => {
                                                        // Consume the finalized frame's
                                                        // bundles from the mempool so they
                                                        // aren't re-proposed.
                                                        if !result.finalized_bundles.is_empty() {
                                                            mc.mark_finalized(&result.finalized_bundles);
                                                        }
                                                        Ok(())
                                                    }
                                                    Err(e) => Err(e),
                                                };
                                                // Leader-gated shard-split rebalance trigger:
                                                // only the producer of THIS frame proposes,
                                                // matching Go's `frameProver` gate (exactly one
                                                // proposer per frame, no duplicates). Publishes
                                                // ShardSplitEligible events; the shard-
                                                // orchestrator loop submits the op to the
                                                // mempool. Runs after materialize so the
                                                // registry reflects this frame's prover changes.
                                                let producer = frame
                                                    .header
                                                    .as_ref()
                                                    .map(|h| h.prover.clone())
                                                    .unwrap_or_default();
                                                if !producer.is_empty() && producer == pa {
                                                    cov.propose_split_rebalance(frame_number);
                                                    // Leader-gated MERGE trigger (16GiB-gated).
                                                    // Assemble the current shard inventory
                                                    // (filters + committed sizes + active counts)
                                                    // and propose merges for under-covered
                                                    // factor-2 sibling pairs that fit the gate.
                                                    let inventory =
                                                        quil_engine::coverage::build_shard_inventory(
                                                            crdt_for_merge.clone(),
                                                            shards_store_for_merge.clone(),
                                                            registry_for_merge.as_ref(),
                                                            frame_number,
                                                        );
                                                    cov.propose_merge_rebalance(
                                                        frame_number,
                                                        &inventory,
                                                    );
                                                }
                                                res
                                            })
                                            .await;
                                            match outcome {
                                                Ok(Ok(())) => {}
                                                // A finalized frame that this node
                                                // cannot materialize is NOT
                                                // skippable: advancing to the next
                                                // frame would apply it on top of a
                                                // hole at `frame_number`, diverging
                                                // this node's CRDT/prover root from
                                                // the committee permanently (its
                                                // subsequent frames then fail
                                                // `verify_prover_root` and peers
                                                // reject them). Stop the materializer
                                                // loudly instead of silently
                                                // corrupting state; a restart
                                                // re-materializes cleanly from the
                                                // durable cursor, and the halt is
                                                // detectable rather than a silent
                                                // fall-out-of-consensus.
                                                Ok(Err(e)) => {
                                                    tracing::error!(
                                                        error = %e,
                                                        frame = frame_number,
                                                        "frame materialize failed — stopping \
                                                         materializer to avoid a permanent state \
                                                         hole; restart to re-materialize from the \
                                                         durable cursor",
                                                    );
                                                    break;
                                                }
                                                Err(e) => {
                                                    tracing::error!(
                                                        error = %e,
                                                        frame = frame_number,
                                                        "materializer task panicked — stopping \
                                                         materializer to avoid a permanent state \
                                                         hole; restart to re-materialize from the \
                                                         durable cursor",
                                                    );
                                                    break;
                                                }
                                            }
                                        }
                                        tracing::info!("global materializer worker exited");
                                        Ok(())
                                    });
                                    Some(tx)
                                } else {
                                    None
                                };

                                    // ── commonware-simplex + Falcon GLOBAL consensus ──
                                    match (mat_job_tx.clone(), direct_publisher.clone()) {
                                        (Some(mat_tx), Some(direct_pub)) => {
                                            // Genesis digest = Poseidon(genesis output)[..32].
                                            let genesis_header =
                                                genesis_frame.header.clone().unwrap_or_default();
                                            let genesis_frame_number = genesis_header.frame_number;
                                            let genesis_id = quil_crypto::poseidon::hash_bytes_to_32(
                                                &genesis_header.output,
                                            )
                                            .unwrap_or([0u8; 32]);
                                            let genesis_digest =
                                                quil_cw_consensus::adapters::digest_from_identity(
                                                    genesis_id,
                                                );

                                            // Leader provider — same inputs the legacy
                                            // activation used. The signer here is the
                                            // PROVER key (signs the frame-header VDF
                                            // proof), distinct from the committee key
                                            // that signs simplex votes below.
                                            let cw_signer: Arc<dyn quil_types::crypto::Signer> =
                                                Arc::from(bls_signer);
                                            let leader_provider: Arc<dyn quil_consensus::leader_provider::LeaderProvider<quil_engine::consensus_types::GlobalState>> =
                                                Arc::new(quil_engine::leader_provider::GlobalLeaderProvider::new(
                                                    sync_pr.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
                                                    sync_fp.clone(),
                                                    sync_da.clone() as Arc<dyn quil_types::consensus::DifficultyAdjuster>,
                                                    sync_cs.clone() as Arc<dyn quil_types::store::ClockStore>,
                                                    sync_mc.clone(),
                                                    sync_pa.to_vec(),
                                                    sync_bls_pub.clone(),
                                                    cw_signer,
                                                    Arc::new(quil_tries::ShaInclusionProver)
                                                        as Arc<dyn quil_types::crypto::InclusionProver + Send + Sync>,
                                                    Some(sync_em.clone()),
                                                    // CRDT for the prover_tree_commitment the leader
                                                    // binds into each frame header + VDF challenge.
                                                    Some(sync_crdt.clone()),
                                                ));

                                            // This node's committee identity IS its proving key
                                            // (`q-prover-key`): the prover and consensus committee
                                            // roles share one Falcon-512 key.
                                            let (my_sk, my_pk) = match sync_km
                                                .get_signer_by_id("q-prover-key")
                                            {
                                                Ok(s) => (
                                                    s.private_key().to_vec(),
                                                    s.public_key().to_vec(),
                                                ),
                                                Err(e) => {
                                                    warn!(error = %e, "no q-prover-key — cannot join simplex committee");
                                                    (Vec::new(), Vec::new())
                                                }
                                            };

                                            // resolve_peer: inbound mTLS peer-id bytes →
                                            // committee Falcon pubkey (parallel config lists).
                                            let resolve_peer: crate::cw_consensus_bridge::PeerResolver = {
                                                let mut map: std::collections::HashMap<
                                                    Vec<u8>,
                                                    quil_cw_consensus::falcon_base::FalconPublicKey,
                                                > = std::collections::HashMap::new();
                                                for (pid_b58, pk_hex) in sync_consensus_committee_peer_ids
                                                    .iter()
                                                    .zip(sync_consensus_committee.iter())
                                                {
                                                    let Ok(pid) =
                                                        bs58::decode(pid_b58).into_vec()
                                                    else {
                                                        continue;
                                                    };
                                                    let Ok(pk_bytes) = hex::decode(pk_hex) else {
                                                        continue;
                                                    };
                                                    if let Some(pk) = quil_cw_consensus::falcon_base::FalconPublicKey::from_bytes(&pk_bytes) {
                                                        map.insert(pid, pk);
                                                    }
                                                }
                                                info!(committee = map.len(), "cw resolve_peer map built");
                                                Arc::new(move |from: &[u8]| map.get(from).cloned())
                                            };

                                            // Bump head atomics / CurrentFrame on finalize.
                                            let head_hook: quil_engine::cw_global_seams::HeadHook = {
                                                let cf = sync_cf.clone();
                                                let lhf = sync_lhf.clone();
                                                let cfin = sync_consensus_finalized.clone();
                                                Arc::new(move |frame_number: u64, rank: u64| {
                                                    cf.observe(frame_number);
                                                    cf.observe_rank(rank);
                                                    lhf.fetch_max(
                                                        frame_number,
                                                        std::sync::atomic::Ordering::Relaxed,
                                                    );
                                                    cfin.fetch_max(
                                                        frame_number,
                                                        std::sync::atomic::Ordering::Relaxed,
                                                    );
                                                })
                                            };

                                            let transport: Arc<dyn quil_engine::cw_global_seams::GlobalConsensusTransport> =
                                                Arc::new(crate::cw_consensus_bridge::Cw8340Transport::new(direct_pub));

                                            let deps = crate::cw_consensus_bridge::CwGlobalDeps {
                                                committee_hex: sync_consensus_committee.clone(),
                                                my_signing_key: my_sk,
                                                my_public_key: my_pk,
                                                leader_provider,
                                                verifier: frame_verifier.clone(),
                                                clock_store: sync_cs.clone()
                                                    as Arc<dyn quil_types::store::ClockStore>,
                                                mat_job_tx: mat_tx,
                                                head_hook,
                                                filter: Vec::new(),
                                                epoch: 0,
                                                genesis_digest,
                                                genesis_frame_number,
                                                leader_timeout_secs: sync_consensus_leader_timeout_secs,
                                                transport,
                                                resolve_peer,
                                                storage_directory: sync_cw_storage_dir.clone(),
                                            };
                                            match crate::cw_consensus_bridge::start_cw_global_consensus(deps) {
                                                Some(router) => {
                                                    if sync_cw_router.set(Arc::new(router)).is_err() {
                                                        warn!("cw_router already set");
                                                    } else {
                                                        info!(
                                                            frame = genesis_frame_number,
                                                            "commonware-simplex global consensus activated",
                                                        );
                                                    }
                                                }
                                                None => warn!(
                                                    "start_cw_global_consensus returned None (committee empty or key absent)",
                                                ),
                                            }
                                        }
                                        _ => {
                                            warn!(
                                                "simplex consensus configured but no materializer / mTLS publisher — not activating (archive + mTLS required)",
                                            );
                                        }
                                    }
                            }
                        }
                    }

                // Periodic incremental sync every 5 minutes
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            // Archives have full history locally — they
                            // don't need to incremental-sync the prover
                            // tree from peers, and on a fresh post-
                            // migration topology this just trades "no
                            // tree data available" errors with other
                            // freshly-migrated archives.
                            if sync_archive_mode {
                                continue;
                            }
                            if let Some(addr) = sync_pool.get_all().await.first() {
                                // Snapshot the local reward balance before the
                                // sync pulls fresh leaves. Compared against the
                                // post-sync balance to surface credits that
                                // arrived via peer data (i.e. not driven by
                                // local `apply_reward`).
                                let pre_balance = quil_execution::global_intrinsic::prover_shard_update::
                                    read_reward_balance_for(&sync_crdt, &sync_pa)
                                    .unwrap_or_else(|_| num_bigint::BigInt::from(0));
                                // Pin the sync to the latest verified
                                // frame's prover_tree_commitment.
                                // Without this, a malicious archive
                                // could serve a self-consistent fake
                                // snapshot at any root — the post-sync
                                // server-claim match only proves
                                // internal consistency, not authority.
                                let expected_root = sync_cs
                                    .get_latest_global_frame()
                                    .ok()
                                    .and_then(|f| f.header.map(|h| h.prover_tree_commitment))
                                    .unwrap_or_default();
                                // Forest sync of the global prover shard, pinned
                                // to the latest verified frame's
                                // prover_tree_commitment (empty ⇒ trust). Pulls
                                // the commitment diff + changed vertices' blobs.
                                match crate::forest_sync::sync_single_shard_verified(
                                    addr, &seed[..], sync_crdt.clone(), &[0xffu8; 32], &expected_root,
                                ).await {
                                    Ok(converged) => {
                                        info!(match_ok = converged, "incremental prover tree sync complete");
                                        // Refresh registry with updated data.
                                        let pr = sync_pr.clone();
                                        let hs3 = sync_hg.clone();
                                        let _ = tokio::task::spawn_blocking(move || pr.refresh_from_store(&hs3)).await;

                                        // Compare reward balance for the local
                                        // prover before/after; log when it changed
                                        // so the operator sees synced-in credits.
                                        let post_balance = quil_execution::global_intrinsic::prover_shard_update::
                                            read_reward_balance_for(&sync_crdt, &sync_pa)
                                            .unwrap_or_else(|_| num_bigint::BigInt::from(0));
                                        if post_balance != pre_balance {
                                            let delta = &post_balance - &pre_balance;
                                            info!(
                                                prover = %hex::encode(&sync_pa),
                                                delta = %delta,
                                                new_balance = %post_balance,
                                                "local prover reward balance updated by sync"
                                            );
                                        }
                                        // Recovery path: if the initial sync at
                                        // startup failed, the lifecycle gate stayed
                                        // held. Unblock it now that we have data.
                                        sync_pl.set_sync_complete();
                                    }
                                    Err(e) => warn!(error = %e, "incremental prover tree sync failed"),
                                }
                            }
                        }
                        _ = sync_token.cancelled() => break,
                    }
                }
                Ok(())
            });
            info!("periodic prover tree sync task spawned (5-minute interval)");
        }

        // Periodic archive-direct shard info refresh. Drives the
        // lifecycle's `ProposeJoin`/`ProposeLeave` gate: until the
        // first successful `GetAppShards` response lands, the
        // lifecycle short-circuits all auto-pick paths. After that,
        // every 60 frames (~10 min on mainnet) we refresh — frame-
        // anchored so a stalled chain doesn't burn endpoints.
        //
        // Distinct from `LocalShardInfoProvider`'s dial-out fallback:
        // that path is "try local first." For auto-allocation we
        // require archive-sourced sizes because the local node may
        // not have visibility into shards it isn't a member of.
        {
            let pool = archive_pool.clone();
            let lifecycle = prover_lifecycle.clone();
            let cf_for_refresh = current_frame.clone();
            let seed_for_refresh = seed.clone();
            let shards_store_for_refresh = shards_store.clone();
            let mc_for_refresh = message_collector.clone();
            sup.spawn("archive-shard-info-refresh", move |cancel| async move {
                const REFRESH_CADENCE_FRAMES: u64 = 60;
                let mut last_refresh_frame: u64 = 0;
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                interval.set_missed_tick_behavior(
                    tokio::time::MissedTickBehavior::Skip,
                );
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = interval.tick() => {}
                    }
                    let now_frame = cf_for_refresh.effective();
                    let needs_initial = !lifecycle.shard_info_loaded();
                    let cadence_due = last_refresh_frame > 0
                        && now_frame >= last_refresh_frame + REFRESH_CADENCE_FRAMES;
                    if !needs_initial && !cadence_due {
                        continue;
                    }
                    match quil_rpc::fetch_shard_sizes_from_archive(
                        &pool,
                        &seed_for_refresh,
                        shards_store_for_refresh.as_ref(),
                        None,
                    )
                    .await
                    {
                        Ok(sizes) => {
                            let count = sizes.len();
                            lifecycle.set_remote_shard_sizes(sizes);
                            last_refresh_frame = now_frame.max(1);
                            // Refresh the message collector's valid-shard set so
                            // preemptive ingestion validation can reject shard
                            // frames whose address isn't a real current shard
                            // (e.g. an old 4096-grid division). A shard frame's
                            // `address` is the L2‖prefix filter, which is
                            // `shard_key[3..35] ‖ prefix_bytes` for each row.
                            if let Ok(rows) = shards_store_for_refresh.range_app_shards() {
                                let mut valid: std::collections::HashSet<Vec<u8>> =
                                    std::collections::HashSet::with_capacity(rows.len());
                                for r in &rows {
                                    if r.shard_key.len() >= 35 {
                                        let mut addr = r.shard_key[3..35].to_vec();
                                        for &p in &r.prefix {
                                            addr.push(p as u8);
                                        }
                                        valid.insert(addr);
                                    }
                                }
                                if !valid.is_empty() {
                                    mc_for_refresh.set_valid_shard_addresses(valid);
                                }
                            }
                            info!(
                                shards = count,
                                frame = now_frame,
                                initial = needs_initial,
                                "shard_info refresh: cache updated"
                            );
                        }
                        Err(quil_rpc::ShardInfoRefreshError::PoolEmpty) => {
                            // Archive pool not yet populated by PeerInfo
                            // gossip — log at debug, retry next tick.
                            tracing::debug!("shard_info refresh: archive pool empty, retrying");
                        }
                        Err(quil_rpc::ShardInfoRefreshError::NoLocalShards) => {
                            // Local shards-store empty — genesis not
                            // yet seeded, or the wrong network ID.
                            tracing::debug!("shard_info refresh: local shards-store empty, retrying");
                        }
                        Err(e) => {
                            warn!(error = %e, "shard_info refresh failed (will retry)");
                        }
                    }
                }
                info!("shard_info refresh task stopped");
                Ok(())
            });
            info!("shard_info refresh task spawned (frame-anchored, 60-frame cadence)");
        }
    } else {
        warn!("no Ed448 seed available — archive poller disabled (production archives require mTLS)");
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    use std::collections::HashSet;

    fn verifier() -> quil_engine::frame_validator::GlobalFrameVerifier {
        quil_engine::frame_validator::GlobalFrameVerifier::with_bls(
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            Arc::new(quil_crypto::FalconKeyConstructor),
        )
    }

    /// A frame whose proposer is NOT in the genesis-prover allowlist is
    /// rejected BEFORE any VDF/BLS work — the same first-line drop the
    /// gossip GLOBAL_FRAME handler performs. This is the archive-sourced
    /// forged-frame defense: it never reaches `put_global_frame`.
    #[test]
    fn rejects_frame_from_non_genesis_prover() {
        let mut addrs: HashSet<Vec<u8>> = HashSet::new();
        addrs.insert(vec![0xAA; 32]);
        let frame = quil_types::proto::global::GlobalFrame {
            header: Some(quil_types::proto::global::GlobalFrameHeader {
                frame_number: 42,
                prover: vec![0xBB; 32], // not in the allowlist
                ..Default::default()
            }),
            requests: Vec::new(),
        };
        assert!(!archive_frame_is_valid(&frame, &addrs, &verifier()));
    }

    /// A headerless frame is malformed and dropped.
    #[test]
    fn rejects_frame_without_header() {
        let addrs: HashSet<Vec<u8>> = HashSet::new();
        let frame = quil_types::proto::global::GlobalFrame {
            header: None,
            requests: Vec::new(),
        };
        assert!(!archive_frame_is_valid(&frame, &addrs, &verifier()));
    }
}
