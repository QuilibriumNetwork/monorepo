use std::sync::Arc;

use tracing::{debug, info, warn};

// Import KeyManager trait for get_signer
use quil_keys::KeyManager as _;

use quil_lifecycle::Supervisor;

/// Consensus catch-up sync. Woken by `notify` (the engine fires
/// `on_missing_parent` when it orphans a proposal because the node is behind),
/// it pulls the missing proposals from a peer's `GlobalService` and submits them
/// into the consensus loop so the node rejoins consensus rather than just
/// mirroring frames into the store. Mirrors Go's `SyncProvider` /
/// `GlobalSyncClient` (`GetGlobalProposal` → `AddProposal`, ascending from the
/// finalized head). The partition is applied to this path for free: the proxy
/// gates `GetGlobalProposal` exactly like `GetGlobalFrame`.
async fn run_proposal_catchup(
    pool: Arc<quil_rpc::ArchiveEndpointPool>,
    consensus_handle: Arc<
        std::sync::OnceLock<quil_engine::consensus_types::GlobalEventLoopHandle>,
    >,
    notify: Arc<tokio::sync::Notify>,
    finalized: Arc<std::sync::atomic::AtomicU64>,
    seed: [u8; 57],
    cancel: tokio_util::sync::CancellationToken,
) {
    use std::sync::atomic::Ordering::Relaxed;
    info!("consensus proposal-catchup task started");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = notify.notified() => {}
        }
        // Coalesce bursts of orphan signals into one catch-up round.
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
        }
        // Need the live consensus handle (set once activation completes).
        let Some(handle) = consensus_handle.get() else { continue };

        // Try known archive endpoints until one serves the gap. During a
        // partition every peer returns UNAVAILABLE here; the next orphan signal
        // retries, so recovery happens on the first poll after the heal.
        for addr in pool.get_all().await {
            if cancel.is_cancelled() {
                return;
            }
            let mut client = match quil_rpc::ArchiveClient::connect_mtls(&addr, &seed).await {
                Ok(c) => c,
                Err(e) => {
                    debug!(%addr, error = %e, "catchup: connect failed");
                    continue;
                }
            };
            let mut next = finalized.load(Relaxed) + 1;
            let mut synced = 0u64;
            loop {
                if cancel.is_cancelled() {
                    return;
                }
                let proposal = match client.get_global_proposal(next).await {
                    Ok(p) => p,
                    Err(e) => {
                        // No proposal at `next` (caught up to source head) or the
                        // peer is partitioned/erroring — stop this endpoint.
                        debug!(%addr, frame = next, error = %e, "catchup: stop (no proposal)");
                        break;
                    }
                };
                match quil_engine::consensus_types::proto_proposal_to_signed(&proposal) {
                    Ok((sp, qc, tc)) => {
                        handle.submit_quorum_certificate(qc);
                        if let Some(tc) = tc {
                            handle.submit_timeout_certificate(tc);
                        }
                        if !handle.submit_proposal(sp).await {
                            break; // loop shutting down
                        }
                        synced += 1;
                        next += 1;
                    }
                    Err(e) => {
                        debug!(%addr, frame = next, error = %e, "catchup: decode failed");
                        break;
                    }
                }
            }
            if synced > 0 {
                info!(%addr, synced, "catchup: submitted synced proposals to consensus");
                break; // made progress; done for this round
            }
        }
    }
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
async fn run_record_only_backfill(
    pool: Arc<quil_rpc::ArchiveEndpointPool>,
    clock_store: Arc<quil_store::RocksClockStore>,
    seed: [u8; 57],
    lo: u64,
    hi: u64,
    cancel: tokio_util::sync::CancellationToken,
) {
    if lo > hi {
        return;
    }
    info!(lo, hi, "record-only frame-record backfill started");
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
    pub p2p_handle: quil_p2p::node::P2PHandle,
    pub consensus_handle:
        Arc<std::sync::OnceLock<quil_engine::consensus_types::GlobalEventLoopHandle>>,
    pub vote_aggregator:
        Arc<std::sync::OnceLock<Arc<quil_engine::vote_aggregation::VoteAggregation>>>,
    pub timeout_aggregator:
        Arc<std::sync::OnceLock<Arc<quil_engine::timeout_aggregation::TimeoutAggregation>>>,
    pub global_validator: Arc<std::sync::OnceLock<Arc<
        quil_engine::validator::ConsensusValidator<
            quil_engine::consensus_types::GlobalState,
            quil_engine::consensus_types::GlobalVote,
        >,
    >>>,
    pub db_arc: Arc<quil_store::RocksDb>,
    pub frame_materializer: Option<Arc<quil_engine::frame_materializer::FrameMaterializer>>,
    pub consensus_loopback_tx: tokio::sync::mpsc::Sender<quil_p2p::node::ReceivedMessage>,
    pub peer_id: quil_p2p::PeerId,
    pub spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
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
        p2p_handle,
        consensus_handle,
        vote_aggregator,
        timeout_aggregator,
        global_validator,
        db_arc,
        frame_materializer,
        consensus_loopback_tx,
        peer_id,
        spawner,
    } = args;

    if let Some(seed) = mtls_seed {
        // Catch-up sync (Part C): the engine fires `on_missing_parent` when it
        // orphans a proposal (node fell behind, e.g. after a partition); that
        // notifies `catchup_notify`, and the task below pulls the missing
        // proposals from a peer's GlobalService and submits them into the
        // consensus loop so the node rejoins consensus. `consensus_finalized`
        // tracks the engine's finalized frame (updated only by the finalized
        // hook — distinct from the poller-written store head) so the sync starts
        // from the right point.
        let catchup_notify = Arc::new(tokio::sync::Notify::new());
        let consensus_finalized = Arc::new(std::sync::atomic::AtomicU64::new(0));
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
            forward_fill: archive_mode,
            ..Default::default()
        };
        {
            let pool = archive_pool.clone();
            let cs = clock_store.clone();
            sup.run_until_cancelled("archive-poller", move |cancel| async move {
                quil_rpc::run_archive_poller(pool, cs, seed, poller_config, cancel).await;
                Ok(())
            });
        }
        info!("archive frame poller spawned (with execution pipeline)");

        // Consensus catch-up sync task — replays missing proposals into the
        // consensus loop when the engine signals it's behind (Part C).
        {
            let pool = archive_pool.clone();
            let ch = consensus_handle.clone();
            let notify = catchup_notify.clone();
            let finalized = consensus_finalized.clone();
            sup.run_until_cancelled("global-consensus-catchup", move |cancel| async move {
                run_proposal_catchup(pool, ch, notify, finalized, seed, cancel).await;
                Ok(())
            });
        }
        info!("consensus proposal-catchup task spawned");

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
            let sync_p2p = p2p_handle.clone();
            let sync_ch = consensus_handle.clone();
            let sync_va = vote_aggregator.clone();
            let sync_ta = timeout_aggregator.clone();
            let sync_gv = global_validator.clone();
            let sync_cov = coverage_monitor.clone();
            let sync_cf = current_frame.clone();
            let sync_lhf = last_global_head_frame.clone();
            let sync_consensus_finalized = consensus_finalized.clone();
            let sync_catchup_notify = catchup_notify.clone();
            let sync_archive_mode = archive_mode;
            let sync_db_for_consensus: Arc<dyn quil_types::store::KvDb> = db_arc.clone();
            // Committee endpoints for the direct global-consensus publisher.
            let sync_archive_pool = archive_pool.clone();
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
                        match quil_rpc::ensure_prover_tree(
                            addr, &seed,
                            quil_types::proto::application::HypergraphPhaseSet::VertexAdds,
                            sync_hg.clone(),
                            &[],
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
                        let latest_qc = cs_trait.get_latest_quorum_certificate(&[]);
                        match &latest_qc {
                            Ok(qc) => info!(
                                rank = qc.rank,
                                frame_number = qc.frame_number,
                                selector = %hex::encode(&qc.selector),
                                "bootstrap: latest QC in store",
                            ),
                            Err(e) => warn!(
                                error = %e,
                                "bootstrap: no latest QC in store",
                            ),
                        }
                        let candidate = latest_qc.ok().and_then(|qc| {
                            match cs_trait
                                .get_global_clock_frame_candidate(qc.frame_number, &qc.selector)
                            {
                                Ok(frame) => Some(frame),
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
                                    let bf_cancel = sync_token.clone();
                                    let lo = canonical_head.saturating_add(1);
                                    let hi = reseed_frame.saturating_sub(1);
                                    spawner.detach("record-only-backfill", async move {
                                        run_record_only_backfill(
                                            bf_pool, bf_cs, seed, lo, hi, bf_cancel,
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
                            if let Ok(bls_signer) = sync_km.get_signer(quil_types::crypto::KeyType::Bls48581G1) {
                                // Global consensus is delivered point-to-point over
                                // the :8340 mTLS channel to the committee archives
                                // (a full-coverage proposal exceeds the gossip
                                // message-size cap); app consensus stays on gossip.
                                // Falls back to the BlossomSub publisher only if we
                                // lack an mTLS identity (not a global prover archive).
                                let publisher: Arc<dyn quil_engine::consensus_glue::ConsensusPublisher> =
                                    match mtls_seed {
                                        Some(seed) => Arc::new(
                                            crate::direct_global_consensus_publisher::DirectGlobalConsensusPublisher::new(
                                                sync_archive_pool.clone(),
                                                seed,
                                                consensus_loopback_tx.clone(),
                                                peer_id.to_bytes(),
                                                sync_p2p.clone(),
                                                spawner.clone(),
                                            ),
                                        ),
                                        None => Arc::new(
                                            crate::blossomsub_consensus_publisher::BlossomsubConsensusPublisher {
                                                p2p_handle: sync_p2p.clone(),
                                                loopback_tx: consensus_loopback_tx.clone(),
                                                self_peer_id: peer_id.to_bytes(),
                                                spawner: spawner.clone(),
                                            },
                                        ),
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
                                                Ok(Err(e)) => tracing::warn!(
                                                    error = %e,
                                                    frame = frame_number,
                                                    "frame materialize failed",
                                                ),
                                                Err(e) => tracing::warn!(
                                                    error = %e,
                                                    frame = frame_number,
                                                    "materializer task panicked",
                                                ),
                                            }
                                        }
                                        tracing::info!("global materializer worker exited");
                                        Ok(())
                                    });
                                    Some(tx)
                                } else {
                                    None
                                };
                                let finalized_hook: quil_engine::consensus_glue::FinalizedStateHook = {
                                    let va_cell = sync_va.clone();
                                    let ta_cell = sync_ta.clone();
                                    let cs_for_fin = sync_cs.clone();
                                    let cf_for_fin = sync_cf.clone();
                                    let lhf_for_fin = sync_lhf.clone();
                                    let consensus_finalized_for_fin = sync_consensus_finalized.clone();
                                    Arc::new(move |state| {
                                        if let Some(va) = va_cell.get() {
                                            va.advance_min_active_rank(state.rank);
                                        }
                                        if let Some(ta) = ta_cell.get() {
                                            ta.advance_min_active_rank(state.rank);
                                        }
                                        // Persist the finalized frame to the
                                        // canonical clock-store path so:
                                        //   1. archive nodes report a real
                                        //      `last_global_head_frame` in
                                        //      PeerInfo (rather than 0),
                                        //   2. peers can fetch the frame via
                                        //      gRPC through the archive pool,
                                        //   3. the archive_poller's per-frame
                                        //      execution pipeline + lifecycle
                                        //      evaluator runs at all (it's
                                        //      driven by `get_latest_global_clock_frame`).
                                        // Without this hook, every node's
                                        // status block reads `frame: 0`
                                        // forever even though Forks contains
                                        // 100+ finalized states.
                                        let app = &state.state;
                                        let header = quil_types::proto::global::GlobalFrameHeader {
                                            frame_number: app.frame_number,
                                            rank: app.rank,
                                            timestamp: app.timestamp,
                                            difficulty: app.difficulty,
                                            output: app.output.clone(),
                                            parent_selector: app.parent_selector.clone(),
                                            prover: app.prover.clone(),
                                            prover_tree_commitment: app.prover_tree_commitment.clone(),
                                            requests_root: app.requests_root.clone(),
                                            ..Default::default()
                                        };
                                        let frame = quil_types::proto::global::GlobalFrame {
                                            header: Some(header),
                                            // Carry the proposal's message bundles
                                            // through to the persisted frame so the
                                            // materializer sees them on finalization.
                                            requests: app.messages.clone(),
                                        };
                                        struct NoTxn;
                                        impl quil_types::store::Transaction for NoTxn {
                                            fn get(&self, _: &[u8]) -> quil_types::error::Result<Option<Vec<u8>>> { Ok(None) }
                                            fn set(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn commit(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn delete(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn abort(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn new_iter(
                                                &self,
                                                _: &[u8],
                                                _: &[u8],
                                            ) -> quil_types::error::Result<Box<dyn quil_types::store::Iterator>> {
                                                Err(quil_types::error::QuilError::NotFound("noop".into()))
                                            }
                                            fn delete_range(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn as_any(&self) -> &dyn std::any::Any { self }
                                        }
                                        let no_txn = NoTxn;
                                        let cs_trait: &dyn quil_types::store::ClockStore = cs_for_fin.as_ref();
                                        if let Err(e) = cs_trait.put_global_clock_frame(&frame, &no_txn) {
                                            tracing::warn!(
                                                error = %e,
                                                frame = app.frame_number,
                                                rank = app.rank,
                                                "failed to persist finalized frame",
                                            );
                                        }
                                        // Bump head-frame atomics so PeerInfo
                                        // advertises the real chain head.
                                        // `observe` / `fetch_max` keep these
                                        // monotonic even if finalization
                                        // callbacks arrive out of order.
                                        cf_for_fin.observe(app.frame_number);
                                        // Track the consensus RANK (distinct from
                                        // the frame number) so the gRPC submit path
                                        // and the GLOBAL_PROVER relay tag mempool
                                        // messages in the rank space the leader's
                                        // `collect_for_rank` actually reads.
                                        cf_for_fin.observe_rank(app.rank);
                                        lhf_for_fin.fetch_max(
                                            app.frame_number,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                        // Track the engine's finalized frame for
                                        // the catch-up sync's start point (only
                                        // the consensus path bumps this, unlike
                                        // the poller-shared head atomic above).
                                        consensus_finalized_for_fin.fetch_max(
                                            app.frame_number,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );

                                        // Hand the finalized frame to the dedicated
                                        // materializer worker (archive nodes only) —
                                        // a non-blocking send so the consensus event
                                        // loop is never stalled by materialization
                                        // (hypergraph commit + per-proof BLS verifies).
                                        // The worker materializes in finalize order:
                                        // commits the hypergraph, verifies the prover
                                        // root, processes bundles, prunes orphan joins,
                                        // evicts inactive provers, persists alt-shard
                                        // updates, publishes the post-materialize
                                        // snapshot, and marks the frame's bundles
                                        // consumed in the mempool. Non-archive masters
                                        // have no worker (`mat_job_tx` is None) and pull
                                        // materialized state from archives via the poller.
                                        if let Some(tx) = &mat_job_tx {
                                            if let Err(e) = tx.send((frame, app.frame_number)) {
                                                tracing::warn!(
                                                    error = %e,
                                                    frame = app.frame_number,
                                                    "materializer worker channel closed",
                                                );
                                            }
                                        }
                                    })
                                };

                                // When a state is incorporated into forks (before
                                // finalization), persist its frame as a candidate
                                // in the clock store so the leader can chain a
                                // rank+1 proposal on top of it via
                                // `prove_next_state` -> `get_global_clock_frame_candidate`.
                                let incorporated_hook: quil_engine::consensus_glue::IncorporatedStateHook = {
                                    let cs = sync_cs.clone();
                                    let cf_for_inc = sync_cf.clone();
                                    Arc::new(move |state| {
                                        let app = &state.state;
                                        // Freshest consensus-rank signal — incorporation
                                        // fires per proposal, ahead of finalization.
                                        cf_for_inc.observe_rank(app.rank);
                                        let header = quil_types::proto::global::GlobalFrameHeader {
                                            frame_number: app.frame_number,
                                            rank: app.rank,
                                            timestamp: app.timestamp,
                                            difficulty: app.difficulty,
                                            output: app.output.clone(),
                                            parent_selector: app.parent_selector.clone(),
                                            prover: app.prover.clone(),
                                            prover_tree_commitment: app.prover_tree_commitment.clone(),
                                            requests_root: app.requests_root.clone(),
                                            ..Default::default()
                                        };
                                        let frame = quil_types::proto::global::GlobalFrame {
                                            header: Some(header),
                                            requests: Vec::new(),
                                        };
                                        // No transaction context here — pass a
                                        // no-op transaction shim. The clock
                                        // store's candidate writer doesn't
                                        // require atomicity with anything else.
                                        struct NoTxn;
                                        impl quil_types::store::Transaction for NoTxn {
                                            fn get(&self, _: &[u8]) -> quil_types::error::Result<Option<Vec<u8>>> { Ok(None) }
                                            fn set(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn commit(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn delete(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn abort(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn new_iter(
                                                &self,
                                                _: &[u8],
                                                _: &[u8],
                                            ) -> quil_types::error::Result<Box<dyn quil_types::store::Iterator>> {
                                                Err(quil_types::error::QuilError::NotFound("noop".into()))
                                            }
                                            fn delete_range(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn as_any(&self) -> &dyn std::any::Any { self }
                                        }
                                        let no_txn = NoTxn;
                                        let cs_trait: &dyn quil_types::store::ClockStore = cs.as_ref();
                                        let identity = quil_crypto::poseidon::hash_bytes_to_32(&app.output)
                                            .map(hex::encode)
                                            .unwrap_or_else(|_| "<poseidon-failed>".into());
                                        match cs_trait.put_global_clock_frame_candidate(&frame, &no_txn) {
                                            Ok(()) => tracing::info!(
                                                frame = app.frame_number,
                                                rank = app.rank,
                                                identity = %identity,
                                                "persisted candidate frame",
                                            ),
                                            Err(e) => tracing::warn!(
                                                error = %e,
                                                frame = app.frame_number,
                                                rank = app.rank,
                                                identity = %identity,
                                                "failed to persist candidate frame",
                                            ),
                                        }
                                    })
                                };

                                // When the consumer observes a fresh QC (from
                                // local aggregation or wire receive), persist
                                // it to the clock store so the leader's
                                // `prove_next_state` for rank+1 finds the
                                // correct latest QC.
                                let qc_observed_hook: quil_engine::consensus_glue::QcObservedHook = {
                                    let cs = sync_cs.clone();
                                    Arc::new(move |qc| {
                                        // NoTxn shim — clock store's QC writer
                                        // doesn't require atomicity with
                                        // anything else here.
                                        struct NoTxn2;
                                        impl quil_types::store::Transaction for NoTxn2 {
                                            fn get(&self, _: &[u8]) -> quil_types::error::Result<Option<Vec<u8>>> { Ok(None) }
                                            fn set(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn commit(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn delete(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn abort(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
                                            fn new_iter(
                                                &self,
                                                _: &[u8],
                                                _: &[u8],
                                            ) -> quil_types::error::Result<Box<dyn quil_types::store::Iterator>> {
                                                Err(quil_types::error::QuilError::NotFound("noop".into()))
                                            }
                                            fn delete_range(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
                                            fn as_any(&self) -> &dyn std::any::Any { self }
                                        }
                                        // Build a proto QC from the trait
                                        // object's fields.
                                        let proto_qc = quil_types::proto::global::QuorumCertificate {
                                            filter: qc.filter().to_vec(),
                                            rank: qc.rank(),
                                            frame_number: qc.frame_number(),
                                            selector: qc.identity().clone(),
                                            timestamp: qc.timestamp(),
                                            aggregate_signature: Some(
                                                quil_types::proto::keys::Bls48581AggregateSignature {
                                                    signature: qc.aggregated_signature().signature().to_vec(),
                                                    public_key: Some(
                                                        quil_types::proto::keys::Bls48581g2PublicKey {
                                                            key_value: qc.aggregated_signature().public_key().to_vec(),
                                                        },
                                                    ),
                                                    bitmask: qc.aggregated_signature().bitmask().to_vec(),
                                                },
                                            ),
                                        };
                                        let no_txn = NoTxn2;
                                        let cs_trait: &dyn quil_types::store::ClockStore = cs.as_ref();
                                        if let Err(e) = cs_trait.put_quorum_certificate(&proto_qc, &no_txn) {
                                            tracing::debug!(
                                                error = %e,
                                                rank = qc.rank(),
                                                "failed to persist QC",
                                            );
                                        }
                                    })
                                };
                                // Load the persisted QC for the trusted
                                // root's rank so the pacemaker boots
                                // with a real BLS-aggregated QC instead
                                // of a zero-signature stub (which peers
                                // would reject on signature verify).
                                let trusted_rank_for_qc: u64 = genesis_frame
                                    .header
                                    .as_ref()
                                    .map(|h| h.rank)
                                    .unwrap_or(0);
                                // Genesis-QC identity for the global
                                // validator's rank-0 trust. Computed here,
                                // before `genesis_frame` is moved into the
                                // activation params below. `Some` only on a
                                // true cold start (bootstrap rank 0); `None`
                                // for a checkpoint-seeded chain so any
                                // rank-0 QC is rejected.
                                let genesis_qc_identity_for_validator: Option<Vec<u8>> =
                                    if trusted_rank_for_qc == 0 {
                                        genesis_frame
                                            .header
                                            .as_ref()
                                            .and_then(|h| {
                                                quil_crypto::poseidon::hash_bytes_to_32(&h.output).ok()
                                            })
                                            .map(|h| h.to_vec())
                                    } else {
                                        None
                                    };
                                let genesis_qc_override = {
                                    use quil_types::store::ClockStore;
                                    let cs_trait: &dyn ClockStore = sync_cs.as_ref();
                                    match cs_trait.get_quorum_certificate(&[], trusted_rank_for_qc) {
                                        Ok(qc_proto) => {
                                            info!(
                                                rank = qc_proto.rank,
                                                frame_number = qc_proto.frame_number,
                                                "seeding consensus with persisted QC",
                                            );
                                            Some(quil_engine::consensus_wire::QuorumCertificate::from_proto(&qc_proto))
                                        }
                                        Err(e) => {
                                            warn!(
                                                rank = trusted_rank_for_qc,
                                                error = %e,
                                                "no persisted QC at trusted rank — \
                                                 falling back to stub genesis QC \
                                                 (peers will reject embedded QC)",
                                            );
                                            None
                                        }
                                    }
                                };
                                match quil_engine::consensus_activation::activate_consensus(
                                    quil_engine::consensus_activation::ConsensusActivationParams {
                                        prover_registry: sync_pr.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
                                        frame_prover: sync_fp.clone(),
                                        difficulty_adjuster: sync_da.clone() as Arc<dyn quil_types::consensus::DifficultyAdjuster>,
                                        clock_store: sync_cs.clone() as Arc<dyn quil_types::store::ClockStore>,
                                        message_collector: sync_mc.clone(),
                                        local_prover_address: sync_pa.to_vec(),
                                        local_bls_pubkey: sync_bls_pub.clone(),
                                        bls_signer,
                                        // Must be the REAL KZG prover (not Noop):
                                        // the leader provider commits the global
                                        // requests tree through this to produce
                                        // `requests_root`. With Noop, any frame
                                        // whose request tree forms a branch
                                        // (≥2 messages) committed to 64 zero bytes,
                                        // so every non-trivial frame shipped a
                                        // zero requests_root. Verification uses the
                                        // CARRIED header value, so this is
                                        // self-consistent / not a fork.
                                        inclusion_prover: Arc::new(quil_crypto::KzgInclusionProver)
                                            as Arc<dyn quil_types::crypto::InclusionProver + Send + Sync>,
                                        // Drop protocol-invalid global messages
                                        // from the mempool at collect time
                                        // instead of re-proposing them until
                                        // they age out (Go liveness-provider
                                        // ValidateMessage + collector.Remove).
                                        message_validator: Some(sync_em.clone()),
                                        genesis_frame,
                                        publisher: Some(publisher),
                                        on_finalized_state: Some(finalized_hook),
                                        on_incorporated_state: Some(incorporated_hook),
                                        on_qc_observed: Some(qc_observed_hook),
                                        // Real catch-up trigger: wake the
                                        // proposal-catchup task when the engine
                                        // orphans a proposal (node is behind).
                                        // Cheap + sync-safe (just stores a permit).
                                        on_missing_parent: {
                                            let n = sync_catchup_notify.clone();
                                            std::sync::Arc::new(move || n.notify_one())
                                        },
                                        config_override: None,
                                        genesis_qc_override,
                                        // Persist consensus + liveness
                                        // state in the node's RocksDB so
                                        // finalized_rank / latest_qc
                                        // survive restarts (without this
                                        // a restart can re-vote for a
                                        // conflicting QC).
                                        kv_db: Some(sync_db_for_consensus.clone()),
                                    },
                                ) {
                                    Ok(activation) => {
                                        // Register the consensus event loop with the
                                        // supervisor BEFORE publishing the handle —
                                        // otherwise a panic in the loop leaves the
                                        // handle pointing at a dead task and we'd
                                        // never know. `Ok(())` here means the loop
                                        // exited cleanly via cancellation; anything
                                        // else (Err or panic) shuts the node down.
                                        let run_future = activation.run_future;
                                        spawner.detach("global-consensus-event-loop", async move {
                                            match run_future.await {
                                                Ok(()) => Ok(()),
                                                Err(e) => Err(anyhow::anyhow!(
                                                    "consensus event loop exited with error: {}", e
                                                )),
                                            }
                                        });
                                        if sync_ch.set(activation.handle).is_err() {
                                            warn!("consensus event loop already activated once");
                                        } else {
                                            // Publish VoteAggregation state so the
                                            // receive loop can feed ProposalVote +
                                            // proposal messages into the per-rank
                                            // collectors. Uses the same committee/
                                            // voting provider/vote domain built
                                            // inside activation to guarantee byte-
                                            // identical signature verification.
                                            let bls_ctor: Arc<dyn quil_types::crypto::BlsConstructor> =
                                                Arc::new(quil_crypto::Bls48581KeyConstructor);

                                            // Inbound-cert verifier.
                                            // Committee-aware so it can also verify the
                                            // proposer's own vote; the global chain signs
                                            // vote messages with an empty filter. Built
                                            // from the same committee + domains the
                                            // aggregators use, so peer-formed certs verify.
                                            let global_validator_instance = {
                                                let raw_agg: Arc<dyn quil_consensus::signature_aggregator::SignatureAggregator> =
                                                    Arc::new(quil_engine::bls_signature_aggregator::BlsSignatureAggregator::new(
                                                        bls_ctor.clone(),
                                                    ));
                                                let verifier = quil_engine::bls_verifier::BlsConsensusVerifier::new_with_committee(
                                                    raw_agg,
                                                    activation.vote_domain.clone(),
                                                    activation.timeout_domain.clone(),
                                                    activation.committee.clone()
                                                        as Arc<dyn quil_consensus::committee::Replicas>,
                                                    Vec::new(),
                                                );
                                                Arc::new(quil_engine::validator::ConsensusValidator::new(
                                                    activation.committee.clone()
                                                        as Arc<dyn quil_consensus::committee::Replicas>,
                                                    Arc::new(verifier),
                                                )
                                                .with_genesis_qc_identity(
                                                    genesis_qc_identity_for_validator.clone(),
                                                ))
                                            };

                                            let va = Arc::new(
                                                quil_engine::vote_aggregation::VoteAggregation::new(
                                                    activation.committee.clone(),
                                                    activation.voting_provider.clone(),
                                                    sync_ch.clone(),
                                                    bls_ctor.clone(),
                                                    activation.vote_domain.clone(),
                                                ),
                                            );
                                            let ta = Arc::new(
                                                quil_engine::timeout_aggregation::TimeoutAggregation::new(
                                                    activation.committee,
                                                    activation.voting_provider,
                                                    sync_ch.clone(),
                                                    bls_ctor,
                                                    activation.vote_domain,
                                                    activation.timeout_domain,
                                                ),
                                            );
                                            // Seed the aggregators' min_active_rank
                                            // to the bootstrap rank. Without this they
                                            // sit at 0 and the `rank > min + MAX_RANK_LOOKAHEAD`
                                            // guard drops every peer vote/timeout for a
                                            // chain that has already advanced more than
                                            // 1024 ranks past genesis — symptom: the
                                            // leader proposes, peers presumably vote, but
                                            // the aggregator silently discards every
                                            // vote and the chain perpetual-times-out.
                                            va.advance_min_active_rank(trusted_rank_for_qc);
                                            ta.advance_min_active_rank(trusted_rank_for_qc);
                                            info!(
                                                bootstrap_rank = trusted_rank_for_qc,
                                                "seeded vote + timeout aggregator min_active_rank",
                                            );
                                            let va_ok = sync_va.set(va).is_ok();
                                            let ta_ok = sync_ta.set(ta).is_ok();
                                            let gv_ok = sync_gv.set(global_validator_instance).is_ok();
                                            if va_ok && ta_ok && gv_ok {
                                                info!("consensus event loop started, handle + vote/timeout aggregators + validator published");
                                            } else {
                                                warn!(va_ok, ta_ok, gv_ok, "aggregators/validator already set");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "consensus activation failed");
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
                                match quil_rpc::ensure_prover_tree_incremental(
                                    addr, &seed,
                                    quil_types::proto::application::HypergraphPhaseSet::VertexAdds,
                                    sync_hg.clone(),
                                    &expected_root,
                                ).await {
                                    Ok(stats) => {
                                        if stats.leaves_pulled > 0 {
                                            info!(
                                                leaves_pulled = stats.leaves_pulled,
                                                match_ok = stats.commitments_match,
                                                "incremental prover tree sync complete"
                                            );
                                            // Refresh registry with updated data
                                            let pr = sync_pr.clone();
                                            let hs3 = sync_hg.clone();
                                            let _ = tokio::task::spawn_blocking(move || pr.refresh_from_store(&hs3)).await;

                                            // Compare reward balance for the
                                            // local prover before/after; log
                                            // when it changed so the operator
                                            // sees synced-in credits.
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
                                        } else {
                                            debug!("incremental sync: tree unchanged");
                                        }
                                        // Recovery path: if the initial sync at
                                        // startup failed (no archive reachable
                                        // yet, transient error), the lifecycle
                                        // gate stayed held. Unblock it now that
                                        // we have data.
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
            let seed_for_refresh = seed;
            let shards_store_for_refresh = shards_store.clone();
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
