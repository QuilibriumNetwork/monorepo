use std::sync::Arc;

use tracing::{debug, info, warn};

// Import KeyManager trait for get_signer
use quil_keys::KeyManager as _;

use quil_lifecycle::Supervisor;

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
        db_arc,
        frame_materializer,
        consensus_loopback_tx,
        peer_id,
        spawner,
    } = args;

    if let Some(seed) = mtls_seed {
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
            let sync_bls_pub = bls_pubkey.clone();
            let sync_pa = prover_address;
            let sync_crdt = crdt.clone();
            let sync_p2p = p2p_handle.clone();
            let sync_ch = consensus_handle.clone();
            let sync_va = vote_aggregator.clone();
            let sync_ta = timeout_aggregator.clone();
            let sync_cov = coverage_monitor.clone();
            let sync_cf = current_frame.clone();
            let sync_lhf = last_global_head_frame.clone();
            let sync_archive_mode = archive_mode;
            let sync_db_for_consensus: Arc<dyn quil_types::store::KvDb> = db_arc.clone();
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
                                let publisher: Arc<dyn quil_engine::consensus_glue::ConsensusPublisher> =
                                    Arc::new(crate::blossomsub_consensus_publisher::BlossomsubConsensusPublisher {
                                        p2p_handle: sync_p2p.clone(),
                                        loopback_tx: consensus_loopback_tx.clone(),
                                        self_peer_id: peer_id.to_bytes(),
                                        spawner: spawner.clone(),
                                    });
                                // Build an on-finalized hook that prunes per-rank
                                // aggregator state below the finalized watermark.
                                // Captures the OnceLocks so the callback stays valid
                                // even though the aggregators are populated later
                                // in this same activation (finalization can't fire
                                // before the event loop runs).
                                let finalized_hook: quil_engine::consensus_glue::FinalizedStateHook = {
                                    let va_cell = sync_va.clone();
                                    let ta_cell = sync_ta.clone();
                                    let cs_for_fin = sync_cs.clone();
                                    let cf_for_fin = sync_cf.clone();
                                    let lhf_for_fin = sync_lhf.clone();
                                    let materializer_for_fin = frame_materializer.clone();
                                    let cov_for_fin = sync_cov.clone();
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
                                        lhf_for_fin.fetch_max(
                                            app.frame_number,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );

                                        // Archive nodes materialize the
                                        // finalized global frame: commit the
                                        // hypergraph, verify the prover root,
                                        // process bundles through execution,
                                        // prune orphan joins, evict inactive
                                        // provers, persist alt-shard updates,
                                        // and publish the post-materialize
                                        // snapshot for workers + non-archive
                                        // peers to sync against. Non-archive
                                        // master threads skip this (their
                                        // `materializer_for_fin` is None);
                                        // they pull materialized state from
                                        // archives via the archive poller.
                                        if let Some(m) = &materializer_for_fin {
                                            // Refresh halt durations right
                                            // before materialize so the
                                            // eviction step inside skips
                                            // halted shards correctly.
                                            let halts = cov_for_fin.check(app.frame_number);
                                            m.set_coverage_halt_durations(halts);
                                            if let Err(e) = m.materialize(&frame) {
                                                tracing::warn!(
                                                    error = %e,
                                                    frame = app.frame_number,
                                                    "frame materialize failed"
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
                                    Arc::new(move |state| {
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
                                        inclusion_prover: Arc::new(quil_types::crypto::NoopInclusionProver)
                                            as Arc<dyn quil_types::crypto::InclusionProver + Send + Sync>,
                                        genesis_frame,
                                        publisher: Some(publisher),
                                        on_finalized_state: Some(finalized_hook),
                                        on_incorporated_state: Some(incorporated_hook),
                                        on_qc_observed: Some(qc_observed_hook),
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
                                            if va_ok && ta_ok {
                                                info!("consensus event loop started, handle + vote/timeout aggregators published");
                                            } else {
                                                warn!(va_ok, ta_ok, "aggregators already set");
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
