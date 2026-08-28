use std::sync::Arc;

use tracing::{info, warn};

use quil_lifecycle::Supervisor;

pub(crate) struct LifecycleHandles {
    pub worker_allocator: Arc<quil_engine::worker_allocator::WorkerAllocator>,
    pub prover_lifecycle: Arc<quil_engine::provers::lifecycle::ProverLifecycle>,
    pub frame_materializer: Option<Arc<quil_engine::frame_materializer::FrameMaterializer>>,
}

pub(crate) struct LifecycleInitArgs {
    pub config: quil_config::Config,
    pub network: u8,
    pub archive_mode: bool,
    pub worker_manager: Arc<dyn quil_engine::worker::WorkerManager>,
    pub prover_registry: Arc<quil_execution::SharedProverRegistry>,
    pub prover_address: [u8; 32],
    pub halt_state: Arc<quil_engine::halt_state::HaltState>,
    pub current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
    pub last_global_head_frame: Arc<std::sync::atomic::AtomicU64>,
    pub shards_store: Arc<dyn quil_types::store::ShardsStore>,
    pub exec_manager: Arc<quil_execution::ExecutionEngineManager>,
    pub frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    pub inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    pub clock_store: Arc<quil_store::RocksClockStore>,
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
}

pub(crate) fn init(
    sup: &mut Supervisor<anyhow::Error>,
    args: LifecycleInitArgs,
) -> LifecycleHandles {
    let LifecycleInitArgs {
        config,
        network,
        archive_mode,
        worker_manager,
        prover_registry,
        prover_address,
        halt_state,
        current_frame,
        last_global_head_frame,
        shards_store,
        exec_manager,
        frame_prover,
        inclusion_prover,
        clock_store,
        crdt,
        hg_store,
    } = args;

    // Worker allocator — reconciles registry vs running workers
    let worker_allocator = Arc::new(quil_engine::worker_allocator::WorkerAllocator::new(
        worker_manager.clone(),
        prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        prover_address.to_vec(),
    ));

    // Compute the config-derived seniority estimate from the mainnet
    // compat table. Uses our local libp2p peer ID plus any peer IDs
    // derived from the configs listed in
    // `engine.multisig_prover_enrollment_paths`. Result is cached on
    // the allocator; lifecycle consults it when deciding whether a
    // seniority merge would raise our on-chain seniority. Computed
    // only on mainnet (P2P.Network == 0).
    if config.p2p.network == 0 {
        let mut peer_ids: Vec<String> = Vec::new();
        let pk_bytes = hex::decode(&config.p2p.peer_priv_key).unwrap_or_default();
        if pk_bytes.len() >= 57 {
            let mut seed = [0u8; 57];
            seed.copy_from_slice(&pk_bytes[..57]);
            let pubkey = quil_p2p::ed448_identity::derive_public_key(&seed);
            let peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&pubkey);
            peer_ids.push(bs58::encode(&peer_id).into_string());
        }
        for extra_path in &config.engine.multisig_prover_enrollment_paths {
            let path = std::path::PathBuf::from(extra_path);
            match quil_config::load_config(&path) {
                Ok(extra_cfg) => {
                    if let Ok(bytes) = hex::decode(&extra_cfg.p2p.peer_priv_key) {
                        if bytes.len() >= 57 {
                            let mut seed = [0u8; 57];
                            seed.copy_from_slice(&bytes[..57]);
                            let pubkey = quil_p2p::ed448_identity::derive_public_key(&seed);
                            let peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&pubkey);
                            peer_ids.push(bs58::encode(&peer_id).into_string());
                        }
                    }
                }
                Err(e) => warn!(
                    path = %extra_path,
                    error = %e,
                    "could not load multisig prover enrollment config"
                ),
            }
        }
        let estimate = quil_execution::seniority_compat::get_aggregated_seniority(&peer_ids);
        worker_allocator.set_config_seniority_estimate(estimate);
        info!(
            local_peer_ids = peer_ids.len(),
            aggregated_seniority = estimate,
            "computed config-derived seniority estimate"
        );
    }

    // Proactive worker allocation reconcile — fire as soon as the
    // background prover registry refresh has data, independent of
    // any archive sync. This is the path that pulls workers out of
    // "filter pinned, consensus deferred" state on startup based on
    // the LOCALLY persisted prover registry, rather than waiting
    // for the first global frame to arrive from the archive poller
    // (which can take 5+ minutes during PeerInfo discovery).
    //
    // Archive nodes don't host app-shard workers, so skip the call
    // there — matches the gate inside the archive poller.
    if !archive_mode {
        let wa_for_init = worker_allocator.clone();
        let pr_for_init = prover_registry.clone();
        let lhf_for_init = last_global_head_frame.clone();
        sup.spawn_startup_task("early-worker-reconcile", move |token_for_init| async move {
            // The background refresh at startup is spawn_blocking and
            // typically finishes in well under a second. Poll up to
            // ~5s for `distinct_provers() > 0`; on a fresh node with
            // an empty registry this just gives up silently and the
            // archive-poller path picks it up later.
            for _ in 0..50 {
                if token_for_init.is_cancelled() { return Ok(()); }
                let count = pr_for_init.read(|r| r.distinct_provers());
                if count > 0 { break; }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            let frame = lhf_for_init.load(std::sync::atomic::Ordering::Relaxed);
            if frame > 0 {
                if let Err(e) = wa_for_init.on_new_frame(frame) {
                    warn!(
                        error = %e,
                        frame,
                        "early worker reconcile failed"
                    );
                } else {
                    info!(frame, "early worker reconcile complete (off local registry)");
                }
            }
            Ok(())
        });
    }

    // Prover lifecycle coordinator — evaluates join/confirm/leave on each frame.
    // Pulls cooldown state off the WorkerAllocator (single source of truth).
    let reward_greedy = config.engine.reward_strategy == "reward-greedy";
    let strategy = if reward_greedy {
        quil_engine::provers::proposer::Strategy::RewardGreedy
    } else {
        quil_engine::provers::proposer::Strategy::DataGreedy
    };
    let lifecycle_inner = quil_engine::provers::lifecycle::ProverLifecycle::new(
        prover_address.to_vec(),
        worker_allocator.clone(),
        halt_state.clone(),
        current_frame.clone(),
        strategy,
    );
    // Testnet/devnet bootstraps drop the join-confirm window from
    // mainnet's 360 frames (one hour at 10s/frame) to a handful of
    // frames so a local smoke test sees a join → confirm cycle in
    // a couple of minutes. Mainnet (network = 0) keeps the full
    // 360-frame protocol value.
    // CLI `--network` is the source of truth — the YAML's `p2p.network`
    // is left at 0 in our test configs because the same files are used
    // for mainnet runs. Use the run-time-supplied `network` arg so a
    // single config file can be reused across networks.
    if network != 0 {
        const TESTNET_CONFIRM_WINDOW_FRAMES: u64 = 10;
        lifecycle_inner.set_confirm_window_frames(TESTNET_CONFIRM_WINDOW_FRAMES);
        // Keep the worker reestablish cutoff in lockstep: a recovered
        // Leaving allocation is reestablished only while within the
        // confirm window, then handed to the lifecycle to confirm.
        worker_allocator.set_confirm_window_frames(TESTNET_CONFIRM_WINDOW_FRAMES);
        // The lifecycle setting controls *when the local node submits*
        // a Confirm. The materializer's `validate_confirm_timing`
        // independently enforces that the recipient ledger has waited
        // long enough — its default (360..720) is mainnet-correct. For
        // testnet we have to override that window too, otherwise every
        // submitted Confirm is rejected as "must wait 360 frames after
        // join" until 360 frames have elapsed (an hour) — exactly the
        // wait the lifecycle override is meant to avoid.
        quil_execution::global_intrinsic::verify::set_confirm_window_frames(
            TESTNET_CONFIRM_WINDOW_FRAMES,
            // Use a generous upper bound so a slow follower can still
            // confirm before the window expires.
            TESTNET_CONFIRM_WINDOW_FRAMES * 72, // 720 ÷ 360 × 10 = 20 → 720
        );
        info!(
            network,
            confirm_window_frames = TESTNET_CONFIRM_WINDOW_FRAMES,
            "testnet/devnet: using shortened prover confirm window",
        );
    }
    let prover_lifecycle = Arc::new(lifecycle_inner);
    // Wire the shards store so `evaluate` can discover shards that
    // have no allocations yet — calls `RangeAppShards` on the local
    // store.
    prover_lifecycle.set_shards_store(
        shards_store.clone() as Arc<dyn quil_types::store::ShardsStore>,
    );

    // Per the architecture: archives materialize global frames;
    // workers materialize app-shard frames (a separate path);
    // non-archive masters only consume the materialized state via
    // sync from archives and do not materialize themselves.
    //
    // Archive nodes get the FrameMaterializer (the canonical
    // post-finalize processor: commits the hypergraph, verifies the
    // prover root, processes message bundles, prunes orphan joins,
    // evicts inactive provers, persists alt-shard updates, publishes
    // post-materialize snapshots) plus the full frame-header deps on
    // the intrinsic so `invoke_frame_header` mutates state on
    // shard-coverage ingest (LastActiveFrameNumber advance + reward
    // distribution). That full install already wires `frame_prover`.
    //
    // Non-archive masters install only `frame_prover` — the minimum
    // their archive-poller path needs so `process_global_frame` →
    // `validate_message` → the intrinsic's `TYPE_PROVER_JOIN` arm
    // doesn't fail closed with "frame_prover not installed".
    let reward_issuer: Arc<dyn quil_types::consensus::RewardIssuance> =
        Arc::new(quil_engine::OptRewardIssuance);
    if archive_mode {
        let bls_for_intrinsic: Arc<dyn quil_types::crypto::BlsConstructor> =
            Arc::new(quil_crypto::FalconKeyConstructor);
        exec_manager.install_global_frame_header_deps(
            prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
            reward_issuer.clone(),
            bls_for_intrinsic,
            inclusion_prover.clone(),
            frame_prover.clone(),
        ).expect("failed to install global frame header dependencies");
    } else {
        exec_manager.install_global_frame_prover(frame_prover.clone()).expect("failed to install global frame prover");
    }
    let frame_materializer: Option<Arc<quil_engine::frame_materializer::FrameMaterializer>> =
        if archive_mode {
            let m = quil_engine::frame_materializer::FrameMaterializer::new(
                exec_manager.clone(),
                prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
                clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
                crdt.clone(),
                hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
                reward_issuer,
                prover_address.to_vec(),
                archive_mode,
            )
            .with_eviction_registry(prover_registry.clone())
            .with_rocks_hg_store(hg_store.clone())
            // (B/#2) At-cutover consolidation on the archive's CRDT store: fold
            // every split app's per-sub-shard trees into its app.l2 tree from
            // current committed vertices before the unified flip, so a split in
            // the [boot, cutover) window is reflected. Deterministic (same frame,
            // same committed state on every archive).
            .with_unified_cutover_consolidate({
                let hg = hg_store.clone();
                let ss = shards_store.clone();
                std::sync::Arc::new(move |frame: u64| -> bool {
                    match quil_forest_migrate::run_unified_consolidation_in_place(
                        hg.as_ref(),
                        ss.as_ref(),
                        0,
                        frame,
                    ) {
                        Ok(n) => {
                            tracing::info!(
                                apps = n,
                                frame,
                                "archive at-cutover unified consolidation complete"
                            );
                            true
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                frame,
                                "archive at-cutover unified consolidation FAILED"
                            );
                            false
                        }
                    }
                })
            })
            // Prover-tree reset rides the same cutover flag day (archive only):
            // wipe the global prover shard + rebuild from the network's genesis
            // committee, so provers stranded on alias sub-shards are cleared and
            // re-join onto the reset grid. The committee is resolved once
            // (network-aware); the reset is deterministic across archives.
            .with_prover_tree_reset({
                let hg = crdt.clone();
                let store = hg_store.clone();
                let net = network;
                let seed = config.engine.genesis_seed.clone();
                // The local Falcon prover pubkey is only consulted by the testnet
                // EMPTY-seed single-prover fallback; mainnet uses the embedded
                // genesis and a seeded testnet/localnet uses the seed keys, so `&[]`
                // suffices here.
                std::sync::Arc::new(move |frame: u64| -> bool {
                    // Three coordinated resets ride this hook: v1 boot cutover, v2
                    // grid reset (740_000), and v3 prover reset (747_000). Each has
                    // its OWN marker so re-wiping never deletes provers that
                    // re-joined after, and an earlier marker never suppresses a later
                    // reset.
                    let is_v4 = frame
                        == quil_execution::global_intrinsic::materialize::quil_prover_reset_v4_frame();
                    let is_v3 = frame
                        == quil_execution::global_intrinsic::materialize::quil_prover_reset_v3_frame();
                    let is_v2 = frame
                        == quil_execution::global_intrinsic::materialize::quil_grid_reset_v2_frame();
                    if is_v4 {
                        if crate::unified_consolidation::prover_reset_v4_applied(&store) {
                            return true;
                        }
                    } else if is_v3 {
                        if crate::unified_consolidation::prover_reset_v3_applied(&store) {
                            return true;
                        }
                    } else if is_v2 {
                        if crate::unified_consolidation::grid_reset_v2_applied(&store) {
                            return true;
                        }
                    } else if crate::unified_consolidation::boot_reset_applied(&store) {
                        return true;
                    }
                    match quil_engine::genesis::reset_prover_tree_to_genesis(
                        &hg, store.as_ref(), frame, net, &seed, &[],
                    ) {
                        Ok(n) => {
                            tracing::info!(seeded = n, frame, is_v2, is_v3, is_v4, "archive at-reset prover-tree reset complete");
                            if is_v4 {
                                crate::unified_consolidation::mark_prover_reset_v4_applied(&store);
                            } else if is_v3 {
                                crate::unified_consolidation::mark_prover_reset_v3_applied(&store);
                            } else if is_v2 {
                                crate::unified_consolidation::mark_grid_reset_v2_applied(&store);
                            }
                            true
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, frame, "archive at-reset prover-tree reset FAILED");
                            false
                        }
                    }
                })
            })
            // Deterministic per-shard data-size source for the eviction
            // halt gate: enumerate committed shards from the shards store
            // and key by `confirmation_filter` = L2(32) ++ prefix-byte
            // (strip the leading L1(3) from shard_key) — exactly how the
            // registry/worker-allocator key filters. Every archive derives
            // the same map from the same committed frames, so eviction is
            // consensus-deterministic. Empty (size==0) shards are thereby
            // excluded from suppressing eviction.
            .with_shard_size_source({
                let ss = shards_store.clone();
                std::sync::Arc::new(move || {
                    let mut out: std::collections::HashMap<Vec<u8>, u64> =
                        std::collections::HashMap::new();
                    if let Ok(shards) = ss.range_app_shards() {
                        for s in shards {
                            let l2_start = if s.shard_key.len() >= 3 { 3 } else { 0 };
                            // Canonical prefix → filter (sentinel-aware).
                            let filter = quil_forest::shard_prefix_to_filter(
                                &s.shard_key[l2_start..],
                                &s.prefix,
                            );
                            if filter.is_empty() {
                                continue;
                            }
                            // `size` is a big-endian byte count; we only need
                            // "has any data" → record 1 when non-zero.
                            let has_data = s.size.iter().any(|&b| b != 0);
                            out.insert(filter, if has_data { 1 } else { 0 });
                        }
                    }
                    out
                })
            })
            .with_current_frame(current_frame.clone())
            // MAINNET-ONLY 2.1.0.25 frozen-era recovery: no-op-materialize the
            // frozen range so the wedged fleet un-sticks deterministically. Off
            // on localnet/testnet, which never reach these heights anyway.
            .with_frozen_era_recovery(network == 0)
            // Same `frame_prover` Arc installed into the intrinsic above, so
            // the batch-preverified set the materializer records is the one
            // `verify_frame_header_signature` reads. BLS constructor is
            // stateless (the set lives on the frame prover), so a fresh one
            // is equivalent.
            .with_bls_batch_verify(
                frame_prover.clone(),
                Arc::new(quil_crypto::FalconKeyConstructor)
                    as Arc<dyn quil_types::crypto::BlsConstructor>,
            );
            Some(Arc::new(m))
        } else {
            None
        };

    LifecycleHandles {
        worker_allocator,
        prover_lifecycle,
        frame_materializer,
    }
}
