use std::sync::Arc;

use tracing::{info, warn};

use super::storage::StorageHandles;

pub(crate) struct EngineHandles {
    pub inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub exec_manager: Arc<quil_execution::ExecutionEngineManager>,
}

pub(crate) fn init_engines(storage: &StorageHandles, network: u8) -> EngineHandles {
    // ---------------------------------------------------------------
    // 3. Create execution engines with full crypto verification
    // ---------------------------------------------------------------
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
        Arc::new(quil_tries::ShaInclusionProver);
    let key_manager: Arc<dyn quil_types::crypto::KeyManager> =
        Arc::new(quil_crypto::DefaultKeyManager::new());
    // CRDT backed by RocksDB for real persistence
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        storage.hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover.clone(),
    ));
    // Phase-3: commit global-consensus state into the JMT forest. Install the
    // persistent forest when the DB is migrated OR brand-new/fresh (a new
    // forest-native node builds on the persistent forest from genesis instead of
    // the ephemeral in-memory default). A store with un-migrated legacy state
    // (committed frames, no forest) is skipped — it must run `--migrate-db`.
    let store_is_fresh = storage
        .clock_store
        .get_latest_frame_number()
        .map(|n| n == 0)
        .unwrap_or(true);
    // Mainnet (network 0) uses the fixed 64-way QUIL grid (migration/state-root
    // legacy); testnet/devnet treats QUIL like every other app — a single shard
    // that splits dynamically.
    if quil_forest_migrate::install_forest_boot(
        crdt.as_ref(),
        storage.hg_store.as_ref(),
        store_is_fresh,
        network == 0,
    ) {
        tracing::info!("Phase-3 JMT forest installed on global CRDT — state commits to the forest");
    }
    // Seed the forest Merkle-sum size index ONCE (marker-gated), BEFORE the first
    // `rebucket_app` — which fires immediately below in `refresh_crdt_shard_prefixes`
    // whenever a split landed while this node was down (the post-split grid loaded
    // from the shards store TRANSITIONS the app's prefix set → re-partition). With a
    // cold index that boot rebucket cold-walks the whole app tree (121M leaves) — the
    // multi-hour boot stall that wedged the fleet at the epoch-1084 split. The index
    // is maintained at write time thereafter (`quil_forest::batch_size_sums`), so this
    // is the ONLY full walk this DB ever does; subsequent boots skip it via the marker.
    {
        let mut seed_apps: Vec<[u8; 32]> = Vec::new();
        if let Ok(rows) = storage.shards_store.range_app_shards() {
            let mut seen = std::collections::HashSet::new();
            for s in rows {
                if s.shard_key.len() == 35 {
                    let mut l2 = [0u8; 32];
                    l2.copy_from_slice(&s.shard_key[3..35]);
                    if seen.insert(l2) {
                        seed_apps.push(l2);
                    }
                }
            }
        }
        let t = std::time::Instant::now();
        match crdt.warm_size_index(&seed_apps) {
            Ok(true) => info!(
                apps = seed_apps.len(),
                ms = t.elapsed().as_millis() as u64,
                "size-index backfill complete (one-time; kept warm by write-time maintenance)"
            ),
            Ok(false) => {} // already seeded (marker present) — silent
            Err(e) => tracing::warn!(error = %e, "warm_size_index (size-index backfill) failed"),
        }
    }
    // Set the unified-tree gate BEFORE the first rebucket below. `refresh_crdt_shard_prefixes`
    // rebuckets any app whose loaded (post-split) grid differs from the in-memory default, and
    // `forest_app_buckets` falls back to the O(all-leaves) `scan_app_buckets` while `unified_tree()`
    // is false. That flag is otherwise only set later in `boot_consolidate_and_gate`, so a
    // post-split boot would cold-scan the whole app tree here — defeating the seed above and
    // re-wedging the archive. An already-consolidated, past-cutover node activates unified now so
    // this rebucket uses the O(depth) seeded forest index. (A non-consolidated node stays legacy
    // here and is gated normally by `boot_consolidate_and_gate`.)
    if std::env::var("QUIL_DISABLE_UNIFIED").is_err() {
        crate::unified_consolidation::pre_gate_unified_if_consolidated(
            &storage.hg_store,
            storage.clock_store.as_ref(),
            crdt.as_ref(),
        );
    }
    // Feed the CRDT each app's REAL shard-prefix set from the shards store so
    // `commit_inner` aggregates the actual (possibly non-uniform, dynamically
    // split) shard set — not just the uniform QUIL default from
    // `install_forest_boot`. Empty store (pre-genesis) → the QUIL default stands.
    // Re-run each frame by the poller so a mid-run split (applied at an epoch
    // boundary) is picked up deterministically on every node. With the size index
    // now seeded (above) AND unified pre-gated, a post-split re-partition here is
    // O(shards×depth), not a walk.
    let populated =
        refresh_crdt_shard_prefixes(crdt.as_ref(), storage.shards_store.as_ref());
    if populated > 0 {
        info!(apps = populated, "populated CRDT shard-prefix sets from shards store");
    }
    // Pre-create the lazy tree for the global prover shard so the
    // first commit materializes its root. Without this, migrated
    // stores skip the shard and the sync server returns None for the
    // tree blob.
    crdt.ensure_all_phase_trees(&quil_types::store::ShardKey {
        l1: [0u8; 3],
        l2: [0xffu8; 32],
    });
    info!("global prover shard primed in CRDT phase_sets");

    // Same prime for every app shard the local shards-store knows
    // about. Without this, the QUIL-token shard's lazy trees never
    // get inserted into `phase_sets` (no in-process mutation happens
    // on a freshly migrated store), so `phase_set_metadata_at_path`
    // returns `None` for every prefix and `GetAppShards` reports
    // `size=0` + zero commitments to remote pollers. Their lifecycle
    // then drops every candidate in `build_proposal_descriptors` and
    // no `ProposeJoin` ever fires. All four phase sets are primed
    // because remote callers verify commitments across all phases,
    // not just vertex_adds.
    // Hoisted out of the prime block below so the size-index backfill (run
    // after the unified-tree flag is set) can reuse the same app list.
    let mut committed_apps: Vec<[u8; 32]> = Vec::new();
    {
        let mut primed_keys: std::collections::HashSet<Vec<u8>> =
            std::collections::HashSet::new();
        let mut primed_count = 0usize;
        if let Ok(shards) = storage.shards_store.range_app_shards() {
            for s in shards {
                if s.shard_key.len() != 35 {
                    continue;
                }
                if !primed_keys.insert(s.shard_key.clone()) {
                    continue;
                }
                let mut l1 = [0u8; 3];
                l1.copy_from_slice(&s.shard_key[..3]);
                let mut l2 = [0u8; 32];
                l2.copy_from_slice(&s.shard_key[3..35]);
                crdt.ensure_all_phase_trees(&quil_types::store::ShardKey { l1, l2 });
                committed_apps.push(l2);
                primed_count += 1;
            }
        }
        info!(shards = primed_count, "app shards primed in CRDT phase_sets");
    }
    // NOTE: the per-sub-shard live-size baseline (`warm_sizes`) is seeded below,
    // AFTER the unified-tree flag is set and AFTER the size-index backfill — so
    // that if `warm_sizes` has to recompute buckets from the forest (a shard-set
    // change since the persisted cache, e.g. a split landed just before a
    // restart), the Merkle-sum size index it reads is already warm and the
    // recompute is O(shards×depth), not a cold O(all-leaves) walk.

    // UNIFIED_APP_TREE cutover: run the one-time split→app-tree consolidation (a
    // no-op after the first boot, via a persisted marker) and set the CRDT's
    // unified-tree flag from the head frame. The per-frame flip at exactly
    // `UNIFIED_TREE_CUTOVER_FRAME` is handled by `gate_unified_at_frame` on the
    // commit paths; this boot call gets a node that starts up already past the
    // cutover into unified mode immediately.
    // DEV: `QUIL_DISABLE_UNIFIED=1` skips the boot consolidation entirely (used to
    // A/B a fully-inert baseline — pair with a high cutover so the per-frame flip
    // never fires either).
    if std::env::var("QUIL_DISABLE_UNIFIED").is_err() {
        crate::unified_consolidation::boot_consolidate_and_gate(
            &storage.hg_store,
            storage.shards_store.as_ref(),
            storage.clock_store.as_ref(),
            crdt.as_ref(),
        );
    }
    // Seed the per-sub-shard live-size buckets from the committed baseline ONCE,
    // before any frame is processed — the world-size denominator + per-sub-shard
    // reward `state_size` are Σ of these live buckets, and migrated coins never
    // passed through `add_vertex`, so without this they'd be omitted. Steady-state
    // growth is then tracked incrementally. Runs AFTER the size-index backfill so
    // any forest recompute here reads a warm index (see the note above).
    info!(apps = committed_apps.len(), "seeding per-sub-shard live-size baseline (one-time; persisted after)");
    if let Err(e) = crdt.warm_sizes(&committed_apps) {
        tracing::warn!(error = %e, "warm_sizes (live-size baseline) failed");
    } else {
        info!(apps = committed_apps.len(), "seeded per-sub-shard live-size baseline");
    }
    // Eagerly run one commit at startup so the per-shard tree blob
    // lands at `[0x2F, vertex, adds, {l1=[0;3], l2=[0xff;32]}]`
    // before any sync probe arrives. Without an eager commit the
    // tree blob isn't written until the first finalized frame is
    // materialized, leaving an interval (sometimes several minutes
    // on the seed nodes) where non-archive peers receive
    // "no tree data available" and fall into perpetual fresh-sync
    // retries.
    match crdt.commit(0) {
        Ok(commits) => {
            let global_shard = quil_types::store::ShardKey {
                l1: [0u8; 3],
                l2: [0xffu8; 32],
            };
            let root_hex = commits
                .get(&global_shard)
                .and_then(|p| p.first())
                .map(|r| hex::encode(r))
                .unwrap_or_else(|| "<no root>".into());
            info!(
                shards = commits.len(),
                global_prover_root = %root_hex,
                "primed hypergraph tree blobs at startup",
            );
        }
        Err(e) => warn!(error = %e, "startup hypergraph commit failed"),
    }
    // ExecutionEngineManager::new takes the crypto + store provider set
    // as mandatory inputs. The decaf448 bulletproof/decaf providers are
    // retired (the confidential-value path is now lattice-CT); the circuit
    // compiler isn't wired to a real impl yet, so it stays a noop stub.
    let circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler> =
        Arc::new(quil_execution::testing::NoopCircuitCompiler);
    let clock_store_for_exec: Arc<dyn quil_types::store::ClockStore> =
        storage.clock_store.clone();
    // Hypergraph engine requires a config resolver. A real resolver
    // would look up the HypergraphDeploy config vertex for each
    // domain; that materialization isn't wired yet, so we use the
    // fail-closed noop (returns None → AuthCheck::UnknownDomain →
    // engine rejects all hypergraph write ops). Swap in a real
    // resolver once the deploy materialization lands.
    let hypergraph_resolver: Arc<dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver> =
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
    // Wire the shard stores so the global intrinsic's shard split/merge ops
    // actually record `PendingShardChange` and apply the topology flip at E+2.
    // Without these, proposed splits validate + "succeed" but never take effect,
    // so overcrowded shards stay overcrowded and provers re-propose every frame.
    let exec_manager = Arc::new(quil_execution::ExecutionEngineManager::new_with_shards(
        inclusion_prover.clone(),
        key_manager.clone(),
        crdt.clone(),
        circuit_compiler,
        clock_store_for_exec,
        hypergraph_resolver,
        true,
        Some(storage.shards_store.clone()),
        Some(storage.db_arc.clone() as Arc<dyn quil_types::store::KvDb>),
    ));
    info!("execution engines initialized with BLS48-581 + Ed448 signature verification");

    EngineHandles {
        inclusion_prover,
        crdt,
        exec_manager,
    }
}

pub(crate) fn bootstrap_genesis(
    network: u8,
    config: &quil_config::Config,
    storage: &StorageHandles,
    engines: &EngineHandles,
    bls_pubkey: &[u8],
) -> anyhow::Result<()> {
    // 3b. Genesis bootstrap (mainnet + testnet/devnet). Idempotent:
    // skips if the genesis frame already exists.
    let clock_store_dyn: &dyn quil_types::store::ClockStore = storage.clock_store.as_ref();
    if network == 0 {
        info!("bootstrapping mainnet genesis frame");
        match quil_engine::genesis::initialize_genesis_state(
            clock_store_dyn,
            storage.shards_store.as_ref() as &dyn quil_types::store::ShardsStore,
            &engines.crdt,
            engines.inclusion_prover.as_ref(),
        ) {
            Ok((frame, _qc)) => {
                let fn_ = frame
                    .header
                    .as_ref()
                    .map(|h| h.frame_number)
                    .unwrap_or(0);
                info!(frame_number = fn_, "mainnet genesis ready");
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to initialize mainnet genesis: {}",
                    e
                ));
            }
        }
    }
    if network != 0 && clock_store_dyn.get_global_clock_frame(0).is_err() {
        info!(
            network = network,
            "bootstrapping testnet/devnet genesis frame"
        );
        let genesis_seed = &config.engine.genesis_seed;
        match quil_engine::genesis::initialize_testnet_genesis_state(
            network,
            genesis_seed,
            bls_pubkey,
            0, // difficulty=0 triggers DEFAULT_TESTNET_DIFFICULTY
            clock_store_dyn,
            storage.shards_store.as_ref() as &dyn quil_types::store::ShardsStore,
            &engines.crdt,
            engines.inclusion_prover.as_ref(),
        ) {
            Ok((frame, _qc)) => {
                let fn_ = frame
                    .header
                    .as_ref()
                    .map(|h| h.frame_number)
                    .unwrap_or(0);
                info!(
                    frame_number = fn_,
                    "testnet genesis established"
                );
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to initialize testnet genesis: {}",
                    e
                ));
            }
        }
    }
    Ok(())
}

/// Feed the CRDT each app's REAL shard-prefix set from the shards store, so
/// `commit_inner` aggregates the actual (possibly non-uniform, dynamically
/// split) shard set rather than the uniform QUIL default. Groups `ShardInfo`
/// rows by app address (`shard_key[3..35]`); `set_app_shard_prefixes` resolves
/// the QUIL-vs-split-marker prefix overload via canonical bit-paths. Returns the
/// number of apps populated (0 = empty store ⇒ the QUIL default stands). Called
/// at engine init AND every frame by the poller, so a mid-run split (applied at
/// an epoch boundary, written to the shards store there) is reflected in the
/// committed state root deterministically on every node — no restart needed.
pub(crate) fn refresh_crdt_shard_prefixes(
    crdt: &quil_hypergraph::HypergraphCrdt,
    shards_store: &dyn quil_types::store::ShardsStore,
) -> usize {
    let rows = match shards_store.range_app_shards() {
        Ok(r) => r,
        Err(_) => return 0,
    };
    let mut by_app: std::collections::HashMap<[u8; 32], Vec<Vec<u32>>> =
        std::collections::HashMap::new();
    for row in rows {
        if row.shard_key.len() >= 35 {
            let mut l2 = [0u8; 32];
            l2.copy_from_slice(&row.shard_key[3..35]);
            by_app.entry(l2).or_default().push(row.prefix);
        }
    }
    let app_count = by_app.len();
    for (app, prefixes) in by_app {
        // A `true` return means the app's registered shard set just TRANSITIONED
        // (a split/merge landed this frame) — re-partition its size buckets so the
        // pre-split data (stranded in the now-removed parent bucket) is re-attributed
        // to the new leaves. Without this a freshly-created deep-split leaf reads
        // size 0 and provers churn, proposing to "leave" the data-bearing child.
        // Deterministic: every node sees the change at the same frame (the shards
        // store is written at the E+2 flip on all nodes) and rescans identical
        // committed state.
        // NOTE: this only fires where `app_prefixes` actually TRANSITIONS — which
        // today means nodes that run `apply_due_shard_changes` into their local
        // shards_store (archives, via the FrameMaterializer). Regular nodes don't
        // apply splits locally (no materializer), so their shards_store stays
        // single-shard and this stays inert on them until that gap is closed —
        // see the size-bucket note in shard_data_migration_design.
        if crdt.set_app_shard_prefixes(app, prefixes) {
            // Log BEFORE the rebucket so a slow one isn't silent. `unified` tells which
            // path it takes: true ⇒ O(depth) forest size index; false ⇒ the O(all-leaves)
            // `scan_app_buckets` fallback (the multi-hour cold walk to avoid at boot).
            let t = std::time::Instant::now();
            info!(
                app = %hex::encode(app),
                unified = crdt.unified_tree(),
                "shard set changed (split/merge) — re-partitioning size buckets…"
            );
            if let Err(e) = crdt.rebucket_app(&app) {
                warn!(
                    app = %hex::encode(app),
                    error = %e,
                    "refresh_crdt_shard_prefixes: rebucket_app failed after shard-set change"
                );
            } else {
                info!(
                    app = %hex::encode(app),
                    ms = t.elapsed().as_millis() as u64,
                    "shard set changed (split/merge) — re-partitioned size buckets"
                );
            }
        }
    }
    app_count
}

/// Re-prime + eagerly commit the app-shard phase trees AFTER genesis bootstrap.
///
/// `init_engines` primes the CRDT from the shards store, but it runs BEFORE
/// `bootstrap_genesis` — so any shard that genesis itself creates (e.g. the
/// seeded QUIL shard under `QUIL_SEED_SHARD_DATA`, or the genesis-registered QUIL
/// token sub-shards) is invisible at prime time (`range_app_shards()` is still
/// empty → the earlier priming logged `shards:0`). The consequence is a
/// CONSENSUS-BREAKING non-determinism: the seeded shard's committed vertex-adds
/// root only materializes into the forest lazily during early-frame processing,
/// so `compute_shard_root` returns ZERO at one moment and the real root moments
/// later. The leader reads the stale-zero root at propose time while verifiers
/// read the materialized non-zero root — every proposal is nullified and the
/// app-shard CW churns views (leaking a 1MiB journal buffer per view).
///
/// Running the SAME prefix-population + phase-tree prime + eager `commit(0)` a
/// second time here — now that genesis has registered the shard — makes
/// `compute_shard_root` return the committed root deterministically from frame 1
/// (mat=0) on every node, so leader and verifier agree. Idempotent: on stores
/// with no genesis-created shards it's a cheap no-op (mirrors `init_engines`).
pub(crate) fn reprime_after_genesis(
    crdt: &quil_hypergraph::HypergraphCrdt,
    shards_store: &dyn quil_types::store::ShardsStore,
) {
    // 1. Re-feed the (now-populated) shard-prefix sets so `commit_inner`
    //    aggregates the seeded/registered sub-shards.
    let apps = refresh_crdt_shard_prefixes(crdt, shards_store);
    // 2. Ensure the lazy phase trees exist for every registered app shard so the
    //    eager commit below materializes their roots (all 4 phases — remote
    //    verifiers check commitments across every phase, not just vertex_adds).
    let mut committed_apps: Vec<[u8; 32]> = Vec::new();
    if let Ok(shards) = shards_store.range_app_shards() {
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for s in shards {
            if s.shard_key.len() != 35 || !seen.insert(s.shard_key.clone()) {
                continue;
            }
            let mut l1 = [0u8; 3];
            l1.copy_from_slice(&s.shard_key[..3]);
            let mut l2 = [0u8; 32];
            l2.copy_from_slice(&s.shard_key[3..35]);
            crdt.ensure_all_phase_trees(&quil_types::store::ShardKey { l1, l2 });
            committed_apps.push(l2);
        }
    }
    // 3. Seed the per-sub-shard live-size baseline for the genesis-created shards
    //    (the seeded coins never passed through `add_vertex`, so the reward
    //    `state_size` denominator would omit them without this).
    if !committed_apps.is_empty() {
        if let Err(e) = crdt.warm_sizes(&committed_apps) {
            warn!(error = %e, "reprime_after_genesis: warm_sizes failed");
        }
    }
    // 4. Eager commit so the seeded shard's committed phase roots are stable +
    //    non-zero BEFORE the first frame is proposed/verified.
    match crdt.commit(0) {
        Ok(commits) => info!(
            apps,
            shards = commits.len(),
            "reprimed app-shard phase trees after genesis (deterministic seeded roots)"
        ),
        Err(e) => warn!(error = %e, "reprime_after_genesis: eager commit failed"),
    }
}
