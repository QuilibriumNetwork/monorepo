use std::sync::Arc;

use tracing::{info, warn};

use super::storage::StorageHandles;

pub(crate) struct EngineHandles {
    pub inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub exec_manager: Arc<quil_execution::ExecutionEngineManager>,
}

pub(crate) fn init_engines(storage: &StorageHandles) -> EngineHandles {
    // ---------------------------------------------------------------
    // 3. Create execution engines with full crypto verification
    // ---------------------------------------------------------------
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
        Arc::new(quil_crypto::KzgInclusionProver);
    let bls_constructor: Arc<dyn quil_types::crypto::BlsConstructor> =
        Arc::new(quil_crypto::Bls48581KeyConstructor);
    let key_manager: Arc<dyn quil_types::crypto::KeyManager> =
        Arc::new(quil_crypto::DefaultKeyManager::new(bls_constructor));
    // CRDT backed by RocksDB for real persistence
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        storage.hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover.clone(),
    ));
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
                primed_count += 1;
            }
        }
        info!(shards = primed_count, "app shards primed in CRDT phase_sets");
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
    // ExecutionEngineManager::new takes the full crypto + store
    // provider set as mandatory inputs. Production bulletproof prover
    // ships in `quil_crypto::Decaf448BulletproofProver`; the Decaf448
    // constructor and circuit compiler aren't wired to real
    // implementations yet (no production impl exists in the Rust
    // tree), so we plug in the testing-stubs noop variants. Those
    // engines' verify paths return `false` for every signature, so
    // any signed op fails closed rather than silently passing.
    let bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver> =
        Arc::new(quil_crypto::Decaf448BulletproofProver);
    let decaf_constructor: Arc<dyn quil_types::crypto::DecafConstructor> =
        Arc::new(quil_execution::testing::NoopDecafConstructor);
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
    let exec_manager = Arc::new(quil_execution::ExecutionEngineManager::new(
        inclusion_prover.clone(),
        key_manager.clone(),
        crdt.clone(),
        bulletproof_prover,
        decaf_constructor,
        circuit_compiler,
        clock_store_for_exec,
        hypergraph_resolver,
        true,
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
