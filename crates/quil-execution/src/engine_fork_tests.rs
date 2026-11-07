use super::*;
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use crate::token_intrinsic::config_resolver::{HypergraphTokenConfigResolver, MintVariant};

fn memory_crdt() -> Arc<quil_hypergraph::HypergraphCrdt> {
    Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(quil_tries::ShaInclusionProver),
    ))
}

fn context(crdt: Arc<quil_hypergraph::HypergraphCrdt>) -> ExecutionForkContext {
    ExecutionForkContext {
        crdt,
        clock_store: Arc::new(crate::testing::NoopClockStore),
        global_clock_store: Arc::new(crate::testing::NoopClockStore),
        shards_store: None,
        prover_registry: Arc::new(crate::prover_registry::SharedProverRegistry::new()),
    }
}

fn token(crdt: Arc<quil_hypergraph::HypergraphCrdt>) -> TokenExecutionEngine {
    let crypto = crate::testing::NoopExecutionCrypto::new();
    TokenExecutionEngine::new_with_state(
        ExecutionMode::Application,
        Arc::new(quil_tries::ShaInclusionProver),
        crdt.clone(),
        crypto.key_manager,
        crypto.clock_store,
    )
    .with_config_resolver(Arc::new(HypergraphTokenConfigResolver::new(crdt)))
}

fn install_mint_config(
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    app: &[u8; 32],
    behavior: u16,
    frame: u64,
) {
    let strategy = crate::token_intrinsic::config::TokenMintStrategy {
        mint_behavior: u32::from(behavior),
        proof_basis: 0,
        verkle_root: vec![],
        authority: vec![],
        payment_address: vec![],
        fee_basis: vec![],
    };
    let cfg = crate::token_intrinsic::config::TokenConfiguration {
        mint_strategy: strategy.to_canonical_bytes().unwrap(),
        ..Default::default()
    };
    let state = HypergraphState::new(crdt.clone());
    crate::token_intrinsic::materialize::materialize_token_deploy(
        &state,
        app,
        &cfg,
        frame,
        &quil_tries::ShaInclusionProver,
    )
    .unwrap();
    state.commit().unwrap();
    state.abort();
    crdt.commit(frame).unwrap();
}

#[test]
fn fork_token_resolver_drops_source_cache_and_uses_only_context_state() {
    use crate::token_intrinsic::constants::{MINT_WITH_PAYMENT, NO_MINT_BEHAVIOR};
    let primary = memory_crdt();
    let target = memory_crdt();
    let app = [17; 32];
    install_mint_config(primary.clone(), &app, MINT_WITH_PAYMENT, 1);
    install_mint_config(target.clone(), &app, NO_MINT_BEHAVIOR, 1);
    let source = token(primary.clone());
    assert_eq!(
        source.config_resolver.mint_variant_for_domain(&app),
        Some(MintVariant::Payment)
    );
    let target_context = context(target.clone());
    let branch = source.fork_with_context(&target_context).unwrap();
    assert_eq!(
        branch.config_resolver.mint_variant_for_domain(&app),
        Some(MintVariant::NoMint)
    );
    assert_eq!(
        source.config_resolver.mint_variant_for_domain(&app),
        Some(MintVariant::Payment)
    );
    assert!(Arc::ptr_eq(
        &branch.clock_store,
        &target_context.global_clock_store
    ));
    assert!(!Arc::ptr_eq(
        &branch.clock_store,
        &target_context.clock_store
    ));

    // A new target config must not be hidden by either the source's cache or
    // a sibling's already-loaded entry, even when a caller invalidates one.
    let sibling_crdt = memory_crdt();
    install_mint_config(sibling_crdt.clone(), &app, MINT_WITH_PAYMENT, 1);
    let sibling = branch.fork_with_context(&context(sibling_crdt)).unwrap();
    assert_eq!(
        sibling.config_resolver.mint_variant_for_domain(&app),
        Some(MintVariant::Payment)
    );
    assert_eq!(
        branch.config_resolver.mint_variant_for_domain(&app),
        Some(MintVariant::NoMint)
    );
    branch.config_resolver.invalidate(&app);
    assert_eq!(
        branch.config_resolver.mint_variant_for_domain(&app),
        Some(MintVariant::NoMint)
    );
    install_mint_config(target, &app, MINT_WITH_PAYMENT, 2);
    branch.config_resolver.invalidate(&app);
    assert_eq!(
        branch.config_resolver.mint_variant_for_domain(&app),
        Some(MintVariant::Payment)
    );
}

#[test]
fn fork_hypergraph_resolver_and_all_claim_clocks_use_the_new_context() {
    let primary = memory_crdt();
    let target = memory_crdt();
    let deploy = |crdt: Arc<quil_hypergraph::HypergraphCrdt>, key: u8| {
        let state = HypergraphState::new(crdt.clone());
        let app = crate::hypergraph_intrinsic::materialize_hypergraph_deploy_init(
            &state,
            &crate::hypergraph_intrinsic::HypergraphConfiguration {
                read_public_key: vec![1; 1158],
                write_public_key: vec![key; 1793],
                owner_public_key: vec![],
            },
            b"",
            1,
            &quil_tries::ShaInclusionProver,
        )
        .unwrap();
        state.commit().unwrap();
        state.abort();
        crdt.commit(1).unwrap();
        app
    };
    let source_app = deploy(primary.clone(), 7);
    let target_app = deploy(target.clone(), 8);
    assert_ne!(source_app, target_app);
    let crypto = crate::testing::NoopExecutionCrypto::new();
    let mut source = HypergraphExecutionEngine::new_with_state(
        ExecutionMode::Global,
        primary.clone(),
        Arc::new(crate::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(primary.clone())),
    )
    .with_key_manager(crypto.key_manager.clone());
    source.set_global_clock_store(crypto.clock_store.clone());
    let context = context(target);
    let branch = source.fork_with_context(&context).unwrap();
    assert_eq!(branch.mode, ExecutionMode::Global);
    assert_eq!(
        branch.config_resolver.write_public_key(&target_app),
        Some(vec![8; 1793])
    );
    assert_eq!(source.config_resolver.write_public_key(&target_app), None);
    assert_eq!(
        source.config_resolver.write_public_key(&source_app),
        Some(vec![7; 1793])
    );
    assert_eq!(branch.config_resolver.write_public_key(&source_app), None);
    assert!(Arc::ptr_eq(
        branch.global_clock.as_ref().unwrap(),
        &context.global_clock_store
    ));
    assert!(Arc::ptr_eq(
        branch.key_manager.as_ref().unwrap(),
        &crypto.key_manager
    ));

    let mut compute = ComputeExecutionEngine::new_with_state(
        ExecutionMode::Application,
        primary,
        crypto.key_manager,
        crypto.circuit_compiler,
    );
    compute.set_global_clock_store(crypto.clock_store);
    let compute_branch = compute.fork_with_context(&context).unwrap();
    assert_eq!(compute_branch.mode, ExecutionMode::Application);
    assert!(Arc::ptr_eq(
        compute_branch.global_clock.as_ref().unwrap(),
        &context.global_clock_store
    ));
    // A write through either branch engine's message state reaches only the
    // supplied CRDT, even though the crypto/compiler services are shared.
    let disc = vertex_adds_discriminator().unwrap();
    compute_branch
        .state
        .as_ref()
        .unwrap()
        .set(&[21; 32], &[22; 32], &disc, 2, b"compute".to_vec())
        .unwrap();
    compute_branch.state.as_ref().unwrap().commit().unwrap();
    assert_eq!(
        branch
            .state
            .as_ref()
            .unwrap()
            .get(&[21; 32], &[22; 32], &disc)
            .unwrap(),
        Some(b"compute".to_vec())
    );
    assert_eq!(
        compute
            .state
            .as_ref()
            .unwrap()
            .get(&[21; 32], &[22; 32], &disc)
            .unwrap(),
        None
    );
}

#[test]
fn fork_rejects_unfinished_state_and_ancillary_message_changes_for_every_engine() {
    let primary = memory_crdt();
    let context = context(memory_crdt());
    let crypto = crate::testing::NoopExecutionCrypto::new();
    let token = token(primary.clone());
    let compute = ComputeExecutionEngine::new_with_state(
        ExecutionMode::Global,
        primary.clone(),
        crypto.key_manager.clone(),
        crypto.circuit_compiler,
    );
    let hypergraph = HypergraphExecutionEngine::new_with_state(
        ExecutionMode::Global,
        primary.clone(),
        Arc::new(crate::testing::NoopHypergraphConfigResolver),
    );
    let global = GlobalExecutionEngine::new_with_intrinsic(
        Arc::new(quil_tries::ShaInclusionProver),
        crypto.key_manager,
        primary,
        crypto.clock_store,
        None,
        None,
    );
    for ancillary in [false, true] {
        for state in [
            &token.state,
            &compute.state,
            &hypergraph.state,
            &global.state,
        ] {
            let state = state.as_ref().unwrap();
            if ancillary {
                state.stage_records([quil_types::store::RecordMutation {
                    key: b"message".to_vec(),
                    value: Some(vec![1]),
                }]);
            } else {
                state
                    .set(
                        &[1; 32],
                        &[2; 32],
                        &vertex_adds_discriminator().unwrap(),
                        1,
                        vec![3],
                    )
                    .unwrap();
            }
        }
        assert!(token.fork_with_context(&context).is_err());
        assert!(compute.fork_with_context(&context).is_err());
        assert!(hypergraph.fork_with_context(&context).is_err());
        assert!(global.fork_with_context(&context).is_err());
        for state in [
            &token.state,
            &compute.state,
            &hypergraph.state,
            &global.state,
        ] {
            assert_eq!(state.as_ref().unwrap().changeset_len(), 1);
            state.as_ref().unwrap().abort();
        }
    }
    assert!(token.fork_with_context(&context).is_ok());
    assert!(compute.fork_with_context(&context).is_ok());
    assert!(hypergraph.fork_with_context(&context).is_ok());
    assert!(global.fork_with_context(&context).is_ok());
}

#[cfg(feature = "native-proof")]
#[test]
fn fork_keeps_configured_token_limits_and_worker_capacity() {
    let mut policy = crate::token_intrinsic::dispatch::TokenPolicy::for_network(9);
    policy.limits.max_inputs = 2;
    policy.limits.max_outputs = 1;
    policy.limits.max_depth = 7;
    policy.snapshots.max_coins = 123;
    policy.snapshots.max_nodes = 456;
    policy.snapshots.max_depth = 7;
    policy.native_budget.max_native_bytes = 1024;
    // Construction spawns no worker; this test checks preservation of a
    // configured client. Clone itself retains its existing slots and lane.
    let worker =
        quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier::new(
            std::path::PathBuf::from("/unused/execution-fork-test-worker"),
            10,
            std::time::Duration::from_secs(10),
        )
        .unwrap()
        .with_concurrency(3)
        .unwrap()
        .for_lane(17);
    let source = token(memory_crdt())
        .with_token_proofs(policy)
        .unwrap()
        .with_token_worker(worker)
        .unwrap();
    let branch = source.fork_with_context(&context(memory_crdt())).unwrap();
    let copied = branch.token_policy.unwrap();
    assert_eq!(copied.network, policy.network);
    assert_eq!(
        (
            copied.limits.max_inputs,
            copied.limits.max_outputs,
            copied.limits.max_depth
        ),
        (2, 1, 7)
    );
    assert_eq!(
        (
            copied.snapshots.max_coins,
            copied.snapshots.max_nodes,
            copied.snapshots.max_depth
        ),
        (123, 456, 7)
    );
    assert_eq!(copied.native_budget.max_native_bytes, 1024);
    assert_eq!(branch.token_worker.as_ref().unwrap().concurrency(), 3);
    assert_eq!(
        branch.verification_capacity(),
        source.verification_capacity()
    );
    assert_eq!(branch.mode, ExecutionMode::Application);
}
