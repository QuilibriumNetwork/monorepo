//! Base reproducers: an operation citing a GLOBAL frame no node can resolve
//! must be refused deterministically. On mainnet that is every frame before
//! the first 2.1.0 frame: none exists below the 2.1 genesis, and the legacy
//! frames from it to the flag day commit 74-byte prover roots. On the base,
//! `clock_reward_root` turns the failed read into `ExecutionUnavailable`,
//! which fails the whole frame on every replica. Each reproducer fails with
//! "EARLY HALT: ..." while that holds; the controls pass and say which path
//! drops cleanly and which class stays retryable.
use super::dispatch::TokenPolicy;
use super::settlement_claim::{
    bundle_context, marker_record, SettlementClaim, TYPE_SETTLEMENT_CLAIM,
};
use crate::domains;
use crate::engines::{
    ComputeExecutionEngine, ExecutionMode, HypergraphExecutionEngine, TokenExecutionEngine,
};
use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use num_bigint::BigInt;
use quil_lattice_ct::confidential::{
    mint::{Mint, MintStatement, RewardClaim, FALCON_PUBLIC_BYTES, FALCON_SIGNATURE_BYTES},
    mint_claim::MintClaim,
    relation::membership::IDENTITY_BYTES,
    transfer::{parameter_context, Output, MEMO_BYTES},
    AmountOpening, CommitmentKey,
};
use quil_types::crypto::NoopInclusionProver;
use quil_types::error::{QuilError, Result};
use quil_types::execution::{FrameExecutionContext, ShardExecutionEngine, ShardPath, Venue};
use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
use std::sync::Arc;

/// First mainnet frame of the 2.1.0 chain, the first with a forest root.
const FIRST: u64 = quil_crypto::GLOBAL_FLAG_DAY_LAST_LEGACY_FRAME + 1;
/// The executing frame's finalized GLOBAL anchor, well inside history.
const ANCHOR: u64 = FIRST + 1_000;
/// A citation no node holds: below the 2.1 genesis.
const BELOW_GENESIS: u64 = 1;
/// The last legacy frame: archives hold it with a 74-byte prover root,
/// regular nodes not at all.
const LAST_LEGACY: u64 = FIRST - 1;

fn policy(network: u8) -> TokenPolicy {
    TokenPolicy::for_network(network)
}

/// GLOBAL frame `number` with a forest-root-sized (32) or legacy (74) root.
fn global_frame(number: u64, root_bytes: usize) -> GlobalFrame {
    GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: number,
            prover_tree_commitment: vec![0x5a; root_bytes],
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Mainnet-shaped clock of a regular node: the 2.1.0 frames up to the anchor.
fn mainnet_clock() -> Arc<quil_store::testing::InMemoryClockStore> {
    let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
    for number in FIRST..=ANCHOR {
        clock.seed_frame(global_frame(number, 32));
    }
    clock
}

/// A clock holding only the anchor: every earlier frame is a local gap.
fn anchor_only_clock() -> Arc<quil_store::testing::InMemoryClockStore> {
    let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
    clock.seed_frame(global_frame(ANCHOR, 32));
    clock
}

fn crdt() -> Arc<quil_hypergraph::HypergraphCrdt> {
    Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(NoopInclusionProver),
    ))
}

fn engine_on(
    network: u8,
    mode: ExecutionMode,
    clock: Arc<quil_store::testing::InMemoryClockStore>,
) -> TokenExecutionEngine {
    let stubs = crate::testing::NoopExecutionCrypto::new();
    TokenExecutionEngine::new_with_state(
        mode,
        Arc::new(NoopInclusionProver),
        crdt(),
        stubs.key_manager,
        clock,
    )
    .with_token_proofs(policy(network))
    .unwrap()
}

/// A mainnet token engine.
fn engine(
    mode: ExecutionMode,
    clock: Arc<quil_store::testing::InMemoryClockStore>,
) -> TokenExecutionEngine {
    engine_on(0, mode, clock)
}

/// A token engine as a node with `proofWorker.disabled` builds it: state,
/// no token policy. It still admits custom-token settlement claims.
fn unsuited_engine(clock: Arc<quil_store::testing::InMemoryClockStore>) -> TokenExecutionEngine {
    let stubs = crate::testing::NoopExecutionCrypto::new();
    TokenExecutionEngine::new_with_state(
        ExecutionMode::Application,
        Arc::new(NoopInclusionProver),
        crdt(),
        stubs.key_manager,
        clock,
    )
}

fn junk_outputs(network: &[u8; 32]) -> Vec<Output> {
    let context = parameter_context(network, &domains::QUIL_TOKEN);
    let key = CommitmentKey::derive(&context);
    let opening = AmountOpening::from_seed(&context, &[2; 32]);
    vec![Output {
        commitment: key.commit(7, &opening),
        owner: [3; IDENTITY_BYTES],
        memo: [4; MEMO_BYTES],
    }]
}

/// A QUIL reward mint any submitter can build on `network`: no reward
/// balance, no valid key, signature or proof. Only its encoding is well formed.
fn junk_mint_on(network: u8, cited_frame: u64) -> Vec<u8> {
    let network = policy(network).network;
    let value = u128::MAX / 2;
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    Mint {
        statement: MintStatement {
            network,
            application: domains::QUIL_TOKEN,
            cited_frame,
            reward_root: [9; 32],
            fee: value,
            claims: vec![RewardClaim {
                owner: [5; 32],
                value,
                public_key: [6; FALCON_PUBLIC_BYTES],
                forest_proof: vec![7; 40],
            }],
            outputs: junk_outputs(&network),
        },
        signatures: vec![[8; FALCON_SIGNATURE_BYTES]],
        proof,
    }
    .encode()
    .unwrap()
}

/// [`junk_mint_on`] mainnet.
fn junk_mint(cited_frame: u64) -> Vec<u8> {
    junk_mint_on(0, cited_frame)
}

/// A mint claim any submitter can build: no authorization behind it.
fn junk_mint_claim(cited_global_frame: u64) -> Vec<u8> {
    let network = policy(0).network;
    MintClaim {
        network,
        application: domains::QUIL_TOKEN,
        cited_global_frame,
        global_root: [9; 32],
        receipt: [10; 32],
        fee: 1,
        outputs: junk_outputs(&network),
        forest_proof: vec![11; 40],
    }
    .encode()
    .unwrap()
}

/// One canonical bundle carrying `op`, as frames carry every request.
fn bundle(op: Vec<u8>) -> Vec<u8> {
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest::wrap(op).unwrap())],
        timestamp: 1,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// The GLOBAL materializer's context (`frame_materializer.rs` ~1076).
fn global_context() -> FrameExecutionContext {
    FrameExecutionContext {
        frame_number: ANCHOR + 1,
        finalized_global_frame: Some(ANCHOR),
        shard: ShardPath::WHOLE,
        venue: Some(Venue::Global),
    }
}

/// The app-shard materializer's context (`app_engine.rs` ~14363).
fn app_context() -> FrameExecutionContext {
    FrameExecutionContext {
        frame_number: 7,
        finalized_global_frame: Some(ANCHOR),
        shard: ShardPath::WHOLE,
        venue: Some(Venue::Application),
    }
}

/// Frame callers fail the frame on `is_execution_unavailable` and skip the
/// op on any other error (`frame_materializer.rs` ~1109, `app_engine.rs`
/// ~14405). Only a deterministic refusal leaves the frame able to finish.
fn expect_refused<T>(case: &str, cited: u64, result: Result<T>) {
    match result {
        Err(error) if error.is_execution_unavailable() => panic!(
            "EARLY HALT: {case}: a citation of GLOBAL frame {cited} (before the first citable \
             frame {FIRST}, resolvable on no node) is ExecutionUnavailable, so every replica \
             fails the frame and retries it forever: {error}"
        ),
        Err(QuilError::InvalidArgument(_)) => {}
        Err(error) => panic!("EARLY UNEXPECTED: {case}: refused with a non-skip class: {error}"),
        Ok(_) => panic!("EARLY UNEXPECTED: {case}: an unauthorized op was accepted"),
    }
}

fn mint_in_global_venue(
    clock: Arc<quil_store::testing::InMemoryClockStore>,
    cited: u64,
) -> Result<quil_types::execution::ProcessMessageResult> {
    engine(ExecutionMode::Global, clock).process_message_with_context(
        global_context(),
        &BigInt::from(0),
        &domains::QUIL_TOKEN,
        &bundle(junk_mint(cited)),
    )
}

#[test]
fn reward_mint_citing_frame_one_must_not_fail_the_global_frame() {
    let engine = engine(ExecutionMode::Global, mainnet_clock());
    let message = bundle(junk_mint(BELOW_GENESIS));
    // The materializer validates first (~1041); a deterministic refusal there
    // would skip the op. Preflight only decodes, so it passes.
    match engine.validate_message(ANCHOR + 1, &domains::QUIL_TOKEN, &message) {
        Err(error) if error.is_execution_unavailable() => {
            panic!("EARLY HALT: H1 GLOBAL validate step is ExecutionUnavailable: {error}")
        }
        Err(error) => {
            eprintln!("CRR NOTE: H1 dropped cleanly at the validate step: {error}");
            return;
        }
        Ok(()) => {}
    }
    expect_refused(
        "QUIL reward mint (GLOBAL venue)",
        BELOW_GENESIS,
        engine.process_message_with_context(
            global_context(),
            &BigInt::from(0),
            &domains::QUIL_TOKEN,
            &message,
        ),
    );
}

#[test]
fn reward_mint_citing_a_legacy_frame_must_not_fail_the_global_frame() {
    // An archive holds the legacy frame with its 74-byte prover root; a
    // regular node does not hold it. Neither can resolve the citation.
    let archive = mainnet_clock();
    archive.seed_frame(global_frame(LAST_LEGACY, 74));
    expect_refused(
        "QUIL reward mint citing the last legacy frame, on an archive",
        LAST_LEGACY,
        mint_in_global_venue(archive, LAST_LEGACY),
    );
    expect_refused(
        "QUIL reward mint citing the last legacy frame, on a regular node",
        LAST_LEGACY,
        mint_in_global_venue(mainnet_clock(), LAST_LEGACY),
    );
}

#[test]
fn mint_claim_citing_frame_one_must_not_fail_the_quil_app_frame() {
    let engine = engine(ExecutionMode::Application, mainnet_clock());
    let message = bundle(junk_mint_claim(BELOW_GENESIS));
    expect_refused(
        "mint claim (QUIL app shard and archive replay)",
        BELOW_GENESIS,
        engine.process_message_with_context(
            app_context(),
            &BigInt::from(0),
            &domains::QUIL_TOKEN,
            &message,
        ),
    );
}

/// The application a settlement claim funds.
const PAID_APP: [u8; 32] = [2; 32];

/// [`settlement_bundle_for`] the paid application.
fn settlement_bundle(cited_global_frame: u64) -> Vec<u8> {
    settlement_bundle_for(PAID_APP, cited_global_frame)
}

/// A claim-funded bundle any submitter can build for `application`: a
/// settlement claim with an attacker-chosen amount and no record behind it,
/// then a write it pays for.
fn settlement_bundle_for(application: [u8; 32], cited_global_frame: u64) -> Vec<u8> {
    let compute = crate::compute_intrinsic::config::TYPE_COMPUTE_DEPLOY;
    let mut inner = compute.to_be_bytes().to_vec();
    inner.resize(100, 0xAB);
    let mut bundle = CanonicalMessageBundle {
        requests: vec![
            None,
            Some(CanonicalMessageRequest {
                inner_type_prefix: compute,
                inner_bytes: inner,
            }),
        ],
        timestamp: 5,
    };
    let context = bundle_context(&bundle).unwrap();
    let claim = SettlementClaim {
        network: [1; 32],
        application,
        cited_global_frame,
        global_root: [3; 32],
        receipt: [4; 32],
        settlement: 2 * (100 + marker_record().unwrap().len() as u128),
        context,
        payment_address: [0; 32],
        payment: 0,
        claimant_key_type: 0,
        claimant_public_key: Vec::new(),
        claimant_signature: Vec::new(),
        forest_proof: vec![6; 40],
    };
    bundle.requests[0] = Some(CanonicalMessageRequest {
        inner_type_prefix: TYPE_SETTLEMENT_CLAIM,
        inner_bytes: claim.encode().unwrap(),
    });
    bundle.to_canonical_bytes().unwrap()
}

/// The engines that admit a settlement claim before the writes it funds
/// (`engines.rs` ~1438 custom-token bundle, with and without the token
/// suite, ~2104 compute, ~3013 hypergraph), each built as a mainnet node
/// builds it.
fn settlement_engines(
    clock: Arc<quil_store::testing::InMemoryClockStore>,
) -> Vec<(&'static str, Box<dyn ShardExecutionEngine>)> {
    let stubs = crate::testing::NoopExecutionCrypto::new();
    let mut compute = ComputeExecutionEngine::new_with_state(
        ExecutionMode::Application,
        crdt(),
        stubs.key_manager.clone(),
        stubs.circuit_compiler.clone(),
    );
    compute.set_global_clock_store(clock.clone());
    let mut hypergraph = HypergraphExecutionEngine::new_with_state(
        ExecutionMode::Application,
        crdt(),
        Arc::new(crate::testing::NoopHypergraphConfigResolver),
    );
    hypergraph.set_global_clock_store(clock.clone());
    vec![
        (
            "custom token without the token suite",
            Box::new(unsuited_engine(clock.clone())),
        ),
        (
            "custom token",
            Box::new(engine(ExecutionMode::Application, clock)),
        ),
        ("compute", Box::new(compute)),
        ("hypergraph", Box::new(hypergraph)),
    ]
}

fn admit_settlement(
    engine: &dyn ShardExecutionEngine,
    cited_global_frame: u64,
) -> Result<quil_types::execution::ProcessMessageResult> {
    engine.process_message_with_context(
        app_context(),
        &BigInt::from(2),
        &PAID_APP,
        &settlement_bundle(cited_global_frame),
    )
}

#[test]
fn settlement_claim_citing_frame_one_must_not_fail_the_paid_frame() {
    for (name, engine) in settlement_engines(mainnet_clock()) {
        expect_refused(
            &format!("settlement claim ({name} engine)"),
            BELOW_GENESIS,
            admit_settlement(engine.as_ref(), BELOW_GENESIS),
        );
    }
}

#[test]
fn settlement_claim_without_the_token_suite_must_not_fail_the_paid_frame() {
    // A node without the token suite admits custom-token settlement claims
    // like every other node, so it reads the cited frame too.
    expect_refused(
        "settlement claim (custom-token engine without the token suite)",
        BELOW_GENESIS,
        admit_settlement(&unsuited_engine(mainnet_clock()), BELOW_GENESIS),
    );
    let application = super::constants::token_base_domain();
    expect_refused(
        "settlement claim (token engine, without the token suite, of a mainnet manager)",
        BELOW_GENESIS,
        admit_through_manager(&manager_on(0, mainnet_clock()), application, BELOW_GENESIS),
    );
}

/// A manager as a node builds one: its pricing network is the node's network.
fn manager_on(
    network: u8,
    clock: Arc<quil_store::testing::InMemoryClockStore>,
) -> crate::manager::ExecutionEngineManager {
    let stubs = crate::testing::NoopExecutionCrypto::new();
    crate::manager::ExecutionEngineManager::new(
        Arc::new(NoopInclusionProver),
        stubs.key_manager,
        crdt(),
        stubs.circuit_compiler,
        clock,
        Arc::new(crate::testing::NoopHypergraphConfigResolver),
        false,
    )
    .with_pricing_network(network)
}

/// The base domains a manager routes straight to its compute, hypergraph
/// and token engines (the token engine without the token suite, as
/// [`manager_on`] builds it).
fn manager_routes() -> [(&'static str, [u8; 32]); 3] {
    [
        ("compute", domains::COMPUTE),
        (
            "hypergraph",
            crate::hypergraph_intrinsic::hypergraph_base_domain(),
        ),
        (
            "token, without the token suite,",
            super::constants::token_base_domain(),
        ),
    ]
}

fn admit_through_manager(
    manager: &crate::manager::ExecutionEngineManager,
    application: [u8; 32],
    cited_global_frame: u64,
) -> Result<quil_types::execution::ProcessMessageResult> {
    manager.process_message_with_context(
        app_context(),
        &BigInt::from(2),
        &application,
        &settlement_bundle_for(application, cited_global_frame),
    )
}

#[test]
fn settlement_claim_through_a_mainnet_manager_must_not_fail_the_frame() {
    for (name, application) in manager_routes() {
        expect_refused(
            &format!("settlement claim ({name} engine of a mainnet manager)"),
            BELOW_GENESIS,
            admit_through_manager(&manager_on(0, mainnet_clock()), application, BELOW_GENESIS),
        );
    }
}

#[test]
fn control_a_future_citation_is_refused_deterministically() {
    // The existing bound: a citation above the anchor is InvalidArgument, so
    // every frame caller skips the op and the frame finishes.
    let refused = mint_in_global_venue(mainnet_clock(), ANCHOR + 1);
    assert!(
        matches!(refused, Err(QuilError::InvalidArgument(_))),
        "control: a future reward-mint citation must drop cleanly (InvalidArgument): {:?}",
        refused.err()
    );
    let app = engine(ExecutionMode::Application, mainnet_clock());
    let refused = app.process_message_with_context(
        app_context(),
        &BigInt::from(0),
        &domains::QUIL_TOKEN,
        &bundle(junk_mint_claim(ANCHOR + 1)),
    );
    assert!(
        matches!(refused, Err(QuilError::InvalidArgument(_))),
        "control: a future mint-claim citation must drop cleanly (InvalidArgument): {:?}",
        refused.err()
    );
    for (name, engine) in settlement_engines(mainnet_clock()) {
        let refused = admit_settlement(engine.as_ref(), ANCHOR + 1);
        assert!(
            matches!(refused, Err(QuilError::InvalidArgument(_))),
            "control: a future settlement-claim citation must drop cleanly on the {name} \
             engine (InvalidArgument): {:?}",
            refused.err()
        );
    }
    eprintln!("EARLY CONTROL: future citations drop cleanly on all paths");
}

#[test]
fn control_the_same_junk_mint_citing_a_held_frame_is_refused_deterministically() {
    // Once the cited frame loads, the junk ops fail their later checks
    // (no reward or record, root, signature) with InvalidArgument: a clean skip.
    let refused = mint_in_global_venue(mainnet_clock(), ANCHOR - 10);
    assert!(
        matches!(refused, Err(QuilError::InvalidArgument(_))),
        "control: the junk reward mint citing a held frame must drop cleanly: {:?}",
        refused.err()
    );
    for (name, engine) in settlement_engines(mainnet_clock()) {
        let refused = admit_settlement(engine.as_ref(), ANCHOR - 10);
        assert!(
            matches!(refused, Err(QuilError::InvalidArgument(_))),
            "control: the junk settlement claim citing a held frame must drop cleanly on the \
             {name} engine: {:?}",
            refused.err()
        );
    }
    eprintln!("EARLY CONTROL: junk ops citing a held frame drop cleanly");
}

#[test]
fn control_a_node_local_gap_inside_history_stays_unavailable() {
    // The intended use of the class: a frame other replicas hold but this
    // node lacks (inside 2.1.0 history) must stay retryable, not refused. A
    // fix must keep this passing.
    let held = mint_in_global_venue(anchor_only_clock(), ANCHOR - 10);
    assert!(
        held.as_ref()
            .is_err_and(|error| error.is_execution_unavailable()),
        "control: a node-local gap inside history must stay ExecutionUnavailable: {:?}",
        held.err()
    );
    eprintln!("EARLY CONTROL: a node-local gap inside history stays retryable");
}

#[test]
fn control_a_node_local_gap_at_the_first_citable_frame_stays_unavailable() {
    // The bound's edge: the first 2.1.0 frame is citable, so lacking it is a
    // local gap (retryable), while the frame before it is refused.
    let held = mint_in_global_venue(anchor_only_clock(), FIRST);
    assert!(
        held.as_ref()
            .is_err_and(|error| error.is_execution_unavailable()),
        "control: a local gap at the first citable frame {FIRST} must stay \
         ExecutionUnavailable: {:?}",
        held.err()
    );
    for (name, engine) in settlement_engines(anchor_only_clock()) {
        let held = admit_settlement(engine.as_ref(), FIRST);
        assert!(
            held.as_ref()
                .is_err_and(|error| error.is_execution_unavailable()),
            "control: a local gap at the first citable frame must stay ExecutionUnavailable \
             on the {name} engine: {:?}",
            held.err()
        );
    }
    eprintln!("EARLY CONTROL: a local gap at the first citable frame stays retryable");
}

#[test]
fn control_a_test_network_cites_from_frame_zero() {
    // Other networks start at frame 0 with forest roots and never rewound, so
    // a missing early frame there is a local gap like any other.
    let engine = engine_on(1, ExecutionMode::Global, anchor_only_clock());
    let held = engine.process_message_with_context(
        global_context(),
        &BigInt::from(0),
        &domains::QUIL_TOKEN,
        &bundle(junk_mint_on(1, BELOW_GENESIS)),
    );
    assert!(
        held.as_ref()
            .is_err_and(|error| error.is_execution_unavailable()),
        "control: a test network's frame {BELOW_GENESIS} must stay a retryable local gap: {:?}",
        held.err()
    );
    for (name, application) in manager_routes() {
        let held = admit_through_manager(
            &manager_on(1, anchor_only_clock()),
            application,
            BELOW_GENESIS,
        );
        assert!(
            held.as_ref()
                .is_err_and(|error| error.is_execution_unavailable()),
            "control: a test network manager's {name} engine must keep frame {BELOW_GENESIS} a \
             retryable local gap: {:?}",
            held.err()
        );
    }
    eprintln!("EARLY CONTROL: a test network cites from frame 0");
}
