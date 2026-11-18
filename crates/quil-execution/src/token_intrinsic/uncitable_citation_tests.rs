//! Base reproducers: an operation citing a GLOBAL frame no node can resolve
//! must be refused deterministically. On mainnet that is every frame before
//! the first 2.1.0 frame: none exists below the 2.1 genesis, and the legacy
//! frames from it to the flag day commit 74-byte prover roots. On the base,
//! `clock_reward_root` turns the failed read into `ExecutionUnavailable`,
//! which fails the whole frame on every replica. Each reproducer fails with
//! "EARLY HALT: ..." while that holds; the controls pass and say which path
//! drops cleanly and which class stays retryable. The `zero_anchor_` and
//! `lone_` rows are the same failure before any citation is read: an
//! operation needing what a certified frame lacks, on every replica alike.
use super::delivery::{CoinDelivery, Delivered};
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
    pending_claim::{ClaimBranch, EscrowPolicy, PendingClaim, PendingClaimStatement},
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

/// The app-shard materializer's context for a frame whose header names no
/// GLOBAL anchor (`app_engine.rs` ~14360): its own property, on every replica.
fn anchorless_context() -> FrameExecutionContext {
    FrameExecutionContext {
        finalized_global_frame: None,
        ..app_context()
    }
}

/// Frame callers fail the frame on `is_execution_unavailable` and skip the
/// op on any other error (`frame_materializer.rs` ~1109, `app_engine.rs`
/// ~14405). Only a deterministic refusal leaves the frame able to finish, and
/// only `reason` shows the op reached the check this row is about: junk that
/// a decode or an earlier check refuses proves nothing.
fn expect_skipped<T>(case: &str, halt: &str, reason: &str, result: Result<T>) {
    match result {
        Err(error) if error.is_execution_unavailable() => panic!(
            "EARLY HALT: {case}: {halt}, so every replica fails the frame and retries it forever: \
             {error}"
        ),
        Err(QuilError::InvalidArgument(message)) if message.contains(reason) => {}
        Err(QuilError::InvalidArgument(message)) => {
            panic!("EARLY WRONG REFUSAL: {case}: expected \"{reason}\", refused with: {message}")
        }
        Err(error) => panic!("EARLY UNEXPECTED: {case}: refused with a non-skip class: {error}"),
        Ok(_) => panic!("EARLY UNEXPECTED: {case}: an unauthorized op was accepted"),
    }
}

/// [`expect_skipped`] for a citation before the first citable frame.
fn expect_refused<T>(case: &str, cited: u64, result: Result<T>) {
    expect_skipped(
        case,
        &format!(
            "a citation of GLOBAL frame {cited} (before the first citable frame {FIRST}, \
             resolvable on no node) is ExecutionUnavailable"
        ),
        "precedes the network's first citable frame",
        result,
    );
}

/// [`expect_skipped`] for an op in a frame whose header names no GLOBAL anchor.
fn expect_anchorless_refused<T>(case: &str, result: Result<T>) {
    expect_skipped(
        case,
        "an operation needing the anchor of a frame that names none is ExecutionUnavailable",
        "the frame's global anchor",
        result,
    );
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
    // The materializer validates first (~1041); a deterministic refusal of the
    // citation there would skip the op. Preflight only decodes, so it passes.
    if let Err(error) = engine.validate_message(ANCHOR + 1, &domains::QUIL_TOKEN, &message) {
        expect_refused::<()>("GLOBAL validate step", BELOW_GENESIS, Err(error));
        return;
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
    admit_settlement_in(engine, app_context(), cited_global_frame)
}

fn admit_settlement_in(
    engine: &dyn ShardExecutionEngine,
    context: FrameExecutionContext,
    cited_global_frame: u64,
) -> Result<quil_types::execution::ProcessMessageResult> {
    engine.process_message_with_context(
        context,
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

/// A delivery of a coin or an escrow with no record behind it, as a byzantine
/// shard leader can include: only its encoding is well formed.
fn junk_deliveries(cited_global_frame: u64) -> [(&'static str, Vec<u8>); 2] {
    let network = policy(0).network;
    let delivery = |delivered| {
        CoinDelivery {
            network,
            application: domains::QUIL_TOKEN,
            cited_global_frame,
            global_root: [9; 32],
            block: 0,
            seq: 0,
            source_frame: 1,
            tx_id: [12; 32],
            source_shard: ShardPath::WHOLE,
            delivered,
            forest_proof: vec![11; 40],
        }
        .encode()
        .unwrap()
    };
    [
        (
            "coin",
            delivery(Delivered::Coin(junk_outputs(&network).remove(0))),
        ),
        ("escrow", delivery(Delivered::Escrow(vec![13; 64]))),
    ]
}

fn deliver(
    clock: Arc<quil_store::testing::InMemoryClockStore>,
    context: FrameExecutionContext,
    delivery: Vec<u8>,
) -> Result<quil_types::execution::ProcessMessageResult> {
    engine(ExecutionMode::Application, clock).process_message_with_context(
        context,
        &BigInt::from(0),
        &domains::QUIL_TOKEN,
        &bundle(delivery),
    )
}

#[test]
fn coin_delivery_citing_frame_one_must_not_fail_the_shard_frame() {
    for (name, delivery) in junk_deliveries(BELOW_GENESIS) {
        expect_refused(
            &format!("{name} delivery"),
            BELOW_GENESIS,
            deliver(mainnet_clock(), app_context(), delivery),
        );
    }
    // An archive holds the legacy frame with its 74-byte prover root.
    for (name, delivery) in junk_deliveries(LAST_LEGACY) {
        let archive = mainnet_clock();
        archive.seed_frame(global_frame(LAST_LEGACY, 74));
        expect_refused(
            &format!("{name} delivery citing the last legacy frame, on an archive"),
            LAST_LEGACY,
            deliver(archive, app_context(), delivery),
        );
    }
}

#[test]
fn control_a_coin_delivery_keeps_its_other_outcomes() {
    let expect_invalid = |case: &str, result: Result<_>, reason: &str| match result {
        Err(QuilError::InvalidArgument(message)) if message.contains(reason) => {}
        other => panic!(
            "control: {case} must drop cleanly with \"{reason}\": {:?}",
            other.err()
        ),
    };
    for (name, delivery) in junk_deliveries(ANCHOR + 1) {
        expect_invalid(
            &format!("a future {name} delivery"),
            deliver(mainnet_clock(), app_context(), delivery),
            "future global reward frame",
        );
    }
    for (name, delivery) in junk_deliveries(ANCHOR - 10) {
        expect_invalid(
            &format!("a {name} delivery with the wrong root of a held frame"),
            deliver(mainnet_clock(), app_context(), delivery),
            "cited global root mismatch",
        );
    }
    for (name, delivery) in junk_deliveries(ANCHOR - 10) {
        expect_invalid(
            &format!("a {name} delivery in a frame naming no anchor"),
            deliver(mainnet_clock(), anchorless_context(), delivery),
            "the frame's global anchor",
        );
    }
    for (name, delivery) in junk_deliveries(FIRST) {
        let held = deliver(anchor_only_clock(), app_context(), delivery);
        assert!(
            held.as_ref()
                .is_err_and(|error| error.is_execution_unavailable()),
            "control: a local gap at the first citable frame must stay ExecutionUnavailable \
             for a {name} delivery: {:?}",
            held.err()
        );
    }
    eprintln!("EARLY CONTROL: deliveries keep their future, root, anchor and local-gap outcomes");
}

#[test]
fn zero_anchor_mint_claim_must_not_fail_the_quil_app_frame() {
    let engine = engine(ExecutionMode::Application, mainnet_clock());
    expect_anchorless_refused(
        "mint claim in a frame naming no anchor",
        engine.process_message_with_context(
            anchorless_context(),
            &BigInt::from(0),
            &domains::QUIL_TOKEN,
            &bundle(junk_mint_claim(ANCHOR - 10)),
        ),
    );
}

#[test]
fn zero_anchor_settlement_claim_must_not_fail_the_paid_frame() {
    for (name, engine) in settlement_engines(mainnet_clock()) {
        expect_anchorless_refused(
            &format!("settlement claim in a frame naming no anchor ({name} engine)"),
            admit_settlement_in(engine.as_ref(), anchorless_context(), ANCHOR - 10),
        );
    }
}

/// An escrow refund any submitter can build: no escrow behind it, no valid
/// signature or proof. Only its encoding is well formed.
fn junk_refund() -> Vec<u8> {
    let network = policy(0).network;
    let context = parameter_context(&network, &domains::QUIL_TOKEN);
    let opening = AmountOpening::from_seed(&context, &[2; 32]);
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    PendingClaim {
        statement: PendingClaimStatement {
            network,
            application: domains::QUIL_TOKEN,
            escrow_address: [12; 32],
            source: CommitmentKey::derive(&context).commit(7, &opening),
            policy: EscrowPolicy {
                recipient: [13; FALCON_PUBLIC_BYTES],
                refund: [14; FALCON_PUBLIC_BYTES],
                refund_after_global_frame: 100,
            },
            branch: ClaimBranch::Refund,
            fee: 0,
            outputs: junk_outputs(&network),
        },
        signature: [8; FALCON_SIGNATURE_BYTES],
        proof,
    }
    .encode()
    .unwrap()
}

#[test]
fn zero_anchor_refund_must_not_fail_the_quil_app_frame() {
    let engine = engine(ExecutionMode::Application, mainnet_clock());
    expect_anchorless_refused(
        "escrow refund in a frame naming no anchor",
        engine.process_message_with_context(
            anchorless_context(),
            &BigInt::from(0),
            &domains::QUIL_TOKEN,
            &bundle(junk_refund()),
        ),
    );
}

#[test]
fn lone_settlement_claim_must_not_fail_the_paid_frame() {
    // Bound to the empty rest of its one-request bundle and covering its marker
    // at the multiplier below, so it passes every check before the state read of
    // the admission it reaches alone.
    let context = bundle_context(&CanonicalMessageBundle {
        requests: vec![None],
        timestamp: 0,
    })
    .unwrap();
    let claim = SettlementClaim {
        network: [1; 32],
        application: PAID_APP,
        cited_global_frame: ANCHOR - 10,
        global_root: [3; 32],
        receipt: [4; 32],
        settlement: 2 * marker_record().unwrap().len() as u128,
        context,
        payment_address: [0; 32],
        payment: 0,
        claimant_key_type: 0,
        claimant_public_key: Vec::new(),
        claimant_signature: Vec::new(),
        forest_proof: vec![6; 40],
    };
    let message = CanonicalMessageRequest {
        inner_type_prefix: TYPE_SETTLEMENT_CLAIM,
        inner_bytes: claim.encode().unwrap(),
    }
    .to_canonical_bytes()
    .unwrap();
    let engines = [
        ("without the token suite", unsuited_engine(mainnet_clock())),
        (
            "with the token suite",
            engine(ExecutionMode::Application, mainnet_clock()),
        ),
    ];
    for (name, engine) in engines {
        expect_skipped(
            &format!("a lone settlement claim (custom-token engine {name})"),
            "a settlement claim alone reaches an admission with no state and is \
             ExecutionUnavailable",
            "a settlement claim must open a bundle",
            engine.process_message_with_context(
                app_context(),
                &BigInt::from(2),
                &PAID_APP,
                &message,
            ),
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

/// The reward citations a shard worker fetches before it executes a
/// frame are the ones execution reads: every mint claim, settlement claim and
/// coin delivery that decodes, from the first citable frame to the anchor.
#[test]
fn reward_citations_of_a_message_are_named_within_the_citable_range() {
    let manager = manager_on(0, mainnet_clock());
    let quil = domains::QUIL_TOKEN;
    let named = |address: &[u8; 32], message: Vec<u8>| {
        manager.message_cited_global_frames(address, &message, ANCHOR)
    };
    let wrapped = |cited: u64| CanonicalMessageRequest::wrap(junk_mint_claim(cited)).unwrap();
    assert_eq!(
        named(&quil, bundle(junk_mint_claim(FIRST + 5))),
        vec![FIRST + 5],
        "a mint claim"
    );
    assert_eq!(
        named(&quil, wrapped(FIRST + 6).to_canonical_bytes().unwrap()),
        vec![FIRST + 6],
        "a lone mint claim request"
    );
    assert_eq!(
        named(&PAID_APP, settlement_bundle(FIRST + 7)),
        vec![FIRST + 7],
        "a settlement claim"
    );
    for (name, delivery) in junk_deliveries(FIRST + 8) {
        assert_eq!(
            named(&quil, bundle(delivery)),
            vec![FIRST + 8],
            "a {name} delivery"
        );
    }
    let several = CanonicalMessageBundle {
        requests: [FIRST + 9, FIRST + 5, FIRST + 9]
            .into_iter()
            .map(|cited| Some(wrapped(cited)))
            .collect(),
        timestamp: 1,
    }
    .to_canonical_bytes()
    .unwrap();
    assert_eq!(
        named(&quil, several),
        vec![FIRST + 5, FIRST + 9],
        "ascending, each once"
    );
    for edge in [FIRST, ANCHOR] {
        assert_eq!(
            named(&quil, bundle(junk_mint_claim(edge))),
            vec![edge],
            "edge {edge}"
        );
    }
    for unread in [BELOW_GENESIS, FIRST - 1, ANCHOR + 1] {
        assert!(
            named(&quil, bundle(junk_mint_claim(unread))).is_empty(),
            "execution refuses a citation of frame {unread} before any read: nothing to fetch"
        );
    }
    assert!(
        named(&PAID_APP, bundle(junk_mint_claim(FIRST + 5))).is_empty(),
        "a mint claim for another application fails decoding before any read"
    );
    let network = policy(0).network;
    let custom = MintClaim {
        network,
        application: PAID_APP,
        cited_global_frame: FIRST + 5,
        global_root: [9; 32],
        receipt: [10; 32],
        fee: 1,
        outputs: junk_outputs(&network),
        forest_proof: vec![11; 40],
    }
    .encode()
    .unwrap();
    assert!(
        named(&PAID_APP, bundle(custom)).is_empty(),
        "execution refuses a mint claim of any application but QUIL before any read"
    );
    assert!(
        named(&quil, bundle(junk_mint(FIRST + 5))).is_empty(),
        "a reward mint executes only at GLOBAL, whose archives hold every frame"
    );
}
