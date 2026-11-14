//! What an arriving submission costs this node before anything checked it
//! could still execute. These tests use only interfaces of the release
//! base, so they show its outcome there. They count what the node's
//! admission queue took ([`crate::admission_verify::global`]), so each runs
//! in its own process (nextest).
use super::*;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// An application engine over an execution manager with no proof worker,
/// and its collector.
fn engine_with_execution() -> (AppConsensusEngine, Arc<MessageCollector>) {
    let collector = Arc::new(MessageCollector::new());
    let engine = engine_on(
        quil_execution::domains::QUIL_TOKEN.to_vec(),
        collector.clone(),
    );
    (engine, collector)
}

/// [`engine_with_execution`] for shard `filter` over `collector`, as a worker
/// keeps its pool when it moves to another shard of the application.
fn engine_on(filter: Vec<u8>, collector: Arc<MessageCollector>) -> AppConsensusEngine {
    let rocks = quil_store::RocksDb::open_in_memory().unwrap();
    let store = Arc::new(quil_store::RocksHypergraphStore::new(rocks.inner()));
    let prover = Arc::new(quil_types::crypto::NoopInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, prover.clone()));
    let clock = Arc::new(quil_store::RocksClockStore::new(rocks.inner()));
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
        prover.clone(),
        crypto.key_manager,
        crdt.clone(),
        crypto.circuit_compiler,
        clock.clone(),
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
        false,
    ));
    // Jobs the node's admission queue still holds keep this manager, and
    // its stores, alive; its thread may drop the last one while the test
    // process exits, closing RocksDB during static teardown ("pthread lock:
    // Invalid argument"). Keep it for the process instead, as the node's
    // own exit does.
    std::mem::forget(manager.clone());
    let (events, _received) = mpsc::unbounded_channel();
    let private = [7; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
    let deps = AppEngineDeps {
        delivery_frame_source: None,
        clock_store: clock,
        global_anchor_store: None,
        global_hypergraph: None,
        prover_registry: Arc::new(crate::test_support::TestProverRegistry::new()),
        frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        message_collector: collector.clone(),
        fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
        local_prover_address: vec![1; 32],
        local_bls_pubkey: vec![],
        bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
        reward_greedy: false,
        min_active_provers_for_propose: 1,
        coverage_publish: None,
        hypergraph: Some(crdt),
        storage_source_hypergraph: None,
        topology: None,
        execution_engine: Some(manager),
        inclusion_prover: Some(prover),
        kv_db: None,
        db_config: Default::default(),
        unified_cutover_hook: None,
    };
    let (engine, _) = AppConsensusEngine::new(1, filter, deps, events);
    engine
}

/// A canonical bundle of one confidential transfer of the QUIL token,
/// distinct per `n`: a valid carrier header (type, version, network,
/// application), so the bundle survives the wire conversion an arrival goes
/// through, and an arbitrary body.
fn transfer_bundle(n: u32) -> Vec<u8> {
    let tp = quil_execution::token_engine::TYPE_LATTICE_TRANSACTION;
    let mut inner = tp.to_be_bytes().to_vec();
    inner.extend_from_slice(b"QCT3TX\0\x02");
    inner.extend_from_slice(&[1; 32]);
    inner.extend_from_slice(&quil_execution::domains::QUIL_TOKEN);
    inner.extend_from_slice(&n.to_le_bytes());
    inner.extend_from_slice(&[0x44; 2048]);
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest {
            inner_type_prefix: tp,
            inner_bytes: inner,
        })],
        timestamp: 1,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// Whether this build counts confidential operations (the workspace builds
/// `quil-execution` with its native prover).
fn counts_confidential(bundle: &[u8]) -> bool {
    quil_execution::ExecutionEngineManager::confidential_operation_count(
        &quil_execution::domains::QUIL_TOKEN,
        bundle,
    ) > 0
}

/// A submission a finalized frame already consumed is not verified again
/// when it arrives again; a new one is.
#[tokio::test]
async fn a_submission_a_finalized_frame_consumed_is_not_verified_again_on_arrival() {
    let (mut engine, collector) = engine_with_execution();
    if !counts_confidential(&transfer_bundle(0)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let queue = crate::admission_verify::global();
    let before = queue.stats().queued;
    engine.add_app_message(&transfer_bundle(1));
    assert_eq!(
        queue.stats().queued,
        before + 1,
        "a new confidential submission is queued on arrival"
    );
    let replay = transfer_bundle(2);
    collector.mark_finalized(&[canonical_app_message(&replay)]);
    engine.add_app_message(&replay);
    assert_eq!(
        queue.stats().queued,
        before + 1,
        "a replayed finalized op was verified again: its arrival was queued for proof verification"
    );
}

/// Arrivals queue at most the admission queue's budget of estimated
/// verification time per window: one thread, 600 worker-seconds, at the
/// 8 s estimate of an operation of a size class not measured yet.
#[tokio::test]
async fn arrivals_queue_at_most_their_budget_of_verification_time() {
    let (mut engine, _collector) = engine_with_execution();
    if !counts_confidential(&transfer_bundle(0)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let queue = crate::admission_verify::global();
    let before = queue.stats().queued;
    const ARRIVALS: u32 = 200;
    for n in 0..ARRIVALS {
        engine.add_app_message(&transfer_bundle(1000 + n));
    }
    let queued = queue.stats().queued - before;
    assert!(
        queued <= 80,
        "arrival verification exceeded its per-interval budget: {queued} of {ARRIVALS} arrivals \
         queued at about 8 s each against 600 worker-seconds"
    );
    assert!(queued >= 70, "the budget admits what fits: {queued} queued");
}

/// The longest shield this test sends: a carrier of 1 MiB does not pass the
/// wire conversion an arrival goes through.
const LONG_SHIELD: usize = (1 << 20) - (1 << 10);
/// Long shields that overflow the 64 MiB rank buffer.
const OVERFLOW: u32 = 66;

/// A canonical bundle of one batch shield of the QUIL token consuming
/// `source` first, distinct per `n`, about `bytes` long: its carrier header,
/// type and version tags and its source are what routing reads, and the rest
/// is arbitrary.
fn shield_bundle(source: [u8; 32], n: u32, bytes: usize) -> Vec<u8> {
    let mut inner = shield_inner(source, n);
    inner.resize(bytes.max(inner.len()), 0x44);
    token_bundle(inner)
}

fn shield_inner(source: [u8; 32], n: u32) -> Vec<u8> {
    let tp = quil_execution::token_engine::TYPE_LATTICE_SHIELD;
    let mut inner = tp.to_be_bytes().to_vec();
    inner.extend_from_slice(b"QCT3SH\0\x03");
    inner.extend_from_slice(&[1; 32]);
    inner.extend_from_slice(&quil_execution::domains::QUIL_TOKEN);
    inner.extend_from_slice(&[0x22; 57]);
    inner.extend_from_slice(&96u16.to_be_bytes());
    inner.extend_from_slice(&source);
    inner.extend_from_slice(&n.to_le_bytes());
    inner
}

fn token_bundle(inner: Vec<u8>) -> Vec<u8> {
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest {
            inner_type_prefix: quil_execution::token_engine::TYPE_LATTICE_SHIELD,
            inner_bytes: inner,
        })],
        timestamp: 1,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// Shard filter of the QUIL token at `bits`.
fn token_shard(bits: &[bool]) -> Vec<u8> {
    quil_forest::encode_shard_bit_path(&quil_execution::domains::QUIL_TOKEN, bits)
}

/// A coin address whose first bits are `bits`.
fn source_under(bits: &[bool], n: u8) -> [u8; 32] {
    let mut source = [n; 32];
    for (index, bit) in bits.iter().enumerate() {
        if *bit {
            source[index / 8] |= 0x80 >> (index % 8);
        } else {
            source[index / 8] &= !(0x80 >> (index % 8));
        }
    }
    source
}

/// 2026-11-02: every worker held bundles only another shard can propose until
/// its 64 MiB rank buffer refused the ones its own shard had to propose,
/// which were lost on that worker and skipped their arrival verification.
#[tokio::test]
async fn shields_only_another_shard_proposes_do_not_refuse_this_shards_own() {
    let shard = token_shard(&[false]);
    let (elsewhere, own) = (source_under(&[true], 1), source_under(&[false], 2));
    let collector = Arc::new(MessageCollector::new());
    let mut engine = engine_on(shard, collector.clone());
    if !counts_confidential(&shield_bundle(own, 0, 1 << 10)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    for n in 0..OVERFLOW {
        engine.add_app_message(&shield_bundle(elsewhere, n, LONG_SHIELD));
    }
    let held = collector.total_pending();
    engine.add_app_message(&shield_bundle(own, 1000, LONG_SHIELD));
    assert_eq!(
        collector.total_pending(),
        held + 1,
        "this shard's own shield was refused: {held} bundles only another shard can propose \
         filled its rank buffer"
    );
}

/// A shield is held only where it can be proposed; a submission that any
/// shard may carry past the routing fallback, and a shield whose source this
/// node cannot read, are held on every shard as before.
#[tokio::test]
async fn a_shield_is_collected_only_on_the_shard_holding_its_source() {
    let holding = [false, true];
    let source = source_under(&holding, 3);
    let shards: Vec<Vec<bool>> = vec![
        vec![false, false],
        vec![false, true],
        vec![true, false],
        vec![true, true],
    ];
    if !counts_confidential(&shield_bundle(source, 0, 1 << 10)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    for bits in &shards {
        let collector = Arc::new(MessageCollector::new());
        let mut engine = engine_on(token_shard(bits), collector.clone());
        engine.add_app_message(&shield_bundle(source, 1, 1 << 10));
        assert_eq!(
            collector.total_pending(),
            usize::from(bits.as_slice() == holding),
            "shard {bits:?} of a shield whose source is under {holding:?}"
        );
        engine.add_app_message(&transfer_bundle(1));
        // Cut before its source: the carrier passes, the source cannot be read.
        let mut unreadable = shield_inner(source, 2);
        unreadable.truncate(100);
        engine.add_app_message(&token_bundle(unreadable));
        assert_eq!(
            collector.total_pending(),
            usize::from(bits.as_slice() == holding) + 2,
            "shard {bits:?} dropped a transfer or a shield with no readable source"
        );
    }
    // The application's one shard holds every source.
    let collector = Arc::new(MessageCollector::new());
    let mut engine = engine_on(
        quil_execution::domains::QUIL_TOKEN.to_vec(),
        collector.clone(),
    );
    engine.add_app_message(&shield_bundle(source, 1, 1 << 10));
    assert_eq!(collector.total_pending(), 1, "an unsplit application");
}

/// A split while a shield is held: the members' pools go with them, so the
/// child holding the source proposes it, and it never leaves a sibling's pool
/// for this; a merge brings it back within the merged shard's range. New
/// arrivals on a child follow the child's range.
#[tokio::test]
async fn a_held_shield_follows_splits_and_merges_to_its_proposer() {
    let (parent, left, right) = (
        token_shard(&[false]),
        token_shard(&[false, false]),
        token_shard(&[false, true]),
    );
    let (under_left, under_right) = (
        source_under(&[false, false], 4),
        source_under(&[false, true], 5),
    );
    let collector = Arc::new(MessageCollector::new());
    if !counts_confidential(&shield_bundle(under_left, 0, 1 << 10)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let mut engine = engine_on(parent.clone(), collector.clone());
    engine.add_app_message(&shield_bundle(under_left, 1, 1 << 10));
    engine.add_app_message(&shield_bundle(under_right, 2, 1 << 10));
    assert_eq!(collector.total_pending(), 2, "the parent holds both");
    // The worker moves to the left child with its pool (`thread_worker`).
    collector.rebase_ranks();
    let mut child = engine_on(left.clone(), collector.clone());
    assert_eq!(collector.total_pending(), 2, "a split drops nothing");
    let proposes = |shard: &[u8], source: [u8; 32]| {
        routed_selection(
            shard,
            &[left.clone(), right.clone()],
            &[[9; 32]],
            &[1],
            &[Some(source)],
            &[std::time::Duration::ZERO],
            ROUTED_FALLBACK,
        )[0]
    };
    assert!(proposes(&left, under_left));
    assert!(!proposes(&left, under_right));
    assert!(proposes(&right, under_right));
    child.add_app_message(&shield_bundle(under_right, 3, 1 << 10));
    assert_eq!(collector.total_pending(), 2, "the sibling's new arrival");
    child.add_app_message(&shield_bundle(under_left, 4, 1 << 10));
    assert_eq!(collector.total_pending(), 3, "its own new arrival");
    // The children merge: the merged shard proposes what either held.
    collector.rebase_ranks();
    let _merged = engine_on(parent.clone(), collector.clone());
    assert_eq!(collector.total_pending(), 3, "a merge drops nothing");
    assert!(routed_selection(
        &parent,
        std::slice::from_ref(&parent),
        &[[9; 32], [8; 32]],
        &[1, 1],
        &[Some(under_left), Some(under_right)],
        &[std::time::Duration::ZERO; 2],
        ROUTED_FALLBACK,
    )
    .iter()
    .all(|keep| *keep));
}

/// The rank buffer still bounds a shard's own shields, and it recovers: past
/// the cap they are refused, and once a frame consumed some, arrivals are
/// collected again.
#[tokio::test]
async fn a_shard_full_of_its_own_shields_collects_again_once_one_executes() {
    let own = source_under(&[false], 6);
    let collector = Arc::new(MessageCollector::new());
    let mut engine = engine_on(token_shard(&[false]), collector.clone());
    if !counts_confidential(&shield_bundle(own, 0, 1 << 10)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let first = shield_bundle(own, 0, LONG_SHIELD);
    engine.add_app_message(&first);
    for n in 1..OVERFLOW {
        engine.add_app_message(&shield_bundle(own, n, LONG_SHIELD));
    }
    let held = collector.total_pending();
    assert!(
        held > 1 && held < OVERFLOW as usize,
        "the cap held {held} of {OVERFLOW} long shields"
    );
    engine.add_app_message(&shield_bundle(own, 1000, LONG_SHIELD));
    assert_eq!(collector.total_pending(), held, "full: refused");
    collector.mark_finalized(&[canonical_app_message(&first)]);
    assert_eq!(collector.total_pending(), held - 1);
    engine.add_app_message(&shield_bundle(own, 1000, LONG_SHIELD));
    assert_eq!(
        collector.total_pending(),
        held,
        "a frame consumed one, and the shard still refuses its shields"
    );
}

/// The arrival lines are bounded, so what came after the last one must reach
/// the log when arrivals stop, or a flood's end is lost.
#[tokio::test]
async fn the_last_count_of_shields_left_to_other_shards_is_logged_when_they_stop() {
    let every = SHIELDS_ELSEWHERE_LOG_EVERY;
    let elsewhere = source_under(&[true], 1);
    let collector = Arc::new(MessageCollector::new());
    let mut engine = engine_on(token_shard(&[false]), collector);
    if !counts_confidential(&shield_bundle(elsewhere, 0, 1 << 10)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let logs = crate::outage::test_logs::CapturedLogs::default();
    let _guard = logs.install();
    let text = "shields for other shards left uncollected";
    for n in 0..3 {
        engine.add_app_message(&shield_bundle(elsewhere, n, 1 << 10));
    }
    assert_eq!(logs.lines_with(text).len(), 1, "the first one reports");
    engine.report_arrivals_left();
    assert_eq!(
        logs.lines_with(text).len(),
        1,
        "bounded: none before it is due"
    );
    engine.shields_elsewhere.logged = std::time::Instant::now().checked_sub(every);
    engine.report_arrivals_left();
    let lines = logs.lines_with(text);
    assert_eq!(lines.len(), 2, "the last count was lost: {lines:?}");
    assert!(lines[1].contains("shields=2"), "{}", lines[1]);
    engine.shields_elsewhere.logged = std::time::Instant::now().checked_sub(every);
    engine.report_arrivals_left();
    assert_eq!(logs.lines_with(text).len(), 2, "nothing left to report");
}

#[test]
fn the_last_count_of_refused_arrivals_is_logged_when_they_stop() {
    let every = SHIELDS_ELSEWHERE_LOG_EVERY;
    let logs = crate::outage::test_logs::CapturedLogs::default();
    let _guard = logs.install();
    let text = "refused on arrival since the last line";
    let mut refused = MalformedArrivals::default();
    for _ in 0..3 {
        refused.note(b"filter", 10);
    }
    assert_eq!(logs.lines_with(text).len(), 1, "the first one reports");
    refused.report(b"filter");
    assert_eq!(
        logs.lines_with(text).len(),
        1,
        "bounded: none before it is due"
    );
    refused.logged = std::time::Instant::now().checked_sub(every);
    refused.report(b"filter");
    let lines = logs.lines_with(text);
    assert_eq!(lines.len(), 2, "the last count was lost: {lines:?}");
    assert!(lines[1].contains("submissions=2"), "{}", lines[1]);
    assert!(lines[1].contains("bytes=20"), "{}", lines[1]);
    refused.logged = std::time::Instant::now().checked_sub(every);
    refused.report(b"filter");
    assert_eq!(logs.lines_with(text).len(), 2, "nothing left to report");
}

/// A shield of legacy coin `source` by the key derived from `owner`, told
/// apart by `seed` (its output): structurally valid, signed by that key when
/// `signed`, with no valid proof.
fn owned_shield(owner: u8, source: [u8; 32], seed: u8, signed: bool) -> Vec<u8> {
    use quil_lattice_ct::confidential::{
        relation::membership::IDENTITY_BYTES,
        shield::{Shield, ShieldStatement},
        transfer::{parameter_context, Output, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    use quil_types::crypto::Signer as _;
    let (network, application) = ([1; 32], quil_execution::domains::QUIL_TOKEN);
    let context = parameter_context(&network, &application);
    let private = [owner; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
    let statement = ShieldStatement {
        network,
        application,
        transparent_address: source,
        owner_public_key: public.clone().try_into().unwrap(),
        amount: 12,
        fee: 2,
        outputs: vec![Output {
            commitment: CommitmentKey::derive(&context)
                .commit(10, &AmountOpening::from_seed(&context, &[seed; 32])),
            owner: [seed; IDENTITY_BYTES],
            memo: [6; MEMO_BYTES],
        }],
    };
    let signature = if signed {
        quil_crypto::Ed448Signer::from_bytes(&private, &public)
            .unwrap()
            .sign(&statement.context_bytes().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    } else {
        [0; 114]
    };
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    Shield {
        statement,
        signature,
        proof,
    }
    .encode()
    .unwrap()
}

/// Once a coin's shield commits, the global commit holds its source as
/// consumed, and any other shield of it can only be rejected there, free of
/// charge. Such a shield is neither collected nor queued for proof
/// verification on arrival: otherwise the shard proposes it, and the shard
/// and every archive verify its proof (minutes of CPU each, GLOBAL waiting on
/// the archives) for nothing.
#[tokio::test]
async fn a_reshield_of_a_consumed_source_is_neither_collected_nor_verified_on_arrival() {
    use quil_execution::token_intrinsic::{global_commit, spend_entries};
    let (mut engine, collector) = engine_with_execution();
    let source = [3; 32];
    let (first, second) = (
        owned_shield(9, source, 1, false),
        owned_shield(9, source, 2, false),
    );
    if !counts_confidential(&token_bundle(first.clone())) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let queue = crate::admission_verify::global();
    let (queued, held) = (queue.stats().queued, collector.total_pending());
    engine.add_app_message(&token_bundle(first.clone()));
    assert_eq!(
        (queue.stats().queued, collector.total_pending()),
        (queued + 1, held + 1),
        "a new shield is collected and verified on arrival"
    );
    // A frame carried it, and the global commit consumed its source.
    collector.mark_finalized(&[canonical_app_message(&token_bundle(first.clone()))]);
    let state = quil_execution::hypergraph_state::HypergraphState::new(
        engine.execution_engine.as_ref().unwrap().crdt(),
    );
    let application = quil_execution::domains::QUIL_TOKEN;
    let entry = spend_entries::spend_entry(
        &[1; 32],
        &application,
        quil_execution::token_engine::TYPE_LATTICE_SHIELD,
        &first,
        40,
    )
    .unwrap();
    assert!(matches!(
        global_commit::commit_entry(
            &state,
            100,
            &application,
            &entry,
            quil_types::execution::ShardPath::WHOLE,
        )
        .unwrap(),
        global_commit::Outcome::Committed { .. }
    ));
    state.commit().unwrap();
    state.abort();

    let (queued, held) = (queue.stats().queued, collector.total_pending());
    engine.add_app_message(&token_bundle(second));
    let (queued_now, held_now) = (queue.stats().queued, collector.total_pending());
    assert!(
        queued_now == queued && held_now == held,
        "VULNERABLE: re-shield of a consumed source passed arrival: collected ({held} -> \
         {held_now} held) and queued for proof verification ({queued} -> {queued_now} queued)"
    );
}

/// A coin's owner has one shield of it pending on its shard at a time:
/// another shield of the coin signed by the same key is refused while the
/// first is held, and once a finalized frame carried the first, while the
/// global commit decides it. Otherwise each copy is verified and proposed,
/// and all but one are rejected by the global commit, free of charge. Only a
/// shield its key signed holds a coin, so a forged one cannot keep the
/// owner's out, and no key's shield keeps another key's out.
#[tokio::test]
async fn an_owner_has_one_shield_of_a_coin_pending_at_a_time() {
    let (mut engine, collector) = engine_with_execution();
    let source = [3; 32];
    if !counts_confidential(&token_bundle(owned_shield(9, source, 1, true))) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    engine.add_app_message(&token_bundle(owned_shield(9, source, 1, false)));
    assert_eq!(collector.total_pending(), 1);
    let first = token_bundle(owned_shield(9, source, 2, true));
    engine.add_app_message(&first);
    assert_eq!(
        collector.total_pending(),
        2,
        "a forged shield kept its key's own out"
    );
    engine.add_app_message(&token_bundle(owned_shield(8, source, 3, true)));
    assert_eq!(
        collector.total_pending(),
        3,
        "a key's pending shield kept another key's out"
    );
    engine.add_app_message(&token_bundle(owned_shield(9, source, 4, true)));
    let pending = collector.total_pending();
    collector.mark_finalized(&[canonical_app_message(&first)]);
    engine.add_app_message(&token_bundle(owned_shield(9, source, 5, true)));
    let carried = collector.total_pending();
    assert!(
        pending == 3 && carried == 2,
        "VULNERABLE: another shield of a coin by its owner was collected while the first was \
         pending ({pending} held, 3 expected) or awaited its GLOBAL decision ({carried} held, \
         2 expected)"
    );
}

/// The owner's signature covers a shield's statement, not its proof, so
/// anyone who sees a shield can send copies of it with other proof bytes. A
/// copy that reaches a shard first must not keep the owner's own shield out
/// of its mempool: the copies make the same statement, and only a proof
/// decides which of them executes.
#[tokio::test]
async fn a_copy_of_a_shield_with_other_proof_bytes_does_not_keep_the_shield_out() {
    let (mut engine, collector) = engine_with_execution();
    let source = [3; 32];
    let shield = owned_shield(9, source, 1, true);
    if !counts_confidential(&token_bundle(shield.clone())) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    // The proof ends the encoding: the copy differs in its last proof byte.
    let mut copy = shield.clone();
    *copy.last_mut().unwrap() ^= 1;
    engine.add_app_message(&token_bundle(copy));
    assert_eq!(collector.total_pending(), 1, "the copy is collected");
    engine.add_app_message(&token_bundle(shield));
    let held = collector.total_pending();
    assert!(
        held == 2,
        "VULNERABLE: a copy of an owner's signed shield with other proof bytes, arriving \
         first, kept the owner's own shield out of the mempool ({held} held, 2 expected): \
         refused as another shield of the coin by the same key"
    );
    // The owner's one pending shield still holds the coin against another
    // statement of the same key.
    engine.add_app_message(&token_bundle(owned_shield(9, source, 2, true)));
    assert_eq!(collector.total_pending(), 2, "another statement of the key");
}

/// A canonical bundle of one confidential transfer of the QUIL token proving
/// membership against root `root`, told apart by `seed`: structurally
/// valid, no valid proof.
fn rooted_transfer_bundle(root: u8, seed: u8) -> Vec<u8> {
    use quil_lattice_ct::confidential::{
        relation::membership::{Node, IDENTITY_BYTES, NODE_BYTES},
        transfer::{parameter_context, Output, Transfer, TransferStatement, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    let (network, application) = ([1; 32], quil_execution::domains::QUIL_TOKEN);
    let context = parameter_context(&network, &application);
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let inner = Transfer {
        statement: TransferStatement {
            network,
            application,
            depth: 1,
            root: Node::from_bytes(&[root; NODE_BYTES]).unwrap(),
            images: vec![[seed; IDENTITY_BYTES]],
            outputs: vec![Output {
                commitment: CommitmentKey::derive(&context)
                    .commit(10, &AmountOpening::from_seed(&context, &[seed; 32])),
                owner: [seed; IDENTITY_BYTES],
                memo: [6; MEMO_BYTES],
            }],
            fee: 2,
        },
        proof,
    }
    .encode()
    .unwrap();
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest {
            inner_type_prefix: quil_execution::token_engine::TYPE_LATTICE_TRANSACTION,
            inner_bytes: inner,
        })],
        timestamp: 1,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// Publish root `root` (depth 1) into the QUIL token's canonical root
/// history in `crdt`, as GLOBAL does.
fn publish_root(crdt: Arc<quil_hypergraph::HypergraphCrdt>, root: u8) {
    use quil_lattice_ct::confidential::{
        coin_tree::RootRecord,
        relation::membership::{Node, NODE_BYTES},
        transfer::parameter_context,
    };
    let application = quil_execution::domains::QUIL_TOKEN;
    let state = quil_execution::hypergraph_state::HypergraphState::new(crdt);
    quil_execution::token_intrinsic::global_accumulator::publish_root_for_tests(
        &state,
        1,
        &application,
        RootRecord {
            context: parameter_context(&[1; 32], &application),
            depth: 1,
            coins: 1,
            root: Node::from_bytes(&[root; NODE_BYTES]).unwrap(),
        },
    )
    .unwrap();
    state.commit().unwrap();
    state.abort();
}

/// A submission naming a root this node's GLOBAL view does not hold (one
/// GLOBAL never published, or one the view has not caught up to) is
/// collected but not verified on arrival: verified, it would cost this node
/// minutes of CPU for what the global commit may only reject. Once the view
/// holds the root, submissions citing it are verified on arrival again.
#[tokio::test]
async fn a_submission_naming_a_root_this_node_lacks_is_collected_but_not_verified() {
    let (mut engine, collector) = engine_with_execution();
    if !counts_confidential(&rooted_transfer_bundle(3, 1)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    let crdt = engine.execution_engine.as_ref().unwrap().crdt();
    publish_root(crdt.clone(), 3);
    let queue = crate::admission_verify::global();
    let (queued, held) = (queue.stats().queued, collector.total_pending());
    engine.add_app_message(&rooted_transfer_bundle(9, 2));
    let (queued_now, held_now) = (queue.stats().queued, collector.total_pending());
    assert!(
        held_now == held + 1 && queued_now == queued,
        "a submission naming a root this node lacks: collected ({held} -> {held_now} held, 1 \
         more expected), verified on arrival ({queued} -> {queued_now} queued, none expected)"
    );
    publish_root(crdt, 9);
    engine.add_app_message(&rooted_transfer_bundle(9, 3));
    assert_eq!(
        (queue.stats().queued, collector.total_pending()),
        (queued_now + 1, held_now + 1),
        "once the view holds the root, a submission citing it is collected and verified"
    );
}

/// Whether `shard` of `shards` is designated to propose `bundle` first.
fn designated_on(shards: &[Vec<u8>], shard: &[u8], bundle: &[u8]) -> bool {
    let digest = crate::admission_verify::digest(&canonical_app_message(bundle));
    arrival_designated(shard, Some(shards), &digest, None)
}

/// Holds the node's admission queue thread on a job until the returned
/// sender drops, so what arrives meanwhile stays queued.
fn hold_admission_thread() -> std::sync::mpsc::Sender<()> {
    let queue = crate::admission_verify::global();
    let (release, held) = std::sync::mpsc::channel::<()>();
    let held = std::sync::Mutex::new(held);
    let job: crate::admission_verify::AdmissionJob = Arc::new(move || {
        let _ = held.lock().unwrap().recv();
        quil_execution::manager::PreverifyCounts::default()
    });
    let blocker = [0xb1; 32];
    assert!(queue.offer(blocker, 1, 1, job, true));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while queue.queued_ahead(&blocker).is_some() {
        assert!(
            std::time::Instant::now() < deadline,
            "the admission queue's thread never took the holding job"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    release
}

/// Mainnet, 2026-11-10: frames of a node's shards waited 2-4 minutes on
/// bundles that had reached the node minutes earlier, unverified because
/// none of its shards was designated to propose them. Such an arrival is
/// now verified, once for the node: whichever of its shards it reaches
/// next is charged nothing and queues nothing again.
#[tokio::test]
async fn an_undesignated_arrival_is_queued_once_whichever_of_this_nodes_shards_it_reaches() {
    let shards = vec![
        token_shard(&[false, false]),
        token_shard(&[false, true]),
        token_shard(&[true, false]),
    ];
    let bundle = (0..)
        .map(transfer_bundle)
        .find(|bundle| designated_on(&shards, &shards[2], bundle))
        .unwrap();
    if !counts_confidential(&bundle) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    note_routing_shards(&quil_execution::domains::QUIL_TOKEN, &shards);
    let mut first = engine_on(shards[0].clone(), Arc::new(MessageCollector::new()));
    let mut second = engine_on(shards[1].clone(), Arc::new(MessageCollector::new()));
    let queue = crate::admission_verify::global();
    let release = hold_admission_thread();
    let before = queue.stats();
    first.add_app_message(&bundle);
    let once = queue.stats();
    assert_eq!(
        once.queued,
        before.queued + 1,
        "undesignated_not_queued: a bundle no shard of this node is designated to propose was not \
         verified on arrival"
    );
    assert!(once.arrival_secs > before.arrival_secs);
    second.add_app_message(&bundle);
    let twice = queue.stats();
    assert_eq!(
        (twice.queued, twice.arrival_secs),
        (once.queued, once.arrival_secs),
        "charged_twice: the bundle reaching another shard of this node was queued or charged again"
    );
    let digest = crate::admission_verify::digest(&canonical_app_message(&bundle));
    assert!(queue.pending(&digest));
    assert_eq!(
        crate::admission_verify::arrival(&digest).map(|(_, verdict)| verdict),
        Some(crate::admission_verify::ArrivalVerdict::Queued)
    );
    drop(release);
}

/// Undesignated arrivals take at most their share of the arrival budget: a
/// flood of them arriving first never refuses a bundle this node's shard
/// is designated to propose.
#[tokio::test]
async fn a_designated_arrival_is_queued_however_many_undesignated_ones_arrived_first() {
    let shards = vec![token_shard(&[false]), token_shard(&[true])];
    let (elsewhere, own) = (&shards[0], &shards[1]);
    if !counts_confidential(&transfer_bundle(0)) {
        eprintln!("skipped: needs quil-execution's native prover (workspace build)");
        return;
    }
    note_routing_shards(&quil_execution::domains::QUIL_TOKEN, &shards);
    let mut other = engine_on(elsewhere.clone(), Arc::new(MessageCollector::new()));
    let mut proposer = engine_on(own.clone(), Arc::new(MessageCollector::new()));
    let queue = crate::admission_verify::global();
    let before = queue.stats().queued;
    const FLOOD: usize = 200;
    for bundle in (2000..)
        .map(transfer_bundle)
        .filter(|bundle| designated_on(&shards, own, bundle))
        .take(FLOOD)
    {
        other.add_app_message(&bundle);
    }
    let flooded = queue.stats().queued - before;
    assert!(
        flooded > 0,
        "undesignated_not_queued: none of {FLOOD} undesignated arrivals was verified on arrival"
    );
    let bundle = (5000..)
        .map(transfer_bundle)
        .find(|bundle| designated_on(&shards, own, bundle))
        .unwrap();
    proposer.add_app_message(&bundle);
    let digest = crate::admission_verify::digest(&canonical_app_message(&bundle));
    let verdict = crate::admission_verify::arrival(&digest).map(|(_, verdict)| verdict);
    assert_eq!(
        verdict,
        Some(crate::admission_verify::ArrivalVerdict::Queued),
        "designated_refused: after {flooded} of {FLOOD} undesignated arrivals were queued, the \
         designated shard's own arrival was not"
    );
}
