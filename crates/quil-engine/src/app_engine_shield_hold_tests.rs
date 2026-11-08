//! What a submission nobody can decide costs a shard's mempool, and that real
//! shields outlast a stall. Only interfaces of the release base, so the same
//! file shows the vulnerable outcome there.
use super::*;
use quil_consensus::leader_provider::LeaderProvider as _;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier;

const CAP: usize = 64 * 1024 * 1024;
/// A gossip message of at most this fits `max_transmit_size` (16 MiB).
const GOSSIP_MESSAGE: usize = 15 * 1024 * 1024;
/// A carrier's bound (`token_intrinsic::wire::domain`).
const MAX_CARRIER: usize = 1024 * 1024 - 1;
/// Larger than what any fill below leaves free.
const PROBE: usize = 8 * 1024;
/// Two hours of 10 s ranks.
const STALL_RANKS: u64 = 720;

#[derive(Clone, Copy, PartialEq)]
enum Proofs {
    /// No token policy: confidential operations are not checked or budgeted.
    Unconfigured,
    /// A policy over a worker that cannot run.
    Absent,
    /// A policy over a worker all of whose slots are taken.
    Busy,
    /// A policy over a worker that rejects a proof holding
    /// [`REFUTED_PROOF`] and fails on any other, giving it no verdict.
    Refuting,
}

/// What a proof holds for the [`Proofs::Refuting`] worker to reject it.
const REFUTED_PROOF: &[u8] = b"REFUTEDPROOF";

struct Rig {
    engine: AppConsensusEngine,
    collector: Arc<MessageCollector>,
    leader: AppLeaderProvider,
    registry: Arc<crate::test_support::TestProverRegistry>,
    _slots: Vec<std::fs::File>,
    dir: std::path::PathBuf,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn rig(filter: Vec<u8>, proofs: Proofs) -> Rig {
    let rocks = quil_store::RocksDb::open_in_memory().unwrap();
    let store = Arc::new(quil_store::RocksHypergraphStore::new(rocks.inner()));
    let prover = Arc::new(quil_types::crypto::NoopInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, prover.clone()));
    let clock = Arc::new(quil_store::RocksClockStore::new(rocks.inner()));
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let dir = std::env::temp_dir().join(format!("quil-shield-hold-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut manager = quil_execution::ExecutionEngineManager::new(
        prover.clone(),
        crypto.key_manager,
        crdt.clone(),
        crypto.circuit_compiler,
        clock.clone(),
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
        false,
    );
    let mut slots = Vec::new();
    if proofs != Proofs::Unconfigured {
        let policy = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0);
        let timeout = std::time::Duration::from_secs(2);
        let worker = WorkerVerifier::new(dir.join("absent-worker"), 1, timeout).unwrap();
        let worker = if proofs == Proofs::Refuting {
            use std::os::unix::fs::PermissionsExt;
            let script = dir.join("refuting-worker");
            std::fs::write(
                &script,
                format!(
                    "#!/bin/sh\nin=\"$0.in.$$\"\ncat > \"$in\"\n\
                     if grep -qa {} \"$in\"; then rm -f \"$in\"; exit 81; fi\n\
                     rm -f \"$in\"\nexit 1\n",
                    std::str::from_utf8(REFUTED_PROOF).unwrap()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            WorkerVerifier::new(script, 1, timeout)
                .unwrap()
                .with_concurrency(8)
                .unwrap()
        } else if proofs == Proofs::Busy {
            let path = dir.join("slots");
            let worker = worker
                .with_concurrency(2)
                .unwrap()
                .with_shared_admission(path.clone())
                .unwrap();
            for path in [path, dir.join("slots.1")] {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .unwrap();
                file.try_lock().unwrap();
                slots.push(file);
            }
            worker
        } else {
            worker
        };
        manager = manager.with_token_worker(policy, worker).unwrap();
    }
    let manager = Arc::new(manager);
    // Jobs the node's admission queue still holds keep this manager alive;
    // keep it for the process, as the node's own exit does.
    std::mem::forget(manager.clone());
    let collector = Arc::new(MessageCollector::new());
    let registry = Arc::new(crate::test_support::TestProverRegistry::new());
    let (events, _received) = mpsc::unbounded_channel();
    let private = [7; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
    let deps = AppEngineDeps {
        delivery_frame_source: None,
        clock_store: clock.clone(),
        global_anchor_store: None,
        global_hypergraph: None,
        prover_registry: registry.clone(),
        frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        message_collector: collector.clone(),
        fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
        local_prover_address: vec![1; 32],
        local_bls_pubkey: vec![],
        bls_signer: Box::new(quil_crypto::Ed448Signer::from_bytes(&private, &public).unwrap()),
        reward_greedy: false,
        min_active_provers_for_propose: 1,
        coverage_publish: None,
        hypergraph: Some(crdt.clone()),
        storage_source_hypergraph: None,
        topology: None,
        execution_engine: Some(manager.clone()),
        inclusion_prover: Some(prover.clone()),
        kv_db: None,
        db_config: Default::default(),
        unified_cutover_hook: None,
    };
    let (engine, _) = AppConsensusEngine::new(1, filter.clone(), deps, events);
    // The leader over the same mempool and arrival clock, as the engine
    // builds it.
    let leader = AppLeaderProvider {
        filter: filter.clone(),
        clock_store: clock.clone(),
        frame_outflows: Arc::new(std::sync::Mutex::new(Default::default())),
        global_anchor_store: clock,
        frame_prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        prover_registry: registry.clone(),
        message_collector: collector.clone(),
        mempool: collector.clone(),
        fee_manager: Arc::new(crate::fees::InMemoryDynamicFeeManager::new(10)),
        local_prover_address: vec![1; 32],
        local_public_key: vec![],
        current_difficulty: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        reward_greedy: false,
        hypergraph: Some(crdt),
        storage_source_hypergraph: None,
        shard_drain: None,
        execution_engine: Some(manager),
        inclusion_prover: Some(prover),
        app_address: filter,
        halted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        min_active_provers_for_propose: 0,
        shard_mat_frame: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        frame_requests: Arc::new(std::sync::Mutex::new(Default::default())),
        kv_db: None,
        frame_attestations: Arc::new(std::sync::Mutex::new(Default::default())),
        replicas_retired_below: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        routing_seen: engine.routing_seen.clone(),
        instance_committee_fp: None,
        session_genesis: None,
        under_session: false,
        session_closing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        private_parent: false,
    };
    Rig {
        engine,
        collector,
        leader,
        registry,
        _slots: slots,
        dir,
    }
}

/// This shard's leader takes its turn at `rank`, whatever the rest of the
/// proposal comes to: the mempool's fate is settled before it builds a frame.
fn turn(leader: &AppLeaderProvider, rank: u64) {
    let genesis = quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap();
    let id: quil_consensus::models::Identity = genesis.to_vec();
    let _ = leader.prove_next_state(rank, &leader.filter, 0, &id);
}

/// A shard of the QUIL token holding addresses with the top bit `high`.
fn half(high: bool) -> Vec<u8> {
    quil_forest::encode_shard_bit_path(&quil_execution::domains::QUIL_TOKEN, &[high])
}

fn network() -> [u8; 32] {
    quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0).network
}

/// A batch shield with only a valid carrier header: type, version, network,
/// application, an arbitrary owner, `source` first. No proof, no signature, no
/// fee, no such coin; `pad` arbitrary bytes.
fn junk_shield(n: u64, source: [u8; 32], pad: usize) -> Vec<u8> {
    let tp = quil_execution::token_engine::TYPE_LATTICE_SHIELD;
    let mut inner = tp.to_be_bytes().to_vec();
    inner.extend_from_slice(b"QCT3SH\0\x03");
    inner.extend_from_slice(&network());
    inner.extend_from_slice(&quil_execution::domains::QUIL_TOKEN);
    inner.extend_from_slice(&[9; 57]);
    inner.extend_from_slice(&1u16.to_le_bytes());
    inner.extend_from_slice(&source);
    inner.extend_from_slice(&n.to_be_bytes());
    inner.resize(inner.len() + pad, 0x44);
    inner
}

/// A confidential transfer carrier of `pad` arbitrary bytes.
fn junk_transfer(n: u64, pad: usize) -> Vec<u8> {
    let tp = quil_execution::token_engine::TYPE_LATTICE_TRANSACTION;
    let mut inner = tp.to_be_bytes().to_vec();
    inner.extend_from_slice(b"QCT3TX\0\x02");
    inner.extend_from_slice(&network());
    inner.extend_from_slice(&quil_execution::domains::QUIL_TOKEN);
    inner.extend_from_slice(&n.to_be_bytes());
    inner.resize(inner.len() + pad, 0x55);
    inner
}

/// A single shield that passes every check before its proof: of a legacy
/// coin its key owns, written into the rig's store in the rig's shard, and
/// signed by that key. Its proof is not valid, as a replayed one's is not.
/// A coin's content address is a BN254 element (big-endian, below
/// `0x3064..`), so every legacy coin lies in `half(false)`.
fn formed_shield(rig: &Rig) -> Vec<u8> {
    formed_shield_with(rig, 2, &[])
}

/// [`formed_shield`] of the same coin and key, its statement told apart by
/// `opening` (its output's opening seed) and its proof by `proof_tail`.
fn formed_shield_with(rig: &Rig, opening: u8, proof_tail: &[u8]) -> Vec<u8> {
    use quil_execution::token_intrinsic::{legacy_migration, materialize};
    use quil_lattice_ct::confidential::{
        relation::membership::IDENTITY_BYTES,
        shield::{Shield, ShieldStatement},
        transfer::{parameter_context, Output, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    use quil_types::crypto::Signer as _;
    let application = quil_execution::domains::QUIL_TOKEN;
    let private = [23; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
    let coin = legacy_migration::TransparentCoin {
        owner_address: quil_crypto::poseidon::hash_bytes_to_32(&public).unwrap(),
        amount: 12,
    };
    let type_hash = legacy_migration::transparent_type_hash(&application).unwrap();
    let (source, tree) = (0..=u8::MAX)
        .map(|salt| {
            let tree =
                legacy_migration::create_transparent_coin_tree(&coin, &type_hash, &[salt; 32])
                    .unwrap();
            (materialize::coin_content_address(&tree).unwrap(), tree)
        })
        .find(|(address, _)| shard_covers(&rig.leader.filter, address))
        .expect("no legacy coin lies in the rig's shard");
    let state = quil_execution::hypergraph_state::HypergraphState::new(
        rig.engine.execution_engine.as_ref().unwrap().crdt(),
    );
    state
        .set(
            &application,
            &source,
            &quil_execution::hypergraph_state::vertex_adds_discriminator().unwrap(),
            1,
            quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
        )
        .unwrap();
    state.commit().unwrap();
    state.abort();
    let context = parameter_context(&network(), &application);
    let key = CommitmentKey::derive(&context);
    let opening = AmountOpening::from_seed(&context, &[opening; 32]);
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    proof[8..8 + proof_tail.len()].copy_from_slice(proof_tail);
    let statement = ShieldStatement {
        network: network(),
        application,
        transparent_address: source,
        owner_public_key: public.clone().try_into().unwrap(),
        amount: 12,
        fee: 2,
        outputs: vec![Output {
            commitment: key.commit(10, &opening),
            owner: [5; IDENTITY_BYTES],
            memo: [6; MEMO_BYTES],
        }],
    };
    let signature = quil_crypto::Ed448Signer::from_bytes(&private, &public)
        .unwrap()
        .sign(&statement.context_bytes().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    Shield {
        statement,
        signature,
        proof,
    }
    .encode()
    .unwrap()
}

fn bundle(requests: Vec<Vec<u8>>) -> Vec<u8> {
    let requests = requests
        .into_iter()
        .map(|inner| {
            let inner_type_prefix = u32::from_be_bytes(inner[..4].try_into().unwrap());
            Some(CanonicalMessageRequest {
                inner_type_prefix,
                inner_bytes: inner,
            })
        })
        .collect();
    CanonicalMessageBundle {
        requests,
        timestamp: 1,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// Offer gossip-sized bundles of junk shields of `source` until the rank cap
/// is full or the shard stops taking them; the messages offered.
fn flood(rig: &mut Rig, source: [u8; 32]) -> usize {
    let mut messages = 0;
    let mut n = 0u64;
    loop {
        let (_, bytes) = rig.collector.pending_totals();
        let room = CAP - bytes;
        if room < 4096 {
            return messages;
        }
        let mut left = room.min(GOSSIP_MESSAGE) - 2048;
        let mut requests = Vec::new();
        while left > 1024 {
            let pad = left.min(MAX_CARRIER - 512) - 512;
            n += 1;
            requests.push(junk_shield(n, source, pad));
            left -= pad + 512;
        }
        let data = bundle(requests);
        assert!(data.len() <= GOSSIP_MESSAGE, "{}", data.len());
        let before = rig.collector.pending_totals();
        rig.engine.handle_prover_message(&data);
        messages += 1;
        if before == rig.collector.pending_totals() {
            return messages;
        }
    }
}

/// Five signed gossip messages of junk shields, valid carrier headers and
/// nothing else: no shard that does not hold their source may keep them.
#[tokio::test]
async fn forged_shields_of_another_shard_do_not_keep_its_mempool_full() {
    let mut rig = rig(half(true), Proofs::Unconfigured);
    let source = [0x3f; 32]; // Held by the other half.
    let messages = flood(&mut rig, source);
    // Far past the retention window (10 ranks), one turn every 100 ranks.
    let turns = 40u64;
    for i in 1..=turns {
        turn(&rig.leader, i * 100);
    }
    let (held, bytes) = rig.collector.pending_totals();
    rig.engine
        .handle_prover_message(&bundle(vec![junk_transfer(7, PROBE)]));
    let refused = rig.collector.pending_totals() == (held, bytes);
    assert!(
        !refused,
        "forged shields retained without limit: {messages} gossip messages of junk shields \
         (valid carrier header only: no proof, signature, fee or source coin) still hold \
         {bytes} of {CAP} bytes in {held} messages after {} ranks past a retention window of \
         10, and the shard's mempool refused an unrelated {PROBE}-byte submission",
        turns * 100
    );
    assert_eq!(held, 0, "no copy of another shard's shield stays");
    // Not by refusing everything: a shield of this shard is collected.
    let before = rig.collector.total_pending();
    rig.engine
        .handle_prover_message(&bundle(vec![junk_shield(1, [0xbf; 32], 64)]));
    assert_eq!(rig.collector.total_pending(), before + 1);
}

/// The count cap: 65,536 tiny junk shields of another shard, about 13 MB.
#[tokio::test]
async fn tiny_forged_shields_of_another_shard_do_not_hold_the_count_cap() {
    let mut rig = rig(half(true), Proofs::Unconfigured);
    let source = [0x3f; 32];
    for n in 0..65_536u64 {
        rig.engine
            .handle_prover_message(&bundle(vec![junk_shield(n, source, 0)]));
    }
    for rank in [1000, 2000] {
        turn(&rig.leader, rank);
    }
    let held = rig.collector.total_pending();
    rig.engine
        .handle_prover_message(&bundle(vec![junk_transfer(7, 64)]));
    assert_ne!(
        rig.collector.total_pending(),
        held,
        "forged shields retained without limit: {held} tiny junk shields held past the \
         retention window fill the count cap, and the mempool refused an unrelated submission"
    );
}

/// What no frame could execute is refused on arrival by the shard that would
/// have proposed it, whatever a signer vouches: no room, no proposal's time.
#[tokio::test]
async fn submissions_no_frame_could_execute_are_refused_on_arrival() {
    let mut rig = rig(half(false), Proofs::Absent);
    let mine = [0x3f; 32];
    let cases = [
        ("a tiny shield", bundle(vec![junk_shield(1, mine, 0)])),
        ("a padded shield", bundle(vec![junk_shield(2, mine, 4096)])),
        ("a junk transfer", bundle(vec![junk_transfer(3, 4096)])),
        (
            "a formed shield with a junk one",
            bundle(vec![formed_shield(&rig), junk_shield(4, mine, 0)]),
        ),
    ];
    for (name, data) in cases {
        rig.engine.handle_prover_message(&data);
        assert_eq!(
            rig.collector.total_pending(),
            0,
            "unverified junk collected: {name} that fails dispatch's checks before native \
             work took room on the shard that would propose it"
        );
    }
    // The gate's other side: a shield that passes them is collected.
    let data = bundle(vec![formed_shield(&rig)]);
    rig.engine.handle_prover_message(&data);
    assert_eq!(rig.collector.total_pending(), 1);
}

/// Nothing in a shield limits when its owner's signature may be used: an
/// earlier shield of the coin the owner signed (one that never committed)
/// can be sent again, with any proof bytes, by anyone who saw it. Held
/// first, it claims the coin; once its proof failed to verify here it can
/// never execute, and neither it nor a later copy of its statement may keep
/// the owner's new shield out. The worker here rejects the replayed copy's
/// proof and gives no verdict on the others.
#[tokio::test]
async fn a_replayed_shield_whose_proof_failed_here_keeps_no_coin() {
    let mut rig = rig(half(false), Proofs::Refuting);
    let mut tail = REFUTED_PROOF.to_vec();
    let replayed = bundle(vec![formed_shield_with(&rig, 1, &tail)]);
    tail[0] ^= 1;
    let again = bundle(vec![formed_shield_with(&rig, 1, &tail)]);
    let new = bundle(vec![formed_shield_with(&rig, 2, &[])]);
    rig.engine.handle_prover_message(&replayed);
    assert_eq!(
        rig.collector.total_pending(),
        1,
        "the replayed shield is collected"
    );
    let exec = rig.engine.execution_engine.clone().unwrap();
    let pair = vec![(quil_execution::domains::QUIL_TOKEN.to_vec(), replayed)];
    exec.preverify_bundles(&pair);
    assert!(
        exec.unverified_confidential_operations(&pair).is_empty(),
        "setup: the replayed shield's proof has its verdict here"
    );
    // A fresh copy of the replayed statement, then the owner's new shield.
    rig.engine.handle_prover_message(&again);
    rig.engine.handle_prover_message(&new);
    let held = rig.collector.total_pending();
    assert!(
        held == 3,
        "VULNERABLE: an owner's new shield was refused ({held} held, 3 expected: the replayed \
         shield, a fresh copy of it and the new one) while a replayed earlier shield of the \
         coin, whose proof failed to verify here, or a copy of it held the coin"
    );
    // The new shield now holds the coin against another statement.
    rig.engine
        .handle_prover_message(&bundle(vec![formed_shield_with(&rig, 3, &[])]));
    assert_eq!(
        rig.collector.total_pending(),
        3,
        "another statement of the key"
    );
}

/// A bundle whose proof failed to verify on this node can never execute (a
/// verdict depends on the operation and the network's policy alone), yet
/// every proposal of this node carried it again while it stayed in the
/// pool, and every archive verifies the proofs a frame carries: a
/// well-formed operation with a garbage proof needs no coin and no proving.
/// It is left out of every proposal and out of the pool, for good; another
/// copy of its statement is not.
#[tokio::test]
async fn a_bundle_whose_proof_failed_here_is_neither_proposed_nor_kept() {
    let mut rig = rig(half(false), Proofs::Refuting);
    let garbage = bundle(vec![formed_shield_with(&rig, 1, REFUTED_PROOF)]);
    rig.engine.handle_prover_message(&garbage);
    assert_eq!(rig.collector.total_pending(), 1, "the bundle is collected");
    let exec = rig.engine.execution_engine.clone().unwrap();
    let pair = vec![(
        quil_execution::domains::QUIL_TOKEN.to_vec(),
        garbage.clone(),
    )];
    exec.preverify_bundles(&pair);
    assert!(
        exec.unverified_confidential_operations(&pair).is_empty(),
        "setup: the bundle's proof has its verdict here"
    );
    let mut proposed = 0;
    for rank in [1, 2] {
        rig.leader.frame_requests.lock().unwrap().clear();
        turn(&rig.leader, rank);
        proposed += rig
            .leader
            .frame_requests
            .lock()
            .unwrap()
            .values()
            .map(Vec::len)
            .sum::<usize>();
    }
    let held = rig.collector.total_pending();
    assert!(
        proposed == 0 && held == 0,
        "VULNERABLE: a bundle whose proof failed to verify on this node was proposed \
         {proposed} times in 2 turns and is still held ({held}): every archive verifies the \
         proofs a frame carries"
    );
    rig.engine.handle_prover_message(&garbage);
    assert_eq!(rig.collector.total_pending(), 0, "it is never held again");
    // Another copy of its statement, with other proof bytes, is collected.
    rig.engine
        .handle_prover_message(&bundle(vec![formed_shield_with(&rig, 1, &[])]));
    assert_eq!(
        rig.collector.total_pending(),
        1,
        "a copy of the statement with other proof bytes was refused"
    );
}

/// A replayed shield whose proof failed here, once a proposal dropped it from
/// the pool, leaves its statement marked as failed: a fresh copy of it with
/// other proof bytes (free to make, no verdict yet) must not take the coin
/// again and keep the owner's new shield out until its own proof fails, once
/// per proposal cycle.
#[tokio::test]
async fn a_replayed_shield_a_proposal_dropped_takes_no_coin_again() {
    let mut rig = rig(half(false), Proofs::Refuting);
    let replayed = bundle(vec![formed_shield_with(&rig, 1, REFUTED_PROOF)]);
    rig.engine.handle_prover_message(&replayed);
    let exec = rig.engine.execution_engine.clone().unwrap();
    let pair = vec![(quil_execution::domains::QUIL_TOKEN.to_vec(), replayed)];
    exec.preverify_bundles(&pair);
    assert!(
        exec.unverified_confidential_operations(&pair).is_empty(),
        "setup: the replayed shield's proof has its verdict here"
    );
    turn(&rig.leader, 1);
    assert_eq!(
        rig.collector.total_pending(),
        0,
        "setup: the proposal dropped the replayed shield"
    );
    rig.engine
        .handle_prover_message(&bundle(vec![formed_shield_with(&rig, 1, b"FRESHCOPY")]));
    rig.engine
        .handle_prover_message(&bundle(vec![formed_shield_with(&rig, 2, &[])]));
    let held = rig.collector.total_pending();
    assert!(
        held == 2,
        "VULNERABLE: the owner's new shield was refused ({held} held, 2 expected: a fresh \
         copy of the dropped replayed shield and the new one) while the fresh copy, of a \
         statement whose proof failed here, held the coin"
    );
}

/// A fresh copy of a replayed shield's statement submitted while a proposal
/// drops the replayed shield (between the drop's steps, so not reachable
/// from a test but by a hook) must not take the coin: the statement is
/// marked failed before the coin is free.
#[tokio::test]
async fn a_copy_submitted_while_a_proposal_drops_its_statement_takes_no_coin() {
    let mut rig = rig(half(false), Proofs::Refuting);
    let replayed = bundle(vec![formed_shield_with(&rig, 1, REFUTED_PROOF)]);
    rig.engine.handle_prover_message(&replayed);
    let exec = rig.engine.execution_engine.clone().unwrap();
    let pair = vec![(quil_execution::domains::QUIL_TOKEN.to_vec(), replayed)];
    exec.preverify_bundles(&pair);
    let copy = bundle(vec![formed_shield_with(&rig, 1, b"GAPCOPY")]);
    let collector = rig.collector.clone();
    crate::message_collector::set_drop_gap_hook(Box::new(move || {
        collector.add_message_newest(copy);
    }));
    turn(&rig.leader, 1);
    assert_eq!(
        rig.collector.total_pending(),
        1,
        "setup: the replayed shield was dropped and the copy collected"
    );
    rig.engine
        .handle_prover_message(&bundle(vec![formed_shield_with(&rig, 2, &[])]));
    let held = rig.collector.total_pending();
    assert!(
        held == 2,
        "VULNERABLE: the owner's new shield was refused ({held} held, 2 expected) while a copy \
         of the replayed statement, submitted as the proposal dropped it, held the coin"
    );
}

/// An honest shield that a peer bundled with an operation whose proof
/// failed here leaves with that bundle, but is not marked failed: its own
/// message, sent alone, holds the coin as before.
#[tokio::test]
async fn an_honest_shield_bundled_with_a_failed_operation_is_not_marked_failed() {
    let mut rig = rig(half(false), Proofs::Refuting);
    let honest = formed_shield_with(&rig, 2, &[]);
    let pairing = bundle(vec![
        honest.clone(),
        formed_shield_with(&rig, 1, REFUTED_PROOF),
    ]);
    rig.engine.handle_prover_message(&pairing);
    assert_eq!(rig.collector.total_pending(), 1, "the pairing is collected");
    let exec = rig.engine.execution_engine.clone().unwrap();
    let pair = vec![(quil_execution::domains::QUIL_TOKEN.to_vec(), pairing)];
    exec.preverify_bundles(&pair);
    turn(&rig.leader, 1);
    assert_eq!(
        rig.collector.total_pending(),
        0,
        "setup: the proposal dropped the pairing"
    );
    rig.engine.handle_prover_message(&bundle(vec![honest]));
    rig.engine
        .handle_prover_message(&bundle(vec![formed_shield_with(&rig, 3, &[])]));
    let held = rig.collector.total_pending();
    assert!(
        held == 1,
        "the honest shield was marked failed ({held} held, 1 expected): sent alone it held \
         no coin, and another statement of the key was collected beside it"
    );
}

/// The header of frame `frame` of a shard of another application, as a
/// leader's bundle carries it beside the requests it relays.
fn shard_header(frame: u64) -> Vec<u8> {
    use quil_execution::global_intrinsic::frame_header::FrameHeader;
    FrameHeader {
        address: vec![0x51; 32],
        frame_number: frame,
        global_frame_number: 99,
        ..Default::default()
    }
    .to_canonical_bytes()
    .unwrap()
}

/// Two held messages carry the same shield. The first leaves the pool
/// without its shield failing: a newer frame of its shard supersedes it, a
/// proposal drops it for another operation whose proof failed here, a
/// contending shield finds that failure first, the leader removes it, or
/// retention prunes it. The second still carries the shield, so another
/// statement of the coin must still be refused: else the coin has two
/// pending shields, and the global commit refuses one, with no fee, after
/// this shard and every archive verified its proof.
#[tokio::test]
async fn a_coin_stays_held_while_another_message_carries_its_shield() {
    let mut vulnerable = Vec::new();
    let mut unset = Vec::new();
    for exit in ["supersede", "drop", "judged", "remove", "prune"] {
        let rig = rig(half(false), Proofs::Refuting);
        let collector = rig.collector.clone();
        let copy = |tail: &[u8]| formed_shield_with(&rig, 2, tail);
        // A failing operation of this arm's own bytes: verdicts are cached
        // for the process, so an earlier arm's would be judged at once.
        let failing = || formed_shield_with(&rig, 1, &[REFUTED_PROOF, exit.as_bytes()].concat());
        let (first, second, rank) = match exit {
            "supersede" => (
                bundle(vec![shard_header(5), copy(b"FIRSTCOPY")]),
                bundle(vec![shard_header(6), copy(b"SECONDCOPY")]),
                1,
            ),
            "drop" | "judged" => (
                bundle(vec![copy(b"FIRSTCOPY"), failing()]),
                bundle(vec![copy(b"SECONDCOPY")]),
                1,
            ),
            "prune" => (
                bundle(vec![copy(b"FIRSTCOPY")]),
                bundle(vec![copy(b"SECONDCOPY")]),
                20,
            ),
            _ => (
                bundle(vec![copy(b"FIRSTCOPY")]),
                bundle(vec![copy(b"SECONDCOPY")]),
                1,
            ),
        };
        let filed = if exit == "supersede" {
            collector.add_verified_message(1, first.clone())
                && collector.add_verified_message(1, second)
        } else {
            use crate::message_collector::SubmitOutcome::Accepted;
            collector.add_message_outcome(1, first.clone()) == Accepted
                && collector.add_message_outcome(rank, second) == Accepted
        };
        if exit == "drop" || exit == "judged" {
            let exec = rig.engine.execution_engine.clone().unwrap();
            let application = quil_execution::domains::QUIL_TOKEN.to_vec();
            exec.preverify_bundles(&[(application.clone(), first.clone())]);
            // Its failing operation has its verdict here; its shield has none.
            if !exec
                .unverified_confidential_operations(&[(application, bundle(vec![failing()]))])
                .is_empty()
            {
                unset.push(format!("{exit}: the failing operation has no verdict"));
                continue;
            }
        }
        match exit {
            "drop" => turn(&rig.leader, 1),
            // The first was asked about its proofs when the second message
            // came, before its verdict: it is asked again once a second
            // passed (the collector's recheck interval), and the contending
            // shield finds it failed.
            "judged" => std::thread::sleep(std::time::Duration::from_millis(1100)),
            "remove" => collector.remove(&[first]),
            "prune" => {
                for finalized in 2..=13 {
                    collector.prune_after_finalization(finalized);
                }
            }
            _ => {}
        }
        // Held now: the second message alone, or both when the contending
        // shield is to find the first one's failure.
        let held = if exit == "judged" { 2 } else { 1 };
        if !filed || collector.total_pending() != held {
            unset.push(format!(
                "{exit}: filed {filed}, {} held, {held} expected",
                collector.total_pending()
            ));
            continue;
        }
        collector.add_message_outcome(rank, bundle(vec![formed_shield_with(&rig, 3, &[])]));
        if collector.total_pending() != held {
            vulnerable.push(exit);
        }
    }
    assert!(
        vulnerable.is_empty() && unset.is_empty(),
        "{}{}",
        if vulnerable.is_empty() {
            String::new()
        } else {
            format!(
                "VULNERABLE: another statement of a coin was collected while a held message \
                 carried its pending shield, once the first message carrying it left by \
                 {vulnerable:?}. "
            )
        },
        if unset.is_empty() {
            String::new()
        } else {
            format!("setup did not hold: {unset:?}")
        }
    );
}

/// Without a token policy nothing can tell, so nothing is refused.
#[tokio::test]
async fn a_node_without_a_token_policy_collects_as_before() {
    let mut rig = rig(half(true), Proofs::Unconfigured);
    rig.engine
        .handle_prover_message(&bundle(vec![junk_shield(1, [0xbf; 32], 0)]));
    assert_eq!(rig.collector.total_pending(), 1);
}

/// A stall whose turns end before collecting (a parent not materialized):
/// two hours of ranks age nothing, and the first turn after it reads the
/// shield.
#[tokio::test]
async fn a_real_shield_outlasts_a_stall_of_refused_turns() {
    let mut rig = rig(half(false), Proofs::Busy);
    let data = bundle(vec![formed_shield(&rig)]);
    rig.engine.handle_prover_message(&data);
    assert_eq!(rig.collector.total_pending(), 1);
    let id: quil_consensus::models::Identity = vec![9; 32];
    for rank in 1..=STALL_RANKS {
        let refused = rig
            .leader
            .prove_next_state(rank, &rig.leader.filter, 5, &id);
        assert!(refused.is_err());
    }
    assert_eq!(rig.collector.total_pending(), 1);
    assert_eq!(rig.collector.collect_for_rank(STALL_RANKS + 1).len(), 1);
}

/// A stall whose turns collect while no proof slot frees: the shield is held
/// to each turn's rank instead of ageing out.
#[tokio::test]
async fn a_real_shield_outlasts_a_stall_of_turns_waiting_for_its_proofs() {
    let mut rig = rig(half(false), Proofs::Busy);
    let data = bundle(vec![formed_shield(&rig)]);
    rig.engine.handle_prover_message(&data);
    assert_eq!(rig.collector.total_pending(), 1);
    for rank in 1..=STALL_RANKS {
        turn(&rig.leader, rank);
    }
    assert_eq!(
        rig.collector.total_pending(),
        1,
        "a shield waiting for its proofs aged out in a stall"
    );
}

/// The harness can fail: on the same shard, in the same turns, messages no
/// proposal holds back age out of the retention window.
#[tokio::test]
async fn control_what_nobody_holds_back_ages_out() {
    let mut rig = rig(half(true), Proofs::Unconfigured);
    rig.engine.handle_prover_message(&[0xa5; 4096]);
    rig.engine
        .handle_prover_message(&bundle(vec![junk_transfer(1, 1024)]));
    rig.engine
        .handle_prover_message(&bundle(vec![junk_shield(1, [0xbf; 32], 1024)]));
    assert_eq!(rig.collector.total_pending(), 3);
    for rank in [1000, 2000, 3000] {
        turn(&rig.leader, rank);
    }
    assert_eq!(rig.collector.total_pending(), 0);
}

/// Bytes no proposal decodes and bundles without a confidential operation take
/// the mempool's room only until they age out, like any message nobody holds
/// back; but only a confidential bundle the mempool holds needs an arrival
/// stamp, and only a turn holding one prunes the stamps. No other arrival may
/// leave one, nor a copy a full rank refused.
#[tokio::test]
async fn arrivals_no_turn_routes_leave_no_routing_stamp() {
    const COUNT_CAP: usize = 65_536;
    let mut rig = rig(half(true), Proofs::Unconfigured);
    let stamps = |rig: &Rig| rig.engine.routing_seen.lock().unwrap().len();
    let mut sent = 0usize;
    // Decodable bundles without a confidential operation.
    for n in 0..100u32 {
        let mut inner = 0x0000_0e01u32.to_be_bytes().to_vec();
        inner.extend_from_slice(&n.to_be_bytes());
        rig.engine.handle_prover_message(&bundle(vec![inner]));
        sent += 1;
    }
    // Bytes no proposal decodes, past the count cap.
    for n in 0..(COUNT_CAP as u64 + 1_000) {
        let mut junk = vec![0xa5; 16];
        junk[8..].copy_from_slice(&n.to_be_bytes());
        rig.engine.handle_prover_message(&junk);
        sent += 1;
    }
    let held = rig.collector.total_pending();
    assert_eq!(held, COUNT_CAP, "the rank's count cap holds");
    // Shields of this shard the full rank refuses.
    for n in 0..100u64 {
        rig.engine
            .handle_prover_message(&bundle(vec![junk_shield(n, [0xbf; 32], 0)]));
        sent += 1;
    }
    assert_eq!(rig.collector.total_pending(), held);
    let start = std::time::Instant::now();
    for rank in [1000, 2000] {
        turn(&rig.leader, rank);
    }
    eprintln!("two turns over {held} held: {:?}", start.elapsed());
    assert_eq!(
        rig.collector.total_pending(),
        0,
        "what nobody holds back ages out"
    );
    let left = stamps(&rig);
    assert_eq!(
        left, 0,
        "arrival stamps retained without limit: {left} routing stamps stay for {sent} \
         submissions no turn routes (undecodable bytes, bundles without a confidential \
         operation, copies a full rank refused) after the mempool let all of them go, and \
         only a turn holding a confidential bundle prunes them"
    );
    // The stamp's purpose stays: a confidential bundle the mempool takes has one.
    rig.engine
        .handle_prover_message(&bundle(vec![junk_shield(1, [0xbf; 32], 64)]));
    assert_eq!(rig.collector.total_pending(), 1);
    assert_eq!(stamps(&rig), 1);
}

/// A confidential bundle the mempool took keeps its arrival stamp after the
/// mempool let it go: only a turn holding a confidential bundle prunes the
/// stamps, and only those an hour old. A peer refilling the rank's count cap
/// with tiny junk shields of this shard leaves a stamp per shield, past
/// anything the mempool holds, for as long as it keeps sending.
#[tokio::test]
async fn reproduces_routing_stamps_outliving_the_mempool() {
    const COUNT_CAP: usize = 65_536;
    let mut rig = rig(half(true), Proofs::Unconfigured);
    let mine = [0xbf; 32];
    let mut n = 0u64;
    for fill in 1..=2u64 {
        for _ in 0..COUNT_CAP {
            n += 1;
            rig.engine
                .handle_prover_message(&bundle(vec![junk_shield(n, mine, 0)]));
        }
        assert_eq!(
            rig.collector.total_pending(),
            COUNT_CAP,
            "rig check: fill {fill} did not reach the rank's count cap"
        );
        // The mempool lets them go once their rank leaves the retention
        // window, as a later collection or a finalized frame's prune does.
        rig.collector.collect_for_rank(fill * 1000);
        assert_eq!(
            rig.collector.total_pending(),
            0,
            "rig check: fill {fill} did not age out"
        );
    }
    let stamps = rig.engine.routing_seen.lock().unwrap().len();
    assert!(
        stamps <= COUNT_CAP,
        "{stamps} arrival stamps kept while the mempool holds nothing, \
         {} past the rank's count cap: each refill by a peer adds {COUNT_CAP} more, \
         and no turn prunes a stamp under an hour old",
        stamps - COUNT_CAP
    );
}

/// What is left open: a well-formed non-shield waits for its routing
/// fallback on a shard its hash does not designate, so it is held up to about
/// shards x `ROUTED_FALLBACK`. Bounded: the fallback ends the hold.
#[tokio::test]
async fn a_transfer_of_another_shard_is_held_only_until_its_routing_fallback() {
    let shards: Vec<Vec<u8>> = [[false, false], [false, true], [true, false], [true, true]]
        .iter()
        .map(|bits| quil_forest::encode_shard_bit_path(&quil_execution::domains::QUIL_TOKEN, bits))
        .collect();
    let filter = shards[0].clone();
    let mut rig = rig(filter.clone(), Proofs::Unconfigured);
    rig.registry.set_summaries(
        shards
            .iter()
            .map(|filter| quil_types::consensus::ProverShardSummary {
                filter: filter.clone(),
                status_counts: [(quil_types::consensus::ProverStatus::Active, 1)].into(),
                total_size: 0,
            })
            .collect(),
    );
    let hash_of = |data: &[u8]| -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        Sha3_256::digest(canonical_app_message(data)).into()
    };
    let mut n = 0u64;
    let mut taken = Vec::new();
    // Bundles one place after their designated shard here, up to the cap. A
    // bundle the mempool refuses with room left, or a run of bundles none
    // designated one place away, ends the fill as a failure.
    let mut skipped = 0u32;
    while CAP - rig.collector.pending_totals().1 >= 4096 {
        let room = CAP - rig.collector.pending_totals().1;
        let mut left = room.min(GOSSIP_MESSAGE) - 2048;
        let mut requests = Vec::new();
        while left > 1024 {
            let pad = left.min(MAX_CARRIER - 512) - 512;
            n += 1;
            requests.push(junk_transfer(n, pad));
            left -= pad + 512;
        }
        let data = bundle(requests);
        let hash = hash_of(&data);
        if routing_offset(&filter, &shards, &hash) != Some(1) {
            skipped += 1;
            assert!(
                skipped < 1000,
                "rig check: {skipped} bundles in a row designated no shard one place before this one"
            );
            continue;
        }
        skipped = 0;
        taken.push(hash);
        let before = rig.collector.pending_totals();
        rig.engine.handle_prover_message(&data);
        assert_ne!(
            rig.collector.pending_totals(),
            before,
            "rig check: the mempool refused a {}-byte bundle with {room} of {CAP} bytes free",
            data.len()
        );
    }
    let full = rig.collector.pending_totals();
    for i in 1..=10u64 {
        turn(&rig.leader, i * 100);
    }
    assert_eq!(
        rig.collector.pending_totals(),
        full,
        "held through the turns"
    );
    rig.engine
        .handle_prover_message(&bundle(vec![junk_transfer(n + 1, PROBE)]));
    assert_eq!(
        rig.collector.pending_totals(),
        full,
        "a full mempool refuses"
    );
    {
        let mut seen = rig.leader.routing_seen.lock().unwrap();
        let earlier = std::time::Instant::now()
            .checked_sub(ROUTED_FALLBACK * 2)
            .unwrap();
        for hash in &taken {
            seen.get_mut(hash).unwrap().arrived = earlier;
        }
    }
    turn(&rig.leader, 2000);
    turn(&rig.leader, 3000);
    assert_eq!(
        rig.collector.total_pending(),
        0,
        "the fallback ends the hold"
    );
}
