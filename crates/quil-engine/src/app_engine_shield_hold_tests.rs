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
}

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
        let worker = if proofs == Proofs::Busy {
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

/// A single shield that passes every check before native work; its signature
/// and proof are not valid, as a replayed or forged one's are not.
fn formed_shield(source: [u8; 32]) -> Vec<u8> {
    use quil_lattice_ct::confidential::{
        relation::membership::IDENTITY_BYTES,
        shield::{Shield, ShieldStatement},
        transfer::{parameter_context, Output, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    let application = quil_execution::domains::QUIL_TOKEN;
    let context = parameter_context(&network(), &application);
    let key = CommitmentKey::derive(&context);
    let opening = AmountOpening::from_seed(&context, &[2; 32]);
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    Shield {
        statement: ShieldStatement {
            network: network(),
            application,
            transparent_address: source,
            owner_public_key: [4; 57],
            amount: 12,
            fee: 2,
            outputs: vec![Output {
                commitment: key.commit(10, &opening),
                owner: [5; IDENTITY_BYTES],
                memo: [6; MEMO_BYTES],
            }],
        },
        signature: [0; 114],
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
    let mut rig = rig(half(true), Proofs::Absent);
    let mine = [0xbf; 32];
    let cases = [
        ("a tiny shield", bundle(vec![junk_shield(1, mine, 0)])),
        ("a padded shield", bundle(vec![junk_shield(2, mine, 4096)])),
        ("a junk transfer", bundle(vec![junk_transfer(3, 4096)])),
        (
            "a formed shield with a junk one",
            bundle(vec![formed_shield(mine), junk_shield(4, mine, 0)]),
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
    rig.engine
        .handle_prover_message(&bundle(vec![formed_shield(mine)]));
    assert_eq!(rig.collector.total_pending(), 1);
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
    let mut rig = rig(half(true), Proofs::Busy);
    let data = bundle(vec![formed_shield([0xbf; 32])]);
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
    let mut rig = rig(half(true), Proofs::Busy);
    rig.engine
        .handle_prover_message(&bundle(vec![formed_shield([0xbf; 32])]));
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
    // Bundles one place after their designated shard here, up to the cap.
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
            continue;
        }
        taken.push(hash);
        rig.engine.handle_prover_message(&data);
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
