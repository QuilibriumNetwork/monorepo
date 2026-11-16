//! A backlog of slow confidential proofs on a regular node (mainnet,
//! 2026-10-31): batch shields verifying for about 240 s each arrived faster
//! than the node's admission queue verified them. A finalized frame waiting
//! on one gave up its background wait after 30 min and verified inline,
//! where the proof worker's slots, taken by the backlog, refused it within
//! its 1.5 s admission wait ("token proof worker: Busy"); the frame failed
//! and its retry waited 30 min again (shards stalled up to 3.6 h). These
//! tests use only the queue's and the deferral's interfaces of the release
//! base, so they show the failure there.
use super::*;
use crate::admission_verify::{AdmissionJob, AdmissionQueue};
use quil_execution::manager::PreverifyCounts;
use quil_lattice_ct::confidential::relation::backend::worker_client::{FrameCheck, WorkerVerifier};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

const SHIELD_BYTES: usize = 207_976;

fn submission(tag: u8, n: u8) -> [u8; 32] {
    let mut digest = [tag; 32];
    digest[1] = n;
    digest
}

fn verified() -> PreverifyCounts {
    PreverifyCounts {
        operations: 1,
        verified: 1,
        ..Default::default()
    }
}

/// A verification of `digest` that succeeds and records it in `log`.
fn recording(log: &Arc<Mutex<Vec<[u8; 32]>>>, digest: [u8; 32]) -> AdmissionJob {
    let log = log.clone();
    Arc::new(move || {
        log.lock().unwrap().push(digest);
        verified()
    })
}

/// Thirteen shards each finalize a frame carrying one batch shield this
/// node has not verified, behind twenty arrivals already queued; the queue
/// verifies one every 240 s, and each frame asks again on its 10 s retry
/// timer. Every frame waits for its own verdict and materializes once it is
/// cached; none leaves the wait to verify inline.
#[test]
fn a_proof_backlog_never_sends_a_finalized_frame_to_inline_verification() {
    const VERIFY_SECS: u64 = 240;
    const RETRY_SECS: u64 = 10;
    const SHARDS: u8 = 13;
    let queue = AdmissionQueue::new(256, 64 << 20, false);
    let log = Arc::new(Mutex::new(Vec::new()));
    for n in 0..20 {
        let arrival = submission(0xa0, n);
        assert!(queue.offer(arrival, SHIELD_BYTES, 1, recording(&log, arrival), false));
    }
    let mut deferrals = ProofDeferrals::default();
    let start = Instant::now();
    let mut waited: Vec<Option<u64>> = vec![None; usize::from(SHARDS)];
    let mut next_verdict = VERIFY_SECS;
    let mut now = 0u64;
    while waited.iter().any(Option::is_none) {
        assert!(
            now <= 24 * 3600,
            "frames still waiting after a day: {waited:?}"
        );
        if now >= next_verdict {
            queue.run_one();
            next_verdict += VERIFY_SECS;
        }
        for shard in 0..SHARDS {
            if waited[usize::from(shard)].is_some() {
                continue;
            }
            let frame = submission(0xf0, shard);
            let cached = log.lock().unwrap().contains(&frame);
            // As `defer_for_proof_verification` asks for each submission.
            let (verifying, restarted) = if cached {
                (true, false)
            } else {
                let restarted = !queue.pending(&frame);
                let offered = queue.offer(frame, SHIELD_BYTES, 1, recording(&log, frame), true);
                (offered || queue.pending(&frame), restarted)
            };
            let decision = deferrals.decide(
                &[shard],
                1,
                usize::from(!cached),
                verifying,
                restarted,
                start + Duration::from_secs(now),
            );
            match decision {
                Deferral::Proceed {
                    inline: None,
                    waited: time,
                } => waited[usize::from(shard)] = Some(time.map_or(0, |w| w.as_secs())),
                Deferral::Proceed {
                    inline: Some(reason),
                    waited: time,
                } => panic!(
                    "shard {shard}'s finalized frame left its background wait after {}s ({reason}) to \
                     verify inline, where this node's busy proof worker refuses it within its 1.5 s \
                     admission wait (\"token proof worker: Busy\"): the frame fails and its retry \
                     waits again from the start",
                    time.map_or(0, |w| w.as_secs())
                ),
                Deferral::Wait { .. } => {}
            }
        }
        now += RETRY_SECS;
    }
    let log = log.lock().unwrap().clone();
    let frames = log.iter().filter(|digest| digest[0] == 0xf0).count();
    assert_eq!(
        frames,
        usize::from(SHARDS),
        "each frame's submission verified once"
    );
    assert!(
        log[..usize::from(SHARDS)]
            .iter()
            .all(|digest| digest[0] == 0xf0),
        "the frames' submissions verified before the arrivals queued ahead of them: {log:?}"
    );
    let longest = waited.iter().flatten().copied().max().unwrap_or(0);
    assert!(
        longest <= u64::from(SHARDS) * VERIFY_SECS + RETRY_SECS,
        "the last frame waited {longest}s, more than the {SHARDS} verifications ahead of it"
    );
}

/// A frame's submission whose verification finds the worker's slots taken
/// (by inline and proposal verifications) stays queued, first, and is
/// retried until a slot frees.
#[test]
fn a_submission_a_frame_waits_on_outlasts_a_busy_proof_worker() {
    const BUSY: usize = 5;
    let queue = AdmissionQueue::new(8, 1 << 20, false);
    let log = Arc::new(Mutex::new(Vec::new()));
    let arrival = submission(0xa1, 0);
    let frame = submission(0xf1, 0);
    let busy_left = Arc::new(AtomicUsize::new(BUSY));
    let job: AdmissionJob = {
        let (log, busy_left) = (log.clone(), busy_left.clone());
        Arc::new(move || {
            log.lock().unwrap().push(frame);
            if busy_left.load(Ordering::SeqCst) > 0 {
                busy_left.fetch_sub(1, Ordering::SeqCst);
                PreverifyCounts {
                    operations: 1,
                    busy: 1,
                    ..Default::default()
                }
            } else {
                verified()
            }
        })
    };
    assert!(queue.offer(arrival, 10, 1, recording(&log, arrival), false));
    assert!(queue.offer(frame, 10, 1, job, true));
    for _ in 0..=BUSY {
        assert!(
            queue.pending(&frame),
            "the submission a frame waits on was given up after {} verifications found the proof worker \
             busy: the frame's retry queues it again and, past its restart bound, verifies it inline, \
             where it fails \"token proof worker: Busy\"",
            BUSY - busy_left.load(Ordering::SeqCst)
        );
        assert!(queue.run_one());
    }
    assert!(!queue.pending(&frame));
    let mut expected = vec![frame; BUSY + 1];
    while queue.run_one() {}
    expected.push(arrival);
    assert_eq!(
        *log.lock().unwrap(),
        expected,
        "the frame's submission was retried behind the arrival"
    );
}

/// Arrivals past the queue's bounds drop the oldest arrival, never a
/// submission a frame waits on.
#[test]
fn the_admission_bounds_never_drop_a_submission_a_frame_waits_on() {
    let queue = AdmissionQueue::new(2, 1 << 20, false);
    let log = Arc::new(Mutex::new(Vec::new()));
    let frame = submission(0xf2, 0);
    assert!(queue.offer(frame, 10, 1, recording(&log, frame), true));
    for n in 0..4 {
        let arrival = submission(0xa2, n);
        queue.offer(arrival, 10, 1, recording(&log, arrival), false);
    }
    assert!(
        queue.pending(&frame),
        "arrivals past the queue's bound dropped the submission a frame waits on: the frame's retry \
         queues it again and, past its restart bound, verifies it inline, where it fails \"token proof \
         worker: Busy\""
    );
    while queue.run_one() {}
    assert_eq!(log.lock().unwrap().first(), Some(&frame));
}

/// Frames waiting on the queue are served in the order they first asked,
/// however often each asks again on its retry timer.
#[test]
fn frames_waiting_on_the_admission_queue_are_served_in_the_order_they_asked() {
    let queue = AdmissionQueue::new(8, 1 << 20, false);
    let log = Arc::new(Mutex::new(Vec::new()));
    for _ in 0..2 {
        for shard in 0..4 {
            let frame = submission(0xf3, shard);
            queue.offer(frame, 10, 1, recording(&log, frame), true);
        }
    }
    while queue.run_one() {}
    let served: Vec<u8> = log.lock().unwrap().iter().map(|digest| digest[1]).collect();
    assert_eq!(
        served,
        vec![0, 1, 2, 3],
        "frames waiting on the queue were served last-asked first: the first frame to wait waited \
         behind every frame that asked after it"
    );
}

/// A member voting on a view whose leader is a committee member: the voter
/// check passes the proposal, then warms up its long confidential
/// operations in the node's admission queue. Every verification finds the
/// proof worker's node-wide slots taken (other worker processes hold them).
struct BusyVoter {
    manager: Arc<quil_execution::ExecutionEngineManager>,
    check: crate::cw_app_seams::AppRequestsRootCheck,
    outflows: Arc<FrameOutflows>,
    clock: Arc<quil_store::RocksClockStore>,
    filter: Vec<u8>,
    _db: Arc<quil_store::RocksDb>,
    /// The node-wide slot locks, held for the test.
    _slots: Vec<std::fs::File>,
    dir: std::path::PathBuf,
}

impl Drop for BusyVoter {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn busy_voter() -> BusyVoter {
    voter_with(|dir| {
        let slots = dir.join("slots");
        let worker = WorkerVerifier::new(dir.join("absent-worker"), 1, Duration::from_secs(2))
            .unwrap()
            .with_concurrency(2)
            .unwrap()
            .with_shared_admission(slots.clone())
            .unwrap();
        let held: Vec<std::fs::File> = [slots, dir.join("slots.1")]
            .into_iter()
            .map(|path| {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .unwrap();
                file.try_lock().unwrap();
                file
            })
            .collect();
        (worker, held)
    })
}

/// A voter over the proof worker `worker` makes in the voter's directory,
/// holding the files it returns for the test.
fn voter_with(
    worker: impl FnOnce(&std::path::Path) -> (WorkerVerifier, Vec<std::fs::File>),
) -> BusyVoter {
    let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
    let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
    let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
    let prover = Arc::new(quil_tries::ShaInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, prover.clone()));
    crdt.set_forest(quil_forest::Forest::with_namespace(
        db.inner(),
        quil_store::FOREST_NAMESPACE,
    ));
    crdt.set_unified_tree(true);
    crdt.warm_sizes(&[]).unwrap();
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "quil-admission-busy-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (worker, held) = worker(&dir);
    let manager = Arc::new(
        quil_execution::ExecutionEngineManager::new_with_shards(
            prover,
            crypto.key_manager,
            crdt.clone(),
            crypto.circuit_compiler,
            clock.clone(),
            Arc::new(quil_execution::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(crdt)),
            false,
            None,
            None,
        )
        .with_token_worker(
            quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0),
            worker,
        )
        .unwrap(),
    );
    // Jobs the node's admission queue still holds keep this manager, and
    // its stores, alive; its thread may drop the last one while the test
    // process exits, closing RocksDB during static teardown ("pthread lock:
    // Invalid argument"). Keep it for the process instead, as the node's
    // own exit does.
    std::mem::forget(manager.clone());
    let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
    let outflows: Arc<FrameOutflows> = Arc::new(std::sync::Mutex::new(Default::default()));
    let check = build_requests_root_check(
        manager.clone(),
        Arc::new(quil_tries::ShaInclusionProver),
        manager.crdt(),
        filter.clone(),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
        outflows.clone(),
        clock.clone(),
        filter.clone(),
        None,
        None,
    );
    BusyVoter {
        manager,
        check,
        outflows,
        clock,
        filter,
        _db: db,
        _slots: held,
        dir,
    }
}

/// A bundle of one shield of a legacy coin, distinct per `n`, as a replayed
/// one is: of a coin of its key, written into `voter`'s store, and signed by
/// that key, so it passes every check before its proof (its proof is not
/// valid). Its proofs are not known to verify within the budget on a node
/// that has not measured its size class, so members verify it in the
/// background. It pays a fee of 2, below its dynamic cost: a frame that
/// materializes it skips it before its proof (`check_self_paid_fee`).
fn shield_bundle(voter: &BusyVoter, n: u32) -> quil_types::proto::global::MessageBundle {
    shield_bundle_with_fee(voter, n, 2)
}

/// `shield_bundle` paying `fee` out of a coin of `10 + fee`.
fn shield_bundle_with_fee(
    voter: &BusyVoter,
    n: u32,
    fee: u128,
) -> quil_types::proto::global::MessageBundle {
    use quil_execution::{
        hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        token_intrinsic::{legacy_migration, materialize},
    };
    use quil_lattice_ct::confidential::{
        relation::membership::IDENTITY_BYTES,
        shield::{Shield, ShieldStatement},
        transfer::{parameter_context, Output, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    use quil_types::crypto::Signer as _;
    use quil_types::proto::global::{message_request::Request, MessageBundle, MessageRequest};
    let network = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0).network;
    let application = quil_execution::domains::QUIL_TOKEN;
    let context = parameter_context(&network, &application);
    let key = CommitmentKey::derive(&context);
    let opening = AmountOpening::from_seed(&context, &[2; 32]);
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let private = [23; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&private).unwrap();
    let mut salt = [3; 32];
    salt[..4].copy_from_slice(&n.to_be_bytes());
    let tree = legacy_migration::create_transparent_coin_tree(
        &legacy_migration::TransparentCoin {
            owner_address: quil_crypto::poseidon::hash_bytes_to_32(&public).unwrap(),
            amount: 10 + fee,
        },
        &legacy_migration::transparent_type_hash(&application).unwrap(),
        &salt,
    )
    .unwrap();
    let transparent_address = materialize::coin_content_address(&tree).unwrap();
    let state = HypergraphState::new(voter.manager.crdt());
    state
        .set(
            &application,
            &transparent_address,
            &vertex_adds_discriminator().unwrap(),
            1,
            quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
        )
        .unwrap();
    state.commit().unwrap();
    state.abort();
    let statement = ShieldStatement {
        network,
        application,
        transparent_address,
        owner_public_key: public.clone().try_into().unwrap(),
        amount: 10 + fee,
        fee,
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
    let op = Shield {
        statement,
        signature,
        proof,
    }
    .encode()
    .unwrap();
    MessageBundle {
        requests: vec![MessageRequest {
            timestamp: 0,
            request: Some(Request::TokenOperation(
                quil_types::proto::token::TokenOperation {
                    canonical_bytes: op,
                },
            )),
        }],
        timestamp: i64::from(n),
    }
}

fn canonical(bundle: &quil_types::proto::global::MessageBundle) -> Vec<u8> {
    crate::consensus_wire::app_bundle_to_canonical_bytes(bundle).unwrap()
}

/// A proposal for app frame 1 over the genesis state carrying `requests`,
/// which every voter check passes (body root, pre-state, fee total, relays).
fn proposal(
    voter: &BusyVoter,
    rank: u64,
    requests: Vec<quil_types::proto::global::MessageBundle>,
) -> quil_types::proto::global::AppShardFrame {
    let crdt = voter.manager.crdt();
    let zero = vec![0u8; if crdt.has_forest() { 32 } else { 64 }];
    let state_roots = [
        ("vertex", "adds"),
        ("vertex", "removes"),
        ("hyperedge", "adds"),
        ("hyperedge", "removes"),
    ]
    .iter()
    .map(|(set, phase)| {
        let root = crdt.sub_shard_commitment_for_filter(set, phase, &voter.filter);
        if root.is_empty() {
            zero.clone()
        } else {
            root
        }
    })
    .collect();
    let bodies: Vec<Vec<u8>> = requests.iter().map(canonical).collect();
    let requests_root = compute_requests_root(
        &bodies,
        &voter.filter,
        1,
        Some(voter.manager.as_ref()),
        Some(&quil_tries::ShaInclusionProver),
        crdt.has_forest(),
    )
    .unwrap();
    let (outflows, clock) = (voter.outflows.as_ref(), voter.clock.as_ref());
    quil_types::proto::global::AppShardFrame {
        header: Some(quil_types::proto::global::FrameHeader {
            address: voter.filter.clone(),
            frame_number: 1,
            rank,
            requests_root,
            state_roots,
            fee_total: materialized_fee_total(outflows, clock, &voter.filter, 0)
                .expect("setup: genesis fee total")
                .to_be_bytes()
                .to_vec(),
            settlements: settlement_relay(outflows, clock, &voter.filter, 1)
                .expect("setup: settlement relay of frame 1"),
            accumulator: accumulator_field(outflows, clock, &voter.filter, 1)
                .expect("setup: accumulator field of frame 1"),
            spends: spend_relay(outflows, clock, &voter.filter, 1)
                .expect("setup: spend relay of frame 1"),
            ..Default::default()
        }),
        requests,
        ..Default::default()
    }
}

/// R113-E-1. A committee member leading a run of views proposes bodies of
/// replayed long confidential operations (public bytes of historic batch
/// shields); none of its proposals finalizes. Every honest member's vote
/// warms them up in its admission queue while the proof worker is busy.
/// Then an honest finalized frame waits on a batch shield. The warm-ups
/// must stay within the queue's bound, and the frame's submission, the
/// only one a frame waits on, must not queue behind them. Uses only
/// release-base interfaces: the voter check, the node's queue, and
/// `offer_submission` as a deferred frame calls it.
#[test]
fn proposal_warm_ups_neither_grow_without_bound_nor_queue_ahead_of_a_finalized_frame() {
    use crate::admission_verify::{self, MAX_BUNDLES};
    const PROPOSALS: u32 = 30;
    const BUNDLES: u32 = 10;
    let voter = busy_voter();
    let queue = admission_verify::global();
    let mut warmed = Vec::new();
    for view in 0..PROPOSALS {
        let requests: Vec<_> = (0..BUNDLES)
            .map(|i| shield_bundle(&voter, view * BUNDLES + i))
            .collect();
        warmed.extend(
            requests
                .iter()
                .map(|bundle| admission_verify::digest(&canonical(bundle))),
        );
        let frame = proposal(&voter, u64::from(view) + 1, requests);
        assert_eq!(
            (voter.check)(&frame),
            Ok(()),
            "setup: the leader's proposal passes every voter check"
        );
    }
    // The finalized frame's materialization defers on its batch shield
    // (`defer_for_proof_verification`).
    let honest = canonical(&shield_bundle(&voter, u32::MAX));
    assert!(admission_verify::offer_submission(
        queue,
        &voter.manager,
        &voter.filter,
        &honest,
        true
    ));
    let held = warmed.iter().filter(|digest| queue.pending(digest)).count();
    let ahead = queue
        .queued_ahead(&admission_verify::digest(&honest))
        .unwrap_or(0);
    assert!(
        held <= MAX_BUNDLES && ahead == 0,
        "vulnerable: unbounded lane growth and an honest frame starved behind speculative entries: \
         {held} of {} vote-time warm-ups of {PROPOSALS} proposals that never finalized are held in \
         the admission queue (its bound is {MAX_BUNDLES}), and the honest finalized frame's \
         submission is queued behind {ahead} of them",
        warmed.len()
    );
}

/// R113-E-2. The other node processes' background verifications hold every
/// node-wide worker slot but the first. A finalized frame's verification
/// takes that slot (here it then fails, the worker executable being absent),
/// while a warm-up and an arrival, background work, find the worker busy.
#[test]
fn a_finalized_frames_verification_takes_the_slot_background_work_leaves_free() {
    use crate::admission_verify::{self, AdmissionQueue, MAX_FAILURES};
    let voter = busy_voter();
    // Only the second slot stays held by "another process".
    voter._slots[0].unlock().unwrap();
    let queue = AdmissionQueue::new(8, 1 << 20, false);
    let (frame, warm, arrival) = (
        canonical(&shield_bundle(&voter, 1)),
        canonical(&shield_bundle(&voter, 2)),
        canonical(&shield_bundle(&voter, 3)),
    );
    assert!(admission_verify::offer_submission(
        &queue,
        &voter.manager,
        &voter.filter,
        &frame,
        true
    ));
    assert!(admission_verify::offer_warmup_submission(
        &queue,
        &voter.manager,
        &voter.filter,
        &warm,
        &voter.filter,
        1,
        None
    ));
    assert!(admission_verify::offer_submission(
        &queue,
        &voter.manager,
        &voter.filter,
        &arrival,
        false
    ));
    assert!(queue.run_one());
    let after_frame = queue.stats().counts;
    assert_eq!(
        (after_frame.busy, after_frame.unavailable),
        (0, 1),
        "the finalized frame's verification found no node-wide slot although one was left free"
    );
    // It is retried first until released; then the background work runs.
    assert!(queue.run_one() && queue.run_one());
    assert!(queue.released(&admission_verify::digest(&frame)));
    while queue.run_one() {}
    let counts = queue.stats().counts;
    assert!(
        counts.busy > 0 && counts.unavailable == usize::from(MAX_FAILURES),
        "background work took the node-wide slot left for frames: {counts:?}"
    );
}

/// A proposal a voter refuses (here: a false fee total) can never finalize
/// with this member's vote: its operations are not warmed up.
#[test]
fn a_refused_proposal_warms_up_nothing() {
    use crate::admission_verify;
    let voter = busy_voter();
    let queue = admission_verify::global();
    let requests: Vec<_> = (0..4).map(|n| shield_bundle(&voter, n)).collect();
    let digests: Vec<_> = requests
        .iter()
        .map(|bundle| admission_verify::digest(&canonical(bundle)))
        .collect();
    let mut frame = proposal(&voter, 1, requests);
    frame.header.as_mut().unwrap().fee_total = 7u128.to_be_bytes().to_vec();
    assert_eq!(
        (voter.check)(&frame).map_err(|(reason, _)| reason),
        Err("fee total differs")
    );
    assert!(
        digests.iter().all(|digest| !queue.pending(digest)),
        "a refused proposal's operations were queued for verification"
    );
    frame.header.as_mut().unwrap().fee_total = 0u128.to_be_bytes().to_vec();
    assert_eq!((voter.check)(&frame), Ok(()));
    assert!(digests.iter().any(|digest| queue.pending(digest)));
}

/// A finalized frame whose operations are known to verify within the
/// budget is not deferred (`defer_for_proof_verification`): it verifies
/// them as it materializes, on its lanes and in its commit dispatch. Under
/// strict (macOS) admission at no headroom, with nothing holding memory,
/// those checks run alone, so the frame materializes; refused, it would
/// fail as busy on every retry. The worker here rejects every proof.
#[test]
fn a_frame_of_known_to_fit_operations_materializes_at_no_headroom() {
    let admission = crate::storage_jobs::Admission::strict_at_no_headroom_for_tests();
    let told = Arc::new(Mutex::new(Vec::new()));
    let seen = told.clone();
    let voter = voter_with(move |dir| {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("rejecting-worker");
        std::fs::write(
            &script,
            "#!/bin/sh\ncat > /dev/null\necho run >> \"$0.runs\"\nexit 81\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let worker = WorkerVerifier::new(script, 1, Duration::from_secs(10))
            .unwrap()
            .with_memory_admission(Arc::new(move |deadline, frame| {
                seen.lock().unwrap().push(frame);
                admission
                    .reserve_verifier(3 << 30, deadline, frame)
                    .map(|permit| Box::new(permit) as _)
            }));
        (worker, Vec::new())
    });
    // The frame skips, before its proof, a shield paying less than its
    // dynamic cost (`check_self_paid_fee`); this one pays more.
    const FEE: u128 = 1 << 24;
    let bundle = shield_bundle_with_fee(&voter, 1, FEE);
    let required = {
        let request = bundle.requests[0].request.as_ref();
        let Some(quil_types::proto::global::message_request::Request::TokenOperation(op)) = request
        else {
            unreachable!("shield_bundle carries one token operation")
        };
        let cost = voter.manager.get_cost(&canonical(&bundle)).unwrap();
        let multiplier = crate::rewards::fee_multiplier_for_cost(
            voter.manager.pricing_network(),
            50_000,
            0,
            &cost,
            1,
        )
        .unwrap();
        multiplier
            * num_bigint::BigInt::from(
                quil_execution::token_intrinsic::cost::state_growth(&op.canonical_bytes).unwrap(),
            )
    };
    assert!(
        required > num_bigint::BigInt::from(2) && required <= num_bigint::BigInt::from(FEE),
        "setup: the shield pays its dynamic cost {required}, which a fee of 2 does not"
    );
    let result = materialize_app_shard_requests(
        &voter.manager,
        &[bundle],
        1,
        50_000,
        0,
        1,
        &voter.filter,
        0,
    );
    let runs = std::fs::read_to_string(voter.dir.join("rejecting-worker.runs"))
        .unwrap_or_default()
        .lines()
        .count();
    let told = std::mem::take(&mut *told.lock().unwrap());
    match result {
        Err(error) if quil_execution::token_intrinsic::is_proof_worker_busy(&error) => panic!(
            "frame_refused_at_no_headroom: a finalized frame fails as busy on every retry; \
             its checks were told {told:?}"
        ),
        Err(error) => panic!("setup: the frame failed otherwise: {error}"),
        Ok(_) => assert!(
            runs > 0,
            "setup: the frame's operation reached the proof worker"
        ),
    }
    assert!(
        told.iter().all(|&frame| frame == FrameCheck::Inline),
        "frame_lanes_unflagged: every check the frame waits on as it executes is told so, \
         within its caller's deadline: {told:?}"
    );
}

/// The admission queue tells the proof worker's memory admission, from its
/// own threads, which check a finalized frame waits on: one queued for a
/// frame (`offer_frame_submission`) may wait in its place and run alone,
/// an arrival (`offer_submission`) neither.
#[test]
fn the_queue_tells_the_memory_admission_which_check_a_frame_waits_on() {
    use crate::admission_verify::{self, AdmissionQueue};
    let told = Arc::new(Mutex::new(Vec::new()));
    let seen = told.clone();
    let voter = voter_with(move |dir| {
        let worker = WorkerVerifier::new(dir.join("absent-worker"), 1, Duration::from_secs(2))
            .unwrap()
            .with_memory_admission(Arc::new(move |_, frame| {
                seen.lock().unwrap().push(frame);
                None
            }));
        (worker, Vec::new())
    });
    let mut asked = Vec::new();
    for (n, for_frame) in [(1, true), (2, false)] {
        let canonical = canonical(&shield_bundle(&voter, n));
        let queue = AdmissionQueue::new(8, 1 << 20, false);
        let (manager, filter) = (&voter.manager, &voter.filter);
        assert!(if for_frame {
            admission_verify::offer_frame_submission(&queue, manager, filter, &canonical, None)
        } else {
            admission_verify::offer_submission(&queue, manager, filter, &canonical, false)
        });
        assert!(queue.run_one());
        asked.push(std::mem::take(&mut *told.lock().unwrap()));
    }
    let (frames, arrivals) = (&asked[0], &asked[1]);
    assert!(
        !frames.is_empty() && !arrivals.is_empty(),
        "setup: both checks reached the memory admission: {asked:?}"
    );
    assert!(
        frames.iter().all(|&frame| frame == FrameCheck::Queued),
        "queued_frame_check_not_told: a frame's check from the queue was told {frames:?}"
    );
    assert!(
        arrivals.iter().all(|&frame| frame == FrameCheck::No),
        "arrival_told_a_frame_waits: an arrival's check was told {arrivals:?}"
    );
}
