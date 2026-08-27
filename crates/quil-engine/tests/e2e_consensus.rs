//! Tier 1 in-process integration tests for the archive↔non-archive
//! consensus flow.
//!
//! ## Scope
//!
//! 1. Archive nodes finalize global frames via HotStuff (multi-node).
//! 2. Non-archive nodes submit `ProverJoin` and observe the join land.
//! 3. After confirm window, worker thread starts app-shard consensus.
//! 4. Workers emit shard proofs; archive's next frame includes them.
//!
//! ## Building blocks
//!
//! Every rig this file drives — `AppShardHarness`, `Tier2ArchiveRig`,
//! `StubFrameProver`, `TestProver`, `InMemoryNetwork`, … — lives in
//! [`mod common`](common), shared verbatim with the other e2e binaries.
//! It used to be copy-pasted here and into `common/mod.rs`, and the copies
//! drifted (this one grew commonware-simplex support the other never got).

mod common;
use common::*;

use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use quil_types::consensus::ProverRegistry;
use quil_types::crypto::{FrameProver, InclusionProver, NoopInclusionProver};
use quil_types::proto::global as gpb;
use quil_types::store::ClockStore;

use quil_engine::test_support::TestProverRegistry;
use quil_store::testing::InMemoryClockStore;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn worker_activates_after_confirm_and_emits_proof() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    // 4 workers form a shard committee for filter [0x55; 32]. Each
    // worker's outbound proposals/votes/timeouts are routed to all
    // peers via the in-memory drain task installed by `build()`.
    let harness = AppShardHarness::build(4);

    // Wait until at least one worker has published a coverage frame
    // (i.e. finalized a shard frame). 3-chain finalization plus
    // pacemaker startup means we need to wait through several
    // proposal rounds.
    let got_coverage = harness
        .wait_for_coverage(std::time::Duration::from_secs(90))
        .await;

    let counts: Vec<usize> = harness
        .workers
        .iter()
        .map(|w| w.coverage_published.lock().len())
        .collect();
    let events: Vec<Vec<String>> = harness
        .workers
        .iter()
        .map(|w| w.events.lock().clone())
        .collect();

    eprintln!("worker coverage counts: {counts:?}");
    for (i, log) in events.iter().enumerate() {
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for ev in log {
            *counts.entry(ev.as_str()).or_insert(0) += 1;
        }
        eprintln!("worker {i} event histogram: {counts:?}");
    }

    assert!(
        got_coverage,
        "no worker emitted a coverage_publish frame within timeout. counts={counts:?}"
    );
}

/// (P3) A single-prover shard driven by commonware-simplex + Falcon
/// (`app_consensus_cw = true`, EQUAL VOTES, quorum 1) self-proposes and
/// self-finalizes app frames end-to-end: `start_consensus_cw` builds the
/// committee (this node's Falcon key, the only active prover), the seam
/// proposer proves + assembles + verifies each frame, simplex finalizes it,
/// and `handle_cw_finalized_frame` persists the shard clock frame + materializes
/// + emits `FullFrameProduced`. Asserts a full `AppShardFrame` is produced and
/// the chain advances past genesis (frame_number >= 1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_consensus_cw_single_prover_finalizes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    let harness = AppShardHarness::build_cw(1);
    let frame = harness
        .wait_for_full_frame(std::time::Duration::from_secs(60))
        .await;
    assert!(
        frame.is_some(),
        "app CW single-prover did not finalize a shard frame within 60s"
    );
    let header = frame.unwrap().header.expect("finalized frame has a header");
    assert!(
        header.frame_number >= 1,
        "app CW chain did not advance past genesis (frame_number = {})",
        header.frame_number
    );
}

/// (P3) A 3-prover shard committee driven by commonware-simplex + Falcon
/// (EQUAL VOTES, quorum 3) finalizes app frames via CROSS-NODE voting: the
/// RoundRobin leader proves + ships its block over the CW block channel, each
/// follower ingests it (`CwIn` → `BlockStore`), verifies (`validate_proposal`),
/// and votes (`CwIn` vote channel, sender resolved to its committee Falcon key);
/// quorum finalizes. Exercises the full in-memory CW transport (CwOut → CwIn)
/// end-to-end — the same round-trip the master's BlossomSub path will carry.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn app_consensus_cw_multi_prover_finalizes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    let harness = AppShardHarness::build_cw(3);
    let frame = harness
        .wait_for_full_frame(std::time::Duration::from_secs(90))
        .await;
    assert!(
        frame.is_some(),
        "3-prover app CW committee did not finalize a shard frame within 90s"
    );
    let header = frame.unwrap().header.expect("finalized frame has a header");
    assert!(
        header.frame_number >= 1,
        "app CW chain did not advance past genesis (frame_number = {})",
        header.frame_number
    );
}

/// Active PoRep path end-to-end through the live consensus harness.
///
/// Each of the 4 workers gets a shared committed CRDT (vertices under the
/// shard filter), an in-memory replica store pre-seeded with its confirmed
/// leaf replicas, and a global beacon frame at frame 1000 — and the
/// process-global activation frame is lowered to 1000. With the storage
/// fork live (`global_frame_number >= storage_activation_frame()`):
///   * the producer omits the app-shard VDF and binds a deterministic
///     ρ_N-bound `header.output`,
///   * each follower's vote carries serialized `StorageOpening`s,
///   * the aggregator stashes the openings by rank, and
///   * the seal recomputes the 74-byte BLS48-581 G1 aggregate
///     `storage_attestation_root` and attaches the `StorageAttestation`.
///
/// Asserts the finalized `AppShardFrame` carries that attestation + root —
/// the inverse of every other harness test, where the (un-activated) path
/// leaves both empty and byte-identical to the legacy frame.
// P4/CW FOLLOW-UP: PoRep storage-attestation assembly is a LEGACY-consensus
// feature — the old app path assembled the committee `StorageAttestation` from
// per-vote openings at QC time. The commonware-simplex path votes are plain
// simplex votes (no openings), so CW-finalized frames carry no attestation yet.
// Porting PoRep to CW (openings in CW votes + assembly on finalize) is tracked
// separately; the core consensus migration does not depend on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn worker_active_storage_attestation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let provers: Vec<TestProver> = (0..4).map(|_| TestProver::generate()).collect();
    // Every member needs an Active allocation on THIS shard's filter, confirmed
    // for the epoch the frame anchors to. `prove_next_state`'s effective-Active
    // gate (app_engine.rs) refuses to propose a storage frame unless the local
    // prover holds one — a prover admitted to the committee without it would mint
    // an attestation whose leaf roots are for a future epoch. `to_prover_info`
    // leaves `allocations` empty, which is fine for the legacy path
    // (`anchor_gfn == 0` skips the gate) but not here: `StorageHarness::seeded`
    // anchors at global frame 1000.
    let infos: Vec<_> = provers
        .iter()
        .map(|p| {
            let mut info = p.to_prover_info(1);
            info.allocations = vec![quil_types::consensus::ProverAllocationInfo {
                status: quil_types::consensus::ProverStatus::Active,
                confirmation_filter: vec![0x55; 32],
                rejection_filter: Vec::new(),
                join_frame_number: 0,
                leave_frame_number: 0,
                pause_frame_number: 0,
                resume_frame_number: 0,
                kick_frame_number: 0,
                join_confirm_frame_number: 0,
                join_reject_frame_number: 0,
                leave_confirm_frame_number: 0,
                leave_reject_frame_number: 0,
                last_active_frame_number: 1000,
                epoch: quil_types::consensus::epoch_for_frame(1000),
                ring: 0,
                vertex_address: Vec::new(),
            }];
            info
        })
        .collect();
    let registry = Arc::new(TestProverRegistry::with_provers(infos));

    // `seeded` lowers `storage_activation_frame()` to 1000 and builds the
    // shared CRDT + a global frame at 1000 (≥ activation → fork live).
    let storage = StorageHarness::seeded(1000);

    // Register every member's storage leaf roots into the registry so the frame
    // validator's registered-leaf cross-check on the proposer's self
    // storage-attestation passes. Production writes these via the confirm
    // intrinsic (prover trie); the harness wires them directly, mirroring the
    // per-worker `compute_storage_confirm` seeding inside `build_inner`. The
    // filter/epoch match `build_inner` (`[0x55;32]`, `epoch_for_frame(1000)`).
    {
        let filter: Vec<u8> = vec![0x55; 32];
        let epoch = quil_types::consensus::epoch_for_frame(1000);
        let rocks = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let rs = quil_store::replica_store::ReplicaStore::new(
            rocks as Arc<dyn quil_types::store::KvDb>,
        );
        for p in &provers {
            let roots = quil_engine::app_shard_metadata::compute_storage_confirm(
                &storage.crdt,
                &rs,
                std::slice::from_ref(&filter),
                &p.address,
                epoch,
                quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
                &quil_crypto::sdr::SdrParams::default(),
            )
            .expect("compute leaf roots for registration");
            for cr in &roots {
                for e in &cr.entries {
                    let lid = quil_execution::global_intrinsic::leaf_id_bytes(&filter, &e.prefix);
                    registry.register_leaf_root(
                        &p.address,
                        &lid,
                        e.leaf_root.clone(),
                        e.num_blocks,
                        epoch,
                    );
                }
            }
        }
    }

    let registry = registry as Arc<dyn ProverRegistry>;
    let harness = AppShardHarness::build_with_storage(provers, registry, storage);

    let frame = harness
        .wait_for_full_frame(std::time::Duration::from_secs(90))
        .await
        .expect("expected a FullFrameProduced AppShardFrame within timeout");

    assert!(
        frame.storage_attestation.is_some(),
        "active-path full frame must carry a StorageAttestation",
    );
    let root = frame
        .header
        .as_ref()
        .map(|h| h.storage_attestation_root.clone())
        .unwrap_or_default();
    assert_eq!(
        root.len(),
        74,
        "storage_attestation_root must be the 74-byte BLS48-581 G1 aggregate; got {} bytes",
        root.len(),
    );

    // The reward proof — the canonical FrameHeader published on GLOBAL_PROVER
    // (captured via coverage_publish) — must ALSO carry the root + the openings
    // blob, since that is the payload the global frame recomputes + audits.
    let cov = harness
        .workers
        .iter()
        .flat_map(|w| w.coverage_published.lock().clone())
        .next()
        .expect("a coverage reward proof must have been published");
    let cov_header =
        quil_execution::global_intrinsic::frame_header::FrameHeader::from_canonical_bytes(&cov)
            .expect("coverage bytes decode as a canonical FrameHeader");
    assert_eq!(
        cov_header.storage_attestation_root.len(),
        74,
        "reward-proof storage_attestation_root must be the 74-byte aggregate",
    );
    assert!(
        !cov_header.storage_attestation.is_empty(),
        "reward proof must carry the StorageAttestation openings for the global audit",
    );
    // And the carried blob must decode as a StorageAttestation with openings.
    let att = <quil_types::proto::global::StorageAttestation as prost::Message>::decode(
        cov_header.storage_attestation.as_slice(),
    )
    .expect("carried attestation decodes");
    assert!(
        !att.openings.is_empty(),
        "carried StorageAttestation must contain member openings",
    );
}

/// Full worker→archive coverage attribution flow:
///   * 4 workers run shard consensus, finalize a shard frame, fire
///     `coverage_publish` with canonical FrameHeader bytes.
///   * A drain task wraps each emission in a
///     `CanonicalMessageBundle{Shard: header}` (mirror of
///     `main.rs:1095-1112`) and broadcasts it to the archive harness
///     via `inject_prover_message`.
///   * 4 archives buffer the bundle in their `message_collector`,
///     leader includes it in the next proposal's `requests`, the
///     proposal finalizes via 3-chain.
///
/// Inject a real dispatch message into a worker's `MessageCollector`,
/// wait for the next coverage frame, and decode the resulting
/// `AppShardProposal` canonical bytes to verify the message ended up
/// in the `requests_root` computation — proof that worker pipelines
/// can actually carry transactions, not just empty frames.
///
/// `requests_root` is computed by `compute_requests_root` over the
/// non-empty message buffer; with an empty buffer it returns 64 zero
/// bytes. A leader-produced frame with our injected message has a
/// non-zero `requests_root` (the first 32 bytes are
/// `sha3_256(commitment)`, non-zero for any real commit).
// CW EVENT MODEL: the commonware-simplex path does NOT emit the legacy
// `FrameProduced` proposal-broadcast event — the CW proposer proves the frame
// inside the seam and ships the block over `CwOut`, surfacing `FullFrameProduced`
// on finalize. So this test locates the leader (and confirms production) via
// `FullFrameProduced`. The kept-request assembly is unchanged, so the injected
// dispatch still rides the frame's `requests_root`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn worker_carries_real_dispatch_message_in_shard_frame() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let harness = AppShardHarness::build(4);

    // Inject a Dispatch message into worker 0 BEFORE the first frame
    // is produced. The message is a stub blob with a recognizable
    // type prefix; the worker's `add_app_message` accepts any
    // 4-byte+ payload (only the wire-level `validate_dispatch_message`
    // checks classify it, and we call `send` here which bypasses that).
    //
    // `0x00000201` is a compute-domain test prefix; the test
    // only cares that the message bytes end up in the frame's
    // requests_root, not that they're a recognized intrinsic.
    // The proposal path (`app_engine.rs:401-417`) decodes each buffered
    // dispatch via `decode_message_bundle`, which requires a canonical
    // `MessageBundle` (type 0x0312). A bare op blob fails to decode and
    // is dropped, leaving `requests_root` zero — so wrap the op in a
    // `CanonicalMessageBundle` exactly as the wire path delivers it.
    let mut op_bytes = Vec::new();
    op_bytes.extend_from_slice(&0x00000201u32.to_be_bytes());
    op_bytes.extend_from_slice(&[0xAAu8; 32]);
    let dispatch_bytes = {
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let req = CanonicalMessageRequest::wrap(op_bytes).expect("wrap dispatch request");
        CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .expect("encode dispatch bundle")
    };
    // Inject into EVERY worker's collector. Dispatch messages are not
    // relayed by the harness's consensus drain (only proposals/votes/
    // timeouts are), and the frame is built by whichever worker leads
    // the finalized rank — which need not be worker 0. In production a
    // dispatch gossips to all shard members, so each buffers it and the
    // leader folds it into `requests_root`; mirror that here so the
    // assertion doesn't hinge on worker 0 happening to be the leader.
    for w in &harness.workers {
        w.handle
            .send(quil_engine::app_engine::AppEngineMessage::Dispatch(
                dispatch_bytes.clone(),
            ));
    }

    // Wait for at least one shard frame to be produced. Under commonware-simplex
    // the drain records "FullFrameProduced" (the CW analog of the legacy
    // "FrameProduced") once a frame finalizes and its full block is shipped.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut leader_idx: Option<usize> = None;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        for (i, w) in harness.workers.iter().enumerate() {
            if w.events.lock().iter().any(|e| e == "FullFrameProduced") {
                leader_idx = Some(i);
                break;
            }
        }
        if leader_idx.is_some() {
            break;
        }
    }
    let leader_idx = leader_idx
        .expect("no worker produced a FullFrameProduced event within 90s — frame production stalled");
    eprintln!("leader is worker {}", leader_idx);

    // Give the leader an extra tick to finish encoding the proposal.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Pull a FrameProduced bundle from the leader's coverage_published
    // sink (the canonical-bytes `AppShardProposal`). We need to
    // decode the embedded `AppShardFrame`'s `FrameHeader.requests_root`
    // and assert it's non-zero.
    //
    // The `coverage_published` Vec only fills on finalization (via
    // AppFollower::on_finalized_state). For a single-shot test where
    // we just need the FRAME (not finalization), we instead look at
    // the worker's `FrameProduced` event count > 0 — implying the
    // proposal was emitted — and decode the proposal bytes that
    // would be routed peer-to-peer. The harness's drain task captures
    // these and routes them via `peer_handles[..].send`, but the
    // canonical bytes are emitted to the engine's event_tx as
    // `FrameProduced{frame_data}`. We don't currently expose those
    // bytes via the harness; if we wait for finalization, the bytes
    // are in `coverage_published`.
    eprintln!("waiting up to 60s for shard finalization...");
    let got_coverage = harness
        .wait_for_coverage(std::time::Duration::from_secs(60))
        .await;
    assert!(
        got_coverage,
        "shard never finalized — workers produced proposals but no QC formed"
    );

    // The injected dispatch lands in exactly ONE finalized frame (once
    // buffered it stays in the collector until `mark_finalized` removes
    // it on inclusion), and NOT necessarily frame 1 — the first frame
    // can be proposed before the async `Dispatch` is drained from the
    // engine's channel. So poll until SOME finalized coverage frame
    // (across all workers, all entries) carries a non-zero
    // `requests_root`, rather than inspecting only the first.
    use quil_execution::global_intrinsic::frame_header::FrameHeader;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut carrying: Option<FrameHeader> = None;
    'outer: while std::time::Instant::now() < deadline {
        for w in &harness.workers {
            let entries: Vec<Vec<u8>> = w.coverage_published.lock().clone();
            for bytes in &entries {
                if let Ok(h) = FrameHeader::from_canonical_bytes(bytes) {
                    let zero_root = vec![0u8; h.requests_root.len()];
                    if h.requests_root != zero_root {
                        carrying = Some(h);
                        break 'outer;
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let header = carrying.expect(
        "no finalized coverage frame carried a non-zero requests_root — the \
         injected dispatch message was never incorporated into a shard frame",
    );
    eprintln!(
        "carrying coverage FrameHeader: frame_number={}, requests_root[..16]={}",
        header.frame_number,
        hex::encode(&header.requests_root[..16.min(header.requests_root.len())]),
    );
}
// =====================================================================
// Tier 2 — full non-archive → confirm → activation flow
// =====================================================================
//
// Tier 1 stops at "wire-layer bytes reach the right channel". Tier 2
// drives the same flow through real production wiring:
//   - Each archive owns a RocksHypergraphStore + HypergraphCrdt +
//     ExecutionEngineManager + FrameMaterializer + SharedProverRegistry
//     + ProverLifecycle + ProverPipeline.
//   - The `on_finalized_state` hook materializes the frame, refreshes
//     the registry, runs lifecycle.evaluate, and dispatches actions
//     through the pipeline.
// First test: a non-archive submits a real signed ProverJoin via the
// same pipeline production uses; assert it appears as a confirmed
// allocation in at least one archive's registry within the testnet
// confirm window.

// (rig moved to `tests/common/mod.rs`)

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_archive_rig_constructs_with_genesis_provers() {
    // Smoke test: build a Tier-2 archive rig and verify the prover
    // registry came back populated from the seeded genesis state. This
    // is the foundation every subsequent Tier-2 test depends on; if it
    // fails the rest of the chain can't possibly pass.
    let provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&provers);
    let me = provers[0].clone();
    let rig = build_tier2_archive_rig(me.clone(), &provers, &seed_hex);

    // After genesis seeding, the registry should know about every
    // prover with seniority=1000, Status=Active.
    let count = rig.prover_registry.read(|r| r.distinct_provers());
    assert_eq!(
        count, 3,
        "expected 3 provers in registry after genesis seeding; got {count}"
    );

    // Self-prover should be discoverable.
    let my_info = rig
        .prover_registry
        .read(|r| r.get_prover_info(&me.address).cloned());
    assert!(
        my_info.is_some(),
        "self prover {} not in registry after genesis seed",
        hex::encode(&me.address),
    );
}

/// Drives a real signed `ProverJoin` through `ProverPipeline` for a
/// new (non-genesis) prover, then ingests the resulting
/// `MessageBundle` into an archive's `FrameMaterializer`. Asserts the
/// archive's `SharedProverRegistry` now reports the prover with a
/// `Joining`-status allocation for the chosen filter.
///
/// This is the "join arrives → archive registry sees it" link — the
/// next step beyond [`tier2_archive_rig_constructs_with_genesis_provers`].
/// Worker activation (which requires a `ProverConfirm` from the
/// lifecycle and a subsequent finalized frame) is exercised in the
/// next test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_non_archive_join_lands_in_archive_registry() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // 1. Build a single archive that knows about 3 genesis provers.
    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(genesis_provers[0].clone(), &genesis_provers, &seed_hex);

    // 2. Seed the archive's clock store with a "head" frame so
    //    `submit_join` can stamp a sane frame_number on the join.
    //    The materializer's verify path rejects joins with
    //    `frame_number < head - 10`, so we ensure head is small.
    let head_header = gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    };
    // (The archive rig already seeds frame 5 into its clock store so the
    // ProverJoin VDF gate can resolve the join's referenced frame.)

    // 3. Build a new (non-genesis) prover. This is the joiner.
    let joiner = TestProver::generate();

    // 4. Build a non-archive ProverPipeline. Reuses the archive's
    //    storage so the test can drive both sides in one process.
    let transport = Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    transport.set_head_header(head_header.clone());
    let joiner_key_manager: Arc<dyn quil_keys::KeyManager + Send + Sync> =
        Arc::new(quil_engine::test_support::TestKeyManager::new(
            joiner.bls_signer.private_key().to_vec(),
            joiner.bls_pubkey.clone(),
        ));
    let joiner_wm = Arc::new(quil_engine::test_support::TestWorkerManager::new());
    let joiner_wm_dyn: Arc<dyn quil_engine::worker::WorkerManager> = joiner_wm.clone();
    let joiner_allocator = Arc::new(quil_engine::worker_allocator::WorkerAllocator::new(
        joiner_wm_dyn.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        joiner.address.clone(),
    ));
    let joiner_halt = Arc::new(quil_engine::halt_state::HaltState::new());
    let joiner_cf = quil_engine::current_frame::CurrentFrame::new();
    let joiner_lifecycle = Arc::new(quil_engine::provers::lifecycle::ProverLifecycle::new(
        joiner.address.clone(),
        joiner_allocator,
        joiner_halt,
        joiner_cf,
        quil_engine::provers::proposer::Strategy::RewardGreedy,
    ));
    let mut joiner_address_array = [0u8; 32];
    let copy_len = joiner.address.len().min(32);
    joiner_address_array[..copy_len].copy_from_slice(&joiner.address[..copy_len]);
    let joiner_pipeline = Arc::new(quil_engine::prover_pipeline::ProverPipeline {
        lifecycle: joiner_lifecycle,
        worker_manager: joiner_wm_dyn,
        frame_prover: Arc::new(StubFrameProver) as Arc<dyn FrameProver>,
        key_manager: joiner_key_manager,
        bls_pubkey: joiner.bls_pubkey.clone(),
        prover_address: joiner_address_array,
        multisig_ed448_seeds: vec![],
        delegate_address: vec![],
        transport: transport.clone()
            as Arc<dyn quil_engine::prover_message_transport::ProverMessageTransport>,
        hypergraph: None,
        replica_store: None,
        local_message_collector: None,
        current_frame: None,
    });

    // 5. Pick a filter that exists in shards_store. Genesis seeds
    //    QUIL_TOKEN-domain shards at addresses [0x00..0x05]; address
    //    bytes [0, 0, ..., 0] (i=0) is the simplest. Filters in the
    //    materializer are the full 32-byte shard address.
    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 1; // pick shard "1" — any of 0..6 work
        a
    };

    // 6. Drive the join through the pipeline. This signs, encodes,
    //    and calls transport.publish_prover_bundle. The transport
    //    captures the resulting MessageBundle.
    joiner_pipeline
        .submit_join(vec![filter.clone()], &[0u32], head_header.frame_number)
        .await
        .expect("submit_join");

    let bundles = transport.drain_outbound();
    assert_eq!(
        bundles.len(),
        1,
        "expected exactly one MessageBundle (the ProverJoin)"
    );

    // 7. Feed the bundle into the archive's materializer by
    //    constructing a synthetic GlobalFrame whose `requests` field
    //    contains the bundle as a single proto MessageBundle.
    //    `decode_message_bundle` handles the canonical→proto conversion,
    //    including the per-type prefix dispatch that wraps the inner
    //    ProverJoin into `message_request::Request::Join(...)`.
    let proto_bundle = quil_engine::consensus_wire::decode_message_bundle(&bundles[0])
        .expect("decode_message_bundle");
    let frame_to_materialize = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: head_header.frame_number + 1,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![proto_bundle],
        ..Default::default()
    };

    let result = archive
        .materializer
        .materialize_synced(&frame_to_materialize)
        .expect("materialize frame with ProverJoin bundle");
    eprintln!(
        "materialize result: processed={} skipped={}",
        result.processed, result.skipped
    );

    // 8. Refresh registry from the now-updated store. After the join
    //    is materialized, the joiner should appear with a Joining
    //    allocation on the chosen filter.
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    let joiner_info = archive
        .prover_registry
        .read(|r| r.get_prover_info(&joiner.address).cloned());
    assert!(
        joiner_info.is_some(),
        "joiner {} not in registry after materialize. processed={} skipped={}",
        hex::encode(&joiner.address),
        result.processed,
        result.skipped,
    );

    // The joining allocation should exist for the filter we chose.
    let provers_on_filter = archive
        .prover_registry
        .read(|r| r.get_provers(&filter).len());
    assert!(
        provers_on_filter >= 1,
        "expected ≥1 prover on filter {} after join (joiner should be Joining); got {}",
        hex::encode(&filter),
        provers_on_filter,
    );
}


// =====================================================================
// Tier 2 — adversarial tests (real BLS verifier)
// =====================================================================

/// Adversarial: submit a `ProverJoin` whose BLS aggregate-signature
/// bytes have been corrupted. The materializer's real BLS verifier
/// should reject it (`processed=0, skipped=1`) and the prover should
/// NOT appear in the registry afterwards.
///
/// Uses `DefaultKeyManager` for real signature verification — without
/// that the materializer accepts anything and the test would
/// false-pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_adversarial_forged_join_signature_rejected() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);

    // Real BLS verifier — DefaultKeyManager dispatches to
    // FalconKeyConstructor::verify_signature_raw.
    let real_km: Arc<dyn quil_types::crypto::KeyManager> = Arc::new(
        quil_crypto::DefaultKeyManager::new(),
    );
    let archive = build_tier2_archive_rig_with_key_manager(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
        real_km,
    );

    let joiner = TestProver::generate();
    let joiner_transport = Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    joiner_transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });
    let joiner_pipeline = build_test_pipeline_with_registry(
        &joiner,
        joiner_transport.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    joiner_pipeline
        .worker_manager
        .add(quil_engine::worker::WorkerInfo {
            core_id: 0,
            filter: Vec::new(),
            available_storage: 1_000_000,
            total_storage: 1_000_000,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated: false,
        });

    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 4;
        a
    };

    // Step 1: submit a valid join (via the real pipeline) to capture
    // a well-formed bundle.
    joiner_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let bundles = joiner_transport.drain_outbound();
    assert_eq!(bundles.len(), 1);
    let valid_bundle = bundles[0].clone();

    // Step 2: tamper with the bundle bytes. The bundle's structure is
    // `[u32 type][lp request][...][i64 timestamp]`. The ProverJoin's
    // BLS signature lives deep inside the inner request payload.
    // Flipping bytes in the second half of the bundle is virtually
    // guaranteed to land inside the signature blob — BLS signatures
    // are dense and any single-bit flip invalidates them.
    let mut tampered = valid_bundle.clone();
    let mid = tampered.len() * 2 / 3;
    tampered[mid] ^= 0xFF;
    tampered[mid + 1] ^= 0xFF;
    tampered[mid + 2] ^= 0xFF;

    // Step 3: materialize the tampered bundle. Real BLS verification
    // should reject inside the intrinsic dispatch.
    let proto = match quil_engine::consensus_wire::decode_message_bundle(&tampered) {
        Ok(b) => b,
        Err(_) => {
            // Tampering hit the canonical envelope (length prefix etc.)
            // — that's an acceptable rejection too (parser refused).
            // Verify the registry is still untouched and return early.
            let info = archive
                .prover_registry
                .read(|r| r.get_prover_info(&joiner.address).cloned());
            assert!(
                info.is_none(),
                "tampered bundle pre-rejected by parser; joiner must not be in registry"
            );
            return;
        }
    };
    let frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: 6,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![proto],
        ..Default::default()
    };
    let result = archive
        .materializer
        .materialize_synced(&frame)
        .expect("materialize call should succeed (rejection happens per-request)");
    eprintln!(
        "tampered-bundle materialize: processed={} skipped={}",
        result.processed, result.skipped
    );

    // Step 4: archive should have REJECTED the tampered request.
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
    let joiner_info = archive
        .prover_registry
        .read(|r| r.get_prover_info(&joiner.address).cloned());
    assert!(
        joiner_info.is_none(),
        "real BLS verifier accepted a tampered ProverJoin — registry now contains the attacker's prover; \
         processed={} skipped={}",
        result.processed,
        result.skipped,
    );
    // Note: the `skipped` count is at the BUNDLE level (validate_message
    // returns Err for the bundle and `frame_materializer` counts the
    // skip). The forged-join case hits this — bundle-level rejection
    // before any state mutation runs.
}

/// Adversarial: submit a `ProverConfirm` whose `frame_number` is
/// outside the confirm window. The materializer's `validate_confirm_timing`
/// should reject it, and the allocation stays `Joining` instead of
/// flipping to `Active`.
///
/// Skips the joiner's lifecycle entirely — manually constructs the
/// ProverConfirm with a too-early `frame_number` to exercise the
/// timing-check rejection path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_adversarial_premature_confirm_rejected() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // Force the confirm window to mainnet defaults (360..720) so a
    // confirm submitted at "join_frame + 1" definitely violates the
    // timing window. (Previous tests may have stomped the static
    // down to (10, 720); reset it here.)
    quil_execution::global_intrinsic::verify::set_confirm_window_frames(360, 720);

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let real_km: Arc<dyn quil_types::crypto::KeyManager> = Arc::new(
        quil_crypto::DefaultKeyManager::new(),
    );
    let archive = build_tier2_archive_rig_with_key_manager(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
        real_km,
    );

    // Submit a valid join first (via the joiner's pipeline) so an
    // allocation exists for the attacker to target.
    let joiner = TestProver::generate();
    let joiner_transport = Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    joiner_transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });
    let joiner_pipeline = build_test_pipeline_with_registry(
        &joiner,
        joiner_transport.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    joiner_pipeline
        .worker_manager
        .add(quil_engine::worker::WorkerInfo {
            core_id: 0,
            filter: Vec::new(),
            available_storage: 1_000_000,
            total_storage: 1_000_000,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated: false,
        });

    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 5;
        a
    };
    joiner_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = joiner_transport.drain_outbound();
    let join_frame = build_global_frame_with_bundle(6, &join_bundles[0]);
    archive
        .materializer
        .materialize_synced(&join_frame)
        .expect("materialize join");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
    let pre_status = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        pre_status,
        Some(quil_types::consensus::ProverStatus::Joining),
        "joiner should be Joining before attacker confirms"
    );

    // Build a ProverConfirm with frame_number = 7 (only 1 frame after
    // join — well below the 360-frame mainnet window).
    use quil_execution::global_intrinsic::{
        addressed_signature::AddressedSignature, prover_ops::ProverConfirm,
    };
    let confirm_frame_number = 7u64; // join_frame=6 + 1, well below window
    let mut msg = Vec::new();
    msg.extend_from_slice(&filter);
    msg.extend_from_slice(&confirm_frame_number.to_be_bytes());
    let mut domain_pre = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    domain_pre.extend_from_slice(b"PROVER_CONFIRM");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&domain_pre).expect("poseidon");
    let signature = joiner
        .bls_signer
        .sign_with_domain(&msg, &domain)
        .expect("sign");
    let confirm = ProverConfirm {
        filter: vec![],
        frame_number: confirm_frame_number,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature,
            address: joiner.address.clone(),
        }),
        filters: vec![filter.clone()],
        leaf_roots: Vec::new(),
    };
    let confirm_bytes = confirm.to_canonical_bytes().expect("encode confirm");

    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    let req = CanonicalMessageRequest::wrap(confirm_bytes).expect("wrap");
    let bundle = CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp: 0,
    };
    let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");
    let proto = quil_engine::consensus_wire::decode_message_bundle(&bundle_bytes)
        .expect("decode_message_bundle");
    let confirm_frame_proto = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: confirm_frame_number,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![proto],
        ..Default::default()
    };
    let result = archive
        .materializer
        .materialize_synced(&confirm_frame_proto)
        .expect("materialize call");
    eprintln!(
        "premature-confirm materialize: processed={} skipped={}",
        result.processed, result.skipped,
    );

    // Verify allocation is still Joining.
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
    let post_status = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        post_status,
        Some(quil_types::consensus::ProverStatus::Joining),
        "premature ProverConfirm should NOT flip allocation to Active; \
         confirm-frame={}, join-frame=6, mainnet window=360..720; \
         processed={} skipped={}",
        confirm_frame_number,
        result.processed,
        result.skipped,
    );
    // Note: the materializer's `processed` counter currently counts
    // every bundle whose envelope decodes — per-request invoke_step
    // errors are logged but swallowed at engines.rs:216-221. So we
    // can't rely on `skipped` here; the security-critical assertion
    // is the `Joining` status above, which depends on `invoke_step`
    // having rejected the confirm internally via
    // `validate_confirm_timing`.
}

/// Adversarial: attacker signs a `ProverConfirm` with their OWN BLS
/// key but addresses it to a victim's pending join filter. The
/// materializer should NOT flip the victim's allocation to Active —
/// `invoke_filter_op` derives the allocation address from the
/// confirm's signer pubkey, so the attacker's confirm targets their
/// OWN (non-existent) allocation, not the victim's.
///
/// Confirms the address binding is what gates a `ProverConfirm`:
/// a valid BLS signature alone is insufficient — the confirm has to
/// derive its target allocation from a pubkey that matches a pending
/// join's prover.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_adversarial_wrong_signer_confirm_does_not_steal_allocation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // Open the confirm window so timing alone isn't what blocks the
    // attacker — we want the test to fail/pass on the SIGNER binding.
    quil_execution::global_intrinsic::verify::set_confirm_window_frames(10, 720);

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let real_km: Arc<dyn quil_types::crypto::KeyManager> = Arc::new(
        quil_crypto::DefaultKeyManager::new(),
    );
    let archive = build_tier2_archive_rig_with_key_manager(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
        real_km,
    );

    // 1. Victim submits a valid ProverJoin.
    let victim = TestProver::generate();
    let victim_transport = Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    victim_transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });
    let victim_pipeline = build_test_pipeline_with_registry(
        &victim,
        victim_transport.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    victim_pipeline
        .worker_manager
        .add(quil_engine::worker::WorkerInfo {
            core_id: 0,
            filter: Vec::new(),
            available_storage: 1_000_000,
            total_storage: 1_000_000,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated: false,
        });

    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 7;
        a
    };
    victim_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = victim_transport.drain_outbound();
    let join_frame = build_global_frame_with_bundle(6, &join_bundles[0]);
    archive
        .materializer
        .materialize_synced(&join_frame)
        .expect("materialize join");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    // Confirm victim's allocation is Joining.
    let pre_status = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&victim.address).expect("victim").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        pre_status,
        Some(quil_types::consensus::ProverStatus::Joining),
        "victim's allocation should be Joining before the attack"
    );

    // 2. Attacker (different BLS key) signs a ProverConfirm for the
    //    SAME filter, using the victim's confirm window. Attacker's
    //    signature is cryptographically valid (their own key), but
    //    derives a different allocation address — so the attacker is
    //    really confirming their own (non-existent) pending join.
    let attacker = TestProver::generate();
    use quil_execution::global_intrinsic::{
        addressed_signature::AddressedSignature, prover_ops::ProverConfirm,
    };
    let confirm_frame_number = 17u64; // 6 + 11, just inside window
    let mut msg = Vec::new();
    msg.extend_from_slice(&filter);
    msg.extend_from_slice(&confirm_frame_number.to_be_bytes());
    let mut domain_pre = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    domain_pre.extend_from_slice(b"PROVER_CONFIRM");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&domain_pre).expect("poseidon");
    let attacker_signature = attacker
        .bls_signer
        .sign_with_domain(&msg, &domain)
        .expect("sign");
    let confirm = ProverConfirm {
        filter: vec![],
        frame_number: confirm_frame_number,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature: attacker_signature,
            address: attacker.address.clone(), // attacker's address, NOT victim's
        }),
        filters: vec![filter.clone()],
        leaf_roots: Vec::new(),
    };
    let confirm_bytes = confirm.to_canonical_bytes().expect("encode");

    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    let req = CanonicalMessageRequest::wrap(confirm_bytes).expect("wrap");
    let bundle = CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp: 0,
    };
    let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");
    let proto = quil_engine::consensus_wire::decode_message_bundle(&bundle_bytes).expect("decode");
    let attack_frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: confirm_frame_number,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![proto],
        ..Default::default()
    };
    let result = archive
        .materializer
        .materialize_synced(&attack_frame)
        .expect("materialize call");
    eprintln!(
        "wrong-signer attack materialize: processed={} skipped={}",
        result.processed, result.skipped,
    );

    // 3. Verify the victim's allocation is STILL Joining.
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
    let post_status = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&victim.address).expect("victim").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        post_status,
        Some(quil_types::consensus::ProverStatus::Joining),
        "attacker's confirm should NOT flip victim's allocation to Active; \
         post_status={:?} processed={} skipped={}",
        post_status,
        result.processed,
        result.skipped,
    );

    // 4. And the attacker should NOT have appeared in the registry.
    let attacker_info = archive
        .prover_registry
        .read(|r| r.get_prover_info(&attacker.address).cloned());
    assert!(
        attacker_info.is_none(),
        "attacker leaked into prover registry — they had no pending join but their confirm \
         materialized something; processed={} skipped={}",
        result.processed,
        result.skipped,
    );
}

/// Full Tier-2 e2e: after the allocator flips a worker to
/// `allocated=true`, we ALSO want to verify that a finalized shard
/// frame's canonical `FrameHeader` bytes (the "coverage proof") flow
/// back through the archive's real `FrameMaterializer` and are
/// accepted (`processed >= 1`). Reuses the Tier-1 `AppShardHarness`
/// to drive a real 4-worker cohort to shard finalization, then feeds
/// the resulting coverage bundle into the Tier-2 archive's
/// materializer.
///
/// This is the closing link: archive ingests shard work and would
/// (in a full deployment) credit the prover's reward + update shard
/// commitments. Asserts that `materialize.processed >= 1` for the
/// coverage frame.
// P4/CW FOLLOW-UP — the significant one: REWARD ATTRIBUTION under CW. The
// coverage bundle DOES reach the archive now (CW finalizer emits ShardFrameFinalized
// + coverage_publish), but the archive materializer SKIPS it (processed=0,
// skipped=1) because a CW-finalized shard-frame header has no BLS AGGREGATE
// SIGNATURE (simplex certifies the frame via its own Falcon cert, not a header
// agg sig). The global reward path currently verifies that agg sig to credit
// shard work, so CW shard provers would not be credited. This needs a design
// decision: how the GLOBAL level verifies CW-finalized shard work (accept the
// VDF + a CW committee attestation, or carry the simplex cert into the coverage
// bundle). PRIORITY follow-up — see CUTOVER §7.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tier2_shard_coverage_reaches_archive_materializer() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // Build a Tier-2 archive — gives us a real materializer.
    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(genesis_provers[0].clone(), &genesis_provers, &seed_hex);

    // Build a Tier-1 worker cohort. They run a full HotStuff round on
    // a shared shard filter and fire `coverage_publish` on
    // finalization with the canonical FrameHeader bytes. The cohort
    // SHARES the archive's prover registry, seeded below with these
    // provers as Active on the shard filter — so the committee the
    // workers sign their coverage FrameHeader with is byte-identical to
    // the one the archive's FrameHeader verifier reconstructs from
    // `get_active_provers(filter)`. Without this the archive's active
    // set for the shard is empty and verification fails with
    // "aggregate pubkey ... active_count=0".
    // Single-signer cohort: a stub-crypto coverage FrameHeader carries a
    // bare 74-byte BLS aggregate with NO VDF multiproof bytes appended.
    // The intrinsic's attestation check treats a 74-byte signature as
    // single-signer (a real multi-signer attestation is >74 bytes — it
    // appends the per-member Wesolowski multiproofs the stub can't
    // produce). So coverage ingest is exercised with one prover; the
    // multi-prover consensus path is covered separately by
    // `worker_activates_after_confirm_and_emits_proof`.
    let shard_filter: Vec<u8> = vec![0x55; 32];
    let worker_provers: Vec<TestProver> = (0..1).map(|_| TestProver::generate()).collect();
    for p in &worker_provers {
        quil_engine::genesis::seed_active_prover_on_filter(
            &archive.crdt,
            &p.bls_pubkey,
            /* seniority */ 1,
            /* frame_number */ 1,
            &shard_filter,
        )
        .expect("seed worker prover as Active on shard filter");
    }
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    // The PoMW reward needs a non-zero shard `state_size`. Seed ~1 MiB of
    // committed data on the worker's shard so `shard_metadata_for_address`
    // reports a real size (fixed 2026-06-29 — was hardcoded zero, which made
    // every reward compute to zero). Without committed data the reward stays 0.
    let worker_pubkey = worker_provers[0].bls_pubkey.clone();
    {
        let mut app = [0u8; 32];
        app.copy_from_slice(&shard_filter);
        archive
            .crdt
            .add_vertex(
                &quil_hypergraph::Location { app_address: app, data_address: [0x01; 32] },
                &vec![0xEEu8; 1 << 20],
            )
            .unwrap();
        // Commit BEFORE the coverage frame (frame 7) so the size is populated
        // when the materializer sources it.
        archive.crdt.commit(6).unwrap();
    }

    let workers = AppShardHarness::build_with_registry(
        worker_provers,
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    let got_coverage = workers
        .wait_for_coverage(std::time::Duration::from_secs(90))
        .await;
    assert!(
        got_coverage,
        "worker cohort never produced a coverage frame"
    );

    // Drain every worker's coverage bytes.
    let mut coverage_bytes: Vec<Vec<u8>> = Vec::new();
    for w in &workers.workers {
        let mut entries = std::mem::take(&mut *w.coverage_published.lock());
        coverage_bytes.append(&mut entries);
    }
    assert!(
        !coverage_bytes.is_empty(),
        "no coverage bytes captured from worker cohort"
    );
    eprintln!(
        "captured {} coverage bundle(s) from worker cohort",
        coverage_bytes.len()
    );

    // Wrap each coverage bundle in a `CanonicalMessageBundle` (the
    // wire format archives expect on `GLOBAL_PROVER`), then build a
    // synthetic GlobalFrame containing all of them as `requests`.
    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    let mut proto_bundles: Vec<quil_types::proto::global::MessageBundle> = Vec::new();
    for bytes in &coverage_bytes {
        let req = CanonicalMessageRequest::wrap(bytes.clone()).expect("wrap request");
        let bundle = CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: 0,
        };
        let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");
        let proto = quil_engine::consensus_wire::decode_message_bundle(&bundle_bytes)
            .expect("decode_message_bundle");
        proto_bundles.push(proto);
    }

    let coverage_frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: 7,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: proto_bundles,
        ..Default::default()
    };

    // Hand the synthetic frame to the archive's real materializer.
    let result = archive
        .materializer
        .materialize_synced(&coverage_frame)
        .expect("materialize coverage frame");
    eprintln!(
        "archive materialize result: processed={} skipped={}",
        result.processed, result.skipped
    );
    assert!(
        result.processed >= 1,
        "archive materializer should process at least one coverage bundle; \
         got processed={} skipped={}",
        result.processed,
        result.skipped,
    );

    // The fix's payoff (the missing reward leg): the participating worker
    // prover received a NON-ZERO reward through the real frame-header
    // materialize path. Before the per-shard-size fix this was always 0.
    use quil_execution::global_intrinsic::materialize::{prover_address_from_pubkey, reward_address};
    let prover_addr = prover_address_from_pubkey(&worker_pubkey).unwrap();
    let reward_addr = reward_address(&prover_addr).unwrap();
    let reward_loc = quil_hypergraph::Location {
        app_address: quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS,
        data_address: reward_addr,
    };
    let blob = archive
        .crdt
        .get_vertex_data(&reward_loc)
        .expect("worker prover reward vertex must exist after coverage materialize");
    let tree = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(&blob);
    let bal_bytes = quil_execution::global_schema::read_field(&tree, "reward:ProverReward", "Balance")
        .unwrap_or_default();
    let balance = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &bal_bytes);
    assert!(
        balance > num_bigint::BigInt::from(0),
        "worker prover must receive a non-zero reward (got {balance})"
    );
    eprintln!("worker prover reward balance: {balance}");
}

/// Self-coverage composite-topology test: a node running both the
/// archive role (with `FrameMaterializer`) and the worker role (with
/// `AppConsensusEngine`) routes its OWN coverage emissions back into
/// its OWN materializer without an inter-node hop. Mirrors
/// production's GLOBAL_PROVER loopback path: `coverage_publish`
/// wraps the canonical FrameHeader in a `CanonicalMessageBundle` and
/// publishes on the GLOBAL_PROVER bitmask — every subscriber receives
/// it, INCLUDING the publishing node itself when it also subscribes
/// (i.e. when it runs an archive). The test pins down that this
/// self-loopback works end-to-end inside one process without races,
/// drops, or duplication of the emitted bundle.
///
/// Mechanism (mirrors `main.rs:1094-1130`):
///   1. `coverage_publish` callback wraps header bytes in a
///      `CanonicalMessageBundle{requests:[wrap(header)], timestamp}`.
///   2. The same node's archive subscriber decodes the bundle proto
///      via `consensus_wire::decode_message_bundle`.
///   3. The decoded proto is fed to the archive's materializer.
///
/// Asserts:
///   - Every emission from the worker arrives in the same-node
///     archive's input queue exactly once (no drop, no duplication).
///   - The archive's materializer accepts the bundle
///     (`processed >= 1`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_coverage_composite_loopback() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // -----------------------------------------------------------------
    // The archive's input queue. Lives on the same node as the worker.
    // Models the GLOBAL_PROVER subscription buffer.
    // -----------------------------------------------------------------
    let archive_inbox: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));

    // Replica of production's `coverage_publish` (main.rs:1094-1130) —
    // wraps the header in a CanonicalMessageBundle and pushes to the
    // shared inbox (= the node's own GLOBAL_PROVER subscription).
    let inbox_for_cb = archive_inbox.clone();
    let coverage_publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> =
        Arc::new(move |header_canonical_bytes: Vec<u8>| {
            use quil_execution::message_envelope::{
                CanonicalMessageBundle, CanonicalMessageRequest,
            };
            let req = CanonicalMessageRequest::wrap(header_canonical_bytes)
                .expect("self-coverage: wrap header");
            let bundle = CanonicalMessageBundle {
                requests: vec![Some(req)],
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64,
            };
            let bytes = bundle
                .to_canonical_bytes()
                .expect("self-coverage: encode bundle");
            inbox_for_cb.lock().push(bytes);
        });

    // -----------------------------------------------------------------
    // Build a worker that pushes coverage through `coverage_publish`.
    // Drive it with a synthetic FrameHeader emission rather than a
    // full HotStuff loop — we're testing the loopback wiring, not the
    // consensus engine (which other tests cover).
    // -----------------------------------------------------------------
    let prover = TestProver::generate();
    let filter: Vec<u8> = vec![0x44; 32];
    let synthetic_header = quil_execution::global_intrinsic::frame_header::FrameHeader {
        address: filter.clone(),
        frame_number: 5,
        rank: 0,
        timestamp: 1_700_000_000_000,
        difficulty: 100_000,
        output: vec![0u8; 516],
        parent_selector: vec![0u8; 64],
        requests_root: vec![0u8; 64],
        state_roots: vec![vec![0u8; 64]; 4],
        // `prover` is the BLS pubkey (a real G2 point) — the committee
        // member; the attestation verifier reconstructs the aggregate
        // pubkey from the registry's active member, so the declared
        // pubkey in `single_signer_agg_sig` must use the same key.
        prover: prover.bls_pubkey.clone(),
        fee_multiplier_vote: 1,
        public_key_signature_bls48581: single_signer_agg_sig(&prover.bls_pubkey)
            .to_canonical_bytes()
            .expect("self-coverage agg sig"),
        storage_attestation_root: Vec::new(),
        global_frame_number: 0,
        storage_attestation: Vec::new(),
    };
    let header_bytes = synthetic_header
        .to_canonical_bytes()
        .expect("encode synthetic header");

    // Worker emits TWO coverage bundles in succession — verifies no
    // race between concurrent emissions and the inbox accumulator.
    coverage_publish(header_bytes.clone());
    coverage_publish(header_bytes.clone());

    // -----------------------------------------------------------------
    // Verify each emission landed in the inbox exactly once.
    // -----------------------------------------------------------------
    let inbox_snapshot = archive_inbox.lock().clone();
    assert_eq!(
        inbox_snapshot.len(),
        2,
        "expected 2 bundles in the same-node inbox (one per coverage_publish), got {}",
        inbox_snapshot.len()
    );

    // -----------------------------------------------------------------
    // Build a Tier-2 archive and have IT materialize the bundles from
    // its own inbox — closes the self-coverage loop in-process.
    // -----------------------------------------------------------------
    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(genesis_provers[0].clone(), &genesis_provers, &seed_hex);

    // Seed the synthetic worker as an Active prover on the coverage
    // frame's shard filter so the archive's attestation verifier can
    // reconstruct the (single-member) committee that signed it.
    quil_engine::genesis::seed_active_prover_on_filter(
        &archive.crdt,
        &prover.bls_pubkey,
        /* seniority */ 1,
        /* frame_number */ 1,
        &filter,
    )
    .expect("seed self-coverage prover as Active on shard filter");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    let proto_bundles: Vec<quil_types::proto::global::MessageBundle> = inbox_snapshot
        .iter()
        .map(|b| {
            quil_engine::consensus_wire::decode_message_bundle(b).expect("self-coverage decode")
        })
        .collect();
    let coverage_frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: 10,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: proto_bundles,
        ..Default::default()
    };

    let result = archive
        .materializer
        .materialize_synced(&coverage_frame)
        .expect("materialize self-coverage frame");
    eprintln!(
        "self-coverage materialize: processed={} skipped={}",
        result.processed, result.skipped
    );
    assert!(
        result.processed >= 1,
        "archive must accept its own coverage bundle via loopback; \
         processed={} skipped={}",
        result.processed,
        result.skipped,
    );
}

/// End-to-end PoRep storage audit + eviction THROUGH the real global
/// materialize path (`FrameMaterializer` → `invoke_frame_header` → sig verify
/// → archive-mode gate → `audit_storage_attestation` → `kick_prover_by_address`).
///
/// A prover is Active on a shard but submits a reward proof whose carried
/// `StorageAttestation` opening is UNREGISTERED (no on-chain
/// `leafroot:LeafRootRegistration` vertex), so the ρ_N-sampled audit's registry
/// cross-check fails → the member is evicted. Asserts the on-chain eviction
/// signature (Seniority zeroed + KickFrameNumber set), proving the audit is
/// actually reached in the materialize pipeline (not just the unit-tested
/// helper) and that it mutates committed prover state.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tier2_storage_audit_evicts_cheating_member() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    quil_crypto::init();

    let prover = TestProver::generate();
    let filter: Vec<u8> = vec![0x46; 32];

    // One opening for `prover`, at the current epoch, but with NO matching
    // leaf-root registration on chain → the audit's registry cross-check fails.
    let opening = quil_types::proto::global::StorageOpening {
        shard_id: vec![0x07u8; 32],
        epoch: quil_types::consensus::epoch_for_frame(1000),
        member_id: prover.address.clone(),
        query: 0,
        leaf_root: vec![0u8; 666],
        num_blocks: 1,
        path_commits: vec![],
        path_proofs: vec![],
        commitment: vec![0u8; 666],
        value: vec![0u8; 32],
        proof: vec![0u8; 666],
    };
    let att = quil_types::proto::global::StorageAttestation {
        openings: vec![opening],
    };

    // Reward proof anchored to a real global frame (gfn=1000 → storage active),
    // signed by the single-member committee (this prover). `output=[0;516]` is
    // accepted by the rig's frame prover (same as `self_coverage_*`).
    let reward = quil_execution::global_intrinsic::frame_header::FrameHeader {
        address: filter.clone(),
        frame_number: 5,
        rank: 0,
        timestamp: 1_700_000_000_000,
        difficulty: 100_000,
        output: vec![0u8; 516],
        parent_selector: vec![0u8; 64],
        requests_root: vec![0u8; 64],
        state_roots: vec![vec![0u8; 64]; 4],
        prover: prover.bls_pubkey.clone(),
        fee_multiplier_vote: 1,
        public_key_signature_bls48581: single_signer_agg_sig(&prover.bls_pubkey)
            .to_canonical_bytes()
            .expect("agg sig"),
        storage_attestation_root: vec![0u8; 666],
        global_frame_number: 1000,
        storage_attestation: prost::Message::encode_to_vec(&att),
    };
    let header_bytes = reward.to_canonical_bytes().expect("encode reward proof");
    let bundle = {
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let req = CanonicalMessageRequest::wrap(header_bytes).expect("wrap reward");
        CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .expect("encode bundle")
    };

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(genesis_provers[0].clone(), &genesis_provers, &seed_hex);

    // Seed the cheating prover Active on the shard (seniority 1) so the
    // attestation verifier reconstructs the single-member committee + the kick
    // has a prover vertex to mutate.
    quil_engine::genesis::seed_active_prover_on_filter(
        &archive.crdt,
        &prover.bls_pubkey,
        /* seniority */ 1,
        /* frame_number */ 1,
        &filter,
    )
    .expect("seed cheating prover Active on shard filter");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    let before = archive
        .prover_registry
        .read(|r| r.get_prover_info(&prover.address).cloned())
        .expect("prover present before audit");
    assert_eq!(
        before.seniority, 1,
        "precondition: prover Active with seniority 1"
    );
    assert_eq!(before.kick_frame_number, 0, "precondition: not yet kicked");

    // STRICT LOCKSTEP: a storage frame's attestation must anchor to the
    // IMMEDIATELY PRECEDING global frame, so the enclosing global frame number
    // must be `global_frame_number + 1` (= 1001) to satisfy the
    // `anchor == frame_number - 1` gate in `audit_storage_attestation`.
    let coverage_frame = build_global_frame_with_bundle(1001, &bundle);
    let result = archive
        .materializer
        .materialize_synced(&coverage_frame)
        .expect("materialize reward proof with cheating attestation");
    assert!(
        result.processed >= 1,
        "reward proof must be processed by the materializer; processed={} skipped={}",
        result.processed,
        result.skipped,
    );

    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
    let after = archive
        .prover_registry
        .read(|r| r.get_prover_info(&prover.address).cloned())
        .expect("prover present after audit");
    // Eviction signature: the kick zeroes the prover's seniority and stamps the
    // allocation with the kick frame (the same `materialize_prover_kick` path a
    // signed ProverKick uses).
    assert_eq!(
        after.seniority, 0,
        "storage audit must evict the unregistered member (Seniority → 0)",
    );
    assert!(
        after.allocations.iter().any(|a| a.kick_frame_number > 0),
        "evicted member's allocation must carry a KickFrameNumber; allocs={:?}",
        after
            .allocations
            .iter()
            .map(|a| (a.status, a.kick_frame_number))
            .collect::<Vec<_>>(),
    );
}

/// After WorkerAllocator detects a Joining→Active transition, the
/// **SpawningWorkerManager** actually instantiates an
/// `AppConsensusEngine` for the confirmed shard. This test verifies
/// the spawn closure is invoked with the correct `(core_id, filter)`,
/// returns a live `AppEngineHandle`, and the spawned engine task
/// successfully transitions past the consensus-bootstrap phase
/// (`shard HotStuff event loop running` info log fires) without
/// panicking.
///
/// Real frame production for a fully-wired AppConsensusEngine is
/// already covered by `worker_carries_real_dispatch_message_in_shard_frame`
/// and friends via `AppShardHarness::build(4)`. The piece this test
/// adds is the **spawn wiring**: WorkerAllocator → set_worker_filter
/// → user-supplied closure → AppConsensusEngine task started.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tier2_allocator_spawns_real_engine_on_confirm() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    let prover = TestProver::generate();
    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 11;
        a
    };

    // Track every spawn the allocator triggers. Each spawn records
    // (core_id, filter) so we can assert what got activated.
    let spawn_log: Arc<Mutex<Vec<(u32, Vec<u8>)>>> = Arc::new(Mutex::new(Vec::new()));
    let event_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Build the deps each spawned worker needs. These get captured
    // into the spawn closure.
    let provers_info = vec![prover.to_prover_info(1)];
    let registry = Arc::new(TestProverRegistry::with_provers(provers_info.clone()));
    let frame_prover: Arc<dyn FrameProver> = Arc::new(StubFrameProver);
    let fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager> =
        Arc::new(quil_engine::InMemoryDynamicFeeManager::new(32));

    let prover_for_spawn = prover.clone();
    let spawn_log_clone = spawn_log.clone();
    let event_log_clone = event_log.clone();
    let spawn_fn: Arc<
        dyn Fn(u32, Vec<u8>) -> quil_engine::app_engine::AppEngineHandle + Send + Sync,
    > = Arc::new(move |core_id: u32, filter_bytes: Vec<u8>| {
        spawn_log_clone.lock().push((core_id, filter_bytes.clone()));

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        let clock_store = Arc::new(InMemoryClockStore::new());
        let message_collector = Arc::new(quil_engine::message_collector::MessageCollector::new());
        let coverage_published: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let cp_for_cb = coverage_published.clone();
        let coverage_publish: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>> =
            Some(Arc::new(move |bytes: Vec<u8>| {
                cp_for_cb.lock().push(bytes);
            }));

        let deps = quil_engine::app_engine::AppEngineDeps {
            clock_store: clock_store as Arc<dyn ClockStore>,
            global_anchor_store: None,
            storage_source_hypergraph: None,
            prover_registry: registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
            frame_prover: frame_prover.clone(),
            message_collector,
            fee_manager: fee_manager.clone(),
            local_prover_address: prover_for_spawn.address.clone(),
            local_bls_pubkey: prover_for_spawn.bls_pubkey.clone(),
            bls_signer: prover_for_spawn.signer_clone(),
            reward_greedy: true,
            min_active_provers_for_propose: 1,
            coverage_publish,
            hypergraph: None,
            execution_engine: Some(Arc::new(build_test_exec_manager(
                Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver>,
                false,
            ))),
            inclusion_prover: Some(
                Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver + Send + Sync>
            ),
            kv_db: None,
            app_consensus_cw: false,
            db_config: quil_config::DbConfig { path: String::new(), worker_path_prefix: String::new(), worker_paths: vec![], ..Default::default() }, // ephemeral journal in tests
            unified_cutover_hook: None,
        };

        let (engine, handle) =
            quil_engine::app_engine::AppConsensusEngine::new(core_id, filter_bytes, deps, event_tx);
        let bls_signer = prover_for_spawn.signer_clone();
        let sk = bls_signer.private_key().to_vec();
        let pk = bls_signer.public_key().to_vec();
        let factory: std::sync::Arc<
            dyn Fn() -> Box<dyn quil_types::crypto::Signer> + Send + Sync,
        > = std::sync::Arc::new(move || {
            Box::new(quil_crypto::FalconSigner::from_bytes(&sk, &pk))
        });
        let exit_log = event_log_clone.clone();
        let join = tokio::spawn(async move {
            engine.run(factory).await;
        });
        // Sentinel: log if the engine task ever exits.
        tokio::spawn(async move {
            let r = join.await;
            let kind = match r {
                Ok(_) => "engine_task_returned".to_string(),
                Err(e) if e.is_panic() => format!("engine_panicked: {:?}", e),
                Err(e) => format!("engine_join_err: {:?}", e),
            };
            eprintln!("[spawn] {kind}");
            exit_log.lock().push(kind);
        });
        let event_log = event_log_clone.clone();
        tokio::spawn(async move {
            while let Some(ev) = event_rx.recv().await {
                use quil_engine::app_engine::AppEngineEvent::*;
                let name = match ev {
                    FrameProduced { .. } => "FrameProduced",
                    FullFrameProduced { .. } => "FullFrameProduced",
                    VoteProduced { .. } => "VoteProduced",
                    TimeoutProduced { .. } => "TimeoutProduced",
                    ShardFrameFinalized { .. } => "ShardFrameFinalized",
                    EquivocationDetected { .. } => "EquivocationDetected",
                    Halted { .. } => "Halted",
                    AncestorSyncRequested { .. } => "AncestorSyncRequested",
                    ParentSealed { .. } => "ParentSealed",
                    CwOut { .. } => "CwOut",
                };
                event_log.lock().push(name.to_string());
            }
        });

        // This focused spawn test has no P2P layer. Its local event drain is
        // already installed, so model the production transport-ready callback
        // explicitly before returning the worker handle.
        handle.set_cw_transport_ready();
        handle
    });

    let wm = Arc::new(quil_engine::test_support::SpawningWorkerManager::new(
        spawn_fn,
    ));
    // Seed worker 0 — the allocator can find it before spawn.
    wm.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: filter.clone(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 0,
        allocated: false, // will be flipped to true on activation
    });

    // Trigger the activation that production's WorkerAllocator would
    // perform after observing Joining→Active in the registry.
    use quil_engine::worker::WorkerManager as _;
    wm.set_worker_filter(0, &filter, /* start_consensus */ true)
        .expect("set_worker_filter");

    // Verify spawn was called.
    let log = spawn_log.lock().clone();
    assert_eq!(
        log.len(),
        1,
        "expected one spawn invocation, got {}",
        log.len()
    );
    assert_eq!(log[0].0, 0);
    assert_eq!(log[0].1, filter);

    // Verify a handle was registered.
    let handles = wm.snapshot_handles();
    assert_eq!(handles.len(), 1, "expected one engine handle");

    // Wait for the spawned engine to emit at least one real
    // `AppEngineEvent`. In a single-prover committee
    // (quorum_threshold = 0), the leader's own proposal forms a QC
    // immediately on self-vote, so `FrameProduced` / `VoteProduced`
    // arrive quickly. A timeout here means the event-loop is
    // busy-looping and starving the engine run-loop.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let entries = event_log.lock();
        // Filter out the "engine exited" sentinels — they indicate
        // crash, not liveness.
        let live = entries
            .iter()
            .any(|e| !e.starts_with("engine_panic") && e.as_str() != "engine_task_returned");
        if live {
            break;
        }
    }
    let entries = event_log.lock().clone();
    eprintln!("post-spawn event entries: {:?}", entries);
    let crashed: Vec<&String> = entries
        .iter()
        .filter(|e| e.starts_with("engine_panic") || e.as_str() == "engine_task_returned")
        .collect();
    assert!(
        crashed.is_empty(),
        "spawned engine task exited — wiring crash. entries={entries:?}"
    );
    let live: Vec<&String> = entries
        .iter()
        .filter(|e| !e.starts_with("engine_panic") && e.as_str() != "engine_task_returned")
        .collect();
    assert!(
        !live.is_empty(),
        "spawned engine produced no AppEngineEvent within 60s — \
         single-prover event-loop is likely busy-looping"
    );
}
