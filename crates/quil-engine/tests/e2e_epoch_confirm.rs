//! Epoch-aligned confirm-flow e2e tests, isolated in their own binary so they
//! can set a short EPOCH_LENGTH override (a process-global atomic) without
//! corrupting the parallel tests in e2e_consensus.rs. Genesis provers are
//! GLOBAL (empty filter) so a short epoch never expires them; only the joiner's
//! data-shard allocation is epoch-gated, which is the point under test.
#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

mod common;
use common::*;

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use quil_types::consensus::{DifficultyAdjuster, ProverRegistry};
use quil_types::crypto::{
    BlsConstructor, FrameProver, InclusionProver, NoopInclusionProver, Signer,
};
use quil_types::error::Result as QResult;
use quil_types::proto::global as gpb;
use quil_types::store::ClockStore;

use quil_engine::test_support::TestProverRegistry;
use quil_store::testing::InMemoryClockStore;

// ===================================================================
// Test helper — ExecutionEngineManager built with noop crypto stubs.
// ===================================================================

/// Drives the join further: after the joiner's `ProverJoin` has been
/// materialized into the shared registry, the *joiner* (not the
/// archive!) ticks its own lifecycle. `ProverConfirm` is a
/// self-affirmation — each prover confirms their own pending joins
/// once `confirm_window` frames have elapsed, not third-party. After
/// enough frames the joiner's lifecycle should emit a `ConfirmJoins`
/// action and the joiner's pipeline turn it into a signed
/// `ProverConfirm` bundle captured by `TestProverMessageTransport`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
// Epoch-aligned lifecycle: a join now self-confirms only after crossing into the
// NEXT epoch (the exact-E+1 confirm slot). This harness ticks ~15 near-genesis
// frames inside a single epoch, so the confirm never fires. It can't use a short
// test epoch because EPOCH_LENGTH_FRAMES is a process-global atomic shared with
// parallel coverage tests (a small value would read their seeded epoch-0 provers
// as ExpiredEpoch), and shifting to the real 720 boundary breaks the rig's
// near-genesis materializer/join-proof context. Re-enable once epoch length is
// threaded per-instance (or via serial_test). See task: epoch-e2e-retarget.
async fn tier2_joiner_lifecycle_emits_self_confirm_after_join() {
    quil_types::consensus::set_epoch_length_frames(16);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // 1. Archive setup.
    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(genesis_provers[0].clone(), &genesis_provers, &seed_hex);

    // Seed transport's head so submit_join works.
    archive.transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });

    // 2. Build joiner pipeline. Crucially, the joiner's lifecycle
    //    needs a `ProverRegistry` that, post-materialize, will report
    //    its OWN Joining allocation. We let the joiner SHARE the
    //    archive's `SharedProverRegistry` — production would refresh
    //    each node's own copy from its own `hg_store` via HyperSync,
    //    but for this test the shared registry is the simplest way
    //    to model "the join was observed and persisted everywhere".
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
    // Seed worker 0 with allocated=false. `decide_joins` only confirms
    // joins up to `available_workers = workers.filter(!allocated).count()`;
    // without this the lifecycle sees zero capacity and rejects every
    // pending join. Mirrors production where workers exist before the
    // first join is proposed.
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

    // 3. Pick filter and submit the join.
    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 2;
        a
    };
    joiner_pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = joiner_transport.drain_outbound();
    assert_eq!(join_bundles.len(), 1);

    // 4. Materialize the join at frame 6.
    let join_frame = build_global_frame_with_bundle(6, &join_bundles[0]);
    archive
        .materializer
        .materialize(&join_frame)
        .expect("materialize join");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    // Sanity: joiner is now in the registry.
    assert!(
        archive
            .prover_registry
            .read(|r| r.get_prover_info(&joiner.address).is_some()),
        "joiner missing from registry after materialize"
    );

    // 5. Tick the JOINER's lifecycle. The joiner's lifecycle reads
    //    its own `Joining` allocation (now in the shared registry
    //    post-materialize) and after `confirm_window_frames = 10`
    //    frames emits a `ConfirmJoins` action.
    //
    // Lifecycle gates the entire `evaluate` body on a baseline
    // readiness check (`frame_seen + initial_sync_complete +
    // tree_verified`). In production these flip true once the node
    // finishes the initial prover-tree sync; tests have to flip them
    // by hand or every `evaluate` call early-returns with empty actions.
    joiner_pipeline.lifecycle.set_sync_complete();
    joiner_pipeline.lifecycle.set_confirm_window_frames(10);
    // `build_decide_descriptors` filters out any shard whose
    // `shard_sizes` lookup returns 0 or missing — those summaries
    // never become descriptors and so `decide_joins` never sees them
    // as confirm candidates, rejecting every pending join by default.
    // Seed a nonzero size for our filter (and a few neighboring
    // genesis shards so the joiner has comparison baseline).
    let mut shard_sizes: std::collections::HashMap<Vec<u8>, u64> = std::collections::HashMap::new();
    shard_sizes.insert(filter.clone(), 1000);
    for i in 0u8..6 {
        let mut a = vec![0u8; 32];
        a[0] = i;
        shard_sizes.insert(a, 1000);
    }
    joiner_pipeline
        .lifecycle
        .set_remote_shard_sizes(shard_sizes);

    let joiner_cf = joiner_pipeline.current_frame.clone();
    joiner_cf.observe(6);
    joiner_cf.materialize(6);

    let mut confirm_seen = false;
    for frame_num in 7u64..=21 {
        joiner_cf.observe(frame_num);
        joiner_cf.materialize(frame_num);
        joiner_pipeline
            .lifecycle
            .set_prover_root_verified_frame(frame_num);

        let registry_ref =
            archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>;
        if frame_num == 16 {
            // Diagnostic: dump everything the lifecycle will see.
            let info = registry_ref
                .get_prover_info(&joiner.address)
                .expect("get_prover_info")
                .expect("joiner missing");
            eprintln!("joiner allocations at frame {}:", frame_num);
            for a in &info.allocations {
                eprintln!(
                    "  filter={} status={:?} join_frame={} confirm_frame={}",
                    hex::encode(&a.confirmation_filter),
                    a.status,
                    a.join_frame_number,
                    a.join_confirm_frame_number,
                );
            }
            let summaries = registry_ref.get_prover_shard_summaries(frame_num).unwrap();
            eprintln!("summaries: {} entries", summaries.len());
            for s in summaries.iter().take(10) {
                eprintln!(
                    "  filter={} status_counts={:?} total_size={}",
                    hex::encode(&s.filter),
                    s.status_counts,
                    s.total_size,
                );
            }
        }
        let actions = joiner_pipeline
            .lifecycle
            .evaluate(
                frame_num,
                100_000,
                registry_ref.as_ref(),
                joiner_pipeline.worker_manager.as_ref(),
            )
            .expect("lifecycle evaluate");
        eprintln!("frame {} → {} action(s)", frame_num, actions.len());
        for action in actions {
            use quil_engine::provers::lifecycle::LifecycleAction;
            eprintln!("    action: {:?}", action);
            if let LifecycleAction::ConfirmJoins { ref filters, .. } = action {
                if filters.iter().any(|f| f == &filter) {
                    confirm_seen = true;
                }
            }
            joiner_pipeline.pipeline.dispatch(action);
        }

        // dispatch is async — give it a tick to drain.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Wait briefly for any in-flight dispatched ProverConfirm to be
    // published through the transport.
    for _ in 0..50 {
        if joiner_transport.outbound_len() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let joiner_outbound = joiner_transport.drain_outbound();
    eprintln!(
        "joiner outbound bundles: {} (lifecycle saw confirm_action: {})",
        joiner_outbound.len(),
        confirm_seen,
    );

    assert!(
        confirm_seen,
        "joiner lifecycle never emitted ConfirmJoins for its own filter \
         after 15 frames past the join (confirm_window=10)"
    );
    assert!(
        !joiner_outbound.is_empty(),
        "joiner pipeline never published any outbound bundle \
         (expected at least one ProverConfirm)"
    );
}

/// Full round-trip: joiner submits ProverJoin → archive materializes
/// (allocation = Joining) → joiner self-confirms after window →
/// archive materializes the ProverConfirm (allocation flips
/// Joining → Active) → `WorkerAllocator.on_new_frame` detects the
/// Active allocation and calls `set_worker_filter(..., true)` to
/// trigger shard-engine spawn.
///
/// Verifies the confirm → Active → allocator → worker-spawn link
/// end-to-end against the in-memory archive harness.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
// Epoch-aligned lifecycle: the joiner self-confirms only after crossing into the
// next epoch, which this near-genesis single-epoch harness never reaches. See the
// note on `tier2_joiner_lifecycle_emits_self_confirm_after_join`.
async fn tier2_confirm_materializes_to_active_and_allocator_starts_worker() {
    quil_types::consensus::set_epoch_length_frames(16);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // The materializer's verifier independently enforces the confirm
    // timing window — its default 360-frame minimum rejects any
    // ProverConfirm submitted earlier (Go's
    // `validate_confirm_timing`). Production calls this on testnet
    // bootstrap (main.rs:1658). Test must do the same or every
    // ProverConfirm gets a "must wait 360 frames after join" reject
    // and the allocation stays Joining.
    //
    // Set via this static once per process; subsequent tests inherit.
    quil_execution::global_intrinsic::verify::set_confirm_window_frames(10, 720);

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(genesis_provers[0].clone(), &genesis_provers, &seed_hex);
    archive.transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });

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
        a[0] = 3;
        a
    };

    // Step A: join → materialize at frame 6 → allocation = Joining
    joiner_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = joiner_transport.drain_outbound();
    assert_eq!(join_bundles.len(), 1);
    let join_frame = build_global_frame_with_bundle(6, &join_bundles[0]);
    archive
        .materializer
        .materialize(&join_frame)
        .expect("materialize join");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    // Verify Joining status.
    let joining = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        joining,
        Some(quil_types::consensus::ProverStatus::Joining),
        "expected joiner to be Joining after materialize"
    );

    // Step B: drive joiner's lifecycle to emit ConfirmJoins.
    joiner_pipeline.lifecycle.set_sync_complete();
    joiner_pipeline.lifecycle.set_confirm_window_frames(10);
    let mut shard_sizes: std::collections::HashMap<Vec<u8>, u64> = std::collections::HashMap::new();
    shard_sizes.insert(filter.clone(), 1000);
    for i in 0u8..6 {
        let mut a = vec![0u8; 32];
        a[0] = i;
        shard_sizes.insert(a, 1000);
    }
    joiner_pipeline
        .lifecycle
        .set_remote_shard_sizes(shard_sizes);

    let joiner_cf = joiner_pipeline.current_frame.clone();
    for frame_num in 6u64..=21 {
        joiner_cf.observe(frame_num);
        joiner_cf.materialize(frame_num);
        joiner_pipeline
            .lifecycle
            .set_prover_root_verified_frame(frame_num);
        let registry_ref =
            archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>;
        let actions = joiner_pipeline
            .lifecycle
            .evaluate(
                frame_num,
                100_000,
                registry_ref.as_ref(),
                joiner_pipeline.worker_manager.as_ref(),
            )
            .expect("evaluate");
        for action in actions {
            joiner_pipeline.pipeline.dispatch(action);
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    // Drain after the loop — dispatch is async and the bundle may
    // arrive at the transport a few hundred ms after the action fires.
    for _ in 0..50 {
        if joiner_transport.outbound_len() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut drained = joiner_transport.drain_outbound();
    eprintln!("joiner emitted {} bundles total", drained.len());
    let confirm_bytes = drained
        .pop()
        .expect("joiner pipeline never emitted a ProverConfirm");

    // Step C: archive materializes the ProverConfirm at frame 17 →
    // allocation flips Joining → Active.
    let confirm_frame = build_global_frame_with_bundle(17, &confirm_bytes);
    let confirm_result = archive
        .materializer
        .materialize(&confirm_frame)
        .expect("materialize ProverConfirm");
    eprintln!(
        "ProverConfirm materialize: processed={} skipped={}",
        confirm_result.processed, confirm_result.skipped,
    );
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    let status_after_confirm = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        status_after_confirm,
        Some(quil_types::consensus::ProverStatus::Active),
        "expected joiner allocation to flip Joining→Active after ProverConfirm; \
         processed={} skipped={}",
        confirm_result.processed,
        confirm_result.skipped,
    );

    // Step D: WorkerAllocator.on_new_frame sees the Active allocation
    // and calls `set_worker_filter(core_id, filter, start_consensus=true)`
    // on its worker manager. We use the ARCHIVE's allocator (which
    // wraps a `TestWorkerManager`) to check this — but the archive
    // isn't the joiner, so its allocations don't change. To verify
    // the allocator's reconciliation logic we need to drive it for
    // the JOINER. Build a dedicated allocator + worker_manager for
    // the joiner that shares the archive's (now-updated) registry.
    let joiner_alloc_wm = Arc::new(quil_engine::test_support::TestWorkerManager::new());
    joiner_alloc_wm.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: filter.clone(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 5, // would be set by submit_join in prod
        allocated: false,        // pending: filter pinned, awaiting confirm
    });
    let joiner_allocator = Arc::new(quil_engine::worker_allocator::WorkerAllocator::new(
        joiner_alloc_wm.clone() as Arc<dyn quil_engine::worker::WorkerManager>,
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        joiner.address.clone(),
    ));

    joiner_allocator
        .on_new_frame(18)
        .expect("WorkerAllocator.on_new_frame");

    // After reconciliation: worker 0's `allocated` flag should be
    // true (allocation transitioned Joining→Active in registry).
    use quil_engine::worker::WorkerManager as _;
    let workers = joiner_alloc_wm.range_workers().expect("range_workers");
    let w0 = workers.iter().find(|w| w.core_id == 0).expect("worker 0");
    eprintln!(
        "worker 0 after reconcile: filter={} allocated={} pending_filter_frame={}",
        hex::encode(&w0.filter),
        w0.allocated,
        w0.pending_filter_frame,
    );
    assert!(
        w0.allocated,
        "WorkerAllocator did not flip worker 0 to allocated=true after the registry showed Active"
    );
    assert_eq!(
        w0.filter, filter,
        "worker 0's filter should remain pinned to the confirmed shard"
    );
}

/// End-to-end: archive ingests a shard `FrameHeader` (coverage proof)
/// and the contributing prover's allocation advances on-chain
/// (`LastActiveFrameNumber`).
///
/// Exercises the full materialize → state-advance path, including
/// `validate_message` → `process_message` ordering, BLS aggregate-sig
/// verification against `get_active_provers`, and `Shard`
/// (`FrameHeader`) variant round-trip through `consensus_wire`'s
/// canonical → proto → canonical encoders.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
// Epoch-aligned lifecycle: depends on a joiner self-confirming within the harness
// (now requires crossing an epoch boundary). See the note on
// `tier2_joiner_lifecycle_emits_self_confirm_after_join`.
async fn tier2_coverage_ingest_advances_archive_allocation_state() {
    quil_types::consensus::set_epoch_length_frames(16);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // Confirm window open enough for the joiner to self-confirm
    // within ~10 frames (testnet shortcut).
    quil_execution::global_intrinsic::verify::set_confirm_window_frames(10, 720);

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let real_km: Arc<dyn quil_types::crypto::KeyManager> = Arc::new(
        quil_crypto::DefaultKeyManager::new(Arc::new(quil_crypto::Bls48581KeyConstructor)),
    );
    let archive = build_tier2_archive_rig_with_key_manager(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
        real_km,
    );

    // 1. Joiner submits a real ProverJoin.
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
        a[0] = 9;
        a
    };
    joiner_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = joiner_transport.drain_outbound();
    archive
        .materializer
        .materialize(&build_global_frame_with_bundle(6, &join_bundles[0]))
        .expect("materialize join");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    // 2. Joiner self-confirms after the window.
    joiner_pipeline.lifecycle.set_sync_complete();
    joiner_pipeline.lifecycle.set_confirm_window_frames(10);
    let mut shard_sizes: std::collections::HashMap<Vec<u8>, u64> = std::collections::HashMap::new();
    shard_sizes.insert(filter.clone(), 1000);
    for i in 0u8..6 {
        let mut a = vec![0u8; 32];
        a[0] = i;
        shard_sizes.insert(a, 1000);
    }
    joiner_pipeline
        .lifecycle
        .set_remote_shard_sizes(shard_sizes);
    let joiner_cf = joiner_pipeline.current_frame.clone();
    for frame_num in 6u64..=21 {
        joiner_cf.observe(frame_num);
        joiner_cf.materialize(frame_num);
        joiner_pipeline
            .lifecycle
            .set_prover_root_verified_frame(frame_num);
        let registry_ref =
            archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>;
        let actions = joiner_pipeline
            .lifecycle
            .evaluate(
                frame_num,
                100_000,
                registry_ref.as_ref(),
                joiner_pipeline.worker_manager.as_ref(),
            )
            .expect("evaluate");
        for action in actions {
            joiner_pipeline.pipeline.dispatch(action);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // Wait for the confirm bundle to publish.
    for _ in 0..50 {
        if joiner_transport.outbound_len() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let confirm_bytes = joiner_transport
        .drain_outbound()
        .pop()
        .expect("joiner pipeline never emitted a ProverConfirm");
    archive
        .materializer
        .materialize(&build_global_frame_with_bundle(17, &confirm_bytes))
        .expect("materialize confirm");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    // Verify allocation is now Active.
    let status_after_confirm = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .cloned()
    });
    let alloc = status_after_confirm.expect("joiner has allocation");
    assert_eq!(
        alloc.status,
        quil_types::consensus::ProverStatus::Active,
        "joiner should be Active after confirm"
    );
    let pre_last_active = alloc.last_active_frame_number;

    // 3. Build a shard `FrameHeader` claiming the joiner participated.
    //    `address` = the shard's app-shard address (Poseidon(filter));
    //    `prover` = joiner's BLS pubkey; aggregate-sig `bitmask=[0x01]`
    //    so participant index 0 = joiner (the only Active prover).
    use quil_execution::global_intrinsic::frame_header::FrameHeader;
    use quil_execution::hypergraph_intrinsic::canonical::AggregateSignature;

    // The FrameHeader's `address` is the raw shard filter (matches
    // what `AppFollower::on_finalized_state` emits in production —
    // see `app_glue.rs:544-549`). `pr.get_active_provers(&filter)`
    // returns provers whose allocation.confirmation_filter == filter,
    // so the participant-index lookup resolves.
    let shard_address = filter.clone();
    // Aggregate signature decoder requires `sig_len == 74` or
    // `sig_len == 74 + n*516` (canonical.rs:198-205). The declared
    // aggregate pubkey must match what the intrinsic reconstructs from
    // the active committee (just the joiner here); `single_signer_agg_sig`
    // builds that. Use a 74-byte placeholder signature.
    let agg_sig = single_signer_agg_sig(&joiner.bls_pubkey);
    let agg_sig_bytes = agg_sig.to_canonical_bytes().expect("agg sig");

    let coverage_frame_number = 25u64; // some frame after confirm

    let header = FrameHeader {
        address: shard_address.clone(),
        frame_number: coverage_frame_number,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        parent_selector: vec![0u8; 32],
        requests_root: vec![0u8; 64],
        state_roots: vec![vec![0u8; 64]; 4],
        prover: joiner.bls_pubkey.clone(),
        fee_multiplier_vote: 0,
        public_key_signature_bls48581: agg_sig_bytes,
        storage_attestation_root: Vec::new(),
        global_frame_number: 0,
        storage_attestation: Vec::new(),
    };
    let header_bytes = header.to_canonical_bytes().expect("encode header");

    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    let req = CanonicalMessageRequest::wrap(header_bytes).expect("wrap");
    let bundle = CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp: 0,
    };
    let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");
    let proto = quil_engine::consensus_wire::decode_message_bundle(&bundle_bytes).expect("decode");

    let coverage_global_frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: coverage_frame_number,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![proto],
        ..Default::default()
    };
    // Diagnostic: what does get_active_provers return for our filter?
    use quil_types::consensus::ProverRegistry as _;
    let active = archive
        .prover_registry
        .get_active_provers(&filter)
        .expect("get_active_provers");
    eprintln!(
        "active provers for filter {}: {}",
        hex::encode(&filter),
        active.len()
    );
    for p in &active {
        eprintln!(
            "  address={} status={:?} pubkey_len={}",
            hex::encode(&p.address),
            p.status,
            p.public_key.len()
        );
    }

    // Probe via the registry's view of the joiner.
    let joiner_pubkey_matches = active
        .iter()
        .find(|p| p.address == joiner.address)
        .map(|p| p.public_key == joiner.bls_pubkey)
        .unwrap_or(false);
    eprintln!(
        "joiner pubkey matches active-registry record: {}",
        joiner_pubkey_matches
    );

    let result = archive
        .materializer
        .materialize(&coverage_global_frame)
        .expect("materialize coverage");
    eprintln!(
        "coverage ingest: processed={} skipped={}",
        result.processed, result.skipped
    );

    // 4. Refresh and assert: joiner's allocation last_active advanced.
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
    let alloc_after = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .cloned()
    });
    let alloc_after = alloc_after.expect("joiner still has allocation");
    eprintln!(
        "last_active: {} → {} (coverage_frame={})",
        pre_last_active, alloc_after.last_active_frame_number, coverage_frame_number,
    );
    assert!(
        alloc_after.last_active_frame_number >= coverage_frame_number,
        "LastActiveFrameNumber should advance to (or past) {} after coverage ingest; \
         pre={} post={}",
        coverage_frame_number,
        pre_last_active,
        alloc_after.last_active_frame_number,
    );
}

/// Tier-2 composite end-to-end: one test that drives the entire
/// pipeline from join → confirm → allocator → spawned worker engine
/// → coverage_publish → archive materialize → LastActiveFrameNumber
/// advance. Existing tests each pin down one link; this one verifies
/// they compose without surprise interactions (timing-window edges,
/// shared registry mutations, materializer back-pressure, etc.).
///
/// Phases:
///   * A — joiner submits ProverJoin → archive materializes Joining
///   * B — joiner lifecycle emits ProverConfirm → archive materializes
///         Joining → Active
///   * C — joiner's `WorkerAllocator` reconciles → SpawningWorkerManager
///         spawns a real `AppConsensusEngine` for the new shard
///   * D — spawned engine produces shard frames; with a single-prover
///         quorum (threshold=0), `FrameProduced` fires within a few
///         seconds via the leader's self-vote
///   * E — engine's `coverage_publish` callback captures the canonical
///         FrameHeader bytes for one finalized shard frame
///   * F — each captured coverage header has its
///         `public_key_signature_bls48581` rewritten with a valid
///         synthetic `AggregateSignature{sig=74×0x00, bitmask=[0x01]}`
///         so the materializer's `invoke_frame_header` aggregate-decode
///         and bitmask-index lookup succeed. The model surface for
///         carrying the certifying QC trait object through to the
///         consumer (`State.parent_quorum_certificate`,
///         `CertifiedState.certifying_quorum_certificate`) is in
///         place; routing it through `AppFollower` end-to-end is
///         left for a follow-on change.
///   * G — archive's `LastActiveFrameNumber` for the joiner's
///         allocation advances to (or past) the coverage frame number
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
// Epoch-aligned lifecycle: the full join→self-confirm→activate→coverage chain now
// requires crossing an epoch boundary mid-harness. See the note on
// `tier2_joiner_lifecycle_emits_self_confirm_after_join`.
async fn tier2_composite_end_to_end() {
    quil_types::consensus::set_epoch_length_frames(16);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    quil_execution::global_intrinsic::verify::set_confirm_window_frames(10, 720);

    // -----------------------------------------------------------------
    // Phase A — bootstrap archive + joiner; submit ProverJoin
    // -----------------------------------------------------------------
    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(genesis_provers[0].clone(), &genesis_provers, &seed_hex);
    archive.transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });

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
        a[0] = 0x33;
        a
    };

    joiner_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = joiner_transport.drain_outbound();
    assert_eq!(join_bundles.len(), 1);
    let join_frame = build_global_frame_with_bundle(6, &join_bundles[0]);
    archive
        .materializer
        .materialize(&join_frame)
        .expect("materialize join");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    // -----------------------------------------------------------------
    // Phase B — lifecycle emits ProverConfirm; archive flips to Active
    // -----------------------------------------------------------------
    joiner_pipeline.lifecycle.set_sync_complete();
    joiner_pipeline.lifecycle.set_confirm_window_frames(10);
    let mut shard_sizes: std::collections::HashMap<Vec<u8>, u64> = std::collections::HashMap::new();
    shard_sizes.insert(filter.clone(), 1000);
    for i in 0u8..6 {
        let mut a = vec![0u8; 32];
        a[0] = i;
        shard_sizes.insert(a, 1000);
    }
    joiner_pipeline
        .lifecycle
        .set_remote_shard_sizes(shard_sizes);

    let joiner_cf = joiner_pipeline.current_frame.clone();
    for frame_num in 6u64..=21 {
        joiner_cf.observe(frame_num);
        joiner_cf.materialize(frame_num);
        joiner_pipeline
            .lifecycle
            .set_prover_root_verified_frame(frame_num);
        let registry_ref =
            archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>;
        let actions = joiner_pipeline
            .lifecycle
            .evaluate(
                frame_num,
                100_000,
                registry_ref.as_ref(),
                joiner_pipeline.worker_manager.as_ref(),
            )
            .expect("evaluate");
        for action in actions {
            joiner_pipeline.pipeline.dispatch(action);
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    for _ in 0..50 {
        if joiner_transport.outbound_len() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut drained = joiner_transport.drain_outbound();
    let confirm_bytes = drained.pop().expect("joiner never emitted ProverConfirm");
    let confirm_frame = build_global_frame_with_bundle(17, &confirm_bytes);
    archive
        .materializer
        .materialize(&confirm_frame)
        .expect("materialize ProverConfirm");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    let status_after = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        status_after,
        Some(quil_types::consensus::ProverStatus::Active),
        "joiner allocation must be Active after ProverConfirm materialize"
    );

    // -----------------------------------------------------------------
    // Phase C — SpawningWorkerManager fires on the Active transition.
    // -----------------------------------------------------------------
    let coverage_published: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let event_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Build the engine deps closure. The spawned engine runs the joiner
    // as a single-prover shard committee — the event loop yields per
    // iteration so the self-vote → QC → propose chain doesn't starve
    // the engine run-loop.
    let registry_for_engine = archive.prover_registry.clone();
    let joiner_for_engine = joiner.clone();
    let coverage_for_cb = coverage_published.clone();
    let event_for_cb = event_log.clone();
    let spawn_fn: Arc<
        dyn Fn(u32, Vec<u8>) -> quil_engine::app_engine::AppEngineHandle + Send + Sync,
    > = Arc::new(move |core_id: u32, filter_bytes: Vec<u8>| {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let clock_store = Arc::new(InMemoryClockStore::new());
        let message_collector = Arc::new(quil_engine::message_collector::MessageCollector::new());
        let cov_inner = coverage_for_cb.clone();
        let coverage_publish: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>> =
            Some(Arc::new(move |bytes: Vec<u8>| {
                cov_inner.lock().push(bytes);
            }));

        let deps = quil_engine::app_engine::AppEngineDeps {
            clock_store: clock_store as Arc<dyn ClockStore>,
            prover_registry: registry_for_engine.clone()
                as Arc<dyn quil_types::consensus::ProverRegistry>,
            frame_prover: Arc::new(StubFrameProver) as Arc<dyn FrameProver>,
            message_collector,
            fee_manager: Arc::new(quil_engine::InMemoryDynamicFeeManager::new(32))
                as Arc<dyn quil_types::consensus::DynamicFeeManager>,
            local_prover_address: joiner_for_engine.address.clone(),
            local_bls_pubkey: joiner_for_engine.bls_pubkey.clone(),
            bls_signer: joiner_for_engine.signer_clone(),
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
        };
        let (engine, handle) =
            quil_engine::app_engine::AppConsensusEngine::new(core_id, filter_bytes, deps, event_tx);
        let bls = joiner_for_engine.signer_clone();
        tokio::spawn(async move {
            engine.run(bls).await;
        });
        let event_drain = event_for_cb.clone();
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
                };
                event_drain.lock().push(name.to_string());
            }
        });
        handle
    });

    let spawn_wm = Arc::new(quil_engine::test_support::SpawningWorkerManager::new(
        spawn_fn,
    ));
    spawn_wm.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: filter.clone(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 5,
        allocated: false,
    });

    let composite_allocator = Arc::new(quil_engine::worker_allocator::WorkerAllocator::new(
        spawn_wm.clone() as Arc<dyn quil_engine::worker::WorkerManager>,
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        joiner.address.clone(),
    ));
    composite_allocator
        .on_new_frame(18)
        .expect("WorkerAllocator.on_new_frame should spawn the engine");

    let handles = spawn_wm.snapshot_handles();
    assert_eq!(
        handles.len(),
        1,
        "expected SpawningWorkerManager to spawn one engine"
    );

    // -----------------------------------------------------------------
    // Phase D/E — wait for the spawned engine to produce events
    // (FrameProduced/VoteProduced) AND emit at least one
    // coverage_publish bundle (one finalized shard frame).
    // -----------------------------------------------------------------
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let evs = event_log.lock().clone();
        let cov_n = coverage_published.lock().len();
        if cov_n >= 1 {
            eprintln!(
                "phase E ready: {} events ({:?}), {} coverage bundles",
                evs.len(),
                evs.iter().take(8).collect::<Vec<_>>(),
                cov_n
            );
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "spawned engine never emitted coverage within 120s; \
                 events={:?} cov={}",
                evs, cov_n
            );
        }
    }
    let cov_bytes_snapshot = std::mem::take(&mut *coverage_published.lock());

    // -----------------------------------------------------------------
    // Phase F — substitute each captured coverage header's
    // `public_key_signature_bls48581` with a valid synthetic
    // `AggregateSignature{sig=74×0x00, bitmask=[0x01]}` so the
    // materializer's `invoke_frame_header` aggregate-decode +
    // bitmask-index lookup succeeds. The coverage header emitted by
    // `AppFollower::on_finalized_state` currently carries the
    // proposer's BLS authorship signature rather than the certifying
    // QC's aggregate; substituting here lets the test pin the
    // materialize → state-advance path without depending on the
    // future change that routes the certifying QC end-to-end.
    // -----------------------------------------------------------------
    use quil_execution::global_intrinsic::frame_header::FrameHeader;
    use quil_execution::hypergraph_intrinsic::canonical::AggregateSignature;
    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

    let _ = AggregateSignature {
        signature: vec![0u8; 74],
        public_key: None,
        bitmask: vec![0x01],
    };

    let mut proto_bundles: Vec<quil_types::proto::global::MessageBundle> = Vec::new();
    for bytes in &cov_bytes_snapshot {
        let mut hdr = FrameHeader::from_canonical_bytes(bytes).expect("decode coverage header");
        // Declare the aggregate pubkey of the single signing worker so
        // the intrinsic's committee reconstruction matches. The stub
        // frame prover leaves `hdr.prover` as a 96-byte placeholder (not
        // a valid G2 point), so use the joiner's real BLS pubkey — it is
        // the Active prover on this shard filter via the confirm/spawn
        // path above, hence the committee member the verifier resolves.
        let synth_agg_bytes = single_signer_agg_sig(&joiner.bls_pubkey)
            .to_canonical_bytes()
            .expect("synth agg sig");
        hdr.public_key_signature_bls48581 = synth_agg_bytes;
        let new_bytes = hdr.to_canonical_bytes().expect("re-encode coverage header");
        let req = CanonicalMessageRequest::wrap(new_bytes).expect("wrap request");
        let bundle = CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: 0,
        };
        let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");
        let proto = quil_engine::consensus_wire::decode_message_bundle(&bundle_bytes)
            .expect("decode bundle");
        proto_bundles.push(proto);
    }
    let coverage_frame_number = 30u64;
    let coverage_frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: coverage_frame_number,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: proto_bundles,
        ..Default::default()
    };
    let pre_last_active = archive.prover_registry.read(|r| {
        r.get_prover_info(&joiner.address)
            .expect("joiner")
            .clone()
            .allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.last_active_frame_number)
            .unwrap_or(0)
    });
    let result = archive
        .materializer
        .materialize(&coverage_frame)
        .expect("materialize coverage frame");
    eprintln!(
        "coverage materialize: processed={} skipped={}",
        result.processed, result.skipped
    );
    assert!(
        result.processed >= 1,
        "archive must process at least one coverage bundle"
    );

    // -----------------------------------------------------------------
    // Phase G — LastActiveFrameNumber advance assertion. The materializer
    // applied the synthetic-aggregate coverage header, so the joiner's
    // allocation should now record `last_active_frame_number >=
    // coverage_frame_number`.
    // -----------------------------------------------------------------
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
    let post_last_active = archive.prover_registry.read(|r| {
        r.get_prover_info(&joiner.address)
            .expect("joiner")
            .clone()
            .allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.last_active_frame_number)
            .unwrap_or(0)
    });
    eprintln!(
        "LastActiveFrame: pre={} post={} (coverage_frame={})",
        pre_last_active, post_last_active, coverage_frame_number
    );
    assert!(
        post_last_active >= coverage_frame_number,
        "LastActiveFrame should advance to ≥{} after coverage ingest; \
         pre={} post={}",
        coverage_frame_number,
        pre_last_active,
        post_last_active
    );
}
