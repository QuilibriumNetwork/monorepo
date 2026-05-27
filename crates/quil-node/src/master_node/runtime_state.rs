use std::sync::Arc;

use tracing::{debug, error, info};

use quil_lifecycle::Supervisor;

pub(crate) struct RuntimeState {
    pub message_collector: Arc<quil_engine::message_collector::MessageCollector>,
    pub prover_registry: Arc<quil_execution::SharedProverRegistry>,
    pub prover_only_flag: Arc<std::sync::atomic::AtomicBool>,
    pub global_event_distributor: Arc<dyn quil_types::consensus::EventDistributor>,
    pub coverage_monitor: Arc<quil_engine::coverage::CoverageMonitor>,
    pub halt_state: Arc<quil_engine::halt_state::HaltState>,
    pub remote_worker_manager_for_halt:
        Arc<std::sync::OnceLock<Arc<quil_engine::remote_worker::RemoteWorkerManager>>>,
}

pub(crate) fn init(
    sup: &mut Supervisor<anyhow::Error>,
    hg_store: Arc<quil_store::RocksHypergraphStore>,
    shard_engines: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_engine::app_engine::AppEngineHandle>,
    >>,
) -> RuntimeState {
    // ---------------------------------------------------------------
    // 5c. Message collector + consensus event loop
    // ---------------------------------------------------------------
    let message_collector = Arc::new(quil_engine::message_collector::MessageCollector::new());

    // The consensus event loop is optional — it runs only when this node
    // has a BLS proving key and is an active prover. For now we create
    // the prover registry and message collector, but defer the full
    // HotStuff event loop until the node has synced enough state to
    // determine its role. The consensus components are ready to be
    // wired when this node becomes an active prover.
    let prover_registry = Arc::new(quil_execution::SharedProverRegistry::new());
    {
        let pr = prover_registry.clone();
        let hs = hg_store.clone();
        // Run in background — don't block P2P startup. The registry
        // populates asynchronously; consensus won't start until it's ready.
        // Supervised as a startup task: a normal completion is expected
        // and won't shut down the node; a panic or error will.
        sup.spawn_startup_task("prover-registry-refresh", move |_token| async move {
            tokio::task::spawn_blocking(move || {
                pr.refresh_from_store(&hs);
                let count = pr.read(|r| r.distinct_provers());
                tracing::info!(provers = count, "prover registry loaded (background)");
            })
            .await
            .map_err(anyhow::Error::from)
        });
    }

    // ---------------------------------------------------------------
    // 5d. Coverage monitor + worker allocator + worker threads
    // ---------------------------------------------------------------
    let prover_only_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let global_event_distributor: Arc<dyn quil_types::consensus::EventDistributor> =
        Arc::new(quil_engine::event_distributor::InMemoryEventDistributor::new());
    let coverage_monitor = Arc::new(quil_engine::coverage::CoverageMonitor::new(
        prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        global_event_distributor.clone(),
        quil_engine::coverage::CoverageThresholds::mainnet(),
        prover_only_flag.clone(),
    ));

    // Shared halt state — written by the coverage-event subscriber
    // below, read by the lifecycle `join_proposal_ready` gate and by
    // the periodic eviction scheduler. Needs to exist before any
    // consumer references it.
    let halt_state = Arc::new(quil_engine::halt_state::HaltState::new());

    // Spawn subscriber: drains ControlEvents from the in-memory
    // distributor and updates `halt_state` on CoverageHalt /
    // CoverageResume. The separate shard orchestration subscriber is
    // wired below once the prover pipeline exists.
    {
        let mut rx = global_event_distributor.subscribe("halt-state");
        let hs = halt_state.clone();
        sup.run_until_cancelled("halt-state-subscriber", move |_token| async move {
            loop {
                let Some(event) = rx.recv().await else { break };
                match (event.event_type, &event.data) {
                    (
                        quil_types::consensus::ControlEventType::CoverageHalt,
                        quil_types::consensus::ControlEventData::Coverage { filter, duration },
                    ) => {
                        if hs.apply(&event) {
                            info!(
                                filter = hex::encode(filter),
                                duration_frames = *duration,
                                halted_count = hs.halted_count(),
                                "coverage halt entered"
                            );
                            quil_engine::metrics::inc_coverage_halts_entered();
                            quil_engine::metrics::set_halted_shards(hs.halted_count() as u64);
                        }
                    }
                    (
                        quil_types::consensus::ControlEventType::Halt,
                        quil_types::consensus::ControlEventData::Alert { message },
                    ) => {
                        // Hard halt — ALL shards stop. This is a fire
                        // alarm, not a per-shard coverage issue.
                        // Permanent for this process lifetime; operator
                        // must restart after the alert is resolved.
                        error!(
                            message = %message,
                            "GLOBAL ALERT — hard halt, stopping all shard engines"
                        );
                        hs.hard_halt();
                    }
                    (
                        quil_types::consensus::ControlEventType::CoverageResume,
                        quil_types::consensus::ControlEventData::Coverage { filter, .. },
                    ) => {
                        if hs.apply(&event) {
                            info!(
                                filter = hex::encode(filter),
                                halted_count = hs.halted_count(),
                                "coverage halt resumed"
                            );
                            quil_engine::metrics::inc_coverage_resumes();
                            quil_engine::metrics::set_halted_shards(hs.halted_count() as u64);
                        }
                    }
                    (
                        quil_types::consensus::ControlEventType::ShardSplitEligible,
                        quil_types::consensus::ControlEventData::ShardSplit { filter, proposed },
                    ) => {
                        info!(
                            filter = hex::encode(filter),
                            proposed = proposed.len(),
                            "shard split eligible (orchestration pending)"
                        );
                    }
                    (
                        quil_types::consensus::ControlEventType::ShardMergeEligible,
                        quil_types::consensus::ControlEventData::ShardMerge { filters, parent },
                    ) => {
                        info!(
                            filter_count = filters.len(),
                            parent = hex::encode(parent),
                            "shard merge eligible (orchestration pending)"
                        );
                    }
                    (quil_types::consensus::ControlEventType::CoverageWarn, _) => {
                        debug!("coverage warn");
                        quil_engine::metrics::inc_coverage_warns();
                    }
                    _ => {}
                }
            }
            Ok(())
        });
    }

    // Broadcast halt-state changes to every active app shard engine
    // AND every standalone worker process. In-process thread-mode
    // engines receive via the `shard_engines` map; standalone workers
    // receive via the `SetHalted` DataIPC RPC, looked up through
    // `remote_worker_manager_for_halt` (populated later by the
    // cluster-mode branch of the worker_manager setup).
    //
    // Two firings:
    //   1. Edge-triggered: when `halt_state.watch_any_halted()` flips,
    //      push the new value immediately.
    //   2. Periodic resync (every 30s) while a halt is active: covers
    //      worker reconnects and the initial-connect race where a
    //      worker boots mid-halt and would otherwise stay halted=false
    //      until the next edge transition.
    let remote_worker_manager_for_halt: Arc<
        std::sync::OnceLock<Arc<quil_engine::remote_worker::RemoteWorkerManager>>,
    > = Arc::new(std::sync::OnceLock::new());
    {
        let mut rx = halt_state.watch_any_halted();
        let engines = shard_engines.clone();
        let remote_mgr_cell = remote_worker_manager_for_halt.clone();
        let halt_state_for_periodic = halt_state.clone();
        sup.run_until_cancelled("halt-state-broadcaster", move |_token| async move {
            let mut periodic = tokio::time::interval(std::time::Duration::from_secs(30));
            periodic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    res = rx.changed() => {
                        if res.is_err() { break; }
                        let halted = *rx.borrow();
                        // Scope the read guard: parking_lot::RwLockReadGuard
                        // is !Send, so it must drop before any .await.
                        let count = {
                            let map = engines.read();
                            let n = map.len();
                            for (_filter, handle) in map.iter() {
                                handle.set_halted(halted);
                            }
                            n
                        };
                        if let Some(mgr) = remote_mgr_cell.get() {
                            mgr.broadcast_set_halted(halted).await;
                        }
                        info!(
                            halted,
                            engines = count,
                            "broadcast halt state to app shard engines"
                        );
                    }
                    _ = periodic.tick() => {
                        let halted = halt_state_for_periodic.any_halted();
                        if !halted {
                            continue;
                        }
                        // Re-push to every engine + remote worker so a
                        // freshly-connected worker picks up the halt.
                        {
                            let map = engines.read();
                            for (_filter, handle) in map.iter() {
                                handle.set_halted(true);
                            }
                        }
                        if let Some(mgr) = remote_mgr_cell.get() {
                            mgr.broadcast_set_halted(true).await;
                        }
                    }
                }
            }
            Ok(())
        });
    }

    // Wire prover-only mode into the message collector
    // (the collector checks this flag on each add_message call)
    let mc_prover_only = message_collector.clone();
    let pof = prover_only_flag.clone();
    sup.run_until_cancelled("prover-only-mode-poll", move |_token| async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            mc_prover_only.set_prover_only_mode(
                pof.load(std::sync::atomic::Ordering::Relaxed),
            );
        }
    });

    RuntimeState {
        message_collector,
        prover_registry,
        prover_only_flag,
        global_event_distributor,
        coverage_monitor,
        halt_state,
        remote_worker_manager_for_halt,
    }
}
