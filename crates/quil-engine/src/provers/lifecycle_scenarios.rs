use quil_types::consensus::EffectiveStatus;

// Deterministic histories over the real lifecycle and worker allocator.
// Registry observations are injected; no fixture pretends to authenticate a
// network message. Signed materialization is covered by e2e_epoch_confirm.

struct Scenario {
    address: Vec<u8>,
    registry: Arc<ConfigurableRegistry>,
    workers: Arc<ConfigurableWorkerManager>,
    lifecycle: Arc<ProverLifecycle>,
    allocations: Vec<ProverAllocationInfo>,
    history: Vec<String>,
}

impl Scenario {
    fn new(allocations: Vec<ProverAllocationInfo>, workers: Vec<WorkerInfo>) -> Self {
        let address = vec![0xCD; 32];
        let registry = Arc::new(ConfigurableRegistry::new());
        registry.set_prover(prover(address.clone(), allocations.clone()));
        registry.set_summaries(
            allocations
                .iter()
                .map(|a| shard_summary(a.confirmation_filter.clone(), 50))
                .collect(),
        );
        let manager = Arc::new(ConfigurableWorkerManager::new());
        for worker in workers {
            manager.add(worker);
        }
        let lifecycle = make_lifecycle(address.clone(), manager.clone(), registry.clone());
        Self {
            address,
            registry,
            workers: manager,
            lifecycle,
            allocations,
            history: vec![],
        }
    }

    fn observe(&mut self) {
        self.registry
            .set_prover(prover(self.address.clone(), self.allocations.clone()));
        self.history
            .push(format!("registry={:?}", self.allocations));
    }

    fn restart(&mut self) {
        // Recreate volatile evaluator/allocator state; persisted allocation
        // state and worker observations survive. An initially idle worker is
        // separately covered by the recovery matrix.
        self.lifecycle = make_lifecycle(
            self.address.clone(),
            self.workers.clone(),
            self.registry.clone(),
        );
        self.history.push("restart".into());
    }

    fn tick(&mut self, frame: u64) -> Vec<LifecycleAction> {
        self.lifecycle.allocator.on_new_frame(frame).unwrap();
        self.lifecycle.set_prover_root_verified_frame(frame);
        let actions = self
            .lifecycle
            .evaluate(frame, 50_000, self.registry.as_ref(), self.workers.as_ref())
            .unwrap();
        self.history
            .push(format!("frame={frame}, actions={actions:?}"));
        self.assert_unique_workers();
        actions
    }

    fn assert_unique_workers(&self) {
        let workers = self.workers.range_workers().unwrap();
        let mut seen = std::collections::HashSet::new();
        for worker in workers.iter().filter(|w| !w.filter.is_empty()) {
            assert!(
                seen.insert(worker.filter.clone()),
                "duplicate binding; history={:?}",
                self.history
            );
        }
    }

    fn is_bound(&self, filter: &[u8]) -> bool {
        self.workers
            .range_workers()
            .unwrap()
            .iter()
            .any(|w| w.filter == filter)
    }
}

#[test]
fn scenario_rejected_leave_recovery_matrix() {
    let _epoch = super::super::buckets_tests::epoch_length_guard();
    // Vary initial reconciliation state, registry delay and process restart.
    // Epochs are real: no far-future fixture hides the storage obligation.
    for initially_bound in [false, true] {
        for renewal_at in [None, Some(730), Some(1439)] {
            for restart_at in [None, Some(726), Some(1439)] {
                let held = filter_bytes(0xA1);
                let mut allocation = alloc(held.clone(), ProverStatus::Active, 10);
                allocation.epoch = 0;
                allocation.leave_frame_number = 500;
                allocation.leave_reject_frame_number = 721;
                let worker = if initially_bound {
                    allocated_worker(1, held.clone())
                } else {
                    idle_worker(1)
                };
                let mut scenario = Scenario::new(vec![allocation], vec![worker]);
                for frame in [725, 726, 730, 1000, 1439, 1440, 1441] {
                    if renewal_at == Some(frame) {
                        scenario.allocations[0].epoch = 2;
                        scenario.observe();
                    }
                    if restart_at == Some(frame) {
                        scenario.restart();
                    }
                    let actions = scenario.tick(frame);
                    let renewal_seen = renewal_at.is_some_and(|at| frame >= at);
                    // Independent expectation: one rejection epoch of grace,
                    // or an actually observed registration covering epoch 2.
                    let should_bind = frame < 1440 || renewal_seen;
                    assert_eq!(scenario.is_bound(&held), should_bind,
                        "bound={initially_bound}, renewal={renewal_at:?}, restart={restart_at:?}; history={:?}", scenario.history);
                    if should_bind {
                        assert_eq!(
                            count_proposed_leaves(&actions),
                            0,
                            "history={:?}",
                            scenario.history
                        );
                    }
                    if !renewal_seen && frame < 1440 {
                        assert_eq!(scenario.allocations[0].epoch, 0);
                        assert_eq!(
                            scenario.allocations[0].effective_status(frame),
                            EffectiveStatus::ExpiredEpoch
                        );
                        assert!(actions.iter().any(|a| matches!(a, LifecycleAction::ReconfirmEpoch { filters, .. } if filters.contains(&held))), "history={:?}", scenario.history);
                    }
                    if !should_bind && frame == 1440 {
                        assert_eq!(
                            count_proposed_leaves(&actions),
                            1,
                            "grace must end; history={:?}",
                            scenario.history
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn scenario_join_confirm_activation_renewal_and_departure() {
    let _epoch = super::super::buckets_tests::epoch_length_guard();
    for restart in [false, true] {
        let held = filter_bytes(0xA1);
        let mut allocation = alloc(held.clone(), ProverStatus::Joining, 1000);
        allocation.epoch = 3;
        let mut scenario = Scenario::new(vec![allocation], vec![idle_worker(1)]);
        scenario.tick(1000);
        assert!(scenario.is_bound(&held));
        let decisions = scenario.tick(1440);
        assert!(decisions.iter().any(|a| matches!(a, LifecycleAction::ConfirmJoins { filters, .. } if filters.contains(&held))), "history={:?}", scenario.history);
        // Observe the materialized confirmation, not a presumed successful
        // publication. Activation remains deferred through this entire epoch.
        scenario.allocations[0].status = ProverStatus::Active;
        scenario.allocations[0].join_confirm_frame_number = 1441;
        scenario.observe();
        if restart {
            scenario.restart();
        }
        for frame in [1441, 2159] {
            scenario.tick(frame);
            assert!(scenario.is_bound(&held));
            assert_eq!(
                scenario.allocations[0].effective_status(frame),
                EffectiveStatus::Joining
            );
        }
        scenario.tick(2160);
        assert_eq!(
            scenario.allocations[0].effective_status(2160),
            EffectiveStatus::Active
        );
        scenario.allocations[0].epoch = 4;
        scenario.observe();
        scenario.tick(2880);
        assert!(scenario.is_bound(&held));
        scenario.allocations[0].status = ProverStatus::Leaving;
        scenario.allocations[0].leave_frame_number = 2900;
        scenario.observe();
        scenario.tick(2900);
        scenario.allocations[0].leave_confirm_frame_number = 3601;
        scenario.observe();
        if restart {
            scenario.restart();
        }
        scenario.tick(4320 - 1);
        assert!(
            scenario.is_bound(&held),
            "notice must preserve service; history={:?}",
            scenario.history
        );
        scenario.tick(4320);
        assert!(
            !scenario.is_bound(&held),
            "departure must free capacity; history={:?}",
            scenario.history
        );
    }
}

#[test]
fn scenario_delayed_join_observation_and_timeout() {
    let _epoch = super::super::buckets_tests::epoch_length_guard();
    for delay in [0, 5, 10, 11, 30] {
        let held = filter_bytes(0xA1);
        let mut worker = idle_worker(1);
        worker.filter = held.clone();
        worker.pending_filter_frame = 1000;
        let mut scenario = Scenario::new(vec![], vec![worker]);
        for frame in 1000..=1031 {
            if frame == 1000 + delay {
                let mut allocation = alloc(held.clone(), ProverStatus::Joining, 1000);
                allocation.epoch = 2;
                scenario.allocations.push(allocation);
                scenario.observe();
            }
            // No unrelated proposals: metadata is unavailable until observed.
            scenario.tick(frame);
            let seen = frame >= 1000 + delay;
            assert_eq!(
                scenario.is_bound(&held),
                seen || frame <= 1010,
                "delay={delay}; history={:?}",
                scenario.history
            );
        }
        // A late observation must recover an idle core, without duplicating
        // ownership or needing a process restart.
        assert!(scenario.is_bound(&held));
    }
}

#[test]
fn scenario_allocation_state_and_worker_matrix() {
    let _epoch = super::super::buckets_tests::epoch_length_guard();
    // Exhaust all small combinations, including boundary-neighbor frames.
    // Expected binding is stated independently from effective_status().
    for status in [
        ProverStatus::Joining,
        ProverStatus::Active,
        ProverStatus::Paused,
        ProverStatus::Leaving,
        ProverStatus::Rejected,
        ProverStatus::Kicked,
    ] {
        for stored_epoch in [0, 1, 2] {
            for bound in [false, true] {
                for manual in [false, true] {
                    for frame in [719, 720, 721, 1439, 1440, 1441] {
                        let held = filter_bytes(0xA1);
                        let mut allocation = alloc(held.clone(), status, 100);
                        allocation.leave_frame_number = 100;
                        allocation.epoch = stored_epoch;
                        let mut worker = if bound {
                            allocated_worker(1, held.clone())
                        } else {
                            idle_worker(1)
                        };
                        worker.manually_managed = manual;
                        let mut scenario = Scenario::new(vec![allocation], vec![worker]);
                        // This matrix characterizes allocator state alone;
                        // targeted histories above exercise policy actions.
                        scenario.lifecycle.allocator.on_new_frame(frame).unwrap();
                        scenario.assert_unique_workers();
                        // Manual selection controls placement, not whether
                        // expired or terminal allocations remain valid. Idle
                        // manual selections are consumed before automatic cores.
                        let expected = match status {
                            ProverStatus::Joining => frame < 1440,
                            ProverStatus::Active => stored_epoch + 1 >= frame / 720,
                            ProverStatus::Paused => true,
                            ProverStatus::Leaving => frame < 1440,
                            _ => false,
                        };
                        assert_eq!(
                            scenario.workers.range_workers().unwrap()[0].manually_managed,
                            manual
                        );
                        assert_eq!(scenario.is_bound(&held), expected,
                            "status={status:?}, epoch={stored_epoch}, bound={bound}, manual={manual}, frame={frame}");
                    }
                }
            }
        }
    }
}

#[test]
fn scenario_replacement_reservation_survives_repeated_ticks_and_restart() {
    let _epoch = super::super::buckets_tests::epoch_length_guard();
    for halt_risk in [false, true] {
        for restart_frame in [504, 530, 730] {
            let (lc, reg, wm, address, mut allocations) = pending_replacement_fixture(halt_risk);
            lc.set_prover_root_verified_frame(500);
            let first =
                proposed_leave_filters(&lc.evaluate(500, 1, reg.as_ref(), wm.as_ref()).unwrap());
            assert!(!first.is_empty());
            let mut scenario = Scenario {
                address,
                registry: reg,
                workers: wm,
                lifecycle: lc,
                allocations: allocations.clone(),
                history: vec![format!("first={first:?}")],
            };
            // Both unobserved submission and registered notice must reserve
            // the same capacity over subsequent policy cycles.
            for frame in [504, 510, 530, 720, 730, 1000, 1439] {
                if frame == 510 {
                    for a in &mut allocations {
                        if first.contains(&a.confirmation_filter) {
                            a.status = ProverStatus::Leaving;
                            a.leave_frame_number = 500;
                        }
                    }
                    scenario.allocations = allocations.clone();
                    scenario.observe();
                }
                if frame == 720 {
                    for a in &mut scenario.allocations {
                        if first.contains(&a.confirmation_filter) {
                            a.leave_confirm_frame_number = 721;
                        }
                    }
                    scenario.observe();
                }
                // A restart before chain observation cannot reconstruct a
                // volatile submission; model only persisted reservations.
                if frame == restart_frame && frame >= 510 {
                    scenario.restart();
                }
                let actions = scenario.tick(frame);
                assert_eq!(
                    count_proposed_leaves(&actions),
                    0,
                    "history={:?}",
                    scenario.history
                );
            }
            let actions = scenario.tick(1440);
            assert!(
                count_proposed_joins(&actions) > 0,
                "released capacity must progress; history={:?}",
                scenario.history
            );
            assert_eq!(
                count_proposed_leaves(&actions),
                0,
                "history={:?}",
                scenario.history
            );
        }
    }
}

#[test]
fn scenario_seeded_recovery_histories() {
    let _epoch = super::super::buckets_tests::epoch_length_guard();
    // Fixed seeds make every failure reproducible. The full event trace is
    // included in assertions; no wall clock, scheduler or network randomness.
    for seed in 0..64u64 {
        let mut random = seed + 1;
        let mut next = || {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            random
        };
        let held = filter_bytes(0xA1);
        let mut allocation = alloc(held.clone(), ProverStatus::Active, 10);
        allocation.epoch = 0;
        allocation.leave_frame_number = 500;
        allocation.leave_reject_frame_number = 721;
        let renewal_at = (next() % 3 != 0).then(|| 725 + next() % 700);
        let mut scenario = Scenario::new(vec![allocation], vec![idle_worker(1)]);
        let mut frame = 725;
        let mut renewed = false;
        for _ in 0..32 {
            if !renewed && renewal_at.is_some_and(|at| frame >= at) {
                scenario.allocations[0].epoch = 2;
                scenario.observe();
                renewed = true;
            }
            if next() % 4 == 0 {
                scenario.restart();
            }
            scenario.tick(frame);
            // The model never calls effective_status or the recovery helper.
            let expected = (renewed && frame / 720 <= 3) || frame < 1440;
            assert_eq!(
                scenario.is_bound(&held),
                expected,
                "seed={seed}, renewal={renewal_at:?}; history={:?}",
                scenario.history
            );
            frame += 1 + next() % 100;
        }
        // Registration for epoch 2 can reserve renewal capacity through
        // epoch 3; without a subsequent registration it must yield in epoch 4.
        scenario.tick(2880);
        assert!(!scenario.is_bound(&held), "unrenewed capacity must be bounded; history={:?}", scenario.history);
    }
}

#[test]
fn unbound_notice_reserves_capacity_before_allocator_recovery() {
    let _epoch = super::super::buckets_tests::epoch_length_guard();
    let mut leaving = alloc(filter_bytes(0xA1), ProverStatus::Leaving, 100);
    leaving.leave_frame_number = 100;
    leaving.leave_confirm_frame_number = 721;
    let scenario = Scenario::new(vec![leaving], vec![idle_worker(1)]);
    scenario.registry.set_summaries(vec![
        shard_summary(filter_bytes(0xA1), 50),
        shard_summary(filter_bytes(0xC1), 1),
    ]);
    seed_sizes_from_registry(&scenario.lifecycle, scenario.registry.as_ref());
    // Deliberately evaluate BEFORE allocator recovery, as a racing caller
    // can see an idle fleet while notice-period allocations remain owed slots.
    for frame in [722, 1439] {
        scenario.lifecycle.set_prover_root_verified_frame(frame);
        let actions = scenario.lifecycle.evaluate(frame, 50_000,
            scenario.registry.as_ref(), scenario.workers.as_ref()).unwrap();
        assert_eq!(count_proposed_joins(&actions), 0, "{actions:?}");
    }
    scenario.lifecycle.set_prover_root_verified_frame(1440);
    let actions = scenario.lifecycle.evaluate(1440, 50_000,
        scenario.registry.as_ref(), scenario.workers.as_ref()).unwrap();
    assert!(count_proposed_joins(&actions) > 0, "departure must release capacity: {actions:?}");
}
