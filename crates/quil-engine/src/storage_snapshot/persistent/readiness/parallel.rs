//! Allocation-wide phase barriers measure elapsed time under real contention.
use super::*;
use crate::storage_readiness::{AllocationMeasurement, AllocationRoundMeasurement};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

pub struct BenchmarkInput {
    pub crdt: Arc<HypergraphCrdt>,
    pub snapshot: quil_types::consensus::StorageSnapshotRoots,
    pub filter: Vec<u8>,
    pub keep: Box<dyn std::any::Any + Send + Sync>,
}
struct Phase {
    generation: usize,
    arrived: usize,
    started: Instant,
    seconds: Vec<f64>,
    failure: Option<String>,
}
pub(super) struct Coordinator {
    count: usize,
    state: Mutex<Phase>,
    changed: Condvar,
    stop: Arc<AtomicBool>,
    progress_directory: Option<PathBuf>,
}
impl Coordinator {
    fn new(count: usize, stop: Arc<AtomicBool>) -> Self {
        Self {
            count,
            progress_directory: None,
            state: Mutex::new(Phase {
                generation: 0,
                arrived: 0,
                started: Instant::now(),
                seconds: Vec::new(),
                failure: None,
            }),
            changed: Condvar::new(),
            stop,
        }
    }
    pub(super) fn fail(&self, error: &QuilError) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.failure.is_none() {
            state.failure = Some(error.to_string());
        }
        self.stop.store(true, Ordering::Relaxed);
        self.changed.notify_all();
    }
    pub(super) fn arrive(&self, phase: usize) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation != phase {
            return Err(unavailable("benchmark phase order mismatch".into()));
        }
        state.arrived += 1;
        if state.arrived == self.count {
            let seconds = state.started.elapsed().as_secs_f64();
            state.seconds.push(seconds);
            if let Some(directory) = &self.progress_directory {
                progress::save(
                    &directory.join(format!("allocation-{phase:03}.json")),
                    &serde_json::json!({"kind":"allocation_phase","phase":phase,"seconds":seconds}),
                )?;
            }
            state.generation += 1;
            state.arrived = 0;
            state.started = Instant::now();
            let name = if phase == 0 {
                "cold initialization"
            } else {
                match (phase - 1) % 3 {
                    0 => "registration",
                    1 => "frame openings",
                    _ => "settlement",
                }
            };
            eprintln!(
                "storage benchmark: allocation {name} phase {phase} completed in {seconds:.3}s"
            );
            self.changed.notify_all();
        } else {
            while state.generation == phase && !self.stop.load(Ordering::Relaxed) {
                state = self
                    .changed
                    .wait_timeout(state, Duration::from_millis(100))
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0;
            }
        }
        if self.stop.load(Ordering::Relaxed) {
            return Err(unavailable("parallel benchmark stopped".into()));
        }
        Ok(())
    }
    fn measurements(&self, rounds: usize) -> AllocationMeasurement {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AllocationMeasurement {
            parallel_jobs: crate::storage_jobs::job_slots(),
            cold_wall_seconds: state.seconds[0],
            rounds: (0..rounds)
                .map(|r| AllocationRoundMeasurement {
                    registration_wall_seconds: state.seconds[1 + r * 3],
                    frame_openings_wall_seconds: state.seconds[2 + r * 3],
                    settlement_wall_seconds: state.seconds[3 + r * 3],
                })
                .collect(),
        }
    }
}

/// Measure all shards and sectors concurrently. Heavy work uses the node's
/// shared CPU/RAM admission; one lightweight coordinator per shard can wait at
/// barriers even when an allocation has more shards than CPU slots.
pub fn measure_allocation(
    inputs: Vec<BenchmarkInput>,
    options: &BenchmarkOptions,
) -> Result<(Vec<SnapshotMeasurement>, AllocationMeasurement)> {
    if inputs.is_empty() {
        return Err(unavailable("empty benchmark allocation".into()));
    }
    let store = LabelStore::new(options.directory.join("labels"))
        .for_profile(options.profile)
        .with_disk_floor(crate::storage_readiness::disk_floor);
    let mut coordinator = Coordinator::new(inputs.len(), options.stop.clone());
    coordinator.progress_directory = Some(options.directory.join("progress"));
    let stable = quil_types::consensus::stable_replica_key_epoch_thread_override();
    let results = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        let mut spawn_error = None;
        for input in &inputs {
            let store = &store;
            let coordinator = &coordinator;
            let worker = std::thread::Builder::new()
                .name("storage-benchmark-shard".into())
                .spawn_scoped(scope, move || {
                    quil_types::consensus::set_stable_replica_key_epoch_for_thread(stable);
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        measure_with_store(
                            input.crdt.clone(),
                            input.snapshot.clone(),
                            input.filter.clone(),
                            options,
                            store,
                            Some(coordinator),
                        )
                    }))
                    .unwrap_or_else(|_| {
                        Err(unavailable("parallel benchmark worker panicked".into()))
                    });
                    if let Err(error) = &result {
                        coordinator.fail(error);
                    }
                    result
                });
            match worker {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    options.stop.store(true, Ordering::Relaxed);
                    coordinator.changed.notify_all();
                    spawn_error = Some(unavailable(format!(
                        "cannot start benchmark shard: {error}"
                    )));
                    break;
                }
            }
        }
        let mut results: Vec<_> = workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|_| Err(unavailable("benchmark worker join failed".into())))
            })
            .collect();
        if let Some(error) = spawn_error {
            results.push(Err(error));
        }
        results
    });
    if let Some(failure) = coordinator
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .failure
        .clone()
    {
        return Err(unavailable(failure));
    }
    let measured = results.into_iter().collect::<Result<Vec<_>>>()?;
    Ok((measured, coordinator.measurements(options.rounds)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelling_a_shard_releases_workers_already_waiting_at_a_phase_barrier() {
        let coordinator = Coordinator::new(2, Arc::new(AtomicBool::new(false)));
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| coordinator.arrive(0));
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if coordinator.state.lock().unwrap().arrived == 1 {
                    break;
                }
                assert!(Instant::now() < deadline, "worker did not reach barrier");
                std::thread::yield_now();
            }
            coordinator.fail(&unavailable("original shard failure".into()));
            assert!(waiter.join().unwrap().is_err());
            assert!(coordinator
                .state
                .lock()
                .unwrap()
                .failure
                .as_ref()
                .unwrap()
                .contains("original shard failure"));
        });
    }
}
