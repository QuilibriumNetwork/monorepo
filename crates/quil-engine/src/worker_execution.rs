//! Local engine observations, with no allocation or reward inference.
use std::sync::{Arc, Mutex};
use quil_types::proto::node::{ShardRecovery, WorkerExecution};

use crate::prover_tree_syncer::ShardRecoveryProgress;

tokio::task_local! {
    /// The record of the worker whose archive recovery runs on this task.
    static RECOVERING: SharedWorkerExecution;
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_millis() as u64
}

#[derive(Clone, Debug, Default)]
pub struct SharedWorkerExecution(Arc<Mutex<WorkerExecution>>);

impl SharedWorkerExecution {
    pub fn snapshot(&self) -> WorkerExecution { self.0.lock().unwrap().clone() }

    pub fn state(&self, state: &str, blocker: &str) {
        let mut s = self.0.lock().unwrap();
        s.state = state.into();
        s.blocker = blocker.into();
        s.observed_unix_ms = now_ms();
    }

    pub fn restored(&self, height: u64) {
        let mut s = self.0.lock().unwrap();
        s.materialized_frame = Some(height);
        s.last_advance_unix_ms = 0;
        s.observed_unix_ms = now_ms();
    }

    pub fn materialized(&self, height: u64) {
        let mut s = self.0.lock().unwrap();
        let now = now_ms();
        // Restoring the initial cursor is an observation, not an advance.
        if s.materialized_frame.is_some_and(|old| height > old) {
            s.last_advance_unix_ms = now;
        }
        s.materialized_frame = Some(height);
        s.observed_unix_ms = now;
    }

    pub fn observe(&self) { self.0.lock().unwrap().observed_unix_ms = now_ms(); }

    fn recovery(&self, update: impl FnOnce(&mut ShardRecovery, u64)) {
        let mut s = self.0.lock().unwrap();
        let now = now_ms();
        update(s.recovery.get_or_insert_with(Default::default), now);
        s.observed_unix_ms = now;
    }

    /// Run one recovery attempt of `filter`, attributing the phases, source
    /// and leaf progress reported on this task to this worker, then record
    /// and log how it ended. A recovery that found nothing usable is an
    /// error, not an outcome.
    pub(crate) async fn recovering(
        &self,
        filter: &[u8],
        attempt: impl std::future::Future<Output = quil_types::error::Result<ShardRecoveryProgress>>,
    ) -> quil_types::error::Result<ShardRecoveryProgress> {
        self.recovery(|r, now| {
            r.attempt_started_unix_ms = now;
            r.permit_wait_ms = 0;
            r.attempt_ms = 0;
            r.attempt_installed_leaves = 0;
            r.source.clear();
        });
        let result = RECOVERING.scope(self.clone(), attempt).await;
        let failure = match &result {
            Ok(ShardRecoveryProgress::NotReady(reason)) => Some((*reason).to_string()),
            Ok(_) => None,
            Err(error) => Some(error.to_string()),
        };
        let mut ended = ShardRecovery::default();
        self.recovery(|r, now| {
            match (&failure, &result) {
                (Some(failure), _) => {
                    r.last_error = failure.clone();
                    r.last_error_unix_ms = now;
                    r.consecutive_failures += 1;
                }
                (None, progress) => {
                    r.last_outcome = progress.as_ref().map(ToString::to_string).unwrap_or_default();
                    r.last_outcome_unix_ms = now;
                    r.consecutive_failures = 0;
                }
            }
            enter(r, "idle", now);
            r.attempts += 1;
            r.attempt_ms = now.saturating_sub(r.attempt_started_unix_ms).saturating_sub(r.permit_wait_ms);
            ended = r.clone();
        });
        let filter = hex::encode(filter);
        let source = if ended.source.is_empty() { "none" } else { ended.source.as_str() };
        match failure {
            None => tracing::info!(%filter, outcome = %ended.last_outcome, source,
                attempt_secs = ended.attempt_ms / 1000, permit_wait_secs = ended.permit_wait_ms / 1000,
                installed_leaves = ended.attempt_installed_leaves, "archive recovery batch complete"),
            Some(error) => tracing::warn!(%filter, %error, source,
                attempt_secs = ended.attempt_ms / 1000, permit_wait_secs = ended.permit_wait_ms / 1000,
                installed_leaves = ended.attempt_installed_leaves, consecutive_failures = ended.consecutive_failures,
                "archive recovery failed; will retry (installed leaves are kept)"),
        }
        result
    }
}

fn enter(r: &mut ShardRecovery, phase: &str, now: u64) {
    if r.phase != phase {
        if r.phase == "waiting_for_permit" {
            r.permit_wait_ms = now.saturating_sub(r.phase_since_unix_ms);
        }
        r.phase = phase.into();
        r.phase_since_unix_ms = now;
    }
}

/// The archive the recovery on this task reads from now; elsewhere nothing.
pub fn recovery_source(source: &str) {
    let _ = RECOVERING.try_with(|s| s.recovery(|r, _| {
        if r.source != source { r.source = source.into(); }
    }));
}

/// `leaves` more leaves installed durably by the recovery on this task;
/// elsewhere nothing.
pub fn recovery_installed(leaves: u64) {
    let _ = RECOVERING.try_with(|s| s.recovery(|r, _| r.attempt_installed_leaves += leaves));
}

/// Enter `phase` of the recovery running on this task; elsewhere nothing.
pub fn recovery_phase(phase: &'static str) {
    let _ = RECOVERING.try_with(|s| s.recovery(|r, now| enter(r, phase, now)));
}

/// `installed` of the `planned` leaves of forest phase `tree_phase`, in the
/// tree the recovery on this task is installing; elsewhere (prover-tree and
/// archive syncs) nothing.
pub fn recovery_leaves(tree_phase: u32, installed: u64, planned: u64) {
    let _ = RECOVERING.try_with(|s| s.recovery(|r, now| {
        r.tree_phase = tree_phase;
        r.installed_leaves = installed;
        r.planned_leaves = planned;
        r.leaves_observed_unix_ms = now;
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restoration_rewind_and_state_are_independent() {
        let s = SharedWorkerExecution::default();
        assert_eq!(s.snapshot().materialized_frame, None);
        s.restored(42);
        assert_eq!(s.snapshot().last_advance_unix_ms, 0);
        s.state("blocked", "checkpoint mismatch");
        s.materialized(43);
        assert!(s.snapshot().last_advance_unix_ms > 0);
        assert_eq!(s.snapshot().state, "blocked");
        s.materialized(40);
        assert_eq!(s.snapshot().materialized_frame, Some(40));
        s.state("running", "");
        assert!(s.snapshot().blocker.is_empty());
        assert!(s.snapshot().observed_unix_ms > 0);
    }

    #[tokio::test]
    async fn recovery_is_reported_beside_the_execution_state_for_its_own_worker() {
        let (worker, other) = (SharedWorkerExecution::default(), SharedWorkerExecution::default());
        recovery_phase("installing_leaves");
        recovery_leaves(0, 1, 2);
        assert!(worker.snapshot().recovery.is_none(), "no recovery runs on this task");
        worker.state("blocked", "state unavailable");
        let installed = worker.recovering(&[7; 32], async {
            recovery_phase("waiting_for_permit");
            assert_eq!(worker.snapshot().recovery.unwrap().phase, "waiting_for_permit");
            recovery_phase("installing_leaves");
            recovery_source("198.51.100.7:8340");
            recovery_leaves(2, 262_144, 2_517_449);
            recovery_installed(1_024);
            recovery_installed(1_024);
            let r = worker.snapshot().recovery.unwrap();
            assert_eq!((r.phase.as_str(), r.tree_phase, r.installed_leaves, r.planned_leaves),
                ("installing_leaves", 2, 262_144, 2_517_449));
            assert!(r.phase_since_unix_ms > 0 && r.leaves_observed_unix_ms > 0);
            Ok(ShardRecoveryProgress::Anchored { frame: 7 })
        }).await;
        assert!(installed.is_ok());
        assert!(other.snapshot().recovery.is_none());
        let s = worker.snapshot();
        assert_eq!((s.state.as_str(), s.blocker.as_str()), ("blocked", "state unavailable"));
        let r = s.recovery.unwrap();
        assert_eq!(r.phase, "idle");
        assert!(r.last_outcome.contains("frame 7") && r.last_outcome_unix_ms > 0);
        assert!(r.last_error.is_empty());
        assert_eq!(r.installed_leaves, 262_144, "the last leaf counts stay visible");
        assert_eq!((r.source.as_str(), r.attempt_installed_leaves), ("198.51.100.7:8340", 2_048));
        assert_eq!((r.attempts, r.consecutive_failures), (1, 0));
        assert!(r.attempt_started_unix_ms > 0);

        let _ = worker.recovering(&[7; 32], async { Ok(ShardRecoveryProgress::NotReady("the archive checkpoint failed validation")) }).await;
        let r = worker.snapshot().recovery.unwrap();
        assert_eq!(r.last_error, "the archive checkpoint failed validation");
        assert!(r.last_outcome.contains("frame 7"), "an error keeps the last outcome");
        assert_eq!((r.attempts, r.consecutive_failures, r.attempt_installed_leaves), (2, 1, 0));
        assert!(r.source.is_empty(), "each attempt names its own source");
        let _ = worker.recovering(&[7; 32], async {
            Err(quil_types::error::QuilError::ExecutionUnavailable("archive discovery timed out".into()))
        }).await;
        let r = worker.snapshot().recovery.unwrap();
        assert!(r.last_error.contains("archive discovery timed out"));
        assert_eq!(r.consecutive_failures, 2);
    }

    #[tokio::test]
    async fn permit_wait_is_measured_apart_from_the_attempt() {
        let worker = SharedWorkerExecution::default();
        let _ = worker.recovering(&[7; 32], async {
            recovery_phase("waiting_for_permit");
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
            recovery_phase("fetching_checkpoint");
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            Ok(ShardRecoveryProgress::Anchored { frame: 1 })
        }).await;
        let r = worker.snapshot().recovery.unwrap();
        assert!(r.permit_wait_ms >= 60, "{}", r.permit_wait_ms);
        assert!(r.attempt_ms >= 30 && r.attempt_ms < r.permit_wait_ms + 30, "{} after {}", r.attempt_ms, r.permit_wait_ms);
    }
}
