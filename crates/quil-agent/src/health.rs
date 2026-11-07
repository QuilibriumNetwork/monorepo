//! Sentences from a diagnostics health report.
//!
//! The report's schema carries no paths, addresses, or keys. These sentences
//! keep that boundary: worker phase, why it holds, store I/O, and the
//! conditions the node already judged.

use quil_rpc::diagnostics_service::{blocker_text, phase_name, recovery_phase_name};
use quil_rpc::health_conditions::{action_text, notice_text};
use quil_types::proto::diagnostics::{
    Blocker, HealthReport, Phase, RecoveryPhase, StoreIoHealth, StoreIoVerdict, WorkerHealth,
};

/// What `node_info` says when the diagnostics report could not be read.
pub const HEALTH_UNAVAILABLE: &str =
    "Health: the node did not serve a diagnostics report. Worker counts above are the local status only.";

/// Plain sentences for `report`. No shard filter, path, or peer id.
pub fn explain(report: &HealthReport) -> String {
    let mut lines = Vec::new();
    if report.master_store_write_failed {
        lines.push(
            "The master store has stopped writing. This node cannot follow the network until that store is reopened.".to_string(),
        );
    }
    lines.push(workers_line(report));
    if let Some(line) = store_line(report.store_io.as_ref()) {
        lines.push(line);
    }
    if let Some(health) = report.health.as_ref() {
        if health.conditions.is_empty() {
            lines.push("No health condition is active.".into());
        } else {
            for condition in health.conditions.iter().take(4) {
                lines.push(format!(
                    "{} Next: {}.",
                    notice_text(condition).trim_end_matches('.'),
                    action_text(condition.action).trim_end_matches('.')
                ));
            }
        }
    } else {
        lines.push("This node version did not include health conditions.".into());
    }
    lines.join("\n")
}

fn workers_line(report: &HealthReport) -> String {
    if report.workers.is_empty() {
        return "The health report listed no workers.".into();
    }
    let notable: Vec<String> = report
        .workers
        .iter()
        .filter(|worker| !quiet(worker))
        .take(8)
        .map(worker_sentence)
        .collect();
    if notable.is_empty() {
        format!(
            "All {} reported workers are serving.",
            report.workers.len()
        )
    } else {
        notable.join("\n")
    }
}

fn quiet(worker: &WorkerHealth) -> bool {
    worker.phase() == Phase::Serving
        && worker.blocker() == Blocker::None
        && matches!(
            worker.recovery_phase(),
            RecoveryPhase::None | RecoveryPhase::Idle
        )
        && !worker.draining
        && worker.recovery_consecutive_failures == 0
}

fn worker_sentence(worker: &WorkerHealth) -> String {
    let phase = phase_name(worker.phase());
    let blocker = blocker_text(worker.blocker());
    let mut line = format!("Worker {}: {phase}", worker.core_id);
    if !blocker.is_empty() {
        line.push_str(&format!(", {blocker}"));
    }
    if worker.draining {
        line.push_str(", draining");
    }
    let recovery = recovery_phase_name(worker.recovery_phase());
    if recovery != "none" {
        line.push_str(&format!(", recovery {recovery}"));
    }
    if worker.recovery_consecutive_failures > 0 {
        line.push_str(&format!(
            ", {} failed recovery attempts in a row",
            worker.recovery_consecutive_failures
        ));
    }
    line
}

fn store_line(io: Option<&StoreIoHealth>) -> Option<String> {
    let io = io?;
    Some(match io.verdict() {
        StoreIoVerdict::Slow => {
            let slow = match io.slow_secs {
                secs @ 0..=119 => format!("{secs} seconds"),
                secs @ 120..=7199 => format!("{} minutes", secs / 60),
                secs => format!("{} hours", secs / 3600),
            };
            format!(
                "Store reads are slow ({slow}). Check the disk, then this node's load."
            )
        }
        StoreIoVerdict::Ok => "Store reads are within normal limits.".into(),
        _ => "Store reads have not been measured yet.".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::diagnostics::HealthConditions;

    #[test]
    fn a_stuck_worker_and_a_slow_store_are_named_without_a_filter() {
        let mut worker = WorkerHealth {
            core_id: 3,
            filter: b"not-shown".to_vec(),
            ..WorkerHealth::default()
        };
        worker.set_phase(Phase::Waiting);
        worker.set_blocker(Blocker::AwaitingAllocationActivation);
        let mut store = StoreIoHealth {
            slow_secs: 240,
            ..StoreIoHealth::default()
        };
        store.set_verdict(StoreIoVerdict::Slow);
        let report = HealthReport {
            workers: vec![worker],
            store_io: Some(store),
            health: Some(HealthConditions::default()),
            ..HealthReport::default()
        };
        let text = explain(&report);
        assert!(text.contains("Worker 3: waiting"), "{text}");
        assert!(text.contains("allocation"), "{text}");
        assert!(text.contains("Store reads are slow (4 minutes)"), "{text}");
        assert!(text.contains("No health condition is active"), "{text}");
        assert!(!text.contains("not-shown"), "{text}");
        assert!(!text.contains("secret-filter"), "{text}");
    }
}
