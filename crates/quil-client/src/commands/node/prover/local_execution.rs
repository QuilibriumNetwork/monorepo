//! Display local worker observations without inferring health from allocation.
use quil_types::proto::node::{ShardRecovery, WorkerExecution};
fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_millis() as u64
}
pub fn state_at(s: Option<&WorkerExecution>, now: u64) -> &str {
    let Some(s) = s else { return "unknown" };
    if s.observed_unix_ms == 0 || now.saturating_sub(s.observed_unix_ms) > 30_000 { return "stale"; }
    match s.state.as_str() {
        "starting" | "running" | "blocked" | "stopped" => s.state.as_str(),
        _ => "unknown",
    }
}
pub fn local_execution_state(s: Option<&WorkerExecution>) -> &str { state_at(s, now_ms()) }
pub fn age(timestamp: u64) -> String {
    if timestamp == 0 { "-".into() } else { format!("{}s", now_ms().saturating_sub(timestamp) / 1000) }
}
pub fn detail(s: Option<&WorkerExecution>) -> String {
    let Some(s) = s else { return "Local execution: unknown (node has no worker observations)".into() };
    format!("Local execution: {}{}; height {}; last advance {}; observation {} ago",
        local_execution_state(Some(s)),
        if s.blocker.is_empty() { String::new() } else { format!(" ({})", s.blocker) },
        s.materialized_frame.map(|h| h.to_string()).unwrap_or_else(|| "unknown".into()),
        if s.last_advance_unix_ms == 0 { "unobserved".into() } else { format!("{} ago", age(s.last_advance_unix_ms)) },
        age(s.observed_unix_ms))
        + &s.recovery.as_ref().map(|r| format!("; {}", recovery(r))).unwrap_or_default()
}
/// Archive recovery, which runs in any execution state: a worker can be
/// downloading its shard while running or blocked at height 0.
pub fn recovery(r: &ShardRecovery) -> String {
    let mut text = format!("Recovery: {} for {}", if r.phase.is_empty() { "unknown" } else { &r.phase }, age(r.phase_since_unix_ms));
    if !r.source.is_empty() { text += &format!(" from {}", r.source); }
    if r.planned_leaves > 0 {
        text += &format!(", leaves {}/{} (phase {}, {} ago)", r.installed_leaves, r.planned_leaves, r.tree_phase, age(r.leaves_observed_unix_ms));
    }
    if r.attempt_started_unix_ms > 0 {
        text += &format!(", attempt {}", r.attempts + u32::from(r.phase != "idle"));
        if r.consecutive_failures > 0 { text += &format!(" ({} failed in a row)", r.consecutive_failures); }
        if r.permit_wait_ms >= 1000 { text += &format!(", waited {}s for a permit", r.permit_wait_ms / 1000); }
        text += &format!(", {} leaves installed in it", r.attempt_installed_leaves);
    }
    if r.last_error_unix_ms > r.last_outcome_unix_ms {
        text += &format!(", last error {} ago: {}", age(r.last_error_unix_ms), r.last_error);
    } else if r.last_outcome_unix_ms > 0 {
        text += &format!(", last {} ago: {}", age(r.last_outcome_unix_ms), r.last_outcome);
    }
    text
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_stale_and_blocked_observations_are_distinct() {
        assert_eq!(state_at(None, 40_000), "unknown");
        let s = WorkerExecution { state: "blocked".into(), blocker: "checkpoint mismatch".into(), observed_unix_ms: 10_000, materialized_frame: Some(0), ..Default::default() };
        assert_eq!(state_at(Some(&s), 20_000), "blocked");
        assert_eq!(state_at(Some(&s), 40_001), "stale");
        let old = WorkerExecution::default();
        assert_eq!(state_at(Some(&old), 1), "stale");
        assert!(detail(None).contains("unknown"));
        assert!(detail(Some(&s)).contains("checkpoint mismatch"));
        assert!(!detail(Some(&s)).contains("Recovery"));
        let r = ShardRecovery { phase: "installing_leaves".into(), installed_leaves: 262_144, planned_leaves: 2_517_449,
            last_outcome: "replayed to frame 3".into(), last_outcome_unix_ms: 5, last_error: "no archive".into(), last_error_unix_ms: 9, ..Default::default() };
        let text = detail(Some(&WorkerExecution { recovery: Some(r), ..s.clone() }));
        assert!(text.contains("installing_leaves") && text.contains("262144/2517449") && text.contains("no archive"));
        let r = ShardRecovery { phase: "idle".into(), source: "192.0.2.1:8340".into(), attempts: 4, consecutive_failures: 3,
            attempt_started_unix_ms: 1, permit_wait_ms: 31_000, attempt_installed_leaves: 262_144,
            last_error: "get_vertex_blobs: Timeout expired".into(), last_error_unix_ms: 9, ..Default::default() };
        let text = recovery(&r);
        assert!(text.contains("from 192.0.2.1:8340") && text.contains("attempt 4 (3 failed in a row)"), "{text}");
        assert!(text.contains("waited 31s for a permit") && text.contains("262144 leaves installed in it"), "{text}");
    }
}
