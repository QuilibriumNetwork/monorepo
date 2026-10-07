//! Display local worker observations without inferring health from allocation.
use quil_types::proto::node::WorkerExecution;
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
    }
}
