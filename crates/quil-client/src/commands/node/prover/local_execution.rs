//! Display local worker observations without inferring health from allocation.
use quil_types::proto::node::{SessionSeal, ShardRecovery, WorkerExecution};
fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_millis() as u64
}
pub fn state_at(s: Option<&WorkerExecution>, now: u64) -> &str {
    let Some(s) = s else { return "unknown" };
    if s.observed_unix_ms == 0 || now.saturating_sub(s.observed_unix_ms) > 30_000 { return "stale"; }
    // Older nodes classified this expected lifecycle wait as a blocker.
    if s.state == "blocked" && s.blocker == "awaiting successor" { return "handoff"; }
    match s.state.as_str() {
        "starting" | "waiting" | "running" | "syncing" | "serving" | "closing" | "handoff" | "blocked" | "stopped" => s.state.as_str(),
        _ => "unknown",
    }
}
/// A worker whose consensus host runs: `running` from nodes that report no
/// lifecycle phase, otherwise serving, syncing its shard data, or closing.
pub fn hosting(state: &str) -> bool {
    matches!(state, "running" | "serving" | "syncing" | "closing")
}
/// A fresh observation in a state this client knows.
pub fn observed(state: &str) -> bool {
    !matches!(state, "stale" | "unknown")
}
pub fn local_execution_state(s: Option<&WorkerExecution>) -> &str { state_at(s, now_ms()) }
/// Compact labels share the column's nine-character budget.
pub fn execution_label(state: &str) -> &str {
    match state {
        "starting" => "start",
        "syncing" => "sync",
        "serving" => "serve",
        "running" => "running", // Older nodes do not report a lifecycle phase.
        "closing" => "close",
        "waiting" => "wait",
        _ => state,
    }
}
pub fn advance_age(timestamp: u64) -> &'static str {
    if now_ms().saturating_sub(timestamp) >= 60_000 { ">60s" } else { "<60s" }
}
/// Stable age buckets distinguish absent observations from old ones.
pub fn age_bucket(timestamp: u64) -> &'static str {
    if timestamp == 0 { "unobserved" } else { advance_age(timestamp) }
}
/// Keep the ordinary row footer focused on the current recovery phase.
pub fn recovery_summary(r: &ShardRecovery) -> String {
    let phase = if r.phase.is_empty() { "unknown" } else { &r.phase };
    let mut text = format!("Recovery: {phase} ({})", age_bucket(r.phase_since_unix_ms));
    if r.last_error_unix_ms > r.last_outcome_unix_ms {
        text += " | Last recovery attempt failed; expand for details";
    }
    text
}
pub fn seal_summary(s: &SessionSeal) -> String {
    if s.recorded_unix_ms > 0 {
        format!("Seal: g{} at frame {}, recorded by GLOBAL", s.generation, s.checkpoint)
    } else {
        format!("Seal: g{} at frame {}, {}", s.generation, s.checkpoint,
            if s.submissions == 0 { "awaiting submission" } else { "awaiting GLOBAL recording" })
    }
}
pub fn age(timestamp: u64) -> String {
    if timestamp == 0 { "-".into() } else { format!("{}s", now_ms().saturating_sub(timestamp) / 1000) }
}
pub fn detail(s: Option<&WorkerExecution>) -> String {
    let Some(s) = s else { return "Local execution: unknown (node has no worker observations)".into() };
    format!("Local execution: {}{}; height {}; last advance {}; observation {} ago",
        execution_label(local_execution_state(Some(s))),
        if s.blocker.is_empty() { String::new() } else { format!(" ({})", s.blocker) },
        s.materialized_frame.map(|h| h.to_string()).unwrap_or_else(|| "unknown".into()),
        if s.last_advance_unix_ms == 0 { "unobserved".into() } else { format!("{} ago", age(s.last_advance_unix_ms)) },
        age(s.observed_unix_ms))
        + &s.recovery.as_ref().map(|r| format!("; {}", recovery(r))).unwrap_or_default()
        + &s.seal.as_ref().map(|seal| format!("; {}", sealed(seal))).unwrap_or_default()
}
/// The session's finalized terminal seal and how far GLOBAL has taken it: a
/// sealed worker produces no frames while it waits for its successor.
pub fn sealed(s: &SessionSeal) -> String {
    let mut text = format!("Seal: generation {} at frame {} (view {}), finalized {}",
        s.generation, s.checkpoint, s.view, age_bucket(s.finalized_unix_ms));
    if s.recorded_unix_ms > 0 {
        return text + &format!(", recorded by GLOBAL {}", age_bucket(s.recorded_unix_ms));
    }
    if s.submissions == 0 {
        return text + ", not submitted yet";
    }
    text += &format!(", submitted {} times (last {}), GLOBAL executed through {}", s.submissions,
        age_bucket(s.last_submitted_unix_ms), s.global_executed);
    text += &match s.drain.as_str() {
        "attached" | "partial" => format!(", drain {} ({} frames)", s.drain, s.drain_headers),
        "too_many" => ", drain too_many (more missing than one submission carries; GLOBAL fences the session)".into(),
        "" => String::new(),
        other => format!(", drain {other}"),
    };
    text
}
/// Archive recovery, which runs in any execution state: a worker can be
/// downloading its shard while running or blocked at height 0.
pub fn recovery(r: &ShardRecovery) -> String {
    let mut text = format!("Recovery: {} ({})", if r.phase.is_empty() { "unknown" } else { &r.phase }, age_bucket(r.phase_since_unix_ms));
    if !r.source.is_empty() { text += &format!(" from {}", r.source); }
    if r.planned_leaves > 0 {
        text += &format!(", leaves {}/{} (phase {}, {})", r.installed_leaves, r.planned_leaves, r.tree_phase, age_bucket(r.leaves_observed_unix_ms));
    }
    if r.attempt_started_unix_ms > 0 {
        text += &format!(", attempt {}", r.attempts + u32::from(r.phase != "idle"));
        if r.consecutive_failures > 0 { text += &format!(" ({} failed in a row)", r.consecutive_failures); }
        if r.permit_wait_ms >= 1000 { text += &format!(", waited {}s for a permit", r.permit_wait_ms / 1000); }
        text += &format!(", {} leaves installed in it", r.attempt_installed_leaves);
    }
    if r.last_error_unix_ms > r.last_outcome_unix_ms {
        text += &format!(", last error {}: {}", age_bucket(r.last_error_unix_ms), r.last_error);
    } else if r.last_outcome_unix_ms > 0 {
        text += &format!(", last {}: {}", age_bucket(r.last_outcome_unix_ms), r.last_outcome);
    }
    text
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_summary_distinguishes_unobserved_old_and_latest_failed_attempts() {
        let mut r = ShardRecovery { phase: "idle".into(), ..Default::default() };
        assert_eq!(recovery_summary(&r), "Recovery: idle (unobserved)");
        r.phase_since_unix_ms = now_ms();
        assert_eq!(recovery_summary(&r), "Recovery: idle (<60s)");
        r.phase_since_unix_ms = now_ms().saturating_sub(61_000);
        r.last_error_unix_ms = 20; r.last_outcome_unix_ms = 10;
        assert!(recovery_summary(&r).contains("idle (>60s) | Last recovery attempt failed"));
        r.last_outcome_unix_ms = 30;
        assert_eq!(recovery_summary(&r), "Recovery: idle (>60s)");
        let mut seal = SessionSeal { generation: 4, checkpoint: 9, ..Default::default() };
        assert!(seal_summary(&seal).contains("awaiting submission"));
        seal.submissions = 1;
        assert!(seal_summary(&seal).contains("awaiting GLOBAL recording"));
        seal.recorded_unix_ms = 2;
        assert!(seal_summary(&seal).contains("recorded by GLOBAL"));
    }
    #[test]
    fn missing_stale_and_blocked_observations_are_distinct() {
        assert_eq!(state_at(None, 40_000), "unknown");
        let s = WorkerExecution { state: "blocked".into(), blocker: "checkpoint mismatch".into(), observed_unix_ms: 10_000, materialized_frame: Some(0), ..Default::default() };
        assert_eq!(state_at(Some(&s), 20_000), "blocked");
        assert_eq!(state_at(Some(&s), 40_001), "stale");
        let old = WorkerExecution::default();
        assert_eq!(state_at(Some(&old), 1), "stale");
        for state in ["running", "serving", "syncing", "closing", "handoff", "waiting", "starting", "stopped"] {
            let s = WorkerExecution { state: state.into(), observed_unix_ms: 10_000, ..Default::default() };
            assert_eq!(state_at(Some(&s), 20_000), state);
            assert!(observed(state_at(Some(&s), 20_000)));
        }
        let unknown = WorkerExecution { state: "unknown".into(), observed_unix_ms: 10_000, ..Default::default() };
        assert!(!observed(state_at(Some(&unknown), 20_000)) && !observed("stale"));
        assert!(["running", "serving", "syncing", "closing"].into_iter().all(hosting));
        assert!(!["starting", "handoff", "waiting", "blocked", "stopped", "stale", "unknown"].into_iter().any(hosting));
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
        let seal = SessionSeal { generation: 1, checkpoint: 575, view: 2671, global_executed: 566, drain: "partial".into(),
            drain_headers: 8, finalized_unix_ms: 1, last_submitted_unix_ms: 2, submissions: 3, ..Default::default() };
        let text = detail(Some(&WorkerExecution { seal: Some(seal.clone()), ..s.clone() }));
        assert!(text.contains("Seal: generation 1 at frame 575") && text.contains("GLOBAL executed through 566"), "{text}");
        assert!(text.contains("drain partial (8 frames)"), "{text}");
        assert!(sealed(&SessionSeal { recorded_unix_ms: 3, ..seal }).contains("recorded by GLOBAL"));
    }

    #[test]
    fn phase_labels_preserve_freshness_and_legacy_observations() {
        for (state, label) in [("starting", "start"), ("syncing", "sync"),
            ("serving", "serve"), ("closing", "close"), ("handoff", "handoff"),
            ("waiting", "wait"), ("blocked", "blocked"), ("stopped", "stopped"),
            ("running", "running")] {
            let observation = WorkerExecution { state: state.into(), observed_unix_ms: 10_000, ..Default::default() };
            assert_eq!(execution_label(state_at(Some(&observation), 20_000)), label);
            assert!(label.len() <= 9);
            assert_eq!(state_at(Some(&observation), 40_001), "stale");
        }
        let legacy = WorkerExecution { state: "blocked".into(), blocker: "awaiting successor".into(),
            observed_unix_ms: 10_000, ..Default::default() };
        assert_eq!(state_at(Some(&legacy), 20_000), "handoff");
        assert_eq!(state_at(Some(&legacy), 40_001), "stale");
    }
}
