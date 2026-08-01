//! Single-test execution: start the compose stack, await the proxy's
//! notification (or cancellation), adjudicate the result, capture artifacts on
//! failure, and always tear the stack down.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use devnet::shared::{FrameNotification, NodeInfo, NotificationType};
use devnet::viewpartitions::ViewPartitionEntry;

use crate::artifacts::{self, TestConfig};
use crate::docker::{self, ExecuteTest};
use crate::notification::NotificationRouter;
use crate::registry::ProjectRegistry;

#[derive(Debug, Clone, Default)]
pub struct TestResult {
    pub run_id: String,
    pub success: bool,
    pub error_message: String,
    pub duration: Duration,
    pub artifact_dir: String,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub exec_dir: String,
    pub bearer_token: String,
    pub listen_port: String,
    pub verbose: bool,
    pub stop_frame: i32,
    pub nodes: Vec<NodeInfo>,
    pub minimum_nodes: i32,
    pub view_partitions_resolved: String,
    pub view_partitions_original: Vec<ViewPartitionEntry>,
    pub out_dir: String,
    pub save_logs_on_success: bool,
    pub parallel: i32,
    pub global_timeout: Duration,
    pub node_catchup_timeout: Duration,
}

/// Runs a single simulation for `run_id` and returns its result.
pub async fn run_single_test(
    cancel: &CancellationToken,
    run_id: &str,
    cfg: &RunConfig,
    router: &NotificationRouter,
    registry: &ProjectRegistry,
) -> TestResult {
    let mut notif_rx = router.register(run_id);
    let project_name = format!("devnet_run_{run_id}");

    // Register before startup, not after. `docker compose up --wait` creates the
    // network and containers before it blocks on healthchecks, so a failure (or
    // an interrupt) part-way through startup can leave a partial stack behind.
    // Registering now means both this function's teardown and the interrupt-time
    // safety net (`cleanup_active_projects`) can reap whatever was created.
    registry.register(&project_name);

    tracing::info!(run_id, view_partitions = ?cfg.view_partitions_original, "Starting test");

    if let Err(e) = docker::execute_test(ExecuteTest {
        run_id,
        exec_dir: &cfg.exec_dir,
        bearer_token: &cfg.bearer_token,
        listen_port: &cfg.listen_port,
        project_name: &project_name,
        stop_frame: cfg.stop_frame,
        verbose: cfg.verbose,
        parallel: cfg.parallel,
        nodes: &cfg.nodes,
        minimum_nodes: cfg.minimum_nodes,
        resolved_view_partitions: &cfg.view_partitions_resolved,
        global_timeout: cfg.global_timeout,
        node_catchup_timeout: cfg.node_catchup_timeout,
    })
    .await
    {
        tracing::error!(error = %e, run_id, "Failed to start compose stack");
        // `up --wait` may have created containers/networks before failing on an
        // unhealthy service, so explicitly tear down with a bounded budget — the
        // interrupt-time safety net only runs on cancellation, not on a normal
        // startup failure. A `down` on a never-created project is a harmless
        // no-op, so this is safe even when `execute_test` failed before `up`.
        let down =
            docker::docker_compose_down(&cfg.exec_dir, &project_name, cfg.verbose, cfg.parallel);
        match tokio::time::timeout(Duration::from_secs(30), down).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::error!(error = %err, run_id, project = %project_name, "Failed to clean up partial compose stack")
            }
            Err(_) => {
                tracing::error!(run_id, project = %project_name, "Timed out tearing down partial compose stack")
            }
        }
        registry.unregister(&project_name);
        router.unregister(run_id);
        return TestResult {
            run_id: run_id.to_string(),
            success: false,
            error_message: format!("failed to start: {e}"),
            ..Default::default()
        };
    }

    // Wait for the proxy's terminal notification or context cancellation, logging
    // intermediate frame-progress updates as they arrive so a live run shows
    // progress instead of going silent until the verdict.
    let mut result = loop {
        tokio::select! {
            maybe_n = notif_rx.recv() => match maybe_n {
                Some(n) if n.notification_type == NotificationType::Progress => {
                    if cfg.verbose {
                        tracing::debug!(
                            run_id,
                            frame = n.stop_frame,
                            stop_frame = cfg.stop_frame,
                            "Frame progress"
                        );
                    }
                    continue;
                }
                Some(n) => break handle_terminal_notification(run_id, cfg, n),
                None => break TestResult {
                    run_id: run_id.to_string(),
                    success: false,
                    error_message: "notification channel closed".to_string(),
                    ..Default::default()
                },
            },
            _ = cancel.cancelled() => {
                tracing::debug!(run_id, "Test run cancelled");
                break TestResult {
                    run_id: run_id.to_string(),
                    success: false,
                    error_message: "test run cancelled".to_string(),
                    ..Default::default()
                };
            }
        }
    };

    // Save artifacts for failing tests (and successes when requested), while the
    // stack is still up so service logs are available.
    if (!result.success || cfg.save_logs_on_success) && !cfg.out_dir.is_empty() {
        let tcfg = TestConfig {
            run_id: run_id.to_string(),
            stop_frame: cfg.stop_frame,
            nodes: cfg.nodes.clone(),
            minimum_nodes: cfg.minimum_nodes,
            view_partitions: cfg.view_partitions_original.clone(),
        };
        result.artifact_dir = artifacts::save_failure_artifacts(
            &cfg.out_dir,
            run_id,
            &project_name,
            &cfg.exec_dir,
            &result,
            &tcfg,
        )
        .await;
    }

    // Always tear the stack down — even on cancellation — with a bounded budget
    // independent of the (possibly cancelled) run context.
    let down = docker::docker_compose_down(&cfg.exec_dir, &project_name, cfg.verbose, cfg.parallel);
    match tokio::time::timeout(Duration::from_secs(30), down).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::error!(error = %e, run_id, project = %project_name, "Failed to cleanup compose stack")
        }
        Err(_) => {
            tracing::error!(run_id, project = %project_name, "Timed out tearing down compose stack")
        }
    }
    registry.unregister(&project_name);
    router.unregister(run_id);

    result
}

fn handle_terminal_notification(run_id: &str, cfg: &RunConfig, n: FrameNotification) -> TestResult {
    tracing::debug!(
        run_id,
        notification_type = ?n.notification_type,
        stop_frame = n.stop_frame,
        nodes_reached_stop_frame = n.nodes_reached_stop_frame,
        total_nodes = n.total_nodes,
        "Terminal notification received"
    );

    let base = || TestResult {
        run_id: run_id.to_string(),
        ..Default::default()
    };

    // Checked first: if the harness did not actually run the scenario, every
    // other signal in this notification is meaningless, and a pass would falsely
    // read as "the scenario was exercised and the network held up".
    if !n.harness_error.is_empty() {
        return TestResult {
            success: false,
            error_message: format!("harness verification failed: {}", n.harness_error),
            ..base()
        };
    }
    if !n.safety_error.is_empty() {
        return TestResult {
            success: false,
            error_message: n.safety_error,
            ..base()
        };
    }
    // `minimum_nodes` is a lower bound, not an exact count: the frame monitor
    // stops as soon as `>= min_nodes` reach the stop frame, and a single poll
    // cycle can carry several nodes across at once, so `nodes_reached_stop_frame`
    // may legitimately exceed the threshold. Only fewer than required is a
    // failure.
    if n.nodes_reached_stop_frame < cfg.minimum_nodes {
        return TestResult {
            success: false,
            error_message: format!(
                "expected at least {} nodes to reach stop frame, but got {}",
                cfg.minimum_nodes, n.nodes_reached_stop_frame
            ),
            ..base()
        };
    }
    if !n.enrollment_error.is_empty() {
        return TestResult {
            success: false,
            error_message: format!("enrollment verification failed: {}", n.enrollment_error),
            ..base()
        };
    }
    if !n.rejoin_error.is_empty() {
        return TestResult {
            success: false,
            error_message: format!("consensus rejoin verification failed: {}", n.rejoin_error),
            ..base()
        };
    }
    TestResult {
        success: true,
        ..base()
    }
}

pub fn print_summary(results: &[TestResult], interrupted: bool) {
    let passed = results.iter().filter(|r| r.success).count();
    let failed = results.len() - passed;

    let status = if interrupted {
        "INTERRUPTED"
    } else if failed > 0 {
        "FAILED"
    } else {
        "PASSED"
    };

    tracing::info!(
        status,
        total = results.len(),
        passed,
        failed,
        "Test Summary"
    );

    if failed > 0 {
        tracing::info!("Failed test runs:");
        for r in results.iter().filter(|r| !r.success) {
            tracing::info!(run_id = %r.run_id, error = %r.error_message, duration = ?r.duration, "  Run failed");
        }
        for r in results.iter().filter(|r| !r.artifact_dir.is_empty()) {
            tracing::info!(dir = %r.artifact_dir, run_id = %r.run_id, "Saved failure artifacts");
        }
    }
}

pub fn has_failures(results: &[TestResult]) -> bool {
    results.iter().any(|r| !r.success)
}

#[cfg(test)]
mod evaluate_notification_tests {
    use super::*;
    use devnet::shared::NotificationType;

    /// A RunConfig that only sets the field `evaluate_notification` reads
    /// (`minimum_nodes`); everything else is irrelevant to the success check.
    fn cfg(minimum_nodes: i32) -> RunConfig {
        RunConfig {
            exec_dir: String::new(),
            bearer_token: String::new(),
            listen_port: String::new(),
            verbose: false,
            stop_frame: 30,
            nodes: Vec::new(),
            minimum_nodes,
            view_partitions_resolved: String::new(),
            view_partitions_original: Vec::new(),
            out_dir: String::new(),
            save_logs_on_success: false,
            parallel: 1,
            global_timeout: Duration::from_secs(120),
            node_catchup_timeout: Duration::from_secs(60),
        }
    }

    /// A clean terminal-frame notification with `reached` nodes and no errors.
    fn ok_notification(reached: i32) -> FrameNotification {
        FrameNotification {
            run_id: String::new(),
            stop_frame: 30,
            notification_type: NotificationType::TerminalFrame,
            safety_error: String::new(),
            nodes_reached_stop_frame: reached,
            total_nodes: reached,
            enrollment_error: String::new(),
            rejoin_error: String::new(),
            harness_error: String::new(),
        }
    }

    /// A run that did not execute its scenario must never report success, even
    /// though every other signal looks clean — that is exactly the false pass
    /// this check exists to prevent.
    #[test]
    fn harness_error_fails_an_otherwise_clean_run() {
        let n = FrameNotification {
            harness_error: "scheduled partition views were never observed: [1]".into(),
            ..ok_notification(3)
        };
        let r = handle_terminal_notification("run", &cfg(3), n);
        assert!(!r.success);
        assert!(
            r.error_message.contains("harness verification failed"),
            "unexpected: {}",
            r.error_message
        );
    }

    /// The harness check outranks the others: if the scenario did not run, the
    /// other verdicts are not evidence of anything.
    #[test]
    fn harness_error_takes_precedence_over_safety_error() {
        let n = FrameNotification {
            harness_error: "consensus event dropped".into(),
            safety_error: "fork detected".into(),
            ..ok_notification(3)
        };
        let r = handle_terminal_notification("run", &cfg(3), n);
        assert!(!r.success);
        assert!(
            r.error_message.contains("harness verification failed"),
            "unexpected: {}",
            r.error_message
        );
    }

    #[test]
    fn exact_match_succeeds() {
        let r = handle_terminal_notification("run", &cfg(3), ok_notification(3));
        assert!(r.success, "{}", r.error_message);
    }

    /// The regression this guards: `minimum_nodes` is a lower bound, so more
    /// nodes than required reaching the stop frame is a pass, not a failure.
    /// With `--minnodes=3` and 4 healthy archives, the frame monitor can report
    /// 4 reached, which previously failed the run via a strict `!=` check.
    #[test]
    fn more_than_minimum_succeeds() {
        let r = handle_terminal_notification("run", &cfg(3), ok_notification(4));
        assert!(r.success, "{}", r.error_message);
    }

    #[test]
    fn fewer_than_minimum_fails() {
        let r = handle_terminal_notification("run", &cfg(3), ok_notification(2));
        assert!(!r.success);
        assert!(
            r.error_message.contains("at least 3"),
            "unexpected message: {}",
            r.error_message
        );
    }
}
