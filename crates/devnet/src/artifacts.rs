//! Failure-artifact capture: writes the test config, result, and per-service
//! logs to `<out_dir>/<run_id>/`. Must be called before `docker compose down`
//! so the service logs are still available.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use devnet::rankpartitions::RankPartitionEntry;
use devnet::shared::NodeInfo;

use crate::docker;
use crate::runner::TestResult;

#[derive(Debug, Serialize)]
pub struct TestConfig {
    pub run_id: String,
    pub stop_frame: i32,
    pub nodes: Vec<NodeInfo>,
    pub minimum_nodes: i32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rank_partitions: Vec<RankPartitionEntry>,
}

#[derive(Debug, Serialize)]
struct TestResultOutput {
    run_id: String,
    success: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    error_message: String,
}

/// Writes config, result, and per-service logs to `<out_dir>/<run_id>/`.
/// Returns the artifact directory path, or an empty string on failure.
pub async fn save_failure_artifacts(
    out_dir: &str,
    run_id: &str,
    project_name: &str,
    exec_dir: &str,
    result: &TestResult,
    cfg: &TestConfig,
) -> String {
    let run_dir = Path::new(out_dir).join(run_id);
    if let Err(e) = std::fs::create_dir_all(&run_dir) {
        tracing::error!(error = %e, dir = %run_dir.display(), "Failed to create artifact directory");
        return String::new();
    }

    match serde_yaml::to_string(cfg) {
        Ok(data) => {
            if let Err(e) = std::fs::write(run_dir.join("config.yaml"), data) {
                tracing::error!(error = %e, run_id, "Failed to write config artifact");
            }
        }
        Err(e) => tracing::error!(error = %e, run_id, "Failed to marshal test config"),
    }

    let out = TestResultOutput {
        run_id: result.run_id.clone(),
        success: result.success,
        error_message: result.error_message.clone(),
    };
    match serde_yaml::to_string(&out) {
        Ok(data) => {
            if let Err(e) = std::fs::write(run_dir.join("result.yaml"), data) {
                tracing::error!(error = %e, run_id, "Failed to write result artifact");
            }
        }
        Err(e) => tracing::error!(error = %e, run_id, "Failed to marshal test result"),
    }

    save_service_logs(&run_dir, run_id, project_name, exec_dir).await;

    run_dir.to_string_lossy().into_owned()
}

async fn save_service_logs(run_dir: &Path, run_id: &str, project_name: &str, exec_dir: &str) {
    let logs_dir = run_dir.join("logs");
    if let Err(e) = std::fs::create_dir_all(&logs_dir) {
        tracing::error!(error = %e, dir = %logs_dir.display(), "Failed to create logs directory");
        return;
    }

    let collect = async {
        let services = docker::docker_compose_project_services(exec_dir, project_name).await?;
        for service in services {
            match docker::docker_compose_service_logs(exec_dir, project_name, &service).await {
                Ok(data) => {
                    let log_file = logs_dir.join(format!("{service}.log"));
                    if let Err(e) = std::fs::write(&log_file, data) {
                        tracing::error!(error = %e, run_id, service, "Failed to write service log");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, run_id, service, "Failed to capture service logs")
                }
            }
        }
        anyhow::Ok(())
    };

    match tokio::time::timeout(Duration::from_secs(60), collect).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!(error = %e, run_id, "Failed to list services"),
        Err(_) => tracing::error!(run_id, "Timed out collecting service logs"),
    }
}
