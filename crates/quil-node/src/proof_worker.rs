//! Token proof verifier: resolve the trusted worker executable,
//! build the node-wide client, and install the compiled per-network policy on
//! execution managers. One `WorkerVerifier` instance is built per process and
//! cloned into every manager so all of them share its single admission slot.
use std::{path::PathBuf, time::Duration};

use quil_config::ProofWorkerConfig;
use quil_execution::{token_intrinsic::dispatch::TokenPolicy, ExecutionEngineManager};
use quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier;

static NEXT_LANE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

pub(crate) const WORKER_FILE_NAME: &str = "quil-amount-proof-worker";
/// First argument that runs the node executable as the worker (see `main`).
pub(crate) const WORKER_MODE_ARG: &str = "--amount-proof-worker";
pub(crate) const WORKER_PATH_ENV: &str = "QUIL_AMOUNT_WORKER_PATH";

/// Resolution order: `proofWorker.path`, then `QUIL_AMOUNT_WORKER_PATH`, then
/// the running node executable itself, started in its worker mode
/// ([`WORKER_MODE_ARG`]); the returned flag says which. The result must be an
/// existing regular file with an absolute path; the client does not attest its
/// bytes, so the path must come from trusted local configuration.
pub(crate) fn resolve_worker_path(config: &ProofWorkerConfig) -> anyhow::Result<(PathBuf, bool)> {
    let (candidate, own_executable) = if !config.path.is_empty() {
        (PathBuf::from(&config.path), false)
    } else if let Some(path) = std::env::var_os(WORKER_PATH_ENV).filter(|path| !path.is_empty()) {
        (PathBuf::from(path), false)
    } else {
        (std::env::current_exe()?, true)
    };
    let path = std::fs::canonicalize(&candidate).map_err(|e| {
        anyhow::anyhow!(
            "token proof worker not found at {}: {e}. Fix or unset proofWorker.path and {WORKER_PATH_ENV} \
             (the node runs itself as the worker by default), or set proofWorker.disabled: true",
            candidate.display()
        )
    })?;
    anyhow::ensure!(
        path.is_absolute() && path.is_file(),
        "token proof worker path {} is not a regular file",
        path.display()
    );
    Ok((path, own_executable))
}

/// Build the shared verifier client, or `None` when the operator disabled the
/// suite. Configuration errors fail here, before any state is opened.
pub(crate) fn build_worker(config: &ProofWorkerConfig) -> anyhow::Result<Option<WorkerVerifier>> {
    if config.disabled {
        tracing::warn!("token suite disabled by proofWorker.disabled; confidential token operations will be rejected");
        return Ok(None);
    }
    config.validate().map_err(anyhow::Error::msg)?;
    let (path, own_executable) = resolve_worker_path(config)?;
    let mut worker = WorkerVerifier::new(path.clone(), config.cpu_seconds, Duration::from_secs(config.wall_timeout_secs))
        .map_err(|e| anyhow::anyhow!("token proof worker configuration rejected: {e:?}"))?;
    if own_executable {
        worker = worker.with_worker_mode_arg(WORKER_MODE_ARG);
    }
    if config.address_space_bytes > 0 {
        if cfg!(target_os = "linux") {
            worker = worker
                .with_address_space_limit(config.address_space_bytes)
                .map_err(|e| anyhow::anyhow!("proofWorker.addressSpaceBytes rejected: {e:?}"))?;
        } else {
            tracing::warn!("proofWorker.addressSpaceBytes is Linux-only and is ignored on this platform");
        }
    }
    worker = worker
        .with_concurrency(config.max_concurrent)
        .and_then(|w| w.with_native_threads(config.native_threads))
        .and_then(|w| w.with_admission_wait(Duration::from_millis(config.admission_wait_ms)))
        .map_err(|e| anyhow::anyhow!("proofWorker concurrency settings rejected: {e:?}"))?;
    if config.max_resident_bytes > 0 {
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            worker = worker
                .with_resident_limit(config.max_resident_bytes)
                .map_err(|e| anyhow::anyhow!("proofWorker.maxResidentBytes rejected: {e:?}"))?;
        } else {
            tracing::warn!("proofWorker.maxResidentBytes is not enforced on this platform");
        }
    }
    quil_execution::token_intrinsic::dispatch::set_verification_budget_secs(config.verify_budget_secs);
    worker.check_ready().map_err(|e| anyhow::anyhow!(
        "token proof worker at {} failed startup/ABI check: {e:?}", path.display()))?;
    tracing::info!(
        worker = %path.display(),
        cpu_seconds = config.cpu_seconds,
        wall_timeout_secs = config.wall_timeout_secs,
        max_concurrent = config.max_concurrent,
        admission_wait_ms = config.admission_wait_ms,
        max_resident_bytes = config.max_resident_bytes,
        native_threads = config.native_threads,
        verify_budget_secs = config.verify_budget_secs,
        "token proof worker configured"
    );
    Ok(Some(worker))
}

/// All processes of one node use its base DB directory for verifier admission,
/// even when remote workers store their shard data in separate directories.
/// Readiness is checked first, before creating the directory or lock file.
pub(crate) fn build_node_worker(config: &quil_config::Config) -> anyhow::Result<Option<WorkerVerifier>> {
    let Some(worker) = build_worker(&config.proof_worker)? else { return Ok(None); };
    let base = if config.db.path.is_empty() { PathBuf::from(".config/store") }
        else { PathBuf::from(&config.db.path) };
    std::fs::create_dir_all(&base)?;
    let lock = std::fs::canonicalize(base)?.join(".proof-worker-admission.lock");
    worker.with_shared_admission(lock.clone()).map(Some)
        .map_err(|e| anyhow::anyhow!("proof worker admission file {}: {e:?}", lock.display()))
}

/// Install the network policy and a clone of the shared worker on a manager.
/// Without a worker (suite disabled) the manager is returned unchanged and
/// rejects confidential token operations.
pub(crate) fn install_token_worker(
    manager: ExecutionEngineManager,
    network: u8,
    worker: Option<&WorkerVerifier>,
) -> anyhow::Result<ExecutionEngineManager> {
    match worker {
        // Each manager waits for verifier slots in its own fairness lane, so a
        // busy shard cannot keep the global engine or another shard out.
        Some(worker) => manager
            .with_token_worker(
                TokenPolicy::for_network(network),
                worker.for_lane(NEXT_LANE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)),
            )
            .map_err(|e| anyhow::anyhow!("install token suite: {e}")),
        None => Ok(manager),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires the Taskfile-built native worker"]
    fn native_worker_passes_startup_check() {
        let path = std::env::var("QUIL_AMOUNT_WORKER_PATH").expect("built worker path");
        assert!(build_worker(&ProofWorkerConfig { path, ..Default::default() }).unwrap().is_some());
    }

    #[tokio::test]
    async fn master_rejects_missing_verifier_before_creating_store() {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("must-not-be-created");
        let mut config = quil_config::Config::default();
        config.db.path = store.to_string_lossy().into_owned();
        config.proof_worker.path = directory.path().join("absent-worker").to_string_lossy().into_owned();
        let result = crate::master_node::start(quil_lifecycle::Supervisor::new(),
            &config, directory.path(), true, 0, None).await;
        assert!(result.is_err());
        assert!(!store.exists());
    }

    #[tokio::test]
    async fn remote_worker_rejects_missing_verifier_before_creating_store() {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("must-not-be-created");
        let mut config = quil_config::Config::default();
        config.db.worker_paths = vec![store.to_string_lossy().into_owned()];
        config.proof_worker.path = directory.path().join("absent-worker").to_string_lossy().into_owned();
        let result = crate::worker_node::start(quil_lifecycle::Supervisor::new(), &config, 1, 0).await;
        assert!(result.is_err());
        assert!(!store.exists());
    }

    #[test]
    fn worker_path_resolution_requires_an_existing_absolute_file() {
        let directory = tempfile::tempdir().unwrap();
        let worker = directory.path().join(WORKER_FILE_NAME);
        std::fs::write(&worker, b"#!/bin/sh\ncat >/dev/null\nexit 80\n").unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let explicit = ProofWorkerConfig { path: worker.to_string_lossy().into_owned(), ..Default::default() };
        assert_eq!(resolve_worker_path(&explicit).unwrap(), (std::fs::canonicalize(&worker).unwrap(), false));
        assert_eq!(
            resolve_worker_path(&ProofWorkerConfig::default()).unwrap(),
            (std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(), true),
            "with nothing configured the node runs itself as the worker"
        );
        let missing = ProofWorkerConfig { path: directory.path().join("absent").to_string_lossy().into_owned(), ..Default::default() };
        assert!(resolve_worker_path(&missing).is_err());
        let directory_path = ProofWorkerConfig { path: directory.path().to_string_lossy().into_owned(), ..Default::default() };
        assert!(resolve_worker_path(&directory_path).is_err());
        // A disabled suite never resolves or builds a worker.
        assert!(build_worker(&ProofWorkerConfig { disabled: true, ..missing.clone() }).unwrap().is_none());
        assert!(build_worker(&missing).is_err());
        assert!(build_worker(&ProofWorkerConfig { cpu_seconds: 0, ..explicit.clone() }).is_err());
        let built = build_worker(&explicit).unwrap();
        assert!(built.is_some());
        let mut node_config = quil_config::Config::default();
        node_config.db.path = directory.path().join("base-store").to_string_lossy().into_owned();
        node_config.db.worker_paths = vec![directory.path().join("shard-store").to_string_lossy().into_owned()];
        node_config.proof_worker = explicit.clone();
        assert!(build_node_worker(&node_config).unwrap().is_some());
        assert!(PathBuf::from(&node_config.db.path).join(".proof-worker-admission.lock").is_file());
        assert!(!PathBuf::from(&node_config.db.worker_paths[0]).exists());
        #[cfg(not(target_os = "linux"))]
        assert!(build_worker(&ProofWorkerConfig { address_space_bytes: 1 << 30, ..explicit.clone() }).unwrap().is_some());
        std::fs::write(&worker, b"#!/bin/sh\ncat >/dev/null\nexit 82\n").unwrap();
        assert!(build_worker(&explicit).is_err());
        // A stalled executable is reaped by the same bounded transport used
        // for proofs; it cannot hold startup indefinitely.
        std::fs::write(&worker, b"#!/bin/sh\nexec sleep 30\n").unwrap();
        let stalled = WorkerVerifier::new(std::fs::canonicalize(&worker).unwrap(), 1,
            Duration::from_millis(50)).unwrap();
        assert!(matches!(stalled.check_ready(), Err(
            quil_lattice_ct::confidential::relation::backend::worker_client::ClientError::Process(
                quil_lattice_ct::confidential::relation::backend::worker_process::WorkerError::Timeout))));
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(build_worker(&explicit).is_err());
        }
    }
}
