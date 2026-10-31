//! Token proof verifier: resolve the trusted worker executable,
//! build the node-wide client, and install the compiled per-network policy on
//! execution managers. One `WorkerVerifier` instance is built per process and
//! cloned into every manager so all of them share its single admission slot.
use std::{path::PathBuf, time::Duration};

use quil_config::ProofWorkerConfig;
use quil_execution::{token_intrinsic::dispatch::TokenPolicy, ExecutionEngineManager};
use quil_lattice_ct::confidential::relation::backend::{
    worker_client::WorkerVerifier,
    worker_process::{set_cpu_report, use_process_cpus, SpawnCpus},
};

static NEXT_LANE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

// Fixture filename; production launches the node in worker mode.
#[allow(dead_code)]
pub(crate) const WORKER_FILE_NAME: &str = "quil-amount-proof-worker";
/// First argument that runs the node executable as the worker (see `main`).
pub(crate) const WORKER_MODE_ARG: &str = "--amount-proof-worker";
pub(crate) const WORKER_PATH_ENV: &str = "QUIL_AMOUNT_WORKER_PATH";

/// Verifier slots of a node that leaves `proofWorker.maxConcurrent` unset,
/// and the fewest an archive sizes itself to.
const DEFAULT_MAX_CONCURRENT: usize = 2;
/// Most verifier slots an archive sizes itself to.
const ARCHIVE_MAX_CONCURRENT_CAP: usize = 8;
/// Available memory an archive sets aside per verifier child when it sizes
/// its slots: the largest resident size recorded for one depth-32 child
/// (2.73 GB, see `proofWorker.maxResidentBytes`) plus margin, so busy slots
/// fit the memory they were sized to.
const ARCHIVE_CHILD_MEMORY_BYTES: u64 = 3 << 30;

/// Where a node's verifier slot count came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotSource {
    /// `proofWorker.maxConcurrent`.
    Configured,
    /// [`DEFAULT_MAX_CONCURRENT`]: not an archive, or an archive whose CPU
    /// count is unknown.
    Default,
    /// An archive's CPUs and available memory.
    Machine,
}

impl SlotSource {
    fn as_str(self) -> &'static str {
        match self {
            SlotSource::Configured => "proofWorker.maxConcurrent",
            SlotSource::Default => "default",
            SlotSource::Machine => {
                "archive: CPUs / nativeThreads, bounded by memory; proofWorker.maxConcurrent overrides"
            }
        }
    }
}

/// A node's verifier slot count and the inputs it was chosen from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifierSlots {
    slots: usize,
    source: SlotSource,
    /// CPUs the node may use, when the machine was asked.
    cpus: Option<usize>,
    /// Available memory in bytes, when the machine was asked.
    available_memory: Option<u64>,
    /// `cpus / nativeThreads`.
    cpu_slots: Option<usize>,
    /// `available_memory / ARCHIVE_CHILD_MEMORY_BYTES`.
    memory_slots: Option<usize>,
}

/// Verifier slots for a node. An explicit `maxConcurrent` always wins. Unset,
/// a regular node takes [`DEFAULT_MAX_CONCURRENT`]; an archive takes `cpus /
/// nativeThreads`, at most `available_memory / ARCHIVE_CHILD_MEMORY_BYTES`,
/// within `DEFAULT_MAX_CONCURRENT..=ARCHIVE_MAX_CONCURRENT_CAP`: it verifies
/// the confidential operations of each GLOBAL frame before publishing it, and
/// two slots fell behind their arrival (2026-10-30). Unknown CPUs leave the
/// default; unknown memory leaves the CPU bound.
fn verifier_slots(
    config: &ProofWorkerConfig,
    archive: bool,
    cpus: Option<usize>,
    available_memory: Option<u64>,
) -> VerifierSlots {
    let fixed = |slots, source| VerifierSlots {
        slots,
        source,
        cpus,
        available_memory,
        cpu_slots: None,
        memory_slots: None,
    };
    if let Some(slots) = config.max_concurrent {
        return fixed(slots, SlotSource::Configured);
    }
    if !archive {
        return fixed(DEFAULT_MAX_CONCURRENT, SlotSource::Default);
    }
    let cpu_slots = cpus.map(|cpus| cpus / usize::from(config.native_threads.max(1)));
    let memory_slots = available_memory
        .map(|bytes| usize::try_from(bytes / ARCHIVE_CHILD_MEMORY_BYTES).unwrap_or(usize::MAX));
    let Some(by_cpu) = cpu_slots else {
        return VerifierSlots {
            memory_slots,
            ..fixed(DEFAULT_MAX_CONCURRENT, SlotSource::Default)
        };
    };
    let slots = by_cpu
        .min(memory_slots.unwrap_or(usize::MAX))
        .clamp(DEFAULT_MAX_CONCURRENT, ARCHIVE_MAX_CONCURRENT_CAP);
    VerifierSlots {
        slots,
        source: SlotSource::Machine,
        cpus,
        available_memory,
        cpu_slots,
        memory_slots,
    }
}

/// CPUs this process may use, counted on a thread moved onto the process's
/// CPU set: the asking thread may be pinned to one core.
fn process_cpus() -> Option<usize> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("proof-slots".into())
            .spawn_scoped(scope, || {
                use_process_cpus();
                std::thread::available_parallelism().ok()
            })
            .ok()
            .and_then(|thread| thread.join().ok())
            .flatten()
            .map(|cpus| cpus.get())
    })
}

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

/// Build the shared verifier client with `slots` verifier slots, or `None`
/// when the operator disabled the suite. Configuration errors fail here,
/// before any state is opened.
fn build_worker(
    config: &ProofWorkerConfig,
    slots: VerifierSlots,
) -> anyhow::Result<Option<WorkerVerifier>> {
    if config.disabled {
        tracing::warn!("token suite disabled by proofWorker.disabled; confidential token operations will be rejected");
        return Ok(None);
    }
    config.validate().map_err(anyhow::Error::msg)?;
    let (path, own_executable) = resolve_worker_path(config)?;
    let mut worker = WorkerVerifier::new(
        path.clone(),
        config.cpu_seconds,
        Duration::from_secs(config.wall_timeout_secs),
    )
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
            tracing::warn!(
                "proofWorker.addressSpaceBytes is Linux-only and is ignored on this platform"
            );
        }
    }
    worker = worker
        .with_concurrency(slots.slots)
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
    quil_execution::token_intrinsic::dispatch::set_verification_budget_secs(
        config.verify_budget_secs,
    );
    set_cpu_report(report_child_cpus);
    worker.check_ready().map_err(|e| {
        anyhow::anyhow!(
            "token proof worker at {} failed startup/ABI check: {e:?}",
            path.display()
        )
    })?;
    tracing::info!(
        worker = %path.display(),
        cpu_seconds = config.cpu_seconds,
        wall_timeout_secs = config.wall_timeout_secs,
        max_concurrent = slots.slots,
        max_concurrent_from = slots.source.as_str(),
        cpus = slots.cpus,
        cpu_slots = slots.cpu_slots,
        available_memory_bytes = slots.available_memory,
        memory_slots = slots.memory_slots,
        admission_wait_ms = config.admission_wait_ms,
        max_resident_bytes = config.max_resident_bytes,
        native_threads = config.native_threads,
        verify_budget_secs = config.verify_budget_secs,
        "token proof worker configured"
    );
    Ok(Some(worker))
}

/// Once per process, at the first verifier child started from a data worker
/// thread pinned to fewer CPUs than the node may use.
fn report_child_cpus(cpus: SpawnCpus) {
    if cpus.child > cpus.spawning_thread {
        tracing::info!(
            child_cpus = cpus.child,
            worker_cpus = cpus.spawning_thread,
            "token proof worker child runs on the node's CPUs, not its data worker's pinned core"
        );
    } else {
        tracing::warn!(
            child_cpus = cpus.child,
            worker_cpus = cpus.spawning_thread,
            "token proof worker child kept its data worker's core pin; verifications share that core"
        );
    }
}

/// [`build_node_worker_as`], as an archive when `engine.archiveMode` is set.
pub(crate) fn build_node_worker(
    config: &quil_config::Config,
) -> anyhow::Result<Option<WorkerVerifier>> {
    build_node_worker_as(config, config.engine.archive_mode)
}

/// All processes of one node use its base DB directory for verifier admission,
/// even when remote workers store their shard data in separate directories.
/// Readiness is checked first, before creating the directory or lock file.
/// An archive without `maxConcurrent` sizes its slots to this machine
/// ([`verifier_slots`]). A process takes at most its own count of the shared
/// slot files, so processes that chose different counts together run at most
/// the largest.
pub(crate) fn build_node_worker_as(
    config: &quil_config::Config,
    archive: bool,
) -> anyhow::Result<Option<WorkerVerifier>> {
    let proof = &config.proof_worker;
    let slots = if archive && proof.max_concurrent.is_none() && !proof.disabled {
        verifier_slots(
            proof,
            true,
            process_cpus(),
            crate::mem_stats::host_memory().map(|memory| memory.available_bytes),
        )
    } else {
        verifier_slots(proof, archive, None, None)
    };
    let Some(worker) = build_worker(proof, slots)? else {
        return Ok(None);
    };
    let base = if config.db.path.is_empty() {
        PathBuf::from(".config/store")
    } else {
        PathBuf::from(&config.db.path)
    };
    std::fs::create_dir_all(&base)?;
    let lock = std::fs::canonicalize(base)?.join(".proof-worker-admission.lock");
    worker
        .with_shared_admission(lock.clone())
        .map(Some)
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

    /// A regular node's worker for `config`.
    fn build(config: &ProofWorkerConfig) -> anyhow::Result<Option<WorkerVerifier>> {
        build_worker(config, verifier_slots(config, false, None, None))
    }

    #[test]
    fn an_unset_max_concurrent_follows_an_archives_machine_only() {
        const GIB: u64 = 1 << 30;
        let unset = ProofWorkerConfig::default();
        let slots = |config: &ProofWorkerConfig, archive, cpus, memory| {
            verifier_slots(config, archive, cpus, memory).slots
        };
        // A regular node keeps two slots whatever the machine.
        let regular = verifier_slots(&unset, false, Some(32), Some(64 * GIB));
        assert_eq!(
            (regular.slots, regular.source),
            (DEFAULT_MAX_CONCURRENT, SlotSource::Default)
        );
        // An archive takes CPUs / nativeThreads (4 by default).
        let archive = verifier_slots(&unset, true, Some(16), Some(64 * GIB));
        assert_eq!(
            (
                archive.slots,
                archive.source,
                archive.cpu_slots,
                archive.memory_slots
            ),
            (4, SlotSource::Machine, Some(4), Some(21)),
            "a 16-CPU archive with 64 GiB available"
        );
        assert_eq!(slots(&unset, true, Some(12), Some(64 * GIB)), 3);
        let two_threads = ProofWorkerConfig {
            native_threads: 2,
            ..unset.clone()
        };
        assert_eq!(slots(&two_threads, true, Some(12), None), 6);
        // Memory bounds it: one slot per 3 GiB available.
        assert_eq!(slots(&unset, true, Some(32), Some(10 * GIB)), 3);
        // Never under the default, never over the cap.
        assert_eq!(slots(&unset, true, Some(4), Some(64 * GIB)), 2);
        assert_eq!(slots(&unset, true, Some(32), Some(GIB)), 2);
        assert_eq!(
            slots(&unset, true, Some(256), Some(1024 * GIB)),
            ARCHIVE_MAX_CONCURRENT_CAP
        );
        // Unknown CPUs leave the default.
        let unknown = verifier_slots(&unset, true, None, Some(64 * GIB));
        assert_eq!((unknown.slots, unknown.source), (2, SlotSource::Default));
        // An explicit value wins on an archive too, below or above the rule.
        for configured in [1, 2, 12] {
            let explicit = ProofWorkerConfig {
                max_concurrent: Some(configured),
                ..unset.clone()
            };
            let chosen = verifier_slots(&explicit, true, Some(16), Some(64 * GIB));
            assert_eq!(
                (chosen.slots, chosen.source),
                (configured, SlotSource::Configured)
            );
        }
    }

    /// An archive budgets 3 GiB of available memory per verifier slot, above
    /// the 2.73 GB a depth-32 child has been recorded holding: N × 3 GiB
    /// admits N slots, one byte less admits N − 1.
    #[test]
    fn an_archives_memory_bound_holds_at_its_boundary() {
        const GIB: u64 = 1 << 30;
        let unset = ProofWorkerConfig::default();
        for n in 3..=ARCHIVE_MAX_CONCURRENT_CAP {
            let at = n as u64 * 3 * GIB;
            for (available, expected) in [(at, n), (at - 1, n - 1)] {
                let chosen = verifier_slots(&unset, true, Some(64), Some(available));
                assert_eq!(
                    (chosen.slots, chosen.memory_slots),
                    (expected, Some(expected)),
                    "{available} bytes available must admit {expected} slots of 3 GiB"
                );
            }
        }
    }

    #[test]
    #[ignore = "requires the Taskfile-built native worker"]
    fn native_worker_passes_startup_check() {
        let path = std::env::var("QUIL_AMOUNT_WORKER_PATH").expect("built worker path");
        assert!(build(&ProofWorkerConfig {
            path,
            ..Default::default()
        })
        .unwrap()
        .is_some());
    }

    #[tokio::test]
    async fn master_rejects_missing_verifier_before_creating_store() {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("must-not-be-created");
        let mut config = quil_config::Config::default();
        config.db.path = store.to_string_lossy().into_owned();
        config.proof_worker.path = directory
            .path()
            .join("absent-worker")
            .to_string_lossy()
            .into_owned();
        let result = crate::master_node::start(
            quil_lifecycle::Supervisor::new(),
            &config,
            directory.path(),
            true,
            0,
            None,
        )
        .await;
        assert!(result.is_err());
        assert!(!store.exists());
    }

    #[tokio::test]
    async fn remote_worker_rejects_missing_verifier_before_creating_store() {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("must-not-be-created");
        let mut config = quil_config::Config::default();
        config.db.worker_paths = vec![store.to_string_lossy().into_owned()];
        config.proof_worker.path = directory
            .path()
            .join("absent-worker")
            .to_string_lossy()
            .into_owned();
        let result = crate::worker_node::start(
            quil_lifecycle::Supervisor::new(),
            &config,
            directory.path(),
            1,
            0,
        )
        .await;
        assert!(result.is_err());
        assert!(!store.exists());
    }

    /// An archive that leaves `maxConcurrent` unset admits as many
    /// verifications at once as its CPUs allow at `nativeThreads`, not the
    /// fixed two that let GLOBAL frames wait on a proof backlog (2026-10-30);
    /// a regular node and an explicit value keep theirs. Uses only APIs the
    /// release base has, so it shows the base admitting two.
    #[test]
    fn an_archive_node_sizes_its_verifier_slots_to_the_machine() {
        let cpus = std::thread::available_parallelism().map_or(1, |cpus| cpus.get());
        let available = crate::mem_stats::host_memory().map(|memory| memory.available_bytes);
        // Three slots at 3 GiB each; a literal so the test builds on the base.
        if cpus < 3 || available.is_some_and(|bytes| bytes < 9 << 30) {
            eprintln!("skipped: {cpus} CPUs and {available:?} bytes available fit two slots");
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let worker = directory.path().join(WORKER_FILE_NAME);
        std::fs::write(&worker, b"#!/bin/sh\ncat >/dev/null\nexit 80\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut config = quil_config::Config::default();
        config.db.path = directory
            .path()
            .join("base-store")
            .to_string_lossy()
            .into_owned();
        config.proof_worker = ProofWorkerConfig {
            path: worker.to_string_lossy().into_owned(),
            native_threads: 1,
            ..Default::default()
        };
        config.engine.archive_mode = true;
        let archive = build_node_worker(&config).unwrap().unwrap().concurrency();
        assert!(
            archive > 2 && archive <= cpus,
            "an archive on {cpus} CPUs with nativeThreads 1 admitted {archive} verifications \
             at once; two let GLOBAL frames wait on a proof backlog"
        );
        config.engine.archive_mode = false;
        let regular = build_node_worker(&config).unwrap().unwrap().concurrency();
        assert_eq!(regular, 2, "a regular node keeps two verifier slots");
        config.engine.archive_mode = true;
        // `into` builds both where the field is optional and where it is a
        // plain count (the release base).
        config.proof_worker.max_concurrent = 2usize.into();
        let explicit = build_node_worker(&config).unwrap().unwrap().concurrency();
        assert_eq!(
            explicit, 2,
            "an explicit maxConcurrent overrides the archive rule"
        );
    }

    #[test]
    fn worker_path_resolution_requires_an_existing_absolute_file() {
        let directory = tempfile::tempdir().unwrap();
        let worker = directory.path().join(WORKER_FILE_NAME);
        std::fs::write(&worker, b"#!/bin/sh\ncat >/dev/null\nexit 80\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let explicit = ProofWorkerConfig {
            path: worker.to_string_lossy().into_owned(),
            ..Default::default()
        };
        assert_eq!(
            resolve_worker_path(&explicit).unwrap(),
            (std::fs::canonicalize(&worker).unwrap(), false)
        );
        assert_eq!(
            resolve_worker_path(&ProofWorkerConfig::default()).unwrap(),
            (
                std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
                true
            ),
            "with nothing configured the node runs itself as the worker"
        );
        let missing = ProofWorkerConfig {
            path: directory
                .path()
                .join("absent")
                .to_string_lossy()
                .into_owned(),
            ..Default::default()
        };
        assert!(resolve_worker_path(&missing).is_err());
        let directory_path = ProofWorkerConfig {
            path: directory.path().to_string_lossy().into_owned(),
            ..Default::default()
        };
        assert!(resolve_worker_path(&directory_path).is_err());
        // A disabled suite never resolves or builds a worker.
        assert!(build(&ProofWorkerConfig {
            disabled: true,
            ..missing.clone()
        })
        .unwrap()
        .is_none());
        assert!(build(&missing).is_err());
        assert!(build(&ProofWorkerConfig {
            cpu_seconds: 0,
            ..explicit.clone()
        })
        .is_err());
        let built = build(&explicit).unwrap();
        assert!(built.is_some());
        let mut node_config = quil_config::Config::default();
        node_config.db.path = directory
            .path()
            .join("base-store")
            .to_string_lossy()
            .into_owned();
        node_config.db.worker_paths = vec![directory
            .path()
            .join("shard-store")
            .to_string_lossy()
            .into_owned()];
        node_config.proof_worker = explicit.clone();
        assert!(build_node_worker(&node_config).unwrap().is_some());
        assert!(PathBuf::from(&node_config.db.path)
            .join(".proof-worker-admission.lock")
            .is_file());
        assert!(!PathBuf::from(&node_config.db.worker_paths[0]).exists());
        #[cfg(not(target_os = "linux"))]
        assert!(build(&ProofWorkerConfig {
            address_space_bytes: 1 << 30,
            ..explicit.clone()
        })
        .unwrap()
        .is_some());
        std::fs::write(&worker, b"#!/bin/sh\ncat >/dev/null\nexit 82\n").unwrap();
        assert!(build(&explicit).is_err());
        // A stalled executable is reaped by the same bounded transport used
        // for proofs; it cannot hold startup indefinitely.
        std::fs::write(&worker, b"#!/bin/sh\nexec sleep 30\n").unwrap();
        let stalled = WorkerVerifier::new(
            std::fs::canonicalize(&worker).unwrap(),
            1,
            Duration::from_millis(50),
        )
        .unwrap();
        assert!(matches!(stalled.check_ready(), Err(
            quil_lattice_ct::confidential::relation::backend::worker_client::ClientError::Process(
                quil_lattice_ct::confidential::relation::backend::worker_process::WorkerError::Timeout))));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(build(&explicit).is_err());
        }
    }
}
