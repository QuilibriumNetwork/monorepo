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

/// Verifier slots of a node that leaves `proofWorker.maxConcurrent` unset and
/// cannot count its CPUs, the fewest a node sizes itself to, and the slots a
/// regular node budgets a frame's verification by.
const DEFAULT_MAX_CONCURRENT: usize = 2;
/// Most verifier slots an archive sizes itself to.
const ARCHIVE_MAX_CONCURRENT_CAP: usize = 8;
/// Most verifier slots a regular node sizes itself to, 15 verifying at once
/// beside the slot left for frames: 510 batch shields of about 100 s each in
/// 50 min need 17 on a node serving every shard (2026-11-02).
const REGULAR_MAX_CONCURRENT_CAP: usize = 16;
/// Available memory an archive sets aside per verifier child when it sizes
/// its slots: the largest resident size recorded for one depth-32 child
/// (2.73 GB, see `proofWorker.maxResidentBytes`) plus margin, so busy slots
/// fit the memory they were sized to.
const ARCHIVE_CHILD_MEMORY_BYTES: u64 = 3 << 30;
/// Available memory a regular node sets aside per verifier child when it
/// sizes its slots: as much as an archive, and that much again for its own
/// growth, since it reads this at startup, before its stores load (one node's
/// process grew to 16.5 GB resident of 31 GB, 2026-11-02).
const REGULAR_CHILD_MEMORY_BYTES: u64 = 6 << 30;

/// Where a node's verifier slot count came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotSource {
    /// `proofWorker.maxConcurrent`.
    Configured,
    /// [`DEFAULT_MAX_CONCURRENT`]: the CPU count is unknown.
    Default,
    /// The node's CPUs and available memory.
    Machine,
}

impl SlotSource {
    fn as_str(self) -> &'static str {
        match self {
            SlotSource::Configured => "proofWorker.maxConcurrent",
            SlotSource::Default => "default",
            SlotSource::Machine => {
                "CPUs / nativeThreads, bounded by memory; proofWorker.maxConcurrent overrides"
            }
        }
    }
}

/// A node's verifier slot count and the inputs it was chosen from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifierSlots {
    slots: usize,
    source: SlotSource,
    /// Slots a frame's verification budget counts
    /// ([`WorkerVerifier::with_budget_slots`]).
    frame_budget_slots: usize,
    /// CPUs the node may use, when the machine was asked.
    cpus: Option<usize>,
    /// Available memory in bytes, when the machine was asked.
    available_memory: Option<u64>,
    /// `cpus / nativeThreads`.
    cpu_slots: Option<usize>,
    /// Available memory over what one child is set aside.
    memory_slots: Option<usize>,
}

/// Verifier slots for a node. An explicit `maxConcurrent` always wins. Unset,
/// a node takes `cpus / nativeThreads`, at most its available memory over what
/// it sets aside per child, from [`DEFAULT_MAX_CONCURRENT`] up to its cap. An
/// archive verifies the confidential operations of each GLOBAL frame before
/// publishing it, and two slots fell behind their arrival (2026-10-30). A
/// regular node cannot apply a frame carrying a batch shield until its own
/// verdict arrives: with two slots it verified one at a time, about 6 of 100 s
/// per 600 s across all its shards, and shards missed quorum for over an hour
/// (2026-11-02). Each child averages 2.7 CPUs at the default four threads
/// (173 CPU-s in 65 s), so the queue's `slots - 1` take at most 2/3 of the CPUs
/// and the workers keep the rest. Unknown CPUs leave the default; unknown
/// memory leaves the CPU bound.
fn verifier_slots(
    config: &ProofWorkerConfig,
    archive: bool,
    cpus: Option<usize>,
    available_memory: Option<u64>,
) -> VerifierSlots {
    let fixed = |slots, source| VerifierSlots {
        slots,
        source,
        frame_budget_slots: slots,
        cpus,
        available_memory,
        cpu_slots: None,
        memory_slots: None,
    };
    if let Some(slots) = config.max_concurrent {
        return fixed(slots, SlotSource::Configured);
    }
    let (child_memory, cap) = if archive {
        (child_memory_bytes(true), ARCHIVE_MAX_CONCURRENT_CAP)
    } else {
        (child_memory_bytes(false), REGULAR_MAX_CONCURRENT_CAP)
    };
    let cpu_slots = cpus.map(|cpus| cpus / usize::from(config.native_threads.max(1)));
    let memory_slots =
        available_memory.map(|bytes| usize::try_from(bytes / child_memory).unwrap_or(usize::MAX));
    let Some(by_cpu) = cpu_slots else {
        return VerifierSlots {
            memory_slots,
            ..fixed(DEFAULT_MAX_CONCURRENT, SlotSource::Default)
        };
    };
    let slots = by_cpu
        .min(memory_slots.unwrap_or(usize::MAX))
        .clamp(DEFAULT_MAX_CONCURRENT, cap);
    VerifierSlots {
        slots,
        source: SlotSource::Machine,
        // A proposal's budget is what its members verify inline: a leader's
        // CPUs must not raise it for members with fewer.
        frame_budget_slots: if archive {
            slots
        } else {
            DEFAULT_MAX_CONCURRENT
        },
        cpus,
        available_memory,
        cpu_slots,
        memory_slots,
    }
}

/// Available memory set aside per verifier child when a node sizes its slots.
fn child_memory_bytes(archive: bool) -> u64 {
    if archive {
        ARCHIVE_CHILD_MEMORY_BYTES
    } else {
        REGULAR_CHILD_MEMORY_BYTES
    }
}

/// The verifier slots `available_memory` admits under the rule an unset
/// `maxConcurrent` follows ([`verifier_slots`]: one per child's memory, never
/// under [`DEFAULT_MAX_CONCURRENT`]), when an explicit `configured` count
/// exceeds them; `None` when it fits or memory is unknown. A node keeps the
/// configured count: this only names the risk (2026-11-03: regular nodes
/// configured with 16, 12 and 6 slots and about 40 GB free, at about 3 GB a
/// busy child).
fn configured_over_memory(
    configured: usize,
    archive: bool,
    available_memory: Option<u64>,
) -> Option<usize> {
    let admitted = usize::try_from(available_memory? / child_memory_bytes(archive))
        .unwrap_or(usize::MAX)
        .max(DEFAULT_MAX_CONCURRENT);
    (configured > admitted).then_some(admitted)
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

/// Memory verifier children may take: what the host has available, at most
/// this process's cgroup limit, read like the store's memory budget. Cgroup
/// v2, then v1; "max" (no limit) does not parse.
fn available_for_verifiers() -> Option<u64> {
    let limit = [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ]
    .iter()
    .find_map(|path| {
        std::fs::read_to_string(path)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    });
    crate::mem_stats::host_memory()
        .map(|memory| limit.map_or(memory.available_bytes, |l| l.min(memory.available_bytes)))
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
             (the node runs itself as the worker by default), or set proofWorker.disabled: true \
             (the node then stops at the first frame carrying a confidential token operation)",
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
        tracing::warn!("token suite disabled by proofWorker.disabled; this node cannot verify confidential token operations and stops at the first frame that carries one");
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
        .and_then(|w| w.with_budget_slots(slots.frame_budget_slots))
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
        frame_budget_slots = slots.frame_budget_slots,
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
/// A node without `maxConcurrent` sizes its slots to this machine
/// ([`verifier_slots`]). A process takes at most its own count of the shared
/// slot files, so processes that chose different counts together run at most
/// the largest.
pub(crate) fn build_node_worker_as(
    config: &quil_config::Config,
    archive: bool,
) -> anyhow::Result<Option<WorkerVerifier>> {
    let proof = &config.proof_worker;
    if let (Some(configured), false) = (proof.max_concurrent, proof.disabled) {
        let available = available_for_verifiers();
        if let Some(admitted) = configured_over_memory(configured, archive, available) {
            tracing::warn!(
                configured,
                memory_admits = admitted,
                available_memory_bytes = available,
                child_memory_bytes = child_memory_bytes(archive),
                scope = "this node",
                action = "lower proofWorker.maxConcurrent to at most memory_admits, or unset it so the \
                          node sizes its slots from its CPUs and memory; the configured value is kept",
                "proofWorker.maxConcurrent exceeds what available memory admits: verifier children \
                 busy at once may exhaust this node's memory"
            );
        }
    }
    let slots = if proof.max_concurrent.is_none() && !proof.disabled {
        verifier_slots(proof, archive, process_cpus(), available_for_verifiers())
    } else {
        verifier_slots(proof, archive, None, None)
    };
    let Some(worker) = build_worker(proof, slots)? else {
        return Ok(None);
    };
    #[cfg(target_os = "macos")]
    let worker = worker.with_memory_admission(std::sync::Arc::new(|deadline| {
        // The measured depth-32 child peak is 2.73 GB; reserve 3 GiB from
        // the same scheduler and host ledger as storage creation. Keep the
        // permit through process exit, including failures and timeouts.
        quil_engine::storage_jobs::reserve_verifier_until(3 << 30, deadline)
            .map(|permit| Box::new(permit) as _)
    }));
    let base = if config.db.path.is_empty() {
        PathBuf::from(".config/store")
    } else {
        PathBuf::from(&config.db.path)
    };
    std::fs::create_dir_all(&base)?;
    quil_engine::admission_verify::use_worker_slots(worker.concurrency());
    let lock = std::fs::canonicalize(base)?.join(".proof-worker-admission.lock");
    worker
        .with_shared_admission(lock.clone())
        .map(Some)
        .map_err(|e| anyhow::anyhow!("proof worker admission file {}: {e:?}", lock.display()))
}

/// Install the network policy and a clone of the shared worker on a manager.
/// Without a worker (suite disabled) the manager is returned unchanged and
/// fails, rather than skips, every frame carrying a confidential token
/// operation: it cannot tell whether the operation is valid.
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
#[path = "proof_worker_capacity_tests.rs"]
mod capacity_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// A regular node's worker for `config`.
    fn build(config: &ProofWorkerConfig) -> anyhow::Result<Option<WorkerVerifier>> {
        build_worker(config, verifier_slots(config, false, None, None))
    }

    #[test]
    fn an_unset_max_concurrent_follows_an_archives_machine() {
        const GIB: u64 = 1 << 30;
        let unset = ProofWorkerConfig::default();
        let slots = |config: &ProofWorkerConfig, archive, cpus, memory| {
            verifier_slots(config, archive, cpus, memory).slots
        };
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

    /// An explicit `maxConcurrent` above what available memory admits under
    /// the auto-size rule is named, never changed: a regular node admits one
    /// slot per 6 GiB, an archive one per 3 GiB, never under two; unknown
    /// memory says nothing.
    #[test]
    fn a_configured_count_over_available_memory_is_named() {
        const GIB: u64 = 1 << 30;
        // The operator report: 16, 12 and 6 slots with about 40 GB available.
        let forty = Some(40 * GIB);
        assert_eq!(configured_over_memory(16, false, forty), Some(6));
        assert_eq!(configured_over_memory(12, false, forty), Some(6));
        assert_eq!(configured_over_memory(7, false, forty), Some(6));
        assert_eq!(
            configured_over_memory(6, false, forty),
            None,
            "at the bound"
        );
        assert_eq!(configured_over_memory(1, false, forty), None);
        // An archive sets aside half as much per child.
        assert_eq!(configured_over_memory(16, true, forty), Some(13));
        assert_eq!(configured_over_memory(13, true, forty), None);
        // Never under the default, as the auto size.
        assert_eq!(configured_over_memory(2, false, Some(GIB)), None);
        assert_eq!(configured_over_memory(3, false, Some(GIB)), Some(2));
        // Unknown memory says nothing.
        assert_eq!(configured_over_memory(64, false, None), None);
        // Agrees with the auto size wherever memory is its bound.
        let unset = ProofWorkerConfig::default();
        for gib in [1u64, 12, 18, 40, 95] {
            for archive in [false, true] {
                let auto = verifier_slots(&unset, archive, Some(1024), Some(gib * GIB)).slots;
                assert_eq!(
                    configured_over_memory(auto, archive, Some(gib * GIB)),
                    None,
                    "{gib} GiB"
                );
                if auto < ARCHIVE_MAX_CONCURRENT_CAP.min(REGULAR_MAX_CONCURRENT_CAP) {
                    assert_eq!(
                        configured_over_memory(auto + 1, archive, Some(gib * GIB)),
                        Some(auto),
                        "{gib} GiB, archive {archive}"
                    );
                }
            }
        }
    }

    /// Every event's level and fields, from the thread that installed it.
    #[derive(Clone, Default)]
    struct Recorder(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl tracing::Subscriber for Recorder {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Fields(String);
            impl tracing::field::Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!(" {}={:?}", field.name(), value));
                }
            }
            let mut fields = Fields(event.metadata().level().to_string());
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// A node started with more verifier slots than its memory admits warns
    /// once and keeps them; one within its memory does not warn.
    #[test]
    fn a_node_configured_over_its_memory_warns_and_keeps_its_slots() {
        const GIB: u64 = 1 << 30;
        let Some(available) = available_for_verifiers() else {
            eprintln!("skipped: available memory unknown");
            return;
        };
        if !(2 * REGULAR_CHILD_MEMORY_BYTES..64 * REGULAR_CHILD_MEMORY_BYTES).contains(&available) {
            eprintln!("skipped: {} GiB available", available / GIB);
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
        let mut warned = |configured: usize| {
            config.proof_worker = ProofWorkerConfig {
                path: worker.to_string_lossy().into_owned(),
                max_concurrent: Some(configured),
                ..Default::default()
            };
            let logs = Recorder::default();
            let slots = {
                let _logging = tracing::subscriber::set_default(logs.clone());
                build_node_worker_as(&config, false)
                    .unwrap()
                    .unwrap()
                    .concurrency()
            };
            let lines: Vec<String> = logs
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|line| line.contains("exceeds what available memory admits"))
                .cloned()
                .collect();
            (slots, lines)
        };
        let (slots, lines) = warned(64);
        assert_eq!(slots, 64, "the configured count was not kept");
        assert_eq!(
            lines.len(),
            1,
            "64 slots on {} GiB: {lines:?}",
            available / GIB
        );
        assert!(
            lines[0].starts_with("WARN") && lines[0].contains("configured=64"),
            "{}",
            lines[0]
        );
        let (slots, lines) = warned(2);
        assert_eq!((slots, lines.len()), (2, 0), "two slots warned: {lines:?}");
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
        let regular = build_node_worker(&config).unwrap().unwrap();
        assert!(
            regular.concurrency() >= 2 && regular.concurrency() <= cpus.max(2),
            "a regular node on {cpus} CPUs admitted {} verifications at once",
            regular.concurrency()
        );
        assert_eq!(
            regular.budget_concurrency(),
            2,
            "a regular node's CPUs raised what its proposals make members verify inline"
        );
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
