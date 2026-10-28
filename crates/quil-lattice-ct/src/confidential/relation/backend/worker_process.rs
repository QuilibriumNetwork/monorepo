//! Bounded public-request transport to a trusted single-process verifier.
//! This isolates worker exit/abort from the caller. It does not impose an OS
//! memory limit, authenticate the executable, or implement proof verification.
use std::{
    io::Write,
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

/// Exclusive local IPC limit, including the framing header. The transaction
/// itself retains the exclusive 1 MiB network limit.
pub const MAX_REQUEST_BYTES: usize =
    super::worker_request::MAX_TRANSACTION_BYTES + super::worker_request::HEADER_BYTES;
// Native libraries use exit(1) on allocation failure. Reserve explicit verdict
// codes so an ordinary exit, assertion or abort cannot count as proof rejection.
pub const VALID_EXIT: i32 = 80;
pub const INVALID_EXIT: i32 = 81;
/// Local startup handshake, disjoint from encoded proof requests. Bump this
/// identifier when the worker request ABI or supported operation suite changes.
pub const READINESS_REQUEST: &[u8] = b"QUIL-AMOUNT-WORKER-READY-QCT3-V1";

#[derive(Debug)]
pub enum WorkerError {
    InvalidLimits,
    Allocation,
    Io(std::io::Error),
    Timeout,
    UnexpectedExit(Option<i32>),
    WriterPanicked,
    /// The worker's resident memory exceeded the configured cap and it was
    /// killed. Local unavailability, like a timeout; never a proof verdict.
    MemoryLimit {
        resident_bytes: u64,
    },
    /// A resident-memory cap was requested where this build cannot measure it.
    MemoryLimitUnsupported,
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Reap on every error path. The configured worker must not spawn
        // descendants that inherit its request pipe.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Only the reserved verdict codes are accepted; every other exit is unavailable.
/// Only public requests belong here. `command` must identify a trusted worker,
/// never an executable or arguments selected by a network transaction.
/// The worker must read its complete request before reporting a verdict.
pub fn run_worker(
    command: Command,
    request: &[u8],
    timeout: Duration,
) -> Result<bool, WorkerError> {
    run_worker_capped(command, request, timeout, None)
}

/// Resident memory of another process, in bytes. Linux reads `/proc`; macOS
/// asks for the physical footprint, which also counts compressed pages the
/// process still owns. `None` when the process is gone or the OS refuses.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn resident_bytes(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        (page > 0).then(|| pages.saturating_mul(page as u64))
    }
    #[cfg(target_os = "macos")]
    unsafe {
        let mut info: libc::rusage_info_v2 = std::mem::zeroed();
        let status = libc::proc_pid_rusage(
            pid as libc::c_int,
            libc::RUSAGE_INFO_V2,
            &mut info as *mut _ as *mut libc::rusage_info_t,
        );
        (status == 0).then_some(info.ri_phys_footprint)
    }
}

/// CPU counts of a worker started from a thread pinned to fewer CPUs than
/// the process may use, passed once per process to [`set_cpu_report`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpawnCpus {
    /// CPUs the child may run on: the process's set, or the spawning
    /// thread's when widening to it failed.
    pub child: usize,
    /// CPUs the spawning thread is pinned to.
    pub spawning_thread: usize,
}

static CPU_REPORT: OnceLock<fn(SpawnCpus)> = OnceLock::new();

/// Install the reporter for [`SpawnCpus`]; the first call wins. It runs once
/// per process, at the first worker spawned from a narrower-pinned thread.
pub fn set_cpu_report(report: fn(SpawnCpus)) {
    let _ = CPU_REPORT.set(report);
}

/// Record this process's CPU set for the workers it starts. Call it at
/// startup, before any thread pins itself (the node pins each data worker
/// thread to one core); the first call wins. Without it, the first
/// [`crate::confidential::relation::backend::worker_client::WorkerVerifier`]
/// or spawn records its own thread's set.
pub fn remember_process_cpus() {
    #[cfg(target_os = "linux")]
    cpus::process();
}

#[cfg(target_os = "linux")]
mod cpus {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    };

    static PROCESS: OnceLock<Option<libc::cpu_set_t>> = OnceLock::new();
    static REPORTED: AtomicBool = AtomicBool::new(false);

    pub(super) fn process() -> Option<libc::cpu_set_t> {
        *PROCESS.get_or_init(current)
    }

    /// The calling thread's CPU set; `None` beyond `CPU_SETSIZE` CPUs.
    pub(super) fn current() -> Option<libc::cpu_set_t> {
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::cpu_set_t>();
        (unsafe { libc::sched_getaffinity(0, size, &mut set) } == 0).then_some(set)
    }

    /// Set the calling thread's CPU set; `false` when the kernel refuses.
    pub(super) fn set_current(set: &libc::cpu_set_t) -> bool {
        let size = std::mem::size_of::<libc::cpu_set_t>();
        unsafe { libc::sched_setaffinity(0, size, set) == 0 }
    }

    pub(super) fn count(set: &libc::cpu_set_t) -> usize {
        unsafe { libc::CPU_COUNT(set) as usize }
    }

    pub(super) fn equal(a: &libc::cpu_set_t, b: &libc::cpu_set_t) -> bool {
        unsafe { libc::CPU_EQUAL(a, b) }
    }

    pub(super) fn report_once(cpus: super::SpawnCpus) {
        if let Some(report) = super::CPU_REPORT.get() {
            if !REPORTED.swap(true, Ordering::AcqRel) {
                report(cpus);
            }
        }
    }
}

/// Start `command` on the process's CPU set rather than the calling thread's.
/// A child inherits its spawning thread's affinity, and the node pins each
/// data worker thread, and every thread it starts, to one core; a verifier
/// child would run all its native threads on that core. The thread widens
/// its own set for the spawn and restores it after; unlike a `pre_exec` hook
/// this keeps `posix_spawn`, so the node's address space is not forked.
fn spawn_with_process_cpus(command: &mut Command) -> std::io::Result<Child> {
    #[cfg(target_os = "linux")]
    if let (Some(process), Some(thread)) = (cpus::process(), cpus::current()) {
        if !cpus::equal(&process, &thread) {
            let widened = cpus::set_current(&process);
            let child_cpus = if widened { cpus::current() } else { None };
            let child = command.spawn();
            // Narrowing back to a subset of its own set does not fail; were
            // it refused, the thread would merely stay unpinned.
            if widened {
                cpus::set_current(&thread);
            }
            if child.is_ok() {
                cpus::report_once(SpawnCpus {
                    child: cpus::count(child_cpus.as_ref().unwrap_or(&thread)),
                    spawning_thread: cpus::count(&thread),
                });
            }
            return child;
        }
    }
    command.spawn()
}

/// [`run_worker`] with a resident-memory cap enforced by this (parent)
/// process: the worker is sampled every 50 ms and killed once it exceeds
/// `max_resident_bytes`. This is a portable policy, unlike `RLIMIT_AS`, but
/// it is sampled: a worker can overshoot by what it allocates in one interval.
/// The address-space limit stays the hard bound where Linux offers it.
pub fn run_worker_capped(
    mut command: Command,
    request: &[u8],
    timeout: Duration,
    max_resident_bytes: Option<u64>,
) -> Result<bool, WorkerError> {
    if max_resident_bytes == Some(0) {
        return Err(WorkerError::InvalidLimits);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    if max_resident_bytes.is_some() {
        return Err(WorkerError::MemoryLimitUnsupported);
    }
    if request.is_empty() || request.len() >= MAX_REQUEST_BYTES || timeout.is_zero() {
        return Err(WorkerError::InvalidLimits);
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(WorkerError::InvalidLimits)?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(request.len())
        .map_err(|_| WorkerError::Allocation)?;
    input.extend_from_slice(request);
    let child = spawn_with_process_cpus(
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .map_err(WorkerError::Io)?;
    let mut child = ChildGuard(child);
    let mut stdin = child.0.stdin.take().expect("piped worker stdin");
    // A non-reading worker must not block the deadline monitor on pipe writes.
    let writer = std::thread::Builder::new()
        .name("proof-worker-input".into())
        .spawn(move || stdin.write_all(&input))
        .map_err(WorkerError::Io)?;
    let mut next_sample = Instant::now();
    let outcome = loop {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(cap) = max_resident_bytes {
            if Instant::now() >= next_sample {
                next_sample = Instant::now() + Duration::from_millis(50);
                if let Some(resident_bytes) =
                    resident_bytes(child.0.id()).filter(|used| *used > cap)
                {
                    break Err(WorkerError::MemoryLimit { resident_bytes });
                }
            }
        }
        match child.0.try_wait() {
            Ok(Some(status)) => {
                break match status.code() {
                    Some(VALID_EXIT) => Ok(true),
                    Some(INVALID_EXIT) => Ok(false),
                    code => Err(WorkerError::UnexpectedExit(code)),
                }
            }
            Err(error) => break Err(WorkerError::Io(error)),
            Ok(None) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break Err(WorkerError::Timeout);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    };
    // Killing and reaping closes the read end before joining a blocked writer.
    drop(child);
    let written = writer.join().map_err(|_| WorkerError::WriterPanicked);
    let verdict = outcome?;
    written?.map_err(WorkerError::Io)?;
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    const CHILD: &str = "confidential::relation::backend::worker_process::tests::worker_fixture";

    fn worker(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", CHILD, "--ignored", "--nocapture"])
            .env("QUIL_PROCESS_TEST_MODE", mode);
        command
    }

    #[test]
    #[ignore = "subprocess fixture; invoked only by worker lifecycle tests"]
    fn worker_fixture() {
        use std::io::Read;
        let Ok(mode) = std::env::var("QUIL_PROCESS_TEST_MODE") else {
            return;
        };
        #[cfg(target_os = "linux")]
        if mode == "address_limit" {
            use super::super::worker_limits::apply_address_space_limit;
            let before = process_limits();
            assert!(apply_address_space_limit(0).is_err());
            assert!(apply_address_space_limit(u64::MAX).is_err());
            assert_eq!(process_limits(), before);
            apply_address_space_limit(1 << 30).unwrap();
            let limits = process_limits();
            assert!(limits[2].0 <= 1 << 30 && limits[2].1 <= 1 << 30);
            apply_address_space_limit(2 << 30).unwrap();
            assert_eq!(process_limits(), limits);
            unsafe {
                // Reserve virtual mappings only; do not consume a GiB of RAM.
                let small = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                assert_ne!(small, libc::MAP_FAILED);
                assert_eq!(libc::munmap(small, 4096), 0);
                let large = libc::mmap(
                    std::ptr::null_mut(),
                    1 << 30,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                assert_eq!(large, libc::MAP_FAILED);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ENOMEM)
                );
            }
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if mode == "limits" || mode == "cpu_limit" {
            use super::super::worker_limits::apply_to_current_worker;
            assert!(apply_to_current_worker(0).is_err());
            assert!(apply_to_current_worker(3601).is_err());
            apply_to_current_worker(1).unwrap();
            let limits = process_limits();
            assert!(limits[0].0 <= 1 && limits[0].1 <= 1);
            assert_eq!(limits[1], (0, 0));
            // A later request cannot raise the inherited hard/soft limit.
            apply_to_current_worker(30).unwrap();
            assert_eq!(process_limits(), limits);
            #[cfg(target_os = "linux")]
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
            if mode == "cpu_limit" {
                loop {
                    std::hint::black_box(17u64.wrapping_mul(31));
                }
            }
        }
        #[cfg(unix)]
        if mode == "orphan_parent" {
            // An intermediate "node" that launches a worker and dies abruptly,
            // without killing or reaping it.
            let mut command = worker("orphan_child");
            command
                .env(
                    "QUIL_PROCESS_TEST_PID_FILE",
                    std::env::var("QUIL_PROCESS_TEST_PID_FILE").unwrap(),
                )
                .env(
                    super::super::worker_limits::PARENT_PID_ENV,
                    std::process::id().to_string(),
                );
            let child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            std::mem::forget(child);
            std::thread::sleep(Duration::from_millis(300));
            unsafe { libc::_exit(0) };
        }
        #[cfg(unix)]
        if mode == "orphan_child" {
            super::super::worker_limits::exit_when_orphaned().unwrap();
            let path = std::env::var("QUIL_PROCESS_TEST_PID_FILE").unwrap();
            std::fs::write(&path, std::process::id().to_string()).unwrap();
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(7);
        }
        #[cfg(unix)]
        if mode == "named_parent" {
            super::super::worker_limits::exit_when_orphaned().unwrap();
        }
        if mode == "hungry" {
            // Touch every page so the memory is resident, then linger.
            let mut block = vec![0u8; 192 << 20];
            for byte in block.iter_mut().step_by(4096) {
                *byte = 1;
            }
            std::hint::black_box(&block);
            std::thread::sleep(Duration::from_secs(30));
        }
        if mode == "stall" {
            std::thread::sleep(Duration::from_secs(30));
        }
        let mut request = Vec::new();
        std::io::stdin().read_to_end(&mut request).unwrap();
        assert_eq!(request, b"public test request");
        std::process::exit(match mode.as_str() {
            "valid" | "limits" | "address_limit" | "named_parent" => VALID_EXIT,
            "invalid" => INVALID_EXIT,
            "allocation_exit" => 1,
            "ordinary_exit" => 0,
            _ => 7,
        });
    }

    #[test]
    fn worker_process_distinguishes_verdicts_and_failures() {
        let request = b"public test request";
        let limit = Duration::from_secs(5);
        assert!(run_worker(worker("valid"), request, limit).unwrap());
        assert!(!run_worker(worker("invalid"), request, limit).unwrap());
        assert!(matches!(
            run_worker(worker("failure"), request, limit),
            Err(WorkerError::UnexpectedExit(Some(7)))
        ));
        for mode in ["allocation_exit", "ordinary_exit"] {
            assert!(matches!(
                run_worker(worker(mode), request, limit),
                Err(WorkerError::UnexpectedExit(_))
            ));
        }
        assert!(matches!(
            run_worker(worker("valid"), &[], limit),
            Err(WorkerError::InvalidLimits)
        ));
        assert!(matches!(
            run_worker(worker("valid"), &vec![0; MAX_REQUEST_BYTES], limit),
            Err(WorkerError::InvalidLimits)
        ));
        assert!(matches!(
            run_worker(worker("valid"), request, Duration::ZERO),
            Err(WorkerError::InvalidLimits)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn a_worker_keeps_only_the_parent_its_launcher_named() {
        use super::super::worker_limits::{ORPHANED_EXIT, PARENT_PID_ENV};
        let request = b"public test request";
        let limit = Duration::from_secs(5);
        // The launcher names itself, as a node running as PID 1 must.
        let mut named = worker("named_parent");
        named.env(PARENT_PID_ENV, std::process::id().to_string());
        assert!(run_worker(named, request, limit).unwrap());
        // A worker whose actual parent is not the named one stops at once.
        let mut other = worker("named_parent");
        other.env(PARENT_PID_ENV, "1");
        assert!(matches!(
            run_worker(other, request, limit),
            Err(WorkerError::UnexpectedExit(Some(ORPHANED_EXIT)))
        ));
    }

    #[test]
    fn worker_process_times_out_even_when_request_pipe_is_full() {
        let start = Instant::now();
        assert!(matches!(
            run_worker(
                worker("stall"),
                &vec![0; MAX_REQUEST_BYTES - 1],
                Duration::from_millis(100)
            ),
            Err(WorkerError::Timeout)
        ));
        assert!(start.elapsed() < Duration::from_secs(5));
        // A killed worker does not leave this process or the runner unusable.
        assert!(run_worker(
            worker("valid"),
            b"public test request",
            Duration::from_secs(5)
        )
        .unwrap());
    }

    // Adopt the deliberately orphaned fixture instead of relying on PID 1
    // to reap it. In containers, kill(pid, 0) also succeeds for dead zombies.
    #[cfg(target_os = "linux")]
    struct OrphanReaper {
        previous: libc::c_int,
        worker: Option<libc::pid_t>,
    }

    #[cfg(target_os = "linux")]
    impl OrphanReaper {
        fn new() -> Self {
            let mut previous: libc::c_int = 0;
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_GET_CHILD_SUBREAPER,
                        &mut previous as *mut libc::c_int,
                    )
                },
                0
            );
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
            Self {
                previous,
                worker: None,
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for OrphanReaper {
        fn drop(&mut self) {
            if let Some(pid) = self.worker {
                let mut status = 0;
                if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == 0 {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                        libc::waitpid(pid, &mut status, 0);
                    }
                }
            }
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, self.previous) },
                0
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn a_worker_does_not_outlive_a_parent_that_died_without_reaping_it() {
        #[cfg(target_os = "linux")]
        let mut reaper = OrphanReaper::new();
        let file = std::env::temp_dir().join(format!(
            "quil-orphan-{}-{:?}",
            std::process::id(),
            Instant::now()
        ));
        let mut parent = worker("orphan_parent");
        parent.env("QUIL_PROCESS_TEST_PID_FILE", &file);
        let status = parent
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "the intermediate parent exits on its own");
        let deadline = Instant::now() + Duration::from_secs(10);
        let pid: i32 = loop {
            if let Ok(text) = std::fs::read_to_string(&file) {
                if let Ok(pid) = text.parse() {
                    break pid;
                }
            }
            assert!(Instant::now() < deadline, "worker never started");
            std::thread::sleep(Duration::from_millis(20));
        };
        let _ = std::fs::remove_file(&file);
        // The worker would otherwise sleep for a minute. Reaping also lets
        // us distinguish the orphan policy from an ordinary fixture exit.
        #[cfg(target_os = "linux")]
        {
            reaper.worker = Some(pid);
            loop {
                let mut status = 0;
                let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if result == pid {
                    reaper.worker = None;
                    assert!(
                        (libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL)
                            || (libc::WIFEXITED(status)
                                && libc::WEXITSTATUS(status)
                                    == super::super::worker_limits::ORPHANED_EXIT),
                        "worker must exit through the orphan policy, got status {status}",
                    );
                    break;
                }
                assert_eq!(result, 0, "orphaned fixture must be adopted by the test");
                assert!(
                    Instant::now() < deadline,
                    "orphaned worker {pid} is still running"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        #[cfg(not(target_os = "linux"))]
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                Instant::now() < deadline,
                "orphaned worker {pid} is still running"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn a_worker_over_its_resident_memory_cap_is_killed_as_unavailable() {
        let request = b"public test request";
        let start = Instant::now();
        match run_worker_capped(
            worker("hungry"),
            request,
            Duration::from_secs(20),
            Some(96 << 20),
        ) {
            Err(WorkerError::MemoryLimit { resident_bytes }) => assert!(resident_bytes > 96 << 20),
            other => panic!("expected a memory-limit kill, got {other:?}"),
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "killed long before the worker's own exit"
        );
        // An ordinary worker fits the same cap, and the runner stays usable.
        assert!(run_worker_capped(
            worker("valid"),
            request,
            Duration::from_secs(5),
            Some(96 << 20)
        )
        .unwrap());
        assert!(matches!(
            run_worker_capped(worker("valid"), request, Duration::from_secs(5), Some(0)),
            Err(WorkerError::InvalidLimits)
        ));
        assert!(resident_bytes(std::process::id()).is_some_and(|used| used > 0));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn process_limits() -> Vec<(libc::rlim_t, libc::rlim_t)> {
        [libc::RLIMIT_CPU, libc::RLIMIT_CORE, libc::RLIMIT_AS]
            .into_iter()
            .map(|resource| {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                assert_eq!(unsafe { libc::getrlimit(resource, &mut limit) }, 0);
                (limit.rlim_cur, limit.rlim_max)
            })
            .collect()
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn worker_process_enforces_cpu_limit_without_changing_parent() {
        let before = process_limits();
        assert!(run_worker(
            worker("limits"),
            b"public test request",
            Duration::from_secs(5)
        )
        .unwrap());
        assert!(matches!(
            run_worker(
                worker("cpu_limit"),
                b"public test request",
                Duration::from_secs(10)
            ),
            Err(WorkerError::UnexpectedExit(None))
        ));
        assert_eq!(process_limits(), before);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn worker_process_enforces_address_limit_without_changing_parent() {
        let before = process_limits();
        assert!(run_worker(
            worker("address_limit"),
            b"public test request",
            Duration::from_secs(5)
        )
        .unwrap());
        assert_eq!(process_limits(), before);
    }

    /// The node pins each data worker thread to one core. A verifier child
    /// it starts must still get the process's CPUs, not that core.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_worker_started_from_a_pinned_thread_gets_the_process_cpus() {
        use std::sync::Mutex;
        static REPORTED: Mutex<Option<SpawnCpus>> = Mutex::new(None);
        fn record(cpus: SpawnCpus) {
            *REPORTED.lock().unwrap() = Some(cpus);
        }
        fn listed(list: &str) -> Vec<usize> {
            list.trim()
                .split(',')
                .filter(|range| !range.is_empty())
                .flat_map(|range| {
                    let (low, high) = range.split_once('-').unwrap_or((range, range));
                    low.parse::<usize>().unwrap()..=high.parse::<usize>().unwrap()
                })
                .collect()
        }
        // As the node does at startup, before its workers pin themselves.
        remember_process_cpus();
        set_cpu_report(record);
        let process = super::cpus::process().expect("process CPU set");
        let expected: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
            .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &process) })
            .collect();
        if expected.len() < 2 {
            eprintln!("skipped: this process may use only one CPU");
            return;
        }
        let pinned = *expected.last().unwrap();
        let out = std::env::temp_dir().join(format!("quil-worker-cpus-{}", std::process::id()));
        let path = out.clone();
        let (verdict, thread_after) = std::thread::spawn(move || {
            let mut one: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            unsafe { libc::CPU_SET(pinned, &mut one) };
            assert!(super::cpus::set_current(&one), "pin the test thread");
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                "cat >/dev/null; grep Cpus_allowed_list /proc/self/status >\"$1\"; exit 80",
                "sh",
            ]);
            command.arg(&path);
            let verdict = run_worker(command, b"public test request", Duration::from_secs(10));
            (verdict, super::cpus::current())
        })
        .join()
        .unwrap();
        let status = std::fs::read_to_string(&out);
        let _ = std::fs::remove_file(&out);
        assert!(matches!(verdict, Ok(true)), "{verdict:?}");
        let child = listed(
            status
                .unwrap()
                .strip_prefix("Cpus_allowed_list:")
                .expect("Cpus_allowed_list line"),
        );
        assert_eq!(
            child, expected,
            "the child ran on CPUs {child:?}, its spawning thread's pin {pinned}, \
             instead of the process's"
        );
        let thread_after = thread_after.expect("thread CPU set");
        assert_eq!(
            super::cpus::count(&thread_after),
            1,
            "spawning thread pin restored"
        );
        assert!(unsafe { libc::CPU_ISSET(pinned, &thread_after) });
        assert_eq!(
            *REPORTED.lock().unwrap(),
            Some(SpawnCpus {
                child: expected.len(),
                spawning_thread: 1
            })
        );
    }
}
