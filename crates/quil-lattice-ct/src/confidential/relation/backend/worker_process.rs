//! Bounded public-request transport to a trusted single-process verifier.
//! This isolates worker exit/abort from the caller. It does not impose an OS
//! memory limit, authenticate the executable, or implement proof verification.
use std::{
    io::Write,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

/// Exclusive local IPC limit, including the framing header. The transaction
/// itself retains the exclusive 1 MiB network limit.
pub const MAX_REQUEST_BYTES: usize = super::worker_request::MAX_TRANSACTION_BYTES
    + super::worker_request::HEADER_BYTES;
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
    MemoryLimit { resident_bytes: u64 },
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
        let status = libc::proc_pid_rusage(pid as libc::c_int, libc::RUSAGE_INFO_V2,
            &mut info as *mut _ as *mut libc::rusage_info_t);
        (status == 0).then_some(info.ri_phys_footprint)
    }
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
    let deadline = Instant::now().checked_add(timeout).ok_or(WorkerError::InvalidLimits)?;
    let mut input = Vec::new();
    input.try_reserve_exact(request.len()).map_err(|_| WorkerError::Allocation)?;
    input.extend_from_slice(request);
    let child = command.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(WorkerError::Io)?;
    let mut child = ChildGuard(child);
    let mut stdin = child.0.stdin.take().expect("piped worker stdin");
    // A non-reading worker must not block the deadline monitor on pipe writes.
    let writer = std::thread::Builder::new().name("proof-worker-input".into())
        .spawn(move || stdin.write_all(&input)).map_err(WorkerError::Io)?;
    let mut next_sample = Instant::now();
    let outcome = loop {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(cap) = max_resident_bytes {
            if Instant::now() >= next_sample {
                next_sample = Instant::now() + Duration::from_millis(50);
                if let Some(resident_bytes) = resident_bytes(child.0.id()).filter(|used| *used > cap) {
                    break Err(WorkerError::MemoryLimit { resident_bytes });
                }
            }
        }
        match child.0.try_wait() {
            Ok(Some(status)) => break match status.code() {
                Some(VALID_EXIT) => Ok(true),
                Some(INVALID_EXIT) => Ok(false),
                code => Err(WorkerError::UnexpectedExit(code)),
            },
            Err(error) => break Err(WorkerError::Io(error)),
            Ok(None) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { break Err(WorkerError::Timeout); }
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
        command.args(["--exact", CHILD, "--ignored", "--nocapture"])
            .env("QUIL_PROCESS_TEST_MODE", mode);
        command
    }

    #[test]
    #[ignore = "subprocess fixture; invoked only by worker lifecycle tests"]
    fn worker_fixture() {
        use std::io::Read;
        let Ok(mode) = std::env::var("QUIL_PROCESS_TEST_MODE") else { return; };
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
                let small = libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
                assert_ne!(small, libc::MAP_FAILED);
                assert_eq!(libc::munmap(small, 4096), 0);
                let large = libc::mmap(std::ptr::null_mut(), 1 << 30, libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
                assert_eq!(large, libc::MAP_FAILED);
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOMEM));
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
                loop { std::hint::black_box(17u64.wrapping_mul(31)); }
            }
        }
        #[cfg(unix)]
        if mode == "orphan_parent" {
            // An intermediate "node" that launches a worker and dies abruptly,
            // without killing or reaping it.
            let mut command = worker("orphan_child");
            command.env("QUIL_PROCESS_TEST_PID_FILE", std::env::var("QUIL_PROCESS_TEST_PID_FILE").unwrap());
            let child = command.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
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
        if mode == "hungry" {
            // Touch every page so the memory is resident, then linger.
            let mut block = vec![0u8; 192 << 20];
            for byte in block.iter_mut().step_by(4096) { *byte = 1; }
            std::hint::black_box(&block);
            std::thread::sleep(Duration::from_secs(30));
        }
        if mode == "stall" { std::thread::sleep(Duration::from_secs(30)); }
        let mut request = Vec::new();
        std::io::stdin().read_to_end(&mut request).unwrap();
        assert_eq!(request, b"public test request");
        std::process::exit(match mode.as_str() {
            "valid" | "limits" | "address_limit" => VALID_EXIT, "invalid" => INVALID_EXIT,
            "allocation_exit" => 1, "ordinary_exit" => 0, _ => 7,
        });
    }

    #[test]
    fn worker_process_distinguishes_verdicts_and_failures() {
        let request = b"public test request";
        let limit = Duration::from_secs(5);
        assert!(run_worker(worker("valid"), request, limit).unwrap());
        assert!(!run_worker(worker("invalid"), request, limit).unwrap());
        assert!(matches!(run_worker(worker("failure"), request, limit),
            Err(WorkerError::UnexpectedExit(Some(7)))));
        for mode in ["allocation_exit", "ordinary_exit"] {
            assert!(matches!(run_worker(worker(mode), request, limit), Err(WorkerError::UnexpectedExit(_))));
        }
        assert!(matches!(run_worker(worker("valid"), &[], limit), Err(WorkerError::InvalidLimits)));
        assert!(matches!(run_worker(worker("valid"), &vec![0; MAX_REQUEST_BYTES], limit), Err(WorkerError::InvalidLimits)));
        assert!(matches!(run_worker(worker("valid"), request, Duration::ZERO), Err(WorkerError::InvalidLimits)));
    }

    #[test]
    fn worker_process_times_out_even_when_request_pipe_is_full() {
        let start = Instant::now();
        assert!(matches!(run_worker(worker("stall"), &vec![0; MAX_REQUEST_BYTES - 1],
            Duration::from_millis(100)), Err(WorkerError::Timeout)));
        assert!(start.elapsed() < Duration::from_secs(5));
        // A killed worker does not leave this process or the runner unusable.
        assert!(run_worker(worker("valid"), b"public test request", Duration::from_secs(5)).unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn a_worker_does_not_outlive_a_parent_that_died_without_reaping_it() {
        let file = std::env::temp_dir().join(format!("quil-orphan-{}-{:?}", std::process::id(), Instant::now()));
        let mut parent = worker("orphan_parent");
        parent.env("QUIL_PROCESS_TEST_PID_FILE", &file);
        let status = parent.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert!(status.success(), "the intermediate parent exits on its own");
        let deadline = Instant::now() + Duration::from_secs(10);
        let pid: i32 = loop {
            if let Ok(text) = std::fs::read_to_string(&file) {
                if let Ok(pid) = text.parse() { break pid; }
            }
            assert!(Instant::now() < deadline, "worker never started");
            std::thread::sleep(Duration::from_millis(20));
        };
        let _ = std::fs::remove_file(&file);
        // The worker would otherwise sleep for a minute.
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(Instant::now() < deadline, "orphaned worker {pid} is still running");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn a_worker_over_its_resident_memory_cap_is_killed_as_unavailable() {
        let request = b"public test request";
        let start = Instant::now();
        match run_worker_capped(worker("hungry"), request, Duration::from_secs(20), Some(96 << 20)) {
            Err(WorkerError::MemoryLimit { resident_bytes }) => assert!(resident_bytes > 96 << 20),
            other => panic!("expected a memory-limit kill, got {other:?}"),
        }
        assert!(start.elapsed() < Duration::from_secs(15), "killed long before the worker's own exit");
        // An ordinary worker fits the same cap, and the runner stays usable.
        assert!(run_worker_capped(worker("valid"), request, Duration::from_secs(5), Some(96 << 20)).unwrap());
        assert!(matches!(run_worker_capped(worker("valid"), request, Duration::from_secs(5), Some(0)),
            Err(WorkerError::InvalidLimits)));
        assert!(resident_bytes(std::process::id()).is_some_and(|used| used > 0));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn process_limits() -> Vec<(libc::rlim_t, libc::rlim_t)> {
        [libc::RLIMIT_CPU, libc::RLIMIT_CORE, libc::RLIMIT_AS].into_iter().map(|resource| {
            let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            assert_eq!(unsafe { libc::getrlimit(resource, &mut limit) }, 0);
            (limit.rlim_cur, limit.rlim_max)
        }).collect()
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn worker_process_enforces_cpu_limit_without_changing_parent() {
        let before = process_limits();
        assert!(run_worker(worker("limits"), b"public test request", Duration::from_secs(5)).unwrap());
        assert!(matches!(run_worker(worker("cpu_limit"), b"public test request", Duration::from_secs(10)),
            Err(WorkerError::UnexpectedExit(None))));
        assert_eq!(process_limits(), before);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn worker_process_enforces_address_limit_without_changing_parent() {
        let before = process_limits();
        assert!(run_worker(worker("address_limit"), b"public test request", Duration::from_secs(5)).unwrap());
        assert_eq!(process_limits(), before);
    }
}
