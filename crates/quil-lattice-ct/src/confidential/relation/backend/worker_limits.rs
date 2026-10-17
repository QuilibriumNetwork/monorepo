//! Process-wide limits for a freshly executed, single-request worker only.
//! Never apply these to the node or a shared test process. This is not a
//! workspace memory cap; the caller still enforces a wall-clock deadline.
use std::io;

/// Cap Linux virtual address space before reading the request. This bounds
/// mappings, not submission accounting, and is not a portable RSS policy.
/// Only call inside the freshly executed worker, never the node process.
pub fn apply_address_space_limit(bytes: u64) -> io::Result<()> {
    if bytes == 0 || bytes >= i64::MAX as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid worker address-space limit"));
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let mut old = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_AS, &mut old) != 0 {
            return Err(io::Error::last_os_error());
        }
        let cap = (bytes as libc::rlim_t).min(old.rlim_cur).min(old.rlim_max);
        let limit = libc::rlimit { rlim_cur: cap, rlim_max: cap };
        if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    Err(io::Error::new(io::ErrorKind::Unsupported, "worker address-space cap is only supported on Linux"))
}

pub fn apply_to_current_worker(cpu_seconds: u64) -> io::Result<()> {
    if !(1..=3600).contains(&cpu_seconds) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "worker CPU seconds must be 1..=3600"));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Do not raise an inherited limit, including an already stricter soft
        // limit. Set both limits so native code cannot extend its CPU budget.
        unsafe {
            let mut old = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::getrlimit(libc::RLIMIT_CPU, &mut old) != 0 { return Err(io::Error::last_os_error()); }
            let cap = (cpu_seconds as libc::rlim_t).min(old.rlim_cur).min(old.rlim_max);
            let cpu = libc::rlimit { rlim_cur: cap, rlim_max: cap };
            let core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
                || libc::setrlimit(libc::RLIMIT_CPU, &cpu) != 0 {
                return Err(io::Error::last_os_error());
            }
            // Linux can pipe a core dump to a collector despite RLIMIT_CORE=0.
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Err(io::Error::new(io::ErrorKind::Unsupported, "worker resource limits unsupported on this OS"))
}

/// Exit code of a worker that stopped because its parent died. Disjoint from
/// the verdict codes, so it can never read as a proof verdict.
pub const ORPHANED_EXIT: i32 = 83;

/// Stop this worker when the node that launched it dies. The parent kills and
/// reaps its worker on every path it still controls; an abrupt parent death
/// (SIGKILL, OOM kill, crash) reaches neither, and would leave a verifier
/// running for its whole CPU budget with nobody to read the verdict.
///
/// Linux delivers SIGKILL on parent death. Every Unix also gets a watchdog
/// that notices reparenting, which covers macOS and the window before the
/// Linux request was installed. Call once, before reading the request.
pub fn exit_when_orphaned() -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = unsafe { libc::getppid() };
        #[cfg(target_os = "linux")]
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // The parent may have died between our exec and the calls above.
        if parent <= 1 || unsafe { libc::getppid() } != parent {
            unsafe { libc::_exit(ORPHANED_EXIT) };
        }
        std::thread::Builder::new().name("proof-worker-parent-watch".into()).spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(200));
            if unsafe { libc::getppid() } != parent {
                // No unwinding or atexit handlers: native proof code may be
                // mid-computation on other threads.
                unsafe { libc::_exit(ORPHANED_EXIT) };
            }
        })?;
        Ok(())
    }
    #[cfg(not(unix))]
    Err(io::Error::new(io::ErrorKind::Unsupported, "worker orphan handling unsupported on this OS"))
}
