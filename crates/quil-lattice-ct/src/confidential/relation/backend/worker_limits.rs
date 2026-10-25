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

/// Environment variable through which a launcher names itself to its worker:
/// the decimal PID of the process that spawns it. A worker cannot otherwise
/// tell a launcher running as PID 1 (a container entrypoint without an init)
/// from init adopting an orphan.
pub const PARENT_PID_ENV: &str = "QUIL_PROOF_WORKER_PARENT_PID";

/// The parent this worker must keep, or `None` when it is already orphaned.
/// `named` is the launcher's [`PARENT_PID_ENV`] value and `startup` the parent
/// the worker saw at startup. A named PID is trusted, including 1. Without
/// one, a startup parent of 1 or less is init that adopted the worker.
#[cfg(unix)]
fn watched_parent(named: Option<&str>, startup: libc::pid_t) -> io::Result<Option<libc::pid_t>> {
    let Some(named) = named else { return Ok((startup > 1).then_some(startup)) };
    match named.parse::<libc::pid_t>() {
        Ok(pid) if pid >= 1 => Ok((startup == pid).then_some(pid)),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid proof worker parent PID")),
    }
}

/// Stop this worker when the node that launched it dies. The parent kills and
/// reaps its worker on every path it still controls; an abrupt parent death
/// (SIGKILL, OOM kill, crash) reaches neither, and would leave a verifier
/// running for its whole CPU budget with nobody to read the verdict.
///
/// Linux delivers SIGKILL on parent death. Every Unix also gets a watchdog
/// that notices reparenting, which covers macOS and the window before the
/// Linux request was installed. Call once, before reading the request.
/// The launcher names itself through [`PARENT_PID_ENV`]; only a worker started
/// without it takes a parent of PID 1 for init.
pub fn exit_when_orphaned() -> io::Result<()> {
    #[cfg(unix)]
    {
        let startup = unsafe { libc::getppid() };
        #[cfg(target_os = "linux")]
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let named = std::env::var_os(PARENT_PID_ENV).map(|value| value.into_string().unwrap_or_default());
        // The parent may have died between our exec and the calls above.
        let parent = match watched_parent(named.as_deref(), startup)? {
            Some(parent) if unsafe { libc::getppid() } == parent => parent,
            _ => unsafe { libc::_exit(ORPHANED_EXIT) },
        };
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_named_parent_is_kept_even_as_pid_1() {
        // A node running as PID 1: a container entrypoint without an init.
        assert_eq!(watched_parent(Some("1"), 1).unwrap(), Some(1));
        assert_eq!(watched_parent(Some("4242"), 4242).unwrap(), Some(4242));
        // The worker was already adopted by init or a subreaper.
        assert_eq!(watched_parent(Some("4242"), 1).unwrap(), None);
        assert_eq!(watched_parent(Some("4242"), 77).unwrap(), None);
        assert_eq!(watched_parent(Some("1"), 77).unwrap(), None);
        for bad in ["", "0", "-1", "x", "99999999999"] {
            assert!(watched_parent(Some(bad), 4242).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_unnamed_parent_of_pid_1_reads_as_init() {
        assert_eq!(watched_parent(None, 4242).unwrap(), Some(4242));
        assert_eq!(watched_parent(None, 1).unwrap(), None);
        assert_eq!(watched_parent(None, 0).unwrap(), None);
    }
}
