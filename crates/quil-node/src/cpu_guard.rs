//! Refuses a native lattice build on a CPU that lacks the features its C was
//! compiled for, before anything else in the process runs.
//!
//! The check runs from `.preinit_array`, ahead of every library initialiser
//! and of jemalloc's constructor. tikv-jemalloc-sys compiles jemalloc with
//! the same CFLAGS as the lattice C (`-march=skylake-avx512` in the AVX-512
//! image), so such a build died with SIGILL while the allocator initialised,
//! before `main` could print the refusal. Hence no allocation here and plain
//! write(2) on stderr.

use libc::{c_char, c_int};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

/// glibc calls `.preinit_array` entries with `argc`, `argv` and `envp`, before
/// libc's own initialiser: `getenv` sees no environment yet, `envp` does.
type PreinitFn = extern "C" fn(c_int, *const *const c_char, *const *const c_char);

#[used]
#[link_section = ".preinit_array"]
static REFUSE_UNSUPPORTED_CPU: PreinitFn = refuse_unsupported_cpu;

/// Set by the hook: proof for tests that it ran before `main`.
#[cfg(test)]
static RAN: AtomicBool = AtomicBool::new(false);

extern "C" fn refuse_unsupported_cpu(
    _argc: c_int,
    _argv: *const *const c_char,
    _envp: *const *const c_char,
) {
    #[cfg(test)]
    RAN.store(true, Ordering::SeqCst);
    let mut first = true;
    let refused = quil_lattice_ct::native_cpu::write_unsupported_cpu_message("quil-node", |p| {
        // The same line `main` printed for this refusal before (anyhow's).
        if std::mem::take(&mut first) {
            write_stderr(b"Error: ");
        }
        write_stderr(p.as_bytes());
    });
    if refused {
        write_stderr(b"\n");
        // SAFETY: ends the process before any initialiser that could crash.
        unsafe { libc::_exit(1) };
    }
}

fn write_stderr(mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: the pointer and length come from a live slice.
        let n = unsafe { libc::write(2, bytes.as_ptr().cast(), bytes.len()) };
        if n > 0 {
            bytes = &bytes[n as usize..];
        } else if n == 0
            || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test runs only where the build runs (the hook exits otherwise), so
    /// what it can show is that the hook is registered and ran before `main`.
    #[test]
    fn the_cpu_check_runs_before_main() {
        assert!(
            RAN.load(Ordering::SeqCst),
            "the .preinit_array hook never ran"
        );
        assert!(quil_lattice_ct::native_cpu::unsupported_cpu_message("quil-node").is_none());
    }
}
