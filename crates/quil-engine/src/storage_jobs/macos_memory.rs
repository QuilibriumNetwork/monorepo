//! macOS admission follows memory pressure, rather than Linux-like free RAM.
//!
//! sysinfo 0.37 subtracts compressor pages from free + inactive + purgeable
//! pages on macOS. That can saturate to zero while the kernel reports normal
//! pressure. Budget free, file-backed and purgeable physical pages instead,
//! without lending other applications' anonymous pages or subtracting the
//! compressor a second time. Keep headroom for the OS, and bound the result
//! by physical capacity minus this process's dirty/compressed footprint.
//! Admission applies its usual 75% share and accounts for outstanding jobs.
//! Warning/critical pressure stops additional admission; running work drains.
//! Page-counter definitions: Apple's osfmk/mach/vm_statistics.h. Speculative
//! pages already belong to free_count and must not be added again.
//!
//! Apple exports dispatch values (normal=1, warning=2, critical=4) via this
//! sysctl, rather than its internal pressure enum (normal=0):
//! https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_memorystatus_notify.c

#[derive(Clone, Copy)]
pub(super) struct Snapshot {
    pub total: u64,
    pub wired: u64,
    /// Includes compressed dirty pages, unlike resident size alone.
    pub footprint: u64,
    /// Free + file-backed + purgeable pages, without speculative duplication.
    pub reclaimable: u64,
    pub pressure: u32,
}

impl Snapshot {
    pub(super) fn headroom(self) -> u64 {
        if self.pressure != 1 {
            // Known pressure is zero headroom, not a failed measurement.
            return 0;
        }
        self.unowned()
            .min(self.reclaimable)
            // Admission leaves another 25% of this budget unused. This
            // additional floor covers host growth while a job starts.
            .saturating_sub(self.floor())
    }

    /// Physical memory neither wired nor this process's footprint, less
    /// [`Self::floor`], whatever the pressure: the most a job running alone
    /// may take without growing wired and own memory past physical memory
    /// (other applications' pages compress or swap instead).
    pub(super) fn capacity(self) -> u64 {
        self.unowned().saturating_sub(self.floor())
    }

    /// Which input made [`Self::headroom`] zero, for its log line: `None`
    /// when it is not.
    pub(super) fn no_headroom_cause(self) -> Option<&'static str> {
        if self.pressure != 1 {
            Some("pressure: the kernel reports warning or critical memory pressure")
        } else if self.unowned() <= self.floor() {
            Some("footprint: wired memory plus this process's footprint fill physical memory")
        } else if self.reclaimable <= self.floor() {
            Some("reclaimable: free, file-backed and purgeable pages are within the floor")
        } else {
            None
        }
    }

    pub(super) fn floor(self) -> u64 {
        (self.total / 32).clamp(256 << 20, 1 << 30)
    }

    fn unowned(self) -> u64 {
        self.total
            .saturating_sub(self.wired)
            .saturating_sub(self.footprint)
    }
}

#[cfg(target_os = "macos")]
pub(super) fn available() -> Option<u64> {
    let snapshot = snapshot()?;
    if let Some(cause) = snapshot.no_headroom_cause() {
        log_no_headroom(snapshot, cause);
    }
    Some(snapshot.headroom())
}

/// At most one line per this interval says why the host has no headroom.
#[cfg(target_os = "macos")]
const NO_HEADROOM_LOG_EVERY: std::time::Duration = std::time::Duration::from_secs(5 * 60);

#[cfg(target_os = "macos")]
fn log_no_headroom(snapshot: Snapshot, cause: &'static str) {
    use std::sync::{Mutex, PoisonError};
    static LINE: Mutex<super::LineEvery> = Mutex::new(super::LineEvery(None));
    let Some(skipped) = LINE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .due(std::time::Instant::now(), NO_HEADROOM_LOG_EVERY)
    else {
        return;
    };
    tracing::info!(
        cause,
        pressure = snapshot.pressure,
        total = snapshot.total,
        wired = snapshot.wired,
        footprint = snapshot.footprint,
        reclaimable = snapshot.reclaimable,
        floor = snapshot.floor(),
        capacity = snapshot.capacity(),
        more_since_last_line = skipped,
        action = "jobs and proof checks admitted by memory wait (a check a finalized frame \
                  waits on may run alone within capacity, past it once checks starve); check `memory_pressure` and \
                  `vm_stat`, quit other applications, or lower the database cache or the \
                  worker count",
        "macOS memory admission has no headroom: pressure normal is 1, warning 2, critical 4; \
         headroom is total less wired and footprint, at most reclaimable, less floor; logged \
         at most once per 5 minutes"
    );
}

/// The kernel's memory pressure level (normal 1, warning 2, critical 4)
/// and [`Snapshot::capacity`], from one snapshot.
#[cfg(target_os = "macos")]
pub(super) fn host_memory() -> super::HostMemory {
    snapshot().map_or_else(super::HostMemory::default, |snapshot| super::HostMemory {
        pressure: Some(snapshot.pressure),
        capacity: Some(snapshot.capacity()),
    })
}

#[cfg(target_os = "macos")]
fn snapshot() -> Option<Snapshot> {
    use std::{ffi::CStr, mem, ptr, sync::OnceLock};

    fn sysctl<T: Default>(name: &CStr) -> Option<T> {
        let mut value = T::default();
        let mut size = mem::size_of::<T>();
        // SAFETY: both callers use integer types of the exact sysctl width;
        // the initialized writable buffer and its length agree.
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&mut value as *mut T).cast(),
                &mut size,
                ptr::null_mut(),
                0,
            )
        };
        (result == 0 && size == mem::size_of::<T>()).then_some(value)
    }

    let total: u64 = sysctl(c"hw.memsize")?;
    let pressure: u32 = sysctl(c"kern.memorystatus_vm_pressure_level")?;
    if total == 0 {
        return None;
    }
    // Keep one host port for the process lifetime, not a new send right on
    // every admission check. Neither host statistics nor our own rusage needs
    // privileges on macOS.
    static HOST: OnceLock<libc::mach_port_t> = OnceLock::new();
    #[allow(deprecated)]
    let host = *HOST.get_or_init(|| unsafe { libc::mach_host_self() });
    let mut count = libc::HOST_VM_INFO64_COUNT;
    // SAFETY: these C output structs admit zero initialization. Each API
    // receives its matching buffer type/count, checked before the fields are
    // used. proc_pid_rusage's buffer is a struct cast to rusage_info_t* as in
    // Apple's libproc API; it is not a pointer-to-pointer output parameter.
    let (mut vm, mut usage) = unsafe {
        (
            mem::zeroed::<libc::vm_statistics64>(),
            mem::zeroed::<libc::rusage_info_v0>(),
        )
    };
    let vm_result = unsafe {
        libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            (&mut vm as *mut libc::vm_statistics64).cast(),
            &mut count,
        )
    };
    let usage_result = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V0,
            (&mut usage as *mut libc::rusage_info_v0).cast(),
        )
    };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if vm_result != libc::KERN_SUCCESS
        || count < libc::HOST_VM_INFO64_COUNT
        || usage_result != 0
        || page_size <= 0
    {
        return None;
    }
    Some(Snapshot {
        total,
        wired: u64::from(vm.wire_count).saturating_mul(page_size as u64),
        footprint: usage.ri_phys_footprint,
        reclaimable: u64::from(vm.free_count)
            .saturating_add(u64::from(vm.external_page_count))
            .saturating_add(u64::from(vm.purgeable_count))
            .saturating_mul(page_size as u64),
        pressure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const GIB: u64 = 1 << 30;

    #[test]
    fn a_small_mac_does_not_lend_other_applications_anonymous_memory() {
        let mac = Snapshot {
            total: 16 * GIB,
            wired: 2 * GIB,
            footprint: 4 * GIB,
            reclaimable: 3 * GIB,
            pressure: 1,
        };
        // The old capacity-minus-own-footprint rule offered 10 GiB here.
        assert_eq!(mac.headroom(), 3 * GIB - GIB / 2);
        assert_eq!(
            Snapshot {
                reclaimable: 256 << 20,
                ..mac
            }
            .headroom(),
            0
        );
        assert_eq!(
            Snapshot {
                footprint: 15 * GIB,
                ..mac
            }
            .headroom(),
            0
        );
    }

    #[test]
    fn compressed_pages_do_not_turn_normal_pressure_into_zero_capacity() {
        // The failing host had ~25 GiB in its compressor and ~17 GiB in
        // free/inactive/purgeable pages: sysinfo reported zero available.
        let normal = Snapshot {
            total: 64 * GIB,
            wired: 7 * GIB,
            footprint: 3 * GIB,
            reclaimable: 17 * GIB,
            pressure: 1,
        };
        assert_eq!(normal.headroom(), 16 * GIB);
        // The process's own compressed allocations remain charged even if
        // macOS has reduced its RSS, and kernel wired memory is unavailable.
        assert_eq!(
            Snapshot {
                footprint: 50 * GIB,
                ..normal
            }
            .headroom(),
            6 * GIB
        );
        assert_eq!(
            Snapshot {
                footprint: 60 * GIB,
                ..normal
            }
            .headroom(),
            0
        );
    }

    #[test]
    fn pressure_and_unknown_levels_do_not_admit_more_work() {
        for pressure in [0, 2, 4, 8, u32::MAX] {
            assert_eq!(
                Snapshot {
                    total: 64 * GIB,
                    wired: 0,
                    footprint: 0,
                    reclaimable: 16 * GIB,
                    pressure
                }
                .headroom(),
                0
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_macos_memory_signals_are_readable() {
        let snapshot =
            snapshot().expect("macOS memory pressure, host statistics and own footprint");
        assert!(snapshot.total > 0);
        assert!(snapshot.wired <= snapshot.total);
        assert!([1, 2, 4].contains(&snapshot.pressure));
        eprintln!(
            "macOS admission: total={} wired={} footprint={} pressure={} headroom={}",
            snapshot.total,
            snapshot.wired,
            snapshot.footprint,
            snapshot.pressure,
            snapshot.headroom()
        );
    }

    /// The line logged at no headroom names the input that made it zero, and
    /// the capacity a check alone is bounded by ignores pressure and
    /// reclaimable pages, but not wired memory, the footprint or the floor.
    #[test]
    fn no_headroom_names_its_cause_and_capacity_ignores_pressure() {
        let mac = Snapshot {
            total: 16 * GIB,
            wired: 2 * GIB,
            footprint: 4 * GIB,
            reclaimable: 3 * GIB,
            pressure: 1,
        };
        assert_eq!(mac.no_headroom_cause(), None);
        assert_eq!(mac.capacity(), 10 * GIB - GIB / 2);
        let warned = Snapshot { pressure: 2, ..mac };
        assert_eq!(warned.headroom(), 0);
        assert!(
            warned
                .no_headroom_cause()
                .is_some_and(|cause| cause.starts_with("pressure")),
            "no_headroom_cause_missed: warning pressure gave {:?}",
            warned.no_headroom_cause()
        );
        assert_eq!(warned.capacity(), mac.capacity());
        let full = Snapshot {
            footprint: 14 * GIB - (GIB / 2),
            ..mac
        };
        assert_eq!(full.capacity(), 0);
        assert!(full
            .no_headroom_cause()
            .is_some_and(|cause| cause.starts_with("footprint")));
        let drained = Snapshot {
            reclaimable: GIB / 2,
            ..mac
        };
        assert_eq!(drained.headroom(), 0);
        assert!(drained
            .no_headroom_cause()
            .is_some_and(|cause| cause.starts_with("reclaimable")));
    }

    /// An operator's 16 GiB Mac at normal pressure (`vm_stat`, `top`): the
    /// node, its data workers in process, owns 8122 MiB; 16 KiB pages, 94950
    /// wired, free 5800 plus 352 speculative, 282560 file-backed and 2971
    /// purgeable. Its headroom is short of a 3 GiB check's share, so only a
    /// check a frame waits on starts, alone, while the node's footprint
    /// leaves room for it (here up to about 11.05 GiB), else once checks
    /// have starved.
    #[test]
    fn an_operators_16_gib_mac_runs_a_frames_check_alone_within_capacity() {
        const PAGE: u64 = 16 << 10;
        const CHECK: u64 = 3 * GIB;
        let mac = Snapshot {
            total: 17_179_869_184,
            wired: 94_950 * PAGE,
            footprint: 8122 << 20,
            reclaimable: (5800 + 352 + 282_560 + 2971) * PAGE,
            pressure: 1,
        };
        assert_eq!(mac.headroom(), 4_242_063_360);
        assert!(mac.headroom() < super::super::needs_available(CHECK));
        assert_eq!(mac.no_headroom_cause(), None);
        assert_eq!(mac.capacity(), 6_570_803_200);
        use super::super::{frame_alone_allowed, FrameAlone, HostMemory, VERIFIER_STARVED_WARN};
        use std::time::Duration;
        let alone = |snapshot: Snapshot, starved_for| {
            frame_alone_allowed(
                0,
                HostMemory {
                    pressure: Some(snapshot.pressure),
                    capacity: Some(snapshot.capacity()),
                },
                CHECK,
                starved_for,
                VERIFIER_STARVED_WARN,
                false,
            )
        };
        assert_eq!(alone(mac, Duration::ZERO), FrameAlone::Fits);
        let edge = mac.total - mac.wired - mac.floor() - CHECK;
        let at_edge = Snapshot {
            footprint: edge,
            ..mac
        };
        assert_eq!(at_edge.capacity(), CHECK);
        assert_eq!(alone(at_edge, Duration::ZERO), FrameAlone::Fits);
        // Its compressor (6531 MiB) counted in the footprint too: refused
        // until checks have starved the bound, then alone past capacity, as
        // nothing in the node shrinks that footprint while frames wait.
        let just_short = VERIFIER_STARVED_WARN - Duration::from_secs(1);
        for footprint in [edge + 1, (8122 + 6531) << 20] {
            let full = Snapshot { footprint, ..mac };
            assert_eq!(
                alone(full, just_short),
                FrameAlone::Refused,
                "frame_alone_past_capacity: a 3 GiB check ran alone at a {footprint} byte \
                 footprint"
            );
            assert_eq!(
                alone(full, VERIFIER_STARVED_WARN),
                FrameAlone::Starved,
                "frame_alone_refused_forever: starved, a 3 GiB check stayed refused at a \
                 {footprint} byte footprint"
            );
        }
        let full = Snapshot {
            footprint: (8122 + 6531) << 20,
            ..mac
        };
        assert_eq!((full.headroom(), full.capacity()), (0, 0));
        assert!(full
            .no_headroom_cause()
            .is_some_and(|cause| cause.starts_with("footprint")));
    }
}
