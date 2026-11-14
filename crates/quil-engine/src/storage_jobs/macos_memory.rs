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
        self.total
            .saturating_sub(self.wired)
            .saturating_sub(self.footprint)
            .min(self.reclaimable)
            // Admission leaves another 25% of this budget unused. This
            // additional floor covers host growth while a job starts.
            .saturating_sub((self.total / 32).clamp(256 << 20, 1 << 30))
    }
}

#[cfg(target_os = "macos")]
pub(super) fn available() -> Option<u64> {
    snapshot().map(Snapshot::headroom)
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
}
