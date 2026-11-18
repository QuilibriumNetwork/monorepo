//! How many data workers, and so allocation seats, a node runs: what its
//! CPUs, memory and disk each hold, the least of them, at least one
//! (decided 2026-11-18). `dataWorkerCount` above zero wins.
//!
//! A worker without a seat costs little, but the count is also the node's
//! allocation capacity, and every seat holds memory and disk. On a 16 GiB
//! Mac sized by its CPUs alone, the seats' memory left no room for a proof
//! verifier, so no check ran and no seat earned (2026-11-16). The memory
//! term leaves the node's base and one due job beside the seats, and on a
//! Mac, whose admission reserves each check's memory, one verifier
//! ([`crate::storage_jobs::VERIFIER_RESERVE_BYTES`]); a seat's memory is
//! the one measured on the host's system. The disk term counts the stores
//! the node's workers hold as theirs and asks room for each further seat.
//!
//! The inputs are read once, at start, from total memory and disk space
//! rather than what is available now: the count must not follow load, or
//! seats would join and leave with it. Lowering the count proposes no leave
//! at once: seats above it leave through the lifecycle's surplus leave, one
//! an epoch, never a shard's last needed ones.

use std::path::Path;
use std::sync::OnceLock;

use tracing::{info, warn};

/// Memory the node holds without seats: a mainnet Linux node of 15 seats
/// held 3.38 GB at restart, its 1 GiB store cache full (2026-11-16), plus
/// margin. It holds those seats' start too, so it errs high.
pub const BASE_BYTES: u64 = 3584 << 20;

/// Memory of one storage job due now: the most common grant on mainnet
/// (2,052 MiB of 551, 2026-11-16).
pub const DUE_JOB_BYTES: u64 = 2 << 30;

/// Steady memory per seat on a Mac: a 16 GiB Mac's footprint of 8.1 GB
/// less the 3.4 GB base, over its 9 workers, 0.52 GB (2026-11-16).
pub const MAC_PER_SEAT_BYTES: u64 = 512 << 20;

/// Steady memory per seat on any other host: a mainnet Linux node's
/// allocated memory, median 5,960 MB over 3,888 samples less 2,768 MB at
/// restart, over its 15 seats, 0.21 GB (2026-11-16), plus margin.
pub const LINUX_PER_SEAT_BYTES: u64 = 256 << 20;

/// Memory a Mac's system and other applications keep resident beyond wired
/// memory and the admission's floor.
pub const MAC_OTHER_BYTES: u64 = 2 << 30;

/// Disk per seat: a mainnet node's worker stores and kept labels over its
/// 15 seats were 7.2 GB (2026-11-15), plus margin.
pub const PER_SEAT_DISK_BYTES: u64 = 7680 << 20;

/// The fewest workers a node runs.
pub const FLOOR: u32 = 1;

/// What the count is derived from, read once at start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inputs {
    /// CPUs the process may use (`available_parallelism`, cgroup-aware).
    pub cpus: u32,
    /// `None` where the host does not say.
    pub memory: Option<Memory>,
    /// `None` where the stores' filesystem cannot be read.
    pub disk: Option<Disk>,
}

/// The node's memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Memory {
    /// The host's memory, or its container's limit when less.
    pub total: u64,
    /// A Mac's wired memory; `None` elsewhere.
    pub wired: Option<u64>,
}

impl Memory {
    /// A Linux host of `host` bytes under a container limit, if any.
    pub fn linux(host: u64, container: Option<u64>) -> Option<Self> {
        crate::storage_jobs::node_memory(host, container).map(|total| Self { total, wired: None })
    }

    /// Memory the node may count on: all of it on Linux; on a Mac, less
    /// wired memory, the admission's floor and what other applications keep.
    pub fn usable(self) -> u64 {
        match self.wired {
            None => self.total,
            Some(wired) => self
                .total
                .saturating_sub(wired)
                .saturating_sub(crate::storage_jobs::memory_floor(self.total))
                .saturating_sub(MAC_OTHER_BYTES),
        }
    }

    /// A seat's steady memory: [`MAC_PER_SEAT_BYTES`] on a Mac, else
    /// [`LINUX_PER_SEAT_BYTES`].
    pub fn per_seat(self) -> u64 {
        match self.wired {
            Some(_) => MAC_PER_SEAT_BYTES,
            None => LINUX_PER_SEAT_BYTES,
        }
    }

    /// Memory kept for a proof check: a Mac's admission reserves
    /// [`crate::storage_jobs::VERIFIER_RESERVE_BYTES`] for each; elsewhere
    /// it reserves none, so the count keeps none.
    pub fn check(self) -> u64 {
        match self.wired {
            Some(_) => crate::storage_jobs::VERIFIER_RESERVE_BYTES,
            None => 0,
        }
    }

    /// Seats the memory holds beside the base, a due job and a check.
    pub fn seats(self) -> u32 {
        let spare = self
            .usable()
            .saturating_sub(BASE_BYTES)
            .saturating_sub(self.check())
            .saturating_sub(DUE_JOB_BYTES);
        u32::try_from(spare / self.per_seat()).unwrap_or(u32::MAX)
    }
}

/// The disk of the workers' stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disk {
    pub total: u64,
    /// What the node may still write.
    pub free: u64,
    /// Bytes of storage labels kept: a cache the node releases for room.
    pub labels: u64,
    /// Worker stores present: each already holds its seat's data.
    pub stores: u32,
}

impl Disk {
    /// The stores present, and a seat for each [`PER_SEAT_DISK_BYTES`]
    /// free or held by labels above the labels' floor.
    pub fn seats(self) -> u32 {
        let room = self
            .free
            .saturating_add(self.labels)
            .saturating_sub(crate::storage_labels::disk_floor(self.total));
        let more = u32::try_from(room / PER_SEAT_DISK_BYTES).unwrap_or(u32::MAX);
        self.stores.saturating_add(more)
    }
}

/// The term that set the count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    Configured,
    Cpu,
    Ram,
    Disk,
}

impl Binding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Cpu => "cpu",
            Self::Ram => "ram",
            Self::Disk => "disk",
        }
    }
}

/// The count and how it was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerCount {
    /// Workers, and so seats, the node runs.
    pub count: u32,
    /// The count when `dataWorkerCount` is unset.
    pub auto: u32,
    /// The term that set `count`.
    pub binding: Binding,
    /// The term that set `auto`: cpu, ram or disk.
    pub auto_binding: Binding,
    pub configured: i32,
    pub cpu: u32,
    pub ram: Option<u32>,
    pub disk: Option<u32>,
    pub inputs: Inputs,
}

/// `configured` when above zero, else the least of what the CPUs (less the
/// master's), the memory and the disk hold, at least [`FLOOR`]. A term not
/// known does not bind; the CPUs win a tie.
pub fn derive(configured: i32, inputs: &Inputs) -> WorkerCount {
    let cpu = inputs.cpus.saturating_sub(1);
    let ram = inputs.memory.map(Memory::seats);
    let disk = inputs.disk.map(Disk::seats);
    let (mut auto, mut binding) = (cpu, Binding::Cpu);
    for (term, by) in [(ram, Binding::Ram), (disk, Binding::Disk)] {
        if let Some(term) = term.filter(|&term| term < auto) {
            (auto, binding) = (term, by);
        }
    }
    let (auto, auto_binding) = (auto.max(FLOOR), binding);
    let (count, binding) = match u32::try_from(configured) {
        Ok(configured) if configured > 0 => (configured, Binding::Configured),
        _ => (auto, auto_binding),
    };
    WorkerCount {
        count,
        auto,
        binding,
        auto_binding,
        configured,
        cpu,
        ram,
        disk,
        inputs: *inputs,
    }
}

/// CPUs the process may use, as counted before the memory and disk terms.
pub fn process_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
}

/// The node's memory as this host reports it.
pub fn detect_memory() -> Option<Memory> {
    #[cfg(target_os = "macos")]
    {
        crate::storage_jobs::mac_total_and_wired().map(|(total, wired)| Memory {
            total,
            wired: Some(wired),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::storage_jobs::total_memory().map(|total| Memory { total, wired: None })
    }
}

/// The disk of the stores under `base`: its filesystem (its nearest
/// existing directory's, before the first start made it), the labels kept
/// in `labels_dir` and `stores` worker stores present.
pub fn detect_disk(base: &Path, labels_dir: &Path, stores: u32) -> Option<Disk> {
    let existing = base.ancestors().find(|dir| dir.is_dir())?;
    let usage = quil_forest::storage_health::fs_usage(existing)?;
    Some(Disk {
        total: usage.total_bytes,
        free: usage.free_bytes,
        labels: dir_bytes(labels_dir),
        stores,
    })
}

/// Bytes of the files under `dir`, symbolic links not followed; 0 where it
/// cannot be read.
pub fn dir_bytes(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => dir_bytes(&entry.path()),
            Ok(kind) if kind.is_file() => entry.metadata().map_or(0, |meta| meta.len()),
            _ => 0,
        })
        .fold(0, u64::saturating_add)
}

/// Whether `dir` is a directory holding anything.
pub fn holds_store(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

/// A count derived once and kept.
#[derive(Default)]
pub struct Once(OnceLock<WorkerCount>);

impl Once {
    pub const fn new() -> Self {
        Self(OnceLock::new())
    }

    /// The count derived at the first call, from `inputs` read then; later
    /// calls neither read nor derive again.
    pub fn resolve(&self, configured: i32, inputs: impl FnOnce() -> Inputs) -> WorkerCount {
        *self.0.get_or_init(|| {
            let count = derive(configured, &inputs());
            count.log();
            count
        })
    }
}

static RESOLVED: Once = Once::new();

/// This process's count, derived at the first call ([`Once::resolve`]):
/// the master of a node whose workers run in its process. Every site that
/// sizes its workers calls it, so whichever runs first derives the count
/// and none reads another.
pub fn init(configured: i32, inputs: impl FnOnce() -> Inputs) -> WorkerCount {
    RESOLVED.resolve(configured, inputs)
}

/// Workers of a process that derives no count (an archive, a cluster's
/// master, a standalone worker): `configured` (`dataWorkerCount`) when
/// above zero, else its CPUs less one, at least one. It never reads
/// [`init`]'s count, which a master running its workers takes instead.
pub fn cpu_count(configured: i32) -> u32 {
    if configured > 0 {
        return configured as u32;
    }
    derive(
        0,
        &Inputs {
            cpus: process_cpus(),
            memory: None,
            disk: None,
        },
    )
    .auto
}

fn term(seats: Option<u32>) -> String {
    seats.map_or_else(|| "unknown".to_string(), |seats| seats.to_string())
}

impl WorkerCount {
    /// Whether the line at start warns: memory or disk hold fewer seats
    /// than the CPUs, or `dataWorkerCount` asks more than the terms hold.
    pub fn warns(&self) -> bool {
        match self.binding {
            Binding::Ram | Binding::Disk => true,
            Binding::Configured => self.count > self.auto,
            Binding::Cpu => false,
        }
    }

    /// One line at start: the count, the term that set it and every input;
    /// a warning when [`Self::warns`].
    pub fn log(&self) {
        let memory = self.inputs.memory;
        let disk = self.inputs.disk;
        let per_seat = memory.map_or(0, Memory::per_seat);
        let check = memory.map_or(0, Memory::check);
        let action = match self.binding {
            Binding::Ram => format!(
                "memory holds fewer seats than the CPUs: each seat keeps {} MiB beside the \
                 node's 3.5 GiB, a 2 GiB job and {} MiB for a proof check; add memory or \
                 quit other applications, then restart",
                per_seat >> 20,
                check >> 20
            ),
            Binding::Disk => "disk holds fewer seats than the CPUs: each further seat needs \
                 7.5 GiB free above the labels' floor; free disk space, then restart"
                .to_string(),
            Binding::Configured if self.count > self.auto => format!(
                "dataWorkerCount {} is above the {} seats the {} term holds: seats past it \
                 starve proof checks and jobs or fill the disk; set dataWorkerCount to 0 \
                 or at most {}, then restart",
                self.count,
                self.auto,
                self.auto_binding.as_str(),
                self.auto
            ),
            Binding::Configured => "dataWorkerCount is set: it wins over every term".to_string(),
            Binding::Cpu => "none: the CPUs bind".to_string(),
        };
        let floor = disk.map_or(0, |disk| crate::storage_labels::disk_floor(disk.total));
        macro_rules! emit {
            ($level:ident) => {
                $level!(
                    workers = self.count,
                    binding = self.binding.as_str(),
                    auto = self.auto,
                    auto_binding = self.auto_binding.as_str(),
                    data_worker_count_configured = self.configured,
                    cpus = self.inputs.cpus,
                    cpu_term = self.cpu,
                    ram_term = %term(self.ram),
                    disk_term = %term(self.disk),
                    memory_total = memory.map_or(0, |memory| memory.total),
                    memory_wired = memory.and_then(|memory| memory.wired).unwrap_or(0),
                    memory_usable = memory.map_or(0, Memory::usable),
                    memory_per_seat = per_seat,
                    memory_check = check,
                    disk_total = disk.map_or(0, |disk| disk.total),
                    disk_free = disk.map_or(0, |disk| disk.free),
                    disk_labels = disk.map_or(0, |disk| disk.labels),
                    disk_stores = disk.map_or(0, |disk| disk.stores),
                    disk_floor = floor,
                    action = %action,
                    "worker count: workers and allocation seats this node runs, the least of \
                     cpu (CPUs less 1), ram ((usable memory - 3.5 GiB base - 2 GiB job - \
                     check) / per seat; a Mac: check 3 GiB, seat 512 MiB; else: check 0, \
                     seat 256 MiB) and disk (worker stores held + (free + labels - floor) / \
                     7.5 GiB), at least 1; dataWorkerCount above 0 wins; read once at start; \
                     bytes"
                )
            };
        }
        if self.warns() {
            emit!(warn);
        } else {
            emit!(info);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn host(cpus: u32, memory: Option<Memory>, disk: Option<Disk>) -> Inputs {
        Inputs { cpus, memory, disk }
    }

    fn linux(gib: u64) -> Option<Memory> {
        Memory::linux(gib * GIB, None)
    }

    /// An operator's 16 GiB Mac with 10 CPUs: 12 GiB usable after 1.5 GiB
    /// wired, the 512 MiB floor and 2 GiB for other applications; 3.5 GiB
    /// beside the base, a check and a job hold 7 seats, fewer than its 9.
    #[test]
    fn a_16_gib_mac_runs_seven_workers_bound_by_memory() {
        let mac = Memory {
            total: 16 * GIB,
            wired: Some(3 * GIB / 2),
        };
        assert_eq!(mac.usable(), 12 * GIB);
        let count = derive(0, &host(10, Some(mac), None));
        let got = (count.count, count.binding);
        assert_eq!(got, (7, Binding::Ram), "the Mac's memory binds at 7");
        assert_eq!((count.cpu, count.ram), (9, Some(7)));
    }

    /// The mainnet node of 16 CPUs and 32 GiB: memory holds 106 seats of
    /// 256 MiB beside the base and a job, the CPUs 15.
    #[test]
    fn a_32_gib_linux_node_of_16_cpus_keeps_15_bound_by_cpu() {
        let count = derive(0, &host(16, linux(32), None));
        let got = (count.count, count.binding);
        assert_eq!(got, (15, Binding::Cpu), "the CPUs bind at 15");
        assert_eq!(count.ram, Some(106));
    }

    /// An 8 GiB Linux host of 8 CPUs keeps its 7 workers: 2.5 GiB beside
    /// the base and a job hold 10 Linux seats of 256 MiB, and Linux
    /// reserves no proof check. A Mac's figures would hold none.
    #[test]
    fn an_8_gib_linux_host_keeps_its_cpus() {
        let count = derive(0, &host(8, linux(8), None));
        assert_eq!(count.ram, Some(10), "Linux memory holds 10 seats");
        let got = (count.count, count.binding);
        assert_eq!(got, (7, Binding::Cpu), "an 8 GiB Linux host keeps its CPUs");
    }

    #[test]
    fn a_configured_count_wins_over_memory() {
        let mac = Memory {
            total: 16 * GIB,
            wired: Some(3 * GIB / 2),
        };
        let count = derive(9, &host(10, Some(mac), None));
        let got = (count.count, count.binding);
        assert_eq!(got, (9, Binding::Configured), "a configured count wins");
        assert_eq!(count.auto, 7);
    }

    /// `dataWorkerCount` above what the terms hold is the overcommit a
    /// 16 GiB Mac starved on: the line warns, naming the term; at or below
    /// it, it does not.
    #[test]
    fn a_configured_count_above_memory_warns() {
        let mac = Memory {
            total: 16 * GIB,
            wired: Some(3 * GIB / 2),
        };
        let above = derive(9, &host(10, Some(mac), None));
        assert_eq!((above.auto, above.auto_binding), (7, Binding::Ram));
        assert!(above.warns(), "a configured count above memory warns");
        let within = derive(7, &host(10, Some(mac), None));
        assert!(!within.warns(), "within memory is quiet");
        let cpu = derive(0, &host(4, linux(32), None));
        assert!(!cpu.warns(), "cpu is quiet");
    }

    #[test]
    fn a_4_gib_host_runs_one_worker() {
        let count = derive(0, &host(8, linux(4), None));
        assert_eq!(count.ram, Some(0));
        let got = (count.count, count.binding);
        assert_eq!(got, (FLOOR, Binding::Ram), "one worker at least");
    }

    /// A container limited to 6 GiB on a 64 GiB host: memory holds 2.
    #[test]
    fn a_container_limit_sizes_memory() {
        let memory = Memory::linux(64 * GIB, Some(6 * GIB));
        let count = derive(0, &host(16, memory, None));
        let got = (count.count, count.binding);
        assert_eq!(got, (2, Binding::Ram), "a container limit binds at 2");
        assert_eq!(Memory::linux(0, Some(GIB)), None, "an unknown host");
    }

    /// A fresh 100 GiB disk with 40 GiB free: 30 GiB above the 10 GiB
    /// floor hold 4 seats of 7.5 GiB.
    #[test]
    fn little_free_disk_binds() {
        let disk = Disk {
            total: 100 * GIB,
            free: 40 * GIB,
            labels: 0,
            stores: 0,
        };
        let count = derive(0, &host(16, linux(64), Some(disk)));
        let got = (count.count, count.binding);
        assert_eq!(got, (4, Binding::Disk), "free disk binds at 4");
    }

    /// A node holding 9 worker stores on a 228 GiB disk, 24.8 GiB free and
    /// no labels: 2 GiB above its 22.8 GiB floor hold no further seat, and
    /// its 9 stores keep their seats rather than dropping it to one.
    #[test]
    fn held_stores_keep_their_seats_on_a_full_disk() {
        let disk = Disk {
            total: 228 * GIB,
            free: 248 * GIB / 10,
            labels: 0,
            stores: 9,
        };
        assert_eq!(disk.seats(), 9, "held stores keep their seats");
        let count = derive(0, &host(16, linux(64), Some(disk)));
        assert_eq!((count.count, count.binding), (9, Binding::Disk));
        let labels = Disk {
            labels: 15 * GIB,
            ..disk
        };
        assert_eq!(labels.seats(), 11, "kept labels are room");
    }

    /// The count is derived once: what the host reports later changes it
    /// not, nor is it read again.
    #[test]
    fn the_count_is_read_once() {
        let once = Once::new();
        let first = once.resolve(0, || host(16, linux(8), None));
        assert_eq!(first.count, 10);
        let again = once.resolve(0, || host(16, linux(64), None));
        assert_eq!(again, first, "the count is derived once");
    }

    #[test]
    fn dir_bytes_sums_nested_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), [0u8; 10]).unwrap();
        std::fs::create_dir(dir.path().join("b")).unwrap();
        std::fs::write(dir.path().join("b/c"), [0u8; 5]).unwrap();
        assert_eq!(dir_bytes(dir.path()), 15);
        assert!(holds_store(dir.path()));
        assert!(!holds_store(&dir.path().join("missing")));
    }
}
