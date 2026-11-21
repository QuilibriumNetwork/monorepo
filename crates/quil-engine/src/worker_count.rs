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
//! the one measured on the host's system. The disk term keeps a seat for
//! each worker store present and sets aside, from the room, what each may
//! still grow to a seat's share; the rest holds further seats. Opening or
//! filling a store so moves room into the store and leaves the count as it
//! was, and a full disk never drops a store's seat.
//!
//! The inputs are read once, at start, from total memory and disk space
//! rather than what is available now: the count must not follow load, or
//! seats would join and leave with it. Seats above a lowered count leave
//! through the lifecycle's surplus leave: the whole surplus proposed in one
//! cycle (at most `MAX_PROPOSALS_PER_CYCLE`), then none through its
//! cooldown, draining workers' seats first, never a seat the halt-risk
//! shield holds.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

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

/// Parts of a Mac's memory set aside as wired, whatever is wired at start:
/// a 16 GiB Mac's wired memory was 1,473 MiB (2026-11-16), 9 % of it;
/// one eighth (2 GiB there) leaves margin. Wired memory follows load, and
/// the count must not.
pub const MAC_WIRED_DIVISOR: u64 = 8;

/// Disk per seat: a mainnet node's worker stores and kept labels over its
/// 15 seats were 7.2 GB (2026-11-15), plus margin.
pub const PER_SEAT_DISK_BYTES: u64 = 7680 << 20;

/// The fewest workers a node runs.
pub const FLOOR: u32 = 1;

/// The longest the walk of the kept labels and the worker stores may take
/// before the line at start warns: the node's start waits on it, on its
/// starting thread.
pub const WALK_BOUND: Duration = Duration::from_secs(5);

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
    /// A Mac's wired memory at start, for the line; `None` elsewhere. The
    /// count sets aside [`Memory::wired_allowance`] instead.
    pub wired: Option<u64>,
}

impl Memory {
    /// A Linux host of `host` bytes under a container limit, if any.
    pub fn linux(host: u64, container: Option<u64>) -> Option<Self> {
        crate::storage_jobs::node_memory(host, container).map(|total| Self { total, wired: None })
    }

    /// Memory the node may count on: all of it on Linux; on a Mac, less
    /// the wired allowance, the admission's floor and what other
    /// applications keep.
    pub fn usable(self) -> u64 {
        match self.wired {
            None => self.total,
            Some(_) => self
                .total
                .saturating_sub(self.wired_allowance())
                .saturating_sub(crate::storage_jobs::memory_floor(self.total))
                .saturating_sub(MAC_OTHER_BYTES),
        }
    }

    /// Wired memory a Mac's count sets aside: its total over
    /// [`MAC_WIRED_DIVISOR`]; none elsewhere.
    pub fn wired_allowance(self) -> u64 {
        match self.wired {
            Some(_) => self.total / MAC_WIRED_DIVISOR,
            None => 0,
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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Disk {
    pub total: u64,
    /// What the node may still write.
    pub free: u64,
    /// Bytes of storage labels kept: a cache the node releases for room.
    pub labels: u64,
    /// Files the walk counted among the kept labels.
    pub labels_files: u64,
    /// Worker stores present: each keeps a seat.
    pub stores: u32,
    /// Bytes the present stores hold.
    pub stores_bytes: u64,
    /// Files the walk counted in the present stores.
    pub stores_files: u64,
    /// What the present stores may still grow: for each,
    /// [`PER_SEAT_DISK_BYTES`] less its bytes, at least 0.
    pub stores_growth: u64,
    /// How long the walk of the kept labels and the stores took.
    pub walk: Duration,
}

impl Disk {
    /// The disk of `total` bytes, `free` of them free, its kept labels
    /// those under `labels_dir` and its worker stores those of `stores`
    /// holding anything; the walk of both timed.
    pub fn measure(total: u64, free: u64, labels_dir: &Path, stores: &[PathBuf]) -> Self {
        let started = Instant::now();
        let (labels, labels_files) = dir_bytes(labels_dir);
        let mut disk = Self {
            total,
            free,
            labels,
            labels_files,
            ..Self::default()
        };
        for store in stores.iter().filter(|store| holds_store(store)) {
            let (bytes, files) = dir_bytes(store);
            disk.stores = disk.stores.saturating_add(1);
            disk.stores_bytes = disk.stores_bytes.saturating_add(bytes);
            disk.stores_files = disk.stores_files.saturating_add(files);
            disk.stores_growth = disk
                .stores_growth
                .saturating_add(PER_SEAT_DISK_BYTES.saturating_sub(bytes));
        }
        disk.walk = started.elapsed();
        disk
    }

    /// The room for further seats: free and kept labels' bytes above the
    /// labels' floor, less what the present stores may still grow.
    pub fn room(self) -> u64 {
        self.free
            .saturating_add(self.labels)
            .saturating_sub(crate::storage_labels::disk_floor(self.total))
            .saturating_sub(self.stores_growth)
    }

    /// A seat for each store present and for each [`PER_SEAT_DISK_BYTES`]
    /// of [`Self::room`]. A store opened or filled takes its bytes from
    /// the free room and gives them to its own, so the count stays.
    pub fn seats(self) -> u32 {
        let more = u32::try_from(self.room() / PER_SEAT_DISK_BYTES).unwrap_or(u32::MAX);
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
/// in `labels_dir` and the worker stores of `stores` present
/// ([`Disk::measure`]).
pub fn detect_disk(base: &Path, labels_dir: &Path, stores: &[PathBuf]) -> Option<Disk> {
    let existing = base.ancestors().find(|dir| dir.is_dir())?;
    let usage = quil_forest::storage_health::fs_usage(existing)?;
    Some(Disk::measure(
        usage.total_bytes,
        usage.free_bytes,
        labels_dir,
        stores,
    ))
}

/// Bytes and number of the files under `dir`, symbolic links not followed;
/// none where it cannot be read.
pub fn dir_bytes(dir: &Path) -> (u64, u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    entries
        .flatten()
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => dir_bytes(&entry.path()),
            Ok(kind) if kind.is_file() => (entry.metadata().map_or(0, |meta| meta.len()), 1),
            _ => (0, 0),
        })
        .fold((0, 0), |(bytes, files), (more, count)| {
            (bytes.saturating_add(more), files.saturating_add(count))
        })
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

/// `bytes` as the line states a constant: from 1 GiB in GiB to a tenth,
/// rounded down; below it in whole MiB.
fn size(bytes: u64) -> String {
    const GIB: u64 = 1 << 30;
    if bytes < GIB {
        return format!("{} MiB", bytes >> 20);
    }
    let tenths = bytes.saturating_mul(10) / GIB;
    match tenths % 10 {
        0 => format!("{} GiB", tenths / 10),
        tenth => format!("{}.{tenth} GiB", tenths / 10),
    }
}

impl WorkerCount {
    /// Whether the line at start warns: memory or disk hold fewer seats
    /// than the CPUs, `dataWorkerCount` asks more than the terms hold, or
    /// the walk of the kept labels and the stores overran [`WALK_BOUND`].
    pub fn warns(&self) -> bool {
        self.walk_overran()
            || match self.binding {
                Binding::Ram | Binding::Disk => true,
                Binding::Configured => self.count > self.auto,
                Binding::Cpu => false,
            }
    }

    /// Whether the walk of the kept labels and the stores took longer than
    /// [`WALK_BOUND`].
    pub fn walk_overran(&self) -> bool {
        self.inputs.disk.is_some_and(|disk| disk.walk > WALK_BOUND)
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
                "memory holds fewer seats than the CPUs: each seat keeps {} beside the \
                 node's {}, a {} job and {} for a proof check; add memory or quit other \
                 applications, then restart",
                size(per_seat),
                size(BASE_BYTES),
                size(DUE_JOB_BYTES),
                size(check)
            ),
            Binding::Disk => format!(
                "disk holds fewer seats than the CPUs: each further seat needs {0} free \
                 above the labels' floor and what the present stores may still grow to \
                 {0} each; free disk space, then restart",
                size(PER_SEAT_DISK_BYTES)
            ),
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
        let action = match disk.filter(|_| self.walk_overran()) {
            Some(disk) => format!(
                "{action}; the start waited {} ms, above the {} ms bound, walking {} files of \
                 kept storage labels and worker stores: the disk under the worker stores is \
                 slow or holds many files; check its load and health",
                disk.walk.as_millis(),
                WALK_BOUND.as_millis(),
                disk.labels_files.saturating_add(disk.stores_files)
            ),
            None => action,
        };
        let floor = disk.map_or(0, |disk| crate::storage_labels::disk_floor(disk.total));
        let walk_ms = disk.map_or(0, |disk| disk.walk.as_millis() as u64);
        let rule = format!(
            "the least of cpu (CPUs less 1), ram ((usable memory - {} base - {} job - check) / \
             per seat; a Mac: usable less total / {} wired, check {}, seat {}; else: check 0, \
             seat {}) and disk (worker stores present + (free + labels - floor - what the \
             stores may still grow to {disk} each) / {disk}), at least {FLOOR}",
            size(BASE_BYTES),
            size(DUE_JOB_BYTES),
            MAC_WIRED_DIVISOR,
            size(crate::storage_jobs::VERIFIER_RESERVE_BYTES),
            size(MAC_PER_SEAT_BYTES),
            size(LINUX_PER_SEAT_BYTES),
            disk = size(PER_SEAT_DISK_BYTES)
        );
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
                    memory_wired_allowance = memory.map_or(0, Memory::wired_allowance),
                    memory_usable = memory.map_or(0, Memory::usable),
                    memory_per_seat = per_seat,
                    memory_check = check,
                    disk_total = disk.map_or(0, |disk| disk.total),
                    disk_free = disk.map_or(0, |disk| disk.free),
                    disk_labels = disk.map_or(0, |disk| disk.labels),
                    disk_labels_files = disk.map_or(0, |disk| disk.labels_files),
                    disk_stores = disk.map_or(0, |disk| disk.stores),
                    disk_stores_bytes = disk.map_or(0, |disk| disk.stores_bytes),
                    disk_stores_files = disk.map_or(0, |disk| disk.stores_files),
                    disk_stores_growth = disk.map_or(0, |disk| disk.stores_growth),
                    disk_walk_ms = walk_ms,
                    disk_floor = floor,
                    action = %action,
                    "worker count: workers and allocation seats this node runs, {}; \
                     dataWorkerCount above 0 wins; read once at start; bytes; the walk of \
                     labels and stores in files and milliseconds",
                    rule
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

    /// An operator's 16 GiB Mac with 10 CPUs: 11.5 GiB usable after the
    /// 2 GiB wired allowance, the 512 MiB floor and 2 GiB for other
    /// applications; 3 GiB beside the base, a check and a job hold 6
    /// seats, fewer than its 9.
    #[test]
    fn a_16_gib_mac_runs_six_workers_bound_by_memory() {
        let mac = Memory {
            total: 16 * GIB,
            wired: Some(3 * GIB / 2),
        };
        assert_eq!(mac.usable(), 23 * GIB / 2);
        let count = derive(0, &host(10, Some(mac), None));
        let got = (count.count, count.binding);
        assert_eq!(got, (6, Binding::Ram), "the Mac's memory binds at 6");
        assert_eq!((count.cpu, count.ram), (9, Some(6)));
    }

    /// Wired memory follows load: the 16 GiB Mac at 1,473 MiB wired, as
    /// measured, and at 3 GiB derives one count.
    #[test]
    fn a_macs_wired_memory_at_start_does_not_move_its_count() {
        let mac = |wired| Memory {
            total: 16 * GIB,
            wired: Some(wired),
        };
        let quiet = derive(0, &host(10, Some(mac(1473 << 20)), None));
        let loaded = derive(0, &host(10, Some(mac(3 * GIB)), None));
        assert_eq!(
            loaded.count, quiet.count,
            "two wired readings give one count"
        );
        assert_eq!(quiet.count, 6, "the Mac's memory binds at 6");
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
        assert_eq!(count.auto, 6);
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
        assert_eq!((above.auto, above.auto_binding), (6, Binding::Ram));
        assert!(above.warns(), "a configured count above memory warns");
        let within = derive(6, &host(10, Some(mac), None));
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
            ..Disk::default()
        };
        let count = derive(0, &host(16, linux(64), Some(disk)));
        let got = (count.count, count.binding);
        assert_eq!(got, (4, Binding::Disk), "free disk binds at 4");
    }

    /// A node holding 9 full worker stores on a 228 GiB disk, 24.8 GiB free
    /// and no labels: 2 GiB above its 22.8 GiB floor hold no further seat,
    /// and its 9 stores keep their seats rather than dropping it to one.
    #[test]
    fn held_stores_keep_their_seats_on_a_full_disk() {
        let disk = Disk {
            total: 228 * GIB,
            free: 248 * GIB / 10,
            stores: 9,
            stores_bytes: 9 * PER_SEAT_DISK_BYTES,
            ..Disk::default()
        };
        assert_eq!(disk.seats(), 9, "held stores keep their seats");
        let count = derive(0, &host(16, linux(64), Some(disk)));
        assert_eq!((count.count, count.binding), (9, Binding::Disk));
        let labels = Disk {
            labels: 15 * GIB,
            ..disk
        };
        assert_eq!(labels.seats(), 11, "kept labels are room");
        let growing = Disk {
            stores_bytes: 9 * GIB,
            stores_growth: 9 * (PER_SEAT_DISK_BYTES - GIB),
            ..disk
        };
        assert_eq!(growing.seats(), 9, "growing stores keep their seats");
    }

    /// `n` worker store paths under `dir`, none made.
    fn store_paths(dir: &Path, n: u32) -> Vec<PathBuf> {
        (1..=n)
            .map(|core| dir.join(format!("worker-{core}")))
            .collect()
    }

    /// Opens `store` as a worker would: its directory and one small file,
    /// whose bytes it returns.
    fn open_store(store: &Path) -> u64 {
        std::fs::create_dir_all(store).unwrap();
        std::fs::write(store.join("CURRENT"), [0u8; 4096]).unwrap();
        4096
    }

    /// A 100 GiB disk, 30 GiB and half a seat above its 10 GiB floor: the
    /// count's 4 seats, once their stores are opened and their bytes taken
    /// from the free room, derive 4 again at the next start, and the next.
    #[test]
    fn opening_the_derived_stores_keeps_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let labels = dir.path().join("storage-labels");
        let stores = store_paths(dir.path(), 16);
        let total = 100 * GIB;
        let mut free = 40 * GIB + PER_SEAT_DISK_BYTES / 2;
        let start = |free| {
            let disk = Disk::measure(total, free, &labels, &stores);
            derive(0, &host(16, linux(64), Some(disk)))
        };
        let first = start(free);
        let got = (first.count, first.binding);
        assert_eq!(got, (4, Binding::Disk), "the premise: free disk binds at 4");
        for store in &stores[..first.count as usize] {
            free -= open_store(store);
        }
        let second = start(free);
        let opened = second.inputs.disk.map(|disk| disk.stores);
        assert_eq!(opened, Some(4), "the premise: 4 stores present");
        assert_eq!(
            second.count, first.count,
            "opening the derived stores keeps the count"
        );
        assert_eq!(start(free).count, first.count, "and at the next start");
    }

    /// Two stores present and room for 4 more seats and a half: a store
    /// filled by 4 GiB, taken from the free room, leaves the count as it
    /// was.
    #[test]
    fn filling_a_store_keeps_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let labels = dir.path().join("storage-labels");
        let stores = store_paths(dir.path(), 16);
        let total = 100 * GIB;
        let mut free = 10 * GIB + 13 * PER_SEAT_DISK_BYTES / 2;
        for store in &stores[..2] {
            free -= open_store(store);
        }
        let start = |free| {
            let disk = Disk::measure(total, free, &labels, &stores);
            derive(0, &host(16, linux(64), Some(disk)))
        };
        let before = start(free);
        let got = (before.count, before.binding);
        assert_eq!(got, (6, Binding::Disk), "the premise: disk binds at 6");
        let filled = 4 * GIB;
        let sst = std::fs::File::create(stores[0].join("000001.sst")).unwrap();
        sst.set_len(filled).unwrap();
        free -= filled;
        let after = start(free);
        let held = after.inputs.disk.map(|disk| disk.stores_bytes);
        assert_eq!(held, Some(2 * 4096 + filled), "the premise: the store grew");
        assert_eq!(after.count, before.count, "filling a store keeps the count");
    }

    /// The line states its constants as they are.
    #[test]
    fn the_line_states_its_constants() {
        assert_eq!(size(BASE_BYTES), "3.5 GiB", "the base");
        assert_eq!(size(DUE_JOB_BYTES), "2 GiB", "a due job");
        assert_eq!(size(MAC_PER_SEAT_BYTES), "512 MiB", "a Mac's seat");
        assert_eq!(size(PER_SEAT_DISK_BYTES), "7.5 GiB", "a seat's disk");
        assert_eq!(size(0), "0 MiB", "no check");
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
        assert_eq!(dir_bytes(dir.path()), (15, 2));
        assert!(holds_store(dir.path()));
        assert!(!holds_store(&dir.path().join("missing")));
    }

    /// The line at start carries the walk's files and duration, of the
    /// kept labels and of the stores, at info within [`WALK_BOUND`] and at
    /// it, and as a warning naming the bound past it, whichever term binds.
    #[test]
    fn the_count_line_carries_the_walk() {
        let dir = tempfile::tempdir().unwrap();
        let labels = dir.path().join("storage-labels");
        std::fs::create_dir_all(labels.join("epoch")).unwrap();
        for name in ["a", "b", "epoch/c"] {
            std::fs::write(labels.join(name), [0u8; 4]).unwrap();
        }
        let stores = store_paths(dir.path(), 2);
        std::fs::create_dir_all(&stores[0]).unwrap();
        for name in ["CURRENT", "000001.sst"] {
            std::fs::write(stores[0].join(name), [0u8; 5]).unwrap();
        }
        let walked = detect_disk(dir.path(), &labels, &stores).expect("the tempdir's filesystem");
        let got = (walked.labels, walked.labels_files);
        assert_eq!(got, (12, 3), "the walk counts the labels");
        let got = (walked.stores, walked.stores_bytes, walked.stores_files);
        assert_eq!(got, (1, 10, 2), "the walk counts the stores present");
        assert_eq!(walked.stores_growth, PER_SEAT_DISK_BYTES - 10);
        let disk = Disk {
            total: 1000 * GIB,
            free: 500 * GIB,
            walk: Duration::from_millis(1234),
            ..walked
        };
        let within = derive(0, &host(16, linux(64), Some(disk)));
        assert_eq!(within.binding, Binding::Cpu);
        assert!(!within.warns(), "a walk within the bound is quiet");
        let at = Disk {
            walk: WALK_BOUND,
            ..disk
        };
        let at = derive(0, &host(16, linux(64), Some(at)));
        assert!(!at.warns(), "a walk of exactly the bound is quiet");
        let slow = Disk {
            walk: WALK_BOUND + Duration::from_millis(1),
            ..disk
        };
        let over = derive(0, &host(16, linux(64), Some(slow)));
        assert!(over.warns(), "a walk past the bound warns");

        let logs = crate::outage::test_logs::CapturedLogs::default();
        let _guard = logs.install();
        within.log();
        over.log();
        let lines = logs.lines_with("worker count:");
        assert_eq!(lines.len(), 2, "one line each: {lines:?}");
        assert!(
            [
                "INFO",
                "disk_labels_files=3",
                "disk_stores_files=2",
                "disk_walk_ms=1234"
            ]
            .iter()
            .all(|part| lines[0].contains(part)),
            "the line carries the walk: {}",
            lines[0]
        );
        assert!(
            [
                "WARN",
                "disk_walk_ms=5001",
                "above the 5000 ms bound",
                "walking 5 files"
            ]
            .iter()
            .all(|part| lines[1].contains(part)),
            "past the bound the line warns: {}",
            lines[1]
        );
    }
}
