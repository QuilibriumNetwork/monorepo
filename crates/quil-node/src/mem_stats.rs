//! Process and structural memory snapshots.
//!
//! Diagnoses OOM growth without a heap profiler: every status tick we
//! sample (a) the OS-reported resident set size for this process, and
//! (b) the live entry counts of every known cache / map / channel that
//! could accumulate state. The deltas between consecutive samples
//! point at which structure is bleeding memory.
//!
//! Linux reads `/proc/self/statm`. macOS uses Mach `task_info`. Other
//! platforms return `None` — the structural counts still log.
//!
//! For deeper analysis (per-allocation provenance), build the node
//! with the `jemalloc-prof` feature and trigger a heap dump via
//! `SIGUSR1`. See `crates/quil-node/Cargo.toml` for the toggle.

use std::sync::Arc;

/// OS resident-set-size snapshot in bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessMemory {
    pub rss_bytes: u64,
    /// Virtual-size; only populated on Linux.
    pub vsize_bytes: u64,
}

/// Collected, structural sizes that could grow without bound. Add
/// fields as new caches are introduced. Each entry is "log this in
/// the status tick"; if a field grows linearly between ticks, that's
/// where to investigate first.
#[derive(Debug, Default)]
pub struct StructuralSizes {
    pub peer_info_cache: usize,
    pub shard_engines: usize,
    pub signer_registry: usize,
    pub archive_peers_seen: usize,
    pub peer_info_digest_cache: usize,
    pub prover_registry_addresses: usize,
    pub prover_registry_filters: usize,
    /// `(nodes, pending_frames, equivocator_buckets)` from the
    /// non-archive `GlobalTimeReel`. Zero on archive nodes.
    pub time_reel_nodes: usize,
    pub time_reel_pending: usize,
    pub time_reel_equivocators: usize,
    /// Sum across all active `AppConsensusEngine` instances of each
    /// internal cache. Per-shard counts × shard count — diagnostic
    /// for the "per-shard caches multiplied by shard count" risk.
    pub app_engine_frame_store: usize,
    pub app_engine_message_spillover: usize,
    pub app_engine_proposal_cache: usize,
    pub app_engine_pending_certified_parents: usize,
}

/// Read process RSS. Returns `None` on platforms not implemented or
/// when the OS-specific call fails. Best-effort; never panics.
pub fn process_memory() -> Option<ProcessMemory> {
    #[cfg(target_os = "linux")]
    {
        // /proc/self/status has `VmRSS:` and `VmSize:` lines in kB —
        // no page-size lookup needed. Slower than statm but doesn't
        // require pulling in libc just for `sysconf`.
        let raw = std::fs::read_to_string("/proc/self/status").ok()?;
        let mut rss_kb: u64 = 0;
        let mut vsize_kb: u64 = 0;
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                rss_kb = parse_kb(rest).unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("VmSize:") {
                vsize_kb = parse_kb(rest).unwrap_or(0);
            }
        }
        if rss_kb == 0 && vsize_kb == 0 {
            return None;
        }
        return Some(ProcessMemory {
            rss_bytes: rss_kb * 1024,
            vsize_bytes: vsize_kb * 1024,
        });
    }
    #[cfg(target_os = "macos")]
    {
        // Mach task_info(MACH_TASK_BASIC_INFO). RSS only — vsize
        // requires a separate call we skip.
        return mach_rss_bytes().map(|rss| ProcessMemory {
            rss_bytes: rss,
            vsize_bytes: 0,
        });
    }
    #[allow(unreachable_code)]
    None
}

#[cfg(target_os = "linux")]
fn parse_kb(line: &str) -> Option<u64> {
    // "  123456 kB"
    let trimmed = line.trim();
    let num: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

#[cfg(target_os = "macos")]
fn mach_rss_bytes() -> Option<u64> {
    use std::mem::MaybeUninit;
    // SAFETY: mach_task_self() returns the current task port; we
    // pass an aligned MaybeUninit struct of the size the kernel
    // expects (verified via MACH_TASK_BASIC_INFO_COUNT).
    unsafe {
        const MACH_TASK_BASIC_INFO: i32 = 20;
        // mach_task_basic_info layout (libc 0.2 doesn't re-export it):
        //   virtual_size: u64
        //   resident_size: u64
        //   resident_size_max: u64
        //   user_time: timeval64 (16 bytes)
        //   system_time: timeval64 (16 bytes)
        //   policy: i32
        //   suspend_count: i32
        // = 64 bytes total → count = 64 / 4 = 16 u32 words.
        #[repr(C)]
        struct MachTaskBasicInfo {
            virtual_size: u64,
            resident_size: u64,
            resident_size_max: u64,
            user_time: [u64; 2],
            system_time: [u64; 2],
            policy: i32,
            suspend_count: i32,
        }
        const COUNT: u32 = (std::mem::size_of::<MachTaskBasicInfo>() / 4) as u32;

        extern "C" {
            fn mach_task_self() -> u32;
            fn task_info(
                target_task: u32,
                flavor: i32,
                task_info_out: *mut i32,
                task_info_count: *mut u32,
            ) -> i32;
        }

        let mut info = MaybeUninit::<MachTaskBasicInfo>::uninit();
        let mut count = COUNT;
        let kr = task_info(
            mach_task_self(),
            MACH_TASK_BASIC_INFO,
            info.as_mut_ptr() as *mut i32,
            &mut count,
        );
        if kr != 0 {
            return None;
        }
        Some(info.assume_init().resident_size)
    }
}

/// Pretty-print bytes as MB (rounded to 0.1).
pub fn fmt_mb(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / (1024.0 * 1024.0))
}

/// Owning accessor bundle for the live components the master node
/// tracks. Cheap to clone (everything is `Arc`).
#[derive(Clone)]
pub struct StructuralSources {
    pub peer_info_cache: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>,
    >>,
    pub shard_engines: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_engine::app_engine::AppEngineHandle>,
    >>,
    pub signer_registry: Arc<quil_p2p::SignerRegistry>,
    pub prover_registry: Arc<quil_execution::SharedProverRegistry>,
    /// `None` on archive nodes (they don't run the time reel).
    pub time_reel: Option<Arc<quil_engine::time_reel::GlobalTimeReel>>,
}

impl StructuralSources {
    /// Snapshot every tracked size in one pass. Each call acquires
    /// short read locks — safe to call from the status-tick path.
    pub fn snapshot(
        &self,
        archive_peers_seen_len: usize,
        peer_info_digest_cache_len: usize,
    ) -> StructuralSizes {
        let (prover_addresses, prover_filters) = self.prover_registry.read(|r| {
            (r.distinct_provers(), r.distinct_filters())
        });
        let (tr_nodes, tr_pending, tr_eq) = self
            .time_reel
            .as_ref()
            .map(|tr| tr.sizes())
            .unwrap_or((0, 0, 0));
        // Aggregate per-shard engine sizes. Quick read-lock on the
        // shard_engines map, then snapshot each handle's atomic
        // sizes slot.
        let (fs, sp, pc, pcp) = {
            let engines = self.shard_engines.read();
            let mut fs = 0usize;
            let mut sp = 0usize;
            let mut pc = 0usize;
            let mut pcp = 0usize;
            for handle in engines.values() {
                let s = handle.sizes();
                fs += s.frame_store;
                sp += s.message_spillover;
                pc += s.proposal_cache;
                pcp += s.pending_certified_parents;
            }
            (fs, sp, pc, pcp)
        };
        StructuralSizes {
            peer_info_cache: self.peer_info_cache.read().len(),
            shard_engines: self.shard_engines.read().len(),
            signer_registry: self.signer_registry.len(),
            archive_peers_seen: archive_peers_seen_len,
            peer_info_digest_cache: peer_info_digest_cache_len,
            prover_registry_addresses: prover_addresses,
            prover_registry_filters: prover_filters,
            time_reel_nodes: tr_nodes,
            time_reel_pending: tr_pending,
            time_reel_equivocators: tr_eq,
            app_engine_frame_store: fs,
            app_engine_message_spillover: sp,
            app_engine_proposal_cache: pc,
            app_engine_pending_certified_parents: pcp,
        }
    }
}
