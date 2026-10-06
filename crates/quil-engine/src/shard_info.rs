//! Shard info discovery module. Port of
//! `node/consensus/global/shard_info.go` (463 lines).
//!
//! Builds a list of shard entries enriched with prover-count, ring,
//! and estimated reward data. The per-shard reward formula matches
//! `proof_of_meaningful_work.go`:
//!
//! ```text
//! per_ring = (basis * shard_size / world_bytes) / (2^(ring+1) * sqrt(data_shards))
//! per_prover = per_ring / 8
//! ```
//!
//! The module is designed so that the pure-math helpers
//! (`compute_shard_reward`, `isqrt`) are independently testable,
//! while the orchestration (`get_shard_info`, `build_shard_entries`)
//! works against trait objects for the prover registry and shards
//! store.

use std::collections::{HashMap, HashSet};

use num_bigint::BigInt;
use num_traits::{One, Zero};

use quil_types::consensus::{
    ProverInfo, ProverRegistry, ShardDetail,
};
use quil_types::error::Result;
use quil_types::store::{ShardInfo, ShardsStore};

use crate::rewards::pomw_basis;

/// Per-shard reward units (8 billion sub-units per QUIL).
const QUIL_TOKEN_UNITS: u64 = 8_000_000_000;

// ---------------------------------------------------------------------------
// ShardEntry — internal intermediate representation
// ---------------------------------------------------------------------------

/// Intermediate shard data built during `build_shard_entries`, before
/// conversion to the public `ShardDetail` type.
#[derive(Debug, Clone)]
pub struct ShardEntry {
    /// Shard filter bytes (L2 prefix + sub-shard prefix bytes).
    pub filter: Vec<u8>,
    /// Total state size in bytes for this shard.
    pub size: BigInt,
    /// Number of data sub-shards.
    pub data_shards: u64,
    /// Total active + joining provers on this shard.
    pub total_active: usize,
    /// Provers sharing this prover's ring (or the joiner ring).
    pub provers_on_ring: usize,
    /// Whether the local prover is allocated to this shard.
    pub is_allocated: bool,
    /// Ring assignment (0-based).
    pub ring: u8,
    pub materialized_frame: u64,
    pub latest_frame: u64,
}

/// Raw shard size info returned by the size-fetching callbacks.
#[derive(Debug, Clone)]
pub struct ShardSizeEntry {
    pub prefix: Vec<u32>,
    pub size: Vec<u8>,
    pub data_shards: u64,
    pub materialized_frame: u64,
    pub latest_frame: u64,
}

// ---------------------------------------------------------------------------
// Ring calculation helpers (mirrors worker_allocator.go)
// ---------------------------------------------------------------------------

/// Ring metadata for a shard, computed from the total count of
/// active + joining provers.
#[derive(Debug, Clone, Copy)]
struct ShardRingInfo {
    /// Ring of the last existing prover (position count-1).
    current_ring: u8,
    /// Ring a new joiner would land on (position count).
    joiner_ring: u8,
    /// Provers sharing the last existing prover's ring.
    active_on_current_ring: u64,
    /// Provers that would share the joiner's ring (existing + joiner).
    active_on_joiner_ring: u64,
}

/// Compute ring metadata from a total count of active+joining provers.
fn compute_shard_ring_info(total_active_joining: usize) -> ShardRingInfo {
    let mut ri = ShardRingInfo {
        current_ring: 0,
        joiner_ring: 0,
        active_on_current_ring: 0,
        active_on_joiner_ring: 0,
    };

    if total_active_joining > 0 {
        ri.current_ring = ((total_active_joining - 1) / 8) as u8;
    }
    ri.joiner_ring = (total_active_joining / 8) as u8;

    ri.active_on_current_ring = (total_active_joining % 8) as u64;
    if ri.active_on_current_ring == 0 && total_active_joining > 0 {
        ri.active_on_current_ring = 8;
    }

    ri.active_on_joiner_ring = (total_active_joining % 8) as u64 + 1;

    ri
}

/// Determine the ring and on-ring count for a shard entry.
///
/// - `total_candidates`: number of active+joining provers on the shard.
/// - `is_allocated`: whether the local prover is allocated to this shard.
/// - `self_address`: the local prover's address (may be empty).
/// - `candidate_addrs`: sorted candidate addresses (only used when
/// `is_allocated && !self_address.is_empty()`).
///
/// Returns `(ring, on_ring)`.
pub fn resolve_prover_ring(
    total_candidates: usize,
    is_allocated: bool,
    self_address: &[u8],
    candidate_addrs: &[Vec<u8>],
) -> (u8, usize) {
    let ri = compute_shard_ring_info(total_candidates);

    if !is_allocated || self_address.is_empty() {
        return (ri.joiner_ring, ri.active_on_joiner_ring as usize);
    }

    // Find this prover's actual rank in the sorted candidate list.
    for (rank, addr) in candidate_addrs.iter().enumerate() {
        if addr.as_slice() == self_address {
            let ring = (rank / 8) as u8;
            let ring_start = rank - (rank % 8);
            let mut on_ring = total_candidates - ring_start;
            if on_ring > 8 {
                on_ring = 8;
            }
            return (ring, on_ring);
        }
    }

    // Allocated but not in the active/joining candidate list (leaving
    // / paused). Fall back to the last-existing-prover's ring. Go
    // parity with `worker_allocator.go::resolveProverRing`'s tail
    // branch.
    (ri.current_ring, ri.active_on_current_ring as usize)
}

// ---------------------------------------------------------------------------
// isqrt — integer square root
// ---------------------------------------------------------------------------

/// Integer square root of `n` using Newton's method.
///
/// Returns the largest integer `x` such that `x * x <= n`.
/// Matches Go's `isqrt` in `shard_info.go`.
pub fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    // Use u128 internally to avoid overflow for large u64 values.
    let n128 = n as u128;
    let mut x = n128;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n128 / x) / 2;
    }
    x as u64
}

/// Integer square root for `BigInt`. Uses Newton's method.
/// Returns the largest `BigInt` `x` such that `x * x <= n`.
/// Returns zero for non-positive inputs.
pub fn isqrt_big(n: &BigInt) -> BigInt {
    if *n <= BigInt::zero() {
        return BigInt::zero();
    }

    let one = BigInt::one();
    let two = &one + &one;
    let mut x = n.clone();
    let mut y = (&x + &one) / &two;
    while y < x {
        x = y.clone();
        y = (&x + n / &x) / &two;
    }
    x
}

// ---------------------------------------------------------------------------
// compute_shard_reward — per-prover per-frame reward estimate
// ---------------------------------------------------------------------------

/// Compute the per-prover per-frame reward estimate for a shard.
///
/// Uses the canonical issuance arithmetic, including fractional square roots
/// and final truncation. Membership/ring selection remains the caller's job.
pub fn compute_shard_reward(
    basis: &BigInt,
    shard_size: &BigInt,
    world_bytes: &BigInt,
    ring: u8,
    data_shards: u64,
) -> BigInt {
    quil_execution::pricing::allocation_prover_reward(
        basis, shard_size, world_bytes, ring, data_shards,
    )
}

// ---------------------------------------------------------------------------
// build_shard_entries — iterate shards and enrich with registry data
// ---------------------------------------------------------------------------

/// Sort key for ring assignment candidates. Mirrors Go's sort in
/// `buildShardEntries`: joinFrame ASC, seniority DESC, address ASC.
#[derive(Debug, Clone)]
struct RingCandidate {
    join_frame: u64,
    seniority: u64,
    address: Vec<u8>,
    /// The ring the allocation records.
    ring: u8,
}

/// Build shard entries from raw shard data and a size-fetching function.
///
/// This is the core of `GetShardInfo`: for each shard, fetch sub-shard
/// sizes, filter by allocation, look up provers from the registry, and
/// compute the ring assignment.
///
/// `get_sizes` is a closure that takes `(shard_key, &ShardInfo)` and
/// returns a list of `ShardSizeEntry` items.
///
/// `frame_number` anchors the 720-frame expiry check inside the
/// per-shard candidate loop. The caller's pre-built
/// `allocated_filters` set already applies this expiry; the candidate
/// loop has its own independent path (`get_provers(bp)` →
/// per-allocation filter match) that ALSO needs the check, otherwise
/// expired Joining allocs leak into `in_candidates → is_alloc` and
/// the server reports `IsAllocated=true` for shards the user has
/// long since timed out of.
pub fn build_shard_entries<F>(
    shards: &[ShardInfo],
    get_sizes: &F,
    allocated_filters: &HashSet<Vec<u8>>,
    self_address: &[u8],
    include_all: bool,
    prover_registry: &dyn ProverRegistry,
    frame_number: u64,
) -> (Vec<ShardEntry>, BigInt)
where
    F: Fn(&[u8], &ShardInfo) -> Result<Vec<ShardSizeEntry>>,
{
    let mut world_bytes = BigInt::zero();
    let mut entries = Vec::new();

    for shard_info in shards {
        let shard_key = &shard_info.shard_key;
        let resp = match get_sizes(shard_key, shard_info) {
            Ok(v) => v,
            Err(_) => continue,
        };

        for shard in &resp {
            let size = BigInt::from_bytes_be(num_bigint::Sign::Plus, &shard.size);

            // `ShardInfo.shard_key` is 35 bytes: `L1[3] ++ L2[32]`.
            let l2 = if shard_key.len() >= 35 {
                &shard_key[3..35]
            } else if shard_key.len() > 3 {
                &shard_key[3..]
            } else {
                &shard_key[..]
            };
            // Canonical prefix → filter (sentinel-aware) so `allocated_filters` /
            // `get_provers` match a deep shard's real ConfirmationFilter.
            let bp = quil_forest::shard_prefix_to_filter(l2, &shard.prefix);

            let is_alloc = allocated_filters.contains(&bp);

            // Skip size-zero shards from world_bytes accumulation
            // (Go parity), but still emit an entry when we're
            // allocated to it — otherwise the TUI's
            // `rewardByFilter[filterHex]` lookup misses and a
            // freshly-Joining row shows reward=0 with the row
            // disconnected from any size/provers/ring data. The
            // entry's reward will be 0 anyway when size=0; what
            // matters is that the alloc row enriches.
            if size.is_zero() && !is_alloc {
                continue;
            }
            if !size.is_zero() {
                world_bytes += &size;
            }

            if !include_all && !is_alloc {
                continue;
            }

            let prs = match prover_registry.get_provers(&bp) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Build sorted ring candidates for TUI display.
            //
            // Includes Joining, Active, Paused, and Leaving (all
            // "live" states — `is_live`). Expired Joining/Leaving and
            // terminal states (Rejected, Kicked) are correctly
            // excluded — those provers no longer hold the slot.
            //
            // Diverges intentionally from Go's `shard_info.go:221`
            // and from the `is_allocated` rule (Active+Joining only).
            // The strict Active+Joining filter is right for the
            // *protocol's* ring-assignment math (a Leaving prover
            // makes room for a fresh joiner who lands at the tail
            // rank), but wrong for display: until the 360-frame
            // leave-confirm window elapses, the leaving prover is
            // still on whatever ring they were on and still earning
            // that ring's reward. Filtering them out of the candidate
            // list silently shifts every other prover's rank by one
            // and makes `resolve_prover_ring` fall through to its
            // "not in candidates" tail branch, returning the
            // *post-leave* network's last-prover ring rather than
            // the leaver's actual current rank.
            let mut candidates: Vec<RingCandidate> = Vec::new();
            for pr in &prs {
                for alloc in &pr.allocations {
                    if alloc.confirmation_filter != bp {
                        continue;
                    }
                    if alloc.is_live(frame_number) {
                        let jf = if alloc.join_frame_number == 0
                            && alloc.join_confirm_frame_number != 0
                        {
                            alloc.join_confirm_frame_number
                        } else {
                            alloc.join_frame_number
                        };
                        candidates.push(RingCandidate {
                            join_frame: jf,
                            seniority: pr.seniority,
                            address: pr.address.clone(),
                            ring: alloc.ring,
                        });
                    }
                    break;
                }
            }

            // Sort: joinFrame ASC, seniority DESC, address ASC.
            candidates.sort_by(|a, b| {
                a.join_frame
                    .cmp(&b.join_frame)
                    .then_with(|| b.seniority.cmp(&a.seniority))
                    .then_with(|| a.address.cmp(&b.address))
            });

            let candidate_addrs: Vec<Vec<u8>> =
                candidates.iter().map(|c| c.address.clone()).collect();

            // Derive is_alloc from the candidate list (the registry's
            // authoritative per-shard prover view), not just from the
            // caller-supplied allocated_filters byte set. This handles
            // the case where the local prover_info's `confirmation_filter`
            // doesn't byte-match the reconstructed `bp` — we may still be
            // listed under this shard in the registry's filter cache. The
            // ring math then correctly returns rank-based, and the
            // TUI shelves the row in the upper "Allocations" panel.
            let in_candidates = !self_address.is_empty()
                && candidate_addrs.iter().any(|a| a.as_slice() == self_address);
            let real_is_alloc = is_alloc || in_candidates;

            let (mut ring, mut on_ring) = resolve_prover_ring(
                candidates.len(),
                real_is_alloc,
                self_address,
                &candidate_addrs,
            );
            // Under the seniority ring rule a member's ring is the one its
            // allocation records (fixed when its committee formed), not a rank
            // recomputed here.
            if quil_execution::global_intrinsic::prover_rings::governs(frame_number) {
                if let Some(own) = candidates.iter().find(|c| c.address.as_slice() == self_address) {
                    ring = own.ring;
                    on_ring = candidates.iter().filter(|c| c.ring == own.ring).count();
                }
            }

            entries.push(ShardEntry {
                filter: bp,
                size,
                data_shards: shard.data_shards,
                total_active: candidates.len(),
                provers_on_ring: on_ring,
                is_allocated: real_is_alloc,
                ring,
                materialized_frame: shard.materialized_frame,
                latest_frame: shard.latest_frame,
            });
        }
    }

    (entries, world_bytes)
}

// ---------------------------------------------------------------------------
// get_shard_info — top-level orchestration
// ---------------------------------------------------------------------------

/// Build the full shard info response.
///
/// This is the Rust equivalent of `GlobalConsensusEngine.GetShardInfo`.
/// It reads the latest frame from the clock store, builds the list of
/// shards from the shards store, enriches each with prover registry
/// data, and computes estimated rewards.
///
/// Returns `(shard_details, difficulty, pomw_basis_value, frame_number)`.
///
/// # Arguments
/// * `include_all` — when false, only return shards the local prover
/// is allocated to.
/// * `self_address` — local prover address (empty slice if unknown).
/// * `allocated_filters` — set of filters this prover is actively on.
/// * `current_frame` — current frame number from the prover registry.
/// * `clock_store` — for fetching the latest global frame.
/// * `shards_store` — for enumerating application shards.
/// * `prover_registry` — for looking up provers per shard.
/// * `get_sizes` — closure to fetch sub-shard size data.
pub fn get_shard_info<F>(
    include_all: bool,
    self_address: &[u8],
    allocated_filters: &HashSet<Vec<u8>>,
    difficulty: u64,
    frame_number: u64,
    shards_store: &dyn ShardsStore,
    prover_registry: &dyn ProverRegistry,
    get_sizes: &F,
) -> Result<(Vec<ShardDetail>, u64, BigInt, u64)>
where
    F: Fn(&[u8], &ShardInfo) -> Result<Vec<ShardSizeEntry>>,
{
    let app_shards = shards_store.range_app_shards()?;

    // Consolidate into high-level L2 shards (dedup by shard_key).
    let mut shard_map: HashMap<Vec<u8>, ShardInfo> = HashMap::new();
    for s in &app_shards {
        shard_map.entry(s.shard_key.clone()).or_insert_with(|| s.clone());
    }
    let shards: Vec<ShardInfo> = shard_map.into_values().collect();

    let (entries, world_bytes) = build_shard_entries(
        &shards,
        get_sizes,
        allocated_filters,
        self_address,
        include_all,
        prover_registry,
        frame_number,
    );

    if world_bytes.is_zero() {
        return Ok((Vec::new(), difficulty, BigInt::zero(), frame_number));
    }

    let basis = pomw_basis(difficulty, world_bytes.to_u64_saturating(), QUIL_TOKEN_UNITS);

    let details: Vec<ShardDetail> = entries
        .iter()
        .map(|entry| {
            let est = compute_shard_reward(
                &basis,
                &entry.size,
                &world_bytes,
                entry.ring,
                entry.data_shards,
            );
            ShardDetail {
                filter: entry.filter.clone(),
                shard_size: entry.size.clone(),
                active_provers: entry.total_active as u32,
                ring: entry.ring as u32,
                estimated_reward: est,
                is_allocated: entry.is_allocated,
                data_shards: entry.data_shards,
                materialized_frame: entry.materialized_frame,
                latest_frame: entry.latest_frame,
            }
        })
        .collect();

    Ok((details, difficulty, basis, frame_number))
}

/// `get_sizes` closure for `get_shard_info` that reads sizes from the
/// local hypergraph CRDT. Falls back to treating the parent shard as
/// the only sub-shard when the layout is empty. An empty shard's committed
/// deliveries come from `sizes`: counting them for every shard took the
/// archive poller 8-26 s per frame (2026-10-04).
pub fn local_app_shard_get_sizes(
    crdt: std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
    shards_store: std::sync::Arc<dyn ShardsStore>,
    sizes: std::sync::Arc<CommittedShardSizes>,
) -> impl Fn(&[u8], &ShardInfo) -> Result<Vec<ShardSizeEntry>> + Send + Sync {
    move |shard_key: &[u8], shard_info: &ShardInfo| -> Result<Vec<ShardSizeEntry>> {
        let committed = crdt
            .read_frame_cursor(&quil_store::encoding::global_materialized_cursor_key())
            .unwrap_or(0);
        let mut sub_shards = shards_store.get_app_shards(shard_key, &[])?;
        if sub_shards.is_empty() {
            sub_shards = vec![shard_info.clone()];
        }

        let mut out = Vec::with_capacity(sub_shards.len());
        for sub in &sub_shards {
            if let Some(meta) = crate::app_shard_metadata::get_app_shard_metadata(&crdt, sub) {
                out.push(ShardSizeEntry {
                    prefix: sub.prefix.clone(),
                    size: sizes.size(&crdt, shard_key, &sub.prefix, meta.size, committed),
                    data_shards: meta.data_shards,
                    materialized_frame: 0,
                    latest_frame: 0,
                });
            }
        }
        Ok(out)
    }
}

/// Size reported per committed-but-undelivered output of an otherwise empty
/// shard. Only "non-zero" matters to the viability gates; this is roughly one
/// coin vertex.
const NOMINAL_DELIVERY_BYTES: u64 = 4096;

/// The size to report for the shard at `(shard_key, prefix)`, measured at
/// `size`. An empty shard is latent, unless the global venue has committed
/// outputs into blocks it owns: those can only land once the shard has a
/// committee to take delivery, so it reports a nominal size per waiting
/// output. Archives answer `GetAppShards` with this too; a regular node's own
/// grid never flips, so its local sizes never reach a split's empty shards.
pub fn reported_shard_size(
    crdt: &std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
    shard_key: &[u8],
    prefix: &[u32],
    size: Vec<u8>,
) -> Vec<u8> {
    if size.iter().any(|byte| *byte != 0) {
        return size;
    }
    match committed_deliveries(crdt, shard_key, prefix).filter(|n| *n > 0) {
        Some(waiting) => waiting.saturating_mul(NOMINAL_DELIVERY_BYTES).to_be_bytes().to_vec(),
        None => size,
    }
}

/// At most one background recount of a shard's size per this long.
pub const RECOUNT_SPACING: std::time::Duration = std::time::Duration::from_secs(30);

/// A kept size is recounted after this long even if the committed frame has
/// not moved: a regular node's GLOBAL cursor need not advance.
pub const MAX_KEPT_AGE: std::time::Duration = std::time::Duration::from_secs(300);

/// [`reported_shard_size`], kept per shard. An empty shard's size counts
/// committed deliveries, GLOBAL records only a GLOBAL commit writes, and
/// counting them reads every block the shard owns (up to 480 at width 9):
/// about 650 ms a shard on a non-avx512 archive, ~30 s for the 48 empty
/// shards after the 837360 split. Counted by the caller under one lock once
/// per committed frame, that stalled a `GetAppShards` for as long and queued
/// every other one behind it for up to 140 s (2026-10-03).
///
/// A shard is counted inline the first time it is asked for. After that a
/// caller gets the last count at once and never waits on a count: once the
/// committed GLOBAL frame moves, one background thread recounts it, at most
/// every [`RECOUNT_SPACING`], and at least every [`MAX_KEPT_AGE`]. Reported
/// sizes lag deliveries by up to that. One instance serves every reader in a
/// node, so each shard is counted once for all of them; a caller that finds a
/// shard's first count running waits for it instead of counting again (a
/// restart's concurrent first callers each counted every shard).
pub struct CommittedShardSizes {
    kept: std::sync::Arc<Kept>,
    recounts: std::sync::OnceLock<std::sync::mpsc::Sender<Recount>>,
    spacing: std::time::Duration,
}

#[derive(Default)]
struct Kept {
    sizes: std::sync::Mutex<std::collections::HashMap<Vec<u8>, KeptSize>>,
    /// Signalled when a first count lands or is abandoned.
    first_counted: std::sync::Condvar,
}

impl Kept {
    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<Vec<u8>, KeptSize>> {
        self.sizes.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

struct KeptSize {
    committed: u64,
    /// `None` while the shard's first count runs.
    size: Option<Vec<u8>>,
    counted: std::time::Instant,
    recounting: bool,
}

struct Recount {
    key: Vec<u8>,
    committed: u64,
    count: Box<dyn FnOnce() -> Vec<u8> + Send>,
}

impl Default for CommittedShardSizes {
    fn default() -> Self {
        Self::with_spacing(RECOUNT_SPACING)
    }
}

impl CommittedShardSizes {
    fn with_spacing(spacing: std::time::Duration) -> Self {
        Self { kept: Default::default(), recounts: std::sync::OnceLock::new(), spacing }
    }

    /// The size to report for `(shard_key, prefix)` measured at `size`, at
    /// the committed GLOBAL frame `committed`.
    pub fn size(
        &self,
        crdt: &std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
        shard_key: &[u8],
        prefix: &[u32],
        size: Vec<u8>,
        committed: u64,
    ) -> Vec<u8> {
        if size.iter().any(|byte| *byte != 0) {
            return size;
        }
        let mut key = shard_key.to_vec();
        key.extend(prefix.iter().flat_map(|part| part.to_be_bytes()));
        let (crdt, shard_key, prefix) = (crdt.clone(), shard_key.to_vec(), prefix.to_vec());
        self.kept_or(committed, key, move || reported_shard_size(&crdt, &shard_key, &prefix, size))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<Vec<u8>, KeptSize>> {
        self.kept.lock()
    }

    fn kept_or(
        &self,
        committed: u64,
        key: Vec<u8>,
        count: impl FnOnce() -> Vec<u8> + Send + 'static,
    ) -> Vec<u8> {
        use quil_execution::step_timing::section;
        let lock_wait = section("size: lock wait");
        let mut kept = self.lock();
        drop(lock_wait);
        let first_count_wait = section("size: first count wait");
        loop {
            let Some(entry) = kept.get_mut(&key) else { break };
            let Some(size) = entry.size.clone() else {
                kept = self.kept.first_counted.wait(kept).unwrap_or_else(|poisoned| poisoned.into_inner());
                continue;
            };
            drop(first_count_wait);
            let age = entry.counted.elapsed();
            let due = (entry.committed != committed && age >= self.spacing) || age >= MAX_KEPT_AGE;
            if due && !entry.recounting {
                entry.recounting = true;
                drop(kept);
                self.recount(Recount { key, committed, count: Box::new(count) });
            }
            return size;
        }
        drop(first_count_wait);
        kept.insert(
            key.clone(),
            KeptSize { committed, size: None, counted: std::time::Instant::now(), recounting: false },
        );
        drop(kept);
        let counted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _timed = section("size: committed deliveries");
            count()
        }));
        let mut kept = self.lock();
        let size = match counted {
            Ok(size) => {
                if let Some(entry) = kept.get_mut(&key) {
                    entry.size = Some(size.clone());
                    entry.counted = std::time::Instant::now();
                }
                Ok(size)
            }
            // A waiter takes the count over.
            Err(panic) => {
                kept.remove(&key);
                Err(panic)
            }
        };
        drop(kept);
        self.kept.first_counted.notify_all();
        size.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    }

    fn recount(&self, job: Recount) {
        let key = job.key.clone();
        let sent = self
            .recounts
            .get_or_init(|| {
                let (sender, jobs) = std::sync::mpsc::channel::<Recount>();
                let kept = self.kept.clone();
                let spawned = std::thread::Builder::new().name("shard-size-recount".into()).spawn(move || {
                    for job in jobs {
                        let counted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job.count)).ok();
                        let mut kept = kept.lock();
                        if let Some(entry) = kept.get_mut(&job.key) {
                            entry.recounting = false;
                            if let Some(size) = counted {
                                entry.size = Some(size);
                                entry.committed = job.committed;
                                entry.counted = std::time::Instant::now();
                            }
                        }
                    }
                });
                if let Err(error) = spawned {
                    tracing::warn!(%error, "shard size recount thread not started; sizes stay as first counted");
                }
                sender
            })
            .send(job)
            .is_ok();
        if !sent {
            if let Some(entry) = self.lock().get_mut(&key) {
                entry.recounting = false;
            }
        }
    }
}

#[cfg(test)]
mod committed_shard_sizes_tests {
    use super::CommittedShardSizes;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn counter(counted: &Arc<AtomicUsize>, n: u8) -> impl FnOnce() -> Vec<u8> + Send + 'static {
        let counted = counted.clone();
        move || {
            counted.fetch_add(1, Ordering::SeqCst);
            vec![n]
        }
    }

    #[test]
    fn a_moved_frame_serves_the_last_count_while_one_recount_runs_behind() {
        let sizes = CommittedShardSizes::with_spacing(std::time::Duration::ZERO);
        let counted = Arc::new(AtomicUsize::new(0));
        assert_eq!(sizes.kept_or(7, vec![1], counter(&counted, 1)), vec![1], "first count is inline");
        assert_eq!(sizes.kept_or(7, vec![1], counter(&counted, 2)), vec![1], "kept within the frame");
        assert_eq!(sizes.kept_or(7, vec![2], counter(&counted, 3)), vec![3], "per shard");
        assert_eq!(counted.load(Ordering::SeqCst), 2);
        assert_eq!(sizes.kept_or(8, vec![1], counter(&counted, 4)), vec![1], "the last count, at once");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while sizes.kept_or(8, vec![1], counter(&counted, 5)) != vec![4] {
            assert!(std::time::Instant::now() < deadline, "the recount never landed");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(counted.load(Ordering::SeqCst), 3, "one recount; callers meanwhile did not count");
    }

    #[test]
    fn concurrent_first_callers_share_one_count() {
        let sizes = Arc::new(CommittedShardSizes::default());
        let counted = Arc::new(AtomicUsize::new(0));
        let callers: Vec<_> = (0..8)
            .map(|_| {
                let (sizes, counted) = (sizes.clone(), counted.clone());
                std::thread::spawn(move || {
                    sizes.kept_or(7, vec![1], move || {
                        counted.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        vec![9]
                    })
                })
            })
            .collect();
        for caller in callers {
            assert_eq!(caller.join().unwrap(), vec![9]);
        }
        assert_eq!(counted.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_abandoned_first_count_is_taken_over() {
        let sizes = Arc::new(CommittedShardSizes::default());
        let first = {
            let sizes = sizes.clone();
            std::thread::spawn(move || {
                sizes.kept_or(7, vec![1], || {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    panic!("count failed")
                })
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(20));
        let counted = Arc::new(AtomicUsize::new(0));
        assert_eq!(sizes.kept_or(7, vec![1], counter(&counted, 3)), vec![3], "the waiter counts");
        assert!(first.join().is_err());
        assert_eq!(counted.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn recounts_are_spaced() {
        let sizes = CommittedShardSizes::with_spacing(std::time::Duration::from_secs(3600));
        let counted = Arc::new(AtomicUsize::new(0));
        assert_eq!(sizes.kept_or(7, vec![1], counter(&counted, 1)), vec![1]);
        assert_eq!(sizes.kept_or(8, vec![1], counter(&counted, 2)), vec![1]);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(counted.load(Ordering::SeqCst), 1, "no recount inside the spacing");
    }
}

/// Outputs and escrows committed into blocks the sub-shard owns, per GLOBAL
/// state. `None` when the shard key or prefix cannot be read as a shard path,
/// or the lookup fails: the shard then simply stays as empty as it measured.
fn committed_deliveries(
    crdt: &std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
    shard_key: &[u8],
    prefix: &[u32],
) -> Option<u64> {
    let application: [u8; 32] = shard_key.get(3..35)?.try_into().ok()?;
    let filter = quil_forest::shard_prefix_to_filter(&application, prefix);
    let (_, bits) = quil_forest::decode_shard_filter_or_root(&filter, 32)?;
    let state = quil_execution::hypergraph_state::HypergraphState::new(crdt.clone());
    quil_execution::token_intrinsic::global_commit::committed_to_shard(&state, &application, &bits).ok()
}

/// Extension trait on BigInt for saturating u64 conversion.
trait BigIntSaturatingU64 {
    fn to_u64_saturating(&self) -> u64;
}

impl BigIntSaturatingU64 for BigInt {
    fn to_u64_saturating(&self) -> u64 {
        use num_traits::ToPrimitive;
        self.to_u64().unwrap_or(u64::MAX)
    }
}

// ---------------------------------------------------------------------------
// Allocation filter builder
// ---------------------------------------------------------------------------

/// Build the set of confirmation filters this prover is actively
/// allocated to, mirroring the Go logic in `GetShardInfo` that
/// skips joining allocations older than 720 frames and leaving
/// allocations older than 720 frames.
pub fn build_allocated_filters(
    prover: &ProverInfo,
    current_frame: u64,
) -> HashSet<Vec<u8>> {
    prover
        .allocations
        .iter()
        .filter(|a| a.is_allocated(current_frame))
        .map(|a| a.confirmation_filter.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- isqrt ----

    #[test]
    fn isqrt_zero() {
        assert_eq!(isqrt(0), 0);
    }

    #[test]
    fn isqrt_one() {
        assert_eq!(isqrt(1), 1);
    }

    #[test]
    fn isqrt_perfect_squares() {
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(16), 4);
        assert_eq!(isqrt(25), 5);
        assert_eq!(isqrt(100), 10);
        assert_eq!(isqrt(10000), 100);
        assert_eq!(isqrt(1_000_000), 1_000);
    }

    #[test]
    fn isqrt_non_perfect() {
        // isqrt(2) = 1, isqrt(3) = 1
        assert_eq!(isqrt(2), 1);
        assert_eq!(isqrt(3), 1);
        // isqrt(5) = 2, isqrt(8) = 2
        assert_eq!(isqrt(5), 2);
        assert_eq!(isqrt(8), 2);
        // isqrt(99) = 9
        assert_eq!(isqrt(99), 9);
        // isqrt(101) = 10
        assert_eq!(isqrt(101), 10);
    }

    #[test]
    fn isqrt_large() {
        // Test with a large perfect square near u64 range.
        // (2^32 - 1)^2 = 18_446_744_065_119_617_025
        let val: u64 = 18_446_744_065_119_617_025;
        assert_eq!(isqrt(val), 4_294_967_295);

        // Large non-perfect squares.
        assert_eq!(isqrt(1_000_000_000_000u64), 1_000_000);
        assert_eq!(isqrt(1_000_000_000_001u64), 1_000_000);
    }

    // ---- isqrt_big ----

    #[test]
    fn isqrt_big_zero_and_negative() {
        assert_eq!(isqrt_big(&BigInt::zero()), BigInt::zero());
        assert_eq!(isqrt_big(&BigInt::from(-5)), BigInt::zero());
    }

    #[test]
    fn isqrt_big_perfect_squares() {
        assert_eq!(isqrt_big(&BigInt::from(1u64)), BigInt::from(1u64));
        assert_eq!(isqrt_big(&BigInt::from(4u64)), BigInt::from(2u64));
        assert_eq!(isqrt_big(&BigInt::from(9u64)), BigInt::from(3u64));
        assert_eq!(isqrt_big(&BigInt::from(10000u64)), BigInt::from(100u64));
    }

    #[test]
    fn isqrt_big_non_perfect() {
        // isqrt(2) = 1
        assert_eq!(isqrt_big(&BigInt::from(2u64)), BigInt::from(1u64));
        // isqrt(99) = 9
        assert_eq!(isqrt_big(&BigInt::from(99u64)), BigInt::from(9u64));
    }

    // ---- compute_shard_reward ----

    #[test]
    fn compute_shard_reward_zero_basis() {
        let r = compute_shard_reward(
            &BigInt::zero(),
            &BigInt::from(1000u64),
            &BigInt::from(10000u64),
            0,
            1,
        );
        assert!(r.is_zero());
    }

    #[test]
    fn compute_shard_reward_zero_world() {
        let r = compute_shard_reward(
            &BigInt::from(1000u64),
            &BigInt::from(1000u64),
            &BigInt::zero(),
            0,
            1,
        );
        assert!(r.is_zero());
    }

    #[test]
    fn compute_shard_reward_zero_data_shards() {
        let r = compute_shard_reward(
            &BigInt::from(1000u64),
            &BigInt::from(1000u64),
            &BigInt::from(10000u64),
            0,
            0,
        );
        assert!(r.is_zero());
    }

    #[test]
    fn compute_shard_reward_basic() {
        // basis = 1_000_000, shard_size = 500, world_bytes = 1000
        // factor = 500 * 1_000_000 / 1000 = 500_000
        // ring=0: divisor = 2^1 = 2 → 500_000/2 = 250_000
        // data_shards=1: no sqrt division
        // /8 → 250_000/8 = 31_250
        let r = compute_shard_reward(
            &BigInt::from(1_000_000u64),
            &BigInt::from(500u64),
            &BigInt::from(1000u64),
            0,
            1,
        );
        assert_eq!(r, BigInt::from(31_250u64));
    }

    #[test]
    fn compute_shard_reward_higher_ring() {
        // Same as basic but ring=1: divisor = 2^2 = 4
        // factor = 500_000 / 4 = 125_000
        // /8 → 125_000 / 8 = 15_625
        let r = compute_shard_reward(
            &BigInt::from(1_000_000u64),
            &BigInt::from(500u64),
            &BigInt::from(1000u64),
            1,
            1,
        );
        assert_eq!(r, BigInt::from(15_625u64));
    }

    #[test]
    fn compute_shard_reward_with_sqrt_shards() {
        // basis = 1_000_000, shard_size = 1000, world_bytes = 1000
        // factor = 1000 * 1_000_000 / 1000 = 1_000_000
        // ring=0: divisor=2 → 500_000
        // data_shards=4: sqrt(4)=2 → 250_000
        // /8 → 31_250
        let r = compute_shard_reward(
            &BigInt::from(1_000_000u64),
            &BigInt::from(1000u64),
            &BigInt::from(1000u64),
            0,
            4,
        );
        assert_eq!(r, BigInt::from(31_250u64));
    }

    #[test]
    fn compute_shard_reward_ring_halves() {
        // Increasing ring should halve the reward each time.
        let basis = BigInt::from(10_000_000u64);
        let size = BigInt::from(1000u64);
        let world = BigInt::from(1000u64);

        let r0 = compute_shard_reward(&basis, &size, &world, 0, 1);
        let r1 = compute_shard_reward(&basis, &size, &world, 1, 1);
        let r2 = compute_shard_reward(&basis, &size, &world, 2, 1);

        // Each successive ring halves the reward (integer division).
        assert_eq!(&r0 / 2, r1, "ring 1 should be half of ring 0");
        assert_eq!(&r1 / 2, r2, "ring 2 should be half of ring 1");
    }

    // ---- resolve_prover_ring ----

    #[test]
    fn resolve_ring_not_allocated() {
        // Not allocated: returns joiner ring.
        let (ring, on_ring) = resolve_prover_ring(10, false, &[], &[]);
        // 10 provers: joiner_ring = 10/8 = 1, active_on_joiner = 10%8 +1 = 3
        assert_eq!(ring, 1);
        assert_eq!(on_ring, 3);
    }

    #[test]
    fn resolve_ring_allocated_found() {
        let addrs: Vec<Vec<u8>> = (0u8..10).map(|i| vec![i]).collect();
        // Prover at index 3 → ring 0 (3/8=0), on_ring = min(10-0, 8) = 8
        let (ring, on_ring) = resolve_prover_ring(10, true, &[3u8], &addrs);
        assert_eq!(ring, 0);
        assert_eq!(on_ring, 8);

        // Prover at index 8 → ring 1 (8/8=1), ring_start=8, on_ring=10-8=2
        let (ring, on_ring) = resolve_prover_ring(10, true, &[8u8], &addrs);
        assert_eq!(ring, 1);
        assert_eq!(on_ring, 2);
    }

    #[test]
    fn resolve_ring_allocated_not_found() {
        // Prover allocated but not in candidate list (leaving/paused).
        let addrs: Vec<Vec<u8>> = (0u8..10).map(|i| vec![i]).collect();
        let (ring, on_ring) = resolve_prover_ring(10, true, &[99u8], &addrs);
        // Falls back to current_ring: (10-1)/8 = 1,
        // active_on_current_ring: 10%8 = 2
        assert_eq!(ring, 1);
        assert_eq!(on_ring, 2);
    }

    #[test]
    fn resolve_ring_empty_shard() {
        let (ring, on_ring) = resolve_prover_ring(0, false, &[], &[]);
        assert_eq!(ring, 0);
        assert_eq!(on_ring, 1);
    }

    // ---- compute_shard_ring_info ----

    #[test]
    fn ring_info_boundaries() {
        // 0 provers
        let ri = compute_shard_ring_info(0);
        assert_eq!(ri.current_ring, 0);
        assert_eq!(ri.joiner_ring, 0);
        assert_eq!(ri.active_on_current_ring, 0);
        assert_eq!(ri.active_on_joiner_ring, 1);

        // 1 prover
        let ri = compute_shard_ring_info(1);
        assert_eq!(ri.current_ring, 0);
        assert_eq!(ri.joiner_ring, 0);
        assert_eq!(ri.active_on_current_ring, 1);
        assert_eq!(ri.active_on_joiner_ring, 2);

        // 8 provers (full ring 0)
        let ri = compute_shard_ring_info(8);
        assert_eq!(ri.current_ring, 0);
        assert_eq!(ri.joiner_ring, 1);
        assert_eq!(ri.active_on_current_ring, 8);
        assert_eq!(ri.active_on_joiner_ring, 1);

        // 9 provers (ring 0 full, ring 1 has 1)
        let ri = compute_shard_ring_info(9);
        assert_eq!(ri.current_ring, 1);
        assert_eq!(ri.joiner_ring, 1);
        assert_eq!(ri.active_on_current_ring, 1);
        assert_eq!(ri.active_on_joiner_ring, 2);

        // 16 provers (ring 0 + ring 1 full)
        let ri = compute_shard_ring_info(16);
        assert_eq!(ri.current_ring, 1);
        assert_eq!(ri.joiner_ring, 2);
        assert_eq!(ri.active_on_current_ring, 8);
        assert_eq!(ri.active_on_joiner_ring, 1);
    }

    // ---- build_allocated_filters ----

    #[test]
    fn build_filters_active_allocations() {
        use quil_types::consensus::ProverAllocationInfo;

        let prover = ProverInfo {
            public_key: vec![],
            address: vec![1, 2, 3],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![
                ProverAllocationInfo {
                    status: ProverStatus::Active,
                    confirmation_filter: vec![0xAA, 0xBB],
                    rejection_filter: vec![],
                    join_frame_number: 100,
                    leave_frame_number: 0,
                    pause_frame_number: 0,
                    resume_frame_number: 0,
                    kick_frame_number: 0,
                    join_confirm_frame_number: 0,
                    join_reject_frame_number: 0,
                    leave_confirm_frame_number: 0,
                    leave_reject_frame_number: 0,
                    last_active_frame_number: 0,
                    // Confirmed for the current epoch (eval frame 2000 → epoch 2)
                    // so always-on epoch expiry doesn't read it as ExpiredEpoch.
                    epoch: 2,
                    ring: 0,
                    vertex_address: vec![],
                },
                ProverAllocationInfo {
                    status: ProverStatus::Joining,
                    confirmation_filter: vec![0xCC, 0xDD],
                    rejection_filter: vec![],
                    // Proposed in epoch 1; still within its epoch-2 confirm window.
                    join_frame_number: 900,
                    leave_frame_number: 0,
                    pause_frame_number: 0,
                    resume_frame_number: 0,
                    kick_frame_number: 0,
                    join_confirm_frame_number: 0,
                    join_reject_frame_number: 0,
                    leave_confirm_frame_number: 0,
                    leave_reject_frame_number: 0,
                    last_active_frame_number: 0,
                    epoch: 0,
                    ring: 0,
                    vertex_address: vec![],
                },
                // Joining but expired: proposed in epoch 0, never confirmed in
                // epoch 1 → implicitly rejected by epoch 2.
                ProverAllocationInfo {
                    status: ProverStatus::Joining,
                    confirmation_filter: vec![0xEE],
                    rejection_filter: vec![],
                    join_frame_number: 100,
                    leave_frame_number: 0,
                    pause_frame_number: 0,
                    resume_frame_number: 0,
                    kick_frame_number: 0,
                    join_confirm_frame_number: 0,
                    join_reject_frame_number: 0,
                    leave_confirm_frame_number: 0,
                    leave_reject_frame_number: 0,
                    last_active_frame_number: 0,
                    epoch: 0,
                    ring: 0,
                    vertex_address: vec![],
                },
            ],
            available_storage: 0,
            seniority: 100,
            delegate_address: vec![],
        };

        let filters = build_allocated_filters(&prover, 2000); // epoch 2
        assert!(filters.contains(&vec![0xAA, 0xBB]));
        assert!(filters.contains(&vec![0xCC, 0xDD]));
        // Expired joining allocation should be excluded.
        assert!(!filters.contains(&vec![0xEE]));
    }

    // ---- end-to-end integration ----------------------------------------
    //
    // Drives the production path: hypergraph CRDT (with vertices) +
    // ShardsStore (with persisted shard entries) → `get_shard_info`
    // with the same `local_app_shard_get_sizes` closure that
    // `LocalShardInfoProvider` uses. Asserts non-zero size, non-zero
    // basis, and a populated reward — the values the qclient
    // `prover manage` TUI displays.

    use std::sync::{Arc, Mutex};

    use quil_hypergraph::{HypergraphCrdt, Location};
    use quil_types::consensus::{
        ProverAllocationInfo, ProverInfo, ProverShardSummary, ProverStatus,
    };
    use quil_types::crypto::{InclusionProver, Multiproof};
    use quil_types::error::{QuilError, Result as QResult};
    use quil_types::store::{
        ChangeRecord, HypergraphStore, ShardKey as TypedShardKey, ShardsStore as ShardsStoreTrait,
        Transaction,
    };

    struct E2EShardsStore {
        shards: Mutex<Vec<ShardInfo>>,
    }

    impl E2EShardsStore {
        fn new() -> Self {
            Self { shards: Mutex::new(Vec::new()) }
        }
        fn push(&self, info: ShardInfo) {
            self.shards.lock().unwrap().push(info);
        }
    }

    impl ShardsStoreTrait for E2EShardsStore {
        fn range_app_shards(&self) -> QResult<Vec<ShardInfo>> {
            Ok(self.shards.lock().unwrap().clone())
        }
        fn get_app_shards(&self, shard_key: &[u8], _prefix: &[u32]) -> QResult<Vec<ShardInfo>> {
            Ok(self
                .shards
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.shard_key == shard_key)
                .cloned()
                .collect())
        }
        fn put_app_shard(&self, _: &dyn Transaction, shard: &ShardInfo) -> QResult<()> {
            self.shards.lock().unwrap().push(shard.clone());
            Ok(())
        }
        fn delete_app_shard(&self, _: &dyn Transaction, _key: &[u8], _prefix: &[u32]) -> QResult<()> {
            Ok(())
        }
    }

    struct E2EHgStore {
        nodes: Mutex<HashMap<String, Vec<u8>>>,
        per_vertex: Mutex<HashMap<(String, Vec<u8>), Vec<u8>>>,
    }
    impl E2EHgStore {
        fn new() -> Self {
            Self {
                nodes: Mutex::new(HashMap::new()),
                per_vertex: Mutex::new(HashMap::new()),
            }
        }
        fn key(set: &str, phase: &str, shard: &TypedShardKey, k: &[u8]) -> String {
            format!("{}/{}/{:?}{:?}/{:?}", set, phase, shard.l1, shard.l2, k)
        }
        fn scope(set: &str, phase: &str, shard: &TypedShardKey) -> String {
            format!("{}/{}/{:?}{:?}", set, phase, shard.l1, shard.l2)
        }
    }
    struct NoopTxn;
    impl Transaction for NoopTxn {
        fn get(&self, _: &[u8]) -> QResult<Option<Vec<u8>>> { Ok(None) }
        fn set(&self, _: &[u8], _: &[u8]) -> QResult<()> { Ok(()) }
        fn commit(self: Box<Self>) -> QResult<()> { Ok(()) }
        fn delete(&self, _: &[u8]) -> QResult<()> { Ok(()) }
        fn abort(self: Box<Self>) -> QResult<()> { Ok(()) }
        fn new_iter(&self, _: &[u8], _: &[u8]) -> QResult<Box<dyn quil_types::store::Iterator>> {
            Err(QuilError::Internal("noop".into()))
        }
        fn delete_range(&self, _: &[u8], _: &[u8]) -> QResult<()> { Ok(()) }
        fn as_any(&self) -> &dyn std::any::Any { self }
    }
    impl HypergraphStore for E2EHgStore {
        fn new_transaction(&self, _: bool) -> QResult<Box<dyn Transaction>> { Ok(Box::new(NoopTxn)) }
        fn get_node_by_key(&self, set: &str, phase: &str, shard: &TypedShardKey, k: &[u8]) -> QResult<Option<Vec<u8>>> {
            Ok(self.nodes.lock().unwrap().get(&Self::key(set, phase, shard, k)).cloned())
        }
        fn get_node_by_path(&self, _: &str, _: &str, _: &TypedShardKey, _: &[i32]) -> QResult<Option<Vec<u8>>> { Ok(None) }
        fn insert_node(&self, _: &dyn Transaction, set: &str, phase: &str, shard: &TypedShardKey, k: &[u8], _: &[i32], data: &[u8]) -> QResult<()> {
            self.nodes.lock().unwrap().insert(Self::key(set, phase, shard, k), data.to_vec());
            if k != [0xFFu8; 32] {
                self.per_vertex.lock().unwrap().insert((Self::scope(set, phase, shard), k.to_vec()), data.to_vec());
            }
            Ok(())
        }
        fn save_root(&self, _: &dyn Transaction, _: &str, _: &str, _: &TypedShardKey, _: &[u8]) -> QResult<()> { Ok(()) }
        fn delete_node(&self, _: &dyn Transaction, _: &str, _: &str, _: &TypedShardKey, _: &[u8], _: &[i32]) -> QResult<()> { Ok(()) }
        fn set_covered_prefix(&self, _: &[i32]) -> QResult<()> { Ok(()) }
        fn set_shard_commit(&self, _: &dyn Transaction, _: u64, _: &str, _: &str, _: &[u8], _: &[u8]) -> QResult<()> { Ok(()) }
        fn get_shard_commit(&self, _: u64, _: &str, _: &str, _: &[u8]) -> QResult<Vec<u8>> { Ok(vec![]) }
        fn get_root_commits(&self, _: u64) -> QResult<HashMap<TypedShardKey, Vec<Vec<u8>>>> { Ok(HashMap::new()) }
        fn load_vertex_underlying_raw(&self, set: &str, phase: &str, shard: &TypedShardKey, k: &[u8]) -> QResult<Option<Vec<u8>>> {
            Ok(self.nodes.lock().unwrap().get(&Self::key(set, phase, shard, k)).cloned())
        }
        fn save_vertex_underlying(&self, _txn: &dyn quil_types::store::Transaction, set: &str, phase: &str, shard: &TypedShardKey, k: &[u8], d: &[u8]) -> QResult<()> {
            self.nodes.lock().unwrap().insert(Self::key(set, phase, shard, k), d.to_vec());
            self.per_vertex.lock().unwrap().insert((Self::scope(set, phase, shard), k.to_vec()), d.to_vec());
            Ok(())
        }
        fn for_each_vertex_underlying(&self, set: &str, phase: &str, shard: &TypedShardKey, callback: &mut dyn FnMut(Vec<u8>, Vec<u8>)) -> QResult<usize> {
            let scope = Self::scope(set, phase, shard);
            let mut count = 0usize;
            for ((s, vk), v) in self.per_vertex.lock().unwrap().iter() {
                if s == &scope {
                    callback(vk.clone(), v.clone());
                    count += 1;
                }
            }
            Ok(count)
        }
        fn apply_snapshot(&self, _: &str) -> QResult<()> { Ok(()) }
        fn set_alt_shard_commit(&self, _: &dyn Transaction, _: u64, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> QResult<()> { Ok(()) }
        fn get_latest_alt_shard_commit(&self, _: &[u8]) -> QResult<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> { Ok((vec![], vec![], vec![], vec![])) }
        fn range_alt_shard_addresses(&self) -> QResult<Vec<Vec<u8>>> { Ok(vec![]) }
        fn reap_old_changesets(&self, _: &dyn Transaction, _: u64) -> QResult<()> { Ok(()) }
        fn track_change(&self, _: &dyn Transaction, _: &[u8], _: Option<&[u8]>, _: u64, _: &str, _: &str, _: &TypedShardKey) -> QResult<()> { Ok(()) }
        fn get_changes(&self, _: u64, _: u64, _: &str, _: &str, _: &TypedShardKey) -> QResult<Vec<ChangeRecord>> { Ok(vec![]) }
        fn untrack_change(&self, _: &dyn Transaction, _: &[u8], _: u64, _: &str, _: &str, _: &TypedShardKey) -> QResult<()> { Ok(()) }
    }

    struct StubInclusion;
    impl InclusionProver for StubInclusion {
        fn commit_raw(&self, data: &[u8], _: u64) -> QResult<Vec<u8>> {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            data.hash(&mut h);
            let hash = h.finish().to_be_bytes();
            let mut out = vec![0u8; 64];
            out[..8].copy_from_slice(&hash);
            Ok(out)
        }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> QResult<Vec<u8>> { Ok(vec![0u8; 64]) }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> QResult<bool> { Ok(true) }
        fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> QResult<Box<dyn Multiproof>> {
            Err(QuilError::Internal("nope".into()))
        }
        fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
    }

    struct StubRegistry {
        prover_addr: Vec<u8>,
        prover_pubkey: Vec<u8>,
    }
    impl ProverRegistry for StubRegistry {
        fn get_prover_info(&self, _: &[u8]) -> QResult<Option<ProverInfo>> { Ok(None) }
        fn get_next_prover(&self, _: &[u8; 32], _: &[u8], _: u64) -> QResult<Vec<u8>> { Ok(vec![]) }
        fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8], _: u64) -> QResult<Vec<Vec<u8>>> { Ok(vec![]) }
        fn get_active_provers(&self, _: &[u8], _: u64) -> QResult<Vec<ProverInfo>> { Ok(vec![]) }
        fn get_prover_count(&self, _: &[u8]) -> QResult<usize> { Ok(0) }
        fn get_provers(&self, filter: &[u8]) -> QResult<Vec<ProverInfo>> {
            // Single Active prover on every queried filter.
            Ok(vec![ProverInfo {
                public_key: self.prover_pubkey.clone(),
                address: self.prover_addr.clone(),
                status: ProverStatus::Active,
                kick_frame_number: 0,
                allocations: vec![ProverAllocationInfo {
                    status: ProverStatus::Active,
                    confirmation_filter: filter.to_vec(),
                    rejection_filter: vec![],
                    join_frame_number: 1,
                    leave_frame_number: 0,
                    pause_frame_number: 0,
                    resume_frame_number: 0,
                    kick_frame_number: 0,
                    join_confirm_frame_number: 2,
                    join_reject_frame_number: 0,
                    leave_confirm_frame_number: 0,
                    leave_reject_frame_number: 0,
                    last_active_frame_number: 100,
                    epoch: 0,
                    ring: 0,
                    vertex_address: vec![],
                }],
                available_storage: 1 << 30,
                seniority: 0,
                delegate_address: vec![],
            }])
        }
        fn get_provers_by_status(&self, _: &[u8], _: ProverStatus) -> QResult<Vec<ProverInfo>> { Ok(vec![]) }
        fn get_prover_shard_summaries(&self, _: u64) -> QResult<Vec<ProverShardSummary>> { Ok(vec![]) }
    }

    #[test]
    fn end_to_end_get_shard_info_reports_real_size_and_reward() {
        // Build the full chain that the production
        // `LocalShardInfoProvider` exercises.
        let hg_store: Arc<dyn HypergraphStore> = Arc::new(E2EHgStore::new());
        let prover: Arc<dyn InclusionProver> = Arc::new(StubInclusion);
        let crdt = Arc::new(HypergraphCrdt::new(hg_store, prover));

        // Insert a vertex so `vertex_adds` has a leaf with non-zero size.
        let mut app_address = [0xCDu8; 32];
        app_address[0] = 0xAB;
        let location = Location {
            app_address,
            data_address: [0x11u8; 32],
        };
        let payload = b"some-vertex-payload-for-size-check";
        crdt.add_vertex(&location, payload).unwrap();

        // Persist the shard entry the way the global intrinsic would
        // — `shard_key = L1 || L2`, no sub-prefix.
        let typed_key = quil_hypergraph::addressing::shard_key_for_location(&location);
        let mut shard_key_bytes = Vec::with_capacity(35);
        shard_key_bytes.extend_from_slice(&typed_key.l1);
        shard_key_bytes.extend_from_slice(&typed_key.l2);
        let shards_store = Arc::new(E2EShardsStore::new());
        shards_store.push(ShardInfo {
            shard_key: shard_key_bytes.clone(),
            prefix: vec![],
            size: vec![],
            data_shards: 0,
            commitment: vec![],
        });

        // Stub a registry that returns 1 Active prover for any filter.
        let prover_addr = vec![0x77u8; 32];
        let registry = StubRegistry {
            prover_addr: prover_addr.clone(),
            prover_pubkey: vec![0xBBu8; 74],
        };

        let get_sizes = local_app_shard_get_sizes(
            crdt.clone(),
            shards_store.clone() as Arc<dyn ShardsStoreTrait>,
            Arc::new(CommittedShardSizes::default()),
        );

        // Mirror what `LocalShardInfoProvider` builds: we are the
        // single allocated prover, so include the shard via
        // allocated_filters. (`include_all=false` would also include
        // it; `include_all=true` includes everything.)
        let allocated_filters: HashSet<Vec<u8>> =
            std::iter::once(typed_key.l2.to_vec()).collect();

        let (details, difficulty, basis, frame_number) = get_shard_info(
            true,           // include_all
            &prover_addr,
            &allocated_filters,
            10_000,         // difficulty (non-zero so basis > 0)
            123,            // frame_number
            shards_store.as_ref(),
            &registry,
            &get_sizes,
        )
        .expect("get_shard_info must succeed");

        // Sanity: non-zero output everywhere.
        assert_eq!(difficulty, 10_000);
        assert_eq!(frame_number, 123);
        assert!(
            !details.is_empty(),
            "details must not be empty — TUI shows zero rows otherwise"
        );
        assert!(
            !basis.is_zero(),
            "pomw_basis must be non-zero — reward depends on it"
        );

        let entry = &details[0];
        assert!(
            !entry.shard_size.is_zero(),
            "shard_size must be non-zero — TUI shows 0 otherwise"
        );
        assert_eq!(
            entry.shard_size,
            num_bigint::BigInt::from(payload.len()),
            "shard_size should match the inserted vertex payload length"
        );
        assert!(
            entry.data_shards >= 1,
            "data_shards must be >= 1 — TUI shows 0 otherwise"
        );
        assert!(
            entry.active_provers >= 1,
            "active_provers must be >= 1 — TUI shows 0 otherwise"
        );
        assert!(
            !entry.estimated_reward.is_zero(),
            "estimated_reward must be non-zero — TUI shows 0 otherwise"
        );
    }

    /// A non-archive prover allocated to one shard out of many. The
    /// local hypergraph only carries data for that one shard; the
    /// other shard entries score zero locally and get dropped. The
    /// remote-fallback trigger logic in `LocalShardInfoProvider`
    /// should kick in because `details.len() < shard_count`. This
    /// test pins down the *signal* the trigger relies on: that local
    /// `get_shard_info` returns fewer entries than the unique shard
    /// count, so the trigger has something to detect.
    #[test]
    fn partial_local_returns_fewer_entries_than_shards() {
        let hg_store: Arc<dyn HypergraphStore> = Arc::new(E2EHgStore::new());
        let prover: Arc<dyn InclusionProver> = Arc::new(StubInclusion);
        let crdt = Arc::new(HypergraphCrdt::new(hg_store, prover));

        // Insert vertex on one shard.
        let mut a1 = [0xCDu8; 32];
        a1[0] = 0xAB;
        let loc_a = Location { app_address: a1, data_address: [0x11u8; 32] };
        crdt.add_vertex(&loc_a, b"data-a").unwrap();

        // Persist three shard entries — only the first has trie data.
        let shard_key = |a: &[u8; 32]| {
            let typed = quil_hypergraph::addressing::shard_key_for_location(&Location {
                app_address: *a,
                data_address: [0u8; 32],
            });
            let mut out = Vec::with_capacity(35);
            out.extend_from_slice(&typed.l1);
            out.extend_from_slice(&typed.l2);
            out
        };
        let mut a2 = [0xEFu8; 32];
        a2[0] = 0x12;
        let mut a3 = [0x77u8; 32];
        a3[0] = 0x55;

        let shards_store = Arc::new(E2EShardsStore::new());
        for app in [a1, a2, a3] {
            shards_store.push(ShardInfo {
                shard_key: shard_key(&app),
                prefix: vec![],
                size: vec![],
                data_shards: 0,
                commitment: vec![],
            });
        }

        let prover_addr = vec![0x77u8; 32];
        let registry = StubRegistry {
            prover_addr: prover_addr.clone(),
            prover_pubkey: vec![0xBBu8; 74],
        };
        let get_sizes = local_app_shard_get_sizes(
            crdt.clone(),
            shards_store.clone() as Arc<dyn ShardsStoreTrait>,
            Arc::new(CommittedShardSizes::default()),
        );
        let allocated_filters: HashSet<Vec<u8>> = HashSet::new();

        let (details, _diff, basis, _frame) = get_shard_info(
            true,
            &prover_addr,
            &allocated_filters,
            10_000,
            123,
            shards_store.as_ref(),
            &registry,
            &get_sizes,
        )
        .expect("get_shard_info");

        // Three unique shard_keys persisted; only one has data.
        let unique_shard_keys: std::collections::HashSet<Vec<u8>> = shards_store
            .shards
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.shard_key.clone())
            .collect();
        assert_eq!(unique_shard_keys.len(), 3);
        assert!(!basis.is_zero(), "basis must be non-zero (one shard has data)");
        assert!(
            details.len() < unique_shard_keys.len(),
            "details ({}) must be fewer than shards ({}) — this is the \
             signal `LocalShardInfoProvider` uses to trigger the remote \
             fallback",
            details.len(),
            unique_shard_keys.len()
        );
    }

    /// PARITY: the TUI per-prover estimate (`compute_shard_reward`) must equal
    /// the actually-minted per-prover share (`OptRewardIssuance::calculate / 8`)
    /// for the same inputs. The two API paths must supply the same inputs and use the canonical
    /// arithmetic, including non-square counts and issuance ring clamping.
    #[test]
    fn estimate_matches_minted_per_prover_share() {
        use crate::rewards::{pomw_basis, OptRewardIssuance};
        use quil_types::consensus::{ProverAllocation, RewardIssuance};
        use std::collections::HashMap;
        let difficulty = 5_000u64;
        let world = 1u64 << 30;
        let units = 1_000_000u64;
        let size = 1u64 << 28;
        let basis = pomw_basis(difficulty, world, units);
        for ring in [0u8, 1, 2, 62, 63, 255] {
            for shards in [1u64, 2, 3, 4, 5, 7, 16, u64::MAX] {
                let est = compute_shard_reward(
                    &basis,
                    &BigInt::from(size),
                    &BigInt::from(world),
                    ring,
                    shards,
                );
                let mut m = HashMap::new();
                m.insert("s".to_string(), ProverAllocation { ring, shards, state_size: size });
                let mint =
                    &OptRewardIssuance.calculate(difficulty, world, units, &[m]).unwrap()[0]
                        / 8;
                assert_eq!(est, mint, "ring={ring} shards={shards}: estimate != minted/8");
            }
        }
    }
}

#[cfg(test)]
mod committed_delivery_size_tests {
    use super::*;
    use std::sync::Arc;

    use quil_execution::hypergraph_state::HypergraphState;
    use quil_execution::token_intrinsic::global_commit::{commit_entry, Outcome, SpendEntry};

    // A wallet's claim committed into block 291 is owned by the empty spine
    // shard `001`. If the archives report that shard's size as zero to the
    // regular nodes, none joins it and the claim is never delivered.
    #[test]
    fn an_empty_shard_with_committed_outputs_reports_a_size() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
        let app = [7u8; 32];
        let mut output = [9u8; 32];
        output[0] = 0b0010_0011;
        let entry = SpendEntry {
            kind: 0x0512,
            tx_id: [1; 32],
            source_frame: 40,
            context: [8; 32],
            root_digest: None,
            consumptions: vec![[2; 32]],
            outputs: vec![output],
            escrow_create: None,
            escrow_claim: None,
            fee: 5,
            settlement: None,
        };
        let state = HypergraphState::new(crdt.clone());
        let outcome = commit_entry(&state, 5, &app, &entry, quil_types::execution::ShardPath::WHOLE).unwrap();
        assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
        state.commit().unwrap();

        let shard_key: Vec<u8> = [0u8; 3].into_iter().chain(app).collect();
        let size = |bits: &[bool], measured: Vec<u8>| {
            reported_shard_size(&crdt, &shard_key, &quil_forest::bit_path_to_prefix(bits), measured)
        };
        assert!(size(&[false, false, true], vec![]).iter().any(|b| *b != 0), "the empty shard owning the output");
        assert!(size(&[true], vec![]).iter().all(|b| *b == 0), "an empty shard with nothing waiting");
        assert_eq!(size(&[false, false, true], vec![0, 5]), vec![0, 5], "a measured size is kept");
    }
}
