//! In-memory prover registry built from persisted hypergraph vertices.
//!
//! `InMemoryProverRegistry` walks every persisted vertex under the
//! global prover shard, partitions them by Poseidon type hash (using
//! `global_schema::TYPE_HASH_TABLE`), extracts `prover:Prover` and
//! `allocation:ProverAllocation` fields via the wire-format sub-tree
//! reader (`quil_tries::deserialize_go_tree`), and builds:
//!
//! - `prover_cache: HashMap<Vec<u8>, ProverInfo>` — address → info
//! - `filter_cache: HashMap<Vec<u8>, Vec<Vec<u8>>>` — confirmation
//!   filter → sorted list of prover addresses with an active
//!   allocation under that filter
//! - `address_to_filters: HashMap<Vec<u8>, Vec<Vec<u8>>>` — reverse
//!   index from prover address to the filters it's allocated under
//!
//! Differences from Go:
//!
//! 1. We don't yet implement the `RollingFrecencyCritbitTrie` that Go
//!    uses for `FindNearestAndApproximateNeighbors`. For now we store
//!    filter → sorted `Vec<Vec<u8>>` and do a linear scan. Fine up to
//!    ~10 K provers per filter.
//! 2. We iterate the persisted blob cache
//!    (`RocksHypergraphStore::for_each_vertex_underlying`), not a
//!    live hypergraph iterator.
//! 3. No locking — the registry is rebuilt from scratch on each
//!    `refresh()` and is read-only after that. Concurrent readers can
//!    wrap in an `Arc<RwLock<_>>` at the call site if needed.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use num_bigint::BigInt;
use num_traits::{Num, Signed};
use quil_store::RocksHypergraphStore;
use quil_tries::{deserialize_go_tree, VectorCommitmentNode};
use quil_types::consensus::{
    ProverAllocationInfo, ProverInfo, ProverRegistry as ProverRegistryTrait, ProverShardSummary,
    ProverStatus,
};
use quil_types::error::{QuilError, Result as QuilResult};
use quil_types::store::ShardKey;

/// BN254 scalar field modulus, same as `iden3-crypto/ff.Modulus()`.
/// Used for the modular-distance sort that picks "next prover" order.
fn bn254_modulus() -> BigInt {
    BigInt::from_str_radix(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("BN254 modulus parses")
}

use crate::global_schema::{
    class_for_type_hash, field_key, TYPE_HASH_ALLOCATION,
};

/// In-memory cache of every prover and their allocations on the global
/// prover shard, built by walking the persisted vertex store.
pub struct InMemoryProverRegistry {
    /// prover_address (32 bytes) → full ProverInfo with allocations
    prover_cache: HashMap<Vec<u8>, ProverInfo>,
    /// confirmation_filter → sorted list of prover addresses with at
    /// least one allocation under that filter. Sorted lexicographically
    /// by address bytes.
    filter_cache: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    /// prover_address → list of filters this prover is allocated on.
    address_to_filters: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    /// Number of `reward:ProverReward` vertices observed during the
    /// last refresh — we don't currently parse them but tracking the
    /// count is cheap and useful for diagnostics.
    reward_vertex_count: usize,
    /// `prover:Prover` vertices seen during the last refresh.
    prover_vertex_count: usize,
    /// `allocation:ProverAllocation` vertices seen during the last refresh.
    allocation_vertex_count: usize,
    /// Vertices whose type hash wasn't in `TYPE_HASH_TABLE`.
    unknown_vertex_count: usize,
}

impl Default for InMemoryProverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryProverRegistry {
    pub fn new() -> Self {
        Self {
            prover_cache: HashMap::new(),
            filter_cache: HashMap::new(),
            address_to_filters: HashMap::new(),
            reward_vertex_count: 0,
            prover_vertex_count: 0,
            allocation_vertex_count: 0,
            unknown_vertex_count: 0,
        }
    }

    /// Clear all state. Called from the start of `refresh`.
    pub fn clear(&mut self) {
        self.prover_cache.clear();
        self.filter_cache.clear();
        self.address_to_filters.clear();
        self.reward_vertex_count = 0;
        self.prover_vertex_count = 0;
        self.allocation_vertex_count = 0;
        self.unknown_vertex_count = 0;
    }

    /// Walk every persisted `vertex/adds` vertex and rebuild the
    /// caches. Uses the blob cache populated by
    /// `quil_rpc::ensure_prover_tree`.
    pub fn refresh(&mut self, hg_store: &Arc<RocksHypergraphStore>) {
        self.clear();
        let shard = ShardKey {
            l1: [0u8; 3],
            l2: [0xffu8; 32],
        };

        // Two-pass walk: first collect provers, then collect allocations.
        // The iterator order is arbitrary, so if we did it in one pass
        // we'd need to synthesize stubs when an allocation arrives
        // before its prover. Two passes are cleaner.
        //
        // Pass 1: provers.
        let _ = hg_store.for_each_vertex_underlying("vertex", "adds", &shard, |vk, data| {
            if vk.len() != 64 {
                return;
            }
            let root = match deserialize_go_tree(&data) {
                Ok(Some(r)) => r,
                _ => return,
            };
            let Some(type_hash) = root.find_leaf_value(&vec![0xFFu8; 32]) else {
                self.unknown_vertex_count += 1;
                return;
            };
            match class_for_type_hash(&type_hash) {
                Some("prover:Prover") => {
                    self.prover_vertex_count += 1;
                    if let Some(info) = decode_prover(&vk, &root) {
                        self.prover_cache.insert(info.address.clone(), info);
                    }
                }
                Some("reward:ProverReward") => {
                    self.reward_vertex_count += 1;
                }
                Some("allocation:ProverAllocation") => {
                    // Handled in pass 2.
                }
                _ => {
                    self.unknown_vertex_count += 1;
                }
            }
        });

        // Pass 2: allocations. Needs provers already in cache so we
        // can attach allocations to the right owner.
        let _ = hg_store.for_each_vertex_underlying("vertex", "adds", &shard, |vk, data| {
            if vk.len() != 64 {
                return;
            }
            let root = match deserialize_go_tree(&data) {
                Ok(Some(r)) => r,
                _ => return,
            };
            let Some(type_hash) = root.find_leaf_value(&vec![0xFFu8; 32]) else {
                return;
            };
            if type_hash != TYPE_HASH_ALLOCATION {
                return;
            }
            self.allocation_vertex_count += 1;
            let Some((prover_ref, alloc)) = decode_allocation(&vk, &root) else {
                return;
            };
            // Find or synthesize the parent prover.
            let prover_entry = self
                .prover_cache
                .entry(prover_ref.clone())
                .or_insert_with(|| ProverInfo {
                    public_key: Vec::new(),
                    address: prover_ref.clone(),
                    status: ProverStatus::Unknown,
                    kick_frame_number: 0,
                    allocations: Vec::new(),
                    available_storage: 0,
                    seniority: 0,
                    delegate_address: Vec::new(),
                });
            let confirmation_filter = alloc.confirmation_filter.clone();
            let is_active = alloc.status == ProverStatus::Active;
            prover_entry.allocations.push(alloc);

            // Update filter_cache and address_to_filters.
            let filter_list = self
                .filter_cache
                .entry(confirmation_filter.clone())
                .or_default();
            // Binary search + insert to maintain sorted order.
            match filter_list.binary_search_by(|a| a.as_slice().cmp(prover_ref.as_slice())) {
                Ok(_) => {}
                Err(idx) => filter_list.insert(idx, prover_ref.clone()),
            }

            if is_active {
                let addr_filters = self
                    .address_to_filters
                    .entry(prover_ref.clone())
                    .or_default();
                if !addr_filters.iter().any(|f| f == &confirmation_filter) {
                    addr_filters.push(confirmation_filter);
                }
            }
        });
    }

    // ------------------------------------------------------------------
    // Query API (mirrors `consensus.ProverRegistry` trait methods)
    // ------------------------------------------------------------------

    pub fn get_prover_info(&self, address: &[u8]) -> Option<&ProverInfo> {
        self.prover_cache.get(address)
    }

    pub fn get_provers(&self, filter: &[u8]) -> Vec<&ProverInfo> {
        let Some(addrs) = self.filter_cache.get(filter) else {
            return Vec::new();
        };
        addrs
            .iter()
            .filter_map(|a| self.prover_cache.get(a))
            .collect()
    }

    pub fn get_active_provers(&self, filter: &[u8]) -> Vec<&ProverInfo> {
        let Some(addrs) = self.filter_cache.get(filter) else {
            return Vec::new();
        };
        addrs
            .iter()
            .filter_map(|a| self.prover_cache.get(a))
            .filter(|p| {
                p.status == ProverStatus::Active
                    && p.allocations.iter().any(|alloc| {
                        alloc.status == ProverStatus::Active
                            && alloc.confirmation_filter == filter
                    })
            })
            .collect()
    }

    pub fn get_prover_count(&self, filter: &[u8]) -> usize {
        self.filter_cache.get(filter).map(|v| v.len()).unwrap_or(0)
    }

    /// Return all prover addresses under `filter` sorted by modular
    /// distance from `input`, ties broken by key value. When `filter`
    /// is empty, iterates all provers across every filter.
    pub fn get_ordered_provers(&self, input: &[u8], filter: &[u8]) -> Vec<Vec<u8>> {
        let modulus = bn254_modulus();
        let target = BigInt::from_bytes_be(num_bigint::Sign::Plus, input);

        let candidates: Vec<Vec<u8>> = if filter.is_empty() {
            // Global view: every distinct prover address.
            let mut all: Vec<Vec<u8>> = self.prover_cache.keys().cloned().collect();
            all.sort();
            all
        } else {
            self.filter_cache.get(filter).cloned().unwrap_or_default()
        };

        let mut scored: Vec<(BigInt, BigInt, Vec<u8>)> = candidates
            .into_iter()
            .map(|addr| {
                let key_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &addr);
                let dist = absolute_modular_minimum_distance(&target, &key_int, &modulus);
                (dist, key_int, addr)
            })
            .collect();

        // Sort by distance ascending; tie-break by key value ascending.
        scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        scored.into_iter().map(|(_, _, a)| a).collect()
    }

    /// Return the single closest prover address to `input` under
    /// `filter`, or `None` if the filter has no provers. Mirrors Go's
    /// `GetNextProver`.
    pub fn get_next_prover(&self, input: &[u8], filter: &[u8]) -> Option<Vec<u8>> {
        self.get_ordered_provers(input, filter).into_iter().next()
    }

    pub fn get_all_active_app_shard_provers(&self) -> Vec<&ProverInfo> {
        // Active provers across every non-empty confirmation filter.
        let mut out: Vec<&ProverInfo> = self
            .prover_cache
            .values()
            .filter(|p| p.status == ProverStatus::Active)
            .collect();
        // Deterministic ordering by address.
        out.sort_by(|a, b| a.address.cmp(&b.address));
        out
    }

    /// Filter provers to those that have at least one allocation with
    /// the given `status` under `filter`. Sorted by address.
    pub fn get_provers_by_status(
        &self,
        filter: &[u8],
        status: ProverStatus,
    ) -> Vec<&ProverInfo> {
        let Some(addrs) = self.filter_cache.get(filter) else {
            return Vec::new();
        };
        let mut out: Vec<&ProverInfo> = addrs
            .iter()
            .filter_map(|addr| self.prover_cache.get(addr))
            .filter(|p| {
                p.allocations.iter().any(|alloc| {
                    alloc.status == status && alloc.confirmation_filter == filter
                })
            })
            .collect();
        out.sort_by(|a, b| a.address.cmp(&b.address));
        out
    }

    /// Per-filter prover count grouped by allocation status.
    pub fn get_prover_shard_summaries(&self) -> Vec<ProverShardSummary> {
        let mut out: Vec<ProverShardSummary> = Vec::with_capacity(self.filter_cache.len());
        for (filter_key, addrs) in &self.filter_cache {
            if filter_key.is_empty() || addrs.is_empty() {
                continue;
            }
            let mut status_counts: HashMap<ProverStatus, u32> = HashMap::new();
            for addr in addrs {
                let Some(info) = self.prover_cache.get(addr) else {
                    continue;
                };
                let mut counted = false;
                for alloc in &info.allocations {
                    if !alloc.confirmation_filter.is_empty()
                        && alloc.confirmation_filter == *filter_key
                    {
                        *status_counts.entry(alloc.status).or_insert(0) += 1;
                        counted = true;
                        break;
                    }
                    if !alloc.rejection_filter.is_empty()
                        && alloc.rejection_filter == *filter_key
                    {
                        *status_counts.entry(alloc.status).or_insert(0) += 1;
                        counted = true;
                        break;
                    }
                }
                if !counted {
                    *status_counts.entry(info.status).or_insert(0) += 1;
                }
            }
            // Approximate total_size as the count of provers in this
            // shard. The Go implementation does not set TotalSize in
            // GetProverShardSummaries either; this provides a non-zero
            // proxy so callers that use it for proportional weighting
            // get meaningful relative values.
            let total_size: u64 = status_counts.values().map(|&c| c as u64).sum();
            out.push(ProverShardSummary {
                filter: filter_key.clone(),
                status_counts,
                total_size,
            });
        }
        out.sort_by(|a, b| a.filter.cmp(&b.filter));
        out
    }

    /// Update the last-active frame number for each active allocation
    /// under `filter` belonging to `address`.
    /// Returns the number of allocations that were touched (0 if the
    /// prover wasn't in the cache or had no active allocation under
    /// the filter).
    pub fn update_prover_activity(
        &mut self,
        address: &[u8],
        filter: &[u8],
        frame_number: u64,
    ) -> usize {
        let Some(info) = self.prover_cache.get_mut(address) else {
            return 0;
        };
        let mut touched = 0;
        for alloc in info.allocations.iter_mut() {
            if alloc.status == ProverStatus::Active && alloc.confirmation_filter == filter {
                alloc.last_active_frame_number = frame_number;
                touched += 1;
            }
        }
        touched
    }

    /// Collect prover addresses whose oldest active allocation's
    /// `LastActiveFrameNumber` is too stale, accounting for shard halt
    /// exemptions. Does **not** perform the RDF mutation — the Rust
    /// port of `HypergraphState::set` doesn't exist yet. Returns the
    /// list of addresses the caller should evict once that path is
    /// wired.
    ///
    /// Find provers that should be evicted for inactivity. Only the
    /// read phase — the caller is responsible for writing the kicked state.
    ///
    /// `shard_halt_durations` maps confirmation-filter bytes →
    /// number of frames the shard has been in a halt state. A value
    /// of `u64::MAX` fully exempts that shard for this tick.
    pub fn find_eviction_candidates(
        &self,
        frame_number: u64,
        inactivity_threshold: u64,
        shard_halt_durations: &HashMap<Vec<u8>, u64>,
    ) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        for info in self.prover_cache.values() {
            if info.status != ProverStatus::Active {
                continue;
            }
            let mut should_evict = false;
            for alloc in &info.allocations {
                if alloc.status != ProverStatus::Active {
                    continue;
                }
                // Global provers (empty confirmation filter) are never
                // evicted.
                if alloc.confirmation_filter.is_empty() {
                    continue;
                }
                let halt_duration = shard_halt_durations
                    .get(&alloc.confirmation_filter)
                    .copied()
                    .unwrap_or(0);
                if halt_duration == u64::MAX {
                    continue;
                }
                if alloc.last_active_frame_number == 0
                    || frame_number <= alloc.last_active_frame_number
                {
                    continue;
                }
                let total_inactive = frame_number - alloc.last_active_frame_number;
                let effective_inactive = if halt_duration == 0 {
                    total_inactive
                } else if halt_duration < total_inactive {
                    total_inactive - halt_duration
                } else {
                    0
                };
                if effective_inactive > inactivity_threshold {
                    should_evict = true;
                    break;
                }
            }
            if should_evict {
                out.push(info.address.clone());
            }
        }
        // Deterministic order for downstream consumers.
        out.sort();
        out
    }

    /// No-op. Pruning orphan joins is disabled because non-deterministic
    /// pruning was causing tree divergence between nodes.
    pub fn prune_orphan_joins(&mut self, _frame_number: u64) {}

    // ------------------------------------------------------------------
    // Stats helpers
    // ------------------------------------------------------------------

    pub fn provers_visited(&self) -> usize { self.prover_vertex_count }
    pub fn allocations_visited(&self) -> usize { self.allocation_vertex_count }
    pub fn rewards_visited(&self) -> usize { self.reward_vertex_count }
    pub fn unknown_visited(&self) -> usize { self.unknown_vertex_count }
    pub fn distinct_provers(&self) -> usize { self.prover_cache.len() }
    pub fn distinct_filters(&self) -> usize { self.filter_cache.len() }
}

// ---------------------------------------------------------------------------
// Trait-shaped wrapper: `Arc<RwLock<InMemoryProverRegistry>>`
// ---------------------------------------------------------------------------

/// Shared, thread-safe wrapper around `InMemoryProverRegistry` that
/// implements `quil_types::consensus::ProverRegistry`. The trait takes
/// `&self` for every method (including mutating ones), so we use an
/// internal `RwLock`.
///
/// Refresh from the persisted vertex store via the inherent
/// `refresh_from_store` method; the trait's `refresh()` method is a
/// no-op because the trait doesn't know which store to read from.
#[derive(Clone)]
pub struct SharedProverRegistry {
    inner: Arc<RwLock<InMemoryProverRegistry>>,
    /// Current global frame number. Stored outside the `RwLock` for
    /// cheap `current_frame()` access.
    current_frame: Arc<std::sync::atomic::AtomicU64>,
}

impl SharedProverRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(InMemoryProverRegistry::new())),
            current_frame: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Rebuild the cache from the given hypergraph store. Takes a
    /// write lock for the duration of the refresh.
    pub fn refresh_from_store(&self, hg_store: &Arc<RocksHypergraphStore>) {
        let mut guard = self.inner.write().expect("prover registry lock poisoned");
        guard.refresh(hg_store);
    }

    pub fn set_current_frame(&self, frame: u64) {
        self.current_frame
            .store(frame, std::sync::atomic::Ordering::Relaxed);
    }

    /// Access the inner registry under a read lock. Use sparingly —
    /// most consumers should call the trait methods.
    pub fn read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&InMemoryProverRegistry) -> R,
    {
        let guard = self.inner.read().expect("prover registry lock poisoned");
        f(&guard)
    }
}

impl Default for SharedProverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProverRegistryTrait for SharedProverRegistry {
    fn get_prover_info(&self, address: &[u8]) -> QuilResult<Option<ProverInfo>> {
        Ok(self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?
            .get_prover_info(address)
            .cloned())
    }

    fn get_next_prover(&self, input: &[u8; 32], filter: &[u8]) -> QuilResult<Vec<u8>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        guard
            .get_next_prover(input, filter)
            .ok_or_else(|| QuilError::NotFound("shard trie empty".into()))
    }

    fn get_ordered_provers(
        &self,
        input: &[u8; 32],
        filter: &[u8],
    ) -> QuilResult<Vec<Vec<u8>>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard.get_ordered_provers(input, filter))
    }

    fn get_active_provers(&self, filter: &[u8]) -> QuilResult<Vec<ProverInfo>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard.get_active_provers(filter).into_iter().cloned().collect())
    }

    fn get_prover_count(&self, filter: &[u8]) -> QuilResult<usize> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard.get_prover_count(filter))
    }

    fn get_provers(&self, filter: &[u8]) -> QuilResult<Vec<ProverInfo>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard.get_provers(filter).into_iter().cloned().collect())
    }

    fn get_provers_by_status(
        &self,
        filter: &[u8],
        status: ProverStatus,
    ) -> QuilResult<Vec<ProverInfo>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard
            .get_provers_by_status(filter, status)
            .into_iter()
            .cloned()
            .collect())
    }

    fn update_prover_activity(
        &self,
        address: &[u8],
        filter: &[u8],
        frame_number: u64,
    ) -> QuilResult<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        guard.update_prover_activity(address, filter, frame_number);
        Ok(())
    }

    fn refresh(&self) -> QuilResult<()> {
        // The trait doesn't know what store to refresh from. Consumers
        // must call `refresh_from_store` directly instead. Returning
        // Ok(()) keeps the trait lightly usable for tests that don't
        // care about refresh.
        Ok(())
    }

    fn get_all_active_app_shard_provers(&self) -> QuilResult<Vec<ProverInfo>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard
            .get_all_active_app_shard_provers()
            .into_iter()
            .cloned()
            .collect())
    }

    fn get_prover_shard_summaries(&self) -> QuilResult<Vec<ProverShardSummary>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard.get_prover_shard_summaries())
    }

    fn prune_orphan_joins(&self, frame_number: u64) -> QuilResult<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        guard.prune_orphan_joins(frame_number);
        Ok(())
    }

    fn evict_inactive_provers(
        &self,
        frame_number: u64,
        inactivity_threshold: u64,
        shard_halt_durations: &HashMap<String, u64>,
    ) -> QuilResult<Vec<Vec<u8>>> {
        // The trait takes `HashMap<String, u64>` (filter as hex
        // string or similar stringly key). The inherent method works
        // in raw bytes. Convert by interpreting each String key as
        // hex. If decoding fails, skip that entry.
        let mut halt_bytes: HashMap<Vec<u8>, u64> = HashMap::with_capacity(shard_halt_durations.len());
        for (k, v) in shard_halt_durations {
            if let Ok(decoded) = hex::decode(k) {
                halt_bytes.insert(decoded, *v);
            }
        }
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        // Currently returns candidates only; mutation phase is TODO
        // until the HypergraphState writer is ported.
        Ok(guard.find_eviction_candidates(frame_number, inactivity_threshold, &halt_bytes))
    }

    fn current_frame(&self) -> u64 {
        self.current_frame
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Modular minimum distance on the BN254 field. Mirrors Go's
/// `utils.AbsoluteModularMinimumDistance` exactly:
/// `min(|a - b|, modulus - |a - b|)`.
fn absolute_modular_minimum_distance(a: &BigInt, b: &BigInt, modulus: &BigInt) -> BigInt {
    let mut diff = (a - b).abs();
    // Normalize diff into `[0, modulus)` in case inputs were reduced
    // already but are too large; Go's big.Int doesn't reduce so
    // inputs can exceed the modulus in principle.
    if &diff >= modulus {
        diff = &diff % modulus;
    }
    let mod_complement = modulus - &diff;
    if diff > mod_complement {
        mod_complement
    } else {
        diff
    }
}

fn read_u64_be(node: &VectorCommitmentNode, class: &str, field: &str) -> u64 {
    let Some(key) = field_key(class, field) else { return 0; };
    let Some(bytes) = node.find_leaf_value(&key) else { return 0; };
    if bytes.len() < 8 {
        return 0;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(buf)
}

fn read_bytes(node: &VectorCommitmentNode, class: &str, field: &str) -> Vec<u8> {
    field_key(class, field)
        .and_then(|k| node.find_leaf_value(&k))
        .unwrap_or_default()
}

/// Map the raw RDF status byte for `prover:Prover` to our enum.
/// Returns `None` for byte 4 (the Go code's "Left" — it `continue`s
/// and excludes the prover from the cache entirely).
fn map_prover_status(byte: u8) -> Option<ProverStatus> {
    match byte {
        0 => Some(ProverStatus::Joining),
        1 => Some(ProverStatus::Active),
        2 => Some(ProverStatus::Paused),
        3 => Some(ProverStatus::Left), // Rust "Left" = Go "Leaving"
        // 4 is "left" for provers — Go skips the vertex.
        _ => None,
    }
}

/// Map the raw RDF status byte for `allocation:ProverAllocation`.
fn map_allocation_status(byte: u8) -> ProverStatus {
    match byte {
        0 => ProverStatus::Joining,
        1 => ProverStatus::Active,
        2 => ProverStatus::Paused,
        3 => ProverStatus::Left,
        4 => ProverStatus::Rejected,
        5 => ProverStatus::Kicked,
        _ => ProverStatus::Unknown,
    }
}

/// Decode a `prover:Prover` vertex. Returns `None` for rows that Go's
/// extraction would skip (missing public key, missing/left status).
fn decode_prover(vertex_key: &[u8], root: &VectorCommitmentNode) -> Option<ProverInfo> {
    let public_key = read_bytes(root, "prover:Prover", "PublicKey");
    if public_key.is_empty() {
        return None;
    }
    let status_bytes = field_key("prover:Prover", "Status")
        .and_then(|k| root.find_leaf_value(&k))?;
    if status_bytes.len() != 1 {
        return None;
    }
    let status = map_prover_status(status_bytes[0])?;
    let available_storage = read_u64_be(root, "prover:Prover", "AvailableStorage");
    let seniority = read_u64_be(root, "prover:Prover", "Seniority");
    let kick_frame_number = read_u64_be(root, "prover:Prover", "KickFrameNumber");

    // Go's extractor doesn't pull DelegateAddress for prover:Prover
    // (the schema doesn't even define it; it's an allocation-level
    // concept in practice). Leave empty.
    let delegate_address = Vec::new();

    // Last 32 bytes of the 64-byte vertex key = prover address.
    let address: Vec<u8> = vertex_key[32..64].to_vec();

    Some(ProverInfo {
        public_key,
        address,
        status,
        kick_frame_number,
        allocations: Vec::new(),
        available_storage,
        seniority,
        delegate_address,
    })
}

/// Decode an `allocation:ProverAllocation` vertex. Returns
/// `(parent_prover_address, allocation_info)`.
fn decode_allocation(
    vertex_key: &[u8],
    root: &VectorCommitmentNode,
) -> Option<(Vec<u8>, ProverAllocationInfo)> {
    // Order 0 — Prover pointer. Go uses this as the map key into
    // `proverCache`. The stored value is a 32-byte address.
    let prover_ref = read_bytes(root, "allocation:ProverAllocation", "Prover");
    if prover_ref.is_empty() {
        return None;
    }
    let status_bytes = field_key("allocation:ProverAllocation", "Status")
        .and_then(|k| root.find_leaf_value(&k))?;
    if status_bytes.len() != 1 {
        return None;
    }
    let status = map_allocation_status(status_bytes[0]);
    let confirmation_filter = read_bytes(root, "allocation:ProverAllocation", "ConfirmationFilter");
    let rejection_filter = read_bytes(root, "allocation:ProverAllocation", "RejectionFilter");
    let alloc = ProverAllocationInfo {
        status,
        confirmation_filter,
        rejection_filter,
        join_frame_number: read_u64_be(root, "allocation:ProverAllocation", "JoinFrameNumber"),
        leave_frame_number: read_u64_be(root, "allocation:ProverAllocation", "LeaveFrameNumber"),
        pause_frame_number: read_u64_be(root, "allocation:ProverAllocation", "PauseFrameNumber"),
        resume_frame_number: read_u64_be(root, "allocation:ProverAllocation", "ResumeFrameNumber"),
        kick_frame_number: read_u64_be(root, "allocation:ProverAllocation", "KickFrameNumber"),
        join_confirm_frame_number: read_u64_be(root, "allocation:ProverAllocation", "JoinConfirmFrameNumber"),
        join_reject_frame_number: read_u64_be(root, "allocation:ProverAllocation", "JoinRejectFrameNumber"),
        leave_confirm_frame_number: read_u64_be(root, "allocation:ProverAllocation", "LeaveConfirmFrameNumber"),
        leave_reject_frame_number: read_u64_be(root, "allocation:ProverAllocation", "LeaveRejectFrameNumber"),
        last_active_frame_number: read_u64_be(root, "allocation:ProverAllocation", "LastActiveFrameNumber"),
        vertex_address: vertex_key[32..64].to_vec(),
    };
    Some((prover_ref, alloc))
}

// =====================================================================
// Public helpers for invoke_step: blob ↔ VectorCommitmentTree
// =====================================================================

/// Rebuild a `VectorCommitmentTree` from a blob stored in the CRDT.
/// The blob is in Go's `SerializeNonLazyTree` format. If the blob is
/// empty or unparseable, returns an empty tree.
pub fn rebuild_vertex_tree_from_blob(blob: &[u8]) -> quil_tries::VectorCommitmentTree {
    if blob.is_empty() {
        return quil_tries::VectorCommitmentTree::new();
    }
    match quil_tries::deserialize_go_tree(blob) {
        Ok(Some(root)) => {
            // Wrap the root node into a VectorCommitmentTree.
            let mut tree = quil_tries::VectorCommitmentTree::new();
            tree.root = Some(root);
            tree
        }
        _ => quil_tries::VectorCommitmentTree::new(),
    }
}

/// Serialize a `VectorCommitmentTree` to a blob for CRDT storage.
/// Uses Go's `SerializeNonLazyTree` format for wire compatibility.
pub fn vertex_tree_to_blob(tree: &quil_tries::VectorCommitmentTree) -> Vec<u8> {
    match quil_tries::serialize_go_tree(tree.root.as_ref()) {
        Ok(data) => data,
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global_schema::{TYPE_HASH_PROVER, TYPE_HASH_REWARD};
    use num_bigint::BigInt;
    use quil_tries::{serialize_go_tree, LeafNode, VectorCommitmentNode, VectorCommitmentTree};

    fn make_vertex_key(address_byte: u8) -> Vec<u8> {
        // 32-byte domain (global intrinsic) + 32-byte address.
        let mut key = vec![0xFFu8; 32];
        key.extend_from_slice(&[address_byte; 32]);
        key
    }

    fn type_hash_leaf(class: &str) -> LeafNode {
        let hash = match class {
            "prover:Prover" => TYPE_HASH_PROVER,
            "allocation:ProverAllocation" => TYPE_HASH_ALLOCATION,
            "reward:ProverReward" => TYPE_HASH_REWARD,
            _ => panic!("unknown class in test fixture"),
        };
        LeafNode {
            key: vec![0xFFu8; 32],
            value: hash.to_vec(),
            hash_target: Vec::new(),
            commitment: vec![0u8; 64],
            size: BigInt::from(0u64),
        }
    }

    fn field_leaf(class: &str, field: &str, value: Vec<u8>) -> LeafNode {
        let key = field_key(class, field).unwrap();
        LeafNode {
            key,
            value,
            hash_target: Vec::new(),
            commitment: vec![0u8; 64],
            size: BigInt::from(0u64),
        }
    }

    /// Build a per-vertex sub-tree with the given leaves and return its
    /// Go-wire-format serialization. We don't bother computing real
    /// commitments since the registry doesn't verify them — it only
    /// reads leaf values by exact key match.
    fn build_sub_tree(leaves: Vec<LeafNode>) -> Vec<u8> {
        let mut tree = VectorCommitmentTree::new();
        for leaf in leaves {
            // Insert via the public API so prefix compression matches
            // what the wire format produces. `size=0` is fine.
            let zero = BigInt::from(0u64);
            tree.insert(&leaf.key, &leaf.value, &leaf.hash_target, &zero)
                .unwrap();
        }
        serialize_go_tree(tree.root.as_ref()).unwrap()
    }

    /// Temp store helper.
    fn temp_store() -> (tempfile::TempDir, Arc<RocksHypergraphStore>) {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = quil_store::RocksDb::open(tmp.path()).unwrap();
        let store = Arc::new(RocksHypergraphStore::new(Arc::new(db).inner()));
        (tmp, store)
    }

    #[test]
    fn decode_prover_fixture() {
        // Build a prover:Prover vertex sub-tree with status=Active (1),
        // AvailableStorage=1024, Seniority=42, KickFrameNumber=0.
        let leaves = vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", vec![0xAA; 57]),
            field_leaf("prover:Prover", "Status", vec![1u8]),
            field_leaf("prover:Prover", "AvailableStorage", 1024u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "Seniority", 42u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
        ];
        let bytes = build_sub_tree(leaves);

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let vk = make_vertex_key(0x01);
        store.save_vertex_underlying("vertex", "adds", &shard, &vk, &bytes).unwrap();

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(&store);

        assert_eq!(reg.provers_visited(), 1);
        assert_eq!(reg.distinct_provers(), 1);
        let got = reg.get_prover_info(&[0x01; 32]).expect("prover present");
        assert_eq!(got.status, ProverStatus::Active);
        assert_eq!(got.available_storage, 1024);
        assert_eq!(got.seniority, 42);
        assert_eq!(got.public_key, vec![0xAA; 57]);
        assert!(got.allocations.is_empty());
    }

    #[test]
    fn decode_allocation_links_to_prover() {
        // Prover has address [0x11; 32]. Allocation's Prover field
        // points to that address; allocation is active under filter
        // [0xCC; 64].
        let prover_addr = [0x11u8; 32];
        let filter = vec![0xCCu8; 64];

        let prover_bytes = build_sub_tree(vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", vec![0xBB; 57]),
            field_leaf("prover:Prover", "Status", vec![1u8]),
            field_leaf("prover:Prover", "AvailableStorage", 2048u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "Seniority", 99u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
        ]);
        let alloc_bytes = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", prover_addr.to_vec()),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.clone()),
            field_leaf("allocation:ProverAllocation", "JoinFrameNumber",
                       12345u64.to_be_bytes().to_vec()),
        ]);

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        store
            .save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x11), &prover_bytes)
            .unwrap();
        // Allocation vertex key needs the last 32 bytes to be the
        // allocation's own address, not the prover's. Use a distinct
        // byte so we can verify `vertex_address` on the allocation.
        store
            .save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x22), &alloc_bytes)
            .unwrap();

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(&store);

        assert_eq!(reg.provers_visited(), 1);
        assert_eq!(reg.allocations_visited(), 1);
        assert_eq!(reg.distinct_provers(), 1);

        let got = reg.get_prover_info(&prover_addr).expect("prover present");
        assert_eq!(got.allocations.len(), 1);
        let alloc = &got.allocations[0];
        assert_eq!(alloc.status, ProverStatus::Active);
        assert_eq!(alloc.confirmation_filter, filter);
        assert_eq!(alloc.join_frame_number, 12345);
        // The allocation's vertex address should be the 0x22 bytes, not 0x11.
        assert_eq!(alloc.vertex_address, vec![0x22u8; 32]);

        // Filter cache should now name this prover under `filter`.
        let prov_list = reg.get_provers(&filter);
        assert_eq!(prov_list.len(), 1);
        assert_eq!(prov_list[0].address, prover_addr);

        // Active-filter query too.
        let active = reg.get_active_provers(&filter);
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn reward_vertex_does_not_populate_prover_cache() {
        let leaves = vec![
            type_hash_leaf("reward:ProverReward"),
            field_leaf("reward:ProverReward", "DelegateAddress", vec![0x33; 32]),
            field_leaf("reward:ProverReward", "Balance", vec![0x00; 32]),
        ];
        let bytes = build_sub_tree(leaves);

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        store
            .save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x33), &bytes)
            .unwrap();

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(&store);

        assert_eq!(reg.rewards_visited(), 1);
        assert_eq!(reg.provers_visited(), 0);
        assert_eq!(reg.distinct_provers(), 0);
    }

    #[test]
    fn modular_distance_min_of_both_directions() {
        // Two small numbers where the direct distance is larger than
        // the wrap-around distance: e.g. modulus=100, a=5, b=95.
        // |5-95| = 90, 100 - 90 = 10 → dist = 10.
        let m = BigInt::from(100u64);
        let d = absolute_modular_minimum_distance(&BigInt::from(5u64), &BigInt::from(95u64), &m);
        assert_eq!(d, BigInt::from(10u64));

        // Direct distance smaller: a=10, b=20 → 10, mod comp = 90 → 10.
        let d = absolute_modular_minimum_distance(&BigInt::from(10u64), &BigInt::from(20u64), &m);
        assert_eq!(d, BigInt::from(10u64));

        // Exactly half — both distances equal.
        let d = absolute_modular_minimum_distance(&BigInt::from(0u64), &BigInt::from(50u64), &m);
        assert_eq!(d, BigInt::from(50u64));
    }

    #[test]
    fn ordered_provers_by_distance_to_input() {
        // Populate the registry with 4 provers having distinct
        // 32-byte addresses, all under filter F. Confirm the ordered
        // list puts them in distance-order from a chosen input.
        let filter = vec![0xEEu8; 64];
        let addrs: Vec<[u8; 32]> = vec![
            // Low-valued address.
            [0x00; 32],
            // One bit set near the top.
            {
                let mut a = [0u8; 32];
                a[0] = 0x80;
                a
            },
            // Another.
            {
                let mut a = [0u8; 32];
                a[31] = 0x01;
                a
            },
            // Mid.
            {
                let mut a = [0u8; 32];
                a[15] = 0x40;
                a
            },
        ];

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };

        for (i, addr) in addrs.iter().enumerate() {
            // Build an Active allocation for each.
            let alloc_bytes = build_sub_tree(vec![
                type_hash_leaf("allocation:ProverAllocation"),
                field_leaf("allocation:ProverAllocation", "Prover", addr.to_vec()),
                field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
                field_leaf(
                    "allocation:ProverAllocation",
                    "ConfirmationFilter",
                    filter.clone(),
                ),
            ]);
            // Use a unique vertex key per allocation so we don't
            // collide in the store.
            let mut vk = vec![0xFFu8; 32];
            vk.extend_from_slice(&[0xA0 + i as u8; 32]);
            store
                .save_vertex_underlying("vertex", "adds", &shard, &vk, &alloc_bytes)
                .unwrap();
        }

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(&store);
        assert_eq!(reg.distinct_provers(), 4);

        // Query from the zero vector. The closest should be addr[0]
        // (all zeros), and addr[2] (lowest non-zero bit) should come
        // next.
        let zero = [0u8; 32];
        let order = reg.get_ordered_provers(&zero, &filter);
        assert_eq!(order[0], addrs[0]);
        assert_eq!(order[1], addrs[2]);
        assert_eq!(order.len(), 4);

        // get_next_prover returns the single nearest.
        let next = reg.get_next_prover(&zero, &filter).unwrap();
        assert_eq!(next, addrs[0]);
    }

    #[test]
    fn update_prover_activity_touches_matching_allocations() {
        let prover_addr = [0x77u8; 32];
        let filter_a = vec![0xAAu8; 64];
        let filter_b = vec![0xBBu8; 64];
        let prover_bytes = build_sub_tree(vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", vec![0x01; 57]),
            field_leaf("prover:Prover", "Status", vec![1u8]),
            field_leaf("prover:Prover", "AvailableStorage", 0u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
        ]);
        let alloc_a = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", prover_addr.to_vec()),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter_a.clone()),
        ]);
        let alloc_b = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", prover_addr.to_vec()),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter_b.clone()),
        ]);

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x77), &prover_bytes).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x78), &alloc_a).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x79), &alloc_b).unwrap();

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(&store);

        // Touch activity only for filter_a.
        let touched = reg.update_prover_activity(&prover_addr, &filter_a, 9999);
        assert_eq!(touched, 1);

        // Verify only filter_a's allocation has the new frame.
        let info = reg.get_prover_info(&prover_addr).unwrap();
        let alloc_a_info = info
            .allocations
            .iter()
            .find(|a| a.confirmation_filter == filter_a)
            .unwrap();
        assert_eq!(alloc_a_info.last_active_frame_number, 9999);
        let alloc_b_info = info
            .allocations
            .iter()
            .find(|a| a.confirmation_filter == filter_b)
            .unwrap();
        assert_eq!(alloc_b_info.last_active_frame_number, 0);
    }

    #[test]
    fn find_eviction_candidates_respects_halt_exemption() {
        // Two active allocations: one past threshold on a normal
        // shard, one past threshold on a shard with `u64::MAX` halt.
        // Only the normal-shard one should be flagged.
        let prover_1 = [0x81u8; 32];
        let prover_2 = [0x82u8; 32];
        let filter_normal = vec![0x11u8; 64];
        let filter_halted = vec![0x22u8; 64];

        let mk_prover = |addr: [u8; 32]| {
            build_sub_tree(vec![
                type_hash_leaf("prover:Prover"),
                field_leaf("prover:Prover", "PublicKey", vec![0xCD; 57]),
                field_leaf("prover:Prover", "Status", vec![1u8]),
                field_leaf("prover:Prover", "AvailableStorage", 0u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
            ])
        };
        let mk_alloc = |prover: &[u8; 32], filter: &[u8]| {
            build_sub_tree(vec![
                type_hash_leaf("allocation:ProverAllocation"),
                field_leaf("allocation:ProverAllocation", "Prover", prover.to_vec()),
                field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
                field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.to_vec()),
                field_leaf(
                    "allocation:ProverAllocation",
                    "LastActiveFrameNumber",
                    100u64.to_be_bytes().to_vec(),
                ),
            ])
        };

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };

        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x81), &mk_prover(prover_1)).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x91), &mk_alloc(&prover_1, &filter_normal)).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x82), &mk_prover(prover_2)).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x92), &mk_alloc(&prover_2, &filter_halted)).unwrap();

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(&store);

        // Frame 1000 → 900 frames inactive. Threshold = 500. Both
        // would hit it, but filter_halted is fully exempt.
        let mut halts: HashMap<Vec<u8>, u64> = HashMap::new();
        halts.insert(filter_halted.clone(), u64::MAX);

        let evict = reg.find_eviction_candidates(1000, 500, &halts);
        assert_eq!(evict.len(), 1);
        assert_eq!(evict[0], prover_1);
    }

    #[test]
    fn prover_shard_summaries_group_by_filter() {
        let filter = vec![0xAAu8; 64];
        let prover_a = [0xA1u8; 32];
        let prover_b = [0xA2u8; 32];

        let mk_prover = |addr: [u8; 32]| {
            build_sub_tree(vec![
                type_hash_leaf("prover:Prover"),
                field_leaf("prover:Prover", "PublicKey", vec![0xAA; 57]),
                field_leaf("prover:Prover", "Status", vec![1u8]),
                field_leaf("prover:Prover", "AvailableStorage", 0u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
            ])
        };
        let mk_alloc = |prover: &[u8; 32], status: u8| {
            build_sub_tree(vec![
                type_hash_leaf("allocation:ProverAllocation"),
                field_leaf("allocation:ProverAllocation", "Prover", prover.to_vec()),
                field_leaf("allocation:ProverAllocation", "Status", vec![status]),
                field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.clone()),
            ])
        };

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xA1), &mk_prover(prover_a)).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xA2), &mk_prover(prover_b)).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xA3), &mk_alloc(&prover_a, 1)).unwrap(); // Active
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xA4), &mk_alloc(&prover_b, 0)).unwrap(); // Joining

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(&store);

        let summaries = reg.get_prover_shard_summaries();
        assert_eq!(summaries.len(), 1);
        let sum = &summaries[0];
        assert_eq!(sum.filter, filter);
        assert_eq!(sum.status_counts.get(&ProverStatus::Active).copied().unwrap_or(0), 1);
        assert_eq!(sum.status_counts.get(&ProverStatus::Joining).copied().unwrap_or(0), 1);
    }

    #[test]
    fn shared_registry_trait_impl_roundtrip() {
        // Build one prover + one active allocation, load them through
        // SharedProverRegistry, and exercise the trait methods.
        let prover_addr = [0xF0u8; 32];
        let filter = vec![0xFCu8; 64];
        let prover_bytes = build_sub_tree(vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", vec![0xFE; 57]),
            field_leaf("prover:Prover", "Status", vec![1u8]),
            field_leaf("prover:Prover", "AvailableStorage", 7u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "Seniority", 13u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
        ]);
        let alloc_bytes = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", prover_addr.to_vec()),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.clone()),
        ]);

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xF0), &prover_bytes).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xF1), &alloc_bytes).unwrap();

        let shared = SharedProverRegistry::new();
        shared.refresh_from_store(&store);

        let trait_obj: &dyn ProverRegistryTrait = &shared;

        let info = trait_obj.get_prover_info(&prover_addr).unwrap().unwrap();
        assert_eq!(info.seniority, 13);
        assert_eq!(info.available_storage, 7);

        assert_eq!(trait_obj.get_prover_count(&filter).unwrap(), 1);
        assert_eq!(trait_obj.get_provers(&filter).unwrap().len(), 1);
        assert_eq!(trait_obj.get_active_provers(&filter).unwrap().len(), 1);
        assert_eq!(
            trait_obj
                .get_provers_by_status(&filter, ProverStatus::Active)
                .unwrap()
                .len(),
            1
        );

        // update_prover_activity via trait mutates shared state.
        trait_obj.update_prover_activity(&prover_addr, &filter, 42).unwrap();
        let updated = trait_obj.get_prover_info(&prover_addr).unwrap().unwrap();
        assert_eq!(updated.allocations[0].last_active_frame_number, 42);

        // prune_orphan_joins is a no-op per Go.
        trait_obj.prune_orphan_joins(1000).unwrap();
        assert_eq!(trait_obj.get_prover_count(&filter).unwrap(), 1);

        // evict_inactive_provers with no halts, threshold larger than
        // the inactive window → no candidates.
        let empty: HashMap<String, u64> = HashMap::new();
        let evict = trait_obj.evict_inactive_provers(100, 10000, &empty).unwrap();
        assert!(evict.is_empty());

        // Summaries round-trip through the trait.
        let sums = trait_obj.get_prover_shard_summaries().unwrap();
        assert_eq!(sums.len(), 1);

        // current_frame starts at 0, can be set.
        assert_eq!(trait_obj.current_frame(), 0);
        shared.set_current_frame(12345);
        assert_eq!(trait_obj.current_frame(), 12345);
    }

    #[test]
    fn orphan_allocation_synthesizes_parent() {
        // Allocation arrives with no matching prover vertex. Go's
        // extractor still inserts a stub ProverInfo with an empty
        // public key. Rust should match.
        let prover_addr = [0x44u8; 32];
        let alloc_bytes = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", prover_addr.to_vec()),
            field_leaf("allocation:ProverAllocation", "Status", vec![0u8]), // Joining
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", vec![0xDD; 64]),
        ]);

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        store
            .save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x44), &alloc_bytes)
            .unwrap();

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(&store);

        let got = reg.get_prover_info(&prover_addr).expect("orphan synthesized");
        assert!(got.public_key.is_empty());
        assert_eq!(got.allocations.len(), 1);
        assert_eq!(got.allocations[0].status, ProverStatus::Joining);
    }
}
