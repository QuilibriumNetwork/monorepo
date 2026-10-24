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
//! filter → sorted list of prover addresses with an active
//! allocation under that filter
//! - `address_to_filters: HashMap<Vec<u8>, Vec<Vec<u8>>>` — reverse
//! index from prover address to the filters it's allocated under
//!
//! Differences from Go:
//!
//! 1. We don't yet implement the `RollingFrecencyCritbitTrie` that Go
//! uses for `FindNearestAndApproximateNeighbors`. For now we store
//! filter → sorted `Vec<Vec<u8>>` and do a linear scan. Fine up to
//! ~10 K provers per filter.
//! 2. We iterate the persisted blob cache
//! (a retained hypergraph-store snapshot), not a
//! live hypergraph iterator.
//! 3. No locking — the registry is rebuilt from scratch on each
//! `refresh()` and is read-only after that. Concurrent readers can
//! wrap in an `Arc<RwLock<_>>` at the call site if needed.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use num_bigint::BigInt;
use num_traits::{Num, Signed};
#[cfg(test)]
use quil_store::RocksHypergraphStore;
use quil_tries::{deserialize_go_tree, VectorCommitmentNode};
use quil_types::consensus::{
    EffectiveStatus, ProverAllocationInfo, ProverInfo,
    ProverRegistry as ProverRegistryTrait, ProverShardSummary, ProverStatus,
};
use quil_types::error::{QuilError, Result as QuilResult};
use quil_types::store::{
    CapturePoint, HypergraphStore, ScanPoint, ShardKey, SnapshotReadable, VertexPageLimits,
};

#[path = "registry_budget.rs"]
mod registry_budget;
pub use registry_budget::{RegistryLimits, RegistryUsage};
use registry_budget::{collect_legacy, RegistryBudget};
#[path = "registry_rows.rs"]
mod registry_rows;
use registry_rows::RegistryRows;

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
/// A member's registered storage root for one leaf, as recorded by its
/// `ProverConfirm` (the leaf-root vertex written at confirm time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafRootRecord {
    pub leaf_root: Vec<u8>,
    pub num_blocks: u64,
    /// The storage epoch this leaf root was registered for. The storage
    /// attestation verifier checks this equals the active epoch.
    pub epoch: u64,
}

#[derive(Clone)]
pub struct InMemoryProverRegistry {
    resource_usage: RegistryUsage,
    /// The one database state the last refresh read its rows from, if any.
    /// `None` after the legacy tree fallback, whose key is not watched.
    scanned: Option<ScanPoint>,
    /// The last refresh read vertex rows rather than the legacy tree fallback.
    from_rows: bool,
    /// Largest key + value, and largest value, among the rows it read.
    largest_row: usize,
    largest_value: usize,
    /// The rows a refresh read, so a later change updates only what it
    /// feeds. `None` after the legacy tree fallback. Shared until changed.
    rows: Option<Arc<RegistryRows>>,
    /// A cache was edited directly, so it may differ from its rows until the
    /// next refresh.
    diverged: bool,
    /// prover_address (32 bytes) → full ProverInfo with allocations
    prover_cache: HashMap<Vec<u8>, ProverInfo>,
    /// (member_address, leaf_id) → registered leaf-root record. `leaf_id` is
    /// `leaf_id_bytes(shard_filter, prefix)`. Populated from
    /// `leafroot:LeafRootRegistration` vertices written by ProverConfirm.
    leaf_root_cache: HashMap<(Vec<u8>, Vec<u8>, u64), LeafRootRecord>,
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
    /// `leafroot:LeafRootRegistration` vertices seen during the last refresh.
    leaf_root_vertex_count: usize,
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
            resource_usage: RegistryUsage::default(),
            scanned: None,
            from_rows: false,
            largest_row: 0,
            largest_value: 0,
            rows: None,
            diverged: false,
            prover_cache: HashMap::new(),
            leaf_root_cache: HashMap::new(),
            filter_cache: HashMap::new(),
            address_to_filters: HashMap::new(),
            reward_vertex_count: 0,
            prover_vertex_count: 0,
            allocation_vertex_count: 0,
            leaf_root_vertex_count: 0,
            unknown_vertex_count: 0,
        }
    }

    fn reward_ring_estimate(&self, address: &[u8], filter: &[u8], frame: u64)
        -> Option<quil_types::reward_ring::RewardRingEstimate> {
        let all = self.get_provers(filter);
        let mut estimate = quil_types::reward_ring::estimate_reward_ring(
            &self.get_active_provers(filter, frame), &all, address, filter, frame)?;
        if estimate.source == "committed_allocation_ring" {
            // A decoded zero cannot establish rank. Require the committed
            // policy fields from the same registry rows. Pending joins and
            // paused owners and allocations without a ring assignment do not
            // establish ring occupancy. Malformed assigned fields stay unknown.
            let rows = self.rows.as_ref()?;
            let members: Option<Vec<_>> = all.iter().filter_map(|p| p.allocations.iter()
                .find(|a| a.confirmation_filter == filter
                    && matches!(a.effective_status(frame), EffectiveStatus::Active | EffectiveStatus::Leaving)))
                .filter_map(|a| match rows.committed_ring(&a.vertex_address) {
                    registry_rows::CommittedRing::Assigned(ring) => Some(Some(ring)),
                    registry_rows::CommittedRing::Unassigned => None,
                    registry_rows::CommittedRing::Invalid => Some(None),
                }).collect();
            let own = all.iter().find(|p| p.address == address)?.allocations.iter()
                .find(|a| a.confirmation_filter == filter)?;
            estimate.ring = match rows.committed_ring(&own.vertex_address) {
                registry_rows::CommittedRing::Assigned(ring) => ring,
                _ => return None,
            };
            let members = members?;
            estimate.provers_on_ring = members.iter().filter(|&&r| r == estimate.ring).count();
            estimate.member_count = members.len();
        }
        Some(estimate)
    }

    /// Clear all state explicitly. A failed refresh retains the previous cache.
    pub fn clear(&mut self) {
        self.resource_usage = RegistryUsage::default();
        self.scanned = None;
        self.from_rows = false;
        self.largest_row = 0;
        self.largest_value = 0;
        self.rows = None;
        self.diverged = false;
        self.prover_cache.clear();
        self.leaf_root_cache.clear();
        self.filter_cache.clear();
        self.address_to_filters.clear();
        self.reward_vertex_count = 0;
        self.prover_vertex_count = 0;
        self.allocation_vertex_count = 0;
        self.leaf_root_vertex_count = 0;
        self.unknown_vertex_count = 0;
    }

    /// The registered leaf-root record for `(member, leaf_id)`, or `None`.
    /// `leaf_id` = `leaf_id_bytes(shard_filter, prefix)`. Used by the storage
    /// attestation verifier to cross-check an opening's claimed `leaf_root`.
    pub fn get_leaf_root(
        &self,
        member: &[u8],
        leaf_id: &[u8],
        epoch: u64,
    ) -> Option<&LeafRootRecord> {
        self.leaf_root_cache
            .get(&(member.to_vec(), leaf_id.to_vec(), epoch))
    }

    /// Total cached leaf-root epoch entries across all members (diagnostics).
    /// One registration contributes up to three entries; use
    /// `leaf_root_vertex_count` for the number of registration vertices.
    pub fn leaf_root_count(&self) -> usize {
        self.leaf_root_cache.len()
    }

    /// Walk every persisted `vertex/adds` vertex and rebuild the
    /// caches from the per-vertex keyspace, which is the canonical
    /// record of vertex content. Each row stores
    /// `key = 64-byte location_id` and `value = the vertex sub-tree
    /// blob`. The commitment tree blob holds only topology + per-node
    /// commitments and is not consulted here.
    pub fn refresh(&mut self, hg_store: &dyn HypergraphStore) -> QuilResult<()> {
        self.refresh_with_limits(hg_store, RegistryLimits::UNBOUNDED)
    }

    pub fn refresh_with_limits(&mut self, hg_store: &dyn HypergraphStore, limits: RegistryLimits) -> QuilResult<()> {
        let snapshot = hg_store.capture_tree_snapshot()?.ok_or_else(|| {
            QuilError::Store("prover registry requires a consistent store snapshot".into())
        })?;
        self.refresh_from_snapshot_with_limits(snapshot.as_ref(), limits)
    }

    /// Read additions, removals and the legacy fallback at one captured store
    /// generation. Publish the replacement cache only after every read succeeds.
    pub fn refresh_from_snapshot(&mut self, snapshot: &dyn SnapshotReadable) -> QuilResult<()> {
        self.refresh_from_snapshot_with_limits(snapshot, RegistryLimits::UNBOUNDED)
    }

    /// Budgets cover both phases, retained serialized input and decoded cache
    /// inserts. A failed refresh preserves the previous registry and usage.
    pub fn refresh_from_snapshot_with_limits(&mut self, snapshot: &dyn SnapshotReadable, limits: RegistryLimits) -> QuilResult<()> {
        let mut budget = RegistryBudget::new(limits)?;
        // The rows every store watches (`prover_registry_key_prefixes`).
        let shard = quil_store::encoding::prover_registry_shard();
        let (mut largest_row, mut largest_value) = (0usize, 0usize);
        let mut row = |key: usize, value: usize| {
            largest_row = largest_row.max(key.saturating_add(value));
            largest_value = largest_value.max(value);
        };

        // Walk the per-vertex keyspace — the canonical record of
        // vertex content. `LazyVectorCommitmentTree::commit` writes
        // every leaf there on every commit, and the RPC sync path
        // populates it too. One row per `(set, phase, shard, vk)` so
        // no dedup is required.
        let mut rows = RegistryRows::default();
        visit_registry_vertices(snapshot, "adds", &shard, limits.page(), |vk, data| {
            budget.input(vk.len(), data.len(), true)?;
            row(vk.len(), data.len());
            rows.add(vk[32..].try_into().expect("64-byte registry key"), &data);
            // Rows retain the decoded data. Release serialized blobs with each
            // page instead of holding another whole registry until publication.
            Ok(())
        })?;
        let from_rows = rows.has_adds();

        // Transitional bootstrap: stores from before the per-vertex
        // commit invariant have data only in the tree blob. Fall back
        // to deserializing the blob and using its leaves so a refresh
        // running before the first post-upgrade commit doesn't see an
        // empty cache. The next commit re-populates the per-vertex
        // range, after which this branch is a no-op.
        let mut leaves: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        if !from_rows {
            if let Some(blob) = snapshot.load_tree_blob("vertex", "adds", &shard)? {
                budget.input(0, blob.len(), false)?;
                if let Some(root) = quil_tries::deserialize_tree(&blob)
                    .map_err(|e| QuilError::Store(format!("registry legacy tree: {e}")))?
                {
                    collect_legacy(&root, &mut leaves, &mut budget)?;
                }
            }
        }

        // Subtract removals. `remove_vertex` tombstones a vertex in the "removes"
        // phase but LEAVES its "adds" blob intact (see
        // `HypergraphCrdt::remove_vertex`), so an adds-only walk resurrects any
        // vertex that was DELETED from committed state — e.g. the non-archive
        // prover records the unified split reset drops. Without this exclusion the
        // registry keeps reporting a dropped allocation as Active, so the
        // lifecycle never notices it's gone and never re-joins (the app-shard then
        // fails its storage attestation against committed state). Exclude any vk
        // present in "removes" so the cache reflects committed `adds ∧ ¬removes`,
        // matching the CRDT's own scan and the authoritative committed reads.
        // A no-op except after a real deletion — removes is empty on the prover
        // shard in steady state (leaves/kicks flip Status in place, they don't
        // delete).
        let mut removed_vks: std::collections::HashSet<Vec<u8>> =
            std::collections::HashSet::new();
        visit_registry_vertices(snapshot, "removes", &shard, limits.page(), |vk, data| {
            budget.input(vk.len(), data.len(), true)?;
            row(vk.len(), data.len());
            rows.remove(vk[32..].try_into().expect("64-byte registry key"), data.len());
            removed_vks.insert(vk);
            Ok(())
        })?;
        if !removed_vks.is_empty() {
            leaves.retain(|(vk, _)| !removed_vks.contains(vk));
        }

        let mut replacement = Self::new();
        if from_rows {
            // The same rows, passes and charges as `decode_vertices`, indexed
            // so a later change to some rows updates only what they feed.
            replacement.compose_from_rows(&mut rows, &mut budget)?;
            replacement.rows = Some(Arc::new(rows));
        } else {
            replacement.decode_vertices(&leaves, &mut budget)?;
        }
        replacement.resource_usage = budget.usage;
        replacement.from_rows = from_rows;
        replacement.scanned = snapshot.scan_point().filter(|_| from_rows);
        replacement.largest_row = largest_row;
        replacement.largest_value = largest_value;
        *self = replacement;
        Ok(())
    }

    /// Whether a refresh of the view at `capture` with `limits` would read
    /// exactly this registry's rows and succeed: no watched write since this
    /// registry's scan, and every budget it charged fits. Budgets only grow
    /// during a refresh, so the final usage decides; per-row and page limits
    /// are checked against the largest row read.
    fn reproduces(&self, capture: &CapturePoint, limits: RegistryLimits) -> bool {
        let usage = self.resource_usage;
        self.scanned.is_some_and(|scan| capture.sees_watched_keys_of(&scan))
            && usage.vertices <= limits.max_vertices
            && usage.input_bytes <= limits.max_input_bytes
            && usage.cache_entries <= limits.max_cache_entries
            && usage.cache_bytes <= limits.max_cache_bytes
            && self.largest_row <= limits.max_record_bytes
            && self.largest_value.saturating_add(64) <= limits.page().max_bytes
    }

    fn decode_vertices(&mut self, leaves: &[(Vec<u8>, Vec<u8>)], budget: &mut RegistryBudget) -> QuilResult<()> {
        // Two-pass walk: first collect provers, then collect allocations.
        // The iterator order is arbitrary, so if we did it in one pass
        // we'd need to synthesize stubs when an allocation arrives
        // before its prover. Two passes are cleaner.
        //
        // Pass 1: provers. A retired prover (status left/kicked) gets no row
        // of its own, but its public key is kept: a row synthesized for one
        // of its allocations in pass 2 must still carry it. An empty key there
        // made an authorized session member unattributable (a live halt).
        let mut retired_keys: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        for (vk, data) in leaves {
            if vk.len() != 64 {
                continue;
            }
            let root = match deserialize_go_tree(data) {
                Ok(Some(r)) => r,
                _ => continue,
            };
            let Some(type_hash) = root.find_leaf_value(&vec![0xFFu8; 32]) else {
                self.unknown_vertex_count += 1;
                continue;
            };
            match class_for_type_hash(&type_hash) {
                Some("prover:Prover") => {
                    self.prover_vertex_count += 1;
                    if let Some(info) = decode_prover(vk, &root) {
                        budget.prover(&info)?;
                        self.prover_cache.insert(info.address.clone(), info);
                    } else {
                        let key = read_bytes(&root, "prover:Prover", "PublicKey");
                        if !key.is_empty() {
                            retired_keys.insert(vk[32..64].to_vec(), key);
                        }
                    }
                }
                Some("reward:ProverReward") => {
                    self.reward_vertex_count += 1;
                }
                Some("leafroot:LeafRootRegistration") => {
                    self.leaf_root_vertex_count += 1;
                    for (key, rec) in decode_leaf_root(&root) {
                        budget.leaf_root(&key, &rec)?;
                        self.leaf_root_cache.insert(key, rec);
                    }
                }
                Some("allocation:ProverAllocation") => {
                    // Handled in pass 2.
                }
                _ => {
                    self.unknown_vertex_count += 1;
                }
            }
        }

        // Pass 2: allocations. Needs provers already in cache so we
        // can attach allocations to the right owner.
        for (vk, data) in leaves {
            if vk.len() != 64 {
                continue;
            }
            let root = match deserialize_go_tree(data) {
                Ok(Some(r)) => r,
                _ => continue,
            };
            let Some(type_hash) = root.find_leaf_value(&vec![0xFFu8; 32]) else {
                continue;
            };
            if type_hash != TYPE_HASH_ALLOCATION {
                continue;
            }
            self.allocation_vertex_count += 1;
            let Some((prover_ref, alloc)) = decode_allocation(vk, &root) else {
                continue;
            };
            budget.allocation(&prover_ref, &alloc)?;
            self.attach_allocation(&prover_ref, alloc, retired_keys.get(&prover_ref));
        }
        Ok(())
    }

    /// Append `alloc` to its owner, synthesizing the owner's row (keyed by a
    /// retired prover's public key) when it has none, and index its filter.
    fn attach_allocation(&mut self, prover_ref: &[u8], alloc: ProverAllocationInfo, retired_key: Option<&Vec<u8>>) {
        // Find or synthesize the parent prover.
        let prover_entry = self
            .prover_cache
            .entry(prover_ref.to_vec())
            .or_insert_with(|| ProverInfo {
                public_key: retired_key.cloned().unwrap_or_default(),
                address: prover_ref.to_vec(),
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
        match filter_list.binary_search_by(|a| a.as_slice().cmp(prover_ref)) {
            Ok(_) => {}
            Err(idx) => filter_list.insert(idx, prover_ref.to_vec()),
        }

        if is_active {
            let addr_filters = self
                .address_to_filters
                .entry(prover_ref.to_vec())
                .or_default();
            if !addr_filters.iter().any(|f| f == &confirmation_filter) {
                addr_filters.push(confirmation_filter);
            }
        }
    }

    pub fn resource_usage(&self) -> RegistryUsage { self.resource_usage }

    /// Everything a refresh determines, in a fixed order (not the scan point).
    #[cfg(test)]
    fn content(&self) -> String {
        fn sorted<K: Ord + Clone, V: Clone>(map: &HashMap<K, V>) -> Vec<(K, V)> {
            let mut entries: Vec<_> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            entries
        }
        format!(
            "{:?}",
            (
                sorted(&self.prover_cache),
                sorted(&self.leaf_root_cache),
                sorted(&self.filter_cache),
                sorted(&self.address_to_filters),
                (self.reward_vertex_count, self.prover_vertex_count, self.allocation_vertex_count,
                    self.leaf_root_vertex_count, self.unknown_vertex_count),
                self.resource_usage,
                (self.largest_row, self.largest_value, self.from_rows),
            ),
        )
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

    /// [`Self::get_provers`] over all of `filters`, each prover once, in
    /// first-seen order.
    pub fn get_provers_on_filters(&self, filters: &[Vec<u8>]) -> Vec<&ProverInfo> {
        let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
        let mut out: Vec<&ProverInfo> = Vec::new();
        for filter in filters {
            let Some(addrs) = self.filter_cache.get(filter) else {
                continue;
            };
            for addr in addrs {
                if !seen.insert(addr.as_slice()) {
                    continue;
                }
                if let Some(info) = self.prover_cache.get(addr) {
                    out.push(info);
                }
            }
        }
        out
    }

    pub fn get_active_provers(&self, filter: &[u8], frame_number: u64) -> Vec<&ProverInfo> {
        let Some(addrs) = self.filter_cache.get(filter) else {
            return Vec::new();
        };
        let members = |lenient: bool| -> Vec<&ProverInfo> {
            addrs
                .iter()
                .filter_map(|a| self.prover_cache.get(a))
                .filter(|p| p.allocations.iter().any(|alloc| {
                    alloc.confirmation_filter == filter
                        && committee_eligible(alloc, frame_number, lenient)
                }))
                .collect()
        };
        let strict = members(false);
        // Empty-committee guard: a non-empty (app-shard) committee must never
        // vanish just because every member was demoted by `effective_status`
        // (a sole freshly-joined prover in its deferred window, or every member
        // transiently stale mid-re-confirm) — that would strand an otherwise-
        // live shard. Fall back to the raw-`Active` floor. Applied identically
        // by producer + verifier (same `frame_number`), so it can't fork; only
        // ever LOOSENS the set, never below the old raw-Active set. The global
        // (empty) filter never needs it — its allocations are never demoted —
        // so `strict` there already equals the full set.
        if !strict.is_empty() || filter.is_empty() {
            strict
        } else {
            members(true)
        }
    }

    pub fn get_prover_count(&self, filter: &[u8]) -> usize {
        self.filter_cache.get(filter).map(|v| v.len()).unwrap_or(0)
    }

    /// Return all prover addresses under `filter` sorted by modular
    /// distance from `input`, ties broken by key value. When `filter`
    /// is empty, iterates global-committee provers (those with a live
    /// active allocation under the global filter) — never includes
    /// app-shard-only provers, even if their prover record exists.
    /// Otherwise iterates the per-filter cache, restricted to provers
    /// whose allocation under that filter is `Active`.
    ///
    /// This filtering matters for leader rotation: an unfiltered
    /// candidate set causes a non-global prover (e.g. one mid-join
    /// with all allocations Joining) to be picked as leader, after
    /// which it cannot produce proposals (the consensus event loop
    /// is intentionally not activated for non-global provers) and
    /// the chain stalls timing out for the rest of its rank window.
    pub fn get_ordered_provers(&self, input: &[u8], filter: &[u8], frame_number: u64) -> Vec<Vec<u8>> {
        let modulus = bn254_modulus();
        let target = BigInt::from_bytes_be(num_bigint::Sign::Plus, input);

        // Eligibility for leader rotation is the SAME committee set as
        // `get_active_provers` (they MUST agree — the leader at a rank must be a
        // member others count toward quorum), including the same empty-committee
        // guard. Determined by allocation `effective_status` via
        // `committee_eligible` at `frame_number`, not the prover's aggregate
        // `status` rollup (whose freshness lags the materializer).
        let candidates: Vec<Vec<u8>> = if filter.is_empty() {
            // Global view: provers with a live allocation under the empty
            // (global) filter — the genesis allocation. Empty-filter
            // allocations are never ExpiredEpoch, so `lenient` is irrelevant.
            let mut all: Vec<Vec<u8>> = self
                .prover_cache
                .iter()
                .filter(|(_, p)| {
                    p.allocations.iter().any(|a| {
                        a.confirmation_filter.is_empty()
                            && committee_eligible(a, frame_number, false)
                    })
                })
                .map(|(addr, _)| addr.clone())
                .collect();
            all.sort();
            all
        } else {
            // Per-filter view: committee members under this filter at
            // `frame_number` — Active or Leaving-within-grace; not Joining
            // (incl. deferred-activation), ExpiredLeaving, or terminal. Falls
            // back to the raw-Active floor if the strict set is empty (same
            // empty-committee guard as `get_active_provers`).
            let Some(addrs) = self.filter_cache.get(filter) else {
                return Vec::new();
            };
            let pick = |lenient: bool| -> Vec<Vec<u8>> {
                addrs
                    .iter()
                    .filter(|a| {
                        self.prover_cache
                            .get(*a)
                            .map(|p| {
                                p.allocations.iter().any(|alloc| {
                                    alloc.confirmation_filter == filter
                                        && committee_eligible(alloc, frame_number, lenient)
                                })
                            })
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect()
            };
            let strict = pick(false);
            if strict.is_empty() {
                pick(true)
            } else {
                strict
            }
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
    pub fn get_next_prover(&self, input: &[u8], filter: &[u8], frame_number: u64) -> Option<Vec<u8>> {
        self.get_ordered_provers(input, filter, frame_number).into_iter().next()
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

    /// Per-filter prover count grouped by allocation status. See the
    /// `live_allocation_status` helper for the filter rules; this
    /// just bucketizes its outputs.
    ///
    /// This is the cache that drives halt-risk classification: an
    /// inflated count from including dead allocations causes the
    /// proposer to skip real halt-risk shards and pile onto already-
    /// healthy ones.
    pub fn get_prover_shard_summaries(
        &self,
        frame_number: u64,
    ) -> Vec<ProverShardSummary> {
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
                for alloc in &info.allocations {
                    let filter_matches = (!alloc.confirmation_filter.is_empty()
                        && alloc.confirmation_filter == *filter_key)
                        || (!alloc.rejection_filter.is_empty()
                            && alloc.rejection_filter == *filter_key);
                    if !filter_matches {
                        continue;
                    }
                    // Map effective status → live status (or skip if dead).
                    // (prover, filter) is unique per the allocation-address
                    // invariant: `allocation_address(pubkey, filter)` is
                    // deterministic and mutations overwrite, so there is
                    // exactly one allocation row per (prover, filter).
                    if let Some(live) =
                        live_allocation_status(alloc, info.status, frame_number)
                    {
                        *status_counts.entry(live).or_insert(0) += 1;
                    }
                    break;
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
        self.diverged |= touched > 0;
        touched
    }

    /// Select the allocations to evict for inactivity. Read phase only:
    /// the caller writes the kicks (see
    /// [`SharedProverRegistry::evict_inactive_provers`]).
    ///
    /// Eviction works per allocation: a prover that is stale on one shard
    /// loses only that allocation, not its other allocations, status or
    /// seniority. Each shard keeps at least `MIN_SHARD_CONSENSUS_PROVERS`
    /// effectively-active allocations (see [`limit_evictions_to_shard_floor`]).
    /// A stalled shard, one on which fewer than two thirds of the active
    /// allocations are fresh, loses none (see [`shard_progressing`] and
    /// [`allocation_fresh_at`]): inactivity there does not tell who votes.
    ///
    /// `shard_halt_durations` maps confirmation-filter bytes →
    /// number of frames the shard has been in a halt state. A value
    /// of `u64::MAX` fully exempts that shard for this tick.
    ///
    /// The result is sorted by (prover address, confirmation filter), so it
    /// is a pure function of the registry contents.
    pub fn find_eviction_candidates(
        &self,
        frame_number: u64,
        inactivity_threshold: u64,
        shard_halt_durations: &HashMap<Vec<u8>, u64>,
    ) -> Vec<EvictionCandidate> {
        self.find_eviction_candidates_at(
            frame_number,
            inactivity_threshold,
            shard_halt_durations,
            quil_types::consensus::SIGNED_FRAME_ACTIVATION_FRAME,
        )
    }

    /// [`Self::find_eviction_candidates`] with the stall census reading
    /// `LastSignedFrameNumber` from `signed_frame_activation` (see
    /// [`allocation_fresh_at`]), so tests can activate it.
    fn find_eviction_candidates_at(
        &self,
        frame_number: u64,
        inactivity_threshold: u64,
        shard_halt_durations: &HashMap<Vec<u8>, u64>,
        signed_frame_activation: u64,
    ) -> Vec<EvictionCandidate> {
        self.scan_eviction_candidates_at(
            frame_number,
            inactivity_threshold,
            shard_halt_durations,
            signed_frame_activation,
        )
        .candidates
    }

    /// [`Self::find_eviction_candidates`] with the census that spared the
    /// other stale allocations, for the eviction pass log.
    pub fn scan_eviction_candidates(
        &self,
        frame_number: u64,
        inactivity_threshold: u64,
        shard_halt_durations: &HashMap<Vec<u8>, u64>,
    ) -> EvictionScan {
        self.scan_eviction_candidates_at(
            frame_number,
            inactivity_threshold,
            shard_halt_durations,
            quil_types::consensus::SIGNED_FRAME_ACTIVATION_FRAME,
        )
    }

    fn scan_eviction_candidates_at(
        &self,
        frame_number: u64,
        inactivity_threshold: u64,
        shard_halt_durations: &HashMap<Vec<u8>, u64>,
        signed_frame_activation: u64,
    ) -> EvictionScan {
        // Per-shard census of effectively-active allocations at this frame.
        // A shard with fewer than `MIN_SHARD_CONSENSUS_PROVERS` active provers
        // cannot run its consensus (it is under a coverage halt), so NO shard
        // frame can be produced and its provers cannot advance
        // `last_active_frame_number` — evicting them for inactivity would
        // punish a shortfall they can't fix and spiral the shard to zero.
        // The same census bounds how many of a shard's allocations one pass
        // may evict, so eviction itself never pushes a shard below that
        // minimum. Counted exactly like the coverage monitor
        // (`effective_status == Active`, ignoring the parent prover byte) so
        // the two agree, and derived from the same committed registry state
        // the eviction pass reads below — deterministic across the fleet,
        // independent of the per-node coverage monitor / shard-size source.
        // The fresh count per shard drives the stall exemption.
        let (active_by_filter, fresh_by_filter) = self.eviction_census(
            frame_number,
            inactivity_threshold,
            shard_halt_durations,
            signed_frame_activation,
        );
        let mut scan = EvictionScan {
            shards: active_by_filter.len() as u64,
            active: active_by_filter.values().sum(),
            ..EvictionScan::default()
        };
        scan.stalled = active_by_filter
            .iter()
            .filter(|(_, active)| **active > quil_types::consensus::MIN_SHARD_CONSENSUS_PROVERS)
            .map(|(filter, &active)| {
                (filter.clone(), active, fresh_by_filter.get(filter).copied().unwrap_or(0))
            })
            .filter(|&(_, active, fresh)| !shard_progressing(active, fresh))
            .collect();
        scan.stalled.sort();

        let mut stale: Vec<EvictionCandidate> = Vec::new();
        for info in self.prover_cache.values() {
            // Consider Active provers (normal eviction) AND `Unknown`
            // stubs. A stub is synthesized by `refresh` (pass 2) when an
            // allocation's parent prover vertex is absent/undecodable —
            // which is exactly the orphan state left when an earlier
            // eviction kicked the PROVER vertex (Status=4 → decode_prover
            // returns None) but NOT its allocation vertices. Those stubs
            // keep their still-Active allocations counted in shard
            // summaries forever, yet were skipped here (so they never
            // returned to the eviction set). Including `Unknown` lets the
            // per-allocation checks below re-select them so their lingering
            // active allocations get kicked and drop out of the count.
            // Other lifecycle states (Joining/Paused/Leaving/Rejected) are
            // still skipped — only genuine orphans look like `Unknown`.
            if info.status != ProverStatus::Active
                && info.status != ProverStatus::Unknown
            {
                continue;
            }
            for alloc in &info.allocations {
                // Frame-aware: only an allocation that is EFFECTIVELY Active for
                // this frame accrues inactivity. Gating on the RAW `alloc.status`
                // wrongly evicted epoch-EXPIRED allocations — the raw status
                // stays `Active` after the epoch ends, but `effective_status`
                // returns `ExpiredEpoch`. Such allocations are already excluded
                // from the committee and the shard summaries (both go through
                // `live_allocation_status`), so evicting them for "inactivity"
                // when they aren't even expected to be active was inconsistent
                // (the "up for eviction but no active shards" contradiction).
                // This matches the committee filter's frame-aware gating; an
                // epoch-expired prover is handled by the epoch lifecycle, not
                // inactivity eviction. Orphan (`Unknown`-prover) allocations
                // whose epoch is still valid remain `Active` here and are still
                // kicked.
                if alloc.effective_status(frame_number) != EffectiveStatus::Active {
                    continue;
                }
                // Global provers (empty confirmation filter) are never
                // evicted.
                if alloc.confirmation_filter.is_empty() {
                    continue;
                }
                // Inactivity first, so the pass log counts what each
                // exemption below spares.
                let halt_duration = shard_halt_durations
                    .get(&alloc.confirmation_filter)
                    .copied()
                    .unwrap_or(0);
                if halt_duration == u64::MAX {
                    continue;
                }
                let Some(effective_inactive) =
                    effective_inactivity(alloc, frame_number, halt_duration)
                else {
                    continue;
                };
                if effective_inactive <= inactivity_threshold {
                    continue;
                }
                // Coverage-halt / under-provisioned exemption: if this shard
                // has fewer than the consensus minimum of active provers it
                // cannot run consensus, so no shard frame is produced and this
                // prover cannot possibly submit a proof — inactivity here is
                // not its fault. Skip (do not accrue inactivity, do not evict).
                // Subsumes the coverage-halt case and the "not enough provers
                // to run consensus" case the coverage `shard_halt_durations`
                // map handled inconsistently (it dropped empty under-covered
                // shards, which then evicted their provers anyway). A shard
                // exactly at the minimum has no allocation to spare either;
                // `limit_evictions_to_shard_floor` enforces that bound, so
                // skipping it here only saves the work.
                let shard_active = active_by_filter
                    .get(&alloc.confirmation_filter)
                    .copied()
                    .unwrap_or(0);
                if shard_active <= quil_types::consensus::MIN_SHARD_CONSENSUS_PROVERS {
                    scan.spared_floor += 1;
                    continue;
                }
                // Stall exemption: a shard that certified no frame within the
                // threshold ages all its members alike, so none is selected.
                let shard_fresh = fresh_by_filter
                    .get(&alloc.confirmation_filter)
                    .copied()
                    .unwrap_or(0);
                if !shard_progressing(shard_active, shard_fresh) {
                    scan.spared_stalled += 1;
                    continue;
                }
                stale.push(EvictionCandidate {
                    prover_address: info.address.clone(),
                    confirmation_filter: alloc.confirmation_filter.clone(),
                    vertex_address: alloc.vertex_address.clone(),
                    effective_inactive,
                });
            }
        }
        scan.stale = stale.len() as u64;
        scan.candidates = limit_evictions_to_shard_floor(stale, &active_by_filter);
        scan
    }

    /// Effectively-active allocations per confirmation filter at
    /// `frame_number` (empty filters excluded), and how many of them are
    /// fresh ([`allocation_fresh_at`]): at most `inactivity_threshold` frames
    /// inactive since their last credit, with credit later than the join
    /// confirm. The credit is `LastActiveFrameNumber`, or
    /// `LastSignedFrameNumber` once the signed-frame census governs. The
    /// census [`Self::find_eviction_candidates`] applies its stall exemption
    /// and shard floor to.
    fn eviction_census(
        &self,
        frame_number: u64,
        inactivity_threshold: u64,
        shard_halt_durations: &HashMap<Vec<u8>, u64>,
        signed_frame_activation: u64,
    ) -> (HashMap<Vec<u8>, u64>, HashMap<Vec<u8>, u64>) {
        let mut active_by_filter: HashMap<Vec<u8>, u64> = HashMap::new();
        let mut fresh_by_filter: HashMap<Vec<u8>, u64> = HashMap::new();
        for info in self.prover_cache.values() {
            for alloc in &info.allocations {
                if alloc.confirmation_filter.is_empty()
                    || alloc.effective_status(frame_number) != EffectiveStatus::Active
                {
                    continue;
                }
                *active_by_filter
                    .entry(alloc.confirmation_filter.clone())
                    .or_insert(0) += 1;
                let halt_duration = shard_halt_durations
                    .get(&alloc.confirmation_filter)
                    .copied()
                    .unwrap_or(0);
                if allocation_fresh_at(
                    alloc,
                    frame_number,
                    halt_duration,
                    inactivity_threshold,
                    signed_frame_activation,
                ) {
                    *fresh_by_filter
                        .entry(alloc.confirmation_filter.clone())
                        .or_insert(0) += 1;
                }
            }
        }
        (active_by_filter, fresh_by_filter)
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

/// What one eviction census saw: the selected allocations, and how many
/// allocations past the threshold each exemption spared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvictionScan {
    /// The selection [`InMemoryProverRegistry::find_eviction_candidates`]
    /// returns, in its order.
    pub candidates: Vec<EvictionCandidate>,
    /// Shards with an effectively-active allocation.
    pub shards: u64,
    /// Effectively-active allocations on those shards.
    pub active: u64,
    /// Allocations past the threshold on progressing shards above the
    /// floor, before the floor limit.
    pub stale: u64,
    /// Past the threshold on a shard at or below the consensus minimum.
    pub spared_floor: u64,
    /// Past the threshold on a stalled shard ([`shard_progressing`]).
    pub spared_stalled: u64,
    /// Stalled shards above the floor as (filter, active, fresh), by filter.
    pub stalled: Vec<(Vec<u8>, u64, u64)>,
}

/// Allocations one eviction pass kicks at most: the first of the sorted
/// candidates, so every archive kicks the same ones.
pub const EVICTION_MAX_PER_PASS: usize = 25;

/// One allocation selected for inactivity eviction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictionCandidate {
    /// Address of the prover that owns the allocation.
    pub prover_address: Vec<u8>,
    /// The allocation's confirmation filter (the shard it serves).
    pub confirmation_filter: Vec<u8>,
    /// The allocation vertex address (32 bytes; empty if unknown).
    pub vertex_address: Vec<u8>,
    /// Frames of inactivity counted against the allocation, after halt credit.
    pub effective_inactive: u64,
}

impl EvictionCandidate {
    /// Whether this candidate names the same allocation as `other`
    /// (prover and shard), regardless of the inactivity measured.
    pub fn same_allocation(&self, other: &EvictionCandidate) -> bool {
        self.prover_address == other.prover_address
            && self.confirmation_filter == other.confirmation_filter
    }
}

/// Frames of inactivity counted against `alloc` at `frame_number`, after
/// `halt_duration` frames of halt credit, counted from [`inactivity_start`].
/// `None` for an allocation never credited (`LastActiveFrameNumber` 0): it
/// accrues no inactivity.
fn effective_inactivity(
    alloc: &ProverAllocationInfo,
    frame_number: u64,
    halt_duration: u64,
) -> Option<u64> {
    if alloc.last_active_frame_number == 0 {
        return None;
    }
    Some(frame_number.saturating_sub(inactivity_start(alloc)).saturating_sub(halt_duration))
}

/// First frame from which `alloc` accrues inactivity: its last activity
/// credit, but not before the network is considered live for eviction
/// (EVICTION_INACTIVITY_START_FRAME), nor before its activation. A joined
/// allocation enters its committee at the first frame of the epoch after its
/// join confirm and cannot sign a frame before then, while the confirm's own
/// credit is already most of an epoch old at that boundary's eviction pass.
pub fn inactivity_start(alloc: &ProverAllocationInfo) -> u64 {
    inactivity_start_from(alloc, alloc.last_active_frame_number)
}

/// [`inactivity_start`] counted from the credit `credit` instead of
/// `LastActiveFrameNumber`.
fn inactivity_start_from(alloc: &ProverAllocationInfo, credit: u64) -> u64 {
    let mut start = credit.max(quil_types::consensus::EVICTION_INACTIVITY_START_FRAME);
    if alloc.join_confirm_frame_number > 0 {
        let activation = (quil_types::consensus::epoch_for_frame(alloc.join_confirm_frame_number) + 1)
            .saturating_mul(quil_types::consensus::epoch_length_frames());
        start = start.max(activation);
    }
    start
}

/// Whether the stall census credits allocations by `LastSignedFrameNumber` at
/// `frame_number`: from one `inactivity_threshold` after
/// `signed_frame_activation`, when every member has had a full threshold of
/// frames that record the field to sign one. With the disabled default
/// (`u64::MAX`) the bound saturates at `u64::MAX`, past every reachable frame.
pub fn signed_frame_census_governs(
    frame_number: u64,
    inactivity_threshold: u64,
    signed_frame_activation: u64,
) -> bool {
    frame_number >= signed_frame_activation.saturating_add(inactivity_threshold)
}

/// Whether `alloc` counts as fresh in its shard's stall census at
/// `frame_number`: at most `inactivity_threshold` frames inactive after
/// `halt_duration` frames of halt credit, counted from its last credit as
/// [`inactivity_start`] counts (not before EVICTION_INACTIVITY_START_FRAME or
/// its activation), with that credit later than its join confirm. The confirm
/// writes `LastActiveFrameNumber` itself, so credit no later than it says
/// nothing about signing frames; a never-credited allocation (credit 0) is
/// not fresh either.
///
/// The credit is `LastActiveFrameNumber` until
/// [`signed_frame_census_governs`], then `LastSignedFrameNumber`, which only
/// the signers of an included app frame record. Public paths pass
/// `SIGNED_FRAME_ACTIVATION_FRAME`; reads committed registry fields only.
pub fn allocation_fresh_at(
    alloc: &ProverAllocationInfo,
    frame_number: u64,
    halt_duration: u64,
    inactivity_threshold: u64,
    signed_frame_activation: u64,
) -> bool {
    let credit = if signed_frame_census_governs(
        frame_number,
        inactivity_threshold,
        signed_frame_activation,
    ) {
        alloc.last_signed_frame_number
    } else {
        alloc.last_active_frame_number
    };
    credit > alloc.join_confirm_frame_number
        && frame_number
            .saturating_sub(inactivity_start_from(alloc, credit))
            .saturating_sub(halt_duration)
            <= inactivity_threshold
}

/// Whether a shard with `active` effectively-active allocations, `fresh` of
/// them within the inactivity threshold ([`allocation_fresh_at`]), is
/// progressing: `fresh` is at least two thirds of `active`. Each finalized app
/// frame GLOBAL includes credits its signers, two thirds of the shard's active
/// members. A committee below that quorum certifies nothing, so its voting
/// and absent members age alike and eviction could only pick by address; it
/// skips such a stalled shard. A frame included within the threshold credited
/// two thirds of the members, so a producing shard stays eligible.
///
/// A join confirm's own credit is not fresh. Until the signed-frame census
/// governs ([`signed_frame_census_governs`]), the credit is
/// `LastActiveFrameNumber`, which confirms also advance. Limitation: an epoch
/// re-confirm records no frame of its own, so a stalled shard on which two
/// thirds of the members re-confirmed within the threshold reads as
/// progressing. Once the census governs, the credit is
/// `LastSignedFrameNumber`, which only signers record, and re-confirms no
/// longer count. Errors the other way only exempt a shard: a committee grown
/// since its last frame, or credited signers now `Leaving`, lowers the fresh
/// share.
pub fn shard_progressing(active: u64, fresh: u64) -> bool {
    u128::from(fresh) * 3 >= u128::from(active) * 2
}

/// Keep, per shard, at most `active − MIN_SHARD_CONSENSUS_PROVERS` of the
/// `stale` allocations, so evicting them all leaves the shard with at least
/// the consensus minimum of effectively-active allocations. `active_by_filter`
/// is the shard's effectively-active census, stale allocations included. The
/// most inactive allocations are kept first, ties broken by prover address
/// (then vertex address). The result is sorted by (prover address,
/// confirmation filter), independent of the input order.
pub fn limit_evictions_to_shard_floor(
    stale: Vec<EvictionCandidate>,
    active_by_filter: &HashMap<Vec<u8>, u64>,
) -> Vec<EvictionCandidate> {
    let mut by_filter: std::collections::BTreeMap<Vec<u8>, Vec<EvictionCandidate>> =
        std::collections::BTreeMap::new();
    for candidate in stale {
        by_filter
            .entry(candidate.confirmation_filter.clone())
            .or_default()
            .push(candidate);
    }
    let mut out: Vec<EvictionCandidate> = Vec::new();
    for (filter, mut group) in by_filter {
        let active = active_by_filter.get(&filter).copied().unwrap_or(0);
        let allowance = active.saturating_sub(quil_types::consensus::MIN_SHARD_CONSENSUS_PROVERS);
        let allowance = usize::try_from(allowance).unwrap_or(usize::MAX);
        group.sort_by(|a, b| {
            b.effective_inactive
                .cmp(&a.effective_inactive)
                .then_with(|| a.prover_address.cmp(&b.prover_address))
                .then_with(|| a.vertex_address.cmp(&b.vertex_address))
        });
        group.truncate(allowance);
        out.extend(group);
    }
    out.sort_by(|a, b| {
        a.prover_address
            .cmp(&b.prover_address)
            .then_with(|| a.confirmation_filter.cmp(&b.confirmation_filter))
            .then_with(|| a.vertex_address.cmp(&b.vertex_address))
    });
    out
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
/// Map a single allocation to its live status (the value surfaced
/// to halt-risk classifiers, RPC summaries, lifecycle decisions).
///
/// Returns `Some(status)` for live allocations and `None` for ones
/// that have effectively been removed:
///
/// - `Joining` (within 720-frame grace) → `Some(Joining)`
/// - `Active` → `Some(Active)`
/// - `Paused` → `Some(Paused)`
/// - `Leaving` (within grace) → `Some(Leaving)`
/// - `ExpiredLeaving` (leave attempt never confirmed/rejected) →
/// `None` (excluded). The prover socially left the shard even
/// though the LeaveConfirm never landed — they stopped proving
/// when they submitted the Leave. Counting them as Active would
/// inflate every shard's live coverage by the number of stuck
/// leaves, which hides real halt-risk shards from the proposer
/// and coverage monitor: a halt-risk shard (active ≤ 3) with 1+
/// ExpiredLeaving allocations would otherwise be classified as ≥4
/// active.
/// - `ExpiredJoining`, `Rejected`, `Kicked` → `None` (excluded)
/// - `Unknown` → `None`
///
/// `prover_status` is the parent prover's overall status, used only
/// when an allocation matched but its own status was Unknown.
fn live_allocation_status(
    alloc: &ProverAllocationInfo,
    _prover_status: ProverStatus,
    frame_number: u64,
) -> Option<ProverStatus> {
    match alloc.effective_status(frame_number) {
        EffectiveStatus::Joining => Some(ProverStatus::Joining),
        EffectiveStatus::Active => Some(ProverStatus::Active),
        EffectiveStatus::Paused => Some(ProverStatus::Paused),
        EffectiveStatus::Leaving => Some(ProverStatus::Leaving),
        EffectiveStatus::ExpiredJoining
        | EffectiveStatus::ExpiredLeaving
        | EffectiveStatus::ExpiredEpoch
        | EffectiveStatus::Rejected
        | EffectiveStatus::Kicked
        // Superseded by a reassignment — not a live allocation on this filter.
        | EffectiveStatus::Historic
        | EffectiveStatus::Unknown => None,
    }
}

/// From this GLOBAL frame a `Leaving` allocation is a committee member only
/// if it was current when its leave was proposed (`left_current`). A leave
/// is accepted from any raw `Active` allocation, also one that stopped
/// re-confirming epochs ago and reads `ExpiredEpoch`, and `effective_status`
/// reads every unexpired leave as `Leaving` whatever its recorded epoch. So
/// a leave made such a lapsed allocation committee-eligible again for its
/// notice, and the next epoch's membership pass seated it in successor
/// committees it never served, raising their quorum beyond their voters.
/// The committee is evaluated at the frame it serves, so the rule changes
/// committee seating, leader rotation and quorum alike: consensus-affecting,
/// and every archive and prover must run a build with it before the frame.
/// Not scheduled on mainnet; `QUIL_LEAVER_CURRENCY_FRAME` elsewhere, never
/// by default.
pub const MAINNET_LEAVER_CURRENCY_FRAME: Option<u64> = None;

static LEAVER_CURRENCY_FRAME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

thread_local! {
    static LEAVER_CURRENCY_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

fn leaver_currency_frame_for(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_LEAVER_CURRENCY_FRAME.unwrap_or(u64::MAX);
    }
    setting.and_then(|value| value.parse().ok()).unwrap_or(u64::MAX)
}

/// Fix this process's leaver currency frame from its network, and return
/// it. Called at startup before any frame is processed; the first call
/// decides.
pub fn init_leaver_currency_frame(network: u8) -> u64 {
    *LEAVER_CURRENCY_FRAME.get_or_init(|| {
        leaver_currency_frame_for(network, std::env::var("QUIL_LEAVER_CURRENCY_FRAME").ok().as_deref())
    })
}

pub fn leaver_currency_frame() -> u64 {
    if let Some(frame) = LEAVER_CURRENCY_OVERRIDE.with(|cell| cell.get()) {
        return frame;
    }
    *LEAVER_CURRENCY_FRAME.get_or_init(|| {
        std::env::var("QUIL_LEAVER_CURRENCY_FRAME").ok().and_then(|value| value.parse().ok()).unwrap_or(u64::MAX)
    })
}

/// Set the leaver currency frame for the calling thread only (tests).
pub fn set_leaver_currency_frame_for_thread(frame: Option<u64>) {
    LEAVER_CURRENCY_OVERRIDE.with(|cell| cell.set(frame));
}

/// Was the leaving `alloc` current, re-confirmed for the epoch, when its
/// leave was proposed? Only then does it keep serving its notice: `epoch`,
/// the highest epoch it registered leaf roots for, reaches the leave's
/// epoch, as `effective_status` requires of an `Active` allocation. The
/// global filter carries no epoch obligation, and a leave without a frame
/// (genesis and test fixtures) has no epoch to compare.
fn left_current(alloc: &ProverAllocationInfo) -> bool {
    alloc.confirmation_filter.is_empty()
        || alloc.leave_frame_number == 0
        || alloc.epoch >= quil_types::consensus::epoch_for_frame(alloc.leave_frame_number)
}

/// Is `alloc` a member of the epoch-aligned consensus committee at
/// `frame_number`? SHARED predicate behind both `get_active_provers`
/// (quorum membership) and `get_ordered_provers` (leader rotation) — they
/// must agree on the set or a leader could be picked from outside the
/// quorum. Aligns the committee with the `effective_status` view the rest
/// of the node (coverage, lifecycle buckets, worker allocator) already
/// uses; the committee filter was the last holdout on raw `status`.
///
/// Included: `Active`, and `Leaving`-within-grace (a departing prover
/// keeps serving notice — still proving, still counted — and stays in the
/// FROZEN committee until the E+2 boundary). From
/// [`leaver_currency_frame`] only a leaver that was current when it left
/// serves that notice ([`left_current`]).
///
/// Excluded: `Joining` — including a just-confirmed prover still inside
/// its deferred-activation window (raw `Active` byte but pre-E+2; it is
/// NOT running its consensus loop yet, so counting it inflated the quorum
/// denominator and could pick it as a leader that can't produce);
/// `ExpiredLeaving` (socially left); terminal (kicked/rejected).
///
/// The `lenient` flag is the EMPTY-COMMITTEE FLOOR (see the guard in
/// `get_active_provers`/`get_ordered_provers`). When the strict pass would
/// leave a non-empty (app-shard) filter with NO members, the lenient pass
/// re-admits any allocation whose RAW status is still `Active` but which
/// `effective_status` demoted — i.e. a deferred-activation prover
/// (raw `Active`, reads `Joining`) or a stale-epoch prover (reads
/// `ExpiredEpoch`). This guarantees a live shard's committee never vanishes
/// (a sole freshly-joined prover can still bootstrap its shard; a shard
/// mid-re-confirm never stalls) — never worse than the old raw-`Active`
/// filter. It does NOT re-admit never-confirmed joins (raw `Joining`),
/// `ExpiredLeaving`, or terminal allocations — those genuinely aren't
/// members. The empty/global filter can never be demoted (`effective_status`
/// exempts it), so GLOBAL consensus is completely unaffected either way.
fn committee_eligible(alloc: &ProverAllocationInfo, frame_number: u64, lenient: bool) -> bool {
    match alloc.effective_status(frame_number) {
        EffectiveStatus::Active => true,
        EffectiveStatus::Leaving => frame_number < leaver_currency_frame() || left_current(alloc),
        // Demoted-but-raw-Active: re-admitted only by the empty-committee floor.
        EffectiveStatus::Joining | EffectiveStatus::ExpiredEpoch => {
            lenient && alloc.status == ProverStatus::Active
        }
        _ => false,
    }
}

/// no-op because the trait doesn't know which store to read from.
#[derive(Clone)]
pub struct SharedProverRegistry {
    inner: Arc<RwLock<InMemoryProverRegistry>>,
    execution_binding: Option<(quil_types::store::BackingStoreIdentity, RegistryLimits)>,
}

pub(crate) struct PreparedRegistryAdoption<'a> {
    source: std::sync::RwLockWriteGuard<'a, InMemoryProverRegistry>,
    incoming: std::sync::RwLockWriteGuard<'a, InMemoryProverRegistry>,
    adopted: bool,
}

impl PreparedRegistryAdoption<'_> {
    pub(crate) fn adopt(&mut self) {
        if !self.adopted {
            std::mem::swap(&mut *self.source, &mut *self.incoming);
            self.adopted = true;
        }
    }

    /// Record that the adopted registry holds exactly the published database's
    /// rows at `scan`. The caller proves no other write reached them.
    pub(crate) fn published_at(&mut self, scan: ScanPoint) {
        if self.adopted && self.source.from_rows {
            self.source.scanned = Some(scan);
        }
    }
}

impl SharedProverRegistry {
    pub(crate) fn prepare_adoption<'a>(
        &'a self,
        incoming: &'a Self,
        overlay: &quil_types::store::BackingStoreIdentity,
    ) -> QuilResult<PreparedRegistryAdoption<'a>> {
        if self.shares_cache_with(incoming) || self.execution_binding.is_some()
            || incoming.execution_binding.as_ref().map(|(identity, _)| identity) != Some(overlay)
        {
            return Err(QuilError::ExecutionUnavailable("registry publication binding mismatch".into()));
        }
        // Readers of the canonical registry (leader selection, RPC) hold it
        // briefly; wait them out rather than discard the executed frame.
        let patience = quil_types::lock_patience::Patience::new();
        let source = patience.write(&self.inner).ok_or_else(|| QuilError::ExecutionUnavailable(
            "canonical registry is busy or poisoned".into()))?;
        let incoming = patience.write(&incoming.inner).ok_or_else(|| QuilError::ExecutionUnavailable(
            "private registry is busy or poisoned".into()))?;
        Ok(PreparedRegistryAdoption { source, incoming, adopted: false })
    }
    /// Identity only; this does not expose or clone the mutable cache.
    pub fn shares_cache_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(InMemoryProverRegistry::new())),
            execution_binding: None,
        }
    }

    /// Build an independent cache from one execution store. Future refreshes
    /// and eviction writes must use that same branch and its original limits.
    /// Clones of this value share only this branch's cache.
    pub fn for_execution_store(store: &dyn HypergraphStore, limits: RegistryLimits) -> QuilResult<Self> {
        Self::for_execution_capture(store, limits, None, None)
    }

    /// [`Self::for_execution_store`] for a branch captured at `capture`, the
    /// store's own capture point. When `seed` holds a scan no watched write
    /// has changed since, its cache is copied instead of read again: the same
    /// rows give the same registry. A busy seed is skipped.
    ///
    /// Those rows are committed state, which every node's canonical registry
    /// already holds in full, so they are read whole; `limits` then bound
    /// only what the branch writes above them ([`RegistryLimits::above`]).
    pub fn for_execution_capture(
        store: &dyn HypergraphStore,
        limits: RegistryLimits,
        seed: Option<&SharedProverRegistry>,
        capture: Option<CapturePoint>,
    ) -> QuilResult<Self> {
        let identity = store.backing_store_identity().ok_or_else(|| {
            QuilError::ExecutionUnavailable("registry requires identifiable execution store".into())
        })?;
        let committed = capture.is_some();
        let read_limits = if committed { RegistryLimits::UNBOUNDED } else { limits };
        let seeded = seed.zip(capture).and_then(|(seed, capture)| {
            let source = seed.inner.try_read().ok()?;
            source.reproduces(&capture, read_limits).then(|| source.clone())
        });
        let read = seeded.is_none();
        let mut registry = Self {
            inner: Arc::new(RwLock::new(seeded.unwrap_or_default())),
            execution_binding: Some((identity.clone(), read_limits)),
        };
        if read {
            registry.refresh_from_store(store)?;
        }
        if committed {
            let bound = registry.read(|r| limits.above(r.resource_usage(), r.largest_row));
            registry.execution_binding = Some((identity, bound));
        }
        Ok(registry)
    }

    /// `limits` as headroom above the committed registry this one comes
    /// from: a branch registry's own bound, or this canonical registry's
    /// usage. A busy canonical registry leaves `limits` as they are.
    fn headroom(&self, limits: RegistryLimits) -> RegistryLimits {
        match &self.execution_binding {
            Some((_, bound)) => bound.max(limits),
            None => self
                .inner
                .try_read()
                .map_or(limits, |r| limits.above(r.resource_usage(), r.largest_row)),
        }
    }

    /// [`Self::for_execution_capture`] for a branch over `overlay`. A fork of
    /// a branch that wrote prover rows has no capture point of its own; when
    /// `seed` holds a scan of the view beneath those writes, its cache is
    /// copied and brought up to date with the rows the fork carries
    /// ([`Self::update_written_rows`]), which is what reading every prover
    /// vertex through the fork gives. Forking a kept GLOBAL execution read
    /// them all again: 184 MB per fork, 6 s on one archive and 13–18 s on
    /// another, as long as executing its frames once more (2026-10-11).
    pub fn for_execution_overlay(
        store: &dyn HypergraphStore,
        limits: RegistryLimits,
        seed: Option<&SharedProverRegistry>,
        overlay: &quil_forest::ExecutionOverlay,
    ) -> QuilResult<Self> {
        if let Some(capture) = overlay.capture_point() {
            return Self::for_execution_capture(store, limits, seed, Some(capture));
        }
        // The view beneath the fork's writes is committed state; `limits`
        // bound the writes above it, as in `for_execution_capture`.
        let seeded = seed.zip(overlay.base_capture_point()).and_then(|(seed, base)| {
            let source = seed.inner.try_read().ok()?;
            source.reproduces(&base, RegistryLimits::UNBOUNDED).then(|| source.clone())
        });
        let Some(seeded) = seeded else {
            let limits = seed.map_or(limits, |seed| seed.headroom(limits));
            return Self::for_execution_capture(store, limits, None, None);
        };
        let identity = store.backing_store_identity().ok_or_else(|| {
            QuilError::ExecutionUnavailable("registry requires identifiable execution store".into())
        })?;
        let bound = limits.above(seeded.resource_usage(), seeded.largest_row);
        let registry = Self {
            inner: Arc::new(RwLock::new(seeded)),
            execution_binding: Some((identity, bound)),
        };
        registry.update_written_rows(store, overlay)?;
        Ok(registry)
    }

    fn check_execution_store(&self, identity: Option<quil_types::store::BackingStoreIdentity>) -> QuilResult<()> {
        if self.execution_binding.as_ref().is_some_and(|(expected, _)| identity.as_ref() != Some(expected)) {
            return Err(QuilError::ExecutionUnavailable("registry execution store mismatch".into()));
        }
        Ok(())
    }

    /// Rebuild the cache from the given hypergraph store. Takes a
    /// write lock for the duration of the refresh.
    ///
    /// Logs an `info!` whenever any field of the LOCAL prover (the one whose
    /// address matches `LOCAL_PROVER_ADDRESS`) or any of its allocations changes
    /// across a refresh, giving operators visibility into the join → confirm
    /// lifecycle (e.g. a freshly-materialized join appearing as `status=Joining`).
    pub fn refresh_from_store(&self, hg_store: &dyn HypergraphStore) -> QuilResult<()> {
        self.check_execution_store(hg_store.backing_store_identity())?;
        if let Some((_, limits)) = self.execution_binding.as_ref() {
            // Tentative state must not emit public local-prover lifecycle logs.
            return self.inner.write()
                .map_err(|_| QuilError::ExecutionUnavailable("registry lock poisoned".into()))?
                .refresh_with_limits(hg_store, *limits)
                .map_err(|error| QuilError::ExecutionUnavailable(format!("execution registry refresh: {error}")));
        }
        // Snapshot the local prover BEFORE taking the write lock for
        // the refresh; it is snapshotted again after and diffed.
        let before = self.snapshot_local_prover();
        {
            let mut guard = self.inner.write()
                .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
            guard.refresh(hg_store)?;
        }
        let after = self.snapshot_local_prover();
        log_local_prover_diff(before.as_ref(), after.as_ref());
        Ok(())
    }

    /// Bring an execution branch's registry up to date with the registry rows
    /// `overlay` wrote, updating only the records they feed. A full refresh
    /// runs only when that cannot match one exactly (see
    /// `InMemoryProverRegistry::update_rows`) or the writes cannot be listed.
    pub(crate) fn update_written_rows(
        &self,
        store: &dyn HypergraphStore,
        overlay: &quil_forest::ExecutionOverlay,
    ) -> QuilResult<()> {
        self.check_execution_store(store.backing_store_identity())?;
        let Some((_, limits)) = self.execution_binding.as_ref() else {
            return self.refresh_from_store(store);
        };
        let Some(written) = registry_rows::written_rows(overlay) else {
            return self.refresh_from_store(store);
        };
        {
            let mut guard = self.inner.write()
                .map_err(|_| QuilError::ExecutionUnavailable("registry lock poisoned".into()))?;
            // Rows from the legacy tree, or a cache edited directly: a refresh
            // would differ even where no row changed.
            if !guard.diverged && guard.rows.is_some() {
                if written.is_empty() {
                    return Ok(());
                }
                let snapshot = store.capture_tree_snapshot()?.ok_or_else(|| {
                    QuilError::Store("prover registry requires a consistent store snapshot".into())
                })?;
                if guard
                    .update_rows(snapshot.as_ref(), &written, *limits)
                    .map_err(|error| QuilError::ExecutionUnavailable(format!("execution registry refresh: {error}")))?
                {
                    return Ok(());
                }
            }
        }
        self.refresh_from_store(store)
    }

    /// Read the LOCAL prover's `ProverInfo` (if any), keyed by the
    /// `LOCAL_PROVER_ADDRESS` global. Returns `None` if either the
    /// address isn't published yet or no matching prover lives in the
    /// registry.
    fn snapshot_local_prover(&self) -> Option<ProverInfo> {
        let addr = crate::global_intrinsic::prover_shard_update::LOCAL_PROVER_ADDRESS
            .get()?
            .clone();
        let guard = self.inner.read().ok()?;
        guard.get_prover_info(&addr).cloned()
    }

    /// The registered leaf-root record for `(member, leaf_id)`, cloned out from
    /// under the lock. `leaf_id = leaf_id_bytes(shard_filter, prefix)`. Used by
    /// the storage attestation verifier to cross-check an opening's leaf root.
    pub fn get_leaf_root(
        &self,
        member: &[u8],
        leaf_id: &[u8],
        epoch: u64,
    ) -> Option<LeafRootRecord> {
        let guard = self.inner.read().ok()?;
        guard.get_leaf_root(member, leaf_id, epoch).cloned()
    }

    /// Read-only view of which allocations WOULD be evicted right now,
    /// with no state mutation. Same selection the mutating
    /// `evict_inactive_provers` uses internally (before its per-frame cap) —
    /// exposed so callers can surface the would-be set (eviction-risk
    /// endpoint, pre-activation logging) before eviction actually runs.
    pub fn find_eviction_candidates(
        &self,
        frame_number: u64,
        inactivity_threshold: u64,
        shard_halt_durations: &HashMap<Vec<u8>, u64>,
    ) -> Vec<EvictionCandidate> {
        match self.inner.read() {
            Ok(guard) => guard.find_eviction_candidates(
                frame_number,
                inactivity_threshold,
                shard_halt_durations,
            ),
            Err(_) => Vec::new(),
        }
    }

    /// [`Self::find_eviction_candidates`] with the census behind it, for the
    /// eviction pass log.
    pub fn scan_eviction_candidates(
        &self,
        frame_number: u64,
        inactivity_threshold: u64,
        shard_halt_durations: &HashMap<Vec<u8>, u64>,
    ) -> EvictionScan {
        match self.inner.read() {
            Ok(guard) => guard.scan_eviction_candidates(
                frame_number,
                inactivity_threshold,
                shard_halt_durations,
            ),
            Err(_) => EvictionScan::default(),
        }
    }

    /// Find stale allocations AND kick them in the supplied
    /// HypergraphState: each selected allocation vertex gets Status=4 and
    /// KickFrameNumber=frame_number. The prover vertex is not touched, so
    /// the prover keeps its status, seniority and other allocations. A
    /// prover left without active allocations stays a registered prover
    /// with nothing allocated, like one whose allocations all expired, and
    /// may join shards again: only a prover-level KickFrameNumber bars a
    /// re-join, and an allocation with Status=4 is re-joinable. The selection
    /// is [`InMemoryProverRegistry::find_eviction_candidates`]'s: stalled and
    /// under-provisioned shards are exempt, and each shard keeps its floor.
    /// Returns the allocations that were kicked.
    ///
    /// Mirrors the role of Go `ProverRegistry.EvictInactiveProvers`
    /// (`node/consensus/provers/prover_registry.go:2110-2201`), which kicks
    /// whole provers. This is the mutation half of the eviction flow that
    /// the trait method (`evict_inactive_provers`) lacks because the trait
    /// doesn't take a state parameter.
    ///
    /// Caller responsibilities:
    /// - Only run on archive nodes (Go gates this on `ArchiveMode`)
    /// - Only run when no shard halt is active (Go gates on `!anyHalted`)
    /// - Commit the state changeset after this call returns
    pub fn evict_inactive_provers(
        &self,
        frame_number: u64,
        inactivity_threshold: u64,
        shard_halt_durations: &HashMap<Vec<u8>, u64>,
        state: &crate::hypergraph_state::HypergraphState,
        store: Option<&dyn HypergraphStore>,
    ) -> QuilResult<Vec<EvictionCandidate>> {
        self.check_execution_store(state.crdt().backing_store_identity())?;
        if let Some(store) = store {
            self.check_execution_store(store.backing_store_identity())?;
        }
        // Read phase: find candidates under one read lock. The registry
        // knows every allocation's exact vertex address
        // (`ProverAllocationInfo.vertex_address`); if one is unset, derive
        // it from the prover's public key and the filter.
        // Cap evictions per frame so a large backlog (e.g. the one-time
        // orphan-stub cleanup) drains GRADUALLY instead of overwhelming the
        // eviction + commit path in a single materialize. Evicting 733 at
        // once wedged the materializer (no frame completed). The cap counts
        // allocations. find_eviction_candidates returns a deterministically
        // SORTED list, so taking the first N yields the same set on every
        // archive, and any subset of it still respects the shard floor.
        let candidates: Vec<(EvictionCandidate, Option<Vec<u8>>)> = {
            let guard = self
                .inner
                .read()
                .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
            guard
                .find_eviction_candidates(frame_number, inactivity_threshold, shard_halt_durations)
                .into_iter()
                .take(EVICTION_MAX_PER_PASS)
                .map(|candidate| {
                    let vertex = if candidate.vertex_address.len() == 32 {
                        Some(candidate.vertex_address.clone())
                    } else {
                        guard
                            .prover_cache
                            .get(&candidate.prover_address)
                            .filter(|info| !info.public_key.is_empty())
                            .and_then(|info| {
                                crate::global_intrinsic::materialize::allocation_address(
                                    &info.public_key,
                                    &candidate.confirmation_filter,
                                )
                                .ok()
                            })
                            .map(|a| a.to_vec())
                    };
                    (candidate, vertex)
                })
                .collect()
        };
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        // Mutation phase: kick each selected allocation vertex. Shard
        // summaries and committees are computed from ALLOCATION status
        // (`live_allocation_status` ignores the prover's status), so the
        // allocation vertex is what removes the prover from that shard.
        let domain = &crate::domains::GLOBAL[..];
        let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
        let global_app: [u8; 32] = crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;
        // Flat per-vertex keyspace shard for all global vertices — the same
        // (l1=0, l2=0xFF*32) shard `refresh_from_store` reads candidates from.
        let global_shard = ShardKey {
            l1: [0u8; 3],
            l2: [0xffu8; 32],
        };
        // Read a vertex's raw blob, preferring the CRDT (`state.get`) but
        // falling back to the authoritative flat per-vertex keyspace. The
        // CRDT's in-memory tree can be missing a vertex that hypergraph SYNC
        // wrote straight into the flat keyspace (sync does not insert into the
        // running CRDT tree), which is exactly why find_eviction_candidates —
        // sourced from `refresh_from_store` over that same flat keyspace —
        // selects an allocation the CRDT can't load. Writing back via
        // `state.set` then inserts/updates the kicked blob into the CRDT tree
        // on commit.
        let read_vertex = |addr: &[u8]| -> QuilResult<Option<Vec<u8>>> {
            if let Some(b) = state.get(domain, addr, &va_disc)? {
                return Ok(Some(b));
            }
            if let Some(s) = store {
                if addr.len() == 32 {
                    let mut vk = Vec::with_capacity(64);
                    vk.extend_from_slice(&global_app);
                    vk.extend_from_slice(addr);
                    return s
                        .load_vertex_underlying_raw("vertex", "adds", &global_shard, &vk)
                        .map_err(|e| {
                            QuilError::Internal(format!("evict: flat-store read: {e}"))
                        });
                }
            }
            Ok(None)
        };
        let mut evicted: Vec<EvictionCandidate> = Vec::new();

        for (candidate, vertex) in candidates {
            let blob = match vertex.as_deref() {
                Some(addr) => read_vertex(addr)?,
                None => None,
            };
            let (Some(alloc_addr), Some(blob)) = (vertex, blob) else {
                // Vertex is absent from BOTH the CRDT and the flat
                // keyspace — genuinely missing, not a cache/CRDT seam.
                tracing::warn!(
                    prover = %hex::encode(&candidate.prover_address),
                    filter = %hex::encode(&candidate.confirmation_filter),
                    "eviction: allocation vertex not found in CRDT or flat store — skipping"
                );
                continue;
            };
            let mut alloc_tree = rebuild_vertex_tree_from_blob(&blob);
            crate::global_intrinsic::materialize::materialize_prover_kick_allocation(
                &mut alloc_tree,
                frame_number,
            )
            .map_err(|e| QuilError::Internal(format!("evict: kick allocation: {e}")))?;
            state.set(domain, &alloc_addr, &va_disc, frame_number, vertex_tree_to_blob(&alloc_tree))?;
            evicted.push(candidate);
        }

        // Cache update: the kicked allocations are no longer active. Byte 4
        // decodes as `Rejected` on the next refresh, so record the same here.
        if !evicted.is_empty() {
            let mut guard = self
                .inner
                .write()
                .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
            for candidate in &evicted {
                if let Some(info) = guard.prover_cache.get_mut(&candidate.prover_address) {
                    for alloc in info.allocations.iter_mut() {
                        if alloc.confirmation_filter == candidate.confirmation_filter
                            && alloc.status == ProverStatus::Active
                        {
                            alloc.status = ProverStatus::Rejected;
                            alloc.kick_frame_number = frame_number;
                        }
                    }
                }
                if let Some(filters) = guard.address_to_filters.get_mut(&candidate.prover_address) {
                    filters.retain(|f| f != &candidate.confirmation_filter);
                }
            }
            guard.diverged = true;
        }

        Ok(evicted)
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

/// Emit an `info!` whenever any tracked field of the LOCAL prover or
/// its allocations changes across two registry snapshots. Per-allocation
/// diffs are keyed by `confirmation_filter` so a stuck `Joining`
/// allocation surfaces as a one-line `appeared` event the moment a
/// refresh first sees it, and a status flip surfaces as a
/// `status_change` event when archives finally materialize the
/// confirm.
///
/// Gives operators visibility into whether the local prover's join eventually
/// converges to a confirmed, active allocation.
fn log_local_prover_diff(before: Option<&ProverInfo>, after: Option<&ProverInfo>) {
    match (before, after) {
        (None, None) => {}
        (None, Some(a)) => {
            tracing::info!(
                address = %hex::encode(&a.address),
                status = ?a.status,
                allocations = a.allocations.len(),
                seniority = a.seniority,
                "local prover appeared in registry"
            );
            for alloc in &a.allocations {
                log_local_alloc_appear(alloc);
            }
        }
        (Some(b), None) => {
            tracing::info!(
                address = %hex::encode(&b.address),
                prev_status = ?b.status,
                "local prover disappeared from registry"
            );
        }
        (Some(b), Some(a)) => {
            if b.status != a.status {
                tracing::info!(
                    address = %hex::encode(&a.address),
                    prev = ?b.status,
                    new = ?a.status,
                    "local prover status changed"
                );
            }
            if b.kick_frame_number != a.kick_frame_number {
                tracing::info!(
                    address = %hex::encode(&a.address),
                    prev = b.kick_frame_number,
                    new = a.kick_frame_number,
                    "local prover kick_frame_number changed"
                );
            }
            if b.seniority != a.seniority {
                tracing::info!(
                    address = %hex::encode(&a.address),
                    prev = b.seniority,
                    new = a.seniority,
                    "local prover seniority changed"
                );
            }
            if b.available_storage != a.available_storage {
                tracing::info!(
                    address = %hex::encode(&a.address),
                    prev = b.available_storage,
                    new = a.available_storage,
                    "local prover available_storage changed"
                );
            }
            if b.delegate_address != a.delegate_address {
                tracing::info!(
                    address = %hex::encode(&a.address),
                    prev = %hex::encode(&b.delegate_address),
                    new = %hex::encode(&a.delegate_address),
                    "local prover delegate_address changed"
                );
            }

            // Diff allocations keyed by confirmation_filter.
            use std::collections::HashMap as Map;
            let before_map: Map<&[u8], &ProverAllocationInfo> = b
                .allocations
                .iter()
                .map(|al| (al.confirmation_filter.as_slice(), al))
                .collect();
            let after_map: Map<&[u8], &ProverAllocationInfo> = a
                .allocations
                .iter()
                .map(|al| (al.confirmation_filter.as_slice(), al))
                .collect();

            for (filter, alloc) in &after_map {
                match before_map.get(filter) {
                    None => log_local_alloc_appear(alloc),
                    Some(prev) => log_local_alloc_diff(prev, alloc),
                }
            }
            for (filter, prev) in &before_map {
                if !after_map.contains_key(filter) {
                    tracing::info!(
                        filter = %hex::encode(filter),
                        prev_status = ?prev.status,
                        prev_join_frame = prev.join_frame_number,
                        "local prover allocation disappeared"
                    );
                }
            }
        }
    }
}

fn log_local_alloc_appear(alloc: &ProverAllocationInfo) {
    tracing::info!(
        filter = %hex::encode(&alloc.confirmation_filter),
        status = ?alloc.status,
        join_frame = alloc.join_frame_number,
        leave_frame = alloc.leave_frame_number,
        kick_frame = alloc.kick_frame_number,
        join_confirm_frame = alloc.join_confirm_frame_number,
        join_reject_frame = alloc.join_reject_frame_number,
        last_active_frame = alloc.last_active_frame_number,
        "local prover allocation appeared"
    );
}

fn log_local_alloc_diff(prev: &ProverAllocationInfo, new: &ProverAllocationInfo) {
    if prev.status != new.status {
        tracing::info!(
            filter = %hex::encode(&new.confirmation_filter),
            prev = ?prev.status,
            new = ?new.status,
            "local allocation status changed"
        );
    }
    if prev.join_frame_number != new.join_frame_number {
        tracing::info!(
            filter = %hex::encode(&new.confirmation_filter),
            prev = prev.join_frame_number,
            new = new.join_frame_number,
            "local allocation join_frame_number changed"
        );
    }
    if prev.join_confirm_frame_number != new.join_confirm_frame_number {
        tracing::info!(
            filter = %hex::encode(&new.confirmation_filter),
            prev = prev.join_confirm_frame_number,
            new = new.join_confirm_frame_number,
            "local allocation join_confirm_frame_number changed"
        );
    }
    if prev.join_reject_frame_number != new.join_reject_frame_number {
        tracing::info!(
            filter = %hex::encode(&new.confirmation_filter),
            prev = prev.join_reject_frame_number,
            new = new.join_reject_frame_number,
            "local allocation join_reject_frame_number changed"
        );
    }
    if prev.leave_frame_number != new.leave_frame_number {
        tracing::info!(
            filter = %hex::encode(&new.confirmation_filter),
            prev = prev.leave_frame_number,
            new = new.leave_frame_number,
            "local allocation leave_frame_number changed"
        );
    }
    if prev.leave_confirm_frame_number != new.leave_confirm_frame_number {
        tracing::info!(
            filter = %hex::encode(&new.confirmation_filter),
            prev = prev.leave_confirm_frame_number,
            new = new.leave_confirm_frame_number,
            "local allocation leave_confirm_frame_number changed"
        );
    }
    if prev.kick_frame_number != new.kick_frame_number {
        tracing::info!(
            filter = %hex::encode(&new.confirmation_filter),
            prev = prev.kick_frame_number,
            new = new.kick_frame_number,
            "local allocation kick_frame_number changed"
        );
    }
}

impl ProverRegistryTrait for SharedProverRegistry {
    fn get_lifecycle_view(
        &self, address: &[u8], frame: u64,
    ) -> QuilResult<quil_types::consensus::ProverLifecycleView> {
        use quil_types::consensus::{LifecycleMembers, ProverLifecycleView};
        let guard = self.inner.read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        let prover = guard.get_prover_info(address).cloned();
        let summaries = guard.get_prover_shard_summaries(frame);
        let filters: std::collections::BTreeSet<_> = prover.iter()
            .flat_map(|p| p.allocations.iter())
            .map(|a| a.confirmation_filter.clone())
            .chain(summaries.iter().map(|s| s.filter.clone()))
            .filter(|f| !f.is_empty()).collect();
        let mut members = HashMap::new();
        let mut reward_rings = HashMap::new();
        for filter in filters {
            if let Some(estimate) = guard.reward_ring_estimate(address, &filter, frame) {
                reward_rings.insert(filter.clone(), estimate);
            }
            // Clone addresses, not complete peer records and cryptographic keys.
            let mut shard = LifecycleMembers::default();
            for status in [ProverStatus::Active, ProverStatus::Leaving] {
                for p in guard.get_provers_by_status(&filter, status) {
                    if let Some(alloc) = p.allocations.iter().find(|a| a.confirmation_filter == filter && a.status == status) {
                        shard.add(p.address.clone(), alloc, frame);
                    }
                }
            }
            shard.sort();
            members.insert(filter, shard);
        }
        Ok(ProverLifecycleView { prover, summaries, members, reward_rings })
    }

    fn get_reward_ring_estimate(&self, address: &[u8], filter: &[u8], frame: u64)
        -> QuilResult<Option<quil_types::reward_ring::RewardRingEstimate>> {
        let guard = self.inner.read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard.reward_ring_estimate(address, filter, frame))
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> { Some(self) }
    fn get_prover_info(&self, address: &[u8]) -> QuilResult<Option<ProverInfo>> {
        Ok(self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?
            .get_prover_info(address)
            .cloned())
    }

    fn get_next_prover(&self, input: &[u8; 32], filter: &[u8], frame_number: u64) -> QuilResult<Vec<u8>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        guard
            .get_next_prover(input, filter, frame_number)
            .ok_or_else(|| QuilError::NotFound("shard trie empty".into()))
    }

    fn get_ordered_provers(
        &self,
        input: &[u8; 32],
        filter: &[u8],
        frame_number: u64,
    ) -> QuilResult<Vec<Vec<u8>>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard.get_ordered_provers(input, filter, frame_number))
    }

    fn get_active_provers(&self, filter: &[u8], frame_number: u64) -> QuilResult<Vec<ProverInfo>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard.get_active_provers(filter, frame_number).into_iter().cloned().collect())
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

    fn get_provers_on_filters(&self, filters: &[Vec<u8>]) -> QuilResult<Vec<ProverInfo>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard.get_provers_on_filters(filters).into_iter().cloned().collect())
    }

    fn get_leaf_root(
        &self,
        member: &[u8],
        leaf_id: &[u8],
        epoch: u64,
    ) -> QuilResult<Option<(Vec<u8>, u64, u64)>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard
            .get_leaf_root(member, leaf_id, epoch)
            .map(|r| (r.leaf_root.clone(), r.num_blocks, r.epoch)))
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

    fn get_prover_shard_summaries(
        &self,
        frame_number: u64,
    ) -> QuilResult<Vec<ProverShardSummary>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        Ok(guard.get_prover_shard_summaries(frame_number))
    }

    fn prune_orphan_joins(&self, frame_number: u64) -> QuilResult<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
        guard.prune_orphan_joins(frame_number);
        Ok(())
    }

}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Page the current vertices without retaining every historical MVCC blob.
/// The caller owns the snapshot for the whole refresh. Page bounds do not bound
/// the complete registry cache; an execution overlay additionally enforces its
/// cumulative read budget and the branch owner must bound retained contexts.
fn visit_registry_vertices(
    snapshot: &dyn SnapshotReadable,
    phase: &str,
    shard: &ShardKey,
    limits: VertexPageLimits,
    mut visit: impl FnMut(Vec<u8>, Vec<u8>) -> QuilResult<()>,
) -> QuilResult<()> {
    let mut after = None;
    loop {
        let page = snapshot.page_vertex_underlying_fixed(
            "vertex", phase, shard, &shard.l2, after.as_ref(), limits,
        )?;
        if page.has_more && page.entries.is_empty() {
            return Err(QuilError::Store("registry page made no progress".into()));
        }
        for (address, blob) in page.entries {
            if after.as_ref().is_some_and(|previous| address <= *previous) {
                return Err(QuilError::Store("registry page is not strictly ordered".into()));
            }
            after = Some(address);
            let mut key = Vec::with_capacity(64);
            key.extend_from_slice(&shard.l2);
            key.extend_from_slice(&address);
            visit(key, blob)?;
        }
        if !page.has_more {
            return Ok(());
        }
    }
}

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

/// Whether a serialized vertex can be a prover or an allocation: its bytes
/// contain one of their type hashes (stored verbatim as a leaf value).
fn holds_scanned_type(blob: &[u8]) -> bool {
    use crate::global_schema::{TYPE_HASH_ALLOCATION, TYPE_HASH_PROVER};
    memchr::memmem::find(blob, &TYPE_HASH_ALLOCATION).is_some()
        || memchr::memmem::find(blob, &TYPE_HASH_PROVER).is_some()
}

/// An allocation's recorded ring key, read the way `prover_rings::read_key`
/// reads a rebuilt tree.
fn decode_ring_key(node: &VectorCommitmentNode) -> Option<crate::global_intrinsic::prover_rings::RingKey> {
    let field = |name| {
        let bytes = read_bytes(node, "allocation:ProverAllocation", name);
        <[u8; 8]>::try_from(bytes.as_slice()).ok().map(u64::from_be_bytes)
    };
    Some(crate::global_intrinsic::prover_rings::RingKey { cohort: field("RingEpoch")?, seniority: field("RingSeniority")? })
}

fn read_bytes(node: &VectorCommitmentNode, class: &str, field: &str) -> Vec<u8> {
    field_key(class, field)
        .and_then(|k| node.find_leaf_value(&k))
        .unwrap_or_default()
}

/// Map the raw RDF status byte for `prover:Prover` to our enum.
/// Returns `None` for byte 4 (the prover-level "left/terminal" value
/// — Go's deserializer `continue`s past it and excludes the prover
/// from the cache entirely; we mirror that with `None`).
fn map_prover_status(byte: u8) -> Option<ProverStatus> {
    match byte {
        0 => Some(ProverStatus::Joining),
        1 => Some(ProverStatus::Active),
        2 => Some(ProverStatus::Paused),
        3 => Some(ProverStatus::Leaving),
        // 4 is "left" for provers — Go skips the vertex.
        _ => None,
    }
}

/// Map the raw RDF status byte for `allocation:ProverAllocation`.
pub fn map_allocation_status(byte: u8) -> ProverStatus {
    match byte {
        0 => ProverStatus::Joining,
        1 => ProverStatus::Active,
        2 => ProverStatus::Paused,
        3 => ProverStatus::Leaving,
        4 => ProverStatus::Rejected,
        5 => ProverStatus::Kicked,
        6 => ProverStatus::Historic,
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
        last_signed_frame_number: read_u64_be(root, "allocation:ProverAllocation", "LastSignedFrameNumber"),
        epoch: read_u64_be(root, "allocation:ProverAllocation", "Epoch"),
        ring: read_bytes(root, "allocation:ProverAllocation", "Ring")
            .first()
            .copied()
            .unwrap_or(0),
        vertex_address: vertex_key[32..64].to_vec(),
    };
    Some((prover_ref, alloc))
}

/// Deterministically enumerate provers whose ACTIVE allocation is on `filter`,
/// read DIRECTLY from committed state via the CRDT (not the async cache), for the
/// epoch-aligned split/merge reassignment which MUST be a pure function of the
/// committed frame. Returns (public_key, prover_address) per matching prover,
/// sorted by address for a stable order. Mirrors `get_active_provers`' intent
/// (raw-Active only; Leaving/Joining are intentionally not reassigned).
/// A single committed-state scan of the global prover shard, REUSABLE across
/// many filters in one frame. [`Self::scan`] does the ONE expensive full-shard
/// pass; [`Self::active_on_filter`] is a cheap in-memory filter over the result.
/// Hoisting the scan OUT of `reassign_shard_allocations`' per-due-change loop
/// turns N full prover-shard scans into one — critical when many splits/merges
/// come due at an epoch boundary (the 48s materialize spikes). This stays
/// COMMITTED-state (deterministic — every node scans the identical tree) and
/// MUST NOT be replaced by the async registry cache, which can differ across
/// nodes and would diverge the prover tree.
pub struct CommittedProverScan {
    addr_to_pubkey: HashMap<Vec<u8>, Vec<u8>>,
    pub(crate) allocations: Vec<(Vec<u8>, ProverAllocationInfo)>,
    /// Each allocation's recorded ring key, aligned with `allocations`.
    ring_keys: Vec<Option<crate::global_intrinsic::prover_rings::RingKey>>,
    /// Each allocation's recorded release, aligned with `allocations`.
    releases: Vec<Option<crate::global_intrinsic::prover_release::Release>>,
    /// Each prover's committed seniority, by address.
    seniority: HashMap<Vec<u8>, u64>,
}

impl CommittedProverScan {
    /// One destructive pass over the committed global prover shard, collecting
    /// prover pubkeys (by address) and every allocation.
    pub fn scan(hg: &quil_hypergraph::HypergraphCrdt) -> Self {
        Self::scan_inner(hg).0
    }

    /// A scan over explicit rows, for tests that drive GLOBAL without prover
    /// records in its hypergraph.
    #[cfg(any(test, feature = "testing-stubs"))]
    pub fn from_parts(
        addr_to_pubkey: HashMap<Vec<u8>, Vec<u8>>,
        allocations: Vec<(Vec<u8>, ProverAllocationInfo)>,
    ) -> Self {
        let ring_keys = vec![None; allocations.len()];
        let releases = vec![None; allocations.len()];
        Self { addr_to_pubkey, allocations, ring_keys, releases, seniority: HashMap::new() }
    }

    /// [`Self::from_parts`] with each allocation's ring key and each prover's
    /// seniority.
    #[cfg(any(test, feature = "testing-stubs"))]
    pub fn from_parts_with_rings(
        addr_to_pubkey: HashMap<Vec<u8>, Vec<u8>>,
        allocations: Vec<(Vec<u8>, ProverAllocationInfo, Option<crate::global_intrinsic::prover_rings::RingKey>)>,
        seniority: HashMap<Vec<u8>, u64>,
    ) -> Self {
        let (allocations, ring_keys): (Vec<_>, _) = allocations.into_iter().map(|(a, info, key)| ((a, info), key)).unzip();
        let releases = vec![None; allocations.len()];
        Self { addr_to_pubkey, allocations, ring_keys, releases, seniority }
    }

    /// This scan with `release` recorded on `address`'s allocation on
    /// `filter`, for tests.
    #[cfg(any(test, feature = "testing-stubs"))]
    pub fn with_release(
        mut self,
        address: &[u8],
        filter: &[u8],
        release: crate::global_intrinsic::prover_release::Release,
    ) -> Self {
        if let Some(index) = self.allocations.iter().position(|(prover, alloc)| {
            prover.as_slice() == address && alloc.confirmation_filter == filter
        }) {
            self.releases[index] = Some(release);
        }
        self
    }

    /// Like [`Self::scan`], but a failed committed-state read is an error
    /// instead of a shorter (possibly empty) prover set. Committee membership
    /// and reassignment must not be decided from a partial scan.
    pub fn try_scan(hg: &quil_hypergraph::HypergraphCrdt) -> quil_types::error::Result<Self> {
        let (scan, outcome) = Self::scan_inner(hg);
        outcome.map(|_| scan)
    }

    fn scan_inner(hg: &quil_hypergraph::HypergraphCrdt) -> (Self, quil_types::error::Result<usize>) {
        let shard = ShardKey {
            l1: [0u8; 3],
            l2: [0xffu8; 32],
        };
        let mut addr_to_pubkey: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let mut allocations: Vec<(Vec<u8>, ProverAllocationInfo)> = Vec::new();
        let mut ring_keys = Vec::new();
        let mut releases = Vec::new();
        let mut seniority: HashMap<Vec<u8>, u64> = HashMap::new();

        // Tombstones first: `remove_vertex` leaves the "adds" blob in place, so
        // an adds-only walk resurrects deleted records (the provers the split
        // reset drops, the allocations the re-home drops). Committed state is
        // `adds ∧ ¬removes`, as the registry and every committed read see it; a
        // resurrected allocation would be reassigned and seated in committees.
        let mut removed: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let removes = hg.for_each_vertex_underlying_shard("vertex", "removes", &shard, &mut |vk: Vec<u8>, _| {
            removed.insert(vk);
        });

        let mut cb = |vk: Vec<u8>, data: Vec<u8>| {
            if vk.len() != 64 || removed.contains(&vk) {
                return;
            }
            // Most of the shard is neither a prover nor an allocation (storage
            // leaf-root registrations, rewards, authorization records). A type
            // hash is stored as a raw leaf value, so a vertex whose bytes hold
            // neither hash cannot be one: skip it without parsing its tree.
            if !holds_scanned_type(&data) {
                return;
            }
            let root = match deserialize_go_tree(&data) {
                Ok(Some(r)) => r,
                _ => return,
            };
            let Some(type_hash) = root.find_leaf_value(&vec![0xFFu8; 32]) else {
                return;
            };
            if type_hash == TYPE_HASH_ALLOCATION {
                if let Some((prover_ref, alloc)) = decode_allocation(&vk, &root) {
                    allocations.push((prover_ref, alloc));
                    ring_keys.push(decode_ring_key(&root));
                    releases.push(crate::global_intrinsic::prover_release::Release::from_bytes(
                        &read_bytes(&root, "allocation:ProverAllocation", "Release"),
                    ));
                }
                return;
            }
            if let Some("prover:Prover") = class_for_type_hash(&type_hash) {
                if let Some(info) = decode_prover(&vk, &root) {
                    seniority.insert(info.address.clone(), info.seniority);
                    addr_to_pubkey.insert(info.address.clone(), info.public_key);
                }
            }
        };
        let adds = hg.for_each_vertex_underlying_shard("vertex", "adds", &shard, &mut cb);
        (
            Self {
                addr_to_pubkey,
                allocations,
                ring_keys,
                releases,
                seniority,
            },
            removes.and(adds),
        )
    }

    /// The prover registered under `address`, by public key.
    pub fn public_key(&self, address: &[u8]) -> Option<&[u8]> {
        self.addr_to_pubkey.get(address).map(Vec::as_slice)
    }

    /// A prover's committed seniority (0 when it has no prover record).
    pub fn seniority(&self, address: &[u8]) -> u64 {
        self.seniority.get(address).copied().unwrap_or(0)
    }

    /// The ring key of `address`'s allocation on `filter`: the one recorded on
    /// it, or for an allocation confirmed before the seniority ring rule, the
    /// key the flag day records ([`prover_rings::preexisting`]).
    ///
    /// [`prover_rings::preexisting`]: crate::global_intrinsic::prover_rings::preexisting
    pub fn ring_key(&self, address: &[u8], filter: &[u8]) -> Option<crate::global_intrinsic::prover_rings::RingKey> {
        let index = self.allocations.iter().position(|(prover, alloc)| {
            prover.as_slice() == address && alloc.confirmation_filter == filter
        })?;
        Some(self.ring_keys[index].unwrap_or_else(|| {
            crate::global_intrinsic::prover_rings::preexisting(
                self.allocations[index].1.join_confirm_frame_number,
                self.seniority(address),
            )
        }))
    }

    /// The releases recorded on the allocations on `filter`, by prover
    /// address; an allocation without one is absent.
    pub fn releases_on_filter(
        &self,
        filter: &[u8],
    ) -> HashMap<&[u8], crate::global_intrinsic::prover_release::Release> {
        self.allocations
            .iter()
            .zip(&self.releases)
            .filter(|((_, alloc), _)| alloc.confirmation_filter == filter)
            .filter_map(|((prover, _), release)| release.map(|release| (prover.as_slice(), release)))
            .collect()
    }

    /// Every allocation, with its prover's public key and its ring key
    /// ([`Self::ring_key`]), in scan order.
    pub fn allocations_with_keys(
        &self,
    ) -> impl Iterator<Item = (&[u8], &ProverAllocationInfo, crate::global_intrinsic::prover_rings::RingKey, bool)> {
        self.allocations.iter().zip(&self.ring_keys).map(|((prover, alloc), key)| {
            let recorded = key.is_some();
            let key = key.unwrap_or_else(|| {
                crate::global_intrinsic::prover_rings::preexisting(alloc.join_confirm_frame_number, self.seniority(prover))
            });
            (prover.as_slice(), alloc, key, recorded)
        })
    }

    /// Reflect, in this scan only, an allocation the current frame moved from
    /// `from` to `to` with `key`: later decisions in the same maintenance pass
    /// see the committee the frame leaves behind, which a committed-state scan
    /// cannot until the frame commits.
    pub fn moved(&mut self, address: &[u8], from: &[u8], to: &[u8], key: crate::global_intrinsic::prover_rings::RingKey) {
        if let Some(index) = self.allocations.iter().position(|(prover, alloc)| {
            prover.as_slice() == address && alloc.confirmation_filter == from
        }) {
            self.allocations[index].1.confirmation_filter = to.to_vec();
            self.ring_keys[index] = Some(key);
        }
    }

    /// Reflect, in this scan only, an allocation the current frame retired.
    pub fn retired(&mut self, address: &[u8], filter: &[u8]) {
        if let Some(index) = self.allocations.iter().position(|(prover, alloc)| {
            prover.as_slice() == address && alloc.confirmation_filter == filter
        }) {
            self.allocations[index].1.status = ProverStatus::Historic;
        }
    }

    /// Record, in this scan only, the keys the current frame wrote.
    pub fn recorded(&mut self, address: &[u8], filter: &[u8], key: crate::global_intrinsic::prover_rings::RingKey) {
        if let Some(index) = self.allocations.iter().position(|(prover, alloc)| {
            prover.as_slice() == address && alloc.confirmation_filter == filter
        }) {
            self.ring_keys[index] = Some(key);
        }
    }

    /// The `(public_key, prover_address)` active on `filter` at `frame_number`.
    /// Matches `get_active_provers`' committee eligibility (effective_status via
    /// `committee_eligible`) — NOT raw `status == Active` — with the same
    /// strict→lenient fallback, so the reassignment moves EXACTLY the provers the
    /// rest of consensus considers on `filter`. A raw-Active check strands
    /// epoch-boundary re-confirmers (effective-Active but not raw-Active), which
    /// is precisely the "2 of 4 not moved" bug: the split flips at an epoch
    /// boundary where some members are mid-re-confirm.
    /// Every live allocation on `filter`, whatever its lifecycle stage. A
    /// shard a split or merge removes cannot keep allocations: one left behind
    /// (a Joining one, say) binds its worker to a shard that no longer exists
    /// and keeps the committee scheduler creating sessions for it. Retired
    /// (Historic) and Kicked slots are not allocations any more and stay where
    /// they are: moving a retired slot would overwrite the live allocation at
    /// its destination (a stale duplicate split did exactly that, live).
    pub fn all_on_filter(&self, filter: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = self
            .allocations
            .iter()
            .filter(|(_, alloc)| alloc.confirmation_filter == filter)
            .filter(|(_, alloc)| !matches!(alloc.status, ProverStatus::Historic | ProverStatus::Kicked))
            .filter_map(|(prover_ref, _)| {
                self.addr_to_pubkey.get(prover_ref).map(|pubkey| (pubkey.clone(), prover_ref.clone()))
            })
            .collect();
        out.sort_by(|a, b| a.1.cmp(&b.1));
        out.dedup_by(|a, b| a.1 == b.1);
        out
    }

    pub fn active_on_filter(&self, filter: &[u8], frame_number: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        let collect = |lenient: bool| -> Vec<(Vec<u8>, Vec<u8>)> {
            let mut v: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            for (prover_ref, alloc) in &self.allocations {
                if alloc.confirmation_filter != filter
                    || !committee_eligible(alloc, frame_number, lenient)
                {
                    continue;
                }
                if let Some(pubkey) = self.addr_to_pubkey.get(prover_ref) {
                    v.push((pubkey.clone(), prover_ref.clone()));
                }
            }
            v
        };
        // Strict first; fall back to the lenient (empty-committee) floor for a
        // non-empty (app-shard) filter, exactly as `get_active_provers` does.
        let mut out = collect(false);
        if out.is_empty() && !filter.is_empty() {
            out = collect(true);
        }
        out.sort_by(|a, b| a.1.cmp(&b.1));
        out.dedup_by(|a, b| a.1 == b.1);
        out
    }
}

/// Back-compat single-call wrapper: one scan + one filter. Prefer
/// `CommittedProverScan::scan(hg)` ONCE + `active_on_filter` per filter when
/// reassigning multiple due changes in a frame (avoids N full scans).
pub fn active_provers_on_filter_committed(
    hg: &quil_hypergraph::HypergraphCrdt,
    filter: &[u8],
    frame_number: u64,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    CommittedProverScan::scan(hg).active_on_filter(filter, frame_number)
}

/// Enumerate EVERY registered prover on the global prover shard from COMMITTED
/// state, returning `(prover_address, public_key, confirmation_filters)` — one
/// entry per `prover:Prover` vertex, with every `allocation:ProverAllocation`
/// filter that references it (global + each app sub-shard). Deterministic (a
/// single committed-state pass, address-sorted), so every node computes the
/// identical set for a given frame. Used by the unified-tree reset to DROP
/// non-archive records without depending on the timing-sensitive async cache.
pub fn all_provers_with_allocations_committed(
    hg: &quil_hypergraph::HypergraphCrdt,
) -> Vec<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> {
    let shard = ShardKey {
        l1: [0u8; 3],
        l2: [0xffu8; 32],
    };
    let mut addr_to_pubkey: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    // prover_address -> every confirmation_filter it is allocated on.
    let mut alloc_filters: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();

    // Tombstones first: `remove_vertex` marks a deletion in the "removes" phase
    // but LEAVES the "adds" blob intact, so an adds-only walk RESURRECTS anything
    // deleted from committed state — the non-archive records the split reset drops,
    // and the deep allocations the allocation re-home drops. Collect the removed vks
    // and skip them below so this reflects committed `adds ∧ ¬removes`, matching the
    // authoritative registry cache (see the same subtraction in `ProverRegistry`).
    let mut removed_vks: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let _ = hg.for_each_vertex_underlying_shard("vertex", "removes", &shard, &mut |vk: Vec<u8>, _| {
        removed_vks.insert(vk);
    });

    let mut cb = |vk: Vec<u8>, data: Vec<u8>| {
        if vk.len() != 64 || removed_vks.contains(&vk) {
            return;
        }
        let root = match deserialize_go_tree(&data) {
            Ok(Some(r)) => r,
            _ => return,
        };
        let Some(type_hash) = root.find_leaf_value(&vec![0xFFu8; 32]) else {
            return;
        };
        if type_hash == TYPE_HASH_ALLOCATION {
            if let Some((prover_ref, alloc)) = decode_allocation(&vk, &root) {
                alloc_filters
                    .entry(prover_ref)
                    .or_default()
                    .push(alloc.confirmation_filter);
            }
            return;
        }
        if let Some("prover:Prover") = class_for_type_hash(&type_hash) {
            if let Some(info) = decode_prover(&vk, &root) {
                addr_to_pubkey.insert(info.address.clone(), info.public_key);
            }
        }
    };
    let _ = hg.for_each_vertex_underlying_shard("vertex", "adds", &shard, &mut cb);

    let mut out: Vec<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> = addr_to_pubkey
        .into_iter()
        .map(|(addr, pubkey)| {
            let mut filters = alloc_filters.remove(&addr).unwrap_or_default();
            filters.sort();
            filters.dedup();
            (addr, pubkey, filters)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Like [`all_provers_with_allocations_committed`] but keeps ONLY the filters on
/// which the prover is effectively `Active` at `frame_number`. Retired (Historic),
/// Rejected, Kicked, and expired Joining/Leaving allocations are dropped — those
/// provers do NOT submit coverage, so they can never trip the message collector's
/// valid-shard reject. Use this (not the all-status walk) when diagnosing which
/// allocations would ACTUALLY be rejected by the current grid, so a retired slot
/// left behind by delete-free reassignment isn't false-flagged.
pub fn all_provers_with_active_allocations_committed(
    hg: &quil_hypergraph::HypergraphCrdt,
    frame_number: u64,
) -> Vec<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> {
    let shard = ShardKey {
        l1: [0u8; 3],
        l2: [0xffu8; 32],
    };
    let mut addr_to_pubkey: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut alloc_filters: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();

    let mut removed_vks: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let _ = hg.for_each_vertex_underlying_shard("vertex", "removes", &shard, &mut |vk: Vec<u8>, _| {
        removed_vks.insert(vk);
    });

    let mut cb = |vk: Vec<u8>, data: Vec<u8>| {
        if vk.len() != 64 || removed_vks.contains(&vk) {
            return;
        }
        let root = match deserialize_go_tree(&data) {
            Ok(Some(r)) => r,
            _ => return,
        };
        let Some(type_hash) = root.find_leaf_value(&vec![0xFFu8; 32]) else {
            return;
        };
        if type_hash == TYPE_HASH_ALLOCATION {
            if let Some((prover_ref, alloc)) = decode_allocation(&vk, &root) {
                // Only allocations that are effectively Active at this frame — the
                // set that actually submits coverage (mirrors the app-engine's
                // propose gate and `live_allocation_status`).
                if alloc.effective_status(frame_number)
                    == quil_types::consensus::EffectiveStatus::Active
                {
                    alloc_filters
                        .entry(prover_ref)
                        .or_default()
                        .push(alloc.confirmation_filter);
                }
            }
            return;
        }
        if let Some("prover:Prover") = class_for_type_hash(&type_hash) {
            if let Some(info) = decode_prover(&vk, &root) {
                addr_to_pubkey.insert(info.address.clone(), info.public_key);
            }
        }
    };
    let _ = hg.for_each_vertex_underlying_shard("vertex", "adds", &shard, &mut cb);

    let mut out: Vec<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> = addr_to_pubkey
        .into_iter()
        .filter_map(|(addr, pubkey)| {
            let mut filters = alloc_filters.remove(&addr)?;
            if filters.is_empty() {
                return None;
            }
            filters.sort();
            filters.dedup();
            Some((addr, pubkey, filters))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// READ-ONLY diagnostic: tally committed allocations whose `confirmation_filter`
/// begins with `app` by the PAIR `(raw status byte, effective status)` at
/// `frame_number` (`{:?}` of [`ProverStatus`] / [`EffectiveStatus`]). Surfacing
/// the raw byte alongside the effective status distinguishes, BEFORE the E+2
/// activation boundary, a confirmed-but-deferred allocation (`Active → Joining` —
/// its join confirmed, it's just waiting to activate; healthy) from an
/// unconfirmed one (`Joining → Joining` — the confirm hasn't happened yet; will
/// become `ExpiredJoining` if it misses its slot). Used by `--dump-shard-state`.
pub struct QuilAllocDiag {
    /// `(raw ProverStatus, EffectiveStatus)` → count.
    pub by_status: std::collections::BTreeMap<(String, String), usize>,
    /// Joining-BYTE allocations bucketed by their PROPOSAL epoch
    /// (`epoch_for_frame(JoinFrameNumber)`) → count. A join proposed in epoch E
    /// is due to confirm in epoch E+1; comparing against the head's epoch tells a
    /// not-yet-due join from an overdue (confirm-path-broken) one.
    pub joining_by_epoch: std::collections::BTreeMap<u64, usize>,
    /// Active-BYTE allocations bucketed by their CONFIRM epoch
    /// (`epoch_for_frame(JoinConfirmFrameNumber)`) → count — the confirmed set.
    pub confirmed_by_epoch: std::collections::BTreeMap<u64, usize>,
}

pub fn allocation_status_breakdown(
    hg: &quil_hypergraph::HypergraphCrdt,
    frame_number: u64,
    app: &[u8],
) -> QuilAllocDiag {
    use quil_types::consensus::epoch_for_frame;
    let shard = ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };
    let mut removed_vks: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let _ = hg.for_each_vertex_underlying_shard("vertex", "removes", &shard, &mut |vk: Vec<u8>, _| {
        removed_vks.insert(vk);
    });
    let mut diag = QuilAllocDiag {
        by_status: std::collections::BTreeMap::new(),
        joining_by_epoch: std::collections::BTreeMap::new(),
        confirmed_by_epoch: std::collections::BTreeMap::new(),
    };
    let mut cb = |vk: Vec<u8>, data: Vec<u8>| {
        if vk.len() != 64 || removed_vks.contains(&vk) {
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
        if let Some((_prover_ref, alloc)) = decode_allocation(&vk, &root) {
            if !alloc.confirmation_filter.starts_with(app) {
                return;
            }
            let key = (
                format!("{:?}", alloc.status),
                format!("{:?}", alloc.effective_status(frame_number)),
            );
            *diag.by_status.entry(key).or_insert(0) += 1;
            match alloc.status {
                quil_types::consensus::ProverStatus::Joining if alloc.join_frame_number > 0 => {
                    *diag
                        .joining_by_epoch
                        .entry(epoch_for_frame(alloc.join_frame_number))
                        .or_insert(0) += 1;
                }
                quil_types::consensus::ProverStatus::Active
                    if alloc.join_confirm_frame_number > 0 =>
                {
                    *diag
                        .confirmed_by_epoch
                        .entry(epoch_for_frame(alloc.join_confirm_frame_number))
                        .or_insert(0) += 1;
                }
                _ => {}
            }
        }
    };
    let _ = hg.for_each_vertex_underlying_shard("vertex", "adds", &shard, &mut cb);
    diag
}

/// Decode a `leafroot:LeafRootRegistration` vertex into one cache entry
/// per populated epoch slot. Return no entries when required fields are missing.
fn decode_leaf_root(
    root: &VectorCommitmentNode,
) -> Vec<((Vec<u8>, Vec<u8>, u64), LeafRootRecord)> {
    let cls = "leafroot:LeafRootRegistration";
    let member = read_bytes(root, cls, "Member");
    let shard_filter = read_bytes(root, cls, "ShardFilter");
    if member.is_empty() {
        return Vec::new();
    }
    let prefix_bytes = read_bytes(root, cls, "Prefix");
    let prefix = crate::global_intrinsic::materialize::unpack_prefix(&prefix_bytes);
    let leaf_id = crate::global_intrinsic::leaf_id_bytes(&shard_filter, &prefix);
    // EVERY populated slot, not just the middle one. The registration vertex
    // holds up to three epochs — `upsert_leaf_root_registration` assigns the
    // highest to the `Next` slot, the one below to `Epoch`, the one below that
    // to `Prev` — because a confirm in epoch E registers E+1 and the audit
    // window reaches back to E-1. Caching only the `Epoch` slot left frame
    // validation blind to the other two: a member whose only registration was
    // the just-written E+1 had no entry at E, so every frame it produced in
    // epoch E was rejected as "no registered leaf ... at epoch E" even though
    // it had confirmed. `leaf_root_registration_for_epoch` already reads all
    // three; this is the same record, read the same way.
    [("PrevEpoch", "PrevLeafRoot", "PrevNumBlocks"),
     ("Epoch", "LeafRoot", "NumBlocks"),
     ("NextEpoch", "NextLeafRoot", "NextNumBlocks")]
        .into_iter()
        .filter_map(|(epoch_field, root_field, blocks_field)| {
            let leaf_root = read_bytes(root, cls, root_field);
            if leaf_root.is_empty() {
                return None;
            }
            let epoch = read_u64_be(root, cls, epoch_field);
            Some((
                (member.clone(), leaf_id.clone(), epoch),
                LeafRootRecord { leaf_root, num_blocks: read_u64_be(root, cls, blocks_field), epoch },
            ))
        })
        .collect()
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
    use quil_tries::{serialize_go_tree, LeafNode, VectorCommitmentTree};

    fn make_vertex_key(address_byte: u8) -> Vec<u8> {
        // 32-byte domain (global intrinsic) + 32-byte address.
        let mut key = vec![0xFFu8; 32];
        key.extend_from_slice(&[address_byte; 32]);
        key
    }

    #[test]
    fn decode_leaf_root_recovers_member_leaf_and_record() {
        let member = [0x9Au8; 32];
        let filter = vec![0xAB; 32];
        let prefix = vec![42u32, 7];
        let tree = crate::global_intrinsic::materialize::create_leaf_root_vertex_tree(
            &member, &filter, &prefix, 19, &vec![0x11; 74], 1234, 900_000,
        )
        .unwrap();
        // Through the same blob path refresh uses.
        let blob = vertex_tree_to_blob(&tree);
        let root = deserialize_go_tree(&blob).unwrap().unwrap();

        let decoded = super::decode_leaf_root(&root);
        assert_eq!(decoded.len(), 1, "a one-slot registration decodes to one entry");
        let ((m, leaf_id, ep), rec) = decoded.into_iter().next().unwrap();
        assert_eq!(ep, 19);
        assert_eq!(m, member.to_vec());
        assert_eq!(
            leaf_id,
            crate::global_intrinsic::leaf_id_bytes(&filter, &prefix)
        );
        assert_eq!(rec.leaf_root, vec![0x11; 74]);
        assert_eq!(rec.num_blocks, 1234);
        assert_eq!(rec.epoch, 19);
    }

    /// A confirm in epoch E registers E+1, and the audit window reaches back
    /// to E-1, so the vertex carries up to three epochs. Frame validation
    /// reads this cache: if it holds only the middle slot, a member whose one
    /// registration is E+1 has nothing at E and every frame it produces that
    /// epoch is rejected though it confirmed.
    #[test]
    fn every_registered_epoch_slot_is_cached_not_just_the_middle_one() {
        let member = [0x7Bu8; 32];
        let filter = vec![0xEF; 32];
        let prefix = vec![9u32];
        // Three consecutive confirms: epochs 40, 41, 42.
        let mut tree = None;
        for (epoch, root_byte) in [(40u64, 0x40u8), (41, 0x41), (42, 0x42)] {
            tree = Some(crate::global_intrinsic::materialize::upsert_leaf_root_registration(
                tree.as_ref(), &member, &filter, &prefix, epoch, &vec![root_byte; 74], 8, 1000,
            ).unwrap());
        }
        let blob = vertex_tree_to_blob(tree.as_ref().unwrap());
        let root = deserialize_go_tree(&blob).unwrap().unwrap();
        let mut reg = InMemoryProverRegistry::new();
        for (key, recd) in super::decode_leaf_root(&root) {
            reg.leaf_root_cache.insert(key, recd);
        }
        let leaf_id = crate::global_intrinsic::leaf_id_bytes(&filter, &prefix);
        for (epoch, expected) in [(40u64, 0x40u8), (41, 0x41), (42, 0x42)] {
            let got = reg.get_leaf_root(&member, &leaf_id, epoch)
                .unwrap_or_else(|| panic!("epoch {epoch} must be cached"));
            assert_eq!(got.leaf_root, vec![expected; 74], "epoch {epoch}");
            assert_eq!(got.epoch, epoch);
        }
        // An epoch it never registered stays absent.
        assert!(reg.get_leaf_root(&member, &leaf_id, 39).is_none());
        assert!(reg.get_leaf_root(&member, &leaf_id, 43).is_none());
    }

    #[test]
    fn refresh_populates_leaf_root_cache() {
        let member = [0x9Au8; 32];
        let filter = vec![0xCD; 32];
        let prefix = vec![3u32];
        let tree = crate::global_intrinsic::materialize::create_leaf_root_vertex_tree(
            &member, &filter, &prefix, 5, &vec![0x22; 74], 64, 100,
        )
        .unwrap();
        let mut reg = InMemoryProverRegistry::new();
        // Drive the same pass-1 dispatch refresh uses.
        let blob = vertex_tree_to_blob(&tree);
        let root = deserialize_go_tree(&blob).unwrap().unwrap();
        for (key, recd) in super::decode_leaf_root(&root) {
            reg.leaf_root_cache.insert(key, recd);
        }
        let leaf_id = crate::global_intrinsic::leaf_id_bytes(&filter, &prefix);
        let got = reg.get_leaf_root(&member, &leaf_id, 5).expect("cached");
        assert_eq!(got.leaf_root, vec![0x22; 74]);
        assert_eq!(got.epoch, 5);
        assert_eq!(reg.leaf_root_count(), 1);
        // Unknown member/leaf → None.
        assert!(reg.get_leaf_root(&[0u8; 32], &leaf_id, 5).is_none());
        // Right member/leaf but wrong epoch → None (per-epoch keying).
        assert!(reg.get_leaf_root(&member, &leaf_id, 6).is_none());
    }

    #[test]
    fn leaf_root_cache_covers_every_epoch_slot_like_the_audit_reader() {
        use crate::global_intrinsic::materialize::{
            leaf_root_registration_for_epoch, upsert_leaf_root_registration,
        };

        let member = [0x7Bu8; 32];
        let filter = vec![0x31u8; 32];
        let prefix: Vec<u32> = vec![11u32, 4];
        let leaf_id = crate::global_intrinsic::leaf_id_bytes(&filter, &prefix);
        let mk = |existing: Option<&VectorCommitmentTree>, epoch: u64, lr: u8| {
            upsert_leaf_root_registration(
                existing,
                &member,
                &filter,
                &prefix,
                epoch,
                &vec![lr; 74],
                (epoch * 10) + 1,
                1000,
            )
            .unwrap()
        };

        // Roll the window forward until all three slots are populated:
        // prev = 5, current = 6, next = 7.
        let tree = mk(Some(&mk(Some(&mk(None, 5, 0x05)), 6, 0x06)), 7, 0x07);

        // Drive the real `refresh` over a real store rather than inserting into
        // the cache by hand: this test must compile and run against pre-fix
        // source too, so it touches only `refresh` and `get_leaf_root`.
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        // Real vertex key — GLOBAL_INTRINSIC_ADDRESS ++ leaf_root_address —
        // as `leaf_root_vertex_round_trips_through_real_store_refresh` uses.
        let addr = crate::global_intrinsic::materialize::leaf_root_address(&member, &leaf_id)
            .unwrap();
        let mut vk = Vec::with_capacity(64);
        vk.extend_from_slice(&crate::global_schema::GLOBAL_INTRINSIC_ADDRESS);
        vk.extend_from_slice(&addr);
        store
            .save_vertex_underlying("vertex", "adds", &shard, &vk, &vertex_tree_to_blob(&tree))
            .unwrap();

        let mut reg = InMemoryProverRegistry::new();
        let fresh = mk(None, 0, 0xA0);
        store.save_vertex_underlying("vertex", "adds", &shard, &vk, &vertex_tree_to_blob(&fresh)).unwrap();
        reg.refresh(store.as_ref()).unwrap();
        assert_eq!(reg.leaf_root_count(), 1, "absent slots must not create entries");
        assert_eq!(reg.get_leaf_root(&member, &leaf_id, 0).unwrap().leaf_root, vec![0xA0; 74]);
        assert!(reg.get_leaf_root(&member, &leaf_id, 1).is_none());

        store.save_vertex_underlying("vertex", "adds", &shard, &vk, &vertex_tree_to_blob(&tree)).unwrap();
        reg.refresh(store.as_ref()).unwrap();
        assert!(reg.get_leaf_root(&member, &leaf_id, 0).is_none(), "refresh removes the replaced registration");
        assert_eq!(reg.leaf_root_count(), 3, "one cache entry per populated epoch slot");

        // Every epoch in the window resolves, with that slot's own values.
        // Epoch 5 is the one that regressed: it lives in `Prev*`.
        for (epoch, expected_root) in [(5u64, 0x05u8), (6, 0x06), (7, 0x07)] {
            let got = reg
                .get_leaf_root(&member, &leaf_id, epoch)
                .unwrap_or_else(|| panic!("epoch {epoch} missing from the cache"));
            assert_eq!(got.leaf_root, vec![expected_root; 74], "epoch {epoch} root");
            assert_eq!(got.num_blocks, (epoch * 10) + 1, "epoch {epoch} num_blocks");
            assert_eq!(got.epoch, epoch, "record carries its own slot's epoch");
        }

        // Outside the window both readers agree it is absent.
        for epoch in [4u64, 8] {
            assert!(reg.get_leaf_root(&member, &leaf_id, epoch).is_none());
            assert!(leaf_root_registration_for_epoch(&tree, epoch).is_none());
        }

        // The point of the fix: cache and audit reader agree everywhere.
        for epoch in 3u64..=9 {
            let cached = reg
                .get_leaf_root(&member, &leaf_id, epoch)
                .map(|r| (r.leaf_root.clone(), r.num_blocks));
            assert_eq!(
                cached,
                leaf_root_registration_for_epoch(&tree, epoch),
                "registry cache and audit reader disagree at epoch {epoch}",
            );
        }
        // Re-register the same vertex: stale epochs must disappear on refresh.
        let rolled = mk(Some(&tree), 8, 0x08);
        store.save_vertex_underlying("vertex", "adds", &shard, &vk, &vertex_tree_to_blob(&rolled)).unwrap();
        reg.refresh(store.as_ref()).unwrap();
        assert_eq!(reg.leaf_root_count(), 3);
        assert!(reg.get_leaf_root(&member, &leaf_id, 5).is_none());
        for epoch in 0u64..=10 {
            let cached = reg.get_leaf_root(&member, &leaf_id, epoch)
                .map(|r| (r.leaf_root.clone(), r.num_blocks));
            assert_eq!(cached, leaf_root_registration_for_epoch(&rolled, epoch),
                "rolled cache and audit reader disagree at epoch {epoch}");
        }
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

    /// Seed one freshly-active prover + allocation on `filter` so a shard can
    /// reach `MIN_SHARD_CONSENSUS_PROVERS` and its real eviction target stays
    /// evictable. The filler is effectively Active at `frame` (current epoch,
    /// last_active = frame), so it counts toward the shard's active census but
    /// is never itself an eviction candidate. `addr_byte` must be distinct per
    /// filler; its allocation vertex is keyed `addr_byte ^ 0x80` to avoid
    /// colliding with the prover vertex key.
    fn seed_active_filler(
        store: &RocksHypergraphStore,
        shard: &ShardKey,
        filter: &[u8],
        frame: u64,
        addr_byte: u8,
    ) {
        let cur_epoch = quil_types::consensus::epoch_for_frame(frame);
        let prover = build_sub_tree(vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", vec![0xCD; 57]),
            field_leaf("prover:Prover", "Status", vec![1u8]),
            field_leaf("prover:Prover", "AvailableStorage", 0u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
        ]);
        let alloc = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", vec![addr_byte; 32]),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.to_vec()),
            field_leaf(
                "allocation:ProverAllocation",
                "LastActiveFrameNumber",
                frame.to_be_bytes().to_vec(),
            ),
            field_leaf(
                "allocation:ProverAllocation",
                "Epoch",
                cur_epoch.to_be_bytes().to_vec(),
            ),
        ]);
        store
            .save_vertex_underlying("vertex", "adds", shard, &make_vertex_key(addr_byte), &prover)
            .unwrap();
        store
            .save_vertex_underlying(
                "vertex",
                "adds",
                shard,
                &make_vertex_key(addr_byte ^ 0x80),
                &alloc,
            )
            .unwrap();
    }

    /// Seed `MIN_SHARD_CONSENSUS_PROVERS` fresh active fillers on `filter`, so
    /// the fillers alone meet the shard's eviction floor and every stale
    /// allocation also seeded on it can be evicted. Fillers use address bytes
    /// from `base_byte` upward.
    fn seed_shard_floor(
        store: &RocksHypergraphStore,
        shard: &ShardKey,
        filter: &[u8],
        frame: u64,
        base_byte: u8,
    ) {
        for i in 0..quil_types::consensus::MIN_SHARD_CONSENSUS_PROVERS {
            seed_active_filler(store, shard, filter, frame, base_byte.wrapping_add(i as u8));
        }
    }

    /// Seed `count` fresh Active provers, each with one allocation on every
    /// filter in `filters`, last active at `frame`. Addresses are
    /// `[tag; 30] ++ [0, i]` for provers and `[tag; 30] ++ [1 + k, i]` for
    /// their allocation on `filters[k]`, outside the single-byte keys of
    /// `make_vertex_key`, so a shard can hold enough fresh members to read
    /// as progressing.
    fn seed_fresh_members(
        store: &RocksHypergraphStore,
        shard: &ShardKey,
        filters: &[&[u8]],
        frame: u64,
        count: u8,
        tag: u8,
    ) {
        let address_and_key = |hi: u8, lo: u8| -> (Vec<u8>, Vec<u8>) {
            let mut address = vec![tag; 30];
            address.extend_from_slice(&[hi, lo]);
            let mut key = vec![0xFFu8; 32];
            key.extend_from_slice(&address);
            (address, key)
        };
        for i in 0..count {
            let (address, prover_key) = address_and_key(0, i);
            let prover = build_sub_tree(vec![
                type_hash_leaf("prover:Prover"),
                field_leaf("prover:Prover", "PublicKey", vec![0xCD; 57]),
                field_leaf("prover:Prover", "Status", vec![1u8]),
                field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
            ]);
            store
                .save_vertex_underlying("vertex", "adds", shard, &prover_key, &prover)
                .unwrap();
            for (k, filter) in filters.iter().enumerate() {
                let (_, alloc_key) = address_and_key(1 + k as u8, i);
                let alloc = build_sub_tree(vec![
                    type_hash_leaf("allocation:ProverAllocation"),
                    field_leaf("allocation:ProverAllocation", "Prover", address.clone()),
                    field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
                    field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.to_vec()),
                    field_leaf(
                        "allocation:ProverAllocation",
                        "LastActiveFrameNumber",
                        frame.to_be_bytes().to_vec(),
                    ),
                    field_leaf(
                        "allocation:ProverAllocation",
                        "Epoch",
                        quil_types::consensus::epoch_for_frame(frame).to_be_bytes().to_vec(),
                    ),
                ]);
                store
                    .save_vertex_underlying("vertex", "adds", shard, &alloc_key, &alloc)
                    .unwrap();
            }
        }
    }

    /// Seed an Active prover vertex keyed `make_vertex_key(prover_byte)`.
    fn seed_prover(store: &RocksHypergraphStore, shard: &ShardKey, prover_byte: u8, seniority: u64) {
        let prover = build_sub_tree(vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", vec![0xCD; 57]),
            field_leaf("prover:Prover", "Status", vec![1u8]),
            field_leaf("prover:Prover", "AvailableStorage", 0u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "Seniority", seniority.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
        ]);
        store
            .save_vertex_underlying("vertex", "adds", shard, &make_vertex_key(prover_byte), &prover)
            .unwrap();
    }

    /// Seed an Active allocation of `prover_byte` on `filter`, keyed
    /// `make_vertex_key(alloc_byte)`, current for the epoch of `frame` and
    /// last active at `last_active`.
    fn seed_allocation(
        store: &RocksHypergraphStore,
        shard: &ShardKey,
        prover_byte: u8,
        alloc_byte: u8,
        filter: &[u8],
        last_active: u64,
        frame: u64,
    ) {
        let alloc = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", vec![prover_byte; 32]),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.to_vec()),
            field_leaf(
                "allocation:ProverAllocation",
                "LastActiveFrameNumber",
                last_active.to_be_bytes().to_vec(),
            ),
            field_leaf(
                "allocation:ProverAllocation",
                "Epoch",
                quil_types::consensus::epoch_for_frame(frame).to_be_bytes().to_vec(),
            ),
        ]);
        store
            .save_vertex_underlying("vertex", "adds", shard, &make_vertex_key(alloc_byte), &alloc)
            .unwrap();
    }

    /// Read a global vertex as the evictor would: the CRDT state first, then
    /// the flat store.
    fn read_global_vertex(
        state: &crate::hypergraph_state::HypergraphState,
        store: &RocksHypergraphStore,
        shard: &ShardKey,
        address_byte: u8,
    ) -> VectorCommitmentTree {
        let va_disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        let blob = match state.get(&crate::domains::GLOBAL, &[address_byte; 32], &va_disc).unwrap() {
            Some(blob) => blob,
            // Both store traits define this read; name the live one.
            None => <RocksHypergraphStore as HypergraphStore>::load_vertex_underlying_raw(
                store,
                "vertex",
                "adds",
                shard,
                &make_vertex_key(address_byte),
            )
            .unwrap()
            .unwrap(),
        };
        rebuild_vertex_tree_from_blob(&blob)
    }

    /// A HypergraphState over an empty in-memory CRDT, so the evictor reads
    /// every vertex through its flat-store fallback.
    fn empty_state() -> crate::hypergraph_state::HypergraphState {
        crate::hypergraph_state::HypergraphState::new(Arc::new(
            quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_hypergraph::testing::MemStore::new()),
                Arc::new(quil_types::crypto::NoopInclusionProver),
            ),
        ))
    }

    /// Integration: a leaf-root vertex written to a REAL store is decoded by
    /// `refresh_from_store` (via the type-hash dispatch) and surfaced through
    /// `get_leaf_root` — the persistence path the unit test stubs. This is the
    /// bridge the storage-attestation verifier relies on (confirm materializes
    /// the vertex → registry refresh → verifier cross-checks the opening).
    #[test]
    fn leaf_root_vertex_round_trips_through_real_store_refresh() {
        use crate::global_intrinsic::leaf_id_bytes;
        use crate::global_intrinsic::materialize::{
            create_leaf_root_vertex_tree, leaf_root_address,
        };
        let member = [0x9Au8; 32];
        let filter = vec![0xABu8; 32];
        let prefix = vec![42u32, 7];
        let epoch = 19u64;
        let leaf_root = vec![0x11u8; 74];
        let num_blocks = 1234u64;

        let tree = create_leaf_root_vertex_tree(
            &member, &filter, &prefix, epoch, &leaf_root, num_blocks, 900_000,
        )
        .unwrap();
        let addr = leaf_root_address(&member, &leaf_id_bytes(&filter, &prefix)).unwrap();

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        // Vertex key = GLOBAL_INTRINSIC_ADDRESS (domain) ++ address.
        let mut vk = Vec::with_capacity(64);
        vk.extend_from_slice(&crate::global_schema::GLOBAL_INTRINSIC_ADDRESS);
        vk.extend_from_slice(&addr);
        store
            .save_vertex_underlying("vertex", "adds", &shard, &vk, &vertex_tree_to_blob(&tree))
            .unwrap();

        let shared = SharedProverRegistry::new();
        shared.refresh_from_store(store.as_ref()).unwrap();

        let leaf_id = leaf_id_bytes(&filter, &prefix);
        let got = shared.get_leaf_root(&member, &leaf_id, epoch).expect("registered");
        assert_eq!(got, LeafRootRecord { leaf_root, num_blocks, epoch });
        // Unknown leaf → None.
        assert!(shared.get_leaf_root(&member, b"nope", epoch).is_none());
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
        reg.refresh(store.as_ref()).unwrap();

        assert_eq!(reg.provers_visited(), 1);
        assert_eq!(reg.distinct_provers(), 1);
        let got = reg.get_prover_info(&[0x01; 32]).expect("prover present");
        assert_eq!(got.status, ProverStatus::Active);
        assert_eq!(got.available_storage, 1024);
        assert_eq!(got.seniority, 42);
        assert_eq!(got.public_key, vec![0xAA; 57]);
        assert!(got.allocations.is_empty());
    }

    /// A kicked prover vertex (Status byte 4) is DROPPED from the registry —
    /// `map_prover_status(4) → None`. Eviction zeroes Seniority before encode;
    /// the disambiguating `KickFrameNumber` is set.
    #[test]
    fn decode_prover_kicked_byte4_is_excluded() {
        let leaves = vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", vec![0xAA; 57]),
            field_leaf("prover:Prover", "Status", vec![4u8]), // kicked/left
            field_leaf("prover:Prover", "AvailableStorage", 1024u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "KickFrameNumber", 700u64.to_be_bytes().to_vec()),
        ];
        let bytes = build_sub_tree(leaves);
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let vk = make_vertex_key(0x02);
        store.save_vertex_underlying("vertex", "adds", &shard, &vk, &bytes).unwrap();

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        assert_eq!(reg.distinct_provers(), 0, "kicked prover (byte 4) excluded from cache");
        assert!(reg.get_prover_info(&[0x02; 32]).is_none());
    }

    #[test]
    fn activated_reward_rings_require_committed_policy_fields() {
        use quil_types::consensus::{CommitteeHandoffPolicy, LegacyHistory};
        struct RestorePolicy(Option<CommitteeHandoffPolicy>);
        impl Drop for RestorePolicy {
            fn drop(&mut self) { quil_types::consensus::set_committee_handoff_policy(self.0); }
        }
        let _restore = RestorePolicy(quil_types::consensus::committee_handoff_policy());
        quil_types::consensus::set_committee_handoff_policy(Some(CommitteeHandoffPolicy {
            activation_frame: 0, chain_id: [1; 32], legacy_history: LegacyHistory::Discard,
            membership_boundary_frame: u64::MAX, first_session_boundary_frame: u64::MAX,
        }));
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let filter = vec![0xCC; 32];
        let shared = SharedProverRegistry::new();
        let save_allocation = |id: u8, status: u8, ring: Option<u8>, key: Option<Vec<u8>>| {
            let mut fields = vec![
                type_hash_leaf("allocation:ProverAllocation"),
                field_leaf("allocation:ProverAllocation", "Prover", vec![id; 32]),
                field_leaf("allocation:ProverAllocation", "Status", vec![status]),
                field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.clone()),
            ];
            if let Some(ring) = ring { fields.push(field_leaf("allocation:ProverAllocation", "Ring", vec![ring])); }
            if let Some(key) = key {
                fields.push(field_leaf("allocation:ProverAllocation", "RingEpoch", key.clone()));
                fields.push(field_leaf("allocation:ProverAllocation", "RingSeniority", key));
            }
            store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(id + 16),
                &build_sub_tree(fields)).unwrap();
            shared.refresh_from_store(store.as_ref()).unwrap();
        };
        for id in [1u8, 2] {
            store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(id),
                &build_sub_tree(vec![type_hash_leaf("prover:Prover"),
                    field_leaf("prover:Prover", "PublicKey", vec![id; 57]),
                    field_leaf("prover:Prover", "Status", vec![1])])).unwrap();
        }
        // Both an absent ring and an old ring without its policy key are unknown.
        save_allocation(1, 1, None, None);
        save_allocation(2, 1, Some(0), None);
        assert!(shared.get_reward_ring_estimate(&[1; 32], &filter, 0).unwrap().is_none());
        save_allocation(1, 1, Some(0), Some(vec![0; 8]));
        assert!(shared.get_reward_ring_estimate(&[1; 32], &filter, 0).unwrap().is_none(),
            "a partial peer snapshot cannot establish ring occupancy");
        for status in [0, 2] { // pending Joining and Paused do not earn
            save_allocation(2, status, None, None);
            let held = shared.get_reward_ring_estimate(&[1; 32], &filter, 0).unwrap().unwrap();
            assert_eq!((held.ring, held.provers_on_ring), (0, 1),
                "a non-earning peer without a ring key must not hide the owner's committed rank");
        }
        for key in [None, Some(vec![0; 8])] {
            save_allocation(2, 1, None, key);
            let held = shared.get_reward_ring_estimate(&[1; 32], &filter, 0).unwrap().unwrap();
            assert_eq!((held.ring, held.provers_on_ring, held.member_count), (0, 1, 1),
                "an active unassigned peer must not hide or dilute the owner's committed rank");
            assert!(shared.get_reward_ring_estimate(&[2; 32], &filter, 0).unwrap().is_none(),
                "an unassigned owner must remain unknown");
        }
        save_allocation(2, 1, None, Some(vec![0; 7]));
        assert!(shared.get_reward_ring_estimate(&[1; 32], &filter, 0).unwrap().is_none(),
            "an absent ring must not conceal malformed policy fields");
        save_allocation(2, 1, Some(0), Some(vec![0; 8]));
        let estimate = shared.get_reward_ring_estimate(&[1; 32], &filter, 0).unwrap().unwrap();
        assert_eq!((estimate.ring, estimate.provers_on_ring), (0, 2), "real zero is valid");
        let lifecycle = shared.get_lifecycle_view(&[1; 32], 0).unwrap();
        assert_eq!(lifecycle.reward_rings[&filter].ring, 0);
        save_allocation(2, 1, Some(1), Some(vec![0; 8]));
        assert_eq!(shared.get_reward_ring_estimate(&[1; 32], &filter, 0).unwrap().unwrap().provers_on_ring, 1);
        save_allocation(2, 1, Some(1), Some(vec![0; 7]));
        assert!(shared.get_reward_ring_estimate(&[1; 32], &filter, 0).unwrap().is_none(),
            "malformed fields must invalidate a previously known estimate");
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
        reg.refresh(store.as_ref()).unwrap();

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
        let active = reg.get_active_provers(&filter, 0);
        assert_eq!(active.len(), 1);
    }

    /// `all_provers_with_allocations_committed` (the unified-tree reset's
    /// enumeration) must surface every prover with EVERY confirmation filter it
    /// holds, keyed by its real address — and each allocation must live at
    /// `allocation_address(pubkey, filter)`, so the reset's drop (which recomputes
    /// that address) targets exactly the seeded vertices. Seeds provers at their
    /// REAL poseidon addresses, the on-chain layout the reset assumes.
    #[test]
    fn all_provers_with_allocations_enumerates_real_addresses_and_filters() {
        use crate::global_intrinsic::materialize::{allocation_address, prover_address_from_pubkey};
        use quil_hypergraph::HypergraphCrdt;
        use quil_types::crypto::NoopInclusionProver;

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let quil = crate::domains::QUIL_TOKEN;
        let mk_filter = |suffix: u8| {
            let mut f = quil.to_vec();
            f.push(suffix);
            f
        };

        // Seed a prover at prover_address_from_pubkey(pk) with an allocation at
        // allocation_address(pk, filter) for each filter. Returns the address.
        let seed = |pk: &[u8], filters: &[Vec<u8>]| -> Vec<u8> {
            let paddr = prover_address_from_pubkey(pk).unwrap();
            let prover = build_sub_tree(vec![
                type_hash_leaf("prover:Prover"),
                field_leaf("prover:Prover", "PublicKey", pk.to_vec()),
                field_leaf("prover:Prover", "Status", vec![1u8]),
                field_leaf("prover:Prover", "AvailableStorage", 0u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
            ]);
            let mut pvk = vec![0xFFu8; 32];
            pvk.extend_from_slice(&paddr);
            store
                .save_vertex_underlying("vertex", "adds", &shard, &pvk, &prover)
                .unwrap();
            for filter in filters {
                let aaddr = allocation_address(pk, filter).unwrap();
                let alloc = build_sub_tree(vec![
                    type_hash_leaf("allocation:ProverAllocation"),
                    field_leaf("allocation:ProverAllocation", "Prover", paddr.to_vec()),
                    field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
                    field_leaf(
                        "allocation:ProverAllocation",
                        "ConfirmationFilter",
                        filter.clone(),
                    ),
                ]);
                let mut avk = vec![0xFFu8; 32];
                avk.extend_from_slice(&aaddr);
                store
                    .save_vertex_underlying("vertex", "adds", &shard, &avk, &alloc)
                    .unwrap();
            }
            paddr.to_vec()
        };

        let pk_a = vec![0xA1u8; 57];
        let pk_b = vec![0xB2u8; 57];
        let fa = vec![mk_filter(0x00), mk_filter(0x01)]; // two sub-shards
        let fb = vec![mk_filter(0x02)];
        let addr_a = seed(&pk_a, &fa);
        let addr_b = seed(&pk_b, &fb);

        let crdt = HypergraphCrdt::new(
            store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
            Arc::new(NoopInclusionProver),
        );
        let by_addr: HashMap<Vec<u8>, (Vec<u8>, Vec<Vec<u8>>)> =
            all_provers_with_allocations_committed(&crdt)
                .into_iter()
                .map(|(a, p, f)| (a, (p, f)))
                .collect();

        assert_eq!(by_addr.len(), 2, "both provers enumerated");
        let (pa, mut fa_got) = by_addr.get(&addr_a).cloned().expect("prover A present");
        fa_got.sort();
        let mut fa_want = fa.clone();
        fa_want.sort();
        assert_eq!(pa, pk_a, "A pubkey recovered");
        assert_eq!(fa_got, fa_want, "A carries BOTH sub-shard filters");
        let (pb, fb_got) = by_addr.get(&addr_b).cloned().expect("prover B present");
        assert_eq!(pb, pk_b, "B pubkey recovered");
        assert_eq!(fb_got, fb, "B carries its single filter");
        // Enumerating A's filter fa[0] proves the allocation seeded at
        // allocation_address(pk_a, fa[0]) was read — i.e. the reset's drop, which
        // recomputes that same address, targets exactly the vertex that exists.

        // A tombstoned allocation is gone from committed state: the scan that
        // reassigns allocations and seats committees must not resurrect it.
        let scan = CommittedProverScan::try_scan(&crdt).unwrap();
        assert_eq!(scan.all_on_filter(&fb[0]), vec![(pk_b.clone(), addr_b.clone())]);
        let mut removed = vec![0xFFu8; 32];
        removed.extend_from_slice(&allocation_address(&pk_b, &fb[0]).unwrap());
        store.save_vertex_underlying("vertex", "removes", &shard, &removed, b"removed").unwrap();
        let scan = CommittedProverScan::try_scan(&crdt).unwrap();
        assert!(scan.all_on_filter(&fb[0]).is_empty(), "a removed allocation stays removed");
        assert_eq!(scan.all_on_filter(&fa[0]), vec![(pk_a.clone(), addr_a.clone())]);
    }

    /// Cost of the committed prover scan over a shard dominated by other
    /// vertices, against parsing every vertex (the scan before its prefilter).
    #[test]
    #[ignore = "measurement"]
    fn measure_committed_prover_scan() {
        use crate::global_intrinsic::materialize::{allocation_address, create_allocation_vertex_tree, create_prover_vertex_tree, prover_address_from_pubkey};
        use crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;
        use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())) as Arc<dyn quil_types::store::HypergraphStore>,
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
        let state = HypergraphState::new(crdt.clone());
        let va = vertex_adds_discriminator().unwrap();
        let (provers, allocations_each, others) = (120usize, 40usize, 60_000usize);
        for p in 0..provers {
            let key = { let mut k = vec![0u8; 897]; k[..2].copy_from_slice(&(p as u16).to_be_bytes()); k };
            let address = prover_address_from_pubkey(&key).unwrap();
            state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &va, 1, vertex_tree_to_blob(&create_prover_vertex_tree(&key, 5).unwrap())).unwrap();
            for a in 0..allocations_each {
                let filter = { let mut f = vec![0x11u8; 32]; f.extend_from_slice(&[0, 7, a as u8]); f };
                let tree = create_allocation_vertex_tree(&address, &filter, 9).unwrap();
                state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &allocation_address(&key, &filter).unwrap(), &va, 1, vertex_tree_to_blob(&tree)).unwrap();
            }
        }
        for o in 0..others {
            let mut tree = quil_tries::VectorCommitmentTree::new();
            for field in 0u8..8 {
                tree.insert(&[field << 2], &[(o % 251) as u8; 40], &[], &num_bigint::BigInt::from(40)).unwrap();
            }
            let address: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest((o as u64).to_be_bytes()).into();
            state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &va, 1, vertex_tree_to_blob(&tree)).unwrap();
        }
        state.commit().unwrap();
        state.abort();
        crdt.commit(1).unwrap();
        let shard = ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };
        for pass in ["cold", "warm"] {
            let started = std::time::Instant::now();
            let scan = CommittedProverScan::try_scan(&crdt).unwrap();
            let scanned = started.elapsed();
            let started = std::time::Instant::now();
            let mut parsed = 0usize;
            crdt.for_each_vertex_underlying_shard("vertex", "adds", &shard, &mut |_k, data| {
                if deserialize_go_tree(&data).ok().flatten().is_some() { parsed += 1; }
            }).unwrap();
            eprintln!("{pass}: scan {:?} ({} allocations); parsing every vertex {:?} ({parsed})",
                scanned, scan.allocations.len(), started.elapsed());
        }
    }

    /// The scan's byte prefilter keeps every prover and allocation and lets
    /// other vertices of the shard skip parsing.
    #[test]
    fn only_provers_and_allocations_pass_the_scan_prefilter() {
        use crate::global_intrinsic::materialize::{create_allocation_vertex_tree, create_prover_vertex_tree};
        let prover = create_prover_vertex_tree(&[7u8; 897], 5).unwrap();
        let allocation = create_allocation_vertex_tree(&[1u8; 32], &[2u8; 35], 9).unwrap();
        assert!(holds_scanned_type(&vertex_tree_to_blob(&prover)));
        assert!(holds_scanned_type(&vertex_tree_to_blob(&allocation)));
        let mut other = quil_tries::VectorCommitmentTree::new();
        other.insert(&[0xFF; 32], &[0x42; 32], &[], &num_bigint::BigInt::from(32)).unwrap();
        other.insert(&[0], b"some record", &[], &num_bigint::BigInt::from(11)).unwrap();
        assert!(!holds_scanned_type(&vertex_tree_to_blob(&other)));
        assert!(!holds_scanned_type(&[]));
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
        reg.refresh(store.as_ref()).unwrap();

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
        reg.refresh(store.as_ref()).unwrap();
        assert_eq!(reg.distinct_provers(), 4);

        // Query from the zero vector. The closest should be addr[0]
        // (all zeros), and addr[2] (lowest non-zero bit) should come
        // next.
        let zero = [0u8; 32];
        let order = reg.get_ordered_provers(&zero, &filter, 0);
        assert_eq!(order[0], addrs[0]);
        assert_eq!(order[1], addrs[2]);
        assert_eq!(order.len(), 4);

        // get_next_prover returns the single nearest.
        let next = reg.get_next_prover(&zero, &filter, 0).unwrap();
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
        reg.refresh(store.as_ref()).unwrap();

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

        let mk_prover = |_addr: [u8; 32]| {
            build_sub_tree(vec![
                type_hash_leaf("prover:Prover"),
                field_leaf("prover:Prover", "PublicKey", vec![0xCD; 57]),
                field_leaf("prover:Prover", "Status", vec![1u8]),
                field_leaf("prover:Prover", "AvailableStorage", 0u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
            ])
        };
        // `Epoch` must satisfy `epoch >= epoch_for_frame(frame)` so the
        // frame-aware eviction gate reads these as effectively Active (a fresh,
        // re-confirmed member). Without it the allocation would read as
        // ExpiredEpoch and be (correctly) exempt from inactivity eviction.
        let cur_epoch = quil_types::consensus::epoch_for_frame(
            quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900,
        );
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
                field_leaf(
                    "allocation:ProverAllocation",
                    "Epoch",
                    cur_epoch.to_be_bytes().to_vec(),
                ),
            ])
        };

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };

        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x81), &mk_prover(prover_1)).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x91), &mk_alloc(&prover_1, &filter_normal)).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x82), &mk_prover(prover_2)).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x92), &mk_alloc(&prover_2, &filter_halted)).unwrap();

        let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900;
        // Both shards carry only ONE real active prover, which is below the
        // consensus quorum and would exempt them via the under-provisioned
        // rule. Seed BOTH with a floor of fresh active fillers so the ONLY
        // thing sparing prover_2 is the `u64::MAX` halt (the behavior under
        // test), and prover_1 stays a genuine inactivity candidate.
        seed_shard_floor(&store, &shard, &filter_normal, frame, 0xE0);
        seed_shard_floor(&store, &shard, &filter_halted, frame, 0xF0);

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();

        // Frame is past the inactivity start; last_active (100) predates
        // it, so inactivity counts from EVICTION_INACTIVITY_START_FRAME:
        // 900 frames inactive. Threshold = 500. Both would hit it, but
        // filter_halted is fully exempt.
        let mut halts: HashMap<Vec<u8>, u64> = HashMap::new();
        halts.insert(filter_halted.clone(), u64::MAX);

        let evict = reg.find_eviction_candidates(frame, 500, &halts);
        assert_eq!(evict.len(), 1);
        assert_eq!(evict[0].prover_address, prover_1.to_vec());
        assert_eq!(evict[0].confirmation_filter, filter_normal);
    }

    #[test]
    fn find_eviction_candidates_exempts_under_provisioned_shard() {
        // A shard with fewer than MIN_SHARD_CONSENSUS_PROVERS effectively-active
        // provers cannot run its consensus (it's under a coverage halt), so no
        // shard frame is produced and its provers physically cannot submit a
        // proof — NONE may be evicted for inactivity, however long they've been
        // idle. The moment the shard reaches quorum its idle provers become
        // evictable. This is the "not enough provers to run consensus / coverage
        // halt" exemption, computed from committed registry state so every
        // archive agrees (no dependence on the per-node coverage monitor).
        let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 5000;
        let cur_epoch = quil_types::consensus::epoch_for_frame(frame);
        let filter = vec![0x44u8; 64];

        // Build `stale` effectively-active but long-INACTIVE provers and
        // `fresh` freshly active ones on one shard and return the eviction
        // candidate set. Two thirds fresh keeps the shard progressing, so only
        // the quorum census decides.
        let candidates_for = |stale: u8, fresh: u8| -> Vec<EvictionCandidate> {
            let (_tmp, store) = temp_store();
            let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
            for i in 0..stale + fresh {
                let last_active = if i < stale { 100u64 } else { frame };
                let addr = [0x10u8 + i; 32];
                let prover = build_sub_tree(vec![
                    type_hash_leaf("prover:Prover"),
                    field_leaf("prover:Prover", "PublicKey", vec![0xCD; 57]),
                    field_leaf("prover:Prover", "Status", vec![1u8]),
                    field_leaf("prover:Prover", "AvailableStorage", 0u64.to_be_bytes().to_vec()),
                    field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
                    field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
                ]);
                let alloc = build_sub_tree(vec![
                    type_hash_leaf("allocation:ProverAllocation"),
                    field_leaf("allocation:ProverAllocation", "Prover", addr.to_vec()),
                    field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
                    field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.clone()),
                    // Stale: idle since before the inactivity-start frame → past threshold.
                    field_leaf("allocation:ProverAllocation", "LastActiveFrameNumber", last_active.to_be_bytes().to_vec()),
                    field_leaf("allocation:ProverAllocation", "Epoch", cur_epoch.to_be_bytes().to_vec()),
                ]);
                store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x10 + i), &prover).unwrap();
                store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x90 + i), &alloc).unwrap();
            }
            let mut reg = InMemoryProverRegistry::new();
            reg.refresh(store.as_ref()).unwrap();
            let halts: HashMap<Vec<u8>, u64> = HashMap::new();
            reg.find_eviction_candidates(frame, 500, &halts)
        };

        let min = quil_types::consensus::MIN_SHARD_CONSENSUS_PROVERS as u8;

        // One prover below quorum: the shard can't run consensus → all exempt,
        // even though its stale prover is long past the inactivity threshold.
        let below = candidates_for(1, min - 2);
        assert!(
            below.is_empty(),
            "an under-provisioned shard (below consensus quorum) must not evict anyone"
        );

        // At quorum: the shard can run consensus, but evicting anyone would
        // take it below the floor, so no one is selected.
        let at = candidates_for(1, min - 1);
        assert!(at.is_empty(), "a shard exactly at the floor has nothing to evict");

        // Above quorum: the stale provers are evictable.
        let above = candidates_for(2, min);
        assert_eq!(
            above.len(),
            2,
            "a progressing shard above MIN_SHARD_CONSENSUS_PROVERS loses its stale provers"
        );
    }

    #[test]
    fn find_eviction_candidates_is_insertion_order_independent() {
        // The eviction set MUST be a pure function of the committed vertex set,
        // NOT of the order vertices were written to the store / iterated out of
        // the prover_cache HashMap. Two archives with the same state but
        // different insert order must select the identical set — otherwise they
        // mutate the prover tree differently and their prover roots diverge.
        // This covers the stall exemption and a prover with stale allocations
        // on two shards.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let frame = start + 5000;
        let filter_a = vec![0x44u8; 64];
        let filter_b = vec![0x55u8; 64];
        let filter_c = vec![0x66u8; 64];

        // (vertex key byte, Some((prover byte, filter, last_active)) for an
        // allocation, None for a prover vertex).
        type SeedWrite = (u8, Option<(u8, Vec<u8>, u64)>);
        let mut writes: Vec<SeedWrite> = Vec::new();
        // Shard A: nine members. 0x20, 0x21, 0x22 are stale; 0x23..=0x28 are
        // fresh, so the shard is progressing and all three stale ones go.
        let mut members = vec![(0x20u8, start + 1000), (0x21, start + 100), (0x22, start + 1000)];
        members.extend((0x23u8..0x29).map(|p| (p, frame)));
        // Shard C: six members, all equally stale. The shard is stalled, so
        // none goes (the floor alone would take two, by address).
        members.extend((0x50u8..0x56).map(|p| (p, start + 1000)));
        for (p, last_active) in members {
            let filter = if p < 0x50 { filter_a.clone() } else { filter_c.clone() };
            writes.push((p, None));
            writes.push((p + 0x80, Some((p, filter, last_active))));
        }
        // Shard B: 0x22's second allocation (stale) plus four fresh members.
        // Floor 4 → only 0x22 may go.
        writes.push((0xC2, Some((0x22, filter_b.clone(), start + 1000))));
        for p in 0x30u8..0x34 {
            writes.push((p, None));
            writes.push((p + 0x80, Some((p, filter_b.clone(), frame))));
        }

        let candidates_for_order = |order: &[usize]| -> Vec<EvictionCandidate> {
            let (_tmp, store) = temp_store();
            let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
            for &i in order {
                match &writes[i] {
                    (key, None) => seed_prover(&store, &shard, *key, 0),
                    (key, Some((p, filter, last_active))) => {
                        seed_allocation(&store, &shard, *p, *key, filter, *last_active, frame)
                    }
                }
            }
            let mut reg = InMemoryProverRegistry::new();
            reg.refresh(store.as_ref()).unwrap();
            let halts: HashMap<Vec<u8>, u64> = HashMap::new();
            reg.find_eviction_candidates(frame, 500, &halts)
        };

        let forward: Vec<usize> = (0..writes.len()).collect();
        let reversed: Vec<usize> = (0..writes.len()).rev().collect();
        let mut interleaved: Vec<usize> = (0..writes.len()).step_by(2).collect();
        interleaved.extend((1..writes.len()).step_by(2).rev());

        let a = candidates_for_order(&forward);
        let b = candidates_for_order(&reversed);
        let c = candidates_for_order(&interleaved);

        let selected: Vec<(Vec<u8>, Vec<u8>)> = a
            .iter()
            .map(|c| (c.prover_address.clone(), c.confirmation_filter.clone()))
            .collect();
        assert_eq!(
            selected,
            vec![
                (vec![0x20u8; 32], filter_a.clone()),
                (vec![0x21u8; 32], filter_a.clone()),
                (vec![0x22u8; 32], filter_a.clone()),
                (vec![0x22u8; 32], filter_b.clone()),
            ],
            "stale allocations of progressing shards only; sorted by (prover, filter)"
        );
        assert_eq!(a, b, "eviction set must not depend on insert order (fwd vs rev)");
        assert_eq!(a, c, "eviction set must not depend on insert order (fwd vs interleaved)");
    }

    /// Seed one prover per `(prover byte, last_active)` member on `filter`,
    /// each allocation keyed `prover byte + 0x80` and current for `frame`.
    fn seed_members(
        store: &RocksHypergraphStore,
        shard: &ShardKey,
        filter: &[u8],
        members: &[(u8, u64)],
        frame: u64,
    ) {
        for &(p, last_active) in members {
            seed_prover(store, shard, p, 0);
            seed_allocation(store, shard, p, p + 0x80, filter, last_active, frame);
        }
    }

    fn selected_pairs(candidates: &[EvictionCandidate]) -> Vec<(Vec<u8>, Vec<u8>)> {
        candidates
            .iter()
            .map(|c| (c.prover_address.clone(), c.confirmation_filter.clone()))
            .collect()
    }

    #[test]
    fn find_eviction_candidates_exempts_stalled_shard() {
        // A committee below voting quorum certifies no frame, so every member
        // ages alike, voters and absentees. Six members, all last active at
        // the same frame, long past the threshold, above the floor: inactivity
        // cannot tell who votes, so none is selected.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let frame = start + 5000;
        let filter = vec![0x47u8; 64];
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let members: Vec<(u8, u64)> = (0x10u8..0x16).map(|p| (p, start + 100)).collect();
        seed_members(&store, &shard, &filter, &members, frame);
        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        assert!(reg.find_eviction_candidates(frame, 500, &HashMap::new()).is_empty());
    }

    #[test]
    fn find_eviction_candidates_evicts_only_on_progressing_shards() {
        // Shard P produces: four of its six members are fresh, so its two
        // stale members go. Shard S has three fresh members of seven, below
        // two thirds: it is stalled and keeps all its members.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let frame = start + 5000;
        let filter_p = vec![0x48u8; 64];
        let filter_s = vec![0x49u8; 64];
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let mut producing = vec![(0x10u8, start + 100), (0x11, start + 1000)];
        producing.extend((0x12u8..0x16).map(|p| (p, frame - 100)));
        seed_members(&store, &shard, &filter_p, &producing, frame);
        let mut stalled: Vec<(u8, u64)> = (0x20u8..0x24).map(|p| (p, start + 100)).collect();
        stalled.extend((0x24u8..0x27).map(|p| (p, frame - 100)));
        seed_members(&store, &shard, &filter_s, &stalled, frame);
        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        assert_eq!(
            selected_pairs(&reg.find_eviction_candidates(frame, 500, &HashMap::new())),
            vec![(vec![0x10u8; 32], filter_p.clone()), (vec![0x11u8; 32], filter_p.clone())]
        );
    }

    /// Seed one prover whose allocation on `filter` was join-confirmed at
    /// `join_confirm`, last active at `last_active`, keyed `prover byte + 0x80`
    /// and current for `frame`.
    fn seed_joined_member(
        store: &RocksHypergraphStore,
        shard: &ShardKey,
        filter: &[u8],
        prover_byte: u8,
        join_confirm: u64,
        last_active: u64,
        frame: u64,
    ) {
        seed_prover(store, shard, prover_byte, 0);
        let alloc = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", vec![prover_byte; 32]),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.to_vec()),
            field_leaf(
                "allocation:ProverAllocation",
                "JoinConfirmFrameNumber",
                join_confirm.to_be_bytes().to_vec(),
            ),
            field_leaf(
                "allocation:ProverAllocation",
                "LastActiveFrameNumber",
                last_active.to_be_bytes().to_vec(),
            ),
            field_leaf(
                "allocation:ProverAllocation",
                "Epoch",
                quil_types::consensus::epoch_for_frame(frame).to_be_bytes().to_vec(),
            ),
        ]);
        store
            .save_vertex_underlying(
                "vertex",
                "adds",
                shard,
                &make_vertex_key(prover_byte + 0x80),
                &alloc,
            )
            .unwrap();
    }

    #[test]
    fn find_eviction_candidates_spares_newly_activated_allocation() {
        // 0x30 was join-confirmed early in the previous epoch and activates at
        // this epoch's first frame, where the eviction pass runs. Its only
        // credit is the confirm, ~710 frames old, yet it could not sign a
        // frame before now: its inactivity counts from activation. Six fresh
        // members keep the shard progressing.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let len = quil_types::consensus::epoch_length_frames();
        let activation = (quil_types::consensus::epoch_for_frame(start) + 10) * len;
        let join_confirm = activation - len + 10;
        let filter = vec![0x4Au8; 64];
        let candidates_at = |fresh_last_active: u64, frame: u64| -> Vec<EvictionCandidate> {
            let (_tmp, store) = temp_store();
            let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
            let members: Vec<(u8, u64)> = (0x10u8..0x16).map(|p| (p, fresh_last_active)).collect();
            seed_members(&store, &shard, &filter, &members, frame);
            seed_joined_member(&store, &shard, &filter, 0x30, join_confirm, join_confirm, frame);
            let mut reg = InMemoryProverRegistry::new();
            reg.refresh(store.as_ref()).unwrap();
            reg.find_eviction_candidates(frame, 500, &HashMap::new())
        };
        assert!(
            candidates_at(activation - 10, activation).is_empty(),
            "an allocation is not stale at its activation"
        );
        assert!(candidates_at(activation + 400, activation + 500).is_empty());
        assert_eq!(
            selected_pairs(&candidates_at(activation + 400, activation + 501)),
            vec![(vec![0x30u8; 32], filter.clone())],
            "stale once it stays idle past the threshold after activation"
        );
    }

    #[test]
    fn find_eviction_candidates_does_not_count_join_confirm_credit_as_fresh() {
        // Four members were join-confirmed late in the previous epoch and have
        // signed nothing since; two more are long stale. Credit from a join
        // confirm proves no signing, so no member is fresh: the shard is
        // stalled and keeps everyone.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let len = quil_types::consensus::epoch_length_frames();
        let activation = (quil_types::consensus::epoch_for_frame(start) + 10) * len;
        let join_confirm = activation - 100;
        let frame = activation + 100;
        let filter = vec![0x4Bu8; 64];
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        seed_members(&store, &shard, &filter, &[(0x10, start + 100), (0x11, start + 100)], frame);
        for p in 0x20u8..0x24 {
            seed_joined_member(&store, &shard, &filter, p, join_confirm, join_confirm, frame);
        }
        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        assert!(reg.find_eviction_candidates(frame, 500, &HashMap::new()).is_empty());

        // Once they sign a frame after joining, they are fresh and the shard
        // progresses: the two stale members go.
        let (_tmp, store) = temp_store();
        seed_members(&store, &shard, &filter, &[(0x10, start + 100), (0x11, start + 100)], frame);
        for p in 0x20u8..0x24 {
            seed_joined_member(&store, &shard, &filter, p, join_confirm, activation + 50, frame);
        }
        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        assert_eq!(
            selected_pairs(&reg.find_eviction_candidates(frame, 500, &HashMap::new())),
            vec![(vec![0x10u8; 32], filter.clone()), (vec![0x11u8; 32], filter.clone())]
        );
    }

    #[test]
    fn find_eviction_candidates_stall_boundary_is_two_thirds_fresh() {
        assert!(shard_progressing(6, 4));
        assert!(!shard_progressing(6, 3));
        assert!(shard_progressing(u64::MAX, u64::MAX));
        // Six members on one shard: `fresh` exactly at the threshold (500
        // frames inactive), the rest one frame past it.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let frame = start + 5000;
        let filter = vec![0x4Au8; 64];
        let candidates_for = |fresh: u8| -> Vec<EvictionCandidate> {
            let (_tmp, store) = temp_store();
            let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
            let members: Vec<(u8, u64)> = (0..6u8)
                .map(|i| (0x10 + i, if i < fresh { frame - 500 } else { frame - 501 }))
                .collect();
            seed_members(&store, &shard, &filter, &members, frame);
            let mut reg = InMemoryProverRegistry::new();
            reg.refresh(store.as_ref()).unwrap();
            reg.find_eviction_candidates(frame, 500, &HashMap::new())
        };
        // fresh·3 == active·2: progressing, both stale members go.
        assert_eq!(candidates_for(4).len(), 2);
        // One fewer fresh: stalled, none goes.
        assert!(candidates_for(3).is_empty());
    }

    #[test]
    fn find_eviction_candidates_reads_reconfirmed_stalled_shard_as_progressing() {
        // Documented limitation until the signed-frame census governs: a
        // confirm credits `LastActiveFrameNumber` like a frame does, so a
        // stalled shard on which two thirds of the members confirmed within
        // the threshold reads as progressing and its other members are
        // selected.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let frame = start + 5000;
        let filter = vec![0x4Bu8; 64];
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let mut members = vec![(0x10u8, start + 100), (0x11, start + 100)];
        members.extend((0x12u8..0x16).map(|p| (p, frame - 10)));
        seed_members(&store, &shard, &filter, &members, frame);
        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        assert_eq!(
            selected_pairs(&reg.find_eviction_candidates(frame, 500, &HashMap::new())),
            vec![(vec![0x10u8; 32], filter.clone()), (vec![0x11u8; 32], filter.clone())]
        );
    }

    /// Signed-frame activation for the stall tests, a non-default value so
    /// the census can read `LastSignedFrameNumber`.
    const SIGNED_ACTIVATION: u64 = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 2000;

    /// Seed one prover per `(prover byte, last_active, last_signed)` member on
    /// `filter`, each allocation keyed `prover byte + 0x80` and current for
    /// `frame`. A zero `last_signed` leaves the field unrecorded.
    fn seed_signers(
        store: &RocksHypergraphStore,
        shard: &ShardKey,
        filter: &[u8],
        members: &[(u8, u64, u64)],
        frame: u64,
    ) {
        for &(p, last_active, last_signed) in members {
            seed_prover(store, shard, p, 0);
            let mut leaves = vec![
                type_hash_leaf("allocation:ProverAllocation"),
                field_leaf("allocation:ProverAllocation", "Prover", vec![p; 32]),
                field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
                field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.to_vec()),
                field_leaf(
                    "allocation:ProverAllocation",
                    "LastActiveFrameNumber",
                    last_active.to_be_bytes().to_vec(),
                ),
                field_leaf(
                    "allocation:ProverAllocation",
                    "Epoch",
                    quil_types::consensus::epoch_for_frame(frame).to_be_bytes().to_vec(),
                ),
            ];
            if last_signed > 0 {
                leaves.push(field_leaf(
                    "allocation:ProverAllocation",
                    "LastSignedFrameNumber",
                    last_signed.to_be_bytes().to_vec(),
                ));
            }
            store
                .save_vertex_underlying(
                    "vertex",
                    "adds",
                    shard,
                    &make_vertex_key(p + 0x80),
                    &build_sub_tree(leaves),
                )
                .unwrap();
        }
    }

    #[test]
    fn refresh_decodes_last_signed_frame_number() {
        let frame = SIGNED_ACTIVATION + 1000;
        let filter = vec![0x4Cu8; 64];
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        seed_signers(&store, &shard, &filter, &[(0x10, frame, frame - 5), (0x11, frame, 0)], frame);
        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        let last_signed = |p: u8| {
            reg.get_prover_info(&[p; 32]).unwrap().allocations[0].last_signed_frame_number
        };
        assert_eq!(last_signed(0x10), frame - 5);
        assert_eq!(last_signed(0x11), 0, "an unrecorded field decodes as 0");
    }

    #[test]
    fn allocation_fresh_matches_last_active_rule_until_signed_frames_govern() {
        // Until the signed-frame census governs, freshness is exactly the
        // `LastActiveFrameNumber` rule: credit later than the join confirm and
        // within the threshold after halt credit, `LastSignedFrameNumber`
        // ignored. With the default activation it never governs.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let (activation, threshold) = (SIGNED_ACTIVATION, 500u64);
        let last_active_rule = |alloc: &ProverAllocationInfo, frame: u64, halt: u64| {
            alloc.last_active_frame_number > alloc.join_confirm_frame_number
                && effective_inactivity(alloc, frame, halt).is_some_and(|i| i <= threshold)
        };
        let below = [start + 10, activation, activation + threshold - 1];
        let after = [activation + threshold, activation + threshold + 100];
        let mut checked = 0;
        let last_actives = [0, start - 50, start + 100, activation + 200, activation + threshold - 2];
        for last_active in last_actives {
            for last_signed in [0, activation + 5, activation + threshold - 2] {
                for join_confirm in [0, start + 100, activation + 100] {
                    for halt in [0, 300, u64::MAX] {
                        let alloc = ProverAllocationInfo {
                            status: ProverStatus::Active,
                            confirmation_filter: vec![0x4Du8; 64],
                            rejection_filter: Vec::new(),
                            join_frame_number: 0,
                            leave_frame_number: 0,
                            pause_frame_number: 0,
                            resume_frame_number: 0,
                            kick_frame_number: 0,
                            join_confirm_frame_number: join_confirm,
                            join_reject_frame_number: 0,
                            leave_confirm_frame_number: 0,
                            leave_reject_frame_number: 0,
                            last_active_frame_number: last_active,
                            last_signed_frame_number: last_signed,
                            epoch: 0,
                            ring: 0,
                            vertex_address: Vec::new(),
                        };
                        for frame in below.iter().chain(after.iter()).copied() {
                            let expected = last_active_rule(&alloc, frame, halt);
                            let default = quil_types::consensus::SIGNED_FRAME_ACTIVATION_FRAME;
                            assert_eq!(
                                allocation_fresh_at(&alloc, frame, halt, threshold, default),
                                expected,
                                "default activation: {alloc:?} at {frame}, halt {halt}"
                            );
                            if below.contains(&frame) {
                                assert_eq!(
                                    allocation_fresh_at(&alloc, frame, halt, threshold, activation),
                                    expected,
                                    "below the boundary: {alloc:?} at {frame}, halt {halt}"
                                );
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 5 * 3 * 3 * 3 * below.len());
        assert!(!signed_frame_census_governs(activation + threshold - 1, threshold, activation));
        assert!(signed_frame_census_governs(activation + threshold, threshold, activation));
        assert!(!signed_frame_census_governs(u64::MAX - 1, threshold, u64::MAX));
    }

    #[test]
    fn scan_eviction_candidates_counts_what_the_floor_and_stall_exemption_spare() {
        // Three shards with members past the threshold: a progressing one
        // whose two stale members are selected, a stalled one whose six are
        // spared, and one at the floor whose stale member is spared.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let (frame, threshold) = (start + 2000, 500);
        let (progressing, stalled, floor) = (vec![0x51u8; 64], vec![0x52u8; 64], vec![0x53u8; 64]);
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let mut members: Vec<(u8, u64, u64)> = vec![(0x10, start + 100, 0), (0x11, start + 100, 0)];
        members.extend((0x12u8..0x16).map(|p| (p, frame - 10, 0)));
        seed_signers(&store, &shard, &progressing, &members, frame);
        let members: Vec<(u8, u64, u64)> = (0x20u8..0x26).map(|p| (p, start + 100, 0)).collect();
        seed_signers(&store, &shard, &stalled, &members, frame);
        let mut members: Vec<(u8, u64, u64)> = vec![(0x30, start + 100, 0)];
        members.extend((0x31u8..0x34).map(|p| (p, frame - 10, 0)));
        seed_signers(&store, &shard, &floor, &members, frame);
        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        let scan = reg.scan_eviction_candidates(frame, threshold, &HashMap::new());
        assert_eq!(
            selected_pairs(&scan.candidates),
            vec![(vec![0x10u8; 32], progressing.clone()), (vec![0x11u8; 32], progressing)]
        );
        assert_eq!(scan.candidates, reg.find_eviction_candidates(frame, threshold, &HashMap::new()));
        assert_eq!((scan.shards, scan.active, scan.stale), (3, 16, 2));
        assert_eq!((scan.spared_floor, scan.spared_stalled), (1, 6));
        assert_eq!(scan.stalled, vec![(stalled, 6, 0)]);
    }

    #[test]
    fn get_provers_on_filters_returns_each_prover_once() {
        // 0xA1 holds two shards, 0xB2 one of them, 0xC3 the global
        // committee; 0xD4 is registered on no listed filter.
        let (shard_a, shard_b) = (vec![0x0Au8; 35], vec![0x0Bu8; 35]);
        let mut reg = InMemoryProverRegistry::new();
        for p in [0xA1u8, 0xB2, 0xC3, 0xD4] {
            reg.prover_cache.insert(
                vec![p; 32],
                ProverInfo {
                    public_key: vec![p; 897],
                    address: vec![p; 32],
                    status: ProverStatus::Active,
                    kick_frame_number: 0,
                    allocations: Vec::new(),
                    available_storage: 0,
                    seniority: 0,
                    delegate_address: Vec::new(),
                },
            );
        }
        reg.filter_cache.insert(shard_a.clone(), vec![vec![0xA1u8; 32]]);
        reg.filter_cache.insert(shard_b.clone(), vec![vec![0xA1u8; 32], vec![0xB2u8; 32]]);
        reg.filter_cache.insert(Vec::new(), vec![vec![0xC3u8; 32]]);
        let addresses = |filters: &[Vec<u8>]| {
            let mut out: Vec<Vec<u8>> =
                reg.get_provers_on_filters(filters).into_iter().map(|p| p.address.clone()).collect();
            out.sort();
            out
        };
        assert_eq!(
            addresses(&[Vec::new(), shard_a.clone(), shard_b.clone()]),
            vec![vec![0xA1u8; 32], vec![0xB2u8; 32], vec![0xC3u8; 32]]
        );
        assert_eq!(addresses(&[shard_a.clone(), shard_a]), vec![vec![0xA1u8; 32]]);
        assert!(addresses(&[vec![0x0Cu8; 35]]).is_empty());
    }

    #[test]
    fn find_eviction_candidates_ignores_reconfirm_credit_once_signed_frames_govern() {
        // A stalled shard whose members re-confirmed recently: four confirmed
        // within the threshold but signed no frame within it (two never
        // recorded one), two are long stale. Read by `LastActiveFrameNumber`
        // the re-confirms are fresh and the two stale members go; once the
        // signed-frame census governs, no member is fresh and none goes.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let (activation, threshold) = (SIGNED_ACTIVATION, 500);
        let frame = activation + threshold + 100;
        let filter = vec![0x4Cu8; 64];
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let members = [
            (0x10u8, start + 100, 0u64),
            (0x11, start + 100, 0),
            (0x12, frame - 10, 0),
            (0x13, frame - 10, 0),
            (0x14, frame - 10, activation + 10),
            (0x15, frame - 10, activation + 10),
        ];
        seed_signers(&store, &shard, &filter, &members, frame);
        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        assert_eq!(
            selected_pairs(&reg.find_eviction_candidates(frame, threshold, &HashMap::new())),
            vec![(vec![0x10u8; 32], filter.clone()), (vec![0x11u8; 32], filter.clone())],
            "the default activation keeps the LastActiveFrameNumber census"
        );
        assert!(reg
            .find_eviction_candidates_at(frame, threshold, &HashMap::new(), activation)
            .is_empty());
    }

    #[test]
    fn find_eviction_candidates_evicts_on_signing_shard_once_signed_frames_govern() {
        // Six of nine members signed a frame within the threshold (three
        // re-confirmed since): two thirds are fresh by signed frames, so the
        // shard progresses and its two stale members go. 0x18 re-confirmed
        // without signing: not fresh, but staleness still reads
        // `LastActiveFrameNumber`, so it is no candidate.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let (activation, threshold) = (SIGNED_ACTIVATION, 500);
        let frame = activation + threshold + 100;
        let filter = vec![0x4Du8; 64];
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let mut members = vec![
            (0x10u8, start + 100, 0u64),
            (0x11, activation + 10, activation + 10),
            (0x18, frame - 10, 0),
        ];
        members.extend((0x12u8..0x15).map(|p| (p, frame - 100, frame - 100)));
        members.extend((0x15u8..0x18).map(|p| (p, frame - 10, frame - 100)));
        seed_signers(&store, &shard, &filter, &members, frame);
        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        let stale = vec![(vec![0x10u8; 32], filter.clone()), (vec![0x11u8; 32], filter.clone())];
        assert_eq!(
            selected_pairs(
                &reg.find_eviction_candidates_at(frame, threshold, &HashMap::new(), activation)
            ),
            stale
        );
        assert_eq!(
            selected_pairs(&reg.find_eviction_candidates(frame, threshold, &HashMap::new())),
            stale
        );
    }

    #[test]
    fn find_eviction_candidates_switches_to_signed_frames_at_activation_plus_threshold() {
        // Four members re-confirmed shortly before the boundary and never
        // signed a recorded frame; two are long stale. One frame before
        // activation + threshold the census still reads re-confirms as
        // fresh; from that frame it reads signed frames only.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let (activation, threshold) = (SIGNED_ACTIVATION, 500);
        let boundary = activation + threshold;
        let filter = vec![0x4Eu8; 64];
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let mut members = vec![(0x10u8, start + 100, 0u64), (0x11, start + 100, 0)];
        members.extend((0x12u8..0x16).map(|p| (p, boundary - 20, 0)));
        seed_signers(&store, &shard, &filter, &members, boundary);
        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        let candidates_at = |frame: u64| {
            selected_pairs(&reg.find_eviction_candidates_at(
                frame,
                threshold,
                &HashMap::new(),
                activation,
            ))
        };
        assert_eq!(
            candidates_at(boundary - 1),
            vec![(vec![0x10u8; 32], filter.clone()), (vec![0x11u8; 32], filter.clone())]
        );
        assert!(candidates_at(boundary).is_empty());
    }

    #[test]
    fn committee_is_epoch_stable_changes_only_at_boundary() {
        // The app-shard committee (`get_active_provers`) must be CONSTANT within
        // an epoch and change ONLY across a boundary — the invariant that lets a
        // worker refresh its registry once per epoch without ever running a stale
        // committee, and that keeps every node's committee agreeing frame to
        // frame. It holds because `committee_eligible` is a pure function of
        // `effective_status`, which is epoch-quantized.
        let filter = vec![0x33u8; 64];
        let e = quil_types::consensus::EPOCH_LENGTH_FRAMES; // 720

        let a = [0xA0u8; 32]; // plain Active — in committee every frame
        let b = [0xB0u8; 32]; // deferred activation at the epoch-1 boundary
        let confirm_frame = 100u64; // epoch 0 → activation_epoch 1 (frame 720)

        let mk_prover = |pk: u8| {
            build_sub_tree(vec![
                type_hash_leaf("prover:Prover"),
                field_leaf("prover:Prover", "PublicKey", vec![pk; 57]),
                field_leaf("prover:Prover", "Status", vec![1u8]),
                field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
            ])
        };
        let mk_alloc = |prover: &[u8; 32], confirm: u64| {
            let mut leaves = vec![
                type_hash_leaf("allocation:ProverAllocation"),
                field_leaf("allocation:ProverAllocation", "Prover", prover.to_vec()),
                field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
                field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.clone()),
                // High epoch → never ExpiredEpoch across the test's frame range.
                field_leaf("allocation:ProverAllocation", "Epoch", 9999u64.to_be_bytes().to_vec()),
            ];
            if confirm > 0 {
                leaves.push(field_leaf(
                    "allocation:ProverAllocation",
                    "JoinConfirmFrameNumber",
                    confirm.to_be_bytes().to_vec(),
                ));
            }
            build_sub_tree(leaves)
        };

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xA0), &mk_prover(0xAA)).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xA1), &mk_alloc(&a, 0)).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xB0), &mk_prover(0xBB)).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xB1), &mk_alloc(&b, confirm_frame)).unwrap();

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();

        let committee = |frame: u64| -> Vec<Vec<u8>> {
            let mut v: Vec<Vec<u8>> = reg
                .get_active_provers(&filter, frame)
                .iter()
                .map(|p| p.address.clone())
                .collect();
            v.sort();
            v
        };

        // Epoch 0 [0, 720): B is deferred (Joining) → committee = {A}, constant.
        let e0_lo = committee(200);
        let e0_hi = committee(e - 1); // 719
        assert_eq!(e0_lo, e0_hi, "committee constant within epoch 0");
        assert_eq!(e0_lo, vec![a.to_vec()], "epoch 0: only A (B's activation deferred)");

        // Epoch 1 [720, 1440): B activated at the boundary → committee = {A, B},
        // constant across the whole epoch.
        let e1_lo = committee(e); // 720
        let e1_mid = committee(e + 300);
        let e1_hi = committee(2 * e - 1); // 1439
        assert_eq!(e1_lo, e1_mid, "committee constant within epoch 1 (lo vs mid)");
        assert_eq!(e1_lo, e1_hi, "committee constant within epoch 1 (lo vs hi)");
        assert_eq!(e1_lo.len(), 2, "epoch 1: both A and B active");

        // The set changes EXACTLY at the boundary (719 → 720), nowhere else.
        assert_ne!(committee(e - 1), committee(e), "committee changes across the boundary");
    }

    fn leaving_alloc(filter: Vec<u8>, epoch: u64, leave: u64, leave_confirm: u64) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status: ProverStatus::Leaving,
            confirmation_filter: filter,
            rejection_filter: Vec::new(),
            join_frame_number: 0,
            leave_frame_number: leave,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: leave_confirm,
            leave_reject_frame_number: 0,
            last_active_frame_number: 0,
            last_signed_frame_number: 0,
            epoch,
            ring: 0,
            vertex_address: Vec::new(),
        }
    }

    /// From the leaver currency frame a `Leaving` allocation is a committee
    /// member only if it was current when its leave was proposed; before the
    /// frame every unexpired leave is, as before. A leave that lands on an
    /// allocation which stopped re-confirming epochs ago must not seat it in
    /// committees for its notice.
    #[test]
    fn a_leaving_allocation_is_committee_eligible_only_if_current_when_it_left() {
        let e = quil_types::consensus::epoch_length_frames();
        let shard = vec![0x4Eu8; 64];
        // Leaves proposed in epoch 5, unconfirmed or confirmed in epoch 6: by
        // allocations re-confirmed for epoch 5 or 6, and by ones whose last
        // re-confirm was for epoch 2 or 4.
        let leave = 5 * e + 10;
        let confirm = 6 * e + 3;
        let current = [
            leaving_alloc(shard.clone(), 5, leave, 0),
            leaving_alloc(shard.clone(), 6, leave, 0),
            leaving_alloc(shard.clone(), 5, leave, confirm),
        ];
        let lapsed = [leaving_alloc(shard.clone(), 2, leave, 0), leaving_alloc(shard.clone(), 4, leave, confirm)];
        let notice = [leave, 6 * e, 7 * e - 1];
        for frame in notice {
            for alloc in current.iter().chain(&lapsed) {
                assert_eq!(alloc.effective_status(frame), EffectiveStatus::Leaving, "{alloc:?} at {frame}");
            }
        }
        // Unset (assumes QUIL_LEAVER_CURRENCY_FRAME is unset): every
        // unexpired leave keeps its seat.
        set_leaver_currency_frame_for_thread(None);
        for frame in notice {
            for alloc in current.iter().chain(&lapsed) {
                assert!(committee_eligible(alloc, frame, false), "unset: {alloc:?} at {frame}");
            }
        }
        // From the frame only current leavers; before it the old rule.
        let activation = 6 * e;
        set_leaver_currency_frame_for_thread(Some(activation));
        for frame in notice {
            for alloc in &current {
                assert!(committee_eligible(alloc, frame, false), "current: {alloc:?} at {frame}");
            }
            for alloc in &lapsed {
                assert_eq!(committee_eligible(alloc, frame, false), frame < activation, "lapsed: {alloc:?} at {frame}");
                assert_eq!(committee_eligible(alloc, frame, true), frame < activation,
                    "the empty-committee floor does not re-admit a lapsed leaver: {alloc:?} at {frame}");
            }
        }
        // The global filter carries no epoch obligation, and a leave without
        // a frame has no epoch to compare.
        assert!(committee_eligible(&leaving_alloc(Vec::new(), 0, leave, 0), activation, false));
        assert!(committee_eligible(&leaving_alloc(shard.clone(), 0, 0, 0), activation, false));
        set_leaver_currency_frame_for_thread(None);
    }

    /// Quorum membership (`get_active_provers`) and leader rotation
    /// (`get_ordered_provers`) drop a lapsed leaver together from the leaver
    /// currency frame, and keep a current one through its notice.
    #[test]
    fn quorum_and_leader_rotation_drop_a_lapsed_leaver_from_the_leaver_currency_frame() {
        let filter = vec![0x34u8; 64];
        let e = quil_types::consensus::epoch_length_frames();
        let leave = 5 * e + 10;
        let (active, current, lapsed) = ([0xA0u8; 32], [0xB0u8; 32], [0xC0u8; 32]);
        let mk_prover = |pk: u8| {
            build_sub_tree(vec![
                type_hash_leaf("prover:Prover"),
                field_leaf("prover:Prover", "PublicKey", vec![pk; 57]),
                field_leaf("prover:Prover", "Status", vec![1u8]),
                field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
            ])
        };
        let mk_alloc = |prover: &[u8; 32], status: u8, epoch: u64, leave: u64| {
            build_sub_tree(vec![
                type_hash_leaf("allocation:ProverAllocation"),
                field_leaf("allocation:ProverAllocation", "Prover", prover.to_vec()),
                field_leaf("allocation:ProverAllocation", "Status", vec![status]),
                field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.clone()),
                field_leaf("allocation:ProverAllocation", "Epoch", epoch.to_be_bytes().to_vec()),
                field_leaf("allocation:ProverAllocation", "LeaveFrameNumber", leave.to_be_bytes().to_vec()),
            ])
        };
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let rows = [(active, 1u8, 9999u64, 0u64), (current, 3, 5, leave), (lapsed, 3, 2, leave)];
        for (address, status, epoch, leave) in rows {
            let (key, alloc) = (address[0], mk_alloc(&address, status, epoch, leave));
            store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(key), &mk_prover(key | 0x0A)).unwrap();
            store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(key | 0x01), &alloc).unwrap();
        }
        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        let committee = |frame: u64| -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
            let mut quorum: Vec<Vec<u8>> =
                reg.get_active_provers(&filter, frame).iter().map(|p| p.address.clone()).collect();
            quorum.sort();
            let mut leaders = reg.get_ordered_provers(&[0x5Au8; 32], &filter, frame);
            leaders.sort();
            (quorum, leaders)
        };
        let all = vec![active.to_vec(), current.to_vec(), lapsed.to_vec()];
        let served = vec![active.to_vec(), current.to_vec()];
        // The first frame of the epoch after the leave, where the membership
        // pass seats successor committees.
        let boundary = 6 * e;
        set_leaver_currency_frame_for_thread(None);
        assert_eq!(committee(boundary), (all.clone(), all.clone()), "unset: the old rule");
        set_leaver_currency_frame_for_thread(Some(boundary));
        assert_eq!(committee(boundary - 1), (all.clone(), all), "not before the frame");
        assert_eq!(committee(boundary), (served.clone(), served.clone()), "a lapsed leaver is no member");
        assert_eq!(committee(7 * e - 1), (served.clone(), served), "a current leaver serves its notice");
        assert_eq!(committee(7 * e).0, vec![active.to_vec()], "an unconfirmed leave expires after it");
        set_leaver_currency_frame_for_thread(None);
    }

    /// Leaver currency is consensus and not scheduled on mainnet.
    #[test]
    fn leaver_currency_is_not_scheduled_by_default() {
        assert_eq!(MAINNET_LEAVER_CURRENCY_FRAME, None);
        assert_eq!(leaver_currency_frame_for(0, None), u64::MAX);
        assert_eq!(leaver_currency_frame_for(0, Some("7")), u64::MAX);
        assert_eq!(leaver_currency_frame_for(1, Some("7")), 7);
        assert_eq!(leaver_currency_frame_for(1, Some("soon")), u64::MAX);
        assert_eq!(leaver_currency_frame_for(1, None), u64::MAX);
    }

    #[test]
    fn prover_shard_summaries_group_by_filter() {
        let filter = vec![0xAAu8; 64];
        let prover_a = [0xA1u8; 32];
        let prover_b = [0xA2u8; 32];

        let mk_prover = |_addr: [u8; 32]| {
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
        reg.refresh(store.as_ref()).unwrap();

        let summaries = reg.get_prover_shard_summaries(0);
        assert_eq!(summaries.len(), 1);
        let sum = &summaries[0];
        assert_eq!(sum.filter, filter);
        assert_eq!(sum.status_counts.get(&ProverStatus::Active).copied().unwrap_or(0), 1);
        assert_eq!(sum.status_counts.get(&ProverStatus::Joining).copied().unwrap_or(0), 1);
    }

    #[test]
    fn lifecycle_views_remain_coherent_during_registry_replacement() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let owner = [0xF0; 32];
        let filter = vec![0xFC; 64];
        let make_state = |status: u8, seniority: u64| {
            let (_tmp, store) = temp_store();
            let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
            let prover = build_sub_tree(vec![
                type_hash_leaf("prover:Prover"),
                field_leaf("prover:Prover", "PublicKey", vec![0xFE; 57]),
                field_leaf("prover:Prover", "Status", vec![1]),
                field_leaf("prover:Prover", "Seniority", seniority.to_be_bytes().to_vec()),
            ]);
            let allocation = build_sub_tree(vec![
                type_hash_leaf("allocation:ProverAllocation"),
                field_leaf("allocation:ProverAllocation", "Prover", owner.to_vec()),
                field_leaf("allocation:ProverAllocation", "Status", vec![status]),
                field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.clone()),
            ]);
            store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xF0), &prover).unwrap();
            store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xF1), &allocation).unwrap();
            let mut registry = InMemoryProverRegistry::new();
            registry.refresh(store.as_ref()).unwrap();
            registry
        };
        let active = make_state(1, 1);
        let leaving = make_state(3, 2);
        let shared = SharedProverRegistry::new();
        let verify = |view: quil_types::consensus::ProverLifecycleView| {
            let owner_info = view.prover.unwrap();
            let members = &view.members[&filter];
            let summary = view.summaries.iter().find(|s| s.filter == filter).unwrap();
            match owner_info.seniority {
                1 => {
                    assert_eq!(members.active, vec![owner.to_vec()]);
                    assert!(members.leaving.is_empty());
                    assert_eq!(summary.status_counts.get(&ProverStatus::Active), Some(&1));
                }
                2 => {
                    assert_eq!(members.leaving, vec![owner.to_vec()]);
                    assert!(members.active.is_empty());
                    assert_eq!(summary.status_counts.get(&ProverStatus::Leaving), Some(&1));
                }
                _ => panic!("unexpected registry generation"),
            }
        };
        // Both sequential controls and the concurrent side use the same API.
        *shared.inner.write().unwrap() = active.clone();
        let retained = shared.get_lifecycle_view(&owner, 0).unwrap();
        *shared.inner.write().unwrap() = leaving.clone();
        verify(retained);
        verify(shared.get_lifecycle_view(&owner, 0).unwrap());
        let running = AtomicBool::new(true);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while running.load(Ordering::Relaxed) {
                    *shared.inner.write().unwrap() = active.clone();
                    std::thread::yield_now();
                    *shared.inner.write().unwrap() = leaving.clone();
                    std::thread::yield_now();
                }
            });
            let reader = scope.spawn(|| {
                for _ in 0..500 {
                    verify(shared.get_lifecycle_view(&owner, 0).unwrap());
                    std::thread::yield_now();
                }
            });
            let result = reader.join();
            running.store(false, Ordering::Relaxed);
            result.unwrap();
        });
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
        shared.refresh_from_store(store.as_ref()).unwrap();

        let trait_obj: &dyn ProverRegistryTrait = &shared;

        let info = trait_obj.get_prover_info(&prover_addr).unwrap().unwrap();
        assert_eq!(info.seniority, 13);
        assert_eq!(info.available_storage, 7);

        assert_eq!(trait_obj.get_prover_count(&filter).unwrap(), 1);
        assert_eq!(trait_obj.get_provers(&filter).unwrap().len(), 1);
        assert_eq!(trait_obj.get_active_provers(&filter, 0).unwrap().len(), 1);
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

        // Summaries round-trip through the trait.
        let sums = trait_obj.get_prover_shard_summaries(0).unwrap();
        assert_eq!(sums.len(), 1);
    }

    #[test]
    fn evict_inactive_provers_kicks_candidates() {
        // Setup: one Active prover with one Active allocation whose
        // LastActiveFrameNumber is 100, past the threshold. Run the mutating
        // helper with both vertices in the CRDT: it returns the allocation,
        // kicks the allocation vertex (Status=4, KickFrameNumber=frame) and
        // leaves the prover vertex untouched.
        use std::sync::Arc;
        use quil_hypergraph::HypergraphCrdt;
        use quil_hypergraph::testing::MemStore;
        use quil_types::crypto::NoopInclusionProver;

        let prover_addr = [0x55u8; 32];
        let alloc_addr = [0xA5u8; 32];
        let filter = vec![0x33u8; 64];

        let prover_bytes = build_sub_tree(vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", vec![0xCD; 57]),
            field_leaf("prover:Prover", "Status", vec![1u8]),
            field_leaf("prover:Prover", "AvailableStorage", 0u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "Seniority", 42u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
        ]);
        // Frame past the inactivity start; last_active (100) predates it,
        // so 900 inactive frames > 500 threshold → eviction candidate.
        let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900;
        let alloc_bytes = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", prover_addr.to_vec()),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.clone()),
            field_leaf(
                "allocation:ProverAllocation",
                "LastActiveFrameNumber",
                100u64.to_be_bytes().to_vec(),
            ),
            // Current epoch → effective_status == Active (else ExpiredEpoch → exempt).
            field_leaf(
                "allocation:ProverAllocation",
                "Epoch",
                quil_types::consensus::epoch_for_frame(frame).to_be_bytes().to_vec(),
            ),
        ]);

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };

        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x55), &prover_bytes).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xA5), &alloc_bytes).unwrap();
        // The target shard otherwise holds one active prover, below quorum;
        // seed a floor of fillers so the target is evictable.
        seed_shard_floor(&store, &shard, &filter, frame, 0xE0);

        let shared = SharedProverRegistry::new();
        shared.refresh_from_store(store.as_ref()).unwrap();

        // Build a HypergraphState over an in-memory CRDT and seed both
        // vertices via state.set so evict can read+write them.
        let crdt = Arc::new(HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let state = crate::hypergraph_state::HypergraphState::new(crdt);
        let va_disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        state.set(&crate::domains::GLOBAL, &prover_addr, &va_disc, 500, prover_bytes).unwrap();
        state.set(&crate::domains::GLOBAL, &alloc_addr, &va_disc, 500, alloc_bytes).unwrap();

        let halts: HashMap<Vec<u8>, u64> = HashMap::new();
        let evicted = shared
            .evict_inactive_provers(frame, 500, &halts, &state, None)
            .unwrap();
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].prover_address, prover_addr.to_vec());
        assert_eq!(evicted[0].confirmation_filter, filter);
        assert_eq!(evicted[0].vertex_address, alloc_addr.to_vec());

        // The allocation is kicked: Status=4, KickFrameNumber=frame.
        let blob = state.get(&crate::domains::GLOBAL, &alloc_addr, &va_disc).unwrap().unwrap();
        let tree = rebuild_vertex_tree_from_blob(&blob);
        let cls = "allocation:ProverAllocation";
        assert_eq!(crate::global_schema::read_field(&tree, cls, "Status").unwrap(), vec![4u8]);
        assert_eq!(
            crate::global_schema::read_field(&tree, cls, "KickFrameNumber").unwrap(),
            frame.to_be_bytes().to_vec()
        );

        // The prover vertex keeps its status, seniority and zero kick frame.
        let blob = state.get(&crate::domains::GLOBAL, &prover_addr, &va_disc).unwrap().unwrap();
        let tree = rebuild_vertex_tree_from_blob(&blob);
        assert_eq!(crate::global_schema::read_field(&tree, "prover:Prover", "Status").unwrap(), vec![1u8]);
        assert_eq!(
            crate::global_schema::read_field(&tree, "prover:Prover", "Seniority").unwrap(),
            42u64.to_be_bytes().to_vec()
        );
        assert_eq!(
            crate::global_schema::read_field(&tree, "prover:Prover", "KickFrameNumber").unwrap(),
            0u64.to_be_bytes().to_vec()
        );
    }

    #[test]
    fn evict_kicks_only_the_stale_allocation() {
        // A prover stale on shard A but active on shard B loses only its
        // shard-A allocation. Its shard-B allocation, its status and its
        // seniority stay, and it remains in the registry.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let frame = start + 900;
        let filter_a = vec![0x31u8; 64];
        let filter_b = vec![0x32u8; 64];
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        seed_prover(&store, &shard, 0x57, 77);
        seed_allocation(&store, &shard, 0x57, 0xA7, &filter_a, 100, frame);
        seed_allocation(&store, &shard, 0x57, 0xB7, &filter_b, frame, frame);
        seed_shard_floor(&store, &shard, &filter_a, frame, 0xE0);
        seed_shard_floor(&store, &shard, &filter_b, frame, 0xF0);

        let shared = SharedProverRegistry::new();
        shared.refresh_from_store(store.as_ref()).unwrap();
        let state = empty_state();
        let halts: HashMap<Vec<u8>, u64> = HashMap::new();
        let evicted = shared
            .evict_inactive_provers(frame, 500, &halts, &state, Some(store.as_ref()))
            .unwrap();
        assert_eq!(evicted.len(), 1, "only the stale allocation is evicted");
        assert_eq!(evicted[0].prover_address, vec![0x57u8; 32]);
        assert_eq!(evicted[0].confirmation_filter, filter_a);

        let cls = "allocation:ProverAllocation";
        let stale = read_global_vertex(&state, &store, &shard, 0xA7);
        assert_eq!(crate::global_schema::read_field(&stale, cls, "Status").unwrap(), vec![4u8]);
        let healthy = read_global_vertex(&state, &store, &shard, 0xB7);
        assert_eq!(crate::global_schema::read_field(&healthy, cls, "Status").unwrap(), vec![1u8]);
        let prover = read_global_vertex(&state, &store, &shard, 0x57);
        assert_eq!(crate::global_schema::read_field(&prover, "prover:Prover", "Status").unwrap(), vec![1u8]);
        assert_eq!(
            crate::global_schema::read_field(&prover, "prover:Prover", "Seniority").unwrap(),
            77u64.to_be_bytes().to_vec()
        );
        assert_eq!(
            crate::global_schema::read_field(&prover, "prover:Prover", "KickFrameNumber").unwrap(),
            0u64.to_be_bytes().to_vec()
        );

        // The in-memory registry reflects the same: prover kept, shard-A
        // allocation no longer active, shard-B allocation untouched.
        let info = shared.get_prover_info(&[0x57u8; 32]).unwrap().expect("prover kept");
        assert_eq!(info.status, ProverStatus::Active);
        assert_eq!(info.seniority, 77);
        let on = |filter: &[u8]| {
            info.allocations
                .iter()
                .find(|a| a.confirmation_filter == filter)
                .map(|a| a.status)
        };
        assert_eq!(on(filter_a.as_slice()), Some(ProverStatus::Rejected));
        assert_eq!(on(filter_b.as_slice()), Some(ProverStatus::Active));
        assert!(shared.find_eviction_candidates(frame, 500, &halts).is_empty());
    }

    #[test]
    fn eviction_keeps_shard_floor_most_inactive_first() {
        // Six members, three stale. Floor 4 → only two go: the two most
        // inactive (0x11, 0x12), not the lowest-addressed stale one (0x10).
        // The stall exemption leaves at most a third of a shard stale, which
        // a shard above a floor of 4 can always spare, so the order is
        // tested on the floor directly.
        let filter = vec![0x46u8; 64];
        let candidate = |p: u8, effective_inactive: u64| EvictionCandidate {
            prover_address: vec![p; 32],
            confirmation_filter: filter.clone(),
            vertex_address: vec![p + 0x80; 32],
            effective_inactive,
        };
        let stale = vec![candidate(0x10, 3000), candidate(0x11, 4900), candidate(0x12, 4500)];
        let census: HashMap<Vec<u8>, u64> = [(filter.clone(), 6)].into_iter().collect();
        let picked: Vec<Vec<u8>> = limit_evictions_to_shard_floor(stale.clone(), &census)
            .into_iter()
            .map(|c| c.prover_address)
            .collect();
        assert_eq!(picked, vec![vec![0x11u8; 32], vec![0x12u8; 32]]);
        // A shard at the floor has nothing to spare.
        let at_floor: HashMap<Vec<u8>, u64> = [(filter.clone(), 4)].into_iter().collect();
        assert!(limit_evictions_to_shard_floor(stale, &at_floor).is_empty());
    }

    #[test]
    fn evict_cap_counts_allocations() {
        // 20 provers, each stale on two shards, and 40 fresh members on both,
        // so each shard is progressing → 40 stale allocations, all above the
        // floor. The per-frame cap of 25 counts allocations, not provers.
        let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900;
        let filter_a = vec![0x61u8; 64];
        let filter_b = vec![0x62u8; 64];
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        for i in 0u8..20 {
            seed_prover(&store, &shard, i, 0);
            seed_allocation(&store, &shard, i, 0x20 + i, &filter_a, 100, frame);
            seed_allocation(&store, &shard, i, 0xA0 + i, &filter_b, 100, frame);
        }
        let filters = [filter_a.as_slice(), filter_b.as_slice()];
        seed_fresh_members(&store, &shard, &filters, frame, 40, 0x5A);

        let shared = SharedProverRegistry::new();
        shared.refresh_from_store(store.as_ref()).unwrap();
        let halts: HashMap<Vec<u8>, u64> = HashMap::new();
        assert_eq!(shared.find_eviction_candidates(frame, 500, &halts).len(), 40);

        let state = empty_state();
        let evicted = shared
            .evict_inactive_provers(frame, 500, &halts, &state, Some(store.as_ref()))
            .unwrap();
        assert_eq!(evicted.len(), 25, "the cap counts allocations");
        // Sorted (prover, filter): provers 0..12 lose both allocations, prover
        // 12 loses only its shard-A allocation.
        let provers: std::collections::BTreeSet<Vec<u8>> =
            evicted.iter().map(|c| c.prover_address.clone()).collect();
        assert_eq!(provers.len(), 13);
        assert_eq!(evicted[24].prover_address, vec![12u8; 32]);
        assert_eq!(evicted[24].confirmation_filter, filter_a);
        assert_eq!(shared.find_eviction_candidates(frame, 500, &halts).len(), 15);
    }

    #[test]
    fn evict_falls_back_to_flat_store_when_crdt_misses() {
        // Mirrors the production seam that caused "evictions never happen":
        // hypergraph SYNC writes prover/alloc vertices straight into the
        // flat per-vertex keyspace (what `refresh_from_store` reads), but
        // the running CRDT's in-memory tree never receives them.
        // `find_eviction_candidates` (registry, from the flat store) selects
        // the prover, yet `state.get` (CRDT) misses it. Without the
        // flat-store fallback, nothing is kicked; WITH it (store = Some),
        // the kick succeeds. This is the exact wiring that broke in the
        // field and had no regression test.
        use std::sync::Arc;
        use quil_hypergraph::HypergraphCrdt;
        use quil_hypergraph::testing::MemStore;
        use quil_types::crypto::NoopInclusionProver;

        let prover_addr = [0x55u8; 32];
        let filter = vec![0x33u8; 64];
        let prover_bytes = build_sub_tree(vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", vec![0xCD; 57]),
            field_leaf("prover:Prover", "Status", vec![1u8]),
            field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
        ]);
        let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900;
        let alloc_bytes = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", prover_addr.to_vec()),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.clone()),
            field_leaf("allocation:ProverAllocation", "LastActiveFrameNumber", 100u64.to_be_bytes().to_vec()),
            // Current epoch → effective_status == Active (else ExpiredEpoch → exempt).
            field_leaf(
                "allocation:ProverAllocation",
                "Epoch",
                quil_types::consensus::epoch_for_frame(frame).to_be_bytes().to_vec(),
            ),
        ]);

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x55), &prover_bytes).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0xA5), &alloc_bytes).unwrap();
        // Seed a floor of fillers on the (flat-store) shard so the target is
        // evictable; fillers are fresh-active, so they're never candidates
        // and the flat-store-vs-CRDT seam under test is unaffected.
        seed_shard_floor(&store, &shard, &filter, frame, 0xE0);

        let shared = SharedProverRegistry::new();
        shared.refresh_from_store(store.as_ref()).unwrap();

        // The CRDT is EMPTY — the synced vertices are absent (the seam).
        let crdt = Arc::new(HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let state = crate::hypergraph_state::HypergraphState::new(crdt);
        let halts: HashMap<Vec<u8>, u64> = HashMap::new();

        // store = None → CRDT miss → nothing kicked (reproduces the bug).
        let none: Option<&dyn HypergraphStore> = None;
        let evicted_none = shared
            .evict_inactive_provers(frame, 500, &halts, &state, none)
            .unwrap();
        assert!(
            evicted_none.is_empty(),
            "without the flat-store fallback a CRDT miss yields no eviction (the bug)"
        );

        // store = Some → fallback reads from the flat keyspace → kicked.
        let evicted = shared
            .evict_inactive_provers(frame, 500, &halts, &state, Some(store.as_ref()))
            .unwrap();
        assert_eq!(
            evicted.iter().map(|c| c.prover_address.clone()).collect::<Vec<_>>(),
            vec![prover_addr.to_vec()],
            "flat-store fallback must kick the candidate the CRDT couldn't load"
        );
        // And the allocation kick landed in the CRDT (written via
        // state.set): Status=4. The prover vertex is not written.
        let va_disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        let blob = state.get(&crate::domains::GLOBAL, &[0xA5u8; 32], &va_disc).unwrap().unwrap();
        let tree = rebuild_vertex_tree_from_blob(&blob);
        assert_eq!(
            crate::global_schema::read_field(&tree, "allocation:ProverAllocation", "Status").unwrap(),
            vec![4u8]
        );
        assert!(state.get(&crate::domains::GLOBAL, &prover_addr, &va_disc).unwrap().is_none());
    }

    #[test]
    fn find_eviction_candidates_exempts_expired_epoch() {
        // A raw-Active allocation whose recorded `Epoch` is STALE (missed its
        // per-epoch re-confirm) reads as `ExpiredEpoch` via `effective_status`.
        // It's already excluded from the committee / shard summaries, so it must
        // NOT be evicted for inactivity — this is the "up for eviction but no
        // active shards" fix. Identical to the evictable case except the epoch
        // is old; would evict under the prior raw-`alloc.status` gate.
        let prover = [0x71u8; 32];
        let filter = vec![0x33u8; 64];
        let mk_prover = build_sub_tree(vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", vec![0xCD; 57]),
            field_leaf("prover:Prover", "Status", vec![1u8]),
            field_leaf("prover:Prover", "AvailableStorage", 0u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
            field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
        ]);
        let alloc = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", prover.to_vec()),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", filter.clone()),
            field_leaf("allocation:ProverAllocation", "LastActiveFrameNumber", 100u64.to_be_bytes().to_vec()),
            // STALE epoch (0) → effective_status == ExpiredEpoch at the test frame.
            field_leaf("allocation:ProverAllocation", "Epoch", 0u64.to_be_bytes().to_vec()),
        ]);
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x71), &mk_prover).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x72), &alloc).unwrap();

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();

        let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900;
        let halts: HashMap<Vec<u8>, u64> = HashMap::new();
        let evict = reg.find_eviction_candidates(frame, 500, &halts);
        assert!(
            evict.is_empty(),
            "epoch-expired prover must not be evicted for inactivity"
        );
    }

    #[test]
    fn find_eviction_candidates_selects_unknown_stub() {
        // After a prover vertex is kicked (Status byte 4 → decode_prover
        // returns None), refresh synthesizes an `Unknown` stub from the
        // prover's still-active allocations. The gate must select that stub
        // so the lingering active allocations get cleaned — otherwise they
        // inflate shard coverage forever (the live "31653 active / unknown
        // provers" symptom).
        let prover_addr = [0x66u8; 32];
        // No decodable prover vertex (byte-4 kicked → None); only an active,
        // long-inactive allocation. refresh → Unknown stub carrying it.
        let alloc_bytes = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", prover_addr.to_vec()),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", vec![0x77u8; 64]),
            field_leaf("allocation:ProverAllocation", "LastActiveFrameNumber", 100u64.to_be_bytes().to_vec()),
            // Current epoch so the frame-aware gate reads it as effectively
            // Active (the orphan's allocation is still live, just its parent
            // prover vertex was kicked).
            field_leaf(
                "allocation:ProverAllocation",
                "Epoch",
                quil_types::consensus::epoch_for_frame(
                    quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900,
                ).to_be_bytes().to_vec(),
            ),
        ]);
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x66), &alloc_bytes).unwrap();
        // The stub's shard (filter 0x77) otherwise holds a single active
        // allocation, below quorum — seed a floor of fillers so the
        // under-provisioned exemption doesn't mask the orphan-stub selection
        // under test.
        seed_shard_floor(
            &store,
            &shard,
            &vec![0x77u8; 64],
            quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900,
            0xE0,
        );

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();
        // Confirm it's an Unknown stub.
        let info = reg.get_prover_info(&prover_addr).expect("stub synthesized");
        assert_eq!(info.status, ProverStatus::Unknown);

        let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900;
        let halts: HashMap<Vec<u8>, u64> = HashMap::new();
        let candidates = reg.find_eviction_candidates(frame, 500, &halts);
        assert!(
            candidates.iter().any(|a| a.prover_address == prover_addr.to_vec()),
            "Unknown stub with an active, inactive allocation must be an eviction candidate"
        );
    }

    #[test]
    fn evict_caps_candidates_per_frame() {
        // A large orphan/eviction backlog must drain gradually, not all at
        // once (evicting 733 in one materialize wedged the worker). Verify
        // at most EVICTION_MAX_PER_FRAME (25) are processed per call.
        use std::sync::Arc;
        use quil_hypergraph::HypergraphCrdt;
        use quil_hypergraph::testing::MemStore;
        use quil_types::crypto::NoopInclusionProver;

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        // 40 distinct active, long-inactive provers all on ONE well-covered
        // shard → 40 candidates (the shard is far above the consensus-quorum
        // exemption, so none is spared for under-provisioning). Shared filter
        // (was per-prover) so the shard clears MIN_SHARD_CONSENSUS_PROVERS; the
        // test only asserts the per-frame cap, not per-shard summaries.
        let cur_epoch = quil_types::consensus::epoch_for_frame(
            quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900,
        );
        let shared_filter = vec![0x99u8; 64];
        for i in 0u8..40 {
            let prover_addr = [i; 32];
            let prover_bytes = build_sub_tree(vec![
                type_hash_leaf("prover:Prover"),
                field_leaf("prover:Prover", "PublicKey", vec![0xCD; 57]),
                field_leaf("prover:Prover", "Status", vec![1u8]),
                field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
            ]);
            let alloc_bytes = build_sub_tree(vec![
                type_hash_leaf("allocation:ProverAllocation"),
                field_leaf("allocation:ProverAllocation", "Prover", prover_addr.to_vec()),
                field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
                field_leaf("allocation:ProverAllocation", "ConfirmationFilter", shared_filter.clone()),
                field_leaf("allocation:ProverAllocation", "LastActiveFrameNumber", 100u64.to_be_bytes().to_vec()),
                // Current epoch → effective_status == Active (not ExpiredEpoch).
                field_leaf("allocation:ProverAllocation", "Epoch", cur_epoch.to_be_bytes().to_vec()),
            ]);
            store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(i), &prover_bytes).unwrap();
            store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(i.wrapping_add(128)), &alloc_bytes).unwrap();
        }
        // 80 fresh members keep the shard progressing (two thirds fresh).
        seed_fresh_members(
            &store,
            &shard,
            &[shared_filter.as_slice()],
            quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900,
            80,
            0x5A,
        );

        let shared = SharedProverRegistry::new();
        shared.refresh_from_store(store.as_ref()).unwrap();
        let crdt = Arc::new(HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let state = crate::hypergraph_state::HypergraphState::new(crdt);
        let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 900;
        let halts: HashMap<Vec<u8>, u64> = HashMap::new();
        let evicted = shared
            .evict_inactive_provers(frame, 500, &halts, &state, Some(store.as_ref()))
            .unwrap();
        assert_eq!(evicted.len(), 25, "must cap evictions at EVICTION_MAX_PER_FRAME per call");
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
        reg.refresh(store.as_ref()).unwrap();

        let got = reg.get_prover_info(&prover_addr).expect("orphan synthesized");
        assert!(got.public_key.is_empty());
        assert_eq!(got.allocations.len(), 1);
        assert_eq!(got.allocations[0].status, ProverStatus::Joining);
    }

    #[test]
    fn a_retired_provers_live_allocation_keeps_its_key() {
        // Before provers' status was derived from all allocations, rejecting
        // one join marked a prover with an active session allocation as left.
        // The row synthesized for that allocation had an empty key, which
        // halted the global chain. The row stays a stub (Unknown), but it must
        // carry the key the prover vertex still records.
        let prover_addr = [0x45u8; 32];
        let key = vec![0xE1u8; 897];
        let prover_bytes = build_sub_tree(vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", key.clone()),
            field_leaf("prover:Prover", "Status", vec![4u8]),
        ]);
        let alloc_bytes = build_sub_tree(vec![
            type_hash_leaf("allocation:ProverAllocation"),
            field_leaf("allocation:ProverAllocation", "Prover", prover_addr.to_vec()),
            field_leaf("allocation:ProverAllocation", "Status", vec![1u8]),
            field_leaf("allocation:ProverAllocation", "ConfirmationFilter", vec![0xDE; 64]),
        ]);
        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x45), &prover_bytes).unwrap();
        store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x46), &alloc_bytes).unwrap();

        let mut reg = InMemoryProverRegistry::new();
        reg.refresh(store.as_ref()).unwrap();

        let got = reg.get_prover_info(&prover_addr).expect("row for the live allocation");
        assert_eq!(got.public_key, key);
        assert_eq!(got.status, ProverStatus::Unknown);
        assert_eq!(got.allocations.len(), 1);
    }

    /// End-to-end lifecycle invariant: 100 provers, each in one of
    /// ten allocation scenarios, written to the per-vertex store,
    /// refreshed, then probed via `get_prover_shard_summaries`. The
    /// live-status mapping must return exactly the counts implied by
    /// each scenario.
    ///
    /// Scenarios (10 provers each):
    /// 1. Join only → Joining
    /// 2. Join + Confirm → Active
    /// 3. Join + Reject → excluded
    /// 4. Join + Expire (grace elapsed) → excluded
    /// 5. Join + Confirm + Leave → Leaving
    /// 6. Join + Confirm + Leave + ConfirmLeave (Kicked) → excluded
    /// 7. Join + Confirm + Leave + RejectLeave → Active again
    /// 8. Join + Confirm + Leave + ExpireLeave → Active (leave failed)
    /// 9. Join + Confirm + Pause → Paused
    /// 10. Join + Confirm + Pause + Resume → Active
    ///
    /// Expected counts at frame=1000 with grace=720:
    /// Active = 40 (scenarios 2, 7, 8, 10)
    /// Joining = 10 (scenario 1)
    /// Leaving = 10 (scenario 5)
    /// Paused = 10 (scenario 9)
    /// excluded = 30 (scenarios 3, 4, 6)
    #[test]
    fn lifecycle_scenarios_produce_correct_live_summary() {
        use crate::global_intrinsic::materialize::allocation_address;

        // Epoch-aligned lifecycle (EPOCH_LENGTH_FRAMES = 720). To exhibit
        // epoch-based expiry of a join/leave we need current_epoch >=
        // proposed_epoch + 2, so the harness runs at epoch 2.
        let filter = vec![0x55u8; 32];
        let current_frame: u64 = 2000;            // epoch 2 (C)
        let recent_frame: u64 = current_frame - 50; // 1950, epoch 2 — current-epoch events
        let prior_frame: u64 = 1000;              // epoch 1 — confirmed last epoch → active now
        let stale_frame: u64 = 100;               // epoch 0 — proposed long ago, never settled

        #[derive(Clone, Copy)]
        enum Scenario {
            JustJoin,
            ConfirmedActive,
            JoinRejected,
            JoinExpired,
            Leaving,
            LeaveConfirmedKicked,
            LeaveRejectedReturnsActive,
            LeaveExpiredReturnsActive,
            Paused,
            PausedThenResumed,
        }

        let scenarios: [Scenario; 10] = [
            Scenario::JustJoin,
            Scenario::ConfirmedActive,
            Scenario::JoinRejected,
            Scenario::JoinExpired,
            Scenario::Leaving,
            Scenario::LeaveConfirmedKicked,
            Scenario::LeaveRejectedReturnsActive,
            Scenario::LeaveExpiredReturnsActive,
            Scenario::Paused,
            Scenario::PausedThenResumed,
        ];

        let (_tmp, store) = temp_store();
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };

        // 100 deterministic prover pubkeys + addresses; 10 provers
        // per scenario, distributed evenly.
        for prover_idx in 0u8..100 {
            let scenario = scenarios[(prover_idx % 10) as usize];
            // Pubkey: deterministic 57-byte blob seeded by idx.
            let mut pubkey = vec![0u8; 57];
            pubkey[0] = prover_idx;
            pubkey[1] = prover_idx.wrapping_add(0x10);
            pubkey[2] = prover_idx.wrapping_add(0x20);
            // Prover address: 32 bytes derived (hash would be ideal,
            // but the registry only uses the address as a lookup key
            // — any unique 32 bytes works for the test).
            let mut prover_addr = vec![0u8; 32];
            prover_addr[0] = prover_idx;
            prover_addr[31] = 0xAA;
            // Allocation vertex address: deterministic per
            // (pubkey, filter). Used as the last 32 bytes of the
            // allocation's vertex key so each prover has a distinct
            // allocation row.
            let alloc_addr_32 = allocation_address(&pubkey, &filter).unwrap();

            // Determine allocation fields per scenario.
            let (
                status_byte,
                join_frame,
                leave_frame,
                join_confirm_frame,
                leave_confirm_frame,
                pause_frame,
                resume_frame,
                join_reject_frame,
                leave_reject_frame,
            ): (u8, u64, u64, u64, u64, u64, u64, u64, u64);
            // On-disk status bytes are RDF-encoded (0-indexed):
            //   0=Joining 1=Active 2=Paused 3=Leaving 4=Rejected 5=Kicked
            // (see `map_allocation_status` / `map_prover_status`).
            match scenario {
                Scenario::JustJoin => {
                    status_byte = 0; // Joining
                    join_frame = recent_frame;
                    leave_frame = 0;
                    join_confirm_frame = 0;
                    leave_confirm_frame = 0;
                    pause_frame = 0;
                    resume_frame = 0;
                    join_reject_frame = 0;
                    leave_reject_frame = 0;
                }
                Scenario::ConfirmedActive => {
                    status_byte = 1; // Active
                    // Confirmed in the PRIOR epoch → activated by the current
                    // epoch (deferred activation gate satisfied).
                    join_frame = prior_frame - 100;
                    leave_frame = 0;
                    join_confirm_frame = prior_frame;
                    leave_confirm_frame = 0;
                    pause_frame = 0;
                    resume_frame = 0;
                    join_reject_frame = 0;
                    leave_reject_frame = 0;
                }
                Scenario::JoinRejected => {
                    status_byte = 4; // Rejected
                    join_frame = recent_frame - 50;
                    leave_frame = 0;
                    join_confirm_frame = 0;
                    leave_confirm_frame = 0;
                    pause_frame = 0;
                    resume_frame = 0;
                    join_reject_frame = recent_frame;
                    leave_reject_frame = 0;
                }
                Scenario::JoinExpired => {
                    // Status still Joining (no on-chain transition),
                    // but join_frame is old → effective_status returns
                    // ExpiredJoining at frame=1000.
                    status_byte = 0; // Joining
                    join_frame = stale_frame;
                    leave_frame = 0;
                    join_confirm_frame = 0;
                    leave_confirm_frame = 0;
                    pause_frame = 0;
                    resume_frame = 0;
                    join_reject_frame = 0;
                    leave_reject_frame = 0;
                }
                Scenario::Leaving => {
                    status_byte = 3; // Leaving
                    join_frame = recent_frame - 200;
                    leave_frame = recent_frame;
                    join_confirm_frame = recent_frame - 150;
                    leave_confirm_frame = 0;
                    pause_frame = 0;
                    resume_frame = 0;
                    join_reject_frame = 0;
                    leave_reject_frame = 0;
                }
                Scenario::LeaveConfirmedKicked => {
                    status_byte = 5; // Kicked (= leave-confirmed)
                    join_frame = recent_frame - 300;
                    leave_frame = recent_frame - 100;
                    join_confirm_frame = recent_frame - 250;
                    leave_confirm_frame = recent_frame;
                    pause_frame = 0;
                    resume_frame = 0;
                    join_reject_frame = 0;
                    leave_reject_frame = 0;
                }
                Scenario::LeaveRejectedReturnsActive => {
                    status_byte = 1; // back to Active
                    // Confirmed in the prior epoch (activated), then proposed a
                    // leave that was rejected → stays Active.
                    join_frame = prior_frame - 200;
                    leave_frame = recent_frame - 100;
                    join_confirm_frame = prior_frame;
                    leave_confirm_frame = 0;
                    pause_frame = 0;
                    resume_frame = 0;
                    join_reject_frame = 0;
                    leave_reject_frame = recent_frame;
                }
                Scenario::LeaveExpiredReturnsActive => {
                    // Status still Leaving (no on-chain confirm/reject),
                    // but leave_frame is old → effective_status returns
                    // ExpiredLeaving → live_allocation_status maps to
                    // None (excluded). The prover socially left when
                    // they submitted the Leave; the absence of a
                    // confirm doesn't put them back into active duty.
                    status_byte = 3; // Leaving
                    join_frame = recent_frame - 800;
                    leave_frame = stale_frame;
                    join_confirm_frame = recent_frame - 750;
                    leave_confirm_frame = 0;
                    pause_frame = 0;
                    resume_frame = 0;
                    join_reject_frame = 0;
                    leave_reject_frame = 0;
                }
                Scenario::Paused => {
                    status_byte = 2; // Paused
                    join_frame = recent_frame - 300;
                    leave_frame = 0;
                    join_confirm_frame = recent_frame - 250;
                    leave_confirm_frame = 0;
                    pause_frame = recent_frame;
                    resume_frame = 0;
                    join_reject_frame = 0;
                    leave_reject_frame = 0;
                }
                Scenario::PausedThenResumed => {
                    status_byte = 1; // back to Active
                    join_frame = prior_frame - 300;
                    leave_frame = 0;
                    join_confirm_frame = prior_frame;
                    leave_confirm_frame = 0;
                    pause_frame = recent_frame - 100;
                    resume_frame = recent_frame;
                    join_reject_frame = 0;
                    leave_reject_frame = 0;
                }
            }

            // Build prover vertex sub-tree. The prover's overall
            // status is the per-allocation status' parent; for this
            // test (one allocation per prover, filter-level counts)
            // we just use Active (byte 1) so every prover vertex
            // decodes cleanly. The allocation's own status drives
            // the per-filter count.
            let prover_leaves = vec![
                type_hash_leaf("prover:Prover"),
                field_leaf("prover:Prover", "PublicKey", pubkey.clone()),
                field_leaf("prover:Prover", "Status", vec![1u8]),
                field_leaf("prover:Prover", "AvailableStorage", 0u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "Seniority", 1u64.to_be_bytes().to_vec()),
                field_leaf("prover:Prover", "KickFrameNumber", 0u64.to_be_bytes().to_vec()),
            ];
            let prover_bytes = build_sub_tree(prover_leaves);

            // Build allocation vertex sub-tree.
            let alloc_leaves = vec![
                type_hash_leaf("allocation:ProverAllocation"),
                field_leaf("allocation:ProverAllocation", "Prover", prover_addr.clone()),
                field_leaf("allocation:ProverAllocation", "Status", vec![status_byte]),
                // Confirmed for the current storage epoch — this test exercises
                // join/leave/pause lifecycle, not epoch expiry (which is now
                // always-on and would otherwise read every epoch-0 alloc as
                // ExpiredEpoch at frame 1000).
                field_leaf(
                    "allocation:ProverAllocation",
                    "Epoch",
                    quil_types::consensus::epoch_for_frame(current_frame).to_be_bytes().to_vec(),
                ),
                field_leaf(
                    "allocation:ProverAllocation",
                    "ConfirmationFilter",
                    filter.clone(),
                ),
                field_leaf(
                    "allocation:ProverAllocation",
                    "JoinFrameNumber",
                    join_frame.to_be_bytes().to_vec(),
                ),
                field_leaf(
                    "allocation:ProverAllocation",
                    "LeaveFrameNumber",
                    leave_frame.to_be_bytes().to_vec(),
                ),
                field_leaf(
                    "allocation:ProverAllocation",
                    "JoinConfirmFrameNumber",
                    join_confirm_frame.to_be_bytes().to_vec(),
                ),
                field_leaf(
                    "allocation:ProverAllocation",
                    "LeaveConfirmFrameNumber",
                    leave_confirm_frame.to_be_bytes().to_vec(),
                ),
                field_leaf(
                    "allocation:ProverAllocation",
                    "PauseFrameNumber",
                    pause_frame.to_be_bytes().to_vec(),
                ),
                field_leaf(
                    "allocation:ProverAllocation",
                    "ResumeFrameNumber",
                    resume_frame.to_be_bytes().to_vec(),
                ),
                field_leaf(
                    "allocation:ProverAllocation",
                    "JoinRejectFrameNumber",
                    join_reject_frame.to_be_bytes().to_vec(),
                ),
                field_leaf(
                    "allocation:ProverAllocation",
                    "LeaveRejectFrameNumber",
                    leave_reject_frame.to_be_bytes().to_vec(),
                ),
            ];
            let alloc_bytes = build_sub_tree(alloc_leaves);

            // Vertex keys: 32-byte domain + 32-byte address. Use the
            // prover address for the prover vertex and the derived
            // allocation address for the allocation vertex.
            let prover_vk = {
                let mut k = vec![0xFFu8; 32];
                k.extend_from_slice(&prover_addr);
                k
            };
            let alloc_vk = {
                let mut k = vec![0xFFu8; 32];
                k.extend_from_slice(&alloc_addr_32);
                k
            };

            store
                .save_vertex_underlying("vertex", "adds", &shard, &prover_vk, &prover_bytes)
                .unwrap();
            store
                .save_vertex_underlying("vertex", "adds", &shard, &alloc_vk, &alloc_bytes)
                .unwrap();
        }

        // Refresh the in-memory registry from the per-vertex store
        // (the canonical source).
        let shared = SharedProverRegistry::new();
        shared.refresh_from_store(store.as_ref()).unwrap();

        // Query the live-allocation view.
        let summaries = shared
            .get_prover_shard_summaries(current_frame)
            .expect("summaries");
        let summary = summaries
            .iter()
            .find(|s| s.filter == filter)
            .expect("filter present");
        let active = summary.status_counts.get(&ProverStatus::Active).copied().unwrap_or(0);
        let joining = summary.status_counts.get(&ProverStatus::Joining).copied().unwrap_or(0);
        let leaving = summary.status_counts.get(&ProverStatus::Leaving).copied().unwrap_or(0);
        let paused = summary.status_counts.get(&ProverStatus::Paused).copied().unwrap_or(0);
        let kicked = summary.status_counts.get(&ProverStatus::Kicked).copied().unwrap_or(0);
        let rejected = summary.status_counts.get(&ProverStatus::Rejected).copied().unwrap_or(0);

        // Active = scenarios 2, 7, 10 = 30. Scenario 8
        // (LeaveExpiredReturnsActive) no longer counts as Active —
        // a stuck Leave is treated as "not on the shard."
        assert_eq!(active, 30, "Active count");
        // Joining = scenario 1 = 10
        assert_eq!(joining, 10, "Joining count");
        // Leaving = scenario 5 = 10
        assert_eq!(leaving, 10, "Leaving count");
        // Paused = scenario 9 = 10
        assert_eq!(paused, 10, "Paused count");
        // Dead states never appear in the live cache.
        assert_eq!(kicked, 0, "Kicked must be excluded from live cache");
        assert_eq!(rejected, 0, "Rejected must be excluded from live cache");

        let total_live: u32 = active + joining + leaving + paused;
        assert_eq!(
            total_live, 60,
            "60 live allocations (40 excluded: Rejected, ExpiredJoining, \
             ExpiredLeaving, Kicked × 10 each)"
        );
    }

    include!("prover_registry_storage_tests.rs");
    include!("registry_rows_tests.rs");

}
