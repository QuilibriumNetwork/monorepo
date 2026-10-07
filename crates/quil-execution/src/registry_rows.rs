//! The vertex rows a prover registry was built from, so that a change to some
//! of them updates only the records they feed. Publication used to rescan
//! every registry row after each GLOBAL frame: 3 s per frame on one archive,
//! three times per frame while it caught up, for frames that wrote a handful.
//!
//! The update reproduces a refresh exactly: the same rows in address order,
//! the same two passes, the same charges. Where it cannot (the registry came
//! from the legacy tree, a cache was edited directly, no rows would remain),
//! it declines and the caller refreshes.
use super::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Key length of every paged registry row: the shard's domain then the address.
const VK_LEN: usize = 64;

type LeafRootKey = (Vec<u8>, Vec<u8>, u64);

/// An absent ring is an unassigned allocation, not decoded ring zero.
#[derive(Clone, Copy)]
pub(super) enum CommittedRing {
    Unassigned,
    Assigned(u8),
    Invalid,
}

/// What one `adds` row contributes to each pass of a refresh.
#[derive(Clone)]
pub(super) struct DecodedRow {
    first: FirstPass,
    /// Assignment and validity of the activated policy's committed fields.
    committed_ring: CommittedRing,
    /// Rows typed as allocations: the owner and allocation, `None` when the
    /// row does not decode. Counted in the second pass either way.
    allocation: Option<Option<(Vec<u8>, ProverAllocationInfo)>>,
}

#[derive(Clone)]
enum FirstPass {
    /// Undecodable rows and allocations: no first-pass effect.
    Nothing,
    Unknown,
    /// A retired prover has no row of its own; its key names the row
    /// synthesized for its allocations.
    Prover { info: Option<ProverInfo>, retired_key: Vec<u8> },
    Reward,
    LeafRoot(Vec<(LeafRootKey, LeafRootRecord)>),
}

/// Decode one `adds` row as both passes of `decode_vertices` read it.
fn decode_row(vk: &[u8], data: &[u8]) -> DecodedRow {
    let root = match deserialize_go_tree(data) {
        Ok(Some(root)) => root,
        _ => return DecodedRow { first: FirstPass::Nothing, allocation: None, committed_ring: CommittedRing::Invalid },
    };
    let Some(type_hash) = root.find_leaf_value(&vec![0xFFu8; 32]) else {
        return DecodedRow { first: FirstPass::Unknown, allocation: None, committed_ring: CommittedRing::Invalid };
    };
    let first = match class_for_type_hash(&type_hash) {
        Some("prover:Prover") => match decode_prover(vk, &root) {
            Some(info) => FirstPass::Prover { info: Some(info), retired_key: Vec::new() },
            None => FirstPass::Prover {
                info: None,
                retired_key: read_bytes(&root, "prover:Prover", "PublicKey"),
            },
        },
        Some("reward:ProverReward") => FirstPass::Reward,
        Some("leafroot:LeafRootRegistration") => FirstPass::LeafRoot(decode_leaf_root(&root)),
        Some("allocation:ProverAllocation") => FirstPass::Nothing,
        _ => FirstPass::Unknown,
    };
    let allocation = (type_hash == TYPE_HASH_ALLOCATION).then(|| decode_allocation(vk, &root));
    let field = |name| field_key("allocation:ProverAllocation", name)
        .and_then(|key| root.find_leaf_value(&key));
    let committed_ring = if allocation.as_ref().is_some_and(|decoded| decoded.is_some()) {
        let key = (field("RingEpoch"), field("RingSeniority"));
        let valid_key = matches!(&key, (Some(epoch), Some(seniority))
            if epoch.len() == 8 && seniority.len() == 8);
        match field("Ring") {
            None if valid_key || matches!(key, (None, None)) => CommittedRing::Unassigned,
            Some(ring) if ring.len() == 1 && valid_key => CommittedRing::Assigned(ring[0]),
            _ => CommittedRing::Invalid,
        }
    } else { CommittedRing::Invalid };
    DecodedRow { first, allocation, committed_ring }
}

fn vertex_key(address: &[u8; 32]) -> Vec<u8> {
    let mut key = quil_store::encoding::prover_registry_shard().l2.to_vec();
    key.extend_from_slice(address);
    key
}

#[derive(Clone)]
struct AddedRow {
    value_len: usize,
    decoded: DecodedRow,
}

#[derive(Clone, Default)]
pub(super) struct RegistryRows {
    adds: BTreeMap<[u8; 32], AddedRow>,
    /// `removes` rows: their value lengths. They hide the `adds` row there.
    removes: BTreeMap<[u8; 32], usize>,
    /// Key + value and value sizes of every row read, with multiplicity.
    row_sizes: BTreeMap<usize, usize>,
    value_sizes: BTreeMap<usize, usize>,
    /// Effective allocation rows by owner. A refresh appends each owner's
    /// allocations in address order.
    owned: HashMap<Vec<u8>, BTreeSet<[u8; 32]>>,
    /// Effective rows naming each leaf-root key; a refresh keeps the highest.
    leaf_sources: HashMap<LeafRootKey, BTreeSet<[u8; 32]>>,
}

impl RegistryRows {
    pub(super) fn committed_ring(&self, address: &[u8]) -> CommittedRing {
        <[u8; 32]>::try_from(address).ok()
            .and_then(|address| self.effective(&address))
            .map(|row| row.committed_ring).unwrap_or(CommittedRing::Invalid)
    }

    /// Record an `adds` row the refresh read (and charged).
    pub(super) fn add(&mut self, address: [u8; 32], data: &[u8]) {
        self.note_size(data.len());
        let decoded = decode_row(&vertex_key(&address), data);
        self.adds.insert(address, AddedRow { value_len: data.len(), decoded });
    }

    /// Record a `removes` row the refresh read (and charged).
    pub(super) fn remove(&mut self, address: [u8; 32], value_len: usize) {
        self.note_size(value_len);
        self.removes.insert(address, value_len);
    }

    pub(super) fn has_adds(&self) -> bool {
        !self.adds.is_empty()
    }

    /// The largest key + value and value among the rows read.
    pub(super) fn largest(&self) -> (usize, usize) {
        (
            self.row_sizes.keys().next_back().copied().unwrap_or(0),
            self.value_sizes.keys().next_back().copied().unwrap_or(0),
        )
    }

    fn note_size(&mut self, value: usize) {
        *self.row_sizes.entry(VK_LEN.saturating_add(value)).or_default() += 1;
        *self.value_sizes.entry(value).or_default() += 1;
    }

    fn forget_size(&mut self, value: usize) {
        for (sizes, size) in [(&mut self.row_sizes, VK_LEN.saturating_add(value)), (&mut self.value_sizes, value)] {
            if let Some(count) = sizes.get_mut(&size) {
                *count -= 1;
                if *count == 0 {
                    sizes.remove(&size);
                }
            }
        }
    }

    /// The `adds` row at `address` unless a `removes` row hides it.
    fn effective(&self, address: &[u8; 32]) -> Option<&DecodedRow> {
        if self.removes.contains_key(address) {
            return None;
        }
        self.adds.get(address).map(|row| &row.decoded)
    }

    fn index(&mut self, address: &[u8; 32], row: &DecodedRow) {
        if let Some(Some((owner, _))) = &row.allocation {
            self.owned.entry(owner.clone()).or_default().insert(*address);
        }
        if let FirstPass::LeafRoot(records) = &row.first {
            for (key, _) in records {
                self.leaf_sources.entry(key.clone()).or_default().insert(*address);
            }
        }
    }

    fn unindex(&mut self, address: &[u8; 32], row: &DecodedRow) {
        if let Some(Some((owner, _))) = &row.allocation {
            if let Some(rows) = self.owned.get_mut(owner) {
                rows.remove(address);
                if rows.is_empty() {
                    self.owned.remove(owner);
                }
            }
        }
        if let FirstPass::LeafRoot(records) = &row.first {
            for (key, _) in records {
                if let Some(rows) = self.leaf_sources.get_mut(key) {
                    rows.remove(address);
                    if rows.is_empty() {
                        self.leaf_sources.remove(key);
                    }
                }
            }
        }
    }

    /// `owner`'s effective allocations, in the order a refresh attaches them.
    fn allocations_of(&self, owner: &[u8]) -> Vec<ProverAllocationInfo> {
        self.owned
            .get(owner)
            .into_iter()
            .flatten()
            .filter_map(|address| match &self.effective(address)?.allocation {
                Some(Some((_, allocation))) => Some(allocation.clone()),
                _ => None,
            })
            .collect()
    }
}

/// The charges of one address's rows: each row read, and what the `adds`
/// row decodes to unless removed. `None` past the record limit.
fn contribution(
    limits: RegistryLimits,
    adds: Option<(usize, &DecodedRow)>,
    removes: Option<usize>,
) -> Option<RegistryUsage> {
    let mut usage = RegistryUsage::default();
    if let Some((len, _)) = adds {
        usage = usage.plus(RegistryBudget::row_charge(limits, VK_LEN, len)?);
    }
    if let Some(len) = removes {
        usage = usage.plus(RegistryBudget::row_charge(limits, VK_LEN, len)?);
    }
    if let (Some((_, decoded)), None) = (adds, removes) {
        match &decoded.first {
            FirstPass::Prover { info: Some(info), .. } => usage = usage.plus(RegistryBudget::prover_charge(info)),
            FirstPass::LeafRoot(records) => {
                for (key, record) in records {
                    usage = usage.plus(RegistryBudget::leaf_root_charge(key, record));
                }
            }
            _ => {}
        }
        if let Some(Some((owner, allocation))) = &decoded.allocation {
            usage = usage.plus(RegistryBudget::allocation_charge(owner, allocation));
        }
    }
    Some(usage)
}

/// One row of `phase` at `address`, read as a refresh pages it.
fn read_row(
    snapshot: &dyn SnapshotReadable,
    phase: &str,
    shard: &ShardKey,
    address: &[u8; 32],
    limits: VertexPageLimits,
) -> QuilResult<Option<Vec<u8>>> {
    // The page starts after `after`; the address before this one.
    let after = address.iter().rposition(|byte| *byte != 0).map(|index| {
        let mut before = *address;
        before[index] -= 1;
        before[index + 1..].fill(0xFF);
        before
    });
    let page = snapshot.page_vertex_underlying_fixed(
        "vertex",
        phase,
        shard,
        &shard.l2,
        after.as_ref(),
        VertexPageLimits { max_entries: 1, ..limits },
    )?;
    if page.has_more && page.entries.is_empty() {
        return Err(QuilError::Store("registry page made no progress".into()));
    }
    Ok(page.entries.into_iter().next().filter(|(found, _)| found == address).map(|(_, data)| data))
}

/// Which phases of one address a branch wrote.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Written {
    pub adds: bool,
    pub removes: bool,
}

/// The registry rows `overlay` wrote, by address; `None` when a range
/// deletion reaches them, so they cannot be listed.
pub(super) fn written_rows(overlay: &quil_forest::ExecutionOverlay) -> Option<BTreeMap<[u8; 32], Written>> {
    let prefixes = quil_store::encoding::prover_registry_row_prefixes();
    let all: Vec<Vec<u8>> = prefixes.iter().map(|(_, prefix)| prefix.clone()).collect();
    let mut written: BTreeMap<[u8; 32], Written> = BTreeMap::new();
    for key in overlay.written_keys_under(&all)? {
        for (phase, prefix) in &prefixes {
            let Some(address) = key.get(prefix.len()..prefix.len() + 32).filter(|_| key.starts_with(prefix)) else {
                continue;
            };
            let entry = written.entry(address.try_into().unwrap()).or_default();
            if *phase == "adds" {
                entry.adds = true;
            } else {
                entry.removes = true;
            }
        }
    }
    Some(written)
}

/// One address's rows after the update: `Some` for a phase it re-read.
struct Change {
    address: [u8; 32],
    adds: Option<Option<(usize, DecodedRow)>>,
    removes: Option<Option<usize>>,
}

impl InMemoryProverRegistry {
    /// Build every cache from `rows` as `decode_vertices` builds them from
    /// the same effective rows in address order, indexing as it goes.
    pub(super) fn compose_from_rows(&mut self, rows: &mut RegistryRows, budget: &mut RegistryBudget) -> QuilResult<()> {
        let RegistryRows { adds, removes, owned, leaf_sources, .. } = rows;
        let effective = || adds.iter().filter(|(address, _)| !removes.contains_key(*address));
        let mut retired_keys: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        for (address, row) in effective() {
            match &row.decoded.first {
                FirstPass::Nothing => {}
                FirstPass::Unknown => self.unknown_vertex_count += 1,
                FirstPass::Prover { info, retired_key } => {
                    self.prover_vertex_count += 1;
                    match info {
                        Some(info) => {
                            budget.prover(info)?;
                            self.prover_cache.insert(info.address.clone(), info.clone());
                        }
                        None if !retired_key.is_empty() => {
                            retired_keys.insert(address.to_vec(), retired_key.clone());
                        }
                        None => {}
                    }
                }
                FirstPass::Reward => self.reward_vertex_count += 1,
                FirstPass::LeafRoot(records) => {
                    self.leaf_root_vertex_count += 1;
                    for (key, record) in records {
                        budget.leaf_root(key, record)?;
                        self.leaf_root_cache.insert(key.clone(), record.clone());
                        leaf_sources.entry(key.clone()).or_default().insert(*address);
                    }
                }
            }
        }
        for (address, row) in effective() {
            let Some(allocation) = &row.decoded.allocation else { continue };
            self.allocation_vertex_count += 1;
            let Some((owner, allocation)) = allocation else { continue };
            budget.allocation(owner, allocation)?;
            owned.entry(owner.clone()).or_default().insert(*address);
            self.attach_allocation(owner, allocation.clone(), retired_keys.get(owner));
        }
        Ok(())
    }

    /// Bring the caches up to date with the `written` rows of `snapshot`, as a
    /// refresh of `snapshot` would leave them when this registry matched every
    /// other row. `Ok(false)`, changing nothing, when only a refresh can: the
    /// registry is not built from rows, a cache was edited directly, or no
    /// `adds` row would remain (a refresh falls back to the legacy tree). An
    /// error is one a refresh would fail with, and changes nothing.
    pub(super) fn update_rows(
        &mut self,
        snapshot: &dyn SnapshotReadable,
        written: &BTreeMap<[u8; 32], Written>,
        limits: RegistryLimits,
    ) -> QuilResult<bool> {
        if self.diverged || !self.from_rows {
            return Ok(false);
        }
        let Some(rows) = self.rows.as_ref() else { return Ok(false) };
        let shard = quil_store::encoding::prover_registry_shard();
        let page = limits.page();
        // Read and decode first, so a failure changes nothing.
        let mut changes = Vec::with_capacity(written.len());
        for (address, phases) in written {
            let adds = if phases.adds {
                Some(read_row(snapshot, "adds", &shard, address, page)?
                    .map(|data| (data.len(), decode_row(&vertex_key(address), &data))))
            } else {
                None
            };
            let removes = if phases.removes {
                Some(read_row(snapshot, "removes", &shard, address, page)?.map(|data| data.len()))
            } else {
                None
            };
            changes.push(Change { address: *address, adds, removes });
        }

        let mut usage = self.resource_usage;
        let mut adds_left = rows.adds.len();
        for change in &changes {
            let old_adds = rows.adds.get(&change.address).map(|row| (row.value_len, &row.decoded));
            let old_removes = rows.removes.get(&change.address).copied();
            let new_adds = match &change.adds {
                Some(new) => new.as_ref().map(|(len, decoded)| (*len, decoded)),
                None => old_adds,
            };
            let new_removes = change.removes.unwrap_or(old_removes);
            let Some(old) = contribution(limits, old_adds, old_removes) else { return Ok(false) };
            let new = contribution(limits, new_adds, new_removes).ok_or_else(registry_budget::limit)?;
            let Some(without) = usage.checked_minus(old) else { return Ok(false) };
            usage = without.plus(new);
            adds_left = adds_left - usize::from(old_adds.is_some()) + usize::from(new_adds.is_some());
        }
        if adds_left == 0 {
            return Ok(false);
        }
        if !RegistryBudget::admits(limits, usage) {
            return Err(registry_budget::limit());
        }

        let mut rows_arc = self.rows.take().expect("checked above");
        let rows = Arc::make_mut(&mut rows_arc);
        // The provers and leaf-root keys any changed row feeds, before or
        // after, and each such prover's allocation filters before.
        let mut provers: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut leaf_keys: HashSet<LeafRootKey> = HashSet::new();
        for change in &changes {
            let new = match &change.adds {
                Some(new) => new.as_ref().map(|(_, decoded)| decoded),
                None => rows.adds.get(&change.address).map(|row| &row.decoded),
            }
            .filter(|_| !change.removes.unwrap_or(rows.removes.get(&change.address).copied()).is_some());
            for row in [rows.effective(&change.address), new].into_iter().flatten() {
                if matches!(row.first, FirstPass::Prover { .. }) {
                    provers.insert(change.address.to_vec());
                }
                if let Some(Some((owner, _))) = &row.allocation {
                    provers.insert(owner.clone());
                }
                if let FirstPass::LeafRoot(records) = &row.first {
                    leaf_keys.extend(records.iter().map(|(key, _)| key.clone()));
                }
            }
        }
        let filters_before: HashMap<Vec<u8>, BTreeSet<Vec<u8>>> = provers
            .iter()
            .map(|prover| {
                let filters = rows.allocations_of(prover).into_iter().map(|a| a.confirmation_filter).collect();
                (prover.clone(), filters)
            })
            .collect();

        for change in changes {
            if let Some(old) = rows.effective(&change.address).cloned() {
                self.count(&old, false);
                rows.unindex(&change.address, &old);
            }
            if let Some(adds) = change.adds {
                if let Some(old) = rows.adds.remove(&change.address) {
                    rows.forget_size(old.value_len);
                }
                if let Some((value_len, decoded)) = adds {
                    rows.note_size(value_len);
                    rows.adds.insert(change.address, AddedRow { value_len, decoded });
                }
            }
            if let Some(removes) = change.removes {
                if let Some(old) = rows.removes.remove(&change.address) {
                    rows.forget_size(old);
                }
                if let Some(value_len) = removes {
                    rows.note_size(value_len);
                    rows.removes.insert(change.address, value_len);
                }
            }
            if let Some(new) = rows.effective(&change.address).cloned() {
                self.count(&new, true);
                rows.index(&change.address, &new);
            }
        }

        for key in leaf_keys {
            let record = rows.leaf_sources.get(&key).and_then(|sources| sources.last()).and_then(|address| {
                match &rows.effective(address)?.first {
                    // A row naming a key twice keeps its last record, as a refresh inserts in order.
                    FirstPass::LeafRoot(records) => records.iter().rev().find(|(k, _)| *k == key).map(|(_, r)| r.clone()),
                    _ => None,
                }
            });
            match record {
                Some(record) => {
                    self.leaf_root_cache.insert(key, record);
                }
                None => {
                    self.leaf_root_cache.remove(&key);
                }
            }
        }
        for prover in &provers {
            self.recompose_prover(rows, prover, &filters_before[prover]);
        }
        (self.largest_row, self.largest_value) = rows.largest();
        self.rows = Some(rows_arc);
        self.resource_usage = usage;
        // These caches now hold the branch's rows, not a database scan.
        self.scanned = None;
        Ok(true)
    }

    fn count(&mut self, row: &DecodedRow, add: bool) {
        let step = |count: &mut usize| if add { *count += 1 } else { *count -= 1 };
        match &row.first {
            FirstPass::Nothing => {}
            FirstPass::Unknown => step(&mut self.unknown_vertex_count),
            FirstPass::Prover { .. } => step(&mut self.prover_vertex_count),
            FirstPass::Reward => step(&mut self.reward_vertex_count),
            FirstPass::LeafRoot(_) => step(&mut self.leaf_root_vertex_count),
        }
        if row.allocation.is_some() {
            step(&mut self.allocation_vertex_count);
        }
    }

    /// Rebuild `prover`'s entry and its filter indexes from `rows`, as a
    /// refresh composes them. `before`: its allocation filters before.
    fn recompose_prover(&mut self, rows: &RegistryRows, prover: &Vec<u8>, before: &BTreeSet<Vec<u8>>) {
        let allocations = rows.allocations_of(prover);
        let own_row = <[u8; 32]>::try_from(prover.as_slice()).ok().and_then(|address| rows.effective(&address));
        let entry = match own_row.map(|row| &row.first) {
            Some(FirstPass::Prover { info: Some(info), .. }) => Some(ProverInfo { allocations: allocations.clone(), ..info.clone() }),
            own if !allocations.is_empty() => Some(ProverInfo {
                public_key: match own {
                    Some(FirstPass::Prover { info: None, retired_key }) => retired_key.clone(),
                    _ => Vec::new(),
                },
                address: prover.clone(),
                status: ProverStatus::Unknown,
                kick_frame_number: 0,
                allocations: allocations.clone(),
                available_storage: 0,
                seniority: 0,
                delegate_address: Vec::new(),
            }),
            _ => None,
        };
        match entry {
            Some(entry) => {
                self.prover_cache.insert(prover.clone(), entry);
            }
            None => {
                self.prover_cache.remove(prover);
            }
        }
        let after: BTreeSet<Vec<u8>> = allocations.iter().map(|a| a.confirmation_filter.clone()).collect();
        for filter in before.difference(&after) {
            if let Some(list) = self.filter_cache.get_mut(filter) {
                if let Ok(index) = list.binary_search_by(|a| a.as_slice().cmp(prover.as_slice())) {
                    list.remove(index);
                }
                if list.is_empty() {
                    self.filter_cache.remove(filter);
                }
            }
        }
        for filter in after.difference(before) {
            let list = self.filter_cache.entry(filter.clone()).or_default();
            if let Err(index) = list.binary_search_by(|a| a.as_slice().cmp(prover.as_slice())) {
                list.insert(index, prover.clone());
            }
        }
        let mut active: Vec<Vec<u8>> = Vec::new();
        for allocation in &allocations {
            if allocation.status == ProverStatus::Active && !active.contains(&allocation.confirmation_filter) {
                active.push(allocation.confirmation_filter.clone());
            }
        }
        if active.is_empty() {
            self.address_to_filters.remove(prover);
        } else {
            self.address_to_filters.insert(prover.clone(), active);
        }
    }
}
