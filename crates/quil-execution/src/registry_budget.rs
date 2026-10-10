//! Explicit retained-input/cache limits for tentative registry construction.
//! These are conservative logical charges, not allocator or process RSS limits.
use super::*;

#[derive(Clone, Copy, Debug)]
pub struct RegistryLimits {
    /// Add/remove records examined, including records later filtered out.
    pub max_vertices: usize,
    pub max_record_bytes: usize,
    /// Serialized input plus row overhead, including the legacy tree fallback.
    pub max_input_bytes: usize,
    /// Conservative insert/allocation count; replacement/duplicate inserts are
    /// charged again instead of claiming their old capacity was reclaimed.
    pub max_cache_entries: usize,
    pub max_cache_bytes: usize,
}

impl RegistryLimits {
    // Preserve the existing durable refresh policy. Tentative owners must
    // choose explicit limits; this is not a public production default.
    pub(super) const UNBOUNDED: Self = Self {
        max_vertices: usize::MAX,
        max_record_bytes: usize::MAX,
        max_input_bytes: usize::MAX,
        max_cache_entries: usize::MAX,
        max_cache_bytes: usize::MAX,
    };

    pub(super) fn page(self) -> VertexPageLimits {
        VertexPageLimits {
            max_entries: self.max_vertices.clamp(1, 256),
            max_bytes: self
                .max_input_bytes
                .min(self.max_record_bytes)
                .clamp(1, 16 << 20),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RegistryUsage {
    pub vertices: usize,
    pub input_bytes: usize,
    pub cache_entries: usize,
    pub cache_bytes: usize,
}

pub(super) fn limit() -> QuilError {
    QuilError::ExecutionUnavailable("execution registry resource limit".into())
}

pub(super) struct RegistryBudget {
    pub limits: RegistryLimits,
    pub usage: RegistryUsage,
}

impl RegistryBudget {
    pub fn new(limits: RegistryLimits) -> QuilResult<Self> {
        let mut budget = Self {
            limits,
            usage: RegistryUsage::default(),
        };
        budget.cache(0, &[4096])?;
        Ok(budget)
    }

    /// The input charge of one vertex row, or `None` past the record limit.
    pub fn row_charge(limits: RegistryLimits, key: usize, value: usize) -> Option<RegistryUsage> {
        let bytes = key.checked_add(value).filter(|bytes| *bytes <= limits.max_record_bytes)?;
        Some(RegistryUsage { vertices: 1, input_bytes: bytes.checked_add(128)?, ..RegistryUsage::default() })
    }

    pub fn prover_charge(info: &ProverInfo) -> RegistryUsage {
        cache_charge(4, &[512, info.address.len(), info.address.len(), info.public_key.len(), info.delegate_address.len()])
    }

    pub fn leaf_root_charge(key: &(Vec<u8>, Vec<u8>, u64), record: &LeafRootRecord) -> RegistryUsage {
        cache_charge(4, &[512, key.0.len(), key.1.len(), record.leaf_root.len()])
    }

    pub fn allocation_charge(owner: &[u8], info: &ProverAllocationInfo) -> RegistryUsage {
        let (owner, confirmation) = (owner.len(), info.confirmation_filter.len());
        cache_charge(16, &[
            2048, owner, owner, owner, owner,
            confirmation, confirmation, confirmation, confirmation,
            info.rejection_filter.len(), info.vertex_address.len(),
        ])
    }

    /// Whether `usage` fits: charges only grow during a refresh, so the
    /// final totals decide whether one would have failed.
    pub fn admits(limits: RegistryLimits, usage: RegistryUsage) -> bool {
        usage.vertices <= limits.max_vertices
            && usage.input_bytes <= limits.max_input_bytes
            && usage.cache_entries <= limits.max_cache_entries
            && usage.cache_bytes <= limits.max_cache_bytes
    }

    pub fn input(&mut self, key: usize, value: usize, vertex: bool) -> QuilResult<()> {
        let bytes = key.checked_add(value).ok_or_else(limit)?;
        if bytes > self.limits.max_record_bytes {
            return Err(limit());
        }
        let total = self
            .usage
            .input_bytes
            .checked_add(bytes)
            .and_then(|n| n.checked_add(128))
            .ok_or_else(limit)?;
        let count = self
            .usage
            .vertices
            .checked_add(usize::from(vertex))
            .ok_or_else(limit)?;
        if total > self.limits.max_input_bytes || count > self.limits.max_vertices {
            return Err(limit());
        }
        self.usage.vertices = count;
        self.usage.input_bytes = total;
        Ok(())
    }

    fn cache(&mut self, entries: usize, lengths: &[usize]) -> QuilResult<()> {
        let bytes = lengths
            .iter()
            .try_fold(self.usage.cache_bytes, |n, len| n.checked_add(*len))
            .ok_or_else(limit)?;
        let count = self
            .usage
            .cache_entries
            .checked_add(entries)
            .ok_or_else(limit)?;
        if bytes > self.limits.max_cache_bytes || count > self.limits.max_cache_entries {
            return Err(limit());
        }
        self.usage.cache_bytes = bytes;
        self.usage.cache_entries = count;
        Ok(())
    }

    fn charge(&mut self, charge: RegistryUsage) -> QuilResult<()> {
        let bytes = self.usage.cache_bytes.checked_add(charge.cache_bytes).ok_or_else(limit)?;
        let count = self.usage.cache_entries.checked_add(charge.cache_entries).ok_or_else(limit)?;
        if bytes > self.limits.max_cache_bytes || count > self.limits.max_cache_entries {
            return Err(limit());
        }
        self.usage.cache_bytes = bytes;
        self.usage.cache_entries = count;
        Ok(())
    }

    pub fn prover(&mut self, info: &ProverInfo) -> QuilResult<()> {
        self.charge(Self::prover_charge(info))
    }

    pub fn leaf_root(
        &mut self,
        key: &(Vec<u8>, Vec<u8>, u64),
        record: &LeafRootRecord,
    ) -> QuilResult<()> {
        self.charge(Self::leaf_root_charge(key, record))
    }

    pub fn allocation(&mut self, owner: &[u8], info: &ProverAllocationInfo) -> QuilResult<()> {
        // Includes the possible synthesized prover, all three indices, map
        // entries and vector growth. Charge even when an index already exists.
        self.charge(Self::allocation_charge(owner, info))
    }
}

fn cache_charge(entries: usize, lengths: &[usize]) -> RegistryUsage {
    RegistryUsage {
        cache_entries: entries,
        cache_bytes: lengths.iter().fold(0usize, |total, len| total.saturating_add(*len)),
        ..RegistryUsage::default()
    }
}

impl RegistryUsage {
    pub(super) fn plus(self, other: Self) -> Self {
        Self {
            vertices: self.vertices.saturating_add(other.vertices),
            input_bytes: self.input_bytes.saturating_add(other.input_bytes),
            cache_entries: self.cache_entries.saturating_add(other.cache_entries),
            cache_bytes: self.cache_bytes.saturating_add(other.cache_bytes),
        }
    }

    /// `self` without `other`; `None` if `self` does not include it.
    pub(super) fn checked_minus(self, other: Self) -> Option<Self> {
        Some(Self {
            vertices: self.vertices.checked_sub(other.vertices)?,
            input_bytes: self.input_bytes.checked_sub(other.input_bytes)?,
            cache_entries: self.cache_entries.checked_sub(other.cache_entries)?,
            cache_bytes: self.cache_bytes.checked_sub(other.cache_bytes)?,
        })
    }
}

/// Visit borrowed legacy leaves so count/byte admission happens before cloning
/// them. The decoded tree is bounded separately by its serialized record cap.
pub(super) fn collect_legacy(
    node: &VectorCommitmentNode,
    leaves: &mut Vec<(Vec<u8>, Vec<u8>)>,
    budget: &mut RegistryBudget,
) -> QuilResult<()> {
    match node {
        VectorCommitmentNode::Leaf(leaf) => {
            budget.input(leaf.key.len(), leaf.value.len(), true)?;
            leaves.push((leaf.key.clone(), leaf.value.clone()));
        }
        VectorCommitmentNode::Branch(branch) => {
            for child in branch.children.iter().flatten() {
                collect_legacy(child, leaves, budget)?;
            }
        }
    }
    Ok(())
}
