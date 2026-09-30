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

fn limit() -> QuilError {
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

    pub fn prover(&mut self, info: &ProverInfo) -> QuilResult<()> {
        self.cache(
            4,
            &[
                512,
                info.address.len(),
                info.address.len(),
                info.public_key.len(),
                info.delegate_address.len(),
            ],
        )
    }

    pub fn leaf_root(
        &mut self,
        key: &(Vec<u8>, Vec<u8>, u64),
        record: &LeafRootRecord,
    ) -> QuilResult<()> {
        self.cache(4, &[512, key.0.len(), key.1.len(), record.leaf_root.len()])
    }

    pub fn allocation(&mut self, owner: &[u8], info: &ProverAllocationInfo) -> QuilResult<()> {
        // Includes the possible synthesized prover, all three indices, map
        // entries and vector growth. Charge even when an index already exists.
        self.cache(
            16,
            &[
                2048,
                owner.len(),
                owner.len(),
                owner.len(),
                owner.len(),
                info.confirmation_filter.len(),
                info.confirmation_filter.len(),
                info.confirmation_filter.len(),
                info.confirmation_filter.len(),
                info.rejection_filter.len(),
                info.vertex_address.len(),
            ],
        )
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
