//! Capture CRDT metadata and its backing-store generation under one barrier.
//! Node-level direct-store/cutover hooks still require their own coordination;
//! a capture does not certify a consensus parent or publish tentative writes.

use super::*;
use quil_types::store::BackingStoreIdentity;
use std::sync::{MutexGuard, RwLockReadGuard, RwLockWriteGuard};

#[path = "execution_adoption.rs"]
mod adoption;
pub use adoption::PreparedCrdtAdoption;

#[derive(Clone, Copy, Debug)]
pub struct ExecutionForkLimits {
    pub overlay: quil_forest::OverlayLimits,
    /// Map entries and nested vector allocations, checked before cloning.
    pub max_metadata_entries: usize,
    /// Conservative logical allocation estimate, not an allocator/RSS limit.
    pub max_metadata_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutionMetadataUsage {
    pub entries: usize,
    pub bytes: usize,
}

pub struct ExecutionFork {
    pub crdt: Arc<HypergraphCrdt>,
    pub overlay: Arc<quil_forest::ExecutionOverlay>,
    pub metadata: ExecutionMetadataUsage,
}

/// Keeps the source CRDT stable while constructing its fork and dependent
/// engines/registry. Do not reenter source CRDT mutation, commit or capture
/// methods while holding this guard. Capture lock order is forest, then commit.
pub struct ExecutionCapture<'a> {
    source: &'a HypergraphCrdt,
    _forest: MutexGuard<'a, ()>,
    _commit: crate::crdt::CommitGuard<'a>,
}

fn read<T>(lock: &RwLock<T>) -> Result<RwLockReadGuard<'_, T>> {
    lock.read().map_err(|_| {
        QuilError::ExecutionUnavailable("execution capture metadata lock poisoned".into())
    })
}

impl HypergraphCrdt {
    /// Identity only; this neither exposes a writable database nor captures a
    /// generation. Use the execution capture barrier for a coherent fork.
    pub fn backing_store_identity(&self) -> Option<BackingStoreIdentity> {
        self.store.backing_store_identity()
    }

    pub fn lock_execution_capture(&self) -> Result<ExecutionCapture<'_>> {
        let forest = self.forest_write_lock.lock().map_err(|_| {
            QuilError::ExecutionUnavailable("execution capture forest lock poisoned".into())
        })?;
        let commit = self.commit_lock.lock().map_err(|_| {
            QuilError::ExecutionUnavailable("execution capture commit lock poisoned".into())
        })?;
        Ok(ExecutionCapture {
            source: self,
            _forest: forest,
            _commit: commit,
        })
    }
}

struct MetadataBudget {
    limits: ExecutionForkLimits,
    usage: ExecutionMetadataUsage,
}

impl MetadataBudget {
    fn charge(&mut self, entries: usize, bytes: usize) -> Result<()> {
        let next = self
            .usage
            .entries
            .checked_add(entries)
            .zip(self.usage.bytes.checked_add(bytes));
        let Some((entries, bytes)) = next.filter(|(e, b)| {
            *e <= self.limits.max_metadata_entries && *b <= self.limits.max_metadata_bytes
        }) else {
            return Err(QuilError::ExecutionUnavailable(
                "execution metadata budget exceeded".into(),
            ));
        };
        self.usage = ExecutionMetadataUsage { entries, bytes };
        Ok(())
    }

    fn entry(&mut self) -> Result<()> {
        self.charge(1, 256)
    }

    fn vector(&mut self, len: usize, width: usize) -> Result<()> {
        let bytes = len
            .checked_mul(width)
            .and_then(|n| n.checked_add(32))
            .ok_or_else(|| {
                QuilError::ExecutionUnavailable("execution metadata size overflow".into())
            })?;
        self.charge(1, bytes)
    }
}

impl ExecutionCapture<'_> {
    /// Fork committed CRDT state with a new record-store wrapper over exactly
    /// the captured overlay. The factory must only construct that wrapper; it
    /// must not reenter/mutate the source or perform execution. Metadata limits
    /// are checked before allocation. No snapshot cache or local observer is
    /// inherited. The caller owns the overlay lifetime and aggregate budgets.
    pub fn fork(
        &self,
        limits: ExecutionForkLimits,
        store_for_overlay: impl FnOnce(
            Arc<quil_forest::ExecutionOverlay>,
        ) -> Result<Arc<dyn HypergraphStore>>,
    ) -> Result<ExecutionFork> {
        let source = self.source;
        if !read(&source.pending)?.is_empty()
            || !read(&source.pending_blobs)?.is_empty()
            || !read(&source.pending_records)?.is_empty()
        {
            return Err(QuilError::ExecutionUnavailable(
                "execution capture has uncommitted CRDT mutations".into(),
            ));
        }
        if !source.sizes_warmed.load(Ordering::Acquire) {
            return Err(QuilError::ExecutionUnavailable(
                "execution capture requires initialized size accounting".into(),
            ));
        }
        if !read(&source.layout_rebuilds)?.is_empty() {
            return Err(QuilError::ExecutionUnavailable(
                "execution capture has unfinished layout changes".into(),
            ));
        }
        let forest = read(&source.forest)?;
        let identity = source.store.backing_store_identity().ok_or_else(|| {
            QuilError::ExecutionUnavailable(
                "execution capture requires identifiable record storage".into(),
            )
        })?;
        if forest.backing_store_identity().as_ref() != Some(&identity) {
            return Err(QuilError::ExecutionUnavailable(
                "execution capture forest/record store mismatch".into(),
            ));
        }
        let roots = read(&source.prover_root_by_frame)?;
        let world_sizes = read(&source.world_size_by_frame)?;
        let phase_versions = read(&source.phase_versions)?;
        let global_versions = read(&source.global_versions)?;
        let prefixes = read(&source.app_shard_prefixes)?;
        let bit_paths = read(&source.app_shard_bit_paths)?;
        let shard_metadata = read(&source.shard_metadata)?;
        let sizes = read(&source.sub_meta)?;
        let covered = read(&source.covered_prefix)?;
        let mut budget = MetadataBudget {
            limits,
            usage: Default::default(),
        };
        budget.charge(0, 4096)?;
        for root in roots.values() {
            budget.entry()?;
            budget.vector(root.len(), 1)?;
        }
        for _ in world_sizes.values() {
            budget.entry()?;
        }
        for (key, _) in phase_versions.keys() {
            budget.entry()?;
            budget.vector(key.len(), 1)?;
        }
        for _ in global_versions.values() {
            budget.entry()?;
        }
        for paths in prefixes.values() {
            budget.entry()?;
            budget.vector(paths.len(), std::mem::size_of::<Vec<u32>>())?;
            for path in paths {
                budget.vector(path.len(), std::mem::size_of::<u32>())?;
            }
        }
        for (app, paths) in bit_paths.iter() {
            if paths.len() != prefixes.get(app).map_or(1, Vec::len) {
                return Err(QuilError::ExecutionUnavailable(
                    "execution capture has misaligned bit paths".into(),
                ));
            }
            budget.entry()?;
            budget.vector(paths.len(), std::mem::size_of::<Vec<bool>>())?;
            for path in paths {
                budget.vector(path.len(), std::mem::size_of::<bool>())?;
            }
        }
        for meta in shard_metadata.values() {
            budget.entry()?;
            budget.vector(meta.commitment.len(), std::mem::size_of::<Vec<u8>>())?;
            for root in &meta.commitment {
                budget.vector(root.len(), 1)?;
            }
            let bytes = usize::try_from(meta.size.bits().div_ceil(8)).map_err(|_| {
                QuilError::ExecutionUnavailable("execution metadata size overflow".into())
            })?;
            budget.vector(bytes, 1)?;
        }
        for key in sizes.keys() {
            budget.entry()?;
            budget.vector(key.len(), 1)?;
        }
        budget.vector(covered.len(), std::mem::size_of::<i32>())?;

        let (fork_forest, overlay) =
            forest.fork_execution_overlay(limits.overlay).map_err(|e| {
                QuilError::ExecutionUnavailable(format!("execution overlay capture: {e}"))
            })?;
        let result = (|| {
            // Cached heads must agree with the captured database, including
            // after external resets. Never transplant a stale version cache.
            for ((shard, phase), version) in phase_versions.iter() {
                if *phase >= PHASES.len()
                    || fork_forest
                        .read_head_version(shard, PHASES[*phase])
                        .map_err(|e| {
                            QuilError::ExecutionUnavailable(format!("captured phase head: {e}"))
                        })?
                        != Some(*version)
                {
                    return Err(QuilError::ExecutionUnavailable(
                        "execution capture phase version mismatch".into(),
                    ));
                }
                if fork_forest
                    .shard_phase_root(shard, PHASES[*phase], *version)
                    .map_err(|e| {
                        QuilError::ExecutionUnavailable(format!("captured phase root: {e}"))
                    })?
                    .is_none()
                {
                    return Err(QuilError::ExecutionUnavailable(
                        "execution capture phase head has no root".into(),
                    ));
                }
            }
            for (bucket, version) in global_versions.iter() {
                if fork_forest.read_global_head_version(*bucket).map_err(|e| {
                    QuilError::ExecutionUnavailable(format!("captured global head: {e}"))
                })? != Some(*version)
                {
                    return Err(QuilError::ExecutionUnavailable(
                        "execution capture global version mismatch".into(),
                    ));
                }
                if fork_forest
                    .global_root(*bucket, *version)
                    .map_err(|e| {
                        QuilError::ExecutionUnavailable(format!("captured global root: {e}"))
                    })?
                    .is_none()
                {
                    return Err(QuilError::ExecutionUnavailable(
                        "execution capture global head has no root".into(),
                    ));
                }
            }
            let store = store_for_overlay(overlay.clone())?;
            if store.backing_store_identity() != Some(BackingStoreIdentity::of(&overlay)) {
                return Err(QuilError::ExecutionUnavailable(
                    "execution fork factory returned a different store".into(),
                ));
            }
            store.set_covered_prefix(&covered)?;
            // Collect maps afresh, so sparse capacity retained by the source
            // cannot bypass the entry/byte bounds checked above.
            let crdt = Arc::new(HypergraphCrdt {
                store,
                prover: source.prover.clone(),
                forest: RwLock::new(fork_forest),
                forest_version: AtomicU64::new(source.forest_version.load(Ordering::Acquire)),
                forest_write_lock: std::sync::Mutex::new(()),
                prover_root_by_frame: RwLock::new(
                    roots.iter().map(|(k, v)| (*k, v.clone())).collect(),
                ),
                world_size_by_frame: RwLock::new(
                    world_sizes.iter().map(|(k, v)| (*k, *v)).collect(),
                ),
                phase_versions: RwLock::new(
                    phase_versions
                        .iter()
                        .map(|(k, v)| (k.clone(), *v))
                        .collect(),
                ),
                global_versions: RwLock::new(
                    global_versions.iter().map(|(k, v)| (*k, *v)).collect(),
                ),
                app_shard_prefixes: RwLock::new(
                    prefixes.iter().map(|(k, v)| (*k, v.clone())).collect(),
                ),
                app_shard_bit_paths: RwLock::new(
                    bit_paths.iter().map(|(k, v)| (*k, v.clone())).collect(),
                ),
                layout_rebuilds: RwLock::new(Default::default()),
                pending: RwLock::new(Default::default()),
                pending_blobs: RwLock::new(Default::default()),
                pending_records: RwLock::new(Default::default()),
                shard_metadata: RwLock::new(
                    shard_metadata
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                ),
                sub_meta: RwLock::new(sizes.iter().map(|(k, v)| (k.clone(), *v)).collect()),
                sizes_warmed: AtomicBool::new(true),
                size_warm_lock: std::sync::Mutex::new(()),
                snapshot_mgr: SnapshotManager::new(),
                local_vertex_observer: RwLock::new(None),
                covered_prefix: RwLock::new(covered.to_vec()),
                commit_lock: Default::default(),
                unified_tree: AtomicBool::new(source.unified_tree.load(Ordering::Acquire)),
            });
            Ok(ExecutionFork {
                crdt,
                overlay: overlay.clone(),
                metadata: budget.usage,
            })
        })();
        if result.is_err() {
            overlay.close();
        }
        result
    }
}
