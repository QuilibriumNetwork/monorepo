//! Prepare all bounded metadata and locks before a canonical storage commit.
use super::*;

struct Metadata {
    forest_version: u64,
    roots: BTreeMap<u64, Vec<u8>>,
    world_sizes: BTreeMap<u64, u64>,
    phase_versions: HashMap<(Vec<u8>, usize), u64>,
    global_versions: HashMap<u8, u64>,
    prefixes: HashMap<[u8; 32], Vec<Vec<u32>>>,
    bit_paths: HashMap<[u8; 32], Vec<Vec<bool>>>,
    shard_metadata: HashMap<ShardKey, ShardMetadata>,
    sizes: HashMap<Vec<u8>, (u64, i128)>,
    covered: Vec<i32>,
    unified: bool,
}

/// Constructed under a retained execution capture. All fallible locks and
/// bounded allocations are acquired before returning. `adopt` only moves the
/// prepared values and keeps the live forest/store/observers/snapshots intact.
pub struct PreparedCrdtAdoption<'a> {
    source: &'a HypergraphCrdt,
    _forest: RwLockWriteGuard<'a, Forest>,
    roots: RwLockWriteGuard<'a, BTreeMap<u64, Vec<u8>>>,
    world_sizes: RwLockWriteGuard<'a, BTreeMap<u64, u64>>,
    phase_versions: RwLockWriteGuard<'a, HashMap<(Vec<u8>, usize), u64>>,
    global_versions: RwLockWriteGuard<'a, HashMap<u8, u64>>,
    prefixes: RwLockWriteGuard<'a, HashMap<[u8; 32], Vec<Vec<u32>>>>,
    bit_paths: RwLockWriteGuard<'a, HashMap<[u8; 32], Vec<Vec<bool>>>>,
    shard_metadata: RwLockWriteGuard<'a, HashMap<ShardKey, ShardMetadata>>,
    sizes: RwLockWriteGuard<'a, HashMap<Vec<u8>, (u64, i128)>>,
    covered: RwLockWriteGuard<'a, Vec<i32>>,
    state: Option<Metadata>,
}

fn unavailable(message: &str) -> QuilError {
    QuilError::ExecutionUnavailable(message.into())
}

/// Readers hold these briefly; waiting them out keeps an executed frame
/// from being discarded. One deadline covers every lock an adoption takes.
fn write<'a, T>(patience: &quil_types::lock_patience::Patience, lock: &'a RwLock<T>) -> Result<RwLockWriteGuard<'a, T>> {
    patience.write(lock)
        .ok_or_else(|| unavailable("execution adoption metadata is busy or poisoned"))
}

fn take<T>(lock: RwLock<T>) -> Result<T> {
    lock.into_inner()
        .map_err(|_| unavailable("prepared execution metadata poisoned"))
}

impl ExecutionCapture<'_> {
    pub fn database(&self) -> Result<quil_forest::CoordinatedDb> {
        read(&self.source.forest)?
            .db()
            .cloned()
            .ok_or_else(|| unavailable("canonical publication requires a durable forest"))
    }

    /// Snapshot the completed private CRDT with the same bounds/coherence checks
    /// used for execution capture. The factory constructs only a record wrapper
    /// for that temporary child. Its overlay is closed before this returns;
    /// only bounded in-memory metadata survives preparation.
    pub fn prepare_adoption(
        &self,
        incoming: &HypergraphCrdt,
        incoming_overlay: &Arc<quil_forest::ExecutionOverlay>,
        limits: ExecutionForkLimits,
        store_for_overlay: impl FnOnce(
            Arc<quil_forest::ExecutionOverlay>,
        ) -> Result<Arc<dyn HypergraphStore>>,
    ) -> Result<PreparedCrdtAdoption<'_>> {
        if std::ptr::eq(self.source, incoming)
            || incoming.backing_store_identity() != Some(BackingStoreIdentity::of(incoming_overlay))
            || !incoming_overlay.execution_healthy()
        {
            return Err(unavailable(
                "execution adoption requires its own healthy private CRDT",
            ));
        }
        let captured = incoming
            .lock_execution_capture()?
            .fork(limits, store_for_overlay)?;
        captured.overlay.close();
        let state = Arc::try_unwrap(captured.crdt)
            .map_err(|_| unavailable("prepared CRDT metadata has another owner"))?;
        let state = Metadata {
            forest_version: state.forest_version.load(Ordering::Acquire),
            unified: state.unified_tree.load(Ordering::Acquire),
            roots: take(state.prover_root_by_frame)?,
            world_sizes: take(state.world_size_by_frame)?,
            phase_versions: take(state.phase_versions)?,
            global_versions: take(state.global_versions)?,
            prefixes: take(state.app_shard_prefixes)?,
            bit_paths: take(state.app_shard_bit_paths)?,
            shard_metadata: take(state.shard_metadata)?,
            sizes: take(state.sub_meta)?,
            covered: take(state.covered_prefix)?,
        };
        let source = self.source;
        // Forest readers commonly acquire version/prefix locks afterwards.
        // Acquire this first and use bounded try-locks throughout to avoid
        // inversion: no wait outlasts the deadline.
        let patience = quil_types::lock_patience::Patience::new();
        let forest = write(&patience, &source.forest)?;
        if !read(&source.pending)?.is_empty()
            || !read(&source.pending_blobs)?.is_empty()
            || !read(&source.pending_records)?.is_empty()
            || !read(&source.layout_rebuilds)?.is_empty()
        {
            return Err(unavailable(
                "canonical source has unfinished CRDT mutations",
            ));
        }
        let roots = write(&patience, &source.prover_root_by_frame)?;
        let world_sizes = write(&patience, &source.world_size_by_frame)?;
        let phase_versions = write(&patience, &source.phase_versions)?;
        let global_versions = write(&patience, &source.global_versions)?;
        let prefixes = write(&patience, &source.app_shard_prefixes)?;
        let bit_paths = write(&patience, &source.app_shard_bit_paths)?;
        let shard_metadata = write(&patience, &source.shard_metadata)?;
        let sizes = write(&patience, &source.sub_meta)?;
        let covered = write(&patience, &source.covered_prefix)?;
        if *covered != state.covered {
            return Err(unavailable(
                "private execution changed node coverage policy",
            ));
        }
        Ok(PreparedCrdtAdoption {
            source,
            _forest: forest,
            roots,
            world_sizes,
            phase_versions,
            global_versions,
            prefixes,
            bit_paths,
            shard_metadata,
            sizes,
            covered,
            state: Some(state),
        })
    }
}

impl PreparedCrdtAdoption<'_> {
    /// Call only after the matching overlay has committed, while retaining its
    /// database write barrier. This does no I/O, locking or allocation.
    pub fn adopt(&mut self) {
        let Some(state) = self.state.take() else {
            return;
        };
        *self.roots = state.roots;
        *self.world_sizes = state.world_sizes;
        *self.phase_versions = state.phase_versions;
        *self.global_versions = state.global_versions;
        *self.prefixes = state.prefixes;
        *self.bit_paths = state.bit_paths;
        *self.shard_metadata = state.shard_metadata;
        *self.sizes = state.sizes;
        *self.covered = state.covered;
        self.source
            .forest_version
            .store(state.forest_version, Ordering::Release);
        self.source
            .unified_tree
            .store(state.unified, Ordering::Release);
        self.source.sizes_warmed.store(true, Ordering::Release);
    }
}
