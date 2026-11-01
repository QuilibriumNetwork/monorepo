//! Storage-proof snapshots (hash storage proofs, decided 2026-10-20; read at
//! certified roots from any copy of them, decided 2026-10-22).
//!
//! A hash registration binds `comm_D`, a commitment to each leaf's data. The
//! data is the shard's state at the roots GLOBAL recorded for the epoch
//! (`quil_execution::global_intrinsic::storage_snapshot`), read from each of
//! its snapshot sources at the version that had those roots: from this node's
//! own retained trees when it executed the shard through them, or else from the
//! source's subtree synced, pinned to them, from a node that retains it
//! ([`install_remote`]) — a joiner, a member of a shard a split or merge
//! creates, one that state-jumped. GLOBAL checks the registered data is that
//! state when it seals the registration (`storage_binding`), from the roots
//! alone: archives keep no snapshots.
//!
//! Leaves tile the shard by address bits: a subtree whose added vertices and
//! hyperedges sum to at most `LEAF_MAX_BYTES` is one leaf, a larger one splits
//! in two, and an empty shard has none. A leaf's data is every vertex and
//! hyperedge added under its bits, indexed
//! (`quil_execution::global_intrinsic::storage_binding::leaf_data`); GLOBAL
//! binds it to the roots it recorded when it seals the registration. The KZG leaf data instead selects by
//! six-bit nibbles of the vertex id, whose last app nibble pads the address's
//! first two bits with zeros, so a whole-shard leaf held only the addresses
//! starting `00` (found 2026-10-22; KZG epochs keep it).
//!
//! Capturing reads, encodes and hashes the leaves in the background
//! ([`request`]), so neither frame execution nor a confirm waits on it: in
//! the seat's lane of `crate::storage_jobs`, beside the other seats' as the
//! node's memory allows.

use std::sync::Arc;

use quil_execution::global_intrinsic::storage_snapshot::Source;
use quil_hypergraph::HypergraphCrdt;
use quil_store::replica_store::ReplicaStore;
use quil_types::error::{QuilError, Result};
use quil_types::store::ClockStore;
use tracing::{info, warn};

use quil_execution::global_intrinsic::storage_binding::{
    self as binding, Entry, LeafBinding, LeafClaim,
};

/// A snapshot source's subtree synced into a store of its own, kept for as
/// long as the capture reading it.
pub struct Synced {
    pub crdt: Arc<HypergraphCrdt>,
    pub keep: Box<dyn std::any::Any + Send + Sync>,
}

/// Sync the subtree of shard `filter` (`app`, `bits`) pinned to `roots` from
/// a node that retains it. Called from a storage job's thread.
pub type RemoteSnapshot =
    dyn Fn(&[u8], &[u8; 32], &[bool], &[[u8; 32]; 4]) -> Result<Synced> + Send + Sync;

static REMOTE: std::sync::OnceLock<Arc<RemoteSnapshot>> = std::sync::OnceLock::new();

/// Install this process's way to sync a snapshot source it does not hold.
/// The first call decides.
pub fn install_remote(remote: Arc<RemoteSnapshot>) {
    let _ = REMOTE.set(remote);
}

fn unavailable(what: String) -> QuilError {
    QuilError::ExecutionUnavailable(what)
}

/// A snapshot source as read: the store holding it, its shard's bits, and
/// each phase's version at its roots.
struct SourceAt {
    crdt: Arc<HypergraphCrdt>,
    bits: Vec<bool>,
    roots: [[u8; 32]; 4],
    versions: [Option<u64>; 4],
    _synced: Option<Box<dyn std::any::Any + Send + Sync>>,
}

/// One shard's data as of an epoch's snapshot.
pub struct Captured {
    pub epoch: u64,
    pub filter: Vec<u8>,
    /// The leaves, as [`leaf_prefix`]es: relative to the shard's bits.
    pub prefixes: Vec<Vec<u32>>,
    app: [u8; 32],
    bits: Vec<bool>,
    sources: Vec<SourceAt>,
    /// The sources as GLOBAL recorded them.
    plan: Vec<Source>,
}

/// `filter`'s snapshot as of `crdt`'s committed state: its current roots, as
/// GLOBAL would record them from a header proposed now. What a member labels
/// its leaves ahead from (`crate::storage_labels::precompute`).
pub fn current_source(crdt: &HypergraphCrdt, filter: &[u8], epoch: u64) -> Source {
    const PHASES: [(&str, &str); 4] = [
        ("vertex", "adds"),
        ("vertex", "removes"),
        ("hyperedge", "adds"),
        ("hyperedge", "removes"),
    ];
    let mut roots = [[0u8; 32]; 4];
    for (root, (set, phase)) in roots.iter_mut().zip(PHASES) {
        if let Ok(found) = <[u8; 32]>::try_from(
            crdt.sub_shard_commitment_for_filter(set, phase, filter)
                .as_slice(),
        ) {
            *root = found;
        }
    }
    Source {
        filter: filter.to_vec(),
        snapshot: quil_types::consensus::StorageSnapshotRoots {
            epoch,
            frame: 1,
            anchor: 1,
            roots,
        },
    }
}

/// A leaf's prefix: the bit-path tag, then its bits below the shard's.
pub fn leaf_prefix(relative: &[bool]) -> Vec<u32> {
    std::iter::once(quil_forest::BIT_PATH_PREFIX_SENTINEL)
        .chain(relative.iter().map(|&bit| bit as u32))
        .collect()
}

/// Read `filter`'s snapshot for `epoch` from its `sources`
/// (`storage_snapshot::sources`): from `crdt`, this node's own store, where
/// it retains a source at its roots, else synced ([`install_remote`]). The
/// shards' bits are decoded by `crdt`, which knows the app's grid.
pub fn capture_at(
    crdt: &Arc<HypergraphCrdt>,
    filter: &[u8],
    epoch: u64,
    sources: &[Source],
) -> Result<Captured> {
    let invalid = |what: &str| {
        QuilError::InvalidArgument(format!(
            "storage snapshot of {}: {what}",
            hex::encode(filter)
        ))
    };
    let app: [u8; 32] = filter
        .get(..32)
        .and_then(|app| app.try_into().ok())
        .ok_or_else(|| invalid("no app"))?;
    let bits = crdt
        .canonical_bits_for_filter(filter)
        .ok_or_else(|| invalid("undecodable filter"))?;
    if sources.is_empty() {
        return Err(invalid("no sources"));
    }
    let mut read = Vec::with_capacity(sources.len());
    for source in sources {
        if source.filter.get(..32) != Some(&app[..]) {
            return Err(invalid("a source in another app"));
        }
        let source_bits = crdt
            .canonical_bits_for_filter(&source.filter)
            .ok_or_else(|| invalid("undecodable source"))?;
        if !source_bits.starts_with(&bits) && !bits.starts_with(&source_bits) {
            return Err(invalid("a source outside the shard"));
        }
        let roots = &source.snapshot.roots;
        read.push(match crdt.snapshot_versions(&app, &source_bits, roots) {
            Some(versions) => SourceAt { crdt: crdt.clone(), bits: source_bits, roots: *roots, versions, _synced: None },
            None => {
                let remote = REMOTE.get().ok_or_else(|| unavailable(format!(
                    "the epoch {epoch} snapshot of {} is not retained here", hex::encode(&source.filter)
                )))?;
                let synced = remote(&source.filter, &app, &source_bits, roots)?;
                let versions = synced.crdt.snapshot_versions(&app, &source_bits, roots).ok_or_else(|| unavailable(format!(
                    "the synced subtree of {} does not have its epoch {epoch} snapshot roots", hex::encode(&source.filter)
                )))?;
                info!(epoch, filter = %hex::encode(filter), source = %hex::encode(&source.filter),
                    "storage snapshot source synced from a node that retains it");
                SourceAt { crdt: synced.crdt, bits: source_bits, roots: *roots, versions, _synced: Some(synced.keep) }
            }
        });
    }
    let mut captured = Captured {
        epoch,
        filter: filter.to_vec(),
        prefixes: Vec::new(),
        app,
        bits,
        sources: read,
        plan: sources.to_vec(),
    };
    captured.prefixes = captured
        .partition(crate::app_shard_metadata::LEAF_MAX_BYTES as u128)?
        .iter()
        .map(|relative| leaf_prefix(relative))
        .collect();
    Ok(captured)
}

impl Captured {
    /// The sources under `bits`, each with the deeper of its own bits and
    /// `bits` as the scope to read.
    fn scoped<'a>(&'a self, bits: &'a [bool]) -> impl Iterator<Item = (&'a SourceAt, &'a [bool])> {
        self.sources.iter().filter_map(move |source| {
            if source.bits.starts_with(bits) {
                Some((source, source.bits.as_slice()))
            } else if bits.starts_with(&source.bits) {
                Some((source, bits))
            } else {
                None
            }
        })
    }

    /// The summed size of the added vertices and hyperedges under `bits`.
    fn size(&self, bits: &[bool]) -> Result<u128> {
        let mut total = 0u128;
        for (source, scope) in self.scoped(bits) {
            for phase in binding::BOUND_PHASES {
                if let Some(version) = source.versions[phase as usize] {
                    total = total.saturating_add(source.crdt.unified_phase_size_at(
                        &self.app,
                        phase as usize,
                        version,
                        scope,
                    )?);
                }
            }
        }
        Ok(total)
    }

    /// The leaves, as bits below the shard's: a subtree of at most `max`
    /// bytes is one (an empty one too), a larger one splits in two, so they
    /// tile the shard; an empty shard has none.
    fn partition(&self, max: u128) -> Result<Vec<Vec<bool>>> {
        if self.size(&self.bits)? == 0 {
            return Ok(Vec::new());
        }
        let mut leaves = Vec::new();
        let mut pending = vec![Vec::new()];
        while let Some(relative) = pending.pop() {
            let bits = [self.bits.as_slice(), &relative].concat();
            if bits.len() >= 256 || self.size(&bits)? <= max {
                leaves.push(relative);
                continue;
            }
            pending.push([relative.as_slice(), &[true]].concat());
            pending.push([relative.as_slice(), &[false]].concat());
        }
        leaves.sort();
        Ok(leaves)
    }

    /// A leaf's absolute bits.
    fn leaf_bits(&self, prefix: &[u32]) -> Result<Vec<bool>> {
        let relative = quil_forest::shard_bit_path_from_prefix(prefix)
            .ok_or_else(|| QuilError::InvalidArgument("not a storage leaf prefix".into()))?;
        Ok([self.bits.as_slice(), &relative].concat())
    }

    /// The vertices and hyperedges added under a leaf's bits, each read from
    /// its source at its version, sorted by phase then address.
    pub fn entries(&self, prefix: &[u32]) -> Result<Vec<Entry>> {
        let bits = self.leaf_bits(prefix)?;
        let mut entries = Vec::new();
        for phase in binding::BOUND_PHASES {
            let start = entries.len();
            for (source, scope) in self.scoped(&bits) {
                if let Some(version) = source.versions[phase as usize] {
                    for (key, value) in source.crdt.unified_phase_entries_at(
                        &self.app,
                        phase as usize,
                        version,
                        scope,
                    )? {
                        let address: [u8; 32] = key
                            .get(32..)
                            .and_then(|a| a.try_into().ok())
                            .ok_or_else(|| {
                                QuilError::Internal("a vertex id without its address".into())
                            })?;
                        entries.push(Entry {
                            phase,
                            address,
                            value,
                        });
                    }
                }
            }
            entries[start..].sort_by(|a, b| a.address.cmp(&b.address));
        }
        Ok(entries)
    }

    /// A leaf's data ([`binding::leaf_data`]).
    pub fn leaf_data(&self, prefix: &[u32]) -> Result<Vec<u8>> {
        Ok(binding::leaf_data(
            &self.filter,
            prefix,
            &self.entries(prefix)?,
        ))
    }

    /// The claim GLOBAL checks a leaf's binding against, for `member` with
    /// the seal's `beacon` and the registration's data commitment and size.
    pub fn claim<'a>(
        &'a self,
        prefix: &'a [u32],
        leaf_id: &'a [u8],
        member: &'a [u8],
        beacon: &'a [u8],
        comm_d: [u8; 32],
        n: u64,
    ) -> Result<LeafClaim<'a>> {
        Ok(LeafClaim {
            filter: &self.filter,
            prefix,
            leaf_id,
            member,
            epoch: self.epoch,
            beacon,
            bits: self.leaf_bits(prefix)?,
            sources: self
                .sources
                .iter()
                .map(|source| (source.bits.clone(), source.roots))
                .collect(),
            comm_d,
            n,
        })
    }

    /// A raw-key proof of `address` in `phase` from the source holding it.
    fn proof(
        &self,
        phase: u8,
        address: &[u8; 32],
    ) -> Result<quil_forest::subtree_proof::CompactProof> {
        let source = self
            .sources
            .iter()
            .find(|source| binding::under(address, &source.bits))
            .ok_or_else(|| QuilError::InvalidArgument("an address no source holds".into()))?;
        match source.versions[phase as usize] {
            Some(version) => {
                source
                    .crdt
                    .unified_phase_proof_at(&self.app, phase as usize, version, address)
            }
            None => Ok(quil_forest::subtree_proof::CompactProof {
                leaf: None,
                siblings: Vec::new(),
            }),
        }
    }

    /// Prove the binding of the leaf `claim` describes (its prefix one of
    /// [`Self::prefixes`]): the data registered is this snapshot's.
    pub fn prove_binding(&self, claim: &LeafClaim) -> Result<LeafBinding> {
        let entries = self.entries(claim.prefix)?;
        let proof_of =
            |phase: u8, address: &[u8; 32]| self.proof(phase, address).map_err(|e| e.to_string());
        binding::prove(claim, &entries, &proof_of).map_err(QuilError::InvalidArgument)
    }

    /// The summed size of the vertices and hyperedges added under a leaf:
    /// its data less the index ([`Self::leaf_data`]).
    pub fn leaf_size(&self, prefix: &[u32]) -> Result<u128> {
        self.size(&self.leaf_bits(prefix)?)
    }
}

/// Peak bytes encoding a leaf of `nodes` nodes holds.
pub(crate) fn encoding_bytes(nodes: u64) -> u64 {
    quil_crypto::storage_proof::labelling_peak_bytes(nodes, &quil_crypto::sdr::SdrParams::default())
}

/// The data bytes of a leaf whose entries' values come to `size` bytes,
/// before it is read: a quarter more for the index, whose size the values'
/// does not tell.
fn estimated_leaf_bytes(size: u128) -> u64 {
    let size = u64::try_from(size).unwrap_or(u64::MAX);
    size.saturating_add(size / 4)
}

/// Peak bytes reading the data of a leaf whose values come to `size` holds:
/// its entries, then its data, about two and a half times the data.
pub(crate) fn leaf_read_bytes(size: u128) -> u64 {
    estimated_leaf_bytes(size).saturating_mul(5) / 2
}

/// How long a leaf's labelling or encode runs before it is reported as
/// running long, and how often again while it runs, at most once a seat.
const LEAF_PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// How often the running leaves are looked at for [`LEAF_PROGRESS_INTERVAL`].
const LEAF_PROGRESS_CHECK: std::time::Duration = std::time::Duration::from_secs(30);

/// A leaf whose labelling is estimated at least this long logs its start and
/// its end: shorter ones only the seat's summary.
const LEAF_LOGGED_FROM: std::time::Duration = std::time::Duration::from_secs(60);

/// Seconds labelling a GiB of a leaf's nodes takes on one core: measured on
/// a mainnet node on 2026-10-28, 16,182,813 nodes in 2,406 s (149
/// microseconds a node, 4,990 s a GiB). 3,600 left large leaves running past
/// their estimate and their renewal's grace.
const LABEL_SECONDS_PER_GIB: u64 = 5000;

/// What a running leaf does ([`leaf_started`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeafWork {
    /// Its snapshot encodes it from the labels kept ahead for it.
    FromLabelsAhead,
    /// Its snapshot labels it now: none were kept ahead that fit it.
    LabellingNow,
    /// It is labelled ahead of a later epoch's snapshot
    /// (`crate::storage_labels::precompute`); nothing waits for it yet.
    LabellingAhead,
}

/// How a leaf's work ended ([`LeafProgress::end`]), named on its
/// `storage leaf work ended` line: only `completed` labelled or encoded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafOutcome {
    /// Labelled or encoded to its end.
    Completed,
    /// Labelling ahead gave its memory back to more urgent work, keeping
    /// the whole layers it labelled, to go on from them once its memory fits
    /// again.
    Yielded,
    /// Labelling ahead gave up: GLOBAL reached its epoch's snapshot frame.
    Expired,
    /// Its snapshot was stopped: the renewal's grace frame passed, or a leaf
    /// of the seat could not be labelled by it.
    Grace,
    /// The node is stopping.
    Stopping,
    /// An error ended it.
    Failed,
}

impl LeafOutcome {
    fn name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Yielded => "yielded",
            Self::Expired => "expired",
            Self::Grace => "grace",
            Self::Stopping => "stopping",
            Self::Failed => "failed",
        }
    }
}

/// The outcome of a snapshot's leaf whose labelling was stopped: the node is
/// stopping, or else the seat's renewal's grace stopped it.
fn stop_outcome() -> LeafOutcome {
    if crate::storage_jobs::stopping() {
        LeafOutcome::Stopping
    } else {
        LeafOutcome::Grace
    }
}

impl LeafWork {
    fn name(self) -> &'static str {
        match self {
            Self::FromLabelsAhead => "encoding from labels kept ahead",
            Self::LabellingNow => "labelling now",
            Self::LabellingAhead => "labelling ahead",
        }
    }
}

/// About how long labelling a leaf of `nodes` nodes takes on one core.
pub fn label_estimate(nodes: u64) -> std::time::Duration {
    let bytes = u128::from(nodes) * quil_crypto::storage_proof::NODE_BYTES as u128;
    let seconds = bytes * u128::from(LABEL_SECONDS_PER_GIB) / (1u128 << 30);
    std::time::Duration::from_secs(u64::try_from(seconds).unwrap_or(u64::MAX))
}

/// [`label_estimate`] for the layers left of a leaf of `nodes` nodes, `kept`
/// of them kept on disk (`crate::storage_labels::LabelStore::resumable`).
fn label_estimate_from(nodes: u64, kept: usize) -> std::time::Duration {
    let layers = quil_crypto::sdr::SdrParams::default().layers;
    let left = u32::try_from(layers.saturating_sub(kept)).unwrap_or(u32::MAX);
    label_estimate(nodes) * left / u32::try_from(layers).unwrap_or(u32::MAX).max(1)
}

/// The frames left at GLOBAL frame `frame` to the renewal's grace frame for
/// `epoch` (`crate::app_shard_metadata::storage_snapshot_grace`) when
/// labelling a leaf of `nodes` nodes now, `kept` of its layers kept on disk,
/// would end past it by its estimate ([`label_estimate_from`]), a frame
/// taking the interval at `frame`
/// ([`quil_types::consensus::ideal_frame_time_ms_at`]) up to the grace frame;
/// `None` when it would end in time.
fn misses_grace(epoch: u64, nodes: u64, kept: usize, frame: u64) -> Option<u64> {
    let grace = quil_types::consensus::storage_snapshot_frame(epoch)
        .saturating_add(crate::app_shard_metadata::storage_snapshot_grace());
    let left = grace.saturating_sub(frame);
    let frame_millis = u128::from(quil_types::consensus::ideal_frame_time_ms_at(frame));
    let estimate = label_estimate_from(nodes, kept);
    (estimate.as_millis() > u128::from(left) * frame_millis).then_some(left)
}

/// Whether a leaf of `nodes` nodes labelled from `epoch`'s snapshot frame
/// would end by the renewal's grace frame by its estimate ([`misses_grace`]):
/// one that would not registers only from labels computed ahead.
pub(crate) fn labels_within_grace(epoch: u64, nodes: u64) -> bool {
    misses_grace(
        epoch,
        nodes,
        0,
        quil_types::consensus::storage_snapshot_frame(epoch),
    )
    .is_none()
}

/// A leaf being labelled or encoded.
struct RunningLeaf {
    epoch: u64,
    filter: Vec<u8>,
    nodes: u64,
    work: LeafWork,
    started: std::time::Instant,
    /// Its labelling's estimate; none when its labels were kept ahead.
    estimate: Option<std::time::Duration>,
    /// Its layers labelled when it started, now, and of how many
    /// ([`LeafProgress::layers`]); none when not reported.
    layers: Option<(usize, usize, usize)>,
    /// How long it paused ([`LeafProgress::paused`]).
    paused: std::time::Duration,
    /// Whether its start was logged, or it was reported running long: its
    /// end is logged then.
    logged: bool,
}

#[derive(Default)]
struct RunningLeaves {
    next: u64,
    leaves: std::collections::HashMap<u64, RunningLeaf>,
    /// When each seat's (epoch, shard, work) long leaves were last reported.
    reported: std::collections::HashMap<(u64, Vec<u8>, LeafWork), std::time::Instant>,
    /// Each leaf's epoch, shard, work and outcome as it ended, for tests.
    #[cfg(test)]
    ended: Vec<(u64, Vec<u8>, LeafWork, LeafOutcome)>,
}

fn running_leaves() -> std::sync::MutexGuard<'static, RunningLeaves> {
    static RUNNING: std::sync::OnceLock<std::sync::Mutex<RunningLeaves>> =
        std::sync::OnceLock::new();
    RUNNING
        .get_or_init(|| {
            if let Err(error) = std::thread::Builder::new()
                .name("storage-progress".into())
                .spawn(report_long_leaves)
            {
                warn!(%error, "storage leaf progress thread not started; long leaves are not reported while they run");
            }
            Default::default()
        })
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A leaf's work in progress ([`leaf_started`]); its end is logged when it
/// drops, if its start was or it ran long, with its outcome ([`Self::end`]).
#[must_use = "the leaf's work ends when this drops"]
pub struct LeafProgress {
    id: u64,
    outcome: Option<LeafOutcome>,
}

impl LeafProgress {
    /// End the leaf's work with `outcome`. Dropped without, it ended as the
    /// node stopped or at an error.
    pub fn end(mut self, outcome: LeafOutcome) {
        self.outcome = Some(outcome);
    }

    /// Note that `done` of the leaf's `of` layers are labelled. The first
    /// note says where its work starts (an attempt that gave up kept the
    /// layers before), and its estimate counts only the layers left.
    pub fn layers(&self, done: usize, of: usize) {
        if let Some(leaf) = running_leaves().leaves.get_mut(&self.id) {
            let from = match leaf.layers {
                Some((from, _, _)) => from,
                None => {
                    leaf.estimate = leaf.estimate.map(|estimate| {
                        estimate.mul_f64((of.saturating_sub(done)) as f64 / of.max(1) as f64)
                    });
                    done
                }
            };
            leaf.layers = Some((from, done, of));
        }
    }

    /// Note that the leaf's work paused for `paused` (labelling ahead beside
    /// a leaf labelled now,
    /// `crate::storage_jobs::Reservation::wait_while_paused`): its pace
    /// counts only the time it ran.
    pub fn paused(&self, paused: std::time::Duration) {
        if let Some(leaf) = running_leaves().leaves.get_mut(&self.id) {
            leaf.paused += paused;
        }
    }
}

/// How long a leaf labelled ahead has still to run: at the pace of its
/// layers labelled since it started, or by its estimate before its first,
/// not counting the time it paused.
fn remaining_ahead(leaf: &RunningLeaf) -> std::time::Duration {
    let elapsed = leaf.started.elapsed().saturating_sub(leaf.paused);
    match leaf.layers {
        Some((from, done, of)) if done > from => {
            elapsed.mul_f64(of.saturating_sub(done) as f64 / (done - from) as f64)
        }
        _ => leaf.estimate.unwrap_or_default().saturating_sub(elapsed),
    }
}

/// How long until GLOBAL reaches `epoch`'s snapshot frame, from which
/// labelling ahead for it is of no use (`crate::storage_labels`); `None`
/// while this process has seen no GLOBAL frame.
fn until_snapshot_frame(epoch: u64) -> Option<std::time::Duration> {
    let frame = global_frame()?;
    let frames = quil_types::consensus::storage_snapshot_frame(epoch).saturating_sub(frame);
    Some(std::time::Duration::from_millis(frames.saturating_mul(
        quil_types::consensus::ideal_frame_time_ms_at(frame),
    )))
}

/// Track `member`'s leaf `leaf_id` of shard `filter` for `epoch`, of `nodes`
/// nodes, while its `work` runs: its start and end are logged when its
/// labelling is estimated at [`LEAF_LOGGED_FROM`] or more, and every
/// [`LEAF_PROGRESS_INTERVAL`] it runs a line reports its seat's long leaves.
pub fn leaf_started(
    epoch: u64,
    filter: &[u8],
    leaf_id: &[u8],
    nodes: u64,
    work: LeafWork,
) -> LeafProgress {
    let estimate = (work != LeafWork::FromLabelsAhead).then(|| label_estimate(nodes));
    let logged = estimate.is_some_and(|estimate| estimate >= LEAF_LOGGED_FROM);
    if logged {
        info!(epoch, filter = %hex::encode(filter), leaf = %hex::encode(leaf_id), nodes,
            work = work.name(), estimated_minutes = estimate.map_or(0, |e| e.as_secs() / 60),
            scope = "local", "storage leaf work started");
    }
    let mut running = running_leaves();
    let id = running.next;
    running.next += 1;
    running.leaves.insert(
        id,
        RunningLeaf {
            epoch,
            filter: filter.to_vec(),
            nodes,
            work,
            started: std::time::Instant::now(),
            estimate,
            layers: None,
            paused: std::time::Duration::ZERO,
            logged,
        },
    );
    LeafProgress { id, outcome: None }
}

impl Drop for LeafProgress {
    fn drop(&mut self) {
        let Some(leaf) = running_leaves().leaves.remove(&self.id) else {
            return;
        };
        let outcome = self.outcome.unwrap_or_else(|| {
            if crate::storage_jobs::stopping() {
                LeafOutcome::Stopping
            } else {
                LeafOutcome::Failed
            }
        });
        #[cfg(test)]
        running_leaves()
            .ended
            .push((leaf.epoch, leaf.filter.clone(), leaf.work, outcome));
        if leaf.logged {
            info!(epoch = leaf.epoch, filter = %hex::encode(&leaf.filter), nodes = leaf.nodes,
                work = leaf.work.name(), seconds = leaf.started.elapsed().as_secs(),
                outcome = outcome.name(), scope = "local", "storage leaf work ended");
        }
    }
}

/// The leaves of a seat's snapshot still running: how many, and at least how
/// long the longest has left by its estimate, and whether any labels now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SnapshotProgress {
    pub leaves: usize,
    pub remaining: std::time::Duration,
    pub labelling_now: bool,
}

/// [`SnapshotProgress`] of the snapshot leaves of `filters` for `epoch`
/// running now; `None` when none is (queued, waiting for memory, or done).
pub fn snapshot_progress(filters: &[Vec<u8>], epoch: u64) -> Option<SnapshotProgress> {
    let running = running_leaves();
    let mut progress = SnapshotProgress::default();
    for leaf in running.leaves.values().filter(|leaf| {
        leaf.epoch == epoch
            && leaf.work != LeafWork::LabellingAhead
            && filters.contains(&leaf.filter)
    }) {
        progress.leaves += 1;
        progress.labelling_now |= leaf.work == LeafWork::LabellingNow;
        if let Some(estimate) = leaf.estimate {
            progress.remaining = progress
                .remaining
                .max(estimate.saturating_sub(leaf.started.elapsed()));
        }
    }
    (progress.leaves > 0).then_some(progress)
}

/// Report, every [`LEAF_PROGRESS_INTERVAL`] at most once a seat, the leaves
/// running longer than it: a renewal waits for a snapshot's.
fn report_long_leaves() {
    loop {
        std::thread::sleep(LEAF_PROGRESS_CHECK);
        #[derive(Default)]
        struct Seat {
            leaves: usize,
            nodes: u64,
            longest: std::time::Duration,
            estimate: Option<std::time::Duration>,
            /// Of leaves labelled ahead, the most any has still to run.
            remaining: std::time::Duration,
        }
        let mut seats: std::collections::BTreeMap<(u64, Vec<u8>, LeafWork), Seat> =
            Default::default();
        {
            let mut running = running_leaves();
            let RunningLeaves {
                leaves, reported, ..
            } = &mut *running;
            for leaf in leaves.values_mut() {
                let elapsed = leaf.started.elapsed();
                if elapsed < LEAF_PROGRESS_INTERVAL {
                    continue;
                }
                let key = (leaf.epoch, leaf.filter.clone(), leaf.work);
                if reported
                    .get(&key)
                    .is_some_and(|at| at.elapsed() < LEAF_PROGRESS_INTERVAL)
                {
                    continue;
                }
                leaf.logged = true;
                let seat = seats.entry(key).or_default();
                seat.leaves += 1;
                seat.nodes += leaf.nodes;
                if elapsed >= seat.longest {
                    seat.longest = elapsed;
                    seat.estimate = leaf.estimate;
                }
                if leaf.work == LeafWork::LabellingAhead {
                    seat.remaining = seat.remaining.max(remaining_ahead(leaf));
                }
            }
            let now = std::time::Instant::now();
            reported.retain(|_, at| at.elapsed() < LEAF_PROGRESS_INTERVAL * 2);
            for key in seats.keys() {
                reported.insert(key.clone(), now);
            }
        }
        for ((epoch, filter, work), seat) in seats {
            let estimated = seat
                .estimate
                .map_or_else(|| "unknown".to_string(), |e| (e.as_secs() / 60).to_string());
            let (longest, filter) = (seat.longest.as_secs() / 60, hex::encode(&filter));
            let overrun = seat.estimate.is_some_and(|e| seat.longest > e);
            let grace_frame = quil_types::consensus::storage_snapshot_frame(epoch)
                .saturating_add(crate::app_shard_metadata::storage_snapshot_grace());
            // Labelling ahead runs past its estimate on a busy node without
            // harm; it matters only once it would end past the snapshot
            // frame, where it is given up.
            let left = until_snapshot_frame(epoch);
            let late = left.is_some_and(|left| seat.remaining > left);
            let (remaining, left) = (
                seat.remaining.as_secs() / 60,
                left.map_or_else(
                    || "unknown".to_string(),
                    |left| (left.as_secs() / 60).to_string(),
                ),
            );
            match work {
                LeafWork::LabellingAhead if !late => info!(epoch, filter = %filter,
                    leaves = seat.leaves, nodes = seat.nodes, longest_minutes = longest,
                    estimated_minutes = %estimated, remaining_minutes = remaining,
                    minutes_to_snapshot_frame = %left, work = work.name(), scope = "local",
                    "storage labels for a later epoch's snapshot still being computed ahead; \
                     nothing waits for them yet"),
                LeafWork::LabellingAhead => warn!(epoch, filter = %filter,
                    leaves = seat.leaves, nodes = seat.nodes, longest_minutes = longest,
                    estimated_minutes = %estimated, remaining_minutes = remaining,
                    minutes_to_snapshot_frame = %left, work = work.name(), scope = "local",
                    action = "check this node's CPU load and how many large leaves it labels \
                              at once: at its pace the labelling ends after the epoch's snapshot \
                              frame, where it is given up, and a leaf its snapshot cannot label \
                              within the renewal's grace then renews without a registration",
                    "storage labels for a later epoch's snapshot would end past its snapshot frame"),
                // Within its estimate (or with none, from labels kept
                // ahead) this is the expected wait of a renewal.
                _ if !overrun => info!(epoch, filter = %filter, leaves = seat.leaves,
                    nodes = seat.nodes, longest_minutes = longest, estimated_minutes = %estimated,
                    grace_frame, work = work.name(), scope = "local",
                    action = "no action needed: the seat's renewal registers its storage once \
                              they end; this warns if they pass their estimate",
                    "this node is still preparing a seat's storage proof data; its renewal waits for it"),
                _ => warn!(epoch, filter = %filter, leaves = seat.leaves, nodes = seat.nodes,
                    longest_minutes = longest, estimated_minutes = %estimated, grace_frame,
                    work = work.name(), scope = "local",
                    action = "check this node's CPU and disk load: storage labelling is CPU-bound; \
                              if the leaves have not ended by the grace frame, the seat renews \
                              without a storage registration and earns no storage share that epoch",
                    "this node's storage proof data for a seat runs past its estimate; its renewal waits for it"),
            }
        }
    }
}

/// A member's sink: encode each leaf into its replica for `member` and store it
/// with its cap and registration root, then the partition, which marks the
/// epoch's leaves ready for the renewal to register. The leaves encode side by
/// side, each once the memory it takes is free (`crate::storage_jobs`), from
/// the labels kept ahead for it when they fit its data (`crate::storage_labels`):
/// otherwise it is labelled now, going on from the whole layers kept on disk
/// at a count its data may register (labelled ahead, or by this snapshot
/// before a restart), its labels kept for its seal when their filesystem has
/// room for them.
pub fn encode_member(captured: &Captured, member: &[u8], replicas: &ReplicaStore) -> Result<()> {
    encode_member_with(
        captured,
        member,
        replicas,
        crate::storage_labels::installed(),
    )
}

/// [`encode_member`] with the labels of `store`.
fn encode_member_with(
    captured: &Captured,
    member: &[u8],
    replicas: &ReplicaStore,
    store: Option<&crate::storage_labels::LabelStore>,
) -> Result<()> {
    encode_member_until(captured, member, replicas, store, &|| false)
}

/// [`encode_member_with`], given up once `stop` says so: looked at before
/// each leaf, while it waits for its memory and once it has it, and while it
/// is labelled. A leaf given up keeps the whole layers it labelled for the
/// next attempt, after a restart say, unless the renewal's grace passed or
/// the seat was given up. Removes the labels of earlier epochs first.
fn encode_member_until(
    captured: &Captured,
    member: &[u8],
    replicas: &ReplicaStore,
    store: Option<&crate::storage_labels::LabelStore>,
    stop: &(dyn Fn() -> bool + Sync),
) -> Result<()> {
    use crate::storage_labels::{Labelling, Stage};
    use quil_crypto::storage_proof::{data_node_count, padded_nodes_allowed};
    let params = quil_crypto::sdr::SdrParams::default();
    let started = std::time::Instant::now();
    let stopped = || unavailable("the storage snapshot's encode was stopped".into());
    if let Some(store) = store {
        store.sweep(captured.epoch);
    }
    let encoded = crate::storage_jobs::for_each_parallel(&captured.prefixes, |prefix| {
        let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(&captured.filter, prefix);
        if stop() {
            return Err(stopped());
        }
        let size = captured.leaf_size(prefix)?;
        // A leaf's data is at least its values (`Captured::leaf_size`), so a
        // leaf with no labels kept at that many nodes or more is labelled now
        // at no fewer. When even that many cannot be labelled by the
        // renewal's grace frame, its seat is given up before the leaf asks
        // for memory: waiting for it, the leaf would hold its place before
        // other seats' leaves and make labelling ahead give its memory back,
        // for nothing (2026-11-01: ten seats' large leaves waited for memory
        // through the grace each epoch, and none was labelled ahead).
        let least = data_node_count(u64::try_from(size).unwrap_or(u64::MAX));
        let may_be_kept = store.is_some_and(|store| {
            store
                .find(captured.epoch, member, &leaf_id, |n| n >= least)
                .is_some()
        });
        // Whole layers kept on disk shorten what is left to label.
        let kept_least = store
            .and_then(|store| store.resumable(captured.epoch, member, &leaf_id, |n| n >= least))
            .map_or(0, |(_, layers)| layers);
        if !may_be_kept
            && gives_up_late_leaf(
                captured,
                member,
                &leaf_id,
                least,
                kept_least,
                LeafCount::Least,
            )
        {
            return Err(stopped());
        }
        // A leaf whose seat's renewal is past its grace leaves the queue for
        // memory, where it would hold its place before other seats' leaves.
        let memory = crate::storage_jobs::reserve_until(
            encoding_bytes(data_node_count(estimated_leaf_bytes(size))),
            stop,
        );
        let Some(mut memory) = memory.filter(|_| !stop()) else {
            return Err(stopped());
        };
        let data = captured.leaf_data(prefix)?;
        let exact = data_node_count(data.len() as u64);
        let ahead = store.and_then(|store| {
            store.find(captured.epoch, member, &leaf_id, |n| {
                padded_nodes_allowed(exact, n)
            })
        });
        // Else the leaf is labelled at the count its data may register
        // with the most whole layers kept on disk, or at its own.
        let (count, kept) = match (&ahead, store) {
            (None, Some(store)) => store
                .resumable(captured.epoch, member, &leaf_id, |n| {
                    padded_nodes_allowed(exact, n)
                })
                .unwrap_or((exact, 0)),
            _ => (exact, 0),
        };
        let nodes = ahead.as_ref().map_or(count, |kept| kept.n);
        memory.resize(encoding_bytes(nodes));
        // A leaf to label now that cannot end by the renewal's grace frame
        // would hold its memory for nothing: its seat renews without it.
        if ahead.is_none()
            && gives_up_late_leaf(captured, member, &leaf_id, count, kept, LeafCount::Exact)
        {
            return Err(stopped());
        }
        let progress = leaf_started(
            captured.epoch,
            &captured.filter,
            &leaf_id,
            nodes,
            if ahead.is_some() {
                LeafWork::FromLabelsAhead
            } else {
                LeafWork::LabellingNow
            },
        );
        let from_kept = ahead.and_then(|kept| {
            use quil_crypto::storage_proof::LabelSource as _;
            let last = kept.last_layer()?;
            quil_crypto::storage_proof::encode_with_labels(&data, kept.n, &last, kept.comm_c).ok()
        });
        let ahead = from_kept.is_some();
        if !ahead {
            // Labelled now: labelling ahead beside it pauses but for
            // `crate::storage_jobs::AHEAD_JOBS_BESIDE_DUE` of it.
            memory.labelling_now();
        }
        // Labelled now and kept when there is room; otherwise encoded as by a
        // process that keeps no labels, and its seal labels it again.
        let mut resumed = 0;
        let labelled = match (&from_kept, store) {
            (None, Some(store)) => {
                match store.admit(captured.epoch, member, &leaf_id, count, Stage::Snapshot) {
                    Some(admitted) => {
                        let layers = params.layers;
                        if let Some(kept) = admitted.resumed() {
                            resumed = kept.layers;
                            info!(epoch = captured.epoch,
                                filter = %hex::encode(&captured.filter),
                                leaf = %hex::encode(&leaf_id), nodes = count,
                                layers_reused = kept.layers, layers,
                                verified_bytes = kept.bytes,
                                verify_seconds = kept.took.as_secs_f64(),
                                kept_by = kept.kept_by.name(), scope = "local",
                                "storage snapshot goes on labelling a leaf from the whole layers \
                                 kept on disk, each checked against its digest: labelled ahead, \
                                 or by this snapshot before a restart");
                        }
                        progress.layers(admitted.resumes_from(), layers);
                        let labelling = admitted
                            .label_kept(&params, stop, &|done| progress.layers(done, layers))?;
                        match labelling {
                            Labelling::Labelled(labelled) => Some((count, labelled)),
                            Labelling::Stopped { .. } => {
                                // Kept for the next attempt unless the seat
                                // renews without them.
                                if grace_passed(member, captured.epoch)
                                    || snapshot_given_up(member, &captured.filter, captured.epoch)
                                {
                                    store.discard(captured.epoch, member, &leaf_id, count);
                                }
                                progress.end(stop_outcome());
                                return Err(stopped());
                            }
                        }
                    }
                    None => None,
                }
            }
            _ => None,
        };
        let encoded = match from_kept {
            Some(encoded) => encoded,
            None => {
                let (n, last, comm_c) = match labelled {
                    Some((n, labelled)) => (n, labelled.last, labelled.comm_c),
                    None => {
                        // As by a process that keeps no labels
                        // (`quil_crypto::storage_proof::encode_leaf`).
                        let Some((last, columns)) = quil_crypto::storage_proof::label_leaf_until(
                            exact,
                            &quil_crypto::sdr::replica_key(member, &leaf_id, captured.epoch),
                            &params,
                            &mut |_, _| {},
                            stop,
                        ) else {
                            progress.end(stop_outcome());
                            return Err(stopped());
                        };
                        let comm_c = quil_crypto::storage_proof::MerkleTree::from_digests(columns)
                            .commitment(quil_crypto::storage_proof::Tree::Column);
                        (exact, last, comm_c)
                    }
                };
                quil_crypto::storage_proof::encode_with_labels(&data, n, &last, comm_c)
                    .map_err(QuilError::Internal)?
            }
        };
        drop(data);
        // Layers kept at other counts are of no use any more.
        if let Some(store) = store {
            store.discard_others(captured.epoch, member, &leaf_id, encoded.n);
        }
        replicas.put_hash(
            captured.epoch,
            &leaf_id,
            &encoded.replica,
            &encoded.replica_cap.to_bytes(),
            &encoded.registration_root(),
        )?;
        progress.end(LeafOutcome::Completed);
        Ok((encoded.n, ahead, resumed))
    })?;
    info!(epoch = captured.epoch, filter = %hex::encode(&captured.filter), leaves = encoded.len(),
        labelled_ahead = encoded.iter().filter(|(_, ahead, _)| *ahead).count(),
        layers_resumed = encoded.iter().map(|(.., resumed)| resumed).sum::<usize>(),
        nodes = encoded.iter().map(|(n, ..)| n).sum::<u64>(), seconds = started.elapsed().as_secs(),
        "storage snapshot leaves encoded");
    let nodes: Vec<u64> = encoded.iter().map(|(n, ..)| *n).collect();
    let plan = quil_execution::global_intrinsic::storage_snapshot::encode_plan(&[(
        captured.filter.clone(),
        captured.plan.clone(),
    )]);
    replicas.put_snapshot_sources(captured.epoch, &captured.filter, &plan)?;
    replicas.put_leaf_nodes(captured.epoch, &captured.filter, &nodes)?;
    replicas.put_partition(captured.epoch, &captured.filter, &captured.prefixes)
}

/// How a leaf's nodes were counted for [`gives_up_late_leaf`].
#[derive(Debug, Clone, Copy)]
enum LeafCount {
    /// From its values, before its data is read: the fewest it can take.
    Least,
    /// From its data.
    Exact,
}

/// Give up `member`'s snapshot of `captured` when labelling its leaf
/// `leaf_id` of `nodes` nodes now would end past the renewal's grace frame by
/// its estimate ([`misses_grace`]): true when it is given up, warned once a
/// seat ([`give_up_snapshot`]). False while this process has seen no GLOBAL
/// frame.
fn gives_up_late_leaf(
    captured: &Captured,
    member: &[u8],
    leaf_id: &[u8],
    nodes: u64,
    kept: usize,
    counted: LeafCount,
) -> bool {
    let Some(frame) = global_frame() else {
        return false;
    };
    let Some(frames_left) = misses_grace(captured.epoch, nodes, kept, frame) else {
        return false;
    };
    if give_up_snapshot(member, &captured.filter, captured.epoch) {
        let counted = match counted {
            LeafCount::Least => "at least, from its values before its data is read",
            LeafCount::Exact => "from its data",
        };
        warn!(epoch = captured.epoch, filter = %hex::encode(&captured.filter),
            leaf = %hex::encode(leaf_id), nodes, counted, layers_kept = kept,
            estimated_minutes = label_estimate_from(nodes, kept).as_secs() / 60, frames_left,
            global_frame = frame, scope = "local",
            action = "check this node's CPU headroom and how many seats it labels at \
                      once; the next epoch's snapshot starts again",
            "storage snapshot given up: this node would finish a seat's storage proof data \
             after the renewal's grace frame, so the seat renews without a storage \
             registration and earns no storage share on its shard this epoch");
    }
    true
}

/// Snapshots this process's members encoded, kept for their seals' bindings
/// (a synced source's scratch store with them).
fn kept() -> &'static std::sync::Mutex<std::collections::HashMap<(Vec<u8>, u64), Arc<Captured>>> {
    static KEPT: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<(Vec<u8>, u64), Arc<Captured>>>,
    > = std::sync::OnceLock::new();
    KEPT.get_or_init(Default::default)
}

/// Whether this process encoded `filter`'s snapshot for `epoch` (kept for
/// its seal): labels computed ahead for that epoch would come too late.
pub(crate) fn snapshot_encoded(filter: &[u8], epoch: u64) -> bool {
    kept()
        .lock()
        .is_ok_and(|kept| kept.contains_key(&(filter.to_vec(), epoch)))
}

/// Members and epochs whose renewal's grace frame passed
/// ([`note_grace_passed`]).
fn graces_passed() -> std::sync::MutexGuard<'static, std::collections::HashSet<(Vec<u8>, u64)>> {
    static PASSED: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashSet<(Vec<u8>, u64)>>,
    > = std::sync::OnceLock::new();
    PASSED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Record that `member`'s confirm for `epoch` reached its renewal's grace
/// frame (`crate::app_shard_metadata::storage_snapshot_grace`): a seat whose
/// snapshot is not encoded by then renews without a storage registration,
/// so its encode is not started, and one running stops ([`request_member`]).
pub fn note_grace_passed(member: &[u8], epoch: u64) {
    let mut passed = graces_passed();
    if passed.contains(&(member.to_vec(), epoch)) {
        return;
    }
    passed.retain(|(_, e)| e.saturating_add(2) >= epoch);
    passed.insert((member.to_vec(), epoch));
}

/// Whether `member`'s renewal's grace frame for `epoch` passed
/// ([`note_grace_passed`]).
pub fn grace_passed(member: &[u8], epoch: u64) -> bool {
    graces_passed().contains(&(member.to_vec(), epoch))
}

/// Seats' snapshots given up before their renewal's grace frame
/// ([`give_up_snapshot`]): member, shard and epoch.
type GivenUp = std::collections::HashSet<(Vec<u8>, Vec<u8>, u64)>;

fn snapshots_given_up() -> std::sync::MutexGuard<'static, GivenUp> {
    static GIVEN_UP: std::sync::OnceLock<std::sync::Mutex<GivenUp>> = std::sync::OnceLock::new();
    GIVEN_UP
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Give up `member`'s snapshot of `filter` for `epoch`: a leaf of it could
/// not be labelled by the renewal's grace frame ([`misses_grace`]). Its
/// encode stops ([`request_member`]) and its seat renews without a storage
/// registration at once (`crate::app_shard_metadata`), its memory going to
/// other seats. False when it already was given up.
fn give_up_snapshot(member: &[u8], filter: &[u8], epoch: u64) -> bool {
    let mut given_up = snapshots_given_up();
    given_up.retain(|(_, _, e)| e.saturating_add(2) >= epoch);
    given_up.insert((member.to_vec(), filter.to_vec(), epoch))
}

/// Whether `member`'s snapshot of `filter` for `epoch` was given up
/// ([`give_up_snapshot`]).
pub fn snapshot_given_up(member: &[u8], filter: &[u8], epoch: u64) -> bool {
    snapshots_given_up().contains(&(member.to_vec(), filter.to_vec(), epoch))
}

/// The latest GLOBAL frame this process saw ([`note_global_frame`]); 0 until
/// it saw one.
static GLOBAL_FRAME: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Note that GLOBAL reached `frame` (an app shard's engine notes each GLOBAL
/// frame, a renewal its own): labelling ahead for an epoch whose snapshot
/// frame it reached gives up (`crate::storage_labels::precompute`), and a
/// snapshot's leaf that cannot be labelled by the renewal's grace frame is
/// not started ([`misses_grace`]).
pub fn note_global_frame(frame: u64) {
    GLOBAL_FRAME.fetch_max(frame, std::sync::atomic::Ordering::Relaxed);
    quil_types::consensus::note_frame_time_head(frame);
}

/// The latest GLOBAL frame this process saw ([`note_global_frame`]), if any.
pub fn global_frame() -> Option<u64> {
    let frame = GLOBAL_FRAME.load(std::sync::atomic::Ordering::Relaxed);
    (frame > 0).then_some(frame)
}

/// Note, before evicting the replicas below
/// `replica_keep_from(current_epoch)`, that GLOBAL reached `current_epoch`:
/// an epoch's replicas go only once its settlement window has ended, and a
/// settlement that finds them gone must see that ([`settlement_closed`]).
pub fn note_replica_eviction(current_epoch: u64) {
    note_global_frame(quil_types::consensus::epoch_start_frame(current_epoch));
}

/// Whether GLOBAL can no longer record a settlement of `epoch`: `frame` or
/// the latest GLOBAL frame this process saw ([`global_frame`]) is past its
/// settlement window, which GLOBAL enforces. A seat's slot and the frame a
/// proof runs from may trail that frame (a GLOBAL stall, a registry view a
/// pull behind), while the replicas of `epoch` are already evicted
/// ([`note_replica_eviction`]): a settlement they still show owed can be
/// neither prepared nor recorded.
pub fn settlement_closed(epoch: u64, frame: u64) -> bool {
    let (_, until) = quil_execution::global_intrinsic::storage_seat::settlement_window(epoch);
    global_frame().unwrap_or(0).max(frame) >= until
}

fn keep(captured: Arc<Captured>) {
    if let Ok(mut kept) = kept().lock() {
        // A registration is sealed before its epoch begins.
        let newest = kept
            .keys()
            .map(|(_, epoch)| *epoch)
            .max()
            .unwrap_or(0)
            .max(captured.epoch);
        kept.retain(|(_, epoch), _| epoch + 2 >= newest);
        kept.insert((captured.filter.clone(), captured.epoch), captured);
    }
}

/// The snapshot `filter`'s registration for `epoch` was encoded from: kept
/// since, or taken again from the sources recorded with it
/// (`ReplicaStore::put_snapshot_sources`), as after a restart.
pub fn captured_for(
    crdt: &Arc<HypergraphCrdt>,
    replicas: &ReplicaStore,
    filter: &[u8],
    epoch: u64,
) -> Result<Arc<Captured>> {
    if let Some(captured) = kept()
        .lock()
        .ok()
        .and_then(|kept| kept.get(&(filter.to_vec(), epoch)).cloned())
    {
        return Ok(captured);
    }
    let plan = replicas
        .get_snapshot_sources(epoch, filter)?
        .ok_or_else(|| {
            unavailable(format!(
                "no recorded snapshot sources of {} for epoch {epoch}",
                hex::encode(filter)
            ))
        })?;
    let sources = quil_execution::global_intrinsic::storage_snapshot::decode_plan(&plan)
        .and_then(|plan| plan.into_iter().find(|(shard, _)| shard == filter))
        .map(|(_, sources)| sources)
        .ok_or_else(|| QuilError::InvalidArgument("undecodable snapshot sources".into()))?;
    let captured = Arc::new(capture_at(crdt, filter, epoch, &sources)?);
    keep(captured.clone());
    Ok(captured)
}

/// Capture `filter`'s snapshot for `epoch` from `sources` and encode
/// `member`'s replicas of it into `replicas`, in the background ([`request`]),
/// in the lane of the seat whose shard is `seat` (its own, or the one a
/// change creates `filter` from).
pub fn request_member(
    crdt: Arc<HypergraphCrdt>,
    replicas: ReplicaStore,
    member: Vec<u8>,
    seat: &[u8],
    filter: Vec<u8>,
    epoch: u64,
    sources: Vec<Source>,
) {
    let key = [b"member".as_slice(), &member, &filter, &epoch.to_be_bytes()].concat();
    request(seat, key, "member", move || {
        let past_grace = || {
            info!(epoch, filter = %hex::encode(&filter), scope = "local",
                "storage snapshot not encoded: the renewal's grace frame passed, so this seat renews \
                 without a storage registration and earns no storage share on its shard that epoch; \
                 its memory goes to other storage work");
            Ok(())
        };
        if grace_passed(&member, epoch) {
            return past_grace();
        }
        if snapshot_given_up(&member, &filter, epoch) {
            return Ok(());
        }
        let captured = capture_at(&crdt, &filter, epoch, &sources)?;
        info!(epoch, leaves = captured.prefixes.len(), filter = %hex::encode(&filter),
            "storage snapshot taken for the epoch's registration");
        let stop = || {
            grace_passed(&member, epoch)
                || snapshot_given_up(&member, &filter, epoch)
                || crate::storage_jobs::stopping()
        };
        match encode_member_until(
            &captured,
            &member,
            &replicas,
            crate::storage_labels::installed(),
            &stop,
        ) {
            Err(_) if grace_passed(&member, epoch) => return past_grace(),
            // Logged as it was given up (`encode_member_until`).
            Err(_) if snapshot_given_up(&member, &filter, epoch) => return Ok(()),
            result => result?,
        }
        keep(Arc::new(captured));
        Ok(())
    });
}

/// GLOBAL frames a member waits before proving a seat's epoch proof again
/// while GLOBAL has not recorded it: 48 on mainnet (about ten minutes), and
/// at least 4 on a test network's short epochs.
pub fn seal_retry_frames() -> u64 {
    (quil_types::consensus::epoch_length_frames() / 15).max(4)
}

type Attempts = std::collections::HashMap<(Vec<u8>, Vec<u8>, u64), (u64, u32)>;

fn epoch_proof_attempts() -> &'static std::sync::Mutex<Attempts> {
    static ATTEMPTS: std::sync::OnceLock<std::sync::Mutex<Attempts>> = std::sync::OnceLock::new();
    ATTEMPTS.get_or_init(Default::default)
}

/// The GLOBAL frame `(member, filter)`'s last epoch proof part settling
/// `epoch` was sent at ([`claim_epoch_proof`]), if one was.
pub fn epoch_proof_sent_at(member: &[u8], filter: &[u8], epoch: u64) -> Option<u64> {
    let attempts = epoch_proof_attempts().lock().ok()?;
    attempts
        .get(&(member.to_vec(), filter.to_vec(), epoch))
        .map(|(at, _)| *at)
}

/// Claim proving `(member, filter)`'s epoch proof settling `epoch` at GLOBAL
/// frame `global_frame`: the attempt's number from 1, or `None` while an
/// attempt made within [`seal_retry_frames`] may still land.
pub fn claim_epoch_proof(
    member: &[u8],
    filter: &[u8],
    epoch: u64,
    global_frame: u64,
) -> Option<u32> {
    let mut attempts = epoch_proof_attempts().lock().ok()?;
    attempts.retain(|(_, _, e), _| *e >= epoch.saturating_sub(1));
    let key = (member.to_vec(), filter.to_vec(), epoch);
    let previous = attempts.get(&key).copied();
    if previous.is_some_and(|(at, _)| global_frame < at.saturating_add(seal_retry_frames())) {
        return None;
    }
    let attempt = previous.map_or(1, |(_, n)| n + 1);
    attempts.insert(key, (global_frame, attempt));
    Some(attempt)
}

/// Restart the retry clock of `(member, filter)`'s epoch proof settling
/// `epoch` at the latest GLOBAL frame this process saw ([`global_frame`]):
/// its part, or the node's proof carrying it, just went out, and GLOBAL needs
/// [`seal_retry_frames`] from then to record it. Claimed long before (a seal
/// relabelling, the node's batch waiting for other seats), a part was sent
/// again a minute after its proof landed, and GLOBAL refused it as settling
/// an epoch already settled.
pub fn note_epoch_proof_published(member: &[u8], filter: &[u8], epoch: u64) {
    let Some(frame) = global_frame() else {
        return;
    };
    if let Ok(mut attempts) = epoch_proof_attempts().lock() {
        if let Some((at, _)) = attempts.get_mut(&(member.to_vec(), filter.to_vec(), epoch)) {
            *at = (*at).max(frame);
        }
    }
}

/// This member's replicas of a seat's registered leaves for `epoch`, as its
/// commitments open them and its epoch proof proves them.
pub struct HeldReplicas {
    pub leaves: Vec<quil_execution::global_intrinsic::storage_epoch_proof::HeldLeaf>,
    stored: Vec<(
        quil_store::replica_store::HashReplica,
        quil_crypto::storage_proof::MerkleCap,
    )>,
}

impl HeldReplicas {
    pub fn load(
        replicas: &ReplicaStore,
        filter: &[u8],
        epoch: u64,
        leaves: &[Vec<u32>],
    ) -> Result<Self> {
        use quil_types::error::QuilError;
        let mut held = Self {
            leaves: Vec::new(),
            stored: Vec::new(),
        };
        for prefix in leaves {
            let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(filter, prefix);
            let stored = replicas.get_hash(epoch, &leaf_id)?.ok_or_else(|| {
                QuilError::ExecutionUnavailable(format!(
                    "no stored replica of leaf {} for epoch {epoch}",
                    hex::encode(&leaf_id)
                ))
            })?;
            let registered =
                quil_crypto::storage_proof::parse_registration_root(&stored.registration_root)
                    .ok_or_else(|| {
                        QuilError::InvalidArgument(
                            "a stored replica without a hash registration".into(),
                        )
                    })?;
            let cap = quil_crypto::storage_proof::MerkleCap::from_bytes(&stored.cap).ok_or_else(
                || QuilError::InvalidArgument("a stored replica's cap does not decode".into()),
            )?;
            held.leaves.push(
                quil_execution::global_intrinsic::storage_epoch_proof::HeldLeaf {
                    leaf_id,
                    n: cap.n,
                    comm_r: registered.comm_r,
                },
            );
            held.stored.push((stored, cap));
        }
        Ok(held)
    }

    pub fn replicas(
        &self,
    ) -> Vec<quil_execution::global_intrinsic::storage_epoch_proof::HeldReplica<'_>> {
        self.stored
            .iter()
            .map(|(stored, cap)| {
                quil_execution::global_intrinsic::storage_epoch_proof::HeldReplica {
                    replica: &stored.replica,
                    cap,
                }
            })
            .collect()
    }
}

/// The root a member commits in app frame `frame_number` of `filter`, whose
/// anchored GLOBAL frame's beacon is `rho_n`, for its sealed registration
/// `slot` (hash storage proofs): its replica nodes the beacon chose, hashed in
/// order. Its epoch proof later proves them.
///
/// Every frame the seat proposes runs this, on the proposal path, for every
/// seat at once: it reads only each opened node's subtree below the cap
/// (`quil_store::replica_store::CHUNK_NODES` nodes, 32 KiB) and the leaf's
/// cached cap, never a whole replica, and never waits on another seat's
/// replica conversion.
pub fn commitment(
    replicas: &ReplicaStore,
    member: &[u8],
    filter: &[u8],
    slot: &quil_types::consensus::StorageSeatSlot,
    frame_number: u64,
    rho_n: &[u8],
) -> Result<[u8; 32]> {
    use quil_execution::global_intrinsic::storage_epoch_proof as epoch_proof;
    use quil_types::error::QuilError;
    let mut stored = Vec::with_capacity(slot.leaves.len());
    let mut held = Vec::with_capacity(slot.leaves.len());
    for prefix in &slot.leaves {
        let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(filter, prefix);
        let leaf = replicas
            .try_get_hash_leaf(slot.epoch, &leaf_id)?
            .ok_or_else(|| {
                QuilError::ExecutionUnavailable(format!(
                    "no stored replica of leaf {} for epoch {}",
                    hex::encode(&leaf_id),
                    slot.epoch
                ))
            })?;
        let registered =
            quil_crypto::storage_proof::parse_registration_root(&leaf.registration_root)
                .ok_or_else(|| {
                    QuilError::InvalidArgument(
                        "a stored replica without a hash registration".into(),
                    )
                })?;
        held.push(epoch_proof::HeldLeaf {
            leaf_id,
            n: leaf.cap.n,
            comm_r: registered.comm_r,
        });
        stored.push(leaf);
    }
    let caps: Vec<&quil_crypto::storage_proof::MerkleCap> =
        stored.iter().map(|leaf| &leaf.cap).collect();
    let mut failed = None;
    let opened = epoch_proof::frame_openings_from(
        member,
        slot.epoch,
        &held,
        &caps,
        rho_n,
        &mut |i, nodes| match replicas.read_nodes(slot.epoch, &held[i].leaf_id, &stored[i], nodes) {
            Ok(nodes) => Some(nodes),
            Err(error) => {
                failed.get_or_insert(error);
                None
            }
        },
    );
    if let Some(error) = failed {
        return Err(error);
    }
    let opened = opened.ok_or_else(|| {
        QuilError::InvalidArgument("a stored replica is not the registered one".into())
    })?;
    epoch_proof::openings_root(frame_number, &opened)
        .ok_or_else(|| QuilError::InvalidArgument("a replica node is not canonical".into()))
}

/// The beacons of the frames GLOBAL chained into a seat's `slot`, in order:
/// each from the output of the GLOBAL frame it anchors to. `None` when one of
/// those GLOBAL frames is not stored here.
pub fn chained_beacons(
    anchors: &dyn ClockStore,
    slot: &quil_types::consensus::StorageSeatSlot,
) -> Option<Vec<[u8; 32]>> {
    slot.chained
        .iter()
        .map(|&(_, anchor)| {
            let output = anchors.get_global_clock_frame(anchor).ok()?.header?.output;
            quil_crypto::porep::derive_storage_beacon(anchor, &output)
                .try_into()
                .ok()
        })
        .collect()
}

/// Peak bytes preparing a seat's part holds ([`prepare_member_seat`]): the
/// replicas it seals (`sealed`: their epoch and leaves) and settles, all
/// loaded at once, and relabelling its largest sealed leaf. A leaf whose node
/// count was not recorded counts as a full one.
fn seat_part_bytes(
    replicas: &ReplicaStore,
    filter: &[u8],
    sealed: Option<(u64, &[Vec<u32>])>,
    settled: Option<(u64, &[Vec<u32>])>,
) -> Result<u64> {
    let full =
        quil_crypto::storage_proof::data_node_count(crate::app_shard_metadata::LEAF_MAX_BYTES);
    let nodes = |epoch: u64, leaves: &[Vec<u32>]| -> Result<Vec<u64>> {
        let recorded: std::collections::HashMap<Vec<u32>, u64> = match (
            replicas.get_partition(epoch, filter)?,
            replicas.get_leaf_nodes(epoch, filter)?,
        ) {
            (Some(prefixes), Some(nodes)) if prefixes.len() == nodes.len() => {
                prefixes.into_iter().zip(nodes).collect()
            }
            _ => Default::default(),
        };
        Ok(leaves
            .iter()
            .map(|leaf| recorded.get(leaf).copied().unwrap_or(full))
            .collect())
    };
    let node_bytes = quil_crypto::storage_proof::NODE_BYTES as u64;
    let (mut loaded, mut relabel) = (0u64, 0u64);
    if let Some((epoch, leaves)) = sealed {
        for n in nodes(epoch, leaves)? {
            loaded = loaded.saturating_add(n.saturating_mul(node_bytes));
            relabel = relabel.max(encoding_bytes(n));
        }
    }
    if let Some((epoch, leaves)) = settled {
        for n in nodes(epoch, leaves)? {
            loaded = loaded.saturating_add(n.saturating_mul(node_bytes));
        }
    }
    Ok(loaded.saturating_add(relabel))
}

/// A seat's part of its member's epoch proof, from this member's replicas
/// (`storage_epoch_batch`): sealing its registration `seal` for `epoch + 2`
/// (with the output of the GLOBAL frame after it, the beacon, and the
/// snapshot it was read from, for each leaf's binding), settling `settle` for
/// `epoch` with the frames GLOBAL chained there (`slot.chained`, with their
/// beacons from [`chained_beacons`]). Each frame's root is recomputed from the
/// replicas, as the member committed it, and the chain must match GLOBAL's.
/// Preparing relabels each sealed leaf at its challenges, so it runs in the
/// background, once the memory it takes is free (`crate::storage_jobs`).
pub fn prepare_member_seat(
    replicas: &ReplicaStore,
    member: &[u8; 32],
    filter: &[u8],
    epoch: u64,
    seal: Option<(&quil_types::consensus::StorageSeatSlot, &[u8], &Captured)>,
    settle: Option<(&quil_types::consensus::StorageSeatSlot, &[[u8; 32]])>,
) -> Result<crate::storage_epoch_batch::PreparedSeat> {
    use quil_execution::global_intrinsic::storage_epoch_proof::{
        self as epoch_proof, SeatClaim, SeatProof,
    };
    use quil_types::error::QuilError;
    let bytes = seat_part_bytes(
        replicas,
        filter,
        seal.map(|(slot, _, _)| (epoch + 2, slot.leaves.as_slice())),
        settle.map(|(slot, _)| (epoch, slot.leaves.as_slice())),
    )?;
    // A settlement alone loads its held replicas for seconds, and never
    // waits behind seals relabelling: GLOBAL withholds the member's storage
    // share (before epoch 1342: kicks it) when its roots go unproven by the
    // window's end.
    let _memory = if seal.is_none() {
        crate::storage_jobs::reserve_settlement(bytes)
    } else {
        crate::storage_jobs::reserve(bytes)
    };
    let mut claim = SeatClaim {
        seal_epoch: epoch + 2,
        settle_epoch: epoch,
        ..Default::default()
    };
    let mut sealed = Vec::new();
    let mut bindings = Vec::new();
    if let Some((slot, beacon_output, captured)) = seal {
        let beacon =
            quil_crypto::porep::derive_storage_beacon(slot.registered_at + 1, beacon_output);
        if captured.epoch != epoch + 2 || captured.filter != filter {
            return Err(QuilError::InvalidArgument(
                "the snapshot is not the sealed registration's".into(),
            ));
        }
        for prefix in &slot.leaves {
            let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(filter, prefix);
            let stored = replicas.get_hash(epoch + 2, &leaf_id)?.ok_or_else(|| {
                QuilError::ExecutionUnavailable(format!(
                    "no stored replica of leaf {} for epoch {}",
                    hex::encode(&leaf_id),
                    epoch + 2
                ))
            })?;
            let registered =
                quil_crypto::storage_proof::parse_registration_root(&stored.registration_root)
                    .ok_or_else(|| {
                        QuilError::InvalidArgument(
                            "a stored replica without a hash registration".into(),
                        )
                    })?;
            let n = (stored.replica.len() / quil_crypto::storage_proof::NODE_BYTES) as u64;
            let leaf_claim =
                captured.claim(prefix, &leaf_id, member, &beacon, registered.comm_d, n)?;
            bindings.push(captured.prove_binding(&leaf_claim)?);
            claim.seals.push(epoch_proof::SealedLeaf {
                n,
                registered,
                beacon: beacon.clone(),
                leaf_id,
            });
            sealed.push(stored.replica);
        }
    }
    let held = match settle {
        Some((slot, beacons)) => {
            if slot.chained.len() as u64 != slot.frames || beacons.len() != slot.chained.len() {
                return Err(QuilError::InvalidArgument(format!(
                    "GLOBAL chained {} roots, {} listed, {} beacons",
                    slot.frames,
                    slot.chained.len(),
                    beacons.len()
                )));
            }
            let held = HeldReplicas::load(replicas, filter, epoch, &slot.leaves)?;
            let opened = held.replicas();
            for (&(frame_number, _), rho_n) in slot.chained.iter().zip(beacons) {
                let values =
                    epoch_proof::frame_openings(member, epoch, &held.leaves, &opened, rho_n)
                        .ok_or_else(|| {
                            QuilError::InvalidArgument(
                                "a stored replica is not the registered one".into(),
                            )
                        })?;
                let root = epoch_proof::openings_root(frame_number, &values).ok_or_else(|| {
                    QuilError::InvalidArgument("a replica node is not canonical".into())
                })?;
                claim.frames.push(epoch_proof::CommittedFrame {
                    frame_number,
                    rho_n: *rho_n,
                    root,
                });
            }
            let chained = quil_execution::global_intrinsic::storage_seat::chain(
                claim
                    .frames
                    .iter()
                    .map(|f| (f.frame_number, &f.rho_n[..], &f.root)),
            );
            if chained != slot.accumulator {
                return Err(QuilError::InvalidArgument(
                    "GLOBAL chained other roots than this member's replicas give".into(),
                ));
            }
            claim.held = held.leaves.clone();
            Some(held)
        }
        None => None,
    };
    let sealed_refs: Vec<&[u8]> = sealed.iter().map(|replica| &replica[..]).collect();
    let held_refs = held
        .as_ref()
        .map(HeldReplicas::replicas)
        .unwrap_or_default();
    // The labels kept when each sealed leaf was labelled, opened instead of
    // labelling it again.
    let kept: Vec<Option<crate::storage_labels::Kept>> = claim
        .seals
        .iter()
        .map(|leaf| {
            crate::storage_labels::installed()?
                .find(claim.seal_epoch, member, &leaf.leaf_id, |n| n == leaf.n)
        })
        .collect();
    if !kept.is_empty() {
        info!(epoch = claim.seal_epoch, filter = %hex::encode(filter), sealed = kept.len(),
            from_kept_labels = kept.iter().filter(|kept| kept.is_some()).count(),
            "storage seal opens the labels kept for its leaves");
    }
    let labels: Vec<Option<&dyn quil_crypto::storage_proof::LabelSource>> = kept
        .iter()
        .map(|kept| {
            kept.as_ref()
                .map(|kept| kept as &dyn quil_crypto::storage_proof::LabelSource)
        })
        .collect();
    let witness =
        epoch_proof::prepare_with_labels(member, &claim, &sealed_refs, &held_refs, &labels)
            .map_err(QuilError::InvalidArgument)?;
    Ok(crate::storage_epoch_batch::PreparedSeat {
        member: *member,
        part: SeatProof {
            shard_filter: filter.to_vec(),
            epoch,
            seals: seal.is_some(),
            settles: settle.is_some(),
            frames: claim.frames.clone(),
            bindings,
        },
        claim,
        witness,
        solo: false,
    })
}

/// Seconds a failed snapshot waits before it is tried again.
const SNAPSHOT_RETRY_SECS: u64 = 60;

/// Run the snapshot job for `key` in `lane` (`crate::storage_jobs::spawn`)
/// unless one is queued or running, or the last failed less than
/// [`SNAPSHOT_RETRY_SECS`] ago. A job that succeeds leaves its record behind,
/// so its caller stops asking.
pub fn request(
    lane: &[u8],
    key: Vec<u8>,
    label: &'static str,
    job: impl FnOnce() -> Result<()> + Send + 'static,
) {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    static STATE: std::sync::OnceLock<std::sync::Mutex<HashMap<Vec<u8>, Option<Instant>>>> =
        std::sync::OnceLock::new();
    let state = STATE.get_or_init(Default::default);
    {
        let Ok(mut jobs) = state.lock() else { return };
        jobs.retain(|_, failed| {
            failed.is_none_or(|at| at.elapsed() < Duration::from_secs(SNAPSHOT_RETRY_SECS))
        });
        if jobs.contains_key(&key) {
            return;
        }
        jobs.insert(key.clone(), None);
    }
    crate::storage_jobs::spawn(lane, label, move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job))
            .unwrap_or_else(|_| Err(QuilError::Internal("the job panicked".into())));
        if let Ok(mut jobs) = state.lock() {
            match &result {
                Ok(()) => {
                    jobs.remove(&key);
                }
                Err(_) => {
                    jobs.insert(key, Some(Instant::now()));
                }
            }
        }
        result
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use quil_hypergraph::Location;

    /// A seat of `member` on `app` owing GLOBAL the settlement of `epoch`:
    /// its replicas encoded into `replicas`, and one root committed in GLOBAL
    /// frame `frame_number`, chained as GLOBAL chains it, with the beacon of
    /// GLOBAL frame `anchor` whose output is `output`.
    pub(crate) fn settlement_owed(
        replicas: &ReplicaStore,
        member: &[u8; 32],
        app: &[u8; 32],
        epoch: u64,
        frame_number: u64,
        anchor: u64,
        output: &[u8],
    ) -> quil_types::consensus::StorageSeatSlot {
        let crdt = test_crdt();
        for d in 0u8..3 {
            crdt.add_vertex(
                &Location {
                    app_address: *app,
                    data_address: [d; 32],
                },
                &vec![d + 3; 500],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let captured = capture_at(&crdt, app, epoch, &[current_source(&crdt, app, epoch)]).unwrap();
        encode_member(&captured, member, replicas).unwrap();
        let mut leaves = captured.prefixes.clone();
        leaves.sort();
        let mut slot = quil_types::consensus::StorageSeatSlot {
            epoch,
            leaves,
            registered_at: 1,
            sealed_at: Some(2),
            frames: 1,
            accumulator: [0; 32],
            chained: vec![(frame_number, anchor)],
            open: true,
        };
        let rho_n: [u8; 32] = quil_crypto::porep::derive_storage_beacon(anchor, output)
            .try_into()
            .unwrap();
        let root = commitment(replicas, member, app, &slot, frame_number, &rho_n).unwrap();
        slot.accumulator = quil_execution::global_intrinsic::storage_seat::chain(
            [(frame_number, &rho_n[..], &root)].into_iter(),
        );
        slot
    }

    fn test_crdt() -> Arc<HypergraphCrdt> {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store,
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE.to_vec(),
        ));
        crdt.set_unified_tree(true);
        crdt
    }

    fn address(lead: u8, tail: u8) -> [u8; 32] {
        let mut address = [tail; 32];
        address[0] = lead;
        address
    }

    /// The whole shard's data is read at the roots GLOBAL recorded, even
    /// after the state has moved on, and holds every address — the KZG leaf
    /// data held only those starting with bits `00`.
    #[test]
    fn a_snapshot_is_read_at_its_roots_after_the_state_moved_on_and_holds_every_address() {
        let crdt = test_crdt();
        let app = [0x3Au8; 32];
        for (i, lead) in [0x00u8, 0x40, 0x80, 0xC0].into_iter().enumerate() {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: address(lead, 1),
                },
                &vec![i as u8 + 1; 200],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let source = current_source(&crdt, &app, 5);
        let before = capture_at(&crdt, &app, 5, std::slice::from_ref(&source)).unwrap();
        assert_eq!(before.prefixes, vec![leaf_prefix(&[])]);
        let data = before.leaf_data(&before.prefixes[0]).unwrap();
        let adds = before.entries(&before.prefixes[0]).unwrap();
        assert_eq!(adds.len(), 4, "every address, not a quarter of them");
        assert!(
            adds.windows(2)
                .all(|pair| pair[0].address < pair[1].address),
            "ascending"
        );

        crdt.add_vertex(
            &Location {
                app_address: app,
                data_address: address(0x41, 2),
            },
            &[9; 64],
        )
        .unwrap();
        crdt.remove_vertex(&Location {
            app_address: app,
            data_address: address(0x80, 1),
        })
        .unwrap();
        crdt.commit(2).unwrap();
        let after = capture_at(&crdt, &app, 5, std::slice::from_ref(&source)).unwrap();
        assert_eq!(
            after.leaf_data(&after.prefixes[0]).unwrap(),
            data,
            "read at the recorded roots"
        );
        let now = capture_at(&crdt, &app, 5, &[current_source(&crdt, &app, 5)]).unwrap();
        assert_ne!(now.leaf_data(&now.prefixes[0]).unwrap(), data);
        assert_eq!(
            now.entries(&now.prefixes[0]).unwrap().len(),
            5,
            "a removed vertex stays in its adds tree"
        );
    }

    /// A shard a split creates reads its parent's snapshot under its own
    /// bits; one a merge creates reads each source at its own roots.
    #[test]
    fn a_split_child_reads_its_parent_and_a_merge_reads_each_source_at_its_roots() {
        let crdt = test_crdt();
        let app = [0x3Bu8; 32];
        let filter = |bits: &[bool]| quil_forest::encode_shard_bit_path(&app, bits);
        for (i, lead) in [0x80u8, 0xA0, 0xC0, 0xE0, 0x10].into_iter().enumerate() {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: address(lead, 3),
                },
                &vec![i as u8 + 1; 150],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let parent = current_source(&crdt, &filter(&[true]), 6);
        let left = capture_at(
            &crdt,
            &filter(&[true, false]),
            6,
            std::slice::from_ref(&parent),
        )
        .unwrap();
        let keys: Vec<u8> = left
            .entries(&left.prefixes[0])
            .unwrap()
            .iter()
            .map(|entry| entry.address[0])
            .collect();
        assert_eq!(keys, vec![0x80, 0xA0], "only the child's addresses");

        // Merge: each child's snapshot recorded at a different version.
        let first = current_source(&crdt, &filter(&[true, false]), 6);
        crdt.add_vertex(
            &Location {
                app_address: app,
                data_address: address(0x90, 4),
            },
            &[7; 80],
        )
        .unwrap();
        crdt.add_vertex(
            &Location {
                app_address: app,
                data_address: address(0xF0, 4),
            },
            &[7; 80],
        )
        .unwrap();
        crdt.commit(2).unwrap();
        let second = current_source(&crdt, &filter(&[true, true]), 6);
        let merged = capture_at(&crdt, &filter(&[true]), 6, &[first, second]).unwrap();
        let keys: Vec<u8> = merged
            .entries(&merged.prefixes[0])
            .unwrap()
            .iter()
            .map(|entry| entry.address[0])
            .collect();
        assert_eq!(
            keys,
            vec![0x80, 0xA0, 0xC0, 0xE0, 0xF0],
            "the left at its roots, the right at its own"
        );
        assert!(
            capture_at(
                &crdt,
                &filter(&[true]),
                6,
                &[current_source(&crdt, &filter(&[false]), 6)]
            )
            .is_err(),
            "a source outside the shard"
        );
    }

    /// A shard larger than a leaf splits by bits until each leaf fits, and
    /// the leaves together hold every entry once.
    #[test]
    fn a_large_shard_splits_into_leaves_that_hold_every_entry_once() {
        let crdt = test_crdt();
        let app = [0x3Cu8; 32];
        for lead in 0u8..32 {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: address(lead * 8, 5),
                },
                &vec![lead; 300],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let mut captured = capture_at(&crdt, &app, 3, &[current_source(&crdt, &app, 3)]).unwrap();
        let whole = captured.size(&[]).unwrap();
        captured.prefixes = captured
            .partition(whole / 5)
            .unwrap()
            .iter()
            .map(|relative| leaf_prefix(relative))
            .collect();
        assert!(
            captured.prefixes.len() >= 5,
            "{} leaves",
            captured.prefixes.len()
        );
        let mut keys = Vec::new();
        for prefix in &captured.prefixes {
            let relative = quil_forest::shard_bit_path_from_prefix(prefix).unwrap();
            assert!(captured.size(&relative).unwrap() <= whole / 5);
            keys.extend(
                captured
                    .entries(prefix)
                    .unwrap()
                    .into_iter()
                    .map(|entry| entry.address),
            );
        }
        keys.sort();
        let before = keys.len();
        keys.dedup();
        assert_eq!((before, keys.len()), (32, 32));
    }

    /// A node that never held a source reads it from the subtree synced
    /// pinned to its roots, and takes the same snapshot as one that did.
    #[test]
    fn a_source_this_node_does_not_hold_is_read_from_its_synced_subtree() {
        use std::collections::HashMap;
        static HOLDERS: std::sync::OnceLock<
            std::sync::Mutex<HashMap<Vec<u8>, Arc<HypergraphCrdt>>>,
        > = std::sync::OnceLock::new();
        let holders = HOLDERS.get_or_init(Default::default);
        install_remote(Arc::new(
            |filter: &[u8], _: &[u8; 32], _: &[bool], _: &[[u8; 32]; 4]| {
                let holder = HOLDERS
                    .get()
                    .and_then(|h| h.lock().unwrap().get(filter).cloned())
                    .ok_or_else(|| QuilError::ExecutionUnavailable("no holder".into()))?;
                Ok(Synced {
                    crdt: holder,
                    keep: Box::new(()),
                })
            },
        ));
        let holder = test_crdt();
        let app = [0x3Du8; 32];
        for lead in [0x01u8, 0x55, 0xAA] {
            holder
                .add_vertex(
                    &Location {
                        app_address: app,
                        data_address: address(lead, 6),
                    },
                    &vec![lead; 120],
                )
                .unwrap();
        }
        holder.commit(1).unwrap();
        let source = current_source(&holder, &app, 4);
        holders.lock().unwrap().insert(app.to_vec(), holder.clone());
        let joiner = test_crdt();
        let synced = capture_at(&joiner, &app, 4, std::slice::from_ref(&source)).unwrap();
        let held = capture_at(&holder, &app, 4, std::slice::from_ref(&source)).unwrap();
        assert_eq!(synced.prefixes, held.prefixes);
        assert_eq!(
            synced.leaf_data(&synced.prefixes[0]).unwrap(),
            held.leaf_data(&held.prefixes[0]).unwrap()
        );
    }

    /// The leaf's encoding and registration, as a member makes them.
    fn registered(captured: &Captured, prefix: &[u32]) -> ([u8; 32], u64) {
        use quil_crypto::storage_proof::{data_nodes, MerkleTree, Tree, NODE_BYTES};
        let nodes = data_nodes(&captured.leaf_data(prefix).unwrap());
        (
            MerkleTree::from_nodes(&nodes)
                .unwrap()
                .commitment(Tree::Data),
            (nodes.len() / NODE_BYTES) as u64,
        )
    }

    /// A member proves its leaf's data is the snapshot's, and GLOBAL checks
    /// it from the recorded roots alone; data that is not, fails.
    #[test]
    fn a_leaf_binding_verifies_from_the_recorded_roots_and_other_data_does_not() {
        let crdt = test_crdt();
        let app = [0x3Fu8; 32];
        for i in 0u8..40 {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: address(i * 6, i),
                },
                &vec![i; 100 + i as usize * 7],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let source = current_source(&crdt, &app, 8);
        // The state moves on: the binding is to the recorded roots.
        crdt.add_vertex(
            &Location {
                app_address: app,
                data_address: address(0xF1, 9),
            },
            &[3; 90],
        )
        .unwrap();
        crdt.commit(2).unwrap();
        let captured = capture_at(&crdt, &app, 8, std::slice::from_ref(&source)).unwrap();
        let prefix = captured.prefixes[0].clone();
        let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(&app, &prefix);
        let (member, beacon) = ([0x71u8; 32], [0x5Au8; 32]);
        let (comm_d, n) = registered(&captured, &prefix);
        let claim = captured
            .claim(&prefix, &leaf_id, &member, &beacon, comm_d, n)
            .unwrap();
        let proved = captured.prove_binding(&claim).unwrap();
        assert_eq!(binding::verify(&claim, &proved), Ok(()));
        assert_eq!(
            LeafBinding::from_bytes(&proved.to_bytes()),
            Some(proved.clone())
        );
        assert!(
            proved.coverage.iter().any(|check| check.record.is_some()),
            "coverage found indexed keys"
        );

        // Another beacon draws other samples: these no longer answer them.
        let other = LeafClaim {
            beacon: &[0x5B; 32],
            ..captured
                .claim(&prefix, &leaf_id, &member, &beacon, comm_d, n)
                .unwrap()
        };
        assert!(binding::verify(&other, &proved).is_err());
        // Other roots: the proofs are not of the recorded state.
        let mut moved = captured
            .claim(&prefix, &leaf_id, &member, &beacon, comm_d, n)
            .unwrap();
        moved.sources[0].1 = current_source(&crdt, &app, 8).snapshot.roots;
        assert!(binding::verify(&moved, &proved).is_err());
        // A value tampered with in the binding.
        let mut tampered = proved.clone();
        if let Some(check) = tampered
            .records
            .iter_mut()
            .find(|check| !check.value.is_empty())
        {
            check.value[0] ^= 1;
        }
        assert!(binding::verify(&claim, &tampered).is_err());
        // A coverage check that hides the key it found.
        let mut hidden = proved.clone();
        if let Some(check) = hidden
            .coverage
            .iter_mut()
            .find(|check| check.record.is_some())
        {
            check.record = None;
        }
        assert!(binding::verify(&claim, &hidden).is_err());

        // Data that leaves an entry out cannot answer: its own commitment
        // fails the coverage that finds the missing key, or the records.
        let mut entries = captured.entries(&prefix).unwrap();
        entries.remove(17);
        let short = binding::leaf_data(&app, &prefix, &entries);
        let short_nodes = quil_crypto::storage_proof::data_nodes(&short);
        let short_tree = quil_crypto::storage_proof::MerkleTree::from_nodes(&short_nodes).unwrap();
        let short_claim = captured
            .claim(
                &prefix,
                &leaf_id,
                &member,
                &beacon,
                short_tree.commitment(quil_crypto::storage_proof::Tree::Data),
                (short_nodes.len() / quil_crypto::storage_proof::NODE_BYTES) as u64,
            )
            .unwrap();
        assert!(
            captured.prove_binding(&short_claim).is_err(),
            "the member's own snapshot is not that data"
        );
    }

    /// A member commits roots from its snapshot replicas and proves a seat's
    /// epoch — the next registration's seal and the roots GLOBAL chained —
    /// in a proof that verifies as GLOBAL checks it.
    #[test]
    fn a_member_epoch_proof_from_its_snapshot_verifies_as_global_checks_it() {
        use crate::storage_epoch_batch::PreparedSeat;
        use quil_execution::global_intrinsic::storage_epoch_proof::{
            self as epoch_proof, CommittedFrame, EpochClaim, SeatClaim, StorageEpochProof,
        };
        let crdt = test_crdt();
        let app = [0x6Du8; 32];
        for d in 0u8..3 {
            crdt.add_vertex(
                &quil_hypergraph::Location {
                    app_address: app,
                    data_address: [d; 32],
                },
                &vec![d + 3; 500],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let epoch = 2;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch));
        let member = [0x5Eu8; 32];
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let mut leaves = Vec::new();
        let mut next = None;
        for e in [epoch, epoch + 2] {
            let captured = capture_at(&crdt, &app, e, &[current_source(&crdt, &app, e)]).unwrap();
            encode_member(&captured, &member, &replicas).unwrap();
            leaves = captured.prefixes.clone();
            next = Some(captured);
        }
        let next = next.unwrap();
        leaves.sort();

        // Three finalized frames commit roots, as their proposer computed
        // them; GLOBAL never executed the second, and chained the others.
        let mut held = quil_types::consensus::StorageSeatSlot {
            epoch,
            leaves: leaves.clone(),
            registered_at: 300,
            sealed_at: Some(301),
            frames: 2,
            accumulator: [0; 32],
            chained: vec![(40, 331), (47, 336)],
            open: true,
        };
        let committed: Vec<CommittedFrame> =
            [(40u64, [0x21u8; 32]), (43, [0x22; 32]), (47, [0x23; 32])]
                .into_iter()
                .map(|(frame_number, rho_n)| CommittedFrame {
                    frame_number,
                    rho_n,
                    root: commitment(&replicas, &member, &app, &held, frame_number, &rho_n)
                        .unwrap(),
                })
                .collect();
        let executed = vec![committed[0].clone(), committed[2].clone()];
        held.accumulator = quil_execution::global_intrinsic::storage_seat::chain(
            executed
                .iter()
                .map(|f| (f.frame_number, &f.rho_n[..], &f.root)),
        );
        let beacons = [[0x21u8; 32], [0x23; 32]];
        let sealing = quil_types::consensus::StorageSeatSlot {
            epoch: epoch + 2,
            leaves: leaves.clone(),
            registered_at: 1000,
            sealed_at: None,
            frames: 0,
            accumulator: [0; 32],
            chained: vec![],
            open: true,
        };
        let beacon_output = vec![0x77u8; 516];
        let seat = prepare_member_seat(
            &replicas,
            &member,
            &app,
            epoch,
            Some((&sealing, &beacon_output, &next)),
            Some((&held, &beacons)),
        )
        .unwrap();
        // The worker hands it to its node.
        let seat = PreparedSeat::from_bytes(&seat.to_bytes()).unwrap();
        assert_eq!(seat.part.frames, executed);
        // Its seal and its settlement each prove alone, as a retry sends
        // them (`storage_epoch_batch::prepare_reusing`).
        let (seal_half, settle_half) = seat.clone().halves();
        for half in [seal_half.unwrap(), settle_half.unwrap()] {
            let claim = EpochClaim {
                member,
                seats: vec![half.claim.clone()],
            };
            let bytes = crate::storage_epoch_batch::prove(vec![half]).unwrap();
            assert_eq!(
                claim.verify(
                    &StorageEpochProof::from_canonical_bytes(&bytes)
                        .unwrap()
                        .proof
                ),
                Ok(())
            );
        }

        // Another shard of the same member: sealing only, proved with the
        // first in one proof.
        let other_app = [0x6Eu8; 32];
        for d in 0u8..2 {
            crdt.add_vertex(
                &quil_hypergraph::Location {
                    app_address: other_app,
                    data_address: [d; 32],
                },
                &vec![d + 9; 700],
            )
            .unwrap();
        }
        crdt.commit(2).unwrap();
        let other_next = capture_at(
            &crdt,
            &other_app,
            epoch + 2,
            &[current_source(&crdt, &other_app, epoch + 2)],
        )
        .unwrap();
        encode_member(&other_next, &member, &replicas).unwrap();
        let mut other_leaves = other_next.prefixes.clone();
        other_leaves.sort();
        let other_sealing = quil_types::consensus::StorageSeatSlot {
            leaves: other_leaves.clone(),
            ..sealing.clone()
        };
        let other_seat = prepare_member_seat(
            &replicas,
            &member,
            &other_app,
            epoch,
            Some((&other_sealing, &beacon_output, &other_next)),
            None,
        )
        .unwrap();
        let bytes = crate::storage_epoch_batch::prove(vec![seat, other_seat]).unwrap();
        let proof = StorageEpochProof::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(proof.seats.len(), 2);
        assert_eq!(proof.seats[0].frames, executed);
        // Each sealed leaf's binding checks as GLOBAL checks it.
        let seal_beacon = quil_crypto::porep::derive_storage_beacon(1001, &beacon_output);
        for (shard, leaves, captured, part) in [
            (&app, &leaves, &next, &proof.seats[0]),
            (&other_app, &other_leaves, &other_next, &proof.seats[1]),
        ] {
            assert_eq!(part.bindings.len(), leaves.len());
            for (prefix, binding) in leaves.iter().zip(&part.bindings) {
                let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(shard, prefix);
                let stored = replicas.get_hash(epoch + 2, &leaf_id).unwrap().unwrap();
                let registered =
                    quil_crypto::storage_proof::parse_registration_root(&stored.registration_root)
                        .unwrap();
                let claim = captured
                    .claim(
                        prefix,
                        &leaf_id,
                        &member,
                        &seal_beacon,
                        registered.comm_d,
                        (stored.replica.len() / quil_crypto::storage_proof::NODE_BYTES) as u64,
                    )
                    .unwrap();
                assert_eq!(binding::verify(&claim, binding), Ok(()));
            }
        }

        // GLOBAL's claim, from the registrations it recorded.
        let registration = |shard: &[u8; 32], e: u64, prefix: &Vec<u32>| {
            let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(shard, prefix);
            let stored = replicas.get_hash(e, &leaf_id).unwrap().unwrap();
            let registered =
                quil_crypto::storage_proof::parse_registration_root(&stored.registration_root)
                    .unwrap();
            (leaf_id, (stored.replica.len() / 32) as u64, registered)
        };
        let sealed = |shard: &[u8; 32], leaves: &[Vec<u32>]| -> Vec<epoch_proof::SealedLeaf> {
            leaves
                .iter()
                .map(|prefix| {
                    let (leaf_id, n, registered) = registration(shard, epoch + 2, prefix);
                    epoch_proof::SealedLeaf {
                        leaf_id,
                        n,
                        registered,
                        beacon: quil_crypto::porep::derive_storage_beacon(1001, &beacon_output),
                    }
                })
                .collect()
        };
        let claim = EpochClaim {
            member,
            seats: vec![
                SeatClaim {
                    seal_epoch: epoch + 2,
                    seals: sealed(&app, &leaves),
                    settle_epoch: epoch,
                    held: leaves
                        .iter()
                        .map(|prefix| {
                            let (leaf_id, n, registered) = registration(&app, epoch, prefix);
                            epoch_proof::HeldLeaf {
                                leaf_id,
                                n,
                                comm_r: registered.comm_r,
                            }
                        })
                        .collect(),
                    frames: proof.seats[0].frames.clone(),
                },
                SeatClaim {
                    seal_epoch: epoch + 2,
                    seals: sealed(&other_app, &other_leaves),
                    settle_epoch: epoch,
                    ..Default::default()
                },
            ],
        };
        assert_eq!(claim.verify(&proof.proof), Ok(()));
        let mut reordered = claim.clone();
        reordered.seats.reverse();
        assert!(
            reordered.verify(&proof.proof).is_err(),
            "the seats in the message's order"
        );
        let mut one = claim.clone();
        one.seats.truncate(1);
        assert!(one.verify(&proof.proof).is_err(), "a seat left out");

        let other = quil_types::consensus::StorageSeatSlot {
            accumulator: [9; 32],
            ..held.clone()
        };
        assert!(
            prepare_member_seat(
                &replicas,
                &member,
                &app,
                epoch,
                None,
                Some((&other, &beacons))
            )
            .is_err(),
            "GLOBAL chained roots this member did not commit"
        );
        assert!(
            prepare_member_seat(
                &replicas,
                &member,
                &app,
                epoch,
                None,
                Some((&held, &beacons[..1]))
            )
            .is_err(),
            "a beacon missing"
        );
        let swapped = [[0x23u8; 32], [0x21; 32]];
        assert!(
            prepare_member_seat(
                &replicas,
                &member,
                &app,
                epoch,
                None,
                Some((&held, &swapped))
            )
            .is_err(),
            "other beacons"
        );
        assert_eq!(claim_epoch_proof(&member, &app, epoch, 1002), Some(1));
        assert_eq!(
            claim_epoch_proof(&member, &app, epoch, 1002 + seal_retry_frames() - 1),
            None,
            "one attempt in flight"
        );
        assert_eq!(
            claim_epoch_proof(&member, &app, epoch, 1002 + seal_retry_frames()),
            Some(2),
            "retried once it may be lost"
        );
        assert_eq!(
            epoch_proof_sent_at(&member, &app, epoch),
            Some(1002 + seal_retry_frames())
        );
        assert_eq!(epoch_proof_sent_at(&member, &app, epoch + 1), None);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }
    /// A seat labelled ahead registers its leaf at the count it was labelled
    /// at, though its data grew a little since; GLOBAL's binding check takes
    /// the padded count, and the seal opened from the kept labels verifies as
    /// GLOBAL checks it. A seat not labelled ahead keeps its labels at its
    /// exact count.
    #[test]
    fn a_seat_labelled_ahead_registers_padded_and_seals_from_its_kept_labels() {
        use crate::storage_epoch_batch::PreparedSeat;
        use quil_crypto::storage_proof::{
            data_node_count, max_padded_nodes, padded_nodes_allowed, parse_registration_root,
            NODE_BYTES,
        };
        use quil_execution::global_intrinsic::storage_epoch_proof::{
            EpochClaim, StorageEpochProof,
        };
        crate::storage_labels::install_with_space(
            std::env::temp_dir().join(format!("quil-labels-tests-{}", std::process::id())),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let crdt = test_crdt();
        let app = [0x7Bu8; 32];
        let add = |from: u8, to: u8| {
            for d in from..to {
                crdt.add_vertex(
                    &Location {
                        app_address: app,
                        data_address: address(d.wrapping_mul(5), d),
                    },
                    &vec![d; 300],
                )
                .unwrap();
            }
        };
        add(0, 30);
        crdt.commit(1).unwrap();
        let epoch = 6;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let member = [0x5Fu8; 32];
        assert!(!crate::storage_labels::precomputed(&member, &app, epoch));
        crate::storage_labels::precompute(store, &crdt, &member, &app, epoch).unwrap();
        assert!(crate::storage_labels::precomputed(&member, &app, epoch));
        // The data grows a little before the snapshot.
        add(30, 31);
        crdt.commit(2).unwrap();
        let captured =
            capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        assert_eq!(captured.prefixes.len(), 1);
        let prefix = captured.prefixes[0].clone();
        let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(&app, &prefix);
        let data = captured.leaf_data(&prefix).unwrap();
        let exact = data_node_count(data.len() as u64);
        let kept = store.find(epoch, &member, &leaf_id, |_| true).unwrap();
        assert!(kept.n > exact && padded_nodes_allowed(exact, kept.n));

        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        encode_member(&captured, &member, &replicas).unwrap();
        let stored = replicas.get_hash(epoch, &leaf_id).unwrap().unwrap();
        assert_eq!(
            stored.replica.len() as u64,
            kept.n * NODE_BYTES as u64,
            "registered at the count labelled ahead"
        );
        assert_eq!(
            replicas.get_leaf_nodes(epoch, &app).unwrap(),
            Some(vec![kept.n])
        );
        let whole = quil_crypto::storage_proof::encode_leaf_at(
            &data,
            &quil_crypto::sdr::replica_key(&member, &leaf_id, epoch),
            &quil_crypto::sdr::SdrParams::default(),
            kept.n,
            &mut |_, _| {},
        );
        assert_eq!(stored.registration_root, whole.registration_root());

        // GLOBAL's binding check takes the padded count, and no count past
        // the bound.
        let registered = parse_registration_root(&stored.registration_root).unwrap();
        let beacon = [0x5Cu8; 32];
        let claim = captured
            .claim(
                &prefix,
                &leaf_id,
                &member,
                &beacon,
                registered.comm_d,
                kept.n,
            )
            .unwrap();
        let proved = captured.prove_binding(&claim).unwrap();
        assert_eq!(binding::verify(&claim, &proved), Ok(()));
        let beyond = captured
            .claim(
                &prefix,
                &leaf_id,
                &member,
                &beacon,
                registered.comm_d,
                max_padded_nodes(exact) + 1,
            )
            .unwrap();
        assert!(binding::verify(&beyond, &proved).is_err());
        assert!(captured.prove_binding(&beyond).is_err());

        // The seal, opened from the kept labels.
        let sealing = quil_types::consensus::StorageSeatSlot {
            epoch,
            leaves: vec![prefix.clone()],
            registered_at: 900,
            sealed_at: None,
            frames: 0,
            accumulator: [0; 32],
            chained: vec![],
            open: true,
        };
        let beacon_output = vec![0x78u8; 516];
        let seat = prepare_member_seat(
            &replicas,
            &member,
            &app,
            epoch - 2,
            Some((&sealing, &beacon_output, &captured)),
            None,
        )
        .unwrap();
        let seat = PreparedSeat::from_bytes(&seat.to_bytes()).unwrap();
        let claim = EpochClaim {
            member,
            seats: vec![seat.claim.clone()],
        };
        let bytes = crate::storage_epoch_batch::prove(vec![seat]).unwrap();
        assert_eq!(
            claim.verify(
                &StorageEpochProof::from_canonical_bytes(&bytes)
                    .unwrap()
                    .proof
            ),
            Ok(())
        );

        // Not labelled ahead: labelled at the snapshot, at its exact count,
        // and kept for the seal.
        let other = [0x60u8; 32];
        encode_member(&captured, &other, &replicas).unwrap();
        assert!(store
            .find(epoch, &other, &leaf_id, |n| n == exact)
            .is_some());
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// An epoch proof is not sent again until GLOBAL had
    /// [`seal_retry_frames`] to record it from when it went out: a part
    /// claimed long before (a seal relabelling, the node's batch waiting)
    /// was sent again a minute after its proof landed, and GLOBAL refused it
    /// as settling an epoch already settled.
    #[test]
    fn an_epoch_proof_retry_waits_from_when_it_went_out() {
        let (member, app, epoch) = ([0x7A; 32], [0x7B; 32], 41);
        let retry = seal_retry_frames();
        assert_eq!(claim_epoch_proof(&member, &app, epoch, 1000), Some(1));
        // Its proof goes out just before the claim's clock would run out.
        note_global_frame(1000 + retry - 1);
        note_epoch_proof_published(&member, &app, epoch);
        assert_eq!(
            claim_epoch_proof(&member, &app, epoch, 1000 + retry),
            None,
            "sent again right after its proof went out, timed from its claim"
        );
        assert_eq!(
            claim_epoch_proof(&member, &app, epoch, 1000 + 2 * retry - 2),
            None
        );
        assert_eq!(
            claim_epoch_proof(&member, &app, epoch, 1000 + 2 * retry - 1),
            Some(2)
        );
        // A seat never claimed here gets no clock.
        note_epoch_proof_published(&member, &[0x7C; 32], epoch);
        assert_eq!(epoch_proof_sent_at(&member, &[0x7C; 32], epoch), None);
    }

    /// An epoch's replicas are evicted only once GLOBAL is past its
    /// settlement window: a settlement finding them gone finds its window
    /// closed, and one within it finds them.
    #[test]
    fn replicas_are_evicted_only_past_their_settlement_window() {
        for current in 1..12 {
            note_replica_eviction(current);
            let keep_from = crate::app_shard_metadata::replica_keep_from(current);
            for epoch in 0..keep_from {
                assert!(
                    settlement_closed(epoch, 0),
                    "epoch {epoch} evicted in {current}"
                );
            }
            assert!(
                !settlement_closed(current - 1, 0),
                "epoch {} settles during {current}",
                current - 1
            );
        }
    }

    /// How the leaves of `filter` for `epoch` doing `work` ended, in order
    /// ([`LeafProgress::end`]).
    fn outcomes(epoch: u64, filter: &[u8], work: LeafWork) -> Vec<LeafOutcome> {
        running_leaves()
            .ended
            .iter()
            .filter(|(e, f, w, _)| *e == epoch && f == filter && *w == work)
            .map(|&(.., outcome)| outcome)
            .collect()
    }

    /// An encode whose renewal's grace frame passed stops, leaving the
    /// seat's snapshot unencoded, and one not started is not started; the
    /// labelling of a leaf as by a process that keeps no labels stops too
    /// and is otherwise unchanged.
    #[test]
    fn an_encode_past_its_renewals_grace_stops() {
        let crdt = test_crdt();
        let app = [0x7Du8; 32];
        for d in 0..30u8 {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: address(d.wrapping_mul(5), d),
                },
                &vec![d; 300],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let epoch = 6;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let captured =
            capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        let replicas =
            || ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let (stopped, whole, unchanged) = (replicas(), replicas(), replicas());
        let looks = std::sync::atomic::AtomicUsize::new(0);
        let late = || looks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 3;
        assert!(encode_member_until(&captured, &[0x62; 32], &stopped, None, &late).is_err());
        assert_eq!(stopped.get_partition(epoch, &app).unwrap(), None);
        let ended = outcomes(epoch, &app, LeafWork::LabellingNow);
        assert!(
            !ended.is_empty() && ended.iter().all(|&o| o == LeafOutcome::Grace),
            "a leaf stopped at the grace ended as {ended:?}"
        );
        encode_member_until(&captured, &[0x62; 32], &unchanged, None, &|| false).unwrap();
        encode_member_with(&captured, &[0x62; 32], &whole, None).unwrap();
        for prefix in &captured.prefixes {
            let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(&app, prefix);
            let expected = quil_crypto::storage_proof::encode_leaf(
                &captured.leaf_data(prefix).unwrap(),
                &quil_crypto::sdr::replica_key(&[0x62; 32], &leaf_id, epoch),
                &quil_crypto::sdr::SdrParams::default(),
            );
            let stored = unchanged.get_hash(epoch, &leaf_id).unwrap().unwrap();
            assert_eq!(stored.registration_root, expected.registration_root());
            assert_eq!(stored, whole.get_hash(epoch, &leaf_id).unwrap().unwrap());
        }

        // The background job: not started past the grace.
        let member = vec![0x63u8; 32];
        note_grace_passed(&member, epoch);
        assert!(grace_passed(&member, epoch) && !grace_passed(&[0x62; 32], epoch));
        let target = replicas();
        let lane = b"test lane: past grace".to_vec();
        request_member(
            crdt.clone(),
            target.clone(),
            member,
            &lane,
            app.to_vec(),
            epoch,
            vec![current_source(&crdt, &app, epoch)],
        );
        assert!(crate::storage_jobs::wait_lane_idle(
            &lane,
            std::time::Duration::from_secs(30)
        ));
        assert_eq!(target.get_partition(epoch, &app).unwrap(), None);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// Work due now (a renewal's snapshot) asked for while a leaf is
    /// labelled ahead waits no longer than a short bound for its memory,
    /// and the labelling ahead still completes once that work is done
    /// (2026-10-28: a node's snapshots waited 40 minutes behind one leaf
    /// labelled ahead, past their renewal's grace).
    #[test]
    fn work_due_now_waits_briefly_behind_a_leaf_labelled_ahead() {
        use crate::storage_labels::{ample_space, precompute, precomputed, LabelStore};
        use std::time::{Duration, Instant};
        const BOUND: Duration = Duration::from_secs(2);
        let crdt = test_crdt();
        let app = [0x7Eu8; 32];
        for d in 0..12u8 {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: address(d.wrapping_mul(3), d),
                },
                &vec![d; 16 << 10],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let epoch = 6;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let captured =
            capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        assert_eq!(captured.prefixes.len(), 1);
        let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(&app, &captured.prefixes[0]);
        let dir = std::env::temp_dir().join(format!("quil-labels-yield-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store: &'static LabelStore =
            Box::leak(Box::new(LabelStore::with_space(dir.clone(), ample_space())));
        let member = [0x64u8; 32];
        let (done_tx, done) = std::sync::mpsc::channel();
        let labelling = crdt.clone();
        let started = Instant::now();
        std::thread::spawn(move || {
            quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
            let result = precompute(store, &labelling, &member, &app, epoch);
            done_tx.send(result).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(60);
        while !running_leaves()
            .leaves
            .values()
            .any(|leaf| leaf.work == LeafWork::LabellingAhead)
        {
            assert!(Instant::now() < deadline, "the leaf is labelled ahead");
            std::thread::sleep(Duration::from_millis(5));
        }
        let asked = Instant::now();
        let due = crate::storage_jobs::reserve(u64::MAX / 4);
        let waited = asked.elapsed();
        let finished = store.find(epoch, &member, &leaf_id, |_| true).is_some();
        assert!(
            waited < BOUND && !finished,
            "work due now waited {waited:?} for its memory behind a leaf labelled ahead \
             (the labelling ran to its end first: {finished}; it started {:?} before)",
            asked.duration_since(started)
        );
        drop(due);
        let result = done
            .recv_timeout(Duration::from_secs(300))
            .expect("the labelling ahead completes once the work due now is done");
        result.unwrap();
        assert!(precomputed(&member, &app, epoch));
        assert!(
            store.find(epoch, &member, &leaf_id, |_| true).is_some(),
            "the leaf is labelled ahead after all"
        );
        assert_eq!(
            outcomes(epoch, &app, LeafWork::LabellingAhead),
            vec![LeafOutcome::Yielded, LeafOutcome::Completed]
        );
        let _ = std::fs::remove_dir_all(&dir);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// Labelling ahead for an epoch once GLOBAL reached its snapshot frame
    /// labels nothing and reads no leaf's data; a frame before it, it labels
    /// as before (2026-10-28: a node labelled an epoch's leaves ahead for 68
    /// minutes after their renewal's grace had passed).
    #[test]
    fn labelling_ahead_past_its_snapshot_frame_labels_nothing() {
        use crate::storage_labels::{ample_space, files_under, precompute, LabelStore};
        let crdt = test_crdt();
        let app = [0x7Fu8; 32];
        for d in 0..30u8 {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: address(d.wrapping_mul(5), d),
                },
                &vec![d; 300],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let epoch = 6;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let captured =
            capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        assert!(!captured.prefixes.is_empty());
        let dir = std::env::temp_dir().join(format!("quil-labels-expired-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = LabelStore::with_space(dir.clone(), ample_space());
        let snapshot_frame = quil_types::consensus::storage_snapshot_frame(epoch);
        let (before, past) = ([0x65u8; 32], [0x66u8; 32]);
        note_global_frame(snapshot_frame - 1);
        precompute(&store, &crdt, &before, &app, epoch).unwrap();
        let read = store.leaves_read();
        assert_eq!(read, captured.prefixes.len() as u64);
        let labelled = files_under(&dir).len();
        note_global_frame(snapshot_frame);
        precompute(&store, &crdt, &past, &app, epoch).unwrap();
        assert_eq!(
            store.leaves_read(),
            read,
            "labelling ahead past the epoch's snapshot frame read leaf data"
        );
        assert_eq!(
            files_under(&dir).len(),
            labelled,
            "labelling ahead past the epoch's snapshot frame wrote labels"
        );
        for prefix in &captured.prefixes {
            let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(&app, prefix);
            assert!(
                store.find(epoch, &before, &leaf_id, |_| true).is_some(),
                "labelled a frame before the snapshot frame"
            );
            assert!(store.find(epoch, &past, &leaf_id, |_| true).is_none());
        }
        let _ = std::fs::remove_dir_all(&dir);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// A shard of `app` whose data is one leaf, long enough to label that a
    /// test sees it labelled: the shard's store and the leaf's id.
    fn one_long_leaf(app: [u8; 32], epoch: u64) -> (Arc<HypergraphCrdt>, Vec<u8>) {
        leaf_of(app, epoch, 12)
    }

    /// [`one_long_leaf`] of `values` values of 16 KiB.
    fn leaf_of(app: [u8; 32], epoch: u64, values: u8) -> (Arc<HypergraphCrdt>, Vec<u8>) {
        let crdt = test_crdt();
        for d in 0..values {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: address(d.wrapping_mul(3), d),
                },
                &vec![d; 16 << 10],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let captured =
            capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        assert_eq!(captured.prefixes.len(), 1);
        let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(&app, &captured.prefixes[0]);
        (crdt, leaf_id)
    }

    /// Labelling ahead on a thread of its own ([`label_ahead_in_background`]).
    struct LabellingAhead {
        done: std::sync::mpsc::Receiver<Result<()>>,
        thread: std::thread::JoinHandle<()>,
        /// Handles of the store before the thread took one.
        held: usize,
    }

    impl LabellingAhead {
        /// The labelling's result, once its thread has ended. The thread
        /// holds the store: a test that returns before it ends lets it close
        /// the store while the process exits, which aborts the process
        /// ("pthread lock: Invalid argument"; CI 2026-10-31).
        fn ended(self, crdt: &Arc<HypergraphCrdt>) -> Result<()> {
            self.ended_within(crdt, std::time::Duration::from_secs(60))
        }

        /// [`Self::ended`], waiting up to `timeout` for the labelling to end.
        fn ended_within(
            self,
            crdt: &Arc<HypergraphCrdt>,
            timeout: std::time::Duration,
        ) -> Result<()> {
            let result = self
                .done
                .recv_timeout(timeout)
                .expect("the labelling ahead ends");
            self.thread.join().expect("the labelling ahead's thread");
            assert_eq!(
                Arc::strong_count(crdt),
                self.held,
                "the labelling ahead's thread still holds the store"
            );
            result
        }
    }

    /// Label `member`'s leaves of `app` ahead for `epoch` into `store` on a
    /// thread of its own, and return once a leaf of `app` is being labelled
    /// ahead.
    fn label_ahead_in_background(
        store: &'static crate::storage_labels::LabelStore,
        crdt: &Arc<HypergraphCrdt>,
        member: [u8; 32],
        app: [u8; 32],
        epoch: u64,
    ) -> LabellingAhead {
        use std::time::{Duration, Instant};
        let (done_tx, done) = std::sync::mpsc::channel();
        let held = Arc::strong_count(crdt);
        let crdt = crdt.clone();
        let thread = std::thread::spawn(move || {
            quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
            let result = crate::storage_labels::precompute(store, &crdt, &member, &app, epoch);
            done_tx.send(result).unwrap();
            // As a loaded runner may: the test goes on before this thread
            // drops its handle of the store.
            std::thread::sleep(Duration::from_millis(50));
        });
        let deadline = Instant::now() + Duration::from_secs(60);
        while !running_leaves()
            .leaves
            .values()
            .any(|leaf| leaf.work == LeafWork::LabellingAhead && leaf.filter == app)
        {
            assert!(Instant::now() < deadline, "the leaf is labelled ahead");
            std::thread::sleep(Duration::from_millis(5));
        }
        LabellingAhead { done, thread, held }
    }

    /// Whatever `dir` holds is whole layers labelled ahead and their
    /// manifest, for the snapshot to go on from: no labels complete.
    fn only_whole_layers_kept(dir: &std::path::Path) {
        for file in crate::storage_labels::files_under(dir) {
            let kind = file.extension().and_then(|kind| kind.to_str());
            assert!(
                matches!(kind, Some("layers" | "kept")),
                "{} left",
                file.display()
            );
        }
    }

    /// Layers labelled so far of the leaf of `app` doing `work`, if one runs.
    fn layers_done(app: &[u8], work: LeafWork) -> Option<usize> {
        running_leaves()
            .leaves
            .values()
            .find(|leaf| leaf.filter == app && leaf.work == work)
            .and_then(|leaf| leaf.layers)
            .map(|(_, done, _)| done)
    }

    /// A snapshot's leaf labelled now and given up (the node stopping, say)
    /// keeps its whole layers on disk, and the next process's encode goes
    /// on from them, each checked against its digest: a restart costs at
    /// most the layer it was labelling, and the replica is the one encoded
    /// at once (2026-11-01: a restart while a seat's leaf was labelled at
    /// its snapshot labelled it again from its first layer). Past the
    /// renewal's grace what it kept goes, and the encode removes earlier
    /// epochs' labels first.
    #[test]
    fn a_snapshot_encode_given_up_goes_on_after_a_restart_from_its_whole_layers() {
        use crate::storage_labels::{ample_space, files_under, LabelStore};
        let (app, member, epoch) = ([0x84u8; 32], [0x6Bu8; 32], 6);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let (crdt, leaf_id) = one_long_leaf(app, epoch);
        let captured =
            capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        let exact = quil_crypto::storage_proof::data_node_count(
            captured.leaf_data(&captured.prefixes[0]).unwrap().len() as u64,
        );
        let replicas =
            || ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let dir = std::env::temp_dir().join(format!("quil-labels-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Labels of an earlier epoch a crash left.
        let stale = dir.join((epoch - 1).to_string()).join("leaf");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("64.layers"), [1u8; 64]).unwrap();

        let before = LabelStore::with_space(dir.clone(), ample_space());
        let stopped = replicas();
        let stop = || layers_done(&app, LeafWork::LabellingNow).is_some_and(|done| done >= 3);
        assert!(encode_member_until(&captured, &member, &stopped, Some(&before), &stop).is_err());
        assert_eq!(stopped.get_partition(epoch, &app).unwrap(), None);
        assert!(
            !dir.join((epoch - 1).to_string()).exists(),
            "earlier epochs' labels go first"
        );
        drop(before);
        // A crash midway through writing the fourth layer left part of it.
        let layers = files_under(&dir)
            .into_iter()
            .find(|file| file.extension().is_some_and(|kind| kind == "layers"))
            .expect("whole layers kept");
        let layer = exact * quil_crypto::storage_proof::NODE_BYTES as u64;
        assert_eq!(std::fs::metadata(&layers).unwrap().len(), 3 * layer);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&layers)
            .unwrap();
        std::io::Write::write_all(&mut file, &[0xAB; 1000]).unwrap();
        drop(file);

        // The next process.
        let after = LabelStore::with_space(dir.clone(), ample_space());
        assert_eq!(
            after.resumable(epoch, &member, &leaf_id, |_| true),
            Some((exact, 3))
        );
        let resumed = replicas();
        encode_member_until(&captured, &member, &resumed, Some(&after), &|| false).unwrap();
        assert_eq!(after.resumed(), vec![(leaf_id.clone(), exact, 3)]);
        let at_once = replicas();
        encode_member_with(&captured, &member, &at_once, None).unwrap();
        let stored = resumed.get_hash(epoch, &leaf_id).unwrap();
        assert!(stored.is_some());
        assert_eq!(stored, at_once.get_hash(epoch, &leaf_id).unwrap());
        assert_eq!(
            resumed.get_partition(epoch, &app).unwrap(),
            at_once.get_partition(epoch, &app).unwrap()
        );
        assert!(
            after
                .find(epoch, &member, &leaf_id, |n| n == exact)
                .is_some(),
            "kept for the seal"
        );
        assert!(
            files_under(&dir)
                .iter()
                .all(|file| file.extension().is_none_or(|kind| kind != "kept")),
            "complete, no manifest is left"
        );

        // Past the renewal's grace, a leaf given up keeps nothing.
        let late = [0x6Cu8; 32];
        let given_up = LabelStore::with_space(dir.clone(), ample_space());
        let stop = || {
            let done = layers_done(&app, LeafWork::LabellingNow).is_some_and(|done| done >= 2);
            if done {
                note_grace_passed(&late, epoch);
            }
            done
        };
        assert!(
            encode_member_until(&captured, &late, &replicas(), Some(&given_up), &stop).is_err()
        );
        assert_eq!(given_up.resumable(epoch, &late, &leaf_id, |_| true), None);
        assert_eq!(
            files_under(&dir)
                .iter()
                .filter(|file| file.extension().is_some_and(|kind| kind == "layers"))
                .count(),
            1,
            "only the first member's labels"
        );
        let _ = std::fs::remove_dir_all(&dir);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// Labelling ahead given up at its epoch's snapshot frame keeps its
    /// whole layers, and the snapshot goes on from them at the count they
    /// were labelled at, which its data may register: the replica is the
    /// leaf encoded at once at that count (2026-11-01: labelling ahead
    /// dropped a leaf of 15 million nodes' layers at the snapshot frame, and
    /// the snapshot, labelling it from its first layer, missed the renewal's
    /// grace).
    #[test]
    fn a_snapshot_goes_on_from_the_layers_labelled_ahead_by_its_snapshot_frame() {
        use crate::storage_labels::{ample_space, files_under, LabelStore};
        use quil_crypto::storage_proof::{data_node_count, precompute_nodes};
        use std::time::{Duration, Instant};
        let (app, member, epoch) = ([0x85u8; 32], [0x6Du8; 32], 6);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let (crdt, leaf_id) = leaf_of(app, epoch, 32);
        let dir =
            std::env::temp_dir().join(format!("quil-labels-ahead-kept-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store: &'static LabelStore =
            Box::leak(Box::new(LabelStore::with_space(dir.clone(), ample_space())));
        let labelling = label_ahead_in_background(store, &crdt, member, app, epoch);
        let deadline = Instant::now() + Duration::from_secs(120);
        while !layers_done(&app, LeafWork::LabellingAhead).is_some_and(|done| done >= 1) {
            assert!(Instant::now() < deadline, "a layer is labelled ahead");
            std::thread::sleep(Duration::from_millis(1));
        }
        note_global_frame(quil_types::consensus::storage_snapshot_frame(epoch));
        labelling.ended(&crdt).unwrap();
        assert_eq!(
            outcomes(epoch, &app, LeafWork::LabellingAhead),
            vec![LeafOutcome::Expired],
            "given up before its last layer"
        );
        only_whole_layers_kept(&dir);
        let captured =
            capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        let data = captured.leaf_data(&captured.prefixes[0]).unwrap();
        let ahead = precompute_nodes(data_node_count(data.len() as u64));
        let (count, kept) = store
            .resumable(epoch, &member, &leaf_id, |_| true)
            .expect("its whole layers kept");
        assert_eq!(count, ahead);
        assert!(kept >= 1, "{kept} layers kept");

        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        encode_member_until(&captured, &member, &replicas, Some(store), &|| false).unwrap();
        assert_eq!(store.resumed(), vec![(leaf_id.clone(), ahead, kept)]);
        let expected = quil_crypto::storage_proof::encode_leaf_at(
            &data,
            &quil_crypto::sdr::replica_key(&member, &leaf_id, epoch),
            &quil_crypto::sdr::SdrParams::default(),
            ahead,
            &mut |_, _| {},
        );
        let stored = replicas.get_hash(epoch, &leaf_id).unwrap().unwrap();
        assert_eq!(stored.registration_root, expected.registration_root());
        assert_eq!(stored.cap, expected.replica_cap.to_bytes());
        assert!(store
            .find(epoch, &member, &leaf_id, |n| n == ahead)
            .is_some());
        let mut kinds: Vec<String> = files_under(&dir)
            .iter()
            .filter_map(|file| file.file_name()?.to_str().map(str::to_string))
            .collect();
        kinds.sort();
        assert_eq!(
            kinds,
            ["columns", "layers", "ready"].map(|kind| format!("{ahead}.{kind}"))
        );
        let _ = std::fs::remove_dir_all(&dir);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// A leaf being labelled ahead is given up, keeping no more than its
    /// whole layers, once GLOBAL reaches its epoch's snapshot frame.
    #[test]
    fn labelling_ahead_stops_at_its_snapshot_frame() {
        use crate::storage_labels::{ample_space, LabelStore};
        let (app, member, epoch) = ([0x81u8; 32], [0x68u8; 32], 6);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let (crdt, leaf_id) = one_long_leaf(app, epoch);
        let dir = std::env::temp_dir().join(format!("quil-labels-stops-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store: &'static LabelStore =
            Box::leak(Box::new(LabelStore::with_space(dir.clone(), ample_space())));
        let labelling = label_ahead_in_background(store, &crdt, member, app, epoch);
        note_global_frame(quil_types::consensus::storage_snapshot_frame(epoch));
        labelling.ended(&crdt).unwrap();
        assert!(
            store.find(epoch, &member, &leaf_id, |_| true).is_none(),
            "the labelling ahead ran on past the epoch's snapshot frame"
        );
        assert_eq!(
            outcomes(epoch, &app, LeafWork::LabellingAhead),
            vec![LeafOutcome::Expired]
        );
        only_whole_layers_kept(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// Labelling ahead that gave its memory back to work due now gives up,
    /// rather than label its leaf again from its start, when GLOBAL reached
    /// the epoch's snapshot frame meanwhile (2026-10-28: a node labelled an
    /// epoch's leaf ahead again after that epoch's renewal's grace).
    #[test]
    fn labelling_ahead_that_yielded_past_its_snapshot_frame_gives_up() {
        use crate::storage_labels::{ample_space, LabelStore};
        let (app, member, epoch) = ([0x82u8; 32], [0x69u8; 32], 6);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let (crdt, leaf_id) = one_long_leaf(app, epoch);
        let dir = std::env::temp_dir().join(format!("quil-labels-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store: &'static LabelStore =
            Box::leak(Box::new(LabelStore::with_space(dir.clone(), ample_space())));
        let labelling = label_ahead_in_background(store, &crdt, member, app, epoch);
        // Granted once the labelling ahead gives its memory back.
        let due = crate::storage_jobs::reserve(u64::MAX / 4);
        note_global_frame(quil_types::consensus::storage_snapshot_frame(epoch));
        drop(due);
        labelling.ended(&crdt).unwrap();
        assert!(
            store.find(epoch, &member, &leaf_id, |_| true).is_none(),
            "the leaf was labelled ahead again past the epoch's snapshot frame"
        );
        // Given back to the work due now, or given up at the snapshot frame
        // as it was given back: never labelled to its end.
        let ended = outcomes(epoch, &app, LeafWork::LabellingAhead);
        assert!(
            matches!(
                ended.as_slice(),
                [LeafOutcome::Yielded] | [LeafOutcome::Expired]
            ),
            "{ended:?}"
        );
        only_whole_layers_kept(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// Labelling ahead that gave its memory back to work due now labels its
    /// leaf again as soon as its memory fits beside that work, while the work
    /// still holds its own (2026-11-01: labelling ahead waited until no work
    /// due now had held memory for a minute, through every seat's snapshot,
    /// and no large leaf was labelled ahead).
    #[test]
    fn labelling_ahead_that_yielded_resumes_beside_work_due_now_once_it_fits() {
        use crate::storage_labels::{ample_space, LabelStore};
        use std::sync::mpsc;
        use std::time::Duration;
        const GIB: u64 = 1 << 30;
        // Work due now holding memory until its release is dropped.
        let hold = |bytes: u64| {
            let (granted_tx, granted) = mpsc::channel();
            let (release, released) = mpsc::channel::<()>();
            std::thread::spawn(move || {
                let _memory = crate::storage_jobs::reserve(bytes);
                granted_tx.send(()).unwrap();
                let _ = released.recv();
            });
            (granted, release)
        };
        assert!(
            crate::storage_jobs::job_slots() >= 2,
            "two jobs hold memory side by side"
        );
        // 40 GiB available: the jobs share 30.
        crate::storage_jobs::set_available_for_test(Some(40 * GIB));
        let (app, member, epoch) = ([0x86u8; 32], [0x6Du8; 32], 6);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let (crdt, leaf_id) = one_long_leaf(app, epoch);
        let dir = std::env::temp_dir().join(format!("quil-labels-beside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store: &'static LabelStore =
            Box::leak(Box::new(LabelStore::with_space(dir.clone(), ample_space())));
        let (first, first_release) = hold(20 * GIB);
        first
            .recv_timeout(Duration::from_secs(10))
            .expect("alone, it runs");
        let labelling = label_ahead_in_background(store, &crdt, member, app, epoch);
        // 10 GiB more fit beside the first only once the leaf gives its
        // memory back.
        let (second, second_release) = hold(10 * GIB);
        second
            .recv_timeout(Duration::from_secs(10))
            .expect("the labelling ahead gives its memory back to work due now");
        // Once the first ends, the leaf's memory fits beside the second.
        drop(first_release);
        labelling
            .ended_within(&crdt, Duration::from_secs(300))
            .unwrap();
        assert!(
            store.find(epoch, &member, &leaf_id, |_| true).is_some(),
            "the leaf is labelled ahead beside the work due now"
        );
        assert_eq!(
            outcomes(epoch, &app, LeafWork::LabellingAhead),
            vec![LeafOutcome::Yielded, LeafOutcome::Completed]
        );
        drop(second_release);
        let _ = std::fs::remove_dir_all(&dir);
        crate::storage_jobs::set_available_for_test(None);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// A renewal's leaf labelled now pauses labelling ahead beside it but for
    /// one leaf, the most urgent, which goes on
    /// (`crate::storage_jobs::AHEAD_JOBS_BESIDE_DUE`); the paused leaf keeps
    /// its memory and labels on to its end once the leaf labelled now has
    /// ended (2026-11-01: beside three or four leaves labelled ahead, a
    /// renewal's leaf estimated at 37 minutes was still labelled at its
    /// grace, 3,137 s in).
    #[test]
    fn labelling_ahead_pauses_while_a_renewals_leaf_is_labelled_now() {
        use crate::storage_labels::{ample_space, LabelStore};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};
        const GIB: u64 = 1 << 30;
        crate::storage_jobs::set_available_for_test(Some(40 * GIB));
        let (app, member, epoch) = ([0x87u8; 32], [0x6Eu8; 32], 6);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let (crdt, leaf_id) = one_long_leaf(app, epoch);
        // A renewal's shard of one small leaf, which its snapshot labels now.
        let renewal = [0x88u8; 32];
        let shard = test_crdt();
        for d in 0..30u8 {
            shard
                .add_vertex(
                    &Location {
                        app_address: renewal,
                        data_address: address(d.wrapping_mul(7), d),
                    },
                    &vec![d; 300],
                )
                .unwrap();
        }
        shard.commit(1).unwrap();
        let captured = capture_at(
            &shard,
            &renewal,
            epoch,
            &[current_source(&shard, &renewal, epoch)],
        )
        .unwrap();
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let dir = std::env::temp_dir().join(format!("quil-labels-pause-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store: &'static LabelStore =
            Box::leak(Box::new(LabelStore::with_space(dir.clone(), ample_space())));
        // A leaf only labelling ahead registers: more urgent than the one
        // labelled below, which its snapshot could label within the grace.
        let urgent = crate::storage_jobs::reserve_ahead(
            GIB,
            crate::storage_jobs::AheadOrder {
                deferrable: false,
                seat_leaves: 1,
                seat: 0,
                leaf: 0,
            },
            &|| false,
        )
        .expect("it fits");
        let labelling = label_ahead_in_background(store, &crdt, member, app, epoch);
        let (looked, paused, urgent_paused) = (
            AtomicBool::new(false),
            AtomicBool::new(false),
            AtomicBool::new(false),
        );
        // Looked at while the renewal's leaf is labelled now.
        let stop = || {
            if crate::storage_jobs::labelling_now_count() > 0
                && !looked.swap(true, Ordering::SeqCst)
            {
                let deadline = Instant::now() + Duration::from_secs(10);
                while crate::storage_jobs::pausing_count() == 0 && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                paused.store(crate::storage_jobs::pausing_count() > 0, Ordering::SeqCst);
                urgent_paused.store(urgent.paused(), Ordering::SeqCst);
            }
            false
        };
        encode_member_until(&captured, &[0x64; 32], &replicas, None, &stop).unwrap();
        assert!(
            paused.load(Ordering::SeqCst),
            "labelling ahead paused while the renewal's leaf was labelled now"
        );
        assert!(
            !urgent_paused.load(Ordering::SeqCst),
            "the most urgent leaf labelled ahead went on beside it"
        );
        labelling.ended(&crdt).unwrap();
        assert!(
            store.find(epoch, &member, &leaf_id, |_| true).is_some(),
            "the paused leaf labelled on to its end"
        );
        assert_eq!(
            outcomes(epoch, &app, LeafWork::LabellingAhead),
            vec![LeafOutcome::Completed],
            "it paused rather than gave its memory back"
        );
        assert_eq!(crate::storage_jobs::pausing_count(), 0);
        drop(urgent);
        let _ = std::fs::remove_dir_all(&dir);
        crate::storage_jobs::set_available_for_test(None);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// A leaf is labelled at its snapshot only when its estimate ends by the
    /// renewal's grace frame (2026-10-28: a leaf of 30 million nodes labelled
    /// for 75 minutes of a 54-minute grace).
    #[test]
    fn a_leaf_labelled_now_must_end_by_the_grace_frame() {
        let epoch = 1317;
        let snapshot = quil_types::consensus::storage_snapshot_frame(epoch);
        let grace = snapshot + crate::app_shard_metadata::storage_snapshot_grace();
        assert_eq!((snapshot, grace), (947_536, 947_856));
        // About 75 minutes against 320 frames of 10 s.
        assert_eq!(misses_grace(epoch, 30_000_000, 0, snapshot), Some(320));
        // Measured at 2,406 s: it ends within 320 frames, not 200.
        assert_eq!(misses_grace(epoch, 16_182_813, 0, snapshot), None);
        assert_eq!(misses_grace(epoch, 16_182_813, 0, grace - 200), Some(200));
        assert_eq!(misses_grace(epoch, 1_000, 0, grace - 1), None);
        assert_eq!(misses_grace(epoch, 1_000_000, 0, grace), Some(0));
    }

    /// A seat's snapshot whose leaf cannot be labelled by the renewal's grace
    /// frame is given up rather than started: nothing is encoded, and the
    /// seat renews without a storage registration at once, before that frame.
    #[test]
    fn a_snapshot_that_cannot_end_by_the_grace_frame_is_given_up() {
        let crdt = test_crdt();
        let app = [0x83u8; 32];
        for d in 0..12u8 {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: address(d.wrapping_mul(3), d),
                },
                &vec![d; 64 << 10],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let (member, epoch) = (vec![0x6Au8; 32], 6);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let snapshot_frame = quil_types::consensus::storage_snapshot_frame(epoch);
        // At the grace frame no leaf's labelling ends by it.
        note_global_frame(snapshot_frame + crate::app_shard_metadata::storage_snapshot_grace());
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let lane = b"test lane: given up".to_vec();
        request_member(
            crdt.clone(),
            replicas.clone(),
            member.clone(),
            &lane,
            app.to_vec(),
            epoch,
            vec![current_source(&crdt, &app, epoch)],
        );
        assert!(crate::storage_jobs::wait_lane_idle(
            &lane,
            std::time::Duration::from_secs(30)
        ));
        assert_eq!(replicas.get_partition(epoch, &app).unwrap(), None);
        assert!(snapshot_given_up(&member, &app, epoch));
        assert!(!snapshot_given_up(&member, &[0x84; 32], epoch));
        let roots = crate::app_shard_metadata::compute_storage_confirm(
            &crdt,
            &replicas,
            &[app.to_vec()],
            &member,
            epoch,
            64,
            &quil_crypto::sdr::SdrParams::default(),
            snapshot_frame + 30,
            &[],
        )
        .expect("a seat whose snapshot was given up does not wait for it");
        assert!(roots[0].entries.is_empty());
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// A seat whose leaf cannot be labelled by the renewal's grace frame even
    /// at the fewest nodes its values allow is given up before the leaf asks
    /// for memory, so it neither waits for memory other work holds nor takes
    /// a place before other seats' leaves; a seat whose leaf could still end
    /// by then asks for its memory and waits as before (2026-11-01: ten seats'
    /// large leaves waited for memory through the grace each epoch, and work
    /// labelled ahead gave its memory back to them).
    #[test]
    fn a_seat_certain_to_miss_its_grace_is_given_up_before_it_asks_for_memory() {
        use std::time::Duration;
        let crdt = test_crdt();
        let app = [0x85u8; 32];
        for d in 0..12u8 {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: address(d.wrapping_mul(3), d),
                },
                &vec![d; 64 << 10],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let epoch = 6;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let snapshot_frame = quil_types::consensus::storage_snapshot_frame(epoch);
        let grace_frame = snapshot_frame + crate::app_shard_metadata::storage_snapshot_grace();
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let ask = |member: &[u8], lane: &[u8]| {
            request_member(
                crdt.clone(),
                replicas.clone(),
                member.to_vec(),
                lane,
                app.to_vec(),
                epoch,
                vec![current_source(&crdt, &app, epoch)],
            )
        };
        // Other work holds all the memory: a leaf that asks for it waits.
        let held = crate::storage_jobs::reserve(u64::MAX / 4);
        let (early, late) = ([0x6Bu8; 32], [0x6Cu8; 32]);
        let (early_lane, late_lane) = (
            b"test lane: may end".to_vec(),
            b"test lane: cannot".to_vec(),
        );
        // At the snapshot frame the leaf could end by the grace frame.
        note_global_frame(snapshot_frame);
        ask(&early, &early_lane);
        assert!(
            !crate::storage_jobs::wait_lane_idle(&early_lane, Duration::from_millis(500)),
            "a leaf that could end by the grace frame asks for its memory and waits for it"
        );
        assert!(!snapshot_given_up(&early, &app, epoch));
        // At the grace frame none can.
        note_global_frame(grace_frame);
        ask(&late, &late_lane);
        assert!(
            crate::storage_jobs::wait_lane_idle(&late_lane, Duration::from_secs(30)),
            "a seat certain to miss its grace waited for memory"
        );
        assert!(snapshot_given_up(&late, &app, epoch));
        // The seat asked earlier gets its memory once the other work ends,
        // reads its leaf, and is given up then, as before.
        drop(held);
        assert!(crate::storage_jobs::wait_lane_idle(
            &early_lane,
            Duration::from_secs(60)
        ));
        assert!(snapshot_given_up(&early, &app, epoch));
        assert_eq!(replicas.get_partition(epoch, &app).unwrap(), None);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// A leaf whose labels' filesystem has no room for them
    /// (`crate::storage_labels::LabelStore::admit`) is not labelled ahead,
    /// and is encoded at its snapshot as by a process that keeps no labels:
    /// the same replica, and no labels left on disk.
    #[test]
    fn a_leaf_without_room_for_its_labels_encodes_as_without_them() {
        use crate::storage_labels::{files_under, precompute, precomputed, LabelStore};
        let crdt = test_crdt();
        let app = [0x7Cu8; 32];
        for d in 0..30u8 {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: address(d.wrapping_mul(5), d),
                },
                &vec![d; 300],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let epoch = 6;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch - 2));
        let dir = std::env::temp_dir().join(format!("quil-labels-full-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // 9 GiB free of 100: below the 10 GiB floor.
        let full = LabelStore::with_space(
            dir.clone(),
            Box::new(|_| {
                Some(quil_forest::storage_health::FsUsage {
                    total_bytes: 100 << 30,
                    free_bytes: 9 << 30,
                    ..Default::default()
                })
            }),
        );
        let member = [0x61u8; 32];
        precompute(&full, &crdt, &member, &app, epoch).unwrap();
        assert!(
            precomputed(&member, &app, epoch),
            "asked again only after a while"
        );
        assert_eq!(
            full.leaves_read(),
            0,
            "a leaf refused room is refused before its data is read into memory"
        );
        let captured =
            capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        assert!(!captured.prefixes.is_empty());
        let replicas =
            || ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let (refused, without) = (replicas(), replicas());
        encode_member_with(&captured, &member, &refused, Some(&full)).unwrap();
        encode_member_with(&captured, &member, &without, None).unwrap();
        for prefix in &captured.prefixes {
            let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(&app, prefix);
            assert!(full.find(epoch, &member, &leaf_id, |_| true).is_none());
            assert_eq!(
                refused.get_hash(epoch, &leaf_id).unwrap(),
                without.get_hash(epoch, &leaf_id).unwrap()
            );
        }
        assert_eq!(files_under(&dir), Vec::<std::path::PathBuf>::new());
        let _ = std::fs::remove_dir_all(&dir);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }
}
