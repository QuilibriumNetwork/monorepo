//! Per-shard size + commitment metadata derived from the hypergraph CRDT.

use num_bigint::BigInt;
use num_traits::Zero;

use quil_hypergraph::HypergraphCrdt;
use quil_tries::{get_full_path, NodeMetadata};
use quil_types::store::{ShardInfo, ShardKey};

#[derive(Debug, Clone)]
pub struct AppShardMetadata {
    pub prefix: Vec<u32>,
    /// Big-endian, leading zero bytes stripped.
    pub size: Vec<u8>,
    pub data_shards: u64,
    /// `[vertex_adds, vertex_removes, hyperedge_adds, hyperedge_removes]`,
    /// each 64 bytes; missing nodes contribute a 64-byte zero blob.
    pub commitments: [Vec<u8>; 4],
}

impl AppShardMetadata {
    pub fn size_bigint(&self) -> BigInt {
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &self.size)
    }
}

pub fn build_app_shard_full_prefix(l2: &[u8], prefix: &[u32]) -> Vec<i32> {
    let mut full = get_full_path(l2);
    full.reserve(prefix.len());
    for &p in prefix {
        full.push(p as i32);
    }
    full
}

/// `ShardInfo.shard_key` is 35 bytes: `L1[3] ++ L2[32]`.
pub fn shard_key_from_bytes(shard_key: &[u8]) -> Option<ShardKey> {
    if shard_key.len() != 35 {
        return None;
    }
    let mut l1 = [0u8; 3];
    let mut l2 = [0u8; 32];
    l1.copy_from_slice(&shard_key[..3]);
    l2.copy_from_slice(&shard_key[3..]);
    Some(ShardKey { l1, l2 })
}

/// Returns `None` only for a malformed `shard_key`. Empty/missing nodes
/// contribute a 64-byte zero commitment and 0 size.
pub fn get_app_shard_metadata(
    crdt: &HypergraphCrdt,
    shard: &ShardInfo,
) -> Option<AppShardMetadata> {
    let typed_key = shard_key_from_bytes(&shard.shard_key)?;
    let full_prefix = build_app_shard_full_prefix(&typed_key.l2, &shard.prefix);

    let metas = match crdt.phase_set_metadata_at_path(&typed_key, &full_prefix) {
        Ok(m) => m,
        Err(_) => [None, None, None, None],
    };

    let zero64 = || vec![0u8; 64];
    let unwrap_commitment = |m: &Option<NodeMetadata>| -> Vec<u8> {
        match m {
            Some(meta) if meta.commitment.len() == 64 => meta.commitment.clone(),
            _ => zero64(),
        }
    };

    let commitments: [Vec<u8>; 4] = [
        unwrap_commitment(&metas[0]),
        unwrap_commitment(&metas[1]),
        unwrap_commitment(&metas[2]),
        unwrap_commitment(&metas[3]),
    ];

    // `size` and `data_shards` come from vertex_adds only.
    let (size_bytes, data_shards) = match &metas[0] {
        Some(meta) => {
            let bytes = if meta.size.is_zero() {
                Vec::new()
            } else {
                let (_, b) = meta.size.to_bytes_be();
                b
            };
            (bytes, meta.leaf_count)
        }
        None => (Vec::new(), 0u64),
    };

    Some(AppShardMetadata {
        prefix: shard.prefix.clone(),
        size: size_bytes,
        data_shards,
        commitments,
    })
}

/// Maximum bytes per storage leaf (≤1 GiB — the SDR/KZG sweet spot). A leaf is a
/// maximal sub-shard prefix whose committed subtree size does not exceed this.
pub const LEAF_MAX_BYTES: u64 = 1 << 30;

/// The 6-bit-nibble branching factor of the shard vector-commitment tree.
pub const SHARD_TREE_BRANCH: u32 = 64;

/// Partition a shard subtree into storage leaves: the set of maximal prefixes
/// (under `base`) whose committed subtree size is `≤ leaf_max_bytes`. Pure +
/// deterministic over a `size_of(prefix) -> bytes` oracle (`0` = no data at that
/// prefix), so it's identical on every node given the same committed state.
///
/// Descends only into prefixes that still exceed the cap and have data; a node
/// that exceeds the cap but has no children (an indivisible oversized vertex) is
/// emitted as its own leaf. `max_depth` bounds recursion.
pub fn partition_leaves<F: Fn(&[u32]) -> u64>(
    base: &[u32],
    leaf_max_bytes: u64,
    branch_factor: u32,
    max_depth: usize,
    size_of: &F,
) -> Vec<Vec<u32>> {
    fn rec<F: Fn(&[u32]) -> u64>(
        prefix: Vec<u32>,
        cap: u64,
        bf: u32,
        depth_left: usize,
        size_of: &F,
        out: &mut Vec<Vec<u32>>,
    ) {
        let sz = size_of(&prefix);
        if sz == 0 {
            return; // no data under this prefix
        }
        if sz <= cap || depth_left == 0 {
            out.push(prefix);
            return;
        }
        let mut any_child = false;
        for nib in 0..bf {
            let mut child = prefix.clone();
            child.push(nib);
            if size_of(&child) > 0 {
                any_child = true;
                rec(child, cap, bf, depth_left - 1, size_of, out);
            }
        }
        if !any_child {
            // Oversized but indivisible (no children) — can't split further.
            out.push(prefix);
        }
    }
    let mut out = Vec::new();
    rec(
        base.to_vec(),
        leaf_max_bytes,
        branch_factor,
        max_depth,
        size_of,
        &mut out,
    );
    out
}

/// Encode a shard's storage leaves for a confirm/epoch boundary. For each leaf
/// prefix, fetches the leaf's canonical data (`leaf_data_for(prefix)`),
/// SDR-encodes it into the member's unique replica, and commits it. Returns the
/// [`ConfirmLeafRoots`] payload to fold into the `ProverConfirm` (so the roots
/// are registered + authenticated) plus the per-leaf `(prefix, replica)` bytes
/// for the worker to persist (and later answer per-frame openings from).
///
/// Pure over the `leaf_data_for` oracle so it's testable independent of the
/// CRDT subtree read; the integration supplies the real leaf bytes. Requires
/// `bls48581::init()`.
#[allow(clippy::type_complexity)]
pub fn compute_confirm_leaf_roots<F: Fn(&[u32]) -> Vec<u8>>(
    filter: &[u8],
    member: &[u8],
    epoch: u64,
    leaf_prefixes: &[Vec<u32>],
    block_poly_size: u64,
    params: &quil_crypto::sdr::SdrParams,
    leaf_data_for: &F,
) -> (
    quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots,
    Vec<(Vec<u32>, Vec<u8>)>,
) {
    use quil_execution::global_intrinsic::leaf_id_bytes;
    use quil_execution::global_intrinsic::leaf_root_registration::{
        ConfirmLeafRoots, LeafRootEntry,
    };

    let mut entries = Vec::with_capacity(leaf_prefixes.len());
    let mut replicas = Vec::with_capacity(leaf_prefixes.len());
    for prefix in leaf_prefixes {
        let leaf_id = leaf_id_bytes(filter, prefix);
        let data = leaf_data_for(prefix);
        let (replica, leaf) = quil_crypto::sdr::build_leaf_replica(
            &data,
            member,
            &leaf_id,
            epoch,
            block_poly_size,
            params,
        );
        entries.push(LeafRootEntry {
            prefix: prefix.clone(),
            leaf_root: leaf.root.clone(),
            num_blocks: leaf.block_commitments().len() as u64,
        });
        replicas.push((prefix.clone(), replica));
    }
    (
        ConfirmLeafRoots {
            filter: filter.to_vec(),
            entries,
        },
        replicas,
    )
}

/// Real `leaf_data_for` oracle: the canonical, member-INDEPENDENT byte string
/// for the storage leaf at `relative_prefix` under shard `filter`. The header
/// (`VERSION(0x01) || filter || relative_prefix`) binds the leaf identity so a
/// replica can't be replayed for a different leaf; the body is the committed
/// 4-phase-set subtree at the absolute path `get_full_path(l2) ++ relative_prefix`
/// (`HypergraphCrdt::serialize_phase_subtrees`). Feeds `compute_confirm_leaf_roots`
/// and the per-frame opening producer — wrap it in a `Fn(&[u32]) -> Vec<u8>` closure
/// at the call site. See memory `porep-leaf-data-canonical-spec`.
///
/// CONSENSUS-CRITICAL: every member covering the leaf must produce identical
/// bytes. Do not change this encoding after storage-epoch activation without a
/// network fork. Reads committed CRDT state — call at a commit boundary.
pub fn leaf_data_for(
    crdt: &HypergraphCrdt,
    filter: &[u8],
    shard_key: &ShardKey,
    relative_prefix: &[u32],
) -> quil_types::error::Result<Vec<u8>> {
    const VERSION: u8 = 0x01;
    let mut out: Vec<u8> = Vec::new();
    out.push(VERSION);
    out.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    out.extend_from_slice(filter);
    out.extend_from_slice(&(relative_prefix.len() as u16).to_be_bytes());
    for &p in relative_prefix {
        out.extend_from_slice(&p.to_be_bytes());
    }
    let full_path = build_app_shard_full_prefix(&shard_key.l2, relative_prefix);
    let body = crdt.serialize_phase_subtrees(shard_key, &full_path)?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// [`leaf_data_for`] over committed state as `snapshot` captured it
/// (`HypergraphCrdt::capture_committed_snapshot`): the leaf data a storage
/// registration binds at an epoch's snapshot, read after the state moved on.
/// Byte-identical to [`leaf_data_for`] at the captured commit.
pub fn leaf_data_at(
    snapshot: &dyn quil_types::store::SnapshotReadable,
    filter: &[u8],
    shard_key: &ShardKey,
    relative_prefix: &[u32],
) -> quil_types::error::Result<Vec<u8>> {
    const VERSION: u8 = 0x01;
    let mut out: Vec<u8> = Vec::new();
    out.push(VERSION);
    out.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    out.extend_from_slice(filter);
    out.extend_from_slice(&(relative_prefix.len() as u16).to_be_bytes());
    for &p in relative_prefix {
        out.extend_from_slice(&p.to_be_bytes());
    }
    let full_path = build_app_shard_full_prefix(&shard_key.l2, relative_prefix);
    out.extend_from_slice(&HypergraphCrdt::serialize_phase_subtrees_at(
        snapshot, shard_key, &full_path,
    )?);
    Ok(out)
}

/// Seed a worker's own committed data for its full coverage filter. Unified
/// workers reject unrelated addresses before retaining blobs and do not write
/// unchanged vertices again. Legacy trees retain whole-app seed semantics.
/// A process worker already uses its own CRDT as the source; skip that copy
/// before enumerating blobs, including before unified mode is enabled.
pub fn sync_app_shard_to_own_crdt(
    source: &HypergraphCrdt,
    own: &HypergraphCrdt,
    filter: &[u8],
    frame_number: u64,
) -> quil_types::error::Result<usize> {
    use quil_types::error::QuilError;
    let app: [u8; 32] = filter
        .get(..32)
        .and_then(|a| a.try_into().ok())
        .ok_or_else(|| {
            QuilError::InvalidArgument("seed filter lacks an application address".into())
        })?;
    let bits = if own.unified_tree() {
        let bits = own
            .canonical_bits_for_filter(filter)
            .filter(|bits| bits.len() <= 256 && (filter.len() != 33 || filter[32] < 64))
            .ok_or_else(|| QuilError::InvalidArgument("invalid unified seed filter".into()))?;
        Some(bits)
    } else {
        None
    };
    if std::ptr::eq(source, own) {
        return Ok(0);
    }
    let matches = |key: &[u8]| {
        key.len() == 64
            && bits.as_ref().is_none_or(|bits| {
                key[..32] == app
                    && bits
                        .iter()
                        .enumerate()
                        .all(|(i, bit)| (key[32 + i / 8] >> (7 - i % 8) & 1 != 0) == *bit)
            })
    };
    let mut copied = 0usize;
    let mut failure = None;
    source.for_each_vertex_adds_blob_matching(&app, &matches, &mut |key, blob| {
        if blob.is_empty() || failure.is_some() {
            return;
        }
        let mut id = [0u8; 64];
        id.copy_from_slice(&key);
        let loc = quil_hypergraph::addressing::Location::from_id(&id);
        if bits.is_some() {
            match own.get_vertex_data_checked(&loc) {
                Ok(Some(existing)) if existing == blob => return,
                Ok(_) => {}
                Err(error) => {
                    failure = Some(error);
                    return;
                }
            }
        }
        match own.add_vertex(&loc, &blob) {
            Ok(()) => copied += 1,
            Err(error) => failure = Some(error),
        }
    })?;
    if let Some(error) = failure {
        return Err(error);
    }
    if copied > 0 {
        own.commit(frame_number)?;
    }
    Ok(copied)
}

/// Split a coverage `filter` into its `(app_address(≤32B), forest sub-shard
/// prefix)`. A split-app (QUIL) sub-shard filter is `app(32) ‖ prefix-bytes`
/// (`coverage.rs` appends `prefix as u8` per level); an unsplit app is the bare
/// 32-byte address (empty prefix). The shard-key is ALWAYS over the 32-byte app —
/// `shard_key_from_bytes` requires exactly 35 bytes — so the trailing bytes are
/// threaded as the forest sub-shard prefix instead.
pub(crate) fn split_coverage_filter(filter: &[u8]) -> (&[u8], Vec<u32>) {
    let app = &filter[..filter.len().min(32)];
    // A bit-path filter (`app ‖ bit_len ‖ packed bits`, every shard of a split
    // application on the unified tree) names its subtree in SENTINEL prefix
    // form, which is what the size metadata and the forest index are keyed by.
    // Read as raw bytes, `[0, 1, 0x80]` is not a path anywhere, so every child
    // shard measured 0 after a split: no leaves, no replicas, no attestation,
    // and the storage gate paid its provers nothing.
    if let Some((_, bits)) = quil_forest::decode_shard_bit_path(filter, 32) {
        return (app, quil_forest::bit_path_to_prefix(&bits));
    }
    let prefix = filter
        .get(32..)
        .unwrap_or(&[])
        .iter()
        .map(|&b| b as u32)
        .collect();
    (app, prefix)
}

/// Whether committed data is present in this worker's covered subtree. This
/// is a presence check, not proof that the state matches a certified frame;
/// the proposal/verifier pre-state checks enforce that separately. A subtree
/// an interrupted download left partly installed holds leaves but not its
/// state, and does not count until a download of it completes.
pub(crate) fn has_committed_shard_data(crdt: &HypergraphCrdt, filter: &[u8]) -> bool {
    if crdt.unified_tree() {
        let Some(bits) = crdt.canonical_bits_for_filter(filter) else {
            return false;
        };
        if crdt.sync_incomplete(&filter[..32], &bits).unwrap_or(true) {
            return false;
        }
        // A sync can install a complete subtree without populating write-time
        // size buckets. Decode the wire bit length and packed path before
        // reading the committed forest.
        return [
            ("vertex", "adds"),
            ("vertex", "removes"),
            ("hyperedge", "adds"),
            ("hyperedge", "removes"),
        ]
        .iter()
        .any(|(set, phase)| crdt.unified_subtree_leaf_count(set, phase, &filter[..32], &bits) > 0);
    }
    let (app, sub_prefix) = split_coverage_filter(filter);
    let mut shard_key = quil_hypergraph::addressing::get_bloom_filter_indices(app, 256, 3).to_vec();
    shard_key.extend_from_slice(app);
    !partition_shard_leaves(crdt, &shard_key, &sub_prefix).is_empty()
}

/// The oldest storage epoch whose replicas a frame in `current_epoch` can
/// still challenge. The previous epoch stays: early in an epoch, frames can
/// still anchor their storage beacon before its boundary (#734).
pub fn replica_keep_from(current_epoch: u64) -> u64 {
    current_epoch.saturating_sub(1)
}

/// Before encoding into `replica_store`, evict the replicas below
/// [`replica_keep_from`], as the master's reconfirmation does for the stores
/// it encodes. A standalone worker's store has no other eviction, so it kept
/// one replica set per epoch. `retired_below` holds the boundary already
/// applied to this store: each boundary is evicted and logged once, and a
/// failure leaves it for the next encoding. Returns whether this call evicted.
pub fn retire_unchallengeable_replicas(
    replica_store: &quil_store::replica_store::ReplicaStore,
    retired_below: &std::sync::atomic::AtomicU64,
    current_epoch: u64,
    filter: &[u8],
    frame_number: u64,
) -> bool {
    use std::sync::atomic::Ordering;
    let keep_from = replica_keep_from(current_epoch);
    let previous = retired_below.load(Ordering::Acquire);
    if keep_from <= previous {
        return false;
    }
    crate::storage_snapshot::note_replica_eviction(current_epoch);
    match replica_store.evict_below_epoch(keep_from) {
        Ok(()) => {
            retired_below.fetch_max(keep_from, Ordering::AcqRel);
            // `since_epoch` 0: the first eviction since start, which also
            // drops any backlog an earlier build left.
            tracing::info!(
                frame = frame_number,
                filter = %hex::encode(filter),
                since_epoch = previous,
                keep_from_epoch = keep_from,
                "evicted storage replicas no frame can challenge",
            );
            true
        }
        Err(error) => {
            tracing::warn!(
                frame = frame_number,
                filter = %hex::encode(filter),
                keep_from_epoch = keep_from,
                %error,
                "storage replica eviction failed; retrying at the next encoding",
            );
            false
        }
    }
}

/// Worker confirm / epoch-boundary hook (PoRep wiring E). For each shard
/// `filter` the prover is confirming, partition its committed subtree into
/// storage leaves, SDR-encode each into the member's UNIQUE replica, register
/// the leaf roots, and persist the replicas to `replica_store` (keyed by
/// `(epoch, leaf_id)`) so the per-frame producer can answer openings. Returns
/// the per-shard [`ConfirmLeafRoots`] to fold into the ProverConfirm via
/// [`crate::provers::actions::build_confirm_bundle_with_leaf_roots`].
///
/// Reads committed CRDT state — call at a commit boundary. Leaf data is fetched
/// fallibly up front (so a store error aborts rather than silently encoding an
/// empty leaf), then encoded through the pure `compute_confirm_leaf_roots`.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
pub fn compute_storage_confirm(
    crdt: &std::sync::Arc<HypergraphCrdt>,
    replica_store: &quil_store::replica_store::ReplicaStore,
    filters: &[Vec<u8>],
    member: &[u8],
    epoch: u64,
    block_poly_size: u64,
    params: &quil_crypto::sdr::SdrParams,
    frame_number: u64,
    snapshots: &[(
        Vec<u8>,
        Vec<quil_execution::global_intrinsic::storage_snapshot::Source>,
    )],
) -> quil_types::error::Result<
    Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>,
> {
    use quil_execution::global_intrinsic::leaf_id_bytes;
    if quil_types::consensus::hash_storage_proofs_at(epoch) {
        return snapshot_storage_confirm(
            crdt,
            replica_store,
            filters,
            member,
            epoch,
            frame_number,
            snapshots,
        );
    }
    let mut all = Vec::with_capacity(filters.len());
    for filter in filters {
        // 35-byte shard key over the 32-byte APP (a split-app sub-shard filter is
        // `app(32) ‖ prefix`; the trailing bytes are the forest sub-shard prefix,
        // NOT part of the shard key — see `split_coverage_filter`).
        let (app, sub_prefix) = split_coverage_filter(filter);
        let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(app, 256, 3);
        let mut shard_key_bytes = Vec::with_capacity(3 + app.len());
        shard_key_bytes.extend_from_slice(&l1);
        shard_key_bytes.extend_from_slice(app);
        let Some(typed) = shard_key_from_bytes(&shard_key_bytes) else {
            continue;
        };

        let prefixes = partition_shard_leaves(crdt, &shard_key_bytes, &sub_prefix);
        if prefixes.is_empty() {
            // Empty shard: nothing to attest, register an empty set so the
            // confirm still records (epoch, filter) coverage.
            all.push(
                quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots {
                    filter: filter.clone(),
                    entries: Vec::new(),
                },
            );
            continue;
        }

        // Fetch every leaf's canonical data up front (fallible), then encode
        // through the pure oracle (a map lookup) so errors propagate.
        let mut data_map: std::collections::HashMap<Vec<u32>, Vec<u8>> =
            std::collections::HashMap::with_capacity(prefixes.len());
        for p in &prefixes {
            data_map.insert(p.clone(), leaf_data_for(crdt, filter, &typed, p)?);
        }
        let oracle = |p: &[u32]| -> Vec<u8> { data_map.get(p).cloned().unwrap_or_default() };

        let (groups, replicas) = compute_confirm_leaf_roots(
            filter,
            member,
            epoch,
            &prefixes,
            block_poly_size,
            params,
            &oracle,
        );
        for (prefix, replica) in &replicas {
            let lid = leaf_id_bytes(filter, prefix);
            replica_store.put(epoch, &lid, replica)?;
        }
        all.push(groups);
    }
    Ok(all)
}

/// GLOBAL frames after an epoch's snapshot frame within which a renewal waits
/// for the member's snapshot of it to be encoded; past them a member without
/// one renews without a registration (its seat stays, its frames that epoch
/// are unattested). Four ninths of an epoch, 320 frames on mainnet: the most
/// that leaves a seat which labels its leaves at the snapshot as long again to
/// label them for its seal before the epoch begins (decided 2026-10-26). A
/// seat whose leaves were labelled ahead (`crate::storage_labels`) needs
/// neither.
pub fn storage_snapshot_grace() -> u64 {
    quil_types::consensus::epoch_length_frames() * 4 / 9
}

/// Ask for the snapshot of each of a seat's `filters` (its shard, then the
/// shards a change creates from it) that `member` has not encoded for
/// `epoch` and whose `snapshots` sources are known, to encode in the
/// background in the seat's lane (`crate::storage_jobs`). A renewal asks for
/// every seat's before it waits on any, so they encode side by side.
pub fn request_storage_snapshots(
    crdt: &std::sync::Arc<HypergraphCrdt>,
    replica_store: &quil_store::replica_store::ReplicaStore,
    filters: &[Vec<u8>],
    member: &[u8],
    epoch: u64,
    snapshots: &[(
        Vec<u8>,
        Vec<quil_execution::global_intrinsic::storage_snapshot::Source>,
    )],
) -> quil_types::error::Result<()> {
    let Some(seat) = filters.first() else {
        return Ok(());
    };
    // Past the renewal's grace a seat renews without the snapshot.
    if !quil_types::consensus::hash_storage_proofs_at(epoch)
        || crate::storage_snapshot::grace_passed(member, epoch)
    {
        return Ok(());
    }
    for filter in filters {
        let Some((_, sources)) = snapshots.iter().find(|(shard, _)| shard == filter) else {
            continue;
        };
        // A snapshot given up renews its seat without it.
        if replica_store.get_partition(epoch, filter)?.is_none()
            && !crate::storage_snapshot::snapshot_given_up(member, filter, epoch)
        {
            crate::storage_snapshot::request_member(
                crdt.clone(),
                replica_store.clone(),
                member.to_vec(),
                seat,
                filter.clone(),
                epoch,
                sources.clone(),
            );
        }
    }
    Ok(())
}

/// A hash-proof epoch's registrations: the leaves the member's snapshot for
/// `epoch` encoded (`crate::storage_snapshot`), never the live data, which has
/// moved on from the state archives commit to. A snapshot not encoded yet is
/// taken now from its `snapshots` sources, and the renewal waits for it until
/// the grace.
fn snapshot_storage_confirm(
    crdt: &std::sync::Arc<HypergraphCrdt>,
    replica_store: &quil_store::replica_store::ReplicaStore,
    filters: &[Vec<u8>],
    member: &[u8],
    epoch: u64,
    frame_number: u64,
    snapshots: &[(
        Vec<u8>,
        Vec<quil_execution::global_intrinsic::storage_snapshot::Source>,
    )],
) -> quil_types::error::Result<
    Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>,
> {
    use quil_execution::global_intrinsic::leaf_id_bytes;
    use quil_execution::global_intrinsic::leaf_root_registration::{
        ConfirmLeafRoots, LeafRootEntry,
    };
    let unavailable = |what: String| quil_types::error::QuilError::ExecutionUnavailable(what);
    let grace_frame =
        quil_types::consensus::storage_snapshot_frame(epoch) + storage_snapshot_grace();
    crate::storage_snapshot::note_global_frame(frame_number);
    if frame_number >= grace_frame {
        // Encodes still running are stopped, their memory free for others.
        crate::storage_snapshot::note_grace_passed(member, epoch);
    }
    request_storage_snapshots(crdt, replica_store, filters, member, epoch, snapshots)?;
    let mut all = Vec::with_capacity(filters.len());
    for (index, filter) in filters.iter().enumerate() {
        let Some(prefixes) = replica_store.get_partition(epoch, filter)? else {
            // The bound shard (first) waits for its snapshot; a shard a
            // recorded change creates from it waits only while its sources are
            // known, rather than hold the renewal up for one never recorded.
            let sources = snapshots.iter().any(|(shard, _)| shard == filter);
            // One given up (a leaf of it could not be labelled by the grace
            // frame) renews without a registration at once.
            let given_up = crate::storage_snapshot::snapshot_given_up(member, filter, epoch);
            if (index == 0 || sources) && frame_number < grace_frame && !given_up {
                return Err(quil_types::error::QuilError::StorageSnapshotPending(
                    format!(
                        "leaf snapshot of {} for epoch {epoch} not encoded yet",
                        hex::encode(filter)
                    ),
                ));
            }
            tracing::warn!(frame = frame_number, epoch, filter = %hex::encode(filter),
                "no leaf snapshot for the epoch: renewing without a storage registration; this seat's frames carry \
                 no storage attestation that epoch");
            all.push(ConfirmLeafRoots {
                filter: filter.clone(),
                entries: Vec::new(),
            });
            continue;
        };
        let mut entries = Vec::with_capacity(prefixes.len());
        for prefix in prefixes {
            let lid = leaf_id_bytes(filter, &prefix);
            let stored = replica_store.get_hash(epoch, &lid)?.ok_or_else(|| {
                unavailable(format!(
                    "leaf {} of the epoch {epoch} snapshot has no replica",
                    hex::encode(&lid)
                ))
            })?;
            let nodes = (stored.replica.len() / quil_crypto::storage_proof::NODE_BYTES) as u64;
            entries.push(LeafRootEntry {
                prefix,
                leaf_root: stored.registration_root,
                num_blocks: nodes,
            });
        }
        all.push(ConfirmLeafRoots {
            filter: filter.clone(),
            entries,
        });
    }
    Ok(all)
}

/// Per-frame producer (PoRep wiring E, part A): build ONE member's possession
/// openings for a frame, from the replicas it persisted at confirm time. For
/// each covered `(filter, prefixes)` it loads the leaf's replica from
/// `replica_store` at `(epoch, leaf_id)`, derives the `(block, point)` challenge
/// for each of `queries` queries from the beacon `rho_n`, and builds the
/// opening. The aggregator assembles these (plus the other committee members'
/// openings, collected via votes) into the frame's `StorageAttestation` with
/// [`quil_crypto::porep::build_frame_storage_attestation`].
///
/// `rho_n = derive_storage_beacon(global_frame_number, global_output)` of the
/// global frame this app-shard frame is anchored to — so the challenge is
/// unpredictable until that VDF output is revealed. Leaves whose replica is
/// missing (never confirmed / evicted) are skipped. Requires `quil_crypto::init()`.
#[allow(clippy::type_complexity)]
pub fn build_member_frame_openings(
    replica_store: &quil_store::replica_store::ReplicaStore,
    covered: &[(Vec<u8>, Vec<Vec<u32>>)],
    member: &[u8],
    epoch: u64,
    rho_n: &[u8],
    poly_size: u64,
    queries: u32,
) -> quil_types::error::Result<Vec<quil_crypto::porep::StorageOpening>> {
    use quil_execution::global_intrinsic::leaf_id_bytes;
    let mut openings = Vec::new();
    let hash = quil_types::consensus::hash_storage_proofs_at(epoch);
    for (filter, prefixes) in covered {
        for prefix in prefixes {
            let lid = leaf_id_bytes(filter, prefix);
            if hash {
                let Some(stored) = replica_store.get_hash(epoch, &lid)? else {
                    continue;
                };
                let Some(cap) = quil_crypto::storage_proof::MerkleCap::from_bytes(&stored.cap)
                else {
                    continue;
                };
                openings.extend((0..queries).filter_map(|q| {
                    quil_crypto::storage_proof::build_opening(
                        &stored.replica,
                        &cap,
                        &stored.registration_root,
                        &lid,
                        epoch,
                        member,
                        q,
                        rho_n,
                    )
                }));
                continue;
            }
            let Some(replica) = replica_store.get(epoch, &lid)? else {
                continue;
            };
            let leaf = quil_crypto::sdr::commit_leaf(&replica, poly_size);
            for q in 0..queries {
                openings.push(quil_crypto::porep::build_storage_opening(
                    &replica, &leaf, &lid, epoch, member, q, rho_n, poly_size,
                ));
            }
        }
    }
    Ok(openings)
}

/// Build the PoRep openings blob a member attaches to its app-shard VOTE: the
/// serialized `StorageAttestation` over this member's openings for every leaf it
/// covers on `filter`, at the per-frame beacon `rho_n`. The vote-aggregator
/// collects these from the rank's votes and assembles the frame attestation
/// (`build_frame_storage_attestation`) when the QC forms. Reads the member's
/// persisted replicas from `replica_store`; returns EMPTY bytes when the member
/// covers no leaves with stored replicas (a not-yet-confirmed member attaches
/// nothing, and the vote serializes byte-identically to the legacy form).
pub fn build_vote_openings(
    crdt: &HypergraphCrdt,
    replica_store: &quil_store::replica_store::ReplicaStore,
    filter: &[u8],
    member: &[u8],
    epoch: u64,
    rho_n: &[u8],
) -> quil_types::error::Result<Vec<u8>> {
    // A split-app (QUIL) sub-shard filter is `app(32) ‖ prefix-bytes`
    // (`coverage.rs` appends `prefix as u8` per level). The shard-key is ALWAYS
    // over the 32-byte APP (`shard_key_from_bytes` requires exactly 35 bytes =
    // L1[3]+L2[32]); the trailing bytes are the forest sub-shard prefix. Without
    // this split, a 33-byte QUIL sub-shard filter yields a 36-byte shard-key that
    // `shard_key_from_bytes` rejects → the shard is silently skipped and NOTHING
    // is ever attested (breaks storage rewards for every split app).
    let prefixes = if quil_types::consensus::hash_storage_proofs_at(epoch) {
        // The leaves registered are the snapshot's, not the live data's.
        replica_store
            .get_partition(epoch, filter)?
            .unwrap_or_default()
    } else {
        let (app, sub_prefix) = split_coverage_filter(filter);
        let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(app, 256, 3);
        let mut shard_key = Vec::with_capacity(3 + app.len());
        shard_key.extend_from_slice(&l1);
        shard_key.extend_from_slice(app);
        partition_shard_leaves(crdt, &shard_key, &sub_prefix)
    };
    if prefixes.is_empty() {
        return Ok(Vec::new());
    }
    let covered = vec![(filter.to_vec(), prefixes)];
    let openings = build_member_frame_openings(
        replica_store,
        &covered,
        member,
        epoch,
        rho_n,
        quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
        quil_types::consensus::STORAGE_QUERIES_PER_LEAF,
    )?;
    if openings.is_empty() {
        return Ok(Vec::new());
    }
    let att = quil_types::proto::global::StorageAttestation {
        openings: openings
            .iter()
            .map(quil_crypto::porep::StorageOpening::to_proto)
            .collect(),
    };
    Ok(prost::Message::encode_to_vec(&att))
}

/// Decode the openings a peer attached to its vote (inverse of
/// [`build_vote_openings`]). Empty / malformed blob → no openings.
pub fn decode_vote_openings(blob: &[u8]) -> Vec<quil_crypto::porep::StorageOpening> {
    if blob.is_empty() {
        return Vec::new();
    }
    match <quil_types::proto::global::StorageAttestation as prost::Message>::decode(blob) {
        Ok(att) => att
            .openings
            .iter()
            .map(quil_crypto::porep::StorageOpening::from_proto)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Partition a shard's subtree into storage-leaf prefixes using the live CRDT's
/// committed size metadata as the oracle. `shard_key` is the 35-byte
/// `L1 ++ L2`. The returned prefixes are the leaves the member must encode +
/// register this epoch (`leaf_id = leaf_id_bytes(filter, prefix)`).
pub fn partition_shard_leaves(
    crdt: &HypergraphCrdt,
    shard_key: &[u8],
    base_prefix: &[u32],
) -> Vec<Vec<u32>> {
    use num_traits::ToPrimitive;
    let size_of = |prefix: &[u32]| -> u64 {
        let shard = ShardInfo {
            shard_key: shard_key.to_vec(),
            prefix: prefix.to_vec(),
            size: Vec::new(),
            data_shards: 0,
            commitment: Vec::new(),
        };
        let bucketed = match get_app_shard_metadata(crdt, &shard) {
            Some(md) => md.size_bigint().to_u64().unwrap_or(u64::MAX),
            None => 0,
        };
        if bucketed > 0 {
            return bucketed;
        }
        // The size buckets are written with the data; a subtree this node
        // received by sync, or inherited when its shard split or merged, has
        // none, and a child shard's members then partitioned no leaves, sealed
        // no replicas and attested nothing (every child frame after a split
        // paid 0). The forest's Merkle-sum index sees the data regardless.
        let app: Option<[u8; 32]> = shard_key.get(3..35).and_then(|a| a.try_into().ok());
        let Some(bits) = quil_forest::shard_bit_path_from_prefix(prefix) else {
            return 0;
        };
        app.and_then(|app| crdt.unified_live_size_at_bits(&app, &bits))
            .unwrap_or(0)
    };
    let leaves = partition_leaves(base_prefix, LEAF_MAX_BYTES, SHARD_TREE_BRANCH, 32, &size_of);
    // DIAGNOSTIC: the committed size THIS crdt reports for the shard subtree.
    // `root_size == 0` ⇒ this crdt holds NO data for the shard, so there are no
    // leaves to seal/attest — distinct from "replicas not sealed yet". A
    // data-bearing shard reading 0 here (while the global intrinsic sees size > 0)
    // is the cluster-worker possession gap: the worker's own crdt is unsynced /
    // unmaterialized, so it can't prove storage it can't see.
    tracing::debug!(
        shard_key = %hex::encode(shard_key),
        base_prefix = ?base_prefix,
        root_size = size_of(base_prefix),
        leaves = leaves.len(),
        "partition_shard_leaves: shard size seen by this crdt (0 => no data to attest)"
    );
    leaves
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use quil_hypergraph::testing::{MemStore, StubProver};
    use quil_hypergraph::Location;
    use quil_types::crypto::InclusionProver;
    use quil_types::store::HypergraphStore;

    fn make_crdt() -> Arc<HypergraphCrdt> {
        let store: Arc<dyn HypergraphStore> = Arc::new(MemStore::new());
        let prover: Arc<dyn InclusionProver> = Arc::new(StubProver);
        Arc::new(HypergraphCrdt::new(store, prover))
    }

    fn seed_test_crdt(unified: bool) -> (Arc<quil_store::RocksDb>, Arc<HypergraphCrdt>) {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(HypergraphCrdt::new(store, Arc::new(StubProver)));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE.to_vec(),
        ));
        crdt.set_unified_tree(unified);
        (db, crdt)
    }

    /// The snapshot reader gives the live reader's bytes at the captured
    /// commit, for the whole shard and for a sub-prefix, and keeps giving them
    /// after the state has moved on.
    #[test]
    fn leaf_data_at_a_snapshot_is_the_live_data_of_that_commit() {
        let (_db, crdt) = seed_test_crdt(true);
        let app = [0x5Bu8; 32];
        let filter = app.to_vec();
        let mut shard_key =
            quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3).to_vec();
        shard_key.extend_from_slice(&app);
        let typed = shard_key_from_bytes(&shard_key).unwrap();
        let addresses: Vec<[u8; 32]> = [0x00u8, 0x13, 0x80, 0x81, 0xF7]
            .iter()
            .map(|&b| {
                let mut a = [b; 32];
                a[31] = b.wrapping_add(1);
                a
            })
            .collect();
        for (i, address) in addresses.iter().enumerate() {
            crdt.add_vertex(
                &Location {
                    app_address: app,
                    data_address: *address,
                },
                &vec![i as u8 + 1; 300],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        crdt.remove_vertex(&Location {
            app_address: app,
            data_address: addresses[2],
        })
        .unwrap();
        crdt.commit(2).unwrap();
        let snapshot = crdt.capture_committed_snapshot().unwrap();
        // The whole shard, and the sub-prefixes of each address's first six bits.
        let mut prefixes: Vec<Vec<u32>> = vec![vec![]];
        let app_path_len = quil_tries::get_full_path(&app).len();
        for address in &addresses {
            let full = build_app_shard_full_prefix(&app, &[]);
            assert_eq!(full.len(), app_path_len);
            let id = [app.as_slice(), address].concat();
            let nibble = |level: usize| -> u32 {
                (0..6).fold(0u32, |acc, j| {
                    let b = level * 6 + j;
                    (acc << 1) | ((id[b / 8] >> (7 - (b % 8))) & 1) as u32
                })
            };
            prefixes.push(vec![nibble(app_path_len)]);
        }
        let live: Vec<Vec<u8>> = prefixes
            .iter()
            .map(|p| leaf_data_for(&crdt, &filter, &typed, p).unwrap())
            .collect();
        for (prefix, expected) in prefixes.iter().zip(&live) {
            assert_eq!(
                &leaf_data_at(snapshot.as_ref(), &filter, &typed, prefix).unwrap(),
                expected,
                "prefix {prefix:?}"
            );
        }
        crdt.add_vertex(
            &Location {
                app_address: app,
                data_address: [0x13; 32],
            },
            &vec![0xEE; 64],
        )
        .unwrap();
        crdt.commit(3).unwrap();
        assert_ne!(
            leaf_data_for(&crdt, &filter, &typed, &[]).unwrap(),
            live[0],
            "the live state moved on"
        );
        assert_eq!(
            leaf_data_at(snapshot.as_ref(), &filter, &typed, &[]).unwrap(),
            live[0],
            "the snapshot did not"
        );
    }

    #[test]
    fn worker_seed_keeps_only_covered_data_and_unchanged_retries_do_not_write() {
        let (_, source) = seed_test_crdt(true);
        let (db, own) = seed_test_crdt(true);
        let app = [0x71; 32];
        let bits = vec![true, false, true, true, false, true, false, true, true];
        let filter = quil_forest::encode_shard_bit_path(&app, &bits);
        let mut address = [0; 32];
        address[0] = 0xb5;
        address[1] = 0x80;
        let covered = Location {
            app_address: app,
            data_address: address,
        };
        address[1] = 0;
        let sibling = Location {
            app_address: app,
            data_address: address,
        };
        let distant = Location {
            app_address: app,
            data_address: [0; 32],
        };
        for (location, value) in [
            (&covered, b"covered".as_slice()),
            (&sibling, b"sibling"),
            (&distant, b"distant"),
        ] {
            source.add_vertex(location, value).unwrap();
        }
        source.commit(1).unwrap();
        assert_eq!(
            sync_app_shard_to_own_crdt(&source, &own, &filter, 2).unwrap(),
            1,
            "worker must not copy unrelated sub-shards of its application"
        );
        assert_eq!(
            own.get_vertex_data_checked(&covered).unwrap(),
            Some(b"covered".to_vec())
        );
        assert_eq!(own.get_vertex_data_checked(&sibling).unwrap(), None);
        assert_eq!(own.get_vertex_data_checked(&distant).unwrap(), None);
        let shard = quil_hypergraph::shard_key_for_location(&covered);
        let path = build_app_shard_full_prefix(&app, &quil_forest::bit_path_to_prefix(&bits));
        let roots = |crdt: &HypergraphCrdt| {
            crdt.phase_set_metadata_at_path(&shard, &path)
                .unwrap()
                .map(|m| m.map(|m| m.commitment))
        };
        assert_eq!(
            roots(&source),
            roots(&own),
            "covered commitments are unchanged by omitted siblings"
        );
        let sequence = db.inner().latest_sequence_number();
        assert_eq!(
            sync_app_shard_to_own_crdt(&source, &own, &filter, 3).unwrap(),
            0
        );
        assert_eq!(
            db.inner().latest_sequence_number(),
            sequence,
            "an unchanged retry must not create blob/tree history"
        );
        source.add_vertex(&covered, b"updated").unwrap();
        source.commit(4).unwrap();
        assert_eq!(
            sync_app_shard_to_own_crdt(&source, &own, &filter, 5).unwrap(),
            1
        );
        assert_eq!(
            own.get_vertex_data_checked(&covered).unwrap(),
            Some(b"updated".to_vec())
        );
        assert_eq!(roots(&source), roots(&own));
    }

    #[test]
    fn worker_seed_preserves_root_and_legacy_scope_and_rejects_invalid_unified_filters() {
        let (_, source) = seed_test_crdt(true);
        let app = [0x71; 32];
        let a = Location {
            app_address: app,
            data_address: [0; 32],
        };
        let b = Location {
            app_address: app,
            data_address: [0xff; 32],
        };
        source.add_vertex(&a, b"a").unwrap();
        source.add_vertex(&b, b"b").unwrap();
        source.commit(1).unwrap();
        let (_, root) = seed_test_crdt(true);
        assert_eq!(
            sync_app_shard_to_own_crdt(&source, &root, &app, 2).unwrap(),
            2
        );
        let (_, legacy) = seed_test_crdt(false);
        let child = quil_forest::encode_shard_bit_path(&app, &[true]);
        assert_eq!(
            sync_app_shard_to_own_crdt(&source, &legacy, &child, 2).unwrap(),
            2,
            "legacy whole-app roots retain their existing seed semantics"
        );
        let (_, byte_suffix) = seed_test_crdt(true);
        let filter = [app.to_vec(), vec![63]].concat();
        assert_eq!(
            sync_app_shard_to_own_crdt(&source, &byte_suffix, &filter, 2).unwrap(),
            1
        );
        assert!(byte_suffix.get_vertex_data_checked(&a).unwrap().is_none());
        assert_eq!(
            byte_suffix.get_vertex_data_checked(&b).unwrap(),
            Some(b"b".to_vec())
        );
        let (db, invalid) = seed_test_crdt(true);
        let before = db.inner().latest_sequence_number();
        for filter in [
            vec![1; 31],
            [app.to_vec(), vec![0, 1, 0x81]].concat(),
            [app.to_vec(), vec![64]].concat(),
            quil_forest::encode_shard_bit_path(&app, &vec![false; 257]),
        ] {
            assert!(sync_app_shard_to_own_crdt(&source, &invalid, &filter, 2).is_err());
        }
        assert_eq!(db.inner().latest_sequence_number(), before);
    }

    #[test]
    fn worker_seed_from_its_own_crdt_copies_nothing() {
        // A cluster worker wires its own CRDT as the storage source.
        let (db, own) = seed_test_crdt(false);
        let app = [0x71; 32];
        own.add_vertex(
            &Location {
                app_address: app,
                data_address: [0; 32],
            },
            b"a",
        )
        .unwrap();
        own.commit(1).unwrap();
        let before = db.inner().latest_sequence_number();
        assert_eq!(sync_app_shard_to_own_crdt(&own, &own, &app, 2).unwrap(), 0);
        assert_eq!(
            db.inner().latest_sequence_number(),
            before,
            "no re-add or commit of its own data"
        );
    }

    /// A bit-path filter names its subtree in sentinel prefix form; a legacy
    /// byte-suffix filter keeps its bytes. (Read raw, a child shard's filter
    /// tail measured 0 after every split.)
    #[test]
    fn coverage_filter_prefix_is_the_sentinel_path_for_bit_path_filters() {
        let app = [0x71u8; 32];
        let bits = vec![true, false, true];
        let filter = quil_forest::encode_shard_bit_path(&app, &bits);
        let (a, prefix) = split_coverage_filter(&filter);
        assert_eq!(a, &app);
        assert_eq!(prefix, quil_forest::bit_path_to_prefix(&bits));
        let (a, root) = split_coverage_filter(&app);
        assert_eq!((a, root), (&app[..], Vec::new()));
        let mut legacy = app.to_vec();
        legacy.push(0x80);
        assert_eq!(split_coverage_filter(&legacy).1, vec![0x80]);
    }

    #[test]
    fn split_readiness_uses_committed_forest_after_reopen_without_size_buckets() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = HypergraphCrdt::new(store.clone(), Arc::new(StubProver));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE.to_vec(),
        ));
        crdt.set_unified_tree(true);
        let app = [0x71; 32];
        // A non-byte-aligned path exercises the wire bit length and padding.
        // Data in this subtree must not mark its empty sibling ready.
        let bits = vec![true, false, true, true, false, true, false, true, true];
        let mut sibling = bits.clone();
        *sibling.last_mut().unwrap() = false;
        let filter = quil_forest::encode_shard_bit_path(&app, &bits);
        let sibling_filter = quil_forest::encode_shard_bit_path(&app, &sibling);
        let mut address = [0; 32];
        address[0] = 0xb5;
        address[1] = 0x80;
        let location = Location {
            app_address: app,
            data_address: address,
        };
        crdt.add_vertex(&location, b"committed covered data")
            .unwrap();
        assert!(
            !has_committed_shard_data(&crdt, &filter),
            "staged writes are not possession"
        );
        crdt.commit(1).unwrap();
        assert!(has_committed_shard_data(&crdt, &filter));
        assert!(!has_committed_shard_data(&crdt, &sibling_filter));
        drop(crdt);

        let reopened = HypergraphCrdt::new(store, Arc::new(StubProver));
        reopened.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE.to_vec(),
        ));
        reopened.set_unified_tree(true);
        assert!(
            reopened.total_size().is_zero(),
            "fixture has not warmed write-time metadata"
        );
        assert!(has_committed_shard_data(&reopened, &filter));
        assert!(has_committed_shard_data(&reopened, &app));
        assert!(!has_committed_shard_data(&reopened, &sibling_filter));
        assert!(
            !has_committed_shard_data(&reopened, &filter[..34]),
            "malformed filter stays gated"
        );
    }

    #[test]
    fn a_partly_downloaded_subtree_is_not_staged_until_its_download_completes() {
        use quil_forest::{SubtreeSyncAnchor, PHASES};
        let open = || {
            let db = quil_store::RocksDb::open_in_memory().unwrap();
            let store: Arc<dyn HypergraphStore> =
                Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
            let crdt = HypergraphCrdt::new(store, Arc::new(StubProver));
            crdt.set_forest(quil_forest::Forest::with_namespace(
                db.inner(),
                quil_store::FOREST_NAMESPACE.to_vec(),
            ));
            crdt.set_unified_tree(true);
            (db, crdt)
        };
        let app = [0x72; 32];
        let bits = vec![true, false, true];
        let filter = quil_forest::encode_shard_bit_path(&app, &bits);
        let (source_db, source) = open();
        for i in 1..=3u8 {
            let mut address = [i; 32];
            address[0] = 0xa0 | i;
            source
                .add_vertex(
                    &Location {
                        app_address: app,
                        data_address: address,
                    },
                    &[i; 40],
                )
                .unwrap();
        }
        source.commit(1).unwrap();
        let (version, _) = source.serve_forest_head(&app, 0).unwrap();
        let source_forest = quil_forest::Forest::with_namespace(
            source_db.inner(),
            quil_store::FOREST_NAMESPACE.to_vec(),
        );
        let reader = source_forest.shard_phase_reader(&app, PHASES[0]);
        let subtree = source.sub_shard_commitment_for_filter("vertex", "adds", &filter);
        let pinned = SubtreeSyncAnchor::SubtreeRoot(subtree.as_slice().try_into().unwrap());

        let (_db, target) = open();
        let mut plan = target
            .prepare_phase_sync(&reader, version, &app, 0, &bits, Some(pinned))
            .unwrap();
        assert_eq!(plan.remaining().len(), 3);
        let blob = |plan: &quil_hypergraph::crdt::ForestSyncPlan, n: usize| {
            plan.remaining()[..n]
                .iter()
                .map(|(key, _)| vec![key[0] & 0x0f; 40])
                .collect::<Vec<_>>()
        };
        let first = blob(&plan, 1);
        target.apply_sync_chunk(&mut plan, &first).unwrap();
        assert!(
            target.unified_subtree_leaf_count("vertex", "adds", &app, &bits) > 0,
            "leaves are installed"
        );
        assert!(
            !has_committed_shard_data(&target, &filter),
            "but the subtree is not staged"
        );
        let rest = blob(&plan, 2);
        target.apply_sync_chunk(&mut plan, &rest).unwrap();
        target.finish_phase_sync(&plan).unwrap();
        assert!(has_committed_shard_data(&target, &filter));
    }

    #[test]
    fn partition_single_leaf_when_under_cap() {
        // Root fits under the cap → one leaf (the root itself).
        let size_of = |p: &[u32]| if p.is_empty() { 500u64 } else { 0 };
        let leaves = partition_leaves(&[], 1000, 64, 8, &size_of);
        assert_eq!(leaves, vec![Vec::<u32>::new()]);
    }

    #[test]
    fn partition_descends_until_under_cap() {
        use std::collections::HashMap;
        // Root = 3000 (> cap 1000); children 0,1,2 each 1000 (≤ cap).
        let mut m: HashMap<Vec<u32>, u64> = HashMap::new();
        m.insert(vec![], 3000);
        m.insert(vec![0], 1000);
        m.insert(vec![1], 1000);
        m.insert(vec![2], 1000);
        let size_of = |p: &[u32]| *m.get(p).unwrap_or(&0);
        let mut leaves = partition_leaves(&[], 1000, 64, 8, &size_of);
        leaves.sort();
        assert_eq!(leaves, vec![vec![0], vec![1], vec![2]]);
    }

    #[test]
    fn partition_recurses_multiple_levels() {
        use std::collections::HashMap;
        // Root 5000 → child [0]=5000 → [0,0]=2000? still >cap → split again.
        let mut m: HashMap<Vec<u32>, u64> = HashMap::new();
        m.insert(vec![], 5000);
        m.insert(vec![0], 5000);
        m.insert(vec![0, 0], 800); // leaf
        m.insert(vec![0, 1], 900); // leaf
        let size_of = |p: &[u32]| *m.get(p).unwrap_or(&0);
        let mut leaves = partition_leaves(&[], 1000, 64, 8, &size_of);
        leaves.sort();
        assert_eq!(leaves, vec![vec![0, 0], vec![0, 1]]);
    }

    #[test]
    fn partition_emits_indivisible_oversized_node() {
        // A node over the cap with no children can't be split — emit it.
        let size_of = |p: &[u32]| if p.is_empty() { 9999u64 } else { 0 };
        let leaves = partition_leaves(&[], 1000, 64, 8, &size_of);
        assert_eq!(leaves, vec![Vec::<u32>::new()]);
    }

    #[test]
    fn partition_empty_shard_yields_nothing() {
        let size_of = |_p: &[u32]| 0u64;
        let leaves = partition_leaves(&[], 1000, 64, 8, &size_of);
        assert!(leaves.is_empty());
    }

    #[test]
    fn confirm_leaf_roots_produce_verifiable_openings() {
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use std::collections::HashMap;
        quil_crypto::init();
        let poly_size = 16u64;
        let params = quil_crypto::sdr::SdrParams::default();
        let filter = vec![0xABu8; 32];
        let member = vec![0x9Au8; 32];
        let epoch = 4u64;
        let rho_n = [0x5Cu8; 32];
        let bitmask = [0x03u8];
        let frame = 11u64;
        let prefixes = vec![vec![0u32], vec![1u32]];

        // 4 blocks of distinct leaf data per prefix.
        let leaf_data_for = |p: &[u32]| -> Vec<u8> {
            let seed = p[0] as u8;
            let nodes = 4 * poly_size as usize;
            (0..nodes * 32)
                .map(|i| (i as u8).wrapping_add(seed))
                .collect()
        };

        // The worker builds the confirm leaf roots + replicas.
        let (groups, replicas) = compute_confirm_leaf_roots(
            &filter,
            &member,
            epoch,
            &prefixes,
            poly_size,
            &params,
            &leaf_data_for,
        );
        assert_eq!(groups.entries.len(), 2);
        assert_eq!(groups.filter, filter);

        // The registry the verifier would build from those (registered) roots.
        let mut reg: HashMap<(Vec<u8>, Vec<u8>, u64), (Vec<u8>, u64, u64)> = HashMap::new();
        for e in &groups.entries {
            let lid = leaf_id_bytes(&filter, &e.prefix);
            reg.insert(
                (member.clone(), lid, epoch),
                (e.leaf_root.clone(), e.num_blocks, epoch),
            );
        }

        // Per-frame openings built from the stored replicas.
        let mut openings = Vec::new();
        for (prefix, replica) in &replicas {
            let lid = leaf_id_bytes(&filter, prefix);
            let leaf = quil_crypto::sdr::commit_leaf(replica, poly_size);
            for q in 0..2u32 {
                openings.push(quil_crypto::porep::build_storage_opening(
                    replica, &leaf, &lid, epoch, &member, q, &rho_n, poly_size,
                ));
            }
        }
        let (att, root) = quil_crypto::porep::build_frame_storage_attestation(
            &openings, frame, &rho_n, &bitmask, poly_size,
        );

        // The verifier accepts against the registered roots for this epoch.
        let good = |m: &[u8], l: &[u8], e: u64| reg.get(&(m.to_vec(), l.to_vec(), e)).cloned();
        assert!(
            quil_crypto::porep::verify_frame_storage_attestation_registered(
                &root, &att, frame, &rho_n, &bitmask, poly_size, epoch, good,
            ),
            "worker-built confirm roots + replicas must yield verifiable openings"
        );
    }

    #[test]
    fn real_crdt_leaf_data_produces_verifiable_openings() {
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use quil_hypergraph::addressing::shard_key_for_location;
        use quil_hypergraph::Location;
        use std::collections::HashMap;
        quil_crypto::init();

        // A real shard with committed vertices.
        let crdt = make_crdt();
        let app = 0x77u8;
        let filter = vec![app; 32]; // app-shard filter == app_address
        for d in 0u8..3 {
            let loc = Location {
                app_address: [app; 32],
                data_address: [d; 32],
            };
            crdt.add_vertex(&loc, &vec![d.wrapping_add(1); 256])
                .unwrap();
        }
        crdt.commit(1).unwrap();
        let shard_key = shard_key_for_location(&Location {
            app_address: [app; 32],
            data_address: [0u8; 32],
        });

        let poly_size = 16u64;
        let params = quil_crypto::sdr::SdrParams::default();
        let member = vec![0x9Au8; 32];
        let epoch = 4u64;
        let rho_n = [0x5Cu8; 32];
        let bitmask = [0x01u8];
        let frame = 11u64;
        // One leaf = the whole shard subtree (relative prefix []).
        let prefixes = vec![Vec::<u32>::new()];

        // The REAL oracle reads the committed CRDT subtree.
        let oracle = |p: &[u32]| -> Vec<u8> {
            leaf_data_for(&crdt, &filter, &shard_key, p).expect("leaf_data_for")
        };
        // Deterministic + carries the committed body (not just the header).
        assert_eq!(oracle(&[]), oracle(&[]));
        assert!(
            oracle(&[]).len() > 5 + filter.len(),
            "leaf data must carry header + committed subtree body"
        );

        let (groups, replicas) = compute_confirm_leaf_roots(
            &filter, &member, epoch, &prefixes, poly_size, &params, &oracle,
        );
        assert_eq!(groups.entries.len(), 1);

        let mut reg: HashMap<(Vec<u8>, Vec<u8>, u64), (Vec<u8>, u64, u64)> = HashMap::new();
        for e in &groups.entries {
            let lid = leaf_id_bytes(&filter, &e.prefix);
            reg.insert(
                (member.clone(), lid, epoch),
                (e.leaf_root.clone(), e.num_blocks, epoch),
            );
        }
        let mut openings = Vec::new();
        for (prefix, replica) in &replicas {
            let lid = leaf_id_bytes(&filter, prefix);
            let leaf = quil_crypto::sdr::commit_leaf(replica, poly_size);
            for q in 0..2u32 {
                openings.push(quil_crypto::porep::build_storage_opening(
                    replica, &leaf, &lid, epoch, &member, q, &rho_n, poly_size,
                ));
            }
        }
        let (att, root) = quil_crypto::porep::build_frame_storage_attestation(
            &openings, frame, &rho_n, &bitmask, poly_size,
        );
        let good = |m: &[u8], l: &[u8], e: u64| reg.get(&(m.to_vec(), l.to_vec(), e)).cloned();
        assert!(
            quil_crypto::porep::verify_frame_storage_attestation_registered(
                &root, &att, frame, &rho_n, &bitmask, poly_size, epoch, good,
            ),
            "real-CRDT leaf data must yield verifiable storage openings"
        );
    }

    #[test]
    fn compute_storage_confirm_persists_replicas_and_folds_roots() {
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use quil_hypergraph::Location;
        quil_crypto::init();

        let crdt = make_crdt();
        let app = 0x33u8;
        let filter = vec![app; 32];
        for d in 0u8..3 {
            crdt.add_vertex(
                &Location {
                    app_address: [app; 32],
                    data_address: [d; 32],
                },
                &vec![d.wrapping_add(1); 256],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();

        let replica_store = quil_store::replica_store::ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_in_memory().unwrap(),
        ));
        let member = vec![0xC1u8; 32];
        let epoch = 7u64;
        let poly_size = 16u64;
        let params = quil_crypto::sdr::SdrParams::default();

        let roots = compute_storage_confirm(
            &crdt,
            &replica_store,
            std::slice::from_ref(&filter),
            &member,
            epoch,
            poly_size,
            &params,
            0,
            &[],
        )
        .expect("compute_storage_confirm");

        assert_eq!(roots.len(), 1, "one shard confirmed");
        assert_eq!(roots[0].filter, filter);
        assert!(
            !roots[0].entries.is_empty(),
            "a shard with committed data must register at least one leaf root"
        );

        // Every registered leaf's replica was persisted under (epoch, leaf_id)
        // and its commitment matches the registered root — the producer can
        // later answer openings from exactly these bytes.
        for e in &roots[0].entries {
            let lid = leaf_id_bytes(&filter, &e.prefix);
            let replica = replica_store
                .get(epoch, &lid)
                .unwrap()
                .expect("replica persisted at (epoch, leaf_id)");
            let leaf = quil_crypto::sdr::commit_leaf(&replica, poly_size);
            assert_eq!(
                leaf.root, e.leaf_root,
                "registered leaf_root must equal the persisted replica's commitment"
            );
            assert_eq!(leaf.block_commitments().len() as u64, e.num_blocks);
        }
    }

    /// In a hash-proof epoch the confirm registers `comm_D ‖ comm_C ‖ comm_R`
    /// and keeps the replica with its cap, the member's openings verify
    /// against those registrations without BLS, and the registered data
    /// commitment is the leaf data's.
    #[test]
    fn hash_epoch_confirm_and_openings_verify_without_kzg() {
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use quil_hypergraph::Location;
        use std::collections::HashMap;
        let (_db, crdt) = seed_test_crdt(true);
        let app = 0x55u8;
        let filter = vec![app; 32];
        for d in 0u8..3 {
            crdt.add_vertex(
                &Location {
                    app_address: [app; 32],
                    data_address: [d; 32],
                },
                &vec![d.wrapping_add(9); 256],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let replica_store = quil_store::replica_store::ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_in_memory().unwrap(),
        ));
        let member = vec![0xC2u8; 32];
        let epoch = 7u64;
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch));
        let params = quil_crypto::sdr::SdrParams::default();
        let confirm_frame = quil_types::consensus::storage_snapshot_frame(epoch) + 30;
        let confirm = |frame| {
            compute_storage_confirm(
                &crdt,
                &replica_store,
                std::slice::from_ref(&filter),
                &member,
                epoch,
                64,
                &params,
                frame,
                &[],
            )
        };
        assert!(
            confirm(confirm_frame)
                .unwrap_err()
                .is_execution_unavailable(),
            "waits for the snapshot"
        );
        assert!(
            confirm(confirm_frame + storage_snapshot_grace()).unwrap()[0]
                .entries
                .is_empty(),
            "past the grace it renews without a registration"
        );
        let source = crate::storage_snapshot::current_source(&crdt, &filter, epoch);
        let captured = crate::storage_snapshot::capture_at(
            &crdt,
            &filter,
            epoch,
            std::slice::from_ref(&source),
        )
        .unwrap();
        crate::storage_snapshot::encode_member(&captured, &member, &replica_store).unwrap();
        let roots = confirm(confirm_frame).unwrap();
        // A shard a recorded change creates whose sources are not recorded
        // registers nothing, and does not hold up the bound shard's renewal.
        let child = [filter.as_slice(), &[0x01]].concat();
        let with_child = compute_storage_confirm(
            &crdt,
            &replica_store,
            &[filter.clone(), child.clone()],
            &member,
            epoch,
            64,
            &params,
            confirm_frame,
            &[],
        )
        .unwrap();
        assert_eq!(with_child[0], roots[0]);
        assert_eq!(
            (with_child[1].filter.clone(), with_child[1].entries.len()),
            (child, 0)
        );
        let mut registry: HashMap<(Vec<u8>, Vec<u8>), (Vec<u8>, u64, u64)> = HashMap::new();
        for entry in &roots[0].entries {
            let registered = quil_crypto::storage_proof::parse_registration_root(&entry.leaf_root)
                .expect("a hash registration root");
            let data = captured.leaf_data(&entry.prefix).unwrap();
            let nodes = quil_crypto::storage_proof::data_nodes(&data);
            assert_eq!(
                registered.comm_d,
                quil_crypto::storage_proof::MerkleTree::from_nodes(&nodes)
                    .unwrap()
                    .commitment(quil_crypto::storage_proof::Tree::Data),
                "the data commitment is the leaf data's"
            );
            assert_eq!(
                entry.num_blocks as usize,
                nodes.len() / quil_crypto::storage_proof::NODE_BYTES
            );
            let lid = leaf_id_bytes(&filter, &entry.prefix);
            registry.insert(
                (member.clone(), lid),
                (entry.leaf_root.clone(), entry.num_blocks, epoch),
            );
        }
        let covered = vec![(
            filter.clone(),
            roots[0].entries.iter().map(|e| e.prefix.clone()).collect(),
        )];
        let rho_n = [0x3Cu8; 32];
        let openings =
            build_member_frame_openings(&replica_store, &covered, &member, epoch, &rho_n, 64, 2)
                .unwrap();
        assert_eq!(openings.len(), 2 * roots[0].entries.len());
        assert!(
            openings
                .iter()
                .all(|o| o.proof.is_empty() && o.commitment.is_empty()),
            "no KZG fields"
        );
        let attestation = quil_types::proto::global::StorageAttestation {
            openings: openings
                .iter()
                .map(quil_crypto::porep::StorageOpening::to_proto)
                .collect(),
        };
        let root =
            quil_crypto::porep::compute_storage_attestation_root(&openings, 9, &rho_n, &[], 64);
        assert_eq!(root.len(), 32);
        let lookup = |m: &[u8], l: &[u8], _: u64| registry.get(&(m.to_vec(), l.to_vec())).cloned();
        assert_eq!(
            quil_crypto::porep::explain_frame_storage_attestation_registered(
                &root,
                &attestation,
                9,
                &rho_n,
                &[],
                64,
                epoch,
                lookup
            ),
            Ok(())
        );
        let failed = quil_crypto::porep::audit_frame_storage_attestations(
            &openings,
            &rho_n,
            64,
            epoch,
            u64::MAX,
            |m: &[u8], l: &[u8]| registry.get(&(m.to_vec(), l.to_vec())).cloned(),
        );
        assert!(failed.is_empty(), "{failed:?}");
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// A renewal's request encodes the seat's snapshot in the background, in
    /// the seat's lane of `crate::storage_jobs`, recording each leaf's node
    /// count beside its partition; before hash storage proofs it asks for none.
    #[test]
    fn a_requested_snapshot_encodes_in_the_background_with_its_node_counts() {
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use quil_hypergraph::Location;
        use std::time::{Duration, Instant};
        let (_db, crdt) = seed_test_crdt(true);
        let app = 0x56u8;
        let filter = vec![app; 32];
        for d in 0u8..3 {
            crdt.add_vertex(
                &Location {
                    app_address: [app; 32],
                    data_address: [d; 32],
                },
                &vec![d.wrapping_add(5); 256],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let replica_store = quil_store::replica_store::ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_in_memory().unwrap(),
        ));
        let member = vec![0xC3u8; 32];
        let epoch = 7u64;
        let source = crate::storage_snapshot::current_source(&crdt, &filter, epoch);
        let snapshots = vec![(filter.clone(), vec![source])];
        let request = || {
            request_storage_snapshots(
                &crdt,
                &replica_store,
                std::slice::from_ref(&filter),
                &member,
                epoch,
                &snapshots,
            )
            .unwrap()
        };
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch + 1));
        request();
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(replica_store.get_partition(epoch, &filter).unwrap(), None);
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(epoch));
        request();
        let deadline = Instant::now() + Duration::from_secs(60);
        let prefixes = loop {
            if let Some(prefixes) = replica_store.get_partition(epoch, &filter).unwrap() {
                break prefixes;
            }
            assert!(Instant::now() < deadline, "the snapshot was not encoded");
            std::thread::sleep(Duration::from_millis(20));
        };
        let nodes = replica_store
            .get_leaf_nodes(epoch, &filter)
            .unwrap()
            .expect("node counts beside the partition");
        assert_eq!(nodes.len(), prefixes.len());
        assert!(!prefixes.is_empty());
        for (prefix, n) in prefixes.iter().zip(&nodes) {
            let stored = replica_store
                .get_hash(epoch, &leaf_id_bytes(&filter, prefix))
                .unwrap()
                .expect("the leaf's replica");
            assert_eq!(
                stored.replica.len() as u64,
                n * quil_crypto::storage_proof::NODE_BYTES as u64
            );
        }
        quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
    }

    /// Each boundary evicts once, keeps the previous epoch, and a later
    /// epoch evicts again.
    #[test]
    fn replica_retirement_keeps_the_previous_epoch_and_applies_each_boundary_once() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let replica_store = quil_store::replica_store::ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_in_memory().unwrap(),
        ));
        for epoch in 3..=7 {
            replica_store.put(epoch, b"leaf", &[epoch as u8]).unwrap();
        }
        let retired_below = AtomicU64::new(0);
        assert!(retire_unchallengeable_replicas(
            &replica_store,
            &retired_below,
            6,
            b"f",
            1
        ));
        assert_eq!(retired_below.load(Ordering::Acquire), 5);
        for epoch in 3..=4 {
            assert!(
                replica_store.get(epoch, b"leaf").unwrap().is_none(),
                "epoch {epoch} is evicted"
            );
        }
        for epoch in 5..=7 {
            assert_eq!(
                replica_store.get(epoch, b"leaf").unwrap(),
                Some(vec![epoch as u8])
            );
        }
        replica_store.put(4, b"leaf", b"late").unwrap();
        assert!(
            !retire_unchallengeable_replicas(&replica_store, &retired_below, 6, b"f", 2),
            "an applied boundary is not evicted or logged again",
        );
        assert!(retire_unchallengeable_replicas(
            &replica_store,
            &retired_below,
            7,
            b"f",
            3
        ));
        assert!(replica_store.get(4, b"leaf").unwrap().is_none());
        assert!(replica_store.get(5, b"leaf").unwrap().is_none());
        assert_eq!(replica_store.get(6, b"leaf").unwrap(), Some(vec![6]));
        // A low epoch cannot underflow the boundary.
        assert!(!retire_unchallengeable_replicas(
            &replica_store,
            &AtomicU64::new(0),
            0,
            b"f",
            4
        ));
    }

    #[test]
    fn member_frame_openings_verify_against_confirm_roots() {
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use quil_hypergraph::Location;
        use std::collections::HashMap;
        quil_crypto::init();

        // Confirm: persist replicas + register roots.
        let crdt = make_crdt();
        let app = 0x44u8;
        let filter = vec![app; 32];
        for d in 0u8..3 {
            crdt.add_vertex(
                &Location {
                    app_address: [app; 32],
                    data_address: [d; 32],
                },
                &vec![d.wrapping_add(1); 256],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let replica_store = quil_store::replica_store::ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_in_memory().unwrap(),
        ));
        let member = vec![0xD2u8; 32];
        let epoch = 5u64;
        let poly_size = 16u64;
        let params = quil_crypto::sdr::SdrParams::default();
        let roots = compute_storage_confirm(
            &crdt,
            &replica_store,
            std::slice::from_ref(&filter),
            &member,
            epoch,
            poly_size,
            &params,
            0,
            &[],
        )
        .unwrap();

        let mut reg: HashMap<(Vec<u8>, Vec<u8>, u64), (Vec<u8>, u64, u64)> = HashMap::new();
        let mut prefixes: Vec<Vec<u32>> = Vec::new();
        for e in &roots[0].entries {
            let lid = leaf_id_bytes(&filter, &e.prefix);
            reg.insert(
                (member.clone(), lid, epoch),
                (e.leaf_root.clone(), e.num_blocks, epoch),
            );
            prefixes.push(e.prefix.clone());
        }

        // Producer: build this member's openings for a frame anchored to a
        // global frame (beacon from its VDF output).
        let rho_n = quil_crypto::porep::derive_storage_beacon(42, &vec![0x9u8; 516]);
        let covered = vec![(filter.clone(), prefixes)];
        let openings = build_member_frame_openings(
            &replica_store,
            &covered,
            &member,
            epoch,
            &rho_n,
            poly_size,
            2,
        )
        .unwrap();
        assert!(!openings.is_empty(), "covered leaves must yield openings");

        // Single-member committee → bitmask [0x01]. The aggregated frame
        // attestation must verify against the confirm-registered roots.
        let frame = 100u64;
        let bitmask = [0x01u8];
        let (att, root) = quil_crypto::porep::build_frame_storage_attestation(
            &openings, frame, &rho_n, &bitmask, poly_size,
        );
        let good = |m: &[u8], l: &[u8], e: u64| reg.get(&(m.to_vec(), l.to_vec(), e)).cloned();
        assert!(
            quil_crypto::porep::verify_frame_storage_attestation_registered(
                &root, &att, frame, &rho_n, &bitmask, poly_size, epoch, good,
            ),
            "producer openings from persisted replicas must verify against confirm roots"
        );
    }

    #[test]
    fn vote_openings_roundtrip_and_verify() {
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use quil_hypergraph::Location;
        use std::collections::HashMap;
        quil_crypto::init();

        let crdt = make_crdt();
        let app = 0x88u8;
        let filter = vec![app; 32];
        for d in 0u8..3 {
            crdt.add_vertex(
                &Location {
                    app_address: [app; 32],
                    data_address: [d; 32],
                },
                &vec![d.wrapping_add(1); 256],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let replica_store = quil_store::replica_store::ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_in_memory().unwrap(),
        ));
        let member = vec![0xE3u8; 32];
        let epoch = 6u64;
        let poly_size = quil_types::consensus::STORAGE_BLOCK_POLY_SIZE;
        let params = quil_crypto::sdr::SdrParams::default();

        // Confirm: persist replicas + register roots (production constants).
        let roots = compute_storage_confirm(
            &crdt,
            &replica_store,
            std::slice::from_ref(&filter),
            &member,
            epoch,
            poly_size,
            &params,
            0,
            &[],
        )
        .unwrap();
        let mut reg: HashMap<(Vec<u8>, Vec<u8>, u64), (Vec<u8>, u64, u64)> = HashMap::new();
        for e in &roots[0].entries {
            let lid = leaf_id_bytes(&filter, &e.prefix);
            reg.insert(
                (member.clone(), lid, epoch),
                (e.leaf_root.clone(), e.num_blocks, epoch),
            );
        }

        // Producer builds the vote blob; aggregator decodes it.
        let rho_n = quil_crypto::porep::derive_storage_beacon(42, &vec![0x9u8; 516]);
        let blob =
            build_vote_openings(&crdt, &replica_store, &filter, &member, epoch, &rho_n).unwrap();
        assert!(!blob.is_empty(), "a covered member must attach openings");
        let openings = decode_vote_openings(&blob);
        assert!(!openings.is_empty());

        // Aggregator assembles the frame attestation (single-member committee).
        let (att, root) = quil_crypto::porep::build_frame_storage_attestation(
            &openings,
            100,
            &rho_n,
            &[0x01u8],
            poly_size,
        );
        let good = |m: &[u8], l: &[u8], e: u64| reg.get(&(m.to_vec(), l.to_vec(), e)).cloned();
        assert!(
            quil_crypto::porep::verify_frame_storage_attestation_registered(
                &root,
                &att,
                100,
                &rho_n,
                &[0x01u8],
                poly_size,
                epoch,
                good,
            ),
            "decoded vote openings must assemble into a verifiable frame attestation"
        );
    }

    #[test]
    fn shard_key_from_bytes_round_trip() {
        let mut buf = vec![0u8; 35];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        let key = shard_key_from_bytes(&buf).expect("valid 35-byte key");
        assert_eq!(&key.l1[..], &buf[..3]);
        assert_eq!(&key.l2[..], &buf[3..]);
    }

    #[test]
    fn shard_key_from_bytes_rejects_bad_length() {
        assert!(shard_key_from_bytes(&[]).is_none());
        assert!(shard_key_from_bytes(&vec![0u8; 34]).is_none());
        assert!(shard_key_from_bytes(&vec![0u8; 36]).is_none());
    }

    #[test]
    fn build_full_prefix_concats_l2_path_and_shard_prefix() {
        // L2 = [0xAB] => 2 nibbles {42, 48} per `get_full_path` test
        // (lib.rs::full_path_single_byte_ab_has_two_nibbles).
        let l2 = vec![0xABu8];
        let prefix = vec![5u32, 12u32];
        let path = build_app_shard_full_prefix(&l2, &prefix);
        assert_eq!(path, vec![42i32, 48, 5, 12]);
    }

    #[test]
    fn empty_shard_returns_zero_metadata() {
        let crdt = make_crdt();
        let mut shard_key = vec![0u8; 35];
        shard_key[0] = 0x01;
        let shard = ShardInfo {
            shard_key,
            prefix: vec![],
            size: vec![],
            data_shards: 0,
            commitment: vec![],
        };
        let meta = get_app_shard_metadata(&crdt, &shard).expect("valid key");
        assert_eq!(meta.size, Vec::<u8>::new());
        assert_eq!(meta.data_shards, 0);
        for c in &meta.commitments {
            assert_eq!(c, &vec![0u8; 64]);
        }
    }

    #[test]
    fn shard_with_vertex_reports_nonzero_metadata() {
        let crdt = make_crdt();

        let mut app_address = [0xCDu8; 32];
        app_address[0] = 0xAB;
        let location = Location {
            app_address,
            data_address: [0x11u8; 32],
        };
        let payload = b"some-vertex-payload";
        crdt.add_vertex(&location, payload).unwrap();

        let typed = quil_hypergraph::addressing::shard_key_for_location(&location);
        let mut shard_key_bytes = Vec::with_capacity(35);
        shard_key_bytes.extend_from_slice(&typed.l1);
        shard_key_bytes.extend_from_slice(&typed.l2);

        let shard = ShardInfo {
            shard_key: shard_key_bytes,
            prefix: vec![],
            size: vec![],
            data_shards: 0,
            commitment: vec![],
        };

        let meta = get_app_shard_metadata(&crdt, &shard).expect("valid key");
        assert_eq!(meta.commitments.len(), 4);
        for c in &meta.commitments {
            assert_eq!(c.len(), 64, "phase commitment must be 64 bytes");
        }
        assert_eq!(meta.size_bigint(), num_bigint::BigInt::from(payload.len()));
        assert_eq!(meta.data_shards, 1);
    }
}
