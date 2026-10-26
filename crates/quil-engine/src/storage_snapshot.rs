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
//! Capturing reads, encodes and hashes the leaves on one background thread
//! ([`request`]), so neither frame execution nor a confirm waits on it.

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
/// a node that retains it. Called from the snapshot thread.
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
/// GLOBAL would record them from a header proposed now (tests).
#[cfg(test)]
pub(crate) fn current_source(crdt: &HypergraphCrdt, filter: &[u8], epoch: u64) -> Source {
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

    /// Each leaf's prefix, id and data.
    fn for_each_leaf(&self, mut f: impl FnMut(&[u32], &[u8], Vec<u8>) -> Result<()>) -> Result<()> {
        for prefix in &self.prefixes {
            let leaf_id = quil_execution::global_intrinsic::leaf_id_bytes(&self.filter, prefix);
            f(prefix, &leaf_id, self.leaf_data(prefix)?)?;
        }
        Ok(())
    }
}

/// A member's sink: encode each leaf into its replica for `member` and store it
/// with its cap and registration root, then the partition, which marks the
/// epoch's leaves ready for the renewal to register.
pub fn encode_member(captured: &Captured, member: &[u8], replicas: &ReplicaStore) -> Result<()> {
    let params = quil_crypto::sdr::SdrParams::default();
    captured.for_each_leaf(|_, leaf_id, data| {
        let key = quil_crypto::sdr::replica_key(member, leaf_id, captured.epoch);
        let encoded = quil_crypto::storage_proof::encode_leaf(&data, &key, &params);
        replicas.put_hash(
            captured.epoch,
            leaf_id,
            &encoded.replica,
            &encoded.replica_cap.to_bytes(),
            &encoded.registration_root(),
        )
    })?;
    let plan = quil_execution::global_intrinsic::storage_snapshot::encode_plan(&[(
        captured.filter.clone(),
        captured.plan.clone(),
    )]);
    replicas.put_snapshot_sources(captured.epoch, &captured.filter, &plan)?;
    replicas.put_partition(captured.epoch, &captured.filter, &captured.prefixes)
}

/// Snapshots this process's members encoded, kept for their seals' bindings
/// (a synced source's scratch store with them).
fn kept() -> &'static std::sync::Mutex<std::collections::HashMap<(Vec<u8>, u64), Arc<Captured>>> {
    static KEPT: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<(Vec<u8>, u64), Arc<Captured>>>,
    > = std::sync::OnceLock::new();
    KEPT.get_or_init(Default::default)
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
/// `member`'s replicas of it into `replicas`, in the background ([`request`]).
pub fn request_member(
    crdt: Arc<HypergraphCrdt>,
    replicas: ReplicaStore,
    member: Vec<u8>,
    filter: Vec<u8>,
    epoch: u64,
    sources: Vec<Source>,
) {
    let key = [b"member".as_slice(), &member, &filter, &epoch.to_be_bytes()].concat();
    request(key, "member", move || {
        let captured = capture_at(&crdt, &filter, epoch, &sources)?;
        info!(epoch, leaves = captured.prefixes.len(), filter = %hex::encode(&filter),
            "storage snapshot taken for the epoch's registration");
        encode_member(&captured, &member, &replicas)?;
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
    let held = HeldReplicas::load(replicas, filter, slot.epoch, &slot.leaves)?;
    let opened =
        epoch_proof::frame_openings(member, slot.epoch, &held.leaves, &held.replicas(), rho_n)
            .ok_or_else(|| {
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

/// A seat's part of its member's epoch proof, from this member's replicas
/// (`storage_epoch_batch`): sealing its registration `seal` for `epoch + 2`
/// (with the output of the GLOBAL frame after it, the beacon, and the
/// snapshot it was read from, for each leaf's binding), settling `settle` for
/// `epoch` with the frames GLOBAL chained there (`slot.chained`, with their
/// beacons from [`chained_beacons`]). Each frame's root is recomputed from the
/// replicas, as the member committed it, and the chain must match GLOBAL's.
/// Preparing relabels each sealed leaf at its challenges, so it runs in the
/// background.
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
    let sealed_refs: Vec<&[u8]> = sealed.iter().map(Vec::as_slice).collect();
    let held_refs = held
        .as_ref()
        .map(HeldReplicas::replicas)
        .unwrap_or_default();
    let witness = epoch_proof::prepare(member, &claim, &sealed_refs, &held_refs)
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

type Job = Box<dyn FnOnce() + Send>;

/// Seconds a failed snapshot waits before it is tried again.
const SNAPSHOT_RETRY_SECS: u64 = 60;

/// Run the snapshot job for `key` ([`spawn`]) unless one is queued or
/// running, or the last failed less than [`SNAPSHOT_RETRY_SECS`] ago. A job
/// that succeeds leaves its record behind, so its caller stops asking.
pub fn request(
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
    spawn(label, move || {
        let result = job();
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

/// Run snapshot jobs one at a time on a thread of their own: an archive may
/// take every shard's snapshot within minutes, and each job holds a leaf's
/// data and tree in memory.
pub fn spawn(label: &'static str, job: impl FnOnce() -> Result<()> + Send + 'static) {
    static QUEUE: std::sync::OnceLock<std::sync::Mutex<std::sync::mpsc::Sender<Job>>> =
        std::sync::OnceLock::new();
    let queue = QUEUE.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("storage-snapshots".into())
            .spawn(move || {
                for job in rx {
                    job();
                }
            })
            .expect("storage snapshot thread");
        std::sync::Mutex::new(tx)
    });
    let job: Job = Box::new(move || {
        let started = std::time::Instant::now();
        match job() {
            Ok(()) => info!(
                label,
                seconds = started.elapsed().as_secs_f64(),
                "storage snapshot job done"
            ),
            Err(error) => {
                warn!(label, %error, "storage snapshot job failed; it is tried again when next needed")
            }
        }
    });
    if let Ok(sender) = queue.lock() {
        let _ = sender.send(job);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_hypergraph::Location;

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
}
