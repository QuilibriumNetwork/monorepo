//! Reclaims a worker store's canonical app payload outside the scopes it still
//! serves. A worker keeps its RocksDB across reassignments, so every shard it
//! leaves would otherwise stay on disk indefinitely. Only versioned vertex and
//! hyperedge blobs of applications with a protected scope are removed; forest
//! nodes, clock/consensus records, replicas and GLOBAL state are untouched.
//! Readiness markers that promised the removed data are invalidated in the same
//! write, so a later assignment to that scope repairs it through sync. The
//! forest confinement records each shard whose subtree it drops while the
//! store keeps that shard's frames ([`lineage_drop_records`]), so a later
//! binding re-anchors it instead of replaying onto the missing state.

use std::collections::BTreeMap;

use quil_forest::CoordinatedDb;
use quil_hypergraph::HypergraphCrdt;
use quil_types::error::{QuilError, Result};

type Address = [u8; 32];
type Interval = (Address, Address);

const VERIFIED: &[u8] = b"quil/forest-sync/verified-blobs/v1/";
const INCOMPLETE: &[u8] = b"quil/forest-sync/incomplete/v1/";
const PAYLOAD_KEY_LEN: usize = 110;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub removed_records: u64,
    pub removed_bytes: u64,
    pub ranges: usize,
    pub invalidated_markers: usize,
    /// Interrupted-sync markers whose evicted scopes were dropped in the
    /// same write, narrowed to the kept scopes they cover or deleted.
    pub sync_markers: usize,
    /// Payload ranges compacted to reclaim files that hold only deleted
    /// records, and those files' bytes. A snapshot older than the deletion
    /// keeps them until it is released; a later pass compacts again.
    pub compacted_ranges: usize,
    pub reclaimable_bytes: u64,
    /// The caller's condition to go on failed before the deletion: nothing
    /// was removed.
    pub stopped: bool,
}

fn unavailable(message: impl Into<String>) -> QuilError {
    QuilError::ExecutionUnavailable(message.into())
}

fn store_error(error: impl std::fmt::Display) -> QuilError {
    QuilError::Store(error.to_string())
}

const HISTORY_REFUSAL: &str = "application has indexed historical roots or manifests";

/// Why a pass removed nothing, with what it had planned to remove and the
/// index entry that stopped it, for its warn line.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub error: QuilError,
    /// Records and bytes the pass planned to remove, once it had planned.
    pub planned: Option<(u64, u64)>,
    /// The tag of the historical root or manifest index entry that refused
    /// the pass, and the frame that entry records where it is well formed.
    pub blocking: Option<(u8, Option<u64>)>,
    /// The phase and bit path of the interrupted-sync scope that refused
    /// the pass.
    pub sync_scope: Option<(u8, Vec<bool>)>,
}

impl From<QuilError> for Refusal {
    fn from(error: QuilError) -> Self {
        Self {
            error,
            planned: None,
            blocking: None,
            sync_scope: None,
        }
    }
}

const INTERRUPTED_SYNC: &str = "application has an interrupted sync";

/// One `(phase, bit path)` scope of an interrupted-sync marker.
type SyncScope = (u8, Vec<bool>);

/// The scopes an interrupted-sync marker lists
/// (`phase ‖ bits(u16) ‖ packed path`, repeated), or `None` unless the
/// value is exactly such a list.
fn sync_scopes(mut value: &[u8]) -> Option<Vec<SyncScope>> {
    let mut scopes = Vec::new();
    while !value.is_empty() {
        let len = u16::from_be_bytes([*value.get(1)?, *value.get(2)?]) as usize;
        if len > 256 {
            return None;
        }
        let packed = value.get(3..3 + len.div_ceil(8))?;
        let bits = (0..len).map(|i| packed[i / 8] & (0x80 >> (i % 8)) != 0);
        scopes.push((value[0], bits.collect()));
        value = &value[3 + packed.len()..];
    }
    Some(scopes)
}

fn encode_sync_scopes(scopes: &[(u8, Vec<bool>)]) -> Vec<u8> {
    let mut value = Vec::new();
    for (phase, bits) in scopes {
        value.push(*phase);
        value.extend((bits.len() as u16).to_be_bytes());
        for chunk in bits.chunks(8) {
            value.push(
                chunk
                    .iter()
                    .enumerate()
                    .fold(0, |byte, (i, bit)| byte | (u8::from(*bit) << (7 - i))),
            );
        }
    }
    value
}

/// An interrupted-sync marker's scopes once the gaps outside `keep` are
/// evicted, or the scope that refuses the pass. A scope wholly in a gap
/// loses all its records, so it is dropped. A scope wholly kept is a sync of
/// a served shard that has not finished: the pass waits for it. A scope
/// reaching both (the parent of a kept shard after a split, whose sync was
/// cut short) keeps its claim only on what stays: it is narrowed to the kept
/// paths inside it, which read as partly installed as before
/// (`HypergraphCrdt::sync_incomplete` matches either way along a path).
fn narrowed_sync_scopes(
    scopes: &[(u8, Vec<bool>)],
    keep: &[Interval],
    paths: &[Vec<bool>],
) -> std::result::Result<Vec<SyncScope>, SyncScope> {
    let mut narrowed: Vec<(u8, Vec<bool>)> = Vec::new();
    for (phase, bits) in scopes {
        let (lo, hi) = bounds(bits);
        if keep.iter().any(|(a, b)| lo >= *a && hi <= *b) {
            return Err((*phase, bits.clone()));
        }
        if keep.iter().all(|(a, b)| hi < *a || lo > *b) {
            continue;
        }
        let inside: Vec<&Vec<bool>> = paths
            .iter()
            .filter(|path| path.len() > bits.len() && path.starts_with(bits))
            .collect();
        if inside.is_empty() {
            return Err((*phase, bits.clone()));
        }
        for path in inside {
            let scope = (*phase, path.clone());
            if !narrowed.contains(&scope) {
                narrowed.push(scope);
            }
        }
    }
    Ok(narrowed)
}

/// The bit path of each protected filter, by application.
fn kept_paths(filters: &[Vec<u8>]) -> BTreeMap<Address, Vec<Vec<bool>>> {
    let mut paths = BTreeMap::<Address, Vec<Vec<bool>>>::new();
    for filter in filters {
        if let Some((app, bits)) = quil_forest::decode_shard_filter_or_root(filter, 32) {
            if let Ok(app) = Address::try_from(app) {
                paths.entry(app).or_default().push(bits);
            }
        }
    }
    paths
}

/// The frame a root-version entry (`version ‖ frame`) or a manifest
/// (`frame ‖ entries`) records.
fn indexed_frame(tag: u8, value: &[u8]) -> Option<u64> {
    let frame = match tag {
        quil_store::encoding::HG_ROOT_VERSION if value.len() == 16 => &value[8..],
        quil_store::encoding::HG_APP_MANIFEST if value.len() >= 8 => &value[..8],
        _ => return None,
    };
    Some(u64::from_be_bytes(frame.try_into().ok()?))
}

/// Whether a store may answer for its historical roots: every store but a
/// data worker's own. A peer that resolves an application root of such a
/// store reads that root's leaves and blobs from it, so an eviction there
/// would hand out a tree without its payload. A worker's store is never
/// served to peers (only the master's is), and the forest confinement that
/// follows each pass drops the trees outside the kept scopes at every
/// version, so its index names nothing a reader of it can still need.
fn serves_history(db: &CoordinatedDb) -> bool {
    !matches!(db.store_role(), Some(quil_forest::StoreRole::Worker(_)))
}

fn increment(mut address: Address) -> Option<Address> {
    for byte in address.iter_mut().rev() {
        if *byte != 255 {
            *byte += 1;
            return Some(address);
        }
        *byte = 0;
    }
    None
}

fn successor(mut prefix: Vec<u8>) -> Option<Vec<u8>> {
    while prefix.last() == Some(&255) {
        prefix.pop();
    }
    *prefix.last_mut()? += 1;
    Some(prefix)
}

fn bounds(bits: &[bool]) -> Interval {
    let (mut lo, mut hi) = ([0; 32], [255; 32]);
    for (i, bit) in bits.iter().enumerate() {
        let mask = 0x80 >> (i % 8);
        if *bit {
            lo[i / 8] |= mask
        } else {
            hi[i / 8] &= !mask
        }
    }
    (lo, hi)
}

/// Merged address intervals each application must keep. GLOBAL is skipped:
/// its records never share the application payload domains.
fn coverage(filters: &[Vec<u8>]) -> Result<BTreeMap<Address, Vec<Interval>>> {
    let mut apps = BTreeMap::<Address, Vec<Interval>>::new();
    for filter in filters {
        let (app, bits) = quil_forest::decode_shard_filter_or_root(filter, 32)
            .ok_or_else(|| QuilError::InvalidArgument("invalid protected filter".into()))?;
        if bits.len() > 256 || (filter.len() == 33 && filter[32] >= 64) {
            return Err(QuilError::InvalidArgument(
                "invalid protected address depth".into(),
            ));
        }
        let app: Address = app
            .try_into()
            .map_err(|_| QuilError::InvalidArgument("invalid application".into()))?;
        if app == [255; 32] {
            continue;
        }
        apps.entry(app).or_default().push(bounds(&bits));
    }
    for ranges in apps.values_mut() {
        ranges.sort();
        let mut merged: Vec<Interval> = Vec::new();
        for (lo, hi) in ranges.drain(..) {
            if let Some((_, end)) = merged.last_mut() {
                if lo <= *end || increment(*end) == Some(lo) {
                    *end = (*end).max(hi);
                    continue;
                }
            }
            merged.push((lo, hi));
        }
        *ranges = merged;
    }
    Ok(apps)
}

/// Half-open address gaps between the kept intervals; `None` is unbounded.
fn gaps(keep: &[Interval]) -> Vec<(Address, Option<Address>)> {
    let mut out = Vec::new();
    let mut cursor = Some([0; 32]);
    for (lo, hi) in keep {
        if let Some(start) = cursor {
            if start < *lo {
                out.push((start, Some(*lo)));
            }
        }
        cursor = increment(*hi);
    }
    if let Some(start) = cursor {
        out.push((start, None));
    }
    out
}

fn scan(
    db: &CoordinatedDb,
    lower: &[u8],
    upper: Option<&[u8]>,
    mut visit: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    // A pass reads whole payload ranges, mostly ones it then deletes: keep
    // their blocks out of the block cache, as the store's shard sweeps do,
    // so a pass does not displace the point-read working set.
    let mut options = rocksdb::ReadOptions::default();
    options.fill_cache(false);
    let mut it = db.raw_iterator_opt(options);
    it.seek(lower);
    while let (Some(key), Some(value)) = (it.key(), it.value()) {
        if upper.map_or(!key.starts_with(lower), |upper| key >= upper) {
            break;
        }
        visit(key, value)?;
        it.next();
    }
    it.status().map_err(store_error)
}

struct Plan {
    /// Gap ranges that still hold records.
    ranges: Vec<(Vec<u8>, Vec<u8>)>,
    /// Every gap range of the protected applications.
    gaps: Vec<(Vec<u8>, Vec<u8>)>,
    records: u64,
    bytes: u64,
}

/// Read-only: the payload ranges outside `keep`, refusing anything whose
/// layout or completeness it cannot vouch for.
fn plan(db: &CoordinatedDb, apps: &BTreeMap<Address, Vec<Interval>>) -> Result<Plan> {
    let mut plan = Plan {
        ranges: Vec::new(),
        gaps: Vec::new(),
        records: 0,
        bytes: 0,
    };
    for (app, keep) in apps {
        let shard = quil_types::store::ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(app, 256, 3),
            l2: *app,
        };
        for (set, phase) in [
            ("vertex", "adds"),
            ("vertex", "removes"),
            ("hyperedge", "adds"),
            ("hyperedge", "removes"),
        ] {
            let mut prefix =
                quil_store::encoding::hypergraph_vertex_data_v2_shard_prefix(set, phase, &shard);
            prefix.extend(app);
            for (lo, hi) in gaps(keep) {
                let mut lower = prefix.clone();
                lower.extend(lo);
                let upper = match hi {
                    Some(hi) => [prefix.as_slice(), hi.as_slice()].concat(),
                    None => successor(prefix.clone())
                        .ok_or_else(|| unavailable("unbounded payload domain"))?,
                };
                let mut found = false;
                // Every key a tombstone would cover must be a canonical blob of
                // this application; mixed-length keys can interleave.
                scan(db, &lower, Some(&upper), |key, value| {
                    if key.len() != PAYLOAD_KEY_LEN {
                        return Err(unavailable("mixed-length keys in a payload gap"));
                    }
                    found = true;
                    plan.records += 1;
                    plan.bytes += (key.len() + value.len()) as u64;
                    Ok(())
                })?;
                if found {
                    plan.ranges.push((lower.clone(), upper.clone()));
                }
                plan.gaps.push((lower, upper));
            }
        }
    }
    Ok(plan)
}

/// The marker writes an eviction makes in its own batch.
#[derive(Default)]
struct Marked {
    /// Readiness markers the removal falsifies.
    invalid: Vec<Vec<u8>>,
    /// Interrupted-sync markers left with no scope.
    dropped: Vec<Vec<u8>>,
    /// Interrupted-sync markers narrowed to their kept scopes.
    narrowed: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Checks that need the write barrier: nothing may claim an interrupted
/// sync of a kept scope ([`narrowed_sync_scopes`]) for an evicted
/// application, nor, on a store that may serve its history
/// ([`serves_history`]), historical roots or manifests; readiness markers
/// the removal falsifies and the evicted scopes of interrupted syncs are
/// collected for the same batch.
fn markers(
    db: &CoordinatedDb,
    apps: &BTreeMap<Address, Vec<Interval>>,
    paths: &BTreeMap<Address, Vec<Vec<bool>>>,
    affected: &[Address],
    history: bool,
) -> std::result::Result<Marked, Refusal> {
    let mut marked = Marked::default();
    let invalid = &mut marked.invalid;
    for app in affected {
        let keep = &apps[app];
        let app_paths = paths.get(app).map_or(&[][..], Vec::as_slice);
        let tags = [
            quil_store::encoding::HG_ROOT_VERSION,
            quil_store::encoding::HG_APP_MANIFEST,
        ];
        for tag in tags.into_iter().filter(|_| history) {
            let mut blocking = None;
            if let Err(error) = scan(db, &[tag], None, |key, value| {
                if key.len() >= 35 && key[3..35] == app[..] {
                    blocking = Some((tag, indexed_frame(tag, value)));
                    return Err(unavailable(HISTORY_REFUSAL));
                }
                Ok(())
            }) {
                return Err(Refusal {
                    blocking,
                    ..Refusal::from(error)
                });
            }
        }
        let mut sync_scope = None;
        let mut rewrites = Vec::new();
        if let Err(error) = scan(db, INCOMPLETE, None, |key, value| {
            let tail = &key[INCOMPLETE.len()..];
            if tail.len() < 34 {
                return Err(unavailable("malformed incomplete-sync marker"));
            }
            if tail[2..34] != app[..] || value.is_empty() {
                return Ok(());
            }
            // A legacy shard id or an unreadable list claims scopes this pass
            // cannot place.
            let scopes = match sync_scopes(value) {
                Some(scopes) if tail.len() == 34 && tail[..2] == 32u16.to_be_bytes() => scopes,
                _ => return Err(unavailable(INTERRUPTED_SYNC)),
            };
            match narrowed_sync_scopes(&scopes, keep, app_paths) {
                Err(scope) => {
                    sync_scope = Some(scope);
                    Err(unavailable(INTERRUPTED_SYNC))
                }
                Ok(narrowed) if narrowed == scopes => Ok(()),
                Ok(narrowed) => {
                    rewrites.push((key.to_vec(), narrowed));
                    Ok(())
                }
            }
        }) {
            return Err(Refusal {
                sync_scope,
                ..Refusal::from(error)
            });
        }
        for (key, narrowed) in rewrites {
            if narrowed.is_empty() {
                marked.dropped.push(key);
            } else {
                marked.narrowed.push((key, encode_sync_scopes(&narrowed)));
            }
        }
        scan(db, VERIFIED, None, |key, value| {
            let tail = &key[VERIFIED.len()..];
            if tail.len() < 2 {
                return Err(unavailable("short readiness marker"));
            }
            let n = u16::from_be_bytes([tail[0], tail[1]]) as usize;
            if n < 32 || tail.len() < n + 5 {
                return Err(unavailable("malformed readiness marker"));
            }
            let bits = u16::from_be_bytes([tail[n + 3], tail[n + 4]]) as usize;
            if bits > 256
                || tail.len() != n + 5 + bits.div_ceil(8)
                || tail[n + 2] >= 4
                || value != [1]
            {
                return Err(unavailable("malformed readiness scope"));
            }
            if tail[2..34] == app[..] {
                let packed = &tail[n + 5..];
                let (lo, hi) = bounds(
                    &(0..bits)
                        .map(|i| packed[i / 8] & (0x80 >> (i % 8)) != 0)
                        .collect::<Vec<_>>(),
                );
                // An exact unified scope wholly inside a kept interval still
                // holds all its data. Broad, overlapping or legacy scopes do not.
                if n != 32 || !keep.iter().any(|(a, b)| lo >= *a && hi <= *b) {
                    invalid.push(key.to_vec());
                }
            }
            Ok(())
        })?;
    }
    Ok(marked)
}

/// Remove payload outside `keep` from this worker's store. Unified stores
/// only: legacy whole-application trees do not isolate their prefixes. The
/// scan runs without barriers; the caller guarantees no writer targets the
/// gaps (only kept scopes are served). The write itself runs under the CRDT
/// forest and commit barriers, which refuse while mutations are pending.
pub fn evict_outside(crdt: &HypergraphCrdt, keep: &[Vec<u8>]) -> Result<Outcome> {
    evict_outside_while(crdt, keep, &|| true)
}

/// [`evict_outside`] while `proceed` says so: it is asked under the forest
/// write barrier just before the deletion, which is skipped once it says no
/// ([`Outcome::stopped`]), as when the worker was rebound during the scan to
/// a shard `keep` does not protect.
pub fn evict_outside_while(
    crdt: &HypergraphCrdt,
    keep: &[Vec<u8>],
    proceed: &dyn Fn() -> bool,
) -> Result<Outcome> {
    evict(crdt, keep, proceed).map_err(|refusal| refusal.error)
}

/// [`evict_outside_while`], keeping what a refused pass had planned and the
/// index entry that refused it ([`Refusal`]).
pub(crate) fn evict(
    crdt: &HypergraphCrdt,
    keep: &[Vec<u8>],
    proceed: &dyn Fn() -> bool,
) -> std::result::Result<Outcome, Refusal> {
    if !crdt.unified_tree() {
        return Err(unavailable("payload eviction requires a unified store").into());
    }
    let apps = coverage(keep)?;
    let guard = crdt.lock_forest_writes();
    let db = crdt.maintain_forest(&guard, |forest| {
        forest
            .db()
            .cloned()
            .ok_or_else(|| unavailable("payload eviction requires a persistent forest"))
    })?;
    drop(guard);
    let planned = plan(&db, &apps)?;
    let mut outcome = Outcome::default();
    if !planned.ranges.is_empty() {
        let history = serves_history(&db);
        let paths = kept_paths(keep);
        outcome =
            delete(crdt, &db, &apps, &paths, &planned, history, proceed).map_err(|refusal| {
                Refusal {
                    planned: Some((planned.records, planned.bytes)),
                    ..refusal
                }
            })?;
        if outcome.stopped {
            return Ok(outcome);
        }
    }
    reclaim(&db, &planned.gaps, &mut outcome)?;
    Ok(outcome)
}

/// Every shard lineage this store keeps: each filter with a materialized
/// cursor above zero, and that cursor. A worker keeps the frames and cursor
/// of every shard it served.
pub(crate) fn lineages(db: &CoordinatedDb) -> Result<Vec<(Vec<u8>, u64)>> {
    let prefix = [
        quil_store::encoding::CONSENSUS,
        quil_store::encoding::CONSENSUS_MATERIALIZED_CURSOR,
    ];
    let mut found = Vec::new();
    scan(db, &prefix, None, |key, value| {
        let filter = &key[prefix.len()..];
        if let (true, Ok(bytes)) = (filter.len() >= 32, <[u8; 8]>::try_from(value)) {
            let cursor = u64::from_be_bytes(bytes);
            if cursor > 0 {
                found.push((filter.to_vec(), cursor));
            }
        }
        Ok(())
    })?;
    Ok(found)
}

/// The dropped-lineage record of each lineage of `crdt`'s store, for the
/// forest confinement to write when it drops that shard's subtree
/// ([`HypergraphCrdt::confine_forest_recording`]): the cursor the frames
/// stopped at ([`crate::app_handoff::dropped_lineage`]). A lineage whose
/// subtree already holds no leaf in any phase (an empty shard, or one an
/// earlier confinement dropped) gets none: there is nothing to drop.
pub(crate) fn lineage_drop_records(
    crdt: &HypergraphCrdt,
) -> Result<Vec<quil_hypergraph::LineageRecord>> {
    let Some(db) = crdt.forest_store() else {
        return Ok(Vec::new());
    };
    let empty = |filter: &[u8]| {
        crdt.canonical_bits_for_filter(filter).is_some_and(|bits| {
            [
                ("vertex", "adds"),
                ("vertex", "removes"),
                ("hyperedge", "adds"),
                ("hyperedge", "removes"),
            ]
            .iter()
            .all(|(set, phase)| {
                crdt.unified_subtree_leaf_count_checked(set, phase, &filter[..32], &bits) == Some(0)
            })
        })
    };
    Ok(lineages(&db)?
        .into_iter()
        .filter(|(filter, _)| !empty(filter))
        .map(|(filter, cursor)| {
            let record = (
                quil_store::encoding::app_lineage_dropped_key(&filter),
                cursor.to_be_bytes().to_vec(),
            );
            (filter, vec![record])
        })
        .collect())
}

/// The shards whose data this store holds, with their materialized cursors:
/// a lineage ([`lineages`]) that no current dropped-lineage record names
/// and, while the store commits unified trees, whose subtree holds committed
/// leaves ([`crate::app_shard_metadata::has_committed_shard_data`]). Binding
/// a shard to the worker that holds it saves an archive install of it.
/// Each lineage costs point reads and subtree leaf counts, so a store that
/// served many shards takes long: run it off a worker's runtime thread.
pub(crate) fn held_shards(crdt: &HypergraphCrdt) -> Result<HeldShards> {
    let Some(db) = crdt.forest_store() else {
        return Ok(HeldShards::default());
    };
    let lineages = lineages(&db)?;
    let count = lineages.len();
    let mut held = Vec::new();
    for (filter, cursor) in lineages {
        let dropped = db
            .get(quil_store::encoding::app_lineage_dropped_key(&filter))
            .map_err(store_error)?
            .is_some_and(|bytes| bytes == cursor.to_be_bytes());
        if dropped
            || (crdt.unified_tree()
                && !crate::app_shard_metadata::has_committed_shard_data(crdt, &filter))
        {
            continue;
        }
        held.push((filter, cursor));
    }
    Ok(HeldShards {
        lineages: count,
        held,
    })
}

/// What [`held_shards`] read: the shards held and the lineages examined.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct HeldShards {
    pub lineages: usize,
    pub held: Vec<(Vec<u8>, u64)>,
}

/// Forest node records a confinement sweep examines per hold of the worker's
/// forest and commit locks, keeping each pause of its frame commits short.
const FOREST_SCAN_BUDGET: usize = 250_000;

/// Why a worker defers a request to evict outside `keep`, or `None` to run
/// it: the scope it is bound to must be protected, served by a running
/// engine, and settled.
pub(crate) fn deferral(
    bound: &[u8],
    keep: &[Vec<u8>],
    serving: bool,
    bound_for: std::time::Duration,
) -> Option<&'static str> {
    if bound.is_empty() || !keep.iter().any(|filter| filter.as_slice() == bound) {
        Some("binding is not protected")
    } else if !serving {
        Some("engine is not serving the binding")
    } else if bound_for < crate::worker_allocator::PAYLOAD_EVICTION_SETTLE {
        Some("binding has not settled")
    } else {
        None
    }
}

/// How long one eviction run, its passes and the read of the shards its
/// store holds, may take before it is warned about. A run that removes
/// nothing takes seconds even where the read of the shards held contends
/// for I/O with every other worker's.
pub(crate) const RUN_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

/// What a worker's eviction passes did, for its run line ([`log_run`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PassReport {
    pub payload: std::time::Duration,
    pub forest: std::time::Duration,
    pub storage: std::time::Duration,
    /// The passes may have changed which shards the store holds: payload
    /// was deleted, the forest of a left shard was dropped or swept, or a
    /// pass failed and its effect is unknown.
    pub changed: bool,
    /// The pass a rebind stopped, if any.
    pub stopped: Option<&'static str>,
}

/// How a run left the record of the shards a worker's store holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Publish {
    /// The passes changed nothing it reads, and it was recorded: kept.
    Skipped,
    /// Read again and recorded.
    Read {
        lineages: usize,
        held: usize,
        took: std::time::Duration,
    },
    /// Read again, but a newer read or a withdrawal began meanwhile, which
    /// stands instead.
    Superseded { took: std::time::Duration },
    /// The read failed; none is recorded for the worker.
    Failed { took: std::time::Duration },
    /// A standalone worker keeps no such record.
    NotKept,
}

impl Publish {
    fn label(&self) -> &'static str {
        match self {
            Self::Skipped => "kept: the passes changed no shard the store holds",
            Self::Read { .. } => "read again",
            Self::Superseded { .. } => "superseded by a newer read",
            Self::Failed { .. } => "read failed",
            Self::NotKept => "not kept by a standalone worker",
        }
    }

    fn took(&self) -> Option<std::time::Duration> {
        match self {
            Self::Read { took, .. } | Self::Superseded { took } | Self::Failed { took } => {
                Some(*took)
            }
            Self::Skipped | Self::NotKept => None,
        }
    }
}

/// One line per eviction run, no-op runs included: each pass's duration,
/// how the record of the shards held was left, and the run's total. A run
/// over [`RUN_BUDGET`] is warned about instead, once per run (each worker
/// runs at most once per eviction interval).
pub(crate) fn log_run(
    core_id: u32,
    filter: &str,
    report: &PassReport,
    publish: &Publish,
    total: std::time::Duration,
) {
    let (lineages, held) = match publish {
        Publish::Read { lineages, held, .. } => (Some(*lineages as u64), Some(*held as u64)),
        _ => (None, None),
    };
    let ms = |d: std::time::Duration| d.as_millis() as u64;
    let publish_ms = publish.took().map(ms);
    let stopped = report.stopped.unwrap_or("none");
    if total > RUN_BUDGET {
        tracing::warn!(core_id, filter, payload_ms = ms(report.payload), forest_ms = ms(report.forest),
            storage_ms = ms(report.storage), changed = report.changed, stopped, shard_data = publish.label(),
            lineages, held, publish_ms, secs = total.as_secs(), budget_secs = RUN_BUDGET.as_secs(),
            scope = "this node",
            action = "the run does not block the worker's thread; if this repeats, check the worker store's disk \
                and I/O pressure, then report it with this line",
            "worker eviction run overran its budget");
    } else {
        tracing::info!(
            core_id,
            filter,
            payload_ms = ms(report.payload),
            forest_ms = ms(report.forest),
            storage_ms = ms(report.storage),
            changed = report.changed,
            stopped,
            shard_data = publish.label(),
            lineages,
            held,
            publish_ms,
            secs = total.as_secs(),
            "worker eviction run finished"
        );
    }
}

/// A worker's eviction passes for `keep`, in a thread or a standalone
/// process: the payload outside its served scopes, the forest of the shards
/// it left, then, under `storage`'s base directory, the consensus storage of
/// shards it left unless the predicate says it still owes that shard's
/// committee a vote or seal. `filter` names the binding in the logs.
/// `bound` says whether the worker still serves the binding the passes
/// were started for: the deferral is checked once, at the start, and a
/// worker rebound meanwhile may serve a shard `keep` does not protect, so
/// the forest and storage passes stop as soon as it says no.
/// `before_delete` runs under the forest write barrier just before the
/// payload deletion, the one write after which the store holds a shard's
/// forest without its payload until the forest pass drops it.
pub(crate) async fn run_passes<R>(
    core_id: u32,
    filter: String,
    crdt: std::sync::Arc<HypergraphCrdt>,
    keep: Vec<Vec<u8>>,
    storage: Option<(std::path::PathBuf, R)>,
    bound: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    before_delete: std::sync::Arc<dyn Fn() + Send + Sync>,
) -> PassReport
where
    R: Fn(&[u8]) -> bool + Send + 'static,
{
    use std::sync::atomic::{AtomicBool, Ordering};
    use tracing::{debug, info, warn};
    let (forest_crdt, forest_keep, storage_keep) = (crdt.clone(), keep.clone(), keep.clone());
    let mut report = PassReport::default();
    let rebound = |stage: &'static str, mut report: PassReport| {
        info!(core_id, filter, stage,
            "worker eviction stopped: the worker was rebound during the pass; the next pass resumes it");
        report.stopped = Some(stage);
        report
    };
    let started = std::time::Instant::now();
    let payload_bound = bound.clone();
    let deleting = std::sync::Arc::new(AtomicBool::new(false));
    let deleted = deleting.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        evict(&crdt, &keep, &|| {
            let proceed = payload_bound();
            if proceed {
                deleting.store(true, Ordering::SeqCst);
                before_delete();
            }
            proceed
        })
    })
    .await;
    report.payload = started.elapsed();
    // A refusal comes before the deletion; a task that failed may have
    // deleted.
    report.changed = deleted.load(Ordering::SeqCst) || outcome.is_err();
    if matches!(&outcome, Ok(Ok(o)) if o.stopped) {
        return rebound("payload eviction", report);
    }
    match outcome {
        Ok(Ok(o)) if o.ranges > 0 || o.compacted_ranges > 0 => info!(
            core_id,
            filter,
            removed_records = o.removed_records,
            removed_bytes = o.removed_bytes,
            ranges = o.ranges,
            invalidated_markers = o.invalidated_markers,
            sync_markers = o.sync_markers,
            compacted_ranges = o.compacted_ranges,
            reclaimable_bytes = o.reclaimable_bytes,
            secs = started.elapsed().as_secs(),
            "worker payload outside served scopes evicted"
        ),
        Ok(Ok(_)) => debug!(core_id, "no worker payload outside served scopes"),
        Ok(Err(refusal)) => {
            let (planned_records, planned_bytes) = refusal.planned.unzip();
            let (blocking_tag, blocking_frame) = match refusal.blocking {
                Some((tag, frame)) => (Some(tag), frame),
                None => (None, None),
            };
            let blocking_index = blocking_tag.map(|tag| match tag {
                quil_store::encoding::HG_ROOT_VERSION => "root version",
                _ => "app manifest",
            });
            // `phase 0 path 0110`; the empty path is the whole application.
            let sync_scope = refusal.sync_scope.as_ref().map(|(phase, bits)| {
                let path: String = bits
                    .iter()
                    .map(|&bit| if bit { '1' } else { '0' })
                    .collect();
                format!(
                    "phase {phase} path {}",
                    if path.is_empty() {
                        "(whole application)"
                    } else {
                        path.as_str()
                    }
                )
            });
            warn!(core_id, filter, error = %refusal.error, planned_records, planned_bytes,
                blocking_index, blocking_tag, blocking_frame, sync_scope = sync_scope.as_deref(),
                scope = "this node",
                action = "the next pass retries within the hour; an interrupted sync of a kept scope stops \
                    refusing once that shard's sync completes; a refusal that repeats for another reason, or a \
                    store error, is a defect: report it with this line",
                "worker payload eviction refused")
        }
        Err(error) => warn!(core_id, filter, %error, "worker payload eviction task failed"),
    }
    // The forest subtrees of the shards this worker left, recording each
    // shard whose frames it keeps.
    if !bound() {
        return rebound("forest confinement", report);
    }
    let started = std::time::Instant::now();
    let proceed = bound.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let lineages = lineage_drop_records(&forest_crdt)?;
        forest_crdt.confine_forest_recording(&forest_keep, FOREST_SCAN_BUDGET, &lineages, &*proceed)
    })
    .await;
    report.forest = started.elapsed();
    // A refusal may follow another application's commit.
    report.changed |= match &outcome {
        Ok(Ok(o)) => !o.dropped_lineages.is_empty() || o.commits > 0 || o.nodes > 0,
        _ => true,
    };
    let stopped = matches!(&outcome, Ok(Ok(o)) if o.stopped);
    if let Ok(Ok(o)) = &outcome {
        if !o.dropped_lineages.is_empty() {
            let shards: Vec<String> = o.dropped_lineages.iter().take(8).map(hex::encode).collect();
            info!(core_id, filter, dropped = o.dropped_lineages.len(), shards = ?shards,
                "evicted shards' lineage marked; a later binding to one of them re-anchors it at once");
        }
    }
    match outcome {
        Ok(Ok(o)) if o.commits > 0 || o.nodes > 0 => info!(
            core_id,
            filter,
            commits = o.commits,
            nodes = o.nodes,
            retained_nodes = o.retained_nodes,
            stale_records = o.stale_records,
            key_ranges = o.key_ranges,
            secs = started.elapsed().as_secs(),
            "worker forest outside served scopes removed"
        ),
        Ok(Ok(_)) => debug!(core_id, "no worker forest outside served scopes"),
        Ok(Err(error)) => warn!(core_id, filter, %error, "worker forest confinement refused"),
        Err(error) => warn!(core_id, filter, %error, "worker forest confinement task failed"),
    }
    if stopped {
        return rebound("forest confinement", report);
    }
    // Consensus storage of shards this worker left, unless it still owes
    // that shard's committee a vote or seal. The record of the shards the
    // store holds reads none of it.
    if !bound() {
        return rebound("consensus storage", report);
    }
    if let Some((base, retained)) = storage {
        let started = std::time::Instant::now();
        let outcome = tokio::task::spawn_blocking(move || {
            crate::worker_consensus_storage::remove_outside(&base, &storage_keep, retained)
        })
        .await;
        report.storage = started.elapsed();
        match outcome {
            Ok(Ok(o)) if o.entries > 0 => info!(
                core_id,
                filter,
                entries = o.entries,
                bytes = o.bytes,
                "worker consensus storage outside served scopes removed"
            ),
            Ok(Ok(_)) => debug!(core_id, "no worker consensus storage outside served scopes"),
            Ok(Err(error)) => {
                warn!(core_id, filter, %error, "worker consensus storage removal failed")
            }
            Err(error) => {
                warn!(core_id, filter, %error, "worker consensus storage removal task failed")
            }
        }
    }
    report
}

/// Compact gap ranges that still contain SST files lying wholly inside them:
/// with no visible keys left there, those files hold only deleted records.
/// A file ends at `upper` when it carries the range tombstone, whose bound
/// is its exclusive end; no payload key equals that shorter bound. Such
/// files usually sit in the bottommost level, which a default range
/// compaction skips, so the bottommost level is compacted explicitly.
fn reclaim(db: &CoordinatedDb, gaps: &[(Vec<u8>, Vec<u8>)], outcome: &mut Outcome) -> Result<()> {
    let files = db.live_files().map_err(store_error)?;
    let mut options = rocksdb::CompactOptions::default();
    options.set_bottommost_level_compaction(rocksdb::BottommostLevelCompaction::ForceOptimized);
    for (lower, upper) in gaps {
        let inside: u64 = files
            .iter()
            .filter(|f| match (f.start_key.as_deref(), f.end_key.as_deref()) {
                (Some(a), Some(b)) => a >= lower.as_slice() && b <= upper.as_slice(),
                _ => false,
            })
            .map(|f| f.size as u64)
            .sum();
        if inside > 0 {
            db.compact_range_opt(Some(lower), Some(upper), &options);
            outcome.compacted_ranges += 1;
            outcome.reclaimable_bytes += inside;
        }
    }
    Ok(())
}

fn delete(
    crdt: &HypergraphCrdt,
    db: &CoordinatedDb,
    apps: &BTreeMap<Address, Vec<Interval>>,
    paths: &BTreeMap<Address, Vec<Vec<bool>>>,
    planned: &Plan,
    history: bool,
    proceed: &dyn Fn() -> bool,
) -> std::result::Result<Outcome, Refusal> {
    let affected: Vec<Address> = apps
        .keys()
        .filter(|app| {
            planned
                .ranges
                .iter()
                .any(|(lower, _)| lower[38..70] == app[..])
        })
        .copied()
        .collect();
    let guard = crdt.lock_forest_writes();
    let written = crdt.maintain_forest(&guard, |_| {
        if !proceed() {
            return Ok(Ok(None));
        }
        let marked = match markers(db, apps, paths, &affected, history) {
            Ok(marked) => marked,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut batch = rocksdb::WriteBatch::default();
        for (lower, upper) in &planned.ranges {
            batch.delete_range(lower, upper);
        }
        for key in marked.invalid.iter().chain(&marked.dropped) {
            batch.delete(key);
        }
        for (key, value) in &marked.narrowed {
            batch.put(key, value);
        }
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        db.write_opt(batch, &options).map_err(store_error)?;
        Ok(Ok(Some((
            marked.invalid.len(),
            marked.dropped.len() + marked.narrowed.len(),
        ))))
    });
    drop(guard);
    let Some((invalidated, sync_markers)) = written?? else {
        return Ok(Outcome {
            stopped: true,
            ..Outcome::default()
        });
    };
    for (lower, upper) in &planned.ranges {
        let mut residue = false;
        scan(db, lower, Some(upper), |_, _| {
            residue = true;
            Ok(())
        })?;
        if residue {
            return Err(QuilError::Store(
                "payload eviction left records in a deleted range".into(),
            )
            .into());
        }
    }
    // Reclaim now where no older snapshot holds the records; boundary files
    // are rewritten without them. `reclaim` retries what a snapshot kept.
    for (lower, upper) in &planned.ranges {
        db.compact_range(Some(lower), Some(upper));
    }
    Ok(Outcome {
        removed_records: planned.records,
        removed_bytes: planned.bytes,
        ranges: planned.ranges.len(),
        invalidated_markers: invalidated,
        sync_markers,
        ..Outcome::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use quil_hypergraph::Location;
    use quil_types::store::{HypergraphStore, ShardKey};

    const APP: Address = [0x21; 32];

    /// A unified store, named as a data worker's own, as every store a
    /// worker evicts from is.
    fn open() -> (
        Arc<quil_store::RocksDb>,
        Arc<quil_store::RocksHypergraphStore>,
        HypergraphCrdt,
    ) {
        open_as(Some(quil_forest::StoreRole::Worker(9_601)))
    }

    /// A unified store named `role`, or never named.
    fn open_as(
        role: Option<quil_forest::StoreRole>,
    ) -> (
        Arc<quil_store::RocksDb>,
        Arc<quil_store::RocksHypergraphStore>,
        HypergraphCrdt,
    ) {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        if let Some(role) = role {
            assert!(db.inner().register_store(role));
        }
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        );
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(true);
        (db, store, crdt)
    }

    fn shard() -> ShardKey {
        ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(&APP, 256, 3),
            l2: APP,
        }
    }

    fn lower_half() -> Vec<Vec<u8>> {
        vec![quil_forest::encode_shard_bit_path(&APP, &[false])]
    }

    fn location(key: u8) -> Location {
        Location {
            app_address: APP,
            data_address: [key; 32],
        }
    }

    #[test]
    fn scans_do_not_fill_the_block_cache() {
        const RECORDS: u32 = 4096;
        const BLOB: usize = 4096;
        let dir = std::env::temp_dir().join(format!(
            "quil-eviction-scan-cache-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        {
            // The default 256 MiB block cache holds every block written here.
            let db = quil_store::RocksDb::open(&dir).unwrap();
            let prefix = [0xe1u8; 4];
            for n in 0..RECORDS {
                let key = [prefix.as_slice(), &n.to_be_bytes()].concat();
                db.inner().put(key, vec![0xab; BLOB]).unwrap();
            }
            // Reads now come from table files, through the block cache.
            db.inner().flush().unwrap();
            let before = db.memory_usage().block_cache;
            let mut rows = 0u32;
            scan(&db.inner(), &prefix, None, |_, _| {
                rows += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(rows, RECORDS);
            let added = db.memory_usage().block_cache.saturating_sub(before);
            assert!(
                added < 1 << 20,
                "scanning 16 MiB of payload added {added} bytes to the block cache"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evicts_unprotected_payload_and_a_later_assignment_repairs_it() {
        use quil_forest::{SubtreeSyncAnchor, PHASES};
        let (source_db, _, source) = open();
        for key in [1, 129] {
            source.add_vertex(&location(key), &vec![key; 48]).unwrap();
        }
        source.commit(1).unwrap();
        let (version, root) = source.serve_forest_head(&APP, 0).unwrap();
        let forest =
            quil_forest::Forest::with_namespace(source_db.inner(), quil_store::FOREST_NAMESPACE);
        let reader = forest.shard_phase_reader(&APP, PHASES[0]);

        let (db, store, target) = open();
        let mut sync = target
            .prepare_phase_sync(
                &reader,
                version,
                &APP,
                0,
                &[],
                Some(SubtreeSyncAnchor::AppRoot(root)),
            )
            .unwrap();
        let blobs: Vec<_> = sync
            .remaining()
            .iter()
            .map(|(key, _)| vec![key[0]; 48])
            .collect();
        target.apply_sync_chunk(&mut sync, &blobs).unwrap();
        target.finish_phase_sync(&sync).unwrap();
        // A readiness promise for the kept half survives; the whole-app one cannot.
        let mut kept_marker = VERIFIED.to_vec();
        kept_marker.extend(32u16.to_be_bytes());
        kept_marker.extend(APP);
        kept_marker.push(0);
        kept_marker.extend(1u16.to_be_bytes());
        kept_marker.push(0);
        db.inner().put(&kept_marker, [1]).unwrap();
        assert!(target.sync_data_ready(&APP, 0, &[]).unwrap());
        let kept = store
            .load_vertex_underlying_at("vertex", "adds", &shard(), &location(1).to_id(), 0)
            .unwrap();

        let outcome = evict_outside(&target, &lower_half()).unwrap();
        assert_eq!(
            (outcome.removed_records, outcome.invalidated_markers),
            (1, 1)
        );
        assert!(target
            .get_vertex_data_checked(&location(129))
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .load_vertex_underlying_at("vertex", "adds", &shard(), &location(1).to_id(), 0)
                .unwrap(),
            kept
        );
        assert_eq!(
            target.serve_forest_head(&APP, 0).unwrap().1,
            root,
            "the forest is untouched"
        );
        assert!(!target.sync_data_ready(&APP, 0, &[]).unwrap());
        assert!(
            target.sync_data_ready(&APP, 0, &[false]).unwrap(),
            "the kept scope needs no repair"
        );
        assert_eq!(
            evict_outside(&target, &lower_half()).unwrap(),
            Outcome::default(),
            "a repeat finds nothing"
        );

        let mut repair = target
            .prepare_phase_sync(
                &reader,
                version,
                &APP,
                0,
                &[],
                Some(SubtreeSyncAnchor::AppRoot(root)),
            )
            .unwrap();
        assert_eq!(
            repair.remaining().len(),
            2,
            "an equal root must not skip the data audit"
        );
        let blobs: Vec<_> = repair
            .remaining()
            .iter()
            .map(|(key, _)| vec![key[0]; 48])
            .collect();
        target.apply_sync_chunk(&mut repair, &blobs).unwrap();
        target.finish_phase_sync(&repair).unwrap();
        assert_eq!(
            target.get_vertex_data_checked(&location(129)).unwrap(),
            Some(vec![129; 48])
        );
        assert!(target.sync_data_ready(&APP, 0, &[]).unwrap());
    }

    #[test]
    fn confining_the_forest_keeps_the_served_root_and_a_later_assignment_repairs_it() {
        use quil_forest::{SubtreeSyncAnchor, PHASES};
        let (source_db, _, source) = open();
        for key in [1, 2, 129, 130] {
            source.add_vertex(&location(key), &vec![key; 48]).unwrap();
        }
        source.commit(1).unwrap();
        let (version, root) = source.serve_forest_head(&APP, 0).unwrap();
        let forest =
            quil_forest::Forest::with_namespace(source_db.inner(), quil_store::FOREST_NAMESPACE);
        let reader = forest.shard_phase_reader(&APP, PHASES[0]);

        let (_db, _, target) = open();
        let mut sync = target
            .prepare_phase_sync(
                &reader,
                version,
                &APP,
                0,
                &[],
                Some(SubtreeSyncAnchor::AppRoot(root)),
            )
            .unwrap();
        let blobs: Vec<_> = sync
            .remaining()
            .iter()
            .map(|(key, _)| vec![key[0]; 48])
            .collect();
        target.apply_sync_chunk(&mut sync, &blobs).unwrap();
        target.finish_phase_sync(&sync).unwrap();
        let served = lower_half();
        let served_root = target.sub_shard_commitment_for_filter("vertex", "adds", &served[0]);
        assert!(!served_root.is_empty());

        evict_outside(&target, &served).unwrap();
        let confined = target.confine_forest(&served, 1).unwrap();
        assert_eq!(confined.commits, 1, "only the populated phase has a head");
        assert!(confined.nodes > 0 && confined.key_ranges > 0);
        assert_eq!(
            target.sub_shard_commitment_for_filter("vertex", "adds", &served[0]),
            served_root
        );
        assert_ne!(
            target.serve_forest_head(&APP, 0).unwrap().1,
            root,
            "the dropped half left the head"
        );
        assert_eq!(
            target.get_vertex_data_checked(&location(1)).unwrap(),
            Some(vec![1; 48])
        );
        assert_eq!(
            target.confine_forest(&served, 1).unwrap(),
            quil_hypergraph::ForestConfinement::default(),
            "a repeat finds nothing and sweeps nothing"
        );
        // A frame commit on the confined tree keeps working.
        target.add_vertex(&location(3), &vec![3; 48]).unwrap();
        target.commit(2).unwrap();
        assert_ne!(
            target.sub_shard_commitment_for_filter("vertex", "adds", &served[0]),
            served_root
        );

        // Reassignment to the whole application syncs the dropped half back.
        let (version, root) = {
            source.add_vertex(&location(3), &vec![3; 48]).unwrap();
            source.commit(2).unwrap();
            source.serve_forest_head(&APP, 0).unwrap()
        };
        let reader = forest.shard_phase_reader(&APP, PHASES[0]);
        let mut repair = target
            .prepare_phase_sync(
                &reader,
                version,
                &APP,
                0,
                &[],
                Some(SubtreeSyncAnchor::AppRoot(root)),
            )
            .unwrap();
        let blobs: Vec<_> = repair
            .remaining()
            .iter()
            .map(|(key, _)| vec![key[0]; 48])
            .collect();
        target.apply_sync_chunk(&mut repair, &blobs).unwrap();
        target.finish_phase_sync(&repair).unwrap();
        assert_eq!(target.serve_forest_head(&APP, 0).unwrap().1, root);
        assert_eq!(
            target.get_vertex_data_checked(&location(130)).unwrap(),
            Some(vec![130; 48])
        );
    }

    /// A confinement that drops the subtree of a shard whose frames the
    /// store keeps records it, at that shard's cursor, in the same write; a
    /// kept shard, another application's and a lineage whose subtree holds
    /// nothing are not recorded, and a confinement whose worker was rebound
    /// before it commits stops untouched. A replay then
    /// reads the dropped shard as the empty subtree, and only the kept shard
    /// is held.
    #[test]
    fn confinement_records_each_lineage_whose_subtree_it_drops() {
        use quil_forest::{SubtreeSyncAnchor, PHASES};
        let (source_db, _, source) = open();
        for key in [1, 2, 129, 130] {
            source.add_vertex(&location(key), &vec![key; 48]).unwrap();
        }
        source.commit(1).unwrap();
        let (version, root) = source.serve_forest_head(&APP, 0).unwrap();
        let forest =
            quil_forest::Forest::with_namespace(source_db.inner(), quil_store::FOREST_NAMESPACE);
        let reader = forest.shard_phase_reader(&APP, PHASES[0]);
        let (db, _, target) = open();
        let mut sync = target
            .prepare_phase_sync(
                &reader,
                version,
                &APP,
                0,
                &[],
                Some(SubtreeSyncAnchor::AppRoot(root)),
            )
            .unwrap();
        let blobs: Vec<_> = sync
            .remaining()
            .iter()
            .map(|(key, _)| vec![key[0]; 48])
            .collect();
        target.apply_sync_chunk(&mut sync, &blobs).unwrap();
        target.finish_phase_sync(&sync).unwrap();

        let served = lower_half();
        let left = quil_forest::encode_shard_bit_path(&APP, &[true]);
        let other = vec![0x22; 32];
        // A lineage of the left half whose own subtree holds nothing.
        let quiet = quil_forest::encode_shard_bit_path(&APP, &[true, true]);
        for (filter, cursor) in [(&served[0], 40u64), (&left, 31), (&other, 12), (&quiet, 7)] {
            db.inner()
                .put(
                    quil_store::encoding::consensus_materialized_cursor_key(filter),
                    cursor.to_be_bytes(),
                )
                .unwrap();
        }
        let sorted = |mut held: Vec<(Vec<u8>, u64)>| {
            held.sort();
            held
        };
        assert_eq!(
            sorted(held_shards(&target).unwrap().held),
            sorted(vec![(served[0].clone(), 40), (left.clone(), 31)]),
            "another application's lineage holds no data here"
        );
        let left_root = target.sub_shard_commitment_for_filter("vertex", "adds", &left);
        assert!(!left_root.is_empty() && left_root != vec![0; 32]);

        evict_outside(&target, &served).unwrap();
        let records = lineage_drop_records(&target).unwrap();
        let record = |filter: &[u8]| {
            db.inner()
                .get(quil_store::encoding::app_lineage_dropped_key(filter))
                .unwrap()
        };
        // Rebound before it commits, the confinement stops untouched.
        let stopped = target
            .confine_forest_recording(&served, 1, &records, &|| false)
            .unwrap();
        assert!(
            stopped.stopped && stopped.commits == 0 && stopped.dropped_lineages.is_empty(),
            "{stopped:?}"
        );
        assert_eq!(
            target.sub_shard_commitment_for_filter("vertex", "adds", &left),
            left_root,
            "nothing dropped"
        );
        assert_eq!(record(&left), None);
        let confined = target
            .confine_forest_recording(&served, 1, &records, &|| true)
            .unwrap();
        assert!(!confined.stopped);
        assert_eq!(
            confined.dropped_lineages,
            vec![left.clone()],
            "the empty lineage has nothing to drop"
        );
        assert_eq!(record(&left), Some(31u64.to_be_bytes().to_vec()));
        assert_eq!(
            (record(&served[0]), record(&other), record(&quiet)),
            (None, None, None)
        );
        // What an archive replay compares the dropped shard's certified
        // pre-state with: an empty subtree, read as the tree's empty-range
        // placeholder for a path ending inside a node that keeps other
        // children, and as all zeros where the path's node is gone.
        assert_eq!(
            target.sub_shard_commitment_for_filter("vertex", "adds", &left),
            b"SPARSE_MERKLE_PLACEHOLDER_HASH__".to_vec()
        );
        let gone = quil_forest::encode_shard_bit_path(&APP, &[true, false, false, false]);
        assert_eq!(
            target.sub_shard_commitment_for_filter("vertex", "adds", &gone),
            vec![0; 32]
        );
        assert_eq!(
            target.unified_subtree_leaf_count("vertex", "adds", &APP, &[true]),
            0
        );
        assert_eq!(
            held_shards(&target).unwrap().held,
            vec![(served[0].clone(), 40)]
        );
        assert!(
            target
                .confine_forest_recording(
                    &served,
                    1,
                    &lineage_drop_records(&target).unwrap(),
                    &|| true
                )
                .unwrap()
                .dropped_lineages
                .is_empty(),
            "a repeat drops nothing"
        );
    }

    /// A store holding a vertex in its lower half, with lineages of both
    /// halves (filters `held` and `quiet`).
    fn lineage_store() -> (
        Arc<quil_store::RocksDb>,
        Arc<quil_store::RocksHypergraphStore>,
        HypergraphCrdt,
        Vec<u8>,
        Vec<u8>,
    ) {
        let (db, store, crdt) = open();
        crdt.add_vertex(&location(1), &vec![1; 48]).unwrap();
        crdt.commit(1).unwrap();
        let held = lower_half()[0].clone();
        let quiet = quil_forest::encode_shard_bit_path(&APP, &[true]);
        for (filter, cursor) in [(&held, 4u64), (&quiet, 3)] {
            db.inner()
                .put(
                    quil_store::encoding::consensus_materialized_cursor_key(filter),
                    cursor.to_be_bytes(),
                )
                .unwrap();
        }
        (db, store, crdt, held, quiet)
    }

    fn drop_record_filters(crdt: &HypergraphCrdt) -> Vec<Vec<u8>> {
        let mut filters: Vec<Vec<u8>> = lineage_drop_records(crdt)
            .unwrap()
            .into_iter()
            .map(|(f, _)| f)
            .collect();
        filters.sort();
        filters
    }

    /// A lineage whose subtree holds no leaf gets no dropped-lineage record.
    #[test]
    fn a_lineage_whose_subtree_is_empty_gets_no_drop_record() {
        let (_db, _store, crdt, held, _quiet) = lineage_store();
        assert_eq!(
            crdt.unified_subtree_leaf_count_checked("vertex", "adds", &APP, &[true]),
            Some(0)
        );
        assert_eq!(
            drop_record_filters(&crdt),
            vec![held],
            "the empty half has nothing to drop"
        );
    }

    /// A leaf count that cannot be read (here a malformed head version on a
    /// store opened afresh) is unknown, not empty: the lineage keeps its
    /// record.
    #[test]
    fn an_unreadable_leaf_count_is_unknown_not_empty() {
        let (db, store, _crdt, held, quiet) = lineage_store();
        let forest = quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE);
        let (head, _) = forest
            .head_version_put(&APP, quil_forest::PHASES[0], 1)
            .unwrap();
        db.inner().put(&head, b"bad").unwrap();
        let reopened =
            HypergraphCrdt::new(store, Arc::new(quil_types::crypto::NoopInclusionProver));
        reopened.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        reopened.set_unified_tree(true);
        assert_eq!(
            reopened.unified_subtree_leaf_count("vertex", "adds", &APP, &[true]),
            0,
            "the unchecked count"
        );
        assert_eq!(
            reopened.unified_subtree_leaf_count_checked("vertex", "adds", &APP, &[true]),
            None
        );
        let mut both = vec![held, quiet];
        both.sort();
        assert_eq!(
            drop_record_filters(&reopened),
            both,
            "an unreadable count is not empty"
        );
    }

    /// A payload pass whose worker was rebound during its scan removes
    /// nothing; one still bound removes what lies outside its scopes.
    #[test]
    fn a_payload_pass_stops_once_its_binding_changed() {
        let (db, _, crdt) = open();
        let inner = db.inner();
        let key = |address: u8| {
            let mut id = APP.to_vec();
            id.extend([address; 32]);
            quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard(), &id, 0)
        };
        inner.put(key(1), b"kept").unwrap();
        inner.put(key(129), b"left").unwrap();
        let stopped = evict_outside_while(&crdt, &lower_half(), &|| false).unwrap();
        assert_eq!((stopped.stopped, stopped.removed_records), (true, 0));
        assert!(inner.get(key(129)).unwrap().is_some(), "nothing removed");
        let done = evict_outside_while(&crdt, &lower_half(), &|| true).unwrap();
        assert_eq!((done.stopped, done.removed_records), (false, 1));
        assert!(inner.get(key(129)).unwrap().is_none());
    }

    #[test]
    fn keeps_every_protected_version_phase_and_other_keyspaces() {
        let (db, _, crdt) = open();
        let inner = db.inner();
        let (mut kept, mut evicted) = (Vec::new(), Vec::new());
        for (set, phase) in [
            ("vertex", "adds"),
            ("vertex", "removes"),
            ("hyperedge", "adds"),
            ("hyperedge", "removes"),
        ] {
            for version in [0, 1, 9] {
                for address in [1u8, 129] {
                    let mut id = APP.to_vec();
                    id.extend([address; 32]);
                    let key = quil_store::encoding::hypergraph_vertex_data_v2_key(
                        set,
                        phase,
                        &shard(),
                        &id,
                        version,
                    );
                    inner.put(&key, [address, version as u8]).unwrap();
                    if address == 1 {
                        kept.push(key)
                    } else {
                        evicted.push(key)
                    }
                }
            }
        }
        // Another application without a protected scope is never classified.
        let other = ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(&[0x22; 32], 256, 3),
            l2: [0x22; 32],
        };
        let foreign_app = quil_store::encoding::hypergraph_vertex_data_v2_key(
            "vertex",
            "adds",
            &other,
            &[[0x22; 32], [129; 32]].concat(),
            0,
        );
        inner.put(&foreign_app, b"other").unwrap();
        let global = quil_store::encoding::hypergraph_vertex_data_v2_key(
            "vertex",
            "adds",
            &quil_store::encoding::prover_registry_shard(),
            &[255; 64],
            5,
        );
        inner.put(&global, b"GLOBAL").unwrap();
        inner.put(b"consensus-metadata", b"preserve").unwrap();

        let mut keep = lower_half();
        keep.push(vec![255; 32]);
        let outcome = evict_outside(&crdt, &keep).unwrap();
        assert_eq!(outcome.removed_records, 12);
        for key in kept {
            assert!(inner.get(key).unwrap().is_some());
        }
        for key in evicted {
            assert!(inner.get(key).unwrap().is_none());
        }
        assert_eq!(
            inner.get(foreign_app).unwrap().as_deref(),
            Some(&b"other"[..])
        );
        assert_eq!(inner.get(global).unwrap().as_deref(), Some(&b"GLOBAL"[..]));
        assert_eq!(
            inner.get(b"consensus-metadata").unwrap().as_deref(),
            Some(&b"preserve"[..])
        );
    }

    #[test]
    fn uncertain_layouts_refuse_without_writing() {
        let (db, _, crdt) = open();
        let inner = db.inner();
        let mut id = APP.to_vec();
        id.extend([129; 32]);
        let key =
            quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard(), &id, 0);
        inner.put(&key, b"unprotected").unwrap();
        let refuses = |setup: &dyn Fn(), cleanup: &dyn Fn()| {
            setup();
            let sequence = inner.latest_sequence_number();
            assert!(evict_outside(&crdt, &lower_half()).is_err());
            assert_eq!(sequence, inner.latest_sequence_number());
            assert!(inner.get(&key).unwrap().is_some());
            cleanup();
        };
        let mixed = key[..key.len() - 1].to_vec();
        refuses(&|| inner.put(&mixed, b"bad shape").unwrap(), &|| {
            inner.delete(&mixed).unwrap()
        });
        let mut incomplete = INCOMPLETE.to_vec();
        incomplete.extend(32u16.to_be_bytes());
        incomplete.extend(APP);
        refuses(&|| inner.put(&incomplete, [0, 0, 1, 0]).unwrap(), &|| {
            inner.delete(&incomplete).unwrap()
        });
        refuses(&|| crdt.set_unified_tree(false), &|| {
            crdt.set_unified_tree(true)
        });
        // A worker's own root and manifest index names nothing a reader of
        // its store needs ([`serves_history`]).
        for (index, value) in history_index() {
            inner.put(index, value).unwrap();
        }
        assert_eq!(
            evict_outside(&crdt, &lower_half()).unwrap().removed_records,
            1,
            "each refusal was the only obstacle"
        );
    }

    /// A root-version entry at frame 7 and a manifest at frame 9 of `APP`.
    fn history_index() -> [(Vec<u8>, Vec<u8>); 2] {
        let root_index =
            quil_store::encoding::hypergraph_root_version_key("vertex", "adds", &APP, &[1; 32]);
        let manifest =
            quil_store::encoding::hypergraph_app_manifest_key("vertex", "adds", &APP, &[2; 32]);
        let mut entry = 3u64.to_be_bytes().to_vec();
        entry.extend(7u64.to_be_bytes());
        let mut listed = 9u64.to_be_bytes().to_vec();
        listed.extend(0u32.to_be_bytes());
        [(root_index, entry), (manifest, listed)]
    }

    /// The vertices at 1 and 129 of `APP`, committed on the store itself at
    /// frame 1, which indexes the application's root at that frame.
    fn committed_store(
        role: Option<quil_forest::StoreRole>,
    ) -> (Arc<quil_store::RocksDb>, HypergraphCrdt) {
        let (db, _, crdt) = open_as(role);
        for key in [1, 129] {
            crdt.add_vertex(&location(key), &[key; 48]).unwrap();
        }
        crdt.commit(1).unwrap();
        let inner = db.inner();
        let mut it = inner.raw_iterator();
        it.seek([quil_store::encoding::HG_ROOT_VERSION]);
        assert!(
            it.key().is_some_and(
                |key| key[0] == quil_store::encoding::HG_ROOT_VERSION && key[3..35] == APP[..]
            ),
            "the commit indexed the application's root"
        );
        (db, crdt)
    }

    /// A worker that committed frames of the shard it keeps, as a worker
    /// bound to a split child does, still evicts the rest of the
    /// application, which its own root index used to refuse at every pass.
    #[test]
    fn a_worker_evicts_beside_the_root_index_of_its_own_commits() {
        let (_db, crdt) = committed_store(Some(quil_forest::StoreRole::Worker(9_602)));
        let outcome = evict_outside(&crdt, &lower_half()).unwrap();
        assert_eq!(outcome.removed_records, 1);
        assert!(outcome.removed_bytes > 0);
        assert!(crdt
            .get_vertex_data_checked(&location(129))
            .unwrap()
            .is_none());
        assert_eq!(
            crdt.get_vertex_data_checked(&location(1)).unwrap(),
            Some(vec![1; 48])
        );
        // The kept shard goes on committing and evicting.
        crdt.add_vertex(&location(2), &[2; 48]).unwrap();
        crdt.commit(2).unwrap();
        assert_eq!(
            evict_outside(&crdt, &lower_half()).unwrap().removed_records,
            0
        );
    }

    /// A raw payload record at 129 of `APP` and a manifest of `APP` at frame
    /// 9, with no root index, on a store named `role`.
    fn manifest_store(role: Option<quil_forest::StoreRole>) -> HypergraphCrdt {
        let (db, _, crdt) = open_as(role);
        let inner = db.inner();
        let mut id = APP.to_vec();
        id.extend([129; 32]);
        let key =
            quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard(), &id, 0);
        inner.put(key, b"left").unwrap();
        let [_, (manifest, listed)] = history_index();
        inner.put(manifest, listed).unwrap();
        crdt
    }

    /// A store that may serve its history (the master's, an archive's, or
    /// one never named) keeps refusing, without writing, while it indexes a
    /// root or manifest of the application; a worker's store with the same
    /// manifest evicts.
    #[test]
    fn a_store_that_may_serve_its_history_refuses_beside_its_index() {
        for role in [None, Some(quil_forest::StoreRole::Master)] {
            let (db, crdt) = committed_store(role);
            let inner = db.inner();
            let sequence = inner.latest_sequence_number();
            let refused = evict_outside(&crdt, &lower_half()).unwrap_err();
            assert!(
                refused.to_string().contains(HISTORY_REFUSAL),
                "{role:?}: {refused}"
            );
            assert_eq!(sequence, inner.latest_sequence_number(), "{role:?}");
            assert_eq!(
                crdt.get_vertex_data_checked(&location(129)).unwrap(),
                Some(vec![129; 48]),
                "{role:?}"
            );
            let refused = evict_outside(&manifest_store(role), &lower_half()).unwrap_err();
            assert!(
                refused.to_string().contains(HISTORY_REFUSAL),
                "{role:?}: {refused}"
            );
        }
        assert_eq!(
            evict_outside(
                &manifest_store(Some(quil_forest::StoreRole::Worker(9_603))),
                &lower_half()
            )
            .unwrap()
            .removed_records,
            1
        );
    }

    /// A refusal after planning names the records and bytes it would have
    /// removed.
    #[test]
    fn a_refusal_names_what_it_planned() {
        let (_db, crdt) = committed_store(Some(quil_forest::StoreRole::Master));
        let refusal = evict(&crdt, &lower_half(), &|| true).unwrap_err();
        let (records, bytes) = refusal.planned.expect("refused after planning");
        assert_eq!(records, 1);
        assert!(bytes > 48, "a key and its 48-byte blob: {bytes}");
    }

    /// A history refusal names the index entry that refused it: its tag
    /// and the frame it records.
    #[test]
    fn a_refusal_names_the_entry_that_refused_it() {
        let (_db, crdt) = committed_store(Some(quil_forest::StoreRole::Master));
        assert_eq!(
            evict(&crdt, &lower_half(), &|| true).unwrap_err().blocking,
            Some((quil_store::encoding::HG_ROOT_VERSION, Some(1)))
        );
        let crdt = manifest_store(Some(quil_forest::StoreRole::Master));
        assert_eq!(
            evict(&crdt, &lower_half(), &|| true).unwrap_err().blocking,
            Some((quil_store::encoding::HG_APP_MANIFEST, Some(9)))
        );
    }

    /// An interrupted-sync marker value listing `scopes` (`phase ‖ bits ‖
    /// packed path` each), encoded here so the tests read the store's format.
    fn sync_marker(scopes: &[(u8, Vec<bool>)]) -> Vec<u8> {
        let mut value = Vec::new();
        for (phase, bits) in scopes {
            value.push(*phase);
            value.extend((bits.len() as u16).to_be_bytes());
            let mut packed = vec![0u8; bits.len().div_ceil(8)];
            for (i, bit) in bits.iter().enumerate() {
                packed[i / 8] |= u8::from(*bit) << (7 - i % 8);
            }
            value.extend(packed);
        }
        value
    }

    /// A worker store holding raw payload at 1 (kept by [`lower_half`]) and
    /// 129 of `APP`, and `APP`'s interrupted-sync marker listing `scopes`;
    /// returns the store and the marker's key.
    fn interrupted_store(
        scopes: &[(u8, Vec<bool>)],
    ) -> (Arc<quil_store::RocksDb>, HypergraphCrdt, Vec<u8>) {
        let (db, _, crdt) = open();
        let inner = db.inner();
        for address in [1u8, 129] {
            let mut id = APP.to_vec();
            id.extend([address; 32]);
            let key = quil_store::encoding::hypergraph_vertex_data_v2_key(
                "vertex",
                "adds",
                &shard(),
                &id,
                0,
            );
            inner.put(key, [address]).unwrap();
        }
        let mut key = INCOMPLETE.to_vec();
        key.extend(32u16.to_be_bytes());
        key.extend(APP);
        inner.put(&key, sync_marker(scopes)).unwrap();
        (db, crdt, key)
    }

    /// The marker of a sync of the split parent that was cut short, left
    /// once the worker serves one child, no longer refuses every pass: it
    /// keeps its claim on the kept child alone.
    #[test]
    fn a_stale_parent_sync_marker_is_narrowed_to_the_kept_scope() {
        let (db, crdt, key) = interrupted_store(&[(0, vec![])]);
        assert!(crdt.sync_incomplete(&APP, &[true]).unwrap());
        let outcome = evict_outside(&crdt, &lower_half()).unwrap();
        assert_eq!(outcome.removed_records, 1);
        assert_eq!(
            db.inner().get(&key).unwrap(),
            Some(sync_marker(&[(0, vec![false])])),
            "narrowed to the kept half"
        );
        assert!(
            crdt.sync_incomplete(&APP, &[false]).unwrap(),
            "the kept half still reads as partly installed"
        );
        assert!(!crdt.sync_incomplete(&APP, &[true]).unwrap());
    }

    /// A marker whose scopes lie wholly in the evicted gap goes with their
    /// records, in the same write.
    #[test]
    fn an_interrupted_sync_marker_inside_an_evicted_gap_is_dropped() {
        let (db, crdt, key) = interrupted_store(&[(1, vec![true, false]), (2, vec![true])]);
        assert_eq!(
            evict_outside(&crdt, &lower_half()).unwrap().removed_records,
            1
        );
        assert_eq!(db.inner().get(&key).unwrap(), None);
        assert!(!crdt.sync_incomplete(&APP, &[]).unwrap());
    }

    /// A sync of a kept scope that has not finished, a legacy shard id's
    /// marker and an unreadable one still refuse, writing nothing; so does a
    /// marker of the binding when a staged child inside it is kept too.
    #[test]
    fn an_interrupted_sync_of_a_kept_scope_still_refuses() {
        let staged = quil_forest::encode_shard_bit_path(&APP, &[false, true]);
        let nested = vec![lower_half()[0].clone(), staged];
        let cases: [(Vec<SyncScope>, Vec<Vec<u8>>); 4] = [
            (vec![(0, vec![false])], lower_half()),
            (vec![(3, vec![false, true])], lower_half()),
            (vec![(0, vec![]), (0, vec![false, false])], lower_half()),
            (vec![(0, vec![false])], nested),
        ];
        for (scopes, keep) in cases {
            let (db, crdt, key) = interrupted_store(&scopes);
            let inner = db.inner();
            let sequence = inner.latest_sequence_number();
            let refused = evict_outside(&crdt, &keep).unwrap_err();
            assert!(
                refused
                    .to_string()
                    .contains("application has an interrupted sync"),
                "{scopes:?}: {refused}"
            );
            assert_eq!(sequence, inner.latest_sequence_number(), "{scopes:?}");
            assert_eq!(inner.get(&key).unwrap(), Some(sync_marker(&scopes)));
        }
        let (db, crdt, key) = interrupted_store(&[(0, vec![true])]);
        let inner = db.inner();
        inner.put(&key, [0, 0, 9]).unwrap();
        assert!(evict_outside(&crdt, &lower_half()).is_err(), "unreadable");
        inner.delete(&key).unwrap();
        let mut legacy = INCOMPLETE.to_vec();
        legacy.extend(33u16.to_be_bytes());
        legacy.extend(APP);
        legacy.push(0);
        inner.put(&legacy, sync_marker(&[(0, vec![true])])).unwrap();
        assert!(evict_outside(&crdt, &lower_half()).is_err(), "legacy id");
    }

    /// An interrupted-sync refusal names the scope that refused it.
    #[test]
    fn an_interrupted_sync_refusal_names_its_scope() {
        let (_db, crdt, _) = interrupted_store(&[(0, vec![true]), (3, vec![false, true])]);
        assert_eq!(
            evict(&crdt, &lower_half(), &|| true)
                .unwrap_err()
                .sync_scope,
            Some((3, vec![false, true]))
        );
    }

    /// A request runs only for a protected, served and settled binding.
    #[test]
    fn eviction_waits_for_a_protected_served_and_settled_binding() {
        let settled = crate::worker_allocator::PAYLOAD_EVICTION_SETTLE;
        let keep = lower_half();
        assert_eq!(
            deferral(&[], &keep, true, settled),
            Some("binding is not protected")
        );
        assert_eq!(
            deferral(&[1; 32], &keep, true, settled),
            Some("binding is not protected")
        );
        assert_eq!(
            deferral(&keep[0], &keep, false, settled),
            Some("engine is not serving the binding")
        );
        assert_eq!(
            deferral(&keep[0], &keep, true, settled / 2),
            Some("binding has not settled")
        );
        assert_eq!(deferral(&keep[0], &keep, true, settled), None);
    }

    /// The passes a standalone worker runs remove the payload outside the
    /// kept scope and the consensus storage of a shard it left, and keep the
    /// storage of the kept shard and of a shard whose committee it still owes.
    #[tokio::test]
    async fn the_passes_remove_payload_and_consensus_storage_outside_keep() {
        let (db, _, crdt) = open();
        let inner = db.inner();
        let key = |address: u8| {
            let mut id = APP.to_vec();
            id.extend([address; 32]);
            quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard(), &id, 0)
        };
        inner.put(key(1), b"kept").unwrap();
        inner.put(key(129), b"left").unwrap();
        let base = std::env::temp_dir().join(format!(
            "quil-worker-passes-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let keep = lower_half();
        let (owed, left) = (vec![0x22; 32], vec![0x23; 32]);
        let entry = |filter: &[u8]| {
            base.join("cw-app-consensus")
                .join(format!("app-{}", hex::encode(filter)))
        };
        for filter in [&keep[0], &owed, &left] {
            std::fs::create_dir_all(entry(filter)).unwrap();
        }
        let retained = {
            let owed = owed.clone();
            move |filter: &[u8]| filter == owed.as_slice()
        };
        run_passes(
            1,
            "test".into(),
            Arc::new(crdt),
            keep.clone(),
            Some((base.clone(), retained)),
            Arc::new(|| true),
            Arc::new(|| {}),
        )
        .await;
        assert_eq!(inner.get(key(1)).unwrap().as_deref(), Some(&b"kept"[..]));
        assert!(
            inner.get(key(129)).unwrap().is_none(),
            "payload outside the kept scope is evicted"
        );
        assert!(entry(&keep[0]).exists() && entry(&owed).exists());
        assert!(
            !entry(&left).exists(),
            "a left shard's consensus storage is removed"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// A snapshot older than the deletion keeps the deleted records on disk;
    /// once it is released, the next pass compacts them away.
    #[test]
    fn a_later_pass_reclaims_space_a_snapshot_held() {
        let (db, _, crdt) = open();
        let inner = db.inner();
        // Kept and unprotected halves in separate files.
        for half in [0u8..=127, 128u8..=255] {
            for address in half {
                let mut id = APP.to_vec();
                id.extend([address; 32]);
                let key = quil_store::encoding::hypergraph_vertex_data_v2_key(
                    "vertex",
                    "adds",
                    &shard(),
                    &id,
                    0,
                );
                inner.put(&key, vec![address; 4096]).unwrap();
            }
            inner.flush().unwrap();
        }
        let inside = |db: &CoordinatedDb| {
            let mut lower = quil_store::encoding::hypergraph_vertex_data_v2_shard_prefix(
                "vertex",
                "adds",
                &shard(),
            );
            lower.extend(APP);
            lower.push(0x80);
            db.live_files()
                .unwrap()
                .iter()
                .filter(|f| {
                    f.start_key
                        .as_deref()
                        .is_some_and(|a| a >= lower.as_slice())
                })
                .map(|f| f.size)
                .sum::<usize>()
        };
        let snapshot = inner.snapshot();
        let first = evict_outside(&crdt, &lower_half()).unwrap();
        assert_eq!(first.removed_records, 128);
        assert!(
            inside(&inner) > 0,
            "the held snapshot keeps the deleted records"
        );
        drop(snapshot);
        let second = evict_outside(&crdt, &lower_half()).unwrap();
        assert_eq!(
            second.removed_records, 0,
            "nothing visible is left to delete"
        );
        assert!(second.compacted_ranges >= 1 && second.reclaimable_bytes > 0);
        assert_eq!(inside(&inner), 0, "the released records are compacted away");
        assert_eq!(
            evict_outside(&crdt, &lower_half()).unwrap(),
            Outcome::default()
        );
    }
}
