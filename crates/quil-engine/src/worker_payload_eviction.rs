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
    let mut it = db.raw_iterator();
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

/// Checks that need the write barrier: nothing may claim historical roots or
/// an interrupted sync for an evicted application, and readiness markers the
/// removal falsifies are collected for the same batch.
fn markers(
    db: &CoordinatedDb,
    apps: &BTreeMap<Address, Vec<Interval>>,
    affected: &[Address],
) -> Result<Vec<Vec<u8>>> {
    let mut invalid = Vec::new();
    for app in affected {
        let keep = &apps[app];
        for tag in [
            quil_store::encoding::HG_ROOT_VERSION,
            quil_store::encoding::HG_APP_MANIFEST,
        ] {
            scan(db, &[tag], None, |key, _| {
                if key.len() >= 35 && key[3..35] == app[..] {
                    return Err(unavailable(
                        "application has indexed historical roots or manifests",
                    ));
                }
                Ok(())
            })?;
        }
        scan(db, INCOMPLETE, None, |key, value| {
            let tail = &key[INCOMPLETE.len()..];
            if tail.len() < 34 {
                return Err(unavailable("malformed incomplete-sync marker"));
            }
            if tail[2..34] == app[..] && !value.is_empty() {
                return Err(unavailable("application has an interrupted sync"));
            }
            Ok(())
        })?;
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
    Ok(invalid)
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
    if !crdt.unified_tree() {
        return Err(unavailable("payload eviction requires a unified store"));
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
        outcome = delete(crdt, &db, &apps, &planned, proceed)?;
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
pub(crate) fn held_shards(crdt: &HypergraphCrdt) -> Result<Vec<(Vec<u8>, u64)>> {
    let Some(db) = crdt.forest_store() else {
        return Ok(Vec::new());
    };
    let mut held = Vec::new();
    for (filter, cursor) in lineages(&db)? {
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
    Ok(held)
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

/// A worker's eviction passes for `keep`, in a thread or a standalone
/// process: the payload outside its served scopes, the forest of the shards
/// it left, then, under `storage`'s base directory, the consensus storage of
/// shards it left unless the predicate says it still owes that shard's
/// committee a vote or seal. `filter` names the binding in the logs.
/// `bound` says whether the worker still serves the binding the passes
/// were started for: the deferral is checked once, at the start, and a
/// worker rebound meanwhile may serve a shard `keep` does not protect, so
/// the forest and storage passes stop as soon as it says no.
pub(crate) async fn run_passes<R>(
    core_id: u32,
    filter: String,
    crdt: std::sync::Arc<HypergraphCrdt>,
    keep: Vec<Vec<u8>>,
    storage: Option<(std::path::PathBuf, R)>,
    bound: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
) where
    R: Fn(&[u8]) -> bool + Send + 'static,
{
    use tracing::{debug, info, warn};
    let (forest_crdt, forest_keep, storage_keep) = (crdt.clone(), keep.clone(), keep.clone());
    let rebound = |stage: &str| {
        info!(core_id, filter, stage,
            "worker eviction stopped: the worker was rebound during the pass; the next pass resumes it");
    };
    let started = std::time::Instant::now();
    let payload_bound = bound.clone();
    let outcome =
        tokio::task::spawn_blocking(move || evict_outside_while(&crdt, &keep, &*payload_bound))
            .await;
    if matches!(&outcome, Ok(Ok(o)) if o.stopped) {
        return rebound("payload eviction");
    }
    match outcome {
        Ok(Ok(o)) if o.ranges > 0 || o.compacted_ranges > 0 => info!(
            core_id,
            filter,
            removed_records = o.removed_records,
            removed_bytes = o.removed_bytes,
            ranges = o.ranges,
            invalidated_markers = o.invalidated_markers,
            compacted_ranges = o.compacted_ranges,
            reclaimable_bytes = o.reclaimable_bytes,
            secs = started.elapsed().as_secs(),
            "worker payload outside served scopes evicted"
        ),
        Ok(Ok(_)) => debug!(core_id, "no worker payload outside served scopes"),
        Ok(Err(error)) => warn!(core_id, filter, %error, "worker payload eviction refused"),
        Err(error) => warn!(core_id, filter, %error, "worker payload eviction task failed"),
    }
    // The forest subtrees of the shards this worker left, recording each
    // shard whose frames it keeps.
    if !bound() {
        return rebound("forest confinement");
    }
    let started = std::time::Instant::now();
    let proceed = bound.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let lineages = lineage_drop_records(&forest_crdt)?;
        forest_crdt.confine_forest_recording(&forest_keep, FOREST_SCAN_BUDGET, &lineages, &*proceed)
    })
    .await;
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
        return rebound("forest confinement");
    }
    // Consensus storage of shards this worker left, unless it still owes
    // that shard's committee a vote or seal.
    if !bound() {
        return rebound("consensus storage");
    }
    if let Some((base, retained)) = storage {
        let outcome = tokio::task::spawn_blocking(move || {
            crate::worker_consensus_storage::remove_outside(&base, &storage_keep, retained)
        })
        .await;
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
    planned: &Plan,
    proceed: &dyn Fn() -> bool,
) -> Result<Outcome> {
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
    let invalidated = crdt.maintain_forest(&guard, |_| {
        if !proceed() {
            return Ok(None);
        }
        let invalid = markers(db, apps, &affected)?;
        let mut batch = rocksdb::WriteBatch::default();
        for (lower, upper) in &planned.ranges {
            batch.delete_range(lower, upper);
        }
        for key in &invalid {
            batch.delete(key);
        }
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        db.write_opt(batch, &options).map_err(store_error)?;
        Ok(Some(invalid.len()))
    })?;
    drop(guard);
    let Some(invalidated) = invalidated else {
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
            ));
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

    fn open() -> (
        Arc<quil_store::RocksDb>,
        Arc<quil_store::RocksHypergraphStore>,
        HypergraphCrdt,
    ) {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
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
            sorted(held_shards(&target).unwrap()),
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
        assert_eq!(held_shards(&target).unwrap(), vec![(served[0].clone(), 40)]);
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
        let root_index =
            quil_store::encoding::hypergraph_root_version_key("vertex", "adds", &APP, &[1; 32]);
        refuses(&|| inner.put(&root_index, [0; 16]).unwrap(), &|| {
            inner.delete(&root_index).unwrap()
        });
        refuses(&|| crdt.set_unified_tree(false), &|| {
            crdt.set_unified_tree(true)
        });
        assert_eq!(
            evict_outside(&crdt, &lower_half()).unwrap().removed_records,
            1,
            "each refusal was the only obstacle"
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
