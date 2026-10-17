//! Reclaims a worker store's canonical app payload outside the scopes it still
//! serves. A worker keeps its RocksDB across reassignments, so every shard it
//! leaves would otherwise stay on disk indefinitely. Only versioned vertex and
//! hyperedge blobs of applications with a protected scope are removed; forest
//! nodes, clock/consensus records, replicas and GLOBAL state are untouched.
//! Readiness markers that promised the removed data are invalidated in the same
//! write, so a later assignment to that scope repairs it through sync.

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
            return Err(QuilError::InvalidArgument("invalid protected address depth".into()));
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
    let mut plan = Plan { ranges: Vec::new(), gaps: Vec::new(), records: 0, bytes: 0 };
    for (app, keep) in apps {
        let shard = quil_types::store::ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(app, 256, 3),
            l2: *app,
        };
        for (set, phase) in [("vertex", "adds"), ("vertex", "removes"), ("hyperedge", "adds"), ("hyperedge", "removes")] {
            let mut prefix = quil_store::encoding::hypergraph_vertex_data_v2_shard_prefix(set, phase, &shard);
            prefix.extend(app);
            for (lo, hi) in gaps(keep) {
                let mut lower = prefix.clone();
                lower.extend(lo);
                let upper = match hi {
                    Some(hi) => [prefix.as_slice(), hi.as_slice()].concat(),
                    None => successor(prefix.clone()).ok_or_else(|| unavailable("unbounded payload domain"))?,
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
fn markers(db: &CoordinatedDb, apps: &BTreeMap<Address, Vec<Interval>>, affected: &[Address]) -> Result<Vec<Vec<u8>>> {
    let mut invalid = Vec::new();
    for app in affected {
        let keep = &apps[app];
        for tag in [quil_store::encoding::HG_ROOT_VERSION, quil_store::encoding::HG_APP_MANIFEST] {
            scan(db, &[tag], None, |key, _| {
                if key.len() >= 35 && key[3..35] == app[..] {
                    return Err(unavailable("application has indexed historical roots or manifests"));
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
            if bits > 256 || tail.len() != n + 5 + bits.div_ceil(8) || tail[n + 2] >= 4 || value != [1] {
                return Err(unavailable("malformed readiness scope"));
            }
            if tail[2..34] == app[..] {
                let packed = &tail[n + 5..];
                let (lo, hi) = bounds(&(0..bits).map(|i| packed[i / 8] & (0x80 >> (i % 8)) != 0).collect::<Vec<_>>());
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
    if !crdt.unified_tree() {
        return Err(unavailable("payload eviction requires a unified store"));
    }
    let apps = coverage(keep)?;
    let guard = crdt.lock_forest_writes();
    let db = crdt.maintain_forest(&guard, |forest| {
        forest.db().cloned().ok_or_else(|| unavailable("payload eviction requires a persistent forest"))
    })?;
    drop(guard);
    let planned = plan(&db, &apps)?;
    let mut outcome = Outcome::default();
    if !planned.ranges.is_empty() {
        outcome = delete(crdt, &db, &apps, &planned)?;
    }
    reclaim(&db, &planned.gaps, &mut outcome)?;
    Ok(outcome)
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

fn delete(crdt: &HypergraphCrdt, db: &CoordinatedDb, apps: &BTreeMap<Address, Vec<Interval>>, planned: &Plan) -> Result<Outcome> {
    let affected: Vec<Address> = apps
        .keys()
        .filter(|app| planned.ranges.iter().any(|(lower, _)| lower[38..70] == app[..]))
        .copied()
        .collect();
    let guard = crdt.lock_forest_writes();
    let invalidated = crdt.maintain_forest(&guard, |_| {
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
        Ok(invalid.len())
    })?;
    drop(guard);
    for (lower, upper) in &planned.ranges {
        let mut residue = false;
        scan(db, lower, Some(upper), |_, _| {
            residue = true;
            Ok(())
        })?;
        if residue {
            return Err(QuilError::Store("payload eviction left records in a deleted range".into()));
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

    fn open() -> (Arc<quil_store::RocksDb>, Arc<quil_store::RocksHypergraphStore>, HypergraphCrdt) {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
        crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
        crdt.set_unified_tree(true);
        (db, store, crdt)
    }

    fn shard() -> ShardKey {
        ShardKey { l1: quil_hypergraph::addressing::get_bloom_filter_indices(&APP, 256, 3), l2: APP }
    }

    fn lower_half() -> Vec<Vec<u8>> {
        vec![quil_forest::encode_shard_bit_path(&APP, &[false])]
    }

    fn location(key: u8) -> Location {
        Location { app_address: APP, data_address: [key; 32] }
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
        let forest = quil_forest::Forest::with_namespace(source_db.inner(), quil_store::FOREST_NAMESPACE);
        let reader = forest.shard_phase_reader(&APP, PHASES[0]);

        let (db, store, target) = open();
        let mut sync = target.prepare_phase_sync(&reader, version, &APP, 0, &[], Some(SubtreeSyncAnchor::AppRoot(root))).unwrap();
        let blobs: Vec<_> = sync.remaining().iter().map(|(key, _)| vec![key[0]; 48]).collect();
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
        let kept = store.load_vertex_underlying_at("vertex", "adds", &shard(), &location(1).to_id(), 0).unwrap();

        let outcome = evict_outside(&target, &lower_half()).unwrap();
        assert_eq!((outcome.removed_records, outcome.invalidated_markers), (1, 1));
        assert!(target.get_vertex_data_checked(&location(129)).unwrap().is_none());
        assert_eq!(store.load_vertex_underlying_at("vertex", "adds", &shard(), &location(1).to_id(), 0).unwrap(), kept);
        assert_eq!(target.serve_forest_head(&APP, 0).unwrap().1, root, "the forest is untouched");
        assert!(!target.sync_data_ready(&APP, 0, &[]).unwrap());
        assert!(target.sync_data_ready(&APP, 0, &[false]).unwrap(), "the kept scope needs no repair");
        assert_eq!(evict_outside(&target, &lower_half()).unwrap(), Outcome::default(), "a repeat finds nothing");

        let mut repair = target.prepare_phase_sync(&reader, version, &APP, 0, &[], Some(SubtreeSyncAnchor::AppRoot(root))).unwrap();
        assert_eq!(repair.remaining().len(), 2, "an equal root must not skip the data audit");
        let blobs: Vec<_> = repair.remaining().iter().map(|(key, _)| vec![key[0]; 48]).collect();
        target.apply_sync_chunk(&mut repair, &blobs).unwrap();
        target.finish_phase_sync(&repair).unwrap();
        assert_eq!(target.get_vertex_data_checked(&location(129)).unwrap(), Some(vec![129; 48]));
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
        let forest = quil_forest::Forest::with_namespace(source_db.inner(), quil_store::FOREST_NAMESPACE);
        let reader = forest.shard_phase_reader(&APP, PHASES[0]);

        let (_db, _, target) = open();
        let mut sync = target.prepare_phase_sync(&reader, version, &APP, 0, &[], Some(SubtreeSyncAnchor::AppRoot(root))).unwrap();
        let blobs: Vec<_> = sync.remaining().iter().map(|(key, _)| vec![key[0]; 48]).collect();
        target.apply_sync_chunk(&mut sync, &blobs).unwrap();
        target.finish_phase_sync(&sync).unwrap();
        let served = lower_half();
        let served_root = target.sub_shard_commitment_for_filter("vertex", "adds", &served[0]);
        assert!(!served_root.is_empty());

        evict_outside(&target, &served).unwrap();
        let confined = target.confine_forest(&served, 1).unwrap();
        assert_eq!(confined.commits, 1, "only the populated phase has a head");
        assert!(confined.nodes > 0 && confined.key_ranges > 0);
        assert_eq!(target.sub_shard_commitment_for_filter("vertex", "adds", &served[0]), served_root);
        assert_ne!(target.serve_forest_head(&APP, 0).unwrap().1, root, "the dropped half left the head");
        assert_eq!(target.get_vertex_data_checked(&location(1)).unwrap(), Some(vec![1; 48]));
        assert_eq!(target.confine_forest(&served, 1).unwrap(), quil_hypergraph::ForestConfinement::default(),
            "a repeat finds nothing and sweeps nothing");
        // A frame commit on the confined tree keeps working.
        target.add_vertex(&location(3), &vec![3; 48]).unwrap();
        target.commit(2).unwrap();
        assert_ne!(target.sub_shard_commitment_for_filter("vertex", "adds", &served[0]), served_root);

        // Reassignment to the whole application syncs the dropped half back.
        let (version, root) = {
            source.add_vertex(&location(3), &vec![3; 48]).unwrap();
            source.commit(2).unwrap();
            source.serve_forest_head(&APP, 0).unwrap()
        };
        let reader = forest.shard_phase_reader(&APP, PHASES[0]);
        let mut repair = target.prepare_phase_sync(&reader, version, &APP, 0, &[], Some(SubtreeSyncAnchor::AppRoot(root))).unwrap();
        let blobs: Vec<_> = repair.remaining().iter().map(|(key, _)| vec![key[0]; 48]).collect();
        target.apply_sync_chunk(&mut repair, &blobs).unwrap();
        target.finish_phase_sync(&repair).unwrap();
        assert_eq!(target.serve_forest_head(&APP, 0).unwrap().1, root);
        assert_eq!(target.get_vertex_data_checked(&location(130)).unwrap(), Some(vec![130; 48]));
    }

    #[test]
    fn keeps_every_protected_version_phase_and_other_keyspaces() {
        let (db, _, crdt) = open();
        let inner = db.inner();
        let (mut kept, mut evicted) = (Vec::new(), Vec::new());
        for (set, phase) in [("vertex", "adds"), ("vertex", "removes"), ("hyperedge", "adds"), ("hyperedge", "removes")] {
            for version in [0, 1, 9] {
                for address in [1u8, 129] {
                    let mut id = APP.to_vec();
                    id.extend([address; 32]);
                    let key = quil_store::encoding::hypergraph_vertex_data_v2_key(set, phase, &shard(), &id, version);
                    inner.put(&key, [address, version as u8]).unwrap();
                    if address == 1 { kept.push(key) } else { evicted.push(key) }
                }
            }
        }
        // Another application without a protected scope is never classified.
        let other = ShardKey { l1: quil_hypergraph::addressing::get_bloom_filter_indices(&[0x22; 32], 256, 3), l2: [0x22; 32] };
        let foreign_app = quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &other, &[[0x22; 32], [129; 32]].concat(), 0);
        inner.put(&foreign_app, b"other").unwrap();
        let global = quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &quil_store::encoding::prover_registry_shard(), &[255; 64], 5);
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
        assert_eq!(inner.get(foreign_app).unwrap().as_deref(), Some(&b"other"[..]));
        assert_eq!(inner.get(global).unwrap().as_deref(), Some(&b"GLOBAL"[..]));
        assert_eq!(inner.get(b"consensus-metadata").unwrap().as_deref(), Some(&b"preserve"[..]));
    }

    #[test]
    fn uncertain_layouts_refuse_without_writing() {
        let (db, _, crdt) = open();
        let inner = db.inner();
        let mut id = APP.to_vec();
        id.extend([129; 32]);
        let key = quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard(), &id, 0);
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
        refuses(&|| inner.put(&mixed, b"bad shape").unwrap(), &|| inner.delete(&mixed).unwrap());
        let mut incomplete = INCOMPLETE.to_vec();
        incomplete.extend(32u16.to_be_bytes());
        incomplete.extend(APP);
        refuses(&|| inner.put(&incomplete, [0, 0, 1, 0]).unwrap(), &|| inner.delete(&incomplete).unwrap());
        let root_index = quil_store::encoding::hypergraph_root_version_key("vertex", "adds", &APP, &[1; 32]);
        refuses(&|| inner.put(&root_index, [0; 16]).unwrap(), &|| inner.delete(&root_index).unwrap());
        refuses(&|| crdt.set_unified_tree(false), &|| crdt.set_unified_tree(true));
        assert_eq!(evict_outside(&crdt, &lower_half()).unwrap().removed_records, 1, "each refusal was the only obstacle");
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
                let key = quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard(), &id, 0);
                inner.put(&key, vec![address; 4096]).unwrap();
            }
            inner.flush().unwrap();
        }
        let inside = |db: &CoordinatedDb| {
            let mut lower = quil_store::encoding::hypergraph_vertex_data_v2_shard_prefix("vertex", "adds", &shard());
            lower.extend(APP);
            lower.push(0x80);
            db.live_files().unwrap().iter().filter(|f| f.start_key.as_deref().is_some_and(|a| a >= lower.as_slice())).map(|f| f.size).sum::<usize>()
        };
        let snapshot = inner.snapshot();
        let first = evict_outside(&crdt, &lower_half()).unwrap();
        assert_eq!(first.removed_records, 128);
        assert!(inside(&inner) > 0, "the held snapshot keeps the deleted records");
        drop(snapshot);
        let second = evict_outside(&crdt, &lower_half()).unwrap();
        assert_eq!(second.removed_records, 0, "nothing visible is left to delete");
        assert!(second.compacted_ranges >= 1 && second.reclaimable_bytes > 0);
        assert_eq!(inside(&inner), 0, "the released records are compacted away");
        assert_eq!(evict_outside(&crdt, &lower_half()).unwrap(), Outcome::default());
    }
}
