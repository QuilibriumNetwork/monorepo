//! Read-only localnet diagnostic for a GLOBAL forest sync mismatch.
//!
//! Opens both stores as secondary readers, pins their current versions, and
//! compares at most 10,000 leaves per store. It never applies the staged diff.
//! The two heads need not be the same global checkpoint; this is a debugging
//! aid, not a mainnet migration-readiness check.
//!
//! cargo run -p quil-store --example compare_global_forest -- SOURCE TARGET

use std::{collections::BTreeMap, path::Path};

use quil_forest::{diff_leaves, Forest, SubtreeSyncAnchor, PHASES};
use quil_store::{RocksClockStore, RocksDb, RocksHypergraphStore, FOREST_NAMESPACE};
use quil_types::store::{ClockStore, HypergraphStore, ShardKey};
use sha2::{Digest, Sha256};
use serde_json::json;

type Error = Box<dyn std::error::Error>;

// A secondary has no snapshot API. This diagnostic catches up exactly once
// before any reads, and never advances its view while reading these records.
fn secondary_frame(db: &quil_forest::CoordinatedDb, number: u64) -> Result<quil_types::proto::global::GlobalFrame, Error> {
    use prost::Message;
    use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader, MessageBundle};
    let header = db.get(quil_store::encoding::clock_global_frame_key(number))?.ok_or("frame missing")?;
    let header = GlobalFrameHeader::decode(header.as_slice())?;
    let prefix = quil_store::encoding::clock_global_frame_request_key(number, 0);
    let prefix = &prefix[..prefix.len() - 2];
    let mut requests = Vec::new();
    let mut bytes = 0usize;
    for item in db.iterator(rocksdb::IteratorMode::From(prefix, rocksdb::Direction::Forward)) {
        let (key, value) = item?;
        if !key.starts_with(prefix) { break; }
        bytes += value.len();
        if requests.len() >= 1024 || bytes > 32 * 1024 * 1024 { return Err("frame diagnostic limit exceeded".into()); }
        requests.push(MessageBundle::decode(value.as_ref())?);
    }
    Ok(GlobalFrame { header: Some(header), requests })
}

fn inspect(source: &Path, target: &Path, frame: Option<u64>, phase_idx: usize) -> Result<serde_json::Value, Error> {
    let source_scratch = tempfile::tempdir()?;
    let target_scratch = tempfile::tempdir()?;
    let source_db = RocksDb::open_as_secondary(source, source_scratch.path())?;
    let target_db = RocksDb::open_as_secondary(target, target_scratch.path())?;
    source_db.inner().try_catch_up_with_primary()?;
    target_db.inner().try_catch_up_with_primary()?;
    let source_forest = Forest::with_namespace(source_db.inner(), FOREST_NAMESPACE);
    let target_forest = Forest::with_namespace(target_db.inner(), FOREST_NAMESPACE);
    let shard = [0xff; 32];
    let phase = *PHASES.get(phase_idx).ok_or("phase must be 0..3")?;
    let source_version = source_forest.read_head_version(&shard, phase)?.ok_or("source has no forest head")?;
    let target_version = target_forest.read_head_version(&shard, phase)?.ok_or("target has no forest head")?;
    let source_root = source_forest.shard_phase_root(&shard, phase, source_version)?.ok_or("source root absent")?;
    let target_root = target_forest.shard_phase_root(&shard, phase, target_version)?.ok_or("target root absent")?;
    let source_count = source_forest.shard_phase_leaf_count(&shard, phase, source_version)?;
    let target_count = target_forest.shard_phase_leaf_count(&shard, phase, target_version)?;
    if source_count > 10_000 || target_count > 10_000 {
        return Err("diagnostic leaf limit exceeded; refusing full enumeration".into());
    }
    let source_reader = source_forest.shard_phase_reader(&shard, phase);
    let target_reader = target_forest.shard_phase_reader(&shard, phase);
    let empty = Forest::in_memory().shard_phase_reader(&shard, phase);
    let source_leaves: BTreeMap<_, _> = diff_leaves(&source_reader, source_version, &empty, 0)?
        .into_iter().map(|(key, value)| (key.0, value)).collect();
    let target_leaves: BTreeMap<_, _> = diff_leaves(&target_reader, target_version, &empty, 0)?
        .into_iter().map(|(key, value)| (key.0, value)).collect();
    let source_only: Vec<_> = source_leaves.keys().filter(|key| !target_leaves.contains_key(*key)).map(hex::encode).collect();
    let target_only: Vec<_> = target_leaves.keys().filter(|key| !source_leaves.contains_key(*key)).map(hex::encode).collect();
    let target_store = RocksHypergraphStore::new(target_db.inner());
    let shard_key = ShardKey { l1: [0; 3], l2: shard };
    let mut target_only_records = Vec::new();
    for key in target_leaves.keys().filter(|key| !source_leaves.contains_key(*key)).take(32) {
        let id: Vec<_> = shard.into_iter().chain(key.iter().copied()).collect();
        let blob = target_store.load_vertex_underlying_at("vertex", "adds", &shard_key, &id, target_version)?;
        let tree = blob.as_ref().and_then(|blob| quil_tries::deserialize_go_tree(blob).ok().flatten());
        let type_hash = tree.as_ref().and_then(|tree| tree.find_leaf_value(&[0xff; 32]));
        let class = type_hash.as_deref().and_then(quil_execution::class_for_type_hash);
        let mut present_versions = Vec::new();
        let mut unavailable_versions = 0;
        for version in source_version.saturating_sub(255)..=source_version {
            match source_forest.shard_phase_get_with_proof_raw(&shard, phase, version, key) {
                Ok((Some(_), _)) => present_versions.push(version),
                Ok((None, _)) => {},
                Err(_) => unavailable_versions += 1,
            }
        }
        target_only_records.push(json!({"key": hex::encode(key), "class": class,
            "type_hash": type_hash.map(hex::encode), "blob_bytes": blob.as_ref().map(Vec::len),
            "source_present_versions": present_versions, "source_unavailable_versions": unavailable_versions}));
    }
    let mut frame_comparison = Vec::new();
    if let Some(number) = frame {
        for (role, db) in [("source", source_db.inner()), ("target", target_db.inner())] {
            use prost::Message;
            use quil_types::proto::global::message_request::Request;
            let frame = secondary_frame(&db, number)?;
            let clock = RocksClockStore::new(db);
            let bundles: Vec<_> = frame.requests.iter().map(|bundle| {
                let ops: Vec<_> = bundle.requests.iter().map(|request| match &request.request {
                    Some(Request::Join(join)) => json!({"kind":"join", "at":join.frame_number, "filters":join.filters.iter().map(hex::encode).collect::<Vec<_>>()}),
                    Some(Request::Confirm(confirm)) => json!({"kind":"confirm", "at":confirm.frame_number}),
                    Some(Request::Shard(_)) => json!({"kind":"shard"}),
                    other => json!({"kind":format!("{:?}", other.as_ref().map(std::mem::discriminant))}),
                }).collect();
                json!({"sha256":hex::encode(Sha256::digest(bundle.encode_to_vec())), "operations":ops})
            }).collect();
            let outcomes: Vec<_> = clock.get_global_clock_frame_outcomes(number)?.into_iter()
                .map(|outcome| json!({"status":format!("{:?}",outcome.status),"error":outcome.error})).collect();
            frame_comparison.push(json!({"role":role,"frame":number,"bundles":bundles,"outcomes":outcomes,
                "materialized_cursor":clock.get_global_materialized_cursor()}));
        }
    }
    let changed = source_leaves.iter().filter(|(key, value)| target_leaves.get(*key).is_some_and(|old| old != *value)).count();
    let (diff, expected) = quil_forest::diff_leaves_under_prefix(
        &source_reader, source_version, &target_reader, target_version,
        &[], Some(SubtreeSyncAnchor::AppRoot(source_root)),
    )?;
    let diff_count = diff.len();
    let staged = target_forest.stage_synced_phase(
        &shard, phase, target_version.checked_add(1).ok_or("target version overflow")?,
        diff.into_iter().map(|(key, value)| (key, Some(value))), &[], Some(expected),
    );
    let reconstruction = match staged {
        Ok(staged) => json!({"matches": true, "root": hex::encode(staged.root())}),
        Err(error) => json!({"matches": false, "error": error.to_string()}),
    };
    // Exercise the production reconciliation planner without applying any
    // chunk. The secondary store also prevents an accidental durable write.
    let target_crdt = quil_hypergraph::HypergraphCrdt::new(
        std::sync::Arc::new(RocksHypergraphStore::new(target_db.inner())),
        std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
    );
    target_crdt.set_forest(target_forest.clone());
    let reconciliation = match target_crdt.prepare_phase_sync(
        &source_reader, source_version, &shard, phase_idx, &[], Some(SubtreeSyncAnchor::AppRoot(source_root)),
    ) {
        Ok(plan) => json!({"matches": true, "updates": plan.remaining().len(),
            "deletions": plan.remaining().iter().filter(|(_, value)| value.is_none()).count()}),
        Err(error) => json!({"matches": false, "error": error.to_string()}),
    };
    let source_stable = source_forest.shard_phase_root(&shard, phase, source_version)? == Some(source_root);
    let target_stable = target_forest.shard_phase_root(&shard, phase, target_version)? == Some(target_root);
    Ok(json!({
        "source": source, "target": target, "phase": phase_idx,
        "source_version": source_version, "target_version": target_version,
        "source_root": hex::encode(source_root), "target_root": hex::encode(target_root),
        "source_count": source_count, "target_count": target_count,
        "source_only": source_only, "target_only": target_only, "target_only_records": target_only_records,
        "changed_common_values": changed, "diff_leaves": diff_count,
        "reconstruction": reconstruction,
        "reconciliation": reconciliation,
        "frame_comparison": frame_comparison,
        "pinned_versions_stable": source_stable && target_stable,
    }))
}

fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if !(2..=4).contains(&args.len()) { return Err("usage: compare_global_forest SOURCE_STORE TARGET_STORE [FRAME|-] [PHASE]".into()); }
    let frame = args.get(2).filter(|value| value.to_str() != Some("-")).map(|value| -> Result<u64, Error> {
        Ok(value.to_str().ok_or("frame is not UTF-8")?.parse()?)
    }).transpose()?;
    let phase = args.get(3).map(|value| -> Result<usize, Error> {
        Ok(value.to_str().ok_or("phase is not UTF-8")?.parse()?)
    }).transpose()?.unwrap_or(0);
    let result = inspect(Path::new(&args[0]), Path::new(&args[1]), frame, phase)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
