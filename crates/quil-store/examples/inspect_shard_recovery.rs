//! Point-read diagnostics for a unified-tree localnet shard and its session.
//! Requires stopped stores, opened read-only. No writes, database copy or scan.
//! The optional outgoing-history fold is capped at 1,024 frames.

use prost::Message;
use quil_execution::global_intrinsic::handoff::{self, CommittedView};
use quil_hypergraph::HypergraphCrdt;
use quil_store::{encoding, RocksDb, RocksHypergraphStore, FOREST_NAMESPACE};
use quil_types::{proto::global::AppShardFrame, store::SnapshotReadable};
use serde_json::json;
use std::{path::Path, sync::Arc};

type Error = Box<dyn std::error::Error>;

fn crdt(db: &RocksDb) -> Arc<HypergraphCrdt> {
    let crdt = Arc::new(HypergraphCrdt::new(
        Arc::new(RocksHypergraphStore::new(db.inner())),
        Arc::new(quil_types::crypto::NoopInclusionProver),
    ));
    crdt.set_forest(quil_forest::Forest::with_namespace(
        db.inner(),
        FOREST_NAMESPACE,
    ));
    crdt.set_unified_tree(true);
    crdt
}

fn number(records: &dyn SnapshotReadable, key: &[u8]) -> Result<Option<u64>, Error> {
    records
        .read_record(key)?
        .map(|v| Ok(u64::from_be_bytes(v.as_slice().try_into()?)))
        .transpose()
}

fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: inspect_shard_recovery GLOBAL_STORE SHARD_STORE FILTER_HEX".into());
    }
    quil_crypto::init();
    let filter = hex::decode(&args[2])?;
    quil_forest::decode_shard_filter_or_root(&filter, 32).ok_or("invalid filter")?;
    let global = RocksDb::open_for_read_only(Path::new(&args[0]))?;
    let shard = RocksDb::open_for_read_only(Path::new(&args[1]))?;
    let snapshot = crdt(&shard).capture_committed_shard(&filter)?;
    let cursor = number(
        snapshot.records.as_ref(),
        &encoding::consensus_materialized_cursor_key(&filter),
    )?;
    let tip = number(
        snapshot.records.as_ref(),
        &encoding::clock_shard_latest_index(&filter),
    )?;
    let mut frame = None;
    if let Some(tip) = tip {
        let bytes = snapshot
            .records
            .read_record(&encoding::clock_shard_frame_key(&filter, tip))?
            .ok_or("tip frame missing")?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err("frame exceeds 16 MiB diagnostic cap".into());
        }
        let stored = AppShardFrame::decode(bytes.as_slice())?;
        let header = stored.header.ok_or("tip frame has no header")?;
        frame = Some(
            json!({"number":header.frame_number,"global_anchor":header.global_frame_number,
            "view":header.rank,"digest":hex::encode(quil_crypto::poseidon::hash_bytes_to_32(&header.output)?),
            "request_bundles":stored.requests.len(),"pre_state_roots":header.state_roots.iter().map(hex::encode).collect::<Vec<_>>()}),
        );
    }
    let global_crdt = crdt(&global);
    let view = CommittedView::capture(&global_crdt)?;
    let session = match handoff::head(&view, &filter)? {
        None => json!(null),
        Some(session) => {
            let id = session.id()?;
            let members: Result<Vec<_>, _> = session
                .members
                .iter()
                .map(|key| quil_crypto::poseidon::hash_bytes_to_32(key).map(hex::encode))
                .collect();
            let history = match cursor {
                Some(cursor) if cursor.saturating_sub(session.base_frame) <= 1024 => {
                    match handoff::history::root(snapshot.records.as_ref(), &session, cursor) {
                        Ok(root) => json!({"root":hex::encode(root)}),
                        Err(error) => json!({"error":error.to_string()}),
                    }
                }
                _ => json!({"skipped":"missing cursor or history exceeds 1024-frame limit"}),
            };
            json!({"id":hex::encode(id),"generation":session.generation,"base_frame":session.base_frame,
                "genesis":hex::encode(session.genesis),"members":members?,
                "status":format!("{:?}",handoff::status(&view,&id)?),"history":history})
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"global_store":args[0],"shard_store":args[1],
        "filter":args[2],"global_cursor":view.frame(),"cursor":cursor,"tip":tip,"frame":frame,
        "committed_roots":snapshot.roots.iter().map(hex::encode).collect::<Vec<_>>(),"session":session}))?
    );
    Ok(())
}
