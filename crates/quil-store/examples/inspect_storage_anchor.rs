//! Bounded, read-only localnet diagnostic for a saved frame's storage roots.
//! Secondary readers catch up once, then keep a fixed view. No database copy,
//! full scan, sync, migration or writes to the inspected stores are performed.

use std::{path::Path, sync::Arc};

use prost::Message;
use quil_execution::global_intrinsic::materialize::{
    leaf_root_address, leaf_root_registration_for_epoch,
};
use quil_forest::{Forest, PHASES};
use quil_hypergraph::HypergraphCrdt;
use quil_store::{encoding, RocksDb, RocksHypergraphStore, FOREST_NAMESPACE};
use quil_types::proto::global::{AppShardFrame, GlobalFrameHeader};
use serde_json::json;

type Error = Box<dyn std::error::Error>;

fn read(db: &quil_forest::CoordinatedDb, key: &[u8]) -> Result<Vec<u8>, Error> {
    let value = db.get(key)?.ok_or("record missing")?;
    if value.len() > 32 * 1024 * 1024 {
        return Err("record exceeds diagnostic's 32 MiB bound".into());
    }
    Ok(value)
}

fn registration(
    crdt: &HypergraphCrdt,
    root: &[u8; 32],
    address: &[u8; 32],
    epoch: u64,
) -> serde_json::Value {
    match crdt.global_vertex_membership_at_root(root, address) {
        Ok(Some(proof)) => match quil_tries::deserialize_go_tree(&proof.vertex_blob) {
            Ok(Some(root)) => json!({"available": true, "registration":
                leaf_root_registration_for_epoch(&quil_tries::VectorCommitmentTree { root: Some(root) }, epoch)
                    .map(|(root, blocks)| json!({"root":hex::encode(root), "blocks":blocks}))}),
            Ok(None) => json!({"available": false, "error":"empty tree"}),
            Err(error) => json!({"available": false, "error":error.to_string()}),
        },
        Ok(None) => json!({"available":true, "present":false}),
        Err(error) => json!({"available":false, "error":error.to_string()}),
    }
}

fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !(3..=4).contains(&args.len()) {
        return Err(
            "usage: inspect_storage_anchor MASTER_STORE WORKER_STORE FILTER_HEX [ARCHIVE_STORE]"
                .into(),
        );
    }
    quil_crypto::init();
    let filter = hex::decode(&args[2])?;
    if !(32..=66).contains(&filter.len()) {
        return Err("invalid filter length".into());
    }
    let scratch = tempfile::tempdir()?;
    let worker = RocksDb::open_as_secondary(Path::new(&args[1]), scratch.path())?;
    worker.inner().try_catch_up_with_primary()?;
    let number = u64::from_be_bytes(
        read(
            &worker.inner(),
            &encoding::clock_shard_latest_index(&filter),
        )?
        .try_into()
        .map_err(|_| "bad frame index")?,
    );
    let frame = AppShardFrame::decode(
        read(
            &worker.inner(),
            &encoding::clock_shard_frame_key(&filter, number),
        )?
        .as_slice(),
    )?;
    let header = frame.header.as_ref().ok_or("frame lacks header")?;
    let openings = frame
        .storage_attestation
        .as_ref()
        .map(|a| a.openings.as_slice())
        .unwrap_or_default();
    if openings.len() > 1024 {
        return Err("too many storage openings".into());
    }
    let mut reports = Vec::new();
    for path in std::iter::once(&args[0]).chain(args.get(3)) {
        let scratch = tempfile::tempdir()?;
        let db = RocksDb::open_as_secondary(Path::new(path), scratch.path())?;
        db.inner().try_catch_up_with_primary()?;
        let anchor = GlobalFrameHeader::decode(
            read(
                &db.inner(),
                &encoding::clock_global_frame_key(header.global_frame_number),
            )?
            .as_slice(),
        )?;
        let root: [u8; 32] = anchor.prover_tree_commitment.as_slice().try_into()?;
        let forest = Forest::with_namespace(db.inner(), FOREST_NAMESPACE);
        let version = forest
            .read_head_version(&[0xff; 32], PHASES[0])?
            .ok_or("no GLOBAL head")?;
        let latest = forest
            .shard_phase_root(&[0xff; 32], PHASES[0], version)?
            .ok_or("no GLOBAL root")?;
        let crdt = HypergraphCrdt::new(
            Arc::new(RocksHypergraphStore::new(db.inner())),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        );
        crdt.set_forest(forest);
        let mut records = Vec::new();
        for opening in openings {
            let address = leaf_root_address(&opening.member_id, &opening.shard_id)?;
            records.push(json!({"member":hex::encode(&opening.member_id), "leaf":hex::encode(&opening.shard_id),
                "epoch":opening.epoch, "opened_root":hex::encode(&opening.leaf_root), "blocks":opening.num_blocks,
                "at_anchor":registration(&crdt, &root, &address, opening.epoch),
                "at_latest":registration(&crdt, &latest, &address, opening.epoch)}));
        }
        reports.push(json!({"store":path, "anchor_root":hex::encode(root), "latest_version":version, "records":records}));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"filter":args[2], "frame":header.frame_number,
        "global_anchor":header.global_frame_number, "stores":reports}))?
    );
    Ok(())
}
