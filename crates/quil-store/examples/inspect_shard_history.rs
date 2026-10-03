//! Bounded point reads of a frozen secondary; no RocksDB snapshot iterators.
//! Reports hashes and small public summary fields, never mutates the primary.
use quil_store::{encoding, RocksDb};
use prost::Message;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

type Error = Box<dyn std::error::Error>;

fn read(db: &RocksDb, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let value = db.inner().get(key)?;
    if value
        .as_ref()
        .is_some_and(|bytes| bytes.len() > 1024 * 1024)
    {
        return Err("history record exceeds 1 MiB diagnostic cap".into());
    }
    Ok(value)
}

fn describe(bytes: Option<Vec<u8>>) -> Value {
    match bytes {
        None => json!({"present":false}),
        Some(bytes) => {
            json!({"present":true,"length":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),
            "small_value":(bytes.len()<=32).then(||hex::encode(bytes))})
        }
    }
}

fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: inspect_shard_history SHARD_STORE FILTER_HEX FROM THROUGH".into());
    }
    let filter = hex::decode(&args[1])?;
    quil_forest::decode_shard_filter_or_root(&filter, 32).ok_or("invalid shard filter")?;
    let from = args[2].parse::<u64>()?;
    let through = args[3].parse::<u64>()?;
    if through < from || through - from >= 1024 {
        return Err("history range must contain 1..1024 frames".into());
    }
    let scratch = tempfile::tempdir()?;
    let db = RocksDb::open_as_secondary(Path::new(&args[0]), scratch.path())?;
    db.inner().try_catch_up_with_primary()?;
    let mut frames = Vec::new();
    for frame in from..=through {
        let certified = db.inner().get(encoding::clock_shard_frame_key(&filter, frame))?;
        let header = match certified {
            Some(bytes) if bytes.len() <= 16 * 1024 * 1024 => {
                let frame = quil_types::proto::global::AppShardFrame::decode(bytes.as_slice())?;
                frame.header.map(|header| json!({"accumulator":describe(Some(header.accumulator)),
                    "roots":header.state_roots.iter().map(hex::encode).collect::<Vec<_>>(),
                    "requests":frame.requests.len(),"global_frame":header.global_frame_number}))
            }
            Some(_) => return Err("certified frame exceeds 16 MiB diagnostic cap".into()),
            None => None,
        };
        let accumulator = read(
            &db,
            &encoding::clock_shard_frame_accumulator_key(&filter, frame),
        )?;
        let report = match accumulator.as_deref() {
            Some(digest) if digest.len() == 32 => read(
                &db,
                &encoding::clock_shard_accumulator_report_key(&filter, digest),
            )?,
            _ => None,
        };
        frames.push(json!({"frame":frame,"header":header,
            "fees":describe(read(&db,&encoding::clock_shard_frame_fee_total_key(&filter,frame))?),
            "settlements":describe(read(&db,&encoding::clock_shard_frame_settlements_key(&filter,frame))?),
            "spends":describe(read(&db,&encoding::clock_shard_frame_spends_key(&filter,frame))?),
            "accumulator":describe(accumulator),"report":describe(report)}));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"store":args[0],"filter":args[1],"frames":frames}))?
    );
    Ok(())
}
