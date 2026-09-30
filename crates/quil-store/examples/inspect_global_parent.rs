//! Three bounded header reads from a frozen secondary, leaving the primary untouched.
use prost::Message;
use quil_store::{encoding, RocksDb};
use serde_json::json;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: inspect_global_parent STORE HEIGHT SELECTOR_HEX".into());
    }
    let height: u64 = args[1].parse()?;
    let selector = hex::decode(&args[2])?;
    if selector.len() != 32 {
        return Err("selector must be 32 bytes".into());
    }
    let scratch = tempfile::tempdir()?;
    let db = RocksDb::open_as_secondary(Path::new(&args[0]), scratch.path())?;
    db.inner().try_catch_up_with_primary()?;
    let mut records = Vec::new();
    for (kind, key) in [
        ("prior", encoding::clock_global_frame_key(height.saturating_sub(1))),
        ("canonical", encoding::clock_global_frame_key(height)),
        ("candidate", encoding::clock_global_frame_candidate_key(height, &selector)),
    ] {
        let raw = db.inner().get(&key)?;
        let header = match raw {
            None => None,
            Some(raw) if raw.len() <= 1024 * 1024 => {
                let h = quil_types::proto::global::GlobalFrameHeader::decode(raw.as_slice())?;
                Some(json!({"height":h.frame_number,"view":h.rank,
                    "digest":hex::encode(quil_crypto::poseidon::hash_bytes_to_32(&h.output)?),
                    "parent":hex::encode(h.parent_selector),"bytes":raw.len(),
                    "signature_bytes":h.public_key_signature_bls48581.as_ref().map(|s|s.signature.len())}))
            }
            Some(_) => return Err("header exceeds 1 MiB diagnostic cap".into()),
        };
        records.push(json!({"kind":kind,"header":header}));
    }
    println!("{}",serde_json::to_string_pretty(&json!({"store":args[0],"records":records}))?);
    Ok(())
}
