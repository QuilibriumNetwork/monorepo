//! Inspect a saved shard's certificate against its historical and current
//! committees. Requires stopped stores, opened read-only without migrations.
use quil_types::{
    consensus::{AppFrameValidator as _, ProverRegistry},
    store::ClockStore,
};
use std::{path::PathBuf, sync::Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err(
            "usage: inspect_app_checkpoint MASTER_STORE WORKER_STORE FILTER_HEX EPOCH_LENGTH"
                .into(),
        );
    }
    quil_crypto::init();
    quil_types::consensus::set_epoch_length_frames(args[3].parse()?);
    let master = quil_store::RocksDb::open_for_read_only(&PathBuf::from(&args[0]))?;
    let worker = quil_store::RocksDb::open_for_read_only(&PathBuf::from(&args[1]))?;
    let registry = Arc::new(quil_execution::prover_registry::SharedProverRegistry::new());
    registry.refresh_from_store(&quil_store::RocksHypergraphStore::new(
        master.inner(),
    ))?;
    let filter = hex::decode(&args[2])?;
    let frame =
        quil_store::RocksClockStore::new(worker.inner()).get_latest_shard_clock_frame(&filter)?;
    let header = frame.header.as_ref().ok_or("shard frame has no header")?;
    let clock = Arc::new(quil_store::RocksClockStore::new(master.inner()));
    let current = clock
        .get_latest_global_clock_frame()?
        .header
        .ok_or("global frame has no header")?
        .frame_number;
    let validation = quil_engine::frame_validator::BlsAppFrameValidator::new(
        registry.clone(),
        Arc::new(quil_crypto::FalconKeyConstructor),
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
    )
    .with_clock_store(clock)
    .validate(&frame);
    let signature = header
        .public_key_signature_bls48581
        .as_ref()
        .ok_or("shard frame has no certificate")?;
    let bytes = quil_cw_consensus::app_cert::unwrap_cert_from_header(&signature.signature)
        .ok_or("shard frame does not carry a Simplex certificate")?;
    let mut namespace = b"appshard".to_vec();
    namespace.extend_from_slice(&filter);
    let digest = quil_crypto::poseidon::hash_bytes_to_32(&header.output)?;
    let mut committees = Vec::new();
    for (label, number) in [
        ("frame_anchor", header.global_frame_number),
        ("current", current),
    ] {
        let members = registry.get_active_provers(&filter, number)?;
        let keys: Vec<_> = members.iter().map(|p| p.public_key.clone()).collect();
        let verified = quil_cw_consensus::app_cert::verify_finalization_details(
            bytes, &keys, &namespace, digest,
        );
        committees.push(serde_json::json!({
            "basis": label, "global_frame": number, "members": keys.len(),
            "verified": verified.is_some(),
            "certificate": verified.map(|v| serde_json::json!({
                "epoch": v.finalization.proposal.round.epoch().get(),
                "view": v.finalization.proposal.round.view().get(),
                "parent_view": v.finalization.proposal.parent.get(),
                "signers": v.signers.len(),
            })),
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "filter": hex::encode(filter), "frame": header.frame_number,
            "declared_rank": header.rank, "global_anchor": header.global_frame_number,
            "committees": committees,
            "frame_validation": match validation {
                Ok(accepted) => serde_json::json!({"accepted": accepted}),
                Err(error) => serde_json::json!({"accepted": false, "error": error.to_string()}),
            },
        }))?
    );
    Ok(())
}
