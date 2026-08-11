//! `qclient deploy compute-update -d <domain> [rdf=<path>]`.
//!
//! Port of `client/cmd/deploy/update.go` `UpdateComputeCmd`, on the current PQ
//! auth: the owner signs the canonical `ComputeUpdate` (signature field cleared)
//! with the Falcon `q-prover-key` under domain `address ‖ "COMPUTE_UPDATE"`, and
//! the raw Falcon bytes go in the proto's `signature` field. The node
//! (`engines.rs` TYPE_COMPUTE_UPDATE branch) re-encodes the update with an empty
//! signature via `ComputeUpdate::to_canonical_bytes()` and verifies it against
//! the *prior* config's `owner_public_key` — so the config here carries the
//! current PQ key material, matching the sibling `hypergraph-update`.
//!
//! Config-only updates (key rotation) omit `rdf=`; a schema evolution supplies
//! `rdf=<file>`.

use quil_execution::compute_intrinsic::conversions::compute_update_from_proto;
use quil_keys::FileKeyManager;
use quil_types::crypto::Signer;
use quil_types::proto::compute::{ComputeConfiguration, ComputeUpdate};
use quil_types::proto::global::{message_request::Request, MessageRequest};
use quil_types::proto::keys::Bls48581AggregateSignature;

use super::DeployCtx;

/// Build a signed `ComputeUpdate` for `domain`. The signed message is the
/// canonical `ComputeUpdate` with the signature field cleared (the node
/// re-encodes it the same way before verifying against the prior config's
/// owner key); the Falcon `q-prover-key` signs it under `domain ‖ "COMPUTE_UPDATE"`.
pub(crate) fn build_compute_update(
    key_manager: &FileKeyManager,
    domain: &[u8],
    cfg: ComputeConfiguration,
    rdf_schema: Vec<u8>,
) -> anyhow::Result<ComputeUpdate> {
    // Signed message = canonical ComputeUpdate with the signature field cleared
    // (the node re-encodes the same way, sig empty, before verifying).
    let unsigned = ComputeUpdate {
        config: Some(cfg.clone()),
        rdf_schema: rdf_schema.clone(),
        public_key_signature_bls48581: None,
    };
    let signed_message = compute_update_from_proto(&unsigned)
        .map_err(|e| anyhow::anyhow!("canonicalize update: {e}"))?
        .to_canonical_bytes()
        .map_err(|e| anyhow::anyhow!("canonical bytes: {e}"))?;

    // Falcon owner signature under `domain ‖ "COMPUTE_UPDATE"`.
    let mut domain_sep = domain.to_vec();
    domain_sep.extend_from_slice(b"COMPUTE_UPDATE");
    let signer: Box<dyn Signer> = key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get owner key (q-prover-key): {e}"))?;
    let sig = signer
        .sign_with_domain(&signed_message, &domain_sep)
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;

    Ok(ComputeUpdate {
        config: Some(cfg),
        rdf_schema,
        public_key_signature_bls48581: Some(Bls48581AggregateSignature {
            signature: sig,
            public_key: None,
            bitmask: Vec::new(),
        }),
    })
}

pub async fn run(dc: &DeployCtx, domain_arg: &str, args: &[String]) -> anyhow::Result<()> {
    if domain_arg.is_empty() {
        anyhow::bail!("--domain <compute address> is required for update");
    }
    let domain = dc.resolve_address(domain_arg, 32)?;

    // Optional `rdf=<path>` schema replacement; absent → config-only update.
    let mut rdf_schema: Vec<u8> = Vec::new();
    for arg in args {
        if let Some((k, v)) = arg.split_once('=') {
            if k.eq_ignore_ascii_case("rdf") {
                rdf_schema =
                    std::fs::read(v).map_err(|e| anyhow::anyhow!("read rdf schema {v:?}: {e}"))?;
            } else {
                anyhow::bail!("unknown compute-update arg: {k} (only rdf=<path>)");
            }
        }
    }

    // Config carries the current (post-PQ) key material.
    let keys = dc.deploy_keys()?;
    let cfg = ComputeConfiguration {
        read_public_key: keys.read,
        write_public_key: keys.write,
        owner_public_key: keys.owner,
    };

    let signed = build_compute_update(&dc.key_manager, &domain, cfg, rdf_schema)?;

    let mut client = dc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::ComputeUpdate(signed)),
        timestamp: 0,
    };
    crate::send::send_message_request(&mut client, &dc.key_manager, domain, request).await?;
    println!("Compute update submitted successfully");
    Ok(())
}
