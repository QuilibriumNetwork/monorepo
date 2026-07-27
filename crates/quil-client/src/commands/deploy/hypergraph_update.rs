//! `qclient deploy hypergraph-update -d <domain> [rdf=<path>]`.
//!
//! Port of `client/cmd/deploy/update.go` `UpdateHypergraphCmd`, on the current
//! PQ auth: the owner signs the canonical `HypergraphUpdate` (signature field
//! cleared) with the Falcon `q-prover-key` under domain
//! `address ‖ "HYPERGRAPH_UPDATE"`, and the raw Falcon bytes go in the proto's
//! `signature` field (see `hypergraph_intrinsic/auth.rs::verify_update_signature`).
//!
//! Config-only updates (key rotation) omit `rdf=`; a schema evolution supplies
//! `rdf=<file>` (the node enforces the strict-superset evolution check).

use quil_execution::hypergraph_intrinsic::HypergraphUpdate as CanonicalHypergraphUpdate;
use quil_types::crypto::Signer;
use quil_types::proto::global::{message_request::Request, MessageRequest};
use quil_types::proto::hypergraph::{HypergraphConfiguration, HypergraphUpdate};
use quil_types::proto::keys::Bls48581AggregateSignature;

use super::DeployCtx;

pub async fn run(dc: &DeployCtx, domain_arg: &str, args: &[String]) -> anyhow::Result<()> {
    if domain_arg.is_empty() {
        anyhow::bail!("--domain <hypergraph address> is required for update");
    }
    let domain = dc.resolve_address(domain_arg, 32)?;

    // Optional `rdf=<path>` schema replacement; absent → config-only update.
    let mut rdf_schema: Vec<u8> = Vec::new();
    for arg in args {
        if let Some((k, v)) = arg.split_once('=') {
            if k.eq_ignore_ascii_case("rdf") {
                rdf_schema = std::fs::read(v)
                    .map_err(|e| anyhow::anyhow!("read rdf schema {v:?}: {e}"))?;
            } else {
                anyhow::bail!("unknown hypergraph-update arg: {k} (only rdf=<path>)");
            }
        }
    }

    // Config carries the current (post-PQ) key material.
    let keys = dc.deploy_keys()?;
    let cfg = HypergraphConfiguration {
        read_public_key: keys.read,
        write_public_key: keys.write,
        owner_public_key: keys.owner,
    };

    // Signed message = canonical HypergraphUpdate with the signature cleared.
    let unsigned = HypergraphUpdate {
        config: Some(cfg.clone()),
        rdf_schema: rdf_schema.clone(),
        public_key_signature_bls48581: None,
    };
    let signed_message = CanonicalHypergraphUpdate::from_proto(&unsigned)
        .map_err(|e| anyhow::anyhow!("canonicalize update: {e}"))?
        .to_canonical_bytes_without_signature()
        .map_err(|e| anyhow::anyhow!("canonical bytes: {e}"))?;

    // Falcon owner signature under `domain ‖ "HYPERGRAPH_UPDATE"`.
    let mut domain_sep = domain.clone();
    domain_sep.extend_from_slice(b"HYPERGRAPH_UPDATE");
    let signer: Box<dyn Signer> = dc
        .key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get owner key (q-prover-key): {e}"))?;
    let sig = signer
        .sign_with_domain(&signed_message, &domain_sep)
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;

    let signed = HypergraphUpdate {
        config: Some(cfg),
        rdf_schema,
        public_key_signature_bls48581: Some(Bls48581AggregateSignature {
            signature: sig,
            public_key: None,
            bitmask: Vec::new(),
        }),
    };

    let mut client = dc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::HypergraphUpdate(signed)),
        timestamp: 0,
    };
    crate::send::send_message_request(&mut client, &dc.key_manager, domain, request).await?;
    println!("Hypergraph update submitted successfully");
    Ok(())
}
