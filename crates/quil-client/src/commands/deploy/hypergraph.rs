//! `qclient deploy hypergraph [key=value...] <schema.rdf>`.
//!
//! Port of `client/cmd/deploy/deploy.go` `DeployHypergraphCmd`. Builds a
//! `HypergraphConfiguration` from the CLI's PQ keys and submits it. The
//! Rust node's `HypergraphDeploy::from_proto` rejects an empty RDF schema,
//! so a `.rdf` file argument is required (unlike Go, where it was optional).

use quil_types::proto::global::{message_request::Request, MessageRequest};
use quil_types::proto::hypergraph::{HypergraphConfiguration, HypergraphDeploy};

use super::DeployCtx;

pub async fn run(dc: &DeployCtx, args: &[String]) -> anyhow::Result<()> {
    let rdf_file = args
        .iter()
        .find(|a| a.ends_with(".rdf"))
        .ok_or_else(|| anyhow::anyhow!("a <schema>.rdf file argument is required"))?;
    let rdf_schema = std::fs::read(rdf_file)
        .map_err(|e| anyhow::anyhow!("read RDF file {rdf_file:?}: {e}"))?;
    if rdf_schema.is_empty() {
        anyhow::bail!("RDF schema file {rdf_file:?} is empty");
    }

    let keys = dc.deploy_keys()?;
    let deploy = HypergraphDeploy {
        config: Some(HypergraphConfiguration {
            read_public_key: keys.read,
            write_public_key: keys.write,
            owner_public_key: keys.owner,
        }),
        rdf_schema,
    };

    let mut client = dc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::HypergraphDeploy(deploy)),
        timestamp: 0,
    };
    dc.send_deploy(&mut client, request).await?;

    println!("Hypergraph schema deployed successfully");
    Ok(())
}
