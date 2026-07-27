//! `qclient hypergraph get vertex|hyperedge` — read hypergraph data.
//!
//! Port of `client/cmd/hypergraph/get.go`.

use clap::Subcommand;

use quil_types::proto::node::{GetHyperedgeDataRequest, GetVertexDataRequest};

use super::HypergraphCtx;

#[derive(Debug, Subcommand)]
pub enum GetCommand {
    /// Retrieve and display vertex data.
    Vertex { address: String },
    /// Retrieve and display hyperedge data.
    Hyperedge { address: String },
}

pub async fn run(hc: &HypergraphCtx, cmd: &GetCommand) -> anyhow::Result<()> {
    match cmd {
        GetCommand::Vertex { address } => vertex(hc, address).await,
        GetCommand::Hyperedge { address } => hyperedge(hc, address).await,
    }
}

async fn vertex(hc: &HypergraphCtx, address: &str) -> anyhow::Result<()> {
    let addr = hc.resolve_address(address, 64)?;
    let mut client = hc.connect().await?;
    let resp = client
        .get_vertex_data(tonic::Request::new(GetVertexDataRequest {
            address: addr.clone(),
            ..Default::default()
        }))
        .await
        .map_err(|e| anyhow::anyhow!("get vertex data: {e}"))?
        .into_inner();

    println!("Address: {}", hex::encode(&addr));
    println!("Type:    {}/{}", resp.set_type, resp.phase_type);
    println!(
        "Shard:   L1={} L2={}",
        hex::encode(&resp.shard_l1),
        hex::encode(&resp.shard_l2)
    );
    println!("Entries ({}):", resp.entries.len());
    for (i, entry) in resp.entries.iter().enumerate() {
        println!("  [{i}] {} = {}", hex::encode(&entry.key), hex::encode(&entry.value));
    }
    Ok(())
}

async fn hyperedge(hc: &HypergraphCtx, address: &str) -> anyhow::Result<()> {
    let addr = hc.resolve_address(address, 64)?;
    let mut client = hc.connect().await?;
    let resp = client
        .get_hyperedge_data(tonic::Request::new(GetHyperedgeDataRequest {
            address: addr.clone(),
            ..Default::default()
        }))
        .await
        .map_err(|e| anyhow::anyhow!("get hyperedge data: {e}"))?
        .into_inner();

    println!("Address: {}", hex::encode(&addr));
    println!("Type:    {}/{}", resp.set_type, resp.phase_type);
    println!(
        "Shard:   L1={} L2={}",
        hex::encode(&resp.shard_l1),
        hex::encode(&resp.shard_l2)
    );
    println!("Entries ({}):", resp.entries.len());
    for (i, entry) in resp.entries.iter().enumerate() {
        println!("  [{i}] {} = {}", hex::encode(&entry.key), hex::encode(&entry.value));
    }
    Ok(())
}
