//! `qclient node prover join` — request the node to join shard filters.
//!
//! Port of `client/cmd/node/prover/proverJoin.go`. Unlike the other
//! lifecycle ops, join does NOT locally build/sign a message — it calls
//! `NodeService::RequestJoin`, and the node computes the VDF proof and
//! signs the join server-side.

use quil_types::proto::node::RequestJoinRequest;

use super::ProverCtx;

/// Default filter when none is supplied: all-0xFF (join all shards).
fn default_filter() -> Vec<u8> {
    vec![0xFFu8; 32]
}

pub async fn run(pc: &ProverCtx, filters: &[String], delegate: &str) -> anyhow::Result<()> {
    let filters: Vec<Vec<u8>> = if filters.is_empty() {
        vec![default_filter()]
    } else {
        filters
            .iter()
            .map(|arg| hex::decode(arg).map_err(|e| anyhow::anyhow!("invalid filter hex {arg:?}: {e}")))
            .collect::<anyhow::Result<_>>()?
    };

    let delegate = if delegate.is_empty() {
        Vec::new()
    } else {
        hex::decode(delegate).map_err(|e| anyhow::anyhow!("invalid delegate address hex: {e}"))?
    };

    let mut client = pc.connect().await?;

    println!("Requesting join (VDF proof computation may take a while)...");
    client
        .request_join(tonic::Request::new(RequestJoinRequest {
            filters,
            delegate,
            worker_ids: Vec::new(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("failed to request join: {e}"))?;

    println!("Prover join submitted successfully");
    Ok(())
}
