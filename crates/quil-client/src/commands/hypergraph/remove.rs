//! `qclient hypergraph remove vertex <FullAddress|Alias> -d <domain>`.
//!
//! Port of `client/cmd/hypergraph/remove.go`. Signs `separator ‖ message`
//! (empty FN-DSA context) with the domain's Falcon write key
//! (`q-prover-key`) — the auth convention the node's `verify_op_signature`
//! checks (`hypergraph_intrinsic/auth.rs`).

use clap::Subcommand;

use quil_execution::hypergraph_intrinsic::vertex_ops::{
    vertex_remove_domain_separator, vertex_remove_signing_message,
};
use quil_types::crypto::Signer;
use quil_types::proto::global::{message_request::Request, MessageRequest};
use quil_types::proto::hypergraph::VertexRemove;

use super::HypergraphCtx;

#[derive(Debug, Subcommand)]
pub enum RemoveCommand {
    /// Remove a vertex by full address.
    Vertex { address: String },
}

pub async fn run(hc: &HypergraphCtx, domain: &str, cmd: &RemoveCommand) -> anyhow::Result<()> {
    match cmd {
        RemoveCommand::Vertex { address } => vertex(hc, domain, address).await,
    }
}

async fn vertex(hc: &HypergraphCtx, domain_arg: &str, address: &str) -> anyhow::Result<()> {
    if domain_arg.is_empty() {
        anyhow::bail!("--domain <32-byte hex|alias> is required");
    }
    let domain = hc.resolve_address(domain_arg, 32)?;
    // Full address is 64 bytes; the data address is the last 32.
    let full = hc.resolve_address(address, 64)?;
    let data_address = full[32..64].to_vec();

    // signed = separator ‖ message, Falcon with empty context.
    let separator = vertex_remove_domain_separator(&domain)
        .map_err(|e| anyhow::anyhow!("vertex remove separator: {e}"))?;
    let message = vertex_remove_signing_message(&domain, &data_address)
        .map_err(|e| anyhow::anyhow!("vertex remove message: {e}"))?;
    let mut signed = Vec::with_capacity(separator.len() + message.len());
    signed.extend_from_slice(&separator);
    signed.extend_from_slice(&message);

    let signer: Box<dyn Signer> = hc
        .key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get write key (q-prover-key): {e}"))?;
    let signature = signer
        .sign_with_domain(&signed, &[])
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;

    let op = VertexRemove {
        domain: domain.clone(),
        data_address,
        signature,
    };

    let mut client = hc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::VertexRemove(op)),
        timestamp: 0,
    };
    crate::send::send_message_request(&mut client, &hc.key_manager, domain, request).await?;

    println!("Vertex removed successfully");
    Ok(())
}
