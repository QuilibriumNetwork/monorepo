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
use quil_execution::hypergraph_intrinsic::{
    hyperedge_remove_domain_separator, hyperedge_remove_signing_message, HYPEREDGE_ID_LEN,
};
use quil_keys::FileKeyManager;
use quil_types::crypto::Signer;
use quil_types::proto::global::{message_request::Request, MessageRequest};
use quil_types::proto::hypergraph::{HyperedgeRemove, VertexRemove};

use super::HypergraphCtx;

/// Build a signed `VertexRemove` for `data_address` under `domain`. Signs
/// `vertex_remove_domain_separator(domain) ‖ vertex_remove_signing_message(...)`
/// (empty FN-DSA context) with the `q-prover-key` Falcon write key — the exact
/// message the node's `verify_op_signature` reconstructs.
pub(crate) fn build_vertex_remove(
    key_manager: &FileKeyManager,
    domain: &[u8],
    data_address: &[u8],
) -> anyhow::Result<VertexRemove> {
    let separator = vertex_remove_domain_separator(domain)
        .map_err(|e| anyhow::anyhow!("vertex remove separator: {e}"))?;
    let message = vertex_remove_signing_message(domain, data_address)
        .map_err(|e| anyhow::anyhow!("vertex remove message: {e}"))?;
    let mut signed = Vec::with_capacity(separator.len() + message.len());
    signed.extend_from_slice(&separator);
    signed.extend_from_slice(&message);

    let signer: Box<dyn Signer> = key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get write key (q-prover-key): {e}"))?;
    let signature = signer
        .sign_with_domain(&signed, &[])
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;

    Ok(VertexRemove {
        domain: domain.to_vec(),
        data_address: data_address.to_vec(),
        signature,
    })
}

/// Build a signed `HyperedgeRemove` for the 64-byte hyperedge `id` under
/// `domain`. The value is `0x01 ‖ id ‖ 0x00` (empty-tree marker); the node's
/// remove path only reads `value[1..65]`. Signs
/// `hyperedge_remove_domain_separator(domain) ‖ hyperedge_remove_signing_message(id)`
/// (empty context) with the `q-prover-key` Falcon write key.
pub(crate) fn build_hyperedge_remove(
    key_manager: &FileKeyManager,
    domain: &[u8],
    id: &[u8; HYPEREDGE_ID_LEN],
) -> anyhow::Result<HyperedgeRemove> {
    // Serialized hyperedge value: `0x01 ‖ app ‖ data ‖ SerializeNonLazyTree(empty)`.
    // Go `hyperedge.ToBytes()` on a bare `NewHyperedge(app, data)` appends the
    // empty extrinsic tree, which serializes to a single nil-node marker (0x00).
    let mut value = Vec::with_capacity(1 + HYPEREDGE_ID_LEN + 1);
    value.push(0x01);
    value.extend_from_slice(id);
    value.push(0x00);

    let separator = hyperedge_remove_domain_separator(domain)
        .map_err(|e| anyhow::anyhow!("hyperedge remove separator: {e}"))?;
    let message = hyperedge_remove_signing_message(id);
    let mut signed = Vec::with_capacity(separator.len() + message.len());
    signed.extend_from_slice(&separator);
    signed.extend_from_slice(&message);

    let signer: Box<dyn Signer> = key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get write key (q-prover-key): {e}"))?;
    let signature = signer
        .sign_with_domain(&signed, &[])
        .map_err(|e| anyhow::anyhow!("sign hyperedge remove: {e}"))?;

    Ok(HyperedgeRemove {
        domain: domain.to_vec(),
        value,
        signature,
    })
}

#[derive(Debug, Subcommand)]
pub enum RemoveCommand {
    /// Remove a vertex by full address.
    Vertex { address: String },
    /// Remove a hyperedge by full address.
    ///
    /// `<address>` is the 64-byte hyperedge address (`app‖data`, hex or
    /// alias) — the hyperedge ID.
    Hyperedge { address: String },
}

pub async fn run(hc: &HypergraphCtx, domain: &str, cmd: &RemoveCommand) -> anyhow::Result<()> {
    match cmd {
        RemoveCommand::Vertex { address } => vertex(hc, domain, address).await,
        RemoveCommand::Hyperedge { address } => hyperedge(hc, domain, address).await,
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

    let op = build_vertex_remove(&hc.key_manager, &domain, &data_address)?;

    let mut client = hc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::VertexRemove(op)),
        timestamp: 0,
    };
    crate::send::send_message_request(&mut client, &hc.key_manager, domain, request).await?;

    println!("Vertex removed successfully");
    Ok(())
}

/// `remove hyperedge <full_address>` — port of Go `RemoveHyperedgeCmd`
/// (`client/cmd/hypergraph/remove.go:96`). The full 64-byte address is the
/// hyperedge ID (`app(32)‖data(32)`). Signs `separator ‖ id` — separator =
/// `domain ‖ "HYPEREDGE_REMOVE"`, message = the 64-byte ID — with the Falcon
/// write key (`q-prover-key`, empty FN-DSA context), matching the node's
/// `verify_op_signature` (`hypergraph_intrinsic/auth.rs`).
async fn hyperedge(hc: &HypergraphCtx, domain_arg: &str, address: &str) -> anyhow::Result<()> {
    if domain_arg.is_empty() {
        anyhow::bail!("--domain <32-byte hex|alias> is required");
    }
    let domain = hc.resolve_address(domain_arg, 32)?;
    // Hyperedge full address = app(32) ‖ data(32) = the hyperedge ID.
    let full = hc.resolve_address(address, HYPEREDGE_ID_LEN)?;
    let mut id = [0u8; HYPEREDGE_ID_LEN];
    id.copy_from_slice(&full);

    let op = build_hyperedge_remove(&hc.key_manager, &domain, &id)?;

    let mut client = hc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::HyperedgeRemove(op)),
        timestamp: 0,
    };
    crate::send::send_message_request(&mut client, &hc.key_manager, domain, request).await?;

    println!("Hyperedge removed successfully");
    println!("Address: {}", hex::encode(id));
    Ok(())
}
