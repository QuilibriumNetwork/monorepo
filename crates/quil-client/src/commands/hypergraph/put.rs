//! `qclient hypergraph put vertex [key=value...] -d <domain>`.
//!
//! Port of `client/cmd/hypergraph/put.go` `PutVertexCmd`, rebuilt for the
//! current PQ crypto:
//! - `data_address = sha3_256(rawData)` where `rawData = concat(key‖value)`.
//! - each ≤`MAX_PLAINTEXT` slice of rawData is sealed to the domain's
//!   sntrup761 **read key** (`confidential::seal` → `encode`), then the
//!   chunks are packed via `pack_vertex_add_proof_chunks`.
//! - signed = `vertex_add_domain_separator(domain) ‖
//!   vertex_add_signing_message(domain, data_address, &chunks)`, signed with
//!   the Falcon write key (`q-prover-key`), empty FN-DSA context.
//!
//! The read key used here is the CLI's own `q-onion-key` — i.e. this targets
//! domains the CLI deployed with its own read key.

use clap::Subcommand;
use sha3::{Digest, Sha3_256};

use quil_execution::hypergraph_intrinsic::{
    build_hyperedge_add_value, extract_hyperedge_id, hyperedge_add_domain_separator,
    hyperedge_add_signing_message, HYPEREDGE_ID_LEN,
};
use quil_types::crypto::Signer;
use quil_types::proto::global::{message_request::Request, MessageRequest};
use quil_types::proto::hypergraph::HyperedgeAdd;

use super::HypergraphCtx;
use crate::vertex_write::{build_vertex_add, own_read_key};

#[derive(Debug, Subcommand)]
pub enum PutCommand {
    /// Insert/update a vertex from `key=value` properties.
    Vertex { properties: Vec<String> },
    /// Create a hyperedge connecting atoms.
    ///
    /// `<full_address>` is the 64-byte hyperedge address (`app‖data`, hex or
    /// alias); the remaining args are 64-byte atom addresses (hex or alias,
    /// comma- or space-separated).
    Hyperedge {
        full_address: String,
        atoms: Vec<String>,
    },
}

pub async fn run(hc: &HypergraphCtx, domain: &str, cmd: &PutCommand) -> anyhow::Result<()> {
    match cmd {
        PutCommand::Vertex { properties } => vertex(hc, domain, properties).await,
        PutCommand::Hyperedge {
            full_address,
            atoms,
        } => hyperedge(hc, domain, full_address, atoms).await,
    }
}

async fn vertex(hc: &HypergraphCtx, domain_arg: &str, properties: &[String]) -> anyhow::Result<()> {
    if domain_arg.is_empty() {
        anyhow::bail!("--domain <32-byte hex|alias> is required");
    }
    let domain = hc.resolve_address(domain_arg, 32)?;

    // rawData = concat(key ‖ value) over all key=value args.
    let mut raw_data = Vec::new();
    for arg in properties {
        if let Some((k, v)) = arg.split_once('=') {
            raw_data.extend_from_slice(k.as_bytes());
            raw_data.extend_from_slice(v.as_bytes());
        }
    }
    if raw_data.is_empty() {
        anyhow::bail!("at least one key=value property is required");
    }

    let data_address = Sha3_256::digest(&raw_data).to_vec();

    let read_pk = own_read_key(&hc.key_manager)?;
    let op = build_vertex_add(&hc.key_manager, &domain, &data_address, &raw_data, &read_pk)?;

    let mut client = hc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::VertexAdd(op)),
        timestamp: 0,
    };
    crate::send::send_message_request(&mut client, &hc.key_manager, domain, request).await?;

    println!("Vertex submitted successfully");
    println!("Address: {}", hex::encode(&data_address));
    Ok(())
}

/// `put hyperedge <full_address> <atom...>` — port of Go
/// `PutHyperedgeCmd` (`client/cmd/hypergraph/put.go:151`) on the current PQ
/// crypto. Builds the extrinsic tree from the atom ids, SHA-Merkle-commits it
/// (via the shared `build_hyperedge_add_value`, byte-identical to the node's
/// verify), then Falcon-signs `separator ‖ (id ‖ commit)` with the write key
/// (`q-prover-key`, empty context) — matching `verify_op_signature`.
async fn hyperedge(
    hc: &HypergraphCtx,
    domain_arg: &str,
    full_address: &str,
    atom_args: &[String],
) -> anyhow::Result<()> {
    if domain_arg.is_empty() {
        anyhow::bail!("--domain <32-byte hex|alias> is required");
    }
    let domain = hc.resolve_address(domain_arg, 32)?;

    // Hyperedge full address = app(32) ‖ data(32).
    let full = hc.resolve_address(full_address, HYPEREDGE_ID_LEN)?;
    let mut app = [0u8; 32];
    let mut data = [0u8; 32];
    app.copy_from_slice(&full[..32]);
    data.copy_from_slice(&full[32..]);

    // Atom addresses (comma- or space-separated, hex or alias), each 64 bytes.
    let mut atoms: Vec<[u8; HYPEREDGE_ID_LEN]> = Vec::new();
    for arg in atom_args {
        for piece in arg.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            let a = hc.resolve_address(piece, HYPEREDGE_ID_LEN)?;
            let mut id = [0u8; HYPEREDGE_ID_LEN];
            id.copy_from_slice(&a);
            atoms.push(id);
        }
    }
    if atoms.is_empty() {
        anyhow::bail!("at least one 64-byte atom address is required");
    }

    // Value bytes (0x01‖app‖data‖tree) + the SHA-Merkle extrinsic commitment.
    let (value, commit) = build_hyperedge_add_value(&app, &data, &atoms)
        .map_err(|e| anyhow::anyhow!("build hyperedge: {e}"))?;

    // signed = separator ‖ (id ‖ commit); Falcon write key, empty context.
    let id = extract_hyperedge_id(&value).map_err(|e| anyhow::anyhow!("hyperedge id: {e}"))?;
    let separator = hyperedge_add_domain_separator(&domain)
        .map_err(|e| anyhow::anyhow!("hyperedge separator: {e}"))?;
    let message = hyperedge_add_signing_message(&id, &commit)
        .map_err(|e| anyhow::anyhow!("hyperedge signing message: {e}"))?;
    let mut signed = Vec::with_capacity(separator.len() + message.len());
    signed.extend_from_slice(&separator);
    signed.extend_from_slice(&message);

    let signer: Box<dyn Signer> = hc
        .key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get write key (q-prover-key): {e}"))?;
    let signature = signer
        .sign_with_domain(&signed, &[])
        .map_err(|e| anyhow::anyhow!("sign hyperedge add: {e}"))?;

    let op = HyperedgeAdd {
        domain: domain.clone(),
        value,
        signature,
    };

    let mut client = hc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::HyperedgeAdd(op)),
        timestamp: 0,
    };
    crate::send::send_message_request(&mut client, &hc.key_manager, domain, request).await?;

    println!("Hyperedge submitted successfully");
    println!("Full address: {}", hex::encode(id));
    Ok(())
}
