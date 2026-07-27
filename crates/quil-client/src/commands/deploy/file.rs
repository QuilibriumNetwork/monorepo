//! `qclient deploy file <file> -d <domain>`.
//!
//! Port of `client/cmd/deploy/deploy.go` `DeployFileCmd`. Files < 4 MB deploy
//! as a single vertex (`deploy_file_single`); files ≥ 4 MB are split into 4 MB
//! chunks — each deployed as its own vertex keyed by `sha3_256(chunk)` — plus a
//! `FILEINDX` index vertex that lists the chunk addresses in order
//! (`deploy_file_chunked`, mirror of Go `deployFileChunked`).
//!
//! Each vertex's bytes are sealed to the domain's sntrup761 read key and
//! Falcon-signed with the write key (via `build_vertex_add`).

use sha3::{Digest, Sha3_256};
use tonic::transport::Channel;

use quil_types::proto::global::{message_request::Request, MessageRequest};
use quil_types::proto::node::node_service_client::NodeServiceClient;

use super::file_index::build_file_index;
use super::DeployCtx;
use crate::vertex_write::{build_vertex_add, own_read_key};

/// Chunk threshold (`chunkThreshold = 4*1024*1024`).
const CHUNK_THRESHOLD: usize = 4 * 1024 * 1024;

pub async fn run(dc: &DeployCtx, domain_arg: &str, file: &str) -> anyhow::Result<()> {
    let domain = dc.resolve_address(domain_arg, 32)?;
    let raw_data = std::fs::read(file).map_err(|e| anyhow::anyhow!("read file {file:?}: {e}"))?;

    if raw_data.len() >= CHUNK_THRESHOLD {
        deploy_file_chunked(dc, &domain, &raw_data).await
    } else {
        deploy_file_single(dc, &domain, &raw_data).await
    }
}

/// Deploy `raw_data` at `sha3_256(raw_data)` under `domain` as one vertex.
async fn deploy_single_vertex(
    dc: &DeployCtx,
    client: &mut NodeServiceClient<Channel>,
    domain: &[u8],
    read_pk: &[u8],
    raw_data: &[u8],
) -> anyhow::Result<[u8; 32]> {
    let data_address = Sha3_256::digest(raw_data);
    let op = build_vertex_add(&dc.key_manager, domain, &data_address, raw_data, read_pk)?;
    let request = MessageRequest {
        request: Some(Request::VertexAdd(op)),
        timestamp: 0,
    };
    crate::send::send_message_request(client, &dc.key_manager, domain.to_vec(), request).await?;
    Ok(data_address.into())
}

async fn deploy_file_single(dc: &DeployCtx, domain: &[u8], raw_data: &[u8]) -> anyhow::Result<()> {
    let read_pk = own_read_key(&dc.key_manager)?;
    let mut client = dc.connect().await?;
    let data_address = deploy_single_vertex(dc, &mut client, domain, &read_pk, raw_data).await?;

    println!("File deployed successfully");
    println!("Address: {}", hex::encode(data_address));
    Ok(())
}

/// Split a large file into 4 MB chunks (each its own vertex) and deploy a
/// `FILEINDX` index vertex listing the chunk addresses. Mirror of Go
/// `deployFileChunked`.
async fn deploy_file_chunked(dc: &DeployCtx, domain: &[u8], raw_data: &[u8]) -> anyhow::Result<()> {
    let read_pk = own_read_key(&dc.key_manager)?;
    let mut client = dc.connect().await?;

    let total_size = raw_data.len() as u64;
    let chunk_count = raw_data.len().div_ceil(CHUNK_THRESHOLD);
    let mut blob_addresses: Vec<[u8; 32]> = Vec::with_capacity(chunk_count);

    for (i, chunk) in raw_data.chunks(CHUNK_THRESHOLD).enumerate() {
        println!(
            "Uploading chunk {}/{} ({:.1} MB)...",
            i + 1,
            chunk_count,
            chunk.len() as f64 / (1024.0 * 1024.0)
        );
        let addr = deploy_single_vertex(dc, &mut client, domain, &read_pk, chunk).await?;
        blob_addresses.push(addr);
    }

    // Index vertex ties the chunks together; deployed like any other vertex
    // (sealed to the CLI's read key — the Rust ecosystem reads it back with the
    // same q-onion-key, so there is no separate "nil key" public-index path).
    let index_content = build_file_index(total_size, CHUNK_THRESHOLD as u32, &blob_addresses);
    println!("Uploading file index...");
    let index_address =
        deploy_single_vertex(dc, &mut client, domain, &read_pk, &index_content).await?;

    let mut full_address = domain.to_vec();
    full_address.extend_from_slice(&index_address);
    println!("File deployed successfully ({chunk_count} chunks)");
    println!("Full address: {}", hex::encode(&full_address));
    Ok(())
}
