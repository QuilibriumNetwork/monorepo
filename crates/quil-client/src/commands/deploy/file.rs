//! `qclient deploy file <file> -d <domain>`.
//!
//! Port of `client/cmd/deploy/deploy.go` `DeployFileCmd`. Files < 4 MB deploy
//! as a single vertex (`deploy_file_single`); files ≥ 4 MB are split into 4 MB
//! chunks — each deployed as its own vertex keyed by `sha3_256(chunk)` — plus a
//! `FILEINDX` index vertex that lists the chunk addresses in order
//! (`deploy_file_chunked`, mirror of Go `deployFileChunked`).
//!
//! Each vertex's bytes are sealed to the CLI's sntrup761 read key, or with
//! `--public` to the published public file key (`crate::public_file_key`) so
//! anyone can read them, and Falcon-signed with the write key (via
//! `build_vertex_add`). Both seal the same vertex form at the same fee.

use sha3::{Digest, Sha3_256};
use tonic::transport::Channel;

use quil_types::proto::global::{message_request::Request, MessageRequest};
use quil_types::proto::node::node_service_client::NodeServiceClient;

use super::file_index::build_file_index;
use super::DeployCtx;
use crate::public_file_key;
use crate::vertex_write::{build_vertex_add, own_read_key};

/// Chunk threshold (`chunkThreshold = 4*1024*1024`).
const CHUNK_THRESHOLD: usize = 4 * 1024 * 1024;

pub async fn run(dc: &DeployCtx, domain_arg: &str, file: &str, public: bool) -> anyhow::Result<()> {
    let domain = dc.resolve_address(domain_arg, 32)?;
    let raw_data = std::fs::read(file).map_err(|e| anyhow::anyhow!("read file {file:?}: {e}"))?;
    let read_pk = read_key(dc, public)?;

    if raw_data.len() >= CHUNK_THRESHOLD {
        deploy_file_chunked(dc, &domain, &read_pk, &raw_data).await?;
    } else {
        deploy_file_single(dc, &domain, &read_pk, &raw_data).await?;
    }
    if public {
        println!("{PUBLIC_LINE}");
    }
    Ok(())
}

/// The line `--public` adds after the address.
const PUBLIC_LINE: &str = "Readable by: anyone (sealed to the public file key)";

/// The key every vertex of the file is sealed to: the public file key with
/// `--public`, else the CLI's own read key.
fn read_key(dc: &DeployCtx, public: bool) -> anyhow::Result<Vec<u8>> {
    if public {
        public_file_key::public_key()
    } else {
        own_read_key(&dc.key_manager)
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
    dc.send_paid(client, domain, request).await?;
    Ok(data_address.into())
}

async fn deploy_file_single(
    dc: &DeployCtx,
    domain: &[u8],
    read_pk: &[u8],
    raw_data: &[u8],
) -> anyhow::Result<()> {
    let mut client = dc.connect().await?;
    let data_address = deploy_single_vertex(dc, &mut client, domain, read_pk, raw_data).await?;

    println!("File deployed successfully");
    println!("Address: {}", hex::encode(data_address));
    Ok(())
}

/// Split a large file into 4 MB chunks (each its own vertex) and deploy a
/// `FILEINDX` index vertex listing the chunk addresses. Mirror of Go
/// `deployFileChunked`.
async fn deploy_file_chunked(
    dc: &DeployCtx,
    domain: &[u8],
    read_pk: &[u8],
    raw_data: &[u8],
) -> anyhow::Result<()> {
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
        let addr = deploy_single_vertex(dc, &mut client, domain, read_pk, chunk).await?;
        blob_addresses.push(addr);
    }

    // Index vertex ties the chunks together; deployed like any other vertex,
    // sealed to the same key as the chunks (`deploy get` reads it back with the
    // key that opens it, so there is no separate "nil key" public-index path).
    let index_content = build_file_index(total_size, CHUNK_THRESHOLD as u32, &blob_addresses);
    println!("Uploading file index...");
    let index_address =
        deploy_single_vertex(dc, &mut client, domain, read_pk, &index_content).await?;

    let mut full_address = domain.to_vec();
    full_address.extend_from_slice(&index_address);
    println!("File deployed successfully ({chunk_count} chunks)");
    println!("Full address: {}", hex::encode(&full_address));
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::super::tests::offline_ctx;
    use super::super::DeployCommand;
    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: DeployCommand,
    }

    fn parsed_public(extra: &[&str]) -> bool {
        let domain = hex::encode([7u8; 32]);
        let mut args = vec!["deploy", "file", "-d", domain.as_str()];
        args.extend_from_slice(extra);
        args.push("image.png");
        match Cli::try_parse_from(args).unwrap().command {
            DeployCommand::File { public, .. } => public,
            other => panic!("parsed as {other:?}"),
        }
    }

    /// `--public` seals to the public file key, at the same vertex form and
    /// fee; without it the file stays sealed to the uploader's key.
    #[test]
    fn deploy_file_public_seals_to_the_public_file_key() {
        assert!(parsed_public(&["--public"]));
        assert!(!parsed_public(&[]));
        let dc = offline_ctx("file-public");
        let sealed_to = read_key(&dc, true).ok();
        assert_eq!(
            sealed_to,
            Some(public_file_key::public_key().unwrap()),
            "deploy file --public did not seal to the public file key"
        );
        assert_ne!(
            read_key(&dc, false).ok(),
            sealed_to,
            "deploy file without --public sealed to the public file key"
        );
        assert_eq!(
            PUBLIC_LINE,
            "Readable by: anyone (sealed to the public file key)"
        );
    }
}
