//! `qclient deploy get <full_address> <output_path>`.
//!
//! Port of `client/cmd/deploy/deploy.go` `GetFileCmd`. Fetches the vertex at
//! `<full_address>` (64 bytes) with `full_data`, reconstructs its plaintext by
//! decrypting the sequential confidential fields with the CLI's `q-onion-key`
//! sntrup761 secret (`vertex_tree_to_plaintext`), and:
//!
//! - if the plaintext is a `FILEINDX` index, fetches every listed chunk vertex,
//!   decrypts+concatenates them, truncates to the recorded total size, and
//!   writes the result (mirror of Go's chunked reassembly);
//! - otherwise writes the plaintext directly (single-vertex file).

use quil_execution::hypergraph_intrinsic::vertex_tree_to_plaintext;
use quil_types::proto::node::node_service_client::NodeServiceClient;
use quil_types::proto::node::GetVertexDataRequest;
use tonic::transport::Channel;

use super::file_index::{is_file_index, parse_file_index};
use super::DeployCtx;

pub async fn run(dc: &DeployCtx, full_address: &str, output_path: &str) -> anyhow::Result<()> {
    let address = dc.resolve_address(full_address, 64)?;
    let kem_sk = dc
        .key_manager
        .get_secret_key_bytes_by_id("q-onion-key")
        .map_err(|e| anyhow::anyhow!("q-onion-key secret: {e}"))?;

    let mut client = dc.connect().await?;

    let raw_data = fetch_and_decrypt(&mut client, &address, &kem_sk).await?;

    if !is_file_index(&raw_data) {
        std::fs::write(output_path, &raw_data)
            .map_err(|e| anyhow::anyhow!("write output {output_path:?}: {e}"))?;
        println!("File saved to {output_path} ({} bytes)", raw_data.len());
        return Ok(());
    }

    // Chunked file: reassemble from the index.
    let (total_size, _chunk_size, blob_addresses) = parse_file_index(&raw_data)?;
    println!(
        "Downloading {} chunks ({:.1} MB total)...",
        blob_addresses.len(),
        total_size as f64 / (1024.0 * 1024.0)
    );

    let domain = &address[..32];
    let mut assembled: Vec<u8> = Vec::with_capacity(total_size as usize);
    for (i, blob) in blob_addresses.iter().enumerate() {
        println!("Downloading chunk {}/{}...", i + 1, blob_addresses.len());
        let mut chunk_address = Vec::with_capacity(64);
        chunk_address.extend_from_slice(domain);
        chunk_address.extend_from_slice(blob);
        let chunk = fetch_and_decrypt(&mut client, &chunk_address, &kem_sk).await?;
        assembled.extend_from_slice(&chunk);
    }

    // The last chunk may carry trailing padding; truncate to the exact size.
    if assembled.len() as u64 > total_size {
        assembled.truncate(total_size as usize);
    }

    std::fs::write(output_path, &assembled)
        .map_err(|e| anyhow::anyhow!("write output {output_path:?}: {e}"))?;
    println!("File saved to {output_path} ({} bytes)", assembled.len());
    Ok(())
}

/// Fetch a vertex's full serialized sub-tree and reconstruct its plaintext.
/// Mirror of Go `fetchAndDecrypt`.
async fn fetch_and_decrypt(
    client: &mut NodeServiceClient<Channel>,
    address: &[u8],
    kem_sk: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let resp = client
        .get_vertex_data(tonic::Request::new(GetVertexDataRequest {
            address: address.to_vec(),
            full_data: true,
        }))
        .await
        .map_err(|e| anyhow::anyhow!("get vertex data: {e}"))?
        .into_inner();

    if resp.raw_data.is_empty() {
        anyhow::bail!(
            "no data returned for vertex {} (not deployed, or wrong address)",
            hex::encode(address)
        );
    }

    vertex_tree_to_plaintext(&resp.raw_data, kem_sk)
        .map_err(|e| anyhow::anyhow!("reconstruct vertex plaintext: {e}"))
}
