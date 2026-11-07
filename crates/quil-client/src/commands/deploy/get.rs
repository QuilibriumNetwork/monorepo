//! `qclient deploy get <full_address> <output_path>`.
//!
//! Port of `client/cmd/deploy/deploy.go` `GetFileCmd`. Fetches the vertex at
//! `<full_address>` (64 bytes) with `full_data`, reconstructs its plaintext by
//! decrypting the sequential confidential fields with the CLI's `q-onion-key`
//! sntrup761 secret, or failing that with the published public file key
//! (`crate::public_file_key`, what `deploy file --public` seals to), and:
//!
//! - if the plaintext is a `FILEINDX` index, fetches every listed chunk vertex,
//!   decrypts+concatenates them, truncates to the recorded total size, and
//!   writes the result (mirror of Go's chunked reassembly);
//! - otherwise writes the plaintext directly (single-vertex file).
//!
//! Its last line names the key that opened the file.

use quil_execution::hypergraph_intrinsic::vertex_tree_to_plaintext;
use quil_types::proto::node::node_service_client::NodeServiceClient;
use quil_types::proto::node::GetVertexDataRequest;
use tonic::transport::Channel;

use super::file_index::{is_file_index, parse_file_index};
use super::DeployCtx;
use crate::public_file_key;

/// The key that opened a vertex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Opener {
    /// The caller's own read key (`q-onion-key`).
    Own,
    /// The published public file key.
    Public,
}

impl Opener {
    fn label(self) -> &'static str {
        match self {
            Opener::Own => "your read key (q-onion-key)",
            Opener::Public => "the public file key",
        }
    }
}

/// The secret keys `deploy get` opens with, in the order it tries them.
struct Readers {
    own: Vec<u8>,
    public: Vec<u8>,
}

/// Open a fetched vertex tree with the caller's key, else the public file
/// key; the error names both when neither opens it.
fn open_vertex(raw: &[u8], readers: &Readers) -> anyhow::Result<(Vec<u8>, Opener)> {
    let own_err = match vertex_tree_to_plaintext(raw, &readers.own) {
        Ok(plaintext) => return Ok((plaintext, Opener::Own)),
        Err(e) => e,
    };
    vertex_tree_to_plaintext(raw, &readers.public)
        .map(|plaintext| (plaintext, Opener::Public))
        .map_err(|_| {
            anyhow::anyhow!(
                "neither your read key nor the public file key opens it ({own_err}); \
                 ask the uploader which key it was sealed to"
            )
        })
}

/// The output line naming each key that opened a part of the file, in the
/// order first used.
fn opened_line(openers: &[Opener]) -> String {
    let mut used: Vec<Opener> = Vec::new();
    for opener in openers {
        if !used.contains(opener) {
            used.push(*opener);
        }
    }
    let labels: Vec<&str> = used.iter().map(|o| o.label()).collect();
    format!("Opened with: {}", labels.join(" and "))
}

pub async fn run(dc: &DeployCtx, full_address: &str, output_path: &str) -> anyhow::Result<()> {
    let address = dc.resolve_address(full_address, 64)?;
    let readers = Readers {
        own: dc
            .key_manager
            .get_secret_key_bytes_by_id("q-onion-key")
            .map_err(|e| anyhow::anyhow!("q-onion-key secret: {e}"))?,
        public: public_file_key::secret_key()?,
    };

    let mut client = dc.connect().await?;

    let (raw_data, opener) = fetch_and_decrypt(&mut client, &address, &readers).await?;
    let mut openers = vec![opener];

    if !is_file_index(&raw_data) {
        std::fs::write(output_path, &raw_data)
            .map_err(|e| anyhow::anyhow!("write output {output_path:?}: {e}"))?;
        println!("File saved to {output_path} ({} bytes)", raw_data.len());
        println!("{}", opened_line(&openers));
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
        let (chunk, opener) = fetch_and_decrypt(&mut client, &chunk_address, &readers).await?;
        openers.push(opener);
        assembled.extend_from_slice(&chunk);
    }

    // The last chunk may carry trailing padding; truncate to the exact size.
    if assembled.len() as u64 > total_size {
        assembled.truncate(total_size as usize);
    }

    std::fs::write(output_path, &assembled)
        .map_err(|e| anyhow::anyhow!("write output {output_path:?}: {e}"))?;
    println!("File saved to {output_path} ({} bytes)", assembled.len());
    println!("{}", opened_line(&openers));
    Ok(())
}

/// Fetch a vertex's full serialized sub-tree and reconstruct its plaintext
/// with the first key that opens it. Mirror of Go `fetchAndDecrypt`.
async fn fetch_and_decrypt(
    client: &mut NodeServiceClient<Channel>,
    address: &[u8],
    readers: &Readers,
) -> anyhow::Result<(Vec<u8>, Opener)> {
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

    open_vertex(&resp.raw_data, readers)
        .map_err(|e| anyhow::anyhow!("reconstruct vertex {} plaintext: {e}", hex::encode(address)))
}

#[cfg(test)]
mod tests {
    use quil_crypto::sntrup761::Sntrup761KeyPair;

    use super::*;
    use crate::public_file_key::tests::sealed_tree;

    fn readers(own: &Sntrup761KeyPair) -> Readers {
        Readers {
            own: own.secret.clone(),
            public: public_file_key::secret_key().unwrap(),
        }
    }

    /// A file sealed by `deploy file --public` opens without the uploader's
    /// key, and the output says the public file key opened it.
    #[test]
    fn get_opens_a_public_file_with_the_public_file_key() {
        let caller = Sntrup761KeyPair::generate();
        let raw = sealed_tree(
            &public_file_key::public_key().unwrap(),
            &[b"a public ", b"image"],
        );
        let opened = open_vertex(&raw, &readers(&caller)).ok();
        assert_eq!(
            opened,
            Some((b"a public image".to_vec(), Opener::Public)),
            "deploy get did not open a public file with the public file key"
        );
        assert_eq!(
            opened_line(&[Opener::Public]),
            "Opened with: the public file key"
        );
    }

    /// The caller's own key is tried first and named.
    #[test]
    fn get_opens_the_callers_file_with_its_read_key() {
        let caller = Sntrup761KeyPair::generate();
        let raw = sealed_tree(&caller.public, &[b"private"]);
        assert_eq!(
            open_vertex(&raw, &readers(&caller)).unwrap(),
            (b"private".to_vec(), Opener::Own)
        );
        assert_eq!(
            opened_line(&[Opener::Own]),
            "Opened with: your read key (q-onion-key)"
        );
    }

    /// Sealed to someone else: the refusal names both keys tried.
    #[test]
    fn get_names_both_keys_when_neither_opens_the_file() {
        let caller = Sntrup761KeyPair::generate();
        let other = Sntrup761KeyPair::generate();
        let raw = sealed_tree(&other.public, &[b"theirs"]);
        let err = open_vertex(&raw, &readers(&caller))
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("neither your read key nor the public file key opens it")
                && err.ends_with("ask the uploader which key it was sealed to"),
            "{err}"
        );
    }

    /// A chunked file whose parts opened with different keys names each
    /// once, in the order first used.
    #[test]
    fn the_opened_line_names_each_key_that_opened_a_part() {
        assert_eq!(
            opened_line(&[Opener::Public, Opener::Public, Opener::Own, Opener::Public]),
            "Opened with: the public file key and your read key (q-onion-key)"
        );
    }
}
