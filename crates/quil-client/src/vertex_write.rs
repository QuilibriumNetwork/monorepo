//! Shared vertex-add construction (used by `hypergraph put vertex` and
//! `deploy file`).
//!
//! Seals `raw_data` (chunked at `MAX_PLAINTEXT`) to the domain's sntrup761
//! read key, packs the confidential chunks, and Falcon-signs
//! `separator ‖ message` (empty FN-DSA context) with the domain's write
//! key — matching the node's `verify_op_signature`.

use rand::RngCore;

use quil_execution::hypergraph_intrinsic::confidential::{encode, seal, MAX_PLAINTEXT};
use quil_execution::hypergraph_intrinsic::conversions::pack_vertex_add_proof_chunks;
use quil_execution::hypergraph_intrinsic::vertex_ops::{
    vertex_add_domain_separator, vertex_add_signing_message,
};
use quil_keys::FileKeyManager;
use quil_types::crypto::Signer;
use quil_types::proto::hypergraph::VertexAdd;

/// Build a signed `VertexAdd` for `raw_data` under `domain` at
/// `data_address`. `read_pk` is the domain's sntrup761 read public key;
/// signing uses the `q-prover-key` Falcon write key.
pub fn build_vertex_add(
    key_manager: &FileKeyManager,
    domain: &[u8],
    data_address: &[u8],
    raw_data: &[u8],
    read_pk: &[u8],
) -> anyhow::Result<VertexAdd> {
    let mut rng = rand::thread_rng();
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    for slice in raw_data.chunks(MAX_PLAINTEXT) {
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);
        let field = seal(slice, read_pk, &salt, &nonce)
            .ok_or_else(|| anyhow::anyhow!("could not encrypt vertex data"))?;
        chunks.push(encode(&field));
    }

    let data =
        pack_vertex_add_proof_chunks(&chunks).map_err(|e| anyhow::anyhow!("pack chunks: {e}"))?;

    let separator = vertex_add_domain_separator(domain)
        .map_err(|e| anyhow::anyhow!("vertex add separator: {e}"))?;
    let message = vertex_add_signing_message(domain, data_address, &chunks)
        .map_err(|e| anyhow::anyhow!("vertex add message: {e}"))?;
    let mut signed = Vec::with_capacity(separator.len() + message.len());
    signed.extend_from_slice(&separator);
    signed.extend_from_slice(&message);

    let signer: Box<dyn Signer> = key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get write key (q-prover-key): {e}"))?;
    let signature = signer
        .sign_with_domain(&signed, &[])
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;

    Ok(VertexAdd {
        domain: domain.to_vec(),
        data_address: data_address.to_vec(),
        data,
        signature,
    })
}

/// The CLI's own sntrup761 read key (`q-onion-key`) — used as the domain
/// read key for domains the CLI deployed.
pub fn own_read_key(key_manager: &FileKeyManager) -> anyhow::Result<Vec<u8>> {
    key_manager
        .public_key_by_id("q-onion-key")
        .map_err(|e| anyhow::anyhow!("read key: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("q-onion-key (sntrup761 read key) not found"))
}
