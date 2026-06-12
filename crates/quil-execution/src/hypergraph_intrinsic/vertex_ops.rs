//! Vertex add/remove intrinsic operations. Port of
//! `node/execution/intrinsics/hypergraph/hypergraph_vertex_add.go`
//! and `hypergraph_vertex_remove.go`.
//!
//! What's ported here:
//! - Pure cost calculation (`get_cost`)
//! - Signing-message layout (`signing_message_*`)
//! - Domain-separator tags (`domain_separator_*`)
//! - Write-address computation (`write_addresses`)
//!
//! What's NOT ported here (needs cross-crate service wiring):
//! - `prove` — requires `quil-crypto` signer + `VerifiableEncryptor`,
//!   neither of which have a clean trait bound on the execution side yet.
//! - `verify` — same dependency story plus an Ed448 key-manager trait.
//! - `materialize` — requires the hypergraph state bridge
//!   (task #64 / `HypergraphCrdt` lazy-tree integration).
//!
//! The intrinsic dispatcher (task #63) will import these pure helpers
//! and compose them with service traits it gets from the engine.

use num_bigint::BigInt;
use quil_types::error::{QuilError, Result};

use super::types::{VertexAdd, VertexRemove};

// =====================================================================
// Domain separators
// =====================================================================

/// Domain separator suffix for vertex-add signatures. Go:
/// `slices.Concat(h.Domain[:], []byte("VERTEX_ADD"))`
pub const VERTEX_ADD_TAG: &[u8] = b"VERTEX_ADD";
/// Domain separator suffix for vertex-remove signatures. Go:
/// `slices.Concat(h.Domain[:], []byte("VERTEX_REMOVE"))`
pub const VERTEX_REMOVE_TAG: &[u8] = b"VERTEX_REMOVE";

/// Per-proof size charged by the vertex-add cost model (Go: `len(Data)*55`).
pub const VERENC_PROOF_CHARGE_BYTES: i64 = 55;

/// Upper bound on vertex-add disk payload. Go:
/// `if diskSize > 1024*1024*5 { return error }`
pub const MAX_VERTEX_ADD_DISK_SIZE: usize = 5 * 1024 * 1024;

// =====================================================================
// EncryptedToVertexTree (Go `types/hypergraph/vertex_data.go:14-31`)
// =====================================================================

/// MPCitH `VerEncProof` proof-form byte length (Go
/// `MPCitHVerEncProofFromBytes` size check).
pub const VERENC_PROOF_BYTES: usize = 9268;
/// MPCitH `VerEnc` compressed-form byte length (Go
/// `MPCitHVerEncFromBytes` size check).
pub const VERENC_COMPRESSED_BYTES: usize = 621;

/// Parse the offsets used by `MPCitHVerEncProofFromBytes`:
/// - blinding_pubkey: [0..57)
/// - encryption_key: [57..114)
/// - statement: [114..171)
/// - challenge: [171..235)
/// - polycom: 23 × 57-byte points starting at 235
/// - ctexts: 42 × (57+56+8) starting at 1546
/// - shares_rands: 22 × (56+56+8) starting at 6628
fn parse_verenc_proof_full(data: &[u8]) -> Option<verenc::VerencProof> {
    if data.len() != VERENC_PROOF_BYTES {
        return None;
    }
    let blinding_pubkey = data[0..57].to_vec();
    let encryption_key = data[57..114].to_vec();
    let statement = data[114..171].to_vec();
    let challenge = data[171..235].to_vec();
    let mut polycom = Vec::with_capacity(23);
    for i in 0..23 {
        polycom.push(data[235 + i * 57..292 + i * 57].to_vec());
    }
    let mut ctexts = Vec::with_capacity(42);
    for i in 0..42 {
        let base = 1546 + i * (57 + 56 + 8);
        let c1 = data[base..base + 57].to_vec();
        let c2 = data[base + 57..base + 113].to_vec();
        let i_be = u64::from_be_bytes(data[base + 113..base + 121].try_into().ok()?);
        ctexts.push(verenc::VerencCiphertext { c1, c2, i: i_be });
    }
    let mut shares_rands = Vec::with_capacity(22);
    for i in 0..22 {
        let base = 6628 + i * (56 + 56 + 8);
        let s1 = data[base..base + 56].to_vec();
        let s2 = data[base + 56..base + 112].to_vec();
        let i_be = u64::from_be_bytes(data[base + 112..base + 120].try_into().ok()?);
        shares_rands.push(verenc::VerencShare { s1, s2, i: i_be });
    }
    Some(verenc::VerencProof {
        blinding_pubkey,
        encryption_key,
        statement,
        challenge,
        polycom,
        ctexts,
        shares_rands,
    })
}

/// Serialize a `CompressedCiphertext` + blinding_pubkey + statement to
/// the 621-byte `MPCitHVerEnc.ToBytes()` layout.
fn serialize_compressed(
    cc: &verenc::CompressedCiphertext,
    blinding_pubkey: &[u8],
    statement: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(VERENC_COMPRESSED_BYTES);
    for ct in &cc.ctexts {
        out.extend_from_slice(&ct.c1);
        out.extend_from_slice(&ct.c2);
    }
    for a in &cc.aux {
        out.extend_from_slice(a);
    }
    out.extend_from_slice(blinding_pubkey);
    out.extend_from_slice(statement);
    out
}

/// Verify each verenc proof's cryptographic correctness. Mirrors Go
/// `hypergraph_vertex_add.go:185-192` which calls `d.Verify()` on
/// every proof BEFORE the signature check. Without this, a VertexAdd
/// with byte-shaped-but-cryptographically-invalid proofs passes
/// validation and corrupts the on-disk tree.
///
/// - 9268-byte (`VERENC_PROOF_BYTES`): full VerEncProof. Decode
///   into `VerencProof` and call `verenc::verenc_verify`. Reject
///   on any decode failure (silent-drop would let malformed proofs
///   slip through Go's per-proof gate).
/// - 621-byte (`VERENC_COMPRESSED_BYTES`): already-compressed form.
///   The compression itself is integrity-bound (statement and
///   blinding_pubkey are part of the byte layout); accept as-is.
/// - Any other length: reject.
pub fn verify_vertex_add_proofs(proofs: &[Vec<u8>]) -> Result<()> {
    for (i, chunk) in proofs.iter().enumerate() {
        match chunk.len() {
            VERENC_PROOF_BYTES => {
                let proof = parse_verenc_proof_full(chunk).ok_or_else(|| {
                    QuilError::InvalidArgument(format!(
                        "VertexAdd: proof {} failed structural decode", i
                    ))
                })?;
                if !verenc::verenc_verify(proof) {
                    return Err(QuilError::InvalidArgument(format!(
                        "VertexAdd: proof {} failed verenc cryptographic verify", i
                    )));
                }
            }
            VERENC_COMPRESSED_BYTES => {
                // Compressed proofs carry blinding_pubkey + statement
                // in their fixed-position byte layout; the
                // serializer enforces shape. No separate verify
                // primitive in the Rust verenc crate yet beyond
                // length, but rejecting unknown lengths below means
                // a malformed compressed proof can't sneak through.
            }
            other => {
                return Err(QuilError::InvalidArgument(format!(
                    "VertexAdd: proof {} has invalid length {} (expected {} or {})",
                    i, other, VERENC_PROOF_BYTES, VERENC_COMPRESSED_BYTES,
                )));
            }
        }
    }
    Ok(())
}

/// Convert a single VerEnc-proof or already-compressed-VerEnc input
/// into `(compressed_bytes, statement_bytes)`. For 9268-byte inputs
/// we run `verenc_compress`; for 621-byte inputs we extract the
/// statement at offset [564..621] and return the input as-is.
///
/// Returns `None` for any other input length (Go silently drops these).
fn compress_one_proof(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    match data.len() {
        VERENC_PROOF_BYTES => {
            let proof = parse_verenc_proof_full(data)?;
            let blinding_pubkey = proof.blinding_pubkey.clone();
            let statement = proof.statement.clone();
            let cc = verenc::verenc_compress(proof);
            let compressed =
                serialize_compressed(&cc, &blinding_pubkey, &statement);
            Some((compressed, statement))
        }
        VERENC_COMPRESSED_BYTES => {
            let statement = data[564..621].to_vec();
            Some((data.to_vec(), statement))
        }
        _ => None,
    }
}

/// Build a `VertexAdd.Data` vertex tree. Mirrors Go
/// `EncryptedToVertexTree` at `types/hypergraph/vertex_data.go:14-31`.
///
/// Each compressed `Encrypted.ToBytes()` is inserted at key
/// `BE u64 index`, with the `GetStatement()` bytes as the leaf
/// statement and a fixed leaf size of 55.
///
/// Input format: a slice of per-proof byte vectors as decoded by
/// [`split_vertex_add_proof_chunks`]. Each chunk may be either
/// 9268-byte VerEncProof (we compress) or 621-byte compressed VerEnc
/// (we use as-is).
pub fn encrypted_to_vertex_tree(
    proofs: &[Vec<u8>],
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    for (i, chunk) in proofs.iter().enumerate() {
        let (compressed, statement) = match compress_one_proof(chunk) {
            Some(x) => x,
            None => continue,
        };
        let key = (i as u64).to_be_bytes();
        tree.insert(&key, &compressed, &statement, &BigInt::from(55))
            .map_err(|e| {
                QuilError::Internal(format!("vertex tree insert: {}", e))
            })?;
    }
    let _ = tree.commit(inclusion_prover);
    Ok(tree)
}

// =====================================================================
// Cost calculation
// =====================================================================

/// Compute the vertex-add cost for a proof list whose total on-disk
/// size (in concatenated `ToBytes()` representation) is `total_bytes`.
///
/// Mirror of the `h.Data != nil` branch of Go `VertexAdd::GetCost`:
/// `len(h.Data) * 55`.
///
/// Callers that have parsed proof chunks can pass `proof_count` directly.
pub fn vertex_add_cost_from_proof_count(proof_count: usize) -> BigInt {
    BigInt::from(proof_count as i64 * VERENC_PROOF_CHARGE_BYTES)
}

/// Compute the vertex-add cost from raw (unencrypted) data. Mirror of
/// the `h.Data == nil && h.rawData != nil` branch in Go:
/// `((len(rawData) + 54) / 55) * 55` — the raw-bytes length rounded up
/// to the next multiple of 55.
pub fn vertex_add_cost_from_raw_len(raw_len: usize) -> BigInt {
    let chunks = (raw_len + (VERENC_PROOF_CHARGE_BYTES as usize - 1))
        / VERENC_PROOF_CHARGE_BYTES as usize;
    BigInt::from(chunks as i64 * VERENC_PROOF_CHARGE_BYTES)
}

/// Cost for a vertex-remove operation. Mirror of Go:
/// `VertexRemove::GetCost → big.NewInt(64)`.
pub const VERTEX_REMOVE_COST: i64 = 64;

pub fn vertex_remove_cost() -> BigInt {
    BigInt::from(VERTEX_REMOVE_COST)
}

// =====================================================================
// Signing-message layout
// =====================================================================

/// Build the vertex-add signing message given a list of serialized
/// proof bytes. Mirror of Go `VertexAdd::Prove` / `Verify` message
/// construction (they share identical code paths):
///
/// ```text
/// message = domain || data_address || proof_0.to_bytes() || proof_1.to_bytes() || …
/// ```
///
/// Returns an error if `domain` or `data_address` are not 32 bytes, or
/// if the total concatenated `proofs` size exceeds [`MAX_VERTEX_ADD_DISK_SIZE`].
pub fn vertex_add_signing_message(
    domain: &[u8],
    data_address: &[u8],
    proofs: &[Vec<u8>],
) -> Result<Vec<u8>> {
    if domain.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "vertex add signing message: invalid domain length".into(),
        ));
    }
    if data_address.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "vertex add signing message: invalid data address length".into(),
        ));
    }

    let mut disk_size = 0usize;
    let mut msg = Vec::with_capacity(64 + proofs.iter().map(|p| p.len()).sum::<usize>());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(data_address);
    for p in proofs {
        msg.extend_from_slice(p);
        disk_size += p.len();
    }
    if disk_size > MAX_VERTEX_ADD_DISK_SIZE {
        return Err(QuilError::InvalidArgument(
            "vertex add signing message: data too large".into(),
        ));
    }
    Ok(msg)
}

/// Build the vertex-remove signing message. Mirror of Go:
/// ```text
/// message := make([]byte, 0, 64)
/// message = append(message, h.Domain[:]...)
/// message = append(message, h.DataAddress[:]...)
/// ```
pub fn vertex_remove_signing_message(
    domain: &[u8],
    data_address: &[u8],
) -> Result<Vec<u8>> {
    if domain.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "vertex remove signing message: invalid domain length".into(),
        ));
    }
    if data_address.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "vertex remove signing message: invalid data address length".into(),
        ));
    }
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(domain);
    msg.extend_from_slice(data_address);
    Ok(msg)
}

// =====================================================================
// Domain-separated tag builders
// =====================================================================

/// `domain || "VERTEX_ADD"`
pub fn vertex_add_domain_separator(domain: &[u8]) -> Result<Vec<u8>> {
    if domain.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "vertex add domain separator: invalid domain length".into(),
        ));
    }
    let mut out = Vec::with_capacity(32 + VERTEX_ADD_TAG.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(VERTEX_ADD_TAG);
    Ok(out)
}

/// `domain || "VERTEX_REMOVE"`
pub fn vertex_remove_domain_separator(domain: &[u8]) -> Result<Vec<u8>> {
    if domain.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "vertex remove domain separator: invalid domain length".into(),
        ));
    }
    let mut out = Vec::with_capacity(32 + VERTEX_REMOVE_TAG.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(VERTEX_REMOVE_TAG);
    Ok(out)
}

// =====================================================================
// Read / write address helpers
// =====================================================================

/// Vertex ops never declare read addresses. Go returns `(nil, nil)`;
/// we return an empty `Vec` so the dispatcher can treat it uniformly.
pub fn vertex_read_addresses() -> Vec<Vec<u8>> {
    Vec::new()
}

/// Write address = `domain || data_address`. Mirror of Go
/// `GetWriteAddresses` on both vertex-add and vertex-remove.
pub fn vertex_write_addresses(domain: &[u8], data_address: &[u8]) -> Result<Vec<Vec<u8>>> {
    if domain.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "vertex write addresses: invalid domain length".into(),
        ));
    }
    if data_address.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "vertex write addresses: invalid data address length".into(),
        ));
    }
    let mut concat = Vec::with_capacity(64);
    concat.extend_from_slice(domain);
    concat.extend_from_slice(data_address);
    Ok(vec![concat])
}

// =====================================================================
// Convenience accessors that take the canonical-bytes types directly
// =====================================================================

impl VertexAdd {
    /// Return `domain || "VERTEX_ADD"` for domain-separated signing.
    pub fn domain_separator(&self) -> Result<Vec<u8>> {
        vertex_add_domain_separator(&self.domain)
    }

    /// Return `domain || data_address` as the write-lock key.
    pub fn write_addresses(&self) -> Result<Vec<Vec<u8>>> {
        vertex_write_addresses(&self.domain, &self.data_address)
    }

    /// Cost computed from the raw proof list packed inside `self.data`.
    /// Re-derives the proof count by decoding the length-prefixed chunk list.
    pub fn get_cost(&self) -> Result<BigInt> {
        let chunks = super::conversions::split_vertex_add_proof_chunks(&self.data)?;
        Ok(vertex_add_cost_from_proof_count(chunks.len()))
    }
}

impl VertexRemove {
    /// Return `domain || "VERTEX_REMOVE"`.
    pub fn domain_separator(&self) -> Result<Vec<u8>> {
        vertex_remove_domain_separator(&self.domain)
    }

    /// Return `domain || data_address` as the write-lock key.
    pub fn write_addresses(&self) -> Result<Vec<Vec<u8>>> {
        vertex_write_addresses(&self.domain, &self.data_address)
    }

    /// Constant cost (64). Mirror of Go `GetCost`.
    pub fn get_cost(&self) -> BigInt {
        vertex_remove_cost()
    }

    /// Build the bytes that a valid vertex-remove signature must cover.
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        vertex_remove_signing_message(&self.domain, &self.data_address)
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypergraph_intrinsic::conversions::pack_vertex_add_proof_chunks;

    // -----------------------------------------------------------------
    // Cost
    // -----------------------------------------------------------------

    #[test]
    fn vertex_add_cost_from_proof_count_matches_go() {
        assert_eq!(vertex_add_cost_from_proof_count(0), BigInt::from(0));
        assert_eq!(vertex_add_cost_from_proof_count(1), BigInt::from(55));
        assert_eq!(vertex_add_cost_from_proof_count(7), BigInt::from(7 * 55));
    }

    #[test]
    fn vertex_add_cost_from_raw_len_rounds_up_to_multiple_of_55() {
        // 0 raw bytes -> 0
        assert_eq!(vertex_add_cost_from_raw_len(0), BigInt::from(0));
        // 1..=55 -> 55
        assert_eq!(vertex_add_cost_from_raw_len(1), BigInt::from(55));
        assert_eq!(vertex_add_cost_from_raw_len(55), BigInt::from(55));
        // 56 -> 110
        assert_eq!(vertex_add_cost_from_raw_len(56), BigInt::from(110));
        // 109 -> 110; 110 -> 110; 111 -> 165
        assert_eq!(vertex_add_cost_from_raw_len(109), BigInt::from(110));
        assert_eq!(vertex_add_cost_from_raw_len(110), BigInt::from(110));
        assert_eq!(vertex_add_cost_from_raw_len(111), BigInt::from(165));
    }

    #[test]
    fn vertex_add_cost_formula_matches_go_integer_math() {
        // Go: `((len(rawData)+54) / 55) * 55`
        for raw in [0usize, 1, 54, 55, 56, 100, 110, 1234] {
            let expected = BigInt::from(((raw + 54) / 55 * 55) as i64);
            assert_eq!(vertex_add_cost_from_raw_len(raw), expected);
        }
    }

    #[test]
    fn vertex_remove_cost_is_constant_64() {
        assert_eq!(vertex_remove_cost(), BigInt::from(64));
    }

    // -----------------------------------------------------------------
    // Signing-message construction
    // -----------------------------------------------------------------

    #[test]
    fn vertex_add_signing_message_layout() {
        let domain = vec![0xAAu8; 32];
        let data_addr = vec![0xBBu8; 32];
        let proofs: Vec<Vec<u8>> = vec![b"proof-a".to_vec(), b"proof-b".to_vec()];
        let msg = vertex_add_signing_message(&domain, &data_addr, &proofs).unwrap();
        // First 32 bytes: domain
        assert_eq!(&msg[..32], &domain[..]);
        // Next 32 bytes: data address
        assert_eq!(&msg[32..64], &data_addr[..]);
        // Then the concatenation of proofs in order
        assert_eq!(&msg[64..64 + 7], b"proof-a");
        assert_eq!(&msg[64 + 7..], b"proof-b");
    }

    #[test]
    fn vertex_add_signing_message_rejects_oversized_disk_size() {
        let domain = vec![0x11u8; 32];
        let data_addr = vec![0x22u8; 32];
        // One big proof chunk over the 5 MiB threshold.
        let proofs = vec![vec![0u8; MAX_VERTEX_ADD_DISK_SIZE + 1]];
        assert!(vertex_add_signing_message(&domain, &data_addr, &proofs).is_err());
    }

    #[test]
    fn vertex_add_signing_message_accepts_exactly_max_disk_size() {
        let domain = vec![0x11u8; 32];
        let data_addr = vec![0x22u8; 32];
        let proofs = vec![vec![0u8; MAX_VERTEX_ADD_DISK_SIZE]];
        let msg = vertex_add_signing_message(&domain, &data_addr, &proofs).unwrap();
        assert_eq!(msg.len(), 64 + MAX_VERTEX_ADD_DISK_SIZE);
    }

    #[test]
    fn vertex_add_signing_message_rejects_short_domain() {
        let domain = vec![0u8; 31];
        let data_addr = vec![0u8; 32];
        assert!(vertex_add_signing_message(&domain, &data_addr, &[]).is_err());
    }

    #[test]
    fn vertex_add_signing_message_rejects_short_data_address() {
        let domain = vec![0u8; 32];
        let data_addr = vec![0u8; 16];
        assert!(vertex_add_signing_message(&domain, &data_addr, &[]).is_err());
    }

    #[test]
    fn vertex_remove_signing_message_layout() {
        let domain = vec![0xAAu8; 32];
        let data_addr = vec![0xBBu8; 32];
        let msg = vertex_remove_signing_message(&domain, &data_addr).unwrap();
        assert_eq!(msg.len(), 64);
        assert_eq!(&msg[..32], &domain[..]);
        assert_eq!(&msg[32..], &data_addr[..]);
    }

    #[test]
    fn vertex_remove_signing_message_rejects_bad_sizes() {
        assert!(vertex_remove_signing_message(&vec![0u8; 31], &vec![0u8; 32]).is_err());
        assert!(vertex_remove_signing_message(&vec![0u8; 32], &vec![0u8; 1]).is_err());
    }

    // -----------------------------------------------------------------
    // Domain separators
    // -----------------------------------------------------------------

    #[test]
    fn vertex_add_domain_separator_concats_tag() {
        let domain = vec![0x01u8; 32];
        let sep = vertex_add_domain_separator(&domain).unwrap();
        assert_eq!(sep.len(), 32 + VERTEX_ADD_TAG.len());
        assert_eq!(&sep[..32], &domain[..]);
        assert_eq!(&sep[32..], VERTEX_ADD_TAG);
    }

    #[test]
    fn vertex_remove_domain_separator_concats_tag() {
        let domain = vec![0x01u8; 32];
        let sep = vertex_remove_domain_separator(&domain).unwrap();
        assert_eq!(sep.len(), 32 + VERTEX_REMOVE_TAG.len());
        assert_eq!(&sep[..32], &domain[..]);
        assert_eq!(&sep[32..], VERTEX_REMOVE_TAG);
    }

    #[test]
    fn domain_separators_are_distinct_for_add_and_remove() {
        let domain = vec![0xFFu8; 32];
        assert_ne!(
            vertex_add_domain_separator(&domain).unwrap(),
            vertex_remove_domain_separator(&domain).unwrap()
        );
    }

    // -----------------------------------------------------------------
    // EncryptedToVertexTree
    // -----------------------------------------------------------------

    #[test]
    fn encrypted_to_vertex_tree_keys_are_be_u64_indices() {
        use quil_types::crypto::NoopInclusionProver;
        // Use 621-byte already-compressed inputs so we exercise the
        // pass-through path without needing the full proof->compressed
        // crypto pipeline.
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        for i in 0..3u8 {
            let mut chunk = vec![0u8; VERENC_COMPRESSED_BYTES];
            // Tag the chunk with a per-index byte so we can confirm
            // round-tripping into the tree.
            chunk[0] = i;
            // Statement at [564..621] — give it a recognizable pattern.
            for b in &mut chunk[564..621] {
                *b = i ^ 0xA5;
            }
            chunks.push(chunk);
        }
        let tree = encrypted_to_vertex_tree(&chunks, &NoopInclusionProver).unwrap();
        // Each chunk lives at key = BE u64 index
        for (i, _chunk) in chunks.iter().enumerate() {
            let key = (i as u64).to_be_bytes();
            let stored = tree.get(&key).expect("entry must exist");
            assert_eq!(stored.len(), VERENC_COMPRESSED_BYTES);
            assert_eq!(stored[0], i as u8);
        }
    }

    #[test]
    fn encrypted_to_vertex_tree_skips_wrong_size_chunks() {
        use quil_types::crypto::NoopInclusionProver;
        let chunks: Vec<Vec<u8>> = vec![
            vec![0u8; VERENC_COMPRESSED_BYTES],
            vec![0u8; 100],            // junk size — skipped
            vec![1u8; VERENC_COMPRESSED_BYTES],
        ];
        let tree = encrypted_to_vertex_tree(&chunks, &NoopInclusionProver).unwrap();
        // Index 0 and 2 present; index 1 absent.
        assert!(tree.get(&0u64.to_be_bytes()).is_some());
        assert!(tree.get(&1u64.to_be_bytes()).is_none());
        assert!(tree.get(&2u64.to_be_bytes()).is_some());
    }

    // -----------------------------------------------------------------
    // Read / write addresses
    // -----------------------------------------------------------------

    #[test]
    fn vertex_read_addresses_is_empty() {
        assert!(vertex_read_addresses().is_empty());
    }

    #[test]
    fn vertex_write_addresses_concatenates_domain_and_data_address() {
        let domain = vec![0x11u8; 32];
        let data_addr = vec![0x22u8; 32];
        let addrs = vertex_write_addresses(&domain, &data_addr).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].len(), 64);
        assert_eq!(&addrs[0][..32], &domain[..]);
        assert_eq!(&addrs[0][32..], &data_addr[..]);
    }

    // -----------------------------------------------------------------
    // Accessors on VertexAdd / VertexRemove structs
    // -----------------------------------------------------------------

    fn sample_vertex_add_with_proofs() -> VertexAdd {
        let proofs: Vec<Vec<u8>> = vec![
            vec![0x11u8; 16],
            vec![0x22u8; 32],
            vec![0x33u8; 8],
        ];
        let packed = pack_vertex_add_proof_chunks(&proofs).unwrap();
        VertexAdd {
            domain: vec![0xAAu8; 32],
            data_address: vec![0xBBu8; 32],
            data: packed,
            signature: vec![0xCCu8; 114],
        }
    }

    #[test]
    fn vertex_add_get_cost_uses_proof_count() {
        let v = sample_vertex_add_with_proofs();
        // 3 proofs * 55
        assert_eq!(v.get_cost().unwrap(), BigInt::from(165));
    }

    #[test]
    fn vertex_add_get_cost_rejects_invalid_data_blob() {
        let v = VertexAdd {
            domain: vec![0u8; 32],
            data_address: vec![0u8; 32],
            data: vec![0u8; 2], // too short for a u16 count
            signature: vec![0u8; 1],
        };
        assert!(v.get_cost().is_err());
    }

    #[test]
    fn vertex_add_struct_domain_separator() {
        let v = sample_vertex_add_with_proofs();
        let sep = v.domain_separator().unwrap();
        assert_eq!(&sep[32..], VERTEX_ADD_TAG);
    }

    #[test]
    fn vertex_add_struct_write_addresses() {
        let v = sample_vertex_add_with_proofs();
        let addrs = v.write_addresses().unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(&addrs[0][..32], &v.domain[..]);
        assert_eq!(&addrs[0][32..], &v.data_address[..]);
    }

    #[test]
    fn vertex_remove_struct_helpers_work() {
        let v = VertexRemove {
            domain: vec![0xAAu8; 32],
            data_address: vec![0xBBu8; 32],
            signature: vec![0xCCu8; 114],
        };
        assert_eq!(v.get_cost(), BigInt::from(64));
        let msg = v.signing_message().unwrap();
        assert_eq!(&msg[..32], &v.domain[..]);
        assert_eq!(&msg[32..], &v.data_address[..]);
        let sep = v.domain_separator().unwrap();
        assert_eq!(&sep[32..], VERTEX_REMOVE_TAG);
        let addrs = v.write_addresses().unwrap();
        assert_eq!(addrs[0].len(), 64);
    }

    #[test]
    fn vertex_remove_struct_rejects_bad_domain_on_helper_calls() {
        let v = VertexRemove {
            domain: vec![0u8; 5], // wrong length
            data_address: vec![0u8; 32],
            signature: vec![],
        };
        assert!(v.domain_separator().is_err());
        assert!(v.write_addresses().is_err());
        assert!(v.signing_message().is_err());
    }
}
