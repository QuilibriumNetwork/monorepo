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
//! neither of which have a clean trait bound on the execution side yet.
//! - `verify` — same dependency story plus an Ed448 key-manager trait.
//! - `materialize` — requires the hypergraph state bridge
//! (`HypergraphCrdt` lazy-tree integration).
//!
//! The intrinsic dispatcher will import these pure helpers
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
pub const CONFIDENTIAL_FIELD_CHARGE_BYTES: i64 = 55;

/// Upper bound on vertex-add disk payload. Go:
/// `if diskSize > 1024*1024*5 { return error }`
pub const MAX_VERTEX_ADD_DISK_SIZE: usize = 5 * 1024 * 1024;

// =====================================================================
// Confidential vertex fields (commit-and-encrypt, post-quantum)
// =====================================================================

use super::confidential;

/// Verify each confidential field's STRUCTURE — the public/consensus check that
/// replaces the retired ECC verenc per-proof crypto verify. The commit-and-encrypt
/// scheme has no public recoverability proof: consensus confirms the field is
/// well-formed (decodes; correct KEM/AEAD sizes) and binds its 32-byte commitment
/// by storing it in committed state; the designated reader verifies decryption
/// against that commitment. Rejects any chunk that fails to decode or is
/// structurally invalid (so malformed fields can't corrupt the tree).
pub fn verify_vertex_add_proofs(proofs: &[Vec<u8>]) -> Result<()> {
    for (i, chunk) in proofs.iter().enumerate() {
        let field = confidential::decode(chunk).ok_or_else(|| {
            QuilError::InvalidArgument(format!(
                "VertexAdd: confidential field {} failed to decode", i
            ))
        })?;
        if !confidential::verify_structural(&field) {
            return Err(QuilError::InvalidArgument(format!(
                "VertexAdd: confidential field {} is structurally invalid", i
            )));
        }
    }
    Ok(())
}

/// Build a `VertexAdd.Data` vertex tree from the confidential-field chunk list.
/// Each field is stored (canonically re-encoded) at key `BE u64 index`, with its
/// 32-byte commitment as the leaf "statement" so the commitment is bound in
/// committed state (the reader checks recovered plaintext against it). Malformed
/// chunks are skipped — `verify_vertex_add_proofs` already gated them at validate.
pub fn encrypted_to_vertex_tree(
    proofs: &[Vec<u8>],
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    for (i, chunk) in proofs.iter().enumerate() {
        let field = match confidential::decode(chunk) {
            Some(f) => f,
            None => continue,
        };
        let value = confidential::encode(&field);
        let key = (i as u64).to_be_bytes();
        tree.insert(&key, &value, &field.commitment, &BigInt::from(value.len() as i64))
            .map_err(|e| QuilError::Internal(format!("vertex tree insert: {}", e)))?;
    }
    Ok(tree)
}

/// Reconstruct the original plaintext bytes from a serialized Go-format vertex
/// sub-tree (`GetVertexData{full_data}` `raw_data`) using the reader's sntrup761
/// secret key. Inverse of [`encrypted_to_vertex_tree`] + decryption: read the
/// sequential 8-byte-BE-indexed confidential fields (0,1,2,…) until a gap,
/// decode+open each with `reader_kem_sk`, and concatenate. Mirror of Go
/// `VertexTreeToEncrypted` + `verEnc.Decrypt` (`types/hypergraph/vertex_data.go`).
///
/// Used by the client's `deploy get` to reassemble a deployed file (and its
/// `FILEINDX` index) from the node.
pub fn vertex_tree_to_plaintext(raw_tree: &[u8], reader_kem_sk: &[u8]) -> Result<Vec<u8>> {
    let root = quil_tries::deserialize_go_tree(raw_tree)
        .map_err(|e| QuilError::InvalidArgument(format!("deserialize vertex tree: {e}")))?;
    let tree = quil_tries::VectorCommitmentTree { root };
    let mut out = Vec::new();
    let mut index: u64 = 0;
    loop {
        let key = index.to_be_bytes();
        let Some(value) = tree.get(&key) else { break };
        let field = confidential::decode(value).ok_or_else(|| {
            QuilError::InvalidArgument(format!(
                "vertex tree to plaintext: field {index} is not a valid confidential field"
            ))
        })?;
        let pt = confidential::open(&field, reader_kem_sk).ok_or_else(|| {
            QuilError::InvalidArgument(format!(
                "vertex tree to plaintext: could not open field {index} (wrong read key?)"
            ))
        })?;
        out.extend_from_slice(&pt);
        index += 1;
    }
    Ok(out)
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
    BigInt::from(proof_count as i64 * CONFIDENTIAL_FIELD_CHARGE_BYTES)
}

/// Compute the vertex-add cost from raw (unencrypted) data. Mirror of
/// the `h.Data == nil && h.rawData != nil` branch in Go:
/// `((len(rawData) + 54) / 55) * 55` — the raw-bytes length rounded up
/// to the next multiple of 55.
pub fn vertex_add_cost_from_raw_len(raw_len: usize) -> BigInt {
    let chunks = (raw_len + (CONFIDENTIAL_FIELD_CHARGE_BYTES as usize - 1))
        / CONFIDENTIAL_FIELD_CHARGE_BYTES as usize;
    BigInt::from(chunks as i64 * CONFIDENTIAL_FIELD_CHARGE_BYTES)
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

    fn sample_confidential_chunk(reader_pk: &[u8], tag: u8, data: &[u8]) -> Vec<u8> {
        let field = super::super::confidential::seal(data, reader_pk, &[tag; 32], &[tag; 12])
            .expect("seal");
        super::super::confidential::encode(&field)
    }

    #[test]
    fn encrypted_to_vertex_tree_keys_are_be_u64_indices() {
        let kp = quil_crypto::sntrup761::Sntrup761KeyPair::generate();
        let chunks: Vec<Vec<u8>> =
            (0..3u8).map(|i| sample_confidential_chunk(&kp.public, i, &[i; 16])).collect();
        let tree = encrypted_to_vertex_tree(&chunks).unwrap();
        for (i, chunk) in chunks.iter().enumerate() {
            let key = (i as u64).to_be_bytes();
            let stored = tree.get(&key).expect("entry must exist");
            // Stored verbatim (canonical decode→re-encode is the identity).
            assert_eq!(&stored, chunk);
        }
    }

    #[test]
    fn vertex_tree_to_plaintext_reassembles_sealed_chunks() {
        let kp = quil_crypto::sntrup761::Sntrup761KeyPair::generate();
        // Three sealed slices whose concatenation is the "file".
        let parts: [&[u8]; 3] = [b"hello ", b"lattice ", b"world"];
        let chunks: Vec<Vec<u8>> = parts
            .iter()
            .enumerate()
            .map(|(i, p)| sample_confidential_chunk(&kp.public, i as u8, p))
            .collect();
        let mut tree = encrypted_to_vertex_tree(&chunks).unwrap();
        // The reconstruction path consumes the serialized Go-format tree, so
        // exercise the real serialize→deserialize round trip.
        let _ = tree.commit(&quil_tries::ShaInclusionProver);
        let raw = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();

        let out = vertex_tree_to_plaintext(&raw, &kp.secret).unwrap();
        assert_eq!(out, b"hello lattice world");
    }

    #[test]
    fn vertex_tree_to_plaintext_wrong_key_fails() {
        let kp = quil_crypto::sntrup761::Sntrup761KeyPair::generate();
        let other = quil_crypto::sntrup761::Sntrup761KeyPair::generate();
        let chunks = vec![sample_confidential_chunk(&kp.public, 0, b"secret")];
        let mut tree = encrypted_to_vertex_tree(&chunks).unwrap();
        let _ = tree.commit(&quil_tries::ShaInclusionProver);
        let raw = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        assert!(vertex_tree_to_plaintext(&raw, &other.secret).is_err());
    }

    #[test]
    fn encrypted_to_vertex_tree_skips_undecodable_chunks() {
        let kp = quil_crypto::sntrup761::Sntrup761KeyPair::generate();
        let chunks: Vec<Vec<u8>> = vec![
            sample_confidential_chunk(&kp.public, 0, b"a"),
            vec![0u8; 100], // junk — too short to decode, skipped
            sample_confidential_chunk(&kp.public, 2, b"b"),
        ];
        let tree = encrypted_to_vertex_tree(&chunks).unwrap();
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
