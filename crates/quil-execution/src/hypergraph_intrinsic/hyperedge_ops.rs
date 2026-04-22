//! Hyperedge add/remove intrinsic operations. Port of
//! `node/execution/intrinsics/hypergraph/hypergraph_hyperedge_add.go`
//! and `hypergraph_hyperedge_remove.go`.
//!
//! Scope (same shape as `vertex_ops.rs`):
//!
//! - Pure cost calculation (`get_cost`)
//! - Hyperedge ID extraction (`extract_hyperedge_id`)
//! - Signing-message layout (`hyperedge_add_signing_message`, `hyperedge_remove_signing_message`)
//! - Domain-separator tags (`HYPEREDGE_ADD_TAG`, `HYPEREDGE_REMOVE_TAG`)
//! - Write-address computation
//!
//! The `Value` field on the canonical-bytes `HyperedgeAdd`/`HyperedgeRemove`
//! is the *serialized hyperedge atom*:
//!
//! ```text
//! [u8 type = 0x01] [32 bytes app_address] [32 bytes data_address] [variable serialized tree]
//! ```
//!
//! Mirror of Go `hypergraph.hyperedge::ToBytes` in
//! `hypergraph/hyperedge.go:59`. The hyperedge ID is
//! `app_address || data_address` (64 bytes), which occupies bytes 1..65
//! of the serialized atom. The extrinsic tree (`bytes[65..]`) is
//! opaque here — actually computing its commitment requires the
//! lazy-tree integration (task #64).
//!
//! Services NOT ported (same reason as `vertex_ops.rs`):
//! - `prove` — needs signer, inclusion prover for commitment
//! - `verify` — needs key manager, inclusion prover
//! - `materialize` — needs hypergraph state bridge

use num_bigint::BigInt;
use quil_types::error::{QuilError, Result};

use super::types::{HyperedgeAdd, HyperedgeRemove};

// =====================================================================
// Constants
// =====================================================================

/// Type-marker byte for a hyperedge atom. Go: `[]byte{0x01}` prefix.
pub const HYPEREDGE_ATOM_TYPE_BYTE: u8 = 0x01;

/// Domain separator suffix for hyperedge-add signatures.
pub const HYPEREDGE_ADD_TAG: &[u8] = b"HYPEREDGE_ADD";
/// Domain separator suffix for hyperedge-remove signatures.
pub const HYPEREDGE_REMOVE_TAG: &[u8] = b"HYPEREDGE_REMOVE";

/// Cost of a hyperedge-remove operation. Go:
/// `HyperedgeRemove::GetCost → big.NewInt(64)`.
pub const HYPEREDGE_REMOVE_COST: i64 = 64;

pub fn hyperedge_remove_cost() -> BigInt {
    BigInt::from(HYPEREDGE_REMOVE_COST)
}

/// HyperedgeAdd cost is `value.GetSize()` — the atom count under the
/// extrinsic tree. Callers that already know the count (e.g. from the
/// lazy-tree dispatcher) can use this wrapper.
pub fn hyperedge_add_cost_from_atom_count(atom_count: u64) -> BigInt {
    BigInt::from(atom_count)
}

// =====================================================================
// Hyperedge ID extraction
// =====================================================================

/// Minimum valid hyperedge-atom byte length: type(1) + app(32) + data(32).
pub const HYPEREDGE_MIN_VALUE_LEN: usize = 1 + 32 + 32;

/// Byte offset of the hyperedge ID inside a serialized hyperedge atom.
pub const HYPEREDGE_ID_OFFSET: usize = 1;

/// Length of a hyperedge ID (app_address || data_address).
pub const HYPEREDGE_ID_LEN: usize = 64;

/// Extract the 64-byte hyperedge ID from a serialized hyperedge atom.
/// Does not parse the trailing extrinsic tree.
///
/// Returns `Err` if:
/// - `value` is shorter than 65 bytes
/// - `value[0] != 0x01` (not a hyperedge atom — probably a vertex)
pub fn extract_hyperedge_id(value: &[u8]) -> Result<[u8; HYPEREDGE_ID_LEN]> {
    if value.len() < HYPEREDGE_MIN_VALUE_LEN {
        return Err(QuilError::InvalidArgument(format!(
            "hyperedge id: value too short ({} < {})",
            value.len(),
            HYPEREDGE_MIN_VALUE_LEN
        )));
    }
    if value[0] != HYPEREDGE_ATOM_TYPE_BYTE {
        return Err(QuilError::InvalidArgument(format!(
            "hyperedge id: unexpected atom type byte 0x{:02x}",
            value[0]
        )));
    }
    let mut id = [0u8; HYPEREDGE_ID_LEN];
    id.copy_from_slice(
        &value[HYPEREDGE_ID_OFFSET..HYPEREDGE_ID_OFFSET + HYPEREDGE_ID_LEN],
    );
    Ok(id)
}

/// Slice view of the 32-byte app_address portion of a hyperedge ID.
pub fn hyperedge_id_app_address(id: &[u8; HYPEREDGE_ID_LEN]) -> &[u8] {
    &id[..32]
}

/// Slice view of the 32-byte data_address portion of a hyperedge ID.
pub fn hyperedge_id_data_address(id: &[u8; HYPEREDGE_ID_LEN]) -> &[u8] {
    &id[32..]
}

// =====================================================================
// Domain separators
// =====================================================================

pub fn hyperedge_add_domain_separator(domain: &[u8]) -> Result<Vec<u8>> {
    if domain.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "hyperedge add domain separator: invalid domain length".into(),
        ));
    }
    let mut out = Vec::with_capacity(32 + HYPEREDGE_ADD_TAG.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(HYPEREDGE_ADD_TAG);
    Ok(out)
}

pub fn hyperedge_remove_domain_separator(domain: &[u8]) -> Result<Vec<u8>> {
    if domain.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "hyperedge remove domain separator: invalid domain length".into(),
        ));
    }
    let mut out = Vec::with_capacity(32 + HYPEREDGE_REMOVE_TAG.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(HYPEREDGE_REMOVE_TAG);
    Ok(out)
}

// =====================================================================
// Signing-message layouts
// =====================================================================

/// Build the hyperedge-add signing message. Go layout:
/// `hyperedgeID[:64] || commit`
pub fn hyperedge_add_signing_message(
    hyperedge_id: &[u8; HYPEREDGE_ID_LEN],
    commit: &[u8],
) -> Result<Vec<u8>> {
    if commit.is_empty() {
        return Err(QuilError::InvalidArgument(
            "hyperedge add signing message: empty commitment".into(),
        ));
    }
    let mut msg = Vec::with_capacity(HYPEREDGE_ID_LEN + commit.len());
    msg.extend_from_slice(hyperedge_id);
    msg.extend_from_slice(commit);
    Ok(msg)
}

/// Build the hyperedge-remove signing message. Go layout:
/// `hyperedgeID[:64]` (no commitment).
pub fn hyperedge_remove_signing_message(
    hyperedge_id: &[u8; HYPEREDGE_ID_LEN],
) -> Vec<u8> {
    hyperedge_id.to_vec()
}

// =====================================================================
// Write address helper
// =====================================================================

/// Hyperedge ops never declare read addresses. Matches Go `(nil, nil)`.
pub fn hyperedge_read_addresses() -> Vec<Vec<u8>> {
    Vec::new()
}

/// Go: `slices.Concat(h.Domain[:], hyperedgeID[32:])` — i.e. `domain ||
/// data_address`. Note that the domain must equal `hyperedgeID[:32]`
/// (the app address) — the validate helpers below enforce that; this
/// pure function just assembles the bytes.
pub fn hyperedge_write_addresses(
    domain: &[u8],
    hyperedge_id: &[u8; HYPEREDGE_ID_LEN],
) -> Result<Vec<Vec<u8>>> {
    if domain.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "hyperedge write addresses: invalid domain length".into(),
        ));
    }
    let mut concat = Vec::with_capacity(64);
    concat.extend_from_slice(domain);
    concat.extend_from_slice(hyperedge_id_data_address(hyperedge_id));
    Ok(vec![concat])
}

// =====================================================================
// Domain / hyperedge-id cross-check
// =====================================================================
//
// Go `Verify` refuses a hyperedge whose `hyperedgeID[:32]` doesn't
// match the operation's `Domain`. We surface the same check here so
// the dispatcher can call it before handing bytes to a key manager.

pub fn assert_hyperedge_domain_matches(
    domain: &[u8],
    hyperedge_id: &[u8; HYPEREDGE_ID_LEN],
) -> Result<()> {
    if domain.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "hyperedge domain check: invalid domain length".into(),
        ));
    }
    if domain != hyperedge_id_app_address(hyperedge_id) {
        return Err(QuilError::InvalidArgument(
            "hyperedge domain check: hyperedge domain mismatch".into(),
        ));
    }
    Ok(())
}

// =====================================================================
// Convenience accessors on the canonical-bytes structs
// =====================================================================

impl HyperedgeAdd {
    /// Extract the hyperedge ID by parsing `self.value`. Does not
    /// touch the trailing extrinsic tree bytes.
    pub fn hyperedge_id(&self) -> Result<[u8; HYPEREDGE_ID_LEN]> {
        extract_hyperedge_id(&self.value)
    }

    pub fn domain_separator(&self) -> Result<Vec<u8>> {
        hyperedge_add_domain_separator(&self.domain)
    }

    pub fn write_addresses(&self) -> Result<Vec<Vec<u8>>> {
        let id = self.hyperedge_id()?;
        hyperedge_write_addresses(&self.domain, &id)
    }

    /// Sanity-check that the domain matches the hyperedge ID's app
    /// address. The Go `Verify` path rejects mismatches.
    pub fn check_domain(&self) -> Result<()> {
        let id = self.hyperedge_id()?;
        assert_hyperedge_domain_matches(&self.domain, &id)
    }

    /// Build the bytes a valid signature must cover, given the
    /// already-computed extrinsic-tree commitment. We can't compute
    /// `commit` yet — that requires quil-tries lazy integration —
    /// so the dispatcher threads it in.
    pub fn signing_message(&self, commit: &[u8]) -> Result<Vec<u8>> {
        let id = self.hyperedge_id()?;
        hyperedge_add_signing_message(&id, commit)
    }

    /// HyperedgeAdd cost depends on the atom count in the extrinsic
    /// tree, which we can't decode yet. The dispatcher passes this in
    /// from its own parse of `value[65..]`.
    pub fn get_cost_with_atom_count(&self, atom_count: u64) -> BigInt {
        hyperedge_add_cost_from_atom_count(atom_count)
    }
}

impl HyperedgeRemove {
    pub fn hyperedge_id(&self) -> Result<[u8; HYPEREDGE_ID_LEN]> {
        extract_hyperedge_id(&self.value)
    }

    pub fn domain_separator(&self) -> Result<Vec<u8>> {
        hyperedge_remove_domain_separator(&self.domain)
    }

    pub fn write_addresses(&self) -> Result<Vec<Vec<u8>>> {
        let id = self.hyperedge_id()?;
        hyperedge_write_addresses(&self.domain, &id)
    }

    pub fn check_domain(&self) -> Result<()> {
        let id = self.hyperedge_id()?;
        assert_hyperedge_domain_matches(&self.domain, &id)
    }

    pub fn signing_message(&self) -> Result<Vec<u8>> {
        let id = self.hyperedge_id()?;
        Ok(hyperedge_remove_signing_message(&id))
    }

    pub fn get_cost(&self) -> BigInt {
        hyperedge_remove_cost()
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Build a synthetic serialized-hyperedge-atom byte buffer:
    // [0x01][app(32)][data(32)][trailing_bytes]
    fn make_hyperedge_value(app: u8, data: u8, trailing: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 32 + trailing.len());
        out.push(HYPEREDGE_ATOM_TYPE_BYTE);
        out.extend_from_slice(&[app; 32]);
        out.extend_from_slice(&[data; 32]);
        out.extend_from_slice(trailing);
        out
    }

    // -----------------------------------------------------------------
    // Cost
    // -----------------------------------------------------------------

    #[test]
    fn hyperedge_remove_cost_is_constant_64() {
        assert_eq!(hyperedge_remove_cost(), BigInt::from(64));
    }

    #[test]
    fn hyperedge_add_cost_equals_atom_count() {
        assert_eq!(
            hyperedge_add_cost_from_atom_count(0),
            BigInt::from(0)
        );
        assert_eq!(
            hyperedge_add_cost_from_atom_count(42),
            BigInt::from(42)
        );
        assert_eq!(
            hyperedge_add_cost_from_atom_count(u64::MAX),
            BigInt::from(u64::MAX)
        );
    }

    // -----------------------------------------------------------------
    // extract_hyperedge_id
    // -----------------------------------------------------------------

    #[test]
    fn extract_hyperedge_id_happy_path() {
        let v = make_hyperedge_value(0xAA, 0xBB, b"trailing-tree-bytes");
        let id = extract_hyperedge_id(&v).unwrap();
        assert_eq!(&id[..32], &[0xAAu8; 32][..]);
        assert_eq!(&id[32..], &[0xBBu8; 32][..]);
    }

    #[test]
    fn extract_hyperedge_id_rejects_too_short_value() {
        // Only the type byte + 1 — well below 65-byte minimum.
        let v = vec![HYPEREDGE_ATOM_TYPE_BYTE, 0];
        assert!(extract_hyperedge_id(&v).is_err());
    }

    #[test]
    fn extract_hyperedge_id_rejects_wrong_type_byte() {
        // 0x00 = vertex atom type — must be rejected.
        let mut v = make_hyperedge_value(0x11, 0x22, b"");
        v[0] = 0x00;
        assert!(extract_hyperedge_id(&v).is_err());
    }

    #[test]
    fn extract_hyperedge_id_accepts_minimum_length() {
        // Exactly 65 bytes with no trailing tree.
        let v = make_hyperedge_value(0x11, 0x22, b"");
        let id = extract_hyperedge_id(&v).unwrap();
        assert_eq!(id.len(), 64);
    }

    #[test]
    fn hyperedge_id_app_and_data_slices() {
        let v = make_hyperedge_value(0xA0, 0xB0, b"");
        let id = extract_hyperedge_id(&v).unwrap();
        assert_eq!(hyperedge_id_app_address(&id), &[0xA0u8; 32][..]);
        assert_eq!(hyperedge_id_data_address(&id), &[0xB0u8; 32][..]);
    }

    // -----------------------------------------------------------------
    // Domain separators
    // -----------------------------------------------------------------

    #[test]
    fn hyperedge_add_domain_separator_concats_tag() {
        let d = vec![0x01u8; 32];
        let sep = hyperedge_add_domain_separator(&d).unwrap();
        assert_eq!(&sep[..32], &d[..]);
        assert_eq!(&sep[32..], HYPEREDGE_ADD_TAG);
    }

    #[test]
    fn hyperedge_remove_domain_separator_concats_tag() {
        let d = vec![0x01u8; 32];
        let sep = hyperedge_remove_domain_separator(&d).unwrap();
        assert_eq!(&sep[..32], &d[..]);
        assert_eq!(&sep[32..], HYPEREDGE_REMOVE_TAG);
    }

    #[test]
    fn hyperedge_add_and_remove_separators_are_distinct() {
        let d = vec![0x02u8; 32];
        assert_ne!(
            hyperedge_add_domain_separator(&d).unwrap(),
            hyperedge_remove_domain_separator(&d).unwrap()
        );
    }

    #[test]
    fn hyperedge_separators_reject_bad_domain() {
        assert!(hyperedge_add_domain_separator(&[0u8; 16]).is_err());
        assert!(hyperedge_remove_domain_separator(&[0u8; 16]).is_err());
    }

    // -----------------------------------------------------------------
    // Signing-message layout
    // -----------------------------------------------------------------

    #[test]
    fn hyperedge_add_signing_message_layout() {
        let mut id = [0u8; HYPEREDGE_ID_LEN];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8;
        }
        let commit = vec![0xFFu8; 74];
        let msg = hyperedge_add_signing_message(&id, &commit).unwrap();
        assert_eq!(msg.len(), HYPEREDGE_ID_LEN + commit.len());
        assert_eq!(&msg[..HYPEREDGE_ID_LEN], &id[..]);
        assert_eq!(&msg[HYPEREDGE_ID_LEN..], &commit[..]);
    }

    #[test]
    fn hyperedge_add_signing_message_rejects_empty_commit() {
        let id = [0u8; HYPEREDGE_ID_LEN];
        assert!(hyperedge_add_signing_message(&id, &[]).is_err());
    }

    #[test]
    fn hyperedge_remove_signing_message_is_just_the_id() {
        let mut id = [0u8; HYPEREDGE_ID_LEN];
        id[5] = 0xFF;
        let msg = hyperedge_remove_signing_message(&id);
        assert_eq!(msg.len(), HYPEREDGE_ID_LEN);
        assert_eq!(&msg[..], &id[..]);
    }

    // -----------------------------------------------------------------
    // Write addresses
    // -----------------------------------------------------------------

    #[test]
    fn hyperedge_write_addresses_concat_domain_and_data_address() {
        let d = vec![0xCCu8; 32];
        let v = make_hyperedge_value(0xCC, 0xDD, b"");
        let id = extract_hyperedge_id(&v).unwrap();
        let addrs = hyperedge_write_addresses(&d, &id).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].len(), 64);
        assert_eq!(&addrs[0][..32], &d[..]);
        assert_eq!(&addrs[0][32..], &[0xDDu8; 32][..]);
    }

    #[test]
    fn hyperedge_write_addresses_rejects_bad_domain() {
        let id = [0u8; HYPEREDGE_ID_LEN];
        assert!(hyperedge_write_addresses(&[0u8; 5], &id).is_err());
    }

    #[test]
    fn hyperedge_read_addresses_is_empty() {
        assert!(hyperedge_read_addresses().is_empty());
    }

    // -----------------------------------------------------------------
    // Domain cross-check
    // -----------------------------------------------------------------

    #[test]
    fn assert_domain_matches_ok_when_app_address_equals_domain() {
        let d = vec![0xABu8; 32];
        let v = make_hyperedge_value(0xAB, 0xCD, b"");
        let id = extract_hyperedge_id(&v).unwrap();
        assert!(assert_hyperedge_domain_matches(&d, &id).is_ok());
    }

    #[test]
    fn assert_domain_matches_fails_on_mismatch() {
        let d = vec![0xABu8; 32];
        let v = make_hyperedge_value(0x00, 0xCD, b"");
        let id = extract_hyperedge_id(&v).unwrap();
        assert!(assert_hyperedge_domain_matches(&d, &id).is_err());
    }

    #[test]
    fn assert_domain_matches_rejects_bad_domain_length() {
        let id = [0u8; HYPEREDGE_ID_LEN];
        assert!(assert_hyperedge_domain_matches(&[0u8; 16], &id).is_err());
    }

    // -----------------------------------------------------------------
    // Struct accessors
    // -----------------------------------------------------------------

    #[test]
    fn hyperedge_add_struct_helpers() {
        let v = make_hyperedge_value(0xE0, 0xF0, b"tree-bytes");
        let h = HyperedgeAdd {
            domain: vec![0xE0u8; 32],
            value: v,
            signature: vec![0x11u8; 114],
        };
        assert!(h.check_domain().is_ok());
        let id = h.hyperedge_id().unwrap();
        assert_eq!(&id[..32], &[0xE0u8; 32][..]);
        assert_eq!(&id[32..], &[0xF0u8; 32][..]);

        let sep = h.domain_separator().unwrap();
        assert_eq!(&sep[32..], HYPEREDGE_ADD_TAG);

        let addrs = h.write_addresses().unwrap();
        assert_eq!(addrs[0].len(), 64);
        assert_eq!(&addrs[0][..32], &h.domain[..]);
        assert_eq!(&addrs[0][32..], &[0xF0u8; 32][..]);

        let msg = h.signing_message(&[0xAAu8; 74]).unwrap();
        assert_eq!(msg.len(), 64 + 74);

        assert_eq!(h.get_cost_with_atom_count(5), BigInt::from(5));
    }

    #[test]
    fn hyperedge_add_struct_check_domain_fails_on_mismatch() {
        let v = make_hyperedge_value(0xA0, 0xB0, b"");
        let h = HyperedgeAdd {
            domain: vec![0x00u8; 32], // different from app_address
            value: v,
            signature: vec![],
        };
        assert!(h.check_domain().is_err());
    }

    #[test]
    fn hyperedge_remove_struct_helpers() {
        let v = make_hyperedge_value(0xA1, 0xA2, b"");
        let h = HyperedgeRemove {
            domain: vec![0xA1u8; 32],
            value: v,
            signature: vec![0x22u8; 114],
        };
        assert!(h.check_domain().is_ok());
        assert_eq!(h.get_cost(), BigInt::from(64));
        let msg = h.signing_message().unwrap();
        assert_eq!(msg.len(), HYPEREDGE_ID_LEN);
        let sep = h.domain_separator().unwrap();
        assert_eq!(&sep[32..], HYPEREDGE_REMOVE_TAG);
        let addrs = h.write_addresses().unwrap();
        assert_eq!(addrs[0].len(), 64);
    }

    #[test]
    fn hyperedge_remove_struct_rejects_invalid_value() {
        let h = HyperedgeRemove {
            domain: vec![0u8; 32],
            value: vec![0x00u8; 65], // wrong type byte
            signature: vec![],
        };
        assert!(h.hyperedge_id().is_err());
        assert!(h.signing_message().is_err());
        assert!(h.write_addresses().is_err());
        assert!(h.check_domain().is_err());
    }
}
