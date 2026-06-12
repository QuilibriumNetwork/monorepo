//! Canonical-bytes serialization for hypergraph messages.
//!
//! Byte-exact port of `protobufs/hypergraph.go`'s
//! `ToCanonicalBytes`/`FromCanonicalBytes` methods plus the BLS48-581
//! aggregate-signature envelope from `protobufs/keys.go`. These bytes
//! are what get signed, broadcast, and stored — they must match Go
//! output byte-for-byte for the Rust node to interoperate on the live
//! network.
//!
//! Wire format (shared by every message in this module):
//!
//! ```text
//! [u32 BE type_prefix]
//!   (for each field in proto declaration order:)
//!     [u32 BE field_len]
//!     [field_len bytes]
//! ```
//!
//! All `uint32` counts are big-endian. `bytes` fields are written as
//! (len, data); optional nested messages are written as
//! (len_of_nested_canonical_bytes, nested_canonical_bytes) where an
//! absent value is encoded as `len=0` followed by no data.
//!
//! Fixed-length fields (BLS pubkey/sig, Ed448 pubkey/sig) are
//! validated on decode where the Go reference enforces a specific
//! size; otherwise the decoder is permissive.

use super::types::{
    HyperedgeAdd, HyperedgeRemove, HypergraphConfiguration, HypergraphDeploy,
    HypergraphUpdate, VertexAdd, VertexRemove,
};
use quil_types::error::{QuilError, Result};

// =====================================================================
// Type-prefix constants
// =====================================================================
//
// These mirror `protobufs/canonical_types.go`. The hypergraph block is
// 0x0400–0x04FF; BLS48-581 key/signature envelopes live in the core
// types block at 0x0117/0x011C.

/// Hypergraph configuration (read/write/owner public keys).
pub const TYPE_HYPERGRAPH_CONFIGURATION: u32 = 0x0401;
/// Hypergraph deployment — establishes a new hypergraph shard.
pub const TYPE_HYPERGRAPH_DEPLOYMENT: u32 = 0x0402;
/// Hypergraph update — rotates config or schema.
pub const TYPE_HYPERGRAPH_UPDATE: u32 = 0x0403;
/// Vertex add.
pub const TYPE_VERTEX_ADD: u32 = 0x0404;
/// Vertex remove (tombstone).
pub const TYPE_VERTEX_REMOVE: u32 = 0x0405;
/// Hyperedge add.
pub const TYPE_HYPEREDGE_ADD: u32 = 0x0406;
/// Hyperedge remove (tombstone).
pub const TYPE_HYPEREDGE_REMOVE: u32 = 0x0407;

/// BLS48-581 G2 public key (585 bytes of key data).
pub const TYPE_BLS48581_G2_PUBLIC_KEY: u32 = 0x0117;
/// BLS48-581 aggregate signature (signature + optional pubkey + bitmask).
pub const TYPE_BLS48581_AGGREGATE_SIGNATURE: u32 = 0x011C;

// Re-use the crate-wide canonical cursor helpers.
use crate::canonical_cursor::{
    put_u32, put_lp as put_len_prefixed,
    read_u32, read_bytes, read_lp as read_len_prefixed,
};

/// Verify that `actual` matches `expected`, returning an error
/// referencing the message name if not.
fn expect_type_prefix(actual: u32, expected: u32, name: &'static str) -> Result<()> {
    if actual != expected {
        return Err(QuilError::InvalidArgument(format!(
            "{}: invalid type prefix (got 0x{:08x}, expected 0x{:08x})",
            name, actual, expected
        )));
    }
    Ok(())
}

// =====================================================================
// BLS48581 G2 public key envelope (protobufs/keys.go:801+)
// =====================================================================
//
// Format:
//   [u32 BE type_prefix = 0x0117]
//   [585 raw bytes of key_value]
//
// Note: unlike most envelopes this one does NOT write a length prefix
// for key_value — the length is fixed by validation, and decode reads
// exactly 585 bytes. The Rust side matches that exactly.

/// Rust mirror of `protobufs.BLS48581G2PublicKey`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bls48581G2PublicKey {
    /// Fixed 585-byte key value when valid.
    pub key_value: Vec<u8>,
}

impl Bls48581G2PublicKey {
    /// Canonical size of the key payload (not counting the 4-byte type prefix).
    pub const KEY_VALUE_LEN: usize = 585;

    /// Serialize. Go equivalent: `BLS48581G2PublicKey::ToCanonicalBytes`.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.key_value.len() != Self::KEY_VALUE_LEN {
            return Err(QuilError::InvalidArgument(
                "BLS48581G2PublicKey: invalid key length".into(),
            ));
        }
        let mut out = Vec::with_capacity(4 + Self::KEY_VALUE_LEN);
        put_u32(&mut out, TYPE_BLS48581_G2_PUBLIC_KEY);
        out.extend_from_slice(&self.key_value);
        Ok(out)
    }

    /// Deserialize. Go equivalent: `BLS48581G2PublicKey::FromCanonicalBytes`.
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        let type_prefix = read_u32(data, &mut cursor)?;
        expect_type_prefix(type_prefix, TYPE_BLS48581_G2_PUBLIC_KEY, "BLS48581G2PublicKey")?;
        let key_value = read_bytes(data, &mut cursor, Self::KEY_VALUE_LEN)?;
        Ok(Self { key_value })
    }
}

// =====================================================================
// BLS48581 aggregate signature envelope (protobufs/keys.go:1190+)
// =====================================================================
//
// Format:
//   [u32 BE type_prefix = 0x011C]
//   [u32 BE sig_len] [sig bytes]
//     sig_len must be 74 or (74 + 516*k) for k in 1..=64 — Go validates
//     `sigLen != 74 && (sigLen > 74+(516*64) || (sigLen-74)%516 != 0)`
//     on decode but NOT on encode; we match that behaviour.
//   [u32 BE pubkey_len] [pubkey canonical bytes]
//     pubkey_len must be 0 or 589. 589 = 4-byte type_prefix + 585 key bytes.
//   [u32 BE bitmask_len] [bitmask bytes]
//     bitmask_len must be ≤ 32 on decode.
//
// Go's `ToCanonicalBytes` writes the pubkey payload as
// `pubkey.ToCanonicalBytes()` so the nested length IS 589 (4 prefix +
// 585 data). The Rust port preserves that.

/// Rust mirror of `protobufs.BLS48581AggregateSignature`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AggregateSignature {
    /// Raw BLS48-581 aggregate signature bytes.
    pub signature: Vec<u8>,
    /// Optional aggregated G2 public key.
    pub public_key: Option<Bls48581G2PublicKey>,
    /// Bitmask of which signers are represented in the aggregate.
    /// Length ≤ 32 bytes.
    pub bitmask: Vec<u8>,
}

impl AggregateSignature {
    /// Single-signer: 74 bytes. Multi-signer: 74 + 4-byte count + N×516
    /// multi-proofs (N ≤ 64). Diverges from Go's limit — see
    /// `from_canonical_bytes`.
    const MAX_SIG_LEN: usize = 78 + 516 * 64;
    /// Decoded public key length when present — 4-byte type prefix +
    /// 585 key bytes.
    const WRAPPED_PUBKEY_LEN: usize = 4 + Bls48581G2PublicKey::KEY_VALUE_LEN;
    /// Decode limit on bitmask length (Go: `bitmaskLen > 32`).
    const MAX_BITMASK_LEN: usize = 32;

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_BLS48581_AGGREGATE_SIGNATURE);
        put_len_prefixed(&mut out, &self.signature);

        match &self.public_key {
            Some(pk) => {
                let pk_bytes = pk.to_canonical_bytes()?;
                put_len_prefixed(&mut out, &pk_bytes);
            }
            None => put_u32(&mut out, 0),
        }

        put_len_prefixed(&mut out, &self.bitmask);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        let type_prefix = read_u32(data, &mut cursor)?;
        expect_type_prefix(
            type_prefix,
            TYPE_BLS48581_AGGREGATE_SIGNATURE,
            "BLS48581AggregateSignature",
        )?;

        let sig_len = read_u32(data, &mut cursor)? as usize;
        // Wire formats: 74 (single signer) or 78 + N×516 (aggregate +
        // u32 count + N multi-proofs). Diverges from Go's canonical
        // gate, which omits the count prefix and would reject every
        // multi-prover signature its own verifier produces.
        let valid_single = sig_len == 74;
        let valid_multi = sig_len >= 78
            && sig_len <= Self::MAX_SIG_LEN
            && (sig_len - 78) % 516 == 0;
        if !valid_single && !valid_multi {
            return Err(QuilError::InvalidArgument(format!(
                "BLS48581AggregateSignature: invalid signature length {}",
                sig_len
            )));
        }
        let signature = read_bytes(data, &mut cursor, sig_len)?;

        let pubkey_len = read_u32(data, &mut cursor)? as usize;
        if pubkey_len != 0 && pubkey_len != Self::WRAPPED_PUBKEY_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "BLS48581AggregateSignature: invalid pubkey length {}",
                pubkey_len
            )));
        }
        let public_key = if pubkey_len > 0 {
            let pk_bytes = read_bytes(data, &mut cursor, pubkey_len)?;
            Some(Bls48581G2PublicKey::from_canonical_bytes(&pk_bytes)?)
        } else {
            None
        };

        let bitmask_len = read_u32(data, &mut cursor)? as usize;
        if bitmask_len > Self::MAX_BITMASK_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "BLS48581AggregateSignature: invalid bitmask length {}",
                bitmask_len
            )));
        }
        let bitmask = read_bytes(data, &mut cursor, bitmask_len)?;

        Ok(Self {
            signature,
            public_key,
            bitmask,
        })
    }
}

// =====================================================================
// HypergraphConfiguration (type 0x0401)
// =====================================================================

impl HypergraphConfiguration {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_HYPERGRAPH_CONFIGURATION);
        put_len_prefixed(&mut out, &self.read_public_key);
        put_len_prefixed(&mut out, &self.write_public_key);
        put_len_prefixed(&mut out, &self.owner_public_key);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        let type_prefix = read_u32(data, &mut cursor)?;
        expect_type_prefix(
            type_prefix,
            TYPE_HYPERGRAPH_CONFIGURATION,
            "HypergraphConfiguration",
        )?;
        let read_public_key = read_len_prefixed(data, &mut cursor)?;
        let write_public_key = read_len_prefixed(data, &mut cursor)?;

        // owner_public_key is optional — Go allocates only when
        // ownerKeyLen > 0, otherwise leaves the field nil. On the
        // Rust side an empty Vec<u8> is the same observable state.
        let owner_len = read_u32(data, &mut cursor)? as usize;
        let owner_public_key = if owner_len > 0 {
            read_bytes(data, &mut cursor, owner_len)?
        } else {
            Vec::new()
        };

        Ok(Self {
            read_public_key,
            write_public_key,
            owner_public_key,
        })
    }

    /// Validate field lengths.
    pub fn validate(&self) -> Result<()> {
        if self.read_public_key.len() != 57 {
            return Err(QuilError::InvalidArgument(
                "HypergraphConfiguration: invalid read public key length".into(),
            ));
        }
        if self.write_public_key.len() != 57 {
            return Err(QuilError::InvalidArgument(
                "HypergraphConfiguration: invalid write public key length".into(),
            ));
        }
        if !self.owner_public_key.is_empty() && self.owner_public_key.len() != 585 {
            return Err(QuilError::InvalidArgument(
                "HypergraphConfiguration: invalid owner public key length (expected 0 or 585)"
                    .into(),
            ));
        }
        Ok(())
    }
}

// =====================================================================
// HypergraphDeploy (type 0x0402)
// =====================================================================

impl HypergraphDeploy {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_HYPERGRAPH_DEPLOYMENT);

        // Go rejects nil config on encode.
        let config = self.config.as_ref().ok_or_else(|| {
            QuilError::InvalidArgument("HypergraphDeploy: nil config".into())
        })?;
        let config_bytes = config.to_canonical_bytes()?;
        put_len_prefixed(&mut out, &config_bytes);

        put_len_prefixed(&mut out, &self.rdf_schema);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        let type_prefix = read_u32(data, &mut cursor)?;
        expect_type_prefix(type_prefix, TYPE_HYPERGRAPH_DEPLOYMENT, "HypergraphDeploy")?;

        let config_bytes = read_len_prefixed(data, &mut cursor)?;
        let config = HypergraphConfiguration::from_canonical_bytes(&config_bytes)?;

        // rdf_schema: Go only allocates when schemaLen > 0.
        let schema_len = read_u32(data, &mut cursor)? as usize;
        let rdf_schema = if schema_len > 0 {
            read_bytes(data, &mut cursor, schema_len)?
        } else {
            Vec::new()
        };

        Ok(Self {
            config: Some(config),
            rdf_schema,
        })
    }

    /// Mirror of Go `HypergraphDeploy::Validate`.
    pub fn validate(&self) -> Result<()> {
        let config = self.config.as_ref().ok_or_else(|| {
            QuilError::InvalidArgument("HypergraphDeploy: nil configuration".into())
        })?;
        config.validate()
    }
}

// =====================================================================
// HypergraphUpdate (type 0x0403)
// =====================================================================

impl HypergraphUpdate {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_HYPERGRAPH_UPDATE);

        match &self.config {
            Some(c) => {
                let cb = c.to_canonical_bytes()?;
                put_len_prefixed(&mut out, &cb);
            }
            None => put_u32(&mut out, 0),
        }

        put_len_prefixed(&mut out, &self.rdf_schema);

        match &self.public_key_signature_bls48581 {
            Some(sig) => {
                let sb = sig.to_canonical_bytes()?;
                put_len_prefixed(&mut out, &sb);
            }
            None => put_u32(&mut out, 0),
        }

        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        let type_prefix = read_u32(data, &mut cursor)?;
        expect_type_prefix(type_prefix, TYPE_HYPERGRAPH_UPDATE, "HypergraphUpdate")?;

        let config_len = read_u32(data, &mut cursor)? as usize;
        let config = if config_len > 0 {
            let cb = read_bytes(data, &mut cursor, config_len)?;
            Some(HypergraphConfiguration::from_canonical_bytes(&cb)?)
        } else {
            None
        };

        let schema_len = read_u32(data, &mut cursor)? as usize;
        let rdf_schema = if schema_len > 0 {
            read_bytes(data, &mut cursor, schema_len)?
        } else {
            Vec::new()
        };

        let sig_len = read_u32(data, &mut cursor)? as usize;
        let public_key_signature_bls48581 = if sig_len > 0 {
            let sb = read_bytes(data, &mut cursor, sig_len)?;
            Some(AggregateSignature::from_canonical_bytes(&sb)?)
        } else {
            None
        };

        Ok(Self {
            config,
            rdf_schema,
            public_key_signature_bls48581,
        })
    }

    /// Mirror of Go `HypergraphUpdate::Validate`.
    pub fn validate(&self) -> Result<()> {
        if self.config.is_none() && self.rdf_schema.is_empty() {
            return Err(QuilError::InvalidArgument(
                "HypergraphUpdate: config and schema can be nil, but not both".into(),
            ));
        }
        if let Some(c) = &self.config {
            c.validate()?;
        }
        if self.public_key_signature_bls48581.is_none() {
            return Err(QuilError::InvalidArgument(
                "HypergraphUpdate: public key signature is nil".into(),
            ));
        }
        Ok(())
    }

    /// Canonical-bytes encoding with `public_key_signature_bls48581`
    /// cleared. This is the byte sequence the BLS aggregate signature
    /// covers — Go's `proto.Clone(updatePb).PublicKeySignatureBls48581
    /// = nil; updateWithoutSignature.ToCanonicalBytes()`.
    pub fn to_canonical_bytes_without_signature(&self) -> Result<Vec<u8>> {
        let mut without = self.clone();
        without.public_key_signature_bls48581 = None;
        without.to_canonical_bytes()
    }
}

// =====================================================================
// VertexAdd (type 0x0404)
// =====================================================================

impl VertexAdd {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_VERTEX_ADD);
        put_len_prefixed(&mut out, &self.domain);
        put_len_prefixed(&mut out, &self.data_address);
        put_len_prefixed(&mut out, &self.data);
        put_len_prefixed(&mut out, &self.signature);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        let type_prefix = read_u32(data, &mut cursor)?;
        expect_type_prefix(type_prefix, TYPE_VERTEX_ADD, "VertexAdd")?;
        let domain = read_len_prefixed(data, &mut cursor)?;
        let data_address = read_len_prefixed(data, &mut cursor)?;
        let data_field = read_len_prefixed(data, &mut cursor)?;
        let signature = read_len_prefixed(data, &mut cursor)?;
        Ok(Self {
            domain,
            data_address,
            data: data_field,
            signature,
        })
    }

    /// Mirror of Go `VertexAdd::Validate`.
    pub fn validate(&self) -> Result<()> {
        if self.domain.len() != 32 {
            return Err(QuilError::InvalidArgument(
                "VertexAdd: invalid domain length".into(),
            ));
        }
        if self.data_address.len() != 32 {
            return Err(QuilError::InvalidArgument(
                "VertexAdd: invalid data address length".into(),
            ));
        }
        if self.data.is_empty() {
            return Err(QuilError::InvalidArgument("VertexAdd: empty data".into()));
        }
        if self.signature.is_empty() {
            return Err(QuilError::InvalidArgument(
                "VertexAdd: empty signature".into(),
            ));
        }
        Ok(())
    }
}

// =====================================================================
// VertexRemove (type 0x0405)
// =====================================================================

impl VertexRemove {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_VERTEX_REMOVE);
        put_len_prefixed(&mut out, &self.domain);
        put_len_prefixed(&mut out, &self.data_address);
        put_len_prefixed(&mut out, &self.signature);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        let type_prefix = read_u32(data, &mut cursor)?;
        expect_type_prefix(type_prefix, TYPE_VERTEX_REMOVE, "VertexRemove")?;
        let domain = read_len_prefixed(data, &mut cursor)?;
        let data_address = read_len_prefixed(data, &mut cursor)?;
        let signature = read_len_prefixed(data, &mut cursor)?;
        Ok(Self {
            domain,
            data_address,
            signature,
        })
    }

    /// Mirror of Go `VertexRemove::Validate`.
    pub fn validate(&self) -> Result<()> {
        if self.domain.len() != 32 {
            return Err(QuilError::InvalidArgument(
                "VertexRemove: invalid domain length".into(),
            ));
        }
        if self.data_address.len() != 32 {
            return Err(QuilError::InvalidArgument(
                "VertexRemove: invalid data address length".into(),
            ));
        }
        if self.signature.is_empty() {
            return Err(QuilError::InvalidArgument(
                "VertexRemove: empty signature".into(),
            ));
        }
        Ok(())
    }
}

// =====================================================================
// HyperedgeAdd (type 0x0406)
// =====================================================================

impl HyperedgeAdd {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_HYPEREDGE_ADD);
        put_len_prefixed(&mut out, &self.domain);
        put_len_prefixed(&mut out, &self.value);
        put_len_prefixed(&mut out, &self.signature);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        let type_prefix = read_u32(data, &mut cursor)?;
        expect_type_prefix(type_prefix, TYPE_HYPEREDGE_ADD, "HyperedgeAdd")?;
        let domain = read_len_prefixed(data, &mut cursor)?;
        let value = read_len_prefixed(data, &mut cursor)?;
        let signature = read_len_prefixed(data, &mut cursor)?;
        Ok(Self {
            domain,
            value,
            signature,
        })
    }

    /// Mirror of Go `HyperedgeAdd::Validate`.
    pub fn validate(&self) -> Result<()> {
        if self.domain.len() != 32 {
            return Err(QuilError::InvalidArgument(
                "HyperedgeAdd: invalid domain length".into(),
            ));
        }
        if self.value.is_empty() {
            return Err(QuilError::InvalidArgument(
                "HyperedgeAdd: empty value".into(),
            ));
        }
        if self.signature.is_empty() {
            return Err(QuilError::InvalidArgument(
                "HyperedgeAdd: empty signature".into(),
            ));
        }
        Ok(())
    }
}

// =====================================================================
// HyperedgeRemove (type 0x0407)
// =====================================================================

impl HyperedgeRemove {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_HYPEREDGE_REMOVE);
        put_len_prefixed(&mut out, &self.domain);
        put_len_prefixed(&mut out, &self.value);
        put_len_prefixed(&mut out, &self.signature);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        let type_prefix = read_u32(data, &mut cursor)?;
        expect_type_prefix(type_prefix, TYPE_HYPEREDGE_REMOVE, "HyperedgeRemove")?;
        let domain = read_len_prefixed(data, &mut cursor)?;
        let value = read_len_prefixed(data, &mut cursor)?;
        let signature = read_len_prefixed(data, &mut cursor)?;
        Ok(Self {
            domain,
            value,
            signature,
        })
    }

    /// Mirror of Go `HyperedgeRemove::Validate`.
    pub fn validate(&self) -> Result<()> {
        if self.domain.len() != 32 {
            return Err(QuilError::InvalidArgument(
                "HyperedgeRemove: invalid domain length".into(),
            ));
        }
        if self.value.is_empty() {
            return Err(QuilError::InvalidArgument(
                "HyperedgeRemove: empty value".into(),
            ));
        }
        if self.signature.is_empty() {
            return Err(QuilError::InvalidArgument(
                "HyperedgeRemove: empty signature".into(),
            ));
        }
        Ok(())
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Low-level helpers
    // -----------------------------------------------------------------

    #[test]
    fn put_u32_is_big_endian() {
        let mut v = Vec::new();
        put_u32(&mut v, 0x01020304);
        assert_eq!(v, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn put_len_prefixed_prepends_u32_be_length() {
        let mut v = Vec::new();
        put_len_prefixed(&mut v, b"abc");
        assert_eq!(v, vec![0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn read_u32_decodes_big_endian() {
        let buf = [0x10, 0x20, 0x30, 0x40, 0xAA];
        let mut cursor = 0;
        assert_eq!(read_u32(&buf, &mut cursor).unwrap(), 0x10203040);
        assert_eq!(cursor, 4);
    }

    #[test]
    fn read_u32_errors_on_short_buffer() {
        let buf = [0x00, 0x00];
        let mut cursor = 0;
        assert!(read_u32(&buf, &mut cursor).is_err());
    }

    #[test]
    fn read_len_prefixed_errors_on_short_payload() {
        // length says 10, but only 2 bytes follow
        let buf = [0, 0, 0, 10, 1, 2];
        let mut cursor = 0;
        assert!(read_len_prefixed(&buf, &mut cursor).is_err());
    }

    // -----------------------------------------------------------------
    // BLS48581 G2 public key
    // -----------------------------------------------------------------

    #[test]
    fn bls_g2_pubkey_round_trips() {
        let pk = Bls48581G2PublicKey {
            key_value: vec![0xAAu8; Bls48581G2PublicKey::KEY_VALUE_LEN],
        };
        let bytes = pk.to_canonical_bytes().unwrap();
        // 4 type prefix + 585 payload
        assert_eq!(bytes.len(), 4 + Bls48581G2PublicKey::KEY_VALUE_LEN);
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x01, 0x17]);
        let restored = Bls48581G2PublicKey::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, pk);
    }

    #[test]
    fn bls_g2_pubkey_encode_rejects_wrong_length() {
        let pk = Bls48581G2PublicKey {
            key_value: vec![0x11u8; 10],
        };
        assert!(pk.to_canonical_bytes().is_err());
    }

    #[test]
    fn bls_g2_pubkey_decode_rejects_bad_type_prefix() {
        let mut bytes = vec![0u8; 4 + Bls48581G2PublicKey::KEY_VALUE_LEN];
        bytes[..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        assert!(Bls48581G2PublicKey::from_canonical_bytes(&bytes).is_err());
    }

    // -----------------------------------------------------------------
    // BLS48581 aggregate signature envelope
    // -----------------------------------------------------------------

    fn sample_pubkey() -> Bls48581G2PublicKey {
        Bls48581G2PublicKey {
            key_value: vec![0x33u8; Bls48581G2PublicKey::KEY_VALUE_LEN],
        }
    }

    #[test]
    fn aggregate_sig_round_trip_with_pubkey() {
        let sig = AggregateSignature {
            signature: vec![0xAAu8; 74],
            public_key: Some(sample_pubkey()),
            bitmask: vec![0xFF, 0x01],
        };
        let bytes = sig.to_canonical_bytes().unwrap();
        let restored = AggregateSignature::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, sig);
    }

    #[test]
    fn aggregate_sig_round_trip_without_pubkey() {
        let sig = AggregateSignature {
            signature: vec![0x11u8; 74],
            public_key: None,
            bitmask: Vec::new(),
        };
        let bytes = sig.to_canonical_bytes().unwrap();
        let restored = AggregateSignature::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, sig);
    }

    #[test]
    fn aggregate_sig_round_trip_multi_signer_sig_size() {
        // Multi-signer aggregate wire format: 74 (BLS agg) + 4 (u32
        // count) + N × 516 (multi-proofs). Diverges from Go's canonical
        // gate (no count prefix) but matches what `verify_frame_header_signature`
        // actually consumes — see canonical.rs::from_canonical_bytes.
        let sig = AggregateSignature {
            signature: vec![0x22u8; 78 + 516 * 3],
            public_key: Some(sample_pubkey()),
            bitmask: vec![0xF0],
        };
        let bytes = sig.to_canonical_bytes().unwrap();
        let restored = AggregateSignature::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, sig);
    }

    #[test]
    fn aggregate_sig_decode_rejects_bad_sig_length() {
        // sig_len = 100 (not 74, not 74 + k*516) — must fail.
        let mut bytes = Vec::new();
        put_u32(&mut bytes, TYPE_BLS48581_AGGREGATE_SIGNATURE);
        put_u32(&mut bytes, 100);
        bytes.extend_from_slice(&[0u8; 100]);
        put_u32(&mut bytes, 0);
        put_u32(&mut bytes, 0);
        assert!(AggregateSignature::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn aggregate_sig_decode_rejects_bad_pubkey_length() {
        let mut bytes = Vec::new();
        put_u32(&mut bytes, TYPE_BLS48581_AGGREGATE_SIGNATURE);
        put_u32(&mut bytes, 74);
        bytes.extend_from_slice(&[0u8; 74]);
        put_u32(&mut bytes, 10); // not 0 or 589
        bytes.extend_from_slice(&[0u8; 10]);
        put_u32(&mut bytes, 0);
        assert!(AggregateSignature::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn aggregate_sig_decode_rejects_bad_bitmask_length() {
        let mut bytes = Vec::new();
        put_u32(&mut bytes, TYPE_BLS48581_AGGREGATE_SIGNATURE);
        put_u32(&mut bytes, 74);
        bytes.extend_from_slice(&[0u8; 74]);
        put_u32(&mut bytes, 0);
        put_u32(&mut bytes, 33); // > 32
        bytes.extend_from_slice(&[0u8; 33]);
        assert!(AggregateSignature::from_canonical_bytes(&bytes).is_err());
    }

    // -----------------------------------------------------------------
    // HypergraphConfiguration
    // -----------------------------------------------------------------

    #[test]
    fn hypergraph_configuration_round_trip_with_owner() {
        let c = HypergraphConfiguration {
            read_public_key: vec![0x01u8; 57],
            write_public_key: vec![0x02u8; 57],
            owner_public_key: vec![0x03u8; 585],
        };
        let bytes = c.to_canonical_bytes().unwrap();
        // type(4) + 3 × (u32 len + payload)
        assert_eq!(bytes.len(), 4 + 4 + 57 + 4 + 57 + 4 + 585);
        // type prefix is 0x0401 — high byte 0x04, low byte 0x01
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x04, 0x01]);
        let restored = HypergraphConfiguration::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, c);
    }

    #[test]
    fn hypergraph_configuration_round_trip_without_owner() {
        let c = HypergraphConfiguration {
            read_public_key: vec![0xAAu8; 57],
            write_public_key: vec![0xBBu8; 57],
            owner_public_key: Vec::new(),
        };
        let bytes = c.to_canonical_bytes().unwrap();
        let restored = HypergraphConfiguration::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, c);
    }

    #[test]
    fn hypergraph_configuration_validate_accepts_well_formed() {
        let c = HypergraphConfiguration {
            read_public_key: vec![1u8; 57],
            write_public_key: vec![2u8; 57],
            owner_public_key: vec![3u8; 585],
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn hypergraph_configuration_validate_rejects_bad_keys() {
        let bad_read = HypergraphConfiguration {
            read_public_key: vec![1u8; 56],
            write_public_key: vec![2u8; 57],
            owner_public_key: Vec::new(),
        };
        assert!(bad_read.validate().is_err());

        let bad_write = HypergraphConfiguration {
            read_public_key: vec![1u8; 57],
            write_public_key: vec![2u8; 58],
            owner_public_key: Vec::new(),
        };
        assert!(bad_write.validate().is_err());

        let bad_owner = HypergraphConfiguration {
            read_public_key: vec![1u8; 57],
            write_public_key: vec![2u8; 57],
            owner_public_key: vec![3u8; 100],
        };
        assert!(bad_owner.validate().is_err());
    }

    #[test]
    fn hypergraph_configuration_validate_allows_empty_owner() {
        let c = HypergraphConfiguration {
            read_public_key: vec![1u8; 57],
            write_public_key: vec![2u8; 57],
            owner_public_key: Vec::new(),
        };
        assert!(c.validate().is_ok());
    }

    // -----------------------------------------------------------------
    // HypergraphDeploy
    // -----------------------------------------------------------------

    fn sample_config() -> HypergraphConfiguration {
        HypergraphConfiguration {
            read_public_key: vec![0x11u8; 57],
            write_public_key: vec![0x22u8; 57],
            owner_public_key: vec![0x33u8; 585],
        }
    }

    #[test]
    fn hypergraph_deploy_round_trip_with_schema() {
        let d = HypergraphDeploy {
            config: Some(sample_config()),
            rdf_schema: b"schema-payload".to_vec(),
        };
        let bytes = d.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x04, 0x02]);
        let restored = HypergraphDeploy::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, d);
    }

    #[test]
    fn hypergraph_deploy_round_trip_empty_schema() {
        let d = HypergraphDeploy {
            config: Some(sample_config()),
            rdf_schema: Vec::new(),
        };
        let bytes = d.to_canonical_bytes().unwrap();
        let restored = HypergraphDeploy::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, d);
    }

    #[test]
    fn hypergraph_deploy_encode_rejects_nil_config() {
        let d = HypergraphDeploy {
            config: None,
            rdf_schema: b"schema".to_vec(),
        };
        assert!(d.to_canonical_bytes().is_err());
    }

    #[test]
    fn hypergraph_deploy_validate_passes_with_valid_config() {
        let d = HypergraphDeploy {
            config: Some(sample_config()),
            rdf_schema: Vec::new(),
        };
        assert!(d.validate().is_ok());
    }

    #[test]
    fn hypergraph_deploy_validate_rejects_nil_config() {
        let d = HypergraphDeploy {
            config: None,
            rdf_schema: b"x".to_vec(),
        };
        assert!(d.validate().is_err());
    }

    // -----------------------------------------------------------------
    // HypergraphUpdate
    // -----------------------------------------------------------------

    fn sample_aggregate_sig() -> AggregateSignature {
        AggregateSignature {
            signature: vec![0x55u8; 74],
            public_key: Some(sample_pubkey()),
            bitmask: vec![0x01, 0x02],
        }
    }

    #[test]
    fn hypergraph_update_round_trip_full() {
        let u = HypergraphUpdate {
            config: Some(sample_config()),
            rdf_schema: b"new-schema".to_vec(),
            public_key_signature_bls48581: Some(sample_aggregate_sig()),
        };
        let bytes = u.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x04, 0x03]);
        let restored = HypergraphUpdate::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, u);
    }

    #[test]
    fn hypergraph_update_round_trip_schema_only() {
        let u = HypergraphUpdate {
            config: None,
            rdf_schema: b"schema-only".to_vec(),
            public_key_signature_bls48581: Some(sample_aggregate_sig()),
        };
        let bytes = u.to_canonical_bytes().unwrap();
        let restored = HypergraphUpdate::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, u);
    }

    #[test]
    fn hypergraph_update_round_trip_config_only() {
        let u = HypergraphUpdate {
            config: Some(sample_config()),
            rdf_schema: Vec::new(),
            public_key_signature_bls48581: Some(sample_aggregate_sig()),
        };
        let bytes = u.to_canonical_bytes().unwrap();
        let restored = HypergraphUpdate::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, u);
    }

    #[test]
    fn hypergraph_update_round_trip_no_sig() {
        // Encoder permits None sig (matches Go — validation is separate).
        let u = HypergraphUpdate {
            config: Some(sample_config()),
            rdf_schema: Vec::new(),
            public_key_signature_bls48581: None,
        };
        let bytes = u.to_canonical_bytes().unwrap();
        let restored = HypergraphUpdate::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, u);
    }

    #[test]
    fn hypergraph_update_validate_rejects_both_empty() {
        let u = HypergraphUpdate {
            config: None,
            rdf_schema: Vec::new(),
            public_key_signature_bls48581: Some(sample_aggregate_sig()),
        };
        assert!(u.validate().is_err());
    }

    #[test]
    fn hypergraph_update_validate_rejects_nil_sig() {
        let u = HypergraphUpdate {
            config: Some(sample_config()),
            rdf_schema: Vec::new(),
            public_key_signature_bls48581: None,
        };
        assert!(u.validate().is_err());
    }

    #[test]
    fn hypergraph_update_validate_accepts_schema_only() {
        let u = HypergraphUpdate {
            config: None,
            rdf_schema: b"schema".to_vec(),
            public_key_signature_bls48581: Some(sample_aggregate_sig()),
        };
        assert!(u.validate().is_ok());
    }

    // -----------------------------------------------------------------
    // VertexAdd
    // -----------------------------------------------------------------

    fn sample_vertex_add() -> VertexAdd {
        VertexAdd {
            domain: vec![0xAAu8; 32],
            data_address: vec![0xBBu8; 32],
            data: b"verenc-proof-bytes".to_vec(),
            signature: vec![0xCCu8; 114],
        }
    }

    #[test]
    fn vertex_add_round_trip() {
        let v = sample_vertex_add();
        let bytes = v.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x04, 0x04]);
        let restored = VertexAdd::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, v);
    }

    #[test]
    fn vertex_add_layout_is_exact() {
        // Use small, distinct payloads so we can hand-verify the layout.
        let v = VertexAdd {
            domain: vec![1u8; 32],
            data_address: vec![2u8; 32],
            data: vec![3u8; 4],
            signature: vec![4u8; 6],
        };
        let bytes = v.to_canonical_bytes().unwrap();
        let mut cursor = 0usize;
        // type prefix
        assert_eq!(&bytes[cursor..cursor + 4], &[0x00, 0x00, 0x04, 0x04]);
        cursor += 4;
        // domain
        assert_eq!(&bytes[cursor..cursor + 4], &32u32.to_be_bytes());
        cursor += 4;
        assert_eq!(&bytes[cursor..cursor + 32], &[1u8; 32][..]);
        cursor += 32;
        // data address
        assert_eq!(&bytes[cursor..cursor + 4], &32u32.to_be_bytes());
        cursor += 4;
        assert_eq!(&bytes[cursor..cursor + 32], &[2u8; 32][..]);
        cursor += 32;
        // data
        assert_eq!(&bytes[cursor..cursor + 4], &4u32.to_be_bytes());
        cursor += 4;
        assert_eq!(&bytes[cursor..cursor + 4], &[3u8; 4][..]);
        cursor += 4;
        // signature
        assert_eq!(&bytes[cursor..cursor + 4], &6u32.to_be_bytes());
        cursor += 4;
        assert_eq!(&bytes[cursor..cursor + 6], &[4u8; 6][..]);
        cursor += 6;
        assert_eq!(cursor, bytes.len());
    }

    #[test]
    fn vertex_add_decode_rejects_bad_type_prefix() {
        let mut bytes = sample_vertex_add().to_canonical_bytes().unwrap();
        // Flip the type prefix.
        bytes[..4].copy_from_slice(&TYPE_VERTEX_REMOVE.to_be_bytes());
        assert!(VertexAdd::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn vertex_add_validate_cases() {
        let good = sample_vertex_add();
        assert!(good.validate().is_ok());

        let mut bad = good.clone();
        bad.domain = vec![0u8; 31];
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.data_address = vec![0u8; 33];
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.data = Vec::new();
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.signature = Vec::new();
        assert!(bad.validate().is_err());
    }

    // -----------------------------------------------------------------
    // VertexRemove
    // -----------------------------------------------------------------

    fn sample_vertex_remove() -> VertexRemove {
        VertexRemove {
            domain: vec![0xAAu8; 32],
            data_address: vec![0xBBu8; 32],
            signature: vec![0xCCu8; 114],
        }
    }

    #[test]
    fn vertex_remove_round_trip() {
        let v = sample_vertex_remove();
        let bytes = v.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x04, 0x05]);
        let restored = VertexRemove::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, v);
    }

    #[test]
    fn vertex_remove_validate_cases() {
        let good = sample_vertex_remove();
        assert!(good.validate().is_ok());

        let mut bad = good.clone();
        bad.domain = vec![0u8; 1];
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.data_address = Vec::new();
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.signature = Vec::new();
        assert!(bad.validate().is_err());
    }

    // -----------------------------------------------------------------
    // HyperedgeAdd
    // -----------------------------------------------------------------

    fn sample_hyperedge_add() -> HyperedgeAdd {
        HyperedgeAdd {
            domain: vec![0x01u8; 32],
            value: b"hyperedge-value".to_vec(),
            signature: vec![0xAAu8; 114],
        }
    }

    #[test]
    fn hyperedge_add_round_trip() {
        let h = sample_hyperedge_add();
        let bytes = h.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x04, 0x06]);
        let restored = HyperedgeAdd::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, h);
    }

    #[test]
    fn hyperedge_add_validate_cases() {
        let good = sample_hyperedge_add();
        assert!(good.validate().is_ok());

        let mut bad = good.clone();
        bad.domain = vec![0u8; 31];
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.value = Vec::new();
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.signature = Vec::new();
        assert!(bad.validate().is_err());
    }

    // -----------------------------------------------------------------
    // HyperedgeRemove
    // -----------------------------------------------------------------

    fn sample_hyperedge_remove() -> HyperedgeRemove {
        HyperedgeRemove {
            domain: vec![0x02u8; 32],
            value: b"edge-to-tombstone".to_vec(),
            signature: vec![0xBBu8; 114],
        }
    }

    #[test]
    fn hyperedge_remove_round_trip() {
        let h = sample_hyperedge_remove();
        let bytes = h.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x04, 0x07]);
        let restored = HyperedgeRemove::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, h);
    }

    #[test]
    fn hyperedge_remove_validate_cases() {
        let good = sample_hyperedge_remove();
        assert!(good.validate().is_ok());

        let mut bad = good.clone();
        bad.domain = vec![0u8; 33];
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.value = Vec::new();
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.signature = Vec::new();
        assert!(bad.validate().is_err());
    }

    // -----------------------------------------------------------------
    // Cross-type distinctness
    // -----------------------------------------------------------------

    #[test]
    fn type_prefixes_are_distinct() {
        let ids = [
            TYPE_HYPERGRAPH_CONFIGURATION,
            TYPE_HYPERGRAPH_DEPLOYMENT,
            TYPE_HYPERGRAPH_UPDATE,
            TYPE_VERTEX_ADD,
            TYPE_VERTEX_REMOVE,
            TYPE_HYPEREDGE_ADD,
            TYPE_HYPEREDGE_REMOVE,
            TYPE_BLS48581_AGGREGATE_SIGNATURE,
            TYPE_BLS48581_G2_PUBLIC_KEY,
        ];
        let unique: std::collections::HashSet<u32> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len());
    }

    #[test]
    fn decoding_wrong_type_fails_uniformly() {
        let va = sample_vertex_add().to_canonical_bytes().unwrap();
        assert!(VertexRemove::from_canonical_bytes(&va).is_err());
        assert!(HyperedgeAdd::from_canonical_bytes(&va).is_err());
        assert!(HyperedgeRemove::from_canonical_bytes(&va).is_err());
        assert!(HypergraphConfiguration::from_canonical_bytes(&va).is_err());
        assert!(HypergraphDeploy::from_canonical_bytes(&va).is_err());
        assert!(HypergraphUpdate::from_canonical_bytes(&va).is_err());
    }
}
