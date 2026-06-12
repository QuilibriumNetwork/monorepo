//! Rust struct shapes for hypergraph messages. These mirror the Go
//! generated protobuf types (`protobufs/hypergraph.pb.go`) at the
//! field-by-field level — the canonical-bytes serializer in
//! `canonical.rs` walks these fields in the same order as the Go
//! `ToCanonicalBytes` implementations, so the types here must stay in
//! sync with `node/protobufs/hypergraph.proto`.
//!
//! All byte fields are owned `Vec<u8>`; we deliberately don't use
//! fixed-size arrays for fields like `domain`/`data_address` because
//! the canonical-bytes format stores them with a length prefix and
//! there are places (sync, replay) where we may encounter messages
//! whose byte slices are not exactly the canonical 32 bytes — the
//! `Validate` path is the one that enforces the 32-byte invariant.

use super::canonical::AggregateSignature;

/// Mirror of `protobufs.HypergraphConfiguration`.
///
/// Go proto fields (from `hypergraph.proto`):
///   bytes read_public_key = 1;
///   bytes write_public_key = 2;
///   bytes owner_public_key = 3;
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HypergraphConfiguration {
    /// Ed448 public key — readers of this hypergraph.
    pub read_public_key: Vec<u8>,
    /// Ed448 public key — writers of this hypergraph.
    pub write_public_key: Vec<u8>,
    /// BLS48-581 G2 public key — owner for updates/admin actions.
    /// Optional: may be empty on read, or 585 bytes when present.
    pub owner_public_key: Vec<u8>,
}

/// Mirror of `protobufs.HypergraphDeploy`.
///
/// A deploy message establishes the initial configuration and RDF
/// schema for a new hypergraph shard.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HypergraphDeploy {
    /// Required — the canonical-bytes encoder rejects a nil config.
    pub config: Option<HypergraphConfiguration>,
    /// RDF schema bytes (may be empty for trivially-typed shards).
    pub rdf_schema: Vec<u8>,
}

/// Mirror of `protobufs.HypergraphUpdate`.
///
/// An update message rotates configuration or swaps RDF schema on an
/// existing hypergraph. At least one of `config` or `rdf_schema` must
/// be present. The BLS48-581 aggregate signature authorizes the update
/// with the owner public key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HypergraphUpdate {
    /// New configuration, or `None` to leave unchanged.
    pub config: Option<HypergraphConfiguration>,
    /// New RDF schema bytes, or empty to leave unchanged.
    pub rdf_schema: Vec<u8>,
    /// Aggregate BLS48-581 signature by the owner. Required for a
    /// valid update; `None` only appears during incremental
    /// construction before signing.
    pub public_key_signature_bls48581: Option<AggregateSignature>,
}

/// Mirror of `protobufs.VertexAdd`.
///
/// Adds a vertex to a hypergraph. `data` is the canonical-bytes
/// encoding of one or more verenc proofs (opaque here — the intrinsic
/// dispatch decodes them separately).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VertexAdd {
    /// 32-byte hypergraph domain address.
    pub domain: Vec<u8>,
    /// 32-byte content-derived vertex address.
    pub data_address: Vec<u8>,
    /// Opaque verenc proof bytes (length-prefixed proof list).
    pub data: Vec<u8>,
    /// Ed448 signature by the write key of the hypergraph config.
    pub signature: Vec<u8>,
}

/// Mirror of `protobufs.VertexRemove`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VertexRemove {
    /// 32-byte hypergraph domain address.
    pub domain: Vec<u8>,
    /// 32-byte content-derived vertex address to tombstone.
    pub data_address: Vec<u8>,
    /// Ed448 signature by the write key of the hypergraph config.
    pub signature: Vec<u8>,
}

/// Mirror of `protobufs.HyperedgeAdd`.
///
/// Adds a hyperedge linking a set of vertices within a hypergraph.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HyperedgeAdd {
    /// 32-byte hypergraph domain address.
    pub domain: Vec<u8>,
    /// Opaque hyperedge value (typically a serialized
    /// `hypergraph.Hyperedge` struct).
    pub value: Vec<u8>,
    /// Ed448 signature by the write key of the hypergraph config.
    pub signature: Vec<u8>,
}

/// Mirror of `protobufs.HyperedgeRemove`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HyperedgeRemove {
    /// 32-byte hypergraph domain address.
    pub domain: Vec<u8>,
    /// Opaque hyperedge value identifying the edge to tombstone.
    pub value: Vec<u8>,
    /// Ed448 signature by the write key of the hypergraph config.
    pub signature: Vec<u8>,
}
