//! Hypergraph intrinsic. Port of
//! `node/execution/intrinsics/hypergraph/`.
//!
//! Contains:
//! - `canonical`: length-prefixed binary serialization (byte-compatible
//!   with Go `protobufs/hypergraph.go` ToCanonicalBytes/FromCanonicalBytes).
//! - `types`: Rust representations of the five hypergraph messages plus
//!   the aggregate-signature envelope.

pub mod auth;
pub mod canonical;
pub mod conversions;
pub mod dispatch;
pub mod hyperedge_ops;
pub mod types;
pub mod vertex_ops;

pub use types::{
    HyperedgeAdd, HyperedgeRemove, HypergraphConfiguration, HypergraphDeploy,
    HypergraphUpdate, VertexAdd, VertexRemove,
};

pub use canonical::{
    AggregateSignature, Bls48581G2PublicKey, TYPE_BLS48581_AGGREGATE_SIGNATURE,
    TYPE_BLS48581_G2_PUBLIC_KEY, TYPE_HYPEREDGE_ADD, TYPE_HYPEREDGE_REMOVE,
    TYPE_HYPERGRAPH_CONFIGURATION, TYPE_HYPERGRAPH_DEPLOYMENT, TYPE_HYPERGRAPH_UPDATE,
    TYPE_VERTEX_ADD, TYPE_VERTEX_REMOVE,
};

pub use conversions::{
    aggregate_sig_from_proto, aggregate_sig_to_proto, pack_vertex_add_proof_chunks,
    split_vertex_add_proof_chunks,
};

pub use vertex_ops::{
    encrypted_to_vertex_tree, vertex_add_cost_from_proof_count,
    vertex_add_cost_from_raw_len, vertex_add_domain_separator,
    vertex_add_signing_message, vertex_read_addresses, vertex_remove_cost,
    vertex_remove_domain_separator, vertex_remove_signing_message,
    vertex_write_addresses, MAX_VERTEX_ADD_DISK_SIZE, VERENC_COMPRESSED_BYTES,
    VERENC_PROOF_BYTES, VERENC_PROOF_CHARGE_BYTES, VERTEX_ADD_TAG,
    VERTEX_REMOVE_COST, VERTEX_REMOVE_TAG,
};

pub use dispatch::{
    check_sufficient_fee, decode_and_validate, decode_and_validate_deploy,
    decode_and_validate_update, decode_message, dispatch_cost, is_mutating_op,
    lock_addresses_for_input, peek_message_kind, validate_rdf_schema_evolution,
    DispatchedDeploy, DispatchedDeployOrUpdate, DispatchedMessage, DispatchedUpdate,
    HypergraphLockState, MessageKind,
};

pub use auth::{verify_op_signature, AuthCheck, HypergraphConfigResolver, OpForAuth};

pub use hyperedge_ops::{
    assert_hyperedge_domain_matches, extract_hyperedge_id,
    hyperedge_add_cost_from_atom_count, hyperedge_add_domain_separator,
    hyperedge_add_signing_message, hyperedge_id_app_address,
    hyperedge_id_data_address, hyperedge_read_addresses, hyperedge_remove_cost,
    hyperedge_remove_domain_separator, hyperedge_remove_signing_message,
    hyperedge_write_addresses, HYPEREDGE_ADD_TAG, HYPEREDGE_ATOM_TYPE_BYTE,
    HYPEREDGE_ID_LEN, HYPEREDGE_ID_OFFSET, HYPEREDGE_MIN_VALUE_LEN,
    HYPEREDGE_REMOVE_COST, HYPEREDGE_REMOVE_TAG,
};
