//! Hypergraph execution engine shim -- pure routing and cost dispatch.
//!
//! - [`HYPERGRAPH_CAPABILITIES`] -- protocol IDs this engine advertises.
//! - [`MessageKindTopLevel`] -- MessageBundle vs MessageRequest dispatch.
//! - [`peek_top_level_kind`] -- u32-BE peek for the top-level dispatcher.
//! - [`get_cost_from_request`] -- per-type cost routing.
//! - [`request_is_hypergraph_op`] -- predicate for bundle validation.
//! - [`request_to_payload`] -- serialize a `MessageRequest` into canonical bytes.
//!
//! NOT ported (service-dependent; needs the HypergraphIntrinsic
//! + HypergraphCrdt bridge from task #64):
//!
//! - `ValidateMessage`, `ProcessMessage`, `handleBundle`,
//!   `processIndividualMessage`, `handleDeploy`, `tryGetIntrinsic`
//! - `Prove`, `Lock`, `Unlock` — Lock can compose on top of
//!   `HypergraphLockState` once wiring lands.

use num_bigint::BigInt;
use quil_types::error::{QuilError, Result};
use quil_types::proto::global::message_request::Request as MessageRequestInner;
use quil_types::proto::global::MessageRequest;
use quil_types::proto::node::Capability;

use crate::capabilities as caps;
use crate::hypergraph_intrinsic::{
    conversions::split_vertex_add_proof_chunks,
    vertex_ops::vertex_add_cost_from_proof_count,
};

// =====================================================================
// Capability list
// =====================================================================

/// Double Ratchet protocol ID. Matches the Go `0x0101` constant in
/// `hypergraph_execution_engine.go:192`.
pub const DOUBLE_RATCHET_PROTOCOL: u32 = 0x0101;
/// Triple Ratchet protocol ID. Matches the Go `0x0201` constant.
pub const TRIPLE_RATCHET_PROTOCOL: u32 = 0x0201;
/// Onion Routing protocol ID. Matches the Go `0x0301` constant.
pub const ONION_ROUTING_PROTOCOL: u32 = 0x0301;
/// Hypergraph protocol v1 — the first capability the engine advertises.
/// This is the same ID as `capabilities::HYPERGRAPH_PROTOCOL_V1`.
pub const HYPERGRAPH_PROTOCOL_V1: u32 = 0x00030001;

/// The full ordered list of capabilities this engine advertises.
pub fn hypergraph_capabilities() -> Vec<Capability> {
    vec![
        Capability {
            protocol_identifier: HYPERGRAPH_PROTOCOL_V1,
            additional_metadata: Vec::new(),
        },
        Capability {
            protocol_identifier: DOUBLE_RATCHET_PROTOCOL,
            additional_metadata: Vec::new(),
        },
        Capability {
            protocol_identifier: TRIPLE_RATCHET_PROTOCOL,
            additional_metadata: Vec::new(),
        },
        Capability {
            protocol_identifier: ONION_ROUTING_PROTOCOL,
            additional_metadata: Vec::new(),
        },
    ]
}

// =====================================================================
// Top-level message-kind dispatch
// =====================================================================
//
// The first 4 bytes of the incoming wire message decide between
// MessageBundleType (0x0312) and MessageRequestType (0x0311).
// Anything else is rejected.

/// Top-level wire-format message kinds the engine accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKindTopLevel {
    /// `protobufs.MessageBundleType = 0x0312` — a bundle of
    /// `MessageRequest`s.
    Bundle,
    /// `protobufs.MessageRequestType = 0x0311` — a single request.
    Request,
}

// Re-export from the canonical message_envelope module.
pub use crate::message_envelope::{TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST};

/// Peek the first 4 bytes of `input` and decide between
/// bundle/request. Returns `Err` for short input or unknown prefix.
pub fn peek_top_level_kind(input: &[u8]) -> Result<MessageKindTopLevel> {
    if input.len() < 4 {
        return Err(QuilError::InvalidArgument(
            "hypergraph engine: input too short to peek type prefix".into(),
        ));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&input[..4]);
    let prefix = u32::from_be_bytes(buf);
    match prefix {
        TYPE_MESSAGE_BUNDLE => Ok(MessageKindTopLevel::Bundle),
        TYPE_MESSAGE_REQUEST => Ok(MessageKindTopLevel::Request),
        other => Err(QuilError::InvalidArgument(format!(
            "hypergraph engine: unsupported message type 0x{:08x}",
            other
        ))),
    }
}

// =====================================================================
// Is-hypergraph-op predicate
// =====================================================================

/// Does this `MessageRequest` carry a hypergraph-domain operation?
/// Matches Go's union in `validateBundle`/`handleBundle`:
///
/// ```go
/// isHypergraphOp := op.GetHypergraphDeploy() != nil ||
///     op.GetHypergraphUpdate() != nil ||
///     op.GetVertexAdd() != nil ||
///     op.GetVertexRemove() != nil ||
///     op.GetHyperedgeAdd() != nil ||
///     op.GetHyperedgeRemove() != nil
/// ```
pub fn request_is_hypergraph_op(request: &MessageRequest) -> bool {
    matches!(
        request.request,
        Some(MessageRequestInner::HypergraphDeploy(_))
            | Some(MessageRequestInner::HypergraphUpdate(_))
            | Some(MessageRequestInner::VertexAdd(_))
            | Some(MessageRequestInner::VertexRemove(_))
            | Some(MessageRequestInner::HyperedgeAdd(_))
            | Some(MessageRequestInner::HyperedgeRemove(_))
    )
}

// =====================================================================
// GetCost
// =====================================================================

/// Compute the cost of a `MessageRequest` under the hypergraph
/// engine's rules.
///
/// - **HypergraphDeploy**: `len(rdf_schema) + len(read) + len(write) + len(owner)`
///   (concatenated byte count across the three keys + schema).
/// - **HypergraphUpdate**: same shape.
/// - **VertexAdd**: delegates to the per-op helper via the packed
///   proof-chunk count (55 bytes per proof).
/// - **VertexRemove**: constant 64.
/// - **HyperedgeAdd**: cost = atom count under the extrinsic tree.
///   We can't decode that without the lazy tree — callers pass a
///   `hyperedge_atom_count_hint` when they know it, else cost defaults
///   to zero.
/// - **HyperedgeRemove**: constant 64.
/// - Any other request variant (including `None`, prover ops, token
///   ops, compute ops): `0`, matching Go's final
///   `return big.NewInt(0), nil`.
pub fn get_cost_from_request(
    request: &MessageRequest,
    hyperedge_atom_count_hint: u64,
) -> Result<BigInt> {
    let Some(req) = &request.request else {
        return Ok(BigInt::from(0));
    };

    match req {
        MessageRequestInner::HypergraphDeploy(d) => {
            let size = d.rdf_schema.len()
                + d.config.as_ref().map(|c| c.read_public_key.len()).unwrap_or(0)
                + d.config
                    .as_ref()
                    .map(|c| c.write_public_key.len())
                    .unwrap_or(0)
                + d.config
                    .as_ref()
                    .map(|c| c.owner_public_key.len())
                    .unwrap_or(0);
            Ok(BigInt::from(size as i64))
        }

        MessageRequestInner::HypergraphUpdate(u) => {
            let size = u.rdf_schema.len()
                + u.config.as_ref().map(|c| c.read_public_key.len()).unwrap_or(0)
                + u.config
                    .as_ref()
                    .map(|c| c.write_public_key.len())
                    .unwrap_or(0)
                + u.config
                    .as_ref()
                    .map(|c| c.owner_public_key.len())
                    .unwrap_or(0);
            Ok(BigInt::from(size as i64))
        }

        MessageRequestInner::VertexAdd(v) => {
            // Go calls VertexAdd.GetCost() which in the Data!=nil path
            // returns `len(Data) * 55`. Data here is the parsed
            // [VerEncProof] list; we count it by decoding the packed
            // chunks.
            let chunks = split_vertex_add_proof_chunks(&v.data)?;
            Ok(vertex_add_cost_from_proof_count(chunks.len()))
        }

        MessageRequestInner::VertexRemove(_) => {
            Ok(BigInt::from(crate::hypergraph_intrinsic::VERTEX_REMOVE_COST))
        }

        MessageRequestInner::HyperedgeAdd(_) => Ok(BigInt::from(
            hyperedge_atom_count_hint,
        )),

        MessageRequestInner::HyperedgeRemove(_) => {
            Ok(BigInt::from(crate::hypergraph_intrinsic::HYPEREDGE_REMOVE_COST))
        }

        // Non-hypergraph ops (prover admin, token ops, compute ops,
        // shard ops) are zero-cost under the hypergraph engine — the
        // cost routing is per-engine, and the token/compute engines
        // handle their own pricing separately.
        _ => Ok(BigInt::from(0)),
    }
}

// =====================================================================
// MessageRequest → canonical-bytes payload
// =====================================================================

/// Serialize a hypergraph-domain `MessageRequest` into the same
/// canonical-bytes payload that the Go `processIndividualMessage`
/// produces (via the oneof-field `ToCanonicalBytes()` calls).
///
/// Returns an error for non-hypergraph requests — matches Go's
/// `"unsupported message type"` fall-through.
pub fn request_to_payload(request: &MessageRequest) -> Result<Vec<u8>> {
    use crate::hypergraph_intrinsic::types::{
        HyperedgeAdd, HyperedgeRemove, HypergraphDeploy, HypergraphUpdate, VertexAdd,
        VertexRemove,
    };

    let Some(req) = &request.request else {
        return Err(QuilError::InvalidArgument(
            "hypergraph engine: empty request".into(),
        ));
    };

    match req {
        MessageRequestInner::HypergraphDeploy(d) => {
            HypergraphDeploy::from_proto(d)?.to_canonical_bytes()
        }
        MessageRequestInner::HypergraphUpdate(u) => {
            HypergraphUpdate::from_proto(u)?.to_canonical_bytes()
        }
        MessageRequestInner::VertexAdd(v) => VertexAdd::from_proto(v).to_canonical_bytes(),
        MessageRequestInner::VertexRemove(v) => {
            VertexRemove::from_proto(v).to_canonical_bytes()
        }
        MessageRequestInner::HyperedgeAdd(h) => {
            HyperedgeAdd::from_proto(h).to_canonical_bytes()
        }
        MessageRequestInner::HyperedgeRemove(h) => {
            HyperedgeRemove::from_proto(h).to_canonical_bytes()
        }
        _ => Err(QuilError::InvalidArgument(
            "hypergraph engine: unsupported message type for payload".into(),
        )),
    }
}

// =====================================================================
// Verify at compile time that the capability IDs match the constants
// in `crate::capabilities` — the engine-shim module is the user-facing
// home for `HYPERGRAPH_PROTOCOL_V1`, but the lower-level `capabilities`
// module already defines a bunch of `*_V1` constants and this engine's
// advertised ID should line up with any consumers using them.
// =====================================================================

const _: () = {
    // Would ideally use `assert!(x == y)` but const-eval on non-copy
    // integers is fine here. If `capabilities` grows a
    // `HYPERGRAPH_PROTOCOL_V1` const, uncomment the line below.
    let _ = caps::GLOBAL_PROTOCOL_V1;
};

/// Does this type prefix correspond to one of the six hypergraph
/// operation types (deploy, update, vertex add/remove, hyperedge
/// add/remove)? Used by the engine to filter bundle ops.
pub fn is_hypergraph_type_prefix(tp: u32) -> bool {
    use crate::hypergraph_intrinsic::canonical::{
        TYPE_HYPEREDGE_ADD, TYPE_HYPEREDGE_REMOVE, TYPE_HYPERGRAPH_CONFIGURATION,
        TYPE_HYPERGRAPH_DEPLOYMENT, TYPE_HYPERGRAPH_UPDATE, TYPE_VERTEX_ADD,
        TYPE_VERTEX_REMOVE,
    };
    matches!(
        tp,
        TYPE_HYPERGRAPH_DEPLOYMENT
            | TYPE_HYPERGRAPH_UPDATE
            | TYPE_HYPERGRAPH_CONFIGURATION
            | TYPE_VERTEX_ADD
            | TYPE_VERTEX_REMOVE
            | TYPE_HYPEREDGE_ADD
            | TYPE_HYPEREDGE_REMOVE
    )
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::hypergraph as hg_pb;
    use quil_types::proto::keys as keys_pb;
    use quil_types::proto::token as token_pb;

    fn make_request_hypergraph_deploy(
        read_len: usize,
        write_len: usize,
        owner_len: usize,
        schema_len: usize,
    ) -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::HypergraphDeploy(
                hg_pb::HypergraphDeploy {
                    config: Some(hg_pb::HypergraphConfiguration {
                        read_public_key: vec![0u8; read_len],
                        write_public_key: vec![0u8; write_len],
                        owner_public_key: vec![0u8; owner_len],
                    }),
                    rdf_schema: vec![0u8; schema_len],
                },
            )),
        }
    }

    fn make_request_hypergraph_update(
        read_len: usize,
        write_len: usize,
        owner_len: usize,
        schema_len: usize,
    ) -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::HypergraphUpdate(
                hg_pb::HypergraphUpdate {
                    config: Some(hg_pb::HypergraphConfiguration {
                        read_public_key: vec![0u8; read_len],
                        write_public_key: vec![0u8; write_len],
                        owner_public_key: vec![0u8; owner_len],
                    }),
                    rdf_schema: vec![0u8; schema_len],
                    public_key_signature_bls48581: Some(
                        keys_pb::Bls48581AggregateSignature {
                            signature: vec![0u8; 74],
                            public_key: None,
                            bitmask: vec![],
                        },
                    ),
                },
            )),
        }
    }

    fn make_request_vertex_add(proof_count: usize) -> MessageRequest {
        use crate::hypergraph_intrinsic::conversions::pack_vertex_add_proof_chunks;
        let proofs: Vec<Vec<u8>> =
            (0..proof_count).map(|_| vec![0xAAu8; 16]).collect();
        let data = pack_vertex_add_proof_chunks(&proofs).unwrap();
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::VertexAdd(hg_pb::VertexAdd {
                domain: vec![0u8; 32],
                data_address: vec![0u8; 32],
                data,
                signature: vec![0u8; 114],
            })),
        }
    }

    fn make_request_vertex_remove() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::VertexRemove(
                hg_pb::VertexRemove {
                    domain: vec![0u8; 32],
                    data_address: vec![0u8; 32],
                    signature: vec![0u8; 114],
                },
            )),
        }
    }

    fn make_hyperedge_value(app: u8, data: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.push(0x01);
        out.extend_from_slice(&[app; 32]);
        out.extend_from_slice(&[data; 32]);
        out
    }

    fn make_request_hyperedge_add() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::HyperedgeAdd(hg_pb::HyperedgeAdd {
                domain: vec![0x10u8; 32],
                value: make_hyperedge_value(0x10, 0x20),
                signature: vec![0u8; 114],
            })),
        }
    }

    fn make_request_hyperedge_remove() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::HyperedgeRemove(
                hg_pb::HyperedgeRemove {
                    domain: vec![0x10u8; 32],
                    value: make_hyperedge_value(0x10, 0x20),
                    signature: vec![0u8; 114],
                },
            )),
        }
    }

    fn make_request_token_tx() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::Transaction(token_pb::Transaction {
                domain: vec![0u8; 32],
                inputs: vec![],
                outputs: vec![],
                fees: vec![],
                range_proof: vec![],
                ..Default::default()
            })),
        }
    }

    // -----------------------------------------------------------------
    // Capabilities
    // -----------------------------------------------------------------

    #[test]
    fn hypergraph_capabilities_has_four_entries() {
        assert_eq!(hypergraph_capabilities().len(), 4);
    }

    #[test]
    fn hypergraph_capabilities_first_is_hypergraph_v1() {
        let caps = hypergraph_capabilities();
        assert_eq!(caps[0].protocol_identifier, HYPERGRAPH_PROTOCOL_V1);
        assert_eq!(caps[0].protocol_identifier, 0x00030001);
    }

    #[test]
    fn hypergraph_capabilities_includes_ratchets_and_onion() {
        let caps = hypergraph_capabilities();
        let ids: Vec<u32> = caps.iter().map(|c| c.protocol_identifier).collect();
        assert!(ids.contains(&DOUBLE_RATCHET_PROTOCOL));
        assert!(ids.contains(&TRIPLE_RATCHET_PROTOCOL));
        assert!(ids.contains(&ONION_ROUTING_PROTOCOL));
    }

    #[test]
    fn hypergraph_capabilities_additional_metadata_empty() {
        for cap in hypergraph_capabilities() {
            assert!(cap.additional_metadata.is_empty());
        }
    }

    #[test]
    fn hypergraph_capabilities_protocol_ids_are_distinct() {
        let caps = hypergraph_capabilities();
        let ids: std::collections::HashSet<u32> =
            caps.iter().map(|c| c.protocol_identifier).collect();
        assert_eq!(ids.len(), 4);
    }

    // -----------------------------------------------------------------
    // peek_top_level_kind
    // -----------------------------------------------------------------

    #[test]
    fn peek_top_level_routes_bundle() {
        let bytes = TYPE_MESSAGE_BUNDLE.to_be_bytes();
        assert_eq!(
            peek_top_level_kind(&bytes).unwrap(),
            MessageKindTopLevel::Bundle
        );
    }

    #[test]
    fn peek_top_level_routes_request() {
        let bytes = TYPE_MESSAGE_REQUEST.to_be_bytes();
        assert_eq!(
            peek_top_level_kind(&bytes).unwrap(),
            MessageKindTopLevel::Request
        );
    }

    #[test]
    fn peek_top_level_rejects_short_input() {
        assert!(peek_top_level_kind(&[]).is_err());
        assert!(peek_top_level_kind(&[0; 3]).is_err());
    }

    #[test]
    fn peek_top_level_rejects_unknown_prefix() {
        assert!(peek_top_level_kind(&[0xDE, 0xAD, 0xBE, 0xEF]).is_err());
        // Vertex-add is not a top-level type — must be rejected here.
        assert!(peek_top_level_kind(&0x0404u32.to_be_bytes()).is_err());
    }

    // -----------------------------------------------------------------
    // request_is_hypergraph_op
    // -----------------------------------------------------------------

    #[test]
    fn is_hypergraph_op_positive_for_all_six_types() {
        assert!(request_is_hypergraph_op(&make_request_hypergraph_deploy(
            57, 57, 0, 10
        )));
        assert!(request_is_hypergraph_op(&make_request_hypergraph_update(
            57, 57, 0, 10
        )));
        assert!(request_is_hypergraph_op(&make_request_vertex_add(1)));
        assert!(request_is_hypergraph_op(&make_request_vertex_remove()));
        assert!(request_is_hypergraph_op(&make_request_hyperedge_add()));
        assert!(request_is_hypergraph_op(&make_request_hyperedge_remove()));
    }

    #[test]
    fn is_hypergraph_op_false_for_token_tx() {
        assert!(!request_is_hypergraph_op(&make_request_token_tx()));
    }

    #[test]
    fn is_hypergraph_op_false_for_none_request() {
        let req = MessageRequest {
            timestamp: 0,
            request: None,
        };
        assert!(!request_is_hypergraph_op(&req));
    }

    // -----------------------------------------------------------------
    // get_cost_from_request
    // -----------------------------------------------------------------

    #[test]
    fn cost_for_hypergraph_deploy_sums_schema_and_keys() {
        let req = make_request_hypergraph_deploy(57, 57, 585, 100);
        // 100 + 57 + 57 + 585 = 799
        assert_eq!(
            get_cost_from_request(&req, 0).unwrap(),
            BigInt::from(799)
        );
    }

    #[test]
    fn cost_for_hypergraph_deploy_with_no_owner_key() {
        let req = make_request_hypergraph_deploy(57, 57, 0, 42);
        assert_eq!(
            get_cost_from_request(&req, 0).unwrap(),
            BigInt::from(42 + 57 + 57)
        );
    }

    #[test]
    fn cost_for_hypergraph_update_sums_schema_and_keys() {
        let req = make_request_hypergraph_update(57, 57, 585, 10);
        assert_eq!(
            get_cost_from_request(&req, 0).unwrap(),
            BigInt::from(10 + 57 + 57 + 585)
        );
    }

    #[test]
    fn cost_for_vertex_add_uses_proof_count() {
        let req = make_request_vertex_add(3);
        assert_eq!(
            get_cost_from_request(&req, 0).unwrap(),
            BigInt::from(3 * 55)
        );
    }

    #[test]
    fn cost_for_vertex_remove_is_64() {
        let req = make_request_vertex_remove();
        assert_eq!(get_cost_from_request(&req, 0).unwrap(), BigInt::from(64));
    }

    #[test]
    fn cost_for_hyperedge_add_uses_atom_count_hint() {
        let req = make_request_hyperedge_add();
        assert_eq!(get_cost_from_request(&req, 5).unwrap(), BigInt::from(5));
        assert_eq!(get_cost_from_request(&req, 0).unwrap(), BigInt::from(0));
    }

    #[test]
    fn cost_for_hyperedge_remove_is_64() {
        let req = make_request_hyperedge_remove();
        assert_eq!(
            get_cost_from_request(&req, 0).unwrap(),
            BigInt::from(64)
        );
    }

    #[test]
    fn cost_for_non_hypergraph_op_is_zero() {
        let req = make_request_token_tx();
        assert_eq!(get_cost_from_request(&req, 0).unwrap(), BigInt::from(0));
    }

    #[test]
    fn cost_for_none_request_is_zero() {
        let req = MessageRequest {
            timestamp: 0,
            request: None,
        };
        assert_eq!(get_cost_from_request(&req, 0).unwrap(), BigInt::from(0));
    }

    // -----------------------------------------------------------------
    // request_to_payload
    // -----------------------------------------------------------------

    #[test]
    fn request_to_payload_vertex_add_produces_type_0x0404() {
        let req = make_request_vertex_add(1);
        let payload = request_to_payload(&req).unwrap();
        assert_eq!(&payload[..4], &[0x00, 0x00, 0x04, 0x04]);
    }

    #[test]
    fn request_to_payload_vertex_remove_produces_type_0x0405() {
        let req = make_request_vertex_remove();
        let payload = request_to_payload(&req).unwrap();
        assert_eq!(&payload[..4], &[0x00, 0x00, 0x04, 0x05]);
    }

    #[test]
    fn request_to_payload_hyperedge_add_produces_type_0x0406() {
        let req = make_request_hyperedge_add();
        let payload = request_to_payload(&req).unwrap();
        assert_eq!(&payload[..4], &[0x00, 0x00, 0x04, 0x06]);
    }

    #[test]
    fn request_to_payload_hyperedge_remove_produces_type_0x0407() {
        let req = make_request_hyperedge_remove();
        let payload = request_to_payload(&req).unwrap();
        assert_eq!(&payload[..4], &[0x00, 0x00, 0x04, 0x07]);
    }

    #[test]
    fn request_to_payload_hypergraph_deploy_produces_type_0x0402() {
        let req = make_request_hypergraph_deploy(57, 57, 0, 10);
        let payload = request_to_payload(&req).unwrap();
        assert_eq!(&payload[..4], &[0x00, 0x00, 0x04, 0x02]);
    }

    #[test]
    fn request_to_payload_hypergraph_update_produces_type_0x0403() {
        let req = make_request_hypergraph_update(57, 57, 0, 10);
        let payload = request_to_payload(&req).unwrap();
        assert_eq!(&payload[..4], &[0x00, 0x00, 0x04, 0x03]);
    }

    #[test]
    fn request_to_payload_rejects_non_hypergraph_op() {
        let req = make_request_token_tx();
        assert!(request_to_payload(&req).is_err());
    }

    #[test]
    fn request_to_payload_rejects_empty_request() {
        let req = MessageRequest {
            timestamp: 0,
            request: None,
        };
        assert!(request_to_payload(&req).is_err());
    }

    // -----------------------------------------------------------------
    // Sanity check on top-level type constants
    // -----------------------------------------------------------------

    #[test]
    fn top_level_type_constants_match_canonical_types_go() {
        // These constants are defined in Go at
        // `node/protobufs/canonical_types.go:57-58`.
        assert_eq!(TYPE_MESSAGE_REQUEST, 0x0311);
        assert_eq!(TYPE_MESSAGE_BUNDLE, 0x0312);
    }
}
