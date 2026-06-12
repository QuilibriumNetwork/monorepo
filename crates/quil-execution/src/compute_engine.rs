//! Compute execution engine shim. Port of the pure dispatch parts of
//! `node/execution/engines/compute_execution_engine.go`.
//!
//! Same structural split as `hypergraph_engine.rs` / `global_engine.rs`:
//!
//! - [`compute_engine_capabilities`] — 12 protocol IDs (compute v1,
//!   ratchets, onion, KZG verify, bulletproof range/sum verify,
//!   SECP256K1/ED25519/ED448/DECAF448/SECP256R1 signature verify).
//! - [`request_is_compute_op`] — boolean predicate for bundle routing.
//! - [`MessageKindCompute`] — the five compute operation types.
//! - [`get_cost_from_request`] — per-type cost dispatch matching Go's
//!   `ComputeExecutionEngine::GetCost` at line 306.

use num_bigint::BigInt;
use quil_types::error::{QuilError, Result};
use quil_types::proto::global::message_request::Request as MessageRequestInner;
use quil_types::proto::global::MessageRequest;
use quil_types::proto::node::Capability;

use crate::hypergraph_engine::{
    DOUBLE_RATCHET_PROTOCOL, ONION_ROUTING_PROTOCOL, TRIPLE_RATCHET_PROTOCOL,
};

// =====================================================================
// Capability constants
// =====================================================================

/// Compute protocol v1. Matches
/// `crate::capabilities::COMPUTE_PROTOCOL_V1` (0x00010001).
pub const COMPUTE_PROTOCOL_V1: u32 = 0x00010001;

// Additional verification protocols exclusive to the compute engine:
/// KZG verification on BLS48-581 curve.
pub const KZG_VERIFY_BLS48581: u32 = 0x00010101;
/// Bulletproof range-proof verification on DECAF448.
pub const BULLETPROOF_RANGE_VERIFY_DECAF448: u32 = 0x00010201;
/// Bulletproof sum-check verification on DECAF448.
pub const BULLETPROOF_SUM_VERIFY_DECAF448: u32 = 0x00010301;
/// SECP256K1 ECDSA signature verification.
pub const SECP256K1_ECDSA_VERIFY: u32 = 0x00010401;
/// ED25519 EdDSA signature verification.
pub const ED25519_EDDSA_VERIFY: u32 = 0x00010501;
/// ED448 EdDSA signature verification.
pub const ED448_EDDSA_VERIFY: u32 = 0x00010601;
/// DECAF448 Schnorr signature verification.
pub const DECAF448_SCHNORR_VERIFY: u32 = 0x00010701;
/// SECP256R1 ECDSA signature verification.
pub const SECP256R1_ECDSA_VERIFY: u32 = 0x00010801;

/// Full ordered capability list. Mirror of
/// `ComputeExecutionEngine::GetCapabilities` at line 77.
pub fn compute_engine_capabilities() -> Vec<Capability> {
    vec![
        Capability { protocol_identifier: COMPUTE_PROTOCOL_V1, additional_metadata: Vec::new() },
        Capability { protocol_identifier: DOUBLE_RATCHET_PROTOCOL, additional_metadata: Vec::new() },
        Capability { protocol_identifier: TRIPLE_RATCHET_PROTOCOL, additional_metadata: Vec::new() },
        Capability { protocol_identifier: ONION_ROUTING_PROTOCOL, additional_metadata: Vec::new() },
        Capability { protocol_identifier: KZG_VERIFY_BLS48581, additional_metadata: Vec::new() },
        Capability { protocol_identifier: BULLETPROOF_RANGE_VERIFY_DECAF448, additional_metadata: Vec::new() },
        Capability { protocol_identifier: BULLETPROOF_SUM_VERIFY_DECAF448, additional_metadata: Vec::new() },
        Capability { protocol_identifier: SECP256K1_ECDSA_VERIFY, additional_metadata: Vec::new() },
        Capability { protocol_identifier: ED25519_EDDSA_VERIFY, additional_metadata: Vec::new() },
        Capability { protocol_identifier: ED448_EDDSA_VERIFY, additional_metadata: Vec::new() },
        Capability { protocol_identifier: DECAF448_SCHNORR_VERIFY, additional_metadata: Vec::new() },
        Capability { protocol_identifier: SECP256R1_ECDSA_VERIFY, additional_metadata: Vec::new() },
    ]
}

// =====================================================================
// Compute op type prefixes
// =====================================================================

// Re-export from the canonical compute_intrinsic modules.
pub use crate::compute_intrinsic::{
    TYPE_COMPUTE_DEPLOY, TYPE_COMPUTE_UPDATE,
    TYPE_CODE_EXECUTE, TYPE_CODE_FINALIZE,
    TYPE_CODE_DEPLOYMENT as TYPE_CODE_DEPLOY,
};

/// The five compute operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKindCompute {
    ComputeDeploy,
    ComputeUpdate,
    CodeDeploy,
    CodeExecute,
    CodeFinalize,
}

impl MessageKindCompute {
    pub const fn type_prefix(self) -> u32 {
        match self {
            Self::ComputeDeploy => TYPE_COMPUTE_DEPLOY,
            Self::ComputeUpdate => TYPE_COMPUTE_UPDATE,
            Self::CodeDeploy => TYPE_CODE_DEPLOY,
            Self::CodeExecute => TYPE_CODE_EXECUTE,
            Self::CodeFinalize => TYPE_CODE_FINALIZE,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::ComputeDeploy => "compute_deploy",
            Self::ComputeUpdate => "compute_update",
            Self::CodeDeploy => "code_deploy",
            Self::CodeExecute => "code_execute",
            Self::CodeFinalize => "code_finalize",
        }
    }

    pub const fn all() -> [MessageKindCompute; 5] {
        [
            Self::ComputeDeploy,
            Self::ComputeUpdate,
            Self::CodeDeploy,
            Self::CodeExecute,
            Self::CodeFinalize,
        ]
    }
}

/// Peek 4-byte type prefix and return compute message kind.
pub fn peek_compute_message_kind(input: &[u8]) -> Result<MessageKindCompute> {
    if input.len() < 4 {
        return Err(QuilError::InvalidArgument(
            "compute dispatch: input too short".into(),
        ));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&input[..4]);
    match u32::from_be_bytes(buf) {
        TYPE_COMPUTE_DEPLOY => Ok(MessageKindCompute::ComputeDeploy),
        TYPE_COMPUTE_UPDATE => Ok(MessageKindCompute::ComputeUpdate),
        TYPE_CODE_DEPLOY => Ok(MessageKindCompute::CodeDeploy),
        TYPE_CODE_EXECUTE => Ok(MessageKindCompute::CodeExecute),
        TYPE_CODE_FINALIZE => Ok(MessageKindCompute::CodeFinalize),
        other => Err(QuilError::InvalidArgument(format!(
            "compute dispatch: unknown type prefix 0x{:08x}",
            other
        ))),
    }
}

// =====================================================================
// Is-compute-op predicate
// =====================================================================

/// Does this `MessageRequest` carry a compute-engine operation?
pub fn request_is_compute_op(request: &MessageRequest) -> bool {
    matches!(
        request.request,
        Some(MessageRequestInner::ComputeDeploy(_))
            | Some(MessageRequestInner::ComputeUpdate(_))
            | Some(MessageRequestInner::CodeDeploy(_))
            | Some(MessageRequestInner::CodeExecute(_))
            | Some(MessageRequestInner::CodeFinalize(_))
    )
}

/// Map a `MessageRequest` oneof to compute kind, if applicable.
pub fn compute_kind_for_request(
    request: &MessageRequest,
) -> Option<MessageKindCompute> {
    match request.request.as_ref()? {
        MessageRequestInner::ComputeDeploy(_) => Some(MessageKindCompute::ComputeDeploy),
        MessageRequestInner::ComputeUpdate(_) => Some(MessageKindCompute::ComputeUpdate),
        MessageRequestInner::CodeDeploy(_) => Some(MessageKindCompute::CodeDeploy),
        MessageRequestInner::CodeExecute(_) => Some(MessageKindCompute::CodeExecute),
        MessageRequestInner::CodeFinalize(_) => Some(MessageKindCompute::CodeFinalize),
        _ => None,
    }
}

// =====================================================================
// Cost dispatch (deploy/update cost is schema+keys; op costs need
// service wiring so they return stubs)
// =====================================================================

/// Cost for a compute `MessageRequest`. Matches Go's
/// `ComputeExecutionEngine::GetCost` at line 306.
///
/// Deploy/Update costs are the sum of schema + key lengths (same
/// pattern as hypergraph). CodeDeploy/Execute/Finalize costs depend
/// on the circuit compiler and verenc — callers that haven't wired
/// those in yet can pass the `code_op_cost_hint` override.
pub fn get_cost_from_request(
    request: &MessageRequest,
    code_op_cost_hint: i64,
) -> Result<BigInt> {
    let Some(req) = &request.request else {
        return Ok(BigInt::from(0));
    };

    match req {
        MessageRequestInner::ComputeDeploy(d) => {
            let size = d.rdf_schema.len()
                + d.config.as_ref().map(|c| c.read_public_key.len()).unwrap_or(0)
                + d.config.as_ref().map(|c| c.write_public_key.len()).unwrap_or(0)
                + d.config.as_ref().map(|c| c.owner_public_key.len()).unwrap_or(0);
            Ok(BigInt::from(size as i64))
        }
        MessageRequestInner::ComputeUpdate(u) => {
            let size = u.rdf_schema.len()
                + u.config.as_ref().map(|c| c.read_public_key.len()).unwrap_or(0)
                + u.config.as_ref().map(|c| c.write_public_key.len()).unwrap_or(0)
                + u.config.as_ref().map(|c| c.owner_public_key.len()).unwrap_or(0);
            Ok(BigInt::from(size as i64))
        }
        MessageRequestInner::CodeDeploy(_)
        | MessageRequestInner::CodeExecute(_)
        | MessageRequestInner::CodeFinalize(_) => {
            // Actual cost depends on circuit size / execution DAG
            // nodes / finalization tree, all of which need the
            // compiler + verenc. Until those are wired in, callers
            // provide a hint.
            Ok(BigInt::from(code_op_cost_hint))
        }
        _ => Ok(BigInt::from(0)),
    }
}

/// Does this type prefix correspond to a compute-engine operation?
pub fn is_compute_type_prefix(tp: u32) -> bool {
    matches!(
        tp,
        TYPE_COMPUTE_DEPLOY
            | TYPE_COMPUTE_UPDATE
            | TYPE_CODE_DEPLOY
            | TYPE_CODE_EXECUTE
            | TYPE_CODE_FINALIZE
    )
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::compute as compute_pb;

    fn make_compute_deploy(
        read_len: usize,
        write_len: usize,
        owner_len: usize,
        schema_len: usize,
    ) -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::ComputeDeploy(
                compute_pb::ComputeDeploy {
                    config: Some(compute_pb::ComputeConfiguration {
                        read_public_key: vec![0u8; read_len],
                        write_public_key: vec![0u8; write_len],
                        owner_public_key: vec![0u8; owner_len],
                    }),
                    rdf_schema: vec![0u8; schema_len],
                },
            )),
        }
    }

    fn make_code_execute() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::CodeExecute(
                compute_pb::CodeExecute {
                    ..Default::default()
                },
            )),
        }
    }

    // -----------------------------------------------------------------
    // Capabilities
    // -----------------------------------------------------------------

    #[test]
    fn compute_capabilities_has_twelve_entries() {
        assert_eq!(compute_engine_capabilities().len(), 12);
    }

    #[test]
    fn compute_capabilities_first_is_compute_v1() {
        let caps = compute_engine_capabilities();
        assert_eq!(caps[0].protocol_identifier, COMPUTE_PROTOCOL_V1);
        assert_eq!(caps[0].protocol_identifier, 0x00010001);
    }

    #[test]
    fn compute_capabilities_matches_core_constant() {
        assert_eq!(
            COMPUTE_PROTOCOL_V1,
            crate::capabilities::COMPUTE_PROTOCOL_V1
        );
    }

    #[test]
    fn compute_capabilities_all_distinct() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = compute_engine_capabilities()
            .iter()
            .map(|c| c.protocol_identifier)
            .collect();
        assert_eq!(ids.len(), 12);
    }

    #[test]
    fn compute_capabilities_includes_common_protocols() {
        let ids: Vec<u32> = compute_engine_capabilities()
            .iter()
            .map(|c| c.protocol_identifier)
            .collect();
        assert!(ids.contains(&DOUBLE_RATCHET_PROTOCOL));
        assert!(ids.contains(&TRIPLE_RATCHET_PROTOCOL));
        assert!(ids.contains(&ONION_ROUTING_PROTOCOL));
    }

    #[test]
    fn compute_capabilities_includes_crypto_verifiers() {
        let ids: Vec<u32> = compute_engine_capabilities()
            .iter()
            .map(|c| c.protocol_identifier)
            .collect();
        assert!(ids.contains(&KZG_VERIFY_BLS48581));
        assert!(ids.contains(&BULLETPROOF_RANGE_VERIFY_DECAF448));
        assert!(ids.contains(&SECP256K1_ECDSA_VERIFY));
        assert!(ids.contains(&ED25519_EDDSA_VERIFY));
        assert!(ids.contains(&ED448_EDDSA_VERIFY));
    }

    // -----------------------------------------------------------------
    // MessageKindCompute
    // -----------------------------------------------------------------

    #[test]
    fn all_compute_kinds_have_distinct_type_prefixes() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = MessageKindCompute::all()
            .iter()
            .map(|k| k.type_prefix())
            .collect();
        assert_eq!(ids.len(), 5);
    }

    #[test]
    fn all_compute_kinds_have_distinct_labels() {
        use std::collections::HashSet;
        let labels: HashSet<&str> = MessageKindCompute::all()
            .iter()
            .map(|k| k.label())
            .collect();
        assert_eq!(labels.len(), 5);
    }

    #[test]
    fn peek_compute_message_kind_routes_all_variants() {
        for kind in MessageKindCompute::all() {
            let bytes = kind.type_prefix().to_be_bytes();
            assert_eq!(peek_compute_message_kind(&bytes).unwrap(), kind);
        }
    }

    #[test]
    fn peek_compute_rejects_unknown_prefix() {
        assert!(peek_compute_message_kind(&[0xDE, 0xAD, 0xBE, 0xEF]).is_err());
    }

    // -----------------------------------------------------------------
    // is_compute_op
    // -----------------------------------------------------------------

    #[test]
    fn is_compute_op_positive_for_compute_deploy() {
        assert!(request_is_compute_op(&make_compute_deploy(57, 57, 0, 10)));
    }

    #[test]
    fn is_compute_op_positive_for_code_execute() {
        assert!(request_is_compute_op(&make_code_execute()));
    }

    #[test]
    fn is_compute_op_false_for_none_request() {
        let req = MessageRequest { timestamp: 0, request: None };
        assert!(!request_is_compute_op(&req));
    }

    // -----------------------------------------------------------------
    // Cost
    // -----------------------------------------------------------------

    #[test]
    fn cost_for_compute_deploy_sums_keys_and_schema() {
        let req = make_compute_deploy(57, 57, 585, 100);
        assert_eq!(
            get_cost_from_request(&req, 0).unwrap(),
            BigInt::from(57 + 57 + 585 + 100)
        );
    }

    #[test]
    fn cost_for_code_execute_uses_hint() {
        let req = make_code_execute();
        assert_eq!(get_cost_from_request(&req, 42).unwrap(), BigInt::from(42));
    }

    #[test]
    fn cost_for_non_compute_op_is_zero() {
        let req = MessageRequest { timestamp: 0, request: None };
        assert_eq!(get_cost_from_request(&req, 0).unwrap(), BigInt::from(0));
    }

    // -----------------------------------------------------------------
    // kind_for_request
    // -----------------------------------------------------------------

    #[test]
    fn compute_kind_for_request_maps_code_execute() {
        let req = make_code_execute();
        assert_eq!(
            compute_kind_for_request(&req),
            Some(MessageKindCompute::CodeExecute)
        );
    }

    #[test]
    fn compute_kind_for_request_maps_compute_deploy() {
        let req = make_compute_deploy(0, 0, 0, 0);
        assert_eq!(
            compute_kind_for_request(&req),
            Some(MessageKindCompute::ComputeDeploy)
        );
    }

    #[test]
    fn compute_kind_for_request_returns_none_for_non_compute() {
        let req = MessageRequest { timestamp: 0, request: None };
        assert!(compute_kind_for_request(&req).is_none());
    }
}
