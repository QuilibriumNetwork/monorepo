//! Global execution engine shim — pure dispatch (no state transitions).
//!
//! - [`GLOBAL_CAPABILITIES`] — protocol IDs the global engine advertises.
//! - [`MessageKindGlobal`] — global-op type prefixes this engine routes.
//! - [`peek_global_message_kind`] — u32-BE peek → enum variant.
//! - [`request_is_global_op`] — predicate for `validateBundle` filtering.
//! - [`global_engine_cost`] — always `BigInt::zero()`.
//! - [`global_engine_capabilities`] — construct the capability list.
//!
//! Not ported (needs service wiring + intrinsic state transitions):
//!
//! - `ValidateMessage`, `ProcessMessage`, `handleBundle`,
//!   `processIndividualMessage`, `tryGetIntrinsic` — these all route
//!   through `GlobalIntrinsic`'s `Validate`/`InvokeStep` entry points,
//!   which in turn touch the prover registry, clock store, shards
//!   store, and BLS constructor. None of those have a Rust surface yet.
//! - `Prove` — Go returns unimplemented.
//! - `tryExtractMessageForIntrinsic` — the shard-store-backed `Join`
//!   validation path requires `ShardsStore`.
//!   We still port the non-Join cases in [`request_to_payload`] below.
//! - `Lock` / `Unlock` — wiring needs the global intrinsic.

use num_bigint::BigInt;
use num_traits::Zero;

use quil_types::error::{QuilError, Result};
use quil_types::proto::global::message_request::Request as MessageRequestInner;
use quil_types::proto::global::MessageRequest;
use quil_types::proto::node::Capability;

use crate::hypergraph_engine::{
    DOUBLE_RATCHET_PROTOCOL, ONION_ROUTING_PROTOCOL, TRIPLE_RATCHET_PROTOCOL,
};

// =====================================================================
// Capabilities
// =====================================================================

/// Global protocol v1 identifier. Matches Go:
/// `hypergraph_execution_engine.go:102` for reference, and the
/// constant at `capabilities::GLOBAL_PROTOCOL_V1` in this crate.
pub const GLOBAL_PROTOCOL_V1: u32 = 0x00020001;

/// Construct the ordered capability list this engine advertises.
/// Same four-entry order as the hypergraph engine, but with the first
/// entry switched to the global protocol ID.
pub fn global_engine_capabilities() -> Vec<Capability> {
    vec![
        Capability {
            protocol_identifier: GLOBAL_PROTOCOL_V1,
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
// Cost
// =====================================================================

/// Global engine cost is always zero (prover admin ops are free).
/// Mirror of `GlobalExecutionEngine::GetCost` at line 92.
pub fn global_engine_cost(_message: &[u8]) -> BigInt {
    BigInt::zero()
}

// =====================================================================
// MessageKindGlobal — per-op type prefixes
// =====================================================================
//
// These are the 12 variants the global engine dispatches on. Mirror
// of the 12 case-branches in the Go `tryExtractMessageForIntrinsic`,
// minus any that the Go code rejects as unsupported.

// Re-export type-prefix constants from the canonical-bytes modules
// where they are defined alongside their structs.
pub use crate::global_intrinsic::{
    TYPE_PROVER_JOIN, TYPE_PROVER_LEAVE, TYPE_PROVER_PAUSE,
    TYPE_PROVER_RESUME, TYPE_PROVER_CONFIRM, TYPE_PROVER_REJECT,
    TYPE_PROVER_KICK, TYPE_PROVER_UPDATE, TYPE_SENIORITY_MERGE,
    TYPE_SHARD_SPLIT, TYPE_SHARD_MERGE, TYPE_FRAME_HEADER,
};

/// The set of global operations the engine dispatches on. Each
/// variant maps one-to-one with a `MessageRequest` oneof case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKindGlobal {
    ProverJoin,
    ProverLeave,
    ProverPause,
    ProverResume,
    ProverConfirm,
    ProverReject,
    ProverKick,
    ProverUpdate,
    Shard,
    SeniorityMerge,
    ShardSplit,
    ShardMerge,
}

impl MessageKindGlobal {
    pub const fn type_prefix(self) -> u32 {
        match self {
            Self::ProverJoin => TYPE_PROVER_JOIN,
            Self::ProverLeave => TYPE_PROVER_LEAVE,
            Self::ProverPause => TYPE_PROVER_PAUSE,
            Self::ProverResume => TYPE_PROVER_RESUME,
            Self::ProverConfirm => TYPE_PROVER_CONFIRM,
            Self::ProverReject => TYPE_PROVER_REJECT,
            Self::ProverKick => TYPE_PROVER_KICK,
            Self::ProverUpdate => TYPE_PROVER_UPDATE,
            Self::Shard => TYPE_FRAME_HEADER,
            Self::SeniorityMerge => TYPE_SENIORITY_MERGE,
            Self::ShardSplit => TYPE_SHARD_SPLIT,
            Self::ShardMerge => TYPE_SHARD_MERGE,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::ProverJoin => "prover_join",
            Self::ProverLeave => "prover_leave",
            Self::ProverPause => "prover_pause",
            Self::ProverResume => "prover_resume",
            Self::ProverConfirm => "prover_confirm",
            Self::ProverReject => "prover_reject",
            Self::ProverKick => "prover_kick",
            Self::ProverUpdate => "prover_update",
            Self::Shard => "shard",
            Self::SeniorityMerge => "seniority_merge",
            Self::ShardSplit => "shard_split",
            Self::ShardMerge => "shard_merge",
        }
    }

    pub const fn all() -> [MessageKindGlobal; 12] {
        [
            Self::ProverJoin,
            Self::ProverLeave,
            Self::ProverPause,
            Self::ProverResume,
            Self::ProverConfirm,
            Self::ProverReject,
            Self::ProverKick,
            Self::ProverUpdate,
            Self::Shard,
            Self::SeniorityMerge,
            Self::ShardSplit,
            Self::ShardMerge,
        ]
    }
}

/// Peek at the first 4 bytes of an individual global-op wire message
/// and determine its kind.
pub fn peek_global_message_kind(input: &[u8]) -> Result<MessageKindGlobal> {
    if input.len() < 4 {
        return Err(QuilError::InvalidArgument(
            "global dispatch: input too short to determine type".into(),
        ));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&input[..4]);
    let prefix = u32::from_be_bytes(buf);
    match prefix {
        TYPE_PROVER_JOIN => Ok(MessageKindGlobal::ProverJoin),
        TYPE_PROVER_LEAVE => Ok(MessageKindGlobal::ProverLeave),
        TYPE_PROVER_PAUSE => Ok(MessageKindGlobal::ProverPause),
        TYPE_PROVER_RESUME => Ok(MessageKindGlobal::ProverResume),
        TYPE_PROVER_CONFIRM => Ok(MessageKindGlobal::ProverConfirm),
        TYPE_PROVER_REJECT => Ok(MessageKindGlobal::ProverReject),
        TYPE_PROVER_KICK => Ok(MessageKindGlobal::ProverKick),
        TYPE_PROVER_UPDATE => Ok(MessageKindGlobal::ProverUpdate),
        TYPE_FRAME_HEADER => Ok(MessageKindGlobal::Shard),
        TYPE_SENIORITY_MERGE => Ok(MessageKindGlobal::SeniorityMerge),
        TYPE_SHARD_SPLIT => Ok(MessageKindGlobal::ShardSplit),
        TYPE_SHARD_MERGE => Ok(MessageKindGlobal::ShardMerge),
        other => Err(QuilError::InvalidArgument(format!(
            "global dispatch: unknown type prefix 0x{:08x}",
            other
        ))),
    }
}

// =====================================================================
// is_global_op predicate
// =====================================================================

/// Does this `MessageRequest` carry a global-engine operation?
/// Returns true for any of the 12 prover/shard op type prefixes.
pub fn request_is_global_op(request: &MessageRequest) -> bool {
    matches!(
        request.request,
        Some(MessageRequestInner::Join(_))
            | Some(MessageRequestInner::Leave(_))
            | Some(MessageRequestInner::Pause(_))
            | Some(MessageRequestInner::Resume(_))
            | Some(MessageRequestInner::Confirm(_))
            | Some(MessageRequestInner::Reject(_))
            | Some(MessageRequestInner::Kick(_))
            | Some(MessageRequestInner::Update(_))
            | Some(MessageRequestInner::Shard(_))
            | Some(MessageRequestInner::SeniorityMerge(_))
            | Some(MessageRequestInner::ShardSplit(_))
            | Some(MessageRequestInner::ShardMerge(_))
    )
}

/// Map a `MessageRequest` oneof case to the corresponding
/// `MessageKindGlobal`. Returns `None` for non-global-op requests —
/// token ops, compute ops, hypergraph ops, `None`, etc.
pub fn global_kind_for_request(request: &MessageRequest) -> Option<MessageKindGlobal> {
    match request.request.as_ref()? {
        MessageRequestInner::Join(_) => Some(MessageKindGlobal::ProverJoin),
        MessageRequestInner::Leave(_) => Some(MessageKindGlobal::ProverLeave),
        MessageRequestInner::Pause(_) => Some(MessageKindGlobal::ProverPause),
        MessageRequestInner::Resume(_) => Some(MessageKindGlobal::ProverResume),
        MessageRequestInner::Confirm(_) => Some(MessageKindGlobal::ProverConfirm),
        MessageRequestInner::Reject(_) => Some(MessageKindGlobal::ProverReject),
        MessageRequestInner::Kick(_) => Some(MessageKindGlobal::ProverKick),
        MessageRequestInner::Update(_) => Some(MessageKindGlobal::ProverUpdate),
        MessageRequestInner::Shard(_) => Some(MessageKindGlobal::Shard),
        MessageRequestInner::SeniorityMerge(_) => Some(MessageKindGlobal::SeniorityMerge),
        MessageRequestInner::ShardSplit(_) => Some(MessageKindGlobal::ShardSplit),
        MessageRequestInner::ShardMerge(_) => Some(MessageKindGlobal::ShardMerge),
        _ => None,
    }
}

/// Does this type prefix correspond to a global-engine operation?
pub fn is_global_type_prefix(tp: u32) -> bool {
    matches!(
        tp,
        TYPE_PROVER_JOIN
            | TYPE_PROVER_LEAVE
            | TYPE_PROVER_PAUSE
            | TYPE_PROVER_RESUME
            | TYPE_PROVER_CONFIRM
            | TYPE_PROVER_REJECT
            | TYPE_PROVER_KICK
            | TYPE_PROVER_UPDATE
            | TYPE_FRAME_HEADER
            | TYPE_SENIORITY_MERGE
            | TYPE_SHARD_SPLIT
            | TYPE_SHARD_MERGE
    )
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::global as global_pb;

    fn empty_join() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::Join(global_pb::ProverJoin {
                ..Default::default()
            })),
        }
    }

    fn empty_leave() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::Leave(global_pb::ProverLeave {
                ..Default::default()
            })),
        }
    }

    fn empty_pause() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::Pause(global_pb::ProverPause {
                ..Default::default()
            })),
        }
    }

    fn empty_resume() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::Resume(global_pb::ProverResume {
                ..Default::default()
            })),
        }
    }

    // -----------------------------------------------------------------
    // Capabilities
    // -----------------------------------------------------------------

    #[test]
    fn global_engine_capabilities_has_four_entries() {
        assert_eq!(global_engine_capabilities().len(), 4);
    }

    #[test]
    fn global_engine_capabilities_first_is_global_v1() {
        let caps = global_engine_capabilities();
        assert_eq!(caps[0].protocol_identifier, GLOBAL_PROTOCOL_V1);
    }

    #[test]
    fn global_engine_capabilities_matches_core_capabilities_v1() {
        // GLOBAL_PROTOCOL_V1 here should equal the corresponding
        // constant in `crate::capabilities`.
        assert_eq!(GLOBAL_PROTOCOL_V1, crate::capabilities::GLOBAL_PROTOCOL_V1);
    }

    #[test]
    fn global_engine_capabilities_ids_are_distinct() {
        use std::collections::HashSet;
        let caps = global_engine_capabilities();
        let ids: HashSet<u32> = caps.iter().map(|c| c.protocol_identifier).collect();
        assert_eq!(ids.len(), 4);
    }

    #[test]
    fn global_engine_capabilities_share_ratchets_with_hypergraph() {
        // Double/Triple Ratchet + Onion Routing are common across both
        // engines.
        let caps = global_engine_capabilities();
        let ids: Vec<u32> = caps.iter().map(|c| c.protocol_identifier).collect();
        assert!(ids.contains(&DOUBLE_RATCHET_PROTOCOL));
        assert!(ids.contains(&TRIPLE_RATCHET_PROTOCOL));
        assert!(ids.contains(&ONION_ROUTING_PROTOCOL));
    }

    // -----------------------------------------------------------------
    // Cost
    // -----------------------------------------------------------------

    #[test]
    fn global_engine_cost_is_always_zero() {
        assert_eq!(global_engine_cost(b""), BigInt::zero());
        assert_eq!(global_engine_cost(b"anything"), BigInt::zero());
    }

    // -----------------------------------------------------------------
    // MessageKindGlobal
    // -----------------------------------------------------------------

    #[test]
    fn all_global_kinds_have_distinct_type_prefixes() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = MessageKindGlobal::all()
            .iter()
            .map(|k| k.type_prefix())
            .collect();
        assert_eq!(ids.len(), 12);
    }

    #[test]
    fn all_global_kinds_have_distinct_labels() {
        use std::collections::HashSet;
        let labels: HashSet<&str> =
            MessageKindGlobal::all().iter().map(|k| k.label()).collect();
        assert_eq!(labels.len(), 12);
    }

    #[test]
    fn message_kind_labels_follow_go_snake_case_convention() {
        assert_eq!(MessageKindGlobal::ProverJoin.label(), "prover_join");
        assert_eq!(MessageKindGlobal::ProverLeave.label(), "prover_leave");
        assert_eq!(MessageKindGlobal::ProverPause.label(), "prover_pause");
        assert_eq!(MessageKindGlobal::ProverResume.label(), "prover_resume");
        assert_eq!(MessageKindGlobal::ProverConfirm.label(), "prover_confirm");
        assert_eq!(MessageKindGlobal::ProverReject.label(), "prover_reject");
        assert_eq!(MessageKindGlobal::ProverKick.label(), "prover_kick");
        assert_eq!(MessageKindGlobal::ProverUpdate.label(), "prover_update");
        assert_eq!(MessageKindGlobal::Shard.label(), "shard");
        assert_eq!(
            MessageKindGlobal::SeniorityMerge.label(),
            "seniority_merge"
        );
        assert_eq!(MessageKindGlobal::ShardSplit.label(), "shard_split");
        assert_eq!(MessageKindGlobal::ShardMerge.label(), "shard_merge");
    }

    // -----------------------------------------------------------------
    // peek_global_message_kind
    // -----------------------------------------------------------------

    #[test]
    fn peek_global_message_kind_routes_all_variants() {
        for kind in MessageKindGlobal::all() {
            let bytes = kind.type_prefix().to_be_bytes();
            assert_eq!(peek_global_message_kind(&bytes).unwrap(), kind);
        }
    }

    #[test]
    fn peek_global_message_kind_rejects_short_input() {
        assert!(peek_global_message_kind(&[]).is_err());
        assert!(peek_global_message_kind(&[0u8; 3]).is_err());
    }

    #[test]
    fn peek_global_message_kind_rejects_unknown_prefix() {
        assert!(peek_global_message_kind(&[0xDE, 0xAD, 0xBE, 0xEF]).is_err());
        // Token prover type (doesn't belong to the global engine).
        assert!(peek_global_message_kind(&0x0500u32.to_be_bytes()).is_err());
    }

    // -----------------------------------------------------------------
    // request_is_global_op
    // -----------------------------------------------------------------

    #[test]
    fn is_global_op_positive_for_join_leave_pause_resume() {
        assert!(request_is_global_op(&empty_join()));
        assert!(request_is_global_op(&empty_leave()));
        assert!(request_is_global_op(&empty_pause()));
        assert!(request_is_global_op(&empty_resume()));
    }

    #[test]
    fn is_global_op_false_for_none_request() {
        let req = MessageRequest {
            timestamp: 0,
            request: None,
        };
        assert!(!request_is_global_op(&req));
    }

    #[test]
    fn is_global_op_false_for_hypergraph_op() {
        let req = MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::VertexRemove(
                quil_types::proto::hypergraph::VertexRemove {
                    domain: vec![0u8; 32],
                    data_address: vec![0u8; 32],
                    signature: vec![0u8; 114],
                },
            )),
        };
        assert!(!request_is_global_op(&req));
    }

    // -----------------------------------------------------------------
    // global_kind_for_request
    // -----------------------------------------------------------------

    #[test]
    fn global_kind_for_request_maps_variants() {
        assert_eq!(
            global_kind_for_request(&empty_join()),
            Some(MessageKindGlobal::ProverJoin)
        );
        assert_eq!(
            global_kind_for_request(&empty_leave()),
            Some(MessageKindGlobal::ProverLeave)
        );
        assert_eq!(
            global_kind_for_request(&empty_pause()),
            Some(MessageKindGlobal::ProverPause)
        );
        assert_eq!(
            global_kind_for_request(&empty_resume()),
            Some(MessageKindGlobal::ProverResume)
        );
    }

    #[test]
    fn global_kind_for_request_returns_none_for_non_global() {
        let req = MessageRequest {
            timestamp: 0,
            request: None,
        };
        assert!(global_kind_for_request(&req).is_none());
    }

    // -----------------------------------------------------------------
    // Consistency: peek vs kind_for_request
    // -----------------------------------------------------------------

    #[test]
    fn peek_and_kind_for_request_agree_across_variants() {
        // For each kind variant, confirm the type-prefix encoded from
        // it round-trips through peek.
        for kind in MessageKindGlobal::all() {
            let bytes = kind.type_prefix().to_be_bytes();
            assert_eq!(peek_global_message_kind(&bytes).unwrap(), kind);
        }
    }
}
