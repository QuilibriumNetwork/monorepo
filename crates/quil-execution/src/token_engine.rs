//! Token execution engine shim. Port of the pure dispatch parts of
//! `node/execution/engines/token_execution_engine.go`.
//!
//! - [`token_engine_capabilities`] — the four protocol IDs (token v1,
//!   Double Ratchet, Triple Ratchet, Onion Routing).
//! - [`request_is_token_op`] — boolean predicate for bundle routing.
//! - [`MessageKindToken`] — the five token operation types.
//! - [`get_cost_from_request`] — stub cost dispatch.

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

/// Token protocol v1. Matches
/// `crate::capabilities::TOKEN_PROTOCOL_V1` (0x00040001).
pub const TOKEN_PROTOCOL_V1: u32 = 0x00040001;

pub fn token_engine_capabilities() -> Vec<Capability> {
    vec![
        Capability { protocol_identifier: TOKEN_PROTOCOL_V1, additional_metadata: Vec::new() },
        Capability { protocol_identifier: DOUBLE_RATCHET_PROTOCOL, additional_metadata: Vec::new() },
        Capability { protocol_identifier: TRIPLE_RATCHET_PROTOCOL, additional_metadata: Vec::new() },
        Capability { protocol_identifier: ONION_ROUTING_PROTOCOL, additional_metadata: Vec::new() },
    ]
}

// =====================================================================
// Token op type prefixes (from canonical_types.go)
// =====================================================================

// Re-export from the canonical token_intrinsic modules.
pub use crate::token_intrinsic::{
    TYPE_TOKEN_DEPLOY, TYPE_TOKEN_UPDATE, TYPE_TRANSACTION,
    TYPE_PENDING_TRANSACTION, TYPE_MINT_TRANSACTION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKindToken {
    TokenDeploy,
    TokenUpdate,
    Transaction,
    PendingTransaction,
    MintTransaction,
}

impl MessageKindToken {
    pub const fn type_prefix(self) -> u32 {
        match self {
            Self::TokenDeploy => TYPE_TOKEN_DEPLOY,
            Self::TokenUpdate => TYPE_TOKEN_UPDATE,
            Self::Transaction => TYPE_TRANSACTION,
            Self::PendingTransaction => TYPE_PENDING_TRANSACTION,
            Self::MintTransaction => TYPE_MINT_TRANSACTION,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::TokenDeploy => "token_deploy",
            Self::TokenUpdate => "token_update",
            Self::Transaction => "transaction",
            Self::PendingTransaction => "pending_transaction",
            Self::MintTransaction => "mint_transaction",
        }
    }

    pub const fn all() -> [MessageKindToken; 5] {
        [
            Self::TokenDeploy,
            Self::TokenUpdate,
            Self::Transaction,
            Self::PendingTransaction,
            Self::MintTransaction,
        ]
    }
}

pub fn peek_token_message_kind(input: &[u8]) -> Result<MessageKindToken> {
    if input.len() < 4 {
        return Err(QuilError::InvalidArgument(
            "token dispatch: input too short".into(),
        ));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&input[..4]);
    match u32::from_be_bytes(buf) {
        TYPE_TOKEN_DEPLOY => Ok(MessageKindToken::TokenDeploy),
        TYPE_TOKEN_UPDATE => Ok(MessageKindToken::TokenUpdate),
        TYPE_TRANSACTION => Ok(MessageKindToken::Transaction),
        TYPE_PENDING_TRANSACTION => Ok(MessageKindToken::PendingTransaction),
        TYPE_MINT_TRANSACTION => Ok(MessageKindToken::MintTransaction),
        other => Err(QuilError::InvalidArgument(format!(
            "token dispatch: unknown type prefix 0x{:08x}",
            other
        ))),
    }
}

// =====================================================================
// Is-token-op predicate
// =====================================================================

pub fn request_is_token_op(request: &MessageRequest) -> bool {
    matches!(
        request.request,
        Some(MessageRequestInner::TokenDeploy(_))
            | Some(MessageRequestInner::TokenUpdate(_))
            | Some(MessageRequestInner::Transaction(_))
            | Some(MessageRequestInner::PendingTransaction(_))
            | Some(MessageRequestInner::MintTransaction(_))
    )
}

pub fn token_kind_for_request(
    request: &MessageRequest,
) -> Option<MessageKindToken> {
    match request.request.as_ref()? {
        MessageRequestInner::TokenDeploy(_) => Some(MessageKindToken::TokenDeploy),
        MessageRequestInner::TokenUpdate(_) => Some(MessageKindToken::TokenUpdate),
        MessageRequestInner::Transaction(_) => Some(MessageKindToken::Transaction),
        MessageRequestInner::PendingTransaction(_) => Some(MessageKindToken::PendingTransaction),
        MessageRequestInner::MintTransaction(_) => Some(MessageKindToken::MintTransaction),
        _ => None,
    }
}

// =====================================================================
// Cost dispatch
// =====================================================================

/// Cost for a token `MessageRequest`. Deploy/update cost is the
/// serialized config size. Transaction/pending/mint costs need the
/// inclusion prover (bulletproof tree) — callers pass a hint until
/// that's wired in.
pub fn get_cost_from_request(
    request: &MessageRequest,
    tx_cost_hint: i64,
) -> Result<BigInt> {
    let Some(req) = &request.request else {
        return Ok(BigInt::from(0));
    };

    match req {
        MessageRequestInner::TokenDeploy(d) => {
            // Go calls `Config.ToCanonicalBytes()` and uses its length.
            let size = match &d.config {
                Some(c) => {
                    let tc = crate::token_intrinsic::conversions::token_config_from_proto(c)?;
                    tc.to_canonical_bytes()?.len()
                }
                None => 0,
            };
            Ok(BigInt::from(size as i64))
        }
        MessageRequestInner::TokenUpdate(u) => {
            let size = match &u.config {
                Some(c) => {
                    let tc = crate::token_intrinsic::conversions::token_config_from_proto(c)?;
                    tc.to_canonical_bytes()?.len()
                }
                None => 0,
            };
            Ok(BigInt::from(size as i64))
        }
        MessageRequestInner::Transaction(_)
        | MessageRequestInner::PendingTransaction(_)
        | MessageRequestInner::MintTransaction(_) => {
            Ok(BigInt::from(tx_cost_hint))
        }
        _ => Ok(BigInt::from(0)),
    }
}

/// Does this type prefix correspond to a token-engine operation?
pub fn is_token_type_prefix(tp: u32) -> bool {
    matches!(
        tp,
        TYPE_TOKEN_DEPLOY
            | TYPE_TOKEN_UPDATE
            | TYPE_TRANSACTION
            | TYPE_PENDING_TRANSACTION
            | TYPE_MINT_TRANSACTION
    )
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::token as token_pb;

    fn make_token_deploy() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::TokenDeploy(token_pb::TokenDeploy {
                config: Some(token_pb::TokenConfiguration {
                    owner_public_key: vec![0u8; 585],
                    name: "test".into(),
                    symbol: "TST".into(),
                    ..Default::default()
                }),
                ..Default::default()
            })),
        }
    }

    fn make_transaction() -> MessageRequest {
        MessageRequest {
            timestamp: 0,
            request: Some(MessageRequestInner::Transaction(token_pb::Transaction {
                ..Default::default()
            })),
        }
    }

    #[test]
    fn token_capabilities_has_four_entries() {
        assert_eq!(token_engine_capabilities().len(), 4);
    }

    #[test]
    fn token_capabilities_first_is_token_v1() {
        assert_eq!(
            token_engine_capabilities()[0].protocol_identifier,
            TOKEN_PROTOCOL_V1
        );
        assert_eq!(
            TOKEN_PROTOCOL_V1,
            crate::capabilities::TOKEN_PROTOCOL_V1
        );
    }

    #[test]
    fn all_token_kinds_have_distinct_type_prefixes() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = MessageKindToken::all()
            .iter()
            .map(|k| k.type_prefix())
            .collect();
        assert_eq!(ids.len(), 5);
    }

    #[test]
    fn peek_token_message_kind_routes_all_variants() {
        for kind in MessageKindToken::all() {
            let bytes = kind.type_prefix().to_be_bytes();
            assert_eq!(peek_token_message_kind(&bytes).unwrap(), kind);
        }
    }

    #[test]
    fn is_token_op_positive_for_token_deploy() {
        assert!(request_is_token_op(&make_token_deploy()));
    }

    #[test]
    fn is_token_op_positive_for_transaction() {
        assert!(request_is_token_op(&make_transaction()));
    }

    #[test]
    fn is_token_op_false_for_none_request() {
        let req = MessageRequest { timestamp: 0, request: None };
        assert!(!request_is_token_op(&req));
    }

    #[test]
    fn token_kind_for_request_maps_transaction() {
        assert_eq!(
            token_kind_for_request(&make_transaction()),
            Some(MessageKindToken::Transaction)
        );
    }

    #[test]
    fn cost_for_token_deploy_uses_canonical_bytes_length() {
        let req = make_token_deploy();
        let cost = get_cost_from_request(&req, 0).unwrap();
        // Uses TokenConfiguration::to_canonical_bytes().len() which
        // includes type prefix + length-prefixed fields. The exact
        // value is deterministic now.
        assert!(cost > BigInt::from(0));
        // Verify it's the actual canonical bytes size by computing it
        // independently.
        let config = req.request.as_ref().unwrap();
        if let MessageRequestInner::TokenDeploy(d) = config {
            let tc = crate::token_intrinsic::conversions::token_config_from_proto(
                d.config.as_ref().unwrap(),
            )
            .unwrap();
            let expected = BigInt::from(tc.to_canonical_bytes().unwrap().len() as i64);
            assert_eq!(cost, expected);
        }
    }

    #[test]
    fn cost_for_transaction_uses_hint() {
        let req = make_transaction();
        assert_eq!(get_cost_from_request(&req, 50).unwrap(), BigInt::from(50));
    }

    #[test]
    fn cost_for_non_token_is_zero() {
        let req = MessageRequest { timestamp: 0, request: None };
        assert_eq!(get_cost_from_request(&req, 0).unwrap(), BigInt::from(0));
    }
}
