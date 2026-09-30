//! Token execution engine shim. Port of the pure dispatch parts of
//! `node/execution/engines/token_execution_engine.go`.
//!
//! - [`token_engine_capabilities`] — the four protocol IDs (token v1,
//! Double Ratchet, Triple Ratchet, Onion Routing).
//! - [`request_is_token_op`] — boolean predicate for bundle routing.
//! - [`MessageKindToken`] — the eight active token operation types.
//! - [`get_cost_from_request`] — administrative token cost dispatch.

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
    TYPE_PENDING_TRANSACTION, TYPE_MINT_TRANSACTION, TYPE_LATTICE_TRANSACTION, TYPE_LATTICE_MINT, TYPE_LATTICE_PENDING, TYPE_LATTICE_PENDING_CLAIM, TYPE_LATTICE_SHIELD, TYPE_LATTICE_MINT_CLAIM, TYPE_LATTICE_SETTLEMENT,
};

/// Structural classification only; this does not validate payloads or proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKindToken {
    TokenDeploy,
    TokenUpdate,
    Transfer,
    Mint,
    PendingCreate,
    PendingClaim,
    Shield,
    MintClaim,
    Settlement,
}

impl MessageKindToken {
    pub const fn type_prefix(self) -> u32 {
        match self {
            Self::TokenDeploy => TYPE_TOKEN_DEPLOY,
            Self::TokenUpdate => TYPE_TOKEN_UPDATE,
            Self::Transfer => TYPE_LATTICE_TRANSACTION,
            Self::Mint => TYPE_LATTICE_MINT,
            Self::PendingCreate => TYPE_LATTICE_PENDING,
            Self::PendingClaim => TYPE_LATTICE_PENDING_CLAIM,
            Self::Shield => TYPE_LATTICE_SHIELD,
            Self::MintClaim => TYPE_LATTICE_MINT_CLAIM,
            Self::Settlement => TYPE_LATTICE_SETTLEMENT,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::TokenDeploy => "token_deploy",
            Self::TokenUpdate => "token_update",
            Self::Transfer => "transfer",
            Self::Mint => "mint",
            Self::PendingCreate => "pending_create",
            Self::PendingClaim => "pending_claim",
            Self::Shield => "shield",
            Self::MintClaim => "mint_claim",
            Self::Settlement => "settlement",
        }
    }

    pub const fn all() -> [MessageKindToken; 9] {
        [
            Self::TokenDeploy,
            Self::TokenUpdate,
            Self::Transfer,
            Self::Mint,
            Self::PendingCreate,
            Self::PendingClaim,
            Self::Shield,
            Self::MintClaim,
            Self::Settlement,
        ]
    }
}

/// Classify an active operation by its prefix. Retired IDs are deliberately
/// rejected here, but remain recognized by `is_token_type_prefix` so execution
/// routes them to explicit rejection rather than silently skipping them.
pub fn peek_token_message_kind(input: &[u8]) -> Result<MessageKindToken> {
    let prefix: [u8; 4] = input.get(..4).ok_or_else(||
        QuilError::InvalidArgument("token dispatch: input too short".into()))?
        .try_into().expect("checked prefix length");
    match u32::from_be_bytes(prefix) {
        TYPE_TOKEN_DEPLOY => Ok(MessageKindToken::TokenDeploy),
        TYPE_TOKEN_UPDATE => Ok(MessageKindToken::TokenUpdate),
        TYPE_LATTICE_TRANSACTION => Ok(MessageKindToken::Transfer),
        TYPE_LATTICE_MINT => Ok(MessageKindToken::Mint),
        TYPE_LATTICE_PENDING => Ok(MessageKindToken::PendingCreate),
        TYPE_LATTICE_PENDING_CLAIM => Ok(MessageKindToken::PendingClaim),
        TYPE_LATTICE_SHIELD => Ok(MessageKindToken::Shield),
        TYPE_LATTICE_MINT_CLAIM => Ok(MessageKindToken::MintClaim),
        TYPE_LATTICE_SETTLEMENT => Ok(MessageKindToken::Settlement),
        TYPE_TRANSACTION | TYPE_PENDING_TRANSACTION | TYPE_MINT_TRANSACTION =>
            Err(QuilError::InvalidArgument("token dispatch: retired token type".into())),
        other => Err(QuilError::InvalidArgument(format!(
            "token dispatch: unknown type prefix 0x{:08x}", other))),
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
            | Some(MessageRequestInner::TokenOperation(_))
    )
}

pub fn token_kind_for_request(
    request: &MessageRequest,
) -> Option<MessageKindToken> {
    match request.request.as_ref()? {
        MessageRequestInner::TokenDeploy(_) => Some(MessageKindToken::TokenDeploy),
        MessageRequestInner::TokenUpdate(_) => Some(MessageKindToken::TokenUpdate),
        MessageRequestInner::TokenOperation(op) => {
            match peek_token_message_kind(&op.canonical_bytes).ok()? {
                MessageKindToken::TokenDeploy | MessageKindToken::TokenUpdate => None,
                kind => Some(kind),
            }
        }
        _ => None,
    }
}

// =====================================================================
// Cost dispatch
// =====================================================================

/// Cost for a token `MessageRequest`. Deploy/update cost is the
/// serialized config size. QCT3 payload pricing is handled by the
/// execution manager; this helper does not price confidential operations.
pub fn get_cost_from_request(
    request: &MessageRequest,
    _tx_cost_hint: i64,
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
            | TYPE_LATTICE_TRANSACTION
            | TYPE_LATTICE_MINT
            | TYPE_LATTICE_PENDING
            | TYPE_LATTICE_PENDING_CLAIM
            | TYPE_LATTICE_SHIELD
            | TYPE_LATTICE_MINT_CLAIM
            | TYPE_LATTICE_SETTLEMENT
            | crate::token_intrinsic::constants::TYPE_COIN_DELIVERY
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
            request: Some(MessageRequestInner::TokenOperation(token_pb::TokenOperation {
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
        assert_eq!(ids.len(), MessageKindToken::all().len());
    }

    #[test]
    fn peek_token_message_kind_routes_all_variants() {
        for kind in MessageKindToken::all() {
            let bytes = kind.type_prefix().to_be_bytes();
            assert_eq!(peek_token_message_kind(&bytes).unwrap(), kind);
        }
    }

    #[test]
    fn retired_prefixes_remain_routed_to_rejection() {
        for prefix in [TYPE_TRANSACTION, TYPE_PENDING_TRANSACTION, TYPE_MINT_TRANSACTION] {
            assert!(is_token_type_prefix(prefix));
            assert!(peek_token_message_kind(&prefix.to_be_bytes()).is_err());
        }
        assert!(peek_token_message_kind(&[0; 3]).is_err());
        assert!(peek_token_message_kind(&u32::MAX.to_be_bytes()).is_err());
    }

    #[test]
    fn confidential_carrier_classifies_only_current_confidential_operations() {
        for kind in MessageKindToken::all() {
            let request = MessageRequest { timestamp: 0,
                request: Some(MessageRequestInner::TokenOperation(token_pb::TokenOperation {
                    canonical_bytes: kind.type_prefix().to_be_bytes().to_vec(),
                })),
            };
            let expected = match kind {
                MessageKindToken::TokenDeploy | MessageKindToken::TokenUpdate => None,
                _ => Some(kind),
            };
            assert_eq!(token_kind_for_request(&request), expected);
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
    fn empty_confidential_carrier_has_no_kind() {
        assert_eq!(
            token_kind_for_request(&make_transaction()),
            None
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
    fn cost_for_non_token_is_zero() {
        let req = MessageRequest { timestamp: 0, request: None };
        assert_eq!(get_cost_from_request(&req, 0).unwrap(), BigInt::from(0));
    }
}
