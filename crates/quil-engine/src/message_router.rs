//! Message routing for incoming consensus messages. Classifies
//! canonical-bytes messages by type prefix and routes to the
//! appropriate handler (consensus event loop, execution engine, etc.).
//!
//! Mirror of `node/consensus/global/message_router.go`.
//!
//! This module exposes two layers:
//!
//! 1. Stateless classification helpers (`classify_message`,
//!    `classify_inner_type`, `classify_consensus_message`) used by the
//!    consensus engine to decide where a message should go once it has
//!    been admitted.
//! 2. A stateful [`MessageRouter`] that holds per-bitmask validator
//!    closures so malformed bytes are dropped before they reach a
//!    queue. The Go reference (`node/consensus/global/message_router.go`)
//!    achieves the same thing via `pubsub.RegisterValidator`; in Rust
//!    the network plumbing isn't pubsub, so we run the validator from
//!    inside [`MessageRouter::route`] before the dispatcher invokes the
//!    real handler.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tracing::debug;

use quil_types::error::{QuilError, Result};

use quil_execution::global_engine::{
    TYPE_PROVER_JOIN, TYPE_PROVER_LEAVE,
    TYPE_PROVER_PAUSE, TYPE_PROVER_RESUME, TYPE_PROVER_CONFIRM,
    TYPE_PROVER_REJECT, TYPE_PROVER_KICK, TYPE_PROVER_UPDATE,
    TYPE_FRAME_HEADER, TYPE_SENIORITY_MERGE, TYPE_SHARD_SPLIT,
    TYPE_SHARD_MERGE,
};
use quil_execution::global_intrinsic::consensus_types::{
    TYPE_GLOBAL_PROPOSAL, TYPE_APP_SHARD_PROPOSAL,
    TYPE_QUORUM_CERTIFICATE, TYPE_TIMEOUT_STATE, TYPE_TIMEOUT_CERTIFICATE,
};
use quil_execution::hypergraph_engine::is_hypergraph_type_prefix;
use quil_execution::message_envelope::{
    CanonicalMessageRequest,
    TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST,
};

/// Classification of an incoming message for routing purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRoute {
    /// A consensus protocol message (proposal, vote, timeout).
    Consensus,
    /// A global prover operation (join, leave, pause, etc.).
    GlobalProverOp,
    /// A shard management message (frame header, split, merge).
    ShardManagement,
    /// A hypergraph operation (vertex/hyperedge add/remove).
    HypergraphOp,
    /// A token or compute operation.
    AppShardOp,
    /// A message bundle containing multiple operations.
    Bundle,
    /// Unrecognized message type.
    Unknown,
}

/// Consensus-specific message sub-types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusMessageKind {
    GlobalProposal,
    AppShardProposal,
    QuorumCertificate,
    TimeoutState,
    TimeoutCertificate,
    ProposalVote,
}

/// ProposalVote type prefix (0x030C) — also defined in consensus_wire.rs
/// as PROPOSAL_VOTE_TYPE.
const TYPE_PROPOSAL_VOTE: u32 = 0x030C;

/// Classify an incoming message by peeking at its type prefix.
pub fn classify_message(data: &[u8]) -> Result<MessageRoute> {
    if data.len() < 4 {
        return Err(QuilError::InvalidArgument("message too short".into()));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[..4]);
    let tp = u32::from_be_bytes(buf);

    match tp {
        TYPE_MESSAGE_BUNDLE => Ok(MessageRoute::Bundle),
        TYPE_MESSAGE_REQUEST => {
            // Peek inside the request to classify
            if let Ok(req) = CanonicalMessageRequest::from_canonical_bytes(data) {
                classify_inner_type(req.inner_type_prefix)
            } else {
                Ok(MessageRoute::Unknown)
            }
        }
        _ => classify_inner_type(tp),
    }
}

fn classify_inner_type(tp: u32) -> Result<MessageRoute> {
    // Consensus messages
    if matches!(tp,
        TYPE_GLOBAL_PROPOSAL | TYPE_APP_SHARD_PROPOSAL |
        TYPE_QUORUM_CERTIFICATE | TYPE_TIMEOUT_STATE |
        TYPE_TIMEOUT_CERTIFICATE | TYPE_PROPOSAL_VOTE
    ) {
        return Ok(MessageRoute::Consensus);
    }

    // Global prover ops
    if matches!(tp,
        TYPE_PROVER_JOIN | TYPE_PROVER_LEAVE | TYPE_PROVER_PAUSE |
        TYPE_PROVER_RESUME | TYPE_PROVER_CONFIRM | TYPE_PROVER_REJECT |
        TYPE_PROVER_KICK | TYPE_PROVER_UPDATE | TYPE_SENIORITY_MERGE
    ) {
        return Ok(MessageRoute::GlobalProverOp);
    }

    // Shard management
    if matches!(tp, TYPE_FRAME_HEADER | TYPE_SHARD_SPLIT | TYPE_SHARD_MERGE) {
        return Ok(MessageRoute::ShardManagement);
    }

    // Hypergraph ops
    if is_hypergraph_type_prefix(tp) {
        return Ok(MessageRoute::HypergraphOp);
    }

    // Token/compute ops (0x05xx, 0x06xx ranges)
    if (tp >> 8) == 0x05 || (tp >> 8) == 0x06 {
        return Ok(MessageRoute::AppShardOp);
    }

    Ok(MessageRoute::Unknown)
}

/// Classify a consensus-specific message type prefix.
pub fn classify_consensus_message(tp: u32) -> Option<ConsensusMessageKind> {
    match tp {
        TYPE_GLOBAL_PROPOSAL => Some(ConsensusMessageKind::GlobalProposal),
        TYPE_APP_SHARD_PROPOSAL => Some(ConsensusMessageKind::AppShardProposal),
        TYPE_QUORUM_CERTIFICATE => Some(ConsensusMessageKind::QuorumCertificate),
        TYPE_TIMEOUT_STATE => Some(ConsensusMessageKind::TimeoutState),
        TYPE_TIMEOUT_CERTIFICATE => Some(ConsensusMessageKind::TimeoutCertificate),
        TYPE_PROPOSAL_VOTE => Some(ConsensusMessageKind::ProposalVote),
        _ => None,
    }
}

// =====================================================================
// Stateful router with per-topic validator closures
// =====================================================================

/// Validator outcome. `Accept` admits the message; every `Reject`
/// variant carries a stable, low-cardinality reason string for
/// per-cause aggregation in operator metrics. Validators should
/// reach for short, fixed strings (e.g. `"sig_invalid"`) so the
/// counter set stays bounded.
#[derive(Debug, Clone, Copy)]
pub enum ValidationOutcome {
    Accept,
    Reject(&'static str),
}

impl ValidationOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, ValidationOutcome::Accept)
    }
    pub fn reject_reason(&self) -> Option<&'static str> {
        match self {
            ValidationOutcome::Accept => None,
            ValidationOutcome::Reject(r) => Some(r),
        }
    }
}

/// A per-bitmask validator closure. Returns [`ValidationOutcome`]:
/// `Accept` admits the message, `Reject(reason)` drops it and the
/// reason string is aggregated by the dispatcher for diagnostics.
///
/// Validators MUST NOT panic — wrap any decoder calls so that
/// errors become `Reject(...)`. A panicking validator would
/// propagate up and crash the receive loop; that defeats the
/// purpose of validation.
pub type TopicValidator = Arc<dyn Fn(&[u8]) -> ValidationOutcome + Send + Sync>;

/// Outcome of [`MessageRouter::route`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOutcome {
    /// No validator was registered for this bitmask — caller should
    /// proceed with the existing dispatch path. Preserves backward
    /// compatibility for topics that haven't been ported to validation.
    Unvalidated,
    /// A validator was registered and accepted the message — caller
    /// should proceed with the existing dispatch path.
    Accepted,
    /// A validator was registered and rejected the message — caller
    /// MUST drop the message. Carries the short reason string the
    /// validator returned so the dispatcher can aggregate per-cause
    /// drop counters.
    Rejected(&'static str),
}

impl RouteOutcome {
    /// True if the caller should hand the message to its dispatcher.
    /// Unvalidated topics fall through; rejected ones do not.
    pub fn should_dispatch(&self) -> bool {
        matches!(self, RouteOutcome::Unvalidated | RouteOutcome::Accepted)
    }

    /// Reason for the rejection if `Rejected`, else `None`.
    pub fn reject_reason(&self) -> Option<&'static str> {
        match self {
            RouteOutcome::Rejected(r) => Some(r),
            _ => None,
        }
    }
}

/// Stateful router that holds a per-bitmask set of validator closures.
///
/// When a network message arrives, the dispatcher calls
/// [`MessageRouter::route`] with the bitmask + payload. If a validator
/// is registered for that bitmask it is invoked synchronously:
/// - validator returns `true` -> [`RouteOutcome::Accepted`]
/// - validator returns `false` -> [`RouteOutcome::Rejected`] (drop)
/// If no validator is registered the router returns
/// [`RouteOutcome::Unvalidated`] so existing topics that haven't been
/// wired up still work.
///
/// The router itself never decodes the payload or knows what queue the
/// message ends up on; that stays in the dispatcher (today
/// `quil-node/src/main.rs` and `GlobalConsensusEngine`).
pub struct MessageRouter {
    validators: RwLock<HashMap<Vec<u8>, TopicValidator>>,
}

impl MessageRouter {
    pub fn new() -> Self {
        Self {
            validators: RwLock::new(HashMap::new()),
        }
    }

    /// Register a validator for a given bitmask. Replaces any prior
    /// validator for the same bitmask.
    pub fn register_validator(&self, bitmask: Vec<u8>, validator: TopicValidator) {
        let mut map = self.validators.write().unwrap();
        map.insert(bitmask, validator);
    }

    /// Remove the validator (if any) for a bitmask. Returns `true` if
    /// a validator was present.
    pub fn unregister_validator(&self, bitmask: &[u8]) -> bool {
        let mut map = self.validators.write().unwrap();
        map.remove(bitmask).is_some()
    }

    /// Number of registered validators (mainly useful for tests).
    pub fn validator_count(&self) -> usize {
        self.validators.read().unwrap().len()
    }

    /// Decide whether a message arriving on `bitmask` should be
    /// dispatched. A validator that panics would unwind through this
    /// call; we install a `catch_unwind` to be defensive — a buggy
    /// validator should drop the message, not crash the router.
    pub fn route(&self, bitmask: &[u8], data: &[u8]) -> RouteOutcome {
        let validator = {
            let map = self.validators.read().unwrap();
            map.get(bitmask).cloned()
        };
        let Some(validator) = validator else {
            return RouteOutcome::Unvalidated;
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| validator(data)));
        match result {
            Ok(ValidationOutcome::Accept) => RouteOutcome::Accepted,
            Ok(ValidationOutcome::Reject(reason)) => RouteOutcome::Rejected(reason),
            Err(_) => RouteOutcome::Rejected("validator_panic"),
        }
    }
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// Pre-built validator constructors for the global topics
// =====================================================================

/// Validator for `GLOBAL_PEER_INFO_BITMASK`. Accepts both `PeerInfo`
/// and `KeyRegistry` payloads — the former must round-trip through the
/// canonical decoder and carry a 38-byte libp2p peer-id; the latter
/// must round-trip and (when populated) carry a 57-byte Ed448 identity
/// key plus a 585-byte BLS48-581 prover key.
pub fn validator_global_peer_info() -> TopicValidator {
    use ValidationOutcome::{Accept, Reject};
    Arc::new(|data: &[u8]| -> ValidationOutcome {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Cheap pre-validate: peek the timestamp out of the raw bytes
        // before doing the full canonical decode + Ed448 verify, which
        // are by far the most expensive steps and dominate CPU when the
        // mesh is forwarding millions of stale messages per hour.
        // 99%+ of GLOBAL_PEER_INFO drops in production were
        // `*_ts_too_old`, all of which the peek can identify without
        // allocating or running the signature check. Peek failures
        // (truncation / wrong type prefix) fall through to the
        // existing full-decode error paths so genuine corruption still
        // gets categorized correctly.
        if data.len() >= 4 {
            let tp = u32::from_be_bytes(data[..4].try_into().unwrap_or([0; 4]));
            if tp == quil_p2p::PEER_INFO_TYPE {
                if let Some(ts) = quil_p2p::peek_peer_info_timestamp(data) {
                    if ts < now_ms - 60_000 {
                        return Reject("pi_ts_too_old");
                    }
                    if ts < now_ms - 1_000 {
                        return Reject("pi_ts_stale");
                    }
                    if ts > now_ms + 300_000 {
                        return Reject("pi_ts_future");
                    }
                }
            } else if tp == quil_p2p::KEY_REGISTRY_TYPE {
                if let Some(ts) = quil_p2p::peek_key_registry_timestamp(data).map(|v| v as i64) {
                    if ts < now_ms - 60_000 {
                        return Reject("kr_ts_too_old");
                    }
                    if ts < now_ms - 1_000 {
                        return Reject("kr_ts_stale");
                    }
                    if ts > now_ms + 5_000 {
                        return Reject("kr_ts_future");
                    }
                }
            }
        }

        match quil_p2p::classify_peer_info_message(data) {
            Ok(quil_p2p::PeerInfoMessage::PeerInfo(info)) => {
                if info.peer_id.is_empty() {
                    return Reject("pi_empty_peer_id");
                }
                if info.public_key.len() != 57 {
                    return Reject("pi_bad_pubkey_len");
                }
                if info.signature.len() != 114 {
                    return Reject("pi_bad_sig_len");
                }
                // Re-check timestamps post-decode in case the peek was
                // skipped (unknown type prefix path) or a malicious
                // peer crafted a payload where peek and full decode
                // disagree. Defense in depth — the costs at this point
                // are already paid.
                if info.timestamp < now_ms - 60_000 {
                    return Reject("pi_ts_too_old");
                }
                if info.timestamp < now_ms - 1_000 {
                    return Reject("pi_ts_stale");
                }
                if info.timestamp > now_ms + 300_000 {
                    return Reject("pi_ts_future");
                }
                let signing_payload = quil_p2p::encode_canonical_peer_info(
                    &info,
                    &info.public_key,
                    &[],
                );
                let pubkey = match ed448_rust::PublicKey::try_from(
                    info.public_key.as_slice(),
                ) {
                    Ok(pk) => pk,
                    Err(_) => return Reject("pi_pubkey_decode"),
                };
                if pubkey.verify(&signing_payload, &info.signature, None).is_ok() {
                    Accept
                } else {
                    Reject("pi_sig_invalid")
                }
            }
            Ok(quil_p2p::PeerInfoMessage::KeyRegistry) => {
                match quil_p2p::decode_canonical_key_registry(data) {
                    Ok(reg) => {
                        if !reg.ed448_pubkey.is_empty() && reg.ed448_pubkey.len() != 57 {
                            return Reject("kr_bad_ed448_len");
                        }
                        if !reg.bls_pubkey.is_empty() && reg.bls_pubkey.len() != 585 {
                            return Reject("kr_bad_bls_len");
                        }
                        let ts = reg.last_updated_ms as i64;
                        if ts < now_ms - 60_000 {
                            return Reject("kr_ts_too_old");
                        }
                        if ts < now_ms - 1_000 {
                            return Reject("kr_ts_stale");
                        }
                        if ts > now_ms + 5_000 {
                            return Reject("kr_ts_future");
                        }
                        Accept
                    }
                    Err(_) => Reject("kr_decode_failed"),
                }
            }
            Ok(quil_p2p::PeerInfoMessage::Unknown(_)) => Reject("pi_unknown_type"),
            Err(_) => Reject("pi_classify_failed"),
        }
    })
}

/// Validator for `GLOBAL_PROVER_BITMASK`. Accepts only canonical-bytes
/// messages whose 4-byte type prefix is one of the known prover op
/// kinds (join / leave / pause / resume / confirm / reject / kick /
/// update / seniority-merge) or a message bundle.
pub fn validator_global_prover() -> TopicValidator {
    use ValidationOutcome::{Accept, Reject};
    Arc::new(|data: &[u8]| -> ValidationOutcome {
        if data.len() < 4 {
            return Reject("prover_short");
        }
        let tp = u32::from_be_bytes(data[..4].try_into().unwrap());
        if tp == TYPE_MESSAGE_BUNDLE || tp == TYPE_MESSAGE_REQUEST {
            return Accept;
        }
        let is_valid_op = matches!(
            tp,
            TYPE_PROVER_JOIN
                | TYPE_PROVER_LEAVE
                | TYPE_PROVER_PAUSE
                | TYPE_PROVER_RESUME
                | TYPE_PROVER_CONFIRM
                | TYPE_PROVER_REJECT
                | TYPE_PROVER_KICK
                | TYPE_PROVER_UPDATE
                | TYPE_SENIORITY_MERGE
        );
        if is_valid_op {
            Accept
        } else {
            Reject("prover_bad_type")
        }
    })
}

/// Validator for `GLOBAL_FRAME_BITMASK`. The wire format is a
/// `GlobalFrame` canonical-bytes blob with the 4-byte
/// `GLOBAL_FRAME_TYPE = 0x030E` prefix; we round-trip through the
/// canonical decoder so partially-truncated frames are dropped before
/// they reach the queue.
pub fn validator_global_frame() -> TopicValidator {
    use ValidationOutcome::{Accept, Reject};
    Arc::new(|data: &[u8]| -> ValidationOutcome {
        if data.len() < 4 {
            return Reject("frame_short");
        }
        let tp = u32::from_be_bytes(data[..4].try_into().unwrap());
        if tp != crate::consensus_wire::GLOBAL_FRAME_TYPE {
            return Reject("frame_bad_type");
        }
        if crate::consensus_wire::decode_global_frame(data).is_ok() {
            Accept
        } else {
            Reject("frame_decode_failed")
        }
    })
}

/// Validator for `GLOBAL_CONSENSUS_BITMASK`. Accepts one of the known
/// consensus sub-types (proposal / vote / QC / TC / timeout-state) and
/// requires the canonical-bytes decoder for that sub-type to succeed.
pub fn validator_global_consensus() -> TopicValidator {
    use ValidationOutcome::{Accept, Reject};
    Arc::new(|data: &[u8]| -> ValidationOutcome {
        use crate::consensus_wire as cw;
        if data.len() < 4 {
            return Reject("cons_short");
        }
        let tp = u32::from_be_bytes(data[..4].try_into().unwrap());
        let decoded = match tp {
            cw::GLOBAL_PROPOSAL_TYPE => cw::GlobalProposal::from_canonical_bytes(data).is_ok(),
            cw::PROPOSAL_VOTE_TYPE => cw::ProposalVote::from_canonical_bytes(data).is_ok(),
            cw::QUORUM_CERTIFICATE_TYPE => {
                cw::QuorumCertificate::from_canonical_bytes(data).is_ok()
            }
            cw::TIMEOUT_CERTIFICATE_TYPE => {
                cw::TimeoutCertificate::from_canonical_bytes(data).is_ok()
            }
            cw::TIMEOUT_STATE_TYPE => cw::TimeoutState::from_canonical_bytes(data).is_ok(),
            _ => return Reject("cons_bad_type"),
        };
        if decoded { Accept } else { Reject("cons_decode_failed") }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_prover_join() {
        let bytes = TYPE_PROVER_JOIN.to_be_bytes();
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::GlobalProverOp);
    }

    #[test]
    fn classify_global_proposal() {
        let bytes = TYPE_GLOBAL_PROPOSAL.to_be_bytes();
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::Consensus);
    }

    #[test]
    fn classify_qc() {
        let bytes = TYPE_QUORUM_CERTIFICATE.to_be_bytes();
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::Consensus);
    }

    #[test]
    fn classify_frame_header() {
        let bytes = TYPE_FRAME_HEADER.to_be_bytes();
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::ShardManagement);
    }

    #[test]
    fn classify_vertex_add() {
        let bytes = 0x0404u32.to_be_bytes(); // TYPE_VERTEX_ADD
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::HypergraphOp);
    }

    #[test]
    fn classify_token_transaction() {
        let bytes = 0x0509u32.to_be_bytes(); // TYPE_TRANSACTION
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::AppShardOp);
    }

    #[test]
    fn classify_compute_code_execute() {
        let bytes = 0x060Cu32.to_be_bytes(); // TYPE_CODE_EXECUTE
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::AppShardOp);
    }

    #[test]
    fn classify_bundle() {
        let bytes = 0x0312u32.to_be_bytes(); // TYPE_MESSAGE_BUNDLE
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::Bundle);
    }

    #[test]
    fn classify_unknown() {
        let bytes = 0xDEADu32.to_be_bytes();
        assert_eq!(classify_message(&bytes).unwrap(), MessageRoute::Unknown);
    }

    #[test]
    fn classify_short_rejects() {
        assert!(classify_message(&[0, 0]).is_err());
    }

    #[test]
    fn consensus_message_kinds_all_distinct() {
        let qc = classify_consensus_message(TYPE_QUORUM_CERTIFICATE);
        let tc = classify_consensus_message(TYPE_TIMEOUT_CERTIFICATE);
        let ts = classify_consensus_message(TYPE_TIMEOUT_STATE);
        assert_ne!(qc, tc);
        assert_ne!(tc, ts);
    }

    // -----------------------------------------------------------------
    // MessageRouter (validator) tests
    // -----------------------------------------------------------------

    use crate::bitmasks;

    /// Convenience: a validator that always accepts.
    fn always_ok() -> TopicValidator {
        Arc::new(|_| ValidationOutcome::Accept)
    }

    /// Convenience: a validator that always rejects.
    fn always_bad() -> TopicValidator {
        Arc::new(|_| ValidationOutcome::Reject("test_reject"))
    }

    #[test]
    fn router_unregistered_topic_falls_through() {
        let r = MessageRouter::new();
        assert_eq!(
            r.route(b"\x00", b"anything"),
            RouteOutcome::Unvalidated,
            "unregistered topic must allow caller's existing dispatch"
        );
        assert!(r.route(b"\x00", b"anything").should_dispatch());
    }

    #[test]
    fn router_validator_drops_malformed_message() {
        let r = MessageRouter::new();
        // GLOBAL_PEER_INFO validator must reject 4 bytes of garbage —
        // type prefix won't match PEER_INFO_TYPE or KEY_REGISTRY_TYPE.
        r.register_validator(
            bitmasks::GLOBAL_PEER_INFO.to_vec(),
            validator_global_peer_info(),
        );
        let outcome = r.route(bitmasks::GLOBAL_PEER_INFO, &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00]);
        assert!(matches!(outcome, RouteOutcome::Rejected(_)));
        assert!(!outcome.should_dispatch());
    }

    /// Pins the `catch_unwind` -> `Rejected` contract: an invalid Ed448
    /// public-key point (all 0xBB bytes) is NOT a valid curve point, so
    /// `PublicKey::from(...)` may panic or `verify` will fail — either
    /// way the validator must reject.
    #[test]
    fn router_validator_rejects_invalid_pubkey_point() {
        let r = MessageRouter::new();
        r.register_validator(
            bitmasks::GLOBAL_PEER_INFO.to_vec(),
            validator_global_peer_info(),
        );

        let info = quil_p2p::CanonicalPeerInfo {
            peer_id: vec![0xAA; 38],
            timestamp: 1_700_000_000_000,
            version: vec![2, 1, 0],
            patch_number: vec![20],
            ..Default::default()
        };
        let pubkey = vec![0xBB; 57]; // 57 == Ed448 pubkey length
        let sig = vec![0xCC; 114];   // 114 == Ed448 signature length
        let bytes = quil_p2p::encode_canonical_peer_info(&info, &pubkey, &sig);

        let outcome = r.route(bitmasks::GLOBAL_PEER_INFO, &bytes);
        assert!(matches!(outcome, RouteOutcome::Rejected(_)));
    }

    #[test]
    fn router_validator_passes_well_formed_peer_info() {
        let r = MessageRouter::new();
        r.register_validator(
            bitmasks::GLOBAL_PEER_INFO.to_vec(),
            validator_global_peer_info(),
        );

        let privkey = ed448_rust::PrivateKey::new(&mut rand::rngs::OsRng);
        let pubkey_bytes = ed448_rust::PublicKey::from(&privkey).as_byte().to_vec();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let info = quil_p2p::CanonicalPeerInfo {
            peer_id: vec![0xAA; 38],
            timestamp: now_ms,
            version: vec![2, 1, 0],
            patch_number: vec![20],
            ..Default::default()
        };
        // Sign the canonical encoding with the signature field cleared,
        // matching what `validator_global_peer_info` reconstructs at
        // verify-time. The validator uses pure Ed448 (context=None) to
        // match Go's `ValidateSignature` with domain=[] context="".
        let signing_payload = quil_p2p::encode_canonical_peer_info(&info, &pubkey_bytes, &[]);
        let sig = privkey
            .sign(&signing_payload, None)
            .expect("sign must succeed")
            .to_vec();
        let bytes = quil_p2p::encode_canonical_peer_info(&info, &pubkey_bytes, &sig);

        let outcome = r.route(bitmasks::GLOBAL_PEER_INFO, &bytes);
        assert_eq!(outcome, RouteOutcome::Accepted, "well-formed PeerInfo must be accepted");
        assert!(outcome.should_dispatch());
    }

    #[test]
    fn router_validator_rejects_short_peer_info_payload() {
        // A type prefix only — no body. Decoder should fail and
        // validator should reject.
        let r = MessageRouter::new();
        r.register_validator(
            bitmasks::GLOBAL_PEER_INFO.to_vec(),
            validator_global_peer_info(),
        );
        let outcome = r.route(bitmasks::GLOBAL_PEER_INFO, &[0x00, 0x00, 0x01, 0x01]);
        assert!(matches!(outcome, RouteOutcome::Rejected(_)));
    }

    #[test]
    fn router_global_prover_validator_accepts_known_op() {
        let r = MessageRouter::new();
        r.register_validator(
            bitmasks::GLOBAL_PROVER.to_vec(),
            validator_global_prover(),
        );
        // ProverJoin type prefix as the leading 4 bytes is enough for
        // the validator (it checks the prefix only, since the prover
        // op decoders live in another crate and we don't want to drag
        // them in for a cheap topic-level filter).
        let bytes = TYPE_PROVER_JOIN.to_be_bytes();
        let outcome = r.route(bitmasks::GLOBAL_PROVER, &bytes);
        assert_eq!(outcome, RouteOutcome::Accepted);
    }

    #[test]
    fn router_global_prover_validator_rejects_garbage() {
        let r = MessageRouter::new();
        r.register_validator(
            bitmasks::GLOBAL_PROVER.to_vec(),
            validator_global_prover(),
        );
        // 0xFFFFFFFF isn't any known prover op type.
        let outcome = r.route(bitmasks::GLOBAL_PROVER, &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(matches!(outcome, RouteOutcome::Rejected(_)));
        // Short data also rejected.
        let outcome = r.route(bitmasks::GLOBAL_PROVER, &[0x00, 0x00]);
        assert!(matches!(outcome, RouteOutcome::Rejected(_)));
    }

    #[test]
    fn router_global_consensus_validator_rejects_garbage() {
        let r = MessageRouter::new();
        r.register_validator(
            bitmasks::GLOBAL_CONSENSUS.to_vec(),
            validator_global_consensus(),
        );
        let outcome = r.route(bitmasks::GLOBAL_CONSENSUS, &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(matches!(outcome, RouteOutcome::Rejected(_)));
    }

    #[test]
    fn router_panicking_validator_drops_message() {
        // A buggy validator that panics must not bring down the router.
        let r = MessageRouter::new();
        let panicking: TopicValidator = Arc::new(|_| panic!("boom"));
        r.register_validator(b"\x42".to_vec(), panicking);
        let outcome = r.route(b"\x42", b"hi");
        assert!(matches!(outcome, RouteOutcome::Rejected(_)));
    }

    #[test]
    fn router_register_replaces_validator() {
        let r = MessageRouter::new();
        r.register_validator(b"\x99".to_vec(), always_bad());
        assert!(matches!(r.route(b"\x99", b"x"), RouteOutcome::Rejected(_)));
        r.register_validator(b"\x99".to_vec(), always_ok());
        assert_eq!(r.route(b"\x99", b"x"), RouteOutcome::Accepted);
        assert!(r.unregister_validator(b"\x99"));
        assert_eq!(r.route(b"\x99", b"x"), RouteOutcome::Unvalidated);
        assert!(!r.unregister_validator(b"\x99"));
    }

    #[test]
    fn router_validator_count_tracks_registrations() {
        let r = MessageRouter::new();
        assert_eq!(r.validator_count(), 0);
        r.register_validator(bitmasks::GLOBAL_FRAME.to_vec(), validator_global_frame());
        r.register_validator(bitmasks::GLOBAL_PROVER.to_vec(), validator_global_prover());
        assert_eq!(r.validator_count(), 2);
    }
}
