//! MessageRequest (0x0311) and MessageBundle (0x0312) canonical-bytes
//! envelopes. Port of `protobufs/global.go:2461-2929`.
//!
//! Wire formats:
//!
//! ```text
//! MessageRequest:
//!   [u32 BE type_prefix = 0x0311]
//!   [u32 BE inner_len]
//!   [inner_len bytes — starts with its own u32 type discriminator]
//!
//! MessageBundle:
//!   [u32 BE type_prefix = 0x0312]
//!   [u32 BE num_requests]
//!     (for each request:)
//!       [u32 BE req_len] [req_len bytes of MessageRequest canonical]
//!   [i64 BE timestamp]
//! ```
//!
//! The decode path peeks at the inner type discriminator to tag the
//! payload but does NOT fully deserialize into a typed struct — callers
//! use the per-type `from_canonical_bytes` methods on the inner bytes
//! after matching on `inner_type_prefix`. This avoids duplicating all
//! 29+ variants as enum arms in the envelope layer.

use quil_types::error::{QuilError, Result};

use crate::canonical_cursor::{put_u32, read_u32, read_bytes, read_lp, expect_tp};

/// `MessageRequestType = 0x0311` from canonical_types.go.
pub const TYPE_MESSAGE_REQUEST: u32 = 0x0311;
/// `MessageBundleType = 0x0312` from canonical_types.go.
pub const TYPE_MESSAGE_BUNDLE: u32 = 0x0312;

// =====================================================================
// MessageRequest
// =====================================================================

/// A decoded MessageRequest envelope. The inner payload is stored as
/// raw bytes tagged with its type discriminator — the caller uses the
/// appropriate per-type decoder from `global_intrinsic`,
/// `token_intrinsic`, `hypergraph_intrinsic`, or `compute_intrinsic`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalMessageRequest {
    /// The inner type prefix (first 4 bytes of the inner payload).
    /// This is the per-op discriminator (e.g. 0x0301 for ProverJoin,
    /// 0x0509 for Transaction, 0x0404 for VertexAdd).
    pub inner_type_prefix: u32,
    /// The full inner canonical-bytes payload (including the
    /// inner type prefix). This can be passed directly to the
    /// per-type `from_canonical_bytes` method.
    pub inner_bytes: Vec<u8>,
}

impl CanonicalMessageRequest {
    /// Encode a MessageRequest envelope around an already-serialized
    /// inner payload.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(4 + 4 + self.inner_bytes.len());
        put_u32(&mut out, TYPE_MESSAGE_REQUEST);
        put_u32(&mut out, self.inner_bytes.len() as u32);
        out.extend_from_slice(&self.inner_bytes);
        Ok(out)
    }

    /// Decode a MessageRequest envelope. Extracts the inner payload
    /// and tags it with the inner type prefix.
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_MESSAGE_REQUEST, "MessageRequest")?;

        let inner_bytes = read_lp(data, &mut c)?;
        if inner_bytes.is_empty() {
            return Err(QuilError::InvalidArgument(
                "MessageRequest: empty inner payload".into(),
            ));
        }
        if inner_bytes.len() < 4 {
            return Err(QuilError::InvalidArgument(
                "MessageRequest: inner payload too short for type discriminator".into(),
            ));
        }

        let mut tp_buf = [0u8; 4];
        tp_buf.copy_from_slice(&inner_bytes[..4]);
        let inner_type_prefix = u32::from_be_bytes(tp_buf);

        Ok(Self {
            inner_type_prefix,
            inner_bytes,
        })
    }

    /// Construct a MessageRequest wrapping pre-encoded inner bytes.
    /// The caller is responsible for ensuring `inner_bytes` starts
    /// with a valid 4-byte type prefix.
    pub fn wrap(inner_bytes: Vec<u8>) -> Result<Self> {
        if inner_bytes.len() < 4 {
            return Err(QuilError::InvalidArgument(
                "MessageRequest::wrap: inner bytes too short".into(),
            ));
        }
        let mut tp_buf = [0u8; 4];
        tp_buf.copy_from_slice(&inner_bytes[..4]);
        Ok(Self {
            inner_type_prefix: u32::from_be_bytes(tp_buf),
            inner_bytes,
        })
    }
}

// =====================================================================
// MessageBundle
// =====================================================================

/// A decoded MessageBundle envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalMessageBundle {
    /// The ordered list of requests in the bundle.
    pub requests: Vec<Option<CanonicalMessageRequest>>,
    /// Bundle-level timestamp (i64 big-endian).
    pub timestamp: i64,
}

impl CanonicalMessageBundle {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_MESSAGE_BUNDLE);
        put_u32(&mut out, self.requests.len() as u32);

        for req in &self.requests {
            match req {
                Some(r) => {
                    let rb = r.to_canonical_bytes()?;
                    put_u32(&mut out, rb.len() as u32);
                    out.extend_from_slice(&rb);
                }
                None => put_u32(&mut out, 0),
            }
        }

        out.extend_from_slice(&self.timestamp.to_be_bytes());
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_MESSAGE_BUNDLE, "MessageBundle")?;

        let num_requests = read_u32(data, &mut c)? as usize;
        // Cap pre-allocation against the remaining buffer: every
        // entry consumes at least a 4-byte length prefix, so the
        // buffer cannot contain more than that many entries. Without
        // this cap, a malicious peer specifying num_requests =
        // 0xFFFFFFFF would trigger a ~96GB allocation
        // (Vec<Option<...>> on 64-bit) before the per-entry bounds
        // check ever runs.
        const MIN_ENTRY_BYTES: usize = 4;
        let max_possible = data.len().saturating_sub(c) / MIN_ENTRY_BYTES;
        let alloc_hint = num_requests.min(max_possible);
        let mut requests = Vec::with_capacity(alloc_hint);
        for _ in 0..num_requests {
            let req_len = read_u32(data, &mut c)? as usize;
            if req_len > 0 {
                let req_bytes = read_bytes(data, &mut c, req_len)?;
                requests.push(Some(CanonicalMessageRequest::from_canonical_bytes(
                    &req_bytes,
                )?));
            } else {
                requests.push(None);
            }
        }

        // Read timestamp (i64 BE)
        if c + 8 > data.len() {
            return Err(QuilError::InvalidArgument(
                "MessageBundle: truncated timestamp".into(),
            ));
        }
        let mut ts_buf = [0u8; 8];
        ts_buf.copy_from_slice(&data[c..c + 8]);
        let timestamp = i64::from_be_bytes(ts_buf);

        Ok(Self {
            requests,
            timestamp,
        })
    }
}

// =====================================================================
// Proto → canonical bytes (signing / authentication path)
// =====================================================================

/// Encode a proto `MessageRequest`'s oneof variant as canonical inner
/// bytes (the per-op type-prefixed envelope). Used by the
/// `NodeService.Send` authentication path which signs over canonical
/// bytes, not over the proto wire format.
pub fn proto_message_request_to_canonical_inner_bytes(
    pb: &quil_types::proto::global::MessageRequest,
) -> quil_types::error::Result<Vec<u8>> {
    use quil_types::proto::global::message_request::Request as Inner;

    let inner = pb.request.as_ref().ok_or_else(|| {
        quil_types::error::QuilError::InvalidArgument(
            "MessageRequest: missing oneof".into(),
        )
    })?;

    match inner {
        Inner::Join(p) => {
            crate::global_intrinsic::conversions::prover_join_from_proto(p)
                .to_canonical_bytes()
        }
        Inner::Leave(p) => {
            crate::global_intrinsic::conversions::prover_leave_from_proto(p)
                .to_canonical_bytes()
        }
        Inner::Pause(p) => {
            crate::global_intrinsic::conversions::prover_pause_from_proto(p)
                .to_canonical_bytes()
        }
        Inner::Resume(p) => {
            crate::global_intrinsic::conversions::prover_resume_from_proto(p)
                .to_canonical_bytes()
        }
        Inner::Confirm(p) => {
            crate::global_intrinsic::conversions::prover_confirm_from_proto(p)
                .to_canonical_bytes()
        }
        Inner::Reject(p) => {
            crate::global_intrinsic::conversions::prover_reject_from_proto(p)
                .to_canonical_bytes()
        }
        Inner::Update(p) => {
            crate::global_intrinsic::conversions::prover_update_from_proto(p)
                .to_canonical_bytes()
        }
        // Variants below haven't had `*_from_proto` helpers ported yet.
        Inner::SeniorityMerge(_)
        | Inner::Kick(_)
        | Inner::TokenDeploy(_)
        | Inner::TokenUpdate(_)
        | Inner::Transaction(_)
        | Inner::PendingTransaction(_)
        | Inner::MintTransaction(_)
        | Inner::HypergraphDeploy(_)
        | Inner::HypergraphUpdate(_)
        | Inner::VertexAdd(_)
        | Inner::VertexRemove(_)
        | Inner::HyperedgeAdd(_)
        | Inner::HyperedgeRemove(_)
        | Inner::ComputeDeploy(_)
        | Inner::ComputeUpdate(_)
        | Inner::CodeDeploy(_)
        | Inner::CodeExecute(_)
        | Inner::CodeFinalize(_)
        | Inner::Shard(_)
        | Inner::AltShardUpdate(_)
        | Inner::ShardSplit(_)
        | Inner::ShardMerge(_) => Err(quil_types::error::QuilError::Internal(
            "proto_message_request_to_canonical_inner_bytes: variant not yet supported"
                .into(),
        )),
    }
}

/// Encode a proto `MessageBundle` as canonical bytes.
pub fn proto_message_bundle_to_canonical_bytes(
    pb: &quil_types::proto::global::MessageBundle,
) -> quil_types::error::Result<Vec<u8>> {
    let mut requests: Vec<Option<CanonicalMessageRequest>> = Vec::with_capacity(pb.requests.len());
    for req in &pb.requests {
        let inner_bytes = proto_message_request_to_canonical_inner_bytes(req)?;
        requests.push(Some(CanonicalMessageRequest::wrap(inner_bytes)?));
    }
    let bundle = CanonicalMessageBundle {
        requests,
        timestamp: pb.timestamp,
    };
    bundle.to_canonical_bytes()
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global_intrinsic::prover_filter_ops::{ProverPause, TYPE_PROVER_PAUSE};
    use crate::global_intrinsic::AddressedSignature;
    use crate::hypergraph_intrinsic::canonical::TYPE_VERTEX_ADD;

    fn sample_inner_bytes(type_prefix: u32) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, type_prefix);
        out.extend_from_slice(b"payload-data");
        out
    }

    fn sample_prover_pause_bytes() -> Vec<u8> {
        let p = ProverPause {
            filter: vec![0xAAu8; 32],
            frame_number: 42,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xCCu8; 32],
            }),
        };
        p.to_canonical_bytes().unwrap()
    }

    #[test]
    fn proto_to_canonical_leave_round_trips() {
        use quil_types::proto::global as pb;
        use quil_types::proto::keys as keys_pb;

        let leave_pb = pb::ProverLeave {
            filters: vec![vec![0x01u8; 8], vec![0x02u8; 16]],
            frame_number: 9_999_999,
            public_key_signature_bls48581: Some(keys_pb::Bls48581AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xCCu8; 32],
            }),
        };
        let request_pb = pb::MessageRequest {
            request: Some(pb::message_request::Request::Leave(leave_pb.clone())),
            timestamp: 0,
        };
        let bundle_pb = pb::MessageBundle {
            requests: vec![request_pb],
            timestamp: 1_700_000_000_000,
        };

        let canonical = proto_message_bundle_to_canonical_bytes(&bundle_pb).unwrap();

        let decoded = CanonicalMessageBundle::from_canonical_bytes(&canonical).unwrap();
        assert_eq!(decoded.requests.len(), 1);
        assert_eq!(decoded.timestamp, 1_700_000_000_000);

        let req = decoded.requests[0].as_ref().expect("request present");
        let leave_decoded = crate::global_intrinsic::prover_filter_ops::ProverLeave
            ::from_canonical_bytes(&req.inner_bytes)
            .unwrap();
        assert_eq!(leave_decoded.filters, leave_pb.filters);
        assert_eq!(leave_decoded.frame_number, leave_pb.frame_number);
        let sig = leave_decoded
            .public_key_signature_bls48581
            .expect("sig present");
        assert_eq!(sig.signature, vec![0xBBu8; 74]);
        assert_eq!(sig.address, vec![0xCCu8; 32]);
    }

    #[test]
    fn proto_to_canonical_confirm_matches_handcrafted() {
        use quil_types::proto::global as pb;
        use quil_types::proto::keys as keys_pb;
        use crate::global_intrinsic::prover_ops::ProverConfirm;

        let confirm_pb = pb::ProverConfirm {
            filter: vec![],
            frame_number: 12345,
            public_key_signature_bls48581: Some(keys_pb::Bls48581AddressedSignature {
                signature: vec![0xAAu8; 74],
                address: vec![0xDDu8; 32],
            }),
            filters: vec![vec![0x10u8; 8]],
        };
        let bundle_pb = pb::MessageBundle {
            requests: vec![pb::MessageRequest {
                request: Some(pb::message_request::Request::Confirm(confirm_pb)),
                timestamp: 0,
            }],
            timestamp: 42,
        };

        let canonical_via_dispatch =
            proto_message_bundle_to_canonical_bytes(&bundle_pb).unwrap();

        let confirm_handcrafted = ProverConfirm {
            filter: vec![],
            frame_number: 12345,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xAAu8; 74],
                address: vec![0xDDu8; 32],
            }),
            filters: vec![vec![0x10u8; 8]],
        };
        let confirm_inner = confirm_handcrafted.to_canonical_bytes().unwrap();
        let bundle_handcrafted = CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest::wrap(confirm_inner).unwrap())],
            timestamp: 42,
        };
        let canonical_handcrafted = bundle_handcrafted.to_canonical_bytes().unwrap();

        assert_eq!(canonical_via_dispatch, canonical_handcrafted);
    }

    // -- MessageRequest --

    #[test]
    fn message_request_round_trip_with_opaque_payload() {
        let inner = sample_inner_bytes(0xDEAD);
        let req = CanonicalMessageRequest::wrap(inner.clone()).unwrap();
        assert_eq!(req.inner_type_prefix, 0xDEAD);
        let encoded = req.to_canonical_bytes().unwrap();
        assert_eq!(&encoded[..4], &TYPE_MESSAGE_REQUEST.to_be_bytes());
        let decoded = CanonicalMessageRequest::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(decoded.inner_bytes, inner);
    }

    #[test]
    fn message_request_round_trip_with_real_prover_pause() {
        let inner = sample_prover_pause_bytes();
        let req = CanonicalMessageRequest::wrap(inner.clone()).unwrap();
        assert_eq!(req.inner_type_prefix, TYPE_PROVER_PAUSE);

        let encoded = req.to_canonical_bytes().unwrap();
        let decoded = CanonicalMessageRequest::from_canonical_bytes(&encoded).unwrap();

        // The inner bytes should be the ProverPause canonical form
        let restored_pause =
            ProverPause::from_canonical_bytes(&decoded.inner_bytes).unwrap();
        assert_eq!(restored_pause.filter, vec![0xAAu8; 32]);
        assert_eq!(restored_pause.frame_number, 42);
    }

    #[test]
    fn message_request_decode_rejects_bad_outer_type() {
        let mut encoded = CanonicalMessageRequest::wrap(sample_inner_bytes(0x0301))
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        // Corrupt outer type prefix
        encoded[..4].copy_from_slice(&0xBEEFu32.to_be_bytes());
        assert!(CanonicalMessageRequest::from_canonical_bytes(&encoded).is_err());
    }

    #[test]
    fn message_request_decode_rejects_empty_inner() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_MESSAGE_REQUEST);
        put_u32(&mut out, 0); // inner_len = 0
        assert!(CanonicalMessageRequest::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn message_request_decode_rejects_short_inner() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_MESSAGE_REQUEST);
        put_u32(&mut out, 2); // inner_len = 2, but needs ≥ 4
        out.extend_from_slice(&[0xAA, 0xBB]);
        assert!(CanonicalMessageRequest::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn message_request_wrap_rejects_too_short() {
        assert!(CanonicalMessageRequest::wrap(vec![0u8; 3]).is_err());
    }

    // -- MessageBundle --

    #[test]
    fn message_bundle_round_trip_with_multiple_requests() {
        let r1 = CanonicalMessageRequest::wrap(sample_inner_bytes(TYPE_PROVER_PAUSE)).unwrap();
        let r2 = CanonicalMessageRequest::wrap(sample_inner_bytes(TYPE_VERTEX_ADD)).unwrap();
        let bundle = CanonicalMessageBundle {
            requests: vec![Some(r1), None, Some(r2)],
            timestamp: 1234567890,
        };
        let encoded = bundle.to_canonical_bytes().unwrap();
        assert_eq!(&encoded[..4], &TYPE_MESSAGE_BUNDLE.to_be_bytes());
        let decoded = CanonicalMessageBundle::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(decoded.requests.len(), 3);
        assert!(decoded.requests[0].is_some());
        assert!(decoded.requests[1].is_none());
        assert!(decoded.requests[2].is_some());
        assert_eq!(decoded.timestamp, 1234567890);
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn message_bundle_empty_requests() {
        let bundle = CanonicalMessageBundle {
            requests: vec![],
            timestamp: 0,
        };
        let encoded = bundle.to_canonical_bytes().unwrap();
        let decoded = CanonicalMessageBundle::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(decoded.requests.len(), 0);
        assert_eq!(decoded.timestamp, 0);
    }

    #[test]
    fn message_bundle_negative_timestamp() {
        let bundle = CanonicalMessageBundle {
            requests: vec![],
            timestamp: -42,
        };
        let encoded = bundle.to_canonical_bytes().unwrap();
        let decoded = CanonicalMessageBundle::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(decoded.timestamp, -42);
    }

    #[test]
    fn message_bundle_decode_rejects_bad_type() {
        let mut encoded = CanonicalMessageBundle {
            requests: vec![],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap();
        encoded[..4].copy_from_slice(&0xBEEFu32.to_be_bytes());
        assert!(CanonicalMessageBundle::from_canonical_bytes(&encoded).is_err());
    }

    #[test]
    fn message_bundle_decode_rejects_truncated_timestamp() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_MESSAGE_BUNDLE);
        put_u32(&mut out, 0); // 0 requests
        out.extend_from_slice(&[0u8; 4]); // only 4 bytes of timestamp (need 8)
        assert!(CanonicalMessageBundle::from_canonical_bytes(&out).is_err());
    }

    // -- End-to-end: encode a real ProverPause inside a bundle --

    #[test]
    fn end_to_end_prover_pause_in_bundle() {
        let pause_bytes = sample_prover_pause_bytes();
        let req = CanonicalMessageRequest::wrap(pause_bytes).unwrap();
        let bundle = CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: 9999,
        };
        let wire = bundle.to_canonical_bytes().unwrap();
        let decoded = CanonicalMessageBundle::from_canonical_bytes(&wire).unwrap();
        let inner = &decoded.requests[0].as_ref().unwrap().inner_bytes;
        let pause = ProverPause::from_canonical_bytes(inner).unwrap();
        assert_eq!(pause.frame_number, 42);
        assert_eq!(pause.filter, vec![0xAAu8; 32]);
    }

    // -- Type prefix sanity --

    #[test]
    fn message_request_and_bundle_prefixes_are_distinct() {
        assert_ne!(TYPE_MESSAGE_REQUEST, TYPE_MESSAGE_BUNDLE);
    }

    #[test]
    fn type_prefixes_match_go_constants() {
        assert_eq!(TYPE_MESSAGE_REQUEST, 0x0311);
        assert_eq!(TYPE_MESSAGE_BUNDLE, 0x0312);
    }
}
