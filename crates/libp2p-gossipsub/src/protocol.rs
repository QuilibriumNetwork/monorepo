// Copyright 2020 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    fmt, io,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use asynchronous_codec::{Decoder, Encoder, Framed};
use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use futures::prelude::*;
use libp2p_core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use libp2p_identity::{KeyType, PeerId, PublicKey};
use libp2p_swarm::StreamProtocol;
use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};
use sha2::{Digest, Sha256};
use web_time::Instant;

use crate::{
    config::ValidationMode,
    handler::HandlerEvent,
    rpc_proto::proto,
    topic::TopicHash,
    types::{
        ControlAction, Graft, IDontWant, IHave, IWant, MessageId, PeerInfo, PeerKind, Prune,
        RawMessage, Rpc, Subscription, SubscriptionAction,
    },
    ValidationError,
};

pub(crate) const SIGNING_PREFIX: &[u8] = b"libp2p-pubsub:";

/// QUILIBRIUM: failed signature checks one inbound stream may cause within
/// [`INVALID_SIGNATURE_WINDOW`]. Every published entry costs a verification
/// with the key the entry carries (Ed448 among them, which is slow), and an
/// honest peer forwards only entries it verified itself, so a stream past
/// this budget is closed instead of verifying further entries. The handler
/// disables gossip on a connection after a few such closures, which bounds
/// the verifications a connection can force.
const MAX_INVALID_SIGNATURES_PER_WINDOW: u32 = 16;

/// QUILIBRIUM: window of [`MAX_INVALID_SIGNATURES_PER_WINDOW`].
const INVALID_SIGNATURE_WINDOW: Duration = Duration::from_secs(10);

/// QUILIBRIUM: failed signature checks of one inbound stream in the current
/// window.
#[derive(Debug, Default)]
struct InvalidSignatureBudget {
    window_start: Option<Instant>,
    failures: u32,
    exhausted: bool,
}

impl InvalidSignatureBudget {
    /// Count a failed check at `now`, spending the budget past its limit.
    fn record_failure(&mut self, now: Instant) {
        match self.window_start {
            Some(start) if now.duration_since(start) < INVALID_SIGNATURE_WINDOW => {
                self.failures = self.failures.saturating_add(1);
            }
            _ => {
                self.window_start = Some(now);
                self.failures = 1;
            }
        }
        if self.failures > MAX_INVALID_SIGNATURES_PER_WINDOW && !self.exhausted {
            self.exhausted = true;
            tracing::warn!(
                failures = self.failures,
                window_secs = INVALID_SIGNATURE_WINDOW.as_secs(),
                "Closing gossipsub inbound stream: too many messages with invalid signatures"
            );
        }
    }
}

/// QUILIBRIUM: the bytes a message's signature covers, `SIGNING_PREFIX` then
/// the protobuf encoding of the message without its signature and key, written
/// from borrowed fields. Signing and verifying each built the message (a copy
/// of the data), encoded it (a second) and prefixed it (a third); this writes
/// the data once. The encoding is that of `proto::Message::write_message`.
pub(crate) fn signature_payload(
    from: Option<&[u8]>,
    data: Option<&[u8]>,
    seqno: Option<&[u8]>,
    topic: &str,
) -> Vec<u8> {
    use quick_protobuf::sizeofs::sizeof_len;
    let field = |value: Option<&[u8]>| value.map_or(0, |value| 1 + sizeof_len(value.len()));
    let size = field(from) + field(data) + field(seqno) + 1 + sizeof_len(topic.len());
    let mut buf = Vec::with_capacity(SIGNING_PREFIX.len() + size);
    buf.extend_from_slice(SIGNING_PREFIX);
    let mut writer = Writer::new(&mut buf);
    let fields = [(10, from), (18, data), (26, seqno)];
    for (tag, value) in fields {
        if let Some(value) = value {
            writer
                .write_with_tag(tag, |w| w.write_bytes(value))
                .expect("Encoding to succeed");
        }
    }
    writer
        .write_with_tag(34, |w| w.write_string(topic))
        .expect("Encoding to succeed");
    buf
}

/// QUILIBRIUM: the key types (protobuf `KeyType` values) a message signature
/// may use: Ed25519 (1) and Falcon (5). Nodes sign gossip with their Falcon
/// network identity; Ed25519 is cheap to verify and used by tests and tools.
/// No node publishes with another type, and some cost far more to verify
/// (Ed448 is reference big-integer code), so an entry carrying one is dropped
/// before anything of it is decoded or hashed
/// ([`ValidationError::RefusedKeyType`]). It is not counted as an invalid
/// signature: releases before this check verify such entries and forward
/// them, and penalising those relays would cut them off the mesh.
const SIGNATURE_KEY_TYPES: [u64; 2] = [1, 5];

/// QUILIBRIUM: the outcome of a message's signature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureCheck {
    Valid,
    Invalid,
    /// Signed with a key of a type not in [`SIGNATURE_KEY_TYPES`].
    RefusedKeyType,
}

/// QUILIBRIUM: the type of a protobuf-encoded public key, read without
/// decoding the key: the last `Type` field (1), as the decoder reads it.
fn encoded_key_type(encoded: &[u8]) -> Option<u64> {
    let mut key = WireReader::new(encoded);
    let mut key_type = None;
    while !key.is_empty() {
        let tag = key.varint32().ok()?;
        if tag == 8 {
            key_type = Some(key.varint().ok()?);
        } else {
            key.skip(tag).ok()?;
        }
    }
    key_type
}

/// QUILIBRIUM: decodes a message's signing key when its type is one of
/// [`SIGNATURE_KEY_TYPES`], checked before and after decoding.
fn decode_signing_key(encoded: &[u8]) -> Option<PublicKey> {
    if !encoded_key_type(encoded).is_some_and(|key_type| SIGNATURE_KEY_TYPES.contains(&key_type)) {
        return None;
    }
    let key = PublicKey::try_decode_protobuf(encoded).ok()?;
    matches!(key.key_type(), KeyType::Ed25519 | KeyType::Falcon).then_some(key)
}

/// QUILIBRIUM: how many verified entries [`VerifiedSignatures`] remembers. The
/// copies of a message reach a node from its mesh peers within seconds, so a
/// few seconds of traffic is enough; at 32 bytes a digest this is under 1 MiB.
const MAX_VERIFIED_SIGNATURES: usize = 16_384;

/// QUILIBRIUM: digests of the published entries whose signatures verified,
/// shared by the inbound streams of one behaviour. An entry identical to one
/// already verified (the same signed fields, signature and key) skips the
/// check. Every mesh peer forwards a copy of each message, and the duplicate
/// check runs in the behaviour, after the codec, so each copy (or a replay of
/// any message seen on the network) otherwise cost a verification of its own.
#[derive(Debug, Default)]
pub(crate) struct VerifiedSignatures {
    entries: Mutex<VerifiedSet>,
}

/// QUILIBRIUM: the digests of [`VerifiedSignatures`], oldest first.
#[derive(Debug, Default)]
struct VerifiedSet {
    digests: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl VerifiedSignatures {
    fn contains(&self, digest: &[u8; 32]) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .digests
            .contains(digest)
    }

    fn insert(&self, digest: [u8; 32]) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !entries.digests.insert(digest) {
            return;
        }
        entries.order.push_back(digest);
        if entries.order.len() > MAX_VERIFIED_SIGNATURES {
            if let Some(oldest) = entries.order.pop_front() {
                entries.digests.remove(&oldest);
            }
        }
    }
}

/// QUILIBRIUM: the key of an entry in [`VerifiedSignatures`]: its signed
/// bytes, signature and key, each length-prefixed.
fn verified_digest(signed: &[u8], signature: &[u8], key: Option<&[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in [Some(signed), Some(signature), key] {
        match part {
            Some(part) => {
                hasher.update([1u8]);
                hasher.update((part.len() as u64).to_be_bytes());
                hasher.update(part);
            }
            None => hasher.update([0u8]),
        }
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

pub(crate) const GOSSIPSUB_1_2_0_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/meshsub/1.2.0"),
    kind: PeerKind::Gossipsubv1_2,
};

pub(crate) const GOSSIPSUB_1_1_0_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/meshsub/1.1.0"),
    kind: PeerKind::Gossipsubv1_1,
};
pub(crate) const GOSSIPSUB_1_0_0_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/meshsub/1.0.0"),
    kind: PeerKind::Gossipsub,
};
pub(crate) const FLOODSUB_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/floodsub/1.0.0"),
    kind: PeerKind::Floodsub,
};

/// Implementation of [`InboundUpgrade`] and [`OutboundUpgrade`] for the Gossipsub protocol.
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// The Gossipsub protocol id to listen on.
    pub(crate) protocol_ids: Vec<ProtocolId>,
    /// Determines the level of validation to be done on incoming messages.
    pub(crate) validation_mode: ValidationMode,
    /// The default max transmit size.
    pub(crate) default_max_transmit_size: usize,
    /// The max transmit sizes for a topic.
    pub(crate) max_transmit_sizes: HashMap<TopicHash, usize>,
    /// QUILIBRIUM: entries whose signatures verified, shared by every stream.
    pub(crate) verified_signatures: Arc<VerifiedSignatures>,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            validation_mode: ValidationMode::Strict,
            protocol_ids: vec![
                GOSSIPSUB_1_2_0_PROTOCOL,
                GOSSIPSUB_1_1_0_PROTOCOL,
                GOSSIPSUB_1_0_0_PROTOCOL,
            ],
            default_max_transmit_size: 65536,
            max_transmit_sizes: HashMap::new(),
            verified_signatures: Arc::default(),
        }
    }
}

impl ProtocolConfig {
    /// Get the max transmit size for a given topic, falling back to the default.
    pub fn max_transmit_size_for_topic(&self, topic: &TopicHash) -> usize {
        self.max_transmit_sizes
            .get(topic)
            .copied()
            .unwrap_or(self.default_max_transmit_size)
    }
}

/// The protocol ID
#[derive(Clone, Debug, PartialEq)]
pub struct ProtocolId {
    /// The RPC message type/name.
    pub protocol: StreamProtocol,
    /// The type of protocol we support
    pub kind: PeerKind,
}

impl AsRef<str> for ProtocolId {
    fn as_ref(&self) -> &str {
        self.protocol.as_ref()
    }
}

impl UpgradeInfo for ProtocolConfig {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocol_ids.clone()
    }
}

impl<TSocket> InboundUpgrade<TSocket> for ProtocolConfig
where
    TSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (Framed<TSocket, GossipsubCodec>, PeerKind);
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, socket: TSocket, protocol_id: Self::Info) -> Self::Future {
        Box::pin(future::ok((
            Framed::new(
                socket,
                GossipsubCodec::new(
                    self.default_max_transmit_size,
                    self.validation_mode,
                    self.max_transmit_sizes,
                )
                .with_verified_signatures(self.verified_signatures),
            ),
            protocol_id.kind,
        )))
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for ProtocolConfig
where
    TSocket: AsyncWrite + AsyncRead + Unpin + Send + 'static,
{
    type Output = (Framed<TSocket, GossipsubCodec>, PeerKind);
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, socket: TSocket, protocol_id: Self::Info) -> Self::Future {
        Box::pin(future::ok((
            Framed::new(
                socket,
                GossipsubCodec::new(
                    self.default_max_transmit_size,
                    self.validation_mode,
                    self.max_transmit_sizes,
                )
                .with_verified_signatures(self.verified_signatures),
            ),
            protocol_id.kind,
        )))
    }
}

// Gossip codec for the framing

pub struct GossipsubCodec {
    /// Determines the level of validation performed on incoming messages.
    validation_mode: ValidationMode,
    /// The codec to handle common encoding/decoding of protobuf messages
    codec: quick_protobuf_codec::Codec<proto::RPC>,
    /// QUILIBRIUM: the largest inbound frame, in bytes. Inbound frames are read here (see
    /// `decode`), the codec only encodes.
    max_length: usize,
    /// Maximum transmit sizes per topic, with a default if not specified.
    max_transmit_sizes: HashMap<TopicHash, usize>,
    /// QUILIBRIUM: failed signature checks this stream has caused.
    invalid_signatures: InvalidSignatureBudget,
    /// QUILIBRIUM: entries whose signatures verified (see [`VerifiedSignatures`]).
    verified_signatures: Arc<VerifiedSignatures>,
}

impl GossipsubCodec {
    pub fn new(
        max_length: usize,
        validation_mode: ValidationMode,
        max_transmit_sizes: HashMap<TopicHash, usize>,
    ) -> GossipsubCodec {
        let codec = quick_protobuf_codec::Codec::new(max_length);
        GossipsubCodec {
            validation_mode,
            codec,
            max_length,
            max_transmit_sizes,
            invalid_signatures: InvalidSignatureBudget::default(),
            verified_signatures: Arc::default(),
        }
    }

    /// QUILIBRIUM: shares `verified` with the other streams of a behaviour.
    pub(crate) fn with_verified_signatures(mut self, verified: Arc<VerifiedSignatures>) -> Self {
        self.verified_signatures = verified;
        self
    }

    /// Get the max transmit size for a given topic if it exists.
    fn max_transmit_size_for_topic(&self, topic: &TopicHash) -> Option<usize> {
        self.max_transmit_sizes.get(topic).copied()
    }

    /// Verifies a gossipsub message. This returns either a success or failure. All errors
    /// are logged, which prevents error handling in the codec and handler. We simply drop invalid
    /// messages and log warnings, rather than propagating errors through the codec.
    fn verify_signature(message: &proto::Message, verified: &VerifiedSignatures) -> SignatureCheck {
        let Some(from) = message.from.as_ref() else {
            tracing::debug!("Signature verification failed: No source id given");
            return SignatureCheck::Invalid;
        };

        let Ok(source) = PeerId::from_bytes(from) else {
            tracing::debug!("Signature verification failed: Invalid Peer Id");
            return SignatureCheck::Invalid;
        };

        let Some(signature) = message.signature.as_ref() else {
            tracing::debug!("Signature verification failed: No signature provided");
            return SignatureCheck::Invalid;
        };

        // QUILIBRIUM: the type of the key the check would use, read first: the
        // entry's key if it has a type, else the one inlined in the source.
        let inline_key = source.to_bytes();
        let key_type = message
            .key
            .as_deref()
            .and_then(encoded_key_type)
            .or_else(|| encoded_key_type(&inline_key[2..]));
        if !key_type.is_some_and(|key_type| SIGNATURE_KEY_TYPES.contains(&key_type)) {
            tracing::debug!(?key_type, "Signature not checked: refused key type");
            return SignatureCheck::RefusedKeyType;
        }

        // Construct the signature bytes
        let signature_bytes = signature_payload(
            message.from.as_deref(),
            message.data.as_deref(),
            message.seqno.as_deref(),
            &message.topic,
        );
        // QUILIBRIUM: a copy of an entry that verified is not verified again.
        let digest = verified_digest(&signature_bytes, signature, message.key.as_deref());
        if verified.contains(&digest) {
            return SignatureCheck::Valid;
        }

        // If there is a key value in the protobuf, use that key otherwise the key must be
        // obtained from the inlined source peer_id.
        // QUILIBRIUM: only keys of the types in `SIGNATURE_KEY_TYPES` are decoded.
        let public_key = match message.key.as_deref().and_then(decode_signing_key) {
            Some(key) => key,
            None => match decode_signing_key(&inline_key[2..]) {
                Some(key) => key,
                None => {
                    tracing::debug!("Signature verification failed: No valid public key supplied");
                    return SignatureCheck::Invalid;
                }
            },
        };

        // The key must match the peer_id
        if source != public_key.to_peer_id() {
            tracing::debug!(
                "Signature verification failed: Public key doesn't match source peer id"
            );
            return SignatureCheck::Invalid;
        }

        if !public_key.verify(&signature_bytes, signature) {
            return SignatureCheck::Invalid;
        }
        verified.insert(digest);
        SignatureCheck::Valid
    }
}

impl Encoder for GossipsubCodec {
    type Item<'a> = proto::RPC;
    type Error = quick_protobuf_codec::Error;

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.codec.encode(item, dst)
    }
}

impl Decoder for GossipsubCodec {
    type Item = HandlerEvent;
    type Error = quick_protobuf_codec::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // QUILIBRIUM: a stream that spent its invalid-signature budget is
        // closed; the error makes the handler drop it.
        if self.invalid_signatures.exhausted {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "too many messages with invalid signatures",
            )
            .into());
        }
        // QUILIBRIUM: the frame is read here rather than by `quick_protobuf_codec`, so that
        // its entries are counted before any of them is decoded (`scan_rpc`). A frame over
        // the limits is consumed undecoded and reported, and the handler closes the stream.
        let Some((prefix_len, frame_len)) = frame_header(src.as_ref())? else {
            return Ok(None);
        };
        if frame_len > self.max_length {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "message with {frame_len}b exceeds maximum of {}b",
                    self.max_length
                ),
            )
            .into());
        }
        if src.len() < prefix_len + frame_len {
            return Ok(None);
        }
        src.advance(prefix_len);
        let frame = src.split_to(frame_len);
        if let Err(rejection) = scan_rpc(&frame) {
            return Ok(Some(HandlerEvent::RpcRejected {
                rejection,
                frame_len,
            }));
        }
        let mut reader = BytesReader::from_bytes(&frame);
        let rpc = proto::RPC::from_reader(&mut reader, &frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        // Store valid messages.
        let mut messages = Vec::with_capacity(rpc.publish.len());
        // Store any invalid messages.
        let mut invalid_messages = Vec::new();

        for message in rpc.publish.into_iter() {
            // QUILIBRIUM: once the budget is spent, the rest of the RPC is
            // dropped unverified.
            if self.invalid_signatures.exhausted {
                break;
            }
            let topic = TopicHash::from_raw(&message.topic);

            // Check the message size to ensure it doesn't bypass the configured max.
            if self
                .max_transmit_size_for_topic(&topic)
                .is_some_and(|max| message.get_size() > max)
            {
                let message = RawMessage {
                    source: None, // don't bother inform the application
                    data: message.data.unwrap_or_default(),
                    sequence_number: None, // don't inform the application
                    topic: TopicHash::from_raw(message.topic),
                    signature: None, // don't inform the application
                    key: message.key,
                    validated: false,
                };

                invalid_messages.push((message, ValidationError::MessageSizeTooLargeForTopic));
                continue;
            }

            // Keep track of the type of invalid message.
            let mut invalid_kind = None;
            let mut verify_signature = false;
            let mut verify_sequence_no = false;
            let mut verify_source = false;

            match self.validation_mode {
                ValidationMode::Strict => {
                    // Validate everything
                    verify_signature = true;
                    verify_sequence_no = true;
                    verify_source = true;
                }
                ValidationMode::Permissive => {
                    // If the fields exist, validate them
                    if message.signature.is_some() {
                        verify_signature = true;
                    }
                    if message.seqno.is_some() {
                        verify_sequence_no = true;
                    }
                    if message.from.is_some() {
                        verify_source = true;
                    }
                }
                ValidationMode::Anonymous => {
                    if message.signature.is_some() {
                        tracing::warn!(
                            "Signature field was non-empty and anonymous validation mode is set"
                        );
                        invalid_kind = Some(ValidationError::SignaturePresent);
                    } else if message.seqno.is_some() {
                        tracing::warn!(
                            "Sequence number was non-empty and anonymous validation mode is set"
                        );
                        invalid_kind = Some(ValidationError::SequenceNumberPresent);
                    } else if message.from.is_some() {
                        tracing::warn!("Message dropped. Message source was non-empty and anonymous validation mode is set");
                        invalid_kind = Some(ValidationError::MessageSourcePresent);
                    }
                }
                ValidationMode::None => {}
            }

            // If the initial validation logic failed, add the message to invalid messages and
            // continue processing the others.
            if let Some(validation_error) = invalid_kind.take() {
                let message = RawMessage {
                    source: None, // don't bother inform the application
                    data: message.data.unwrap_or_default(),
                    sequence_number: None, // don't inform the application
                    topic: TopicHash::from_raw(message.topic),
                    signature: None, // don't inform the application
                    key: message.key,
                    validated: false,
                };
                invalid_messages.push((message, validation_error));
                // proceed to the next message
                continue;
            }

            // verify message signatures if required
            let signature_check = if verify_signature {
                GossipsubCodec::verify_signature(&message, &self.verified_signatures)
            } else {
                SignatureCheck::Valid
            };
            // QUILIBRIUM: an entry signed with a refused key type is reported
            // without counting against the stream's budget.
            if signature_check == SignatureCheck::RefusedKeyType {
                let source = message
                    .from
                    .as_deref()
                    .and_then(|from| PeerId::from_bytes(from).ok());
                // Source and sequence number are kept: the behaviour computes
                // the message id to release the promises of the message.
                let sequence_number = message
                    .seqno
                    .as_deref()
                    .filter(|seqno| seqno.len() == 8)
                    .map(BigEndian::read_u64);
                let message = RawMessage {
                    source,
                    data: message.data.unwrap_or_default(),
                    sequence_number,
                    topic: TopicHash::from_raw(message.topic),
                    signature: None, // don't inform the application
                    key: None,
                    validated: false,
                };
                invalid_messages.push((message, ValidationError::RefusedKeyType));
                continue;
            }
            if signature_check == SignatureCheck::Invalid {
                // QUILIBRIUM: debug, as every entry of an RPC can fail; the
                // budget logs once when it closes the stream.
                tracing::debug!("Invalid signature for received message");
                self.invalid_signatures.record_failure(Instant::now());
                // Build the invalid message (ignoring further validation of sequence number
                // and source)
                let message = RawMessage {
                    source: None, // don't bother inform the application
                    data: message.data.unwrap_or_default(),
                    sequence_number: None, // don't inform the application
                    topic: TopicHash::from_raw(message.topic),
                    signature: None, // don't inform the application
                    key: message.key,
                    validated: false,
                };
                invalid_messages.push((message, ValidationError::InvalidSignature));
                // proceed to the next message
                continue;
            }

            // ensure the sequence number is a u64
            let sequence_number = if verify_sequence_no {
                if let Some(seq_no) = message.seqno {
                    if seq_no.is_empty() {
                        None
                    } else if seq_no.len() != 8 {
                        tracing::debug!(
                            sequence_number=?seq_no,
                            sequence_length=%seq_no.len(),
                            "Invalid sequence number length for received message"
                        );

                        let message = RawMessage {
                            source: None, // don't bother inform the application
                            data: message.data.unwrap_or_default(),
                            sequence_number: None, // don't inform the application
                            topic: TopicHash::from_raw(message.topic),
                            signature: message.signature, // don't inform the application
                            key: message.key,
                            validated: false,
                        };
                        invalid_messages.push((message, ValidationError::InvalidSequenceNumber));
                        // proceed to the next message
                        continue;
                    } else {
                        // valid sequence number
                        Some(BigEndian::read_u64(&seq_no))
                    }
                } else {
                    // sequence number was not present
                    tracing::debug!("Sequence number not present but expected");
                    let message = RawMessage {
                        source: None, // don't bother inform the application
                        data: message.data.unwrap_or_default(),
                        sequence_number: None, // don't inform the application
                        topic: TopicHash::from_raw(message.topic),
                        signature: message.signature, // don't inform the application
                        key: message.key,
                        validated: false,
                    };
                    invalid_messages.push((message, ValidationError::EmptySequenceNumber));
                    continue;
                }
            } else {
                // Do not verify the sequence number, consider it empty
                None
            };

            // Verify the message source if required
            let source = if verify_source {
                if let Some(bytes) = message.from {
                    if !bytes.is_empty() {
                        match PeerId::from_bytes(&bytes) {
                            Ok(peer_id) => Some(peer_id), // valid peer id
                            Err(_) => {
                                // invalid peer id, add to invalid messages
                                tracing::debug!("Message source has an invalid PeerId");
                                let message = RawMessage {
                                    source: None, // don't bother inform the application
                                    data: message.data.unwrap_or_default(),
                                    sequence_number,
                                    topic: TopicHash::from_raw(message.topic),
                                    signature: message.signature, // don't inform the application
                                    key: message.key,
                                    validated: false,
                                };
                                invalid_messages.push((message, ValidationError::InvalidPeerId));
                                continue;
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // This message has passed all validation, add it to the validated messages.
            messages.push(RawMessage {
                source,
                data: message.data.unwrap_or_default(),
                sequence_number,
                topic: TopicHash::from_raw(message.topic),
                signature: message.signature,
                key: message.key,
                validated: false,
            });
        }

        let mut control_msgs = Vec::new();

        if let Some(rpc_control) = rpc.control {
            // Collect the gossipsub control messages
            let ihave_msgs: Vec<ControlAction> = rpc_control
                .ihave
                .into_iter()
                .map(|ihave| {
                    ControlAction::IHave(IHave {
                        topic_hash: TopicHash::from_raw(ihave.topic_id.unwrap_or_default()),
                        message_ids: ihave
                            .message_ids
                            .into_iter()
                            .map(MessageId::from)
                            .collect::<Vec<_>>(),
                    })
                })
                .collect();

            let iwant_msgs: Vec<ControlAction> = rpc_control
                .iwant
                .into_iter()
                .map(|iwant| {
                    ControlAction::IWant(IWant {
                        message_ids: iwant
                            .message_ids
                            .into_iter()
                            .map(MessageId::from)
                            .collect::<Vec<_>>(),
                    })
                })
                .collect();

            let graft_msgs: Vec<ControlAction> = rpc_control
                .graft
                .into_iter()
                .map(|graft| {
                    ControlAction::Graft(Graft {
                        topic_hash: TopicHash::from_raw(graft.topic_id.unwrap_or_default()),
                    })
                })
                .collect();

            let mut prune_msgs = Vec::new();

            for prune in rpc_control.prune {
                // filter out invalid peers
                let peers = prune
                    .peers
                    .into_iter()
                    .filter_map(|info| {
                        info.peer_id
                            .as_ref()
                            .and_then(|id| PeerId::from_bytes(id).ok())
                            .map(|peer_id|
                                    //TODO signedPeerRecord, see https://github.com/libp2p/specs/pull/217
                                    PeerInfo {
                                        peer_id: Some(peer_id),
                                    })
                    })
                    .collect::<Vec<PeerInfo>>();

                let topic_hash = TopicHash::from_raw(prune.topic_id.unwrap_or_default());
                prune_msgs.push(ControlAction::Prune(Prune {
                    topic_hash,
                    peers,
                    backoff: prune.backoff,
                }));
            }

            let idontwant_msgs: Vec<ControlAction> = rpc_control
                .idontwant
                .into_iter()
                .map(|idontwant| {
                    ControlAction::IDontWant(IDontWant {
                        message_ids: idontwant
                            .message_ids
                            .into_iter()
                            .map(MessageId::from)
                            .collect::<Vec<_>>(),
                    })
                })
                .collect();

            control_msgs.extend(ihave_msgs);
            control_msgs.extend(iwant_msgs);
            control_msgs.extend(graft_msgs);
            control_msgs.extend(prune_msgs);
            control_msgs.extend(idontwant_msgs);
        }

        Ok(Some(HandlerEvent::Message {
            rpc: Rpc {
                messages,
                subscriptions: rpc
                    .subscriptions
                    .into_iter()
                    .map(|sub| Subscription {
                        action: if Some(true) == sub.subscribe {
                            SubscriptionAction::Subscribe
                        } else {
                            SubscriptionAction::Unsubscribe
                        },
                        topic_hash: TopicHash::from_raw(sub.topic_id.unwrap_or_default()),
                    })
                    .collect(),
                control_msgs,
            },
            invalid_messages,
        }))
    }
}

/// QUILIBRIUM: the most publish entries one inbound RPC may carry. This crate sends one
/// message per RPC (`RpcOut`).
const MAX_RPC_PUBLISH: usize = 128;
/// QUILIBRIUM: the most subscription changes one inbound RPC may carry; sent one per RPC.
const MAX_RPC_SUBSCRIPTIONS: usize = 1024;
/// QUILIBRIUM: the most control messages (IHAVE, IWANT, GRAFT, PRUNE, IDONTWANT) one inbound
/// RPC may carry; sent one per RPC.
const MAX_RPC_CONTROL_MESSAGES: usize = 1024;
/// QUILIBRIUM: the most message ids across one inbound RPC's control messages: twice the
/// default `max_ihave_length` (5000), the most ids an IHAVE or IWANT carries.
const MAX_RPC_MESSAGE_IDS: usize = 10_000;
/// QUILIBRIUM: the most peer-exchange records across one inbound RPC's PRUNEs; a PRUNE
/// carries at most `prune_peers` (0 by default, 16 upstream).
const MAX_RPC_PRUNE_PEERS: usize = 1024;
/// The longest varint, of a 64-bit value.
const MAX_VARINT_LEN: usize = 10;

/// QUILIBRIUM: a kind of entry counted in an inbound RPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcEntry {
    /// A published message.
    Publish,
    /// A subscription change.
    Subscription,
    /// A control message.
    ControlMessage,
    /// A message id in IHAVE, IWANT or IDONTWANT.
    MessageId,
    /// A peer-exchange record in PRUNE.
    PrunePeer,
}

impl RpcEntry {
    /// The most entries of this kind one RPC may carry.
    fn limit(self) -> usize {
        match self {
            RpcEntry::Publish => MAX_RPC_PUBLISH,
            RpcEntry::Subscription => MAX_RPC_SUBSCRIPTIONS,
            RpcEntry::ControlMessage => MAX_RPC_CONTROL_MESSAGES,
            RpcEntry::MessageId => MAX_RPC_MESSAGE_IDS,
            RpcEntry::PrunePeer => MAX_RPC_PRUNE_PEERS,
        }
    }

    fn name(self) -> &'static str {
        match self {
            RpcEntry::Publish => "published messages",
            RpcEntry::Subscription => "subscription changes",
            RpcEntry::ControlMessage => "control messages",
            RpcEntry::MessageId => "message ids",
            RpcEntry::PrunePeer => "peer-exchange records",
        }
    }
}

/// QUILIBRIUM: why an inbound RPC was dropped before it was decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcRejection {
    /// It carried more entries of one kind than an RPC may.
    TooMany {
        /// The kind of entry.
        entry: RpcEntry,
        /// The most entries of that kind an RPC may carry.
        limit: usize,
    },
    /// It was not well-formed protobuf, which the decoder could read differently from the
    /// count.
    Malformed,
}

impl fmt::Display for RpcRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcRejection::TooMany { entry, limit } => {
                write!(f, "more than {limit} {}", entry.name())
            }
            RpcRejection::Malformed => f.write_str("malformed protobuf"),
        }
    }
}

/// QUILIBRIUM: inbound RPCs dropped before decoding, counted since the behaviour was built.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RejectedRpcStats {
    /// RPCs dropped.
    pub rejected: u64,
    /// Bytes of their frames.
    pub bytes: u64,
    /// The sender of the latest and why it was dropped.
    pub last: Option<(PeerId, RpcRejection)>,
}

/// QUILIBRIUM: the unsigned-varint length prefix of the frame at the start of `src`, as its
/// own length and the frame's, or `None` until the prefix is complete.
fn frame_header(src: &[u8]) -> io::Result<Option<(usize, usize)>> {
    let mut frame_len: u64 = 0;
    for (i, byte) in src.iter().take(MAX_VARINT_LEN).enumerate() {
        frame_len |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            let frame_len = usize::try_from(frame_len)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok(Some((i + 1, frame_len)));
        }
    }
    if src.len() >= MAX_VARINT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length prefix longer than a varint",
        ));
    }
    Ok(None)
}

/// QUILIBRIUM: counts of one inbound RPC's entries.
#[derive(Default)]
struct RpcEntryCounts {
    publish: usize,
    subscriptions: usize,
    control_messages: usize,
    message_ids: usize,
    prune_peers: usize,
}

impl RpcEntryCounts {
    fn add(&mut self, entry: RpcEntry) -> Result<(), RpcRejection> {
        let count = match entry {
            RpcEntry::Publish => &mut self.publish,
            RpcEntry::Subscription => &mut self.subscriptions,
            RpcEntry::ControlMessage => &mut self.control_messages,
            RpcEntry::MessageId => &mut self.message_ids,
            RpcEntry::PrunePeer => &mut self.prune_peers,
        };
        *count += 1;
        let limit = entry.limit();
        if *count > limit {
            return Err(RpcRejection::TooMany { entry, limit });
        }
        Ok(())
    }
}

/// QUILIBRIUM: a strict reader of protobuf wire format, which never allocates.
struct WireReader<'a> {
    bytes: &'a [u8],
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn varint(&mut self) -> Result<u64, RpcRejection> {
        let bytes = self.bytes;
        let mut value: u64 = 0;
        for (i, byte) in bytes.iter().take(MAX_VARINT_LEN).enumerate() {
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                self.bytes = &bytes[i + 1..];
                return Ok(value);
            }
        }
        Err(RpcRejection::Malformed)
    }

    /// A tag or a length. The decoder reads those as 32-bit varints and drops higher bits,
    /// so a larger value is refused rather than read as another field or length.
    fn varint32(&mut self) -> Result<u32, RpcRejection> {
        u32::try_from(self.varint()?).map_err(|_| RpcRejection::Malformed)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RpcRejection> {
        let bytes = self.bytes;
        if len > bytes.len() {
            return Err(RpcRejection::Malformed);
        }
        let (taken, rest) = bytes.split_at(len);
        self.bytes = rest;
        Ok(taken)
    }

    /// The contents of a length-delimited field.
    fn len_delimited(&mut self) -> Result<&'a [u8], RpcRejection> {
        let len = self.varint32()? as usize;
        self.take(len)
    }

    /// Skips the value of a field with `tag`, by its wire type.
    fn skip(&mut self, tag: u32) -> Result<(), RpcRejection> {
        match tag & 0x7 {
            0 => {
                self.varint()?;
            }
            1 => {
                self.take(8)?;
            }
            2 => {
                self.len_delimited()?;
            }
            5 => {
                self.take(4)?;
            }
            // Groups (3, 4), which the decoder refuses too, and undefined wire types.
            _ => return Err(RpcRejection::Malformed),
        }
        Ok(())
    }
}

/// QUILIBRIUM: checks that `frame` is well-formed protobuf and counts the entries of the RPC
/// it encodes, without allocating, so that an RPC over the limits is dropped before it is
/// decoded and decoding stays proportional to the frame. Every nested message is walked to
/// its end, and a frame the decoder could read differently from this walk is refused.
fn scan_rpc(frame: &[u8]) -> Result<(), RpcRejection> {
    let mut counts = RpcEntryCounts::default();
    let mut rpc = WireReader::new(frame);
    while !rpc.is_empty() {
        match rpc.varint32()? {
            // `subscriptions` (1).
            10 => {
                counts.add(RpcEntry::Subscription)?;
                check_fields(rpc.len_delimited()?)?;
            }
            // `publish` (2).
            18 => {
                counts.add(RpcEntry::Publish)?;
                check_fields(rpc.len_delimited()?)?;
            }
            // `control` (3).
            26 => scan_control(rpc.len_delimited()?, &mut counts)?,
            tag => rpc.skip(tag)?,
        }
    }
    Ok(())
}

/// QUILIBRIUM: counts the entries of a `ControlMessage`.
fn scan_control(control: &[u8], counts: &mut RpcEntryCounts) -> Result<(), RpcRejection> {
    let mut control = WireReader::new(control);
    while !control.is_empty() {
        let tag = control.varint32()?;
        // The repeated field of each control message: IHAVE (1), IWANT (2) and
        // IDONTWANT (5) list message ids, PRUNE (4) peer-exchange records, GRAFT (3) none.
        let list = match tag {
            10 => Some((18, RpcEntry::MessageId)),
            18 | 42 => Some((10, RpcEntry::MessageId)),
            34 => Some((18, RpcEntry::PrunePeer)),
            26 => None,
            _ => {
                control.skip(tag)?;
                continue;
            }
        };
        counts.add(RpcEntry::ControlMessage)?;
        let mut message = WireReader::new(control.len_delimited()?);
        while !message.is_empty() {
            let tag = message.varint32()?;
            match list {
                Some((list_tag, entry)) if tag == list_tag => {
                    counts.add(entry)?;
                    let item = message.len_delimited()?;
                    if entry == RpcEntry::PrunePeer {
                        check_fields(item)?;
                    }
                }
                _ => message.skip(tag)?,
            }
        }
    }
    Ok(())
}

/// QUILIBRIUM: checks a message without repeated or nested message fields.
fn check_fields(message: &[u8]) -> Result<(), RpcRejection> {
    let mut message = WireReader::new(message);
    while !message.is_empty() {
        let tag = message.varint32()?;
        message.skip(tag)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use libp2p_identity::Keypair;
    use quickcheck::*;

    use super::*;
    use crate::{
        config::Config, Behaviour, ConfigBuilder, IdentTopic as Topic, MessageAuthenticity, Version,
    };

    #[derive(Clone, Debug)]
    struct Message(RawMessage);

    impl Arbitrary for Message {
        fn arbitrary(g: &mut Gen) -> Self {
            let keypair = TestKeypair::arbitrary(g);

            // generate an arbitrary GossipsubMessage using the behaviour signing functionality
            let config = Config::default();
            let mut gs: Behaviour =
                Behaviour::new(MessageAuthenticity::Signed(keypair.0), config).unwrap();
            let mut data_g = quickcheck::Gen::new(10024);
            let data = (0..u8::arbitrary(&mut data_g))
                .map(|_| u8::arbitrary(g))
                .collect::<Vec<_>>();
            let topic_id = TopicId::arbitrary(g).0;
            Message(gs.build_raw_message(topic_id, data).unwrap())
        }
    }

    #[derive(Clone, Debug)]
    struct TopicId(TopicHash);

    impl Arbitrary for TopicId {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut data_g = quickcheck::Gen::new(1024);
            let topic_string: String = (0..u8::arbitrary(&mut data_g))
                .map(|_| char::arbitrary(g))
                .collect::<String>();
            TopicId(Topic::new(topic_string).into())
        }
    }

    #[derive(Clone)]
    struct TestKeypair(Keypair);

    impl Arbitrary for TestKeypair {
        fn arbitrary(_g: &mut Gen) -> Self {
            // Small enough to be inlined.
            TestKeypair(Keypair::generate_ed25519())
        }
    }

    impl std::fmt::Debug for TestKeypair {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestKeypair")
                .field("public", &self.0.public())
                .finish()
        }
    }

    #[test]
    /// Test that RPC messages can be encoded and decoded successfully.
    fn encode_decode() {
        fn prop(message: Message) {
            let message = message.0;

            let rpc = Rpc {
                messages: vec![message.clone()],
                subscriptions: vec![],
                control_msgs: vec![],
            };

            let mut codec =
                GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict, HashMap::new());
            let mut buf = BytesMut::new();
            codec.encode(rpc.into_protobuf(), &mut buf).unwrap();
            let decoded_rpc = codec.decode(&mut buf).unwrap().unwrap();
            // mark as validated as its a published message
            match decoded_rpc {
                HandlerEvent::Message { mut rpc, .. } => {
                    rpc.messages[0].validated = true;

                    assert_eq!(vec![message], rpc.messages);
                }
                _ => panic!("Must decode a message"),
            }
        }

        QuickCheck::new().quickcheck(prop as fn(_) -> _)
    }

    /// Signed messages on one topic, with `tampered` of them altered after
    /// signing so that their signatures fail.
    fn signed_messages(valid: u8, tampered: u8) -> Vec<RawMessage> {
        let keypair = Keypair::generate_ed25519();
        let mut gs: Behaviour =
            Behaviour::new(MessageAuthenticity::Signed(keypair), Config::default()).unwrap();
        let topic = TopicHash::from_raw("test");
        (0..valid.saturating_add(tampered))
            .map(|i| {
                let mut message = gs.build_raw_message(topic.clone(), vec![i]).unwrap();
                if i >= valid {
                    message.data.push(0xff);
                }
                message
            })
            .collect()
    }

    fn decode_rpc(
        codec: &mut GossipsubCodec,
        messages: Vec<RawMessage>,
    ) -> Result<Option<HandlerEvent>, quick_protobuf_codec::Error> {
        let rpc = Rpc {
            messages,
            subscriptions: vec![],
            control_msgs: vec![],
        };
        let mut buf = BytesMut::new();
        codec.encode(rpc.into_protobuf(), &mut buf).unwrap();
        codec.decode(&mut buf)
    }

    fn counts(event: Option<HandlerEvent>) -> (usize, usize) {
        match event {
            Some(HandlerEvent::Message {
                rpc,
                invalid_messages,
            }) => (rpc.messages.len(), invalid_messages.len()),
            _ => panic!("must decode an RPC"),
        }
    }

    /// QUILIBRIUM: a stream that sends more invalid signatures than the budget
    /// has the rest of its RPC dropped unverified and is then closed.
    #[test]
    fn invalid_signatures_past_the_budget_close_the_stream() {
        let budget = MAX_INVALID_SIGNATURES_PER_WINDOW as u8;
        let mut codec =
            GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict, HashMap::new());
        let event = decode_rpc(&mut codec, signed_messages(0, budget + 5)).unwrap();
        assert_eq!(counts(event), (0, budget as usize + 1));
        assert!(decode_rpc(&mut codec, signed_messages(1, 0)).is_err());
    }

    /// QUILIBRIUM: invalid signatures within the budget are reported and the
    /// stream keeps delivering valid messages.
    #[test]
    fn invalid_signatures_within_the_budget_keep_the_stream() {
        let budget = MAX_INVALID_SIGNATURES_PER_WINDOW as u8;
        let mut codec =
            GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict, HashMap::new());
        let event = decode_rpc(&mut codec, signed_messages(1, budget)).unwrap();
        assert_eq!(counts(event), (1, budget as usize));
        let event = decode_rpc(&mut codec, signed_messages(2, 0)).unwrap();
        assert_eq!(counts(event), (2, 0));
    }

    /// QUILIBRIUM: the signed bytes written from borrowed fields are those of
    /// the encoded message without signature and key, after the prefix.
    #[test]
    fn signature_payload_matches_the_encoded_message() {
        fn prop(message: Message, drop_from: bool, drop_seqno: bool, drop_data: bool) {
            let mut message: proto::Message = message.0.into();
            if drop_from {
                message.from = None;
            }
            if drop_seqno {
                message.seqno = None;
            }
            if drop_data {
                message.data = None;
            }
            let mut unsigned = message.clone();
            unsigned.signature = None;
            unsigned.key = None;
            let mut expected = SIGNING_PREFIX.to_vec();
            let mut writer = Writer::new(&mut expected);
            unsigned.write_message(&mut writer).unwrap();
            let payload = signature_payload(
                message.from.as_deref(),
                message.data.as_deref(),
                message.seqno.as_deref(),
                &message.topic,
            );
            assert_eq!(payload, expected);
            assert_eq!(payload.capacity(), payload.len(), "sized exactly");
        }

        QuickCheck::new().quickcheck(prop as fn(_, _, _, _) -> _)
    }

    /// QUILIBRIUM: the length computed from the fields is the encoded size.
    #[test]
    fn raw_protobuf_len_is_the_encoded_size() {
        fn prop(message: Message, drop_source: bool, drop_signature: bool, key: Vec<u8>) {
            let mut message = message.0;
            if drop_source {
                message.source = None;
                message.sequence_number = None;
            }
            if drop_signature {
                message.signature = None;
            }
            if !key.is_empty() {
                message.key = Some(key);
            }
            assert_eq!(
                message.raw_protobuf_len(),
                proto::Message::from(message.clone()).get_size(),
            );
        }

        QuickCheck::new().quickcheck(prop as fn(_, _, _, _) -> _)
    }

    /// QUILIBRIUM: the frame limit of the node's gossip (`MAX_MESSAGE_SIZE` in quil-p2p).
    const FRAME_LIMIT: usize = 16 * 1024 * 1024;

    /// QUILIBRIUM: `rpc` framed as on the wire.
    fn frame(rpc: proto::RPC) -> BytesMut {
        let mut codec =
            GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict, HashMap::new());
        let mut buf = BytesMut::new();
        codec.encode(rpc, &mut buf).unwrap();
        buf
    }

    /// QUILIBRIUM: decodes one whole frame, under the node's frame limit.
    fn decode_frame(mut buf: BytesMut) -> HandlerEvent {
        let mut codec = GossipsubCodec::new(FRAME_LIMIT, ValidationMode::Strict, HashMap::new());
        let event = codec.decode(&mut buf).unwrap().expect("a whole frame");
        assert!(buf.is_empty(), "the frame is consumed");
        event
    }

    /// QUILIBRIUM: an RPC with `count` entries of `entry`, each as small as it gets.
    fn rpc_with(entry: RpcEntry, count: usize) -> proto::RPC {
        let topic_id = Some("00".to_string());
        let mut rpc = proto::RPC::default();
        match entry {
            RpcEntry::Publish => rpc.publish = vec![proto::Message::default(); count],
            RpcEntry::Subscription => {
                rpc.subscriptions = vec![
                    proto::SubOpts {
                        subscribe: Some(true),
                        topic_id,
                    };
                    count
                ]
            }
            RpcEntry::ControlMessage => {
                rpc.control = Some(proto::ControlMessage {
                    graft: vec![proto::ControlGraft { topic_id }; count],
                    ..Default::default()
                })
            }
            RpcEntry::MessageId => {
                rpc.control = Some(proto::ControlMessage {
                    ihave: vec![proto::ControlIHave {
                        topic_id,
                        message_ids: vec![Vec::new(); count],
                    }],
                    ..Default::default()
                })
            }
            RpcEntry::PrunePeer => {
                rpc.control = Some(proto::ControlMessage {
                    prune: vec![proto::ControlPrune {
                        topic_id,
                        peers: vec![proto::PeerInfo::default(); count],
                        backoff: Some(60),
                    }],
                    ..Default::default()
                })
            }
        }
        rpc
    }

    /// QUILIBRIUM: an RPC with one entry more than its limit is dropped and consumed without
    /// being decoded; one at the limit is decoded.
    #[test]
    fn rpc_over_an_entry_limit_is_dropped_before_decoding() {
        let entries = [
            RpcEntry::Publish,
            RpcEntry::Subscription,
            RpcEntry::ControlMessage,
            RpcEntry::MessageId,
            RpcEntry::PrunePeer,
        ];
        for entry in entries {
            let limit = entry.limit();
            match decode_frame(frame(rpc_with(entry, limit + 1))) {
                HandlerEvent::RpcRejected { rejection, .. } => {
                    assert_eq!(rejection, RpcRejection::TooMany { entry, limit });
                }
                _ => panic!("{} {entry:?} entries were decoded", limit + 1),
            }
            assert!(
                matches!(
                    decode_frame(frame(rpc_with(entry, limit))),
                    HandlerEvent::Message { .. }
                ),
                "{limit} {entry:?} entries must be decoded"
            );
        }
    }

    /// QUILIBRIUM: frames the decoder could read differently from the count are dropped too.
    #[test]
    fn malformed_rpc_is_dropped_before_decoding() {
        let frames: [&[u8]; 4] = [
            // A publish entry whose topic runs past the entry's end.
            &[0x12, 0x02, 0x22, 0x05, 0x00, 0x00, 0x00],
            // A publish entry running past the frame's end.
            &[0x12, 0x05, 0x00],
            // A group.
            &[0x13, 0x00],
            // A tag beyond 32 bits.
            &[0x92, 0x80, 0x80, 0x80, 0x10, 0x00],
        ];
        for bytes in frames {
            let mut buf = BytesMut::from(&[bytes.len() as u8][..]);
            buf.extend_from_slice(bytes);
            assert!(
                matches!(
                    decode_frame(buf),
                    HandlerEvent::RpcRejected {
                        rejection: RpcRejection::Malformed,
                        ..
                    }
                ),
                "{bytes:02x?} must be dropped as malformed"
            );
        }
    }

    /// QUILIBRIUM: the largest legitimate RPCs are still decoded: a signed 15 MiB message (the
    /// node gossips GLOBAL frames up to that size) under the 16 MiB frame limit, and an IHAVE
    /// with `max_ihave_length` ids of the node's 33-byte message id.
    #[test]
    fn largest_legitimate_rpcs_are_decoded() {
        let config = Config::default();
        let max_ihave_length = config.max_ihave_length();
        let mut gs: Behaviour = Behaviour::new(
            MessageAuthenticity::Signed(Keypair::generate_ed25519()),
            config,
        )
        .unwrap();
        let topic: TopicHash = Topic::new("0000").into();
        let message = gs
            .build_raw_message(topic.clone(), vec![0xab; 15 * 1024 * 1024])
            .unwrap();
        let publish = Rpc {
            messages: vec![message],
            subscriptions: vec![],
            control_msgs: vec![],
        };
        match decode_frame(frame(publish.into_protobuf())) {
            HandlerEvent::Message {
                rpc,
                invalid_messages,
            } => {
                assert!(invalid_messages.is_empty());
                assert_eq!(rpc.messages.len(), 1);
            }
            _ => panic!("the largest message must be decoded"),
        }

        let ihave = Rpc {
            messages: vec![],
            subscriptions: vec![],
            control_msgs: vec![ControlAction::IHave(IHave {
                topic_hash: topic,
                message_ids: vec![MessageId::from(vec![0x01; 33]); max_ihave_length],
            })],
        };
        assert!(matches!(
            decode_frame(frame(ihave.into_protobuf())),
            HandlerEvent::Message { .. }
        ));
    }

    #[test]
    fn support_floodsub_with_custom_protocol() {
        let protocol_config = ConfigBuilder::default()
            .protocol_id("/foosub", Version::V1_1)
            .support_floodsub()
            .build()
            .unwrap()
            .protocol_config();

        assert_eq!(protocol_config.protocol_ids[0].protocol, "/foosub");
        assert_eq!(protocol_config.protocol_ids[1].protocol, "/floodsub/1.0.0");
    }

    /// Gossip entries signed with an Ed448 key are verified like any other,
    /// with big-integer reference code that costs far more than the Falcon
    /// keys nodes sign with; validly signed ones cost that check every time.
    #[test]
    fn reproduces_ed448_signed_gossip_verified() {
        let mut gs: Behaviour = Behaviour::new(
            MessageAuthenticity::Signed(Keypair::generate_ed448()),
            Config::default(),
        )
        .unwrap();
        let message = gs
            .build_raw_message(TopicHash::from_raw("test"), vec![1, 2, 3])
            .unwrap();
        let rpc = Rpc {
            messages: vec![message],
            subscriptions: vec![],
            control_msgs: vec![],
        };
        let mut codec =
            GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict, HashMap::new());
        let mut buf = BytesMut::new();
        codec.encode(rpc.into_protobuf(), &mut buf).unwrap();
        let accepted = match codec.decode(&mut buf) {
            Ok(Some(HandlerEvent::Message { rpc, .. })) => rpc.messages.len(),
            Ok(_) => panic!("must decode an RPC"),
            Err(_) => 0,
        };
        assert_eq!(
            accepted, 0,
            "an Ed448-signed gossip entry was verified and accepted"
        );
    }

    /// One RPC whose entries all carry invalid signatures must not cost one
    /// signature verification per entry: the key and signature of each entry
    /// are the sender's choice, and verification runs before any dedup.
    #[test]
    fn reproduces_unbounded_signature_verification_per_rpc() {
        let keypair = Keypair::generate_ed25519();
        let mut gs: Behaviour =
            Behaviour::new(MessageAuthenticity::Signed(keypair), Config::default()).unwrap();
        let topic = TopicHash::from_raw("test");
        let messages = (0..64u8)
            .map(|i| {
                let mut message = gs.build_raw_message(topic.clone(), vec![i]).unwrap();
                // Altered after signing, so the signature no longer verifies.
                message.data.push(0xff);
                message
            })
            .collect::<Vec<_>>();
        let rpc = Rpc {
            messages,
            subscriptions: vec![],
            control_msgs: vec![],
        };
        let mut codec =
            GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict, HashMap::new());
        let mut buf = BytesMut::new();
        codec.encode(rpc.into_protobuf(), &mut buf).unwrap();
        let verified = match codec.decode(&mut buf) {
            Ok(Some(HandlerEvent::Message {
                invalid_messages, ..
            })) => invalid_messages.len(),
            Ok(_) => panic!("must decode an RPC"),
            Err(_) => 0,
        };
        assert!(
            verified <= 32,
            "one RPC made the codec verify {verified} invalid signatures out of 64 entries"
        );
    }

    /// QUILIBRIUM: a frame of empty publish entries is not decoded entry by entry. Each such
    /// entry is two bytes on the wire, but a decoded one becomes a message record of hundreds
    /// of bytes, so decoding them all lets one frame of the node's 16 MiB limit cost
    /// gigabytes. The frame here is a sixty-fourth of that limit; the cost scales with it.
    #[test]
    fn reproduces_empty_entry_frame_decoding() {
        /// The bytes a vector of records holds.
        fn held<T>(records: &Vec<T>) -> usize {
            records.capacity() * std::mem::size_of::<T>()
        }

        /// The frame limit of the node's gossip (`MAX_MESSAGE_SIZE` in quil-p2p).
        const FRAME_LIMIT: usize = 16 * 1024 * 1024;
        /// The most entries an RPC is expected to carry: this crate sends one per RPC.
        const MAX_DECODED_ENTRIES: usize = 128;
        let entries = FRAME_LIMIT / 64 / 2;

        // `publish` (field 2), an empty message, repeated.
        let body: Vec<u8> = [0x12, 0x00].repeat(entries);
        let mut frame = Vec::with_capacity(body.len() + 10);
        let mut len = body.len();
        while len >= 0x80 {
            frame.push((len as u8 & 0x7f) | 0x80);
            len >>= 7;
        }
        frame.push(len as u8);
        frame.extend_from_slice(&body);
        let frame_len = frame.len();

        let mut codec = GossipsubCodec::new(FRAME_LIMIT, ValidationMode::Strict, HashMap::new());
        let mut buf = BytesMut::from(&frame[..]);
        let event = codec
            .decode(&mut buf)
            .expect("a well-formed frame is not an error")
            .expect("a whole frame");
        assert!(buf.is_empty(), "the frame is consumed");

        if let HandlerEvent::Message {
            rpc,
            invalid_messages,
        } = event
        {
            let decoded = rpc.messages.len() + invalid_messages.len();
            let bytes = held(&rpc.messages) + held(&invalid_messages);
            assert!(
                decoded <= MAX_DECODED_ENTRIES,
                "a {frame_len}-byte frame of {entries} empty publish entries was decoded into \
                 {decoded} message records holding {bytes} bytes ({}x the frame): the codec \
                 decodes every entry before it checks any",
                bytes / frame_len,
            );
        }
    }

    /// Signed messages from one Falcon key, the network identity's type.
    fn falcon_signed_messages(count: u8) -> Vec<RawMessage> {
        let mut gs: Behaviour = Behaviour::new(
            MessageAuthenticity::Signed(Keypair::generate_falcon()),
            Config::default(),
        )
        .unwrap();
        let topic = TopicHash::from_raw("test");
        (0..count)
            .map(|i| gs.build_raw_message(topic.clone(), vec![i]).unwrap())
            .collect()
    }

    /// QUILIBRIUM: entries signed with the Falcon network identity verify.
    #[test]
    fn falcon_signed_entries_are_accepted() {
        let mut codec =
            GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict, HashMap::new());
        let event = decode_rpc(&mut codec, falcon_signed_messages(2)).unwrap();
        assert_eq!(counts(event), (2, 0));
    }

    /// QUILIBRIUM: a copy of a verified entry is accepted from the shared
    /// cache, on any stream of the behaviour, but the cache is keyed by the
    /// key the entry carries: a copy whose key was swapped is checked again
    /// and fails.
    #[test]
    fn verified_entries_are_shared_and_keyed_by_their_key() {
        let verified = Arc::new(VerifiedSignatures::default());
        let codec = || {
            GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict, HashMap::new())
                .with_verified_signatures(verified.clone())
        };
        let message = falcon_signed_messages(1).remove(0);
        let event = decode_rpc(&mut codec(), vec![message.clone()]).unwrap();
        assert_eq!(counts(event), (1, 0));
        let proto = proto::Message::from(message.clone());
        let signed = signature_payload(
            proto.from.as_deref(),
            proto.data.as_deref(),
            proto.seqno.as_deref(),
            &proto.topic,
        );
        let digest = verified_digest(
            &signed,
            proto.signature.as_deref().unwrap(),
            proto.key.as_deref(),
        );
        assert!(verified.contains(&digest), "the verified entry is cached");
        let event = decode_rpc(&mut codec(), vec![message.clone()]).unwrap();
        assert_eq!(counts(event), (1, 0));

        let mut swapped = message;
        swapped.key = Some(Keypair::generate_falcon().public().encode_protobuf());
        let event = decode_rpc(&mut codec(), vec![swapped]).unwrap();
        assert_eq!(counts(event), (0, 1));
    }

    /// QUILIBRIUM: entries signed with a refused key type (Ed448 here) are
    /// reported as such, not as invalid signatures, so they do not spend the
    /// stream's budget, and are not verified.
    #[test]
    fn refused_key_types_are_reported_without_spending_the_budget() {
        let mut gs: Behaviour = Behaviour::new(
            MessageAuthenticity::Signed(Keypair::generate_ed448()),
            Config::default(),
        )
        .unwrap();
        let topic = TopicHash::from_raw("test");
        let budget = MAX_INVALID_SIGNATURES_PER_WINDOW as u8;
        let messages = (0..budget + 4)
            .map(|i| gs.build_raw_message(topic.clone(), vec![i]).unwrap())
            .collect();
        let mut codec =
            GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict, HashMap::new());
        match decode_rpc(&mut codec, messages).unwrap() {
            Some(HandlerEvent::Message {
                rpc,
                invalid_messages,
            }) => {
                assert!(rpc.messages.is_empty());
                assert_eq!(invalid_messages.len(), budget as usize + 4);
                assert!(invalid_messages
                    .iter()
                    .all(|(_, error)| *error == ValidationError::RefusedKeyType));
            }
            _ => panic!("must decode an RPC"),
        }
        assert!(!codec.invalid_signatures.exhausted);
        let event = decode_rpc(&mut codec, falcon_signed_messages(1)).unwrap();
        assert_eq!(counts(event), (1, 0));
    }

    /// QUILIBRIUM: the cache keeps the newest `MAX_VERIFIED_SIGNATURES`.
    #[test]
    fn verified_signatures_are_bounded() {
        let verified = VerifiedSignatures::default();
        let digest = |i: usize| verified_digest(&i.to_be_bytes(), &[], None);
        for i in 0..=MAX_VERIFIED_SIGNATURES {
            verified.insert(digest(i));
        }
        assert!(!verified.contains(&digest(0)));
        assert!(verified.contains(&digest(1)));
        assert!(verified.contains(&digest(MAX_VERIFIED_SIGNATURES)));
    }

    /// QUILIBRIUM: a key type is read as the decoder reads it, so a repeated
    /// `Type` field cannot pass the check under one type and decode as another.
    #[test]
    fn encoded_key_type_reads_the_last_type_field() {
        let falcon = Keypair::generate_falcon().public().encode_protobuf();
        assert_eq!(encoded_key_type(&falcon), Some(5));
        let mut retyped = vec![0x08, 0x05];
        retyped.extend_from_slice(&falcon);
        retyped.extend_from_slice(&[0x08, 0x04]);
        assert_eq!(encoded_key_type(&retyped), Some(4));
        assert!(decode_signing_key(&retyped).is_none());
        assert!(decode_signing_key(&falcon).is_some());
        assert_eq!(encoded_key_type(&[0x80]), None);
    }
}
