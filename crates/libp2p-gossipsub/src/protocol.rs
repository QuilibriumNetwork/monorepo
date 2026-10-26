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

use std::{collections::HashMap, convert::Infallible, fmt, io, pin::Pin};

use asynchronous_codec::{Decoder, Encoder, Framed};
use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use futures::prelude::*;
use libp2p_core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use libp2p_identity::{PeerId, PublicKey};
use libp2p_swarm::StreamProtocol;
use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};

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
                ),
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
                ),
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
        }
    }

    /// Get the max transmit size for a given topic if it exists.
    fn max_transmit_size_for_topic(&self, topic: &TopicHash) -> Option<usize> {
        self.max_transmit_sizes.get(topic).copied()
    }

    /// Verifies a gossipsub message. This returns either a success or failure. All errors
    /// are logged, which prevents error handling in the codec and handler. We simply drop invalid
    /// messages and log warnings, rather than propagating errors through the codec.
    fn verify_signature(message: &proto::Message) -> bool {
        let Some(from) = message.from.as_ref() else {
            tracing::debug!("Signature verification failed: No source id given");
            return false;
        };

        let Ok(source) = PeerId::from_bytes(from) else {
            tracing::debug!("Signature verification failed: Invalid Peer Id");
            return false;
        };

        let Some(signature) = message.signature.as_ref() else {
            tracing::debug!("Signature verification failed: No signature provided");
            return false;
        };

        // If there is a key value in the protobuf, use that key otherwise the key must be
        // obtained from the inlined source peer_id.
        let public_key = match message.key.as_deref().map(PublicKey::try_decode_protobuf) {
            Some(Ok(key)) => key,
            _ => match PublicKey::try_decode_protobuf(&source.to_bytes()[2..]) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!("Signature verification failed: No valid public key supplied");
                    return false;
                }
            },
        };

        // The key must match the peer_id
        if source != public_key.to_peer_id() {
            tracing::warn!(
                "Signature verification failed: Public key doesn't match source peer id"
            );
            return false;
        }

        // Construct the signature bytes
        let signature_bytes = signature_payload(
            message.from.as_deref(),
            message.data.as_deref(),
            message.seqno.as_deref(),
            &message.topic,
        );
        public_key.verify(&signature_bytes, signature)
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
            if verify_signature && !GossipsubCodec::verify_signature(&message) {
                tracing::warn!("Invalid signature for received message");
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
}
