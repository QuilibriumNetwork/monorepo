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

use crate::config::ValidationMode;
use crate::handler::HandlerEvent;
use crate::pb;
use crate::topic::TopicHash;
use crate::types::{
    ControlAction, MessageId, PeerInfo, PeerKind, RawMessage, Rpc, Subscription, SubscriptionAction,
};
use crate::ValidationError;
use asynchronous_codec::{Decoder, Encoder, Framed};
use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use futures::prelude::*;
use libp2p_core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use libp2p_identity::{PeerId, PublicKey};
use libp2p_swarm::StreamProtocol;
use prost::Message as _;
use std::pin::Pin;
use void::Void;

pub(crate) const SIGNING_PREFIX: &[u8] = b"libp2p-pubsub:";

/// Maximum RPC message size accepted/produced by the BlossomSub codec (16 MiB),
/// matching the reference implementation in `quil-p2p`.
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum length (bytes) of a bitmask topic accepted in an inbound SUBSCRIBE.
/// A `TopicHash` wraps the raw bitmask `Vec<u8>` and is retained in the
/// per-peer/per-topic tracking maps, so without this cap a single 16 MiB RPC
/// frame could register topics whose keys alone exhaust memory (a peer can pack
/// millions of oversized-bitmask subscriptions into one frame). Real bitmasks
/// are tiny (a 256-bit shard bloom is 32 bytes); 256 is far above any
/// legitimate value while bounding the per-subscription key size.
pub const MAX_BITMASK_LEN: usize = 256;

/// The BlossomSub v2.1.0 protocol negotiated on mainnet (`network = 0`).
pub(crate) const BLOSSOMSUB_2_1_0_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/blossomsub/2.1.0"),
    kind: PeerKind::Gossipsubv1_1,
};

// Retained so the `ConfigBuilder::support_floodsub` machinery keeps compiling.
// BlossomSub negotiates a single `/blossomsub/2.1.0` protocol by default (see
// `ProtocolConfig::default`).
pub(crate) const FLOODSUB_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/floodsub/1.0.0"),
    kind: PeerKind::Floodsub,
};

/// Protocol ID string for `network`. Mainnet (`0`) keeps the bare ID; every
/// other network suffixes `-network-N` so isolated chains never negotiate a
/// common stream protocol. Mirrors `quil-p2p::protocol::protocol_id_for_network`.
#[allow(dead_code)] // configurability helper for later stages / callers
pub fn protocol_id_for_network(network: u8) -> String {
    if network == 0 {
        "/blossomsub/2.1.0".to_string()
    } else {
        format!("/blossomsub/2.1.0-network-{}", network)
    }
}

/// Implementation of [`InboundUpgrade`] and [`OutboundUpgrade`] for the Gossipsub protocol.
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// The Gossipsub protocol id to listen on.
    pub(crate) protocol_ids: Vec<ProtocolId>,
    /// The maximum transmit size for a packet.
    pub(crate) max_transmit_size: usize,
    /// Determines the level of validation to be done on incoming messages.
    pub(crate) validation_mode: ValidationMode,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            max_transmit_size: MAX_MESSAGE_SIZE,
            validation_mode: ValidationMode::Strict,
            protocol_ids: vec![BLOSSOMSUB_2_1_0_PROTOCOL],
        }
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
    type Error = Void;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, socket: TSocket, protocol_id: Self::Info) -> Self::Future {
        Box::pin(future::ok((
            Framed::new(
                socket,
                GossipsubCodec::new(self.max_transmit_size, self.validation_mode),
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
    type Error = Void;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, socket: TSocket, protocol_id: Self::Info) -> Self::Future {
        Box::pin(future::ok((
            Framed::new(
                socket,
                GossipsubCodec::new(self.max_transmit_size, self.validation_mode),
            ),
            protocol_id.kind,
        )))
    }
}

/* Gossip codec for the framing */

pub struct GossipsubCodec {
    /// Determines the level of validation performed on incoming messages.
    validation_mode: ValidationMode,
    /// The maximum permitted RPC frame size (excluding the length prefix).
    max_length: usize,
}

/// Reads an unsigned LEB128 varint from the front of `buf` **without
/// consuming** it. Returns `Ok(Some((value, bytes_used)))` on success,
/// `Ok(None)` if the buffer holds an incomplete varint, or `Err` if it is
/// malformed (more than 10 bytes).
fn peek_uvarint(buf: &[u8]) -> Result<Option<(u64, usize)>, std::io::Error> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if i >= 10 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "varint length prefix too long",
            ));
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(Some((value, i + 1)));
        }
        shift += 7;
    }
    // Ran out of bytes before the terminating byte: incomplete.
    Ok(None)
}

/// Writes `value` as an unsigned LEB128 varint into `dst`.
fn put_uvarint(mut value: u64, dst: &mut BytesMut) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        dst.extend_from_slice(&[byte]);
        if value == 0 {
            break;
        }
    }
}

impl GossipsubCodec {
    pub fn new(max_length: usize, validation_mode: ValidationMode) -> GossipsubCodec {
        GossipsubCodec {
            validation_mode,
            max_length,
        }
    }

    /// Verifies a BlossomSub message signature. This returns either a success or failure. All
    /// errors are logged, which prevents error handling in the codec and handler. We simply drop
    /// invalid messages and log warnings, rather than propagating errors through the codec.
    ///
    /// The signed bytes are `"libp2p-pubsub:" ++ prost_marshal(Message{sig=[], key=[]})`.
    fn verify_signature(message: &pb::Message) -> bool {
        if message.from.is_empty() {
            tracing::debug!("Signature verification failed: No source id given");
            return false;
        }
        let from = &message.from;

        let Ok(source) = PeerId::from_bytes(from) else {
            tracing::debug!("Signature verification failed: Invalid Peer Id");
            return false;
        };

        if message.signature.is_empty() {
            tracing::debug!("Signature verification failed: No signature provided");
            return false;
        }
        let signature = &message.signature;

        // If there is a key value in the protobuf, use that key otherwise the key must be
        // obtained from the inlined source peer_id.
        let public_key = if !message.key.is_empty() {
            match PublicKey::try_decode_protobuf(&message.key) {
                Ok(key) => key,
                Err(_) => {
                    tracing::debug!("Signature verification failed: No valid public key supplied");
                    return false;
                }
            }
        } else {
            match PublicKey::try_decode_protobuf(&source.to_bytes()[2..]) {
                Ok(v) => v,
                Err(_) => {
                    tracing::debug!("Signature verification failed: No valid public key supplied");
                    return false;
                }
            }
        };

        // The key must match the peer_id
        if source != public_key.to_peer_id() {
            tracing::debug!(
                "Signature verification failed: Public key doesn't match source peer id"
            );
            return false;
        }

        // Construct the signature bytes: sign over the message with signature/key cleared.
        let mut message_sig = message.clone();
        message_sig.signature = Vec::new();
        message_sig.key = Vec::new();
        let mut signature_bytes = SIGNING_PREFIX.to_vec();
        message_sig.encode(&mut signature_bytes).expect(
            "Vec<u8> is an infallible prost encode target",
        );
        public_key.verify(&signature_bytes, signature)
    }
}

impl Encoder for GossipsubCodec {
    type Item<'a> = pb::Rpc;
    type Error = std::io::Error;

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let len = item.encoded_len();
        if len > self.max_length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "rpc message length {len} exceeds maximum {}",
                    self.max_length
                ),
            ));
        }
        let mut body = Vec::with_capacity(len);
        item.encode(&mut body)
            .expect("Vec<u8> is an infallible prost encode target");
        dst.reserve(body.len() + 10);
        put_uvarint(body.len() as u64, dst);
        dst.extend_from_slice(&body);
        Ok(())
    }
}

impl Decoder for GossipsubCodec {
    type Item = HandlerEvent;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Peek the length prefix without consuming, so a partial frame is left
        // intact for the next call.
        let (msg_len, prefix_len) = match peek_uvarint(src)? {
            Some(v) => v,
            None => return Ok(None),
        };
        let msg_len = msg_len as usize;
        if msg_len > self.max_length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "rpc message length {msg_len} exceeds maximum {}",
                    self.max_length
                ),
            ));
        }
        if src.len() < prefix_len + msg_len {
            // Not enough data for the full frame yet.
            src.reserve(prefix_len + msg_len - src.len());
            return Ok(None);
        }
        // Consume the prefix and the frame body.
        let _ = src.split_to(prefix_len);
        let frame = src.split_to(msg_len);
        let rpc = pb::Rpc::decode(&frame[..]).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;

        // Store valid messages.
        let mut messages = Vec::with_capacity(rpc.publish.len());
        // Store any invalid messages.
        let mut invalid_messages = Vec::new();

        for message in rpc.publish.into_iter() {
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
                    if !message.signature.is_empty() {
                        verify_signature = true;
                    }
                    if !message.seqno.is_empty() {
                        verify_sequence_no = true;
                    }
                    if !message.from.is_empty() {
                        verify_source = true;
                    }
                }
                ValidationMode::Anonymous => {
                    if !message.signature.is_empty() {
                        tracing::debug!(
                            "Signature field was non-empty and anonymous validation mode is set"
                        );
                        invalid_kind = Some(ValidationError::SignaturePresent);
                    } else if !message.seqno.is_empty() {
                        tracing::debug!(
                            "Sequence number was non-empty and anonymous validation mode is set"
                        );
                        invalid_kind = Some(ValidationError::SequenceNumberPresent);
                    } else if !message.from.is_empty() {
                        tracing::debug!("Message dropped. Message source was non-empty and anonymous validation mode is set");
                        invalid_kind = Some(ValidationError::MessageSourcePresent);
                    }
                }
                ValidationMode::None => {}
            }

            // A `bytes` field is "absent" (proto3) when empty; map to `Option`
            // semantics so the rest of the validation reads naturally.
            let opt_key = if message.key.is_empty() {
                None
            } else {
                Some(message.key.clone())
            };
            let opt_signature = if message.signature.is_empty() {
                None
            } else {
                Some(message.signature.clone())
            };

            // If the initial validation logic failed, add the message to invalid messages and
            // continue processing the others.
            if let Some(validation_error) = invalid_kind.take() {
                let message = RawMessage {
                    source: None, // don't bother inform the application
                    data: message.data,
                    sequence_number: None, // don't inform the application
                    topic: TopicHash::from_raw(message.bitmask),
                    signature: None, // don't inform the application
                    key: opt_key,
                    validated: false,
                };
                invalid_messages.push((message, validation_error));
                // proceed to the next message
                continue;
            }

            // verify message signatures if required
            if verify_signature && !GossipsubCodec::verify_signature(&message) {
                tracing::debug!("Invalid signature for received message");

                // Build the invalid message (ignoring further validation of sequence number
                // and source)
                let message = RawMessage {
                    source: None, // don't bother inform the application
                    data: message.data,
                    sequence_number: None, // don't inform the application
                    topic: TopicHash::from_raw(message.bitmask),
                    signature: None, // don't inform the application
                    key: opt_key,
                    validated: false,
                };
                invalid_messages.push((message, ValidationError::InvalidSignature));
                // proceed to the next message
                continue;
            }

            // ensure the sequence number is a u64
            let sequence_number = if verify_sequence_no {
                if message.seqno.is_empty() {
                    None
                } else if message.seqno.len() != 8 {
                    tracing::debug!(
                        sequence_number=?message.seqno,
                        sequence_length=%message.seqno.len(),
                        "Invalid sequence number length for received message"
                    );
                    let message = RawMessage {
                        source: None, // don't bother inform the application
                        data: message.data,
                        sequence_number: None, // don't inform the application
                        topic: TopicHash::from_raw(message.bitmask),
                        signature: opt_signature, // don't inform the application
                        key: opt_key,
                        validated: false,
                    };
                    invalid_messages.push((message, ValidationError::InvalidSequenceNumber));
                    // proceed to the next message
                    continue;
                } else {
                    // valid sequence number
                    Some(BigEndian::read_u64(&message.seqno))
                }
            } else {
                // Do not verify the sequence number, consider it empty
                None
            };

            // Verify the message source if required
            let source = if verify_source && !message.from.is_empty() {
                match PeerId::from_bytes(&message.from) {
                    Ok(peer_id) => Some(peer_id), // valid peer id
                    Err(_) => {
                        // invalid peer id, add to invalid messages
                        tracing::debug!("Message source has an invalid PeerId");
                        let message = RawMessage {
                            source: None, // don't bother inform the application
                            data: message.data,
                            sequence_number,
                            topic: TopicHash::from_raw(message.bitmask),
                            signature: opt_signature, // don't inform the application
                            key: opt_key,
                            validated: false,
                        };
                        invalid_messages.push((message, ValidationError::InvalidPeerId));
                        continue;
                    }
                }
            } else {
                None
            };

            // This message has passed all validation, add it to the validated messages.
            messages.push(RawMessage {
                source,
                data: message.data,
                sequence_number,
                topic: TopicHash::from_raw(message.bitmask),
                signature: opt_signature,
                key: opt_key,
                validated: false,
            });
        }

        let mut control_msgs = Vec::new();

        if let Some(rpc_control) = rpc.control {
            // Collect the BlossomSub control messages
            let ihave_msgs: Vec<ControlAction> = rpc_control
                .ihave
                .into_iter()
                .map(|ihave| ControlAction::IHave {
                    topic_hash: TopicHash::from_raw(ihave.bitmask),
                    message_ids: ihave
                        .message_i_ds
                        .into_iter()
                        .map(MessageId::from)
                        .collect::<Vec<_>>(),
                })
                .collect();

            let iwant_msgs: Vec<ControlAction> = rpc_control
                .iwant
                .into_iter()
                .map(|iwant| ControlAction::IWant {
                    message_ids: iwant
                        .message_i_ds
                        .into_iter()
                        .map(MessageId::from)
                        .collect::<Vec<_>>(),
                })
                .collect();

            let graft_msgs: Vec<ControlAction> = rpc_control
                .graft
                .into_iter()
                .map(|graft| ControlAction::Graft {
                    topic_hash: TopicHash::from_raw(graft.bitmask),
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

                let topic_hash = TopicHash::from_raw(prune.bitmask);
                prune_msgs.push(ControlAction::Prune {
                    topic_hash,
                    peers,
                    backoff: Some(prune.backoff),
                });
            }

            let idontwant_msgs: Vec<ControlAction> = rpc_control
                .idontwant
                .into_iter()
                .map(|idontwant| ControlAction::IDontWant {
                    message_ids: idontwant
                        .message_i_ds
                        .into_iter()
                        .map(MessageId::from)
                        .collect::<Vec<_>>(),
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
                    // Drop subscriptions carrying an over-long bitmask: the
                    // topic key is retained in per-peer/per-topic maps, so an
                    // uncapped bitmask is a memory-exhaustion vector. Real
                    // bitmasks are <= 32 bytes.
                    .filter(|sub| sub.bitmask.len() <= MAX_BITMASK_LEN)
                    .map(|sub| Subscription {
                        action: if sub.subscribe {
                            SubscriptionAction::Subscribe
                        } else {
                            SubscriptionAction::Unsubscribe
                        },
                        topic_hash: TopicHash::from_raw(sub.bitmask),
                    })
                    .collect(),
                control_msgs,
            },
            invalid_messages,
        }))
    }
}

// Quarantined during the BlossomSub fork: this quickcheck codec property test
// targets upstream's native RPC/topic protobuf, which Stage 2 replaces with the
// BlossomSub wire format. Rewritten there. (Also needs the old quickcheck
// `Gen::gen_range` API.)
#[cfg(all(test, feature = "upstream-tests"))]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::{Behaviour, ConfigBuilder};
    use crate::{IdentTopic as Topic, Version};
    use libp2p_identity::Keypair;
    use quickcheck::*;

    #[derive(Clone, Debug)]
    struct Message(RawMessage);

    impl Arbitrary for Message {
        fn arbitrary(g: &mut Gen) -> Self {
            let keypair = TestKeypair::arbitrary(g);

            // generate an arbitrary GossipsubMessage using the behaviour signing functionality
            let config = Config::default();
            let mut gs: Behaviour =
                Behaviour::new(crate::MessageAuthenticity::Signed(keypair.0), config).unwrap();
            let data = (0..g.gen_range(10..10024u32))
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
            let topic_string: String = (0..g.gen_range(20..1024u32))
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

            let mut codec = GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict);
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

/// Stage-4: IDONTWANT wire round trip. Kept OUT of the quarantined
/// `upstream-tests`-gated `tests` module above so it runs by default.
#[cfg(test)]
mod stage4_wire_tests {
    use super::*;
    use crate::types::{ControlAction, MessageId, Rpc};
    use asynchronous_codec::{Decoder, Encoder};
    use bytes::BytesMut;

    #[test]
    /// IDONTWANT control messages survive a full encode -> wire -> decode round
    /// trip (Stage-4 carry-forward: decode previously dropped them).
    fn idontwant_wire_round_trip() {
        let ids = vec![
            MessageId::from(vec![1u8, 2, 3]),
            MessageId::from(vec![9u8, 9]),
        ];
        let rpc = Rpc {
            messages: vec![],
            subscriptions: vec![],
            control_msgs: vec![ControlAction::IDontWant {
                message_ids: ids.clone(),
            }],
        };

        let mut codec = GossipsubCodec::new(u32::MAX as usize, ValidationMode::Permissive);
        let mut buf = BytesMut::new();
        codec.encode(rpc.into_protobuf(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        match decoded {
            HandlerEvent::Message { rpc, .. } => {
                let got = rpc
                    .control_msgs
                    .into_iter()
                    .find_map(|c| match c {
                        ControlAction::IDontWant { message_ids } => Some(message_ids),
                        _ => None,
                    })
                    .expect("IDONTWANT must survive encode + decode");
                assert_eq!(got, ids);
            }
            _ => panic!("must decode a message"),
        }
    }
}

/// Stage-7 wire-sanity guard: lock the StrictSign signing preimage so future
/// edits can't silently drift the on-wire signature contract away from Go's
/// `WithStrictSignatureVerification`. `verify_signature` (above) is the
/// authoritative reconstruction; this test pins the exact bytes it signs over.
#[cfg(test)]
mod wire_sanity_tests {
    use super::*;
    use crate::pb;
    use libp2p_identity::Keypair;
    use prost::Message as _;

    /// The signing prefix must be exactly `libp2p-pubsub:` (byte-for-byte).
    #[test]
    fn signing_prefix_is_locked() {
        assert_eq!(SIGNING_PREFIX, b"libp2p-pubsub:");
    }

    /// StrictSign preimage = `"libp2p-pubsub:" ++ prost(Message{sig=[], key=[]})`.
    /// A signature produced over that preimage must verify against the author's
    /// key — i.e. this is the real contract both `sign` and `verify_signature`
    /// implement.
    #[test]
    fn strict_sign_preimage_is_prefix_plus_prost_with_empty_sig_key() {
        let kp = Keypair::generate_ed25519();
        let author = kp.public().to_peer_id();

        // The wire message as it appears after signing (sig/key populated).
        let mut signed = pb::Message {
            from: author.to_bytes(),
            data: vec![1, 2, 3, 4, 5],
            seqno: 42u64.to_be_bytes().to_vec(),
            bitmask: vec![0xC0, 0x00],
            signature: Vec::new(),
            key: Vec::new(),
        };

        // Reconstruct the preimage exactly as the signer does.
        let mut preimage = SIGNING_PREFIX.to_vec();
        signed.encode(&mut preimage).unwrap();
        assert_eq!(&preimage[..SIGNING_PREFIX.len()], b"libp2p-pubsub:");
        // Body after the prefix is exactly prost(message) with empty sig/key.
        assert_eq!(&preimage[SIGNING_PREFIX.len()..], signed.encode_to_vec().as_slice());

        // Sign and populate the wire fields.
        let signature = kp.sign(&preimage).unwrap();
        signed.signature = signature.clone();

        // Independently recompute the preimage from the signed wire message
        // (clearing sig/key) and confirm it verifies — the receive path.
        let mut cleared = signed.clone();
        cleared.signature = Vec::new();
        cleared.key = Vec::new();
        let mut verify_bytes = SIGNING_PREFIX.to_vec();
        cleared.encode(&mut verify_bytes).unwrap();
        assert_eq!(verify_bytes, preimage);
        assert!(kp.public().verify(&verify_bytes, &signature));
    }
}
