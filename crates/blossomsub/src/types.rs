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

//! A collection of types using the Gossipsub system.
use crate::TopicHash;
use libp2p_identity::PeerId;
use libp2p_swarm::ConnectionId;
use prometheus_client::encoding::EncodeLabelValue;
use prost::Message as _;
use std::fmt;
use std::fmt::Debug;

use crate::pb;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug)]
/// Validation kinds from the application for received messages.
pub enum MessageAcceptance {
    /// The message is considered valid, and it should be delivered and forwarded to the network.
    Accept,
    /// The message is considered invalid, and it should be rejected and trigger the P₄ penalty.
    Reject,
    /// The message is neither delivered nor forwarded to the network, but the router does not
    /// trigger the P₄ penalty.
    Ignore,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub Vec<u8>);

impl MessageId {
    pub fn new(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl<T: Into<Vec<u8>>> From<T> for MessageId {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_fmt::HexFmt(&self.0))
    }
}

impl std::fmt::Debug for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MessageId({})", hex_fmt::HexFmt(&self.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeerConnections {
    /// The kind of protocol the peer supports.
    pub(crate) kind: PeerKind,
    /// Its current connections.
    pub(crate) connections: Vec<ConnectionId>,
}

/// Describes the types of peers that can exist in the gossipsub context.
#[derive(Debug, Clone, PartialEq, Hash, EncodeLabelValue, Eq)]
pub enum PeerKind {
    /// A gossipsub 1.1 peer.
    Gossipsubv1_1,
    /// A gossipsub 1.0 peer.
    Gossipsub,
    /// A floodsub peer.
    Floodsub,
    /// The peer doesn't support any of the protocols.
    NotSupported,
}

/// A message received by the gossipsub system and stored locally in caches..
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawMessage {
    /// Id of the peer that published this message.
    pub source: Option<PeerId>,

    /// Content of the message. Its meaning is out of scope of this library.
    pub data: Vec<u8>,

    /// A random sequence number.
    pub sequence_number: Option<u64>,

    /// The topic this message belongs to
    pub topic: TopicHash,

    /// The signature of the message if it's signed.
    pub signature: Option<Vec<u8>>,

    /// The public key of the message if it is signed and the source [`PeerId`] cannot be inlined.
    pub key: Option<Vec<u8>>,

    /// Flag indicating if this message has been validated by the application or not.
    pub validated: bool,
}

impl RawMessage {
    /// Calculates the encoded length of this message (used for calculating metrics).
    pub fn raw_protobuf_len(&self) -> usize {
        let message: pb::Message = self.clone().into();
        message.encoded_len()
    }
}

impl From<RawMessage> for pb::Message {
    fn from(raw: RawMessage) -> Self {
        pb::Message {
            from: raw.source.map(|m| m.to_bytes()).unwrap_or_default(),
            data: raw.data,
            seqno: raw
                .sequence_number
                .map(|s| s.to_be_bytes().to_vec())
                .unwrap_or_default(),
            bitmask: raw.topic.into_bytes(),
            signature: raw.signature.unwrap_or_default(),
            key: raw.key.unwrap_or_default(),
        }
    }
}

/// The message sent to the user after a [`RawMessage`] has been transformed by a
/// [`crate::DataTransform`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Message {
    /// Id of the peer that published this message.
    pub source: Option<PeerId>,

    /// Content of the message.
    pub data: Vec<u8>,

    /// A random sequence number.
    pub sequence_number: Option<u64>,

    /// The topic this message belongs to
    pub topic: TopicHash,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field(
                "data",
                &format_args!("{:<20}", &hex_fmt::HexFmt(&self.data)),
            )
            .field("source", &self.source)
            .field("sequence_number", &self.sequence_number)
            .field("topic", &self.topic)
            .finish()
    }
}

/// A subscription received by the gossipsub system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Subscription {
    /// Action to perform.
    pub action: SubscriptionAction,
    /// The topic from which to subscribe or unsubscribe.
    pub topic_hash: TopicHash,
}

/// Action that a subscription wants to perform.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubscriptionAction {
    /// The remote wants to subscribe to the given topic.
    Subscribe,
    /// The remote wants to unsubscribe from the given topic.
    Unsubscribe,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    pub peer_id: Option<PeerId>,
    //TODO add this when RFC: Signed Address Records got added to the spec (see pull request
    // https://github.com/libp2p/specs/pull/217)
    //pub signed_peer_record: ?,
}

/// A Control message received by the gossipsub system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ControlAction {
    /// Node broadcasts known messages per topic - IHave control message.
    IHave {
        /// The topic of the messages.
        topic_hash: TopicHash,
        /// A list of known message ids (peer_id + sequence _number) as a string.
        message_ids: Vec<MessageId>,
    },
    /// The node requests specific message ids (peer_id + sequence _number) - IWant control message.
    IWant {
        /// A list of known message ids (peer_id + sequence _number) as a string.
        message_ids: Vec<MessageId>,
    },
    /// The node has been added to the mesh - Graft control message.
    Graft {
        /// The mesh topic the peer should be added to.
        topic_hash: TopicHash,
    },
    /// The node has been removed from the mesh - Prune control message.
    Prune {
        /// The mesh topic the peer should be removed from.
        topic_hash: TopicHash,
        /// A list of peers to be proposed to the removed peer as peer exchange
        peers: Vec<PeerInfo>,
        /// The backoff time in seconds before we allow to reconnect
        backoff: Option<u64>,
    },
    /// The node informs a peer that it already has these messages, so the peer
    /// should not forward them (gossipsub-1.2 IDONTWANT semantics).
    IDontWant {
        /// A list of message ids the peer should not send us.
        message_ids: Vec<MessageId>,
    },
}

/// A Gossipsub RPC message sent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RpcOut {
    /// Publish a Gossipsub message on network.
    Publish(RawMessage),
    /// Forward a Gossipsub message to the network.
    Forward(RawMessage),
    /// Subscribe a topic.
    Subscribe(TopicHash),
    /// Unsubscribe a topic.
    Unsubscribe(TopicHash),
    /// A single Gossipsub control message.
    Control(ControlAction),
    /// A batch of Gossipsub control messages destined for one peer, encoded as
    /// a SINGLE piggybacked `pb::Rpc` (one `control` field carrying all
    /// sub-messages) rather than one RPC per action. Used by the per-peer
    /// control-pool flush each heartbeat.
    Controls(Vec<ControlAction>),
}

impl RpcOut {
    /// Converts the RPC into its protobuf format.
    // A convenience function to avoid explicitly specifying types.
    pub fn into_protobuf(self) -> pb::Rpc {
        self.into()
    }
}

/// Empty control message (all lists empty).
fn empty_control() -> pb::ControlMessage {
    pb::ControlMessage {
        ihave: Vec::new(),
        iwant: Vec::new(),
        graft: Vec::new(),
        prune: Vec::new(),
        idontwant: Vec::new(),
    }
}

/// Folds a single [`ControlAction`] into a [`pb::ControlMessage`], appending to
/// the relevant repeated field. Shared by the single-action and batched control
/// encodings so a `Vec<ControlAction>` maps to ONE `pb::ControlMessage`.
fn push_control_action(control: &mut pb::ControlMessage, action: ControlAction) {
    match action {
        ControlAction::IHave {
            topic_hash,
            message_ids,
        } => control.ihave.push(pb::ControlIHave {
            bitmask: topic_hash.into_bytes(),
            message_i_ds: message_ids.into_iter().map(|msg_id| msg_id.0).collect(),
        }),
        ControlAction::IWant { message_ids } => control.iwant.push(pb::ControlIWant {
            message_i_ds: message_ids.into_iter().map(|msg_id| msg_id.0).collect(),
        }),
        ControlAction::Graft { topic_hash } => control.graft.push(pb::ControlGraft {
            bitmask: topic_hash.into_bytes(),
        }),
        ControlAction::Prune {
            topic_hash,
            peers,
            backoff,
        } => control.prune.push(pb::ControlPrune {
            bitmask: topic_hash.into_bytes(),
            peers: peers
                .into_iter()
                .map(|info| pb::PeerInfo {
                    peer_id: info.peer_id.map(|id| id.to_bytes()),
                    // TODO, see https://github.com/libp2p/specs/pull/217
                    signed_peer_record: None,
                })
                .collect(),
            backoff: backoff.unwrap_or_default(),
        }),
        ControlAction::IDontWant { message_ids } => control.idontwant.push(pb::ControlIDontWant {
            message_i_ds: message_ids.into_iter().map(|msg_id| msg_id.0).collect(),
        }),
    }
}

impl From<RpcOut> for pb::Rpc {
    /// Converts the RPC into protobuf format.
    fn from(rpc: RpcOut) -> Self {
        match rpc {
            RpcOut::Publish(message) => pb::Rpc {
                subscriptions: Vec::new(),
                publish: vec![message.into()],
                control: None,
            },
            RpcOut::Forward(message) => pb::Rpc {
                publish: vec![message.into()],
                subscriptions: Vec::new(),
                control: None,
            },
            RpcOut::Subscribe(topic) => pb::Rpc {
                publish: Vec::new(),
                subscriptions: vec![pb::rpc::SubOpts {
                    subscribe: true,
                    bitmask: topic.into_bytes(),
                }],
                control: None,
            },
            RpcOut::Unsubscribe(topic) => pb::Rpc {
                publish: Vec::new(),
                subscriptions: vec![pb::rpc::SubOpts {
                    subscribe: false,
                    bitmask: topic.into_bytes(),
                }],
                control: None,
            },
            RpcOut::Control(action) => {
                let mut control = empty_control();
                push_control_action(&mut control, action);
                pb::Rpc {
                    publish: Vec::new(),
                    subscriptions: Vec::new(),
                    control: Some(control),
                }
            }
            RpcOut::Controls(actions) => {
                // Fold every pooled control action into ONE pb::ControlMessage
                // so the whole batch rides a single piggybacked pb::Rpc.
                let mut control = empty_control();
                for action in actions {
                    push_control_action(&mut control, action);
                }
                pb::Rpc {
                    publish: Vec::new(),
                    subscriptions: Vec::new(),
                    control: Some(control),
                }
            }
        }
    }
}

/// An RPC received/sent.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Rpc {
    /// List of messages that were part of this RPC query.
    pub messages: Vec<RawMessage>,
    /// List of subscriptions.
    pub subscriptions: Vec<Subscription>,
    /// List of Gossipsub control messages.
    pub control_msgs: Vec<ControlAction>,
}

impl Rpc {
    /// Converts the RPC into its protobuf format.
    // A convenience function to avoid explicitly specifying types.
    pub fn into_protobuf(self) -> pb::Rpc {
        self.into()
    }
}

impl From<Rpc> for pb::Rpc {
    /// Converts the RPC into protobuf format.
    fn from(rpc: Rpc) -> Self {
        // Messages
        let publish = rpc.messages.into_iter().map(Into::into).collect::<Vec<_>>();

        // subscriptions
        let subscriptions = rpc
            .subscriptions
            .into_iter()
            .map(|sub| pb::rpc::SubOpts {
                subscribe: sub.action == SubscriptionAction::Subscribe,
                bitmask: sub.topic_hash.into_bytes(),
            })
            .collect::<Vec<_>>();

        // control messages
        let mut control = empty_control();

        let empty_control_msg = rpc.control_msgs.is_empty();

        for action in rpc.control_msgs {
            push_control_action(&mut control, action);
        }

        pb::Rpc {
            subscriptions,
            publish,
            control: if empty_control_msg {
                None
            } else {
                Some(control)
            },
        }
    }
}

impl fmt::Debug for Rpc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut b = f.debug_struct("GossipsubRpc");
        if !self.messages.is_empty() {
            b.field("messages", &self.messages);
        }
        if !self.subscriptions.is_empty() {
            b.field("subscriptions", &self.subscriptions);
        }
        if !self.control_msgs.is_empty() {
            b.field("control_msgs", &self.control_msgs);
        }
        b.finish()
    }
}

impl PeerKind {
    pub fn as_static_ref(&self) -> &'static str {
        match self {
            Self::NotSupported => "Not Supported",
            Self::Floodsub => "Floodsub",
            Self::Gossipsub => "Gossipsub v1.0",
            Self::Gossipsubv1_1 => "Gossipsub v1.1",
        }
    }
}

impl AsRef<str> for PeerKind {
    fn as_ref(&self) -> &str {
        self.as_static_ref()
    }
}

impl fmt::Display for PeerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}
