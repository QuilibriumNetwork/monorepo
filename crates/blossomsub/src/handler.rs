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

use crate::pb;
use crate::protocol::{GossipsubCodec, ProtocolConfig};
use crate::types::{PeerKind, RawMessage, Rpc, RpcOut};
use crate::ValidationError;
use asynchronous_codec::Framed;
use futures::future::Either;
use futures::prelude::*;
use futures::StreamExt;
use libp2p_core::upgrade::DeniedUpgrade;
use libp2p_swarm::handler::{
    ConnectionEvent, ConnectionHandler, ConnectionHandlerEvent, DialUpgradeError,
    FullyNegotiatedInbound, FullyNegotiatedOutbound, StreamUpgradeError, SubstreamProtocol,
};
use libp2p_swarm::Stream;
use prost::Message as _;
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};
use web_time::Instant;

/// Per-connection cap on buffered outbound bytes. A peer whose outbound
/// substream stalls, never negotiates, or whose socket is backpressured would
/// otherwise accumulate forwarded RPCs without bound in `send_queue` — a
/// regular-node OOM (jeprof: 25 GB retained through `handle_rpc`, held
/// downstream in this queue). Above this, the oldest `bulk` payloads (and, as
/// a last resort, the oldest control) are dropped; a peer we can't write to
/// can't use them anyway, and gossip tolerates loss. 8 MiB comfortably covers
/// a healthy mesh peer's transient burst. Ported from quil-p2p handler.rs.
const SEND_QUEUE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// After this many consecutive shed events with no successful outbound write
/// in between, the peer is unwritable — its outbound socket is wedged (remote
/// not reading). A healthy peer drains at least one RPC between cap-overflows,
/// resetting this counter, so only a true zero-drain peer reaches the
/// threshold. When it does, we drop keep-alive and stop queuing so the swarm
/// can replace the connection instead of spinning forever shedding a
/// quarter-million-entry queue. Ported from quil-p2p handler.rs.
const MAX_STUCK_SHEDS: u32 = 2048;

/// An outbound RPC buffered in the handler's `send_queue`, tagged with whether
/// it carries a full message payload (a forward or a publish) so the
/// backpressure cap can drop bulk traffic first, and with its encoded byte
/// length so shedding is O(dropped) rather than re-encoding on every scan.
pub(crate) struct QueuedRpc {
    rpc: pb::Rpc,
    /// True for `Publish`/`Forward` (gossip-tolerant); false for control
    /// (subscriptions, GRAFT/PRUNE/IHAVE/IWANT/IDONTWANT — protocol).
    bulk: bool,
    /// Encoded protobuf length (cached; matches what the codec will write).
    len: usize,
}

/// The event emitted by the Handler. This informs the behaviour of various events created
/// by the handler.
#[derive(Debug)]
pub enum HandlerEvent {
    /// A GossipsubRPC message has been received. This also contains a list of invalid messages (if
    /// any) that were received.
    Message {
        /// The GossipsubRPC message excluding any invalid messages.
        rpc: Rpc,
        /// Any invalid messages that were received in the RPC, along with the associated
        /// validation error.
        invalid_messages: Vec<(RawMessage, ValidationError)>,
    },
    /// An inbound or outbound substream has been established with the peer and this informs over
    /// which protocol. This message only occurs once per connection.
    PeerKind(PeerKind),
}

/// A message sent from the behaviour to the handler.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum HandlerIn {
    /// A gossipsub message to send.
    Message(RpcOut),
    /// The peer has joined the mesh.
    JoinedMesh,
    /// The peer has left the mesh.
    LeftMesh,
}

/// The maximum number of inbound or outbound substreams attempts we allow.
///
/// Gossipsub is supposed to have a single long-lived inbound and outbound substream. On failure we
/// attempt to recreate these. This imposes an upper bound of new substreams before we consider the
/// connection faulty and disable the handler. This also prevents against potential substream
/// creation loops.
const MAX_SUBSTREAM_ATTEMPTS: usize = 5;

#[allow(clippy::large_enum_variant)]
pub enum Handler {
    Enabled(EnabledHandler),
    Disabled(DisabledHandler),
}

/// Protocol Handler that manages a single long-lived substream with a peer.
pub struct EnabledHandler {
    /// Upgrade configuration for the gossipsub protocol.
    listen_protocol: ProtocolConfig,

    /// The single long-lived outbound substream.
    outbound_substream: Option<OutboundSubstreamState>,

    /// The single long-lived inbound substream.
    inbound_substream: Option<InboundSubstreamState>,

    /// Queue of values that we want to send to the remote. A `VecDeque` drained
    /// FIFO via `pop_front` so the OLDEST enqueued RPC is sent first (no
    /// reordering) and matches the OLDEST-first shed order — a stale front
    /// entry can never starve under sustained just-under-cap load. Mirrors the
    /// quil-p2p reference (which uses a `VecDeque` on both send and drop paths).
    send_queue: VecDeque<QueuedRpc>,

    /// Running total of `send_queue` encoded payload bytes (for the OOM cap).
    send_queue_bytes: usize,

    /// Of `send_queue_bytes`, how many belong to `bulk` entries. Lets
    /// `shed_send_queue` skip its O(n) bulk-selective scan entirely when the
    /// backlog is pure control (the observed flood: 209k × 40-byte RPCs),
    /// keeping shedding O(dropped) instead of O(queue len) per push.
    send_queue_bulk_bytes: usize,

    /// Consecutive shed events since the last successful outbound write. A
    /// nonzero value means the peer isn't keeping up; `MAX_STUCK_SHEDS` means
    /// it isn't draining at all. Reset to 0 on every successful flush.
    stuck_sheds: u32,

    /// Set once the peer is declared unwritable. We stop queuing new sends and
    /// drop keep-alive so the connection can close.
    closing: bool,

    /// Flag indicating that an outbound substream is being established to prevent duplicate
    /// requests.
    outbound_substream_establishing: bool,

    /// The number of outbound substreams we have requested.
    outbound_substream_attempts: usize,

    /// The number of inbound substreams that have been created by the peer.
    inbound_substream_attempts: usize,

    /// The type of peer this handler is associated to.
    peer_kind: Option<PeerKind>,

    /// Keeps track on whether we have sent the peer kind to the behaviour.
    //
    // NOTE: Use this flag rather than checking the substream count each poll.
    peer_kind_sent: bool,

    last_io_activity: Instant,

    /// Keeps track of whether this connection is for a peer in the mesh. This is used to make
    /// decisions about the keep alive state for this connection.
    in_mesh: bool,
}

pub enum DisabledHandler {
    /// If the peer doesn't support the gossipsub protocol we do not immediately disconnect.
    /// Rather, we disable the handler and prevent any incoming or outgoing substreams from being
    /// established.
    ProtocolUnsupported {
        /// Keeps track on whether we have sent the peer kind to the behaviour.
        peer_kind_sent: bool,
    },
    /// The maximum number of inbound or outbound substream attempts have happened and thereby the
    /// handler has been disabled.
    MaxSubstreamAttempts,
}

/// State of the inbound substream, opened either by us or by the remote.
enum InboundSubstreamState {
    /// Waiting for a message from the remote. The idle state for an inbound substream.
    WaitingInput(Framed<Stream, GossipsubCodec>),
    /// The substream is being closed.
    Closing(Framed<Stream, GossipsubCodec>),
    /// An error occurred during processing.
    Poisoned,
}

/// State of the outbound substream, opened either by us or by the remote.
enum OutboundSubstreamState {
    /// Waiting for the user to send a message. The idle state for an outbound substream.
    WaitingOutput(Framed<Stream, GossipsubCodec>),
    /// Waiting to send a message to the remote.
    PendingSend(Framed<Stream, GossipsubCodec>, pb::Rpc),
    /// Waiting to flush the substream so that the data arrives to the remote.
    PendingFlush(Framed<Stream, GossipsubCodec>),
    /// An error occurred during processing.
    Poisoned,
}

impl Handler {
    /// Builds a new [`Handler`].
    pub fn new(protocol_config: ProtocolConfig) -> Self {
        Handler::Enabled(EnabledHandler {
            listen_protocol: protocol_config,
            inbound_substream: None,
            outbound_substream: None,
            outbound_substream_establishing: false,
            outbound_substream_attempts: 0,
            inbound_substream_attempts: 0,
            send_queue: VecDeque::new(),
            send_queue_bytes: 0,
            send_queue_bulk_bytes: 0,
            stuck_sheds: 0,
            closing: false,
            peer_kind: None,
            peer_kind_sent: false,
            last_io_activity: Instant::now(),
            in_mesh: false,
        })
    }
}

impl EnabledHandler {
    /// Queue an outbound RPC, tagged as bulk (forward/publish payload) or
    /// control, then bound the backlog. Called from `on_behaviour_event`.
    fn queue_send(&mut self, rpc: pb::Rpc, bulk: bool) {
        if self.closing {
            // Peer declared unwritable; the connection is winding down.
            // Queuing more would only be shed — drop it now.
            return;
        }
        let len = rpc.encoded_len();
        self.send_queue_bytes += len;
        if bulk {
            self.send_queue_bulk_bytes += len;
        }
        self.send_queue.push_back(QueuedRpc { rpc, bulk, len });
        self.shed_send_queue();
    }

    /// Bound the outbound backlog. When buffered bytes exceed
    /// `SEND_QUEUE_MAX_BYTES`, drop the OLDEST `bulk` payloads first
    /// (forwards/publishes — gossip tolerates loss); if still over budget with
    /// only control left, drop oldest control too as a hard stop. A peer that
    /// never drains across `MAX_STUCK_SHEDS` sheds is declared unwritable and
    /// the connection is closed. Oldest = front of the deque; the poll loop
    /// also drains front-first (`pop_front`), so shed order and send order
    /// agree and the front entry is always the stalest. Ported from quil-p2p
    /// handler.rs.
    fn shed_send_queue(&mut self) {
        if self.send_queue_bytes <= SEND_QUEUE_MAX_BYTES {
            return;
        }
        let mut dropped = 0usize;

        // Pass 1: drop oldest bulk entries first. Skip the O(n) rebuild
        // entirely when the backlog holds no bulk — the observed pathology is
        // a flood of tiny control RPCs where rebuilding a quarter-million-entry
        // queue on every push pegs the core. With no bulk, fall through to the
        // cheap O(dropped) front-drop below.
        if self.send_queue_bulk_bytes > 0 {
            let mut kept: VecDeque<QueuedRpc> = VecDeque::with_capacity(self.send_queue.len());
            for q in std::mem::take(&mut self.send_queue) {
                if self.send_queue_bytes > SEND_QUEUE_MAX_BYTES && q.bulk {
                    self.send_queue_bytes -= q.len;
                    self.send_queue_bulk_bytes -= q.len;
                    dropped += 1;
                    continue;
                }
                kept.push_back(q);
            }
            self.send_queue = kept;
        }

        // Pass 2: still over budget (all control, or bulk exhausted) — drop
        // oldest (front) regardless so memory stays bounded. O(dropped).
        while self.send_queue_bytes > SEND_QUEUE_MAX_BYTES {
            match self.send_queue.pop_front() {
                Some(q) => {
                    self.send_queue_bytes -= q.len;
                    if q.bulk {
                        self.send_queue_bulk_bytes -= q.len;
                    }
                    dropped += 1;
                }
                None => break,
            }
        }

        if dropped == 0 {
            return;
        }

        self.stuck_sheds = self.stuck_sheds.saturating_add(1);
        if self.stuck_sheds == 1 {
            tracing::warn!(
                dropped,
                remaining = self.send_queue.len(),
                remaining_bytes = self.send_queue_bytes,
                "blossomsub handler: outbound backlog over cap — peer draining \
                 slowly (backpressure guard)"
            );
        }

        // No outbound progress across many sheds → the peer is unwritable.
        // Drop keep-alive and free the doomed backlog so the swarm can replace
        // the connection.
        if self.stuck_sheds >= MAX_STUCK_SHEDS && !self.closing {
            self.closing = true;
            let abandoned = self.send_queue.len();
            self.send_queue.clear();
            self.send_queue_bytes = 0;
            self.send_queue_bulk_bytes = 0;
            tracing::warn!(
                stuck_sheds = self.stuck_sheds,
                abandoned,
                "blossomsub handler: peer unwritable (zero outbound drain) — \
                 closing connection so the swarm can replace it"
            );
        }
    }

    fn on_fully_negotiated_inbound(
        &mut self,
        (substream, peer_kind): (Framed<Stream, GossipsubCodec>, PeerKind),
    ) {
        // update the known kind of peer
        if self.peer_kind.is_none() {
            self.peer_kind = Some(peer_kind);
        }

        // new inbound substream. Replace the current one, if it exists.
        tracing::trace!("New inbound substream request");
        self.inbound_substream = Some(InboundSubstreamState::WaitingInput(substream));
    }

    fn on_fully_negotiated_outbound(
        &mut self,
        FullyNegotiatedOutbound { protocol, .. }: FullyNegotiatedOutbound<
            <Handler as ConnectionHandler>::OutboundProtocol,
            <Handler as ConnectionHandler>::OutboundOpenInfo,
        >,
    ) {
        let (substream, peer_kind) = protocol;

        // update the known kind of peer
        if self.peer_kind.is_none() {
            self.peer_kind = Some(peer_kind);
        }

        assert!(
            self.outbound_substream.is_none(),
            "Established an outbound substream with one already available"
        );
        self.outbound_substream = Some(OutboundSubstreamState::WaitingOutput(substream));
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<
            <Handler as ConnectionHandler>::OutboundProtocol,
            <Handler as ConnectionHandler>::OutboundOpenInfo,
            <Handler as ConnectionHandler>::ToBehaviour,
        >,
    > {
        if !self.peer_kind_sent {
            if let Some(peer_kind) = self.peer_kind.as_ref() {
                self.peer_kind_sent = true;
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                    HandlerEvent::PeerKind(peer_kind.clone()),
                ));
            }
        }

        // determine if we need to create the outbound stream
        if !self.send_queue.is_empty()
            && self.outbound_substream.is_none()
            && !self.outbound_substream_establishing
        {
            self.outbound_substream_establishing = true;
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(self.listen_protocol.clone(), ()),
            });
        }

        // process outbound stream
        loop {
            match std::mem::replace(
                &mut self.outbound_substream,
                Some(OutboundSubstreamState::Poisoned),
            ) {
                // outbound idle state
                Some(OutboundSubstreamState::WaitingOutput(substream)) => {
                    // FIFO drain: oldest RPC first. No `shrink_to_fit` — a
                    // VecDeque keeps its capacity (wanted for a hot queue), and
                    // reallocating the whole backlog per dequeue was O(n²) on a
                    // large spilled backlog (the CPU-peg the shed exists to
                    // avoid).
                    if let Some(queued) = self.send_queue.pop_front() {
                        self.send_queue_bytes = self.send_queue_bytes.saturating_sub(queued.len);
                        if queued.bulk {
                            self.send_queue_bulk_bytes =
                                self.send_queue_bulk_bytes.saturating_sub(queued.len);
                        }
                        self.outbound_substream =
                            Some(OutboundSubstreamState::PendingSend(substream, queued.rpc));
                        continue;
                    }

                    self.outbound_substream =
                        Some(OutboundSubstreamState::WaitingOutput(substream));
                    break;
                }
                Some(OutboundSubstreamState::PendingSend(mut substream, message)) => {
                    match Sink::poll_ready(Pin::new(&mut substream), cx) {
                        Poll::Ready(Ok(())) => {
                            match Sink::start_send(Pin::new(&mut substream), message) {
                                Ok(()) => {
                                    self.outbound_substream =
                                        Some(OutboundSubstreamState::PendingFlush(substream))
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        "Failed to send message on outbound stream: {e}"
                                    );
                                    self.outbound_substream = None;
                                    break;
                                }
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            tracing::debug!("Failed to send message on outbound stream: {e}");
                            self.outbound_substream = None;
                            break;
                        }
                        Poll::Pending => {
                            self.outbound_substream =
                                Some(OutboundSubstreamState::PendingSend(substream, message));
                            break;
                        }
                    }
                }
                Some(OutboundSubstreamState::PendingFlush(mut substream)) => {
                    match Sink::poll_flush(Pin::new(&mut substream), cx) {
                        Poll::Ready(Ok(())) => {
                            self.last_io_activity = Instant::now();
                            // A full RPC reached the peer — it's draining, so
                            // it isn't the wedged/zero-drain case. Reset the
                            // backpressure guard.
                            self.stuck_sheds = 0;
                            self.outbound_substream =
                                Some(OutboundSubstreamState::WaitingOutput(substream))
                        }
                        Poll::Ready(Err(e)) => {
                            tracing::debug!("Failed to flush outbound stream: {e}");
                            self.outbound_substream = None;
                            break;
                        }
                        Poll::Pending => {
                            self.outbound_substream =
                                Some(OutboundSubstreamState::PendingFlush(substream));
                            break;
                        }
                    }
                }
                None => {
                    self.outbound_substream = None;
                    break;
                }
                Some(OutboundSubstreamState::Poisoned) => {
                    unreachable!("Error occurred during outbound stream processing")
                }
            }
        }

        loop {
            match std::mem::replace(
                &mut self.inbound_substream,
                Some(InboundSubstreamState::Poisoned),
            ) {
                // inbound idle state
                Some(InboundSubstreamState::WaitingInput(mut substream)) => {
                    match substream.poll_next_unpin(cx) {
                        Poll::Ready(Some(Ok(message))) => {
                            self.last_io_activity = Instant::now();
                            self.inbound_substream =
                                Some(InboundSubstreamState::WaitingInput(substream));
                            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(message));
                        }
                        Poll::Ready(Some(Err(error))) => {
                            tracing::debug!("Failed to read from inbound stream: {error}");
                            // Close this side of the stream. If the
                            // peer is still around, they will re-establish their
                            // outbound stream i.e. our inbound stream.
                            self.inbound_substream =
                                Some(InboundSubstreamState::Closing(substream));
                        }
                        // peer closed the stream
                        Poll::Ready(None) => {
                            tracing::debug!("Inbound stream closed by remote");
                            self.inbound_substream =
                                Some(InboundSubstreamState::Closing(substream));
                        }
                        Poll::Pending => {
                            self.inbound_substream =
                                Some(InboundSubstreamState::WaitingInput(substream));
                            break;
                        }
                    }
                }
                Some(InboundSubstreamState::Closing(mut substream)) => {
                    match Sink::poll_close(Pin::new(&mut substream), cx) {
                        Poll::Ready(res) => {
                            if let Err(e) = res {
                                // Don't close the connection but just drop the inbound substream.
                                // In case the remote has more to send, they will open up a new
                                // substream.
                                tracing::debug!("Inbound substream error while closing: {e}");
                            }
                            self.inbound_substream = None;
                            break;
                        }
                        Poll::Pending => {
                            self.inbound_substream =
                                Some(InboundSubstreamState::Closing(substream));
                            break;
                        }
                    }
                }
                None => {
                    self.inbound_substream = None;
                    break;
                }
                Some(InboundSubstreamState::Poisoned) => {
                    unreachable!("Error occurred during inbound stream processing")
                }
            }
        }

        Poll::Pending
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = HandlerIn;
    type ToBehaviour = HandlerEvent;
    type InboundOpenInfo = ();
    type InboundProtocol = either::Either<ProtocolConfig, DeniedUpgrade>;
    type OutboundOpenInfo = ();
    type OutboundProtocol = ProtocolConfig;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        match self {
            Handler::Enabled(handler) => {
                SubstreamProtocol::new(either::Either::Left(handler.listen_protocol.clone()), ())
            }
            Handler::Disabled(_) => {
                SubstreamProtocol::new(either::Either::Right(DeniedUpgrade), ())
            }
        }
    }

    fn on_behaviour_event(&mut self, message: HandlerIn) {
        match self {
            Handler::Enabled(handler) => match message {
                HandlerIn::Message(m) => {
                    // Bulk = full message payload (forward/publish); these are
                    // gossip-tolerant and shed first under backpressure.
                    // Control (subs/graft/prune/ihave/iwant/idontwant) is
                    // preserved as long as possible.
                    let bulk = matches!(m, RpcOut::Publish(_) | RpcOut::Forward(_));
                    handler.queue_send(m.into_protobuf(), bulk);
                }
                HandlerIn::JoinedMesh => {
                    handler.in_mesh = true;
                }
                HandlerIn::LeftMesh => {
                    handler.in_mesh = false;
                }
            },
            Handler::Disabled(_) => {
                tracing::debug!(?message, "Handler is disabled. Dropping message");
            }
        }
    }

    fn connection_keep_alive(&self) -> bool {
        // An unwritable peer (`closing`) drops keep-alive so the connection can
        // be reaped and replaced by the swarm.
        matches!(self, Handler::Enabled(h) if h.in_mesh && !h.closing)
    }

    #[tracing::instrument(level = "trace", name = "ConnectionHandler::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        match self {
            Handler::Enabled(handler) => handler.poll(cx),
            Handler::Disabled(DisabledHandler::ProtocolUnsupported { peer_kind_sent }) => {
                if !*peer_kind_sent {
                    *peer_kind_sent = true;
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        HandlerEvent::PeerKind(PeerKind::NotSupported),
                    ));
                }

                Poll::Pending
            }
            Handler::Disabled(DisabledHandler::MaxSubstreamAttempts) => Poll::Pending,
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match self {
            Handler::Enabled(handler) => {
                if event.is_inbound() {
                    handler.inbound_substream_attempts += 1;

                    if handler.inbound_substream_attempts == MAX_SUBSTREAM_ATTEMPTS {
                        tracing::debug!(
                            "The maximum number of inbound substreams attempts has been exceeded"
                        );
                        *self = Handler::Disabled(DisabledHandler::MaxSubstreamAttempts);
                        return;
                    }
                }

                if event.is_outbound() {
                    handler.outbound_substream_establishing = false;

                    handler.outbound_substream_attempts += 1;

                    if handler.outbound_substream_attempts == MAX_SUBSTREAM_ATTEMPTS {
                        tracing::debug!(
                            "The maximum number of outbound substream attempts has been exceeded"
                        );
                        *self = Handler::Disabled(DisabledHandler::MaxSubstreamAttempts);
                        return;
                    }
                }

                match event {
                    ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                        protocol,
                        ..
                    }) => match protocol {
                        Either::Left(protocol) => handler.on_fully_negotiated_inbound(protocol),
                        Either::Right(v) => void::unreachable(v),
                    },
                    ConnectionEvent::FullyNegotiatedOutbound(fully_negotiated_outbound) => {
                        handler.on_fully_negotiated_outbound(fully_negotiated_outbound)
                    }
                    ConnectionEvent::DialUpgradeError(DialUpgradeError {
                        error: StreamUpgradeError::Timeout,
                        ..
                    }) => {
                        tracing::debug!("Dial upgrade error: Protocol negotiation timeout");
                    }
                    ConnectionEvent::DialUpgradeError(DialUpgradeError {
                        error: StreamUpgradeError::Apply(e),
                        ..
                    }) => void::unreachable(e),
                    ConnectionEvent::DialUpgradeError(DialUpgradeError {
                        error: StreamUpgradeError::NegotiationFailed,
                        ..
                    }) => {
                        // The protocol is not supported
                        tracing::debug!(
                            "The remote peer does not support gossipsub on this connection"
                        );
                        *self = Handler::Disabled(DisabledHandler::ProtocolUnsupported {
                            peer_kind_sent: false,
                        });
                    }
                    ConnectionEvent::DialUpgradeError(DialUpgradeError {
                        error: StreamUpgradeError::Io(e),
                        ..
                    }) => {
                        tracing::debug!("Protocol negotiation failed: {e}")
                    }
                    _ => {}
                }
            }
            Handler::Disabled(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topic::TopicHash;

    fn enabled() -> EnabledHandler {
        match Handler::new(ProtocolConfig::default()) {
            Handler::Enabled(h) => h,
            _ => unreachable!("Handler::new always builds Enabled"),
        }
    }

    /// Feed a bulk (forward) RPC of roughly `len` payload bytes.
    fn feed_bulk(h: &mut EnabledHandler, len: usize) {
        let msg = RawMessage {
            source: None,
            data: vec![0u8; len],
            sequence_number: None,
            topic: TopicHash::from_raw(vec![0x01]),
            signature: None,
            key: None,
            validated: true,
        };
        h.queue_send(RpcOut::Forward(msg).into_protobuf(), true);
    }

    /// Feed a control RPC of roughly `len` bytes (a subscription with a padded
    /// bitmask — classified as control, never shed before bulk).
    fn feed_control(h: &mut EnabledHandler, len: usize) {
        let rpc = pb::Rpc {
            subscriptions: vec![pb::rpc::SubOpts {
                subscribe: true,
                bitmask: vec![0u8; len],
            }],
            publish: Vec::new(),
            control: None,
        };
        h.queue_send(rpc, false);
    }

    /// REGRESSION (OOM): the per-connection outbound `send_queue` had no bound.
    /// A peer whose outbound stream stalls accumulates forwarded payloads
    /// forever. The cap must bound buffered bytes while preserving control.
    #[test]
    fn send_queue_capped_drops_bulk_keeps_control() {
        let mut h = enabled();
        // A few small control RPCs first (must survive).
        for _ in 0..4 {
            feed_control(&mut h, 64);
        }
        // Flood with 1 MiB bulk forwards — far over the 8 MiB cap.
        for _ in 0..64 {
            feed_bulk(&mut h, 1024 * 1024);
        }
        assert!(
            h.send_queue_bytes <= SEND_QUEUE_MAX_BYTES,
            "outbound backlog must stay under the cap, got {}",
            h.send_queue_bytes
        );
        // All 4 control RPCs preserved (control has no publish payload).
        let control = h
            .send_queue
            .iter()
            .filter(|q| !q.bulk)
            .count();
        assert_eq!(control, 4, "control RPCs must survive backlog shedding");
        // Accounting matches the actual buffered bytes.
        let actual: usize = h.send_queue.iter().map(|q| q.len).sum();
        assert_eq!(actual, h.send_queue_bytes, "byte accounting must stay exact");
    }

    /// FIX A/B (FIFO): a control RPC enqueued BEFORE a flood of bulk must drain
    /// FIRST and never starve at the bottom of the queue. Under the old LIFO
    /// `pop()` the newest bulk drained first, leaving old control stuck forever;
    /// FIFO `pop_front` delivers oldest-first, and shedding (which also drops
    /// oldest bulk first) keeps the control entry.
    #[test]
    fn oldest_control_drains_first_and_is_not_starved() {
        let mut h = enabled();
        // One control RPC FIRST.
        feed_control(&mut h, 128);
        // Then flood bulk well over the 8 MiB cap so shedding runs.
        for _ in 0..64 {
            feed_bulk(&mut h, 1024 * 1024);
        }
        assert!(
            h.send_queue_bytes <= SEND_QUEUE_MAX_BYTES,
            "backlog must stay under cap, got {}",
            h.send_queue_bytes
        );
        // The control RPC survived shedding (bulk shed first).
        assert_eq!(
            h.send_queue.iter().filter(|q| !q.bulk).count(),
            1,
            "the single control RPC must survive the bulk flood"
        );
        // FIFO drain delivers it FIRST — not stuck behind newer bulk.
        let first = h.send_queue.pop_front().expect("queue non-empty");
        assert!(
            !first.bulk,
            "the oldest (control) RPC must drain first under FIFO, not starve behind bulk"
        );
    }

    /// Hard stop: a queue of pure control that still exceeds the cap drops
    /// oldest entries so memory can't grow without bound even with no bulk.
    #[test]
    fn send_queue_hard_caps_even_pure_control() {
        let mut h = enabled();
        for _ in 0..200 {
            feed_control(&mut h, 64 * 1024); // 200 × 64 KiB = 12.5 MiB of control
        }
        assert!(
            h.send_queue_bytes <= SEND_QUEUE_MAX_BYTES,
            "pure-control backlog must still be bounded, got {}",
            h.send_queue_bytes
        );
    }

    /// REGRESSION (CPU peg + warning storm): a peer that never drains must
    /// eventually be declared unwritable so the connection closes.
    #[test]
    fn unwritable_peer_closes_after_repeated_sheds() {
        let mut h = enabled();
        let entry = 64 * 1024; // 64 KiB; ~128 fill the 8 MiB cap
        for _ in 0..(128 + MAX_STUCK_SHEDS as usize + 8) {
            feed_control(&mut h, entry);
            if h.closing {
                break;
            }
        }
        assert!(h.closing, "a zero-drain peer must be declared unwritable");
        // Backlog freed on close; further sends are dropped, not queued.
        assert_eq!(h.send_queue_bytes, 0);
        assert!(h.send_queue.is_empty());
        feed_control(&mut h, entry);
        assert!(h.send_queue.is_empty(), "closing handler must not re-queue");
    }

    /// A peer that drains keeps the connection: a successful write resets the
    /// stuck counter, so transient over-cap bursts never trip the close path.
    #[test]
    fn draining_peer_is_not_closed() {
        let mut h = enabled();
        for _ in 0..200 {
            feed_control(&mut h, 64 * 1024);
            // Simulate the peer accepting a full RPC between pushes.
            h.stuck_sheds = 0;
        }
        assert!(!h.closing, "a draining peer must not be closed");
        assert!(h.send_queue_bytes <= SEND_QUEUE_MAX_BYTES);
    }
}
