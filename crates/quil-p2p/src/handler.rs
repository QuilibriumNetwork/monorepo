//! BlossomSub `ConnectionHandler` — manages a bidirectional protobuf RPC
//! stream per connection for BlossomSub message exchange.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::prelude::*;
use libp2p::core::upgrade::ReadyUpgrade;
use libp2p::swarm::handler::{
    ConnectionEvent, ConnectionHandler, ConnectionHandlerEvent, FullyNegotiatedInbound,
    FullyNegotiatedOutbound, SubstreamProtocol,
};
use libp2p::swarm::Stream;
use libp2p::StreamProtocol;
use tracing::debug;

use crate::protocol;
use crate::protocol::pb;

/// Messages from the behaviour to the handler.
#[derive(Debug, Clone)]
pub struct HandlerIn {
    /// Serialized RPC to send to the peer.
    pub rpc_data: Vec<u8>,
}

/// Messages from the handler to the behaviour.
#[derive(Debug)]
pub enum HandlerOut {
    /// A decoded RPC received from the peer.
    Rpc(pb::Rpc),
    /// The handler encountered an error.
    Error(String),
}

/// BlossomSub connection handler.
pub struct BlossomSubHandler {
    /// Negotiated protocol ID — network-aware (e.g. mainnet
    /// `/blossomsub/2.1.0`, testnet `/blossomsub/2.1.0-network-1`).
    protocol: StreamProtocol,
    /// Inbound substream (reading RPCs from peer).
    inbound: Option<InboundState>,
    /// Outbound substream (writing RPCs to peer).
    outbound: Option<OutboundState>,
    /// Pending outbound RPCs to send.
    send_queue: VecDeque<Vec<u8>>,
    /// Pending events to emit to the behaviour.
    events: VecDeque<HandlerOut>,
    /// Whether we've requested an outbound substream.
    outbound_requested: bool,
    /// Keep the connection alive for BlossomSub.
    keep_alive: bool,
    /// Outbound stream negotiation retry counter.
    outbound_retries: u32,
}

enum InboundState {
    /// We have a stream and a read buffer.
    Active {
        stream: Stream,
        buf: Vec<u8>,
    },
}

enum OutboundState {
    /// We have a stream ready to write.
    Active { stream: Stream },
}

impl BlossomSubHandler {
    pub fn new(protocol: StreamProtocol) -> Self {
        Self {
            protocol,
            inbound: None,
            outbound: None,
            send_queue: VecDeque::new(),
            events: VecDeque::new(),
            outbound_requested: false,
            keep_alive: true,
            outbound_retries: 0,
        }
    }

    /// Create a handler with initial data to send (subscription RPC).
    pub fn with_initial_data(protocol: StreamProtocol, initial_rpc: Vec<u8>) -> Self {
        let mut h = Self::new(protocol);
        if !initial_rpc.is_empty() {
            h.send_queue.push_back(initial_rpc);
        }
        h
    }

    /// Try to read an RPC from the inbound stream.
    fn poll_inbound(&mut self, cx: &mut Context<'_>) {
        let inbound = match &mut self.inbound {
            Some(inbound) => inbound,
            None => return,
        };

        let InboundState::Active { stream, buf } = inbound;

        // Read in a loop until Pending (which registers the waker)
        loop {
            let mut read_buf = [0u8; 16384];
            match Pin::new(&mut *stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(0)) => {
                    debug!("inbound stream closed");
                    self.inbound = None;
                    return;
                }
                Poll::Ready(Ok(n)) => {
                    buf.extend_from_slice(&read_buf[..n]);
                    if n > 1 {
                        debug!(bytes = n, total_buf = buf.len(), "read from inbound");
                    }
                    // Continue loop to read more or get Pending
                }
                Poll::Ready(Err(e)) => {
                    debug!(%e, "inbound read error");
                    self.inbound = None;
                    return;
                }
                Poll::Pending => break, // Waker registered for next data
            }
        }

        // Decode all available RPCs from buffer
        let inbound = match &mut self.inbound {
            Some(inbound) => inbound,
            None => return,
        };
        let InboundState::Active { buf, .. } = inbound;

        loop {
            match protocol::decode_rpc(buf) {
                Ok((rpc, consumed)) => {
                    let subs = rpc.subscriptions.len();
                    let msgs = rpc.publish.len();
                    let has_control = rpc.control.is_some();
                    let ctrl_grafts = rpc.control.as_ref().map(|c| c.graft.len()).unwrap_or(0);
                    let ctrl_prunes = rpc.control.as_ref().map(|c| c.prune.len()).unwrap_or(0);
                    let ctrl_ihaves = rpc.control.as_ref().map(|c| c.ihave.len()).unwrap_or(0);
                    if subs > 0 || msgs > 0 || has_control {
                        debug!(consumed, subs, msgs, ctrl_grafts, ctrl_prunes, ctrl_ihaves, "decoded RPC");
                    }
                    self.events.push_back(HandlerOut::Rpc(rpc));
                    *buf = buf[consumed..].to_vec();
                }
                Err(protocol::DecodeError::Incomplete { .. }) => break,
                Err(e) => {
                    debug!(%e, "RPC decode error");
                    if buf.len() > 1 {
                        *buf = buf[1..].to_vec();
                    } else {
                        buf.clear();
                        break;
                    }
                }
            }
        }
    }

    /// Try to write pending RPCs to the outbound stream.
    fn poll_outbound(&mut self, cx: &mut Context<'_>) {
        if self.send_queue.is_empty() {
            return;
        }

        let outbound = match &mut self.outbound {
            Some(outbound) => outbound,
            None => return,
        };

        let OutboundState::Active { stream } = outbound;

        while let Some(data) = self.send_queue.front() {
            match Pin::new(&mut *stream).poll_write(cx, data) {
                Poll::Ready(Ok(n)) => {
                    if n == data.len() {
                        self.send_queue.pop_front();
                        debug!(bytes = n, "wrote to outbound");
                    } else {
                        // Partial write — trim what was sent
                        let remaining = data[n..].to_vec();
                        *self.send_queue.front_mut().unwrap() = remaining;
                        break;
                    }
                }
                Poll::Ready(Err(e)) => {
                    debug!(%e, "outbound write error");
                    self.outbound = None;
                    break;
                }
                Poll::Pending => break,
            }
        }

        // Flush
        if let Some(OutboundState::Active { stream }) = &mut self.outbound {
            let _ = Pin::new(stream).poll_flush(cx);
        }
    }
}

impl ConnectionHandler for BlossomSubHandler {
    type FromBehaviour = HandlerIn;
    type ToBehaviour = HandlerOut;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(ReadyUpgrade::new(self.protocol.clone()), ())
    }

    fn connection_keep_alive(&self) -> bool {
        self.keep_alive
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        debug!(data_len = event.rpc_data.len(), queue_len = self.send_queue.len(), "handler received data from behaviour");
        self.send_queue.push_back(event.rpc_data);
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
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: stream,
                ..
            }) => {
                debug!("inbound BlossomSub stream negotiated");
                self.inbound = Some(InboundState::Active {
                    stream,
                    buf: Vec::with_capacity(4096),
                });
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: stream,
                ..
            }) => {
                debug!("outbound BlossomSub stream negotiated");
                self.outbound = Some(OutboundState::Active { stream });
                self.outbound_requested = false;
            }
            ConnectionEvent::DialUpgradeError(_) => {
                self.outbound_retries += 1;
                if self.outbound_retries < 3 {
                    debug!(retry = self.outbound_retries, "outbound BlossomSub upgrade failed, will retry");
                    self.outbound_requested = false;
                } else {
                    debug!("outbound BlossomSub upgrade failed 3 times, giving up");
                    // Keep outbound_requested=true to prevent more retries
                }
            }
            _ => {}
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        // Read from inbound
        self.poll_inbound(cx);

        // Write to outbound
        self.poll_outbound(cx);

        // Request outbound substream if we have data to send and no outbound yet
        if !self.send_queue.is_empty() && self.outbound.is_none() && !self.outbound_requested {
            self.outbound_requested = true;
            debug!(queue_len = self.send_queue.len(), "requesting outbound BlossomSub stream");
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(self.protocol.clone()), ()),
            });
        }

        // Emit pending events to behaviour
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }

        Poll::Pending
    }
}
