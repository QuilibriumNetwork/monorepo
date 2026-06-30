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
use tracing::{debug, warn};

use crate::protocol;
use crate::protocol::pb;

/// Per-connection cap on buffered outbound bytes. A peer whose outbound
/// substream stalls, never negotiates, or whose socket is backpressured
/// would otherwise accumulate forwarded RPCs without bound in `send_queue`
/// — the regular-node OOM (jeprof: 25 GB retained through `handle_rpc`,
/// held downstream in this queue after the behaviour drained its own
/// bounded `events` queue). Above this, the oldest `bulk` payloads (and,
/// as a last resort, the oldest control) are dropped; a peer we can't
/// write to can't use them anyway, and gossip tolerates loss. 8 MiB
/// comfortably covers a healthy mesh peer's transient burst.
const SEND_QUEUE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// After this many consecutive shed events with no successful outbound write
/// in between, the peer is unwritable — its outbound substream never
/// negotiated (3 failed upgrades, then we give up) or its socket is wedged
/// (remote not reading). A healthy peer drains at least one RPC between
/// cap-overflows, which resets this counter, so only a true zero-drain peer
/// reaches the threshold. When it does, we let the connection close so the
/// swarm can replace it. Without this, a wedged peer is fed forever and the
/// master core spins shedding a quarter-million-entry queue instead of doing
/// useful work. At the observed ~1.5k sheds/s this is ~1.4s of grace.
const MAX_STUCK_SHEDS: u32 = 2048;

/// Messages from the behaviour to the handler.
#[derive(Debug, Clone)]
pub struct HandlerIn {
    /// Serialized RPC to send to the peer.
    pub rpc_data: Vec<u8>,
    /// True if `rpc_data` carries a full message payload (a forward, a
    /// local publish, or an IWANT response). The handler ignores this; it
    /// exists so the behaviour's backpressure guard (`shed_overflow_events`)
    /// can drop these bulky events under OOM pressure while preserving small
    /// control RPCs (graft/prune/IWANT-request/IHAVE/IDONTWANT/subscribe).
    pub bulk: bool,
}

/// An outbound RPC buffered in the handler's `send_queue`, tagged with
/// whether it carries a full message payload so the backpressure cap can
/// drop bulk traffic first.
struct QueuedRpc {
    data: Vec<u8>,
    bulk: bool,
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
    send_queue: VecDeque<QueuedRpc>,
    /// Running total of `send_queue` payload bytes (for the OOM cap).
    send_queue_bytes: usize,
    /// Of `send_queue_bytes`, how many belong to `bulk` entries. Lets
    /// `shed_send_queue` skip its O(n) bulk-selective scan entirely when the
    /// backlog is pure control (the observed flood: 209k × 40-byte RPCs),
    /// keeping shedding O(dropped) instead of O(queue len) per push.
    send_queue_bulk_bytes: usize,
    /// Consecutive shed events since the last successful full outbound write.
    /// A nonzero value means the peer isn't keeping up; `MAX_STUCK_SHEDS`
    /// means it isn't draining at all. Reset to 0 on every full write.
    stuck_sheds: u32,
    /// Set once the peer is declared unwritable. We stop queuing new sends
    /// (they could never go out) and let the connection close.
    closing: bool,
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
            send_queue_bytes: 0,
            send_queue_bulk_bytes: 0,
            stuck_sheds: 0,
            closing: false,
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
            h.send_queue_bytes += initial_rpc.len();
            // Subscription hello — control, never shed.
            h.send_queue.push_back(QueuedRpc {
                data: initial_rpc,
                bulk: false,
            });
        }
        h
    }

    /// Bound the outbound backlog. When buffered bytes exceed
    /// `SEND_QUEUE_MAX_BYTES`, drop the OLDEST `bulk` payloads first
    /// (forwards/publishes — gossip tolerates loss); if the queue is still
    /// over budget with only control left, drop oldest control too as a hard
    /// stop. Prevents a stalled/unwritable peer from ballooning memory.
    fn shed_send_queue(&mut self) {
        if self.send_queue_bytes <= SEND_QUEUE_MAX_BYTES {
            return;
        }
        let mut dropped = 0usize;
        let mut dropped_bytes = 0usize;

        // Pass 1: drop oldest bulk entries first (gossip tolerates loss). Skip
        // the full O(n) scan entirely when the backlog holds no bulk — the
        // observed pathology is a flood of tiny control RPCs (209k × 40 B),
        // where rebuilding a quarter-million-entry deque on every push pegs
        // the master core. With no bulk, fall straight through to the cheap
        // O(dropped) front-pop below.
        if self.send_queue_bulk_bytes > 0 {
            let mut kept: VecDeque<QueuedRpc> = VecDeque::with_capacity(self.send_queue.len());
            for q in std::mem::take(&mut self.send_queue) {
                if self.send_queue_bytes > SEND_QUEUE_MAX_BYTES && q.bulk {
                    self.send_queue_bytes -= q.data.len();
                    self.send_queue_bulk_bytes -= q.data.len();
                    dropped += 1;
                    dropped_bytes += q.data.len();
                    continue;
                }
                kept.push_back(q);
            }
            self.send_queue = kept;
        }

        // Pass 2: still over budget (all control, or bulk exhausted) — drop
        // oldest regardless so memory stays bounded. O(dropped).
        while self.send_queue_bytes > SEND_QUEUE_MAX_BYTES {
            match self.send_queue.pop_front() {
                Some(q) => {
                    self.send_queue_bytes -= q.data.len();
                    if q.bulk {
                        self.send_queue_bulk_bytes -= q.data.len();
                    }
                    dropped += 1;
                    dropped_bytes += q.data.len();
                }
                None => break,
            }
        }

        if dropped == 0 {
            return;
        }

        self.stuck_sheds = self.stuck_sheds.saturating_add(1);

        // Rate-limited logging: a wedged peer can trigger thousands of sheds
        // per second. Log once at onset, then once when we give up — not on
        // every drop.
        if self.stuck_sheds == 1 {
            warn!(
                dropped,
                dropped_bytes,
                remaining = self.send_queue.len(),
                remaining_bytes = self.send_queue_bytes,
                "blossomsub handler: outbound backlog over cap — peer draining \
                 slowly (backpressure guard)"
            );
        }

        // No outbound progress across many sheds → the peer is unwritable.
        // Stop feeding it and let the connection close; the swarm/mesh will
        // graft a replacement. Free the doomed backlog immediately.
        if self.stuck_sheds >= MAX_STUCK_SHEDS && !self.closing {
            self.closing = true;
            self.keep_alive = false;
            let abandoned = self.send_queue.len();
            self.send_queue.clear();
            self.send_queue_bytes = 0;
            self.send_queue_bulk_bytes = 0;
            warn!(
                stuck_sheds = self.stuck_sheds,
                abandoned,
                "blossomsub handler: peer unwritable (zero outbound drain) — \
                 closing connection so the swarm can replace it"
            );
        }
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

        while let Some(queued) = self.send_queue.front() {
            match Pin::new(&mut *stream).poll_write(cx, &queued.data) {
                Poll::Ready(Ok(n)) => {
                    if n == queued.data.len() {
                        if let Some(done) = self.send_queue.pop_front() {
                            self.send_queue_bytes -= done.data.len();
                            if done.bulk {
                                self.send_queue_bulk_bytes -= done.data.len();
                            }
                        }
                        // The peer accepted a full RPC — it's draining, so it
                        // isn't the wedged/zero-drain case. Reset the guard.
                        self.stuck_sheds = 0;
                        debug!(bytes = n, "wrote to outbound");
                    } else {
                        // Partial write — trim what was sent
                        let front = self.send_queue.front_mut().unwrap();
                        front.data = front.data[n..].to_vec();
                        self.send_queue_bytes -= n;
                        if front.bulk {
                            self.send_queue_bulk_bytes -= n;
                        }
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
        if self.closing {
            // Peer declared unwritable; the connection is winding down.
            // Queuing more would only be shed — drop it now.
            return;
        }
        debug!(data_len = event.rpc_data.len(), queue_len = self.send_queue.len(), "handler received data from behaviour");
        self.send_queue_bytes += event.rpc_data.len();
        if event.bulk {
            self.send_queue_bulk_bytes += event.rpc_data.len();
        }
        self.send_queue.push_back(QueuedRpc {
            data: event.rpc_data,
            bulk: event.bulk,
        });
        self.shed_send_queue();
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
                    // Outbound never negotiated after 3 tries: we can never
                    // send to this peer. Don't sit on it as a zombie with a
                    // growing send_queue — close so the swarm can re-dial /
                    // graft a replacement.
                    debug!("outbound BlossomSub upgrade failed 3 times, giving up — closing");
                    self.closing = true;
                    self.keep_alive = false;
                    self.send_queue.clear();
                    self.send_queue_bytes = 0;
                    self.send_queue_bulk_bytes = 0;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn handler() -> BlossomSubHandler {
        BlossomSubHandler::new(StreamProtocol::new("/blossomsub/test"))
    }

    fn feed(h: &mut BlossomSubHandler, len: usize, bulk: bool) {
        h.on_behaviour_event(HandlerIn {
            rpc_data: vec![0u8; len],
            bulk,
        });
    }

    /// REGRESSION (OOM): the per-connection outbound `send_queue` had no
    /// bound. A peer whose outbound stream stalls/never negotiates accumulates
    /// forwarded payloads forever (jeprof: 25 GB retained through handle_rpc,
    /// held here). The cap must bound buffered bytes while preserving control.
    #[test]
    fn send_queue_capped_drops_bulk_keeps_control() {
        let mut h = handler();
        // A few small control RPCs first (must survive).
        for _ in 0..4 {
            feed(&mut h, 64, false);
        }
        // Flood with 1 MiB bulk forwards — far over the 8 MiB cap.
        for _ in 0..64 {
            feed(&mut h, 1024 * 1024, true);
        }
        assert!(
            h.send_queue_bytes <= SEND_QUEUE_MAX_BYTES,
            "outbound backlog must stay under the cap, got {}",
            h.send_queue_bytes
        );
        // All 4 control RPCs preserved.
        let control = h.send_queue.iter().filter(|q| !q.bulk).count();
        assert_eq!(control, 4, "control RPCs must survive backlog shedding");
        // Accounting matches the actual buffered bytes.
        let actual: usize = h.send_queue.iter().map(|q| q.data.len()).sum();
        assert_eq!(actual, h.send_queue_bytes, "byte accounting must stay exact");
    }

    /// Hard stop: a queue of pure control that still exceeds the cap drops
    /// oldest entries so memory can't grow without bound even with no bulk.
    #[test]
    fn send_queue_hard_caps_even_pure_control() {
        let mut h = handler();
        for _ in 0..200 {
            feed(&mut h, 64 * 1024, false); // 200 × 64 KiB = 12.5 MiB of control
        }
        assert!(
            h.send_queue_bytes <= SEND_QUEUE_MAX_BYTES,
            "pure-control backlog must still be bounded, got {}",
            h.send_queue_bytes
        );
    }

    /// REGRESSION (CPU peg + warning storm): a peer that never drains (no
    /// outbound write ever resets `stuck_sheds`) must eventually be declared
    /// unwritable so the connection closes — otherwise the master core spins
    /// shedding a quarter-million-entry queue forever (observed: 6k warns in
    /// 4s, zero useful work).
    #[test]
    fn unwritable_peer_closes_after_repeated_sheds() {
        let mut h = handler();
        // No outbound stream is ever negotiated, so nothing drains. Each
        // over-cap push triggers a shed. Push enough small control RPCs to
        // exceed the cap, then keep pushing past MAX_STUCK_SHEDS.
        let entry = 64 * 1024; // 64 KiB; ~128 fill the 8 MiB cap
        for _ in 0..(128 + MAX_STUCK_SHEDS as usize + 8) {
            feed(&mut h, entry, false);
            if h.closing {
                break;
            }
        }
        assert!(h.closing, "a zero-drain peer must be declared unwritable");
        assert!(!h.keep_alive, "closing handler must drop keep_alive");
        // Backlog freed on close; further sends are dropped, not queued.
        assert_eq!(h.send_queue_bytes, 0);
        assert!(h.send_queue.is_empty());
        feed(&mut h, entry, false);
        assert!(h.send_queue.is_empty(), "closing handler must not re-queue");
    }

    /// A peer that drains keeps the connection: a successful write resets the
    /// stuck counter, so transient over-cap bursts never trip the close path.
    #[test]
    fn draining_peer_is_not_closed() {
        let mut h = handler();
        for _ in 0..200 {
            feed(&mut h, 64 * 1024, false);
            // Simulate the peer accepting a full RPC between pushes.
            h.stuck_sheds = 0;
        }
        assert!(!h.closing, "a draining peer must not be closed");
        assert!(h.send_queue_bytes <= SEND_QUEUE_MAX_BYTES);
    }
}
