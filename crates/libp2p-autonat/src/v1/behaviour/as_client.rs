// Copyright 2021 Protocol Labs.
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
    task::{Context, Poll},
    time::Duration,
};

use futures::FutureExt;
use futures_timer::Delay;
use libp2p_core::{multiaddr::Protocol, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_request_response::{self as request_response, OutboundFailure, OutboundRequestId};
use libp2p_swarm::{ConnectionId, ListenAddresses, ToSwarm};
use rand::{seq::SliceRandom, thread_rng};
use web_time::Instant;

use super::{
    Action, AutoNatCodec, Config, DialRequest, DialResponse, Event, HandleInnerEvent, NatStatus,
    ProbeId,
};
use crate::{protocol::MAX_MESSAGE_LEN, ResponseError};

/// Outbound probe failed or was aborted.
#[derive(Debug)]
pub enum OutboundProbeError {
    /// Probe was aborted because no server is known, or all servers
    /// are throttled through [`Config::throttle_server_period`].
    NoServer,
    ///  Probe was aborted because the local peer has no listening or
    /// external addresses.
    NoAddresses,
    /// Sending the dial-back request or receiving a response failed.
    OutboundRequest(OutboundFailure),
    /// The server refused or failed to dial us.
    Response(ResponseError),
}

#[derive(Debug)]
pub enum OutboundProbeEvent {
    /// A dial-back request was sent to a remote peer.
    Request {
        probe_id: ProbeId,
        /// Peer to which the request is sent.
        peer: PeerId,
    },
    /// The remote successfully dialed one of our addresses.
    Response {
        probe_id: ProbeId,
        /// Id of the peer that sent the response.
        peer: PeerId,
        /// The address at which the remote succeeded to dial us.
        address: Multiaddr,
    },
    /// The outbound request failed, was rejected, or the remote could dial
    /// none of our addresses.
    Error {
        probe_id: ProbeId,
        /// Id of the peer used for the probe.
        /// `None` if the probe was aborted due to no addresses or no qualified server.
        peer: Option<PeerId>,
        error: OutboundProbeError,
    },
}

/// View over [`super::Behaviour`] in a client role.
pub(crate) struct AsClient<'a> {
    pub(crate) inner: &'a mut request_response::Behaviour<AutoNatCodec>,
    pub(crate) local_peer_id: PeerId,
    pub(crate) config: &'a Config,
    pub(crate) connected: &'a HashMap<PeerId, HashMap<ConnectionId, Option<Multiaddr>>>,
    pub(crate) probe_id: &'a mut ProbeId,
    pub(crate) servers: &'a HashSet<PeerId>,
    pub(crate) throttled_servers: &'a mut Vec<(PeerId, Instant)>,
    pub(crate) nat_status: &'a mut NatStatus,
    pub(crate) confidence: &'a mut usize,
    pub(crate) ongoing_outbound: &'a mut HashMap<OutboundRequestId, ProbeId>,
    pub(crate) last_probe: &'a mut Option<Instant>,
    pub(crate) schedule_probe: &'a mut Delay,
    pub(crate) listen_addresses: &'a ListenAddresses,
    pub(crate) other_candidates: &'a VecDeque<Multiaddr>,
    pub(crate) last_probe_addresses: &'a mut Vec<Multiaddr>,
}

impl HandleInnerEvent for AsClient<'_> {
    fn handle_event(
        &mut self,
        event: request_response::Event<DialRequest, DialResponse>,
    ) -> VecDeque<Action> {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                tracing::debug!(?response, "Outbound dial-back request returned response");

                let probe_id = self
                    .ongoing_outbound
                    .remove(&request_id)
                    .expect("OutboundRequestId exists.");

                let event = match response.result.clone() {
                    Ok(address) => OutboundProbeEvent::Response {
                        probe_id,
                        peer,
                        address,
                    },
                    Err(e) => OutboundProbeEvent::Error {
                        probe_id,
                        peer: Some(peer),
                        error: OutboundProbeError::Response(e),
                    },
                };

                let mut actions = VecDeque::with_capacity(3);

                actions.push_back(ToSwarm::GenerateEvent(Event::OutboundProbe(event)));

                if let Some(old) = self.handle_reported_status(response.result.clone().into()) {
                    actions.push_back(ToSwarm::GenerateEvent(Event::StatusChanged {
                        old,
                        new: self.nat_status.clone(),
                    }));
                }

                if let Ok(address) = response.result {
                    actions.push_back(ToSwarm::ExternalAddrConfirmed(address));
                }

                actions
            }
            request_response::Event::OutboundFailure {
                peer,
                error,
                request_id,
                ..
            } => {
                tracing::debug!(
                    %peer,
                    "Outbound Failure {} when on dial-back request to peer.",
                    error,
                );
                let probe_id = self
                    .ongoing_outbound
                    .remove(&request_id)
                    .unwrap_or_else(|| self.probe_id.next());

                self.schedule_probe.reset(Duration::ZERO);

                VecDeque::from([ToSwarm::GenerateEvent(Event::OutboundProbe(
                    OutboundProbeEvent::Error {
                        probe_id,
                        peer: Some(peer),
                        error: OutboundProbeError::OutboundRequest(error),
                    },
                ))])
            }
            _ => VecDeque::default(),
        }
    }
}

impl AsClient<'_> {
    pub(crate) fn poll_auto_probe(&mut self, cx: &mut Context<'_>) -> Poll<OutboundProbeEvent> {
        match self.schedule_probe.poll_unpin(cx) {
            Poll::Ready(()) => {
                self.schedule_probe.reset(self.config.retry_interval);

                // QUILIBRIUM: listen addresses first, one per dial-back
                // stack, within the server's limits (see `probe_addresses`).
                let addresses = probe_addresses(
                    self.local_peer_id,
                    self.listen_addresses.iter(),
                    self.other_candidates.iter(),
                );

                let probe_id = self.probe_id.next();
                let event = match self.do_probe(probe_id, addresses) {
                    Ok(peer) => OutboundProbeEvent::Request { probe_id, peer },
                    Err(error) => {
                        self.handle_reported_status(NatStatus::Unknown);
                        OutboundProbeEvent::Error {
                            probe_id,
                            peer: None,
                            error,
                        }
                    }
                };
                Poll::Ready(event)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    // An inbound connection can indicate that we are public; adjust the delay to the next probe.
    pub(crate) fn on_inbound_connection(&mut self) {
        if *self.confidence == self.config.confidence_max {
            if self.nat_status.is_public() {
                self.schedule_next_probe(self.config.refresh_interval * 2);
            } else {
                self.schedule_next_probe(self.config.refresh_interval / 5);
            }
        }
    }

    pub(crate) fn on_new_address(&mut self) {
        if !self.nat_status.is_public() {
            // New address could be publicly reachable, trigger retry.
            if *self.confidence > 0 {
                *self.confidence -= 1;
            }
            self.schedule_next_probe(self.config.retry_interval);
        }
    }

    pub(crate) fn on_expired_address(&mut self, addr: &Multiaddr) {
        if let NatStatus::Public(public_address) = self.nat_status {
            if public_address == addr {
                *self.confidence = 0;
                *self.nat_status = NatStatus::Unknown;
                self.schedule_next_probe(Duration::ZERO);
            }
        }
    }

    // Select a random server for the probe.
    fn random_server(&mut self) -> Option<PeerId> {
        // Update list of throttled servers.
        let i = self.throttled_servers.partition_point(|(_, time)| {
            *time + self.config.throttle_server_period < Instant::now()
        });
        self.throttled_servers.drain(..i);

        let mut servers: Vec<&PeerId> = self.servers.iter().collect();

        if self.config.use_connected {
            servers.extend(self.connected.iter().filter_map(|(id, addrs)| {
                // Filter servers for which no qualified address is known.
                // This is the case if the connection is relayed or the address is
                // not global (in case of Config::only_global_ips).
                addrs.values().any(|a| a.is_some()).then_some(id)
            }));
        }

        servers.retain(|s| !self.throttled_servers.iter().any(|(id, _)| s == &id));

        servers.choose(&mut thread_rng()).map(|&&p| p)
    }

    // Send a dial-request to a randomly selected server.
    // Returns the server that is used in this probe.
    // `Err` if there are no qualified servers or no addresses.
    fn do_probe(
        &mut self,
        probe_id: ProbeId,
        addresses: Vec<Multiaddr>,
    ) -> Result<PeerId, OutboundProbeError> {
        let _ = self.last_probe.insert(Instant::now());
        // QUILIBRIUM: kept for `Behaviour::last_probe_addresses`.
        self.last_probe_addresses.clone_from(&addresses);
        if addresses.is_empty() {
            tracing::debug!("Outbound dial-back request aborted: No dial-back addresses");
            return Err(OutboundProbeError::NoAddresses);
        }

        let server = self.random_server().ok_or(OutboundProbeError::NoServer)?;

        let request_id = self.inner.send_request(
            &server,
            DialRequest {
                peer_id: self.local_peer_id,
                addresses,
            },
        );
        self.throttled_servers.push((server, Instant::now()));
        tracing::debug!(peer=%server, "Send dial-back request to peer");
        self.ongoing_outbound.insert(request_id, probe_id);
        Ok(server)
    }

    // Set the delay to the next probe based on the time of our last probe
    // and the specified delay.
    fn schedule_next_probe(&mut self, delay: Duration) {
        let Some(last_probe_instant) = self.last_probe else {
            return;
        };
        let schedule_next = *last_probe_instant + delay;
        self.schedule_probe
            .reset(schedule_next.saturating_duration_since(Instant::now()));
    }

    // Adapt current confidence and NAT status to the status reported by the latest probe.
    // Return the old status if it flipped.
    fn handle_reported_status(&mut self, reported_status: NatStatus) -> Option<NatStatus> {
        self.schedule_next_probe(self.config.retry_interval);

        if matches!(reported_status, NatStatus::Unknown) {
            return None;
        }

        if reported_status == *self.nat_status {
            if *self.confidence < self.config.confidence_max {
                *self.confidence += 1;
            }
            // Delay with (usually longer) refresh-interval.
            if *self.confidence >= self.config.confidence_max {
                self.schedule_next_probe(self.config.refresh_interval);
            }
            return None;
        }

        if reported_status.is_public() && self.nat_status.is_public() {
            // Different address than the currently assumed public address was reported.
            // Switch address, but don't report as flipped.
            *self.nat_status = reported_status;
            return None;
        }
        if *self.confidence > 0 {
            // Reduce confidence but keep old status.
            *self.confidence -= 1;
            return None;
        }

        tracing::debug!(
            old_status=?self.nat_status,
            new_status=?reported_status,
            "Flipped assumed NAT status"
        );

        let old_status = self.nat_status.clone();
        *self.nat_status = reported_status;

        Some(old_status)
    }
}

/// QUILIBRIUM: the most addresses one dial-back request carries. A server
/// keeps the first `Config::max_peer_addresses` (16 by default) and dials
/// them one at a time, so each address delays the ones behind it.
pub(crate) const MAX_PROBE_ADDRESSES: usize = 8;

/// QUILIBRIUM: the dial-back addresses of a probe.
///
/// A server replaces the IP of each address with the one it observes for
/// us, so an address tells it only the protocols after its IP (transport
/// and port): one address per such stack is enough. The listen addresses
/// come first, since a public or port-forwarded node is reachable on its
/// listen port; then the external candidates, most recent first, for a NAT
/// that maps another external port. The list holds at most
/// [`MAX_PROBE_ADDRESSES`], and its request fits the server's frame limit.
///
/// Upstream sends every candidate ever observed, in hash order, ahead of
/// the listen addresses. Peers behind address translation report many
/// different ports for us, so the server's first dials went to closed
/// ports until the request timed out, and with enough candidates the
/// request outgrew the frame limit and no server could read it.
pub(crate) fn probe_addresses<'a>(
    local_peer_id: PeerId,
    listen_addresses: impl Iterator<Item = &'a Multiaddr>,
    candidates: impl Iterator<Item = &'a Multiaddr>,
) -> Vec<Multiaddr> {
    // Listen addresses are a hash set: sort them so each stack keeps the
    // same representative.
    let mut listen: Vec<&Multiaddr> = listen_addresses.collect();
    listen.sort();
    let mut stacks = HashSet::new();
    let addresses = listen
        .into_iter()
        .chain(candidates)
        .filter(|addr| dial_back_stack(addr).is_some_and(|stack| stacks.insert(stack)))
        .take(MAX_PROBE_ADDRESSES)
        .cloned()
        .collect();
    let mut request = DialRequest {
        peer_id: local_peer_id,
        addresses,
    };
    while !request.addresses.is_empty() && request.encoded_len() > MAX_MESSAGE_LEN {
        request.addresses.pop();
    }
    request.addresses
}

/// QUILIBRIUM: what a server dials of `addr` besides our IP: the protocols
/// after its first IP component, without `/p2p`. `None` without an IP
/// component, since a server drops such an address.
fn dial_back_stack(addr: &Multiaddr) -> Option<Multiaddr> {
    let mut protocols = addr.iter();
    protocols.find(|p| matches!(p, Protocol::Ip4(_) | Protocol::Ip6(_)))?;
    Some(
        protocols
            .filter(|p| !matches!(p, Protocol::P2p(_)))
            .collect(),
    )
}

impl From<Result<Multiaddr, ResponseError>> for NatStatus {
    fn from(result: Result<Multiaddr, ResponseError>) -> Self {
        match result {
            Ok(addr) => NatStatus::Public(addr),
            Err(ResponseError::DialError) => NatStatus::Private,
            _ => NatStatus::Unknown,
        }
    }
}

// QUILIBRIUM: tests of the probe address list (see PATCHES.md).
#[cfg(test)]
mod tests {
    use super::*;

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    /// A candidate on an ephemeral port, as peers behind address
    /// translation report us.
    fn junk(n: u16) -> Multiaddr {
        ma(&format!("/ip4/203.0.113.7/tcp/{}", 40_000 + n))
    }

    fn stack(addr: &Multiaddr) -> String {
        dial_back_stack(addr).unwrap().to_string()
    }

    fn encoded_len(peer_id: PeerId, addresses: Vec<Multiaddr>) -> usize {
        DialRequest { peer_id, addresses }.encoded_len()
    }

    #[test]
    fn listen_stacks_go_first_one_each_then_recent_candidates() {
        let listen = [
            ma("/ip4/127.0.0.1/tcp/9336"),
            ma("/ip4/10.0.0.2/tcp/9336"),
            ma("/ip4/10.0.0.2/udp/9336/quic-v1"),
        ];
        // Most recent first: an observation on the listen port adds nothing.
        let mut candidates: Vec<Multiaddr> = (0..100).map(junk).collect();
        candidates.insert(0, ma("/ip4/198.51.100.4/tcp/9336"));
        let sent = probe_addresses(PeerId::random(), listen.iter(), candidates.iter());
        assert_eq!(sent.len(), MAX_PROBE_ADDRESSES);
        let mut first: Vec<String> = sent[..2].iter().map(stack).collect();
        first.sort();
        assert_eq!(first, ["/tcp/9336", "/udp/9336/quic-v1"]);
        assert_eq!(sent.iter().filter(|a| stack(a) == "/tcp/9336").count(), 1);
        assert_eq!(&sent[2..], &candidates[1..7]);
    }

    #[test]
    fn addresses_without_an_ip_are_skipped() {
        let listen = [ma("/dns4/node.example.com/tcp/9336")];
        let candidates = [junk(1).with(Protocol::P2p(PeerId::random()))];
        let sent = probe_addresses(PeerId::random(), listen.iter(), candidates.iter());
        assert_eq!(sent, candidates);
        assert_eq!(stack(&candidates[0]), "/tcp/40001");
    }

    /// Upstream's list (every candidate, then the listen addresses) outgrows
    /// the server's frame limit; ours stays within it.
    #[test]
    fn the_request_fits_the_frame_limit() {
        let me = PeerId::random();
        let listen = [ma("/ip4/10.0.0.2/tcp/9336")];
        let candidates: Vec<Multiaddr> =
            (0..100).map(|n| junk(n).with(Protocol::P2p(me))).collect();
        let upstream = candidates.iter().chain(listen.iter()).cloned().collect();
        assert!(encoded_len(me, upstream) > MAX_MESSAGE_LEN);
        let sent = probe_addresses(me, listen.iter(), candidates.iter());
        assert_eq!(sent.len(), MAX_PROBE_ADDRESSES);
        assert!(encoded_len(me, sent.clone()) <= MAX_MESSAGE_LEN);
        assert_eq!(sent[0], listen[0]);

        // Long stacks: the list stops short of the limit, listen port first.
        let long: Vec<Multiaddr> = (0..8)
            .map(|n| junk(n).with(Protocol::Ws(format!("/{}", "a".repeat(200)).into())))
            .collect();
        let sent = probe_addresses(me, listen.iter(), long.iter());
        let len = encoded_len(me, sent.clone());
        assert!(len <= MAX_MESSAGE_LEN, "{len} bytes");
        assert!(
            sent.len() > 1 && sent.len() < MAX_PROBE_ADDRESSES,
            "{}",
            sent.len()
        );
        assert_eq!(sent[0], listen[0]);
    }
}
