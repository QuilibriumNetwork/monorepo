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

mod as_client;
mod as_server;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    iter,
    net::IpAddr,
    task::{Context, Poll},
    time::Duration,
};

use as_client::AsClient;
pub use as_client::{OutboundProbeError, OutboundProbeEvent};
use as_server::AsServer;
pub use as_server::{InboundProbeError, InboundProbeEvent, ServerStats};
use futures_timer::Delay;
use libp2p_core::{multiaddr::Protocol, transport::PortUse, ConnectedPoint, Endpoint, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_request_response::{self as request_response, OutboundRequestId, ProtocolSupport};
use libp2p_swarm::{
    behaviour::{AddressChange, ConnectionClosed, ConnectionEstablished, DialFailure, FromSwarm},
    ConnectionDenied, ConnectionId, ListenAddresses, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use web_time::Instant;

use crate::{
    protocol::{AutoNatCodec, DialRequest, DialResponse, ResponseError},
    DEFAULT_PROTOCOL_NAME,
};

/// Config for the [`Behaviour`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Timeout for requests.
    pub timeout: Duration,

    // Client Config
    /// Delay on init before starting the fist probe.
    pub boot_delay: Duration,
    /// Interval in which the NAT should be tested again if max confidence was reached in a status.
    pub refresh_interval: Duration,
    /// Interval in which the NAT status should be re-tried if it is currently unknown
    /// or max confidence was not reached yet.
    pub retry_interval: Duration,
    /// Throttle period for re-using a peer as server for a dial-request.
    pub throttle_server_period: Duration,
    /// Use connected peers as servers for probes.
    pub use_connected: bool,
    /// Max confidence that can be reached in a public / private NAT status.
    /// Note: for [`NatStatus::Unknown`] the confidence is always 0.
    pub confidence_max: usize,

    // Server Config
    /// Max addresses that are tried per peer.
    ///
    /// QUILIBRIUM: 8 (upstream 16), the most this repository's clients
    /// send (`as_client::MAX_PROBE_ADDRESSES`). They are dialed one at a
    /// time, each that does not answer taking up to the transport timeout,
    /// so the count sets how long a dial-back runs, not how many dials run
    /// at once ([`Config::max_concurrent_dial_backs`] bounds those).
    /// Clients without that limit send their external candidates first
    /// and their listen addresses after; a lower count would leave their
    /// listen port undialed more often.
    pub max_peer_addresses: usize,
    /// QUILIBRIUM: max dial-backs in progress at once whose request is
    /// open; those whose request failed (it timed out, or the client
    /// closed it) answer no one and give their place at once, but count
    /// until their dial ends against twice this in all. A request beyond
    /// either is refused (`DialRefused`, which leaves the client's status
    /// unchanged). 16 by default: with one dial-back per IP and two per IP
    /// group (an IPv4 /24 or an IPv6 /48), holding them all takes 16 IPs in
    /// 8 groups each keeping a request open, and each dial-back holds one
    /// pending outgoing dial,
    /// at most 32, which leaves half of the 64 this repository's node
    /// allows to its other dials and its own probes.
    pub max_concurrent_dial_backs: usize,
    /// QUILIBRIUM: the age at which a dial-back the swarm never reported
    /// ended is dropped, checked at each request. 160 s by default: twice
    /// the longest a dial-back of [`Config::max_peer_addresses`] takes at
    /// the swarm's default connection timeout (10 s each). The swarm
    /// reports how every dial ends; this bounds the harm if a version
    /// misses one, which would hold a place for good.
    pub max_dial_back_age: Duration,
    /// Max total dial requests done in `[Config::throttle_clients_period`].
    pub throttle_clients_global_max: usize,
    /// Max dial requests done in `[Config::throttle_clients_period`] for a peer.
    pub throttle_clients_peer_max: usize,
    /// Period for throttling clients requests.
    pub throttle_clients_period: Duration,
    /// As a server reject probes for clients that are observed at a non-global ip address.
    /// Correspondingly as a client only pick peers as server that are not observed at a
    /// private ip address. Note that this does not apply for servers that are added via
    /// [`Behaviour::add_server`].
    pub only_global_ips: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            timeout: Duration::from_secs(30),
            boot_delay: Duration::from_secs(15),
            retry_interval: Duration::from_secs(90),
            refresh_interval: Duration::from_secs(15 * 60),
            throttle_server_period: Duration::from_secs(90),
            use_connected: true,
            confidence_max: 3,
            max_peer_addresses: 8,
            max_concurrent_dial_backs: 16,
            max_dial_back_age: Duration::from_secs(160),
            throttle_clients_global_max: 30,
            throttle_clients_peer_max: 3,
            throttle_clients_period: Duration::from_secs(1),
            only_global_ips: true,
        }
    }
}

/// Assumed NAT status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatStatus {
    Public(Multiaddr),
    Private,
    Unknown,
}

impl NatStatus {
    pub fn is_public(&self) -> bool {
        matches!(self, NatStatus::Public(..))
    }
}

/// Unique identifier for a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProbeId(usize);

impl ProbeId {
    fn next(&mut self) -> ProbeId {
        let current = *self;
        self.0 += 1;
        current
    }
}

/// Event produced by [`Behaviour`].
#[derive(Debug)]
pub enum Event {
    /// Event on an inbound probe.
    InboundProbe(InboundProbeEvent),
    /// Event on an outbound probe.
    OutboundProbe(OutboundProbeEvent),
    /// The assumed NAT changed.
    StatusChanged {
        /// Former status.
        old: NatStatus,
        /// New status.
        new: NatStatus,
    },
}

/// [`NetworkBehaviour`] for AutoNAT.
///
/// The behaviour frequently runs probes to determine whether the local peer is behind NAT and/ or a
/// firewall, or publicly reachable.
/// In a probe, a dial-back request is sent to a peer that is randomly selected from the list of
/// fixed servers and connected peers. Upon receiving a dial-back request, the remote tries to dial
/// the included addresses. When a first address was successfully dialed, a status Ok will be send
/// back together with the dialed address. If no address can be reached a dial-error is send back.
/// Based on the received response, the sender assumes themselves to be public or private.
/// The status is retried in a frequency of [`Config::retry_interval`] or
/// [`Config::retry_interval`], depending on whether enough confidence in the assumed NAT status was
/// reached or not. The confidence increases each time a probe confirms the assumed status, and
/// decreases if a different status is reported. If the confidence is 0, the status is flipped and
/// the Behaviour will report the new status in an `OutEvent`.
pub struct Behaviour {
    // Local peer id
    local_peer_id: PeerId,

    // Inner behaviour for sending requests and receiving the response.
    inner: request_response::Behaviour<AutoNatCodec>,

    config: Config,

    // Additional peers apart from the currently connected ones, that may be used for probes.
    servers: HashSet<PeerId>,

    // Assumed NAT status.
    nat_status: NatStatus,

    // Confidence in the assumed NAT status.
    confidence: usize,

    // Timer for the next probe.
    schedule_probe: Delay,

    // Ongoing inbound requests, where no response has been sent back to the remote yet.
    // QUILIBRIUM: with the connection id of the dial-back.
    ongoing_inbound: as_server::OngoingInbounds,

    // QUILIBRIUM: what the server did since the last `take_server_stats`.
    server_stats: ServerStats,

    // Ongoing outbound probes and mapped to the inner request id.
    // QUILIBRIUM: with the addresses each probe offered.
    ongoing_outbound: HashMap<OutboundRequestId, as_client::OngoingOutbound>,

    // Connected peers with the observed address of each connection.
    // If the endpoint of a connection is relayed or not global (in case of
    // Config::only_global_ips), the observed address is `None`.
    connected: HashMap<PeerId, HashMap<ConnectionId, Option<Multiaddr>>>,

    // Used servers in recent outbound probes that are throttled through
    // Config::throttle_server_period.
    throttled_servers: Vec<(PeerId, Instant)>,

    // Recent probes done for clients
    throttled_clients: Vec<(PeerId, Instant)>,

    last_probe: Option<Instant>,

    pending_actions: VecDeque<ToSwarm<<Self as NetworkBehaviour>::ToSwarm, THandlerInEvent<Self>>>,

    probe_id: ProbeId,

    listen_addresses: ListenAddresses,
    // QUILIBRIUM: most recent first, at most `MAX_CANDIDATES` (upstream: an
    // unbounded hash set that never forgets an address).
    other_candidates: VecDeque<Multiaddr>,
    // QUILIBRIUM: the addresses of the latest probe request.
    last_probe_addresses: Vec<Multiaddr>,
    // QUILIBRIUM: the IP each observer group last observed this node at,
    // most recent first, at most `MAX_OBSERVERS` (see
    // `note_observed_address`).
    observers: VecDeque<as_client::Observation>,
}

/// QUILIBRIUM: how many external address candidates the client keeps.
/// Identify reports a candidate per connection, and peers behind address
/// translation report a different port each; only the most recent ones are
/// kept for the probe list (see `as_client::probe_addresses`).
const MAX_CANDIDATES: usize = 16;

/// QUILIBRIUM: how many observations of this node's IP the client keeps,
/// one per peer and per observer IP group (see
/// [`Behaviour::note_observed_address`]).
const MAX_OBSERVERS: usize = 64;

impl Behaviour {
    pub fn new(local_peer_id: PeerId, config: Config) -> Self {
        let protocols = iter::once((DEFAULT_PROTOCOL_NAME, ProtocolSupport::Full));
        let inner = request_response::Behaviour::with_codec(
            AutoNatCodec,
            protocols,
            request_response::Config::default().with_request_timeout(config.timeout),
        );
        Self {
            local_peer_id,
            inner,
            schedule_probe: Delay::new(config.boot_delay),
            config,
            servers: HashSet::new(),
            ongoing_inbound: HashMap::default(),
            ongoing_outbound: HashMap::default(),
            connected: HashMap::default(),
            nat_status: NatStatus::Unknown,
            confidence: 0,
            throttled_servers: Vec::new(),
            throttled_clients: Vec::new(),
            last_probe: None,
            pending_actions: VecDeque::new(),
            probe_id: ProbeId(0),
            listen_addresses: Default::default(),
            other_candidates: Default::default(),
            last_probe_addresses: Vec::new(),
            server_stats: ServerStats::default(),
            observers: VecDeque::new(),
        }
    }

    /// Assumed public address of the local peer.
    /// Returns `None` in case of status [`NatStatus::Private`] or [`NatStatus::Unknown`].
    pub fn public_address(&self) -> Option<&Multiaddr> {
        match &self.nat_status {
            NatStatus::Public(address) => Some(address),
            _ => None,
        }
    }

    /// Assumed NAT status.
    pub fn nat_status(&self) -> NatStatus {
        self.nat_status.clone()
    }

    /// Confidence in the assumed NAT status.
    pub fn confidence(&self) -> usize {
        self.confidence
    }

    /// Add a peer to the list over servers that may be used for probes.
    /// These peers are used for dial-request even if they are currently not connection, in which
    /// case a connection will be establish before sending the dial-request.
    pub fn add_server(&mut self, peer: PeerId, address: Option<Multiaddr>) {
        self.servers.insert(peer);
        if let Some(addr) = address {
            #[allow(deprecated)]
            self.inner.add_address(&peer, addr);
        }
    }

    /// Remove a peer from the list of servers.
    /// See [`Behaviour::add_server`] for more info.
    pub fn remove_server(&mut self, peer: &PeerId) {
        self.servers.retain(|p| p != peer);
    }

    /// Explicitly probe the provided address for external reachability.
    pub fn probe_address(&mut self, candidate: Multiaddr) {
        // QUILIBRIUM: a repeated candidate moves to the front; the oldest
        // beyond `MAX_CANDIDATES` is forgotten.
        self.other_candidates.retain(|a| *a != candidate);
        self.other_candidates.push_front(candidate);
        self.other_candidates.truncate(MAX_CANDIDATES);
        self.as_client().on_new_address();
    }

    /// QUILIBRIUM: send the next probe now rather than at its scheduled
    /// time. The servers of recent probes stay throttled
    /// ([`Config::throttle_server_period`]), so it goes to another server,
    /// or fails with `NoServer` when there is none. The embedder calls it
    /// when a first address awaits a second server, which the next
    /// scheduled probe would ask only a retry interval later.
    pub fn probe_now(&mut self) {
        self.schedule_probe.reset(Duration::ZERO);
    }

    /// QUILIBRIUM: `observer`, connected from `observer_ip` (the remote IP
    /// of the connection identify ran on), saw this node at `observed`
    /// (identify's observed address). A server's answer naming an IP that
    /// no listen address has counts only when a peer other than that
    /// server observed the node there (see `as_client::answers_probe`):
    /// external candidates carry no observer, and one peer could plant a
    /// candidate through identify and then answer a probe of it as a
    /// server. Keeps the latest observation per peer and per observer IP
    /// group (an IPv4 /24 or an IPv6 /48), for the [`MAX_OBSERVERS`] most
    /// recent: one host or one rented block with any number of peer IDs,
    /// pushing identify again and again, holds one entry and cannot evict
    /// other hosts' observations; that takes [`MAX_OBSERVERS`] groups.
    pub fn note_observed_address(
        &mut self,
        observer: PeerId,
        observer_ip: IpAddr,
        observed: &Multiaddr,
    ) {
        let Some(seen) = as_client::first_ip(observed) else {
            return;
        };
        let group = as_client::observer_group(observer_ip);
        self.observers
            .retain(|o| o.observer != observer && o.group != group);
        self.observers.push_front(as_client::Observation {
            observer,
            group,
            seen,
        });
        self.observers.truncate(MAX_OBSERVERS);
    }

    /// QUILIBRIUM: what this node did as a server with other nodes'
    /// dial-back requests since the last call, for an operator summary.
    pub fn take_server_stats(&mut self) -> ServerStats {
        std::mem::take(&mut self.server_stats)
    }

    /// QUILIBRIUM: the dial-back addresses of the latest probe request
    /// (empty before the first).
    pub fn last_probe_addresses(&self) -> &[Multiaddr] {
        &self.last_probe_addresses
    }

    /// QUILIBRIUM: how many servers the next probe can choose from: the
    /// servers (and, with [`Config::use_connected`], the connected peers with
    /// a qualified address) not throttled by
    /// [`Config::throttle_server_period`].
    pub fn eligible_servers(&self) -> usize {
        let now = Instant::now();
        let throttled = |peer: &PeerId| {
            self.throttled_servers
                .iter()
                .any(|(id, time)| id == peer && *time + self.config.throttle_server_period >= now)
        };
        let mut eligible = self.servers.iter().filter(|p| !throttled(*p)).count();
        if self.config.use_connected {
            eligible += self
                .connected
                .iter()
                .filter(|&(id, addrs)| {
                    !self.servers.contains(id)
                        && addrs.values().any(Option::is_some)
                        && !throttled(id)
                })
                .count();
        }
        eligible
    }

    fn as_client(&mut self) -> AsClient<'_> {
        AsClient {
            inner: &mut self.inner,
            local_peer_id: self.local_peer_id,
            config: &self.config,
            connected: &self.connected,
            probe_id: &mut self.probe_id,
            servers: &self.servers,
            throttled_servers: &mut self.throttled_servers,
            nat_status: &mut self.nat_status,
            confidence: &mut self.confidence,
            ongoing_outbound: &mut self.ongoing_outbound,
            last_probe: &mut self.last_probe,
            schedule_probe: &mut self.schedule_probe,
            listen_addresses: &self.listen_addresses,
            other_candidates: &self.other_candidates,
            last_probe_addresses: &mut self.last_probe_addresses,
            observers: &self.observers,
        }
    }

    fn as_server(&mut self) -> AsServer<'_> {
        AsServer {
            inner: &mut self.inner,
            config: &self.config,
            connected: &self.connected,
            probe_id: &mut self.probe_id,
            throttled_clients: &mut self.throttled_clients,
            ongoing_inbound: &mut self.ongoing_inbound,
            stats: &mut self.server_stats,
        }
    }

    fn on_connection_established(
        &mut self,
        ConnectionEstablished {
            peer_id: peer,
            connection_id: conn,
            endpoint,
            ..
        }: ConnectionEstablished,
    ) {
        let connections = self.connected.entry(peer).or_default();
        let addr = endpoint.get_remote_address();
        let observed_addr =
            if !endpoint.is_relayed() && (!self.config.only_global_ips || addr.is_global_ip()) {
                Some(addr.clone())
            } else {
                None
            };
        connections.insert(conn, observed_addr);

        match endpoint {
            ConnectedPoint::Dialer {
                address,
                role_override: Endpoint::Dialer,
                port_use: _,
            } => {
                // QUILIBRIUM: the connection id tells the dial-back from
                // other connections to the client.
                if let Some(event) = self
                    .as_server()
                    .on_outbound_connection(&peer, conn, address)
                {
                    self.pending_actions
                        .push_back(ToSwarm::GenerateEvent(Event::InboundProbe(event)));
                }
            }
            ConnectedPoint::Dialer {
                address: _,
                role_override: Endpoint::Listener,
                port_use: _,
            } => {
                // Outgoing connection was dialed as a listener. In other words outgoing connection
                // was dialed as part of a hole punch. `libp2p-autonat` never attempts to hole
                // punch, thus this connection has not been requested by this [`NetworkBehaviour`].
            }
            ConnectedPoint::Listener { .. } => self.as_client().on_inbound_connection(),
        }
    }

    fn on_connection_closed(
        &mut self,
        ConnectionClosed {
            peer_id,
            connection_id,
            remaining_established,
            ..
        }: ConnectionClosed,
    ) {
        if remaining_established == 0 {
            self.connected.remove(&peer_id);
        } else {
            let connections = self
                .connected
                .get_mut(&peer_id)
                .expect("Peer is connected.");
            connections.remove(&connection_id);
        }
    }

    fn on_dial_failure(
        &mut self,
        DialFailure {
            peer_id,
            error,
            connection_id,
        }: DialFailure,
    ) {
        // QUILIBRIUM: the connection id tells the dial-back from other dials.
        if let Some(event) = self
            .as_server()
            .on_outbound_dial_error(peer_id, connection_id, error)
        {
            self.pending_actions
                .push_back(ToSwarm::GenerateEvent(Event::InboundProbe(event)));
        }
    }

    fn on_address_change(
        &mut self,
        AddressChange {
            peer_id: peer,
            connection_id: conn,
            old,
            new,
        }: AddressChange,
    ) {
        if old.is_relayed() && new.is_relayed() {
            return;
        }
        let connections = self.connected.get_mut(&peer).expect("Peer is connected.");
        let addr = new.get_remote_address();
        let observed_addr =
            if !new.is_relayed() && (!self.config.only_global_ips || addr.is_global_ip()) {
                Some(addr.clone())
            } else {
                None
            };
        connections.insert(conn, observed_addr);
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler =
        <request_response::Behaviour<AutoNatCodec> as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = Event;

    #[tracing::instrument(level = "trace", name = "NetworkBehaviour::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            if let Some(event) = self.pending_actions.pop_front() {
                return Poll::Ready(event);
            }

            match self.inner.poll(cx) {
                Poll::Ready(ToSwarm::GenerateEvent(event)) => {
                    let actions = match event {
                        request_response::Event::Message {
                            message: request_response::Message::Response { .. },
                            ..
                        }
                        | request_response::Event::OutboundFailure { .. } => {
                            self.as_client().handle_event(event)
                        }
                        request_response::Event::Message {
                            message: request_response::Message::Request { .. },
                            ..
                        }
                        | request_response::Event::InboundFailure { .. } => {
                            self.as_server().handle_event(event)
                        }
                        request_response::Event::ResponseSent { .. } => VecDeque::new(),
                    };

                    self.pending_actions.extend(actions);
                    continue;
                }
                Poll::Ready(action) => {
                    self.pending_actions
                        .push_back(action.map_out(|_| unreachable!()));
                    continue;
                }
                Poll::Pending => {}
            }

            match self.as_client().poll_auto_probe(cx) {
                Poll::Ready(event) => {
                    self.pending_actions
                        .push_back(ToSwarm::GenerateEvent(Event::OutboundProbe(event)));
                    continue;
                }
                Poll::Pending => {}
            }

            return Poll::Pending;
        }
    }

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.listen_addresses.on_swarm_event(&event);
        self.inner.on_swarm_event(event);

        match event {
            FromSwarm::ConnectionEstablished(e) => self.on_connection_established(e),
            FromSwarm::ConnectionClosed(e) => self.on_connection_closed(e),
            FromSwarm::DialFailure(e) => self.on_dial_failure(e),
            FromSwarm::AddressChange(e) => self.on_address_change(e),
            FromSwarm::NewListenAddr(_) => {
                self.as_client().on_new_address();
            }
            FromSwarm::ExpiredListenAddr(e) => {
                self.as_client().on_expired_address(e.addr);
            }
            FromSwarm::ExternalAddrExpired(e) => {
                self.as_client().on_expired_address(e.addr);
            }
            FromSwarm::NewExternalAddrCandidate(e) => {
                self.probe_address(e.addr.to_owned());
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(peer_id, connection_id, event)
    }
}

type Action = ToSwarm<<Behaviour as NetworkBehaviour>::ToSwarm, THandlerInEvent<Behaviour>>;

// Trait implemented for `AsClient` and `AsServer` to handle events from the inner
// [`request_response::Behaviour`] Protocol.
trait HandleInnerEvent {
    fn handle_event(
        &mut self,
        event: request_response::Event<DialRequest, DialResponse>,
    ) -> VecDeque<Action>;
}

trait GlobalIp {
    fn is_global_ip(&self) -> bool;
}

impl GlobalIp for Multiaddr {
    fn is_global_ip(&self) -> bool {
        match self.iter().next() {
            Some(Protocol::Ip4(a)) => a.is_global_ip(),
            Some(Protocol::Ip6(a)) => a.is_global_ip(),
            _ => false,
        }
    }
}

impl GlobalIp for std::net::Ipv4Addr {
    // NOTE: The below logic is copied from `std::net::Ipv4Addr::is_global`, which is at the time of
    // writing behind the unstable `ip` feature.
    // See https://github.com/rust-lang/rust/issues/27709 for more info.
    fn is_global_ip(&self) -> bool {
        // Check if this address is 192.0.0.9 or 192.0.0.10. These addresses are the only two
        // globally routable addresses in the 192.0.0.0/24 range.
        if u32::from_be_bytes(self.octets()) == 0xc0000009
            || u32::from_be_bytes(self.octets()) == 0xc000000a
        {
            return true;
        }

        // Copied from the unstable method `std::net::Ipv4Addr::is_shared`.
        fn is_shared(addr: &std::net::Ipv4Addr) -> bool {
            addr.octets()[0] == 100 && (addr.octets()[1] & 0b1100_0000 == 0b0100_0000)
        }

        // Copied from the unstable method `std::net::Ipv4Addr::is_reserved`.
        //
        // **Warning**: As IANA assigns new addresses, this logic will be
        // updated. This may result in non-reserved addresses being
        // treated as reserved in code that relies on an outdated version
        // of this method.
        fn is_reserved(addr: &std::net::Ipv4Addr) -> bool {
            addr.octets()[0] & 240 == 240 && !addr.is_broadcast()
        }

        // Copied from the unstable method `std::net::Ipv4Addr::is_benchmarking`.
        fn is_benchmarking(addr: &std::net::Ipv4Addr) -> bool {
            addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18
        }

        !self.is_private()
            && !self.is_loopback()
            && !self.is_link_local()
            && !self.is_broadcast()
            && !self.is_documentation()
            && !is_shared(self)
            // addresses reserved for future protocols (`192.0.0.0/24`)
            && !(self.octets()[0] == 192 && self.octets()[1] == 0 && self.octets()[2] == 0)
            && !is_reserved(self)
            && !is_benchmarking(self)
            // Make sure the address is not in 0.0.0.0/8
            && self.octets()[0] != 0
    }
}

impl GlobalIp for std::net::Ipv6Addr {
    // NOTE: The below logic is copied from `std::net::Ipv6Addr::is_global`, which is at the time of
    // writing behind the unstable `ip` feature.
    // See https://github.com/rust-lang/rust/issues/27709 for more info.
    //
    // Note that contrary to `Ipv4Addr::is_global_ip` this currently checks for global scope
    // rather than global reachability.
    fn is_global_ip(&self) -> bool {
        // Copied from the unstable method `std::net::Ipv6Addr::is_unicast`.
        fn is_unicast(addr: &std::net::Ipv6Addr) -> bool {
            !addr.is_multicast()
        }
        // Copied from the unstable method `std::net::Ipv6Addr::is_unicast_link_local`.
        fn is_unicast_link_local(addr: &std::net::Ipv6Addr) -> bool {
            (addr.segments()[0] & 0xffc0) == 0xfe80
        }
        // Copied from the unstable method `std::net::Ipv6Addr::is_unique_local`.
        fn is_unique_local(addr: &std::net::Ipv6Addr) -> bool {
            (addr.segments()[0] & 0xfe00) == 0xfc00
        }
        // Copied from the unstable method `std::net::Ipv6Addr::is_documentation`.
        fn is_documentation(addr: &std::net::Ipv6Addr) -> bool {
            (addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8)
        }

        // Copied from the unstable method `std::net::Ipv6Addr::is_unicast_global`.
        fn is_unicast_global(addr: &std::net::Ipv6Addr) -> bool {
            is_unicast(addr)
                && !addr.is_loopback()
                && !is_unicast_link_local(addr)
                && !is_unique_local(addr)
                && !addr.is_unspecified()
                && !is_documentation(addr)
        }

        // Variation of unstable method [`std::net::Ipv6Addr::multicast_scope`] that instead of the
        // `Ipv6MulticastScope` just returns if the scope is global or not.
        // Equivalent to `Ipv6Addr::multicast_scope(..).map(|scope| matches!(scope,
        // Ipv6MulticastScope::Global))`.
        fn is_multicast_scope_global(addr: &std::net::Ipv6Addr) -> Option<bool> {
            match addr.segments()[0] & 0x000f {
                14 => Some(true),         // Global multicast scope.
                1..=5 | 8 => Some(false), // Local multicast scope.
                _ => None,                // Unknown multicast scope.
            }
        }

        match is_multicast_scope_global(self) {
            Some(true) => true,
            None => is_unicast_global(self),
            _ => false,
        }
    }
}

// QUILIBRIUM: tests of the local patches (see PATCHES.md).
#[cfg(test)]
mod tests {
    use libp2p_core::transport::ListenerId;
    use libp2p_swarm::behaviour::NewListenAddr;

    use super::*;

    fn junk(n: u16) -> Multiaddr {
        format!("/ip4/203.0.113.7/tcp/{}", 40_000 + n)
            .parse()
            .unwrap()
    }

    #[test]
    fn candidates_are_bounded_most_recent_first() {
        let mut behaviour = Behaviour::new(PeerId::random(), Config::default());
        for n in 0..40 {
            behaviour.probe_address(junk(n));
        }
        let candidates = &behaviour.other_candidates;
        assert_eq!(candidates.len(), MAX_CANDIDATES);
        assert_eq!(candidates.front(), Some(&junk(39)));
        assert_eq!(candidates.back(), Some(&junk(40 - MAX_CANDIDATES as u16)));
        // A repeated observation moves to the front instead of adding a copy.
        behaviour.probe_address(junk(30));
        let candidates = &behaviour.other_candidates;
        assert_eq!(candidates.len(), MAX_CANDIDATES);
        assert_eq!(candidates.front(), Some(&junk(30)));
        assert_eq!(candidates.iter().filter(|a| **a == junk(30)).count(), 1);
    }

    /// After many ephemeral-port observations, a probe still offers the
    /// listen port first, within the limits, and throttles its server.
    #[test]
    fn a_probe_offers_the_listen_port_first() {
        let config = Config {
            boot_delay: Duration::ZERO,
            ..Config::default()
        };
        let mut behaviour = Behaviour::new(PeerId::random(), config);
        let listen: Multiaddr = "/ip4/10.0.0.2/tcp/9336".parse().unwrap();
        behaviour.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
            listener_id: ListenerId::next(),
            addr: &listen,
        }));
        for n in 0..40 {
            behaviour.probe_address(junk(n));
        }
        let server = PeerId::random();
        behaviour.add_server(server, None);
        assert_eq!(behaviour.eligible_servers(), 1);
        assert!(behaviour.last_probe_addresses().is_empty());

        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut probed = None;
        for _ in 0..500 {
            match behaviour.poll(&mut cx) {
                Poll::Ready(ToSwarm::GenerateEvent(Event::OutboundProbe(
                    OutboundProbeEvent::Request { peer, .. },
                ))) => {
                    probed = Some(peer);
                    break;
                }
                Poll::Ready(_) => {}
                Poll::Pending => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        assert_eq!(probed, Some(server));
        let sent = behaviour.last_probe_addresses();
        assert_eq!(sent.first(), Some(&listen));
        assert_eq!(sent.len(), as_client::MAX_PROBE_ADDRESSES);
        assert_eq!(sent[1], junk(39));
        assert_eq!(behaviour.eligible_servers(), 0);
    }

    /// A behaviour listening on `/ip4/10.0.0.2/tcp/8336`, seen by a peer at
    /// `/ip4/198.51.100.4/tcp/40001`, that sent one probe; its server and
    /// the probe's request.
    fn probed(local: PeerId) -> (Behaviour, PeerId, OutboundRequestId) {
        let config = Config {
            boot_delay: Duration::ZERO,
            ..Config::default()
        };
        let mut behaviour = Behaviour::new(local, config);
        let listen: Multiaddr = "/ip4/10.0.0.2/tcp/8336".parse().unwrap();
        behaviour.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
            listener_id: ListenerId::next(),
            addr: &listen,
        }));
        behaviour.probe_address("/ip4/198.51.100.4/tcp/40001".parse().unwrap());
        let server = PeerId::random();
        behaviour.add_server(server, None);
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..500 {
            match behaviour.poll(&mut cx) {
                Poll::Ready(ToSwarm::GenerateEvent(Event::OutboundProbe(
                    OutboundProbeEvent::Request { peer, .. },
                ))) => {
                    assert_eq!(peer, server);
                    let request = *behaviour.ongoing_outbound.keys().next().unwrap();
                    return (behaviour, server, request);
                }
                Poll::Ready(_) => {}
                Poll::Pending => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        panic!("no probe sent");
    }

    /// `server` answers `request` that it reached us at `address`.
    fn answer(
        behaviour: &mut Behaviour,
        server: PeerId,
        request_id: OutboundRequestId,
        address: Multiaddr,
    ) -> VecDeque<Action> {
        behaviour
            .as_client()
            .handle_event(request_response::Event::Message {
                peer: server,
                connection_id: ConnectionId::new_unchecked(1),
                message: request_response::Message::Response {
                    request_id,
                    response: DialResponse {
                        result: Ok(address),
                        status_text: None,
                    },
                },
            })
    }

    /// Whether `actions` report that the probe reached this node.
    fn reached(actions: &VecDeque<Action>) -> bool {
        actions.iter().any(|a| {
            matches!(
                a,
                ToSwarm::GenerateEvent(Event::OutboundProbe(OutboundProbeEvent::Response { .. }))
            )
        })
    }

    /// QUILIBRIUM: a server's answer confirms an address only when it is
    /// one the probe offered: a plain TCP or QUIC address on a probed port,
    /// at an IP this node is known at, with no other peer's id. An external
    /// candidate's IP is known only once a peer other than the server
    /// observed this node there, since identify lets any peer plant a
    /// candidate. Upstream confirmed whatever address the server named, so
    /// one server could set this node's external address, and with it where
    /// peers dial it.
    #[test]
    fn a_dial_back_answer_confirms_only_a_probed_address() {
        let me = PeerId::random();
        let other = PeerId::random();
        for (address, why) in [
            ("/ip4/10.0.0.2/tcp/9999".to_string(), "port not probed"),
            ("/ip4/192.0.2.66/tcp/8336".to_string(), "IP never seen"),
            (
                "/ip4/10.0.0.2/udp/8336/quic-v1".to_string(),
                "transport not probed",
            ),
            (
                "/ip4/10.0.0.2/ip4/127.0.0.1/tcp/8336".to_string(),
                "stacked IP",
            ),
            ("/ip4/10.0.0.2/tcp/8336/ws".to_string(), "protocol on top"),
            (
                format!("/ip4/10.0.0.2/tcp/8336/p2p/{other}"),
                "another peer",
            ),
            (
                format!("/ip4/198.51.100.4/tcp/40001/p2p/{me}"),
                "candidate no other peer observed",
            ),
        ] {
            let (mut behaviour, server, request) = probed(me);
            let actions = answer(&mut behaviour, server, request, address.parse().unwrap());
            println!("REACH autonat dial-back answer handled");
            assert!(
                !actions
                    .iter()
                    .any(|a| matches!(a, ToSwarm::ExternalAddrConfirmed(_))),
                "unprobed address confirmed ({why}): {address}"
            );
            assert!(
                !reached(&actions),
                "unprobed address reported reached ({why}): {address}"
            );
            assert_eq!(behaviour.nat_status(), NatStatus::Unknown, "{why}");
        }

        // A listen address on the probed port is reached.
        let (mut behaviour, server, request) = probed(me);
        let reached_at: Multiaddr = format!("/ip4/10.0.0.2/tcp/8336/p2p/{me}").parse().unwrap();
        let actions = answer(&mut behaviour, server, request, reached_at.clone());
        assert!(reached(&actions), "probed address refused: {reached_at}");
        assert_eq!(behaviour.nat_status(), NatStatus::Public(reached_at));
    }

    /// QUILIBRIUM: one server's answer, even on an address the probe
    /// offered, adds no external address to the swarm. The swarm announces
    /// its external addresses through identify and peers add them to
    /// Kademlia, so the node adds one only once servers on two IPs confirm
    /// it (`quil-p2p`'s external address tracker). Upstream confirmed the
    /// address of every answer.
    #[test]
    fn one_servers_answer_sets_no_external_address() {
        let me = PeerId::random();
        let (mut behaviour, server, request) = probed(me);
        let reached_at: Multiaddr = format!("/ip4/10.0.0.2/tcp/8336/p2p/{me}").parse().unwrap();
        let actions = answer(&mut behaviour, server, request, reached_at.clone());
        println!("REACH autonat dial-back answer handled");
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, ToSwarm::ExternalAddrConfirmed(_))),
            "one server set an external address: {reached_at}"
        );
        assert!(reached(&actions), "probed address refused: {reached_at}");
        assert_eq!(behaviour.nat_status(), NatStatus::Public(reached_at));
    }

    /// The remote IP of the `n`-th observer host in these tests, each in
    /// its own IPv4 /24.
    fn host(n: u16) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(
            198,
            18 + (n >> 8) as u8,
            n as u8,
            1,
        ))
    }

    /// QUILIBRIUM: an answer at an IP no listen address has counts once a
    /// peer other than the answering server observed this node there; the
    /// server's own observation does not, nor does a later one of another
    /// peer that replaced it. Observations are kept one per peer and per
    /// observer IP group, for the most recent ones.
    #[test]
    fn a_candidate_ip_counts_only_when_another_peer_observed_it() {
        let me = PeerId::random();
        let at: Multiaddr = format!("/ip4/198.51.100.4/tcp/8336/p2p/{me}")
            .parse()
            .unwrap();
        let observed: Multiaddr = "/ip4/198.51.100.4/tcp/51234".parse().unwrap();
        let elsewhere: Multiaddr = "/ip4/192.0.2.9/tcp/51234".parse().unwrap();

        let (mut behaviour, server, request) = probed(me);
        behaviour.note_observed_address(server, host(1), &observed);
        let actions = answer(&mut behaviour, server, request, at.clone());
        println!("REACH autonat dial-back answer handled");
        assert!(
            !reached(&actions),
            "IP only the server observed confirmed: {at}"
        );

        let (mut behaviour, server, request) = probed(me);
        let witness = PeerId::random();
        behaviour.note_observed_address(witness, host(2), &observed);
        behaviour.note_observed_address(witness, host(2), &elsewhere);
        let actions = answer(&mut behaviour, server, request, at.clone());
        assert!(
            !reached(&actions),
            "IP a peer no longer observes confirmed: {at}"
        );

        let (mut behaviour, server, request) = probed(me);
        behaviour.note_observed_address(server, host(1), &observed);
        behaviour.note_observed_address(PeerId::random(), host(2), &observed);
        let actions = answer(&mut behaviour, server, request, at.clone());
        assert!(reached(&actions), "IP another peer observed refused: {at}");
        assert_eq!(behaviour.nat_status(), NatStatus::Public(at));

        for n in 0..MAX_OBSERVERS as u16 + 10 {
            behaviour.note_observed_address(PeerId::random(), host(100 + n), &elsewhere);
        }
        assert_eq!(behaviour.observers.len(), MAX_OBSERVERS);
    }

    /// QUILIBRIUM: one host keeps one observation, whatever its peer IDs.
    /// Identify reports a peer's observation at every push, so one host
    /// with more peer IDs than the list holds, pushing again and again,
    /// evicted every other host's observation while the list was kept per
    /// peer; a NAT'd node's answers at its public IP then all failed as
    /// unprobed, and it got no first address. An IPv6 host counts by its
    /// /48.
    #[test]
    fn sybil_observers_on_one_host_keep_one_observation() {
        let me = PeerId::random();
        let at: Multiaddr = format!("/ip4/198.51.100.4/tcp/8336/p2p/{me}")
            .parse()
            .unwrap();
        let observed: Multiaddr = "/ip4/198.51.100.4/tcp/51234".parse().unwrap();
        let elsewhere: Multiaddr = "/ip4/192.0.2.9/tcp/51234".parse().unwrap();
        let (mut behaviour, server, request) = probed(me);
        behaviour.note_observed_address(PeerId::random(), host(1), &observed);
        for n in 0..=MAX_OBSERVERS as u16 {
            behaviour.note_observed_address(PeerId::random(), host(2), &elsewhere);
            let site: IpAddr = format!("2001:db8:1:{n:x}::1").parse().unwrap();
            behaviour.note_observed_address(PeerId::random(), site, &elsewhere);
        }
        println!("REACH autonat sybil observations noted");
        assert_eq!(
            behaviour.observers.len(),
            3,
            "sybil observers on one host took {} entries",
            behaviour.observers.len()
        );
        let actions = answer(&mut behaviour, server, request, at.clone());
        assert!(
            reached(&actions),
            "sybil observers on one host evicted an honest observation: {at}"
        );
    }

    /// QUILIBRIUM: one IPv4 /24 keeps one observation, as a server admits
    /// dial-backs by it. Kept by IPv4 address, the 64 addresses of one
    /// rented /26, each pushing identify with its own peer ID, filled the
    /// list and evicted every other observation, so a NAT'd node's answers
    /// at its public IP all failed as unprobed.
    #[test]
    fn observers_in_one_ipv4_24_keep_one_observation() {
        let me = PeerId::random();
        let at: Multiaddr = format!("/ip4/198.51.100.4/tcp/8336/p2p/{me}")
            .parse()
            .unwrap();
        let observed: Multiaddr = "/ip4/198.51.100.4/tcp/51234".parse().unwrap();
        let elsewhere: Multiaddr = "/ip4/192.0.2.9/tcp/51234".parse().unwrap();
        let (mut behaviour, server, request) = probed(me);
        behaviour.note_observed_address(PeerId::random(), host(1), &observed);
        for n in 64..128 {
            let sybil = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, n));
            behaviour.note_observed_address(PeerId::random(), sybil, &elsewhere);
        }
        println!("REACH autonat sybil observations noted");
        assert_eq!(
            behaviour.observers.len(),
            2,
            "sybil observers in one IPv4 /26 took {} entries",
            behaviour.observers.len()
        );
        let actions = answer(&mut behaviour, server, request, at.clone());
        assert!(
            reached(&actions),
            "sybil observers in one IPv4 /26 evicted an honest observation: {at}"
        );
    }

    /// QUILIBRIUM: `probe_now` sends the next probe at once, to a server
    /// other than the one just asked, instead of a retry interval (90 s)
    /// later. A first address needs servers on two IPs, so without it the
    /// first address came with the second scheduled probe, about 105 s
    /// after start.
    #[test]
    fn probe_now_asks_another_server_at_once() {
        let me = PeerId::random();
        let (mut behaviour, first, request) = probed(me);
        let second = PeerId::random();
        behaviour.add_server(second, None);
        let reached_at: Multiaddr = format!("/ip4/10.0.0.2/tcp/8336/p2p/{me}").parse().unwrap();
        let actions = answer(&mut behaviour, first, request, reached_at);
        assert!(reached(&actions));

        behaviour.probe_now();
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut asked = None;
        for _ in 0..500 {
            match behaviour.poll(&mut cx) {
                Poll::Ready(ToSwarm::GenerateEvent(Event::OutboundProbe(
                    OutboundProbeEvent::Request { peer, .. },
                ))) => {
                    asked = Some(peer);
                    break;
                }
                Poll::Ready(_) => {}
                Poll::Pending => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        println!("REACH autonat probe_now polled");
        assert_eq!(asked, Some(second), "no probe right after probe_now");
    }
}
