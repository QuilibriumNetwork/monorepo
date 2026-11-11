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
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU8,
};

use libp2p_core::{multiaddr::Protocol, transport::TransportError, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_request_response::{
    self as request_response, InboundFailure, InboundRequestId, ResponseChannel,
};
use libp2p_swarm::{
    dial_opts::{DialOpts, PeerCondition},
    ConnectionId, DialError, ToSwarm,
};
use web_time::Instant;

use super::{
    Action, AutoNatCodec, Config, DialRequest, DialResponse, Event, HandleInnerEvent, ProbeId,
    ResponseError,
};

/// Inbound probe failed.
#[derive(Debug)]
pub enum InboundProbeError {
    /// Receiving the dial-back request or sending a response failed.
    InboundRequest(InboundFailure),
    /// We refused or failed to dial the client.
    Response(ResponseError),
}

#[derive(Debug)]
pub enum InboundProbeEvent {
    /// A dial-back request was received from a remote peer.
    Request {
        probe_id: ProbeId,
        /// Peer that sent the request.
        peer: PeerId,
        /// The addresses that will be attempted to dial.
        addresses: Vec<Multiaddr>,
    },
    /// A dial request to the remote was successful.
    Response {
        probe_id: ProbeId,
        /// Peer to which the response is sent.
        peer: PeerId,
        address: Multiaddr,
    },
    /// The inbound request failed, was rejected, or none of the remote's
    /// addresses could be dialed.
    Error {
        probe_id: ProbeId,
        /// Peer that sent the dial-back request.
        peer: PeerId,
        error: InboundProbeError,
    },
}

/// View over [`super::Behaviour`] in a server role.
pub(crate) struct AsServer<'a> {
    pub(crate) inner: &'a mut request_response::Behaviour<AutoNatCodec>,
    pub(crate) config: &'a Config,
    pub(crate) connected: &'a HashMap<PeerId, HashMap<ConnectionId, Option<Multiaddr>>>,
    pub(crate) probe_id: &'a mut ProbeId,
    pub(crate) throttled_clients: &'a mut Vec<(PeerId, Instant)>,
    // QUILIBRIUM: with the connection id of the dial-back (see
    // `dial_back_failure`).
    pub(crate) ongoing_inbound: &'a mut OngoingInbounds,
    // QUILIBRIUM: outcomes for the operator summary.
    pub(crate) stats: &'a mut ServerStats,
}

/// QUILIBRIUM: a dial-back this server runs: `dial` is its connection id,
/// `channel` the request's, `None` once the request failed (it timed out,
/// or its stream closed) while the dial goes on. It stays until the dial
/// ends, so a client cannot start a second dial-back meanwhile, and it
/// counts against the dial-backs in progress (see [`admit_dial_back`]).
/// `ip` is the client's IP (see [`client_ip`]), which every address of the
/// dial-back starts with: another client there cannot start one either,
/// nor more than [`DIAL_BACKS_PER_GROUP`] run in its IP group. `started`
/// is when it started (see [`take_stale_dial_backs`]).
pub(crate) struct OngoingInbound<R, C> {
    pub(crate) probe_id: ProbeId,
    pub(crate) request_id: R,
    pub(crate) addrs: Vec<Multiaddr>,
    pub(crate) dial: ConnectionId,
    pub(crate) ip: Option<IpAddr>,
    pub(crate) started: Instant,
    pub(crate) channel: Option<C>,
}

/// QUILIBRIUM: the first IP in `addr`, the one a dial-back is rebuilt at
/// (see `filter_valid_addrs`): the client's IP, by which its dial-back is
/// admitted (see [`admit_dial_back`]).
pub(crate) fn client_ip(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// QUILIBRIUM: the IP group of `ip`, by which dial-backs are admitted (see
/// [`admit_dial_back`]) and a client keeps observations of its IP (see
/// `as_client::observer_group`): the /24 of an IPv4 address, or the /48 of
/// an IPv6 one. A /48 is a usual site allocation, and a tunnel broker
/// hands one out for free; grouping by /64 let its holder take one
/// dial-back slot for each of its /64s. By IPv4 address, sixteen addresses
/// of one rented /28 held every slot of every server. The node's AutoNAT
/// server list and address tracker count an IPv4 address.
pub(crate) fn ip_group(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & !0xff)),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !((1u128 << 80) - 1))),
    }
}

/// QUILIBRIUM: how many dial-backs run at once in one IP group (see
/// [`ip_group`]), each at another IP. With one, a client in another
/// node's /24, keeping a dial-back to an address that never answers in
/// progress at every server, had that node's every probe refused, and it
/// got no address; that now takes two addresses in its /24. Clients in a
/// group with two running get `DialRefused`, which leaves their status
/// unchanged.
pub(crate) const DIAL_BACKS_PER_GROUP: usize = 2;

/// QUILIBRIUM: the requests being served, by client.
pub(crate) type OngoingInbounds =
    HashMap<PeerId, OngoingInbound<InboundRequestId, ResponseChannel<DialResponse>>>;

/// QUILIBRIUM: what this server did with dial-back requests since the last
/// [`super::Behaviour::take_server_stats`], for an operator summary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerStats {
    /// Dial-backs that reached the client.
    pub served: u32,
    /// Dial-backs that reached none of the client's addresses, or another
    /// peer (`DialError`).
    pub failed: u32,
    /// Requests refused, and dial-backs this server denied or gave up
    /// (`DialRefused`, `BadRequest`), by reason.
    pub refused: BTreeMap<&'static str, u32>,
    /// Requests whose exchange failed while their dial-back was pending.
    pub request_failures: u32,
    /// The clients behind `served`.
    pub served_clients: BTreeSet<PeerId>,
    /// The clients behind `failed`, with their failures.
    pub failed_clients: BTreeMap<PeerId, u32>,
    /// `failed` by the first address the dial-back tried (transport and
    /// port class, see `address_class`).
    pub failed_by_address: BTreeMap<&'static str, u32>,
    /// `failed` by why the dial-back failed (see `dial_error_class`).
    pub failed_by_error: BTreeMap<&'static str, u32>,
}

impl ServerStats {
    /// Whether nothing happened.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The refusals by reason, most frequent first (`denied=3
    /// throttled=1`), or `none`.
    pub fn refused_by_reason(&self) -> String {
        by_count(self.refused.iter().map(|(r, n)| (r.to_string(), *n)))
    }

    /// The failures by the first address tried (`tcp:default=3
    /// quic:ephemeral=1`), or `none`.
    pub fn failed_by_address(&self) -> String {
        by_count(
            self.failed_by_address
                .iter()
                .map(|(c, n)| (c.to_string(), *n)),
        )
    }

    /// The failures by why the dial-back failed (`timeout=3 refused=1`), or
    /// `none`.
    pub fn failed_by_error(&self) -> String {
        by_count(
            self.failed_by_error
                .iter()
                .map(|(c, n)| (c.to_string(), *n)),
        )
    }

    /// The `limit` clients with the most failures, by the last six
    /// characters of their peer ID (`…a1b2c3=4`), or `none`.
    pub fn top_failed_clients(&self, limit: usize) -> String {
        let tail = |peer: &PeerId| {
            let id = peer.to_base58();
            format!("…{}", &id[id.len().saturating_sub(6)..])
        };
        let mut counts: Vec<(String, u32)> = self
            .failed_clients
            .iter()
            .map(|(p, n)| (tail(p), *n))
            .collect();
        counts.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        counts.truncate(limit);
        by_count(counts.into_iter())
    }

    fn refuse(&mut self, reason: &'static str) {
        *self.refused.entry(reason).or_default() += 1;
    }

    fn serve(&mut self, client: PeerId) {
        self.served += 1;
        self.served_clients.insert(client);
    }

    fn fail(&mut self, client: PeerId, addrs: &[Multiaddr], error: &DialError) {
        self.failed += 1;
        *self.failed_clients.entry(client).or_default() += 1;
        let address = addrs.first().map_or("none", address_class);
        *self.failed_by_address.entry(address).or_default() += 1;
        *self
            .failed_by_error
            .entry(dial_error_class(error))
            .or_default() += 1;
    }
}

/// QUILIBRIUM: `name=count` pairs, most frequent first, or `none`.
fn by_count(counts: impl Iterator<Item = (String, u32)>) -> String {
    let mut counts: Vec<(String, u32)> = counts.collect();
    if counts.is_empty() {
        return "none".to_string();
    }
    counts.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    counts
        .iter()
        .map(|(r, n)| format!("{r}={n}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// QUILIBRIUM: the transport and port class of a dial-back address, for the
/// operator summary: `default` is the node's default port 8336, `worker`
/// the remote worker range 25000–25999, `ephemeral` a port from 32768 up
/// (an outbound connection's source port, which nothing listens on), and
/// `other` any other port, such as a configured listen port.
pub(crate) fn address_class(addr: &Multiaddr) -> &'static str {
    let (mut tcp, mut udp, mut quic) = (None, None, false);
    for protocol in addr.iter() {
        match protocol {
            Protocol::Tcp(port) => tcp = Some(port),
            Protocol::Udp(port) => udp = Some(port),
            Protocol::QuicV1 | Protocol::Quic => quic = true,
            _ => {}
        }
    }
    let (quic, port) = match (tcp, udp) {
        (Some(port), _) => (false, port),
        (None, Some(port)) if quic => (true, port),
        _ => return "other",
    };
    match (quic, port) {
        (false, 8336) => "tcp:default",
        (false, 25000..=25999) => "tcp:worker",
        (false, 32768..) => "tcp:ephemeral",
        (false, _) => "tcp:other",
        (true, 8336) => "quic:default",
        (true, 25000..=25999) => "quic:worker",
        (true, 32768..) => "quic:ephemeral",
        (true, _) => "quic:other",
    }
}

/// QUILIBRIUM: why a dial-back reached none of the client's addresses, from
/// the last address it tried: `refused` (nothing listens there, or a
/// firewall rejects), `timeout` (no answer: a firewall drops, or NAT),
/// `reset` (the connection broke during the handshake), `no_route`,
/// `wrong_peer` (another node answered), or `other` (e.g. a failed
/// handshake upgrade).
pub(crate) fn dial_error_class(error: &DialError) -> &'static str {
    use std::io::ErrorKind;
    let DialError::Transport(errors) = error else {
        return match error {
            DialError::WrongPeerId { .. } => "wrong_peer",
            _ => "other",
        };
    };
    let last = errors.iter().rev().find_map(|(_, error)| match error {
        TransportError::Other(error) => Some(error.kind()),
        TransportError::MultiaddrNotSupported(_) => None,
    });
    match last {
        Some(ErrorKind::ConnectionRefused) => "refused",
        Some(ErrorKind::TimedOut) => "timeout",
        Some(
            ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::UnexpectedEof
            | ErrorKind::BrokenPipe,
        ) => "reset",
        Some(ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable) => "no_route",
        _ => "other",
    }
}

/// QUILIBRIUM: dial `peer` back on `addrs`, one address at a time, and
/// record the request under the dial's connection id, with the client's
/// IP, which the addresses start with.
pub(crate) fn start_dial_back<R, C>(
    ongoing: &mut HashMap<PeerId, OngoingInbound<R, C>>,
    peer: PeerId,
    probe_id: ProbeId,
    request_id: R,
    addrs: Vec<Multiaddr>,
    channel: C,
) -> DialOpts {
    let opts = DialOpts::peer_id(peer)
        .condition(PeerCondition::Always)
        .override_dial_concurrency_factor(NonZeroU8::new(1).expect("1 > 0"))
        .addresses(addrs.clone())
        .allocate_new_port()
        .build();
    let dial = opts.connection_id();
    ongoing.insert(
        peer,
        OngoingInbound {
            probe_id,
            request_id,
            ip: addrs.first().and_then(client_ip),
            addrs,
            dial,
            started: Instant::now(),
            channel: Some(channel),
        },
    );
    opts
}

/// Whether a dial-back for `sender`, a client at `ip` (see [`client_ip`]),
/// may start beside the `ongoing` ones: one per client and one per IP, at
/// most [`DIAL_BACKS_PER_GROUP`] per IP group (see [`ip_group`]), at most
/// `budget` with their request open, and at most twice `budget` in all.
///
/// QUILIBRIUM: each dial-back holds an outbound dial slot of this node
/// until it connects or its last address times out; the budget keeps
/// clients from taking the slots its other dials need. A host can run
/// any number of peer IDs, so one per client alone let a few identities
/// on one host, asking for addresses that never answer, hold the whole
/// budget, and every other node's probes to this server failed. A
/// dial-back whose request failed (see [`request_failed`]) answers no
/// one, so it gives its place among the `budget` to another client at
/// once; it still holds its client, its IP and its place in its IP group,
/// and its dial, until the dial ends, and those count against the total.
pub(crate) fn admit_dial_back<R, C>(
    ongoing: &HashMap<PeerId, OngoingInbound<R, C>>,
    sender: PeerId,
    ip: Option<IpAddr>,
    budget: usize,
) -> Result<(), (String, ResponseError)> {
    if ongoing.contains_key(&sender) {
        let status_text = "dial-back already ongoing".to_string();
        return Err((status_text, ResponseError::DialRefused));
    }
    if ip.is_some() && ongoing.values().any(|o| o.ip == ip) {
        let status_text = "dial-back already ongoing at this IP".to_string();
        return Err((status_text, ResponseError::DialRefused));
    }
    let group = ip.map(ip_group);
    let in_group = ongoing
        .values()
        .filter(|o| group.is_some() && o.ip.map(ip_group) == group)
        .count();
    if in_group >= DIAL_BACKS_PER_GROUP {
        let status_text = "dial-backs already ongoing in this IP group".to_string();
        return Err((status_text, ResponseError::DialRefused));
    }
    let open = ongoing.values().filter(|o| o.channel.is_some()).count();
    if open >= budget {
        let status_text = "too many concurrent dial-backs".to_string();
        return Err((status_text, ResponseError::DialRefused));
    }
    if ongoing.len() >= budget.saturating_mul(2) {
        let status_text = "too many dial-backs still dialing".to_string();
        return Err((status_text, ResponseError::DialRefused));
    }
    Ok(())
}

/// QUILIBRIUM: take the dial-backs that started `max_age` or longer before
/// `now`. The swarm reports how every dial ends, which takes its entry
/// (see [`take_reached_dial_back`], [`take_failed_dial_back`]), and a dial
/// lasts at most its addresses times the connection timeout; an entry this
/// old means a report was missed, as a future libp2p version could, and
/// would otherwise hold its client, its IP group and its place for good.
pub(crate) fn take_stale_dial_backs<R, C>(
    ongoing: &mut HashMap<PeerId, OngoingInbound<R, C>>,
    now: Instant,
    max_age: std::time::Duration,
) -> Vec<(PeerId, OngoingInbound<R, C>)> {
    let stale: Vec<PeerId> = ongoing
        .iter()
        .filter(|(_, o)| now.saturating_duration_since(o.started) >= max_age)
        .map(|(peer, _)| *peer)
        .collect();
    stale
        .into_iter()
        .filter_map(|peer| ongoing.remove(&peer).map(|o| (peer, o)))
        .collect()
}

/// QUILIBRIUM: `peer`'s request `request_id` failed: no answer is owed any
/// more, but its dial-back goes on and holds its client and IP group until
/// the dial ends (see [`OngoingInbound`], [`admit_dial_back`]). Returns its
/// probe id when it was the request being served. Upstream dropped the
/// request here, so a client that let its requests time out could keep
/// any number of dials running.
pub(crate) fn request_failed<R: PartialEq, C>(
    ongoing: &mut HashMap<PeerId, OngoingInbound<R, C>>,
    peer: PeerId,
    request_id: &R,
) -> Option<ProbeId> {
    let ongoing = ongoing
        .get_mut(&peer)
        .filter(|o| o.request_id == *request_id && o.channel.is_some())?;
    ongoing.channel = None;
    Some(ongoing.probe_id)
}

/// QUILIBRIUM: take `peer`'s request when this node's outbound connection
/// `connected`, to `address`, is its dial-back reaching the client on one
/// of the requested addresses; leave it in place for any other connection.
///
/// Upstream took the request at any outbound connection to the client on
/// a requested address, so another behaviour's dial to the client there
/// answered the probe as reached and freed its place in the budget while
/// the dial-back itself was still running.
pub(crate) fn take_reached_dial_back<R, C>(
    ongoing: &mut HashMap<PeerId, OngoingInbound<R, C>>,
    peer: PeerId,
    connected: ConnectionId,
    address: &Multiaddr,
) -> Option<OngoingInbound<R, C>> {
    let request = ongoing.get(&peer)?;
    if request.dial != connected || !request.addrs.contains(address) {
        return None;
    }
    ongoing.remove(&peer)
}

/// QUILIBRIUM: take `peer`'s request when `error`, reported for the dial
/// `failed`, ends its dial-back, with the answer owed and its reason; leave
/// it in place when `failed` is another dial.
pub(crate) fn take_failed_dial_back<R, C>(
    ongoing: &mut HashMap<PeerId, OngoingInbound<R, C>>,
    peer: PeerId,
    failed: ConnectionId,
    error: &DialError,
) -> Option<(OngoingInbound<R, C>, ResponseError, &'static str)> {
    let (answer, reason) = dial_back_failure(ongoing.get(&peer)?.dial, failed, error)?;
    let request = ongoing.remove(&peer)?;
    Some((request, answer, reason))
}

/// QUILIBRIUM: the answer owed to a client whose dial-back `dial` is pending
/// when the swarm reports `error` for the dial `failed` to the same peer,
/// with the reason for the operator summary.
///
/// Upstream answered `DialError` to any failed dial to the client, and the
/// client counts `DialError` as evidence that it is unreachable. But another
/// behaviour's dial to the client can fail meanwhile, and the dial-back
/// itself can be refused by this node before or after it reaches the client:
/// the connection limits deny a third connection to a peer, a peer condition
/// or a pending-dial limit stops it, or this node has no transport for the
/// client's addresses. Reachable clients then saw most probes fail and
/// AutoNAT held them private. So a failure of another dial is none of the
/// probe's business (`None`), a dial this node refused, abandoned or could
/// not attempt answers `DialRefused`, which leaves the client's status
/// unchanged, and only a dial that reached none of the addresses, or reached
/// another peer, answers `DialError`.
pub(crate) fn dial_back_failure(
    dial: ConnectionId,
    failed: ConnectionId,
    error: &DialError,
) -> Option<(ResponseError, &'static str)> {
    if dial != failed {
        return None;
    }
    Some(match error {
        DialError::Transport(errors)
            if errors
                .iter()
                .all(|(_, e)| matches!(e, TransportError::MultiaddrNotSupported(_))) =>
        {
            (ResponseError::DialRefused, "unsupported_transport")
        }
        DialError::Transport(_) => (ResponseError::DialError, "unreachable"),
        DialError::WrongPeerId { .. } => (ResponseError::DialError, "wrong_peer"),
        DialError::Denied { .. } => (ResponseError::DialRefused, "denied"),
        DialError::DialPeerConditionFalse(_) => (ResponseError::DialRefused, "peer_condition"),
        DialError::Aborted => (ResponseError::DialRefused, "aborted"),
        DialError::LocalPeerId { .. } => (ResponseError::DialRefused, "local_peer"),
        DialError::NoAddresses => (ResponseError::DialRefused, "no_addresses"),
    })
}

/// QUILIBRIUM: the reason of a request refused before any dial, from its
/// status text (see `resolve_inbound_request`).
fn refusal_reason(status_text: &str) -> &'static str {
    match status_text {
        "peer id mismatch" => "bad_request",
        "dial-back already ongoing" => "already_ongoing",
        "dial-back already ongoing at this IP" => "same_ip",
        "dial-backs already ongoing in this IP group" => "same_group",
        "too many total dials" | "too many dials for peer" => "throttled",
        "too many concurrent dial-backs" => "busy",
        "too many dial-backs still dialing" => "busy_dialing",
        "sender disconnected before request resolved" => "not_connected",
        "refusing to dial peer with blocked observed address" => "no_observed_address",
        "no dialable addresses" => "no_dialable_address",
        _ => "other",
    }
}

impl HandleInnerEvent for AsServer<'_> {
    fn handle_event(
        &mut self,
        event: request_response::Event<DialRequest, DialResponse>,
    ) -> VecDeque<Action> {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request_id,
                        request,
                        channel,
                    },
                ..
            } => {
                // QUILIBRIUM: first drop dial-backs older than any dial
                // lasts (see `take_stale_dial_backs`).
                let mut actions = self.drop_stale_dial_backs(Instant::now());
                let probe_id = self.probe_id.next();
                if !self.connected.contains_key(&peer) {
                    tracing::debug!(
                        %peer,
                        "Reject inbound dial request from peer since it is not connected"
                    );
                    self.stats.refuse("not_connected");

                    actions.push_back(ToSwarm::GenerateEvent(Event::InboundProbe(
                        InboundProbeEvent::Error {
                            probe_id,
                            peer,
                            error: InboundProbeError::Response(ResponseError::DialRefused),
                        },
                    )));
                    return actions;
                }

                match self.resolve_inbound_request(peer, request) {
                    Ok(addrs) => {
                        tracing::debug!(
                            %peer,
                            "Inbound dial request from peer with dial-back addresses {:?}",
                            addrs
                        );

                        // QUILIBRIUM: remember the dial-back's connection id
                        // (see `dial_back_failure`).
                        let opts = start_dial_back(
                            &mut *self.ongoing_inbound,
                            peer,
                            probe_id,
                            request_id,
                            addrs.clone(),
                            channel,
                        );
                        self.throttled_clients.push((peer, Instant::now()));

                        actions.extend([
                            ToSwarm::GenerateEvent(Event::InboundProbe(
                                InboundProbeEvent::Request {
                                    probe_id,
                                    peer,
                                    addresses: addrs,
                                },
                            )),
                            ToSwarm::Dial { opts },
                        ]);
                        actions
                    }
                    Err((status_text, error)) => {
                        tracing::debug!(
                            %peer,
                            status=%status_text,
                            "Reject inbound dial request from peer"
                        );
                        self.stats.refuse(refusal_reason(&status_text));

                        let response = DialResponse {
                            result: Err(error.clone()),
                            status_text: Some(status_text),
                        };
                        let _ = self.inner.send_response(channel, response);

                        actions.push_back(ToSwarm::GenerateEvent(Event::InboundProbe(
                            InboundProbeEvent::Error {
                                probe_id,
                                peer,
                                error: InboundProbeError::Response(error),
                            },
                        )));
                        actions
                    }
                }
            }
            request_response::Event::InboundFailure {
                peer,
                error,
                request_id,
                ..
            } => {
                tracing::debug!(
                    %peer,
                    "Inbound Failure {} when on dial-back request from peer",
                    error
                );

                // QUILIBRIUM: the dial-back holds its client and IP group
                // until its dial ends (see `request_failed`).
                let probe_id = match request_failed(&mut *self.ongoing_inbound, peer, &request_id) {
                    Some(probe_id) => {
                        self.stats.request_failures += 1;
                        probe_id
                    }
                    None => self.probe_id.next(),
                };

                VecDeque::from([ToSwarm::GenerateEvent(Event::InboundProbe(
                    InboundProbeEvent::Error {
                        probe_id,
                        peer,
                        error: InboundProbeError::InboundRequest(error),
                    },
                ))])
            }
            _ => VecDeque::new(),
        }
    }
}

impl AsServer<'_> {
    /// QUILIBRIUM: drop the dial-backs older at `now` than
    /// [`Config::max_dial_back_age`] (see [`take_stale_dial_backs`]),
    /// answering a request still open with `DialRefused`.
    fn drop_stale_dial_backs(&mut self, now: Instant) -> VecDeque<Action> {
        let stale = take_stale_dial_backs(
            &mut *self.ongoing_inbound,
            now,
            self.config.max_dial_back_age,
        );
        let mut actions = VecDeque::new();
        for (peer, ongoing) in stale {
            tracing::warn!(
                %peer,
                age_secs = now.saturating_duration_since(ongoing.started).as_secs(),
                "AutoNAT dial-back dropped: the swarm reported no end of its dial; \
                 its client and IP group may ask again"
            );
            self.stats.refuse("stale");
            let Some(channel) = ongoing.channel else {
                continue;
            };
            let response = DialResponse {
                result: Err(ResponseError::DialRefused),
                status_text: Some("dial-back abandoned by this server".to_string()),
            };
            let _ = self.inner.send_response(channel, response);
            actions.push_back(ToSwarm::GenerateEvent(Event::InboundProbe(
                InboundProbeEvent::Error {
                    probe_id: ongoing.probe_id,
                    peer,
                    error: InboundProbeError::Response(ResponseError::DialRefused),
                },
            )));
        }
        actions
    }

    pub(crate) fn on_outbound_connection(
        &mut self,
        peer: &PeerId,
        connection_id: ConnectionId,
        address: &Multiaddr,
    ) -> Option<InboundProbeEvent> {
        // QUILIBRIUM: only the dial-back's own connection answers the probe
        // (see `take_reached_dial_back`).
        let OngoingInbound {
            probe_id, channel, ..
        } = take_reached_dial_back(&mut *self.ongoing_inbound, *peer, connection_id, address)?;

        tracing::debug!(
            %peer,
            %address,
            "Dial-back to peer succeeded"
        );

        // QUILIBRIUM: a request that failed meanwhile is owed nothing; it
        // was counted then.
        let channel = channel?;
        self.stats.serve(*peer);
        let response = DialResponse {
            result: Ok(address.clone()),
            status_text: None,
        };
        let _ = self.inner.send_response(channel, response);

        Some(InboundProbeEvent::Response {
            probe_id,
            peer: *peer,
            address: address.clone(),
        })
    }

    pub(crate) fn on_outbound_dial_error(
        &mut self,
        peer: Option<PeerId>,
        connection_id: ConnectionId,
        error: &DialError,
    ) -> Option<InboundProbeEvent> {
        let peer = peer?;
        // QUILIBRIUM: only the dial-back's own failure answers the probe,
        // and only a dial that failed to reach the client is a `DialError`
        // (see `dial_back_failure`).
        let (
            OngoingInbound {
                probe_id,
                channel,
                addrs,
                ..
            },
            response_error,
            reason,
        ) = take_failed_dial_back(&mut *self.ongoing_inbound, peer, connection_id, error)?;
        // QUILIBRIUM: a request that failed meanwhile is owed nothing; it
        // was counted then.
        let channel = channel?;
        match response_error {
            ResponseError::DialError => self.stats.fail(peer, &addrs, error),
            _ => self.stats.refuse(reason),
        }

        tracing::debug!(
            %peer,
            "Dial-back to peer failed with error {:?}",
            error
        );

        let status_text = match response_error {
            ResponseError::DialError => "dial failed",
            _ => "dial-back refused by this server",
        };
        let response = DialResponse {
            result: Err(response_error.clone()),
            status_text: Some(status_text.to_string()),
        };
        let _ = self.inner.send_response(channel, response);

        Some(InboundProbeEvent::Error {
            probe_id,
            peer,
            error: InboundProbeError::Response(response_error),
        })
    }

    // Validate the inbound request and collect the addresses to be dialed.
    fn resolve_inbound_request(
        &mut self,
        sender: PeerId,
        request: DialRequest,
    ) -> Result<Vec<Multiaddr>, (String, ResponseError)> {
        // Update list of throttled clients.
        let i = self.throttled_clients.partition_point(|(_, time)| {
            *time + self.config.throttle_clients_period < Instant::now()
        });
        self.throttled_clients.drain(..i);

        if request.peer_id != sender {
            let status_text = "peer id mismatch".to_string();
            return Err((status_text, ResponseError::BadRequest));
        }

        if self.throttled_clients.len() >= self.config.throttle_clients_global_max {
            let status_text = "too many total dials".to_string();
            return Err((status_text, ResponseError::DialRefused));
        }

        let throttled_for_client = self
            .throttled_clients
            .iter()
            .filter(|(p, _)| p == &sender)
            .count();

        if throttled_for_client >= self.config.throttle_clients_peer_max {
            let status_text = "too many dials for peer".to_string();
            return Err((status_text, ResponseError::DialRefused));
        }

        // Obtain an observed address from non-relayed connections.
        //
        // QUILIBRIUM (see PATCHES.md): upstream libp2p-autonat 0.15.0 uses
        // `.expect("Peer is connected.")` here, which panics under a real
        // race — an inbound dial-back request can be
        // dispatched on a now-closed connection (`ConnectionClosed` already
        // removed the sender from `self.connected`, but the protocol message
        // was already in flight). The panic kills the whole swarm task, after
        // which every `cmd_tx.send().await` returns "p2p command channel
        // closed" forever (master loses coverage until restart). Demote the
        // missing-from-connected case to a transient refusal so the swarm
        // keeps running; the client retries with a different server.
        let observed_addr = self
            .connected
            .get(&sender)
            .ok_or_else(|| {
                let status_text = "sender disconnected before request resolved".to_string();
                (status_text, ResponseError::DialRefused)
            })?
            .values()
            .find_map(|a| a.as_ref())
            .ok_or_else(|| {
                let status_text = "refusing to dial peer with blocked observed address".to_string();
                (status_text, ResponseError::DialRefused)
            })?;

        // QUILIBRIUM: one dial-back at a time per client and per IP, two per
        // IP group, within the budget (see `admit_dial_back`).
        admit_dial_back(
            self.ongoing_inbound,
            sender,
            client_ip(observed_addr),
            self.config.max_concurrent_dial_backs,
        )?;

        let mut addrs = Self::filter_valid_addrs(sender, request.addresses, observed_addr);
        addrs.truncate(self.config.max_peer_addresses);

        if addrs.is_empty() {
            let status_text = "no dialable addresses".to_string();
            return Err((status_text, ResponseError::DialRefused));
        }

        Ok(addrs)
    }

    // Filter dial addresses and replace demanded ip with the observed one.
    //
    // QUILIBRIUM: only plain TCP and QUIC addresses, rebuilt from the
    // observed IP (see `PlainAddr`). Upstream replaced only the first IP
    // of each address and dialed the rest as given, so a client could make
    // this server dial a second, stacked IP (its loopback or another host),
    // a name it resolves, or a protocol layered on top.
    fn filter_valid_addrs(
        peer: PeerId,
        demanded: Vec<Multiaddr>,
        observed_remote_at: &Multiaddr,
    ) -> Vec<Multiaddr> {
        let Some(observed_ip) = observed_remote_at
            .into_iter()
            .find(|p| matches!(p, Protocol::Ip4(_) | Protocol::Ip6(_)))
        else {
            return Vec::new();
        };

        let mut distinct = HashSet::new();
        demanded
            .iter()
            .filter_map(|addr| {
                let plain = PlainAddr::of(addr)?;
                if plain.peer.is_some_and(|p| p != peer) {
                    return None;
                }
                let addr = plain.at(observed_ip.clone()).with(Protocol::P2p(peer));
                // Only collect distinct addresses.
                distinct.insert(addr.clone()).then_some(addr)
            })
            .collect()
    }
}

/// QUILIBRIUM: a plain TCP or QUIC address,
/// `/ip{4,6}/<ip>/tcp/<port>[/p2p/<peer>]` or
/// `/ip{4,6}/<ip>/udp/<port>/quic-v1[/p2p/<peer>]`, with a port other than
/// zero: the only shapes a dial-back goes to, and the only ones a client
/// takes as reached.
pub(crate) struct PlainAddr<'a> {
    pub(crate) ip: Protocol<'a>,
    /// `Tcp(port)` or `Udp(port)`.
    port: Protocol<'a>,
    quic: bool,
    pub(crate) peer: Option<PeerId>,
}

impl<'a> PlainAddr<'a> {
    pub(crate) fn of(addr: &'a Multiaddr) -> Option<Self> {
        let mut protocols = addr.iter();
        let ip = protocols
            .next()
            .filter(|p| matches!(p, Protocol::Ip4(_) | Protocol::Ip6(_)))?;
        let (port, quic) = match protocols.next()? {
            port @ Protocol::Tcp(1..) => (port, false),
            port @ Protocol::Udp(1..) => match protocols.next()? {
                Protocol::QuicV1 => (port, true),
                _ => return None,
            },
            _ => return None,
        };
        let peer = match protocols.next() {
            None => None,
            Some(Protocol::P2p(peer)) => Some(peer),
            Some(_) => return None,
        };
        if protocols.next().is_some() {
            return None;
        }
        Some(Self {
            ip,
            port,
            quic,
            peer,
        })
    }

    /// The same transport and port at `ip`, without a peer id.
    pub(crate) fn at(&self, ip: Protocol<'_>) -> Multiaddr {
        let addr = Multiaddr::empty().with(ip).with(self.port.clone());
        if self.quic {
            addr.with(Protocol::QuicV1)
        } else {
            addr
        }
    }
}

#[cfg(test)]
mod test {
    use libp2p_swarm::ConnectionDenied;

    use super::*;

    /// QUILIBRIUM: a failure of another dial to the client is ignored, a
    /// dial-back this server refused, abandoned or could not attempt is
    /// `DialRefused`, and only one that reached none of the addresses, or
    /// another peer, is `DialError`.
    #[test]
    fn only_the_dial_backs_own_failure_to_reach_the_client_is_a_dial_error() {
        let dial = ConnectionId::new_unchecked(7);
        let other = ConnectionId::new_unchecked(8);
        let addr: Multiaddr = "/ip4/203.0.113.7/tcp/8336".parse().unwrap();
        let refused = || {
            TransportError::Other(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "refused",
            ))
        };
        let denied = || DialError::Denied {
            cause: ConnectionDenied::new(std::io::Error::other("connection limit")),
        };
        let unreached = || DialError::Transport(vec![(addr.clone(), refused())]);
        let unsupported = || TransportError::MultiaddrNotSupported(addr.clone());

        // Another dial to the client failed: the probe's dial-back goes on.
        assert_eq!(dial_back_failure(dial, other, &unreached()), None);
        assert_eq!(dial_back_failure(dial, other, &denied()), None);
        assert_eq!(
            dial_back_failure(
                dial,
                other,
                &DialError::DialPeerConditionFalse(PeerCondition::Disconnected)
            ),
            None
        );

        // This server refused, gave up or could not attempt its dial-back.
        for (error, reason) in [
            (denied(), "denied"),
            (
                DialError::DialPeerConditionFalse(PeerCondition::Always),
                "peer_condition",
            ),
            (DialError::Aborted, "aborted"),
            (DialError::NoAddresses, "no_addresses"),
            (
                DialError::LocalPeerId {
                    address: addr.clone(),
                },
                "local_peer",
            ),
            (
                DialError::Transport(vec![
                    (addr.clone(), unsupported()),
                    (addr.clone(), unsupported()),
                ]),
                "unsupported_transport",
            ),
        ] {
            assert_eq!(
                dial_back_failure(dial, dial, &error),
                Some((ResponseError::DialRefused, reason)),
                "{error:?}"
            );
        }

        // The dial-back reached none of the addresses, or another peer; one
        // supported address that failed is enough.
        assert_eq!(
            dial_back_failure(dial, dial, &unreached()),
            Some((ResponseError::DialError, "unreachable"))
        );
        let mixed = DialError::Transport(vec![
            (addr.clone(), unsupported()),
            (addr.clone(), refused()),
        ]);
        assert_eq!(
            dial_back_failure(dial, dial, &mixed),
            Some((ResponseError::DialError, "unreachable"))
        );
        let wrong_peer = DialError::WrongPeerId {
            obtained: PeerId::random(),
            address: addr.clone(),
        };
        assert_eq!(
            dial_back_failure(dial, dial, &wrong_peer),
            Some((ResponseError::DialError, "wrong_peer"))
        );
    }

    /// QUILIBRIUM: the request is recorded under the connection id of the
    /// dial it starts; another dial's failure leaves it in place, and the
    /// dial-back's own failure takes it with the answer owed.
    #[test]
    fn a_dial_back_is_answered_by_its_own_dial_only() {
        let mut ongoing: HashMap<PeerId, OngoingInbound<(), &str>> = HashMap::new();
        let peer = PeerId::random();
        let addr: Multiaddr = "/ip4/203.0.113.7/tcp/8336".parse().unwrap();
        let opts = start_dial_back(
            &mut ongoing,
            peer,
            ProbeId(3),
            (),
            vec![addr.clone()],
            "channel",
        );
        let dial = opts.connection_id();
        assert_eq!(ongoing[&peer].dial, dial);
        assert_eq!(ongoing[&peer].addrs, vec![addr.clone()]);

        let other = ConnectionId::new_unchecked(usize::MAX);
        assert_ne!(other, dial);
        let unreached = DialError::Transport(vec![(
            addr.clone(),
            TransportError::Other(std::io::Error::other("refused")),
        )]);
        assert!(take_failed_dial_back(&mut ongoing, peer, other, &unreached).is_none());
        assert!(take_failed_dial_back(&mut ongoing, PeerId::random(), dial, &unreached).is_none());
        assert_eq!(ongoing[&peer].dial, dial);

        let denied = DialError::Denied {
            cause: ConnectionDenied::new(std::io::Error::other("limit")),
        };
        let (request, answer, reason) =
            take_failed_dial_back(&mut ongoing, peer, dial, &denied).unwrap();
        assert_eq!(
            (request.probe_id, request.channel),
            (ProbeId(3), Some("channel"))
        );
        assert_eq!((answer, reason), (ResponseError::DialRefused, "denied"));
        assert!(ongoing.is_empty());
    }

    /// QUILIBRIUM: the operator summary lists refusals by reason, most
    /// frequent first.
    #[test]
    fn server_stats_list_refusals_by_reason() {
        let mut stats = ServerStats::default();
        assert!(stats.is_empty());
        assert_eq!(stats.refused_by_reason(), "none");
        stats.refuse("throttled");
        stats.refuse("denied");
        stats.refuse("denied");
        stats.served += 1;
        assert!(!stats.is_empty());
        assert_eq!(stats.refused_by_reason(), "denied=2 throttled=1");
        assert_eq!(refusal_reason("too many dials for peer"), "throttled");
        assert_eq!(
            refusal_reason("no dialable addresses"),
            "no_dialable_address"
        );
    }

    /// QUILIBRIUM: a failed dial-back is counted by client, by the class of
    /// the first address tried and by why it failed; the summary names the
    /// clients that failed most, by peer ID tail.
    #[test]
    fn server_stats_describe_failed_dial_backs() {
        let io = |kind| TransportError::Other(std::io::Error::new(kind, "dial"));
        let unreached =
            |addr: &Multiaddr, kind| DialError::Transport(vec![(addr.clone(), io(kind))]);
        let default: Multiaddr = "/ip4/203.0.113.7/tcp/8336".parse().unwrap();
        let ephemeral: Multiaddr = "/ip4/203.0.113.8/tcp/51234".parse().unwrap();
        let quic: Multiaddr = "/ip4/203.0.113.9/udp/8336/quic-v1".parse().unwrap();
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());

        let mut stats = ServerStats::default();
        assert_eq!(stats.failed_by_address(), "none");
        assert_eq!(stats.failed_by_error(), "none");
        assert_eq!(stats.top_failed_clients(3), "none");
        stats.fail(
            a,
            &[ephemeral.clone(), default.clone()],
            &unreached(&default, std::io::ErrorKind::TimedOut),
        );
        stats.fail(
            a,
            &[ephemeral.clone()],
            &unreached(&ephemeral, std::io::ErrorKind::TimedOut),
        );
        stats.fail(
            b,
            &[quic.clone()],
            &unreached(&quic, std::io::ErrorKind::ConnectionRefused),
        );
        stats.serve(c);
        stats.serve(c);

        assert_eq!((stats.failed, stats.served), (3, 2));
        assert_eq!(
            (stats.failed_clients.len(), stats.served_clients.len()),
            (2, 1)
        );
        assert_eq!(stats.failed_by_address(), "tcp:ephemeral=2 quic:default=1");
        assert_eq!(stats.failed_by_error(), "timeout=2 refused=1");
        let a_id = a.to_base58();
        assert_eq!(
            stats.top_failed_clients(1),
            format!("…{}=2", &a_id[a_id.len() - 6..])
        );
        assert_eq!(stats.top_failed_clients(3).split(' ').count(), 2);
    }

    /// QUILIBRIUM: addresses are classed by transport and port, dial errors
    /// by the last supported address tried.
    #[test]
    fn dial_backs_are_classed_by_address_and_error() {
        for (addr, class) in [
            ("/ip4/203.0.113.7/tcp/8336", "tcp:default"),
            ("/ip4/203.0.113.7/tcp/25003", "tcp:worker"),
            ("/ip4/203.0.113.7/tcp/40000", "tcp:ephemeral"),
            (
                "/ip4/203.0.113.7/tcp/9336/p2p/QmP9NNzAzRjCL8gdQBkKHwyBCWJGVb3jPrQzTveYdU24kH",
                "tcp:other",
            ),
            ("/ip4/203.0.113.7/udp/8336/quic-v1", "quic:default"),
            ("/ip4/203.0.113.7/udp/61000/quic-v1", "quic:ephemeral"),
            ("/ip4/203.0.113.7/udp/8336", "other"),
        ] {
            assert_eq!(address_class(&addr.parse().unwrap()), class, "{addr}");
        }
        let addr: Multiaddr = "/ip4/203.0.113.7/tcp/8336".parse().unwrap();
        let io = |kind| {
            (
                addr.clone(),
                TransportError::Other(std::io::Error::new(kind, "dial")),
            )
        };
        let unsupported = || {
            (
                addr.clone(),
                TransportError::MultiaddrNotSupported(addr.clone()),
            )
        };
        use std::io::ErrorKind::*;
        for (errors, class) in [
            (vec![io(ConnectionRefused)], "refused"),
            (
                vec![io(ConnectionRefused), io(TimedOut), unsupported()],
                "timeout",
            ),
            (vec![io(ConnectionReset)], "reset"),
            (vec![io(UnexpectedEof)], "reset"),
            (vec![io(HostUnreachable)], "no_route"),
            (vec![io(Other)], "other"),
            (vec![unsupported()], "other"),
        ] {
            let shown = format!("{errors:?}");
            assert_eq!(
                dial_error_class(&DialError::Transport(errors)),
                class,
                "{shown}"
            );
        }
        let wrong_peer = DialError::WrongPeerId {
            obtained: PeerId::random(),
            address: addr.clone(),
        };
        assert_eq!(dial_error_class(&wrong_peer), "wrong_peer");
    }

    fn random_ip<'a>() -> Protocol<'a> {
        Protocol::Ip4(Ipv4Addr::new(
            rand::random(),
            rand::random(),
            rand::random(),
            rand::random(),
        ))
    }
    fn random_port<'a>() -> Protocol<'a> {
        Protocol::Tcp(rand::random::<u16>().max(1))
    }

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    /// QUILIBRIUM: a server dials back only plain TCP and QUIC addresses,
    /// rebuilt from the IP it observes for the client: the client names
    /// the transport and port, nothing else. Upstream replaced only the
    /// first IP of each address and dialed the rest as given, so a client
    /// could make servers dial a second, stacked IP (their own loopback or
    /// another host), a name they resolve, or a protocol layered on top.
    #[test]
    fn a_dial_back_goes_only_to_plain_tcp_or_quic_at_the_observed_ip() {
        let peer = PeerId::random();
        let observed = ma("/ip4/198.51.100.4/tcp/50123");
        let demanded = vec![
            ma("/ip4/10.0.0.2/tcp/8336"),
            ma(&format!("/ip4/10.0.0.2/udp/8336/quic-v1/p2p/{peer}")),
            ma("/ip4/203.0.113.9/ip4/127.0.0.1/tcp/8337"),
            ma("/ip4/203.0.113.9/ip6/::1/tcp/8338"),
            ma("/ip4/203.0.113.9/dns4/localhost/tcp/8339"),
            ma("/ip4/203.0.113.9/tcp/8340/ws"),
            ma("/ip4/203.0.113.9/udp/8341/quic-v1/webtransport"),
            ma("/ip4/203.0.113.9/udp/8342"),
            ma("/ip4/203.0.113.9/udp/8343/quic"),
            ma("/ip4/203.0.113.9/tcp/0"),
            ma(&format!("/ip4/203.0.113.9/tcp/8344/p2p/{peer}/p2p/{peer}")),
            ma("/ip4/203.0.113.9/tcp/8345/tcp/8346"),
        ];
        let dialed = AsServer::filter_valid_addrs(peer, demanded, &observed);
        println!("REACH autonat dial-back addresses filtered");
        let expected = vec![
            ma(&format!("/ip4/198.51.100.4/tcp/8336/p2p/{peer}")),
            ma(&format!("/ip4/198.51.100.4/udp/8336/quic-v1/p2p/{peer}")),
        ];
        for addr in &dialed {
            assert!(expected.contains(addr), "stacked address dialed: {addr}");
        }
        assert_eq!(dialed, expected);
    }

    /// QUILIBRIUM: the same over IPv6, and an address naming another peer
    /// is never dialed: the dial-back goes to the client's id alone.
    #[test]
    fn a_dial_back_over_ip6_goes_only_to_the_client_at_the_observed_ip() {
        let peer = PeerId::random();
        let other = PeerId::random();
        let observed = ma("/ip6/2001:db8::4/tcp/50123");
        let demanded = vec![
            ma("/ip6/fe80::2/tcp/8336"),
            ma(&format!("/ip6/fe80::2/udp/8336/quic-v1/p2p/{peer}")),
            ma("/ip4/10.0.0.2/tcp/9336"),
            ma("/ip6/2001:db8::9/ip6/::1/tcp/8337"),
            ma("/ip6/2001:db8::9/ip4/127.0.0.1/tcp/8338"),
            ma("/ip6/2001:db8::9/dns6/localhost/tcp/8339"),
            ma(&format!("/ip6/2001:db8::9/tcp/8340/p2p/{other}")),
            ma(&format!("/ip4/10.0.0.2/udp/8341/quic-v1/p2p/{other}")),
            ma(&format!("/ip6/2001:db8::9/tcp/8342/p2p/{other}/p2p/{peer}")),
            ma(&format!("/ip6/2001:db8::9/tcp/8343/p2p/{peer}/p2p/{other}")),
            ma(&format!("/p2p/{other}/ip6/2001:db8::9/tcp/8344")),
        ];
        let dialed = AsServer::filter_valid_addrs(peer, demanded, &observed);
        println!("REACH autonat dial-back addresses filtered");
        let expected = vec![
            ma(&format!("/ip6/2001:db8::4/tcp/8336/p2p/{peer}")),
            ma(&format!("/ip6/2001:db8::4/udp/8336/quic-v1/p2p/{peer}")),
            ma(&format!("/ip6/2001:db8::4/tcp/9336/p2p/{peer}")),
        ];
        for addr in &dialed {
            assert!(expected.contains(addr), "stacked address dialed: {addr}");
        }
        assert_eq!(dialed, expected);
    }

    /// QUILIBRIUM: a server dials back at most eight addresses of a
    /// request, the most a client of this repository sends. It dials them
    /// one at a time, each that does not answer taking up to the
    /// transport timeout, within its budget of dial-backs in progress.
    #[test]
    fn a_dial_back_tries_at_most_eight_addresses() {
        use libp2p_request_response::ProtocolSupport;

        let config = Config::default();
        let mut inner = request_response::Behaviour::with_codec(
            AutoNatCodec,
            std::iter::once((crate::DEFAULT_PROTOCOL_NAME, ProtocolSupport::Full)),
            request_response::Config::default(),
        );
        let client = PeerId::random();
        let connected = HashMap::from([(
            client,
            HashMap::from([(
                ConnectionId::new_unchecked(1),
                Some(ma("/ip4/198.51.100.4/tcp/50123")),
            )]),
        )]);
        let mut server = AsServer {
            inner: &mut inner,
            config: &config,
            connected: &connected,
            probe_id: &mut ProbeId(0),
            throttled_clients: &mut Vec::new(),
            ongoing_inbound: &mut HashMap::new(),
            stats: &mut ServerStats::default(),
        };
        let addresses = (0..12)
            .map(|n| ma(&format!("/ip4/10.0.0.2/tcp/{}", 9000 + n)))
            .collect();
        let dialed = server
            .resolve_inbound_request(
                client,
                DialRequest {
                    peer_id: client,
                    addresses,
                },
            )
            .unwrap();
        println!("REACH autonat dial-back request resolved");
        assert!(dialed.len() <= 8, "{} addresses dialed back", dialed.len());
        assert_eq!(dialed.len(), 8);
    }

    /// QUILIBRIUM: a request beyond the budget of dial-backs in progress is
    /// refused, which leaves the client's status unchanged; the budget is
    /// 16 by default.
    #[test]
    fn a_dial_back_beyond_the_budget_is_refused() {
        use libp2p_request_response::ProtocolSupport;

        assert_eq!(Config::default().max_concurrent_dial_backs, 16);
        let client = PeerId::random();
        let connected = HashMap::from([(
            client,
            HashMap::from([(
                ConnectionId::new_unchecked(1),
                Some(ma("/ip4/198.51.100.4/tcp/50123")),
            )]),
        )]);
        let resolve = |budget| {
            let config = Config {
                max_concurrent_dial_backs: budget,
                ..Config::default()
            };
            let mut inner = request_response::Behaviour::with_codec(
                AutoNatCodec,
                std::iter::once((crate::DEFAULT_PROTOCOL_NAME, ProtocolSupport::Full)),
                request_response::Config::default(),
            );
            AsServer {
                inner: &mut inner,
                config: &config,
                connected: &connected,
                probe_id: &mut ProbeId(0),
                throttled_clients: &mut Vec::new(),
                ongoing_inbound: &mut HashMap::new(),
                stats: &mut ServerStats::default(),
            }
            .resolve_inbound_request(
                client,
                DialRequest {
                    peer_id: client,
                    addresses: vec![ma("/ip4/10.0.0.2/tcp/8336")],
                },
            )
        };
        // No dial-back is in progress: a budget of one has room, none has
        // not.
        let (room, over) = (resolve(1), resolve(0));
        println!("REACH autonat dial-back request resolved");
        assert_eq!(room.map(|a| a.len()), Ok(1));
        let (status_text, error) = over.expect_err("dial-back over budget accepted");
        assert_eq!(error, ResponseError::DialRefused, "dial-back over budget");
        assert_eq!(refusal_reason(&status_text), "busy");
    }

    /// QUILIBRIUM: a dial-back whose request failed (the client's 30 s
    /// request timeout passed while its addresses were still being dialed,
    /// or the client closed its request) answers no one: it gives its place
    /// in the budget to another client at once. Until its dial ends it
    /// still holds its client and IP, and counts against twice the
    /// budget in all, which bounds the dials running at once.
    #[test]
    fn a_dial_back_whose_request_failed_frees_its_place_but_holds_its_ip() {
        let mut ongoing: HashMap<PeerId, OngoingInbound<u32, &str>> = HashMap::new();
        let (client, other) = (PeerId::random(), PeerId::random());
        let addr: Multiaddr = "/ip4/203.0.113.7/tcp/8336".parse().unwrap();
        let dial = start_dial_back(
            &mut ongoing,
            client,
            ProbeId(5),
            1,
            vec![addr.clone()],
            "ch",
        )
        .connection_id();
        let reason = |admitted: Result<(), (String, ResponseError)>| {
            admitted.map_err(|(text, error)| (refusal_reason(&text), error))
        };
        let ip = |addr: &str| client_ip(&ma(addr));
        let (at_client, at_other) = (client_ip(&addr), ip("/ip4/198.51.100.9/tcp/1"));
        assert_eq!(
            reason(admit_dial_back(&ongoing, other, at_other, 1)),
            Err(("busy", ResponseError::DialRefused))
        );

        assert_eq!(request_failed(&mut ongoing, client, &2), None);
        assert_eq!(request_failed(&mut ongoing, other, &1), None);
        assert_eq!(request_failed(&mut ongoing, client, &1), Some(ProbeId(5)));
        assert_eq!(request_failed(&mut ongoing, client, &1), None);
        println!("REACH autonat dial-back request failed");
        assert_eq!(
            reason(admit_dial_back(&ongoing, other, at_other, 1)),
            Ok(()),
            "a failed request kept its place in the budget"
        );
        assert_eq!(
            reason(admit_dial_back(&ongoing, client, at_client, 4)),
            Err(("already_ongoing", ResponseError::DialRefused)),
            "dial-back after a failed request let its client start another"
        );
        assert_eq!(
            reason(admit_dial_back(
                &ongoing,
                other,
                ip("/ip4/203.0.113.7/tcp/1"),
                4
            )),
            Err(("same_ip", ResponseError::DialRefused)),
            "dial-back after a failed request let its IP start another"
        );
        assert!(ongoing[&client].channel.is_none());

        // A second one whose request failed: with a budget of one, two
        // dials run, and a third waits for one of them to end.
        start_dial_back(
            &mut ongoing,
            other,
            ProbeId(6),
            3,
            vec![ma("/ip4/198.51.100.9/tcp/8336")],
            "ch",
        );
        assert_eq!(request_failed(&mut ongoing, other, &3), Some(ProbeId(6)));
        assert_eq!(
            reason(admit_dial_back(
                &ongoing,
                PeerId::random(),
                ip("/ip4/192.0.2.9/tcp/1"),
                1
            )),
            Err(("busy_dialing", ResponseError::DialRefused)),
            "dialing beyond twice the budget"
        );

        // The dial ends: the client and its IP are free, and nothing
        // is owed.
        let unreached = DialError::Transport(vec![(
            addr.clone(),
            TransportError::Other(std::io::Error::other("timed out")),
        )]);
        let (request, ..) = take_failed_dial_back(&mut ongoing, client, dial, &unreached).unwrap();
        assert!(request.channel.is_none());
        assert_eq!(admit_dial_back(&ongoing, client, at_client, 1), Ok(()));
    }

    /// QUILIBRIUM: a dial-back is refused while another client's runs at
    /// its IP, whatever its peer ID, and while two run in its IP group (an
    /// IPv4 /24, an IPv6 /48), each at another IP: one host with a few
    /// identities, one rented IPv4 block of a few addresses, or one holder
    /// of a /48 with a few /64s, could otherwise hold the whole budget. A
    /// second IP in the group is admitted while the first runs, so one
    /// address in another node's /24 cannot have that node's probes
    /// refused. Clients in other groups go on, and the group has room
    /// again once a dial ends.
    #[test]
    fn an_ip_group_gets_two_dial_backs_one_per_ip() {
        type Ongoing = HashMap<PeerId, OngoingInbound<u32, &'static str>>;
        fn start(ongoing: &mut Ongoing, at: &str) -> (PeerId, ConnectionId, Multiaddr) {
            let peer = PeerId::random();
            let addr = ma(&format!("{at}/tcp/8336/p2p/{peer}"));
            let dial = start_dial_back(ongoing, peer, ProbeId(1), 1, vec![addr.clone()], "ch")
                .connection_id();
            (peer, dial, addr)
        }
        let mut ongoing = Ongoing::new();
        let reason = |admitted: Result<(), (String, ResponseError)>| {
            admitted.map_err(|(text, error)| (refusal_reason(&text), error))
        };
        let ip = |addr: &str| client_ip(&ma(addr));
        let (v4, dial, v4_addr) = start(&mut ongoing, "/ip4/203.0.113.7");
        start(&mut ongoing, "/ip6/2001:db8:1:2::5");
        println!("REACH autonat dial-back admission checked");

        for (addr, at) in [
            ("/ip4/203.0.113.7/tcp/40001", "the same IPv4 address"),
            ("/ip6/2001:db8:1:2::5/tcp/40001", "the same IPv6 address"),
        ] {
            assert_eq!(
                reason(admit_dial_back(&ongoing, PeerId::random(), ip(addr), 16)),
                Err(("same_ip", ResponseError::DialRefused)),
                "second dial-back from one IP: another peer ID at {at}"
            );
        }
        for (second, at) in [
            ("/ip4/203.0.113.250", "one IPv4 /24"),
            ("/ip6/2001:db8:1:3::5", "one IPv6 /48"),
        ] {
            let admitted = admit_dial_back(
                &ongoing,
                PeerId::random(),
                ip(&format!("{second}/tcp/40001")),
                16,
            );
            assert_eq!(
                reason(admitted),
                Ok(()),
                "a second address of {at} refused while the first ran"
            );
            start(&mut ongoing, second);
        }
        for (addr, at) in [
            (
                "/ip4/203.0.113.8/tcp/40001",
                "a third address of one IPv4 /28",
            ),
            (
                "/ip4/203.0.113.100/tcp/40001",
                "a third address of one IPv4 /24",
            ),
            (
                "/ip6/2001:db8:1:4::5/tcp/40001",
                "a third /64 inside one /48",
            ),
            (
                "/ip6/2001:db8:1:2::77/tcp/40001",
                "a third address of one /48",
            ),
        ] {
            assert_eq!(
                reason(admit_dial_back(&ongoing, PeerId::random(), ip(addr), 16)),
                Err(("same_group", ResponseError::DialRefused)),
                "three dial-backs at once from one IP group: {at}"
            );
        }
        for addr in [
            "/ip4/203.0.114.7/tcp/40001",
            "/ip6/2001:db8:2:2::5/tcp/40001",
        ] {
            assert_eq!(
                admit_dial_back(&ongoing, PeerId::random(), ip(addr), 16),
                Ok(())
            );
        }

        let unreached = DialError::Transport(vec![(
            v4_addr,
            TransportError::Other(std::io::Error::other("timed out")),
        )]);
        assert!(take_failed_dial_back(&mut ongoing, v4, dial, &unreached).is_some());
        for addr in ["/ip4/203.0.113.8/tcp/40001", "/ip4/203.0.113.7/tcp/40001"] {
            assert_eq!(
                admit_dial_back(&ongoing, PeerId::random(), ip(addr), 16),
                Ok(())
            );
        }
    }

    /// QUILIBRIUM: a dial-back the swarm never reported ended is dropped
    /// once it is `max_dial_back_age` old, twice the longest a dial-back
    /// takes, so a missed report cannot hold its client, its IP group and
    /// its place for good. Younger ones stay.
    #[test]
    fn a_dial_back_past_its_age_cap_is_dropped() {
        let max_age = Config::default().max_dial_back_age;
        assert_eq!(max_age, std::time::Duration::from_secs(160));
        let mut ongoing: HashMap<PeerId, OngoingInbound<u32, &str>> = HashMap::new();
        let (old, young) = (PeerId::random(), PeerId::random());
        start_dial_back(
            &mut ongoing,
            old,
            ProbeId(1),
            1,
            vec![ma("/ip4/203.0.113.7/tcp/8336")],
            "ch",
        );
        let started = ongoing[&old].started;
        assert!(take_stale_dial_backs(&mut ongoing, started + max_age / 2, max_age).is_empty());
        start_dial_back(
            &mut ongoing,
            young,
            ProbeId(2),
            2,
            vec![ma("/ip4/198.51.100.9/tcp/8336")],
            "ch",
        );
        ongoing.get_mut(&young).unwrap().started = started + max_age / 2;

        let dropped = take_stale_dial_backs(&mut ongoing, started + max_age, max_age);
        println!("REACH autonat stale dial-backs checked");
        let dropped: Vec<PeerId> = dropped.into_iter().map(|(peer, _)| peer).collect();
        assert_eq!(dropped, vec![old], "a dial-back past its age cap stayed");
        assert!(ongoing.contains_key(&young));
        assert_eq!(
            admit_dial_back(&ongoing, old, client_ip(&ma("/ip4/203.0.113.7/tcp/1")), 1),
            Err((
                "too many concurrent dial-backs".to_string(),
                ResponseError::DialRefused
            ))
        );
        assert_eq!(
            admit_dial_back(&ongoing, old, client_ip(&ma("/ip4/203.0.113.7/tcp/1")), 2),
            Ok(())
        );
    }

    /// QUILIBRIUM: only the dial-back's own connection answers its probe.
    /// Another connection to the client on a requested address, such as
    /// another behaviour's dial, leaves the dial-back running and in the
    /// budget.
    #[test]
    fn a_dial_back_is_reached_by_its_own_connection_only() {
        let mut ongoing: HashMap<PeerId, OngoingInbound<u32, &str>> = HashMap::new();
        let client = PeerId::random();
        let addr = ma(&format!("/ip4/203.0.113.7/tcp/8336/p2p/{client}"));
        let dial = start_dial_back(
            &mut ongoing,
            client,
            ProbeId(4),
            1,
            vec![addr.clone()],
            "ch",
        )
        .connection_id();
        let other = ConnectionId::new_unchecked(usize::MAX);
        assert_ne!(other, dial);

        let taken = take_reached_dial_back(&mut ongoing, client, other, &addr);
        println!("REACH autonat dial-back connection checked");
        assert!(taken.is_none(), "another connection answered the dial-back");
        assert_eq!(ongoing[&client].dial, dial);
        let unrequested = ma(&format!("/ip4/203.0.113.7/tcp/9999/p2p/{client}"));
        assert!(take_reached_dial_back(&mut ongoing, client, dial, &unrequested).is_none());
        assert!(take_reached_dial_back(&mut ongoing, PeerId::random(), dial, &addr).is_none());

        let request = take_reached_dial_back(&mut ongoing, client, dial, &addr).unwrap();
        assert_eq!(request.probe_id, ProbeId(4));
        assert!(ongoing.is_empty());
    }

    #[test]
    fn filter_addresses() {
        let peer_id = PeerId::random();
        let observed_ip = random_ip();
        let observed_addr = Multiaddr::empty()
            .with(observed_ip.clone())
            .with(random_port())
            .with(Protocol::P2p(peer_id));
        // Valid address with matching peer-id
        let demanded_1 = Multiaddr::empty()
            .with(random_ip())
            .with(random_port())
            .with(Protocol::P2p(peer_id));
        // Invalid because peer_id does not match
        let demanded_2 = Multiaddr::empty()
            .with(random_ip())
            .with(random_port())
            .with(Protocol::P2p(PeerId::random()));
        // Valid address without peer-id
        let demanded_3 = Multiaddr::empty().with(random_ip()).with(random_port());
        // Invalid because relayed
        let demanded_4 = Multiaddr::empty()
            .with(random_ip())
            .with(random_port())
            .with(Protocol::P2p(PeerId::random()))
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(peer_id));
        let demanded = vec![
            demanded_1.clone(),
            demanded_2,
            demanded_3.clone(),
            demanded_4,
        ];
        let filtered = AsServer::filter_valid_addrs(peer_id, demanded, &observed_addr);
        let expected_1 = demanded_1
            .replace(0, |_| Some(observed_ip.clone()))
            .unwrap();
        let expected_2 = demanded_3
            .replace(0, |_| Some(observed_ip))
            .unwrap()
            .with(Protocol::P2p(peer_id));
        assert_eq!(filtered, vec![expected_1, expected_2]);
    }
}
