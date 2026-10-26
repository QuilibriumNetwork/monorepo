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
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
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

/// QUILIBRIUM: a dial-back request this server serves and has not answered
/// yet. `dial` is the connection id of its dial-back.
pub(crate) struct OngoingInbound<R, C> {
    pub(crate) probe_id: ProbeId,
    pub(crate) request_id: R,
    pub(crate) addrs: Vec<Multiaddr>,
    pub(crate) dial: ConnectionId,
    pub(crate) channel: C,
}

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
}

impl ServerStats {
    /// Whether nothing happened.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The refusals by reason, most frequent first (`denied=3
    /// throttled=1`), or `none`.
    pub fn refused_by_reason(&self) -> String {
        let mut counts: Vec<(&str, u32)> = self.refused.iter().map(|(r, n)| (*r, *n)).collect();
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

    fn refuse(&mut self, reason: &'static str) {
        *self.refused.entry(reason).or_default() += 1;
    }
}

/// QUILIBRIUM: dial `peer` back on `addrs`, one address at a time, and
/// record the request under the dial's connection id.
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
            addrs,
            dial,
            channel,
        },
    );
    opts
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
        "too many total dials" | "too many dials for peer" => "throttled",
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
                let probe_id = self.probe_id.next();
                if !self.connected.contains_key(&peer) {
                    tracing::debug!(
                        %peer,
                        "Reject inbound dial request from peer since it is not connected"
                    );
                    self.stats.refuse("not_connected");

                    return VecDeque::from([ToSwarm::GenerateEvent(Event::InboundProbe(
                        InboundProbeEvent::Error {
                            probe_id,
                            peer,
                            error: InboundProbeError::Response(ResponseError::DialRefused),
                        },
                    ))]);
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

                        VecDeque::from([
                            ToSwarm::GenerateEvent(Event::InboundProbe(
                                InboundProbeEvent::Request {
                                    probe_id,
                                    peer,
                                    addresses: addrs,
                                },
                            )),
                            ToSwarm::Dial { opts },
                        ])
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

                        VecDeque::from([ToSwarm::GenerateEvent(Event::InboundProbe(
                            InboundProbeEvent::Error {
                                probe_id,
                                peer,
                                error: InboundProbeError::Response(error),
                            },
                        ))])
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

                let probe_id = match self.ongoing_inbound.get(&peer) {
                    Some(ongoing) if ongoing.request_id == request_id => {
                        self.stats.request_failures += 1;
                        self.ongoing_inbound.remove(&peer).unwrap().probe_id
                    }
                    _ => self.probe_id.next(),
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
    pub(crate) fn on_outbound_connection(
        &mut self,
        peer: &PeerId,
        address: &Multiaddr,
    ) -> Option<InboundProbeEvent> {
        let addrs = &self.ongoing_inbound.get(peer)?.addrs;

        // Check if the dialed address was among the requested addresses.
        if !addrs.contains(address) {
            return None;
        }

        tracing::debug!(
            %peer,
            %address,
            "Dial-back to peer succeeded"
        );

        let OngoingInbound {
            probe_id, channel, ..
        } = self.ongoing_inbound.remove(peer).unwrap();
        self.stats.served += 1;
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
                probe_id, channel, ..
            },
            response_error,
            reason,
        ) = take_failed_dial_back(&mut *self.ongoing_inbound, peer, connection_id, error)?;
        match response_error {
            ResponseError::DialError => self.stats.failed += 1,
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

        if self.ongoing_inbound.contains_key(&sender) {
            let status_text = "dial-back already ongoing".to_string();
            return Err((status_text, ResponseError::DialRefused));
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

        let mut addrs = Self::filter_valid_addrs(sender, request.addresses, observed_addr);
        addrs.truncate(self.config.max_peer_addresses);

        if addrs.is_empty() {
            let status_text = "no dialable addresses".to_string();
            return Err((status_text, ResponseError::DialRefused));
        }

        Ok(addrs)
    }

    // Filter dial addresses and replace demanded ip with the observed one.
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
            .into_iter()
            .filter_map(|addr| {
                // Replace the demanded ip with the observed one.
                let i = addr
                    .iter()
                    .position(|p| matches!(p, Protocol::Ip4(_) | Protocol::Ip6(_)))?;
                let mut addr = addr.replace(i, |_| Some(observed_ip.clone()))?;

                let is_valid = addr.iter().all(|proto| match proto {
                    Protocol::P2pCircuit => false,
                    Protocol::P2p(peer_id) => peer_id == peer,
                    _ => true,
                });

                if !is_valid {
                    return None;
                }
                if !addr.iter().any(|p| matches!(p, Protocol::P2p(_))) {
                    addr.push(Protocol::P2p(peer))
                }
                // Only collect distinct addresses.
                distinct.insert(addr.clone()).then_some(addr)
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

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
        assert_eq!((request.probe_id, request.channel), (ProbeId(3), "channel"));
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

    fn random_ip<'a>() -> Protocol<'a> {
        Protocol::Ip4(Ipv4Addr::new(
            rand::random(),
            rand::random(),
            rand::random(),
            rand::random(),
        ))
    }
    fn random_port<'a>() -> Protocol<'a> {
        Protocol::Tcp(rand::random())
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
