//! Seat concentration: whether one network site holds so many seats of a
//! committee this node sits in that its outage alone leaves the shard at
//! most one member above quorum. On 2026-11-04 one operator's five nodes on
//! one IP held 4-5 seats of every shard, about a fifth of all seats, and
//! their outage halted 28 shards; nothing had shown it before.
//!
//! Members are grouped by the networks of their PeerInfo addresses (IPv4
//! /24, IPv6 /48; members sharing any network join one group); this node
//! uses the addresses of the last PeerInfo it published. Members without a
//! public address form no group, so a group's seats are a lower bound. Each
//! session is evaluated once when this node first sees it and once per
//! epoch, from state this node already holds: no network traffic. Lines
//! name a group by a short hash, never an address.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

use parking_lot::RwLock;
use quil_cw_consensus::handoff::Session;
use quil_types::error::Result;
use quil_types::proto::node::SeatConcentration;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// The network a public address sits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Network {
    /// An IPv4 /24.
    V4([u8; 3]),
    /// An IPv6 /48.
    V6([u8; 6]),
}

impl Network {
    /// A short stable name for logs, never the address: the first four bytes
    /// of SHA-256 over the address family and network prefix, in hex.
    fn label(self) -> String {
        let digest = match self {
            Network::V4(prefix) => Sha256::new().chain_update([4]).chain_update(prefix),
            Network::V6(prefix) => Sha256::new().chain_update([6]).chain_update(prefix),
        }
        .finalize();
        hex::encode(&digest[..4])
    }
}

fn ipv4_network(ip: Ipv4Addr) -> Option<Network> {
    let o = ip.octets();
    let not_public = ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0
        // Carrier-grade NAT, 100.64.0.0/10.
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || o[0] >= 240;
    (!not_public).then_some(Network::V4([o[0], o[1], o[2]]))
}

fn ipv6_network(ip: Ipv6Addr) -> Option<Network> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_network(v4);
    }
    let first = ip.segments()[0];
    let not_public = ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // Unique local fc00::/7 and link-local fe80::/10.
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80;
    let o = ip.octets();
    (!not_public).then_some(Network::V6([o[0], o[1], o[2], o[3], o[4], o[5]]))
}

/// The network of a multiaddr's leading IP: `/ip4/203.0.113.7/tcp/8336` is
/// in 203.0.113.0/24. DNS names, relayed (`p2p-circuit`) addresses, whose
/// IP is the relay's, and non-public IPs have none.
pub(super) fn network_of(multiaddr: &str) -> Option<Network> {
    if multiaddr.contains("/p2p-circuit") {
        return None;
    }
    let mut parts = multiaddr.split('/');
    if parts.next() != Some("") {
        return None;
    }
    match (parts.next()?, parts.next()?) {
        ("ip4", ip) => ipv4_network(ip.parse().ok()?),
        ("ip6", ip) => ipv6_network(ip.parse().ok()?),
        _ => None,
    }
}

/// The networks of a set of multiaddrs.
pub(super) fn networks<'a>(addrs: impl IntoIterator<Item = &'a String>) -> BTreeSet<Network> {
    addrs
        .into_iter()
        .filter_map(|a| network_of(a.as_str()))
        .collect()
}

/// The networks a peer's PeerInfo announces, over all its records.
pub(super) fn peer_networks(info: &quil_p2p::CanonicalPeerInfo) -> BTreeSet<Network> {
    networks(
        info.reachability
            .iter()
            .flat_map(|r| r.pubsub_multiaddrs.iter().chain(&r.stream_multiaddrs)),
    )
}

/// The Simplex quorum of a session of `members`.
pub(super) fn quorum(members: usize) -> usize {
    members - members.saturating_sub(1) / 3
}

/// The seats from which a group's outage leaves its session at most one
/// member above quorum (`members - seats - quorum <= 1`), and at least two:
/// a lone member is no group. On 2026-11-04 shards at margin 0 stalled and
/// those at margin 1 flapped.
pub(super) fn concentration_seats(members: usize) -> usize {
    members
        .saturating_sub(quorum(members))
        .saturating_sub(1)
        .max(2)
}

/// A session's members grouped by network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Grouping {
    pub members: usize,
    /// Member indices of the largest group, ascending; empty when no member
    /// has a known network. On a tie, this node's group, else the one with
    /// the lowest member index.
    pub largest: Vec<usize>,
    /// The largest group's name: [`Network::label`] of its lowest network.
    pub label: String,
    /// Seats of this node's group, this node included; 0 when this node's
    /// networks are unknown.
    pub own_seats: usize,
    /// Whether this node is in the largest group.
    pub own_in_largest: bool,
    /// Members with no known public network.
    pub unaddressed: usize,
}

fn root(parent: &mut [usize], mut i: usize) -> usize {
    while parent[i] != i {
        parent[i] = parent[parent[i]];
        i = parent[i];
    }
    i
}

/// Group members (`networks[i]` are member `i`'s) by shared networks;
/// `own` is this node's member index.
pub(super) fn group(networks: &[BTreeSet<Network>], own: Option<usize>) -> Grouping {
    // Union-find; a group's root is its lowest member index.
    let mut parent: Vec<usize> = (0..networks.len()).collect();
    let mut first: HashMap<Network, usize> = HashMap::new();
    for (i, nets) in networks.iter().enumerate() {
        for net in nets {
            let j = *first.entry(*net).or_insert(i);
            let (a, b) = (root(&mut parent, i), root(&mut parent, j));
            parent[a.max(b)] = a.min(b);
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, nets) in networks.iter().enumerate() {
        if !nets.is_empty() {
            let r = root(&mut parent, i);
            groups.entry(r).or_default().push(i);
        }
    }
    let own_root = own
        .filter(|&i| networks.get(i).is_some_and(|nets| !nets.is_empty()))
        .map(|i| root(&mut parent, i));
    let own_seats = own_root.and_then(|r| groups.get(&r)).map_or(0, Vec::len);
    let largest_root = groups
        .iter()
        .max_by_key(|(r, members)| (members.len(), Some(**r) == own_root, std::cmp::Reverse(**r)))
        .map(|(r, _)| *r);
    let largest = largest_root
        .and_then(|r| groups.remove(&r))
        .unwrap_or_default();
    let label = largest
        .iter()
        .filter_map(|&i| networks[i].first())
        .min()
        .map_or_else(String::new, |net| net.label());
    Grouping {
        members: networks.len(),
        own_in_largest: own_root.is_some() && own_root == largest_root,
        largest,
        label,
        own_seats,
        unaddressed: networks.iter().filter(|nets| nets.is_empty()).count(),
    }
}

/// One session's grouping against its thresholds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Evaluation {
    pub grouping: Grouping,
    pub quorum: usize,
    pub threshold: usize,
}

impl Evaluation {
    pub(super) fn new(grouping: Grouping) -> Self {
        Self {
            quorum: quorum(grouping.members),
            threshold: concentration_seats(grouping.members),
            grouping,
        }
    }

    /// Some group's outage leaves the session at most one above quorum.
    pub(super) fn concentrated(&self) -> bool {
        self.grouping.largest.len() >= self.threshold
    }

    /// This node's own group's outage does.
    pub(super) fn own_concentrated(&self) -> bool {
        self.grouping.own_seats >= self.threshold
    }

    /// Members left with the largest group offline, less the quorum.
    fn margin_without_largest(&self) -> i64 {
        self.grouping.members as i64 - self.grouping.largest.len() as i64 - self.quorum as i64
    }

    fn report(&self, epoch: u64) -> SeatConcentration {
        SeatConcentration {
            members: self.grouping.members as u32,
            quorum: self.quorum as u32,
            largest_group_seats: self.grouping.largest.len() as u32,
            own_group_seats: self.grouping.own_seats as u32,
            unaddressed_members: self.grouping.unaddressed as u32,
            concentration_seats: self.threshold as u32,
            epoch,
        }
    }
}

/// Evaluate `session` for this node (`own_peer`, its peer ID bytes, on
/// `own_networks`); `None` when this node is no member. `peer_networks`
/// gives another member's networks by peer ID.
pub(super) fn evaluate(
    session: &Session,
    own_peer: &[u8],
    own_networks: &BTreeSet<Network>,
    peer_networks: impl Fn(&[u8]) -> BTreeSet<Network>,
) -> Option<Evaluation> {
    let mut own = None;
    let networks: Vec<BTreeSet<Network>> = session
        .members
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let peer = quil_p2p::peer_id_from_falcon_pubkey(key);
            if peer == own_peer {
                own = Some(i);
                own_networks.clone()
            } else {
                peer_networks(&peer)
            }
        })
        .collect();
    let own = own?;
    Some(Evaluation::new(group(&networks, Some(own))))
}

struct Seen {
    session: [u8; 32],
    epoch: u64,
    /// `None` while this node is no member of the session.
    evaluation: Option<Evaluation>,
}

/// Per served shard, the session and epoch last evaluated and the outcome.
#[derive(Default)]
pub(super) struct SeatConcentrations {
    seen: HashMap<Vec<u8>, Seen>,
}

impl SeatConcentrations {
    /// Whether `filter`'s session is due: a new session or a new epoch.
    pub(super) fn due(&self, filter: &[u8], session: [u8; 32], epoch: u64) -> bool {
        self.seen
            .get(filter)
            .is_none_or(|seen| seen.session != session || seen.epoch != epoch)
    }

    /// Record an evaluation; true when the shard was concentrated at its last
    /// one and is not any more, so the end is logged once.
    pub(super) fn record(
        &mut self,
        filter: &[u8],
        session: [u8; 32],
        epoch: u64,
        evaluation: Option<Evaluation>,
    ) -> bool {
        let now = evaluation.as_ref().is_some_and(Evaluation::concentrated);
        let before = self
            .seen
            .insert(
                filter.to_vec(),
                Seen {
                    session,
                    epoch,
                    evaluation,
                },
            )
            .and_then(|seen| seen.evaluation)
            .is_some_and(|e| e.concentrated());
        before && !now
    }

    /// Forget shards this node no longer serves.
    pub(super) fn retain(&mut self, served: &BTreeSet<Vec<u8>>) {
        self.seen.retain(|filter, _| served.contains(filter));
    }

    /// The RPC report for `filter`, when this node sits in its session.
    pub(super) fn report(&self, filter: &[u8]) -> Option<SeatConcentration> {
        let seen = self.seen.get(filter)?;
        seen.evaluation.as_ref().map(|e| e.report(seen.epoch))
    }
}

fn log_concentration(filter: &[u8], session: &Session, epoch: u64, e: &Evaluation) {
    let g = &e.grouping;
    let group_members = g
        .largest
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let margin_without_group = e.margin_without_largest();
    if e.own_concentrated() {
        warn!(
            scope = "this node's site",
            filter = %hex::encode(filter),
            generation = session.generation,
            epoch,
            members = g.members,
            quorum = e.quorum,
            threshold = e.threshold,
            own_group_seats = g.own_seats,
            largest_group_seats = g.largest.len(),
            this_node_in_largest = g.own_in_largest,
            group = %g.label,
            group_members = %group_members,
            margin_without_group,
            unaddressed = g.unaddressed,
            action = "this operator's to fix: keep fewer than `threshold` of a shard's seats on \
                      one network (IPv4 /24, IPv6 /48) by spreading provers across sites; until \
                      then an outage, restart or upgrade of this site's nodes together can stall \
                      the shard until GLOBAL reseats its committee",
            "seat concentration: this node's site holds this shard's quorum margin; its outage leaves the shard at most one member above quorum"
        );
    } else {
        info!(
            scope = "peer",
            filter = %hex::encode(filter),
            generation = session.generation,
            epoch,
            members = g.members,
            quorum = e.quorum,
            threshold = e.threshold,
            largest_group_seats = g.largest.len(),
            this_node_in_largest = g.own_in_largest,
            group = %g.label,
            group_members = %group_members,
            margin_without_group,
            unaddressed = g.unaddressed,
            action = "nothing to fix on this node: the group's operator can spread its provers \
                      across sites; if this shard stalls, compare `group_members` with the \
                      absent members of its 'app session liveness' lines",
            "seat concentration: one network group holds this shard's quorum margin; its outage leaves the shard at most one member above quorum"
        );
    }
}

/// Evaluate each served shard's head session that is due and log what it
/// shows. `head` reads a shard's committed head session; `peer_networks`
/// gives a member's networks by peer ID.
pub(super) fn pass(
    state: &RwLock<SeatConcentrations>,
    served: &BTreeSet<Vec<u8>>,
    head: impl Fn(&[u8]) -> Result<Option<Session>>,
    epoch: u64,
    own_peer: &[u8],
    own_networks: &BTreeSet<Network>,
    peer_networks: impl Fn(&[u8]) -> BTreeSet<Network>,
) {
    state.write().retain(served);
    for filter in served {
        let session = match head(filter) {
            Ok(Some(session)) => session,
            Ok(None) => continue,
            Err(error) => {
                debug!(filter = %hex::encode(filter), %error, "seat concentration: head session unreadable");
                continue;
            }
        };
        let Ok(id) = session.id() else { continue };
        if !state.read().due(filter, id, epoch) {
            continue;
        }
        let evaluation = evaluate(&session, own_peer, own_networks, &peer_networks);
        if let Some(e) = evaluation
            .as_ref()
            .filter(|e| e.concentrated() || e.own_concentrated())
        {
            log_concentration(filter, &session, epoch, e);
        }
        let largest = evaluation.as_ref().map_or(0, |e| e.grouping.largest.len());
        let members = session.members.len();
        if state.write().record(filter, id, epoch, evaluation) {
            info!(
                scope = "peer",
                filter = %hex::encode(filter),
                generation = session.generation,
                epoch,
                members,
                quorum = quorum(members),
                threshold = concentration_seats(members),
                largest_group_seats = largest,
                "seat concentration ended: no network group holds this shard's quorum margin any more"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: &str) -> BTreeSet<Network> {
        networks(&[format!("/ip4/{a}/tcp/8336")])
    }

    fn v6(a: &str) -> BTreeSet<Network> {
        networks(&[format!("/ip6/{a}/udp/8336/quic-v1")])
    }

    fn none() -> BTreeSet<Network> {
        BTreeSet::new()
    }

    /// `n` members on distinct /24s, the first `site` of them on one.
    fn site_of(n: usize, site: usize) -> Vec<BTreeSet<Network>> {
        (0..n)
            .map(|i| {
                if i < site {
                    v4("198.51.100.1")
                } else {
                    v4(&format!("192.0.{i}.1"))
                }
            })
            .collect()
    }

    #[test]
    fn addresses_map_to_their_public_networks() {
        assert_eq!(
            network_of("/ip4/203.0.113.7/tcp/8336"),
            Some(Network::V4([203, 0, 113]))
        );
        assert_eq!(
            network_of("/ip4/203.0.113.7/tcp/8336"),
            network_of("/ip4/203.0.113.250/udp/8336/quic-v1")
        );
        assert_ne!(
            network_of("/ip4/203.0.113.7/tcp/8336"),
            network_of("/ip4/203.0.114.7/tcp/8336")
        );
        assert_eq!(
            network_of("/ip6/2001:db8:1234:5678::7/tcp/8336"),
            Some(Network::V6([0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34]))
        );
        assert_eq!(
            network_of("/ip6/::ffff:203.0.113.7/tcp/8336"),
            Some(Network::V4([203, 0, 113])),
            "an IPv4-mapped address is in its IPv4 network"
        );
        for addr in [
            "/ip4/10.1.2.3/tcp/8336",
            "/ip4/192.168.1.20/tcp/8336",
            "/ip4/172.16.0.1/tcp/8336",
            "/ip4/127.0.0.1/tcp/8336",
            "/ip4/0.0.0.0/tcp/8336",
            "/ip4/100.64.1.1/tcp/8336",
            "/ip4/169.254.1.1/tcp/8336",
            "/ip4/255.255.255.255/tcp/8336",
            "/ip6/::1/tcp/8336",
            "/ip6/::/tcp/8336",
            "/ip6/fd00::1/tcp/8336",
            "/ip6/fe80::1/tcp/8336",
            "/ip6/ff02::1/tcp/8336",
            "/dns4/node.example.com/tcp/8336",
            "/ip4/203.0.113.7/tcp/8336/p2p/QmRelay/p2p-circuit",
            "/ip4/not-an-ip/tcp/8336",
            "ip4/203.0.113.7/tcp/8336",
            "/ip4",
            "",
        ] {
            assert_eq!(network_of(addr), None, "{addr}");
        }
    }

    #[test]
    fn quorum_and_threshold_follow_the_session_size() {
        // n, q(n), max(2, n - q(n) - 1).
        for (n, q, t) in [
            (1, 1, 2),
            (4, 3, 2),
            (10, 7, 2),
            (15, 11, 3),
            (16, 11, 4),
            (17, 12, 4),
            (18, 13, 4),
            (21, 15, 5),
            (24, 17, 6),
            (25, 17, 7),
        ] {
            assert_eq!((quorum(n), concentration_seats(n)), (q, t), "n={n}");
        }
    }

    #[test]
    fn members_sharing_a_network_form_one_group() {
        // 0, 2 and 5 on one /24; 1 and 4 on another; 3 alone; 6 unaddressed.
        let nets = [
            v4("198.51.100.1"),
            v4("203.0.113.1"),
            v4("198.51.100.2"),
            v4("192.0.2.1"),
            v4("203.0.113.9"),
            v4("198.51.100.200"),
            none(),
        ];
        let g = group(&nets, Some(3));
        assert_eq!(g.largest, vec![0, 2, 5]);
        assert_eq!((g.own_seats, g.own_in_largest), (1, false));
        assert_eq!(g.unaddressed, 1);
        assert_eq!(g.label, Network::V4([198, 51, 100]).label());
        assert_eq!(g.label.len(), 8);
        // A member announcing both networks joins their groups into one.
        let mut nets = nets.to_vec();
        nets[3] = v4("198.51.100.3");
        nets[3].extend(v4("203.0.113.3"));
        let g = group(&nets, Some(3));
        assert_eq!(g.largest, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!((g.own_seats, g.own_in_largest), (6, true));
    }

    #[test]
    fn ipv6_members_group_by_their_48() {
        let nets = [
            v6("2001:db8:aa:1::1"),
            v6("2001:db8:aa:2::1"),
            v6("2001:db8:ab:1::1"),
            v6("2001:db8:aa:ffff::9"),
        ];
        let g = group(&nets, Some(2));
        assert_eq!(g.largest, vec![0, 1, 3]);
        assert_eq!((g.own_seats, g.own_in_largest), (1, false));
    }

    #[test]
    fn members_without_a_known_address_form_no_group() {
        let nets = [none(), none(), none(), v4("198.51.100.1"), none()];
        let g = group(&nets, Some(0));
        assert_eq!(g.largest, vec![3]);
        assert_eq!(g.unaddressed, 4);
        assert_eq!(g.own_seats, 0, "this node's own address is unknown");
        assert!(!g.own_in_largest);
        let g = group(&[none(), none()], None);
        assert!(g.largest.is_empty() && g.label.is_empty());
        let unaddressed: Vec<_> = (0..10).map(|_| none()).collect();
        let e = Evaluation::new(group(&unaddressed, Some(0)));
        assert!(!e.concentrated() && !e.own_concentrated());
    }

    #[test]
    fn concentration_starts_at_exactly_members_less_quorum_less_one() {
        // n = 17, q = 12: four seats leave margin 1, three leave margin 2.
        let at = Evaluation::new(group(&site_of(17, 4), Some(0)));
        assert_eq!((at.threshold, at.margin_without_largest()), (4, 1));
        assert!(at.concentrated() && at.own_concentrated());
        let below = Evaluation::new(group(&site_of(17, 3), Some(0)));
        assert_eq!(below.margin_without_largest(), 2);
        assert!(!below.concentrated() && !below.own_concentrated());
        // Another member's site, not this node's.
        let other = Evaluation::new(group(&site_of(17, 4), Some(16)));
        assert!(other.concentrated() && !other.own_concentrated());
        assert!(!other.grouping.own_in_largest);
        let r = other.report(1393);
        assert_eq!(
            (
                r.members,
                r.quorum,
                r.largest_group_seats,
                r.own_group_seats,
                r.concentration_seats,
                r.unaddressed_members,
                r.epoch
            ),
            (17, 12, 4, 1, 4, 0, 1393)
        );
    }

    #[test]
    fn this_nodes_group_is_concentrated_even_when_not_the_largest() {
        // n = 24, threshold 6: another site holds 7, this node's holds 6.
        let mut nets = site_of(24, 7);
        for net in nets.iter_mut().skip(7).take(6) {
            *net = v4("203.0.113.1");
        }
        let e = Evaluation::new(group(&nets, Some(10)));
        assert_eq!(e.grouping.largest.len(), 7);
        assert_eq!(e.grouping.own_seats, 6);
        assert!(!e.grouping.own_in_largest);
        assert!(e.own_concentrated());
    }

    #[test]
    fn a_session_is_evaluated_once_per_session_and_epoch_and_its_end_noted_once() {
        let concentrated = || Some(Evaluation::new(group(&site_of(10, 4), Some(9))));
        let spread = || Some(Evaluation::new(group(&site_of(10, 0), Some(9))));
        let mut s = SeatConcentrations::default();
        assert!(s.due(b"f", [1; 32], 7));
        assert!(!s.record(b"f", [1; 32], 7, concentrated()));
        assert!(!s.due(b"f", [1; 32], 7));
        assert!(s.due(b"f", [1; 32], 8), "new epoch");
        assert!(s.due(b"f", [2; 32], 7), "new session");
        assert_eq!(
            s.report(b"f").map(|r| (r.largest_group_seats, r.epoch)),
            Some((4, 7))
        );
        assert!(s.record(b"f", [1; 32], 8, spread()), "ended");
        assert!(!s.record(b"f", [1; 32], 9, spread()), "noted once");
        assert!(!s.record(b"f", [2; 32], 9, None));
        assert_eq!(s.report(b"f"), None, "no member of the session");
        s.retain(&BTreeSet::new());
        assert!(s.due(b"f", [2; 32], 9), "forgotten once unserved");
    }

    #[test]
    fn only_a_session_this_node_sits_in_is_evaluated() {
        let key = |b: u8| vec![b; quil_crypto::FALCON_PUBLIC_KEY_LEN];
        let session = Session {
            chain_id: [0; 32],
            filter: vec![1; 32],
            generation: 1,
            genesis: [0; 32],
            base_frame: 0,
            authorization: [0; 32],
            members: vec![key(1), key(2), key(3)],
        };
        let own = quil_p2p::peer_id_from_falcon_pubkey(&key(2));
        let shared = v4("198.51.100.1");
        let e = evaluate(&session, &own, &shared, |_| shared.clone()).expect("a member");
        assert_eq!((e.grouping.largest.len(), e.grouping.own_seats), (3, 3));
        assert!(e.own_concentrated());
        let other = |peer: &[u8]| {
            if peer == own.as_slice() {
                v4("203.0.113.1")
            } else {
                none()
            }
        };
        let e = evaluate(&session, &own, &none(), other).expect("a member");
        assert_eq!((e.grouping.own_seats, e.grouping.unaddressed), (0, 3));
        assert!(evaluate(&session, b"someone else", &shared, |_| shared.clone()).is_none());
    }
}
