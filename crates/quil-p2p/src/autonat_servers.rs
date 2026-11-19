//! The AutoNAT servers this node probes.
//!
//! AutoNAT v1 sends each probe to a random server. Upstream draws from every
//! connected peer, so an operator running many nodes behind one IP receives
//! a matching share of the probes, and peers that do not serve AutoNAT are
//! drawn as well. [`ProbeServers`] registers a peer only once identify shows
//! that it serves AutoNAT, at most one peer per remote IP (an IPv6 address
//! counts by its /48), and only peers reached over an address family this
//! node listens on, since a server dials back over the family it sees. The
//! configured archive and bootstrap peers are registered from the start, so
//! the first probe, 15 s after start, does not wait for identify; one
//! connected over a family this node does not listen on is no server until
//! that connection closes. AutoNAT keeps its own probe rate.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};

use libp2p::multiaddr::Protocol;
use libp2p::swarm::ConnectionId;
use libp2p::{Multiaddr, PeerId};

/// AutoNAT's configuration: upstream defaults (timings, probe rate), but
/// probes go only to the servers [`ProbeServers`] registers.
pub(crate) fn autonat_config() -> libp2p::autonat::Config {
    libp2p::autonat::Config {
        use_connected: false,
        ..Default::default()
    }
}

/// The first IP of a multiaddr.
pub(crate) fn ip_of(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// The operator group of a remote IP: an IPv6 address counts by its /48,
/// which one site typically holds whole and a tunnel broker hands out for
/// free. By /64, one holder of a /48 could fill this node's server list
/// and count as two servers for the address tracker.
pub(crate) fn ip_group(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !((1u128 << 80) - 1))),
    }
}

/// A change to AutoNAT's server list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServerChange {
    Add(PeerId),
    /// A configured peer serves again, at the addresses it is pinned at.
    AddAt(PeerId, Vec<Multiaddr>),
    Remove(PeerId),
}

/// Apply `changes` to AutoNAT. Configured peers are added by the caller,
/// with their addresses, and again with them after an off-family
/// connection (see [`ProbeServers::on_connection`]).
pub(crate) fn apply(autonat: &mut libp2p::autonat::Behaviour, changes: Vec<ServerChange>) {
    for change in changes {
        match change {
            ServerChange::Add(peer) => autonat.add_server(peer, None),
            ServerChange::AddAt(peer, addrs) if addrs.is_empty() => autonat.add_server(peer, None),
            ServerChange::AddAt(peer, addrs) => {
                for addr in addrs {
                    autonat.add_server(peer, Some(addr));
                }
            }
            ServerChange::Remove(peer) => autonat.remove_server(&peer),
        }
    }
}

/// A configured peer AutoNAT probes.
struct Pin {
    /// Its remote IP group once known.
    ip: Option<IpAddr>,
    /// The addresses it is pinned at, in families this node listens on or
    /// DNS names.
    addrs: Vec<Multiaddr>,
}

impl Pin {
    /// Whether it is pinned at an IP: one pinned at DNS names only keeps the
    /// rule of an unknown family (see [`ProbeServers::on_connection`]).
    fn at_an_ip(&self) -> bool {
        self.addrs.iter().any(|addr| ip_of(addr).is_some())
    }
}

/// Chooses AutoNAT's servers: peers that serve the protocol, one per remote
/// IP, plus the configured peers.
pub(crate) struct ProbeServers {
    routable: fn(&Multiaddr) -> bool,
    listen_v4: bool,
    listen_v6: bool,
    /// The peer and remote IP group of each open connection.
    conns: HashMap<ConnectionId, (PeerId, IpAddr)>,
    /// Connected peers whose identify lists the AutoNAT protocol.
    capable: HashSet<PeerId>,
    /// Configured peers, servers until identify shows they do not serve
    /// AutoNAT, except while connected over an unlistened family (see
    /// [`ProbeServers::on_connection`]).
    pinned: HashMap<PeerId, Pin>,
    /// The other servers, with the IP each one holds.
    servers: HashMap<PeerId, IpAddr>,
    by_ip: HashMap<IpAddr, PeerId>,
}

impl ProbeServers {
    /// `routable` decides which remote IPs count as distinct operators;
    /// `listen_v4`/`listen_v6` name the address families this node listens on.
    pub(crate) fn new(routable: fn(&Multiaddr) -> bool, listen_v4: bool, listen_v6: bool) -> Self {
        Self {
            routable,
            listen_v4,
            listen_v6,
            conns: HashMap::new(),
            capable: HashSet::new(),
            pinned: HashMap::new(),
            servers: HashMap::new(),
            by_ip: HashMap::new(),
        }
    }

    /// The configured peer `peer` at `addrs`, every address it is listed
    /// at, is a server; the caller adds it to AutoNAT with those addresses.
    /// It takes its IP from another server when one listened IP group is
    /// all it can be reached at; with several (an archive's IPv4 and IPv6
    /// entries on a node listening on both) its IP is the one it connects
    /// from. One at no address in a family this node listens on is removed.
    pub(crate) fn pin(&mut self, peer: PeerId, addrs: &[Multiaddr]) -> Vec<ServerChange> {
        if let Some(ip) = self.servers.remove(&peer) {
            self.by_ip.remove(&ip);
        }
        let reachable: Vec<&Multiaddr> = addrs
            .iter()
            .filter(|addr| ip_of(addr).is_none_or(|ip| self.listened(ip)))
            .collect();
        let ips: Vec<Option<IpAddr>> = reachable
            .iter()
            .map(|addr| ip_of(addr).map(ip_group))
            .collect();
        let Some(&first) = ips.first() else {
            return vec![ServerChange::Remove(peer)];
        };
        let ip = if ips.iter().all(|&ip| ip == first) {
            first
        } else {
            None
        };
        let addrs = reachable.into_iter().cloned().collect();
        self.pinned.insert(peer, Pin { ip, addrs });
        let mut changes = ip.map(|ip| self.evict(ip)).unwrap_or_default();
        if self.suspended(&peer) {
            changes.push(ServerChange::Remove(peer));
        }
        changes
    }

    /// A connection to `peer` from `remote` opened. A configured peer
    /// pinned at an IP is no server while it holds a connection over a
    /// family this node does not listen on: AutoNAT would probe over it and
    /// the server would dial back over that family. It serves again when
    /// the last such connection closes ([`Self::on_connection_closed`]).
    /// One pinned at DNS names only is removed for good by its first
    /// connection over such a family, before its IP is known.
    pub(crate) fn on_connection(
        &mut self,
        conn: ConnectionId,
        peer: PeerId,
        remote: &Multiaddr,
    ) -> Vec<ServerChange> {
        let Some(ip) = ip_of(remote).map(ip_group) else {
            return Vec::new();
        };
        let was_suspended = self.suspended(&peer);
        self.conns.insert(conn, (peer, ip));
        let listened = self.listened(ip);
        let Some(pin) = self.pinned.get_mut(&peer) else {
            return Vec::new();
        };
        if !listened && !pin.at_an_ip() {
            if pin.ip.is_none() {
                self.pinned.remove(&peer);
                return vec![ServerChange::Remove(peer)];
            }
            return Vec::new();
        }
        if !listened {
            if was_suspended {
                return Vec::new();
            }
            tracing::info!(
                %peer,
                remote = %remote,
                "a configured AutoNAT server is connected over an address family this node does \
                 not listen on (its listened-family addresses did not answer the dial, or it \
                 dialed this node there); it is not probed until that connection closes, so \
                 this node has one AutoNAT server less meanwhile"
            );
            return vec![ServerChange::Remove(peer)];
        }
        if pin.ip.is_none() {
            pin.ip = Some(ip);
            return self.evict(ip);
        }
        Vec::new()
    }

    /// Identify on `conn` reported whether `peer` serves AutoNAT.
    pub(crate) fn on_identify(
        &mut self,
        conn: ConnectionId,
        peer: PeerId,
        serves_autonat: bool,
    ) -> Vec<ServerChange> {
        if self.pinned.contains_key(&peer) {
            if serves_autonat {
                return Vec::new();
            }
            let ip = self.pinned.remove(&peer).and_then(|pin| pin.ip);
            let mut changes = vec![ServerChange::Remove(peer)];
            changes.extend(ip.map(|ip| self.promote(ip)).unwrap_or_default());
            return changes;
        }
        if !serves_autonat {
            self.capable.remove(&peer);
            return self.release(peer);
        }
        self.capable.insert(peer);
        if self.servers.contains_key(&peer) {
            return Vec::new();
        }
        match self.conns.get(&conn) {
            Some(&(p, ip)) if p == peer => self.register(peer, ip),
            _ => Vec::new(),
        }
    }

    /// A connection to `peer` closed, leaving `remaining` open.
    pub(crate) fn on_connection_closed(
        &mut self,
        conn: ConnectionId,
        peer: PeerId,
        remaining: u32,
    ) -> Vec<ServerChange> {
        let was_suspended = self.suspended(&peer);
        self.conns.remove(&conn);
        let mut changes = Vec::new();
        if was_suspended && !self.suspended(&peer) {
            let addrs = self.pinned.get(&peer).map(|pin| pin.addrs.clone());
            tracing::info!(
                %peer,
                "a configured AutoNAT server's connection over an address family this node does \
                 not listen on closed; it is probed again, and its next dial tries the listened \
                 family first"
            );
            changes.push(ServerChange::AddAt(peer, addrs.unwrap_or_default()));
        }
        if remaining > 0 {
            return changes;
        }
        // A configured peer stays a server: AutoNAT dials it when needed.
        self.capable.remove(&peer);
        changes.extend(self.release(peer));
        changes
    }

    /// The remote IP group (see [`ip_group`]) of `peer`'s open connection
    /// `conn`, if it is an IP connection.
    pub(crate) fn ip_of_connection(&self, conn: ConnectionId, peer: PeerId) -> Option<IpAddr> {
        match self.conns.get(&conn) {
            Some(&(p, ip)) if p == peer => Some(ip),
            _ => None,
        }
    }

    /// The remote IP group of server `peer` (see [`ip_group`]), if known.
    pub(crate) fn ip_of_server(&self, peer: &PeerId) -> Option<IpAddr> {
        self.servers
            .get(peer)
            .copied()
            .or_else(|| self.pinned.get(peer).and_then(|pin| pin.ip))
            .or_else(|| {
                self.conns
                    .values()
                    .find_map(|&(p, ip)| (p == *peer).then_some(ip))
            })
    }

    /// How many servers AutoNAT holds.
    pub(crate) fn count(&self) -> usize {
        let pinned = self
            .pinned
            .keys()
            .filter(|peer| !self.suspended(peer))
            .count();
        pinned + self.servers.len()
    }

    /// Whether configured peer `peer`, pinned at an IP, holds a connection
    /// over a family this node does not listen on, and so is no server
    /// (see [`Self::on_connection`]).
    fn suspended(&self, peer: &PeerId) -> bool {
        self.pinned.get(peer).is_some_and(Pin::at_an_ip)
            && self
                .conns
                .values()
                .any(|&(p, ip)| p == *peer && !self.listened(ip))
    }

    fn listened(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.listen_v4,
            IpAddr::V6(_) => self.listen_v6,
        }
    }

    fn ip_taken(&self, ip: IpAddr) -> bool {
        self.by_ip.contains_key(&ip) || self.pinned.values().any(|pin| pin.ip == Some(ip))
    }

    /// Make `peer` the server of `ip` if `ip` is listened, routable and free.
    fn register(&mut self, peer: PeerId, ip: IpAddr) -> Vec<ServerChange> {
        if !self.listened(ip) || !(self.routable)(&Multiaddr::from(ip)) || self.ip_taken(ip) {
            return Vec::new();
        }
        self.servers.insert(peer, ip);
        self.by_ip.insert(ip, peer);
        vec![ServerChange::Add(peer)]
    }

    /// `peer` is no server any more; another capable peer may take its IP.
    fn release(&mut self, peer: PeerId) -> Vec<ServerChange> {
        let Some(ip) = self.servers.remove(&peer) else {
            return Vec::new();
        };
        self.by_ip.remove(&ip);
        let mut changes = vec![ServerChange::Remove(peer)];
        changes.extend(self.promote(ip));
        changes
    }

    /// A configured peer took `ip`: its other server gives way.
    fn evict(&mut self, ip: IpAddr) -> Vec<ServerChange> {
        match self.by_ip.remove(&ip) {
            Some(peer) => {
                self.servers.remove(&peer);
                vec![ServerChange::Remove(peer)]
            }
            None => Vec::new(),
        }
    }

    /// Register a connected, capable peer on `ip`, if `ip` is free.
    fn promote(&mut self, ip: IpAddr) -> Vec<ServerChange> {
        let next = self
            .conns
            .values()
            .filter(|&&(p, i)| {
                i == ip
                    && self.capable.contains(&p)
                    && !self.servers.contains_key(&p)
                    && !self.pinned.contains_key(&p)
            })
            .map(|&(p, _)| p)
            .min();
        next.map(|peer| self.register(peer, ip)).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ServerChange::{Add, AddAt, Remove};

    /// The node's routability rule, widened to the documentation ranges the
    /// tests use in place of real public addresses.
    fn routable(addr: &Multiaddr) -> bool {
        let documentation = addr.iter().any(|p| match p {
            Protocol::Ip4(ip) => ip.is_documentation(),
            _ => false,
        });
        documentation || crate::node::is_routable(addr)
    }

    struct Net {
        servers: ProbeServers,
        next_conn: usize,
    }

    impl Net {
        fn new() -> Self {
            Self {
                servers: ProbeServers::new(routable, true, true),
                next_conn: 0,
            }
        }

        /// Connect `peer` from `ip` and report its identify.
        fn identified(
            &mut self,
            peer: PeerId,
            ip: &str,
            serves: bool,
        ) -> (ConnectionId, Vec<ServerChange>) {
            let conn = self.connect(peer, ip);
            (conn, self.servers.on_identify(conn, peer, serves))
        }

        fn connect(&mut self, peer: PeerId, ip: &str) -> ConnectionId {
            self.next_conn += 1;
            let conn = ConnectionId::new_unchecked(self.next_conn);
            let ip: IpAddr = ip.parse().unwrap();
            let remote = Multiaddr::from(ip).with(Protocol::Tcp(8336));
            assert!(self.servers.on_connection(conn, peer, &remote).is_empty());
            conn
        }
    }

    #[test]
    fn only_peers_that_serve_autonat_become_servers() {
        let mut net = Net::new();
        let peer = PeerId::random();
        let (conn, changes) = net.identified(peer, "203.0.113.1", false);
        assert!(changes.is_empty());
        assert_eq!(net.servers.on_identify(conn, peer, true), vec![Add(peer)]);
        // Repeated identify (push) changes nothing.
        assert!(net.servers.on_identify(conn, peer, true).is_empty());
        // A peer that stops serving AutoNAT is dropped.
        assert_eq!(
            net.servers.on_identify(conn, peer, false),
            vec![Remove(peer)]
        );
        assert_eq!(net.servers.count(), 0);
    }

    /// Many nodes behind one IP give one server.
    #[test]
    fn one_server_per_remote_ip() {
        let mut net = Net::new();
        let first = PeerId::random();
        assert_eq!(
            net.identified(first, "198.51.100.7", true).1,
            vec![Add(first)]
        );
        for _ in 0..150 {
            assert!(net
                .identified(PeerId::random(), "198.51.100.7", true)
                .1
                .is_empty());
        }
        let other = PeerId::random();
        assert_eq!(
            net.identified(other, "203.0.113.9", true).1,
            vec![Add(other)]
        );
        assert_eq!(net.servers.count(), 2);
        assert_eq!(
            net.servers.ip_of_server(&first),
            Some("198.51.100.7".parse().unwrap())
        );
    }

    #[test]
    fn non_routable_remote_ips_give_no_server() {
        let mut net = Net::new();
        for ip in ["10.1.2.3", "127.0.0.1", "192.168.1.20"] {
            assert!(
                net.identified(PeerId::random(), ip, true).1.is_empty(),
                "{ip}"
            );
        }
    }

    /// A disconnected server frees its IP for another capable peer there.
    #[test]
    fn a_freed_ip_passes_to_another_peer_on_it() {
        let mut net = Net::new();
        let (a, b) = (PeerId::random(), PeerId::random());
        let (conn_a, _) = net.identified(a, "198.51.100.7", true);
        let conn_a2 = net.connect(a, "198.51.100.7");
        let (conn_b, changes) = net.identified(b, "198.51.100.7", true);
        assert!(changes.is_empty());
        // Another connection of A remains: nothing changes.
        assert!(net.servers.on_connection_closed(conn_a, a, 1).is_empty());
        assert_eq!(
            net.servers.on_connection_closed(conn_a2, a, 0),
            vec![Remove(a), Add(b)]
        );
        assert_eq!(
            net.servers.on_connection_closed(conn_b, b, 0),
            vec![Remove(b)]
        );
        assert_eq!(net.servers.count(), 0);
    }

    /// Configured peers are servers from the start and hold their IP, until
    /// identify shows they do not serve AutoNAT.
    #[test]
    fn configured_peers_hold_their_ip_while_they_serve() {
        let mut net = Net::new();
        let archive = PeerId::random();
        let addr: Multiaddr = format!("/ip4/192.0.2.10/tcp/8336/p2p/{archive}")
            .parse()
            .unwrap();
        assert!(net.servers.pin(archive, &[addr]).is_empty());
        assert_eq!(net.servers.count(), 1);
        let peer = PeerId::random();
        assert!(net.identified(peer, "192.0.2.10", true).1.is_empty());
        let (conn, changes) = net.identified(archive, "192.0.2.10", true);
        assert!(changes.is_empty());
        // A configured peer stays a server when disconnected.
        assert!(net
            .servers
            .on_connection_closed(conn, archive, 0)
            .is_empty());
        let conn = net.connect(archive, "192.0.2.10");
        assert_eq!(
            net.servers.on_identify(conn, archive, false),
            vec![Remove(archive), Add(peer)]
        );
    }

    /// A configured peer known by name takes its IP once it connects, and a
    /// server already on that IP gives way.
    #[test]
    fn a_configured_peer_displaces_a_server_on_its_ip() {
        let mut net = Net::new();
        let peer = PeerId::random();
        assert_eq!(net.identified(peer, "192.0.2.10", true).1, vec![Add(peer)]);
        let archive = PeerId::random();
        let addr: Multiaddr = "/dns4/archive.example.com/tcp/8336".parse().unwrap();
        assert!(net.servers.pin(archive, &[addr]).is_empty());
        let remote: Multiaddr = "/ip4/192.0.2.10/tcp/8336".parse().unwrap();
        let conn = ConnectionId::new_unchecked(1_000);
        assert_eq!(
            net.servers.on_connection(conn, archive, &remote),
            vec![Remove(peer)]
        );
        assert_eq!(
            net.servers.ip_of_server(&archive),
            Some("192.0.2.10".parse().unwrap())
        );
        assert_eq!(net.servers.count(), 1);
    }

    /// An IPv6 site counts once: addresses in one /48 (a usual site
    /// allocation, free from a tunnel broker) give one server, so its
    /// holder cannot fill this node's server list from its /64s.
    #[test]
    fn ipv6_servers_count_by_their_slash_48() {
        let mut net = Net::new();
        let first = PeerId::random();
        assert_eq!(
            net.identified(first, "2001:db8:1:2::1", true).1,
            vec![Add(first)]
        );
        assert!(net
            .identified(PeerId::random(), "2001:db8:1:2:ffff::9", true)
            .1
            .is_empty());
        let second = net.identified(PeerId::random(), "2001:db8:1:3::1", true).1;
        println!("REACH autonat server inside one /48 identified");
        assert!(
            second.is_empty(),
            "a second /64 inside one /48 gave a second server"
        );
        let other = PeerId::random();
        assert_eq!(
            net.identified(other, "2001:db8:2:3::1", true).1,
            vec![Add(other)]
        );
        assert_eq!(net.servers.count(), 2);
        assert_eq!(
            net.servers.ip_of_server(&first),
            Some("2001:db8:1::".parse().unwrap())
        );
    }

    /// A server dials back over the family it sees us on: peers on a family
    /// this node does not listen on would only report dial errors.
    #[test]
    fn servers_of_an_unlistened_family_are_not_registered() {
        let mut net = Net {
            servers: ProbeServers::new(routable, true, false),
            next_conn: 0,
        };
        assert!(net
            .identified(PeerId::random(), "2001:db8:1:2::1", true)
            .1
            .is_empty());
        let v4 = PeerId::random();
        assert_eq!(net.identified(v4, "198.51.100.7", true).1, vec![Add(v4)]);
        let archive = PeerId::random();
        let addr: Multiaddr = "/ip6/2001:db8:5::1/tcp/8336".parse().unwrap();
        assert_eq!(net.servers.pin(archive, &[addr]), vec![Remove(archive)]);
        assert_eq!(net.servers.count(), 1);
    }

    /// The node pins a configured peer at every address it is listed at.
    fn pin_listed(
        servers: &mut ProbeServers,
        peer: PeerId,
        addrs: &[Multiaddr],
    ) -> Vec<ServerChange> {
        servers.pin(peer, addrs)
    }

    /// An archive listed at its IPv4 and its IPv6 address, in either order,
    /// stays a server on a node listening on IPv4 only, on IPv6 only, or on
    /// both. On one family it holds that family's IP group; on both it
    /// takes the IP of the connection it opens.
    #[test]
    fn an_archive_at_both_families_stays_a_server_on_any_listener() {
        let v4: Multiaddr = "/ip4/192.0.2.10/udp/8336/quic-v1".parse().unwrap();
        let v6: Multiaddr = "/ip6/2001:db8:5::1/udp/8336/quic-v1".parse().unwrap();
        let v4_ip: IpAddr = "192.0.2.10".parse().unwrap();
        let v6_group: IpAddr = "2001:db8:5::".parse().unwrap();
        for (listen_v4, listen_v6, held) in [
            (true, false, Some(v4_ip)),
            (false, true, Some(v6_group)),
            (true, true, None),
        ] {
            for addrs in [[v4.clone(), v6.clone()], [v6.clone(), v4.clone()]] {
                let mut net = Net {
                    servers: ProbeServers::new(routable, listen_v4, listen_v6),
                    next_conn: 0,
                };
                let archive = PeerId::random();
                let changes = pin_listed(&mut net.servers, archive, &addrs);
                eprintln!("REACH v6-bootstrap checked");
                let case = format!("listen v4 {listen_v4} v6 {listen_v6}, listed {addrs:?}");
                assert!(
                    !changes.contains(&Remove(archive)),
                    "an archive listed at both families lost its server ({case}): {changes:?}"
                );
                assert_eq!(net.servers.count(), 1, "{case}");
                assert_eq!(net.servers.ip_of_server(&archive), held, "{case}");
                if held.is_none() {
                    net.connect(archive, "2001:db8:5::1");
                    assert_eq!(net.servers.ip_of_server(&archive), Some(v6_group), "{case}");
                }
            }
        }
    }

    /// Opens a connection to `peer` from `ip`; the changes it makes.
    fn open(net: &mut Net, peer: PeerId, ip: &str) -> (ConnectionId, Vec<ServerChange>) {
        net.next_conn += 1;
        let conn = ConnectionId::new_unchecked(net.next_conn);
        let remote = Multiaddr::from(ip.parse::<IpAddr>().unwrap()).with(Protocol::Udp(8336));
        (conn, net.servers.on_connection(conn, peer, &remote))
    }

    /// A node listening on one family, with an archive pinned at its address
    /// there: the archive's address, its IP in the other family, and the
    /// archive.
    fn pinned_archive(listen_v6: bool) -> (Net, Multiaddr, &'static str, PeerId) {
        let (own, other) = if listen_v6 {
            ("/ip6/2001:db8:5::1/udp/8336/quic-v1", "192.0.2.10")
        } else {
            ("/ip4/192.0.2.10/udp/8336/quic-v1", "2001:db8:5::1")
        };
        let own: Multiaddr = own.parse().unwrap();
        let mut net = Net {
            servers: ProbeServers::new(routable, !listen_v6, listen_v6),
            next_conn: 0,
        };
        let archive = PeerId::random();
        assert!(net
            .servers
            .pin(archive, std::slice::from_ref(&own))
            .is_empty());
        assert_eq!(
            net.servers.count(),
            1,
            "the pinned archive serves (listen v6 {listen_v6})"
        );
        (net, own, other, archive)
    }

    /// An archive pinned at its address in the listened family that
    /// connects over the other family (its listened address did not answer)
    /// is no server while that connection is open: AutoNAT would probe over
    /// it and the archive would dial back over a family this node does not
    /// listen on. When the connection closes it serves again, at its pinned
    /// address, and counts again.
    #[test]
    fn an_archive_over_the_unlistened_family_serves_again_once_that_connection_closes() {
        for listen_v6 in [false, true] {
            let (mut net, own, other, archive) = pinned_archive(listen_v6);
            let (conn, changes) = open(&mut net, archive, other);
            eprintln!("REACH v6-bootstrap checked: listen v6 {listen_v6}, opened {changes:?}");
            assert_eq!(
                changes,
                vec![Remove(archive)],
                "an archive connected over the unlistened family stayed a server (listen v6 \
                 {listen_v6})"
            );
            assert_eq!(
                net.servers.count(),
                0,
                "a suspended archive is counted as a server (listen v6 {listen_v6})"
            );
            let changes = net.servers.on_connection_closed(conn, archive, 0);
            assert_eq!(
                changes,
                vec![AddAt(archive, vec![own.clone()])],
                "an archive whose unlistened-family connection closed was not added back at its \
                 pinned address (listen v6 {listen_v6})"
            );
            assert_eq!(net.servers.count(), 1, "listen v6 {listen_v6}");
            assert_eq!(
                net.servers.ip_of_server(&archive),
                ip_of(&own).map(ip_group),
                "listen v6 {listen_v6}"
            );
        }
    }

    /// An archive with a connection in each family is no server until the
    /// unlistened family's connection closes, in either opening order;
    /// closing its listened-family connection first changes nothing.
    #[test]
    fn an_archive_with_both_families_open_serves_once_the_unlistened_one_closes() {
        for listen_v6 in [false, true] {
            let (mut net, own, other, archive) = pinned_archive(listen_v6);
            let own_ip = ip_of(&own).unwrap().to_string();
            let (listened, changes) = open(&mut net, archive, &own_ip);
            assert!(changes.is_empty(), "listen v6 {listen_v6}: {changes:?}");
            let (unlistened, changes) = open(&mut net, archive, other);
            assert_eq!(changes, vec![Remove(archive)], "listen v6 {listen_v6}");
            let changes = net.servers.on_connection_closed(listened, archive, 1);
            eprintln!(
                "REACH v6-bootstrap checked: listen v6 {listen_v6}, closed listened {changes:?}"
            );
            assert!(
                changes.is_empty(),
                "an archive served again while its unlistened-family connection was open \
                 (listen v6 {listen_v6}): {changes:?}"
            );
            assert_eq!(net.servers.count(), 0, "listen v6 {listen_v6}");
            assert_eq!(
                net.servers.on_connection_closed(unlistened, archive, 0),
                vec![AddAt(archive, vec![own.clone()])],
                "listen v6 {listen_v6}"
            );
            // The other order: the unlistened family first.
            let (unlistened, changes) = open(&mut net, archive, other);
            assert_eq!(changes, vec![Remove(archive)], "listen v6 {listen_v6}");
            let (listened, changes) = open(&mut net, archive, &own_ip);
            assert!(
                changes.is_empty(),
                "an archive served again while its unlistened-family connection was open \
                 (listen v6 {listen_v6}): {changes:?}"
            );
            assert_eq!(
                net.servers.on_connection_closed(unlistened, archive, 1),
                vec![AddAt(archive, vec![own.clone()])],
                "listen v6 {listen_v6}"
            );
            assert!(net
                .servers
                .on_connection_closed(listened, archive, 0)
                .is_empty());
            assert_eq!(net.servers.count(), 1, "listen v6 {listen_v6}");
        }
    }

    /// A configured peer listed at a DNS name only is removed for good by a
    /// first connection over a family this node does not listen on, as
    /// before IPv6 entries: its family is unknown until it connects.
    #[test]
    fn a_peer_pinned_at_a_dns_name_over_the_unlistened_family_stays_removed() {
        let mut net = Net {
            servers: ProbeServers::new(routable, true, false),
            next_conn: 0,
        };
        let archive = PeerId::random();
        let addr: Multiaddr = "/dns/archive.example.com/udp/8336/quic-v1".parse().unwrap();
        assert!(net.servers.pin(archive, &[addr]).is_empty());
        let (conn, changes) = open(&mut net, archive, "2001:db8:5::1");
        assert_eq!(changes, vec![Remove(archive)]);
        let changes = net.servers.on_connection_closed(conn, archive, 0);
        eprintln!("REACH v6-bootstrap checked: dns pin closed {changes:?}");
        assert!(
            changes.is_empty(),
            "a peer pinned at a DNS name came back after an unlistened-family connection: \
             {changes:?}"
        );
        assert_eq!(net.servers.count(), 0);
    }

    /// Probes go only to registered servers, at AutoNAT's own rate.
    #[test]
    fn autonat_draws_only_registered_servers_at_its_own_rate() {
        let config = autonat_config();
        assert!(!config.use_connected);
        let defaults = libp2p::autonat::Config::default();
        assert_eq!(
            config,
            libp2p::autonat::Config {
                use_connected: false,
                ..defaults
            }
        );
    }
}

/// A server's dial-backs, over real TCP swarms on loopback.
#[cfg(test)]
mod dial_back_tests {
    use std::time::Duration;

    use futures::StreamExt;
    use libp2p::autonat::{
        Behaviour, Config, Event, InboundProbeError, InboundProbeEvent, ResponseError,
    };
    use libp2p::multiaddr::Protocol;
    use libp2p::swarm::SwarmEvent;
    use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder};

    /// Bound for each step: connection set-up and one request.
    const STEP: Duration = Duration::from_secs(60);

    /// The connection and request timeouts of the test swarms, far beyond
    /// any test: a dial-back to an address that never answers, and its
    /// request, stay in progress until the test ends, however loaded the
    /// host. With the defaults (10 s and 30 s) a slow step let the first
    /// dial-back end before the next client asked.
    const NEVER: Duration = Duration::from_secs(3600);

    fn swarm(config: Config) -> Swarm<Behaviour> {
        SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .expect("tcp transport")
            .with_behaviour(|key| Behaviour::new(key.public().to_peer_id(), config))
            .expect("behaviour")
            .with_swarm_config(|c| c.with_idle_connection_timeout(NEVER))
            .with_connection_timeout(NEVER)
            .build()
    }

    /// A server listening on loopback that never probes; its peer ID and
    /// address.
    async fn listening_server() -> (Swarm<Behaviour>, PeerId, Multiaddr) {
        let mut server = swarm(Config {
            boot_delay: NEVER,
            only_global_ips: false,
            timeout: NEVER,
            ..Config::default()
        });
        let server_id = *server.local_peer_id();
        server
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .expect("listen");
        let server_addr = tokio::time::timeout(STEP, async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                    return address;
                }
            }
        })
        .await
        .expect("server listens");
        (server, server_id, server_addr)
    }

    /// An address at `ip` where the kernel completes TCP connections into
    /// the backlog of a listener nobody accepts from, and nothing answers
    /// on them; with the listener, which must stay open.
    fn silent(ip: &str) -> (std::net::TcpListener, Multiaddr) {
        let listener = std::net::TcpListener::bind((ip, 0)).expect("silent listener");
        let port = listener.local_addr().expect("silent address").port();
        let addr = format!("/ip4/{ip}/tcp/{port}").parse().unwrap();
        (listener, addr)
    }

    /// A client polled in the background that asks `server` at
    /// `server_addr` to dial it back at `candidate` only (it listens
    /// nowhere); its peer ID.
    fn spawn_client(server: PeerId, server_addr: &Multiaddr, candidate: &Multiaddr) -> PeerId {
        let mut client = swarm(Config {
            boot_delay: Duration::ZERO,
            use_connected: false,
            only_global_ips: false,
            timeout: NEVER,
            ..Config::default()
        });
        client
            .behaviour_mut()
            .add_server(server, Some(server_addr.clone()));
        client.behaviour_mut().probe_address(candidate.clone());
        let id = *client.local_peer_id();
        tokio::spawn(async move {
            loop {
                client.select_next_some().await;
            }
        });
        id
    }

    /// A client at `ip`, dialed by `server` so that the server observes it
    /// at `ip`, then polled in the background; it asks `server` to dial it
    /// back at `candidate` only. It listens only until the server is
    /// connected, so its request offers no listen address. Its peer ID.
    async fn client_dialed_at(
        server: &mut Swarm<Behaviour>,
        ip: &str,
        candidate: &Multiaddr,
    ) -> PeerId {
        // Probes before the server is added find none and retry a second
        // later; after its answer the server stays throttled for the test.
        let mut client = swarm(Config {
            boot_delay: Duration::ZERO,
            retry_interval: Duration::from_secs(1),
            use_connected: false,
            only_global_ips: false,
            timeout: NEVER,
            ..Config::default()
        });
        let id = *client.local_peer_id();
        let server_id = *server.local_peer_id();
        let listener = client
            .listen_on(format!("/ip4/{ip}/tcp/0").parse().unwrap())
            .expect("client listens");
        let at = tokio::time::timeout(STEP, async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = client.select_next_some().await {
                    return address;
                }
            }
        })
        .await
        .expect("client listens");
        server
            .dial(at.with(Protocol::P2p(id)))
            .expect("server dials the client");
        tokio::time::timeout(STEP, async {
            loop {
                tokio::select! {
                    event = client.select_next_some() => {
                        if matches!(
                            event,
                            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == server_id
                        ) {
                            return;
                        }
                    }
                    event = server.select_next_some() => {
                        if let SwarmEvent::Behaviour(Event::InboundProbe(event)) = event {
                            panic!("dial-back event while a client connected: {event:?}");
                        }
                    }
                }
            }
        })
        .await
        .expect("server connects to the client");
        assert!(client.remove_listener(listener));
        tokio::time::timeout(STEP, async {
            loop {
                if let SwarmEvent::ListenerClosed { .. } = client.select_next_some().await {
                    return;
                }
            }
        })
        .await
        .expect("client stops listening");
        client.behaviour_mut().add_server(server_id, None);
        client.behaviour_mut().probe_address(candidate.clone());
        tokio::spawn(async move {
            loop {
                client.select_next_some().await;
            }
        });
        id
    }

    /// The server's next dial-back event, with its client.
    async fn next_inbound(server: &mut Swarm<Behaviour>) -> (PeerId, InboundProbeEvent) {
        let next = async {
            loop {
                if let SwarmEvent::Behaviour(Event::InboundProbe(event)) =
                    server.select_next_some().await
                {
                    let peer = match &event {
                        InboundProbeEvent::Request { peer, .. }
                        | InboundProbeEvent::Response { peer, .. }
                        | InboundProbeEvent::Error { peer, .. } => *peer,
                    };
                    return (peer, event);
                }
            }
        };
        tokio::time::timeout(STEP, next)
            .await
            .expect("no dial-back event within the step bound")
    }

    /// Whether `event` refused a request, which leaves the client's status
    /// unchanged.
    fn refused(event: &InboundProbeEvent) -> bool {
        matches!(
            event,
            InboundProbeEvent::Error {
                error: InboundProbeError::Response(ResponseError::DialRefused),
                ..
            }
        )
    }

    /// QUILIBRIUM: a server runs one dial-back at a time per client IP (an
    /// IPv6 /48), whatever the peer IDs behind it. Each dial-back holds one
    /// of the few the server runs at once until it connects or its last
    /// address times out, so one host with a few identities asking for
    /// addresses that never answer held them all, and with them every
    /// other node's probes to that server. Here the first client's address
    /// accepts TCP and never answers the handshake, so its dial-back stays
    /// in progress; a second peer ID from the same IP is then refused,
    /// which leaves its status unchanged.
    #[tokio::test]
    async fn one_ip_gets_one_dial_back_at_a_time_whatever_its_peer_ids() {
        let (mut server, server_id, server_addr) = listening_server().await;
        let (_silent, silent_addr) = silent("127.0.0.1");

        let first = spawn_client(server_id, &server_addr, &silent_addr);
        let (peer, event) = next_inbound(&mut server).await;
        assert_eq!(peer, first, "first event from another client: {event:?}");
        assert!(
            matches!(event, InboundProbeEvent::Request { .. }),
            "first client's request refused: {event:?}"
        );

        let second = spawn_client(server_id, &server_addr, &silent_addr);
        let (peer, event) = next_inbound(&mut server).await;
        println!("REACH autonat second peer ID's request handled");
        assert_eq!(
            peer, second,
            "the first client's dial-back ended before the second asked: {event:?}"
        );
        assert!(refused(&event), "second dial-back from one IP: {event:?}");
    }

    /// QUILIBRIUM: IPv4 clients count by their /24 for a dial-back: two
    /// run at once, at two addresses. Sixteen addresses of one /28, a
    /// cheap rented block, each asking for addresses that never answer,
    /// held every dial-back a server runs at once, the same sixteen
    /// against every server; with one at a time per /24, one address
    /// there kept every other one's probes refused. Here a client at
    /// 127.0.0.16, a second peer ID at that address, then a client at each
    /// other address of 127.0.0.16/28 ask in turn while the dial-backs
    /// started stay in progress: the first and the one at 127.0.0.17 run,
    /// and the others are refused, which leaves their status unchanged.
    #[tokio::test]
    async fn one_ipv4_24_gets_two_dial_backs_at_a_time() {
        let (mut server, ..) = listening_server().await;
        let mut silent_listeners = Vec::new();
        let mut running: Vec<String> = Vec::new();
        for n in 16..32 {
            let ip = format!("127.0.0.{n}");
            let (listener, candidate) = silent(&ip);
            silent_listeners.push(listener);
            // A second peer ID at the first address asks right after it.
            let clients_here = if n == 16 { 2 } else { 1 };
            for _ in 0..clients_here {
                let client = client_dialed_at(&mut server, &ip, &candidate).await;
                let (peer, event) = next_inbound(&mut server).await;
                assert_eq!(peer, client, "event from another client: {event:?}");
                match event {
                    InboundProbeEvent::Request { .. } => running.push(ip.clone()),
                    ref event => assert!(refused(event), "request at {ip}: {event:?}"),
                }
            }
        }
        println!("REACH autonat requests from one /28 handled");
        assert!(
            running.len() <= 2,
            "{} dial-backs at once from one IPv4 /28: {running:?}",
            running.len()
        );
        assert!(
            running.iter().filter(|ip| *ip == "127.0.0.16").count() <= 1,
            "second dial-back from one IP of one IPv4 /24: {running:?}"
        );
        assert_eq!(
            running,
            ["127.0.0.16", "127.0.0.17"],
            "a second address of one IPv4 /24 refused while the first ran"
        );
    }
}
