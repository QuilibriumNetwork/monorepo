//! The AutoNAT servers this node probes.
//!
//! AutoNAT v1 sends each probe to a random server. Upstream draws from every
//! connected peer, so an operator running many nodes behind one IP receives
//! a matching share of the probes, and peers that do not serve AutoNAT are
//! drawn as well. [`ProbeServers`] registers a peer only once identify shows
//! that it serves AutoNAT, at most one peer per remote IP (an IPv6 address
//! counts by its /64), and only peers reached over an address family this
//! node listens on, since a server dials back over the family it sees. The
//! configured archive and bootstrap peers are registered from the start, so
//! the first probe, 15 s after start, does not wait for identify. AutoNAT
//! keeps its own probe rate.

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

/// The operator group of a remote IP: an IPv6 address counts by its /64,
/// which one site or host typically holds whole.
pub(crate) fn ip_group(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1))),
    }
}

/// A change to AutoNAT's server list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServerChange {
    Add(PeerId),
    Remove(PeerId),
}

/// Apply `changes` to AutoNAT. Configured peers are added by the caller,
/// with their address.
pub(crate) fn apply(autonat: &mut libp2p::autonat::Behaviour, changes: Vec<ServerChange>) {
    for change in changes {
        match change {
            ServerChange::Add(peer) => autonat.add_server(peer, None),
            ServerChange::Remove(peer) => autonat.remove_server(&peer),
        }
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
    /// AutoNAT; their IP once known.
    pinned: HashMap<PeerId, Option<IpAddr>>,
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

    /// The configured peer `peer` at `addr` is a server; the caller adds it
    /// to AutoNAT with its address. It takes its IP from another server.
    /// One on an address family this node does not listen on is removed.
    pub(crate) fn pin(&mut self, peer: PeerId, addr: &Multiaddr) -> Vec<ServerChange> {
        if let Some(ip) = self.servers.remove(&peer) {
            self.by_ip.remove(&ip);
        }
        let ip = ip_of(addr).map(ip_group);
        if ip.is_some_and(|ip| !self.listened(ip)) {
            return vec![ServerChange::Remove(peer)];
        }
        self.pinned.insert(peer, ip);
        ip.map(|ip| self.evict(ip)).unwrap_or_default()
    }

    /// A connection to `peer` from `remote` opened.
    pub(crate) fn on_connection(
        &mut self,
        conn: ConnectionId,
        peer: PeerId,
        remote: &Multiaddr,
    ) -> Vec<ServerChange> {
        let Some(ip) = ip_of(remote).map(ip_group) else {
            return Vec::new();
        };
        self.conns.insert(conn, (peer, ip));
        if self.pinned.get(&peer) == Some(&None) {
            if !self.listened(ip) {
                self.pinned.remove(&peer);
                return vec![ServerChange::Remove(peer)];
            }
            self.pinned.insert(peer, Some(ip));
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
            let ip = self.pinned.remove(&peer).flatten();
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
        self.conns.remove(&conn);
        if remaining > 0 {
            return Vec::new();
        }
        // A configured peer stays a server: AutoNAT dials it when needed.
        self.capable.remove(&peer);
        self.release(peer)
    }

    /// The remote IP group of server `peer` (see [`ip_group`]), if known.
    pub(crate) fn ip_of_server(&self, peer: &PeerId) -> Option<IpAddr> {
        self.servers
            .get(peer)
            .copied()
            .or_else(|| self.pinned.get(peer).copied().flatten())
            .or_else(|| {
                self.conns
                    .values()
                    .find_map(|&(p, ip)| (p == *peer).then_some(ip))
            })
    }

    /// How many servers AutoNAT holds.
    pub(crate) fn count(&self) -> usize {
        self.pinned.len() + self.servers.len()
    }

    fn listened(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.listen_v4,
            IpAddr::V6(_) => self.listen_v6,
        }
    }

    fn ip_taken(&self, ip: IpAddr) -> bool {
        self.by_ip.contains_key(&ip) || self.pinned.values().any(|p| *p == Some(ip))
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
    use ServerChange::{Add, Remove};

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
        assert!(net.servers.pin(archive, &addr).is_empty());
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
        assert!(net.servers.pin(archive, &addr).is_empty());
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

    /// An IPv6 site counts once: addresses in one /64 give one server.
    #[test]
    fn ipv6_servers_count_by_their_slash_64() {
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
        let other = PeerId::random();
        assert_eq!(
            net.identified(other, "2001:db8:1:3::1", true).1,
            vec![Add(other)]
        );
        assert_eq!(
            net.servers.ip_of_server(&first),
            Some("2001:db8:1:2::".parse().unwrap())
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
        assert_eq!(net.servers.pin(archive, &addr), vec![Remove(archive)]);
        assert_eq!(net.servers.count(), 1);
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
