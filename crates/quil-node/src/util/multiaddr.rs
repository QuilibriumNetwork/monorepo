/// Convert an `/ip4/X/tcp/Y` or `/ip6/X/tcp/Y` multiaddr string into `X:Y`
/// (`[X]:Y`). Returns `None` for unsupported multiaddr shapes (DNS, non-TCP)
/// so we don't try to dial non-routable archive endpoints. Filters loopback
/// and private ranges since those would only resolve to our own machine.
#[allow(dead_code)]
pub(crate) fn multiaddr_to_host_port(ma: &str) -> Option<String> {
    multiaddr_to_host_port_with_network(ma, 0)
}

/// Like `multiaddr_to_host_port`, but on testnet/devnet (network != 0)
/// accepts RFC1918 private addresses (192.168.x.x, 10.x.x.x, etc.) and
/// loopback. Mainnet still rejects them so a misconfigured archive
/// doesn't poison the pool with unroutable peers.
pub(crate) fn multiaddr_to_host_port_with_network(ma: &str, network: u8) -> Option<String> {
    match ma.trim_start_matches('/').split('/').next() {
        Some("ip4" | "ip6") => archive_multiaddr_to_host_port(ma, network),
        _ => None,
    }
}

/// The `host:port` the peer gRPC server binds for
/// `p2p.streamListenMultiaddr`, `/ip4/H/tcp/P` or `/ip6/H/tcp/P`; `None` for
/// any other shape.
pub(crate) fn stream_listen_host_port(ma: &str) -> Option<String> {
    let parts: Vec<&str> = ma.trim_start_matches('/').split('/').collect();
    if parts.len() < 4 || parts[2] != "tcp" {
        return None;
    }
    match parts[0] {
        "ip4" => Some(format!("{}:{}", parts[1], parts[3])),
        "ip6" => Some(format!("[{}]:{}", parts[1], parts[3])),
        _ => None,
    }
}

/// Whether a p2p listen address on IPv6 leaves peers without a stream address
/// to dial: the stream listener takes IPv4 only and no announce override names
/// another. PeerInfo then carries no stream address.
pub(crate) fn ipv6_p2p_without_stream(listen: &str, stream_listen: &str, announce: &str) -> bool {
    let is_ip6 = |ma: &str| ma.trim_start_matches('/').starts_with("ip6/");
    is_ip6(listen) && !is_ip6(stream_listen) && announce.is_empty()
}

/// The stream endpoint of a peer-info `host:port`: the pubsub port replaced by
/// the stream port. Only the port: an IPv6 host may hold the same digits.
pub(crate) fn pubsub_to_stream_endpoint(addr: &str) -> String {
    match addr.rsplit_once(':') {
        Some((host, "8336")) => format!("{host}:8340"),
        _ => addr.to_string(),
    }
}

/// Parse a libp2p multiaddr string from `engine.archiveEndpoints` into a
/// `host:port` the mTLS gRPC client can dial. Matches what the Go node's
/// `manet.ToNetAddr` accepts for archive client setup: `/ip4/`, `/ip6/`,
/// `/dns4/`, `/dns6/`, `/dns/` over `/tcp/PORT`. Bare `host:port` is
/// rejected so configs round-trip between Go and Rust.
///
/// IP forms apply the same private/loopback/unspecified filtering as
/// `multiaddr_to_host_port_with_network` (gated on `network`). DNS forms
/// pass the hostname through verbatim — the gRPC client resolves at dial
/// time, which mirrors `manet.ToNetAddr`'s behavior.
pub(crate) fn archive_multiaddr_to_host_port(ma: &str, network: u8) -> Option<String> {
    let parts: Vec<&str> = ma.trim_start_matches('/').split('/').collect();
    if parts.len() < 4 {
        return None;
    }
    if parts[2] != "tcp" {
        return None;
    }
    let port: u16 = parts[3].parse().ok()?;
    let allow_private = network != 0;
    match parts[0] {
        "ip4" => {
            let ip: std::net::Ipv4Addr = parts[1].parse().ok()?;
            let reject = if allow_private {
                ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast()
            } else {
                ip.is_loopback()
                    || ip.is_private()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_broadcast()
                    || ip.is_multicast()
            };
            if reject {
                return None;
            }
            Some(format!("{}:{}", ip, port))
        }
        "ip6" => {
            let ip: std::net::Ipv6Addr = parts[1].parse().ok()?;
            let reject = if allow_private {
                ip.is_unspecified() || ip.is_multicast()
            } else {
                ip.is_loopback() || ip.is_unspecified() || ip.is_multicast()
                    || (ip.segments()[0] & 0xfe00) == 0xfc00  // unique-local fc00::/7
                    || (ip.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
            };
            if reject {
                return None;
            }
            Some(format!("[{}]:{}", ip, port))
        }
        "dns4" | "dns6" | "dns" => {
            let host = parts[1];
            if host.is_empty() {
                return None;
            }
            Some(format!("{}:{}", host, port))
        }
        _ => None,
    }
}

/// The peer an `engine.archiveEndpoints` multiaddr names (`.../p2p/<id>`),
/// which a dial to its endpoint must then reach; `None` when it names none
/// or the id does not parse.
pub(crate) fn archive_multiaddr_peer(ma: &str) -> Option<quil_p2p::PeerId> {
    let parts: Vec<&str> = ma.trim_start_matches('/').split('/').collect();
    parts
        .windows(2)
        .find(|pair| pair[0] == "p2p")
        .and_then(|pair| pair[1].parse().ok())
}

/// Build a stream multiaddr by extracting the IP from a pubsub multiaddr and
/// combining it with the port/protocol from the stream listen pattern.
///
/// IP precedence: prefer the pubsub IP (it's the address peers actually
/// see us on) when the stream listener takes its family; if that's a wildcard
/// or loopback, fall back to the stream listen IP (covers testnet bootstraps
/// where listen_multiaddr is `/ip4/0.0.0.0/...` but stream_listen has the real
/// LAN IP). `/ip6/::` takes both families (see `stream_listener`), any other
/// `/ip6` address IPv6, and everything else IPv4, the fallback included.
pub(crate) fn extract_stream_addr(pubsub_ma: &str, stream_listen: &str) -> Option<String> {
    let pub_parts: Vec<&str> = pubsub_ma.trim_start_matches('/').split('/').collect();
    let stream_parts: Vec<&str> = stream_listen.trim_start_matches('/').split('/').collect();

    if stream_parts.len() < 4 {
        return None;
    }
    let protocol = stream_parts[2]; // "tcp"
    let port = stream_parts[3]; // "8340"
    let (stream_family, stream_ip) = (stream_parts[0], stream_parts[1]);

    let usable = |family: &str, ip: &str| -> bool {
        match family {
            "ip4" => ip != "0.0.0.0" && ip != "127.0.0.1",
            "ip6" => ip
                .parse::<std::net::Ipv6Addr>()
                .is_ok_and(|ip| !ip.is_unspecified() && !ip.is_loopback()),
            _ => false,
        }
    };
    let listener_takes = |family: &str| -> bool {
        if stream_family != "ip6" {
            return family == "ip4";
        }
        family == "ip6"
            || stream_ip
                .parse::<std::net::Ipv6Addr>()
                .is_ok_and(|ip| ip.is_unspecified())
    };

    if pub_parts.len() >= 2 && usable(pub_parts[0], pub_parts[1]) && listener_takes(pub_parts[0]) {
        let (family, ip) = (pub_parts[0], pub_parts[1]);
        return Some(format!("/{family}/{ip}/{protocol}/{port}"));
    }
    if usable(stream_family, stream_ip) {
        return Some(format!("/{stream_family}/{stream_ip}/{protocol}/{port}"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{archive_multiaddr_peer, archive_multiaddr_to_host_port};
    use super::{
        extract_stream_addr, ipv6_p2p_without_stream, multiaddr_to_host_port,
        multiaddr_to_host_port_with_network, pubsub_to_stream_endpoint, stream_listen_host_port,
    };

    #[test]
    fn archive_multiaddr_names_its_peer_only_with_a_valid_p2p_id() {
        let id = "QmRECrGL6yDoMgSydFDN5bhnnpJLAByKVuieAbwmmAiodC";
        assert_eq!(
            archive_multiaddr_peer(&format!("/ip4/165.140.86.86/tcp/8340/p2p/{id}"))
                .map(|peer| peer.to_string()),
            Some(id.to_string())
        );
        assert_eq!(archive_multiaddr_peer("/ip4/165.140.86.86/tcp/8340"), None);
        assert_eq!(
            archive_multiaddr_peer("/ip4/165.140.86.86/tcp/8340/p2p/not-a-peer"),
            None
        );
    }

    #[test]
    fn archive_multiaddr_accepts_ip4() {
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/1.2.3.4/tcp/8340", 0),
            Some("1.2.3.4:8340".into())
        );
    }

    #[test]
    fn archive_multiaddr_accepts_ip6() {
        assert_eq!(
            archive_multiaddr_to_host_port("/ip6/2001:db8::1/tcp/8340", 0),
            Some("[2001:db8::1]:8340".into())
        );
    }

    #[test]
    fn archive_multiaddr_accepts_dns4() {
        assert_eq!(
            archive_multiaddr_to_host_port("/dns4/archive.example.com/tcp/8340", 0),
            Some("archive.example.com:8340".into())
        );
    }

    #[test]
    fn archive_multiaddr_accepts_dns6() {
        assert_eq!(
            archive_multiaddr_to_host_port("/dns6/archive.example.com/tcp/8340", 0),
            Some("archive.example.com:8340".into())
        );
    }

    #[test]
    fn archive_multiaddr_accepts_dns() {
        assert_eq!(
            archive_multiaddr_to_host_port("/dns/archive.example.com/tcp/8340", 0),
            Some("archive.example.com:8340".into())
        );
    }

    #[test]
    fn archive_multiaddr_rejects_bare_host_port() {
        assert_eq!(
            archive_multiaddr_to_host_port("archive.example.com:8340", 0),
            None
        );
        assert_eq!(archive_multiaddr_to_host_port("1.2.3.4:8340", 0), None);
    }

    #[test]
    fn archive_multiaddr_rejects_non_tcp() {
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/1.2.3.4/udp/8340", 0),
            None
        );
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/1.2.3.4/udp/8340/quic-v1", 0),
            None
        );
    }

    #[test]
    fn archive_multiaddr_rejects_malformed() {
        assert_eq!(archive_multiaddr_to_host_port("", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/ip4/1.2.3.4", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/ip4//tcp/8340", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/ip4/1.2.3.4/tcp/", 0), None);
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/1.2.3.4/tcp/notaport", 0),
            None
        );
        assert_eq!(archive_multiaddr_to_host_port("/dns4//tcp/8340", 0), None);
    }

    #[test]
    fn archive_multiaddr_rejects_private_ip_on_mainnet() {
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/192.168.1.1/tcp/8340", 0),
            None
        );
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/10.0.0.1/tcp/8340", 0),
            None
        );
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/127.0.0.1/tcp/8340", 0),
            None
        );
    }

    #[test]
    fn archive_multiaddr_allows_private_ip_on_devnet() {
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/192.168.1.1/tcp/8340", 1),
            Some("192.168.1.1:8340".into())
        );
        assert_eq!(
            archive_multiaddr_to_host_port("/ip4/127.0.0.1/tcp/8340", 1),
            Some("127.0.0.1:8340".into())
        );
    }

    #[test]
    fn stream_listen_binds_ipv4_and_ipv6_as_written() {
        for (ma, expected) in [
            ("/ip4/0.0.0.0/tcp/8340", "0.0.0.0:8340"),
            ("/ip4/192.0.2.5/tcp/40000", "192.0.2.5:40000"),
            ("/ip6/::/tcp/8340", "[::]:8340"),
            ("/ip6/::1/tcp/8340", "[::1]:8340"),
            ("/ip6/2001:db8::5/tcp/40000", "[2001:db8::5]:40000"),
            ("/ip6/::/tcp/8340/p2p/QmPeer", "[::]:8340"),
        ] {
            assert_eq!(
                stream_listen_host_port(ma).as_deref(),
                Some(expected),
                "{ma}"
            );
            assert!(expected.parse::<std::net::SocketAddr>().is_ok(), "{ma}");
        }
    }

    /// What the caller warns about before falling back: a shape it cannot
    /// bind must not pass for an address.
    #[test]
    fn stream_listen_rejects_shapes_it_cannot_bind() {
        for ma in [
            "",
            "/",
            "/ip6/::",
            "/ip6/::/udp/8340",
            "/ip4/0.0.0.0/udp/8340/quic-v1",
            "/dns6/node.example.com/tcp/8340",
            "not a multiaddr",
        ] {
            assert_eq!(stream_listen_host_port(ma), None, "{ma}");
        }
    }

    #[test]
    fn stream_address_takes_the_ipv6_pubsub_ip_when_the_listener_serves_it() {
        const PUB6: &str = "/ip6/2001:db8::7/udp/8336/quic-v1";
        for stream_listen in ["/ip6/::/tcp/8340", "/ip6/2001:db8::9/tcp/8340"] {
            assert_eq!(
                extract_stream_addr(PUB6, stream_listen).as_deref(),
                Some("/ip6/2001:db8::7/tcp/8340"),
                "{stream_listen}"
            );
        }
        // Wildcard pubsub: the listener's own specific IP.
        assert_eq!(
            extract_stream_addr("/ip6/::/udp/8336/quic-v1", "/ip6/2001:db8::9/tcp/8340").as_deref(),
            Some("/ip6/2001:db8::9/tcp/8340")
        );
        // Nothing a peer could dial.
        for (pubsub, stream_listen) in [
            ("", "/ip6/::/tcp/8340"),
            ("/ip6/::/udp/8336/quic-v1", "/ip6/::/tcp/8340"),
            ("/ip6/::1/udp/8336/quic-v1", "/ip6/::1/tcp/8340"),
        ] {
            assert_eq!(
                extract_stream_addr(pubsub, stream_listen),
                None,
                "{pubsub} {stream_listen}"
            );
        }
    }

    /// The stream address names a host that really takes the family: an IPv6
    /// node with the default IPv4 stream listener announces none, and a
    /// listener on a specific IPv6 address does not serve an IPv4 pubsub IP.
    #[test]
    fn stream_address_never_crosses_to_a_family_its_listener_does_not_serve() {
        const PUB6: &str = "/ip6/2001:db8::7/udp/8336/quic-v1";
        const PUB4: &str = "/ip4/203.0.113.7/udp/8336/quic-v1";
        assert_eq!(extract_stream_addr(PUB6, "/ip4/0.0.0.0/tcp/8340"), None);
        // A specific IPv4 stream IP is announced, as before.
        assert_eq!(
            extract_stream_addr(PUB6, "/ip4/192.0.2.5/tcp/8340").as_deref(),
            Some("/ip4/192.0.2.5/tcp/8340")
        );
        assert_eq!(
            extract_stream_addr(PUB4, "/ip6/2001:db8::9/tcp/8340").as_deref(),
            Some("/ip6/2001:db8::9/tcp/8340")
        );
        assert_eq!(extract_stream_addr(PUB4, "/ip6/::1/tcp/8340"), None);
        // `::` takes IPv4 too.
        assert_eq!(
            extract_stream_addr(PUB4, "/ip6/::/tcp/8340").as_deref(),
            Some("/ip4/203.0.113.7/tcp/8340")
        );
    }

    /// Existing IPv4 configs get exactly what they got.
    #[test]
    fn stream_address_for_ipv4_is_unchanged() {
        const PUB4: &str = "/ip4/203.0.113.7/udp/8336/quic-v1";
        assert_eq!(
            extract_stream_addr(PUB4, "/ip4/0.0.0.0/tcp/8340").as_deref(),
            Some("/ip4/203.0.113.7/tcp/8340")
        );
        assert_eq!(
            extract_stream_addr(PUB4, "/ip4/192.0.2.5/tcp/8340").as_deref(),
            Some("/ip4/203.0.113.7/tcp/8340")
        );
        assert_eq!(
            extract_stream_addr(PUB4, "/dns4/node.example.com/tcp/8340").as_deref(),
            Some("/ip4/203.0.113.7/tcp/8340")
        );
        assert_eq!(
            extract_stream_addr("/ip4/0.0.0.0/tcp/8336", "/ip4/192.0.2.5/tcp/8340").as_deref(),
            Some("/ip4/192.0.2.5/tcp/8340")
        );
        for pubsub in ["", "/ip4/0.0.0.0/tcp/8336", "/ip4/127.0.0.1/tcp/8336"] {
            assert_eq!(extract_stream_addr(pubsub, "/ip4/0.0.0.0/tcp/8340"), None);
        }
    }

    #[test]
    fn published_ipv6_stream_address_reaches_the_archive_pool() {
        assert_eq!(
            multiaddr_to_host_port("/ip6/2001:4860::1/tcp/8340").as_deref(),
            Some("[2001:4860::1]:8340")
        );
        assert_eq!(
            multiaddr_to_host_port("/ip4/8.8.8.8/tcp/8340").as_deref(),
            Some("8.8.8.8:8340")
        );
        for rejected in [
            "/ip6/::1/tcp/8340",
            "/ip6/::/tcp/8340",
            "/ip6/fe80::1/tcp/8340",
            "/ip6/fd00::1/tcp/8340",
            "/ip6/not-an-ip/tcp/8340",
            "/ip6/2001:4860::1/udp/8340",
            "/dns6/archive.example.com/tcp/8340",
            "/ip4/10.0.0.1/tcp/8340",
        ] {
            assert_eq!(multiaddr_to_host_port(rejected), None, "{rejected}");
        }
        // Testnets take loopback, IPv6 like IPv4.
        assert_eq!(
            multiaddr_to_host_port_with_network("/ip6/::1/tcp/8340", 1).as_deref(),
            Some("[::1]:8340")
        );
    }

    #[test]
    fn stream_endpoint_replaces_the_port_only() {
        for (addr, expected) in [
            ("203.0.113.7:8336", "203.0.113.7:8340"),
            ("203.0.113.7:8340", "203.0.113.7:8340"),
            ("[2001:db8::1]:8336", "[2001:db8::1]:8340"),
            ("[2001:db8:8336::1]:8340", "[2001:db8:8336::1]:8340"),
            ("[2001:db8:8336::1]:8336", "[2001:db8:8336::1]:8340"),
        ] {
            assert_eq!(pubsub_to_stream_endpoint(addr), expected, "{addr}");
        }
    }

    #[test]
    fn ipv6_p2p_with_the_default_ipv4_stream_listener_is_flagged() {
        const P6: &str = "/ip6/::/udp/8336/quic-v1";
        assert!(ipv6_p2p_without_stream(P6, "/ip4/0.0.0.0/tcp/8340", ""));
        assert!(!ipv6_p2p_without_stream(P6, "/ip6/::/tcp/8340", ""));
        assert!(!ipv6_p2p_without_stream(
            P6,
            "/ip4/0.0.0.0/tcp/8340",
            "/ip6/2001:db8::7/tcp/8340"
        ));
        assert!(!ipv6_p2p_without_stream(
            "/ip4/0.0.0.0/udp/8336/quic-v1",
            "/ip4/0.0.0.0/tcp/8340",
            ""
        ));
    }
}
