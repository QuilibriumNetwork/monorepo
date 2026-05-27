/// Convert a `/ip4/X/tcp/Y` multiaddr string into `X:Y`. Returns `None` for
/// unsupported multiaddr shapes (DNS, IPv6, non-TCP) so we don't try to dial
/// non-routable archive endpoints. Filters loopback and private ranges since
/// those would only resolve to our own machine.
#[allow(dead_code)]
pub(crate) fn multiaddr_to_host_port(ma: &str) -> Option<String> {
    multiaddr_to_host_port_with_network(ma, 0)
}

/// Like `multiaddr_to_host_port`, but on testnet/devnet (network != 0)
/// accepts RFC1918 private addresses (192.168.x.x, 10.x.x.x, etc.) and
/// loopback. Mainnet still rejects them so a misconfigured archive
/// doesn't poison the pool with unroutable peers.
pub(crate) fn multiaddr_to_host_port_with_network(ma: &str, network: u8) -> Option<String> {
    let parts: Vec<&str> = ma.trim_start_matches('/').split('/').collect();
    if parts.len() < 4 {
        return None;
    }
    if parts[0] != "ip4" || parts[2] != "tcp" {
        return None;
    }
    let ip: std::net::Ipv4Addr = parts[1].parse().ok()?;
    let allow_private = network != 0;
    let reject = if allow_private {
        ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast()
    } else {
        ip.is_loopback() || ip.is_private() || ip.is_link_local()
            || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast()
    };
    if reject {
        return None;
    }
    let port: u16 = parts[3].parse().ok()?;
    Some(format!("{}:{}", ip, port))
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
                ip.is_loopback() || ip.is_private() || ip.is_link_local()
                    || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast()
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
                    || (ip.segments()[0] & 0xffc0) == 0xfe80  // link-local fe80::/10
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

/// Build a stream multiaddr by extracting the IP from a pubsub multiaddr and
/// combining it with the port/protocol from the stream listen pattern.
///
/// IP precedence: prefer the pubsub IP (it's the address peers actually
/// see us on); if that's a wildcard or loopback, fall back to the stream
/// listen IP (covers testnet bootstraps where listen_multiaddr is
/// `/ip4/0.0.0.0/...` but stream_listen has the real LAN IP).
pub(crate) fn extract_stream_addr(pubsub_ma: &str, stream_listen: &str) -> Option<String> {
    let pub_parts: Vec<&str> = pubsub_ma.trim_start_matches('/').split('/').collect();
    let stream_parts: Vec<&str> = stream_listen.trim_start_matches('/').split('/').collect();

    if stream_parts.len() < 4 {
        return None;
    }
    let protocol = stream_parts[2]; // "tcp"
    let port = stream_parts[3]; // "8340"

    let pub_ip = if pub_parts.len() >= 2 && pub_parts[0] == "ip4" {
        Some(pub_parts[1])
    } else {
        None
    };
    let stream_ip = if stream_parts.len() >= 2 && stream_parts[0] == "ip4" {
        Some(stream_parts[1])
    } else {
        None
    };

    let usable = |ip: &str| -> bool {
        ip != "0.0.0.0" && ip != "127.0.0.1"
    };

    let ip = match (pub_ip, stream_ip) {
        (Some(p), _) if usable(p) => p,
        (_, Some(s)) if usable(s) => s,
        _ => return None,
    };

    Some(format!("/ip4/{}/{}/{}", ip, protocol, port))
}

#[cfg(test)]
mod tests {
    use super::archive_multiaddr_to_host_port;

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
        assert_eq!(archive_multiaddr_to_host_port("archive.example.com:8340", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("1.2.3.4:8340", 0), None);
    }

    #[test]
    fn archive_multiaddr_rejects_non_tcp() {
        assert_eq!(archive_multiaddr_to_host_port("/ip4/1.2.3.4/udp/8340", 0), None);
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
        assert_eq!(archive_multiaddr_to_host_port("/ip4/1.2.3.4/tcp/notaport", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/dns4//tcp/8340", 0), None);
    }

    #[test]
    fn archive_multiaddr_rejects_private_ip_on_mainnet() {
        assert_eq!(archive_multiaddr_to_host_port("/ip4/192.168.1.1/tcp/8340", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/ip4/10.0.0.1/tcp/8340", 0), None);
        assert_eq!(archive_multiaddr_to_host_port("/ip4/127.0.0.1/tcp/8340", 0), None);
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
}
