//! The socket of the peer gRPC listener (`p2p.streamListenMultiaddr`).
//!
//! An address binds as written. `::` takes both address families, whatever
//! `net.ipv6.bindv6only` says, so one listener serves a dual-stack host and
//! the announced stream address does not depend on a sysctl; an IPv4 peer
//! arrives under its IPv4-mapped address, which the connection limits count as
//! IPv4. Any other address, specific or `0.0.0.0`, takes its own family only.
//!
//! A config naming no p2p listen address also takes IPv6 on the default
//! `0.0.0.0` stream address: it binds `::` of that port, and a host where that
//! fails keeps the IPv4 listener ([`bind_plan`]).

use std::io;
use std::net::{Ipv6Addr, SocketAddr};

use tokio::net::{TcpListener, TcpSocket};
use tracing::warn;

/// The backlog of the `::` socket.
const BACKLOG: u32 = 1024;

/// Bind the listener.
pub(crate) async fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    if !takes_both_families(addr) {
        return TcpListener::bind(addr).await;
    }
    let socket = TcpSocket::new_v6()?;
    socket.set_reuseaddr(true)?;
    socket2::SockRef::from(&socket).set_only_v6(false)?;
    socket.bind(addr)?;
    socket.listen(BACKLOG)
}

/// The address the listener at `addr` binds first and the one it falls back
/// to when that fails: `::` of the port for an IPv4 wildcard of a config that
/// listens on both families
/// ([`stream_listens_on_both_families`](quil_config::P2PConfig::stream_listens_on_both_families)),
/// then `addr` itself.
pub(crate) fn bind_plan(
    addr: SocketAddr,
    p2p: &quil_config::P2PConfig,
) -> (SocketAddr, Option<SocketAddr>) {
    if p2p.stream_listens_on_both_families() && addr.is_ipv4() && addr.ip().is_unspecified() {
        (
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), addr.port()),
            Some(addr),
        )
    } else {
        (addr, None)
    }
}

/// Bind the first address of a [`bind_plan`], or its fallback when that fails.
pub(crate) async fn bind_planned(
    (first, fallback): (SocketAddr, Option<SocketAddr>),
) -> io::Result<TcpListener> {
    let error = match bind(first).await {
        Ok(listener) => return Ok(listener),
        Err(error) => error,
    };
    let Some(fallback) = fallback else {
        return Err(error);
    };
    warn!(
        addr = %first,
        %error,
        %fallback,
        "the peer gRPC listener failed to take IPv6, so peers reach its port over IPv4 only; \
         IPv4 continues. A host without IPv6 can set p2p.listenMultiaddr to silence this"
    );
    bind(fallback).await
}

/// Whether the listener at `addr` also takes IPv4 peers of an IPv6 address.
pub(crate) fn takes_both_families(addr: SocketAddr) -> bool {
    addr.is_ipv6() && addr.ip().is_unspecified()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use tokio::net::TcpStream;

    use super::*;

    /// Whether this host has an IPv6 loopback; says so when it has none.
    fn ipv6_loopback(test: &str) -> bool {
        match std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("SKIP {test}: no IPv6 loopback on this host: {e}");
                false
            }
        }
    }

    /// Whether a connection to `to` reaches `listener`.
    async fn reaches(listener: &TcpListener, to: SocketAddr) -> bool {
        let (connected, accepted) = tokio::join!(
            TcpStream::connect(to),
            tokio::time::timeout(Duration::from_secs(1), listener.accept()),
        );
        connected.is_ok() && matches!(accepted, Ok(Ok(_)))
    }

    fn on(ip: impl Into<IpAddr>, port: u16) -> SocketAddr {
        SocketAddr::new(ip.into(), port)
    }

    /// The default IPv4 wildcard of a config listening on both families
    /// binds `::` first and falls back to itself; any other address, or a
    /// config naming its listen address, binds as written.
    #[test]
    fn the_default_wildcard_binds_both_families_first() {
        let mut both = quil_config::P2PConfig::default();
        both.apply_defaults();
        let mut named = both.clone();
        named.listen_multiaddr = "/ip4/0.0.0.0/udp/8336/quic-v1".into();
        let v4_any = on(Ipv4Addr::UNSPECIFIED, 8340);
        assert_eq!(
            bind_plan(v4_any, &both),
            (on(Ipv6Addr::UNSPECIFIED, 8340), Some(v4_any)),
            "the default wildcard does not bind both families"
        );
        assert_eq!(
            bind_plan(v4_any, &named),
            (v4_any, None),
            "a config naming its listen address binds both families"
        );
        let v4_one = on(Ipv4Addr::new(192, 0, 2, 1), 8340);
        assert_eq!(bind_plan(v4_one, &both), (v4_one, None));
        let v6_any = on(Ipv6Addr::UNSPECIFIED, 8340);
        assert_eq!(bind_plan(v6_any, &both), (v6_any, None));
    }

    /// A host where `::` does not bind, here an IPv6 address no host holds,
    /// keeps the IPv4 listener; without a fallback the error stands.
    #[tokio::test]
    async fn an_ipv6_bind_failure_falls_back_to_ipv4() {
        let unbindable = on("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 0);
        let listener = bind_planned((unbindable, Some(on(Ipv4Addr::LOCALHOST, 0))))
            .await
            .expect("no IPv4 fallback after the IPv6 bind failed");
        let bound = listener.local_addr().unwrap();
        assert!(bound.is_ipv4(), "{bound}");
        assert!(reaches(&listener, on(Ipv4Addr::LOCALHOST, bound.port())).await);
        assert!(bind_planned((unbindable, None)).await.is_err());
    }

    #[tokio::test]
    async fn ipv6_wildcard_takes_both_families() {
        if !ipv6_loopback("ipv6_wildcard_takes_both_families") {
            return;
        }
        let listener = bind(on(Ipv6Addr::UNSPECIFIED, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(reaches(&listener, on(Ipv6Addr::LOCALHOST, port)).await);
        assert!(reaches(&listener, on(Ipv4Addr::LOCALHOST, port)).await);
    }

    #[tokio::test]
    async fn specific_ipv6_address_takes_ipv6_only() {
        if !ipv6_loopback("specific_ipv6_address_takes_ipv6_only") {
            return;
        }
        let listener = bind(on(Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(reaches(&listener, on(Ipv6Addr::LOCALHOST, port)).await);
        assert!(!reaches(&listener, on(Ipv4Addr::LOCALHOST, port)).await);
    }

    /// An IPv4 config binds as it always did.
    #[tokio::test]
    async fn ipv4_wildcard_takes_ipv4_only() {
        let listener = bind(on(Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(reaches(&listener, on(Ipv4Addr::LOCALHOST, port)).await);
        if ipv6_loopback("ipv4_wildcard_takes_ipv4_only, its IPv6 half") {
            assert!(!reaches(&listener, on(Ipv6Addr::LOCALHOST, port)).await);
        }
    }
}
