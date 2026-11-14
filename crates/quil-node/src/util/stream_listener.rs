//! The socket of the peer gRPC listener (`p2p.streamListenMultiaddr`).
//!
//! An address binds as written. `::` takes both address families, whatever
//! `net.ipv6.bindv6only` says, so one listener serves a dual-stack host and
//! the announced stream address does not depend on a sysctl; an IPv4 peer
//! arrives under its IPv4-mapped address, which the connection limits count as
//! IPv4. Any other address, specific or `0.0.0.0`, takes its own family only.

use std::io;
use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpSocket};

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
