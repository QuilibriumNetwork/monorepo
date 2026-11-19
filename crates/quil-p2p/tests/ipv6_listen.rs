//! Real nodes on loopback: the listen address decides the address family, an
//! IPv6 listener serves gossip, it still dials out over IPv4 (a DS-Lite host:
//! IPv6 inbound, IPv4 only through its carrier's NAT), and an IPv4 config stays
//! on IPv4. The IPv4 and IPv6 wildcards share a port, as the default config
//! has them. A peer listed at both families gets one connection, over the
//! listened family while it answers and over the other family when it does
//! not. A host without an IPv6 loopback skips with the reason.
//!
//! Every listener binds port 0 and the test reads the port the kernel gave
//! it: a probed port is free only until the probe closes, and nextest runs
//! each test in its own process, so two tests could take the same port.

use std::time::Duration;

use quil_p2p::{P2PHandle, P2PNode, ReceivedMessage};
use tokio::sync::mpsc;

type Supervisor = quil_lifecycle::Supervisor<anyhow::Error>;

/// Whether this host has an IPv6 loopback; says so when it has none.
fn ipv6_loopback(test: &str) -> bool {
    match std::net::TcpListener::bind("[::1]:0") {
        Ok(_) => true,
        Err(e) => {
            eprintln!("SKIP {test}: no IPv6 loopback on this host: {e}");
            false
        }
    }
}

/// The port in a listen address `prefix<port>...`, such as
/// `/ip4/127.0.0.1/udp/` for a QUIC listener on the IPv4 loopback.
fn port_after(addr: &str, prefix: &str) -> Option<u16> {
    addr.strip_prefix(prefix)?.split('/').next()?.parse().ok()
}

/// The port the kernel gave a listener bound to port 0, once the node lists
/// an address starting with `prefix`.
async fn bound_port(node: &P2PHandle, prefix: &str) -> u16 {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let addrs = node.listen_addresses();
        if let Some(port) = addrs.iter().find_map(|a| port_after(a, prefix)) {
            return port;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no listener on {prefix}: {addrs:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn base_config() -> quil_config::P2PConfig {
    let mut config = quil_config::P2PConfig::default();
    config.network = 99;
    config.bootstrap_peers = Vec::new();
    config.direct_peers = Vec::new();
    config
}

/// A shard's CW topic: `0x01 || appFilter`.
fn topic() -> Vec<u8> {
    let mut cw = vec![0x01u8];
    cw.extend_from_slice(&[0x40u8; 32]);
    cw
}

/// A receiving node on `listen`; its peer ID as text for the sender's dial.
async fn start_receiver(
    sup: &mut Supervisor,
    listen: &str,
    additional: &[String],
) -> (P2PHandle, mpsc::Receiver<ReceivedMessage>, String) {
    let mut config = base_config();
    config.additional_listen_multiaddrs = additional.to_vec();
    let node = P2PNode::new_with_options(&config, true, None).unwrap();
    let id = node.peer_id.to_string();
    let (handle, inbound) = node.start(sup, listen).await.unwrap();
    handle.subscribe_confirmed(topic()).await.unwrap();
    (handle, inbound, id)
}

/// A node on `listen` that dials `dial` and publishes one message, which
/// `inbound` must deliver.
async fn gossip_to(
    sup: &mut Supervisor,
    listen: &str,
    dial: &str,
    inbound: &mut mpsc::Receiver<ReceivedMessage>,
    payload: &[u8],
) {
    let mut config = base_config();
    config.bootstrap_peers = vec![dial.to_string()];
    publish_over(sup, &config, listen, inbound, payload).await;
}

/// A node with `config` on `listen` that publishes one message, which
/// `inbound` must deliver; the node, once it did.
async fn publish_over(
    sup: &mut Supervisor,
    config: &quil_config::P2PConfig,
    listen: &str,
    inbound: &mut mpsc::Receiver<ReceivedMessage>,
    payload: &[u8],
) -> P2PHandle {
    let dial = &config.bootstrap_peers;
    let node = P2PNode::new_with_options(config, true, None).unwrap();
    let (sender, _rx) = node.start(sup, listen).await.unwrap();
    sender.subscribe_confirmed(topic()).await.unwrap();
    // The sender dials its bootstrap peer on its first discovery tick, and
    // publishing fails until it knows the receiver's subscription.
    let data = [&[0x80u8][..], &[1u8; 8][..], payload].concat();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match sender.publish(topic(), data.clone()).await {
            Ok(()) => break,
            Err(e) if tokio::time::Instant::now() > deadline => {
                panic!("not published over {dial:?}: {e}")
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    let message = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let message = inbound.recv().await.expect("the node is running");
            if message.data == data {
                return message;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("not delivered over {dial:?}"));
    assert_eq!(message.bitmask, topic());
    sender
}

/// Whether the node lists `expected` within `wait`.
async fn lists_within(node: &P2PHandle, expected: &str, wait: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + wait;
    while !node.listen_addresses().iter().any(|a| a == expected) {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

/// The node's listen addresses once `expected` shows among them.
async fn listening_on(node: &P2PHandle, expected: &str) -> Vec<String> {
    let listed = lists_within(node, expected, Duration::from_secs(15)).await;
    let addrs = node.listen_addresses();
    assert!(listed, "not listening on {expected}: {addrs:?}");
    addrs
}

/// A listen address family: the address a config names and the loopback a
/// test dials on it.
type Family = (&'static str, &'static str);
const IPV4_WILDCARD: Family = ("/ip4/0.0.0.0", "/ip4/127.0.0.1");
/// An IPv4 config naming a specific IP, which binds `0.0.0.0`.
const IPV4_NAMED: Family = ("/ip4/192.0.2.10", "/ip4/127.0.0.1");
const IPV6_WILDCARD: Family = ("/ip6/::", "/ip6/::1");

/// Tries before a second listener that does not bind the first's port fails
/// the test: another test process may hold that port in the second family.
const SHARED_PORT_TRIES: u32 = 3;

/// A node on the `first` family's wildcard binds port 0; a second node takes
/// the port it got in the `second` family, as written, and both serve gossip
/// on it. `transport` is `tcp` or `udp`, with `suffix` `/quic-v1` for QUIC.
async fn second_family_takes_the_first_ones_port(
    transport: &str,
    suffix: &str,
    first: Family,
    second: Family,
) {
    // The node's warning names the error of a listener that did not bind.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("quil_p2p=warn"))
        .with_writer(std::io::stderr)
        .try_init();
    let mut sup = Supervisor::new();
    for attempt in 1..=SHARED_PORT_TRIES {
        let (a, mut a_inbound, a_id) =
            start_receiver(&mut sup, &format!("{}/{transport}/0{suffix}", first.0), &[]).await;
        let port = bound_port(&a, &format!("{}/{transport}/", first.1)).await;
        let a_addr = format!("{}/{transport}/{port}{suffix}", first.1);
        let (b, mut b_inbound, b_id) = start_receiver(
            &mut sup,
            &format!("{}/{transport}/{port}{suffix}", second.0),
            &[],
        )
        .await;
        let b_addr = format!("{}/{transport}/{port}{suffix}", second.1);
        if !lists_within(&b, &b_addr, Duration::from_secs(10)).await {
            let addrs = b.listen_addresses();
            assert!(
                attempt < SHARED_PORT_TRIES,
                "no listener on {b_addr} beside one on {a_addr}, {attempt} tries: {addrs:?}"
            );
            eprintln!("try {attempt}: no listener on {b_addr} beside {a_addr}: {addrs:?}");
            continue;
        }
        listening_on(&a, &a_addr).await;
        for (family, addr, id, inbound) in [
            (first, &a_addr, &a_id, &mut a_inbound),
            (second, &b_addr, &b_id, &mut b_inbound),
        ] {
            gossip_to(
                &mut sup,
                &format!("{}/{transport}/0{suffix}", family.0),
                &format!("{addr}/p2p/{id}"),
                inbound,
                addr.as_bytes(),
            )
            .await;
        }
        return;
    }
}

#[tokio::test]
async fn specific_ipv6_address_binds_as_written_and_serves_gossip_over_tcp() {
    if !ipv6_loopback("specific_ipv6_address_binds_as_written_and_serves_gossip_over_tcp") {
        return;
    }
    let mut sup = Supervisor::new();
    let (node, mut inbound, id) = start_receiver(&mut sup, "/ip6/::1/tcp/0", &[]).await;
    let bound = format!("/ip6/::1/tcp/{}", bound_port(&node, "/ip6/::1/tcp/").await);
    assert_eq!(listening_on(&node, &bound).await, [bound.clone()]);
    gossip_to(
        &mut sup,
        "/ip6/::1/tcp/0",
        &format!("{bound}/p2p/{id}"),
        &mut inbound,
        b"over ipv6 tcp",
    )
    .await;
}

#[tokio::test]
async fn ipv6_wildcard_takes_ipv6_only_and_serves_gossip_over_quic() {
    if !ipv6_loopback("ipv6_wildcard_takes_ipv6_only_and_serves_gossip_over_quic") {
        return;
    }
    let mut sup = Supervisor::new();
    let (node, mut inbound, id) = start_receiver(&mut sup, "/ip6/::/udp/0/quic-v1", &[]).await;
    let port = bound_port(&node, "/ip6/::1/udp/").await;
    let loopback = format!("/ip6/::1/udp/{port}/quic-v1");
    let addrs = listening_on(&node, &loopback).await;
    assert!(addrs.iter().all(|a| a.starts_with("/ip6/")), "{addrs:?}");
    gossip_to(
        &mut sup,
        "/ip6/::/udp/0/quic-v1",
        &format!("{loopback}/p2p/{id}"),
        &mut inbound,
        b"over ipv6 quic",
    )
    .await;
}

/// A DS-Lite host listens on IPv6 and still reaches IPv4 peers outbound.
#[tokio::test]
async fn ipv6_only_listener_dials_an_ipv4_peer() {
    if !ipv6_loopback("ipv6_only_listener_dials_an_ipv4_peer") {
        return;
    }
    for (prefix, transport, sender_listen) in [
        ("/ip4/127.0.0.1/tcp/", "", "/ip6/::/tcp/0"),
        ("/ip4/127.0.0.1/udp/", "/quic-v1", "/ip6/::/udp/0/quic-v1"),
    ] {
        let mut sup = Supervisor::new();
        let (node, mut inbound, id) =
            start_receiver(&mut sup, &format!("{prefix}0{transport}"), &[]).await;
        let v4 = format!("{prefix}{}{transport}", bound_port(&node, prefix).await);
        gossip_to(
            &mut sup,
            sender_listen,
            &format!("{v4}/p2p/{id}"),
            &mut inbound,
            b"out over ipv4",
        )
        .await;
    }
}

/// A dual-stack node names both families; an entry in the family it already
/// has starts no listener.
#[tokio::test]
async fn additional_listener_serves_the_other_family() {
    if !ipv6_loopback("additional_listener_serves_the_other_family") {
        return;
    }
    let mut sup = Supervisor::new();
    let additional = [
        "/ip6/::/tcp/0".to_string(),
        "/ip4/0.0.0.0/tcp/0".to_string(),
    ];
    let (node, mut inbound, id) = start_receiver(&mut sup, "/ip4/0.0.0.0/tcp/0", &additional).await;
    let v4_port = bound_port(&node, "/ip4/127.0.0.1/tcp/").await;
    let v4 = format!("/ip4/127.0.0.1/tcp/{v4_port}");
    let v6 = format!("/ip6/::1/tcp/{}", bound_port(&node, "/ip6/::1/tcp/").await);
    let addrs = listening_on(&node, &v6).await;
    // The ignored IPv4 entry would have bound a second IPv4 port.
    assert!(
        addrs
            .iter()
            .filter(|a| a.starts_with("/ip4/"))
            .all(|a| a.ends_with(&format!("/tcp/{v4_port}"))),
        "{addrs:?}"
    );
    gossip_to(
        &mut sup,
        "/ip4/0.0.0.0/tcp/0",
        &format!("{v4}/p2p/{id}"),
        &mut inbound,
        b"over the ipv4 listener",
    )
    .await;
    gossip_to(
        &mut sup,
        "/ip6/::/tcp/0",
        &format!("{v6}/p2p/{id}"),
        &mut inbound,
        b"over the additional ipv6 listener",
    )
    .await;
}

/// The default config's two QUIC wildcards share one port, each taking only
/// its own family; in either order, and an IPv4 config naming a specific IP
/// keeps its port when it binds `0.0.0.0`.
#[tokio::test]
async fn ipv4_and_ipv6_wildcards_share_a_port_over_quic() {
    if !ipv6_loopback("ipv4_and_ipv6_wildcards_share_a_port_over_quic") {
        return;
    }
    second_family_takes_the_first_ones_port("udp", "/quic-v1", IPV4_WILDCARD, IPV6_WILDCARD).await;
    second_family_takes_the_first_ones_port("udp", "/quic-v1", IPV6_WILDCARD, IPV4_NAMED).await;
}

/// As over QUIC, the TCP wildcards share one port.
#[tokio::test]
async fn ipv4_and_ipv6_wildcards_share_a_port_over_tcp() {
    if !ipv6_loopback("ipv4_and_ipv6_wildcards_share_a_port_over_tcp") {
        return;
    }
    second_family_takes_the_first_ones_port("tcp", "", IPV4_WILDCARD, IPV6_WILDCARD).await;
    second_family_takes_the_first_ones_port("tcp", "", IPV6_WILDCARD, IPV4_NAMED).await;
}

/// An IPv4 config, even one naming a specific IP, binds `0.0.0.0` and no IPv6
/// socket, as it always did.
#[tokio::test]
async fn ipv4_config_stays_on_the_ipv4_wildcard() {
    let mut sup = Supervisor::new();
    let (node, _inbound, _id) = start_receiver(&mut sup, "/ip4/192.0.2.10/tcp/0", &[]).await;
    let port = bound_port(&node, "/ip4/127.0.0.1/tcp/").await;
    let addrs = listening_on(&node, &format!("/ip4/127.0.0.1/tcp/{port}")).await;
    assert!(addrs.iter().all(|a| a.starts_with("/ip4/")), "{addrs:?}");
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok());
    if ipv6_loopback("ipv4_config_stays_on_the_ipv4_wildcard, its IPv6 half") {
        assert!(tokio::net::TcpStream::connect(("::1", port)).await.is_err());
    }
}

/// A host without IPv6, here an IPv6 address no host holds, still starts:
/// the IPv6 listener's failure is not fatal and the IPv4 one serves gossip.
#[tokio::test]
async fn an_ipv6_listener_that_cannot_bind_leaves_ipv4_serving() {
    let mut sup = Supervisor::new();
    let mut config = base_config();
    config.additional_listen_multiaddrs = vec!["/ip6/2001:db8::1/udp/0/quic-v1".to_string()];
    let node = P2PNode::new_with_options(&config, true, None).unwrap();
    let id = node.peer_id.to_string();
    let (node, mut inbound) = node
        .start(&mut sup, "/ip4/127.0.0.1/udp/0/quic-v1")
        .await
        .expect("a failed IPv6 listener stopped the node");
    node.subscribe_confirmed(topic()).await.unwrap();
    let port = bound_port(&node, "/ip4/127.0.0.1/udp/").await;
    let listen = format!("/ip4/127.0.0.1/udp/{port}/quic-v1");
    let addrs = listening_on(&node, &listen).await;
    assert!(addrs.iter().all(|a| a.starts_with("/ip4/")), "{addrs:?}");
    gossip_to(
        &mut sup,
        "/ip4/127.0.0.1/udp/0/quic-v1",
        &format!("{listen}/p2p/{id}"),
        &mut inbound,
        b"over ipv4 beside a failed ipv6 listener",
    )
    .await;
}

/// The outbound connections `node` established, from its metrics.
fn outbound_connections(node: &P2PHandle) -> u64 {
    let metrics = node.render_metrics();
    let line = metrics
        .lines()
        .find(|line| {
            line.starts_with("libp2p_connections_established")
                && line.to_ascii_lowercase().contains("direction=\"outbound\"")
        })
        .unwrap_or_else(|| panic!("no outbound connection count in the metrics:\n{metrics}"));
    let count = line.rsplit(' ').next().unwrap_or_default();
    count
        .parse::<f64>()
        .unwrap_or_else(|e| panic!("{line}: {e}")) as u64
}

/// A node listed at the two addresses `at` (address prefixes to the port,
/// read from its listen address `bound`) in a peer's bootstrap and direct
/// lists, as the built-in list names each archive at its IPv4 and its IPv6
/// address: the peer delivers gossip to it over one connection, not one
/// per address or list entry.
async fn one_connection_to_a_peer_at(
    listen: &str,
    additional: &[String],
    bound: [&str; 2],
    at: [&str; 2],
    suffix: &str,
) {
    let mut sup = Supervisor::new();
    let (node, mut inbound, id) = start_receiver(&mut sup, listen, additional).await;
    let mut entries = Vec::new();
    for (bound, at) in bound.iter().zip(at) {
        let port = bound_port(&node, bound).await;
        entries.push(format!("{at}{port}{suffix}/p2p/{id}"));
    }
    let mut config = base_config();
    config.additional_listen_multiaddrs = additional.to_vec();
    config.bootstrap_peers = entries.clone();
    config.direct_peers = entries.iter().rev().cloned().collect();
    let sender = publish_over(&mut sup, &config, listen, &mut inbound, b"one connection").await;
    let connections = outbound_connections(&sender);
    eprintln!("REACH v6-bootstrap checked: {connections} connection(s) over {entries:?}");
    assert_eq!(
        connections, 1,
        "a peer listed at two addresses holds one connection per address: {entries:?}"
    );
}

/// An archive listed at its IPv4 and its IPv6 address gets one connection
/// from a dual-stack node; two IPv4 addresses of one peer stand in for the
/// pair on a host without an IPv6 loopback, and run on every host.
#[tokio::test]
async fn a_peer_listed_at_two_addresses_gets_one_connection() {
    one_connection_to_a_peer_at(
        "/ip4/0.0.0.0/tcp/0",
        &[],
        ["/ip4/127.0.0.1/tcp/", "/ip4/127.0.0.1/tcp/"],
        ["/ip4/127.0.0.1/tcp/", "/ip4/127.0.0.2/tcp/"],
        "",
    )
    .await;
    if !ipv6_loopback("a_peer_listed_at_two_addresses_gets_one_connection, its dual-stack half") {
        return;
    }
    one_connection_to_a_peer_at(
        "/ip4/0.0.0.0/udp/0/quic-v1",
        &["/ip6/::/udp/0/quic-v1".to_string()],
        ["/ip4/127.0.0.1/udp/", "/ip6/::1/udp/"],
        ["/ip4/127.0.0.1/udp/", "/ip6/::1/udp/"],
        "/quic-v1",
    )
    .await;
}

/// The QUIC multiaddr of a UDP socket address.
fn quic_at(addr: std::net::SocketAddr) -> String {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => format!("/ip4/{ip}/udp/{}/quic-v1", addr.port()),
        std::net::IpAddr::V6(ip) => format!("/ip6/{ip}/udp/{}/quic-v1", addr.port()),
    }
}

/// A UDP socket on `loopback` (`127.0.0.1` or `[::1]`) that answers
/// nothing: a configured address that does not answer.
fn silent_udp(loopback: &str) -> std::net::UdpSocket {
    let socket = std::net::UdpSocket::bind(format!("{loopback}:0")).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
}

/// The datagrams `socket` received so far.
fn datagrams(socket: &std::net::UdpSocket) -> usize {
    let mut buf = [0u8; 2048];
    let mut count = 0;
    loop {
        match socket.recv_from(&mut buf) {
            Ok(_) => count += 1,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return count,
            Err(e) => panic!("{socket:?}: {e}"),
        }
    }
}

/// A listened family for the dial-order tests: the node's QUIC listen
/// address and loopback, and the other family's loopback.
type DialFamily = (&'static str, &'static str, &'static str);
const DIAL_FAMILIES: [DialFamily; 2] = [
    ("/ip4/0.0.0.0/udp/0/quic-v1", "127.0.0.1", "[::1]"),
    ("/ip6/::/udp/0/quic-v1", "[::1]", "127.0.0.1"),
];

/// The receiving node's QUIC listen address on `loopback`.
fn quic_listen(loopback: &str) -> &'static str {
    if loopback == "127.0.0.1" {
        "/ip4/0.0.0.0/udp/0/quic-v1"
    } else {
        "/ip6/::/udp/0/quic-v1"
    }
}

/// Its QUIC listen address prefix, to the port.
fn quic_prefix(loopback: &str) -> &'static str {
    if loopback == "127.0.0.1" {
        "/ip4/127.0.0.1/udp/"
    } else {
        "/ip6/::1/udp/"
    }
}

/// An archive listed at both families, with both answering, is reached
/// over the family of the node's listen address only: a server dials back
/// over the family a probe arrives on. The other family's address is a
/// UDP socket that must receive no datagram: one dial of both families
/// sends its first packet there at once, before the listened family's
/// handshake ends, and so before the gossip that follows it arrives.
#[tokio::test]
async fn an_archive_listed_at_both_families_is_reached_over_the_listened_one() {
    if !ipv6_loopback("an_archive_listed_at_both_families_is_reached_over_the_listened_one") {
        return;
    }
    for (listen, own, other) in DIAL_FAMILIES {
        let mut sup = Supervisor::new();
        let (node, mut inbound, id) = start_receiver(&mut sup, quic_listen(own), &[]).await;
        let port = bound_port(&node, quic_prefix(own)).await;
        let own = format!("{}{port}/quic-v1/p2p/{id}", quic_prefix(own));
        let decoy = silent_udp(other);
        let other = format!("{}/p2p/{id}", quic_at(decoy.local_addr().unwrap()));
        let mut config = base_config();
        config.bootstrap_peers = vec![other.clone(), own.clone()];
        config.direct_peers = vec![other.clone(), own.clone()];
        publish_over(&mut sup, &config, listen, &mut inbound, b"listened family").await;
        let received = datagrams(&decoy);
        eprintln!("REACH v6-bootstrap checked: listen {listen}, {received} datagram(s) at {other}");
        assert_eq!(
            received, 0,
            "an archive listed at both families was dialed over the family this node does not \
             listen on: {other} (listen {listen})"
        );
    }
}

/// The node dials an archive's first address at once, and a tick redial
/// comes 30 s later: an archive reached sooner was reached by the first
/// dial.
const BEFORE_A_TICK: Duration = Duration::from_secs(25);

/// An archive whose listened-family addresses `dead` do not answer is
/// reached over its address in the other family by the same dial, before
/// a tick redial.
async fn reached_over_the_other_family(listen: &str, other: &str, dead: &[String], case: &str) {
    let mut sup = Supervisor::new();
    let (node, mut inbound, id) = start_receiver(&mut sup, quic_listen(other), &[]).await;
    let port = bound_port(&node, quic_prefix(other)).await;
    let reachable = format!("{}{port}/quic-v1/p2p/{id}", quic_prefix(other));
    let mut config = base_config();
    config.bootstrap_peers = dead
        .iter()
        .map(|addr| format!("{addr}/p2p/{id}"))
        .chain([reachable.clone()])
        .collect();
    let started = tokio::time::Instant::now();
    publish_over(&mut sup, &config, listen, &mut inbound, case.as_bytes()).await;
    let took = started.elapsed();
    eprintln!("REACH v6-bootstrap checked: {case}, listen {listen}, reached in {took:?}");
    assert!(
        took < BEFORE_A_TICK,
        "an archive whose listened-family addresses do not answer was reached over {reachable} \
         only after {took:?}, by a later redial ({case}, listen {listen})"
    );
}

/// An archive whose listened-family address is closed is reached over its
/// address in the other family by the same dial.
#[tokio::test]
async fn an_archive_whose_listened_address_is_closed_is_reached_over_the_other_family() {
    if !ipv6_loopback(
        "an_archive_whose_listened_address_is_closed_is_reached_over_the_other_family",
    ) {
        return;
    }
    for (listen, own, other) in DIAL_FAMILIES {
        let closed = quic_at(silent_udp(own).local_addr().unwrap());
        reached_over_the_other_family(listen, other, &[closed], "closed listened address").await;
    }
}

/// An archive behind two silent listened-family addresses is reached over
/// its third address, in the other family: every address of one libp2p
/// dial starts its transport timeout when the dial starts, so the other
/// family takes a dial of its own.
#[tokio::test]
async fn an_archive_behind_two_silent_listened_addresses_is_reached_over_the_third() {
    if !ipv6_loopback("an_archive_behind_two_silent_listened_addresses_is_reached_over_the_third") {
        return;
    }
    for (listen, own, other) in DIAL_FAMILIES {
        let silent = [silent_udp(own), silent_udp(own)];
        let dead: Vec<String> = silent
            .iter()
            .map(|socket| quic_at(socket.local_addr().unwrap()))
            .collect();
        reached_over_the_other_family(listen, other, &dead, "two silent listened addresses").await;
    }
}
