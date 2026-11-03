//! Real nodes on loopback: the listen address decides the address family, an
//! IPv6 listener serves gossip, it still dials out over IPv4 (a DS-Lite host:
//! IPv6 inbound, IPv4 only through its carrier's NAT), and an IPv4 config stays
//! on IPv4. A host without an IPv6 loopback skips with the reason.

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
    let node = P2PNode::new_with_options(&config, true, None).unwrap();
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
                panic!("not published over {dial}: {e}")
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
    .unwrap_or_else(|_| panic!("not delivered over {dial}"));
    assert_eq!(message.bitmask, topic());
}

/// The node's listen addresses once `expected` shows among them.
async fn listening_on(node: &P2PHandle, expected: &str) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let addrs = node.listen_addresses();
        if addrs.iter().any(|a| a == expected) {
            return addrs;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "not listening on {expected}: {addrs:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn specific_ipv6_address_binds_as_written_and_serves_gossip_over_tcp() {
    if !ipv6_loopback("specific_ipv6_address_binds_as_written_and_serves_gossip_over_tcp") {
        return;
    }
    let mut sup = Supervisor::new();
    let bound = format!("/ip6/::1/tcp/{}", free_port());
    let (node, mut inbound, id) = start_receiver(&mut sup, &bound, &[]).await;
    assert_eq!(listening_on(&node, &bound).await, [bound.clone()]);
    gossip_to(
        &mut sup,
        &format!("/ip6/::1/tcp/{}", free_port()),
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
    let port = free_port();
    let (node, mut inbound, id) =
        start_receiver(&mut sup, &format!("/ip6/::/udp/{port}/quic-v1"), &[]).await;
    let loopback = format!("/ip6/::1/udp/{port}/quic-v1");
    let addrs = listening_on(&node, &loopback).await;
    assert!(addrs.iter().all(|a| a.starts_with("/ip6/")), "{addrs:?}");
    gossip_to(
        &mut sup,
        &format!("/ip6/::/udp/{}/quic-v1", free_port()),
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
    for (v4_listen, sender_listen) in [
        (
            format!("/ip4/127.0.0.1/tcp/{}", free_port()),
            format!("/ip6/::/tcp/{}", free_port()),
        ),
        (
            format!("/ip4/127.0.0.1/udp/{}/quic-v1", free_port()),
            format!("/ip6/::/udp/{}/quic-v1", free_port()),
        ),
    ] {
        let mut sup = Supervisor::new();
        let (_node, mut inbound, id) = start_receiver(&mut sup, &v4_listen, &[]).await;
        gossip_to(
            &mut sup,
            &sender_listen,
            &format!("{v4_listen}/p2p/{id}"),
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
    let port = free_port();
    let ignored_port = free_port();
    let additional = [
        format!("/ip6/::/tcp/{port}"),
        format!("/ip4/0.0.0.0/tcp/{ignored_port}"),
    ];
    let (node, mut inbound, id) =
        start_receiver(&mut sup, &format!("/ip4/0.0.0.0/tcp/{port}"), &additional).await;
    let v4 = format!("/ip4/127.0.0.1/tcp/{port}");
    let v6 = format!("/ip6/::1/tcp/{port}");
    listening_on(&node, &v4).await;
    let addrs = listening_on(&node, &v6).await;
    assert!(
        !addrs
            .iter()
            .any(|a| a.ends_with(&format!("/{ignored_port}"))),
        "{addrs:?}"
    );
    gossip_to(
        &mut sup,
        &format!("/ip4/0.0.0.0/tcp/{}", free_port()),
        &format!("{v4}/p2p/{id}"),
        &mut inbound,
        b"over the ipv4 listener",
    )
    .await;
    gossip_to(
        &mut sup,
        &format!("/ip6/::/tcp/{}", free_port()),
        &format!("{v6}/p2p/{id}"),
        &mut inbound,
        b"over the additional ipv6 listener",
    )
    .await;
}

/// An IPv4 config, even one naming a specific IP, binds `0.0.0.0` and no IPv6
/// socket, as it always did.
#[tokio::test]
async fn ipv4_config_stays_on_the_ipv4_wildcard() {
    let mut sup = Supervisor::new();
    let port = free_port();
    let (node, _inbound, _id) =
        start_receiver(&mut sup, &format!("/ip4/192.0.2.10/tcp/{port}"), &[]).await;
    let addrs = listening_on(&node, &format!("/ip4/127.0.0.1/tcp/{port}")).await;
    assert!(addrs.iter().all(|a| a.starts_with("/ip4/")), "{addrs:?}");
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok());
    if ipv6_loopback("ipv4_config_stays_on_the_ipv4_wildcard, its IPv6 half") {
        assert!(tokio::net::TcpStream::connect(("::1", port)).await.is_err());
    }
}
