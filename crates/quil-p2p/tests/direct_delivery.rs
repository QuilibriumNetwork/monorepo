//! Two real nodes on loopback: a direct message reaches the one peer it is
//! sent to, as a message on its bitmask from the sender, only on a bitmask
//! the receiver allows.

use std::time::Duration;

use quil_p2p::node::{ListenFamily, ListenTransport, CONNECT_WAIT};
use quil_p2p::{DirectOutcome, P2PHandle, P2PNode};

/// The connection counters [`connection_state`] reports.
const COUNTERS: [&str; 3] = [
    "libp2p_connections_",
    "libp2p_dial_failures",
    "libp2p_incoming_failures",
];

/// A node's listen addresses, peer count and connection counters, for a
/// failure message: whether it listened, dialed, connected or lost the
/// connection.
fn connection_state(name: &str, node: &P2PHandle) -> String {
    let metrics = node.render_metrics();
    let counters: Vec<&str> = metrics
        .lines()
        .filter(|line| COUNTERS.iter().any(|c| line.starts_with(c)))
        .collect();
    format!(
        "{name}: listening on {:?}, {} peers, {}",
        node.listen_addresses(),
        node.peer_count(),
        counters.join(", ")
    )
}

#[tokio::test]
async fn a_direct_message_reaches_its_connected_peer_on_an_allowed_bitmask() {
    let mut sup = quil_lifecycle::Supervisor::<anyhow::Error>::new();
    let mut config = quil_config::P2PConfig::default();
    config.network = 99;
    config.bootstrap_peers = Vec::new();
    config.direct_peers = Vec::new();

    let receiver = P2PNode::new_with_options(&config, true, None).unwrap();
    let receiver_id = receiver.peer_id;
    let (receiver, mut inbound, receiver_port) = receiver
        .start_on_loopback(&mut sup, ListenTransport::Tcp, ListenFamily::Ip4)
        .await
        .unwrap();

    let mut sender_config = config.clone();
    sender_config.bootstrap_peers = vec![format!(
        "/ip4/127.0.0.1/tcp/{receiver_port}/p2p/{receiver_id}"
    )];
    let sender = P2PNode::new_with_options(&sender_config, true, None).unwrap();
    let sender_id = sender.peer_id;
    let (sender, _, _) = sender
        .start_on_loopback(&mut sup, ListenTransport::Tcp, ListenFamily::Ip4)
        .await
        .unwrap();

    let allowed = vec![1, 7, 7];
    receiver.allow_direct(allowed.clone()).await;
    // The sender dials its bootstrap peer once its listener binds.
    let deadline = tokio::time::Instant::now() + CONNECT_WAIT;
    let outcome = loop {
        let outcome = sender
            .send_direct(receiver_id, allowed.clone(), b"resolver response".to_vec())
            .await;
        if outcome != DirectOutcome::NotConnected || tokio::time::Instant::now() > deadline {
            break outcome;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        outcome,
        DirectOutcome::Delivered,
        "{}; {}",
        connection_state("sender", &sender),
        connection_state("receiver", &receiver)
    );
    let message = tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(message.bitmask, allowed);
    assert_eq!(message.data, b"resolver response");
    assert_eq!(
        message.from,
        sender_id.to_bytes(),
        "attributed to the authenticated connection's peer"
    );

    assert_eq!(
        sender
            .send_direct(receiver_id, vec![9, 9], b"elsewhere".to_vec())
            .await,
        DirectOutcome::Refused,
        "a bitmask the receiver does not allow is refused"
    );
    receiver.revoke_direct(allowed.clone()).await;
    assert_eq!(
        sender
            .send_direct(receiver_id, allowed.clone(), Vec::new())
            .await,
        DirectOutcome::Refused
    );
    assert_eq!(
        sender
            .send_direct(quil_p2p::PeerId::random(), allowed, Vec::new())
            .await,
        DirectOutcome::NotConnected,
        "no dial: an unconnected peer is reported at once"
    );
    let stats = sender.direct_stats();
    assert_eq!((stats.delivered, stats.refused), (1, 2));
    assert_eq!(receiver.direct_stats().received, 1);
}

/// The node's dials that failed before establishment. The counter has a
/// sample from the start, so a missing one fails instead of reading 0.
fn dial_failures(node: &P2PHandle) -> u64 {
    node.render_metrics()
        .lines()
        .filter(|line| line.starts_with("libp2p_dial_failures_total"))
        .filter_map(|line| line.rsplit(' ').next()?.trim().parse::<u64>().ok())
        .reduce(|a, b| a + b)
        .expect("the node's metrics count failed dials")
}

/// A bootstrap peer that refused the sender's dials before the discovery
/// tick is connected by the tick once it listens: a direct message
/// reaches it within [`CONNECT_WAIT`].
///
/// The sender dials the peer once its listener binds, Kademlia half a
/// second after it learns the address (a failed dial drops it), and
/// AutoNAT on its first probe, its boot delay after the start; AutoNAT
/// probes next 90 s later. The peer starts once AutoNAT's dial failed,
/// so only the tick reaches it within the wait.
#[tokio::test]
async fn a_bootstrap_peer_that_listens_late_is_connected_by_the_discovery_tick() {
    let mut sup = quil_lifecycle::Supervisor::<anyhow::Error>::new();
    let config = quil_config::P2PConfig {
        network: 99,
        bootstrap_peers: Vec::new(),
        direct_peers: Vec::new(),
        ..Default::default()
    };

    let receiver = P2PNode::new_with_options(&config, true, None).unwrap();
    let receiver_id = receiver.peer_id;
    // The receiver's port, held without a listener until the receiver
    // listens on it: a dial there is refused, and no other socket takes
    // the port. The receiver's listener binds beside this socket, as both
    // reuse the address and only one of them listens.
    let reserve = tokio::net::TcpSocket::new_v4().unwrap();
    reserve.set_reuseaddr(true).unwrap();
    reserve.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let receiver_port = reserve.local_addr().unwrap().port();
    let receiver_addr = format!("/ip4/127.0.0.1/tcp/{receiver_port}");

    let mut sender_config = config.clone();
    sender_config.bootstrap_peers = vec![format!("{receiver_addr}/p2p/{receiver_id}")];
    // The node takes AutoNAT's default timings (a unit test of
    // `autonat_servers` holds it to them).
    let autonat_probe = tokio::time::Instant::now() + libp2p::autonat::Config::default().boot_delay;
    let sender = P2PNode::new_with_options(&sender_config, true, None).unwrap();
    let (sender, _, _) = sender
        .start_on_loopback(&mut sup, ListenTransport::Tcp, ListenFamily::Ip4)
        .await
        .unwrap();
    tokio::time::sleep_until(autonat_probe).await;
    let early = dial_failures(&sender);
    assert!(
        early > 0 && sender.peer_count() == 0,
        "the sender's dials before AutoNAT's failed; {}",
        connection_state("sender", &sender)
    );
    // AutoNAT's dial fails next; the tick would also count.
    let cap = tokio::time::Instant::now() + CONNECT_WAIT;
    while dial_failures(&sender) == early {
        assert!(
            tokio::time::Instant::now() < cap,
            "AutoNAT's first probe did not dial the peer; {}",
            connection_state("sender", &sender)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let (receiver, mut inbound) = receiver.start(&mut sup, &receiver_addr).await.unwrap();
    let allowed = vec![1, 7, 7];
    receiver.allow_direct(allowed.clone()).await;
    let deadline = tokio::time::Instant::now() + CONNECT_WAIT;
    let outcome = loop {
        let outcome = sender
            .send_direct(receiver_id, allowed.clone(), b"after the tick".to_vec())
            .await;
        if outcome != DirectOutcome::NotConnected || tokio::time::Instant::now() > deadline {
            break outcome;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        outcome,
        DirectOutcome::Delivered,
        "the discovery tick re-dials a bootstrap peer it is not connected to; {}; {}",
        connection_state("sender", &sender),
        connection_state("receiver", &receiver)
    );
    let message = tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(message.data, b"after the tick");
    drop(reserve);
}
