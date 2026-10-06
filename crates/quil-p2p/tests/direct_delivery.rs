//! Two real nodes on loopback: a direct message reaches the one peer it is
//! sent to, as a message on its bitmask from the sender, only on a bitmask
//! the receiver allows.

use std::time::Duration;

use quil_p2p::{DirectOutcome, P2PNode};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
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
    let receiver_port = free_port();
    let (receiver, mut inbound) = receiver
        .start(&mut sup, &format!("/ip4/127.0.0.1/tcp/{receiver_port}"))
        .await
        .unwrap();

    let mut sender_config = config.clone();
    sender_config.bootstrap_peers = vec![format!("/ip4/127.0.0.1/tcp/{receiver_port}/p2p/{receiver_id}")];
    let sender = P2PNode::new_with_options(&sender_config, true, None).unwrap();
    let sender_id = sender.peer_id;
    let (sender, _) = sender
        .start(&mut sup, &format!("/ip4/127.0.0.1/tcp/{}", free_port()))
        .await
        .unwrap();

    let allowed = vec![1, 7, 7];
    receiver.allow_direct(allowed.clone()).await;
    // The sender dials its bootstrap peer on its first discovery tick.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let outcome = loop {
        let outcome = sender.send_direct(receiver_id, allowed.clone(), b"resolver response".to_vec()).await;
        if outcome != DirectOutcome::NotConnected || tokio::time::Instant::now() > deadline {
            break outcome;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(outcome, DirectOutcome::Delivered);
    let message = tokio::time::timeout(Duration::from_secs(5), inbound.recv()).await.unwrap().unwrap();
    assert_eq!(message.bitmask, allowed);
    assert_eq!(message.data, b"resolver response");
    assert_eq!(message.from, sender_id.to_bytes(), "attributed to the authenticated connection's peer");

    assert_eq!(
        sender.send_direct(receiver_id, vec![9, 9], b"elsewhere".to_vec()).await,
        DirectOutcome::Refused,
        "a bitmask the receiver does not allow is refused"
    );
    receiver.revoke_direct(allowed.clone()).await;
    assert_eq!(sender.send_direct(receiver_id, allowed.clone(), Vec::new()).await, DirectOutcome::Refused);
    assert_eq!(
        sender.send_direct(quil_p2p::PeerId::random(), allowed, Vec::new()).await,
        DirectOutcome::NotConnected,
        "no dial: an unconnected peer is reported at once"
    );
    let stats = sender.direct_stats();
    assert_eq!((stats.delivered, stats.refused), (1, 2));
    assert_eq!(receiver.direct_stats().received, 1);
}
