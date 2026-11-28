//! A direct send was answered "delivered" once the message entered the
//! receiver's queue. The application could still drop it there (a full
//! queue further on, or a standalone worker that does not answer), and its
//! sender, told "delivered", sent no gossip copy: the member lost it. A
//! message the receiver's application does not take must be reported not
//! delivered.

use std::time::Duration;

use quil_p2p::node::{ListenFamily, ListenTransport, CONNECT_WAIT};
use quil_p2p::{DirectOutcome, P2PNode};

#[tokio::test]
async fn reproduces_a_direct_message_reported_delivered_before_it_is_taken() {
    let mut sup = quil_lifecycle::Supervisor::<anyhow::Error>::new();
    let config = quil_config::P2PConfig {
        network: 99,
        bootstrap_peers: Vec::new(),
        direct_peers: Vec::new(),
        ..Default::default()
    };

    let receiver = P2PNode::new_with_options(&config, true, None).unwrap();
    let receiver_id = receiver.peer_id;
    let (receiver, mut inbound, receiver_port) = receiver
        .start_on_loopback(&mut sup, ListenTransport::Tcp, ListenFamily::Ip4)
        .await
        .unwrap();
    // The application reads each message and drops it, as one whose own
    // queue is full does.
    let (read_tx, mut read) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(message) = inbound.recv().await {
            let _ = read_tx.send(message.data.clone());
            drop(message);
        }
    });

    let mut sender_config = config.clone();
    sender_config.bootstrap_peers = vec![format!(
        "/ip4/127.0.0.1/tcp/{receiver_port}/p2p/{receiver_id}"
    )];
    let sender = P2PNode::new_with_options(&sender_config, true, None).unwrap();
    let (sender, _, _) = sender
        .start_on_loopback(&mut sup, ListenTransport::Tcp, ListenFamily::Ip4)
        .await
        .unwrap();

    let allowed = vec![1, 7, 7];
    receiver.allow_direct(allowed.clone()).await;
    let deadline = tokio::time::Instant::now() + CONNECT_WAIT;
    let outcome = loop {
        let outcome = sender
            .send_direct(receiver_id, allowed.clone(), b"a vote".to_vec())
            .await;
        if outcome != DirectOutcome::NotConnected || tokio::time::Instant::now() > deadline {
            break outcome;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let arrived = tokio::time::timeout(Duration::from_secs(5), read.recv())
        .await
        .expect("the message reached the receiver's application")
        .unwrap();
    assert_eq!(
        arrived, b"a vote",
        "the premise: it arrived and was dropped"
    );
    assert_eq!(
        outcome,
        DirectOutcome::Refused,
        "a message its receiver's application dropped was reported {outcome:?}"
    );
}
