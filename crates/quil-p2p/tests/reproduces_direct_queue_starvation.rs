//! Direct messages share the receive queue with gossip and bypass gossip's
//! duplicate check and scoring: one connected peer must not be able to fill
//! that queue, or the node drops gossip (consensus messages among it).

use std::time::Duration;

use quil_p2p::{DirectOutcome, P2PNode};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Slots of the node's receive queue (`P2PNode::start`).
const RECEIVE_QUEUE: usize = 4096;

#[tokio::test]
async fn reproduces_direct_messages_filling_the_receive_queue() {
    let mut sup = quil_lifecycle::Supervisor::<anyhow::Error>::new();
    let mut config = quil_config::P2PConfig::default();
    config.network = 99;
    config.bootstrap_peers = Vec::new();
    config.direct_peers = Vec::new();

    let receiver = P2PNode::new_with_options(&config, true, None).unwrap();
    let receiver_id = receiver.peer_id;
    let receiver_port = free_port();
    // The receive queue is never read, like that of a node whose receive
    // loop is busy; it must stay open.
    let (receiver, _inbound) = receiver
        .start(&mut sup, &format!("/ip4/127.0.0.1/tcp/{receiver_port}"))
        .await
        .unwrap();

    let mut sender_config = config.clone();
    sender_config.bootstrap_peers = vec![format!(
        "/ip4/127.0.0.1/tcp/{receiver_port}/p2p/{receiver_id}"
    )];
    let sender = P2PNode::new_with_options(&sender_config, true, None).unwrap();
    let (sender, _) = sender
        .start(&mut sup, &format!("/ip4/127.0.0.1/tcp/{}", free_port()))
        .await
        .unwrap();

    let allowed = vec![1, 7, 7];
    receiver.allow_direct(allowed.clone()).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut delivered = loop {
        let outcome = sender
            .send_direct(receiver_id, allowed.clone(), vec![0])
            .await;
        if outcome == DirectOutcome::Delivered {
            break 1;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the sender never reached the receiver: {outcome:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    let sent = RECEIVE_QUEUE * 3 / 4 + 256;
    for _ in 1..sent {
        if sender
            .send_direct(receiver_id, allowed.clone(), vec![0])
            .await
            == DirectOutcome::Delivered
        {
            delivered += 1;
        }
    }
    assert!(
        delivered <= RECEIVE_QUEUE * 3 / 4,
        "{delivered} of {sent} direct messages from one peer were queued: they took \
         {delivered} of the {RECEIVE_QUEUE} slots gossip shares with them"
    );
}
