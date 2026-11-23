//! Direct messages share the receive queue with gossip and bypass gossip's
//! duplicate check and scoring: one connected peer must not be able to fill
//! that queue, or the node drops gossip (consensus messages among it).

use std::time::Duration;

use futures::StreamExt;
use quil_p2p::node::{ListenFamily, ListenTransport, CONNECT_WAIT};
use quil_p2p::{DirectOutcome, P2PNode};

/// Direct sends in flight at once. A message left unread is answered only
/// after the receiver's take wait, so one at a time would take minutes.
const IN_FLIGHT: usize = 192;

/// Slots of the node's receive queue (`P2PNode::start`).
const RECEIVE_QUEUE: usize = 4096;

#[tokio::test]
async fn reproduces_direct_messages_filling_the_receive_queue() {
    let mut sup = quil_lifecycle::Supervisor::<anyhow::Error>::new();
    let config = quil_config::P2PConfig {
        network: 99,
        bootstrap_peers: Vec::new(),
        direct_peers: Vec::new(),
        ..Default::default()
    };

    let receiver = P2PNode::new_with_options(&config, true, None).unwrap();
    let receiver_id = receiver.peer_id;
    // The receive queue is never read, like that of a node whose receive
    // loop is busy; it must stay open.
    let (receiver, _inbound, receiver_port) = receiver
        .start_on_loopback(&mut sup, ListenTransport::Tcp, ListenFamily::Ip4)
        .await
        .unwrap();

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
    loop {
        let outcome = sender
            .send_direct(receiver_id, allowed.clone(), vec![0])
            .await;
        if outcome != DirectOutcome::NotConnected {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the sender never reached the receiver: {outcome:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        receiver.direct_stats().received,
        1,
        "the first one was queued"
    );

    let sent = RECEIVE_QUEUE * 3 / 4 + 256;
    futures::stream::iter(1..sent)
        .map(|_| sender.send_direct(receiver_id, allowed.clone(), vec![0]))
        .buffer_unordered(IN_FLIGHT)
        .collect::<Vec<_>>()
        .await;
    let queued = receiver.direct_stats().received as usize;
    assert!(
        queued <= RECEIVE_QUEUE * 3 / 4,
        "{queued} of {sent} direct messages from one peer were queued: they took \
         {queued} of the {RECEIVE_QUEUE} slots gossip shares with them"
    );
}
