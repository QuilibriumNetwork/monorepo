//! Two real nodes on loopback: each gossip message is counted in its class,
//! as published and sent by the node that publishes it, and as received by
//! its peer, with the same encoded size on both sides.

use std::time::Duration;

use quil_p2p::{ClassTraffic, Flow, GossipClass, P2PNode};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[tokio::test]
async fn gossip_messages_are_counted_by_class_on_both_nodes() {
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
    let (sender, _) = sender
        .start(&mut sup, &format!("/ip4/127.0.0.1/tcp/{}", free_port()))
        .await
        .unwrap();

    // A shard's CW topic: `0x01 || appFilter`.
    let mut cw = vec![0x01u8];
    cw.extend_from_slice(&[0x40u8; 32]);
    receiver.subscribe_confirmed(cw.clone()).await.unwrap();
    sender.subscribe_confirmed(cw.clone()).await.unwrap();

    // The sender dials its bootstrap peer on its first discovery tick, and
    // publishing fails until it knows the receiver's subscription.
    let vote = [&[0x80u8][..], &[1u8; 8][..], &b"a vote"[..]].concat();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        match sender.publish(cw.clone(), vote.clone()).await {
            Ok(()) => break,
            Err(e) if tokio::time::Instant::now() > deadline => panic!("vote not published: {e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    let certificate = [&[0x81u8][..], &[2u8; 8][..], &b"a certificate, longer than the vote"[..]].concat();
    sender.publish(cw.clone(), certificate.clone()).await.unwrap();
    for expected in [&vote, &certificate] {
        let message = tokio::time::timeout(Duration::from_secs(10), inbound.recv()).await.unwrap().unwrap();
        assert_eq!(message.bitmask, cw);
        assert_eq!(&message.data, expected);
    }

    let sent = sender.gossip_traffic();
    let received = receiver.gossip_traffic();
    for (class, payload) in [(GossipClass::Votes, &vote), (GossipClass::ShardConsensus, &certificate)] {
        let (out, inc) = (sent.class(class), received.class(class));
        assert_eq!(out.published.messages, 1, "{}", class.name());
        assert_eq!(out.sent.messages, 1, "{}: one peer", class.name());
        assert_eq!(out.received, Flow::default(), "{}: not echoed back", class.name());
        assert!(out.published.bytes > payload.len() as u64, "{}: the encoded message, with its signature", class.name());
        assert_eq!(out.sent.bytes, out.published.bytes);
        assert_eq!(inc.received, out.sent, "{}: the receiver counts the copy the sender sent", class.name());
        assert_eq!(inc.unique, inc.received, "{}: a first copy", class.name());
        assert_eq!((inc.sent, inc.published), (Flow::default(), Flow::default()), "{}", class.name());
    }
    assert!(sent.class(GossipClass::ShardConsensus).sent.bytes > sent.class(GossipClass::Votes).sent.bytes);
    for class in [GossipClass::ShardFrames, GossipClass::Global, GossipClass::PeerInfo, GossipClass::Other] {
        assert_eq!(sent.class(class), ClassTraffic::default(), "sender {}", class.name());
        assert_eq!(received.class(class), ClassTraffic::default(), "receiver {}", class.name());
    }
    assert!(sent.uptime > Duration::ZERO);
}
