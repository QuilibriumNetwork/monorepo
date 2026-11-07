//! A standalone worker connects under its own transport identity but signs
//! gossip with its node's identity, which is also its master's transport
//! identity (`P2PNode::new_for_worker`). An honest relay forwards the master's
//! messages to the worker: the relay excludes only the message's source, the
//! master, and cannot know the worker shares its identity. The worker must
//! check such a message like any other; the relay must keep its score.

use std::time::Duration;

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, Swarm, SwarmBuilder};
use quil_p2p::{BlossomSubBehaviour, BlossomSubEvent, Keypair};

/// GLOBAL_PEER_INFO, scored on every build.
const PEER_INFO: [u8; 4] = [0, 0, 0, 0];

/// A wait fails when it makes no progress for this long.
const STALL: Duration = Duration::from_secs(30);
/// And in any case after this long.
const CAP: Duration = Duration::from_secs(120);

fn swarm(transport: Keypair, signing: Keypair) -> Swarm<BlossomSubBehaviour> {
    SwarmBuilder::with_existing_identity(transport)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .expect("tcp transport")
        .with_behaviour(move |_| {
            let mut behaviour = BlossomSubBehaviour::new(0);
            behaviour.set_signing_identity(signing.public().to_peer_id(), signing);
            Ok(behaviour)
        })
        .expect("behaviour")
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build()
}

/// Messages the swarm's gossipsub refused, on every topic.
fn invalid_messages(swarm: &Swarm<BlossomSubBehaviour>) -> u64 {
    quil_p2p::metrics::render(&swarm.behaviour().metrics_registry())
        .lines()
        .filter(|line| line.starts_with("gossipsub_invalid_messages_per_topic_total"))
        .filter_map(|line| line.rsplit(' ').next()?.trim().parse::<u64>().ok())
        .sum()
}

async fn listen(swarm: &mut Swarm<BlossomSubBehaviour>) -> Multiaddr {
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .expect("listen");
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return address;
        }
    }
}

/// What the worker made of its master's message, relayed by an honest peer:
/// the relay's score at the worker, whether the message reached the worker,
/// and how many messages the worker's gossipsub refused.
struct Outcome {
    relay_score: f64,
    delivered: bool,
    refused: u64,
}

/// Master and worker share the node identity; each is connected only to the
/// relay. The master publishes on `bitmask` once the relay meshes both; the
/// run ends when the worker delivers the message or refuses one.
async fn master_message_relayed_to_its_worker(bitmask: &[u8]) -> Outcome {
    let node = Keypair::generate_ed25519();
    let relay_key = Keypair::generate_ed25519();
    let mut master = swarm(node.clone(), node.clone());
    let mut relay = swarm(relay_key.clone(), relay_key);
    let mut worker = swarm(Keypair::generate_ed25519(), node);
    let relay_id = *relay.local_peer_id();
    assert_ne!(master.local_peer_id(), worker.local_peer_id());

    for swarm in [&mut master, &mut relay, &mut worker] {
        swarm.behaviour_mut().subscribe(bitmask.to_vec());
    }
    let relay_addr = listen(&mut relay).await;
    master.dial(relay_addr.clone()).expect("master dial");
    worker.dial(relay_addr).expect("worker dial");

    let payload = b"a message signed with the node identity".to_vec();
    let mut published = false;
    let mut delivered = false;
    let mut stage = 0u8;
    let started = tokio::time::Instant::now();
    let mut progressed = started;
    loop {
        tokio::select! {
            _ = master.select_next_some() => {}
            _ = relay.select_next_some() => {}
            event = worker.select_next_some() => {
                if let SwarmEvent::Behaviour(BlossomSubEvent::Message { message, .. }) = event {
                    if message.data == payload {
                        delivered = true;
                    }
                }
            }
            _ = tokio::time::sleep_until(progressed + STALL) => {}
        }
        let now_stage = if delivered || invalid_messages(&worker) > 0 {
            4
        } else if published {
            3
        } else if relay.behaviour().mesh_peers(bitmask) >= 2 {
            2
        } else if master.behaviour().peer_subscribed_to(&relay_id, bitmask) {
            1
        } else {
            0
        };
        if now_stage != stage {
            stage = now_stage;
            progressed = tokio::time::Instant::now();
        }
        if stage == 2 && !published {
            published = master
                .behaviour_mut()
                .publish(bitmask.to_vec(), payload.clone())
                .is_ok();
        }
        if stage == 4 {
            break;
        }
        let now = tokio::time::Instant::now();
        assert!(
            now < progressed + STALL && now < started + CAP,
            "no outcome: stage {stage} (0 connecting, 1 subscribed, 2 meshed, 3 published) \
             for {:?}, {:?} in all",
            now - progressed,
            now - started
        );
    }
    Outcome {
        relay_score: worker.behaviour().score(&relay_id),
        delivered,
        refused: invalid_messages(&worker),
    }
}

fn assert_relay_kept_its_score(topic: &str, outcome: Outcome) {
    let Outcome {
        relay_score,
        delivered,
        refused,
    } = outcome;
    assert!(
        relay_score >= 0.0,
        "VULNERABLE: on {topic}, the worker scored the honest relay {relay_score} for \
         forwarding its master's message: a self-origin penalty for a message signed by the \
         identity the worker shares with its master (refused {refused}, delivered {delivered})"
    );
    assert!(
        delivered && refused == 0,
        "on {topic}, the worker refused its master's relayed message as self-origin \
         (refused {refused}, delivered {delivered}, relay score {relay_score})"
    );
}

#[tokio::test]
async fn reproduces_a_shard_topic_relay_penalised_by_a_worker_sharing_its_masters_identity() {
    let shard_topic = [0x0c; 32];
    let outcome = master_message_relayed_to_its_worker(&shard_topic).await;
    assert_relay_kept_its_score("a shard topic", outcome);
}

#[tokio::test]
async fn reproduces_a_peer_info_relay_penalised_by_a_worker_sharing_its_masters_identity() {
    let outcome = master_message_relayed_to_its_worker(&PEER_INFO).await;
    assert_relay_kept_its_score("GLOBAL_PEER_INFO", outcome);
}
