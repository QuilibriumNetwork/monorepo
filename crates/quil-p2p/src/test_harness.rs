//! In-memory multi-node test harness for `BlossomSubBehaviour`.
//!
//! Bypasses the libp2p swarm + transport layer entirely: each
//! `TestNode` owns a `BlossomSubBehaviour` and a `PeerId`, and
//! [`TestNetwork`] wires nodes together by mutating the behaviours'
//! `connected_peers` / `peer_subscriptions` directly. Outbound RPCs
//! are collected from each behaviour's event queue, decoded with
//! [`crate::protocol::decode_rpc`], and delivered to the recipient's
//! [`BlossomSubBehaviour::handle_rpc`].
//!
//! Lets us write integration-style tests (mesh formation across N
//! nodes, message propagation, partition/heal scenarios, score-driven
//! eviction across a real topology) without the runtime cost or
//! flakiness of spinning up real libp2p swarms. Heartbeats are
//! injected explicitly so tests are deterministic regardless of wall-
//! clock timing.

use std::collections::{HashMap, HashSet};

use libp2p::PeerId;

use crate::behaviour::{BlossomSubBehaviour, BlossomSubEvent};
use crate::protocol::pb;

/// One node in the in-memory network.
pub struct TestNode {
    pub peer_id: PeerId,
    pub behaviour: BlossomSubBehaviour,
    /// Messages this node has received from its peers (collected from
    /// emitted `BlossomSubEvent::Message` events during `pump`).
    pub received: Vec<ReceivedMessage>,
}

/// A message a node received from a peer.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub propagation_source: PeerId,
    pub message_id: Vec<u8>,
    pub bitmask: Vec<u8>,
    pub data: Vec<u8>,
}

/// Network of N test nodes wired together via direct RPC delivery.
pub struct TestNetwork {
    pub nodes: Vec<TestNode>,
}

impl TestNetwork {
    /// Create a network of `n` disconnected nodes. Use `connect` or
    /// one of the topology helpers below to wire them together.
    pub fn new(n: usize) -> Self {
        let mut nodes = Vec::with_capacity(n);
        for _ in 0..n {
            let peer_id = PeerId::random();
            let mut behaviour = BlossomSubBehaviour::default();
            behaviour.set_local_peer_id(peer_id);
            nodes.push(TestNode {
                peer_id,
                behaviour,
                received: Vec::new(),
            });
        }
        Self { nodes }
    }

    /// Establish a bidirectional connection between nodes `a` and
    /// `b`. Each side learns the other's peer_id is connected and
    /// the other's current subscription set.
    pub fn connect(&mut self, a: usize, b: usize) {
        assert!(a != b, "cannot connect a node to itself");
        let (peer_a, peer_b) = (self.nodes[a].peer_id, self.nodes[b].peer_id);
        let subs_a: HashSet<Vec<u8>> = self.nodes[a].behaviour.subscriptions().clone();
        let subs_b: HashSet<Vec<u8>> = self.nodes[b].behaviour.subscriptions().clone();

        // A learns about B.
        self.nodes[a].behaviour.test_record_connection(peer_b);
        for bm in &subs_b {
            self.nodes[a].behaviour.test_record_subscription(peer_b, bm.clone());
        }
        // B learns about A.
        self.nodes[b].behaviour.test_record_connection(peer_a);
        for bm in &subs_a {
            self.nodes[b].behaviour.test_record_subscription(peer_a, bm.clone());
        }
    }

    /// Subscribe node `i` to `bitmask`. Also notifies all currently-
    /// connected peers (mirrors how `subscribe()` + heartbeat would
    /// surface the subscription to the wire).
    pub fn subscribe(&mut self, i: usize, bitmask: Vec<u8>) {
        let peer_id = self.nodes[i].peer_id;
        self.nodes[i].behaviour.subscribe(bitmask.clone());

        // Propagate the subscription to every node that knows `i` as
        // a connected peer — keeps `peer_subscriptions` consistent
        // with what real subscription RPCs would deliver.
        for j in 0..self.nodes.len() {
            if j == i {
                continue;
            }
            if self.nodes[j].behaviour.is_connected(&peer_id) {
                self.nodes[j]
                    .behaviour
                    .test_record_subscription(peer_id, bitmask.clone());
            }
        }
    }

    /// Publish a message from node `i`. Returns the underlying
    /// behaviour result.
    pub fn publish(
        &mut self,
        i: usize,
        bitmask: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<(), String> {
        self.nodes[i].behaviour.publish(bitmask, data)
    }

    /// Drive a heartbeat tick on every node.
    pub fn heartbeat_all(&mut self) {
        for node in &mut self.nodes {
            node.behaviour.test_force_heartbeat();
        }
    }

    /// One pump cycle: drain outbound RPC events from every node and
    /// deliver them to the targeted recipients. Inbound
    /// `BlossomSubEvent::Message` events are collected into
    /// `TestNode::received`. Returns the number of RPCs delivered.
    ///
    /// Most non-trivial scenarios need several pump cycles (a publish
    /// from node 0 reaches node 1's mesh, which forwards to node 2,
    /// etc.). See `pump_until_stable` for the convenience helper.
    pub fn pump(&mut self) -> usize {
        // Phase 1: collect outbound deliveries from every node.
        struct Outbound {
            from: PeerId,
            target: PeerId,
            rpc: pb::Rpc,
        }
        let mut outbound: Vec<Outbound> = Vec::new();
        for node in &mut self.nodes {
            let from = node.peer_id;
            node.behaviour.test_drain_events(|target, rpc_bytes| {
                if let Ok((rpc, _)) = crate::protocol::decode_rpc(&rpc_bytes) {
                    outbound.push(Outbound { from, target, rpc });
                }
            });
            // Also drain any locally-generated Message events into
            // `received` — these happen when the behaviour processes
            // an incoming publish and surfaces it to the application
            // layer.
            node.behaviour.test_drain_generated(|ev| {
                if let BlossomSubEvent::Message {
                    propagation_source,
                    message_id,
                    message,
                } = ev
                {
                    node.received.push(ReceivedMessage {
                        propagation_source,
                        message_id,
                        bitmask: message.bitmask,
                        data: message.data,
                    });
                }
            });
        }

        // Phase 2: deliver each outbound RPC to the target node.
        let delivered = outbound.len();
        // Build a peer_id → node index map for delivery routing.
        let index: HashMap<PeerId, usize> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.peer_id, i))
            .collect();
        for Outbound { from, target, rpc } in outbound {
            if let Some(&j) = index.get(&target) {
                self.nodes[j].behaviour.handle_rpc(from, rpc);
            }
            // Target not in the network → drop (peer disconnected).
        }

        delivered
    }

    /// Pump until no more RPCs are flowing or `max_rounds` hit.
    /// Returns the number of rounds executed.
    pub fn pump_until_stable(&mut self, max_rounds: usize) -> usize {
        for round in 0..max_rounds {
            let delivered = self.pump();
            if delivered == 0 {
                return round + 1;
            }
        }
        max_rounds
    }

    /// Reset the `received` log on every node — useful between
    /// per-message propagation rounds.
    pub fn clear_received(&mut self) {
        for node in &mut self.nodes {
            node.received.clear();
        }
    }

    /// Number of subscribers to `bitmask` across the network.
    pub fn subscribers(&self, bitmask: &[u8]) -> usize {
        self.nodes
            .iter()
            .filter(|n| n.behaviour.subscriptions().contains(bitmask))
            .count()
    }

    // ---- topology helpers ----

    /// Connect every pair of nodes (n × (n−1) / 2 connections).
    pub fn dense_connect(&mut self) {
        let n = self.nodes.len();
        for i in 0..n {
            for j in (i + 1)..n {
                self.connect(i, j);
            }
        }
    }

    /// Sparse: each node connected to its `degree` forward neighbours
    /// on a ring (mod n). Each (i, i+k) pair only added once via a
    /// seen-pair dedup so degree is uniform across the network.
    /// Final per-node degree is `2 * degree` (each node has both its
    /// own `degree` forward neighbours and `degree` inbound from
    /// predecessors).
    pub fn sparse_connect(&mut self, degree: usize) {
        let n = self.nodes.len();
        if n <= 1 {
            return;
        }
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        for i in 0..n {
            for offset in 1..=degree {
                let j = (i + offset) % n;
                if i == j {
                    continue;
                }
                let pair = if i < j { (i, j) } else { (j, i) };
                if seen.insert(pair) {
                    self.connect(i, j);
                }
            }
        }
    }

    /// Star: node 0 is the hub; every other node connects only to
    /// node 0.
    pub fn star_connect(&mut self) {
        for i in 1..self.nodes.len() {
            self.connect(0, i);
        }
    }
}

#[cfg(test)]
mod harness_tests {
    use super::*;

    /// A new network of N nodes has no inter-node knowledge until
    /// `connect` runs.
    #[test]
    fn new_network_starts_disconnected() {
        let net = TestNetwork::new(5);
        assert_eq!(net.nodes.len(), 5);
        for node in &net.nodes {
            assert_eq!(node.behaviour.connected_count(), 0);
        }
    }

    /// After `connect(0, 1)`, both nodes see each other as connected.
    #[test]
    fn connect_is_bidirectional() {
        let mut net = TestNetwork::new(2);
        net.connect(0, 1);
        let peer0 = net.nodes[0].peer_id;
        let peer1 = net.nodes[1].peer_id;
        assert!(net.nodes[0].behaviour.is_connected(&peer1));
        assert!(net.nodes[1].behaviour.is_connected(&peer0));
    }

    /// Subscription on node `i` propagates to every connected peer's
    /// `peer_subscriptions` view.
    #[test]
    fn subscribe_propagates_to_connected_peers() {
        let mut net = TestNetwork::new(3);
        net.dense_connect();
        let bm = vec![0xC0];
        net.subscribe(0, bm.clone());

        let peer0 = net.nodes[0].peer_id;
        for j in 1..3 {
            assert!(
                net.nodes[j].behaviour.peer_subscribed_to(&peer0, &bm),
                "node {} should see node 0's subscription",
                j,
            );
        }
    }

    /// `dense_connect` produces n × (n−1) / 2 unique pairs.
    #[test]
    fn dense_connect_links_every_pair() {
        let n = 4;
        let mut net = TestNetwork::new(n);
        net.dense_connect();
        for node in &net.nodes {
            assert_eq!(
                node.behaviour.connected_count(),
                n - 1,
                "each node should see n-1 peers",
            );
        }
    }

    /// `star_connect` makes node 0 the hub: n-1 connections; every
    /// leaf node has exactly 1 connection (to node 0).
    #[test]
    fn star_connect_centers_on_hub() {
        let n = 5;
        let mut net = TestNetwork::new(n);
        net.star_connect();
        assert_eq!(net.nodes[0].behaviour.connected_count(), n - 1);
        for i in 1..n {
            assert_eq!(
                net.nodes[i].behaviour.connected_count(),
                1,
                "leaf {} should only see the hub",
                i,
            );
        }
    }

    /// `sparse_connect(degree)` gives every node roughly `degree`
    /// links (each i picks `degree` offsets forward; self-counting
    /// yields exactly `degree` from-i edges, plus inbound from prior
    /// indices in the wraparound).
    #[test]
    fn sparse_connect_yields_consistent_degree() {
        let n = 8;
        let degree = 2;
        let mut net = TestNetwork::new(n);
        net.sparse_connect(degree);
        // Each node has both incoming (from earlier i values whose
        // wraparound landed on this one) and outgoing edges. Net
        // degree per node is exactly `2 * degree` for this scheme
        // (every edge is bidirectional and each node contributes
        // `degree` outgoing pairs).
        for node in &net.nodes {
            assert_eq!(
                node.behaviour.connected_count(),
                2 * degree,
                "expected uniform degree under sparse_connect",
            );
        }
    }
}
