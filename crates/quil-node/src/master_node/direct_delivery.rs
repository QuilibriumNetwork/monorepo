//! Point-to-point delivery of app-shard resolver messages to the committee
//! members they are addressed to, over this node's peer connections
//! (`quil_p2p::direct`), instead of to the shard's whole gossip topic. Used
//! for engines this node runs in-process and, through `SendShardConsensusDirect`,
//! for its standalone workers.

use std::collections::HashMap;
use std::sync::Arc;

/// Most recipients a resolver message is delivered to one by one; more go to
/// the topic.
pub(crate) const MAX_DIRECT_RECIPIENTS: usize = 4;

/// Committee key → network peer, from PeerInfo (`public_key` is the prover
/// key, the committee member's key): the mapping inbound shard consensus
/// messages are attributed by. Kept per key, since otherwise each lookup
/// scans every peer's PeerInfo.
#[derive(Clone)]
pub(crate) struct CommitteePeers {
    peer_info: Arc<parking_lot::RwLock<HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>>,
    known: Arc<parking_lot::Mutex<HashMap<Vec<u8>, quil_p2p::PeerId>>>,
}

impl CommitteePeers {
    pub(crate) fn new(peer_info: Arc<parking_lot::RwLock<HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>>) -> Self {
        Self { peer_info, known: Default::default() }
    }

    pub(crate) fn peer(&self, key: &[u8]) -> Option<quil_p2p::PeerId> {
        if let Some(peer) = self.known.lock().get(key) {
            return Some(*peer);
        }
        let peer = self
            .peer_info
            .read()
            .iter()
            .find(|(_, info)| info.public_key == key)
            .and_then(|(id, _)| quil_p2p::PeerId::from_bytes(id).ok())?;
        let mut known = self.known.lock();
        if known.len() >= 4096 {
            known.clear();
        }
        known.insert(key.to_vec(), peer);
        Some(peer)
    }

    pub(crate) fn forget(&self, key: &[u8]) {
        self.known.lock().remove(key);
    }
}

/// Deliver a resolver message to just its recipients over their existing
/// connections. False: send it to the topic instead (a member with no known
/// peer, not connected, without the protocol, or refusing it). A recipient
/// already served before a later one fails then also gets the topic copy,
/// which consensus ignores as a duplicate.
pub(crate) async fn deliver_direct(
    p2p: &quil_p2p::node::P2PHandle,
    peers: &CommitteePeers,
    recipients: &[Vec<u8>],
    topic: &[u8],
    payload: &[u8],
) -> bool {
    if recipients.len() > MAX_DIRECT_RECIPIENTS {
        return false;
    }
    for key in recipients {
        let Some(peer) = peers.peer(key) else { return false };
        if p2p.send_direct(peer, topic.to_vec(), payload.to_vec()).await != quil_p2p::DirectOutcome::Delivered {
            peers.forget(key);
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A committee key resolves to the peer whose PeerInfo names it, and is
    /// kept. Any recipient that cannot be served directly (unmapped, too
    /// many, or a send that fails) sends the message to the topic instead.
    #[tokio::test]
    async fn resolver_messages_go_direct_only_when_every_recipient_can_be_served() {
        let member = quil_p2p::PeerId::random();
        let key = vec![7u8; 897];
        let cache: Arc<parking_lot::RwLock<HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>> = Default::default();
        cache.write().insert(
            member.to_bytes(),
            quil_p2p::CanonicalPeerInfo { public_key: key.clone(), ..Default::default() },
        );
        let peers = CommitteePeers::new(cache.clone());
        assert_eq!(peers.peer(&key), Some(member));
        cache.write().clear();
        assert_eq!(peers.peer(&key), Some(member), "kept once found");
        peers.forget(&key);
        assert_eq!(peers.peer(&key), None);

        // The stub swarm never answers a direct send: every attempt fails.
        let p2p = quil_p2p::node::P2PHandle::for_test(false);
        let topic = quil_engine::bitmasks::shard_cw_bitmask(&[1; 32]);
        assert!(!deliver_direct(&p2p, &peers, &[vec![9u8; 897]], &topic, b"x").await, "unmapped");
        let many: Vec<Vec<u8>> = (0..=MAX_DIRECT_RECIPIENTS as u8).map(|n| vec![n; 897]).collect();
        assert!(!deliver_direct(&p2p, &peers, &many, &topic, b"x").await, "too many recipients");
        cache.write().insert(
            member.to_bytes(),
            quil_p2p::CanonicalPeerInfo { public_key: key.clone(), ..Default::default() },
        );
        assert!(!deliver_direct(&p2p, &peers, &[key.clone()], &topic, b"x").await, "a failed send");
        assert!(peers.known.lock().is_empty(), "a failed recipient is looked up again next time");
    }
}
