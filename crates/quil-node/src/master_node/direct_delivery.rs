//! Point-to-point delivery of app-shard consensus messages to the committee
//! members they are addressed to, over this node's peer connections
//! (`quil_p2p::direct`), instead of to the shard's whole gossip topic. Used
//! for engines this node runs in-process and, through `SendShardConsensusDirect`,
//! for its standalone workers.
//!
//! Votes, certificates and blocks went to the topic, whose mesh carried each
//! to every subscriber several times over: an estimated 27 Mbit/s of an
//! active node's shard consensus out, about 3 with a copy per member
//! (2026-11 estimate). Members not served directly share one topic copy.

use std::collections::HashMap;
use std::sync::Arc;

/// Most recipients a message is delivered to one by one; more go to the
/// topic. A committee is far smaller; this bounds a malformed request.
pub(crate) const MAX_DIRECT_RECIPIENTS: usize = 64;

/// How long one member's direct send may take before that member is served
/// by the topic copy instead. Consensus waits on votes, so this is well
/// under the direct protocol's own timeout; a send that lands later is a
/// duplicate consensus ignores.
pub(crate) const COMMITTEE_SEND_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(1500);

/// The direct side of a committee send.
#[async_trait::async_trait]
pub(crate) trait DirectSend: Send + Sync {
    async fn send_direct(
        &self,
        peer: quil_p2p::PeerId,
        topic: Vec<u8>,
        data: Vec<u8>,
    ) -> quil_p2p::DirectOutcome;
}

#[async_trait::async_trait]
impl DirectSend for quil_p2p::node::P2PHandle {
    async fn send_direct(
        &self,
        peer: quil_p2p::PeerId,
        topic: Vec<u8>,
        data: Vec<u8>,
    ) -> quil_p2p::DirectOutcome {
        quil_p2p::node::P2PHandle::send_direct(self, peer, topic, data).await
    }
}

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
    pub(crate) fn new(
        peer_info: Arc<parking_lot::RwLock<HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>>,
    ) -> Self {
        Self {
            peer_info,
            known: Default::default(),
        }
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

/// Deliver a shard CW message to each of its recipients over their existing
/// connections, all at once, each copy naming its member. Returns the
/// recipients not served (no known peer, not connected, without the
/// protocol, refusing it, or slower than [`COMMITTEE_SEND_TIMEOUT`]), in
/// request order: all of them when there are more than
/// [`MAX_DIRECT_RECIPIENTS`].
pub(crate) async fn deliver_direct<S: DirectSend + ?Sized>(
    sender: &S,
    peers: &CommitteePeers,
    channel: u64,
    bytes: &[u8],
    recipients: &[Vec<u8>],
    topic: &[u8],
) -> Vec<Vec<u8>> {
    if recipients.len() > MAX_DIRECT_RECIPIENTS {
        return recipients.to_vec();
    }
    let sends = recipients.iter().map(|key| async move {
        let peer = peers.peer(key)?;
        let payload =
            quil_engine::bitmasks::shard_cw_frame_for(channel, bytes, std::slice::from_ref(key));
        let sent = tokio::time::timeout(
            COMMITTEE_SEND_TIMEOUT,
            sender.send_direct(peer, topic.to_vec(), payload),
        )
        .await;
        if sent == Ok(quil_p2p::DirectOutcome::Delivered) {
            return Some(());
        }
        peers.forget(key);
        None
    });
    futures::future::join_all(sends)
        .await
        .into_iter()
        .zip(recipients)
        .filter(|(served, _)| served.is_none())
        .map(|(_, key)| key.clone())
        .collect()
}

/// The topic copy for the recipients [`deliver_direct`] did not serve, if
/// any: one naming its member when one is left, else one every member reads.
pub(crate) fn fallback_payload(
    channel: u64,
    bytes: &[u8],
    undelivered: &[Vec<u8>],
) -> Option<Vec<u8>> {
    (!undelivered.is_empty())
        .then(|| quil_engine::bitmasks::shard_cw_frame_for(channel, bytes, undelivered))
}

/// Send a shard CW message to its recipients, directly where possible and
/// through the topic for the rest; with no recipients, to the topic.
pub(crate) async fn send_committee(
    p2p: &quil_p2p::node::P2PHandle,
    peers: &CommitteePeers,
    core_id: u32,
    filter: &[u8],
    channel: u64,
    bytes: &[u8],
    recipients: &[Vec<u8>],
) {
    let topic = quil_engine::bitmasks::shard_cw_bitmask(filter);
    let payload = if recipients.is_empty() {
        quil_engine::bitmasks::shard_cw_frame_payload(channel, bytes)
    } else {
        let undelivered = deliver_direct(p2p, peers, channel, bytes, recipients, &topic).await;
        let Some(payload) = fallback_payload(channel, bytes, &undelivered) else {
            return;
        };
        p2p.note_direct_fallback();
        payload
    };
    super::cw_publish::publish_shard_cw(p2p, core_id, filter, topic, payload).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_p2p::DirectOutcome;
    use std::time::Duration;

    fn mapped(keys: &[(quil_p2p::PeerId, Vec<u8>)]) -> CommitteePeers {
        let cache: Arc<parking_lot::RwLock<HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>> =
            Default::default();
        for (peer, key) in keys {
            cache.write().insert(
                peer.to_bytes(),
                quil_p2p::CanonicalPeerInfo {
                    public_key: key.clone(),
                    ..Default::default()
                },
            );
        }
        CommitteePeers::new(cache)
    }

    /// Answers each peer after its delay with its outcome; records each send.
    #[derive(Default)]
    struct Peers {
        answers: HashMap<quil_p2p::PeerId, (Duration, DirectOutcome)>,
        sent: parking_lot::Mutex<Vec<(quil_p2p::PeerId, Vec<u8>)>>,
    }

    #[async_trait::async_trait]
    impl DirectSend for Peers {
        async fn send_direct(
            &self,
            peer: quil_p2p::PeerId,
            _topic: Vec<u8>,
            data: Vec<u8>,
        ) -> DirectOutcome {
            self.sent.lock().push((peer, data));
            let (delay, outcome) = self.answers[&peer];
            tokio::time::sleep(delay).await;
            outcome
        }
    }

    /// A committee key resolves to the peer whose PeerInfo names it, and is
    /// kept until a send to it fails.
    #[test]
    fn a_member_key_resolves_to_its_peer_until_forgotten() {
        let member = quil_p2p::PeerId::random();
        let key = vec![7u8; 897];
        let peers = mapped(&[(member, key.clone())]);
        assert_eq!(peers.peer(&key), Some(member));
        peers.peer_info.write().clear();
        assert_eq!(peers.peer(&key), Some(member), "kept once found");
        peers.forget(&key);
        assert_eq!(peers.peer(&key), None);
    }

    /// Every member of a committee larger than four gets its own copy, naming
    /// it, all sent at once; the members not served (unmapped, not
    /// connected, too slow) are returned in order, and forgotten.
    #[tokio::test(start_paused = true)]
    async fn each_member_gets_its_own_copy_at_once_and_the_rest_are_returned() {
        let delivered: Vec<_> = (1..=4u8)
            .map(|n| (quil_p2p::PeerId::random(), vec![n; 897]))
            .collect();
        let offline = (quil_p2p::PeerId::random(), vec![5u8; 897]);
        let slow = (quil_p2p::PeerId::random(), vec![6u8; 897]);
        let unmapped = vec![7u8; 897];
        let mut known = delivered.clone();
        known.extend([offline.clone(), slow.clone()]);
        let peers = mapped(&known);
        let mut sender = Peers::default();
        for (peer, _) in &delivered {
            sender
                .answers
                .insert(*peer, (Duration::from_secs(1), DirectOutcome::Delivered));
        }
        sender
            .answers
            .insert(offline.0, (Duration::ZERO, DirectOutcome::NotConnected));
        sender
            .answers
            .insert(slow.0, (Duration::from_secs(60), DirectOutcome::Delivered));
        let mut recipients: Vec<Vec<u8>> = delivered.iter().map(|(_, key)| key.clone()).collect();
        recipients.splice(2..2, [offline.1.clone(), unmapped.clone(), slow.1.clone()]);
        let topic = quil_engine::bitmasks::shard_cw_bitmask(&[1; 32]);

        let started = tokio::time::Instant::now();
        let undelivered = deliver_direct(&sender, &peers, 0, b"vote", &recipients, &topic).await;
        let took = started.elapsed();

        assert_eq!(
            undelivered,
            vec![offline.1.clone(), unmapped, slow.1.clone()]
        );
        assert!(
            took <= COMMITTEE_SEND_TIMEOUT,
            "sends run at once, the slowest bounded: {took:?}"
        );
        let sent = sender.sent.lock().clone();
        assert_eq!(sent.len(), 6, "every mapped member was sent to");
        for (peer, key) in known {
            let (_, payload) = sent.iter().find(|(to, _)| *to == peer).unwrap();
            assert_eq!(
                quil_engine::bitmasks::shard_cw_addressee(payload),
                Some(quil_engine::bitmasks::shard_cw_addressee_tag(&key)),
                "each copy names its member"
            );
            assert_eq!(
                quil_engine::bitmasks::shard_cw_split_payload(payload),
                Some((0, b"vote".as_slice()))
            );
        }
        assert!(
            peers.known.lock().get(&offline.1).is_none(),
            "looked up again"
        );
        assert!(peers.known.lock().get(&slow.1).is_none(), "looked up again");
        assert!(peers.known.lock().get(&delivered[0].1).is_some());
    }

    /// Past the bound, nothing is sent directly: every recipient is left to
    /// the topic.
    #[tokio::test]
    async fn too_many_recipients_all_go_to_the_topic() {
        let sender = Peers::default();
        let peers = mapped(&[]);
        let many: Vec<Vec<u8>> = (0..=MAX_DIRECT_RECIPIENTS as u8)
            .map(|n| vec![n; 897])
            .collect();
        let topic = quil_engine::bitmasks::shard_cw_bitmask(&[1; 32]);
        assert_eq!(
            deliver_direct(&sender, &peers, 1, b"x", &many, &topic).await,
            many
        );
        assert!(sender.sent.lock().is_empty());
    }

    /// The topic copy: none when every member was served, one naming the
    /// member when one is left, one every member reads when more are.
    #[test]
    fn the_members_left_share_one_topic_copy() {
        let (a, b) = (vec![1u8; 897], vec![2u8; 897]);
        assert_eq!(fallback_payload(1, b"cert", &[]), None);
        let one = fallback_payload(1, b"cert", std::slice::from_ref(&a)).unwrap();
        assert_eq!(
            quil_engine::bitmasks::shard_cw_addressee(&one),
            Some(quil_engine::bitmasks::shard_cw_addressee_tag(&a))
        );
        let both = fallback_payload(1, b"cert", &[a, b]).unwrap();
        assert_eq!(quil_engine::bitmasks::shard_cw_addressee(&both), None);
        assert_eq!(
            quil_engine::bitmasks::shard_cw_split_payload(&both),
            Some((1, b"cert".as_slice()))
        );
    }
}
