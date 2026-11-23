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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quil_engine::cw_app_seams::CW_APP_RESOLVER_CHANNEL;
use tracing::info;

/// Most recipients a message is delivered to one by one; more go to the
/// topic. A committee is far smaller; this bounds a malformed request.
pub(crate) const MAX_DIRECT_RECIPIENTS: usize = 64;

/// Largest message delivered to members one by one; a larger one (a big
/// block) goes to the topic. Sent directly, the leader would upload a copy
/// per member (14 in a committee of 15) where the mesh has it upload about
/// six and members relay the rest, and the slowest copy would hold back the
/// topic copy of every member not served.
pub(crate) const MAX_DIRECT_BYTES: usize = 256 * 1024;

/// How long one member's direct send of a small message may take before
/// that member is served by the topic copy instead. Consensus waits on
/// votes, so this is well under the direct protocol's own timeout; a send
/// that lands later is a duplicate consensus ignores.
pub(crate) const COMMITTEE_SEND_TIMEOUT: Duration = Duration::from_millis(1500);

/// The upload rate, in bytes per second, a committee send is given time for
/// on top of [`COMMITTEE_SEND_TIMEOUT`].
const ASSUMED_UPLOAD_BYTES_PER_SEC: u64 = 4 * 1024 * 1024;

/// How long each of `copies` direct sends of `bytes`, all sent at once, may
/// take: [`COMMITTEE_SEND_TIMEOUT`] plus the time to upload every copy at
/// [`ASSUMED_UPLOAD_BYTES_PER_SEC`], within the direct protocol's timeout.
pub(crate) fn committee_send_timeout(copies: usize, bytes: usize) -> Duration {
    let upload = (copies as u64).saturating_mul(bytes as u64);
    let upload = Duration::from_millis(upload.saturating_mul(1000) / ASSUMED_UPLOAD_BYTES_PER_SEC);
    (COMMITTEE_SEND_TIMEOUT + upload).min(quil_p2p::direct::DIRECT_REQUEST_TIMEOUT)
}

/// The direct side of a committee send.
#[async_trait::async_trait]
pub(crate) trait DirectSend: Send + Sync {
    async fn send_direct(
        &self,
        peer: quil_p2p::PeerId,
        topic: Vec<u8>,
        data: Vec<u8>,
    ) -> quil_p2p::DirectOutcome;

    /// Where its sends are counted.
    fn committee_sends(&self) -> &CommitteeSends {
        &COMMITTEE_SENDS
    }
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

/// Both sides of a committee send.
pub(crate) trait CommitteeTransport: DirectSend + super::cw_publish::CwGossip {
    /// Record that a message's members not served directly got a topic copy.
    fn note_direct_fallback(&self);
}

impl CommitteeTransport for quil_p2p::node::P2PHandle {
    fn note_direct_fallback(&self) {
        quil_p2p::node::P2PHandle::note_direct_fallback(self);
    }
}

/// This node's committee sends since start.
pub(crate) static COMMITTEE_SENDS: CommitteeSends = CommitteeSends::new();

/// Committee sends of one CW channel: how many members direct delivery
/// served, which is what the bandwidth saving rests on.
pub(crate) struct ChannelSends {
    /// Messages with recipients.
    messages: AtomicU64,
    /// Their recipients, summed.
    members: AtomicU64,
    /// Recipients whose application took their copy.
    served: AtomicU64,
    /// Recipients with no known peer.
    unmapped: AtomicU64,
    /// Recipients sent to but not served: not connected, refused, without
    /// the protocol, failed or slower than the send's timeout.
    unserved: AtomicU64,
    /// Recipients on an earlier build, which answered on queueing.
    earlier: AtomicU64,
    /// Recipients of messages too large or too widely addressed to send
    /// one by one.
    kept: AtomicU64,
    /// Topic copies sent for recipients not served.
    copies: AtomicU64,
}

impl ChannelSends {
    const fn new() -> Self {
        Self {
            messages: AtomicU64::new(0),
            members: AtomicU64::new(0),
            served: AtomicU64::new(0),
            unmapped: AtomicU64::new(0),
            unserved: AtomicU64::new(0),
            earlier: AtomicU64::new(0),
            kept: AtomicU64::new(0),
            copies: AtomicU64::new(0),
        }
    }
}

/// A [`ChannelSends`] reading.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelSendCounts {
    pub(crate) messages: u64,
    pub(crate) members: u64,
    pub(crate) served: u64,
    pub(crate) unmapped: u64,
    pub(crate) unserved: u64,
    pub(crate) earlier: u64,
    pub(crate) kept: u64,
    pub(crate) copies: u64,
}

impl ChannelSendCounts {
    fn since(self, earlier: Self) -> Self {
        Self {
            messages: self.messages - earlier.messages,
            members: self.members - earlier.members,
            served: self.served - earlier.served,
            unmapped: self.unmapped - earlier.unmapped,
            unserved: self.unserved - earlier.unserved,
            earlier: self.earlier - earlier.earlier,
            kept: self.kept - earlier.kept,
            copies: self.copies - earlier.copies,
        }
    }
}

impl std::fmt::Display for ChannelSendCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}/{}/{}/{}/{}",
            self.messages,
            self.members,
            self.served,
            self.unmapped,
            self.unserved,
            self.earlier,
            self.kept,
            self.copies
        )
    }
}

/// CW channels: votes, certificates, the resolver and blocks.
const CHANNELS: usize = 4;

/// Committee sends by CW channel ([`ChannelSends`]); a channel beyond these
/// counts with blocks.
pub(crate) struct CommitteeSends {
    channels: [ChannelSends; CHANNELS],
}

impl Default for CommitteeSends {
    fn default() -> Self {
        Self::new()
    }
}

/// How one recipient of a committee send was served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Served {
    Yes,
    Unmapped,
    No,
    Earlier,
}

impl CommitteeSends {
    pub(crate) const fn new() -> Self {
        Self {
            channels: [
                ChannelSends::new(),
                ChannelSends::new(),
                ChannelSends::new(),
                ChannelSends::new(),
            ],
        }
    }

    fn channel(&self, channel: u64) -> &ChannelSends {
        &self.channels[usize::try_from(channel).map_or(CHANNELS - 1, |c| c.min(CHANNELS - 1))]
    }

    fn note_message(&self, channel: u64, members: usize) {
        let sends = self.channel(channel);
        sends.messages.fetch_add(1, Ordering::Relaxed);
        sends.members.fetch_add(members as u64, Ordering::Relaxed);
    }

    fn note_kept(&self, channel: u64, members: usize) {
        self.channel(channel)
            .kept
            .fetch_add(members as u64, Ordering::Relaxed);
    }

    fn note_member(&self, channel: u64, served: Served) {
        let sends = self.channel(channel);
        let counter = match served {
            Served::Yes => &sends.served,
            Served::Unmapped => &sends.unmapped,
            Served::No => &sends.unserved,
            Served::Earlier => &sends.earlier,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn note_copy(&self, channel: u64) {
        self.channel(channel).copies.fetch_add(1, Ordering::Relaxed);
    }

    /// Each channel's counts since start.
    pub(crate) fn counts(&self) -> [ChannelSendCounts; CHANNELS] {
        std::array::from_fn(|channel| {
            let sends = &self.channels[channel];
            let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
            ChannelSendCounts {
                messages: get(&sends.messages),
                members: get(&sends.members),
                served: get(&sends.served),
                unmapped: get(&sends.unmapped),
                unserved: get(&sends.unserved),
                earlier: get(&sends.earlier),
                kept: get(&sends.kept),
                copies: get(&sends.copies),
            }
        })
    }
}

/// How often [`log_committee_sends`] writes its line.
pub(crate) const COMMITTEE_SENDS_EVERY: Duration = Duration::from_secs(300);

/// One line of this node's committee sends by channel since `since`, the
/// counts read then: what share of members direct delivery served. Returns
/// the counts now.
pub(crate) fn log_committee_sends(
    since: [ChannelSendCounts; CHANNELS],
    secs: u64,
) -> [ChannelSendCounts; CHANNELS] {
    let now = COMMITTEE_SENDS.counts();
    let [votes, certificates, resolver, blocks] =
        std::array::from_fn(|channel| now[channel].since(since[channel]));
    if [votes, certificates, resolver, blocks]
        .iter()
        .any(|counts| counts.messages > 0)
    {
        info!(secs, %votes, %certificates, %resolver, %blocks,
            fields = "messages/members/served/unmapped/unserved/earlier build/kept on topic/topic copies",
            "committee sends by channel: members not served directly get a topic copy; if unserved or unmapped is high, check this node's connections to its committees");
    }
    now
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
/// protocol, refusing it, on an earlier build, or slower than
/// [`committee_send_timeout`]), in request order: all of them when there are
/// more than [`MAX_DIRECT_RECIPIENTS`] or the message is larger than
/// [`MAX_DIRECT_BYTES`].
pub(crate) async fn deliver_direct<S: DirectSend + ?Sized>(
    sender: &S,
    peers: &CommitteePeers,
    channel: u64,
    bytes: &[u8],
    recipients: &[Vec<u8>],
    topic: &[u8],
) -> Vec<Vec<u8>> {
    let counted = sender.committee_sends();
    counted.note_message(channel, recipients.len());
    if recipients.len() > MAX_DIRECT_RECIPIENTS || bytes.len() > MAX_DIRECT_BYTES {
        counted.note_kept(channel, recipients.len());
        return recipients.to_vec();
    }
    let timeout = committee_send_timeout(recipients.len(), bytes.len());
    // An earlier build answers once the message is queued, where it can
    // still be dropped: enough for a resolver reply, which is asked again,
    // not for consensus.
    let queued_serves = channel == CW_APP_RESOLVER_CHANNEL;
    let sends = recipients.iter().map(|key| async move {
        let Some(peer) = peers.peer(key) else {
            return Served::Unmapped;
        };
        let payload =
            quil_engine::bitmasks::shard_cw_frame_for(channel, bytes, std::slice::from_ref(key));
        let sent =
            tokio::time::timeout(timeout, sender.send_direct(peer, topic.to_vec(), payload)).await;
        match sent {
            Ok(quil_p2p::DirectOutcome::Delivered) => Served::Yes,
            Ok(quil_p2p::DirectOutcome::Queued) if queued_serves => Served::Yes,
            Ok(quil_p2p::DirectOutcome::Queued) => Served::Earlier,
            _ => {
                peers.forget(key);
                Served::No
            }
        }
    });
    let served = futures::future::join_all(sends).await;
    for served in &served {
        counted.note_member(channel, *served);
    }
    served
        .into_iter()
        .zip(recipients)
        .filter(|(served, _)| *served != Served::Yes)
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
pub(crate) async fn send_committee<T: CommitteeTransport>(
    transport: &T,
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
        let undelivered =
            deliver_direct(transport, peers, channel, bytes, recipients, &topic).await;
        let Some(payload) = fallback_payload(channel, bytes, &undelivered) else {
            return;
        };
        transport.note_direct_fallback();
        transport.committee_sends().note_copy(channel);
        payload
    };
    super::cw_publish::publish_shard_cw(transport, core_id, filter, topic, payload).await;
}

/// Topic copies this node is sending for its standalone workers' messages,
/// after answering them.
pub(crate) static WORKER_TOPIC_COPIES: quil_engine::spawn_gate::SpawnGate =
    quil_engine::spawn_gate::SpawnGate::new("worker-topic-copy", 256);

/// A standalone worker's shard CW message, relayed by this node: each member
/// directly, then the members left get a topic copy sent from here after the
/// worker is answered. False, with nothing sent, when `copies` are all in
/// flight: the worker then sends to the topic itself.
pub(crate) async fn relay_for_worker<T: CommitteeTransport + Clone + 'static>(
    transport: &T,
    peers: &CommitteePeers,
    copies: &'static quil_engine::spawn_gate::SpawnGate,
    filter: Vec<u8>,
    channel: u64,
    data: Vec<u8>,
    recipients: Vec<Vec<u8>>,
) -> bool {
    let Some(place) = copies.try_enter() else {
        return false;
    };
    let topic = quil_engine::bitmasks::shard_cw_bitmask(&filter);
    let undelivered = deliver_direct(transport, peers, channel, &data, &recipients, &topic).await;
    if let Some(payload) = fallback_payload(channel, &data, &undelivered) {
        transport.note_direct_fallback();
        transport.committee_sends().note_copy(channel);
        let transport = transport.clone();
        tokio::spawn(async move {
            let _place = place;
            // The worker's request does not name its core.
            super::cw_publish::publish_shard_cw(&transport, 0, &filter, topic, payload).await;
        });
    }
    true
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

    /// A direct send: to whom, what.
    type Sent = (quil_p2p::PeerId, Vec<u8>);
    /// A topic copy: topic, payload.
    type Published = (Vec<u8>, Vec<u8>);

    /// Answers each peer after its delay with its outcome; records each send
    /// and topic copy, and counts its own committee sends.
    #[derive(Default, Clone)]
    struct Peers {
        answers: HashMap<quil_p2p::PeerId, (Duration, DirectOutcome)>,
        sent: Arc<parking_lot::Mutex<Vec<Sent>>>,
        published: Arc<parking_lot::Mutex<Vec<Published>>>,
        fallbacks: Arc<AtomicU64>,
        sends: Arc<CommitteeSends>,
    }

    impl Peers {
        fn answering(
            members: &[(quil_p2p::PeerId, Vec<u8>)],
            after: Duration,
            outcome: DirectOutcome,
        ) -> Self {
            let mut peers = Self::default();
            for (peer, _) in members {
                peers.answers.insert(*peer, (after, outcome));
            }
            peers
        }
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

        fn committee_sends(&self) -> &CommitteeSends {
            &self.sends
        }
    }

    #[async_trait::async_trait]
    impl super::super::cw_publish::CwGossip for Peers {
        async fn publish(&self, topic: Vec<u8>, payload: Vec<u8>) -> quil_types::error::Result<()> {
            self.published.lock().push((topic, payload));
            Ok(())
        }

        fn peer_count(&self) -> usize {
            1
        }
    }

    impl CommitteeTransport for Peers {
        fn note_direct_fallback(&self) {
            self.fallbacks.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn members(from: u8, count: u8) -> Vec<(quil_p2p::PeerId, Vec<u8>)> {
        (from..from + count)
            .map(|n| (quil_p2p::PeerId::random(), vec![n; 897]))
            .collect()
    }

    fn keys(members: &[(quil_p2p::PeerId, Vec<u8>)]) -> Vec<Vec<u8>> {
        members.iter().map(|(_, key)| key.clone()).collect()
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
        assert_eq!(
            sender.sends.counts()[0],
            ChannelSendCounts {
                messages: 1,
                members: 7,
                served: 4,
                unmapped: 1,
                unserved: 2,
                ..Default::default()
            },
            "each member counted by how it was served"
        );
    }

    /// A message larger than a vote or a certificate (a block) is not sent
    /// one by one: the leader would upload a copy per member, where the mesh
    /// shares the upload.
    #[tokio::test]
    async fn a_large_message_goes_to_the_topic_not_to_each_member() {
        let committee = members(1, 14);
        let sender = Peers::answering(&committee, Duration::ZERO, DirectOutcome::Delivered);
        let peers = mapped(&committee);
        let topic = quil_engine::bitmasks::shard_cw_bitmask(&[1; 32]);
        let block = vec![9u8; 1024 * 1024];
        let recipients = keys(&committee);
        assert_eq!(
            deliver_direct(&sender, &peers, 3, &block, &recipients, &topic).await,
            recipients
        );
        assert!(sender.sent.lock().is_empty(), "no copy was sent directly");
        assert_eq!(sender.sends.counts()[3].kept, 14);
    }

    /// A message up to the direct size limit, sent to every other member of
    /// a committee of 15 at once, is given time to upload every copy.
    #[tokio::test(start_paused = true)]
    async fn a_mid_sized_message_gets_time_to_upload_every_copy() {
        let committee = members(1, 14);
        let sender = Peers::answering(&committee, Duration::from_secs(2), DirectOutcome::Delivered);
        let peers = mapped(&committee);
        let topic = quil_engine::bitmasks::shard_cw_bitmask(&[1; 32]);
        let block = vec![9u8; 200 * 1024];
        assert_eq!(
            deliver_direct(&sender, &peers, 3, &block, &keys(&committee), &topic).await,
            Vec::<Vec<u8>>::new(),
            "every member answering in 2 s is served"
        );
        assert_eq!(sender.sends.counts()[3].served, 14);
    }

    /// The send timeout grows with the bytes uploaded, up to the direct
    /// protocol's own.
    #[test]
    fn the_send_timeout_scales_with_the_upload_up_to_the_protocols() {
        assert_eq!(committee_send_timeout(14, 0), COMMITTEE_SEND_TIMEOUT);
        assert!(
            committee_send_timeout(14, 1000) < COMMITTEE_SEND_TIMEOUT + Duration::from_millis(10)
        );
        assert_eq!(
            committee_send_timeout(4, 1024 * 1024),
            COMMITTEE_SEND_TIMEOUT + Duration::from_secs(1)
        );
        assert_eq!(
            committee_send_timeout(64, MAX_DIRECT_BYTES),
            quil_p2p::direct::DIRECT_REQUEST_TIMEOUT
        );
    }

    /// An earlier build answers once a message is queued, where it can
    /// still be dropped: that serves a resolver reply, asked again if lost,
    /// but a vote, certificate or block still gets its topic copy. The peer
    /// stays known.
    #[tokio::test]
    async fn a_queued_answer_serves_only_a_resolver_reply() {
        let committee = members(1, 2);
        let sender = Peers::answering(&committee, Duration::ZERO, DirectOutcome::Queued);
        let peers = mapped(&committee);
        let topic = quil_engine::bitmasks::shard_cw_bitmask(&[1; 32]);
        let recipients = keys(&committee);
        for channel in [0, 1, 3] {
            assert_eq!(
                deliver_direct(&sender, &peers, channel, b"m", &recipients, &topic).await,
                recipients,
                "channel {channel}"
            );
            assert_eq!(sender.sends.counts()[channel as usize].earlier, 2);
        }
        assert_eq!(
            deliver_direct(
                &sender,
                &peers,
                CW_APP_RESOLVER_CHANNEL,
                b"m",
                &recipients,
                &topic
            )
            .await,
            Vec::<Vec<u8>>::new()
        );
        assert!(peers.known.lock().get(&recipients[0]).is_some(), "kept");
    }

    /// A committee send publishes to the topic only for the members not
    /// served: nothing when all were, one copy naming the member when one
    /// was not, and an unaddressed copy when the message names no one.
    #[tokio::test]
    async fn a_committee_send_publishes_only_for_the_members_left() {
        let committee = members(1, 3);
        let mut sender = Peers::answering(&committee, Duration::ZERO, DirectOutcome::Delivered);
        let peers = mapped(&committee);
        let filter = [1u8; 32];
        let topic = quil_engine::bitmasks::shard_cw_bitmask(&filter);
        let recipients = keys(&committee);

        send_committee(&sender, &peers, 0, &filter, 0, b"vote", &recipients).await;
        assert!(sender.published.lock().is_empty(), "all served");

        sender
            .answers
            .insert(committee[1].0, (Duration::ZERO, DirectOutcome::Refused));
        send_committee(&sender, &peers, 0, &filter, 0, b"vote", &recipients).await;
        let published = std::mem::take(&mut *sender.published.lock());
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, topic);
        assert_eq!(
            quil_engine::bitmasks::shard_cw_addressee(&published[0].1),
            Some(quil_engine::bitmasks::shard_cw_addressee_tag(
                &recipients[1]
            ))
        );
        assert_eq!(sender.fallbacks.load(Ordering::Relaxed), 1);
        assert_eq!(sender.sends.counts()[0].copies, 1);

        send_committee(&sender, &peers, 0, &filter, 2, b"ask", &[]).await;
        let published = std::mem::take(&mut *sender.published.lock());
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, topic);
        assert_eq!(
            quil_engine::bitmasks::shard_cw_addressee(&published[0].1),
            None
        );
        assert_eq!(
            quil_engine::bitmasks::shard_cw_split_payload(&published[0].1),
            Some((2, b"ask".as_slice()))
        );
        assert_eq!(sender.fallbacks.load(Ordering::Relaxed), 1);
    }

    /// A standalone worker's message is relayed: the worker is answered,
    /// then the members not served get a topic copy from this node. With
    /// every copy place taken, nothing is sent and the worker is told to
    /// send to the topic itself.
    #[tokio::test]
    async fn a_relayed_message_is_answered_then_copied_unless_copies_are_full() {
        static COPIES: quil_engine::spawn_gate::SpawnGate =
            quil_engine::spawn_gate::SpawnGate::new("test-worker-topic-copy", 1);
        let committee = members(1, 2);
        let mut sender = Peers::answering(&committee, Duration::ZERO, DirectOutcome::Delivered);
        sender.answers.insert(
            committee[0].0,
            (Duration::ZERO, DirectOutcome::NotConnected),
        );
        let peers = mapped(&committee);
        let filter = vec![1u8; 32];
        let recipients = keys(&committee);

        assert!(
            relay_for_worker(
                &sender,
                &peers,
                &COPIES,
                filter.clone(),
                1,
                b"cert".to_vec(),
                recipients.clone()
            )
            .await
        );
        let copied = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let copy = sender.published.lock().first().cloned();
                if let Some(copy) = copy.filter(|_| COPIES.in_flight() == 0) {
                    return copy;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the topic copy is sent after the answer");
        assert_eq!(
            quil_engine::bitmasks::shard_cw_addressee(&copied.1),
            Some(quil_engine::bitmasks::shard_cw_addressee_tag(
                &recipients[0]
            ))
        );
        assert_eq!(sender.sent.lock().len(), 2);

        let _held = COPIES.try_enter().expect("the copy freed its place");
        assert!(
            !relay_for_worker(
                &sender,
                &peers,
                &COPIES,
                filter,
                1,
                b"cert".to_vec(),
                recipients
            )
            .await,
            "refused with every place taken"
        );
        assert_eq!(sender.sent.lock().len(), 2, "nothing more was sent");
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
