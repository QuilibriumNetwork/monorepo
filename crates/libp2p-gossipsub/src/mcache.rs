// Copyright 2020 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    fmt::Debug,
};

use libp2p_identity::PeerId;

use crate::{
    topic::TopicHash,
    types::{MessageId, RawMessage},
};

/// CacheEntry stored in the history.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheEntry {
    mid: MessageId,
    topic: TopicHash,
}

/// QUILIBRIUM: occupancy and byte-budget evictions of the message cache.
///
/// The eviction counters are cumulative since the cache was created.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MessageCacheStats {
    /// Bytes currently accounted to cached messages: payload, signature, key, topic and id.
    pub bytes: usize,
    /// The configured budget ([`crate::Config::mcache_max_bytes`]).
    pub max_bytes: usize,
    /// Messages currently cached.
    pub messages: usize,
    /// Messages evicted to keep the cache within its budget.
    pub evicted_messages: u64,
    /// Bytes of the evicted messages.
    pub evicted_bytes: u64,
    /// Evicted messages that the application had not validated yet. Such a
    /// message still reaches the application, but is not forwarded.
    pub evicted_unvalidated: u64,
}

/// MessageCache struct holding history of messages.
#[derive(Clone)]
pub(crate) struct MessageCache {
    msgs: HashMap<MessageId, (RawMessage, HashSet<PeerId>)>,
    /// For every message and peer the number of times this peer asked for the message
    iwant_counts: HashMap<MessageId, HashMap<PeerId, u32>>,
    history: Vec<Vec<CacheEntry>>,
    /// The number of indices in the cache history used for gossiping. That means that a message
    /// won't get gossiped anymore when shift got called `gossip` many times after inserting the
    /// message in the cache.
    gossip: usize,
    /// QUILIBRIUM: byte budget. The history windows bound the cache by heartbeats, not by bytes:
    /// under a flood of large messages, or while heartbeats run late, the windows hold whatever
    /// arrives. When a new message would take the cache over `max_bytes`, the oldest messages
    /// are evicted, validated ones first, down to [`MessageCache::low_watermark`].
    max_bytes: usize,
    /// Bytes accounted to the messages in `msgs` (see [`cached_bytes`]).
    bytes: usize,
    evicted_messages: u64,
    evicted_bytes: u64,
    evicted_unvalidated: u64,
}

/// QUILIBRIUM: the bytes a cached message is accounted for: its payload, signature, key and
/// topic, plus its id, which is held twice (map key and history entry). Fixed-size fields and
/// allocator overhead are not counted.
fn cached_bytes(message_id: &MessageId, msg: &RawMessage) -> usize {
    msg.data.len()
        + msg.signature.as_ref().map_or(0, Vec::len)
        + msg.key.as_ref().map_or(0, Vec::len)
        + msg.topic.as_str().len()
        + 2 * message_id.0.len()
}

impl fmt::Debug for MessageCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageCache")
            .field("msgs", &self.msgs)
            .field("history", &self.history)
            .field("gossip", &self.gossip)
            .field("bytes", &self.bytes)
            .field("max_bytes", &self.max_bytes)
            .finish()
    }
}

/// Implementation of the MessageCache.
impl MessageCache {
    pub(crate) fn new(gossip: usize, history_capacity: usize, max_bytes: usize) -> Self {
        MessageCache {
            gossip,
            msgs: HashMap::default(),
            iwant_counts: HashMap::default(),
            history: vec![Vec::new(); history_capacity],
            max_bytes,
            bytes: 0,
            evicted_messages: 0,
            evicted_bytes: 0,
            evicted_unvalidated: 0,
        }
    }

    /// QUILIBRIUM: occupancy and eviction counters.
    pub(crate) fn stats(&self) -> MessageCacheStats {
        MessageCacheStats {
            bytes: self.bytes,
            max_bytes: self.max_bytes,
            messages: self.msgs.len(),
            evicted_messages: self.evicted_messages,
            evicted_bytes: self.evicted_bytes,
            evicted_unvalidated: self.evicted_unvalidated,
        }
    }

    /// QUILIBRIUM: the level an eviction pass brings the cache down to, 7/8 of the budget, so
    /// that one pass over the history makes room for many further messages.
    fn low_watermark(&self) -> usize {
        self.max_bytes - self.max_bytes / 8
    }

    /// QUILIBRIUM: evicts messages, oldest first, until at most `target` bytes remain. Validated
    /// messages go first: they have been forwarded already and only serve IWANT requests. Only
    /// if that is not enough, unvalidated ones follow; those still reach the application but are
    /// no longer forwarded. Evicted entries leave the history too, so they are not advertised.
    fn evict(&mut self, target: usize) {
        let MessageCache {
            msgs,
            iwant_counts,
            history,
            bytes,
            evicted_messages,
            evicted_bytes,
            evicted_unvalidated,
            ..
        } = self;
        for validated_only in [true, false] {
            // `history[0]` is the newest window; within a window, entries are in arrival order.
            for window in history.iter_mut().rev() {
                if *bytes <= target {
                    return;
                }
                window.retain(|entry| {
                    if *bytes <= target {
                        return true;
                    }
                    let validated = match msgs.get(&entry.mid) {
                        // Left behind by `remove`; drop it while we are here.
                        None => return false,
                        Some((msg, _)) => msg.validated,
                    };
                    if validated_only && !validated {
                        return true;
                    }
                    if let Some((msg, _)) = msgs.remove(&entry.mid) {
                        let size = cached_bytes(&entry.mid, &msg);
                        *bytes = bytes.saturating_sub(size);
                        *evicted_messages += 1;
                        *evicted_bytes += size as u64;
                        if !validated {
                            *evicted_unvalidated += 1;
                        }
                    }
                    iwant_counts.remove(&entry.mid);
                    false
                });
            }
        }
    }

    /// Put a message into the memory cache.
    ///
    /// Returns true if the message didn't already exist in the cache.
    pub(crate) fn put(&mut self, message_id: &MessageId, msg: RawMessage) -> bool {
        if self.history.is_empty() {
            return true;
        }
        // Don't add duplicate entries to the cache.
        if self.msgs.contains_key(message_id) {
            return false;
        }
        // QUILIBRIUM: make room within the byte budget before admitting the message. The new
        // message itself is always cached, as before, so a message larger than the whole budget
        // is cached alone.
        let size = cached_bytes(message_id, &msg);
        if self.bytes.saturating_add(size) > self.max_bytes {
            self.evict(self.low_watermark().saturating_sub(size));
        }
        let cache_entry = CacheEntry {
            mid: message_id.clone(),
            topic: msg.topic.clone(),
        };
        self.bytes += size;
        self.msgs
            .insert(message_id.clone(), (msg, HashSet::default()));
        self.history[0].push(cache_entry);

        tracing::trace!(message=?message_id, "Put message in mcache");
        true
    }

    /// Keeps track of peers we know have received the message to prevent forwarding to said peers.
    pub(crate) fn observe_duplicate(&mut self, message_id: &MessageId, source: &PeerId) {
        if let Some((message, originating_peers)) = self.msgs.get_mut(message_id) {
            // if the message is already validated, we don't need to store extra peers sending us
            // duplicates as the message has already been forwarded
            if message.validated {
                return;
            }

            originating_peers.insert(*source);
        }
    }

    /// Get a message with `message_id`
    #[cfg(test)]
    pub(crate) fn get(&self, message_id: &MessageId) -> Option<&RawMessage> {
        self.msgs.get(message_id).map(|(message, _)| message)
    }

    /// Increases the iwant count for the given message by one and returns the message together
    /// with the iwant if the message exists.
    pub(crate) fn get_with_iwant_counts(
        &mut self,
        message_id: &MessageId,
        peer: &PeerId,
    ) -> Option<(&RawMessage, u32)> {
        let iwant_counts = &mut self.iwant_counts;
        self.msgs.get(message_id).and_then(|(message, _)| {
            if !message.validated {
                None
            } else {
                Some((message, {
                    let count = iwant_counts
                        .entry(message_id.clone())
                        .or_default()
                        .entry(*peer)
                        .or_default();
                    *count += 1;
                    *count
                }))
            }
        })
    }

    /// Gets a message with [`MessageId`] and tags it as validated.
    /// This function also returns the known peers that have sent us this message. This is used to
    /// prevent us sending redundant messages to peers who have already propagated it.
    pub(crate) fn validate(
        &mut self,
        message_id: &MessageId,
    ) -> Option<(&RawMessage, HashSet<PeerId>)> {
        self.msgs.get_mut(message_id).map(|(message, known_peers)| {
            message.validated = true;
            // Clear the known peers list (after a message is validated, it is forwarded and we no
            // longer need to store the originating peers).
            let originating_peers = std::mem::take(known_peers);
            (&*message, originating_peers)
        })
    }

    /// Get a list of [`MessageId`]s for a given topic.
    pub(crate) fn get_gossip_message_ids(&self, topic: &TopicHash) -> Vec<MessageId> {
        self.history[..self.gossip]
            .iter()
            .fold(vec![], |mut current_entries, entries| {
                // search for entries with desired topic
                let mut found_entries: Vec<MessageId> = entries
                    .iter()
                    .filter_map(|entry| {
                        if &entry.topic == topic {
                            let mid = &entry.mid;
                            // Only gossip validated messages
                            if let Some(true) = self.msgs.get(mid).map(|(msg, _)| msg.validated) {
                                Some(mid.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect();

                // generate the list
                current_entries.append(&mut found_entries);
                current_entries
            })
    }

    /// Shift the history array down one and delete messages associated with the
    /// last entry.
    pub(crate) fn shift(&mut self) {
        if self.history.is_empty() {
            return;
        }

        for entry in self.history.pop().expect("history is always > 1") {
            if let Some((msg, _)) = self.msgs.remove(&entry.mid) {
                self.bytes = self.bytes.saturating_sub(cached_bytes(&entry.mid, &msg));
                if !msg.validated {
                    // If GossipsubConfig::validate_messages is true, the implementing
                    // application has to ensure that Gossipsub::validate_message gets called for
                    // each received message within the cache timeout time."
                    tracing::debug!(
                        message=%&entry.mid,
                        "The message got removed from the cache without being validated."
                    );
                }
            }
            tracing::trace!(message=%&entry.mid, "Remove message from the cache");

            self.iwant_counts.remove(&entry.mid);
        }

        // Insert an empty vec in position 0
        self.history.insert(0, Vec::new());
    }

    /// Removes a message from the cache and returns it if existent
    pub(crate) fn remove(
        &mut self,
        message_id: &MessageId,
    ) -> Option<(RawMessage, HashSet<PeerId>)> {
        // We only remove the message from msgs and iwant_count and keep the message_id in the
        // history vector. Zhe id in the history vector will simply be ignored on popping.

        self.iwant_counts.remove(message_id);
        let removed = self.msgs.remove(message_id);
        if let Some((msg, _)) = &removed {
            self.bytes = self.bytes.saturating_sub(cached_bytes(message_id, msg));
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentTopic as Topic;

    fn gen_testm(x: u64, topic: TopicHash) -> (MessageId, RawMessage) {
        let default_id = |message: &RawMessage| {
            // default message id is: source + sequence number
            let mut source_string = message.source.as_ref().unwrap().to_base58();
            source_string.push_str(&message.sequence_number.unwrap().to_string());
            MessageId::from(source_string)
        };
        let u8x: u8 = x as u8;
        let source = Some(PeerId::random());
        let data: Vec<u8> = vec![u8x];
        let sequence_number = Some(x);

        let m = RawMessage {
            source,
            data,
            sequence_number,
            topic,
            signature: None,
            key: None,
            validated: false,
        };

        let id = default_id(&m);
        (id, m)
    }

    fn new_cache(gossip_size: usize, history: usize) -> MessageCache {
        MessageCache::new(gossip_size, history, usize::MAX)
    }

    /// A message with a `len`-byte payload and a 4-byte id.
    fn sized_message(x: u32, len: usize, topic: TopicHash) -> (MessageId, RawMessage) {
        let m = RawMessage {
            source: None,
            data: vec![0; len],
            sequence_number: None,
            topic,
            signature: None,
            key: None,
            validated: false,
        };
        (MessageId::new(&x.to_be_bytes()), m)
    }

    #[test]
    /// Test that the message cache can be created.
    fn test_new_cache() {
        let x: usize = 3;
        let mc = new_cache(x, 5);

        assert_eq!(mc.gossip, x);
    }

    #[test]
    /// Test you can put one message and get one.
    fn test_put_get_one() {
        let mut mc = new_cache(10, 15);

        let topic1_hash = Topic::new("topic1").hash();
        let (id, m) = gen_testm(10, topic1_hash);

        mc.put(&id, m.clone());

        assert_eq!(mc.history[0].len(), 1);

        let fetched = mc.get(&id);

        assert_eq!(fetched.unwrap(), &m);
    }

    #[test]
    /// Test attempting to 'get' with a wrong id.
    fn test_get_wrong() {
        let mut mc = new_cache(10, 15);

        let topic1_hash = Topic::new("topic1").hash();
        let (id, m) = gen_testm(10, topic1_hash);

        mc.put(&id, m);

        // Try to get an incorrect ID
        let wrong_id = MessageId::new(b"wrongid");
        let fetched = mc.get(&wrong_id);
        assert!(fetched.is_none());
    }

    #[test]
    /// Test attempting to 'get' empty message cache.
    fn test_get_empty() {
        let mc = new_cache(10, 15);

        // Try to get an incorrect ID
        let wrong_string = MessageId::new(b"imempty");
        let fetched = mc.get(&wrong_string);
        assert!(fetched.is_none());
    }

    #[test]
    /// Test shift mechanism.
    fn test_shift() {
        let mut mc = new_cache(1, 5);

        let topic1_hash = Topic::new("topic1").hash();

        // Build the message
        for i in 0..10 {
            let (id, m) = gen_testm(i, topic1_hash.clone());
            mc.put(&id, m.clone());
        }

        mc.shift();

        // Ensure the shift occurred
        assert!(mc.history[0].is_empty());
        assert!(mc.history[1].len() == 10);

        // Make sure no messages deleted
        assert!(mc.msgs.len() == 10);
    }

    #[test]
    /// Test Shift with no additions.
    fn test_empty_shift() {
        let mut mc = new_cache(1, 5);

        let topic1_hash = Topic::new("topic1").hash();

        // Build the message
        for i in 0..10 {
            let (id, m) = gen_testm(i, topic1_hash.clone());
            mc.put(&id, m.clone());
        }

        mc.shift();

        // Ensure the shift occurred
        assert!(mc.history[0].is_empty());
        assert!(mc.history[1].len() == 10);

        mc.shift();

        assert!(mc.history[2].len() == 10);
        assert!(mc.history[1].is_empty());
        assert!(mc.history[0].is_empty());
    }

    #[test]
    /// Test shift to see if the last history messages are removed.
    fn test_remove_last_from_shift() {
        let mut mc = new_cache(4, 5);

        let topic1_hash = Topic::new("topic1").hash();

        // Build the message
        for i in 0..10 {
            let (id, m) = gen_testm(i, topic1_hash.clone());
            mc.put(&id, m.clone());
        }

        // Shift right until deleting messages
        mc.shift();
        mc.shift();
        mc.shift();
        mc.shift();

        assert_eq!(mc.history[mc.history.len() - 1].len(), 10);

        // Shift and delete the messages
        mc.shift();
        assert_eq!(mc.history[mc.history.len() - 1].len(), 0);
        assert_eq!(mc.history[0].len(), 0);
        assert_eq!(mc.msgs.len(), 0);
    }

    #[test]
    /// QUILIBRIUM: the byte budget bounds the cache however many messages one history window
    /// receives, evicting the oldest, validated ones first.
    fn test_byte_budget_bounds_the_cache() {
        let topic = Topic::new("t").hash();
        let (id, m) = sized_message(0, 1000, topic.clone());
        let entry = cached_bytes(&id, &m);
        let budget = 10 * entry;
        let mut mc = MessageCache::new(3, 5, budget);

        // An unvalidated message first: it outlives validated ones that arrive after it.
        let (pending, m) = sized_message(0, 1000, topic.clone());
        mc.put(&pending, m);
        for i in 1..100 {
            let (id, m) = sized_message(i, 1000, topic.clone());
            mc.put(&id, m);
            let _ = mc.validate(&id);
            assert!(
                mc.stats().bytes <= budget,
                "{:?} after {} puts",
                mc.stats(),
                i + 1
            );
        }

        let stats = mc.stats();
        assert_eq!(stats.bytes, stats.messages * entry);
        assert!(stats.messages >= 8, "{stats:?}");
        assert!(stats.evicted_messages > 0);
        assert_eq!(stats.evicted_unvalidated, 0);
        assert!(
            mc.get(&pending).is_some(),
            "the unvalidated message was evicted first"
        );
        assert!(mc.get(&MessageId::new(&99u32.to_be_bytes())).is_some());
        assert!(mc.get(&MessageId::new(&1u32.to_be_bytes())).is_none());
        // Evicted messages are no longer advertised.
        let advertised = mc.get_gossip_message_ids(&topic);
        assert_eq!(advertised.len(), stats.messages - 1);

        // Unvalidated messages go only when nothing else is left.
        let mut mc = MessageCache::new(3, 5, budget);
        for i in 0..20 {
            let (id, m) = sized_message(i, 1000, topic.clone());
            mc.put(&id, m);
            assert!(mc.stats().bytes <= budget);
        }
        assert!(mc.stats().evicted_unvalidated > 0);
    }

    #[test]
    /// QUILIBRIUM: under the budget the cache behaves as before, and removals and history
    /// shifts release their bytes.
    fn test_byte_accounting_follows_removal_and_shift() {
        let topic = Topic::new("t").hash();
        let mut mc = MessageCache::new(1, 2, 1 << 20);
        let (a, m) = sized_message(1, 100, topic.clone());
        let size = cached_bytes(&a, &m);
        assert!(mc.put(&a, m.clone()));
        assert!(
            !mc.put(&a, m),
            "a duplicate is not cached or accounted twice"
        );
        assert_eq!(mc.stats().bytes, size);
        let (b, m) = sized_message(2, 200, topic.clone());
        mc.put(&b, m);
        assert!(mc.remove(&a).is_some());
        assert_eq!(mc.stats().bytes, cached_bytes(&b, mc.get(&b).unwrap()));
        mc.shift();
        mc.shift();
        assert_eq!(mc.stats().bytes, 0);
        assert_eq!(mc.stats().messages, 0);
        assert_eq!(mc.stats().evicted_messages, 0);

        // A message larger than the whole budget is still cached, alone.
        let mut mc = MessageCache::new(1, 2, 1000);
        let (small, m) = sized_message(3, 10, topic.clone());
        mc.put(&small, m);
        let (big, m) = sized_message(4, 5000, topic);
        mc.put(&big, m);
        assert!(mc.get(&big).is_some());
        assert!(mc.get(&small).is_none());
        assert_eq!(mc.stats().messages, 1);
    }

    #[test]
    /// QUILIBRIUM: under pressure an evicted message is neither advertised (IHAVE) nor served
    /// (IWANT) and leaves no request counters behind, while the survivors stay available.
    fn test_iwant_and_ihave_under_byte_pressure() {
        let topic = Topic::new("t").hash();
        let peer = PeerId::random();
        let (id, m) = sized_message(0, 1000, topic.clone());
        let entry = cached_bytes(&id, &m);
        let mut mc = MessageCache::new(3, 5, 4 * entry);

        let ids: Vec<MessageId> = (0..4)
            .map(|i| {
                let (id, m) = sized_message(i, 1000, topic.clone());
                mc.put(&id, m);
                let _ = mc.validate(&id);
                assert!(mc.get_with_iwant_counts(&id, &peer).is_some());
                id
            })
            .collect();
        assert_eq!(mc.stats().evicted_messages, 0);
        assert_eq!(mc.get_gossip_message_ids(&topic).len(), 4);

        // One more message pushes the cache over its budget: the oldest go.
        let (newest, m) = sized_message(4, 1000, topic.clone());
        mc.put(&newest, m);
        let _ = mc.validate(&newest);
        assert!(mc.stats().evicted_messages > 0);
        assert!(mc.stats().bytes <= 4 * entry);
        assert!(
            mc.get_with_iwant_counts(&ids[0], &peer).is_none(),
            "evicted: IWANT fails"
        );
        assert!(!mc.iwant_counts.contains_key(&ids[0]));
        assert!(!mc.get_gossip_message_ids(&topic).contains(&ids[0]));
        assert!(mc.get_with_iwant_counts(&newest, &peer).is_some());
        assert!(mc.get_gossip_message_ids(&topic).contains(&newest));
        assert_eq!(mc.get_gossip_message_ids(&topic).len(), mc.stats().messages);

        // An unvalidated message is not served over IWANT, evicted or not.
        let (pending, m) = sized_message(5, 1000, topic);
        mc.put(&pending, m);
        assert!(mc.get_with_iwant_counts(&pending, &peer).is_none());
    }
}
