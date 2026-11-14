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

use crate::topic::TopicHash;
use crate::types::{MessageId, RawMessage};
use libp2p_identity::PeerId;
use std::collections::hash_map::Entry;
use std::fmt::Debug;
use std::{
    collections::{HashMap, HashSet},
    fmt,
};

/// CacheEntry stored in the history.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheEntry {
    mid: MessageId,
    topic: TopicHash,
}

/// Approximate retained-heap cost of one cached message: the dominant
/// allocations are the payload, the message-id key, and the topic bytes.
fn entry_bytes(mid: &MessageId, msg: &RawMessage) -> usize {
    mid.0.len() + msg.data.len() + msg.topic.as_bytes().len()
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
    /// Hard cap on total cached payload bytes. When exceeded, the OLDEST
    /// history windows are drained early (before they age out via `shift`)
    /// so a catch-up flood of large subscribed messages can't drive OOM.
    /// Window-count history alone does not bound bytes. `0` disables the
    /// budget (count-based history only).
    max_bytes: usize,
    /// Running total of `entry_bytes` over every cached message.
    cur_bytes: usize,
}

impl fmt::Debug for MessageCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageCache")
            .field("msgs", &self.msgs)
            .field("history", &self.history)
            .field("gossip", &self.gossip)
            .field("bytes", &self.cur_bytes)
            .finish()
    }
}

/// Implementation of the MessageCache.
impl MessageCache {
    /// NOTE: fork arg order is `(gossip, history_capacity, max_bytes)` — this is
    /// TRANSPOSED relative to quil-p2p's `(history_length, history_gossip, ...)`.
    /// Do NOT "fix" the call site to the reference order: passing `gossip=24`
    /// over a 16-window `history` Vec would make `history[..gossip]` panic.
    pub(crate) fn new(gossip: usize, history_capacity: usize, max_bytes: usize) -> Self {
        MessageCache {
            gossip,
            msgs: HashMap::default(),
            iwant_counts: HashMap::default(),
            history: vec![Vec::new(); history_capacity],
            max_bytes,
            cur_bytes: 0,
        }
    }

    /// Total cached payload bytes (for diagnostics / OOM gauges).
    #[cfg(test)]
    pub(crate) fn byte_len(&self) -> usize {
        self.cur_bytes
    }

    /// Drain whole history windows from the OLDEST end (the back — newest is
    /// `history[0]`) until under the byte budget, never touching the current
    /// window (`history[0]`) we are still writing into, so gossip recovery of
    /// the most-recent messages still works. Mirrors the quil-p2p reference
    /// `MessageCache::evict_to_budget`.
    fn evict_to_budget(&mut self) {
        if self.max_bytes == 0 {
            return;
        }
        let mut idx = self.history.len();
        let mut evicted_gossip_window = false;
        while self.cur_bytes > self.max_bytes && idx > 1 {
            idx -= 1;
            // Windows `[0, gossip)` are still advertised via IHAVE. Evicting one
            // means IWANT recovery of those messages will now fail — inherent to
            // a byte budget under a large-payload flood (present in the
            // reference too), but operators need field signal for it.
            if idx < self.gossip {
                evicted_gossip_window = true;
            }
            for entry in std::mem::take(&mut self.history[idx]) {
                if let Some((msg, _)) = self.msgs.remove(&entry.mid) {
                    self.cur_bytes = self.cur_bytes.saturating_sub(entry_bytes(&entry.mid, &msg));
                }
                self.iwant_counts.remove(&entry.mid);
            }
        }
        if evicted_gossip_window {
            // Once per call (not per window) to avoid a warn storm under sustained
            // pressure.
            tracing::warn!(
                gossip_window = self.gossip,
                cur_bytes = self.cur_bytes,
                max_bytes = self.max_bytes,
                "mcache byte budget evicted a window inside the gossip window — \
                 IWANT recovery of those messages will fail; raise mcache_max_bytes"
            );
        }
    }

    /// Put a message into the memory cache.
    ///
    /// Returns true if the message didn't already exist in the cache.
    pub(crate) fn put(&mut self, message_id: &MessageId, msg: RawMessage) -> bool {
        match self.msgs.entry(message_id.clone()) {
            Entry::Occupied(_) => {
                // Don't add duplicate entries to the cache.
                false
            }
            Entry::Vacant(entry) => {
                let cache_entry = CacheEntry {
                    mid: message_id.clone(),
                    topic: msg.topic.clone(),
                };
                self.cur_bytes += entry_bytes(message_id, &msg);
                entry.insert((msg, HashSet::default()));
                self.history[0].push(cache_entry);

                tracing::trace!(message=?message_id, "Put message in mcache");
                // Bound total cached bytes: a catch-up flood of large messages
                // can pile up far faster than `shift` ages windows out.
                self.evict_to_budget();
                true
            }
        }
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
        for entry in self.history.pop().expect("history is always > 1") {
            if let Some((msg, _)) = self.msgs.remove(&entry.mid) {
                self.cur_bytes = self.cur_bytes.saturating_sub(entry_bytes(&entry.mid, &msg));
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
        //We only remove the message from msgs and iwant_count and keep the message_id in the
        // history vector. Zhe id in the history vector will simply be ignored on popping.

        self.iwant_counts.remove(message_id);
        let removed = self.msgs.remove(message_id);
        if let Some((msg, _)) = &removed {
            self.cur_bytes = self.cur_bytes.saturating_sub(entry_bytes(message_id, msg));
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
        // 0 disables the byte budget → count-based history only (upstream
        // behaviour), so the pre-existing history/shift tests are unaffected.
        MessageCache::new(gossip_size, history, 0)
    }

    fn gen_testm_data(x: u64, topic: TopicHash, data: Vec<u8>) -> (MessageId, RawMessage) {
        let m = RawMessage {
            source: Some(PeerId::random()),
            data,
            sequence_number: Some(x),
            topic,
            signature: None,
            key: None,
            validated: true,
        };
        let id = MessageId::from(x.to_le_bytes().to_vec());
        (id, m)
    }

    #[test]
    /// REGRESSION (OOM): a catch-up flood of large subscribed messages piled
    /// the mcache up to 14+ GB because window-count history alone does not
    /// bound bytes. With a byte budget, the OLDEST windows are drained early
    /// so total cached bytes stays bounded, while the most-recent window
    /// (`history[0]`) survives so gossip recovery of recent messages works.
    fn byte_budget_evicts_oldest_windows_and_bounds_bytes() {
        let topic = Topic::new("t").hash();
        // 10 windows of history, but only a 4 KiB byte ceiling.
        let mut mc = MessageCache::new(3, 10, 4096);
        // Put 40 × 1 KiB messages across several windows (shift between
        // batches so they land in distinct windows).
        for batch in 0..8u64 {
            for i in 0..5u64 {
                let (id, m) = gen_testm_data(batch * 5 + i, topic.clone(), vec![0u8; 1024]);
                mc.put(&id, m);
            }
            mc.shift();
        }
        // Byte total must stay bounded by the budget (+ at most one window
        // that pushed us over before eviction).
        assert!(
            mc.byte_len() <= 4096 + 5 * (1024 + topic.as_bytes().len() + 8),
            "cached bytes must stay near the budget, got {}",
            mc.byte_len()
        );
        // The most-recent window's messages must still be present (gossip
        // recovery of recent messages must keep working).
        let (recent_id, recent_m) = gen_testm_data(999, topic.clone(), vec![0u8; 1024]);
        mc.put(&recent_id, recent_m);
        assert!(
            mc.get(&recent_id).is_some(),
            "the most-recent message must survive byte-budget eviction"
        );
    }

    #[test]
    /// Byte accounting round-trips: put then remove leaves cur_bytes at 0.
    fn byte_accounting_is_exact_across_put_and_remove() {
        let topic = Topic::new("t").hash();
        let mut mc = MessageCache::new(3, 5, 1 << 30);
        let mut ids = Vec::new();
        for i in 0..10u64 {
            let (id, m) = gen_testm_data(i, topic.clone(), vec![0u8; 500]);
            mc.put(&id, m);
            ids.push(id);
        }
        assert!(mc.byte_len() > 0);
        for id in &ids {
            mc.remove(id);
        }
        assert_eq!(mc.byte_len(), 0, "removing all messages must zero the byte total");
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
}
