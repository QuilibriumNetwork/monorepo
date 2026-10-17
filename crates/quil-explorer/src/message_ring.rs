//! Bounded ring of recently-observed pubsub messages, backing the
//! `GET /messages` endpoint.
//!
//! The Go explorer keeps the last 256 gossip messages in memory (newest
//! first), stamping each with the wall-clock time it was observed. We
//! mirror that exactly. The ring is only fed (from the master node's
//! inbound pubsub path) when the explorer is enabled, so it costs nothing
//! when the service is off.

use std::collections::VecDeque;

use parking_lot::RwLock;
use quil_types::p2p::PubSubMessage;

/// Default capacity, matching the Go explorer's `newMessageStore(256)`.
pub const DEFAULT_CAPACITY: usize = 256;

/// A single observed message plus the time we saw it.
#[derive(Debug, Clone)]
pub struct RecentMessage {
    /// Observation time, RFC3339 (matches Go's `time.Now().UTC()` JSON).
    pub timestamp: String,
    pub from: Vec<u8>,
    pub bitmask: Vec<u8>,
    pub seqno: Vec<u8>,
    pub signature: Vec<u8>,
    pub key: Vec<u8>,
    pub data: Vec<u8>,
}

/// Newest-first bounded ring of recent messages.
#[derive(Debug)]
pub struct RecentMessageRing {
    capacity: usize,
    inner: RwLock<VecDeque<RecentMessage>>,
}

impl RecentMessageRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: RwLock::new(VecDeque::with_capacity(capacity.max(1))),
        }
    }

    /// Record a message at the front (newest), dropping the oldest if full.
    /// Mirrors Go `messageStore.Add`: insert at index 0, drop the tail.
    pub fn push(&self, msg: &PubSubMessage) {
        self.record(RecentMessage {
            timestamp: now_rfc3339(),
            from: msg.from.clone(),
            bitmask: msg.bitmask.clone(),
            seqno: msg.seqno.clone(),
            signature: msg.signature.clone(),
            key: msg.key.clone(),
            data: msg.data.clone(),
        });
    }

    /// Record a message from only the fields the node's inbound pubsub
    /// path carries (`ReceivedMessage` has `from`/`bitmask`/`data` but not
    /// `seqno`/`signature`/`key` — those aren't plumbed to this layer, so
    /// they are recorded empty).
    pub fn push_received(&self, from: &[u8], bitmask: &[u8], data: &[u8]) {
        self.record(RecentMessage {
            timestamp: now_rfc3339(),
            from: from.to_vec(),
            bitmask: bitmask.to_vec(),
            seqno: Vec::new(),
            signature: Vec::new(),
            key: Vec::new(),
            data: data.to_vec(),
        });
    }

    fn record(&self, record: RecentMessage) {
        let mut q = self.inner.write();
        if q.len() == self.capacity {
            q.pop_back();
        }
        q.push_front(record);
    }

    /// Snapshot up to `limit` newest records (Go `messageStore.Snapshot`).
    /// `limit <= 0` or `limit > len` returns all.
    pub fn snapshot(&self, limit: usize) -> Vec<RecentMessage> {
        let q = self.inner.read();
        let n = if limit == 0 || limit > q.len() { q.len() } else { limit };
        q.iter().take(n).cloned().collect()
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(tag: u8) -> PubSubMessage {
        PubSubMessage {
            from: vec![tag],
            data: vec![tag, tag],
            bitmask: vec![0xBB],
            seqno: vec![tag, 0, 0],
            signature: vec![0x51, 0x47],
            key: vec![0x4B],
        }
    }

    #[test]
    fn newest_first_and_bounded() {
        let ring = RecentMessageRing::new(3);
        for i in 0..5u8 {
            ring.push(&msg(i));
        }
        let snap = ring.snapshot(0);
        assert_eq!(snap.len(), 3); // bounded to capacity
        // Newest first: last pushed (4) is at front.
        assert_eq!(snap[0].from, vec![4]);
        assert_eq!(snap[1].from, vec![3]);
        assert_eq!(snap[2].from, vec![2]);
    }

    #[test]
    fn snapshot_respects_limit() {
        let ring = RecentMessageRing::new(10);
        for i in 0..5u8 {
            ring.push(&msg(i));
        }
        assert_eq!(ring.snapshot(2).len(), 2);
        assert_eq!(ring.snapshot(0).len(), 5);
        assert_eq!(ring.snapshot(100).len(), 5);
        // RFC3339 with Z suffix.
        assert!(ring.snapshot(1)[0].timestamp.ends_with('Z'));
    }
}
