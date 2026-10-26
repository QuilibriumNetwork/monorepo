//! Bounded ring of recently-observed pubsub messages, backing the
//! `GET /messages` endpoint.
//!
//! The Go explorer keeps the last 256 gossip messages in memory (newest
//! first), stamping each with the wall-clock time it was observed. We
//! mirror that exactly. The ring is only fed (from the master node's
//! inbound pubsub path) when the explorer is enabled, so it costs nothing
//! when the service is off.
//!
//! Recording is on the node's message hot path, so a record holds its
//! fields as shared [`Bytes`] (a snapshot clones reference counts, not
//! the ~126 KB average payloads) and the observation time as a
//! [`SystemTime`]; the RFC3339 text is formatted only when serialized.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use axum::body::Bytes;
use parking_lot::{Mutex, RwLock};
use quil_types::p2p::PubSubMessage;

/// Default capacity, matching the Go explorer's `newMessageStore(256)`.
pub const DEFAULT_CAPACITY: usize = 256;

/// A single observed message plus the time we saw it.
#[derive(Debug, Clone)]
pub struct RecentMessage {
    /// Observation time (UTC wall clock).
    pub time: SystemTime,
    pub from: Bytes,
    pub bitmask: Bytes,
    pub seqno: Bytes,
    pub signature: Bytes,
    pub key: Bytes,
    pub data: Bytes,
}

impl RecentMessage {
    /// Observation time, RFC3339 (matches Go's `time.Now().UTC()` JSON).
    pub fn timestamp(&self) -> String {
        chrono::DateTime::<chrono::Utc>::from(self.time)
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
    }
}

/// The last serialized `/messages` body and what it was built from.
#[derive(Debug)]
struct CachedBody {
    version: u64,
    limit: usize,
    built: Instant,
    body: Bytes,
}

/// Newest-first bounded ring of recent messages.
#[derive(Debug)]
pub struct RecentMessageRing {
    capacity: usize,
    inner: RwLock<VecDeque<RecentMessage>>,
    /// Count of records ever recorded; bumped under the `inner` write lock.
    version: AtomicU64,
    /// One serialized body (see [`Self::cached_body`]).
    cache: Mutex<Option<CachedBody>>,
}

impl RecentMessageRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: RwLock::new(VecDeque::with_capacity(capacity.max(1))),
            version: AtomicU64::new(0),
            cache: Mutex::new(None),
        }
    }

    /// Record a message at the front (newest), dropping the oldest if full.
    /// Mirrors Go `messageStore.Add`: insert at index 0, drop the tail.
    pub fn push(&self, msg: &PubSubMessage) {
        self.record(RecentMessage {
            time: SystemTime::now(),
            from: Bytes::copy_from_slice(&msg.from),
            bitmask: Bytes::copy_from_slice(&msg.bitmask),
            seqno: Bytes::copy_from_slice(&msg.seqno),
            signature: Bytes::copy_from_slice(&msg.signature),
            key: Bytes::copy_from_slice(&msg.key),
            data: Bytes::copy_from_slice(&msg.data),
        });
    }

    /// Record a message from only the fields the node's inbound pubsub
    /// path carries (`ReceivedMessage` has `from`/`bitmask`/`data` but not
    /// `seqno`/`signature`/`key` — those aren't plumbed to this layer, so
    /// they are recorded empty). Copies each field once; no formatting.
    pub fn push_received(&self, from: &[u8], bitmask: &[u8], data: &[u8]) {
        self.record(RecentMessage {
            time: SystemTime::now(),
            from: Bytes::copy_from_slice(from),
            bitmask: Bytes::copy_from_slice(bitmask),
            seqno: Bytes::new(),
            signature: Bytes::new(),
            key: Bytes::new(),
            data: Bytes::copy_from_slice(data),
        });
    }

    pub(crate) fn record(&self, record: RecentMessage) {
        let mut q = self.inner.write();
        if q.len() == self.capacity {
            q.pop_back();
        }
        q.push_front(record);
        self.version.fetch_add(1, Ordering::Release);
    }

    /// Snapshot up to `limit` newest records (Go `messageStore.Snapshot`).
    /// `limit <= 0` or `limit > len` returns all. Clones reference counts,
    /// not payloads.
    pub fn snapshot(&self, limit: usize) -> Vec<RecentMessage> {
        self.snapshot_versioned(limit).1
    }

    /// [`Self::snapshot`] with the version it was taken at.
    fn snapshot_versioned(&self, limit: usize) -> (u64, Vec<RecentMessage>) {
        let q = self.inner.read();
        let version = self.version.load(Ordering::Acquire);
        let n = if limit == 0 || limit > q.len() {
            q.len()
        } else {
            limit
        };
        (version, q.iter().take(n).cloned().collect())
    }

    /// The serialized body for `limit`, from `render` over the newest
    /// records. The last body is reused while the ring has not changed
    /// since it was built (same version) and `limit` matches. Under steady
    /// gossip the version moves constantly, so a body younger than
    /// `max_age` is reused as well: a response may trail the ring by up to
    /// `max_age` (bounded staleness). One body is held; a request for
    /// another limit replaces it. Concurrent requests wait on the one
    /// build instead of repeating it.
    pub fn cached_body(
        &self,
        limit: usize,
        now: Instant,
        max_age: Duration,
        render: impl FnOnce(&[RecentMessage]) -> Bytes,
    ) -> Bytes {
        let mut cache = self.cache.lock();
        if let Some(c) = cache.as_ref() {
            let fresh = now.saturating_duration_since(c.built) < max_age;
            if c.limit == limit && (fresh || c.version == self.version.load(Ordering::Acquire)) {
                return c.body.clone();
            }
        }
        let (version, records) = self.snapshot_versioned(limit);
        let body = render(&records);
        *cache = Some(CachedBody {
            version,
            limit,
            built: now,
            body: body.clone(),
        });
        body
    }
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
        assert_eq!(snap[0].from.as_ref(), [4]);
        assert_eq!(snap[1].from.as_ref(), [3]);
        assert_eq!(snap[2].from.as_ref(), [2]);
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
        assert!(ring.snapshot(1)[0].timestamp().ends_with('Z'));
    }

    #[test]
    fn snapshots_share_payload_memory() {
        let ring = RecentMessageRing::new(4);
        ring.push_received(&[1], &[2], &[7u8; 4096]);
        let (a, b) = (ring.snapshot(1), ring.snapshot(1));
        assert_eq!(a[0].data.as_ptr(), b[0].data.as_ptr());
        assert_eq!(a[0].data.len(), 4096);
        assert!(a[0].seqno.is_empty() && a[0].signature.is_empty() && a[0].key.is_empty());
    }

    #[test]
    fn timestamp_format_is_nanosecond_rfc3339_utc() {
        let mut r = ring_record();
        r.time = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
        assert_eq!(r.timestamp(), "2023-11-14T22:13:20.123456789Z");
        // A whole second keeps all nine digits, as `now_rfc3339` did.
        r.time = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 0);
        assert_eq!(r.timestamp(), "2023-11-14T22:13:20.000000000Z");
    }

    fn ring_record() -> RecentMessage {
        let ring = RecentMessageRing::new(1);
        ring.push(&msg(1));
        ring.snapshot(1).remove(0)
    }

    #[test]
    fn cached_body_reused_until_version_and_age_allow_rebuild() {
        let ring = RecentMessageRing::new(8);
        ring.push(&msg(1));
        let t0 = Instant::now();
        let age = Duration::from_secs(1);
        let builds = std::cell::Cell::new(0);
        let get = |limit: usize, at: Instant| {
            ring.cached_body(limit, at, age, |recs| {
                builds.set(builds.get() + 1);
                Bytes::from(recs.len().to_string())
            })
        };
        let first = get(5, t0);
        // Unchanged ring: reused even long after the window.
        let again = get(5, t0 + Duration::from_secs(60));
        assert_eq!(first.as_ptr(), again.as_ptr());
        assert_eq!(builds.get(), 1);
        // Another limit rebuilds.
        get(6, t0);
        get(5, t0);
        assert_eq!(builds.get(), 3);
        // A push inside the window serves the stale body; after it, a new one.
        ring.push(&msg(2));
        assert_eq!(get(5, t0 + Duration::from_millis(500)).as_ref(), b"1");
        assert_eq!(builds.get(), 3);
        assert_eq!(get(5, t0 + Duration::from_millis(1500)).as_ref(), b"2");
        assert_eq!(builds.get(), 4);
    }
}
