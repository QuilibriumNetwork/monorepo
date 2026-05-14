//! Per-rank message collector with deduplication and truncation.
//! Port of `node/consensus/global/message_collector.go`.
//!
//! Messages are buffered per consensus rank. The leader provider
//! drains the buffer for the current rank when producing a frame.
//! Messages older than the retention window are automatically pruned.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;

use sha3::{Digest, Sha3_256};

/// Maximum messages per frame (matches Go's maxGlobalMessagesPerFrame).
pub const MAX_MESSAGES_PER_FRAME: usize = 100;

/// Number of ranks to retain before pruning (matches Go's retention window).
const RETENTION_WINDOW: u64 = 10;

/// A collected message with its hash for deduplication.
#[derive(Clone)]
struct CollectedMessage {
    data: Vec<u8>,
    _hash: [u8; 32],
}

/// Outcome of adding a message to a [`RankBuffer`].
#[derive(Debug)]
enum AddOutcome {
    Added,
    Duplicate,
    Full,
}

/// Per-rank message buffer.
struct RankBuffer {
    messages: Vec<CollectedMessage>,
    seen: HashSet<[u8; 32]>,
}

impl RankBuffer {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            seen: HashSet::new(),
        }
    }

    /// Add a message if not already seen and there's capacity.
    fn add(&mut self, data: Vec<u8>) -> AddOutcome {
        let hash = sha256(&data);
        if self.seen.contains(&hash) {
            return AddOutcome::Duplicate;
        }
        if self.messages.len() >= MAX_MESSAGES_PER_FRAME {
            return AddOutcome::Full;
        }
        self.seen.insert(hash);
        self.messages.push(CollectedMessage { data, _hash: hash });
        AddOutcome::Added
    }

    /// Drain all messages, returning their raw bytes.
    fn drain(&mut self) -> Vec<Vec<u8>> {
        let msgs: Vec<Vec<u8>> = self.messages.drain(..).map(|m| m.data).collect();
        self.seen.clear();
        msgs
    }

    fn len(&self) -> usize {
        self.messages.len()
    }
}

/// Thread-safe message collector. The message receive loop (writer)
/// adds messages via `add_message`. The leader provider (reader)
/// drains messages via `collect_for_rank`.
pub struct MessageCollector {
    buffers: RwLock<HashMap<u64, RankBuffer>>,
    /// When true, only prover-protocol messages are accepted.
    prover_only_mode: std::sync::atomic::AtomicBool,
    /// Per-shard last-seen-frame deduplication. Mirrors Go's
    /// `shardFrameDedup` at `message_collector.go:255-269`. Different
    /// delivery paths (pubsub vs gRPC) can produce different
    /// serializations of the same shard frame; hash dedup misses
    /// those, but `(shard_address, frame_number)` catches them.
    shard_frame_dedup: RwLock<HashMap<Vec<u8>, u64>>,
    /// Spillover bundles per target rank. Mirrors Go's
    /// `globalMessageSpillover` (`message_collector.go:519-574`). When
    /// `add_message` would exceed `MAX_MESSAGES_PER_FRAME` for a rank,
    /// the bundle is appended to `spillover[rank]` instead of being
    /// dropped silently. On `collect_for_rank(rank)`, all spillover
    /// entries for ranks `<= rank` are drained and merged into the
    /// returned message list (Go flushes a single target rank when
    /// rank rolls forward; merging `<= rank` accomplishes the same
    /// end-to-end behavior since collect is what advances the rank).
    spillover: RwLock<HashMap<u64, VecDeque<Vec<u8>>>>,
}

impl MessageCollector {
    pub fn new() -> Self {
        Self {
            buffers: RwLock::new(HashMap::new()),
            prover_only_mode: std::sync::atomic::AtomicBool::new(false),
            shard_frame_dedup: RwLock::new(HashMap::new()),
            spillover: RwLock::new(HashMap::new()),
        }
    }

    /// Reject a bundle if any of its embedded shard frames is at or
    /// below the last-seen frame for that shard's address. Mirrors
    /// Go's per-shard dedup loop at `message_collector.go:250-271`.
    /// Returns `true` when the bundle is acceptable; `false` when at
    /// least one shard frame is stale → caller drops the whole bundle.
    ///
    /// `shard_frames` is the list of `(shard_address, frame_number)`
    /// pairs extracted from the bundle's requests by the caller (the
    /// extraction needs proto knowledge that lives one layer up).
    pub fn dedup_shard_frames(&self, shard_frames: &[(Vec<u8>, u64)]) -> bool {
        let mut map = self.shard_frame_dedup.write().unwrap();
        // First pass: check none are stale. Match Go's "drop whole
        // bundle on first stale frame" semantic.
        for (addr, frame) in shard_frames {
            if let Some(&last_seen) = map.get(addr) {
                if *frame <= last_seen {
                    return false;
                }
            }
        }
        // Second pass: commit the new high-water marks.
        for (addr, frame) in shard_frames {
            map.insert(addr.clone(), *frame);
        }
        true
    }

    /// Drop the per-shard high-water cache. Used in tests and on
    /// chain reorganization.
    pub fn clear_shard_frame_dedup(&self) {
        self.shard_frame_dedup.write().unwrap().clear();
    }

    /// Add a message for the given rank. Returns true if the message
    /// was accepted (not a duplicate, not truncated, not filtered).
    /// When the per-rank buffer is full, the message is appended to
    /// `spillover[rank]` instead of being dropped — matches Go's
    /// `deferGlobalMessage` semantic (`message_collector.go:519-543`).
    pub fn add_message(&self, rank: u64, data: Vec<u8>) -> bool {
        // Prover-only mode filtering: check if the message is a
        // prover-protocol op (type prefix 0x0301-0x031A). If not,
        // reject it during degraded coverage.
        if self.prover_only_mode.load(std::sync::atomic::Ordering::Relaxed) {
            if !is_prover_message(&data) {
                return false;
            }
        }

        let mut buffers = self.buffers.write().unwrap();
        let buffer = buffers.entry(rank).or_insert_with(RankBuffer::new);
        match buffer.add(data.clone()) {
            AddOutcome::Added => true,
            AddOutcome::Duplicate => false,
            AddOutcome::Full => {
                // Spill over instead of dropping — match Go's
                // deferGlobalMessage behavior.
                drop(buffers);
                let mut spill = self.spillover.write().unwrap();
                spill
                    .entry(rank)
                    .or_insert_with(VecDeque::new)
                    .push_back(data);
                true
            }
        }
    }

    /// Drain all messages for the given rank. Returns up to
    /// `MAX_MESSAGES_PER_FRAME` messages, removing them from the buffer.
    /// Also prunes ranks older than the retention window. Drains any
    /// spillover entries for ranks `<= rank` and merges them in —
    /// matches Go's `flushDeferredGlobalMessages` rolling forward as
    /// rank advances (`event_distributor.go:61`).
    ///
    /// Buffers at ranks `< rank` are also drained: receivers tag
    /// inbound messages with their local "current rank" (e.g. last
    /// finalized frame), but on archives that never receive their own
    /// broadcasts the local rank lags behind the consensus rank the
    /// leader uses to collect. Draining `<= rank` matches Go's
    /// behavior where producer and consumer share a single rank view.
    /// The `MAX_MESSAGES_PER_FRAME` cap is applied to the merged set.
    pub fn collect_for_rank(&self, rank: u64) -> Vec<Vec<u8>> {
        let mut buffers = self.buffers.write().unwrap();

        // Drain messages for all ranks <= rank, in ascending rank order
        // so older messages land first (FIFO across ranks).
        let mut ranks_to_drain: Vec<u64> = buffers
            .keys()
            .copied()
            .filter(|r| *r <= rank)
            .collect();
        ranks_to_drain.sort();
        let mut messages: Vec<Vec<u8>> = Vec::new();
        for r in &ranks_to_drain {
            if let Some(buf) = buffers.get_mut(r) {
                messages.extend(buf.drain());
            }
        }

        // Prune old ranks
        if rank > RETENTION_WINDOW {
            let cutoff = rank - RETENTION_WINDOW;
            buffers.retain(|&r, _| r >= cutoff);
        }
        drop(buffers);

        // Drain spillover for ranks <= rank.
        let mut spill = self.spillover.write().unwrap();
        let to_flush: Vec<u64> = spill.keys().copied().filter(|r| *r <= rank).collect();
        for r in to_flush {
            if let Some(mut q) = spill.remove(&r) {
                while let Some(payload) = q.pop_front() {
                    messages.push(payload);
                }
            }
        }

        if messages.len() > MAX_MESSAGES_PER_FRAME {
            messages.truncate(MAX_MESSAGES_PER_FRAME);
        }

        messages
    }

    /// Number of pending spillover bundles for a given rank. For tests
    /// and diagnostics.
    pub fn spillover_count(&self, rank: u64) -> usize {
        self.spillover
            .read()
            .unwrap()
            .get(&rank)
            .map(|q| q.len())
            .unwrap_or(0)
    }

    /// Number of pending messages for a given rank.
    pub fn pending_count(&self, rank: u64) -> usize {
        self.buffers.read().unwrap()
            .get(&rank)
            .map(|b| b.len())
            .unwrap_or(0)
    }

    /// Total messages across all ranks.
    pub fn total_pending(&self) -> usize {
        self.buffers.read().unwrap()
            .values()
            .map(|b| b.len())
            .sum()
    }

    /// Set prover-only mode. When enabled, non-prover messages are
    /// rejected. Used during degraded coverage.
    pub fn set_prover_only_mode(&self, enabled: bool) {
        self.prover_only_mode
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_prover_only_mode(&self) -> bool {
        self.prover_only_mode
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// SHA3-256 digest of `data`. Mirrors Go's
/// `node/consensus/global/message_collector.go:37` (`sha3.Sum256`).
fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = Sha3_256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Check if a message is a prover-protocol message. Messages added
/// to the collector are raw bundle bytes — the outer type prefix
/// determines if it's a prover message. MessageBundle (0x0312) and
/// MessageRequest (0x0311) always pass since they wrap inner ops.
/// Direct prover ops (0x0301–0x031A) also pass.
fn is_prover_message(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let tp = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    // MessageBundle / MessageRequest wrappers — always allowed
    // (they contain prover ops inside; filtering happens at the
    // individual op level during processing, not collection).
    if tp == 0x0312 || tp == 0x0311 {
        return true;
    }
    // Direct prover ops: 0x0301–0x031A
    (0x0301..=0x031A).contains(&tp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_collect() {
        let mc = MessageCollector::new();
        assert!(mc.add_message(1, b"msg-a".to_vec()));
        assert!(mc.add_message(1, b"msg-b".to_vec()));
        assert_eq!(mc.pending_count(1), 2);

        let msgs = mc.collect_for_rank(1);
        assert_eq!(msgs.len(), 2);
        assert_eq!(mc.pending_count(1), 0);
    }

    #[test]
    fn deduplication() {
        let mc = MessageCollector::new();
        assert!(mc.add_message(1, b"same".to_vec()));
        assert!(!mc.add_message(1, b"same".to_vec()));
        assert_eq!(mc.pending_count(1), 1);
    }

    #[test]
    fn truncation_at_max() {
        let mc = MessageCollector::new();
        for i in 0..MAX_MESSAGES_PER_FRAME + 10 {
            mc.add_message(1, format!("msg-{}", i).into_bytes());
        }
        // Live buffer is capped at MAX_MESSAGES_PER_FRAME; the rest
        // overflow into spillover (no longer dropped silently).
        assert_eq!(mc.pending_count(1), MAX_MESSAGES_PER_FRAME);
        assert_eq!(mc.spillover_count(1), 10);
    }

    #[test]
    fn spillover_buffers_overflow() {
        // Past the per-rank cap, additional messages spill over instead
        // of being silently dropped. add_message should still return
        // true for accepted-into-spillover bundles.
        let mc = MessageCollector::new();
        for i in 0..MAX_MESSAGES_PER_FRAME {
            assert!(mc.add_message(1, format!("a-{}", i).into_bytes()));
        }
        // Next 5 messages overflow into spillover.
        for i in 0..5 {
            assert!(mc.add_message(1, format!("b-{}", i).into_bytes()));
        }
        assert_eq!(mc.pending_count(1), MAX_MESSAGES_PER_FRAME);
        assert_eq!(mc.spillover_count(1), 5);
    }

    #[test]
    fn spillover_drains_on_collect() {
        // `collect_for_rank(rank)` drains every live buffer and every
        // spillover bucket for ranks `<= rank`, then caps the merged
        // result at `MAX_MESSAGES_PER_FRAME` (proposals can't carry
        // more than the per-frame cap regardless of how much was
        // queued).
        let mc = MessageCollector::new();
        // Fill rank 0 to capacity + spill 2.
        for i in 0..MAX_MESSAGES_PER_FRAME + 2 {
            mc.add_message(0, format!("r0-{}", i).into_bytes());
        }
        assert_eq!(mc.spillover_count(0), 2);
        // Fill rank 1 to capacity + spill 3.
        for i in 0..MAX_MESSAGES_PER_FRAME + 3 {
            mc.add_message(1, format!("r1-{}", i).into_bytes());
        }
        assert_eq!(mc.spillover_count(1), 3);

        // Total queued = 2 * MAX + 5 = 205. After collect, the merged
        // set is truncated to MAX_MESSAGES_PER_FRAME.
        let msgs = mc.collect_for_rank(1);
        assert_eq!(msgs.len(), MAX_MESSAGES_PER_FRAME);
        // Both spillover buckets drain on collect.
        assert_eq!(mc.spillover_count(0), 0);
        assert_eq!(mc.spillover_count(1), 0);
        // Live buffers also drain (single rank-view: producer & consumer share).
        assert_eq!(mc.pending_count(0), 0);
        assert_eq!(mc.pending_count(1), 0);
    }

    #[test]
    fn per_rank_isolation() {
        let mc = MessageCollector::new();
        mc.add_message(1, b"rank-1".to_vec());
        mc.add_message(2, b"rank-2".to_vec());
        assert_eq!(mc.pending_count(1), 1);
        assert_eq!(mc.pending_count(2), 1);
        assert_eq!(mc.total_pending(), 2);
    }

    #[test]
    fn collect_prunes_old_ranks() {
        let mc = MessageCollector::new();
        mc.add_message(1, b"old".to_vec());
        mc.add_message(15, b"recent".to_vec());
        mc.add_message(20, b"new".to_vec());

        let msgs = mc.collect_for_rank(20);
        // Producer and consumer share a single rank view: collect_for_rank
        // drains EVERY live rank `<= rank`, not just the target rank.
        // All three ranks (1, 15, 20) drain.
        assert_eq!(msgs.len(), 3);
        // Retention prune: rank 1 < 20 - RETENTION_WINDOW(10) → bucket dropped.
        assert_eq!(mc.pending_count(1), 0);
        // Rank 15 stays inside the retention window but is now empty.
        assert_eq!(mc.pending_count(15), 0);
        assert_eq!(mc.total_pending(), 0);
    }

    #[test]
    fn prover_only_mode() {
        let mc = MessageCollector::new();
        mc.set_prover_only_mode(true);

        // Non-prover message rejected
        assert!(!mc.add_message(1, b"random-data-here".to_vec()));

        // Prover message accepted (0x00000312 = MessageBundle type prefix)
        let mut bundle = 0x0312u32.to_be_bytes().to_vec();
        bundle.extend_from_slice(b"payload");
        assert!(mc.add_message(1, bundle));

        // Direct prover op (0x00000301 = ProverJoin type prefix)
        let mut join = 0x0301u32.to_be_bytes().to_vec();
        join.extend_from_slice(b"join-data");
        assert!(mc.add_message(1, join));

        assert_eq!(mc.pending_count(1), 2);
    }

    #[test]
    fn collect_empty_rank() {
        let mc = MessageCollector::new();
        assert!(mc.collect_for_rank(999).is_empty());
    }

    #[test]
    fn dedup_shard_frames_first_seen_accepted() {
        let mc = MessageCollector::new();
        let shards = vec![(vec![0xAAu8; 32], 100u64)];
        assert!(mc.dedup_shard_frames(&shards));
    }

    #[test]
    fn dedup_shard_frames_higher_frame_accepted() {
        let mc = MessageCollector::new();
        assert!(mc.dedup_shard_frames(&vec![(vec![0xAAu8; 32], 100)]));
        assert!(mc.dedup_shard_frames(&vec![(vec![0xAAu8; 32], 101)]));
    }

    #[test]
    fn dedup_shard_frames_same_or_lower_frame_rejected() {
        let mc = MessageCollector::new();
        assert!(mc.dedup_shard_frames(&vec![(vec![0xAAu8; 32], 100)]));
        // Same frame → reject.
        assert!(!mc.dedup_shard_frames(&vec![(vec![0xAAu8; 32], 100)]));
        // Lower frame → reject.
        assert!(!mc.dedup_shard_frames(&vec![(vec![0xAAu8; 32], 99)]));
    }

    #[test]
    fn dedup_shard_frames_per_shard_independent() {
        let mc = MessageCollector::new();
        assert!(mc.dedup_shard_frames(&vec![(vec![0xAAu8; 32], 100)]));
        // Different shard, same frame number — accepted.
        assert!(mc.dedup_shard_frames(&vec![(vec![0xBBu8; 32], 100)]));
    }

    #[test]
    fn dedup_shard_frames_bundle_atomic() {
        // Bundle with two shards: one fresh, one stale → entire
        // bundle rejected and the fresh frame's high-water mark is
        // NOT advanced.
        let mc = MessageCollector::new();
        assert!(mc.dedup_shard_frames(&vec![(vec![0xAAu8; 32], 100)]));
        let bundle = vec![
            (vec![0xBBu8; 32], 50),     // fresh
            (vec![0xAAu8; 32], 100),    // stale
        ];
        assert!(!mc.dedup_shard_frames(&bundle));
        // 0xBB should still be acceptable on its own.
        assert!(mc.dedup_shard_frames(&vec![(vec![0xBBu8; 32], 50)]));
    }

    #[test]
    fn clear_shard_frame_dedup_resets() {
        let mc = MessageCollector::new();
        assert!(mc.dedup_shard_frames(&vec![(vec![0xAAu8; 32], 100)]));
        mc.clear_shard_frame_dedup();
        // Same frame number now accepted because cache is empty.
        assert!(mc.dedup_shard_frames(&vec![(vec![0xAAu8; 32], 100)]));
    }
}
