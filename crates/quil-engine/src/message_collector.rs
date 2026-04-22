//! Per-rank message collector with deduplication and truncation.
//! Port of `node/consensus/global/message_collector.go`.
//!
//! Messages are buffered per consensus rank. The leader provider
//! drains the buffer for the current rank when producing a frame.
//! Messages older than the retention window are automatically pruned.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use sha2::{Digest, Sha256};

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

    /// Add a message if not already seen. Returns true if added.
    fn add(&mut self, data: Vec<u8>) -> bool {
        let hash = sha256(&data);
        if self.seen.contains(&hash) {
            return false;
        }
        if self.messages.len() >= MAX_MESSAGES_PER_FRAME {
            return false; // truncated
        }
        self.seen.insert(hash);
        self.messages.push(CollectedMessage { data, _hash: hash });
        true
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
}

impl MessageCollector {
    pub fn new() -> Self {
        Self {
            buffers: RwLock::new(HashMap::new()),
            prover_only_mode: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Add a message for the given rank. Returns true if the message
    /// was accepted (not a duplicate, not truncated, not filtered).
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
        buffer.add(data)
    }

    /// Drain all messages for the given rank. Returns up to
    /// `MAX_MESSAGES_PER_FRAME` messages, removing them from the buffer.
    /// Also prunes ranks older than the retention window.
    pub fn collect_for_rank(&self, rank: u64) -> Vec<Vec<u8>> {
        let mut buffers = self.buffers.write().unwrap();

        // Drain messages for this rank
        let messages = buffers
            .get_mut(&rank)
            .map(|b| b.drain())
            .unwrap_or_default();

        // Prune old ranks
        if rank > RETENTION_WINDOW {
            let cutoff = rank - RETENTION_WINDOW;
            buffers.retain(|&r, _| r >= cutoff);
        }

        messages
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

fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
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
        assert_eq!(mc.pending_count(1), MAX_MESSAGES_PER_FRAME);
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

        mc.collect_for_rank(20);
        // Rank 1 should be pruned (20 - 10 = 10, 1 < 10)
        assert_eq!(mc.pending_count(1), 0);
        // Rank 15 is within window (15 >= 10), still has its message
        assert_eq!(mc.pending_count(15), 1);
        // Total: rank 15's message (rank 20 was drained by collect)
        assert_eq!(mc.total_pending(), 1);
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
}
