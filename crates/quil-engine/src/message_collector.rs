//! Per-rank message collector with deduplication and truncation.
//! Port of `node/consensus/global/message_collector.go`.
//!
//! Messages are buffered per consensus rank. The leader provider
//! drains the buffer for the current rank when producing a frame.
//! Messages older than the retention window are automatically pruned.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;

use sha3::{Digest, Sha3_256};

// NOTE: global consensus has NO per-frame request cap. The original
// 100-message cap existed because a global proposal was gossiped and
// BlossomSub has a ~1 MiB message-size ceiling; global consensus now
// uses the direct point-to-point :8340 transport (see
// `direct_global_consensus_publisher`), which has no such ceiling, so
// the global frame carries every pending request (e.g. a shard-frame
// coverage proof from every shard). App-shard consensus keeps its own
// cap (`MAX_APP_MESSAGES_PER_RANK` in `app_engine`); this collector is
// global-only.

/// Number of ranks to retain before pruning (matches Go's retention window).
const RETENTION_WINDOW: u64 = 10;

/// A collected message with its hash for deduplication.
#[derive(Clone)]
struct CollectedMessage {
    data: Vec<u8>,
    hash: [u8; 32],
}

/// Maximum number of finalized message hashes retained for the
/// "already-included-in-a-finalized-frame" reject set. Bounded FIFO so
/// the set can't grow without limit; sized well above the per-frame cap
/// times the consensus depth so a message can't be re-collected before
/// it ages out.
const MAX_FINALIZED_HASHES: usize = 8192;

/// Bounded FIFO set of message hashes already included in a finalized
/// frame. New `add_message` / `collect_for_rank` skip these so a message
/// consumed by a finalized frame is never re-proposed.
struct FinalizedSet {
    set: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl FinalizedSet {
    fn new() -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    fn contains(&self, h: &[u8; 32]) -> bool {
        self.set.contains(h)
    }

    fn insert(&mut self, h: [u8; 32]) {
        if self.set.insert(h) {
            self.order.push_back(h);
            if self.order.len() > MAX_FINALIZED_HASHES {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

/// Outcome of adding a message to a [`RankBuffer`].
#[derive(Debug)]
enum AddOutcome {
    Added,
    Duplicate,
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

    /// Add a message if not already seen. There is no per-frame cap on
    /// global consensus, so the only rejection is exact-duplicate.
    fn add(&mut self, data: Vec<u8>) -> AddOutcome {
        let hash = sha256(&data);
        if self.seen.contains(&hash) {
            return AddOutcome::Duplicate;
        }
        self.seen.insert(hash);
        self.messages.push(CollectedMessage { data, hash });
        AddOutcome::Added
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
    /// Hashes of messages already included in a finalized frame. A
    /// message here is never re-collected or re-accepted — this is the
    /// "consume on finalize" half of the lifecycle. Mirrors the effect
    /// of Go's per-frame `lockCollectorMessage`, which prevents an
    /// already-included message from being proposed again.
    finalized: RwLock<FinalizedSet>,
}

impl MessageCollector {
    pub fn new() -> Self {
        Self {
            buffers: RwLock::new(HashMap::new()),
            prover_only_mode: std::sync::atomic::AtomicBool::new(false),
            shard_frame_dedup: RwLock::new(HashMap::new()),
            finalized: RwLock::new(FinalizedSet::new()),
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
    /// was accepted (not a duplicate, not filtered). Global consensus has
    /// no per-frame count cap, so a well-formed, non-duplicate message is
    /// always retained.
    pub fn add_message(&self, rank: u64, data: Vec<u8>) -> bool {
        // Prover-only mode filtering: check if the message is a
        // prover-protocol op (type prefix 0x0301-0x031A). If not,
        // reject it during degraded coverage.
        if self.prover_only_mode.load(std::sync::atomic::Ordering::Relaxed) {
            if !is_prover_message(&data) {
                return false;
            }
        }

        // Already included in a finalized frame → never re-accept. This
        // is what stops a message from re-entering the mempool after it
        // has been consumed by a committed frame.
        if self.finalized.read().unwrap().contains(&sha256(&data)) {
            return false;
        }

        // Shard-frame dedup at ingest (Go parity,
        // `message_collector.go:250-271`): a bundle carrying a shard
        // `FrameHeader` is rejected if that shard's frame_number is at or
        // below the last one already seen for the shard. Without this,
        // re-gossiped or stale shard-frame proofs re-enter the mempool
        // every round, so frames fill with already-seen proofs that the
        // materializer must re-verify (the expensive per-proof BLS work)
        // and then skip — the backlog explosion behind the halt. The
        // dedup commits the new high-water marks as a side effect.
        let shard_frames = extract_shard_frame_keys(&data);
        if !shard_frames.is_empty() && !self.dedup_shard_frames(&shard_frames) {
            return false;
        }

        let mut buffers = self.buffers.write().unwrap();
        let buffer = buffers.entry(rank).or_insert_with(RankBuffer::new);
        match buffer.add(data) {
            AddOutcome::Added => true,
            AddOutcome::Duplicate => false,
        }
    }

    /// Collect (NON-destructively) ALL pending messages for ranks
    /// `<= rank`. There is no per-frame count cap on global consensus —
    /// the frame carries every pending request (e.g. a coverage proof
    /// from every shard). Messages are NOT removed — they stay available
    /// so a proposal that times out (very common under churn) doesn't
    /// vaporize them; the next proposal sees the same set. They leave the
    /// collector only via [`mark_finalized`] (consumed by a committed
    /// frame) or retention pruning (aged out).
    ///
    /// Buffers at ranks `< rank` are also included: receivers tag inbound
    /// messages with their local "current rank", but on archives that
    /// never receive their own broadcasts the local rank lags the
    /// consensus rank the leader collects at. Including `<= rank` matches
    /// Go's behavior where producer and consumer share a single rank view.
    ///
    /// Mirrors Go's `consensus_liveness_provider.go`, which reads
    /// `collector.Records()` non-destructively into a persistent
    /// `collectedMessages` rather than draining. The previous Rust
    /// implementation drained here, so under the field's heavy timeout
    /// rate every finalized frame came out empty (messages were consumed
    /// by earlier proposals that never finalized).
    pub fn collect_for_rank(&self, rank: u64) -> Vec<Vec<u8>> {
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut messages: Vec<Vec<u8>> = Vec::new();

        // PEEK first (before any pruning) so a message at a rank that is
        // about to age out is still returned by this call — matching the
        // old drain-then-prune ordering. Test harnesses tag with rank 0
        // and rely on `collect_for_rank(N)` finding them.
        {
            let buffers = self.buffers.read().unwrap();
            let finalized = self.finalized.read().unwrap();
            let mut ranks: Vec<u64> = buffers.keys().copied().filter(|r| *r <= rank).collect();
            ranks.sort();
            for r in &ranks {
                if let Some(buf) = buffers.get(r) {
                    for m in &buf.messages {
                        if finalized.contains(&m.hash) || !seen.insert(m.hash) {
                            continue;
                        }
                        messages.push(m.data.clone());
                    }
                }
            }
        }

        // Retention prune AFTER peeking: ranks strictly older than the
        // window are dropped (they aged out). This is the only removal
        // path besides `mark_finalized`. No per-frame count cap — global
        // frames carry every pending request (direct transport, no gossip
        // size ceiling).
        if rank > RETENTION_WINDOW {
            let cutoff = rank - RETENTION_WINDOW;
            self.buffers.write().unwrap().retain(|&r, _| r >= cutoff);
        }

        messages
    }

    /// Mark `raw_msgs` as included in a finalized frame: remove them from
    /// the live buffers and record their hashes so they are never
    /// re-collected or re-accepted. Called by the materializer
    /// after a frame commits, with the canonical bytes of every bundle in
    /// the finalized frame. This is the "consume" half of the lifecycle
    /// that [`collect_for_rank`] (now non-destructive) no longer performs.
    pub fn mark_finalized(&self, raw_msgs: &[Vec<u8>]) {
        if raw_msgs.is_empty() {
            return;
        }
        let hashes: HashSet<[u8; 32]> = raw_msgs.iter().map(|m| sha256(m)).collect();

        {
            let mut buffers = self.buffers.write().unwrap();
            for buf in buffers.values_mut() {
                buf.messages.retain(|m| !hashes.contains(&m.hash));
                buf.seen.retain(|h| !hashes.contains(h));
            }
            buffers.retain(|_, b| !b.messages.is_empty());
        }
        {
            let mut fin = self.finalized.write().unwrap();
            for h in hashes {
                fin.insert(h);
            }
        }
    }

    /// Remove `raw_msgs` from the live buffers WITHOUT recording them as
    /// finalized. Used by the leader's collect path to drop messages that
    /// fail protocol validation, mirroring Go's `collector.Remove(record)`
    /// after a failed `lockCollectorMessage`/`ValidateMessage`
    /// (`consensus_liveness_provider.go:86-97`). Unlike [`mark_finalized`],
    /// a removed message is NOT blacklisted: validity is frame- and
    /// state-dependent (a join may reference a not-yet-seen frame), so a
    /// message invalid now can be valid later and is re-accepted if
    /// re-received. This stops invalid messages from being re-collected
    /// and re-proposed every rank until they age out of the retention
    /// window — they leave the mempool the moment we know they're invalid.
    pub fn remove(&self, raw_msgs: &[Vec<u8>]) {
        if raw_msgs.is_empty() {
            return;
        }
        let hashes: HashSet<[u8; 32]> = raw_msgs.iter().map(|m| sha256(m)).collect();
        let mut buffers = self.buffers.write().unwrap();
        for buf in buffers.values_mut() {
            buf.messages.retain(|m| !hashes.contains(&m.hash));
            buf.seen.retain(|h| !hashes.contains(h));
        }
        buffers.retain(|_, b| !b.messages.is_empty());
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

/// Extract `(shard_address, frame_number)` keys from every shard
/// `FrameHeader` request carried by a canonical `MessageBundle`. Used by
/// [`MessageCollector::add_message`] to dedup shard-frame proofs at
/// ingest. Returns empty if `data` isn't a decodable bundle or carries
/// no shard frames (the common case for prover-admin ops) — those skip
/// the dedup entirely. Mirrors Go's `req.GetShard()` extraction in
/// `addGlobalMessage`.
/// True if `data` (a canonical `MessageBundle`) carries at least one
/// shard `FrameHeader` request. The leader uses this to skip protocol
/// re-validation of shard-frame bundles at collect time: they are
/// deduplicated at ingest and fully validated by the materializer, and
/// re-verifying their (unbatchable, per-challenge class-group) VDF
/// multiproofs here — now that the per-frame cap is gone and a frame can
/// carry thousands — would load the latency-sensitive prove path. Only
/// non-shard-frame messages (joins, leaves, confirms, kicks) are
/// validated + dropped on the leader.
pub fn bundle_has_shard_frame(data: &[u8]) -> bool {
    !extract_shard_frame_keys(data).is_empty()
}

/// True iff every shard `FrameHeader` carried by `data` is in STRICT LOCKSTEP
/// with a global frame `frame_number`: its `global_frame_number` (storage-beacon
/// anchor) is either 0 (genesis / legacy-VDF, no anchor) or exactly
/// `frame_number - 1` (the immediately-preceding global frame). Returns `true`
/// for bundles that aren't decodable / carry no shard frames (this gate only
/// governs shard proofs).
///
/// The global leader calls this to include ONLY in-lockstep shard proofs.
/// Because the materializer HARD-REJECTS any frame containing an out-of-lockstep
/// shard op (`audit_storage_attestation`), a leader that packed a stale proof
/// would produce a frame its followers refuse — a halt. Dropping stale proofs
/// here keeps producer and verifier symmetric: the shard must re-attest fresh
/// (anchored to the new tip) to be included.
pub fn bundle_shard_frames_in_lockstep(data: &[u8], frame_number: u64) -> bool {
    use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
    use quil_execution::message_envelope::CanonicalMessageBundle;

    let expected = frame_number.saturating_sub(1);
    let bundle = match CanonicalMessageBundle::from_canonical_bytes(data) {
        Ok(b) => b,
        Err(_) => return true,
    };
    for req in bundle.requests.into_iter().flatten() {
        if req.inner_type_prefix == TYPE_FRAME_HEADER {
            if let Ok(fh) = FrameHeader::from_canonical_bytes(&req.inner_bytes) {
                let anchor = fh.global_frame_number;
                if anchor != 0 && anchor != expected {
                    return false;
                }
            }
        }
    }
    true
}

fn extract_shard_frame_keys(data: &[u8]) -> Vec<(Vec<u8>, u64)> {
    use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
    use quil_execution::message_envelope::CanonicalMessageBundle;

    let bundle = match CanonicalMessageBundle::from_canonical_bytes(data) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let mut keys = Vec::new();
    for req in bundle.requests.into_iter().flatten() {
        if req.inner_type_prefix == TYPE_FRAME_HEADER {
            if let Ok(fh) = FrameHeader::from_canonical_bytes(&req.inner_bytes) {
                if !fh.address.is_empty() {
                    keys.push((fh.address, fh.frame_number));
                }
            }
        }
    }
    keys
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

        // Collect is now NON-destructive: the messages stay pending so a
        // timed-out proposal doesn't lose them.
        let msgs = mc.collect_for_rank(1);
        assert_eq!(msgs.len(), 2);
        assert_eq!(mc.pending_count(1), 2);

        // A second collect returns the same set.
        assert_eq!(mc.collect_for_rank(1).len(), 2);

        // Only mark_finalized consumes them.
        mc.mark_finalized(&[b"msg-a".to_vec(), b"msg-b".to_vec()]);
        assert_eq!(mc.pending_count(1), 0);
        assert!(mc.collect_for_rank(1).is_empty());
    }

    #[test]
    fn finalized_messages_not_recollected_or_readded() {
        let mc = MessageCollector::new();
        assert!(mc.add_message(3, b"tx-1".to_vec()));
        assert_eq!(mc.collect_for_rank(3).len(), 1);

        // Finalize it → gone from the buffer and from future collects.
        mc.mark_finalized(&[b"tx-1".to_vec()]);
        assert!(mc.collect_for_rank(3).is_empty());

        // A late re-submission of the same bytes is rejected (already
        // included in a finalized frame).
        assert!(!mc.add_message(3, b"tx-1".to_vec()));
        assert!(mc.collect_for_rank(3).is_empty());
    }

    #[test]
    fn collect_is_idempotent_across_timeouts() {
        // Simulates a proposal collecting at rank R, timing out, then a
        // re-proposal at R+1 still seeing the messages (the bug this
        // fixes: the old drain lost them on the first collect).
        let mc = MessageCollector::new();
        mc.add_message(5, b"a".to_vec());
        mc.add_message(5, b"b".to_vec());
        assert_eq!(mc.collect_for_rank(5).len(), 2); // proposal @ rank 5 (times out)
        assert_eq!(mc.collect_for_rank(6).len(), 2); // re-proposal @ rank 6 still sees them
    }

    #[test]
    fn deduplication() {
        let mc = MessageCollector::new();
        assert!(mc.add_message(1, b"same".to_vec()));
        assert!(!mc.add_message(1, b"same".to_vec()));
        assert_eq!(mc.pending_count(1), 1);
    }

    #[test]
    fn no_per_frame_cap() {
        // Global consensus has NO per-frame request cap: every message is
        // retained (only exact-duplicate is rejected). 500 distinct
        // messages all stay pending.
        let mc = MessageCollector::new();
        for i in 0..500 {
            assert!(mc.add_message(1, format!("msg-{}", i).into_bytes()));
        }
        assert_eq!(mc.pending_count(1), 500);
        // Duplicate still rejected.
        assert!(!mc.add_message(1, b"msg-0".to_vec()));
        assert_eq!(mc.pending_count(1), 500);
    }

    #[test]
    fn remove_drops_without_blacklisting() {
        // `remove` evicts messages from the live buffers but, unlike
        // `mark_finalized`, does NOT blacklist them — a removed message can
        // be re-accepted if re-received (validity is state-dependent).
        let mc = MessageCollector::new();
        mc.add_message(1, b"keep".to_vec());
        mc.add_message(1, b"drop".to_vec());
        assert_eq!(mc.pending_count(1), 2);

        mc.remove(&[b"drop".to_vec()]);
        assert_eq!(mc.pending_count(1), 1);
        // The surviving message is still collectable.
        assert_eq!(mc.collect_for_rank(1), vec![b"keep".to_vec()]);

        // Not blacklisted: the same bytes can be re-added later.
        assert!(mc.add_message(1, b"drop".to_vec()));
        assert_eq!(mc.pending_count(1), 2);
    }

    #[test]
    fn collect_returns_all_uncapped() {
        // collect_for_rank returns EVERY pending message `<= rank`, no
        // truncation, and is non-destructive.
        let mc = MessageCollector::new();
        for i in 0..250 {
            mc.add_message(0, format!("r0-{}", i).into_bytes());
        }
        for i in 0..250 {
            mc.add_message(1, format!("r1-{}", i).into_bytes());
        }
        let msgs = mc.collect_for_rank(1);
        assert_eq!(msgs.len(), 500);
        // Non-destructive: still pending after collect.
        assert_eq!(mc.pending_count(0), 250);
        assert_eq!(mc.pending_count(1), 250);
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
        // collect_for_rank PEEKS every live rank `<= rank` (including the
        // about-to-age-out rank 1) before pruning, so all 3 are returned.
        assert_eq!(msgs.len(), 3);
        // Retention prune runs AFTER the peek: rank 1 < 20 - WINDOW(10) is
        // dropped; ranks 15 and 20 survive and are NOT consumed (collect is
        // non-destructive).
        assert_eq!(mc.pending_count(1), 0);
        assert_eq!(mc.pending_count(15), 1);
        assert_eq!(mc.pending_count(20), 1);
        assert_eq!(mc.total_pending(), 2);
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

    #[test]
    fn lockstep_gate_accepts_only_preceding_anchor() {
        use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
        use quil_execution::message_envelope::{
            CanonicalMessageBundle, CanonicalMessageRequest,
        };

        // A bundle carrying one shard FrameHeader anchored to `anchor`.
        let make = |anchor: u64| -> Vec<u8> {
            let fh = FrameHeader {
                address: vec![0x11u8; 32],
                frame_number: 7,
                global_frame_number: anchor,
                ..Default::default()
            };
            let req = CanonicalMessageRequest {
                inner_type_prefix: TYPE_FRAME_HEADER,
                inner_bytes: fh.to_canonical_bytes().unwrap(),
            };
            CanonicalMessageBundle { requests: vec![Some(req)], timestamp: 0 }
                .to_canonical_bytes()
                .unwrap()
        };

        // Building global frame 100: in lockstep iff anchor == 99 (frame-1) or 0.
        assert!(bundle_shard_frames_in_lockstep(&make(99), 100), "anchor==frame-1 in lockstep");
        assert!(bundle_shard_frames_in_lockstep(&make(0), 100), "genesis anchor exempt");
        assert!(!bundle_shard_frames_in_lockstep(&make(98), 100), "stale anchor dropped");
        assert!(!bundle_shard_frames_in_lockstep(&make(100), 100), "future anchor dropped");
        // Non-bundle / non-shard-frame data passes (this gate only governs shard frames).
        assert!(bundle_shard_frames_in_lockstep(b"not a bundle", 100));
    }
}
