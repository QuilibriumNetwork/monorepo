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
    /// The per-rank count/byte cap is full — message rejected (not retained).
    Full,
}

/// Per-rank caps. Without these an attacker floods DISTINCT payloads (vary one
/// byte to defeat the SHA-256 dedup) at the current rank — each retained until
/// the rank ages out — a memory-amplification DoS (submit paths accept up to
/// 64 MiB/msg on :8340). A leader can only pack ~15 MiB into one proposal anyway,
/// so retaining far more than that is pointless; these bound the buffer while
/// staying well above any legitimate per-rank volume.
const MAX_MESSAGES_PER_RANK: usize = 65_536;
const MAX_BYTES_PER_RANK: usize = 64 * 1024 * 1024;

/// Per-rank message buffer.
struct RankBuffer {
    messages: Vec<CollectedMessage>,
    seen: HashSet<[u8; 32]>,
    bytes: usize,
}

impl RankBuffer {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            seen: HashSet::new(),
            bytes: 0,
        }
    }

    /// Add a message if not already seen and the rank isn't over its cap.
    fn add(&mut self, data: Vec<u8>) -> AddOutcome {
        let hash = sha256(&data);
        if self.seen.contains(&hash) {
            return AddOutcome::Duplicate;
        }
        if self.messages.len() >= MAX_MESSAGES_PER_RANK
            || self.bytes.saturating_add(data.len()) > MAX_BYTES_PER_RANK
        {
            return AddOutcome::Full;
        }
        self.seen.insert(hash);
        self.bytes += data.len();
        self.messages.push(CollectedMessage { data, hash });
        AddOutcome::Added
    }

    fn len(&self) -> usize {
        self.messages.len()
    }
}

/// Outcome of an [`MessageCollector::add_message_outcome`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Newly added to the mempool.
    Accepted,
    /// The collector already holds this message (already finalized, a byte
    /// duplicate, or superseded by a newer shard frame for the same shard).
    /// The submitter's work is NOT lost — a network submit handler should
    /// report this to the caller as success, not a dropped message.
    Duplicate,
    /// Rejected by a real filter (prover-only mode dropped a non-prover
    /// message during degraded coverage); the message was NOT retained.
    Filtered,
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
    /// The set of CURRENT valid shard addresses (a shard `FrameHeader`'s
    /// `address` — the L2‖prefix filter). Refreshed from the shards store. Used
    /// to preemptively reject shard frames whose address is not a real current
    /// shard (e.g. an old 4096-grid division that no longer exists). Empty =
    /// "not yet loaded" → the address check is skipped (fail-open) so a fresh
    /// node doesn't drop everything before its first refresh.
    valid_shard_addresses: RwLock<HashSet<Vec<u8>>>,
    /// The newest rank this collector has been collected, copied or carried
    /// at. [`Self::add_message_newest`] files arrivals here.
    newest_rank: std::sync::atomic::AtomicU64,
}

impl MessageCollector {
    pub fn new() -> Self {
        Self {
            buffers: RwLock::new(HashMap::new()),
            prover_only_mode: std::sync::atomic::AtomicBool::new(false),
            shard_frame_dedup: RwLock::new(HashMap::new()),
            finalized: RwLock::new(FinalizedSet::new()),
            valid_shard_addresses: RwLock::new(HashSet::new()),
            newest_rank: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn note_rank(&self, rank: u64) {
        self.newest_rank.fetch_max(rank, std::sync::atomic::Ordering::AcqRel);
    }

    /// Re-file every held message at rank 0 and restart the newest rank: a new
    /// consensus instance numbers its views from the start again, and a
    /// collection only takes ranks at or below its own, so messages held at
    /// the previous instance's ranks would stay out of reach.
    pub fn rebase_ranks(&self) {
        let mut buffers = self.buffers.write().unwrap();
        let mut merged = RankBuffer::new();
        let mut ranks: Vec<u64> = buffers.keys().copied().collect();
        ranks.sort_unstable();
        for rank in ranks {
            if let Some(buffer) = buffers.remove(&rank) {
                for message in buffer.messages {
                    merged.add(message.data);
                }
            }
        }
        if merged.len() > 0 {
            buffers.insert(0, merged);
        }
        self.newest_rank.store(0, std::sync::atomic::Ordering::Release);
    }

    /// Add an arriving message at the newest rank the collector has seen, so
    /// it counts as the newest message: an application shard's engine has no
    /// rank of its own (its views are the consensus host's). Filed at rank 0,
    /// arrivals read as the oldest messages: the first collection pruned them
    /// and a private-parent copy, which takes the newest first, cut them
    /// first.
    pub fn add_message_newest(&self, data: Vec<u8>) -> bool {
        let rank = self.newest_rank.load(std::sync::atomic::Ordering::Acquire);
        self.add_message(rank, data)
    }

    /// Replace the set of valid current shard addresses (called from the
    /// shard-info refresh with the L2‖prefix filter of every current shard).
    /// Once populated, shard frames whose address isn't in the set are rejected
    /// at ingestion.
    pub fn set_valid_shard_addresses(&self, addresses: HashSet<Vec<u8>>) {
        *self.valid_shard_addresses.write().unwrap() = addresses;
    }

    /// Refresh admission from committed local topology. Archives call this
    /// after materialization, before advertising the new global frame, so the
    /// first child header does not wait for the periodic remote size refresh.
    /// A failed read leaves the last successful set intact.
    pub fn refresh_valid_shard_addresses(
        &self,
        store: &dyn quil_types::store::ShardsStore,
    ) -> quil_types::error::Result<()> {
        let rows = store.range_app_shards()?;
        let mut valid = HashSet::with_capacity(rows.len());
        for row in rows {
            if row.shard_key.len() != 35 {
                return Err(quil_types::error::QuilError::InvalidArgument(
                    "invalid shard key in committed topology".into(),
                ));
            }
            valid.insert(quil_forest::shard_prefix_to_filter(
                &row.shard_key[3..35], &row.prefix,
            ));
        }
        self.set_valid_shard_addresses(valid);
        Ok(())
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

    /// Add a message for the given rank. Returns true iff it was NEWLY
    /// added (see [`SubmitOutcome`] via [`add_message_outcome`] for the
    /// duplicate-vs-filtered distinction). Global consensus has no
    /// per-frame count cap, so a well-formed, non-duplicate message is
    /// always retained.
    pub fn add_message(&self, rank: u64, data: Vec<u8>) -> bool {
        matches!(self.add_message_outcome(rank, data), SubmitOutcome::Accepted)
    }

    /// Add a message, distinguishing "newly accepted" from "we already
    /// hold its exact bytes" from "filtered out". A network
    /// submit handler should treat both `Accepted` and `Duplicate` as
    /// SUCCESS — re-delivering something the collector already has (or has
    /// superseded) is not a dropped message; only `Filtered` is a real
    /// rejection. This is what stops a prover's idempotent re-submission
    /// of an already-delivered bundle from being reported to it as a
    /// transport failure.
    pub fn add_message_outcome(&self, rank: u64, data: Vec<u8>) -> SubmitOutcome {
        // Prover-only mode filtering: check if the message is a
        // prover-protocol op (type prefix 0x0301-0x031A). If not,
        // reject it during degraded coverage.
        if self.prover_only_mode.load(std::sync::atomic::Ordering::Relaxed) {
            if !is_prover_message(&data) {
                tracing::debug!(
                    "message collector: submit rejected — prover-only (degraded coverage) mode, non-prover message"
                );
                return SubmitOutcome::Filtered;
            }
        }

        // Already included in a finalized frame → never re-accept. This
        // is what stops a message from re-entering the mempool after it
        // has been consumed by a committed frame. The archive already has
        // this work, so this is a duplicate, not a rejection.
        if self.finalized.read().unwrap().contains(&sha256(&data)) {
            return SubmitOutcome::Duplicate;
        }

        // Candidates have not passed certificate/intrinsic validation. Their
        // declared heights must not advance a trusted high-water mark: doing
        // so lets an invalid candidate suppress valid frames on every retry.
        // The bounded buffers and finalized set deduplicate exact bytes.
        let checks = extract_shard_frame_checks(&data);

        // Reject addresses outside the known current shard set before spending
        // certificate-verification work. Missing attestations affect rewards,
        // not admission, and are left to intrinsic validation below.
        // The address check only engages once the valid-shard set has been
        // populated from the shards store (fail-open before the first refresh
        // so a just-started node doesn't drop everything).
        if !checks.is_empty() {
            let valid = self.valid_shard_addresses.read().unwrap();
            for c in &checks {
                // A storage frame with NO attestation is NOT invalid: the app-shard
                // validator binds an empty `storage_attestation_root` into its
                // deterministic output like any other value (frame_validator.rs),
                // and the GLOBAL proof-of-storage gate withholds only the REWARD for
                // a data-bearing shard WITHOUT halting (intrinsic.rs). Rejecting it
                // here wedged the shard: its frames never entered the mempool → never
                // got included → the shard could not advance (e.g. frame_number=1
                // with no replicas yet to attest). So do NOT filter on a missing
                // attestation — let it through; the intrinsic zeros the reward if the
                // shard carries committed data, and the shard still progresses.
                if c.global_frame_number > 0 && !c.has_attestation {
                    tracing::debug!(
                        address = %hex::encode(&c.address[..c.address.len().min(8)]),
                        frame_number = c.frame_number,
                        global_frame_number = c.global_frame_number,
                        "message collector: storage frame carries no attestation — ACCEPTING (reward withheld by the intrinsic if data-bearing; frame not wedged)"
                    );
                }
                if !valid.is_empty() && !valid.contains(&c.address) {
                    tracing::warn!(
                        address = %hex::encode(&c.address[..c.address.len().min(8)]),
                        frame_number = c.frame_number,
                        valid_shard_count = valid.len(),
                        "message collector: shard-frame submit REJECTED — address not in current valid-shard set (stale / pre-split / wrong-grid address)"
                    );
                    return SubmitOutcome::Filtered;
                }
            }
        }

        let mut buffers = self.buffers.write().unwrap();
        let buffer = buffers.entry(rank).or_insert_with(RankBuffer::new);
        match buffer.add(data) {
            AddOutcome::Added => SubmitOutcome::Accepted,
            AddOutcome::Duplicate => SubmitOutcome::Duplicate,
            AddOutcome::Full => {
                tracing::warn!(
                    rank,
                    "message collector: submit rejected — rank buffer full (per-rank count/byte cap reached)"
                );
                SubmitOutcome::Filtered
            }
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
        self.note_rank(rank);
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

    /// Copy proposal inputs without pruning, consuming or changing admission
    /// state in the public collector. At most `max_items` messages are
    /// inspected and `max_bytes` copied, newest ranks first; what does not fit
    /// waits for a later proposal. The copy is returned in collection order
    /// (oldest rank first). A backlog over the budget must not fail the copy:
    /// the public buffers are pruned only after a finalized frame, so a
    /// restart's backlog would otherwise leave GLOBAL unable to make any
    /// private proposal, and therefore any frame, again.
    pub(crate) fn snapshot_for_execution(
        &self, rank: u64, max_bytes: usize, max_items: usize,
    ) -> quil_types::error::Result<Vec<Vec<u8>>> {
        use quil_types::error::QuilError;
        let unavailable = || QuilError::ExecutionUnavailable("proposal message snapshot lock failure".into());
        self.note_rank(rank);
        let buffers = self.buffers.read().map_err(|_| unavailable())?;
        let finalized = self.finalized.read().map_err(|_| unavailable())?;
        let mut ranks: Vec<_> = buffers.keys().copied().filter(|r| *r <= rank).collect();
        ranks.sort_unstable_by(|a, b| b.cmp(a));
        let mut seen = HashSet::new();
        let mut taken: Vec<Vec<Vec<u8>>> = Vec::new();
        let (mut bytes, mut inspected) = (0usize, 0usize);
        'ranks: for rank in ranks {
            let mut in_rank = Vec::new();
            for message in &buffers[&rank].messages {
                if inspected >= max_items {
                    taken.push(in_rank);
                    break 'ranks;
                }
                inspected += 1;
                if finalized.contains(&message.hash) || seen.contains(&message.hash) { continue; }
                if bytes.saturating_add(message.data.len()) > max_bytes {
                    taken.push(in_rank);
                    break 'ranks;
                }
                bytes += message.data.len();
                seen.insert(message.hash);
                in_rank.push(message.data.clone());
            }
            taken.push(in_rank);
        }
        Ok(taken.into_iter().rev().flatten().collect())
    }

    /// Age public GLOBAL inputs only after a finalized frame has materialized.
    /// Tentative proposals use private snapshots and cannot advance this window.
    pub fn prune_after_finalization(&self, rank: u64) {
        if let Some(cutoff) = rank.checked_sub(RETENTION_WINDOW) {
            self.buffers.write().unwrap().retain(|&r, _| r >= cutoff);
        }
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
                buf.bytes = buf.messages.iter().map(|m| m.data.len()).sum();
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
            buf.bytes = buf.messages.iter().map(|m| m.data.len()).sum();
        }
        buffers.retain(|_, b| !b.messages.is_empty());
    }

    /// Hold `raw_msgs` at `rank`, for a retention window starting there, in
    /// the order given and ahead of what arrived at `rank` itself. A proposal
    /// that holds collected messages back (an application shard's
    /// proof-verification budget) carries them forward, so waiting behind
    /// other work never ages them out, including one its own collection has
    /// just aged out; a message nobody holds back ages out as before.
    /// Messages already consumed by a finalized frame are not held again, and
    /// none displaces what arrived at `rank`.
    pub fn carry_forward(&self, rank: u64, raw_msgs: &[Vec<u8>]) {
        self.note_rank(rank);
        if raw_msgs.is_empty() {
            return;
        }
        let carried: Vec<CollectedMessage> = {
            let finalized = self.finalized.read().unwrap();
            let mut seen = HashSet::new();
            raw_msgs
                .iter()
                .map(|data| CollectedMessage { hash: sha256(data), data: data.clone() })
                .filter(|m| !finalized.contains(&m.hash) && seen.insert(m.hash))
                .collect()
        };
        let mut buffers = self.buffers.write().unwrap();
        let arrived = buffers.remove(&rank).unwrap_or_else(RankBuffer::new);
        let (mut rest_count, mut rest_bytes) = (arrived.messages.len(), arrived.bytes);
        let mut target = RankBuffer::new();
        let mut moved = HashSet::new();
        for m in carried {
            let already = arrived.seen.contains(&m.hash);
            let (count, bytes) = if already { (0, 0) } else { (1, m.data.len()) };
            if target.messages.len() + rest_count + count > MAX_MESSAGES_PER_RANK
                || target.bytes + rest_bytes + bytes > MAX_BYTES_PER_RANK
            {
                continue;
            }
            if already {
                rest_count -= 1;
                rest_bytes -= m.data.len();
            }
            if matches!(target.add(m.data), AddOutcome::Added) {
                moved.insert(m.hash);
            }
        }
        for m in arrived.messages {
            if !moved.contains(&m.hash) {
                target.add(m.data);
            }
        }
        for buf in buffers.values_mut() {
            buf.messages.retain(|m| !moved.contains(&m.hash));
            buf.seen.retain(|h| !moved.contains(h));
            buf.bytes = buf.messages.iter().map(|m| m.data.len()).sum();
        }
        buffers.insert(rank, target);
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

    // WINDOWED LOCKSTEP (must mirror the materializer's `audit_storage_attestation`
    // exactly, or a packed frame would be rejected by followers → halt): a storage
    // shard proof is includable iff its anchor is 0 (genesis/legacy) OR within
    // `[expected - W, expected]`. Multi-member shards anchor to `latest − K`, so a
    // strict `== expected` is unsatisfiable; the window absorbs K + transit.
    use quil_execution::global_intrinsic::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW;
    let expected = frame_number.saturating_sub(1);
    let oldest = expected.saturating_sub(STORAGE_ANCHOR_LOCKSTEP_WINDOW);
    let bundle = match CanonicalMessageBundle::from_canonical_bytes(data) {
        Ok(b) => b,
        Err(_) => return true,
    };
    for req in bundle.requests.into_iter().flatten() {
        if req.inner_type_prefix == TYPE_FRAME_HEADER {
            if let Ok(fh) = FrameHeader::from_canonical_bytes(&req.inner_bytes) {
                let anchor = fh.global_frame_number;
                if anchor != 0 && (anchor > expected || anchor < oldest) {
                    return false;
                }
            }
        }
    }
    true
}

/// A shard `FrameHeader` carried by a bundle, with the fields needed for both
/// dedup and preemptive ingestion validation.
struct ShardFrameCheck {
    address: Vec<u8>,
    frame_number: u64,
    /// The global frame this shard frame anchors to. `> 0` ⇒ a storage frame
    /// (must carry storage attestation); `== 0` ⇒ genesis/legacy VDF frame.
    global_frame_number: u64,
    /// True iff the header commits to a storage attestation
    /// (`storage_attestation_root` non-empty).
    has_attestation: bool,
}

fn extract_shard_frame_checks(data: &[u8]) -> Vec<ShardFrameCheck> {
    use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
    use quil_execution::message_envelope::CanonicalMessageBundle;

    let bundle = match CanonicalMessageBundle::from_canonical_bytes(data) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for req in bundle.requests.into_iter().flatten() {
        if req.inner_type_prefix == TYPE_FRAME_HEADER {
            if let Ok(fh) = FrameHeader::from_canonical_bytes(&req.inner_bytes) {
                if !fh.address.is_empty() {
                    out.push(ShardFrameCheck {
                        address: fh.address,
                        frame_number: fh.frame_number,
                        global_frame_number: fh.global_frame_number,
                        has_attestation: !fh.storage_attestation_root.is_empty(),
                    });
                }
            }
        }
    }
    out
}

pub fn extract_shard_frame_keys(data: &[u8]) -> Vec<(Vec<u8>, u64)> {
    extract_shard_frame_checks(data)
        .into_iter()
        .map(|c| (c.address, c.frame_number))
        .collect()
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

    /// A message a proposal holds back is carried to the proposal's rank, in
    /// the proposal's order and ahead of later arrivals, and outlives the
    /// window it arrived in; one nobody holds back still ages out. One the
    /// proposal's own collection just aged out is held again; a consumed one
    /// is not.
    /// A new consensus instance restarts its views: rebased, everything held
    /// is within its reach, and arrivals are filed at its ranks.
    #[test]
    fn a_rebase_brings_held_messages_within_a_restarted_instances_reach() {
        let collector = MessageCollector::new();
        let (held, arrival) = (vec![7u8; 32], vec![8u8; 32]);
        collector.carry_forward(500, &[held.clone()]);
        assert!(collector.collect_for_rank(3).is_empty(), "held above a restarted instance's ranks");
        collector.rebase_ranks();
        assert!(collector.add_message_newest(arrival.clone()));
        let collected = collector.collect_for_rank(3);
        assert!(collected.contains(&held) && collected.contains(&arrival));
    }

    /// An arrival is the newest message: filed at the newest rank the collector
    /// has seen, a collection keeps it for the next one, and a copy limited to
    /// one message takes it before older held messages. Filed at rank 0, the
    /// first collection pruned it and the copy took an older message.
    #[test]
    fn arrivals_are_filed_as_the_newest_messages() {
        let collector = MessageCollector::new();
        let (held_a, held_b, arrival) = (vec![1u8; 64], vec![2u8; 64], vec![3u8; 64]);
        collector.carry_forward(50, &[held_a.clone(), held_b.clone()]);
        assert_eq!(collector.collect_for_rank(60).len(), 2);
        assert!(collector.add_message_newest(arrival.clone()));
        assert_eq!(collector.snapshot_for_execution(60, 1 << 20, 1).unwrap(), vec![arrival.clone()],
            "a copy limited to one message takes the newest");
        assert!(collector.collect_for_rank(65).contains(&arrival));
        assert!(collector.collect_for_rank(65).contains(&arrival), "one collection does not prune a new arrival");
    }

    #[test]
    fn held_back_messages_outlive_the_retention_window() {
        let mc = MessageCollector::new();
        mc.add_message(1, b"held".to_vec());
        mc.add_message(1, b"idle".to_vec());
        mc.add_message(4, b"second".to_vec());
        mc.add_message(8, b"arrived at 8".to_vec());
        mc.carry_forward(8, &[b"held".to_vec(), b"second".to_vec()]);
        assert_eq!(mc.pending_count(1), 1, "moved out of its arrival rank");
        assert_eq!(mc.pending_count(4), 0);
        assert_eq!(mc.pending_count(8), 3, "into the proposal's rank");
        assert_eq!(mc.collect_for_rank(8), vec![b"idle".to_vec(), b"held".to_vec(), b"second".to_vec(), b"arrived at 8".to_vec()],
            "carried messages keep their order, ahead of later arrivals");
        mc.remove(&[b"second".to_vec(), b"arrived at 8".to_vec()]);
        let collected = mc.collect_for_rank(12);
        assert!(collected.contains(&b"held".to_vec()) && collected.contains(&b"idle".to_vec()));
        assert_eq!(mc.collect_for_rank(15), vec![b"held".to_vec()], "rank 1 aged out");
        // Collection at 19 returns "held" and ages it out; the proposal holds
        // it back again from its own copy.
        assert_eq!(mc.collect_for_rank(19), vec![b"held".to_vec()]);
        assert_eq!(mc.total_pending(), 0);
        mc.carry_forward(19, &[b"held".to_vec()]);
        assert_eq!(mc.collect_for_rank(30), vec![b"held".to_vec()]);
        assert!(mc.collect_for_rank(31).is_empty(), "not held back again: it ages out");
        // A consumed message is not held again.
        mc.add_message(40, b"done".to_vec());
        mc.mark_finalized(&[b"done".to_vec()]);
        mc.carry_forward(41, &[b"done".to_vec()]);
        assert_eq!(mc.total_pending(), 0);
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
    fn add_message_outcome_distinguishes_accepted_duplicate_filtered() {
        let mc = MessageCollector::new();
        // A prover op (0x0301 = ProverJoin): new → Accepted, re-submit →
        // Duplicate (the collector already holds it — NOT a drop, so a submit
        // handler reports success and the prover doesn't see a transport error).
        let mut bundle = 0x0301u32.to_be_bytes().to_vec();
        bundle.extend_from_slice(b"prover-op");
        assert_eq!(mc.add_message_outcome(1, bundle.clone()), SubmitOutcome::Accepted);
        assert_eq!(mc.add_message_outcome(1, bundle), SubmitOutcome::Duplicate);
        // In prover-only mode a non-prover message is a REAL reject (Filtered).
        mc.set_prover_only_mode(true);
        assert_eq!(
            mc.add_message_outcome(2, b"not-a-prover-message".to_vec()),
            SubmitOutcome::Filtered
        );
        // The bool `add_message` wrapper is unchanged: true only for Accepted.
        let mut b2 = 0x0301u32.to_be_bytes().to_vec();
        b2.extend_from_slice(b"another");
        assert!(mc.add_message(3, b2.clone()));
        assert!(!mc.add_message(3, b2));
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
    fn committed_split_and_merge_refresh_admission_without_remote_size_poll() {
        use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use quil_types::store::{ClockStore, ShardInfo, ShardsStore};

        let rocks = quil_store::RocksDb::open_in_memory().unwrap();
        let clock = quil_store::RocksClockStore::new(rocks.inner());
        let shards = quil_store::RocksShardsStore::new(rocks.inner());
        let collector = MessageCollector::new();
        let app = [0x51; 32];
        let mut key = vec![1, 2, 3];
        key.extend_from_slice(&app);
        let row = |prefix| ShardInfo {
            shard_key: key.clone(), prefix, size: vec![], data_shards: 0, commitment: vec![],
        };
        let parent = row(vec![]);
        let children = [row(quil_forest::bit_path_to_prefix(&[false])),
                        row(quil_forest::bit_path_to_prefix(&[true]))];
        let bundle = |prefix: &[u32], frame_number| {
            let header = FrameHeader {
                address: quil_forest::shard_prefix_to_filter(&app, prefix),
                frame_number, global_frame_number: 10, ..Default::default()
            };
            CanonicalMessageBundle {
                timestamp: 0,
                requests: vec![Some(CanonicalMessageRequest {
                    inner_type_prefix: TYPE_FRAME_HEADER,
                    inner_bytes: header.to_canonical_bytes().unwrap(),
                })],
            }.to_canonical_bytes().unwrap()
        };
        let txn = clock.new_transaction(false).unwrap();
        shards.put_app_shard(txn.as_ref(), &parent).unwrap();
        txn.commit().unwrap();
        collector.refresh_valid_shard_addresses(&shards).unwrap();
        assert_eq!(collector.add_message_outcome(1, bundle(&parent.prefix, 1)), SubmitOutcome::Accepted);

        let txn = clock.new_transaction(false).unwrap();
        shards.delete_app_shard(txn.as_ref(), &key, &parent.prefix).unwrap();
        for child in &children { shards.put_app_shard(txn.as_ref(), child).unwrap(); }
        // A staged topology must not leak through a committed-store refresh.
        collector.refresh_valid_shard_addresses(&shards).unwrap();
        assert_eq!(collector.add_message_outcome(1, bundle(&children[0].prefix, 1)), SubmitOutcome::Filtered);
        txn.commit().unwrap();
        collector.refresh_valid_shard_addresses(&shards).unwrap();
        for child in &children {
            assert_eq!(collector.add_message_outcome(1, bundle(&child.prefix, 1)), SubmitOutcome::Accepted);
        }
        assert_eq!(collector.add_message_outcome(1, bundle(&parent.prefix, 2)), SubmitOutcome::Filtered);

        let txn = clock.new_transaction(false).unwrap();
        for child in &children { shards.delete_app_shard(txn.as_ref(), &key, &child.prefix).unwrap(); }
        shards.put_app_shard(txn.as_ref(), &parent).unwrap();
        txn.commit().unwrap();
        collector.refresh_valid_shard_addresses(&shards).unwrap();
        assert_eq!(collector.add_message_outcome(1, bundle(&parent.prefix, 2)), SubmitOutcome::Accepted);
        assert_eq!(collector.add_message_outcome(1, bundle(&children[0].prefix, 2)), SubmitOutcome::Filtered);
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

        // Building global frame 100: in lockstep iff anchor ∈ [99-W, 99] or 0.
        // With W = STORAGE_ANCHOR_LOCKSTEP_WINDOW, the window is [87, 99].
        assert!(bundle_shard_frames_in_lockstep(&make(99), 100), "anchor==frame-1 in lockstep");
        assert!(bundle_shard_frames_in_lockstep(&make(0), 100), "genesis anchor exempt");
        assert!(bundle_shard_frames_in_lockstep(&make(98), 100), "anchor just inside window accepted");
        assert!(bundle_shard_frames_in_lockstep(&make(87), 100), "oldest in-window anchor accepted");
        assert!(!bundle_shard_frames_in_lockstep(&make(86), 100), "anchor older than window dropped");
        assert!(!bundle_shard_frames_in_lockstep(&make(100), 100), "future anchor dropped");
        // Non-bundle / non-shard-frame data passes (this gate only governs shard frames).
        assert!(bundle_shard_frames_in_lockstep(b"not a bundle", 100));
    }
}
